package mdns

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// queryAt are the offsets at which Browse (re)sends its query; the gap at
// least doubles (RFC 6762 clause 5.2).
var queryAt = []time.Duration{0, time.Second, 3 * time.Second, 7 * time.Second}

// maxQuery is the largest query packet sent in one piece; a query for many
// types with many known answers is split per type above it (RFC 6762
// clause 17 keeps multicast packets within the link's MTU).
const maxQuery = 1400

// Browse looks for instances of service (for example "_matter._tcp" or a
// subtype such as "_L840._sub._matterc._udp") and returns what answered
// before ctx ended or opts.Wait passed.
//
// By default (BrowseBoth) it sends one-shot queries from an ephemeral port
// to the mDNS group on each interface (RFC 6762 clause 5.1), to which
// responders reply by unicast, and the same query from the mDNS port with
// the groups joined (shared with the operating system's responder through
// SO_REUSEPORT), so responders that answer only by multicast are heard as
// well. Later queries list the complete instances already known
// (known-answer suppression) and ask directly for the SRV, TXT and address
// records still missing. Instances whose goodbye (TTL 0) arrives are
// dropped. Results are sorted by instance name; use Service.Addr to
// connect, which favours the .local host name.
func Browse(ctx context.Context, service string, opts Options) ([]Service, error) {
	all, err := BrowseTypes(ctx, []string{service}, opts)
	if err != nil {
		return nil, err
	}
	return all[service], nil
}

// BrowseTypes is Browse for several service types over one set of sockets
// and one query train; the result is keyed by the types as given.
func BrowseTypes(ctx context.Context, services []string, opts Options) (map[string][]Service, error) {
	names, err := typeNames(services)
	if err != nil {
		return nil, err
	}
	ifaces, err := opts.interfaces()
	if err != nil {
		return nil, err
	}
	if opts.Wait > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Wait)
		defer cancel()
	} else if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, DefaultWait)
		defer cancel()
	}
	c := newCache()
	q, err := newQuerier(ctx, opts, ifaces, func(m message, ifIndex int) {
		c.addFor(m, ifIndex, time.Now(), names)
	})
	if err != nil {
		return nil, err
	}

	var errs []error
	sent := 0
	start := time.Now()
	for _, at := range queryAt {
		t := time.NewTimer(time.Until(start.Add(at)))
		select {
		case <-ctx.Done():
			t.Stop()
		case <-t.C:
		}
		if ctx.Err() != nil {
			break
		}
		pkts, err := c.queries(names, time.Now())
		if err != nil {
			errs = append(errs, err)
			break
		}
		for _, p := range pkts {
			if q.send(p) {
				sent++
			}
		}
	}
	<-ctx.Done()
	q.close()
	if sent == 0 {
		return nil, fmt.Errorf("mdns: sending the query failed on every interface: %w", errors.Join(append(errs, q.errs()...)...))
	}
	now := time.Now()
	out := make(map[string][]Service, len(services))
	for i, s := range services {
		out[s] = c.services(names[i], now)
	}
	return out, nil
}

// typeNames checks and qualifies service types.
func typeNames(services []string) ([]string, error) {
	if len(services) == 0 {
		return nil, errors.New("mdns: no service type to browse")
	}
	out := make([]string, len(services))
	for i, s := range services {
		out[i] = serviceTypeName(s)
		if _, err := dnsmessage.NewName(out[i]); err != nil {
			return nil, fmt.Errorf("mdns: service %q: %w", s, err)
		}
	}
	return out, nil
}

// cache holds records from responses with their expiry.
type cache struct {
	mu      sync.Mutex
	entries []cached
}

type cached struct {
	r        rr
	received time.Time
	expires  time.Time
	ifIndex  int // receiving interface; 0 when unknown
	// refreshed counts the refresh queries sent for the record since it
	// was last received (RFC 6762 clause 5.2: at 80, 85, 90 and 95 % of
	// its TTL).
	refreshed int
	jitter    float64
}

type want struct {
	name string
	typ  dnsmessage.Type
}

func newCache() *cache { return &cache{} }

// add stores the answers and additional records of a response. A record
// with TTL 0 removes the matching record (a goodbye). A cache-flush record
// replaces the other records of its name and type (RFC 6762 clause 10.2).
func (c *cache) add(m message, now time.Time) { c.addOn(m, 0, now) }

// addOn is add for a response received on interface ifIndex. A cache
// flush only replaces records received on the same interface, since a
// multihomed responder answers each interface with that interface's
// addresses (RFC 6762 clause 10.2); ifIndex 0 flushes every interface.
func (c *cache) addOn(m message, ifIndex int, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.store(append(append([]rr(nil), m.Answers...), m.Additionals...), ifIndex, now)
}

// addFor is addOn keeping only the records that belong to the browsed
// types: their PTR records, the SRV and TXT records of the instances they
// name, and the addresses of the SRV targets. Listening on the mDNS port
// hears every response on the link; the rest is not kept.
func (c *cache) addFor(m message, ifIndex int, now time.Time, typeNames []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	incoming := append(append([]rr(nil), m.Answers...), m.Additionals...)
	types := map[string]bool{}
	for _, t := range typeNames {
		types[strings.ToLower(t)] = true
	}
	insts, hosts := map[string]bool{}, map[string]bool{}
	for _, e := range c.entries {
		if e.r.Type == dnsmessage.TypePTR && types[strings.ToLower(e.r.Name)] {
			insts[strings.ToLower(e.r.PTR)] = true
		}
	}
	for _, x := range incoming {
		if x.Type == dnsmessage.TypePTR && types[strings.ToLower(x.Name)] {
			insts[strings.ToLower(x.PTR)] = true
		}
	}
	for _, e := range c.entries {
		if e.r.Type == dnsmessage.TypeSRV && insts[strings.ToLower(e.r.Name)] {
			hosts[strings.ToLower(e.r.Target)] = true
		}
	}
	for _, x := range incoming {
		if x.Type == dnsmessage.TypeSRV && insts[strings.ToLower(x.Name)] {
			hosts[strings.ToLower(x.Target)] = true
		}
	}
	var keep []rr
	for _, x := range incoming {
		n := strings.ToLower(x.Name)
		switch x.Type {
		case dnsmessage.TypePTR:
			if types[n] {
				keep = append(keep, x)
			}
		case dnsmessage.TypeSRV, dnsmessage.TypeTXT:
			if insts[n] {
				keep = append(keep, x)
			}
		case dnsmessage.TypeA, dnsmessage.TypeAAAA:
			if hosts[n] {
				keep = append(keep, x)
			}
		}
	}
	c.store(keep, ifIndex, now)
}

// store adds records; the caller holds mu.
func (c *cache) store(incoming []rr, ifIndex int, now time.Time) {
	flushed := map[want]bool{}
	for _, x := range incoming {
		key := want{strings.ToLower(x.Name), x.Type}
		if x.Flush && x.TTL > 0 && !flushed[key] {
			flushed[key] = true
			c.drop(func(e cached) bool {
				return (ifIndex == 0 || e.ifIndex == 0 || e.ifIndex == ifIndex) && strings.EqualFold(e.r.Name, x.Name) && e.r.Type == x.Type
			})
		}
		expires := now.Add(time.Duration(x.TTL) * time.Second)
		// The same record heard again (by multicast and in a legacy
		// unicast reply, whose TTL is capped at 10 s) keeps the later
		// expiry; a goodbye removes it.
		for _, e := range c.entries {
			if x.TTL > 0 && e.r.sameData(x) && e.expires.After(expires) {
				expires = e.expires
			}
		}
		c.drop(func(e cached) bool { return e.r.sameData(x) })
		if x.TTL == 0 {
			continue
		}
		x.TTL = uint32(expires.Sub(now) / time.Second)
		c.entries = append(c.entries, cached{r: x, received: now, expires: expires, ifIndex: ifIndex, jitter: rand.Float64() * 0.02})
	}
}

func (c *cache) drop(match func(cached) bool) {
	out := c.entries[:0]
	for _, e := range c.entries {
		if !match(e) {
			out = append(out, e)
		}
	}
	c.entries = out
}

// purge drops expired records.
func (c *cache) purge(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.drop(func(e cached) bool { return !e.expires.After(now) })
}

func (c *cache) live(now time.Time, name string, t dnsmessage.Type) []rr {
	var out []rr
	for _, e := range c.entries {
		if e.expires.After(now) && e.r.Type == t && strings.EqualFold(e.r.Name, name) {
			r := e.r
			r.TTL = uint32(e.expires.Sub(now) / time.Second)
			out = append(out, r)
		}
	}
	return out
}

// pending returns the PTR records of complete instances (known answers)
// and the questions still needed to complete the others.
func (c *cache) pending(typeName string, now time.Time) (known []rr, missing []want) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pendingLocked(typeName, now)
}

func (c *cache) pendingLocked(typeName string, now time.Time) (known []rr, missing []want) {
	for _, p := range c.live(now, typeName, dnsmessage.TypePTR) {
		srv := c.live(now, p.PTR, dnsmessage.TypeSRV)
		txt := c.live(now, p.PTR, dnsmessage.TypeTXT)
		complete := len(srv) > 0 && len(txt) > 0
		if len(srv) == 0 {
			missing = append(missing, want{p.PTR, dnsmessage.TypeSRV})
		}
		if len(txt) == 0 {
			missing = append(missing, want{p.PTR, dnsmessage.TypeTXT})
		}
		if len(srv) > 0 && len(c.live(now, srv[0].Target, dnsmessage.TypeA))+len(c.live(now, srv[0].Target, dnsmessage.TypeAAAA)) == 0 {
			complete = false
			missing = append(missing, want{srv[0].Target, dnsmessage.TypeA}, want{srv[0].Target, dnsmessage.TypeAAAA})
		}
		if complete {
			known = append(known, p)
		}
	}
	return known, missing
}

// queries builds the next query for the types: a PTR question for each
// with the complete instances as known answers, plus direct questions for
// records still missing. It is one packet unless that would exceed
// maxQuery, then one per type.
func (c *cache) queries(typeNames []string, now time.Time) ([][]byte, error) {
	build := func(types []string) ([]byte, error) {
		m := message{}
		for _, t := range types {
			q, err := question(t, dnsmessage.TypePTR, false)
			if err != nil {
				return nil, err
			}
			m.Questions = append(m.Questions, q)
			known, missing := c.pending(t, now)
			m.Answers = append(m.Answers, known...)
			for _, x := range missing {
				if qq, err := question(x.name, x.typ, false); err == nil {
					m.Questions = append(m.Questions, qq)
				}
			}
		}
		return m.pack()
	}
	all, err := build(typeNames)
	if err != nil || len(all) <= maxQuery || len(typeNames) == 1 {
		return [][]byte{all}, err
	}
	var out [][]byte
	for _, t := range typeNames {
		p, err := build([]string{t})
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// due returns the questions for records of the types that have reached
// 80, 85, 90 or 95 % of their TTL (plus up to 2 % random) since they were
// last received, and counts the refresh (RFC 6762 clause 5.2).
func (c *cache) due(typeNames []string, now time.Time) []want {
	c.mu.Lock()
	defer c.mu.Unlock()
	types := map[string]bool{}
	for _, t := range typeNames {
		types[strings.ToLower(t)] = true
	}
	seen := map[want]bool{}
	var out []want
	for i := range c.entries {
		e := &c.entries[i]
		if e.refreshed >= 4 || !e.expires.After(now) {
			continue
		}
		ttl := e.expires.Sub(e.received)
		at := e.received.Add(time.Duration(float64(ttl) * (0.80 + 0.05*float64(e.refreshed) + e.jitter)))
		if now.Before(at) {
			continue
		}
		e.refreshed++
		// A PTR record is refreshed by asking for its type, the others by
		// their own name and type.
		w := want{e.r.Name, e.r.Type}
		if e.r.Type == dnsmessage.TypePTR && !types[strings.ToLower(e.r.Name)] {
			continue
		}
		if k := (want{strings.ToLower(w.name), w.typ}); !seen[k] {
			seen[k] = true
			out = append(out, w)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].name != out[j].name {
			return out[i].name < out[j].name
		}
		return out[i].typ < out[j].typ
	})
	return out
}

// services assembles the instances of typeName that have an SRV record.
func (c *cache) services(typeName string, now time.Time) []Service {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []Service
	seen := map[string]bool{}
	base := typeName
	if i := strings.Index(strings.ToLower(base), "._sub."); i >= 0 {
		base = base[i+len("._sub."):]
	}
	suffix := "." + base
	for _, p := range c.live(now, typeName, dnsmessage.TypePTR) {
		key := strings.ToLower(p.PTR)
		if seen[key] {
			continue
		}
		seen[key] = true
		srv := c.live(now, p.PTR, dnsmessage.TypeSRV)
		if len(srv) == 0 {
			continue
		}
		inst := p.PTR
		if len(inst) > len(suffix) && strings.EqualFold(inst[len(inst)-len(suffix):], suffix) {
			inst = inst[:len(inst)-len(suffix)]
		}
		// A multihomed responder may answer each interface with its own
		// SRV target host (matter.js names hosts per interface MAC), so
		// the addresses of every target are merged. Host and Port come
		// from the first target with a routable address.
		primary := srv[0]
		s := Service{Instance: inst, TXT: map[string]string{}}
		if txt := c.live(now, p.PTR, dnsmessage.TypeTXT); len(txt) > 0 {
			s.TXT = decodeTXT(txt[0].TXT)
		}
		found := false
		for _, sv := range srv {
			for _, t := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
				for _, a := range c.live(now, sv.Target, t) {
					if !found && !a.IP.IsLinkLocalUnicast() {
						primary, found = sv, true
					}
					dup := false
					for _, ip := range s.IPs {
						if ip.Equal(a.IP) {
							dup = true
						}
					}
					if !dup {
						s.IPs = append(s.IPs, a.IP)
					}
				}
			}
		}
		s.Host = strings.TrimSuffix(primary.Target, ".")
		s.Port = int(primary.Port)
		// Routable addresses first: a link-local address is only usable
		// with the zone of the interface it was learned on.
		sort.SliceStable(s.IPs, func(i, j int) bool {
			return !s.IPs[i].IsLinkLocalUnicast() && s.IPs[j].IsLinkLocalUnicast()
		})
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Instance < out[j].Instance })
	return out
}
