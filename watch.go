// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package mdns

import (
	"context"
	"maps"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// EventKind says what happened to a watched instance.
type EventKind int

// The event kinds.
const (
	// Added: an instance was found (its SRV record arrived).
	Added EventKind = iota + 1
	// Updated: its host, port, addresses or TXT record changed.
	Updated
	// Removed: it said goodbye (TTL 0) or its records expired without
	// being refreshed.
	Removed
)

func (k EventKind) String() string {
	switch k {
	case Added:
		return "added"
	case Updated:
		return "updated"
	case Removed:
		return "removed"
	}
	return "unknown"
}

// Event is one change seen by a Watcher. Type is the service type as given
// to Watch; for Removed, Service is the instance as last seen.
type Event struct {
	Kind    EventKind
	Type    string
	Service Service
}

// MaxQueryInterval caps the gap between a Watcher's periodic queries
// (RFC 6762 clause 5.2 says at most one hour).
var MaxQueryInterval = time.Hour

// watchTick is how often a Watcher checks for records to refresh and for
// expiry.
var watchTick = 250 * time.Millisecond

// Watcher browses continuously for one or more service types over one set
// of sockets. It queries at start like Browse, then at intervals that
// double up to MaxQueryInterval; it keeps every announcement heard on the
// mDNS port (with the default BrowseBoth or BrowseMulticast mode); it asks
// again for each record at 80, 85, 90 and 95 % of its TTL, so instances
// that only answer queries stay known; and it reports instances that
// appear, change and leave.
type Watcher struct {
	services []string // as given
	names    []string // fully qualified
	opts     Options
	ifaces   []net.Interface
	q        *querier
	c        *cache
	fn       func(Event)

	mu   sync.Mutex
	last map[string]map[string]Service // type -> lower-cased instance -> service
	// asked holds when another host last asked each question with no
	// known answers for it, for duplicate question suppression (RFC 6762
	// clause 7.3).
	asked map[want]time.Time
	// again are the re-sends of reconfirmation queries still to come.
	again []resend

	dirty   chan struct{}
	settled chan struct{}
	done    chan struct{}
	stop    context.CancelFunc
	wg      sync.WaitGroup
	once    sync.Once
}

// Watch starts watching the service types until Close or the end of ctx.
// fn, when not nil, is called for every change, one call at a time, from
// the Watcher's own goroutine; it must not call Close. opts.Wait (or
// DefaultWait) sets when Settled is closed: by then the first queries have
// had the time a Browse gives them.
func Watch(ctx context.Context, services []string, opts Options, fn func(Event)) (*Watcher, error) {
	names, err := typeNames(services)
	if err != nil {
		return nil, err
	}
	ifaces, err := opts.interfaces()
	if err != nil {
		return nil, err
	}
	ctx, stop := context.WithCancel(ctx)
	w := &Watcher{services: services, names: names, opts: opts, ifaces: ifaces, c: newCache(), fn: fn,
		last: map[string]map[string]Service{}, asked: map[want]time.Time{}, dirty: make(chan struct{}, 1), settled: make(chan struct{}),
		done: make(chan struct{}), stop: stop}
	w.q, err = newQuerier(ctx, opts, ifaces, func(m message, ifIndex int, mc bool) {
		w.c.addFor(m, ifIndex, time.Now(), names, mc)
		select {
		case w.dirty <- struct{}{}:
		default:
		}
	}, w.observe)
	if err != nil {
		stop()
		return nil, err
	}
	wait := opts.Wait
	if wait <= 0 {
		wait = DefaultWait
	}
	w.wg.Add(1)
	go w.loop(ctx, wait)
	return w, nil
}

// Settled is closed once the first round of queries has had opts.Wait (or
// DefaultWait) to be answered, or when the Watcher stops.
func (w *Watcher) Settled() <-chan struct{} { return w.settled }

// Done is closed when the Watcher has stopped.
func (w *Watcher) Done() <-chan struct{} { return w.done }

// Services returns the instances of service (one of the types given to
// Watch) known now, sorted by instance name.
func (w *Watcher) Services(service string) []Service {
	for i, s := range w.services {
		if s == service {
			return w.c.services(w.names[i], time.Now())
		}
	}
	return nil
}

// Close stops watching and closes the sockets. It is safe to call more
// than once.
func (w *Watcher) Close() error {
	w.stop()
	<-w.done
	return nil
}

func (w *Watcher) loop(ctx context.Context, wait time.Duration) {
	defer w.wg.Done()
	defer func() {
		w.q.close()
		w.once.Do(func() {
			select {
			case <-w.settled:
			default:
				close(w.settled)
			}
			close(w.done)
		})
	}()
	start := time.Now()
	settleAt := start.Add(wait)
	// The opening train follows queryAt; then the gap doubles up to
	// MaxQueryInterval (RFC 6762 clause 5.2).
	next, qi := start, 0
	gap := queryAt[len(queryAt)-1] - queryAt[len(queryAt)-2]
	lastIface := start
	tick := time.NewTicker(watchTick)
	defer tick.Stop()
	for {
		now := time.Now()
		if !now.Before(next) {
			if pkts, err := w.c.queries(w.names, now); err == nil {
				for _, p := range pkts {
					w.q.send(p)
				}
			}
			qi++
			if qi < len(queryAt) {
				next = start.Add(queryAt[qi])
			} else {
				gap = min(2*gap, MaxQueryInterval)
				next = now.Add(gap)
			}
		}
		if due := w.c.due(w.names, now); len(due) > 0 {
			w.refresh(w.unasked(due, now))
		}
		w.resendReconfirms(now)
		w.c.expireSilent(now)
		if now.Sub(lastIface) >= ifaceCheck {
			lastIface = now
			if cur := currentInterfaces(w.opts); len(cur) > 0 && w.q.setInterfaces(cur) {
				// A new interface: ask there at once.
				if pkts, err := w.c.queries(w.names, now); err == nil {
					for _, p := range pkts {
						w.q.send(p)
					}
				}
			}
		}
		w.c.purge(now)
		w.diff(now)
		if !now.Before(settleAt) {
			select {
			case <-w.settled:
			default:
				close(w.settled)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		case <-w.dirty:
		}
	}
}

// observe takes a query another host multicast from the mDNS port (a
// one-shot querier gets unicast answers this Watcher cannot hear, so its
// queries say nothing): it counts towards passive observation of failures
// (RFC 6762 clause 10.5) and notes questions asked with no known answers,
// for duplicate question suppression (clause 7.3). Probes are left out.
func (w *Watcher) observe(m message, src *net.UDPAddr, ifIndex int) {
	if src.Port != w.opts.port() || len(m.Authorities) > 0 {
		return
	}
	now := time.Now()
	w.c.observeQuery(m, now)
	w.mu.Lock()
	defer w.mu.Unlock()
	for k, t := range w.asked {
		if now.Sub(t) > dupQuestionWindow {
			delete(w.asked, k)
		}
	}
next:
	for _, q := range m.Questions {
		if uint16(q.Class)&topBit != 0 {
			continue
		}
		name := q.Name.String()
		for _, k := range m.Answers {
			if strings.EqualFold(k.Name, name) {
				continue next
			}
		}
		w.asked[want{strings.ToLower(name), q.Type}] = now
	}
}

// dupQuestionWindow is how recently another host must have asked a
// question for this Watcher to treat its own as sent (RFC 6762 clause
// 7.3).
var dupQuestionWindow = time.Second

// unasked drops from due the questions another host asked within
// dupQuestionWindow.
func (w *Watcher) unasked(due []want, now time.Time) []want {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []want
	for _, x := range due {
		if t, ok := w.asked[want{strings.ToLower(x.name), x.typ}]; ok && now.Sub(t) <= dupQuestionWindow {
			continue
		}
		out = append(out, x)
	}
	return out
}

// resend is a reconfirmation query still to be sent.
type resend struct {
	qs []want
	at time.Time
}

// reconfirmWait is how long a reconfirmed record lives without an answer;
// reconfirmAt are the offsets of the queries sent for it (RFC 6762 clause
// 10.4).
var (
	reconfirmWait = 10 * time.Second
	reconfirmAt   = []time.Duration{0, time.Second, 3 * time.Second}
)

// Reconfirm asks the network whether instance (its label, as in
// Service.Instance) of service (one of the types given to Watch) is still
// there, for when a connection to it failed: the Watcher queries for its
// PTR, SRV, TXT and address records several times, and removes those that
// get no answer within ten seconds, reporting Removed when the instance
// goes (RFC 6762 clause 10.4). It returns false when the instance is not
// known.
func (w *Watcher) Reconfirm(service, instance string) bool {
	typeName := ""
	for i, s := range w.services {
		if s == service {
			typeName = w.names[i]
		}
	}
	if typeName == "" {
		return false
	}
	base := typeName
	if i := strings.Index(strings.ToLower(base), "._sub."); i >= 0 {
		base = base[i+len("._sub."):]
	}
	inst := instance + "." + base
	now := time.Now()
	w.c.mu.Lock()
	var hosts []string
	for _, s := range w.c.live(now, inst, dnsmessage.TypeSRV) {
		hosts = append(hosts, s.Target)
	}
	w.c.mu.Unlock()
	qs := w.c.markReconfirm(func(r rr) bool {
		switch r.Type {
		case dnsmessage.TypePTR:
			return strings.EqualFold(r.PTR, inst)
		case dnsmessage.TypeA, dnsmessage.TypeAAAA:
			return slices.ContainsFunc(hosts, func(h string) bool { return strings.EqualFold(h, r.Name) })
		}
		return strings.EqualFold(r.Name, inst)
	}, now.Add(reconfirmWait))
	if len(qs) == 0 {
		return false
	}
	w.mu.Lock()
	for _, at := range reconfirmAt {
		w.again = append(w.again, resend{qs: qs, at: now.Add(at)})
	}
	w.mu.Unlock()
	select {
	case w.dirty <- struct{}{}:
	default:
	}
	return true
}

// resendReconfirms sends the reconfirmation queries that are due.
func (w *Watcher) resendReconfirms(now time.Time) {
	w.mu.Lock()
	var due [][]want
	keep := w.again[:0]
	for _, r := range w.again {
		if now.Before(r.at) {
			keep = append(keep, r)
			continue
		}
		due = append(due, r.qs)
	}
	w.again = keep
	w.mu.Unlock()
	for _, qs := range due {
		w.refresh(qs)
	}
}

// refresh asks for the records that are due.
func (w *Watcher) refresh(due []want) {
	m := message{}
	for _, x := range due {
		if q, err := question(x.name, x.typ, false); err == nil {
			m.Questions = append(m.Questions, q)
		}
	}
	if len(m.Questions) == 0 {
		return
	}
	if p, err := m.pack(); err == nil && len(p) <= maxQuery {
		w.q.send(p)
		return
	}
	for _, q := range m.Questions {
		if p, err := (message{Questions: []dnsmessage.Question{q}}).pack(); err == nil {
			w.q.send(p)
		}
	}
}

// diff compares what the cache holds with what was last reported and
// calls fn for each change.
func (w *Watcher) diff(now time.Time) {
	var events []Event
	w.mu.Lock()
	for i, svc := range w.services {
		cur := map[string]Service{}
		for _, s := range w.c.services(w.names[i], now) {
			cur[strings.ToLower(s.Instance)] = s
		}
		prev := w.last[svc]
		for k, s := range cur {
			old, ok := prev[k]
			switch {
			case !ok:
				events = append(events, Event{Kind: Added, Type: svc, Service: s})
			case !sameService(old, s):
				events = append(events, Event{Kind: Updated, Type: svc, Service: s})
			}
		}
		for k, s := range prev {
			if _, ok := cur[k]; !ok {
				events = append(events, Event{Kind: Removed, Type: svc, Service: s})
			}
		}
		w.last[svc] = cur
	}
	w.mu.Unlock()
	if w.fn == nil {
		return
	}
	slices.SortStableFunc(events, func(a, b Event) int {
		if a.Type != b.Type {
			return strings.Compare(a.Type, b.Type)
		}
		return strings.Compare(a.Service.Instance, b.Service.Instance)
	})
	for _, e := range events {
		w.fn(e)
	}
}

func sameService(a, b Service) bool {
	if a.Host != b.Host || a.Port != b.Port || !maps.Equal(a.TXT, b.TXT) || len(a.IPs) != len(b.IPs) {
		return false
	}
	for i := range a.IPs {
		if !a.IPs[i].Equal(b.IPs[i]) {
			return false
		}
	}
	return true
}
