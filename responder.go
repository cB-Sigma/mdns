package mdns

import (
	"bytes"
	"slices"
	"sort"
	"strings"
	"sync"

	"golang.org/x/net/dns/dnsmessage"
)

// servicesMeta is the DNS-SD service type enumeration name (RFC 6763
// clause 9).
const servicesMeta = "_services._dns-sd._udp.local."

// responder holds the records of one service and answers questions. It
// does no I/O, so tests drive it with packets built in memory.
type responder struct {
	typeName string   // _matter._tcp.local.
	instName string   // Instance._matter._tcp.local.
	subNames []string // _S3._sub._matterc._udp.local.
	hostName string   // host.local.
	port     uint16

	// mu guards the TXT strings and the address records, which change
	// after Announce (UpdateTXT, interface changes).
	mu       sync.RWMutex
	txt      []string
	fixedIPs []rr         // from Service.IPs
	ifIPs    map[int][]rr // interface index -> address records
	allIPs   []rr         // every address record we may answer with
}

func newResponder(s Service, service string) (*responder, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	txt, err := encodeTXT(s.TXT)
	if err != nil {
		return nil, err
	}
	r := &responder{
		typeName: serviceTypeName(service),
		hostName: hostName(s.Host),
		port:     uint16(s.Port),
		txt:      txt,
		ifIPs:    map[int][]rr{},
	}
	r.instName = s.Instance + "." + r.typeName
	for _, st := range s.Subtypes {
		r.subNames = append(r.subNames, st+"._sub."+r.typeName)
	}
	for _, ip := range s.IPs {
		r.fixedIPs = append(r.fixedIPs, r.addrRR(ip))
	}
	r.allIPs = append(r.allIPs, r.fixedIPs...)
	return r, nil
}

// renamed is a responder for s (the same service under a new instance or
// host name) that keeps the addresses learned from the interfaces.
func (r *responder) renamed(s Service, service string) (*responder, error) {
	nr, err := newResponder(s, service)
	if err != nil {
		return nil, err
	}
	if len(nr.fixedIPs) > 0 {
		return nr, nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for idx, list := range r.ifIPs {
		var ips [][]byte
		for _, x := range list {
			ips = append(ips, x.IP)
		}
		nr.setInterfaceAddrs(idx, ips)
	}
	return nr, nil
}

func (r *responder) addrRR(ip []byte) rr {
	a := rr{Name: r.hostName, TTL: ttlHost, Flush: true, Type: dnsmessage.TypeAAAA, IP: ip}
	if v4 := a.IP.To4(); v4 != nil {
		a.Type, a.IP = dnsmessage.TypeA, v4
	}
	return a
}

// setInterfaceAddrs records the addresses of one interface, used when the
// service has no fixed IPs; it replaces what the interface had and reports
// whether anything changed.
func (r *responder) setInterfaceAddrs(index int, ips [][]byte) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	var list []rr
	for _, ip := range ips {
		list = append(list, r.addrRR(ip))
	}
	old := r.ifIPs[index]
	same := len(old) == len(list)
	for i := 0; same && i < len(list); i++ {
		same = old[i].sameData(list[i])
	}
	if same {
		return false
	}
	r.ifIPs[index] = list
	r.rebuildLocked()
	return true
}

// dropInterface forgets an interface that went away.
func (r *responder) dropInterface(index int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.ifIPs, index)
	r.rebuildLocked()
}

func (r *responder) rebuildLocked() {
	r.allIPs = append([]rr(nil), r.fixedIPs...)
	if len(r.fixedIPs) > 0 {
		return
	}
	idx := make([]int, 0, len(r.ifIPs))
	for i := range r.ifIPs {
		idx = append(idx, i)
	}
	sort.Ints(idx)
	for _, i := range idx {
		r.allIPs = append(r.allIPs, r.ifIPs[i]...)
	}
}

// setTXT replaces the TXT strings.
func (r *responder) setTXT(txt []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.txt = txt
}

// addrs returns the address records to give on an interface.
func (r *responder) addrs(ifIndex int) []rr {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.fixedIPs) > 0 {
		return append([]rr(nil), r.fixedIPs...)
	}
	if a, ok := r.ifIPs[ifIndex]; ok && len(a) > 0 {
		return append([]rr(nil), a...)
	}
	return append([]rr(nil), r.allIPs...)
}

func (r *responder) allAddrs() []rr {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]rr(nil), r.allIPs...)
}

func (r *responder) ptr() rr {
	return rr{Name: r.typeName, Type: dnsmessage.TypePTR, TTL: ttlOther, PTR: r.instName}
}

func (r *responder) srv() rr {
	return rr{Name: r.instName, Type: dnsmessage.TypeSRV, TTL: ttlHost, Flush: true, Target: r.hostName, Port: r.port}
}

func (r *responder) txtRR() rr {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return rr{Name: r.instName, Type: dnsmessage.TypeTXT, TTL: ttlOther, Flush: true, TXT: r.txt}
}

func (r *responder) subPTRs() []rr {
	var out []rr
	for _, n := range r.subNames {
		out = append(out, rr{Name: n, Type: dnsmessage.TypePTR, TTL: ttlOther, PTR: r.instName})
	}
	return out
}

// all returns every record for an interface: PTR (and subtype PTRs), SRV,
// TXT, addresses.
func (r *responder) all(ifIndex int) []rr {
	out := append([]rr{r.ptr()}, r.subPTRs()...)
	out = append(out, r.srv(), r.txtRR())
	return append(out, r.addrs(ifIndex)...)
}

// answer computes the answer and additional records for the questions,
// dropping answers the querier already knows with at least half their TTL
// (known-answer suppression, RFC 6762 clause 7.1).
func (r *responder) answer(qs []dnsmessage.Question, known []rr, ifIndex int) (ans, add []rr) {
	is := func(q dnsmessage.Question, name string, types ...dnsmessage.Type) bool {
		if !strings.EqualFold(q.Name.String(), name) {
			return false
		}
		if q.Type == dnsmessage.TypeALL {
			return true
		}
		for _, t := range types {
			if q.Type == t {
				return true
			}
		}
		return false
	}
	addrs := r.addrs(ifIndex)
	// The negative answers for our two unique names (RFC 6762 clause
	// 6.1): the instance has SRV and TXT, the host the address types it
	// has on this interface. No NSEC is made for a host with no address.
	var hostTypes []dnsmessage.Type
	for _, a := range addrs {
		if !slices.Contains(hostTypes, a.Type) {
			hostTypes = append(hostTypes, a.Type)
		}
	}
	nsecHost := rr{Name: r.hostName, Type: typeNSEC, TTL: ttlHost, Flush: true, Types: hostTypes}
	nsecInst := rr{Name: r.instName, Type: typeNSEC, TTL: ttlHost, Flush: true, Types: []dnsmessage.Type{dnsmessage.TypeTXT, dnsmessage.TypeSRV}}
	// withAddrs adds the host's addresses as additional records and, when
	// one address family is missing, the NSEC that says so (clause 6.2).
	withAddrs := func() {
		add = append(add, addrs...)
		if len(hostTypes) == 1 {
			add = append(add, nsecHost)
		}
	}
	named := func(q dnsmessage.Question, name string) bool { return strings.EqualFold(q.Name.String(), name) }
	for _, q := range qs {
		if dnsmessage.Class(uint16(q.Class)&^topBit) != dnsmessage.ClassINET && q.Class != dnsmessage.ClassANY {
			continue
		}
		if is(q, servicesMeta, dnsmessage.TypePTR) {
			ans = append(ans, rr{Name: servicesMeta, Type: dnsmessage.TypePTR, TTL: ttlOther, PTR: r.typeName})
		}
		if is(q, r.typeName, dnsmessage.TypePTR) {
			ans = append(ans, r.ptr())
			add = append(add, r.srv(), r.txtRR())
			withAddrs()
		}
		for _, sp := range r.subPTRs() {
			if is(q, sp.Name, dnsmessage.TypePTR) {
				ans = append(ans, sp)
				add = append(add, r.srv(), r.txtRR())
				withAddrs()
			}
		}
		if is(q, r.instName, dnsmessage.TypeSRV) {
			ans = append(ans, r.srv())
			withAddrs()
		}
		if is(q, r.instName, dnsmessage.TypeTXT) {
			ans = append(ans, r.txtRR())
		}
		if named(q, r.instName) && q.Type != dnsmessage.TypeALL && q.Type != dnsmessage.TypeSRV && q.Type != dnsmessage.TypeTXT {
			ans = append(ans, nsecInst)
		}
		answered := false
		for _, a := range addrs {
			if is(q, r.hostName, a.Type) {
				ans = append(ans, a)
				answered = true
			}
		}
		if answered && q.Type != dnsmessage.TypeALL {
			// The other family as additional records, or its absence.
			withAddrs()
		}
		if named(q, r.hostName) && !answered && len(hostTypes) > 0 {
			ans = append(ans, nsecHost)
		}
	}
	keep := func(list []rr, drop []rr) []rr {
		var out []rr
	next:
		for _, x := range list {
			for _, d := range drop {
				if x.sameData(d) {
					continue next
				}
			}
			for _, k := range known {
				if x.sameData(k) && k.TTL >= x.TTL/2 {
					continue next
				}
			}
			for _, o := range out {
				if x.sameData(o) {
					continue next
				}
			}
			out = append(out, x)
		}
		return out
	}
	ans = keep(ans, nil)
	if len(ans) == 0 {
		return nil, nil
	}
	add = keep(add, ans)
	return ans, add
}

// reply builds the response to a query received from srcPort. legacy is
// true for a query not sent from the mDNS port (RFC 6762 clause 6.7): the
// reply echoes the ID and questions, caps TTLs and clears cache-flush bits.
func (r *responder) reply(q message, legacy bool, ifIndex int) ([]byte, error) {
	ans, add := r.answer(q.Questions, q.Answers, ifIndex)
	if len(ans) == 0 {
		return nil, nil
	}
	m := message{
		Header:      dnsmessage.Header{Response: true, Authoritative: true},
		Answers:     ans,
		Additionals: add,
	}
	if legacy {
		m.Header.ID = q.Header.ID
		m.Questions = q.Questions
		for _, list := range [][]rr{m.Answers, m.Additionals} {
			for i := range list {
				list[i].Flush = false
				list[i].TTL = min(list[i].TTL, legacyTTL)
			}
		}
		// Questions in a reply carry no QU bit.
		qs := make([]dnsmessage.Question, len(q.Questions))
		for i, x := range q.Questions {
			x.Class = dnsmessage.Class(uint16(x.Class) &^ topBit)
			qs[i] = x
		}
		m.Questions = qs
	}
	return m.pack()
}

// unsolicited builds an announcement (ttl true) or a goodbye (ttl false,
// every TTL 0, RFC 6762 clause 10.1) for an interface.
func (r *responder) unsolicited(ifIndex int, goodbye bool) ([]byte, error) {
	all := r.all(ifIndex)
	if goodbye {
		for i := range all {
			all[i].TTL = 0
		}
	}
	return message{Header: dnsmessage.Header{Response: true, Authoritative: true}, Answers: all}.pack()
}

// probe builds a probe query (RFC 6762 clause 8.1): ANY questions for the
// instance and host names with the proposed records in the authority
// section.
func (r *responder) probe(ifIndex int, first bool) ([]byte, error) {
	qi, err := question(r.instName, dnsmessage.TypeALL, first)
	if err != nil {
		return nil, err
	}
	qh, err := question(r.hostName, dnsmessage.TypeALL, first)
	if err != nil {
		return nil, err
	}
	auth := append([]rr{r.srv(), r.txtRR()}, r.addrs(ifIndex)...)
	return message{Questions: []dnsmessage.Question{qi, qh}, Authorities: auth}.pack()
}

// conflicts reports whether a response from another responder claims our
// instance or host name with other data. Identical data is not a conflict
// (RFC 6762 clause 9). For the host name, a record set that shares an
// address with ours is taken as the same host (the OS responder may hold
// more addresses than we announce).
func (r *responder) conflicts(m message) bool {
	if !m.Header.Response {
		return false
	}
	ours := r.all(0)
	allIPs := r.allAddrs()
	var hostSeen, hostShared bool
	for _, x := range append(append([]rr(nil), m.Answers...), m.Additionals...) {
		switch {
		case strings.EqualFold(x.Name, r.instName) && (x.Type == dnsmessage.TypeSRV || x.Type == dnsmessage.TypeTXT):
			if x.TTL == 0 {
				continue
			}
			match := false
			for _, o := range ours {
				if o.sameData(x) {
					match = true
				}
			}
			if !match {
				return true
			}
		case strings.EqualFold(x.Name, r.hostName) && (x.Type == dnsmessage.TypeA || x.Type == dnsmessage.TypeAAAA):
			if x.TTL == 0 {
				continue
			}
			hostSeen = true
			for _, o := range allIPs {
				if o.sameData(x) {
					hostShared = true
				}
			}
		}
	}
	return hostSeen && !hostShared && len(allIPs) > 0
}

// tieBreak compares another host's probe with ours (RFC 6762 clause 8.2):
// for each name both probe for, the records each proposes in the authority
// section are sorted by class, type and rdata and compared pairwise; the
// first difference decides, and a list that runs out first loses. It
// returns -1 when the other host wins (we defer), 1 when we win or the
// probe does not touch our names, and 0 when the proposals are identical
// (our own probe looped back, or the same host announcing the same data).
func (r *responder) tieBreak(m message, ifIndex int) int {
	if m.Header.Response || len(m.Authorities) == 0 {
		return 1
	}
	ours := append([]rr{r.srv(), r.txtRR()}, r.addrs(ifIndex)...)
	result := 0
	for _, name := range []string{r.instName, r.hostName} {
		var theirs, mine []rr
		for _, x := range m.Authorities {
			if strings.EqualFold(x.Name, name) {
				theirs = append(theirs, x)
			}
		}
		if len(theirs) == 0 {
			continue
		}
		for _, x := range ours {
			if strings.EqualFold(x.Name, name) {
				mine = append(mine, x)
			}
		}
		switch c := compareRecordSets(mine, theirs); {
		case c < 0:
			return -1
		case c > 0:
			result = 1
		}
	}
	if result == 0 {
		// Nothing of ours was named, or every named set was identical.
		for _, x := range m.Authorities {
			if strings.EqualFold(x.Name, r.instName) || strings.EqualFold(x.Name, r.hostName) {
				return 0
			}
		}
		return 1
	}
	return result
}

// compareRecordSets orders two record sets for probe tie-breaking: <0 when
// a is lexicographically earlier (a loses), >0 when later, 0 when equal.
func compareRecordSets(a, b []rr) int {
	sortRecords := func(l []rr) []rr {
		l = append([]rr(nil), l...)
		sort.Slice(l, func(i, j int) bool { return compareRecord(l[i], l[j]) < 0 })
		return l
	}
	a, b = sortRecords(a), sortRecords(b)
	for i := 0; i < len(a) && i < len(b); i++ {
		if c := compareRecord(a[i], b[i]); c != 0 {
			return c
		}
	}
	return len(a) - len(b)
}

// compareRecord compares class (every record here is IN, the cache-flush
// bit left out), then type, then the raw rdata.
func compareRecord(a, b rr) int {
	if a.Type != b.Type {
		if a.Type < b.Type {
			return -1
		}
		return 1
	}
	return bytes.Compare(a.rdata(), b.rdata())
}
