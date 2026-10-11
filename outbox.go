// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package mdns

import (
	"math/rand/v2"
	"net"
	"strconv"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// outKey names one outgoing path: an interface and an address family.
type outKey struct {
	ifIndex int
	v6      bool
}

// outbox holds an announcer's multicast answers that wait to be sent, so
// answers to several queries go out together (RFC 6762 clause 6), and
// remembers when each record was last multicast on each interface, for the
// one-per-second limit (clause 6) and the QU rule (clause 5.4).
type outbox struct {
	mu      sync.Mutex
	pending map[outKey]*batch
	last    map[outKey]map[string]time.Time
	stopped bool
}

type batch struct {
	ans, add []rr
	timer    *time.Timer
}

func (o *outbox) init() {
	o.pending = map[outKey]*batch{}
	o.last = map[outKey]map[string]time.Time{}
}

// admit drops the records multicast on k less than gap ago (none when gap
// is 0) and notes the time of the rest.
func (o *outbox) admit(k outKey, ans, add []rr, gap time.Duration, now time.Time) ([]rr, []rr) {
	o.mu.Lock()
	defer o.mu.Unlock()
	seen := o.last[k]
	if seen == nil {
		seen = map[string]time.Time{}
		o.last[k] = seen
	}
	filter := func(list []rr) []rr {
		var out []rr
		for _, x := range list {
			key := x.key()
			if t, ok := seen[key]; ok && gap > 0 && now.Sub(t) < gap {
				continue
			}
			seen[key] = now
			out = append(out, x)
		}
		return out
	}
	return filter(ans), filter(add)
}

// multicastWithin reports whether every record was multicast on k within
// 1/frac of its TTL.
func (o *outbox) multicastWithin(k outKey, recs []rr, frac int) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	now := time.Now()
	for _, x := range recs {
		t, ok := o.last[k][x.key()]
		if !ok || now.Sub(t) > time.Duration(x.TTL)*time.Second/time.Duration(frac) {
			return false
		}
	}
	return true
}

// suppress drops waiting answers that another responder has just sent
// with at least the TTL we would give (duplicate answer suppression, RFC
// 6762 clause 7.4).
func (o *outbox) suppress(k outKey, m message) {
	o.mu.Lock()
	defer o.mu.Unlock()
	b := o.pending[k]
	if b == nil {
		return
	}
	var keep []rr
next:
	for _, x := range b.ans {
		for _, y := range m.Answers {
			if y.sameData(x) && y.TTL >= x.TTL {
				continue next
			}
		}
		keep = append(keep, x)
	}
	b.ans = keep
}

// stop cancels the waiting answers.
func (o *outbox) stop(a *Announcer) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.stopped = true
	for k, b := range o.pending {
		if b.timer.Stop() {
			a.wg.Done()
		}
		delete(o.pending, k)
	}
}

// multicastNow sends the records on k at once, in as many packets as they
// need, leaving out those multicast there less than gap ago.
func (a *Announcer) multicastNow(k outKey, ans, add []rr, gap time.Duration) {
	ans, add = a.out.admit(k, ans, add, gap, time.Now())
	if len(ans) == 0 {
		return
	}
	pkts, err := packResponse(dnsmessage.Header{Response: true, Authoritative: true}, ans, add, maxPacket)
	if err != nil {
		return
	}
	for _, p := range pkts {
		a.send(p, k, nil)
	}
}

// multicastLater queues the records on k to go out after delay together
// with any answers already waiting there.
func (a *Announcer) multicastLater(k outKey, ans, add []rr, delay time.Duration) {
	a.out.mu.Lock()
	defer a.out.mu.Unlock()
	if a.out.stopped {
		return
	}
	b := a.out.pending[k]
	if b == nil {
		b = &batch{}
		a.out.pending[k] = b
		a.wg.Add(1)
		b.timer = time.AfterFunc(delay, func() {
			defer a.wg.Done()
			a.flushBatch(k, b)
		})
	}
	b.ans = append(b.ans, ans...)
	b.add = append(b.add, add...)
}

func (a *Announcer) flushBatch(k outKey, b *batch) {
	a.out.mu.Lock()
	if a.out.pending[k] == b {
		delete(a.out.pending, k)
	}
	ans, add := dedupe(b.ans, nil), dedupe(b.add, b.ans)
	a.out.mu.Unlock()
	if a.closed() || a.withdrawn.Load() || a.probing.Load() {
		return
	}
	a.multicastNow(k, ans, add, time.Second)
}

// dedupe drops repeated records and those also in skip.
func dedupe(list, skip []rr) []rr {
	var out []rr
next:
	for _, x := range list {
		for _, y := range skip {
			if x.sameData(y) {
				continue next
			}
		}
		for _, y := range out {
			if x.sameData(y) {
				continue next
			}
		}
		out = append(out, x)
	}
	return out
}

// knownAnswerWait holds queries whose known answers continue in further
// packets (TC bit) until those have arrived (RFC 6762 clause 7.2).
type knownAnswerWait struct {
	mu      sync.Mutex
	pending map[string]*kaEntry
	stopped bool
}

type kaEntry struct {
	m       message
	udp     *net.UDPAddr
	ifIndex int
	v6      bool
	timer   *time.Timer
}

// knownAnswerDelay is how long a truncated query waits for the rest of its
// known answers: 400-500 ms (RFC 6762 clause 7.2).
var knownAnswerDelay = func() time.Duration {
	return 400*time.Millisecond + time.Duration(rand.Int64N(int64(100*time.Millisecond)))
}

// collect takes a truncated query, or a further known-answer packet from a
// querier whose truncated query is waiting, and reports whether it did.
func (w *knownAnswerWait) collect(a *Announcer, m message, udp *net.UDPAddr, ifIndex int, v6 bool) bool {
	if udp == nil {
		return false
	}
	key := udp.String() + "/" + strconv.Itoa(ifIndex)
	w.mu.Lock()
	defer w.mu.Unlock()
	e := w.pending[key]
	if e == nil {
		if !m.Header.Truncated || len(m.Questions) == 0 {
			return false
		}
		if w.stopped {
			return true
		}
		if w.pending == nil {
			w.pending = map[string]*kaEntry{}
		}
		e = &kaEntry{m: message{Header: m.Header, Questions: m.Questions, Answers: m.Answers}, udp: udp, ifIndex: ifIndex, v6: v6}
		w.pending[key] = e
		a.wg.Add(1)
		e.timer = time.AfterFunc(knownAnswerDelay(), func() {
			defer a.wg.Done()
			w.mu.Lock()
			if w.pending[key] == e {
				delete(w.pending, key)
			}
			w.mu.Unlock()
			if a.closed() || a.withdrawn.Load() || a.probing.Load() {
				return
			}
			a.respond(e.m, e.udp, e.ifIndex, e.v6, true)
		})
		return true
	}
	e.m.Questions = append(e.m.Questions, m.Questions...)
	e.m.Answers = append(e.m.Answers, m.Answers...)
	return true
}

func (w *knownAnswerWait) stop(a *Announcer) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.stopped = true
	for k, e := range w.pending {
		if e.timer.Stop() {
			a.wg.Done()
		}
		delete(w.pending, k)
	}
}

// hostAddrs lists this host's addresses; tests replace it.
var hostAddrs = net.InterfaceAddrs

// onLink reports whether ip is a link-local or loopback address or lies
// in a subnet of one of this host's interfaces (RFC 6762 clause 11).
func onLink(ip net.IP) bool {
	if ip.IsLinkLocalUnicast() || ip.IsLoopback() {
		return true
	}
	addrs, err := hostAddrs()
	if err != nil {
		return true
	}
	for _, ad := range addrs {
		if n, ok := ad.(*net.IPNet); ok && n.Contains(ip) {
			return true
		}
	}
	return false
}
