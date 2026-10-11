// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package mdns

// Unit tests (no network) for the v0.2.0 behaviour: NSEC, known answers
// over truncated packets, response splitting, cache-flush timing, passive
// observation of failures, duplicate question suppression and the
// conflict limits.

import (
	"bytes"
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// TestNSECWireForm: the restricted NSEC form of RFC 6762 clause 6.1 (next
// name = own name, one bitmap window) is written uncompressed and read
// back, including a next name sent as a compression pointer; malformed
// bitmaps are rejected.
// Covers: SIG-IPE-7340
func TestNSECWireForm(t *testing.T) {
	n := rr{Name: "host.local.", Type: typeNSEC, TTL: 120, Flush: true, Types: []dnsmessage.Type{dnsmessage.TypeAAAA, dnsmessage.TypeA}}
	// A is type 1 (bit 1 of byte 0), AAAA type 28 (bit 4 of byte 3).
	want := append([]byte("\x04host\x05local\x00"), 0, 4, 0x40, 0, 0, 0x08)
	if got := n.rdata(); !bytes.Equal(got, want) {
		t.Fatalf("rdata % x, want % x", got, want)
	}
	pkt, err := message{Header: dnsmessage.Header{Response: true}, Answers: []rr{n, {Name: "host.local.", Type: dnsmessage.TypeA, TTL: 120, IP: net.IPv4(192, 0, 2, 1)}}}.pack()
	if err != nil {
		t.Fatal(err)
	}
	m, err := parse(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Answers) != 2 || m.Answers[0].Type != typeNSEC || !m.Answers[0].sameData(n) || !m.Answers[0].Flush || !m.Answers[0].has(dnsmessage.TypeA) || m.Answers[0].has(dnsmessage.TypeTXT) {
		t.Fatalf("parsed %+v", m.Answers)
	}
	// A next name given as a pointer (some responders compress it).
	types, ok := nsecTypes([]byte{0xC0, 12, 0, 1, 0x40})
	if !ok || fmt.Sprint(types) != fmt.Sprint([]dnsmessage.Type{dnsmessage.TypeA}) {
		t.Fatalf("pointer next name: %v %v", types, ok)
	}
	// Types above 255 use another window.
	if b := nsecBitmap([]dnsmessage.Type{dnsmessage.TypeA, 257}); !bytes.Equal(b, []byte{0, 1, 0x40, 1, 1, 0x40}) {
		t.Fatalf("two windows % x", b)
	}
	for _, bad := range [][]byte{{}, {4, 'h'}, {0, 0, 0}, {0, 0, 33}, {0, 0, 2, 0xff}, {0x80}} {
		if _, ok := nsecTypes(bad); ok {
			t.Errorf("nsecTypes(% x) accepted", bad)
		}
	}
}

func decodeOne(t *testing.T, r *responder, q message) message {
	t.Helper()
	b, err := r.reply(q, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if b == nil {
		return message{}
	}
	m, err := parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func typesOf(list []rr) string {
	var s []string
	for _, x := range list {
		if x.Type == typeNSEC {
			s = append(s, "NSEC")
			continue
		}
		s = append(s, x.Type.String())
	}
	return strings.Join(s, ",")
}

// TestResponderNSEC: for its unique names the responder answers questions
// for types it does not have with NSEC (RFC 6762 clause 6.1), adds the
// NSEC as an additional record when an address family is missing, and
// adds the other family's addresses when it has both (clause 6.2).
// Covers: SIG-IPE-7340
func TestResponderNSEC(t *testing.T) {
	s := testService()
	s.IPs = []net.IP{net.IPv4(192, 0, 2, 7)} // IPv4 only
	r, err := newResponder(s, ServiceType)
	if err != nil {
		t.Fatal(err)
	}
	ask := func(name string, typ dnsmessage.Type) message {
		return decodeOne(t, r, queryPacket(t, 0, []dnsmessage.Question{mustQ(t, name, typ, false)}, nil))
	}
	m := ask("vtn-test.local.", dnsmessage.TypeAAAA)
	if len(m.Answers) != 1 || m.Answers[0].Type != typeNSEC || fmt.Sprint(m.Answers[0].Types) != fmt.Sprint([]dnsmessage.Type{dnsmessage.TypeA}) || !m.Answers[0].Flush {
		t.Fatalf("AAAA for an IPv4-only host: %+v", m.Answers)
	}
	m = ask("vtn-test.local.", dnsmessage.TypeA)
	if typesOf(m.Answers) != "TypeA" || typesOf(m.Additionals) != "NSEC" {
		t.Fatalf("A without AAAA: answers %s additionals %s", typesOf(m.Answers), typesOf(m.Additionals))
	}
	m = ask("Site gateway._openadr3._tcp.local.", dnsmessage.TypeHINFO)
	if len(m.Answers) != 1 || m.Answers[0].Type != typeNSEC || !m.Answers[0].has(dnsmessage.TypeSRV) || !m.Answers[0].has(dnsmessage.TypeTXT) || len(m.Answers[0].Types) != 2 {
		t.Fatalf("HINFO for the instance: %+v", m.Answers)
	}
	m = ask("_openadr3._tcp.local.", dnsmessage.TypePTR)
	if !strings.Contains(typesOf(m.Additionals), "NSEC") {
		t.Fatalf("PTR answer without the host NSEC: %s", typesOf(m.Additionals))
	}
	// A known NSEC is not repeated (known-answer suppression applies).
	nsec := m.Additionals[len(m.Additionals)-1]
	if b, _ := r.reply(queryPacket(t, 0, []dnsmessage.Question{mustQ(t, "vtn-test.local.", dnsmessage.TypeAAAA, false)}, []rr{nsec}), false, 0); b != nil {
		t.Fatal("known NSEC answered again")
	}
	// ANY gets the positive records only.
	m = ask("vtn-test.local.", dnsmessage.TypeALL)
	if typesOf(m.Answers) != "TypeA" {
		t.Fatalf("ANY: %s", typesOf(m.Answers))
	}
	// Names that are not ours get nothing.
	if m := ask("other.local.", dnsmessage.TypeAAAA); len(m.Answers) != 0 {
		t.Fatalf("other host: %+v", m.Answers)
	}

	// With both families an A question brings the AAAA along, no NSEC.
	both, err := newResponder(testService(), ServiceType)
	if err != nil {
		t.Fatal(err)
	}
	m = decodeOne(t, both, queryPacket(t, 0, []dnsmessage.Question{mustQ(t, "vtn-test.local.", dnsmessage.TypeA, false)}, nil))
	if typesOf(m.Additionals) != "TypeAAAA" {
		t.Fatalf("A with both families: additionals %s", typesOf(m.Additionals))
	}
	// A host with no address at all makes no NSEC claim.
	none := testService()
	none.IPs = nil
	rn, err := newResponder(none, ServiceType)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := rn.reply(queryPacket(t, 0, []dnsmessage.Question{mustQ(t, "vtn-test.local.", dnsmessage.TypeAAAA, false)}, nil), false, 0); b != nil {
		t.Fatal("NSEC for a host with no address")
	}
}

// TestBrowserReadsNSEC: an NSEC answer that an instance has no TXT record,
// or a host no AAAA record, ends the questions for them and completes the
// instance (RFC 6762 clause 6.1); an NSEC also removes cached records of
// types it says do not exist, if they are older than a second.
// Covers: SIG-IPE-7340
func TestBrowserReadsNSEC(t *testing.T) {
	r, err := newResponder(testService(), ServiceType)
	if err != nil {
		t.Fatal(err)
	}
	typeName := serviceTypeName(ServiceType)
	now := time.Now()
	c := newCache()
	resp := func(rs ...rr) message { return message{Header: dnsmessage.Header{Response: true}, Answers: rs} }
	c.addFor(resp(r.ptr(), r.srv()), 1, now, []string{typeName}, true)
	_, missing := c.pending(typeName, now)
	if fmt.Sprint(missing) != fmt.Sprint([]want{{r.instName, dnsmessage.TypeTXT}, {r.hostName, dnsmessage.TypeA}, {r.hostName, dnsmessage.TypeAAAA}}) {
		t.Fatalf("missing before NSEC: %v", missing)
	}
	c.addFor(resp(rr{Name: r.instName, Type: typeNSEC, TTL: 120, Flush: true, Types: []dnsmessage.Type{dnsmessage.TypeSRV}},
		rr{Name: r.hostName, Type: typeNSEC, TTL: 120, Flush: true, Types: []dnsmessage.Type{dnsmessage.TypeA}}), 1, now, []string{typeName}, true)
	_, missing = c.pending(typeName, now)
	if fmt.Sprint(missing) != fmt.Sprint([]want{{r.hostName, dnsmessage.TypeA}}) {
		t.Fatalf("missing after NSEC: %v", missing)
	}
	c.addFor(resp(r.addrRR(net.IPv4(192, 0, 2, 7))), 1, now, []string{typeName}, true)
	known, missing := c.pending(typeName, now)
	if len(known) != 1 || len(missing) != 0 {
		t.Fatalf("known %v missing %v", known, missing)
	}
	if got := c.services(typeName, now); len(got) != 1 || len(got[0].TXT) != 0 {
		t.Fatalf("services %+v", got)
	}
	// NSEC records are never refreshed by asking for type NSEC.
	for _, d := range c.due([]string{typeName}, now.Add(119*time.Second)) {
		if d.typ == typeNSEC {
			t.Fatalf("NSEC refreshed: %v", d)
		}
	}
	// An AAAA cached two seconds ago is dropped by an NSEC saying the
	// host has none; one from the same second is kept.
	c = newCache()
	c.addFor(resp(r.ptr(), r.srv(), r.addrRR(net.ParseIP("2001:db8::7"))), 1, now, []string{typeName}, true)
	c.addFor(resp(rr{Name: r.hostName, Type: typeNSEC, TTL: 120, Flush: true, Types: []dnsmessage.Type{dnsmessage.TypeA}}), 1, now.Add(500*time.Millisecond), []string{typeName}, true)
	if len(c.live(now, r.hostName, dnsmessage.TypeAAAA)) != 1 {
		t.Fatal("AAAA from the same second dropped")
	}
	c.addFor(resp(rr{Name: r.hostName, Type: typeNSEC, TTL: 120, Flush: true, Types: []dnsmessage.Type{dnsmessage.TypeA}}), 1, now.Add(2*time.Second), []string{typeName}, true)
	if len(c.live(now.Add(2*time.Second), r.hostName, dnsmessage.TypeAAAA)) != 0 {
		t.Fatal("AAAA kept after NSEC denied it")
	}
}

// TestPackQueryTruncated: known answers that do not fit in one packet go
// on in further packets; the first holds the questions, every packet but
// the last has the TC bit, none is over the limit and no known answer is
// lost (RFC 6762 clause 7.2).
// Covers: SIG-IPE-7341
func TestPackQueryTruncated(t *testing.T) {
	q := mustQ(t, "_openadr3._tcp.local.", dnsmessage.TypePTR, false)
	var known []rr
	for i := range 80 {
		known = append(known, rr{Name: "_openadr3._tcp.local.", Type: dnsmessage.TypePTR, TTL: 4500, PTR: fmt.Sprintf("Gateway number %02d._openadr3._tcp.local.", i)})
	}
	pkts, err := packQuery([]dnsmessage.Question{q}, known, 512)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkts) < 3 {
		t.Fatalf("%d packets", len(pkts))
	}
	var got []rr
	for i, p := range pkts {
		if len(p) > 512 {
			t.Errorf("packet %d is %d bytes", i, len(p))
		}
		m, err := parse(p)
		if err != nil {
			t.Fatal(err)
		}
		if m.Header.Response || m.Header.Truncated != (i < len(pkts)-1) || (len(m.Questions) == 1) != (i == 0) {
			t.Errorf("packet %d: header %+v questions %d", i, m.Header, len(m.Questions))
		}
		got = append(got, m.Answers...)
	}
	if len(got) != len(known) {
		t.Fatalf("%d known answers sent, want %d", len(got), len(known))
	}
	for i := range known {
		if !got[i].sameData(known[i]) {
			t.Fatalf("known answer %d: %+v", i, got[i])
		}
	}
	// Few known answers: one packet, no TC.
	if pkts, _ := packQuery([]dnsmessage.Question{q}, known[:2], 512); len(pkts) != 1 {
		t.Fatalf("short query in %d packets", len(pkts))
	} else if m, _ := parse(pkts[0]); m.Header.Truncated {
		t.Fatal("TC on a complete query")
	}

	// The browser's query for one type with many complete instances.
	c := newCache()
	now := time.Now()
	typeName := serviceTypeName(ServiceType)
	for i := range 60 {
		s := testService()
		s.Instance = fmt.Sprintf("Gateway number %02d", i)
		s.Host = fmt.Sprintf("gw%02d", i)
		r, err := newResponder(s, ServiceType)
		if err != nil {
			t.Fatal(err)
		}
		c.add(message{Header: dnsmessage.Header{Response: true}, Answers: append([]rr{r.ptr(), r.srv(), r.txtRR()}, r.addrs(0)...)}, now)
	}
	train, err := c.queries([]string{typeName}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(train) < 2 {
		t.Fatalf("60 known answers in %d packet", len(train))
	}
	first, _ := parse(train[0])
	last, _ := parse(train[len(train)-1])
	if !first.Header.Truncated || len(first.Questions) != 1 || last.Header.Truncated {
		t.Fatalf("first %+v last %+v", first.Header, last.Header)
	}
}

// TestPackResponseSplit: a response too long for one packet is split
// between answers, and additional records are added while they fit.
// Covers: SIG-IPE-7343
func TestPackResponseSplit(t *testing.T) {
	var ans []rr
	for i := range 40 {
		ans = append(ans, rr{Name: "_sub" + fmt.Sprint(i) + "._sub._matterc._udp.local.", Type: dnsmessage.TypePTR, TTL: 4500, PTR: "ABCDEF0123456789._matterc._udp.local."})
	}
	add := []rr{{Name: "h.local.", Type: dnsmessage.TypeA, TTL: 120, Flush: true, IP: net.IPv4(192, 0, 2, 1)}}
	pkts, err := packResponse(dnsmessage.Header{Response: true, Authoritative: true}, ans, add, 600)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkts) < 2 {
		t.Fatalf("%d packets", len(pkts))
	}
	n, addSeen := 0, 0
	for _, p := range pkts {
		if len(p) > 600 {
			t.Errorf("packet of %d bytes", len(p))
		}
		m, _ := parse(p)
		if m.Header.Truncated || !m.Header.Response {
			t.Errorf("header %+v", m.Header)
		}
		n += len(m.Answers)
		addSeen += len(m.Additionals)
	}
	if n != len(ans) || addSeen != 1 {
		t.Fatalf("answers %d additionals %d", n, addSeen)
	}
}

// TestPassiveObservationOfFailures: queries from other hosts that ask for
// a cached record without listing it as known, at least two of them,
// with no answer for poofWindow, remove the record (RFC 6762 clause
// 10.5). QU questions, queries listing the record and records only heard
// in unicast replies do not count; an answer resets the count.
// Covers: SIG-IPE-7345
func TestPassiveObservationOfFailures(t *testing.T) {
	r, err := newResponder(testService(), ServiceType)
	if err != nil {
		t.Fatal(err)
	}
	typeName := serviceTypeName(ServiceType)
	now := time.Now()
	full := message{Header: dnsmessage.Header{Response: true}, Answers: append([]rr{r.ptr(), r.srv(), r.txtRR()}, r.addrs(0)...)}
	c := newCache()
	c.addFor(full, 1, now, []string{typeName}, true)
	ptrQ := queryPacket(t, 0, []dnsmessage.Question{mustQ(t, typeName, dnsmessage.TypePTR, false)}, nil)
	quQ := queryPacket(t, 0, []dnsmessage.Question{mustQ(t, typeName, dnsmessage.TypePTR, true)}, nil)
	knownQ := queryPacket(t, 0, []dnsmessage.Question{mustQ(t, typeName, dnsmessage.TypePTR, false)}, []rr{r.ptr()})

	c.observeQuery(quQ, now)
	c.observeQuery(knownQ, now)
	c.observeQuery(ptrQ, now)
	c.expireSilent(now.Add(time.Hour))
	if len(c.services(typeName, now)) != 1 {
		t.Fatal("one query was enough to drop the record")
	}
	c.observeQuery(ptrQ, now.Add(time.Second))
	c.expireSilent(now.Add(poofWindow - time.Millisecond))
	if len(c.services(typeName, now)) != 1 {
		t.Fatal("dropped before the window")
	}
	c.expireSilent(now.Add(poofWindow))
	if len(c.services(typeName, now)) != 0 {
		t.Fatal("not dropped after two unanswered queries")
	}

	// An answer between the queries starts over.
	c = newCache()
	c.addFor(full, 1, now, []string{typeName}, true)
	c.observeQuery(ptrQ, now)
	c.addFor(message{Header: dnsmessage.Header{Response: true}, Answers: []rr{r.ptr()}}, 1, now.Add(time.Second), []string{typeName}, true)
	c.observeQuery(ptrQ, now.Add(2*time.Second))
	c.expireSilent(now.Add(time.Minute))
	if len(c.services(typeName, now.Add(3*time.Second))) != 1 {
		t.Fatal("answered record dropped")
	}

	// Records only heard in unicast replies are left alone.
	c = newCache()
	c.addFor(full, 1, now, []string{typeName}, false)
	c.observeQuery(ptrQ, now)
	c.observeQuery(ptrQ, now.Add(time.Second))
	c.expireSilent(now.Add(time.Minute))
	if len(c.services(typeName, now.Add(2*time.Second))) != 1 {
		t.Fatal("unicast-only record dropped")
	}
}

// TestReconfirmDeadline: records marked for reconfirmation are dropped at
// the deadline unless received again (RFC 6762 clause 10.4).
// Covers: SIG-IPE-7346
func TestReconfirmDeadline(t *testing.T) {
	r, err := newResponder(testService(), ServiceType)
	if err != nil {
		t.Fatal(err)
	}
	typeName := serviceTypeName(ServiceType)
	now := time.Now()
	c := newCache()
	c.add(message{Header: dnsmessage.Header{Response: true}, Answers: []rr{r.ptr(), r.srv(), r.txtRR()}}, now)
	qs := c.markReconfirm(func(x rr) bool { return x.Type == dnsmessage.TypeSRV }, now.Add(10*time.Second))
	if fmt.Sprint(qs) != fmt.Sprint([]want{{r.instName, dnsmessage.TypeSRV}}) {
		t.Fatalf("questions %v", qs)
	}
	c.expireSilent(now.Add(9 * time.Second))
	if len(c.services(typeName, now)) != 1 {
		t.Fatal("dropped early")
	}
	c.expireSilent(now.Add(10 * time.Second))
	if len(c.services(typeName, now)) != 0 {
		t.Fatal("not dropped at the deadline")
	}
	// Received again: the mark goes.
	c.add(message{Header: dnsmessage.Header{Response: true}, Answers: []rr{r.srv()}}, now)
	c.markReconfirm(func(x rr) bool { return x.Type == dnsmessage.TypeSRV }, now.Add(10*time.Second))
	c.add(message{Header: dnsmessage.Header{Response: true}, Answers: []rr{r.srv()}}, now.Add(time.Second))
	c.expireSilent(now.Add(11 * time.Second))
	if len(c.services(typeName, now.Add(11*time.Second))) != 1 {
		t.Fatal("reconfirmed record dropped")
	}
}

// TestDuplicateQuestionSuppression: a refresh question another host has
// just asked with no known answers is not asked again (RFC 6762 clause
// 7.3); one asked with known answers, a QU question or one asked longer
// ago still is.
// Covers: SIG-IPE-7347
func TestDuplicateQuestionSuppression(t *testing.T) {
	w := &Watcher{opts: Options{Port: 5353}, c: newCache(), asked: map[want]time.Time{}}
	src := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 9), Port: 5353}
	srvQ := mustQ(t, "Site gateway._openadr3._tcp.local.", dnsmessage.TypeSRV, false)
	txtQ := mustQ(t, "Site gateway._openadr3._tcp.local.", dnsmessage.TypeTXT, true)
	aQ := mustQ(t, "vtn-test.local.", dnsmessage.TypeA, false)
	w.observe(queryPacket(t, 0, []dnsmessage.Question{srvQ, txtQ}, nil), src, 1)
	w.observe(queryPacket(t, 0, []dnsmessage.Question{aQ}, []rr{{Name: "vtn-test.local.", Type: dnsmessage.TypeA, TTL: 120, IP: net.IPv4(192, 0, 2, 1)}}), src, 1)
	// A one-shot querier's question is answered by unicast, which we do
	// not hear, so it does not count.
	w.observe(queryPacket(t, 0, []dnsmessage.Question{mustQ(t, "_x._tcp.local.", dnsmessage.TypePTR, false)}, nil), &net.UDPAddr{IP: src.IP, Port: 40000}, 1)
	due := []want{{"Site Gateway._openadr3._tcp.local.", dnsmessage.TypeSRV}, {"Site gateway._openadr3._tcp.local.", dnsmessage.TypeTXT}, {"vtn-test.local.", dnsmessage.TypeA}, {"_x._tcp.local.", dnsmessage.TypePTR}}
	got := w.unasked(due, time.Now())
	if fmt.Sprint(got) != fmt.Sprint(due[1:]) {
		t.Fatalf("unasked %v", got)
	}
	if got := w.unasked(due, time.Now().Add(2*dupQuestionWindow)); len(got) != 4 {
		t.Fatalf("after the window %v", got)
	}
}

// TestOnLink: the source check of RFC 6762 clause 11 accepts link-local,
// loopback and on-subnet addresses and refuses others.
// Covers: SIG-IPE-7348
func TestOnLink(t *testing.T) {
	old := hostAddrs
	hostAddrs = func() ([]net.Addr, error) {
		return []net.Addr{&net.IPNet{IP: net.IPv4(192, 0, 2, 10), Mask: net.CIDRMask(24, 32)}}, nil
	}
	t.Cleanup(func() { hostAddrs = old })
	for ip, want := range map[string]bool{"192.0.2.99": true, "169.254.1.1": true, "fe80::1": true, "127.0.0.1": true, "198.51.100.1": false, "2001:db8::1": false} {
		if got := onLink(net.ParseIP(ip)); got != want {
			t.Errorf("onLink(%s) = %v", ip, got)
		}
	}
	// The announcer drops a response sent to its unicast address from off
	// the link, but takes the same response sent to the group.
	r, err := newResponder(testService(), ServiceType)
	if err != nil {
		t.Fatal(err)
	}
	other := r.srv()
	other.Port = 9
	pkt, err := message{Header: dnsmessage.Header{Response: true}, Answers: []rr{other}}.pack()
	if err != nil {
		t.Fatal(err)
	}
	a := &Announcer{port: 5353, done: make(chan struct{})}
	a.rp.Store(r)
	a.probing.Store(true)
	off := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 5353}
	a.handle(pkt, off, net.IPv4(192, 0, 2, 10), 1, false)
	if a.conflict.Load() {
		t.Fatal("off-link unicast response taken")
	}
	a.handle(pkt, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 50), Port: 40000}, group4, 1, false)
	if a.conflict.Load() {
		t.Fatal("response from a port other than the mDNS port taken")
	}
	a.handle(pkt, off, group4, 1, false)
	if !a.conflict.Load() {
		t.Fatal("multicast response not taken")
	}
	// Responses with an error code are ignored (RFC 6762 clause 18.11).
	a.conflict.Store(false)
	bad, _ := message{Header: dnsmessage.Header{Response: true, RCode: dnsmessage.RCodeServerFailure}, Answers: []rr{other}}.pack()
	a.handle(bad, off, group4, 1, false)
	if a.conflict.Load() {
		t.Fatal("response with an error code taken")
	}
}

// TestConflictLimit: after 15 conflicts within ten seconds the next probe
// waits five seconds (RFC 6762 clause 8.1); older conflicts do not count.
// Covers: SIG-IPE-7344
func TestConflictLimit(t *testing.T) {
	a := &Announcer{}
	now := time.Now()
	for i := range conflictLimit - 1 {
		a.noteConflict(now.Add(time.Duration(i) * 100 * time.Millisecond))
	}
	if d := a.conflictBackoff(now.Add(2 * time.Second)); d != 0 {
		t.Fatalf("backoff after 14: %v", d)
	}
	a.noteConflict(now.Add(2 * time.Second))
	if d := a.conflictBackoff(now.Add(2 * time.Second)); d != conflictPause {
		t.Fatalf("backoff after 15: %v", d)
	}
	if d := a.conflictBackoff(now.Add(11 * time.Second)); d != 0 {
		t.Fatalf("backoff after the window: %v", d)
	}
}

// TestRenameSkipsSameName: an ongoing rename numbers on from the renames
// made so far and skips a result that would keep the name.
// Covers: SIG-IPE-7344
func TestRenameSkipsSameName(t *testing.T) {
	s := testService()
	s.Instance = "Site gateway (2)"
	r, err := newResponder(s, ServiceType)
	if err != nil {
		t.Fatal(err)
	}
	var attempts []int
	a := &Announcer{service: ServiceType, svc: s, opts: Options{Rename: func(s Service, n int) Service {
		attempts = append(attempts, n)
		return RenameInstance(s, n)
	}}}
	a.rp.Store(r)
	if err := a.rename(s); err != nil {
		t.Fatal(err)
	}
	if got := a.Service().Instance; got != "Site gateway (3)" || !slices.Equal(attempts, []int{1, 2}) {
		t.Fatalf("renamed to %q after attempts %v", got, attempts)
	}
	if !strings.HasPrefix(a.r().instName, "Site gateway (3).") || !a.r().fixedIPs[0].IP.Equal(net.IPv4(192, 0, 2, 7)) {
		t.Fatalf("responder %s %+v", a.r().instName, a.r().fixedIPs)
	}
}
