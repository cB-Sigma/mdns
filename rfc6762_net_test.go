// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package mdns

// Network tests (multicast on a random port) for the v0.2.0 behaviour:
// the announcer against a hand-driven peer, and Watch's passive
// observation, reconfirmation and service type enumeration.

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// TestKnownAnswersOverTruncatedPackets: a query with the TC bit is held
// 400-500 ms for the rest of its known answers; a known answer that comes
// in a following packet suppresses our answer, and without one the answer
// follows the wait (RFC 6762 clause 7.2).
// Covers: SIG-IPE-7341
func TestKnownAnswersOverTruncatedPackets(t *testing.T) {
	port, ifi := testPort(t)
	setVar(t, &announceAt, []time.Duration{0})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	svc := testService()
	svc.IPs = nil
	a, err := Announce(ctx, svc, ServiceType, Options{Interfaces: []net.Interface{*ifi}, Port: port, Loopback: true})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	peer := newRawPeer(t, port, ifi)
	time.Sleep(1100 * time.Millisecond) // past the per-record limit after the announcement
	r := a.r()
	q := mustQ(t, r.typeName, dnsmessage.TypePTR, false)
	other := rr{Name: r.typeName, Type: dnsmessage.TypePTR, TTL: 4500, PTR: "Other._openadr3._tcp.local."}
	ours := func(h heard) bool { return answersWith(h, r.ptr()) }

	t0 := time.Now()
	peer.send(message{Header: dnsmessage.Header{Truncated: true}, Questions: []dnsmessage.Question{q}, Answers: []rr{other}})
	time.Sleep(100 * time.Millisecond)
	peer.send(message{Answers: []rr{r.ptr()}})
	if h, ok := peer.await(t0, 1200*time.Millisecond, ours); ok {
		t.Fatalf("answered %v after the query although its second packet listed the answer", h.at.Sub(t0))
	}

	t1 := time.Now()
	peer.send(message{Header: dnsmessage.Header{Truncated: true}, Questions: []dnsmessage.Question{q}, Answers: []rr{other}})
	h, ok := peer.await(t1, 2*time.Second, ours)
	if !ok {
		t.Fatal("truncated query never answered")
	}
	if d := h.at.Sub(t1); d < 380*time.Millisecond {
		t.Fatalf("answered after %v, before waiting for more known answers", d)
	}
}

// TestResponseTimingAndLimits: answers made of unique records go out at
// once and those with shared records after the 20-120 ms delay (here
// lengthened), answers to queries in that window go out together, a
// record is multicast at most once a second except in defence against a
// probe (every 250 ms), an answer another responder has just given is not
// repeated, and a QU question gets a unicast reply unless the record has
// not been multicast lately (RFC 6762 clauses 5.4, 6 and 7.4).
// Covers: SIG-IPE-7342
func TestResponseTimingAndLimits(t *testing.T) {
	port, ifi := testPort(t)
	setVar(t, &announceAt, []time.Duration{0})
	setVar(t, &sharedDelay, func() time.Duration { return 300 * time.Millisecond })
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	svc := testService()
	svc.IPs = nil
	svc.Subtypes = []string{"_vtn"}
	a, err := Announce(ctx, svc, ServiceType, Options{Interfaces: []net.Interface{*ifi}, Port: port, Loopback: true})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	peer := newRawPeer(t, port, ifi)
	time.Sleep(1100 * time.Millisecond)
	r := a.r()
	ask := func(qs ...dnsmessage.Question) { peer.send(message{Questions: qs}) }
	srvQ := mustQ(t, r.instName, dnsmessage.TypeSRV, false)
	hasSRV := func(h heard) bool { return h.mcast && answersWith(h, r.srv()) }

	t.Run("unique answer at once, then once a second", func(t *testing.T) {
		t0 := time.Now()
		ask(srvQ)
		h, ok := peer.await(t0, time.Second, hasSRV)
		if !ok {
			t.Fatal("SRV question not answered")
		}
		if d := h.at.Sub(t0); d > 200*time.Millisecond {
			t.Errorf("unique answer after %v", d)
		}
		t1 := time.Now()
		ask(srvQ)
		if _, ok := peer.await(t1, 600*time.Millisecond, hasSRV); ok {
			t.Error("SRV multicast twice within a second")
		}
		time.Sleep(time.Until(h.at.Add(1100 * time.Millisecond)))
		t2 := time.Now()
		ask(srvQ)
		if _, ok := peer.await(t2, time.Second, hasSRV); !ok {
			t.Error("SRV not answered a second later")
		}
	})

	t.Run("shared answers delayed and aggregated", func(t *testing.T) {
		sub := r.subPTRs()[0]
		t0 := time.Now()
		ask(mustQ(t, r.typeName, dnsmessage.TypePTR, false))
		time.Sleep(50 * time.Millisecond)
		ask(mustQ(t, sub.Name, dnsmessage.TypePTR, false))
		h, ok := peer.await(t0, 2*time.Second, func(h heard) bool { return h.mcast && answersWith(h, r.ptr()) })
		if !ok {
			t.Fatal("PTR question not answered")
		}
		if d := h.at.Sub(t0); d < 280*time.Millisecond {
			t.Errorf("shared answer after %v", d)
		}
		if !answersWith(h, sub) {
			t.Errorf("the two answers went out apart: %+v", h.m.Answers)
		}
		time.Sleep(300 * time.Millisecond)
		if n := len(peer.since(t0, func(h heard) bool { return answersWith(h, r.ptr()) })); n != 1 {
			t.Errorf("%d responses with the PTR", n)
		}
	})

	t.Run("probe defence every 250 ms", func(t *testing.T) {
		time.Sleep(1100 * time.Millisecond)
		bad := r.srv()
		bad.Port = 9
		probe := message{Questions: []dnsmessage.Question{mustQ(t, r.instName, dnsmessage.TypeALL, false)}, Authorities: []rr{bad}}
		t0 := time.Now()
		peer.send(probe)
		time.Sleep(300 * time.Millisecond)
		peer.send(probe)
		time.Sleep(300 * time.Millisecond)
		if n := len(peer.since(t0, hasSRV)); n != 2 {
			t.Errorf("%d defences, want 2", n)
		}
	})

	t.Run("duplicate answer suppression", func(t *testing.T) {
		time.Sleep(1100 * time.Millisecond)
		t0 := time.Now()
		ask(mustQ(t, r.typeName, dnsmessage.TypePTR, false))
		time.Sleep(50 * time.Millisecond)
		peer.send(message{Header: dnsmessage.Header{Response: true, Authoritative: true}, Answers: []rr{r.ptr()}})
		time.Sleep(700 * time.Millisecond)
		if list := peer.since(t0, func(h heard) bool { return answersWith(h, r.ptr()) && len(h.m.Additionals) > 0 }); len(list) != 0 {
			t.Errorf("answered although another responder just gave the answer")
		}
	})

	t.Run("QU", func(t *testing.T) {
		time.Sleep(1100 * time.Millisecond)
		quTXT := mustQ(t, r.instName, dnsmessage.TypeTXT, true)
		hasTXT := func(h heard) bool { return h.mcast && answersWith(h, r.txtRR()) }
		t0 := time.Now()
		ask(quTXT)
		if _, ok := peer.await(t0, 500*time.Millisecond, hasTXT); ok {
			t.Error("QU question answered by multicast although the TXT was multicast lately")
		}
		a.out.mu.Lock()
		clear(a.out.last)
		a.out.mu.Unlock()
		t1 := time.Now()
		ask(quTXT)
		if _, ok := peer.await(t1, 500*time.Millisecond, hasTXT); !ok {
			t.Error("QU question not answered by multicast although the TXT was not multicast lately")
		}
	})
}

// conflictLog records an announcer's conflict events.
type conflictLog struct {
	mu   sync.Mutex
	list []ConflictEvent
}

func (l *conflictLog) add(e ConflictEvent) {
	l.mu.Lock()
	l.list = append(l.list, e)
	l.mu.Unlock()
}

func (l *conflictLog) wait(t *testing.T, d time.Duration, kinds ...ConflictKind) []ConflictEvent {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		l.mu.Lock()
		var got []ConflictKind
		for _, e := range l.list {
			got = append(got, e.Kind)
		}
		list := append([]ConflictEvent(nil), l.list...)
		l.mu.Unlock()
		if slices.Equal(got, kinds) {
			return list
		}
		if time.Now().After(deadline) {
			t.Fatalf("events %v, want %v", got, kinds)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestConflictAfterProbing: after probing, a response from another host
// with other data for our instance name makes the announcer probe again
// (RFC 6762 clause 9). A stale record that nobody defends leaves the name
// as it was; an owner that answers the probes makes it rename through
// Options.Rename, or without Rename give the name up, and the caller hears
// each step.
// Covers: SIG-IPE-7344
func TestConflictAfterProbing(t *testing.T) {
	port, ifi := testPort(t)
	setVar(t, &announceAt, []time.Duration{0})
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	log := &conflictLog{}
	opts := Options{Interfaces: []net.Interface{*ifi}, Port: port, Loopback: true, Wait: 1500 * time.Millisecond, Rename: RenameInstance, OnConflict: log.add}
	svc := testService()
	svc.IPs = nil
	a, err := Announce(ctx, svc, ServiceType, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	peer := newRawPeer(t, port, ifi)
	r := a.r()
	bad := r.srv()
	bad.Port, bad.Target = 9, "intruder.local."
	claim := message{Header: dnsmessage.Header{Response: true, Authoritative: true}, Answers: []rr{bad}}

	// A stale claim nobody defends: probed again, kept.
	peer.send(claim)
	ev := log.wait(t, 5*time.Second, ConflictSeen, ConflictKept)
	if ev[1].Service.Instance != svc.Instance || a.Service().Instance != svc.Instance {
		t.Fatalf("kept as %+v", ev[1].Service)
	}

	// An owner that answers the probes: renamed.
	peer.setAnswer(func(m message) *message {
		for _, q := range m.Questions {
			if strings.EqualFold(q.Name.String(), r.instName) {
				return &claim
			}
		}
		return nil
	})
	peer.send(claim)
	ev = log.wait(t, 8*time.Second, ConflictSeen, ConflictKept, ConflictSeen, ConflictRenamed)
	if ev[3].Service.Instance != "Site gateway (2)" || ev[3].Previous.Instance != svc.Instance || a.Service().Instance != "Site gateway (2)" || a.Err() != nil {
		t.Fatalf("renamed %+v from %+v", ev[3].Service, ev[3].Previous)
	}
	got, err := Browse(ctx, ServiceType, opts)
	if err != nil {
		t.Fatal(err)
	}
	if f := instances(got); f["Site gateway (2)"].Port != svc.Port {
		t.Fatalf("after the rename found %+v", got)
	}

	// No Rename: the name is given up.
	log2 := &conflictLog{}
	o2 := opts
	o2.Rename, o2.OnConflict = nil, log2.add
	s2 := svc
	s2.Instance, s2.Host = "Box", "box-host"
	b, err := Announce(ctx, s2, ServiceType, o2)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	rb := b.r()
	badB := rb.srv()
	badB.Port = 9
	claimB := message{Header: dnsmessage.Header{Response: true, Authoritative: true}, Answers: []rr{badB}}
	peer.setAnswer(func(m message) *message {
		for _, q := range m.Questions {
			if strings.EqualFold(q.Name.String(), rb.instName) {
				return &claimB
			}
		}
		return nil
	})
	peer.send(claimB)
	ev = log2.wait(t, 5*time.Second, ConflictSeen, ConflictWithdrawn)
	if !errors.Is(b.Err(), ErrConflict) || !errors.Is(ev[1].Err, ErrConflict) {
		t.Fatalf("Err %v, event %+v", b.Err(), ev[1])
	}
	if err := b.UpdateTXT(map[string]string{"a": "1"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("UpdateTXT after withdrawal: %v", err)
	}
	t0 := time.Now()
	got, err = Browse(ctx, ServiceType, opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := instances(got)["Box"]; ok {
		t.Fatalf("withdrawn instance still answered: %+v", got)
	}
	_ = b.Close()
	if list := peer.since(t0, func(h heard) bool {
		for _, x := range h.m.Answers {
			if x.TTL == 0 && strings.EqualFold(x.Name, rb.instName) {
				return true
			}
		}
		return false
	}); len(list) != 0 {
		t.Fatal("goodbye sent for a name given up")
	}
}

// TestWatchPassiveObservation: a device that announced and then went away
// without a goodbye is removed once other hosts have asked for it twice
// without an answer (RFC 6762 clause 10.5); one that still answers stays.
// Covers: SIG-IPE-7345
func TestWatchPassiveObservation(t *testing.T) {
	port, ifi := testPort(t)
	setVar(t, &poofWindow, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	const typ = "_poof._tcp"
	dev, err := newResponder(Service{Instance: "Lamp", Host: "lamp", Port: 80, IPs: []net.IP{net.IPv4(192, 0, 2, 44)}}, typ)
	if err != nil {
		t.Fatal(err)
	}
	peer := newRawPeer(t, port, ifi)
	ev := newEvents()
	w, err := Watch(ctx, []string{typ}, Options{Interfaces: []net.Interface{*ifi}, Port: port, Loopback: true, Wait: time.Second}, ev.add)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	<-w.Settled()
	announce := message{Header: dnsmessage.Header{Response: true, Authoritative: true}, Answers: dev.all(0)}
	peer.send(announce)
	ev.wait(t, 3*time.Second, "added event", func(e Event) bool { return e.Kind == Added })
	// The peer runs on this host, so its query must not be byte for byte
	// the Watcher's own (which a Watcher ignores when it comes from a
	// local address); a second question makes it another host's.
	query := message{Questions: []dnsmessage.Question{mustQ(t, dev.typeName, dnsmessage.TypePTR, false), mustQ(t, "_printer._tcp.local.", dnsmessage.TypePTR, false)}}

	// The device answers: two queries change nothing.
	peer.setAnswer(func(m message) *message { return &announce })
	peer.send(query)
	time.Sleep(time.Second)
	peer.send(query)
	time.Sleep(2500 * time.Millisecond)
	for _, e := range ev.all() {
		if e.Kind == Removed {
			t.Fatalf("removed while it answers: %+v", ev.all())
		}
	}

	// Gone without a goodbye: removed after two unanswered queries.
	peer.setAnswer(nil)
	t0 := time.Now()
	peer.send(query)
	time.Sleep(time.Second)
	peer.send(query)
	ev.wait(t, 4*time.Second, "removed event", func(e Event) bool { return e.Kind == Removed })
	if d := time.Since(t0); d < poofWindow-100*time.Millisecond {
		t.Fatalf("removed after %v, before the window", d)
	}
}

// TestWatchReconfirm: Reconfirm removes an instance that no longer
// answers (RFC 6762 clause 10.4) and keeps one that does.
// Covers: SIG-IPE-7346
func TestWatchReconfirm(t *testing.T) {
	port, ifi := testPort(t)
	setVar(t, &reconfirmWait, 1500*time.Millisecond)
	setVar(t, &announceAt, []time.Duration{0})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	const typ = "_rcf._tcp"
	opts := Options{Interfaces: []net.Interface{*ifi}, Port: port, Loopback: true, Wait: time.Second}
	dev, err := newResponder(Service{Instance: "Lamp", Host: "lamp", Port: 80, IPs: []net.IP{net.IPv4(192, 0, 2, 44)}}, typ)
	if err != nil {
		t.Fatal(err)
	}
	peer := newRawPeer(t, port, ifi)
	ev := newEvents()
	w, err := Watch(ctx, []string{typ}, opts, ev.add)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	<-w.Settled()
	peer.send(message{Header: dnsmessage.Header{Response: true, Authoritative: true}, Answers: dev.all(0)})
	ev.wait(t, 3*time.Second, "added event", func(e Event) bool { return e.Kind == Added && e.Service.Instance == "Lamp" })
	if w.Reconfirm(typ, "Nobody") || w.Reconfirm("_other._tcp", "Lamp") {
		t.Fatal("Reconfirm of an unknown instance or type")
	}
	if !w.Reconfirm(typ, "Lamp") {
		t.Fatal("Reconfirm of a known instance returned false")
	}
	gone := ev.wait(t, 4*time.Second, "removed event", func(e Event) bool { return e.Kind == Removed })
	if gone.Service.Instance != "Lamp" {
		t.Fatalf("removed %+v", gone)
	}

	svc := testService()
	svc.IPs = nil
	a, err := Announce(ctx, svc, typ, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	ev.wait(t, 3*time.Second, "added event", func(e Event) bool { return e.Kind == Added && e.Service.Instance == svc.Instance })
	time.Sleep(1100 * time.Millisecond)
	if !w.Reconfirm(typ, svc.Instance) {
		t.Fatal("Reconfirm of the announcer returned false")
	}
	time.Sleep(2500 * time.Millisecond)
	if got := w.Services(typ); len(got) != 1 || got[0].Instance != svc.Instance {
		t.Fatalf("after reconfirming a live instance: %+v (events %+v)", got, ev.all())
	}
}

// TestBrowseServiceTypes: the service type enumeration finds the type of
// every announcer on the link, each once (RFC 6763 clause 9).
// Covers: SIG-IPE-7349
func TestBrowseServiceTypes(t *testing.T) {
	port, ifi := testPort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	opts := Options{Interfaces: []net.Interface{*ifi}, Port: port, Loopback: true, Wait: 2 * time.Second}
	for i, typ := range []string{"_openadr3._tcp", "_sigmatest._udp", "_openadr3._tcp"} {
		s := testService()
		s.IPs = nil
		s.Instance += string(rune('A' + i))
		s.Host = "vtn-" + string(rune('a'+i))
		a, err := Announce(ctx, s, typ, opts)
		if err != nil {
			t.Fatal(err)
		}
		defer a.Close()
	}
	got, err := BrowseServiceTypes(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"_openadr3._tcp", "_sigmatest._udp"}) {
		t.Fatalf("types %v", got)
	}
}
