// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package mdns

// The Watcher and Browse tests against simulated devices live with the
// simulator, in github.com/cB-Sigma/mdns-sim (sim/browse_integration_test.go).

import (
	"fmt"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// TestCacheRefreshSchedule: a record is asked for again at 80, 85, 90 and
// 95 % of its TTL (plus at most 2 %), once at each step, and not again
// after a fresh copy arrives; records of other types are not refreshed.
// Covers: SIG-IPE-7350
func TestCacheRefreshSchedule(t *testing.T) {
	r, err := newResponder(testService(), ServiceType)
	if err != nil {
		t.Fatal(err)
	}
	typeName := serviceTypeName(ServiceType)
	c := newCache()
	t0 := time.Now()
	srv := r.srv() // 120 s
	c.add(message{Header: dnsmessage.Header{Response: true}, Answers: []rr{r.ptr(), srv}}, t0)
	c.add(message{Header: dnsmessage.Header{Response: true}, Answers: []rr{{Name: "_other._tcp.local.", Type: dnsmessage.TypePTR, TTL: 120, PTR: "x._other._tcp.local."}}}, t0)
	if d := c.due([]string{typeName}, t0.Add(95*time.Second)); len(d) != 0 {
		t.Fatalf("due at 79 %%: %v", d)
	}
	steps := []time.Duration{99 * time.Second, 105 * time.Second, 111 * time.Second, 117 * time.Second}
	for i, at := range steps {
		d := c.due([]string{typeName}, t0.Add(at))
		if fmt.Sprint(d) != fmt.Sprint([]want{{srv.Name, dnsmessage.TypeSRV}}) {
			t.Fatalf("step %d at %v: %v", i, at, d)
		}
		if again := c.due([]string{typeName}, t0.Add(at)); len(again) != 0 {
			t.Fatalf("step %d asked twice: %v", i, again)
		}
	}
	if d := c.due([]string{typeName}, t0.Add(119*time.Second)); len(d) != 0 {
		t.Fatalf("a fifth refresh: %v", d)
	}
	// A fresh copy starts the schedule again.
	t1 := t0.Add(110 * time.Second)
	c.add(message{Header: dnsmessage.Header{Response: true}, Answers: []rr{srv}}, t1)
	if d := c.due([]string{typeName}, t1.Add(90*time.Second)); len(d) != 0 {
		t.Fatalf("fresh record due early: %v", d)
	}
	// The PTR (4500 s) of the watched type is refreshed by asking for the
	// type; the other type's PTR never is.
	d := c.due([]string{typeName}, t0.Add(3700*time.Second))
	if fmt.Sprint(d) != fmt.Sprint([]want{{typeName, dnsmessage.TypePTR}}) {
		t.Fatalf("PTR refresh %v", d)
	}
}

// TestCacheKeepsOnlyBrowsedRecords: listening on the mDNS port hears every
// response on the link; only the browsed types' records are kept, and the
// later expiry wins when a record arrives both by multicast and in a
// legacy reply capped at 10 s.
// Covers: SIG-IPE-7350
func TestCacheKeepsOnlyBrowsedRecords(t *testing.T) {
	r, err := newResponder(testService(), ServiceType)
	if err != nil {
		t.Fatal(err)
	}
	other, err := newResponder(Service{Instance: "Kitchen", Host: "speaker", Port: 8009}, "_googlecast._tcp")
	if err != nil {
		t.Fatal(err)
	}
	typeName := serviceTypeName(ServiceType)
	now := time.Now()
	c := newCache()
	pkt := func(rs ...*responder) message {
		m := message{Header: dnsmessage.Header{Response: true}}
		for _, x := range rs {
			m.Answers = append(m.Answers, x.ptr())
			m.Additionals = append(m.Additionals, x.srv(), x.txtRR())
			m.Additionals = append(m.Additionals, x.addrs(0)...)
		}
		return m
	}
	c.addFor(pkt(r, other), 0, now, []string{typeName}, true)
	for _, e := range c.entries {
		if e.r.Name == other.typeName || e.r.Name == other.instName {
			t.Fatalf("kept %v", e.r)
		}
	}
	if got := c.services(typeName, now); len(got) != 1 || len(got[0].IPs) != 2 {
		t.Fatalf("services %+v", got)
	}
	legacy := r.srv()
	legacy.TTL, legacy.Flush = legacyTTL, false
	c.addFor(message{Header: dnsmessage.Header{Response: true}, Answers: []rr{legacy}}, 0, now, []string{typeName}, false)
	if got := c.services(typeName, now.Add(60*time.Second)); len(got) != 1 {
		t.Fatalf("legacy copy shortened the SRV: %+v", got)
	}
}
