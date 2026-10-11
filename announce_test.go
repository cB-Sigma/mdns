// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package mdns

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// TestProbeTieBreak: two hosts probing for the same instance name at the
// same time compare their proposed records (class, type, rdata); the
// lexicographically earlier set defers, identical sets (our own probe
// looped back) are no conflict, and a probe for other names is ignored
// (RFC 6762 clauses 8.2 and 8.2.1).
//
// Covers: SIG-IPE-6422
func TestProbeTieBreak(t *testing.T) {
	a := testService()
	b := a
	b.Port = 9 // SRV rdata 0,0,0,9 sorts before 0,0,0x20,0xfb (8443)
	ra, err := newResponder(a, ServiceType)
	if err != nil {
		t.Fatal(err)
	}
	rb, err := newResponder(b, ServiceType)
	if err != nil {
		t.Fatal(err)
	}
	probeOf := func(r *responder) message {
		pkt, err := r.probe(0, true)
		if err != nil {
			t.Fatal(err)
		}
		m, err := parse(pkt)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	if got := ra.tieBreak(probeOf(rb), 0); got != 1 {
		t.Errorf("8443 against 9: %d, want 1 (win)", got)
	}
	if got := rb.tieBreak(probeOf(ra), 0); got != -1 {
		t.Errorf("9 against 8443: %d, want -1 (defer)", got)
	}
	if got := ra.tieBreak(probeOf(ra), 0); got != 0 {
		t.Errorf("own probe: %d, want 0", got)
	}
	c := a
	c.Instance, c.Host = "Other", "other-host"
	rc, err := newResponder(c, ServiceType)
	if err != nil {
		t.Fatal(err)
	}
	if got := ra.tieBreak(probeOf(rc), 0); got != 1 {
		t.Errorf("unrelated probe: %d", got)
	}
	// Same records, but the other host proposes one address more, which
	// sorts last: the list that runs out first loses.
	d := a
	d.IPs = append(append([]net.IP(nil), a.IPs...), net.ParseIP("fe80::2"))
	rd, err := newResponder(d, ServiceType)
	if err != nil {
		t.Fatal(err)
	}
	if got := ra.tieBreak(probeOf(rd), 0); got != -1 {
		t.Errorf("fewer records: %d, want -1", got)
	}
	// A TXT difference decides too.
	e := a
	e.TXT = map[string]string{"version": "4"}
	re, err := newResponder(e, ServiceType)
	if err != nil {
		t.Fatal(err)
	}
	if ra.tieBreak(probeOf(re), 0) == 0 || re.tieBreak(probeOf(ra), 0) == 0 || ra.tieBreak(probeOf(re), 0) == re.tieBreak(probeOf(ra), 0) {
		t.Error("TXT difference not decided one way")
	}
	if rr := (rr{Type: dnsmessage.TypeSRV, Port: 9, Target: "h.local."}).rdata(); string(rr) != "\x00\x00\x00\x00\x00\x09\x01h\x05local\x00" {
		t.Errorf("SRV rdata %q", rr)
	}
}

// TestSimultaneousProbes: two announcers that probe at the same moment
// for the same instance with different data end up with two names: the
// loser of the tie-break waits, probes again, meets the winner's answer
// and renames itself (RFC 6762 clauses 8.2 and 9).
//
// Covers: SIG-IPE-6422
func TestSimultaneousProbes(t *testing.T) {
	port, ifi := testPort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// Both probe in step, so neither hears the other's announcement while
	// probing: only the tie-break tells them apart.
	oldDelay := firstProbeDelay
	firstProbeDelay = func() time.Duration { return 0 }
	t.Cleanup(func() { firstProbeDelay = oldDelay })
	opts := Options{Interfaces: []net.Interface{*ifi}, Port: port, Loopback: true, Wait: 2 * time.Second, Rename: RenameInstance}
	svc := testService()
	svc.IPs = nil
	other := svc
	other.Port = 9
	type res struct {
		a   *Announcer
		err error
	}
	ch := make(chan res, 2)
	for _, s := range []Service{svc, other} {
		go func(s Service) {
			a, err := Announce(ctx, s, ServiceType, opts)
			ch <- res{a, err}
		}(s)
	}
	for range 2 {
		r := <-ch
		if r.err != nil {
			t.Fatalf("Announce: %v", r.err)
		}
		defer r.a.Close()
	}
	got, err := Browse(ctx, ServiceType, opts)
	if err != nil {
		t.Fatal(err)
	}
	f := instances(got)
	if len(got) != 2 || f["Site gateway"].Port == 0 || f["Site gateway (2)"].Port == 0 || f["Site gateway"].Port == f["Site gateway (2)"].Port {
		t.Fatalf("found %+v", got)
	}
}

// TestUpdateTXT: a changed TXT record is announced at once without a new
// probe, and a Watcher sees the new metadata.
//
// Covers: SIG-IPE-6422
func TestUpdateTXT(t *testing.T) {
	port, ifi := testPort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	opts := Options{Interfaces: []net.Interface{*ifi}, Port: port, Loopback: true, Wait: time.Second}
	svc := testService()
	svc.IPs = nil
	a, err := Announce(ctx, svc, ServiceType, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	ev := newEvents()
	w, err := Watch(ctx, []string{ServiceType}, opts, ev.add)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	ev.wait(t, 3*time.Second, "added event", func(e Event) bool { return e.Kind == Added })
	if err := a.UpdateTXT(map[string]string{"program_names": "local,flex,ev"}); err != nil {
		t.Fatal(err)
	}
	if a.probing.Load() {
		t.Fatal("UpdateTXT probed again")
	}
	up := ev.wait(t, 3*time.Second, "updated event", func(e Event) bool { return e.Kind == Updated })
	if up.Service.TXT["program_names"] != "local,flex,ev" || up.Service.Instance != svc.Instance {
		t.Fatalf("updated %+v", up)
	}
	if err := a.UpdateTXT(map[string]string{"a=b": "x"}); err == nil {
		t.Fatal("bad TXT accepted")
	}
}

// TestInterfaceChange: when an interface's addresses change the announcer
// re-announces with the new ones, and a dropped group membership is
// restored by the periodic re-join (on macOS, where delivery follows the
// socket's own membership, the answer depends on it).
//
// Covers: SIG-IPE-6422
func TestInterfaceChange(t *testing.T) {
	port, ifi := testPort(t)
	var extra atomic.Bool
	oldAddrs := interfaceAddrs
	interfaceAddrs = func(i net.Interface) ([]net.Addr, error) {
		list, err := i.Addrs()
		if extra.Load() && i.Name == ifi.Name {
			list = append(list, &net.IPNet{IP: net.IPv4(192, 0, 2, 77), Mask: net.CIDRMask(32, 32)})
		}
		return list, err
	}
	t.Cleanup(func() { interfaceAddrs = oldAddrs })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	opts := Options{Interfaces: []net.Interface{*ifi}, Port: port, Loopback: true, Wait: 1500 * time.Millisecond}
	svc := testService()
	svc.IPs = nil
	a, err := Announce(ctx, svc, ServiceType, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	ev := newEvents()
	w, err := Watch(ctx, []string{ServiceType}, opts, ev.add)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	ev.wait(t, 3*time.Second, "added event", func(e Event) bool { return e.Kind == Added })

	extra.Store(true)
	a.refreshInterfaces()
	ev.wait(t, 3*time.Second, "updated event with the new address", func(e Event) bool {
		return e.Kind == Updated && strings.Contains(ipList(e.Service.IPs), "192.0.2.77")
	})

	// Drop the membership behind the announcer's back; the refresh joins
	// again and a fresh browse finds the service.
	_ = a.p4.LeaveGroup(ifi, &net.UDPAddr{IP: group4})
	a.refreshInterfaces()
	got, err := Browse(ctx, ServiceType, Options{Interfaces: opts.Interfaces, Port: port, Loopback: true, Wait: 1500 * time.Millisecond, Mode: BrowseOneShot})
	if err != nil || len(got) != 1 {
		t.Fatalf("after re-join: %+v %v", got, err)
	}
}

func ipList(ips []net.IP) string {
	var b strings.Builder
	for _, ip := range ips {
		b.WriteString(ip.String() + " ")
	}
	return b.String()
}

// TestRenameInstance numbers instance names the way DNS-SD browsers show
// them and keeps them within one label.
func TestRenameInstance(t *testing.T) {
	s := Service{Instance: "Site gateway", Host: "vtn"}
	if got := RenameInstance(s, 1).Instance; got != "Site gateway (2)" {
		t.Errorf("first rename %q", got)
	}
	if got := RenameInstance(Service{Instance: "Site gateway (2)"}, 2).Instance; got != "Site gateway (3)" {
		t.Errorf("second rename %q", got)
	}
	if got := RenameInstance(Service{Instance: "Box (old)"}, 1).Instance; got != "Box (old) (2)" {
		t.Errorf("non-numeric suffix %q", got)
	}
	long := strings.Repeat("x", 63)
	if got := RenameInstance(Service{Instance: long}, 1).Instance; len(got) != 63 || !strings.HasSuffix(got, " (2)") {
		t.Errorf("long rename %q", got)
	}
	if got := RenameInstance(s, 1).Host; got != "vtn" {
		t.Errorf("host changed to %q", got)
	}
}
