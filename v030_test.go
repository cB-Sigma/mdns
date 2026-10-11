// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package mdns

import (
	"context"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Covers: SIG-IPE-7357
//
// BrowseDomains asks for the five domain enumeration names of RFC 6763
// clause 11 and returns what the link answers, by kind.
func TestBrowseDomains(t *testing.T) {
	port, ifi := testPort(t)
	rp := newRawPeer(t, port, ifi)
	rp.setAnswer(func(m message) *message {
		var ans []rr
		for _, q := range m.Questions {
			switch strings.ToLower(q.Name.String()) {
			case "b._dns-sd._udp.local.":
				ans = append(ans, rr{Name: "b._dns-sd._udp.local.", Type: dnsmessage.TypePTR, TTL: 4500, PTR: "example.com."},
					rr{Name: "b._dns-sd._udp.local.", Type: dnsmessage.TypePTR, TTL: 4500, PTR: "sites.example.org."})
			case "lb._dns-sd._udp.local.":
				ans = append(ans, rr{Name: "lb._dns-sd._udp.local.", Type: dnsmessage.TypePTR, TTL: 4500, PTR: "example.com."})
			}
		}
		if len(ans) == 0 {
			return nil
		}
		return &message{Header: dnsmessage.Header{Response: true, Authoritative: true}, Answers: ans}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	d, err := BrowseDomains(ctx, Options{Interfaces: []net.Interface{*ifi}, Port: port, Loopback: true, Wait: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(d.Browse, []string{"example.com.", "sites.example.org."}) || !slices.Equal(d.Legacy, []string{"example.com."}) ||
		len(d.Register) != 0 || len(d.DefaultBrowse) != 0 || len(d.DefaultRegister) != 0 {
		t.Fatalf("domains %+v", d)
	}
	// One query carries all five questions.
	qs := rp.since(time.Time{}, func(h heard) bool { return !h.m.Header.Response && len(h.m.Questions) == 5 })
	if len(qs) == 0 {
		t.Fatal("no query with the five domain questions")
	}
}

// Covers: SIG-IPE-7358
//
// Options.QU sets the unicast-response bit on the first query of a browse
// only (RFC 6762 5.4); without it no question asks for unicast.
func TestBrowseQU(t *testing.T) {
	port, ifi := testPort(t)
	rp := newRawPeer(t, port, ifi)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for _, qu := range []bool{true, false} {
		t0 := time.Now()
		if _, err := Browse(ctx, "_sigmaqu._tcp", Options{Interfaces: []net.Interface{*ifi}, Port: port, Loopback: true, QU: qu, Mode: BrowseMulticast, Wait: 2500 * time.Millisecond}); err != nil {
			t.Fatal(err)
		}
		qs := rp.since(t0, func(h heard) bool {
			return !h.m.Header.Response && len(h.m.Questions) > 0 && strings.HasPrefix(h.m.Questions[0].Name.String(), "_sigmaqu.")
		})
		if len(qs) < 2 {
			t.Fatalf("QU %v: %d queries heard", qu, len(qs))
		}
		for i, h := range qs {
			isQU := uint16(h.m.Questions[0].Class)&topBit != 0
			if isQU != (qu && i == 0) {
				t.Fatalf("QU %v: query %d has the unicast bit %v", qu, i, isQU)
			}
		}
	}
}

// Covers: SIG-IPE-7348
//
// Options.StrictSource keeps answers from sources on this host's links
// only (RFC 6762 11); by default every source is taken.
func TestStrictSource(t *testing.T) {
	setVar(t, &hostAddrs, func() ([]net.Addr, error) {
		return []net.Addr{&net.IPNet{IP: net.IPv4(192, 168, 10, 5), Mask: net.CIDRMask(24, 32)}}, nil
	})
	on := &net.UDPAddr{IP: net.IPv4(192, 168, 10, 77), Port: 5353}
	off := &net.UDPAddr{IP: net.IPv4(10, 9, 8, 7), Port: 5353}
	ll := &net.UDPAddr{IP: net.IPv4(169, 254, 3, 4), Port: 5353}
	strict, loose := &querier{strict: true}, &querier{}
	if !strict.acceptFrom(on) || strict.acceptFrom(off) || !strict.acceptFrom(ll) {
		t.Fatal("strict: on-link and link-local taken, off-link dropped")
	}
	if !loose.acceptFrom(off) {
		t.Fatal("default: every source is taken")
	}
}

// Covers: SIG-IPE-7360
//
// The reflector never repeats a copy of what it sent on an interface, but
// does repeat a host's own repeated query on another link; it needs two
// interfaces.
func TestReflectorLoopKey(t *testing.T) {
	r := &Reflector{recent: map[sentKey]time.Time{}, port: 5353}
	pkt := []byte("query")
	r.remember(pkt, 2)
	if !r.ours(pkt, 2) || r.ours(pkt, 1) {
		t.Fatal("a packet is ours only on the interface we sent it on")
	}
	if _, err := Reflect(context.Background(), Options{Interfaces: []net.Interface{{Index: 1, Name: "one"}}}); err == nil {
		t.Fatal("a reflector on one interface started")
	}
}
