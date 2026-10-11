// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"context"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/mdns"
)

// dnssd runs Apple's dns-sd (the client of the system's mDNSResponder) for
// d and returns what it printed; it is skipped where there is no dns-sd.
func dnssd(t *testing.T, d time.Duration, args ...string) string {
	t.Helper()
	if _, err := exec.LookPath("dns-sd"); err != nil {
		t.Skip("no dns-sd (mDNSResponder's client): macOS only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	out, _ := exec.CommandContext(ctx, "dns-sd", args...).CombinedOutput()
	return string(out)
}

// startDnssd runs dns-sd in the background until the test ends; the
// returned function gives its output so far.
func startDnssd(t *testing.T, args ...string) func() string {
	t.Helper()
	if _, err := exec.LookPath("dns-sd"); err != nil {
		t.Skip("no dns-sd (mDNSResponder's client): macOS only")
	}
	var buf strings.Builder
	var mu = make(chan struct{}, 1)
	mu <- struct{}{}
	cmd := exec.Command("dns-sd", args...)
	w := writerFunc(func(p []byte) (int, error) { <-mu; buf.Write(p); mu <- struct{}{}; return len(p), nil })
	cmd.Stdout, cmd.Stderr = w, w
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	return func() string { <-mu; s := buf.String(); mu <- struct{}{}; return s }
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// Covers: SIG-IPE-7356
//
// TestMDNSResponder runs github.com/cB-Sigma/mdns against the system's
// mDNSResponder through dns-sd on the real port 5353 (macOS, LAN): our
// announcer browsed, resolved and looked up, its subtype, NSEC for the
// address family it lacks, conflicts while probing and after, goodbye;
// and dns-sd's registration found by our browsers and type enumeration.
func TestMDNSResponder(t *testing.T) {
	ifi := needLAN(t)
	ip := ipv4Of(t, ifi)
	opts := mdns.Options{Interfaces: []net.Interface{*ifi}, Rename: mdns.RenameInstance}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	inst, host := unique("Sigma DNSSD"), "sigma-dnssd-"+strings.ReplaceAll(unique("h"), " ", "")

	a, err := mdns.Announce(ctx, mdns.Service{Instance: inst, Host: host, Port: 8130, TXT: map[string]string{"peer": "sigma"},
		IPs: []net.IP{ip}, Subtypes: []string{"_vtn"}}, "_sigmadnssd._tcp", opts)
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	defer func() {
		if !closed {
			a.Close()
		}
	}()

	t.Run("dns-sd browses, resolves and looks up our announcer", func(t *testing.T) {
		if out := dnssd(t, 3*time.Second, "-B", "_sigmadnssd._tcp", "local"); !strings.Contains(out, inst) {
			t.Errorf("dns-sd -B:\n%s", out)
		}
		if out := dnssd(t, 3*time.Second, "-B", "_sigmadnssd._tcp,_vtn", "local"); !strings.Contains(out, inst) {
			t.Errorf("dns-sd -B with the subtype:\n%s", out)
		}
		out := dnssd(t, 3*time.Second, "-L", inst, "_sigmadnssd._tcp", "local")
		if !strings.Contains(out, host+".local.:8130") || !strings.Contains(out, "peer=sigma") {
			t.Errorf("dns-sd -L:\n%s", out)
		}
		if out := dnssd(t, 3*time.Second, "-G", "v4", host+".local"); !strings.Contains(out, ip.String()) {
			t.Errorf("dns-sd -G v4:\n%s", out)
		}
	})

	t.Run("mDNSResponder takes our NSEC for the missing IPv6 address", func(t *testing.T) {
		start := time.Now()
		out := dnssd(t, 4*time.Second, "-G", "v6", host+".local")
		if !strings.Contains(out, "No Such Record") {
			t.Fatalf("dns-sd -G v6 for our IPv4-only host:\n%s", out)
		}
		t.Logf("answered negatively within the %s run", time.Since(start).Round(time.Millisecond))
	})

	t.Run("our browsers find a dns-sd registration", func(t *testing.T) {
		reg := startDnssd(t, "-R", "DNSSD Box", "_sigmadnssd2._tcp", "local", "8131", "peer=dnssd")
		time.Sleep(3 * time.Second)
		for _, mode := range []mdns.BrowseMode{mdns.BrowseBoth, mdns.BrowseOneShot, mdns.BrowseMulticast} {
			o := opts
			o.Wait, o.Mode = 3*time.Second, mode
			list, err := mdns.Browse(ctx, "_sigmadnssd2._tcp", o)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, s := range list {
				found = found || (s.Instance == "DNSSD Box" && s.Port == 8131 && s.TXT["peer"] == "dnssd")
			}
			if !found {
				t.Errorf("mode %v: %+v\ndns-sd: %s", mode, list, reg())
			}
		}
		o := opts
		o.Wait = 3 * time.Second
		types, err := mdns.BrowseServiceTypes(ctx, o)
		if err != nil || !contains(types, "_sigmadnssd2._tcp") {
			t.Errorf("types %v, %v", types, err)
		}
	})

	t.Run("we rename when mDNSResponder holds the name", func(t *testing.T) {
		held := unique("DNSSD Held")
		startDnssd(t, "-R", held, "_sigmadnssd3._tcp", "local", "8132")
		time.Sleep(3 * time.Second)
		b, err := mdns.Announce(ctx, mdns.Service{Instance: held, Host: host, Port: 8133, IPs: []net.IP{ip}}, "_sigmadnssd3._tcp", opts)
		if err != nil {
			t.Fatal(err)
		}
		defer b.Close()
		if b.Service().Instance == held {
			t.Fatal("we kept a name mDNSResponder holds")
		}
		t.Logf("we took %q", b.Service().Instance)
	})

	t.Run("mDNSResponder renames when we hold the name", func(t *testing.T) {
		out := dnssd(t, 6*time.Second, "-R", inst, "_sigmadnssd._tcp", "local", "8134")
		if !strings.Contains(out, "Name now registered and active") || strings.Contains(out, "Got a reply for service "+inst+"._sigmadnssd._tcp.local.: Name now registered") {
			t.Fatalf("dns-sd -R of our name:\n%s", out)
		}
		if a.Service().Instance != inst {
			t.Fatalf("we renamed to %q", a.Service().Instance)
		}
	})

	t.Run("dns-sd sees our goodbye", func(t *testing.T) {
		watch := startDnssd(t, "-B", "_sigmadnssd._tcp", "local")
		time.Sleep(2 * time.Second)
		a.Close()
		closed = true
		time.Sleep(3 * time.Second)
		out := watch()
		if !strings.Contains(out, "Rmv") || !strings.Contains(out, inst) {
			t.Fatalf("dns-sd -B after our goodbye:\n%s", out)
		}
	})
}
