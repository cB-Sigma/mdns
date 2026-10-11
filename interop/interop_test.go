// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/grandcat/zeroconf"
	hmdns "github.com/hashicorp/mdns"

	"github.com/cB-Sigma/mdns"
)

// These tests need the real mDNS port 5353 (the peers cannot use another),
// a LAN interface that carries multicast, and they put a few test records
// on the link for some seconds. They run only with SIGMA_MDNS_INTEROP=1 and
// are skipped in CI, where neither holds.
func needLAN(t *testing.T) *net.Interface {
	t.Helper()
	if os.Getenv("SIGMA_MDNS_INTEROP") != "1" {
		t.Skip("needs the real mDNS port 5353 and a multicast LAN; set SIGMA_MDNS_INTEROP=1 to run")
	}
	all, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for i := range all {
		ifi := all[i]
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagMulticast == 0 || ifi.Flags&(net.FlagLoopback|net.FlagPointToPoint) != 0 {
			continue
		}
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && !n.IP.IsLinkLocalUnicast() {
				return &ifi
			}
		}
	}
	t.Skip("no LAN interface with an IPv4 address")
	return nil
}

func ipv4Of(t *testing.T, ifi *net.Interface) net.IP {
	addrs, _ := ifi.Addrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil {
			return n.IP.To4()
		}
	}
	t.Fatal("no IPv4 address")
	return nil
}

func unique(prefix string) string { return fmt.Sprintf("%s %d", prefix, time.Now().UnixNano()%1000000) }

func has(list []mdns.Service, inst string) bool {
	for _, s := range list {
		if s.Instance == inst {
			return true
		}
	}
	return false
}

// hashicorp/mdns answers every query by unicast to its source and never
// announces: the default browse finds it (from the one-shot socket); a
// browse that only queries from 5353 usually does not where the operating
// system's responder holds the port (logged, not asserted).
func TestFindsUnicastOnlyResponder(t *testing.T) {
	ifi := needLAN(t)
	const typ = "_sigmainterop._tcp"
	inst := unique("hashicorp")
	svc, err := hmdns.NewMDNSService(inst, typ, "", "sigma-interop-h.", 8080, []net.IP{ipv4Of(t, ifi)}, []string{"peer=hashicorp"})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := hmdns.NewServer(&hmdns.Config{Zone: svc, Iface: ifi})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Shutdown()
	ctx := context.Background()
	opts := mdns.Options{Interfaces: []net.Interface{*ifi}, Wait: 3 * time.Second}
	got, err := mdns.Browse(ctx, typ, opts)
	if err != nil || !has(got, inst) {
		t.Fatalf("default browse missed %q: %+v %v", inst, got, err)
	}
	opts.Mode = mdns.BrowseMulticast
	only, _ := mdns.Browse(ctx, typ, opts)
	t.Logf("multicast-only browse found it: %v", has(only, inst))
}

// grandcat/zeroconf ignores one-shot queries and answers by multicast: the
// default browse finds it (on the 5353 socket); a one-shot-only browse
// does not (logged, not asserted).
func TestFindsMulticastOnlyResponder(t *testing.T) {
	ifi := needLAN(t)
	const typ = "_sigmainterop._tcp"
	inst := unique("zeroconf")
	srv, err := zeroconf.RegisterProxy(inst, typ, "local.", 8081, "sigma-interop-z", []string{ipv4Of(t, ifi).String()}, []string{"peer=zeroconf"}, []net.Interface{*ifi})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Shutdown()
	ctx := context.Background()
	opts := mdns.Options{Interfaces: []net.Interface{*ifi}, Wait: 3 * time.Second}
	got, err := mdns.Browse(ctx, typ, opts)
	if err != nil || !has(got, inst) {
		t.Fatalf("default browse missed %q: %+v %v", inst, got, err)
	}
	opts.Mode = mdns.BrowseOneShot
	only, _ := mdns.Browse(ctx, typ, opts)
	t.Logf("one-shot-only browse found it: %v", has(only, inst))
}

// Both peers' browsers find our announcer (grandcat/zeroconf cannot browse
// by subtype, so it browses the type).
func TestPeersFindOurAnnouncer(t *testing.T) {
	ifi := needLAN(t)
	const typ = "_sigmainterop._tcp"
	inst := unique("sigma")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	a, err := mdns.Announce(ctx, mdns.Service{Instance: inst, Host: "sigma-interop-s", Port: 8082, TXT: map[string]string{"peer": "sigma"}, Subtypes: []string{"_sub1"}},
		typ, mdns.Options{Interfaces: []net.Interface{*ifi}, Rename: mdns.RenameInstance})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	// hashicorp's client keeps writing to an entry after sending it, so
	// the entries are read only once Query has returned.
	entries := make(chan *hmdns.ServiceEntry, 64)
	hp := hmdns.DefaultParams(typ)
	hp.Entries, hp.Interface, hp.Timeout, hp.DisableIPv6 = entries, ifi, 3*time.Second, true
	_ = hmdns.Query(hp)
	close(entries)
	foundH := false
	for e := range entries {
		if strings.HasPrefix(e.Name, strings.ReplaceAll(inst, " ", "\\ ")) || strings.HasPrefix(e.Name, inst) {
			foundH = e.Port == 8082
		}
	}
	if !foundH {
		t.Error("hashicorp/mdns client did not find our announcer")
	}

	r, err := zeroconf.NewResolver(zeroconf.SelectIfaces([]net.Interface{*ifi}))
	if err != nil {
		t.Fatal(err)
	}
	zc := make(chan *zeroconf.ServiceEntry, 32)
	zctx, zcancel := context.WithTimeout(ctx, 3*time.Second)
	defer zcancel()
	if err := r.Browse(zctx, typ, "local.", zc); err != nil {
		t.Fatal(err)
	}
	foundZ := false
	for {
		select {
		case e := <-zc:
			// zeroconf returns the instance label with spaces escaped.
			if e != nil && strings.ReplaceAll(e.Instance, `\ `, " ") == inst && e.Port == 8082 {
				foundZ = true
			}
			continue
		case <-zctx.Done():
		}
		break
	}
	if !foundZ {
		t.Error("grandcat/zeroconf did not find our announcer")
	}
}
