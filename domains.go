// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package mdns

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Domains are the DNS-SD domains a link recommends (RFC 6763 clause 11):
// where to browse, where to register, and the legacy browsing domains,
// each as fully qualified domain names such as "example.com.". They point
// at unicast DNS-SD; on the link itself the domain is always "local.".
type Domains struct {
	Browse, DefaultBrowse     []string // b._dns-sd._udp, db._dns-sd._udp
	Register, DefaultRegister []string // r._dns-sd._udp, dr._dns-sd._udp
	Legacy                    []string // lb._dns-sd._udp
}

// BrowseDomains asks the link for its recommended DNS-SD domains, the way
// Browse asks for services and with the same Options.
func BrowseDomains(ctx context.Context, opts Options) (Domains, error) {
	const suffix = "._dns-sd._udp.local."
	kinds := []string{"b", "db", "r", "dr", "lb"}
	names := make([]string, len(kinds))
	for i, k := range kinds {
		names[i] = k + suffix
	}
	got, err := browsePTR(ctx, opts, names)
	if err != nil {
		return Domains{}, err
	}
	return Domains{Browse: got[names[0]], DefaultBrowse: got[names[1]], Register: got[names[2]],
		DefaultRegister: got[names[3]], Legacy: got[names[4]]}, nil
}

// browsePTR queries PTR records of the names (repeated as Browse does,
// with known answers) and returns their live targets per name, sorted.
func browsePTR(ctx context.Context, opts Options, names []string) (map[string][]string, error) {
	ifaces, err := opts.interfaces()
	if err != nil {
		return nil, err
	}
	if opts.Wait > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Wait)
		defer cancel()
	} else if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, DefaultWait)
		defer cancel()
	}
	c := newCache()
	q, err := newQuerier(ctx, opts, ifaces, func(m message, ifIndex int, mc bool) {
		c.addFor(m, ifIndex, time.Now(), names, mc)
	}, nil)
	if err != nil {
		return nil, err
	}
	qs := make([]dnsmessage.Question, 0, len(names))
	for _, n := range names {
		qm, err := question(n, dnsmessage.TypePTR, false)
		if err != nil {
			q.close()
			return nil, err
		}
		qs = append(qs, qm)
	}
	sent := 0
	start := time.Now()
	for _, at := range queryAt {
		t := time.NewTimer(time.Until(start.Add(at)))
		select {
		case <-ctx.Done():
			t.Stop()
		case <-t.C:
		}
		if ctx.Err() != nil {
			break
		}
		now := time.Now()
		var known []rr
		c.mu.Lock()
		for _, n := range names {
			known = append(known, c.knownLocked(now, n, dnsmessage.TypePTR, true)...)
		}
		c.mu.Unlock()
		pkts, err := packQuery(qs, known, maxQuery)
		if err != nil {
			q.close()
			return nil, err
		}
		for _, p := range pkts {
			if q.send(p) {
				sent++
			}
		}
	}
	<-ctx.Done()
	q.close()
	if sent == 0 {
		return nil, fmt.Errorf("mdns: sending the query failed on every interface: %w", errors.Join(q.errs()...))
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	out := map[string][]string{}
	for _, n := range names {
		seen := map[string]bool{}
		for _, p := range c.live(time.Now(), n, dnsmessage.TypePTR) {
			d := p.PTR
			if d == "" || seen[strings.ToLower(d)] {
				continue
			}
			seen[strings.ToLower(d)] = true
			out[n] = append(out[n], d)
		}
		sort.Strings(out[n])
	}
	return out, nil
}
