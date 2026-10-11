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

// BrowseServiceTypes lists the service types announced on the link, such
// as "_http._tcp", sorted, by asking for the DNS-SD service type
// enumeration name _services._dns-sd._udp.local. (RFC 6763 clause 9). It
// queries the way Browse does, with the same Options, and returns what
// answered before ctx ended or opts.Wait passed.
func BrowseServiceTypes(ctx context.Context, opts Options) ([]string, error) {
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
	names := []string{servicesMeta}
	q, err := newQuerier(ctx, opts, ifaces, func(m message, ifIndex int, mc bool) {
		c.addFor(m, ifIndex, time.Now(), names, mc)
	}, nil)
	if err != nil {
		return nil, err
	}
	qm, err := question(servicesMeta, dnsmessage.TypePTR, false)
	if err != nil {
		q.close()
		return nil, err
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
		c.mu.Lock()
		known := c.knownLocked(now, servicesMeta, dnsmessage.TypePTR, true)
		c.mu.Unlock()
		pkts, err := packQuery([]dnsmessage.Question{qm}, known, maxQuery)
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
	seen := map[string]bool{}
	var out []string
	for _, p := range c.live(time.Now(), servicesMeta, dnsmessage.TypePTR) {
		t := hostLabel(p.PTR)
		if t == "" || seen[strings.ToLower(t)] {
			continue
		}
		seen[strings.ToLower(t)] = true
		out = append(out, t)
	}
	sort.Strings(out)
	return out, nil
}
