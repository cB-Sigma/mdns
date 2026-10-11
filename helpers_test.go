// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package mdns

import (
	"math/rand/v2"
	"net"
	"sync"
	"testing"
	"time"
)

// testPort picks a random port for a test's mDNS traffic and an interface
// on which multicast comes back to this host, or skips.
func testPort(t *testing.T) (int, *net.Interface) {
	t.Helper()
	if testing.Short() {
		t.Skip("uses multicast; skipped with -short")
	}
	port := 20000 + rand.IntN(30000)
	ifi, err := TestInterface(port)
	if err != nil {
		t.Skipf("%v", err)
	}
	return port, ifi
}

// events collects a Watcher's events for a test.
type events struct {
	mu   sync.Mutex
	list []Event
	ch   chan Event
}

func newEvents() *events { return &events{ch: make(chan Event, 64)} }

func (e *events) add(ev Event) {
	e.mu.Lock()
	e.list = append(e.list, ev)
	e.mu.Unlock()
	select {
	case e.ch <- ev:
	default:
	}
}

func (e *events) all() []Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]Event(nil), e.list...)
}

// wait returns the first event (from now on) that match accepts.
func (e *events) wait(t *testing.T, d time.Duration, what string, match func(Event) bool) Event {
	t.Helper()
	deadline := time.After(d)
	for {
		select {
		case ev := <-e.ch:
			if match(ev) {
				return ev
			}
		case <-deadline:
			t.Fatalf("no %s within %v; events so far %+v", what, d, e.all())
			return Event{}
		}
	}
}

func instances(list []Service) map[string]Service {
	out := map[string]Service{}
	for _, s := range list {
		out[s.Instance] = s
	}
	return out
}
