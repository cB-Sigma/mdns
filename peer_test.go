// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package mdns

import (
	"context"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/ipv4"
)

// rawPeer is a socket on a test's mDNS port, joined to the group, that
// sends hand-built packets and records what arrives: another host on the
// link, as far as the code under test can tell.
type rawPeer struct {
	t    *testing.T
	c    net.PacketConn
	p    *ipv4.PacketConn
	port int
	ifi  *net.Interface

	mu   sync.Mutex
	got  []heard
	ch   chan heard
	done chan struct{}
	// answer, when set, is called for every query heard and may return
	// a response to multicast.
	answer func(m message) *message
}

type heard struct {
	m     message
	src   *net.UDPAddr
	mcast bool
	at    time.Time
}

func newRawPeer(t *testing.T, port int, ifi *net.Interface) *rawPeer {
	t.Helper()
	lc := net.ListenConfig{Control: reuseControl}
	c, err := lc.ListenPacket(context.Background(), "udp4", net.JoinHostPort("0.0.0.0", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	p := ipv4.NewPacketConn(c)
	if err := p.JoinGroup(ifi, &net.UDPAddr{IP: group4}); err != nil {
		_ = c.Close()
		t.Fatal(err)
	}
	_ = p.SetMulticastInterface(ifi)
	_ = p.SetMulticastLoopback(true)
	_ = p.SetMulticastTTL(255)
	_ = p.SetControlMessage(ipv4.FlagDst, true)
	rp := &rawPeer{t: t, c: c, p: p, port: port, ifi: ifi, ch: make(chan heard, 256), done: make(chan struct{})}
	go rp.read()
	t.Cleanup(rp.close)
	return rp
}

func (rp *rawPeer) close() {
	select {
	case <-rp.done:
	default:
		close(rp.done)
		_ = rp.c.Close()
	}
}

func (rp *rawPeer) read() {
	buf := make([]byte, 9000)
	for {
		n, cm, src, err := rp.p.ReadFrom(buf)
		if err != nil {
			return
		}
		m, err := parse(buf[:n])
		if err != nil {
			continue
		}
		udp, _ := src.(*net.UDPAddr)
		h := heard{m: m, src: udp, mcast: cm != nil && cm.Dst != nil && cm.Dst.IsMulticast(), at: time.Now()}
		rp.mu.Lock()
		rp.got = append(rp.got, h)
		answer := rp.answer
		rp.mu.Unlock()
		select {
		case rp.ch <- h:
		default:
		}
		if !m.Header.Response && answer != nil {
			if resp := answer(m); resp != nil {
				if b, err := resp.pack(); err == nil {
					_, _ = rp.p.WriteTo(b, nil, &net.UDPAddr{IP: group4, Port: rp.port})
				}
			}
		}
	}
}

func (rp *rawPeer) setAnswer(f func(m message) *message) {
	rp.mu.Lock()
	rp.answer = f
	rp.mu.Unlock()
}

// send multicasts m to the group.
func (rp *rawPeer) send(m message) {
	b, err := m.pack()
	if err != nil {
		rp.t.Error(err)
		return
	}
	if _, err := rp.p.WriteTo(b, nil, &net.UDPAddr{IP: group4, Port: rp.port}); err != nil {
		rp.t.Error(err)
	}
}

// since returns what arrived at or after t0 and matches.
func (rp *rawPeer) since(t0 time.Time, match func(heard) bool) []heard {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	var out []heard
	for _, h := range rp.got {
		if !h.at.Before(t0) && match(h) {
			out = append(out, h)
		}
	}
	return out
}

// await waits up to d for a packet arriving at or after t0 that matches.
func (rp *rawPeer) await(t0 time.Time, d time.Duration, match func(heard) bool) (heard, bool) {
	deadline := time.Now().Add(d)
	for {
		if list := rp.since(t0, match); len(list) > 0 {
			return list[0], true
		}
		if time.Now().After(deadline) {
			return heard{}, false
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// answersWith reports whether h is a response carrying a record like x in
// its answer section.
func answersWith(h heard, x rr) bool {
	if !h.m.Header.Response {
		return false
	}
	for _, a := range h.m.Answers {
		if a.sameData(x) && a.TTL > 0 {
			return true
		}
	}
	return false
}

// setVar sets a package variable for one test and restores it after.
func setVar[T any](t *testing.T, p *T, v T) {
	old := *p
	*p = v
	t.Cleanup(func() { *p = old })
}
