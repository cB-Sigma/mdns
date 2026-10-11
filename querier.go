// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package mdns

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"strconv"
	"sync"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// querier is the socket set of a browser: one-shot sockets on ephemeral
// ports and listening sockets on the mDNS port with the groups joined,
// each for IPv4 and IPv6, as opts.Mode asks. Every response read on any of
// them goes to onResponse with the receiving interface and whether it was
// sent to the group; queries other hosts multicast go to onQuery, when
// set.
type querier struct {
	port       int
	loopback   bool
	onResponse func(m message, ifIndex int, mcast bool)
	onQuery    func(m message, src *net.UDPAddr, ifIndex int)

	mu      sync.Mutex
	ifaces  []net.Interface
	errList []error
	// sent holds the packets this querier sent lately, so its own queries
	// heard back are not taken for another host's.
	sent map[string]time.Time

	one4, mc4 *ipv4.PacketConn
	one6, mc6 *ipv6.PacketConn
	conns     []net.PacketConn

	wg     sync.WaitGroup
	closed chan struct{}
	once   sync.Once
}

func newQuerier(ctx context.Context, opts Options, ifaces []net.Interface, onResponse func(message, int, bool), onQuery func(message, *net.UDPAddr, int)) (*querier, error) {
	q := &querier{port: opts.port(), loopback: opts.Loopback, onResponse: onResponse, onQuery: onQuery, ifaces: ifaces,
		sent: map[string]time.Time{}, closed: make(chan struct{})}
	var errs []error
	if opts.Mode.oneShot() {
		if c, err := net.ListenPacket("udp4", "0.0.0.0:0"); err != nil {
			errs = append(errs, err)
		} else {
			q.one4 = q.setup4(c, false)
		}
		if c, err := net.ListenPacket("udp6", "[::]:0"); err != nil {
			errs = append(errs, err)
		} else {
			q.one6 = q.setup6(c, false)
		}
	}
	if opts.Mode.multicast() {
		lc := net.ListenConfig{Control: reuseControl}
		port := strconv.Itoa(q.port)
		if c, err := lc.ListenPacket(ctx, "udp4", net.JoinHostPort("0.0.0.0", port)); err != nil {
			errs = append(errs, fmt.Errorf("listen udp4 :%s: %w", port, err))
		} else {
			q.mc4 = q.setup4(c, true)
		}
		if c, err := lc.ListenPacket(ctx, "udp6", net.JoinHostPort("::", port)); err != nil {
			errs = append(errs, fmt.Errorf("listen udp6 :%s: %w", port, err))
		} else {
			q.mc6 = q.setup6(c, true)
		}
	}
	if len(q.conns) == 0 {
		return nil, fmt.Errorf("mdns: no socket: %w", errors.Join(errs...))
	}
	q.errList = errs
	q.join()
	return q, nil
}

func (q *querier) setup4(c net.PacketConn, listening bool) *ipv4.PacketConn {
	p := ipv4.NewPacketConn(c)
	_ = p.SetMulticastTTL(255)
	if q.loopback {
		_ = p.SetMulticastLoopback(true)
	}
	// The receiving interface, so a cache flush only replaces records
	// learned on that interface (RFC 6762 clause 10.2), and the
	// destination, which tells a multicast answer from a unicast one.
	_ = p.SetControlMessage(ipv4.FlagInterface|ipv4.FlagDst, true)
	q.conns = append(q.conns, c)
	q.wg.Add(1)
	go q.read(listening, func(b []byte) (int, int, net.IP, net.Addr, error) {
		n, cm, src, err := p.ReadFrom(b)
		if cm != nil {
			return n, cm.IfIndex, cm.Dst, src, err
		}
		return n, 0, nil, src, err
	})
	return p
}

func (q *querier) setup6(c net.PacketConn, listening bool) *ipv6.PacketConn {
	p := ipv6.NewPacketConn(c)
	_ = p.SetMulticastHopLimit(255)
	if q.loopback {
		_ = p.SetMulticastLoopback(true)
	}
	_ = p.SetControlMessage(ipv6.FlagInterface|ipv6.FlagDst, true)
	q.conns = append(q.conns, c)
	q.wg.Add(1)
	go q.read(listening, func(b []byte) (int, int, net.IP, net.Addr, error) {
		n, cm, src, err := p.ReadFrom(b)
		if cm != nil {
			return n, cm.IfIndex, cm.Dst, src, err
		}
		return n, 0, nil, src, err
	})
	return p
}

func (q *querier) read(listening bool, read func([]byte) (int, int, net.IP, net.Addr, error)) {
	defer q.wg.Done()
	buf := make([]byte, 9000)
	for {
		n, ifIndex, dst, src, err := read(buf)
		if err != nil {
			select {
			case <-q.closed:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		m, err := parse(buf[:n])
		// Only standard queries and responses without an error code
		// (RFC 6762 clauses 18.3 and 18.11).
		if err != nil || m.Header.OpCode != 0 || m.Header.RCode != 0 {
			continue
		}
		if m.Header.Response {
			q.onResponse(m, ifIndex, dst != nil && dst.IsMulticast())
			continue
		}
		udp, _ := src.(*net.UDPAddr)
		if listening && q.onQuery != nil && udp != nil && !(q.own(buf[:n]) && isLocal(udp.IP)) {
			q.onQuery(m, udp, ifIndex)
		}
	}
}

// isLocal reports whether ip is one of this host's addresses.
func isLocal(ip net.IP) bool {
	if ip.IsLoopback() {
		return true
	}
	addrs, err := hostAddrs()
	if err != nil {
		return false
	}
	for _, ad := range addrs {
		if n, ok := ad.(*net.IPNet); ok && n.IP.Equal(ip) {
			return true
		}
	}
	return false
}

// own reports whether pkt is one this querier sent in the last few
// seconds (another host may send the same bytes; the caller also checks
// the source address).
func (q *querier) own(pkt []byte) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	t, ok := q.sent[string(pkt)]
	return ok && time.Since(t) <= ownWindow
}

// ownWindow is how long a sent query is remembered as the querier's own.
const ownWindow = 5 * time.Second

// join (re-)joins the groups on the listening sockets for every interface.
// Joining twice is harmless; a membership the system dropped (an interface
// that went down and came back, a Wi-Fi roam) is restored.
func (q *querier) join() {
	q.mu.Lock()
	ifaces := q.ifaces
	q.mu.Unlock()
	for _, ifi := range ifaces {
		if q.mc4 != nil {
			_ = q.mc4.JoinGroup(&ifi, &net.UDPAddr{IP: group4})
		}
		if q.mc6 != nil {
			_ = q.mc6.JoinGroup(&ifi, &net.UDPAddr{IP: group6})
		}
	}
}

// setInterfaces replaces the interface set and re-joins; it reports
// whether an interface was added.
func (q *querier) setInterfaces(ifaces []net.Interface) bool {
	q.mu.Lock()
	old := map[string]bool{}
	for _, ifi := range q.ifaces {
		old[ifi.Name] = true
	}
	added := false
	for _, ifi := range ifaces {
		if !old[ifi.Name] {
			added = true
		}
	}
	q.ifaces = ifaces
	q.mu.Unlock()
	q.join()
	return added
}

// send multicasts the query on every interface from each socket: with a
// random ID from the one-shot sockets, with ID 0 from the mDNS port (RFC
// 6762 clause 18.1). It reports whether at least one send succeeded.
func (q *querier) send(pkt []byte) bool {
	if len(pkt) < 2 {
		return false
	}
	legacy := append([]byte(nil), pkt...)
	id := uint16(rand.Uint32())
	legacy[0], legacy[1] = byte(id>>8), byte(id)
	mcast := append([]byte(nil), pkt...)
	mcast[0], mcast[1] = 0, 0

	q.mu.Lock()
	defer q.mu.Unlock()
	now := time.Now()
	for k, t := range q.sent {
		if now.Sub(t) > ownWindow {
			delete(q.sent, k)
		}
	}
	q.sent[string(legacy)], q.sent[string(mcast)] = now, now
	ok := false
	for _, ifi := range q.ifaces {
		for _, s := range []struct {
			p   *ipv4.PacketConn
			pkt []byte
		}{{q.one4, legacy}, {q.mc4, mcast}} {
			if s.p == nil {
				continue
			}
			if err := s.p.SetMulticastInterface(&ifi); err != nil {
				continue
			}
			if _, err := s.p.WriteTo(s.pkt, nil, &net.UDPAddr{IP: group4, Port: q.port}); err == nil {
				ok = true
			} else {
				q.errList = append(q.errList, fmt.Errorf("%s: %w", ifi.Name, err))
			}
		}
		for _, s := range []struct {
			p   *ipv6.PacketConn
			pkt []byte
		}{{q.one6, legacy}, {q.mc6, mcast}} {
			if s.p == nil {
				continue
			}
			if err := s.p.SetMulticastInterface(&ifi); err != nil {
				continue
			}
			if _, err := s.p.WriteTo(s.pkt, nil, &net.UDPAddr{IP: group6, Port: q.port, Zone: ifi.Name}); err == nil {
				ok = true
			}
		}
	}
	return ok
}

func (q *querier) errs() []error {
	q.mu.Lock()
	defer q.mu.Unlock()
	return append([]error(nil), q.errList...)
}

func (q *querier) close() {
	q.once.Do(func() {
		close(q.closed)
		for _, c := range q.conns {
			_ = c.Close()
		}
		q.wg.Wait()
	})
}
