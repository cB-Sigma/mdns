// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package mdns

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// Reflector repeats multicast DNS traffic between interfaces, so that
// devices on one network segment (a VLAN, a guest network) and browsers on
// another find each other, as Avahi's reflector does. Every mDNS message
// multicast on one interface is multicast unchanged on the others, IPv4
// to IPv4 and IPv6 to IPv6; answers a responder sends by unicast to the
// reflector's own port 5353 (to a QU question it reflected) are multicast
// on the other interfaces too. Queries sent from other ports (one-shot
// queries, RFC 6762 6.7) stay on their link. Address records are not
// rewritten: a browser on another segment needs a route to the device.
// RFC 6762 does not define reflection; this is the common practice.
type Reflector struct {
	ifaces []net.Interface
	port   int

	mu     sync.Mutex
	recent map[sentKey]time.Time // what we sent where, so we never repeat our own copies
	p4     *ipv4.PacketConn
	p6     *ipv6.PacketConn
	conns  []net.PacketConn

	reflected atomic.Int64
	closed    chan struct{}
	once      sync.Once
	wg        sync.WaitGroup
}

// Reflect starts a reflector on opts.Interfaces (all usable interfaces when
// empty; at least two are needed) and opts.Port. It runs until ctx ends or
// Close.
func Reflect(ctx context.Context, opts Options) (*Reflector, error) {
	ifaces, err := opts.interfaces()
	if err != nil {
		return nil, err
	}
	if len(ifaces) < 2 {
		return nil, fmt.Errorf("mdns: a reflector needs two interfaces or more, not %d", len(ifaces))
	}
	r := &Reflector{ifaces: ifaces, port: opts.port(), recent: map[sentKey]time.Time{}, closed: make(chan struct{})}
	lc := net.ListenConfig{Control: reuseControl}
	port := strconv.Itoa(r.port)
	var errs []error
	if c, err := lc.ListenPacket(ctx, "udp4", net.JoinHostPort("0.0.0.0", port)); err != nil {
		errs = append(errs, err)
	} else {
		p := ipv4.NewPacketConn(c)
		_ = p.SetMulticastTTL(255)
		_ = p.SetMulticastLoopback(false)
		_ = p.SetControlMessage(ipv4.FlagInterface|ipv4.FlagDst, true)
		joined := 0
		for i := range ifaces {
			if p.JoinGroup(&ifaces[i], &net.UDPAddr{IP: group4}) == nil {
				joined++
			}
		}
		if joined > 0 {
			r.p4 = p
			r.conns = append(r.conns, c)
		} else {
			_ = c.Close()
		}
	}
	if c, err := lc.ListenPacket(ctx, "udp6", net.JoinHostPort("::", port)); err != nil {
		errs = append(errs, err)
	} else {
		p := ipv6.NewPacketConn(c)
		_ = p.SetMulticastHopLimit(255)
		_ = p.SetMulticastLoopback(false)
		_ = p.SetControlMessage(ipv6.FlagInterface|ipv6.FlagDst, true)
		joined := 0
		for i := range ifaces {
			if p.JoinGroup(&ifaces[i], &net.UDPAddr{IP: group6}) == nil {
				joined++
			}
		}
		if joined > 0 {
			r.p6 = p
			r.conns = append(r.conns, c)
		} else {
			_ = c.Close()
		}
	}
	if len(r.conns) == 0 {
		return nil, fmt.Errorf("mdns: the reflector has no socket: %w", errors.Join(errs...))
	}
	if r.p4 != nil {
		r.wg.Add(1)
		go r.loop(func(b []byte) (int, int, net.IP, net.Addr, error) {
			n, cm, src, err := r.p4.ReadFrom(b)
			if cm == nil {
				return n, 0, nil, src, err
			}
			return n, cm.IfIndex, cm.Dst, src, err
		}, r.send4)
	}
	if r.p6 != nil {
		r.wg.Add(1)
		go r.loop(func(b []byte) (int, int, net.IP, net.Addr, error) {
			n, cm, src, err := r.p6.ReadFrom(b)
			if cm == nil {
				return n, 0, nil, src, err
			}
			return n, cm.IfIndex, cm.Dst, src, err
		}, r.send6)
	}
	go func() {
		select {
		case <-ctx.Done():
			r.Close()
		case <-r.closed:
		}
	}()
	return r, nil
}

// Reflected counts the messages repeated so far (one per interface sent
// to).
func (r *Reflector) Reflected() int64 { return r.reflected.Load() }

// Close stops the reflector.
func (r *Reflector) Close() error {
	r.once.Do(func() {
		close(r.closed)
		for _, c := range r.conns {
			_ = c.Close()
		}
	})
	r.wg.Wait()
	return nil
}

func (r *Reflector) send4(pkt []byte, ifi *net.Interface) error {
	_, err := r.p4.WriteTo(pkt, &ipv4.ControlMessage{IfIndex: ifi.Index}, &net.UDPAddr{IP: group4, Port: r.port})
	return err
}

func (r *Reflector) send6(pkt []byte, ifi *net.Interface) error {
	_, err := r.p6.WriteTo(pkt, &ipv6.ControlMessage{IfIndex: ifi.Index}, &net.UDPAddr{IP: group6, Port: r.port, Zone: ifi.Name})
	return err
}

func (r *Reflector) loop(read func([]byte) (int, int, net.IP, net.Addr, error), send func([]byte, *net.Interface) error) {
	defer r.wg.Done()
	buf := make([]byte, 9000)
	for {
		n, ifIndex, dst, src, err := read(buf)
		if err != nil {
			select {
			case <-r.closed:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		pkt := append([]byte(nil), buf[:n]...)
		if !r.shouldReflect(pkt, ifIndex, dst, src) {
			continue
		}
		for i := range r.ifaces {
			ifi := &r.ifaces[i]
			if ifi.Index == ifIndex {
				continue
			}
			r.remember(pkt, ifi.Index)
			if send(pkt, ifi) == nil {
				r.reflected.Add(1)
			}
		}
	}
}

// shouldReflect decides what is repeated: valid mDNS messages from port
// 5353 that we did not send ourselves; multicast ones, and responses sent
// to us by unicast.
func (r *Reflector) shouldReflect(pkt []byte, ifIndex int, dst net.IP, src net.Addr) bool {
	udp, ok := src.(*net.UDPAddr)
	if !ok || udp.Port != r.port {
		return false
	}
	m, err := parse(pkt)
	if err != nil || m.Header.OpCode != 0 {
		return false
	}
	if dst != nil && !dst.IsMulticast() && !m.Header.Response {
		return false
	}
	if r.ours(pkt, ifIndex) {
		return false
	}
	return true
}

// sentKey is a packet we sent and the interface it went out on.
type sentKey struct {
	sum     [32]byte
	ifIndex int
}

// remember notes a packet we send on an interface; ours tells whether a
// packet received on an interface is one we sent there within the last
// two seconds (a copy looped back, or reflected back by another
// reflector). A host repeating its own query on its own link is not
// taken for ours.
func (r *Reflector) remember(pkt []byte, ifIndex int) {
	h := sentKey{sha256.Sum256(pkt), ifIndex}
	now := time.Now()
	r.mu.Lock()
	r.recent[h] = now
	if len(r.recent) > 4096 {
		for k, t := range r.recent {
			if now.Sub(t) > 2*time.Second {
				delete(r.recent, k)
			}
		}
	}
	r.mu.Unlock()
}

func (r *Reflector) ours(pkt []byte, ifIndex int) bool {
	h := sentKey{sha256.Sum256(pkt), ifIndex}
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.recent[h]
	return ok && time.Since(t) < 2*time.Second
}
