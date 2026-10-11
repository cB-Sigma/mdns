package mdns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/net/ipv4"
)

// TestInterface picks an interface on which multicast sent from this host
// on port comes back to this host, for tests that announce and browse in
// one process. It returns an error (tests skip) when none works.
func TestInterface(port int) (*net.Interface, error) {
	ifi, err := multicastInterface()
	if err != nil {
		return nil, err
	}
	if err := checkMulticastDelivery(ifi, port); err != nil {
		return nil, err
	}
	return ifi, nil
}

// multicastInterface picks an interface for the network test: the loopback
// interface when it is multicast-capable (macOS lo0), otherwise the first
// up, multicast, non point-to-point interface with an IPv4 address.
func multicastInterface() (*net.Interface, error) {
	all, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var fallback *net.Interface
	for i := range all {
		ifi := all[i]
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagMulticast == 0 || ifi.Flags&net.FlagPointToPoint != 0 {
			continue
		}
		addrs, _ := ifi.Addrs()
		has4 := false
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil {
				has4 = true
			}
		}
		if !has4 {
			continue
		}
		if ifi.Flags&net.FlagLoopback != 0 {
			return &ifi, nil
		}
		if fallback == nil {
			fallback = &ifi
		}
	}
	if fallback == nil {
		return nil, errors.New("no multicast-capable interface")
	}
	return fallback, nil
}

// checkMulticastDelivery sends one datagram to the group on port and
// reports whether a socket joined on ifi receives it, so a sandbox that
// drops multicast shows up as a skip, not a failure.
func checkMulticastDelivery(ifi *net.Interface, port int) error {
	lc := net.ListenConfig{Control: reuseControl}
	c, err := lc.ListenPacket(context.Background(), "udp4", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer c.Close()
	p := ipv4.NewPacketConn(c)
	if err := p.JoinGroup(ifi, &net.UDPAddr{IP: group4}); err != nil {
		return fmt.Errorf("joining 224.0.0.251 failed: %w", err)
	}
	s, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		return err
	}
	defer s.Close()
	sp := ipv4.NewPacketConn(s)
	_ = sp.SetMulticastInterface(ifi)
	_ = sp.SetMulticastLoopback(true)
	if _, err := sp.WriteTo([]byte("probe"), nil, &net.UDPAddr{IP: group4, Port: port}); err != nil {
		return fmt.Errorf("sending to 224.0.0.251 on %s failed: %w", ifi.Name, err)
	}
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 64)
	for {
		n, _, err := c.ReadFrom(buf)
		if err != nil {
			return fmt.Errorf("multicast on %s not delivered back to this host: %w", ifi.Name, err)
		}
		if string(buf[:n]) == "probe" {
			return nil
		}
	}
}
