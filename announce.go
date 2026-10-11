package mdns

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// Probe and announcement timing (RFC 6762 clauses 8.1 and 8.3).
var (
	probeInterval = 250 * time.Millisecond
	probeCount    = 3
	// announceAt are the offsets of the unsolicited announcements; the gap
	// at least doubles each time.
	announceAt = []time.Duration{0, time.Second, 3 * time.Second}
)

// Announcer advertises one service until Close or until its context ends.
type Announcer struct {
	r    *responder
	port int
	opts Options

	c4, c6 net.PacketConn
	p4     *ipv4.PacketConn
	p6     *ipv6.PacketConn
	// ifMu guards the joined interface lists, which change when
	// interfaces come and go.
	ifMu     sync.Mutex
	joined4  []net.Interface
	joined6  []net.Interface
	sendMu   sync.Mutex
	probing  atomic.Bool
	conflict atomic.Bool
	// lostTie is set when another host probing for one of our names at
	// the same time wins the tie-break (RFC 6762 clause 8.2).
	lostTie atomic.Bool

	done      chan struct{}
	wg        sync.WaitGroup
	closeOnce sync.Once
	closeErr  error
}

// Announce advertises s as an instance of service (for example
// "_matter._tcp"). It joins
// 224.0.0.251 and ff02::fb on opts.Port (5353 by default) on the given
// interfaces (all multicast-capable ones when none), probes that the names
// are free, sends unsolicited announcements and answers queries. Close, or
// the end of ctx, sends goodbyes (TTL 0) and leaves.
//
// The sockets set SO_REUSEADDR and SO_REUSEPORT where the platform has
// them, so the announcer can share 5353 with the operating system's own
// responder (mDNSResponder on macOS, Avahi or systemd-resolved on Linux).
//
// When probing finds a conflict and opts.Rename is set, Announce asks it
// for a new service (new instance and/or host name) and probes again, up
// to MaxRenames times (RFC 6762 clause 9); otherwise it fails with
// ErrConflict.
func Announce(ctx context.Context, s Service, service string, opts Options) (*Announcer, error) {
	for attempt := 1; ; attempt++ {
		a, err := announce(ctx, s, service, opts)
		if err == nil || !errors.Is(err, ErrConflict) || opts.Rename == nil || attempt > MaxRenames {
			return a, err
		}
		s = opts.Rename(s, attempt)
	}
}

// MaxRenames bounds automatic renaming after conflicts (RFC 6762 clause 9
// limits a responder to 15 conflicts in 10 seconds).
const MaxRenames = 15

func announce(ctx context.Context, s Service, service string, opts Options) (*Announcer, error) {
	r, err := newResponder(s, service)
	if err != nil {
		return nil, err
	}
	ifaces, err := opts.interfaces()
	if err != nil {
		return nil, err
	}
	a := &Announcer{r: r, port: opts.port(), opts: opts, done: make(chan struct{})}
	lc := net.ListenConfig{Control: reuseControl}
	var errs []error

	if c, err := lc.ListenPacket(ctx, "udp4", net.JoinHostPort("0.0.0.0", strconv.Itoa(a.port))); err != nil {
		errs = append(errs, fmt.Errorf("listen udp4 :%d: %w", a.port, err))
	} else {
		p := ipv4.NewPacketConn(c)
		for _, ifi := range ifaces {
			if err := p.JoinGroup(&ifi, &net.UDPAddr{IP: group4}); err != nil {
				errs = append(errs, fmt.Errorf("joining %v on %s failed: %w", group4, ifi.Name, err))
				continue
			}
			a.joined4 = append(a.joined4, ifi)
		}
		if len(a.joined4) == 0 {
			_ = c.Close()
		} else {
			_ = p.SetControlMessage(ipv4.FlagInterface, true)
			_ = p.SetMulticastTTL(255)
			if opts.Loopback {
				_ = p.SetMulticastLoopback(true)
			}
			a.c4, a.p4 = c, p
		}
	}
	if c, err := lc.ListenPacket(ctx, "udp6", net.JoinHostPort("::", strconv.Itoa(a.port))); err != nil {
		errs = append(errs, fmt.Errorf("listen udp6 :%d: %w", a.port, err))
	} else {
		p := ipv6.NewPacketConn(c)
		for _, ifi := range ifaces {
			if err := p.JoinGroup(&ifi, &net.UDPAddr{IP: group6}); err != nil {
				errs = append(errs, fmt.Errorf("joining %v on %s failed: %w", group6, ifi.Name, err))
				continue
			}
			a.joined6 = append(a.joined6, ifi)
		}
		if len(a.joined6) == 0 {
			_ = c.Close()
		} else {
			_ = p.SetControlMessage(ipv6.FlagInterface, true)
			_ = p.SetMulticastHopLimit(255)
			if opts.Loopback {
				_ = p.SetMulticastLoopback(true)
			}
			a.c6, a.p6 = c, p
		}
	}
	if a.p4 == nil && a.p6 == nil {
		return nil, fmt.Errorf("mdns: no multicast socket: %w", errors.Join(errs...))
	}

	if len(s.IPs) == 0 {
		for _, ifi := range ifaces {
			a.learnAddrs(ifi)
		}
	}

	a.probing.Store(true)
	if a.p4 != nil {
		a.wg.Add(1)
		go a.read4()
	}
	if a.p6 != nil {
		a.wg.Add(1)
		go a.read6()
	}

	if err := a.probe(ctx); err != nil {
		_ = a.shutdown(false)
		return nil, err
	}
	a.probing.Store(false)

	a.wg.Add(3)
	go a.announceLoop(announceAt)
	go a.watchInterfaces()
	go func() {
		defer a.wg.Done()
		select {
		case <-ctx.Done():
			go func() { _ = a.Close() }()
		case <-a.done:
		}
	}()
	return a, nil
}

// probe sends the probes and waits for conflicting answers. When another
// host probing for the same name at the same time wins the tie-break, it
// waits one second and starts again (RFC 6762 clause 8.2), at most
// MaxRenames times.
func (a *Announcer) probe(ctx context.Context) error {
	wait := firstProbeDelay()
	restarts := 0
	for i := 0; i <= probeCount; i++ {
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
		if a.conflict.Load() {
			return fmt.Errorf("%w: %s or %s", ErrConflict, a.r.instName, a.r.hostName)
		}
		if a.lostTie.Swap(false) {
			restarts++
			if restarts > MaxRenames {
				return fmt.Errorf("%w: %s or %s (lost every simultaneous probe)", ErrConflict, a.r.instName, a.r.hostName)
			}
			i, wait = -1, tieBreakWait
			continue
		}
		if i == probeCount {
			return nil
		}
		a.sendAll(func(ifIndex int) ([]byte, error) { return a.r.probe(ifIndex, i == 0) })
		wait = probeInterval
	}
	return nil
}

// firstProbeDelay is the random 0-250 ms delay before the first probe
// (RFC 6762 clause 8.1); tests fix it to make probes simultaneous.
var firstProbeDelay = func() time.Duration { return time.Duration(rand.Int64N(int64(probeInterval))) }

// tieBreakWait is how long a prober that lost a tie-break waits before
// probing again (RFC 6762 clause 8.2).
var tieBreakWait = time.Second

func (a *Announcer) announceLoop(schedule []time.Duration) {
	defer a.wg.Done()
	start := time.Now()
	for _, at := range schedule {
		t := time.NewTimer(time.Until(start.Add(at)))
		select {
		case <-a.done:
			t.Stop()
			return
		case <-t.C:
		}
		a.sendAll(func(ifIndex int) ([]byte, error) { return a.r.unsolicited(ifIndex, false) })
	}
}

// sendAll multicasts a per-interface message on every joined interface.
func (a *Announcer) sendAll(build func(ifIndex int) ([]byte, error)) {
	a.ifMu.Lock()
	j4, j6 := append([]net.Interface(nil), a.joined4...), append([]net.Interface(nil), a.joined6...)
	a.ifMu.Unlock()
	for _, ifi := range j4 {
		if b, err := build(ifi.Index); err == nil {
			a.send4(b, ifi.Index, nil)
		}
	}
	for _, ifi := range j6 {
		if b, err := build(ifi.Index); err == nil {
			a.send6(b, ifi.Index, nil)
		}
	}
}

// send4 sends to dst, or multicasts on the interface when dst is nil.
func (a *Announcer) send4(b []byte, ifIndex int, dst net.Addr) {
	a.sendMu.Lock()
	defer a.sendMu.Unlock()
	if dst == nil {
		if ifi, err := net.InterfaceByIndex(ifIndex); err == nil {
			_ = a.p4.SetMulticastInterface(ifi)
		}
		dst = &net.UDPAddr{IP: group4, Port: a.port}
	}
	_, _ = a.p4.WriteTo(b, nil, dst)
}

func (a *Announcer) send6(b []byte, ifIndex int, dst net.Addr) {
	a.sendMu.Lock()
	defer a.sendMu.Unlock()
	if dst == nil {
		ifi, err := net.InterfaceByIndex(ifIndex)
		if err != nil {
			return
		}
		_ = a.p6.SetMulticastInterface(ifi)
		dst = &net.UDPAddr{IP: group6, Port: a.port, Zone: ifi.Name}
	}
	_, _ = a.p6.WriteTo(b, nil, dst)
}

func (a *Announcer) read4() {
	defer a.wg.Done()
	buf := make([]byte, 9000)
	for {
		n, cm, src, err := a.p4.ReadFrom(buf)
		if err != nil {
			if a.closed() {
				return
			}
			continue
		}
		idx := 0
		if cm != nil {
			idx = cm.IfIndex
		}
		a.handle(buf[:n], src, idx, false)
	}
}

func (a *Announcer) read6() {
	defer a.wg.Done()
	buf := make([]byte, 9000)
	for {
		n, cm, src, err := a.p6.ReadFrom(buf)
		if err != nil {
			if a.closed() {
				return
			}
			continue
		}
		idx := 0
		if cm != nil {
			idx = cm.IfIndex
		}
		a.handle(buf[:n], src, idx, true)
	}
}

func (a *Announcer) closed() bool {
	select {
	case <-a.done:
		return true
	default:
		return false
	}
}

// handle processes one received packet.
func (a *Announcer) handle(pkt []byte, src net.Addr, ifIndex int, v6 bool) {
	m, err := parse(pkt)
	if err != nil || m.Header.OpCode != 0 {
		return
	}
	if m.Header.Response {
		if a.probing.Load() && a.r.conflicts(m) {
			a.conflict.Store(true)
		}
		return
	}
	if a.probing.Load() {
		if len(m.Authorities) > 0 && a.r.tieBreak(m, ifIndex) < 0 {
			a.lostTie.Store(true)
		}
		return
	}
	if len(m.Questions) == 0 {
		return
	}
	udp, _ := src.(*net.UDPAddr)
	legacy := udp != nil && udp.Port != a.port
	unicast := legacy
	for _, q := range m.Questions {
		if uint16(q.Class)&topBit != 0 {
			unicast = true
		}
	}
	b, err := a.r.reply(m, legacy, ifIndex)
	if err != nil || b == nil {
		return
	}
	send := func(dst net.Addr) {
		if v6 {
			a.send6(b, ifIndex, dst)
		} else {
			a.send4(b, ifIndex, dst)
		}
	}
	if unicast && udp != nil {
		send(udp)
		return
	}
	if ifIndex == 0 {
		return
	}
	// A probe (a query with proposed records in the authority section) is
	// answered at once, so the prober sees the conflict in time.
	if len(m.Authorities) > 0 {
		send(nil)
		return
	}
	// Multicast answers wait 20-120 ms so answers from several responders
	// to a shared question spread out (RFC 6762 clause 6).
	delay := 20*time.Millisecond + time.Duration(rand.Int64N(int64(100*time.Millisecond)))
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		t := time.NewTimer(delay)
		defer t.Stop()
		select {
		case <-a.done:
		case <-t.C:
			send(nil)
		}
	}()
}

// UpdateTXT replaces the TXT metadata and announces the new record twice,
// one second apart, without probing again: the instance name stays the
// same, and the record's cache-flush bit makes caches replace the old one
// (RFC 6762 clauses 8.4 and 10.2).
func (a *Announcer) UpdateTXT(txt map[string]string) error {
	enc, err := encodeTXT(txt)
	if err != nil {
		return err
	}
	if a.closed() {
		return errors.New("mdns: announcer closed")
	}
	a.r.setTXT(enc)
	a.wg.Add(1)
	go a.announceLoop(txtAnnounceAt)
	return nil
}

// txtAnnounceAt are the offsets of the announcements after UpdateTXT.
var txtAnnounceAt = []time.Duration{0, time.Second}

// learnAddrs reads an interface's addresses into the responder and reports
// whether they changed.
func (a *Announcer) learnAddrs(ifi net.Interface) bool {
	addrs, err := interfaceAddrs(ifi)
	if err != nil {
		return false
	}
	var ips [][]byte
	for _, ad := range addrs {
		if n, ok := ad.(*net.IPNet); ok {
			ips = append(ips, n.IP)
		}
	}
	return a.r.setInterfaceAddrs(ifi.Index, ips)
}

// watchInterfaces re-checks the interfaces every ifaceCheck until Close.
func (a *Announcer) watchInterfaces() {
	defer a.wg.Done()
	t := time.NewTicker(ifaceCheck)
	defer t.Stop()
	for {
		select {
		case <-a.done:
			return
		case <-t.C:
			a.refreshInterfaces()
		}
	}
}

// currentInterfaces lists the interfaces the announcer should be on now:
// the configured ones that are still up (looked up again by name, since an
// interface that comes back may have a new index), or the default set.
func currentInterfaces(opts Options) []net.Interface {
	if len(opts.Interfaces) == 0 {
		list, err := opts.interfaces()
		if err != nil {
			return nil
		}
		return list
	}
	all, err := listInterfaces()
	if err != nil {
		return opts.Interfaces
	}
	var out []net.Interface
	for _, want := range opts.Interfaces {
		for _, ifi := range all {
			if ifi.Name == want.Name && ifi.Flags&net.FlagUp != 0 {
				out = append(out, ifi)
			}
		}
	}
	return out
}

// refreshInterfaces follows interface changes: it re-joins the groups on
// every current interface (a membership the system dropped, after a Wi-Fi
// roam or sleep, is restored), joins and announces on interfaces that came
// up, re-announces on interfaces whose addresses changed, and forgets
// interfaces that went away.
func (a *Announcer) refreshInterfaces() {
	cur := currentInterfaces(a.opts)
	byName := map[string]bool{}
	var announce []int
	fixed := len(a.r.fixedIPs) > 0
	a.ifMu.Lock()
	for _, ifi := range cur {
		byName[ifi.Name] = true
		was4, was6 := hasInterface(a.joined4, ifi.Name), hasInterface(a.joined6, ifi.Name)
		ok4 := a.p4 != nil && a.p4.JoinGroup(&ifi, &net.UDPAddr{IP: group4}) == nil
		ok6 := a.p6 != nil && a.p6.JoinGroup(&ifi, &net.UDPAddr{IP: group6}) == nil
		if !was4 && ok4 {
			a.joined4 = append(a.joined4, ifi)
		}
		if !was6 && ok6 {
			a.joined6 = append(a.joined6, ifi)
		}
		changed := !fixed && a.learnAddrs(ifi)
		if (!was4 && ok4) || (!was6 && ok6) || changed {
			announce = append(announce, ifi.Index)
		}
	}
	keep := func(list []net.Interface, leave func(*net.Interface)) []net.Interface {
		var out []net.Interface
		for _, ifi := range list {
			if byName[ifi.Name] {
				out = append(out, ifi)
				continue
			}
			leave(&ifi)
			a.r.dropInterface(ifi.Index)
		}
		return out
	}
	if a.p4 != nil {
		a.joined4 = keep(a.joined4, func(ifi *net.Interface) { _ = a.p4.LeaveGroup(ifi, &net.UDPAddr{IP: group4}) })
	}
	if a.p6 != nil {
		a.joined6 = keep(a.joined6, func(ifi *net.Interface) { _ = a.p6.LeaveGroup(ifi, &net.UDPAddr{IP: group6}) })
	}
	j4, j6 := append([]net.Interface(nil), a.joined4...), append([]net.Interface(nil), a.joined6...)
	a.ifMu.Unlock()
	for _, idx := range announce {
		b, err := a.r.unsolicited(idx, false)
		if err != nil {
			continue
		}
		if hasIndex(j4, idx) {
			a.send4(b, idx, nil)
		}
		if hasIndex(j6, idx) {
			a.send6(b, idx, nil)
		}
	}
}

func hasInterface(list []net.Interface, name string) bool {
	for _, ifi := range list {
		if ifi.Name == name {
			return true
		}
	}
	return false
}

func hasIndex(list []net.Interface, idx int) bool {
	for _, ifi := range list {
		if ifi.Index == idx {
			return true
		}
	}
	return false
}

// Close sends goodbye records (TTL 0), leaves the groups and closes the
// sockets. It is safe to call more than once.
func (a *Announcer) Close() error {
	return a.shutdown(true)
}

func (a *Announcer) shutdown(goodbye bool) error {
	a.closeOnce.Do(func() {
		close(a.done)
		if goodbye {
			a.sendAll(func(ifIndex int) ([]byte, error) { return a.r.unsolicited(ifIndex, true) })
		}
		var errs []error
		if a.c4 != nil {
			errs = append(errs, a.c4.Close())
		}
		if a.c6 != nil {
			errs = append(errs, a.c6.Close())
		}
		a.wg.Wait()
		a.closeErr = errors.Join(errs...)
	})
	return a.closeErr
}
