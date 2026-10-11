// Package mdns is a multicast DNS (RFC 6762) and DNS-SD (RFC 6763)
// responder and browser with subtype support, written on golang.org/x/net
// (dnsmessage, ipv4, ipv6) and the standard library. It began as SigmaM2M's
// OpenADR 3 local-VTN discovery and was extended for Matter; this module
// is the one copy both use (see PROVENANCE.md).
//
// The responder (Announce) answers PTR, SRV, TXT, A, AAAA and ANY
// questions for the names it owns, probes before announcing with
// simultaneous-probe tie-breaking, renames after a conflict through
// Options.Rename, announces unsolicited, answers legacy unicast (one-shot)
// queries, applies known-answer suppression, re-announces a changed TXT
// record without probing again, re-joins the groups when interfaces change
// and sends goodbyes on Close.
//
// The browser (Browse, BrowseTypes) queries both ways at once by default:
// one-shot queries from an ephemeral port, which responders that only
// answer by unicast reply to, and multicast queries from the mDNS port with
// the groups joined, shared with the operating system's responder, which
// catches responders that only answer by multicast. Watch keeps browsing:
// it caches unsolicited announcements, re-queries before records expire
// and reports instances that appear, change and leave.
//
// Not built: NSEC negative answers, known answers split over truncated
// packets, and the response aggregation and rate limits a responder for a
// large network would need.
package mdns

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cB-Sigma/mdns/internal/reuse"
)

// reuseControl lets our sockets share the mDNS port with the operating
// system's responder.
var reuseControl = reuse.Control

// DefaultPort is the multicast DNS port (RFC 6762 clause 3).
const DefaultPort = 5353

// DefaultWait is how long Browse collects answers when neither opts.Wait
// nor a context deadline bounds it.
const DefaultWait = 3 * time.Second

var (
	group4 = net.IPv4(224, 0, 0, 251)
	group6 = net.ParseIP("ff02::fb")
)

// ErrConflict is returned by Announce when another responder on the link
// already answers for the service instance or host name with other data
// (RFC 6762 clause 9).
var ErrConflict = errors.New("mdns: name already in use on the link")

// Service is one DNS-SD service instance.
//
// Instance is the instance label (for example "Site gateway"); it may hold
// spaces but no dots. Host is the host label, with or without ".local"
// ("myvtn" and "myvtn.local" are the same host). Port is the TCP port of the
// service. TXT holds the key/value metadata. IPs, when set, are the
// addresses the responder answers for Host; when empty it answers with the
// addresses of the interface a query arrived on.
//
// Browse returns Host as "<label>.local" (no trailing dot).
type Service struct {
	Instance, Host string
	Port           int
	TXT            map[string]string
	IPs            []net.IP
	// Subtypes are DNS-SD subtype labels (RFC 6763 clause 7.1), for
	// example "_L840"; the responder answers PTR queries for
	// "<subtype>._sub.<service>.local." with this instance.
	Subtypes []string
}

// Addr returns host:port for connecting to the service. It favours the
// .local host name over an address, because DHCP-assigned addresses change;
// it falls back to the first IP only when no host name is known.
func (s Service) Addr() string {
	if s.Host != "" {
		return net.JoinHostPort(strings.TrimSuffix(s.Host, "."), strconv.Itoa(s.Port))
	}
	if len(s.IPs) > 0 {
		return net.JoinHostPort(s.IPs[0].String(), strconv.Itoa(s.Port))
	}
	return ""
}

// Options configure Announce and Browse.
type Options struct {
	// Interfaces to use; all up, multicast-capable, non point-to-point
	// interfaces when empty (loopback only when Loopback is set).
	Interfaces []net.Interface
	// Wait bounds Browse; DefaultWait when zero and ctx has no deadline.
	Wait time.Duration
	// Port is the multicast DNS port; 0 means 5353. Tests use another port
	// so they do not collide with the operating system's responder.
	Port int
	// Mode selects how Browse, BrowseTypes and Watch query; BrowseBoth
	// when zero.
	Mode BrowseMode
	// Rename, when set, picks a new name after a probing conflict; attempt
	// counts from 1. Announce retries with the returned service.
	Rename func(s Service, attempt int) Service
	// Loopback turns on multicast loopback, so an announcer and a browser
	// on the same host see each other, and lets the default interface set
	// include the loopback interface.
	Loopback bool
}

// BrowseMode is how a browser sends its queries and hears the answers.
type BrowseMode int

const (
	// BrowseBoth sends one-shot queries from an ephemeral port and
	// multicast queries from the mDNS port with the groups joined, and
	// listens on both. Responders that answer only by unicast to the
	// query's source (RFC 6762 clause 6.7) answer the first; responders
	// that answer only by multicast (clause 6) are heard on the second,
	// which also receives announcements. When the mDNS port cannot be
	// bound, the browser carries on with one-shot queries alone.
	BrowseBoth BrowseMode = iota
	// BrowseOneShot only sends one-shot queries from an ephemeral port
	// (RFC 6762 clause 5.1) and never binds the mDNS port.
	BrowseOneShot
	// BrowseMulticast only queries from the mDNS port with the groups
	// joined. A unicast reply to the mDNS port reaches only one of the
	// sockets bound there, so responders that answer by unicast may be
	// missed while the operating system's responder holds the port.
	BrowseMulticast
)

func (m BrowseMode) oneShot() bool   { return m == BrowseBoth || m == BrowseOneShot }
func (m BrowseMode) multicast() bool { return m == BrowseBoth || m == BrowseMulticast }

// RenameInstance is an Options.Rename that keeps the host name and gives
// the instance a number: "Site gateway" becomes "Site gateway (2)", then
// "Site gateway (3)" (RFC 6762 clause 9 leaves the choice of the new name
// to the responder; this is the form DNS-SD browsers show).
func RenameInstance(s Service, attempt int) Service {
	base := s.Instance
	if i := strings.LastIndex(base, " ("); i > 0 && strings.HasSuffix(base, ")") {
		if _, err := strconv.Atoi(base[i+2 : len(base)-1]); err == nil {
			base = base[:i]
		}
	}
	suffix := " (" + strconv.Itoa(attempt+1) + ")"
	if len(base)+len(suffix) > 63 {
		base = base[:63-len(suffix)]
	}
	s.Instance = base + suffix
	return s
}

// listInterfaces and interfaceAddrs are the operating system's interface
// lists; tests replace them to simulate interface changes.
var (
	listInterfaces = net.Interfaces
	interfaceAddrs = func(ifi net.Interface) ([]net.Addr, error) { return ifi.Addrs() }
)

// ifaceCheck is how often announcers and watchers look for interface
// changes and re-join the groups.
var ifaceCheck = 10 * time.Second

func (o Options) port() int {
	if o.Port == 0 {
		return DefaultPort
	}
	return o.Port
}

// interfaces returns the interfaces to use.
func (o Options) interfaces() ([]net.Interface, error) {
	if len(o.Interfaces) > 0 {
		return o.Interfaces, nil
	}
	all, err := listInterfaces()
	if err != nil {
		return nil, fmt.Errorf("mdns: list interfaces: %w", err)
	}
	var out []net.Interface
	for _, ifi := range all {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagMulticast == 0 || ifi.Flags&net.FlagPointToPoint != 0 {
			continue
		}
		if ifi.Flags&net.FlagLoopback != 0 && !o.Loopback {
			continue
		}
		out = append(out, ifi)
	}
	if len(out) == 0 {
		return nil, errors.New("mdns: no multicast-capable interface")
	}
	return out, nil
}

// hostLabel strips a trailing dot and ".local" from a host name.
func hostLabel(h string) string {
	h = strings.TrimSuffix(h, ".")
	if len(h) >= 6 && strings.EqualFold(h[len(h)-6:], ".local") {
		h = h[:len(h)-6]
	}
	return h
}

// serviceTypeName turns "_openadr3._tcp" (with or without ".local" and a
// trailing dot) into the fully qualified "_openadr3._tcp.local.".
func serviceTypeName(service string) string {
	return hostLabel(service) + ".local."
}

func hostName(host string) string { return hostLabel(host) + ".local." }

// encodeTXT turns the map into TXT strings "key=value", sorted by key so
// the record is stable (RFC 6763 clause 6).
func encodeTXT(m map[string]string) ([]string, error) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		if k == "" || strings.ContainsRune(k, '=') {
			return nil, fmt.Errorf("mdns: TXT key %q must be non-empty and hold no '='", k)
		}
		for _, r := range k {
			if r < 0x20 || r > 0x7e {
				return nil, fmt.Errorf("mdns: TXT key %q must be printable ASCII", k)
			}
		}
		s := k + "=" + m[k]
		if len(s) > 255 {
			return nil, fmt.Errorf("mdns: TXT entry %q longer than 255 bytes", k)
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		// RFC 6763 clause 6.1: an empty TXT record holds one empty string.
		out = []string{""}
	}
	return out, nil
}

// decodeTXT parses TXT strings. A key without '=' is present with an empty
// value; keys compare case-insensitively and the first occurrence wins
// (RFC 6763 clause 6.4). Keys are returned lower-cased.
func decodeTXT(txt []string) map[string]string {
	m := map[string]string{}
	for _, s := range txt {
		if s == "" {
			continue
		}
		k, v, _ := strings.Cut(s, "=")
		if k == "" {
			continue
		}
		k = strings.ToLower(k)
		if _, seen := m[k]; seen {
			continue
		}
		m[k] = v
	}
	return m
}

// validate checks a Service for announcing and returns the normalised
// instance label and host label.
func (s Service) validate() error {
	if s.Instance == "" || len(s.Instance) > 63 || strings.ContainsRune(s.Instance, '.') {
		return fmt.Errorf("mdns: instance %q must be 1 to 63 bytes with no dot", s.Instance)
	}
	h := hostLabel(s.Host)
	if h == "" || len(h) > 63 || strings.ContainsRune(h, '.') {
		return fmt.Errorf("mdns: host %q must be one label, optionally followed by .local", s.Host)
	}
	if s.Port < 1 || s.Port > 65535 {
		return fmt.Errorf("mdns: port %d out of range", s.Port)
	}
	for _, ip := range s.IPs {
		if ip.To4() == nil && ip.To16() == nil {
			return fmt.Errorf("mdns: bad IP %v", ip)
		}
	}
	_, err := encodeTXT(s.TXT)
	return err
}
