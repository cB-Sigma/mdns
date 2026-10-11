package mdns

import (
	"fmt"
	"net"
	"slices"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// Record TTLs (RFC 6762 clause 10): records naming a host (SRV, A, AAAA)
// live two minutes, the others 75 minutes.
const (
	ttlHost  = 120
	ttlOther = 4500
	// legacyTTL caps TTLs in replies to legacy unicast queries
	// (RFC 6762 clause 6.7).
	legacyTTL = 10
)

// Top bit of the class field: cache-flush in a record, unicast-response
// requested in a question (RFC 6762 clauses 10.2 and 5.4).
const topBit = 0x8000

// rr is one resource record in a form both sides can compare.
type rr struct {
	Name  string // fully qualified, trailing dot
	Type  dnsmessage.Type
	TTL   uint32
	Flush bool // cache-flush bit (unique records)

	PTR    string   // PTR target
	Target string   // SRV target
	Port   uint16   // SRV port
	Prio   uint16   // SRV priority
	Weight uint16   // SRV weight
	TXT    []string // TXT strings
	IP     net.IP   // A or AAAA
}

// sameData reports whether two records have the same name, type and data.
func (r rr) sameData(o rr) bool {
	if !strings.EqualFold(r.Name, o.Name) || r.Type != o.Type {
		return false
	}
	switch r.Type {
	case dnsmessage.TypePTR:
		return strings.EqualFold(r.PTR, o.PTR)
	case dnsmessage.TypeSRV:
		return strings.EqualFold(r.Target, o.Target) && r.Port == o.Port
	case dnsmessage.TypeTXT:
		return slices.Equal(r.TXT, o.TXT)
	case dnsmessage.TypeA, dnsmessage.TypeAAAA:
		return r.IP.Equal(o.IP)
	}
	return false
}

func mustName(s string) (dnsmessage.Name, error) {
	n, err := dnsmessage.NewName(s)
	if err != nil {
		return n, fmt.Errorf("mdns: name %q: %w", s, err)
	}
	return n, nil
}

// addRR appends one record to the builder's current section.
func addRR(b *dnsmessage.Builder, r rr) error {
	name, err := mustName(r.Name)
	if err != nil {
		return err
	}
	class := uint16(dnsmessage.ClassINET)
	if r.Flush {
		class |= topBit
	}
	h := dnsmessage.ResourceHeader{Name: name, Class: dnsmessage.Class(class), TTL: r.TTL}
	switch r.Type {
	case dnsmessage.TypePTR:
		t, err := mustName(r.PTR)
		if err != nil {
			return err
		}
		return b.PTRResource(h, dnsmessage.PTRResource{PTR: t})
	case dnsmessage.TypeSRV:
		t, err := mustName(r.Target)
		if err != nil {
			return err
		}
		return b.SRVResource(h, dnsmessage.SRVResource{Priority: r.Prio, Weight: r.Weight, Target: t, Port: r.Port})
	case dnsmessage.TypeTXT:
		return b.TXTResource(h, dnsmessage.TXTResource{TXT: r.TXT})
	case dnsmessage.TypeA:
		var a [4]byte
		copy(a[:], r.IP.To4())
		return b.AResource(h, dnsmessage.AResource{A: a})
	case dnsmessage.TypeAAAA:
		var a [16]byte
		copy(a[:], r.IP.To16())
		return b.AAAAResource(h, dnsmessage.AAAAResource{AAAA: a})
	}
	return fmt.Errorf("mdns: cannot pack record type %v", r.Type)
}

// message is a decoded or to-be-encoded DNS message.
type message struct {
	Header      dnsmessage.Header
	Questions   []dnsmessage.Question
	Answers     []rr
	Authorities []rr
	Additionals []rr
}

// pack encodes the message with name compression.
func (m message) pack() ([]byte, error) {
	b := dnsmessage.NewBuilder(make([]byte, 0, 512), m.Header)
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	for _, q := range m.Questions {
		if err := b.Question(q); err != nil {
			return nil, err
		}
	}
	sections := []struct {
		start func() error
		rrs   []rr
	}{{b.StartAnswers, m.Answers}, {b.StartAuthorities, m.Authorities}, {b.StartAdditionals, m.Additionals}}
	for _, s := range sections {
		if err := s.start(); err != nil {
			return nil, err
		}
		for _, r := range s.rrs {
			if err := addRR(&b, r); err != nil {
				return nil, err
			}
		}
	}
	return b.Finish()
}

// parse decodes a message; compressed names are expanded by the parser.
// Record types other than PTR, SRV, TXT, A and AAAA are skipped.
func parse(pkt []byte) (message, error) {
	var p dnsmessage.Parser
	var m message
	h, err := p.Start(pkt)
	if err != nil {
		return m, fmt.Errorf("mdns: header: %w", err)
	}
	m.Header = h
	if m.Questions, err = p.AllQuestions(); err != nil {
		return m, fmt.Errorf("mdns: questions: %w", err)
	}
	all := [3][]dnsmessage.Resource{}
	if all[0], err = p.AllAnswers(); err != nil {
		return m, fmt.Errorf("mdns: answers: %w", err)
	}
	if all[1], err = p.AllAuthorities(); err != nil {
		return m, fmt.Errorf("mdns: authorities: %w", err)
	}
	if all[2], err = p.AllAdditionals(); err != nil {
		return m, fmt.Errorf("mdns: additionals: %w", err)
	}
	dst := [3]*[]rr{&m.Answers, &m.Authorities, &m.Additionals}
	for i, rs := range all {
		for _, res := range rs {
			if r, ok := fromResource(res); ok {
				*dst[i] = append(*dst[i], r)
			}
		}
	}
	return m, nil
}

func fromResource(res dnsmessage.Resource) (rr, bool) {
	r := rr{
		Name:  res.Header.Name.String(),
		Type:  res.Header.Type,
		TTL:   res.Header.TTL,
		Flush: uint16(res.Header.Class)&topBit != 0,
	}
	if dnsmessage.Class(uint16(res.Header.Class)&^topBit) != dnsmessage.ClassINET {
		return r, false
	}
	switch b := res.Body.(type) {
	case *dnsmessage.PTRResource:
		r.PTR = b.PTR.String()
	case *dnsmessage.SRVResource:
		r.Target, r.Port, r.Prio, r.Weight = b.Target.String(), b.Port, b.Priority, b.Weight
	case *dnsmessage.TXTResource:
		r.TXT = b.TXT
	case *dnsmessage.AResource:
		r.IP = net.IP(slices.Clone(b.A[:]))
	case *dnsmessage.AAAAResource:
		r.IP = net.IP(slices.Clone(b.AAAA[:]))
	default:
		return r, false
	}
	return r, true
}

// question builds a question; unicast sets the QU bit.
func question(name string, t dnsmessage.Type, unicast bool) (dnsmessage.Question, error) {
	n, err := mustName(name)
	if err != nil {
		return dnsmessage.Question{}, err
	}
	class := uint16(dnsmessage.ClassINET)
	if unicast {
		class |= topBit
	}
	return dnsmessage.Question{Name: n, Type: t, Class: dnsmessage.Class(class)}, nil
}

// rdata is the record's data in wire form with names uncompressed, for the
// lexicographic comparison of simultaneous probes (RFC 6762 clause 8.2).
func (r rr) rdata() []byte {
	var b []byte
	name := func(n string) {
		for _, l := range strings.Split(strings.TrimSuffix(n, "."), ".") {
			if l == "" {
				continue
			}
			b = append(b, byte(len(l)))
			b = append(b, l...)
		}
		b = append(b, 0)
	}
	switch r.Type {
	case dnsmessage.TypePTR:
		name(r.PTR)
	case dnsmessage.TypeSRV:
		b = append(b, byte(r.Prio>>8), byte(r.Prio), byte(r.Weight>>8), byte(r.Weight), byte(r.Port>>8), byte(r.Port))
		name(r.Target)
	case dnsmessage.TypeTXT:
		for _, t := range r.TXT {
			b = append(b, byte(len(t)))
			b = append(b, t...)
		}
	case dnsmessage.TypeA:
		b = append(b, r.IP.To4()...)
	case dnsmessage.TypeAAAA:
		b = append(b, r.IP.To16()...)
	}
	return b
}
