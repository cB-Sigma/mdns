package mdns

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"math/rand/v2"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// ServiceType is the example service type used by these tests.
const ServiceType = "_openadr3._tcp"

func testService() Service {
	return Service{
		Instance: "Site gateway",
		Host:     "vtn-test.local",
		Port:     8443,
		TXT:      map[string]string{"version": "3.1.0", "base_path": "openadr3/3.1.0", "openapi_url": "https://vtn-test.local:8443/openadr3/3.1.0/openapi.yaml", "local_url": "https://vtn-test.local:8443/openadr3/3.1.0", "requires_auth": "True", "program_names": "local,flex"},
		IPs:      []net.IP{net.IPv4(192, 0, 2, 7), net.ParseIP("fe80::1")},
	}
}

func TestTXTEncodeDecode(t *testing.T) {
	enc, err := encodeTXT(map[string]string{"b": "2", "a": "x=y", "c": ""})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(enc, "|") != "a=x=y|b=2|c=" {
		t.Fatalf("encoded %q", enc)
	}
	dec := decodeTXT([]string{"A=first", "a=second", "flag", "", "=nokey", "v=1=2"})
	want := map[string]string{"a": "first", "flag": "", "v": "1=2"}
	if !maps.Equal(dec, want) {
		t.Fatalf("decoded %v want %v", dec, want)
	}
	if e, _ := encodeTXT(nil); len(e) != 1 || e[0] != "" {
		t.Fatalf("empty TXT %q", e)
	}
	for _, bad := range []map[string]string{{"": "v"}, {"a=b": "v"}, {"k": strings.Repeat("x", 254)}} {
		if _, err := encodeTXT(bad); err == nil {
			t.Fatalf("encodeTXT(%v) accepted", bad)
		}
	}
}

func TestServiceValidate(t *testing.T) {
	ok := testService()
	if err := ok.validate(); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*Service){
		"no instance":  func(s *Service) { s.Instance = "" },
		"dot instance": func(s *Service) { s.Instance = "a.b" },
		"no host":      func(s *Service) { s.Host = ".local" },
		"dotted host":  func(s *Service) { s.Host = "a.b.local" },
		"port":         func(s *Service) { s.Port = 0 },
		"txt":          func(s *Service) { s.TXT = map[string]string{"a=b": ""} },
	} {
		s := testService()
		mut(&s)
		if err := s.validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Announce(context.Background(), Service{}, ServiceType, Options{}); err == nil {
		t.Fatal("Announce accepted an empty service")
	}
}

func TestServiceAddrPrefersLocalHost(t *testing.T) {
	s := Service{Host: "myvtn.local", Port: 883, IPs: []net.IP{net.IPv4(192, 0, 2, 1)}}
	if got := s.Addr(); got != "myvtn.local:883" {
		t.Fatalf("Addr %q", got)
	}
	s.Host = ""
	if got := s.Addr(); got != "192.0.2.1:883" {
		t.Fatalf("Addr without host %q", got)
	}
}

func TestRecordsPackParseRoundTrip(t *testing.T) {
	r, err := newResponder(testService(), ServiceType)
	if err != nil {
		t.Fatal(err)
	}
	pkt, err := r.unsolicited(0, false)
	if err != nil {
		t.Fatal(err)
	}
	// Name compression when writing: the service type name is spelled out
	// once and referenced by pointers afterwards.
	wire := append([]byte{9}, "_openadr3"...)
	if n := bytes.Count(pkt, wire); n != 1 {
		t.Fatalf("service type label written %d times, want 1 (compression)", n)
	}
	m, err := parse(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if !m.Header.Response || !m.Header.Authoritative || m.Header.ID != 0 {
		t.Fatalf("header %+v", m.Header)
	}
	want := r.all(0)
	if len(m.Answers) != len(want) {
		t.Fatalf("got %d answers want %d", len(m.Answers), len(want))
	}
	for i := range want {
		if !m.Answers[i].sameData(want[i]) || m.Answers[i].TTL != want[i].TTL || m.Answers[i].Flush != want[i].Flush {
			t.Errorf("answer %d: got %+v want %+v", i, m.Answers[i], want[i])
		}
	}
	if m.Answers[0].Type != dnsmessage.TypePTR || m.Answers[0].PTR != "Site gateway._openadr3._tcp.local." || m.Answers[0].Flush {
		t.Errorf("PTR %+v", m.Answers[0])
	}
	if m.Answers[1].Target != "vtn-test.local." || m.Answers[1].Port != 8443 || m.Answers[1].TTL != ttlHost {
		t.Errorf("SRV %+v", m.Answers[1])
	}
	if got := decodeTXT(m.Answers[2].TXT); !maps.Equal(got, testService().TXT) {
		t.Errorf("TXT %v", got)
	}
}

// TestParseCompressedNames reads a packet assembled byte by byte whose
// second record's owner name and the PTR target use compression pointers
// (RFC 1035 clause 4.1.4).
func TestParseCompressedNames(t *testing.T) {
	var b []byte
	b = append(b, 0, 0, 0x84, 0, 0, 0, 0, 2, 0, 0, 0, 0) // response, AA, 2 answers
	typeOff := len(b)
	b = append(b, 9)
	b = append(b, "_openadr3"...)
	b = append(b, 4)
	b = append(b, "_tcp"...)
	b = append(b, 5)
	b = append(b, "local"...)
	b = append(b, 0)
	rec := func(typ, class uint16, ttl uint32, rdata []byte) {
		b = binary.BigEndian.AppendUint16(b, typ)
		b = binary.BigEndian.AppendUint16(b, class)
		b = binary.BigEndian.AppendUint32(b, ttl)
		b = binary.BigEndian.AppendUint16(b, uint16(len(rdata)))
		b = append(b, rdata...)
	}
	// PTR rdata: "Gate" + pointer to the type name. Its offset is the
	// current length plus type, class, TTL and rdlength (10 bytes).
	instOff := len(b) + 10
	rec(uint16(dnsmessage.TypePTR), 1, 4500, []byte{4, 'G', 'a', 't', 'e', 0xC0 | byte(typeOff>>8), byte(typeOff)})
	// TXT owner name is a pointer to the instance name inside the PTR rdata.
	b = append(b, 0xC0|byte(instOff>>8), byte(instOff))
	rec(uint16(dnsmessage.TypeTXT), 0x8001, 4500, []byte{3, 'a', '=', '1', 7, 'b', '=', 't', 'w', 'o', '=', '2'})

	m, err := parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Answers) != 2 {
		t.Fatalf("answers %+v", m.Answers)
	}
	if m.Answers[0].Name != "_openadr3._tcp.local." || m.Answers[0].PTR != "Gate._openadr3._tcp.local." {
		t.Errorf("PTR %+v", m.Answers[0])
	}
	if m.Answers[1].Name != "Gate._openadr3._tcp.local." || !m.Answers[1].Flush {
		t.Errorf("TXT owner %+v", m.Answers[1])
	}
	if got := decodeTXT(m.Answers[1].TXT); !maps.Equal(got, map[string]string{"a": "1", "b": "two=2"}) {
		t.Errorf("TXT %v", got)
	}
	// A pointer loop is rejected, not followed forever.
	loop := append([]byte{0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0}, 0xC0, 12)
	loop = binary.BigEndian.AppendUint16(loop, 1)
	if _, err := parse(append(loop, 0, 1, 0, 0, 0, 0, 0, 0)); err == nil {
		t.Fatal("pointer loop accepted")
	}
}

func queryPacket(t *testing.T, id uint16, qs []dnsmessage.Question, known []rr) message {
	t.Helper()
	pkt, err := message{Header: dnsmessage.Header{ID: id}, Questions: qs, Answers: known}.pack()
	if err != nil {
		t.Fatal(err)
	}
	m, err := parse(pkt)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func mustQ(t *testing.T, name string, typ dnsmessage.Type, qu bool) dnsmessage.Question {
	t.Helper()
	q, err := question(name, typ, qu)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

// TestResponderAnswersPTRQuery drives the responder with query packets
// built in the test (no network): a PTR query for _openadr3._tcp gets the
// PTR answer with SRV, TXT, A and AAAA as additional records, carrying the
// OpenADR 3 TXT keys.
//
// Covers: SIG-MTR-060, SIG-IPE-2364
func TestResponderAnswersPTRQuery(t *testing.T) {
	r, err := newResponder(testService(), ServiceType)
	if err != nil {
		t.Fatal(err)
	}
	decode := func(b []byte, err error) message {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		if b == nil {
			return message{}
		}
		m, err := parse(b)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	ptrQ := mustQ(t, "_OpenADR3._tcp.local.", dnsmessage.TypePTR, false) // names compare case-insensitively

	t.Run("multicast", func(t *testing.T) {
		m := decode(r.reply(queryPacket(t, 0, []dnsmessage.Question{ptrQ}, nil), false, 0))
		if !m.Header.Response || !m.Header.Authoritative || len(m.Questions) != 0 {
			t.Fatalf("header %+v questions %d", m.Header, len(m.Questions))
		}
		if len(m.Answers) != 1 || m.Answers[0].Type != dnsmessage.TypePTR || m.Answers[0].PTR != "Site gateway._openadr3._tcp.local." || m.Answers[0].TTL != ttlOther {
			t.Fatalf("answers %+v", m.Answers)
		}
		types := map[dnsmessage.Type]rr{}
		for _, x := range m.Additionals {
			types[x.Type] = x
			if !x.Flush {
				t.Errorf("unique record without cache-flush: %+v", x)
			}
		}
		if s := types[dnsmessage.TypeSRV]; s.Target != "vtn-test.local." || s.Port != 8443 {
			t.Errorf("SRV %+v", s)
		}
		if a := types[dnsmessage.TypeA]; !a.IP.Equal(net.IPv4(192, 0, 2, 7)) || a.Name != "vtn-test.local." || a.TTL != ttlHost {
			t.Errorf("A %+v", a)
		}
		if a := types[dnsmessage.TypeAAAA]; !a.IP.Equal(net.ParseIP("fe80::1")) {
			t.Errorf("AAAA %+v", a)
		}
		txt := decodeTXT(types[dnsmessage.TypeTXT].TXT)
		for _, k := range []string{"version", "base_path", "local_url", "program_names", "requires_auth", "openapi_url"} {
			if _, ok := txt[k]; !ok {
				t.Errorf("TXT lacks %s: %v", k, txt)
			}
		}
		if txt["local_url"] != "https://vtn-test.local:8443/openadr3/3.1.0" || txt["requires_auth"] != "True" || txt["program_names"] != "local,flex" {
			t.Errorf("TXT %v", txt)
		}
	})

	t.Run("legacy unicast", func(t *testing.T) {
		m := decode(r.reply(queryPacket(t, 0x4242, []dnsmessage.Question{mustQ(t, "_openadr3._tcp.local.", dnsmessage.TypePTR, true)}, nil), true, 0))
		if m.Header.ID != 0x4242 || len(m.Questions) != 1 || uint16(m.Questions[0].Class)&topBit != 0 {
			t.Fatalf("header %+v questions %+v", m.Header, m.Questions)
		}
		for _, x := range append(m.Answers, m.Additionals...) {
			if x.TTL > legacyTTL || x.Flush {
				t.Errorf("legacy reply record %+v", x)
			}
		}
		if len(m.Additionals) != 4 {
			t.Errorf("additionals %d", len(m.Additionals))
		}
	})

	t.Run("known answer suppression", func(t *testing.T) {
		fresh := r.ptr()
		b, err := r.reply(queryPacket(t, 0, []dnsmessage.Question{ptrQ}, []rr{fresh}), false, 0)
		if err != nil || b != nil {
			t.Fatalf("known PTR still answered: %v %v", b, err)
		}
		stale := fresh
		stale.TTL = ttlOther/2 - 1
		if m := decode(r.reply(queryPacket(t, 0, []dnsmessage.Question{ptrQ}, []rr{stale}), false, 0)); len(m.Answers) != 1 {
			t.Fatalf("PTR under half TTL not refreshed: %+v", m.Answers)
		}
	})

	t.Run("direct questions", func(t *testing.T) {
		m := decode(r.reply(queryPacket(t, 0, []dnsmessage.Question{
			mustQ(t, "Site gateway._openadr3._tcp.local.", dnsmessage.TypeSRV, false),
			mustQ(t, "Site gateway._openadr3._tcp.local.", dnsmessage.TypeTXT, false),
			mustQ(t, "vtn-test.local.", dnsmessage.TypeA, false),
		}, nil), false, 0))
		var got []dnsmessage.Type
		for _, x := range m.Answers {
			got = append(got, x.Type)
		}
		if fmt.Sprint(got) != fmt.Sprint([]dnsmessage.Type{dnsmessage.TypeSRV, dnsmessage.TypeTXT, dnsmessage.TypeA}) {
			t.Fatalf("answers %v", got)
		}
		for _, x := range m.Additionals {
			if x.Type == dnsmessage.TypeA {
				t.Errorf("A repeated in additionals")
			}
		}
		all := decode(r.reply(queryPacket(t, 0, []dnsmessage.Question{mustQ(t, "vtn-test.local.", dnsmessage.TypeALL, false)}, nil), false, 0))
		if len(all.Answers) != 2 {
			t.Errorf("ANY host answers %+v", all.Answers)
		}
		meta := decode(r.reply(queryPacket(t, 0, []dnsmessage.Question{mustQ(t, servicesMeta, dnsmessage.TypePTR, false)}, nil), false, 0))
		if len(meta.Answers) != 1 || meta.Answers[0].PTR != "_openadr3._tcp.local." {
			t.Errorf("service enumeration %+v", meta.Answers)
		}
	})

	t.Run("not ours", func(t *testing.T) {
		for _, q := range []dnsmessage.Question{
			mustQ(t, "_http._tcp.local.", dnsmessage.TypePTR, false),
			mustQ(t, "other.local.", dnsmessage.TypeA, false),
			mustQ(t, "_openadr3._tcp.local.", dnsmessage.TypeSRV, false),
		} {
			if b, err := r.reply(queryPacket(t, 0, []dnsmessage.Question{q}, nil), false, 0); err != nil || b != nil {
				t.Errorf("%v answered", q)
			}
		}
	})

	t.Run("per-interface addresses", func(t *testing.T) {
		s := testService()
		s.IPs = nil
		r2, err := newResponder(s, ServiceType)
		if err != nil {
			t.Fatal(err)
		}
		r2.setInterfaceAddrs(3, [][]byte{net.IPv4(10, 0, 0, 3)})
		r2.setInterfaceAddrs(4, [][]byte{net.IPv4(10, 0, 0, 4)})
		m := decode(r2.reply(queryPacket(t, 0, []dnsmessage.Question{mustQ(t, "vtn-test.local.", dnsmessage.TypeA, false)}, nil), false, 4))
		if len(m.Answers) != 1 || !m.Answers[0].IP.Equal(net.IPv4(10, 0, 0, 4)) {
			t.Fatalf("answers %+v", m.Answers)
		}
	})

	t.Run("goodbye and probe", func(t *testing.T) {
		m := decode(r.unsolicited(0, true))
		if len(m.Answers) != 5 {
			t.Fatalf("goodbye answers %d", len(m.Answers))
		}
		for _, x := range m.Answers {
			if x.TTL != 0 {
				t.Errorf("goodbye TTL %d", x.TTL)
			}
		}
		p := decode(r.probe(0, true))
		if p.Header.Response || len(p.Questions) != 2 || p.Questions[0].Type != dnsmessage.TypeALL || uint16(p.Questions[0].Class)&topBit == 0 || len(p.Authorities) != 4 {
			t.Fatalf("probe %+v", p)
		}
	})

	t.Run("conflict", func(t *testing.T) {
		same := message{Header: dnsmessage.Header{Response: true}, Answers: r.all(0)}
		if r.conflicts(same) {
			t.Error("identical records taken as a conflict")
		}
		other := r.srv()
		other.Port = 9
		if !r.conflicts(message{Header: dnsmessage.Header{Response: true}, Answers: []rr{other}}) {
			t.Error("different SRV not a conflict")
		}
		host := r.addrRR(net.IPv4(198, 51, 100, 1))
		if !r.conflicts(message{Header: dnsmessage.Header{Response: true}, Answers: []rr{host}}) {
			t.Error("host name on another address not a conflict")
		}
		shared := r.addrRR(net.IPv4(192, 0, 2, 7))
		if r.conflicts(message{Header: dnsmessage.Header{Response: true}, Answers: []rr{host, shared}}) {
			t.Error("host set sharing our address taken as a conflict")
		}
	})
}

// TestBrowseCache feeds responses to the browser's cache: it assembles the
// instance from PTR, SRV, TXT and address records, asks for what is
// missing, favours the .local host name and drops an instance on goodbye.
//
// Covers: SIG-MTR-061, SIG-IPE-2365
func TestBrowseCache(t *testing.T) {
	r, err := newResponder(testService(), ServiceType)
	if err != nil {
		t.Fatal(err)
	}
	typeName := serviceTypeName(ServiceType)
	now := time.Now()
	c := newCache()

	// Only the PTR so far: the next query asks for SRV and TXT.
	c.add(message{Header: dnsmessage.Header{Response: true}, Answers: []rr{r.ptr()}}, now)
	known, missing := c.pending(typeName, now)
	if len(known) != 0 || fmt.Sprint(missing) != fmt.Sprint([]want{{r.instName, dnsmessage.TypeSRV}, {r.instName, dnsmessage.TypeTXT}}) {
		t.Fatalf("known %v missing %v", known, missing)
	}
	if got := c.services(typeName, now); len(got) != 0 {
		t.Fatalf("instance without SRV returned: %+v", got)
	}

	pkt, err := r.reply(queryPacket(t, 0, []dnsmessage.Question{mustQ(t, typeName, dnsmessage.TypePTR, false)}, nil), false, 0)
	if err != nil {
		t.Fatal(err)
	}
	m, err := parse(pkt)
	if err != nil {
		t.Fatal(err)
	}
	c.add(m, now)
	known, missing = c.pending(typeName, now)
	if len(known) != 1 || len(missing) != 0 {
		t.Fatalf("known %v missing %v", known, missing)
	}
	got := c.services(typeName, now)
	if len(got) != 1 {
		t.Fatalf("services %+v", got)
	}
	s := got[0]
	if s.Instance != "Site gateway" || s.Host != "vtn-test.local" || s.Port != 8443 || len(s.IPs) != 2 || !maps.Equal(s.TXT, testService().TXT) {
		t.Fatalf("service %+v", s)
	}
	if s.Addr() != "vtn-test.local:8443" {
		t.Fatalf("Addr %q does not favour the .local host", s.Addr())
	}

	// A cache-flush SRV replaces the old one.
	moved := r.srv()
	moved.Port = 9443
	c.add(message{Header: dnsmessage.Header{Response: true}, Answers: []rr{moved}}, now)
	if got := c.services(typeName, now); len(got) != 1 || got[0].Port != 9443 {
		t.Fatalf("after flush %+v", got)
	}

	// Expiry and goodbye.
	if got := c.services(typeName, now.Add(ttlOther*time.Second)); len(got) != 0 {
		t.Fatalf("expired records returned %+v", got)
	}
	bye, err := r.unsolicited(0, true)
	if err != nil {
		t.Fatal(err)
	}
	gm, err := parse(bye)
	if err != nil {
		t.Fatal(err)
	}
	c.add(gm, now)
	if got := c.services(typeName, now); len(got) != 0 {
		t.Fatalf("goodbye left %+v", got)
	}
}

// TestCacheFlushPerInterface: a multihomed responder answers each
// interface with that interface's addresses, each set cache-flushed; a
// flush on one interface must not remove the addresses learned on
// another, routable addresses are listed before link-local ones, and
// per-interface SRV targets are merged.
//
// Covers: SIG-MTR-097
func TestCacheFlushPerInterface(t *testing.T) {
	r, err := newResponder(testService(), ServiceType)
	if err != nil {
		t.Fatal(err)
	}
	typeName := serviceTypeName(ServiceType)
	now := time.Now()
	c := newCache()
	resp := func(ips ...string) message {
		m := message{Header: dnsmessage.Header{Response: true}, Answers: []rr{r.ptr(), r.srv(), r.txtRR()}}
		for _, ip := range ips {
			m.Additionals = append(m.Additionals, r.addrRR(net.ParseIP(ip)))
		}
		return m
	}
	c.addOn(resp("fe80::a", "2001:db8::a"), 4, now) // en0
	c.addOn(resp("fe80::b"), 9, now)                // a tunnel
	got := c.services(typeName, now)
	if len(got) != 1 || fmt.Sprint(got[0].IPs) != "[2001:db8::a fe80::a fe80::b]" {
		t.Fatalf("services %+v", got)
	}
	// A new flushed set on interface 4 replaces only interface 4's.
	c.addOn(resp("2001:db8::c"), 4, now)
	if got := c.services(typeName, now); fmt.Sprint(got[0].IPs) != "[2001:db8::c fe80::b]" {
		t.Fatalf("after flush on 4: %v", got[0].IPs)
	}

	// Per-interface SRV targets (distinct host names per interface): the
	// addresses of every target are merged and Host is a routable one.
	c = newCache()
	tunnel := r.srv()
	tunnel.Target, tunnel.Flush = "tun-host.local.", false
	c.addOn(message{Header: dnsmessage.Header{Response: true}, Answers: []rr{r.ptr(), tunnel, r.txtRR()},
		Additionals: []rr{{Name: tunnel.Target, Type: dnsmessage.TypeAAAA, TTL: ttlHost, IP: net.ParseIP("fe80::b")}}}, 9, now)
	lan := r.srv()
	lan.Flush = false
	c.addOn(message{Header: dnsmessage.Header{Response: true}, Answers: []rr{r.ptr(), lan, r.txtRR()},
		Additionals: []rr{r.addrRR(net.ParseIP("2001:db8::a"))}}, 4, now)
	got = c.services(typeName, now)
	if len(got) != 1 || got[0].Host != "vtn-test.local" || fmt.Sprint(got[0].IPs) != "[2001:db8::a fe80::b]" {
		t.Fatalf("per-interface targets: %+v", got)
	}
}

// TestMulticastRoundTrip announces a VTN on a real interface and browses
// for it, on a non-standard port so the OS responder on 5353 is untouched.
//
// Covers: SIG-MTR-060, SIG-MTR-061, SIG-MTR-085
func TestMulticastRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("uses the network; skipped with -short")
	}
	port := 20000 + rand.IntN(30000)
	ifi, err := TestInterface(port)
	if err != nil {
		t.Skipf("%v", err)
	}
	opts := Options{Interfaces: []net.Interface{*ifi}, Port: port, Loopback: true, Wait: 2 * time.Second}
	t.Logf("interface %s, port %d", ifi.Name, port)
	svc := testService()
	svc.IPs = nil // answer with the interface's own addresses

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	a, err := Announce(ctx, svc, ServiceType, opts)
	if err != nil {
		t.Fatalf("Announce on %s port %d: %v", ifi.Name, port, err)
	}
	defer a.Close()

	got, err := Browse(ctx, ServiceType, opts)
	if err != nil {
		t.Fatalf("Browse: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("Browse on %s port %d found %+v", ifi.Name, port, got)
	}
	s := got[0]
	if s.Instance != svc.Instance || s.Host != "vtn-test.local" || s.Port != svc.Port || !maps.Equal(s.TXT, svc.TXT) {
		t.Fatalf("found %+v", s)
	}
	if len(s.IPs) == 0 {
		t.Errorf("no addresses for %s", s.Host)
	}
	if s.Addr() != "vtn-test.local:8443" {
		t.Errorf("Addr %q", s.Addr())
	}

	// A second announcer with the same instance but another port is a
	// conflict found by probing.
	dup := svc
	dup.Port = 9
	if b, err := Announce(ctx, dup, ServiceType, opts); !errors.Is(err, ErrConflict) {
		if b != nil {
			_ = b.Close()
		}
		t.Errorf("duplicate announce: %v", err)
	}
	// With Rename the duplicate picks a new instance name and succeeds
	// (RFC 6762 clause 9).
	ropts := opts
	var attempts []int
	ropts.Rename = func(s Service, attempt int) Service {
		attempts = append(attempts, attempt)
		s.Instance = fmt.Sprintf("%s (%d)", svc.Instance, attempt+1)
		return s
	}
	b, err := Announce(ctx, dup, ServiceType, ropts)
	if err != nil {
		t.Fatalf("renaming announce: %v", err)
	}
	if len(attempts) != 1 {
		t.Errorf("rename attempts %v", attempts)
	}
	got, _ = Browse(ctx, ServiceType, opts)
	if len(got) != 2 {
		t.Errorf("after rename found %+v", got)
	}
	_ = b.Close()

	if err := a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	got, err = Browse(ctx, ServiceType, Options{Interfaces: opts.Interfaces, Port: port, Loopback: true, Wait: 1500 * time.Millisecond})
	if err != nil {
		t.Fatalf("Browse after Close: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("closed announcer still found: %+v", got)
	}
}
