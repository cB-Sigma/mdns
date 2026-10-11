// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// zcSetup builds the python-zeroconf peer image (python-zeroconf 0.151.5
// and avahipeer) and returns its tag, skipping without Docker.
func zcSetup(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("builds a Docker image; skipped with -short")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("no docker command")
	}
	arch, err := run("docker", "info", "--format", "{{.Architecture}}")
	if err != nil {
		t.Skipf("Docker is not running: %v", err)
	}
	goarch := map[string]string{"aarch64": "arm64", "arm64": "arm64", "x86_64": "amd64", "amd64": "amd64"}[strings.TrimSpace(arch)]
	if goarch == "" {
		t.Skipf("Docker architecture %q", arch)
	}
	dir := t.TempDir()
	build := exec.Command("go", "build", "-o", filepath.Join(dir, "avahipeer"), "./cmd/avahipeer")
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+goarch, "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building avahipeer: %v\n%s", err, out)
	}
	for _, f := range []string{"Dockerfile", "zcpeer.py"} {
		b, err := os.ReadFile(filepath.Join("testdata", "zeroconf", f))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, f), b, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	const image = "sigma-mdns-zeroconf-interop:zeroconf-0.151.5"
	if out, err := run("docker", "build", "-q", "-t", image, dir); err != nil {
		t.Fatalf("docker build: %v\n%s", err, out)
	}
	return image
}

// network creates a Docker network (extra arguments such as --ipv6) and
// removes it at the end.
func network(t *testing.T, name string, extra ...string) {
	t.Helper()
	if out, err := run("docker", append(append([]string{"network", "create"}, extra...), name)...); err != nil {
		t.Fatalf("docker network create %s: %v\n%s", name, err, out)
	}
	t.Cleanup(func() { _, _ = run("docker", "network", "rm", name) })
}

// container starts a peer container on the first network and connects it
// to the others.
func container(t *testing.T, image, name, host string, networks ...string) {
	t.Helper()
	if out, err := run("docker", "run", "-d", "--rm", "--name", name, "--hostname", host, "--network", networks[0], image); err != nil {
		t.Fatalf("docker run %s: %v\n%s", name, err, out)
	}
	t.Cleanup(func() { _, _ = run("docker", "kill", name) })
	for _, n := range networks[1:] {
		if out, err := run("docker", "network", "connect", n, name); err != nil {
			t.Fatalf("docker network connect %s %s: %v\n%s", n, name, err, out)
		}
	}
}

func ipOn(t *testing.T, c, network string, v6 bool) string {
	t.Helper()
	field := "IPAddress"
	if v6 {
		field = "GlobalIPv6Address"
	}
	out, err := run("docker", "inspect", "-f", fmt.Sprintf(`{{(index .NetworkSettings.Networks %q).%s}}`, network, field), c)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	return strings.TrimSpace(out)
}

// zcBrowse runs python-zeroconf's browser in container c.
func zcBrowse(t *testing.T, c, typ, wait, ipv string) map[string]peerFound {
	t.Helper()
	out, err := run("docker", "exec", c, "python", "/usr/local/bin/zcpeer.py", "browse", typ, wait, ipv)
	if err != nil {
		t.Fatalf("zcpeer browse: %v\n%s", err, out)
	}
	var list []peerFound
	if err := json.Unmarshal([]byte(lastLine(out)), &list); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	m := map[string]peerFound{}
	for _, f := range list {
		m[f.Instance] = f
	}
	return m
}

// detached starts a command in container c with its JSON lines going to
// file; lines reads them back.
func detached(t *testing.T, c string, args ...string) {
	t.Helper()
	if out, err := run("docker", append([]string{"exec", "-d", c}, args...)...); err != nil {
		t.Fatalf("docker exec -d %v: %v\n%s", args, err, out)
	}
}

func lines(t *testing.T, c, file string) []map[string]any {
	t.Helper()
	out, _ := run("docker", "exec", c, "cat", file)
	var got []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) == nil {
			got = append(got, m)
		}
	}
	return got
}

func eventOf(ls []map[string]any, kind string) map[string]any {
	for _, l := range ls {
		if l["event"] == kind {
			return l
		}
	}
	return nil
}

// Covers: SIG-IPE-7353
//
// TestZeroconf runs github.com/cB-Sigma/mdns against python-zeroconf
// 0.151.5 on Linux, in two containers on a Docker network: discovery both
// ways (subtypes included), conflicts while probing and after, goodbyes,
// and responses too large for one packet both ways.
func TestZeroconf(t *testing.T) {
	image := zcSetup(t)
	id := fmt.Sprint(os.Getpid())
	net1 := "sigma-mdns-zc-" + id
	network(t, net1)
	zc, peer := "sigma-zc-"+id, "sigma-zcpeer-"+id
	container(t, image, zc, "zc-box", net1)
	container(t, image, peer, "sigma-box", net1)
	zcIP, peerIP := ipOn(t, zc, net1, false), ipOn(t, peer, net1, false)

	t.Run("python-zeroconf finds our announcer and its subtype", func(t *testing.T) {
		detached(t, peer, "avahipeer", "-out", "/tmp/a1", "announce", "Sigma Box", "sigma-box", "_sigmazc._tcp", "8095", "12s", "_vtn")
		time.Sleep(3 * time.Second)
		got := zcBrowse(t, zc, "_sigmazc._tcp", "3", "v4")
		box, ok := got["Sigma Box"]
		if !ok || box.Port != 8095 || box.TXT["peer"] != "sigma" || !contains(box.IPs, peerIP) {
			t.Fatalf("python-zeroconf found %+v", got)
		}
		if sub := zcBrowse(t, zc, "_vtn._sub._sigmazc._tcp", "3", "v4"); len(sub) != 1 {
			t.Fatalf("subtype browse found %+v", sub)
		}
	})

	t.Run("our browser finds python-zeroconf's service", func(t *testing.T) {
		detached(t, zc, "python", "/usr/local/bin/zcpeer.py", "-out", "/tmp/z1", "register", "ZC Box", "zc-box", "_sigmazc2._tcp", "8096", "15", "v4")
		time.Sleep(3 * time.Second)
		for _, mode := range []string{"both", "oneshot", "multicast"} {
			got := browse(t, peer, "_sigmazc2._tcp", mode)
			box, ok := got["ZC Box"]
			if !ok || box.Port != 8096 || box.TXT["peer"] != "zeroconf" || !contains(box.IPs, zcIP) {
				t.Errorf("%s browse: %+v", mode, got)
			}
		}
	})

	t.Run("python-zeroconf renames after our announcer holds the name", func(t *testing.T) {
		detached(t, peer, "avahipeer", "-out", "/tmp/a2", "announce", "Held Name", "sigma-box", "_sigmazc3._tcp", "8097", "15s")
		time.Sleep(3 * time.Second)
		detached(t, zc, "python", "/usr/local/bin/zcpeer.py", "-out", "/tmp/z2", "register", "Held Name", "zc-box", "_sigmazc3._tcp", "8098", "8", "v4")
		time.Sleep(5 * time.Second)
		reg := eventOf(lines(t, zc, "/tmp/z2"), "registered")
		if reg == nil || reg["instance"] == "Held Name" {
			t.Fatalf("python-zeroconf registered %v", reg)
		}
		if c := eventOf(lines(t, peer, "/tmp/a2"), "conflict-renamed"); c != nil {
			t.Fatalf("our announcer renamed: %v", c)
		}
		t.Logf("python-zeroconf took %q", reg["instance"])
	})

	t.Run("our announcer renames when python-zeroconf holds the name", func(t *testing.T) {
		detached(t, zc, "python", "/usr/local/bin/zcpeer.py", "-out", "/tmp/z3", "register", "ZC Held", "zc-box", "_sigmazc4._tcp", "8099", "15", "v4")
		time.Sleep(4 * time.Second)
		detached(t, peer, "avahipeer", "-out", "/tmp/a3", "announce", "ZC Held", "sigma-box", "_sigmazc4._tcp", "8100", "5s")
		time.Sleep(4 * time.Second)
		ann := eventOf(lines(t, peer, "/tmp/a3"), "announced")
		if ann == nil || ann["instance"] == "ZC Held" {
			t.Fatalf("our announcer: %v", lines(t, peer, "/tmp/a3"))
		}
		t.Logf("we took %q", ann["instance"])
	})

	t.Run("python-zeroconf sees our goodbye", func(t *testing.T) {
		detached(t, zc, "python", "/usr/local/bin/zcpeer.py", "-out", "/tmp/z4", "watch", "_sigmazc5._tcp", "10", "v4")
		time.Sleep(time.Second)
		detached(t, peer, "avahipeer", "-out", "/tmp/a4", "announce", "Brief Box", "sigma-box", "_sigmazc5._tcp", "8101", "3s")
		time.Sleep(10 * time.Second)
		ev := lines(t, zc, "/tmp/z4")
		added, removed := false, false
		for _, e := range ev {
			if strings.HasPrefix(fmt.Sprint(e["name"]), "Brief Box.") {
				added = added || e["event"] == "added"
				removed = removed || e["event"] == "removed"
			}
		}
		if !added || !removed {
			t.Fatalf("events %v", ev)
		}
	})

	t.Run("thirty instances each way", func(t *testing.T) {
		// Both sides probe each name in turn: wait until all are announced.
		detached(t, peer, "avahipeer", "-out", "/tmp/a5", "announce-many", "Many", "30", "sigma-box", "_sigmazc6._tcp", "8102", "90s")
		detached(t, zc, "python", "/usr/local/bin/zcpeer.py", "-out", "/tmp/z5", "register", "ZMany", "zc-box", "_sigmazc7._tcp", "8103", "90", "v4", "30")
		deadline := time.Now().Add(75 * time.Second)
		for time.Now().Before(deadline) {
			n := 0
			for _, l := range lines(t, zc, "/tmp/z5") {
				if l["event"] == "registered" {
					n++
				}
			}
			if n == 30 && eventOf(lines(t, peer, "/tmp/a5"), "announced") != nil {
				break
			}
			time.Sleep(time.Second)
		}
		time.Sleep(2 * time.Second)
		if got := zcBrowse(t, zc, "_sigmazc6._tcp", "4", "v4"); len(got) != 30 {
			t.Errorf("python-zeroconf found %d of our 30", len(got))
		}
		for _, mode := range []string{"both", "multicast"} {
			if got := browse(t, peer, "_sigmazc7._tcp", mode); len(got) != 30 {
				t.Errorf("%s browse found %d of python-zeroconf's 30", mode, len(got))
			}
		}
	})
}

// Covers: SIG-IPE-7354
//
// TestMultiInterface: our responder and browser in a container on two
// Docker networks. A python-zeroconf peer on each network finds our
// announcer with the address of its own network only, and our browser
// finds both peers' services, each with its network's address.
func TestMultiInterface(t *testing.T) {
	image := zcSetup(t)
	id := fmt.Sprint(os.Getpid())
	n1, n2 := "sigma-mdns-n1-"+id, "sigma-mdns-n2-"+id
	network(t, n1)
	network(t, n2)
	multi, a, b := "sigma-multi-"+id, "sigma-a-"+id, "sigma-b-"+id
	container(t, image, multi, "multi-box", n1, n2)
	container(t, image, a, "a-box", n1)
	container(t, image, b, "b-box", n2)
	m1, m2 := ipOn(t, multi, n1, false), ipOn(t, multi, n2, false)

	detached(t, multi, "avahipeer", "-out", "/tmp/m1", "announce", "Multi Box", "multi-box", "_sigmamulti._tcp", "8110", "15s")
	detached(t, a, "python", "/usr/local/bin/zcpeer.py", "-out", "/tmp/r", "register", "A Box", "a-box", "_sigmamulti2._tcp", "8111", "15", "v4")
	detached(t, b, "python", "/usr/local/bin/zcpeer.py", "-out", "/tmp/r", "register", "B Box", "b-box", "_sigmamulti2._tcp", "8112", "15", "v4")
	time.Sleep(4 * time.Second)
	for _, p := range []struct{ c, want, not string }{{a, m1, m2}, {b, m2, m1}} {
		got := zcBrowse(t, p.c, "_sigmamulti._tcp", "3", "v4")
		box, ok := got["Multi Box"]
		if !ok || !contains(box.IPs, p.want) || contains(box.IPs, p.not) {
			t.Errorf("from %s: %+v (want %s, not %s)", p.c, got, p.want, p.not)
		}
	}
	got := browse(t, multi, "_sigmamulti2._tcp", "both")
	if got["A Box"].Port != 8111 || got["B Box"].Port != 8112 ||
		!contains(got["A Box"].IPs, ipOn(t, a, n1, false)) || !contains(got["B Box"].IPs, ipOn(t, b, n2, false)) {
		t.Errorf("our browser on two networks: %+v", got)
	}
}

// Covers: SIG-IPE-7355
//
// TestIPv6Only: on a Docker network without IPv4, our announcer is found
// by python-zeroconf over IPv6 with its IPv6 address, and our browser
// finds python-zeroconf's service with its IPv6 address.
func TestIPv6Only(t *testing.T) {
	image := zcSetup(t)
	id := fmt.Sprint(os.Getpid())
	n6 := "sigma-mdns-v6-" + id
	network(t, n6, "--ipv6", "--ipv4=false", "--subnet", "fd53:5353:"+fmt.Sprintf("%x", os.Getpid()%0xffff)+"::/64")
	ours, zc := "sigma-v6peer-"+id, "sigma-v6zc-"+id
	container(t, image, ours, "v6-sigma", n6)
	container(t, image, zc, "v6-zc", n6)
	oursIP, zcIP := ipOn(t, ours, n6, true), ipOn(t, zc, n6, true)
	if v4 := ipOn(t, ours, n6, false); oursIP == "" || zcIP == "" || (v4 != "" && v4 != "invalid IP") {
		t.Fatalf("not an IPv6-only network: %q %q", oursIP, zcIP)
	}
	detached(t, ours, "avahipeer", "-out", "/tmp/v1", "announce", "V6 Box", "v6-sigma", "_sigmav6._tcp", "8120", "15s")
	detached(t, zc, "python", "/usr/local/bin/zcpeer.py", "-out", "/tmp/v2", "register", "ZV6 Box", "v6-zc", "_sigmav6b._tcp", "8121", "15", "v6")
	time.Sleep(4 * time.Second)
	got := zcBrowse(t, zc, "_sigmav6._tcp", "3", "v6")
	if box, ok := got["V6 Box"]; !ok || box.Port != 8120 || !contains(box.IPs, oursIP) {
		t.Errorf("python-zeroconf over IPv6: %+v (want %s)", got, oursIP)
	}
	ourGot := browse(t, ours, "_sigmav6b._tcp", "both")
	if box, ok := ourGot["ZV6 Box"]; !ok || box.Port != 8121 || !contains(box.IPs, zcIP) {
		t.Errorf("our browser over IPv6: %+v (want %s)", ourGot, zcIP)
	}
}

// Covers: SIG-IPE-7360
//
// TestReflector: our reflector in a container on two Docker networks. A
// service python-zeroconf registers on one network is found by
// python-zeroconf and by our browser on the other, and the other way
// round; without the reflector it is not.
func TestReflector(t *testing.T) {
	image := zcSetup(t)
	id := fmt.Sprint(os.Getpid())
	n1, n2 := "sigma-mdns-r1-"+id, "sigma-mdns-r2-"+id
	network(t, n1)
	network(t, n2)
	refl, a, b := "sigma-refl-"+id, "sigma-ra-"+id, "sigma-rb-"+id
	container(t, image, refl, "refl-box", n1, n2)
	container(t, image, a, "ra-box", n1)
	container(t, image, b, "rb-box", n2)
	detached(t, a, "python", "/usr/local/bin/zcpeer.py", "-out", "/tmp/r", "register", "Left Box", "ra-box", "_sigmarefl._tcp", "8130", "40", "v4")
	detached(t, b, "python", "/usr/local/bin/zcpeer.py", "-out", "/tmp/r", "register", "Right Box", "rb-box", "_sigmarefl._tcp", "8131", "40", "v4")
	time.Sleep(3 * time.Second)
	if got := zcBrowse(t, b, "_sigmarefl._tcp", "3", "v4"); len(got) != 1 {
		t.Fatalf("without the reflector, the right network sees %+v", got)
	}
	detached(t, refl, "avahipeer", "-out", "/tmp/refl", "reflect", "30s")
	time.Sleep(time.Second)
	gotB := zcBrowse(t, b, "_sigmarefl._tcp", "4", "v4")
	if left, ok := gotB["Left Box"]; !ok || left.Port != 8130 || !contains(left.IPs, ipOn(t, a, n1, false)) {
		t.Errorf("python-zeroconf on the right network: %+v", gotB)
	}
	gotA := browse(t, a, "_sigmarefl._tcp", "multicast")
	if right, ok := gotA["Right Box"]; !ok || right.Port != 8131 {
		t.Errorf("our browser on the left network: %+v", gotA)
	}
}
