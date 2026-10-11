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

// TestAvahi runs github.com/cB-Sigma/mdns against Avahi on Linux: two
// Alpine containers with avahi-daemon on a user-defined Docker network;
// one also runs avahipeer (cmd/avahipeer, this module's library built for
// Linux) on the real mDNS port next to its own avahi-daemon. It needs
// Docker and network access for the image (alpine and its avahi
// packages), and is skipped without Docker and with -short.
//
// Docker Desktop on macOS and Windows runs containers in a virtual
// machine, so multicast between the host and the containers does not
// work there; both peers therefore run in containers.
func TestAvahi(t *testing.T) {
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
	for _, f := range []string{"Dockerfile", "start.sh"} {
		b, err := os.ReadFile(filepath.Join("testdata", "avahi", f))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, f), b, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	const image = "sigma-mdns-avahi-interop:test"
	if out, err := run("docker", "build", "-q", "-t", image, dir); err != nil {
		t.Fatalf("docker build: %v\n%s", err, out)
	}
	id := fmt.Sprint(os.Getpid())
	network := "sigma-mdns-avahi-" + id
	if out, err := run("docker", "network", "create", network); err != nil {
		t.Fatalf("docker network create: %v\n%s", err, out)
	}
	t.Cleanup(func() { _, _ = run("docker", "network", "rm", network) })
	avahi, peer := "sigma-avahi-"+id, "sigma-peer-"+id
	for _, c := range [][2]string{{avahi, "avahi-box"}, {peer, "sigma-box"}} {
		if out, err := run("docker", "run", "-d", "--rm", "--name", c[0], "--hostname", c[1], "--network", network, image); err != nil {
			t.Fatalf("docker run %s: %v\n%s", c[0], err, out)
		}
		t.Cleanup(func() { _, _ = run("docker", "kill", c[0]) })
	}
	for _, c := range []string{avahi, peer} {
		ready := false
		for range 50 {
			if _, err := run("docker", "exec", c, "avahi-browse", "-tpk", "_ready._tcp"); err == nil {
				ready = true
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
		if !ready {
			t.Fatalf("avahi-daemon in %s did not start", c)
		}
	}
	avahiIP := containerIP(t, avahi)
	peerIP := containerIP(t, peer)
	t.Logf("avahi container %s, peer container %s", avahiIP, peerIP)
	version, _ := run("docker", "exec", avahi, "avahi-daemon", "--version")
	t.Logf("%s", strings.TrimSpace(version))

	// Avahi publishes, our browser finds.
	publish(t, avahi, "-s", "Avahi Box", "_sigmaavahi._tcp", "8090", "peer=avahi", "fw=2")
	publish(t, avahi, "-s", "--subtype=_vtn._sub._sigmaavahi._tcp", "Avahi Sub", "_sigmaavahi._tcp", "8091")
	time.Sleep(2 * time.Second)

	t.Run("our browser finds avahi-publish", func(t *testing.T) {
		for _, mode := range []string{"both", "oneshot", "multicast"} {
			got := browse(t, peer, "_sigmaavahi._tcp", mode)
			box, ok := got["Avahi Box"]
			if !ok || box.Port != 8090 || box.TXT["peer"] != "avahi" || box.TXT["fw"] != "2" || box.Host != "avahi-box.local" || !contains(box.IPs, avahiIP) {
				t.Errorf("%s browse: %+v", mode, got)
			}
			if _, ok := got["Avahi Sub"]; !ok {
				t.Errorf("%s browse missed the second instance: %+v", mode, got)
			}
		}
		sub := browse(t, peer, "_vtn._sub._sigmaavahi._tcp", "both")
		if len(sub) != 1 || sub["Avahi Sub"].Port != 8091 {
			t.Errorf("subtype browse: %+v", sub)
		}
	})

	t.Run("our type enumeration lists avahi's types", func(t *testing.T) {
		out, err := run("docker", "exec", peer, "avahipeer", "types", "3s")
		if err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		var types []string
		if err := json.Unmarshal([]byte(lastLine(out)), &types); err != nil {
			t.Fatalf("%v: %s", err, out)
		}
		if !contains(types, "_sigmaavahi._tcp") {
			t.Errorf("types %v", types)
		}
	})

	// Our announcer, found by avahi-browse in the other container.
	if out, err := run("docker", "exec", "-d", peer, "avahipeer", "-out", "/tmp/announce.log", "announce", "Sigma Box", "sigma-peer", "_sigmaavahi2._tcp", "8092", "120s", "_vtn"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	time.Sleep(3 * time.Second)

	t.Run("avahi-browse finds our announcer", func(t *testing.T) {
		got := avahiBrowse(t, avahi, "-rtpk", "_sigmaavahi2._tcp")
		r, ok := got["Sigma Box"]
		if !ok || r.port != "8092" || r.host != "sigma-peer.local" || r.addr != peerIP || !strings.Contains(r.txt, `"peer=sigma"`) {
			t.Fatalf("avahi-browse -r: %+v", got)
		}
		if _, ok := avahiBrowse(t, avahi, "-tpk", "_vtn._sub._sigmaavahi2._tcp")["Sigma Box"]; !ok {
			t.Error("avahi-browse of the subtype missed our instance")
		}
		all, err := run("docker", "exec", avahi, "avahi-browse", "-atpk")
		if err != nil || !strings.Contains(all, ";_sigmaavahi2._tcp;") {
			t.Errorf("avahi-browse -a (service type enumeration) lacks our type: %v\n%s", err, all)
		}
	})

	t.Run("avahi resolves our host name", func(t *testing.T) {
		out, err := run("docker", "exec", avahi, "avahi-resolve", "-4", "-n", "sigma-peer.local")
		if err != nil || !strings.Contains(out, peerIP) {
			t.Fatalf("avahi-resolve -4: %v %q", err, out)
		}
		// The containers have no IPv6 address: our responder answers the
		// AAAA question with NSEC. Logged, not asserted: how Avahi takes
		// it is Avahi's business.
		start := time.Now()
		out, err = run("docker", "exec", avahi, "avahi-resolve", "-6", "-n", "sigma-peer.local")
		t.Logf("avahi-resolve -6 after %v: %v %q", time.Since(start).Round(time.Millisecond), err, strings.TrimSpace(out))
	})

	t.Run("avahi renames on our name; we keep it", func(t *testing.T) {
		publish(t, avahi, "-s", "Sigma Box", "_sigmaavahi2._tcp", "9999")
		time.Sleep(3 * time.Second)
		got := avahiBrowse(t, avahi, "-rtpk", "_sigmaavahi2._tcp")
		if got["Sigma Box"].port != "8092" {
			t.Errorf("our instance: %+v", got)
		}
		renamed := false
		for name, r := range got {
			if name != "Sigma Box" && strings.HasPrefix(name, "Sigma Box") && r.port == "9999" {
				renamed = true
				t.Logf("avahi renamed its service to %q", name)
			}
		}
		if !renamed {
			t.Errorf("avahi did not rename: %+v", got)
		}
		log, _ := run("docker", "exec", peer, "cat", "/tmp/announce.log")
		if strings.Contains(log, "conflict-") {
			t.Errorf("our announcer saw a conflict: %s", log)
		}
	})

	t.Run("we rename on avahi's name", func(t *testing.T) {
		out, err := run("docker", "exec", peer, "avahipeer", "announce", "Avahi Box", "sigma-peer2", "_sigmaavahi._tcp", "8093", "2s")
		if err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		if !strings.Contains(out, `"event":"announced","instance":"Avahi Box (2)"`) || !strings.Contains(out, `"event":"conflict-renamed"`) {
			t.Fatalf("announce: %s", out)
		}
	})

	t.Run("avahi drops our instance on goodbye", func(t *testing.T) {
		if out, err := run("docker", "exec", "-d", peer, "avahipeer", "announce", "Brief", "sigma-brief", "_sigmaavahi3._tcp", "8094", "3s"); err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		time.Sleep(2 * time.Second)
		if _, ok := avahiBrowse(t, avahi, "-tpk", "_sigmaavahi3._tcp")["Brief"]; !ok {
			t.Fatal("brief announcer not found")
		}
		time.Sleep(4 * time.Second)
		if got := avahiBrowse(t, avahi, "-tpk", "_sigmaavahi3._tcp"); len(got) != 0 {
			t.Fatalf("still listed after goodbye: %+v", got)
		}
	})
}

func run(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return string(out), err
}

func containerIP(t *testing.T, c string) string {
	t.Helper()
	out, err := run("docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", c)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	return strings.TrimSpace(out)
}

// publish runs avahi-publish detached in container c.
func publish(t *testing.T, c string, args ...string) {
	t.Helper()
	if out, err := run("docker", append([]string{"exec", "-d", c, "avahi-publish"}, args...)...); err != nil {
		t.Fatalf("avahi-publish: %v\n%s", err, out)
	}
}

type peerFound struct {
	Instance string            `json:"instance"`
	Host     string            `json:"host"`
	Port     int               `json:"port"`
	TXT      map[string]string `json:"txt"`
	IPs      []string          `json:"ips"`
}

// browse runs our browser in container c.
func browse(t *testing.T, c, typ, mode string) map[string]peerFound {
	t.Helper()
	out, err := run("docker", "exec", c, "avahipeer", "browse", typ, "3s", mode)
	if err != nil {
		t.Fatalf("browse: %v\n%s", err, out)
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

type avahiEntry struct{ host, addr, port, txt string }

// avahiBrowse runs avahi-browse with parsable output (-p) in container c
// and returns the IPv4 entries by instance name: resolved ("=") lines,
// or plain ("+") lines without -r.
func avahiBrowse(t *testing.T, c string, args ...string) map[string]avahiEntry {
	t.Helper()
	out, err := run("docker", append([]string{"exec", c, "avahi-browse"}, args...)...)
	if err != nil {
		t.Fatalf("avahi-browse %v: %v\n%s", args, err, out)
	}
	got := map[string]avahiEntry{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(line, ";")
		if len(f) < 6 || f[2] != "IPv4" {
			continue
		}
		name := unescape(f[3])
		switch {
		case f[0] == "=" && len(f) >= 10:
			got[name] = avahiEntry{host: f[6], addr: f[7], port: f[8], txt: strings.Join(f[9:], ";")}
		case f[0] == "+":
			if _, ok := got[name]; !ok {
				got[name] = avahiEntry{}
			}
		}
	}
	return got
}

// unescape undoes avahi-browse's \DDD escapes in names.
func unescape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			var n int
			if _, err := fmt.Sscanf(s[i+1:i+4], "%03d", &n); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return lines[len(lines)-1]
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
