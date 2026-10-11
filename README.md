# mdns

A multicast DNS (RFC 6762) and DNS-SD (RFC 6763) responder and browser in pure Go.

[![Go Reference](https://pkg.go.dev/badge/github.com/cB-Sigma/mdns.svg)](https://pkg.go.dev/github.com/cB-Sigma/mdns) [![test](https://github.com/cB-Sigma/mdns/actions/workflows/test.yml/badge.svg)](https://github.com/cB-Sigma/mdns/actions/workflows/test.yml) [![Licence: Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](LICENSE) [![Go](https://img.shields.io/badge/go-1.27.1-00ADD8.svg)](go.mod)

It announces services with subtypes, probes, renames on conflicts found
while probing or later, and browses so that it finds responders that
answer only by unicast as well as those that answer only by multicast,
once or continuously. It is built on golang.org/x/net and the standard
library, without cgo. It was written for SigmaM2M, a oneM2M platform,
where it serves OpenADR 3, Matter and several device integrations.

## Features

Clauses are RFC 6762 unless marked RFC 6763.

| Feature | Status |
|---|---|
| Responder: PTR, SRV, TXT, A, AAAA, ANY; subtypes; `_services._dns-sd._udp` (RFC 6763 9) | yes |
| Probing, conflict detection while probing, renaming (`Options.Rename`, at most 15) | yes |
| Simultaneous-probe tie-breaking (8.2, 8.2.1) | yes |
| Conflicts after probing (9): re-probe, rename or withdraw, `Options.OnConflict` events, `Announcer.Service`, `Announcer.Err`; 15 conflicts in 10 s pause probing 5 s (8.1) | yes (since v0.2.0) |
| NSEC negative answers for our names (6.1), and NSEC or the other family's addresses as additional records (6.2) | yes (since v0.2.0) |
| Legacy unicast replies (6.7), known-answer suppression (7.1) | yes |
| QU questions answered by unicast unless the record was not multicast within a quarter of its TTL (5.4) | yes (the 5.4 rule since v0.2.0) |
| Known answers over several packets with the TC bit: the responder waits 400-500 ms for them (7.2) | yes (since v0.2.0) |
| Unique answers at once, shared answers after 20-120 ms and aggregated per interface (6) | yes (since v0.2.0) |
| A record multicast at most once a second per interface, 250 ms in probe defence (6); probes answered by multicast | yes (since v0.2.0) |
| Duplicate answer suppression (7.4) | yes (since v0.2.0) |
| Responses over the MTU split into several packets (17) | yes (since v0.2.0) |
| Packets sent to our unicast address only from the local link (11); responses only from port 5353 (6); messages with an error code ignored (18.11) | yes (since v0.2.0) |
| TXT update without probing (`UpdateTXT`) | yes |
| Re-join and re-announce on interface changes (checked every 10 s) | yes; a new interface is announced on without a new probe |
| Browser: one-shot and multicast queries at once, several types in one query train | yes |
| Known answers over several packets with the TC bit when they do not fit in one (7.2) | yes (since v0.2.0) |
| Known answers only with at least half their TTL left (7.1) | yes (since v0.2.0) |
| NSEC read: no more questions for types a responder says it lacks; cached records of those types dropped (6.1) | yes (since v0.2.0) |
| Cache flush: per interface, merged multihomed answers; records from the last second kept (10.2); goodbyes kept one second (10.1) | yes (the one-second rules since v0.2.0) |
| Continuous browsing (`Watch`): passive cache, refresh at 80 to 95 % of TTL (5.2), events | yes |
| Passive observation of failures: records others ask for twice without an answer are dropped after 10 s (10.5) | yes, in `Watch` (since v0.2.0) |
| Reconfirmation on request: `Watcher.Reconfirm` (10.4) | yes (since v0.2.0) |
| Duplicate question suppression for refresh queries (7.3) | yes, in `Watch` (since v0.2.0) |
| Service type enumeration as a browser: `BrowseServiceTypes` (RFC 6763 9) | yes (since v0.2.0) |
| IPv4 and IPv6 | yes |

Left out on purpose:

- QU questions from the browser (5.4). A unicast reply to port 5353
  reaches only one of the sockets that share it, often the operating
  system's responder, so the browser asks without QU and gets unicast
  answers through its one-shot socket instead.
- Browsing domains (RFC 6763 11, `b._dns-sd._udp` and the like). They
  point at unicast DNS-SD domains; on the link, `local.` is the only
  domain.
- Off-link source checks in the browser (11). A device with a wrong static
  address on the same segment should still be found, so the browser takes
  answers from any source; a host off the link that can reach the
  browser's one-shot port could therefore add records to its results. The
  responder does check.

### Why both ways at once

Responders on real networks answer a query in one of two ways, and a
browser that queries only one way misses the others:

| Responder | Answers | One-shot only (ephemeral port) | From 5353 only | Both (default) |
|---|---|---|---|---|
| hashicorp/mdns, a cast receiver | unicast to the query's source | found | missed where the OS responder holds 5353 | found |
| Go zeroconf forks, betamos, matter.js, a Spotify desktop responder | multicast only | missed | found | found |
| this module, mDNSResponder, Avahi | both | found | found | found |

The 5353 sockets set SO_REUSEADDR and SO_REUSEPORT so they share the port
with mDNSResponder, Avahi or systemd-resolved. When the port cannot be
bound (another responder holds it without SO_REUSEPORT, or Windows), the
browser carries on with one-shot queries. In a container, multicast needs
the host network.

## Choosing a Go mDNS library

Compared from each library's source at the versions named, in October
2026 (the rows on conflicts after probing, NSEC, TC, rate limits and
failure observation by searching each source for them on 2026-10-11);
"tested" rows were run on one macOS LAN. Check the projects themselves
before relying on a row.

| | this module | hashicorp/mdns v1.0.7 | grandcat/zeroconf v1.0.0 | libp2p/zeroconf v2.2.0 | brutella/dnssd v1.2.14 | pion/mdns v2.2.2 |
|---|---|---|---|---|---|---|
| Announces unsolicited (not only answers queries) | yes | no | yes | yes | yes | yes |
| Probing, conflict renaming | yes, with tie-breaking | no | no | no | yes, with tie-breaking | no |
| Conflicts after probing (RFC 6762 9) | yes, with events | no | no | no | yes | no |
| NSEC negative answers | sends and reads | no | no | no | sends | no |
| Known answers over truncated (TC) packets | as querier and responder | no (TODO in source) | no | no | as responder | no |
| Shared-answer delay, aggregation, per-record rate limit | yes | no | no | no | delay only | no |
| Passive observation of failures, reconfirm | yes (`Watch`) | no | no | no | no | no |
| Subtypes, announce and browse (tested) | yes | no | no | yes | no | no |
| Answers one-shot (legacy unicast) queries (tested) | yes | yes | no | no | yes | yes |
| Finds unicast-only and multicast-only responders in one browse (tested) | yes | no | no | no | no | no |
| Browse returns only the asked type | yes | no, other types too | yes | yes | yes | no, caller filters |
| Continuous browse with change events | yes (`Watch`) | no | partial | yes | yes | yes |
| Goodbye on close | yes | no | yes | yes | yes | yes |
| Port other than 5353, for tests | yes | no | no | no | no | yes |
| `context.Context` | yes | timeouts only | yes | yes | yes | yes |
| Dependencies | golang.org/x/net | miekg/dns | miekg/dns and two more | miekg/dns | miekg/dns, netlink | pion/logging, pion/transport |

Pick this module when you need to be found reliably and to find every
kind of device on a real LAN: Matter, HomeKit-style or OpenADR
announcements with subtypes and probing, or discovery of consumer devices
whose responders answer only one way. Pick hashicorp/mdns if you already
use it, only need simple lookups in a controlled network, and want the
longest track record. Pick pion/mdns inside a pion WebRTC stack, and
brutella/dnssd for a HomeKit accessory built on brutella/hap.
brutella/dnssd also keeps results of Apple's Bonjour Conformance Test in
its repository; this module has not been run against that test, so where
a passed conformance run is a requirement, brutella/dnssd is the one with
evidence.

## Install

```
go get github.com/cB-Sigma/mdns@latest
```

Requires Go 1.27.1 or later.

## Quick start

```go
import "github.com/cB-Sigma/mdns"

// Once.
found, err := mdns.Browse(ctx, "_hue._tcp", mdns.Options{Wait: 3 * time.Second})

// Continuously.
w, err := mdns.Watch(ctx, []string{"_ewelink._tcp", "_shelly._tcp"}, mdns.Options{}, func(e mdns.Event) {
	fmt.Println(e.Kind, e.Type, e.Service.Instance, e.Service.TXT["seq"])
})
defer w.Close()

// Announce, with a subtype, renaming on a conflict, also one found later.
a, err := mdns.Announce(ctx, mdns.Service{Instance: "Site gateway", Host: "gateway", Port: 8443,
	TXT: map[string]string{"version": "1"}, Subtypes: []string{"_vtn"}}, "_openadr3._tcp",
	mdns.Options{Rename: mdns.RenameInstance, OnConflict: func(e mdns.ConflictEvent) {
		fmt.Println(e.Kind, e.Service.Instance)
	}})
defer a.Close()
_ = a.UpdateTXT(map[string]string{"version": "2"})

// The service types on the link.
types, err := mdns.BrowseServiceTypes(ctx, mdns.Options{Wait: 3 * time.Second})

// An instance a connection failed to: ask whether it is still there.
w.Reconfirm("_shelly._tcp", "shellyplus1-a8032ab1")
```

These mirror `ExampleBrowse`, `ExampleWatch`, `ExampleAnnounce`,
`ExampleConflictEvent`, `ExampleBrowseServiceTypes` and
`ExampleWatcher_Reconfirm` in example_test.go, which compile with the
tests but do not run (they need a network). `ExampleRenameInstance` runs
and checks its output.

## Documentation

API reference: https://pkg.go.dev/github.com/cB-Sigma/mdns

| Package | What it does |
|---|---|
| `mdns` (module root) | `Announce` (probe with tie-breaking, `Options.Rename` with `RenameInstance`, announce, answer with NSEC, delays, aggregation and rate limits, `UpdateTXT`, re-join on interface changes, goodbye on `Close`; conflicts after probing through `Options.OnConflict`, `Announcer.Service`, `Announcer.Err`), `Browse` and `BrowseTypes` (one-shot and multicast queries at once by default; `Options.Mode` for either alone), `BrowseServiceTypes`, `Watch` (continuous: cached announcements, refresh before expiry, passive observation of failures, `Watcher.Reconfirm`, `Added`/`Updated`/`Removed` events), `TestInterface` |
| `internal/reuse` | SO_REUSEADDR and SO_REUSEPORT on the mDNS sockets |
| `interop` (nested module, tests only) | this module against hashicorp/mdns and grandcat/zeroconf on the real port 5353, and against Avahi in Linux containers (`cmd/avahipeer`, `testdata/avahi`) |

## Testing

```
go test -race ./...
```

Tests that need multicast pick a random port and an interface on which
multicast loops back to the host; they skip when there is none, and with
`-short`. Tests carry `// Covers: SIG-...` and `// Covers: SIG-MTR-...`
comments: these are requirement IDs of the SigmaM2M project's compliance
report and have no meaning outside it. The tests added in v0.2.0 carry
none yet.

The browse and watch tests against the simulated devices are in
[mdns-sim](https://github.com/cB-Sigma/mdns-sim), so this module does not
depend on its simulator.

`interop/` is a nested module with its own go.mod, so its dependencies stay
out of this one. Its tests against hashicorp/mdns and grandcat/zeroconf
use the real port 5353 and are skipped unless `SIGMA_MDNS_INTEROP=1` is
set. `TestAvahi` builds `cmd/avahipeer` (this module) for Linux and runs it
in an Alpine container next to avahi-daemon, with a second Avahi container
on the same user-defined Docker network; it needs Docker and network
access for the image, and is skipped without Docker and with `-short`.
Docker Desktop on macOS and Windows runs containers in a virtual machine,
where multicast does not reach the host, so both peers run in containers.

```
cd interop && SIGMA_MDNS_INTEROP=1 go test -v ./...   # LAN peers and Avahi
cd interop && go test -v -run TestAvahi ./...         # Avahi only
```

### Interop tested against

- In process, on a test port: the simulated devices of each answer style
  in mdns-sim (written with dnsmessage rather than this module's encoder,
  but by the same author, so not independent).
- On the real port 5353 on one macOS LAN (`interop`, 2026-10-06):
  hashicorp/mdns v1.0.7 and grandcat/zeroconf v1.0.0 as responders (found
  by the default browse; hashicorp missed from 5353 alone, zeroconf missed
  one-shot alone) and as browsers (both found our announcer).
- Real devices on that LAN: a Sony BRAVIA cast receiver
  (`_googlecast._tcp`), a Sony audio device and a Spotify desktop
  responder (`_spotify-connect._tcp`) were all found by the default
  browse, the same instances `dns-sd -B` listed; one-shot alone missed
  the Spotify desktop responder.
- matter.js 0.17.9, through the interop tests of SigmaM2M's Matter stack
  (runs made before this module was split out).
- Avahi 0.8 on Linux (`TestAvahi`, Alpine 3.20.3 containers on a
  user-defined Docker bridge network, Docker Desktop 29.4.3 on arm64,
  2026-10-11; v0.2.0): our browser found services from `avahi-publish`
  by default, one-shot only and multicast only, with TXT, host and
  address, and a subtype alone; `BrowseServiceTypes` listed Avahi's type;
  `avahi-browse -r` found and resolved our announcer, its subtype and its
  type in `avahi-browse -a`; `avahi-resolve -4` resolved our host name;
  when `avahi-publish` claimed our instance name, Avahi renamed its
  service to "Sigma Box #2" and our announcer kept its name; when we
  claimed Avahi's name, we renamed to "Avahi Box (2)"; Avahi dropped our
  instance after our goodbye. Our side shared port 5353 with an
  avahi-daemon in its own container throughout. `avahi-resolve -6` for
  our IPv4-only host, which we answer with NSEC, still waited for its
  5 s timeout: Avahi 0.8 did not act on the NSEC.
- v0.2.0 on the macOS LAN (2026-10-11): the hashicorp/mdns and
  grandcat/zeroconf runs above repeated with the same results, and
  `BrowseServiceTypes` listed six types (the Mac's own mDNSResponder
  types and a Sony BRAVIA's `_googlecast._tcp` and
  `_androidtvremote2._tcp`).
- Not yet: systemd-resolved, Windows, Apple's Bonjour Conformance Test,
  several active interfaces, IPv6-only links. NSEC, truncated known
  answers, rate limits, passive observation and late conflicts are tested
  against the simulator and hand-built packets (written by the same
  author), not against another implementation.

## Related repositories

- [mdns-sim](https://github.com/cB-Sigma/mdns-sim): simulated mDNS/DNS-SD
  devices in each answer style, as a Go package and a command.

## Status

v0.x: the API may change before v1.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md) to report a vulnerability privately.

## Licence

Apache-2.0 (see [LICENSE](LICENSE) and [NOTICE](NOTICE)). Copyright 2026
Abhinav Gautam.
