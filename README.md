# mdns

A multicast DNS (RFC 6762) and DNS-SD (RFC 6763) responder and browser in pure Go.

[![Go Reference](https://pkg.go.dev/badge/github.com/cB-Sigma/mdns.svg)](https://pkg.go.dev/github.com/cB-Sigma/mdns) [![test](https://github.com/cB-Sigma/mdns/actions/workflows/test.yml/badge.svg)](https://github.com/cB-Sigma/mdns/actions/workflows/test.yml) [![Licence: Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](LICENSE) [![Go](https://img.shields.io/badge/go-1.27.1-00ADD8.svg)](go.mod)

It announces services with subtypes, probes and renames on conflicts, and
browses so that it finds responders that answer only by unicast as well as
those that answer only by multicast, once or continuously. It is built on
golang.org/x/net and the standard library, without cgo. It was written for
SigmaM2M, a oneM2M platform, where it serves OpenADR 3, Matter and several
device integrations.

## Features

| Feature | Status |
|---|---|
| Responder: PTR, SRV, TXT, A, AAAA, ANY; subtypes; `_services._dns-sd._udp` | yes |
| Probing, conflict detection while probing, renaming (`Options.Rename`, at most 15) | yes |
| Simultaneous-probe tie-breaking (RFC 6762 8.2, 8.2.1) | yes |
| Legacy unicast replies, known-answer suppression, QU questions | yes |
| TXT update without probing (`UpdateTXT`) | yes |
| Re-join and re-announce on interface changes (checked every 10 s) | yes; a new interface is announced on without a new probe |
| Conflicts after probing (RFC 6762 9, ongoing) | no |
| Browser: one-shot and multicast queries at once, several types in one query train | yes |
| Per-interface cache flush, merged multihomed answers | yes |
| Continuous browsing (`Watch`): passive cache, refresh at 80 to 95 % of TTL, events | yes |
| NSEC, known answers split over truncated packets, response aggregation and rate limits | no |
| IPv4 and IPv6 | yes |

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

// Announce, with a subtype, renaming on a conflict.
a, err := mdns.Announce(ctx, mdns.Service{Instance: "Site gateway", Host: "gateway", Port: 8443,
	TXT: map[string]string{"version": "1"}, Subtypes: []string{"_vtn"}}, "_openadr3._tcp",
	mdns.Options{Rename: mdns.RenameInstance})
defer a.Close()
_ = a.UpdateTXT(map[string]string{"version": "2"})
```

These mirror `ExampleBrowse`, `ExampleWatch` and `ExampleAnnounce` in
example_test.go, which compile with the tests but do not run (they need a
network). `ExampleRenameInstance` runs and checks its output.

## Documentation

API reference: https://pkg.go.dev/github.com/cB-Sigma/mdns

| Package | What it does |
|---|---|
| `mdns` (module root) | `Announce` (probe with tie-breaking, `Options.Rename` with `RenameInstance`, announce, answer, `UpdateTXT`, re-join on interface changes, goodbye on `Close`), `Browse` and `BrowseTypes` (one-shot and multicast queries at once by default; `Options.Mode` for either alone), `Watch` (continuous: cached announcements, refresh before expiry, `Added`/`Updated`/`Removed` events), `TestInterface` |
| `internal/reuse` | SO_REUSEADDR and SO_REUSEPORT on the mDNS sockets |
| `interop` (nested module, tests only) | this module against hashicorp/mdns and grandcat/zeroconf on the real port 5353 |

## Testing

```
go test -race ./...
```

Tests that need multicast pick a random port and an interface on which
multicast loops back to the host; they skip when there is none, and with
`-short`. Tests carry `// Covers: SIG-...` and `// Covers: SIG-MTR-...`
comments: these are requirement IDs of the SigmaM2M project's compliance
report and have no meaning outside it.

The browse and watch tests against the simulated devices are in
[mdns-sim](https://github.com/cB-Sigma/mdns-sim), so this module does not
depend on its simulator.

`interop/` is a nested module with its own go.mod, so its dependencies stay
out of this one. It runs this module against hashicorp/mdns and
grandcat/zeroconf on the real port 5353, and is skipped unless
`SIGMA_MDNS_INTEROP=1` is set:

```
cd interop && SIGMA_MDNS_INTEROP=1 go test -v ./...
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
- Not yet: Linux with Avahi or systemd-resolved, Windows, several active
  interfaces, IPv6-only links.

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
