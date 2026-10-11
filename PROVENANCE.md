# Provenance

## How the code was written

Written in Go for SigmaM2M, a oneM2M platform, from the IETF RFCs listed
below. No code was ported or copied from another implementation, and no
source file of another project was translated.

The responder and browser began as the local VTN discovery of SigmaM2M's
OpenADR 3 integration. A copy went into SigmaM2M's Matter stack, which
added subtypes, renaming after a conflict, browsing from the mDNS port and
the per-interface cache flush. On 2026-10-06 the two copies were merged
into this module, starting from the Matter copy, which held everything the
other had except OpenADR's service type and TXT helper (those stayed with
the OpenADR code). Writing our own module was chosen over adopting an
existing library because none answered both ways (see the README).

Added for this module: browsing both ways at once (querier.go), several
types per browse, Watch (watch.go), simultaneous-probe tie-breaking,
UpdateTXT, interface re-join, RenameInstance, the simulator and its
command (now in the separate mdns-sim module), and the interop tests.

Added in v0.2.0 (2026-10-11), again from the RFCs alone: conflicts after
probing (conflict.go), NSEC records (message.go, responder.go,
browse.go), known answers over truncated packets, response delay,
aggregation, rate limits and duplicate answer suppression (outbox.go),
the source checks, passive observation of failures, reconfirmation and
duplicate question suppression (watch.go, browse.go, querier.go), the
one-second cache-flush and goodbye rules, service type enumeration as a
browser (enumerate.go), and the Avahi interop test (interop/avahi_test.go,
interop/cmd/avahipeer, interop/testdata/avahi).

## Sources

| Area (files) | Followed |
|---|---|
| Messages, records, TTLs (message.go) | RFC 6762 clauses 6.1, 7.2, 10, 10.2, 17, 18, 18.14; RFC 4034 clause 4 for the NSEC record and its type bitmaps; RFC 1035 for the message format through golang.org/x/net/dns/dnsmessage |
| Responder (responder.go, announce.go, outbox.go, conflict.go) | RFC 6762 clauses 5.4, 6, 6.1, 6.2, 6.7, 7.1, 7.2, 7.4, 8.1 to 8.4, 9, 10.1, 11, 13, 18.11; RFC 6763 clauses 4, 6, 7.1, 9 |
| Browser (browse.go, querier.go, watch.go, enumerate.go) | RFC 6762 clauses 5.1, 5.2, 5.4, 6.1, 7.1, 7.2, 7.3, 10.1, 10.2, 10.4, 10.5, 17, 18.1, 18.11; RFC 6763 clauses 4, 6.4, 9 |
| Socket options (internal/reuse) | the operating systems' SO_REUSEADDR and SO_REUSEPORT, through golang.org/x/sys |

The libraries in the interop module (hashicorp/mdns, grandcat/zeroconf)
were run, not read for code. Their behaviour (who answers which query, and
how) was observed in a comparison on 2026-10-06, together with the devices
named in the README. Avahi (avahi-daemon 0.8 and its command-line tools,
from Alpine's packages, installed in a container at test time and not
distributed) was likewise run, not read, on 2026-10-11.

For v0.3.0, python-zeroconf 0.151.5 (LGPL-2.1) and the macOS 26.3.1
mDNSResponder (through dns-sd) were run as peers, not read, on
2026-10-12. The reflector repeats multicast mDNS between interfaces, the behaviour
Avahi's enable-reflector option is known for; it was written without
reading Avahi's code. RFC 6763 clause 11
(browsing domains) and RFC 6762 clauses 5.4 and 11 were followed for
BrowseDomains, Options.QU and Options.StrictSource.

For the README's comparison table, the sources of hashicorp/mdns,
grandcat/zeroconf, libp2p/zeroconf, brutella/dnssd and pion/mdns at the
versions named there were searched for NSEC, TC, conflict, delay and
reconfirmation handling on 2026-10-11; nothing was taken from them.

No RFC text is included; comments cite clause numbers in our own words.

## Test data

Instance names, host names, MAC-like identifiers, ports and the
192.0.2.0/24, 198.51.100.0/24 and 2001:db8::/32 (documentation)
addresses in the tests and examples are made up.
