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

## Sources

| Area (files) | Followed |
|---|---|
| Messages, records, TTLs (message.go) | RFC 6762 clauses 10, 10.2, 18; RFC 1035 for the message format through golang.org/x/net/dns/dnsmessage |
| Responder (responder.go, announce.go) | RFC 6762 clauses 6, 6.7, 7.1, 8.1 to 8.4, 9, 10.1, 13; RFC 6763 clauses 4, 6, 7.1, 9 |
| Browser (browse.go, querier.go, watch.go) | RFC 6762 clauses 5.1, 5.2, 5.4, 7.1, 10.2, 17, 18.1; RFC 6763 clauses 4, 6.4 |
| Socket options (internal/reuse) | the operating systems' SO_REUSEADDR and SO_REUSEPORT, through golang.org/x/sys |

The libraries in the interop module (hashicorp/mdns, grandcat/zeroconf)
were run, not read for code. Their behaviour (who answers which query, and
how) was observed in a comparison on 2026-10-06, together with the devices
named in the README.

No RFC text is included; comments cite clause numbers in our own words.

## Test data

Instance names, host names, MAC-like identifiers, ports and the
192.0.2.0/24 addresses in the tests and examples are made up.
