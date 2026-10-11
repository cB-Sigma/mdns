# Changelog

## v0.3.0 (2026-10-12)

The API only grows; code written for v0.2 builds unchanged.

### Added

- `Reflect` and `Reflector`: repeat mDNS between interfaces (VLANs, guest
  networks), IPv4 and IPv6, with loop suppression per interface;
  `Reflector.Reflected`.
- `BrowseDomains` and `Domains`: the browsing and registration domain
  enumeration of RFC 6763 clause 11.
- `Options.StrictSource`: the browser drops answers from off-link sources
  (RFC 6762 clause 11), off by default.
- `Options.QU`: the unicast-response bit on the first query of a browse
  (RFC 6762 clause 5.4), off by default.
- Interop tests: mDNSResponder through dns-sd on macOS; python-zeroconf
  0.151.5 in Docker (discovery both ways, subtypes, conflicts both ways,
  goodbye, 30 instances each way); several interfaces; an IPv6-only
  network; the reflector between two networks.
- `// Covers:` requirement IDs on the tests added in v0.2.0.

## v0.2.0 (2026-10-11)

Every "no" in the v0.1 feature table is now implemented. The API only
grows; code written for v0.1 builds unchanged.

### Added

- Conflicts after probing (RFC 6762 clause 9): an announcer that hears
  another responder claim its instance or host name with other data stops
  answering for it, probes again and keeps the name, renames through
  `Options.Rename` (numbering on from earlier renames) or gives the name up.
  `Options.OnConflict` receives `ConflictEvent`s (`ConflictSeen`,
  `ConflictKept`, `ConflictRenamed`, `ConflictWithdrawn`), also for a rename
  during `Announce`. `Announcer.Service` returns the name in use and
  `Announcer.Err` the reason after a withdrawal. After 15 conflicts in 10 s
  the next probe waits 5 s (clause 8.1).
- NSEC (clause 6.1): the responder answers questions for types its names
  lack with NSEC, and adds the NSEC (or the other family's addresses) to
  answers that carry addresses (clause 6.2). The browser reads NSEC, stops
  asking for the types it denies and drops cached records of those types.
- Known answers over several packets (clause 7.2): the browser sends known
  answers that do not fit in one packet in further packets with the TC
  bit; the responder holds a truncated query 400-500 ms for them.
- Response timing (clause 6): answers of unique records go out at once,
  answers with shared records after 20-120 ms, aggregated per interface; a
  record is multicast at most once a second per interface, every 250 ms in
  defence against a probe; duplicate answer suppression (clause 7.4).
  Responses longer than one packet are split.
- QU questions are answered by multicast when the record was not multicast
  within a quarter of its TTL (clause 5.4).
- `Watch`: passive observation of failures (clause 10.5), `Watcher.Reconfirm`
  (clause 10.4) and duplicate question suppression for refresh queries
  (clause 7.3).
- `BrowseServiceTypes` lists the service types on the link (RFC 6763
  clause 9).
- Interop test against Avahi 0.8 in Linux containers (`interop`,
  `TestAvahi`, needs Docker).

### Changed

- Probes for our names are answered by multicast, also when the probe asks
  for a unicast reply, so the prober sees the answer on every socket that
  shares port 5353.
- A cache-flush record replaces only records received more than a second
  before it (clause 10.2), and a goodbye leaves its record one more second
  (clause 10.1), so `Watch` reports `Removed` up to a second later than
  before.
- Known answers in queries are only records with at least half their TTL
  left (clause 7.1).
- When a flush leaves two copies of a record for that second, the browser
  uses the newest.
- The responder ignores packets sent to its unicast address from off the
  local link (clause 11), responses not sent from the mDNS port (clause 6),
  and messages with a non-zero response code (clause 18.11); the browser
  ignores messages with a non-zero response code.

## v0.1.1 and v0.1.0

First published releases; see the repository history.
