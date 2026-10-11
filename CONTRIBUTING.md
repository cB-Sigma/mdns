# Contributing to mdns

Issues and pull requests are welcome.

## Reporting a problem

Open an issue with the version (`go list -m github.com/cB-Sigma/mdns`),
the Go version, what you did, what you expected and what happened. For a
protocol problem, a captured frame or message (with any real identifiers,
keys and addresses replaced) helps most. Report security problems
privately instead; see [SECURITY.md](SECURITY.md).

## Pull requests

- Keep a change to one subject, with a test that fails without it.
- Run `gofmt`, `go vet ./...` and `go test -race ./...` before you push.
- No cgo, and no new dependency without a reason given in the pull request.
- New Go files carry `// Copyright <year> <author>` and
  `// SPDX-License-Identifier: Apache-2.0`.
- Write comments and documentation in your own words. Cite standards by
  number and clause; do not copy their text, tables or examples into the
  code, tests or documentation.
- A sign-off (DCO) is not required. By opening a pull request you agree that
  your contribution is licensed under the Apache License 2.0, as section 5
  of the licence describes.
