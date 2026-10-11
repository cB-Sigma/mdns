// Test-only module: github.com/cB-Sigma/mdns against other mDNS implementations on the
// real port 5353 (see interop_test.go). Not part of the published module;
// its dependencies stay out of the library's go.mod.
module github.com/cB-Sigma/mdns/interop

go 1.27.1

replace github.com/cB-Sigma/mdns => ../

require (
	github.com/grandcat/zeroconf v1.0.0
	github.com/hashicorp/mdns v1.0.7
	github.com/cB-Sigma/mdns v0.0.0
)

require (
	github.com/cenkalti/backoff v2.2.1+incompatible // indirect
	github.com/miekg/dns v1.1.72 // indirect
	golang.org/x/mod v0.31.0 // indirect
	golang.org/x/net v0.59.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/tools v0.40.0 // indirect
)
