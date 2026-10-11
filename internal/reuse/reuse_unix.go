// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

// Package reuse sets the socket options that let several sockets (ours,
// the simulator's and the operating system's responder) bind the mDNS port
// together.
package reuse

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// Control sets SO_REUSEADDR and SO_REUSEPORT; every socket bound to the
// port receives each multicast datagram. Use it as net.ListenConfig.Control.
func Control(_, _ string, c syscall.RawConn) error {
	var serr error
	err := c.Control(func(fd uintptr) {
		if serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); serr != nil {
			return
		}
		serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	})
	if err != nil {
		return err
	}
	return serr
}
