// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

//go:build !(darwin || dragonfly || freebsd || linux || netbsd || openbsd)

package reuse

import "syscall"

// Control does nothing here: the platform has no SO_REUSEPORT, so the
// mDNS port cannot be shared with another responder.
func Control(_, _ string, _ syscall.RawConn) error { return nil }
