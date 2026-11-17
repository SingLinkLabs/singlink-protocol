//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly && !windows

// Copyright 2026 SingLinkVPN (https://singlinkvpn.com)
// SPDX-License-Identifier: Apache-2.0
package singlink

import "testing"

// The reference file store fails closed on this platform; its permission
// tests do not apply.

func exposeReplayPath(t *testing.T, _ string) {
	t.Helper()
	t.Skip("no reference file store on this platform")
}

func restrictReplayPath(t *testing.T, _ string) {
	t.Helper()
	t.Skip("no reference file store on this platform")
}

func assertReplayPathPrivate(t *testing.T, _ string) {
	t.Helper()
	t.Skip("no reference file store on this platform")
}
