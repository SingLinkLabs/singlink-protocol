//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

// Copyright 2026 SingLinkVPN (https://singlinkvpn.com)
// SPDX-License-Identifier: Apache-2.0
package singlink

import (
	"os"
	"testing"
)

// exposeReplayPath gives other local users access to path (mode 0644/0755).
func exposeReplayPath(t *testing.T, path string) {
	t.Helper()
	st, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	mode := os.FileMode(0644)
	if st.IsDir() {
		mode = 0755
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// restrictReplayPath makes path private again (mode 0600/0700).
func restrictReplayPath(t *testing.T, path string) {
	t.Helper()
	st, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	mode := os.FileMode(0600)
	if st.IsDir() {
		mode = 0700
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// assertReplayPathPrivate checks the exact private mode of a state object.
func assertReplayPathPrivate(t *testing.T, path string) {
	t.Helper()
	st, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	want := os.FileMode(0600)
	if st.IsDir() {
		want = 0700
	}
	if st.Mode().Perm() != want || !replayPrivate(path, st) {
		t.Fatalf("state object %s has mode %v", path, st.Mode().Perm())
	}
}
