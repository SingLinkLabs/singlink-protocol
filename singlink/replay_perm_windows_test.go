//go:build windows

// Copyright 2026 SingLinkVPN (https://singlinkvpn.com)
// SPDX-License-Identifier: Apache-2.0
package singlink

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func isDir(t *testing.T, path string) bool {
	t.Helper()
	st, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return st.IsDir()
}

// exposeReplayPath grants Everyone access to path (a protected DACL).
func exposeReplayPath(t *testing.T, path string) {
	t.Helper()
	sddl := "D:P(A;;FA;;;WD)"
	if isDir(t, path) {
		sddl = "D:P(A;OICI;FA;;;WD)"
	}
	if err := setDACL(path, sddl); err != nil {
		t.Fatal(err)
	}
	if replayPrivate(path, nil) {
		t.Fatal("exposed path still counts as private")
	}
}

// restrictReplayPath restores the store's private DACL on path.
func restrictReplayPath(t *testing.T, path string) {
	t.Helper()
	sid, err := currentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	sddl := "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + sid + ")"
	if isDir(t, path) {
		sddl = privateDirSDDL(sid)
	}
	if err := setDACL(path, sddl); err != nil {
		t.Fatal(err)
	}
}

// assertReplayPathPrivate checks the owner and DACL of a state object.
func assertReplayPathPrivate(t *testing.T, path string) {
	t.Helper()
	st, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !replayPrivate(path, st) {
		t.Fatalf("state object %s is not private", path)
	}
}

// Windows-only: a store directory that inherits a public DACL is refused,
// and a directory the store creates is private with inherited entries.
func TestWindowsReplayDirectoryACL(t *testing.T) {
	base := t.TempDir()
	public := filepath.Join(base, "public")
	if err := os.Mkdir(public, 0700); err != nil {
		t.Fatal(err)
	}
	exposeReplayPath(t, public)
	if _, err := InitializeReplayFile(filepath.Join(public, "replay.db"), 0); err == nil {
		t.Fatal("state initialized in a public directory")
	}
	s, err := InitializeReplayFile(filepath.Join(base, "private", "replay.db"), 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{filepath.Dir(s.path), s.path, s.path + ".lock"} {
		assertReplayPathPrivate(t, p)
	}
	if ok, err := s.CheckAndMark(context.Background(), replayTag("w"), time.Now().Add(time.Minute)); !ok || err != nil {
		t.Fatal("mark in private Windows state failed", err)
	}
}
