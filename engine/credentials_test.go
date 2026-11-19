// Copyright 2026 SingLinkVPN (https://singlinkvpn.com)
// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"io"
	"net"
	"testing"
	"time"
)

// socksAuth reports whether the local proxy at addr accepts user/pass.
func socksAuth(t *testing.T, addr, user, pass string) bool {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		return false
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	c.Write([]byte{5, 1, 2})
	r := make([]byte, 2)
	if _, err := io.ReadFull(c, r); err != nil || r[1] != 2 {
		return false
	}
	c.Write(append(append(append([]byte{1, byte(len(user))}, user...), byte(len(pass))), pass...))
	if _, err := io.ReadFull(c, r); err != nil {
		return false
	}
	return r[1] == 0
}

// Stop forgets the generated proxy credentials, and every Start with Auth
// generates fresh ones; credentials of an earlier session are refused.
func TestCredentialsClearedOnStopAndFreshOnStart(t *testing.T) {
	p, _ := testNode(t)
	var e Engine
	defer e.Stop()
	if err := e.Start(p.Link(), "127.0.0.1:0", Options{Auth: true}); err != nil {
		t.Fatal(err)
	}
	user1, pass1 := e.Credentials()
	listen1 := e.Status().Listen
	if user1 == "" || pass1 == "" || !socksAuth(t, listen1, user1, pass1) {
		t.Fatal("first session credentials not usable")
	}
	e.Stop()
	if user, pass := e.Credentials(); user != "" || pass != "" {
		t.Fatal("credentials kept after Stop")
	}

	user2, pass2, err := e.StartAuth(p.Link(), "127.0.0.1:0", Options{Auth: true})
	if err != nil {
		t.Fatal(err)
	}
	if u, pw := e.Credentials(); u != user2 || pw != pass2 {
		t.Fatal("StartAuth and Credentials disagree")
	}
	listen2 := e.Status().Listen
	if user2 == "" || pass2 == "" || user2 == user1 || pass2 == pass1 {
		t.Fatal("second session did not get fresh credentials")
	}
	if !socksAuth(t, listen2, user2, pass2) {
		t.Fatal("second session credentials not usable")
	}
	if socksAuth(t, listen2, user1, pass1) {
		t.Fatal("first session credentials accepted by the second session")
	}

	// StopClient of the active client clears them as well.
	e.mu.Lock()
	c := e.client
	e.mu.Unlock()
	if !e.StopClient(c) {
		t.Fatal("StopClient did not stop the active client")
	}
	if user, pass := e.Credentials(); user != "" || pass != "" {
		t.Fatal("credentials kept after StopClient")
	}

	// A failed Start does not bring back old credentials.
	if err := e.Start("singlink://invalid", "127.0.0.1:0", Options{Auth: true}); err == nil {
		t.Fatal("invalid link accepted")
	}
	if user, pass := e.Credentials(); user != "" || pass != "" {
		t.Fatal("credentials after a failed Start")
	}
}
