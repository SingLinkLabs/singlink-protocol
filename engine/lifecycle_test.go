// Copyright 2026 SingLinkVPN (https://singlinkvpn.com)
// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"context"
	"crypto/ed25519"
	"errors"
	"github.com/SingLinkLabs/singlink-protocol/singlink"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func lifecycleProfile(t *testing.T, node string) *singlink.Profile {
	t.Helper()
	key, _ := singlink.GenerateServerKey()
	issuer, _ := singlink.GenerateEd25519()
	device, _ := singlink.GenerateEd25519()
	if node == "" {
		srv, err := singlink.NewServer(singlink.ServerConfig{Key: key, ReplayStore: testReplayStore(t), Issuers: singlink.NewIssuers(issuer.Public().(ed25519.PublicKey)), BlockedPorts: []uint16{443}})
		if err != nil {
			t.Fatal(err)
		}
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		go srv.Serve(ln)
		node = ln.Addr().String()
	}
	token, err := singlink.IssueToken(issuer, &singlink.Token{DevicePub: device.Public().(ed25519.PublicKey), Caps: singlink.CapTCP, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	return &singlink.Profile{Server: node, Transport: "tcp", ServerKey: key.Public(), Token: token, Device: device}
}

func TestStopInvalidatesOldTransportCompletion(t *testing.T) {
	link := lifecycleProfile(t, "").Link()
	var e Engine
	defer e.Stop()
	entered, release := make(chan struct{}), make(chan struct{})
	var oldCleanup, newCleanup atomic.Int32
	done := make(chan error, 1)
	go func() {
		done <- e.StartWith(link, "old", func(*singlink.Client) (func(), error) {
			close(entered)
			<-release
			return func() { oldCleanup.Add(1) }, nil
		})
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("callback not reached")
	}
	e.Stop()
	if e.Status().Running {
		t.Fatal("stop did not stop")
	}
	if err := e.StartWith(link, "new", func(*singlink.Client) (func(), error) { return func() { newCleanup.Add(1) }, nil }); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal("stale completion accepted")
	}
	if oldCleanup.Load() != 1 || newCleanup.Load() != 0 || !e.Status().Running || e.Status().Listen != "new" {
		t.Fatal("old completion changed new transport")
	}
	e.Stop()
	e.Stop()
	if oldCleanup.Load() != 1 || newCleanup.Load() != 1 {
		t.Fatal("cleanup not exactly once")
	}
}

func TestStopCancelsPendingHandshake(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	link := lifecycleProfile(t, ln.Addr().String()).Link()
	var e Engine
	defer e.Stop()
	var called atomic.Bool
	done := make(chan error, 1)
	go func() {
		done <- e.StartWith(link, "cancel", func(*singlink.Client) (func(), error) { called.Store(true); return func() {}, nil })
	}()
	select {
	case c := <-accepted:
		defer c.Close()
	case <-time.After(time.Second):
		t.Fatal("no connection")
	}
	e.Stop()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("wrong cancellation result")
		}
	case <-time.After(time.Second):
		t.Fatal("handshake cancellation stalled")
	}
	if called.Load() || e.Status().Running {
		t.Fatal("cancelled start became active")
	}
}

func TestOldErrorCannotOverwriteNewLifecycle(t *testing.T) {
	var e Engine
	old := e.begin()
	e.Stop()
	current := e.begin()
	if err := e.finish(current, nil, func() {}, "current", "", "", nil); err != nil {
		t.Fatal(err)
	}
	if err := e.finish(old, nil, nil, "old", "", "", errors.New("old failure")); !errors.Is(err, context.Canceled) {
		t.Fatal("old error not cancelled")
	}
	if st := e.Status(); !st.Running || st.LastError != "" || st.Listen != "current" {
		t.Fatal("stale error overwrote current state")
	}
	e.Stop()
}

func TestStopClientOwnsPendingAndActiveGeneration(t *testing.T) {
	var e Engine
	oldClient, newClient := &singlink.Client{}, &singlink.Client{}
	old := e.begin()
	if !e.attachClient(old, oldClient) || !e.StopClient(oldClient) {
		t.Fatal("pending owner not cancelled")
	}
	var oldCleanup, newCleanup atomic.Int32
	current := e.begin()
	if !e.attachClient(current, newClient) {
		t.Fatal("current owner not attached")
	}
	if err := e.finish(current, newClient, func() { newCleanup.Add(1) }, "current", "", "", nil); err != nil {
		t.Fatal(err)
	}
	if e.StopClient(oldClient) {
		t.Fatal("stale owner stopped replacement")
	}
	if err := e.finish(old, oldClient, func() { oldCleanup.Add(1) }, "old", "", "", nil); !errors.Is(err, context.Canceled) {
		t.Fatal("old callback republished")
	}
	if oldCleanup.Load() != 1 || newCleanup.Load() != 0 || !e.Status().Running {
		t.Fatal("wrong resource cleaned")
	}
	if !e.StopClient(newClient) || newCleanup.Load() != 1 || e.Status().Running {
		t.Fatal("active owner not stopped")
	}
	if e.StopClient(newClient) || e.StopClient(nil) {
		t.Fatal("already-stopped owner matched")
	}
}
