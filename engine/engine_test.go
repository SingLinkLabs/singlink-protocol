// Copyright 2026 SingLinkVPN (https://singlinkvpn.com)
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"crypto/ed25519"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/SingLinkLabs/singlink-protocol/singlink"
)

func TestStartWithCustomTransport(t *testing.T) {
	key, _ := singlink.GenerateServerKey()
	issuer, _ := singlink.GenerateEd25519()
	dev, _ := singlink.GenerateEd25519()
	srv, _ := singlink.NewServer(singlink.ServerConfig{BlockedPorts: []uint16{443}, ReplayStore: testReplayStore(t), Key: key, Issuers: singlink.NewIssuers(issuer.Public().(ed25519.PublicKey))})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go srv.Serve(ln)
	time.Sleep(1100 * time.Millisecond)
	tok, _ := singlink.IssueToken(issuer, &singlink.Token{DevicePub: dev.Public().(ed25519.PublicKey), Caps: singlink.CapTCP,
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)})
	link := (&singlink.Profile{Server: ln.Addr().String(), Transport: "tcp", ServerKey: key.Public(), Token: tok, Device: dev}).Link()

	var e Engine
	stopped := false
	err = e.StartWith(link, "tun", func(c *singlink.Client) (func(), error) {
		if c == nil {
			t.Fatal("no client")
		}
		return func() { stopped = true }, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if st := e.Status(); !st.Running || st.Listen != "tun" {
		t.Fatalf("status %+v", st)
	}
	if e.StartWith(link, "tun", nil) == nil {
		t.Fatal("second start accepted")
	}
	e.Stop()
	if !stopped || e.Status().Running {
		t.Fatal("stop not propagated")
	}
}

func testReplayStore(t *testing.T) singlink.ReplayStore {
	t.Helper()
	s, err := singlink.InitializeReplayFile(filepath.Join(t.TempDir(), "state", "replay.db"), 0)
	if err != nil {
		t.Fatal(err)
	}
	// Registered after t.TempDir, so it runs before the directory is
	// removed: it waits for store operations still running in node handlers
	// (which outlive the test) and refuses new ones. Otherwise Windows can
	// fail the cleanup with "directory is not empty" while a handler writes
	// a snapshot.
	cs := &closingStore{store: s}
	t.Cleanup(cs.close)
	return cs
}

// closingStore wraps a test replay store so that it can be shut down before
// its directory is removed.
type closingStore struct {
	store  singlink.ReplayStore
	mu     sync.Mutex
	closed bool
	active sync.WaitGroup
}

func (c *closingStore) enter() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return false
	}
	c.active.Add(1)
	return true
}

func (c *closingStore) close() {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	c.active.Wait()
}

func (c *closingStore) CheckAndMark(ctx context.Context, tag [32]byte, expiry time.Time) (bool, error) {
	if !c.enter() {
		return false, singlink.ErrReplayStore
	}
	defer c.active.Done()
	return c.store.CheckAndMark(ctx, tag, expiry)
}

func (c *closingStore) Has(ctx context.Context, tag [32]byte) (bool, error) {
	if !c.enter() {
		return false, singlink.ErrReplayStore
	}
	defer c.active.Done()
	return c.store.Has(ctx, tag)
}

// auditNodeConfig completes a synthetic test node configuration.
func auditNodeConfig(t *testing.T, cfg singlink.ServerConfig) singlink.ServerConfig {
	t.Helper()
	cfg.ReplayStore = testReplayStore(t)
	return cfg
}
