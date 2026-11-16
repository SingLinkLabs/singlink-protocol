// Copyright 2026 SingLinkLabs
// SPDX-License-Identifier: Apache-2.0
package singlink

import (
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRevocationFailuresRetainLastGood(t *testing.T) {
	p := filepath.Join(t.TempDir(), "revocations")
	valid := []byte("token 12340000000000000000000000000000\n")
	if err := os.WriteFile(p, valid, 0600); err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, envOpt{mutate: func(c *ServerConfig) { c.RevokedFile = p }})
	tok := &Token{ID: [16]byte{0x12, 0x34}}
	if !e.srv.isRevoked(tok) {
		t.Fatal("valid list missing")
	}
	for _, bad := range []string{"", "# comments only\n", "token 1234", strings.Repeat("#", 80*1024) + "\n", "token invalid\n", "unknown 12340000000000000000000000000000\n", "token 12340000000000000000000000000000 extra\n", "device invalid\n"} {
		if err := os.WriteFile(p, []byte(bad), 0600); err != nil {
			t.Fatal(err)
		}
		if e.srv.reloadRevoked() == nil {
			t.Fatal("malformed update accepted")
		}
		if !e.srv.isRevoked(tok) {
			t.Fatal("last good revocation lost")
		}
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if e.srv.reloadRevoked() == nil || !e.srv.isRevoked(tok) {
		t.Fatal("read failure replaced state")
	}
	if err := os.WriteFile(p, []byte("# explicit valid empty list\nempty\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := e.srv.reloadRevoked(); err != nil {
		t.Fatal(err)
	}
	if e.srv.isRevoked(tok) {
		t.Fatal("valid replacement not applied")
	}
}

func TestInvalidInitialRevocationListRefusesStartup(t *testing.T) {
	key, _ := GenerateServerKey()
	issuer, _ := GenerateEd25519()
	store, err := InitializeReplayFile(filepath.Join(t.TempDir(), "state", "replay.db"), 0)
	if err != nil {
		t.Fatal(err)
	}
	cfg := ServerConfig{Key: key, ReplayStore: store, Issuers: NewIssuers(issuer.Public().(ed25519.PublicKey)), RevokedFile: filepath.Join(t.TempDir(), "missing")}
	if _, err := NewServer(cfg); err == nil {
		t.Fatal("invalid configured list did not refuse startup")
	}
}

// blockingReplayStore holds admissions until released, widening the window
// between the first revocation check and session registration.
type blockingReplayStore struct {
	inner   ReplayStore
	entered chan struct{}
	release chan struct{}
}

func (b *blockingReplayStore) CheckAndMark(ctx context.Context, tag [32]byte, exp time.Time) (bool, error) {
	select {
	case b.entered <- struct{}{}:
	default:
	}
	<-b.release
	return b.inner.CheckAndMark(ctx, tag, exp)
}

// A revocation published while a handshake is between its revocation check
// and session registration must still end that session.
func TestRevocationDuringAdmissionClosesSession(t *testing.T) {
	file := filepath.Join(t.TempDir(), "revocations")
	if err := os.WriteFile(file, []byte("empty\n"), 0600); err != nil {
		t.Fatal(err)
	}
	inner, err := InitializeReplayFile(filepath.Join(t.TempDir(), "state", "replay.db"), 0)
	if err != nil {
		t.Fatal(err)
	}
	bs := &blockingReplayStore{inner: inner, entered: make(chan struct{}, 1), release: make(chan struct{})}
	tok := &Token{Subject: [16]byte{0x9}, Caps: CapTCP, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}
	e := newEnv(t, envOpt{tok: tok, mutate: func(c *ServerConfig) { c.RevokedFile = file; c.ReplayStore = bs }})
	echo := echoServer(t, "")
	done := make(chan *Conn, 1)
	go func() {
		c, err := e.client.DialTCP(context.Background(), echo)
		if err != nil {
			done <- nil
			return
		}
		c.Write([]byte("x"))
		done <- c
	}()
	select {
	case <-bs.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("admission not reached")
	}
	if err := os.WriteFile(file, []byte("subject 09000000000000000000000000000000\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := e.srv.reloadRevoked(); err != nil {
		t.Fatal(err)
	}
	close(bs.release)
	c := <-done
	if c == nil {
		t.Fatal("dial failed")
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if err := c.Handshake(); err != nil {
		return // rejected: safe
	}
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("revoked subject kept a live relayed session")
	}
}
