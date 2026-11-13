// Copyright 2026 SingLinkLabs
// SPDX-License-Identifier: Apache-2.0
package singlink

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
