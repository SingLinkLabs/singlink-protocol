// Copyright 2026 SingLinkLabs
// SPDX-License-Identifier: Apache-2.0
package singlink

// Regression tests ported from the 2026-11-13 third-party source audit of
// commit 78cde5e (findings P-01, P-02, P-03, P-05; P-04 is in package
// engine). The audit's reproductions passed while the defect existed; these
// versions assert the safe behaviour instead and fail on 78cde5e. Synthetic
// keys, loopback sockets and temporary files only.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Control (not a finding): the cryptographic checks the audit confirmed.
func TestAuditCryptographicControls(t *testing.T) {
	key, err := GenerateServerKey()
	if err != nil {
		t.Fatal(err)
	}
	issuer, _ := GenerateEd25519()
	device, _ := GenerateEd25519()
	tok, err := IssueToken(issuer, &Token{DevicePub: device.Public().(ed25519.PublicKey), Caps: CapTCP, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	dst, _ := ParseAddr("example.invalid:443")
	marker := []byte("SYNTHETIC-AUDIT-CIPHERTEXT-CONTROL")
	flight, _, err := buildFirstFlight(key.Public(), device, &request{ts: time.Now(), cmd: CmdTCP, dst: dst, token: tok, early: marker}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(flight, marker) {
		t.Fatal("plaintext marker in ciphertext")
	}
	hs, err := parseFirstFlight(flight, []*ServerPrivateKey{key})
	if err != nil || !bytes.Equal(hs.req.early, marker) {
		t.Fatal("valid decrypt control failed", err)
	}
	corrupt := append([]byte{}, flight...)
	corrupt[len(corrupt)-1] ^= 1
	if _, err := parseFirstFlight(corrupt, []*ServerPrivateKey{key}); err == nil {
		t.Fatal("mutated AEAD accepted")
	}
	changed := append([]byte{}, tok...)
	changed[85] ^= 1
	if _, err := NewIssuers(issuer.Public().(ed25519.PublicKey)).Verify(changed); err == nil {
		t.Fatal("mutated signed capability accepted")
	}
	_, c2s, s2c, err := hs.accept()
	if err != nil {
		t.Fatal(err)
	}
	if len(c2s.key) != 32 || len(s2c.key) != 32 || bytes.Equal(c2s.key, s2c.key) {
		t.Fatal("directional keys not separated")
	}
	if c2s.aead.NonceSize() != 12 || c2s.aead.Overhead() != 16 {
		t.Fatal("unexpected AEAD parameters")
	}
}

func auditServe(t *testing.T, cfg ServerConfig) string {
	t.Helper()
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go srv.Serve(ln)
	return ln.Addr().String()
}

// P-01: a captured first flight must trigger at most one destination
// operation across a fresh process and across two instances racing on it.
func TestAuditP01ReplayRejectedAcrossInstances(t *testing.T) {
	e := newEnv(t, envOpt{mutate: func(c *ServerConfig) {
		c.FlightIdle = 5 * time.Millisecond
		c.HandshakeTimeout = 2 * time.Second
	}})
	dst, _ := ParseAddr(echoServer(t, ""))
	build := func(marker []byte) ([]byte, *clientHandshake) {
		flight, hs, err := buildFirstFlight(e.key.Public(), e.device, &request{ts: time.Now().Add(45 * time.Second), cmd: CmdTCP, dst: dst, token: e.profile.Token, early: marker}, 0)
		if err != nil {
			t.Fatal(err)
		}
		return flight, hs
	}
	accepted := func(addr string, flight []byte, hs *clientHandshake, marker []byte) bool {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			t.Error(err)
			return false
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err = c.Write(flight); err != nil {
			return false
		}
		F := make([]byte, 32)
		if _, err = io.ReadFull(c, F); err != nil {
			return false
		}
		_, s2c, err := hs.finish(F)
		if err != nil {
			return false
		}
		fr := &frameReader{r: c, cs: s2c}
		typ, b, err := fr.readFrame()
		if err != nil || typ != frameStatus || len(b) == 0 || Status(b[0]) != StatusOK {
			return false
		}
		typ, b, err = fr.readFrame()
		return err == nil && typ == frameData && bytes.Equal(b, marker)
	}

	marker := []byte("SYNTHETIC-REPLAY-RESTART")
	flight, hs := build(marker)
	if !accepted(e.addr, flight, hs, marker) {
		t.Fatal("positive control: initial request rejected")
	}
	if accepted(e.addr, flight, hs, marker) {
		t.Fatal("same-instance duplicate accepted")
	}
	fresh := auditServe(t, auditFreshInstanceConfig(t, e.srv.cfg))
	if accepted(fresh, flight, hs, marker) {
		t.Fatal("P-01: replayed first flight accepted by a fresh instance sharing the key")
	}

	marker = []byte("SYNTHETIC-REPLAY-PARALLEL")
	flight, hs = build(marker)
	nodes := []string{
		auditServe(t, auditFreshInstanceConfig(t, e.srv.cfg)),
		auditServe(t, auditFreshInstanceConfig(t, e.srv.cfg)),
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	count := 0
	for _, n := range nodes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if accepted(n, flight, hs, marker) {
				mu.Lock()
				count++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if count != 1 {
		t.Fatalf("P-01: one first flight admitted %d times by two parallel instances", count)
	}
}

// P-02: an oversized line must not silently drop a valid revocation.
func TestAuditP02OversizedRevocationRetainsLastGood(t *testing.T) {
	file := filepath.Join(t.TempDir(), "synthetic-revocations")
	entry := "token 12340000000000000000000000000000\n"
	if err := os.WriteFile(file, []byte(entry), 0600); err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, envOpt{mutate: func(c *ServerConfig) { c.RevokedFile = file }})
	token := &Token{ID: [16]byte{0x12, 0x34}}
	if !e.srv.isRevoked(token) {
		t.Fatal("positive control: valid revocation absent")
	}
	if err := os.WriteFile(file, []byte(strings.Repeat("#", 80*1024)+"\n"+entry), 0600); err != nil {
		t.Fatal(err)
	}
	e.srv.reloadRevoked()
	if !e.srv.isRevoked(token) {
		t.Fatal("P-02: oversized line removed a previously valid revocation")
	}
}

// P-02: after a rejected update, a corrected list still takes effect and
// closes live sessions it revokes.
func TestAuditP02CorrectedRevocationClosesLiveSession(t *testing.T) {
	file := filepath.Join(t.TempDir(), "synthetic-revocations")
	entry := "token 12340000000000000000000000000000\n"
	if err := os.WriteFile(file, []byte(entry), 0600); err != nil {
		t.Fatal(err)
	}
	tok := &Token{Subject: [16]byte{0x7}, Caps: CapTCP, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}
	e := newEnv(t, envOpt{tok: tok, mutate: func(c *ServerConfig) { c.RevokedFile = file }})
	c := dial(t, e, echoServer(t, ""))
	roundTrip(t, c, []byte("live"))
	subject := "subject 07000000000000000000000000000000\n"
	if err := os.WriteFile(file, []byte(entry+"\xff\xfe not-an-entry\n"+subject), 0600); err != nil {
		t.Fatal(err)
	}
	e.srv.reloadRevoked()
	if !e.srv.isRevoked(&Token{ID: [16]byte{0x12, 0x34}}) {
		t.Fatal("invalid update dropped the last good list")
	}
	roundTrip(t, c, []byte("still live"))
	if err := os.WriteFile(file, []byte(entry+subject), 0600); err != nil {
		t.Fatal(err)
	}
	e.srv.reloadRevoked()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("corrected revocation did not close the live session")
	}
	if !e.srv.isRevoked(&Token{ID: [16]byte{0x12, 0x34}}) {
		t.Fatal("corrected list lost an existing revocation")
	}
}

// P-03: NAT64 equivalents get the same deny/local/private policy as the
// embedded IPv4 address; legitimate targets and port rules are unchanged.
func TestAuditP03NAT64EquivalentPolicy(t *testing.T) {
	v4 := netip.MustParseAddr("8.8.8.8")
	equivalent := netip.MustParseAddr("64:ff9b::808:808")
	mapped := netip.MustParseAddr("::ffff:8.8.8.8")
	check := func(r *resolver, ip netip.Addr, port uint16) Status {
		_, status := r.resolve(context.Background(), Addr{IP: ip, Port: port})
		return status
	}
	synthetic := func(set map[netip.Addr]bool) localAddrs { return localAddrs{set: set, when: time.Now()} }
	cases := []struct {
		name string
		r    *resolver
	}{
		{"custom IPv4 deny", &resolver{deny: []netip.Prefix{netip.MustParsePrefix("8.8.8.8/32")}, local: synthetic(map[netip.Addr]bool{})}},
		{"synthetic node interface", &resolver{local: synthetic(map[netip.Addr]bool{v4: true})}},
	}
	for _, c := range cases {
		for _, ip := range []netip.Addr{v4, mapped, equivalent} {
			if got := check(c.r, ip, 443); got != StatusForbiddenDest {
				t.Fatalf("P-03 %s: %v allowed (%v)", c.name, ip, got)
			}
		}
	}
	if check(&resolver{local: synthetic(map[netip.Addr]bool{}), allowPrivate: false}, netip.MustParseAddr("64:ff9b::a00:1"), 443) != StatusForbiddenDest {
		t.Fatal("NAT64 equivalent of a private IPv4 allowed")
	}
	open := &resolver{local: synthetic(map[netip.Addr]bool{}), blockedPorts: map[uint16]bool{25: true}}
	for _, ip := range []netip.Addr{v4, equivalent} {
		if check(open, ip, 443) != StatusOK {
			t.Fatalf("public target %v regressed", ip)
		}
		if check(open, ip, 25) != StatusForbiddenDest {
			t.Fatalf("port rule regressed for %v", ip)
		}
	}
}

func auditSink(t *testing.T) (string, chan int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	received := make(chan int, 32)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				b := make([]byte, MaxEarlyData)
				if n, err := io.ReadFull(c, b); err == nil {
					received <- n
				}
			}()
		}
	}()
	return ln.Addr().String(), received
}

// P-05: early application bytes debit the subject's token bucket, shared with
// framed bytes and parallel reconnects, and isolated from other subjects.
func TestAuditP05EarlyBytesShareSubjectBucket(t *testing.T) {
	tok := &Token{Subject: [16]byte{0x51}, Caps: CapTCP, RateKbps: 8, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}
	e := newEnv(t, envOpt{tok: tok, mutate: func(c *ServerConfig) { c.FlightIdle = 2 * time.Millisecond }})
	payload := bytes.Repeat([]byte{0x58}, MaxEarlyData)
	early := func(cl *Client, dst string) {
		c, err := cl.DialTCP(context.Background(), dst)
		if err != nil {
			t.Error(err)
			return
		}
		t.Cleanup(func() { c.Close() })
		c.SetDeadline(time.Now().Add(5 * time.Second))
		if n, err := c.Write(payload); err != nil || n != len(payload) {
			t.Error("write", n, err)
			return
		}
		if err := c.Handshake(); err != nil {
			t.Error(err)
		}
	}
	blocked := func(ch chan int, what string) {
		select {
		case <-ch:
			t.Fatalf("P-05: %s delivered although the subject bucket was exhausted", what)
		case <-time.After(700 * time.Millisecond):
		}
	}

	// Eight parallel reconnects carry exactly the 64 KiB burst as early data.
	sink, received := auditSink(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); early(e.client, sink) }()
	}
	wg.Wait()
	if t.Failed() {
		t.FailNow()
	}
	for i := 0; i < 8; i++ {
		select {
		case <-received:
		case <-time.After(5 * time.Second):
			t.Fatal("early bytes within the burst not delivered")
		}
	}
	e.srv.subjects.mu.Lock()
	st := e.srv.subjects.m[tok.Subject]
	e.srv.subjects.mu.Unlock()
	if st == nil || st.lim == nil {
		t.Fatal("limiter missing")
	}
	st.lim.mu.Lock()
	tokens, burst := st.lim.tokens, st.lim.burst
	st.lim.mu.Unlock()
	if burst != 64*1024 || tokens > float64(MaxEarlyData) {
		t.Fatalf("P-05: early bytes not debited: tokens=%v burst=%v", tokens, burst)
	}

	// The next early flight and framed bytes of the same subject must wait.
	sink, received = auditSink(t)
	early(e.client, sink)
	blocked(received, "early bytes on a reconnect")
	sink, received = auditSink(t)
	framed := dial(t, e, sink)
	if err := framed.Handshake(); err != nil {
		t.Fatal(err)
	}
	go framed.Write(payload)
	blocked(received, "framed bytes")

	// Another subject keeps its own budget.
	other := &Token{Subject: [16]byte{0x52}, Caps: CapTCP, RateKbps: 8, DevicePub: e.device.Public().(ed25519.PublicKey), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}
	raw, err := IssueToken(e.issuer, other)
	if err != nil {
		t.Fatal(err)
	}
	p := *e.profile
	p.Token = raw
	sink, received = auditSink(t)
	early(NewClient(&p), sink)
	select {
	case <-received:
	case <-time.After(3 * time.Second):
		t.Fatal("another subject's early bytes were throttled")
	}
}
