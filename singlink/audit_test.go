// Copyright 2026 SingLinkLabs (https://github.com/SingLinkLabs)
// SPDX-License-Identifier: Apache-2.0

package singlink

// Regression tests for the findings of the 2026-11 security review
// (docs/SECURITY-AUDIT.md). Test names carry the finding IDs.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func expectRejected(t *testing.T, c *Conn) {
	t.Helper()
	if err := c.Handshake(); !errors.Is(err, ErrRejected) {
		t.Fatalf("want ErrRejected, got %v", err)
	}
}

// C-3, C-12, I-6
func TestRevocation(t *testing.T) {
	dir := t.TempDir()
	rf := filepath.Join(dir, "revoked.txt")
	site, _ := fallbackSite(t)
	tok := &Token{ID: [16]byte{0xaa, 0xbb}, Caps: CapTCP, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	os.WriteFile(rf, []byte("# revoked\naabb0000000000000000000000000000\n"), 0o600)
	e := newEnv(t, envOpt{tok: tok, fallback: site, mutate: func(c *ServerConfig) { c.RevokedFile = rf }})
	expectRejected(t, dial(t, e, echoServer(t, "")))

	// Revoking a subject closes its live sessions on the next reload.
	os.WriteFile(rf, nil, 0o600)
	tok2 := &Token{Subject: [16]byte{0x7}, Caps: CapTCP, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	e = newEnv(t, envOpt{tok: tok2, mutate: func(c *ServerConfig) { c.RevokedFile = rf }})
	c := dial(t, e, echoServer(t, ""))
	roundTrip(t, c, []byte("live"))
	os.WriteFile(rf, []byte("subject 07000000000000000000000000000000\n"), 0o600)
	e.srv.reloadRevoked()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("revoked session still open")
	}
	os.WriteFile(rf, []byte("device "+B64.EncodeToString(e.device.Public().(ed25519.PublicKey))+"\n"), 0o600)
	e.srv.reloadRevoked()
	if !e.srv.isRevoked(&Token{DevicePub: e.device.Public().(ed25519.PublicKey)}) {
		t.Fatal("device revocation not loaded")
	}
}

// C-5
func TestReplayAcrossRestart(t *testing.T) {
	site, _ := fallbackSite(t)
	e := newEnv(t, envOpt{fallback: site})
	dst, _ := ParseAddr(echoServer(t, ""))
	flight, _, err := buildFirstFlight(e.key.Public(), e.device, &request{ts: time.Now(), cmd: CmdTCP, dst: dst, token: e.profile.Token}, 0)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	// A new process with the same key must not accept a flight made before it started.
	srv2, _ := NewServer(ServerConfig{Key: e.key, Issuers: e.srv.cfg.Issuers, AllowPrivate: true, Fallback: site})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go srv2.Serve(ln)
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write(flight)
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	r, _ := io.ReadAll(c)
	if !strings.Contains(string(r), "HTTP/1.1 200") {
		t.Fatalf("pre-start flight accepted after restart: %q", r)
	}
}

// C-4
func TestTruncationIsAnError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		c.Write([]byte("part1"))
		time.Sleep(200 * time.Millisecond)
		c.(*net.TCPConn).SetLinger(0) // reset, not a clean close
		c.Close()
	}()
	e := newEnv(t, envOpt{})
	c := dial(t, e, ln.Addr().String())
	c.Write([]byte("x"))
	got, err := io.ReadAll(c)
	if string(got) != "part1" || err == nil {
		t.Fatalf("got %q err %v; want data then an error", got, err)
	}

	// Cutting the outer stream at a frame boundary is not a clean EOF either.
	a, b := net.Pipe()
	k := bytes.Repeat([]byte{1}, 32)
	cw, _ := newCipherState(k)
	cr, _ := newCipherState(k)
	go func() {
		(&frameWriter{w: a, cs: cw}).writeFrame(frameData, []byte("hi"))
		a.Close()
	}()
	sc := newServerConn(b, cr, cr, 0, 0)
	buf, err := io.ReadAll(sc)
	if string(buf) != "hi" || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("got %q err %v", buf, err)
	}
}

// C-1, C-2
func TestProbeTimingIsUniform(t *testing.T) {
	// A decoy site that reports when the first bytes arrive.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	arrived := make(chan time.Time, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.Read(make([]byte, 1))
				arrived <- time.Now()
			}()
		}
	}()
	e := newEnv(t, envOpt{tls: true, fallback: ln.Addr().String(), mutate: func(c *ServerConfig) { c.HandshakeTimeout = 5 * time.Second }})
	probe := func(payload []byte) time.Duration {
		c, err := tls.Dial("tcp", e.addr, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		start := time.Now()
		c.Write(payload)
		return (<-arrived).Sub(start)
	}
	short := make([]byte, 100)
	rand.Read(short)
	// A valid E || CT || LEN announcing a header that never comes.
	flight, _, _ := buildFirstFlight(e.key.Public(), e.device, &request{ts: time.Now(), cmd: CmdTCP, dst: Addr{Host: "a.b", Port: 1}, token: e.profile.Token}, 0)
	for name, p := range map[string][]byte{"short random": short, "valid prefix only": flight[:firstFlightFixed]} {
		if d := probe(p); d > 500*time.Millisecond {
			t.Errorf("%s: fallback after %v (node waited for more)", name, d)
		}
	}
}

// C-8
func TestSmallOrderDeviceKeys(t *testing.T) {
	identity := make([]byte, 32)
	identity[0] = 1
	for i, k := range smallOrder {
		for _, hi := range []byte{0, 0x80} {
			kk := k
			kk[31] |= hi
			if ValidDeviceKey(kk[:]) {
				t.Fatalf("small-order key %d accepted", i)
			}
		}
	}
	// The identity entry is the key that admits forged signatures.
	if !ed25519.Verify(identity, []byte("m"), append(append([]byte{}, identity...), make([]byte, 32)...)) {
		t.Log("note: this Go version already rejects the identity forgery")
	}
	issuer, _ := GenerateEd25519()
	if _, err := IssueToken(issuer, &Token{DevicePub: identity, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}); err == nil {
		t.Fatal("token issued for identity key")
	}
	if _, err := IssueToken(issuer, &Token{DevicePub: make([]byte, 32), NotBefore: time.Now(), NotAfter: time.Unix(1<<41, 0)}); err == nil {
		t.Fatal("token with absurd NotAfter issued")
	}
	dev, _ := GenerateEd25519()
	if !ValidDeviceKey(dev.Public().(ed25519.PublicKey)) {
		t.Fatal("normal key rejected")
	}
}

// C-11
func TestRekey(t *testing.T) {
	old := rekeyEvery
	rekeyEvery = 4
	defer func() { rekeyEvery = old }()
	a, b := net.Pipe()
	k0 := bytes.Repeat([]byte{9}, 32)
	ka, _ := newCipherState(k0)
	kb, _ := newCipherState(k0)
	fw := &frameWriter{w: a, cs: ka}
	fr := &frameReader{r: b, cs: kb}
	go func() {
		for i := 0; i < 10; i++ {
			fw.writeFrame(frameData, []byte{byte(i)})
		}
	}()
	for i := 0; i < 10; i++ {
		_, d, err := fr.readFrame()
		if err != nil || d[0] != byte(i) {
			t.Fatalf("frame %d: %v", i, err)
		}
	}
	if bytes.Equal(kb.key, k0) {
		t.Fatal("key never rotated")
	}
}

// C-7 (rotation support)
func TestKeyRotation(t *testing.T) {
	oldKey, _ := GenerateServerKey()
	e := newEnv(t, envOpt{mutate: func(c *ServerConfig) { c.OldKeys = []*ServerPrivateKey{oldKey} }})
	echo := echoServer(t, "")
	roundTrip(t, dial(t, e, echo), []byte("new key"))
	p := *e.profile
	p.ServerKey = oldKey.Public()
	c, err := NewClient(&p).DialTCP(context.Background(), echo)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	roundTrip(t, c, []byte("old key"))
}

// I-4
func TestDestinationPolicy(t *testing.T) {
	for _, s := range []string{
		"0.1.2.3", "10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.169.254", "172.16.0.1", "192.0.0.1",
		"192.0.2.1", "192.168.1.1", "198.18.0.1", "203.0.113.5", "224.0.0.1", "240.0.0.1", "255.255.255.255",
		"::", "::1", "::127.0.0.1", "::a00:1", "::ffff:10.0.0.1", "64:ff9b::a00:1", "64:ff9b::a9fe:a9fe",
		"64:ff9b:1::a00:1", "2001::1", "2001:db8::1", "2002:7f00:1::1", "fc00::1", "fe80::1", "fec0::1",
		"ff02::1", "100::1",
	} {
		if publicIP(netip.MustParseAddr(s)) {
			t.Errorf("%s treated as public", s)
		}
	}
	for _, s := range []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111", "64:ff9b::808:808"} {
		if !publicIP(netip.MustParseAddr(s)) {
			t.Errorf("%s treated as non-public", s)
		}
	}
	rs := &resolver{r: net.DefaultResolver, deny: []netip.Prefix{netip.MustParsePrefix("1.1.1.0/24")}}
	if _, st := rs.resolve(context.Background(), Addr{IP: netip.MustParseAddr("1.1.1.1"), Port: 443}); st != StatusForbiddenDest {
		t.Error("deny_cidrs not applied")
	}
}

// I-7
func TestRateLimitSurvivesReconnect(t *testing.T) {
	var s subjects
	tok := &Token{Subject: [16]byte{1}, RateKbps: 800}
	lim, _ := s.acquire(tok)
	lim.wait(context.Background(), 64*1024)
	s.release(tok)
	lim2, _ := s.acquire(tok)
	if lim2 != lim || lim2.full() {
		t.Fatal("reconnecting reset the rate limit")
	}
}

// I-3, I-2
func TestGuard(t *testing.T) {
	g := newGuard(10, 2)
	ip := netip.MustParseAddr("192.0.2.9")
	junk := make([]byte, firstFlightFixed+10)
	rand.Read(junk)
	if !g.worthDecrypting(ip, junk) {
		t.Fatal("first try refused")
	}
	g.failedFlight(ip, junk)
	if g.worthDecrypting(netip.MustParseAddr("192.0.2.10"), junk) {
		t.Fatal("identical failed flight decrypted again")
	}
	for i := 0; i < 60; i++ {
		g.failedFlight(ip, nil)
	}
	other := make([]byte, firstFlightFixed)
	rand.Read(other)
	if g.worthDecrypting(ip, other) {
		t.Fatal("IP that keeps failing still gets handshake cryptography")
	}
	if !g.begin(ip) || !g.begin(ip) || g.begin(ip) {
		t.Fatal("per-IP pending limit")
	}
}

// I-5
func TestProxyProtocolV2(t *testing.T) {
	var b bytes.Buffer
	writeProxyV2(&b, &net.TCPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 5555}, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443})
	want := append([]byte("\r\n\r\n\x00\r\nQUIT\n"), 0x21, 0x11, 0, 12, 203, 0, 113, 7, 127, 0, 0, 1, 0x15, 0xb3, 0x01, 0xbb)
	if !bytes.Equal(b.Bytes(), want) {
		t.Fatalf("got %x", b.Bytes())
	}
}

// I-13
func TestLinkErrorsDoNotLeakSecrets(t *testing.T) {
	_, err := ParseLink("singlink://TOKEN.SECRETDEVICESEED@host:44 3?pk=x")
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("error leaks link: %v", err)
	}
}

// I-8
func TestUDPDropsUnsolicitedPackets(t *testing.T) {
	e := newEnv(t, envOpt{})
	echo, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer echo.Close()
	relayAddr := make(chan *net.UDPAddr, 1)
	go func() {
		b := make([]byte, 1500)
		for {
			n, from, err := echo.ReadFromUDP(b)
			if err != nil {
				return
			}
			select {
			case relayAddr <- from:
			default:
			}
			echo.WriteToUDP(b[:n], from)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pc, err := e.client.DialUDP(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	dst, _ := ParseAddr(echo.LocalAddr().String())
	pc.WriteTo([]byte("hello"), dst)
	pc.c.raw.SetReadDeadline(time.Now().Add(3 * time.Second))
	if b, _, err := pc.ReadFrom(); err != nil || string(b) != "hello" {
		t.Fatalf("echo: %q %v", b, err)
	}
	// A stranger who knows the node's relay port sends a datagram.
	stranger, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer stranger.Close()
	stranger.WriteToUDP([]byte("injected"), <-relayAddr)
	pc.c.raw.SetReadDeadline(time.Now().Add(700 * time.Millisecond))
	if b, _, err := pc.ReadFrom(); err == nil {
		t.Fatalf("unsolicited datagram delivered: %q", b)
	}
}
