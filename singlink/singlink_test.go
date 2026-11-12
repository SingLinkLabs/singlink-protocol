package singlink

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type env struct {
	srv     *Server
	addr    string
	issuer  ed25519.PrivateKey
	device  ed25519.PrivateKey
	key     *ServerPrivateKey
	profile *Profile
	client  *Client
}

type envOpt struct {
	tls      bool
	fallback string
	tok      *Token
	mutate   func(*ServerConfig)
}

func newEnv(t *testing.T, o envOpt) *env {
	t.Helper()
	key, err := GenerateServerKey()
	if err != nil {
		t.Fatal(err)
	}
	issuer, _ := GenerateEd25519()
	device, _ := GenerateEd25519()
	cfg := ServerConfig{
		Key:          key,
		Issuers:      NewIssuers(issuer.Public().(ed25519.PublicKey)),
		AllowPrivate: true,
		Fallback:     o.fallback,
	}
	var pin []byte
	if o.tls {
		cert, sum := selfSigned(t)
		cfg.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
		pin = sum
	}
	if o.mutate != nil {
		o.mutate(&cfg)
	}
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

	tok := o.tok
	if tok == nil {
		tok = &Token{Caps: CapTCP | CapUDP, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}
	}
	tok.DevicePub = device.Public().(ed25519.PublicKey)
	raw, err := IssueToken(issuer, tok)
	if err != nil {
		t.Fatal(err)
	}
	p := &Profile{Name: "test", Server: ln.Addr().String(), Transport: "tcp", ServerKey: key.Public(), Token: raw, Device: device}
	if o.tls {
		p.Transport, p.SNI, p.Pin = "tls", "localhost", pin
	}
	return &env{srv: srv, addr: ln.Addr().String(), issuer: issuer, device: device, key: key, profile: p, client: NewClient(p)}
}

func selfSigned(t *testing.T) (tls.Certificate, []byte) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	pin, err := PinFromCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}, pin
}

// echoServer echoes everything; if greeting is set it is sent first.
func echoServer(t *testing.T, greeting string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				if greeting != "" {
					c.Write([]byte(greeting))
				}
				io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().String()
}

func dial(t *testing.T, e *env, dst string) *Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := e.client.DialTCP(ctx, dst)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(20 * time.Second))
	return c
}

func roundTrip(t *testing.T, c *Conn, msg []byte) {
	t.Helper()
	errc := make(chan error, 1)
	go func() { _, err := c.Write(msg); errc <- err }()
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatal("echo mismatch")
	}
}

func TestKeysAndTokenRoundTrip(t *testing.T) {
	k, err := GenerateServerKey()
	if err != nil {
		t.Fatal(err)
	}
	k2, err := ParseServerPrivateKey(k.Bytes())
	if err != nil || !bytes.Equal(k2.Public().Bytes(), k.Public().Bytes()) {
		t.Fatal("server key round trip failed")
	}
	if len(k.Public().Bytes()) != 1216 {
		t.Fatal("public key size")
	}
	issuer, _ := GenerateEd25519()
	dev, _ := GenerateEd25519()
	tok := &Token{Subject: [16]byte{1, 2, 3}, DevicePub: dev.Public().(ed25519.PublicKey), NotBefore: time.Unix(1000, 0), NotAfter: time.Unix(2000, 0), Caps: CapTCP, RateKbps: 5000, MaxConns: 7, Plan: 3}
	raw, err := IssueToken(issuer, tok)
	if err != nil || len(raw) != TokenLen {
		t.Fatal(err)
	}
	is := NewIssuers(issuer.Public().(ed25519.PublicKey))
	got, err := is.Verify(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Subject != tok.Subject || got.RateKbps != 5000 || got.MaxConns != 7 || got.Plan != 3 || !got.NotAfter.Equal(tok.NotAfter) || !got.Has(CapTCP) || got.Has(CapUDP) {
		t.Fatalf("token fields mismatch: %+v", got)
	}
	for i := 0; i < TokenLen; i++ {
		bad := append([]byte{}, raw...)
		bad[i] ^= 1
		if _, err := is.Verify(bad); err == nil {
			t.Fatalf("tampered byte %d accepted", i)
		}
	}
	other, _ := GenerateEd25519()
	if _, err := NewIssuers(other.Public().(ed25519.PublicKey)).Verify(raw); err == nil {
		t.Fatal("unknown issuer accepted")
	}
}

func TestLinkRoundTrip(t *testing.T) {
	e := newEnv(t, envOpt{tls: true})
	e.profile.Name = "Hong Kong 01 🇭🇰"
	link := e.profile.Link()
	p, err := ParseLink(link)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "Hong Kong 01 🇭🇰" || p.Server != e.profile.Server || p.Transport != "tls" || p.SNI != "localhost" ||
		!bytes.Equal(p.Pin, e.profile.Pin) || !bytes.Equal(p.Token, e.profile.Token) ||
		!bytes.Equal(p.Device, e.profile.Device) || !bytes.Equal(p.ServerKey.Bytes(), e.profile.ServerKey.Bytes()) {
		t.Fatal("link round trip mismatch")
	}
	for _, bad := range []string{"vless://x@y:1", "singlink://a@b:1", strings.Replace(link, "tr=tls", "tr=quic", 1)} {
		if _, err := ParseLink(bad); err == nil {
			t.Fatalf("accepted bad link %q", bad)
		}
	}
}

func TestTCPRelayTLSAndRaw(t *testing.T) {
	for _, useTLS := range []bool{false, true} {
		e := newEnv(t, envOpt{tls: useTLS})
		c := dial(t, e, echoServer(t, ""))
		roundTrip(t, c, []byte("hello"))
		// Large transfer, full duplex, crosses many frames.
		big := make([]byte, 4<<20)
		rand.Read(big)
		roundTrip(t, c, big)
		if e.client.Stats.Up.Load() != int64(len(big)+5) {
			t.Fatalf("up stats %d", e.client.Stats.Up.Load())
		}
	}
}

func TestServerSpeaksFirst(t *testing.T) {
	e := newEnv(t, envOpt{})
	c := dial(t, e, echoServer(t, "220 ready\r\n"))
	buf := make([]byte, 11)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "220 ready\r\n" {
		t.Fatalf("got %q", buf)
	}
	roundTrip(t, c, []byte("EHLO"))
}

func TestHalfClose(t *testing.T) {
	e := newEnv(t, envOpt{})
	c := dial(t, e, echoServer(t, ""))
	c.Write([]byte("bye"))
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(c)
	if err != nil || string(got) != "bye" {
		t.Fatalf("got %q err %v", got, err)
	}
}

func TestUDPRelay(t *testing.T) {
	e := newEnv(t, envOpt{tls: true})
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := uc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			uc.WriteToUDP(append([]byte("re:"), buf[:n]...), from)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pc, err := e.client.DialUDP(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	dst, _ := ParseAddr(uc.LocalAddr().String())
	for i := 0; i < 3; i++ {
		if err := pc.WriteTo([]byte("ping"), dst); err != nil {
			t.Fatal(err)
		}
		pc.c.raw.SetReadDeadline(time.Now().Add(5 * time.Second))
		b, from, err := pc.ReadFrom()
		if err != nil {
			t.Fatal(err)
		}
		if string(b) != "re:ping" || from.String() != dst.String() {
			t.Fatalf("got %q from %s", b, from)
		}
	}
}

func expectStatus(t *testing.T, c *Conn, want Status) {
	t.Helper()
	err := c.Handshake()
	var se *StatusError
	if !errors.As(err, &se) || se.Code != want {
		t.Fatalf("want status %v, got %v", want, err)
	}
}

func TestPermissions(t *testing.T) {
	echo := echoServer(t, "")
	now := time.Now()

	// Recently expired: the user is told; long expired or not yet valid:
	// the node does not reveal itself.
	e := newEnv(t, envOpt{tok: &Token{Caps: CapTCP, NotBefore: now.Add(-2 * time.Hour), NotAfter: now.Add(-time.Hour)}})
	expectStatus(t, dial(t, e, echo), StatusTokenExpired)
	e = newEnv(t, envOpt{tok: &Token{Caps: CapTCP, NotBefore: now.Add(-72 * time.Hour), NotAfter: now.Add(-48 * time.Hour)}})
	expectRejected(t, dial(t, e, echo))
	e = newEnv(t, envOpt{tok: &Token{Caps: CapTCP, NotBefore: now.Add(time.Hour), NotAfter: now.Add(2 * time.Hour)}})
	expectRejected(t, dial(t, e, echo))

	e = newEnv(t, envOpt{tok: &Token{Caps: CapUDP, NotBefore: now, NotAfter: now.Add(time.Hour)}})
	expectStatus(t, dial(t, e, echo), StatusCapDenied)

	e = newEnv(t, envOpt{tok: &Token{Caps: CapTCP, NotBefore: now, NotAfter: now.Add(time.Hour)}})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := e.client.DialUDP(ctx); err == nil || !strings.Contains(err.Error(), "capability") {
		t.Fatalf("UDP without cap: %v", err)
	}

	// Default node policy refuses loopback destinations and port 25.
	e = newEnv(t, envOpt{mutate: func(c *ServerConfig) { c.AllowPrivate = false }})
	expectStatus(t, dial(t, e, echo), StatusForbiddenDest)
	// A name that resolves only to forbidden addresses looks unresolvable.
	expectStatus(t, dial(t, e, "localhost:80"), StatusDialFailed)
	e = newEnv(t, envOpt{})
	expectStatus(t, dial(t, e, "127.0.0.1:25"), StatusForbiddenDest)

	// Max concurrent connections per subject.
	e = newEnv(t, envOpt{tok: &Token{Caps: CapTCP, MaxConns: 1, NotBefore: now, NotAfter: now.Add(time.Hour)}})
	c1 := dial(t, e, echo)
	roundTrip(t, c1, []byte("a"))
	expectStatus(t, dial(t, e, echo), StatusTooManyConns)
	c1.Close()
	time.Sleep(200 * time.Millisecond)
	roundTrip(t, dial(t, e, echo), []byte("b"))
}

func TestRateLimit(t *testing.T) {
	// 800 kbit/s = 100 KB/s, burst 64 KB.
	e := newEnv(t, envOpt{tok: &Token{Caps: CapTCP, RateKbps: 800, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}})
	c := dial(t, e, echoServer(t, ""))
	start := time.Now()
	roundTrip(t, c, make([]byte, 200*1024))
	// Upstream and downstream share the bucket: 400 KB through it.
	if d := time.Since(start); d < 2*time.Second {
		t.Fatalf("rate limit not applied: %v", d)
	}
}

// fallbackSite records what it receives and answers like a web server.
func fallbackSite(t *testing.T) (string, chan []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got := make(chan []byte, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetReadDeadline(time.Now().Add(2 * time.Second))
				var b []byte
				buf := make([]byte, 4096)
				for !bytes.Contains(b, []byte("\r\n\r\n")) && len(b) < firstFlightFixed {
					n, err := c.Read(buf)
					b = append(b, buf[:n]...)
					if err != nil {
						break
					}
				}
				got <- b
				c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"))
			}()
		}
	}()
	return ln.Addr().String(), got
}

func TestProbeGoesToFallbackImmediately(t *testing.T) {
	site, got := fallbackSite(t)
	e := newEnv(t, envOpt{tls: true, fallback: site})
	c, err := tls.Dial("tcp", e.addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	start := time.Now()
	c.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	resp, _ := io.ReadAll(c)
	if !strings.HasSuffix(string(resp), "hi") {
		t.Fatalf("fallback response %q", resp)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("fallback too slow: %v", d)
	}
	if b := <-got; !strings.HasPrefix(string(b), "GET / HTTP/1.1") {
		t.Fatalf("fallback got %q", b)
	}
}

func TestUnauthenticatedGoesToFallback(t *testing.T) {
	site, got := fallbackSite(t)
	e := newEnv(t, envOpt{fallback: site})
	// A client holding a token from an untrusted issuer.
	rogue, _ := GenerateEd25519()
	tok := &Token{Caps: CapTCP, DevicePub: e.device.Public().(ed25519.PublicKey), NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	raw, _ := IssueToken(rogue, tok)
	p := *e.profile
	p.Token = raw
	c, err := NewClient(&p).DialTCP(context.Background(), "1.1.1.1:443")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if err := c.Handshake(); err == nil {
		t.Fatal("rogue token accepted")
	}
	b := <-got
	if len(b) < firstFlightFixed {
		t.Fatalf("fallback did not get the first flight (%d bytes)", len(b))
	}

	// A valid token presented with the wrong device key (stolen token).
	thief, _ := GenerateEd25519()
	p2 := *e.profile
	p2.Device = thief
	c2, _ := NewClient(&p2).DialTCP(context.Background(), "1.1.1.1:443")
	defer c2.Close()
	c2.SetDeadline(time.Now().Add(5 * time.Second))
	if err := c2.Handshake(); err == nil {
		t.Fatal("stolen token without device key accepted")
	}
	<-got
}

func TestReplayIsRejected(t *testing.T) {
	site, got := fallbackSite(t)
	e := newEnv(t, envOpt{fallback: site})
	echo := echoServer(t, "")
	dst, _ := ParseAddr(echo)
	flight, _, err := buildFirstFlight(e.key.Public(), e.device, &request{ts: time.Now(), cmd: CmdTCP, dst: dst, token: e.profile.Token, early: []byte("x")}, 0)
	if err != nil {
		t.Fatal(err)
	}
	send := func() []byte {
		c, err := net.Dial("tcp", e.addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.Write(flight)
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		b := make([]byte, 64)
		n, _ := io.ReadAtLeast(c, b, 32)
		return b[:n]
	}
	if r := send(); len(r) < 32 {
		t.Fatal("first use rejected")
	}
	if r := send(); strings.Contains(string(r), "HTTP/1.1 200") == false {
		t.Fatalf("replay not sent to fallback: %q", r)
	}
	if b := <-got; !bytes.Equal(b[:len(b)], flight[:len(b)]) {
		t.Fatal("fallback did not receive the replayed bytes")
	}
}

func TestReplayCacheRotation(t *testing.T) {
	rc := newReplayCache(time.Second)
	now := time.Now()
	k := bytes.Repeat([]byte{7}, 32)
	if !rc.checkAndAdd(k, now) || rc.checkAndAdd(k, now) {
		t.Fatal("basic replay check")
	}
	if rc.checkAndAdd(k, now.Add(3*time.Second)) {
		t.Fatal("entry expired too early")
	}
	if !rc.checkAndAdd(k, now.Add(10*time.Second)) {
		t.Fatal("entry never expired")
	}
}

func TestConcurrentStreams(t *testing.T) {
	e := newEnv(t, envOpt{tls: true})
	echo := echoServer(t, "")
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := dial(t, e, echo)
			msg := make([]byte, 64*1024)
			rand.Read(msg)
			roundTrip(t, c, msg)
		}()
	}
	wg.Wait()
}

func BenchmarkHandshake(b *testing.B) {
	key, _ := GenerateServerKey()
	dev, _ := GenerateEd25519()
	req := &request{ts: time.Now(), cmd: CmdTCP, dst: Addr{Host: "example.com", Port: 443}, token: make([]byte, TokenLen)}
	for i := 0; i < b.N; i++ {
		flight, _, _ := buildFirstFlight(key.Public(), dev, req, 0)
		if _, err := parseFirstFlight(flight, []*ServerPrivateKey{key}); err != nil {
			b.Fatal(err)
		}
	}
}
