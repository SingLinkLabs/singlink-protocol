// Copyright 2026 SingLinkVPN (https://singlinkvpn.com)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/SingLinkLabs/singlink-protocol/singlink"
)

// The CLI help must show the required original-author attribution (NOTICE).
func TestUsageShowsAttribution(t *testing.T) {
	if !strings.Contains(usage, singlink.Attribution) {
		t.Fatalf("usage does not contain the attribution:\n%s", usage)
	}
}

// runCLI runs one command with captured output. Tests in this package do not
// run in parallel because they swap the package-level streams and hooks.
func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	oldOut, oldErr := stdout, stderr
	stdout, stderr = &out, &errOut
	defer func() { stdout, stderr = oldOut, oldErr }()
	code := run(args)
	return code, out.String(), errOut.String()
}

func mustRun(t *testing.T, args ...string) string {
	t.Helper()
	code, out, errOut := runCLI(t, args...)
	if code != 0 {
		t.Fatalf("%v: exit %d, stderr %q", args, code, errOut)
	}
	return out
}

func decodeJSON(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("not JSON: %q", s)
	}
	return m
}

func TestVersionAndHelp(t *testing.T) {
	for _, arg := range []string{"version", "-v", "--version"} {
		out := mustRun(t, arg)
		for _, want := range []string{singlink.Version, singlink.ProtocolName, singlink.Attribution, "Copyright 2026 SingLinkVPN", "draft 4"} {
			if !strings.Contains(out, want) {
				t.Fatalf("%s output lacks %q:\n%s", arg, want, out)
			}
		}
	}
	for _, arg := range []string{"help", "-h", "--help"} {
		if out := mustRun(t, arg); out != usage {
			t.Fatalf("%s did not print usage", arg)
		}
	}
	if code, _, errOut := runCLI(t); code != 2 || errOut != usage {
		t.Fatal("no arguments")
	}
	if code, _, errOut := runCLI(t, "frobnicate"); code != 2 || errOut != usage {
		t.Fatal("unknown command")
	}
}

func TestKeygen(t *testing.T) {
	m := decodeJSON(t, mustRun(t, "keygen", "server"))
	priv, err := singlink.B64.DecodeString(m["private_key"].(string))
	if err != nil {
		t.Fatal(err)
	}
	k, err := singlink.ParseServerPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	if singlink.B64.EncodeToString(k.Public().Bytes()) != m["public_key"] {
		t.Fatal("server public key does not match private key")
	}
	m = decodeJSON(t, mustRun(t, "keygen", "issuer"))
	seed, _ := singlink.B64.DecodeString(m["seed"].(string))
	issuer, err := singlink.Ed25519FromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	pub := issuer.Public().(ed25519.PublicKey)
	if m["public_key"] != singlink.B64.EncodeToString(pub) || m["key_id"] != fmt.Sprintf("%08x", singlink.IssuerKeyID(pub)) {
		t.Fatal("issuer output")
	}
	m = decodeJSON(t, mustRun(t, "keygen", "device"))
	if _, ok := m["key_id"]; ok || m["seed"] == "" {
		t.Fatal("device output")
	}
	for _, args := range [][]string{{"keygen"}, {"keygen", "other"}, {"keygen", "server", "extra"}} {
		if code, _, errOut := runCLI(t, args...); code != 1 || !strings.Contains(errOut, "usage") {
			t.Fatalf("%v: exit %d %q", args, code, errOut)
		}
	}
}

type testKeys struct {
	issuerSeed, issuerPub string
	deviceSeed, devicePub string
	serverPriv, serverPub string
}

func newTestKeys(t *testing.T) testKeys {
	t.Helper()
	var k testKeys
	m := decodeJSON(t, mustRun(t, "keygen", "issuer"))
	k.issuerSeed, k.issuerPub = m["seed"].(string), m["public_key"].(string)
	m = decodeJSON(t, mustRun(t, "keygen", "device"))
	k.deviceSeed, k.devicePub = m["seed"].(string), m["public_key"].(string)
	m = decodeJSON(t, mustRun(t, "keygen", "server"))
	k.serverPriv, k.serverPub = m["private_key"].(string), m["public_key"].(string)
	return k
}

func TestTokenIssueAndInspect(t *testing.T) {
	k := newTestKeys(t)
	subject := strings.Repeat("ab", 16)
	tok := strings.TrimSpace(mustRun(t, "token", "issue", "-issuer", k.issuerSeed, "-device", k.devicePub, "-subject", subject,
		"-days", "2", "-caps", "tcp", "-rate", "800", "-max-conns", "3", "-plan", "7"))
	raw, err := singlink.B64.DecodeString(tok)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := singlink.B64.DecodeString(k.issuerPub)
	parsed, err := singlink.NewIssuers(pub).Verify(raw)
	if err != nil {
		t.Fatal("issued token does not verify:", err)
	}
	if !parsed.Has(singlink.CapTCP) || parsed.Has(singlink.CapUDP) || parsed.RateKbps != 800 || parsed.MaxConns != 3 || parsed.Plan != 7 ||
		hex.EncodeToString(parsed.Subject[:]) != subject || parsed.NotAfter.Sub(time.Now()) < 47*time.Hour {
		t.Fatalf("token fields %+v", parsed)
	}
	m := decodeJSON(t, mustRun(t, "token", "inspect", tok))
	if m["subject"] != subject || m["tcp"] != true || m["udp"] != false || m["plan"] != float64(7) || m["device"] != k.devicePub {
		t.Fatalf("inspect output %v", m)
	}
	// A random subject is used when none is given.
	tok2 := strings.TrimSpace(mustRun(t, "token", "issue", "-issuer", k.issuerSeed, "-device", k.devicePub))
	if tok2 == tok {
		t.Fatal("tokens not unique")
	}

	issue := func(extra ...string) []string {
		return append([]string{"token", "issue", "-issuer", k.issuerSeed, "-device", k.devicePub}, extra...)
	}
	for _, c := range []struct {
		args []string
		code int
	}{
		{[]string{"token"}, 1},
		{[]string{"token", "other"}, 1},
		{[]string{"token", "inspect"}, 1},
		{[]string{"token", "inspect", "%%%"}, 1},
		{[]string{"token", "inspect", singlink.B64.EncodeToString([]byte("short"))}, 1},
		{[]string{"token", "issue", "-issuer", "%%%", "-device", k.devicePub}, 1},
		{[]string{"token", "issue", "-issuer", singlink.B64.EncodeToString([]byte("short")), "-device", k.devicePub}, 1},
		{[]string{"token", "issue", "-issuer", k.issuerSeed, "-device", "%%%"}, 1},
		{issue("-subject", "xyz"), 1},
		{issue("-caps", "tcp,ftp"), 1},
		{issue("-rate", "4294967296"), 1},
		{issue("-max-conns", "65536"), 1},
		{issue("-plan", "256"), 1},
		{issue("-days", "0"), 1},
		{issue("-days", "NaN"), 1},
		{issue("-unknown"), 2},
		{issue("extra"), 2},
		{issue("-h"), 0},
	} {
		if code, _, _ := runCLI(t, c.args...); code != c.code {
			t.Fatalf("%v: exit %d, want %d", c.args, code, c.code)
		}
	}
}

func TestLinkCommand(t *testing.T) {
	k := newTestKeys(t)
	tok := strings.TrimSpace(mustRun(t, "token", "issue", "-issuer", k.issuerSeed, "-device", k.devicePub))
	pin := singlink.B64.EncodeToString(bytes.Repeat([]byte{1}, 32))
	l := strings.TrimSpace(mustRun(t, "link", "-server", "vpn.example.com:443", "-pk", k.serverPub, "-token", tok,
		"-device", k.deviceSeed, "-sni", "vpn.example.com", "-pin", pin, "-name", "Test"))
	p, err := singlink.ParseLink(l)
	if err != nil {
		t.Fatal(err)
	}
	if p.Server != "vpn.example.com:443" || p.SNI != "vpn.example.com" || p.Name != "Test" || p.Transport != "tls" || len(p.Pin) != 32 {
		t.Fatalf("link profile %+v", p)
	}
	base := []string{"-server", "vpn.example.com:443", "-pk", k.serverPub, "-token", tok, "-device", k.deviceSeed}
	with := func(flag, value string) []string {
		args := []string{"link"}
		for i := 0; i < len(base); i += 2 {
			if base[i] != flag {
				args = append(args, base[i], base[i+1])
			}
		}
		return append(args, flag, value)
	}
	for _, args := range [][]string{
		with("-pk", "%%%"),
		with("-pk", singlink.B64.EncodeToString([]byte("short"))),
		with("-token", "%%%"),
		with("-token", singlink.B64.EncodeToString([]byte("short"))),
		with("-device", "%%%"),
		with("-device", singlink.B64.EncodeToString([]byte("short"))),
		with("-pin", "%%%"),
		with("-pin", singlink.B64.EncodeToString([]byte("short"))),
		with("-server", "no-port"),
		with("-tr", "udp"),
	} {
		code, out, errOut := runCLI(t, args...)
		if code != 1 {
			t.Fatalf("%v: exit %d", args, code)
		}
		if strings.Contains(out+errOut, k.deviceSeed) {
			t.Fatal("error output echoes the device secret")
		}
	}
	if code, _, _ := runCLI(t, "link", "-bogus"); code != 2 {
		t.Fatal("unknown flag")
	}
}

func TestReplayInitCommand(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "replay.db")
	mustRun(t, "replay-init", "-path", path, "-max-entries", "16")
	if _, err := singlink.OpenFileReplayStore(path, 16); err != nil {
		t.Fatal("initialized state does not open:", err)
	}
	if code, _, errOut := runCLI(t, "replay-init", "-path", path); code != 1 || !strings.Contains(errOut, "error:") {
		t.Fatal("existing state reinitialized")
	}
	if code, _, _ := runCLI(t, "replay-init"); code != 1 {
		t.Fatal("missing -path accepted")
	}
	if code, _, _ := runCLI(t, "replay-init", "-path", filepath.Join(t.TempDir(), "x", "r.db"), "-max-entries", "-1"); code != 1 {
		t.Fatal("invalid capacity accepted")
	}
	if code, _, _ := runCLI(t, "replay-init", "-nope"); code != 2 {
		t.Fatal("unknown flag")
	}
}

// writeTLSPair writes a self-signed certificate and key as PEM files.
func writeTLSPair(t *testing.T, dir string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "node.test"}, DNSNames: []string{"node.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600)
	os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0600)
	return certPath, keyPath
}

func writeConfig(t *testing.T, dir string, f map[string]any) string {
	t.Helper()
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, fmt.Sprintf("server-%d.json", time.Now().UnixNano()))
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestServerConfigAndStartup(t *testing.T) {
	k := newTestKeys(t)
	old := newTestKeys(t)
	dir := t.TempDir()
	replayPath := filepath.Join(dir, "state", "replay.db")
	mustRun(t, "replay-init", "-path", replayPath)
	certPath, keyPath := writeTLSPair(t, dir)
	good := func() map[string]any {
		return map[string]any{
			"replay_file": replayPath, "listen": "127.0.0.1:0", "private_key": k.serverPriv,
			"old_private_keys": []string{old.serverPriv}, "issuers": []string{k.issuerPub, old.issuerPub},
			"tls_cert": certPath, "tls_key": keyPath, "fallback": "127.0.0.1:9", "fallback_proxy_protocol": true,
			"deny_cidrs": []string{"198.51.100.0/24", "2001:db8::/32"}, "blocked_ports": []int{22}, "max_connections": 10,
			"log_level": "debug",
		}
	}
	cfg, listen, err := loadServerConfig(writeConfig(t, dir, good()))
	if err != nil {
		t.Fatal(err)
	}
	if listen != "127.0.0.1:0" || cfg.TLS == nil || len(cfg.OldKeys) != 1 || len(cfg.Issuers) != 2 || len(cfg.DenyCIDRs) != 2 ||
		cfg.ReplayFile != replayPath || !cfg.FallbackProxyProtocol || cfg.MaxConnections != 10 || cfg.Logger == nil {
		t.Fatalf("config not applied: %+v", cfg)
	}
	minimal := map[string]any{"replay_file": replayPath, "private_key": k.serverPriv, "issuers": []string{k.issuerPub}}
	if _, listen, err := loadServerConfig(writeConfig(t, dir, minimal)); err != nil || listen != ":443" {
		t.Fatal("default listen address", listen, err)
	}

	// The node starts with a valid configuration; the serve hook stands in
	// for the accept loop.
	served := false
	oldServe := serve
	serve = func(srv *singlink.Server, ln net.Listener) error {
		served = srv != nil && ln.Addr().(*net.TCPAddr).IP.IsLoopback()
		return ln.Close()
	}
	defer func() { serve = oldServe }()
	if code, _, errOut := runCLI(t, "server", "-c", writeConfig(t, dir, good())); code != 0 || !served || !strings.Contains(errOut, "SingLink node starting") {
		t.Fatalf("server startup: exit %d served %v\n%s", code, served, errOut)
	}

	bad := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"private key", func(m map[string]any) { m["private_key"] = "%%%" }},
		{"private key length", func(m map[string]any) { m["private_key"] = singlink.B64.EncodeToString([]byte("x")) }},
		{"old key", func(m map[string]any) { m["old_private_keys"] = []string{"%%%"} }},
		{"deny cidr", func(m map[string]any) { m["deny_cidrs"] = []string{"300.0.0.0/8"} }},
		{"issuer", func(m map[string]any) { m["issuers"] = []string{"%%%"} }},
		{"tls pair", func(m map[string]any) { m["tls_key"] = certPath }},
	}
	for _, c := range bad {
		m := good()
		c.mutate(m)
		if _, _, err := loadServerConfig(writeConfig(t, dir, m)); err == nil {
			t.Fatalf("%s: invalid config accepted", c.name)
		}
	}
	notJSON := filepath.Join(dir, "bad.json")
	os.WriteFile(notJSON, []byte("{"), 0600)
	for _, args := range [][]string{
		{"server", "-c", filepath.Join(dir, "missing.json")},
		{"server", "-c", notJSON},
		{"server", "-c", writeConfig(t, dir, map[string]any{"private_key": k.serverPriv, "issuers": []string{k.issuerPub}, "replay_file": filepath.Join(dir, "none")})},
		{"server", "-c", writeConfig(t, dir, map[string]any{"private_key": k.serverPriv, "replay_file": replayPath})},
		{"server", "-c", writeConfig(t, dir, func() map[string]any { m := good(); m["listen"] = "256.0.0.1:1"; return m }())},
	} {
		if code, _, _ := runCLI(t, args...); code != 1 {
			t.Fatalf("%v: invalid node configuration started", args[2])
		}
	}
	if code, _, _ := runCLI(t, "server", "-x"); code != 2 {
		t.Fatal("unknown flag")
	}
}

// startNode runs a loopback test node that refuses port 443 before any DNS
// lookup, so the engine's verification handshake needs no network.
func startNode(t *testing.T) string {
	t.Helper()
	key, _ := singlink.GenerateServerKey()
	issuer, _ := singlink.GenerateEd25519()
	device, _ := singlink.GenerateEd25519()
	file, err := singlink.InitializeReplayFile(filepath.Join(t.TempDir(), "state", "replay.db"), 0)
	if err != nil {
		t.Fatal(err)
	}
	// Runs before t.TempDir's cleanup: waits for store operations of node
	// handlers that outlive the test, so Windows can remove the directory.
	store := &closingStore{store: file}
	t.Cleanup(store.close)
	srv, err := singlink.NewServer(singlink.ServerConfig{Key: key, ReplayStore: store, Issuers: singlink.NewIssuers(issuer.Public().(ed25519.PublicKey)),
		BlockedPorts: []uint16{443}, FlightIdle: 5 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go srv.Serve(ln)
	tok, err := singlink.IssueToken(issuer, &singlink.Token{DevicePub: device.Public().(ed25519.PublicKey), Caps: singlink.CapTCP,
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	return (&singlink.Profile{Server: ln.Addr().String(), Transport: "tcp", ServerKey: key.Public(), Token: tok, Device: device}).Link()
}

func TestClientAndDemoCommands(t *testing.T) {
	oldWait := waitSignal
	waited := 0
	waitSignal = func() { waited++ }
	defer func() { waitSignal = oldWait }()

	// Node start-up takes at least one second (flights stamped before the
	// node process started are refused), so wait for it.
	link := startNode(t)
	time.Sleep(1100 * time.Millisecond)
	code, out, errOut := runCLI(t, "client", "-link", link, "-listen", "127.0.0.1:0")
	if code != 0 || !strings.Contains(out, "SOCKS5 proxy on 127.0.0.1:") || !strings.Contains(errOut, singlink.Attribution) || waited != 1 {
		t.Fatalf("client: exit %d out %q err %q", code, out, errOut)
	}
	if code, _, errOut := runCLI(t, "client", "-link", "singlink://bad", "-listen", "127.0.0.1:0"); code != 1 || !strings.Contains(errOut, "error:") {
		t.Fatal("bad link accepted")
	}
	if code, _, _ := runCLI(t, "client", "-link", link, "-listen", "0.0.0.0:0"); code != 1 {
		t.Fatal("non-loopback listen accepted")
	}

	code, out, _ = runCLI(t, "demo", "-link-only", "-node", "127.0.0.1:0")
	if code != 0 || !strings.Contains(out, "singlink://") || waited != 2 {
		t.Fatalf("demo: exit %d out %q", code, out)
	}
	var demoLink string
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "singlink://") {
			demoLink = line
		}
	}
	p, err := singlink.ParseLink(demoLink)
	if err != nil || p.Transport != "tls" || len(p.Pin) != 32 || p.SNI != "singlink-demo.local" {
		t.Fatalf("demo link %v %+v", err, p)
	}
	if code, _, _ := runCLI(t, "demo", "-node", "256.0.0.1:1"); code != 1 {
		t.Fatal("bad node address accepted")
	}
	for _, cmd := range []string{"client", "demo"} {
		if code, _, _ := runCLI(t, cmd, "-nope"); code != 2 {
			t.Fatalf("%s: unknown flag", cmd)
		}
	}
}

// closingStore lets a test node's replay store be shut down before its
// directory is removed.
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
