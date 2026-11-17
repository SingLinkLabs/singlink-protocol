// Copyright 2026 SingLinkVPN (https://singlinkvpn.com)
// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/SingLinkLabs/singlink-protocol/singlink"
)

// testNode runs a loopback node that allows private destinations (for local
// HTTP test servers) but refuses port 443 before any DNS lookup, so the
// engine's verification handshake needs no network. It returns a link.
func testNode(t *testing.T) (*singlink.Profile, *singlink.ServerPrivateKey) {
	t.Helper()
	key, _ := singlink.GenerateServerKey()
	issuer, _ := singlink.GenerateEd25519()
	device, _ := singlink.GenerateEd25519()
	srv, err := singlink.NewServer(singlink.ServerConfig{Key: key, ReplayStore: testReplayStore(t), Issuers: singlink.NewIssuers(issuer.Public().(ed25519.PublicKey)),
		AllowPrivate: true, BlockedPorts: []uint16{443}, FlightIdle: 5 * time.Millisecond, HandshakeTimeout: time.Second})
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
	// Flights stamped in the node's first second are refused (restart rule).
	time.Sleep(1100 * time.Millisecond)
	return &singlink.Profile{Server: ln.Addr().String(), Transport: "tcp", ServerKey: key.Public(), Token: tok, Device: device}, key
}

func TestStartSOCKS5ProbeAndExitIP(t *testing.T) {
	p, _ := testNode(t)
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ip":
			fmt.Fprint(w, " 203.0.113.7\n")
		case "/junk":
			fmt.Fprint(w, "not an address")
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer site.Close()
	oldURL := exitIPURL
	defer func() { exitIPURL = oldURL }()

	var e Engine
	defer e.Stop()
	if _, _, err := e.Probe(site.URL, time.Second); err == nil {
		t.Fatal("probe while stopped")
	}
	if err := e.Start(p.Link(), "127.0.0.1:0", Options{Auth: true}); err != nil {
		t.Fatal(err)
	}
	st := e.Status()
	if !st.Running || !strings.HasPrefix(st.Listen, "127.0.0.1:") || st.Since == 0 {
		t.Fatalf("status %+v", st)
	}
	if user, pass := e.Credentials(); len(user) < 16 || len(pass) < 16 || user == pass {
		t.Fatal("SOCKS5 credentials not generated")
	}
	if e.Start(p.Link(), "127.0.0.1:0") == nil {
		t.Fatal("second start accepted")
	}
	code, latency, err := e.Probe(site.URL+"/", 0)
	if err != nil || code != http.StatusNoContent || latency <= 0 {
		t.Fatalf("probe: %d %v %v", code, latency, err)
	}
	exitIPURL = site.URL + "/ip"
	if ip, err := e.ExitIP(time.Hour); err != nil || ip != "203.0.113.7" {
		t.Fatalf("exit IP %q %v", ip, err)
	}
	exitIPURL = site.URL + "/junk"
	if _, err := e.ExitIP(time.Second); err == nil {
		t.Fatal("junk exit IP accepted")
	}
	exitIPURL = "http://127.0.0.1:1/unreachable"
	if _, err := e.ExitIP(time.Second); err == nil {
		t.Fatal("unreachable exit IP service")
	}
	if _, _, err := e.Probe("http://127.0.0.1:1/", time.Second); err == nil {
		t.Fatal("unreachable probe")
	}
	if st := e.Status(); st.Up == 0 || st.Down == 0 {
		t.Fatalf("counters not updated: %+v", st)
	}
	e.Stop()
	if st := e.Status(); st.Running || st.Listen == "" {
		t.Fatalf("stopped status %+v", st)
	}
	if _, err := e.ExitIP(time.Second); err == nil {
		t.Fatal("exit IP while stopped")
	}
	// Without Auth no credentials are issued; the engine restarts cleanly.
	if err := e.Start(p.Link(), "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	if user, pass := e.Credentials(); user != "" || pass != "" {
		t.Fatal("credentials without Auth")
	}
}

func TestStartErrorsAreReported(t *testing.T) {
	p, _ := testNode(t)
	var e Engine
	defer e.Stop()
	if err := e.Start("singlink://broken", "127.0.0.1:0"); err == nil || e.Status().LastError == "" || e.Status().Running {
		t.Fatal("bad link")
	}
	for _, listen := range []string{"0.0.0.0:0", "localhost:1080", "garbage"} {
		if err := e.Start(p.Link(), listen); err == nil || !strings.Contains(err.Error(), "loopback") {
			t.Fatalf("listen %q accepted: %v", listen, err)
		}
	}
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	if err := e.Start(p.Link(), busy.Addr().String()); err == nil {
		t.Fatal("busy listen address accepted")
	}

	// A link for another node key (the same symptom as a protocol draft
	// mismatch) is reported with the client's diagnostic.
	other, _ := singlink.GenerateServerKey()
	wrong := *p
	wrong.ServerKey = other.Public()
	err = e.Start(wrong.Link(), "127.0.0.1:0")
	if !errors.Is(err, singlink.ErrRejected) || !strings.Contains(e.Status().LastError, "draft mismatch") {
		t.Fatalf("mismatch not diagnosed: %v / %q", err, e.Status().LastError)
	}

	if err := e.StartWith(p.Link(), "tun", nil); err == nil {
		t.Fatal("nil transport callback")
	}
	if err := e.StartWith("singlink://broken", "tun", func(*singlink.Client) (func(), error) { return nil, nil }); err == nil {
		t.Fatal("bad link in StartWith")
	}
	cleaned := false
	failure := errors.New("synthetic transport failure")
	err = e.StartWith(p.Link(), "tun", func(*singlink.Client) (func(), error) { return func() { cleaned = true }, failure })
	if !errors.Is(err, failure) || !cleaned || e.Status().Running || e.Status().LastError != failure.Error() {
		t.Fatalf("failed transport: %v cleaned=%v status=%+v", err, cleaned, e.Status())
	}
	if e.StopClient(nil) {
		t.Fatal("nil client matched")
	}
}
