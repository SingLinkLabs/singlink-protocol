// Copyright 2026 SingLinkVPN (https://singlinkvpn.com)
// SPDX-License-Identifier: Apache-2.0
package engine

// Regression test ported from the 2026-11-13 third-party source audit of
// commit 9b04898 (finding P-04). The audit's reproduction passed while the
// defect existed; this version asserts the safe behaviour and fails on
// 9b04898. Synthetic keys and loopback only; destination 443 is blocked by
// the test node before any DNS lookup or dial.

import (
	"crypto/ed25519"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SingLinkLabs/singlink-protocol/singlink"
)

func TestAuditP04StopDuringPendingStart(t *testing.T) {
	key, _ := singlink.GenerateServerKey()
	issuer, _ := singlink.GenerateEd25519()
	device, _ := singlink.GenerateEd25519()
	node, err := singlink.NewServer(auditNodeConfig(t, singlink.ServerConfig{Key: key, Issuers: singlink.NewIssuers(issuer.Public().(ed25519.PublicKey)), BlockedPorts: []uint16{443}, FlightIdle: time.Millisecond}))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go node.Serve(ln)
	token, err := singlink.IssueToken(issuer, &singlink.Token{DevicePub: device.Public().(ed25519.PublicKey), Caps: singlink.CapTCP, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	link := (&singlink.Profile{Server: ln.Addr().String(), Transport: "tcp", ServerKey: key.Public(), Token: token, Device: device}).Link()
	var e Engine
	defer e.Stop()
	var cleanups atomic.Int32
	entered, release := make(chan struct{}), make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- e.StartWith(link, "audit-mock-transport", func(*singlink.Client) (func(), error) {
			close(entered)
			<-release
			return func() { cleanups.Add(1) }, nil
		})
	}()
	select {
	case <-entered:
	case <-time.After(4 * time.Second):
		t.Fatal("startup callback not reached")
	}
	e.Stop()
	if e.Status().Running {
		t.Fatal("control: Stop did not report stopped")
	}
	close(release)
	if err := <-result; err == nil {
		t.Fatal("P-04: cancelled startup reported success")
	}
	if e.Status().Running {
		t.Fatal("P-04: late startup completion republished a running transport after Stop")
	}
	if cleanups.Load() != 1 {
		t.Fatalf("P-04: late transport cleaned up %d times, want exactly once", cleanups.Load())
	}
	e.Stop()
	if cleanups.Load() != 1 {
		t.Fatal("P-04: second Stop repeated cleanup")
	}
}
