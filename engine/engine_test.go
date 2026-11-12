// Copyright 2026 SingLinkLabs (https://github.com/SingLinkLabs)
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"crypto/ed25519"
	"net"
	"testing"
	"time"

	"github.com/SingLinkLabs/singlink-protocol/singlink"
)

func TestStartWithCustomTransport(t *testing.T) {
	key, _ := singlink.GenerateServerKey()
	issuer, _ := singlink.GenerateEd25519()
	dev, _ := singlink.GenerateEd25519()
	srv, _ := singlink.NewServer(singlink.ServerConfig{Key: key, Issuers: singlink.NewIssuers(issuer.Public().(ed25519.PublicKey))})
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
