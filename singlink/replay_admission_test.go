// Copyright 2026 SingLinkLabs
// SPDX-License-Identifier: Apache-2.0
package singlink

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func TestFutureFlightRejectedAcrossRestart(t *testing.T) {
	e := newEnv(t, envOpt{mutate: func(c *ServerConfig) {
		c.FlightIdle = 5 * time.Millisecond
		c.HandshakeTimeout = 100 * time.Millisecond
	}})
	dst, _ := ParseAddr(echoServer(t, ""))
	marker := []byte("synthetic-restart-control")
	stamp := time.Now().Add(45 * time.Second)
	flight, hs, err := buildFirstFlight(e.key.Public(), e.device, &request{ts: stamp, cmd: CmdTCP, dst: dst, token: e.profile.Token, early: marker}, 0)
	if err != nil {
		t.Fatal(err)
	}
	accepts := func(addr string) bool {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(time.Second))
		if _, err := c.Write(flight); err != nil {
			return false
		}
		f := make([]byte, 32)
		if _, err := io.ReadFull(c, f); err != nil {
			return false
		}
		_, s2c, err := hs.finish(f)
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
	if !accepts(e.addr) {
		t.Fatal("fresh control rejected")
	}
	snapshot, err := e.srv.cfg.ReplayStore.(*FileReplayStore).load()
	if err != nil || len(snapshot.entries) != 1 {
		t.Fatal("admission did not persist mark")
	}
	expected := time.Unix(stamp.Unix(), 0).Add(e.srv.cfg.MaxTimeSkew + time.Second).UnixNano()
	for _, expiry := range snapshot.entries {
		if expiry != expected {
			t.Fatal("future flight expiry did not cover its full accepted window")
		}
	}

	if accepts(e.addr) {
		t.Fatal("same-instance replay admitted")
	}
	// A separate store object models a new process over the same durable state.
	reopened, err := OpenFileReplayStore(e.srv.cfg.ReplayStore.(*FileReplayStore).path, 0)
	if err != nil {
		t.Fatal(err)
	}
	cfg := e.srv.cfg
	cfg.ReplayStore = reopened
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go srv.Serve(ln)
	if accepts(ln.Addr().String()) {
		t.Fatal("future-dated restart replay admitted")
	}
	rotated, _ := GenerateServerKey()
	cfg.Key, cfg.OldKeys = rotated, []*ServerPrivateKey{e.key}
	rotatedServer, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rotatedLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer rotatedLn.Close()
	go rotatedServer.Serve(rotatedLn)
	if accepts(rotatedLn.Addr().String()) {
		t.Fatal("old-key replay namespace reset on rotation")
	}
}
