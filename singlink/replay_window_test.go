// Copyright 2026 SingLinkVPN (https://singlinkvpn.com)
// SPDX-License-Identifier: Apache-2.0
package singlink

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestSharedReplayStoreMixedAcceptanceWindows(t *testing.T) {
	short := 2 * time.Second
	e := newEnv(t, envOpt{mutate: func(c *ServerConfig) {
		c.MaxTimeSkew = short
		c.FlightIdle = 2 * time.Millisecond
		c.HandshakeTimeout = 500 * time.Millisecond
	}})
	firstStore := e.srv.cfg.ReplayStore.(*FileReplayStore)
	secondStore, err := OpenFileReplayStore(firstStore.path, 0)
	if err != nil {
		t.Fatal(err)
	}
	cfg := e.srv.cfg
	cfg.MaxTimeSkew = maxSupportedTimeSkew
	cfg.ReplayStore = secondStore
	longer, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go longer.Serve(ln)
	var clock atomic.Int64
	clock.Store(time.Now().UnixNano())
	sharedNow := func() time.Time { return time.Unix(0, clock.Load()) }
	firstStore.now, secondStore.now = sharedNow, sharedNow
	dst, _ := ParseAddr(echoServer(t, ""))
	marker := []byte("synthetic-mixed-window")
	stamp := time.Now().Add(time.Second)
	flight, hs, err := buildFirstFlight(e.key.Public(), e.device, &request{ts: stamp, cmd: CmdTCP, dst: dst, token: e.profile.Token, early: marker}, 0)
	if err != nil {
		t.Fatal(err)
	}
	accepted := func(addr string, packet []byte, handshake *clientHandshake) bool {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(time.Second))
		if _, err := c.Write(packet); err != nil {
			return false
		}
		f := make([]byte, 32)
		if _, err := io.ReadFull(c, f); err != nil {
			return false
		}
		_, s2c, err := handshake.finish(f)
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
	if !accepted(e.addr, flight, hs) {
		t.Fatal("short-window valid control rejected")
	}
	snapshot, err := firstStore.load()
	if err != nil || len(snapshot.entries) != 1 {
		t.Fatal("short-window mark missing")
	}
	commonExpiry := time.Unix(stamp.Unix(), 0).Add(maxSupportedTimeSkew + time.Second)
	for _, expiry := range snapshot.entries {
		if expiry != commonExpiry.UnixNano() {
			t.Fatal("short instance reduced shared replay retention")
		}
	}
	// Advance only the store's injected test clock beyond the SHORT expiry and
	// trigger GC. No system clock is changed and no external destination is used.
	clock.Store(time.Unix(stamp.Unix(), 0).Add(short + time.Second + time.Nanosecond).UnixNano())
	if ok, err := secondStore.CheckAndMark(context.Background(), replayTag("gc-trigger"), sharedNow().Add(time.Minute)); !ok || err != nil {
		t.Fatal("normal GC control failed")
	}
	if accepted(ln.Addr().String(), flight, hs) {
		t.Fatal("long-window instance replayed short-window admission after GC")
	}
	fresh, freshHS, err := buildFirstFlight(e.key.Public(), e.device, &request{ts: time.Now().Add(time.Second), cmd: CmdTCP, dst: dst, token: e.profile.Token, early: marker}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !accepted(ln.Addr().String(), fresh, freshHS) {
		t.Fatal("fresh long-window control rejected")
	}
}

func TestUnsupportedReplayWindowRefusesStartup(t *testing.T) {
	e := newEnv(t, envOpt{})
	cfg := e.srv.cfg
	cfg.MaxTimeSkew = maxSupportedTimeSkew + time.Nanosecond
	if _, err := NewServer(cfg); err == nil {
		t.Fatal("unsupported replay window accepted")
	}
	cfg.MaxTimeSkew = -time.Second
	if _, err := NewServer(cfg); err == nil {
		t.Fatal("negative replay window accepted")
	}
}
