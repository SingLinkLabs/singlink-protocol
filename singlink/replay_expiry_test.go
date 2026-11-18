// Copyright 2026 SingLinkVPN (https://singlinkvpn.com)
// SPDX-License-Identifier: Apache-2.0
package singlink

// F-01 (reported by VPN Labs against b924690): a first flight that was
// admitted with STATUS 0 while its token was valid, replayed after the
// token's NotAfter but inside the timestamp window, must not get a status-only
// answer (STATUS 1, token expired). More generally, no status-only refusal may
// answer a flight whose opaque tag is already durably marked, by this or by
// another process sharing the store: such a copy is a replay and goes to the
// fallback exactly like a random probe. Synthetic keys and loopback sockets
// only.

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// flightAt builds a first flight from the env's device with an explicit
// timestamp.
func flightAt(t *testing.T, e *env, cmd Cmd, dst string, token []byte, ts time.Time) ([]byte, *clientHandshake) {
	t.Helper()
	a, err := ParseAddr(dst)
	if err != nil {
		t.Fatal(err)
	}
	if token == nil {
		token = e.profile.Token
	}
	flight, hs, err := buildFirstFlight(e.key.Public(), e.device, &request{ts: ts, cmd: cmd, dst: a, token: token}, 0)
	if err != nil {
		t.Fatal(err)
	}
	return flight, hs
}

// rawAnswer sends b and returns every byte the endpoint sends back until it
// closes the connection.
func rawAnswer(t *testing.T, addr string, b []byte) []byte {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(4 * time.Second))
	if _, err := c.Write(b); err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(c)
	return out
}

// expectProbeLike asserts that flight gets exactly the answer a random probe
// of the same length gets (the fallback website's), and that the fallback
// received the flight's bytes unchanged.
func expectProbeLike(t *testing.T, name, addr string, flight []byte, got chan []byte) {
	t.Helper()
	answer := rawAnswer(t, addr, flight)
	select {
	case b := <-got:
		if len(b) < firstFlightFixed || !bytes.HasPrefix(flight, b) {
			t.Fatalf("%s: fallback did not receive the flight unchanged", name)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("%s: flight did not reach the fallback (answer %d bytes)", name, len(answer))
	}
	probe := make([]byte, len(flight))
	rand.Read(probe)
	want := rawAnswer(t, addr, probe)
	<-got
	if !bytes.Equal(answer, want) || !bytes.HasPrefix(answer, []byte("HTTP/")) {
		t.Fatalf("%s: answer differs from a random probe's (%d vs %d bytes)", name, len(answer), len(want))
	}
}

// sleepUntil waits until the wall clock passes at.
func sleepUntil(at time.Time) {
	if d := time.Until(at); d > 0 {
		time.Sleep(d)
	}
}

// countingListener accepts and counts connections (a destination that must
// never be contacted by a replay).
func countingListener(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	var n atomic.Int32
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
			n.Add(1)
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	return ln.Addr().String(), &n
}

// The reported case, one process: token valid for about 3 s, the original
// flight gets STATUS 0, the same bytes replayed after expiry (inside the
// 120 s window) go to the fallback, indistinguishable from a probe.
func TestF01AdmittedThenExpiredReplaySingleProcess(t *testing.T) {
	site, got := fallbackSite(t)
	notAfter := time.Unix(time.Now().Add(3*time.Second).Unix(), 0)
	e := newEnv(t, envOpt{fallback: site, tok: &Token{Caps: CapTCP, NotBefore: time.Now().Add(-time.Minute), NotAfter: notAfter},
		mutate: func(c *ServerConfig) { c.FlightIdle = 5 * time.Millisecond }})
	dst, dialed := countingListener(t)
	flight, hs := flightFor(t, e, CmdTCP, dst, nil)
	if st, ok := exchange(t, e.addr, flight, hs); !ok || st != StatusOK {
		t.Fatalf("original flight: %v %v", st, ok)
	}
	sleepUntil(notAfter.Add(1500 * time.Millisecond))
	expectProbeLike(t, "replay after expiry", e.addr, flight, got)
	expectProbeLike(t, "second replay after expiry", e.addr, flight, got)
	if n := dialed.Load(); n != 1 {
		t.Fatalf("destination contacted %d times, want 1", n)
	}
}

// The reported case across two processes sharing the replay store: the
// original is admitted by one, the copy after expiry is sent to the other.
func TestF01AdmittedThenExpiredReplayAcrossProcesses(t *testing.T) {
	site, got := fallbackSite(t)
	notAfter := time.Unix(time.Now().Add(4*time.Second).Unix(), 0)
	e := newEnv(t, envOpt{fallback: site, tok: &Token{Caps: CapTCP, NotBefore: time.Now().Add(-time.Minute), NotAfter: notAfter},
		mutate: func(c *ServerConfig) { c.FlightIdle = 5 * time.Millisecond }})
	other := auditServe(t, auditFreshInstanceConfig(t, e.srv.cfg))
	time.Sleep(1100 * time.Millisecond) // flights must not predate the second process
	dst, dialed := countingListener(t)
	flight, hs := flightFor(t, e, CmdTCP, dst, nil)
	if st, ok := exchange(t, e.addr, flight, hs); !ok || st != StatusOK {
		t.Fatalf("original flight: %v %v", st, ok)
	}
	sleepUntil(notAfter.Add(1500 * time.Millisecond))
	expectProbeLike(t, "replay to the sibling after expiry", other, flight, got)
	expectProbeLike(t, "replay to the admitting process after expiry", e.addr, flight, got)
	if n := dialed.Load(); n != 1 {
		t.Fatalf("destination contacted %d times, want 1", n)
	}
}

// A flight made while its token was valid but first received after expiry
// is answered once with STATUS 1, without a destination operation; its copy
// goes to the fallback on every process sharing the store.
func TestF01ExpiredInWindowAnsweredOnceAcrossProcesses(t *testing.T) {
	site, got := fallbackSite(t)
	notAfter := time.Unix(time.Now().Add(3*time.Second).Unix(), 0)
	e := newEnv(t, envOpt{fallback: site, tok: &Token{Caps: CapTCP, NotBefore: time.Now().Add(-time.Minute), NotAfter: notAfter},
		mutate: func(c *ServerConfig) { c.FlightIdle = 5 * time.Millisecond }})
	other := auditServe(t, auditFreshInstanceConfig(t, e.srv.cfg))
	time.Sleep(1100 * time.Millisecond)
	dst, dialed := countingListener(t)
	flight, hs := flightFor(t, e, CmdTCP, dst, nil)
	sleepUntil(notAfter.Add(500 * time.Millisecond))
	if st, ok := exchange(t, e.addr, flight, hs); !ok || st != StatusTokenExpired {
		t.Fatalf("first copy after expiry: %v %v", st, ok)
	}
	expectProbeLike(t, "copy to the sibling", other, flight, got)
	expectProbeLike(t, "copy to the same process", e.addr, flight, got)
	if dialed.Load() != 0 {
		t.Fatal("an expired token's flight reached its destination")
	}
}

// Every status-only refusal path that a durably held flight can reach: a
// flight whose tag is already durably held (admitted earlier here, or by
// another process sharing the store) goes to the fallback, with no
// status-only mark and no further durable write. (An expired-token flight
// that could have been admitted takes the durable path, covered above; one
// stamped later cannot be durably held by any instance.)
func TestF01DurablyMarkedFlightGetsNoStatusOnlyAnswer(t *testing.T) {
	site, got := fallbackSite(t)
	now := time.Now()
	e := newEnv(t, envOpt{fallback: site, tok: &Token{Caps: CapTCP, NotBefore: now.Add(-2 * time.Hour), NotAfter: now.Add(-time.Hour)},
		mutate: func(c *ServerConfig) {
			c.FlightIdle = 5 * time.Millisecond
			c.AllowPrivate = false
		}})
	live := issueFor(t, e, CapTCP)
	// A second handle on the same state stands for another process.
	sibling := auditFreshInstanceConfig(t, e.srv.cfg).ReplayStore
	cases := []struct {
		name  string
		cmd   Cmd
		dst   string
		token []byte
		want  Status
	}{
		{"capability", CmdUDP, "udp:0", live, StatusCapDenied},
		{"command", Cmd(7), "192.0.2.1:443", live, StatusBadRequest},
		{"literal policy", CmdTCP, "10.1.2.3:443", live, StatusForbiddenDest},
		{"port policy", CmdTCP, "192.0.2.1:25", live, StatusForbiddenDest},
	}
	for _, c := range cases {
		for _, store := range []struct {
			name string
			s    ReplayStore
		}{{"same process", e.srv.replay}, {"other process", sibling}} {
			name := c.name + " / " + store.name
			// Control: an unmarked flight of this kind gets its status.
			flight, hs := flightFor(t, e, c.cmd, c.dst, c.token)
			if st, ok := exchange(t, e.addr, flight, hs); !ok || st != c.want {
				t.Fatalf("%s: control answer %v %v", name, st, ok)
			}
			flight, _ = flightFor(t, e, c.cmd, c.dst, c.token)
			tag := replayTagFor(e.key, flight[:x25519Len])
			if ok, err := store.s.CheckAndMark(t.Context(), tag, time.Now().Add(time.Minute)); !ok || err != nil {
				t.Fatalf("%s: pre-mark: %v %v", name, ok, err)
			}
			expectProbeLike(t, name, e.addr, flight, got)
			if e.srv.statusMarks.seen(tag, time.Now()) {
				t.Fatalf("%s: a durably held flight took a status-only mark", name)
			}
		}
	}
}

// A destination policy tightened between processes (or across a restart)
// cannot turn an admitted flight's copy into a status-only answer.
func TestF01PolicyRefusalOfAdmittedFlightAcrossProcesses(t *testing.T) {
	site, got := fallbackSite(t)
	dst, dialed := countingListener(t)
	port := uint16(mustPort(t, dst))
	e := newEnv(t, envOpt{fallback: site, mutate: func(c *ServerConfig) { c.FlightIdle = 5 * time.Millisecond }})
	cfg := auditFreshInstanceConfig(t, e.srv.cfg)
	cfg.BlockedPorts = []uint16{port}
	strict := auditServe(t, cfg)
	time.Sleep(1100 * time.Millisecond)
	flight, hs := flightFor(t, e, CmdTCP, dst, nil)
	if st, ok := exchange(t, e.addr, flight, hs); !ok || st != StatusOK {
		t.Fatalf("original flight: %v %v", st, ok)
	}
	expectProbeLike(t, "copy to the stricter process", strict, flight, got)
	if n := dialed.Load(); n != 1 {
		t.Fatalf("destination contacted %d times, want 1", n)
	}
}

func mustPort(t *testing.T, hostport string) int {
	t.Helper()
	a, err := net.ResolveTCPAddr("tcp", hostport)
	if err != nil {
		t.Fatal(err)
	}
	return a.Port
}

// A failing read-only lookup fails closed on every status-only path that
// performs one: no answer (probe-like fallback), no durable write, no
// status-only mark.
func TestF01StatusOnlyLookupFailureFailsClosed(t *testing.T) {
	site, got := fallbackSite(t)
	store := &capacityStore{limit: 100, hasFail: errors.New("synthetic lookup failure")}
	now := time.Now()
	e := newEnv(t, envOpt{fallback: site, tok: &Token{Caps: CapTCP, NotBefore: now.Add(-2 * time.Hour), NotAfter: now.Add(-time.Hour)},
		mutate: func(c *ServerConfig) {
			c.ReplayStore = store
			c.FlightIdle = 5 * time.Millisecond
			c.AllowPrivate = false
		}})
	live := issueFor(t, e, CapTCP)
	for _, c := range []struct {
		name  string
		cmd   Cmd
		dst   string
		token []byte
	}{
		{"capability", CmdUDP, "udp:0", live},
		{"command", Cmd(7), "192.0.2.1:443", live},
		{"literal policy", CmdTCP, "10.1.2.3:443", live},
		{"port policy", CmdTCP, "192.0.2.1:25", live},
	} {
		flight, _ := flightFor(t, e, c.cmd, c.dst, c.token)
		expectProbeLike(t, c.name, e.addr, flight, got)
		if e.srv.statusMarks.seen(replayTagFor(e.key, flight[:x25519Len]), time.Now()) {
			t.Fatalf("%s: unanswered flight took a status-only mark", c.name)
		}
	}
	if store.calls.Load() != 0 || store.hasCalls.Load() != 4 {
		t.Fatalf("writes %d, lookups %d", store.calls.Load(), store.hasCalls.Load())
	}
	// A slow lookup is bounded by the handshake timeout and fails closed too.
	slow := &slowLookupStore{capacityStore: capacityStore{limit: 10}, delay: 2 * time.Second}
	e2 := newEnv(t, envOpt{fallback: site, tok: &Token{Caps: CapTCP, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)},
		mutate: func(c *ServerConfig) {
			c.ReplayStore = slow
			c.FlightIdle = 5 * time.Millisecond
			c.HandshakeTimeout = 300 * time.Millisecond
		}})
	flight, hs := flightFor(t, e2, CmdUDP, "udp:0", nil)
	if st, ok := exchange(t, e2.addr, flight, hs); ok {
		t.Fatalf("refusal answered after a timed-out lookup: %v", st)
	}
}

// slowLookupStore answers lookups only after delay (or when ctx ends, with
// a stale "not held" result plus no error, which the node must still treat
// as a failure because its deadline passed).
type slowLookupStore struct {
	capacityStore
	delay time.Duration
}

func (s *slowLookupStore) Has(ctx context.Context, tag [32]byte) (bool, error) {
	select {
	case <-time.After(s.delay):
	case <-ctx.Done():
	}
	return false, nil
}

// Concurrent copies of one expired-in-window flight sent to two processes
// sharing the store: exactly one copy gets a node answer.
func TestF01ConcurrentExpiredCopiesAnsweredOnce(t *testing.T) {
	site, got := fallbackSite(t)
	go func() {
		for range got {
		}
	}()
	notAfter := time.Unix(time.Now().Add(3*time.Second).Unix(), 0)
	e := newEnv(t, envOpt{fallback: site, tok: &Token{Caps: CapTCP, NotBefore: time.Now().Add(-time.Minute), NotAfter: notAfter},
		mutate: func(c *ServerConfig) { c.FlightIdle = 5 * time.Millisecond }})
	other := auditServe(t, auditFreshInstanceConfig(t, e.srv.cfg))
	time.Sleep(1100 * time.Millisecond)
	flight, hs := flightFor(t, e, CmdTCP, "192.0.2.1:443", nil)
	sleepUntil(notAfter.Add(500 * time.Millisecond))
	var answered atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		addr := e.addr
		if i%2 == 1 {
			addr = other
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if st, ok := exchange(t, addr, flight, hs); ok {
				if st != StatusTokenExpired {
					t.Errorf("unexpected status %v", st)
				}
				answered.Add(1)
			}
		}()
	}
	wg.Wait()
	if n := answered.Load(); n != 1 {
		t.Fatalf("%d copies answered, want exactly 1", n)
	}
}

// Expiry is decided against the flight timestamp: only a flight that no
// supported instance could have admitted before NotAfter skips the durable
// path.
func TestF01MayHaveBeenAdmitted(t *testing.T) {
	na := time.Unix(1_000_000, 0)
	tok := &Token{NotAfter: na}
	for _, c := range []struct {
		ts   time.Time
		want bool
	}{
		{na.Add(-time.Hour), true},
		{na, true},
		{na.Add(maxSupportedTimeSkew), true},
		{na.Add(maxSupportedTimeSkew + time.Second - time.Nanosecond), true},
		{na.Add(maxSupportedTimeSkew + time.Second), false},
		{na.Add(time.Hour), false},
	} {
		if got := mayHaveBeenAdmitted(c.ts, tok); got != c.want {
			t.Fatalf("ts %v after NotAfter: got %v", c.ts.Sub(na), got)
		}
	}
}

// Has is read-only, observes marks made through another handle, ignores
// expired marks and fails closed like CheckAndMark.
func TestReplayStoreHasIsReadOnly(t *testing.T) {
	s := replayTestStore(t, 4)
	ctx := context.Background()
	now := time.Now().Add(time.Second)
	s.now = func() time.Time { return now }
	if held, err := s.Has(ctx, replayTag("a")); held || err != nil {
		t.Fatalf("empty store: %v %v", held, err)
	}
	other, err := OpenFileReplayStore(s.path, 4)
	if err != nil {
		t.Fatal(err)
	}
	other.now = s.now
	if ok, err := other.CheckAndMark(ctx, replayTag("a"), now.Add(2*time.Second)); !ok || err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if held, err := s.Has(ctx, replayTag("a")); !held || err != nil {
		t.Fatalf("mark from another handle not seen: %v %v", held, err)
	}
	if held, err := s.Has(ctx, replayTag("b")); held || err != nil {
		t.Fatalf("unmarked tag: %v %v", held, err)
	}
	now = now.Add(3 * time.Second)
	if held, err := s.Has(ctx, replayTag("a")); held || err != nil {
		t.Fatalf("expired mark reported: %v %v", held, err)
	}
	after, err := os.ReadFile(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("lookup changed the durable state")
	}
	// Clock behind the watermark, cancellation and corrupt state fail closed.
	now = now.Add(-time.Hour)
	if held, err := s.Has(ctx, replayTag("a")); held || err == nil {
		t.Fatal("lookup accepted a clock behind the watermark")
	}
	now = now.Add(time.Hour)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := s.Has(cancelled, replayTag("a")); err == nil {
		t.Fatal("cancelled lookup succeeded")
	}
	unlock, err := s.lock(ctx)
	if err != nil {
		t.Fatal(err)
	}
	short, cancelShort := context.WithTimeout(ctx, 20*time.Millisecond)
	_, err = s.Has(short, replayTag("a"))
	cancelShort()
	unlock()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lookup did not wait for the lock and honor cancellation: %v", err)
	}
	bad := append([]byte{}, after...)
	bad[len(bad)-1] ^= 1
	if err := os.WriteFile(s.path, bad, 0600); err != nil {
		t.Fatal(err)
	}
	if held, err := s.Has(ctx, replayTag("a")); held || err == nil {
		t.Fatal("corrupt state accepted by lookup")
	}
}

// The read-only lookup cannot be used as an amplifier: an expired-token
// flight stamped too late to have been admitted needs none, and a subject
// over its status-only share is dropped before any lookup (reviewer finding:
// lapsed or over-quota tokens must not contend for the store lock).
func TestF01RefusalsWithoutAnswerDoNotReadStore(t *testing.T) {
	store := &capacityStore{limit: 100}
	now := time.Now()
	e := newEnv(t, envOpt{tok: &Token{Caps: CapTCP, NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(-23 * time.Hour)},
		mutate: func(c *ServerConfig) {
			c.ReplayStore = store
			c.FlightIdle = 5 * time.Millisecond
			c.HandshakeTimeout = 300 * time.Millisecond
		}})
	e.srv.statusMarks.perSubject = 2
	answered := 0
	for i := 0; i < 6; i++ {
		flight, hs := flightFor(t, e, CmdTCP, "192.0.2.1:443", nil)
		if st, ok := exchange(t, e.addr, flight, hs); ok {
			if st != StatusTokenExpired {
				t.Fatalf("unexpected status %v", st)
			}
			answered++
		}
	}
	if answered != 2 || store.hasCalls.Load() != 0 || store.calls.Load() != 0 {
		t.Fatalf("lapsed token: answered %d, lookups %d, writes %d", answered, store.hasCalls.Load(), store.calls.Load())
	}
	live := issueFor(t, e, CapTCP)
	answered = 0
	for i := 0; i < 6; i++ {
		flight, hs := flightFor(t, e, CmdUDP, "udp:0", live)
		if st, ok := exchange(t, e.addr, flight, hs); ok {
			if st != StatusCapDenied {
				t.Fatalf("unexpected status %v", st)
			}
			answered++
		}
	}
	if answered != 2 || store.hasCalls.Load() != 2 || store.calls.Load() != 0 {
		t.Fatalf("over-quota subject: answered %d, lookups %d, writes %d", answered, store.hasCalls.Load(), store.calls.Load())
	}
}
