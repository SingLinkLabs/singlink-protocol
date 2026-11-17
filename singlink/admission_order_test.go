// Copyright 2026 SingLinkVPN (https://singlinkvpn.com)
// SPDX-License-Identifier: Apache-2.0
package singlink

// Admission order (re-audit 2026-11-17, section 6): refusals that depend only
// on the authenticated request, the token and the node configuration are
// decided before the durable replay store, so they cannot consume its
// capacity or block other subjects; replayed copies of refused flights still
// go to the fallback; nothing reaches a destination before the replay check.
// Synthetic keys, loopback sockets and an in-memory test store only (never a
// deployable store).

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// capacityStore is a test-only atomic in-memory ReplayStore with a fixed
// capacity, like the reviewer's 3-slot control.
type capacityStore struct {
	mu    sync.Mutex
	limit int
	marks map[[32]byte]time.Time
	calls atomic.Int32
	fail  error
}

func (s *capacityStore) CheckAndMark(_ context.Context, tag [32]byte, expiry time.Time) (bool, error) {
	s.calls.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail != nil {
		return false, s.fail
	}
	if s.marks == nil {
		s.marks = map[[32]byte]time.Time{}
	}
	if _, ok := s.marks[tag]; ok {
		return false, nil
	}
	if len(s.marks) >= s.limit {
		return false, ErrReplayStore
	}
	s.marks[tag] = expiry
	return true, nil
}

func (s *capacityStore) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.marks)
}

// exchange sends one prepared first flight and reports the node's status, or
// answered=false when the connection was handed to the fallback (the fallback
// site answers "HTTP/") or closed without a node answer.
func exchange(t *testing.T, addr string, flight []byte, hs *clientHandshake) (Status, bool) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write(flight); err != nil {
		return 0, false
	}
	F := make([]byte, x25519Len)
	if _, err := io.ReadFull(c, F); err != nil || bytes.HasPrefix(F, []byte("HTTP/")) {
		return 0, false
	}
	_, s2c, err := hs.finish(F)
	if err != nil {
		return 0, false
	}
	typ, b, err := (&frameReader{r: c, cs: s2c}).readFrame()
	if err != nil || typ != frameStatus || len(b) == 0 {
		return 0, false
	}
	return Status(b[0]), true
}

// flightFor builds a first flight from the env's device and token.
func flightFor(t *testing.T, e *env, cmd Cmd, dst string, token []byte) ([]byte, *clientHandshake) {
	t.Helper()
	a, err := ParseAddr(dst)
	if err != nil {
		t.Fatal(err)
	}
	if token == nil {
		token = e.profile.Token
	}
	flight, hs, err := buildFirstFlight(e.key.Public(), e.device, &request{ts: time.Now(), cmd: cmd, dst: a, token: token}, 0)
	if err != nil {
		t.Fatal(err)
	}
	return flight, hs
}

// issueFor issues a token for the env's device with the given capabilities
// and a fresh random subject.
func issueFor(t *testing.T, e *env, caps uint32) []byte {
	t.Helper()
	tok := &Token{Caps: caps, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), DevicePub: e.device.Public().(ed25519.PublicKey)}
	if _, err := rand.Read(tok.Subject[:]); err != nil {
		t.Fatal(err)
	}
	raw, err := IssueToken(e.issuer, tok)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// The reviewer's control: one permitted flight and two capability-denied
// flights against a 3-slot store must not block another valid subject.
func TestCapabilityDeniedFlightsDoNotConsumeReplayCapacity(t *testing.T) {
	store := &capacityStore{limit: 3}
	site, _ := fallbackSite(t)
	e := newEnv(t, envOpt{fallback: site, tok: &Token{Caps: CapTCP, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)},
		mutate: func(c *ServerConfig) { c.ReplayStore = store; c.FlightIdle = 5 * time.Millisecond }})
	echo := echoServer(t, "")

	flight, hs := flightFor(t, e, CmdTCP, echo, nil)
	if st, ok := exchange(t, e.addr, flight, hs); !ok || st != StatusOK {
		t.Fatalf("permitted control: %v %v", st, ok)
	}
	for i := 0; i < 2; i++ {
		flight, hs := flightFor(t, e, CmdUDP, "udp:0", nil)
		if st, ok := exchange(t, e.addr, flight, hs); !ok || st != StatusCapDenied {
			t.Fatalf("capability-denied flight %d: %v %v", i, st, ok)
		}
	}
	// Policy and malformed-command refusals are free as well.
	flight, hs = flightFor(t, e, CmdTCP, "127.0.0.1:25", nil)
	if st, ok := exchange(t, e.addr, flight, hs); !ok || st != StatusForbiddenDest {
		t.Fatalf("blocked-port flight: %v %v", st, ok)
	}
	flight, hs = flightFor(t, e, Cmd(9), echo, nil)
	if st, ok := exchange(t, e.addr, flight, hs); !ok || st != StatusBadRequest {
		t.Fatalf("unknown-command flight: %v %v", st, ok)
	}
	if n := store.len(); n != 1 {
		t.Fatalf("refused flights consumed replay capacity: %d marks", n)
	}

	// Another valid subject is still admitted.
	other := issueFor(t, e, CapTCP)
	flight, hs = flightFor(t, e, CmdTCP, echo, other)
	if st, ok := exchange(t, e.addr, flight, hs); !ok || st != StatusOK {
		t.Fatalf("another valid subject blocked: %v %v", st, ok)
	}
	if n := store.len(); n != 2 {
		t.Fatalf("want 2 marks, got %d", n)
	}
}

// Replayed copies of refused flights get no second node answer: they go to
// the fallback like any other replay, without touching the durable store.
func TestRefusedFlightReplaysGoToFallback(t *testing.T) {
	store := &capacityStore{limit: 100}
	site, got := fallbackSite(t)
	now := time.Now()
	e := newEnv(t, envOpt{fallback: site, tok: &Token{Caps: CapTCP, NotBefore: now.Add(-2 * time.Hour), NotAfter: now.Add(-time.Hour)},
		mutate: func(c *ServerConfig) {
			c.ReplayStore = store
			c.FlightIdle = 5 * time.Millisecond
			c.AllowPrivate = false
		}})
	live := issueFor(t, e, CapTCP)
	cases := []struct {
		name  string
		cmd   Cmd
		dst   string
		token []byte
		want  Status
	}{
		{"expired", CmdTCP, "192.0.2.1:443", nil, StatusTokenExpired},
		{"capability", CmdUDP, "udp:0", live, StatusCapDenied},
		{"command", Cmd(7), "192.0.2.1:443", live, StatusBadRequest},
		{"literal policy", CmdTCP, "10.1.2.3:443", live, StatusForbiddenDest},
		{"port policy", CmdTCP, "192.0.2.1:25", live, StatusForbiddenDest},
	}
	for _, c := range cases {
		flight, hs := flightFor(t, e, c.cmd, c.dst, c.token)
		if st, ok := exchange(t, e.addr, flight, hs); !ok || st != c.want {
			t.Fatalf("%s: first answer %v %v", c.name, st, ok)
		}
		if st, ok := exchange(t, e.addr, flight, hs); ok {
			t.Fatalf("%s: replay got a node answer %v", c.name, st)
		}
		select {
		case b := <-got:
			if len(b) < firstFlightFixed || !bytes.HasPrefix(flight, b) {
				t.Fatalf("%s: fallback did not receive the replayed bytes unchanged", c.name)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("%s: replay did not reach the fallback", c.name)
		}
	}
	if store.calls.Load() != 0 {
		t.Fatalf("refusals touched the durable replay store %d times", store.calls.Load())
	}
}

// A flight that already received a status-only answer is a replay for the
// durable path too, so a later change of the subject's state cannot turn a
// refused flight into an executed one.
func TestStatusOnlyMarkBlocksLaterAdmission(t *testing.T) {
	store := &capacityStore{limit: 10}
	e := newEnv(t, envOpt{mutate: func(c *ServerConfig) {
		c.ReplayStore = store
		c.FlightIdle = 5 * time.Millisecond
		c.HandshakeTimeout = time.Second
	}})
	var dialed atomic.Int32
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			dialed.Add(1)
			c.Close()
		}
	}()
	flight, hs := flightFor(t, e, CmdTCP, ln.Addr().String(), nil)
	if ok, _ := e.srv.statusMarks.mark(replayTagFor(e.key, flight[:x25519Len]), [16]byte{}, time.Now().Add(time.Minute), time.Now()); !ok {
		t.Fatal("mark failed")
	}
	if st, ok := exchange(t, e.addr, flight, hs); ok {
		t.Fatalf("status-marked flight admitted: %v", st)
	}
	if store.calls.Load() != 0 || dialed.Load() != 0 {
		t.Fatal("status-marked flight reached the store or the destination")
	}
}

// Ordering: with an unavailable store a permitted flight never reaches its
// destination, while a refusal (no destination operation) is still answered.
func TestNoDestinationOperationBeforeReplayCheck(t *testing.T) {
	store := &capacityStore{limit: 10, fail: errors.New("synthetic store outage")}
	e := newEnv(t, envOpt{tok: &Token{Caps: CapTCP, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)},
		mutate: func(c *ServerConfig) {
			c.ReplayStore = store
			c.FlightIdle = 5 * time.Millisecond
			c.HandshakeTimeout = time.Second
		}})
	var dialed atomic.Int32
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			dialed.Add(1)
			c.Close()
		}
	}()
	flight, hs := flightFor(t, e, CmdTCP, ln.Addr().String(), nil)
	if st, ok := exchange(t, e.addr, flight, hs); ok {
		t.Fatalf("flight admitted without a durable mark: %v", st)
	}
	time.Sleep(50 * time.Millisecond)
	if dialed.Load() != 0 || store.calls.Load() != 1 {
		t.Fatalf("destination contacted before replay check (dials %d, store calls %d)", dialed.Load(), store.calls.Load())
	}
	flight, hs = flightFor(t, e, CmdUDP, "udp:0", nil)
	if st, ok := exchange(t, e.addr, flight, hs); !ok || st != StatusCapDenied {
		t.Fatalf("refusal not answered: %v %v", st, ok)
	}
	if store.calls.Load() != 1 {
		t.Fatal("refusal used the durable store")
	}
}

// preAdmission is pure: it never resolves names or consults host state.
func TestPreAdmissionIsConfigOnly(t *testing.T) {
	s := &Server{res: &resolver{blockedPorts: map[uint16]bool{25: true}, r: nil}}
	tok := &Token{Caps: CapTCP}
	name, _ := ParseAddr("name.invalid:443")
	if st, _ := s.preAdmission(request{cmd: CmdTCP, dst: name}, tok, false); st != StatusOK {
		t.Fatalf("domain names are decided after admission, got %v", st)
	}
	for _, c := range []struct {
		dst  string
		want Status
	}{{"8.8.8.8:443", StatusOK}, {"8.8.8.8:25", StatusForbiddenDest}, {"8.8.8.8:0", StatusForbiddenDest}, {"127.0.0.1:443", StatusForbiddenDest}, {"[64:ff9b::a00:1]:443", StatusForbiddenDest}} {
		a, _ := ParseAddr(c.dst)
		if st, _ := s.preAdmission(request{cmd: CmdTCP, dst: a}, tok, false); st != c.want {
			t.Fatalf("%s: got %v want %v", c.dst, st, c.want)
		}
	}
	if st, _ := s.preAdmission(request{cmd: CmdTCP}, tok, true); st != StatusTokenExpired {
		t.Fatal("expired token")
	}
	if st, msg := s.preAdmission(request{cmd: 3}, tok, false); st != StatusBadRequest || msg == "" {
		t.Fatal("unknown command")
	}
	if st, _ := s.preAdmission(request{cmd: CmdUDP}, tok, false); st != StatusCapDenied {
		t.Fatal("udp capability")
	}
	if st, _ := s.preAdmission(request{cmd: CmdUDP}, &Token{Caps: CapUDP}, false); st != StatusOK {
		t.Fatal("udp permitted")
	}
	if st, _ := s.preAdmission(request{cmd: CmdTCP}, &Token{Caps: CapUDP}, false); st != StatusCapDenied {
		t.Fatal("tcp capability")
	}
}

func TestStatusMarksBoundedAndExpiring(t *testing.T) {
	s := &statusMarks{limit: 2}
	now := time.Unix(1_000_000, 0)
	a, b, c := replayTag("a"), replayTag("b"), replayTag("c")
	var subj [16]byte
	if ok, dup := s.mark(a, subj, now.Add(10*time.Second), now); !ok || dup {
		t.Fatal("first mark")
	}
	if ok, dup := s.mark(a, subj, now.Add(10*time.Second), now); ok || !dup {
		t.Fatal("duplicate status mark accepted")
	}
	if ok, _ := s.mark(b, subj, now.Add(20*time.Second), now); !ok {
		t.Fatal("second mark refused")
	}
	if ok, dup := s.mark(c, subj, now.Add(20*time.Second), now); ok || dup {
		t.Fatal("full set accepted a mark")
	}
	if ok, _ := s.mark(c, subj, now, now); ok {
		t.Fatal("already expired mark accepted")
	}
	if !s.seen(a, now.Add(9*time.Second)) || s.seen(c, now) {
		t.Fatal("seen")
	}
	later := now.Add(11 * time.Second)
	if s.seen(a, later) {
		t.Fatal("expired mark still seen")
	}
	if ok, _ := s.mark(c, subj, later.Add(time.Minute), later); !ok {
		t.Fatal("expired capacity not reclaimed")
	}
	if ok, dup := s.mark(a, subj, later.Add(time.Minute), later); ok || dup {
		t.Fatal("full set accepted a re-mark")
	}
	// b expires at +20 s; a can take its slot afterwards.
	if ok, _ := s.mark(a, subj, now.Add(90*time.Second), now.Add(20*time.Second)); !ok {
		t.Fatal("slot of an expired mark not reused")
	}
	if len(s.m) != 2 || len(s.h) != 2 || s.subjects[subj] != 2 {
		t.Fatalf("unexpected state %d/%d/%d", len(s.m), len(s.h), s.subjects[subj])
	}
	if !s.seen(a, now.Add(30*time.Second)) || s.seen(a, now.Add(91*time.Second)) || len(s.subjects) != 0 {
		t.Fatal("subject accounting not released on expiry")
	}

	// One subject cannot use more than its share.
	q := &statusMarks{limit: 100, perSubject: 2}
	var x, y [16]byte
	y[0] = 1
	for i, tag := range [][32]byte{replayTag("1"), replayTag("2")} {
		if ok, _ := q.mark(tag, x, now.Add(time.Minute), now); !ok {
			t.Fatalf("mark %d", i)
		}
	}
	if ok, dup := q.mark(replayTag("3"), x, now.Add(time.Minute), now); ok || dup {
		t.Fatal("subject exceeded its share")
	}
	if ok, _ := q.mark(replayTag("3"), y, now.Add(time.Minute), now); !ok {
		t.Fatal("another subject blocked by the first one's share")
	}

	var d statusMarks // zero value uses the default bounds
	if ok, _ := d.mark(a, subj, now.Add(time.Second), now); !ok {
		t.Fatal("zero value unusable")
	}
}

// A subject that floods refusals uses up only its own share: another
// subject's refusal is still answered, and the flooder is not locked out of
// permitted admissions by the per-address handshake guard.
func TestRefusalFloodDoesNotSilenceOtherSubjects(t *testing.T) {
	store := &capacityStore{limit: 100}
	e := newEnv(t, envOpt{tok: &Token{Caps: CapTCP, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)},
		mutate: func(c *ServerConfig) {
			c.ReplayStore = store
			c.FlightIdle = 5 * time.Millisecond
			c.HandshakeTimeout = 300 * time.Millisecond
		}})
	e.srv.statusMarks.perSubject = 2
	for i := 0; i < 2; i++ {
		flight, hs := flightFor(t, e, CmdUDP, "udp:0", nil)
		if st, ok := exchange(t, e.addr, flight, hs); !ok || st != StatusCapDenied {
			t.Fatalf("refusal %d: %v %v", i, st, ok)
		}
	}
	flight, hs := flightFor(t, e, CmdUDP, "udp:0", nil)
	if st, ok := exchange(t, e.addr, flight, hs); ok {
		t.Fatalf("flooding subject exceeded its share: %v", st)
	}
	other := issueFor(t, e, CapTCP)
	flight, hs = flightFor(t, e, CmdUDP, "udp:0", other)
	if st, ok := exchange(t, e.addr, flight, hs); !ok || st != StatusCapDenied {
		t.Fatalf("other subject's refusal silenced: %v %v", st, ok)
	}
	if store.calls.Load() != 0 {
		t.Fatal("refusals used the durable store")
	}
	flight, hs = flightFor(t, e, CmdTCP, echoServer(t, ""), nil)
	if st, ok := exchange(t, e.addr, flight, hs); !ok || st != StatusOK {
		t.Fatalf("permitted flight after quota overflow: %v %v", st, ok)
	}
}

// Two processes sharing keys, store and (as required) destination policy: a
// replayed refused flight is never executed by either, and a replayed
// permitted flight goes to the fallback on both.
func TestRefusedReplayAcrossProcessesNeverExecutes(t *testing.T) {
	var dialed atomic.Int32
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			dialed.Add(1)
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	blocked := uint16(ln.Addr().(*net.TCPAddr).Port)
	site, _ := fallbackSite(t)
	e := newEnv(t, envOpt{fallback: site, mutate: func(c *ServerConfig) {
		c.FlightIdle = 5 * time.Millisecond
		c.BlockedPorts = []uint16{blocked}
	}})
	cfg := auditFreshInstanceConfig(t, e.srv.cfg)
	other := auditServe(t, cfg)
	time.Sleep(1100 * time.Millisecond) // the second process just started

	a, err := ParseAddr(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	flight, hs, err := buildFirstFlight(e.key.Public(), e.device, &request{ts: time.Now(), cmd: CmdTCP, dst: a, token: e.profile.Token, early: []byte("EHLO")}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if st, ok := exchange(t, e.addr, flight, hs); !ok || st != StatusForbiddenDest {
		t.Fatalf("refusal: %v %v", st, ok)
	}
	if st, ok := exchange(t, e.addr, flight, hs); ok {
		t.Fatalf("same-process replay answered: %v", st)
	}
	if st, ok := exchange(t, other, flight, hs); ok && st != StatusForbiddenDest {
		t.Fatalf("sibling process answered a refused replay with %v", st)
	}
	if dialed.Load() != 0 {
		t.Fatal("a refused flight reached its destination")
	}

	echo := echoServer(t, "")
	flight, hs = flightFor(t, e, CmdTCP, echo, nil)
	if st, ok := exchange(t, e.addr, flight, hs); !ok || st != StatusOK {
		t.Fatalf("permitted control: %v %v", st, ok)
	}
	if st, ok := exchange(t, other, flight, hs); ok {
		t.Fatalf("permitted flight replayed on the sibling process: %v", st)
	}
}
