// Copyright 2026 SingLinkVPN (https://singlinkvpn.com)
// SPDX-License-Identifier: Apache-2.0
package singlink

// Draft compatibility (re-audit 2026-11-17, P-R01). Draft 4 changed IDENT, so
// draft 3 and draft 4 peers derive different keys. A mismatched first flight
// must look exactly like any other probe to the node (byte-for-byte fallback,
// no version negotiation, no plaintext answer), while the client reports a
// clear, actionable error. Synthetic keys and loopback only.

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// draft3Identifier is the IDENT of spec draft 3, used only to build a
// mismatched test flight.
const draft3Identifier = "SingLink/1 by SingLinkLabs (singlinkvpn.com)"

// flightWithIdent builds a first flight like buildFirstFlight but with an
// arbitrary IDENT, to model a peer that speaks another draft.
func flightWithIdent(t *testing.T, ident string, spk *ServerPublicKey, device ed25519.PrivateKey, req *request) []byte {
	t.Helper()
	e, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	E := e.PublicKey().Bytes()
	ssx, err := e.ECDH(spk.x)
	if err != nil {
		t.Fatal(err)
	}
	sspq, ct := spk.kem.Encapsulate()
	salt := hash([]byte(ident), []byte("salt"), spk.id[:], E, ct)
	ek, err := deriveKey(append(append([]byte{}, ssx...), sspq...), salt, "singlink early")
	if err != nil {
		t.Fatal(err)
	}
	h := []byte{wireVersion}
	h = binary.BigEndian.AppendUint64(h, uint64(req.ts.Unix()))
	h = append(h, byte(req.cmd))
	h = req.dst.appendTo(h)
	h = binary.BigEndian.AppendUint16(h, uint16(len(req.token)))
	h = append(h, req.token...)
	h = binary.BigEndian.AppendUint16(h, 0) // early
	h = binary.BigEndian.AppendUint16(h, 0) // padding
	h = append(h, ed25519.Sign(device, hash([]byte("SingLink pop"), salt, h))...)
	cs, err := newCipherState(ek)
	if err != nil {
		t.Fatal(err)
	}
	out := append(append([]byte{}, E...), ct...)
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(h)))
	if out, err = cs.seal(out, l[:]); err != nil {
		t.Fatal(err)
	}
	if out, err = cs.seal(out, h); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestDraftConstantsAndDiagnostic(t *testing.T) {
	if SpecDraft != 4 || Identifier != "SingLink/1 by SingLinkVPN (singlinkvpn.com)" || wireVersion != 1 {
		t.Fatal("draft constants changed")
	}
	msg := ErrRejected.Error()
	for _, want := range []string{"handshake rejected", "protocol draft mismatch", "draft 4", "wrong server key", "clock"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("diagnostic %q lacks %q", msg, want)
		}
	}
}

// A draft 3 flight is indistinguishable from a probe: the node decrypts
// nothing, answers nothing itself, and hands every byte to the fallback.
func TestDraft3FlightGoesToFallbackUnchanged(t *testing.T) {
	site, got := fallbackSite(t)
	e := newEnv(t, envOpt{fallback: site, mutate: func(c *ServerConfig) { c.FlightIdle = 5 * time.Millisecond }})
	dst, _ := ParseAddr("192.0.2.1:443")
	req := &request{ts: time.Now(), cmd: CmdTCP, dst: dst, token: e.profile.Token}

	// Control: the same builder with the current IDENT is accepted.
	current := flightWithIdent(t, Identifier, e.key.Public(), e.device, req)
	if _, err := parseFirstFlight(current, e.srv.keys); err != nil {
		t.Fatal("current-draft control rejected:", err)
	}
	old := flightWithIdent(t, draft3Identifier, e.key.Public(), e.device, req)
	if _, err := parseFirstFlight(old, e.srv.keys); !errors.Is(err, errProbe) {
		t.Fatalf("draft 3 flight not treated as a probe: %v", err)
	}
	random := make([]byte, len(old))
	rand.Read(random)
	for name, flight := range map[string][]byte{"draft 3": old, "random": random} {
		c, err := net.Dial("tcp", e.addr)
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(3 * time.Second))
		c.Write(flight)
		reply, _ := io.ReadAll(c)
		c.Close()
		if !bytes.HasPrefix(reply, []byte("HTTP/1.1 200 OK")) {
			t.Fatalf("%s: answer did not come from the fallback: %q", name, reply)
		}
		select {
		case b := <-got:
			if len(b) < firstFlightFixed || !bytes.HasPrefix(flight, b) {
				t.Fatalf("%s: fallback did not receive the bytes unchanged", name)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("%s: nothing reached the fallback", name)
		}
	}
	if cs, ok := e.srv.replay.(*closingStore); ok {
		snap, err := cs.file.load()
		if err != nil || len(snap.entries) != 0 {
			t.Fatal("mismatched flights reached replay state")
		}
	}
}

// The client turns every "not a node of my draft and key" answer into the
// clear ErrRejected diagnostic, and keeps genuine status answers.
func TestClientReportsDraftOrKeyMismatch(t *testing.T) {
	other, err := GenerateServerKey()
	if err != nil {
		t.Fatal(err)
	}
	expectMismatch := func(name string, p *Profile) {
		t.Helper()
		c := NewClient(p)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := c.DialTCP(ctx, "192.0.2.1:443")
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		err = conn.Handshake()
		if !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "draft mismatch") {
			t.Fatalf("%s: got %v", name, err)
		}
		if !strings.Contains(c.LastError(), "draft mismatch") {
			t.Fatalf("%s: LastError %q", name, c.LastError())
		}
	}

	// Node with a website fallback, link with another node's key (the same
	// failure as a draft mismatch: the node cannot decrypt the flight).
	site, _ := fallbackSite(t)
	e := newEnv(t, envOpt{fallback: site, mutate: func(c *ServerConfig) { c.FlightIdle = 5 * time.Millisecond }})
	p := *e.profile
	p.ServerKey = other.Public()
	expectMismatch("fallback site", &p)

	// Node without a fallback: it drains and closes.
	e = newEnv(t, envOpt{mutate: func(c *ServerConfig) {
		c.FlightIdle = 5 * time.Millisecond
		c.HandshakeTimeout = 200 * time.Millisecond
	}})
	p = *e.profile
	p.ServerKey = other.Public()
	expectMismatch("no fallback", &p)

	// Something that answers with non-HTTP bytes of a plausible size.
	for _, n := range []int{x25519Len, x25519Len + lenBlock, 512} {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			c.Read(make([]byte, maxFlightLen))
			junk := make([]byte, n)
			rand.Read(junk)
			junk[0] = 0x80 // never "HTTP/"
			c.Write(junk)
		}()
		p = *e.profile
		p.Server = ln.Addr().String()
		expectMismatch("junk reply", &p)
		ln.Close()
	}

	// Control: a matching node still reports its real status.
	e = newEnv(t, envOpt{})
	expectStatus(t, dial(t, e, "127.0.0.1:25"), StatusForbiddenDest)
}
