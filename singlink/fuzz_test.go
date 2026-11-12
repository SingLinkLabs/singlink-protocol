// Copyright 2026 SingLinkLabs (https://github.com/SingLinkLabs)
// SPDX-License-Identifier: Apache-2.0

package singlink

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"
)

func fuzzToken() (ed25519.PrivateKey, ed25519.PrivateKey, []byte) {
	iss, _ := GenerateEd25519()
	dev, _ := GenerateEd25519()
	tok, _ := IssueToken(iss, &Token{DevicePub: dev.Public().(ed25519.PublicKey), NotBefore: time.Unix(0, 0), NotAfter: time.Unix(1<<40, 0)})
	return iss, dev, tok
}

func FuzzDecodeAddr(f *testing.F) {
	f.Add([]byte{1, 127, 0, 0, 1, 0, 80})
	f.Add([]byte{3, 3, 'a', 'b', 'c', 1, 187})
	f.Add(append([]byte{4}, make([]byte, 18)...))
	f.Fuzz(func(t *testing.T, b []byte) {
		a, rest, err := decodeAddr(b)
		if err != nil {
			return
		}
		if enc := a.appendTo(nil); !bytes.Equal(append(enc, rest...), b) && !(b[0] == atypIPv6 && a.IP.Is4()) {
			t.Fatalf("round trip %x -> %x", b, enc)
		}
	})
}

func FuzzParseHeader(f *testing.F) {
	_, _, tok := fuzzToken()
	h := Addr{Host: "example.com", Port: 443}.appendTo([]byte{wireVersion, 0, 0, 0, 0, 0, 0, 0, 1, 1})
	h = append(append(h, byte(len(tok)>>8), byte(len(tok))), tok...)
	h = append(h, 0, 2, 'h', 'i', 0, 1, 0)
	h = append(h, make([]byte, 64)...)
	f.Add(h)
	f.Fuzz(func(t *testing.T, b []byte) {
		var hs serverHandshake
		if hs.parseHeader(b) == nil && (len(hs.req.early) > MaxEarlyData || len(hs.sig) != 64 || len(hs.signed)+64 != len(b)) {
			t.Fatal("invariant")
		}
	})
}

func FuzzParseToken(f *testing.F) {
	iss, _, tok := fuzzToken()
	is := NewIssuers(iss.Public().(ed25519.PublicKey))
	f.Add(tok)
	f.Fuzz(func(t *testing.T, b []byte) {
		ParseToken(b)
		if _, err := is.Verify(b); err == nil && !bytes.Equal(b, tok) {
			t.Fatalf("forged token accepted")
		}
	})
}

func FuzzParseLink(f *testing.F) {
	key, _ := GenerateServerKey()
	_, dev, tok := fuzzToken()
	f.Add((&Profile{Name: "n", Server: "example.com:443", ServerKey: key.Public(), Token: tok, Device: dev, SNI: "x"}).Link())
	f.Add("singlink://a.b@[::1]:1?pk=&tr=tcp")
	f.Fuzz(func(t *testing.T, s string) { ParseLink(s) })
}

func FuzzParseFirstFlight(f *testing.F) {
	key, _ := GenerateServerKey()
	_, dev, tok := fuzzToken()
	fl, _, _ := buildFirstFlight(key.Public(), dev, &request{ts: time.Now(), cmd: CmdTCP, dst: Addr{Host: "example.com", Port: 443}, token: tok, early: []byte("hi")}, 16)
	f.Add(fl)
	f.Add([]byte("GET / HTTP/1.1\r\n\r\n"))
	keys := []*ServerPrivateKey{key}
	f.Fuzz(func(t *testing.T, b []byte) {
		if hs, err := parseFirstFlight(b, keys); err == nil {
			hs.verifyPoP(dev.Public().(ed25519.PublicKey))
		}
	})
}

func FuzzReadFrame(f *testing.F) {
	key := make([]byte, 32)
	f.Add([]byte{0, 0, 5, 'h', 'e', 'l', 'l', 'o'}, uint16(8))
	f.Fuzz(func(t *testing.T, body []byte, claimed uint16) {
		w, _ := newCipherState(key)
		r, _ := newCipherState(key)
		out, _ := w.seal(nil, []byte{byte(claimed >> 8), byte(claimed)})
		out, _ = w.seal(out, body)
		_, data, err := (&frameReader{r: bytes.NewReader(out), cs: r}).readFrame()
		if err == nil && len(data) > maxFrameData+maxFramePad {
			t.Fatal("oversized frame accepted")
		}
	})
}
