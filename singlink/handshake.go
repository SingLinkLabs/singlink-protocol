package singlink

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"time"
)

// Handshake (Noise "NK"-like, one round trip, 0-RTT request):
//
//	C -> S  E || CT || seal_ek(len) || seal_ek(header)        (one TLS record)
//	S -> C  F || frames sealed with s2c                       (one write, first frame STATUS)
//
//	ss_x  = X25519(e, S_x)          ss_pq = ML-KEM-768 shared secret (CT to S_kem)
//	salt  = SHA256(label || "salt" || server_id || E || CT)
//	ek    = HKDF(ss_x || ss_pq, salt, "singlink early")
//	ee    = X25519(f, E)
//	tsalt = SHA256(label || "traffic" || salt || F || SHA256(sealed header))
//	c2s, s2c = HKDF(ss_x || ss_pq || ee, tsalt, "singlink c2s" / "singlink s2c")
//
// Header plaintext:
//
//	ver(1) ts(8) cmd(1) addr tokenLen(2) token earlyLen(2) early padLen(2) pad sig(64)
//
// sig = Ed25519(device, SHA256("SingLink pop" || salt || header without sig))
// proves that the sender holds the device key the token was issued to, and
// binds every header field (including early data) to that device.

// maxFlightLen is the largest first flight. Over TLS it MUST fit in one
// record, so the node can judge a connection from a single read.
const maxFlightLen = 16 * 1024

// plaintextPrefixes are first bytes of protocols a prober is likely to send.
// Clients never produce an ephemeral key that starts with one of them, so a
// server can hand such connections to the fallback without waiting.
var plaintextPrefixes = [][]byte{
	[]byte("GET "), []byte("POST"), []byte("HEAD"), []byte("PUT "), []byte("OPTI"),
	[]byte("DELE"), []byte("PATC"), []byte("TRAC"), []byte("CONN"), []byte("PRI "),
	{0x16, 0x03}, // TLS handshake record
	[]byte("SSH-"),
}

func looksLikePlaintext(b []byte) bool {
	for _, p := range plaintextPrefixes {
		if len(b) >= len(p) && bytes.Equal(b[:len(p)], p) {
			return true
		}
	}
	return false
}

func hash(parts ...[]byte) []byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

func deriveKey(secret, salt []byte, info string) ([]byte, error) {
	return hkdf.Key(sha256.New, secret, salt, info, 32)
}

type request struct {
	ts    time.Time
	cmd   Cmd
	dst   Addr
	token []byte
	early []byte
}

// clientHandshake holds the client's state between the two flights.
type clientHandshake struct {
	e      *ecdh.PrivateKey
	secret []byte // ss_x || ss_pq
	salt   []byte
	hashH  []byte
}

func buildFirstFlight(spk *ServerPublicKey, device ed25519.PrivateKey, req *request, padMax int) ([]byte, *clientHandshake, error) {
	var e *ecdh.PrivateKey
	var E []byte
	for {
		var err error
		e, err = ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		E = e.PublicKey().Bytes()
		if !looksLikePlaintext(E) {
			break
		}
	}
	ssx, err := e.ECDH(spk.x)
	if err != nil {
		return nil, nil, err
	}
	sspq, ct := spk.kem.Encapsulate()
	secret := append(append([]byte{}, ssx...), sspq...)
	salt := hash([]byte(label), []byte("salt"), spk.id[:], E, ct)
	ek, err := deriveKey(secret, salt, "singlink early")
	if err != nil {
		return nil, nil, err
	}

	h := make([]byte, 0, 512+len(req.token)+len(req.early)+padMax)
	h = append(h, wireVersion)
	h = binary.BigEndian.AppendUint64(h, uint64(req.ts.Unix()))
	h = append(h, byte(req.cmd))
	h = req.dst.appendTo(h)
	h = binary.BigEndian.AppendUint16(h, uint16(len(req.token)))
	h = append(h, req.token...)
	h = binary.BigEndian.AppendUint16(h, uint16(len(req.early)))
	h = append(h, req.early...)
	room := maxHeaderLen - len(h) - 2 - ed25519.SignatureSize
	if room < 0 {
		return nil, nil, errors.New("singlink: request header too large")
	}
	pad := randInt(min(padMax, room) + 1)
	h = binary.BigEndian.AppendUint16(h, uint16(pad))
	h = append(h, make([]byte, pad)...)
	h = append(h, ed25519.Sign(device, hash([]byte("SingLink pop"), salt, h))...)

	cs, err := newCipherState(ek)
	if err != nil {
		return nil, nil, err
	}
	out := make([]byte, 0, firstFlightFixed+len(h)+tagLen)
	out = append(out, E...)
	out = append(out, ct...)
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(h)))
	if out, err = cs.seal(out, l[:]); err != nil {
		return nil, nil, err
	}
	sealedStart := len(out) - lenBlock
	if out, err = cs.seal(out, h); err != nil {
		return nil, nil, err
	}
	return out, &clientHandshake{e: e, secret: secret, salt: salt, hashH: hash(out[sealedStart:])}, nil
}

// trafficKeys derives the two directional keys once F is known.
func trafficKeys(secret, ee, salt, F, hashH []byte) (c2s, s2c *cipherState, err error) {
	full := append(append([]byte{}, secret...), ee...)
	tsalt := hash([]byte(label), []byte("traffic"), salt, F, hashH)
	kc, err := deriveKey(full, tsalt, "singlink c2s")
	if err != nil {
		return nil, nil, err
	}
	ks, err := deriveKey(full, tsalt, "singlink s2c")
	if err != nil {
		return nil, nil, err
	}
	if c2s, err = newCipherState(kc); err != nil {
		return nil, nil, err
	}
	s2c, err = newCipherState(ks)
	return c2s, s2c, err
}

// finish completes the client side after reading the server's F.
func (hs *clientHandshake) finish(F []byte) (c2s, s2c *cipherState, err error) {
	fpub, err := ecdh.X25519().NewPublicKey(F)
	if err != nil {
		return nil, nil, err
	}
	ee, err := hs.e.ECDH(fpub)
	if err != nil {
		return nil, nil, err
	}
	return trafficKeys(hs.secret, ee, hs.salt, F, hs.hashH)
}

// readFlight collects a client's first flight without ever blocking on a
// length taken from the data, so every non-client looks the same in time.
//
// Over TLS the flight is one record and a single Read returns all of it.
// Over raw TCP bytes are gathered until the stream is idle for idle.
func readFlight(c net.Conn, isTLS bool, first, idle time.Duration) ([]byte, error) {
	buf := make([]byte, maxFlightLen)
	c.SetReadDeadline(time.Now().Add(first))
	n, err := c.Read(buf)
	if n == 0 || isTLS || looksLikePlaintext(buf[:min(n, 4)]) {
		return buf[:n], err
	}
	for n < len(buf) && err == nil {
		c.SetReadDeadline(time.Now().Add(idle))
		var m int
		m, err = c.Read(buf[n:])
		n += m
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		err = nil
	}
	return buf[:n], err
}

// serverHandshake is the result of a successfully decrypted first flight.
type serverHandshake struct {
	req    request
	sig    []byte
	signed []byte // header bytes covered by sig
	E      []byte
	secret []byte
	salt   []byte
	hashH  []byte
}

// parseFirstFlight decrypts a complete first flight with one of keys (the
// current key first, then keys kept for rotation). Any error means the peer
// must be treated as unauthenticated.
func parseFirstFlight(b []byte, keys []*ServerPrivateKey) (*serverHandshake, error) {
	if len(b) < firstFlightFixed || looksLikePlaintext(b[:4]) {
		return nil, errProbe
	}
	E := b[:x25519Len]
	ct := b[x25519Len : x25519Len+mlkemCTLen]
	sealedLen := b[x25519Len+mlkemCTLen : firstFlightFixed]
	epub, err := ecdh.X25519().NewPublicKey(E)
	if err != nil {
		return nil, errProbe
	}
	for _, key := range keys {
		ssx, err := key.x.ECDH(epub)
		if err != nil {
			return nil, errProbe
		}
		sspq, err := key.kem.Decapsulate(ct)
		if err != nil {
			return nil, errProbe
		}
		secret := append(append([]byte{}, ssx...), sspq...)
		salt := hash([]byte(label), []byte("salt"), key.pub.id[:], E, ct)
		ek, err := deriveKey(secret, salt, "singlink early")
		if err != nil {
			return nil, err
		}
		cs, err := newCipherState(ek)
		if err != nil {
			return nil, err
		}
		var l [2]byte
		if _, err := cs.open(l[:0], sealedLen); err != nil {
			continue // not this key
		}
		hl := int(binary.BigEndian.Uint16(l[:]))
		if hl > maxHeaderLen || len(b) != firstFlightFixed+hl+tagLen {
			return nil, errProbe
		}
		sealed := b[firstFlightFixed:]
		h, err := cs.open(nil, sealed)
		if err != nil {
			return nil, errProbe
		}
		hs := &serverHandshake{E: append([]byte{}, E...), secret: secret, salt: salt, hashH: hash(sealedLen, sealed)}
		if err := hs.parseHeader(h); err != nil {
			return nil, errProbe
		}
		return hs, nil
	}
	return nil, errProbe
}

func (hs *serverHandshake) parseHeader(h []byte) error {
	if len(h) < 1+8+1+ed25519.SignatureSize || h[0] != wireVersion {
		return errBadFrame
	}
	hs.signed = h[:len(h)-ed25519.SignatureSize]
	hs.sig = h[len(h)-ed25519.SignatureSize:]
	b := hs.signed
	hs.req.ts = time.Unix(int64(binary.BigEndian.Uint64(b[1:9])), 0)
	hs.req.cmd = Cmd(b[9])
	dst, rest, err := decodeAddr(b[10:])
	if err != nil {
		return err
	}
	hs.req.dst = dst
	field := func() ([]byte, error) {
		if len(rest) < 2 {
			return nil, errBadFrame
		}
		n := int(binary.BigEndian.Uint16(rest))
		if len(rest) < 2+n {
			return nil, errBadFrame
		}
		f := rest[2 : 2+n]
		rest = rest[2+n:]
		return f, nil
	}
	if hs.req.token, err = field(); err != nil {
		return err
	}
	if hs.req.early, err = field(); err != nil {
		return err
	}
	if len(hs.req.early) > MaxEarlyData {
		return errBadFrame
	}
	if _, err = field(); err != nil { // padding
		return err
	}
	if len(rest) != 0 {
		return errBadFrame
	}
	return nil
}

// verifyPoP checks the device signature against the token's device key.
func (hs *serverHandshake) verifyPoP(devicePub ed25519.PublicKey) bool {
	return ed25519.Verify(devicePub, hash([]byte("SingLink pop"), hs.salt, hs.signed), hs.sig)
}

// accept generates the server ephemeral key and returns F plus traffic keys.
func (hs *serverHandshake) accept() (F []byte, c2s, s2c *cipherState, err error) {
	f, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	epub, err := ecdh.X25519().NewPublicKey(hs.E)
	if err != nil {
		return nil, nil, nil, err
	}
	ee, err := f.ECDH(epub)
	if err != nil {
		return nil, nil, nil, err
	}
	F = f.PublicKey().Bytes()
	c2s, s2c, err = trafficKeys(hs.secret, ee, hs.salt, F, hs.hashH)
	return F, c2s, s2c, err
}
