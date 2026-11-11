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
	"io"
	"time"
)

// Handshake (Noise "NK"-like, one round trip, 0-RTT request):
//
//	C -> S  E || CT || seal_ek(len) || seal_ek(header)
//	S -> C  F || frames sealed with s2c
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
//	ver(1) ts(8) cmd(1) addr tokenLen(2) token sig(64) earlyLen(2) early padLen(2) pad
//
// sig = Ed25519(device, SHA256("SingLink pop" || salt || ver..token)) proves that
// the sender holds the device key the token was issued to.

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

// x25519Wire clears the top bit that clients randomise on the wire.
func x25519Wire(b []byte) (*ecdh.PublicKey, error) {
	k := append([]byte{}, b...)
	k[31] &= 0x7f
	return ecdh.X25519().NewPublicKey(k)
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
		var r [1]byte
		rand.Read(r[:])
		E[31] |= r[0] & 0x80 // hide the always-zero top bit
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

	// Header.
	h := make([]byte, 0, 256+len(req.token)+len(req.early)+padMax)
	h = append(h, wireVersion)
	h = binary.BigEndian.AppendUint64(h, uint64(req.ts.Unix()))
	h = append(h, byte(req.cmd))
	h = req.dst.appendTo(h)
	h = binary.BigEndian.AppendUint16(h, uint16(len(req.token)))
	h = append(h, req.token...)
	sig := ed25519.Sign(device, hash([]byte("SingLink pop"), salt, h))
	h = append(h, sig...)
	h = binary.BigEndian.AppendUint16(h, uint16(len(req.early)))
	h = append(h, req.early...)
	pad := randInt(padMax + 1)
	h = binary.BigEndian.AppendUint16(h, uint16(pad))
	h = append(h, make([]byte, pad)...)
	if len(h) > maxHeaderLen {
		return nil, nil, errors.New("singlink: request header too large")
	}

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
	fpub, err := x25519Wire(F)
	if err != nil {
		return nil, nil, err
	}
	ee, err := hs.e.ECDH(fpub)
	if err != nil {
		return nil, nil, err
	}
	return trafficKeys(hs.secret, ee, hs.salt, F, hs.hashH)
}

// recorder keeps every byte read during the handshake so an unauthenticated
// connection can be replayed verbatim to the fallback server.
type recorder struct {
	r   io.Reader
	buf []byte
}

func (rc *recorder) Read(p []byte) (int, error) {
	n, err := rc.r.Read(p)
	rc.buf = append(rc.buf, p[:n]...)
	return n, err
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

// readFirstFlight decrypts and parses a client's first flight. Any error
// means the peer must be treated as unauthenticated.
func readFirstFlight(r io.Reader, key *ServerPrivateKey) (*serverHandshake, error) {
	fixed := make([]byte, firstFlightFixed)
	if _, err := io.ReadFull(r, fixed[:4]); err != nil {
		return nil, err
	}
	if looksLikePlaintext(fixed[:4]) {
		return nil, errProbe
	}
	if _, err := io.ReadFull(r, fixed[4:]); err != nil {
		return nil, err
	}
	E := fixed[:x25519Len]
	ct := fixed[x25519Len : x25519Len+mlkemCTLen]
	epub, err := x25519Wire(E)
	if err != nil {
		return nil, errProbe
	}
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
	if _, err := cs.open(l[:0], fixed[x25519Len+mlkemCTLen:]); err != nil {
		return nil, errProbe
	}
	hl := int(binary.BigEndian.Uint16(l[:]))
	if hl > maxHeaderLen {
		return nil, errProbe
	}
	sealed := make([]byte, hl+tagLen)
	if _, err := io.ReadFull(r, sealed); err != nil {
		return nil, err
	}
	hashH := hash(fixed[x25519Len+mlkemCTLen:], sealed)
	h, err := cs.open(nil, sealed)
	if err != nil {
		return nil, errProbe
	}
	hs := &serverHandshake{E: append([]byte{}, E...), secret: secret, salt: salt, hashH: hashH}
	if err := hs.parseHeader(h); err != nil {
		return nil, errProbe
	}
	return hs, nil
}

func (hs *serverHandshake) parseHeader(h []byte) error {
	full := h
	if len(h) < 1+8+1 || h[0] != wireVersion {
		return errBadFrame
	}
	hs.req.ts = time.Unix(int64(binary.BigEndian.Uint64(h[1:9])), 0)
	hs.req.cmd = Cmd(h[9])
	dst, rest, err := decodeAddr(h[10:])
	if err != nil {
		return err
	}
	hs.req.dst = dst
	if len(rest) < 2 {
		return errBadFrame
	}
	tl := int(binary.BigEndian.Uint16(rest))
	rest = rest[2:]
	if len(rest) < tl+ed25519.SignatureSize+2 {
		return errBadFrame
	}
	hs.req.token = rest[:tl]
	hs.signed = full[:len(full)-len(rest)+tl]
	hs.sig = rest[tl : tl+ed25519.SignatureSize]
	rest = rest[tl+ed25519.SignatureSize:]
	el := int(binary.BigEndian.Uint16(rest))
	rest = rest[2:]
	if len(rest) < el+2 || el > MaxEarlyData {
		return errBadFrame
	}
	hs.req.early = rest[:el]
	rest = rest[el:]
	pl := int(binary.BigEndian.Uint16(rest))
	if len(rest[2:]) != pl {
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
	epub, err := x25519Wire(hs.E)
	if err != nil {
		return nil, nil, nil, err
	}
	ee, err := f.ECDH(epub)
	if err != nil {
		return nil, nil, nil, err
	}
	F = f.PublicKey().Bytes()
	var r [1]byte
	rand.Read(r[:])
	F[31] |= r[0] & 0x80
	c2s, s2c, err = trafficKeys(hs.secret, ee, hs.salt, F, hs.hashH)
	return F, c2s, s2c, err
}
