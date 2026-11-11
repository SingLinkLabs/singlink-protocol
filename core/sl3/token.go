package sl3

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"time"
)

// Permission token layout (all integers big-endian):
//
//	off  len  field
//	0    1    version (1)
//	1    4    issuer key id
//	5    16   token id (for revocation)
//	21   16   subject (pseudonymous account id)
//	37   32   device public key (Ed25519), proof-of-possession key
//	69   8    not before (unix seconds)
//	77   8    not after  (unix seconds)
//	85   4    capability bits
//	89   4    rate limit, kbit/s per subject per node (0 = unlimited)
//	93   2    max concurrent connections per subject per node (0 = unlimited)
//	95   1    plan id (opaque to nodes)
//	96   64   Ed25519 signature over tokenSigCtx || bytes[0:96]
const (
	tokenVersion = 1
	tokenBodyLen = 96
	// TokenLen is the encoded size of a permission token.
	TokenLen    = tokenBodyLen + ed25519.SignatureSize
	tokenSigCtx = "SL3 token v1\x00"
)

// Token is a permission grant signed by an issuer (the account backend).
type Token struct {
	KeyID     uint32
	ID        [16]byte
	Subject   [16]byte
	DevicePub ed25519.PublicKey
	NotBefore time.Time
	NotAfter  time.Time
	Caps      uint32
	RateKbps  uint32
	MaxConns  uint16
	Plan      uint8

	raw []byte
}

// Raw returns the encoded token (only set for parsed or issued tokens).
func (t *Token) Raw() []byte { return t.raw }

// Has reports whether the token grants every bit in caps.
func (t *Token) Has(caps uint32) bool { return t.Caps&caps == caps }

// IssueToken signs t with issuer and returns the encoded token. KeyID is
// filled in from the issuer key and a random token ID is assigned if empty.
func IssueToken(issuer ed25519.PrivateKey, t *Token) ([]byte, error) {
	if len(t.DevicePub) != ed25519.PublicKeySize {
		return nil, errors.New("sl3: token needs a device public key")
	}
	if !t.NotAfter.After(t.NotBefore) {
		return nil, errors.New("sl3: token NotAfter must be after NotBefore")
	}
	t.KeyID = IssuerKeyID(issuer.Public().(ed25519.PublicKey))
	if t.ID == ([16]byte{}) {
		if _, err := rand.Read(t.ID[:]); err != nil {
			return nil, err
		}
	}
	b := make([]byte, TokenLen)
	b[0] = tokenVersion
	binary.BigEndian.PutUint32(b[1:5], t.KeyID)
	copy(b[5:21], t.ID[:])
	copy(b[21:37], t.Subject[:])
	copy(b[37:69], t.DevicePub)
	binary.BigEndian.PutUint64(b[69:77], uint64(t.NotBefore.Unix()))
	binary.BigEndian.PutUint64(b[77:85], uint64(t.NotAfter.Unix()))
	binary.BigEndian.PutUint32(b[85:89], t.Caps)
	binary.BigEndian.PutUint32(b[89:93], t.RateKbps)
	binary.BigEndian.PutUint16(b[93:95], t.MaxConns)
	b[95] = t.Plan
	sig := ed25519.Sign(issuer, append([]byte(tokenSigCtx), b[:tokenBodyLen]...))
	copy(b[tokenBodyLen:], sig)
	t.raw = b
	return b, nil
}

// ParseToken decodes a token WITHOUT checking its signature.
func ParseToken(b []byte) (*Token, error) {
	if len(b) != TokenLen || b[0] != tokenVersion {
		return nil, errors.New("sl3: malformed token")
	}
	t := &Token{
		KeyID:     binary.BigEndian.Uint32(b[1:5]),
		DevicePub: ed25519.PublicKey(append([]byte{}, b[37:69]...)),
		NotBefore: time.Unix(int64(binary.BigEndian.Uint64(b[69:77])), 0),
		NotAfter:  time.Unix(int64(binary.BigEndian.Uint64(b[77:85])), 0),
		Caps:      binary.BigEndian.Uint32(b[85:89]),
		RateKbps:  binary.BigEndian.Uint32(b[89:93]),
		MaxConns:  binary.BigEndian.Uint16(b[93:95]),
		Plan:      b[95],
		raw:       append([]byte{}, b...),
	}
	copy(t.ID[:], b[5:21])
	copy(t.Subject[:], b[21:37])
	return t, nil
}

// Issuers is the set of issuer public keys a node trusts, by key id.
type Issuers map[uint32]ed25519.PublicKey

// NewIssuers builds an Issuers set from public keys.
func NewIssuers(keys ...ed25519.PublicKey) Issuers {
	is := Issuers{}
	for _, k := range keys {
		is[IssuerKeyID(k)] = k
	}
	return is
}

// Verify parses b and checks its signature against a trusted issuer. It does
// not check validity times; callers do that so they can report the reason.
func (is Issuers) Verify(b []byte) (*Token, error) {
	t, err := ParseToken(b)
	if err != nil {
		return nil, err
	}
	pub, ok := is[t.KeyID]
	if !ok {
		return nil, errors.New("sl3: unknown token issuer")
	}
	if !ed25519.Verify(pub, append([]byte(tokenSigCtx), b[:tokenBodyLen]...), b[tokenBodyLen:]) {
		return nil, errors.New("sl3: bad token signature")
	}
	return t, nil
}
