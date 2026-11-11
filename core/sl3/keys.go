package sl3

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
)

// B64 is the encoding used for every key, token and link component.
var B64 = base64.RawURLEncoding

const (
	serverPrivLen = 32 + 64                // X25519 scalar || ML-KEM-768 seed
	serverPubLen  = x25519Len + mlkemEKLen // 1216
)

// ServerPublicKey is what clients need to reach a node: an X25519 public key
// and an ML-KEM-768 encapsulation key.
type ServerPublicKey struct {
	x   *ecdh.PublicKey
	kem *mlkem.EncapsulationKey768
	raw []byte
	id  [32]byte // SHA-256(label || raw), binds handshakes to this key
}

// ServerPrivateKey is the node's long-term static key.
type ServerPrivateKey struct {
	x   *ecdh.PrivateKey
	kem *mlkem.DecapsulationKey768
	pub *ServerPublicKey
}

// GenerateServerKey creates a fresh hybrid server key.
func GenerateServerKey() (*ServerPrivateKey, error) {
	b := make([]byte, serverPrivLen)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return ParseServerPrivateKey(b)
}

// ParseServerPrivateKey decodes the 96-byte private key encoding.
func ParseServerPrivateKey(b []byte) (*ServerPrivateKey, error) {
	if len(b) != serverPrivLen {
		return nil, errors.New("sl3: server private key must be 96 bytes")
	}
	x, err := ecdh.X25519().NewPrivateKey(b[:32])
	if err != nil {
		return nil, err
	}
	kem, err := mlkem.NewDecapsulationKey768(b[32:])
	if err != nil {
		return nil, err
	}
	raw := append(append([]byte{}, x.PublicKey().Bytes()...), kem.EncapsulationKey().Bytes()...)
	pub, err := ParseServerPublicKey(raw)
	if err != nil {
		return nil, err
	}
	return &ServerPrivateKey{x: x, kem: kem, pub: pub}, nil
}

// Bytes returns the 96-byte private key encoding.
func (k *ServerPrivateKey) Bytes() []byte {
	return append(append([]byte{}, k.x.Bytes()...), k.kem.Bytes()...)
}

// Public returns the matching public key.
func (k *ServerPrivateKey) Public() *ServerPublicKey { return k.pub }

// ParseServerPublicKey decodes the 1216-byte public key encoding.
func ParseServerPublicKey(b []byte) (*ServerPublicKey, error) {
	if len(b) != serverPubLen {
		return nil, errors.New("sl3: server public key must be 1216 bytes")
	}
	x, err := ecdh.X25519().NewPublicKey(b[:x25519Len])
	if err != nil {
		return nil, err
	}
	kem, err := mlkem.NewEncapsulationKey768(b[x25519Len:])
	if err != nil {
		return nil, err
	}
	p := &ServerPublicKey{x: x, kem: kem, raw: append([]byte{}, b...)}
	h := sha256.New()
	h.Write([]byte(label))
	h.Write(p.raw)
	copy(p.id[:], h.Sum(nil))
	return p, nil
}

// Bytes returns the 1216-byte public key encoding.
func (p *ServerPublicKey) Bytes() []byte { return append([]byte{}, p.raw...) }

// GenerateEd25519 returns a new Ed25519 key, used for issuers and devices.
func GenerateEd25519() (ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	return priv, err
}

// Ed25519FromSeed rebuilds an Ed25519 key from its 32-byte seed.
func Ed25519FromSeed(seed []byte) (ed25519.PrivateKey, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("sl3: ed25519 seed must be 32 bytes")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// IssuerKeyID derives the 32-bit key id that tokens use to name their issuer.
func IssuerKeyID(pub ed25519.PublicKey) uint32 {
	h := sha256.Sum256(append([]byte(label+" issuer "), pub...))
	return binary.BigEndian.Uint32(h[:4])
}
