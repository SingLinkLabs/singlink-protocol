// Package singlink implements the SingLink Protocol protocol (wire name "SingLink/1").
//
// SingLink is a stream proxy protocol in the VLESS / Trojan family: a client sends
// one request at the start of a TLS (or raw TCP) connection and the server
// relays the stream to the requested destination. Compared with VLESS it adds:
//
//   - an inner hybrid key exchange (X25519 + ML-KEM-768), so the payload stays
//     encrypted end to end even when the outer TLS is terminated by a CDN or
//     load balancer, and stays confidential against "harvest now, decrypt
//     later" quantum attacks;
//   - signed permission tokens (Ed25519) instead of a shared UUID, so every
//     node can authorise users, plans and capabilities without a user
//     database, and a token leaked from one node is useless without the
//     device key it is bound to;
//   - silent fallback to a real website for anything that does not
//     authenticate, plus replay protection and length padding.
//
// See SPEC.md in the repository root for the normative description.
package singlink

import (
	"errors"
	"fmt"
)

const (
	// Version is the implementation version.
	Version = "1.0.0-draft"
	// ProtocolName is the wire protocol identifier.
	ProtocolName = "SingLink/1"

	wireVersion = 1
	label       = "SingLink/1"
)

const (
	x25519Len  = 32
	mlkemEKLen = 1184
	mlkemCTLen = 1088
	tagLen     = 16
	lenBlock   = 2 + tagLen

	// firstFlightFixed is the fixed-size prefix of the client's first flight:
	// E || CT || sealed(header length).
	firstFlightFixed = x25519Len + mlkemCTLen + lenBlock

	// MaxEarlyData is the largest payload a client may send inside its first flight.
	MaxEarlyData = 8 * 1024
	maxFrameData = 16 * 1024
	maxFramePad  = 1024
	maxBodyLen   = 3 + maxFrameData + maxFramePad
	maxHeaderLen = 16 * 1024
)

// Cmd is the request command carried in the client header.
type Cmd byte

const (
	CmdTCP Cmd = 1 // relay a TCP stream
	CmdUDP Cmd = 2 // relay UDP datagrams over the stream
)

// Capability bits carried in permission tokens.
const (
	CapTCP uint32 = 1 << 0
	CapUDP uint32 = 1 << 1
)

type frameType byte

const (
	frameData    frameType = 0
	framePadding frameType = 1
	frameEOF     frameType = 2
	frameUDP     frameType = 3
	frameStatus  frameType = 4
)

// Status is the server's answer to an authenticated request.
type Status byte

const (
	StatusOK            Status = 0
	StatusTokenExpired  Status = 1
	StatusTokenRevoked  Status = 2
	StatusNotYetValid   Status = 3
	StatusForbiddenDest Status = 4
	StatusCapDenied     Status = 5
	StatusTooManyConns  Status = 6
	StatusDialFailed    Status = 7
	StatusBadRequest    Status = 8
)

func (s Status) String() string {
	switch s {
	case StatusOK:
		return "ok"
	case StatusTokenExpired:
		return "token expired"
	case StatusTokenRevoked:
		return "token revoked"
	case StatusNotYetValid:
		return "token not yet valid"
	case StatusForbiddenDest:
		return "destination forbidden"
	case StatusCapDenied:
		return "capability not granted by token"
	case StatusTooManyConns:
		return "too many concurrent connections"
	case StatusDialFailed:
		return "server could not reach destination"
	case StatusBadRequest:
		return "bad request"
	}
	return fmt.Sprintf("status %d", byte(s))
}

// StatusError is returned to a client whose request the server refused.
type StatusError struct {
	Code Status
	Msg  string
}

func (e *StatusError) Error() string {
	if e.Msg != "" {
		return "singlink: " + e.Code.String() + ": " + e.Msg
	}
	return "singlink: " + e.Code.String()
}

var (
	errBadFrame   = errors.New("singlink: malformed frame")
	errNonceLimit = errors.New("singlink: nonce space exhausted")
	errProbe      = errors.New("singlink: unauthenticated connection")
)
