package singlink

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// Profile is everything a client needs to use one node.
type Profile struct {
	Name      string
	Server    string // host:port
	Transport string // "tls" (default) or "tcp"
	SNI       string
	Pin       []byte // optional SHA-256 of the server certificate (DER)
	Insecure  bool   // skip certificate verification (testing only)
	ServerKey *ServerPublicKey
	Token     []byte
	Device    ed25519.PrivateKey
}

// Link encodes p as
//
//	singlink://<token>.<device-seed>@host:port?pk=<server-key>&tr=tls&sni=..&pin=..#name
//
// The link contains the device secret: treat it like a password.
func (p *Profile) Link() string {
	q := url.Values{}
	q.Set("pk", B64.EncodeToString(p.ServerKey.Bytes()))
	tr := p.Transport
	if tr == "" {
		tr = "tls"
	}
	q.Set("tr", tr)
	if p.SNI != "" {
		q.Set("sni", p.SNI)
	}
	if len(p.Pin) > 0 {
		q.Set("pin", B64.EncodeToString(p.Pin))
	}
	if p.Insecure {
		q.Set("insecure", "1")
	}
	u := url.URL{
		Scheme:   "singlink",
		User:     url.User(B64.EncodeToString(p.Token) + "." + B64.EncodeToString(p.Device.Seed())),
		Host:     p.Server,
		RawQuery: q.Encode(),
		Fragment: p.Name,
	}
	return u.String()
}

// ParseLink decodes an singlink:// link.
func ParseLink(s string) (*Profile, error) {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil {
		return nil, err
	}
	if u.Scheme != "singlink" {
		return nil, errors.New("singlink: link must start with singlink://")
	}
	if u.User == nil {
		return nil, errors.New("singlink: link has no credentials")
	}
	tokB64, devB64, ok := strings.Cut(u.User.Username(), ".")
	if !ok {
		return nil, errors.New("singlink: link credentials must be <token>.<device>")
	}
	p := &Profile{Name: u.Fragment, Server: u.Host}
	if _, _, err := net.SplitHostPort(p.Server); err != nil {
		return nil, fmt.Errorf("singlink: bad server address: %w", err)
	}
	if p.Token, err = B64.DecodeString(tokB64); err != nil {
		return nil, errors.New("singlink: bad token encoding")
	}
	if _, err := ParseToken(p.Token); err != nil {
		return nil, err
	}
	seed, err := B64.DecodeString(devB64)
	if err != nil {
		return nil, errors.New("singlink: bad device key encoding")
	}
	if p.Device, err = Ed25519FromSeed(seed); err != nil {
		return nil, err
	}
	q := u.Query()
	pk, err := B64.DecodeString(q.Get("pk"))
	if err != nil {
		return nil, errors.New("singlink: bad server key encoding")
	}
	if p.ServerKey, err = ParseServerPublicKey(pk); err != nil {
		return nil, err
	}
	p.Transport = q.Get("tr")
	if p.Transport == "" {
		p.Transport = "tls"
	}
	if p.Transport != "tls" && p.Transport != "tcp" {
		return nil, fmt.Errorf("singlink: unknown transport %q", p.Transport)
	}
	p.SNI = q.Get("sni")
	if v := q.Get("pin"); v != "" {
		if p.Pin, err = B64.DecodeString(v); err != nil || len(p.Pin) != sha256.Size {
			return nil, errors.New("singlink: bad certificate pin")
		}
	}
	p.Insecure = q.Get("insecure") == "1"
	return p, nil
}

// TokenInfo parses the profile's token (without verifying it).
func (p *Profile) TokenInfo() (*Token, error) { return ParseToken(p.Token) }

// Client dials SingLink connections for one profile.
type Client struct {
	p            *Profile
	Dialer       net.Dialer
	Stats        Stats
	HeaderPadMax int // random padding added to the request header
	PadFrames    int // number of leading frames that get random padding
	PadMax       int // max padding per padded frame
}

// NewClient returns a client with default padding settings.
func NewClient(p *Profile) *Client {
	return &Client{
		p:            p,
		Dialer:       net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second},
		HeaderPadMax: 512,
		PadFrames:    8,
		PadMax:       512,
	}
}

// Profile returns the client's profile.
func (c *Client) Profile() *Profile { return c.p }

func (c *Client) dialTransport(ctx context.Context) (net.Conn, error) {
	raw, err := c.Dialer.DialContext(ctx, "tcp", c.p.Server)
	if err != nil {
		return nil, err
	}
	if c.p.Transport == "tcp" {
		return raw, nil
	}
	sni := c.p.SNI
	if sni == "" {
		sni, _, _ = net.SplitHostPort(c.p.Server)
	}
	cfg := &tls.Config{
		ServerName: sni,
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h2", "http/1.1"},
	}
	if len(c.p.Pin) > 0 {
		pin := c.p.Pin
		cfg.InsecureSkipVerify = true
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("singlink: no server certificate")
			}
			sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if !bytes.Equal(sum[:], pin) {
				return errors.New("singlink: server certificate does not match pin")
			}
			return nil
		}
	} else if c.p.Insecure {
		cfg.InsecureSkipVerify = true
	}
	tc := tls.Client(raw, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	return tc, nil
}

func (c *Client) newConn(raw net.Conn, cmd Cmd, dst Addr) *Conn {
	return &Conn{
		raw:    raw,
		client: c,
		req:    request{cmd: cmd, dst: dst, token: c.p.Token},
		sentCh: make(chan struct{}),
		hsDone: make(chan struct{}),
		stats:  &c.Stats,
	}
}

// DialTCP opens a relayed TCP stream to dst ("host:port"). The request is
// sent together with the first Write; call Handshake to force it earlier.
func (c *Client) DialTCP(ctx context.Context, dst string) (*Conn, error) {
	a, err := ParseAddr(dst)
	if err != nil {
		return nil, err
	}
	raw, err := c.dialTransport(ctx)
	if err != nil {
		return nil, err
	}
	return c.newConn(raw, CmdTCP, a), nil
}

// DialUDP opens a UDP relay session and waits for the server to accept it.
func (c *Client) DialUDP(ctx context.Context) (*PacketConn, error) {
	raw, err := c.dialTransport(ctx)
	if err != nil {
		return nil, err
	}
	conn := c.newConn(raw, CmdUDP, Addr{Host: "udp", Port: 0})
	if dl, ok := ctx.Deadline(); ok {
		raw.SetDeadline(dl)
	}
	if err := conn.Handshake(); err != nil {
		raw.Close()
		return nil, err
	}
	raw.SetDeadline(time.Time{})
	return &PacketConn{c: conn}, nil
}
