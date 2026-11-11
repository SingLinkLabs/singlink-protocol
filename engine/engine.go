// Package engine runs an SingLink client behind a local SOCKS5 port. It is the
// layer shared by the CLI and the C ABI used by mobile/desktop apps.
package engine

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/SingLinkLabs/singlink-protocol/singlink"
	"github.com/SingLinkLabs/singlink-protocol/socks5"
)

// Status is a snapshot of the running engine.
type Status struct {
	Running   bool   `json:"running"`
	Listen    string `json:"listen"`
	Up        int64  `json:"up"`
	Down      int64  `json:"down"`
	Conns     int64  `json:"conns"`
	Since     int64  `json:"since"`
	LastError string `json:"lastError"`
}

// Engine is safe for concurrent use. The zero value is ready.
type Engine struct {
	mu       sync.Mutex
	starting bool
	client   *singlink.Client
	socks    *socks5.Server
	listen   string
	user     string
	pass     string
	since    time.Time
	lastErr  string
}

// Options tunes Start.
type Options struct {
	// Auth requires a random SOCKS5 username/password (returned by
	// Credentials) so other local users and apps cannot use the tunnel.
	// Leave it off when the port is used as the system proxy, since many
	// applications do not support SOCKS5 authentication.
	Auth bool
}

// Start connects the profile in link and listens on listen (default
// 127.0.0.1:1080, must be a loopback IP literal). It verifies the node with
// a short handshake first so a wrong link or expired token is reported
// immediately. Status and Stop stay responsive while it runs.
func (e *Engine) Start(link, listen string, opts ...Options) error {
	var o Options
	if len(opts) > 0 {
		o = opts[0]
	}
	e.mu.Lock()
	if e.socks != nil || e.starting {
		e.mu.Unlock()
		return errors.New("already running")
	}
	e.starting = true
	e.mu.Unlock()

	c, s, addr, user, pass, err := start(link, listen, o)

	e.mu.Lock()
	defer e.mu.Unlock()
	e.starting = false
	if err != nil {
		e.lastErr = err.Error()
		return err
	}
	e.client, e.socks, e.listen, e.user, e.pass, e.since, e.lastErr = c, s, addr, user, pass, time.Now(), ""
	return nil
}

func start(link, listen string, o Options) (*singlink.Client, *socks5.Server, string, string, string, error) {
	if listen == "" {
		listen = "127.0.0.1:1080"
	}
	p, err := singlink.ParseLink(link)
	if err != nil {
		return nil, nil, "", "", "", err
	}
	host, _, err := net.SplitHostPort(listen)
	if ip, perr := netip.ParseAddr(host); err != nil || perr != nil || !ip.IsLoopback() {
		return nil, nil, "", "", "", fmt.Errorf("listen address must be a loopback IP such as 127.0.0.1:1080, got %q", listen)
	}
	c := singlink.NewClient(p)
	if err := check(c); err != nil {
		return nil, nil, "", "", "", err
	}
	s := &socks5.Server{Client: c}
	if o.Auth {
		s.Username, s.Password = randomToken(), randomToken()
	}
	addr, err := s.Start(listen)
	if err != nil {
		return nil, nil, "", "", "", err
	}
	return c, s, addr.String(), s.Username, s.Password, nil
}

func randomToken() string {
	b := make([]byte, 12)
	rand.Read(b)
	return singlink.B64.EncodeToString(b)
}

// Credentials returns the SOCKS5 username and password ("" without Auth).
func (e *Engine) Credentials() (string, string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.user, e.pass
}

// check performs one authenticated handshake to a well-known destination.
func check(c *singlink.Client) error {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	conn, err := c.DialTCP(ctx, "www.gstatic.com:443")
	if err != nil {
		return fmt.Errorf("cannot reach node: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(8 * time.Second))
	err = conn.Handshake()
	var se *singlink.StatusError
	if errors.As(err, &se) && (se.Code == singlink.StatusDialFailed || se.Code == singlink.StatusForbiddenDest) {
		return nil // authenticated; the probe destination itself is the problem
	}
	return err
}

// Stop closes the local port and all connections.
func (e *Engine) Stop() {
	e.mu.Lock()
	s := e.socks
	e.socks, e.client = nil, nil
	e.mu.Unlock()
	if s != nil {
		s.Close()
	}
}

// Status returns current counters.
func (e *Engine) Status() Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := Status{Running: e.socks != nil, Listen: e.listen, LastError: e.lastErr}
	if e.client != nil {
		if st.LastError == "" {
			st.LastError = e.client.LastError()
		}
		st.Up = e.client.Stats.Up.Load()
		st.Down = e.client.Stats.Down.Load()
		st.Conns = e.client.Stats.Conns.Load()
		st.Since = e.since.Unix()
	}
	return st
}

// ExitIP returns the public IP address websites see through the tunnel.
func (e *Engine) ExitIP(timeout time.Duration) (string, error) {
	hc, err := e.httpClient(timeout)
	if err != nil {
		return "", err
	}
	resp, err := hc.Get("https://api.ipify.org")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return "", err
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(string(b)))
	if err != nil {
		return "", errors.New("unexpected answer from IP service")
	}
	return ip.String(), nil
}

func (e *Engine) httpClient(timeout time.Duration) (*http.Client, error) {
	if timeout <= 0 || timeout > time.Minute {
		timeout = 10 * time.Second
	}
	e.mu.Lock()
	c := e.client
	e.mu.Unlock()
	if c == nil {
		return nil, errors.New("not running")
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return c.DialTCP(ctx, addr)
			},
			DisableKeepAlives: true,
		},
	}, nil
}

// Probe fetches url through the tunnel and returns the HTTP status and
// latency of the full request.
func (e *Engine) Probe(url string, timeout time.Duration) (int, time.Duration, error) {
	hc, err := e.httpClient(timeout)
	if err != nil {
		return 0, 0, err
	}
	start := time.Now()
	resp, err := hc.Get(url)
	if err != nil {
		return 0, 0, err
	}
	resp.Body.Close()
	return resp.StatusCode, time.Since(start), nil
}
