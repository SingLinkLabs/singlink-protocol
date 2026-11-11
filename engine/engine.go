// Package engine runs an SingLink client behind a local SOCKS5 port. It is the
// layer shared by the CLI and the C ABI used by mobile/desktop apps.
package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/singlinklabs/singlink-protocol/singlink"
	"github.com/singlinklabs/singlink-protocol/socks5"
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
	mu      sync.Mutex
	client  *singlink.Client
	socks   *socks5.Server
	listen  string
	since   time.Time
	lastErr string
}

// Start connects the profile in link and listens on listen (default
// 127.0.0.1:1080). It verifies the node with a short handshake first so a
// wrong link or expired token is reported immediately.
func (e *Engine) Start(link, listen string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.socks != nil {
		return errors.New("already running")
	}
	if listen == "" {
		listen = "127.0.0.1:1080"
	}
	p, err := singlink.ParseLink(link)
	if err != nil {
		e.lastErr = err.Error()
		return err
	}
	if host, _, err := net.SplitHostPort(listen); err != nil || !isLoopback(host) {
		err := fmt.Errorf("listen address must be on loopback, got %q", listen)
		e.lastErr = err.Error()
		return err
	}
	c := singlink.NewClient(p)
	if err := check(c); err != nil {
		e.lastErr = err.Error()
		return err
	}
	s := &socks5.Server{Client: c}
	addr, err := s.Start(listen)
	if err != nil {
		e.lastErr = err.Error()
		return err
	}
	e.client, e.socks, e.listen, e.since, e.lastErr = c, s, addr.String(), time.Now(), ""
	return nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
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
