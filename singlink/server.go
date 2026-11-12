// Copyright 2026 SingLinkLabs (https://github.com/SingLinkLabs)
// SPDX-License-Identifier: Apache-2.0

package singlink

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ServerConfig configures a node.
type ServerConfig struct {
	Key *ServerPrivateKey
	// OldKeys are still accepted during a key rotation (tried after Key).
	// Rotate node keys regularly: whoever later obtains a static key can
	// decrypt recorded request headers made to it (SPEC §5.4).
	OldKeys []*ServerPrivateKey
	Issuers Issuers

	// TLS, if set, wraps the listener (recommended; TLS 1.3 only).
	TLS *tls.Config

	// Fallback is a host:port that receives every connection that does not
	// authenticate, byte for byte (typically the real website behind the
	// node). Empty means unauthenticated connections are held open and
	// silently drained until HandshakeTimeout.
	Fallback string

	// FallbackProxyProtocol prefixes fallback connections with a PROXY
	// protocol v2 header so the website sees the prober's real address
	// (otherwise every prober appears as the node, often 127.0.0.1).
	FallbackProxyProtocol bool
	FallbackIdle          time.Duration // default 60s
	FallbackMaxLifetime   time.Duration // default 10m

	// AllowPrivate permits destinations in private, loopback, link-local and
	// other special-purpose ranges, and the node's own addresses. Keep it
	// false on public nodes.
	AllowPrivate bool
	// DenyCIDRs are extra destination ranges refused for every user.
	DenyCIDRs []netip.Prefix
	// BlockedPorts are refused for every user, in addition to port 25
	// (outbound SMTP) unless AllowSMTP is set.
	BlockedPorts []uint16
	AllowSMTP    bool

	MaxConnections  int // default 20000; accept waits when reached
	MaxPendingPerIP int // default 64 concurrent unauthenticated handshakes per IP

	MaxTimeSkew      time.Duration // default 120s
	HandshakeTimeout time.Duration // default 10s: wait for the first bytes
	FlightIdle       time.Duration // default 500ms: raw TCP only, end of first flight
	// ExpiredGrace is how long after expiry a token still gets an explicit
	// "expired" answer (so the app can tell the user); older tokens and
	// revoked or not-yet-valid ones are treated as unauthenticated.
	ExpiredGrace time.Duration // default 24h
	IdleTimeout  time.Duration // default 5m
	DialTimeout  time.Duration // default 10s

	// RevokedFile lists revocations, one per line: "token <hex id>",
	// "subject <hex id>" or "device <base64url key>" (a bare hex id means a
	// token). It is checked every 10 s; live sessions of newly revoked
	// tokens are closed.
	RevokedFile string

	Logger *slog.Logger
}

// Server is an SingLink node.
type Server struct {
	cfg      ServerConfig
	replay   *replayCache
	subjects subjects
	res      *resolver
	log      *slog.Logger
	Stats    Stats

	keys    []*ServerPrivateKey
	started time.Time
	guard   *guard

	revMu    sync.RWMutex
	revoked  revocations
	revStamp string
	revCheck atomic.Int64

	watchOnce sync.Once
	sessMu    sync.Mutex
	sessions  map[*session]struct{}
}

type session struct {
	tok   *Token
	close func()
}

type revocations struct {
	tokens   map[[16]byte]bool
	subjects map[[16]byte]bool
	devices  map[string]bool
}

func (r revocations) has(t *Token) bool {
	return r.tokens[t.ID] || r.subjects[t.Subject] || r.devices[string(t.DevicePub)]
}

// NewServer validates cfg and returns a server.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Key == nil {
		return nil, errors.New("singlink: server key required")
	}
	for _, k := range cfg.OldKeys {
		if k == nil {
			return nil, errors.New("singlink: nil old key")
		}
	}
	if len(cfg.Issuers) == 0 {
		return nil, errors.New("singlink: at least one token issuer required")
	}
	if cfg.MaxTimeSkew == 0 {
		cfg.MaxTimeSkew = 120 * time.Second
	}
	if cfg.HandshakeTimeout == 0 {
		cfg.HandshakeTimeout = 10 * time.Second
	}
	if cfg.FlightIdle == 0 {
		cfg.FlightIdle = 500 * time.Millisecond
	}
	if cfg.ExpiredGrace == 0 {
		cfg.ExpiredGrace = 24 * time.Hour
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 5 * time.Minute
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 10 * time.Second
	}
	if !cfg.AllowSMTP {
		cfg.BlockedPorts = append(cfg.BlockedPorts, 25)
	}
	if cfg.FallbackIdle == 0 {
		cfg.FallbackIdle = time.Minute
	}
	if cfg.FallbackMaxLifetime == 0 {
		cfg.FallbackMaxLifetime = 10 * time.Minute
	}
	if cfg.MaxConnections == 0 {
		cfg.MaxConnections = 20000
	}
	if cfg.MaxPendingPerIP == 0 {
		cfg.MaxPendingPerIP = 64
	}
	if cfg.TLS != nil {
		cfg.TLS = cfg.TLS.Clone()
		cfg.TLS.MinVersion = tls.VersionTLS13
		if len(cfg.TLS.NextProtos) == 0 {
			cfg.TLS.NextProtos = []string{"http/1.1"}
		}
	}
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	bp := map[uint16]bool{}
	for _, p := range cfg.BlockedPorts {
		bp[p] = true
	}
	s := &Server{
		cfg:    cfg,
		replay: newReplayCache(cfg.MaxTimeSkew),
		res:    &resolver{allowPrivate: cfg.AllowPrivate, blockedPorts: bp, deny: cfg.DenyCIDRs, r: net.DefaultResolver},
		guard:  newGuard(cfg.MaxConnections, cfg.MaxPendingPerIP),
		log:    log,
		keys:   append([]*ServerPrivateKey{cfg.Key}, cfg.OldKeys...),
		// Flights stamped before this process started may already have
		// been accepted by a previous process with the same key.
		started:  time.Now(),
		sessions: map[*session]struct{}{},
	}
	s.reloadRevoked()
	return s, nil
}

// Serve accepts connections on ln until it is closed.
func (s *Server) Serve(ln net.Listener) error {
	s.watchOnce.Do(func() {
		if s.cfg.RevokedFile != "" {
			go func() {
				for range time.Tick(10 * time.Second) {
					s.reloadRevoked()
				}
			}()
		}
	})
	if s.cfg.TLS != nil {
		ln = tls.NewListener(ln, s.cfg.TLS)
	}
	var backoff time.Duration
	for {
		s.guard.slots <- struct{}{}
		c, err := ln.Accept()
		if err != nil {
			<-s.guard.slots
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			// Out of file descriptors and similar: wait and keep serving.
			backoff = min(max(2*backoff, 5*time.Millisecond), time.Second)
			s.log.Warn("accept failed", "err", err, "retry_in", backoff)
			time.Sleep(backoff)
			continue
		}
		backoff = 0
		go func() {
			defer func() { <-s.guard.slots }()
			s.handle(c)
		}()
	}
}

func (s *Server) handle(raw net.Conn) {
	s.Stats.Conns.Add(1)
	defer s.Stats.Conns.Add(-1)
	defer raw.Close()
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("connection handler panic", "panic", r)
		}
	}()
	ip := remoteIP(raw)
	if !s.guard.begin(ip) {
		return
	}
	pending := true
	defer func() {
		if pending {
			s.guard.end(ip)
		}
	}()

	raw.SetReadDeadline(time.Now().Add(s.cfg.HandshakeTimeout))
	_, isTLS := raw.(*tls.Conn)
	if isTLS {
		if err := raw.(*tls.Conn).Handshake(); err != nil {
			return
		}
	}
	flight, err := readFlight(raw, isTLS, s.cfg.HandshakeTimeout, s.cfg.FlightIdle)
	if err != nil && len(flight) == 0 {
		return
	}
	fail := func(err error) {
		s.guard.failedFlight(ip, flight)
		s.guard.end(ip)
		pending = false
		s.fallback(raw, flight, err)
	}
	if !s.guard.worthDecrypting(ip, flight) {
		fail(errProbe)
		return
	}
	s.guard.crypto <- struct{}{}
	hs, err := parseFirstFlight(flight, s.keys)
	var tok *Token
	if err == nil {
		tok, err = s.cfg.Issuers.Verify(hs.req.token)
		if err == nil && !hs.verifyPoP(tok.DevicePub) {
			err = errProbe
		}
	}
	<-s.guard.crypto
	if err != nil {
		fail(err)
		return
	}
	now := time.Now()
	if d := now.Sub(hs.req.ts); d > s.cfg.MaxTimeSkew || d < -s.cfg.MaxTimeSkew || hs.req.ts.Unix() < s.started.Unix() {
		fail(errProbe)
		return
	}
	// Only current users (and recently expired ones) learn this is a node.
	expired := !now.Before(tok.NotAfter)
	if now.Before(tok.NotBefore) || s.isRevoked(tok) || (expired && now.Sub(tok.NotAfter) > s.cfg.ExpiredGrace) {
		fail(errProbe)
		return
	}
	if !s.replay.checkAndAdd(hs.E, now) {
		fail(errProbe)
		return
	}
	raw.SetReadDeadline(time.Time{})
	s.guard.end(ip)
	pending = false

	// From here on the peer is an authenticated user: answer with a status.
	// F goes out together with the first (padded) frame in one write.
	F, c2s, s2c, err := hs.accept()
	if err != nil {
		return
	}
	conn := newServerConn(raw, c2s, s2c, 8, 512)
	conn.fw.prefix = F
	reject := func(st Status, msg string) {
		conn.fw.writeFrame(frameStatus, append([]byte{byte(st)}, msg...))
		// Half-close and drain briefly so a reset cannot destroy the status.
		if cw, ok := raw.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		raw.SetReadDeadline(time.Now().Add(time.Second))
		io.Copy(io.Discard, io.LimitReader(raw, 1<<20))
	}
	if expired {
		reject(StatusTokenExpired, "")
		return
	}
	need := CapTCP
	if hs.req.cmd == CmdUDP {
		need = CapUDP
	} else if hs.req.cmd != CmdTCP {
		reject(StatusBadRequest, "unknown command")
		return
	}
	if !tok.Has(need) {
		reject(StatusCapDenied, "")
		return
	}
	lim, ok := s.subjects.acquire(tok)
	if !ok {
		reject(StatusTooManyConns, "")
		return
	}
	defer s.subjects.release(tok)

	// Close the session when the token expires or is revoked.
	ctx, cancel := context.WithDeadline(context.Background(), tok.NotAfter)
	defer cancel()
	go func() { <-ctx.Done(); raw.Close() }()
	sess := &session{tok: tok, close: cancel}
	s.sessMu.Lock()
	s.sessions[sess] = struct{}{}
	s.sessMu.Unlock()
	defer func() {
		s.sessMu.Lock()
		delete(s.sessions, sess)
		s.sessMu.Unlock()
	}()

	if hs.req.cmd == CmdUDP {
		s.serveUDP(ctx, conn, lim, reject)
		return
	}
	s.serveTCP(ctx, conn, hs.req, lim, reject)
}

func (s *Server) serveTCP(ctx context.Context, conn *Conn, req request, lim *limiter, reject func(Status, string)) {
	dctx, dcancel := context.WithTimeout(ctx, s.cfg.DialTimeout)
	ap, status := s.res.resolve(dctx, req.dst)
	if status != StatusOK {
		dcancel()
		reject(status, "")
		return
	}
	var d net.Dialer
	target, err := d.DialContext(dctx, "tcp", ap.String())
	dcancel()
	if err != nil {
		reject(StatusDialFailed, "")
		return
	}
	defer target.Close()
	if err := conn.fw.writeFrame(frameStatus, []byte{byte(StatusOK)}); err != nil {
		return
	}
	if len(req.early) > 0 {
		if _, err := target.Write(req.early); err != nil {
			return
		}
		s.Stats.Up.Add(int64(len(req.early)))
	}
	relay(ctx, conn, target, lim, s.cfg.IdleTimeout, &s.Stats)
}

func (s *Server) serveUDP(ctx context.Context, conn *Conn, lim *limiter, reject func(Status, string)) {
	pc, err := net.ListenUDP("udp", nil)
	if err != nil {
		reject(StatusDialFailed, "")
		return
	}
	defer pc.Close()
	if err := conn.fw.writeFrame(frameStatus, []byte{byte(StatusOK)}); err != nil {
		return
	}
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-ctx.Done()
		pc.Close()
		conn.raw.Close()
	}()
	// Only endpoints the client has sent to may answer.
	var peersMu sync.Mutex
	peers := map[netip.AddrPort]struct{}{}
	go idleWatch(ctx, cancel, &last, s.cfg.IdleTimeout)

	// node -> client
	go func() {
		defer cancel()
		buf := make([]byte, 65536)
		for {
			n, from, err := pc.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			if n > maxFrameData-260 {
				continue
			}
			peersMu.Lock()
			_, ok := peers[netip.AddrPortFrom(from.Addr().Unmap(), from.Port())]
			peersMu.Unlock()
			if !ok {
				continue
			}
			last.Store(time.Now().UnixNano())
			if lim != nil && lim.wait(ctx, n) != nil {
				return
			}
			b := AddrFromAddrPort(from).appendTo(make([]byte, 0, 32+n))
			b = append(b, buf[:n]...)
			if conn.fw.writeFrame(frameUDP, b) != nil {
				return
			}
			s.Stats.Down.Add(int64(n))
		}
	}()

	// client -> node
	for {
		t, data, err := conn.fr.readFrame()
		if err != nil {
			return
		}
		if t == framePadding {
			continue
		}
		if t != frameUDP {
			return
		}
		a, payload, err := decodeAddr(data)
		if err != nil {
			return
		}
		last.Store(time.Now().UnixNano())
		rctx, rcancel := context.WithTimeout(ctx, 5*time.Second)
		ap, status := s.res.resolve(rctx, a)
		rcancel()
		if status != StatusOK {
			continue // datagrams to forbidden destinations are dropped
		}
		if lim != nil && lim.wait(ctx, len(payload)) != nil {
			return
		}
		peersMu.Lock()
		if len(peers) >= 1024 {
			clear(peers)
		}
		peers[netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())] = struct{}{}
		peersMu.Unlock()
		pc.WriteToUDPAddrPort(payload, ap)
		s.Stats.Up.Add(int64(len(payload)))
	}
}

// fallback forwards an unauthenticated connection to the decoy website.
func (s *Server) fallback(raw net.Conn, consumed []byte, cause error) {
	s.log.Debug("unauthenticated connection", "remote", raw.RemoteAddr().String(), "cause", cause)
	if s.cfg.Fallback == "" {
		raw.SetReadDeadline(time.Now().Add(s.cfg.HandshakeTimeout))
		io.Copy(io.Discard, raw)
		return
	}
	raw.SetReadDeadline(time.Time{})
	up, err := net.DialTimeout("tcp", s.cfg.Fallback, s.cfg.DialTimeout)
	if err != nil {
		return
	}
	defer up.Close()
	if s.cfg.FallbackProxyProtocol {
		if err := writeProxyV2(up, raw.RemoteAddr(), raw.LocalAddr()); err != nil {
			return
		}
	}
	if len(consumed) > 0 {
		if _, err := up.Write(consumed); err != nil {
			return
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.FallbackMaxLifetime)
	defer cancel()
	relay(ctx, raw, up, nil, s.cfg.FallbackIdle, nil)
}

func (s *Server) isRevoked(t *Token) bool {
	// Re-check the file at most every 10 seconds.
	now := time.Now().Unix()
	if last := s.revCheck.Load(); now-last >= 10 && s.revCheck.CompareAndSwap(last, now) {
		s.reloadRevoked()
	}
	s.revMu.RLock()
	defer s.revMu.RUnlock()
	return s.revoked.has(t)
}

func (s *Server) reloadRevoked() {
	if s.cfg.RevokedFile == "" {
		return
	}
	b, err := os.ReadFile(s.cfg.RevokedFile)
	if err != nil {
		return
	}
	stamp := string(hash(b))
	s.revMu.RLock()
	same := stamp == s.revStamp
	s.revMu.RUnlock()
	if same {
		return
	}
	r := revocations{tokens: map[[16]byte]bool{}, subjects: map[[16]byte]bool{}, devices: map[string]bool{}}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 0 || strings.HasPrefix(f[0], "#") {
			continue
		}
		kind, val := "token", f[0]
		if len(f) >= 2 {
			kind, val = f[0], f[1]
		}
		switch kind {
		case "token", "subject":
			id, err := hex.DecodeString(val)
			if err != nil || len(id) != 16 {
				continue
			}
			if kind == "token" {
				r.tokens[[16]byte(id)] = true
			} else {
				r.subjects[[16]byte(id)] = true
			}
		case "device":
			k, err := B64.DecodeString(val)
			if err == nil && len(k) == 32 {
				r.devices[string(k)] = true
			}
		}
	}
	s.revMu.Lock()
	s.revoked, s.revStamp = r, stamp
	s.revMu.Unlock()
	s.log.Info("revocation list loaded", "tokens", len(r.tokens), "subjects", len(r.subjects), "devices", len(r.devices))

	// Close live sessions that are now revoked.
	s.sessMu.Lock()
	for sess := range s.sessions {
		if r.has(sess.tok) {
			sess.close()
		}
	}
	s.sessMu.Unlock()
}

// relay copies both directions until both are done, the context ends or the
// pair is idle for longer than idle.
func relay(ctx context.Context, a, b net.Conn, lim *limiter, idle time.Duration, stats *Stats) {
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-ctx.Done()
		a.Close()
		b.Close()
	}()
	go idleWatch(ctx, cancel, &last, idle)

	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn, counter *atomic.Int64) {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				last.Store(time.Now().UnixNano())
				if lim != nil && lim.wait(ctx, n) != nil {
					cancel()
					return
				}
				if _, werr := dst.Write(buf[:n]); werr != nil {
					cancel()
					return
				}
				if counter != nil {
					counter.Add(int64(n))
				}
			}
			if err != nil {
				if errors.Is(err, io.EOF) {
					if cw, ok := dst.(interface{ CloseWrite() error }); ok {
						cw.CloseWrite()
						return
					}
				}
				cancel()
				return
			}
		}
	}
	var up, down *atomic.Int64
	if stats != nil {
		up, down = &stats.Up, &stats.Down
	}
	go cp(b, a, up)
	go cp(a, b, down)
	wg.Wait()
}

func idleWatch(ctx context.Context, cancel context.CancelFunc, last *atomic.Int64, idle time.Duration) {
	t := time.NewTicker(min(idle/4, 30*time.Second))
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if time.Since(time.Unix(0, last.Load())) > idle {
				cancel()
				return
			}
		}
	}
}
