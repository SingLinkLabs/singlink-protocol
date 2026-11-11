package singlink

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ServerConfig configures a node.
type ServerConfig struct {
	Key     *ServerPrivateKey
	Issuers Issuers

	// TLS, if set, wraps the listener (recommended; TLS 1.3 only).
	TLS *tls.Config

	// Fallback is a host:port that receives every connection that does not
	// authenticate, byte for byte (typically the real website behind the
	// node). Empty means unauthenticated connections are held open and
	// silently drained until HandshakeTimeout.
	Fallback string

	// AllowPrivate permits destinations in private, loopback and link-local
	// ranges. Keep it false on public nodes.
	AllowPrivate bool
	// BlockedPorts are refused for every user (default: 25, outbound SMTP).
	BlockedPorts []uint16

	MaxTimeSkew      time.Duration // default 120s
	HandshakeTimeout time.Duration // default 10s
	IdleTimeout      time.Duration // default 5m
	DialTimeout      time.Duration // default 10s

	// RevokedFile lists revoked token IDs (hex, one per line). It is
	// re-read when its modification time changes.
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

	revMu    sync.RWMutex
	revoked  map[[16]byte]bool
	revMtime time.Time
	revCheck atomic.Int64
}

// NewServer validates cfg and returns a server.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Key == nil {
		return nil, errors.New("singlink: server key required")
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
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 5 * time.Minute
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 10 * time.Second
	}
	if cfg.BlockedPorts == nil {
		cfg.BlockedPorts = []uint16{25}
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
		res:    &resolver{allowPrivate: cfg.AllowPrivate, blockedPorts: bp, r: net.DefaultResolver},
		log:    log,
	}
	s.reloadRevoked()
	return s, nil
}

// Serve accepts connections on ln until it is closed.
func (s *Server) Serve(ln net.Listener) error {
	if s.cfg.TLS != nil {
		ln = tls.NewListener(ln, s.cfg.TLS)
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return err
		}
		go s.handle(c)
	}
}

func (s *Server) handle(raw net.Conn) {
	s.Stats.Conns.Add(1)
	defer s.Stats.Conns.Add(-1)
	defer raw.Close()

	raw.SetReadDeadline(time.Now().Add(s.cfg.HandshakeTimeout))
	if tc, ok := raw.(*tls.Conn); ok {
		if err := tc.Handshake(); err != nil {
			return
		}
	}
	rec := &recorder{r: raw}
	hs, err := readFirstFlight(rec, s.cfg.Key)
	if err != nil {
		s.fallback(raw, rec.buf, err)
		return
	}
	now := time.Now()
	tok, err := s.cfg.Issuers.Verify(hs.req.token)
	if err != nil || !hs.verifyPoP(tok.DevicePub) {
		s.fallback(raw, rec.buf, errProbe)
		return
	}
	if d := now.Sub(hs.req.ts); d > s.cfg.MaxTimeSkew || d < -s.cfg.MaxTimeSkew {
		s.fallback(raw, rec.buf, errProbe)
		return
	}
	if !s.replay.checkAndAdd(hs.E, now) {
		s.fallback(raw, rec.buf, errProbe)
		return
	}
	raw.SetReadDeadline(time.Time{})

	// From here on the peer is an authenticated user: answer with a status.
	F, c2s, s2c, err := hs.accept()
	if err != nil {
		return
	}
	if _, err := raw.Write(F); err != nil {
		return
	}
	conn := newServerConn(raw, c2s, s2c, 8, 512)
	reject := func(st Status, msg string) {
		conn.fw.writeFrame(frameStatus, append([]byte{byte(st)}, msg...))
	}

	switch {
	case now.Before(tok.NotBefore):
		reject(StatusNotYetValid, "")
		return
	case !now.Before(tok.NotAfter):
		reject(StatusTokenExpired, "")
		return
	case s.isRevoked(tok.ID):
		reject(StatusTokenRevoked, "")
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

	// Close the session when the token expires.
	ctx, cancel := context.WithDeadline(context.Background(), tok.NotAfter)
	defer cancel()
	go func() { <-ctx.Done(); raw.Close() }()

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
	if len(consumed) > 0 {
		if _, err := up.Write(consumed); err != nil {
			return
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	relay(ctx, raw, up, nil, s.cfg.IdleTimeout, nil)
}

func (s *Server) isRevoked(id [16]byte) bool {
	// Re-check the file at most every 10 seconds.
	now := time.Now().Unix()
	if last := s.revCheck.Load(); now-last >= 10 && s.revCheck.CompareAndSwap(last, now) {
		s.reloadRevoked()
	}
	s.revMu.RLock()
	defer s.revMu.RUnlock()
	return s.revoked[id]
}

func (s *Server) reloadRevoked() {
	if s.cfg.RevokedFile == "" {
		return
	}
	fi, err := os.Stat(s.cfg.RevokedFile)
	if err != nil {
		return
	}
	s.revMu.RLock()
	same := fi.ModTime().Equal(s.revMtime)
	s.revMu.RUnlock()
	if same {
		return
	}
	f, err := os.Open(s.cfg.RevokedFile)
	if err != nil {
		return
	}
	defer f.Close()
	m := map[[16]byte]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		b, err := hex.DecodeString(line)
		if err != nil || len(b) != 16 {
			continue
		}
		m[[16]byte(b)] = true
	}
	s.revMu.Lock()
	s.revoked, s.revMtime = m, fi.ModTime()
	s.revMu.Unlock()
	s.log.Info("revocation list loaded", "entries", len(m))
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
