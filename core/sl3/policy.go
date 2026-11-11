package sl3

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"
)

// replayCache remembers client ephemeral keys seen inside the timestamp
// window. Two generations are kept and rotated every window.
type replayCache struct {
	mu      sync.Mutex
	window  time.Duration
	rotated time.Time
	cur     map[[32]byte]struct{}
	prev    map[[32]byte]struct{}
}

func newReplayCache(window time.Duration) *replayCache {
	return &replayCache{window: window, rotated: time.Now(), cur: map[[32]byte]struct{}{}, prev: map[[32]byte]struct{}{}}
}

// checkAndAdd returns false if E was already seen.
func (rc *replayCache) checkAndAdd(E []byte, now time.Time) bool {
	var k [32]byte
	copy(k[:], E)
	rc.mu.Lock()
	defer rc.mu.Unlock()
	// Entries must live for 2×window (timestamps are accepted ±window).
	for now.Sub(rc.rotated) >= 2*rc.window {
		rc.prev, rc.cur = rc.cur, map[[32]byte]struct{}{}
		rc.rotated = rc.rotated.Add(2 * rc.window)
		if now.Sub(rc.rotated) >= 4*rc.window {
			rc.prev = map[[32]byte]struct{}{}
			rc.rotated = now
		}
	}
	if _, ok := rc.cur[k]; ok {
		return false
	}
	if _, ok := rc.prev[k]; ok {
		return false
	}
	rc.cur[k] = struct{}{}
	return true
}

// limiter is a token bucket shared by all connections of one subject.
type limiter struct {
	mu     sync.Mutex
	rate   float64 // bytes per second
	burst  float64
	tokens float64
	last   time.Time
}

func newLimiter(kbps uint32) *limiter {
	rate := float64(kbps) * 1000 / 8
	burst := max(rate/4, 64*1024)
	return &limiter{rate: rate, burst: burst, tokens: burst, last: time.Now()}
}

// wait blocks until n bytes may pass.
func (l *limiter) wait(ctx context.Context, n int) error {
	for {
		l.mu.Lock()
		now := time.Now()
		l.tokens = min(l.burst, l.tokens+now.Sub(l.last).Seconds()*l.rate)
		l.last = now
		if l.tokens >= float64(n) || (l.tokens >= l.burst && float64(n) > l.burst) {
			l.tokens -= float64(n)
			l.mu.Unlock()
			return nil
		}
		need := (min(float64(n), l.burst) - l.tokens) / l.rate
		l.mu.Unlock()
		t := time.NewTimer(time.Duration(need * float64(time.Second)))
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
}

// subjects tracks per-subject connection counts and rate limiters.
type subjects struct {
	mu sync.Mutex
	m  map[[16]byte]*subjectState
}

type subjectState struct {
	conns int
	lim   *limiter
	kbps  uint32
}

// acquire registers a connection and returns the subject's shared rate
// limiter (nil when unlimited); it fails if the subject is at its limit.
func (s *subjects) acquire(t *Token) (*limiter, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[[16]byte]*subjectState{}
	}
	st := s.m[t.Subject]
	if st == nil {
		st = &subjectState{}
		s.m[t.Subject] = st
	}
	if t.MaxConns > 0 && st.conns >= int(t.MaxConns) {
		return nil, false
	}
	if t.RateKbps > 0 && (st.lim == nil || st.kbps != t.RateKbps) {
		st.lim = newLimiter(t.RateKbps)
		st.kbps = t.RateKbps
	}
	st.conns++
	if t.RateKbps == 0 {
		return nil, true
	}
	return st.lim, true
}

func (s *subjects) release(t *Token) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st := s.m[t.Subject]; st != nil {
		st.conns--
		if st.conns <= 0 {
			delete(s.m, t.Subject)
		}
	}
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// publicIP reports whether ip is a globally routable unicast address.
func publicIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.IsValid() && !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsUnspecified() &&
		!ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() && !ip.IsInterfaceLocalMulticast() &&
		!ip.IsMulticast() && !cgnat.Contains(ip)
}

// resolver resolves destinations and applies the node's destination policy.
// The checked IP is what gets dialled, so DNS rebinding cannot bypass it.
type resolver struct {
	allowPrivate bool
	blockedPorts map[uint16]bool
	r            *net.Resolver

	mu    sync.Mutex
	cache map[string]cachedIP
}

type cachedIP struct {
	ip  netip.Addr
	exp time.Time
}

func (rs *resolver) resolve(ctx context.Context, a Addr) (netip.AddrPort, Status) {
	if rs.blockedPorts[a.Port] || a.Port == 0 {
		return netip.AddrPort{}, StatusForbiddenDest
	}
	allowed := func(ip netip.Addr) bool { return rs.allowPrivate || publicIP(ip) }
	if a.IP.IsValid() {
		if !allowed(a.IP) {
			return netip.AddrPort{}, StatusForbiddenDest
		}
		return netip.AddrPortFrom(a.IP, a.Port), StatusOK
	}
	rs.mu.Lock()
	if c, ok := rs.cache[a.Host]; ok && time.Now().Before(c.exp) {
		rs.mu.Unlock()
		return netip.AddrPortFrom(c.ip, a.Port), StatusOK
	}
	rs.mu.Unlock()
	ips, err := rs.r.LookupNetIP(ctx, "ip", a.Host)
	if err != nil || len(ips) == 0 {
		return netip.AddrPort{}, StatusDialFailed
	}
	var pick netip.Addr
	for _, ip := range ips {
		if allowed(ip) && (!pick.IsValid() || (ip.Unmap().Is4() && !pick.Is4())) {
			pick = ip.Unmap()
		}
	}
	if !pick.IsValid() {
		return netip.AddrPort{}, StatusForbiddenDest
	}
	rs.mu.Lock()
	if rs.cache == nil || len(rs.cache) > 4096 {
		rs.cache = map[string]cachedIP{}
	}
	rs.cache[a.Host] = cachedIP{ip: pick, exp: time.Now().Add(time.Minute)}
	rs.mu.Unlock()
	return netip.AddrPortFrom(pick, a.Port), StatusOK
}
