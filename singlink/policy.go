// Copyright 2026 SingLinkLabs (https://github.com/SingLinkLabs)
// SPDX-License-Identifier: Apache-2.0

package singlink

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"
)

// limiter is a token bucket shared by all connections of one subject.
type limiter struct {
	mu     sync.Mutex
	rate   float64 // bytes per second
	burst  float64
	tokens float64
	last   time.Time
}

func newLimiter(kbps uint32) *limiter {
	l := &limiter{last: time.Now()}
	l.setRate(kbps)
	l.tokens = l.burst
	return l
}

// setRate changes the rate, keeping (but capping) the current tokens.
func (l *limiter) setRate(kbps uint32) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.rate = float64(kbps) * 1000 / 8
	l.burst = max(l.rate/4, 64*1024)
	l.tokens = min(l.tokens, l.burst)
}

// full reports whether the bucket has refilled completely.
func (l *limiter) full() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.tokens+time.Since(l.last).Seconds()*l.rate >= l.burst
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

// subjects tracks per-subject connection counts and rate limiters. A
// subject's limiter outlives its connections until its bucket would be full
// again, so reconnecting does not reset the rate limit.
type subjects struct {
	mu    sync.Mutex
	m     map[[16]byte]*subjectState
	calls int
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
	if s.calls++; s.calls%1024 == 0 {
		s.evictLocked()
	}
	st := s.m[t.Subject]
	if st == nil {
		st = &subjectState{}
		s.m[t.Subject] = st
	}
	if t.MaxConns > 0 && st.conns >= int(t.MaxConns) {
		return nil, false
	}
	if t.RateKbps > 0 {
		if st.lim == nil {
			st.lim = newLimiter(t.RateKbps)
		} else if st.kbps != t.RateKbps {
			st.lim.setRate(t.RateKbps)
		}
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
		if st.conns <= 0 && st.lim == nil {
			delete(s.m, t.Subject)
		}
	}
}

// evictLocked drops idle subjects whose bucket has refilled.
func (s *subjects) evictLocked() {
	for k, st := range s.m {
		if st.conns <= 0 && (st.lim == nil || st.lim.full()) {
			delete(s.m, k)
		}
	}
}

// deniedPrefixes are special-purpose ranges (IANA registries) that a public
// node must never connect to on behalf of a user.
var deniedPrefixes = func() []netip.Prefix {
	var ps []netip.Prefix
	for _, c := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"::/96", "::ffff:0:0/96", "64:ff9b:1::/48", "100::/64", "2001::/23", "2001:db8::/32",
		"2002::/16", "fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8",
	} {
		ps = append(ps, netip.MustParsePrefix(c))
	}
	return ps
}()

// nat64 is the well-known NAT64 prefix; the embedded IPv4 address is checked.
var nat64 = netip.MustParsePrefix("64:ff9b::/96")

// publicIP reports whether ip is a globally routable unicast address.
func publicIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() {
		return false
	}
	if nat64.Contains(ip) {
		b := ip.As16()
		return publicIP(netip.AddrFrom4([4]byte(b[12:])))
	}
	for _, p := range deniedPrefixes {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

// localAddrs caches the node's own interface addresses, which are denied as
// destinations (services bound to 0.0.0.0 would otherwise be reachable).
type localAddrs struct {
	mu   sync.Mutex
	set  map[netip.Addr]bool
	when time.Time
}

func (l *localAddrs) has(ip netip.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.set == nil || time.Since(l.when) > time.Minute {
		l.set = map[netip.Addr]bool{}
		if addrs, err := net.InterfaceAddrs(); err == nil {
			for _, a := range addrs {
				if p, err := netip.ParsePrefix(a.String()); err == nil {
					l.set[p.Addr().Unmap()] = true
				}
			}
		}
		l.when = time.Now()
	}
	return l.set[ip.Unmap()]
}

// resolver resolves destinations and applies the node's destination policy.
// The checked IP is what gets dialled, so DNS rebinding cannot bypass it.
type resolver struct {
	allowPrivate bool
	blockedPorts map[uint16]bool
	deny         []netip.Prefix
	local        localAddrs
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
	allowed := func(ip netip.Addr) bool {
		return rs.allowedAddress(ip)
	}
	if a.IP.IsValid() {
		if !allowed(a.IP) {
			return netip.AddrPort{}, StatusForbiddenDest
		}
		return netip.AddrPortFrom(a.IP, a.Port), StatusOK
	}
	rs.mu.Lock()
	if c, ok := rs.cache[a.Host]; ok && time.Now().Before(c.exp) && allowed(c.ip) {
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
		// Same answer as an unresolvable name, so users cannot probe
		// which internal names exist.
		return netip.AddrPort{}, StatusDialFailed
	}
	rs.mu.Lock()
	if rs.cache == nil || len(rs.cache) > 4096 {
		rs.cache = map[string]cachedIP{}
	}
	rs.cache[a.Host] = cachedIP{ip: pick, exp: time.Now().Add(time.Minute)}
	rs.mu.Unlock()
	return netip.AddrPortFrom(pick, a.Port), StatusOK
}
