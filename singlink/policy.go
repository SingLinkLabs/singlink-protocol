// Copyright 2026 SingLinkVPN (https://singlinkvpn.com)
// SPDX-License-Identifier: Apache-2.0

package singlink

import (
	"context"
	"net"
	"net/netip"
	"strings"
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

// deniedPrefixes are the special-purpose ranges that a public node must
// never connect to on behalf of a user: every block of the IANA IPv4 and IPv6
// Special-Purpose Address Registries that is not globally reachable (registry
// snapshot 2026-11-19), the multicast and deprecated ranges, and the
// IPv4-translated format. A block is denied as a whole when only parts of it
// are globally reachable (192.0.0.0/24, 2001::/23).
var deniedPrefixes = func() []netip.Prefix {
	var ps []netip.Prefix
	for _, c := range []string{
		// IPv4
		"0.0.0.0/8",       // "this network" (RFC 791, RFC 1122)
		"10.0.0.0/8",      // private use (RFC 1918)
		"100.64.0.0/10",   // shared address space, CGN (RFC 6598)
		"127.0.0.0/8",     // loopback (RFC 1122)
		"169.254.0.0/16",  // link local (RFC 3927)
		"172.16.0.0/12",   // private use (RFC 1918)
		"192.0.0.0/24",    // IETF protocol assignments (RFC 6890), incl. RFC 7335, 7600, 7723, 8155, 8880
		"192.0.2.0/24",    // documentation, TEST-NET-1 (RFC 5737)
		"192.88.99.0/24",  // deprecated 6to4 relay anycast (RFC 7526), 6a44 (RFC 6751)
		"192.168.0.0/16",  // private use (RFC 1918)
		"198.18.0.0/15",   // benchmarking (RFC 2544)
		"198.51.100.0/24", // documentation, TEST-NET-2 (RFC 5737)
		"203.0.113.0/24",  // documentation, TEST-NET-3 (RFC 5737)
		"224.0.0.0/4",     // multicast (RFC 5771)
		"240.0.0.0/4",     // reserved (RFC 1112), incl. limited broadcast 255.255.255.255 (RFC 919, RFC 8190)
		// IPv6
		"::/96",           // unspecified ::/128, loopback ::1/128 (RFC 4291), deprecated IPv4-compatible (RFC 4291)
		"::ffff:0:0/96",   // IPv4-mapped (RFC 4291); listed for completeness: publicIP unmaps first and checks the IPv4 address
		"::ffff:0:0:0/96", // IPv4-translated (RFC 2765, obsoleted by RFC 6145 and RFC 6052)
		"64:ff9b:1::/48",  // local-use IPv4/IPv6 translation (RFC 8215)
		"100::/64",        // discard-only (RFC 6666)
		"100:0:0:1::/64",  // dummy IPv6 prefix (RFC 9780)
		"2001::/23",       // IETF protocol assignments (RFC 2928): Teredo, benchmarking, ORCHID, ...
		"2001:db8::/32",   // documentation (RFC 3849)
		"2002::/16",       // 6to4 (RFC 3056)
		"3fff::/20",       // documentation (RFC 9637)
		"5f00::/16",       // segment routing (SRv6) SIDs (RFC 9602)
		"fc00::/7",        // unique local (RFC 4193)
		"fe80::/10",       // link-local unicast (RFC 4291)
		"fec0::/10",       // deprecated site-local (RFC 3879)
		"ff00::/8",        // multicast (RFC 4291)
	} {
		ps = append(ps, netip.MustParsePrefix(c))
	}
	return ps
}()

// globalUnicast6 is the only IPv6 range from which IANA assigns global
// unicast addresses (IANA IPv6 Address Space registry, RFC 4291 §2.4).
// Everything else is reserved by the IETF, special purpose or multicast, so
// an IPv6 destination outside it is refused even if a future special-purpose
// block there is not yet listed above (5f00::/16 and 100:0:0:1::/64 were
// both assigned from such reserved space). The NAT64 prefix is handled before
// this check.
var globalUnicast6 = netip.MustParsePrefix("2000::/3")

// nat64 is the well-known NAT64 prefix (RFC 6052); the embedded IPv4 address
// is checked.
var nat64 = netip.MustParsePrefix("64:ff9b::/96")

// ipv4Translated is the IPv4-translated format of RFC 2765 (SIIT). The
// default policy refuses it whatever IPv4 address it embeds; its embedded
// IPv4 address is also matched against deny_cidrs (policyAddresses), and that
// match applies with allow_private too.
var ipv4Translated = netip.MustParsePrefix("::ffff:0:0:0/96")

// builtinPolicy describes the built-in part of the destination policy for
// PolicyFingerprint.
func builtinPolicy() string {
	parts := []string{"v6only=" + globalUnicast6.String(), "nat64=" + nat64.String(), "translated=" + ipv4Translated.String()}
	for _, p := range deniedPrefixes {
		parts = append(parts, p.String())
	}
	return strings.Join(parts, ",")
}

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
	if ip.Is6() && !globalUnicast6.Contains(ip) {
		return false
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
	// The cached address is re-checked outside the cache lock: the check
	// reads the node's interface addresses, and nothing it calls may leave
	// the lock held if it fails.
	rs.mu.Lock()
	c, ok := rs.cache[a.Host]
	rs.mu.Unlock()
	if ok && time.Now().Before(c.exp) && allowed(c.ip) {
		return netip.AddrPortFrom(c.ip, a.Port), StatusOK
	}
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
