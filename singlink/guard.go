package singlink

import (
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"time"
)

// guard bounds what unauthenticated peers can cost a node: connection
// slots, concurrent handshakes per IP, and the CPU spent on handshake
// cryptography (X25519 + ML-KEM decapsulation) for peers that keep failing.
type guard struct {
	slots   chan struct{} // all connections
	crypto  chan struct{} // concurrent first-flight decryptions
	perIP   int
	failMax float64

	mu     sync.Mutex
	ips    map[netip.Addr]*ipState
	failed map[[32]byte]struct{} // recently failed flight prefixes
}

type ipState struct {
	pending int
	fails   float64 // decays by failDecay per second
	last    time.Time
}

const failDecay = 10 // failures forgiven per second per IP

func newGuard(maxConns, perIP int) *guard {
	return &guard{
		slots:   make(chan struct{}, maxConns),
		crypto:  make(chan struct{}, 2*runtime.NumCPU()),
		perIP:   perIP,
		failMax: 50,
		ips:     map[netip.Addr]*ipState{},
		failed:  map[[32]byte]struct{}{},
	}
}

func remoteIP(c net.Conn) netip.Addr {
	if ap, err := netip.ParseAddrPort(c.RemoteAddr().String()); err == nil {
		return ap.Addr().Unmap()
	}
	return netip.Addr{}
}

func (g *guard) stateLocked(ip netip.Addr, now time.Time) *ipState {
	st := g.ips[ip]
	if st == nil {
		if len(g.ips) > 1<<16 {
			for k, v := range g.ips { // drop idle entries
				if v.pending == 0 {
					delete(g.ips, k)
				}
			}
		}
		st = &ipState{last: now}
		g.ips[ip] = st
	}
	st.fails = max(0, st.fails-now.Sub(st.last).Seconds()*failDecay)
	st.last = now
	return st
}

// begin registers a handshake from ip; false means the IP already has too
// many handshakes in progress.
func (g *guard) begin(ip netip.Addr) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	st := g.stateLocked(ip, time.Now())
	if st.pending >= g.perIP {
		return false
	}
	st.pending++
	return true
}

func (g *guard) end(ip netip.Addr) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if st := g.ips[ip]; st != nil {
		st.pending--
		if st.pending <= 0 && st.fails == 0 {
			delete(g.ips, ip)
		}
	}
}

// worthDecrypting reports whether a flight from ip should get the
// handshake cryptography at all. Flights from IPs that keep failing, and
// exact repeats of a flight that already failed, go straight to fallback.
func (g *guard) worthDecrypting(ip netip.Addr, flight []byte) bool {
	if len(flight) < firstFlightFixed {
		return true // parse rejects it without any cryptography
	}
	k := sha256.Sum256(flight[:firstFlightFixed])
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, seen := g.failed[k]; seen {
		return false
	}
	return g.stateLocked(ip, time.Now()).fails < g.failMax
}

func (g *guard) failedFlight(ip netip.Addr, flight []byte) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.stateLocked(ip, time.Now()).fails++
	if len(flight) >= firstFlightFixed {
		if len(g.failed) >= 4096 {
			clear(g.failed)
		}
		g.failed[sha256.Sum256(flight[:firstFlightFixed])] = struct{}{}
	}
}

// writeProxyV2 sends a PROXY protocol v2 header so the fallback website sees
// the real client address instead of the node's loopback address.
func writeProxyV2(w io.Writer, src, dst net.Addr) error {
	s, err1 := netip.ParseAddrPort(src.String())
	d, err2 := netip.ParseAddrPort(dst.String())
	hdr := []byte("\r\n\r\n\x00\r\nQUIT\n")
	if err1 != nil || err2 != nil {
		hdr = append(hdr, 0x20, 0x00, 0, 0) // LOCAL, no address
		_, err := w.Write(hdr)
		return err
	}
	sa, da := s.Addr().Unmap(), d.Addr().Unmap()
	var body []byte
	fam := byte(0x11) // TCP over IPv4
	if sa.Is4() && da.Is4() {
		a, b := sa.As4(), da.As4()
		body = append(append(body, a[:]...), b[:]...)
	} else {
		fam = 0x21 // TCP over IPv6
		a, b := sa.As16(), da.As16()
		body = append(append(body, a[:]...), b[:]...)
	}
	body = binary.BigEndian.AppendUint16(body, s.Port())
	body = binary.BigEndian.AppendUint16(body, d.Port())
	hdr = append(hdr, 0x21, fam)
	hdr = binary.BigEndian.AppendUint16(hdr, uint16(len(body)))
	_, err := w.Write(append(hdr, body...))
	return err
}
