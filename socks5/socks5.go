// Package socks5 is a minimal local SOCKS5 inbound (CONNECT and UDP
// ASSOCIATE, no authentication) that forwards everything through an SingLink
// client. It is meant to listen on loopback only.
package socks5

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/SingLinkLabs/singlink-protocol/singlink"
)

// Server accepts SOCKS5 clients.
type Server struct {
	Client *singlink.Client
	// Username and Password, if set, require RFC 1929 authentication so
	// other local users and apps cannot borrow the tunnel.
	Username, Password string
	// MaxSessions caps concurrent client connections (default 512).
	MaxSessions int

	mu     sync.Mutex
	ln     net.Listener
	wg     sync.WaitGroup
	closed bool
	open   map[io.Closer]struct{}
}

// ListenAndServe listens on addr and serves until Close.
func (s *Server) ListenAndServe(addr string) error {
	a, err := s.Start(addr)
	if err != nil {
		return err
	}
	_ = a
	s.wg.Wait()
	return nil
}

// Start listens on addr and serves in the background.
func (s *Server) Start(addr string) (net.Addr, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		ln.Close()
		return nil, net.ErrClosed
	}
	s.ln = ln
	if s.open == nil {
		s.open = map[io.Closer]struct{}{}
	}
	if s.MaxSessions == 0 {
		s.MaxSessions = 512
	}
	s.wg.Add(1)
	s.mu.Unlock()
	go func() {
		defer s.wg.Done()
		s.serve(ln)
	}()
	return ln.Addr(), nil
}

func (s *Server) serve(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed || errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if !s.track(c, true) {
			c.Close()
			continue
		}
		go func() {
			defer s.wg.Done()
			defer s.untrack(c)
			defer c.Close()
			s.handle(c)
		}()
	}
}

// track registers a closer; it fails once the server is closed or full.
// Accepted client connections (handler != false) also take a WaitGroup slot.
func (s *Server) track(c io.Closer, handler ...bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	if len(handler) > 0 && handler[0] {
		if len(s.open) >= s.MaxSessions*3 {
			return false
		}
		s.wg.Add(1)
	}
	s.open[c] = struct{}{}
	return true
}

func (s *Server) untrack(c io.Closer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.open, c)
}

// Close stops the listener and every open connection, including the
// tunnels to the node, and waits for all handlers to return.
func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	if s.ln != nil {
		s.ln.Close()
	}
	for c := range s.open {
		c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
	return nil
}

const (
	cmdConnect   = 1
	cmdAssociate = 3

	repOK          = 0
	repFailure     = 1
	repNotAllowed  = 2
	repHostUnreach = 4
	repCmdNotSupp  = 7
)

func (s *Server) handle(c net.Conn) {
	c.SetDeadline(time.Now().Add(15 * time.Second))
	var h [2]byte
	if _, err := io.ReadFull(c, h[:]); err != nil || h[0] != 5 {
		return
	}
	methods := make([]byte, h[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	want := byte(0) // no authentication
	if s.Username != "" {
		want = 2 // username/password
	}
	ok := false
	for _, m := range methods {
		ok = ok || m == want
	}
	if !ok {
		c.Write([]byte{5, 0xff})
		return
	}
	c.Write([]byte{5, want})
	if want == 2 && !s.checkAuth(c) {
		return
	}

	var req [3]byte
	if _, err := io.ReadFull(c, req[:]); err != nil || req[0] != 5 {
		return
	}
	dst, err := readAddr(c)
	if err != nil {
		return
	}
	c.SetDeadline(time.Time{})
	switch req[1] {
	case cmdConnect:
		s.connect(c, dst)
	case cmdAssociate:
		s.associate(c)
	default:
		reply(c, repCmdNotSupp, nil)
	}
}

// checkAuth runs the RFC 1929 sub-negotiation.
func (s *Server) checkAuth(c net.Conn) bool {
	var h [2]byte
	if _, err := io.ReadFull(c, h[:]); err != nil || h[0] != 1 {
		return false
	}
	user := make([]byte, h[1])
	if _, err := io.ReadFull(c, user); err != nil {
		return false
	}
	var pl [1]byte
	if _, err := io.ReadFull(c, pl[:]); err != nil {
		return false
	}
	pass := make([]byte, pl[0])
	if _, err := io.ReadFull(c, pass); err != nil {
		return false
	}
	good := subtle.ConstantTimeCompare(user, []byte(s.Username))&subtle.ConstantTimeCompare(pass, []byte(s.Password)) == 1
	if !good {
		c.Write([]byte{1, 1})
		return false
	}
	c.Write([]byte{1, 0})
	return true
}

func (s *Server) connect(c net.Conn, dst string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	up, err := s.Client.DialTCP(ctx, dst)
	cancel()
	if err != nil {
		reply(c, repHostUnreach, nil)
		return
	}
	defer up.Close()
	if !s.track(up) {
		return
	}
	defer s.untrack(up)
	s.Client.Stats.Conns.Add(1)
	defer s.Client.Stats.Conns.Add(-1)
	// Reply before the SingLink request is answered so the application's first
	// bytes can ride in the 0-RTT first flight.
	reply(c, repOK, nil)
	pipe(c, up)
}

func (s *Server) associate(c net.Conn) {
	local, ok := c.LocalAddr().(*net.TCPAddr)
	if !ok {
		reply(c, repFailure, nil)
		return
	}
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: local.IP})
	if err != nil {
		reply(c, repFailure, nil)
		return
	}
	defer uc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	pc, err := s.Client.DialUDP(ctx)
	cancel()
	if err != nil {
		var se *singlink.StatusError
		if errors.As(err, &se) && se.Code == singlink.StatusCapDenied {
			reply(c, repNotAllowed, nil)
		} else {
			reply(c, repFailure, nil)
		}
		return
	}
	defer pc.Close()
	if !s.track(pc) {
		return
	}
	defer s.untrack(pc)
	s.Client.Stats.Conns.Add(1)
	defer s.Client.Stats.Conns.Add(-1)
	reply(c, repOK, uc.LocalAddr().(*net.UDPAddr))

	var peerMu sync.Mutex
	var peer netip.AddrPort
	ctlIP := netip.Addr{}
	if ap, err := netip.ParseAddrPort(c.RemoteAddr().String()); err == nil {
		ctlIP = ap.Addr().Unmap()
	}
	done := make(chan struct{})
	go func() {
		// The association lives as long as the TCP control connection.
		io.Copy(io.Discard, c)
		close(done)
		uc.Close()
		pc.Close()
	}()
	go func() {
		for {
			b, from, err := pc.ReadFrom()
			if err != nil {
				uc.Close()
				return
			}
			peerMu.Lock()
			p := peer
			peerMu.Unlock()
			if !p.IsValid() {
				continue
			}
			out := append([]byte{0, 0, 0}, encodeAddr(from)...)
			uc.WriteToUDPAddrPort(append(out, b...), p)
		}
	}()
	buf := make([]byte, 65536)
	for {
		n, from, err := uc.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		pkt := buf[:n]
		if n < 4 || pkt[2] != 0 { // fragmentation is not supported
			continue
		}
		dst, rest, err := parseAddr(pkt[3:])
		if err != nil {
			continue
		}
		// Only the application that opened the association may use it:
		// same IP as the control connection, first source port wins.
		peerMu.Lock()
		if from.Addr().Unmap() != ctlIP || (peer.IsValid() && peer != from) {
			peerMu.Unlock()
			continue
		}
		peer = from
		peerMu.Unlock()
		a, err := singlink.ParseAddr(dst)
		if err != nil {
			continue
		}
		if pc.WriteTo(rest, a) != nil {
			return
		}
	}
}

func pipe(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		_, err := io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok && err == nil {
			cw.CloseWrite()
			return
		}
		// Error or truncation: tear down both sides.
		a.Close()
		b.Close()
	}
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
}

func reply(c net.Conn, rep byte, bind *net.UDPAddr) {
	b := []byte{5, rep, 0}
	if bind == nil {
		b = append(b, 1, 0, 0, 0, 0, 0, 0)
	} else {
		ap := bind.AddrPort()
		b = append(b, encodeAddr(singlink.AddrFromAddrPort(ap))...)
	}
	c.Write(b)
}

func readAddr(r io.Reader) (string, error) {
	var t [1]byte
	if _, err := io.ReadFull(r, t[:]); err != nil {
		return "", err
	}
	var host string
	switch t[0] {
	case 1:
		var b [4]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", err
		}
		host = netip.AddrFrom4(b).String()
	case 4:
		var b [16]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", err
		}
		host = netip.AddrFrom16(b).String()
	case 3:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return "", err
		}
		b := make([]byte, l[0])
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		host = string(b)
	default:
		return "", errors.New("socks5: bad address type")
	}
	var p [2]byte
	if _, err := io.ReadFull(r, p[:]); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(p[:])))), nil
}

func parseAddr(b []byte) (string, []byte, error) {
	r := &sliceReader{b: b}
	s, err := readAddr(r)
	return s, r.b, err
}

type sliceReader struct{ b []byte }

func (r *sliceReader) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.b)
	r.b = r.b[n:]
	return n, nil
}

func encodeAddr(a singlink.Addr) []byte {
	var b []byte
	switch {
	case a.IP.Is4():
		ip := a.IP.As4()
		b = append([]byte{1}, ip[:]...)
	case a.IP.Is6():
		ip := a.IP.As16()
		b = append([]byte{4}, ip[:]...)
	default:
		b = append([]byte{3, byte(len(a.Host))}, a.Host...)
	}
	return binary.BigEndian.AppendUint16(b, a.Port)
}
