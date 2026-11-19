// Copyright 2026 SingLinkVPN (https://singlinkvpn.com)
// SPDX-License-Identifier: Apache-2.0

package socks5

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// udpEcho is a UDP echo target; seen records every payload it received.
type udpEcho struct {
	conn *net.UDPConn
	mu   sync.Mutex
	seen [][]byte
}

func newUDPEcho(t *testing.T) *udpEcho {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	e := &udpEcho{conn: c}
	go func() {
		b := make([]byte, 1500)
		for {
			n, from, err := c.ReadFromUDP(b)
			if err != nil {
				return
			}
			e.mu.Lock()
			e.seen = append(e.seen, append([]byte(nil), b[:n]...))
			e.mu.Unlock()
			c.WriteToUDP(b[:n], from)
		}
	}()
	return e
}

func (e *udpEcho) received(payload string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, b := range e.seen {
		if string(b) == payload {
			return true
		}
	}
	return false
}

// associate opens a SOCKS5 control connection (with RFC 1929 credentials if
// user is set) and sends UDP ASSOCIATE declaring declared (IPv4 or IPv6).
// It returns the control connection, the reply code and the relay address.
func associate(t *testing.T, proxy, user, pass string, declared *net.UDPAddr) (net.Conn, byte, *net.UDPAddr) {
	t.Helper()
	ctl, err := net.Dial("tcp", proxy)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ctl.Close() })
	ctl.SetDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 64)
	if user == "" {
		ctl.Write([]byte{5, 1, 0})
	} else {
		ctl.Write([]byte{5, 1, 2})
	}
	if _, err := io.ReadFull(ctl, buf[:2]); err != nil {
		t.Fatal(err)
	}
	if user != "" {
		ctl.Write(append(append(append([]byte{1, byte(len(user))}, user...), byte(len(pass))), pass...))
		if _, err := io.ReadFull(ctl, buf[:2]); err != nil || buf[1] != 0 {
			t.Fatalf("auth %v %v", buf[:2], err)
		}
	}
	req := []byte{5, 3, 0}
	if ip4 := declared.IP.To4(); ip4 != nil {
		req = append(append(req, 1), ip4...)
	} else {
		req = append(append(req, 4), declared.IP.To16()...)
	}
	req = append(req, byte(declared.Port>>8), byte(declared.Port))
	ctl.Write(req)
	if _, err := io.ReadFull(ctl, buf[:4]); err != nil {
		t.Fatal(err)
	}
	rep := buf[1]
	var relay *net.UDPAddr
	switch buf[3] {
	case 1:
		io.ReadFull(ctl, buf[:6])
		relay = &net.UDPAddr{IP: net.IP(append([]byte(nil), buf[:4]...)), Port: int(buf[4])<<8 | int(buf[5])}
	case 4:
		io.ReadFull(ctl, buf[:18])
		relay = &net.UDPAddr{IP: net.IP(append([]byte(nil), buf[:16]...)), Port: int(buf[16])<<8 | int(buf[17])}
	}
	return ctl, rep, relay
}

func udpClient(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// sendVia sends payload to target through the relay and reports whether the
// echo came back to c within wait.
func sendVia(c *net.UDPConn, relay *net.UDPAddr, target *net.UDPAddr, payload string, wait time.Duration) bool {
	pkt := append([]byte{0, 0, 0, 1}, target.IP.To4()...)
	pkt = append(pkt, byte(target.Port>>8), byte(target.Port))
	pkt = append(pkt, payload...)
	deadline := time.Now().Add(wait)
	b := make([]byte, 1500)
	for time.Now().Before(deadline) {
		c.WriteToUDP(pkt, relay)
		c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		for {
			n, _, err := c.ReadFromUDP(b)
			if err != nil {
				break
			}
			if n >= 10 && string(b[10:n]) == payload {
				return true
			}
		}
	}
	return false
}

// With a declared client address (RFC 1928), the association belongs to that
// port only: another local socket, even one that sends first, can neither
// use the association nor receive its replies. With and without auth.
func TestUDPAssociateBoundToDeclaredPort(t *testing.T) {
	for _, auth := range []bool{false, true} {
		t.Run(fmt.Sprintf("auth=%v", auth), func(t *testing.T) {
			s, addr := newTestServer(t)
			defer s.Close()
			user, pass := "", ""
			if auth {
				user, pass = "user", "secret"
				s.Username, s.Password = user, pass
			}
			echo := newUDPEcho(t)
			target := echo.conn.LocalAddr().(*net.UDPAddr)
			legit := udpClient(t)
			hijacker := udpClient(t)

			declared := legit.LocalAddr().(*net.UDPAddr)
			_, rep, relay := associate(t, addr, user, pass, declared)
			if rep != repOK || relay == nil {
				t.Fatalf("associate reply %d", rep)
			}
			// The other socket races first and keeps trying.
			if sendVia(hijacker, relay, target, "hijack-1", time.Second) {
				t.Fatal("a socket on another port used the association")
			}
			if !sendVia(legit, relay, target, "legit", 5*time.Second) {
				t.Fatal("the declared client cannot use the association")
			}
			if sendVia(hijacker, relay, target, "hijack-2", 500*time.Millisecond) {
				t.Fatal("a socket on another port used the association")
			}
			if echo.received("hijack-1") || echo.received("hijack-2") {
				t.Fatal("datagrams from another port were relayed")
			}
		})
	}
}

// The declared address may leave the IP unspecified (0.0.0.0:port or
// [::]:port, common for clients bound to the wildcard address): the port
// still binds the association, the IP must be the control connection's.
func TestUDPAssociateDeclaredPortWildcardIP(t *testing.T) {
	s, addr := newTestServer(t)
	defer s.Close()
	echo := newUDPEcho(t)
	target := echo.conn.LocalAddr().(*net.UDPAddr)
	legit := udpClient(t)
	hijacker := udpClient(t)
	port := legit.LocalAddr().(*net.UDPAddr).Port
	_, rep, relay := associate(t, addr, "", "", &net.UDPAddr{IP: net.IPv4zero, Port: port})
	if rep != repOK {
		t.Fatalf("associate reply %d", rep)
	}
	if sendVia(hijacker, relay, target, "hijack", time.Second) {
		t.Fatal("a socket on another port used the association")
	}
	if !sendVia(legit, relay, target, "legit", 5*time.Second) {
		t.Fatal("the declared client cannot use the association")
	}
}

// With authentication on, an association must declare its client port: with
// 0.0.0.0:0 or [::]:0 the first datagram from any local port would claim it,
// which would let an unauthenticated process use the authenticated tunnel.
func TestUDPAssociateUndeclaredRefusedWithAuth(t *testing.T) {
	s, addr := newTestServer(t)
	defer s.Close()
	s.Username, s.Password = "user", "secret"
	for _, declared := range []*net.UDPAddr{{IP: net.IPv4zero, Port: 0}, {IP: net.IPv6zero, Port: 0}} {
		_, rep, _ := associate(t, addr, "user", "secret", declared)
		if rep != repNotAllowed {
			t.Fatalf("%v: reply %d, want %d (not allowed)", declared, rep, repNotAllowed)
		}
	}
}

// Without authentication, 0.0.0.0:0 keeps working for compatibility: the
// first datagram from the control connection's IP claims the association
// and later datagrams from other ports are ignored. (Any local process can
// open its own association on an unauthenticated port anyway.)
func TestUDPAssociateUndeclaredWithoutAuthFirstPortWins(t *testing.T) {
	s, addr := newTestServer(t)
	defer s.Close()
	echo := newUDPEcho(t)
	target := echo.conn.LocalAddr().(*net.UDPAddr)
	first := udpClient(t)
	other := udpClient(t)
	_, rep, relay := associate(t, addr, "", "", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if rep != repOK {
		t.Fatalf("associate reply %d", rep)
	}
	if !sendVia(first, relay, target, "first", 5*time.Second) {
		t.Fatal("the first client cannot use the association")
	}
	if sendVia(other, relay, target, "other", 500*time.Millisecond) || echo.received("other") {
		t.Fatal("a second port used a claimed association")
	}
}

// A plain HTTP request is forwarded alone: bytes the client pipelines after
// it (for example a second request carrying Proxy-Authorization, or one for
// another host) must never reach the first request's origin.
func TestHTTPProxyForwardsOnlyTheAuthenticatedRequest(t *testing.T) {
	s, addr := newTestServer(t)
	defer s.Close()
	s.Username, s.Password = "user", "secret"

	origin, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	got := make(chan []byte, 1)
	go func() {
		c, err := origin.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		var all bytes.Buffer
		br := bufio.NewReader(c)
		// Read the first request's header, answer, then keep reading
		// whatever else arrives for a moment.
		for {
			line, err := br.ReadString('\n')
			all.WriteString(line)
			if err != nil || line == "\r\n" {
				break
			}
		}
		io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
		c.SetReadDeadline(time.Now().Add(time.Second))
		io.Copy(&all, br)
		got <- all.Bytes()
	}()

	cred := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:secret"))
	target := origin.Addr().String()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(c, "GET http://%s/one HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\n\r\n"+
		"GET http://other.invalid/two HTTP/1.1\r\nHost: other.invalid\r\nProxy-Authorization: %s\r\n\r\n",
		target, target, cred, cred)
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("first request: %v %v", resp, err)
	}
	resp.Body.Close()
	var seen []byte
	select {
	case seen = <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("origin never saw the request")
	}
	if strings.Count(string(seen), "GET ") != 1 || strings.Contains(strings.ToLower(string(seen)), "proxy-authorization") {
		t.Fatalf("origin received more than the first request:\n%s", seen)
	}
}

// Some clients (sing-box, for example) put the first destination, not their
// own address, into the request. Such a request is undeclared: without auth
// the first source port claims the association as before; with auth it is
// refused with an explicit error instead of silently dropping datagrams.
// A host name is undeclared as well.
func TestUDPAssociateDestinationInRequestIsUndeclared(t *testing.T) {
	for _, auth := range []bool{false, true} {
		t.Run(fmt.Sprintf("auth=%v", auth), func(t *testing.T) {
			s, addr := newTestServer(t)
			defer s.Close()
			user, pass := "", ""
			if auth {
				user, pass = "user", "secret"
				s.Username, s.Password = user, pass
			}
			echo := newUDPEcho(t)
			target := echo.conn.LocalAddr().(*net.UDPAddr)
			client := udpClient(t)
			// The destination is a loopback address too, but not the
			// control connection's IP.
			declared := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: target.Port}
			_, rep, relay := associate(t, addr, user, pass, declared)
			if auth {
				if rep != repNotAllowed {
					t.Fatalf("reply %d, want %d (not allowed)", rep, repNotAllowed)
				}
				return
			}
			if rep != repOK {
				t.Fatalf("reply %d", rep)
			}
			if !sendVia(client, relay, target, "dest-declared", 5*time.Second) {
				t.Fatal("a client that declares its destination gets no relay")
			}
		})
	}
}

// The relayed answer to a plain request is marked "Connection: close", and
// the proxy releases the upstream stream after that one response even when
// the origin keeps its connection open.
func TestHTTPProxyOneResponseThenClose(t *testing.T) {
	s, addr := newTestServer(t)
	defer s.Close()
	origin, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	go func() {
		c, err := origin.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		br := bufio.NewReader(c)
		if _, err := http.ReadRequest(br); err != nil {
			return
		}
		// Keep-alive answer; the origin then waits and never closes first.
		io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
		c.SetReadDeadline(time.Now().Add(10 * time.Second))
		io.Copy(io.Discard, br)
	}()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(c, "GET http://%s/x HTTP/1.1\r\nHost: %s\r\n\r\n", origin.Addr(), origin.Addr())
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("response %v %v", resp, err)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok" || !resp.Close {
		t.Fatalf("body %q, Connection: close %v", body, resp.Close)
	}
	// The proxy closes the client connection itself.
	if _, err := br.ReadByte(); err != io.EOF {
		t.Fatalf("client connection still open after the response: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		s.mu.Lock()
		n := len(s.open)
		s.mu.Unlock()
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d connections still tracked after the response", n)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
