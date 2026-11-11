package socks5

import (
	"context"
	"crypto/ed25519"
	"io"
	"net"
	"testing"
	"time"

	"github.com/SingLinkLabs/singlink-protocol/singlink"
)

func TestSOCKS5ConnectAndUDP(t *testing.T) {
	key, _ := singlink.GenerateServerKey()
	issuer, _ := singlink.GenerateEd25519()
	device, _ := singlink.GenerateEd25519()
	srv, err := singlink.NewServer(singlink.ServerConfig{Key: key, Issuers: singlink.NewIssuers(issuer.Public().(ed25519.PublicKey)), AllowPrivate: true})
	if err != nil {
		t.Fatal(err)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go srv.Serve(ln)
	tok, _ := singlink.IssueToken(issuer, &singlink.Token{DevicePub: device.Public().(ed25519.PublicKey), Caps: singlink.CapTCP | singlink.CapUDP,
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)})
	c := singlink.NewClient(&singlink.Profile{Server: ln.Addr().String(), Transport: "tcp", ServerKey: key.Public(), Token: tok, Device: device})

	s := &Server{Client: c}
	addr, err := s.Start("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// TCP echo target.
	echo, _ := net.Listen("tcp", "127.0.0.1:0")
	defer echo.Close()
	go func() {
		for {
			e, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer e.Close(); io.Copy(e, e) }()
		}
	}()

	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	conn.Write([]byte{5, 1, 0})
	buf := make([]byte, 64)
	io.ReadFull(conn, buf[:2])
	ea := echo.Addr().(*net.TCPAddr)
	req := []byte{5, 1, 0, 1}
	req = append(req, ea.IP.To4()...)
	req = append(req, byte(ea.Port>>8), byte(ea.Port))
	conn.Write(req)
	if _, err := io.ReadFull(conn, buf[:10]); err != nil || buf[1] != 0 {
		t.Fatalf("connect reply %v %v", buf[:10], err)
	}
	conn.Write([]byte("through socks"))
	if _, err := io.ReadFull(conn, buf[:13]); err != nil || string(buf[:13]) != "through socks" {
		t.Fatalf("echo %q %v", buf[:13], err)
	}

	// UDP ASSOCIATE.
	uecho, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer uecho.Close()
	go func() {
		b := make([]byte, 1500)
		for {
			n, from, err := uecho.ReadFromUDP(b)
			if err != nil {
				return
			}
			uecho.WriteToUDP(b[:n], from)
		}
	}()
	ctl, _ := net.Dial("tcp", addr.String())
	defer ctl.Close()
	ctl.SetDeadline(time.Now().Add(10 * time.Second))
	ctl.Write([]byte{5, 1, 0})
	io.ReadFull(ctl, buf[:2])
	ctl.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	if _, err := io.ReadFull(ctl, buf[:10]); err != nil || buf[1] != 0 {
		t.Fatalf("associate reply %v %v", buf[:10], err)
	}
	relay := &net.UDPAddr{IP: net.IP(buf[4:8]), Port: int(buf[8])<<8 | int(buf[9])}
	uc, _ := net.DialUDP("udp", nil, relay)
	defer uc.Close()
	ua := uecho.LocalAddr().(*net.UDPAddr)
	pkt := []byte{0, 0, 0, 1}
	pkt = append(pkt, ua.IP.To4()...)
	pkt = append(pkt, byte(ua.Port>>8), byte(ua.Port))
	pkt = append(pkt, "dgram"...)
	uc.SetDeadline(time.Now().Add(5 * time.Second))
	uc.Write(pkt)
	n, err := uc.Read(buf)
	if err != nil || string(buf[10:n]) != "dgram" {
		t.Fatalf("udp reply %q %v", buf[:n], err)
	}
	_ = context.Background
}

func newTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	key, _ := singlink.GenerateServerKey()
	issuer, _ := singlink.GenerateEd25519()
	device, _ := singlink.GenerateEd25519()
	srv, _ := singlink.NewServer(singlink.ServerConfig{Key: key, Issuers: singlink.NewIssuers(issuer.Public().(ed25519.PublicKey)), AllowPrivate: true})
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	t.Cleanup(func() { ln.Close() })
	go srv.Serve(ln)
	tok, _ := singlink.IssueToken(issuer, &singlink.Token{DevicePub: device.Public().(ed25519.PublicKey), Caps: singlink.CapTCP | singlink.CapUDP,
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)})
	c := singlink.NewClient(&singlink.Profile{Server: ln.Addr().String(), Transport: "tcp", ServerKey: key.Public(), Token: tok, Device: device})
	s := &Server{Client: c}
	addr, err := s.Start("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return s, addr.String()
}

// I-11: Close must not hang while a CONNECT is open.
func TestCloseWithOpenConnect(t *testing.T) {
	s, addr := newTestServer(t)
	hold, _ := net.Listen("tcp", "127.0.0.1:0")
	defer hold.Close()
	go func() {
		for {
			c, err := hold.Accept()
			if err != nil {
				return
			}
			defer c.Close() // silent target
		}
	}()
	conn, _ := net.Dial("tcp", addr)
	defer conn.Close()
	conn.Write([]byte{5, 1, 0})
	buf := make([]byte, 16)
	io.ReadFull(conn, buf[:2])
	ha := hold.Addr().(*net.TCPAddr)
	conn.Write(append(append([]byte{5, 1, 0, 1}, ha.IP.To4()...), byte(ha.Port>>8), byte(ha.Port)))
	io.ReadFull(conn, buf[:10])
	conn.Write([]byte("data"))
	time.Sleep(300 * time.Millisecond)
	done := make(chan struct{})
	go func() { s.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Close hung with an open CONNECT")
	}
}

// I-10: optional username/password.
func TestAuth(t *testing.T) {
	s, addr := newTestServer(t)
	defer s.Close()
	s.Username, s.Password = "u", "p"
	try := func(methods []byte, user, pass string) bool {
		c, _ := net.Dial("tcp", addr)
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		c.Write(append([]byte{5, byte(len(methods))}, methods...))
		r := make([]byte, 2)
		if _, err := io.ReadFull(c, r); err != nil || r[1] != 2 {
			return false
		}
		c.Write(append(append(append([]byte{1, byte(len(user))}, user...), byte(len(pass))), pass...))
		if _, err := io.ReadFull(c, r); err != nil {
			return false
		}
		return r[1] == 0
	}
	if try([]byte{0}, "", "") {
		t.Fatal("no-auth accepted")
	}
	if try([]byte{2}, "u", "wrong") {
		t.Fatal("wrong password accepted")
	}
	if !try([]byte{0, 2}, "u", "p") {
		t.Fatal("correct password refused")
	}
}
