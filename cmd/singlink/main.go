// Copyright 2026 SingLinkLabs (https://github.com/SingLinkLabs)
// SPDX-License-Identifier: Apache-2.0

// Command singlink is the SingLink Protocol reference node, client and key tool.
package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/SingLinkLabs/singlink-protocol/engine"
	"github.com/SingLinkLabs/singlink-protocol/singlink"
)

const usage = `singlink — SingLink Protocol protocol tool (` + singlink.Version + `)

Usage:
  singlink keygen server|issuer|device      generate a key pair (JSON)
  singlink token issue [flags]              sign a permission token
  singlink token inspect <token>            decode a token
  singlink link [flags]                     build an singlink:// client link
  singlink server -c server.json            run a node
  singlink client -link <singlink://...> [-listen 127.0.0.1:1080]
  singlink demo [-listen 127.0.0.1:1080]    local node + client in one process

Run "singlink <command> -h" for flags.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	args := os.Args[2:]
	switch os.Args[1] {
	case "keygen":
		err = keygen(args)
	case "token":
		err = token(args)
	case "link":
		err = link(args)
	case "server":
		err = server(args)
	case "client":
		err = client(args)
	case "demo":
		err = demo(args)
	case "version", "-v", "--version":
		fmt.Println(singlink.Version, singlink.ProtocolName)
		fmt.Println("Copyright 2026 SingLinkLabs · Apache-2.0 · https://github.com/SingLinkLabs/singlink-protocol")
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func printJSON(v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(b))
}

func keygen(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: singlink keygen server|issuer|device")
	}
	switch args[0] {
	case "server":
		k, err := singlink.GenerateServerKey()
		if err != nil {
			return err
		}
		printJSON(map[string]string{
			"private_key": singlink.B64.EncodeToString(k.Bytes()),
			"public_key":  singlink.B64.EncodeToString(k.Public().Bytes()),
		})
	case "issuer", "device":
		k, err := singlink.GenerateEd25519()
		if err != nil {
			return err
		}
		pub := k.Public().(ed25519.PublicKey)
		m := map[string]any{"seed": singlink.B64.EncodeToString(k.Seed()), "public_key": singlink.B64.EncodeToString(pub)}
		if args[0] == "issuer" {
			m["key_id"] = fmt.Sprintf("%08x", singlink.IssuerKeyID(pub))
		}
		printJSON(m)
	default:
		return errors.New("usage: singlink keygen server|issuer|device")
	}
	return nil
}

func parseCaps(s string) (uint32, error) {
	var caps uint32
	for _, c := range strings.Split(s, ",") {
		switch strings.TrimSpace(c) {
		case "tcp":
			caps |= singlink.CapTCP
		case "udp":
			caps |= singlink.CapUDP
		case "":
		default:
			return 0, fmt.Errorf("unknown capability %q", c)
		}
	}
	return caps, nil
}

func token(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: singlink token issue|inspect")
	}
	switch args[0] {
	case "inspect":
		if len(args) != 2 {
			return errors.New("usage: singlink token inspect <token>")
		}
		b, err := singlink.B64.DecodeString(args[1])
		if err != nil {
			return err
		}
		t, err := singlink.ParseToken(b)
		if err != nil {
			return err
		}
		printJSON(tokenJSON(t))
		return nil
	case "issue":
		fs := flag.NewFlagSet("token issue", flag.ExitOnError)
		issuerSeed := fs.String("issuer", "", "issuer seed (base64url)")
		devicePub := fs.String("device", "", "device public key (base64url)")
		subject := fs.String("subject", "", "subject id, 32 hex chars (random if empty)")
		days := fs.Float64("days", 1, "validity in days (keep short; the app renews tokens)")
		caps := fs.String("caps", "tcp,udp", "capabilities")
		rate := fs.Uint("rate", 0, "rate limit in kbit/s (0 = unlimited)")
		maxConns := fs.Uint("max-conns", 0, "max concurrent connections (0 = unlimited)")
		plan := fs.Uint("plan", 0, "plan id")
		fs.Parse(args[1:])
		seed, err := singlink.B64.DecodeString(*issuerSeed)
		if err != nil {
			return errors.New("bad -issuer")
		}
		issuer, err := singlink.Ed25519FromSeed(seed)
		if err != nil {
			return err
		}
		dp, err := singlink.B64.DecodeString(*devicePub)
		if err != nil || len(dp) != ed25519.PublicKeySize {
			return errors.New("bad -device")
		}
		c, err := parseCaps(*caps)
		if err != nil {
			return err
		}
		t := &singlink.Token{
			DevicePub: dp,
			NotBefore: time.Now().Add(-5 * time.Minute),
			NotAfter:  time.Now().Add(time.Duration(*days * float64(24*time.Hour))),
			Caps:      c, RateKbps: uint32(*rate), MaxConns: uint16(*maxConns), Plan: uint8(*plan),
		}
		if *subject != "" {
			b, err := hex.DecodeString(*subject)
			if err != nil || len(b) != 16 {
				return errors.New("-subject must be 32 hex characters")
			}
			copy(t.Subject[:], b)
		} else {
			rand.Read(t.Subject[:])
		}
		raw, err := singlink.IssueToken(issuer, t)
		if err != nil {
			return err
		}
		fmt.Println(singlink.B64.EncodeToString(raw))
		return nil
	}
	return errors.New("usage: singlink token issue|inspect")
}

func tokenJSON(t *singlink.Token) map[string]any {
	return map[string]any{
		"key_id":     fmt.Sprintf("%08x", t.KeyID),
		"token_id":   hex.EncodeToString(t.ID[:]),
		"subject":    hex.EncodeToString(t.Subject[:]),
		"device":     singlink.B64.EncodeToString(t.DevicePub),
		"not_before": t.NotBefore.UTC().Format(time.RFC3339),
		"not_after":  t.NotAfter.UTC().Format(time.RFC3339),
		"tcp":        t.Has(singlink.CapTCP),
		"udp":        t.Has(singlink.CapUDP),
		"rate_kbps":  t.RateKbps,
		"max_conns":  t.MaxConns,
		"plan":       t.Plan,
	}
}

func link(args []string) error {
	fs := flag.NewFlagSet("link", flag.ExitOnError)
	server := fs.String("server", "", "node host:port")
	pk := fs.String("pk", "", "node public key (base64url)")
	tok := fs.String("token", "", "token (base64url)")
	dev := fs.String("device", "", "device seed (base64url)")
	tr := fs.String("tr", "tls", "transport: tls or tcp")
	sni := fs.String("sni", "", "TLS server name")
	pin := fs.String("pin", "", "certificate SHA-256 pin (base64url)")
	name := fs.String("name", "", "display name")
	fs.Parse(args)
	p := &singlink.Profile{Name: *name, Server: *server, Transport: *tr, SNI: *sni}
	var err error
	b, err := singlink.B64.DecodeString(*pk)
	if err != nil {
		return errors.New("bad -pk")
	}
	if p.ServerKey, err = singlink.ParseServerPublicKey(b); err != nil {
		return err
	}
	if p.Token, err = singlink.B64.DecodeString(*tok); err != nil {
		return errors.New("bad -token")
	}
	seed, err := singlink.B64.DecodeString(*dev)
	if err != nil {
		return errors.New("bad -device")
	}
	if p.Device, err = singlink.Ed25519FromSeed(seed); err != nil {
		return err
	}
	if *pin != "" {
		if p.Pin, err = singlink.B64.DecodeString(*pin); err != nil {
			return errors.New("bad -pin")
		}
	}
	l := p.Link()
	if _, err := singlink.ParseLink(l); err != nil {
		return err
	}
	fmt.Println(l)
	return nil
}

type serverFile struct {
	Listen                string   `json:"listen"`
	PrivateKey            string   `json:"private_key"`
	OldPrivateKeys        []string `json:"old_private_keys"`
	Issuers               []string `json:"issuers"`
	TLSCert               string   `json:"tls_cert"`
	TLSKey                string   `json:"tls_key"`
	Fallback              string   `json:"fallback"`
	FallbackProxyProtocol bool     `json:"fallback_proxy_protocol"`
	AllowPrivate          bool     `json:"allow_private"`
	DenyCIDRs             []string `json:"deny_cidrs"`
	BlockedPorts          []uint16 `json:"blocked_ports"`
	AllowSMTP             bool     `json:"allow_smtp"`
	MaxConnections        int      `json:"max_connections"`
	RevokedFile           string   `json:"revoked_file"`
	LogLevel              string   `json:"log_level"`
}

func parseServerKey(s string) (*singlink.ServerPrivateKey, error) {
	kb, err := singlink.B64.DecodeString(s)
	if err != nil {
		return nil, errors.New("bad private key encoding")
	}
	return singlink.ParseServerPrivateKey(kb)
}

func server(args []string) error {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	path := fs.String("c", "server.json", "config file (systemd: $CREDENTIALS_DIRECTORY/server.json)")
	fs.Parse(args)
	b, err := os.ReadFile(*path)
	if err != nil {
		return err
	}
	var f serverFile
	if err := json.Unmarshal(b, &f); err != nil {
		return err
	}
	key, err := parseServerKey(f.PrivateKey)
	if err != nil {
		return fmt.Errorf("private_key: %w", err)
	}
	var old []*singlink.ServerPrivateKey
	for i, k := range f.OldPrivateKeys {
		ok, err := parseServerKey(k)
		if err != nil {
			return fmt.Errorf("old_private_keys[%d]: %w", i, err)
		}
		old = append(old, ok)
	}
	var deny []netip.Prefix
	for _, c := range f.DenyCIDRs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return fmt.Errorf("deny_cidrs: %w", err)
		}
		deny = append(deny, p)
	}
	var pubs []ed25519.PublicKey
	for _, s := range f.Issuers {
		p, err := singlink.B64.DecodeString(s)
		if err != nil || len(p) != ed25519.PublicKeySize {
			return fmt.Errorf("bad issuer key %q", s)
		}
		pubs = append(pubs, p)
	}
	lvl := slog.LevelInfo
	if f.LogLevel == "debug" {
		lvl = slog.LevelDebug
	}
	cfg := singlink.ServerConfig{
		Key: key, OldKeys: old, Issuers: singlink.NewIssuers(pubs...),
		Fallback: f.Fallback, FallbackProxyProtocol: f.FallbackProxyProtocol,
		AllowPrivate: f.AllowPrivate, DenyCIDRs: deny, BlockedPorts: f.BlockedPorts, AllowSMTP: f.AllowSMTP,
		MaxConnections: f.MaxConnections, RevokedFile: f.RevokedFile,
		Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})),
	}
	if f.TLSCert != "" {
		cert, err := tls.LoadX509KeyPair(f.TLSCert, f.TLSKey)
		if err != nil {
			return err
		}
		cfg.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	}
	srv, err := singlink.NewServer(cfg)
	if err != nil {
		return err
	}
	if f.Listen == "" {
		f.Listen = ":443"
	}
	ln, err := net.Listen("tcp", f.Listen)
	if err != nil {
		return err
	}
	cfg.Logger.Info("SingLink node listening", "addr", ln.Addr().String(), "tls", cfg.TLS != nil, "issuers", len(pubs))
	return srv.Serve(ln)
}

func waitSignal() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	<-ch
}

func client(args []string) error {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	l := fs.String("link", "", "singlink:// link")
	listen := fs.String("listen", "127.0.0.1:1080", "local SOCKS5 address")
	fs.Parse(args)
	var e engine.Engine
	if err := e.Start(*l, *listen); err != nil {
		return err
	}
	fmt.Println("SOCKS5 proxy on", e.Status().Listen)
	waitSignal()
	e.Stop()
	return nil
}

// demo runs a node with a self-signed certificate on loopback, issues a
// token and starts a client, so the whole stack can be tried on one machine.
func demo(args []string) error {
	fs := flag.NewFlagSet("demo", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:1080", "local SOCKS5 address")
	nodeAddr := fs.String("node", "127.0.0.1:8443", "address for the demo node")
	linkOnly := fs.Bool("link-only", false, "run only the node and print a link for another client (e.g. the Flutter app)")
	fs.Parse(args)

	key, _ := singlink.GenerateServerKey()
	issuer, _ := singlink.GenerateEd25519()
	device, _ := singlink.GenerateEd25519()
	ck, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "singlink-demo.local"},
		DNSNames: []string{"singlink-demo.local"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(30 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &ck.PublicKey, ck)
	if err != nil {
		return err
	}
	pin, err := singlink.PinFromCertificate(der)
	if err != nil {
		return err
	}
	srv, err := singlink.NewServer(singlink.ServerConfig{
		Key: key, Issuers: singlink.NewIssuers(issuer.Public().(ed25519.PublicKey)),
		TLS: &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: ck}}},
	})
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", *nodeAddr)
	if err != nil {
		return err
	}
	go srv.Serve(ln)

	t := &singlink.Token{DevicePub: device.Public().(ed25519.PublicKey), NotBefore: time.Now().Add(-time.Minute),
		NotAfter: time.Now().Add(30 * 24 * time.Hour), Caps: singlink.CapTCP | singlink.CapUDP, Plan: 1}
	rand.Read(t.Subject[:])
	raw, err := singlink.IssueToken(issuer, t)
	if err != nil {
		return err
	}
	p := &singlink.Profile{Name: "SingLink local demo node", Server: ln.Addr().String(), Transport: "tls", SNI: "singlink-demo.local",
		Pin: pin, ServerKey: key.Public(), Token: raw, Device: device}
	fmt.Println("node:", ln.Addr().String(), "(TLS 1.3, pinned self-signed certificate)")
	fmt.Println("link:")
	fmt.Println(p.Link())
	if *linkOnly {
		fmt.Println("\nnode running; paste the link into a client. Ctrl+C to stop.")
		waitSignal()
		return nil
	}
	var e engine.Engine
	if err := e.Start(p.Link(), *listen); err != nil {
		return err
	}
	fmt.Println("\nSOCKS5 proxy on", e.Status().Listen, "— try: curl -x socks5h://"+e.Status().Listen+" https://www.gstatic.com/generate_204 -i")
	waitSignal()
	e.Stop()
	return nil
}
