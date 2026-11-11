// Command sl3 is the SingLink 3.0 reference node, client and key tool.
package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
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
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/singlinklabs/sl3/engine"
	"github.com/singlinklabs/sl3/sl3"
)

const usage = `sl3 — SingLink 3.0 protocol tool (` + sl3.Version + `)

Usage:
  sl3 keygen server|issuer|device      generate a key pair (JSON)
  sl3 token issue [flags]              sign a permission token
  sl3 token inspect <token>            decode a token
  sl3 link [flags]                     build an sl3:// client link
  sl3 server -c server.json            run a node
  sl3 client -link <sl3://...> [-listen 127.0.0.1:1080]
  sl3 demo [-listen 127.0.0.1:1080]    local node + client in one process

Run "sl3 <command> -h" for flags.
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
		fmt.Println(sl3.Version, sl3.ProtocolName)
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
		return errors.New("usage: sl3 keygen server|issuer|device")
	}
	switch args[0] {
	case "server":
		k, err := sl3.GenerateServerKey()
		if err != nil {
			return err
		}
		printJSON(map[string]string{
			"private_key": sl3.B64.EncodeToString(k.Bytes()),
			"public_key":  sl3.B64.EncodeToString(k.Public().Bytes()),
		})
	case "issuer", "device":
		k, err := sl3.GenerateEd25519()
		if err != nil {
			return err
		}
		pub := k.Public().(ed25519.PublicKey)
		m := map[string]any{"seed": sl3.B64.EncodeToString(k.Seed()), "public_key": sl3.B64.EncodeToString(pub)}
		if args[0] == "issuer" {
			m["key_id"] = fmt.Sprintf("%08x", sl3.IssuerKeyID(pub))
		}
		printJSON(m)
	default:
		return errors.New("usage: sl3 keygen server|issuer|device")
	}
	return nil
}

func parseCaps(s string) (uint32, error) {
	var caps uint32
	for _, c := range strings.Split(s, ",") {
		switch strings.TrimSpace(c) {
		case "tcp":
			caps |= sl3.CapTCP
		case "udp":
			caps |= sl3.CapUDP
		case "":
		default:
			return 0, fmt.Errorf("unknown capability %q", c)
		}
	}
	return caps, nil
}

func token(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: sl3 token issue|inspect")
	}
	switch args[0] {
	case "inspect":
		if len(args) != 2 {
			return errors.New("usage: sl3 token inspect <token>")
		}
		b, err := sl3.B64.DecodeString(args[1])
		if err != nil {
			return err
		}
		t, err := sl3.ParseToken(b)
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
		days := fs.Float64("days", 30, "validity in days")
		caps := fs.String("caps", "tcp,udp", "capabilities")
		rate := fs.Uint("rate", 0, "rate limit in kbit/s (0 = unlimited)")
		maxConns := fs.Uint("max-conns", 0, "max concurrent connections (0 = unlimited)")
		plan := fs.Uint("plan", 0, "plan id")
		fs.Parse(args[1:])
		seed, err := sl3.B64.DecodeString(*issuerSeed)
		if err != nil {
			return errors.New("bad -issuer")
		}
		issuer, err := sl3.Ed25519FromSeed(seed)
		if err != nil {
			return err
		}
		dp, err := sl3.B64.DecodeString(*devicePub)
		if err != nil || len(dp) != ed25519.PublicKeySize {
			return errors.New("bad -device")
		}
		c, err := parseCaps(*caps)
		if err != nil {
			return err
		}
		t := &sl3.Token{
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
		raw, err := sl3.IssueToken(issuer, t)
		if err != nil {
			return err
		}
		fmt.Println(sl3.B64.EncodeToString(raw))
		return nil
	}
	return errors.New("usage: sl3 token issue|inspect")
}

func tokenJSON(t *sl3.Token) map[string]any {
	return map[string]any{
		"key_id":     fmt.Sprintf("%08x", t.KeyID),
		"token_id":   hex.EncodeToString(t.ID[:]),
		"subject":    hex.EncodeToString(t.Subject[:]),
		"device":     sl3.B64.EncodeToString(t.DevicePub),
		"not_before": t.NotBefore.UTC().Format(time.RFC3339),
		"not_after":  t.NotAfter.UTC().Format(time.RFC3339),
		"tcp":        t.Has(sl3.CapTCP),
		"udp":        t.Has(sl3.CapUDP),
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
	p := &sl3.Profile{Name: *name, Server: *server, Transport: *tr, SNI: *sni}
	var err error
	b, err := sl3.B64.DecodeString(*pk)
	if err != nil {
		return errors.New("bad -pk")
	}
	if p.ServerKey, err = sl3.ParseServerPublicKey(b); err != nil {
		return err
	}
	if p.Token, err = sl3.B64.DecodeString(*tok); err != nil {
		return errors.New("bad -token")
	}
	seed, err := sl3.B64.DecodeString(*dev)
	if err != nil {
		return errors.New("bad -device")
	}
	if p.Device, err = sl3.Ed25519FromSeed(seed); err != nil {
		return err
	}
	if *pin != "" {
		if p.Pin, err = sl3.B64.DecodeString(*pin); err != nil {
			return errors.New("bad -pin")
		}
	}
	l := p.Link()
	if _, err := sl3.ParseLink(l); err != nil {
		return err
	}
	fmt.Println(l)
	return nil
}

type serverFile struct {
	Listen       string   `json:"listen"`
	PrivateKey   string   `json:"private_key"`
	Issuers      []string `json:"issuers"`
	TLSCert      string   `json:"tls_cert"`
	TLSKey       string   `json:"tls_key"`
	Fallback     string   `json:"fallback"`
	AllowPrivate bool     `json:"allow_private"`
	BlockedPorts []uint16 `json:"blocked_ports"`
	RevokedFile  string   `json:"revoked_file"`
	LogLevel     string   `json:"log_level"`
}

func server(args []string) error {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	path := fs.String("c", "server.json", "config file")
	fs.Parse(args)
	b, err := os.ReadFile(*path)
	if err != nil {
		return err
	}
	var f serverFile
	if err := json.Unmarshal(b, &f); err != nil {
		return err
	}
	kb, err := sl3.B64.DecodeString(f.PrivateKey)
	if err != nil {
		return errors.New("bad private_key")
	}
	key, err := sl3.ParseServerPrivateKey(kb)
	if err != nil {
		return err
	}
	var pubs []ed25519.PublicKey
	for _, s := range f.Issuers {
		p, err := sl3.B64.DecodeString(s)
		if err != nil || len(p) != ed25519.PublicKeySize {
			return fmt.Errorf("bad issuer key %q", s)
		}
		pubs = append(pubs, p)
	}
	lvl := slog.LevelInfo
	if f.LogLevel == "debug" {
		lvl = slog.LevelDebug
	}
	cfg := sl3.ServerConfig{
		Key: key, Issuers: sl3.NewIssuers(pubs...), Fallback: f.Fallback,
		AllowPrivate: f.AllowPrivate, BlockedPorts: f.BlockedPorts, RevokedFile: f.RevokedFile,
		Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})),
	}
	if f.TLSCert != "" {
		cert, err := tls.LoadX509KeyPair(f.TLSCert, f.TLSKey)
		if err != nil {
			return err
		}
		cfg.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	}
	srv, err := sl3.NewServer(cfg)
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
	cfg.Logger.Info("SL3 node listening", "addr", ln.Addr().String(), "tls", cfg.TLS != nil, "issuers", len(pubs))
	return srv.Serve(ln)
}

func waitSignal() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	<-ch
}

func client(args []string) error {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	l := fs.String("link", "", "sl3:// link")
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

	key, _ := sl3.GenerateServerKey()
	issuer, _ := sl3.GenerateEd25519()
	device, _ := sl3.GenerateEd25519()
	ck, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "sl3-demo.local"},
		DNSNames: []string{"sl3-demo.local"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(30 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &ck.PublicKey, ck)
	if err != nil {
		return err
	}
	pin := sha256.Sum256(der)
	srv, err := sl3.NewServer(sl3.ServerConfig{
		Key: key, Issuers: sl3.NewIssuers(issuer.Public().(ed25519.PublicKey)),
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

	t := &sl3.Token{DevicePub: device.Public().(ed25519.PublicKey), NotBefore: time.Now().Add(-time.Minute),
		NotAfter: time.Now().Add(30 * 24 * time.Hour), Caps: sl3.CapTCP | sl3.CapUDP, Plan: 1}
	rand.Read(t.Subject[:])
	raw, err := sl3.IssueToken(issuer, t)
	if err != nil {
		return err
	}
	p := &sl3.Profile{Name: "SL3 本機示範節點", Server: ln.Addr().String(), Transport: "tls", SNI: "sl3-demo.local",
		Pin: pin[:], ServerKey: key.Public(), Token: raw, Device: device}
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
