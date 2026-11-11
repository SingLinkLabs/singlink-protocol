// Command ffi builds libsinglink, the C ABI used by the Flutter client:
//
//	go build -buildmode=c-shared -o build/libsinglink.dylib ./ffi
//
// Every function returns a JSON string allocated with malloc that the caller
// must release with SingLinkFree.
package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"encoding/hex"
	"encoding/json"
	"time"
	"unsafe"

	"github.com/singlinklabs/singlink-protocol/engine"
	"github.com/singlinklabs/singlink-protocol/singlink"
)

var eng engine.Engine

func out(v any) *C.char {
	b, err := json.Marshal(v)
	if err != nil {
		b = []byte(`{"ok":false,"error":"internal encoding error"}`)
	}
	return C.CString(string(b))
}

func fail(err error) *C.char { return out(map[string]any{"ok": false, "error": err.Error()}) }

//export SingLinkVersion
func SingLinkVersion() *C.char {
	return out(map[string]string{"version": singlink.Version, "protocol": singlink.ProtocolName})
}

//export SingLinkParseLink
func SingLinkParseLink(link *C.char) *C.char {
	p, err := singlink.ParseLink(C.GoString(link))
	if err != nil {
		return fail(err)
	}
	t, err := p.TokenInfo()
	if err != nil {
		return fail(err)
	}
	var caps []string
	if t.Has(singlink.CapTCP) {
		caps = append(caps, "tcp")
	}
	if t.Has(singlink.CapUDP) {
		caps = append(caps, "udp")
	}
	return out(map[string]any{"ok": true, "profile": map[string]any{
		"name":      p.Name,
		"server":    p.Server,
		"transport": p.Transport,
		"sni":       p.SNI,
		"subject":   hex.EncodeToString(t.Subject[:]),
		"plan":      t.Plan,
		"expiresAt": t.NotAfter.Unix(),
		"caps":      caps,
		"rateKbps":  t.RateKbps,
		"maxConns":  t.MaxConns,
	}})
}

//export SingLinkStart
func SingLinkStart(config *C.char) *C.char {
	var cfg struct {
		Link   string `json:"link"`
		Listen string `json:"listen"`
	}
	if err := json.Unmarshal([]byte(C.GoString(config)), &cfg); err != nil {
		return fail(err)
	}
	if err := eng.Start(cfg.Link, cfg.Listen); err != nil {
		return fail(err)
	}
	return out(map[string]any{"ok": true})
}

//export SingLinkStop
func SingLinkStop() *C.char {
	eng.Stop()
	return out(map[string]any{"ok": true})
}

//export SingLinkStatus
func SingLinkStatus() *C.char { return out(eng.Status()) }

//export SingLinkProbe
func SingLinkProbe(url *C.char, timeoutMs C.int) *C.char {
	code, d, err := eng.Probe(C.GoString(url), time.Duration(timeoutMs)*time.Millisecond)
	if err != nil {
		return fail(err)
	}
	return out(map[string]any{"ok": true, "status": code, "latencyMs": d.Milliseconds()})
}

//export SingLinkExitIP
func SingLinkExitIP(timeoutMs C.int) *C.char {
	ip, err := eng.ExitIP(time.Duration(timeoutMs) * time.Millisecond)
	if err != nil {
		return fail(err)
	}
	return out(map[string]any{"ok": true, "ip": ip})
}

//export SingLinkFree
func SingLinkFree(p *C.char) { C.free(unsafe.Pointer(p)) }

func main() {}
