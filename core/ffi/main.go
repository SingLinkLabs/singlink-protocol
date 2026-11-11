// Command ffi builds libsl3, the C ABI used by the Flutter client:
//
//	go build -buildmode=c-shared -o build/libsl3.dylib ./ffi
//
// Every function returns a JSON string allocated with malloc that the caller
// must release with SL3Free.
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

	"github.com/singlinklabs/sl3/engine"
	"github.com/singlinklabs/sl3/sl3"
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

//export SL3Version
func SL3Version() *C.char {
	return out(map[string]string{"version": sl3.Version, "protocol": sl3.ProtocolName})
}

//export SL3ParseLink
func SL3ParseLink(link *C.char) *C.char {
	p, err := sl3.ParseLink(C.GoString(link))
	if err != nil {
		return fail(err)
	}
	t, err := p.TokenInfo()
	if err != nil {
		return fail(err)
	}
	var caps []string
	if t.Has(sl3.CapTCP) {
		caps = append(caps, "tcp")
	}
	if t.Has(sl3.CapUDP) {
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

//export SL3Start
func SL3Start(config *C.char) *C.char {
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

//export SL3Stop
func SL3Stop() *C.char {
	eng.Stop()
	return out(map[string]any{"ok": true})
}

//export SL3Status
func SL3Status() *C.char { return out(eng.Status()) }

//export SL3Probe
func SL3Probe(url *C.char, timeoutMs C.int) *C.char {
	code, d, err := eng.Probe(C.GoString(url), time.Duration(timeoutMs)*time.Millisecond)
	if err != nil {
		return fail(err)
	}
	return out(map[string]any{"ok": true, "status": code, "latencyMs": d.Milliseconds()})
}

//export SL3Free
func SL3Free(p *C.char) { C.free(unsafe.Pointer(p)) }

func main() {}
