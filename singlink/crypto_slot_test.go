// Copyright 2026 SingLinkVPN (https://singlinkvpn.com)
// SPDX-License-Identifier: Apache-2.0
package singlink

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// F-04 (VPN Labs, VPNL-2026-0013): a panic while a handler held a handshake
// cryptography slot leaked the slot; after cap(crypto) such panics every new
// handshake blocked. The handler's recover keeps the node running, so the
// slot must be released on that path too.
func TestF04CryptoSlotReleasedOnPanic(t *testing.T) {
	var calls, panics, limit atomic.Int64
	e := newEnv(t, envOpt{tls: true, mutate: func(c *ServerConfig) {
		c.cryptoHook = func() {
			calls.Add(1)
			if panics.Load() < limit.Load() {
				panics.Add(1)
				panic("injected panic in the handshake cryptography section")
			}
		}
	}})
	slots := cap(e.srv.guard.crypto)
	// More panics than there are slots: without the fix the last ones (and
	// every later handshake) block on a full semaphore.
	limit.Store(int64(slots + 2))
	echo := echoServer(t, "")

	for i := int64(0); i < limit.Load(); i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		c, err := e.client.DialTCP(ctx, echo)
		cancel()
		if err == nil {
			// The handler panicked and closed the connection: any read ends.
			c.SetDeadline(time.Now().Add(5 * time.Second))
			var b [1]byte
			c.Write([]byte("x"))
			c.Read(b[:])
			c.Close()
		}
		deadline := time.Now().Add(5 * time.Second)
		for panics.Load() <= i && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		if panics.Load() <= i {
			t.Fatalf("handshake %d never reached the cryptography section (%d of %d slots in use)", i, len(e.srv.guard.crypto), slots)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(e.srv.guard.crypto) != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if n := len(e.srv.guard.crypto); n != 0 {
		t.Fatalf("%d cryptography slots leaked after %d panics", n, panics.Load())
	}

	// Handshakes continue normally after the panics.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := e.client.DialTCP(ctx, echo)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	roundTrip(t, c, []byte("still serving"))
	if got, want := calls.Load(), limit.Load()+1; got != want {
		t.Fatalf("cryptography section entered %d times, want %d", got, want)
	}
}
