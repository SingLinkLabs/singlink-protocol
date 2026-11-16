// Copyright 2026 SingLinkLabs
// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"context"
	"github.com/SingLinkLabs/singlink-protocol/singlink"
	"time"
)

type startAttempt struct {
	client *singlink.Client
	id     uint64
	ctx    context.Context
	cancel context.CancelFunc
}

func (e *Engine) begin() *startAttempt {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stop != nil || e.pending != nil {
		return nil
	}
	e.generation++
	ctx, cancel := context.WithCancel(context.Background())
	a := &startAttempt{id: e.generation, ctx: ctx, cancel: cancel}
	e.pending = a
	return a
}

func (e *Engine) finish(a *startAttempt, c *singlink.Client, stop func(), listen, user, pass string, err error) error {
	e.mu.Lock()
	stale := e.pending != a || e.generation != a.id || a.ctx.Err() != nil
	if !stale {
		e.pending = nil
		if err == nil {
			e.client, e.stop, e.listen, e.user, e.pass, e.since, e.lastErr = c, stop, listen, user, pass, time.Now(), ""
		} else {
			e.lastErr = err.Error()
		}
	}
	e.mu.Unlock()
	a.cancel()
	if stale || err != nil {
		// A cancelled old operation owns only its own cleanup, never global Stop.
		if stop != nil {
			stop()
		}
		if stale {
			return context.Canceled
		}
	}
	return err
}

// StopClient stops only the active or pending operation owned by c. A late
// watcher holding an older client cannot stop a replacement session. The return
// value reports whether this client owned the operation that was invalidated.
func (e *Engine) StopClient(c *singlink.Client) bool {
	if c == nil {
		return false
	}
	return e.stopOwned(c, true)
}

func (e *Engine) attachClient(a *startAttempt, c *singlink.Client) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.pending != a || e.generation != a.id || a.ctx.Err() != nil {
		return false
	}
	a.client = c
	return true
}

func (e *Engine) stopCurrent() { e.stopOwned(nil, false) }

func (e *Engine) stopOwned(c *singlink.Client, matched bool) bool {
	e.mu.Lock()
	if matched && e.client != c && (e.pending == nil || e.pending.client != c) {
		e.mu.Unlock()
		return false
	}
	e.generation++
	pending, stop := e.pending, e.stop
	// Like the original Stop, keep listen/credentials/lastErr for Status.
	e.pending, e.stop, e.client = nil, nil, nil
	e.mu.Unlock()
	if pending != nil {
		pending.cancel()
	}
	if stop != nil {
		stop()
	}
	return true
}
