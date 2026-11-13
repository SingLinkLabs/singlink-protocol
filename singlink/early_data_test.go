// Copyright 2026 SingLinkLabs
// SPDX-License-Identifier: Apache-2.0
package singlink

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

func TestEarlyPayloadSharesSubjectBudget(t *testing.T) {
	var ss subjects
	tok := &Token{Subject: [16]byte{1}, RateKbps: 8}
	a, _ := ss.acquire(tok)
	b, _ := ss.acquire(tok)
	if a != b {
		t.Fatal("subject does not share limiter")
	}
	a.mu.Lock()
	a.tokens = 0
	a.mu.Unlock()
	var out bytes.Buffer
	var stats Stats
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := forwardEarlyData(ctx, &out, bytes.Repeat([]byte{1}, 8192), b, &stats); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("exhausted budget not blocked")
	}
	if out.Len() != 0 || stats.Up.Load() != 0 {
		t.Fatal("unapproved bytes escaped")
	}
	other, _ := ss.acquire(&Token{Subject: [16]byte{2}, RateKbps: 8})
	if err := forwardEarlyData(context.Background(), &out, []byte("synthetic"), other, &stats); err != nil {
		t.Fatal(err)
	}
	if out.String() != "synthetic" || stats.Up.Load() != 9 {
		t.Fatal("allowed bytes not accounted")
	}
	other.mu.Lock()
	remaining := other.tokens
	other.mu.Unlock()
	if remaining >= other.burst {
		t.Fatal("early bytes not debited")
	}
}

type shortEarlyWriter struct{}

func (shortEarlyWriter) Write(b []byte) (int, error) { return len(b) / 2, nil }
func TestEarlyPayloadUnlimitedAndPartialWrite(t *testing.T) {
	var out bytes.Buffer
	var stats Stats
	if err := forwardEarlyData(context.Background(), &out, []byte("test"), nil, &stats); err != nil {
		t.Fatal(err)
	}
	if err := forwardEarlyData(context.Background(), shortEarlyWriter{}, []byte("test"), nil, &stats); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal("short write not rejected")
	}
	if stats.Up.Load() != 6 {
		t.Fatal("partial bytes incorrectly counted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := forwardEarlyData(ctx, &out, []byte("blocked"), nil, &stats); !errors.Is(err, context.Canceled) {
		t.Fatal("cancel not honored")
	}
	if out.String() != "test" {
		t.Fatal("cancelled bytes written")
	}
}
