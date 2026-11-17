// Copyright 2026 SingLinkVPN (https://singlinkvpn.com)
// SPDX-License-Identifier: Apache-2.0
package singlink

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func replayTestStore(t *testing.T, n int) *FileReplayStore {
	t.Helper()
	s, err := InitializeReplayFile(filepath.Join(t.TempDir(), "state", "replay.db"), n)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func replayTag(s string) [32]byte { return sha256.Sum256([]byte(s)) }

func TestReplayStoreRestartAndCapacity(t *testing.T) {
	s := replayTestStore(t, 2)
	ctx := context.Background()
	expiry := time.Now().Add(time.Minute)
	if ok, err := s.CheckAndMark(ctx, replayTag("a"), expiry); !ok || err != nil {
		t.Fatal("initial mark failed")
	}
	reopened, err := OpenFileReplayStore(s.path, 2)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := reopened.CheckAndMark(ctx, replayTag("a"), expiry); ok || err != nil {
		t.Fatal("restart replay admitted")
	}
	if ok, err := reopened.CheckAndMark(ctx, replayTag("b"), expiry); !ok || err != nil {
		t.Fatal("second mark failed")
	}
	if ok, err := reopened.CheckAndMark(ctx, replayTag("c"), expiry); ok || err == nil {
		t.Fatal("capacity did not fail closed")
	}
	if _, err := InitializeReplayFile(s.path, 2); err == nil {
		t.Fatal("existing state reinitialized")
	}
}

func TestReplayStoreIndependentInstancesAtomic(t *testing.T) {
	s := replayTestStore(t, 100)
	other, err := OpenFileReplayStore(s.path, 100)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan bool, 20)
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			store := s
			if i%2 == 0 {
				store = other
			}
			ok, err := store.CheckAndMark(context.Background(), replayTag("shared"), time.Now().Add(time.Minute))
			results <- ok
			errs <- err
		}(i)
	}
	wg.Wait()
	close(results)
	close(errs)
	accepted := 0
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	for ok := range results {
		if ok {
			accepted++
		}
	}
	if accepted != 1 {
		t.Fatal("same nonce admitted more than once")
	}
}

func TestReplayStoreLockCancellation(t *testing.T) {
	s := replayTestStore(t, 10)
	unlock, err := s.lock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if ok, err := s.CheckAndMark(ctx, replayTag("cancel"), time.Now().Add(time.Minute)); ok || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("lock did not honor cancellation")
	}
}

func TestReplayStoreGCAndClockRollbackFailClosed(t *testing.T) {
	s := replayTestStore(t, 1)
	now := time.Now().Add(time.Second)
	s.now = func() time.Time { return now }
	if ok, err := s.CheckAndMark(context.Background(), replayTag("expired"), now.Add(time.Second)); !ok || err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Second)
	if ok, err := s.CheckAndMark(context.Background(), replayTag("new"), now.Add(time.Second)); !ok || err != nil {
		t.Fatal("expired state not collected")
	}
	snap, err := s.load()
	if err != nil || len(snap.entries) != 1 {
		t.Fatal("unexpected retained state")
	}
	now = now.Add(-2 * time.Second)
	if ok, err := s.CheckAndMark(context.Background(), replayTag("expired"), now.Add(time.Second)); ok || err == nil {
		t.Fatal("rollback resurrected collected replay")
	}
	if _, err := OpenFileReplayStore(s.path, 1); err == nil {
		t.Fatal("restart accepted backwards clock")
	}
}

func TestReplayStoreMissingCorruptAndPermissionsFailClosed(t *testing.T) {
	s := replayTestStore(t, 10)
	good, err := os.ReadFile(s.path)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{nil, []byte("corrupt"), append([]byte{}, good[:len(good)-1]...)} {
		if err := os.WriteFile(s.path, bad, 0600); err != nil {
			t.Fatal(err)
		}
		if ok, err := s.CheckAndMark(context.Background(), replayTag("x"), time.Now().Add(time.Minute)); ok || err == nil {
			t.Fatal("corrupt state accepted")
		}
		if _, err := OpenFileReplayStore(s.path, 10); err == nil {
			t.Fatal("corrupt startup accepted")
		}
	}
	// A correctly checksummed but invalid unsigned count must not overflow int.
	bad := append([]byte{}, good...)
	binary.BigEndian.PutUint32(bad[16:20], ^uint32(0))
	sum := sha256.Sum256(bad[:len(bad)-32])
	copy(bad[len(bad)-32:], sum[:])
	os.WriteFile(s.path, bad, 0600)
	if _, err := s.load(); err == nil {
		t.Fatal("invalid count accepted")
	}
	os.WriteFile(s.path, good, 0600)
	exposeReplayPath(t, s.path)
	if _, err := OpenFileReplayStore(s.path, 10); err == nil {
		t.Fatal("public state permissions accepted")
	}
	restrictReplayPath(t, s.path)
	if _, err := OpenFileReplayStore(s.path, 10); err != nil {
		t.Fatal("restored private state rejected")
	}
	exposeReplayPath(t, s.path+".lock")
	if ok, err := s.CheckAndMark(context.Background(), replayTag("x"), time.Now().Add(time.Minute)); ok || err == nil {
		t.Fatal("public lock file accepted")
	}
	restrictReplayPath(t, s.path+".lock")
	dir := filepath.Dir(s.path)
	exposeReplayPath(t, dir)
	if _, err := OpenFileReplayStore(s.path, 10); err == nil {
		t.Fatal("public state directory accepted")
	}
	restrictReplayPath(t, dir)
	if _, err := OpenFileReplayStore(s.path, 10); err != nil {
		t.Fatal("restored private directory rejected")
	}
	os.Remove(s.path)
	if _, err := OpenFileReplayStore(s.path, 10); err == nil {
		t.Fatal("missing state silently rebuilt")
	}
	if _, err := InitializeReplayFile(s.path, 10); err == nil {
		t.Fatal("initialization evidence ignored")
	}
}

func TestReplayStoreContainsOnlyOpaqueSecurityState(t *testing.T) {
	s := replayTestStore(t, 10)
	raw := []byte("synthetic-credential-not-for-persistence")
	if ok, err := s.CheckAndMark(context.Background(), sha256.Sum256(raw), time.Now().Add(time.Minute)); !ok || err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != replayHeaderSize+40+sha256.Size || bytes.Contains(b, raw) {
		t.Fatal("unexpected state content")
	}
	assertReplayPathPrivate(t, s.path)
	assertReplayPathPrivate(t, s.path+".lock")
	assertReplayPathPrivate(t, filepath.Dir(s.path))
}

func TestReplayStoreSurvivesAbruptProcessExit(t *testing.T) {
	s := replayTestStore(t, 10)
	cmd := exec.Command(os.Args[0], "-test.run=^TestReplayStoreHelperProcess$")
	cmd.Env = append(os.Environ(), "SINGLINK_SYNTHETIC_REPLAY_HELPER="+s.path)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("helper failed (output bytes %d)", len(b))
	}
	reopened, err := OpenFileReplayStore(s.path, 10)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := reopened.CheckAndMark(context.Background(), replayTag("crash-marker"), time.Now().Add(time.Minute)); ok || err != nil {
		t.Fatal("acknowledged mark lost across process exit")
	}
}

func TestReplayStoreHelperProcess(t *testing.T) {
	path := os.Getenv("SINGLINK_SYNTHETIC_REPLAY_HELPER")
	if path == "" {
		return
	}
	s, err := OpenFileReplayStore(path, 10)
	if err != nil {
		os.Exit(2)
	}
	if id := os.Getenv("SINGLINK_SYNTHETIC_COMPETITOR"); id != "" {
		if os.WriteFile(path+".ready-"+id, nil, 0600) != nil {
			os.Exit(4)
		}
		deadline := time.Now().Add(5 * time.Second)
		for {
			if _, err := os.Stat(path + ".release"); err == nil {
				break
			}
			if time.Now().After(deadline) {
				os.Exit(5)
			}
			time.Sleep(time.Millisecond)
		}
	}
	ok, err := s.CheckAndMark(context.Background(), replayTag("crash-marker"), time.Now().Add(time.Minute))
	if err != nil {
		os.Exit(2)
	}
	if !ok {
		os.Exit(3)
	}
	os.Exit(0) // no process-level graceful server shutdown
}

func TestReplayStoreConcurrentProcesses(t *testing.T) {
	s := replayTestStore(t, 10)
	children := make([]*exec.Cmd, 2)
	for i, id := range []string{"one", "two"} {
		c := exec.Command(os.Args[0], "-test.run=^TestReplayStoreHelperProcess$")
		c.Env = append(os.Environ(), "SINGLINK_SYNTHETIC_REPLAY_HELPER="+s.path, "SINGLINK_SYNTHETIC_COMPETITOR="+id)
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		children[i] = c
		t.Cleanup(func() {
			if c.Process != nil {
				c.Process.Kill()
			}
		})
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, a := os.Stat(s.path + ".ready-one")
		_, b := os.Stat(s.path + ".ready-two")
		if a == nil && b == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("synthetic workers did not become ready")
		}
		time.Sleep(time.Millisecond)
	}
	if err := os.WriteFile(s.path+".release", nil, 0600); err != nil {
		t.Fatal(err)
	}
	accepted, rejected := 0, 0
	for _, c := range children {
		err := c.Wait()
		if err == nil {
			accepted++
		} else if e, ok := err.(*exec.ExitError); ok && e.ExitCode() == 3 {
			rejected++
		} else {
			t.Fatal("worker failed")
		}
	}
	if accepted != 1 || rejected != 1 {
		t.Fatal("cross-process nonce admitted incorrectly")
	}
}

func TestReplayStorePruneErasesOnlyExpiredMarks(t *testing.T) {
	s := replayTestStore(t, 10)
	now := time.Now().Add(time.Second)
	s.now = func() time.Time { return now }
	if ok, err := s.CheckAndMark(context.Background(), replayTag("short"), now.Add(time.Second)); !ok || err != nil {
		t.Fatal(err)
	}
	if ok, err := s.CheckAndMark(context.Background(), replayTag("long"), now.Add(time.Hour)); !ok || err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Second)
	if err := s.Prune(context.Background()); err != nil {
		t.Fatal(err)
	}
	snap, err := s.load()
	if err != nil || len(snap.entries) != 1 || snap.high != now.UnixNano() {
		t.Fatal("prune did not erase exactly the expired mark")
	}
	if _, ok := snap.entries[replayTag("long")]; !ok {
		t.Fatal("prune removed an unexpired mark")
	}
	now = now.Add(-time.Second)
	if err := s.Prune(context.Background()); err == nil {
		t.Fatal("prune ran with the clock behind the watermark")
	}
}

func TestReplayTagIsKeyedAndStable(t *testing.T) {
	k1, _ := GenerateServerKey()
	k2, _ := GenerateServerKey()
	E := bytes.Repeat([]byte{0x42}, x25519Len)
	again, err := ParseServerPrivateKey(k1.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	t1 := replayTagFor(k1, E)
	if t1 != replayTagFor(again, E) {
		t.Fatal("tag not stable for the same static key")
	}
	if t1 == replayTagFor(k2, E) || t1 == sha256.Sum256(E) || bytes.Contains(t1[:], E[:8]) {
		t.Fatal("tag not keyed to the node static key")
	}
}
