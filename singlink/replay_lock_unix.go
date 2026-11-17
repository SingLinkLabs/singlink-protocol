//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

// Copyright 2026 SingLinkVPN (https://singlinkvpn.com)
// SPDX-License-Identifier: Apache-2.0
package singlink

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

func lockReplayFile(ctx context.Context, path string) (func(), error) {
	if st, err := os.Lstat(path); err == nil && (!st.Mode().IsRegular() || !replayPrivate(path, st)) {
		return nil, ErrReplayStore
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, ErrReplayStore
	}
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || !replayPrivate(path, st) {
		f.Close()
		return nil, ErrReplayStore
	}
	for {
		if err := ctx.Err(); err != nil {
			f.Close()
			return nil, err
		}
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() { syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			f.Close()
			return nil, ErrReplayStore
		}
		timer := time.NewTimer(5 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			f.Close()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

// replayPrivate reports whether st (describing path) is owned by this
// process's effective user and has no group or other permissions.
func replayPrivate(_ string, st os.FileInfo) bool {
	return st.Mode().Perm()&0077 == 0 && replayOwnerOK(st)
}

func replayOwnerOK(st os.FileInfo) bool {
	v, ok := st.Sys().(*syscall.Stat_t)
	return ok && v.Uid == uint32(os.Geteuid())
}

// makeReplayDir creates the private state directory if it does not exist.
// An existing directory is left unchanged and checked under the lock.
func makeReplayDir(dir string) error { return os.MkdirAll(dir, 0700) }

// replaceReplayFile atomically renames temp over path in the same directory
// and syncs the directory, so the new snapshot is durable when it returns.
func replaceReplayFile(temp, path string) error {
	if err := os.Rename(temp, path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	err = dir.Sync()
	if closeErr := dir.Close(); err == nil {
		err = closeErr
	}
	return err
}
