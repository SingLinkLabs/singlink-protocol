// Copyright 2026 SingLinkLabs
// SPDX-License-Identifier: Apache-2.0
package singlink

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ReplayStore atomically and durably marks an opaque handshake tag until expiry.
// true means this caller alone inserted it; false means replay. Implementations
// MUST commit before returning true, fail closed on unavailable/corrupt state,
// and reject time rollback after expiry GC. All instances accepting the same
// static key (including OldKeys) MUST share the same store/atomic namespace.
// A host-local mutex or independent per-node files do not meet that contract.
// expiry is absolute, computed on the node; a store shared by several hosts
// MUST NOT drop a mark before that instant as seen by any of them (keep clocks
// synchronized, or retain marks for expiry plus the maximum clock offset).
type ReplayStore interface {
	CheckAndMark(context.Context, [32]byte, time.Time) (bool, error)
}

var ErrReplayStore = errors.New("singlink: replay store unavailable or invalid")

// ReplayPruner is optionally implemented by a ReplayStore that can erase
// expired marks without a new admission. A serving node calls it every
// replayPruneInterval so an idle node does not keep expired tags around.
type ReplayPruner interface {
	Prune(context.Context) error
}

const replayPruneInterval = 30 * time.Second

const defaultReplayEntries = 65536
const maxReplayEntries = 1 << 20
const replayHeaderSize = 20

var replayMagic = []byte("SLRPLY01")

// FileReplayStore is a reference local-filesystem store for supported Unix hosts.
// Processes on one host may share a path. Network filesystems/multi-host storage
// are not supported: provide an external ReplayStore meeting the full contract.
// Each admission rewrites/fsyncs a bounded snapshot; size for the handshake load.
// The snapshot holds only opaque tag/expiry pairs and a global clock watermark.
type FileReplayStore struct {
	path  string
	limit int
	now   func() time.Time
}

func replayLimit(n int) (int, error) {
	if n == 0 {
		n = defaultReplayEntries
	}
	if n < 1 || n > maxReplayEntries {
		return 0, ErrReplayStore
	}
	return n, nil
}

// InitializeReplayFile explicitly creates NEW state, never overwriting existing
// state. Use only for fresh keys/deployments; resetting state with accepted keys
// can re-enable replay. Normal startup never creates or recreates missing state.
func InitializeReplayFile(path string, maxEntries int) (*FileReplayStore, error) {
	limit, err := replayLimit(maxEntries)
	if err != nil || path == "" {
		return nil, ErrReplayStore
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, ErrReplayStore
	}
	if _, err := os.Lstat(path + ".lock"); !os.IsNotExist(err) {
		return nil, ErrReplayStore
	}
	s := &FileReplayStore{path: path, limit: limit, now: time.Now}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	unlock, err := s.lock(ctx)
	if err != nil {
		return nil, ErrReplayStore
	}
	defer unlock()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		return nil, ErrReplayStore
	}
	if err := s.save(replaySnapshot{high: s.now().UnixNano(), entries: map[[32]byte]int64{}}); err != nil {
		return nil, err
	}
	return s, nil
}

// OpenFileReplayStore requires pre-initialized, private, intact persistent state.
func OpenFileReplayStore(path string, maxEntries int) (*FileReplayStore, error) {
	limit, err := replayLimit(maxEntries)
	if err != nil || path == "" {
		return nil, ErrReplayStore
	}
	if _, err := os.Lstat(path); err != nil {
		return nil, ErrReplayStore
	}
	s := &FileReplayStore{path: path, limit: limit, now: time.Now}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	unlock, err := s.lock(ctx)
	if err != nil {
		return nil, ErrReplayStore
	}
	defer unlock()
	snap, err := s.load()
	if err != nil || s.now().UnixNano() < snap.high {
		return nil, ErrReplayStore
	}
	return s, nil
}

type replaySnapshot struct {
	high    int64
	entries map[[32]byte]int64
}

func (s *FileReplayStore) lock(ctx context.Context) (func(), error) {
	// Only a private directory is supported. Do not follow symlinks for state.
	st, err := os.Lstat(filepath.Dir(s.path))
	if err != nil || !st.IsDir() || st.Mode().Perm()&0077 != 0 || !replayOwnerOK(st) {
		return nil, ErrReplayStore
	}
	return lockReplayFile(ctx, s.path+".lock")
}

func (s *FileReplayStore) load() (replaySnapshot, error) {
	empty := replaySnapshot{}
	st, err := os.Lstat(s.path)
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || !replayOwnerOK(st) {
		return empty, ErrReplayStore
	}
	if st.Size() < replayHeaderSize+sha256.Size || st.Size() > int64(replayHeaderSize+s.limit*40+sha256.Size) {
		return empty, ErrReplayStore
	}
	f, err := os.Open(s.path)
	if err != nil {
		return empty, ErrReplayStore
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, int64(replayHeaderSize+s.limit*40+sha256.Size+1)))
	if err != nil || len(b) < replayHeaderSize+sha256.Size {
		return empty, ErrReplayStore
	}
	data, checksum := b[:len(b)-sha256.Size], b[len(b)-sha256.Size:]
	sum := sha256.Sum256(data)
	if !bytes.Equal(data[:8], replayMagic) || !bytes.Equal(sum[:], checksum) {
		return empty, ErrReplayStore
	}
	high := int64(binary.BigEndian.Uint64(data[8:16]))
	rawCount := binary.BigEndian.Uint32(data[16:20])
	if rawCount > uint32(s.limit) {
		return empty, ErrReplayStore
	}
	count := int(rawCount)
	if high <= 0 || len(data) != replayHeaderSize+count*40 {
		return empty, ErrReplayStore
	}
	snap := replaySnapshot{high: high, entries: make(map[[32]byte]int64, count)}
	for off := replayHeaderSize; off < len(data); off += 40 {
		var tag [32]byte
		copy(tag[:], data[off:off+32])
		expiry := int64(binary.BigEndian.Uint64(data[off+32 : off+40]))
		if expiry <= 0 {
			return empty, ErrReplayStore
		}
		if _, seen := snap.entries[tag]; seen {
			return empty, ErrReplayStore
		}
		snap.entries[tag] = expiry
	}
	return snap, nil
}

func (s *FileReplayStore) save(snap replaySnapshot) error {
	b := append([]byte{}, replayMagic...)
	b = binary.BigEndian.AppendUint64(b, uint64(snap.high))
	b = binary.BigEndian.AppendUint32(b, uint32(len(snap.entries)))
	tags := make([][32]byte, 0, len(snap.entries))
	for tag := range snap.entries {
		tags = append(tags, tag)
	}
	sort.Slice(tags, func(i, j int) bool { return bytes.Compare(tags[i][:], tags[j][:]) < 0 })
	for _, tag := range tags {
		b = append(b, tag[:]...)
		b = binary.BigEndian.AppendUint64(b, uint64(snap.entries[tag]))
	}
	sum := sha256.Sum256(b)
	b = append(b, sum[:]...)
	// Clean only this store's abandoned temporary snapshots under its lock.
	prefix := sha256.Sum256([]byte(filepath.Base(s.path)))
	tempPrefix := fmt.Sprintf(".replay-%x-", prefix[:8])
	entries, err := os.ReadDir(filepath.Dir(s.path))
	if err != nil {
		return ErrReplayStore
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), tempPrefix) {
			info, err := entry.Info()
			if err != nil || !info.Mode().IsRegular() || !replayOwnerOK(info) || info.Mode().Perm()&0077 != 0 {
				return ErrReplayStore
			}
			if err := os.Remove(filepath.Join(filepath.Dir(s.path), entry.Name())); err != nil {
				return ErrReplayStore
			}
		}
	}
	f, err := os.CreateTemp(filepath.Dir(s.path), tempPrefix+"*")
	if err != nil {
		return ErrReplayStore
	}
	temp := f.Name()
	defer os.Remove(temp)
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return ErrReplayStore
	}
	if err := os.Rename(temp, s.path); err != nil {
		return ErrReplayStore
	}
	dir, err := os.Open(filepath.Dir(s.path))
	if err != nil {
		return ErrReplayStore
	}
	err = dir.Sync()
	closeErr = dir.Close()
	if err != nil || closeErr != nil {
		return ErrReplayStore
	}
	return nil
}

func (s *FileReplayStore) CheckAndMark(ctx context.Context, tag [32]byte, expiry time.Time) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	unlock, err := s.lock(ctx)
	if err != nil {
		return false, err
	}
	defer unlock()
	snap, err := s.load()
	if err != nil {
		return false, err
	}
	now := s.now()
	n := now.UnixNano()
	if n < snap.high || !expiry.After(now) || expiry.After(now.Add(24*time.Hour)) {
		return false, ErrReplayStore
	}
	if _, seen := snap.entries[tag]; seen && snap.entries[tag] > n {
		return false, nil
	}
	for k, e := range snap.entries {
		if e <= n {
			delete(snap.entries, k)
		}
	}
	if len(snap.entries) >= s.limit {
		return false, ErrReplayStore
	}
	snap.high = n
	snap.entries[tag] = expiry.UnixNano()
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if err := s.save(snap); err != nil {
		return false, err
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return true, nil
}

// Prune removes expired marks. Like admission it never removes a mark that a
// supported instance could still accept, and it refuses to run while the
// clock is behind the durable watermark.
func (s *FileReplayStore) Prune(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	unlock, err := s.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	snap, err := s.load()
	if err != nil {
		return err
	}
	n := s.now().UnixNano()
	if n < snap.high {
		return ErrReplayStore
	}
	removed := false
	for k, e := range snap.entries {
		if e <= n {
			delete(snap.entries, k)
			removed = true
		}
	}
	if !removed {
		return nil
	}
	snap.high = n
	return s.save(snap)
}
