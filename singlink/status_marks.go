// Copyright 2026 SingLinkVPN (https://singlinkvpn.com)
// SPDX-License-Identifier: Apache-2.0
package singlink

import (
	"container/heap"
	"sync"
	"time"
)

const (
	// defaultStatusMarks bounds the per-process marks kept for status-only
	// answers.
	defaultStatusMarks = 32768
	// statusMarksPerSubject bounds what one subject may hold, so a single
	// account cannot fill the set and silence other subjects' answers.
	statusMarksPerSubject = 256
)

// statusMarks remembers, inside one node process, the opaque replay tags of
// authenticated flights that were answered with a refusal status only (token
// expired, capability not granted, unknown command, destination refused by the
// node's configured policy). Those answers never perform a destination
// operation, so they are decided before the durable ReplayStore and never
// consume its capacity. This bounded in-memory set keeps a replayed copy of
// such a flight from getting a node answer a second time from this process:
// the copy goes to the fallback exactly like any other replay. When the set,
// or the subject's share of it, is full a further status-only answer is not
// given at all (the flight goes to the fallback); admission of permitted
// flights never depends on this set.
//
// Like the durable markers it holds only keyed one-way hashes and expiries
// (plus, transiently, a per-subject counter for the quota), and entries
// disappear when their timestamp window ends.
type statusMarks struct {
	mu         sync.Mutex
	limit      int
	perSubject int
	m          map[[32]byte]int64
	subjects   map[[16]byte]int
	h          expiryHeap
}

type expiryEntry struct {
	exp     int64
	tag     [32]byte
	subject [16]byte
}

type expiryHeap []expiryEntry

func (h expiryHeap) Len() int           { return len(h) }
func (h expiryHeap) Less(i, j int) bool { return h[i].exp < h[j].exp }
func (h expiryHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *expiryHeap) Push(x any)        { *h = append(*h, x.(expiryEntry)) }
func (h *expiryHeap) Pop() any {
	old := *h
	e := old[len(old)-1]
	*h = old[:len(old)-1]
	return e
}

// pruneLocked drops marks whose window has ended.
func (s *statusMarks) pruneLocked(now int64) {
	for len(s.h) > 0 && s.h[0].exp <= now {
		e := heap.Pop(&s.h).(expiryEntry)
		if s.m[e.tag] == e.exp {
			delete(s.m, e.tag)
		}
		if s.subjects[e.subject]--; s.subjects[e.subject] <= 0 {
			delete(s.subjects, e.subject)
		}
	}
}

// seen reports whether tag holds an unexpired status-only mark.
func (s *statusMarks) seen(tag [32]byte, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := now.UnixNano()
	s.pruneLocked(n)
	exp, ok := s.m[tag]
	return ok && exp > n
}

// mark inserts tag for subject until expiry. replay reports a tag that is
// already marked; marked=false without replay means no room (the set or the
// subject's quota is full, or expiry has passed). Either way the caller sends
// no status.
func (s *statusMarks) mark(tag [32]byte, subject [16]byte, expiry, now time.Time) (marked, replay bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := now.UnixNano()
	s.pruneLocked(n)
	if exp, ok := s.m[tag]; ok && exp > n {
		return false, true
	}
	limit, perSubject := s.limit, s.perSubject
	if limit <= 0 {
		limit = defaultStatusMarks
	}
	if perSubject <= 0 {
		perSubject = statusMarksPerSubject
	}
	if len(s.m) >= limit || s.subjects[subject] >= perSubject || !expiry.After(now) {
		return false, false
	}
	if s.m == nil {
		s.m = map[[32]byte]int64{}
		s.subjects = map[[16]byte]int{}
	}
	s.m[tag] = expiry.UnixNano()
	s.subjects[subject]++
	heap.Push(&s.h, expiryEntry{exp: expiry.UnixNano(), tag: tag, subject: subject})
	return true, false
}
