// Copyright 2026 SingLinkLabs
// SPDX-License-Identifier: Apache-2.0
package singlink

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"
)

const maxRevocationBytes = 4 << 20
const maxRevocationLine = 64 << 10

var errRevocations = errors.New("singlink: invalid or unavailable revocation list")

func readRevocations(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errRevocations
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxRevocationBytes+1))
	if err != nil || len(b) > maxRevocationBytes {
		return nil, errRevocations
	}
	return b, nil
}

func parseRevocations(b []byte) (revocations, error) {
	r := revocations{tokens: map[[16]byte]bool{}, subjects: map[[16]byte]bool{}, devices: map[string]bool{}}
	if len(b) == 0 || len(b) > maxRevocationBytes || b[len(b)-1] != '\n' {
		return r, errRevocations
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 4096), maxRevocationLine)
	empty := false
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 0 || strings.HasPrefix(f[0], "#") {
			continue
		}
		if len(f) == 1 && f[0] == "empty" {
			empty = true
			continue
		}
		kind, val := "token", f[0]
		if len(f) == 2 {
			kind, val = f[0], f[1]
		} else if len(f) != 1 {
			return r, errRevocations
		}
		switch kind {
		case "token", "subject":
			id, err := hex.DecodeString(val)
			if err != nil || len(id) != 16 {
				return r, errRevocations
			}
			if kind == "token" {
				r.tokens[[16]byte(id)] = true
			} else {
				r.subjects[[16]byte(id)] = true
			}
		case "device":
			k, err := B64.DecodeString(val)
			if err != nil || len(k) != 32 {
				return r, errRevocations
			}
			r.devices[string(k)] = true
		default:
			return r, errRevocations
		}
	}
	if sc.Err() != nil {
		return r, errRevocations
	}
	count := len(r.tokens) + len(r.subjects) + len(r.devices)
	if (count == 0 && !empty) || (count > 0 && empty) {
		return r, errRevocations
	}
	return r, nil
}
