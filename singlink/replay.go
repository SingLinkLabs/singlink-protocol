// Copyright 2026 SingLinkLabs
// SPDX-License-Identifier: Apache-2.0
package singlink

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
)

// replayTagFor returns the opaque one-time mark stored for an accepted first flight.
// It is keyed with a secret derived from the static key that decrypted the
// flight, so the tag is stable across restarts, instances and key rotation
// (OldKeys), but the stored state cannot be matched against captured traffic
// without that node private key. Only local replay state uses it; nothing
// on the wire changes.
func replayTagFor(key *ServerPrivateKey, E []byte) [32]byte {
	k, err := hkdf.Key(sha256.New, key.x.Bytes(), key.pub.id[:], "singlink replay tag", 32)
	if err != nil {
		panic(err) // unreachable: fixed-size output from a valid hash
	}
	m := hmac.New(sha256.New, k)
	m.Write(E)
	var tag [32]byte
	copy(tag[:], m.Sum(nil))
	return tag
}
