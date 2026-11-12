# Security review: SingLink Beta Protocol, draft 1 → draft 2

Date: 2026-11-12. Scope: this repository (protocol design, `SPEC.md`, the Go
implementation, CLI, C ABI, deploy files) as of commit `3eb3fd3`.

**Nature of this review.** It was an internal review by two independent
reviewers, working in parallel and in separate copies of the code. One
covered the cryptographic design, the other the implementation. Every
finding marked "reproduced" was confirmed with a test or proof of concept.

It is **not** a substitute for an independent third-party audit, which we
still plan before calling the protocol stable (see SPEC §11).

## Summary

| | Critical | High | Medium | Low | Info |
|---|---|---|---|---|---|
| Cryptographic design (C-) | 0 | 1 | 6 | 5 | 3 |
| Implementation (I-) | 0 | 1 | 8 | 6 | 1 |

No finding broke confidentiality or authentication of user traffic.

The most serious issues were:
- a node could be recognised by its timing (C-1, C-2);
- a node could be taken down by running it out of file descriptors (I-1, I-2);
- the destination policy could be bypassed via NAT64 and other
  special-purpose ranges (I-4).

All High and Medium findings are fixed or mitigated in draft 2. Each fix has
a regression test, named by finding ID in `singlink/audit_test.go` and
`socks5/socks5_test.go`. Fuzz targets for every parser are in
`singlink/fuzz_test.go`; together they ran for several million executions
with no crash.

## Cryptographic design

| ID | Sev. | Finding | Status |
|---|---|---|---|
| C-1 | High | Unauthenticated probes could recognise a node by timing. The node waited for 1138 bytes, so short probes reached the fallback only after the handshake timeout. | **Fixed.** Over TLS the first flight must be one record, and the node decides from that single read. Over raw TCP the node uses a 500 ms idle rule (documented as having no camouflage). Test: `TestProbeTimingIsUniform`. |
| C-2 | Medium | Anyone holding a node's public key could confirm the node by sending a valid length prefix and then stalling. | **Fixed.** The node never waits for a length it decrypted, and the flight length must match exactly. Same test. |
| C-3 | Medium | Expired or revoked credentials still received a SingLink reply, confirming the node. | **Fixed.** Validity and revocation are checked before any byte is sent; failures go to the fallback. Only tokens expired for less than 24 h get an explicit "expired" answer. Test: `TestPermissions`, `TestRevocation`. |
| C-4 | Medium | A connection cut at a frame boundary looked like a clean EOF. | **Fixed.** Only an EOF frame ends a stream; a cut is reported as `io.ErrUnexpectedEOF`, and relays tear down instead of half-closing. Test: `TestTruncationIsAnError`. |
| C-5 | Medium | A 0-RTT flight could be replayed against a restarted process or another node with the same key. | **Mitigated.** Nodes reject flights stamped before the process started. SPEC requires one key per node or a shared replay store. Test: `TestReplayAcrossRestart`. |
| C-6 | Medium | The node's reply had a fixed 49-byte first TLS record, sent before the destination dial. | **Fixed.** `F` and a padded STATUS frame go out in one write after the dial. Still open: the client's first flight is at least about 1.4 KB, which is documented. |
| C-7 | Medium | The spec understated what lacks forward secrecy, and the code comments overclaimed the post-quantum protection. | **Fixed.** SPEC §5.4 now lists exactly what is exposed. Node key rotation is supported (`OldKeys` / `old_private_keys`). Test: `TestKeyRotation`. |
| C-8 | Low | A small-order device key allowed forged proofs of possession. | **Fixed.** Such keys are rejected at issuance and at verification. Test: `TestSmallOrderDeviceKeys`. |
| C-9 | Low | The device signature did not cover the early data and padding. | **Fixed.** The signature is now at the end of the header and covers every byte before it. Accepted as inherent to 0-RTT: whoever has the device key can pre-sign future flights. |
| C-10 | Low | Randomising the top bit did not make `E` look random. | **Accepted.** The randomisation was removed, and SPEC states that the inner flight is distinguishable without TLS. Elligator2 is listed as an open item. |
| C-11 | Low | The AEAD usage limit was far too high. | **Fixed.** Keys are replaced automatically after every 2^24 invocations. Test: `TestRekey`. |
| C-12 | Low | Revocation was weak: live sessions survived it, file changes could be missed, it worked by token only, and the default token lifetime was 30 days. | **Fixed.** Live sessions are closed, changes are detected by content hash, subjects and devices can be revoked, and the CLI default is 1 day. Test: `TestRevocation`. |
| C-13 | Info | Link secrets were in the URL, the pin was on the leaf certificate, and `insecure=1` gave no warning. | **Fixed.** Pins now use SPKI, the client warns on `insecure=1`, and SPEC documents that links are bearer credentials. |
| C-14 | Info | A very large NotAfter value wrapped around. | **Fixed.** Values are bounded at issuance. |
| C-15 | Info | The spec and README had inaccuracies. | **Fixed.** |

## Implementation

| ID | Sev. | Finding | Status |
|---|---|---|---|
| I-1 | High | Any accept error (for example EMFILE) stopped the node. Reproduced. | **Fixed.** Accept errors are retried with backoff, and a total connection cap makes accept wait instead. The systemd unit uses `Restart=always` and `StartLimitIntervalSec=0`. |
| I-2 | Medium | Unauthenticated connections had no cap and were held for 5 minutes. Reproduced. | **Fixed.** Total connections and concurrent handshakes per IP are capped. Fallback connections have a 60 s idle timeout and a 10 min lifetime. |
| I-3 | Medium | Pre-auth CPU amplification: replaying one random blob cost the node a full decapsulation each time. | **Mitigated.** Exact repeats of a failed flight skip all cryptography, each IP has a failure budget, and concurrent decapsulations are capped. Test: `TestGuard`. |
| I-4 | Medium | Destination policy gaps: NAT64, 6to4, Teredo, `0/8`, reserved ranges, the node's own addresses. Reproduced. | **Fixed.** Full IANA special-purpose lists, the NAT64-embedded IPv4 is checked, local addresses are denied, `deny_cidrs` is added, and systemd `IPAddressDeny` adds a second layer. Test: `TestDestinationPolicy`. |
| I-5 | Medium | The fallback website saw every prober as 127.0.0.1. | **Fixed.** Optional PROXY protocol v2, on in the example config. Test: `TestProxyProtocolV2`. |
| I-6 | Medium | Revocation did not end open sessions, and a failed reload could install a partial list. Reproduced. | **Fixed.** See C-12; the whole file is read, and changes are detected by content hash. |
| I-7 | Low/Med | Reconnecting reset the rate limit. Reproduced. | **Fixed.** Limiter state outlives connections until the bucket refills. Test: `TestRateLimitSurvivesReconnect`. |
| I-8 | Low | The UDP relay accepted packets from anyone. | **Fixed.** Only endpoints the client has sent to may answer. Test: `TestUDPDropsUnsolicitedPackets`. |
| I-9 | Medium (local) | Another local process could hijack a SOCKS5 UDP association. Reproduced. | **Fixed.** The peer is pinned to the control connection's IP, and the first source port wins. |
| I-10 | Medium (local) | The local SOCKS5 port needed no authentication and had no limits. | **Mitigated.** Optional random username/password (`Options.Auth`), a session cap, and an IP-literal loopback listen address. Remaining risk: auth stays off by default, because the desktop app uses the port as the system proxy and many applications cannot authenticate. A packet tunnel (Network Extension / VpnService) removes the port entirely. |
| I-11 | Medium | `Close` / `Stop` hung while a CONNECT was open, and there were races in Start/Close. Reproduced. | **Fixed.** Tunnels are tracked and closed, the listener is set synchronously, and the WaitGroup is only touched under the lock. Test: `TestCloseWithOpenConnect`. |
| I-12 | Low | Clock skew and rejections produced a useless "malformed frame" error. Reproduced. | **Fixed.** The client returns `ErrRejected` with advice, and the engine reports the last handshake error. |
| I-13 | Low | Link parse errors echoed the device seed. Reproduced. | **Fixed.** Messages are fixed text. Test: `TestLinkErrorsDoNotLeakSecrets`. |
| I-14 | Low | The engine held its lock during Start, there was no timeout for values ≤ 0, and the C ABI had no panic guard. | **Fixed.** |
| I-15 | Low | Deploy hardening was missing. | **Fixed.** Full systemd sandboxing, `LoadCredential` for the private key, and port 25 always blocked unless `allow_smtp` is set. |
| I-16 | Info | The STATUS frame could be lost to a reset, the handler had no `recover`, and status codes allowed internal DNS enumeration. | **Fixed.** |

## Not covered

- The Flutter client is a separate repository. Its system-proxy manager is
  covered by unit tests, but it was not part of this review.
- Side channels in Go's standard-library cryptography were taken as given.
- Formal verification of the handshake has not been done.
