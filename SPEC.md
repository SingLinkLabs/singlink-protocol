# SingLink Beta Protocol Specification

Status: **Draft 3** (2026-11-12). Draft 3 binds the protocol identifier
`IDENT` into the handshake (§4). Draft 2 added the fixes from an
internal security review; see [docs/SECURITY-AUDIT.md](docs/SECURITY-AUDIT.md).
**It has not yet had an independent third-party audit.**
Wire version byte: `0x01`. Reference implementation: `singlink/` (Go,
standard library only).

The public protocol and project name is **SingLink Beta**. The legacy ASCII
strings containing `SingLink/1` below are fixed cryptographic compatibility
constants, not the public name. Implementations MUST retain their exact bytes
to interoperate with existing peers; the naming update does not change the wire
format or key derivation.

The key words MUST, SHOULD and MAY are used as in RFC 2119.

## 1. Goals

SingLink is a single-request stream proxy protocol in the family of VLESS
and Trojan. The client opens a connection and sends one request naming a
destination, and the server relays bytes. SingLink keeps that simplicity:
there is no extra round trip, and the first payload rides with the request.
On top of that it adds:

| Property | VLESS | SingLink |
|---|---|---|
| Who may connect | anyone holding the shared UUID | holder of an issuer-signed **permission token** *and* the device key it is bound to |
| Per-user policy at the node | none in protocol (panel-side) | expiry, capabilities (TCP/UDP), rate limit, concurrent-connection limit, revocation (token, subject, device), enforced by every node from the token alone |
| Payload confidentiality | relies on outer TLS (plaintext to a TLS-terminating CDN) | inner AEAD, end to end client ↔ node, independent of the outer transport |
| Post-quantum | no | hybrid X25519 + ML-KEM-768 (FIPS 203) key agreement (see §5.4 for exact scope) |
| Forward secrecy | from outer TLS only | inner ephemeral–ephemeral X25519 for all traffic after the first flight |
| Active probing | fallback (by configuration) | built in: anything that does not authenticate goes to a real website, with no timing difference between kinds of probes over TLS |
| Replay | n/a | timestamp window, ephemeral-key cache, restart rule |
| Length obfuscation | Vision flow (optional) | random header padding and per-frame padding |

Non-goals for SingLink Beta:
- Multiplexing several streams in one connection (use a mux layer above).
- Making the inner bytes indistinguishable from random. The inner flight
  has structure: X25519 keys are curve points and ML-KEM ciphertexts are
  not uniform. Censorship resistance comes from the TLS transport, which
  hides the inner bytes.

## 2. Keys and identities

| Key | Algorithm | Held by | Purpose |
|---|---|---|---|
| Node static key | X25519 + ML-KEM-768 | node (private), clients (public) | authenticates the node, encrypts the request |
| Issuer key | Ed25519 | account backend (private), nodes (public) | signs permission tokens |
| Device key | Ed25519 | the client device (private), embedded in its token (public) | proof of possession on every connection |

Encodings: all binary values in links, configs and the CLI are base64url
without padding.

- Node public key: `X25519 public (32) || ML-KEM-768 encapsulation key (1184)` = 1216 bytes.
- Node private key: `X25519 scalar (32) || ML-KEM-768 seed d||z (64)` = 96 bytes.
- `IDENT` = the ASCII string `SingLink/1 by SingLinkLabs (singlinkvpn.com)`, mixed
  into both handshake salts. It identifies the protocol and its origin, as the
  identifier string does in WireGuard; peers that use a different `IDENT`
  derive different keys and cannot interoperate.
- `server_id = SHA-256("SingLink/1" || node public key)`.
- Issuer key id: first 4 bytes (big-endian uint32) of `SHA-256("SingLink/1 issuer " || issuer public key)`.

Node keys SHOULD be rotated regularly (for example daily or weekly). A node
MAY accept a previous key during the overlap; it tries its current key first
and then the old ones. Old private keys MUST be deleted when the overlap
ends, because they are what protects recorded traffic (§5.4).

## 3. Permission token

160 bytes, all integers big-endian:

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | version = `0x01` |
| 1 | 4 | issuer key id |
| 5 | 16 | token id (random; used for revocation) |
| 21 | 16 | subject (pseudonymous account id; never an e-mail or name) |
| 37 | 32 | device public key (Ed25519) |
| 69 | 8 | not before (unix seconds, 0 ≤ value) |
| 77 | 8 | not after (unix seconds, ≤ 2^40) |
| 85 | 4 | capability bits: `0x1` TCP, `0x2` UDP; other bits reserved (MUST be ignored) |
| 89 | 4 | rate limit, kbit/s, per subject per node; `0` = unlimited |
| 93 | 2 | max concurrent connections per subject per node; `0` = unlimited |
| 95 | 1 | plan id (opaque to nodes) |
| 96 | 64 | Ed25519 signature over `"SingLink token v1\x00" || bytes[0:96]` |

- Nodes hold a set of trusted issuer public keys (several, to allow
  rotation) and look the issuer up by key id.
- Issuers and nodes MUST reject device keys that are small-order points
  (the 7 encodings in `singlink/token.go`, top bit ignored). A token bound
  to such a key would accept forged proofs of possession.
- Issuers SHOULD require a signature by the device key before issuing a
  token for it.
- Token lifetimes SHOULD be short (hours to a few days); the app renews
  them. This keeps revocation lists small.

Revocation: nodes MAY load a list with lines `token <hex id>`,
`subject <hex id>` or `device <base64url key>`. A bare hex value means a
token id. Nodes MUST re-check the list periodically (the reference
implementation checks every 10 s) and close live sessions that become
revoked.

## 4. Transport

SingLink runs over any reliable, ordered byte stream.

- `tls` (default): TCP + TLS 1.3.
  - The node SHOULD present a certificate that a browser would accept for
    its domain, and SHOULD put a real website behind the fallback (§7).
  - ALPN offered by the client: `h2`, `http/1.1`; the node selects
    `http/1.1`.
  - Clients MAY pin the node certificate's public key: the pin is the
    SHA-256 of its SubjectPublicKeyInfo, so it survives renewals that keep
    the key.
  - **The client's first flight MUST be sent as a single TLS record.** It
    is at most 16384 bytes; Go clients set `DynamicRecordSizingDisabled`.
    This lets the node judge a connection from one record, without waiting
    for more data.
- `tcp`: SingLink directly on TCP, for testing or for use inside another
  tunnel. The node collects the first flight until the stream has been idle
  for 500 ms. This mode has no camouflage, and its timing differs from a web
  server's.

Future transports (WebSocket, HTTP/2, QUIC) carry the same byte stream. The
inner encryption makes them safe to route through CDNs.

## 5. Handshake

The handshake is a one-round-trip, Noise-NK-like exchange. The request and
up to 8 KiB of application data are sent in the first flight (0-RTT).

### 5.1 Client first flight

```
E          32 bytes   client ephemeral X25519 public key
CT         1088 bytes ML-KEM-768 ciphertext to the node's encapsulation key
LEN        18 bytes   AEAD_ek(nonce 0, uint16 header length)
HDR        n+16 bytes AEAD_ek(nonce 1, header)
```

The whole flight is at most 16384 bytes, so the header is at most 15230 bytes.

Key schedule (HKDF-SHA-256, AEAD = AES-256-GCM):

```
ss_x  = X25519(e, S_x)
ss_pq = ML-KEM-768.Encaps(S_kem) -> (ss_pq, CT)
salt  = SHA-256(IDENT || "salt" || server_id || E || CT)
ek    = HKDF(ikm = ss_x || ss_pq, salt = salt, info = "singlink early", L = 32)
```

The client MUST NOT use an ephemeral key whose first bytes equal one of the
plaintext prefixes in §7 (it generates a new one), so the node can classify
those connections immediately.

Header plaintext:

```
ver        1   0x01
ts         8   client clock, unix seconds
cmd        1   0x01 TCP, 0x02 UDP
addr       var ATYP(1): 0x01 IPv4(4) | 0x03 domain len(1)+name | 0x04 IPv6(16); then port(2)
tok_len    2
token      tok_len
early_len  2   <= 8192
early      early_len   first application bytes (TCP only)
pad_len    2
pad        pad_len     zeros (random length chosen by the client)
pop_sig    64  Ed25519(device_key, SHA-256("SingLink pop" || salt || every header byte before pop_sig))
```

The device signature covers the whole header, including the early data and
the padding, and through `salt` it is bound to `E`, `CT` and the node. For
`cmd = UDP` the address is ignored (the reference client sends the domain
`udp`, port 0).

### 5.2 Node processing

The node MUST perform these checks before sending any byte. Every failure in
this list is **silent**: the connection is handed to the fallback (§7) with
all bytes read so far.

1. The first flight is read as described in §4. The node MUST NOT wait for
   more data because of a length it decrypted.
2. The first bytes do not match a plaintext prefix, the flight is at least
   1138 bytes, `E` and `CT` decode, and the X25519 result is not all-zero.
3. `LEN` and `HDR` authenticate under `ek` for one of the node's keys. The
   flight length equals exactly `1138 + header length + 16`, and the header
   is well-formed.
4. The token signature verifies under a trusted issuer, and the token's
   device key is not small-order.
5. `pop_sig` verifies under the token's device key.
6. `|now − ts| ≤ 120 s`, and `ts` is not earlier than the moment the node
   process started (§5.4, replay).
7. The token is currently valid and not revoked. Exception: a token that
   expired less than 24 h ago gets an explicit "expired" answer (step 9),
   so the app can tell the user.
8. `E` has not been seen within the last 2 × 120 s (replay cache).

After step 8 the peer is an authenticated user, and the node answers.

### 5.3 Node reply

```
F          32 bytes   node ephemeral X25519 public key
frames...             sealed with s2c (§6); the first frame is STATUS (padded)
```

`F` and the first frame MUST be written together, in one write (one TLS
record).

```
ee    = X25519(f, E)
tsalt = SHA-256(IDENT || "traffic" || salt || F || SHA-256(LEN || HDR))
c2s   = HKDF(ikm = ss_x || ss_pq || ee, salt = tsalt, info = "singlink c2s", L = 32)
s2c   = HKDF(ikm = ss_x || ss_pq || ee, salt = tsalt, info = "singlink s2c", L = 32)
```

Status codes (code ≠ 0 is followed by half-close of the connection):

| Code | Meaning |
|---|---|
| 0 | OK, relaying |
| 1 | token expired (only within 24 h after expiry; later the connection goes to the fallback) |
| 4 | destination forbidden by node policy (IP literal) |
| 5 | capability not granted (e.g. UDP) |
| 6 | too many concurrent connections for this subject |
| 7 | destination unreachable (also used for names that resolve only to forbidden addresses) |
| 8 | bad request |

Codes 2 (revoked) and 3 (not yet valid) are reserved. Those cases go to the
fallback silently.

- For TCP, the node resolves and dials the destination before sending
  `STATUS OK`, then writes the early data to it.
- The connection is closed when the token's `not after` passes, or when the
  token, its subject or its device is revoked.

A client that reads `HTTP/` instead of `F` has been handed to the fallback.
It SHOULD tell the user to check the device clock and renew the link.

### 5.4 Security properties and their limits (informal)

- **Node authentication and request confidentiality.** Only the holder of
  the node's static keys can derive `ek`. Breaking it requires breaking
  **both** X25519 and ML-KEM-768.
- **What is not forward secret.** The entire first flight (`HDR`) is
  protected only by the node's static keys:
  - the token (subject id, plan, device key),
  - the destination,
  - the timestamp,
  - up to 8 KiB of early data (often a TLS ClientHello with the SNI, or a
    plain HTTP request).

  Anyone who records traffic and later obtains a node static key can read
  these. This is the same class of exposure as TLS 1.3 0-RTT and Noise NK.
  Rotate node keys and delete old ones (§2).
- **Forward secrecy.** All traffic after the first flight is keyed with
  `ee` as well, so it is forward secret against classical attackers.
- **Post-quantum scope.** Against a future quantum attacker, recorded
  traffic is safe only while the node's static ML-KEM key stays secret.
  SingLink Beta has **no post-quantum forward secrecy** (§11).
- **Client authentication.** Token signature plus device proof of
  possession over the whole header, bound to this handshake's `salt`. A
  token copied from one node is useless without the device key. Exception:
  links that embed the device seed (§9) are bearer credentials.
- **Replay.**
  - Within a node process, a captured first flight is rejected by the
    ephemeral-key cache.
  - Across restarts, the node rejects flights stamped before it started.
    The cost: clients whose clock lags the node's are refused for up to
    that lag after a restart.
  - Nodes that share a static key do not share a replay cache. Give each
    node (and each process) its own key, or share a replay store.
- **Truncation.** A stream ends cleanly only with an EOF frame. An
  implementation MUST report a stream that ends without one as an error,
  never as end of data.
- **Without TLS.** With `tcp`, `insecure=1`, or an intercepted TLS
  connection, the inner handshake still gives confidentiality, integrity,
  node authentication and client authentication. What is lost is
  camouflage: the flight structure is visible.

## 6. Frames

After the handshake each direction is a sequence of frames:

```
AEAD(nonce n,   uint16 body_len)            18 bytes
AEAD(nonce n+1, type(1) || data_len(2) || data || padding)   body_len + 16 bytes
```

- Nonce: 96 bits. The first 8 bytes are a little-endian invocation counter
  starting at 0 per key; the rest are zero.
- Rekeying: after 2^24 AEAD invocations under one key, both sides replace
  the key with `HKDF(ikm = key, salt = none, info = "singlink rekey", L = 32)`
  and reset the counter to 0. This needs no signalling.
- `3 ≤ body_len ≤ 3 + 16384 + 1024`; `data_len ≤ body_len − 3`.
- Implementations SHOULD pad the first 8 frames of each direction with a
  random amount (0–512 bytes in the reference implementation).

| Type | Name | Data |
|---|---|---|
| 0 | DATA | stream bytes |
| 1 | PADDING | ignored |
| 2 | EOF | empty; sender will send no more DATA (half close). The only clean end of a stream. |
| 3 | UDP | ATYP address + port, then one datagram (≤ 16124 bytes) |
| 4 | STATUS | code(1) || optional UTF-8 message; node → client, first frame only |

Unknown frame types MUST close the connection.

UDP: the node MUST only relay datagrams back from endpoints the client has
sent to during the session.

## 7. Fallback and probing resistance

The node keeps every byte of the first flight. If the connection does not
authenticate (§5.2), the node opens a TCP connection to the configured
fallback address, writes those bytes and relays both directions, so the
prober talks to an ordinary website.

- The node MAY prefix the fallback connection with a PROXY protocol v2
  header, so the website sees the prober's real address instead of the node.
  It SHOULD do so, or serve the fallback from a site that grants no trust to
  loopback.
- Fallback connections SHOULD have their own idle timeout (60 s) and a
  maximum lifetime (10 min).
- Without a fallback, the node reads and discards until the handshake
  timeout.

Plaintext prefixes that are classified immediately: `GET `, `POST`, `HEAD`,
`PUT `, `OPTI`, `DELE`, `PATC`, `TRAC`, `CONN`, `PRI `, `0x16 0x03`, `SSH-`.

Over TLS, every unauthenticated first record reaches the fallback right away:
short, long, random, or a valid prefix with a missing header. That removes
the timing difference.

**Pre-authentication limits.** Nodes SHOULD bound what unauthenticated peers
can cost them. The reference implementation:
- caps total connections, waiting in accept instead of failing;
- caps concurrent unauthenticated handshakes per IP;
- limits handshake cryptography for IPs that keep failing;
- skips cryptography for an exact repeat of a flight that already failed;
- caps concurrent decapsulations.

All of these still end at the fallback. Accept errors (for example, out of
file descriptors) MUST NOT stop the node.

## 8. Node destination policy

Independently of tokens, nodes SHOULD refuse:
- every IANA special-purpose IPv4 and IPv6 range: `0/8`, `10/8`,
  `100.64/10`, `127/8`, `169.254/16`, `172.16/12`, `192.0.0/24`,
  `192.0.2/24`, `192.88.99/24`, `192.168/16`, `198.18/15`,
  `198.51.100/24`, `203.0.113/24`, `224/4`, `240/4`, `::/96`,
  `::ffff:0:0/96`, `64:ff9b:1::/48`, `100::/64`, `2001::/23`,
  `2001:db8::/32`, `2002::/16`, `fc00::/7`, `fe80::/10`, `fec0::/10`,
  `ff00::/8`;
- the IPv4 address embedded in `64:ff9b::/96` (NAT64), when it is itself
  non-public;
- the node's own interface addresses;
- operator-configured CIDRs;
- port 25.

Domain names are resolved by the node, and the **checked IP** is the one
dialled, so DNS rebinding cannot bypass the policy. A name that resolves
only to forbidden addresses is answered like an unresolvable name (status 7).
Nodes SHOULD NOT log destinations.

## 9. Client link

```
singlink://<token>.<device-seed>@host:port?pk=<node-public-key>&tr=tls&sni=<name>&pin=<spki-sha256>#<name>
```

- The link contains the device secret and MUST be handled like a password.
  Implementations MUST NOT echo it in error messages.
- Whoever creates a link knows the seed, so a token delivered by link is
  effectively a bearer credential.
- Production apps SHOULD generate the device key on the device and ask the
  account backend to issue a token for its public key, instead of receiving
  a link.
- A link is about 2 KB, mostly the ML-KEM key. Subscription formats MAY
  reference node keys by `server_id` instead.
- Clients SHOULD warn when `insecure=1` is used without `pin`.

## 10. Versioning

The header `ver` byte and the token `version` byte allow new versions. A
node that receives an unknown version treats the connection as
unauthenticated.

## 11. Open items

- Independent third-party cryptographic review, and a formal model of the
  handshake (Tamarin or ProVerif).
- Post-quantum forward secrecy (ephemeral ML-KEM in the reply).
- Elligator2-encoded ephemeral keys, for transports without TLS.
- uTLS-style client fingerprints for the `tls` transport; WebSocket,
  HTTP/2 and QUIC transports.
- Stream multiplexing and connection reuse.
- Interoperability test vectors (deterministic keys and nonces).
