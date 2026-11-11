# SingLink Protocol Specification (SingLink/1)

Status: **Draft 1 — not yet independently audited.** Wire version byte: `0x01`.
Reference implementation: `core/singlink` (Go, standard library only).

The key words MUST, SHOULD and MAY are used as in RFC 2119.

## 1. Goals

SingLink is a single-request stream proxy protocol in the family of VLESS and
Trojan: the client opens a connection, sends one request naming a
destination, and the server relays bytes. SingLink keeps that simplicity
(no extra round trip, the first payload rides with the request) and adds:

| Property | VLESS | SingLink |
|---|---|---|
| Who may connect | anyone holding the shared UUID | holder of an issuer-signed **permission token** *and* the device key it is bound to |
| Per-user policy at the node | none in protocol (panel-side) | expiry, capabilities (TCP/UDP), rate limit, concurrent-connection limit, revocation — enforced by every node from the token alone |
| Payload confidentiality | relies on outer TLS (plaintext to a TLS-terminating CDN) | inner AEAD, end to end client ↔ node, independent of the outer transport |
| Post-quantum | no | hybrid X25519 + ML-KEM-768 (FIPS 203) key agreement |
| Forward secrecy | from outer TLS only | inner ephemeral–ephemeral X25519 |
| Active probing | fallback (by configuration) | built in: every unauthenticated byte stream is handed to a real website, plaintext probes immediately |
| Replay | n/a | timestamp window + ephemeral-key cache |
| Length obfuscation | Vision flow (optional) | random header padding and per-frame padding |

Non-goals for SingLink/1: multiplexing several streams in one connection
(use a mux layer above), and making the raw-TCP transport indistinguishable
from random bytes (use the TLS transport for censorship resistance).

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
- `server_id = SHA-256("SingLink/1" || node public key)`.
- Issuer key id: first 4 bytes (big-endian uint32) of `SHA-256("SingLink/1 issuer " || issuer public key)`.

## 3. Permission token

160 bytes, all integers big-endian:

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | version = `0x01` |
| 1 | 4 | issuer key id |
| 5 | 16 | token id (random; used for revocation) |
| 21 | 16 | subject (pseudonymous account id; never an e-mail or name) |
| 37 | 32 | device public key (Ed25519) |
| 69 | 8 | not before (unix seconds) |
| 77 | 8 | not after (unix seconds) |
| 85 | 4 | capability bits: `0x1` TCP, `0x2` UDP; other bits reserved (MUST be ignored) |
| 89 | 4 | rate limit, kbit/s, per subject per node; `0` = unlimited |
| 93 | 2 | max concurrent connections per subject per node; `0` = unlimited |
| 95 | 1 | plan id (opaque to nodes) |
| 96 | 64 | Ed25519 signature over `"SingLink token v1\x00" || bytes[0:96]` |

Nodes hold a set of trusted issuer public keys (several, to allow rotation)
and look the issuer up by key id. Tokens are bearer credentials only together
with the device key (§5.3), so a token observed on a compromised node cannot
be replayed elsewhere.

Revocation: nodes MAY load a list of revoked token ids. Issuers SHOULD keep
token lifetimes short (hours to days) and re-issue, so that revocation lists
stay small.

## 4. Transport

SingLink runs over any reliable, ordered byte stream.

- `tls` (default): TCP + TLS 1.3. The node SHOULD present a certificate that a
  browser would accept for its domain and SHOULD put a real website behind
  the fallback (§7). ALPN offered by the client: `h2`, `http/1.1`; the node
  selects `http/1.1`. Clients MAY pin the certificate (SHA-256 of the leaf
  DER) instead of using the Web PKI.
- `tcp`: SingLink directly on TCP. For testing or for use inside another tunnel.

Future transports (WebSocket, HTTP/2, QUIC) carry the same byte stream; the
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

Key schedule (HKDF-SHA-256, AEAD = AES-256-GCM):

```
ss_x  = X25519(e, S_x)
ss_pq = ML-KEM-768.Encaps(S_kem) -> (ss_pq, CT)
salt  = SHA-256("SingLink/1" || "salt" || server_id || E || CT)
ek    = HKDF(ikm = ss_x || ss_pq, salt = salt, info = "singlink early", L = 32)
```

`E` on the wire: the client MUST set bit 255 (the top bit of byte 31) to a
random value; receivers MUST clear it before use. The client MUST NOT use an
ephemeral key whose first bytes equal one of the plaintext prefixes in §7
(it generates a new one), so the node can classify those immediately.

Header plaintext:

```
ver        1   0x01
ts         8   client clock, unix seconds
cmd        1   0x01 TCP, 0x02 UDP
addr       var ATYP(1): 0x01 IPv4(4) | 0x03 domain len(1)+name | 0x04 IPv6(16); then port(2)
tok_len    2
token      tok_len
pop_sig    64  Ed25519(device_key, SHA-256("SingLink pop" || salt || ver..token))
early_len  2   <= 8192
early      early_len   first application bytes (TCP only)
pad_len    2
pad        pad_len     zeros (random length chosen by the client)
```

For `cmd = UDP` the address is ignored (the reference client sends the
domain `udp`, port 0).

### 5.2 Node processing

The node MUST perform these checks. Every failure in this list is
**silent**: the connection is handed to the fallback (§7) with all bytes
read so far, and no SingLink byte is ever sent.

1. First 4 bytes match a plaintext prefix → fallback immediately.
2. `E` and `CT` decode; X25519 result is not all-zero.
3. `LEN` and `HDR` authenticate under `ek`; header is well-formed; header length ≤ 16 KiB.
4. Token signature verifies under a trusted issuer.
5. `pop_sig` verifies under the token's device key.
6. `|now − ts| ≤ 120 s`.
7. `E` has not been seen within the last 2 × 120 s (replay cache).

After step 7 the peer is an authenticated user and the node answers.

### 5.3 Node reply

```
F          32 bytes   node ephemeral X25519 public key (bit 255 randomised)
frames...             sealed with s2c (§6); the first frame is STATUS
```

```
ee    = X25519(f, E)
tsalt = SHA-256("SingLink/1" || "traffic" || salt || F || SHA-256(LEN || HDR))
c2s   = HKDF(ikm = ss_x || ss_pq || ee, salt = tsalt, info = "singlink c2s", L = 32)
s2c   = HKDF(ikm = ss_x || ss_pq || ee, salt = tsalt, info = "singlink s2c", L = 32)
```

Policy checks, answered with a STATUS frame and then close:

| Code | Meaning |
|---|---|
| 0 | OK — relaying |
| 1 | token expired |
| 2 | token revoked |
| 3 | token not yet valid |
| 4 | destination forbidden by node policy |
| 5 | capability not granted (e.g. UDP) |
| 6 | too many concurrent connections for this subject |
| 7 | destination unreachable |
| 8 | bad request |

For TCP the node resolves and dials the destination before sending
`STATUS OK`, then writes the early data to it. The connection is closed
when the token's `not after` passes.

### 5.4 Security properties (informal)

- Request confidentiality and node authentication: only the holder of the
  node's static keys can derive `ek`. Breaking it requires breaking **both**
  X25519 and ML-KEM-768.
- Early data has no forward secrecy against later compromise of the node's
  static keys (same as TLS 1.3 0-RTT and Noise NK). All later traffic uses
  `ee` and is forward secret against classical adversaries; it is protected
  against quantum adversaries as long as the node's ML-KEM key stays secret.
- Client authentication: token signature + device proof of possession bound
  to this handshake's `salt` (and therefore to `E`, `CT` and the node).
- Replay: 0-RTT data can only be replayed within the timestamp window and
  is rejected by the ephemeral-key cache on the same node. Deployments with
  many nodes sharing a static key SHOULD give each node its own key.

## 6. Frames

After the handshake each direction is a sequence of frames:

```
AEAD(nonce n,   uint16 body_len)            18 bytes
AEAD(nonce n+1, type(1) || data_len(2) || data || padding)   body_len + 16 bytes
```

- Nonce: 96 bits, the first 8 bytes are a little-endian counter starting at 0
  per key, the rest zero. Endpoints MUST close the connection before the
  counter reaches 2^62.
- `3 ≤ body_len ≤ 3 + 16384 + 1024`; `data_len ≤ body_len − 3`.
- Implementations SHOULD pad the first 8 frames of each direction with a
  random amount (0–512 bytes in the reference implementation).

| Type | Name | Data |
|---|---|---|
| 0 | DATA | stream bytes |
| 1 | PADDING | ignored |
| 2 | EOF | empty; sender will send no more DATA (half close) |
| 3 | UDP | ATYP address + port, then one datagram (≤ 16124 bytes) |
| 4 | STATUS | code(1) || optional UTF-8 message; node → client, first frame only |

Unknown frame types MUST close the connection.

## 7. Fallback and probing resistance

The node keeps every byte read during the handshake. If the connection does
not authenticate (§5.2), it opens a TCP connection to the configured fallback
address, writes those bytes and relays both directions, so the prober talks
to an ordinary website. Without a fallback, the node reads and discards until
the handshake timeout.

Plaintext prefixes that trigger immediate fallback: `GET `, `POST`, `HEAD`,
`PUT `, `OPTI`, `DELE`, `PATC`, `TRAC`, `CONN`, `PRI `, `0x16 0x03`, `SSH-`.
Other short probes reach the fallback after the handshake timeout (10 s by
default).

## 8. Node destination policy

Independently of tokens, nodes SHOULD refuse loopback, private (RFC 1918 /
ULA), link-local, CGNAT (100.64/10), multicast and unspecified addresses,
and port 25. Domain names are resolved by the node and the **checked IP** is
dialled, so DNS rebinding cannot bypass the policy. Nodes SHOULD NOT log
destinations.

## 9. Client link

```
singlink://<token>.<device-seed>@host:port?pk=<node-public-key>&tr=tls&sni=<name>&pin=<sha256>#<name>
```

The link contains the device secret and MUST be handled like a password.
Production apps SHOULD generate the device key on the device and ask the
account backend to issue a token for its public key, instead of receiving a
link that contains the seed. A link is about 2 KB, mostly the ML-KEM key;
subscription formats MAY reference node keys by `server_id` instead.

## 10. Versioning

The header `ver` byte and token `version` byte allow new versions. A node
that receives an unknown version treats the connection as unauthenticated.

## 11. Open items before 1.0 final

- Independent cryptographic review and a formal model of the handshake (e.g. Tamarin/ProVerif).
- uTLS-style client fingerprints for the `tls` transport; WebSocket / HTTP/2 / QUIC transports.
- Optional post-quantum forward secrecy (ephemeral ML-KEM in the reply).
- Stream multiplexing and connection reuse.
- Rekeying for very long connections.
- Interoperability test vectors (deterministic keys and nonces).
