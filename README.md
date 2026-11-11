# SingLink 3.0 Protocol (SL3)

**[繁體中文說明 →](README.zh-Hant.md)**

SL3 is an open proxy/VPN protocol from SingLinkLabs. It keeps what makes
VLESS and Trojan fast — one request at the start of a TLS connection, the
first payload in the same flight, no extra round trip — and adds what a
production VPN service needs:

- **Permission tokens instead of a shared UUID.** The account backend signs
  a 160-byte token (expiry, TCP/UDP capabilities, rate limit, connection
  limit, plan). Every node verifies and enforces it offline — no user
  database on the node.
- **Device-bound credentials.** Each token is bound to a device key; the
  client proves possession on every connection, so a token copied from a
  compromised node is useless.
- **End-to-end inner encryption** (AES-256-GCM), independent of the outer TLS,
  so the payload stays private even through a TLS-terminating CDN.
- **Post-quantum hybrid key agreement**: X25519 + ML-KEM-768 (FIPS 203),
  with ephemeral X25519 forward secrecy.
- **Probe resistance**: anything that does not authenticate is handed,
  byte for byte, to a real website; plaintext probes immediately.
- **Replay protection, length padding, half-close, UDP relay**, and a
  node-side policy that blocks private networks and SMTP by default.

The full wire format is in **[SPEC.md](SPEC.md)**.

> **Status: 3.0.0-draft.** The design uses only standard primitives from the
> Go standard library, and the implementation is fully tested, but neither
> has had an independent security audit yet. Do not rely on it for high-risk
> use until it has.

## Repository layout

| Path | What |
|---|---|
| `SPEC.md` | Protocol specification (SL3/1) |
| `core/sl3` | Protocol library (Go, standard library only) |
| `core/socks5` | Local SOCKS5 inbound (CONNECT + UDP ASSOCIATE) |
| `core/engine` | Client runtime shared by the CLI and the C ABI |
| `core/cmd/sl3` | CLI: key generation, tokens, links, node, client, demo |
| `core/ffi` | `libsl3` C ABI for apps |
| `app/` | Flutter client shell (macOS), loads `libsl3` via `dart:ffi` |
| `deploy/` | Example node config and systemd unit |

## Quick start (one machine)

Requires Go ≥ 1.24.

```sh
cd core
go test ./...
go build -o build/sl3 ./cmd/sl3
./build/sl3 demo            # local node + client on 127.0.0.1:1080
curl -x socks5h://127.0.0.1:1080 https://www.gstatic.com/generate_204 -i
```

To try the Flutter app, run `./build/sl3 demo -link-only`, build the app
(see `app/README.md`) and paste the printed `sl3://` link.

## Running a node

```sh
sl3 keygen server   > node-key.json     # private_key stays on the node
sl3 keygen issuer   > issuer.json       # seed stays on the account backend
sl3 keygen device   > device.json       # normally generated on the user's device
sl3 token issue -issuer <issuer seed> -device <device public key> -days 30 -caps tcp,udp
sl3 link -server vpn.example.com:443 -pk <node public key> -token <token> -device <device seed> -sni vpn.example.com
sl3 server -c deploy/server.example.json
```

Put a real website on the node's domain and point `fallback` at it (for
example nginx on `127.0.0.1:8080`), and use a certificate the Web PKI
accepts.

## Building libsl3 and the app

```sh
make -C core lib       # core/build/libsl3.dylib (universal) + libsl3.h
make -C core cli       # core/build/sl3
cd app && flutter build macos --release
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).
