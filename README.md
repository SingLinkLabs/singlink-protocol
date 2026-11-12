# SingLink Protocol

**[繁體中文說明 →](README.zh-Hant.md)**

SingLink/1 is the first-generation version of the SingLink protocol, an open
proxy/VPN protocol from SingLinkLabs. It keeps what makes
VLESS and Trojan fast: one request at the start of a TLS connection, with the
first payload in the same flight and no extra round trip. On top of that it
adds what a production VPN service needs.

- **Permission tokens instead of a shared UUID.** The account backend signs
  a 160-byte token carrying expiry, TCP/UDP capabilities, rate limit,
  connection limit and plan. Every node verifies and enforces it offline,
  so there is no user database on the node. Tokens can be revoked by token,
  account or device, and revocation also closes live sessions.
- **Device-bound credentials.** Each token is bound to a device key, and the
  client proves possession on every connection. A token copied from a
  compromised node is useless without that key.
- **End-to-end inner encryption** (AES-256-GCM) that does not depend on the
  outer TLS, so the payload stays private even through a TLS-terminating CDN.
- **Hybrid post-quantum key agreement**: X25519 + ML-KEM-768 (FIPS 203), with
  ephemeral X25519 forward secrecy. See SPEC §5.4 for exactly what is
  covered.
- **Probe resistance.** Anything that does not authenticate is handed byte
  for byte to a real website, with no timing difference between kinds of
  probes. Expired, revoked and replayed credentials get the same treatment.
- **Hardened nodes.** They have:
  - connection and per-IP limits, and a CPU budget for handshakes;
  - a complete special-purpose-address block list (including NAT64), and no
    access to the node's own addresses;
  - PROXY protocol towards the decoy site;
  - replay protection across restarts;
  - automatic rekeying.

The wire format is in **[SPEC.md](SPEC.md)**. The internal security review
and its fixes are in **[docs/SECURITY-AUDIT.md](docs/SECURITY-AUDIT.md)**.

> **Status: 1.0.0-draft (spec draft 3).** The protocol uses only standard
> primitives from the Go standard library. It has been through an internal
> security review, with a regression test for every finding plus fuzzing.
> **A third-party audit is planned**; until it is complete, evaluate the
> protocol carefully before high-risk use.

SingLinkLabs released its first-generation protocol and client code after a
security audit. The latest versions (the SingLink 2.0 core and the current
SingLinkVPN apps) are not yet fully public for security reasons, so only code
that poses no security risk was released. The open-source plan continues, and
more will be released in later phases after security review. The
first-generation SingLinkVPN client built on this protocol is at
[SingLinkLabs/singlink-vpn-app](https://github.com/SingLinkLabs/singlink-vpn-app).

## Layout

| Path | What |
|---|---|
| `SPEC.md` | Protocol specification (SingLink/1) |
| `singlink/` | Protocol library (Go, standard library only) |
| `socks5/` | Local SOCKS5 inbound (CONNECT + UDP ASSOCIATE, optional auth) |
| `engine/` | Client runtime shared by the CLI and the C ABI |
| `cmd/singlink/` | CLI: key generation, tokens, links, node, client, demo |
| `ffi/` | `libsinglink` C ABI for apps |
| `deploy/` | Example node config and hardened systemd unit |
| `docs/` | Security review |

The reference desktop client (Flutter) lives in a separate repository.

## Quick start (one machine)

Requires Go ≥ 1.24.

```sh
make test
make cli
./build/singlink demo      # local node + client on 127.0.0.1:1080
curl -x socks5h://127.0.0.1:1080 https://www.gstatic.com/generate_204 -i
```

## Running a node

```sh
singlink keygen server  > node-key.json     # private_key stays on the node; rotate it regularly
singlink keygen issuer  > issuer.json       # seed stays on the account backend
singlink keygen device  > device.json       # normally generated on the user's device
singlink token issue -issuer <issuer seed> -device <device public key> -days 1 -caps tcp,udp
singlink link -server vpn.example.com:443 -pk <node public key> -token <token> -device <device seed> -sni vpn.example.com
singlink server -c deploy/server.example.json
```

- Put a real website on the node's domain and point `fallback` at it (for
  example nginx on `127.0.0.1:8080` with PROXY protocol enabled).
- Use a certificate that the Web PKI accepts.
- Install `deploy/singlink.service` (systemd) to run the node.

## Building the library for apps

```sh
make lib       # build/libsinglink.dylib (universal macOS) + libsinglink.h
make linux     # static node binaries for Linux amd64/arm64
```

## Reporting vulnerabilities

Please report security issues privately, not in public issues. See
[SECURITY.md](SECURITY.md).

## License

Apache License 2.0, see [LICENSE](LICENSE) and [NOTICE](NOTICE).
Redistributions and derivative works must keep the copyright headers and the
NOTICE attribution ("Based on the SingLink Protocol by SingLinkLabs"). "SingLink"
and "SingLinkVPN" are trademarks of SingLinkLabs: a modified version must use its
own name.
