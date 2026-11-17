# Security policy

Please report vulnerabilities privately through GitHub: open the
**Security** tab of this repository and choose **Report a vulnerability**.
Do not open a public issue for security problems.

Include the version or commit, a description, and if possible a proof of
concept. We aim to acknowledge reports within 3 working days.

Supported versions: the latest commit on `main`. The protocol is a draft
(SingLink Beta, spec draft 4); wire-format changes are still possible.

Past reviews: [docs/SECURITY-AUDIT.md](docs/SECURITY-AUDIT.md) and the
remediation of the 2026-11-13 source audit,
[docs/SECURITY-REMEDIATION.md](docs/SECURITY-REMEDIATION.md).

## Node deployment contract (replay protection)

- Every node needs durable replay state: `replay_file` provisioned once with
  `singlink replay-init` for new keys, in a private directory owned by the
  service user. A node refuses to start, and rejects handshakes, when that
  state is missing, corrupt, full, unreadable or the clock is behind it.
- One state per host is enough for any number of processes on that host
  (Linux, macOS, the BSDs and Windows; on Windows the directory must have a
  private DACL, which `singlink replay-init` creates).
  Nodes on different hosts that accept the same key (including
  `old_private_keys`) must share one external atomic store; separate files per
  host do not protect against replay between them. Simplest: one key per host.
- Never delete, reset or restore an older copy of the state while its keys are
  still accepted.
- Nodes and processes that accept the same key must use the same destination
  policy (`allow_private`, `deny_cidrs`, `blocked_ports`, `allow_smtp`).
  Refusals decided from that policy, the token's capabilities or an unknown
  command do not use the replay store (so they cannot fill it); each process
  keeps them replay-protected in memory. With differing policies, a flight
  refused by one instance could be executed when replayed to another.
- What the state holds: to prevent replay attacks, a node briefly keeps a
  cryptographically processed one-time handshake marker, deleted automatically
  after about 4 minutes. It contains no IP address, destination, account or any
  information that identifies a user, and it is not a log. Details:
  [docs/SECURITY-REMEDIATION.md](docs/SECURITY-REMEDIATION.md).
