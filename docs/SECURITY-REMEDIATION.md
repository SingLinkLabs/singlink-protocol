# Security remediation candidate

This change set addresses the five findings against the first-generation
open-source protocol baseline `78cde5ee`. It is not a claim about the current
commercial service and does not alter the earlier audit evidence or report.
Independent remediation verification must complete before publishing a passed
audit conclusion.

## Required replay-state migration (P-01)

`ServerConfig` now requires an atomic, durable `ReplayStore`, or a `ReplayFile`
pointing to explicitly initialized state. Missing, unreadable, corrupt, insecurely
owned/permitted, full, or backwards-clock state is rejected. There is no implicit
memory-only fallback and normal startup never recreates missing state.

For a **new deployment with fresh keys**, create a dedicated private directory
and initialize once:

```sh
mkdir -m 700 state
singlink replay-init -path state/replay.db
```

Set `replay_file` in the node configuration to the same path. State is limited
to 65,536 live tags by default; `replay_max_entries` can explicitly select a
capacity from 1 to 1,048,576. Capacity exhaustion rejects admission, never evicts
an unexpired mark. Choose capacity for the complete accepted timestamp window.

**Never reset, replace with an empty copy, or independently initialize state
while the associated keys (including `old_private_keys`) remain accepted.**
Restoring an older backup can also restore the ability to replay old flights.
Use a reviewed key retirement/reprovisioning procedure if state is lost. The
initializer refuses existing state or an existing lock/initialization marker.

### Supported backend and durability boundary

The included reference file store uses a stable sidecar `flock`, bounded binary
snapshot, private directory/file ownership and permissions, file `fsync`, atomic
same-directory rename, and directory `fsync`. Admission is acknowledged only
after durable commit and a final cancellation check. Processes on **one Unix
host** may share the same path. Keep the snapshot and lock on a local filesystem
that provides these guarantees. Do not delete/replace the stable lock file.

The file backend supports Linux, Darwin and the selected BSD targets in its
build constraints. Unsupported platforms, including the Windows reference
server backend, fail closed. Client/FFI builds retain the same API/ABI.
Multi-host/network-filesystem durability is **not validated or supported by this
backend**. Deployments sharing accepted keys across hosts must provide an
external `ReplayStore` with a single atomic/durable namespace, correct expiry,
and clock-rollback safety. An independent local file on each host is not enough.

Every admission rewrites and syncs the snapshot while holding the lock. Lock
waiting is cancellation-aware; opening/initializing bounds that wait to five
seconds. Synchronous filesystem I/O cannot be forcibly interrupted; an admission
that completes durable I/O after cancellation is conservatively rejected while
retaining its mark.
This is a correctness-oriented reference backend, not a high-throughput claim.
Benchmark storage latency/capacity for a deployment before choosing it at scale.

The bundled systemd example declares a private persistent `StateDirectory`.
Provision replay state once under the service identity before first startup;
the unit intentionally does not auto-initialize lost/missing state. Preserve it
across restarts and key rotation. Do not weaken permissions to make startup pass.

### Data retained and clock policy

Records contain a one-way opaque digest of the accepted key domain and ephemeral
handshake key, plus expiry. The snapshot also contains format/checksum metadata
and a global high-water clock value. It contains no source IP, destination,
payload, account/subject identifier, raw token, device seed, or node private key.
These are short-lived **security state**, not a promise of retaining no data.
Assess retention, access controls and the product's privacy definitions explicitly.

Marks cover the full accepted request timestamp window with a conservative
one-second rounding margin. Expired marks are garbage-collected on subsequent
successful admissions; idle/offline snapshots retain them until such maintenance.
Abandoned temporary snapshots for the same state file are removed on the next
successful write. The durable global clock watermark is preserved through GC;
wall-clock rollback below it rejects admission/startup until time catches up.
Operators must manage clock corrections and storage faults as availability events.
Do not bypass this by clearing state.

## Revocation replacement (P-02)

Updates are serialized, bounded, strictly parsed and fully validated before the
live map/stamp is replaced. Scanner errors, invalid kinds/encoding/fields, missing
final newline, empty/truncated files and unavailable sources retain the last good
list. A configured invalid initial source refuses startup.

To intentionally clear all revocations, use a complete file containing `empty`
and a final newline (comments may accompany it). A blank or comment-only file is
not an explicit clear operation. `empty` cannot be mixed with entries. Existing
valid nonempty token/subject/device lines remain supported. Producers must write
complete updates through a temporary file and atomic rename; no plaintext parser
can distinguish a deliberately shortened valid list from an intended larger list.
Errors do not echo input lines, credential values or private file paths.

## Destination policy (P-03)

The original address and supported NAT64-embedded IPv4 equivalent receive the
same custom CIDR, private/special-use and node-own-address checks, including the
DNS cache route. The actual dial address is unchanged. Supported translation is
the well-known `64:ff9b::/96` prefix; network-specific translation prefixes need
separate configuration/design. Policy-level loopback/synthetic tests do not
constitute a real NAT64 translator deployment test.

## Startup cancellation (P-04)

Each engine startup owns a generation and cancellation context. Stop invalidates
pending work; a late success/error cannot republish state or overwrite a newer
session. Late callbacks clean up their own resource exactly once outside the
state lock, never by invoking global Stop. Existing Start/StartWith/Stop and C ABI
remain intact. The additive Go `StopClient(client)` operation atomically stops
only a matching active/pending client; TUN watchers must use their own client
handle instead of checking shared state then invoking global Stop. A legacy callback that does not accept context cannot be forcibly
interrupted internally; its returned resource is discarded and cleaned when it
returns. Built-in verification handshakes are actively cancelled.

## Early application bytes (P-05)

TCP early bytes debit the same subject token bucket before forwarding, obey
cancellation and the idle deadline, and count partial writes accurately. Unlimited
accounts retain their existing behavior. Rate-limited users may observe the
intended rate/burst wait on the first application bytes. This is not a claim that
billing, total-byte statistics, encryption or signatures had been bypassed.

## Compatibility and remaining platform validation

Wire identifiers, KDF, AEAD, signature input and frame encoding are unchanged.
Operational startup/revocation configuration is stricter as documented above.
Cross-host store deployment, real NAT64 translator routing, hardware power-loss
behavior, target-device runtime and production throughput require their own
platform/deployment validation. Local synthetic regression, race and build results
must be reported separately, without using real credentials or private nodes.
