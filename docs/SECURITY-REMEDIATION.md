# Security remediation: 2026-11-13 source audit

This change set addresses the five findings of the 2026-11-13 third-party
source audit against the open-source protocol baseline `78cde5ee`. It is not a
claim about the current commercial service and does not alter the earlier audit
evidence or report.

Each audit reproduction was ported as a `TestAudit*` regression test that
asserts the safe behaviour. All of them fail on `78cde5ee` and pass after the
fixes (the cryptographic control test passes on both).

| Finding | Severity | Fix commits | Regression tests | Compatibility notes |
|---|---|---|---|---|
| P-01 first-flight replay across restart / instances | Medium | `6a7cd58`, `26c1707`, `b8e6fd7`, `24b6b19` | `TestAuditP01ReplayRejectedAcrossInstances`, `TestFutureFlightRejectedAcrossRestart`, `TestSharedReplayStoreMixedAcceptanceWindows`, `TestUnsupportedReplayWindowRefusesStartup`, `TestReplayStore*` (restart/capacity, independent instances, concurrent processes, abrupt exit, lock cancellation, GC and clock rollback, missing/corrupt/permissions, opaque content, prune), `TestReplayTagIsKeyedAndStable` | **Breaking for operators:** a node needs `replay_file` (or a `ReplayStore`) provisioned once with `singlink replay-init`; startup fails closed without it. The library `ServerConfig.MaxTimeSkew` above 120 s is refused (the CLI has no such setting). The reference file store handles roughly tens to about a hundred handshakes per second (see below). Multi-host deployments sharing a key need an external shared atomic store. Library: `NewServer` without a store returns `ErrReplayStore`. |
| P-02 revocation list partial / non-atomic reload | Medium | `6a7cd58`, `b8e6fd7`, `24b6b19` | `TestAuditP02OversizedRevocationRetainsLastGood`, `TestAuditP02CorrectedRevocationClosesLiveSession`, `TestRevocationFailuresRetainLastGood`, `TestInvalidInitialRevocationListRefusesStartup`, `TestRevocationDuringAdmissionClosesSession` | A configured revocation file that is missing or invalid at startup refuses startup. An invalid update keeps the last good list and logs a warning. Stricter format: a zero-byte or comment-only file, lines with extra fields or trailing comments, unknown kinds, lines over 64 KiB and files over 4 MiB are invalid; write `empty` to clear the list. |
| P-03 NAT64 equivalents bypass custom/local policy | Medium | `6a7cd58`, `627d776` | `TestAuditP03NAT64EquivalentPolicy`, `TestNAT64EquivalentPolicies`, `TestNAT64CachedPolicyIsRechecked` | None. The dial target is unchanged; only `64:ff9b::/96` is translated for policy. |
| P-04 Stop during pending engine start | Low | `6a7cd58` | `TestAuditP04StopDuringPendingStart`, `TestStopInvalidatesOldTransportCompletion`, `TestStopCancelsPendingHandshake`, `TestOldErrorCannotOverwriteNewLifecycle`, `TestStopClientOwnsPendingAndActiveGeneration` | None for existing callers; `Stop` keeps `Status().Listen`/`LastError` as before. A startup cancelled by `Stop` now returns an error (`context.Canceled`). Additive Go API `Engine.StopClient`. C ABI unchanged. |
| P-05 early bytes skip the subject rate limit | Medium | `6a7cd58` | `TestAuditP05EarlyBytesShareSubjectBucket`, `TestEarlyPayloadSharesSubjectBudget`, `TestEarlyPayloadUnlimitedAndPartialWrite` | Rate-limited accounts may see the first application bytes wait for their bucket, as already advertised. Unlimited accounts and UDP are unchanged. |

Scope of the next statement: the five fixes above (commits `6a7cd58`,
`26c1707`, `b8e6fd7`, `24b6b19`, `627d776`). Within that remediation set the
wire format, KDF, AEAD, token and signature formats are unchanged. It does
**not** describe spec draft 4 (commit `ddfd0d7`), a separate change that
replaced `IDENT` and therefore every derived handshake key; draft 3 and draft 4
peers do not interoperate. See [Draft 4 compatibility](#draft-4-compatibility).

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

With the bundled systemd unit (static `singlink` system user):

```sh
useradd --system --no-create-home --shell /usr/sbin/nologin singlink
install -d -m 0700 -o singlink -g singlink /var/lib/singlink
runuser -u singlink -- /usr/local/bin/singlink replay-init -path /var/lib/singlink/replay.db
```

The state directory must be a real directory (not a symlink) owned by the
service user with mode 0700, and the state file mode 0600. systemd
`DynamicUser=` places `StateDirectory` behind a symlink and is therefore not
supported by the reference file store.

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
same-directory rename, and directory `fsync` (Windows equivalents below).
Admission is acknowledged only after durable commit and a final cancellation
check. Processes on **one host** may share the same path. Keep the snapshot and lock on a local filesystem
that provides these guarantees. Do not delete/replace the stable lock file.

The file backend supports Linux, Darwin, the selected BSD targets and (since
the 2026-11-17 re-audit follow-up) Windows; other platforms fail closed.
Client/FFI builds retain the same API/ABI.

On Windows the same contract is implemented with the standard library only:
an exclusive `LockFileEx` lock on the same stable sidecar `.lock` file (held
per handle, released by `UnlockFileEx` and by the system if the process dies);
privacy checked on the owner and DACL of the directory, lock, state and
temporary files (owner must be the service account, SYSTEM or Administrators;
the DACL may grant access only to those and OWNER RIGHTS; a NULL DACL or any
other grant fails closed, the Windows counterpart of the 0700/0600 rule); a
directory that `replay-init` creates gets exactly that protected DACL, which
its files inherit; the flushed temporary snapshot (checked to be private
before it is written) replaces the state with
`MoveFileExW(MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)` (a retry of
at most half a second, under the store lock, absorbs sharing violations from
scanners; anything else fails closed). Windows has no portable directory
`fsync`: the snapshot data is flushed before the rename and NTFS journals the
rename, but the durability of the rename itself across a power loss is not
something the standard library can force or this project has tested. A
process restart is covered regardless, because flights stamped before a node
process started are refused.

Run `singlink replay-init` as the account the node service runs as, because
the directory it creates grants only that account, SYSTEM and Administrators.
For a service running as LocalSystem, initialize from an elevated context
running as SYSTEM; for a virtual service account (`NT SERVICE\...`), create
the directory yourself with an equivalent protected DACL for that account
(for example with `icacls`), then run `replay-init` for the file path. An
existing directory is never re-permissioned. Use a local NTFS volume; network
shares and multi-host storage are not supported, as on Unix.
Multi-host/network-filesystem durability is **not validated or supported by this
backend**. Deployments sharing accepted keys across hosts must provide an
external `ReplayStore` with a single atomic/durable namespace, correct expiry,
and clock-rollback safety. An independent local file on each host is not enough.
Expiry is an absolute time computed by the node (request timestamp + 121 s). A
shared store must not treat a mark as expired earlier than that instant as seen
by any node: keep node and store clocks synchronized (NTP) to well under one
second, or have the store retain marks for `expiry` plus the maximum clock offset.

Every admission rewrites and syncs the snapshot while holding the lock. Lock
waiting is cancellation-aware; opening/initializing bounds that wait to five
seconds. Synchronous filesystem I/O cannot be forcibly interrupted; an admission
that completes durable I/O after cancellation is conservatively rejected while
retaining its mark.
This is a correctness-oriented reference backend, not a high-throughput claim.
Every proxied TCP connection or UDP association is a new handshake and one
admission. The independent review measured about 10 ms per admission with an
empty store, about 12 ms with 10,000 live marks and about 70 ms with 60,000 on
macOS/APFS, i.e. roughly 14 to 100 handshakes per second for the whole node.
Holders of a valid token can use up that budget or the capacity (65,536 marks
by default, about 4 minutes of admissions), after which admissions fail closed.
Benchmark storage latency/capacity for a deployment before choosing it at scale,
and provide a faster external `ReplayStore` for busy nodes.

### Admission order: refusals never use the store

Since the 2026-11-17 re-audit follow-up, every refusal that follows from the
authenticated request, the token and the node configuration alone is decided
**before** the durable store: recently expired token, unknown command,
capability not granted (for example UDP on a TCP-only token) and a TCP
destination refused by the configured policy because of its port or an IP
literal (`deny_cidrs`, special-purpose ranges unless `allow_private`). These
flights receive only their status, perform no destination operation and never
call `CheckAndMark`, so a valid-token holder cannot fill the store's capacity
or spend its I/O budget with refused requests, and cannot block other
subjects that way. The re-audit's control (one permitted and two
capability-denied flights against a 3-slot store, then another subject) is
the regression test `TestCapabilityDeniedFlightsDoNotConsumeReplayCapacity`.

Replay resistance of these answers is kept without the durable store: each
process keeps the same opaque tag for each status-only answer in a bounded
in-memory set (32,768 tags per process, at most 256 per subject so one account
cannot crowd out the others) until its timestamp window ends. A replayed copy
sent to the same process goes to the fallback like any other replay; when the
set or the subject's share is full, further refusals get no answer at all (the
fallback, without counting against the client address); and a tag in the set
is also treated as a replay by the durable path. Flights stamped before the
process started are already refused, so a restart does not reopen that window.

Limits of this design, stated plainly:

- The set is per process. Another process or host that accepts the same keys
  can answer a replayed copy of a refused flight once more, with the same
  status and without any destination operation. Replaying an inner first
  flight requires seeing it (raw `tcp` transport, a TLS-terminating proxy or
  CDN, or an accepted interception), and such an observer has already seen the
  original answer.
- All processes and hosts that accept the same keys **must** use the same
  destination policy (`allow_private`, `deny_cidrs`, `blocked_ports`,
  `allow_smtp`). Refusals leave no durable mark, so if one instance refuses a
  flight and another would allow it, a replayed copy sent to the permissive
  instance would be executed once. Roll policy changes out to all instances
  sharing keys together (or rotate keys with the change).

Still decided after the durable mark, because they depend on host or
per-subject state: name resolution (status 7), the node's own interface
addresses, and the per-subject connection limit (status 6). Permitted
requests of a valid token still consume one mark each, as intended; bound
authenticated admission rates and monitor capacity for busy nodes.

The bundled systemd example runs as a static system user and declares a private
persistent `StateDirectory`. Provision replay state once under that identity
before first startup; the unit intentionally does not auto-initialize lost or
missing state. Preserve it across restarts and key rotation. Do not weaken
permissions to make startup pass.

### Anti-replay marker and clock policy

To prevent replay attacks, a node briefly keeps a cryptographically processed
one-time handshake marker, deleted automatically after about 4 minutes. It
contains no IP address, destination, account or any information that identifies
a user, and it is not a log.

Technically, each marker is a 32-byte keyed one-way hash plus an 8-byte expiry.
The hash is HMAC-SHA256 of the client's single-use ephemeral public key `E`,
keyed with a secret derived (HKDF) from the node private key that decrypted the
flight; clients generate a fresh `E` for every handshake. Without
that node private key, a marker cannot be matched to any captured traffic. The
state file also carries format/checksum metadata and one global clock value
used for rollback protection. It holds no source IP, destination, payload,
account/subject identifier, raw token, device key or seed, or node private key,
and markers are not linked to each other or to any user.

Every instance supports a timestamp skew of at most 120 seconds (the original
default); larger `MaxTimeSkew` settings refuse startup. An instance may choose a
smaller acceptance window, but all instances keep markers until the request
timestamp plus the common 120-second ceiling and a conservative one-second
rounding margin. A short-window instance therefore cannot expire a marker while
a longer supported instance would still accept that same flight.

Expired marks are removed by the next admission and by a maintenance pass that
a serving node runs every 30 seconds, so a mark is logically deleted at most
about 30 seconds after expiry (at most about 4.5 minutes after admission) while
the node is running. A stopped node keeps its last snapshot until it runs again.
Each update replaces the file by atomic rename; the filesystem may keep freed
blocks of earlier snapshots until they are reused, so this is logical deletion,
not secure physical erasure. Abandoned temporary snapshots for the same state
file are removed at the start of the next write. The durable global clock
watermark is preserved through GC; wall-clock rollback below it rejects
admission/startup until time catches up. Operators must manage clock
corrections and storage faults as availability events. Do not bypass this by
clearing state.

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
Lines are limited to 64 KiB and the whole file to 4 MiB. Errors do not echo
input lines, credential values or private file paths. A rejected or unreadable update is logged once per distinct failure as a
warning ("keeping last good list") so operators notice it.

A handshake re-checks the live list after registering its session, so a list
published while the handshake was in progress (for example waiting on the replay
store) still ends that session.

Compatibility: a zero-byte or comment-only revocation file was previously read
as "no revocations", and lines with extra fields or unknown kinds were skipped;
all of these now make the update invalid (refuses startup, or keeps the last good
list on reload). Write a file containing `empty` to clear the list.

The revocation file is re-read every 10 seconds from `revoked_file`. Point it at
a path the service can read directly (for example `/etc/singlink/revoked.txt`);
systemd `LoadCredential=` copies files only at service start, so updates to a
credential copy are never seen.

## Destination policy (P-03)

The original address and supported NAT64-embedded IPv4 equivalent receive the
same custom CIDR, private/special-use and node-own-address checks, including the
DNS cache route. The actual dial address is unchanged. Supported translation is
the well-known `64:ff9b::/96` prefix; network-specific translation prefixes need
separate configuration/design. With the default policy, the local-use prefix
`64:ff9b:1::/48` and other special ranges are denied outright. With
`allow_private` set, IPv4 addresses embedded in network-specific prefixes are not
matched against `deny_cidrs`; deny those IPv6 prefixes explicitly if a local
NAT64 translator uses them. Policy-level loopback/synthetic tests do not
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

Within the remediation set listed at the top of this document, wire
identifiers, KDF, AEAD, signature input and frame encoding are unchanged.
Spec draft 4 (`ddfd0d7`) is a separate change that replaced `IDENT` and so
every derived key; see [Draft 4 compatibility](#draft-4-compatibility).
Operational startup/revocation configuration is stricter as documented above.
Cross-host store deployment, real NAT64 translator routing, hardware power-loss
behavior, target-device runtime and production throughput require their own
platform/deployment validation. Local synthetic regression, race and build results
must be reported separately, without using real credentials or private nodes.

## Draft 4 compatibility

The 2026-11-17 re-audit (P-R01, informational) noted that the statements
"unchanged" above were broader than intended. They apply to the remediation
commits only. Spec draft 4 changed `IDENT` from
`SingLink/1 by SingLinkLabs (singlinkvpn.com)` to
`SingLink/1 by SingLinkVPN (singlinkvpn.com)`. The HKDF-SHA-256 and
AES-256-GCM algorithms, the X25519 + ML-KEM-768 exchange, the wire layout,
the wire version byte (`0x01`), tokens, links and replay state are the same;
every handshake key derived from `IDENT` is different.

| Node \ client (or native library) | Draft 3 client | Draft 4 client |
|---|---|---|
| **Draft 3 node** | works | silent fallback on the node; client reports "handshake rejected: possible protocol draft mismatch or wrong server key" |
| **Draft 4 node** | silent fallback on the node; a draft 3 client reports its older generic rejection | works |

Upgrade nodes, apps and native libraries together (the app pins the protocol
commit). There is deliberately no version negotiation and no plaintext or
older-draft fallback: a mismatched flight is indistinguishable from any other
probe and gets the same fallback treatment, so the mismatch cannot be used to
identify a node. The diagnostics live on the client only: `ErrRejected` now
names the likely causes, a reply that cannot be authenticated as a STATUS
frame under the handshake keys is reported the same way, and the draft is
available as `singlink.SpecDraft`, in `singlink version` and in the `draft`
field of the FFI `SingLinkVersion` result. Regression tests:
`TestDraft3FlightGoesToFallbackUnchanged`,
`TestClientReportsDraftOrKeyMismatch`, `TestDraftConstantsAndDiagnostic`.

## 2026-11-17 re-audit follow-up

| Item | Change | Tests |
|---|---|---|
| P-R01 draft 4 wording | Scoped the "unchanged" statements; upgrade matrix here, in SPEC §10 and the README; client mismatch diagnostic; node behaviour unchanged | `TestDraft*`, `TestClientReportsDraftOrKeyMismatch` |
| Authenticated refusals and replay capacity (section 6) | Stateless refusals decided before `CheckAndMark`; per-process status-only replay set with a per-subject share | `TestCapabilityDeniedFlightsDoNotConsumeReplayCapacity`, `TestRefusedFlightReplaysGoToFallback`, `TestRefusedReplayAcrossProcessesNeverExecutes`, `TestRefusalFloodDoesNotSilenceOtherSubjects`, `TestStatusOnlyMarkBlocksLaterAdmission`, `TestNoDestinationOperationBeforeReplayCheck`, `TestPreAdmissionIsConfigOnly`, `TestStatusMarksBoundedAndExpiring` |
| Windows (section 8, 29 pass / 43 fail baseline) | Windows `FileReplayStore` backend (LockFileEx, DACL checks, write-through replace); CI runs the full suite on Windows | `TestReplayStore*` on every OS, `TestPrivateACLPolicy` |
| Coverage | CLI made testable. Visible changes: range checks on `-rate`, `-max-conns`, `-plan` (values that used to wrap silently, for example a rate of 2^32 becoming "unlimited") and `-days`; exit status 2 for unexpected arguments; a `help` command; one extra `version` line naming the spec draft; `tls_key` without `tls_cert` is now an error instead of being ignored. Engine tests | `cmd/singlink`, `engine` |
| CI | GitHub Actions: gofmt, vet (also cross-compiled), `go test -race` on Linux and macOS, `go test` on Windows, 60 s fuzz smoke per target; actions pinned by SHA, read-only token | `.github/workflows/ci.yml` |

Still outside what this repository can demonstrate: a real NAT64 translator
path, a multi-host shared `ReplayStore`, physical power-loss behaviour of the
file store (Unix or Windows) and production throughput.
