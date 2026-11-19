# Security remediation: third-party source audits

This document records the third-party source audit of 2026-11-13 (first
sections), its 2026-11-17 re-audit follow-up, and the VPN Labs audit
VPNL-2026-0013 (sections F-01 and "VPN Labs follow-up (2026-11-19)").

## 2026-11-13 source audit

This change set addresses the five findings of the 2026-11-13 third-party
source audit against the open-source protocol baseline `9b04898`. It is not a
claim about the current commercial service and does not alter the earlier audit
evidence or report.

Commit identifiers in this document refer to the public history of this
repository. Earlier revisions of this document cited identifiers from a
history that was rewritten before publication; each was replaced by the
public commit with the same change and the same resulting tree.

Each audit reproduction was ported as a `TestAudit*` regression test that
asserts the safe behaviour. All of them fail on `9b04898` and pass after the
fixes (the cryptographic control test passes on both).

| Finding | Severity | Fix commits | Regression tests | Compatibility notes |
|---|---|---|---|---|
| P-01 first-flight replay across restart / instances | Medium | `fd7c848`, `fe55c57`, `8dba7e2`, `1a992f1` | `TestAuditP01ReplayRejectedAcrossInstances`, `TestFutureFlightRejectedAcrossRestart`, `TestSharedReplayStoreMixedAcceptanceWindows`, `TestUnsupportedReplayWindowRefusesStartup`, `TestReplayStore*` (restart/capacity, independent instances, concurrent processes, abrupt exit, lock cancellation, GC and clock rollback, missing/corrupt/permissions, opaque content, prune), `TestReplayTagIsKeyedAndStable` | **Breaking for operators:** a node needs `replay_file` (or a `ReplayStore`) provisioned once with `singlink replay-init`; startup fails closed without it. The library `ServerConfig.MaxTimeSkew` above 120 s is refused (the CLI has no such setting). The reference file store handles roughly tens to about a hundred handshakes per second (see below). Multi-host deployments sharing a key need an external shared atomic store. Library: `NewServer` without a store returns `ErrReplayStore`. |
| P-02 revocation list partial / non-atomic reload | Medium | `fd7c848`, `8dba7e2`, `1a992f1` | `TestAuditP02OversizedRevocationRetainsLastGood`, `TestAuditP02CorrectedRevocationClosesLiveSession`, `TestRevocationFailuresRetainLastGood`, `TestInvalidInitialRevocationListRefusesStartup`, `TestRevocationDuringAdmissionClosesSession` | A configured revocation file that is missing or invalid at startup refuses startup. An invalid update keeps the last good list and logs a warning. Stricter format: a zero-byte or comment-only file, lines with extra fields or trailing comments, unknown kinds, lines over 64 KiB and files over 4 MiB are invalid; write `empty` to clear the list. |
| P-03 NAT64 equivalents bypass custom/local policy | Medium | `fd7c848`, `3c201dd` | `TestAuditP03NAT64EquivalentPolicy`, `TestNAT64EquivalentPolicies`, `TestNAT64CachedPolicyIsRechecked` | None. The dial target is unchanged; only `64:ff9b::/96` is translated for policy. |
| P-04 Stop during pending engine start | Low | `fd7c848` | `TestAuditP04StopDuringPendingStart`, `TestStopInvalidatesOldTransportCompletion`, `TestStopCancelsPendingHandshake`, `TestOldErrorCannotOverwriteNewLifecycle`, `TestStopClientOwnsPendingAndActiveGeneration` | None for existing callers; `Stop` keeps `Status().Listen`/`LastError` as before. A startup cancelled by `Stop` now returns an error (`context.Canceled`). Additive Go API `Engine.StopClient`. C ABI unchanged. |
| P-05 early bytes skip the subject rate limit | Medium | `fd7c848` | `TestAuditP05EarlyBytesShareSubjectBucket`, `TestEarlyPayloadSharesSubjectBudget`, `TestEarlyPayloadUnlimitedAndPartialWrite` | Rate-limited accounts may see the first application bytes wait for their bucket, as already advertised. Unlimited accounts and UDP are unchanged. |

Scope of the next statement: the five fixes above (commits `fd7c848`,
`3c201dd`, `fe55c57`, `8dba7e2`, `1a992f1`). Within that remediation set the
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

Run `singlink replay-init` as the same account the node service runs as: the
directory it creates grants only that account, SYSTEM and Administrators, and
the store accepts no other grant, so state initialized by one account cannot
be used by another. For a service running as LocalSystem, initialize from a
context running as SYSTEM; for a dedicated local user account, use
`runas /user:<account>`; for a virtual service account (`NT SERVICE\...`),
run the one-time initialization under that identity as well (for example as a
one-shot task or service configured with that account). An existing
directory is never re-permissioned. Use a local NTFS volume; network
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
Since F-01, status-only refusals that can still be answered also take the
store lock once for a read-only lookup (no write), bounded per subject by the
status-only share described below.
Benchmark storage latency/capacity for a deployment before choosing it at scale,
and provide a faster external `ReplayStore` for busy nodes.

### Admission order: refusals never write to the store

Since the 2026-11-17 re-audit follow-up, every refusal that follows from the
authenticated request, the token and the node configuration alone is decided
**before** anything is written to the durable store: recently expired token, unknown command,
capability not granted (for example UDP on a TCP-only token) and a TCP
destination refused by the configured policy because of its port or an IP
literal (`deny_cidrs`, special-purpose ranges unless `allow_private`). These
flights receive only their status, perform no destination operation and never
call `CheckAndMark`, so a valid-token holder cannot fill the store's capacity
with refused requests. Since the F-01 fix (below) two qualifications apply:
an expired-token flight stamped early enough that it could have been
admitted before expiry is marked durably like a permitted flight (one mark,
then status 1 only), and the other refusals perform one read-only lookup
(`ReplayStore.Has`) before they are answered. The re-audit's control (one permitted and two
capability-denied flights against a 3-slot store, then another subject) is
the regression test `TestCapabilityDeniedFlightsDoNotConsumeReplayCapacity`.

Replay resistance of these answers is kept without writing to the durable store: each
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
  can answer a replayed copy of a refused (never admitted) flight once more,
  with the same status and without any destination operation. A copy of an
  admitted flight is never answered that way (F-01). Replaying an inner first
  flight requires seeing it (raw `tcp` transport, a TLS-terminating proxy or
  CDN, or an accepted interception), and such an observer has already seen the
  original answer.
- All processes and hosts that accept the same keys **must** use the same
  destination policy (`allow_private`, `deny_cidrs`, `blocked_ports`,
  `allow_smtp`). Policy refusals leave no durable mark, so if one instance refuses a
  flight and another would allow it, a replayed copy sent to the permissive
  instance would be executed once. Tightening a policy is safe in any order
  as far as execution goes (a held-back original could still be answered once
  by a stricter instance and admitted by a looser one).
  Loosening is the risky direction: from the first loosened instance until
  every instance runs the looser policy (plus the 121-second tag window), a
  flight refused by a stricter instance could be executed by a looser one.
  Loosen together with a key rotation, or keep that window short. Each node logs a
  short fingerprint of its destination policy at start-up (`policy=` in the
  "SingLink node listening" line) so that drift between instances is
  visible.

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
the well-known `64:ff9b::/96` prefix (and, since the VPN Labs follow-up below,
the IPv4-translated format `::ffff:0:0:0/96`, which the default policy refuses
outright); network-specific translation prefixes need
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
| Authenticated refusals and replay capacity (section 6) | Stateless refusals decided before `CheckAndMark` (read-only lookup and in-window expiry since F-01, below); per-process status-only replay set with a per-subject share | `TestCapabilityDeniedFlightsDoNotConsumeReplayCapacity`, `TestRefusedFlightReplaysGoToFallback`, `TestRefusedReplayAcrossProcessesNeverExecutes`, `TestRefusalFloodDoesNotSilenceOtherSubjects`, `TestPolicyFingerprint`, `TestStatusOnlyMarkBlocksLaterAdmission`, `TestNoDestinationOperationBeforeReplayCheck`, `TestPreAdmissionIsConfigOnly`, `TestStatusMarksBoundedAndExpiring` |
| Windows (section 8, 29 pass / 43 fail baseline) | Windows `FileReplayStore` backend (LockFileEx, DACL checks, write-through replace); CI runs the full suite on Windows | `TestReplayStore*` on every OS, `TestPrivateACLPolicy` |
| Coverage | CLI made testable. Visible changes: range checks on `-rate`, `-max-conns`, `-plan` (values that used to wrap silently, for example a rate of 2^32 becoming "unlimited") and `-days`; exit status 2 for unexpected arguments; a `help` command; one extra `version` line naming the spec draft; `tls_key` without `tls_cert` is now an error instead of being ignored. Engine tests | `cmd/singlink`, `engine` |
| CI | GitHub Actions: gofmt, vet (also cross-compiled), `go test -race` on Linux and macOS, `go test` on Windows, 60 s fuzz smoke per target; actions pinned by SHA, read-only token | `.github/workflows/ci.yml` |

Still outside what this repository can demonstrate: a real NAT64 translator
path, a multi-host shared `ReplayStore`, physical power-loss behaviour of the
file store (Unix or Windows) and production throughput.

## F-01: replayed flight answered after token expiry

Reported by VPN Labs against `b924690` (their rating: Low).

**Cause.** The node decided the "token expired" refusal before the durable
replay check, and the status-only branch consulted only the per-process set
of status-only answers, never the `ReplayStore`. A first flight admitted with
STATUS 0 while its token was valid, replayed after the token's `not after`
but inside the 120-second timestamp window, therefore got an authenticated
STATUS 1 instead of the fallback, which showed that the endpoint is a
SingLink node and that the token had expired. No destination operation
followed, and the replayer could not decrypt the frame. SPEC §5.2 requires a
replayed flight to be handled silently. The same gap existed for any
status-only refusal of a flight an instance had admitted, for example after
a destination policy was tightened between processes or across a restart.

**Fix.**

- Expiry is also decided against the flight timestamp. An expired-token
  flight with `ts` earlier than `not after` + 121 s could have been admitted
  by some instance while the token was valid; it now takes the durable path
  (atomic `CheckAndMark`), so exactly one copy is answered across all
  processes sharing the store, and the answer is still status 1 only, with no
  destination operation. Later-stamped expired flights cannot have been
  admitted by any instance and stay status-only.
- `ReplayStore` has a new read-only method `Has(ctx, tag)`. Before every other
  status-only answer (unknown command, capability not granted, destination
  refused by policy) the node looks the tag up; a held tag goes to the
  fallback exactly like a replay, byte for byte the same as a random probe.
  The lookup writes nothing (no mark, no garbage collection, no watermark
  update), takes the same lock as `CheckAndMark` in the reference file store
  on Unix and Windows, and fails closed: an error, an unavailable store, a
  clock behind the watermark or a lookup past the handshake timeout gets no
  answer (not counted against the client address).
- The lookup happens only when an answer could follow: a subject that has
  used up its status-only share is dropped before it, and an expired-token
  flight stamped too late to have been admitted needs none. A lapsed token
  or an over-quota subject therefore cannot make the node read the store.
- Wire format, `IDENT`, KDF, AEAD, token and signature formats and probe
  resistance are unchanged.

**Compatibility.**

- Breaking for library users with their own `ReplayStore`: implement `Has`.
  It must be linearizable with `CheckAndMark` (after any instance's
  `CheckAndMark` returns true, every later `Has` on any instance returns true
  until expiry, without stale replica or cache reads), judge expiry under the
  same clock rule, and fail closed.
- Status-only refusals now depend on the replay store being available: while
  it is down (or the clock is behind its watermark) they get no answer, like
  permitted flights. Expired-token flights in the window above use one
  durable mark each, as a permitted flight does, for at most about 4 minutes
  around each token's expiry.
- During a rolling upgrade, instances still running `b924690` or earlier that
  share the store keep the old behaviour until they are upgraded.
- A replayed copy reaches the fallback after decryption and a store lookup,
  so it can take slightly longer than a random probe. This timing difference
  already existed for replays on the durable path.

**Tests** (`singlink/replay_expiry_test.go`; every node-level test below
fails against the `b924690` admission logic): `TestF01AdmittedThenExpiredReplaySingleProcess` (token valid for
about 3 s, original STATUS 0, copies after expiry get exactly a random probe's
answer), `TestF01AdmittedThenExpiredReplayAcrossProcesses`,
`TestF01ExpiredInWindowAnsweredOnceAcrossProcesses`,
`TestF01DurablyMarkedFlightGetsNoStatusOnlyAnswer` (capability, unknown
command, IP-literal and port policy, each with the mark made by the same
process and by another process),
`TestF01PolicyRefusalOfAdmittedFlightAcrossProcesses`,
`TestF01ConcurrentExpiredCopiesAnsweredOnce`,
`TestF01StatusOnlyLookupFailureFailsClosed` (errors and timeouts),
`TestF01RefusalsWithoutAnswerDoNotReadStore`, `TestF01MayHaveBeenAdmitted`,
`TestReplayStoreHasIsReadOnly` (read-only, cross-handle, expiry, rollback,
cancellation, lock wait, corruption). `TestNoDestinationOperationBeforeReplayCheck`
now expects a refusal to get no answer while the store is unavailable.

## VPN Labs follow-up (2026-11-19)

VPN Labs audited this repository at `b924690` (report VPNL-2026-0013,
<https://vpn.com.de/reports/VPNL-2026-0013>) and confirmed the F-01 fix
above at `7822e49`. This section covers the remaining protocol findings.
File and line references in the report are to `b924690`; all of these
findings were reported by VPN Labs.

| Finding | Their rating | Change | Tests |
|---|---|---|---|
| F-02 Go toolchain | Low | `go 1.26.11` and `toolchain go1.27.4` in `go.mod`; CI on 1.26.x and stable; govulncheck in CI; Makefile release check | CI jobs `test`, `govulncheck`; `make check-go`, `make vulncheck` |
| F-03 IPv6 special-purpose blocks | Informational | `3fff::/20`, `5f00::/16`, `100:0:0:1::/64` and `::ffff:0:0:0/96` refused; IPv6 outside `2000::/3` refused | `TestF03SpecialPurposeIPv6`, `TestIANASpecialPurposeBlocksDenied`, `TestIPv4TranslatedEquivalentPolicy`, `TestPolicyFingerprint` |
| F-04 crypto slot on panic | Informational | Handshake cryptography moved into a helper that releases its slot with `defer` | `TestF04CryptoSlotReleasedOnPanic` |
| F-10 commit identifiers | Informational | Public commit identifiers throughout; audit status aligned in SPEC, README and SECURITY.md | (documentation) |
| Local proxy (our own review, see below) | (not a VPN Labs finding) | UDP ASSOCIATE bound to the declared client port, undeclared requests refused with authentication; plain HTTP forwarding sends only the checked request and relays one response; engine drops proxy credentials on Stop | `TestUDPAssociate*`, `TestHTTPProxy*`, `TestCredentialsClearedOnStopAndFreshOnStart` |

### F-02: declared Go toolchain

**Cause.** `go.mod` declared `go 1.24` and no toolchain, CI tested Go 1.24.x
and the Makefile built with whatever `go` was on `PATH`. Go 1.24 is no longer
supported; with its last release, go1.24.13, govulncheck v1.10.0 reports 25
standard-library vulnerabilities reachable from this module, each fixed only
in Go 1.25 or later.

**Fix.**

- `go.mod` declares `go 1.26.11` (the oldest supported release line, at a
  patch release with no reachable advisory) and `toolchain go1.27.4` (the
  current release). With the default `GOTOOLCHAIN=auto` the go command
  switches to go1.27.4 when the installed toolchain is older. A toolchain
  older than 1.26.11 is not used for this module, also when it is built as
  a dependency: the go command (Go 1.21 and later) switches to a newer one
  or, with `GOTOOLCHAIN=local`, refuses to build.
- CI tests the newest Go 1.26.x (Linux with the race detector, Windows) and
  the current stable release (Linux, macOS, Windows) with `GOTOOLCHAIN=local`, so each
  job tests the toolchain it installed. Go 1.24.x is gone from the matrix.
- A new CI job runs govulncheck v1.10.0 (installed by exact module version,
  verified through the Go checksum database) with exactly the `go` and the
  `toolchain` versions from `go.mod`, and fails on any reachable
  vulnerability. Actions stay pinned by commit SHA, and every checkout uses
  `persist-credentials: false`.
- `make cli`, `make lib` and `make linux` refuse a toolchain older than the
  `toolchain` line (`make check-go`), for example when `GOTOOLCHAIN=local`
  selects an older installed Go. `make vulncheck` runs govulncheck.

**Result** (govulncheck v1.10.0, database of 2026-11-11, `./...`): with
go1.24.13 at `7822e49`, 25 reachable vulnerabilities (as reported); with
go1.26.11 and go1.27.4, before and after this change, none.

### F-03: IPv6 special-purpose blocks

**Cause.** The built-in list predated three registry entries:
`3fff::/20` (documentation, RFC 9637), `5f00::/16` (SRv6 SIDs, RFC 9602)
and `100:0:0:1::/64` (dummy prefix, RFC 9780). The IPv4-translated format of
RFC 2765 (`::ffff:0:0:0/96`), which is not in the registry, was not listed
either. `publicIP` and the configuration check accepted, for example,
`3fff::1`, `5f00::1` and `::ffff:0:a00:1`.

**Fix.**

- The list was compared entry by entry with the IANA IPv4 and IPv6
  Special-Purpose Address Registries (as published on 2026-11-19). Every
  block that is not globally reachable is refused; each entry in
  `singlink/policy.go` names its RFC. The IPv4 list was already complete.
  Blocks that are only partly globally reachable stay refused as a whole,
  as before: `192.0.0.0/24` (including the PCP and TURN anycast addresses
  `192.0.0.9` and `192.0.0.10`) and `2001::/23` (including the anycast
  addresses `2001:1::1`, `2001:1::2` and `2001:1::3`, AMT `2001:3::/32`,
  AS112-v6 `2001:4:112::/48`, ORCHIDv2 `2001:20::/28` and DETs
  `2001:30::/28`). The globally reachable blocks outside them (AS112-v4
  `192.31.196.0/24`, AMT `192.52.193.0/24`, `192.175.48.0/24` and
  `2620:4f:8000::/48`) stay allowed.
- Any IPv6 destination outside `2000::/3` is refused. IANA assigns global
  unicast addresses only from `2000::/3`; the rest is reserved by the IETF,
  special purpose or multicast. `5f00::/16` and `100:0:0:1::/64` were both
  assigned from that reserved space, so this also covers later assignments
  there. The well-known NAT64 prefix `64:ff9b::/96` keeps its existing
  handling (its embedded IPv4 address is checked).
- IPv4-translated addresses (`::ffff:0:0:0/96`) are refused by the default
  policy whatever IPv4 address they embed: the format was obsoleted by
  RFC 6145 and RFC 6052, and a public node has no reason to dial it. Like
  the NAT64 and IPv4-mapped forms, its embedded IPv4 address is also matched
  against `deny_cidrs`, so with `allow_private` a denied IPv4 range cannot
  be reached through it. IPv4-mapped addresses are still checked, and
  dialled, as the IPv4 address they map.
- An address carrying an IPv6 zone (which no prefix matches) is refused.
  None can reach the check today: the wire format has no zone and the
  resolver strips it.
- The `policy=` fingerprint now also covers the built-in ranges, so nodes
  running releases with different built-in lists show different
  fingerprints even with the same configuration. The fingerprint of an
  unchanged configuration therefore changes with this release.

**Compatibility.** Destinations in the newly refused ranges get status 4
(forbidden destination), or a name resolving only to them gets status 7, as
for the other special-purpose ranges. None of them is globally routable.
With `allow_private`, only the `deny_cidrs` match on IPv4-translated
addresses is new. As before, all instances that accept the same keys must
run the same destination policy: upgrade them together, since an instance
still running the older list would accept destinations the newer one
refuses.

**Tests** (`singlink/policy_special_test.go`; they fail on `7822e49`):
`TestF03SpecialPurposeIPv6` (`publicIP`, `configAllowed`, `configStatus`
and `resolve` for `3fff::1`, `5f00::1`, `100:0:0:1::1`, `::ffff:0:a00:1`,
`::ffff:0:808:808` and addresses in each IETF-reserved range, with
globally reachable controls such as `3fff:1000::1`, `2620:4f:8000::1` and
`192.31.196.1`), `TestIANASpecialPurposeBlocksDenied` (first and last
address of every registry entry that is not globally reachable, IPv4 also
in IPv4-mapped form), `TestIPv4TranslatedEquivalentPolicy`, `TestZonedAddressRefused`, and an
addition to `TestPolicyFingerprint`.

### F-04: handshake cryptography slot on panic

**Cause.** `handle` took a slot from the bounded handshake cryptography
semaphore (2 × the number of CPUs) and returned it without `defer`. The
handler's `recover` keeps the node running after a panic, but a panic
between the two statements would have kept the slot, and after enough such
panics every new handshake would have blocked. No input is known to cause a
panic there; the finding is about robustness.

**Fix.** Decryption, token verification and the proof-of-possession check
now run in `Server.authenticate`, which takes the slot and releases it with
`defer`. Behaviour is otherwise unchanged. The other acquire/release pairs
in the node were reviewed: connection slots, per-IP handshake counts and
per-subject connection counts already release with `defer` or on every
path, and the remaining short lock sections only read or write maps or cancel
contexts. The
resolver's DNS cache lookup re-checked a cached address (which reads the
node's interface addresses) while holding the cache lock; that check now
runs after the lock is released.

**Tests.** `TestF04CryptoSlotReleasedOnPanic` (`singlink/crypto_slot_test.go`)
injects a panic into the cryptography section through a test-only hook, for
two more handshakes than there are slots, checks that no slot is held
afterwards and that a normal handshake then relays data. Against `7822e49`
it fails with every slot held and the next handshake blocked.

### F-10: commit identifiers and audit status

**Cause.** The remediation table above cited commit identifiers from a
history that was rewritten before publication. SPEC.md still said that the
protocol had not had an independent third-party audit, while this document
described the 2026-11-13 third-party source audit.

**Fix.** Each identifier was matched to the public commit with the same
patch (`git patch-id`) and the same resulting tree, and replaced: the audit
baseline is `9b04898`, the fixes are `fd7c848`, `3c201dd`, `fe55c57`,
`8dba7e2` and `1a992f1`, and the internal review of
[SECURITY-AUDIT.md](SECURITY-AUDIT.md) refers to `6cd1884`. Every commit
identifier in the repository's documentation and comments was checked to be
reachable from the public `main` branch. Commit messages already in the
public history are not rewritten. SPEC.md, both READMEs, SECURITY.md and
the internal review now state that the code has had third-party source
audits (2026-11-13, and VPN Labs, VPNL-2026-0013), that an audit is not a
guarantee or a formal proof, and that the protocol is still a draft.

### Test reliability on Windows

`socks5.TestCloseWithOpenConnect` occasionally failed on Windows CI with
"The directory is not empty" while removing its temporary directory. The
test closed after a fixed 300 ms sleep, which over raw TCP is shorter than
the node's 500 ms end-of-flight rule, so the node could still be writing a
replay snapshot into that directory during cleanup. The test now waits until
the node has dialled the target, and the test replay stores of the
`singlink`, `socks5`, `engine` and `cmd/singlink` tests refuse new
operations and wait for running ones before the directory is removed. Test
code only.

### Local proxy hardening (found during our own review of App F-01)

These three issues were found during our own review of how the app should
use the local proxy authentication (App F-01 of VPNL-2026-0014). They were
not reported by VPN Labs. They concern the local SOCKS5/HTTP proxy in
`socks5/` and `engine/`, not the protocol or the node.

**SOCKS5 UDP ASSOCIATE.**

- *Cause.* After a control connection (authenticated or not) opened a UDP
  association, the relay accepted the first datagram from the control
  connection's IP on any source port as the association's client. On
  loopback every local process, of any user, has that IP, so one that sent
  first could use the association, and with authentication on that meant
  using the authenticated tunnel without the credentials. The request's
  DST.ADDR/DST.PORT (RFC 1928: the address the client will send from) was
  ignored.
- *Fix.* The request declares the client's port when DST.ADDR is an IP
  literal that is unspecified (`0.0.0.0`, `::`) or equal to the control
  connection's IP and DST.PORT is not zero. A declared port binds the
  association: only datagrams from the control connection's IP and that
  port are relayed, and only that address receives replies, even if
  another socket sends first. Any other request is undeclared: port 0, a
  host name, or another IP (some clients, for example sing-box, put their
  first destination there instead of their own address). With
  authentication enabled, an undeclared request is refused with reply 2
  (connection not allowed by ruleset), because the association could
  otherwise be claimed by whichever local socket sends first. Without
  authentication it is still accepted for compatibility and the first
  datagram's source port claims the association. That leaves a race in
  which another local process can claim it first (the legitimate client's
  datagrams are then dropped), but gives that process nothing it could not
  get by opening its own association on the unauthenticated port.
- *Compatibility.* With authentication on, SOCKS5 clients must declare the
  UDP port they send from. Clients that send `0.0.0.0:0` (for example the
  Xray and mihomo cores) or their destination (sing-box) get reply 2 and
  cannot use UDP through an authenticated port; TCP is unaffected. Clients
  that declare a port must send from it, as RFC 1928 says. The residual
  protection rests on the operating system's port ownership: a local
  process that can bind the declared address and port itself (for example
  with address-reuse options, normally only as the same user) is not
  distinguished from the client.

**HTTP proxy, plain requests.** CONNECT tunnels were fine: authentication
is checked before the tunnel exists and the tunnel carries one stream. A
plain (absolute-URI) request, however, was followed by a raw two-way copy,
so bytes the client pipelined after the checked request reached the same
origin unchanged: a second request with its own `Proxy-Authorization`
header (sent to the origin, not stripped) or for another host. Now only the
checked request and its body are written upstream; later client bytes are
read and discarded (a client half-close is passed on, a client that goes
away ends the upstream request). Exactly one final response is relayed,
marked `Connection: close`, and then both connections are closed, also when
the origin keeps its connection open. Every further request needs a new
connection, which is checked again.

**Engine credentials.** The engine kept the generated SOCKS5/HTTP
credentials after `Stop` (and `Credentials` kept returning them). `Stop`
and `StopClient` now drop them, as does the start of a new session, and
the stopped proxy server's copies are dropped after it has closed. Every
`Start` with `Auth` generates new random credentials, and those of an
earlier session are refused. The new `Engine.StartAuth` returns the
credentials of the session it started, and the C ABI's `SingLinkStart` uses
it, so a concurrent `Stop` or `Start` can no longer make it report empty or
another session's credentials. Go strings cannot be overwritten in place,
so this removes the references rather than wiping the memory.

**Tests.** `TestUDPAssociateBoundToDeclaredPort` (with and without
authentication: a second local socket on another port, sending first and
again later, gets no relay and no replies; the declared client works),
`TestUDPAssociateDeclaredPortWildcardIP`,
`TestUDPAssociateUndeclaredRefusedWithAuth`,
`TestUDPAssociateUndeclaredWithoutAuthFirstPortWins` (documents the
remaining unauthenticated behaviour),
`TestUDPAssociateDestinationInRequestIsUndeclared`,
`TestHTTPProxyForwardsOnlyTheAuthenticatedRequest`,
`TestHTTPProxyOneResponseThenClose` (`socks5/udp_assoc_test.go`) and
`TestCredentialsClearedOnStopAndFreshOnStart` (`engine/credentials_test.go`).
All fail on `c59a42d` except the cases that check unchanged behaviour
(undeclared requests without authentication), which pass there as well.

### Findings recorded as accepted design trade-offs (F-05 to F-09)

VPNL-2026-0013 records five further informational findings as accepted
design trade-offs. We agree with that classification and make no change;
our position, consistent with the sections above, SPEC.md and
[SECURITY-AUDIT.md](SECURITY-AUDIT.md):

- **F-05 replay-store throughput and capacity.** The reference file store is
  a correctness-oriented backend, not a high-throughput one, and admission
  fails closed when it is slow or full. The measured rates and the guidance
  to benchmark storage and provide a faster external `ReplayStore` for busy
  nodes are under "Supported backend and durability boundary" above. The
  read-only lookups added by F-01 take the store lock without writing; they
  happen only while a subject still has room in its status-only share, and
  like every handshake they are limited by the per-address and global
  pre-authentication caps.
- **F-06 status-only refusals replay-protected per process.** Since
  `7822e49` this applies only to flights that were refused and never
  admitted; the limits and the requirement of a common destination policy
  are under "Admission order" above.
- **F-07 pre-authentication limits per source address.** The limits are
  keyed by the full source address. Clients behind a shared NAT address
  share its budget, and a holder of an IPv6 /64 can spread over many
  addresses; the global connection cap and the concurrent decapsulation cap
  still bound the node as a whole. Operators who need per-prefix limits can
  add them in front of the node (firewall or load balancer).
- **F-08 unauthenticated local proxy by default.** `engine.Options.Auth`
  enables random SOCKS5/HTTP proxy credentials. It stays off by default at
  the library level because the desktop client uses the port as the system
  proxy and many applications cannot authenticate (I-10 in
  SECURITY-AUDIT.md). The listen address is loopback only. How the app uses
  it is a client decision, reported as finding F-01 of the app audit,
  VPNL-2026-0014. With `Auth` on, the local UDP relay now also requires
  a declared client port (see "Local proxy hardening" above).
- **F-09 forward secrecy.** The first flight is not forward secret, and
  there is no post-quantum forward secrecy. SPEC §5.4 lists exactly what is
  exposed if a node's static key is later compromised, recommends regular
  node key rotation, and SPEC §11 keeps post-quantum forward secrecy as an
  open item.
