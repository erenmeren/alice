# Security Review — Phase 6 (SSH key lifecycle and rotation)

Scope (spec §17.2, Phase 6: "never remove last access, own-key protection, overlap logic"; exit criteria: "rotation
failure-injection tests; platform key cannot be removed"; §26.8): generated SSH private keys at rest, in memory and in
the download; the deploy of a public key and which lines Alice may later remove; the test login; the rotation state
machine and the database guards that hold the old-key rule; the license lock; the fidelity of the fake key world and
of the SSH emulator; the e2e-only endpoint.

**Nothing in this phase was run against a customer's server.** Real OpenSSH was exercised only by `TestRealOpenSSH`
(`make test-ssh`) in three container distributions (Ubuntu 22.04, Debian 12, Rocky 9): the test login with a key as
another OS user, an added key accepted, a key never added refused, a removed key refused, and the added line number.
Every other behaviour is proven against the in-repository fake key world (`internal/providers/fake`) or the SSH
emulator behind the real provider (`linuxsshtest`). The section "Known limitations" lists what that leaves open.

The decisions behind this phase are R41 in `docs/superpowers/specs/alice-v1/00-decisions.md`; R41 item numbers are
given in brackets below. The controller's rulings, with what each costs if wrong, are in
`docs/superpowers/rulings/phase-6.md`.

## Method

The phase was built in 19 tasks on branch `phase-6` (base `master` 39838e7, plan 2e34517). Each task or task group
(1–2, 3–4, 5–6, 7–12, 13, 14, 15, 16, 17) was reviewed by an agent that did not write it, and every finding went
back to the implementer as a fix round that was reviewed again in scope. The ledger names security reviews for the
provider and the real test login (Tasks 3–4), the service (Task 7 and Task 9), the job handlers and the property test
(Tasks 10–12, and the combined re-review with the store's round 4 and the provider's listing coverage) and the API
(Task 13); the migration (Task 5) was re-reviewed four times by agents who attacked it as the application role.
Reviewers walked interleavings of the store's transactions, mutated code to see a named test turn red and swept logs,
answers and tables for canaries. Small follow-ups after an
approval were checked by the controller reading the diff.

Before Task 1 a pre-flight security design review found 13 design findings (S1–S13, no Critical) and a consistency
scan found 1 blocking and 13 fix-round defects of the plan (B1, F1–F13); all were ruled on before the first task.
During the tasks the controller ruled on 25 guard rules for the migration (G1–G25) and on the findings listed below.
The last scoped re-review of Tasks 7–12 (at f703350) answered "complete from a security point of view, nothing must
be fixed before merge"; the API integration suite (Task 14) then found two defects, T14-D1 and T14-D2, which were
fixed in the service and the job handlers.

This document was written before the Playwright journeys (Task 18) had finished and before the final whole-branch
review, the coverage floors and the final `make ci`. Cells that depend on those runs read `PENDING-FINAL-RUN`.

## Evidence

All commands run from the repository root; `-tags integration` needs Docker (testcontainers). The column "Recorded
before the final run" holds the latest results the implementers recorded in their task reports, with the commit
named; they are their reports, not runs made for this review, which was written without Docker. The column "Final
run" holds the results of the final `make ci` (which runs `make coverage`) and of the final Playwright run.

| # | Check | Command | Expected | Recorded before the final run | Final run |
|---|---|---|---|---|---|
| 1 | Key material: generation of every type, the OpenSSH file with and without a passphrase, `authorized_keys` lines, options and comments, the signer, every zeroing call; fuzz of the line parser | `go test ./internal/sshkeys/keymat -count=1`, `make fuzz-ssh` | ok, no crasher | ok, coverage 95.0 % (12a0842, implementer's report); `FuzzAuthorizedLine` 30 s clean (d968e45, implementer's report) | PENDING-FINAL-RUN |
| 2 | Planner: skips, verification rules, shared files, the digest pins every field, timers and overlap boundaries | `go test ./internal/sshkeys/plan -count=1` | ok, coverage 100 % | ok, coverage 100 % (31d0793, implementer's report) | PENDING-FINAL-RUN |
| 3 | Provider contract, the fake key world and its conformance script (`CheckKeyLifecycle`), listing coverage, the real provider against the emulator | `go test ./internal/providers/... -count=1` | ok | ok: `internal/providers` 100 %, `linuxssh` 93.3 %, fake 96.3 % (b423c6f); listing coverage and unparsed lines (540651d, 1bae6ec); implementers' reports | PENDING-FINAL-RUN |
| 4 | Real OpenSSH: the test login as another user, an added key accepted, a never-added key refused, a removed key refused, the line number (the helper is unchanged; this run shows no regression) | `make test-ssh` | ok on ubuntu22, debian12, rocky9 | `TestRealOpenSSH` green on the three distributions (b423c6f, implementer's report) | PENDING-FINAL-RUN |
| 5 | Migration `00010`: every CHECK and trigger violated as the application role, the edge matrix, the old-key gate, grants listed exactly, down refusal `Z1012` | `go test -tags integration ./migrations -count=1` | ok | ok, 63.6 s (94d7779, implementer's report) | PENDING-FINAL-RUN |
| 6 | Inventory: key-change readiness, transactional reads, the added-key record, `facts.key_files` with completeness | `go test -tags integration -count=1 -cover ./internal/inventory/...` | ok, coverage ≥ 89 | ok, coverage 89.1 % (4c25ae6, implementer's report) | PENDING-FINAL-RUN |
| 7 | Service: generation, deploy rules, download and its audit order, destruction, policies, previews, scheduled starts on an advancing clock, the store's gate, decisions, sweep, reconciliation, L-83 | `go test -race -tags integration -count=1 -cover ./internal/sshkeys/...` | ok | ok with `-race`, 62.6 s, coverage 90.1 %, `plan` 100 % (31d0793, implementer's report) | PENDING-FINAL-RUN |
| 8 | Job handlers: deploy decision table and ownership under every listing fault, location phases, F-36..F-39, F-67, kills at every point, L-81, L-83..L-86, L-88, the licence gate before any session | `go test -race -tags integration -count=1 -cover ./internal/jobs/...` | ok | ok, 100 s at load 6 (b7eab4e); `sshkeyjobs` 86.2 % (628ed61), `internal/jobs` 89.2 % (f703350); implementers' reports | PENDING-FINAL-RUN |
| 9 | Property test `TestOldKeyRemainsUnderAnyInjectedFailure`: scenario count | (part of row 8) | every schedule keeps the old key unless freshly re-checked | 510 schedules (20 of them random) plus a 48-case deploy matrix under listing faults (f703350); the licence invariant covers every world call including listings and logins (b7eab4e); earlier 492 schedules + 4 baselines + 24 kill points (628ed61); implementers' reports | PENDING-FINAL-RUN |
| 10 | API unit: routes, permissions, step-up, the download handler and its limiter, the catalogue and its troubleshooting sections, caller-specific `actions_allowed`; authorization matrix | `go test ./internal/api ./internal/rbac ./internal/notify -count=1`; `make authz-doc && git diff --exit-code docs/authz-matrix.md` | ok, no diff | ok: `api` 95.0 %, `rbac` 98.0 %; matrix unchanged (b5fdf0d, implementer's report) | PENDING-FINAL-RUN |
| 11 | API over the wire with the real service and handlers: journeys, S-09, the secret-leak suite with generated keys, dry run equals run, lock at every phase (L-29, nothing reaches a server), F-36 | `go test -tags integration -count=1 -cover ./internal/api/...` | ok, 0 skips | ok, 92.5 s, coverage 95.8 %, 0 skips (03332df, implementer's report) | PENDING-FINAL-RUN |
| 12 | Wiring, periodic tasks, the e2e endpoint absent from the release binary, every `/test` route e2e-only | `go test -tags integration ./cmd/... -count=1`, `make release-symcheck`, `go test ./internal/archtest/...` | ok | ok: `cmd/alice` 91.5 %; `release-symcheck: ok` (dfade43, 08a8e10, implementer's report) | PENDING-FINAL-RUN |
| 13 | Web: Vitest; locale consistency | `make web-coverage`, `make i18n-check` | ok | Vitest 78 files, 1090 tests (754f8fc); i18n consistent (e2e8705); implementers' reports | PENDING-FINAL-RUN |
| 14 | Playwright: Phase 6 journeys in EN and TR (generate, deploy, verified login, a manual rotation with a one-minute overlap, the old key removed only after it), axe | `make e2e-up && make e2e-hardening-check && make e2e`, then `make e2e-down` | all passed | not run when this document was written (Task 18 in progress) | PENDING-FINAL-RUN |
| 15 | Coverage floors: every package at or above its floor, with new floors for `internal/sshkeys/plan` (100), `internal/sshkeys/keymat`, `internal/sshkeys` and `internal/jobs/sshkeyjobs` (measured, rounded down) | `make coverage` | ok | not run for this phase | PENDING-FINAL-RUN |
| 16 | No secret in the repository | `make secrets-scan` | no leaks | no leaks (2355d10 and dfade43, implementers' reports), after 11 reviewed false positives were allow-listed (6a32c97) | PENDING-FINAL-RUN |
| 17 | Go vulnerabilities | `make vuln` | none | not recorded for this phase | PENDING-FINAL-RUN |
| 18 | File system and image scan | `make fs-scan` | 0 HIGH/CRITICAL | not recorded for this phase | PENDING-FINAL-RUN |
| 19 | The whole gate | `make ci` (with `TRIVY_IMAGE="--network host <the pinned image>"` on the build machine) | exit code 0 | not run | PENDING-FINAL-RUN |

Mutation evidence recorded by the reviewers and implementers (their reports, not re-run here): every digest input and
every zeroing call of `keymat` and `plan` turned a named test red (re-review of Tasks 1–2); each zeroing, S5 and S7
line of the service (Task 7); every refusal test of the migration was red against the earlier migration round (15
in round 1, 7 in round 4); 13 security mutations of the API (passphrase and file zeroing, the file-name check, the
download permission, the limiter and its reset, the enable permission, the key-files filters, the digest format, the
gate in `actions_allowed`, the clock-behind mapping); in the property test an undo that removes the old fingerprint
fails 51 schedules, and "gone = not listed" fails 23. Survivors the reports name: the store's own checks of G3' and
G17 survive their mutations because the database refuses the same statement; the sweep's gate check in `phaseOf` (a
second line of defence) survived one round; `after_write` and `late_write` removal pairs under a listing fault cannot
catch a mutated absence check by construction (the old key really is gone there).

## Threat notes

### Private keys: generation, storage and zeroing

A key is generated in `keymat.Generate` inside a slot (at most two at a time) and sealed at once as an envelope in
`managed_private_keys` (owner `ssh_key`, PKCS #8 DER, AES-256-GCM with the AAD bound to the row ID) in the same
transaction as its `ssh_keys` row and its audit row [2]. The clear PKCS #8 exists only (a) in the generator until it
is sealed, (b) in the test-login signer for one handshake, (c) in the download while the file is built; each holder
zeroes its buffer on every path (`TestGenerateZeroesTheClearKey`, `TestKeySignerSignsAndZeroes`,
`TestDownloadZeroesTheOpenedKey`, `TestWipeClearsEd25519`, `TestOpenSSHClearsTheBlockDER`,
`TestClearKeyBuffersAreZeroedByTheirOwners`). What cannot be cleared: Go strings; the `big.Int` limbs of RSA and
ECDSA keys; the copies `golang.org/x/crypto/ssh` makes while it marshals the OpenSSH block (and, with a passphrase,
the bcrypt-derived AES key and IV); the growth copies of `pem.EncodeToMemory`; Go's HTTP response buffer and the TLS
layer's record buffers holding the downloaded file (P4-04, extended). The database guard makes a private key's payload
immutable, its destruction one-way and a re-wrap possible only upwards [34]. Backups taken before a destruction keep
the sealed key.

### The download

`POST /api/v1/ssh-keys/{id}/actions/download-private-key` needs an Administrator in a browser session with a fresh
step-up, never a token, and a reason that passes `ValidateReason` (no PEM block, no control, format or bidi
characters) [5]. The limiter (5 per minute) is keyed by user and charged only to full browser sessions, so refused
tokens and half-signed-in sessions cannot use up an Administrator's allowance (`TestDownloadLimitIsPerUserSession`).
The file is built outside the transaction; the counter and `sshkey.private_key_downloaded` commit before the first
byte; a failed commit zeroes the file and sends nothing (`TestDownloadAuditsBeforeTheFile`,
`TestDownloadWithoutItsAuditRowZeroesTheFile`; over the wire, the Task 14 probe wraps the stack's response writer and
reads the audit row on another pool). The passphrase is a `secretText` zeroed by the handler and cleared again by the
service; it is never stored or logged (only `protected=true`). The file name has a closed form. Alice's own key,
keys Alice does not hold and destroyed keys are refused and audited; a retired key can be downloaded until destroyed.
The download works in lock by design.

### Deploy and ownership of a line

A deploy is re-checked in full when its job runs (`DeployJob` reads the database again; the options must be exactly
`from=` and `restrict` as Alice writes them) [8]. Alice never touches the connection account or any of its key files,
by file and not only by user, and fails closed when the last scan did not list that account's files completely and
exactly once (S7) [8], [36]. The open question of a deploy is which line it may remove after a failed login. As built
[38], [39]: every send is recorded in the audit log before the helper call (`sshkey.add_sent`, claim-fenced, with the
coverage of the listing taken before the first send); a line is the deploy's only when that listing read the file
completely and did not show it, or the helper answered that it wrote it; a line that was there before is
`already_present` and never removed; a send known to have written nothing owns nothing; unknown means never removed.
An undo or a re-send waits until no earlier send can still land (S3: latest send + helper budget + 30 s). Deploys
whose job ended without an outcome are reconciled hourly with one audit row and one scan, removing nothing [40].
Residuals: L2, L10, L11, L12 in "Known limitations".

### The test login

`VerifyKeyLogin` dials a fresh connection outside the pool, requires the pinned host key, authenticates as the OS user
with only the new key and opens no channel [9], [32]. A server that lets the client in without asking for the key, or
offers no public-key method, gives `unprovable`, never `accepted` (`TestVerifyKeyLoginWithoutKeyIsUnprovable`). A
refused login on a `from=` line is `unverifiable` (Alice may be outside the list). A root place under `PermitRootLogin
no` is never tried, and one under `forced-commands-only` without `command=` is skipped [36]. The test login proves
authentication only: a forced command that breaks the consumer still counts as working. A failed test login never
changes the server's status. In a rotation a login that cannot connect fails the place and rolls the run back; in a
deploy it leaves the line `unverified`.

### The rotation state machine and the database guards

The old-key rule (§13.6 item 8; plan "Old-key rule") is enforced twice. The store's `BeginRemove` (under the run's
`FOR UPDATE`) checks: run in `removing_old` with removal allowed; not paused; the gate allows changes; the place
verified and freshly re-checked (at most 15 minutes, strictly after the verification, later than any failed removal);
every other place of the run in the same file verified, removing or removed; the new place recorded and live; the
fingerprint not protected. Migration `00010` checks the same in triggers and CHECKs (`Z1011`), and also every run and
place edge, frozen finished runs, immutable keys of a run, single-use new keys and operation IDs, monotonic times
[34]. The first form of the migration let a removal skip its gate and a finished run be reopened (P6-01, P6-02); the
four fix rounds were attacked as the application role and the last re-review found no state where a run can never
end. Every removal job lists the file before it records "removed" and believes absence only from a complete listing
[37]. An undo removes only the new key's fingerprint, which the run generated, and keeps it where the old key is
already gone (S12). The property test drives 15 fault kinds at every world-call index on one to three places, plus
Administrator decisions, clock steps forward, lease loss, listing faults and a licence timeline, and asserts after
each schedule that the old key is in every file where it was not removed after a fresh re-check, that no pre-existing
line was removed and that no world call happened in lock outside the two exceptions.

### License lock

In lock no run is planned (L-88), a previewed run is cancelled, and a started run is flagged at the first sweep in
every status with work or a timer ahead, with one email [21], [43]. Its overlap and decision timers stop; after the
renewal nothing moves until the sweep has queued the renewal notice and an Administrator chose **Continue**, and every
removal still needs its own fresh login [43], [44]. No command reaches a server in lock (L-29) except a send recorded
before the lock began and the undo of a rollback (L-85, L-86) [45]: T14-D2 showed that a queued removal job still
opened a session and logged in before the store refused; the add and removal jobs now read the pause flag and the
licence gate before any session, the composition root wires the gate and a nil gate fails a wiring test
(`TestLockDuringRemovingOldSendsNoCommand`, `TestRotationInLockRunsNoCommand`, `TestAbortInLockUndoesOverTheWire`).
**Stop and undo** is the only decision in a pause; the download stays possible [5], [44].

### The fake, the emulator and their fidelity

The fake key world (`fake.Config.World`) models files, users, logins, the owner rule for shared files, late writes
(`FaultLateWrite` follows the world's clock) and listing coverage, and is held to the same conformance script as the
real provider (`providertest.CheckKeyLifecycle`). It is stricter than the real provider for a file never put, its root
and connection-account rules are simpler (owner equals root, the constant `alice-svc`), and it does not model `from=`,
`StrictModes` or the order of `AuthorizedKeysFile` entries; the helper fidelity suite has no shared-file owner case.
The real provider's shared-file case runs against the emulator, not a container. The emulator is not the helper: a
helper-side refusal of a protected fingerprint is covered by the helper's and the provider's own suites only.

### The e2e-only endpoint

`POST /test/rotation/overlap` exists only in the e2e build (`e2e testlicense` tags); it sets a policy's
`overlap_minutes` (0 to 129,600) as the owner role, bumps its version and writes no audit row [60]. It is refused
cross-site like every `/test` route; `make release-symcheck` checks each guarded symbol present in the e2e binary and
absent from the release binary, `TestReleaseHasNoRotationTestEndpoint` checks the release server answers 404, and the
archtest rule requires every `/test` route to be e2e-only. A run keeps the overlap it was created with, and the store
and the database require the fresh re-check whatever the overlap (`TestZeroOverlapStillNeedsTheRecheck`).

## Review checklist

- [ ] The old key is never removed without a verified login, a re-check of at most 15 minutes and every place of the
      file verified (`TestOldKeyRemainsUnderAnyInjectedFailure`, `TestKillAtEveryRecordedPoint`,
      `TestF67KillBetweenAddAndVerify`, `TestNewKeyDeletedDuringOverlapKeepsOld`,
      `TestHostKeyChangeMidRotationRemovesNothing`, `TestTargetDeletedMidRotation`, `TestOwnerStep6NetworkLoss`;
      database: `migrations/rotation_integration_test.go`, `rotation_round4_integration_test.go`).
- [ ] Never remove last access: a removal needs a login with the new key as that user just before; an undo keeps the
      new key where the old one is gone (`rotation.old_key_gone`); the manual removal keeps its last-root-key rule.
- [ ] Own-key protection: Alice's key is refused as a policy key, a run's old or new key, in a deploy, a download and
      a removal, by the service and the database (`TestF36OwnKeyNeverRotated`, `TestF36OwnKeyNeverRotatedOrDownloaded`,
      `TestF36ConnectionAccountOverTheAPI`, `TestManagedPrivateKeyGuard`).
- [ ] The platform key cannot be removed: the Phase 3 trigger and the removal gate's protected fingerprints are
      unchanged and exercised by the rotation suites.
- [ ] Overlap logic: boundaries (`TestOverlapBoundaries`), a zero overlap still needs the re-check
      (`TestZeroOverlapStillNeedsTheRecheck`), a paused overlap resumes with the remaining time
      (`TestL83FlaggedWhenTheLockEnters`, `TestL84RenewalAfterTwentyDays`), **Finish now** keeps every re-check.
- [ ] Dry run equals the run (`TestDigestChangesWithEveryDecision`, `TestDigestPinsEveryField`,
      `TestRunNowNeedsThePreviewedDigest`, `TestScheduledStartReplansAndRenotifies`, `TestDryRunEqualsActualPlan`).
- [ ] A scheduled run starts only after a delivered notice, on a real (advancing) clock
      (`TestScheduledStartWaitsForADeliveredNotice`, `TestScheduledRunStartsOnARealClock`).
- [ ] No command reaches a server in lock except the two exceptions (`TestRotationInLockRunsNoCommand`,
      `TestLockDuringRemovingOldSendsNoCommand`, `TestAbortInLockUndoesOverTheWire`, L-83..L-88 tests).
- [ ] The private key appears only in the download response, after its audit row (`TestS09PrivateKeyDownload`,
      `TestSecretLeakSuiteWithGeneratedKeys`, `TestMaterialNeverPrints`, `TestStoredKeyIsAnEnvelope`).
- [ ] Permissions: the generated matrix, `TestRotationRoutesAuthz`, `TestPhase6RoutesAuthzOverTheWire` (14 change
      routes × 8 identities), `TestRunActionsFollowTheCaller`.
- [ ] The release binary has no e2e endpoint (`make release-symcheck`, `TestReleaseHasNoRotationTestEndpoint`).
- [ ] A refused login is never "verified" and an unprovable one never removes anything
      (`TestVerifyKeyLoginOutcomes`, `TestVerifyKeyLoginWithoutKeyIsUnprovable`, `TestDeployRefusedLoginIsUndone`).
- [ ] The e2e journeys pass in EN and TR (row 14 of the Evidence table).

## Findings

Found by the per-task reviews, their re-reviews and the API integration suite, with the commits that closed them.
The reviewers rated findings Critical, Important or Minor; none was rated High, and none of the listed findings is
open. Minor findings that were parked are in "Known limitations".

| ID | Area | Rating | Description | Decision |
|---|---|---|---|---|
| P6-01 | Schema | Critical | The old-key gate fired only on the move into `removing`: `verified → removed` directly, inserting a place as `removing` or `removed`, setting `verified_at` in the same statement, rewriting `removed`, and the platform and connection flags were not checked (Task 5 review at 312bc59). | Fixed: 95519af (the triggers enforce the state machine), hardened in 7d67576, 6b7e6a8, 94d7779. |
| P6-02 | Schema | Critical | `rotations` had no guard: a finished run could be reopened, and `new_ssh_key_id` could be set to Alice's platform key, which an undo would then remove. | Fixed: 95519af (`rotations_guard`, `Z1013`), 7d67576 (a new key belongs to one run ever). |
| P6-03 | Schema | Important | Re-reviews 2 and 3: a failed removal could be retried on its stale re-check (G3), a place could be stuck `adding` in `removing_old`, a late add after a direct `undo_failed` left the key unrecorded, and `reverified_at` could be lowered by a failure statement (N9). | Fixed: 6b7e6a8 (G3', G16–G19), 94d7779 (G20–G25, the outbox index). |
| P6-04 | Service | Critical (fails closed) | The delivered-notice lookup joined `o.created_at = r.notified_at`, two clock reads that never match on a real clock: every scheduled run would have been cancelled as undelivered; the frozen test clock hid it. Introduced by 9193d5d. | Fixed: 3371ec2 (lookup by the run's ID; `TestScheduledRunStartsOnARealClock` red before); index 94d7779. |
| P6-05 | Job handlers | Critical | Handlers read "not in the listing" as "not in the file", while the listing dropped which files were read: an unread file recorded `removed` (old key still authorised) or `undone` (new key left without a record) (Tasks 10–12 review). | Fixed: 540651d (the provider states coverage per file), a0848fb (absence only from a complete listing), 1bae6ec (a file with a line not understood is partial). |
| P6-06 | Job handlers and service | Important | A pre-existing line could be removed: an attempt after the first treated a found line as its own (I1), and after the first fix a send recorded but never made still made a pre-existing line "owned" (A-I1). | Fixed: b484b26 (durable send record), 1703a3d, 82dad01 (pre-send evidence, `Owned()`), c3794c9; a send known to have written nothing owns nothing: 31d0793, f703350. |
| P6-07 | Test evidence | Critical | The over-the-wire test of "audit row before the first byte" could not fail: `net/http` buffers a small body (Task 14 review). | Fixed (tests only): c2aa0ac (the probe wraps the server's writer and reads on another pool; a failed audit gives no file). |
| P6-08 | Service (L-83) | Defect T14-D1 | A lock during the overlap flagged the run only once the overlap's end had passed in lock; the spec says at once. Nothing was removed either way. | Fixed: 31d0793 (pause at the first sweep, remaining time after Continue); tests df265c1, f703350; web e2e8705; texts b5fdf0d. |
| P6-09 | Job handlers (L-29) | Defect T14-D2 | In lock a queued removal job for a second server opened a session and logged in with the new key before the store refused; nothing was written or removed. | Fixed: b7eab4e (pause flag and gate before any session), 2c47749 (the gate wired; nil fails a test), 03332df (test unskipped). |
| P6-10 | Service | Important | The connection-account file check (S7) failed open when the scan had no or an incomplete file list for that account (Task 7 review). | Fixed: a4c44d4 (completeness in the provider), edcff2e (kept by the inventory), 0961220 (deploy fails closed), 4bbb1d3 (own reason `ALC-KEY-0014`). |
| P6-11 | Service | Important | Switching a policy off or editing it raced the planner: the run just created was not cancelled and started later (Task 8 review). | Fixed: d016735, 9193d5d (a scheduled run of a policy switched off never starts). |
| P6-12 | Service | Important | The S3 wait was skipped after an uncertain add and a refused or unprovable login; **Continue** worked before any renewal notice; an `adding` place in `rolling_back` was re-queued without bound; a lock with only an `adding` place did not pause (Task 9 review). | Fixed: 3371ec2. |
| P6-13 | Service | Important | The planner did not skip servers the add refuses (unknown connection-account files), so the preview showed changes, the place burned its retries and the whole run rolled back, on every server not scanned after the upgrade. | Fixed: c1f28ce (skips `connection_files_unknown`, `connection_account_file`). |
| P6-14 | Service | Important (liveness) | The sweep re-queued every place of a run in one transaction; one refused place rolled back the whole re-queue on every sweep and the run stalled silently (N18). | Fixed: 79af2e9 (one transaction per place). |
| P6-15 | API and service | Important | Keep old was offered and accepted without the licence gate; the run list loaded every place of every run (Task 13 review). | Fixed: c1f28ce (one predicate per decision), da3dc1a, 6589a59 (summaries with counts). |
| P6-16 | API | Spec deviation | Stop and undo was built with step-up because the controller's dispatch said so; the plan says `rotation.manage`. | Fixed: da3dc1a (`rotation.manage`), 6589a59 (accepted in lock). |
| P6-17 | Job runner | Important | The runner discarded a handler's retry wait on lost lease or shutdown (S3 unanchored for deploys); a lock and a lost unproven add rolled the run back in lock. | Fixed: 17935e7, a0848fb. |
| P6-18 | Test evidence | Important | The property test's Administrator actions were refused everywhere, there was no licence invariant, one login sufficed, end states were unasserted, undo and listing were not fault points; F-36 weak; a wall-clock deadline. | Fixed (tests only): 628ed61, 2afb404, 195ed12. |
| P6-19 | Service | Important | The reconciliation looked back only 7 days from a job's end, so deploys that ended before a lock or outage of 7 days or more were never reconciled; a deploy of the new key of an unfinished run was not refused. | Fixed: 31d0793 (durable cursor, no age limit; `ALC-KEY-0018`). |
| P6-20 | Provider and fake | Important | `cmd/alice` tests red for the new capability; candidate key files included paths the helper refuses; the fake added a file to the user's login set; `FaultLateWrite` was vacuous by default and skipped the owner rule. | Fixed: b423c6f. |
| P6-21 | Key material and planner | Important | The digest test did not pin `Verify`, `VerifyNote` and `Skip`; the zeroing calls were not pinned by tests. | Fixed: 12a0842, 6c43ccf. |
| P6-22 | Web | Spec deviation | The deploy dialog was never rendered in Turkish by the named test (Task 16). | Fixed: 14f96f8. |
| P6-23 | Web | Important | Decision buttons were shown to Operators and Auditors; **Run now** was disabled for a previewed run; the page decided "notice pending" itself and showed a false message in lock; the paused banner said nothing is sent although Stop and undo acts; the kept-places help told Administrators to remove an old key where the new key was never added (lock-out risk) (Task 17). | Fixed: c28a2c5, 413d890, 754f8fc; caller-specific `actions_allowed` 6589a59. |
| P6-24 | Test evidence | Important | A time bomb in the leak suite's self-test (a database `now()` against the fake clock: red from about October 2027). | Fixed (tests only): d8e030c. |
| P6-25 | Build | Minor | `make secrets-scan` flagged 11 Go import paths in the archtest tables and the plan as generic API keys. | Allow-listed after reading each line: 6a32c97. |
| P6-26 | Web | Minor | The audit label of `sshkey.add_sent` was changed to "sent", but the row is written before the helper call. | Restored "about to be sent": c9ae2ab. |
| P6-27 | Wiring | Minor | The periodic tasks' targets were unpinned, a nil keyring passed, the symbol check passed on any one symbol, only `/test/clock` was guarded by archtest (Task 15 review). | Fixed: 3b26c23, 08a8e10. |

## Known limitations

Scope and evidence:

- **Nothing was run against a customer server.** Real OpenSSH ran only in the three containers of `make test-ssh`.
  `from=`, `StrictModes`, PAM and `AllowUsers` behaviour, the order of `AuthorizedKeysFile` entries and sshd versions
  other than those three are not covered; the fake does not model them, and the shared-file owner rule ran against
  the emulator only.
- **The test login proves authentication only** [9]. A forced `command=` that breaks a consumer still counts as working.
  Servers where Alice cannot test a login keep both keys unless an Administrator stops the run [11].
- **Shared files are skipped** [29]: a file that holds more than one place of the key is never rotated. A co-user of a
  file whose place Alice never recorded is protected only by the provider's owner check (Task 2 m1); **the same file
  under two path strings (a symlinked `AuthorizedKeysFile`) is invisible to the planner and to the guard alike**, so
  the gate's same-file rule cannot see it (the parked N17: a verified sibling exempts a send however old its re-check;
  unreachable while the planner's shared-file rule is the only inserter).
- A root place under `PermitRootLogin forced-commands-only` without `command=` is skipped; under `no` it is
  `unverifiable` [9], [36].
- **After the upgrade every server refuses deploys and is skipped by rotations until it has been scanned again**; a
  server with more than 200 accounts or whose connection account is not in `/etc/passwd` stays so; a key-file path
  with zero-width joiners, soft hyphens, direction marks or no-break spaces makes the account's list incomplete [36],
  [59].
- **Old scans' key-file lists**: there is no age bound on a scan's list; a change of sshd's settings is seen only at
  the next scan (the helper checks the file again at write time) (N2).
- Discovered key places' paths and user names shown in previews get no character check (rendered as text) (I-5).
- **Scheduled rotation needs working email delivery** (S1): with no SMTP, every scheduled run is cancelled and counts
  as its interval; only **Run now** rotates [15].
- A scheduled policy whose plan exceeds 10,000 places or 2 MiB fails at every planning tick with only a log line and
  no email; **Run now** shows `ALC-ROT-0019` [62].
- **A run that ends `needs_attention` leaves the policy on the old key**; its next run rotates only the places where
  the old key is still live, and the new key has no policy until an Administrator creates one [64].
- After `needs_attention` the old key at failed-removal places is removed by hand (G3); Stop and undo is not offered
  once removal has begun.
- No certificate private-key download (carry 11, Phase 7); no cron-like schedules and no partial-location policies
  [12], [13]; notification recipients are all Administrators until Phase 7 [15]; the 30-day retention is not
  configurable until Phase 7 [23]; a rotation costs about four helper scans per place (carry 4, Phase 8).
- Inventory refusal rows (`sshkey.deploy.denied`, `sshkey.private_key_download.denied`, `rotation.policy.denied`) are
  not coalesced (carry 12).

Memory and storage:

- **Go strings, `big.Int` limbs of RSA and ECDSA keys, the copies x/crypto makes while marshalling (and the
  bcrypt-derived key and IV of a passphrase), `pem.EncodeToMemory`'s growth copies, Go's HTTP response buffer and the
  TLS layer's buffers of the downloaded file cannot be cleared** (P4-04, extended).
- **Backups keep destroyed keys** (sealed with the master key).
- **The download may be used during a lock** (by design) [5].
- A re-wrap of a generated key's envelope can only move to a higher key version; rolling a master-key rotation back
  means restoring a backup (see `docs/operator-guide.md`, "Master-key rotation").

The 13 limitations of the last re-review of Tasks 7–12 (task-7-12-final-rereview, section 8):

- **L1.** "Removed" and "undone" mean that no line Alice's parser understands carries the fingerprint. A line sshd
  accepts in a form the parser rejects makes listings partial, but a helper removal answering "0 removed" is still
  recorded as removed.
- **L2.** A line added by hand in the milliseconds between a deploy's pre-send listing and its send can become owned
  if the add's answer is lost and the login fails, and is then removed by the deploy's undo.
- **L3.** A deploy whose job ended more than 90 days before the hourly reconciliation next runs (a license lock or
  downtime of over 90 days) is pruned with its job (`maintenance.cleanup`) and never reconciled; only its
  `sshkey.add_sent` rows remain, and the next ordinary scan finds the line. A complete fix needs a deploy-send table.
- **L4.** A backward clock step or instance clock skew of more than an hour can hide an ended deploy from the
  reconciliation cursor (parked F1); the periodic scan still records the line. A cheap later fix: start each walk
  24 hours before the cursor.
- **L5.** A paused overlap resumes after Continue with the time that remained at the first sweep in lock, so it lasts
  longer in wall time by the pause; it can end earlier in absolute time than first announced only after a backward
  clock step, and the reminder is sent again for the new end.
- **L6.** On a server beyond the discovery bounds, or with a key file that is unreadable, too large or holds lines
  Alice cannot parse, absence can never be proven: every rollback there ends `undo_failed` with
  `rotation.listing_incomplete` and needs a person.
- **L7.** A deploy of the new key of an unfinished run is refused, but a deploy of the old key during a run is not;
  that line is outside the run's plan and keeps the old key live after the rotation completes.
- **L8.** A run in `adding_new` whose only pending work is the verification of places already added is not flagged
  `paused_license` and sends no pause email during a lock (parked F3); nothing is sent or removed, and the run's
  `notice_state` and `actions_allowed` show the lock.
- **L9.** A definite answer that arrives in a job run that lost its lease is dropped, not recorded as a late result;
  the next job learns the truth from the file. (No test reached a `late_result` step through the handlers; the store
  path is tested directly.)
- **L10.** The add and the undo of one deploy share the job ID as operation ID; how the real helper treats a reused ID
  is unverified.
- **L11.** S3's wait counts from the send record; the provider's add may still write after up to two compare-and-set
  retries, so on a very slow host a write can land after the wait.
- **L12.** If recording "not written" for a failed send itself fails, that send keeps counting for ownership (parked
  F4; needs a store failure, a hand-added line and a refused login together).
- **L13.** The cause shown for a place exhausted after an incomplete listing is its last recorded step; a later
  unreachable attempt does not change it (parked F2; wrong text only).

Migration residuals (re-review 4 of Tasks 5–6):

- An `undo_failed` place may carry an error code inherited from an earlier failure (N15; history only).
- The stamped failure time of a removal is floored by the place's recorded times but otherwise the application's
  `updated_at` (N16): a database boundary the store does not reach.
- The operation-ID table accepts inserts by the application role, which only burns IDs (D24); the remaining
  inaccuracies of the internal schema-rules text (D22–D28) were not corrected.

Other parked or deferred items of the phase:

- A place job stopped by the lock before it reached the store keeps the retry the sweep counted (at most one per lock
  entry) (Task 11).
- The audit-log lookup of a deploy's sends is bounded by time through the audit log's primary key (no index on the
  request ID); its plan on a large audit log was not measured.
- Two property schedules to add when the loop reopens: a second lock during a resumed overlap, and Keep old on a shared
  file with a hang at the first removal (Task 12).
- `keymat`: inside quotes a backslash escapes any byte (sshd escapes only `\"`), so `HasOption`/`HasFromOption` on
  stored options could disagree with sshd; the `onHold` test hook is a package variable; the archtest purity rule is a
  deny list (Task 1).
- The fake is stricter than the real provider for a file never put and simpler for root and the connection account
  (Task 3).
- Web: a content type compared case-sensitively (`client.ts`); the deploy dialog's failed-job alert would be green
  for a failed job whose result is verified or already present (not produced by the contract) (Task 16); a retried
  vault in the import history shows only its first page (Task 17).
- The test login's own budget-expiry branch (not the dial's error) is untested (Task 4).

## Owner verification

Spec §26.8 "Owner verifies", steps 1–6. You need:

- A development stack signed in as an Administrator with an authenticator app, a working email setup (scheduled runs
  and the preview email need it; see [operator-guide.md](../../operator-guide.md#email)), and an evaluation or license
  that allows changes.
- A disposable **test** Linux server prepared for Alice (Phase 3 walkthrough), confirmed and scanned with this version
  (**Scan for SSH keys**), with a test user that has a home directory and a login shell, and console access to the
  server that does not depend on SSH (for step 6).

Without your own server, steps 1 to 5 can be walked on the e2e stack (`make e2e-up`; its target has the user
`deploy`); write "e2e" in the notes. That proves the screens, not your server.

1. **Generate and deploy.** **SSH keys** → **Generate key**, name `owner-test`, **Ed25519 (recommended)**. On the key's
   page choose **Deploy to a server**, pick the test server, the test user and the offered file, **Deploy**. On the
   server: `cat ~<user>/.ssh/authorized_keys` shows a line ending in `alice:owner-test:<today>`.
2. **Download.** **Download private key**, a reason of at least 10 characters, a passphrase of at least 12 characters,
   then the authenticator code. Run `ssh -i <file> <user>@<server> true` (enter the passphrase). Open **Audit log**.
3. **Policy.** Under **Automatic rotation** choose **Create rotation policy**: **Rotate every (days)** 90, **Keep the
   old key for (days)** 7. Leave it as created.
4. **Preview.** Choose **Preview next run**. Check your mailbox.
5. **Manual rotation.** In the preview choose **Run now**, then **Start rotation** (authenticator code). Watch the run's
   page. During **Both keys valid**, look at the user's `authorized_keys` on the server. Then choose **Finish now**
   (or wait for the 7 days) and look again after **Completed**.
6. **Network loss.** Start another rotation with **Run now** and, while the run shows **Adding the new key** or **Both
   keys valid**, cut the test server's network (for example `ip link set <interface> down` from the console, or
   detach its network in the hypervisor). Wait at least ten minutes, look at the run's page, then restore the network
   and look at `authorized_keys`.

| # | Step (§26.8) | Expected | Result | Date | Notes |
|---|---|---|---|---|---|
| 1 | Generate an Ed25519 key, deploy it to a test server and user | Alice reports a verified login with the new key | | | |
| 2 | Download private key | Authenticator code and reason are asked; the Audit log records the download | | | |
| 3 | Create a rotation policy (every 90 days, keep the old key 7 days) | It stays Off until switched on | | | |
| 4 | Preview next run | The exact servers, users and files; an email arrives | | | |
| 5 | Start a rotation manually | Both keys on the server during the overlap; nothing removed before the overlap ends and the new key was checked again | | | |
| 6 | Cut the test server's network in the middle of a rotation | The old key stays; Alice reports the incomplete rotation | | | |
| — | Turkish tone review of the new texts | Formal and natural | | | |
| — | Crypto sign-off (key generation, sealing, the OpenSSH file with a passphrase) | Signed | | | |

## Sign-off

Reviewer, date and commit are filled in when the review is completed.
