# Canary Deployment and Application Health Check Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A service policy key `canary` makes every multi-website deployment whose key comes from that service deploy to a deterministic subset first (wave 1), observe it for a hold time (the post-deploy TLS probe repeated and an optional HTTPS application check through the new certificate), and only then deploy to the rest (wave 2); a failed observation, a failed wave-1 deployment or a person's abort puts wave 1 back through the existing guarded rollback and leaves wave 2 untouched.

**Architecture:** No second engine. A new deployment state `holding` sits between a verified send and `done` for wave-1 deployments; a release finishes them `succeeded` (with the location update a success does today), a revert sends them to `recovering` with a `revert_reason`, and the existing recovery path rolls them back with the R48 guard read right before. A `deployment_rollouts` row holds the waves, the hold times and a snapshot of the policy; a `canary_checks` row per holding deployment holds the latest round. A periodic ClassAlways task `canary.advance` decides every transition; a ClassAlways job `canary.check` runs one round on one server. The HTTPS check is a new package `internal/providers/httpcheck` that dials only the location's own address through `netaddr.DialContext`. The ACME and Key Vault planners gain one rule each through their pure plan functions.

**Tech Stack:** Go 1.27.3, pgx/v5, goose, `net/http` + `crypto/tls` (no new dependency), React 18 + Mantine + TanStack Query + i18next, Vitest, Playwright.

**Spec:** `docs/superpowers/specs/2026-10-24-canary-deployment-design.md` (read it whole first; § numbers below are its sections). Background designs: `docs/superpowers/specs/2026-10-21-scoped-rbac-and-service-ownership-design.md` §5.6, §7.3, §7.4; rulings `certificate-revocation.md` "Rollback guard (R48)", `deployment-trust-verification.md` (R51), `certificate-drift.md` (R52), `license-lock-continuity.md` (R44), `windows-iis.md` W2/W3. Format model: `docs/superpowers/plans/2026-10-23-windows-w4-ci-and-release.md`.

**Decision:** R65 "Canary deployment and application health check" (R64 is the parallel "hardening batch 1"). **Size:** L, 14 tasks. **Migration:** `00035` (and `00036` if a second one is needed), written `NNNNN` below: hardening batch 1 reserves `00033` and `00034`; Task 1 confirms the next free number after merging `main`. Hardening batch 1 also reserves `ALC-CRT-0020..0025`, `internal/revocation`, the job type and settings key `revocation.check`, the e-mail templates `incident.*` and `certificate.revoked_by_authority*`, and widens `PATCH /bindings/{id}` to any-visible: nothing here may reuse those names. If `ALC-DEP-0031..0035` or `ALC-SVC-0020` are taken by the time Task 1 runs, take the next free numbers and record the renumbering as a ruling.

## Global Constraints

- **Branch.** Worktree branch `canary-deploy`, cut from `main` **after hardening batch 1 (R64) is merged** (Task 1 checks it). The first commit copies the spec and this plan unchanged. Take `main` in with `git merge main`, never rebase. Never push, never touch `main`; the coordinator merges.
- **Commits.**
  - `git -c user.name="Eren Altan" -c user.email="erenaltan@gmail.com" commit --only -m "<subject> (R65)" -m "Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>" -- <paths>`. Every subject ends with `(R65)`.
  - New files: `git add -- <path>` first. Never `git add -A` / `git add .`. Check `git status --short` before each commit.
  - Never touch `.claude/`, the untracked PDFs, `alice-helper` (untracked binary at the root), `docs/security/reviews/*`.
  - Never rebase, squash or amend a commit (`.gitleaksignore` pins hashes). Never commit key material.
- **Numbers.** Decision R65. Test IDs `CAN-01`..`CAN-32` (`alice-v1/06-quality.md` new subsection "Canary deployment (R65)", `test/matrix/traceability.json`). Error codes `ALC-DEP-0031`..`0035`, `ALC-SVC-0020` (§17.2). STRIDE rows `CN-1`..`CN-5` (§20.5). Migration `NNNNN` (`00035` unless Task 1 finds otherwise); its down's SQLSTATE is the next free `Z10xx` (grep `migrations/` for the highest).
- **Policy bounds (§5.1, verbatim):** `subset.count` 1..10, `subset.percent` 1..50, `first` 0..20, `hold` `1m`..`24h` default `10m`, `interval` `15s`..`10m` default `30s` and `<= hold`, `failures` 1..10 default 2, `check.path` starts with `/` and ≤ 512 bytes, `check.host` DNS name ≤ 253 bytes or `""`, `check.port` 0 or 1..65535, `check.expect_status` 1..10 codes in 100..599 default `[200]`, `check.timeout` `1s`..`10s` default `5s` and `< interval`, `override` `allowed` (default) | `forbidden`. Durations match `^[1-9][0-9]{0,4}(s|m|h)$`.
- **Engine constants:** expiry margin 24 h (`CanaryExpiryMargin`); grace `max(2 × interval, 5 min)` (`canaryGrace`); transient-gate stop after 1 h (`CanaryGateWait`); advance batch 100 rollouts; release-build `canary.advance` every 10 s; HTTP check header cap 16 KiB, body read cap 64 KiB, connect timeout `min(timeout, 5s)`.
- **Ports.** Local test servers of `httpcheck` and `canaryjobs` bind `127.0.0.1:45420`..`45439` only. e2e: `E2E_PROJECT=alice-e2e-canary ALICE_E2E_PORT=9979 make e2e-up e2e; E2E_PROJECT=alice-e2e-canary make e2e-down`.
- **Never at the same time:** Docker-based Go runs (`-tags integration`, testcontainers) and Playwright; neither while another `make ci` on the machine runs.
- **Coverage floors** (`coverage-floors.json`, never lower one): `deployjobs` 99, `inventory` 89, `authz` (current value), `api` 95. New entries: `alice/internal/providers/httpcheck` 95, `alice/internal/jobs/canaryjobs` 95.
- **archtest** (`internal/archtest/arch_test.go`): `"alice/internal/providers/httpcheck": {"alice/internal/platform/netaddr", "alice/internal/platform/clock"}`; `"alice/internal/jobs/canaryjobs"` = the `jobs/...` rule plus `"alice/internal/providers/httpcheck"`, `"alice/internal/jobs"`. No other rule widens.
- **Guards that stay green:** `TestImportRules`, `TestAllowed` (netaddr), `TestScopedIDOR`, `TestAuthzMatrix`, the OpenAPI `x-scope`/`x-permission` test, the error catalogue test, `TestNoCodeAcceptsAnyHostKey`, `make i18n-check` (EN = TR keys), `make matrix-check MATRIXCHECK_FLAGS=-strict`, `make docs-check`.
- **Verification commands.** `go build ./... && go vet ./... && go vet -tags integration ./...`; `go test -race -count=1 ./<pkgs>`; integration: `go test -race -count=1 -tags integration ./<pkgs> -run <Test>`; web: `cd web && npx vitest run <files> && npx tsc --noEmit && npm run lint`; final `make coverage`, `make ci`.

## Rulings (where the spec is silent; each goes into `docs/superpowers/rulings/canary-deployment.md` with "why" and "cost if wrong", marked "owner to confirm")

The 29 defaults of spec §24 are rulings 1-29, copied with their reasons. Added here for execution:

30. **Wave-2 jobs are `certificate.deploy` (ClassChange) with trigger `manual`**, `requested_by` the original requester, audit actor `jobs`. Why: they are part of a person's request; a lock that begins after insertion holds them for an Administrator as today. Cost if wrong: a wave 2 paused in lock needs `jobs.confirm`; reversible by switching the job type in `insertDeployment`.
31. **The rollout row is inserted in the same transaction as the wave-1 deployments** (manual: `RequestDeployment`/`RequestKVDeployment`; automatic: the planner's per-certificate/binding transaction). Why: a rollout without its deployments, or the reverse, must never be visible. Cost if wrong: none found.
32. **`holding` counts as "sent" everywhere `sent(state)` is consulted** (`allowedFrom`, `wasSent`). Why: the operation id is recorded and the files changed. Cost if wrong: a holding row could be finished `failed` ("nothing written"), which `aliceFingerprints` would misread.
33. **e2e health paths are static Nginx locations** (`/healthz` → 200, `/canary-fail` → 503) in `test/images/e2e-target/nginx-www.conf`, added to the `s1`..`s5` server blocks. Why: the real check runs end to end with no test seam in the product. Cost if wrong: an image rebuild.
34. **`DeploymentView` shows `holding` as one extra step row "Under observation"** with the round summary. Why: the steps list is where people look at a running deployment.

## Review Focus

1. **A wave-1 deployment that is still sending when the rollout fails or is aborted** (the verdict races the engine): it must end reverted, never `succeeded`. Test: Task 6 `TestRolloutRevertsAHoldThatArrivesAfterTheVerdict`.
2. **The check address is not the one an Administrator set** (a policy `check.host` that resolves to a metadata or public address, a location with `verify_address`): the dial goes to the location's address only, through the SEC-065 rule. Tests: Task 4 `TestCheckNeverDialsTheHostName`, `TestCheckRefusesLinkLocal`; Task 6 `TestRoundUsesTheLocationsVerifyAddress`.
3. **Alice restarts in the middle of a revert** (after `RequestRevert` committed, before or after the restore was sent): the recovery reads the journal and ends `rolled_back` once, never `succeeded`. Test: Task 3 `TestRevertSurvivesARestartAfterTheRestoreWasSent`.
4. **The licence locks during a manual hold**: observation and revert keep running; on release wave 1 stays, wave 2 is not started, the rollout says `stopped` and one e-mail goes out. Test: Task 6 `TestManualRolloutStopsAfterWaveOneInLock`.
5. **A certificate on a wave-2 website expires during the hold** (an almost-expired current certificate): the canary is skipped at request time and the audit says why. Test: Task 5 `TestCanarySkippedWhenAWaveTwoCertificateExpiresSoon`.

---

### Task 1: Merge `main`, confirm the numbers

**Files:**
- Create: `docs/superpowers/specs/2026-10-24-canary-deployment-design.md`, `docs/superpowers/plans/2026-10-24-canary-deployment.md` (copied unchanged), `docs/superpowers/rulings/canary-deployment.md` (header and a "Numbers" section only)

**Interfaces:**
- Produces: the confirmed migration number `NNNNN`, decision number, error codes and Z-SQLSTATE, recorded in the rulings file; every later task uses them.

- [ ] **Step 1:** `git log --oneline main | grep -c "(R64)"` is non-zero and `ls migrations/00034_*.sql` exists (hardening batch 1 is merged). If not, stop and report to the coordinator: this phase starts after R64.
- [ ] **Step 2:** cut `canary-deploy` from that `main`; copy the spec and this plan; commit `docs: canary deployment design and plan (R65)`.
- [ ] **Step 3: Confirm the numbers** and write them into the rulings file's "Numbers" section:
  - next migration: `ls migrations/*.sql | tail -1` (expected `00034_...`, so `NNNNN` = `00035`);
  - decisions: the last `R` entry of `docs/superpowers/specs/alice-v1/00-decisions.md` (expected R64, so R65);
  - error codes: `grep -rhoE "ALC-(DEP|SVC)-[0-9]{4}" internal locales | sort -u | tail` (expected last `ALC-DEP-0030`, `ALC-SVC-0019`);
  - the highest `Z10[0-9][0-9]` SQLSTATE in `migrations/` (the down's code is the next);
  - names: `grep -rn "canary\|rollout" internal/jobs/types.go locales/common/en.json internal/api/errors.go` finds nothing this plan would collide with (`revocation.check`, `incident.*`, `certificate.revoked_by_authority*` belong to R64).
  If any number differs, replace it throughout the spec and the plan in the same commit and say so in the rulings file.
- [ ] **Step 4:** `go build ./... && go vet ./...` on the merged tree; commit `docs(rulings): canary deployment numbers confirmed (R65)` with the three files.

---

### Task 2: The `canary` policy key

**Files:**
- Modify: `internal/authz/policy.go` (struct, `ReservedPolicyKeys`, `normalize`, `ChangedKeys` already generic), `internal/authz/policy_test.go`
- Create: `internal/authz/canary.go` (types, defaults, `CanaryWaves`, duration parsing), `internal/authz/canary_test.go`
- Modify: `internal/authz/services/services.go` (`SetPolicy`: the `first` existence check), `internal/authz/services/policy_integration_test.go`
- Modify: `internal/api/errors.go` (`ErrSVCCanaryOverrideForbidden` `ALC-SVC-0020`, 422, registered for Task 9's use), `locales/common/en.json`, `locales/common/tr.json`, `internal/api/errors_catalogue_test.go` expectations

**Interfaces:**
- Produces:
  - `type CanaryPolicy struct { Enabled bool; Subset *CanarySubset; First []uuid.UUID; Hold, Interval string; Failures *int; Check *CanaryCheck; Override string }` (JSON names per §5.1) and `type CanarySubset struct { Count, Percent *int }`, `type CanaryCheck struct { Path, Host string; Port int; ExpectStatus []int; Timeout string }`.
  - `Policy.Canary *CanaryPolicy` (`json:"canary,omitempty"`).
  - `type CanarySettings struct { Count, Percent int; First []uuid.UUID; Hold, Interval, Timeout time.Duration; Failures int; Check *CanaryCheck; OverrideAllowed bool }` — the effective values, defaults filled (this is what a rollout snapshots, JSON-encoded, §5.3).
  - `func (p Policy) CanaryEnabled() bool`; `func (p Policy) CanarySettings() (CanarySettings, bool)` (false when absent or disabled).
  - `func CanaryWaves(dests []uuid.UUID, s CanarySettings) (wave1, wave2 []uuid.UUID)` (§7; returns `nil, nil` for fewer than 2 destinations).
  - Constants `CanaryOverrideAllowed = "allowed"`, `CanaryOverrideForbidden = "forbidden"`.
  - `ReservedPolicyKeys = []string{"verification", "drift", "windows", "thresholds"}`.

- [ ] **Step 1: Write the failing tests** (`canary_test.go`, CAN-01..CAN-03):
  - `TestParseCanaryDefaultsAndNormalization`: `{"schema":1,"canary":{"enabled":true}}` parses; `CanarySettings()` = count 1, hold 10m, interval 30s, failures 2, timeout 5s, override allowed, no check; `{"canary":{"enabled":true,"hold":"120s"}}` stores `"2m"`; `{"canary":{"enabled":false}}` normalizes to `{"schema":1}`; `first` keeps its order.
  - `TestParseCanaryRefuses` (table, each a `validate.Errors` with the exact field): `subset` with both members and with none (`body.canary.subset`); count 0 and 11; percent 0 and 51; 21 `first` ids; a duplicate `first` id; hold `30s`, `25h`, `1h30m`, `1.5h`; interval `10s`, `11m`, interval > hold; failures 0 and 11; check without path; path `healthz`, a path with `#`, a space, a control char, 513 bytes; host `*.example.com`, `10.0.0.1`, `[::1]`, 254 bytes; port 70000; expect_status `[]`, `[99]`, `[600]`, 11 codes, duplicates; timeout `0s`, `11s`, timeout ≥ interval; override `maybe`. An unknown sub-field (`canary.check.url`) is `ErrPolicyMalformed`.
  - `TestCanaryWaves` (table): n=1 → nil; n=2 count 1 → 1/1; n=2 count 10 → 1/1 (wave 2 never empty); n=20 percent 10 → 2/18; n=3 percent 1 → 1/2; n=5 percent 50 → 3/2 (ceil); `first` = [d4, x (not a destination), d2] → wave 1 starts d4, d2; the rest sorted by UUID byte order; the same input in shuffled order gives the same waves.
  - In `policy_test.go`: the reserved-keys test no longer lists `canary`; `TestChangedKeys` reports `canary` when only it changes.
- [ ] **Step 2: Run** `go test ./internal/authz/` — Expected: FAIL (`CanaryPolicy` undefined).
- [ ] **Step 3: Implement** the types and parsing in `canary.go`; `normalize` calls `p.Canary.normalize(&v, prefix+"canary")`; durations parsed with the regex then `time.ParseDuration`, re-rendered with the largest whole unit. `CanaryWaves` exactly as §7.
- [ ] **Step 4: Run** `go test -race -count=1 -cover ./internal/authz/` — Expected: PASS, coverage ≥ the floor.
- [ ] **Step 5: `first` at save — write the failing integration test** `TestSetPolicyCanaryFirstMustBeTheServicesLocations` (`internal/authz/services/policy_integration_test.go`, CAN-04): a location of a server in service A is accepted for A; the same id for service B → `validate.Errors` field `body.canary.first.0` code `not_found`; an unknown id likewise; a location of a deleted server likewise.
- [ ] **Step 6: Implement** the check inside `SetPolicy`'s transaction (one query: `SELECT l.id FROM certificate_locations l JOIN targets t ON t.id = l.target_id AND t.deleted_at IS NULL WHERE l.id = ANY($1) AND t.service_id = $2`).
- [ ] **Step 7: Register `ALC-SVC-0020`** (`service.canary_override_forbidden`, 422) with EN/TR texts; run `go test ./internal/api/ -run TestErrorCatalogue` and `make i18n-check`.
- [ ] **Step 8: Run** `go test -race -count=1 -tags integration ./internal/authz/services/ -run TestSetPolicy` — Expected: PASS.
- [ ] **Step 9: Commit** `feat(policy): the canary service policy key (R65)` with the paths above.

---

### Task 3: Migration and the `holding` state in the engine

**Files:**
- Create: `migrations/NNNNN_canary_deployment.sql` (§16 verbatim, plus the grants and the down), `migrations/canary_integration_test.go`
- Modify: `migrations/frozen_test.go`
- Modify: `internal/inventory/deployments.go` (`DeployStateHolding = "holding"`, `Deployment.RolloutID *uuid.UUID`, `Deployment.Wave int`, `Deployment.RevertReason string`, `deploymentSelect`/`scanDeployment`), `internal/inventory/deployment_records.go` (`sent`, `finishLocked`, new `ReleaseHold`, `RequestRevert`), `internal/inventory/sweep.go` (`sweepWhere` excludes `holding`)
- Modify: `internal/jobs/deployjobs/deploy.go` (`follow`), `internal/jobs/deployjobs/recover.go` (`recoverJob`, revert rows), `internal/jobs/deployjobs/deployjobs.go` (`resultOf`)
- Create: `internal/inventory/canary_hold_integration_test.go`, `internal/jobs/deployjobs/canary_revert_integration_test.go`
- Modify: `internal/jobs/deployjobs/deployjobs_test.go` (unit rows for the decision tables; floor 99)

**Interfaces:**
- Consumes: none.
- Produces (all in `inventory`):
  - `const DeployStateHolding = "holding"`.
  - `func (s *Service) ReleaseHold(ctx context.Context, tx pgx.Tx, id uuid.UUID, cause string) error` — `holding` → `done succeeded` with the stored values; `cause` ∈ `release`, `incident`, `target_deleted` goes into the `deployment.succeeded` audit details as `hold_cause`. `ErrDeploymentState` from any other state. Caller holds the location and deployment locks (helper `lockForHold(ctx, tx, id)` exported to the package).
  - `func (s *Service) RequestRevert(ctx context.Context, tx pgx.Tx, id uuid.UUID, reason string) error` — `holding` → `recovering`, `revert_reason = error_code = reason`, `recover_after = now`, recovery job queued (`requestRecoveryLocked`), audit `deployment.revert_requested`. `ErrDeploymentState` otherwise.
  - Closed reasons `ReasonCanaryCheckFailed = "deployment.canary_check_failed"`, `ReasonCanaryAborted = "deployment.canary_aborted"`, `ReasonCanaryWaveFailed = "deployment.canary_wave_failed"`.
  - A wave-1 deployment (`rollout_id` set, `wave = 1`) whose finish is `succeeded` enters `holding` (writes `held_cert_file_sha256`, inserts its `canary_checks` row with `next_check_at = now`, audit `deployment.holding`, no e-mail, no location update).

- [ ] **Step 1: Migration test first** — `TestMigrationNNNNNCanary` (CAN-05): up on the populated fixture leaves every existing deployment row equal (`to_jsonb` compare minus the new columns); inserting a `holding` row without `rollout_id` fails `deployments_holding_wave1`; `rollout_id` without `wave` fails `deployments_wave_rollout`; down with a rollout row raises the new SQLSTATE; down without one restores the old state CHECK (a `holding` insert fails after down).
- [ ] **Step 2: Run** `go test -tags integration ./migrations/ -run TestMigrationNNNNNCanary` — FAIL (no migration). **Step 3:** write the migration (§16; state CHECK dropped/re-added by its generated name `deployments_state_check`; grants per §16) and add it to `frozen_test.go`. **Step 4:** run again — PASS.
- [ ] **Step 5: Engine tests first** (`canary_hold_integration_test.go`, CAN-06..CAN-08), each with a rollout fixture row and the fake provider:
  - `TestWaveOneSuccessEntersHolding`: a wave-1 deployment's committed+verified outcome leaves `state holding, status running, finished_at NULL`, `held_cert_file_sha256` = the outcome's hash, the location's `certificate_id` unchanged, a `canary_checks` row, audit `deployment.holding`, no outbox row.
  - `TestUnchangedWaveOneFinishesAtOnce`: an `unchanged` outcome finishes `done unchanged` (no hold).
  - `TestWaveTwoAndPlainDeploymentsNeverHold`.
  - `TestReleaseHoldFinishesAsASuccess`: `ReleaseHold` → `done succeeded`, location `certificate_id`/`deployed_fingerprint`/`cert_file_sha256` updated as a success does, audit `deployment.succeeded` with `hold_cause`; a second call → `ErrDeploymentState`.
  - `TestRequestRevertQueuesARecovery`: `holding` → `recovering`, `revert_reason`, a live `certificate.deploy_recover` job, audit row; from `done` → `ErrDeploymentState`.
  - `TestSweepLeavesHoldingAlone`: a holding row with `recover_after` in the past and its server deleted is not picked by `SweepDeployments`.
- [ ] **Step 6: Revert tests first** (`canary_revert_integration_test.go`, CAN-09..CAN-11):
  - `TestRevertRollsBackACommittedOperation`: fake journal `committed`, new certificate verifies → `RollbackDeployment` sent with the guard → `done rolled_back`, `error_code` = the revert reason, `deployment.failed` e-mail queued.
  - `TestRevertRespectsTheRollbackGuard`: previous certificate marked compromised before the revert → nothing restored, `rollback_failed deployment.rollback_forbidden`.
  - `TestRevertSurvivesARestartAfterTheRestoreWasSent` (Review Focus 3): the first recovery run sends the restore and its record write fails; a second run reads journal `restored` and records `rolled_back` once.
  - `TestDeployJobFindingHoldingDoesNothing` and `TestRecoveryJobFindingHoldingWithoutRevertDoesNothing`: success results `{outcome: holding}`, no provider call.
- [ ] **Step 7: Run** both test files — FAIL. **Step 8: Implement** per §8 and §10 (the revert rows of §10's table in `recoverDeployment`; `resultOf` maps `holding` to success). **Step 9: Run** `go test -race -count=1 ./internal/jobs/deployjobs/ ./internal/inventory/` and the two integration files — PASS; `go test -cover ./internal/jobs/deployjobs/` ≥ 99.
- [ ] **Step 10: Commit** `feat(deploy): the holding state, release and revert of a wave-1 deployment (R65)`.

---

### Task 4: `httpcheck`: the application check

**Files:**
- Create: `internal/providers/httpcheck/httpcheck.go`, `internal/providers/httpcheck/httpcheck_test.go`
- Modify: `internal/archtest/arch_test.go` (the rule of Global Constraints), `coverage-floors.json` (`httpcheck` 95)

**Interfaces:**
- Produces:
  - `type Request struct { Address string; Port int; ServerName string; Path string; ExpectStatus []int; Timeout time.Duration; ExpectLeafSHA256 string; UserAgent string }`.
  - `type Result struct { OK bool; Reason string; HTTPStatus int; LatencyMS int; ServedSHA256 string }`; reasons `ReasonHTTPStatus = "canary.http_status"`, `ReasonServedOther = "canary.served_other"`, `ReasonUnreachable = "canary.unreachable"`, `ReasonNotAllowed = "canary.not_allowed"`, `ReasonTimeout = "canary.timeout"`, `ReasonProtocol = "canary.protocol"`.
  - `type Checker interface { Check(ctx context.Context, r Request) Result }`; `type HTTPChecker struct { Clock clock.Clock; Resolver *net.Resolver }` implementing it (dial through `netaddr.DialContext`; §9.3 table exactly: TLS ≥ 1.2, `InsecureSkipVerify` + leaf compare in `VerifyConnection` before any request byte, no proxy, no redirects, keep-alives off, header cap 16 KiB, body discard cap 64 KiB, `Host` = `ServerName` or the address).

- [ ] **Step 1: Write the failing tests** (CAN-12..CAN-15), servers on `127.0.0.1:45420`..`45439` with a test CA leaf whose SHA-256 is the expectation:
  - `TestCheckPasses` (200 → OK, latency ≥ 0, served hash set); `TestCheckStatusNotExpected` (503 → `canary.http_status`, status 503); `TestCheckDoesNotFollowRedirects` (302 to a second server on 45421 which records no request; result `canary.http_status` 302; with `ExpectStatus [302]` OK).
  - `TestCheckComparesTheServedLeaf`: another leaf served → `canary.served_other` and the server saw **no** HTTP request (handshake only).
  - `TestCheckSendsTheServerNameAndHost`: the server records SNI and `Host` = `ServerName`; the method is `GET`, path+query exact, no `Cookie`/`Authorization`, `User-Agent` as given.
  - `TestCheckNeverDialsTheHostName` (Review Focus 2): `ServerName` = `metadata.invalid` while `Address` = `127.0.0.1`: the connection goes to 127.0.0.1 (the resolver records no lookup of the server name).
  - `TestCheckRefusesLinkLocal`: `Address` `169.254.169.254` → `canary.not_allowed`, nothing dialed; a resolver answering a name with `169.254.169.254` → `canary.not_allowed`.
  - `TestCheckIgnoresEnvironmentProxies`: `HTTPS_PROXY` set to a recording listener → it records nothing.
  - `TestCheckTimeouts`: a server that accepts and never answers → `canary.timeout` within `Timeout + 1s`; a slow-loris body (1 byte/s) is cut at the timeout; a 10 MiB body → OK after reading at most 64 KiB (the server's write is cut); headers over 16 KiB → `canary.protocol`; a plaintext listener → `canary.unreachable`; a refused port → `canary.unreachable`.
- [ ] **Step 2: Run** `go test ./internal/providers/httpcheck/` — FAIL. **Step 3: Implement.** **Step 4: Run** `go test -race -count=1 -cover ./internal/providers/httpcheck/ ./internal/archtest/` — PASS, ≥ 95 %.
- [ ] **Step 5: Commit** `feat(httpcheck): the canary's HTTPS application check through the SEC-065 address rule (R65)`.

---

### Task 5: Rollouts for manual requests (create, waves, override, expiry guard)

**Files:**
- Create: `internal/inventory/canary.go` (rollout type, reads, `createRollout`), `internal/inventory/canary_request_integration_test.go`, `internal/inventory/canary_test.go`
- Modify: `internal/inventory/deployments.go` (`DeployRequestInput.CanaryOverride bool`; `RequestDeployment`), `internal/inventory/kv_deploy.go` (`KVDeployInput.CanaryOverride`; `RequestKVDeployment`), `internal/inventory/acme_bindings.go` (Deploy now passes the override), `internal/inventory/deployments.go` `insertDeployment` (`deploySource.RolloutID *uuid.UUID`, `deploySource.Wave int`)

**Interfaces:**
- Consumes: Task 2 `authz.Policy.CanarySettings`, `authz.CanaryWaves`; Task 3 columns.
- Produces:
  - `type Rollout struct { ID uuid.UUID; CertificateID uuid.UUID; ServiceID *uuid.UUID; PolicyVersion int; Settings authz.CanarySettings; Origin string; ACMECertificateID, BindingID, KVVersionID, RequestedBy *uuid.UUID; State, Reason string; ReasonParams map[string]string; Wave1, Wave2 []uuid.UUID; Skipped []RolloutSkip; HoldStartedAt, HoldUntil, FinishedAt *time.Time; CreatedAt time.Time; Version int }`; `type RolloutSkip struct { LocationID uuid.UUID; Reason string }`.
  - States `RolloutWave1 = "wave1"`, `RolloutHold = "hold"`, `RolloutWave2 = "wave2"`, `RolloutCompleted = "completed"`, `RolloutFailed = "failed"`, `RolloutAborted = "aborted"`, `RolloutStopped = "stopped"`, `RolloutPreempted = "preempted"`; origins `"manual"`, `"acme"`, `"key_vault"`.
  - `func (s *Service) Rollout(ctx context.Context, id uuid.UUID) (Rollout, error)` (`ErrRolloutNotFound`).
  - `func canaryDecision(p authz.Policy, dests []uuid.UUID, current map[uuid.UUID]time.Time, now time.Time, override, exempt bool) (s authz.CanarySettings, wave1, wave2 []uuid.UUID, skip string)` — pure; `skip` ∈ `""` (canary applies), `"disabled"`, `"single"`, `"override"`, `"exempt"`, `"expiry"`; `current` = each destination's current certificate `not_after` (absent when unknown).
  - `RequestedDeployment` unchanged; `RequestDeployment` and `RequestKVDeployment` return `([]RequestedDeployment, *Rollout, error)` (the API maps both). `ErrCanaryOverrideForbidden`.
  - `const CanaryExpiryMargin = 24 * time.Hour`.

- [ ] **Step 1: Pure tests first** (`canary_test.go`, CAN-16): `TestCanaryDecision` table: disabled → `disabled`; one destination → `single`; override with `override: allowed` → `override`; incident (`exempt`) → `exempt`; a destination's current certificate ending at `now + hold + 23h` → `expiry`; at `now + hold + 25h` → applies with the waves of `CanaryWaves`; unknown current certificate → applies.
- [ ] **Step 2: Integration tests first** (`canary_request_integration_test.go`, CAN-17..CAN-19), fake provider, policy enabled on the certificate's service:
  - `TestRequestCreatesARollout`: three locations → one rollout (`wave1`, settings snapshot, policy version), one deployment with `wave 1`, `rollout_id`, wave 2 = two ids not inserted; audit `deployment.rollout_started`; all location checks still run on all three (a not-ready wave-2 server refuses the whole request as today).
  - `TestCanarySkippedWhenAWaveTwoCertificateExpiresSoon` (Review Focus 5): three deployments, no rollout, audit `deployment.canary_skipped` with `reason expiry`, `not_after`, `location_id`.
  - `TestOverride`: `CanaryOverride` with `override: allowed` → three deployments, audit `deployment.canary_overridden`; with `forbidden` → `ErrCanaryOverrideForbidden`, nothing inserted, audit `deployment.denied` reason `canary_override_forbidden`.
  - `TestKVDeployNowAndACMEDeployNowCreateRollouts` (source service's policy: the vault's / the ACME certificate's, not the certificate row's).
  - `TestIncidentReplacementNeverCreatesARollout`.
- [ ] **Step 3: Run** — FAIL. **Step 4: Implement**: inside the request transaction after `checkDeployLocation` for every location: load the source policy (`authz.LoadPolicy(ctx, tx, c.service)`), read current `not_after` per location, `canaryDecision`, insert the rollout (`createRollout`), insert only wave-1 deployments with `RolloutID`/`Wave 1`. The override's step-up is the API's (Task 9); inventory checks only the policy's `override`.
- [ ] **Step 5: Run** `go test -race -count=1 ./internal/inventory/ -run TestCanaryDecision` and the integration file — PASS.
- [ ] **Step 6: Commit** `feat(deploy): manual requests split into canary waves (R65)`.

---

### Task 6: The advance task and the round job

**Files:**
- Create: `internal/inventory/canary_advance.go` (`AdvanceRollouts`, the pure `decideRollout`, transitions), `internal/inventory/canary_rounds.go` (`CanaryRoundTarget`, `RecordCanaryRound`, due rounds), `internal/inventory/canary_advance_test.go`, `internal/inventory/canary_advance_integration_test.go`
- Create: `internal/jobs/canaryjobs/canaryjobs.go`, `internal/jobs/canaryjobs/canaryjobs_test.go`, `internal/jobs/canaryjobs/canaryjobs_integration_test.go`
- Modify: `internal/jobs/types.go` (`CanaryAdvance = Register("canary.advance", license.ClassAlways)`, `CanaryCheck = Register(inventory.JobCanaryCheck, license.ClassAlways)`, `MaxAttemptsFor` 1, `AlertsWhenExhausted` false), `internal/jobs/*_types_test.go` (pins), `cmd/alice/services.go` (`canaryjobs.AdvanceTask`, `canaryjobs.Register`), `cmd/alice/wiring.go`, `cmd/alice/testapi_release.go` (`canaryAdvanceEvery = 10 * time.Second`), `cmd/alice/testapi_e2e.go` (never ticks), `coverage-floors.json` (`canaryjobs` 95), `internal/archtest/arch_test.go`
- Create: notification template `deployment.rollout_stopped` (EN/TR) in `locales/common/*.json` and its render test in `internal/notify`

**Interfaces:**
- Consumes: Tasks 3 and 5; Task 4 `httpcheck.Checker`.
- Produces:
  - `const JobCanaryCheck = "canary.check"`.
  - `func (s *Service) AdvanceRollouts(ctx context.Context) (int, error)`.
  - `type rolloutSnapshot struct{...}` and `func decideRollout(sn rolloutSnapshot) rolloutPlan` — pure; `rolloutPlan` lists `release []uuid.UUID`, `revert map[uuid.UUID]string` (deployment → reason), `endQueued []uuid.UUID`, `queueRounds []uuid.UUID`, `next string` (state), `reason string`, `reasonParams map[string]string`, `insertWave2 bool`, `holdStart bool`.
  - `type CanaryTarget struct { Deployment uuid.UUID; TargetID uuid.UUID; Verify providers.VerifyRequest; Check *httpcheck.Request }` and `func (s *Service) CanaryRoundTarget(ctx context.Context, id uuid.UUID) (CanaryTarget, error)` (`ErrDeploymentState` unless `holding`); `type CanaryRound struct { Result, Reason, TLS string; HTTPStatus, LatencyMS int }`; `func (s *Service) RecordCanaryRound(ctx context.Context, id uuid.UUID, r CanaryRound) error` (fenced to the claim; ignores a non-holding row).
  - `canaryjobs.Register(r *jobs.Runner, d Deps)`, `canaryjobs.AdvanceTask(inv Inventory, every time.Duration, log *slog.Logger) jobs.Task`; `Deps{Inventory, Registry, Checker httpcheck.Checker, Clock, Log}`.

- [ ] **Step 1: Pure decision tests first** (`canary_advance_test.go`, CAN-20): `TestDecideRollout` table, one row per transition of §9.1 and §11: wave1 with one deployment still running → nothing; all holding → `hold` with `holdStart`; a wave-1 deployment `failed` → `failed canary.wave1_failed`, revert the holding ones with `deployment.canary_wave_failed` (cause `deployment_failed`), end queued ones; consecutive failures = `failures` → `failed canary.check_failed`, revert all with `deployment.canary_check_failed`; hold elapsed and every last round pass after `hold_started_at` → release, manual → `wave2` + `insertWave2`, automatic → `completed`; hold elapsed with one last round unknown before grace → nothing, after grace → `failed canary.check_unavailable`; certificate revoked → `failed canary.certificate_revoked`; a holding deployment of a `failed`/`aborted` rollout → revert; of a `completed`/`stopped`/`preempted` rollout → release; server deleted → release (`target_deleted`) and drop from wave 1, every wave-1 location gone → `failed canary.wave_gone`; `wave2` with every wave-2 deployment done → `completed`; due rounds listed only for holding deployments with `next_check_at <= now`.
- [ ] **Step 2: Integration tests first** (`canary_advance_integration_test.go`, CAN-21..CAN-25):
  - `TestRolloutPassesAndStartsWaveTwo`: fake provider, clock moved past the hold, rounds recorded as pass → wave-1 `done succeeded`, location updated, two wave-2 deployments inserted (`wave 2`, trigger manual, `requested_by` the requester, job `certificate.deploy`), audit `deployment.rollout_released`, `deployment.rollout_wave2_started`; after they finish → `completed`.
  - `TestRolloutFailsAndRevertsWaveOneOnly`: two failed rounds → every wave-1 deployment `recovering` with `revert_reason`, no wave-2 row exists, rollout `failed`, audit `deployment.rollout_check_failed` once.
  - `TestRolloutRevertsAHoldThatArrivesAfterTheVerdict` (Review Focus 1): rollout aborted while a wave-1 deployment is `deploying`; its success enters `holding`; the next advance reverts it.
  - `TestManualRolloutStopsAfterWaveOneInLock` (Review Focus 4): licence locked (confirmed) at release → wave 1 `succeeded`, no wave-2 row, rollout `stopped license.locked`, one `deployment.rollout_stopped` outbox row per recipient; with `ErrLockDue` → stays `hold` with `gate_waiting_since`, and after `CanaryGateWait` → `stopped`.
  - `TestWaveTwoRechecksEachLocation`: a wave-2 server disabled meanwhile → recorded in `skipped` (`target_not_ready`), audit `deployment.denied` (actor jobs), the other location inserted.
  - `TestTwoAdvancersDoNotDoubleTransition`: two concurrent `AdvanceRollouts` → one set of transitions, one set of audit rows.
  - `TestRoundUsesTheLocationsVerifyAddress` (Review Focus 2): `CanaryRoundTarget` sets `Check.Address` = `verify_address` when set, else `targets.host`; port and server name per §9.3's precedence (four rows).
- [ ] **Step 3: Job tests first** (`canaryjobs_test.go` with fakes; `canaryjobs_integration_test.go` with the fake provider and an `httpcheck` server on 45422): `TestRoundPassFailUnknown` (baseline pass + HTTP pass → pass; baseline pass + 503 → fail `canary.http_status`; session refused → unknown, nothing counted as failure; skipped baseline + no check → pass); `TestRoundIgnoresANonHoldingDeployment`; `TestAdvanceTaskQueuesOneJobPerDueRound` (dedupe `canary.check:<id>`, TargetID = the server).
- [ ] **Step 4: Run** all three — FAIL. **Step 5: Implement**: `AdvanceRollouts` pages active rollouts (`deployment_rollouts_active`), per rollout one transaction: `SELECT ... FOR UPDATE SKIP LOCKED` on the rollout, snapshot, `decideRollout`, apply (lock order rollout → locations → deployments, id order; §20.3), gate asked only for `insertWave2` (manual: `license.Allow(license.ClassChange)`), wave 2 through `checkDeployLocation` + `insertDeployment`. Wire the task and the handler.
- [ ] **Step 6: Run** `go test -race -count=1 -cover ./internal/jobs/canaryjobs/ ./internal/inventory/ ./internal/jobs/ ./cmd/alice/` and the integration files — PASS; `canaryjobs` ≥ 95.
- [ ] **Step 7: Commit** `feat(canary): the advance task, rounds and wave 2 (R65)`.

---

### Task 7: Automatic deployments follow the policy

**Files:**
- Modify: `internal/inventory/acme_autodeploy_plan.go` (`acmeDeploySnapshot.canary *canaryPlanState`), `internal/inventory/acme_autodeploy.go` (snapshot read, rollout insert, wave-1 only), `internal/inventory/kv_autodeploy_plan.go`, `internal/inventory/kv_autodeploy.go` (same), `internal/inventory/canary_advance.go` (on `failed`/`aborted` of an automatic rollout: the existing stop mark, stop audit and stop notice with `error_reason` = the revert reason)
- Test: `internal/inventory/acme_autodeploy_test.go`, `internal/inventory/kv_autodeploy_test.go` (pure), `internal/inventory/canary_auto_integration_test.go`

**Interfaces:**
- Consumes: Tasks 2, 5, 6.
- Produces: `type canaryPlanState struct { settings authz.CanarySettings; enabled bool; rollout *Rollout; currentNotAfter map[uuid.UUID]time.Time; reserved map[uuid.UUID]bool }` (`reserved`: the locations of every rollout of any origin in `wave1`/`hold`, spec §12 "Reservation"); both plans gain `createRollout *rolloutWaves` (`wave1, wave2 []uuid.UUID`).

- [ ] **Step 1: Pure tests first** (CAN-26): in both plan test files `TestPlanCanary*`: enabled, 3 destinations, no rollout → `createRollout` with the waves, `deploy` = wave 1 only; rollout `wave1`/`hold` → only unattempted wave-1 locations; rollout `failed` → nothing deployed; rollout `completed`, `preempted` or `stopped` → today's plan over the rest, no new rollout; a location in `reserved` → never a candidate, no attention mark; one destination → today's plan; expiry within hold + 24 h → today's plan (no rollout) and the plan reports `canarySkipped "expiry"`.
- [ ] **Step 2: Integration test first** (`canary_auto_integration_test.go`, CAN-27): `TestACMERenewalRollsOutWithACanary` and `TestKVRenewalRollsOutWithACanary`: renewal → rollout `origin acme`/`key_vault` + one `certificate.deploy_auto` deployment; check failure → wave 1 reverted, `deploy_stopped_certificate_id` / `stopped_version` set, one stop notice with `error_reason deployment.canary_check_failed`; re-arm → a second rollout is allowed (the partial unique index admits it). `TestPlannerLeavesAPersonsRolloutAlone`: an ACME Deploy now rollout (`origin manual`) in `hold` → `PlanACMEAutoDeploy` creates nothing at its wave-2 locations; same for a Key Vault Deploy now. `TestFailedPersonsRolloutStopsTheAutomaticDeployment`: that manual rollout fails → the ACME certificate's stop mark for that certificate is set (and the binding's `stopped_version` in the KV variant), so the next planner run creates nothing.
- [ ] **Step 3: Run** — FAIL. **Step 4: Implement.** **Step 5: Run** the pure and integration tests plus the existing ACME/KV planner suites unchanged — PASS.
- [ ] **Step 6: Commit** `feat(canary): ACME and Key Vault automatic deployments follow the canary policy (R65)`.

---

### Task 8: Interactions: incidents, Windows cleanup, drift, revocation

**Files:**
- Modify: `internal/inventory/incidents_engine.go` (`followIncidentDeployment`: a `holding` deployment at an affected place → `ReleaseHold(..., "incident")` and the rollout `preempted`, audit `deployment.rollout_preempted`)
- Test: `internal/inventory/canary_interactions_integration_test.go`

**Interfaces:**
- Consumes: Tasks 3, 6.

- [ ] **Step 1: Write the failing tests** (CAN-28): `TestIncidentPreemptsAHold` (the place's holding deployment released, rollout `preempted`, no wave 2, the incident proceeds on the next step); `TestIncidentNeverReleasesACompromisedHold` (the held certificate itself is compromised and an incident covers the place: the hold is not released, `ReleaseHold` answers `ErrCertificateCompromised`, the next advance reverts it with `canary.certificate_revoked`, the incident waits on the busy place until the revert ends); `TestWindowsCleanupKeepsTheCertificatesOfAHold` (a holding deployment on a fake Windows server: `JudgeCleanup` keeps both thumbprints with `deployment_running`); `TestDriftSkipsAHoldingLocation` (no observation queued, no repair planned); `TestDeployedCertificateRevokedDuringTheHold` (mark compromised → next advance fails the rollout `canary.certificate_revoked` and reverts with the guard allowing the previous certificate).
- [ ] **Step 2: Run** — FAIL only for the incident test (the others pin existing behaviour; if one fails, fix it in the task that owns the code). **Step 3: Implement** the incident branch. **Step 4: Run** — PASS, and the existing incident suites unchanged.
- [ ] **Step 5: Commit** `feat(canary): incidents preempt a hold; interactions pinned (R65)`.

---

### Task 9: API: rollout routes, override, DTOs, errors

**Files:**
- Create: `internal/api/rollouts_handlers.go`, `internal/api/rollouts_handlers_test.go`, `internal/api/canary_integration_test.go`
- Modify: `internal/api/certificates_handlers.go` (`canary_override`), `internal/api/acme_handlers.go` (Deploy now), `internal/api/bindings_handlers.go` (Deploy now), `internal/api/deployments_handlers.go` (`rollout_id` filter, DTO), `internal/api/certs_dto.go` (deployment DTO `rollout`, detail `canary`), `internal/api/inventory_dto.go` (if the location list lives there: `service_id` filter), `internal/api/server.go` (interface methods), `internal/api/errors.go` (`ALC-DEP-0031..0035`), `internal/authz/services/resolve.go` (`KindRollout`), `api/openapi.yaml`, `docs/authz-matrix.md` (regenerated), `locales/common/*.json`

**Interfaces:**
- Consumes: Tasks 2-6.
- Produces: inventory methods the API calls — `func (s *Service) ContinueRollout(ctx context.Context, a Actor, id uuid.UUID) (Rollout, error)`, `func (s *Service) AbortRollout(ctx context.Context, a Actor, id uuid.UUID) (Rollout, error)` (both `ErrRolloutState` as §13.2/§13.3; implemented in `canary_advance.go` reusing the transitions), `ErrRolloutNotFound`, `ErrRolloutState`; JSON per §17.1 (`rolloutDTO`, `allowed_actions`, `now`, `hidden_count`).

- [ ] **Step 1: Write the failing tests** (CAN-29, CAN-30):
  - `TestRolloutRoutes` (unit, fakes): GET answers the DTO; continue without step-up → 403 `ALC-AUTH-0003` (`auth.stepup_required`), with step-up → 200 and `ContinueRollout` called; continue from a token → 403; continue lacking `certificates.operate` on a wave-2 server's service → 403 `ALC-SVC-0012`; abort from an Operator without step-up → 200; abort in `wave2` → 409 `ALC-DEP-0034`; unknown id → 404 `ALC-DEP-0035`; abort works in lock (ClassAlways), continue refused in lock (ClassChange).
  - `TestCanaryPermissionsEquivalent`: `rbac.PolicyFor(AcmeOperate)` and `rbac.PolicyFor(CertificatesOperate)` have equal roles, token scope and step-up (spec Decision 26: an ACME-sourced rollout is steered with `certificates.operate`).
  - `TestDeployOverrideNeedsStepUp`: `canary_override: true` without step-up → 403 step-up, nothing requested; with → `CanaryOverride` passed; a token → 403; `forbidden` policy → 422 `ALC-SVC-0020`. Same three rows for ACME and Key Vault Deploy now.
  - `TestDeployAnswerCarriesTheRollout`: 202 body has `rollout` with waves and `deployments` = wave 1.
  - `TestDeploymentDTOHasRolloutAndCanary`, `TestDeploymentsFilterByRollout`, `TestLocationsFilterByService`.
  - `canary_integration_test.go`: the whole manual path over the wire with the fake provider (request → holding → rounds → advance → wave 2).
  - The generated `TestScopedIDOR`, `TestAuthzMatrix`, OpenAPI and error-catalogue tests pick the new routes and codes up.
- [ ] **Step 2: Run** `go test ./internal/api/ -run 'TestRollout|TestDeploy|TestDeployment|TestLocations'` — FAIL. **Step 3: Implement** (routes per §17.1: `scopeResource` with `by(services.KindRollout, "id")` for GET and abort, `scopeCross` for continue with `checkDestinationsOf` over wave 2; step-up via `strictActionFor(w, r, rbac.SessionStepUp)`). Regenerate `docs/authz-matrix.md` with its existing generator.
- [ ] **Step 4: Run** `go test -race -count=1 -cover ./internal/api/ ./internal/authz/...` and `go test -race -count=1 -tags integration ./internal/api/ -run 'TestScopedIDOR|TestCanary'` — PASS, api ≥ 95.
- [ ] **Step 5: Commit** `feat(api): rollout routes, the canary override and the rollout in deployment answers (R65)`.

---

### Task 10: Web: the policy editor's canary section

**Files:**
- Modify: `web/src/components/services/PolicyPanel.tsx`, `web/src/components/services/PolicyPanel.test.tsx`, `web/src/api/` (the policy and location types; the location list's `service_id` parameter), `web/src/locales/en.json`, `web/src/locales/tr.json`

**Interfaces:**
- Consumes: Task 2's JSON shape; Task 9's `GET /certificate-locations?service_id=`.

- [ ] **Step 1: Write the failing tests** (CAN-31, part 1) in `PolicyPanel.test.tsx`: the section renders from a stored policy (count, hold, check fields); switching on and saving sends exactly `{"canary":{"enabled":true}}` plus changed fields (defaults not sent); choosing "percent" sends `subset: {percent: n}` and drops `count`; server field errors `body.canary.check.timeout` land on that input; read-only without `services.policy`; the "observed by time only" warning when no check is set and a service location skips verification; both languages render without missing keys.
- [ ] **Step 2: Run** `cd web && npx vitest run src/components/services/PolicyPanel.test.tsx` — FAIL. **Step 3: Implement** (Mantine `Switch`, `SegmentedControl` for count/percent, `NumberInput`, duration `TextInput` with the regex hint, `MultiSelect` for `first`, `TagsInput` for statuses). Terms per spec §19.
- [ ] **Step 4: Run** the test, `npx tsc --noEmit`, `npm run lint`, `make i18n-check` — PASS.
- [ ] **Step 5: Commit** `feat(web): canary section of the service policy (R65)`.

---

### Task 11: Web: deploy dialogs, deployment detail and list

**Files:**
- Create: `web/src/components/RolloutPanel.tsx`, `web/src/components/RolloutPanel.test.tsx`
- Modify: `web/src/components/DeployDialog.tsx` (+ test), `web/src/components/KVDeployDialog.tsx` (+ test), the ACME Deploy now confirmation in `web/src/components/acme/` (+ test), `web/src/pages/DeploymentDetailPage.tsx` (+ test), `web/src/components/DeploymentView.tsx` (+ test), `web/src/pages/DeploymentsPage.tsx` (+ test), `web/src/api/` types, `web/src/locales/en.json`, `web/src/locales/tr.json`, job labels for `canary.advance` and `canary.check`

**Interfaces:**
- Consumes: Task 9's DTOs and routes.

- [ ] **Step 1: Write the failing tests** (CAN-31, part 2):
  - `RolloutPanel.test.tsx`: state badge and localized reason; the countdown from `hold_until − now` (server `now`), ticking with fake timers; both waves with links and statuses; wave-1 round columns; skipped rows with reasons; **Continue now** shown only with `continue` in `allowed_actions`, runs `useStepUp().run` then POSTs; **Abort** asks for confirmation then POSTs; a 409 `ALC-DEP-0034` shows the error alert.
  - `DeployDialog.test.tsx` (and KV, ACME): with a canary policy and two websites selected the note shows N and the hold; "Deploy to all at once" appears only with `override: allowed` and sends `canary_override: true` after step-up.
  - `DeploymentView.test.tsx`: `holding` renders "Under observation" with the round summary.
  - `DeploymentsPage.test.tsx`: the "Canary · wave 1" badge on a row with `rollout`.
- [ ] **Step 2: Run** the six test files — FAIL. **Step 3: Implement.** **Step 4: Run** them, `npx tsc --noEmit`, `npm run lint`, `make i18n-check` — PASS.
- [ ] **Step 5: Commit** `feat(web): rollout panel, canary note and override in the deploy dialogs, list badge (R65)`.

---

### Task 12: e2e: `web/e2e/canary.spec.ts`

**Files:**
- Modify: `test/images/e2e-target/nginx-www.conf` (`location = /healthz { return 200 "ok\n"; }` and `location = /canary-fail { return 503; }` in the `s1`..`s5` blocks)
- Create: `web/e2e/canary.spec.ts`

**Interfaces:**
- Consumes: everything above; helpers `resetInstall`, `runScheduled`, `drainJobs`, `drainUntil`, `advanceClock`, `answerStepUp`, `apiAs` from `web/e2e/helpers.ts`; the target's `alice-e2e-served` command for the served leaf.

- [ ] **Step 1: Write the spec** (CAN-32), each test resets the install and prepares the SSH target as `phase4.spec.ts` does, uploads one certificate covering `s1.example.test`..`s3.example.test`, sets the Default service policy through the UI (count 1, hold 1m, interval 15s, failures 2, check path `/healthz`):
  1. **Pass path (EN)**: deploy to s1-s3 from the certificate page; the dialog shows the canary note; the deployment page shows wave 1 "Under observation" and a countdown; `drainJobs`, `runScheduled('canary.advance')` (rounds), `advanceClock(70)`, `runScheduled('canary.advance')`, `drainJobs` → wave 2 succeeded, rollout "Completed", all three serve the new leaf.
  2. **Check failure (EN)**: policy path `/canary-fail`; two rounds → rollout "Failed", wave-1 deployment "Rolled back" with the canary reason; s2 and s3 still serve the old leaf; no wave-2 deployment exists (API).
  3. **Abort (EN)**: during the hold, Abort → wave 1 rolled back, rollout "Aborted".
  4. **Override with step-up (EN)**: "Deploy to all at once" → step-up → three deployments, no rollout; the audit page lists `deployment.canary_overridden`.
  5. **Turkish**: journey 1 with the interface in Turkish (`uiLang`), asserting the Turkish labels of the panel and the badge.
- [ ] **Step 2: Run** `E2E_PROJECT=alice-e2e-canary ALICE_E2E_PORT=9979 make e2e-up` then `cd web && ALICE_E2E_PORT=9979 ALICE_E2E_PROJECT=alice-e2e-canary npx playwright test e2e/canary.spec.ts --project=chromium` — Expected: 5 passed (no Docker Go run in parallel). Then `E2E_PROJECT=alice-e2e-canary make e2e-down`.
- [ ] **Step 3: Commit** `test(e2e): canary deployment journeys in English and Turkish (R65)`.

---

### Task 13: Decision, documents, security report, rulings, test IDs, CHANGELOG

**Files:**
- Modify: `docs/superpowers/specs/alice-v1/00-decisions.md` (R65), `02-architecture.md` (state machine, tables, job types), `04-security.md` (new SEC row for the check's egress; AC-8 extended to the revert), `06-quality.md` (subsection "Canary deployment (R65)", CAN-01..CAN-32 with the test names of Tasks 2-12), `test/matrix/traceability.json`
- Modify: `docs/superpowers/specs/2026-10-21-scoped-rbac-and-service-ownership-design.md` §7.4 (one line: `canary` delivered by R65, link to the spec)
- Modify: `docs/admin-guide.md` (new section "Canary deployment"), `docs/operator-guide.md` (the rollout panel, continue, abort, override), `docs/troubleshooting.md` (ALC-DEP-0031..0035, ALC-SVC-0020), `docs/security-overview.md`, `docs/api.md` (routes), `SECURITY-REPORT.md` (scope, CN-1..CN-5, the accepted port item of §20.1), `CHANGELOG.md` (Unreleased: Added / Changed / Security)
- Create: `docs/superpowers/rulings/canary-deployment.md` (rulings 1-34 with why and cost if wrong, the "What remains" list, the owner items)

- [ ] **Step 1:** write the documents; every code, route, reason and term exactly as in the code (grep each).
- [ ] **Step 2: Run** `make docs-check`, `make matrix-check MATRIXCHECK_FLAGS=-strict`, `make i18n-check` — PASS.
- [ ] **Step 3: Commit** `docs: canary deployment decision, guides, security report and rulings (R65)`.

---

### Task 14: Final gates and review

**Files:** none new. Fixes go to the task that owns the code, each with its own commit.

- [ ] **Step 1:** `go build ./... && go vet ./... && go vet -tags integration ./...`; `make lint`; `make test`; `make coverage` (no floor lower; the two new floors met).
- [ ] **Step 2:** full local `make ci` on the branch with `E2E_PROJECT=alice-e2e-canary ALICE_E2E_PORT=9979 make ci` (nothing else Docker-based running); record the totals in the rulings file.
- [ ] **Step 3:** gitleaks over `<branch point>..HEAD` (the `main` commit Task 1 cut from) exported with `git log -p`, scanned in `dir` mode; fingerprint any finding without key material.
- [ ] **Step 4: Final code review** with `superpowers:requesting-code-review` over `<branch point>..HEAD` (the `main` commit Task 1 cut from), briefed with the Review Focus list and spec §20.3; fix every finding in its owning task; re-run the affected tests and Step 2's `make ci` if Go or web code changed.
- [ ] **Step 5: Acceptance**, one line each in the rulings file: G1 (Tasks 5, 7), G2 (Task 6), G3 (Tasks 3, 6), G4 (Tasks 4, 6, spec §21), G5 (Task 4), G6 (Tasks 9, 11), G7 (`TestZeroChangeWithoutCanary`: the existing deployment, ACME and KV suites pass unchanged and the golden outbox of `internal/notify` is byte-identical), the five Review Focus tests green, CAN-01..CAN-32 traced. Hand the branch `canary-deploy` to the coordinator; do not merge or push.

---

## Execution notes

- Order: 1 → 2 → 3 ∥ 4 (disjoint files) → 5 → 6 → 7 → 8 → 9 → 10 ∥ 11 (disjoint files except the locale files: run 10 first if done by one agent) → 12 → 13 → 14.
- Review gates: after Task 3 (state machine, Review Focus 3), after Task 6 (Review Focus 1, 4; spec §20.3 lock order), after Task 9 (permissions, step-up, IDOR).
- Record every ruling made during execution in `docs/superpowers/rulings/canary-deployment.md`, one line each with why and cost if wrong.

## Left for later

- More than two waves, progressive percentages, metric-based promotion; deployment windows (`windows` key), verification policy (`verification` key).
- A manual "roll back this finished deployment" action (still carried from W2/W3).
- Apache and HAProxy canaries come with their deployment support, with no canary change.
- Owner items: the 29 defaults of spec §24 and rulings 30-34; whether override should require an Administrator rather than any deployer with step-up.
