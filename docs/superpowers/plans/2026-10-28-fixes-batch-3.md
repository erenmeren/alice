# Fixes Batch 3 (the Windows Target's Deferred Minors, W2-W6) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the Windows target's known debt before W7: every minor deferred during W3-W6, the three W6 final-review minors M2, M3 and M5, the coordinator's five extra items, and an assessment of W6 residual risk 7. Each item is either fixed with one test, or declined with a one-line reason in the rulings file.

**Architecture:** Small changes in their own files, in six areas. Parallel subagents never edit the same file.
- (a) `winhelper`, `tlsverify`, `winproto` tests (Task 1); the emulator `wintest` and the provider `internal/providers/windows` (Task 2).
- (b) `cmd/alice-winhelper`, Windows only: one new refusal (a read-deny ACE on the RDP key) and two real tests made stricter (Task 3).
- (c) Inventory, notify, the migrations test and the engine's RDP crash table (Task 4).
- (d) Web (Task 5).
- (e) Tooling: the Makefile's gitleaks and actionlint steps, the apacheconf lexer bound, two archtest precision fixes (Task 6).
- (f) Documents, then one push for the real runners (Task 7), and the final gates (Task 8).
No migration. No new error code. No helper protocol change. The helper version stays `1.2.0` (Ruling 3).

**Tech Stack:** Go 1.27.3, pgx/v5, golang.org/x/sys/windows, React 18 + Mantine + i18next, Vitest 5, Playwright, GNU make, Docker (gitleaks v8.30.1, shellcheck v0.11.0 images already pinned in the Makefile).

**Spec** (the plan argues from these sources; the executor reads them):
- `docs/superpowers/rulings/windows-iis.md`: `## Deferred to W7+` (line 2812: "Minors deferred during W6 (known debt)", 18 items, M2/M3/M5 among them); `## Deferred to W6+` (line 2296: "Minors deferred during W5", and the W3/W4 minors carried from W2-W4); `## Deferred to W5+` (line 1690) and `## Deferred to W4` (line 1310) for the original wording; `## Security review (W6)` residual risk 7 (line 2670); `## Final review fixes (W6)` (line 2678, M2/M3/M5 and the two parked residual minors at line 2704).
- W6 final review report with the M2/M3/M5 details and the deferred-minor triage table: `.superpowers/sdd/2026-10-28-windows-w6-rdp/final-review.md` (in the W6 worktree `/home/meren/projects/alice-secrets/.claude/worktrees/agent-a041c63d0a62daebc/`; read-only, untracked).
- `docs/superpowers/rulings/fixes-2026-10-26.md` "Found, not fixed" review M7 (the apacheconf lexer bound).
- The coordinator's brief of 2026-10-28 (items 1-6; the out-of-scope list under "Not in this batch" below).

**Decision:** R70 "Windows target: deferred minors batch (fixes batch 3)", appended to `docs/superpowers/specs/alice-v1/00-decisions.md` after R69 (the last entry) in R69's form. **Size:** S, 8 tasks, about one implementer day. **Migrations:** none.

## Global Constraints

- **Branch.** Worktree branch `fixes-3`, cut from `main` at `c95d3db2` or later. The first commit is this plan, copied unchanged (`docs: fixes batch 3 plan (R70)`). Take `main` in with `git merge main`, never rebase. The executor may push `fixes-3` (only that branch) so `windows.yml` runs on the real runners. It never pushes `main`, never opens a pull request and never changes repository settings. The coordinator merges and pushes.
- **Commits.**
  - `git -c user.name="Eren Altan" -c user.email="erenaltan@gmail.com" commit --only -m "<subject> (R70)" -m "Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>" -- <paths>`. Every subject ends with `(R70)`.
  - New files: `git add -- <path>` first. Never `git add -A` or `git add .`. Check `git status --short` before each commit.
  - Never touch `.claude/`, untracked files (the PDFs, `alice-helper` at the root, `.superpowers/`, `docs/security/reviews/independent-audit*`). Never rebase, squash or amend a pushed commit (`.gitleaksignore` pins commit hashes). Never commit key material; tests make keys at run time (`internal/testutil/pki`).
- **Real-Windows runs.** Budget: **4 runs** of `.github/workflows/windows.yml`. Every file under `.github/windows-paths.txt` starts a run on push: `cmd/alice-winhelper/**`, `internal/providers/windows/**`, `internal/providers/tlsverify/**`, `internal/providers/linuxssh/**`, `internal/providers/apacheconf/**`, `internal/testutil/pki/**`, `Makefile`, `docs/windows-host-preparation.md`, among others. So:
  - **No push before Task 7.** Tasks 1-6 commit locally. Task 7 makes **push 1** (run 1), which covers every runner-path change of the batch.
  - Task 8's fix wave makes **push 2** (run 2) only when a fix touches a watched path. Runs 3-4 are spares for a red run. A documents-only commit outside the watched paths may be pushed without spending a run.
  - Record every run (URL, commit, both legs, `windows-required`) in a runner-run table in the rulings file.
  - Fixture rules from W6 stay: fixture ports 45500-45519 for RDP tests, certificates named `alice-w6-*`, cleanup registered before the fixture, `TestRealRunnerIsClean` green.
- **Security guards that must stay green.** `TestNoCodeAcceptsAnyHostKey`; `TestImportRules`, `TestAllowed` (`internal/archtest`); `TestWindowsHelperLinksOnlyItsProtocol`; `TestWindowsWorkflowWatchesEveryDependency`; `TestWindowsWorkflowRequiresEveryRealTest`; `TestWindowsHelperBuildFlagsAgree`; `TestReleaseBinariesLinkNoTestPackages`; `make release-symcheck`; `make image-check`. Inventory never imports the Windows provider (archtest): a Windows code it needs is a local constant pinned by a test that imports `winproto`.
- **Protocol and version.** `winproto.Protocol = 1`, `MinProtocol = 1`, `Version = "1.2.0"` and every `*MinVersion` stay unchanged. No new subcommand, no new argument, no new JSON field.
- **Error codes.** None new. The deny-ACE refusal (Task 3) reuses `ALC-WIN-0023` `windows.rdp_key_acl_failed` through the existing `grant_key_read` / `key_acl` path.
- **Test IDs.** New: `WIN-65` (Task 3), `WIN-66` (Task 4, M3), `WIN-67` (Task 4, items 1-2), in `docs/superpowers/specs/alice-v1/06-quality.md` §24.7, whose heading gains "R70". Every other fix strengthens the test of an existing ID (named per task). `FX-08`'s row gains the apacheconf lexer test.
- **Coverage floors** (`coverage-floors.json`): never lower one. Current: windows 98.8, winhelper 97.2, winproto 100, helperproto 100, tlsverify 98.9, wintest 97.6, alice-fakewindows 93.4, inventory 89.2 (measured at W6's gate). No new Go package.
- **Locales.** EN and TR keep identical keys and placeholders, in `locales/common/{en,tr}.json` and `web/src/locales/{en,tr}.json` (`make i18n-check`). Turkish never puts a suffix on a placeholder that holds a path or a host.
- **e2e.** Project `alice-e2e-fixes3`, `ALICE_E2E_PORT=9984` (free at planning: `ss -ltn` shows no listener). Docker-based Go runs and Playwright never run at the same time, and neither runs while another `make ci` is active: check `pgrep -af 'playwright|make ci|go test'` first.
- **Per-task gate.** `make lint` plus the package tests the task names. `make ci` only in Task 8.
- **Verification commands.**
  - `go build ./... && go vet ./... && go vet -tags integration ./...`
  - `GOOS=windows GOARCH=amd64 go build ./cmd/alice-winhelper/ ./internal/providers/windows/... && GOOS=windows GOARCH=arm64 go build ./cmd/alice-winhelper/ && GOOS=windows go vet ./cmd/alice-winhelper/ ./internal/providers/windows/... && GOOS=windows go vet -tags alicetest ./cmd/alice-winhelper/ && GOOS=windows go test -tags alicetest -c -o /dev/null ./cmd/alice-winhelper/`
  - `go test -race -count=1 ./<pkgs>`; integration (Docker): `go test -race -count=1 -tags integration ./<pkgs> -run <name>`
  - Web: `cd web && npx vitest run <files> && npx tsc --noEmit && npm run lint`
  - `make lint`, `make test`, `make i18n-check`, `make matrix-check MATRIXCHECK_FLAGS=-strict`, `make docs-check`; final `make ci`.
  - A helper change: `make helper winhelper` before the e2e (the checksums Alice embeds; `bin/` is untracked).

## Review Focus

1. **A read-deny ACE for NETWORK SERVICE or Everyone on the RDP key ends the deployment at `grant_key_read` with `windows.rdp_key_acl_failed`, before any ACE is written and before the listener is touched.** A deny ACE of another trustee, or a deny without the read bits, does not. Tests: Task 3 `TestRealRDPKeyReadRefusesADeny` (real runner) and the existing fake path `TestRDPDeploy*` row "the first RDPKeyRead fails".
2. **A Windows server whose helper is below 1.2.0 never marks its stored RDP listener missing, and still marks a vanished binding missing.** Test: Task 4 `TestRDPHelperDowngradeKeepsTheListener` (both halves in one test).
3. **A cut Windows location (stored `list_truncated`) is never verified as "skipped" by the drift probe or by `FinishDeployment`'s CCS exception**, while an uncut unlinked CCS file still is. Tests: Task 4 `TestDriftProbeCarriesTheStoredWarnings`, `TestCCSSkipNeedsAnUncutFile`.
4. **No test proves less than before.** Tasks 1, 2 and 6 change tests and bounds: each states the property before and after; the reviewer checks they match. The apacheconf bound still fails a quadratic lexer (Task 6 Step 2 numbers).
5. **The RDP e-mails' reason line names the Remote Desktop listener, never "binding", in EN and TR, and a binding's e-mail is byte for byte unchanged.** Test: Task 4 `TestRDPDeploymentMail` (strengthened) and `TestRenderReasonVariant` (new, notify).

---

## Item table

`win.yml` = the change is on a path `windows.yml` watches (so it rides push 1). "Done" = found already fixed at `c95d3db2`; the rulings file records where.

| # | Item (one line) | Source | Decision | Task | Test | win.yml |
|---|---|---|---|---|---|---|
| C1 | `DriftProbes` builds a Windows location without its stored warnings (`drift_observe.go:151`) | coordinator 1; W5 deferred | fix | 4 | `TestDriftProbeCarriesTheStoredWarnings` (WIN-67) | n |
| C2 | W5-15 skip exception (`servers = '[]'`) ignores `list_truncated` | coordinator 2 | fix | 4 | `TestCCSSkipNeedsAnUncutFile` (WIN-67) | n |
| C3 | `make secrets-scan` scans 0 commits in a git worktree | coordinator 3; W5 found-not-fixed | fix | 6 | run in the worktree before/after (Step 1, Step 4) | y (Makefile) |
| C4 | Deploy picker shows raw `{{application}}` for a `win_foreign_app` binding | coordinator 4; W6 found-not-fixed | fix | 5 | `DeployDialog.test.tsx` "names the application of a foreign binding" | n |
| C5 | `TestLexHostileSizes` bound is `raceSlowdown` only; failed at 20.9 s on GitHub coverage | coordinator 5; fixes-2026-10-26 M7 | fix | 6 | FX-08 (lexer test added to the row) | y (apacheconf) |
| M2 | Shared `errors.windows.*` titles say "binding" in RDP e-mails and API problems | W6 final review M2 | fix (e-mails); decline API: one code, one title for every client; the web overrides | 4 | `TestRenderReasonVariant`, `TestRDPDeploymentMail` (WIN-62) | n |
| M3 | Helper downgraded below 1.2.0 marks a stored `win_rdp` location missing | W6 final review M3 | fix | 4 | `TestRDPHelperDowngradeKeepsTheListener` (WIN-66) | n |
| M5 | `iis-status` reads an absent value as the previous self-signed leaf without checking `Remote Desktop` | W6 final review M5 | fix | 1 | `TestRDPStatusAbsentValueChecksTheStore` (WIN-23) | y |
| R7 | "Can read" ignores deny ACEs and group membership | W6 security review residual 7 | fix the deny half (refuse before any change); decline groups: needs `AuthzAccessCheck` over a token Alice cannot build without TermService's logon | 3 | `TestRealRDPKeyReadRefusesADeny` (WIN-65) | y |
| W6-1 | tlsverify's RDP negotiation honours ctx only via the 10 s deadline | W6 Task 1 | fix | 1 | `TestProbeRDPNegotiationHonoursTheContext` (WIN-59) | y |
| W6-2 | Only `RDPFailure(2)` maps to `ErrRDPNoTLS` | W6 Task 1 | decline: both errors become `ErrProbeFailed`/`PROBE_FAILED`, so nothing differs; F22 measured no failure code | - | - | - |
| W6-3 | Take-back test's grant fails before appending (fake); real "read bits" vs "exact mask" must stay distinct | W6 Task 2 | fix the test; second half done (`RDPKeyRead` `rdp_windows.go:271`, revoke `:328`) | 1 | `TestRDPRevokeKeepsOtherACEs` new subtest (WIN-58) | y |
| W6-4a | One long comment line in `winhelper/write.go:48` (127 columns) | W6 Task 2 r3 | fix (wrap) | 1 | - (comment) | y |
| W6-4b | Take-back may report `rdp_key_acl_left` after a read error | W6 Task 2 r3 | decline: ruled fail-closed (unknown counts as left) | - | - | - |
| W6-5 | Emulator answers a CR without `RDP_NEG_REQ` with a failure | W6 Task 3 | fix as a `shortcut:` comment (Alice always sends `RDP_NEG_REQ`) | 2 | - (comment) | y |
| W6-6 | Emulator's stale pin stays nil when the certificate lookup errors | W6 Task 3 | fix | 2 | `TestModelRDPStalePinKeepsAFailure` | y |
| W6-7 | "Closed unanswered" test also passes on a read timeout | W6 Task 3 | fix (assert `io.EOF`) | 2 | `TestModelRDPSecurityLayer` (strengthened) | y |
| W6-8 | Re-adding an existing `My` certificate drops its NS read flag (emulator) | W6 Task 3 | fix (keep the flag of an existing entry) | 2 | `TestModelReAddKeepsTheNetworkServiceGrant` | y |
| W6-9a | Emulator's NS state is one bool per key | W6 Task 3 | decline: Ruling 23 allows it; the real KSP is covered by the runner tests | - | - | - |
| W6-9b | Emulator selects SSL with NLA off; F22 measured HYBRID on and off | W6 Task 3 | fix | 2 | `TestModelRDPSecurityLayer` (rows updated) | y |
| W6-10 | Migration test never proves 00037 Down's `deployments` EXISTS alone | W6 Task 5 | fix | 4 | `TestMigration00037Down` (strengthened) | n |
| W6-14 | `TestRDPDeployOutcomeTable` refusal rows do not assert nothing changed | W6 Task 6 | fix | 2 | `TestRDPDeployOutcomeTable` (strengthened) | y |
| W6-15 | `logSteps` builds a per-step map literal | W6 Task 6 | decline: style; behaviour and order identical | - | - | - |
| W6-16 | `TestConvertRDP`'s failed `rdp-dump` has no budget or undecodable rows | W6 Task 6 | fix | 2 | `TestConvertRDP` (2 subtests, WIN-56) | y |
| W6-17 | `TestWindowsRDPCrashTable` runs only with the previous certificate in `My` | W6 Task 6 | fix (also self-signed `previous_absent`) | 4 | `TestWindowsRDPCrashTable` (WIN-61) | n |
| W6-18 | `discover.go:51` appends to a slice it may alias | W6 Task 6 | fix (`slices.Concat`) | 2 | - (existing `TestDiscover*`) | y |
| W6-P1 | Admin guide's refusal sentences sit inside the deployment steps (~1536-1539) | W6 final review, parked | fix (move them under the steps) | 7 | `make docs-check` | n |
| W6-P2 | Real exportable-key test asserts only `KEY_UNUSABLE` | W6 final review, parked | fix (assert the message too) | 3 | the real exportable-key test (WIN-63) | y |
| W5-1 | `ValidCCSPath` accepts an empty segment (`C:\a\\b`) | W5 Task 1 | decline: Win32 collapses `\\` the same way on every call, so the path names one folder; refusing it would hide a working store | - | - | - |
| W5-2 | `CCSHost` maps a literal `*.example.com.pfx` | W5 Task 1 | decline: NTFS refuses `*` in a file name, so no listing carries one | - | - | - |
| W5-3 | A test uses an all-zero 8-digit operation instead of a UUID (temp-file case) | W5 Task 1 | fix | 1 | `winproto_test.go:690` row | y |
| W5-4 | Reparse-folder check of a restore runs before the gate | W5 Task 3 | decline: a time-of-check gap only an Administrator of the server can use, who can also repoint the CCS path itself (WN-19 boundary) | - | - | - |
| W5-5 | `SetCCSPassword` checks the password rule before the target type (422, not 409, on Nginx) | W5 Task 6 | fix | 4 | `TestSetCCSPasswordOnANonWindowsTargetIsAConflict` (WIN-47) | n |
| W5-6 | The database does not tie a `win_ccs` credential to a Windows target | W5 Task 6 | decline: accepted (W5 Ruling 1); a tie needs a migration this batch does not make | - | - | - |
| W5-7a | Emulator `ReadCCS` with a negative limit would panic | W5 Task 4 | decline: unreachable (callers pass constants) | - | - | - |
| W5-7b | Emulator cannot delete a CCS folder or file | W5 Task 4 | decline: no test needs it | - | - | - |
| W5-8a | Emulator serves a third party's `PutRawCCSFile` at once | W5 Task 5 | decline: deliberate (documented) | - | - | - |
| W5-8b | Emulator's `RestoreCCS` spelling rule is unmeasured | W5 Task 5 | decline: no Alice path depends on it; a measurement-only run is not worth a runner run | - | - | - |
| W5-8c | Emulator answers `not_a_pfx` for a certificates-only PFX (Windows: `key_missing`) | W5 Task 5 | decline: the emulator reads only `BuildPFX`'s form; both answers make the file not deployable | - | - | - |
| W5-9 | Cut `iis-dump` site list leaves a partial-site `win_ccs_unlinked` | W5 Task 8 | done (W5 final review I1) | - | - | - |
| W5-10 | `ccsDir` checks the leaf folder only; a parent junction is followed | W5 Task 5 | decline: same boundary as W5-4 | - | - | - |
| W5-11 | Real fixture adopts a pre-existing `ccs:45480` record on a dirty runner | W5 Task 5 | fix (fail loudly) | 3 | the CCS real fixture (`ccs_windows_test.go`) | y |
| W5-12a | Web: `win_ccs_enabled` text stays after the password is set | W5 Task 8 | fix | 5 | `TargetDetailPage.test.tsx` new case | n |
| W5-12b | Web: busy double submit of the password panel | W5 Task 8 | fix (a ref guard) | 5 | `CCSPasswordPanel` test new case | n |
| W5-12c | Web: the deploy dialog's summary follows the opening location's kind | W5 Task 8; W6 T7a | fix (one summary per kind present) | 5 | `DeployDialog.test.tsx` new case | n |
| W5-12d | Web: "Select all bindings of this certificate" also selects CCS files | W5 Task 8 | fix (the label names places when the group holds non-bindings) | 5 | `DeployDialog.test.tsx` new case | n |
| W3-1 | The heal step may clear a chain for a DER still present in another store | W3 | decline: benign, the next deployment rewrites it; a fix needs a per-store DER index | - | - | - |
| W3-2 | No test of the `maxImports` trim of adopted entries | W3 | fix (test) | 1 | `TestCleanupPlanTrimsAdoptedEntries` (WIN-34) | y |
| W3-3 | `cleanup.go` not split | W3 | decline: a refactor with no behaviour change | - | - | - |
| W3-4 | The provider's plan check accepts duplicate candidates | W3 | fix | 2 | `TestCheckPlan` row "a candidate listed twice" | y |
| W3-5 | `UpdateTarget` writes `certificate_cleanup` back on every edit | W3 | decline: harmless (the same value in the same UPDATE) | - | - | - |
| W3-6 | A skipped incident place queues one extra cleanup | W3 | decline: one extra dial; a fix needs incident state in the cleanup planner | - | - | - |
| W4-1 | The dependency test's `_test` strip would also strip a real directory ending in `_test` | W4 | fix | 6 | `TestTestedPackageDir` (archtest) | n |
| W4-2 | The Dockerfile subtest of `TestWindowsHelperBuildFlagsAgree` matches an exact indented string | W4 | fix (whitespace-tolerant regexp) | 6 | the subtest itself | n |
| W4-3 | No releasebuild row for a checksum file missing one `.exe` line | W4 | done (R66 FX-06 row "a Windows checksum file without its arm64 line") | - | - | - |
| W4-4 | The `refusalNames` table is keyed by subtest names | W4 | done (no such table at `c95d3db2`; the rows carry `names`) | - | - | - |
| W4-5 | No ShellCheck of the workflows' `run:` scripts | W4 | fix (actionlint runs the pinned shellcheck image; all four workflows are clean today) | 6 | `make actionlint` | y (Makefile) |
| W4-6 | `helperSetEntries` accepts extra or duplicate lines | W4 final review m-4 | done (R66 ruling 9, FX-06) | - | - | - |

---

### Task 1: `winhelper`, `tlsverify`, `winproto` tests (M5, W6-1, W6-3, W6-4a, W5-3, W3-2)

**Files:**
- Modify: `internal/providers/windows/winhelper/status.go:47-58` (M5); `internal/providers/windows/winhelper/write.go:48` (wrap to ≤120 columns); `internal/providers/tlsverify/tlsverify.go:494-500` (W6-1).
- Test: `internal/providers/windows/winhelper/status_test.go`, `rdp_test.go`, `cleanup_test.go`; `internal/providers/tlsverify/tlsverify_test.go`; `internal/providers/windows/winproto/winproto_test.go:690`.

**Interfaces:** Consumes the existing `rdpCurrent(ctx, h WriteHost, l RDPListener) (*winproto.StoreCertificate, int, error)` (`winhelper/rdp.go:25`). Produces nothing new.

- [ ] **Step 1: Write the failing tests.**
  - `TestRDPStatusAbsentValueChecksTheStore` (status_test.go): an RDP journal with `PreviousAbsent: true`, phase `restored`, the value absent. (a) `Remote Desktop` holds the journal's previous certificate (`PreviousSHA1`): `CurrentCertSHA256 == j.PreviousSHA256`. (b) `Remote Desktop` holds another self-signed certificate (Windows made a new one): `CurrentCertSHA256 == ""`. (c) It holds two: `""`.
  - `TestProbeRDPNegotiationHonoursTheContext` (tlsverify_test.go): a `127.0.0.1:0` listener that accepts and never writes; `TLSProber{RDP: true}` with the default handshake timeout; the context is cancelled after 50 ms; `Probe` returns an error that `errors.Is(err, ErrProbeFailed)` within 2 s (before the fix: 10 s).
  - `TestRDPRevokeKeepsOtherACEs`, new subtest "a grant that appended then failed is taken back": the fake's `grantErrAfter` fault (it appends the ACE, then fails; already used by `TestRDPMergedGrantIsNeverSilent`) with the pre-existing deny ACE and allow `0x1`; after the deployment fails at `grant_key_read`, the grant's ACE is gone and both pre-existing ACEs stay. This subtest passes before the fix: it is the missing coverage, so the RED step is "remove the take-back's `revokeKeyRead` call locally and see it fail", then restore.
  - `TestCleanupPlanTrimsAdoptedEntries` (cleanup_test.go): an import inventory of `maxImports-1` entries and a plan that adopts 2 more; the written inventory holds exactly `maxImports` entries, the oldest one is gone, both adopted ones are the last two. RED as above (comment out the trim locally).
  - `winproto_test.go:690`: the `.alice-00000000.tmp` row becomes `".alice-" + uuid.NewString() + ".tmp"`, so the row tests the name the helper really writes.
- [ ] **Step 2: Run to verify they fail.** `go test -race -count=1 -run 'TestRDPStatusAbsentValueChecksTheStore|TestProbeRDPNegotiationHonoursTheContext' ./internal/providers/windows/winhelper/ ./internal/providers/tlsverify/` Expected: FAIL ((b) names the previous leaf; the probe takes about 10 s).
- [ ] **Step 3: Implement.**
  - status.go: in the `j.RDP != nil` branch, when the value is absent (`l.CertSHA1 == ""`) and the journal's previous was absent, set `CurrentCertSHA256 = j.PreviousSHA256` only when `rdpCurrent` answers one certificate whose `SHA1` equals `j.PreviousSHA1`; else leave `""`. Comment: final review M5; `CurrentCertSHA256` is informational (no recovery decision reads it).
  - tlsverify.go: before `RDPNegotiate`, `stop := context.AfterFunc(hctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })`, `defer stop()`. Comment: the negotiation ends with the context, not only with the deadline (W6 Task 1 minor).
  - write.go:48: wrap the comment line.
- [ ] **Step 4: Run.** `go test -race -count=1 ./internal/providers/windows/winhelper/ ./internal/providers/tlsverify/ ./internal/providers/windows/winproto/ && make lint` plus the Windows build and vet line of Global Constraints. Expected: PASS.
- [ ] **Step 5: Commit** (one commit per item, in this order): `fix(winhelper): iis-status names the previous self-signed RDP certificate only while Remote Desktop still holds it (W6 final review M5) (R70)`; `fix(tlsverify): the RDP negotiation ends with the probe's context (R70)`; `test(winhelper): a grant that appended then failed is taken back; the import inventory's trim keeps the adopted entries (R70)`; `test(winproto): the temporary-file row uses a real operation id (R70)`; `style(winhelper): wrap a long comment line (R70)`.

---

### Task 2: The emulator `wintest` and the provider tests (W6-5, W6-6, W6-7, W6-8, W6-9b, W6-14, W6-16, W6-18, W3-4)

**Files:**
- Modify: `internal/providers/windows/wintest/tls.go:305-336` (W6-5 comment, W6-9b), `wintest/write.go:980-985` and `:109`, `:1017` (W6-6), `wintest/model.go:240-244` (W6-8); `internal/providers/windows/discover.go:48` (W6-18); `internal/providers/windows/cleanup.go:172-189` (W3-4).
- Test: `internal/providers/windows/wintest/write_test.go`, `wintest_test.go`; `internal/providers/windows/rdp_test.go`, `cleanup_test.go`.

**Interfaces:** No exported change. `wintest.Model` keeps its methods; a new unexported field `rdpPinSet bool` beside `rdpPinned`.

- [ ] **Step 1: Write the failing tests.**
  - W6-9b: in `TestModelRDPSecurityLayer` (write_test.go), the rows with NLA off and a request of SSL|HYBRID expect `RDPConfirm(RDPProtocolHybrid)` (F22: HYBRID with NLA on and off). A request of SSL only with NLA off still gets SSL; NLA on without HYBRID asked still gets `RDPFailure(5)`.
  - W6-7: the test's "closed unanswered" block asserts `errors.Is(err, io.EOF)` on the read, with a 5 s read deadline, so a timeout fails it.
  - W6-6: `TestModelRDPStalePinKeepsAFailure`: `ServeStaleRDP(true)`, no usable certificate for the listener (so `rdpCertLocked` errors), set the value twice (two certificates); a TLS handshake to the RDP listener fails (the original state), never serves the first set's certificate.
  - W6-8: `TestModelReAddKeepsTheNetworkServiceGrant`: `AddCertificate("My", …)` with a key, grant NS read (the model's grant path), `AddCertificate` the same certificate again; `KeyReadableByNetworkService("My", sha1)` stays true. A first add into `My` stays false; into `Remote Desktop` true.
  - W6-14: in `TestRDPDeployOutcomeTable`'s body, for every row whose `result` is `DeployNoChange`: `r.model.RDPThumbprint()` is what it was before the call, and the new leaf is not in `My` (the model's store lookup by `sha1Hex(nl.Cert.Raw)`).
  - W6-16: `TestConvertRDP`, two subtests modelled on "a failed rdp-dump keeps the bindings": an `rdp-dump` answer over its output budget, and one that does not decode (`Stdout: "not json"`); both keep the bindings and warn `list_truncated`, `locations_dropped`.
  - W3-4: `TestCheckPlan` (or the table that calls `checkPlan`), row "a candidate listed twice": two candidates with the same store (case-folded) and SHA-1; `checkPlan` answers the reason "a candidate listed twice".
- [ ] **Step 2: Run to verify they fail.** `go test -race -count=1 ./internal/providers/windows/wintest/ ./internal/providers/windows/ -run 'TestModelRDP|TestModelReAdd|TestRDPDeployOutcomeTable|TestConvertRDP|TestCheckPlan'` Expected: FAIL on W6-9b, W6-6, W6-8 and W3-4; W6-7, W6-14 and W6-16 pass (missing coverage): show each fails against a one-line local break of the code it guards, then restore.
- [ ] **Step 3: Implement.**
  - `rdpConfirmLocked`: `case requested&RDPProtocolHybrid != 0` (any NLA) answers HYBRID; then `case c.NLA` → `RDPFailure(5)`; then SSL; then `RDPFailure(1)`. Update the doc comment to F22's measurement.
  - tls.go's request parse: `// shortcut: a Connection Request without RDP_NEG_REQ is answered as requested=0 (a failure), where Windows answers a plain confirm; no Alice client sends one, model it when a test needs it.`
  - write.go: pin once per stale period: `if m.rdpStale && !m.rdpPinSet { m.rdpPinned, _ = m.rdpCertLocked(); m.rdpPinSet = true }`; clear `rdpPinSet` wherever `rdpPinned = nil` is set; tls.go:344 serves `rdpPinned` when `rdpPinSet`, and a nil pin then fails the handshake as `rdpCertLocked`'s error does.
  - model.go:243: keep the existing flag when the key already exists: set `nsRead` only for a new entry (or for `Remote Desktop`).
  - discover.go:48: `for _, w := range slices.Concat(moreWarns, rdpWarns) {`.
  - cleanup.go `checkPlan`: before appending, refuse a candidate whose `asciiLower(Store)+SHA1` was seen (the helper's own key form).
- [ ] **Step 4: Run.** `go test -race -count=1 ./internal/providers/windows/... ./cmd/alice-fakewindows/ && make lint` plus the Windows build and vet line. Expected: PASS; `wintest` and `windows` coverage at or above their floors.
- [ ] **Step 5: Commit** per item group: `fix(wintest): the RDP listener selects HYBRID whenever asked, as F22 measured; a stale pin keeps a failed lookup; a re-added certificate keeps its NETWORK SERVICE grant (R70)`; `test(wintest): the closed-unanswered case asserts EOF (R70)`; `fix(windows): checkPlan refuses a candidate listed twice; discovery's warnings no longer alias (R70)`; `test(windows): RDP refusals change nothing; a cut or undecodable rdp-dump keeps the bindings (R70)`.

---

### Task 3: `cmd/alice-winhelper` (Windows only; proven on the runner): R7 deny half, W6-P2, W5-11

**Files:**
- Modify: `cmd/alice-winhelper/rdp_windows.go:455-484` (`networkServiceCanRead`).
- Test: `cmd/alice-winhelper/rdp_dacl_windows_test.go` (or `rdp_windows_test.go` beside `TestRealRDPKeyReadForNetworkService:675`); the real exportable-key test (grep `KEY_UNUSABLE` in `rdp_windows_test.go`); the CCS real fixture (`ccs_windows_test.go`, the code that makes the `ccs:45480` http.sys record).

**Interfaces:** `RDPKeyRead(ctx, store, sha1Hex string) (bool, error)` keeps its signature. New unexported `var errKeyReadDenied = errors.New("alice-winhelper: NETWORK SERVICE or Everyone is denied read on the key")`. `winhelper/rdp.go:238` already turns any `RDPKeyRead` error into `grant_key_read` / `key_acl` with the listener untouched; `restore.go:160` already counts an error as "left". No change outside `cmd/alice-winhelper`.

- [ ] **Step 1: Write the tests.**
  - `TestRealRDPKeyReadRefusesADeny` (WIN-65): a fresh `alice-w6-deny` certificate with a non-exportable key in `My` (the existing real fixture helpers); add an explicit `ACCESS_DENIED_ACE` for NETWORK SERVICE with `GENERIC_READ` (the existing `explicitACE` with `windows.DENY_ACCESS`, then the existing write-back); `RDPKeyRead` answers `errKeyReadDenied`. Rows: the same deny for Everyone → error; a deny for another SID (Guests, `S-1-5-32-546`) → no error; a deny for NS with `WRITE_DAC` only → no error. Then an `rdp-deploy` of that certificate through the helper's real entry (as the existing real RDP deploy tests do): the outcome fails `grant_key_read` with class `key_acl`, `SSLCertificateSHA1Hash` is as found, and no ACE was added (the DACL bytes equal those before). Cleanup registered first.
  - W6-P2: the real exportable-key test also asserts the answer's message names the export policy (the `5f903ecb` refusal's text), so the older "no usable key" refusal no longer satisfies it.
  - W5-11: the CCS real fixture checks, before it creates `ccs:45480`, that no such http.sys record exists, and fails with "a ccs:45480 record exists before the test (dirty runner)" instead of adopting it.
- [ ] **Step 2: Cross-compile.** The Windows build and vet line of Global Constraints, `GOOS=windows golangci-lint run ./cmd/alice-winhelper/...`. Expected: PASS. The RED is run 1 (Task 7): without Step 3 the deny rows would fail; the implementer does not push to see it (Ruling 2).
- [ ] **Step 3: Implement** in `networkServiceCanRead`: in the same `eachACE` walk, an `ACCESS_DENIED_ACE_TYPE` (same layout as the allowed ACE) without `INHERIT_ONLY_ACE`, for NS or Everyone, whose mask has any bit of `GENERIC_READ|GENERIC_ALL|0x89` (the generic read bits and the key-read bits of `rdpGrantMask`, without `READ_CONTROL|SYNCHRONIZE`), makes the function return `false, errKeyReadDenied`. Doc comment: residual risk 7's deny half (R70); group membership is still not evaluated.
- [ ] **Step 4: Run** the cross-compile line again and `make lint`. Expected: PASS.
- [ ] **Step 5: Commit:** `fix(alice-winhelper): a read-deny ACE for NETWORK SERVICE or Everyone on the RDP key ends the deployment before any ACE or listener change (residual risk 7, WIN-65) (R70)`; `test(alice-winhelper): the exportable-key refusal is asserted by its message; the CCS fixture refuses a dirty runner's record (R70)`.

---

### Task 4: Inventory, notify, migrations test, engine crash table (C1, C2, M2, M3, W5-5, W6-10, W6-17)

**Files:**
- Modify: `internal/inventory/drift_observe.go:113-152` (C1); `internal/inventory/deployment_records.go:1090` (C2); `internal/inventory/notify.go:314-370` and `internal/inventory/drift.go:802-822` (M2: the param); `internal/notify/sender.go:219-264` (M2: the lookup); `locales/common/{en,tr}.json` (M2 texts); `internal/inventory/locations.go:589,655-662` and `internal/inventory/sshkeys.go:243` (M3); `internal/inventory/ccs_password.go:59-80` (W5-5).
- Test: `internal/inventory/windows_drift_integration_test.go`, `ccs_password_integration_test.go`, `windows_rdp_integration_test.go`; `internal/notify/` (the render test file that covers `windows_note`); `migrations/windows_rdp_integration_test.go`; `internal/jobs/deployjobs/windows_rdp_integration_test.go`.

**Interfaces:**
- Produces: queued deployment and drift e-mails of a `win_rdp` location carry the param `reason_variant=rdp`; `notify.Sender.Render` drops it and renders `reason` from `errors.<code>.title_rdp` when that key exists, else `errors.<code>.title` (unchanged rule). No other template or kind gets the param.
- `reconcileLocations(ctx, tx, t, scan, markMissing, keepRDP bool, now)`: `keepRDP` is true when the result carries the server warning `win_rdp_helper_outdated` (inventory constant `warnRDPHelperOutdated`, pinned to `winproto.WarnRDPHelperOutdated` by the M3 test).

- [ ] **Step 1: Write the failing tests.**
  - C1 `TestDriftProbeCarriesTheStoredWarnings` (windows_drift_integration_test.go): `newWinDriftFixture(t, true)`; `UPDATE certificate_locations SET warnings = ARRAY['list_truncated'] WHERE id = f.bound`; `DriftProbes(ctx, f.win)`: the probe of `f.bound` has `Request.Location.Warnings` containing `list_truncated`; a file location (`f.file` on the Nginx server) keeps `Warnings` nil, as `DeploymentMaterial` does.
  - C2 `TestCCSSkipNeedsAnUncutFile` (ccs_password_integration_test.go): `newCCSFixture`; `UPDATE … SET servers = '[]'` on `f.file`; a deployment recorded with a skipped success succeeds (control). A second deployment after `SET warnings = ARRAY['list_truncated']`: `FinishDeployment(…Verified: "skipped")` is refused (`ErrDeploymentState`, as `TestSkippedVerificationNeedsTheSetting`) and `RecordOutcome` leaves it `recovering`/`uncertain`.
  - M2 `TestRenderReasonVariant` (notify): `Render` with `error_reason=windows.binding_changed` and `reason_variant=rdp` renders the `title_rdp` text in EN and TR, the param never appears in the body; without the variant, the binding title; with the variant and a code that has no `title_rdp` (`windows.busy`), the plain title. `TestRDPDeploymentMail` (WIN-62) gains: a `deployment.failed` of the RDP listener with `windows.binding_changed` queues `reason_variant=rdp`; a binding's queued params are unchanged.
  - M3 `TestRDPHelperDowngradeKeepsTheListener` (windows_rdp_integration_test.go): `newRDPFixture`; reconcile iis-02 with no certificate and the warning `providers.Warning{Code: winproto.WarnRDPHelperOutdated}`: the listener `f.rdp` has no `missing_since`. Then a reconcile with no certificate and no warning: it is missing (control).
  - W5-5 `TestSetCCSPasswordOnANonWindowsTargetIsAConflict` (ccs_password_integration_test.go): an invalid password on the Nginx target `f.web` answers `ErrNotWindowsTarget`, not `ErrCCSPasswordInvalid`. If an API test asserts 422 for that case, it changes to 409.
  - W6-10 `TestMigration00037Down`: the RDP deployment row points at a `win_sslbinding` location of the same server (the FK does not check the kind); order: refused while both exist → delete the RDP location → still refused (the deployment alone) → delete the deployment → Down passes. RED: drop the `deployments` EXISTS clause of 00037's Down locally; the middle step must fail.
  - W6-17 `TestWindowsRDPCrashTable`: the table runs for `addRDPServer(…, false)` and `(…, true)` (self-signed previous, `previous_absent`), subtests named `my/<point>` and `self_signed/<point>`; if the self-signed run lists other crash points, add their rows (same expectations shape; `want` is the self-signed leaf).
- [ ] **Step 2: Run to verify they fail.** `go test -race -count=1 -tags integration ./internal/inventory/ -run 'TestDriftProbeCarriesTheStoredWarnings|TestCCSSkipNeedsAnUncutFile|TestRDPHelperDowngradeKeepsTheListener|TestSetCCSPasswordOnANonWindowsTargetIsAConflict|TestRDPDeploymentMail'` and `go test -race -count=1 ./internal/notify/ -run TestRenderReasonVariant`. Expected: FAIL each.
- [ ] **Step 3: Implement.**
  - C1: select `l.warnings` in `DriftProbes` and set `loc.Warnings` inside the `!kind.IsFile()` branch, with the same comment as `deployment_records.go:353`.
  - C2: the query becomes `SELECT skip_verify OR (kind = $2 AND servers = '[]'::jsonb AND NOT 'list_truncated' = ANY(warnings)) …`; comment "defence in depth: the provider already refuses the skip (W5 final review I1)".
  - M2: `windowsDeploymentMail` sets `out["reason_variant"] = "rdp"` for every `rdp` mail (both the RDP texts and the binding texts with `windows_note`); `windowsLocationMail` does the same for `o.kind == providers.LocationWinRDP`. `Sender.Render` deletes `reason_variant` from the rendered params and passes it to `reasonTitle(locale, code, variant string)`, which tries `errors.<code>.title_<variant>` first (only `[a-z]+` variants). Texts (`locales/common`), under `errors.windows.<code>`:
    - `binding_changed.title_rdp`: EN "The Remote Desktop listener no longer names the certificate Alice expected. Nothing was changed." TR "Uzak Masaüstü dinleyicisi artık Alice'in beklediği sertifikayı göstermiyor. Hiçbir şey değiştirilmedi."
    - `binding_not_found.title_rdp`: EN "The Windows server has no Remote Desktop listener RDP-Tcp any more. Nothing was changed." TR "Windows sunucusunda artık RDP-Tcp Uzak Masaüstü dinleyicisi yok. Hiçbir şey değiştirilmedi."
    - `location_unsupported.title_rdp`: EN "Alice does not deploy to this Remote Desktop listener now." TR "Alice şu an bu Uzak Masaüstü dinleyicisine dağıtım yapmaz."
    - `drift_not_repairable.title_rdp`: EN "Alice cannot repair the Remote Desktop listener: its certificate or key is gone from the server." TR "Alice Uzak Masaüstü dinleyicisini onaramaz: sertifikası ya da anahtarı sunucuda yok."
    (The first three are the web's `deployments.rdpErrors.windows.*.title`, verbatim.) If a catalogue test refuses a key other than title/cause/action under `errors.*`, put the four under `email.reason_rdp.<code>` instead and look them up there; record the choice.
  - M3: `const warnRDPHelperOutdated = "win_rdp_helper_outdated"` in locations.go (comment: `winproto.WarnRDPHelperOutdated`; inventory may not import the provider); the caller passes `keepRDP := slices.ContainsFunc(res.Warnings, func(w providers.Warning) bool { return w.Code == warnRDPHelperOutdated })`; the missing UPDATE gains `AND NOT ($4 AND kind = 'win_rdp')`. Doc comment: W6 final review M3; the listener keeps its last known state until a 1.2.0 scan; a deployment to it is refused `windows.helper_outdated` before anything is sent (`rdpReady`).
  - W5-5: move the `validCCSPassword` check into the transaction, after `ErrNotWindowsTarget` and before `ErrVersionMismatch` (the seal of an invalid password is discarded with the transaction; `pw.Zero()` stays deferred).
- [ ] **Step 4: Run.** `go test -race -count=1 ./internal/inventory/ ./internal/notify/ ./internal/api/ && go test -race -count=1 -tags integration ./internal/inventory/ ./internal/notify/ ./migrations/ -run 'Drift|CCS|RDP|Migration00037|Render|Mail' && go test -race -count=1 -tags integration ./internal/jobs/deployjobs/ -run 'TestWindowsRDP' && make lint i18n-check`. Expected: PASS.
- [ ] **Step 5: Commit** one per item: `fix(inventory): the drift probe of a Windows location carries its stored warnings, so a cut CCS file is never observed as skipped (W5 final review I1) (R70)`; `fix(inventory): the CCS skip exception also requires an uncut file (R70)`; `fix(notify,inventory): RDP e-mails name the Remote Desktop listener in their reason (W6 final review M2) (R70)`; `fix(inventory): a helper below 1.2.0 never marks the stored RDP listener missing (W6 final review M3) (R70)`; `fix(inventory): setting a CCS password on a server that is not Windows is a conflict before the password rule (R70)`; `test(migrations,deployjobs): 00037's Down refuses on an RDP deployment alone; the RDP crash table also runs with a self-signed previous certificate (R70)`.

---

### Task 5: Web (C4, W5-12a-d)

**Files:**
- Modify: `web/src/components/WebsitesPanel.tsx:224-236` (export the foreign-application text), `web/src/components/DeployDialog.tsx:325-327, 379-390, 476-483`, `web/src/components/CCSPasswordPanel.tsx:38-41`, `web/src/pages/TargetDetailPage.tsx:492`, `web/src/locales/{en,tr}.json`.
- Test: `web/src/components/DeployDialog.test.tsx`, `web/src/components/CCSPasswordPanel.test.tsx` (or the panel's cases in `TargetDetailPage.test.tsx`), `web/src/pages/TargetDetailPage.test.tsx`.

**Interfaces:** `export function foreignAppText(t: TFunction, l: CertificateLocation): string | null` in `WebsitesPanel.tsx`: the three current `win_foreign_app` branches (iis_unused, a named application via `APPLICATION_NAMES`, an unknown `app_id`), `null` for any other reason. `unsupportedText` and `WebsiteChoice` both call it.

- [ ] **Step 1: Write the failing tests.**
  - C4 "names the application of a foreign binding": a place with `supported: false`, `unsupported_reason: 'win_foreign_app'`, `details: { application: 'winrm', app_id: '{…}' }`; the dialog shows "This binding belongs to another application (WinRM). Alice does not change it." and no `{{`. Same for an unknown application (the `app_id` text).
  - W5-12c "one summary per kind": opened from a binding with a CCS file and the RDP listener ticked: `summaryWindows`, `summaryCCS`, `summaryRDP` each once, the opening kind first; opened from the listener with a binding ticked: `summaryRDP` then `summaryWindows`.
  - W5-12d: a group holding a binding and a CCS file shows "Select all places of this certificate"; a group of bindings only keeps "Select all bindings of this certificate".
  - W5-12b: two `submit` events fired in the same tick send `setCCSPassword` once (mock call count 1).
  - W5-12a: a target with the warning `win_ccs_enabled` and `ccs_password_set_at` set shows the `win_ccs_enabled_set` text; without the password, the current text.
- [ ] **Step 2: Run to verify they fail.** `cd web && npx vitest run src/components/DeployDialog.test.tsx src/pages/TargetDetailPage.test.tsx src/components/CCSPasswordPanel.test.tsx` Expected: FAIL.
- [ ] **Step 3: Implement.**
  - `WebsiteChoice`: `!place.supported ? (foreignAppText(t, place) ?? t(unsupportedReasonKey(place.unsupported_reason)))`.
  - Summary: the kinds present among the opening location and the ticked places (`rdp`, `ccs`, binding, else the Linux `summary`), each once, opening kind first; this replaces the single `!rdp && …` extra line.
  - Select-all label: `g.items.some((p) => p.kind !== 'win_sslbinding')` → `deploy.selectGroupPlaces` / `deploy.selectGroupPlacesNamed`; else the current keys. (Use the kind constant the file already uses for a binding.)
  - Panel: `const inFlight = useRef(false)` checked and set at the top of `submit`, cleared in a `finally`; `busy` stays for the button.
  - TargetDetailPage: `w.code === 'win_ccs_enabled' && target.ccs_password_set_at` → `warnings.win_ccs_enabled_set`.
  - Locales: `deploy.selectGroupPlaces` EN "Select all places of this certificate", TR "Bu sertifikanın tüm yerlerini seç"; `deploy.selectGroupPlacesNamed` EN "Select all places of this certificate: {{name}}", TR "Bu sertifikanın tüm yerlerini seç: {{name}}"; `warnings.win_ccs_enabled_set` EN "IIS on this server uses the Centralized Certificate Store. Alice holds its CCS password, lists its files and deploys to them.", TR "Bu sunucudaki IIS Merkezi Sertifika Deposu kullanıyor. Alice CCS parolasını saklıyor, deponun dosyalarını listeler ve onlara dağıtım yapar."
- [ ] **Step 4: Run.** The Step 2 command, then `npx tsc --noEmit && npm run lint` and `make i18n-check`. Expected: PASS.
- [ ] **Step 5: Commit:** `fix(web): the deploy dialog names a foreign binding's application, shows one summary per kind and names places when a group holds files (R70)`; `fix(web): the CCS panel sends one request per submit; the CCS warning says when the password is set (R70)`.

---

### Task 6: Tooling (C3, C5, W4-1, W4-2, W4-5)

**Files:**
- Modify: `Makefile:354-356` (`secrets-scan`), `Makefile:345-346` (`actionlint`), `Makefile` `SHELL_SCRIPTS` (add the wrapper); create `deploy/dev/shellcheck.sh`; `internal/providers/apacheconf/lexer_test.go:178`; `internal/archtest/windowsci_test.go:175-186, 590`.

**Interfaces:** `deploy/dev/shellcheck.sh` runs the pinned image on standard input: `exec docker run --rm -i "${SHELLCHECK_IMAGE:?}" "$@"` (the Makefile exports `SHELLCHECK_IMAGE`). archtest: `func testedPackageDir(line string) (string, bool)` (the `go list` line to its `alice/` directory, `false` for a generated `.test` main).

- [ ] **Step 1: Record the RED.**
  - C3: in this worktree, `make secrets-scan 2>&1 | tail -4` shows `fatal: not a git repository: …/.git/worktrees/<name>` and `0 commits scanned.` (measured at planning: 0 commits; with the common git directory mounted at its own path, 2054 commits scanned in 7.8 s, no leaks).
  - C5: `go test -race -covermode=atomic -count=1 -v -run TestLexHostileSizes ./internal/providers/apacheconf/` (planning, unloaded: `many_sections` 4.23 s of a 20 s bound; plain 0.08 s; GitHub's coverage job: 20.9 s).
  - W4-1: `TestTestedPackageDir` rows: `"alice/a_test [alice/a.test]"` → `a`; `"alice/b_test"` (a real package `b_test`, no bracket) → `b_test`; `"alice/c [alice/c.test]"` → `c`; `"alice/c.test"` → `false`. FAIL before (the function does not exist; the inline code strips `_test` from the second row).
  - W4-5: planning ran `actionlint -shellcheck=<wrapper>` on all four workflows: no finding; a scratch workflow with `echo $FOO` reported SC2086, so the wrapper is used.
- [ ] **Step 2: Implement.**
  - `secrets-scan`: add `-v "$(GIT_COMMON_DIR):$(GIT_COMMON_DIR):ro"` with `GIT_COMMON_DIR := $(shell git rev-parse --path-format=absolute --git-common-dir)` (in a plain checkout it is `$(CURDIR)/.git`, mounted twice, harmless), pass `--no-color`, and fail loudly: `out=$$(mktemp); trap 'rm -f "$$out"' EXIT; set -o pipefail; docker run … 2>&1 | tee "$$out"; grep -Eq '(^|[^0-9])[1-9][0-9]* commits scanned' "$$out" || { echo 'secrets-scan: gitleaks scanned no commits (a worktree whose git directory is not mounted?)' >&2; exit 1; }` (the `test-backup-cycle` pattern).
  - `actionlint`: `SHELLCHECK_IMAGE=$(SHELLCHECK_IMAGE) actionlint -shellcheck="$(CURDIR)/deploy/dev/shellcheck.sh" .github/workflows/*.yml`; the wrapper joins `SHELL_SCRIPTS`.
  - C5: `2*time.Second*raceSlowdown` → `2*time.Second*slowdown()` (the package's `slowdown_test.go`, R67). Property before and after: a hostile input is lexed within 2 s, ×10 under race, ×5 more under coverage; a quadratic `many sections` (MaxTokens/2 sections) would take minutes plain, far above every bound.
  - W4-1: the loop calls `testedPackageDir`; `_test` is stripped only when the bracket names `<pkg without _test>.test`.
  - W4-2: the Dockerfile assertion becomes `assert.Regexp(t, `RUN for arch in amd64 arm64; do \\\n\s+CGO_ENABLED=0 GOOS=windows`, text, …)`.
- [ ] **Step 3: Run.** `make secrets-scan` (in the worktree: N > 0 commits, exit 0), `make actionlint shellcheck`, `go test -race -count=1 ./internal/providers/apacheconf/ ./internal/archtest/ && go test -race -covermode=atomic -count=1 ./internal/providers/apacheconf/ && make lint`. Expected: PASS; record the scanned-commit count and the actionlint time.
- [ ] **Step 4: Prove the loud failure.** Run the `secrets-scan` recipe once with the common-dir mount removed (a local edit, not committed): it exits 1 with the message. Restore.
- [ ] **Step 5: Commit:** `fix(make): secrets-scan mounts the common git directory, so a worktree's history is scanned, and fails when no commit was scanned (R70)`; `build(make): actionlint checks the workflows' run scripts with the pinned shellcheck (R70)`; `test(apacheconf): the lexer's hostile-size bound takes the coverage factor (fixes-2026-10-26 M7) (R70)`; `test(archtest): the tested-package directory strips _test only from an external test package; the Dockerfile loop is matched by shape (R70)`.

---

### Task 7: Decision R70, test IDs, guides, changelog; push 1

**Files:**
- `docs/superpowers/specs/alice-v1/00-decisions.md`: R70 after R69, in R69's form: the coordinator's assignment of 2026-10-28 ("finish the Windows deferred minors before W7"); plan and rulings paths; no migration, no error code, no protocol or version change; the behaviour changes (Owner to confirm 1-5); tests `WIN-65`..`WIN-67`.
- `docs/superpowers/specs/alice-v1/06-quality.md`: §24.7 heading and the §24 intro line gain "fixes batch 3, R70: WIN-65..WIN-67"; rows:

| ID | Case | Expected |
|---|---|---|
| WIN-65 | An RDP deployment to a certificate whose key has a read-deny ACE for NETWORK SERVICE or Everyone | Ends at `grant_key_read` with `windows.rdp_key_acl_failed`; no ACE added, the listener's value as found |
| WIN-66 | A scan of a Windows server whose helper is below 1.2.0, with a stored RDP listener | The listener is not marked missing; a binding the scan no longer lists is |
| WIN-67 | A Windows location whose stored warnings carry `list_truncated` (a cut CCS file with no servers) | The drift probe carries the warnings (never observed as skipped); a skipped deployment success is refused; an uncut unlinked file still skips |

- `test/matrix/traceability.json`: rows `WIN-65` (`cmd/alice-winhelper:TestRealRDPKeyReadRefusesADeny`), `WIN-66` (`internal/inventory:TestRDPHelperDowngradeKeepsTheListener`), `WIN-67` (`internal/inventory:TestDriftProbeCarriesTheStoredWarnings`, `internal/inventory:TestCCSSkipNeedsAnUncutFile`); `FX-08` gains `internal/providers/apacheconf:TestLexHostileSizes`; `WIN-62` gains `internal/notify:TestRenderReasonVariant`; `WIN-59` gains `internal/providers/tlsverify:TestProbeRDPNegotiationHonoursTheContext`; `WIN-34` gains `internal/providers/windows/winhelper:TestCleanupPlanTrimsAdoptedEntries`; `WIN-58` gains `internal/providers/windows/winhelper:TestRDPRevokeKeepsOtherACEs`. Real-runner IDs follow WIN-63's form (the `windows.yml` required list: `TestWindowsWorkflowRequiresEveryRealTest` tells whether the new real test must be named there; add it if so). `docs/security/traceability.md`: `go run ./tools/matrixcheck -update`.
- `docs/admin-guide.md`: W6-P1 (the RDP refusal sentences move out of the numbered deployment steps, below them); the RDP key paragraph: a read-deny for NETWORK SERVICE or Everyone stops the deployment before any change (WIN-65); "Helper versions": after a helper downgrade below 1.2.0 the RDP listener keeps its last scan until a 1.2.0 helper scans again (M3).
- `docs/windows-host-preparation.md`: the RDP key sentence (deny ACE). (A watched path: it rides push 1.)
- `docs/troubleshooting.md` `ALC-WIN-0023`: one cause sentence for the deny ACE.
- `CHANGELOG.md`: "Unreleased — Fixes batch 3 (R70)": **Changed**: the deny-ACE refusal; a helper below 1.2.0 keeps the RDP listener; a CCS password on a non-Windows server is 409. **Fixed**: the RDP e-mails' reason wording; the drift view of a cut CCS file; the deploy picker's foreign-application text; the deploy dialog's summaries and select-all label; the CCS warning after the password is set.
- `docs/superpowers/rulings/windows-iis.md` `## Deferred to W7+`: one line "Minors and residual 7 settled in R70 (`docs/superpowers/rulings/fixes-2026-10-28.md`)"; `fixes-2026-10-26.md` "Found, not fixed" M7: "fixed in R70".

- [ ] **Step 1: Write** the entries. Run `go test ./tools/matrixcheck/ && make matrix-check MATRIXCHECK_FLAGS=-strict docs-check i18n-check`. Expected: PASS, 0 gaps, 0 pending.
- [ ] **Step 2: Commit:** `docs: decision R70, test IDs WIN-65..WIN-67, the guides and the changelog of fixes batch 3 (R70)`.
- [ ] **Step 3: Push 1.** `pgrep`-check nothing heavy runs, `git push -u origin fixes-3`. Watch `windows.yml` (run 1). Expected: both legs and `windows-required` green. A red leg: capture the failing test's output, fix in its own commit, push (run 2, then the spares); never push a guess.

---

### Task 8: Final gates, final review, rulings file

**Files:** Create `docs/superpowers/rulings/fixes-2026-10-28.md` in `fixes-2026-10-26.md`'s form: Coordinator rulings, Rulings (below, plus execution rulings with reason and cost if wrong), Final review fixes, Owner to confirm, Deferred (every declined row of the item table with its one-line reason), Found not fixed, Gate evidence (with the runner-run table and the Task 6 measurements).

- [ ] **Step 1: Full gate.** `pgrep -af 'playwright|make ci|go test'` answers nothing; `make helper winhelper`; `E2E_PROJECT=alice-e2e-fixes3 ALICE_E2E_PORT=9984 make ci`. Expected: exit 0, including `secrets-scan` with N > 0 commits in the worktree (C3's proof in the real gate). Record e2e totals, the coverage floors met (the eight of Global Constraints) and the matrix totals. If staged: the R67 staging list, then `E2E_PROJECT=alice-e2e-fixes3 make e2e-down`.
- [ ] **Step 2: Final review.** `superpowers:requesting-code-review` over `main..fixes-3` by a fresh reviewer given the code and the item table, not the conclusions. Fix every Critical and Important in its own commit; a fix on a watched path is push 2. List declined Minors with reasons.
- [ ] **Step 3: Write** the rulings file. `make docs-check`. Expected: PASS.
- [ ] **Step 4: Commit:** `docs(rulings): fixes batch 3 rulings, owner items and gate evidence (R70)` (not a watched path: no run).

---

## Rulings (each goes into `docs/superpowers/rulings/fixes-2026-10-28.md`)

1. **One decision, R70.** No migration, no error code, no protocol change. Test IDs `WIN-65`..`WIN-67`; the other fixes strengthen existing IDs. Cost if wrong: none functional.
2. **The runner budget is spent in one push for the whole batch.** Every watched-path change (Tasks 1, 2, 3, 6 and the host guide) rides push 1; the implementer never pushes to see a RED. Cost if wrong: a red run 1 needs run 2.
3. **The helper stays `1.2.0`.** The batch changes no protocol shape; no release tag carries 1.2.0 yet (W4/W5 owner items still open), so two builds never meet in the field under one version. Cost if wrong: a server with a W6 build answers a deny-ACE key by the old path (deployment, verify failure, rollback). **Owner to confirm.**
4. **Residual 7: the deny half is refused; group membership is not evaluated.** A deny ACE wins over Alice's allow ACE (explicit deny comes first in a canonical DACL), so the old path always ended in a verification failure and a rollback after Remote Desktop briefly named an unusable certificate; now nothing changes. Groups need `AuthzAccessCheck` with TermService's token, out of proportion. Cost if wrong: a deny ACE an administrator wanted ignored now blocks the deployment (`rdp_key_acl_failed` names the key ACL). **Owner to confirm.**
5. **M3: a helper below 1.2.0 keeps the stored RDP listener.** Its row shows the last 1.2.0 scan until a 1.2.0 helper scans again; a deployment to it is refused `helper_outdated` before anything is sent. `locations_dropped` is not used (it would stop missing-marking for every binding on every 1.1.0 server). Cost if wrong: a listener removed while the helper was downgraded stays listed until the next 1.2.0 scan. **Owner to confirm.**
6. **M2: RDP e-mails get listener titles; API problems keep one title per code.** The web already overrides; an API client reads the code. Cost if wrong: an API problem of an RDP deployment still says "binding".
7. **M5: `iis-status` names the previous self-signed leaf only while `Remote Desktop` holds exactly it.** `CurrentCertSHA256` is informational. Cost if wrong: none to outcomes.
8. **C2's guard is defence in depth.** The provider already refuses the skip for a cut file. Cost if wrong: none.
9. **W5-5: a non-Windows target answers 409 before the password rule.** Cost if wrong: a client that relied on 422 for an Nginx target sees 409. **Owner to confirm.**
10. **The emulator follows F22: HYBRID whenever asked.** Cost if wrong: none to Alice (TLS follows either way).
11. **`make secrets-scan` mounts the common git directory and fails on 0 commits.** Cost if wrong: a checkout layout gitleaks cannot read now fails the gate instead of passing silently, which is the intent.
12. **The apacheconf lexer bound takes `slowdown()`.** Cost if wrong: a 5× slower lexer passes under coverage; plain `-race` (20 s) and the quadratic case still fail.

## Owner to confirm

1. Ruling 4 (WIN-65): a read-deny ACE for NETWORK SERVICE or Everyone on the RDP certificate's key now stops the deployment before any change, with `windows.rdp_key_acl_failed`. Group membership (a key readable only through Users) is still not evaluated: Alice adds its own ACE there, revoked on rollback (WN-23 as accepted).
2. Ruling 5 (WIN-66): after a helper downgrade below 1.2.0, the RDP listener stays listed with its last known state instead of going missing.
3. Ruling 3: the helper version stays 1.2.0 for this batch's helper changes.
4. Ruling 9: setting a CCS password on a server that is not Windows answers 409 (it was 422 when the password also broke the rule).
5. Wording an administrator sees: RDP e-mails name the Remote Desktop listener in their reason line (Ruling 6); the deploy dialog shows one summary per kind and "Select all places of this certificate" for a group with files; the CCS warning reads "Alice holds its CCS password" once it is set.

## Not in this batch (the boundary; unchanged, still deferred)

- Class B features: a manual "roll back this deployment" action; deploying to a binding whose only problem is its key; IDN U-label host headers; a third party's intermediate added after Alice's commit (`unchanged` + `win.chain_differs`); removing or clearing the CCS password; a CCS password Alice's rule refuses; a `merge_group` trigger; `ci.yml` checks required (owner step); a Windows gate in `make release-gates`; removing intermediates from `CA`; a cleanup history page; the emulator's slow-host fault (and the abandoned-call marking it needs).
- Class C phases: the CCS farm layout; Alice creating a CCS file; RD Gateway, Web Access, Connection Broker and RemoteApp certificates; listeners other than `RDP-Tcp`; a real ARM64 leg; Windows Server 2019 on a runner; W7's WinRM transport.
- The non-Windows deferred lists of `fixes-2026-10-25.md` and `fixes-2026-10-26.md` (except M7, fixed here as C5).
- The W6 owner items (the manual matrix, Authenticode, the first release tag, the helper update procedure) and W6 residual risks 1-6, 8, 9 as accepted.

## Files touched (merge order and parallel safety)

| Task | Files |
|---|---|
| 1 | `internal/providers/windows/winhelper/{status,write}.go`, `…/winhelper/{status,rdp,cleanup}_test.go`, `internal/providers/tlsverify/{tlsverify,tlsverify_test}.go`, `internal/providers/windows/winproto/winproto_test.go` |
| 2 | `internal/providers/windows/wintest/{tls,write,model}.go`, `…/wintest/{write,wintest}_test.go`, `internal/providers/windows/{discover,cleanup}.go`, `…/windows/{rdp,cleanup}_test.go` |
| 3 | `cmd/alice-winhelper/rdp_windows.go`, `cmd/alice-winhelper/{rdp_dacl,rdp,ccs}_windows_test.go` |
| 4 | `internal/inventory/{drift_observe,deployment_records,notify,drift,locations,sshkeys,ccs_password}.go`, `internal/notify/sender.go`, `locales/common/{en,tr}.json`, tests `internal/inventory/{windows_drift,ccs_password,windows_rdp}_integration_test.go`, `internal/notify/<render test>`, `migrations/windows_rdp_integration_test.go`, `internal/jobs/deployjobs/windows_rdp_integration_test.go` |
| 5 | `web/src/components/{WebsitesPanel,DeployDialog,CCSPasswordPanel}.tsx`, `web/src/pages/TargetDetailPage.tsx`, `web/src/locales/{en,tr}.json`, their tests |
| 6 | `Makefile`, `deploy/dev/shellcheck.sh` (new), `internal/providers/apacheconf/lexer_test.go`, `internal/archtest/windowsci_test.go` |
| 7 | `docs/superpowers/specs/alice-v1/{00-decisions,06-quality}.md`, `test/matrix/traceability.json`, `docs/security/traceability.md`, `docs/{admin-guide,windows-host-preparation,troubleshooting}.md`, `CHANGELOG.md`, `docs/superpowers/rulings/{windows-iis,fixes-2026-10-26}.md` |
| 8 | `docs/superpowers/rulings/fixes-2026-10-28.md` (new) |

Tasks 1-6 touch disjoint files and may run in parallel; Task 7 waits for 1-6; Task 8 for 7.
