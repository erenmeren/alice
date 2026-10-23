# Windows Servers, Phase W4 (Real-Windows CI Job and Release) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every change under the Windows paths must pass one stable check before it can merge: `windows-required`, backed by the real-Windows legs on `windows-2022` and `windows-2025`. The check also runs nightly and, through `release.yml`, on every release tag. `alice-helper.exe` 1.0.0 for amd64 and arm64 ships in the release package's `helper/` folder and in its signed `SHA256SUMS`, and the bytes are the same as the binary the runners tested. The customer documents, the security report, the test IDs and the release checklist describe the finished Windows target, including the owner's manual matrix as an owner step. Configuring the repository to require the check is written down for the owner and is not done by the executor.

**Architecture:** No product behaviour changes apart from the helper's version string and one DTO field. `windows.yml` loses its trigger path filters. A cheap Linux `changes` job decides from a single watched-path list whether the Windows legs run. A Linux `linux-build` job builds the helper with `make winhelper`, and the Windows legs compare their own build with it byte for byte. An always-running `windows-required` job turns the legs' results into the one required check: success when nothing Windows changed, failure on any failed, cancelled or missing leg. A shell script holds the decision logic, and Go tests check it, so the logic is not hidden in YAML. Further Go tests keep the watched list, the required real-test list and the helper build flags complete. The release stage takes the Windows helpers next to the Linux ones (`tools/releasebuild`), `make release` builds them, and `release.yml` calls `windows.yml` before staging. No migration, no new error code.

**Tech Stack:** Go 1.27.3, `go.yaml.in/yaml/v3` (tests only), bash, PowerShell 7 on the runners, GitHub Actions (`windows-2022`, `windows-2025`, `ubuntu-latest`, `workflow_call`), `tools/releasebuild`, `tools/matrixcheck`, React 18 + Mantine + Vitest (one panel).

**Spec:** `docs/superpowers/specs/2026-10-21-windows-iis-target-design.md`. This phase is §13 "Phase W4" and its acceptance. It also draws on §7 (release line), §12 items 4-6, §14.1 (runner facts), §15 Q2 (no Authenticode yet), §16-§18 (W1-W3 as built). Every W1-W3 item marked for W4 is in `docs/superpowers/rulings/windows-iis.md`: W1 Rulings 16-17 and owner item M5, W2 owner items, W3 "Owner items (W3)" and "## Deferred to W4", and the W3 execution ruling on the ACME bindings panel. Each one is settled in Ruling 20. The plans used as format models are `docs/superpowers/plans/2026-10-23-windows-w3-drift-and-cleanup.md` and `docs/superpowers/plans/2026-10-22-windows-w2-deployment-verification-rollback.md`. The owner approved W0-W4 with the §15 defaults on 2026-10-22.

**Scope:** Design §13 W4 only: the required, nightly and path-decided real-Windows check; the Windows helper in the release package and `SHA256SUMS`; helper `1.0.0`; the documents, test IDs and matrix; the owner's manual matrix as an owner step; and the W3 items carried here (Ruling 20). Not in scope: CCS, RDP deployment, WinRM transport (W5-W7, on demand), Authenticode (§15 Q2), and changes to repository settings (the owner's, Ruling 15).

**Decision:** R63 "Windows server target, phase W4: real-Windows CI and release" (R62 is the last entry of `00-decisions.md`). **Size:** M, 7 tasks. **Migration:** none.

## Before you start: what W4 must measure on a runner

Two facts are new. Task 3's first runner runs check them before the code that depends on them is called done. Record each verdict as a ruling under the "W4 (R63)" heading of `docs/superpowers/rulings/windows-iis.md`.

| Fact | What W4 relies on | If it is wrong | Tasks |
|---|---|---|---|
| F13 | `alice-helper.exe` built on the Windows runner (`go build` with the flags of `make winhelper`, same Go from `go.mod`) is byte-identical to the one `make winhelper` builds on `ubuntu-latest`, for amd64 and arm64. The release is built on Linux, so this proves the runners test the shipped bytes. | The comparison step reports a `::warning::` with both hashes instead of failing. Record the verdict and the differing hashes. It becomes an owner item ("the tested binary is not the shipped one"), and the release checklist row 1.46 says the release engineer compares the CI stage's helper hashes with the local build (as row 3.4 already does for Linux). | 3 |
| F14 | GitHub reports a job skipped by its `if:` as `skipped` to a dependent job with `if: always()`. The `windows-required` job then runs and its decision (Ruling 4) passes on a run whose `changes` answers `false`. Its context name is exactly `windows-required`. | Make `helper` and `linux-build` always run and exit early with success when `changes` answers `false` (a step-level `if:`), and adjust the gate decision. | 3 |

## Global Constraints

- **Branch.** Worktree branch `windows-w4`, cut from `main` at `2ec69c8c` or later. Never switch branches inside a task. Take `main` in with `git merge main`, never rebase. The executor may push `windows-w4` (only that branch) so `windows.yml` runs on the real runners. It never pushes `main`, never opens a pull request and never changes repository settings (Ruling 15). The coordinator merges to `main` and pushes.
- **Commits.**
  - `git -c user.name="Eren Altan" -c user.email="erenaltan@gmail.com" commit --only -m "<subject> (R63)" -m "Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>" -- <paths>`. Every subject ends with `(R63)`.
  - New files: run `git add -- <path>` first. Never `git add -A` or `git add .`. Check `git status --short` before each commit.
  - Never touch `.claude/`, the untracked PDFs, `alice-helper` (an untracked binary at the root), `docs/security/reviews/independent-audit*` or the other untracked review files.
  - `.gitleaksignore` is pinned to commit hashes, so never rebase, squash or amend a pushed commit. Never commit key material.
- **Security guards that must stay green.**
  - `TestNoCodeAcceptsAnyHostKey`, `tools/pincheck` (every `uses:` pinned by SHA with a `# vX` comment; a local `./.github/workflows/windows.yml` call passes), `TestImportRules`, `TestAllowed`.
  - `TestWindowsHelperLinksOnlyItsProtocol` (W4 adds no dependency to the helper), `TestReleaseBinariesLinkNoTestPackages`, `TestNoWindowsReservedFileNames`, `make release-symcheck`, `make image-check`.
- **Protocol.** `winproto.Protocol = 1` and `MinProtocol = 1` stay. `winproto.Version = "1.0.0"`. `WriteMinVersion = "0.2.0"` and `CleanupMinVersion = "0.3.0"` stay. No subcommand, shape or behaviour changes in `winproto`, `winhelper`, `wintest` or `cmd/alice-winhelper` apart from the version string.
- **Error codes:** none new (the last is `ALC-WIN-0014`). **Test IDs:** `WIN-39`..`WIN-45`. **STRIDE:** `WN-18` new, `WN-6` amended. **Migration:** none; the next free number stays `00033`.
- **Coverage floors** (`coverage-floors.json`; never lower one): unchanged. W4 adds no new Go package.
- **Locales.** No new key unless Task 5 needs one. EN and TR stay identical (`make i18n-check`).
- **Real-Windows runs.** The phase has a budget of **6 runs** of `windows.yml`. Every run counts, including one whose legs were skipped. Record each in a runner-run table in the rulings file. W4 adds no real fixture (Ruling 18). Should one become necessary, it uses ports **45321-45329**, names starting `alice-w4-`, cleanup registered before the fixture is made, and an extension of `TestRealRunnerIsClean` (W2 Ruling 22).
- **e2e.** `E2E_PROJECT=alice-e2e-w4 ALICE_E2E_PORT=9977 make e2e-up e2e; E2E_PROJECT=alice-e2e-w4 make e2e-down`. Docker-based Go runs and Playwright never run at the same time, and neither runs while another `make ci` on the machine is active.
- **Verification commands.**
  - `go build ./... && go vet ./... && go vet -tags integration ./...`
  - `GOOS=windows GOARCH=amd64 go build ./cmd/alice-winhelper/ ./internal/providers/windows/... && GOOS=windows GOARCH=arm64 go build ./cmd/alice-winhelper/ && GOOS=windows go vet ./cmd/alice-winhelper/ ./internal/providers/windows/... && GOOS=windows go vet -tags alicetest ./cmd/alice-winhelper/`
  - `go test -race -count=1 ./<pkgs>`; `actionlint .github/workflows/*.yml`; `go run ./tools/pincheck`
  - `make lint`, `make test`, `make i18n-check`, `make matrix-check MATRIXCHECK_FLAGS=-strict`, `make docs-check`; final `make coverage` and `make ci`
  - web: `cd web && npx vitest run <files> && npx tsc --noEmit && npm run lint`
  - Any helper change regenerates the checksums: `make helper winhelper`.

## Rulings (where the spec is silent; each goes into `docs/superpowers/rulings/windows-iis.md` under a new "W4 (R63)" heading for the owner to confirm)

1. **Decision R63: no migration, no error code.**
   - Test IDs are `WIN-39`..`WIN-45`. STRIDE adds `WN-18` (a tampered helper in the package or on its way to the server) and amends `WN-6`.
   - W4 changes no product behaviour except the helper's version string (Ruling 2) and `location_kind` on the ACME binding (Ruling 17).
2. **Helper 1.0.0, protocol 1, minimums unchanged.**
   - `1.0.0` marks the first released helper (W1 Ruling 2: nothing was released before). It adds no subcommand.
   - So a 0.3.0 helper keeps every feature under Alice 1.0, and a 1.0.0 helper works under a W3 Alice (`VersionAtLeast("1.0.0", "0.3.0")`).
   - `WriteMinVersion` 0.2.0 and `CleanupMinVersion` 0.3.0 stay, so no server must be updated at once.
   - The guidance "update the helpers first, then Alice" stays.
3. **`internal/api/nul.go`: nothing to do in W4.**
   - W1 renamed it (design §16 "Tests" row; W1 Ruling 17 amended).
   - `windows.yml` uses a plain checkout, and `TestNoWindowsReservedFileNames` keeps any reserved name out of the tree.
   - No sparse checkout is added.
4. **One required check, `windows-required`.**
   - A job with that id and that `name:` runs on every trigger with `if: always()` and `needs: [changes, linux-build, helper]`. It passes exactly when one of these holds:
     - `changes` succeeded, answered `windows=false`, and both `linux-build` and `helper` were `skipped`; or
     - `changes` answered `windows=true` and both `linux-build` and `helper` (every matrix leg) succeeded.
   - Every other combination fails it: a failed, cancelled or skipped leg on a Windows change, and a failed `changes`.
   - Why one gate job:
     - A workflow skipped by trigger `paths:` leaves a required check pending forever.
     - The matrix legs' names (`helper (windows-2022)`) change when GitHub retires an image, which would silently drop a required name.
   - The decision lives in `deploy/dev/windows-ci.sh gate`, so `TestWindowsGateDecision` can test it.
5. **Change detection without trigger filters.**
   - `push` (every branch) and `pull_request` carry no `paths:`.
   - The `changes` job (ubuntu, `fetch-depth: 0`) answers `windows=true` when any of these holds:
     - the event is `schedule` or `workflow_dispatch`, or the `workflow_call` input `all` is true;
     - `git diff --name-only <base> HEAD` names a path that `.github/windows-paths.txt` matches, judged by `deploy/dev/windows-ci.sh changed`.
   - The base:
     - a pull request: `github.event.pull_request.base.sha`;
     - a push: `github.event.before`;
     - when that is empty, all zeros or not a commit in the clone (a new branch, a force push): `git merge-base origin/main HEAD`;
     - when even that fails: answer `true`. An unknown base runs the legs, it never skips them.
   - Every `${{ }}` value reaches the scripts through `env:` and never inside a `run:` text (script injection).
   - No third-party paths-filter action: one fewer pinned dependency, and the decision stays testable.
6. **The watched list is complete by test.**
   - `.github/windows-paths.txt` holds one entry per line, `#` comments allowed. An entry is one of three forms:
     - `dir/**`: everything below `dir`;
     - `dir/*`: the files directly in `dir`;
     - an exact file path.
   - `TestWindowsWorkflowWatchesEveryDependency` takes every `alice/...` package from `GOOS=windows go list -deps -test` of `./cmd/alice-winhelper/... ./internal/providers/windows/...`, with tags `""` and `alicetest`. It requires each package's directory to be matched.
   - The same test requires these fixed entries, and requires every entry to match at least one tracked file (no stale entry): `.github/workflows/windows.yml`, `.github/windows-paths.txt`, `deploy/dev/windows-ci.sh`, `go.mod`, `go.sum`, `Makefile` (the `winhelper` flags, Ruling 10), and `docs/windows-host-preparation.md` (read by `internal/providers/windows:TestPreparationGuideQuotesTheMatchBlock`).
   - Today's trigger filter misses `internal/providers/providertest`, `apacheconf`, `haproxyconf`, `nginx/nginxconf`, `internal/secrets`, the guide and the `Makefile`. This test finds that gap and keeps it closed.
7. **Every real test is required by name.**
   - `TestWindowsWorkflowRequiresEveryRealTest` requires the `$required` list in `windows.yml` to equal exactly the set of `TestReal*` and `TestFidelity*` functions in `cmd/alice-winhelper/*_test.go` and `internal/providers/windows/**/*_test.go`.
   - That means no missing name and no stale one. The rule "a skipped real test is a failure" stays.
8. **Concurrency.**
   - Group: `windows-${{ github.event_name == 'schedule' && 'nightly' || github.ref }}`. A literal prefix, not `github.workflow`: a called workflow sees the caller's name, and the shared group would deadlock `release.yml`.
   - `cancel-in-progress: ${{ github.event_name == 'push' || github.event_name == 'pull_request' }}`. A newer push supersedes an older one. The nightly run and a release call are never cancelled by a push, and they never cancel one.
9. **Nightly stays in `windows.yml`** (cron `41 2 * * *`, the default branch, the full legs).
   - One workflow keeps one check name and one job definition. `nightly.yml` is unchanged.
   - A nightly failure is reported by GitHub's own workflow e-mail. There is no Alice-side alert.
   - GitHub pauses schedules after 60 days without repository activity (noted in `docs/dev/windows-ci.md`).
10. **Cross-host reproducibility (F13) and one set of build flags.**
    - The `linux-build` job runs `make winhelper` and passes the two SHA-256 values as job outputs. The Windows legs build with the same environment (`CGO_ENABLED=0`, `GOOS=windows`, `GOAMD64=v1` / `GOARM64=v8.0`, `-trimpath -buildvcs=false -ldflags "-s -w"`) and fail when a hash differs.
    - Fallback if F13 fails: a warning (see the table).
    - `TestWindowsHelperBuildFlagsAgree` requires the `winhelper` recipe of the `Makefile`, `deploy/dev/reproducible-check.sh` and the build step of `windows.yml` to carry that same flag set for both architectures.
11. **Release package layout.**
    - `helper/` gains `alice-winhelper-windows-amd64.exe`, `alice-winhelper-windows-arm64.exe` and `alice-winhelper.sha256`, next to the Linux files. The names are those of `make winhelper`, already used by the setup script's messages and the guide. The administrator copies the file as `alice-helper.exe`.
    - `make release` gains the prerequisite `winhelper`.
    - `releasebuild`'s `helperEntries` checks both checksum files: every listed binary must exist, be a regular file and match, and the stage refuses otherwise. `SHA256SUMS` lists the new files without new code (it lists every package file).
    - The chain of trust:
      1. the offline-signed `SHA256SUMS` names each file;
      2. `make image-check` proves the image's `alice` embeds exactly the checksums of `bin/alice-winhelper.sha256`, the file the stage checks the bundled binaries against;
      3. the setup script built from those embedded checksums refuses any other `alice-helper.exe`.
    - There is no separate download outside the package. `install.sh` copies `helper/` as a whole (`alice-lib.sh`), so no script changes.
12. **`release.yml` waits for real Windows.**
    - A job `windows: uses: ./.github/workflows/windows.yml` with `with: { all: true }` and `permissions: contents: read`. `stage` gains `needs: [gates, zap-full, fuzz, windows]`.
    - `windows.yml` gains `on: workflow_call` with the boolean input `all` (default `false`).
    - No Windows gate is added to `make release-gates`: it runs on one Linux machine. The release checklist's row 1.46 records the run instead.
13. **No Authenticode (§15 Q2).**
    - The release-key-signed `SHA256SUMS` and the setup script's hash check are the controls.
    - The gap is written in `docs/windows-host-preparation.md`, `docs/security-overview.md`, `SECURITY-REPORT.md` KI-42 and `WN-18`. It matters for WDAC or AppLocker allow-lists by publisher; the workaround is a hash rule.
    - Owner decision: before the first customer that runs WDAC or AppLocker, and before general availability.
14. **The setup script's behaviour is unchanged.**
    - Its two messages name the package folder: "Copy `helper\alice-winhelper-windows-amd64.exe` or `helper\alice-winhelper-windows-arm64.exe` from the package of this Alice version ...".
    - `internal/providers/windows/setup_test.go` pins the new texts.
15. **Repository settings are the owner's.**
    - The executor writes `docs/dev/windows-ci.md`. It holds the exact check names, the `gh api` ruleset command and the equivalent UI steps.
    - The executor also adds release-checklist row 1.47 and an owner item in the rulings file. It never runs these commands.
    - The ruleset to recommend:
      - default branch, rule `required_status_checks` with the context `windows-required` (integration id `15368`, GitHub Actions);
      - `strict_required_status_checks_policy: false`;
      - a bypass for the repository admin role (`actor_id 5`, `RepositoryRole`, `bypass_mode: always`). The owner pushes `main` directly. The coordinator's flow pushes the phase branch first, so the commit fast-forwarded onto `main` already has a green `windows-required`.
    - `ci.yml`'s job names are listed as a recommendation for the same rule, the owner's choice.
16. **Pull requests run twice** (once for `push`, once for `pull_request`), as `ci.yml` does: accepted. The `changes` job keeps a run with no Windows change at a minute of ubuntu.
17. **ACME bindings panel** (W3 execution ruling, carried to W4).
    - `inventory.ACMEBinding.LocationKind` (from `certificate_locations.kind`, `OrFile()`) and `acmeBindingDTO.LocationKind` (`location_kind`, always present). `AcmeBindingsPanel` passes `windows` to `ObservationFacts` for a `win_sslbinding` binding.
    - Why now: it is the last carried user-visible gap, and the phase's e2e run covers it.
18. **No new real fixture.** W4 adds no real-Windows test, so `TestRealRunnerIsClean` is unchanged. Ports 45321-45329 and `alice-w4-` are reserved should a fix need one.
19. **The owner's manual matrix is a release-checklist section.**
    - New section "8. Windows servers before release", one row per case. Row 1.48 points to it, and `WIN-45` has status `owner`.
    - The rows:
      - **8.1 Windows Server 2019** (Desktop Experience): setup script, **Test connection**, discovery (`winspike osinfo` for the httpapi export, F2), a deployment to an SNI and an IP binding (F2, F9, F10), a failed-verification rollback, one cleanup run.
      - **8.2 Server Core** (2022 or 2025): appcmd present and IIS sites discovered (F6), setup, a deployment.
      - **8.3 A domain-joined server under the Microsoft security baseline** with `CORP\alice-svc` in a GPO-managed Administrators group: setup with `$AliceUser` edited, the lower-case `Match User`, the key line's `command=` confining the key (W1 C1), an elevated token, a deployment.
      - **8.4 Defender (or the customer's EDR) real-time protection on**: setup script, first **Test connection** (the W2 first-sign-in delay), a deployment (journal and machine key), a cleanup run that removes a certificate (W3).
      - **8.5 An RDP listener with its own CA certificate** (`SSLCertificateSHA1Hash` set): a cleanup run keeps it (`kept rdp`), and Alice never changes it.
      - **8.6 The helper from the signed package**: `helper\alice-winhelper-windows-amd64.exe` verified against the signed `SHA256SUMS`; the setup script accepts it; a copy with one byte changed is refused.
      - **8.7 AD FS** (when available): the raw application id is shown; send the id.
      - **8.8 ARM64 Windows Server** (when available): setup and a deployment with the arm64 helper.
20. **Every item marked for W4 in W1-W3, settled.**
    - **`windows.yml` required:** Rulings 4-9, 15. The repository setting is an owner step.
    - **Helper in the package and `SHA256SUMS`:** Rulings 11-12. This closes W1 owner item M5.
    - **Version 1.0.0:** Ruling 2.
    - **The owner's manual matrix,** with a cleanup run under Defender and an RDP listener with its own certificate: Ruling 19.
    - **`nul.go`:** Ruling 3.
    - **ACME bindings panel wording:** Ruling 17.
    - **W3's deferred minors are declined** and carried to "Left for later phases", unchanged in behaviour and recorded as a known debt:
      - the heal step may clear a chain for a DER still present in another store;
      - no test of the `maxImports` trim of adopted entries;
      - `cleanup.go` is not split;
      - the provider's plan check accepts duplicate candidates;
      - `UpdateTarget` writes `certificate_cleanup` back on every edit;
      - a skipped incident place queues one extra cleanup.
    - **The W2 items W3 carried are carried again:** a third party's intermediate makes a redeploy answer `unchanged` with `win.chain_differs`; the emulator's slow-host fault; deploying to a binding whose only problem is its key; IDN host headers; a manual rollback action.
    - **The W3 owner decisions stay owner items:** cleanup while the licence is locked, and the accepted gaps.
21. **ARM64 is built but not run on real Windows.**
    - It is built, checksummed and byte-compared, but no hosted Windows Server ARM64 runner exists. The real-run check is row 8.8 and "Left for later phases".
22. **Docs.**
    - `docs/admin-guide.md` "Windows servers", `docs/operator-guide.md`, `docs/security-overview.md`, a `SECURITY-REPORT.md` delta (scope, §3, KI-42, §8, §9), `docs/windows-host-preparation.md` (the package as the source; the stale sentence "never removes a certificate in this release" corrected; Authenticode), `docs/nginx-host-preparation.md` ("Release packages ship ...").
    - `docs/release-checklist.md` rows 1.46-1.48 and section 8, the new `docs/dev/windows-ci.md`, `CHANGELOG.md`.
    - The spec amendments and the matrix (Task 6).

## Review Focus

1. **A change with no Windows path never leaves the required check pending, and a Windows change never passes on skipped or cancelled legs.** Tests: Task 2 `TestWindowsGateDecision`; Task 3 `TestWindowsWorkflowGate`; runs 1-2 (F14).
2. **The watched list goes stale when a Windows package gains a dependency** (a new provider package, a moved test helper). Tests: Task 2 `TestWindowsWorkflowWatchesEveryDependency`, `TestWindowsChangedScript` (the `dir/*` vs `dir/**` forms and a renamed file).
3. **A release package with a missing, stale or mismatched Windows helper must not stage, and `SHA256SUMS` must name both helpers.** Tests: Task 4 `TestStageLayout`, `TestStageRefusesAMissingInput` (new rows), `TestStageListsTheWindowsHelpersInSHA256SUMS`.
4. **The binary the runners test differs from the shipped one** (another host, other flags). Tests: Task 3 `TestWindowsHelperBuildFlagsAgree`; the F13 comparison in run 1.
5. **Helper 1.0.0 breaks nothing in either direction**: a 0.3.0 helper still cleans under Alice 1.0, and a 1.0.0 helper passes every minimum. Tests: Task 1 `TestReleasedHelperVersion`; `internal/providers/windows:TestCleanupNeedsHelper030` (unchanged, still green).

---

### Task 1: `winproto`: helper 1.0.0

**Files:**
- Modify: `internal/providers/windows/winproto/winproto.go` (`Version`, package comment), `internal/providers/windows/winproto/winproto_test.go` (the two version assertions at lines ~295 and ~589), `internal/providers/windows/winhelper/winhelper_test.go` (`TestRunVersion` reads `1.0.0`), `internal/providers/windows/provider_test.go` (`HelperVersion` `1.0.0`)

**Interfaces:**
- Produces: `winproto.Version = "1.0.0"`. `WriteMinVersion = "0.2.0"` and `CleanupMinVersion = "0.3.0"` are unchanged.

- [ ] **Step 1: Write the failing test** in `winproto_test.go`, `TestReleasedHelperVersion`: `Version == "1.0.0"`; `VersionAtLeast(Version, WriteMinVersion)`; `VersionAtLeast(Version, CleanupMinVersion)`; `VersionAtLeast("0.3.0", CleanupMinVersion)` (a W3 helper still cleans); `!VersionAtLeast("0.3.0", Version)`; `VersionAtLeast("1.0.0", "0.3.0")` (numeric, not text, comparison). Update the two existing assertions to `1.0.0`.
- [ ] **Step 2: Run it to verify it fails**
Run: `go test ./internal/providers/windows/winproto/`
Expected: FAIL (`Version` is `0.3.0`).
- [ ] **Step 3: Implement.** Set `Version = "1.0.0"` and rewrite the package comment: 0.1.0 W1, 0.2.0 W2, 0.3.0 W3, 1.0.0 the first released helper (W4, R63), protocol 1 throughout. Update `TestRunVersion` and the provider test's expected version. Grep for any other `"0.3.0"` that means the helper's own version (not a minimum) and update it.
- [ ] **Step 4: Run the tests**
Run: `go test -race -count=1 -cover ./internal/providers/windows/... ./cmd/alice-fakewindows/ && GOOS=windows go vet ./cmd/alice-winhelper/ && make winhelper`
Expected: PASS, winproto 100.0%.
- [ ] **Step 5: Commit**: `feat(winproto): helper 1.0.0, the first released alice-helper.exe; protocol 1 and the write and cleanup minimums unchanged (R63)`.

---

### Task 2: The watched-path list, the CI decision script and their guards

**Files:**
- Create: `.github/windows-paths.txt`, `deploy/dev/windows-ci.sh` (mode 0755; bash, `set -euo pipefail`), `internal/archtest/windowsci_test.go`

**Interfaces:**
- Produces:
  - `deploy/dev/windows-ci.sh changed <list-file>`: reads changed file names (one per line) on standard input. Exit 0 and prints the first matching name when any name matches an entry. Exit 1 when none does. Exit 2 for a usage error, an unreadable list, or an entry of another form (`a/**/b`, a leading `/`, `..`, white space inside).
  - `deploy/dev/windows-ci.sh gate <changes_result> <windows> <linux_build_result> <helper_result>`: exit 0 or 1 by Ruling 4. It prints one line saying why. Results are GitHub's `success|failure|cancelled|skipped`; `windows` is `true|false`. Any other value: exit 2.
  - Entry semantics (Ruling 6). `dir/**` matches names starting `dir/`. `dir/*` matches `dir/<name>` with no further `/`. Anything else matches only itself.
  - The initial list: `cmd/alice-winhelper/**`, `internal/providers/windows/**`, `internal/providers/*`, `internal/providers/linuxssh/**`, `internal/providers/tlsverify/**`, `internal/providers/providertest/**`, `internal/providers/apacheconf/**`, `internal/providers/haproxyconf/**`, `internal/providers/nginx/nginxconf/**`, `internal/platform/**`, `internal/secrets/**`, `internal/testutil/pki/**`, plus the fixed entries of Ruling 6. Task 2's test decides the final list: add what it reports and nothing else.
- Mirror: `internal/archtest/buildtags_test.go` (`goListDepsFor`, `moduleRoot`, `covers`); shell style of `deploy/dev/reproducible-check.sh`.

- [ ] **Step 1: Write the failing tests** in `windowsci_test.go`:
  - `TestWindowsChangedScript` table (runs `bash deploy/dev/windows-ci.sh changed` on a temporary list file):
    - entries `a/**`, `b/*`, `c.txt` → `a/x/y.go` matches, `b/z.go` matches, `b/sub/z.go` does not, `c.txt` matches, `c.txt.bak` does not, `ab/x` does not;
    - empty input → exit 1;
    - an entry `a/**/b` → exit 2;
    - `#` comments and blank lines are ignored.
  - `TestWindowsGateDecision` table over the script's `gate`:
    - pass: `success false skipped skipped`, `success true success success`;
    - fail: `success true success failure`, `success true success cancelled`, `success true skipped skipped`, `success true failure success`, `failure false skipped skipped`, `success false success success` (the legs ran although nothing changed: a wrong `changes` output), `cancelled true skipped skipped`;
    - `success maybe skipped skipped` → exit 2.
  - `TestWindowsWorkflowWatchesEveryDependency` (Ruling 6): every in-repo dependency directory is matched by `.github/windows-paths.txt`, read through the script so the test and CI share one matcher; every fixed entry is present; every entry matches at least one file of `git ls-files`. Positive control: `alice/internal/providers/windows/winproto` is among the dependencies.
- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./internal/archtest/ -run 'WindowsChanged|WindowsGate|WatchesEveryDependency'`
Expected: FAIL (no script, no list).
- [ ] **Step 3: Implement** the script and the list. Complete the list until the dependency test passes, and no further.
- [ ] **Step 4: Run the tests**
Run: `go test -race -count=1 ./internal/archtest/ && make shellcheck`. `make shellcheck` is a short Docker run of the pinned ShellCheck image over every tracked `*.sh`, the new script included. Run it only when no other Docker run is active, else defer it to Task 7.
Expected: PASS, ShellCheck silent.
- [ ] **Step 5: Commit**: `ci(windows): one watched-path list, a tested change and gate decision script, and a guard that the list covers every package the Windows tests build (R63)`.

---

### Task 3: `windows.yml`: the required gate, change detection, cross-host build check, workflow guards **[F13, F14]**

**Files:**
- Modify: `.github/workflows/windows.yml`
- Modify: `internal/archtest/windowsci_test.go` (three tests below)

**Interfaces:**
- Consumes: Task 2's script and list.
- Produces: the workflow shape that `docs/dev/windows-ci.md` (Task 6) documents:
  - `on:` `push` (no `paths`), `pull_request` (no `paths`), `schedule` (`41 2 * * *`), `workflow_dispatch`, and `workflow_call` with input `all` (boolean, default `false`). `permissions: contents: read`. Concurrency per Ruling 8.
  - Job `changes` (ubuntu-latest, 5 min): checkout with `fetch-depth: 0` and `persist-credentials: false`; one step by Ruling 5; output `windows`.
  - Job `linux-build` (ubuntu-latest, `needs: changes`, `if: needs.changes.outputs.windows == 'true'`): setup-go from `go.mod`, `make winhelper`, outputs `amd64` and `arm64` (the SHA-256 values of `bin/alice-winhelper.sha256`).
  - Job `helper` (the existing matrix, `needs: [changes, linux-build]`, same `if:`): unchanged steps, except that the build step sets `GOAMD64: v1` / `GOARM64: v8.0` per architecture and a new step "Compare with the Linux build" fails on a differing SHA-256 (values through `env:`).
  - Job `windows-required` (`name: windows-required`, ubuntu-latest, `if: always()`, `needs: [changes, linux-build, helper]`): one step running `deploy/dev/windows-ci.sh gate` with the four values through `env:`. Each value comes from `needs.<job>.result`, plus `needs.changes.outputs.windows` read as `false` when it is empty.
  - The header comment says the workflow is the required check (R63) and names `docs/dev/windows-ci.md`.
- Mirror: the current `windows.yml`; `release.yml` for `persist-credentials: false`.

- [ ] **Step 1: Write the failing tests** in `windowsci_test.go`, parsing the YAML with `go.yaml.in/yaml/v3` into a map. A YAML `on:` key may decode as boolean `true`, so look up both forms.
  - `TestWindowsWorkflowGate` (Rulings 4, 5, 8, 12):
    - `push` and `pull_request` have no `paths` or `paths-ignore`; `schedule`, `workflow_dispatch` and `workflow_call.inputs.all` (boolean) exist;
    - jobs `changes`, `linux-build`, `helper`, `windows-required` exist;
    - `windows-required` has `name: windows-required`, `if: always()`, needs exactly the other three, and its run text calls `deploy/dev/windows-ci.sh gate`;
    - `helper` and `linux-build` have an `if:` naming `needs.changes.outputs.windows`;
    - `concurrency.group` starts with the literal `windows-`;
    - no `run:` text anywhere contains `${{` (values go through `env:`).
  - `TestWindowsWorkflowRequiresEveryRealTest` (Ruling 7): parse the `$required = @(...)` names from the test step and compare them as a set with the `TestReal*`/`TestFidelity*` functions found by `go/parser` in `cmd/alice-winhelper/*_test.go` and `internal/providers/windows/**/*_test.go`. Print the missing and the stale names.
  - `TestWindowsHelperBuildFlagsAgree` (Ruling 10): the `winhelper` recipe of the `Makefile`, the two Windows lines of `deploy/dev/reproducible-check.sh` and the build step of `windows.yml` each contain `-trimpath`, `-buildvcs=false`, `-ldflags "-s -w"` and `CGO_ENABLED=0` (or the `env:` equivalent), with `GOAMD64=v1` for amd64 and `GOARM64=v8.0` for arm64.
- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./internal/archtest/ -run 'WindowsWorkflow|BuildFlagsAgree'`
Expected: FAIL (the old workflow has `paths`, no gate, no GOAMD64 / GOARM64).
- [ ] **Step 3: Implement** the workflow.
- [ ] **Step 4: Verify locally what can be verified**
Run: `actionlint .github/workflows/windows.yml && go run ./tools/pincheck && go test -race -count=1 ./internal/archtest/`
Expected: PASS.
- [ ] **Step 5: Commit**: `ci(windows): windows-required as the one required check, the legs decided by the watched paths, nightly and callable, the runner's helper compared byte for byte with the Linux build (R63)`.
- [ ] **Step 6: Run on real Windows (runs 1 and 2).**
  - **Run 1:** push `windows-w4` with Tasks 1-3. The head changes Windows paths, so both legs run. Expect `windows-required` green, the F13 comparison passing on both images, and every required test passing.
  - **Run 2:** push the next commit, one that touches only `docs/superpowers/rulings/windows-iis.md` (the runner-run table with run 1). Expect `changes` false, `linux-build` and `helper` skipped, `windows-required` green, context name `windows-required` (F14).
  - Record F13 and F14 with the run links. If a fact differs, apply its "If it is wrong" column in its own fix commit.

---

### Task 4: The Windows helper in the release package; `release.yml` waits for real Windows; setup script texts **(parallel with Task 5)**

**Files:**
- Modify: `tools/releasebuild/main.go` (`helperFiles` becomes a per-checksum-file table; `helperEntries`), `tools/releasebuild/main_test.go` (`fixture`: the Windows binaries and `alice-winhelper.sha256`; `TestStageLayout`; `TestStageRefusesAMissingInput` rows; new `TestStageListsTheWindowsHelpersInSHA256SUMS`)
- Modify: `Makefile` (`release: release-preflight helper winhelper notices`; the release comment block names `bin/alice-winhelper.sha256` too)
- Modify: `.github/workflows/release.yml` (job `windows`, `stage.needs`, header comment)
- Modify: `internal/providers/windows/setup.go` (the two messages, Ruling 14), `internal/providers/windows/setup_test.go`
- Modify: `internal/archtest/windowsci_test.go` (`TestReleaseWorkflowWaitsForWindows`)

**Interfaces:**
- Produces:
  ```go
  // helperSets: each checksum file of bin/ and the binaries it must list, all bundled under helper/.
  var helperSets = []struct{ sums string; files []string }{
      {"alice-helper.sha256", []string{"alice-helper-linux-amd64", "alice-helper-linux-arm64"}},
      {"alice-winhelper.sha256", []string{"alice-winhelper-windows-amd64.exe", "alice-winhelper-windows-arm64.exe"}},
  }
  ```
  - `helperEntries(dir)` returns, for each set, the checksum file and its binaries under `helper/` (mode 0644).
  - The error text for a mismatch names the checksum file and the `make` target (`run make winhelper` for the Windows set).
- Mirror: the existing Linux checks and their tests.

- [ ] **Step 1: Write the failing tests**
  - `TestStageLayout`: the package holds `helper/alice-winhelper-windows-amd64.exe`, `helper/alice-winhelper-windows-arm64.exe` and `helper/alice-winhelper.sha256`.
  - `TestStageRefusesAMissingInput` rows: "no Windows arm64 helper", "Windows helper checksum differs" (refusal names `alice-winhelper.sha256` and `make winhelper`), "no Windows checksum file".
  - `TestStageListsTheWindowsHelpersInSHA256SUMS`: the stage's `SHA256SUMS` has a line for each of the three Windows files whose hash equals `sha256` of the staged file. The `.exe` hashes also equal the lines of the fixture's `alice-winhelper.sha256`.
  - `setup_test.go`: the script's two messages name `helper\alice-winhelper-windows-amd64.exe` and `helper\alice-winhelper-windows-arm64.exe` "from the package of this Alice version". The checksum logic is unchanged.
  - `TestReleaseWorkflowWaitsForWindows` (Ruling 12): `release.yml` has a job `windows` with `uses: ./.github/workflows/windows.yml` and `with.all: true`, and `stage.needs` contains `windows`.
- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./tools/releasebuild/ ./internal/providers/windows/ ./internal/archtest/ -run 'Stage|Setup|ReleaseWorkflow'`
Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the tests**
Run: `go test -race -count=1 ./tools/releasebuild/ ./internal/providers/windows/... ./internal/archtest/ && actionlint .github/workflows/release.yml .github/workflows/windows.yml && go run ./tools/pincheck && make helper winhelper`
Expected: PASS. A full `make release-test VERSION=1.0.0-rc.90` (Docker) runs in Task 7 only when the machine is free.
- [ ] **Step 5: Commit**: `feat(release): alice-helper.exe for amd64 and arm64 and its checksum file in the package's helper folder and SHA256SUMS; release.yml stages only after the real-Windows check; the setup script names the package folder (R63)`.

---

### Task 5: ACME bindings panel: Windows wording by `location_kind` **(parallel with Task 4)**

**Files:**
- Modify: `internal/inventory/acme_bindings.go` (`acmeBindingSelect` selects `l.kind`; `ACMEBinding.LocationKind providers.LocationKind`, set with `OrFile()`), `internal/api/acme_dto.go` (`acmeBindingDTO.LocationKind string json:"location_kind"`), `api/openapi.yaml` (the ACME binding schema: `location_kind`, required, the `LocationKind` enum)
- Modify: `web/src/api/types.ts` (the ACME binding type gains `location_kind: LocationKind`), `web/src/components/acme/AcmeBindingsPanel.tsx` (`windows={b.location_kind === 'win_sslbinding'}` on `ObservationFacts`; delete the W3 comment), `web/src/test/fixtures.ts`
- Tests: `internal/api/acme_handlers_test.go`, `internal/inventory/acme_more_integration_test.go`, `web/src/pages/AcmeCertificatePage.test.tsx`

**Interfaces:**
- Consumes: `providers.LocationKind`, `.OrFile()`; `ObservationFacts({ observation, windows })`.
- Mirror: W3 Task 10's `deploymentDTO.LocationKind` and its test `TestDeploymentDTOHasLocationKind`.

- [ ] **Step 1: Write the failing tests**
  - `TestACMEBindingDTOHasLocationKind`: an ACME binding on a Windows binding renders `location_kind: win_sslbinding`; one on an Nginx file renders `server_file`.
  - `acme_more_integration_test.go`, `TestListACMEBindingsCarriesTheLocationKind`: the listed binding of a Windows location carries `LocationKind == "win_sslbinding"`.
  - `AcmeCertificatePage.test.tsx`: a Windows binding's observation reads "Binding (last scan)" and a file binding keeps the file wording. EN only; the TR key already exists from W3.
  - The OpenAPI conformance tests pass.
- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./internal/api/ -run 'ACMEBinding|OpenAPI' && cd web && npx vitest run src/pages/AcmeCertificatePage.test.tsx`
Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the tests**
Run: `go test -race -count=1 ./internal/api/ && go test -race -count=1 -tags integration ./internal/inventory/ -run ACME && cd web && npx vitest run && npx tsc --noEmit && npm run lint`. The integration run happens only when no other Docker run is active. Otherwise record it as pending for Task 7.
Expected: PASS.
- [ ] **Step 5: Commit**: `fix(acme): the bindings panel speaks of a Windows binding as a binding; location_kind on the ACME binding (R63)`.

---

### Task 6: Decision, rulings, specification amendments, test IDs, documents, owner steps

**Files:**
- Modify: `docs/superpowers/rulings/windows-iis.md`. Add a heading "W4 (R63)" with these sections:
  - the 22 rulings as built;
  - the F13 and F14 verdicts;
  - the runner-run table;
  - rulings made during execution;
  - the acceptance against design §13 W4;
  - "Owner items (W4)": the ruleset of Ruling 15; the manual matrix of Ruling 19; Authenticode (Ruling 13); a confirmation of the bypass choice; the W3 owner decisions still open;
  - "Deferred to W5+".
- Modify: `docs/superpowers/specs/alice-v1/00-decisions.md`. Add R63 after R62:

  > R63 (owner approval of the Windows design with its §15 defaults, 2026-10-22; phase W4 ...; rulings in `docs/superpowers/rulings/windows-iis.md` "W4 (R63)") Windows server target, phase W4: real-Windows CI and release ...

  The R63 text summarises:
  - `windows-required`, change detection and the watched list;
  - nightly and `workflow_call`;
  - F13;
  - the package's `helper/` Windows files and `SHA256SUMS`;
  - `release.yml`;
  - helper 1.0.0;
  - no Authenticode;
  - the owner steps;
  - no migration and no error code.
- Modify: `docs/superpowers/specs/2026-10-21-windows-iis-target-design.md`:
  - status "W4 built (R63)"; §13 W4 heading "built, R63, §19";
  - F13 and F14 rows in §14;
  - a new "§19 Phase W4 as built" table with the rows CI check, Change detection, Nightly, Release package, Release workflow, Helper version, Reproducibility, Documents, Owner steps, each with "Differs from this design" (for example: one gate job instead of path-filtered required jobs; the matrix legs are not themselves required).
- Modify: `docs/superpowers/specs/alice-v1/04-security.md`:
  - §14.4: `WN-6` amended (the package's signed `SHA256SUMS` lists the helper) and new `WN-18`, T: a tampered `alice-helper.exe` in the package or on its way to the server. Mitigation: the offline-signed `SHA256SUMS`, the setup script's embedded hash, the image check. Residual: Low. There is no Authenticode, so a WDAC or AppLocker publisher rule cannot name it (Q2).
  - §17.5: one sentence noting that the package's `helper/` carries the Linux and Windows helpers.
- Modify: `docs/superpowers/specs/alice-v1/06-quality.md` §24.7 (rows below; the heading names R63), `test/matrix/traceability.json`, `docs/security/traceability.md` (regenerated)
- Modify: `docs/admin-guide.md` "Windows servers":
  - the helper comes from the package's `helper\` folder;
  - versions (1.0.0 is the first released helper; update the helpers first);
  - what the automated real-Windows check covers (2022 and 2025, Desktop Experience) and what the release's manual matrix covers.
- Modify: `docs/operator-guide.md`:
  - the Commands table gains `make winhelper`;
  - "Production layout": `helper/` holds the Linux and Windows helpers with their checksum files;
  - "Updates": copy the new `alice-helper.exe` to the Windows servers before updating Alice.
- Modify: `docs/security-overview.md`:
  - architecture and trust boundaries: Windows servers over OpenSSH with a forced command;
  - network ports: 22 to Windows servers;
  - supply chain: the helper in the signed `SHA256SUMS`, no Authenticode;
  - residual risks: a pointer to KI-42.
- Modify: `SECURITY-REPORT.md`:
  - §2 scope adds `alice-helper.exe`;
  - §3 gains a "Windows servers" paragraph with evidence names;
  - §7 gains KI-42, Windows servers: platform compromise reaches every managed binding and Alice-imported certificate (as KI-02/KI-03); no Authenticode; not verified on 2019, Server Core, a domain baseline, Defender on or ARM64 until the owner matrix; the W3 accepted cleanup gaps;
  - §8: the key line's `from=` and the firewall rule for Windows;
  - §9: `certificate_cleanup` on by default, helper data directory ACL.
- Modify: `docs/windows-host-preparation.md`:
  - step 1 takes the helper from the package's `helper\` folder and checks it against `helper\alice-winhelper.sha256`, which the signed `SHA256SUMS` covers. A development checkout still uses `make winhelper`;
  - the intro's stale "never removes a certificate in this release" is corrected (W3 cleanup);
  - a short "Code signing" paragraph covers Ruling 13.
- Modify: `docs/nginx-host-preparation.md` ("Release packages ship the same files in a `helper/` directory").
- Modify: `docs/release-checklist.md`:
  - row 1.46: real Windows green on the release commit (`release.yml` job `windows`, or a `windows.yml` run of that commit; record the link; class B, Release engineer);
  - row 1.47: the required check configured as in `docs/dev/windows-ci.md` (class B, Owner);
  - row 1.48: section 8 done (class B, Owner);
  - section 5 gains row 5.9: Windows servers W1-W4, owner tables in the rulings file;
  - new section "8. Windows servers before release", rows 8.1-8.8 of Ruling 19, with the result, date and initials columns.
- Create: `docs/dev/windows-ci.md`:
  - what runs when (Ruling 5 table) and the job names;
  - **the exact check names**: `windows-required` (required); `changes`, `linux-build`, `helper (windows-2022)`, `helper (windows-2025)` (informational); and `ci.yml`'s `go`, `coverage`, `ssh-matrix`, `licensectl (ubuntu-latest)`, `licensectl (macos-latest)`, `web`, `secrets`, `stack` (recommended);
  - the owner's ruleset command, as below;
  - the UI equivalent: Settings → Rules → Rulesets → New branch ruleset, target the default branch, "Require status checks to pass", add `windows-required` from GitHub Actions, bypass list "Repository admin: Always allow";
  - the check `gh api repos/erenmeren/alice/rules/branches/main`;
  - how to run the workflow by hand (`gh workflow run windows.yml --ref <branch>`);
  - the 60-day schedule pause;
  - how to add a package to the watched list.

  The ruleset command:
  ```
  gh api --method POST repos/erenmeren/alice/rulesets --input - <<'EOF'
  {"name":"main: windows-required","target":"branch","enforcement":"active",
   "conditions":{"ref_name":{"include":["~DEFAULT_BRANCH"],"exclude":[]}},
   "bypass_actors":[{"actor_id":5,"actor_type":"RepositoryRole","bypass_mode":"always"}],
   "rules":[{"type":"required_status_checks","parameters":{"strict_required_status_checks_policy":false,
     "do_not_enforce_on_create":false,"required_status_checks":[{"context":"windows-required","integration_id":15368}]}}]}
  EOF
  ```
- Modify: `tools/docscheck/required.txt`. Pin two sentences: the host guide's "not signed with Authenticode" sentence, and the release checklist's row 1.46 text.
- Modify: `CHANGELOG.md` ("Unreleased — Windows servers (CI and release, R63)": helper 1.0.0 in the package, the required check, the ACME panel fix), `docs/superpowers/specs/2026-10-21-deployment-targets-roadmap.md` (the Windows row: W0-W4 built)

| ID | Case | Tests |
|---|---|---|
| WIN-39 | A change under the Windows paths runs the real-Windows legs, and any other change does not; the one required check passes only on green legs or on no Windows change | `internal/archtest:TestWindowsChangedScript`, `TestWindowsGateDecision`, `TestWindowsWorkflowGate` |
| WIN-40 | The watched paths cover every package the Windows tests build; every real-Windows test must pass, not skip | `internal/archtest:TestWindowsWorkflowWatchesEveryDependency`, `TestWindowsWorkflowRequiresEveryRealTest` |
| WIN-41 | The release package carries both Windows helpers and their checksum file, listed in `SHA256SUMS`; a missing or changed helper refuses the stage | `tools/releasebuild:TestStageLayout`, `TestStageRefusesAMissingInput`, `TestStageListsTheWindowsHelpersInSHA256SUMS` |
| WIN-42 | The helper the runners test is the one the release ships: one set of build flags, byte-identical builds on Linux and Windows; a tag is staged only after real Windows passed | `internal/archtest:TestWindowsHelperBuildFlagsAgree`, `TestReleaseWorkflowWaitsForWindows`, `.github/workflows/windows.yml:Compare with the Linux build` |
| WIN-43 | Helper 1.0.0: a 0.3.0 helper keeps every feature, a 0.2.0 helper still deploys and is never sent `iis-cleanup` | `internal/providers/windows/winproto:TestReleasedHelperVersion`, `internal/providers/windows:TestCleanupNeedsHelper030` |
| WIN-44 | An ACME certificate's Windows binding speaks of a binding, not a file | `internal/api:TestACMEBindingDTOHasLocationKind`, `web/src/pages/AcmeCertificatePage.test.tsx:Binding (last scan)` |
| WIN-45 | The owner's manual matrix before release: Windows Server 2019, Server Core, a domain baseline, Defender on (with a cleanup run), an RDP listener with its own certificate, the helper from the signed package, AD FS and ARM64 when available | owner: `docs/release-checklist.md` section 8, rows 8.1-8.8 (status `owner`) |

Adjust the test names in the table to the ones Tasks 1-5 actually wrote (the web entry's text must exist in the file).

- [ ] **Step 1: Write the failing check**: add the rows to `06-quality.md`.
- [ ] **Step 2: Run it to verify it fails**
Run: `make matrix-check MATRIXCHECK_FLAGS=-strict`
Expected: FAIL (7 gaps).
- [ ] **Step 3: Write** the documents and `traceability.json` (WIN-45 `{"id":"WIN-45","status":"owner","owner":"docs/release-checklist.md section 8 (rows 8.1-8.8)"}`). Then regenerate: `go run ./tools/matrixcheck -spec docs/superpowers/specs/alice-v1/06-quality.md -map test/matrix/traceability.json -doc docs/security/traceability.md -update`.
- [ ] **Step 4: Verify**
Run: `make matrix-check MATRIXCHECK_FLAGS=-strict && make docs-check && make i18n-check && go test -count=1 ./internal/providers/windows/ -run Docs && go test -count=1 ./tools/releasebuild/`
Expected: PASS, 0 gaps, 0 pending, 1 more owner row. The guide's Match block test still passes. The stage still packs `windows-host-preparation.md` and does not ship `docs/dev/`.
- [ ] **Step 5: Commit**: `docs: Windows servers phase W4 (R63): decision, rulings, design as built, WN-18, WIN-39..WIN-45, admin, operator and host guides, security overview and report, release checklist with the Windows matrix, the owner's required-check steps, changelog`.

---

### Task 7: Final gates

**Files:** none new. Fixes go to the task that owns the code.

- [ ] **Step 1: Full local gates**
Run: `make lint && make test && make i18n-check && make matrix-check MATRIXCHECK_FLAGS=-strict && make docs-check && make helper winhelper && make build && make coverage`
Expected: PASS. Every coverage floor is met and none was lowered.
- [ ] **Step 2: Windows build and vet**
Run: the Windows line of "Verification commands".
Expected: PASS.
- [ ] **Step 3: e2e, image and a test release.** Only when no other `make ci` or Docker-based run is active on the machine:
  - `E2E_PROJECT=alice-e2e-w4 ALICE_E2E_PORT=9977 make ci`;
  - then `make release-test VERSION=1.0.0-rc.90` and `tar tzf bin/release/alice-1.0.0-rc.90.tar.gz | grep 'helper/alice-winhelper'` (three lines);
  - then remove the rc.90 outputs the target made.

  Otherwise run Task 5's integration test and `E2E_PROJECT=alice-e2e-w4 ALICE_E2E_PORT=9977 make e2e-up e2e; E2E_PROJECT=alice-e2e-w4 make e2e-down` when the machine frees, and list `make release-test` as pending in the acceptance report.
Expected: PASS; e2e totals recorded.
- [ ] **Step 4: Real Windows.** The `windows.yml` run of the branch's code head is green on both runners with `windows-required` green (runs counted, at most 6). If it cannot be, the rulings file lists it as an owner item and the acceptance report says it is pending.
- [ ] **Step 5: gitleaks** over the whole range `2ec69c8c..HEAD`. Export it with `git log -p` and scan in `dir` mode (the worktree's git-mode scan sees no commits), as W3 did. Fingerprint any finding in `.gitleaksignore` without key material.
- [ ] **Step 6: Acceptance check against design §13 W4**, one line each in the rulings file:
  - the jobs are required for changes under the Windows paths: Tasks 2-3, run links; the repository setting is owner step 1.47;
  - nightly and path-decided jobs on both images: Task 3;
  - the helper in the release artifacts and `SHA256SUMS`: Task 4;
  - the documentation: Task 6;
  - `make matrix-check` passes: Task 6;
  - the owner's manual matrix is listed as an owner step: Task 6, section 8.

  Hand the branch `windows-w4` to the coordinator. Do not merge or push `main`.

---

## Execution notes for the implementer

- Work in the worktree branch `windows-w4`; never switch branches inside a task. Take `main` in with `git merge main` (never rebase). You may push `windows-w4` (and only it) so `windows.yml` runs. Never push `main`, never open a pull request, never run the `gh api` ruleset command or change any repository setting.
- Dispatch order: 1 → 2 → 3 → push (run 1) → (4 ∥ 5: disjoint files; Tasks 2, 3 and 4 all extend `internal/archtest/windowsci_test.go`, in that order, and Task 5 never touches it) → 6 → 7.
  - Run 2 is the push of the rulings-only commit that records run 1 (F14).
  - Push again after Tasks 4-5 (run 3: the version and setup changes are under watched paths) and after the final review's fixes (run 4).
  - That leaves 2 runs spare.
- Review gates: after Task 3 (Review Focus 1, 2, 4) and after Task 4 (Review Focus 3) a review before the next dependent task. Every finding is fixed in the task that owns the code, with its own commit.
- Record every ruling made during execution in `docs/superpowers/rulings/windows-iis.md` under "W4 (R63)", one line each: the ruling, then why. Keep a runner-run table as W2 and W3 did, `ci.yml` runs of the branch included.
- Commit with `git -c user.name="Eren Altan" -c user.email="erenaltan@gmail.com" commit --only ...` and the trailer `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`. Subjects end with `(R63)`.

## Left for later phases

- **Owner steps (not phases):**
  - the ruleset that makes `windows-required` required (`docs/dev/windows-ci.md`, release-checklist 1.47);
  - the manual matrix, release-checklist section 8:
    - 8.1 Windows Server 2019;
    - 8.2 Server Core;
    - 8.3 a domain-joined server under the security baseline with `CORP\alice-svc`;
    - 8.4 Defender or EDR on, including a cleanup run that removes a certificate;
    - 8.5 an RDP listener with its own CA certificate, kept by cleanup;
    - 8.6 the helper from the signed package;
    - 8.7 AD FS;
    - 8.8 ARM64;
  - the W3 owner decisions (cleanup while the licence is locked, the accepted gaps);
  - Authenticode before the first WDAC or AppLocker customer and before general availability (§15 Q2).
- **W5-W7, on demand:** CCS (`win_ccs_file`), RDP deployment (`win_rdp`), WinRM transport.
- **Carried from W2 and W3, not decided in W4:**
  - a third party's intermediate added after Alice's commit makes a redeploy answer `unchanged` with `win.chain_differs`;
  - the emulator's slow-host fault and the abandoned-call marking it needs;
  - deploying to a binding whose only problem is its key;
  - IDN host headers in their U-label form;
  - a manual "roll back this deployment" action;
  - W3's deferred minors (Ruling 20).
- **Not built:**
  - a real-Windows ARM64 leg (no hosted Windows Server ARM64 runner);
  - `ci.yml` checks made required (the owner's choice, listed in `docs/dev/windows-ci.md`);
  - a Windows gate in `make release-gates`;
  - removing intermediates Alice added to `CA` (design §6.7: never);
  - a cleanup history page.

## Self-review notes (for the executor)

- **Spec coverage.**
  - §13 W4 "nightly and path-filtered workflow jobs on both images": Task 3 (Rulings 5, 8, 9).
  - "the helper in release artifacts and `SHA256SUMS`": Task 4 (Rulings 11, 12).
  - "documentation (admin guide, operator guide, security overview, `SECURITY-REPORT.md` delta, test IDs, traceability)": Task 6.
  - Acceptance "required for changes under the Windows paths": Tasks 2-3 plus owner step 1.47 (Ruling 15).
  - "`make matrix-check` passes": Task 6.
  - "the owner's manual matrix listed as an owner step": Task 6, Ruling 19.
  - §7 release line ("built reproducibly ..., listed in `SHA256SUMS` ...; the setup script embeds the SHA-256"): Rulings 10, 11, 14.
  - §12 items 4 and 6: Task 3, Ruling 19.
  - §15 Q2: Ruling 13.
  - W1-W3 items for W4: Ruling 20, item by item.
- **Names used across tasks.**
  - `winproto.Version` (`1.0.0`).
  - `.github/windows-paths.txt`; `deploy/dev/windows-ci.sh changed|gate`.
  - Jobs `changes`, `linux-build`, `helper`, `windows-required`; the `workflow_call` input `all`; the step "Compare with the Linux build".
  - `releasebuild.helperSets`, `helperEntries`.
  - `inventory.ACMEBinding.LocationKind`, `api.acmeBindingDTO.LocationKind` (`location_kind`).
  - Tests: `TestReleasedHelperVersion`, `TestWindowsChangedScript`, `TestWindowsGateDecision`, `TestWindowsWorkflowWatchesEveryDependency`, `TestWindowsWorkflowGate`, `TestWindowsWorkflowRequiresEveryRealTest`, `TestWindowsHelperBuildFlagsAgree`, `TestReleaseWorkflowWaitsForWindows`, `TestStageListsTheWindowsHelpersInSHA256SUMS`, `TestACMEBindingDTOHasLocationKind`.
