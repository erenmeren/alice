# Windows Servers, Phase W8 (debt and small features) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the Windows target's known debt after W7 and add three small features: every minor deferred during W7, the W6 minors not settled by R70 (none remain; this plan records the check), the code items of R70's "Found, not fixed", the emulator's F26 fidelity gap; and (1) a web input for Alice's address (`from`) in both setup dialogs, (2) one live Windows target per host across transports (`ALC-WIN-0029`), (3) removing a WinRM or CCS password. Each debt item is fixed with one test, declined with a one-line reason, or shown already done at `main`.

**Architecture:** Small changes in their own files, in five areas; parallel subagents never edit the same file.
- (a) Go, watched paths: the emulator `wintest`, `winhelper`, the real-runner tests of `cmd/alice-winhelper` and `internal/providers/windows` (Task 1).
- (b) Inventory, API, migration `00039`, `locales/common` (Task 2): the host rule, the password removal, the seal order.
- (c) Web and e2e (Task 3).
- (d) Tooling and the flake capture (Task 4).
- (e) Documents, then push 1 (Task 5); final gates (Task 6).
The helper does not change: `winproto.Version` stays `1.2.0`, protocol 1, no new subcommand, argument or JSON field. One migration, `00039`. One new error code, `ALC-WIN-0029`.

**Tech Stack:** Go 1.27.3, pgx/v5, PostgreSQL, React 18 + Mantine + TanStack Query + i18next, Vitest, Playwright, GNU make, Docker (gitleaks, shellcheck images pinned in the Makefile), GitHub Actions `windows-2022` / `windows-2025`.

**Spec** (the plan argues from these sources; the executor reads them):
- `docs/superpowers/rulings/windows-iis.md`: "Deferred to W8+" ("Minors deferred during W7 (known debt)"), "Final review fixes (W7)" (the ledger minors "fine to defer"), "Coordinator review (W7)", "Owner items (W7)" (items 4 and "A web input for Alice's address"), "Deferred to W7+" (the W6 minors) and "Deferred to W6+".
- `docs/superpowers/rulings/fixes-2026-10-28.md`: the item table, "Deferred", "Found, not fixed".
- `docs/superpowers/plans/2026-10-28-windows-w7-winrm.md` Rulings 3, 7, 18, 19, 22, 27 and Owner item 4; `docs/superpowers/plans/2026-10-28-fixes-batch-3.md` (the item-table form).
- The coordinator's brief of 2026-10-31 (the owner: "start W8 and finish it").

**Decision:** R72 "Windows server target, phase W8: debt and small features", appended to `docs/superpowers/specs/alice-v1/00-decisions.md` after R71 (the last entry) in R71's form. **Size:** M, 7 tasks (0-6), about two implementer days plus runner waits. **Migration:** `00039`.

## Coordinator decisions at approval (2026-10-31)

The planner's seven open points, decided as the plan proposes: (1) the host rule is a partial unique index (migration 00039, `Z1037` while duplicates exist), not a code-only check; (2) `ALC-WIN-0027`'s advice flips to "remove, then add"; (3) a removal ends the live rows through `rotated_at`, keeps the ciphertext, and a repeat is an idempotent 200; (4) a `PUT` ends the older row (one live row per purpose); (5) the `from` input appears beside every setup script, Linux profiles included, and in the server page's script modal; (6) A8 is asserted on run 1 first and fixed only on evidence; (7) F5 decides validity before the seal and keeps R70 Ruling 9's answer order. All eight "Owner items (W8)" are reported to the owner after the fact, as in W7.

## Global Constraints

- **Branch.** Worktree branch `windows-w8`, cut from `main` at `fa182290` or later. The first commit of the branch is this plan, unchanged (`docs: Windows servers phase W8 (debt and small features) plan (R72)`). Take `main` in with `git merge main`, never rebase. The executor may push `windows-w8` (only that branch) so `windows.yml` runs on the real runners; the coordinator pushes first (the ruleset `windows-required` is required on `main` with admin bypass; branches are not affected). The executor never pushes `main`, never opens a pull request, never changes repository settings.
- **Commits.** `git -c user.name="Eren Altan" -c user.email="erenaltan@gmail.com" commit --only -m "<subject> (R72)" -m "Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>" -- <paths>`. Every subject ends with `(R72)`. New files: `git add -- <path>` first. Never `git add -A`, never rebase, squash or amend a pushed commit (`.gitleaksignore` pins hashes). Never touch `.claude/`, `.superpowers/`, untracked PDFs, `alice-helper` at the root, `web/node_modules` (an untracked symlink in a worktree: never added). No key material, no password literal: tests generate them.
- **Real-Windows runs.** Budget **4 runs** of `windows.yml`. The watched list is `.github/windows-paths.txt`: `internal/providers/windows/**` (so `wintest`, `winrs`, `winhelper`, every provider test), `cmd/alice-winhelper/**`, `internal/providers/*`, `Makefile`, `go.mod`, `docs/windows-host-preparation.md`, among others. R70 Ruling 25: a push of a branch that carries any watched change runs the legs, whatever the push adds; so every push of this branch spends a run. Hence: **no push before Task 5** (push 1, run 1, carries Tasks 1-5); Task 6's review fixes make push 2 (run 2); runs 3-4 are spares for a red leg. Commits after the last push stay local; the coordinator's merge carries them (R70 Ruling 25's form). Record every run (URL, commit, both legs, `windows-required`) in a runner-run table in the rulings file.
- **Runner hygiene.** No new real listener, account or certificate. Fixture ports **45540-45559** are reserved for W8 and expected unused; if a real test needs one, it takes 45540 and `TestRealRunnerIsClean` checks the range. Task 1's A16 extends `TestRealRunnerIsClean` to the `administrators_authorized_keys` line of `TestRealBothTransportsShareTheHelper`.
- **Security guards that must stay green.** `TestNoCodeAcceptsAnyHostKey`; `TestImportRules`, `TestAllowed`; `TestOnlyWinRSImportsNTLMSSP`, `TestNoCodeAllowsBasicAuth`; `TestWindowsHelperLinksOnlyItsProtocol`; `TestWindowsWorkflowWatchesEveryDependency`; `TestWindowsWorkflowRequiresEveryRealTest`; `TestWindowsHelperBuildFlagsAgree`; `TestReleaseBinariesLinkNoTestPackages`; `make release-symcheck`; `make image-check`. Inventory never imports the Windows provider.
- **Protocol and helper.** `winproto.Protocol = 1`, `MinProtocol = 1`, `Version = "1.2.0"`, every `*MinVersion` unchanged. If an item cannot be done without a helper change, it is declined and says so (none in this plan needs one).
- **Error codes.** Existing: `ALC-WIN-0001..0028`. New: `ALC-WIN-0029` `windows.host_already_managed` (409), Task 2. `ALC-WIN-0030` is reserved, unused, for the owner's alternative of Ruling 8 (a 409 on "nothing to remove").
- **Test IDs.** New: `WIN-76` (B1), `WIN-77` (B2), `WIN-78` (B3), in `06-quality.md` §24.7, whose heading and the §24 intro line gain "phase W8 (R72): WIN-76..WIN-78". Every debt fix strengthens an existing ID (named per task). No new STRIDE row: `WN-26` and `WN-29` are amended in place (Task 5).
- **Migration.** `00039_windows_one_target_per_host.sql`; its Up refuses with SQLSTATE `Z1037` (the next after 00038's `Z1036`) while two live Windows targets share a host; its Down drops the index.
- **Coverage floors** (`coverage-floors.json`; never lower one): `inventory` 89, `api` 95, `windows` 95, `winproto` 100, `winhelper` 95, `wintest` 90, `winrs` 95, `cmd/alice-fakewindows` 90. No new Go package.
- **Locales.** EN and TR with identical keys and placeholders in `locales/common/{en,tr}.json` and `web/src/locales/{en,tr}.json` (`make i18n-check`). Turkish never puts a suffix on a placeholder holding a path or a host. The new Turkish texts are quoted in the rulings file for the owner (R70's C6 pattern).
- **e2e.** Project `alice-e2e-w8`, `ALICE_E2E_PORT=9986` (free at planning). Every e2e test resets the shared server (`web/playwright.config.ts`), so B2's host rule does not collide with the four Windows journeys that all use host `fakewindows`. Docker-based Go runs and Playwright never run at the same time, and neither while another `make ci` is active: `pgrep -af 'playwright|make ci|go test'` first.
- **Per-task gate.** `make lint` plus the package tests the task names. `make ci` only in Task 6.
- **Verification commands.**
  - `go build ./... && go vet ./... && go vet -tags integration ./...`
  - `GOOS=windows GOARCH=amd64 go build ./cmd/alice-winhelper/ ./internal/providers/windows/... && GOOS=windows GOARCH=arm64 go build ./cmd/alice-winhelper/ && GOOS=windows go vet ./cmd/alice-winhelper/ ./internal/providers/windows/... && GOOS=windows go vet -tags alicetest ./cmd/alice-winhelper/ && GOOS=windows go test -tags alicetest -c -o /dev/null ./cmd/alice-winhelper/ && GOOS=windows go test -c -o /dev/null ./internal/providers/windows/ ./internal/providers/windows/winrs/`
  - `go test -race -count=1 ./<pkgs>`; integration (Docker): `go test -race -count=1 -tags integration ./<pkgs> -run <name>`
  - Web: `cd web && npx vitest run <files> && npx tsc --noEmit && npm run lint`
  - `make lint`, `make test`, `make i18n-check`, `make matrix-check MATRIXCHECK_FLAGS=-strict`, `make docs-check`; final `make coverage` and `E2E_PROJECT=alice-e2e-w8 ALICE_E2E_PORT=9986 make ci`.
  - `make helper winhelper` before the e2e (checksums Alice embeds; the helper is unchanged, so they do not change).

## Rulings (each goes into `docs/superpowers/rulings/windows-iis.md` under a new "# W8 (R72)" heading)

1. **One decision, R72; one migration; one error code; the helper stays 1.2.0.** Cost if wrong: none functional.
2. **The runner budget is spent in two planned pushes** (Task 5 and Task 6's fixes); the implementer never pushes to see a RED (R70 Ruling 2). Cost if wrong: a red run 1 needs a spare.
3. **The `from` input is web-only on the server side.** `GET /api/v1/ssh-keys/platform-key?from=` (`internal/api/sshkeys_handlers.go`, `inventory.SetupGuide`) and `GET /api/v1/targets/{id}/winrm-setup?from=` (`targets_handlers.go`, `inventory.WinRMSetup`) both exist and share `queryFrom` (API) and `setupFrom` (`internal/inventory/platformkey.go`: an IP literal, canonical form, no zone, no 4-in-6). No API change. The web sends the typed address and shows the API's 422 for a bad one; it does not re-implement the rule. The input appears beside every setup script (the Linux profiles' key line takes `from=` too) and in the target page's "Show setup script again" modal. Cost if wrong: an input on Linux dialogs the owner did not ask for (easy to hide). **Owner to confirm.**
4. **One live Windows target per host.** At most one target of type `windows` with `deleted_at IS NULL` per `lower(config->>'host')`, any port, either transport. Host comparison is textual, as `targets_endpoint_live` (`migrations/00005_inventory_jobs.sql`) compares: `iis-01`, `iis-01.corp.example` and its IP address are three hosts (the docs say so). Enforced by the partial unique index `targets_windows_host_live` (migration 00039), so a race between two creates cannot slip through; `closedTargetWriteError` (`internal/inventory/targets.go`) maps that index's violation with `db.IsUniqueViolationOn(err, "targets_windows_host_live")` (`internal/platform/db/tx.go`) to `ErrWindowsHostManaged` before the generic `ErrDuplicateTarget` case. A removed target frees the host at once. Other types are untouched (an Nginx target on the same host is allowed, as today). The API answers `ALC-WIN-0029` `windows.host_already_managed` 409. `UpdateTarget` cannot change a host (`TargetPatch` has no host field), so no update path exists. Cost if wrong: an operator with a legitimate second entry (a test entry beside the live one) must remove one. **Owner to confirm.**
5. **Existing duplicates block the migration.** 00039's Up runs a `DO` block first: when `SELECT lower(config->>'host') FROM targets WHERE type = 'windows' AND deleted_at IS NULL GROUP BY 1 HAVING count(*) > 1` returns rows, it raises `Z1037` with the message "cannot migrate up: two Windows servers share a host; remove one of each pair in Alice (Servers page), then upgrade"; `docs/upgrade.md` names the query. Alternative considered: a code-only check in `CreateTarget`'s transaction, which lets the migration pass but cannot exclude a race and leaves existing pairs double-counted. Cost if wrong: an upgrade stops until the operator removes an entry. **Owner to confirm.**
6. **`ALC-WIN-0027`'s action text is flipped.** Today: "add the server again with it, then remove the old entry" (`errors.windows.transport_immutable.action`). Under Ruling 4 the second add is refused, so the text becomes "remove this entry, then add the server again with the other connection" (EN and TR), and the admin guide, the host guide and troubleshooting say the same. Cost if wrong: none; the old order is impossible now. **Owner to confirm.**
7. **Removing a password ends its live rows; nothing is deleted.** `credentials.rotated_at` (a column since 00005, unused by any Go code today) marks a row ended: a live row is `rotated_at IS NULL`. `clearTargetPassword(ctx, a, target, ifVersion, spec)` runs in one transaction: the target read with its lock, `spec.check` (the CCS spec: a Windows server; the WinRM spec: `requireWinRM`), the version, then `UPDATE credentials SET rotated_at = $now WHERE target_id = $1 AND purpose = $2 AND rotated_at IS NULL`; when it ended at least one row, the target's version moves and the audit action `target.ccs_password_removed` / `target.winrm_password_removed` is appended with `name` and the ended credential ids, never a secret. The reads (`targetPassword`'s query in `ccs_password.go`; the two `targetColumns` subqueries in `targets.go`) add `AND c.rotated_at IS NULL`. `setTargetPassword` also ends the live rows before its INSERT, so one live row per purpose is an invariant and "the newest row wins" keeps its meaning. The ended ciphertext stays sealed under the master key, in the database and in backups (the docs say so). Cost if wrong: an operator who expects the secret erased finds it still sealed in history. **Owner to confirm.**
8. **Removing when nothing is set is idempotent.** `DELETE` with no live row answers 200 with the target unchanged: no version bump, no audit row. HTTP DELETE semantics; the web disables the button when nothing is set. The alternative (409, `ALC-WIN-0030` reserved) is the owner's. Cost if wrong: a client that wants a signal gets none. **Owner to confirm.**
9. **The removal's effects are the "not set" state.** A WinRM target refuses every helper call with `windows.winrm_password_missing` (`ALC-WIN-0025`) before any dial until a new `PUT`; its page shows "Password not set". A CCS server's next discovery warns `win_ccs_password_missing` and lists no file; a CCS deployment is refused `ALC-WIN-0018`. No new reason, no new text beyond the panel's.
10. **The DELETE endpoints are the PUTs' twins.** `DELETE /api/v1/targets/{id}/ccs-password` and `DELETE /api/v1/targets/{id}/winrm-password`: `scopeResource`, `rbac.CredentialsManage` (an Administrator with a fresh step-up, never a token), `license.ClassChange`, `If-Match` required (412 `ALC-SYS-0008`), no body, answer 200 with the target and its `ETag`. One handler `clearTargetPassword(w, r, clear)` beside `setTargetPassword` in `targets_handlers.go`.
11. **F5: validity is decided before the seal, reported after the target check.** `setTargetPassword` computes `valid := spec.valid(pw.Bytes())` first and seals only when valid; inside the transaction the order of Ruling 9 (R70) is unchanged: licence, target (404), type (409), rule (422), version (412). A refused password is never sealed. Cost if wrong: none to clients (the answers are the same).
12. **The emulator follows F26: an oversized request is HTTP 413 with an empty body**, not a WS-Man fault (`wintest/winrm.go`). The other fault codes stay as they are (A7 declined). Cost if wrong: none to Alice (its client never sends more than `MaxSendChunk`).
13. **Declines** (the item table's reasons; owner informed): A1, A5, A7, A11, A15, A17, F7, F10, F11, F12.
14. **W6's deferred minors are all settled.** Every row of "Minors deferred during W6" (18 rows) is in R70's item table as fix, decline or done, and R70's fixes are present at `fa182290` (Task 0 lists the test names it found). Nothing remains for W8.

## Review Focus

1. **One live Windows target per host, nothing more.** Inputs: the same host over the other transport; the same host with another case; another port; the host of a removed target; an Nginx target on a Windows host; a re-add after removal; two creates in parallel. Expected: `ALC-WIN-0029` only for a live Windows duplicate; `ALC-TGT-0001` unchanged for a duplicate name or endpoint; 00039's Up refuses with `Z1037` on a database with a pair and passes without. Tests: Task 2 `TestOneWindowsTargetPerHost`, `TestMigration00039`, the API row.
2. **A removal ends the live rows and nothing else.** Inputs: `DELETE` without step-up, without `If-Match`, with a stale version, on an SSH Windows target (WinRM path), on a Linux target, twice in a row, then a `PUT`. Expected: the CCS/WinRM `PUT`'s answers for the refusals; after a removal the row still exists with `rotated_at` set, the source answers `ErrNoWinRMPassword` / `ErrNoCCSPassword`, the target's `*_password_set_at` is null, the audit holds no secret, the second `DELETE` changes nothing, the `PUT` works. Tests: Task 2 `TestClearTargetPassword*`, `TestWinRMTargetAfterPasswordRemoval`; Task 3's e2e step.
3. **The address reaches the scripts and only the scripts.** Inputs: an IPv4, an IPv6, a hostname, an address with a zone, an empty field. Expected: the web calls the endpoints with exactly the typed value; the served script's `$AliceAddress` holds the canonical address; a bad one shows the API's `from` field error and no script; the help texts never say "any address" when one is given. Tests: Task 3's dialog tests; the existing `TestSetupScriptWinRM*` and platform-key tests (unchanged).
4. **No test proves less than before.** A2, A6, A8, A16, F1, F2 change tests or test fixtures: each states the property before and after.
5. **The web fixes change only what they name.** F3 moves one function; F6 changes the summary list only; A9/A10 add text; the `from` input adds a query-key component. Every existing dialog test stays green unchanged.

---

## Item table

`win.yml` = on a watched path (rides push 1). "Done" = found already fixed at `fa182290`; the rulings file records where.

| # | Item (one line) | Source | Decision | Task | Test | win.yml |
|---|---|---|---|---|---|---|
| A1 | `ConfigSchema`'s port default is 22 under `winrm` too (`provider.go`) | W7 Task 5; ledger | decline: `providers.Field.Default` is one static value; `ParseConfig` fills 5986 and the form sets it (Ruling 2, 22); Task 5 checks `provider.windows.fields.port.help` names both ports and adds the sentence if missing | 5 | - | - |
| A2 | `wintest/ntlm.go` `field()` converts a `uint32` offset to `int` (wraps on 32-bit) | W7 Tasks 1-2 | fix (compare in `uint64` before converting) | 1 | `TestNTLMServerRefuses` row "an offset above the message" (WIN-69) | y |
| A3 | `sshRun`'s context-ended-after-acquire branch untested | W7 Task 6 | done (W7 final review M4, `d3cd8e21`, `TestSSHRunContextEndedAfterAcquire`) | - | - | - |
| A4 | The WinRM crash table does not assert "sent once" | W7 Task 6 | done (M5, `b2a15584`) | - | - | - |
| A5 | A failed WinRM call returns an empty `HostKey` (`winrm.go`) | W7 Task 6; ledger | decline: `sshRun` returns a key only once a connection exists (`provider.go`); under WinRM the verifier records the sighting before any request; no caller reads a failed call's key | - | - | - |
| A6 | The emulator answers an oversized Send with a WS-Man fault; Windows answers HTTP 413 (F26) | W7 Task 3; coordinator | fix | 1 | `TestWinRMServer*` oversized row asserts 413; a `winrs` client row asserts the mapped error (WIN-70) | y |
| A7 | The other emulator fault codes are placeholders | W7 Task 3 | decline: F29 showed a missing program is an exit, not a fault; fault 5/2147942405 was measured (M1); the rest are never produced by Alice's client; a measurement-only run is not worth a runner run (R70 W5-8b) | - | - | - |
| A8 | The shared deny-rights fragment is not idempotent (prints "Denying" every run) | W7 Ruling 18; ledger | fix, test first: the fragment already guards with `$changed` (`setup.go`); the real WinRM script test runs the script twice and asserts one "Denying"; on evidence, fix the comparison and refresh the SSH golden | 1 | `TestRealWinRMSetupScript` (WIN-73) idempotency assertion; `TestSetupScriptUnchangedByTheRefactor` if the fragment changes | y |
| A9 | Web: no hint after a failed connection test right after the password is saved | W7 Task 8; ledger | fix (a sentence in the `failed` phase when it follows `passwordSaved`) | 3 | the dialog test "a refused sign-in after the password shows the hint" | n |
| A10 | Web: leaving the WinRM phase leaves the password missing without a word | W7 Task 8; ledger | fix (a sentence above Close in the `winrm` phase) | 3 | the dialog test (text present) | n |
| A11 | Web: `deployments.rdpErrors.ssh.output_too_large` exists for the source-scanning test (`DeploymentDetailPage.test.tsx`) | W7 Task 8; ledger | decline: the text is correct for the listener; removing it needs the scanning test to special-case one key | - | - | - |
| A12 | The web passes no `from` | W7 Task 8; owner item | → B1 | 3 | WIN-76 | n |
| A13 | The OID first-arc shortcut comment (`setup.go`) | ledger | done (`b44326e2` names the OIDs the one-byte first pair cannot encode); Task 0 confirms the commit is in `main` | - | - | - |
| A14 | The netsh cleanup's log line says "deleted" even when the delete failed (`setup_winrm_windows_test.go`) | ledger | fix (one line: "delete attempted") | 1 | - (log text) | y |
| A15 | A Task 4 commit carried Task 7 clean-test lines | ledger | decline: history; no rebase | - | - | - |
| A16 | The test `authorized_keys` line of `TestRealBothTransportsShareTheHelper` (`alice-w7-both`) is left on the runner | ledger | fix (cleanup restores `administrators_authorized_keys` as found; the clean test asserts no `alice-w7-both` line) | 1 | `TestRealRunnerIsClean` (WIN-74) | y |
| A17 | The setup script's no-listener and domain-account paths are untested on runners | ledger | decline: manual matrix (release checklist 8.3); the no-listener path would delete the image's listener, forbidden by W7's constraints | - | - | - |
| W6-* | "Minors deferred during W6" (18 rows) | `windows-iis.md` "Deferred to W7+" | done: every row is in R70's table; 12 fix tests verified at `fa182290` (Task 0) | 0 | - | - |
| F1 | `winhelper/status.go`: the `rdpCurrent` error branch is untested | R70 found-not-fixed Task 1 | fix (test) | 1 | `TestRDPStatusAbsentValueChecksTheStore` row (d): the store read fails → `""` (WIN-23) | y |
| F2 | CCS real fixture: `hasRecord` treats a listing error as "no record"; the teardown deletes a refused pre-existing `ccs:45480` record (`ccs_zz_shared_windows_test.go`) | R70 Task 3, final M2 | fix (`hasRecord` returns `(bool, error)` and fails the fixture; the teardown removes the record only when the fixture made it) | 1 | the CCS real fixture (WIN-47) | y |
| F3 | Import cycle `WebsitesPanel.tsx` → `DeployDialog.tsx` → `WebsitesPanel.tsx` | R70 Task 5 | fix (move `foreignAppText` to `web/src/components/foreignApp.ts`) | 3 | existing tests; `tsc` | n |
| F4 | The shellcheck pin lives in the Makefile and the wrapper's default (`deploy/dev/shellcheck.sh`); no test ties them | R70 Task 6 | fix (test) | 4 | `archtest:TestShellcheckPinsAgree` | n |
| F5 | `SetCCSPassword` seals before it validates (`ccs_password.go`) | R70 final M4 | fix (Ruling 11) | 2 | `TestSetCCSPasswordRefusesBeforeSealing` (a counting keyring fake; WIN-47) | n |
| F6 | The deploy dialog's opening-location summary stays after an untick (`DeployDialog.tsx`) | R70 final M5 | fix (summaries from the ticked places only, the opening kind first when ticked) | 3 | `DeployDialog.test.tsx` "an unticked opening binding leaves no summary of its kind" | n |
| F7 | `kv.auto_deploy_stopped` carries no `reason_variant` (`canary_auto.go`, `kv_autodeploy.go`) | R70 final M9 | decline: the wave path passes no `error_reason` at all; the canary path would need the failed deployments' location kinds; the code is right, the web overrides (R70 Ruling 6's reasoning) | - | - | - |
| F8 | The from-certificate summary (opened from a certificate, places picked) is untested | R70 owner item 7 | fix (test) | 3 | `DeployDialog.test.tsx` "opened from a certificate, a Windows place shows the Windows summary" | n |
| F9 | `internal/api:TestUnverifiedLicenseRefusesChangesAndKeepsUploadsWorking` failed once under `make ci` (expected 503, got 201) | R70 found-not-fixed | capture first (R67 rule): 10 runs with `-v` under a parallel `make test`; fix only a found root cause; else record "not reproduced" | 4 | the test itself, `-v` output in the rulings file | n |
| F10 | `rdpDenyReadMask` counts `FILE_READ_EA` and `FILE_READ_ATTRIBUTES` as read bits | R70 Task 3 | decline: errs on the safe side (R70 Ruling 4) | - | - | - |
| F11 | The take-back reports `rdp_key_acl_left` when a deny is added after the grant | R70 final M1 | decline: fail-closed by ruling | - | - | - |
| F12 | `web/node_modules` is an untracked symlink in a worktree | R70 found-not-fixed | decline: not code; never added; `rm web/node_modules` before handing over | 6 | `git status --short` clean of it | - |
| B1 | A web input for Alice's address (`from`) in both setup dialogs | W7 owner item; final review I1 | feature | 3, 5 | WIN-76 | n |
| B2 | Refuse a second live Windows target for one host across transports | W7 Ruling 3 gap; owner item 4 | feature (migration 00039, `ALC-WIN-0029`) | 2, 5 | WIN-77 | n |
| B3 | Remove a WinRM or CCS password (one shared implementation) | W5, W7 deferred | feature (DELETE endpoints, `rotated_at`) | 2, 3, 5 | WIN-78 | n |

---

### Task 0: Start the branch; confirm what is already done

**Files:** none.

- [ ] **Step 1:** `git log --oneline -1` in the worktree shows `fa182290` or a later `main`; `git merge-base --is-ancestor b44326e2 HEAD && git merge-base --is-ancestor d3cd8e21 HEAD && git merge-base --is-ancestor b2a15584 HEAD` (A13, A3, A4 done).
- [ ] **Step 2:** The W6 check: `grep -rl` for `TestProbeRDPNegotiationHonoursTheContext`, `TestModelRDPStalePinKeepsAFailure`, `TestModelReAddKeepsTheNetworkServiceGrant`, `TestMigration00037Down`, `TestRDPHelperDowngradeKeepsTheListener`, `TestRenderReasonVariant`, `TestCleanupPlanTrimsAdoptedEntries`, `TestRDPStatusAbsentValueChecksTheStore`, `TestDriftProbeCarriesTheStoredWarnings`, `TestCCSSkipNeedsAnUncutFile` each finds its file (planning found all ten). Record the list in the rulings file (Ruling 14).
- [ ] **Step 3:** Commit this plan: `docs: Windows servers phase W8 (debt and small features) plan (R72)`.

---

### Task 1: Go on watched paths: the emulator, `winhelper`, the real tests (A2, A6, A8, A14, A16, F1, F2)

**Files:**
- Modify: `internal/providers/windows/wintest/ntlm.go` (`field()`, A2); `internal/providers/windows/wintest/winrm.go` (the oversized-request answer, A6); `internal/providers/windows/setup_winrm_windows_test.go` (the netsh log line, A14; the `TestRealBothTransportsShareTheHelper` cleanup, A16; `TestRealWinRMSetupScript`, A8); `cmd/alice-winhelper/zz_runner_clean_windows_test.go` (A16); `cmd/alice-winhelper/ccs_zz_shared_windows_test.go` (`hasRecord`, the teardown; F2).
- Test: `internal/providers/windows/wintest/{ntlm,winrm}_test.go`; `internal/providers/windows/winrs/client_test.go`; `internal/providers/windows/winhelper/status_test.go`.

**Interfaces:** no exported change. `hasRecord` becomes `func() (bool, error)`; `createCCSSite` returns `made bool` to the caller, and `removeCCSSite` is called with it (the teardown deletes the record only when `made`).

- [ ] **Step 1: Write the failing tests.**
  - A2: a type 3 message whose field offset is `0xFFFFFFFF` is refused (401), never panics (`ntlm_test.go`; run also with `GOARCH=386 go vet ./internal/providers/windows/wintest/` for the conversion).
  - A6: `winrm_test.go`: the oversized request answers status 413 and an empty body; `client_test.go`: a server that answers 413 to a Send makes `Run` fail with the error the client's status switch gives (`client.go`: not 200, not 401/403 → the protocol path), after a Delete.
  - F1: `TestRDPStatusAbsentValueChecksTheStore` row (d): the fake's `rdpCurrent` read fails; `CurrentCertSHA256 == ""`.
  - A8: `TestRealWinRMSetupScript` runs the script a second time and asserts "Denying" appears in the first output and not in the second (log both). A16: the shared-helper test reads `administrators_authorized_keys` before, restores it in `t.Cleanup`; `TestRealRunnerIsClean` asserts no line contains `alice-w7-both`. F2: `hasRecord` error → the fixture fails "cannot list http.sys records: …"; a refused pre-existing record is not deleted by the teardown (assert by inspection: `removeCCSSite` is skipped when `made` is false).
- [ ] **Step 2: Run to verify they fail.** `go test -race -count=1 ./internal/providers/windows/wintest/ ./internal/providers/windows/winrs/ ./internal/providers/windows/winhelper/ -run 'NTLM|WinRM|RDPStatus'`. Expected: FAIL on A2, A6; F1 passes (missing coverage: show it fails against a local one-line break, then restore). The real tests' RED is run 1 (Ruling 2).
- [ ] **Step 3: Implement.** A2: `start := uint64(binary.LittleEndian.Uint32(...)); n := uint64(...Uint16(...)); if start > uint64(len(msg)) || n > uint64(len(msg))-start { return nil }`. A6: `w.WriteHeader(http.StatusRequestEntityTooLarge); return` with a comment "F26: Windows answers 413, no WS-Man fault". A14, A16, F2, A8 as Step 1 describes (A8's fix only on run 1's evidence; if the fragment text changes, refresh the SSH golden and say so in the commit).
- [ ] **Step 4: Run.** The Step 2 line, the Windows build and vet line, `make lint`. Expected: PASS; `wintest`, `winrs`, `winhelper` at or above their floors.
- [ ] **Step 5: Commit** per item: `fix(wintest): an oversized WinRM request is HTTP 413 as Windows answers (F26); NTLM field offsets are compared before conversion (R72)`; `test(winhelper): the RDP status row where the store read fails (R72)`; `test(windows,alice-winhelper): the shared-helper test restores the authorized_keys file; the CCS fixture fails on a listing error and never deletes a record it did not make; the WinRM script is run twice; the netsh log names the attempt (R72)`.

---

### Task 2: Inventory, API, migration 00039 (B2, B3 server side, F5)

**Files:**
- Create: `migrations/00039_windows_one_target_per_host.sql`; `migrations/windows_one_host_integration_test.go`.
- Modify: `internal/inventory/targets.go` (the two `targetColumns` subqueries gain `AND c.rotated_at IS NULL`; `closedTargetWriteError`); `internal/inventory/errors.go` (`ErrWindowsHostManaged`); `internal/inventory/ccs_password.go` (F5 in `setTargetPassword`; `clearTargetPassword`; `ClearCCSPassword`; the read filter of `targetPassword`); `internal/inventory/winrm_password.go` (`ClearWinRMPassword`); `internal/api/targets_handlers.go` (two DELETE routes; `clearTargetPassword` handler beside `setTargetPassword`); `internal/api/errors.go` (`ErrWINHostManaged`, the catalogue list, the mapping row); `internal/api/server.go` (the inventory interface gains `ClearCCSPassword`, `ClearWinRMPassword`); `api/openapi.yaml` (two `delete` operations; `POST /api/v1/targets` names 409 `ALC-WIN-0029`); `locales/common/{en,tr}.json`.
- Test: `internal/inventory/{windows,ccs_password,winrm_password}_integration_test.go`; `internal/api/errors_winserver_test.go`; `migrations/windows_one_host_integration_test.go`.

**Interfaces:**
- `inventory.ErrWindowsHostManaged = errors.New("inventory: a live Windows server with this host exists")` → `api.ErrWINHostManaged{Code: "ALC-WIN-0029", Reason: "windows.host_already_managed", Status: 409}`.
- `func (s *Service) ClearCCSPassword(ctx, a Actor, target uuid.UUID, ifVersion int) (Target, error)`; `ClearWinRMPassword` likewise; both call `clearTargetPassword(ctx, a, target, ifVersion, spec)` (Ruling 7). `targetPasswordSpec` gains `removed string` (the audit action).
- Routes: `DELETE /api/v1/targets/{id}/ccs-password`, `DELETE /api/v1/targets/{id}/winrm-password` (Ruling 10).

- [ ] **Step 1: Write the failing tests.**
  - `TestOneWindowsTargetPerHost` (`windows_integration_test.go`, the `iis-02` fixture): a second Windows target `IIS-02.corp.example` with `transport: winrm`, port 5986 → `ErrWindowsHostManaged`; same host, port 2222, ssh → the same; an Nginx target on that host → created; after `DeleteTarget` of the first, the WinRM one is created; a Windows target on another host → created. The API row (`errors_winserver_test.go`): 409 `ALC-WIN-0029`; a duplicate name still answers `ALC-TGT-0001`.
  - `TestMigration00039` (new file, `TestMigration00038Down`'s form): migrate to 00038, insert two live Windows targets on one host, `up` → SQLSTATE `Z1037`; remove one, `up` → the index exists; `down` → gone.
  - `TestClearTargetPassword` (`ccs_password_integration_test.go`, the `newCCSFixture`): set, then clear: the row has `rotated_at` set, `CCSPasswordSetAt` nil, `CCSPassword` answers `ErrNotFound` wrapping `ErrNoCCSPassword`, the audit holds `target.ccs_password_removed` with no secret, the version moved by one; a second clear changes nothing (version, audit count); a `PUT` after it sets a new live row and ends none other (one live row). The refusals: stale version → `ErrVersionMismatch`; an Nginx target → `ErrNotWindowsTarget`. `TestWinRMTargetAfterPasswordRemoval` (`winrm_password_integration_test.go`): after the clear, the provider's call refuses `windows.winrm_password_missing` (the existing `TestWinRMTargetWithoutPassword` shape). `TestSetTargetPasswordEndsTheOlderRow`: two `PUT`s leave one live row.
  - F5 `TestSetCCSPasswordRefusesBeforeSealing`: a keyring fake that counts `Seal`; an invalid password on a Windows target answers `ErrCCSPasswordInvalid` with 0 seals; a valid one seals once; an invalid password on an Nginx target answers `ErrNotWindowsTarget` (Ruling 9's order kept).
  - API (`errors_winserver_test.go`): `DELETE .../winrm-password` without step-up 403 `ALC-AUTH-0003`, without `If-Match` 412, with a token 403 `ALC-AUTH-0002`, success 200 with `winrm_password_set_at: null` and a new `ETag`; the same four for `ccs-password`.
- [ ] **Step 2: Run to verify they fail.** `go test -race -count=1 -tags integration ./internal/inventory/ ./migrations/ -run 'OneWindowsTargetPerHost|Migration00039|ClearTargetPassword|AfterPasswordRemoval|EndsTheOlderRow|RefusesBeforeSealing' && go test -race -count=1 ./internal/api/ -run 'WinRM|CCS|Host'`. Expected: FAIL each.
- [ ] **Step 3: Implement.** The migration (Ruling 5's `DO` block, then `CREATE UNIQUE INDEX targets_windows_host_live ON targets (lower(config->>'host')) WHERE type = 'windows' AND deleted_at IS NULL;`; Down: `DROP INDEX targets_windows_host_live;`). `closedTargetWriteError`: the `IsUniqueViolationOn(err, "targets_windows_host_live")` case first. `clearTargetPassword` and the `IS NULL` filters (Ruling 7). F5 (Ruling 11). The handler, routes, error code, catalogue list, mapping, OpenAPI. Texts (`locales/common`): `errors.windows.host_already_managed.title` EN "Alice already manages this Windows server." TR "Alice bu Windows sunucusunu zaten yönetiyor."; `.cause` EN "Another entry with the same address exists (over OpenSSH or WinRM). Two entries for one server would count twice against the licence and would both change the same bindings. Nothing was added." TR "Aynı adrese sahip başka bir kayıt var (OpenSSH ya da WinRM üzerinden). Bir sunucu için iki kayıt lisansta iki kez sayılır ve ikisi de aynı bağlamaları değiştirir. Hiçbir şey eklenmedi."; `.action` EN "Use the existing entry. To change its connection type, remove it first, then add the server again." TR "Var olan kaydı kullanın. Bağlantı türünü değiştirmek için önce kaydı kaldırın, ardından sunucuyu yeniden ekleyin."; `errors.windows.transport_immutable.action` EN "To use the other connection, remove this entry, then add the server again with it." TR "Diğer bağlantıyı kullanmak için bu kaydı kaldırın, ardından sunucuyu o bağlantıyla yeniden ekleyin." (Ruling 6).
- [ ] **Step 4: Run.** The Step 2 line, `go test -race -count=1 ./internal/inventory/ ./internal/api/ && make lint i18n-check`. Expected: PASS; `inventory` ≥ 89, `api` ≥ 95.
- [ ] **Step 5: Commit** per item: `feat(inventory,api,migrations): one live Windows server per host across transports, ALC-WIN-0029 (migration 00039) (R72)`; `feat(inventory,api): remove a CCS or WinRM password: DELETE with step-up ends the live rows (R72)`; `fix(inventory): a password outside the rule is never sealed (R70 final review M4) (R72)`.

---

### Task 3: Web and e2e (B1, B3 web, A9, A10, F3, F6, F8)

**Files:**
- Create: `web/src/components/foreignApp.ts` (F3).
- Modify: `web/src/api/endpoints.ts` (`getWinRMSetup(id, from?)`, `getPlatformKey(from?)` add `?from=` when given); `web/src/components/AddServerModal.tsx` (the address input beside `ProfileScript` and inside `WinRMSetupScript`; query keys include the address; A9, A10 texts); `web/src/pages/TargetDetailPage.tsx` (the modal uses `WinRMSetupScript`, which now owns the input); `web/src/components/CCSPasswordPanel.tsx` (the Remove button, `clear` per kind in `KINDS`); `web/src/components/DeployDialog.tsx` (F3, F6); `web/src/components/WebsitesPanel.tsx` (F3); `web/src/locales/{en,tr}.json`; `web/e2e/windows-winrm.spec.ts` (the removal step).
- Test: the dialog's test file (`AddServerModal.test.tsx`), `CCSPasswordPanel.test.tsx` (or the panel's cases), `DeployDialog.test.tsx`.

**Interfaces:** `clearCCSPassword(id, version)`, `clearWinRMPassword(id, version)` in `endpoints.ts` (`DELETE`, `If-Match`, answer `Target`). `KINDS[kind].clear`. `WinRMSetupScript({ targetId })` keeps its props and owns an address field. `foreignAppText` moves to `foreignApp.ts`; `WebsitesPanel.tsx` and `DeployDialog.tsx` import it from there.

- [ ] **Step 1: Write the failing tests.**
  - B1: typing `10.0.0.5` in the address field calls `getPlatformKey('10.0.0.5')` (mock) and re-renders the script; in the WinRM phase, `getWinRMSetup(id, '10.0.0.5')`; an API 422 with field `from` shows its text and no script; an empty field calls without `from`.
  - B3: the panel with `*_password_set_at` set shows "Remove password"; confirming calls `clearWinRMPassword(id, version)` through `run` (step-up) once; the answer updates the state to "not set"; with nothing set the button is absent.
  - A9: a refused test after `passwordSaved` shows `targets.winrm.failedAfterPassword`. A10: the `winrm` phase shows `targets.winrm.closeWithoutPassword`.
  - F6: opened from binding X of a Windows server, X unticked, a CCS file ticked: the summaries are `summaryCCS` only. F8: opened from a certificate (no `location`), a Windows binding picked: `summaryWindows` once.
- [ ] **Step 2: Run to verify they fail.** `cd web && npx vitest run src/components/AddServerModal.test.tsx src/components/CCSPasswordPanel.test.tsx src/components/DeployDialog.test.tsx` (the real file names as found). Expected: FAIL.
- [ ] **Step 3: Implement.** F6: `const ordered = location && targets.includes(location) ? [location, ...targets.filter((l) => l !== location)] : targets; const summaries = [...new Set(ordered.map(summaryKey))];`. The Remove button uses the house confirm pattern the target page uses for Remove server. Texts (`web/src/locales`): `targets.form.aliceAddress` EN "Alice's address (optional)" TR "Alice'in adresi (isteğe bağlı)"; `targets.form.aliceAddressHelp` EN "The IP address the server sees Alice connect from. With it, the script opens the port (22 or 5986) in the firewall to that address only; without it, to any address until you set $AliceAddress in the script." TR "Sunucunun Alice'in bağlandığını gördüğü IP adresi. Girilirse betik güvenlik duvarında bağlantı noktasını (22 ya da 5986) yalnızca bu adrese açar; girilmezse betikte $AliceAddress değerini belirleyene kadar her adrese açar."; `targets.winrm.setupHelp` (replace "opens port 5986 in the firewall to any address until you set $AliceAddress in the script" with "opens port 5986 in the firewall to Alice's address when you entered one above, otherwise to any address until you set $AliceAddress in the script"; TR likewise); `targets.form.scriptWindowsHelp` gains "With Alice's address above, the key line and the firewall rule accept that address only." TR "Yukarıda Alice'in adresi girildiyse anahtar satırı ve güvenlik duvarı kuralı yalnızca o adresi kabul eder."; `targets.winrm.failedAfterPassword` EN "The password is saved. If the server refused the sign-in, compare the password with the one set on the server, then use Test connection on the server's page." TR "Parola kaydedildi. Sunucu oturum açmayı reddettiyse parolayı sunucuda belirlenenle karşılaştırın, ardından sunucunun sayfasında Bağlantıyı sına'yı kullanın."; `targets.winrm.closeWithoutPassword` EN "If you close now, Alice keeps the server without a password and cannot reach it. You can set the password later on the server's page." TR "Şimdi kapatırsanız Alice sunucuyu parolasız tutar ve ona ulaşamaz. Parolayı daha sonra sunucunun sayfasında belirleyebilirsiniz."; `ccs.remove` EN "Remove password" TR "Parolayı kaldır"; `ccs.removeConfirm` EN "Remove the CCS password of this server? Alice then lists and deploys no CCS file until a new password is set." TR "Bu sunucunun CCS parolası kaldırılsın mı? Yeni bir parola belirlenene kadar Alice hiçbir CCS dosyasını listelemez ve dağıtmaz."; `winrm.removeConfirm` EN "Remove the WinRM password of this server? Alice cannot reach the server until a new password is set." TR "Bu sunucunun WinRM parolası kaldırılsın mı? Yeni bir parola belirlenene kadar Alice sunucuya ulaşamaz."; `ccs.removed` EN "Removed." TR "Kaldırıldı."; `audit.actions.target_ccs_password_removed` EN "CCS password of a Windows server removed" TR "Bir Windows sunucusunun CCS parolası kaldırıldı"; `audit.actions.target_winrm_password_removed` EN "WinRM password of a Windows server removed" TR "Bir Windows sunucusunun WinRM parolası kaldırıldı".
- [ ] **Step 4: e2e.** `windows-winrm.spec.ts` gains a last step: on the server page, Remove password (step-up with a fresh code, as `setPassword` does), the state reads "not set", Test connection fails with `ALC-WIN-0025`; the comment's job count moves from five to six. Run `make helper winhelper && E2E_PROJECT=alice-e2e-w8 ALICE_E2E_PORT=9986 make e2e-up e2e; E2E_PROJECT=alice-e2e-w8 make e2e-down` when the machine is free.
- [ ] **Step 5: Run.** The Step 2 line, `npx tsc --noEmit && npm run lint`, `make i18n-check`. Expected: PASS.
- [ ] **Step 6: Commit:** `feat(web): Alice's address in both setup dialogs reaches the served scripts (R72)`; `feat(web): remove a CCS or WinRM password from the server page, with step-up (R72)`; `fix(web): the WinRM dialog says what a close without a password means and what a refused sign-in needs; the deploy summary follows the ticked places; foreignAppText has its own module (R72)`.

---

### Task 4: Tooling and the flake capture (F4, F9)

**Files:** `internal/archtest/windowsci_test.go` (or the archtest file that already reads the Makefile; F4); the rulings file (F9's record).

- [ ] **Step 1 (F4):** `TestShellcheckPinsAgree`: read `Makefile`'s `SHELLCHECK_IMAGE ?= …` and `deploy/dev/shellcheck.sh`'s `${SHELLCHECK_IMAGE:-…}` default; assert equal. RED: change one locally, see it fail, restore.
- [ ] **Step 2 (F9):** with `make test` running in another shell, run `go test -race -count=10 -tags integration -v -run TestUnverifiedLicenseRefusesChangesAndKeepsUploadsWorking ./internal/api/ 2>&1 | tail -60`. A failure: keep the `-v` output in the rulings file, find the root cause (the test holds the license row `FOR UPDATE` and expects `Tick` to leave the state unverified; the 201 means the handler saw a verified state), fix in its own commit with a test. No failure in 10 runs: record "not reproduced", no change.
- [ ] **Step 3: Run.** `go test -race -count=1 ./internal/archtest/ && make lint`. Expected: PASS.
- [ ] **Step 4: Commit:** `test(archtest): the shellcheck wrapper's default pin equals the Makefile's (R72)` (+ the F9 fix if any).

---

### Task 5: Documents; push 1

**Files:**
- `docs/superpowers/specs/alice-v1/00-decisions.md`: R72 after R71 in R71's form: the owner's instruction (2026-10-31, "start W8 and finish it"); the debt dispositions in one sentence (17 fixed, 10 declined, 3 done); the three features with their rules (Rulings 3-10); `ALC-WIN-0029`; `WIN-76..78`; migration 00039 and `Z1037`; the helper unchanged.
- `docs/superpowers/specs/alice-v1/06-quality.md` §24.7 heading and the §24 intro line gain R72; rows:

| ID | Case | Expected |
|---|---|---|
| WIN-76 | Alice's address typed in the Add server dialog (OpenSSH and WinRM) or the server page's script modal | The served script's `$AliceAddress` (and the SSH key line's `from=`) holds the address; the firewall rule accepts it only; a bad address shows the API's `from` field error and no script; an empty field gives today's script with its warning |
| WIN-77 | A second live Windows target for a host Alice already manages (the other transport, another port, another case) | `ALC-WIN-0029`, nothing added; an Nginx target on that host, or a Windows target after the first is removed, is created; migration 00039 refuses with `Z1037` while a pair exists |
| WIN-78 | `DELETE .../winrm-password` or `.../ccs-password` by an Administrator with step-up and `If-Match` | The live rows are ended (kept, never deleted), the target's `*_password_set_at` is null, audited without the secret; a WinRM target refuses every call with `ALC-WIN-0025` until a new password; a repeat is 200 and changes nothing; a later `PUT` works |

- `test/matrix/traceability.json`: `WIN-76` (the dialog's vitest cases), `WIN-77` (`internal/inventory:TestOneWindowsTargetPerHost`, `migrations:TestMigration00039`), `WIN-78` (`internal/inventory:TestClearTargetPassword`, `TestWinRMTargetAfterPasswordRemoval`, `web/e2e/windows-winrm.spec.ts`); `WIN-23`, `WIN-47`, `WIN-69`, `WIN-70`, `WIN-73`, `WIN-74` gain the strengthened tests. `docs/security/traceability.md` regenerated (`go run ./tools/matrixcheck … -update`).
- `docs/superpowers/specs/alice-v1/04-security.md` §14.4: `WN-26`'s mitigation "the firewall rule opens 5986 to Alice's address only" becomes "…to Alice's address when the Administrator enters it in the dialog (W8), else to any address with a printed warning"; `WN-29` gains "the password can be removed (the row is ended, its ciphertext kept sealed)".
- `docs/superpowers/specs/alice-v1/03-integrations.md`: §13A.22 "One Windows server per host; removing a password; Alice's address in the setup dialogs (amendment, R72)".
- `docs/superpowers/specs/2026-10-21-windows-iis-target-design.md`: §13 gains "Phase W8 (R72)" as a line; "## 23. Phase W8 as built" placeholder after §22 (filled in Task 6).
- `docs/windows-host-preparation.md` (watched: rides push 1): the Servers page now takes the address; the WinRM script's `$AliceAddress` from the dialog; "The password" section (removal and its effect); a sentence under "WinRM transport" that one entry per server is allowed and how to change the transport (remove, then add).
- `docs/admin-guide.md` "Windows servers": the address field, removing a password, one entry per server, the flipped transport-change order. `docs/operator-guide.md`: the upgrade note for 00039. `docs/upgrade.md`: 00039's refusal and the query. `docs/troubleshooting.md`: `## ALC-WIN-0029`, `ALC-WIN-0027`'s action re-worded, `ALC-WIN-0025` gains "or the password was removed".
- `api/openapi.yaml`: checked in Task 2 (the DELETEs, 409 on `POST /targets`). `CHANGELOG.md`: "## Unreleased — W8 (Windows debt and small features, R72)": **Added** (the address field; one server per host; password removal), **Changed** (the transport-change order; the 413 emulator; `ALC-WIN-0027` text), **Fixed** (the dialog texts, the deploy summary, the seal order, the test fixes).
- `docs/superpowers/rulings/windows-iis.md`: the heading `# W8 (R72)` with the rulings as built, the item table's dispositions, the Turkish texts table, the runner-run table (filled as runs happen), "Owner items (W8)", "Deferred to W9+" (everything under "Not in W8").

- [ ] **Step 1:** Write; `go test ./tools/matrixcheck/ && make matrix-check MATRIXCHECK_FLAGS=-strict docs-check i18n-check`. Expected: PASS, 0 gaps, 0 pending.
- [ ] **Step 2: Commit:** `docs: Windows servers phase W8 (R72): decision, rulings, WIN-76..WIN-78, security and integration amendments, the guides, troubleshooting, changelog`.
- [ ] **Step 3: Push 1.** `pgrep` shows nothing heavy; `git push -u origin windows-w8` (the coordinator has pushed the branch first). Watch `windows.yml` (run 1): both legs and `windows-required` green. A red leg: capture the failing test's output, fix in its own commit; A8's second-run evidence decides its fix here.

---

### Task 6: Final gates, final review, as built

**Files:** none new; fixes go to the task that owns the code.

- [ ] **Step 1: Full local gates.** `go mod tidy && git diff --exit-code go.mod go.sum && make lint && make test && make i18n-check && make matrix-check MATRIXCHECK_FLAGS=-strict && make docs-check && make helper winhelper && make build && make coverage`. Expected: PASS; every floor met, none lowered.
- [ ] **Step 2: Windows build and vet** (the line of Global Constraints). Expected: PASS.
- [ ] **Step 3: e2e and image.** Only when no other `make ci` or Docker-based run is active: `E2E_PROJECT=alice-e2e-w8 ALICE_E2E_PORT=9986 make ci`. Record the e2e totals; `secrets-scan` scans N > 0 commits.
- [ ] **Step 4: Real Windows.** The `windows.yml` run of the branch's code head is green on both legs with `windows-required`, at most 4 runs. Record the runner-run table.
- [ ] **Step 5: gitleaks** over `fa182290..HEAD` with `make secrets-scan`; fingerprint nothing that holds key material; no password literal in tests.
- [ ] **Step 6: Independent review** of `fa182290..HEAD` against Review Focus 1-5 and Rulings 4-11, by a reviewer that wrote none of it, given the code and the item table, not the conclusions. Fix every Critical and Important in its own commit; a fix on any path makes push 2 (run 2, Ruling 2). List declined Minors with reasons under "Final review fixes (W8)".
- [ ] **Step 7: Acceptance**, one line each in the rulings file, then fill "## 23. Phase W8 as built": every item of the table has its disposition and test; `WIN-76..78` green; the address reaches both scripts; one live Windows target per host, `ALC-WIN-0029`, 00039; the password removal with step-up, ended rows kept; the helper unchanged at 1.2.0; the runs used. `rm web/node_modules` if present; `git status --short` clean. Hand `windows-w8` to the coordinator. Do not merge or push `main`.

---

## Not in W8 (the boundary; stays deferred, carried to W9+)

PSRP and JEA; Kerberos and UPN names; CredSSP; client-certificate mapping; NTLM channel binding (`CbtHardeningLevel` Strict); tlspin's CA-bundle mode for WinRM; Alice rotating the Windows password; changing a target's transport (the way stays remove-then-add); the CCS farm layout; CCS file creation; RD Gateway, RD Web Access, RD Connection Broker and RemoteApp certificates and the other "Not in W6" items; the manual matrix rows (8.1-8.8); an ARM64 runner leg; anything that needs a helper protocol change (none was needed); R70's class B and C boundary; the items R70 and this plan declined; a domain account on a runner; Server Core and Windows Server 2019 over WinRM.

## Execution notes for the implementer

- Dispatch order: 0 → (1 ∥ 2 ∥ 3 ∥ 4) → 5 → 6. Tasks 1-4 touch disjoint files; Task 3's B3 web work codes against the contract of Ruling 10 (mocked), so it does not wait for Task 2. A repo-wide `make lint` or `go test` during parallel Go tasks may read a half edit: run Tasks 1, 2 and 4 one after another if the same machine runs them (R70 Ruling 13).
- Runner runs (budget 4): push 1 after Task 5 (every watched change of the batch), push 2 after Task 6's review fixes, two spares. Any push of this branch runs the legs (R70 Ruling 25): never push a docs-only commit to "save" a run; leave it local for the coordinator's merge.
- Review gates: after Tasks 2 and 3, a review against Review Focus 1-3 before Task 5.
- Record every ruling made during execution under "W8 (R72)", one line each: the ruling, then why.
- Commit with `git -c user.name="Eren Altan" -c user.email="erenaltan@gmail.com" commit --only …` and the trailer `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`; subjects end with `(R72)`.

## Owner items (W8)

1. **Ruling 4-5, the second-target rule:** one live Windows server per host (textual `lower(host)`, any port, both transports); existing pairs stop the upgrade at 00039 until one is removed.
2. **Ruling 6:** `ALC-WIN-0027`'s advice becomes "remove, then add" (the old order is refused by Ruling 4).
3. **Rulings 7-9, password removal:** the rows are ended and kept sealed (not erased from the database or backups); a repeat removal is 200 and changes nothing; a WinRM server then refuses every call with `ALC-WIN-0025`; a CCS server lists no file.
4. **Ruling 3:** the address field appears beside every setup script (Linux types included) and in the server page's script modal.
5. **Ruling 11:** a password outside the rule is no longer sealed; the error order of R70 Ruling 9 is unchanged.
6. **Ruling 13, the declines**, A1, A5, A7, A11, A15, A17, F7, F10, F11, F12, with their reasons.
7. **The Turkish texts** of Tasks 2 and 3 (the rulings file quotes every EN/TR pair).
8. **A8's verdict** from run 1 (whether the deny-rights fragment prints "Denying" on a second run, and the SSH golden change if it did).

## Files touched (merge order and parallel safety)

| Task | Files |
|---|---|
| 1 | `internal/providers/windows/wintest/{ntlm,winrm}.go` and tests, `internal/providers/windows/winrs/client_test.go`, `internal/providers/windows/winhelper/status_test.go`, `internal/providers/windows/setup_winrm_windows_test.go`, `cmd/alice-winhelper/{zz_runner_clean,ccs_zz_shared}_windows_test.go` |
| 2 | `migrations/00039_windows_one_target_per_host.sql` (new) and its test, `internal/inventory/{targets,errors,ccs_password,winrm_password}.go` and tests, `internal/api/{targets_handlers,errors,server}.go`, `internal/api/errors_winserver_test.go`, `api/openapi.yaml`, `locales/common/{en,tr}.json` |
| 3 | `web/src/api/endpoints.ts`, `web/src/components/{AddServerModal,CCSPasswordPanel,DeployDialog,WebsitesPanel}.tsx`, `web/src/components/foreignApp.ts` (new), `web/src/pages/TargetDetailPage.tsx`, `web/src/locales/{en,tr}.json`, their tests, `web/e2e/windows-winrm.spec.ts` |
| 4 | `internal/archtest/windowsci_test.go` |
| 5 | `docs/superpowers/specs/alice-v1/{00-decisions,03-integrations,04-security,06-quality}.md`, `docs/superpowers/specs/2026-10-21-windows-iis-target-design.md`, `test/matrix/traceability.json`, `docs/security/traceability.md`, `docs/{admin-guide,operator-guide,upgrade,windows-host-preparation,troubleshooting}.md`, `CHANGELOG.md`, `docs/superpowers/rulings/windows-iis.md` |
| 6 | the rulings file, the design's §23 |
