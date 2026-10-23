# Windows Servers, Phase W3 (Drift and Cleanup) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A Windows binding bound to an ACME or Key Vault certificate is watched like a Linux file (R52): re-pointed outside Alice it is `drifted` and `auto` repairs it through the deployment engine, flapping backs off, and a certificate removed from the store or a key http.sys can no longer use is reported with its Windows cause (never "repaired" into a failure loop); notices and e-mails speak of bindings, not files. A daily `windows.cleanup` job removes from the machine store only the certificates Alice imported that no http.sys binding, RDP, WinRM or live journal uses and that no rollback can need, removes a compromised one at once after its incident replaced it (§15 Q7), bounds the helper's journals and fence tombstones, and the dump shows which certificates Alice imported.

**Architecture:** Drift needs no new engine path: `drift.observe` already scans a Windows server through `Discover` + `Reconcile` (the file fact) and probes through the Windows provider's `VerifyDeployment` (the TLS fact); W3 adds a Windows-only scan rule (a bound binding that loses its certificate or key was changed outside Alice), a derived drift cause, Windows texts and tests on the emulator. Cleanup is a new protocol-1 subcommand `iis-cleanup --plan | --apply` whose rules live in platform-neutral `winhelper` code behind five new `WriteHost` methods (the real helper and `wintest` implement them), an optional provider interface `providers.CertificateCleaner` implemented by `internal/providers/windows`, Alice's own judgement in `internal/inventory` (rollback window, running deployments, what locations show, compromised certificates, the per-server switch) and a job package `internal/jobs/winjobs` (`windows.cleanup`, `windows.cleanup_schedule`). No migration.

**Tech Stack:** Go 1.27.3 (`golang.org/x/crypto/ssh`, `golang.org/x/sys/windows` and `.../registry`, pgx/v5, testcontainers), PostgreSQL, React 18 + Mantine + TanStack Query + i18next, Vitest, Playwright, GitHub Actions `windows-2022` / `windows-2025` runners.

**Spec:** `docs/superpowers/specs/2026-10-21-windows-iis-target-design.md` (this phase is §13 "Phase W3" and its acceptance list; it draws on §5, §6.2 item 4, §6.6, §6.7, §7, §8, §9, §11 (AD CS autoenrolment row), §12 items 3-4, §15 Q6, Q7, Q10, §16 and §17). W1 and W2 rulings and the "Deferred to W3" list: `docs/superpowers/rulings/windows-iis.md`. R52 as built: `docs/superpowers/specs/alice-v1/00-decisions.md` R52, `docs/superpowers/rulings/certificate-drift.md`, `internal/inventory/drift*.go`, `internal/jobs/driftjobs`. Model plan for format: `docs/superpowers/plans/2026-10-22-windows-w2-deployment-verification-rollback.md`. The owner approved W0-W4 with the §15 defaults on 2026-10-22.

**Scope:** design §13 W3 only: R52 for `win_sslbinding` locations, the Windows causes in notices and e-mails, `iis-cleanup` and `windows.cleanup`, the incident cleanup rule, the journal and tombstone bounds, `alice_imported` in the dump, and the W2 items deferred here (each settled in Ruling 23). Not in scope: required real-Windows checks and the release bundle (W4), CCS, RDP deployment, WinRM transport (W5-W7).

**Decision:** R62 "Windows server target, phase W3: drift and cleanup" (R61 is the last entry of `00-decisions.md`). **Size:** M, 13 tasks. **Migration:** none (Ruling 1).

## Before you start: what W3 must measure on a runner

W0 F4 showed that deleting the CNG key and the certificate leaves the key unopenable. Two facts are new and are checked by Task 5's real tests before the code depending on them is claimed done. Record each verdict as a ruling under the "W3" heading of `docs/superpowers/rulings/windows-iis.md`.

| Fact | What W3 relies on | If it is wrong | Tasks |
|---|---|---|---|
| F11 | `CryptAcquireCertificatePrivateKey(CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG)` then `NCryptDeleteKey` removes the key file of an imported certificate (`C:\ProgramData\Microsoft\Crypto\Keys`), and `CertDeleteCertificateFromStore` of a duplicated context then removes the certificate; neither touches another certificate's key. | Delete the key through the `CERT_KEY_PROV_INFO_PROP_ID` container name with `NCryptOpenKey(MS_KEY_STORAGE_PROVIDER, NCRYPT_MACHINE_KEY_FLAG)`; record the route. | 2, 5 |
| F12 | The RDP listener's certificate is `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp` value `SSLCertificateSHA1Hash` (REG_BINARY, absent when RDP uses its self-signed certificate) and each WinRM HTTPS listener's is `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Listener\*+HTTPS` value `certThumbprint`; on the images the WinRM value equals the hash of the http.sys record `0.0.0.0:5986` (W0 F8). | Read the WinRM listener's thumbprint only from its http.sys record (already protected by rule 2) and record that the registry route is unavailable; RDP stays the registry value. | 2, 5 |

## Global Constraints

- **Branch.** Worktree branch `windows-w3` cut from `main` at `e21e1ba3` or later. Never switch branches inside a task. `git merge main` to take `main` in, never rebase. The executor may push `windows-w3` (only that branch) so `.github/workflows/windows.yml` runs on the real runners; it never pushes `main`. The coordinator merges to `main` and pushes.
- **Commits.**
  - `git -c user.name="Eren Altan" -c user.email="erenaltan@gmail.com" commit --only -m "<subject>" -m "Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>" -- <paths>`; every subject ends with `(R62)`.
  - New files: `git add -- <path>` first. Never `git add -A` or `git add .`. Check `git status --short` before each commit.
  - Never touch `.claude/`, the untracked PDFs, `alice-helper` (untracked binary at the root) or `docs/security/reviews/independent-audit*` and the other untracked review files.
  - `.gitleaksignore` is pinned to commit hashes: never rebase, squash or amend a pushed commit. A test that needs a key generates it at run time (`internal/testutil/pki`); never commit PEM or PFX key material. If gitleaks flags a test table, follow commit `4d5f2eff` (fingerprint in `.gitleaksignore`, no key material).
- **Security guards that must stay green.** `TestNoCodeAcceptsAnyHostKey`; `tools/pincheck`; `TestOnlyTheTypeListNamesWebServerTypes`; `TestImportRules` and `TestAllowed` (`internal/archtest/arch_test.go`; `internal/jobs/winjobs` falls under the existing `alice/internal/jobs/...` rule); `TestWindowsHelperLinksOnlyItsProtocol` (W3 adds nothing to its list: `golang.org/x/sys/windows/registry` is already allowed); `TestReleaseBinariesLinkNoTestPackages` (the `alicetest` clock hook of Task 5 never ships); `TestNoWindowsReservedFileNames`; the archtest guard that only `internal/providers/windows` and `linuxssh` call `linuxssh.ForcedCommand`.
- **Protocol.** `winproto.Protocol = 1`, `MinProtocol = 1` stay. `winproto.Version = "0.3.0"`; `1.0.0` stays reserved for W4's release. New subcommand `iis-cleanup` with exactly one of `--plan`, `--apply`. A `0.2.0` helper answers it `UNKNOWN_SUBCOMMAND` (exit 2, nothing changed): Alice refuses before sending to a helper older than `winproto.CleanupMinVersion = "0.3.0"` (`windows.helper_outdated`), and the write subcommands keep `WriteMinVersion = "0.2.0"` (a W2 helper still deploys).
- **Paths.** As W2: journal `C:\ProgramData\Alice\helper\journal\<op>.json`, binding records `...\helper\bindings\<hash>.json`, import inventory `...\helper\imports.json`, lock `...\helper\helper.lock`; every state file written temp, flush, `MoveFileEx(MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)`. Event source `Alice Helper`: 1001 deploy, 1002 restore (W2), **1003 certificate removed** (W3).
- **Error codes.** Existing `ALC-WIN-0001..0012`. New (Task 10): `ALC-WIN-0013` `windows.drift_not_repairable` (409), `ALC-WIN-0014` `windows.cleanup_outcome_unknown` (502, retryable).
- **No migration** (Ruling 1). If a task finds it needs schema, stop and add a ruling; the next free number is `00032`.
- **Coverage floors** (`coverage-floors.json`; never lower one): `winproto` 100, `winhelper` 95, `windows` 95, `wintest` 90, `cmd/alice-fakewindows` 90 (unchanged); new `alice/internal/jobs/winjobs` 95. No floor for `cmd/alice-winhelper`.
- **Locales.** EN and TR in `locales/common/{en,tr}.json` and `web/src/locales/{en,tr}.json`, identical keys and placeholders (`make i18n-check`). Turkish never puts a suffix on `{{software}}` or on a placeholder holding a binding text.
- **Real-Windows runs.** Budget **10 runs** of `windows.yml` for the phase. Real fixtures use ports **45390-45398** (W1 holds 45301-45320 and 45399, W2 45330-45389), certificates and sites prefixed `alice-w3-`, a data directory of the test's own under `C:\ProgramData\Alice\helper-test-<random>`; a test never leaves an http.sys record, a certificate, a key, an intermediate, a site, a data directory or a registry value behind (W2 Ruling 22): cleanup registered before the fixture is made, `TestRealRunnerIsClean` extended to 45390-45398 and `alice-w3-`. No test writes the RDP or WinRM registry values (Ruling 22).
- **e2e.** `E2E_PROJECT=alice-e2e-w3 ALICE_E2E_PORT=9976 make e2e-up e2e; E2E_PROJECT=alice-e2e-w3 make e2e-down`. Docker-based Go runs and Playwright never run at the same time.
- **Verification commands.**
  - `go build ./... && go vet ./... && go vet -tags integration ./...`
  - `GOOS=windows GOARCH=amd64 go build ./cmd/alice-winhelper/ ./internal/providers/windows/... && GOOS=windows GOARCH=arm64 go build ./cmd/alice-winhelper/ && GOOS=windows go vet ./cmd/alice-winhelper/ ./internal/providers/windows/... && GOOS=windows go vet -tags alicetest ./cmd/alice-winhelper/`
  - `go test -race -count=1 ./<pkgs>`; `go test -race -count=1 -tags integration ./<pkgs>`
  - `make lint`, `make test`, `make i18n-check`, `make matrix-check`, `make docs-check`; final `make coverage` and `make ci`
  - web: `cd web && npx vitest run <files> && npx tsc --noEmit && npm run lint`
  - A helper change regenerates checksums: `make helper winhelper`.

## Rulings (where the spec is silent; each goes into `docs/superpowers/rulings/windows-iis.md` under a new "W3 (R62)" heading for the owner to confirm)

1. **Decision R62, no migration.** The per-server switch is a `targets.config` key (jsonb); drift uses the existing columns (`changed_outside_at`, `problem`, `key_problem`, `location_observations`); the import inventory and journals are server files (design §5: no table for imports); the Q7 notice is made once by the job's dedupe key instead of a new `alerts.kind` (whose CHECK would need a migration). Error codes continue at `ALC-WIN-0013`; test IDs at `WIN-29`; STRIDE rows at `WN-14`.
2. **Protocol 1, helper 0.3.0, `CleanupMinVersion` 0.3.0.** `iis-cleanup` is additive and nothing was released (W1 Ruling 2), so the protocol number stays and Alice gates the feature by helper version, as W2 gated writing. The provider refuses a helper below `CleanupMinVersion` before sending (`windows.helper_outdated`, params `helper_version`, `required_version`); the backstop `UNKNOWN_SUBCOMMAND` maps to the same reason. W1's `TestFidelityVersionAndRefusals` swaps its unknown-subcommand probe from `iis-cleanup` to `rdp-deploy` (W6's future name, still unknown).
3. **Command line and standard input; no operation id.** `iis-cleanup --plan` and `iis-cleanup --apply`; their inputs are JSON on standard input (`winproto.CleanupPlanInput`, `CleanupApplyInput`, at most `MaxCleanupInput` = 64 KiB). Cleanup has no journal and no fence: `--apply` judges every rule again under the helper lock at the moment it runs and removing an absent certificate answers `absent`, so a repeated or late apply is harmless (unlike a deployment, it never acts on a state read earlier).
4. **Two judges, both must agree.** The helper decides what only the server knows (rule 1: Alice imported it; rule 2: no http.sys record of any application, no RDP or WinRM listener names it; rule 3's live journals; rule 4's age by its own clock). Alice decides what only Alice knows (rule 3's "no deployment may still roll back to it", running deployments, what its locations show, compromised certificates for Q7, the switch). A certificate is removed only when both hold at apply time.
5. **Alice imported (rule 1).** A certificate counts as Alice's when (a) `imports.json` lists it, or (b) a journal written by a 0.3.0 helper names it as `new_sha1` with its **"existed" record** `false` (the prepared journal records, before any import, whether the store already held that certificate); **and** in both cases the store copy's friendly name is Alice's form ending in that entry's operation (`Alice ... <op8>`). A W2 journal has no "existed" record and never counts (the kill between `ImportPFX` and `recordImport` it could reveal stays kept, the safe side). `WriteHost.ImportPFX` gains an `existed` result (`CERT_STORE_ADD_NEW` met the certificate already): such an import is never recorded as Alice's, which closes W2's existing-copy race; a third party's identical copy keeps its own friendly name, so (a) and (b) both fail on it.
6. **In use (rule 2).** Any http.sys record of any application whose hash is the certificate's SHA-1 (any store: conservative), the RDP listener's `SSLCertificateSHA1Hash` and every WinRM HTTPS listener's `certThumbprint` (F12) keep it. If the bindings or either registry value cannot be read, the plan and the apply refuse with `IO_ERROR` and remove nothing. `win-facts` is unchanged (its only W3 consumer would be cleanup, which reads them itself).
7. **Live journals (rule 3, helper half).** A journal in `prepared`, `writing`, `restoring` or `restore_failed` naming the certificate as previous or new keeps it. A journal the helper cannot decode keeps **every** candidate of that run (warning `journal_unreadable` in the plan), until pruning removes it (Ruling 11). `committed`, `unchanged`, `restored`, `restore_forbidden` and `fenced` are final; the rollback window after a final deployment is Alice's (Ruling 8).
8. **Age (rule 4) and the rollback window (rule 3, Alice's half; §15 Q6).** Each plan stamps `unbound_since` (RFC 3339 UTC, the helper's clock) on every Alice-imported certificate it finds unused and clears it on one it finds used; an `unbound_since` in the helper's future is reset to now (a clock that jumped back never shortens the wait). Eligible: `aged` when unused for at least `winproto.CleanupMinAge` = 7 days, `expired` when its `NotAfter` is before the helper's now. Alice adds: no deployment of the target finished less than `inventory.CleanupRollbackWindow` = 7 days ago with the certificate as its new or previous fingerprint, no unfinished deployment of the target names it, no location of the target (not missing) holds it (`certificate_id` or `deployed_fingerprint`). Why the helper's clock: a binding re-pointed outside Alice leaves no trace in Alice's deployments; "replaced at least 7 days ago" is "found unused by daily plans for 7 days".
9. **Incident rule (§15 Q7).** A certificate Alice holds as compromised (`certificates.compromised`) is removed at once (reason `incident`: no age, and the rollback window does not apply because R48 forbids any rollback to it) when the helper finds it Alice's and unused and no unfinished deployment of the target names it. Alice asks the helper about each compromised certificate the target ever held (`watch`: compromised certificates named by a deployment or a location of the target, at most `MaxForbidden`). When an incident location on a Windows server reaches `verified` or `unverified`, the incident engine queues a `windows.cleanup` for that server with payload `incident_id` at once (dedupe `windows.cleanup:<target>:incident:<incident>`); that job, and only it, sends one notice `windows.compromised_in_store` to the server's and the certificate's services when a watched compromised certificate is still in a store afterwards (not Alice's, or still used), naming store and thumbprint. Unverified counts like verified: the compromised certificate is out of the binding either way.
10. **Removal.** Per certificate: the CNG key first (F11), then the certificate, then its `imports.json` entry, then the `chain` of every binding record that names its DER SHA-256 is cleared (the next deployment of it makes a same-hash write); then event 1003 `removed store <store> sha1 <sha1> sha256 <sha256> reason <reason>`. Key first, because a kill between the two leaves a certificate without a key that the next plan removes, never an orphan key no listing finds. **Intermediates are never removed** (design §6.7, R61), so W2's deferred "binding-record chains naming removed intermediates" cannot arise; the chain clearing applies to removed leaves.
11. **Journal and tombstone bounds** (W2 deferred; mirror `cmd/alice-helper/cleanup.go` `sweepBackups`). Every `--plan` removes, under the lock, journals older than `winproto.JournalKeep` = 7 days (file time) in `committed`, `unchanged`, `restored`, `restore_forbidden`, `prepared` and `fenced`, and `restore_failed` or undecodable ones older than `JournalRetention` = 30 days; never `writing` or `restoring`, never a journal a binding record names as its latest operation (W2: a missing latest journal would read as `RECOVERY_PENDING`), at most `MaxPrunePerRun` = 1000 per plan. A late `iis-deploy` of a fenced operation older than 7 days could run once its tombstone is gone; Alice cut that send within `linuxssh.LongCommandTimeout`, so none can still be in flight (as Linux's `NginxBackupKeep`).
12. **Bounds.** `MaxCleanupItems` = 256 items per apply, `MaxCleanupCandidates` = 256 candidates per plan (more set `truncated`; the next day takes the rest), watch lists `MaxForbidden`. `--plan` and `--apply` run under `winproto.HelperBudget` and the W2 write gate: the first durable write of a plan (the imports inventory or a pruned file) and of an apply (a key) enters it; an error after it answers `OUTCOME_UNKNOWN`, which the job records as `windows.cleanup_outcome_unknown` and the next run settles.
13. **The job.** `windows.cleanup` (ClassChange: removal changes a server; held in a licence lock) per Windows server, queued by the periodic `windows.cleanup_schedule` (ClassReadOnly, as `discovery.schedule`: it only queues; every hour; never on the wall clock in the e2e build) for each Windows server with status ok, the cleanup capability, and no `windows.cleanup` job created for it in the last 24 hours (dedupe `windows.cleanup:<target>:<unix day>`). The switch `certificate_cleanup` (FieldBool, default true; "Remove certificates Alice imported once nothing uses them") lives in `targets.config`: off, the job still plans (bookkeeping, pruning, the Q7 report) and applies nothing. Each removal is audited `windows.certificate_removed` (store, SHA-1, SHA-256, reason) and each Alice-side refusal of a candidate is in the job's result, never e-mailed.
14. **Drift: the engine is unchanged; one Windows scan rule.** Windows locations enter `drift.schedule`, `drift.observe`, `drift.repair` like files. A binding re-pointed outside Alice is drifted by both facts (the scan's `changed_outside_at` and the TLS probe). New, Windows only: when a scan finds a bound `win_sslbinding` location newly in `cert_missing`, `key_missing` or `key_inaccessible` (it had none before), `reconcileLocations` sets `changed_outside_at` (Alice never removes a bound certificate (Ruling 6) nor changes a key's ACL) and `locationHealth` counts a broken file newer than the deployment as disagreeing even when the certificate is the desired one. Such a location is unsupported (`file_problem`), so the repair planner's `checkDeployLocation` skips it without a deployment (no failure is counted, no back-off happens) and `POST /locations/{id}/actions/repair` answers `windows.drift_not_repairable` (ALC-WIN-0013); `repair_available` is false.
15. **Drift cause, derived, not stored.** `LocationObservation.Cause` for a drifted `win_sslbinding` location: `cert_removed` (problem `cert_missing`), `key_unusable` (a key problem), else `binding_repointed`; `AutoCertRebind` true when the server's facts carry the warning `win_autocertrebind` (design §6.2 item 4, §11). Empty for every other kind. The API's observation gains `drift_cause` and `autocertrebind`.
16. **Windows drift e-mails.** `notifyLocation` switches a `win_sslbinding` location to Windows texts (mirror W2's `windowsDeploymentMail`): `location.drift_detected_windows`, `..._windows_cert_removed`, `..._windows_key_unusable`, `location.drift_repair_ready_windows`, `location.drift_repaired_windows`, `location.drift_flapping_windows`, `location.drift_repair_failing_windows` (seven; an approve-mode drift whose cause cannot be repaired gets the detected text of its cause). The AutoCertRebind sentence is appended by `notify.Sender.Render` when param `windows_note` is `autocertrebind` (`email.windows_note_autocertrebind`), as `license_note` is. The Linux texts and params are byte-identical.
17. **Lost connection for Windows.** `needsAttentionTemplate` picks the lost-connection text for a `win_sslbinding` deployment also when the cause is `deployment.interrupted` or `windows.helper_missing` (a Windows OpenSSH session that ended with no answer, W2 Ruling 6); Linux deployments decide as before.
18. **`location_kind` on the Deployment DTO.** `deploymentDTO.LocationKind` (`location_kind`, always present: `server_file` for files); the web recognises a Windows deployment by it and drops the `backup_store` / `http.sys/` guess (W2 Task 13 review minor 4).
19. **The dump shows `alice_imported`.** `StoreCertificate.AliceImported` is true when rule 1 holds for it (Ruling 5, read best effort from `imports.json` and the journals: an unreadable inventory reads false, never fails the dump); the location's details carry `alice_imported`; the bindings panel shows "Imported by Alice".
20. **UI.** Windows wording for a binding's observation (the file fact reads "Binding (last scan)"), the drift cause, the AutoCertRebind hint, no Repair button when `repair_available` is false, the "Imported by Alice" badge, the switch through the provider's config form. No cleanup history page: the job history and the audit log hold it.
21. **e2e.** No drift or cleanup journey (R52 has none; the 7-day age cannot pass in a browser run); the Windows journey asserts the "Imported by Alice" badge after its deployment, the switch saved off and on, and the deployment page reading `location_kind`. Engine tests on the emulator cover drift and cleanup end to end (Task 9).
22. **Runner hygiene.** Ports 45390-45398, `alice-w3-` names, a private data directory, cleanup registered first, `TestRealRunnerIsClean` extended; the real tests read the RDP and WinRM registry values and never write them; the age path on a runner uses an `alicetest`-only clock offset (`ALICE_WIN_TEST_CLOCK_OFFSET`, file `now_alicetest_windows.go`, never in the shipped binary).
23. **W2 items deferred to W3, settled.** Kill between `ImportPFX` and `recordImport`: the "existed" record (Ruling 5). Binding-record chains: cleared for removed leaves; intermediates never removed (Ruling 10); a third party's intermediate after Alice's commit still answers `unchanged` with `win.chain_differs` (carried, Left for later). `ImportPFX` "existed": Ruling 5. Tombstones: Ruling 11. `location.drift_*` e-mails and `needsAttentionTemplate`: Rulings 16, 17. `location_kind`: Ruling 18. `alice_imported` in the dump: Ruling 19. R52, `iis-cleanup`, Q7: Rulings 4-15. The emulator's abandoned-call slow-host fault: declined, W3 adds no slow-host fault (carried).
24. **Test IDs.** `WIN-29`..`WIN-38` in `06-quality.md` §24.7 (Task 12 lists them); STRIDE `WN-14`..`WN-17` in `04-security.md` §14.4, WN-12 amended (tombstones bounded).

## Review Focus

1. **A certificate in use is never removed**, including when a binding is re-pointed to it between plan and apply, when only an RDP or WinRM listener uses it, when a live journal names it, and when a journal is unreadable. Tests: Task 3 `TestCleanupKeepsEveryUsedCertificate`, `TestApplyJudgesAgainUnderTheLock`; Task 9 `TestWindowsCleanupKeepsRows`; Task 5 `TestFidelityCleanup`.
2. **Removal is complete and survives a kill**: key first, then certificate; a kill between leaves a keyless certificate the next plan removes, never an orphan key. Tests: Task 3 `TestRemovalOrderSurvivesAKill`; Task 5 `TestRealCleanupRemovesKeyAndCertificate` (machine key files counted).
3. **Clocks never shorten the wait**: an `unbound_since` in the future resets, a certificate used again loses its stamp, Alice's rollback window holds for a non-compromised certificate. Tests: Task 3 `TestUnboundSinceRules`; Task 7 `TestJudgeCleanupRules`.
4. **An unrepairable Windows drift never loops**: a removed certificate or unusable key is drifted with its cause, mailed once, no repair deployment, no back-off, repair refused with ALC-WIN-0013. Tests: Task 8 `TestBrokenBindingIsDriftedNotRepaired`; Task 9 `TestWindowsDriftCertRemovedIsReportedNotRepaired`.
5. **Linux is unchanged**: drift health for files, the drift and needs-attention e-mails of a file location, `TestDeploymentTemplatesRenderInBothLanguages`. Tests: Task 8 `TestLinuxDriftUnchanged`, `TestLinuxNeedsAttentionUnchanged`; Task 10 the OpenAPI conformance tests.
6. **A W2 helper is never sent `iis-cleanup`** and keeps deploying. Tests: Task 6 `TestCleanupNeedsHelper030`.

---

### Task 1: `winproto`: `iis-cleanup`, helper 0.3.0, `alice_imported`

**Files:**
- Modify: `internal/providers/windows/winproto/winproto.go`, `internal/providers/windows/winproto/winproto_test.go`, `internal/providers/windows/winhelper/winhelper_test.go` (`TestRunVersion` reads `0.3.0`)

**Interfaces:**
- Produces (package `winproto`):
  - `Version = "0.3.0"`, `CleanupMinVersion = "0.3.0"` (`WriteMinVersion` stays `"0.2.0"`)
  - `SubIISCleanup = "iis-cleanup"`, `ArgPlan = "--plan"`, `ArgApply = "--apply"`
  - Bounds and times: `MaxCleanupInput = 64 << 10`, `MaxCleanupItems = 256`, `MaxCleanupCandidates = 256`, `CleanupMinAge = 7 * 24 * time.Hour`, `JournalKeep = 7 * 24 * time.Hour`, `JournalRetention = 30 * 24 * time.Hour`, `MaxPrunePerRun = 1000`
  - Reasons `CleanupAged = "aged"`, `CleanupExpired = "expired"`, `CleanupIncident = "incident"`; kept reasons `KeptBound = "bound"`, `KeptRDP = "rdp"`, `KeptWinRM = "winrm"`, `KeptJournal = "journal"`, `KeptNotAlice = "not_alice"`, `KeptTooYoung = "too_young"`, `KeptJournalUnreadable = "journal_unreadable"`; results `CleanupRemoved = "removed"`, `CleanupKept = "kept"`, `CleanupAbsent = "absent"`; watched states `WatchRemovable = "removable"`, `WatchKept = "kept"`, `WatchAbsent = "absent"`; warning `WarnJournalUnreadable = "journal_unreadable"`
  - `type CleanupRef struct{ SHA1, SHA256 string }` (tags `sha1`, `sha256`)
  - `type CleanupPlanInput struct{ Watch []CleanupRef }` (tag `watch`, required, possibly empty, at most `MaxForbidden`)
  - `type CleanupCandidate struct{ Store, SHA1, SHA256, FriendlyName, NotAfter, UnboundSince, Eligible string }` (tags `store, sha1, sha256, friendly_name, not_after, unbound_since, eligible`; `Eligible` ∈ `aged`, `expired`, or `""` with no removal possible yet)
  - `type CleanupWatched struct{ Store, SHA1, SHA256, State, Reason string }`
  - `type CleanupPlanResponse struct{ OK bool; Candidates []CleanupCandidate; Watched []CleanupWatched; Pruned int; Warnings []string; Truncated bool }` (tags `ok, candidates, watched, pruned, warnings, truncated`)
  - `type CleanupItem struct{ Store, SHA1, SHA256, Reason string }`, `type CleanupApplyInput struct{ Remove []CleanupItem }` (tag `remove`, 1..`MaxCleanupItems`)
  - `type CleanupResult struct{ SHA256, Result, Reason string }`, `type CleanupApplyResponse struct{ OK bool; Results []CleanupResult }`
  - `StoreCertificate.AliceImported bool json:"alice_imported"`
  - `func ValidCleanupItem(i CleanupItem) bool` (valid store, SHA-1, SHA-256, a reason of the three)
- Mirror: W2 Task 1's shapes and their tests in the same files.

- [ ] **Step 1: Write the failing tests** in `winproto_test.go`:
  - `TestCleanupShapesJSON`: golden key sets of the five cleanup types; `StoreCertificate` carries `alice_imported`.
  - `TestValidCleanupItem` table: a valid item of each reason accepted; upper-case hex, a 39-digit SHA-1, store `Root`-like names accepted by `ValidStore` but reason `forced`, an empty reason refused.
  - `TestVersions`: `Version == "0.3.0"`, `VersionAtLeast(Version, CleanupMinVersion)`, `!VersionAtLeast("0.2.0", CleanupMinVersion)`, `VersionAtLeast("0.2.0", WriteMinVersion)`.
  - `TestCleanupBoundsAreConsistent`: `JournalKeep < JournalRetention`, `CleanupMinAge == JournalKeep`, `MaxCleanupItems <= MaxCleanupCandidates`.
- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./internal/providers/windows/winproto/`
Expected: FAIL (undefined names).
- [ ] **Step 3: Implement.** Correct the package comment (protocol 1 spans W1-W3; `iis-cleanup` is W3's; `1.0.0` is W4's).
- [ ] **Step 4: Run the tests**
Run: `go test -race -count=1 ./internal/providers/windows/... && go test -cover ./internal/providers/windows/winproto/`
Expected: PASS, winproto 100.0%.
- [ ] **Step 5: Commit**: `feat(winproto): iis-cleanup --plan and --apply, their input and answers, alice_imported in the dump, helper 0.3.0 (R62)`.

---

### Task 2: `winhelper` core: five `WriteHost` methods, the "existed" record, the import inventory's age, `alice_imported` in the dump

**Files:**
- Modify: `internal/providers/windows/winhelper/write.go` (interface), `journal.go` (`journal.Existed`, `importEntry.UnboundSince`, state listing helpers), `deploy.go` (the "existed" record at `prepared`, `ImportPFX`'s `existed`), `dump.go` (Ruling 19), `fakehost_test.go` (`fakeWriteHost` implements the new methods), `journal_test.go`, `deploy_test.go`, `dump_test.go`
- Modify (to keep building): `internal/providers/windows/wintest/model.go`, `write.go` (stubs that Task 4 fills; `ImportPFX` already returns `existed` correctly), `cmd/alice-winhelper/host_windows.go`, `import_windows.go` (`existed` from `CRYPT_E_EXISTS`; Task 5 fills the rest)

**Interfaces:**
- Consumes: Task 1.
- Produces:
  ```go
  // WriteHost gains:
  Now() time.Time                                                       // the helper's clock
  ListState(dir string) ([]StateFile, error)                            // "journal/" or "bindings/": regular files only, no reparse point
  RemoveState(name string) error                                        // absent is nil
  RemoveCertificate(ctx context.Context, store, sha1 string) (removed bool, err error) // CNG key first, then the certificate (F11, Ruling 10)
  ProtectedThumbprints(ctx context.Context) (Protected, error)          // F12; an unreadable value is an error
  // and ImportPFX becomes:
  ImportPFX(ctx context.Context, store string, pfx, password []byte, friendlyName string) (sha1 string, existed bool, err error)
  type StateFile struct{ Name string; ModTime time.Time }
  type Protected struct{ RDP, WinRM []string } // lower-case SHA-1s
  func aliceImported(h WriteHost, c winproto.StoreCertificate, imports importsFile, journals []journal) bool // Ruling 5
  ```
  The journal gains `Existed *bool json:"existed,omitempty"` (written at `prepared`: true when the store held the certificate with a usable key; nil only in W2 journals, which `readJournal` still accepts); `importEntry` gains `UnboundSince string json:"unbound_since,omitempty"` (RFC 3339 UTC; validated when present). A deploy whose `ImportPFX` answers `existed` records `alice_imported:false` and no import entry.
- Mirror: W2 Task 2 (`fakeWriteHost`), `cmd/alice-helper/journal.go` (time and listing).

- [ ] **Step 1: Write the failing tests**
  - `journal_test.go`, `TestJournalExistedRecord`: a 0.3.0 journal round-trips `existed` true and false; a W2 journal without it decodes with `Existed == nil`; `TestImportEntryUnboundSince`: a valid timestamp round-trips, a malformed one makes `readImports` refuse (`errBadJournal`), a W2 `imports.json` without the field reads.
  - `deploy_test.go`, `TestDeployRecordsWhetherTheCertificateExisted`: a store without the certificate → journal `existed:false` written before `import_certificate`; with a usable copy → `existed:true`, `alice_imported:false`; `TestImportRaceIsNotRecorded`: the fake's `ImportPFX` answers `existed` (a third party added it after the check) → `alice_imported:false`, no `imports.json` entry, deploy still commits.
  - `dump_test.go`, `TestDumpShowsAliceImported`: three certificates (one in `imports.json` with Alice's friendly name, one named by a 0.3.0 journal with `existed:false` and Alice's name, one in `imports.json` whose friendly name another tool changed) → `alice_imported` true, true, false; an unreadable `imports.json` → all false and the dump still answers.
  - `TestAliceImportedRules` table (Ruling 5): W2 journal without `existed` → false; `existed:true` → false; friendly name with another op8 → false; name prefix `Alice` but malformed → false.
- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./internal/providers/windows/winhelper/`
Expected: FAIL.
- [ ] **Step 3: Implement**, then make `wintest` and `cmd/alice-winhelper` build with the new interface (unimplemented methods return an error; `ImportPFX`'s `existed` implemented on both).
- [ ] **Step 4: Run the tests**
Run: `go test -race -count=1 -cover ./internal/providers/windows/... && GOOS=windows go vet ./cmd/alice-winhelper/ ./internal/providers/windows/...`
Expected: PASS, winhelper at least 95%.
- [ ] **Step 5: Commit**: `feat(winhelper): the helper's clock, state listing and removal, certificate removal and the listeners' thumbprints on WriteHost; every journal records whether the certificate existed; the dump shows what Alice imported (R62)`.

---

### Task 3: `winhelper`: `iis-cleanup --plan` and `--apply`

**Files:**
- Create: `internal/providers/windows/winhelper/cleanup.go`, `internal/providers/windows/winhelper/cleanup_test.go`
- Modify: `internal/providers/windows/winhelper/winhelper.go` (register `iis-cleanup` as a `write` command taking input; exactly one of `--plan`, `--apply`, else `USAGE`)

**Interfaces:**
- Consumes: Task 2.
- Produces: the handler, in this order. Common: elevated → stdin decoded strictly (`BAD_CONTENT` for syntax, unknown or duplicate members, trailing data; `INVALID_ARGUMENT` for a value: a ref, an item, more than the bounds) → `DataDirSafe` (`JOURNAL_FAILED`) → lock (`BUSY`) → read every http.sys record (`SSLBindings`) and `ProtectedThumbprints` (`IO_ERROR` on failure, nothing written) → list and decode journals (Ruling 7) → read `imports.json`.
  - `--plan`: for each Alice-imported certificate (imports entries and 0.3.0 journals with `existed:false`; `Certificate(store, sha1)`; absent → its entry dropped; not Alice's by Ruling 5 → kept `not_alice`, entry left): in use (Rulings 6, 7) → `unbound_since` cleared; else stamped when empty or in the future (Ruling 8); `Eligible` per Ruling 8 → `Candidates` (at most `MaxCleanupCandidates`, oldest stamp first, `Truncated`). `Watch` refs: looked up by SHA-1 in `My` and `WebHosting` (DER SHA-256 must match, else absent) → `removable` (Alice's and unused), `kept` with its reason, or `absent`. Then pruning (Ruling 11; `Pruned`). **gate.enter** right before the first write (`imports.json` when it changed, or the first `RemoveState`); every write after it answers `OUTCOME_UNKNOWN` on failure.
  - `--apply`: per item, judged again now: absent → `absent`; DER SHA-256 differs → `kept` `not_alice`; not Alice's → `not_alice`; in use → its reason; `aged` with `unbound_since` younger than `CleanupMinAge` (or missing) → `too_young`; `expired` with `NotAfter` not passed → `too_young`; `incident` → no age. Removable → **gate.enter** (first item) → `RemoveCertificate` → `h.Point("cleanup.removed")` → entry dropped and `imports.json` written → binding-record chains naming its SHA-256 cleared (`ListState("bindings/")`) → event 1003 → `removed`.
- Mirror: `cmd/alice-helper/cleanup.go` (`sweepBackups`), W2's `deploy.go` (the gate, refusal order, fixed messages).

- [ ] **Step 1: Write the failing tests** (`cleanup_test.go`, against `fakeWriteHost` with a settable clock):
  - `TestCleanupKeepsEveryUsedCertificate` (Review Focus 1) table: bound by an IIS record; bound by a foreign-application record (WinRM app id) in another store; RDP thumbprint; WinRM thumbprint; previous of a `writing` journal; new of a `prepared` journal; any candidate while one journal is undecodable (warning `journal_unreadable`); a third party's copy (friendly name not Alice's); a W2 journal's certificate without `existed` → none is a candidate, each `kept` with its reason when watched.
  - `TestUnboundSinceRules` (Review Focus 3): first plan stamps now, not eligible; after 7 days `aged`; bound again in between → stamp cleared and the 7 days start over; a stamp in the future → reset to now; `NotAfter` passed → `expired` on the first plan.
  - `TestApplyJudgesAgainUnderTheLock` (Review Focus 1): an item planned `aged`, then a record re-pointed to it before the apply → `kept` `bound`, nothing removed; an item for a certificate removed meanwhile → `absent`; a re-sent apply of a removed one → `absent`.
  - `TestApplyRemovesAndRecords`: `RemoveCertificate` called once per removed item, key before certificate (the fake logs the order); its `imports.json` entry gone; a binding record whose `chain` names it now has none, another binding's chain untouched; event 1003 text has no PEM; intermediates in `CA` untouched.
  - `TestRemovalOrderSurvivesAKill` (Review Focus 2): `Point("cleanup.removed")` kills after the removal → `imports.json` still lists it, the next plan drops the entry (absent); a kill after the key only (the fake removes the key and fails before the certificate) → the next plan offers the keyless certificate again and the next apply removes it.
  - `TestPrune`: journals at 6 and 8 days in each final phase and `prepared`/`fenced` → the 8-day ones go; `restore_failed` and an undecodable journal at 8 days stay, at 31 days go; `writing`/`restoring` at 60 days stay; the latest op of a binding record at 60 days stays; more than `MaxPrunePerRun` → exactly that many.
  - `TestCleanupRefusals`: not elevated, both or neither flag (`USAGE`), oversized stdin (`TOO_LARGE`), an item with reason `forced` (`INVALID_ARGUMENT`), unreadable registry (`IO_ERROR`, nothing written), lock held (`BUSY`), unsafe data directory (`JOURNAL_FAILED`); the fake's write log is empty for each.
  - `TestCleanupGate`: a budget that ends after the first removal → `OUTCOME_UNKNOWN` (exit 4).
- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./internal/providers/windows/winhelper/ -run 'Cleanup|Unbound|Apply|Removal|Prune'`
Expected: FAIL.
- [ ] **Step 3: Implement** `cleanup.go`. Messages are fixed texts.
- [ ] **Step 4: Run the tests**
Run: `go test -race -count=1 -cover ./internal/providers/windows/winhelper/`
Expected: PASS, at least 95%.
- [ ] **Step 5: Commit**: `feat(winhelper): iis-cleanup plans and removes only certificates Alice imported that nothing uses, after 7 days unused or expired, judged again under the lock; journals and fence tombstones bounded (R62)`.

---

### Task 4: `wintest`: the emulator's cleanup half

**Files:**
- Modify: `internal/providers/windows/wintest/model.go`, `internal/providers/windows/wintest/write.go`, `internal/providers/windows/wintest/write_test.go`, `internal/providers/windows/wintest/demo.go` (the demo's IIS certificates keep `alice_imported:false`)

**Interfaces:**
- Consumes: Task 3 through `winhelper.ExecuteForced`.
- Produces (new `Model` methods):
  ```go
  func (m *Model) SetNow(t time.Time)                 // the helper's clock (default time.Now)
  func (m *Model) Advance(d time.Duration)
  func (m *Model) SetRDPThumbprint(sha1 string)       // "" none
  func (m *Model) SetWinRMThumbprints(sha1s ...string)
  func (m *Model) FailProtected(on bool)              // the registry cannot be read
  func (m *Model) HasCertificate(store, sha1 string) bool
  func (m *Model) HasKey(store, sha1 string) bool     // the certificate's key still exists
  func (m *Model) KeyCount() int                      // keys in the modelled machine key store (orphans included)
  func (m *Model) StateFiles() []string               // names under the data directory
  func (m *Model) SetStateTime(name string, t time.Time)
  func (m *Model) FailAfterKey(on bool)               // the next RemoveCertificate deletes the key, then fails before the certificate
  ```
  `RemoveCertificate` drops the key then the certificate; state files carry a modification time from the model clock.
- Mirror: W2 Task 4 (`write.go`, `write_test.go`).

- [ ] **Step 1: Write the failing tests** (`write_test.go`, over the SSH handler):
  - `TestModelCleanupAfterARedeploy`: deploy A, then B to the same binding over SSH; plan → A not eligible; `Advance(7*24h+time.Minute)`, plan → A `aged`; apply → `removed`, `HasCertificate` and `HasKey` false, `KeyCount` one lower, B untouched.
  - `TestModelCleanupKeepsListeners`: A unbound but `SetRDPThumbprint(A)` → kept `rdp`; `SetWinRMThumbprints(A)` → `winrm`; `FailProtected(true)` → `IO_ERROR`.
  - `TestModelKillBetweenKeyAndCertificate` (Review Focus 2): `FailAfterKey(true)` → the apply answers `OUTCOME_UNKNOWN`, the next plan offers A again (keyless), the next apply removes it, `KeyCount` never shows an orphan.
  - `TestModelPrunesStateFiles`: `SetStateTime` on old journals → the plan prunes them (`StateFiles` lists the survivors).
  - `TestDemoHostDumpShowsAliceImported`: the demo's certificates read `alice_imported:false`; after a deploy over SSH the new one reads true.
- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./internal/providers/windows/wintest/`
Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the tests**
Run: `go test -race -count=1 -cover ./internal/providers/windows/wintest/ ./internal/providers/windows/winhelper/ ./cmd/alice-fakewindows/`
Expected: PASS, wintest at least 90%, the fake's tests unchanged.
- [ ] **Step 5: Commit**: `test(wintest): the emulator's cleanup half: the helper's clock, RDP and WinRM listeners, key and certificate removal with a kill between, state file ages (R62)`.

---

### Task 5: `cmd/alice-winhelper`: the real cleanup half and its runner tests **[F11, F12]**

**Files:**
- Create (`//go:build windows`): `cmd/alice-winhelper/cleanup_windows.go` (`RemoveCertificate`, `ProtectedThumbprints`), `cmd/alice-winhelper/now_windows.go` (`Now` = `time.Now`), `cmd/alice-winhelper/now_alicetest_windows.go` (`//go:build windows && alicetest`: `Now` plus `ALICE_WIN_TEST_CLOCK_OFFSET`), `cmd/alice-winhelper/fidelity_cleanup_windows_test.go`
- Modify: `cmd/alice-winhelper/state_windows.go` (`ListState`: `FindFirstFile` on the directory, regular files only, no reparse point, `ModTime` from the find data; `RemoveState`: `DeleteFile` of a regular file), `cmd/alice-winhelper/host_windows.go`, `cmd/alice-winhelper/zz_runner_clean_windows_test.go` (45390-45398, `alice-w3-`), `cmd/alice-winhelper/emulator_fidelity_windows_test.go` (`TestFidelityVersionAndRefusals` probes `rdp-deploy`, Ruling 2), `.github/workflows/windows.yml` (required list)

**Interfaces:**
- Produces (unexported): `RemoveCertificate`: open the store, find by SHA-1 (`CertFindCertificateInStore(CERT_FIND_SHA1_HASH)`; absent → `removed:false`), `CryptAcquireCertificatePrivateKey(CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG|CRYPT_ACQUIRE_SILENT_FLAG)` (the BOOL out-parameter bound with `*uint32`, W0) then `NCryptDeleteKey` (a certificate without a key skips it), then `CertDeleteCertificateFromStore` of a `CertDuplicateCertificateContext`. `ProtectedThumbprints`: `registry.OpenKey(LOCAL_MACHINE, ...RDP-Tcp, QUERY_VALUE)` `GetBinaryValue("SSLCertificateSHA1Hash")` (`ErrNotExist` → none; 20 bytes → hex), and every subkey of `...\WSMAN\Listener` ending in `+HTTPS` → `GetStringValue("certThumbprint")` folded to lower case (absent key → none). **[F11, F12]**
- Mirror: W2 Task 6 (`import_windows.go`, `state_windows.go`), W2 Task 9 (the twin `twin.same`).

- [ ] **Step 1: Write the tests** (skip unless `ALICE_WIN_REAL=1`; fixtures on 45390-45398, `alice-w3-`; build tag `alicetest` for the twin package as W2):
  - `TestRealCleanupRemovesKeyAndCertificate` **[F11]** (Review Focus 2): deploy A then B to an `alice-w3-` ipport record on 45390 through the real helper; apply A with reason `incident` (no clock needed) → `removed`; A is gone from `My`, its key no longer opens (`NCryptOpenKey` of its container 0x80090016) and no machine key file created since the test started is left; B still binds and serves (a fresh `tls.Dial`); a second apply → `absent`.
  - `TestRealProtectedThumbprints` **[F12]**: `ProtectedThumbprints` succeeds; the WinRM list contains the hash of the image's `0.0.0.0:5986` http.sys record (W0 F8); RDP is a 40-hex value or none; the verdicts are logged for the ruling.
  - `TestFidelityCleanup` (Review Focus 1): on both hosts: A deployed then replaced by B (45391), C imported by the test without Alice's name (foreign), D Alice-deployed and bound by a second record (45392) → plan: nothing eligible; `ALICE_WIN_TEST_CLOCK_OFFSET=192h` plan → A `aged`, C kept `not_alice` when watched, D kept `bound`; apply A, C, D → `removed`, `kept not_alice`, `kept bound`; answers equal field by field (messages dropped).
  - `TestRealRunnerIsClean` extended: no record on 45390-45398, no `alice-w3-` certificate or key, no W3 test data directory.
  - `windows.yml`: the required list adds `TestRealCleanupRemovesKeyAndCertificate`, `TestRealProtectedThumbprints`, `TestFidelityCleanup` (before `TestRealRunnerIsClean`).
- [ ] **Step 2: Verify locally what can be verified**
Run: `GOOS=windows GOARCH=amd64 go build -o /dev/null ./cmd/alice-winhelper/ && GOOS=windows GOARCH=arm64 go build -o /dev/null ./cmd/alice-winhelper/ && GOOS=windows go vet ./cmd/alice-winhelper/ && GOOS=windows go vet -tags alicetest ./cmd/alice-winhelper/ && actionlint .github/workflows/windows.yml && go run ./tools/pincheck && go test -count=1 ./internal/archtest/ && make winhelper`
Expected: PASS (`TestReleaseBinariesLinkNoTestPackages` proves `now_alicetest_windows.go` is not in the release binary).
- [ ] **Step 3: Run on real Windows.** Push `windows-w3`; both legs green. Count every run against the budget of 10 in the rulings file. Record the F11 and F12 verdicts as rulings; if a fact differs, adjust this task's code in its own fix commit (the "If it is wrong" column).
- [ ] **Step 4: Fix** every fidelity difference in the emulator (the helper is the specification), in the task that owns the code.
- [ ] **Step 5: Commit**: `feat(alice-winhelper): certificate and key removal, the RDP and WinRM listeners' thumbprints, state file listing; cleanup fidelity on windows-2022 and windows-2025 (R62)`.

---

### Task 6: Providers: `CertificateCleaner`, the Windows provider's cleanup, `alice_imported`, the switch **(parallel with Tasks 4-5)**

**Files:**
- Modify: `internal/providers/capability.go` (`CapCleanupCertificates Capability = "cleanup_certificates"`), `internal/providers/provider.go` (the interface and types below), `internal/providers/providertest/` (`CheckProvider` accepts the capability only with the interface)
- Create: `internal/providers/windows/cleanup.go`, `internal/providers/windows/cleanup_test.go`
- Modify: `internal/providers/windows/provider.go` (capability; `ConfigSchema` field `certificate_cleanup`, `FieldBool`, default true, label and help keys `provider.windows.fields.certificate_cleanup.*`), `internal/providers/windows/config.go` (`ParseConfig` validates it as a boolean; `func CleanupEnabled(cfg providers.TargetConfig) bool`), `internal/providers/windows/errors.go` (`ReasonCleanupOutcomeUnknown = "windows.cleanup_outcome_unknown"`; budgets and refusal table of `iis-cleanup`), `internal/providers/windows/convert.go` (`certDetails` writes `alice_imported`), `convert_test.go`, `conformance_test.go`
- Modify: `locales/common/{en,tr}.json` (the field's label and help)

**Interfaces:**
- Consumes: Tasks 1, 4.
- Produces (package `providers`):
  ```go
  type CleanupRef struct{ SHA1, SHA256 string }
  type CleanupCertificate struct{ Store, SHA1, SHA256, FriendlyName, Eligible string; NotAfter, UnboundSince time.Time }
  type CleanupWatched struct{ Store, SHA1, SHA256, State, Reason string }
  type CleanupPlan struct{ Candidates []CleanupCertificate; Watched []CleanupWatched; Pruned int; Partial bool }
  type CleanupItem struct{ Store, SHA1, SHA256, Reason string }
  type CleanupItemResult struct{ SHA256, Result, Reason string }
  type CleanupApplyResult struct{ Results []CleanupItemResult }
  // CertificateCleaner (CapCleanupCertificates) removes certificates Alice put on a target and no longer uses.
  type CertificateCleaner interface {
      PlanCleanup(ctx context.Context, watch []CleanupRef) (CleanupPlan, error)
      ApplyCleanup(ctx context.Context, items []CleanupItem) (CleanupApplyResult, error)
  }
  ```
  `windows.(*session)` implements it: version gate before sending (Ruling 2), one fresh connection per call, `iis-cleanup --plan` / `--apply` with the input on stdin, budget `winproto.HelperBudget` and 1 MiB of output; answers validated (every value in its closed set, timestamps RFC 3339, refs valid; anything else `ssh.protocol_error`); `OUTCOME_UNKNOWN` → `*providers.Error{Code: ReasonCleanupOutcomeUnknown, Retryable: true}`; helper codes mapped as W2 Ruling 6.
- Mirror: `internal/providers/windows/status.go` (one call, decode, map), W2 Task 7's tests.

- [ ] **Step 1: Write the failing tests**
  - `cleanup_test.go` (over SSH with `wintest.NewServer`): `TestCleanupNeedsHelper030` (Review Focus 6): a model answering `0.2.0` → both methods `windows.helper_outdated` with `required_version 0.3.0`, the server saw only `version`; a `0.2.0` model still deploys (`DeployCertificate` committed); a model answering `UNKNOWN_SUBCOMMAND` → `windows.helper_outdated`. `TestPlanAndApplyOverSSH`: the Task 4 scenario through the provider returns typed results; `TestCleanupAnswerValidation` table: an unknown `eligible`, a bad timestamp, an item result for a SHA-256 not sent → `ssh.protocol_error`; `TestCleanupOutcomeUnknown`: exit 4 → retryable `windows.cleanup_outcome_unknown`; `TestEachCleanupCallUsesItsOwnConnection`.
  - `convert_test.go`, `TestDetailsCarryAliceImported`: true and false reach `loc.Details["alice_imported"]`.
  - `provider_test.go`, `TestCleanupSwitch`: `ParseConfig` accepts `true`, `false`, absent (true); refuses `"yes"`; `CleanupEnabled` follows it.
  - `conformance_test.go`: `TestWindowsConformance` with the five capabilities; `internal/providers/providers_test.go`: `CheckProvider` fails a provider that lists `cleanup_certificates` without implementing `CertificateCleaner`.
- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./internal/providers/ ./internal/providers/windows/ ./internal/providers/providertest/ -run 'Cleanup|AliceImported|Conformance|Check'`
Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the tests**
Run: `go test -race -count=1 -cover ./internal/providers/... && make i18n-check`
Expected: PASS, windows at least 95%.
- [ ] **Step 5: Commit**: `feat(providers/windows): plan and apply the cleanup of a Windows server's certificates, a W2 helper named outdated before anything is sent; the switch per server; what Alice imported in the location's details (R62)`.

---

### Task 7: Inventory and `winjobs`: Alice's judgement, the job, the schedule, the incident rule

**Files:**
- Create: `internal/inventory/windows_cleanup.go`, `internal/inventory/windows_cleanup_integration_test.go`, `internal/jobs/winjobs/winjobs.go`, `internal/jobs/winjobs/winjobs_test.go`, `internal/jobs/winjobs/winjobs_integration_test.go`
- Modify: `internal/jobs/types.go` (`WindowsCleanup = Register(inventory.JobWindowsCleanup, license.ClassChange)`, `WindowsCleanupSchedule = Register("windows.cleanup_schedule", license.ClassReadOnly)`), `internal/inventory/incidents_engine.go` (`followIncidentDeployment` queues the incident cleanup, Ruling 9), `internal/inventory/notify.go` (template registered in `Templates()`), `cmd/alice/services.go` (register the handler and the task; `windowsCleanupScheduleEvery = time.Hour`, never ticked in the e2e build), the e2e test scheduler's task list (`POST /test/scheduler/run` accepts `windows.cleanup_schedule`), `coverage-floors.json` (`alice/internal/jobs/winjobs` 95), `locales/common/{en,tr}.json` (`email.windows.compromised_in_store.{subject,body}`, the two job reasons' texts come in Task 10)

**Interfaces:**
- Consumes: Task 6.
- Produces (package `inventory`):
  ```go
  const JobWindowsCleanup = "windows.cleanup"
  const CleanupRollbackWindow = 7 * 24 * time.Hour
  const TemplateWindowsCompromisedInStore = "windows.compromised_in_store"
  // Alice-side reasons a candidate stays (CleanupKept.Reason).
  const (CleanupKeptRollbackWindow = "rollback_window"; CleanupKeptDeploymentRunning = "deployment_running"
         CleanupKeptLocationHolds = "location_holds"; CleanupKeptSwitchOff = "cleanup_off")
  type CleanupKept struct{ SHA256, Reason string }
  type CleanupDecision struct{ Remove []providers.CleanupItem; Kept []CleanupKept }
  func (s *Service) CleanupWatch(ctx context.Context, target uuid.UUID) ([]providers.CleanupRef, error)
  func (s *Service) JudgeCleanup(ctx context.Context, target uuid.UUID, plan providers.CleanupPlan) (CleanupDecision, error)
  func (s *Service) RecordCleanup(ctx context.Context, target uuid.UUID, incident *uuid.UUID, plan providers.CleanupPlan,
      d CleanupDecision, res providers.CleanupApplyResult) error
  func (s *Service) ScheduleWindowsCleanup(ctx context.Context) (int, error)
  ```
  (package `winjobs`) `Register(r *jobs.Runner, d Deps)`, `ScheduleTask(inv Inventory, every time.Duration, log *slog.Logger) jobs.Task`, `Inventory` interface as `driftjobs.Inventory` with the five methods above plus `TargetRef`, `Credentials`, `HostKeyStore`, `RecordConnectionFailure`. The handler: open (the `driftjobs.open` checks) → capability and type assertion (else `jobs.Fail("internal.unexpected")`) → `CleanupWatch` → `PlanCleanup` → `JudgeCleanup` → `ApplyCleanup` when `Remove` is not empty → `RecordCleanup`; result `{"candidates", "removed", "kept", "pruned"}`; a provider error is `jobs.FromProvider`, one attempt (the next day retries).
  `CleanupWatch` computes each ref's SHA-1 from the certificate's DER (`certificates.pem_chain`'s first block) and its SHA-256 is `fingerprint_sha256`. `JudgeCleanup` rules: Ruling 8's three Alice checks per candidate; a candidate or watched `removable` certificate that is compromised → item reason `incident` (Ruling 9) bypassing the window; switch off (`windows.CleanupEnabled` false) → every candidate kept `cleanup_off`. `RecordCleanup`: one audit `windows.certificate_removed` (actor jobs; store, sha1, sha256, reason) per `removed`; when `incident` is set and a watched certificate is `kept` or was not removed, one notice `TemplateWindowsCompromisedInStore` (params `target_name`, `certificate_name`, `store`, `thumbprint`) through `notifyTarget` plus the certificate's service.
- Mirror: `internal/jobs/driftjobs/driftjobs.go` (open, tasks), `internal/inventory/drift_observe.go` (`ScheduleDriftObservations`), `internal/inventory/schedule.go` (`ScheduleDiscovery`).

- [ ] **Step 1: Write the failing tests**
  - `windows_cleanup_integration_test.go` (tag `integration`): `TestJudgeCleanupRules` (Review Focus 3) table over one Windows target: a candidate replaced by a deployment finished 6 days ago → kept `rollback_window`, 8 days → removed `aged`; named by an unfinished deployment → `deployment_running`; held by a location's `certificate_id` or `deployed_fingerprint` → `location_holds`; compromised and replaced 1 day ago → removed `incident`; switch off → `cleanup_off`; a certificate of another target's deployment does not count. `TestCleanupWatchListsCompromisedCertificatesOfTheTarget`; `TestScheduleWindowsCleanup`: queues once per day per eligible target, never for a Linux server, a disabled or host-key-changed one, nor twice in 24 h. `TestRecordCleanupAuditsAndNotifiesOnce`: two removals → two audit rows; an incident job with a kept compromised certificate → one notice; a scheduled job (no incident) with the same plan → none.
  - `internal/inventory/incidents_*_integration_test.go`, `TestIncidentQueuesWindowsCleanup`: a verified incident location on a Windows server queues `windows.cleanup` with `incident_id`; on an Nginx server nothing.
  - `winjobs_test.go` (fakes): the handler's order, the switch-off path applies nothing, a provider without the interface fails `internal.unexpected`, `OUTCOME_UNKNOWN` fails with `windows.cleanup_outcome_unknown`; `winjobs_integration_test.go`: one job over SSH against `wintest` removes an aged certificate end to end.
- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./internal/jobs/winjobs/ && go test -count=1 -tags integration ./internal/inventory/ ./internal/jobs/winjobs/ -run 'Cleanup|IncidentQueuesWindows'`
Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the tests**
Run: `go test -race -count=1 -cover ./internal/jobs/winjobs/ ./internal/jobs/ ./internal/archtest/ && go test -race -count=1 -tags integration ./internal/inventory/ ./internal/jobs/winjobs/ ./cmd/alice/`
Expected: PASS, winjobs at least 95%.
- [ ] **Step 5: Commit**: `feat(inventory): windows.cleanup removes what Alice imported once no rollback can need it, a compromised certificate at once after its incident, with one notice when one stays (R62)`.

---

### Task 8: Inventory: Windows drift rule, cause, e-mails, lost-connection text

**Files:**
- Modify: `internal/inventory/locations.go` (`existingLocation` reads `problem`, `key_problem`; `reconcileLocations` applies Ruling 14's rule for `win_sslbinding`), `internal/inventory/drift.go` (`healthInput.fileBroken`; `observationSelect` reads `l.kind`, `l.problem`, `l.key_problem` and the target's facts warning; `LocationObservation.Cause`, `.AutoCertRebind`; `DriftCause*`; `WindowsDriftTemplates()`; `driftNotice` passes `windows_note`), `internal/inventory/notify.go` (`notifyLocation` → `windowsLocationMail`), `internal/inventory/drift_repair.go` (no change expected: assert by test), `internal/inventory/deployment_records.go` (`needsAttentionTemplate`, Ruling 17), `internal/inventory/drift.go` (`RepairDrift` refuses a `cert_removed` or `key_unusable` drift with `ErrDriftNotRepairable` before `RequestDeployment`), `internal/notify/sender.go` (`windows_note`), `locales/common/{en,tr}.json` (the seven Windows drift texts, `email.windows_note_autocertrebind`)
- Tests: `internal/inventory/drift_test.go`, `internal/inventory/windows_drift_integration_test.go` (create), `internal/notify/render_iis_test.go`, `internal/notify/render_drift_test.go`

**Interfaces:**
- Consumes: R52 as built; Task 6 (`alice_imported` in details is untouched by this task).
- Produces:
  ```go
  const (DriftCauseRepointed = "binding_repointed"; DriftCauseCertRemoved = "cert_removed"; DriftCauseKeyUnusable = "key_unusable")
  var ErrDriftNotRepairable = errors.New("inventory: the drifted binding cannot be repaired from Alice")
  func WindowsDriftTemplates() []string // the seven of Ruling 16
  ```
  `locationHealth`: `fileDisagrees := newer(fileAt, deployedAt) && newer(changedOutside, deployedAt) && (fileFP != desired || fileBroken)`; `fileBroken` only for `win_sslbinding`.
- Mirror: `windowsDeploymentMail` and `previousCertificate` (`notify.go`), `render_iis_test.go`.

- [ ] **Step 1: Write the failing tests**
  - `drift_test.go`: `TestLocationHealthBrokenFile` (pure): a broken file newer than the deployment with the desired fingerprint → drifted; older → in sync; `fileBroken` false keeps every existing table row's answer (`TestLinuxDriftUnchanged`, Review Focus 5: the existing table runs unchanged).
  - `windows_drift_integration_test.go` (tag `integration`): `TestBrokenBindingIsDriftedNotRepaired` (Review Focus 4): a bound Windows location in sync, then a scan with `cert_missing` → `changed_outside_at` set, health drifted, cause `cert_removed`; `PlanDriftRepairs` in mode auto creates no deployment over three runs and backs off never; `RepairDrift` → `ErrDriftNotRepairable`; the same for `key_inaccessible` (cause `key_unusable`); a re-pointed scan → cause `binding_repointed`; a file location with problem `missing` stays as R52 decides (no `changed_outside_at`). `TestAutoCertRebindHint`: the target's facts warning sets `AutoCertRebind`.
  - `TestWindowsDriftMail`: a Windows drift queues `location.drift_detected_windows_cert_removed` with `windows_note=autocertrebind` when the warning is present; a file location queues `location.drift_detected` with the R52 params only.
  - `TestWindowsNeedsAttentionLostConnection` and `TestLinuxNeedsAttentionUnchanged` (Review Focus 5): cause `deployment.interrupted` → Windows lost-connection text for a binding, unconfirmed text for an Nginx file.
  - `render_iis_test.go`, `TestWindowsDriftTemplatesRenderInBothLanguages`: the seven render in EN and TR with params of R52 plus `windows_note`, never match `linuxWording`; the note appears only with `windows_note=autocertrebind`; `render_drift_test.go` still passes unchanged.
- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./internal/inventory/ ./internal/notify/ -run 'Health|Drift|Windows' && go test -count=1 -tags integration ./internal/inventory/ -run 'Broken|AutoCert|WindowsDrift|NeedsAttention'`
Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the tests**
Run: `go test -race -count=1 ./internal/inventory/ ./internal/notify/ && go test -race -count=1 -tags integration ./internal/inventory/ ./internal/notify/ && make i18n-check`
Expected: PASS; every existing drift test unchanged.
- [ ] **Step 5: Commit**: `feat(inventory): a Windows binding that loses its certificate or key is drifted with its cause and never repaired into a loop; Windows texts for every drift e-mail and the lost connection (R62)`.

---

### Task 9: Engine and jobs: Windows drift and cleanup end to end on the emulator

**Files:**
- Create: `internal/jobs/deployjobs/windows_drift_integration_test.go`, `internal/jobs/deployjobs/windows_cleanup_integration_test.go`
- Modify: `internal/jobs/deployjobs/harness_integration_test.go` (a `winDriftWorld`: the Windows ACME world of `TestWindowsACMEAutomaticDeployment` with the drift handler and tasks and the `winjobs` handler on the same runner), and **no** production file of `internal/jobs/deployjobs` or `internal/jobs/driftjobs` (if one turns out unavoidable, stop and add a ruling)

**Interfaces:**
- Consumes: Tasks 4, 7, 8; `drift_integration_test.go`'s `driftWorld` helpers (`observe`, `observation`).
- Mirror: `internal/jobs/deployjobs/drift_integration_test.go`, `windows_integration_test.go`.

- [ ] **Step 1: Write the failing tests** (tag `integration`):
  - `TestWindowsDriftObservedIsReported` (acceptance item 1): the ACME certificate deployed to the binding; the model's record re-pointed to the old certificate (`AddBinding` over it) → observe → drifted, cause `binding_repointed`, source file and TLS, one `location.drift_detected_windows` e-mail; mode observe makes no deployment.
  - `TestWindowsDriftAutoIsRepaired`: mode auto → `drift.repair` deploys (trigger `drift_repair`) through the Windows provider, the binding names the desired certificate again, the next observation is in sync and `location.drift_repaired_windows` is sent.
  - `TestWindowsDriftFlappingBacksOff`: re-pointed after each of three repairs → back-off `flapping`, mode observe, `location.drift_flapping_windows` once.
  - `TestWindowsDriftCertRemovedIsReportedNotRepaired` (Review Focus 4): `RemoveCertificate` of the bound certificate on the model → drifted `cert_removed`, no repair deployment after several `drift.repair` runs, no back-off, the auto-mode notice after `DriftAutoNoticeAfter`.
  - `TestWindowsDriftAutoCertRebind`: `SetIIS(... AutoCertRebind: true)` → the e-mail carries the AutoCertRebind note.
  - `TestWindowsCleanupAfterRenewal` (acceptance item 2): a renewal deploys C3 over C2; at 6 days `windows.cleanup` removes nothing (`rollback_window` and helper `too_young`), at 8 days (Alice's and the model's clocks advanced) C2 is removed from the model, audited, and C3 still serves.
  - `TestWindowsCleanupKeepsRows` (Review Focus 1, acceptance item 2) table: C2 bound by a foreign-application record, by RDP, by WinRM, named by a `writing` journal (a deployment killed at `deploy.writing` and not yet recovered), imported by a third party → kept with the matching reason, still in the store.
  - `TestWindowsIncidentRemovesTheCompromisedCertificate`: an incident on C2 whose replacement verifies → the queued cleanup removes C2 at once; a compromised certificate the test imported without Alice's name → kept and one `windows.compromised_in_store` e-mail.
- [ ] **Step 2: Run them to verify they fail**
Run: `go test -count=1 -tags integration ./internal/jobs/deployjobs/ -run 'WindowsDrift|WindowsCleanup|WindowsIncidentRemoves'`
Expected: FAIL.
- [ ] **Step 3: Implement** the harness additions.
- [ ] **Step 4: Run the tests**
Run: `go test -race -count=1 -tags integration ./internal/jobs/deployjobs/ ./internal/jobs/... && git diff --stat main -- internal/jobs/deployjobs/ internal/jobs/driftjobs/ ':!*_test.go'`
Expected: PASS; the diff of production files is empty.
- [ ] **Step 5: Commit**: `test(deployjobs): Windows drift observed, repaired and backed off, a removed certificate reported and never repaired, the cleanup's age, kept rows and incident rule on the emulator (R62)`.

---

### Task 10: API: codes, `location_kind`, the drift cause, `alice_imported`, OpenAPI **(parallel with Task 9)**

**Files:**
- Modify: `internal/api/errors.go` (`ErrWINDriftNotRepairable` `ALC-WIN-0013` 409; `ErrWINCleanupOutcomeUnknown` `ALC-WIN-0014` 502 retryable; `AllErrorCodes`), `internal/api/certs_dto.go` (`deploymentDTO.LocationKind`), `internal/api/drift.go` (`drift_cause`, `autocertrebind`; `repair_available` false for `cert_removed` / `key_unusable`; `ErrDriftNotRepairable` → ALC-WIN-0013), the location DTO path that passes `details` (`alice_imported` kept), `api/openapi.yaml` (the fields, `cleanup_certificates` in the capability enum, the Windows config field)
- Modify: `locales/common/{en,tr}.json` (`errors.windows.drift_not_repairable.*`, `errors.windows.cleanup_outcome_unknown.*`), `docs/troubleshooting.md` (a section per new code)
- Extend: `internal/api/errors_winserver_test.go`, `internal/api/deployments_winserver_test.go` (or the file W2 used), `internal/api/drift_test.go`

**Interfaces:**
- Consumes: Tasks 6-8.
- Mirror: W2 Task 12; commit `ee1eaba7` (the files an error-code addition touches).

- [ ] **Step 1: Write the failing tests**
  - `TestWindowsErrorCodes` extended: the two codes, statuses, retryable flag, EN and TR texts, troubleshooting sections.
  - `TestDeploymentDTOHasLocationKind`: a Windows deployment `win_sslbinding`, an Nginx one `server_file`.
  - `TestObservationDriftCause`: `drift_cause` and `autocertrebind` rendered; `repair_available` false for `cert_removed`; `POST /locations/{id}/actions/repair` on it → 409 `ALC-WIN-0013`.
  - The OpenAPI conformance tests pass (Review Focus 5).
- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./internal/api/ -run 'Windows|LocationKind|DriftCause|OpenAPI|Catalogue'`
Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the tests**
Run: `go test -race -count=1 ./internal/api/ && go test -race -count=1 -tags integration ./internal/api/ -run 'Deploy|Drift|Windows|OpenAPI' && make i18n-check && make docs-check`
Expected: PASS.
- [ ] **Step 5: Commit**: `feat(api): ALC-WIN-0013 and 0014, the location kind of a deployment, the cause of a Windows drift, what Alice imported (R62)`.

---

### Task 11: Web and e2e: Windows drift wording, "Imported by Alice", the switch, `location_kind`

**Files:**
- Modify: `web/src/api/types.ts` (`location_kind`, `drift_cause`, `autocertrebind`), `web/src/api/deployments.ts` (`isWindowsDeployment` reads `location_kind`), `web/src/components/drift/LocationDrift.tsx` (Ruling 20's wording and cause, no Repair when `repair_available` is false), `web/src/components/WebsitesPanel.tsx` (badge), `web/src/pages/TargetDetailPage.tsx` (the switch through the config form; check that the schema-driven form renders `FieldBool`, add it if not), `web/src/locales/{en,tr}.json`, `web/src/test/fixtures.ts`, `web/e2e/windows.spec.ts`
- Tests: `web/src/components/drift/LocationDrift.test.tsx`, `web/src/components/WebsitesPanel.test.tsx`, `web/src/pages/TargetDetailPage.test.tsx`, `web/src/pages/DeploymentDetailPage.test.tsx`, `web/src/api/deployments.test.ts`

**Interfaces:**
- Consumes: Task 10's API.
- Mirror: W2 Task 13 and Task 14.

- [ ] **Step 1: Write the failing tests**
  - `LocationDrift`: a Windows observation shows "Binding (last scan)", the cause text for each of the three causes (EN and TR), the AutoCertRebind hint, no Repair button for `cert_removed`; a file location's texts unchanged.
  - `WebsitesPanel`: "Imported by Alice" on a binding whose details say so, absent otherwise.
  - `TargetDetailPage`: a Windows server's settings show "Remove certificates Alice imported once nothing uses them", on by default, saved off.
  - `DeploymentDetailPage` and `deployments.test.ts`: a deployment is Windows by `location_kind` only (a `backup_store` without it is not).
  - `windows.spec.ts` (EN and TR, after W2's journey): the deployed binding shows "Imported by Alice"; the switch saved off then on; `expectAccessible` on the server page.
- [ ] **Step 2: Run them to verify they fail**
Run: `cd web && npx vitest run src/components/drift/LocationDrift.test.tsx src/components/WebsitesPanel.test.tsx src/pages/TargetDetailPage.test.tsx src/pages/DeploymentDetailPage.test.tsx src/api/deployments.test.ts`
Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the tests**
Run: `cd web && npx vitest run && npx tsc --noEmit && npm run lint && cd .. && make i18n-check && make web-coverage && E2E_PROJECT=alice-e2e-w3 ALICE_E2E_PORT=9976 make e2e-up && E2E_PROJECT=alice-e2e-w3 ALICE_E2E_PORT=9976 make e2e; E2E_PROJECT=alice-e2e-w3 make e2e-down`
Expected: PASS, the whole e2e suite green (no Docker-based Go run at the same time).
- [ ] **Step 5: Commit**: `feat(web): the cause of a Windows binding's drift, Imported by Alice, the cleanup switch per server, Windows deployments by their location kind; English and Turkish (R62)`.

---

### Task 12: Decision, rulings, specification amendments, test IDs, documents

**Files:**
- Modify: `docs/superpowers/rulings/windows-iis.md` (a heading "W3 (R62)": the 24 rulings as built, F11 and F12 verdicts, the runner runs used, the acceptance lines, owner items, "Deferred to W4"), `docs/superpowers/specs/alice-v1/00-decisions.md` (R62 after R61: "R62 (owner approval of the Windows design with its §15 defaults, 2026-10-22; phase W3 ...; rulings in `docs/superpowers/rulings/windows-iis.md` "W3 (R62)") Windows server target, phase W3: drift and cleanup ..." summarising Windows locations in R52 with the scan rule, causes and texts; `iis-cleanup`, helper 0.3.0, `CleanupMinVersion`; the four rules and the two judges, the 7-day age and window, Q7; removal order; journal and tombstone bounds; `windows.cleanup` and its switch; `alice_imported`; `location_kind`; `ALC-WIN-0013..0014`; no migration)
- Modify: `docs/superpowers/specs/2026-10-21-windows-iis-target-design.md` (status "W3 built (R62)"; §13 W3 heading "built, R62, §18"; F11 and F12 rows; "§18 Phase W3 as built" table: Protocol, Cleanup rules, Removal, Bounds, Job, Drift, Notices, Provider, API and UI, Tests, each with "Differs from this design"), `docs/superpowers/specs/alice-v1/02-architecture.md` ("Windows servers": cleanup and drift), `03-integrations.md` §13A (drift for bindings, cleanup), `04-security.md` §14.4 (WN-12 amended; new `WN-14` T/D cleanup deleting a certificate someone else uses, `WN-15` D cleanup deleting a rollback target, `WN-16` I a compromised key left on a server, `WN-17` T a late `iis-deploy` after its tombstone was pruned), `06-quality.md` §24.7 (rows below), `test/matrix/traceability.json`, `docs/security/traceability.md` (regenerated)
- Modify: `CHANGELOG.md` ("Unreleased": "Windows servers (drift and cleanup): ..."), `docs/admin-guide.md` ("Windows servers": drift of bindings, the switch, what cleanup removes and keeps, Q7), `docs/windows-host-preparation.md` (what cleanup deletes, event 1003, the registry values read), `docs/troubleshooting.md` (from Task 10), `docs/superpowers/specs/2026-10-21-deployment-targets-roadmap.md` (the Windows row)

| ID | Case | Tests |
|---|---|---|
| WIN-29 | A binding re-pointed outside Alice is drifted | `internal/jobs/deployjobs:TestWindowsDriftObservedIsReported`, `internal/inventory:TestBrokenBindingIsDriftedNotRepaired` |
| WIN-30 | Auto repairs a re-pointed binding; flapping backs off | `TestWindowsDriftAutoIsRepaired`, `TestWindowsDriftFlappingBacksOff` |
| WIN-31 | A removed certificate or unusable key is reported with its cause and never repaired into a loop | `TestWindowsDriftCertRemovedIsReportedNotRepaired`, `TestBrokenBindingIsDriftedNotRepaired`, `internal/api:TestObservationDriftCause` |
| WIN-32 | Drift and lost-connection e-mails speak of bindings; the AutoCertRebind hint | `internal/notify:TestWindowsDriftTemplatesRenderInBothLanguages`, `TestWindowsNeedsAttentionLostConnection`, `TestWindowsDriftAutoCertRebind` |
| WIN-33 | Cleanup removes only Alice-imported, unused certificates after 7 days or expiry, outside the rollback window | `winhelper:TestUnboundSinceRules`, `internal/inventory:TestJudgeCleanupRules`, `TestWindowsCleanupAfterRenewal` |
| WIN-34 | A certificate bound by any application, RDP, WinRM, a live journal, or without an "existed" record is kept | `winhelper:TestCleanupKeepsEveryUsedCertificate`, `TestApplyJudgesAgainUnderTheLock`, `TestWindowsCleanupKeepsRows`, `winhelper:TestAliceImportedRules` |
| WIN-35 | A compromised certificate is removed after its incident, or reported once when it stays | `TestWindowsIncidentRemovesTheCompromisedCertificate`, `TestRecordCleanupAuditsAndNotifiesOnce`, `TestIncidentQueuesWindowsCleanup` |
| WIN-36 | Removal survives a kill; a W2 helper is never sent `iis-cleanup` | `winhelper:TestRemovalOrderSurvivesAKill`, `wintest:TestModelKillBetweenKeyAndCertificate`, `internal/providers/windows:TestCleanupNeedsHelper030` |
| WIN-37 | Journals and fence tombstones are bounded | `winhelper:TestPrune`, `wintest:TestModelPrunesStateFiles` |
| WIN-38 | The emulator cleans up as the real helper; the real removal leaves no key; the runner is left clean | `cmd/alice-winhelper:TestFidelityCleanup`, `TestRealCleanupRemovesKeyAndCertificate`, `TestRealProtectedThumbprints`, `TestRealRunnerIsClean` |

- [ ] **Step 1: Write the failing check**: add the rows to `06-quality.md`.
- [ ] **Step 2: Run it to verify it fails**
Run: `make matrix-check MATRIXCHECK_FLAGS=-strict`
Expected: FAIL (10 gaps).
- [ ] **Step 3: Write** the documents and `traceability.json`; regenerate: `go run ./tools/matrixcheck -spec docs/superpowers/specs/alice-v1/06-quality.md -map test/matrix/traceability.json -doc docs/security/traceability.md -update`.
- [ ] **Step 4: Verify**
Run: `make matrix-check MATRIXCHECK_FLAGS=-strict && make docs-check && make i18n-check`
Expected: PASS, 0 gaps, 0 pending.
- [ ] **Step 5: Commit**: `docs: Windows servers phase W3 (R62): decision, rulings, design as built, security and quality amendments, WIN-29..WIN-38, admin and host guides, changelog`.

---

### Task 13: Final gates

**Files:** none new; fixes go to the task that owns the code.

- [ ] **Step 1: Full local gates**
Run: `make lint && make test && make i18n-check && make matrix-check MATRIXCHECK_FLAGS=-strict && make docs-check && make helper winhelper && make build && make coverage`
Expected: PASS; `covercheck` shows every floor met (`winjobs` included) and none lower.
- [ ] **Step 2: Windows build and vet**
Run: `GOOS=windows GOARCH=amd64 go build ./cmd/alice-winhelper/ ./internal/providers/windows/... && GOOS=windows GOARCH=arm64 go build ./cmd/alice-winhelper/ && GOOS=windows go vet ./cmd/alice-winhelper/ ./internal/providers/windows/... && GOOS=windows go vet -tags alicetest ./cmd/alice-winhelper/`
Expected: PASS.
- [ ] **Step 3: e2e and image**
Run: `E2E_PROJECT=alice-e2e-w3 ALICE_E2E_PORT=9976 make ci` (only when no other `make ci` or Docker-based run is active on the machine; otherwise `make image-check` and Task 11's e2e run)
Expected: PASS.
- [ ] **Step 4: Real Windows**: the `windows.yml` run of the branch head is green on both runners (runs counted, at most 10), or the rulings file lists it as an owner item and the acceptance report says the real-runner case is pending.
- [ ] **Step 5: gitleaks** over the whole range `e21e1ba3..HEAD` (the worktree's own scan sees no commits); fingerprint any finding in `.gitleaksignore` (no key material), as W2 did.
- [ ] **Step 6: Acceptance check against design §13 W3**, one line each in the rulings file: a binding re-pointed outside Alice is drifted, `auto` repairs it, flapping backs off (Tasks 8, 9); cleanup removes only Alice-imported, unreferenced, aged certificates, keeps one bound by a foreign application, RDP, WinRM or a live journal (table test on the emulator: Tasks 3, 4, 9; one real-runner case: Task 5). Hand the branch `windows-w3` to the coordinator; do not merge or push `main`.

---

## Execution notes for the implementer

- Work in the worktree branch `windows-w3`; never switch branches inside a task. Take `main` in with `git merge main` (never rebase). You may push `windows-w3` (and only it) so `windows.yml` runs; never push `main`.
- Dispatch order: 1 → 2 → 3 → (4 ∥ 5 ∥ 6: disjoint files `wintest`, `cmd/alice-winhelper`, `internal/providers`) → 7 → 8 (may run in parallel with 7: disjoint files except `locales/common/*.json`; commit locale keys with the task that adds them and merge carefully) → 9 and 10 in parallel → 11 → 12 → 13. Task 5's runner runs may wait for capacity while 6-8 proceed; push for an early run after Task 3 if F11/F12 are in doubt.
- Review gates: after Tasks 3, 5, 7 and 8 a review against Review Focus 1-6 before the next dependent task. Every finding is fixed in the task that owns the code, with its own commit.
- Record every ruling made during execution in `docs/superpowers/rulings/windows-iis.md` under "W3 (R62)" (one line each: the ruling, then why); a W0-like fact (F11, F12) gets its verdict and the run link; keep a runner-run table as W2 did.
- Commit with `git -c user.name="Eren Altan" -c user.email="erenaltan@gmail.com" commit --only ...` and the trailer `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`; subjects end with `(R62)`.

## Left for later phases

- **W4**: `windows.yml` required for the Windows paths; the helper in the release bundle and `SHA256SUMS`; helper version `1.0.0`; the owner's manual matrix (2019, a domain account, Server Core, Defender on), now including a cleanup run with Defender on.
- **W5-W7**: CCS (`win_ccs_file`), RDP deployment (`win_rdp`; W3 only reads the RDP listener's thumbprint to keep its certificate), WinRM transport.
- Carried from W2 and not decided in W3: a third party's intermediate added after Alice's commit makes a redeploy answer `unchanged` with `win.chain_differs` (Ruling 23); the emulator's slow-host fault and the abandoned-call marking it needs (Ruling 23); deploying to a binding whose only problem is its key (W2 Ruling 14); IDN host headers (W2 Ruling 5); a manual "roll back this deployment" action.
- Not built: removing intermediates Alice added to `CA` (design §6.7: never); counting or removing expired certificates Alice did not import beyond `win.expired_in_store`; a cleanup history page.

## Self-review notes (for the executor)

- **Spec coverage.** §6.6: Tasks 8, 9 (scan rule, causes, AutoCertRebind, repair by `drift_repair`). §6.7 rules 1-4: Tasks 2, 3 (helper), 7 (Alice), removal and intermediates: Ruling 10, Task 5 (key). §7 subcommand list: Task 1. §8 (one connection per call): Task 6. §9 rows "Deleting a certificate someone else uses", "Rollback reinstalling a compromised certificate": Rulings 6-9, WN-14..WN-16. §11 AD CS row: Rulings 15-16. §12 item 3 (drift observe and repair, cleanup on the emulator): Task 9; item 4 (real runner): Task 5. §15 Q6: Ruling 8; Q7: Ruling 9; Q10: event 1003. §13 W3 acceptance: Task 13 step 6. W2 "Deferred to W3": Ruling 23, item by item.
- **Names used across tasks.** `winproto.SubIISCleanup`, `ArgPlan`, `ArgApply`, `CleanupMinVersion`, `CleanupPlanInput`, `CleanupPlanResponse`, `CleanupCandidate`, `CleanupWatched`, `CleanupItem`, `CleanupApplyInput`, `CleanupApplyResponse`, `CleanupResult`, `CleanupMinAge`, `JournalKeep`, `JournalRetention`, `MaxPrunePerRun`, `StoreCertificate.AliceImported`; `winhelper.WriteHost.Now/ListState/RemoveState/RemoveCertificate/ProtectedThumbprints`, `ImportPFX(...) (sha1, existed, err)`, `StateFile`, `Protected`; `wintest.Model.SetNow/Advance/SetRDPThumbprint/SetWinRMThumbprints/FailProtected/FailAfterKey/HasCertificate/HasKey/KeyCount/StateFiles/SetStateTime`; `providers.CapCleanupCertificates`, `CertificateCleaner`, `CleanupRef`, `CleanupCertificate`, `CleanupPlan`, `CleanupItem`, `CleanupApplyResult`; `windows.CleanupEnabled`, `windows.ReasonCleanupOutcomeUnknown`; `inventory.JobWindowsCleanup`, `CleanupRollbackWindow`, `JudgeCleanup`, `CleanupWatch`, `RecordCleanup`, `ScheduleWindowsCleanup`, `TemplateWindowsCompromisedInStore`, `DriftCause*`, `ErrDriftNotRepairable`, `WindowsDriftTemplates`; `winjobs.Register`, `winjobs.ScheduleTask`.
