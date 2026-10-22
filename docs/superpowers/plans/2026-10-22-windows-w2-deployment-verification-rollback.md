# Windows Servers, Phase W2 (Deployment, Verification and Rollback) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An Administrator, an ACME binding or a Key Vault binding deploys a certificate to an http.sys SSL binding of a Windows server (location kind `win_sslbinding`): the helper imports the chain into `LocalMachine\CA` and the certificate with a non-exportable machine key into the binding's store, re-points the binding in one `HttpUpdateServiceConfiguration` call that keeps every other setting (the Ex records' extended parameters included), journals every phase on the server, and restores the previous certificate itself when the bind reads back wrong. Alice verifies with its own TLS probe or the helper's (R51 levels, `win.chain_differs`), rolls back under the R48 guard that the helper checks again, and recovers any interruption through `iis-status` and `iis-fence` with the engine's existing recovery table.

**Architecture:** `winproto` 1 grows the write subcommands `iis-deploy`, `iis-restore`, `iis-status`, `iis-fence` and their shapes (W1 Ruling 2; `iis-cleanup` stays W3). The helper's whole transaction (validation, lock, journal state machine, binding records, guard check, PKCS #12 build, step order, self-restore) is platform-neutral code in `internal/providers/windows/winhelper` behind a new `winhelper.WriteHost` interface; the real helper `cmd/alice-winhelper` implements it with `httpapi.dll` (update and Ex queries), crypt32 (`PFXImportCertStore`, store adds), `LockFileEx`, `MoveFileEx` and the Event Log, and the emulator `wintest` implements it with a modelled host that keeps http.sys's whole-record replace, schannel's chain cache and kill points between every journal phase. The provider `internal/providers/windows` mirrors the Nginx provider's `DeployCertificate` / `RollbackDeployment` / `DeploymentStatus` / `FenceDeployment` / `VerifyDeployment` (`internal/providers/nginx/deploy.go`, `verify.go`), on one fresh SSH connection per helper call; the platform-neutral verification judgement moves out of `nginx` into a shared package both use. Engine, inventory, API and web change only where a Windows location must become deployable; no migration.

**Tech Stack:** Go 1.27.3 (`golang.org/x/crypto/ssh`, `golang.org/x/sys/windows`, pgx/v5, testcontainers, `software.sslmate.com/src/go-pkcs12` in tests only), PostgreSQL, React 18 + Mantine + TanStack Query + i18next, Vitest, Playwright, Docker images pinned by digest, GitHub Actions `windows-2022` / `windows-2025` runners.

**Spec:** `docs/superpowers/specs/2026-10-21-windows-iis-target-design.md` (this phase is §13 "Phase W2" and its acceptance list; it draws on §5, §6.3, §6.4, §6.5, §7, §8, §9, §10, §11, §12, §14 and §14.1 (W0 facts F1-F5), §15 Q5, Q9, Q10, and §16 (W1 as built)). W1 rulings and the "Deferred to W2" list: `docs/superpowers/rulings/windows-iis.md`. Shared groundwork as built: `docs/superpowers/specs/2026-10-21-deployment-targets-roadmap.md` §1 and §5, rulings `docs/superpowers/rulings/deployment-targets-groundwork.md` (`RollbackTraits`, `SatisfiedBy`, `HeldBackups`, `ExpectCertSHA256` as the compare-and-swap token, the step names `import_chain`, `import_certificate`, `bind`). Model plan for format: `docs/superpowers/plans/2026-10-22-windows-w1-target-connection-discovery.md`. The owner approved W0-W4 with the §15 defaults on 2026-10-22.

**Scope:** design §13 W2 only: the four write subcommands and their journal, import and bind, the guard on the server, the provider's five deployment methods and its two new capabilities, the verification rules of §6.4, Windows locations deployable manually and by ACME and Key Vault bindings, the error codes, the deployment pages' Windows step names and the per-certificate grouping of bindings (§15 Q5). Not in scope: drift for Windows locations and `iis-cleanup` (W3), required real-Windows checks and the release bundle (W4), CCS, RDP, WinRM (W5-W7).

**Decision:** R61 "Windows server target, phase W2" (R60 is the last entry of `00-decisions.md`). **Size:** XL, 16 tasks. **Migration:** none (see Global Constraints).

## Before you start: what W2 must measure on a runner

W0 confirmed the facts W2 rests on (design §14.1: F1 IIS takes the http.sys change; F2 one update call per record, which **replaces the whole record**; F4 the import flags; F5 schannel's chain and its cache per record). Two facts were not measured and are checked by Task 6 and Task 9 on the runners before the code depending on them is claimed done. Record each verdict as a ruling under the "W2" heading of `docs/superpowers/rulings/windows-iis.md`.

| Fact | What W2 relies on | If it is wrong | Tasks |
|---|---|---|---|
| F9 | On 2022 and 2025, `HttpQueryServiceConfiguration` with `HttpServiceConfigSslCertInfoEx` / `HttpServiceConfigSslSniCertInfoEx` and each `HTTP_SSL_SERVICE_CONFIG_EX_PARAM_TYPE` returns the record's extended parameters (HTTP/2 window and limits, performance, TLS restrictions, error headers, session ticket keys), `ERROR_FILE_NOT_FOUND` for a type not set, and an update of the base record leaves them as they were. | The helper rewrites each extended parameter it read after the base update (one `HttpUpdateServiceConfiguration` per Ex type) and self-restores when the read-back still differs; the ruling records the extra calls. | 1, 6, 9 |
| F10 | `PFXImportCertStore` of the standard-library PFX into a temporary memory store, then `CertAddCertificateContextToStore(CERT_STORE_ADD_NEW)` into `LocalMachine\My` (and `WebHosting`), keeps the key link (`CERT_KEY_PROV_INFO_PROP_ID`) so http.sys binds it without 1312. | Import with `PKCS12_ALWAYS_CNG_KSP` straight into the target store opened with `CERT_STORE_OPEN_EXISTING_FLAG` (the spike's route), or the `NCryptImportKey` route of `tools/winspike` on `windows-w0-spike`. | 6, 9 |

## Global Constraints

- **Branch.** Worktree branch `windows-w2` cut from `main` at `1cb75ebd` or later. Never switch branches inside a task. `git merge main` to take `main` in, never rebase. The executor may push `windows-w2` (only that branch) so `.github/workflows/windows.yml` runs on the real runners; it never pushes `main`. The coordinator merges to `main` and pushes.
- **Commits.**
  - `git -c user.name="Eren Altan" -c user.email="erenaltan@gmail.com" commit --only -m "<subject>" -m "Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>" -- <paths>`.
  - New files: `git add -- <path>` first. Never `git add -A` or `git add .`. Check `git status --short` before each commit.
  - Never touch `.claude/`, the untracked PDFs, `alice-helper` (untracked binary at the root) or `docs/security/reviews/independent-audit*` and the other untracked review files.
  - `.gitleaksignore` is pinned to commit hashes: never rebase, squash or amend a pushed commit. A test that needs a key generates it at run time (`internal/testutil/pki`); never commit PEM or PFX key material. If gitleaks flags a test table, follow commit `4d5f2eff` (fingerprint in `.gitleaksignore`, no key material).
- **Security guards that must stay green.** `TestNoCodeAcceptsAnyHostKey` (`internal/providers/linuxssh/guard_test.go`); `tools/pincheck` (`make lint`: every `uses:` pinned by 40-hex SHA with its version comment, every image by digest); `TestOnlyTheTypeListNamesWebServerTypes`; `TestImportRules` and `TestAllowed` (`internal/archtest/arch_test.go`) with the new rules of Tasks 2 and 5; `TestWindowsHelperLinksOnlyItsProtocol` (`internal/archtest/buildtags_test.go`: the helper links only x/sys/windows (and its sub-packages it already uses), `winproto`, `winhelper`, `helperproto`; W2 adds nothing to that list, so the PKCS #12 writer is standard library, Ruling 9); `TestReleaseBinariesLinkNoTestPackages`; `TestNoWindowsReservedFileNames`; the archtest guard that only `internal/providers/windows` and `linuxssh` call `linuxssh.ForcedCommand`.
- **Protocol.** `winproto.Protocol = 1`, `MinProtocol = 1` stay (W1 Ruling 2: nothing was released between W1 and W2). `winproto.Version = "0.2.0"` (Ruling 2; the "W2 sets 1.0.0" comment is corrected). New subcommands `iis-deploy`, `iis-restore`, `iis-status`, `iis-fence`; `iis-cleanup` is W3. A W1 helper (`0.1.0`) answers them `UNKNOWN_SUBCOMMAND` (exit 2, nothing changed): Alice refuses before sending to a helper older than `winproto.WriteMinVersion = "0.2.0"` and maps the backstop answer to `windows.helper_outdated` (Ruling 3).
- **Paths.** Journal `C:\ProgramData\Alice\helper\journal\<op>.json`, binding records `...\helper\bindings\<sha256 of the canonical text>.json`, import inventory `...\helper\imports.json`, lock `...\helper\helper.lock` (all under `winproto.DataDir`, the directory the setup script made Administrators and SYSTEM only). Every state file is written as `<name>.tmp`, `FlushFileBuffers`, then `MoveFileEx(MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)`. Event source `Alice Helper`, event id 1001 (Application log).
- **W0 facts that bind the code** (design §14.1): `HttpUpdateServiceConfiguration` replaces the whole record, so the helper always sends back every field it read (base and Ex) with only hash and store changed; schannel serves the chain it built when the record was last written, so intermediates are imported before the bind and a same-hash write happens when only intermediates changed; PFX import flags `CRYPT_MACHINE_KEYSET|PKCS12_ALWAYS_CNG_KSP`, never `CRYPT_EXPORTABLE`, never `PKCS12_NO_PERSIST_KEY`; `x/sys/windows.CryptAcquireCertificatePrivateKey`'s BOOL out-parameter bound with a `*uint32`; amd64 struct sizes (`SSL_PARAM` 80, `SSL_SET` 88, `SSL_SNI_SET` 216, `SSL_CCS_SET` 208, `SSL_QUERY` 24, `SSL_SNI_QUERY` 152, `SSL_CCS_QUERY` 144) asserted by a test, plus the Ex structs of Task 6; `HttpInitialize` with version 2.0 and `HTTP_INITIALIZE_CONFIG`, the result is the ULONG return value; one fresh SSH connection per helper call (W1 Ruling 5).
- **Error codes.** Existing `ALC-WIN-0001..0003`. New (Task 12): `ALC-WIN-0004` `windows.binding_changed` (409, retryable), `ALC-WIN-0005` `windows.binding_not_found` (409), `ALC-WIN-0006` `windows.busy` (409, retryable), `ALC-WIN-0007` `windows.io_error` (502, retryable), `ALC-WIN-0008` `windows.store_error` (502), `ALC-WIN-0009` `windows.key_unusable` (502), `ALC-WIN-0010` `windows.backup_missing` (502), `ALC-WIN-0011` `windows.location_unsupported` (409), `ALC-WIN-0012` `windows.helper_refused` (502, param `helper_code`).
- **No migration.** `targets.type` `windows`, `certificate_locations.kind` `win_sslbinding`, `deployments.location_kind` and the non-file deployment CHECKs exist since `00031`; step names, error classes and reasons are format checks (`00006`); `rollback_info` is a bounded object that takes the new `BackupRef` fields; `deployments` has no warnings column, so `win.chain_differs` rides on the verify step's params (Ruling 16). If a task finds it needs schema, stop and add a ruling; the next free number is `00032`.
- **Coverage floors** (`coverage-floors.json`; never lower an existing one): `alice/internal/providers/windows/winproto` 100, `alice/internal/providers/windows/winhelper` 95, `alice/internal/providers/windows` 95, `alice/internal/providers/windows/wintest` 90, `alice/cmd/alice-fakewindows` 90, new `alice/internal/providers/tlsverify` 95, `alice/internal/providers/nginx` unchanged. No floor for `alice/cmd/alice-winhelper` (Windows only; its tests run on the runners).
- **Locales.** EN and TR in `locales/common/{en,tr}.json` and `web/src/locales/{en,tr}.json`, identical keys and placeholders (`make i18n-check`). Turkish never puts a suffix on `{{software}}`.
- **Real-Windows runs.** Budget **20 runs** of `windows.yml` for the phase (W0 used 4 of 15, W1 7). Real fixtures use ports **45330-45389** (W1 holds 45301-45320 and 45399), certificates and sites prefixed `alice-w2-`, a data directory of the test's own under `C:\ProgramData\Alice\helper-test-<random>`; **a test never leaves an http.sys record, a certificate, a key, an intermediate, a site or a data directory behind** (Ruling 22): cleanup is registered before the fixture is made and runs on failure too, and `TestRealRunnerIsClean` runs last and fails on any leftover.
- **e2e.** `E2E_PROJECT=alice-e2e-w2 ALICE_E2E_PORT=9975 make e2e-up e2e; E2E_PROJECT=alice-e2e-w2 make e2e-down`. Docker-based Go runs and Playwright never run at the same time.
- **Verification commands.**
  - `go build ./... && go vet ./... && go vet -tags integration ./...`
  - `GOOS=windows GOARCH=amd64 go build ./cmd/alice-winhelper/ ./internal/providers/windows/... && GOOS=windows GOARCH=arm64 go build ./cmd/alice-winhelper/ && GOOS=windows go vet ./cmd/alice-winhelper/ ./internal/providers/windows/...`
  - `go test -race -count=1 ./<pkgs>`; `go test -race -count=1 -tags integration ./<pkgs>`
  - `make lint`, `make test`, `make i18n-check`, `make matrix-check`, `make docs-check`; final `make coverage` and `make ci`
  - web: `cd web && npx vitest run <files> && npx tsc --noEmit && npm run lint`
  - A helper change regenerates checksums: `make helper winhelper`.

## Rulings (where the spec is silent; each goes into `docs/superpowers/rulings/windows-iis.md` under a new "W2" heading for the owner to confirm)

1. **Decision R61, no migration.** R61 records W2 in `00-decisions.md`; the schema of `00031` carries everything (Global Constraints). Error codes continue at `ALC-WIN-0004`; test IDs at `WIN-15`.
2. **Protocol 1, helper 0.2.0.** The write subcommands join protocol 1 (W1 Ruling 2); the helper version string is `0.2.0`, not the `1.0.0` the W1 comment names: `1.0.0` is kept for the first released helper (W4). `iis-cleanup` stays out (W3), so a 0.2.0 helper answers it `UNKNOWN_SUBCOMMAND`.
3. **A W1 helper is outdated for writing, named before anything is sent.** `Open` keeps the helper's version; `DeployCertificate`, `RollbackDeployment`, `DeploymentStatus` and `FenceDeployment` refuse a helper whose version is below `winproto.WriteMinVersion` (dotted-decimal compare, an unparsable version is below) with `windows.helper_outdated` (params `helper_version`, `required_version`), DeployNoChange. The backstop `UNKNOWN_SUBCOMMAND` at exit 2 is in every write subcommand's refusal table (a W1 helper changes nothing) and maps to `windows.helper_outdated`. For status and fence such a refusal proves nothing about the operation and stays an error (the engine's recovery waits), never a state.
4. **Command line and standard input.** The command line carries the subcommand and `--op <uuid>` only (`iis-deploy --op <id>`, `iis-restore --op <id>`, `iis-status --op <id>`, `iis-fence --op <id>`), so process auditing (event 4688) sees the operation id and nothing else. Everything else of `iis-deploy` (locator, expected DER SHA-256, chain PEM, key PEM, the forbidden lists) is `winproto.DeployInput` JSON on standard input, at most `winproto.MaxDeployInput` = 256 KiB; `iis-restore`'s forbidden lists are `winproto.RestoreInput` (both members required, possibly empty). The target store is not sent: the helper uses the binding's current store (§15 Q9, never moves a binding between stores), so Alice cannot make it write elsewhere.
5. **ASCII host tokens before deploying** (W1 carry-forward, Task 9 ruling). Discovery lists IDN U-label and wildcard host headers; W2 deploys only to a locator whose host passes `winproto.ValidHost` (`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`, at most 253, ASCII lower case; a leading `*.` label allowed) and whose IP is canonical; anything else is refused before sending with `windows.location_unsupported`. The helper applies the same validator to the stdin locator (`INVALID_ARGUMENT`).
6. **Helper codes get Windows reasons** (W1 carry-forward). `mapHelper` maps every Windows helper code to its own reason: `HASH_MISMATCH` → `windows.binding_changed`, `BINDING_NOT_FOUND` → `windows.binding_not_found`, `BUSY` → `windows.busy`, `IO_ERROR` and `JOURNAL_FAILED` → `windows.io_error`, `STORE_ERROR` → `windows.store_error`, `KEY_UNUSABLE` → `windows.key_unusable`, `BACKUP_MISSING` → `windows.backup_missing`, `RECOVERY_PENDING` → `deployment.recovery_pending` (param `operation_id`, so the engine's pending-operation path works unchanged), `FENCED` → `deployment.interrupted`, `SUPERSEDED` → `deployment.superseded`, `UNKNOWN_OP` → `deployment.unknown_operation`, `NOT_ELEVATED` and `UNKNOWN_SUBCOMMAND` as in W1, every other code `windows.helper_refused` with `helper_code`. Nothing of the Windows provider answers `ssh.helper_refused` any more; the transport's `ssh.*` codes (unreachable, timeout, host key, protocol error, helper missing → `windows.helper_missing`) stay.
7. **Mutating handlers honour their context; the budget never lies** (W1 carry-forward: Run's goroutine outlived the budget). Read subcommands keep W1's early `IO_ERROR`. A write subcommand runs under a `gate`: its handler calls `gate.enter()` right before its first durable write (the `prepared` journal, the fence tombstone, the `restoring` journal); `enter` fails once the context ended, and the answer is then `IO_ERROR` (nothing changed). When the budget ends, Run closes the gate: if the handler had not entered, the answer is `IO_ERROR` and the handler can no longer enter; if it had, the answer is `OUTCOME_UNKNOWN` (exit 4, in no refusal table: uncertain) and the real helper's `main` returns, which ends the process like a crash, so the journal decides at the next `iis-status`. After `enter`, the handler finishes its step or self-restore with `context.WithoutCancel` bounded by `winproto.WriteGrace` = 8 s, before Alice's own cut (`linuxssh.LongCommandTimeout`).
8. **Journal and binding records** mirror the Linux helper's state machine (`cmd/alice-helper/journal.go`) with Windows fields: phases `prepared → writing → committed | unchanged`, `restoring → restored | restore_failed | restore_forbidden`, `fenced` tombstones; the journal holds the full previous record (base and Ex), the previous and new SHA-1 and DER SHA-256, the store, the intermediates it added, whether Alice imported the certificate, the forbidden lists, the steps (trimmed as Linux: 64, first 12 kept), never key material. A binding record per canonical text names its latest operation: `iis-restore` of an older one is `SUPERSEDED`; `iis-deploy` on a binding whose latest operation is `writing` or `restoring` (or unreadable) is `RECOVERY_PENDING` with `operation_id`. One helper lock (`helper.lock`, `LockFileEx` exclusive, wait up to `winproto.LockWait` = 20 s, then `BUSY`); `Active` in a status is "another process holds the lock now". An operation id the helper knows is `OPERATION_EXISTS` for `iis-deploy` (a re-send never runs twice), a fenced one `FENCED`. A journal directory that is a reparse point, not owned by Administrators or SYSTEM, or not writable refuses before any change (`JOURNAL_FAILED`).
9. **Import.** Platform-neutral `winhelper.BuildPFX(chainLeafDER, keyPKCS8 []byte, password []byte) ([]byte, error)` is the spike's standard-library writer (`tools/winspike/pfx.go` on `windows-w0-spike`: one data ContentInfo, a PBES2/PBKDF2-HMAC-SHA256/AES-256-CBC `pkcs8ShroudedKeyBag` and a certBag sharing a localKeyId, HMAC-SHA256 MAC), with a 32-byte random one-time password encoded as the BMPString PKCS #12 needs; the leaf only goes into the PFX (intermediates go to `CA` as public certificates). The PEM key is parsed and re-encoded as PKCS #8; the PEM input, the PKCS #8 DER, the PFX and the password (and its UTF-16 copy on Windows) are cleared after use; Go's parsed key objects cannot be wiped (stated in WN-4). The key is non-exportable, machine keyset, software KSP. A certificate already in the store with a usable key is used as is and recorded `alice_imported:false`; one present without a usable key is refused `KEY_UNUSABLE` before any change (re-attaching a key to someone else's certificate is not Alice's call). An imported certificate gets the friendly name `Alice <first SAN> <notAfter yyyy-mm-dd> <op8>` and goes into `imports.json` (W3's cleanup reads it).
10. **Bind.** The helper reads the record (base by its key and every Ex parameter type; F9), refuses `HASH_MISMATCH` (exit 3, nothing changed) when the DER SHA-256 of the certificate it names is not the expected one (a record naming a hash its store does not hold has no DER: mismatch), answers `unchanged` when it already names the new certificate and no intermediate was added, changes only hash and store name (the store as read; a NULL store is written back NULL), sends one `HttpUpdateServiceConfiguration`, then reads back base and Ex: any field other than hash and store that differs from what was read, or a hash that is not the new one, is a read-back mismatch: the helper restores the previous record (guarded, Ruling 12) and answers `restored` with `failed_step bind`, `error read_back`. http.sys's 1312 (no usable key) is `failed_step bind`, `error key_unusable`, record unchanged, answered `restored` with no restore call needed (nothing was written) — Alice maps it to `windows.key_unusable` in the rolled-back outcome.
11. **The lists are checked by the helper on every restore path.** Leaf DER SHA-256 and SPKI SHA-256 of the previous certificate (read from the store, not from the journal) against the journal's lists and the lists of the `iis-restore` input (`winhelper.Forbids`, the port of `cmd/alice-helper/rollbackguard.go`); forbidden → `restore_forbidden`, nothing restored. Hence `GuardsRollback` is true from `winproto` 1 and `RollbackTraits{Backup: BackupOnTarget, SelfRestores: true}`: a `Required` guard is satisfied (`SatisfiedBy(traits, true)`), so incident replacements run on every 0.2.0 helper.
12. **Restore preconditions** (design §6.5). Only from `committed` or `writing` (or a `restore_failed` re-try), only when the record still names the new certificate (otherwise, when it names the previous one, `restored` again without a write; when it names a third one, `restore_failed` with `error file_changed`, nothing done), the previous certificate in its store with a usable key (`BACKUP_MISSING` otherwise, journal `restore_failed`, nothing changed), the guard (Ruling 11), then one update back to the full previous record, read back, `restored`. Intermediates added are left in `CA` (never removed: they may serve others, design §6.7).
13. **Event Log.** After `committed` and after `restored`, an Application event id 1001 (deploy) or 1002 (restore) from source `Alice Helper` with operation, canonical binding text, old and new SHA-256 (no key material, §15 Q10). Writing the event is best effort: a failure changes nothing in the answer (the journal is the record), and the emulator records events for tests.
14. **Alice imported or not.** The deploy answer and the journal carry `alice_imported`; the dump does not show it in W2 (W3's cleanup does). A location whose only problem is a key problem (`key_missing`, `key_inaccessible`) stays `file_problem`, unsupported (W1 Ruling 9 deferred this): the engine's pre-check would fail on its handshake anyway; a key with unknown facts (a legacy CSP key, W1 Tasks 4+5) is deployable, because the new import is a CNG key.
15. **Verification** (design §6.4, R51). The platform-neutral judgement (endpoint list, `SNIFor`, `probeFromAlice`, attempts and retry wait, the second probe by key type, chain-length and trust checks, the result's level, trust and failure kind) moves from `internal/providers/nginx/verify.go` to a new package `internal/providers/tlsverify` with a server-side probe hook; Nginx delegates to it with no behaviour change (its tests stay unchanged). Windows endpoints come from the locator: `hostnameport` → (target address, port, SNI = host); `ipport` wildcard (`0.0.0.0`, `::`) → (target address, port) with SNI from each distinct IIS host header (`SNIFor`, then the SANs), at least one endpoint; `ipport` with a specific IP → listen = that IP: Alice probes it only when `probeFromAlice` holds, else the helper's `tls-probe --addr <ip>`; the Administrator's port, SNI, skip and probe address apply. Every probe is a fresh handshake (no client session cache; a test asserts it); the existing attempts cover the first handshake after the bind.
16. **`win.chain_differs`.** The deploy answer carries `built_chain_length` (the helper's `CertGetCertificateChain` after the imports, root excluded, plus the leaf). Verification compares the served chain length with that number, not with Alice's chain; when it differs from Alice's chain length, the verify step's params carry `chain_differs` `true` with `deployed_chain` and `built_chain` (inventory's `stepParamKeys` gain the three), the deployment page shows "Windows serves a chain of {{built}} certificates; Alice deployed {{deployed}}" (key `deployments.warnings.win_chain_differs`), and the R51 trust check decides as usual. No column (Global Constraints).
17. **Rollback info.** `providers.BackupRef` gains `Store`, `PreviousSHA1`, `PreviousSHA256` (`omitempty`; `Dir` stays the Linux helper's). Inventory's start record writes them for a `win_sslbinding` location from its details (`store`, `cert_sha1`) and `cert_file_sha256`, and an empty `Dir`; `DeploymentState.BackupDir` is "" for Windows. A rollback failure's params are `store` and `previous_sha1` instead of `backup_dir` (the API params allowlist gains them); the deployment page shows "Previous certificate: {{store}} \ {{sha1}}" for a Windows deployment.
18. **A cut scan does not block a deployment** (W1 carry-forward). When the dump is truncated (sites cut, certificates dropped, `dropped_certificates`), convert no longer reports a location whose verdict rests on what was cut (`win_foreign_app` for want of a site, `cert_missing` for a certificate not listed): it drops it with `locations_dropped`, so inventory keeps the stored row (supported, deployable) untouched instead of relabelling it.
19. **One unreadable certificate no longer fails the dump** (W1 carry-forward, Task 3 ruling). A `Certificate` read error drops that certificate into `dropped_certificates` with `truncated` and `list_truncated` (the binding reads `leaf_unreadable` Alice-side, W1 M3), instead of `STORE_ERROR` for the whole dump; a store that cannot be opened at all still fails it.
20. **Engine unchanged except where it must not be.** `internal/jobs/deployjobs` gets no Windows branch; the engine's own reasons (`nginx.busy` for an active helper, `nginx.location_unsupported`) keep their names. Inventory's `deployTypes` offers every type whose provider deploys (Windows included), and `ListDeployableLocations` accepts a non-file location by its kind (`kind <> 'server_file'`, a locator, an empty key path) instead of only the file path pattern; ACME and Key Vault bindings already gate on the capability (`bindings.go:311`, `acme_bindings.go:251`) and on `checkDeployLocation`, so the trust check of R49 applies unchanged.
21. **UI grouping (§15 Q5).** The locations panel of a Windows server groups bindings by the certificate they serve (a group row with the certificate's subject, expiry and the count of bindings; the bindings beneath, sorted by canonical text); a binding without a certificate is in a last group "No certificate". Deployment stays per location; the deploy dialog's location picker shows the same grouping and a "Select all bindings of this certificate" control. Linux and web servers are unchanged.
22. **Runner hygiene.** Ports 45330-45389, `alice-w2-` names, a private data directory, cleanup registered before each fixture, a final `TestRealRunnerIsClean` (no http.sys record on 45330-45389, no `alice-w2-` certificate in `My`, `WebHosting` or `CA`, no `alice-w2-` site, no test data directory); the event source is registered by the test only when absent and removed only if the test created it.
23. **e2e forced rollback.** The fake gets `ctl stale-tls-on` / `ctl stale-tls-off` (no arguments, the W1 parser kept): while on, the emulated listeners keep serving the certificate they served before the next bind (a website that did not take the change), so the deployment's verification fails and the provider's `iis-restore` rolls it back. There is no manual rollback action in the UI, and W2 adds none.
24. **Test IDs.** `WIN-15`..`WIN-28` in `06-quality.md` §24.7 (Task 15 lists them); STRIDE rows `WN-10`..`WN-13` and amended WN-1 and WN-4 in `04-security.md` §14.4.

## Review Focus

1. **The budget must never answer a refusal after a change.** A host whose `UpdateBinding` blocks past the budget must give `OUTCOME_UNKNOWN`, never `IO_ERROR`; a context that ended before `prepared` must give `IO_ERROR` and leave no journal. Tests: Task 2 `TestWriteGateNeverLiesAfterTheFirstWrite`, Task 7 `TestDeployOutcomeUnknownIsUncertain`.
2. **Every other setting of the record survives a deployment and a restore**, including the Ex parameters, client-certificate negotiation, revocation values, `DISABLE_TLS13`/`DISABLE_LEGACY_TLS` flags and a CTL: Task 3 `TestBindPreservesTheWholeRecord`, Task 4 `TestModelUpdateReplacesTheWholeRecord`, Task 9 `TestFidelityDeployKeepsEverySetting` on both runners.
3. **The guard is checked on the server on every restore path**: the self-restore after a read-back mismatch, `iis-restore` from Alice, and a re-sent restore; forbidden restores nothing and answers `restore_forbidden`. Tests: Task 3 `TestRestoreForbiddenOnEveryPath`, Task 8 `TestWindowsLocationTargetContract`, Task 9 `TestRealRestoreForbidden`, Task 11 `TestWindowsRollbackGuardRows`.
4. **Kill at every journal point**: after Alice's recovery the binding names exactly the previous or the new certificate, the deployment's record agrees with what is served, and no operation runs after a fence. Tests: Task 4 `TestModelKillAtEveryPoint`, Task 11 `TestWindowsDeploymentSurvivesAKillAtEveryPoint`.
5. **Key material**: never on a command line, never in the journal, a log, an error, an event or an answer; every buffer that held it is cleared. Tests: Task 2 `TestDeployInputIsRedacted`, Task 3 `TestNoKeyMaterialOutsideStdin`, Task 7 `TestDeployKeyIsNeverOutsideStdin`.
6. **No Nginx behaviour change** from the verification extraction: Task 5 keeps `internal/providers/nginx` tests unchanged (only imports move).

---

### Task 1: `winproto`: the write subcommands and their shapes

**Files:**
- Modify: `internal/providers/windows/winproto/winproto.go`, `internal/providers/windows/winproto/winproto_test.go`

**Interfaces:**
- Produces (package `winproto`; mirror `helperproto.NginxDeploy*`, `NginxRestore*`, `NginxStatusResponse`, `helperproto.go:560-680`):
  - `Version = "0.2.0"`, `WriteMinVersion = "0.2.0"`, `func VersionAtLeast(v, min string) bool` (dotted decimal, at most 4 parts of at most 5 digits; anything else false)
  - Subcommands `SubIISDeploy = "iis-deploy"`, `SubIISRestore = "iis-restore"`, `SubIISStatus = "iis-status"`, `SubIISFence = "iis-fence"`; `ArgOp = "--op"`
  - Codes (Linux names where they mean the same, design §7): `CodeHashMismatch`, `CodeFenced`, `CodeSuperseded`, `CodeOutcomeUnknown`, `CodeBusy`, `CodeUnknownOp "UNKNOWN_OP"`, `CodeRecoveryPending`, `CodeOperationExists "OPERATION_EXISTS"`, `CodeBadContent "BAD_CONTENT"`, `CodeTooLarge "TOO_LARGE"`, `CodeIISNotFound "IIS_NOT_FOUND"`, `CodeBindingNotFound "BINDING_NOT_FOUND"`, `CodeBackupMissing "BACKUP_MISSING"`, `CodeKeyUnusable "KEY_UNUSABLE"`, `CodeJournalFailed "JOURNAL_FAILED"` (`CodeStoreError` exists); `ErrorResponse` gains `PendingOp string json:"pending_op,omitempty"` (the `RECOVERY_PENDING` operation, as helperproto's)
  - Steps `StepImportChain`, `StepImportCertificate`, `StepBind`, `StepJournal`, `StepRestore` equal to `providers.StepName*` (a test compares); step error classes `ErrKeyUnusable "key_unusable"`, `ErrReadBack "read_back"`, `ErrStore "store_error"`, `ErrFileChanged "file_changed"`, `ErrForbidden "forbidden"`, `ErrBackupMissing "backup_missing"`
  - Bounds `MaxDeployInput = 256 << 10`, `MaxRestoreInput = 32 << 10`, `MaxExtendedParams = 16`, `MaxExtendedBytes = 4096` (each Ex parameter's raw bytes), `MaxForbidden = helperproto.MaxForbidden`, `LockWait = 20 * time.Second`, `WriteGrace = 8 * time.Second`
  - `type ExtendedParam struct{ Type uint32 json:"type"; Data string json:"data" }` (standard base64 of the parameter struct as read, so the helper can write it back byte for byte) and `SSLBinding.Extended []ExtendedParam json:"extended,omitempty"` **[F9]**
  - `type Locator struct{ Type string json:"type"; IP string json:"ip,omitempty"; Host string json:"host,omitempty"; Port int json:"port"; AppID string json:"app_id" }`, `func (l Locator) Canonical() (string, bool)` (the W1 canonical text; `ccs` refused: not deployable), `func ValidHost(s string) bool` (Ruling 5), `func ValidOpID(s string) bool` (lower-case UUID)
  - `type DeployInput struct{ Locator Locator json:"locator"; ExpectSHA256 string json:"expect_sha256"; ChainPEM string json:"chain_pem"; KeyPEM string json:"key_pem"; ForbiddenSPKI []string json:"forbidden_spki_sha256"; ForbiddenLeaf []string json:"forbidden_leaf_sha256" }` with redacting `String`, `GoString`, `LogValue` (helperproto.NginxDeployInput's rule)
  - `type Step struct{ Name, Status, Error string }` (tags `name`, `status`, `error`)
  - `type DeployResponse struct{ OK bool; Phase, FailedStep, CauseStep, Error string; Steps []Step; NewSHA1, NewSHA256, PreviousSHA1, PreviousSHA256, Store string; AliceImported bool; BuiltChainLength int }` (tags `ok, phase, failed_step, cause_step, error, steps, new_sha1, new_sha256, previous_sha1, previous_sha256, store, alice_imported, built_chain_length`)
  - `type RestoreInput struct{ ForbiddenSPKI, ForbiddenLeaf []string }` (both required), `type RestoreResponse struct{ OK bool; Phase, FailedStep, CauseStep, Error string; Steps []Step }`
  - `type StatusResponse struct{ OK bool; Phase string; Active bool; FailedStep, CauseStep, Error, NewCertSHA256, CurrentCertSHA256 string }` (answers `iis-status` and `iis-fence`; the Linux tags without `backup_dir`)
- Mirror: `helperproto.ValidForbidden`, `ValidOpID`, the redaction tests of `internal/providers/linuxssh/helperproto/helperproto_test.go`.

- [ ] **Step 1: Write the failing tests** in `winproto_test.go`:
  - `TestStepsEqualTheProviders`: each `winproto.Step*` equals its `providers.StepName*`; the phase test of W1 still passes.
  - `TestVersionAtLeast` table: `0.2.0 ≥ 0.2.0`, `0.10.0 ≥ 0.2.0`, `1.0 ≥ 0.2.0`, `0.1.0 < 0.2.0`; `""`, `v0.2.0`, `0.2.0-rc1`, `1.2.3.4.5`, `123456.0` are below.
  - `TestValidHost` table: `www.example.com`, `*.example.com`, `a-b.c` accepted; `WWW.example.com` (not folded), `b\u00fccher.example`, `xn--bcher-kva.example` accepted (an A-label is ASCII), `a..b`, `-a.b`, `a.b-`, a 64-byte label, a 254-byte name, `*`, `a.*.b`, `a b` refused.
  - `TestLocatorCanonical`: hostnameport/ipport give W1's texts (`http.sys/hostnameport/www.example.com:443`, `http.sys/ipport/[::]:443`); `ccs`, an invalid app id, port 0, a non-canonical IP (`::ffff:10.0.0.5`, `010.0.0.5`) refused.
  - `TestDeployInputIsRedacted`: `%v`, `%+v`, `%#v`, `%s` and `slog` of a `DeployInput` holding a key PEM never print `PRIVATE KEY` or the PEM text.
  - `TestWriteShapesJSON`: golden key sets of `DeployResponse`, `RestoreResponse`, `StatusResponse`, `DeployInput`, `SSLBinding` with `extended` (omitted when empty).
  - `TestValidOpID`: a lower-case UUID accepted; upper case, braces, `00000000-0000-0000-0000-000000000000` refused.
- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./internal/providers/windows/winproto/`
Expected: FAIL (undefined names).
- [ ] **Step 3: Implement.** Correct the package's comments (protocol 1 spans W1 and W2; version `0.2.0`; `iis-cleanup` is W3).
- [ ] **Step 4: Run the tests**
Run: `go test -race -count=1 ./internal/providers/windows/... && go test -cover ./internal/providers/windows/winproto/`
Expected: PASS, winproto 100.0%; W1's winhelper `TestRunVersion` updated to `0.2.0` in this commit.
- [ ] **Step 5: Commit**: `feat(winproto): the write subcommands of protocol 1: iis-deploy, iis-restore, iis-status, iis-fence, their input and answers, helper 0.2.0 (R61)`.

---

### Task 2: `winhelper` write core: `WriteHost`, the write gate, stdin, journal, records, guard, PKCS #12, dump carry-forward

**Files:**
- Create: `internal/providers/windows/winhelper/write.go` (WriteHost, gate, stdin read), `internal/providers/windows/winhelper/journal.go`, `internal/providers/windows/winhelper/guard.go`, `internal/providers/windows/winhelper/pfx.go`, and their `_test.go` files; extend `fakehost_test.go` with a `fakeWriteHost`
- Modify: `internal/providers/windows/winhelper/winhelper.go` (Run reads stdin and passes it; commands gain `write bool`), `internal/providers/windows/winhelper/dump.go` (Ruling 19), `internal/providers/windows/winhelper/dump_test.go`

**Interfaces:**
- Consumes: Task 1.
- Produces:
  ```go
  // WriteHost is a Host that can change the machine (the real helper and wintest).
  type WriteHost interface {
      Host
      // Lock takes the helper lock, waiting at most winproto.LockWait (ErrBusy after); release is idempotent.
      Lock(ctx context.Context) (release func(), err error)
      LockHeld() bool                                   // another process holds it now (status Active)
      ReadState(name string) (data []byte, found bool, err error) // "journal/<op>.json", "bindings/<hash>.json", "imports.json"
      WriteState(name string, data []byte) error        // temp file, flush, replace-rename (write through)
      DataDirSafe() error                               // ErrJournal: reparse point, foreign owner, not writable
      Binding(ctx context.Context, l winproto.Locator) (winproto.SSLBinding, bool, error) // base and Extended
      UpdateBinding(ctx context.Context, b winproto.SSLBinding) error // one update of the whole record (ErrKeyUnusable, ErrBindingNotFound)
      AddIntermediate(ctx context.Context, der []byte) (added bool, err error)           // LocalMachine\CA, never replaces
      ImportPFX(ctx context.Context, store string, pfx, password []byte, friendlyName string) (sha1 string, err error)
      Event(id uint32, text string)                     // best effort
      Point(name string) error                          // crash points; nil on the real host
  }
  var ErrBusy, ErrJournal, ErrKeyUnusable, ErrBindingNotFound, ErrStore = errors.New(...), ...
  func BuildPFX(leafDER, keyPKCS8, password []byte) ([]byte, error)
  func Forbids(certDER []byte, spki, leaf []string) bool          // leaf DER SHA-256 or SPKI SHA-256 listed
  type journal struct{ /* Ruling 8 fields; never key material */ }
  ```
  `Run` reads at most `MaxDeployInput + 1` bytes of stdin only for subcommands that take input (more is `TOO_LARGE`, exit 2), and runs a `write` command under the gate of Ruling 7; read commands keep W1's behaviour and ignore stdin.
- Mirror: `cmd/alice-helper/journal.go` (journal fields and `valid`, `trimSteps`, pair records, `point`), `cmd/alice-helper/rollbackguard.go` (guard), `tools/winspike/pfx.go` on `windows-w0-spike` (`git show windows-w0-spike:tools/winspike/pfx.go`), `cmd/alice-helper/deployinput.go` (bounded stdin).

- [ ] **Step 1: Write the failing tests**
  - `TestWriteGateNeverLiesAfterTheFirstWrite` (Review Focus 1): a write command whose handler blocks before `enter` → after the budget (lowered to 50 ms) exit 4 `IO_ERROR` and `enter` then fails; a handler that entered and then blocks → exit 4 `OUTCOME_UNKNOWN`; a context cancelled before `enter` → `IO_ERROR` and no state written.
  - `TestRunReadsBoundedStdin`: `iis-deploy` with 256 KiB + 1 → exit 2 `TOO_LARGE` before any host call; `iis-status` with stdin ignores it; read commands never read stdin (a reader that fails the test when read).
  - `TestWriteCommandsNeedElevation`: each write subcommand with `Elevated() == false` → exit 2 `NOT_ELEVATED`, no host write.
  - `TestJournalRoundTripAndValidation`: a journal survives encode/decode; `valid` refuses another operation's id, an unknown phase, more than 64 steps, invalid hashes, a store failing `ValidStore`, a fenced tombstone with any other field; a JSON field named like key material is impossible (`reflect` walk over the type: no field holds PEM or bytes beyond hashes).
  - `TestBindingRecordAndSuperseded`: records keyed by `hex(sha256(canonical))`; a second operation on the binding makes the first `SUPERSEDED`.
  - `TestForbids`: leaf and SPKI listed → true (RSA and ECDSA leaves from `pki`); unlisted → false; a DER that does not parse → true (the safe side, as Linux).
  - `TestBuildPFXDecodes`: `BuildPFX` of a `pki` RSA and an ECDSA leaf decodes with `software.sslmate.com/src/go-pkcs12` (`DecodeChain` with the password) to the same leaf and key; a wrong password fails the MAC; the password is not in the output; `BuildPFX` clears nothing of its inputs (the caller does) but leaves no copy of the key in its returned errors.
  - `dump_test.go`, `TestBuildDumpDropsAnUnreadableCertificate` (Ruling 19): one `Certificate` error among three → the other two listed, the third in `dropped_certificates`, `truncated` and `list_truncated`; `TestBuildDumpReadsExtendedParams`: bindings carry `extended` as the host returned it, more than `MaxExtendedParams` or a parameter over `MaxExtendedBytes` drops the binding with `list_truncated`.
- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./internal/providers/windows/winhelper/`
Expected: FAIL (undefined names; the dump test fails on `STORE_ERROR`).
- [ ] **Step 3: Implement.** The archtest rule of `winhelper` is unchanged (standard library, `winproto`, `helperproto`); the test-only import of go-pkcs12 is allowed for `_test.go` (check `TestImportRules` covers test files the same way it does for `certs`; add the test-only allowance if it does not).
- [ ] **Step 4: Run the tests**
Run: `go test -race -count=1 -cover ./internal/providers/windows/winhelper/ ./internal/archtest/ && GOOS=windows go vet ./internal/providers/windows/...`
Expected: PASS, coverage at least 95%.
- [ ] **Step 5: Commit**: `feat(winhelper): the helper's write core: elevated write commands under a gate that never refuses after a change, bounded stdin, journal and binding records, the server-side rollback guard, a standard-library PKCS #12 writer; one unreadable certificate no longer fails the dump (R61)`.

---

### Task 3: `winhelper` write subcommands: `iis-deploy`, `iis-restore`, `iis-status`, `iis-fence`

**Files:**
- Create: `internal/providers/windows/winhelper/deploy.go`, `internal/providers/windows/winhelper/restore.go`, `internal/providers/windows/winhelper/status.go`, `internal/providers/windows/winhelper/deploy_test.go`, `internal/providers/windows/winhelper/restore_test.go`, `internal/providers/windows/winhelper/status_test.go`
- Modify: `internal/providers/windows/winhelper/winhelper.go` (register the four commands as `write`, `iis-status` as elevated read under the lock's try)

**Interfaces:**
- Consumes: Task 2.
- Produces: the handlers; `iis-deploy` in the order of design §6.3 with Rulings 4, 8-13: validate (`--op`, stdin `DeployInput`, `ValidHost`, PEM: one leaf, at most `MaxChainCerts` intermediates, an RSA or ECDSA key that matches the leaf, else `BAD_CONTENT`) → `DataDirSafe` (`JOURNAL_FAILED`) → lock (`BUSY`) → known op (`OPERATION_EXISTS` / `FENCED`) → binding record (`RECOVERY_PENDING`) → `Binding` (`BINDING_NOT_FOUND`) → expected hash (`HASH_MISMATCH`) → **gate.enter** → journal `prepared` (full previous record, previous and new hashes, store, lists) and the binding record → step `import_chain` (each intermediate, `added` recorded in the journal) → step `import_certificate` (Ruling 9; zeroing) → unchanged check (Ruling 10) or journal `writing` → step `bind` → read back (mismatch: self-restore under the guard, Ruling 12) → journal `committed` → event 1001 → answer with `built_chain_length` (from `Certificate` of the new hash after the imports). Every step and journal write is followed by `h.Point("deploy.<name>")` (`deploy.locked`, `deploy.prepared`, `deploy.import_chain`, `deploy.import_certificate`, `deploy.writing`, `deploy.bound`, `deploy.read_back`, `deploy.committed`), and `restore.restoring`, `restore.bound`, `restore.restored` in the restore path. `iis-status` answers the journal under no lock (`Active` = `LockHeld`), with `CurrentCertSHA256` the DER SHA-256 of what the binding names now ("" when its store lacks it). `iis-fence` (lock taken): no journal → tombstone `fenced`; `prepared` → tombstone (the binding record handed back); any other phase → that state, nothing changed.
- Mirror: `cmd/alice-helper/deploy.go` (order of refusals, `prepared` before the first change, the steps), `cmd/alice-helper/fence.go`, the nginx-status/restore tests of `cmd/alice-helper/deploy_test.go` and `fence_test.go`.

- [ ] **Step 1: Write the failing tests** (all against `fakeWriteHost`, which models a record table with whole-record replace):
  - `TestDeployCommitsAndJournals`: committed answer, steps `import_chain ok`, `import_certificate ok`, `bind ok`; journal phases seen in order `prepared, writing, committed` (the fake records each `WriteState`); the record names the new SHA-1 in the original store; event 1001 with no PEM text; `alice_imported` true; `imports.json` holds the new certificate.
  - `TestDeployRefusalsChangeNothing`: each refusal (`BAD_CONTENT` mismatched key, `INVALID_ARGUMENT` IDN host, `BINDING_NOT_FOUND`, `HASH_MISMATCH`, `BUSY`, `OPERATION_EXISTS`, `FENCED`, `RECOVERY_PENDING` with `pending_op`, `JOURNAL_FAILED`, `KEY_UNUSABLE` for an existing copy without a key) at its exit code, and the fake's write log is empty.
  - `TestDeployUnchanged`: the binding names the new certificate and no intermediate is added → phase `unchanged`, no update call; with an intermediate added → `committed` with a same-hash update (schannel's cache, §6.4).
  - `TestBindPreservesTheWholeRecord` (Review Focus 2): a record with flags `0x42`, check mode 1, freshness 600, URL timeout 7000, a CTL and two Ex parameters → the update carries all of them unchanged, only `cert_sha1` changed and the store as read (NULL stays NULL).
  - `TestBindKeyUnusable`: the update fails with `ErrKeyUnusable` → answer `restored`, `failed_step bind`, `error key_unusable`, record unchanged, journal `restored`.
  - `TestReadBackMismatchSelfRestores`: the fake's read-back drops an Ex parameter → the helper writes the previous record back, answers `restored`, `failed_step bind`, `cause_step bind`, `error read_back`; with the previous certificate forbidden → `restore_forbidden`, nothing restored.
  - `TestRestoreForbiddenOnEveryPath` (Review Focus 3): the self-restore, `iis-restore` with the lists on stdin, and a second `iis-restore` of a `restore_forbidden` journal → `restore_forbidden` each time, the record still the new one.
  - `TestRestoreRules` (Ruling 12): from `committed` → `restored` and the record is the previous one byte for byte; the record already the previous → `restored` without a write; a third certificate → `restore_failed`, `error file_changed`; previous certificate deleted → `BACKUP_MISSING`; an older operation → `SUPERSEDED`; unknown op → `UNKNOWN_OP`; `prepared` or `unchanged` → that phase, nothing to restore; a fenced op → phase `fenced`.
  - `TestStatusAndFence`: status of an unknown op → `none`; a fence of an unknown op → `fenced` and a later `iis-deploy` of it → `FENCED`; a fence of `committed` → `committed`, nothing changed; status `Active` while another lock holder exists.
  - `TestNoKeyMaterialOutsideStdin` (Review Focus 5): after a deploy, no answer, journal, record, event text or error message contains the key PEM, its DER, the PFX or the password; the fake's `ImportPFX` receives the password, and the handler's buffers are zero after the call (the fake keeps references to the slices it was given and checks them after the handler returns).
  - `TestKillPointsAreNamed`: every point name above is reached once in a successful deploy and once in a restore (the fake's `Point` records them).
- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./internal/providers/windows/winhelper/ -run 'Deploy|Bind|ReadBack|Restore|Status|Fence|KeyMaterial|KillPoints'`
Expected: FAIL.
- [ ] **Step 3: Implement** the three files. Messages are fixed texts, never OS error text.
- [ ] **Step 4: Run the tests**
Run: `go test -race -count=1 -cover ./internal/providers/windows/winhelper/`
Expected: PASS, coverage at least 95%.
- [ ] **Step 5: Commit**: `feat(winhelper): iis-deploy, iis-restore, iis-status and iis-fence: import, one whole-record bind with read-back and self-restore, the guard on every restore, journal phases and fences as on Linux (R61)`.

---

### Task 4: `wintest`: the emulator's write half

**Files:**
- Modify: `internal/providers/windows/wintest/model.go` (state files, lock, whole-record update, imports, CA, events, points), `internal/providers/windows/wintest/tls.go` (schannel's chain cache, stale serving), `internal/providers/windows/wintest/demo.go` (a deployable demo), `internal/providers/windows/wintest/wintest_test.go`

**Interfaces:**
- Consumes: `winhelper.WriteHost`, Task 3's handlers through `winhelper.RunForced`.
- Produces (new `Model` methods; `Model.Host()` now returns a `winhelper.WriteHost`):
  ```go
  func (m *Model) KillAt(point string)                 // the helper "dies" at that point: no answer, exit 255, state as written
  func (m *Model) Reboot()                             // drops the lock and the TLS cache; keeps the records, stores and state files
  func (m *Model) HoldLock() (release func())          // another helper process holds the lock (Active, BUSY)
  func (m *Model) FailUpdate(err error)                // next UpdateBinding fails (winhelper.ErrKeyUnusable, ErrStore, ...)
  func (m *Model) CorruptReadBack(bool)                // the next read after an update loses an Ex parameter
  func (m *Model) FailImport(bool)                     // ImportPFX fails (ErrStore)
  func (m *Model) StaleTLS(bool)                       // listeners keep serving what they served before the next write (Ruling 23)
  func (m *Model) ChainDiffers(extraIntermediate []byte) // the store holds a cross-signed intermediate: the built chain is longer (win.chain_differs)
  func (m *Model) Binding(l winproto.Locator) (winproto.SSLBinding, bool)
  func (m *Model) Journal(op string) ([]byte, bool)
  func (m *Model) Events() []Event                     // id, text
  func (m *Model) Imported() []string                  // SHA-1s Alice imported
  ```
  `UpdateBinding` **replaces** the record with exactly what it is given (W0 F2: a missing field resets it); a hash whose certificate has no usable key is refused like 1312 and changes nothing; the served chain of a binding is computed at the moment of its last write (schannel's cache, W0 F5) and served from then on until the next write; `ImportPFX` decodes the PFX with the helper's own format (it accepts what `BuildPFX` writes, refuses anything else), marks the key non-exportable and in the software KSP; `KillAt` makes `RunForced` stop at that point (the handler's panic is the emulator's kill, as `sys.killed` on Linux).
- Mirror: `internal/providers/linuxssh/linuxsshtest/emulator.go` (kill points, `Reboot`-like resets), `nginx_probe.go` (served selection).

- [ ] **Step 1: Write the failing tests** (`wintest_test.go`, the handler called directly):
  - `TestModelDeployServesTheNewCertificate`: deploy over `Handler()`, then a real `tls.Dial` to the endpoint serves the new leaf with the built chain.
  - `TestModelUpdateReplacesTheWholeRecord` (Review Focus 2): an update without the Ex parameters or flags leaves them reset in the model (the model is http.sys, the helper must send everything).
  - `TestModelChainCache`: an intermediate added to `CA` after the bind is not served until a same-hash write.
  - `TestModelKillAtEveryPoint` (Review Focus 4): for every point of Task 3, `KillAt(point)` then `Reboot()` then `iis-status` answers the phase written last, and `iis-restore` (when the phase allows it) leaves the binding naming the previous certificate; a `iis-fence` after a kill before `prepared` answers `fenced` and a re-sent `iis-deploy` is `FENCED`.
  - `TestModelFaults`: `HoldLock` → status `Active`, deploy `BUSY` after the (lowered) lock wait; `FailUpdate(ErrKeyUnusable)` → `restored` with `key_unusable`; `CorruptReadBack` → `restored` with `read_back`; `FailImport` → the import fails after `prepared`, so the answer is `restored` with `failed_step import_certificate`, `error store_error`, the record untouched and the journal `restored` (`STORE_ERROR` as a refusal is only a store that cannot be opened before `prepared`); `StaleTLS(true)` keeps the old leaf served after the bind.
  - `TestModelEventsAndImports`: event 1001 after a commit, 1002 after a restore; `Imported()` lists the deployed SHA-1.
  - `TestDemoHostIsDeployable`: `Demo` is unchanged for discovery (W1's `TestDemoHost` passes) and its two IIS bindings accept a deploy.
- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./internal/providers/windows/wintest/`
Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the tests**
Run: `go test -race -count=1 -cover ./internal/providers/windows/wintest/ ./internal/providers/windows/winhelper/`
Expected: PASS, wintest coverage at least 90%.
- [ ] **Step 5: Commit**: `test(wintest): the emulator's write half: whole-record http.sys updates, schannel's chain cache, journal and lock on a modelled disk, kill at every journal point, reboot, import and bind faults (R61)`.

---

### Task 5: `tlsverify`: the verification judgement shared by Nginx and Windows **(parallel with Tasks 2-4)**

**Files:**
- Create: `internal/providers/tlsverify/tlsverify.go`, `internal/providers/tlsverify/tlsverify_test.go`
- Modify: `internal/providers/nginx/verify.go`, `internal/providers/nginx/probe.go`, `internal/providers/nginx/prober.go` (delegate; exported names kept as aliases where other packages or tests use them), `internal/archtest/arch_test.go` (rule `"alice/internal/providers/tlsverify": {"alice/internal/providers", "alice/internal/providers/linuxssh/helperproto"}`), `coverage-floors.json` (`tlsverify` 95)

**Interfaces:**
- Produces:
  ```go
  type Endpoint struct{ Port int; SNI, Addr, Listen string }
  type Prober interface{ Probe(ctx context.Context, host string, port int, sni, keyType string) (Probe, error) } // nginx.Prober moved
  type TLSProber struct{ /* nginx.TLSProber moved: no ClientSessionCache, fresh handshake */ }
  // ServerProbe is the target's own probe (alice-helper tls-probe on Linux or Windows); nil when there is none.
  type ServerProbe func(ctx context.Context, ep Endpoint, keyType string) (served Served, reached bool, err error)
  type Options struct{ Attempts int; RetryWait time.Duration; Clock clock.Clock }
  func SNIFor(names, sans []string) string
  func ProbeFromAlice(ep Endpoint, host string) bool
  func Verify(ctx context.Context, host string, eps []Endpoint, req providers.VerifyRequest, p Prober, server ServerProbe, o Options) (providers.VerifyResult, error)
  ```
  `nginx.Endpoints` (server blocks to endpoints) stays in `nginx`; everything after the endpoint list (`VerifyDeployment`'s loop, `probeEndpoint`, `judge`, the trust check, levels) moves.
- Mirror: `internal/providers/nginx/verify.go:100-426`.

- [ ] **Step 1: Write the failing tests** in `tlsverify_test.go`: `TestVerifyTableFromNginx` (the cases of `internal/providers/nginx/verify_test.go` and `verify_trust_test.go` that do not need an SSH session, re-run against `Verify` with a fake prober and server probe); `TestProbeIsAFreshHandshake` (the `tls.Config` `TLSProber` builds has no `ClientSessionCache` and `SessionTicketsDisabled` true); `TestServerProbeWhenAliceCannot` (Alice's probe fails → the server probe decides; `ProbeFromAlice` false → only the server probe is used).
- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./internal/providers/tlsverify/`
Expected: FAIL (package does not exist).
- [ ] **Step 3: Implement** the move; `nginx` calls `tlsverify.Verify` with its `Endpoints` and its helper probe.
- [ ] **Step 4: Run the tests** (Review Focus 6)
Run: `go test -race -count=1 -cover ./internal/providers/tlsverify/ ./internal/providers/nginx/... ./internal/providers/webserver/... ./internal/archtest/ && go test -race -count=1 -tags integration ./internal/providers/nginx/ && git diff --stat main -- internal/providers/nginx/*_test.go`
Expected: PASS; the diff of nginx's test files is empty or import lines only.
- [ ] **Step 5: Commit**: `refactor(providers): the served-certificate judgement moves to tlsverify, shared by Nginx and Windows; Nginx behaves the same (R61)`.

---

### Task 6: `cmd/alice-winhelper`: the real write half **[F9, F10]**

**Files:**
- Create (`//go:build windows`): `cmd/alice-winhelper/httpapi_update_windows.go`, `cmd/alice-winhelper/import_windows.go`, `cmd/alice-winhelper/state_windows.go` (data directory, `LockFileEx`, `MoveFileEx`), `cmd/alice-winhelper/event_windows.go`, `cmd/alice-winhelper/write_windows_test.go`
- Modify: `cmd/alice-winhelper/httpapi_windows.go` (the Ex queries and `HttpUpdateServiceConfiguration` procs; `SSLBinding.Extended`), `cmd/alice-winhelper/host_windows.go` (`host` implements `winhelper.WriteHost`; `newHost(dataDir string)`), `cmd/alice-winhelper/main.go` (data dir `winproto.DataDir`; an `OUTCOME_UNKNOWN` return ends the process)

**Interfaces:**
- Produces (unexported):
  - `httpapi_update_windows.go`: `HttpUpdateServiceConfiguration` with the record built from the `SSLBinding` read (pointer fields kept alive with `runtime.KeepAlive`), for `HttpServiceConfigSslCertInfo` and `...SslSniCertInfo`; the Ex structs `HTTP_SERVICE_CONFIG_SSL_SET_EX`, `HTTP_SERVICE_CONFIG_SSL_SNI_SET_EX`, `HTTP2_WINDOW_SIZE_PARAM`, `HTTP2_SETTINGS_LIMITS_PARAM`, `HTTP_PERFORMANCE_PARAM`, `HTTP_TLS_RESTRICTIONS_PARAM`, `HTTP_ERROR_HEADERS_PARAM`, `HTTP_TLS_SESSION_TICKET_KEYS_PARAM` laid out as `http.h` (sizes asserted on amd64 and arm64 in the test); the Ex query per parameter type (`ERROR_FILE_NOT_FOUND` = not set; `ERROR_INVALID_PARAMETER` on a build without Ex = none, recorded); the Ex update after the base update only when F9 shows the base update resets them. Results are the ULONG return values; 1312 → `winhelper.ErrKeyUnusable`, 2 → `ErrBindingNotFound`. **[F9]**
  - `import_windows.go`: `PFXImportCertStore(CRYPT_MACHINE_KEYSET|PKCS12_ALWAYS_CNG_KSP)` into a memory store, the leaf added to the target store (`CERT_STORE_ADD_NEW`; an existing copy found by SHA-1 is reported, Ruling 9), `CERT_FRIENDLY_NAME_PROP_ID` set; the UTF-16 password copy and the PFX bytes cleared with `clear` after the call; `AddIntermediate` into `CA` with `CERT_STORE_ADD_NEW` (exists → `added:false`). **[F10]**
  - `state_windows.go`: `DataDirSafe` (owner Administrators or SYSTEM via `GetNamedSecurityInfo`, no reparse point on the directory or `journal`/`bindings`, created with the parent's ACL), `WriteState` (`CreateFile` temp, `WriteFile`, `FlushFileBuffers`, `MoveFileEx(MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)`), `Lock` (`LockFileEx(LOCKFILE_EXCLUSIVE_LOCK)` polled with `LOCKFILE_FAIL_IMMEDIATELY` every 200 ms until `LockWait`), `LockHeld` (a fail-immediately try).
  - `event_windows.go`: `windows.RegisterEventSource` / `ReportEvent` / `DeregisterEventSource` of x/sys/windows, source `Alice Helper`, type information; any error ignored (Ruling 13).
- Mirror: `tools/winspike/httpapi.go`, `certstore.go`, `pfx.go` on `windows-w0-spike`.

- [ ] **Step 1: Write the failing tests** (`write_windows_test.go`, skip unless `ALICE_WIN_REAL=1`; fixtures per Ruling 22 on ports 45330-45339):
  - `TestRealStructSizes` (also without `ALICE_WIN_REAL`, on every Windows build): the W0 sizes and the Ex structs' sizes.
  - `TestRealUpdateKeepsTheRecordAndExParams` **[F9]**: an `ipport` and a `hostnameport` test record made with netsh (`clientcertnegotiation=enable`, `verifyclientcertrevocation=disable`, `disabletls13=enable`) plus one Ex parameter set by the test through the helper's own Ex update (HTTP/2 window); `UpdateBinding` with only the hash changed; the read-back equals the record before except the hash; the verdict (Ex kept or reset by the base update) is logged for the ruling.
  - `TestRealImportPFX` **[F10]**: a `BuildPFX` of a `pki` ECDSA leaf imports into `My`; provider Microsoft Software Key Storage Provider, not exportable (`NCryptExportKey` refused), friendly name set; the binding update with its hash succeeds (no 1312); a second import of the same certificate reports the existing copy.
  - `TestRealStateFiles`: `WriteState` then `ReadState` round-trips; a reparse point planted as `journal` (`mklink /J` from the test) makes `DataDirSafe` fail; a second process holding the lock (a child `go test` helper process) makes `Lock` answer `ErrBusy` after a lowered wait and `LockHeld` true.
  - `TestRealEvent`: an event 1001 is readable with `Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='Alice Helper'; Id=1001}` after `Event`.
- [ ] **Step 2: Run them to verify they fail to build**
Run: `GOOS=windows go vet ./cmd/alice-winhelper/`
Expected: FAIL (`host` does not implement `WriteHost`).
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Verify**
Run: `GOOS=windows GOARCH=amd64 go build -o /dev/null ./cmd/alice-winhelper/ && GOOS=windows GOARCH=arm64 go build -o /dev/null ./cmd/alice-winhelper/ && GOOS=windows go vet ./cmd/alice-winhelper/ && go test -count=1 ./internal/archtest/ && make winhelper`
Expected: PASS (the real tests run in Task 9's workflow; `TestWindowsHelperLinksOnlyItsProtocol` unchanged).
- [ ] **Step 5: Commit**: `feat(alice-winhelper): the real write half: whole-record http.sys updates with the extended parameters, PFX import into the machine store, journal files written through, the helper lock, Event Log entries (R61)`.

---

### Task 7: Provider: errors, version gate, `RollbackDeployment`, `DeploymentStatus`, `FenceDeployment` **(parallel with Task 6)**

**Files:**
- Modify: `internal/providers/windows/errors.go` (Ruling 6 reasons and mapping; budgets of the write subcommands; `cmd` takes stdin), `internal/providers/windows/provider.go` (`RollbackTraits`, `writeReady`), `internal/providers/types.go` (`BackupRef` fields, Ruling 17)
- Create: `internal/providers/windows/deploy.go` (shared call sorting, `decodeCall`, refusal tables, `toSteps`), `internal/providers/windows/rollback.go`, `internal/providers/windows/status.go`, `internal/providers/windows/rollback_test.go`, `internal/providers/windows/status_test.go`, extend `provider_test.go` (`TestMapHelper` table)

**Interfaces:**
- Consumes: Tasks 1, 4 (`wintest`), `linuxssh.ForcedCommand`.
- Produces:
  ```go
  const (ReasonBindingChanged = "windows.binding_changed"; ReasonBindingNotFound = "windows.binding_not_found"; ReasonBusy = "windows.busy"
         ReasonIOError = "windows.io_error"; ReasonStoreError = "windows.store_error"; ReasonKeyUnusable = "windows.key_unusable"
         ReasonBackupMissing = "windows.backup_missing"; ReasonLocationUnsupported = "windows.location_unsupported"; ReasonHelperRefused = "windows.helper_refused")
  func (p *Provider) RollbackTraits() providers.RollbackTraits // {BackupOnTarget, SelfRestores: true}
  func (s *session) RollbackDeployment(ctx, req providers.RollbackRequest, log providers.StepLogger) (providers.RollbackOutcome, error)
  func (s *session) DeploymentStatus(ctx, op uuid.UUID) (providers.DeploymentState, error)
  func (s *session) FenceDeployment(ctx, op uuid.UUID) (providers.DeploymentState, error)
  ```
  Budgets: `iis-deploy` and `iis-restore` `linuxssh.LongCommandTimeout` and 64 KiB of output, `iis-status`, `iis-fence` the default timeout and 64 KiB. Refusal tables per subcommand with exit statuses (the `deployRefusals` rule of `nginx/deploy.go:59-86`): only a well-formed refusal at its table's exit status is "nothing changed"; `OUTCOME_UNKNOWN` is in no table. A W1 helper is refused before sending (Ruling 3).
- Mirror: `internal/providers/nginx/deploy.go:157-262, 849-1072`.

- [ ] **Step 1: Write the failing tests** (over SSH with `wintest.NewServer`):
  - `TestMapHelper` (extended table): every row of Ruling 6, and that no Windows reason is `ssh.helper_refused` any more.
  - `TestWriteNeedsHelper020`: a model answering version `0.1.0` → each write method refuses `windows.helper_outdated` with `helper_version 0.1.0`, `required_version 0.2.0`, and the server saw only `version`; a W1-like model answering `UNKNOWN_SUBCOMMAND` to `iis-restore` → no_change `windows.helper_outdated`.
  - `TestRollbackOutcomes` table (mirror `nginx` `TestRollbackOutcomes`): restored and verified; restored and the old leaf not served (rollback_failed verify_old); `restore_failed` file_changed; `BACKUP_MISSING` → rollback_failed `windows.backup_missing` with params `store`, `previous_sha1`; `restore_forbidden` → rollback_failed `deployment.rollback_forbidden`, error forbidden; `SUPERSEDED`, `UNKNOWN_OP` → no_change; `prepared`/`unchanged` → no_change `deployment.nothing_to_restore`; transport failure → uncertain; each passes `providers.CheckRollbackReturn`.
  - `TestRollbackSendsTheGuardAlways`: the restore input always carries both lists (empty arrays when the guard is empty), the server's stdin record shows them.
  - `TestStatusAndFenceStates`: each journal phase of the model maps to a `DeploymentState` that passes `Validate`, `BackupDir` ""; an unknown phase or a hash that is not hex → `ssh.protocol_error`; a fence answer `fenced` with `Active` true → protocol error; status on a W1 helper is an error, not a state.
  - `TestEveryWriteCallUsesItsOwnConnection`: status, fence and restore each open one fresh connection (W1 Ruling 5).
  - `internal/providers/providers_test.go`: `BackupRef` JSON with the new fields omitted when empty (the Nginx `rollback_info` bytes are unchanged).
- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./internal/providers/windows/ ./internal/providers/ -run 'MapHelper|Helper020|Rollback|StatusAndFence|OwnConnection|BackupRef'`
Expected: FAIL.
- [ ] **Step 3: Implement.** The capabilities stay W1's until Task 8 (a provider advertises only what it implements).
- [ ] **Step 4: Run the tests**
Run: `go test -race -count=1 -cover ./internal/providers/windows/ ./internal/providers/`
Expected: PASS; `providers` keeps its coverage.
- [ ] **Step 5: Commit**: `feat(providers/windows): rollback, status and fence through the helper's journal, Windows reasons for the helper's codes, a W1 helper named outdated before anything is sent (R61)`.

---

### Task 8: Provider: `DeployCertificate`, `VerifyDeployment`, capabilities, conformance, discovery carry-forward

**Files:**
- Create: `internal/providers/windows/deploycert.go`, `internal/providers/windows/verify.go`, `internal/providers/windows/deploycert_test.go`, `internal/providers/windows/verify_test.go`, `internal/providers/windows/conformance_test.go`
- Modify: `internal/providers/windows/provider.go` (capabilities `test_connection`, `discover_certificates`, `deploy_certificate`, `verify_deployment`), `internal/providers/windows/convert.go` and `convert_test.go` (Ruling 18), `internal/providers/windows/discover_test.go`

**Interfaces:**
- Consumes: Tasks 5, 7.
- Produces: `session.DeployCertificate` (the shape table of `nginx.(*session).DeployCertificate`, `nginx/deploy.go:370-492`: refusals before sending — closed session, unsupported location, a non-`win_sslbinding` kind, Ruling 5, a fingerprint that is not the chain's leaf, an operation id or token missing — then `iis-deploy`, then `answer`: committed/unchanged → verify; `restored` (helper's own) → `DeployRolledBack` with the helper's failed and cause step and its reason (`windows.key_unusable` for `key_unusable`, `windows.store_error` for `store_error`, `deployment.interrupted` for `read_back`), then verify old; `restore_forbidden` → rollback_failed forbidden; `restore_failed` → rollback_failed; a failed verification → `RecheckGuard`, `iis-restore` retried on `BUSY` (`restoreAttempts` 3, `restoreWait` 10 s, as Nginx), verify old; every `Backup` = `BackupRef{OperationID, Store, PreviousSHA1, PreviousSHA256}` from the request's location and the answer); `session.VerifyDeployment` with Ruling 15's endpoints and the helper's `tls-probe` as `tlsverify.ServerProbe`; the deploy's verification uses `ChainLength` = the answer's `built_chain_length`, and adds the verify step params of Ruling 16.
- Mirror: `internal/providers/nginx/deploy.go:431-847`, `deploy_test.go` (`TestDeployOutcomeTable`), `internal/providers/providertest` (`CheckProvider`, `CheckLocationTarget`).

- [ ] **Step 1: Write the failing tests**
  - `deploycert_test.go`, `TestDeployOutcomeTable` (every row of the shape table against `wintest` faults, each through `providers.CheckDeployReturn`): committed level 3 with a public-like CA chain the trust policy holds; level 2 with a private CA (no root in the policy, not enforced: trust untrusted, warning); level 1 with skip; unchanged; `HASH_MISMATCH` → no_change `windows.binding_changed`, binding untouched; `BINDING_NOT_FOUND`; `key_unusable`; `read_back`; import failure; verification fails (`StaleTLS`) → rolled_back with `deployment.verify_failed` and the previous leaf served; verification fails and the old leaf is not served either → rollback_failed verify_old; a forbidden backup after a failed verification → rollback_failed `deployment.rollback_forbidden`; `BUSY` on the inline restore three times → uncertain with the verification's reason; a transport failure after the send → uncertain.
  - `TestDeployOutcomeUnknownIsUncertain` (Review Focus 1): the helper's `OUTCOME_UNKNOWN` → `DeployUncertain`, and `DeploymentStatus` afterwards reads the journal.
  - `TestDeployRefusesNonASCIIHost`: a hostnameport locator with `bücher.example` → no_change `windows.location_unsupported`, nothing sent.
  - `TestDeployKeyIsNeverOutsideStdin` (Review Focus 5): the command line seen by the server is exactly `iis-deploy --op <id>`; the request's `Format` and the session's logs never show the key; the input buffer is cleared after the send.
  - `TestDeployChainDiffers`: `ChainDiffers` on the model → committed, verify step params `chain_differs true`, `deployed_chain 2`, `built_chain 3`.
  - `verify_test.go`, `TestWindowsEndpoints` table (Ruling 15): hostnameport, ipport wildcard with two IIS host headers (two endpoints), ipport wildcard with no host header (SNI from the SANs), ipport `10.0.0.5` (only the helper probes it), the Administrator's port, SNI and probe address; `TestVerifyUsesTheHelperWhenAliceCannotReach`.
  - `conformance_test.go`, `TestWindowsConformance` (`providertest.CheckProvider` with the four capabilities) and `TestWindowsLocationTargetContract` (`providertest.CheckLocationTarget` against a fresh `wintest` per case, traits `{on_target, true}`; Review Focus 3).
  - `convert_test.go`, `TestCutDumpDropsUnprovableVerdicts` (Ruling 18): a truncated dump whose sites list was cut → the IIS binding without a site in the dump is not in the result, `locations_dropped` set; the same binding in an uncut dump is `win_foreign_app` as in W1; a binding naming a `dropped_certificates` entry keeps `leaf_unreadable` (W1 M3) and a binding whose certificate is absent from a truncated dump is dropped instead of `cert_missing`.
- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./internal/providers/windows/ -run 'Deploy|Verify|Endpoints|Conformance|LocationTarget|CutDump'`
Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the tests**
Run: `go test -race -count=1 -cover ./internal/providers/windows/... ./internal/providers/providertest/ && go test -run TestNoCodeAcceptsAnyHostKey ./internal/providers/linuxssh/`
Expected: PASS, windows coverage at least 95%.
- [ ] **Step 5: Commit**: `feat(providers/windows): deploy to an http.sys binding with Alice's or the helper's verification, R51 levels, win.chain_differs, inline rollback under the guard; deployment and verification capabilities; a cut scan relabels nothing (R61)`.

---

### Task 9: Real Windows: fidelity of every write subcommand, `restore_forbidden` on a runner, workflow **[F9, F10]**

**Files:**
- Modify: `cmd/alice-winhelper/emulator_fidelity_windows_test.go` (write scenarios), `.github/workflows/windows.yml` (required test list, path filter adds `internal/providers/tlsverify/**`)
- Create: `cmd/alice-winhelper/fidelity_write_windows_test.go`, `cmd/alice-winhelper/runner_clean_windows_test.go`

**Interfaces:**
- Consumes: the twin of W1 (`twin.same`), Tasks 3, 4, 6.
- Produces: twin helpers `deploy(loc, chain, key, expect)`, `restore(op, guard)`, `status(op)`, `fence(op)`, each running `winhelper.Run` on both hosts with the same stdin and comparing exit codes and answers (normalised: `message` dropped, SHA-1s compared after both hosts imported the same certificate, `built_chain_length` compared), and comparing afterwards the record (base and Ex), the store contents of the fixtures and the journal JSON (field by field, timestamps none).
- Mirror: `cmd/alice-helper/emulator_fidelity_test.go`.

- [ ] **Step 1: Write the tests** (skip unless `ALICE_WIN_REAL=1`; Ruling 22 for every fixture; ports 45340-45389):
  - `TestFidelityDeploySNIAndIP`: deploy to an SNI and an `ipport 0.0.0.0` test binding with a site; committed on both; a real `tls.Dial` with a fresh session to each serves the new leaf with leaf + intermediate (schannel), equal to the model's served chain.
  - `TestFidelityDeployKeepsEverySetting` (Review Focus 2): the record of Task 6's test with flags, revocation values, client-certificate negotiation and an Ex parameter; after deploy and after restore the record equals the original except the hash (and the hash is back after restore). **[F9]**
  - `TestFidelityDeployRefusals`: `HASH_MISMATCH`, `BINDING_NOT_FOUND`, `BAD_CONTENT`, `OPERATION_EXISTS`, `FENCED`, `RECOVERY_PENDING` after a deploy killed at `deploy.writing` (the real helper killed by a test hook: `ALICE_WIN_TEST_KILL_AT` read by a test build only, `//go:build windows && alicetest`, never in the shipped binary; `TestReleaseBinariesLinkNoTestPackages` covers the tag).
  - `TestFidelityUnchangedAndSameHashWrite`: deploying the bound certificate again → `unchanged`; with a new intermediate → `committed` and the served chain changes only after it (W0 F5).
  - `TestFidelityStatusAndFence`: status after each phase; fence of an unknown op and a later deploy `FENCED`.
  - `TestRealRestoreForbidden` (design §13 W2 item 3): deploy, then `iis-restore` with the previous leaf's SHA-256 in the lists → `restore_forbidden` on the real helper and the model; the binding still names the new certificate; a restore without lists then restores.
  - `TestFidelityKeyUnusable`: a certificate imported without its key into `My` by the test, deploy of that certificate (existing copy) → `KEY_UNUSABLE` on both, nothing changed.
  - `TestRealRunnerIsClean` (Ruling 22, run last by name order and by `t.Cleanup` of the package's `TestMain`): no record on 45330-45389, no `alice-w2-` certificate or key in `My`, `WebHosting`, `CA`, no `alice-w2-` site, no test data directory.
  - `windows.yml`: the required list adds `TestRealStructSizes`, `TestRealUpdateKeepsTheRecordAndExParams`, `TestRealImportPFX`, `TestRealStateFiles`, `TestRealEvent`, `TestFidelityDeploySNIAndIP`, `TestFidelityDeployKeepsEverySetting`, `TestFidelityDeployRefusals`, `TestFidelityUnchangedAndSameHashWrite`, `TestFidelityStatusAndFence`, `TestRealRestoreForbidden`, `TestFidelityKeyUnusable`, `TestRealRunnerIsClean`; the test step runs `go test -tags alicetest` for the fidelity package only.
- [ ] **Step 2: Verify locally what can be verified**
Run: `GOOS=windows go vet ./cmd/alice-winhelper/ && GOOS=windows go vet -tags alicetest ./cmd/alice-winhelper/ && actionlint .github/workflows/windows.yml && go run ./tools/pincheck && go test -count=1 ./internal/archtest/`
Expected: PASS.
- [ ] **Step 3: Run on real Windows.** Push `windows-w2` and run the workflow (`workflow_dispatch` or the push); both legs green. Count every run against the budget of 20 in the rulings file. Record the F9 and F10 verdicts as rulings and adjust Task 6's code in its own fix commit if a fact differs.
- [ ] **Step 4: Fix** every fidelity difference in the emulator (the helper is the specification), in the task that owns the code.
- [ ] **Step 5: Commit**: `test(windows): fidelity of iis-deploy, iis-restore, iis-status and iis-fence on windows-2022 and windows-2025, the server's own restore_forbidden on a runner, a runner left clean (R61)`.

---

### Task 10: Inventory: Windows locations deployable

**Files:**
- Modify: `internal/inventory/types.go` (`deployTypes` lists every type whose provider deploys: web servers and Windows, Ruling 20; the comment of `HasCertificateLocations`), `internal/inventory/locations_list.go:120-140` (a non-file location is listed by its kind, locator and empty key path; a file keeps the path pattern), `internal/inventory/deployment_records.go:625` (Ruling 17's `BackupRef` for a `win_sslbinding` location), `internal/inventory/deployment_records.go:644` (`stepParamKeys` + `chain_differs`, `deployed_chain`, `built_chain`), `internal/inventory/deployment_outcome.go:74` (`windows.busy`, `windows.io_error` stay as real causes like `nginx.busy`)
- Create: `internal/inventory/windows_deploy_integration_test.go`, extend `internal/inventory/windows_test.go`

**Interfaces:**
- Consumes: `providers.BackupRef` (Task 7), the Windows provider's capabilities (Task 8).
- Mirror: `internal/inventory/groundwork_integration_test.go` (non-file locations through an Nginx server) and `windows_integration_test.go` (W1's harness).

- [ ] **Step 1: Write the failing tests**
  - `windows_test.go`, `TestDeployTypesFollowTheCapability`: with a registry whose Windows provider deploys, `deployTypes` has `windows`; with W1's capabilities it has not.
  - `windows_deploy_integration_test.go` (tag `integration`):
    - `TestListDeployableLocationsIncludesWindowsBindings`: a supported `win_sslbinding` location is listed with its canonical text; an unsupported one, a `ccs` one and one with a key problem are not; Nginx's listing is unchanged (an existing assertion of `locations_list` tests still holds).
    - `TestRequestDeploymentToAWindowsBinding`: `RequestDeployment` of a certificate to the binding queues one job; the location's `config_invalid` gate does not apply (no web-server facts needed); a `win_foreign_app` location is `location_unsupported`; the trust check of R49 refuses a cross-service request without trust (`ReasonServiceUntrusted`).
    - `TestStartDeploymentWritesTheWindowsBackupRef`: `rollback_info` = `{"operation_id", "store", "previous_sha1", "previous_sha256"}` with no `dir`; a file location's `rollback_info` is byte for byte what it was.
    - `TestChainDiffersStepParamsAreKept`: the verify step's three params are stored and returned.
- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./internal/inventory/ -run DeployTypes && go test -count=1 -tags integration ./internal/inventory/ -run 'Windows'`
Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the tests**
Run: `go test -race -count=1 ./internal/inventory/ ./internal/archtest/ && go test -race -count=1 -tags integration ./internal/inventory/`
Expected: PASS; every existing inventory test unchanged.
- [ ] **Step 5: Commit**: `feat(inventory): Windows bindings are deployable locations: listed, requested, recorded with the previous certificate as their rollback info (R61)`.

---

### Task 11: Engine and jobs: Windows deployments end to end on the emulator

**Files:**
- Create: `internal/jobs/deployjobs/windows_integration_test.go`, `internal/jobs/deployjobs/windows_crash_integration_test.go`
- Modify: `internal/jobs/deployjobs/harness_integration_test.go` (a Windows server on `wintest` in the test world: registry with the Windows provider, a target with a pinned host key, a discovered binding), and **no** production file of `internal/jobs/deployjobs` (Ruling 20; if a production change turns out unavoidable, stop and add a ruling)

**Interfaces:**
- Consumes: Tasks 8, 10; the ACME and Key Vault worlds of `acme_integration_test.go` and `kv_integration_test.go`.
- Mirror: `crash_integration_test.go:30-411`, `rollbackguard_integration_test.go`, `trust_integration_test.go`, `services_integration_test.go`.

- [ ] **Step 1: Write the failing tests** (tag `integration`):
  - `TestWindowsManualDeployment`: committed and `verified` with level 3 (the world's trust store holds the test CA), the deployment record names the Windows steps `import_chain`, `import_certificate`, `bind`, `verify`; the binding on the model names the new certificate.
  - `TestWindowsDeploymentLevels`: level 2 with a private CA not in the policy (trust untrusted, not enforced), level 1 with skip (design §13 W2 item 1).
  - `TestWindowsHashMismatchChangesNothing` and `TestWindowsUnchanged` (item 2).
  - `TestWindowsFailedVerificationRollsBack` (`StaleTLS`): rolled_back, the previous leaf served, the deployment's reason `deployment.verify_failed`.
  - `TestWindowsRollbackGuardRows` (item 3; mirror `rollbackguard_integration_test.go`): the previous certificate marked compromised during the deployment → rollback_failed `deployment.rollback_forbidden`, the model's binding still the new certificate, its journal `restore_forbidden`; an incident replacement (`Required`) runs (traits satisfy it).
  - `TestWindowsDeploymentSurvivesAKillAtEveryPoint` (item 4, Review Focus 4): for each point of Task 3, `KillAt(point)`, run the job, `Reboot()`, run the recovery: the final record is committed (the binding names the new certificate and it is served) or rolled back / failed with the binding naming the previous one, never a record that disagrees with the model; a kill before `prepared` is fenced and the re-sent operation never runs.
  - `TestWindowsRecoveryWaitsForAnActiveHelper`: `HoldLock` → the recovery records `nginx.busy` (the engine's reason) and resolves once released.
  - `TestWindowsACMEAutomaticDeployment` and `TestWindowsKeyVaultAutomaticDeployment` (item 5): a renewal of an ACME binding and a new Key Vault version bound to the Windows location deploy automatically and commit.
  - `TestWindowsCrossServiceNeedsTrust` (item 5): a binding of service A's certificate to service B's Windows server is refused without trust and deploys with it.
- [ ] **Step 2: Run them to verify they fail**
Run: `go test -count=1 -tags integration ./internal/jobs/deployjobs/ -run Windows`
Expected: FAIL (no Windows world).
- [ ] **Step 3: Implement** the harness additions.
- [ ] **Step 4: Run the tests**
Run: `go test -race -count=1 -tags integration ./internal/jobs/deployjobs/ ./internal/jobs/... && git diff --stat main -- internal/jobs/deployjobs/ ':!*_test.go'`
Expected: PASS; the diff of production files is empty.
- [ ] **Step 5: Commit**: `test(deployjobs): Windows deployments on the emulator: manual, ACME and Key Vault, R51 levels, the rollback guard rows, a kill at every journal point recovered (R61)`.

---

### Task 12: API: error codes, texts, OpenAPI **(parallel with Tasks 10-11)**

**Files:**
- Modify: `internal/api/errors.go` (`ErrWINBindingChanged` `ALC-WIN-0004` ... `ErrWINHelperRefused` `ALC-WIN-0012` of Global Constraints; `AllErrorCodes`; the params allowlist gains `helper_version`, `required_version`, `store`, `previous_sha1`), `internal/api/deployments_dto.go` or the file that renders `rollback_info` (`backup_store`, `backup_sha1` for a Windows deployment), `api/openapi.yaml` (the Deployment schema's two fields; the step param names; the provider capability lists of `windows`)
- Modify: `locales/common/en.json`, `locales/common/tr.json` (`errors.windows.<reason>.{title,cause,action}` for the nine reasons; `steps.import_chain|import_certificate|bind` exist since G: check)
- Modify: `docs/troubleshooting.md` (a section per new code, as the W1 ones)
- Extend: `internal/api/errors_winserver_test.go`, `internal/api/targets_winserver_test.go` (or a new `deployments_winserver_test.go`)

**Interfaces:**
- Consumes: the reasons of Tasks 7-8.
- Mirror: commit `ee1eaba7` (the files an error-code addition touches), W1 Task 13.

- [ ] **Step 1: Write the failing tests**
  - `TestWindowsErrorCodes`: the twelve reasons map to their codes and statuses, are in `AllErrorCodes`, have EN and TR texts and a troubleshooting section; `windows.busy`, `windows.io_error` and `windows.binding_changed` are retryable.
  - `TestWindowsDeploymentDTO`: a Windows deployment shows `backup_store` and `backup_sha1` and no `backup_dir`; a Nginx one is unchanged.
  - The OpenAPI conformance tests pass.
- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./internal/api/ -run 'Windows|OpenAPI|Catalogue'`
Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the tests**
Run: `go test -race -count=1 ./internal/api/ && go test -race -count=1 -tags integration ./internal/api/ -run 'Deploy|Windows|OpenAPI' && make i18n-check && make docs-check`
Expected: PASS.
- [ ] **Step 5: Commit**: `feat(api): ALC-WIN-0004..0012 for Windows deployments, the previous certificate of a Windows deployment, texts in English and Turkish (R61)`.

---

### Task 13: Web: deploy to Windows bindings, step names, grouping per certificate

**Files:**
- Modify: `web/src/components/WebsitesPanel.tsx` (Ruling 21's grouping for `windows`; the deploy control enabled by capability as for web servers), `web/src/components/DeployDialog.tsx` (or the component that picks locations: grouping and "Select all bindings of this certificate"), `web/src/pages/DeploymentDetailPage.tsx` (the Windows step names in their order, "Previous certificate: {{store}} \ {{sha1}}", the `win_chain_differs` note), `web/src/pages/TargetDetailPage.tsx` (the operations text: "Alice deploys certificates to the http.sys bindings of this server"), `web/src/api/types.ts` (`backup_store`, `backup_sha1`), `web/src/api/enums.ts` (the step error classes `key_unusable`, `read_back`, `store_error`, `backup_missing`)
- Modify: `web/src/locales/en.json`, `web/src/locales/tr.json`, `web/src/test/fixtures.ts` (a Windows deployment and grouped bindings)
- Tests: `web/src/components/WebsitesPanel.test.tsx` (or the file that tests it), `web/src/pages/DeploymentDetailPage.test.tsx`, `web/src/pages/TargetDetailPage.test.tsx`, `web/src/api/enums.test.ts`

**Interfaces:**
- Consumes: Task 12's API.
- Mirror: W1 Task 14; the Nginx deployment detail page's steps.

- [ ] **Step 1: Write the failing tests**
  - `WebsitesPanel`: a Windows server's bindings are grouped by certificate (two groups, one "No certificate"), each binding has an enabled deploy control; the W1 note "Not available for IIS servers yet" is gone for Windows; Nginx rows are unchanged.
  - Deploy dialog: "Select all bindings of this certificate" selects exactly the bindings of that group.
  - `DeploymentDetailPage`: steps "Import the chain", "Import the certificate", "Bind", "Verify" (EN) and their TR texts; the previous-certificate line; the chain-differs note with both numbers; `rollback_forbidden` still shows its text.
  - `enums.test.ts`: every new class and key in both locales.
- [ ] **Step 2: Run them to verify they fail**
Run: `cd web && npx vitest run src/components/WebsitesPanel.test.tsx src/pages/DeploymentDetailPage.test.tsx src/pages/TargetDetailPage.test.tsx src/api/enums.test.ts`
Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the tests**
Run: `cd web && npx vitest run && npx tsc --noEmit && npm run lint && cd .. && make i18n-check && make web-coverage`
Expected: PASS.
- [ ] **Step 5: Commit**: `feat(web): deploy to the http.sys bindings of a Windows server, grouped by the certificate they serve; Windows steps, previous certificate and chain note on the deployment page, English and Turkish (R61)`.

---

### Task 14: e2e: the fake learns the write subcommands; deploy and roll back in the browser

**Files:**
- Modify: `cmd/alice-fakewindows/main.go`, `cmd/alice-fakewindows/main_test.go` (`ctl stale-tls-on`, `ctl stale-tls-off`; the demo's state files in memory; the TLS CA of the fake trusted by the e2e stack's trust store as for fakefleet, so level 3 is reachable), `web/e2e/windows.spec.ts` (the deployment journey), `web/e2e/helpers.ts` (if a helper is needed)

**Interfaces:**
- Consumes: Tasks 4, 13; `wintest.Demo`.
- Mirror: `web/e2e/phase4.spec.ts` (the deploy journey and its rollback), W1 Task 15.

- [ ] **Step 1: Write the failing tests**
  - `main_test.go`: `ctl stale-tls-on`/`-off` toggle the model (an `iis-deploy` over SSH then a TLS dial serves the old leaf while on); the existing tests pass; coverage at least 90%.
  - `windows.spec.ts` (EN and TR, after W1's journey): upload a certificate for `www.win.example.test` (generated by the spec's helpers at run time), open `e2e-windows`, the bindings grouped by certificate; deploy to `http.sys/hostnameport/www.win.example.test:443`; the deployment page shows the steps import chain, import certificate, bind, verify and ends **committed** and **verified**; then `windowsExec(['ctl','stale-tls-on'])`, deploy a second certificate: the deployment ends **rolled back** with the verification-failed text, the previous certificate line shows; `windowsExec(['ctl','stale-tls-off'])`; `expectAccessible` on the deployment page.
- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./cmd/alice-fakewindows/`
Expected: FAIL (unknown ctl command).
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run**
Run: `go test -race -count=1 -cover ./cmd/alice-fakewindows/ ./cmd/alice/ && E2E_PROJECT=alice-e2e-w2 ALICE_E2E_PORT=9975 make e2e-up && E2E_PROJECT=alice-e2e-w2 ALICE_E2E_PORT=9975 make e2e; E2E_PROJECT=alice-e2e-w2 make e2e-down`
Expected: PASS, the whole e2e suite green.
- [ ] **Step 5: Commit**: `test(e2e): deploy to a binding of the emulated Windows server, committed and verified, then a verification failure rolled back (R61)`.

---

### Task 15: Decision, rulings, specification amendments, test IDs, documents

**Files:**
- Modify: `docs/superpowers/rulings/windows-iis.md` (a heading "W2 (R61)": the 24 rulings as built, F9 and F10 verdicts, the runner runs used, the acceptance lines, owner items, "Deferred to W3"), `docs/superpowers/specs/alice-v1/00-decisions.md` (R61 after R60: "R61 (owner approval of the Windows design with its §15 defaults, 2026-10-22; phase W2 ...; rulings in `docs/superpowers/rulings/windows-iis.md` "W2") Windows server target, phase W2: deployment, verification and rollback ..." summarising the subcommands, helper 0.2.0, the journal and fence, import and bind rules, the guard on the server, the provider's capabilities and verification, `win.chain_differs`, `ALC-WIN-0004..0012`, the UI grouping, no migration)
- Modify: `docs/superpowers/specs/alice-v1/02-architecture.md` (the "Windows servers" paragraph: the write flow and `tlsverify`), `03-integrations.md` §13A (deployment, verification, rollback and recovery, failure cases of design §11 W2 covers), `04-security.md` §14.4 (WN-1 residual now Nginx's, WN-4 rewritten for W2; new `WN-10` the PFX password and buffers (I), `WN-11` a journal or binding record tampered with on the server (T: Administrators and SYSTEM only, validated on read, refused when invalid), `WN-12` a late send after a fence (T, AUD-05), `WN-13` the budget answering a refusal after a change (R: Ruling 7)), `06-quality.md` §24.7 (rows below), `test/matrix/traceability.json`, `docs/security/traceability.md` (regenerated)
- Modify: `CHANGELOG.md` ("Unreleased": "Windows servers (deployment): ..."), `docs/admin-guide.md` ("Windows servers": deploy, verification levels, rollback, the Event Log entries), `docs/windows-host-preparation.md` (no longer read-only: what a deployment changes, the stores, the journal directory, the event ids 1001/1002, antivirus exclusion of `C:\ProgramData\Alice\helper`), `docs/troubleshooting.md` (from Task 12), `docs/superpowers/specs/2026-10-21-windows-iis-target-design.md` (status "W2 built (R61)"; "§17 Phase W2 as built" table), `docs/superpowers/specs/2026-10-21-deployment-targets-roadmap.md` (the Windows row)

The WIN rows (ID | case | tests):

| ID | Case | Tests |
|---|---|---|
| WIN-15 | Manual deploy to an SNI and an IP binding: committed at level 3, 2 or 1 | `internal/jobs/deployjobs:TestWindowsManualDeployment`, `TestWindowsDeploymentLevels`, `internal/providers/windows:TestDeployOutcomeTable`, `web/e2e/windows.spec.ts` |
| WIN-16 | The binding changed since discovery, or is gone | `TestWindowsHashMismatchChangesNothing`, `internal/providers/windows/winhelper:TestDeployRefusalsChangeNothing` |
| WIN-17 | The certificate is already bound | `TestWindowsUnchanged`, `TestDeployUnchanged`, `cmd/alice-winhelper:TestFidelityUnchangedAndSameHashWrite` |
| WIN-18 | Every other setting of the record survives | `TestBindPreservesTheWholeRecord`, `wintest:TestModelUpdateReplacesTheWholeRecord`, `cmd/alice-winhelper:TestFidelityDeployKeepsEverySetting` |
| WIN-19 | http.sys refuses the key, or the read-back differs: the helper restores | `TestBindKeyUnusable`, `TestReadBackMismatchSelfRestores`, `TestFidelityKeyUnusable` |
| WIN-20 | A failed verification rolls back | `TestWindowsFailedVerificationRollsBack`, `web/e2e/windows.spec.ts` |
| WIN-21 | A forbidden backup restores nothing (the server's own refusal) | `TestRestoreForbiddenOnEveryPath`, `TestWindowsRollbackGuardRows`, `cmd/alice-winhelper:TestRealRestoreForbidden` |
| WIN-22 | Kill or reboot at every journal point | `wintest:TestModelKillAtEveryPoint`, `internal/jobs/deployjobs:TestWindowsDeploymentSurvivesAKillAtEveryPoint` |
| WIN-23 | A late send after a fence never runs | `TestStatusAndFence`, `internal/providers/windows:TestWindowsLocationTargetContract` |
| WIN-24 | The budget never answers a refusal after a change | `TestWriteGateNeverLiesAfterTheFirstWrite`, `TestDeployOutcomeUnknownIsUncertain` |
| WIN-25 | Schannel serves another chain than deployed | `TestDeployChainDiffers`, `wintest:TestModelChainCache` |
| WIN-26 | ACME and Key Vault deploy automatically; cross-service needs trust | `TestWindowsACMEAutomaticDeployment`, `TestWindowsKeyVaultAutomaticDeployment`, `TestWindowsCrossServiceNeedsTrust` |
| WIN-27 | Key material only on standard input, buffers cleared | `TestNoKeyMaterialOutsideStdin`, `TestDeployKeyIsNeverOutsideStdin`, `winproto:TestDeployInputIsRedacted` |
| WIN-28 | The emulator answers as the real helper (write subcommands); the runner is left clean | `TestFidelityDeploySNIAndIP`, `TestFidelityDeployRefusals`, `TestFidelityStatusAndFence`, `TestRealRunnerIsClean` |

- [ ] **Step 1: Write the failing check**: add the rows to `06-quality.md` and run `make matrix-check MATRIXCHECK_FLAGS=-strict` (it fails: the IDs have no entries in `traceability.json`).
- [ ] **Step 2: Run it to verify it fails**
Run: `make matrix-check MATRIXCHECK_FLAGS=-strict`
Expected: FAIL (14 gaps).
- [ ] **Step 3: Write** the documents and `traceability.json`; regenerate: `go run ./tools/matrixcheck -spec docs/superpowers/specs/alice-v1/06-quality.md -map test/matrix/traceability.json -doc docs/security/traceability.md -update`.
- [ ] **Step 4: Verify**
Run: `make matrix-check MATRIXCHECK_FLAGS=-strict && make docs-check && make i18n-check`
Expected: PASS, 0 gaps, 0 pending.
- [ ] **Step 5: Commit**: `docs: Windows servers phase W2 (R61): decision, rulings, integration and security amendments, WIN-15..WIN-28, admin and host preparation guides, changelog`.

---

### Task 16: Final gates

**Files:** none new; fixes go to the task that owns the code.

- [ ] **Step 1: Full local gates**
Run: `make lint && make test && make i18n-check && make matrix-check MATRIXCHECK_FLAGS=-strict && make docs-check && make helper winhelper && make build && make coverage`
Expected: PASS; `covercheck` shows every floor met (the new `tlsverify` floor included) and none lower.
- [ ] **Step 2: Windows build and vet**
Run: `GOOS=windows GOARCH=amd64 go build ./cmd/alice-winhelper/ ./internal/providers/windows/... && GOOS=windows GOARCH=arm64 go build ./cmd/alice-winhelper/ && GOOS=windows go vet ./cmd/alice-winhelper/ ./internal/providers/windows/... && GOOS=windows go vet -tags alicetest ./cmd/alice-winhelper/`
Expected: PASS.
- [ ] **Step 3: e2e and image**
Run: `E2E_PROJECT=alice-e2e-w2 ALICE_E2E_PORT=9975 make ci` (or, when `make ci` cannot run here, `make image-check` and Task 14's e2e run)
Expected: PASS.
- [ ] **Step 4: Real Windows**: the `windows.yml` run of the branch head is green on both runners (runs counted, at most 20), or the rulings file lists it as an owner item and the acceptance report says acceptance item 4's second half is pending.
- [ ] **Step 5: Acceptance check against design §13 W2**, one line each in the rulings file: manual deploy to SNI and IP bindings at levels 3, 2, 1 (Tasks 8, 11, 14); hash mismatch changes nothing, unchanged answers unchanged (3, 11); failed verification rolls back, forbidden backup restores nothing with `deployment.rollback_forbidden`, the helper's refusal on a real runner (3, 8, 9, 11); crash table on the emulator, fidelity of every write subcommand on real Windows (4, 9, 11); ACME and Key Vault automatic deployment and the trust check (10, 11). Hand the branch `windows-w2` to the coordinator for the merge; do not merge or push `main`.

---

## Execution notes for the implementer

- Work in the worktree branch `windows-w2`; never switch branches inside a task. Take `main` in with `git merge main` (never rebase: `.gitleaksignore` pins commit hashes). You may push `windows-w2` (and only it) so `windows.yml` runs on the real runners; never push `main`. The coordinator merges to `main` and pushes.
- Dispatch order: 1 → (2 → 3 → 4) in parallel with 5 → 6 and 7 in parallel (disjoint files: `cmd/alice-winhelper` vs `internal/providers/windows`) → 8 → 9 (needs 4 and 6; spends runner runs) → 10 and 12 in parallel → 11 (needs 10) → 13 (needs 12) → 14 (needs 11 and 13) → 15 → 16. Task 9 may wait for runner capacity while 10-13 proceed.
- Review gates: after Tasks 3, 6, 8 and 11 a review against Review Focus 1-5 before the next dependent task; after Task 5 a review of Review Focus 6 only (Nginx unchanged). Every review finding is fixed in the task that owns the code, with its own commit.
- Record every ruling made during execution in `docs/superpowers/rulings/windows-iis.md` under the "W2 (R61)" heading (one line each: the ruling, then why), as W1 did; a W0-like fact (F9, F10) gets its verdict and the run link.
- Commit with `git -c user.name="Eren Altan" -c user.email="erenaltan@gmail.com" commit --only ...` and the trailer `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`.

## Left for later phases

- **W3**: R52 drift observation for Windows locations and the Windows causes in notices (re-pointed binding, certificate removed, key unusable, AutoCertRebind); `iis-cleanup` and the `windows.cleanup` job reading `imports.json`; the incident cleanup rule (Q7); the dump showing `alice_imported`.
- **W4**: `windows.yml` required for the Windows paths; the helper in the release bundle and `SHA256SUMS`; helper version `1.0.0`; the owner's manual matrix (2019, a domain account, Server Core, Defender on).
- **W5-W7**: CCS (`win_ccs_file`), RDP (`win_rdp`), WinRM transport.
- Not decided in W2 and left open: deploying to a location whose only problem is a key problem (Ruling 14); IDN host headers (Ruling 5); a manual "roll back this deployment" action (none exists for any target).

## Self-review notes (for the executor)

- **Spec coverage.** §6.3: Tasks 2, 3, 6 (steps 1-9), 8 (provider side). §6.4: Tasks 5, 8 (Ruling 15, 16). §6.5: Tasks 3, 7, 11. §7: Tasks 1-3, 6. §8: Tasks 7, 8 (capabilities, one connection per call). §9: Task 15's WN rows; Rulings 4, 7, 9, 11. §10: Task 8, 11. §11 rows W2 covers: binding changed or removed, import fails, bind fails or reads back wrong, Alice killed, server reboot, verification fails, other chain, key unusable, journal unwritable (Tasks 3, 4, 8, 11). §12 items 1-5 and 7: Tasks 2-4, 9, 11, 14. §13 W2 acceptance: Task 16 step 5. §15 Q5 (Task 13), Q9 (Ruling 4), Q10 (Ruling 13). W1 "Deferred to W2": Ex parameters (Tasks 1, 6, 9), key problems (Ruling 14), cut scans (Ruling 18), context (Ruling 7), host tokens (Ruling 5), Windows reasons (Ruling 6), STORE_ERROR (Ruling 19), grouping (Ruling 21).
- **Names used across tasks.** `winproto.DeployInput`, `DeployResponse`, `RestoreInput`, `RestoreResponse`, `StatusResponse`, `Locator`, `ExtendedParam`, `ValidHost`, `VersionAtLeast`, `WriteMinVersion`, `winhelper.WriteHost`, `winhelper.BuildPFX`, `winhelper.Forbids`, `wintest.Model.KillAt`, `Reboot`, `HoldLock`, `StaleTLS`, `ChainDiffers`, `tlsverify.Verify`, `tlsverify.ServerProbe`, `windows.Reason*`, `providers.BackupRef.Store/PreviousSHA1/PreviousSHA256`.
