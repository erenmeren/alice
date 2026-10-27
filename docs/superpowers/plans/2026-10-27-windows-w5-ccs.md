# Windows Servers, Phase W5 (Centralized Certificate Store) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A Windows server whose IIS uses the Centralized Certificate Store (CCS) in a local folder gets one `win_ccs_file` location per PFX file in that folder. Each location is linked to the IIS `https` bindings that IIS serves from that file. Alice deploys a certificate to such a location by writing the PFX atomically: a temporary file in the same folder, then `ReplaceFile` with a backup kept for rollback. The file is encrypted with the server's CCS password, which an Administrator enters once in Alice. Alice verifies the write by probing the linked host headers and by reading the file back. A failed verification restores the backup. A file replaced outside Alice is drifted and can be repaired, and backups are pruned with their journals.

**Architecture:** No new engine. The helper gains two protocol-1 subcommands, `ccs-dump` (read, the password on standard input) and `ccs-deploy` (write, the W2 transaction with a file step in place of the bind step). Restore, status and fence reuse `iis-restore`, `iis-status` and `iis-fence`, which act on the journal's kind. Both commands live in platform-neutral `winhelper` code behind new `WriteHost` methods, implemented by the real helper and by the emulator `wintest`. Alice side:
- the location kind `win_ccs_file` (migration `00036` widens the kind CHECKs and the credential purpose);
- the password, a sealed `credentials` row of the server, which reaches the provider through a new optional `providers.CCSPasswordSource` on the platform credential source;
- a `ccs` branch in the Windows provider's `Discover`, `DeployCertificate` and `VerifyDeployment`;
- the few inventory sites that name `win_sslbinding`;
- a password panel and the CCS file rows in the web UI.

The helper's version becomes `1.1.0`. A `1.0.0` helper keeps every W1-W4 feature and is never sent a CCS subcommand.

**Tech Stack:** Go 1.27.3 (`golang.org/x/crypto/ssh`, `golang.org/x/sys/windows`, pgx/v5, testcontainers), PostgreSQL, React 18 + Mantine + TanStack Query + i18next, Vitest, Playwright, GitHub Actions `windows-2022` / `windows-2025` runners.

**Spec:** `docs/superpowers/specs/2026-10-21-windows-iis-target-design.md`. This phase is §13 "Phase W5". It also draws on §3 (the `ccs` binding), §5 (`win_ccs` until W5), §6.2 item 4 (CCS enabled and its path), §6.3-§6.7 (the W2 transaction, verification, rollback, drift and cleanup, which W5 reuses), §7, §8 (one fresh connection per helper call), §13 "Interactions with other work", §14 F2, F3 and F4, and §16-§19 (W1-W4 as built). Rulings and the "Deferred to W5+" list are in `docs/superpowers/rulings/windows-iis.md`. The format models are `docs/superpowers/plans/2026-10-23-windows-w4-ci-and-release.md`, `2026-10-23-windows-w3-drift-and-cleanup.md` and `2026-10-22-windows-w2-deployment-verification-rollback.md`. W5 is "on demand" in the design. The coordinator assigned it on 2026-10-27, and the owner confirms the rulings listed under [Owner to confirm](#owner-to-confirm).

**Scope:**
- In scope: design §13 W5, which covers the `win_ccs_file` location kind, the CCS password, the atomic write with a backup, verification through the linked `ccs` bindings, rollback, drift, pruning of backups, helper `1.1.0`, the UI and the documents.
- Not in scope:
  - a CCS folder on a share of another server (the "farm" layout, Ruling 3);
  - creating a CCS file that does not exist yet (Ruling 7);
  - removing the CCS password;
  - RDP (W6) and WinRM transport (W7);
  - the items carried in "Deferred to W5+", which stay carried unless a ruling below names them.

**Decision:** R68 "Windows server target, phase W5: Centralized Certificate Store" (R67 is the last entry of `00-decisions.md`). **Size:** M, 10 tasks (about 6-8 implementer hours of code, plus runner waits). **Migration:** `00036` (Ruling 1).

## Before you start: what W5 must measure on a runner

Four facts are new. Task 5's real tests check them before the code that depends on them is called done. Record each verdict, with its run link, as a ruling under the "W5 (R68)" heading of `docs/superpowers/rulings/windows-iis.md`.

| Fact | What W5 relies on | If it is wrong | Tasks |
|---|---|---|---|
| F15 | `ReplaceFileW(file, tmp, backup, REPLACEFILE_WRITE_THROUGH)` on a CCS file keeps the file's ACL, leaves the old bytes in the backup, and makes IIS serve the new certificate at the next fresh handshake without a restart or `iisreset`. The test measures the delay, polling every 100 ms for up to 120 s. A file named `*.tmp` or `*.bak` in the folder is never served. Also recorded: whether adding an IIS binding with `sslFlags=3` through appcmd creates the http.sys `ccs:<port>` record. | (a) If a same-record update of the http.sys `ccs:<port>` record (F2/F5's same-hash write) makes the pickup immediate, `ccs-deploy` makes that update after the replace, for each `ccs` record of a linked port. (b) Otherwise `winproto.CCSPickupWait` is set to the measured maximum plus 50 %, and the provider's verification retries for that long. Record which route applies. | 3, 5, 7 |
| F16 | IIS opens a PFX that `BuildPFX` wrote (PBES2/AES-256-CBC key, plain certBag, HMAC-SHA256 MAC) with its configured private-key password. A file written with another password is not served; the test records how the failure surfaces (handshake error, alert, Application event id). `PFXImportCertStore(PKCS12_NO_PERSIST_KEY)` reads a PFX's certificates without leaving a key file (machine and user key directories counted). A wrong password gives `ERROR_INVALID_PASSWORD` (86) or the code measured. | If IIS refuses the `BuildPFX` format, write the PFX through `PFXExportCertStoreEx` of a memory store (the route that reads the key from `NCryptImportKey` with an export policy for the export only, then deletes it); record the route. If `NO_PERSIST_KEY` leaves a key file, delete it after the read, and record that. | 2, 5 |
| F17 | IIS's file lookup for SNI host `h` is `h.pfx`, then `_.<parent>.pfx` (one label only), compared without case. An explicit `hostnameport` record for `h:port` takes precedence over the CCS binding on the same port. | Change the linking rule of Ruling 6 to the measured order, and record it. If CCS wins over `hostnameport`, the `win_sslbinding` location of that host gets the warning `win.ccs_shadows` (Task 7). | 5, 7 |
| F18 | The chain served for a CCS file: are the PFX's intermediates sent, or only those schannel finds in `LocalMachine\CA`? | Either way `ccs-deploy` keeps W2's `import_chain` step and writes the intermediates into the PFX. Only the chain-length comparison (`win.chain_differs`) follows the measured source. | 3, 5, 7 |

## Global Constraints

- **Branch.**
  - Worktree branch `windows-w5`, cut from `main` at `e15fad4b` or later. **The first commit of the branch is this plan** (`docs: Windows servers phase W5 (CCS) plan (R68)`). The plan is never committed on `main`.
  - Never switch branches inside a task. Take `main` in with `git merge main`, never rebase.
  - The executor may push `windows-w5` (only that branch) so `.github/workflows/windows.yml` runs on the real runners. It never pushes `main`, never opens a pull request and never changes repository settings. The coordinator merges and pushes.
- **Commits.**
  - `git -c user.name="Eren Altan" -c user.email="erenaltan@gmail.com" commit --only -m "<subject> (R68)" -m "Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>" -- <paths>`. Every subject ends with `(R68)`.
  - New files: run `git add -- <path>` first. Never `git add -A` or `git add .`. Check `git status --short` before each commit.
  - Never touch `.claude/`, the untracked PDFs, `alice-helper` (an untracked binary at the root), `docs/security/reviews/independent-audit*` or the other untracked review files.
  - `.gitleaksignore` is pinned to commit hashes, so never rebase, squash or amend a pushed commit. Never commit key material or a real password. Tests generate keys at run time (`internal/testutil/pki`) and use passwords built at run time (never a literal that gitleaks flags; if it flags one anyway, follow commit `4d5f2eff`).
- **Security guards that must stay green.**
  - Connections and SSH: `TestNoCodeAcceptsAnyHostKey`; the archtest rule that only `internal/providers/windows` and `linuxssh` call `linuxssh.ForcedCommand`.
  - Imports and pins: `tools/pincheck`; `TestImportRules` and `TestAllowed` (`internal/archtest/arch_test.go`); `TestWindowsHelperLinksOnlyItsProtocol` (W5 adds no dependency to the helper).
  - Build and release: `TestReleaseBinariesLinkNoTestPackages`; `TestNoWindowsReservedFileNames`; `TestWindowsWorkflowWatchesEveryDependency`; `TestWindowsWorkflowRequiresEveryRealTest`; `TestWindowsHelperBuildFlagsAgree`; `make release-symcheck`; `make image-check`.
- **Protocol.**
  - `winproto.Protocol = 1` and `MinProtocol = 1` stay. `winproto.Version = "1.1.0"`.
  - New constant `CCSMinVersion = "1.1.0"`. `WriteMinVersion = "0.2.0"` and `CleanupMinVersion = "0.3.0"` are unchanged.
  - New subcommands `ccs-dump` and `ccs-deploy --op <uuid>`. Both take JSON on standard input.
  - A `1.0.0` helper answers them `UNKNOWN_SUBCOMMAND` (exit 2, nothing changed). Alice refuses before sending to a helper below `CCSMinVersion`.
  - The command line never carries a path, a file name, a host or the password (W2 Ruling 4, `winproto.ValidToken`).
  - One fresh SSH connection per helper call (design §8).
- **Helper version literal.** Every place that asserts the helper's own version changes from `1.0.0` to `1.1.0` in Task 1 (the W4 deferred minor):
  - `internal/providers/windows/winproto/winproto.go:28` and its package comment;
  - `winproto_test.go:295`, `:589` and `TestReleasedHelperVersion` (`:615-634`);
  - `internal/providers/windows/winhelper/winhelper_test.go:63` (`TestRunVersion`);
  - `internal/providers/windows/provider_test.go:123` (`HelperVersion` from the emulator);
  - `docs/admin-guide.md:1532` ("Helper versions").

  The `HelperVersion: "1.0.0"` values in `internal/jobs/targetjobs/*_integration_test.go`, `internal/inventory/status_integration_test.go`, `internal/api/targets_handlers_test.go`, `web/src/test/fixtures.ts` and `web/src/pages/TargetDetailPage.test.tsx` are fixture values that do not read `winproto.Version`, so they stay.
- **Paths on the server.**
  - As in W2: the journal `C:\ProgramData\Alice\helper\journal\<op>.json`, the file records `...\helper\bindings\<hash>.json` (keyed by the CCS file's canonical text), the lock `...\helper\helper.lock`.
  - New in the CCS folder only: `<file>.alice-<op8>.bak` (the backup) and `.alice-<op>.tmp` (the temporary file). Neither ends in `.pfx`, so IIS never serves them (F15).
- **Event source `Alice Helper`:** 1001 deploy, 1002 restore, 1003 certificate removed; **1004 CCS file written** (W5). No event carries a password or key material.
- **Error codes.** The existing codes are `ALC-WIN-0001..0014`. New (Task 6): `ALC-WIN-0015` `windows.ccs_disabled` (409), `ALC-WIN-0016` `windows.ccs_path_changed` (409), `ALC-WIN-0017` `windows.ccs_password_mismatch` (409), `ALC-WIN-0018` `windows.ccs_password_missing` (409), `ALC-WIN-0019` `windows.ccs_password_invalid` (422), `ALC-WIN-0020` `windows.ccs_file_not_found` (409).
- **Test IDs:** `WIN-46`..`WIN-55`. **STRIDE:** `WN-19`..`WN-22`. **Migration:** `00036` only (Ruling 1); the next free number after it is `00037`.
- **Coverage floors** (`coverage-floors.json`; never lower one): `winproto` 100, `winhelper` 95, `windows` 95, `wintest` 90, `cmd/alice-fakewindows` 90, `winjobs` 95. No new Go package.
- **Locales.** EN and TR in `locales/common/{en,tr}.json` and `web/src/locales/{en,tr}.json`, with identical keys and placeholders (`make i18n-check`). Turkish never puts a suffix on a placeholder that holds a path or a host.
- **Real-Windows runs.**
  - Budget: **8 runs** of `windows.yml` (windows-2022 and windows-2025 legs). Every run counts; record each in a runner-run table in the rulings file.
  - Fixtures: ports **45480-45499**, names starting `alice-w5-`, a CCS folder `C:\alice-w5-ccs-<random>`, and a local account `alice-w5-ccs` (CCS's access account). Cleanup is registered before the fixture is made.
  - The tests restore the CCS configuration (disabled, the registry key as found) and delete the account, the site, the folder and every http.sys record they made. `TestRealRunnerIsClean` is extended to check all of that (W2 Ruling 22).
  - The `Web-CertProvider` feature, once installed, stays installed (feature removal needs a restart).
  - Where a test needs a TCP listener of its own (not an http.sys binding), it asks the OS for a free port (`127.0.0.1:0`). R65's canary test showed that fixed ports in the ephemeral range collide on GitHub runners. The fixed ports above are http.sys/IIS bindings only.
- **e2e.** `E2E_PROJECT=alice-e2e-w5 ALICE_E2E_PORT=9982 make e2e-up e2e; E2E_PROJECT=alice-e2e-w5 make e2e-down`; final `E2E_PROJECT=alice-e2e-w5 ALICE_E2E_PORT=9982 make ci`. Docker-based Go runs and Playwright never run at the same time, and neither runs while another `make ci` on the machine is active.
- **Verification commands.**
  - `go build ./... && go vet ./... && go vet -tags integration ./...`
  - `GOOS=windows GOARCH=amd64 go build ./cmd/alice-winhelper/ ./internal/providers/windows/... && GOOS=windows GOARCH=arm64 go build ./cmd/alice-winhelper/ && GOOS=windows go vet ./cmd/alice-winhelper/ ./internal/providers/windows/... && GOOS=windows go vet -tags alicetest ./cmd/alice-winhelper/`
  - `go test -race -count=1 ./<pkgs>`; `go test -race -count=1 -tags integration ./<pkgs>`
  - `make lint`, `make test`, `make i18n-check`, `make matrix-check MATRIXCHECK_FLAGS=-strict`, `make docs-check`; final `make coverage` and `make ci`
  - web: `cd web && npx vitest run <files> && npx tsc --noEmit && npm run lint`
  - A helper change regenerates the checksums: `make helper winhelper`.

## Rulings (where the spec is silent; each goes into `docs/superpowers/rulings/windows-iis.md` under a new "W5 (R68)" heading for the owner to confirm)

1. **Decision R68; one migration, `00036`.** A new location kind cannot avoid schema: `certificate_locations_kind_check` and `deployments.location_kind`'s CHECK list the kinds (00031). The password needs a credential purpose (`credentials_purpose_check`, `_kind_check`, `_target_purpose`, `_kind_purpose`). `00036` widens exactly those six CHECKs with `win_ccs_file`, purpose `win_ccs` and kind `win_ccs_password` (target-bound, like `azure_vault`). Nothing else changes: the locator, the details and `verify_address` are 00031's columns. Its Down restores the 00035 lists and refuses (as 00031's Down does) while a `win_ccs_file` location, deployment or `win_ccs` credential exists.
2. **Helper 1.1.0, protocol 1, `CCSMinVersion` 1.1.0; two new subcommands only.**
   - `ccs-dump` and `ccs-deploy` are added to protocol 1, because they are additive (W2 and W3 did the same).
   - Restore, status and fence of a CCS operation go through `iis-restore`, `iis-status` and `iis-fence`, which dispatch on the journal's new `kind` field (`"ccs_file"`; absent means a binding). This keeps one recovery path in the provider and in the engine. Only a 1.1.0 helper writes a CCS journal, so an older helper never meets one.
   - The provider refuses a CCS call to a helper below 1.1.0 before sending: discovery skips CCS (Ruling 18), and a deployment ends `windows.helper_outdated` with `required_version 1.1.0`. The backstop `UNKNOWN_SUBCOMMAND` maps to the same reason.
   - `TestFidelityVersionAndRefusals` keeps probing `rdp-deploy` as its unknown subcommand.
3. **Supported layout: a local CCS folder on the server whose IIS uses it.**
   - The folder is IIS's `CertStoreLocation` (`HKLM\SOFTWARE\Microsoft\IIS\CentralCertProvider`, read by `win-facts` since W1). It must be an absolute drive path (`X:\...`). A UNC path, `\\?\` or `\\.\`, a relative path, or a folder that is a reparse point is not managed. Discovery then reports the server warning `win_ccs_remote` (UNC) or `win_ccs_path_unsupported` (the rest) and no `win_ccs_file` locations.
   - The helper writes a local path only, so there is no double hop.
   - The farm layout (IIS servers reading `\\fileserver\certs`, the files written on the file server as a target of its own) is deferred. It needs the share-to-folder resolution and links across targets.
4. **The path comes from the server only.**
   - Every `ccs-dump` and `ccs-deploy` reads `Enabled` and `CertStoreLocation` from the registry itself.
   - Alice sends the folder it discovered only as a compare-and-swap value. The comparison folds ASCII case and trims one trailing backslash. A difference refuses with `CCS_PATH_CHANGED` (exit 3, nothing changed). A disabled CCS refuses with `CCS_DISABLED`.
   - The helper derives the file name from the host (Ruling 5) and opens it inside the folder with `FILE_FLAG_OPEN_REPARSE_POINT`. A file that is a reparse point or not a regular file is refused (`INVALID_ARGUMENT`).
   - Nothing about the file is ever on the command line (it carries only `--op`).
5. **File-name rule.**
   - Host `a.example.com` maps to `a.example.com.pfx`; wildcard host `*.example.com` maps to `_.example.com.pfx`. The host must be `winproto.ValidHost` (lower-case A-labels).
   - Back from a folder entry: the name is folded to ASCII lower case, `.pfx` is stripped and a leading `_.` becomes `*.`.
   - A `.pfx` whose name gives no valid host is ignored and counted (server warning `win_ccs_files_ignored`, param `count`).
6. **One location per file, discovered automatically; links derived by Alice.**
   - No Administrator "create location" flow. Each `.pfx` that `ccs-dump` reads becomes a location: kind `win_ccs_file`, locator `{"type":"ccs_file","path":"<folder as read>","host":"<host>"}`, `cert_path` the full Windows path `<folder>\<file>` (unique per server; shown in the UI).
   - Details: `ccs_path`, `file_name`, `file_sha256` (the bytes' SHA-256, for display), `file_size`, `modified_at`.
   - Servers: the IIS `https` bindings with the CCS flag (`sslFlags & 0x2`) whose host header IIS serves from this file. The exact file is matched first; otherwise the wildcard file of the one-label parent (F17). `CertServer.Names` is the host header, `Listens` is `ip:port`, `Section` is the site.
   - The http.sys `ccs:<port>` record location stays as W1 made it (Ruling 19).
7. **No file creation in W5.**
   - An IIS CCS binding whose host maps to no file gets a `win_ccs_file` location with problem `cert_missing` (unsupported, file problem). Its UI text says to place the first file in the folder; Alice manages it from then on.
   - The engine's compare-and-swap needs an existing token (the Linux helper refuses an absent `--expect-sha256` too). Allowing an "absent" token would change inventory's supported-location rule (`locations.go:204-211`).
   - Creation is deferred.
8. **A file no IIS binding uses (unlinked) is deployable.**
   - The location is supported with the location warning `win_ccs_unlinked`.
   - Its verification is the helper's read-back only (Ruling 14 step 8). `VerifyDeployment` answers it as a skipped verification (R51 level 1) with the param `ccs_unlinked` on the verify step.
9. **The CCS password: one per Windows server, entered by an Administrator.**
   - IIS's CCS has one private-key password for every file of the store, so Alice keeps one per server, not one per location. (The brief said "a location secret"; this ruling narrows it.)
   - It is set and replaced through `PUT /api/v1/targets/{id}/ccs-password`: Windows servers only, permission `rbac.CredentialsManage` (an Administrator with step-up, never an API token, as `PUT .../vault-credentials`), licence `ClassChange`, body cap 4 KiB, the field a `secretText`.
   - It is stored as a `credentials` row (purpose `win_ccs`, kind `win_ccs_password`, `target_id` = the server, sealed with AAD `credentials/<id>/ciphertext`). Rows are append-only; the newest row of the server is its password. There is no delete in W5.
   - Audit `target.ccs_password_set` (target, no secret). The target DTO gains `ccs_password_set_at` (RFC 3339 or null; Windows servers only).
10. **Password rule: 12 to 128 characters, printable ASCII `0x21`-`0x7E`.**
    - This is `BuildPFX`'s `validPassword` alphabet: its BMPString (MAC) and PBKDF2 bytes are then the same text. A password outside it is refused with `ALC-WIN-0019` (422) and never stored.
    - Alice generates nothing here: the owner of the CCS chose the password, so the W2 rule (192 random bits) cannot apply. The minimum length is the floor Alice can enforce.
    - A CCS configured with an empty, shorter, space-holding or non-ASCII password cannot be managed in W5.
11. **Password transport.**
    - The password travels only inside the JSON on standard input of `ccs-dump` and `ccs-deploy`. The types (`CCSDumpInput`, `CCSDeployInput`) redact it in `String`, `GoString` and `LogValue`, as `DeployInput` does. The buffers are cleared after the send.
    - It never appears in the command line, a journal, an event, a log line, an error, an API answer, an audit row or a fixture file.
    - The provider obtains it through `providers.CCSPasswordSource` (`CCSPassword(ctx, target uuid.UUID) (secrets.Plaintext, func(), error)`), implemented by inventory's platform credential source. It answers only for a live Windows target and only with a `win_ccs` row whose `target_id` is that target, else `errForeignCredential`. The Windows provider asks only for its own `TargetRef.ID`.
12. **Alice never reads IIS's stored password.**
    - The registry value `PrivateKeyPassword` is encrypted by IIS, and decrypting it would put a second secret on the wire.
    - A mismatch is detected through the files instead. A file the password does not open gets the problem `ccs_password_mismatch` (unsupported, so never deployed over), and the server gets the warning `win_ccs_password_mismatch` (param `count`).
    - After a write, the probe of a linked host proves that IIS opens the new file (F16).
13. **Token = the SHA-256 of the leaf's DER in the file**, as for an http.sys binding (`newCertSHA256` treats `win_ccs_file` like `win_sslbinding`). A re-export of the same certificate with new bytes is therefore no change, and another certificate is. The bytes' hash is a detail, not the token.
14. **`ccs-deploy` transaction**, in this order, each refusal before step 5 changing nothing:
    1. Decode stdin strictly. Elevated. Lock. Then refuse with `OPERATION_EXISTS` or `FENCED` as W2 does.
    2. Registry: refuse with `CCS_DISABLED`, `CCS_PATH_CHANGED` or `CCS_PATH_UNSUPPORTED` (Rulings 3, 4).
    3. Read the file (at most `MaxCCSFile` = 256 KiB): absent → `CCS_FILE_NOT_FOUND`; the password does not open it → `CCS_PASSWORD_MISMATCH`; its leaf ≠ `expect_sha256` → `HASH_MISMATCH` (exit 3). When the leaf equals the new leaf and the file's intermediates equal the deployment's, answer `unchanged`.
    4. Journal `prepared` with `kind` `ccs_file`, the folder, the file name, the previous leaf's SHA-1, SHA-256 and SPKI SHA-256, the previous file's bytes SHA-256, the backup and temporary names, the new leaf's SHA-256 and the forbidden lists. The file record (a binding record keyed by `ccs/<file>`) names this operation.
    5. Step `import_chain` (W2's code: intermediates into `LocalMachine\CA`, never replaced, recorded).
    6. Journal `writing`. Step `write_file`:
       - build the PFX: leaf, key and intermediates, `BuildPFX` with the CCS password;
       - write `.alice-<op>.tmp` (`CREATE_NEW`, `FILE_FLAG_WRITE_THROUGH`, `FlushFileBuffers`);
       - `ReplaceFileW(file, tmp, <file>.alice-<op8>.bak, REPLACEFILE_WRITE_THROUGH)`.

       A failure before the replace removes the temporary file and answers `restored` with `failed_step write_file` and no write.
    7. F15 route (a), only if F15 needs it: the same-record update of each `ccs` record of the linked ports.
    8. Read back: the bytes' SHA-256 equals the built PFX's, and the password opens the file to the new leaf. On a mismatch, self-restore under the guard (Ruling 15).
    9. Journal `committed`; event 1004 `ccs file <name> sha256 <old> -> <new> op <op>`.

    The answer is `winproto.DeployResponse` (shared with W2) with `Store` empty and `AliceImported` false (no store import). `BuiltChainLength` is the chain Windows builds for the leaf after the imports (W2's function).
15. **Rollback through `iis-restore` on a CCS journal.**
    - The guard is checked on the journal's previous leaf and SPKI hashes (R48), monotonic as in W2.
    - The file must still be the bytes this operation wrote; otherwise the restore answers `SUPERSEDED` or `file_changed` and does nothing.
    - The backup must exist with the previous file's bytes; otherwise `BACKUP_MISSING`, refused before any write.
    - Then `MoveFileEx(backup, file, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)`, a read-back, journal `restored`, event 1002.
    - `iis-status` answers `current_cert_sha256` from the file's bytes: the new leaf, the previous leaf, else `""`. `iis-fence` is unchanged.
16. **Backups, temporary files and W3 cleanup.**
    - A backup stays until `iis-cleanup --plan` prunes its journal. W3 Ruling 11's ages apply: final journals after 7 days, `restore_failed` after 30, never `writing` or `restoring`.
    - Pruning a CCS journal first deletes its temporary file, then its backup (only when the name is the journal's and the bytes' SHA-256 equals the journal's previous file hash), then the journal. A restore consumes the backup.
    - W3's certificate cleanup ignores the CCS folder. A CCS deployment imports no leaf into a store (only intermediates into `CA`, which are never removed), and a file is not a store certificate.
17. **CCS turned off, or its path changed, after a location exists.**
    - Discovery then lists no files for the old folder, so its locations go missing by the existing scan rule.
    - A queued deployment is refused by the helper with nothing changed: `CCS_DISABLED` → `ALC-WIN-0015`, `CCS_PATH_CHANGED` → `ALC-WIN-0016`.
    - A rollback of a committed CCS operation still restores into the folder its journal names. A deliberate path change does not strand a half-done operation.
18. **Discovery.**
    - `Discover` calls `ccs-dump` after `iis-dump`, each on a fresh connection, only when three things hold: the dump says CCS is enabled with a local path, the helper is at least 1.1.0, and the server has a password. Otherwise there are no `win_ccs_file` locations, and the server warning is `win_ccs_password_missing` or `win_ccs_helper_outdated`.
    - A failed `ccs-dump` (error, budget, undecodable answer) keeps the `iis-dump` result and adds `list_truncated` and `locations_dropped` (W2 Ruling 18: nothing is marked missing).
    - Bounds: `MaxCCSFiles` = 500 files and 256 KiB each, within `HelperBudget`. More files set `truncated`, which gives the same two warnings. A larger file gets the problem `too_large`.
    - `ccs-dump` is elevated (the folder's ACL normally admits Administrators and SYSTEM) and runs under no lock.
19. **The http.sys `ccs` record location stays.** It is still a `win_sslbinding` location, unsupported `win_ccs`, because it names no certificate. Its UI text and the server warning `win_ccs_enabled` now point to the CCS files and the password panel.
20. **Verification endpoints.**
    - There is one endpoint per linked IIS binding: its port, SNI = its host header (`tlsverify.SNIFor`: a `*.` host becomes `alice-check.`, which IIS serves from the wildcard file), the address by W2's rules (`*` → Alice's probe to the target's address, the helper's probe to `127.0.0.1`), at most `maxEndpoints`.
    - The Administrator's port, SNI, skip and probe-address options apply.
    - The served chain is compared with the chain the helper built (`win.chain_differs`; F18 decides which source).
    - With F15 route (b), the verify attempts span `CCSPickupWait`.
21. **Engine and inventory.** `win_ccs_file` is a non-file kind wherever the code tests `IsFile()`. At the sites that name `win_sslbinding`:
    - `newCertSHA256` (`deployment_records.go:247`): the leaf, Ruling 13.
    - `startBackupRef` (`:718`): `BackupRef{OperationID, PreviousSHA256: token}`; the journal holds the backup.
    - The details update (`:1142`): binding only.
    - `windowsLost` (`:1313`): includes `win_ccs_file`.
    - `notify.go:273` and `drift.go:779`: a CCS file keeps the file texts, because it is a file.
    - `bindingBroken`, `driftCause`, AutoCertRebind and the cleanup judge (`drift.go:120/128/424`, `windows_cleanup.go:396`): binding only.

    The steps are `import_chain`, the new `write_file` (`providers.StepNameWriteFile`; `winproto.StepWriteFile`, compared by the existing test) and the engine's `verify`, `restore` and `verify_old`.
22. **Drift.** A file replaced outside Alice (another leaf) is drifted by the generic rule (the scan's token, the probe). The repair is a deployment with trigger `drift_repair` (ClassContinuity), guarded by the token. A file the password no longer opens is a problem (Ruling 12), not drift, and is never repaired.
23. **Interactions, unchanged** (design §13):
    - Scoped access: a CCS location belongs to its server's service.
    - Licence: discovery, `ccs-dump` included, is ClassReadOnly; deployment and pruning ClassChange; automatic deployment and drift repair ClassContinuity; setting the password ClassChange, as vault credentials.
    - Incidents: CCS locations are incident places, and the guard is checked twice.
    - Canary: applies as to any location.
    - Network discovery: an endpoint whose certificate a CCS location holds shows as managed.
24. **Test IDs and STRIDE.** `WIN-46`..`WIN-55` (Task 9 lists them).
    - STRIDE `WN-19` (I): the CCS password disclosed (log, command line, API, backup of Alice).
    - `WN-20` (T): a write outside the CCS folder (path or name injection, reparse point, a changed registry path).
    - `WN-21` (D): a write that IIS cannot open breaks every site served by the file.
    - `WN-22` (I): backup files holding a password-encrypted private key stay in the CCS folder for up to 7 days.
25. **e2e.**
    - A new journey `web/e2e/windows-ccs.spec.ts` (EN and TR) against `cmd/alice-fakewindows`, whose demo host gains:
      - CCS enabled at `C:\CCS`;
      - one file `ccs.example.test.pfx` made at start with a password the fake prints on `ctl ccs-password`;
      - an IIS CCS binding on its TLS port;
      - one unlinked file `_.unlinked.test.pfx`.
    - The journey:
      1. the CCS files are absent and a hint is shown;
      2. setting the password asks for step-up, and the panel then shows the date;
      3. after the rescan, the linked file shows its site and the unlinked one its warning;
      4. a deployment commits and verifies;
      5. with `ctl stale-tls-on`, a deployment rolls back to the backup;
      6. `expectAccessible` on the server page.
    - Separate from `windows.spec.ts`, so W2's serial journey keeps its state.
26. **Runner hygiene and budget** as in Global Constraints. The CCS fixture is made with PowerShell (`Install-WindowsFeature Web-CertProvider`, `Enable-WebCentralCertProvider` with the `alice-w5-ccs` account and a run-time password), the only PowerShell in W5, and in tests only.

## Review Focus

1. **Nothing is written outside the CCS folder, and only to the file named by the host.** Inputs: a host with `..`, `\`, `:`, a `%` or a NUL; a registry path that changed between discovery and deploy; a UNC path; a file or folder that is a junction or symlink. Tests: Task 1 `TestCCSFileNameRule`, `TestValidCCSPath`; Task 3 `TestCCSDeployRefusesBeforeAnyWrite`; Task 5 `TestRealCCSRefusesReparsePoints`.
2. **The password never leaves standard input.** Inputs: `%v`, `%+v`, `%#v` and slog of every input type; a helper error; the journal; event 1004; the API answer and audit row; a failed deployment's params. Tests: Task 1 `TestCCSInputsRedact`; Task 3 `TestCCSJournalHoldsNoPassword`; Task 6 `TestCCSPasswordNeverEchoed`; Task 7 `TestCCSPasswordIsNeverOutsideStdin`.
3. **A write IIS cannot open never stays.** Inputs: a wrong password Alice holds (the existing files do not open: deploy refused); a correct-looking file that IIS still refuses (the probe fails: the backup is restored); an unlinked file (read-back only, level 1, the warning shown). Tests: Task 3 `TestCCSDeployReadBackRestores`; Task 7 `TestCCSFailedVerificationRestoresBackup`, `TestCCSUnlinkedIsReadBackOnly`; Task 5 `TestRealCCSWrongPasswordIsNotServed` (F16).
4. **A kill at every journal point recovers, and a restore never puts back a forbidden certificate or overwrites a third party's file.** Tests: Task 3 `TestCCSKillAtEveryPoint`, `TestCCSRestoreRules`; Task 7 `TestWindowsCCSCrashTable`.
5. **A 1.0.0 helper and a server without a password keep working as in W4**: discovery of bindings unchanged, no CCS subcommand sent, the old `win_ccs` reason. Tests: Task 7 `TestCCSNeedsHelper110`, `TestDiscoverWithoutPasswordIsW4`.

---

### Task 1: `winproto`: helper 1.1.0, the CCS subcommands, shapes and rules

**Files:**
- Modify: `internal/providers/windows/winproto/winproto.go`, `internal/providers/windows/winproto/winproto_test.go`, `internal/providers/windows/winhelper/winhelper_test.go` (`TestRunVersion`), `internal/providers/windows/provider_test.go` (`:123`), `docs/admin-guide.md` (`:1532`, one sentence)

**Interfaces:**
- Produces (package `winproto`):
  - `Version = "1.1.0"`, `CCSMinVersion = "1.1.0"`; `SubCCSDump = "ccs-dump"`, `SubCCSDeploy = "ccs-deploy"`
  - Codes: `CodeCCSDisabled = "CCS_DISABLED"`, `CodeCCSPathChanged = "CCS_PATH_CHANGED"`, `CodeCCSPathUnsupported = "CCS_PATH_UNSUPPORTED"`, `CodeCCSPasswordMismatch = "CCS_PASSWORD_MISMATCH"`, `CodeCCSFileNotFound = "CCS_FILE_NOT_FOUND"` (all exit 3, nothing changed)
  - `StepWriteFile = "write_file"`; `JournalKindCCS = "ccs_file"`; `LocatorCCSFile = "ccs_file"`
  - Bounds: `MaxCCSFiles = 500`, `MaxCCSFile = 256 << 10`, `MaxCCSDumpInput = 4 << 10`, `MaxCCSDeployInput = 256 << 10`, `MinCCSPassword = 12`, `MaxCCSPassword = 128`, `MaxCCSPath = 240`; `CCSPickupWait time.Duration = 0` (Task 5 sets it if F15 needs route (b))
  - File problems: `CCSProblemPasswordMismatch = "ccs_password_mismatch"`, `CCSProblemNotPFX = "not_a_pfx"`, `CCSProblemNoKey = "key_missing"`, `CCSProblemTooLarge = "too_large"`
  - Warnings: `WarnCCSRemote = "win_ccs_remote"`, `WarnCCSPathUnsupported = "win_ccs_path_unsupported"`, `WarnCCSFilesIgnored = "win_ccs_files_ignored"`
  - `func CCSFileName(host string) (string, bool)` and `func CCSHost(fileName string) (string, bool)` (Ruling 5); `func ValidCCSPassword(pw []byte) bool` (Ruling 10); `func ValidCCSPath(p string) bool` (absolute `X:\`, at most `MaxCCSPath`, no `\\` prefix, no `..` segment, no control characters, no `"*?<>|`)
  - `type CCSDumpInput struct{ Password string }` (tag `password`); `type CCSFile struct{ Name, Host, FileSHA256, ModifiedAt, LeafDER, Problem string; Size int64; Chain []string }` (tags `name, host, file_sha256, modified_at, leaf_der, problem, size, chain`; DERs standard base64); `type CCSDumpResponse struct{ OK, Enabled, Local bool; Path string; Files []CCSFile; Ignored int; Truncated bool }`
  - `type CCSDeployInput struct{ Path, Host, ExpectSHA256, ChainPEM, KeyPEM, Password string; ForbiddenSPKI, ForbiddenLeaf []string }` (tags `path, host, expect_sha256, chain_pem, key_pem, password, forbidden_spki_sha256, forbidden_leaf_sha256`), and `CCSDumpInput`, both with redacting `String`, `GoString` and `LogValue`

- [ ] **Step 1: Write the failing tests** in `winproto_test.go`:
  - `TestReleasedHelperVersion` updated: `Version == "1.1.0"`; every minimum is at most `Version`; `VersionAtLeast("1.0.0", CCSMinVersion)` is false; `VersionAtLeast("1.0.0", CleanupMinVersion)` is true; `VersionAtLeast("1.10.0", "1.9.0")` is true (closes the W4 deferred "numeric" minor). The two older assertions are updated to `1.1.0`.
  - `TestCCSFileNameRule` table:

    | Input | `CCSFileName` | `CCSHost` back |
    |---|---|---|
    | `www.example.com` | `www.example.com.pfx` | same host |
    | `*.example.com` | `_.example.com.pfx` | same host |
    | `WWW.example.com`, `a..b`, `a\b`, `a:b`, `..`, `*.`, `*.*.example.com`, a 254-byte name, a U-label | refused | — |
    | `WWW.Example.COM.PFX` | — | `www.example.com` |
    | `_.example.com.pfx` | — | `*.example.com` |
    | `x.pfx.bak`, `.alice-<op>.tmp`, `_..pfx` | — | refused |

  - `TestValidCCSPassword`: lengths 11, 12, 128 and 129 give false, true, true and false; a space, a tab, `é` and a NUL each give false.
  - `TestValidCCSPath`: `C:\CCS` and `D:\Certs\IIS` true; `\\srv\certs`, `\\?\C:\CCS`, `C:CCS`, `C:\a\..\b`, `C:\a*` and a 241-character path false.
  - `TestCCSInputsRedact`: `%v`, `%+v`, `%#v`, `%s` and a `slog` JSON handler of both inputs never contain the password or the key.
  - `TestCCSShapesJSON`: golden key sets of the four types.
- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./internal/providers/windows/winproto/`
Expected: FAIL (undefined names; version `1.0.0`).
- [ ] **Step 3: Implement.** Rewrite the package comment: 1.1.0 adds the CCS subcommands (W5, R68), protocol 1 throughout. Update `TestRunVersion`, `provider_test.go:123` and the admin guide's "Helper versions" sentence (Alice manages CCS files with a helper of 1.1.0 or later).
- [ ] **Step 4: Run the tests**
Run: `go test -race -count=1 -cover ./internal/providers/windows/... ./cmd/alice-fakewindows/ && GOOS=windows go vet ./cmd/alice-winhelper/ && make docs-check`
Expected: PASS, winproto 100.0%.
- [ ] **Step 5: Commit**: `feat(winproto): helper 1.1.0 with ccs-dump and ccs-deploy, the CCS file-name, path and password rules, redacted inputs (R68)`.

---

### Task 2: `winhelper`: the CCS host surface, `BuildPFX` with intermediates, `ccs-dump`

**Files:**
- Create: `internal/providers/windows/winhelper/ccs.go`, `internal/providers/windows/winhelper/ccs_test.go`
- Modify: `internal/providers/windows/winhelper/write.go` (interface), `pfx.go` (`BuildPFX` gains intermediates), `pfx_test.go`, `winhelper.go` (register `ccs-dump`: elevated, input `MaxCCSDumpInput`, no lock), `fakehost_test.go` (the fake implements the new methods)
- Modify (to keep building; Tasks 4 and 5 fill them): `internal/providers/windows/wintest/model.go`, `wintest/write.go`, `cmd/alice-winhelper/host_windows.go`

**Interfaces:**
- Consumes: Task 1.
- Produces:
  ```go
  // WriteHost gains (every path argument is the folder the helper itself read, never input):
  CCSConfig(ctx context.Context) (enabled bool, path string, err error)               // registry, read on every call
  ListCCS(ctx context.Context, folder string) ([]CCSEntry, error)                      // *.pfx regular files, no reparse point; refuses a folder that is one
  ReadCCS(ctx context.Context, folder, name string, max int) (data []byte, found bool, err error)
  OpenPFX(data, password []byte) (leafDER []byte, chain [][]byte, problem string, err error) // problem: a winproto.CCSProblem* or ""
  WriteCCSTemp(ctx context.Context, folder, tmpName string, data []byte) error         // CREATE_NEW, write-through, flushed
  ReplaceCCS(ctx context.Context, folder, name, tmpName, backupName string) error     // ReplaceFileW (F15)
  RestoreCCS(ctx context.Context, folder, backupName, name string) error              // MoveFileEx REPLACE_EXISTING|WRITE_THROUGH
  RemoveCCS(ctx context.Context, folder, name string) error                            // a .tmp or .bak only; absent is nil
  type CCSEntry struct{ Name string; Size int64; ModTime time.Time }
  func BuildPFX(leafDER, keyPKCS8, password []byte, intermediates ...[]byte) ([]byte, error) // extra certBags without localKeyId
  func cmdCCSDump(ctx context.Context, c *call) (any, error)
  ```
  `ccs-dump` works in this order: elevated; stdin decoded strictly (`BAD_CONTENT`, `INVALID_ARGUMENT` for a password outside `ValidCCSPassword`); `CCSConfig`. Disabled → `{enabled:false}`. A path outside `ValidCCSPath` → `{enabled:true, local:false, path}`. Otherwise `ListCCS`, and for each entry: `CCSHost` (none → `Ignored++`), `ReadCCS` up to `MaxCCSFile` (over → `too_large`), the bytes' SHA-256, `OpenPFX` (leaf, chain and problem), at most `MaxCCSFiles` (`Truncated`), under the budget (`Truncated` when it ends). The password buffer is cleared before the answer.
- Mirror: `dump.go` (bounds and `Truncated`), `deployinput.go` (strict decode), W3 Task 2 (`fakeWriteHost`).

- [ ] **Step 1: Write the failing tests**
  - `pfx_test.go`, `TestBuildPFXWithIntermediates`: the PFX of a leaf and two intermediates opens through the test's own reader (`OpenPFX` of `fakeWriteHost`, which decrypts the `BuildPFX` format with stdlib PBKDF2 and AES); the leaf is the bag sharing the key's `localKeyId`; the chain is in order; zero intermediates gives W2's bytes structure (`TestBuildPFX` unchanged).
  - `ccs_test.go`, `TestCCSDump` table:
    - disabled → `enabled:false`, no `ListCCS` call;
    - UNC path → `local:false`;
    - three files: one Alice-made, one with another password (`ccs_password_mismatch`, no leaf), one `x.pfx.bak` (not listed by the fake, as the real `*.pfx` filter);
    - a name without a valid host → `Ignored 1`;
    - 501 files → 500 and `Truncated`;
    - a 257 KiB file → `too_large`;
    - a budget that ends after 2 files → `Truncated`, 2 files.
  - `TestCCSDumpRefusals`: not elevated (`NOT_ELEVATED`), a password of 11 characters (`INVALID_ARGUMENT`), unknown or duplicate members (`BAD_CONTENT`), trailing data, 4 KiB + 1 (`TOO_LARGE`), an unreadable registry (`IO_ERROR`). The fake's call log shows no `ReadCCS` in each case.
  - `TestCCSDumpClearsThePassword`: the fake's `OpenPFX` keeps the slice it was given; after the call it is all zeroes.
- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./internal/providers/windows/winhelper/ -run 'CCS|BuildPFX'`
Expected: FAIL.
- [ ] **Step 3: Implement** `ccs.go` (the dump half), the interface, the fake, and the stubs in `wintest` and `cmd/alice-winhelper` (an unimplemented method returns an error).
- [ ] **Step 4: Run the tests**
Run: `go test -race -count=1 -cover ./internal/providers/windows/... && GOOS=windows go vet ./cmd/alice-winhelper/ ./internal/providers/windows/...`
Expected: PASS, winhelper at least 95%.
- [ ] **Step 5: Commit**: `feat(winhelper): ccs-dump reads the CCS folder the registry names with the password from standard input; BuildPFX carries the intermediates (R68)`.

---

### Task 3: `winhelper`: `ccs-deploy`, CCS journals in restore, status and fence, pruning of backups

**Files:**
- Modify: `internal/providers/windows/winhelper/ccs.go`, `ccs_test.go`, `journal.go` (`journal.Kind`, `journal.CCS *ccsJournal`; `valid` per kind), `restore.go` and `status.go` (dispatch on `Kind`), `cleanup.go` (prune), `winhelper.go` (register `ccs-deploy`: write, input `MaxCCSDeployInput`), `journal_test.go`, `restore_test.go`, `status_test.go`, `cleanup_test.go`

**Interfaces:**
- Consumes: Task 2.
- Produces:
  ```go
  type ccsJournal struct {
      Folder, File, Host, Backup, Temp      string // as derived; Backup "<file>.alice-<op8>.bak", Temp ".alice-<op>.tmp"
      PreviousFileSHA256, NewFileSHA256      string
      PreviousSPKISHA256                     string
  }
  func cmdCCSDeploy(ctx context.Context, c *call) (any, error) // Ruling 14
  ```
  The journal's `PreviousSHA1`, `PreviousSHA256`, `NewSHA256`, `Intermediates`, `Steps` and forbidden lists are W2's fields with the same meaning (leaf hashes). `Locator` and `Previous` stay empty for a CCS journal. `valid(op)` checks the fields of its kind. `iis-restore` follows Ruling 15, `iis-status` and `iis-fence` follow Ruling 15's last line, and `iis-cleanup --plan` follows Ruling 16. The W2 write gate applies: `OUTCOME_UNKNOWN` after the first durable write, which is the prepared journal.
- Mirror: `deploy.go` (`deployTx`, `selfRestore`, the gate, `interruptedLatest`), `restore.go`, W3 Task 3's prune.

- [ ] **Step 1: Write the failing tests** (`ccs_test.go` and the existing files, against `fakeWriteHost`):
  - `TestCCSDeployCommits`:
    - steps `import_chain`, `write_file`;
    - the fake's file holds a PFX that opens with the password to the new leaf and its intermediates;
    - the backup holds the old bytes;
    - no temporary file is left;
    - the journal is `committed` and names the backup;
    - event 1004 holds no password and no PEM;
    - the answer's `new_sha256` is the leaf DER's.
  - `TestCCSDeployUnchanged`: the same leaf and intermediates answer `unchanged` with no write; the same leaf with another chain writes.
  - `TestCCSDeployRefusesBeforeAnyWrite` (Review Focus 1). Each case leaves the fake's write log empty and answers exit 3 or 2:
    - CCS disabled;
    - the input path `C:\Other`, while the registry says `C:\CCS` → `CCS_PATH_CHANGED`;
    - `c:\ccs\` against `C:\CCS` → accepted;
    - a UNC registry path → `CCS_PATH_UNSUPPORTED`;
    - an absent file → `CCS_FILE_NOT_FOUND`;
    - another password → `CCS_PASSWORD_MISMATCH`;
    - another leaf → `HASH_MISMATCH`;
    - a host `a\b` or `..` → `INVALID_ARGUMENT`;
    - a known operation → `OPERATION_EXISTS`;
    - a fenced operation → `FENCED`;
    - not elevated;
    - lock held → `BUSY`.
  - `TestCCSDeployReadBackRestores` (Review Focus 3): the fake's file reads back other bytes after the replace → the backup is moved back, the phase is `restored` with `failed_step write_file` and `error read_back`; a replace that fails before swapping → `restored`, no backup, the temporary file removed.
  - `TestCCSKillAtEveryPoint` (Review Focus 4): `Point` kills after `prepared`, after the temporary write, after the replace and before `committed`. For each, `iis-status` gives the phase and `current_cert_sha256`, and `iis-restore` either restores (after the replace) or answers `restored` with nothing written (before it).
  - `TestCCSRestoreRules`:
    - a forbidden previous leaf or SPKI → `restore_forbidden`, the file untouched;
    - a third party replaced the file after the commit → `SUPERSEDED`, nothing done;
    - the backup deleted, or its bytes changed → `BACKUP_MISSING` before any write;
    - a second restore → `restored` without a write.
  - `TestCCSJournalHoldsNoPassword` (Review Focus 2): the journal and the file record never contain the password's bytes, the key or the PFX.
  - `cleanup_test.go`, `TestPruneCCSBackups`:
    - a committed CCS journal 8 days old → its `.tmp` and `.bak` removed, then the journal;
    - a `.bak` whose bytes changed → kept, the journal still pruned;
    - a `writing` journal 60 days old → kept with its files;
    - a `restored` journal → no backup to remove.
- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./internal/providers/windows/winhelper/ -run 'CCS|Prune'`
Expected: FAIL.
- [ ] **Step 3: Implement.** All messages are fixed texts. Clear the password, the key and the PFX buffers on every path.
- [ ] **Step 4: Run the tests**
Run: `go test -race -count=1 -cover ./internal/providers/windows/winhelper/`
Expected: PASS, at least 95%; every W2 and W3 test unchanged.
- [ ] **Step 5: Commit**: `feat(winhelper): ccs-deploy writes the CCS file atomically with a backup under the W2 journal; iis-restore, iis-status and iis-fence act on CCS journals; backups pruned with their journals (R68)`.

---

### Task 4: `wintest` and `cmd/alice-fakewindows`: the emulator's CCS half

**Files:**
- Modify: `internal/providers/windows/wintest/model.go`, `write.go`, `tls.go` (serve a `ccs` port by SNI from the model's CCS files, exact name before the one-label wildcard, F17), `demo.go`, `write_test.go`, `wintest_test.go`; `cmd/alice-fakewindows/main.go` (`ctl ccs-password`), `main_test.go`

**Interfaces:**
- Consumes: Tasks 2-3 through `winhelper.ExecuteForced`.
- Produces (new `Model` methods):
  ```go
  func (m *Model) SetCCS(enabled bool, path string)
  func (m *Model) PutCCSFile(name string, leaf *x509.Certificate, chain []*x509.Certificate, key crypto.Signer, password string) // a file as a third party made it
  func (m *Model) PutRawCCSFile(name string, data []byte)
  func (m *Model) CCSFile(name string) (data []byte, ok bool)
  func (m *Model) CCSNames() []string                          // every name in the folder, .bak and .tmp included
  func (m *Model) FailReplace(on bool)                         // the next ReplaceCCS fails before swapping
  func (m *Model) ServeStaleCCS(on bool)                       // TLS keeps serving the file as it was before the last replace (F15 route (b) modelled)
  ```
  The model keeps each file's bytes. `OpenPFX` decrypts the `BuildPFX` format (shared test-only reader, Task 2) and recognises `PutCCSFile` files by their bytes' SHA-256. The demo host: CCS on at `C:\CCS`; `ccs.example.test.pfx` (linked by an IIS site binding `https *:<tls port>:ccs.example.test` with `sslFlags` 3); `_.unlinked.test.pfx` (no binding); the password built at start and answered by `ctl ccs-password` (stdout only).
- Mirror: W2 Task 4 and W3 Task 4.

- [ ] **Step 1: Write the failing tests** (`write_test.go`, over the SSH handler):
  - `TestModelCCSDeployAndServe`: dump over SSH; deploy B over A; a fresh TLS handshake with SNI `ccs.example.test` on the ccs port serves B; restore → A again.
  - `TestModelCCSWildcard` (F17 as modelled): `_.example.test.pfx` serves `x.example.test`; adding `x.example.test.pfx` makes it serve that one instead.
  - `TestModelCCSFailReplace`: the deploy answers `restored` and `CCSNames` shows no `.tmp`.
  - `TestDemoHostHasCCS`: the demo's dump lists the two files; `ctl ccs-password` prints the password, which opens them.
- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./internal/providers/windows/wintest/ ./cmd/alice-fakewindows/`
Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the tests**
Run: `go test -race -count=1 -cover ./internal/providers/windows/wintest/ ./internal/providers/windows/winhelper/ ./cmd/alice-fakewindows/`
Expected: PASS, wintest at least 90%, fakewindows at least 90%.
- [ ] **Step 5: Commit**: `test(wintest): the emulator's CCS half: the folder, files by password, ReplaceFile with a backup, TLS by SNI from the store; the demo host's CCS (R68)`.

---

### Task 5: `cmd/alice-winhelper`: the real CCS half and its runner tests **[F15, F16, F17, F18]**

**Files:**
- Create (`//go:build windows`): `cmd/alice-winhelper/ccs_windows.go`, `cmd/alice-winhelper/ccs_windows_test.go`, `cmd/alice-winhelper/fidelity_ccs_windows_test.go`
- Modify: `cmd/alice-winhelper/host_windows.go` (wire the methods; `centralCertStore` is reused for `CCSConfig`), `cmd/alice-winhelper/zz_runner_clean_windows_test.go` (45480-45499, `alice-w5-`, CCS disabled, the account and the folder gone), `.github/workflows/windows.yml` (the required list), `internal/providers/windows/winproto/winproto.go` (`CCSPickupWait`, only if F15 needs it)

**Interfaces:**
- Produces (unexported):
  - `ListCCS`: `FindFirstFileEx` on `<folder>\*.pfx`, regular files only, `FILE_ATTRIBUTE_REPARSE_POINT` refused.
  - `ReadCCS`: `CreateFile` with `FILE_FLAG_OPEN_REPARSE_POINT`, bounded read.
  - `OpenPFX`: `PFXVerifyPassword`, then `PFXImportCertStore(PKCS12_NO_PERSIST_KEY)` into a memory store; the leaf is the certificate with a key; the store is closed and the password cleared.
  - `WriteCCSTemp`, `ReplaceCCS` (`ReplaceFileW`, `REPLACEFILE_WRITE_THROUGH`), `RestoreCCS`, `RemoveCCS` (only names matching the two patterns).
  - F15 route (a), if it applies: `UpdateBinding` of the `ccs` record read by port (extends `httpapi_update_windows.go`'s key, which today refuses `ccs`).
- Mirror: W2 Task 6 (`import_windows.go`, `state_windows.go`), W3 Task 5 (fixtures, fidelity), `tools/winspike` for the httpapi layout of `SSL_CCS_SET` (208 bytes).

- [ ] **Step 1: Write the tests.** They are skipped unless `ALICE_WIN_REAL=1`. Each fixture is an `alice-w5-` site with an `sslFlags=3` binding on 45480-45489, CCS enabled at a fresh folder with the `alice-w5-ccs` account and a run-time password.
  - `TestRealCCSReplaceIsPickedUp` **[F15]**: write A through `ccs-deploy`, then B. Poll fresh `tls.Dial` handshakes until B is served; log the delay and whether a same-record `ccs` update shortens it. Check that the backup holds A's bytes, that the ACL (SDDL) is unchanged after the replace, and that a `.bak` or `.tmp` name is never served. Log whether appcmd's binding created the `ccs:<port>` record.
  - `TestRealCCSWrongPasswordIsNotServed` **[F16]** (Review Focus 3): a file `BuildPFX` made with the CCS password is served. One made with another password is not; log the client's error and any Application event. `OpenPFX` with the wrong password gives a mismatch with the measured error, and with the right one leaves the machine and user key directories' file counts unchanged.
  - `TestRealCCSNameRules` **[F17]**: `_.alice-w5.test.pfx` serves `x.alice-w5.test`; an exact file wins; an upper-case file name is found. A `hostnameport` record for `y.alice-w5.test:45481` with cert C, next to a CCS file with cert D, decides the precedence; log the winner.
  - `TestRealCCSServedChain` **[F18]**: a file with leaf and intermediate and no intermediate in `CA` → log the served chain length; with the intermediate in `CA` → log it again.
  - `TestRealCCSRefusesReparsePoints` (Review Focus 1): a junction as the folder and a symlink as the file → refused, nothing written outside.
  - `TestFidelityCCS`: on both hosts (the emulator configured like the fixture), run dump, deploy, unchanged, every refusal of Task 3, then restore. The answers must be equal field by field, with messages dropped.
  - `TestRealRunnerIsClean` extended.
  - `windows.yml`: the required list adds the six tests before `TestRealRunnerIsClean`. `TestWindowsWorkflowRequiresEveryRealTest` keeps the list exact.
- [ ] **Step 2: Verify locally what can be verified**
Run: `GOOS=windows GOARCH=amd64 go build -o /dev/null ./cmd/alice-winhelper/ && GOOS=windows GOARCH=arm64 go build -o /dev/null ./cmd/alice-winhelper/ && GOOS=windows go vet ./cmd/alice-winhelper/ && GOOS=windows go vet -tags alicetest ./cmd/alice-winhelper/ && actionlint .github/workflows/windows.yml && go run ./tools/pincheck && go test -count=1 ./internal/archtest/ && make winhelper`
Expected: PASS.
- [ ] **Step 3: Run on real Windows.** Push `windows-w5`; both legs must be green. Count every run against the budget of 8. Record F15-F18 as rulings with the run links. When a fact differs, apply its "If it is wrong" column in its own fix commit, in the task that owns the code.
- [ ] **Step 4: Fix** every fidelity difference in the emulator (the helper is the specification).
- [ ] **Step 5: Commit**: `feat(alice-winhelper): the CCS folder, PFX reading without a persisted key, ReplaceFile with a backup; CCS fidelity and F15-F18 on windows-2022 and windows-2025 (R68)`.

---

### Task 6: Migration `00036`, the location kind, the CCS password in inventory and the API **(parallel with Tasks 4-5)**

**Files:**
- Create: `migrations/00036_windows_ccs.sql`, `migrations/windows_ccs_integration_test.go`, `internal/inventory/ccs_password.go`, `internal/inventory/ccs_password_integration_test.go`, `internal/api/ccs_password_handlers_test.go`
- Modify:
  - providers: `internal/providers/groundwork.go` (`LocationWinCCSFile LocationKind = "win_ccs_file"` in `locationKinds`; `StepNameWriteFile = "write_file"`; `CCSPasswordSource`), `internal/providers/providers_test.go` (step-name and kind lists);
  - inventory: `internal/inventory/platformkey.go` (`platformCredentials` implements `CCSPasswordSource`), `internal/inventory/deployment_records.go` (Ruling 21's four sites), `internal/inventory/notify.go` (unchanged texts, a test), `internal/inventory/targets.go` (`Target.CCSPasswordSetAt`);
  - API: `internal/api/targets_handlers.go` (the route), `internal/api/errors.go` (`ALC-WIN-0015..0020`), `internal/api/certs_dto.go` (`ccs_password_set_at` on the target DTO), `api/openapi.yaml`, `internal/api/errors_winserver_test.go`;
  - `locales/common/{en,tr}.json` (the six reasons).

**Interfaces:**
- Consumes: Task 1 (codes).
- Produces:
  ```go
  // providers
  type CCSPasswordSource interface {
      CCSPassword(ctx context.Context, target uuid.UUID) (secrets.Plaintext, func(), error) // ErrNotFound when none
  }
  // inventory
  func (s *Service) SetCCSPassword(ctx context.Context, a Actor, target uuid.UUID, ifVersion int, pw secrets.Plaintext) (Target, error)
  var ErrCCSPasswordInvalid, ErrNotWindowsTarget error
  ```
  The route is `PUT /api/v1/targets/{id}/ccs-password` (`scopeResource`, `rbac.CredentialsManage`, `license.ClassChange`), with body `{"password": secretText}` and the `If-Match` version as the vault-credential route uses it. The answer is the target DTO. Errors: a non-Windows target → `ALC-WIN-0011` `windows.location_unsupported` (409); the rule of Ruling 10 → `ALC-WIN-0019`. Audit `target.ccs_password_set`.
- Mirror: `vault_credentials.go` and `target_credentials.go` (seal, insert, open, the foreign-credential refusal), `vaults_handlers.go:34` (the strict route), 00031's Up and Down.

- [ ] **Step 1: Write the failing tests**
  - `windows_ccs_integration_test.go`: Up accepts a `win_ccs_file` location and deployment, and a `win_ccs` credential with a `target_id`. It refuses a `win_ccs` credential without one, and kind `win_ccs_password` under purpose `f5_device`. Down refuses while such rows exist and succeeds after they are removed.
  - `ccs_password_integration_test.go`:
    - `TestSetCCSPassword`: a Windows target stores a sealed row; `CCSPassword` returns the newest of two; `ccs_password_set_at` follows.
    - `TestCCSPasswordForeign`: another target's id, or a Nginx target → `ErrNotFound` or `errForeignCredential`, no plaintext.
    - `TestCCSPasswordRule`: 11 characters and a space → `ErrCCSPasswordInvalid`, no row.
    - `TestNewCertSHA256ForCCS`: a `win_ccs_file` token is the leaf DER's SHA-256.
    - `TestStartBackupRefForCCS`: the op id and the token only.
    - `TestWindowsLostIncludesCCS`.
  - `ccs_password_handlers_test.go`:
    - an Administrator without step-up → `ErrStepUpRequired`;
    - an API token → denied;
    - an Operator → 403;
    - success → 200 with `ccs_password_set_at` and no password field;
    - `TestCCSPasswordNeverEchoed` (Review Focus 2): the response, the audit row's params and a 422 answer never contain the submitted value.
  - `errors_winserver_test.go`: the six new codes with their reasons and statuses.
- [ ] **Step 2: Run them to verify they fail**
Run: `go test -count=1 -tags integration ./migrations/ ./internal/inventory/ ./internal/api/ -run 'CCS|WindowsLost|Winserver'`
Expected: FAIL.
- [ ] **Step 3: Implement**, the OpenAPI entries included (`api/openapi.yaml`: the route, `ccs_password_set_at`, `win_ccs_file` in every `location_kind` enum, the six codes).
- [ ] **Step 4: Run the tests**
Run: `go test -race -count=1 ./internal/providers/... && go test -count=1 -tags integration ./migrations/ ./internal/inventory/ ./internal/api/ && make i18n-check`
Expected: PASS; the OpenAPI conformance tests green.
- [ ] **Step 5: Commit**: `feat(inventory): the win_ccs_file location kind and the CCS password of a Windows server, sealed and set by an Administrator with step-up; migration 00036 (R68)`.

---

### Task 7: Windows provider: CCS discovery, deployment, verification and rollback; engine tests on the emulator

**Files:**
- Create: `internal/providers/windows/ccs.go`, `internal/providers/windows/ccs_test.go`, `internal/jobs/deployjobs/windows_ccs_integration_test.go`
- Modify:
  - provider: `internal/providers/windows/discover.go` (the second call, Ruling 18), `convert.go` (`convertCCS`: locations, links, problems, warnings; the `win_ccs` text), `deploycert.go` (the kind branch to `ccs-deploy`; the input built by hand as `deployInput`), `verify.go` (`Endpoints` for `win_ccs_file`, Ruling 20; unlinked → skip), `rollback.go` and `status.go` (CCS journals need no new call, only the `BackupRef` of Ruling 21), `provider.go` (`ccsReady()`), `errors.go` (six reasons, the refusal table of `ccs-deploy`);
  - tests: `convert_test.go`, `deploycert_test.go`, `verify_test.go`, `conformance_test.go`.

**Interfaces:**
- Consumes: Tasks 1, 4, 6.
- Produces:
  - `func convertCCS(d winproto.IISDumpResponse, c winproto.CCSDumpResponse) ([]providers.DiscoveredCertificate, []providers.Warning)` (Rulings 5-8, 12, 19). Each location's `FileSHA256` is the leaf DER's SHA-256 and its `PEMChain` the leaf and chain, re-parsed as `certificateChain` does.
  - `func (s *session) ccsReady() error` (`windows.helper_outdated`, `required_version 1.1.0`).
  - Reasons `ReasonCCSDisabled`, `ReasonCCSPathChanged`, `ReasonCCSPasswordMismatch`, `ReasonCCSPasswordMissing`, `ReasonCCSFileNotFound` (`windows.*`; the path-unsupported refusal maps to `windows.location_unsupported`).
- Mirror: `deploycert.go`'s whole flow (`runWrite`, `d.answer`, the inline rollback), W2 Task 7's tests, W3 Task 9's engine tests.

- [ ] **Step 1: Write the failing tests**
  - `ccs_test.go` (over SSH with `wintest.NewServer`):
    - `TestCCSNeedsHelper110` (Review Focus 5): a model answering `1.0.0` → `Discover` sends `version`, `iis-dump` and no `ccs-dump`, and carries the warning `win_ccs_helper_outdated`; a deployment to a `win_ccs_file` location → `windows.helper_outdated` `required_version 1.1.0`, and only `version` was sent; a `1.0.0` model still deploys to a binding.
    - `TestDiscoverWithoutPasswordIsW4`: the binding locations are unchanged, with no `win_ccs_file` locations and `win_ccs_password_missing`.
    - `TestDiscoverCCSLinks`: the demo host gives the linked file with its site as server, the unlinked one with `win_ccs_unlinked`, and an IIS CCS binding without a file as `cert_missing`. A mismatching file gives `ccs_password_mismatch` and the server warning with `count 1`. A failed `ccs-dump` gives `locations_dropped`.
    - `TestEachCCSCallUsesItsOwnConnection`.
    - `TestCCSPasswordIsNeverOutsideStdin` (Review Focus 2): the emulator's recorded `SSH_ORIGINAL_COMMAND`s never contain the password; the input buffer is cleared after the send (`inputHook`).
    - `TestCCSDeployOutcomeTable`: one row per refusal code of Task 3 → its reason, plus committed, unchanged, restored and uncertain (`OUTCOME_UNKNOWN`). Every return passes `providers.CheckDeployReturn`.
  - `verify_test.go`, `TestCCSEndpoints`: two linked bindings give two SNI endpoints; a `*.` host gives `alice-check.`; the Administrator's port and SNI replace them. `TestCCSUnlinkedIsReadBackOnly` (Review Focus 3): no servers → a skipped result with param `ccs_unlinked`.
  - `windows_ccs_integration_test.go` (the engine on the emulator):
    - `TestWindowsCCSManualDeploy` (level 3 with a public chain, level 2 with a private CA);
    - `TestCCSFailedVerificationRestoresBackup` (`ServeStaleCCS(true)` → `rolled_back`, the file holds A's bytes);
    - `TestWindowsCCSGuardForbids` (`rollback_failed`, `deployment.rollback_forbidden`);
    - `TestWindowsCCSCrashTable` (Review Focus 4: a kill at each point of Task 3, then the engine's recovery);
    - `TestWindowsCCSACMEAndKeyVault` (automatic deployment reaches the linked file);
    - `TestWindowsCCSDriftRepaired` (a third party's file → drifted → `auto` repairs);
    - `TestWindowsCCSDisabledRefuses` (`ALC-WIN-0015`, the file untouched).
- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./internal/providers/windows/ -run 'CCS|Endpoints' && go test -tags integration ./internal/jobs/deployjobs/ -run CCS`
Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the tests**
Run: `go test -race -count=1 -cover ./internal/providers/windows/... && go test -race -count=1 -tags integration ./internal/jobs/deployjobs/ ./internal/jobs/driftjobs/ ./internal/jobs/winjobs/`
Expected: PASS, windows at least 95%; every W2-W3 engine test unchanged.
- [ ] **Step 5: Commit**: `feat(providers/windows): CCS files discovered with the server's password and linked to their IIS bindings, written by ccs-deploy, verified by host header and restored from the backup (R68)`.

---

### Task 8: Web and e2e: CCS files, the password panel, the CCS steps

**Files:**
- Create: `web/src/components/CCSPasswordPanel.tsx`, `web/src/components/CCSPasswordPanel.test.tsx`, `web/e2e/windows-ccs.spec.ts`
- Modify:
  - API layer: `web/src/api/types.ts` (`LocationKind` gains `win_ccs_file`; `ccs_password_set_at`), `web/src/api/targets.ts` (`setCCSPassword`), `web/src/api/enums.ts` (the six reasons, `write_file`, the problems and warnings), `web/src/api/warnings.ts`, `web/src/api/deployments.ts` (`isCCSDeployment` by `location_kind`);
  - components: `web/src/components/DeploymentSteps.tsx` (`CCS_GROUPS`: `import_chain`, `write_file`, `verify`), `web/src/components/WebsitesPanel.tsx` (CCS file rows: the path, the linked sites, "No IIS site uses this file", "The CCS password does not open this file"), `web/src/components/acme/AcmeBindingsPanel.tsx` (a CCS file is spoken of as a file);
  - pages: `web/src/pages/TargetDetailPage.tsx` (the panel on a Windows server whose facts say CCS is on);
  - `web/src/locales/{en,tr}.json`, `web/src/test/fixtures.ts`; tests `WebsitesPanel.test.tsx`, `DeploymentSteps.test.tsx`, `TargetDetailPage.test.tsx`.

**Interfaces:**
- Consumes: Task 6's API, Task 7's locations.
- Mirror: `ReplaceCredentialsDialog.tsx` and `StepUpProvider.tsx` (the step-up flow, a password field that is never echoed or kept after submit), W3 Task 11.

- [ ] **Step 1: Write the failing tests**
  - `CCSPasswordPanel.test.tsx`: "Not set" before and the date after; 11 characters are refused client-side with the server's text; the submit asks for step-up when the API answers it; the field is empty after success; the request body holds the value and no other request does.
  - `WebsitesPanel.test.tsx`: a linked CCS file shows its path and site; an unlinked one its warning; a mismatch its problem; binding rows unchanged.
  - `DeploymentSteps.test.tsx`: a `win_ccs_file` deployment shows import chain, write file, verify.
  - `TargetDetailPage.test.tsx`: the panel shows only for a Windows server with CCS on.
  - `windows-ccs.spec.ts` (Ruling 25), in EN and TR.
- [ ] **Step 2: Run them to verify they fail**
Run: `cd web && npx vitest run src/components/CCSPasswordPanel.test.tsx src/components/WebsitesPanel.test.tsx src/components/DeploymentSteps.test.tsx src/pages/TargetDetailPage.test.tsx`
Expected: FAIL.
- [ ] **Step 3: Implement.** Help texts in EN and TR: what CCS is, why Alice needs its password, and that the password stays sealed on the Alice server.
- [ ] **Step 4: Run the tests**
Run: `cd web && npx vitest run && npx tsc --noEmit && npm run lint && cd .. && make i18n-check && make web-coverage && E2E_PROJECT=alice-e2e-w5 ALICE_E2E_PORT=9982 make e2e-up && E2E_PROJECT=alice-e2e-w5 ALICE_E2E_PORT=9982 make e2e; E2E_PROJECT=alice-e2e-w5 make e2e-down`
Expected: PASS; the whole e2e suite green.
- [ ] **Step 5: Commit**: `feat(web): CCS files of a Windows server, the CCS password with step-up, the CCS deployment steps; English and Turkish (R68)`.

---

### Task 9: Decision, rulings, specification amendments, test IDs, documents

**Files:**
- Modify (decision and design):
  - `docs/superpowers/rulings/windows-iis.md`: a heading "W5 (R68)" with the 26 rulings as built, F15-F18 verdicts, the runner-run table, acceptance, owner items, and "Deferred to W6+" (the list moved on).
  - `docs/superpowers/specs/alice-v1/00-decisions.md`: R68 after R67.
  - `docs/superpowers/specs/2026-10-21-windows-iis-target-design.md`: §13 W5 "built, R68, §20"; the F15-F18 rows; "§20 Phase W5 as built".
- Modify (specifications):
  - `docs/superpowers/specs/alice-v1/03-integrations.md`: §13A gains 13A.15-13A.17 (CCS files, the password, the write and its rollback).
  - `04-security.md` §14.4: `WN-19`..`WN-22`, plus the CCS password in §15.11's secret list.
  - `06-quality.md` §24.7: the rows below.
  - `test/matrix/traceability.json` and `docs/security/traceability.md` (regenerated).
- Modify (guides and changelog):
  - `CHANGELOG.md` ("Unreleased").
  - `docs/admin-guide.md` ("Windows servers": CCS).
  - `docs/windows-host-preparation.md`: the CCS prerequisites (local folder, the password rule, event 1004, the `.bak` files and their 7 days).
  - `docs/troubleshooting.md`: ALC-WIN-0015..0020.

| ID | Case | Tests |
|---|---|---|
| WIN-46 | CCS files are discovered with the server's password and linked to their IIS bindings; without a password, with a 1.0.0 helper or a UNC path none are, with a warning | `internal/providers/windows:TestDiscoverCCSLinks`, `TestDiscoverWithoutPasswordIsW4`, `winhelper:TestCCSDump` |
| WIN-47 | The CCS password is set by an Administrator with step-up, sealed, and never echoed or put outside standard input | `internal/api:TestCCSPasswordNeverEchoed`, `internal/inventory:TestSetCCSPassword`, `TestCCSPasswordForeign`, `windows:TestCCSPasswordIsNeverOutsideStdin`, `winproto:TestCCSInputsRedact` |
| WIN-48 | `ccs-deploy` writes atomically with a backup; compare-and-swap, unchanged, and every refusal before a write | `winhelper:TestCCSDeployCommits`, `TestCCSDeployUnchanged`, `TestCCSDeployRefusesBeforeAnyWrite` |
| WIN-49 | Verification by host header; an unlinked file is read back only; a failed verification restores the backup; the guard forbids | `windows:TestCCSEndpoints`, `TestCCSUnlinkedIsReadBackOnly`, `deployjobs:TestCCSFailedVerificationRestoresBackup`, `TestWindowsCCSGuardForbids` |
| WIN-50 | A kill at every journal point recovers; restore rules | `winhelper:TestCCSKillAtEveryPoint`, `TestCCSRestoreRules`, `deployjobs:TestWindowsCCSCrashTable` |
| WIN-51 | A CCS file replaced outside Alice is drifted and repaired; ACME and Key Vault reach CCS files | `deployjobs:TestWindowsCCSDriftRepaired`, `TestWindowsCCSACMEAndKeyVault` |
| WIN-52 | Backups and temporary files are pruned with their journals; CCS turned off refuses with nothing changed | `winhelper:TestPruneCCSBackups`, `deployjobs:TestWindowsCCSDisabledRefuses` |
| WIN-53 | Helper 1.1.0; a 1.0.0 helper is never sent a CCS subcommand and keeps every W1-W4 feature | `winproto:TestReleasedHelperVersion`, `windows:TestCCSNeedsHelper110` |
| WIN-54 | The emulator matches the real helper for CCS; IIS serves the replaced file (F15-F18); no write leaves the folder; the runner is left clean | `cmd/alice-winhelper:TestFidelityCCS`, `TestRealCCSReplaceIsPickedUp`, `TestRealCCSWrongPasswordIsNotServed`, `TestRealCCSNameRules`, `TestRealCCSServedChain`, `TestRealCCSRefusesReparsePoints`, `TestRealRunnerIsClean` |
| WIN-55 | The CCS journey in the browser, in English and Turkish | `web/e2e/windows-ccs.spec.ts` |

R68's text names:
- the kind, the locator and the file-name rule;
- one password per server, with its rule and transport;
- `ccs-dump`, `ccs-deploy`, the reused restore, status and fence, and helper 1.1.0 with `CCSMinVersion`;
- the transaction and its rollback, the backups and their pruning;
- the unlinked and missing-file rules;
- `ALC-WIN-0015..0020`, `WIN-46..55`, `WN-19..22`, and migration `00036`.

- [ ] **Step 1: Write the failing check**: add the rows to `06-quality.md`.
- [ ] **Step 2: Run it to verify it fails**
Run: `make matrix-check MATRIXCHECK_FLAGS=-strict`
Expected: FAIL (10 gaps).
- [ ] **Step 3: Write** the documents and `traceability.json`, then regenerate: `go run ./tools/matrixcheck -spec docs/superpowers/specs/alice-v1/06-quality.md -map test/matrix/traceability.json -doc docs/security/traceability.md -update`.
- [ ] **Step 4: Verify**
Run: `make matrix-check MATRIXCHECK_FLAGS=-strict && make docs-check && make i18n-check`
Expected: PASS, 0 gaps, 0 pending.
- [ ] **Step 5: Commit**: `docs: Windows servers phase W5 (R68): decision, rulings, design as built, security and quality amendments, WIN-46..WIN-55, admin and host guides, changelog`.

---

### Task 10: Final gates

**Files:** none new. Fixes go to the task that owns the code.

- [ ] **Step 1: Full local gates**
Run: `make lint && make test && make i18n-check && make matrix-check MATRIXCHECK_FLAGS=-strict && make docs-check && make helper winhelper && make build && make coverage`
Expected: PASS. Every floor is met and none was lowered.
- [ ] **Step 2: Windows build and vet**
Run: the Windows line of "Verification commands".
Expected: PASS.
- [ ] **Step 3: e2e and image.** Only when no other `make ci` or Docker-based run is active on the machine: `E2E_PROJECT=alice-e2e-w5 ALICE_E2E_PORT=9982 make ci`. Otherwise run Task 8's e2e when the machine frees and list `make ci` as pending in the acceptance report.
Expected: PASS; the e2e totals are recorded.
- [ ] **Step 4: Real Windows.** The `windows.yml` run of the branch's code head is green on windows-2022 and windows-2025 with `windows-required` green (runs counted, at most 8). If it cannot be, the rulings file lists it as an owner item and the acceptance report says it is pending.
- [ ] **Step 5: gitleaks** over the whole range `e15fad4b..HEAD` (export with `git log -p`, scan in `dir` mode, as W3 and W4 did). Fingerprint any finding in `.gitleaksignore` without key material.
- [ ] **Step 6: Independent review** of `e15fad4b..HEAD` against Review Focus 1-5, Rulings 3, 4, 9-12 and 14-16 (the security-relevant ones), by a reviewer that did not write the code. Fix or decline every finding with a reason in the rulings file ("Final review fixes (W5)").
- [ ] **Step 7: Acceptance check against design §13 W5**, one line each in the rulings file:
  - a CCS location belongs to the server that hosts the folder (Tasks 6-7);
  - kind `win_ccs_file`, named `<host>.pfx` or `_.<domain>.pfx` (Task 1);
  - written with the CCS password entered by an Administrator (Task 6);
  - atomically with a backup kept for rollback (Tasks 3, 5);
  - the IIS servers' `ccs` bindings linked for verification (Task 7);
  - no double hop (Ruling 3).

  Hand the branch `windows-w5` to the coordinator. Do not merge or push `main`.

---

## Execution notes for the implementer

- Commit this plan first (`git add -- docs/superpowers/plans/2026-10-27-windows-w5-ccs.md`, subject `docs: Windows servers phase W5 (CCS) plan (R68)`).
- **Dispatch order:** 1 → 2 → 3 → (4 ∥ 5 ∥ 6: disjoint files `wintest` + `cmd/alice-fakewindows`, `cmd/alice-winhelper` + `windows.yml`, `migrations` + `internal/inventory` + `internal/api` + `internal/providers/groundwork.go`) → 7 → 8 → 9 → 10.
- **Runner runs:**
  - Push for run 1 right after Task 3, so that F15-F18 are known before Task 7 sets the verification wait and the linking order.
  - Run 2 after Task 5's fixes. Run 3 after Task 7. Run 4 after the final review's fixes.
  - That leaves 4 runs spare.
- **Review gates:** after Tasks 3, 5, 6 and 7, a review against Review Focus 1-5 before the next dependent task. Every finding is fixed in the task that owns the code, with its own commit.
- Record every ruling made during execution in `docs/superpowers/rulings/windows-iis.md` under "W5 (R68)", one line each: the ruling, then why.
- Commit with `git -c user.name="Eren Altan" -c user.email="erenaltan@gmail.com" commit --only ...` and the trailer `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`. Subjects end with `(R68)`.

## Left for later phases

- **W5+ (deferred by this plan):**
  - the farm layout: a CCS folder on a share of another server, the file server as the target, links across targets, the share-to-folder resolution (Ruling 3);
  - creating a CCS file for an IIS CCS binding that has none (Ruling 7);
  - removing or clearing the CCS password;
  - a CCS whose password Alice's rule refuses (Ruling 10).
- **W6-W7, on demand:** RDP deployment (`win_rdp`), WinRM transport.
- **Carried from W2-W4, not decided in W5:** every item of "Deferred to W5+" except the helper version literal minor (Task 1 updates every site and `TestReleasedHelperVersion` gains a case that discriminates numerically). These include a third party's intermediate and `unchanged`, the emulator's slow-host fault, a binding whose only problem is its key, IDN U-labels, a manual rollback action, W3's minors, and W4's minors other than the two closed here.

## Owner to confirm

1. **Ruling 3:** only a local CCS folder on the IIS server itself is managed in W5; the shared-folder farm layout is deferred.
2. **Ruling 7:** Alice never creates a CCS file in W5. The first file for a host is placed by the administrator; Alice then manages it.
3. **Ruling 9:** one CCS password per Windows server (not per location), set through the API with step-up, append-only, with no delete in W5.
4. **Ruling 10:** the password must be 12-128 printable ASCII characters without spaces. A CCS whose configured password does not meet that cannot be managed.
5. **Ruling 12:** Alice does not read IIS's stored password. A wrong password shows as files it cannot open, and a wrong write is caught by the probe of a linked host. An unlinked file is checked by read-back only (Ruling 8).
6. **Rulings 14-16, WN-22:** each write leaves a backup `<file>.alice-<op8>.bak` in the CCS folder for 7 days (pruned by the daily `windows.cleanup`). It holds the previous private key, encrypted with the CCS password, under the folder's ACL. If that is not acceptable, the alternative is a backup under `C:\ProgramData\Alice\helper` (same volume only, F15).
7. **Ruling 2:** restore, status and fence of CCS operations reuse the `iis-*` subcommands by journal kind, instead of adding `ccs-restore` and `ccs-status`.
8. **Ruling 26:** the runner tests install `Web-CertProvider` and leave it installed on the hosted runner images (they are discarded after each job).
9. **The F15-F18 verdicts** once measured, especially F15 if IIS caches a CCS file and Alice must rewrite the http.sys `ccs` record or wait (route (a) or (b)).

## Self-review notes (for the executor)

- **Spec coverage:**
  - §13 W5 "a CCS location belongs to the Windows server that hosts the CCS folder": Rulings 3 and 6, Task 7.
  - "location kind `win_ccs_file`": Tasks 1 and 6.
  - "named `<host>.pfx` or `_.<domain>.pfx`": Ruling 5, Task 1.
  - "the CCS PFX password, an Alice location secret entered by an Administrator": Rulings 9-11, Task 6 (narrowed to one per server).
  - "atomically (temporary file, `ReplaceFile` with a backup file kept for rollback)": Rulings 14-15, Tasks 3 and 5.
  - "the IIS servers' `ccs` bindings are linked to it for verification": Rulings 6 and 20, Task 7.
  - "no double hop": Ruling 3.
  - "Interactions with other work": Ruling 23.
  - §6.6 drift: Ruling 22. §6.7 cleanup: Ruling 16. §8 one connection per call: Task 7 `TestEachCCSCallUsesItsOwnConnection`. §5 `win_ccs` until W5: Ruling 19.
- **Names used across tasks:**
  - `winproto`: `Version`, `CCSMinVersion`, `SubCCSDump`, `SubCCSDeploy`, `CodeCCS*`, `StepWriteFile`, `JournalKindCCS`, `LocatorCCSFile`, `MaxCCS*`, `CCSPickupWait`, `CCSProblem*`, `WarnCCS*`, `CCSFileName`, `CCSHost`, `ValidCCSPassword`, `ValidCCSPath`, `CCSDumpInput`, `CCSFile`, `CCSDumpResponse`, `CCSDeployInput`.
  - `winhelper`: `WriteHost.CCSConfig/ListCCS/ReadCCS/OpenPFX/WriteCCSTemp/ReplaceCCS/RestoreCCS/RemoveCCS`, `CCSEntry`, `BuildPFX(..., intermediates...)`, `cmdCCSDump`, `cmdCCSDeploy`, `ccsJournal`.
  - `wintest`: `Model.SetCCS/PutCCSFile/PutRawCCSFile/CCSFile/CCSNames/FailReplace/ServeStaleCCS`.
  - `providers`: `LocationWinCCSFile`, `StepNameWriteFile`, `CCSPasswordSource`.
  - `inventory`: `SetCCSPassword`, `ErrCCSPasswordInvalid`, `ErrNotWindowsTarget`.
  - `windows`: `convertCCS`, `ccsReady`, `ReasonCCS*`.
  - web: `CCSPasswordPanel`, `setCCSPassword`, `CCS_GROUPS`, `isCCSDeployment`.

### Files the implementer will touch

- New:
  - `migrations/00036_windows_ccs.sql`, `migrations/windows_ccs_integration_test.go`;
  - `internal/providers/windows/winhelper/ccs.go`, `ccs_test.go`;
  - `internal/providers/windows/ccs.go`, `ccs_test.go`;
  - `cmd/alice-winhelper/ccs_windows.go`, `ccs_windows_test.go`, `fidelity_ccs_windows_test.go`;
  - `internal/inventory/ccs_password.go`, `ccs_password_integration_test.go`;
  - `internal/api/ccs_password_handlers_test.go`, `internal/jobs/deployjobs/windows_ccs_integration_test.go`;
  - `web/src/components/CCSPasswordPanel.tsx`, `CCSPasswordPanel.test.tsx`, `web/e2e/windows-ccs.spec.ts`.
- Modified:
  - `winproto/winproto.go`, `winproto_test.go`;
  - `winhelper/{write,pfx,pfx_test,winhelper,winhelper_test,journal,journal_test,restore,restore_test,status,status_test,cleanup,cleanup_test,fakehost_test}.go`;
  - `wintest/{model,write,write_test,tls,demo,wintest_test}.go`;
  - `cmd/alice-fakewindows/{main,main_test}.go`;
  - `cmd/alice-winhelper/{host_windows,zz_runner_clean_windows_test}.go` (+ `httpapi_update_windows.go` if F15 route (a));
  - `internal/providers/windows/{discover,convert,convert_test,deploycert,deploycert_test,verify,verify_test,rollback,status,provider,provider_test,errors,conformance_test}.go`;
  - `internal/providers/{groundwork,providers_test}.go`;
  - `internal/inventory/{platformkey,deployment_records,targets,notify}.go`;
  - `internal/api/{targets_handlers,errors,certs_dto,errors_winserver_test}.go`, `api/openapi.yaml`;
  - `.github/workflows/windows.yml`;
  - `locales/common/{en,tr}.json`, `web/src/locales/{en,tr}.json`;
  - `web/src/api/{types,targets,enums,warnings,deployments}.ts`, `web/src/components/{DeploymentSteps,WebsitesPanel}.tsx`, `web/src/components/acme/AcmeBindingsPanel.tsx`, `web/src/pages/TargetDetailPage.tsx`, `web/src/test/fixtures.ts`, and the matching tests;
  - docs: `docs/superpowers/rulings/windows-iis.md`, `docs/superpowers/specs/2026-10-21-windows-iis-target-design.md`, `docs/superpowers/specs/alice-v1/{00-decisions,03-integrations,04-security,06-quality}.md`, `test/matrix/traceability.json`, `docs/security/traceability.md`, `CHANGELOG.md`, `docs/admin-guide.md`, `docs/windows-host-preparation.md`, `docs/troubleshooting.md`.
