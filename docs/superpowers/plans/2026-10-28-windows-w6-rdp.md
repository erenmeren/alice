# Windows Servers, Phase W6 (Remote Desktop certificate) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A Windows server's Remote Desktop listener (`RDP-Tcp`) becomes one location of kind `win_rdp`. Alice deploys a certificate to it: the certificate is imported as in W2, NETWORK SERVICE is given read access to its private key, and the listener's `SSLCertificateSHA1Hash` names it. Alice verifies the change with a TLS handshake on the listener's port after the RDP security-layer negotiation (a new probe mode). A failed verification puts the previous certificate back (or, when RDP used its self-signed certificate, removes the value again) and removes the key access it added. A listener re-pointed outside Alice is drifted and can be repaired.

**Architecture:** No new engine. The helper gains two protocol-1 subcommands, `rdp-dump` (read) and `rdp-deploy` (write: the W2 transaction with a `grant_key_read` step and a `set_listener` step in place of `bind`). Restore, status and fence reuse `iis-restore`, `iis-status` and `iis-fence`, which act on the journal's kind (`rdp_listener`), as W5 did for CCS. The code is platform-neutral `winhelper` code behind new `WriteHost` methods, implemented by the real helper and by the emulator `wintest`. `tls-probe` gains a trailing `--rdp`. The RDP negotiation bytes live once, in `helperproto` (the shared probe code), and are used by the helper's `tls-probe` and by `tlsverify.TLSProber{RDP: true}`. Alice side:
- the location kind `win_rdp` (migration `00037` widens the two kind CHECKs);
- an `rdp` branch in the Windows provider's `Discover`, `DeployCertificate` and `VerifyDeployment`;
- the inventory sites that name `win_sslbinding`;
- the RDP row on the server page, the RDP steps and texts in the web UI.

The helper's version becomes `1.2.0`. A `1.1.0` helper keeps every W1-W5 feature and is never sent an RDP subcommand or `tls-probe --rdp`.

**Tech Stack:** Go 1.27.3 (`golang.org/x/crypto/ssh`, `golang.org/x/sys/windows` and `.../registry`, pgx/v5, testcontainers), PostgreSQL, React 18 + Mantine + TanStack Query + i18next, Vitest, Playwright, GitHub Actions `windows-2022` / `windows-2025` runners.

**Spec:** `docs/superpowers/specs/2026-10-21-windows-iis-target-design.md`. This phase is §13 "Phase W6". It also draws on:
- §5 (data model: later consumers are "more facts and location kinds of the same target");
- §6.2-§6.7 (discovery, the W2 transaction, verification, rollback, drift, cleanup), which W6 reuses;
- §8 (one fresh SSH connection per helper call); §9 (security analysis); §13 "Interactions with other work";
- §14 F4 (a key imported by the helper has the DACL `O:BAD:P(A;OICI;0xd01f01ff;;;SY)(A;OICI;0xd01f01ff;;;BA)`, so NETWORK SERVICE has no access until granted), F11 (the key delete route), F12 (`SSLCertificateSHA1Hash` absent on both runner images);
- §15 Q8 (RDP first, on demand), Q9 (the store), Q11 (one target); §16-§20 (W1-W5 as built).

Rulings and the "Deferred to W6+" list are in `docs/superpowers/rulings/windows-iis.md`. The format models are `docs/superpowers/plans/2026-10-27-windows-w5-ccs.md` and `2026-10-23-windows-w3-drift-and-cleanup.md`. The owner approved W6 on 2026-10-28 and confirms the rulings listed under [Owner to confirm](#owner-to-confirm).

**Scope:**
- In scope: design §13 W6, which covers the `win_rdp` location kind, its discovery, the import, the NETWORK SERVICE key grant, the listener write, the RDP probe mode, rollback, drift, helper `1.2.0`, the UI and the documents. A dedicated security review of the key grant (§13: "Key ACLs are the new risk and get their own review").
- Not in scope:
  - listeners other than `RDP-Tcp` (custom WinStations), RD Gateway, RD Web Access, RD Connection Broker and RemoteApp certificates;
  - changing the listener's port, security layer, NLA or any other RDP setting (Alice reads them only);
  - Group Policy and autoenrolment writers of the RDP certificate (Alice warns, Ruling 5);
  - the WinRM transport (W7);
  - the items carried in "Deferred to W6+", which stay carried unless a ruling below names them (Ruling 28).

**Decision:** R69 "Windows server target, phase W6: Remote Desktop certificate" (R68 is the last entry of `00-decisions.md`). **Size:** M, 8 tasks (6 code tasks, documents, final gates; about 6-8 implementer hours plus runner waits). **Migration:** `00037` (Ruling 1).

## Before you start: facts to measure on a runner

Five facts are new. Task 4's real tests measure them before the code that depends on them is called done. Record each verdict, with its run link, as a ruling under the "W6 (R69)" heading of `docs/superpowers/rulings/windows-iis.md`, and as a row F19-F23 of design §14.

| Fact | What W6 relies on | If it is wrong | Tasks |
|---|---|---|---|
| F19 | On `windows-2022` and `windows-2025`, the test can turn RDP on by writing `fDenyTSConnections` = 0 under `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server` (after recording the value it found), without a reboot or a service restart, and the listener then answers on `127.0.0.1:<PortNumber>` (3389 on the images). Recorded: the TermService state, the values found (`fDenyTSConnections`, `PortNumber`, `SecurityLayer`, `UserAuthentication`, the policy key `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services`), the number of certificates in `LocalMachine\Remote Desktop`, and that the leaf the listener serves while `SSLCertificateSHA1Hash` is absent is that store's single certificate. | If RDP cannot be turned on: the real tests cover the registry, the key grant and the store half only; the probe half stays emulator-only and becomes an owner item of the manual matrix (release checklist section 8). If the served self-signed leaf is not the store's single certificate: Ruling 4's token for an absent value becomes the leaf of the helper's own `tls-probe --rdp` of `127.0.0.1` during `rdp-dump`, and the change is recorded. | 2, 4, 6 |
| F20 | A raw registry write of `SSLCertificateSHA1Hash` (REG_BINARY, 20 bytes) naming a certificate in `LocalMachine\My` is served at the next fresh handshake without a restart; deleting the value makes the listener serve its self-signed certificate again. The test polls fresh handshakes every 100 ms for up to 120 s and logs the delay. Also logged: the served chain length against `CertGetCertificateChain`'s, whether a certificate only in `Remote Desktop` (not `My`) is served when named, and what `Win32_TSGeneralSetting` reports afterwards (read through PowerShell in the test only). | (a) A delay below 10 s: `winproto.RDPPickupWait` = the measured maximum + 50 %, and the verification's attempts span it (W5's `CCSPickupWait` pattern). (b) Not served within 120 s: the write goes through WMI `Win32_TSGeneralSetting.SetSSLCertificateSHA1Hash` by a hand-written COM call in `cmd/alice-winhelper` (no new module). That adds about one task; the coordinator decides before Task 6 starts. Restarting TermService is never an option: it disconnects every session. | 2, 4, 6 |
| F21 | With the key as imported (F4's DACL), the RDP handshake fails (the test logs the client error and the Schannel System event, 36870 expected). After the helper adds one ACE `(A;;GR;;;NS)` (S-1-5-20, `GENERIC_READ`, no inheritance flags) through `NCryptSetProperty(NCRYPT_SECURITY_DESCR_PROPERTY, DACL_SECURITY_INFORMATION)`, the handshake succeeds. The SDDL read back is logged, and the helper's "has read" test matches it. Removing the ACE gives F4's SDDL back byte for byte. The key stays not exportable (`NCryptExportKey` 0x80090029). | If `GENERIC_READ` is not enough: the measured mask is used and recorded. If the handshake succeeds without any grant on both images: the coordinator decides whether `grant_key_read` stays (Windows Server 2019 and older builds are not measured) or is dropped (least privilege). Record the decision either way. | 2, 4 |
| F22 | The negotiation bytes: the X.224 Connection Request `03 00 00 13 0e e0 00 00 00 00 00 01 00 08 00 03 00 00 00` (TPKT, CR TPDU, `RDP_NEG_REQ` with `PROTOCOL_SSL \| PROTOCOL_HYBRID`) is answered by a 19-byte Connection Confirm with `RDP_NEG_RSP` (type 0x02), and its `selectedProtocol` is 1 or 2. A TLS ClientHello on the same connection then completes. Logged: the bytes for NLA on and off, and for `SecurityLayer` 0 (the expected answer is `RDP_NEG_FAILURE`, type 0x03, or `selectedProtocol` 0). | `helperproto.RDPNegotiate` follows the measured bytes; the table test gains the measured answers. | 1, 4 |
| F23 | With NLA required (`UserAuthentication` = 1), the TLS handshake completes before CredSSP, so the leaf is read without credentials. A disconnect right after the handshake leaves no failed-logon event (Security 4625) and no account lockout. | If a 4625 is logged: the admin and host guides say so (a probe per verification attempt). If the handshake needs credentials: an NLA listener is verified by read-back only (level 1, step param `rdp_nla_unverifiable`), and the change is recorded. | 1, 4, 6 |

## Global Constraints

- **Branch.**
  - Worktree branch `windows-w6`, cut from `main` at `7432cfd5` or later. **The first commit of the branch is this plan** (`docs: Windows servers phase W6 (Remote Desktop) plan (R69)`). The plan is never committed on `main`.
  - Never switch branches inside a task. Take `main` in with `git merge main`, never rebase.
  - The executor may push `windows-w6` (only that branch) so `.github/workflows/windows.yml` runs on the real runners. It never pushes `main`, never opens a pull request and never changes repository settings. The coordinator merges and pushes.
- **Commits.**
  - `git -c user.name="Eren Altan" -c user.email="erenaltan@gmail.com" commit --only -m "<subject> (R69)" -m "Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>" -- <paths>`. Every subject ends with `(R69)`.
  - New files: run `git add -- <path>` first. Never `git add -A` or `git add .`. Check `git status --short` before each commit.
  - Never touch `.claude/`, the untracked PDFs, `alice-helper` (an untracked binary at the root), `docs/security/reviews/independent-audit*` or the other untracked review files.
  - `.gitleaksignore` is pinned to commit hashes, so never rebase, squash or amend a pushed commit. Never commit key material. Tests generate keys at run time (`internal/testutil/pki`).
- **Security guards that must stay green.**
  - Connections and SSH: `TestNoCodeAcceptsAnyHostKey`; the archtest rule that only `internal/providers/windows` and `linuxssh` call `linuxssh.ForcedCommand`.
  - Imports and pins: `tools/pincheck`; `TestImportRules` and `TestAllowed` (`internal/archtest/arch_test.go`); `TestWindowsHelperLinksOnlyItsProtocol` (W6 adds no dependency to the helper: `golang.org/x/sys/windows/registry` is already linked by `cmd/alice-winhelper/cleanup_windows.go`).
  - Build and release: `TestReleaseBinariesLinkNoTestPackages`; `TestNoWindowsReservedFileNames`; `TestWindowsWorkflowWatchesEveryDependency` (`internal/providers/linuxssh/**` and `internal/providers/tlsverify/**` are already in `.github/windows-paths.txt`); `TestWindowsWorkflowRequiresEveryRealTest`; `TestWindowsHelperBuildFlagsAgree`; `make release-symcheck`; `make image-check`.
- **Protocol.**
  - `winproto.Protocol = 1` and `MinProtocol = 1` stay. `winproto.Version = "1.2.0"`.
  - New constant `RDPMinVersion = "1.2.0"`. `WriteMinVersion = "0.2.0"`, `CleanupMinVersion = "0.3.0"` and `CCSMinVersion = "1.1.0"` are unchanged.
  - New subcommands `rdp-dump` (no standard input) and `rdp-deploy --op <uuid>` (JSON on standard input). `tls-probe` accepts a ninth argument `--rdp` (Ruling 15).
  - A `1.1.0` helper answers the new subcommands `UNKNOWN_SUBCOMMAND` and a nine-argument `tls-probe` `USAGE` (exit 2, nothing changed). Alice refuses before sending to a helper below `RDPMinVersion`.
  - The command line never carries a registry path, a SID, a store or a thumbprint (W2 Ruling 4, `winproto.ValidToken`).
  - One fresh SSH connection per helper call (design §8).
- **Helper version literal.** Every place that asserts the helper's own version changes from `1.1.0` to `1.2.0` in Task 1:
  - `internal/providers/windows/winproto/winproto.go:29` and the package comment (`:19-25`);
  - `winproto_test.go:295`, `:589` and `TestReleasedHelperVersion` (`:615-645`);
  - `internal/providers/windows/winhelper/winhelper_test.go:63` (`TestRunVersion`);
  - `internal/providers/windows/provider_test.go:123`;
  - `docs/admin-guide.md:1568-1569` ("Helper versions").

  Fixture values `HelperVersion: "1.0.0"` that do not read `winproto.Version` stay (as in W5).
- **The unknown subcommand of the tests.** Four tests use `rdp-deploy` as a subcommand that does not exist. W6 makes it exist, so Task 1 moves them to `winrm-deploy` (W7's, still unknown):
  - `cmd/alice-winhelper/emulator_fidelity_windows_test.go:467-468` (`TestFidelityVersionAndRefusals`);
  - `internal/providers/windows/rollback_test.go:649`;
  - `internal/providers/windows/winhelper/winhelper_test.go:74`;
  - `internal/providers/windows/provider_test.go:355`.
- **What the helper may write (Ruling 10 and 11; WN-23, WN-24).**
  - In the registry: only the value `SSLCertificateSHA1Hash` of `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp` (set to 20 bytes, or deleted). Both names are constants in code, never input.
  - In a key's security descriptor: only one ACE for NETWORK SERVICE (S-1-5-20, a constant), added or removed, on the key of the certificate `rdp-deploy` sets on the listener.
- **Paths on the server.** As in W2: the journal `C:\ProgramData\Alice\helper\journal\<op>.json`, the binding record `...\helper\bindings\<hash>.json` keyed by the canonical text `rdp/RDP-Tcp`, the lock `...\helper\helper.lock`.
- **Event source `Alice Helper`:** 1001 deploy, 1002 restore, 1003 certificate removed, 1004 CCS file written; **1005 RDP certificate set** (W6). No event carries key material.
- **Error codes.** The existing codes are `ALC-WIN-0001..0020`. New (Task 5): `ALC-WIN-0021` `windows.rdp_disabled` (409), `ALC-WIN-0022` `windows.rdp_tls_off` (409), `ALC-WIN-0023` `windows.rdp_key_acl_failed` (409).
- **Test IDs:** `WIN-56`..`WIN-64`. **STRIDE:** `WN-23`..`WN-25`. **Migration:** `00037` only; its Down's SQLSTATE is `Z1035` (the next free after 00036's `Z1034`).
- **Coverage floors** (`coverage-floors.json`; never lower one): `winproto` 100, `helperproto` 100, `tlsverify` 95, `winhelper` 95, `windows` 95, `wintest` 90, `cmd/alice-fakewindows` 90, `inventory` 89. No new Go package.
- **Locales.** EN and TR in `locales/common/{en,tr}.json` and `web/src/locales/{en,tr}.json`, with identical keys and placeholders (`make i18n-check`). Turkish never puts a suffix on a placeholder that holds a path or a host.
- **Real-Windows runs.**
  - Budget: **8 runs** of `windows.yml` (windows-2022 and windows-2025 legs). Every run counts; record each in a runner-run table in the rulings file.
  - The real RDP listener stays on the port the image has (3389). The tests never write `PortNumber`, `SecurityLayer` or the policy key: a port change needs a TermService restart. They may write `fDenyTSConnections` and `UserAuthentication` and restore both as found.
  - Fixture ports **45500-45519** are for http.sys bindings the RDP tests make (Ruling 26). Certificates are named `alice-w6-*`. Cleanup is registered before the fixture is made.
  - The tests restore `SSLCertificateSHA1Hash` as found (absent on the images). They delete every certificate and key they made, and every http.sys record. `TestRealRunnerIsClean` is extended to check all of that (W2 Ruling 22). W3 Ruling 22 ("no test writes the listeners' values") is amended for these tests only.
  - A test that needs a TCP listener of its own (not http.sys, not RDP) asks the OS for a free port (`127.0.0.1:0`), as R65 taught.
- **e2e.** `E2E_PROJECT=alice-e2e-w6 ALICE_E2E_PORT=9983 make e2e-up e2e; E2E_PROJECT=alice-e2e-w6 make e2e-down`; final `E2E_PROJECT=alice-e2e-w6 ALICE_E2E_PORT=9983 make ci`. Docker-based Go runs and Playwright never run at the same time, and neither runs while another `make ci` on the machine is active.
- **Verification commands.**
  - `go build ./... && go vet ./... && go vet -tags integration ./...`
  - `GOOS=windows GOARCH=amd64 go build ./cmd/alice-winhelper/ ./internal/providers/windows/... && GOOS=windows GOARCH=arm64 go build ./cmd/alice-winhelper/ && GOOS=windows go vet ./cmd/alice-winhelper/ ./internal/providers/windows/... && GOOS=windows go vet -tags alicetest ./cmd/alice-winhelper/`
  - `go test -race -count=1 ./<pkgs>`; `go test -race -count=1 -tags integration ./<pkgs>`
  - `make lint`, `make test`, `make i18n-check`, `make matrix-check MATRIXCHECK_FLAGS=-strict`, `make docs-check`; final `make coverage` and `make ci`
  - web: `cd web && npx vitest run <files> && npx tsc --noEmit && npm run lint`
  - A helper change regenerates the checksums: `make helper winhelper`.

## Rulings (where the spec is silent; each goes into `docs/superpowers/rulings/windows-iis.md` under a new "W6 (R69)" heading for the owner to confirm)

1. **Decision R69; one migration, `00037`.** `win_rdp` is in no CHECK yet: `certificate_locations_kind_check` and `deployments_location_kind_check` (`00036` lists `server_file`, `win_sslbinding`, `f5_clientssl`, `k8s_tls_secret`, `win_ccs_file`). `00037_windows_rdp.sql` widens exactly those two with `win_rdp`. No credential, no column: the locator and details are 00031's. Its Down restores 00036's lists and refuses with SQLSTATE `Z1035` while a `win_rdp` location or deployment exists (00036's pattern).
2. **Helper 1.2.0, protocol 1, `RDPMinVersion` 1.2.0; two new subcommands and one flag.**
   - `rdp-dump` and `rdp-deploy` are added to protocol 1, because they are additive (W2, W3 and W5 did the same).
   - Restore, status and fence of an RDP operation go through `iis-restore`, `iis-status` and `iis-fence`, which dispatch on the journal's `kind` `rdp_listener` (W5 Ruling 2's pattern). Only a 1.2.0 helper writes such a journal.
   - The provider refuses an RDP call to a helper below 1.2.0 before sending. Discovery then lists no `win_rdp` location and adds the server warning `win_rdp_helper_outdated`. A deployment ends `windows.helper_outdated` with `required_version 1.2.0`. The backstop `UNKNOWN_SUBCOMMAND` maps to the same reason.
3. **One location per server: the `RDP-Tcp` listener.**
   - Kind `win_rdp`. Locator `{"type":"rdp","listener":"RDP-Tcp","port":<PortNumber>}`. `cert_path` is the canonical text `rdp/RDP-Tcp` (unique per server; the UI shows "Remote Desktop (RDP-Tcp), port N"). `key_path` is empty and `servers` is `[]`.
   - Details: `store` (`MY`, or `Remote Desktop` for the self-signed certificate), `cert_sha1`, `self_signed` (bool), `enabled`, `security_layer` (0, 1 or 2), `nla` (bool), `cert_template` (the policy's template name, or "").
   - Other WinStations keys are not read. A server whose `RDP-Tcp` key is absent has no `win_rdp` location.
4. **The listener's current certificate and the token.**
   - When `SSLCertificateSHA1Hash` is present, the current certificate is the one with that SHA-1 in `LocalMachine\My` (F20 confirms the store). Absent there → problem `cert_missing`. Present without a usable key → `key_missing`. Both make the location unsupported, by inventory's existing rule.
   - When the value is absent, RDP serves its self-signed certificate. That is the single certificate of `LocalMachine\Remote Desktop` (F19). Its DER SHA-256 is the token, and `self_signed` is true.
   - An absent value is a deployable location, not `cert_missing`: the first deployment sets the value. With no certificate, or more than one, in `Remote Desktop` while the value is absent, the location is unsupported with reason `win_rdp_cert_unknown` (no token could prove what is replaced).
   - The token is the leaf's DER SHA-256, as for a binding (`newCertSHA256` treats `win_rdp` like `win_sslbinding`).
5. **Effective settings are read the way Windows applies them.**
   - Each of `fDenyTSConnections`, `SecurityLayer` and `UserAuthentication` is read from the policy key `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services` when set there, otherwise from the listener's own key (`fDenyTSConnections` from `...\Control\Terminal Server`).
   - RDP off (`fDenyTSConnections` 1) → unsupported `win_rdp_disabled`: nothing would serve the certificate, so the verification could only fail.
   - `SecurityLayer` 0 (RDP security, no TLS) → unsupported `win_rdp_no_tls`: the certificate is never used.
   - The policy value `CertTemplateName` set (RDP certificate autoenrolment) → location warning `win_rdp_autoenroll`: deployable, warned, and named as the likely cause when the listener drifts (as `IIS-AutoCertRebind` for bindings).
6. **The store of an RDP import: always `LocalMachine\My`.** RDP has no store of its own for a named certificate (Q9's rule does not apply, there is no binding store). The previous certificate's store is recorded (`MY` or `Remote Desktop`).
7. **W3 cleanup and RDP.**
   - Unchanged: cleanup rule 2 keeps whatever the listener names (`winproto.KeptRDP`, reason `rdp`).
   - After an RDP deployment, the replaced certificate is a normal cleanup candidate when Alice imported it and nothing else uses it (7 days, Q6). The self-signed certificate is never Alice's, so it is never removed.
   - Removing a certificate removes its key, and with it the NETWORK SERVICE ACE (F11).
   - On Alice's side, the `win_rdp` location holds its certificate, as every location (the Alice judge of W3 Ruling 4).
   - Incident cleanup (Q7) applies to `win_rdp` places as to bindings (`windows_cleanup.go:396`).
8. **`rdp-deploy` input.** `winproto.RDPDeployInput{ExpectSHA256, ChainPEM, KeyPEM string; ForbiddenSPKI, ForbiddenLeaf []string}` (tags `expect_sha256, chain_pem, key_pem, forbidden_spki_sha256, forbidden_leaf_sha256`), at most `MaxDeployInput`. It is decoded strictly, as W2's `DeployInput`, and redacts the key in `String`, `GoString` and `LogValue`. There is no locator (one listener, named in code) and no store (Ruling 6).
9. **`rdp-deploy` transaction**, in this order, each refusal before step 5 changing nothing:
   1. Decode stdin strictly. Elevated. Lock. Refuse with `OPERATION_EXISTS` or `FENCED` (W2), then `RECOVERY_PENDING` for an interrupted latest operation of `rdp/RDP-Tcp` (`interruptedLatest`).
   2. Read the listener (`RDPListener`): key absent → `BINDING_NOT_FOUND`; RDP off → `RDP_DISABLED`; `SecurityLayer` 0 → `RDP_TLS_OFF` (exit 3).
   3. The current certificate by Ruling 4; its DER SHA-256 ≠ `expect_sha256` → `HASH_MISMATCH` (exit 3). The new certificate in `My` without a usable key → `KEY_UNUSABLE` (W2 Ruling 9).
   4. Journal `prepared`: `kind` `rdp_listener`, `binding` `rdp/RDP-Tcp`, `store` `MY`, the previous leaf's SHA-1, SHA-256 and SPKI SHA-256, `rdp.previous_store`, `rdp.previous_absent`, the new hashes, the forbidden lists. The binding record names this operation.
   5. Step `import_chain` (W2's code). Step `import_certificate` (W2's code, store `My`; an existing copy with a usable key is used as is and not Alice's).
   6. Step `grant_key_read` (Ruling 10): read whether NETWORK SERVICE can read the key, write it into the journal (`rdp.key_read_had`), then add the ACE when it could not. A failure → `restored` with `failed_step grant_key_read` and error `key_acl` (the listener is untouched; an ACE that was added is removed again).
   7. Unchanged rule (Ruling 14). Otherwise journal `writing`, then step `set_listener`: write the value with the new SHA-1. Read it back. A mismatch → self-restore under the guard (Ruling 11).
   8. Journal `committed`; the binding record keeps the deployment's chain (W2); event 1005 `operation <op> rdp RDP-Tcp old <sha256> new <sha256> key_read_granted <true|false>`.

   The answer is `winproto.DeployResponse` (shared) with `Store` `MY`, `AliceImported` as W2, and `BuiltChainLength` from W2's function. The steps are `import_chain`, `import_certificate`, `grant_key_read`, `set_listener`. The W2 write gate applies: `OUTCOME_UNKNOWN` after the first durable write, which is the prepared journal.
10. **The NETWORK SERVICE key grant: exactly what is granted.**
    - One access-allowed ACE, trustee S-1-5-20 (NETWORK SERVICE, the account TermService runs as), mask `GENERIC_READ` (F21 may change the mask), no inheritance flags, appended to the key's existing DACL. The owner, the group, the SACL and the other ACEs are unchanged. It is set through `NCryptSetProperty(NCRYPT_SECURITY_DESCR_PROPERTY, ..., DACL_SECURITY_INFORMATION)` on the key `CryptAcquireCertificatePrivateKey(CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG)` opens for the certificate in `My`.
    - Only on the key of the certificate this operation puts on the listener. Never on a key named by input: the SID, the store and the certificate are fixed by the transaction.
    - "Can read" means an access-allowed ACE for S-1-5-20 or S-1-1-0 (Everyone) whose mask includes the read bits F21 measures. When it already holds, nothing is written (`key_read_had` true).
    - The key stays not exportable (export policy 0). The grant lets a NETWORK SERVICE process use the key; it never lets anyone export it.
    - Revoked by every restore of the operation when `key_read_had` is false: the NETWORK SERVICE ACEs that are not inherited are removed, and the rest of the DACL is unchanged. A revoke failure does not fail the restore. The restore step carries the param `rdp_key_acl_left` true, and the e-mail text says so.
    - Not revoked when a later deployment replaces the certificate: its rollback needs the previous certificate working. W3's cleanup removes the key with the certificate when Alice imported it. A third party's certificate keeps the ACE until someone removes it (owner item).
11. **Rollback through `iis-restore` on an RDP journal.**
    - The guard is checked on the journal's previous leaf and SPKI hashes (R48), monotonic as in W2. A previous self-signed certificate is checked like any other.
    - The listener must still name this operation's certificate. Otherwise the restore answers `SUPERSEDED` (committed journal) or `restore_failed` `file_changed` (interrupted journal), and nothing is done.
    - `previous_absent`: the value is deleted. RDP then serves its self-signed certificate, or makes a new one if someone removed it. There is no `BACKUP_MISSING` for this case.
    - Otherwise the previous certificate must be in `previous_store` with a usable key (`BACKUP_MISSING` before any write). Then the value is set back, read back, the ACE revoked (Ruling 10), journal `restored`, event 1002.
    - `iis-status` answers `current_cert_sha256` from the listener: the new leaf, the previous leaf, or `""`. `iis-fence` is unchanged.
12. **Recovery after a reboot or a kill.** The registry and the key DACL are persistent, and the journal is on disk. A kill after `prepared` or after `grant_key_read` and before `writing` answers `restored` with nothing on the listener. The ACE is revoked by the restore when `key_read_had` is false. Recorded before the grant, that field makes the revoke correct even after a kill between the grant and the next journal write.
13. **Journal shape.** `journal.Kind` `winproto.JournalKindRDP` (`"rdp_listener"`) and `journal.RDP *rdpJournal{PreviousStore string; PreviousAbsent bool; PreviousSPKISHA256 string; KeyReadHad *bool; ACLLeft bool}`. `Locator` and `Previous` stay empty. `Binding` is `rdp/RDP-Tcp`, and `Store` is `MY`. `valid` checks the fields of its kind: `PreviousStore` is `MY` or `Remote Desktop`; `PreviousAbsent` needs `Remote Desktop`; `KeyReadHad` is nil only in `prepared`. W3's cleanup and pruning read RDP journals like binding journals, because they name a certificate in `My`.
14. **Unchanged.** The answer is `unchanged`, with no write, when all of these hold: the listener names the new SHA-1, NETWORK SERVICE can read its key, no intermediate was added, and the binding record's chain equals the deployment's (W2 Ruling 10). Otherwise the value is written even when it is the same, because F20 measures whether a same-value write rebuilds the served chain.
15. **The RDP probe mode.**
    - `helperproto.RDPNegotiate(rw io.ReadWriter) (selected uint32, err error)` writes the 19-byte Connection Request of F22 (`requestedProtocols` = `PROTOCOL_SSL | PROTOCOL_HYBRID` = 3, no cookie). It reads one TPKT (version 3, length 11 to 64), checks the X.224 Connection Confirm code 0xD0, and parses the optional `RDP_NEG_RSP` or `RDP_NEG_FAILURE`. `selected` 1, 2 or 8 → nil (TLS follows). 0, no negotiation data, a failure, or anything malformed → `ErrRDPNoTLS` or `ErrRDPNegotiation`. The read is bounded and uses the caller's deadline.
    - Alice's probe is `tlsverify.TLSProber{RDP: true}`: it dials, negotiates, then runs the same handshake and answer as the TLS probe. A negotiation failure is `ErrProbeFailed`.
    - The helper's probe is `tls-probe ... --rdp` (a ninth argument; the eight-argument form is unchanged). It is sent only to a 1.2.0 helper.
    - The probe stops after the TLS handshake. It never starts CredSSP and sends no credentials or application data.
16. **Verification endpoints of a `win_rdp` location** (`rdpEndpoints`): one endpoint, the locator's port (the Administrator's port replaces it), SNI = the Administrator's SNI or `tlsverify.SNIFor(nil, sans)`, `Addr` `127.0.0.1`, `Listen` "" (`RDP-Tcp` listens on every address). The SNI is also the name the R51 trust check uses; RDP serves one certificate whatever the SNI. When Alice cannot reach the port (a firewall that admits 3389 from administrators only), the helper's `tls-probe --rdp` of `127.0.0.1` decides (tlsverify's existing fallback). The chain length is compared with the chain the helper built (`win.chain_differs`, W2).
17. **Pickup.** `winproto.RDPPickupWait` is 0 unless F20 route (a) sets it. The provider's `verifyAttempts` spans it for `win_rdp`, as W5's `CCSPickupWait` does.
18. **Discovery call order.** `Discover` calls `iis-dump`, then `ccs-dump` (W5), then `rdp-dump`, each on a fresh connection. `rdp-dump` runs when the helper is at least 1.2.0, and that does not depend on IIS. A failed `rdp-dump` (error, budget, undecodable answer) keeps the other results and adds `list_truncated` and `locations_dropped` (W2 Ruling 18: nothing is marked missing). `rdp-dump` is elevated, takes no lock and reads no input.
19. **Engine and inventory sites** (W5 Ruling 21's list):
    - `newCertSHA256` (`internal/inventory/deployment_records.go:248`): the leaf, as a binding.
    - `startBackupRef` (`:713-740`): as a binding (`store` and `cert_sha1` from the details when the token matches). The rollback info is `{operation_id, store, previous_sha1, previous_sha256}`.
    - The details update after a deployment (`:1153-1154`): `win_rdp` sets `cert_sha1` like a binding **and** `store` to `MY` and `self_signed` to false. Otherwise the next deployment's rollback info would name the self-signed certificate's store for the new certificate.
    - `windowsLost` (`:1324`): includes `win_rdp`.
    - `bindingBroken` and `driftCause` (`internal/inventory/drift.go:120`, `:128`): include `win_rdp`, so an RDP certificate removed from `My`, or a broken key, is reported with its cause and never repaired into a failure loop (W3 Ruling 15).
    - AutoCertRebind (`drift.go:424`): binding only.
    - The incident cleanup (`internal/inventory/windows_cleanup.go:396`): includes `win_rdp`.
    - The notices: Ruling 20.

    The steps are `import_chain`, `import_certificate`, the new `grant_key_read` (`providers.StepNameGrantKeyRead`; `winproto.StepGrantKeyRead`) and `set_listener` (`providers.StepNameSetListener`; `winproto.StepSetListener`), then the engine's `verify`, `restore` and `verify_old`. The existing step-name test compares the two packages.
20. **Notices and e-mails.**
    - The three manual-action deployment e-mails get RDP texts of their own (`_windows_rdp`; W5-5's pattern): `rollback_failed`, `outcome_unknown` and `restored_unverified`. They name the listener, the previous certificate (`previous_certificate`), how to check it on the server (Remote Desktop settings, `Win32_TSGeneralSetting`) and that a broken RDP certificate blocks new Remote Desktop sessions, so the server's console or SSH is the way in.
    - Every other deployment e-mail and every drift e-mail of a `win_rdp` location keeps the Windows text (`_windows`) and adds the param `windows_note=rdp`. `internal/notify/sender.go:234` then appends `email.windows_note_rdp`: "This location is the Remote Desktop (RDP-Tcp) listener of the server, not an IIS binding. Its private key must be readable by NETWORK SERVICE." A drift whose location has `win_rdp_autoenroll` names RDP autoenrolment in the same note.
21. **Drift.** The generic rule applies. A listener re-pointed outside Alice is drifted (`binding_repointed`), and the repair is a deployment with trigger `drift_repair` (ClassContinuity), guarded by the token. A certificate removed from `My` or a broken key is reported, never repaired. A value deleted outside Alice makes the listener serve the self-signed certificate: that is a re-point too.
22. **Interactions, unchanged** (design §13):
    - Scoped access: the location belongs to its server's service.
    - Licence: `rdp-dump` is ClassReadOnly with discovery; deployment ClassChange; automatic deployment and drift repair ClassContinuity. One server is one target, whatever it hosts (Q11).
    - Incidents: `win_rdp` locations are incident places, and the guard is checked twice.
    - Canary: applies as to any location.
    - Network discovery: it does not speak the RDP negotiation, so it does not see the listener's certificate (no change in W6).
23. **Emulator model.**
    - The model's RDP listener has: present, enabled, port, security layer, NLA, the value (or absent), the policy template name, and a `Remote Desktop` store with one self-signed certificate. It also keeps a per-key "NETWORK SERVICE can read" flag.
    - It serves a real TCP listener that speaks the negotiation of F22 (answering per security layer and NLA), then TLS with the listener's certificate. A key NETWORK SERVICE cannot read fails the handshake (F21 modelled).
    - The emulator's RDP code reuses `helperproto`'s constants for the bytes.
24. **Test IDs and STRIDE.** `WIN-56`..`WIN-64` (Task 7 lists them).
    - STRIDE `WN-23` (E/I): NETWORK SERVICE gains use of a private key. Every NETWORK SERVICE service can use that key for TLS (never export it). Mitigations: Ruling 10's exact ACE, the RDP certificate only, revoked on rollback, removed with the key by cleanup.
    - `WN-24` (T): a registry or ACL write outside the one value and the one ACE (an injected path, SID or store). Mitigations: constants in code, no such input, `rdp-deploy` without a locator.
    - `WN-25` (D): a certificate RDP cannot use blocks new Remote Desktop sessions. Mitigations: the probe after the negotiation, the restore, the RDP texts naming console and SSH as the way in, the `alice` account's RDP logon already denied (§4.3).
25. **e2e.**
    - A new journey `web/e2e/windows-rdp.spec.ts` (EN and TR) against `cmd/alice-fakewindows`. Its demo host gains an RDP listener on port 3389 inside the container (enabled, `SecurityLayer` 2, NLA on, value absent, one self-signed certificate). Alice reaches it as `fakewindows:3389` on the backend network, so there is no compose change.
    - The journey: the server page shows "Remote Desktop (RDP-Tcp)" with its self-signed certificate; a deployment commits and verifies (steps import chain, import certificate, grant key read, set listener, verify); with `ctl stale-tls-on`, a deployment rolls back to the previous certificate; `expectAccessible` on the server page.
    - Separate from `windows.spec.ts` and `windows-ccs.spec.ts`, so their serial journeys keep their state.
26. **Runner hygiene and budget** as in Global Constraints. The RDP fixture turns RDP on with `fDenyTSConnections` and records and restores the value. It is the only registry write the tests make outside the helper's own; PowerShell appears in tests only. `TestRealRDPSharedWithBinding` binds the same certificate to an http.sys record on 45500. This settles W3's manual-matrix item "an RDP listener with its own certificate kept by cleanup" on the runners.
27. **The dedicated security review (§13 "Key ACLs ... get their own review").** Task 8 step 6 is a review of Rulings 9-13, WN-23..WN-25 and the code of `grant_key_read`, its revoke and the registry write, by a reviewer that wrote none of it. It checks:
    - the ACE is exactly Ruling 10's;
    - no input reaches a SID, a store, a key or a registry name;
    - every restore path revokes;
    - a kill between the grant and the journal cannot leave an unrecorded ACE on a key Alice did not import;
    - the key stays not exportable.

    Its findings are recorded under "Security review (W6)" in the rulings file.
28. **"Deferred to W6+": settled or carried.**
    - Settled by W6: RDP deployment (`win_rdp`); the helper version literal sites (Task 1); F12's set-value half and W3's manual-matrix RDP item (Ruling 26).
    - Carried, unchanged, to W7+: the WinRM transport; W5's deferred items (the farm layout, CCS file creation, removing the CCS password, a CCS password Alice's rule refuses); every "Carried from W2-W4" item; every "Minor deferred during W5", including the `drift_observe.go:151` warning gap. That gap is a CCS read-only understatement the coordinator assigned to the next small batch. W6's RDP endpoints do not read stored warnings.

## Review Focus

1. **The helper writes nothing but the one registry value and the one ACE.** Inputs: an input with a member naming a store, a SID, a registry path or a listener; a certificate the listener does not get (an import that met an existing copy, a failed `set_listener`); a kill after the grant. Tests: Task 2 `TestRDPDeployInputHasNoLocator`, `TestRDPGrantOnlyTheListenersKey`, `TestRDPKillAtEveryPoint`; Task 4 `TestRealRDPKeyReadForNetworkService`.
2. **Every restore takes the grant back, and only a grant this operation made.** Inputs: `key_read_had` true (a key that NETWORK SERVICE could already read: kept), false (revoked); a revoke that fails (restored, `rdp_key_acl_left`); a self-restore after a read-back mismatch. Tests: Task 2 `TestRDPRestoreRules`, `TestRDPRestoreRevokesOnlyItsGrant`; Task 4 `TestRealRDPKeyReadForNetworkService` (F4's SDDL back).
3. **A first deployment over the self-signed certificate, and its rollback.** Inputs: the value absent (deployable, token = the self-signed leaf); a rollback (the value deleted, the self-signed certificate served); no or two certificates in `Remote Desktop` (`win_rdp_cert_unknown`). Tests: Task 2 `TestRDPDumpSelfSigned`; Task 6 `TestConvertRDP`, `TestWindowsRDPFirstDeployAndRollback`; Task 4 `TestRealRDPDeployIsPickedUp`.
4. **The probe reads the right certificate and never authenticates.** Inputs: NLA on and off; security layer 0 (no TLS); a negotiation failure; a truncated or oversized TPKT; Alice unreachable on 3389 (the helper's probe decides); a 1.1.0 helper (no `--rdp` sent). Tests: Task 1 `TestRDPNegotiate`, `TestTLSProberRDP`; Task 2 `TestTLSProbeRDP`; Task 6 `TestRDPEndpoints`, `TestRDPVerifyFallsBackToTheHelper`; Task 4 `TestRealRDPNegotiation` (F22, F23).
5. **A 1.1.0 helper and a server without RDP keep working as in W5.** Discovery of bindings and CCS files is unchanged, and no RDP subcommand is sent. Tests: Task 6 `TestRDPNeedsHelper120`, `TestDiscoverWithoutRDPIsW5`.

---

### Task 1: `winproto`, `helperproto` and `tlsverify`: helper 1.2.0, the RDP shapes, the negotiation, the RDP probe

**Files:**
- Create: `internal/providers/linuxssh/helperproto/rdp.go`, `internal/providers/linuxssh/helperproto/rdp_test.go`
- Modify: `internal/providers/windows/winproto/winproto.go`, `winproto_test.go`, `internal/providers/tlsverify/tlsverify.go`, `tlsverify_test.go`
- Modify (version literal and unknown-subcommand sites of Global Constraints): `internal/providers/windows/winhelper/winhelper_test.go`, `internal/providers/windows/provider_test.go`, `internal/providers/windows/rollback_test.go`, `cmd/alice-winhelper/emulator_fidelity_windows_test.go`, `docs/admin-guide.md`

**Interfaces:**
- Produces (package `helperproto`):
  ```go
  const (
      RDPProtocolSSL, RDPProtocolHybrid, RDPProtocolHybridEx uint32 = 1, 2, 8
      MaxRDPConfirm = 64 // bytes of one TPKT the negotiation reads
  )
  var RDPConnectionRequest = []byte{0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00}
  var ErrRDPNoTLS, ErrRDPNegotiation error
  func RDPNegotiate(rw io.ReadWriter) (selected uint32, err error)          // Ruling 15
  func RDPConfirm(selected uint32) []byte                                   // the 19-byte answer the emulator sends
  func RDPFailure(code uint32) []byte                                       // RDP_NEG_FAILURE
  ```
- Produces (package `tlsverify`): `TLSProber.RDP bool` (negotiate before the handshake; a negotiation error wraps `ErrProbeFailed`).
- Produces (package `winproto`):
  - `Version = "1.2.0"`, `RDPMinVersion = "1.2.0"`; `SubRDPDump = "rdp-dump"`, `SubRDPDeploy = "rdp-deploy"`; `ArgRDP = "--rdp"`
  - Codes: `CodeRDPDisabled = "RDP_DISABLED"`, `CodeRDPTLSOff = "RDP_TLS_OFF"` (exit 3, nothing changed)
  - `StepGrantKeyRead = "grant_key_read"`, `StepSetListener = "set_listener"`; `ErrKeyACL = "key_acl"` (error class); `JournalKindRDP = "rdp_listener"`; `LocatorRDP = "rdp"`, `RDPListenerName = "RDP-Tcp"`, `RDPCanonical = "rdp/RDP-Tcp"`; `RDPStoreSelfSigned = "Remote Desktop"`; `RDPPickupWait time.Duration = 0` (Task 4 sets it if F20 needs route (a))
  - Unsupported reasons and warnings: `UnsupportedRDPDisabled = "win_rdp_disabled"`, `UnsupportedRDPNoTLS = "win_rdp_no_tls"`, `UnsupportedRDPCertUnknown = "win_rdp_cert_unknown"`, `WarnRDPAutoenroll = "win_rdp_autoenroll"`, `WarnRDPHelperOutdated = "win_rdp_helper_outdated"`
  - `type RDPDumpResponse struct{ OK, Present, Enabled, NLA, ValueSet bool; Port, SecurityLayer int; CertTemplate string; Certificate *StoreCertificate; SelfSignedCount int }` (tags `ok, present, enabled, nla, value_set, port, security_layer, cert_template, certificate, self_signed_count`): `Certificate` is the current certificate by Ruling 4 (`nil` when there is none).
  - `type RDPDeployInput struct{...}` (Ruling 8) with redacting `String`, `GoString` and `LogValue`.

- [ ] **Step 1: Write the failing tests**
  - `rdp_test.go`, `TestRDPNegotiate` table over a `bytes.Buffer` pair: it checks that the request written equals `RDPConnectionRequest`. Answers:

    | Answer | Result |
    |---|---|
    | `RDPConfirm(1)`, `RDPConfirm(2)`, `RDPConfirm(8)` | selected 1, 2, 8; nil |
    | `RDPConfirm(0)`; an 11-byte confirm without negotiation data | `ErrRDPNoTLS` |
    | `RDPFailure(2)` (SSL not allowed), `RDPFailure(5)` (HYBRID required) | `ErrRDPNoTLS`, `ErrRDPNegotiation` |
    | TPKT version 2; length 10 or 65; code 0xE0 instead of 0xD0; 18 of 19 bytes then EOF; type 0x02 with length 7 | `ErrRDPNegotiation` |
  - `TestRDPNegotiateReadsOneTPKT`: bytes after the confirm (the server's TLS) stay unread.
  - `tlsverify_test.go`, `TestTLSProberRDP`: a test listener that answers `RDPConfirm(2)`, then TLS, gives the leaf and chain; one that answers `RDPFailure(2)` gives `ErrProbeFailed`; a plain TLS listener probed with `RDP: true` gives `ErrProbeFailed` (it reads a ServerHello where a confirm belongs); `RDP: false` is byte-for-byte the old behaviour (existing tests unchanged).
  - `winproto_test.go`:
    - `TestReleasedHelperVersion` updated: `Version == "1.2.0"`; `VersionAtLeast("1.1.0", RDPMinVersion)` false; `VersionAtLeast("1.1.0", CCSMinVersion)` true. The two older assertions read `1.2.0`.
    - `TestRDPInputRedacts`: `%v`, `%+v`, `%#v`, `%s` and a slog JSON handler never contain the key.
    - `TestRDPShapesJSON`: golden key sets of `RDPDumpResponse` and `RDPDeployInput`.
    - The step-name and error-class lists gain the new names.
- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./internal/providers/linuxssh/helperproto/ ./internal/providers/tlsverify/ ./internal/providers/windows/winproto/`
Expected: FAIL (undefined names; version `1.1.0`).
- [ ] **Step 3: Implement**, then:
  - rewrite `winproto`'s package comment: 1.2.0 adds the RDP subcommands (W6, R69), protocol 1 throughout;
  - update the version sites and move the four unknown-subcommand probes to `winrm-deploy`;
  - change the admin guide's "Helper versions" sentence: Alice manages the Remote Desktop certificate with a helper of 1.2.0 or later.
- [ ] **Step 4: Run the tests**
Run: `go test -race -count=1 -cover ./internal/providers/linuxssh/helperproto/ ./internal/providers/tlsverify/ ./internal/providers/windows/... ./cmd/alice-fakewindows/ && GOOS=windows go vet ./cmd/alice-winhelper/ && make docs-check`
Expected: PASS; helperproto and winproto 100.0 %, tlsverify at least 95 %.
- [ ] **Step 5: Commit**: `feat(winproto): helper 1.2.0 with rdp-dump and rdp-deploy; the RDP negotiation in helperproto and tlsverify's RDP probe (R69)`.

---

### Task 2: `winhelper`: the RDP host surface, `rdp-dump`, `rdp-deploy`, RDP journals in restore, status and fence, `tls-probe --rdp`

**Files:**
- Create: `internal/providers/windows/winhelper/rdp.go`, `internal/providers/windows/winhelper/rdp_test.go`
- Modify: `write.go` (interface), `journal.go` (`JournalKindRDP`, `rdpJournal`, `valid` per kind), `restore.go` and `status.go` (dispatch on `Kind`), `deployinput.go` (strict decode of `RDPDeployInput`, sharing `checkContent`), `probe.go` (`--rdp`), `winhelper.go` (register `rdp-dump`: elevated, no input, no lock; `rdp-deploy`: write, `MaxDeployInput`), `fakehost_test.go`, `journal_test.go`, `restore_test.go`, `status_test.go`, `cleanup_test.go` (an RDP journal is read and pruned like a binding's), `winhelper_test.go`
- Modify (to keep building; Tasks 3 and 4 fill them): `internal/providers/windows/wintest/write.go`, `cmd/alice-winhelper/host_windows.go`

**Interfaces:**
- Consumes: Task 1.
- Produces:
  ```go
  // WriteHost gains (no argument names a registry path, a value or a SID: they are the host's constants):
  RDPListener(ctx context.Context) (RDPListener, error)                   // the effective settings (Ruling 5); Present false when RDP-Tcp is absent
  SetRDPCertificate(ctx context.Context, sha1 string) error               // "" deletes SSLCertificateSHA1Hash
  StoreCertificates(ctx context.Context, store string, limit int) ([]winproto.StoreCertificate, error) // Remote Desktop's, at most limit
  RDPKeyRead(ctx context.Context, store, sha1 string) (readable bool, err error)
  SetRDPKeyRead(ctx context.Context, store, sha1 string, grant bool) error // add Ruling 10's ACE, or remove the non-inherited NETWORK SERVICE ACEs
  type RDPListener struct {
      Present, Enabled, NLA bool
      Port, SecurityLayer   int
      CertSHA1              string // "" when the value is absent
      CertTemplate          string
  }
  func cmdRDPDump(ctx context.Context, c *call) (any, error)
  func cmdRDPDeploy(ctx context.Context, c *call) (any, error) // Ruling 9
  type rdpJournal struct{ ... }                                // Ruling 13
  ```
  `rdp-dump` checks elevation, then reads `RDPListener`. With `Present` false the answer is `{present:false}`. Otherwise it reads the current certificate by Ruling 4 (`Certificate` in `My`, or `StoreCertificates("Remote Desktop", 2)` and `SelfSignedCount`), under the budget. `iis-restore` follows Ruling 11, `iis-status` and `iis-fence` follow Ruling 11's last line. `ProtectedThumbprints` stays as built (it reads the same value).
- Mirror: `deploy.go` (`deployTx`, `importChain`, the import, `selfRestore`, the gate, `interruptedLatest`), `ccs.go` (a second deploy command on the shared journal), `restore.go`'s `planRestoreCCS`.

- [ ] **Step 1: Write the failing tests** (`rdp_test.go` and the existing files, against `fakeWriteHost`):
  - `TestRDPDump` table:
    - `RDP-Tcp` absent → `present:false`, no store read;
    - value set → the certificate from `My`;
    - value set to a certificate not in `My` → `certificate` null, `value_set` true;
    - value absent with one `Remote Desktop` certificate → that certificate, `self_signed_count` 1 (`TestRDPDumpSelfSigned`);
    - value absent with 0 or 2 → `certificate` null, `self_signed_count` 0 or 2;
    - policy values override the listener's (`SecurityLayer` 0 under policy, 2 on the listener → 0);
    - not elevated → `NOT_ELEVATED`; an unreadable registry → `IO_ERROR`.
  - `TestRDPDeployCommits`:
    - steps `import_chain`, `import_certificate`, `grant_key_read`, `set_listener`;
    - the fake's listener names the new SHA-1, and its key is readable by NETWORK SERVICE;
    - the journal is `committed`, with `previous_absent` true over a self-signed certificate;
    - event 1005 holds no PEM;
    - the answer's `store` is `MY`.
  - `TestRDPDeployUnchanged` (Ruling 14): same certificate, readable key, same chain → `unchanged`, no write; same certificate with the key not readable → grant, then a same-value write.
  - `TestRDPDeployRefusesBeforeAnyWrite`. Each case leaves the fake's write log empty:
    - `RDP-Tcp` absent → `BINDING_NOT_FOUND`;
    - RDP off → `RDP_DISABLED`;
    - security layer 0 → `RDP_TLS_OFF`;
    - another current leaf, and two self-signed certificates → `HASH_MISMATCH`;
    - the new certificate in `My` without a key → `KEY_UNUSABLE`;
    - a known operation → `OPERATION_EXISTS`; a fenced one → `FENCED`; an interrupted latest → `RECOVERY_PENDING`;
    - not elevated; lock held → `BUSY`.
  - `TestRDPDeployInputHasNoLocator` (Review Focus 1): members `locator`, `store`, `sid` or `listener` → `BAD_CONTENT`; the strict-decode cases of W2.
  - `TestRDPGrantOnlyTheListenersKey` (Review Focus 1): the fake's ACL log holds one grant, for `My` and the new SHA-1. With an import that met an existing copy, the grant goes to that copy (and `alice_imported` is false). No other key is touched.
  - `TestRDPGrantFails`: `SetRDPKeyRead` fails → `restored`, `failed_step grant_key_read`, error `key_acl`, the listener untouched.
  - `TestRDPDeployReadBackRestores`: the value reads back other bytes → self-restore under the guard → `restored`, `failed_step set_listener`, `error read_back`, the ACE revoked.
  - `TestRDPKillAtEveryPoint` (Review Focus 1, 2): `Point` kills after `prepared`, after the grant and before its journal write, after `writing`, after the value write and before `committed`. For each, `iis-status` gives the phase and `current_cert_sha256`. `iis-restore` then leaves the listener on the previous certificate (value deleted when it was absent) and the key without an ACE this operation added.
  - `TestRDPRestoreRules`:
    - a forbidden previous leaf or SPKI → `restore_forbidden`, nothing written;
    - a third party re-pointed the listener after the commit → `SUPERSEDED`;
    - the previous certificate gone from `My` → `BACKUP_MISSING` before any write;
    - the previous value absent and the self-signed certificate gone → `restored`, the value deleted;
    - a second restore → `restored` without a write.
  - `TestRDPRestoreRevokesOnlyItsGrant` (Review Focus 2): `key_read_had` true → the ACE stays; false → removed; a failing revoke → `restored` with the restore step's param `rdp_key_acl_left`.
  - `journal_test.go`: an RDP journal with `previous_absent` and `previous_store` `MY` is invalid, as is one with `locator` set, or with `key_read_had` nil in `committed`.
  - `winhelper_test.go`, `TestTLSProbeRDP`: `tls-probe ... --rdp` against a negotiating listener answers the leaf; a tenth argument or `--rdp` not last → `USAGE`; without `--rdp` unchanged.
- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./internal/providers/windows/winhelper/ -run 'RDP|TLSProbe'`
Expected: FAIL.
- [ ] **Step 3: Implement.** All messages are fixed texts. The key buffers are cleared on every path, as in W2.
- [ ] **Step 4: Run the tests**
Run: `go test -race -count=1 -cover ./internal/providers/windows/winhelper/ && GOOS=windows go vet ./cmd/alice-winhelper/ ./internal/providers/windows/...`
Expected: PASS, at least 95 %; every W2, W3 and W5 test unchanged.
- [ ] **Step 5: Commit**: `feat(winhelper): rdp-dump and rdp-deploy set the RDP listener's certificate under the W2 journal with a NETWORK SERVICE key grant; iis-restore, iis-status and iis-fence act on RDP journals; tls-probe --rdp (R69)`.

---

### Task 3: `wintest` and `cmd/alice-fakewindows`: the emulator's RDP listener

**Files:**
- Modify: `internal/providers/windows/wintest/model.go`, `write.go` (the RDP `WriteHost` methods, replacing `SetRDPThumbprint`'s bare field), `tls.go` (the RDP listener: negotiation, then TLS), `demo.go`, `write_test.go`, `wintest_test.go`; `cmd/alice-fakewindows/main.go` (the demo's RDP port in `endpoints`), `main_test.go`
- Modify: `internal/jobs/deployjobs/windows_cleanup_integration_test.go:116` (it calls `SetRDPThumbprint`, which keeps its name and now sets the listener's value)

**Interfaces:**
- Consumes: Task 2 through `winhelper.ExecuteForced`.
- Produces (new `Model` methods):
  ```go
  func (m *Model) SetRDP(l RDPConfig)          // present, enabled, port, security layer, NLA, policy template
  type RDPConfig struct{ Present, Enabled, NLA bool; Port, SecurityLayer int; CertTemplate string }
  func (m *Model) SetRDPThumbprint(sha1 string) // as before: the value ("" absent)
  func (m *Model) RDPThumbprint() string
  func (m *Model) KeyReadableByNetworkService(store, sha1 string) bool
  func (m *Model) FailKeyACL(on bool)          // the next SetRDPKeyRead fails
  func (m *Model) ServeStaleRDP(on bool)       // the listener keeps serving what it served before the last write (StaleTLS's RDP half)
  ```
  The demo host has an RDP listener on its own port: enabled, security layer 2, NLA on, value absent, one self-signed certificate in `Remote Desktop` whose key NETWORK SERVICE can read. `ctl stale-tls-on` also switches `ServeStaleRDP`. A handshake for a key NETWORK SERVICE cannot read fails (F21 modelled). Security layer 0 answers `RDPFailure(2)`.
- Mirror: W5 Task 4 (`ServeStaleCCS`, the demo, `ctl`).

- [ ] **Step 1: Write the failing tests** (`write_test.go`, over the SSH handler):
  - `TestModelRDPDeployAndServe`: `rdp-dump` over SSH shows the self-signed certificate. `rdp-deploy` of B → `tlsverify.TLSProber{RDP: true}` on the listener serves B. `iis-restore` → the value is absent and the self-signed certificate is served again.
  - `TestModelRDPNeedsKeyRead`: a value set by `SetRDPThumbprint` to a certificate whose key NETWORK SERVICE cannot read fails the handshake. After the grant it succeeds.
  - `TestModelRDPSecurityLayer`: layer 0 → the probe fails with `ErrRDPNoTLS` underneath.
  - `TestModelRDPFailKeyACL`: the deploy answers `restored` with `failed_step grant_key_read`.
  - `TestDemoHostHasRDP`: the demo's dump lists the listener; `ctl endpoints` names its port.
- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./internal/providers/windows/wintest/ ./cmd/alice-fakewindows/`
Expected: FAIL.
- [ ] **Step 3: Implement.** The listener's negotiation uses `helperproto.RDPConfirm` and `RDPFailure`. Go tests use random ports (`127.0.0.1:0`).
- [ ] **Step 4: Run the tests**
Run: `go test -race -count=1 -cover ./internal/providers/windows/wintest/ ./internal/providers/windows/winhelper/ ./cmd/alice-fakewindows/ && go test -race -count=1 -tags integration ./internal/jobs/deployjobs/ -run Cleanup`
Expected: PASS, wintest at least 90 %, fakewindows at least 90 %.
- [ ] **Step 5: Commit**: `test(wintest): the emulator's RDP listener: the negotiation, TLS with the listener's certificate, the NETWORK SERVICE key flag, the demo host's listener (R69)`.

---

### Task 4: `cmd/alice-winhelper`: the real RDP half and its runner tests **[F19, F20, F21, F22, F23]**

**Files:**
- Create (`//go:build windows`): `cmd/alice-winhelper/rdp_windows.go`, `cmd/alice-winhelper/rdp_windows_test.go`, `cmd/alice-winhelper/rdp_fidelity_windows_test.go`
- Modify: `cmd/alice-winhelper/host_windows.go` (wire the methods), `cmd/alice-winhelper/cleanup_windows.go` (`keyRDPTcp` and `valueRDPHash` move to `rdp_windows.go`; `rdpThumbprint` reads through `RDPListener`), `cmd/alice-winhelper/zz_runner_clean_windows_test.go` (the value as found, `fDenyTSConnections` and `UserAuthentication` as found, no `alice-w6-` certificate or key, no record on 45500-45519), `.github/workflows/windows.yml` (the required list), `internal/providers/windows/winproto/winproto.go` (`RDPPickupWait`, only if F20 needs it)

**Interfaces:**
- Produces (unexported):
  - `RDPListener`: `registry.OpenKey(LOCAL_MACHINE, ..., QUERY_VALUE|WOW64_64KEY)` of the policy key, the `Terminal Server` key and `RDP-Tcp`. A value that is absent takes the documented default (`SecurityLayer` 2 on 2022 and 2025 as F19 records, `UserAuthentication` 1, `fDenyTSConnections` 1). A value of the wrong type or size is an error.
  - `SetRDPCertificate`: `SetBinaryValue` (20 bytes) or `DeleteValue` on `RDP-Tcp` opened with `SET_VALUE` only.
  - `StoreCertificates`: the existing store enumeration (`stores_windows.go`) for one store, at most `limit`.
  - `RDPKeyRead` and `SetRDPKeyRead`: `acquireKey` (`cleanup_windows.go`), then `NCryptGetProperty` and `NCryptSetProperty` of `NCRYPT_SECURITY_DESCR_PROPERTY` with `DACL_SECURITY_INFORMATION`. The ACE is built with `windows.ACLFromEntries` (an `EXPLICIT_ACCESS` with `GRANT_ACCESS`, `NO_INHERITANCE`, a well-known SID from `windows.CreateWellKnownSid(WinNetworkServiceSid)`), and the descriptor with `windows.NewSecurityDescriptor`, `SetDACL` and `ToSelfRelative`. x/sys/windows only, no new module.
  - F20 route (b), only if it applies: the WMI call (coordinator first).
- Mirror: W3 Task 5 (`cleanup_windows.go`'s key access), W5 Task 5 (fixtures, fidelity, the clean check).

- [ ] **Step 1: Write the tests.** They are skipped unless `ALICE_WIN_REAL=1`. Each fixture records `fDenyTSConnections`, `UserAuthentication` and `SSLCertificateSHA1Hash` before it changes anything, and restores them in `t.Cleanup`.
  - `TestRealRDPListenerOnRunner` **[F19]**: log the values found and the policy key. Turn RDP on, then wait up to 30 s for `127.0.0.1:<port>` to answer the negotiation. Compare the served leaf (`tls-probe --rdp`) with `rdp-dump`'s certificate. Log `self_signed_count`.
  - `TestRealRDPDeployIsPickedUp` **[F20]**: `rdp-deploy` of an `alice-w6-` certificate. Poll fresh `--rdp` handshakes every 100 ms for up to 120 s until it is served, and log the delay. Log the served chain length against `built_chain_length`, and `Win32_TSGeneralSetting.SSLCertificateHash` read with PowerShell. Then `iis-restore` → the value is absent and the self-signed leaf is served again (log that delay too).
  - `TestRealRDPKeyReadForNetworkService` **[F21]** (Review Focus 1, 2): set the value with `SetRDPCertificate` on a certificate imported without the grant, and log the handshake error and Schannel events 36870 of the last minute. Grant, then log the SDDL and check that `RDPKeyRead` answers true and the handshake succeeds. Revoke → F4's SDDL byte for byte. `NCryptExportKey` is still refused.
  - `TestRealRDPNegotiation` **[F22, F23]**: the raw confirm bytes with `UserAuthentication` 1 and 0 (written by the test, restored). No 4625 event appears after ten probes with NLA on.
  - `TestRealRDPSharedWithBinding`: one `alice-w6-` certificate deployed through `iis-deploy` to an `ipport` record on `0.0.0.0:45500` and through `rdp-deploy` to the listener. Rolling back the RDP operation leaves the binding serving. `iis-cleanup --plan` keeps the certificate with reason `rdp` while the listener names it and `bound` afterwards.
  - `TestFidelityRDP`: on both hosts (the emulator configured like the runner as F19 found it), run dump, deploy, unchanged, every refusal of Task 2 that a runner can produce, then restore. The answers must be equal field by field, with messages dropped.
  - `TestRealRunnerIsClean` extended.
  - `windows.yml`: the required list adds the six tests before `TestRealRunnerIsClean`. `TestWindowsWorkflowRequiresEveryRealTest` keeps the list exact.
- [ ] **Step 2: Verify locally what can be verified**
Run: `GOOS=windows GOARCH=amd64 go build -o /dev/null ./cmd/alice-winhelper/ && GOOS=windows GOARCH=arm64 go build -o /dev/null ./cmd/alice-winhelper/ && GOOS=windows go vet ./cmd/alice-winhelper/ && GOOS=windows go vet -tags alicetest ./cmd/alice-winhelper/ && actionlint .github/workflows/windows.yml && go run ./tools/pincheck && go test -count=1 ./internal/archtest/ && make winhelper`
Expected: PASS.
- [ ] **Step 3: Run on real Windows.** Push `windows-w6`; both legs must be green. Count every run against the budget of 8. Record F19-F23 as rulings with the run links. When a fact differs, apply its "If it is wrong" column in its own fix commit, in the task that owns the code. F20 route (b) goes to the coordinator before any code.
- [ ] **Step 4: Fix** every fidelity difference in the emulator (the helper is the specification).
- [ ] **Step 5: Commit**: `feat(alice-winhelper): the RDP listener's registry value, the NETWORK SERVICE key grant and its revoke; RDP fidelity and F19-F23 on windows-2022 and windows-2025 (R69)`.

---

### Task 5: Migration `00037`, the location kind, inventory, notices and error codes **(parallel with Tasks 3-4)**

**Files:**
- Create: `migrations/00037_windows_rdp.sql`, `migrations/windows_rdp_integration_test.go`
- Modify:
  - providers: `internal/providers/groundwork.go` (`LocationWinRDP LocationKind = "win_rdp"` in `locationKinds`; `StepNameGrantKeyRead = "grant_key_read"`, `StepNameSetListener = "set_listener"`), `internal/providers/providers_test.go`;
  - inventory: `internal/inventory/deployment_records.go` (Ruling 19's sites), `internal/inventory/drift.go` (`bindingBroken`, `driftCause`, `windowsLocationMail` with `windows_note=rdp`), `internal/inventory/notify.go` (`rdpDeploymentTemplates`, `WindowsRDPTemplate`, `windowsDeploymentMail`), `internal/inventory/windows_cleanup.go:396`; their tests (`deployment_records_test.go` or the existing integration files, `notify_test.go`, `drift_test.go`);
  - `internal/notify/sender.go:234` (the `rdp` note) and its test;
  - API: `internal/api/errors.go` (`ALC-WIN-0021..0023`), `internal/api/errors_winserver_test.go`, `api/openapi.yaml` (`win_rdp` in every `location_kind` enum, the three codes, the two step names);
  - `locales/common/{en,tr}.json` (the three reasons, the three `_windows_rdp` e-mails, `email.windows_note_rdp`).

**Interfaces:**
- Consumes: Task 1 (codes, names).
- Produces: `providers.LocationWinRDP`, `providers.StepNameGrantKeyRead`, `providers.StepNameSetListener`; `inventory.WindowsRDPTemplate(template string) string` and `WindowsRDPDeploymentTemplates() []string` (render tests); `api.ErrWINRDPDisabled`, `ErrWINRDPTLSOff`, `ErrWINRDPKeyACLFailed`.
- Mirror: `00036_windows_ccs.sql` (Up, the refusing Down), W5 Task 6 (the inventory sites), `windowsCCSTemplateSuffix`.

- [ ] **Step 1: Write the failing tests**
  - `windows_rdp_integration_test.go`: Up accepts a `win_rdp` location and deployment. Down refuses with `Z1035` while one exists and succeeds after they are removed. `TestServeStartsOnAPhase3Database` (or the test that pins the latest migration) expects 37.
  - inventory:
    - `TestNewCertSHA256ForRDP`: the leaf DER's SHA-256.
    - `TestStartBackupRefForRDP`: `Remote Desktop` and the self-signed SHA-1 before the first deployment; after it, `MY` and the deployed SHA-1.
    - `TestRDPDetailsAfterDeployment`: `store` `MY`, `self_signed` false, `cert_sha1` the deployed one.
    - `TestWindowsLostIncludesRDP`.
    - `TestDriftCauseRDP`: `cert_missing` → `cert_removed`, never repaired; a re-point → `binding_repointed`.
    - `TestRDPIncidentQueuesCleanup`.
  - `notify_test.go`, `TestRDPDeploymentMail`: `rollback_failed`, `outcome_unknown` and `restored_unverified` → `_windows_rdp` with `previous_certificate` and without `backup_dir`; `failed` → `_windows` with `windows_note=rdp`. A drift of a `win_rdp` location → the Windows text with `windows_note=rdp`.
  - `internal/notify`: the `rdp` note renders in EN and TR.
  - `errors_winserver_test.go`: the three new codes with their reasons and statuses.
- [ ] **Step 2: Run them to verify they fail**
Run: `go test -count=1 -tags integration ./migrations/ ./internal/inventory/ ./internal/notify/ ./internal/api/ -run 'RDP|WindowsLost|Winserver|Migration'`
Expected: FAIL.
- [ ] **Step 3: Implement**, the OpenAPI entries included.
- [ ] **Step 4: Run the tests**
Run: `go test -race -count=1 ./internal/providers/... && go test -count=1 -tags integration ./migrations/ ./internal/inventory/ ./internal/notify/ ./internal/api/ && make i18n-check`
Expected: PASS; the OpenAPI conformance tests green; inventory at least 89 %.
- [ ] **Step 5: Commit**: `feat(inventory): the win_rdp location kind, its rollback info, drift causes, incident cleanup and Remote Desktop e-mail texts; migration 00037 (R69)`.

---

### Task 6: Windows provider: RDP discovery, deployment and verification; engine tests on the emulator

**Files:**
- Create: `internal/providers/windows/rdp.go`, `internal/providers/windows/rdp_test.go`, `internal/jobs/deployjobs/windows_rdp_integration_test.go`
- Modify:
  - provider: `discover.go` (the third call, Ruling 18), `deploycert.go` (the `LocationWinRDP` case to `rdp-deploy`; the input built by hand as `deployInput`), `verify.go` (`Endpoints` for `win_rdp`; the RDP prober and the `--rdp` server probe in `VerifyDeployment`), `provider.go` (`Options.RDPProber`, nil = `tlsverify.TLSProber{RDP: true}`; `rdpReady()`; `verifyAttempts` for `win_rdp`), `errors.go` (`ReasonRDPDisabled`, `ReasonRDPTLSOff`, `ReasonRDPKeyACLFailed`; `rdp-deploy`'s refusal table);
  - tests: `deploycert_test.go`, `verify_test.go`, `conformance_test.go`, `discover_test.go`;
  - engine harness: `internal/jobs/deployjobs/harness_integration_test.go` (`winProber` gains the RDP mode, passed as `RDPProber`).

**Interfaces:**
- Consumes: Tasks 1, 3, 5.
- Produces:
  - `func convertRDP(r winproto.RDPDumpResponse) ([]providers.DiscoveredCertificate, []providers.Warning)` (Rulings 3-5). Its `FileSHA256` is the current leaf DER's SHA-256, and its `PEMChain` the leaf and chain, re-parsed as `certificateChain` does.
  - `func rdpEndpoints(loc providers.CertLocation, v providers.VerifyOptions, sans []string) []tlsverify.Endpoint` (Ruling 16).
  - `func (s *session) rdpReady() error` (`windows.helper_outdated`, `required_version 1.2.0`); `func (s *session) rdpServerProbe(ctx context.Context, ep tlsverify.Endpoint, keyType string) (tlsverify.Served, bool, error)` (`serverProbe` with `--rdp`).
- Mirror: `deploycert.go`'s whole flow (`runWrite`, `d.answer`, the inline rollback), `ccs.go` (`discoverCCS`, `ccsReady`), W5 Task 7's tests.

- [ ] **Step 1: Write the failing tests**
  - `rdp_test.go` (over SSH with `wintest.NewServer`):
    - `TestRDPNeedsHelper120` (Review Focus 5): a model answering `1.1.0` → `Discover` sends `version`, `iis-dump`, `ccs-dump` as in W5, and no `rdp-dump`, and carries `win_rdp_helper_outdated`. A deployment to a `win_rdp` location → `windows.helper_outdated` `required_version 1.2.0`, and only `version` was sent. Its verification sends no `tls-probe --rdp`.
    - `TestDiscoverWithoutRDPIsW5`: `RDP-Tcp` absent → the binding and CCS locations are unchanged, and there is no `win_rdp` location and no warning.
    - `TestConvertRDP` table (Review Focus 3):
      - absent value with one self-signed → deployable, `self_signed`, token = its leaf;
      - 0 or 2 self-signed → `win_rdp_cert_unknown`;
      - RDP off → `win_rdp_disabled`; layer 0 → `win_rdp_no_tls`;
      - the value naming a certificate not in `My` → `cert_missing`;
      - a template → `win_rdp_autoenroll`;
      - a failed `rdp-dump` → `locations_dropped`.
    - `TestEachRDPCallUsesItsOwnConnection`.
    - `TestRDPDeployOutcomeTable`: one row per refusal code of Task 2 → its reason (`BINDING_NOT_FOUND` → `windows.binding_not_found`, `RDP_DISABLED` → `windows.rdp_disabled`, `RDP_TLS_OFF` → `windows.rdp_tls_off`, error class `key_acl` → `windows.rdp_key_acl_failed`), plus committed, unchanged, restored and uncertain (`OUTCOME_UNKNOWN`). Every return passes `providers.CheckDeployReturn`.
    - `TestRDPInputHasNoLocator`: the JSON sent holds exactly Ruling 8's members, and the command line is `rdp-deploy --op <id>`.
  - `verify_test.go`:
    - `TestRDPEndpoints`: one endpoint, the locator's port, SNI from the SANs, `Addr` `127.0.0.1`, `Listen` ""; the Administrator's port and SNI replace them.
    - `TestRDPVerifyFallsBackToTheHelper` (Review Focus 4): Alice's RDP prober unreachable → `tls-probe ... --rdp` is sent and decides.
  - `windows_rdp_integration_test.go` (the engine on the emulator):
    - `TestWindowsRDPFirstDeployAndRollback` (Review Focus 3): over the self-signed certificate → committed, level 2 with a private CA. With `ServeStaleRDP(true)` → `rolled_back`, the value absent again, the key's ACE removed, `verify_old` passes.
    - `TestWindowsRDPManualDeploy`: level 3 with a public chain; `win.chain_differs` when the built chain differs.
    - `TestWindowsRDPGuardForbids`: `rollback_failed`, `deployment.rollback_forbidden`.
    - `TestWindowsRDPCrashTable`: a kill at each point of Task 2, then the engine's recovery.
    - `TestWindowsRDPACMEAndKeyVault`: automatic deployment reaches the listener.
    - `TestWindowsRDPDriftRepaired`: a third party re-points the listener → drifted → `auto` repairs.
    - `TestWindowsRDPDisabledRefuses`: `ALC-WIN-0021`, the listener untouched.
    - `TestWindowsRDPKeyACLFails`: `FailKeyACL(true)` → `failed` with `windows.rdp_key_acl_failed` (the helper answered `restored` before any listener write), the listener untouched.
    - `TestWindowsRDPSharedCertificateCleanup`: the same certificate on a binding and RDP; after the RDP deployment is replaced, `windows.cleanup` keeps it while the binding names it.
- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./internal/providers/windows/ -run 'RDP' && go test -tags integration ./internal/jobs/deployjobs/ -run RDP`
Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the tests**
Run: `go test -race -count=1 -cover ./internal/providers/windows/... ./internal/providers/tlsverify/ && go test -race -count=1 -tags integration ./internal/jobs/deployjobs/ ./internal/jobs/driftjobs/ ./internal/jobs/winjobs/`
Expected: PASS, windows at least 95 %; every W2-W5 engine test unchanged.
- [ ] **Step 5: Commit**: `feat(providers/windows): the Remote Desktop listener discovered, deployed by rdp-deploy and verified after the RDP negotiation, from Alice or the helper (R69)`.

---

### Task 7: Web, e2e and documents

**Files:**
- Create: `web/e2e/windows-rdp.spec.ts`
- Modify (web):
  - `web/src/api/types.ts` (`LocationKind` gains `win_rdp`), `web/src/api/enums.ts` (the three reasons, the two steps, the unsupported reasons and warnings), `web/src/api/warnings.ts`, `web/src/api/deployments.ts` (`isRDPDeployment` by `location_kind`);
  - `web/src/components/DeploymentSteps.tsx` (`RDP_GROUPS`: `import_chain`, `import_certificate`, `grant_key_read`, `set_listener`, `verify`), `web/src/components/WebsitesPanel.tsx` (a "Remote Desktop" row: the listener, the port, NLA, "Self-signed by Windows", the reasons and the warning), `web/src/components/DeployDialog.tsx` (an RDP location is picked like a binding; the summary names the listener), `web/src/components/acme/AcmeBindingsPanel.tsx` (an RDP location is spoken of as the Remote Desktop listener);
  - `web/src/locales/{en,tr}.json`, `web/src/test/fixtures.ts`; tests `WebsitesPanel.test.tsx`, `DeploymentSteps.test.tsx`, `DeployDialog.test.tsx`.
- Modify (decision, design, specifications, guides):
  - `docs/superpowers/rulings/windows-iis.md`: the heading "W6 (R69)" with the rulings as built, the F19-F23 verdicts, the runner-run table, the security review, acceptance, owner items, and "Deferred to W7+" (Ruling 28's list moved on).
  - `docs/superpowers/specs/alice-v1/00-decisions.md`: R69 after R68.
  - `docs/superpowers/specs/2026-10-21-windows-iis-target-design.md`: §13 W6 "built, R69, §21"; the F19-F23 rows of §14; "§21 Phase W6 as built".
  - `docs/superpowers/specs/alice-v1/03-integrations.md`: §13A.18-13A.19 (the RDP location and discovery; `rdp-deploy`, the key grant, the probe and the rollback).
  - `04-security.md` §14.4: `WN-23`..`WN-25`.
  - `06-quality.md` §24.7: the rows below. `test/matrix/traceability.json` and `docs/security/traceability.md` (regenerated).
  - `CHANGELOG.md` ("Unreleased").
  - `docs/admin-guide.md` ("Windows servers": Remote Desktop).
  - `docs/windows-host-preparation.md`: RDP's prerequisites (on, security layer not RDP, port 3389 from Alice or the helper's probe, the NETWORK SERVICE grant, event 1005, F23's verdict, the autoenrolment warning). Update `:224` (W3's read-only sentence).
  - `docs/troubleshooting.md`: ALC-WIN-0021..0023 and "Remote Desktop no longer connects after a deployment".

**Interfaces:**
- Consumes: Task 5's names, Task 6's locations.
- Mirror: W5 Task 8 (`CCS_GROUPS`, `isCCSDeployment`, the CCS rows), W5 Task 9 (the documents).

| ID | Case | Tests |
|---|---|---|
| WIN-56 | The RDP listener is discovered with its effective settings; absent value = the self-signed certificate; off, no TLS, unknown self-signed, a 1.1.0 helper | `internal/providers/windows:TestConvertRDP`, `TestRDPNeedsHelper120`, `TestDiscoverWithoutRDPIsW5`, `winhelper:TestRDPDump` |
| WIN-57 | `rdp-deploy` imports, grants, sets the value; compare-and-swap, unchanged, every refusal before a write; no locator in the input | `winhelper:TestRDPDeployCommits`, `TestRDPDeployUnchanged`, `TestRDPDeployRefusesBeforeAnyWrite`, `TestRDPDeployInputHasNoLocator` |
| WIN-58 | The NETWORK SERVICE grant: the listener's key only, revoked by every restore of its operation only | `winhelper:TestRDPGrantOnlyTheListenersKey`, `TestRDPRestoreRevokesOnlyItsGrant`, `TestRDPGrantFails`, `deployjobs:TestWindowsRDPKeyACLFails` |
| WIN-59 | The RDP probe: negotiation, TLS, never CredSSP; Alice's probe or the helper's | `helperproto:TestRDPNegotiate`, `tlsverify:TestTLSProberRDP`, `winhelper:TestTLSProbeRDP`, `windows:TestRDPEndpoints`, `TestRDPVerifyFallsBackToTheHelper` |
| WIN-60 | A first deployment over the self-signed certificate and its rollback; the guard forbids; manual, ACME and Key Vault | `deployjobs:TestWindowsRDPFirstDeployAndRollback`, `TestWindowsRDPManualDeploy`, `TestWindowsRDPGuardForbids`, `TestWindowsRDPACMEAndKeyVault` |
| WIN-61 | A kill at every journal point recovers; restore rules | `winhelper:TestRDPKillAtEveryPoint`, `TestRDPRestoreRules`, `deployjobs:TestWindowsRDPCrashTable` |
| WIN-62 | Drift of the listener and its repair; RDP off refuses; cleanup keeps a certificate the listener or a binding names; the RDP e-mails | `deployjobs:TestWindowsRDPDriftRepaired`, `TestWindowsRDPDisabledRefuses`, `TestWindowsRDPSharedCertificateCleanup`, `inventory:TestRDPDeploymentMail`, `TestDriftCauseRDP` |
| WIN-63 | Helper 1.2.0 on real Windows: the emulator matches; F19-F23; the runner is left clean | `cmd/alice-winhelper:TestFidelityRDP`, `TestRealRDPListenerOnRunner`, `TestRealRDPDeployIsPickedUp`, `TestRealRDPKeyReadForNetworkService`, `TestRealRDPNegotiation`, `TestRealRDPSharedWithBinding`, `TestRealRunnerIsClean`, `winproto:TestReleasedHelperVersion` |
| WIN-64 | The RDP journey in the browser, in English and Turkish | `web/e2e/windows-rdp.spec.ts` |

R69's text names:
- the kind, the locator and the self-signed rule;
- `rdp-dump`, `rdp-deploy`, the reused restore, status and fence, `tls-probe --rdp`, and helper 1.2.0 with `RDPMinVersion`;
- the transaction, the exact grant and its revoke, the rollback to the self-signed certificate;
- the probe mode;
- `ALC-WIN-0021..0023`, `WIN-56..64`, `WN-23..25`, and migration `00037`.

- [ ] **Step 1: Write the failing tests**
  - `WebsitesPanel.test.tsx`: the RDP row shows "Remote Desktop (RDP-Tcp)", its port, NLA and "Self-signed by Windows"; `win_rdp_disabled` shows its text and no deploy action; `win_rdp_autoenroll` shows its warning; binding and CCS rows unchanged.
  - `DeploymentSteps.test.tsx`: a `win_rdp` deployment shows import chain, import certificate, grant key read, set listener, verify; the `rdp_key_acl_left` param shows its note.
  - `DeployDialog.test.tsx`: the RDP location is offered with the listener's summary.
  - `windows-rdp.spec.ts` (Ruling 25), in EN and TR.
  - `06-quality.md`: the rows above.
- [ ] **Step 2: Run them to verify they fail**
Run: `cd web && npx vitest run src/components/WebsitesPanel.test.tsx src/components/DeploymentSteps.test.tsx src/components/DeployDialog.test.tsx; cd .. && make matrix-check MATRIXCHECK_FLAGS=-strict`
Expected: FAIL (the components; 9 matrix gaps).
- [ ] **Step 3: Implement** the UI with EN and TR help texts: what the listener is, that Windows' self-signed certificate is replaced, that NETWORK SERVICE gets read access to the new key, and that a rollback goes back to the previous certificate. Then write the documents and `traceability.json`, and regenerate: `go run ./tools/matrixcheck -spec docs/superpowers/specs/alice-v1/06-quality.md -map test/matrix/traceability.json -doc docs/security/traceability.md -update`.
- [ ] **Step 4: Run the tests**
Run: `cd web && npx vitest run && npx tsc --noEmit && npm run lint && cd .. && make i18n-check && make web-coverage && make matrix-check MATRIXCHECK_FLAGS=-strict && make docs-check && E2E_PROJECT=alice-e2e-w6 ALICE_E2E_PORT=9983 make e2e-up && E2E_PROJECT=alice-e2e-w6 ALICE_E2E_PORT=9983 make e2e; E2E_PROJECT=alice-e2e-w6 make e2e-down`
Expected: PASS; 0 gaps, 0 pending; the whole e2e suite green.
- [ ] **Step 5: Commit** (two commits): `feat(web): the Remote Desktop listener of a Windows server, its deployment steps; English and Turkish (R69)` and `docs: Windows servers phase W6 (R69): decision, rulings, design as built, security and quality amendments, WIN-56..WIN-64, admin and host guides, changelog`.

---

### Task 8: Final gates

**Files:** none new. Fixes go to the task that owns the code.

- [ ] **Step 1: Full local gates**
Run: `make lint && make test && make i18n-check && make matrix-check MATRIXCHECK_FLAGS=-strict && make docs-check && make helper winhelper && make build && make coverage`
Expected: PASS. Every floor is met and none was lowered.
- [ ] **Step 2: Windows build and vet**
Run: the Windows line of "Verification commands".
Expected: PASS.
- [ ] **Step 3: e2e and image.** Only when no other `make ci` or Docker-based run is active on the machine: `E2E_PROJECT=alice-e2e-w6 ALICE_E2E_PORT=9983 make ci`. Otherwise run Task 7's e2e when the machine frees and list `make ci` as pending in the acceptance report.
Expected: PASS; the e2e totals are recorded.
- [ ] **Step 4: Real Windows.** The `windows.yml` run of the branch's code head is green on windows-2022 and windows-2025 with `windows-required` green (runs counted, at most 8). If it cannot be, the rulings file lists it as an owner item and the acceptance report says it is pending.
- [ ] **Step 5: gitleaks** over the whole range `7432cfd5..HEAD` (export with `git log -p`, scan in `dir` mode with `.gitleaks.toml`, as W5 did: `make ci`'s own step scans no commits in a worktree). Fingerprint any finding in `.gitleaksignore` without key material.
- [ ] **Step 6: The key-ACL security review (Ruling 27)**, then the independent review of `7432cfd5..HEAD` against Review Focus 1-5 and Rulings 4, 9-16. Both are made by reviewers that did not write the code. Fix or decline every finding with a reason in the rulings file ("Security review (W6)", "Final review fixes (W6)").
- [ ] **Step 7: Acceptance check against design §13 W6**, one line each in the rulings file:
  - location kind `win_rdp` for the RDP-Tcp listener (Tasks 5-6);
  - import as in §6.3 (Task 2, W2's code);
  - read on the key granted to NETWORK SERVICE (Tasks 2, 4; F21);
  - the listener's hash set, `SSLCertificateSHA1Hash` (Tasks 2, 4; F20);
  - verified by a TLS handshake on 3389 after the RDP security-layer negotiation (Tasks 1, 6; F22, F23);
  - the key ACL's own review (Ruling 27).

  Hand the branch `windows-w6` to the coordinator. Do not merge or push `main`.

---

## Execution notes for the implementer

- Commit this plan first (`git add -- docs/superpowers/plans/2026-10-28-windows-w6-rdp.md`, subject `docs: Windows servers phase W6 (Remote Desktop) plan (R69)`).
- **Dispatch order:** 1 → 2 → (3 ∥ 4 ∥ 5: disjoint files `wintest` + `cmd/alice-fakewindows`, `cmd/alice-winhelper` + `windows.yml`, `migrations` + `internal/inventory` + `internal/notify` + `internal/api` + `internal/providers/groundwork.go`) → 6 → 7 → 8. Task 4's `TestFidelityRDP` needs Task 3's emulator; run it after Task 3 is in.
- **Runner runs:**
  - Push for run 1 right after Task 2 with Task 4's F19-F23 tests (the fidelity test may fail then), so the facts are known before Task 6 sets `RDPPickupWait` and before the grant mask is final.
  - Run 2 after Task 4's fixes. Run 3 after Task 6. Run 4 after the final review's fixes.
  - That leaves 4 runs spare.
- **Review gates:** after Tasks 2, 4, 5 and 6, a review against Review Focus 1-5 before the next dependent task. Task 2's review includes Ruling 27's checklist. Every finding is fixed in the task that owns the code, with its own commit.
- Record every ruling made during execution in `docs/superpowers/rulings/windows-iis.md` under "W6 (R69)", one line each: the ruling, then why.
- Commit with `git -c user.name="Eren Altan" -c user.email="erenaltan@gmail.com" commit --only ...` and the trailer `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`. Subjects end with `(R69)`.

## Left for later phases

- **W6+ (deferred by this plan):** listeners other than `RDP-Tcp`; RD Gateway, RD Web Access, Connection Broker and RemoteApp certificates; changing RDP settings; revoking the NETWORK SERVICE ACE on a third party's certificate after a later deployment replaced it (Ruling 10).
- **W7, on demand:** the WinRM transport.
- **Carried unchanged** (Ruling 28): W5's deferred items, the "Carried from W2-W4" items and the minors deferred during W5, `drift_observe.go:151` among them.

## Owner to confirm

1. **Ruling 3:** only the `RDP-Tcp` listener is managed, one location per server; other WinStations, RD Gateway and the other RDS roles are not.
2. **Ruling 4:** an absent `SSLCertificateSHA1Hash` is a deployable location whose current certificate is Windows' self-signed one from `LocalMachine\Remote Desktop`; with none or several there, the location is not deployable (`win_rdp_cert_unknown`).
3. **Ruling 5:** RDP off or RDP security (no TLS) makes the location not deployable; Alice never turns RDP on or changes its security layer. An RDP autoenrolment policy is a warning, not a refusal.
4. **Ruling 6:** RDP certificates are always imported into `LocalMachine\My`.
5. **Ruling 10:** the exact grant. One access-allowed ACE for NETWORK SERVICE, `GENERIC_READ` (or the mask F21 measures), on the RDP certificate's key only, revoked by every rollback of the operation that added it, removed with the key by cleanup. It is not revoked when a later deployment replaces the certificate, so a third party's certificate keeps it.
6. **Ruling 11:** a rollback of a first deployment deletes the value, and RDP goes back to its self-signed certificate (Windows makes a new one if it was removed).
7. **Ruling 2:** restore, status and fence of RDP operations reuse the `iis-*` subcommands by journal kind; `tls-probe` gains `--rdp`.
8. **Ruling 20:** three RDP e-mail texts of their own; every other RDP e-mail is the Windows text with an RDP note.
9. **Ruling 26:** the runner tests turn RDP on (`fDenyTSConnections`) and toggle NLA on the hosted runners, and restore both. They never change the port or the security layer.
10. **The F19-F23 verdicts** once measured, especially F20 if a raw registry write is not picked up (the WMI route adds about one task) and F21 if the grant turns out not to be needed.
11. **Ruling 2's warning:** every Windows server with a helper below 1.2.0 shows `win_rdp_helper_outdated` until its helper is updated (the W4 "update the helpers first, then Alice" step applies).

## Self-review notes (for the executor)

- **Spec coverage:**
  - §13 W6 "location kind `win_rdp` (the RDP-Tcp listener)": Rulings 1, 3, Tasks 5-6.
  - "import as in §6.3": Ruling 9 step 5, Task 2.
  - "grant read on the key to `NETWORK SERVICE`": Rulings 10-13, Tasks 2, 4 (F21).
  - "set the listener's hash (`SSLCertificateSHA1Hash`, Q8)": Ruling 9 step 7, Task 4 (F20).
  - "verify by a TLS handshake on 3389 after the RDP security layer negotiation (new probe mode)": Rulings 15-17, Tasks 1, 6 (F22, F23).
  - "Key ACLs ... their own review": Ruling 27, Task 8 step 6.
  - §6.6 drift: Ruling 21. §6.7 cleanup: Ruling 7. §8 one connection per call: `TestEachRDPCallUsesItsOwnConnection`. §13 interactions: Ruling 22. F12: Rulings 4, 26.
- **Names used across tasks:**
  - `helperproto`: `RDPProtocol*`, `MaxRDPConfirm`, `RDPConnectionRequest`, `ErrRDPNoTLS`, `ErrRDPNegotiation`, `RDPNegotiate`, `RDPConfirm`, `RDPFailure`.
  - `tlsverify`: `TLSProber.RDP`.
  - `winproto`: `Version`, `RDPMinVersion`, `SubRDPDump`, `SubRDPDeploy`, `ArgRDP`, `CodeRDPDisabled`, `CodeRDPTLSOff`, `StepGrantKeyRead`, `StepSetListener`, `ErrKeyACL`, `JournalKindRDP`, `LocatorRDP`, `RDPListenerName`, `RDPCanonical`, `RDPStoreSelfSigned`, `RDPPickupWait`, `UnsupportedRDP*`, `WarnRDP*`, `RDPDumpResponse`, `RDPDeployInput`.
  - `winhelper`: `WriteHost.RDPListener/SetRDPCertificate/StoreCertificates/RDPKeyRead/SetRDPKeyRead`, `RDPListener`, `cmdRDPDump`, `cmdRDPDeploy`, `rdpJournal`.
  - `wintest`: `Model.SetRDP/SetRDPThumbprint/RDPThumbprint/KeyReadableByNetworkService/FailKeyACL/ServeStaleRDP`, `RDPConfig`.
  - `providers`: `LocationWinRDP`, `StepNameGrantKeyRead`, `StepNameSetListener`.
  - `inventory`: `WindowsRDPTemplate`, `WindowsRDPDeploymentTemplates`.
  - `windows`: `convertRDP`, `rdpEndpoints`, `rdpReady`, `rdpServerProbe`, `Options.RDPProber`, `ReasonRDP*`.
  - web: `RDP_GROUPS`, `isRDPDeployment`.
