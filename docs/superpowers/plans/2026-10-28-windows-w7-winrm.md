# Windows Servers, Phase W7 (WinRM transport) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **The design's own caution (§4.2, §13 W7, §15 Q1).** WinRM is built **only on customer demand** (a customer that refuses sshd on Windows). OpenSSH with a forced command stays the recommended transport and the default. **Under WinRM the account is not limited to the helper**: WinRS gives whoever holds the account's username and password a full shell of an administrator account, and only PSRP with a JEA endpoint could limit it, which this phase does not build. The password is also an ordinary Windows password: it signs in to any network service of the server that accepts the account, not only WinRM. The owner accepted this residual as competitor parity (WN-26, R71; Keyfactor, Venafi and AppViewX all sign in to IIS servers over WinRM with a stored administrator password). The security analysis (Ruling 21, WN-26) says so in those words, and the UI and the guides say it where the transport is chosen.

**Goal:** A Windows server target can use WinRM over HTTPS instead of OpenSSH. Alice runs the same `alice-helper.exe`, with the same protocol, subcommands, journal, fence and rollback guard, through WinRS. It signs in with the target's username and a password an Administrator sets in Alice (NTLMv2 only, over TLS 1.2 or later to port 5986), pins the listener's certificate by its SubjectPublicKeyInfo, and refuses Basic, unencrypted HTTP on 5985, redirects and proxies by construction. Kerberos, CredSSP, client-certificate mapping and PSRP are not implemented.

**Architecture:** One provider, one helper protocol, one fresh connection per helper call. The Windows provider sends every helper call through one seam, `session.run`. Today three sites call `Pool.AcquireFresh` and `Conn.Run` (`provider.go:221-245`, `deploy.go:201-215`, `verify.go:177-200`). Under `transport: winrm`, `session.run` runs the same `linuxssh.HelperCommand` (built by the same `cmd()` and the one audited constructor `linuxssh.ForcedCommand`) through a new package `internal/providers/windows/winrs`, an in-house WS-Management WinRS client over `net/http`, `encoding/xml` and `crypto/tls`. Authentication is NTLMv2 through one small module, `github.com/Azure/go-ntlmssp` v0.1.1 (already in the module graph through go-ldap): its `Negotiator` wraps the call's TLS transport and turns the request's credentials into the Negotiate/NTLM exchange; Basic is never sent (Ruling 28). Each call is one TLS connection and one WinRS shell: Create, Command, Send (stdin), Receive, Signal (only on a timeout), Delete. The connection is authenticated once (NTLM is connection-bound on Windows) and closed when the call ends. The command line is a constant, `"C:\Program Files\Alice\alice-helper.exe" ssh`, run without `cmd.exe`. The helper's subcommand line reaches the helper in the shell's environment variable `SSH_ORIGINAL_COMMAND`, so the helper takes its existing forced-command path byte for byte (Ruling 4). Key material travels only in Send. The server's identity is checked by the existing `tlspin.Verifier` (R59 G2, `host_keys` key type `tls-spki`), so the confirm flow and `host_key_changed` apply unchanged. The password is a sealed, append-only credential of the target (migration `00038`), set by an Administrator with a fresh step-up through `PUT /api/v1/targets/{id}/winrm-password`, exactly as W5's CCS password. A WinRM setup script prepares the account and the listener. The emulator `wintest` gains a WinRM HTTPS listener that speaks the same WS-Man subset and verifies NTLMv2 server-side, so the provider tests, the engine tests and the e2e journey run without Windows. **The helper does not change: it stays `1.2.0`** (Ruling 4).

**Tech Stack:** Go 1.27.3 (`net/http`, `encoding/xml`, `crypto/tls`, `crypto/x509`; `github.com/Azure/go-ntlmssp` v0.1.1, `golang.org/x/crypto/ssh`, `golang.org/x/crypto/md4` (the emulator only), `golang.org/x/sys/windows`, pgx/v5, testcontainers), PostgreSQL, React 18 + Mantine + TanStack Query + i18next, Vitest, Playwright, GitHub Actions `windows-2022` / `windows-2025` runners. **One module becomes direct, none is added:** `go-ntlmssp` moves from `// indirect` to the direct `require` block; `go.sum` does not change (Ruling 29).

**Spec:** `docs/superpowers/specs/2026-10-21-windows-iis-target-design.md`. This phase is §13 "Phase W7". It also draws on:
- §4.1 (the options table: authentication, server identity, "Limiting what Alice can run", "Secrets in Windows logs");
- §4.2 (the W7 paragraph: the helper and its protocol do not change; WinRS; the listener's certificate pinned by SPKI; Basic and unencrypted HTTP refused; the account not limited to the helper). R71 amends §4.2's authentication from client-certificate mapping to username and password over NTLMv2 (owner delegation, see [Owner decisions and items still to confirm](#owner-decisions-and-items-still-to-confirm));
- §4.3 (the account and its deny rights); §6.1 (the setup script); §8 (one fresh connection per helper call, `SSH_ORIGINAL_COMMAND`); §9 (security analysis);
- §14 F3 (`LocalAccountTokenFilterPolicy` 1 on both images), F8 (the WinRM HTTPS listener on both images: `0.0.0.0:5986`, appid `{afebb9ad-9b97-4a91-9ab5-daf4d59122f6}`, self-signed certificate) and F12 (`WSMAN\Listener\*+HTTPS` `certThumbprint` equals the `0.0.0.0:5986` record's hash);
- §15 Q1; §16-§21 (W1-W6 as built); W5's CCS password (`internal/inventory/ccs_password.go`, `00036_windows_ccs.sql`, `internal/api/targets_handlers.go:162-191`, `web/src/components/CCSPasswordPanel.tsx`), which the WinRM password copies.

Rulings and the "Deferred to W7+" list are in `docs/superpowers/rulings/windows-iis.md` (line 2812). The R70 plan `docs/superpowers/plans/2026-10-28-fixes-batch-3.md` (branch `fixes-3`) is merged into `main` (`9b856c88`); this plan does not repeat its items, and Task 0 checks that `main` holds R70 when the implementer starts. The shared TLS pinning is `internal/providers/tlspin/tlspin.go` (its package comment names "later a WinRM listener"), with `providers.TLSIdentity`, `ValidTLSIdentity` and `HostKeyTypeTLSSPKI` (`internal/providers/groundwork.go:388-406`) and inventory's `hostKeyStore` (`internal/inventory/hostkeys.go:52-104`, which already accepts `tls-spki`). The format models are `docs/superpowers/plans/2026-10-28-windows-w6-rdp.md` and `2026-10-27-windows-w5-ccs.md`. The owner approved W7 on 2026-10-28 and on 2026-10-29 delegated its open decisions to competitor parity; the decisions and the items the owner still confirms are under [Owner decisions and items still to confirm](#owner-decisions-and-items-still-to-confirm).

**Scope:**
- In scope: design §13 W7, as amended by R71. That covers:
  - the transport choice on the Windows target, and the WinRM password credential (set, changed, never read back);
  - the WinRS client with NTLMv2 and its refusals, and SPKI pinning with the existing confirm flow;
  - local accounts (`alice`, `.\alice`, `HOST\alice`) and domain accounts (`DOMAIN\alice`) over NTLM;
  - the WinRM setup script and the emulator's WinRM listener with a server-side NTLMv2 check;
  - the UI, the security analysis update (§9, STRIDE `WN-26`..`WN-30`), the real-runner facts F24-F32 and the documents;
  - a dedicated security review of the transport (Ruling 26).
- Not in scope (deferred, Ruling 27):
  - PSRP and JEA (the account stays unrestricted under WinRM, Ruling 21);
  - Kerberos, CredSSP and client-certificate mapping; UPN usernames (`alice@corp.example`);
  - NTLM channel binding (Extended Protection, `CbtHardeningLevel` Strict; Ruling 31);
  - tlspin's CA-bundle mode for a WinRM listener (pin only, Ruling 9);
  - Alice rotating the Windows password itself; removing a WinRM password; changing the transport of an existing target (Ruling 3);
  - deploying to the WinRM listener's own binding (Ruling 11);
  - the items carried in "Deferred to W7+" (Ruling 27).
- Refused by construction (never built): Basic authentication, HTTP on 5985, `AllowUnencrypted`, redirects, proxies.

**Decision:** R71 "Windows server target, phase W7: WinRM transport" (R70 is the last entry of `docs/superpowers/specs/alice-v1/00-decisions.md`). **Size:** L, 10 tasks (8 code tasks, documents, final gates; about 11-13 implementer hours plus runner waits). **Migration:** `00038` (Ruling 5).

## Before you start: facts to measure on a runner

Nine facts are new. Task 4's real tests measure F24-F31 with the `winrs` client before the provider code that depends on them is called done. Task 7 measures F32 with the setup script. Record each verdict, with its run link, as a ruling under the "W7 (R71)" heading of `docs/superpowers/rulings/windows-iis.md`, and as a row F24-F32 of design §14.

| Fact | What W7 relies on | If it is wrong | Tasks |
|---|---|---|---|
| F24 | On `windows-2022` and `windows-2025`, a local account in `Administrators` (`alice-w7`, made by the fixture with a random password that is never logged) authenticates with NTLMv2 to the image's `0.0.0.0:5986` HTTPS listener through `winrs.Client` (go-ntlmssp's `Negotiator`). `version` answers, and the helper's `win-facts` reports the token elevated with `LocalAccountTokenFilterPolicy` as the image ships it (1, F3). The username forms `alice-w7` and `HOSTNAME\alice-w7` (the computer name) each authenticate; the form `.\alice-w7` sent raw (domain `.`) is logged pass or fail, because Alice sends it as `alice-w7` (Ruling 6). Also logged: the request count of the first request of a call (expected 3: anonymous, type 1, type 3) and of the following requests on the same connection (expected 1 each: the connection stays authenticated), and the result with `LocalAccountTokenFilterPolicy` 0 (set and restored; expected refused or not elevated, because remote UAC filters a local account's token). | (a) Policy 0 refuses or does not elevate a local account: the setup script sets `LocalAccountTokenFilterPolicy` = 1 for a local account only when it finds 0, and prints the value it found (WN-30); a domain account is not filtered and needs no change. (b) `HOSTNAME\` refused: Alice sends `HOST\` forms without the domain as well (Ruling 6 amended). (c) The connection does not stay authenticated: every request does the exchange (3 requests each); F27's cost decides the budgets. (d) The test also logs the dial count of a call (a counting `Dial`). If Windows closes the connection after the anonymous 401 (so the exchange needs a second connection), Ruling 12's dialer allows `maxDialsPerCall = 2` instead of one, and Send still goes only on the connection that authenticated; more than 2 dials is a bug. | 2, 4, 6, 7 |
| F25 | A shell created with `<rsp:Environment><rsp:Variable Name="SSH_ORIGINAL_COMMAND">version</rsp:Variable></rsp:Environment>`, then a Command `"C:\Program Files\Alice\alice-helper.exe"` with the argument `ssh` and the option `WINRS_SKIP_CMD_SHELL` TRUE, runs the helper's forced-command entry with that line. The process's command line (read from `Win32_Process` in the test) is exactly the constant line. Its parent is the WinRM host process (`winrshost.exe`), not `cmd.exe`. The test logs what Security event 4688 records when process-creation auditing with command lines is on (set and restored by the test). | The helper becomes `1.3.0` with an entry `winrs <tokens…>`, whose tokens go through `winproto.JoinCommandLine` before `Execute`. `WinRMMinVersion = "1.3.0"`, and a WinRM target refuses a helper below it (`windows.helper_outdated`). That is about one task more; the coordinator decides before Task 6. | 2, 4, 6 |
| F26 | `MaxDeployInput` (256 KiB) of stdin sent in Send chunks of `winrs.MaxSendChunk` (96 KiB) with `End="true"` on the last chunk reaches the process byte for byte. The test runs a test-only program that prints the SHA-256 of its stdin. The listener's `MaxEnvelopeSizekb` is logged (500 on the images is expected). A request above it gets a WS-Man fault, whose code is logged. | The chunk size and `winrs.MaxEnvelopeSize` are set to the measured limit minus 25 %. | 1, 2, 4 |
| F27 | The cost of one shell per call: 20 sequential `version` calls, with p50 and maximum logged (the NTLM exchange included). `MaxShellsPerUser` and the clamp on the `IdleTimeOut` Alice sends are logged. A shell left undeleted (the test skips Delete) is gone after that idle time. | Above 3 s per call at p50: the budgets of `iis-dump` and the probes are re-checked (`budgets` in `internal/providers/windows/errors.go:141-172`). A shell that is never reaped: `winrs.ShellIdleTimeout` becomes the measured minimum, and the host guide names `MaxShellsPerUser`. | 2, 4 |
| F28 | The listener's identity. The image's 5986 certificate (self-signed, its SPKI logged) is presented unchanged after a `WinRM` service restart. A test listener `Address=IP:127.0.0.1+Transport=HTTPS` on port 45520 is renewed with a new key: Alice's client fails the handshake (`tlspin.ErrIdentityRefused`) before any HTTP request, so no NTLM message is sent. Renewed with the same key: accepted. An expired listener certificate is still served and accepted (Alice checks the pin only). | A presented identity that changes on a service restart: the host guide says so, and the setup script makes its own listener certificate (Ruling 18). | 2, 4 |
| F29 | Exit codes: the helper's exits 0, 2, 3 and 4 arrive as Receive's `ExitCode`. A helper killed at an `alicetest` crash point arrives as the exit code `wintest.KilledExit` models (logged). A program path that does not exist gives a WS-Man fault at Command, whose code is logged (2, `ERROR_FILE_NOT_FOUND`, expected). | The emulator and `winrs.Fault` mapping follow the measured codes (Ruling 13's table). | 1, 3, 4 |
| F30 | What the listener offers and what Alice's client does with it. Logged: the status and `WWW-Authenticate` values of an anonymous request (expected `Negotiate` and `Basic realm="WSMAN"` when Basic is on; the image's values are recorded), the image's 5985 HTTP listener, `AllowUnencrypted`, the `Service\Auth` values (Basic, Kerberos, Negotiate, Certificate, CredSSP, `CbtHardeningLevel`) and `LmCompatibilityLevel` (absent means the OS default). Asserted: (a) with `Service\Auth\Negotiate` false and `Basic` true (both set and restored), the listener offers only Basic, and Alice's client sends exactly one request, with no `Authorization` header, then fails with `winrs.ErrAuthRefused`; (b) a wrong password fails `ErrAuthRefused` after at most three requests; (c) with `LmCompatibilityLevel` 5 (NTLMv2 only, set and restored) the call works. Logged: the result with `CbtHardeningLevel` Strict (set and restored; expected refused, because go-ntlmssp sends no channel binding). Alice never dials 5985. | (a) or (b) fails: a bug in the wrapping (Ruling 28); fixed before Task 6. (c) fails: the host guide names the setting Alice needs, and the coordinator decides. Strict accepted: the host guide says Strict works; Ruling 31 is amended. | 2, 4 |
| F31 | The account's rights and the password. With "Deny log on locally", "Deny log on through Remote Desktop Services" and `PasswordNeverExpires` set on `alice-w7` (as the setup script sets them for `alice`), the call still authenticates: they do not block a network logon. The Security 4624 event of a WinRS call is logged and asserted: logon type 3 (network), `AuthenticationPackageName` NTLM, `LmPackageName` `NTLM V2`. A wrong password is logged as 4625. Changing the account's password (`net user alice-w7 <new random>`) makes the next call with the old password fail `ErrAuthRefused`, and a call with the new password works. Also logged: the account removed from Administrators (expected `ErrAuthRefused` or an access-denied WS-Man fault), and "Deny access to this computer from the network" holding S-1-5-114 (set and restored; expected refused for a local account). | A deny right that blocks the network logon: the WinRM script leaves it out, and WN-30 says which. A non-admin answer that is a fault, not a 401: Ruling 13 maps its code to `windows.winrm_auth_refused`. | 4, 7 |
| F32 | The setup script's printed listener fingerprint (`SHA256:` + unpadded base64 of the SHA-256 of the listener certificate's SubjectPublicKeyInfo, computed in Windows PowerShell 5.1) equals `providers.TLSIdentity(...)` of the certificate Alice's client sees, for the image's RSA listener and for an ECDSA test listener on 45521. | The script prints the certificate's SHA-1 thumbprint as well. The confirm dialog's help text names `Get-ChildItem WSMan:\localhost\Listener` and says the SPKI fingerprint is compared in Alice only. | 7 |

## Global Constraints

- **Branch.**
  - Worktree branch `windows-w7`, cut from `main` **after R70 is merged** (Task 0). **The first commit of the branch is this plan** (`docs: Windows servers phase W7 (WinRM transport) plan (R71)`). The plan is never committed on `main`.
  - Never switch branches inside a task. Take `main` in with `git merge main`, never rebase.
  - The executor may push `windows-w7` (only that branch) so `.github/workflows/windows.yml` runs on the real runners. It never pushes `main`, never opens a pull request and never changes repository settings. The coordinator merges and pushes.
- **Commits.**
  - `git -c user.name="Eren Altan" -c user.email="erenaltan@gmail.com" commit --only -m "<subject> (R71)" -m "Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>" -- <paths>`. Every subject ends with `(R71)`.
  - New files: run `git add -- <path>` first. Never `git add -A` or `git add .`. Check `git status --short` before each commit.
  - Never touch `.claude/`, `.superpowers/`, the untracked PDFs, `alice-helper` (an untracked binary at the root), `docs/security/reviews/independent-audit*` or the other untracked review files.
  - `.gitleaksignore` is pinned to commit hashes, so never rebase, squash or amend a pushed commit. Never commit key material or a password. Tests generate keys and passwords at run time (`internal/testutil/pki`, `crypto/rand`).
- **Dependencies (Ruling 29).** No new module in `go.mod` or `go.sum`. Task 2 moves `github.com/Azure/go-ntlmssp v0.1.1` from the indirect block to the direct `require` block (one line moves; `go.sum` unchanged). `winrs` uses the standard library, `github.com/google/uuid` (already required), `github.com/Azure/go-ntlmssp` and `alice/internal/platform/netaddr`. Only `winrs` imports go-ntlmssp (`TestOnlyWinRSImportsNTLMSSP`). The emulator's NTLMv2 check uses `crypto/hmac`, `crypto/md5` and `golang.org/x/crypto/md4`, both already compiled into `cmd/alice` through go-ldap. `go mod tidy` leaves `go.mod` and `go.sum` as Task 2 leaves them (checked in Task 10). `go.mod` is a Windows path (`.github/windows-paths.txt:14`): Task 2's commit is pushed with the first runner run, not alone.
- **Security guards that must stay green.**
  - Connections and SSH: `TestNoCodeAcceptsAnyHostKey` (`internal/providers/linuxssh/guard_test.go`); the archtest rule that only `internal/providers/windows` and `linuxssh` call `linuxssh.ForcedCommand` (`internal/archtest/forcedcommand_test.go`). WinRM calls build their command with the same constructor.
  - Imports and pins:
    - `tools/pincheck`; `TestImportRules` and `TestAllowed` (`internal/archtest/arch_test.go`), with Task 1's new rows;
    - new in Task 2: `TestOnlyWinRSImportsNTLMSSP` and `TestNoCodeAllowsBasicAuth` (`internal/archtest/buildtags_test.go`, the `TestOnlyTheDirectoryPackageImportsTheLDAPClient` pattern);
    - `TestWindowsHelperLinksOnlyItsProtocol` (the helper links nothing new: it does not change);
    - `TestReleaseBinariesLinkNoTestPackages` (`winrs` is product code; `wintest` stays test-only).
  - Lint (`.golangci.yml`): `forbidigo` refuses `strings.ToUpper` and `time.Now` outside tests, so the emulator's NTLMv2 check upper-cases the ASCII user name with its own byte loop (the account rule is ASCII) and takes the time from the model's clock. `gosec` and `staticcheck` flag `crypto/md5` and the deprecated `x/crypto/md4` in `wintest`: each import carries `//nolint:gosec,staticcheck // NTLMv2 is defined over MD4 and HMAC-MD5 (MS-NLMP 3.3.2); test-only emulator`.
  - Build and release:
    - `TestNoWindowsReservedFileNames`;
    - `TestWindowsWorkflowWatchesEveryDependency` (`internal/providers/windows/**` already covers `winrs`; `internal/platform/**` covers `netaddr`; `go.mod` covers the module);
    - `TestWindowsWorkflowRequiresEveryRealTest`; `TestWindowsHelperBuildFlagsAgree`;
    - `make release-symcheck`; `make image-check`.
- **Protocol and helper.**
  - `winproto.Protocol = 1`, `MinProtocol = 1` and `Version = "1.2.0"` stay. No new subcommand, argument or JSON field. No `WinRMMinVersion` (Ruling 4; F25's fallback only).
  - The four tests that use `winrm-deploy` as an unknown subcommand (moved there by W6) stay valid: W7 adds no such subcommand.
  - The command line never carries key material, a password, a registry path, a SID, a store or a thumbprint (W2 Ruling 4, `winproto.ValidToken`).
  - One fresh connection per helper call (design §8): under WinRM, one TLS connection and one shell per call. Keep-alive is on **within** the call only, because Windows binds the NTLM logon to the connection: the call's `http.Transport` allows one connection (`MaxConnsPerHost` 1), its `Dial` refuses a second dial, and the transport's idle connection is closed when the call ends (Ruling 12).
- **What WinRS may carry (Rulings 4, 12; WN-26, WN-28).** Alice sends the Create, Command, Send, Receive, Signal (terminate only) and Delete actions of the `cmd` shell resource URI, nothing else. Every call uses:
  - the Command `"C:\Program Files\Alice\alice-helper.exe"` (`winproto.HelperPath`) with the one argument `ssh`;
  - one environment variable, `SSH_ORIGINAL_COMMAND`, which holds the line;
  - stdin only in Send.
  No PowerShell, no other program, no other resource URI. A unit test asserts the request set (Task 2 `TestWinRSSendsOnlyTheHelper`).
- **What the transport refuses by construction (Rulings 12, 28; WN-27).** The URL scheme is the constant `https`, the port the target's (5986 by default), and the path `/wsman`. TLS 1.2 or later. Authentication is NTLMv2 inside the Negotiate or NTLM HTTP scheme, through go-ntlmssp's `Negotiator` with `AllowBasicAuth` never set: there is no code path that sends Basic, and none for Kerberos, CredSSP or a client certificate (the TLS config may hold no certificate). Alice never dials port 5985 or speaks `http`. Redirects are refused. No proxy: `Transport.Proxy` is nil, and `HTTP(S)_PROXY` is ignored. Every dial goes through `netaddr.DialContext` (AUD-25 a). A refused logon is never retried within the call.
- **Error codes.** The existing codes are `ALC-WIN-0001..0023` (R70 adds none). New (Task 5): `ALC-WIN-0024` `windows.winrm_auth_refused` (502), `ALC-WIN-0025` `windows.winrm_password_missing` (409), `ALC-WIN-0026` `windows.winrm_fault` (502), `ALC-WIN-0027` `windows.transport_immutable` (409), `ALC-WIN-0028` `windows.winrm_password_invalid` (422; the CCS pair is `ALC-WIN-0018` 409 and `ALC-WIN-0019` 422). Other transport failures reuse the `ssh.*` reasons with the param `transport=winrm` (Ruling 13).
- **Test IDs:** `WIN-68`..`WIN-75` (R70 uses `WIN-65`..`WIN-67`). **STRIDE:** `WN-26`..`WN-30` (`WN-25` is the last). **Migration:** `00038` only; its Down's SQLSTATE is `Z1036` (the next free after 00037's `Z1035`).
- **Coverage floors** (`coverage-floors.json`; never lower one): `winproto` 100, `helperproto` 100, `tlsverify` 95, `tlspin` 97, `linuxssh` 93, `winhelper` 95, `windows` 95, `wintest` 90, `cmd/alice-fakewindows` 90, `inventory` 89, `api` 95. **New:** `alice/internal/providers/windows/winrs` at **95** (Task 1 adds the entry).
- **Locales.** EN and TR in `locales/common/{en,tr}.json` and `web/src/locales/{en,tr}.json`, with identical keys and placeholders (`make i18n-check`). Turkish never puts a suffix on a placeholder that holds a path or a host. The Turkish texts of the WN-26 caution and the password dialog are owner items (R70's pattern: the rulings file quotes the shipped Turkish texts for the owner).
- **Real-Windows runs.**
  - Budget: **10 runs** of `windows.yml` (windows-2022 and windows-2025 legs). Every run counts; record each in a runner-run table in the rulings file.
  - The image's `0.0.0.0:5986` listener is never deleted and its certificate is never changed. The tests may set `Service\Auth\Negotiate`, `Service\Auth\Basic`, `Service\Auth\CbtHardeningLevel`, `LocalAccountTokenFilterPolicy`, `LmCompatibilityLevel` and the "Deny access to this computer from the network" right, add and remove test listeners, and create and remove the account `alice-w7`. They record each value before the first change and restore it as found in `t.Cleanup`. The account's password is generated with `crypto/rand` and never logged.
  - Fixture ports **45520-45539**: 45520 is the renewal test listener (F28), 45521 the ECDSA listener (F32), 45522-45539 spare. Certificates are named `alice-w7-*`, the test account is `alice-w7`, and cleanup is registered before the fixture is made.
  - `TestRealRunnerIsClean` is extended. It checks that no `alice-w7-*` certificate is in `My` or `Root`; that no listener is on 45520-45539; that no `alice-w7` account exists; that no firewall rule `Alice WinRM` exists; and that the WinRM and LSA values above are as found.
  - PowerShell appears in tests only (W6's rule).
- **e2e.** `E2E_PROJECT=alice-e2e-w7 ALICE_E2E_PORT=9985 make e2e-up e2e; E2E_PROJECT=alice-e2e-w7 make e2e-down`; final `E2E_PROJECT=alice-e2e-w7 ALICE_E2E_PORT=9985 make ci`. Port 9985 was free at planning (`ss -ltn` shows no listener on it). Docker-based Go runs and Playwright never run at the same time, and neither runs while another `make ci` is active: check `pgrep -af 'playwright|make ci|go test'` first.
- **Verification commands.**
  - `go build ./... && go vet ./... && go vet -tags integration ./...`
  - `GOOS=windows GOARCH=amd64 go build ./cmd/alice-winhelper/ ./internal/providers/windows/... && GOOS=windows GOARCH=arm64 go build ./cmd/alice-winhelper/ && GOOS=windows go vet ./cmd/alice-winhelper/ ./internal/providers/windows/... && GOOS=windows go vet -tags alicetest ./cmd/alice-winhelper/ && GOOS=windows go test -tags alicetest -c -o /dev/null ./cmd/alice-winhelper/ && GOOS=windows go test -c -o /dev/null ./internal/providers/windows/winrs/`
  - `go test -race -count=1 ./<pkgs>`; integration (Docker): `go test -race -count=1 -tags integration ./<pkgs> -run <name>`
  - `make lint`, `make test`, `make i18n-check`, `make matrix-check MATRIXCHECK_FLAGS=-strict`, `make docs-check`; final `make coverage` and `make ci`
  - web: `cd web && npx vitest run <files> && npx tsc --noEmit && npm run lint`
  - `make helper winhelper` before the e2e (the checksums Alice embeds; `bin/` is untracked). The helper does not change, so the checksums do not either.

## Rulings (where the spec is silent; each goes into `docs/superpowers/rulings/windows-iis.md` under a new "# W7 (R71)" heading; the owner delegated them to competitor parity on 2026-10-29)

1. **The client library: an in-house WinRS subset, `internal/providers/windows/winrs`, with go-ntlmssp for NTLMSSP only (owner-delegated).**
   - Option (a), in-house plus go-ntlmssp:
     - Code: the WS-Man envelopes of six actions (`encoding/xml`), one HTTPS client with the pin (`net/http`, `crypto/tls`) wrapped in go-ntlmssp's `Negotiator`, stdin chunks, the Receive loop, bounds and faults.
     - Estimate: about 850 lines of code and 1,100 of tests. The emulator's server half (Task 3) adds about 450 lines and 400 of tests, plus its NTLMv2 check (Task 2, about 150 lines and 150 of tests).
     - Dependencies: none new. `github.com/Azure/go-ntlmssp` v0.1.1 (MIT, Microsoft) is already compiled into `cmd/alice` through go-ldap; it becomes direct (Ruling 29).
   - Option (b), `github.com/masterzen/winrm` (checked 2026-10-28):
     - It is maintained (commits up to 2026-10-04) and supports NTLM (through a newer go-ntlmssp pseudo-version), Kerberos, client certificates and CredSSP.
     - Its `go.mod` brings about ten modules Alice does not have: `jcmturner/gokrb5/v8` and five `jcmturner/*` helpers, `ChrisTrenkamp/goxpath`, `masterzen/simplexml`, `gofrs/uuid`, `hashicorp/go-uuid`.
     - That links Kerberos and CredSSP code into `alice`, which this phase does not use, adds attack surface and pins for `tools/pincheck` and Dependabot, and moves go-ntlmssp off its release tag.
     - Alice would still write the pin, the slot, the bounds and the one-shell-per-call rule around it.
   - Ruling: (a), because:
     - the repository rule is the standard library and existing code first, and go-ntlmssp is existing code in the graph;
     - a client that cannot speak Basic, Kerberos or CredSSP refuses them by construction, not by configuration (Ruling 12);
     - the subset is six fixed SOAP bodies;
     - the emulator needs a server for the same subset anyway, and the codec serves both halves.
   - Cost of (a): Alice owns WS-Man parsing (bounded, strict, Task 1). F24-F30 and `TestFidelityWinRM` (Task 7) check it against real Windows.
2. **The transport is a target setting.**
   - `config.transport` is a `FieldEnum` with the values `ssh` (default) and `winrm`, in `ConfigSchema` (`internal/providers/windows/provider.go:112-122`).
   - `port` defaults to 22 for `ssh` and to 5986 for `winrm` when absent (`ParseConfig` fills it in).
   - `ParseConfig` returns `windows.Config{linuxssh.Config; Transport string}`. The embedding keeps `cfg.Host`, `cfg.Port` and `cfg.Username`. The SSH path passes `cfg.Config` to `Pool.AcquireFresh`.
   - The config is jsonb, so the transport needs no migration. `targets_endpoint_live` (`(type, host, port)`) is unchanged.
3. **The transport is fixed when the target is created.**
   - `UpdateTarget` refuses a patch that changes `config.transport` with `inventory.ErrTransportImmutable`, which maps to `ALC-WIN-0027` `windows.transport_immutable` (409).
   - Reason: the pinned identity's type (`ssh-*` or `tls-spki`) and the credential differ by transport. A change would silently drop the pin's meaning.
   - To change transport, the Administrator adds a new target. W7 does not refuse a second live Windows target for the same host on the other transport (owner item 4).
4. **The helper does not change; the line reaches it through `SSH_ORIGINAL_COMMAND` (owner-delegated; F25).**
   - The WinRS shell is created with one environment variable, `SSH_ORIGINAL_COMMAND`, which holds the line `linuxssh.HelperCommand.Line()` gives. It is the same bytes sshd would pass: tokens of `^[A-Za-z0-9._:@+-]{1,253}$` joined by one space, at most 16 tokens and 4096 bytes.
   - The Command is `winproto.HelperPath` with the one argument `ssh`, and the options `WINRS_SKIP_CMD_SHELL` TRUE (no `cmd.exe` parses anything) and `WINRS_CONSOLEMODE_STDIN` FALSE (stdin is a pipe).
   - So the helper runs `winhelper.ExecuteForced` exactly as under sshd (`cmd/alice-winhelper/main.go`; `winhelper/write.go:331`): `winproto.SplitCommandLine` validates the line, then the subcommand's own checks run.
   - Every helper since 1.0.0 has this entry. Hence `winproto.Version` stays `1.2.0`, there is no `WinRMMinVersion`, and every `*MinVersion` rule applies unchanged (a 1.1.0 helper over WinRM still gets no RDP subcommand).
   - The fixed command line is also all that Security event 4688 can record (F25).
   - F25's fallback (helper 1.3.0 with a `winrs` entry) goes to the coordinator before Task 6, not into this plan's code.
5. **One migration, `00038`: the WinRM password is a credential of the target.**
   - `00038_windows_winrm.sql` widens the four credential CHECKs of `00036` (`credentials_purpose_check`, `credentials_kind_check`, `credentials_target_purpose`, `credentials_kind_purpose`) with purpose `win_winrm` and kind `winrm_password` (`target_id` set: the target owns it). No table and no column is added; the location CHECKs are unchanged.
   - The rows are append-only; the newest row of a target is its password (W5's CCS pattern, `00036`). They are sealed like every credential (AAD `credentials/<id>/ciphertext`; `public_info` empty).
   - `targetColumns` (`internal/inventory/targets.go:30-33`) gains one subquery after the CCS one, `(SELECT max(c.created_at) FROM credentials c WHERE c.target_id = targets.id AND c.purpose = 'win_winrm')`, scanned into `Target.WinRMPasswordSetAt`.
   - `targets.credential_id` keeps naming the platform key, unused by a WinRM target, so `targets_check_credential` (`00031`) is unchanged (owner item 5).
   - The Down restores 00036's lists. It refuses with `Z1036` while a `win_winrm` credential exists.
   - `host_keys.key_type` has no CHECK, so `tls-spki` needs nothing.
6. **The accounts and their username forms (owner-delegated).**
   - Under `transport: winrm`, `ParseConfig` accepts the existing account rule (`userRE`, `config.go:18`: an optional NetBIOS domain of at most 15 characters and a backslash, then a SAM name of at most 20) and, under `winrm` only, the form `.\<SAM name>`. Anything else is the field error `username` `pattern` (a UPN `alice@corp.example` too: deferred with Kerberos). The name is stored as typed.
   - What goes to go-ntlmssp (`req.SetBasicAuth(user, password)`; its `splitNameForAuth` takes the part before the first `\` as the NTLM domain):

     | Typed | Kind | User sent | Domain sent |
     |---|---|---|---|
     | `alice` | local | `alice` | empty (the server checks its own accounts) |
     | `.\alice` | local | `alice` (Alice strips `.\`) | empty |
     | `HOST\alice` | local (the computer name) | `alice` | `HOST` |
     | `DOMAIN\alice` | domain | `alice` | `DOMAIN` |

   - F24 measures the first three on the images; a domain account is checked syntactically only in W7 (no domain on the runners; manual matrix).
   - The account must be in `Administrators`, directly or through a group (the helper needs it; WinRM's default `RootSDDL` admits Administrators). Where "Deny access to this computer from the network" holds S-1-5-114 (hardened baselines), a local account cannot sign in over the network: use a domain account (the host guide says so).
7. **The WinRM password (owner-delegated; W5's CCS pattern exactly).**
   - Set with `PUT /api/v1/targets/{id}/winrm-password`, body `{"password": "..."}` (capped at 4 KiB, `decodeExact`), `If-Match` with the target's version required. Permission `rbac.CredentialsManage` (Administrator, fresh step-up), licence class `ClassChange`. The answer is **200 with the target** (its new version, `ETag`, and `winrm_password_set_at`), as `setCCSPassword` answers (`targets_handlers.go:167-191`); never the password, and no endpoint reads it back.
   - `inventory.Service.SetWinRMPassword(ctx, a, target, ifVersion, pw secrets.Plaintext) (Target, error)` mirrors `SetCCSPassword` (`ccs_password.go:59-102`): `pw` is zeroed on every path; the seal happens before the transaction; inside it, a target that is not a Windows server, or a Windows server with `transport` `ssh`, is `ErrNotWindowsTarget` (wrapped with the reason), then the rule, then the version; one append-only row; the target's version bumped; the audit event `target.winrm_password_set` (details: name, credential id, never the secret).
   - The rule is the CCS rule (W5 Ruling 10): 12 to 128 characters of printable ASCII without a space (0x21-0x7e). `validWinRMPassword` calls the existing `validCCSPassword`; a password outside it is `inventory.ErrWinRMPasswordInvalid` → `ALC-WIN-0028` (422). Windows' own password policy is the server's: a password Windows refuses is set by the operator on the server, not by Alice.
   - **A WinRM target can be created before its password is set** (the CCS pattern: a Windows server exists before its CCS password, `CCSPasswordSetAt` nil). Until it is set, every helper call (connection test, discovery, deployment, verification, drift, cleanup) refuses with `windows.winrm_password_missing` (`ALC-WIN-0025`, 409) before any dial, so the identity sighting also waits for the password. The target page shows the password panel with "not set".
   - Changing it is the same `PUT` again (the newest row wins). Changing `username` does not clear it. Removing it and Alice rotating the Windows password are deferred (Ruling 27).
8. **The credential source.**
   - `providers.WinRMPasswordSource` (in `groundwork.go`, next to `CCSPasswordSource`): `WinRMPassword(ctx context.Context, target uuid.UUID) (secrets.Plaintext, func(), error)`, with the sentinels `ErrNoWinRMPassword` and `ErrWinRMPasswordUnusable`, worded as `ErrNoCCSPassword` and `ErrCCSPasswordUnusable` (`groundwork.go:370-386`).
   - It is implemented by inventory's `platformCredentials` with `CCSPassword`'s query (`ccs_password.go:111-139`) and purpose `win_winrm`: the newest row of a live Windows target. A row of another type or kind is refused (`errForeignCredential` wrapping `ErrWinRMPasswordUnusable`), never opened. A key the master key cannot open is `ErrWinRMPasswordUnusable`.
   - The provider reads it per call (`s.winrmPassword`, the `s.ccsPassword` shape, `ccs.go:50-64`), passes it to `winrs` for the one call, and calls `release` (which zeroes the `Plaintext`) as soon as `Run` returns, on every path.
   - A credential source without the interface, or `ErrNoWinRMPassword`, gives `windows.winrm_password_missing` before any dial. `ErrWinRMPasswordUnusable` gives `internal.unexpected` (final), the end of `ctx` `ssh.timeout`, any other read failure `windows.io_error` (retryable): `ccsPasswordRefusal`'s table (`ccs.go:70-82`).
   - Shortcut, stated in the code: go-ntlmssp takes the password as a Go `string` (`SetBasicAuth`, then its `identity`), which cannot be zeroed. The string copy lives for the call only; the `Plaintext` is zeroed after it. Upgrade only if go-ntlmssp gains a byte-slice API.
9. **The listener is pinned by its SPKI, with the existing flow.**
   - Under WinRM, `Open` builds one `tlspin.Verifier` per session with `tlspin.Options{Target: t.ID, ServerName: cfg.Host, Store: env.HostKeys}`, in pin mode (no CA bundle in W7: it is not a one-line addition, because `ConfigSchema`, the API and the UI would all gain a bundle field; deferred). `env.HostKeys` is used only on this path; the SSH path still uses the pool's dialer.
   - Every call's TLS config is `v.TLSConfig()`, with no client certificate.
   - A handshake the verifier refuses becomes `v.Refusal(ctx, err)`: `target.host_key_unconfirmed` with the fingerprint (first contact), or `target.host_key_changed` with both (the store blocks the target). That happens before any HTTP request, so no NTLM message reaches an unpinned listener (F28).
   - The Administrator confirms or re-pins with the existing endpoints (`/api/v1/targets/{id}/host-keys/{key_id}/actions/confirm` and `.../repin`). Background work never pins (tlspin's rule).
   - `ConnectionReport.HostKey` is the presented TLS identity.
   - A customer who renews the listener certificate with the same key changes nothing. A new key blocks the target until re-pinned (host guide: how to compare with the script's printed fingerprint).
   - An expired listener certificate is accepted (only the pin is checked, F28).
10. **The transport seam.**
    - `session` gains `run func(ctx context.Context, c linuxssh.HelperCommand) (linuxssh.Result, providers.HostKey, error)`, set by `Open` from the transport: `sshRun` (today's `AcquireFresh`, `Run`, `release(false)`) or `winrmRun`.
    - The three call sites (`callIn`, `runWrite`, `probeWith`) call `s.run` and keep everything after it: `DecodeHelper`, `mapHelper`, `decodeCall`, the refusal rule. So exit codes, the helper's JSON, the write gate, the journal, the fence, the rollback guard and every outcome rule are one code path for both transports.
    - `runWrite`'s rule "everything before the command can have been sent is a refusal" becomes "an error matching `winrs.ErrNotSent`" under WinRM: the password read, dial, TLS, identity, an auth refusal, and a fault or protocol error at Create Shell. Anything after the Command request was written is uncertain.
11. **The WinRM listener's own binding is never deployable (the self-pin problem).**
    - The http.sys record `0.0.0.0:5986` with WinRM's appid stays unsupported, reason `win_foreign_app` (`internal/providers/windows/convert.go:27`, `winproto.KnownApps` `:150-155`), on both transports.
    - Reason: a deployment there would replace the identity Alice pinned mid-operation. The verification, the rollback and every later call would then fail the pin, and the target would block itself.
    - W3's cleanup keeps the listener's certificate (`winproto.KeptWinRM`, `:671`).
    - A test pins this (`TestWinRMListenerBindingStaysUnsupported`).
12. **The WinRS client's rules** (`winrs.Client.Run`):
    - The config is refused before any dial (`winrs.ErrBadConfig`) when the TLS config's `MinVersion < tls.VersionTLS12`, when it holds any client certificate (`Certificates` or `GetClientCertificate`), when `InsecureSkipVerify` is set without a `VerifyConnection`, or when the user or the password is empty.
    - One `http.Transport` per call: `ForceAttemptHTTP2` false, `Proxy` nil, `MaxConnsPerHost` 1, `MaxIdleConnsPerHost` 1, `DialTLSContext` unset (TLS by the transport with the given config), `DialContext` = the call's dialer, which runs `netaddr.DialContext` with the dial timeout once and refuses a second dial (`ErrUnreachable` with its stage), `TLSHandshakeTimeout` = `linuxssh.DefaultHandshakeTimeout`'s value. Keep-alive stays on within the call, because Windows binds the NTLM logon to the connection; `CloseIdleConnections` runs when the call ends, on every path.
    - The `http.Client` is `{Transport: ntlmssp.Negotiator{RoundTripper: transport}, CheckRedirect: refuse}` (Ruling 28). Every request carries the credentials through `req.SetBasicAuth`, which the Negotiator reads and never forwards.
    - The URL is `https://<host>:<port>/wsman` from `net.JoinHostPort`.
    - Every request has `Content-Type: application/soap+xml;charset=UTF-8`. Alice sets no other `Authorization` value. The first request of a call costs at most three round trips (anonymous, NTLM type 1, type 3; F24); a final 401 or 403 is `ErrAuthRefused`, and no request is sent after it.
    - Every response body is read through `io.LimitReader(MaxResponseBody+1)` (256 KiB). A larger one is `ErrProtocol`.
    - stdin goes in Sends of at most `MaxSendChunk` (96 KiB raw), the last with `End="true"`, and an empty end-only Send when stdin is nil. Nothing else carries it. Sends go only on the call's one connection, after it was authenticated.
    - Receive is looped with `OperationTimeout` `PT20S` until `CommandState/Done`.
    - Output limits: stdout is capped at the call's `MaxOutput`. Overflow → Signal terminate, Delete, `ErrOutputTooLarge`. stderr is capped at 64 KiB and discarded.
    - The whole call (Create to Done) runs under the command's timeout. On the timeout or `ctx` end: Signal terminate, then Delete, each with its own 5 s budget detached from `ctx`, then `ErrTimeout`.
    - Delete is sent on every path after a successful Create.
    - The shell is created with `IdleTimeOut` `PT<timeout+60s>S` (F27 may clamp it) and the `MaxEnvelopeSize` header `MaxEnvelopeSize` (153,600 bytes).
13. **Error mapping under WinRM** (`winrmError(err) error` in `internal/providers/windows/winrm.go`). Every mapped error carries the params `subcommand` and `transport=winrm`:

    | `winrs` error | Reason | Retryable | Not sent |
    |---|---|---|---|
    | `tlspin.ErrIdentityRefused` (handshake) | `v.Refusal` → `target.host_key_unconfirmed` / `target.host_key_changed` | no | yes |
    | `ErrNoWinRMPassword` / unusable / read failure | `windows.winrm_password_missing` / `internal.unexpected` / `windows.io_error` (Ruling 8) | no / no / yes | yes |
    | `netaddr.ErrNotAllowed`, dial, TLS other | `ssh.unreachable` | yes | yes |
    | `ErrAuthRefused` | `windows.winrm_auth_refused` | no | yes |
    | `*FaultError` at Create with the access-denied code (5, or what F31 measures) | `windows.winrm_auth_refused` | no | yes |
    | `*FaultError` at Create (other) | `windows.winrm_fault` (`wsman_code` decimal) | no | yes |
    | `*FaultError` at Command with code 2 (F29) | `ssh.helper_missing` (then `mapHelper` → `windows.helper_missing`) | no | no (nothing ran) |
    | `*FaultError` after Command (other) | `windows.winrm_fault` | no | no |
    | `ErrTimeout` | `ssh.timeout` | yes | no |
    | `ErrOutputTooLarge` | `ssh.output_too_large` | no | no |
    | `ErrProtocol` | `ssh.protocol_error` | no | as its stage |

    - Reusing the `ssh.*` reasons keeps every engine rule unchanged: `internal/inventory/deployment_outcome.go:80`, `internal/jobs/deployjobs/recover.go`, and the retryable flags.
    - The e-mails choose the WinRM wording through R70's reason-variant lookup in `internal/notify/sender.go` (R70 Task 4, `TestRenderReasonVariant`), variant key `transport=winrm`. If its shape does not take a second variant, Task 5 extends it in place.
    - The API problem keeps one title per code (R70's decline of API variants) and carries the param. The web shows "(WinRM)" from the param.
    - The fault's text is never kept: only the numeric code, `^[0-9]{1,10}$`. `windows.winrm_auth_refused`'s text names the three causes: the password in Alice differs from the server's, the account is not an administrator, or the server refuses NTLM (Negotiate off, `CbtHardeningLevel` Strict, an NTLM restriction policy).
14. **Slots.** A WinRM call holds one slot of the shared `linuxssh.Pool` (the global and per-target limits, `pool.go:38-75`) for its whole life. The new `func (p *Pool) Slot(ctx context.Context, target uuid.UUID) (release func(), err error)` waits like `acquire` does and refuses a forgotten target. So the per-target bound covers both transports, and `ForgetTarget` stops both.
15. **`HelperCommand` accessors.** `linuxssh.HelperCommand` gains `Input() []byte` (the command's own copy, still wiped by `WipeInput`), `Timeout() time.Duration` and `MaxOutput() int64`. `ForcedCommand` stays the only constructor of a bare command, and the archtest rule on it is unchanged. `winrmRun` passes `c.Line()`, `c.Input()`, `c.Timeout()` and `c.MaxOutput()` to `winrs`.
16. **What Windows logs under WinRM** (for §9 and the host guide; F25, F31):
    - no PowerShell runs, so script block logging (4104) and transcription see nothing;
    - Security 4688 (when process creation is audited with command lines) shows `"C:\Program Files\Alice\alice-helper.exe" ssh` only; the subcommand is in the environment, which 4688 does not record;
    - `Microsoft-Windows-WinRM/Operational` records each shell's creation and deletion and the user, never the stream contents;
    - Security 4624 records one network logon (type 3, package NTLM, `NTLM V2`) per call; a refused logon is 4625 with the account name; a domain account's logon is also checked on a domain controller (4776 there);
    - the helper's Application events 1001-1005 record the writes, as under SSH.
    Key material is in a TLS-protected Send body only; the password never leaves Alice (NTLMv2 sends a proof, not the password).
17. **Discovery, deployment, verification, rollback, drift and cleanup are unchanged.**
    - Every subcommand, its budget (`errors.go:141-172`), its input and its answer are the SSH ones.
    - Alice's own TLS probes of locations are unchanged, and the helper's `tls-probe` fallback runs over WinRS.
    - Licence classes, scoped access, incidents and canary (design §13 "Interactions") are unchanged; a WinRM target is one target (Q11).
18. **The WinRM setup script** (`windows.SetupScriptWinRM(user, from string, allowUnverified bool) (string, error)`).
    - Windows PowerShell 5.1 or PowerShell 7, run once as an administrator in the directory that holds `.\alice-helper.exe`, safe to run again. It holds no secret (Alice never embeds the password). It does, in order:
      1. Checks the helper's SHA-256 (the shared `helperCheck`). Installs the helper, the data directory with its ACL, and the event source `Alice Helper` (the fragments shared with `SetupScript`).
      2. The account `<user>`, with the SSH script's account fragment (`setup.go:350-410`: `Get-AccountSid`, the `Administrators` SID, the two deny rights of §4.3, `DONT_EXPIRE_PASSWORD`, the S-1-5-113/114 warning):
         - a **local** account that does not exist is created; the script asks the operator for its password with `Read-Host -AsSecureString`, twice, and refuses a password outside Alice's rule (Ruling 7) or two entries that differ;
         - a local account that exists (for example the one the SSH script made, whose random password nobody knows) gets the same prompt, where an empty answer keeps the current password (so a second run changes nothing);
         - a **domain** account is never created and its password never changed: the script checks that the account resolves and warns when it is not a member of `Administrators` (directly or through a group);
         - the password is never printed, logged or written to a file; the script removes its variables after `SetPassword`. The operator then enters the same password in Alice's password dialog.
         It adds the account to `Administrators` (local accounts), sets "Deny log on locally" and "Deny log on through Remote Desktop Services" (they do not block a network logon, F31), and never sets "Deny access to this computer from the network".
      3. For a local account only: reads `LocalAccountTokenFilterPolicy`; sets it to 1 when F24 (a) shows it is needed and the value found is 0 or absent, and prints the value it found (WN-30).
      4. Sets the WinRM service to start automatically. If no HTTPS listener exists, it creates a non-exportable self-signed listener certificate for the computer's DNS names, valid 10 years, and an HTTPS listener on `*:5986`. An existing HTTPS listener and its certificate are kept.
      5. Leaves `Service\Auth\Negotiate` on; when it finds it off, it stops with a message that Alice needs it (it does not change it: another tool may rely on the setting; owner item 3).
      6. Adds the firewall rule `Alice WinRM` for TCP 5986 from `$AliceAddress` (`firewallAddress(from)`, the platform key line's `from=` as the SSH script uses it).
      7. Prints the listener's SPKI fingerprint (F32) and SHA-1 thumbprint, and the values it did not change: Basic, Kerberos, CredSSP, Certificate, `CbtHardeningLevel`, `AllowUnencrypted` and the 5985 listener. It warns when Basic, `AllowUnencrypted` or the 5985 listener is enabled (Alice never uses them), and when `CbtHardeningLevel` is Strict (Alice cannot sign in then, Ruling 31).
    - It never installs or changes OpenSSH, never changes Basic, Negotiate, Kerberos, CredSSP, `CbtHardeningLevel`, `AllowUnencrypted` or the 5985 listener (it warns instead), never maps a client certificate, and never runs PowerShell remoting configuration (`Enable-PSRemoting`).
    - Coexistence with the SSH half: both scripts may run on one server, in either order. They share the helper, the data directory, the event source, the account and its rights. Setting the account's password does not affect SSH, where the account signs in by key only (`TestRealBothTransportsShareTheHelper`).
    - The SSH script's output is byte for byte unchanged by the refactor of the shared fragments (golden test).
19. **The setup endpoint.**
    - `GET /api/v1/targets/{id}/winrm-setup` answers `{script}` for a live Windows target with `transport: winrm`. Any other target gets `inventory.ErrNotWindowsTarget`, which the existing mapping (`internal/api/errors.go:883`) answers as `ALC-WIN-0011` `windows.location_unsupported` (409).
    - The RBAC permission is the target read permission (the script holds no secret).
    - A build without helper checksums answers `script` "" as `SetupSnippets` does.
20. **Emulator model** (Tasks 2-3):
    - The model's WinRM listener is the http.sys record of WinRM's appid (`0.0.0.0:5986` on the demo host). Its served certificate is that record's (F12), and it speaks HTTPS without client certificates.
    - Its account table is `Model.SetWinRMAccount(user, password string)` (one account; the domain the emulator accepts is empty, `.`, the model's computer name or the model's domain). Authentication is checked by `wintest.NTLMServer` (Task 2), connection-bound like Windows: the server's `ConnContext` gives each TLS connection its NTLM state.
      - A request without `Authorization` on an unauthenticated connection → 401 with `WWW-Authenticate: Negotiate` and `Basic realm="WSMAN"` (what F30 logs), and the body is discarded. `OfferBasicOnly()` drops `Negotiate`, for the client's refusal test.
      - Type 1 (`Negotiate` or `NTLM` scheme, signature `NTLMSSP\0`, message type 1) → 401 with a type 2: flags without `NEGOTIATE_LM_KEY` and `KEY_EXCH`, an 8-byte server challenge from `crypto/rand`, target info (NetBIOS and DNS computer and domain names, the model clock's timestamp, EOL).
      - Type 3 → it reads the UTF-16LE user and domain, refuses an NT response shorter than 48 bytes (NTLMv1 is 24), splits `NTProofStr` (16 bytes) from `temp`, checks that `temp`'s target info is the one it issued, and accepts only when `NTProofStr = HMAC-MD5(NTOWFv2, serverChallenge || temp)` with `NTOWFv2 = HMAC-MD5(MD4(UTF-16LE(password)), UTF-16LE(upper(user) || domain))`. The challenge is used once: a second type 3 on the connection, or a type 3 without a type 1 before it, is 401.
      - An accepted connection serves later requests without a new exchange, as Windows does.
      - It never accepts Basic, whatever the request carries.
      - Size: about 150 lines and 150 of tests (`ntlm.go`, `ntlm_test.go`), including MS-NLMP §4.2.4's NTLMv2 test vector (user `User`, domain `Domain`, password `Password`, server challenge `0123456789abcdef`).
    - Shells: a shell holds its environment. Command must be `winproto.HelperPath` with `ssh`, or the fault code 2. Send collects stdin until `End`, then the model runs `winhelper.ExecuteForced` with `SSH_ORIGINAL_COMMAND`.
    - Receive returns stdout in chunks of at most 64 KiB and `Done` with the exit code (`wintest.KilledExit` for a kill). Delete removes the shell. `MaxShellsPerUser` 30.
    - Faults: `FailWinRM(code uint32)` makes the next request fault, and a request above `winrs.MaxEnvelopeSize` faults with F26's code.
    - It counts TLS connections (one per call is asserted) and keeps a request log for the tests (actions, environment names and the authentication step only, never stdin or a password).
21. **Security analysis (design §9) amended, and STRIDE `WN-26`..`WN-30`** (Task 9, `04-security.md` §14.4):
    - `WN-26` (E) **The account is not limited to the helper under WinRM.** Whoever holds the account's username and password for a server, or controls Alice, has a full administrator shell on it, and the password also signs in to the server's other network services (SMB, RPC, WMI) wherever they are reachable. Under SSH, the forced command limits Alice's key to helper subcommands. Mitigations:
      - Alice's client sends only Ruling 4's request set (`TestWinRSSendsOnlyTheHelper`);
      - the password is sealed per target, decrypted per call, never readable through the API, and set only with a step-up;
      - the account is per server and removable or disabled on the server; the firewall rule opens 5986 to Alice's address only;
      - WinRM is opt-in per target, and the UI and the guides say it.
      Residual: **High, accepted by the owner as competitor parity** (2026-10-29; Keyfactor, Venafi and AppViewX all use full-admin accounts over WinRM). Only PSRP with a JEA endpoint would limit it, and no maintained Go PSRP library exists (§4.1).
    - `WN-27` (S/I) A man in the middle, a relay of the NTLM exchange, or a downgrade to Basic or HTTP. Mitigations: the SPKI pin with Administrator confirmation, checked before any HTTP byte, so NTLM messages reach only the pinned listener; NTLMv2 only (go-ntlmssp refuses a server that asks for LM or key exchange); Basic never sent and HTTP never spoken (Rulings 12, 28); no redirect, no proxy; no 5985. Relaying Alice's exchange needs the listener's private key, because the exchange runs inside TLS to the pinned SPKI; go-ntlmssp sends no channel binding, so `CbtHardeningLevel` Strict is unusable (Ruling 31), which leaves the server's own relay protection at Relaxed. Residual Low.
    - `WN-28` (I) Key material, the password and commands in Windows logs. Mitigations: Ruling 16 (no PowerShell; the command line is a constant; stdin only in Send over TLS; NTLMv2 sends a proof, never the password; 4624 and 4625 name the account, not the secret). Residual Low.
    - `WN-29` (I/E) Theft of the password from Alice's database, or offline cracking of a captured exchange. Mitigations: sealed under the master key (the Phase 3 envelope), one row per server, audit on every set; a captured NTLMv2 exchange is inside TLS to a pinned listener, so cracking it offline first needs that TLS broken; Alice's rule asks for at least 12 characters. Reusing one password across servers is the operator's choice: the UI and the host guide ask for a different password per server, so a stolen row opens one server. Residual Med (as the platform SSH key, but without the forced-command limit and usable for any network logon: see WN-26).
    - `WN-30` (E/T) Server-side setup weakens the host. Possible effects:
      - `LocalAccountTokenFilterPolicy` = 1, if F24 (a), lifts remote UAC filtering for every local administrator;
      - an administrator account with a password that works over the network (not only for WinRM).
      Mitigations: the policy change only when F24 shows it is needed and only for a local account, printed by the script, and named in the host guide; the account has the deny rights for local and Remote Desktop sign-in, no profile use, and a password the operator chooses under Alice's rule; the script never weakens Basic, `AllowUnencrypted` or 5985. Residual Med when F24 (a) applies, else Low.
22. **UI** (Task 8):
    - The Windows server form (`web/src/components/AddServerModal.tsx`) gains a transport choice: "OpenSSH (recommended)" and "WinRM over HTTPS". Choosing WinRM sets the port to 5986, keeps the username field (help: `alice`, `.\alice`, `SERVER\alice` or `DOMAIN\alice`), and shows the WN-26 warning in plain words: "Under WinRM, anyone with this account's password can run any command on the server as an administrator. With OpenSSH, Alice's key can run only alice-helper.exe."
    - After creation, the form shows the WinRM setup script (from Ruling 19's endpoint), then the password step (the password panel below, with step-up), then the identity confirm. `HostKeyConfirm.tsx` shows a `tls-spki` identity as "TLS certificate key (SPKI SHA-256)".
    - The password panel is `CCSPasswordPanel.tsx` with a new `kind` prop (`'ccs' | 'winrm'`) that chooses the endpoint (`setCCSPassword` or the new `setWinRMPassword`), the `*_set_at` field and the locale keys; the step-up (`useStepUp().run`), the `If-Match` version and the "set / change" wording are shared. Its WinRM help says: use the password the setup script set, a different one per server.
    - The target detail page shows "Transport: WinRM (HTTPS, NTLM)", the account, "Password set on <date>" or "Password not set" with the panel, and "Show setup script again". The audit log labels `target.winrm_password_set`.
    - Error texts for `ALC-WIN-0024..0028`, plus the "(WinRM)" note on `ssh.*` reasons with `transport=winrm`. EN and TR.
23. **e2e** (Task 8):
    - A new journey `web/e2e/windows-winrm.spec.ts` (EN and TR) against `cmd/alice-fakewindows`.
    - The demo host's WinRM record `0.0.0.0:5986` becomes the emulator's WinRM listener (Ruling 20), so the compose file is unchanged (Alice reaches `fakewindows:5986` on the backend network).
    - `ctl winrm-account` reads one line `<user> <password>` on stdin and sets the emulator's account (the password never on the command line); `ctl winrm-fingerprint` prints the listener's fingerprint.
    - The journey: add a Windows server with WinRM; read the setup script; pipe the account and a test password into `ctl winrm-account`; set the same password in Alice's dialog (with step-up); confirm the fingerprint; the connection test passes; discovery lists the bindings; a deployment to the demo binding `0.0.0.0:9444` (new, used only by this journey) commits and verifies; with `ctl stale-tls-on` a deployment rolls back; a wrong password set in Alice makes the connection test fail with `ALC-WIN-0024`; `expectAccessible` on the target page.
    - The demo host's new binding changes the counts `windows.spec.ts` asserts, if any; Task 8 updates them.
24. **Real-runner tests and hygiene** as in Global Constraints. The real tests live in `internal/providers/windows` and `internal/providers/windows/winrs` (`//go:build windows`), skipped unless `ALICE_WIN_REAL=1` (and `ALICE_WIN_SETUP=1` for the setup script test). The `go test ./internal/providers/windows/...` line of `windows.yml` (`:239`) already runs them.
25. **Test IDs.** `WIN-68`..`WIN-75` (Task 9 lists them).
26. **The dedicated security review of the transport** (Task 10 step 6). A reviewer that wrote none of it reviews Rulings 4, 6-16, 28, 31, WN-26..WN-30, `winrs`, `wintest/ntlm.go` and `winrm.go`. It checks:
    - no request outside Ruling 4's set can be built;
    - no code path sends Basic, sets `AllowBasicAuth` or `PasswordHashed`, follows a redirect, uses a proxy, speaks HTTP or dials 5985;
    - the pin is checked before any request, on every call, so no NTLM message reaches an unpinned listener;
    - a refused logon is never retried within the call;
    - the password is released (zeroed) on every path and never logged, and stdin appears only in Send on the authenticated connection;
    - every response is bounded;
    - `ErrNotSent` is never set after the Command request was written.
    Its findings go under "Security review (W7)" in the rulings file.
27. **"Deferred to W7+": settled or carried.**
    - Settled by W7: the WinRM transport (§13 W7), with username and password over NTLMv2.
    - Carried, unchanged, to W8+:
      - everything under "Not in W6": listeners other than `RDP-Tcp`; RD Gateway, RD Web Access, RD Connection Broker and RemoteApp certificates; changing a Remote Desktop setting; Group Policy and autoenrolment writers; `SecurityLayer` 0's answer; Windows Server 2019 on a runner;
      - W5's deferred items: the CCS farm layout, Alice creating a CCS file, removing or clearing the CCS password, a CCS password Alice's rule refuses;
      - R70's "Not in this batch" boundary:
        - class B: a manual "roll back this deployment" action; deploying to a binding whose only problem is its key; IDN U-label host headers; a third party's intermediate after Alice's commit; a `merge_group` trigger; `ci.yml` checks required; a Windows gate in `make release-gates`; removing intermediates from `CA`; a cleanup history page; the emulator's slow-host fault;
        - class C: a real ARM64 leg;
      - the items R70 declined, which stay declined;
      - the W6 owner items and W6 residual risks 1-6, 8, 9.
    - New in W7's own deferred list: PSRP and JEA; Kerberos (and UPN usernames); CredSSP; client-certificate mapping; NTLM channel binding (`CbtHardeningLevel` Strict); tlspin's CA-bundle mode for WinRM; Alice rotating the Windows password; removing a WinRM password; changing a target's transport; refusing a second target for one host across transports; a domain account tested on a runner; Server Core and Windows Server 2019 over WinRM (manual matrix).
28. **The Negotiator wrapping (owner-delegated).**
    - `winrs` builds `ntlmssp.Negotiator{RoundTripper: transport}` and sets no other field: `AllowBasicAuth` stays false, so a server that offers only Basic gets no credentials (go-ntlmssp returns its 401, and Alice answers `ErrAuthRefused` after one request); `WorkstationName` and `WorkstationDomain` stay empty.
    - The credentials go in through `req.SetBasicAuth` on every request; the Negotiator removes that header from its clone before the anonymous first try and replaces it with the NTLM tokens, so the Basic header never leaves the process. A unit test with a server that records every `Authorization` value asserts none starts with `Basic` (Task 2 `TestWinRSNeverSendsBasic`), also against a Basic-only offer and a 401 at every stage.
    - The hash mode (`AuthenticateMessageOptions.PasswordHashed`) is never used: the Negotiator calls `NewAuthenticateMessage` with nil options, so a password holding `:` is a password.
    - `TestNoCodeAllowsBasicAuth` (archtest) refuses the identifiers `AllowBasicAuth` and `PasswordHashed`, and any call of `ntlmssp.NewAuthenticateMessage`, `ProcessChallenge` or `ProcessChallengeWithHash`, in non-test code.
29. **The direct-module rule (owner-delegated).**
    - `github.com/Azure/go-ntlmssp v0.1.1` moves from the indirect block (`go.mod:42`) to the direct `require` block, sorted. `go.sum` does not change (`go mod tidy` and `go mod verify` show it). It is already compiled into `cmd/alice` through go-ldap (`go list -deps ./cmd/alice` lists it and its internal `md4`), so `THIRD_PARTY_NOTICES.md` (`tools/notices`), `make release-symcheck` and the image do not change.
    - Only `internal/providers/windows/winrs` imports it in non-test code (`TestOnlyWinRSImportsNTLMSSP`, the `TestOnlyTheDirectoryPackageImportsTheLDAPClient` pattern, `internal/archtest/buildtags_test.go:417`).
    - `docs/dev/dependency-updates.md`: the go-ldap section's sentence "linked by go-ldap but never called" is replaced, and a section "go-ntlmssp (WinRM)" gives why, the update procedure (as go-ldap's, plus `go test ./internal/providers/windows/...` and the NTLM emulator tests) and the rule that a go-ldap update that moves go-ntlmssp is checked against `winrs`'s tests.
    - Dependabot's `gomod` entry (`.github/dependabot.yml:46-51`) already covers direct modules; no change. `tools/pincheck` checks image and action pins, not Go modules; no change.
    - `CHANGELOG.md` says the module became direct.
30. **The username is configuration, not a secret.** It lives in `config.username` (jsonb, readable by target readers, as today), is shown on the target page and in the audit details of target changes, and is never sent anywhere but in the NTLM type 3 message.
31. **NTLM channel binding is not available (owner-delegated).** go-ntlmssp v0.1.1 sends no channel binding (`MsvAvChannelBindings`) and no MIC. WinRM's `Service\Auth\CbtHardeningLevel` default `Relaxed` accepts that; `Strict` refuses it (F30). Alice does not change the setting; the setup script warns, `windows.winrm_auth_refused`'s text names it, and the host guide says Strict needs a later phase. Channel binding is deferred (Ruling 27).

## Review Focus

1. **Nothing but NTLMv2 inside TLS to a pinned listener is ever spoken.** Inputs:
   - a listener that answers 401 with `WWW-Authenticate: Basic realm="WSMAN"` only, or with `Negotiate` and `Basic`;
   - a wrong password, a 401 at type 3, a 403;
   - a 302 to `http://`; an `HTTPS_PROXY` in the environment;
   - a TLS config with `InsecureSkipVerify` and no `VerifyConnection`, or with a client certificate;
   - a listener presenting another SPKI, or none pinned;
   - a host that resolves to a link-local address.
   Expected: at most three requests on one connection, no `Authorization` value but the NTLM tokens (never Basic), no retry after a refusal, and the identity error before any HTTP byte. Tests: Task 2 `TestWinRSRefusesEverythingButNTLMOverTLS`, `TestWinRSNeverSendsBasic`, `TestWinRSPinBeforeAnyRequest`; Task 6 `TestWinRMIdentityFlow`; Task 4 `TestRealWinRMAuthOffer` (F30).
2. **Key material only in Send, and the password released on every path.** Inputs:
   - an `iis-deploy` with a PEM key;
   - a call that times out after Send;
   - a fault at Create;
   - an auth refusal;
   - an output overflow.
   Tests: Task 2 `TestWinRSKeyOnlyInSend`, `TestWinRSAlwaysDeletesTheShell`; Task 6 `TestWinRMReleasesThePassword`.
3. **A write over WinRM is a refusal only when nothing reached the helper.** Inputs: a fault at Create (refusal); an auth refusal (refusal); a fault, timeout or protocol error after Command (uncertain); a kill at every journal point over WinRS (the engine recovers through `iis-status` and `iis-fence`). Tests: Task 2 `TestWinRSNotSentStages`; Task 6 `TestWinRMWriteOutcomeTable`, `TestWindowsWinRMCrashTable`.
4. **The listener's own binding and a renewed listener certificate.** Inputs:
   - the `0.0.0.0:5986` record in discovery;
   - a renewal with the same key (no change), with a new key (blocked, re-pin works), and an expired certificate (accepted).
   Tests: Task 6 `TestWinRMListenerBindingStaysUnsupported`, `TestWinRMIdentityFlow`; Task 4 `TestRealWinRMListenerIdentity` (F28).
5. **An SSH target behaves exactly as in W6.** A target without `transport`, or with `ssh`, takes the pool path, sends the same bytes, and needs no `env.HostKeys` and no WinRM password. Tests: Task 6 `TestSSHTransportIsW6`; every existing `internal/providers/windows` and `deployjobs` Windows test unchanged.
6. **The password is a CCS-style secret.** Inputs: `PUT .../winrm-password` without a step-up, without `If-Match`, with a stale version, with an 11-character password, on an SSH Windows target and on a Linux target; `GET` of the target after a set. Expected: the CCS answers (`ALC-AUTH-0003` 403, `ALC-SYS-0008` 412 for both a missing and a stale version, `ALC-WIN-0028`, `ALC-WIN-0011`), the target answer carries `winrm_password_set_at` and never the password, and the audit holds no secret. Tests: Task 5 `TestSetWinRMPassword*`, `errors_winserver_test.go`.

---

### Task 0: Start the branch on a `main` that holds R70

**Files:** none (the plan's own commit).

- [x] **Step 1:** `git merge main`, then check `grep -c '^- R70 ' docs/superpowers/specs/alice-v1/00-decisions.md` = 1, and that `docs/superpowers/rulings/windows-iis.md` has R70's entries. If R70 is not on `main`, stop and tell the coordinator. W7 changes files R70 touches (`internal/notify/sender.go`, `internal/providers/windows/discover.go`, the rulings file).
- [x] **Step 2:** Re-check the numbering against `main`: the last `ALC-WIN-` code is `0023`, the last test ID in `06-quality.md` §24.7 is `WIN-67`, the last STRIDE ID is `WN-25`, the last migration is `00037`, and `Z1036` is free (`grep -rhoE 'Z10[0-9]{2}' migrations | sort -u | tail -1` = `Z1035`). Check that `go.mod` still lists `github.com/Azure/go-ntlmssp v0.1.1 // indirect` and that `go list -deps ./cmd/alice | grep go-ntlmssp` prints it (Ruling 29). Check that port 9985 is free (`ss -ltn`). Any difference shifts the numbers and is a ruling.
- [x] **Step 3: Commit** the plan: `git add -- docs/superpowers/plans/2026-10-28-windows-w7-winrm.md`, subject `docs: Windows servers phase W7 (WinRM transport) plan (R71)`.

---

### Task 1: `winrs` codec: the WS-Man envelopes of the WinRS subset, both directions

**Files:**
- Create: `internal/providers/windows/winrs/doc.go`, `internal/providers/windows/winrs/wsman.go`, `internal/providers/windows/winrs/wsman_test.go`
- Modify: `internal/archtest/arch_test.go` (the `winrs` rule and its `TestAllowed` rows), `coverage-floors.json` (`"alice/internal/providers/windows/winrs": 95`)

**Interfaces:**
- Produces (package `winrs`, standard library and `github.com/google/uuid` only in this file):
  ```go
  const (
      ResourceCmd   = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd"
      ActionCreate  = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create"
      ActionDelete  = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete"
      ActionCommand = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command"
      ActionSend    = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Send"
      ActionReceive = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive"
      ActionSignal  = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal"
      SignalTerminate = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/terminate"
      StateDone     = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done"
      ContentType   = "application/soap+xml;charset=UTF-8"
      MaxEnvelopeSize = 153600   // the MaxEnvelopeSize header Alice sends (F26 may lower it)
      MaxResponseBody = 256 << 10
      MaxSendChunk    = 96 << 10 // raw bytes of one Send (base64 ~128 KiB)
      MaxEnvVars      = 1
  )
  type Header struct{ To, MessageID string; OperationTimeout time.Duration } // MessageID "uuid:<lowercase uuid>"
  // Client half.
  func CreateShellRequest(h Header, env map[string]string, idle time.Duration) ([]byte, error) // options WINRS_NOPROFILE TRUE, WINRS_CODEPAGE 65001; stdin/stdout streams
  func CommandRequest(h Header, shellID, program string, args []string) ([]byte, error)      // options WINRS_CONSOLEMODE_STDIN FALSE, WINRS_SKIP_CMD_SHELL TRUE
  func SendRequest(h Header, shellID, commandID string, chunk []byte, end bool) ([]byte, error)
  func ReceiveRequest(h Header, shellID, commandID string) ([]byte, error)
  func SignalRequest(h Header, shellID, commandID, code string) ([]byte, error)
  func DeleteRequest(h Header, shellID string) ([]byte, error)
  func ParseShellCreated(b []byte) (shellID string, err error)
  func ParseCommandStarted(b []byte) (commandID string, err error)
  type Received struct{ Stdout, Stderr []byte; Done bool; ExitCode int }
  func ParseReceived(b []byte, commandID string) (Received, error)
  type FaultError struct{ Code uint32 }          // the WSManFault Code only; the text is never kept
  func (e *FaultError) Error() string
  func ParseFault(b []byte) (*FaultError, bool)
  var ErrProtocol error                          // malformed, unexpected or out-of-bounds XML
  // Server half (the emulator, Task 3).
  type Request struct{ Action, MessageID, ShellID, CommandID, Program, Signal string; Args []string; Env map[string]string; Stream []byte; End bool }
  func ParseRequest(b []byte) (Request, error)
  func ShellCreatedResponse(relatesTo, shellID string) []byte
  func CommandStartedResponse(relatesTo, commandID string) []byte
  func ReceivedResponse(relatesTo, commandID string, stdout []byte, done bool, exitCode int) []byte
  func EmptyResponse(relatesTo, action string) []byte // Send, Signal, Delete
  func FaultResponse(relatesTo string, code uint32) []byte
  ```
  The shell and command IDs match `^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$` (Windows answers uppercase; F24 logs it). Any other ID is `ErrProtocol`.
- Mirror: `helperproto`'s strict decoders (one bounded input, unknown shapes refused) and its table tests.

- [x] **Step 1: Write the failing tests** (`wsman_test.go`):
  - `TestRequestsRoundTrip`: every client-half builder's output parses with `ParseRequest` back to its fields: the action, the shell ID, the env (one variable), the program and args, the stream bytes, `End`, and the signal code.
  - `TestRequestsCarryTheFixedOptions`: Create carries `WINRS_NOPROFILE` and `WINRS_CODEPAGE` 65001, and Command carries `WINRS_CONSOLEMODE_STDIN` FALSE and `WINRS_SKIP_CMD_SHELL` TRUE (the XML read back with `encoding/xml`). The `MaxEnvelopeSize` header is `153600` with `mustUnderstand="true"`.
  - `TestRequestsRefuseBadInput`: an env with two variables, a name outside `^[A-Z_]{1,32}$`, a value with a byte outside 0x20-0x7E, a chunk over `MaxSendChunk`, or an ID that is not an uppercase UUID → error, no bytes.
  - `TestParseReceived` table:
    - two stdout chunks and one stderr chunk → concatenated, in order;
    - `Done` with `<rsp:ExitCode>3</rsp:ExitCode>` → `Done`, 3;
    - `Done` without `ExitCode`, a stream for another command ID, invalid base64, an exit code outside int32, or a body over `MaxResponseBody` → `ErrProtocol`.
  - `TestParseFault`: a fault with `<f:WSManFault Code="2150858770">` gives `Code` 2150858770. A non-numeric code, or no `WSManFault`, gives `FaultError{Code: 0}` with ok true for an `s:Fault`. The fault text is not in `Error()`.
  - `TestParseRejectsHostileXML`: a DOCTYPE, an entity reference, nesting deeper than 32 elements, or two `Body` elements → `ErrProtocol` (the decoder runs with `Strict` and a token-depth bound).
  - `TestServerResponsesParse`: each server-half response parses with the client half's parser.
  - archtest `TestAllowed` rows: winrs to netaddr allowed; winrs to providers denied; winrs to linuxssh denied; winrs to winproto denied; wintest to winrs allowed; windows to winrs allowed.
- [x] **Step 2: Run them to verify they fail**
Run: `go test ./internal/providers/windows/winrs/ ./internal/archtest/`
Expected: FAIL (package and rule missing).
- [x] **Step 3: Implement.** Add `"alice/internal/providers/windows/winrs": {"alice/internal/platform/netaddr"}` to `allowed` in `arch_test.go`, next to the `winproto` rule (`:50`), with the comment "the WinRS client: the address rule only; no provider contract, no SSH; NTLMSSP through go-ntlmssp (R71)". Also add `"alice/internal/providers/tlspin"` to the `"alice/internal/providers/..."` entry (`:41-42`), with the comment "API targets and the WinRM transport check the server identity with the shared pin (R59 G2, R71)". `doc.go` states the package's scope: the six actions of the `cmd` resource, over TLS to a pinned listener, NTLMv2 only.
- [x] **Step 4: Run the tests**
Run: `go test -race -count=1 -cover ./internal/providers/windows/winrs/ ./internal/archtest/ && go run ./tools/pincheck`
Expected: PASS; winrs at least 95 % (the codec alone).
- [x] **Step 5: Commit**: `feat(winrs): the WS-Management envelopes of the WinRS subset, client and server halves, strict and bounded (R71)`.

---

### Task 2: `winrs` client with NTLMv2, the emulator's NTLM check, and the `linuxssh` seam

**Files:**
- Create: `internal/providers/windows/winrs/client.go`, `internal/providers/windows/winrs/client_test.go` (package `winrs_test`, so it may import `wintest`; archtest's import rules read non-test imports only), `internal/providers/windows/wintest/ntlm.go`, `internal/providers/windows/wintest/ntlm_test.go`
- Modify: `go.mod` (go-ntlmssp direct, Ruling 29), `internal/archtest/buildtags_test.go` (`TestOnlyWinRSImportsNTLMSSP`, `TestNoCodeAllowsBasicAuth`), `docs/dev/dependency-updates.md` (Ruling 29), `internal/providers/linuxssh/command.go` (`Input`, `Timeout`, `MaxOutput` on `HelperCommand`, next to `Line` at `:381`), `internal/providers/linuxssh/pool.go` (`Slot`), `command_test.go`, `pool_test.go`

**Interfaces:**
- Consumes: Task 1.
- Produces:
  ```go
  // package winrs
  type Client struct {
      TLS      *tls.Config                                                      // the pin (tlspin); no client certificate
      User     string                                                           // as Ruling 6 sends it ("alice", "HOST\alice", "DOMAIN\alice")
      Password string                                                           // for this call only (Ruling 8's shortcut)
      Dial     func(ctx context.Context, network, addr string) (net.Conn, error) // nil = netaddr.DialContext with linuxssh's dial timeout value (10 s, copied as a constant)
  }
  type Call struct {
      Addr      string            // host:port
      Program   string            // winproto.HelperPath, passed in by the caller
      Args      []string          // ["ssh"]
      Env       map[string]string // {"SSH_ORIGINAL_COMMAND": line}
      Stdin     []byte            // nil for none
      Timeout   time.Duration
      MaxOutput int64
  }
  type Result struct{ Stdout []byte; ExitCode int; PeerSPKI []byte } // PeerSPKI: the leaf's RawSubjectPublicKeyInfo
  func (c *Client) Run(ctx context.Context, call Call) (Result, error)
  var ErrBadConfig, ErrAuthRefused, ErrTimeout, ErrUnreachable, ErrOutputTooLarge, ErrNotSent error
  const ShellIdleSlack = 60 * time.Second
  // package wintest (test-only; Ruling 20)
  type NTLMAccount struct{ User, Password, Domain, Computer string }
  type NTLMOption func(*ntlmConfig)
  func OfferBasicOnly() NTLMOption                                    // the 401 offers only Basic; for the client's refusal test
  func NTLMServer(acct NTLMAccount, clock func() time.Time, next http.Handler, opts ...NTLMOption) (h http.Handler, connContext func(context.Context, net.Conn) context.Context)
  // package linuxssh
  func (c HelperCommand) Input() []byte
  func (c HelperCommand) Timeout() time.Duration
  func (c HelperCommand) MaxOutput() int64
  func (p *Pool) Slot(ctx context.Context, target uuid.UUID) (release func(), err error)
  ```
  Errors wrap their stage: everything up to and including the Create response wraps `ErrNotSent` (`errors.Is`), the NTLM exchange included. `*FaultError` and `ErrProtocol` keep their stage the same way. A TLS identity refusal keeps the verifier's error in the chain (`errors.Is(err, tlspin.ErrIdentityRefused)` must hold; `winrs` does not import `tlspin`: the error comes from `VerifyConnection`). `winrs` does not import `linuxssh`: it holds its own `defaultDialTimeout = 10 * time.Second`, and a test in `internal/providers/windows` compares it with `linuxssh.DefaultDialTimeout`. The exact `NTLMServer` signature may follow `wintest`'s existing server helpers; the behaviour is Ruling 20's.
- Mirror: `linuxssh.Conn.Run` (`dial.go:638-700`: ctx first, budget covering everything, abandon on timeout) and `cappedWriter`; `TestOnlyTheDirectoryPackageImportsTheLDAPClient` (`buildtags_test.go:417`).

- [x] **Step 1: Write the failing tests.**
  - `wintest/ntlm_test.go` (the server check on its own, with go-ntlmssp's `Negotiator` as the client):
    - `TestNTLMv2Vector`: MS-NLMP §4.2.4's NTLMv2 values give its `NTProofStr`.
    - `TestNTLMServerAccepts`: `alice`, `HOST\alice` and the model's `DOMAIN\alice` with the right password → 200; a second request on the same connection → 200 without a new exchange.
    - `TestNTLMServerRefuses`: a wrong password; a wrong user; an unknown domain; a type 3 replayed on a new connection and a second type 3 on the same one; a type 3 without a type 1; an NTLMv1 (24-byte) response; a request with no `Authorization` (anonymous) → 401 with `Negotiate` and `Basic realm="WSMAN"`; a `Basic` header with the right password → 401 (never accepted); with `OfferBasicOnly`, the 401 offers only Basic.
  - `client_test.go`. Each test runs against an `httptest.NewUnstartedServer` with TLS and no client certificates, its handler wrapped in `wintest.NTLMServer` and built from Task 1's server half (about 80 lines in the test file: shells in a map, the handler's request log, every `Authorization` value recorded):
    - `TestWinRSRunsOneShellPerCall` (WIN-70): one call → exactly the requests Create (with its NTLM exchange), Command, Send (end), Receive…, Delete, on one TLS connection (the server counts `ConnState` `StateNew`). Two calls → two connections, each with its own exchange. `Result.ExitCode` and `Stdout` are what the handler gave. `PeerSPKI` equals the server leaf's SPKI.
    - `TestWinRSSendsOnlyTheHelper` (Review Focus 1, Ruling 4): the log holds only the six actions, the `cmd` resource URI, the one env variable and the program and args given. With `Program` other than `winproto.HelperPath`, or `Args` other than `["ssh"]`, the test of Task 6 (`TestWinRMCallShape`) fails. This test checks that `winrs` sends what it was given and nothing else.
    - `TestWinRSKeyOnlyInSend` (Review Focus 2): with a 200 KiB stdin holding a PEM key marker, the marker's base64 appears only in Send bodies (three chunks: 96 + 96 + 8 KiB, the last `End="true"`), never in Create, Command, headers or the URL, and only on the authenticated connection. With nil stdin, one empty Send with `End="true"`.
    - `TestWinRSNeverSendsBasic` (Ruling 28): across a successful call, a wrong password, a Basic-only offer and a 401 injected at each stage, no recorded `Authorization` value starts with `Basic`, and the password's bytes appear in no request.
    - `TestWinRSRefusesEverythingButNTLMOverTLS` (Review Focus 1):
      - Rejected before any dial, `ErrBadConfig`: TLS 1.1 as `MinVersion`; a client certificate in `Certificates` or `GetClientCertificate`; `InsecureSkipVerify` without `VerifyConnection`; an empty user or password.
      - A Basic-only offer → exactly one request reached the server, without `Authorization`, and the error is `ErrAuthRefused` and `ErrNotSent`.
      - A wrong password → at most three requests, then `ErrAuthRefused` and `ErrNotSent`, no fourth request. A 403 after the exchange → the same.
      - A 302 to `http://127.0.0.1:1/wsman` → no second request, `ErrProtocol`.
      - `t.Setenv("HTTPS_PROXY", <a listener that records connects>)` → the proxy sees nothing.
      - A plain-HTTP server on the address → TLS handshake error, `ErrUnreachable`, `ErrNotSent`.
      - A server that closes the connection after Create → the client's dialer refuses the second dial, `ErrUnreachable`, and no Send was written.
    - `TestWinRSPinBeforeAnyRequest`: a `VerifyConnection` that refuses → the handler saw no request (no NTLM message), and `errors.Is(err, refusal)` holds.
    - `TestWinRSNotSentStages` (Review Focus 3) table. Each fault or error is injected by the handler at one stage, and the test checks `ErrNotSent` set or not:

      | Stage | Error | `ErrNotSent` |
      |---|---|---|
      | dial (refused address: `127.0.0.1` passes, `169.254.169.254` refused by `netaddr`) | `ErrUnreachable` | yes |
      | NTLM refused | `ErrAuthRefused` | yes |
      | Create fault | `*FaultError` | yes |
      | Create malformed | `ErrProtocol` | yes |
      | Command fault 2 | `*FaultError{2}` | no |
      | Send fault | `*FaultError` | no |
      | Receive malformed | `ErrProtocol` | no |
      | Receive never Done before the timeout | `ErrTimeout` | no |

    - `TestWinRSAlwaysDeletesTheShell` (Review Focus 2): after a timeout, an output overflow, a Send fault and a Receive protocol error, the handler got Signal terminate (timeout and overflow only) and Delete. After a Create fault or an auth refusal, no Delete (there is no shell). A `ctx` cancelled mid-Receive still sends Signal and Delete (on their own 5 s budget). The transport's idle connection is closed after every call.
    - `TestWinRSBounds`: stdout over `MaxOutput` → `ErrOutputTooLarge`; a response body over `MaxResponseBody` → `ErrProtocol`; stderr over 64 KiB is discarded without error.
    - `TestWinRSShellIdle`: Create's `IdleTimeOut` is `PT<timeout+60>S`.
  - archtest: `TestOnlyWinRSImportsNTLMSSP` (only `internal/providers/windows/winrs` imports `github.com/Azure/go-ntlmssp` in non-test code; positive control) and `TestNoCodeAllowsBasicAuth` (Ruling 28's identifiers and calls absent from non-test code).
  - `linuxssh`: `TestForcedCommandAccessors` (Input is the copy and is wiped by `WipeInput`; Timeout and MaxOutput are the constructor's); `TestPoolSlot` (Slot counts against the per-target and global limits, waits, honours `ctx`, and refuses a forgotten target and a closed pool).
- [x] **Step 2: Run them to verify they fail**
Run: `go test ./internal/providers/windows/winrs/ ./internal/providers/windows/wintest/ ./internal/providers/linuxssh/ ./internal/archtest/ -run 'WinRS|NTLM|ForcedCommandAccessors|PoolSlot|NTLMSSP|BasicAuth'`
Expected: FAIL.
- [x] **Step 3: Implement** `Run` as Rulings 12 and 28. The order of a call:
  1. check config;
  2. build the transport, the one-dial dialer and the Negotiator client;
  3. Create (with the env; the NTLM exchange happens here), then Command;
  4. Sends;
  5. Receive loop;
  6. Delete (deferred, detached budget), then `CloseIdleConnections`.
  The stdin copy belongs to the caller (`HelperCommand`), so `winrs` never retains it after `Run`. All error texts are fixed; no server text and no credential is kept. Move go-ntlmssp to the direct block in `go.mod` (`go mod tidy`, then `git diff go.sum` is empty), and update `docs/dev/dependency-updates.md` (Ruling 29). The NTLM check in `wintest/ntlm.go` follows Ruling 20 and the lint notes of Global Constraints.
- [x] **Step 4: Run the tests**
Run: `go mod tidy && go mod verify && git diff --exit-code go.sum && go test -race -count=1 -cover ./internal/providers/windows/winrs/ ./internal/providers/windows/wintest/ ./internal/providers/linuxssh/... && go test -count=1 ./internal/archtest/ && make lint`
Expected: PASS; winrs at least 95 %, linuxssh at least 93 %, wintest at least 90 %.
- [x] **Step 5: Commit**: `feat(winrs): a WinRS client over TLS with NTLMv2 only (go-ntlmssp direct, Basic never sent), one shell per call, stdin in Send only, bounded; the emulator's NTLMv2 check; linuxssh's HelperCommand accessors and Pool.Slot (R71)`.

---

### Task 3: `wintest` and `cmd/alice-fakewindows`: the emulator's WinRM listener **(parallel with Tasks 4-5)**

**Files:**
- Create: `internal/providers/windows/wintest/winrm.go`, `internal/providers/windows/wintest/winrm_test.go`
- Modify: `internal/providers/windows/wintest/model.go` (the account, `FailWinRM`), `tls.go` (the WinRM record's listener serves WS-Man behind the NTLM check), `demo.go` (the `0.0.0.0:9444` binding of Ruling 23), `wintest_test.go`; `cmd/alice-fakewindows/main.go` (`ctl winrm-account`, `ctl winrm-fingerprint`), `main_test.go`

**Interfaces:**
- Consumes: Task 1 (server half), Task 2 (`NTLMServer`), `winhelper.ExecuteForced`.
- Produces:
  ```go
  func (m *Model) SetWinRMAccount(user, password string)
  func (m *Model) ClearWinRMAccount()
  func (m *Model) FailWinRM(code uint32)                         // the next request faults with code
  func (m *Model) WinRMLog() []WinRMRequest                       // actions, env names, auth steps; never stdin or a password
  type WinRMRequest struct{ Action string; EnvNames []string; Program string; Args []string; Conn int; Auth string }
  func NewWinRMServer(t testing.TB, m *Model) *WinRMServer        // a test listener on 127.0.0.1:0 with the model's WinRM certificate
  type WinRMServer struct{ Addr string; SPKI []byte }
  func (s *WinRMServer) Connections() int
  ```
  The handler implements Ruling 20. `ExecuteForced` runs once the stdin `End` arrives, under the model's lock, with the shell's `SSH_ORIGINAL_COMMAND`. Crash points kill as on the SSH server (`wintest.KilledExit`).
- Mirror: `wintest/server.go` (`NewServer`, one connection per call, the killed-process answer), `tls.go`'s per-record listeners, W6 Task 3 (`ctl`, the demo).

- [x] **Step 1: Write the failing tests** (`winrm_test.go`, with Task 2's `winrs.Client` as the client):
  - `TestWinRMEmulatorRunsTheHelper`: `version` and `win-facts` over WinRS give the same JSON as over the SSH emulator, with one connection per call.
  - `TestWinRMEmulatorDeploysAndRollsBack`: `iis-deploy` with stdin over WinRS commits, the binding serves the new certificate, and `iis-restore` restores it.
  - `TestWinRMEmulatorRefusesBadLogons`: no account set, a wrong password, a wrong user → 401 after the exchange, and no shell was created.
  - `TestWinRMEmulatorRefusesOtherPrograms`: a Command with another program or other args → fault 2; a shell with a second env variable → fault.
  - `TestWinRMEmulatorKill`: a crash point during `iis-deploy` → `Done` with `KilledExit`, and the journal as on SSH.
  - `TestWinRMEmulatorFaultsAndLimits`: `FailWinRM(2150858770)` faults the next request; the 31st open shell faults; a body over `winrs.MaxEnvelopeSize` faults.
  - `TestDemoHostHasWinRM` (fakewindows `main_test.go`): `ctl winrm-account` with `alice <password>` on stdin sets the account (a call with that password works, another fails); a password given as an argument is refused; `ctl winrm-fingerprint` prints `providers.TLSIdentity` of the 5986 record's certificate; `ctl endpoints` names 5986 and 9444.
- [x] **Step 2: Run them to verify they fail**
Run: `go test ./internal/providers/windows/wintest/ ./cmd/alice-fakewindows/ -run 'WinRM|DemoHost'`
Expected: FAIL.
- [x] **Step 3: Implement.** Go tests use random ports (`127.0.0.1:0`). The fakewindows container keeps its user, ports and flags (the compose file does not change).
- [x] **Step 4: Run the tests**
Run: `go test -race -count=1 -cover ./internal/providers/windows/wintest/ ./cmd/alice-fakewindows/ ./internal/providers/windows/winhelper/`
Expected: PASS; wintest at least 90 %, fakewindows at least 90 %; every W1-W6 emulator test unchanged.
- [x] **Step 5: Commit**: `test(wintest): the emulator's WinRM HTTPS listener: NTLMv2 logon, WinRS shells running the helper's forced entry, faults and limits; fakewindows ctl winrm-account (R71)`.

---

### Task 4: Real-runner facts F24-F31 with the `winrs` client **[F24, F25, F26, F27, F28, F29, F30, F31]** **(parallel with Tasks 3, 5)**

**Files:**
- Create (`//go:build windows`): `internal/providers/windows/winrs/real_windows_test.go`, `internal/providers/windows/winrs/fixture_windows_test.go`, `internal/providers/windows/winrs/testdata/stdinhash/main.go` (a test-only program: prints the hex SHA-256 of stdin, exits with its first argument)
- Modify: `cmd/alice-winhelper/zz_runner_clean_windows_test.go` (the W7 checks of Global Constraints), `.github/workflows/windows.yml` (the required list `:245-293`, before `TestRealRunnerIsClean`)

**Interfaces:**
- Consumes: Task 2.
- Produces (test fixtures only):
  - `winrmFixture(t) *fx`. It records `LocalAccountTokenFilterPolicy`, `LmCompatibilityLevel` and the `Service\Auth` values. It creates `alice-w7` with a `crypto/rand` password (never logged), puts it in Administrators, and keeps the password in memory for the client. All through PowerShell in the test (the password passed on the child's stdin, never on its command line), restored in `t.Cleanup`.
  - `fx.client(t, user string) *winrs.Client` builds a TLS config that pins the presented SPKI it read first (the test's own trust-on-first-use; logged), with the fixture's password.
  - The helper for these tests is the one the job built (`go build ./cmd/alice-winhelper`), copied to a temp path that is passed as `Call.Program` (the product always passes `winproto.HelperPath`).
- Mirror: W6 Task 4 (record and restore, logged facts, the clean check), `setup_windows_test.go`'s `runNet` and `setupPowershell` helpers (copied, not imported: another package).

- [x] **Step 1: Write the tests.** They are skipped unless `ALICE_WIN_REAL=1`.
  - `TestRealWinRMNTLMAuth` **[F24]**:
    - `version` over WinRS answers with the user `alice-w7`; `win-facts` reports `elevated` true.
    - `HOSTNAME\alice-w7` answers; `.\alice-w7` sent raw is logged pass or fail.
    - The request counts of the first and the following requests of a call are logged (a counting `Dial` and a counting `RoundTripper` under the Negotiator); at most three for the first is asserted.
    - `LocalAccountTokenFilterPolicy` 0: the result and `elevated` are logged.
    - Log the account's 4624 events during the test.
  - `TestRealWinRMRunsTheForcedEntry` **[F25]**: `SSH_ORIGINAL_COMMAND=version` with Program = the helper and Args `ssh` → the version JSON. The process's command line and parent image from `Win32_Process`, caught by a test-only `stdinhash` run that sleeps 2 s, are logged and asserted (no `cmd.exe`). With process-creation auditing and command lines on (set and restored), the 4688 command line is logged.
  - `TestRealWinRMStdin` **[F26]**: 1 B, 96 KiB, 96 KiB + 1, and 256 KiB through `stdinhash` → the hash equals the Go hash. Log `MaxEnvelopeSizekb`. A hand-built 600 KB Send → the fault code is logged.
  - `TestRealWinRMCost` **[F27]**: 20 `version` calls, with p50 and max logged. Log `MaxShellsPerUser`, and the clamp on the shell's `IdleTimeOut` (read back with `Get-WSManInstance shell`). A shell left undeleted is gone after the clamp (polled up to the clamp plus 30 s; skipped with a log line when the clamp is over 5 minutes).
  - `TestRealWinRMListenerIdentity` **[F28]** (Review Focus 4):
    - The image's 5986 SPKI is logged and unchanged after `Restart-Service WinRM`.
    - A listener on `127.0.0.1:45520` with an `alice-w7-` certificate is renewed with a new key → the pinning client is refused before any request (the WinRM operational log shows no new shell; Security shows no 4624 or 4625 for the account). Renewed with the same key → accepted.
    - An `alice-w7-` certificate expired yesterday on 45520 → accepted.
  - `TestRealWinRMExitCodes` **[F29]**: `stdinhash` with exit 0, 2, 3 and 4 → the same `ExitCode`. The real helper's `iis-status` with a bad `--op` → exit 2 JSON. A missing program path → `*FaultError` code logged and asserted equal to Ruling 13's code. A helper built with `-tags alicetest`, killed at `deploy.prepared` → the exit code logged.
  - `TestRealWinRMAuthOffer` **[F30]** (Review Focus 1): log the anonymous answer and the settings of F30. Assert (a) Negotiate false and Basic true → one request, no `Authorization`, `ErrAuthRefused`; (b) a wrong password → `ErrAuthRefused` after at most three requests; (c) `LmCompatibilityLevel` 5 → works. Log the result with `CbtHardeningLevel` Strict.
  - `TestRealWinRMAccountRights` **[F31]**: with the two deny rights and `PasswordNeverExpires` on `alice-w7`, the call works; the 4624 event's logon type, package and `LmPackageName` are asserted; the wrong-password 4625 is logged. After `net user alice-w7` with a new random password (on stdin), the old password is `ErrAuthRefused` and the new one works. Log the result with the account out of Administrators and with S-1-5-114 in "Deny access to this computer from the network".
  - `TestRealRunnerIsClean` extended.
  - `windows.yml`: the required list adds the eight tests. `TestWindowsWorkflowRequiresEveryRealTest` keeps the list exact.
- [x] **Step 2: Verify locally what can be verified**
Run: `GOOS=windows GOARCH=amd64 go vet ./internal/providers/windows/winrs/ && GOOS=windows go test -c -o /dev/null ./internal/providers/windows/winrs/ && GOOS=windows go build -o /dev/null ./internal/providers/windows/winrs/testdata/stdinhash/ && actionlint .github/workflows/windows.yml && go test -count=1 ./internal/archtest/`
Expected: PASS.
- [ ] **Step 3: Run on real Windows.** Push `windows-w7` (run 1; it carries Task 2's `go.mod` change). Both legs must run every fact test (a fact test may fail on a variant it only logs; the asserted parts must pass). Count every run against the budget of 10. Record F24-F31 as rulings with the run links. When a fact differs, apply its "If it is wrong" column in its own fix commit, in the task that owns the code. F25's fallback goes to the coordinator before Task 6.
- [ ] **Step 4: Commit**: `test(winrs): F24-F31 on windows-2022 and windows-2025: NTLMv2 logon and username forms, the forced entry over WinRS, stdin, cost, listener identity, exit codes, the auth offer, account rights and password change (R71)`.

---

### Task 5: Migration `00038`, the WinRM password, inventory, API and error codes **(parallel with Tasks 3-4)**

**Files:**
- Create: `migrations/00038_windows_winrm.sql`, `migrations/windows_winrm_integration_test.go`, `internal/inventory/winrm_password.go`, `internal/inventory/winrm_password_integration_test.go`, `internal/inventory/winrm_password_test.go`
- Modify:
  - providers: `internal/providers/groundwork.go` (`WinRMPasswordSource`, its sentinels), `internal/providers/providers_test.go`;
  - inventory:
    - `internal/inventory/targets.go` (`targetColumns` `:30-33` and `scanTarget` gain `WinRMPasswordSetAt`; `UpdateTarget` refuses a transport change);
    - `internal/inventory/types.go` (`Target.WinRMPasswordSetAt`, next to `CCSPasswordSetAt` `:136-137`);
  - `internal/notify/sender.go` (the `transport=winrm` reason variant, Ruling 13) and its test;
  - API:
    - `internal/api/errors.go` (`ALC-WIN-0024..0028` after `:331`, the list at `:684-687`, `inventory.ErrTransportImmutable` and `ErrWinRMPasswordInvalid` in the mapping table near `:880-883`);
    - `internal/api/errors_winserver_test.go`;
    - `internal/api/server.go` (`SetWinRMPassword` and `WinRMSetup` on the inventory interface, next to `SetCCSPassword` `:176`);
    - `internal/api/targets_handlers.go` (`PUT /api/v1/targets/{id}/winrm-password` next to the CCS route `:40`, same `perm`, `lic` and `scope`; `setWinRMPassword` as `setCCSPassword` `:162-191`; `GET /api/v1/targets/{id}/winrm-setup`, Ruling 19);
    - `internal/api/inventory_dto.go` (`winrm_password_set_at` next to `ccs_password_set_at` `:152-154`, `:214-225`);
    - `api/openapi.yaml` (the two paths next to `/api/v1/targets/{id}/ccs-password` `:2510`, the five codes, `transport` in the Windows config schema, `winrm_password_set_at` in the target);
  - `locales/common/{en,tr}.json` (the five reasons, the `transport=winrm` variants of the `ssh.*` reasons, the e-mail texts).

**Interfaces:**
- Consumes: Task 1 (nothing at run time; the names only).
- Produces:
  - `providers.WinRMPasswordSource`, `providers.ErrNoWinRMPassword`, `ErrWinRMPasswordUnusable` (Ruling 8);
  - `func (c platformCredentials) WinRMPassword(ctx context.Context, target uuid.UUID) (secrets.Plaintext, func(), error)`;
  - `func (s *Service) SetWinRMPassword(ctx context.Context, a Actor, target uuid.UUID, ifVersion int, pw secrets.Plaintext) (Target, error)` (Ruling 7);
  - `func (s *Service) WinRMSetup(ctx context.Context, target uuid.UUID) (WinRMSetup, error)` with `type WinRMSetup struct{ User string }` (the API handler passes it to `windows.SetupScriptWinRM`, Task 7: the API package imports providers, never inventory the Windows provider);
  - `inventory.ErrTransportImmutable`, `inventory.ErrWinRMPasswordInvalid`; `api.ErrWINWinRMAuthRefused`, `ErrWINWinRMPasswordMissing`, `ErrWINWinRMFault`, `ErrWINTransportImmutable`, `ErrWINWinRMPasswordInvalid`;
  - constants `purposeWinWinRM = "win_winrm"`, `kindWinRMPassword = "winrm_password"`.
- Mirror: `00036_windows_ccs.sql` (the four CHECKs, the refusing Down), `ccs_password.go` (the sealed append-only credential, its rule, its source, its audit), `setCCSPassword` and its tests, W6 Task 5 (codes, OpenAPI).

- [x] **Step 1: Write the failing tests**
  - `windows_winrm_integration_test.go`:
    - Up accepts a `win_winrm` / `winrm_password` credential with `target_id`, and refuses one without it, and refuses `winrm_password` under another purpose.
    - Down refuses with `Z1036` while one exists and succeeds after it is removed.
    - The test that pins the latest migration expects 38.
  - `winrm_password_test.go`, `TestWinRMPasswordRuleIsTheCCSRule`: 11 and 129 characters, a space, a byte above 0x7e → invalid; 12 and 128 printable → valid.
  - `winrm_password_integration_test.go`:
    - `TestSetWinRMPassword`: one `win_winrm` row, the target's version bumped, `WinRMPasswordSetAt` set, the audit event `target.winrm_password_set` without the secret, and `WinRMPassword` answers the same bytes; a second set → the newest wins; the `Plaintext` is zeroed after the call.
    - `TestSetWinRMPasswordRefuses`: a Linux target and a Windows target with `transport` `ssh` → `ErrNotWindowsTarget`; an invalid password → `ErrWinRMPasswordInvalid`, and no row; a stale version → `ErrVersionMismatch`.
    - `TestWinRMPasswordForeign`: a row of another target, kind or type → `ErrWinRMPasswordUnusable`, never decrypted. No row → `ErrNoWinRMPassword` (and `ErrNotFound`).
    - `TestWinRMTargetWithoutPassword`: a WinRM target is created without a row; `WinRMPasswordSetAt` is nil.
    - `TestTransportImmutable`: a patch with another `transport` → `ErrTransportImmutable`; the same transport, or no `transport` member, passes.
    - `TestWinRMSetupOnlyForWinRMTargets`.
  - `internal/notify`: the `transport=winrm` variant of `ssh.unreachable` and `ssh.timeout` renders in EN and TR; without the param, the text is byte for byte R70's.
  - `errors_winserver_test.go`: the five codes with their reasons and statuses. `PUT .../winrm-password`: 200 with the target, `ETag` and `winrm_password_set_at`, and no password in the answer; without step-up `ALC-AUTH-0003`; without `If-Match` or with a stale one `ALC-SYS-0008`; an invalid password `ALC-WIN-0028`; an SSH Windows target `ALC-WIN-0011`; an unknown member in the body refused (`decodeExact`). The setup endpoint answers 200 with a script for a WinRM target, the code of `ErrNotWindowsTarget` for an SSH one, and 404 for an unknown target. The OpenAPI conformance test passes.
- [x] **Step 2: Run them to verify they fail**
Run: `go test -count=1 -tags integration ./migrations/ ./internal/inventory/ ./internal/notify/ ./internal/api/ -run 'WinRM|Transport|Winserver|Migration'`
Expected: FAIL.
- [x] **Step 3: Implement**, the OpenAPI entries included.
- [x] **Step 4: Run the tests**
Run: `go test -race -count=1 ./internal/providers/ && go test -count=1 -tags integration ./migrations/ ./internal/inventory/ ./internal/notify/ ./internal/api/ && make i18n-check`
Expected: PASS; inventory at least 89 %, api at least 95 %.
- [x] **Step 5: Commit**: `feat(inventory): a Windows target's transport, its WinRM password as a sealed append-only credential set with step-up, the setup endpoint and ALC-WIN-0024..0028; migration 00038 (R71)`.

---

### Task 6: Windows provider: the transport seam, WinRS calls, the pin; engine tests on the emulator

**Files:**
- Create: `internal/providers/windows/winrm.go`, `internal/providers/windows/winrm_test.go`, `internal/jobs/deployjobs/windows_winrm_integration_test.go`
- Modify:
  - provider:
    - `config.go` (`Config`, `transport`, the port default, the `.\` form under WinRM);
    - `provider.go` (`ConfigSchema` `transport` field; `Open` chooses `run` and builds the verifier under WinRM; `session.cfg Config`; `session.run`; `callIn` `:221-245`);
    - `deploy.go` (`runWrite` `:201-215`: `s.run`, and the not-sent rule);
    - `verify.go` (`probeWith` `:177-200`: `s.run`);
    - `errors.go` (the five reasons);
  - tests: `provider_test.go`, `deploycert_test.go`, `conformance_test.go`, `discover_test.go`;
  - engine harness: `internal/jobs/deployjobs/harness_integration_test.go` (a WinRM Windows target on `wintest.NewWinRMServer`, with the inventory's real credential source and a password set through `SetWinRMPassword`).

**Interfaces:**
- Consumes: Tasks 2, 3, 5.
- Produces:
  ```go
  type Config struct {
      linuxssh.Config
      Transport string // TransportSSH | TransportWinRM
  }
  const (TransportSSH = "ssh"; TransportWinRM = "winrm"; DefaultWinRMPort = 5986)
  func ParseConfig(cfg providers.TargetConfig) (Config, []validate.FieldError)
  func ntlmUser(username string) string // Ruling 6: ".\alice" → "alice"; every other form as typed
  func (s *session) sshRun(ctx context.Context, c linuxssh.HelperCommand) (linuxssh.Result, providers.HostKey, error)
  func (s *session) winrmRun(ctx context.Context, c linuxssh.HelperCommand) (linuxssh.Result, providers.HostKey, error)
  func (s *session) winrmPassword(ctx context.Context) (pw []byte, release func(), err error) // s.ccsPassword's shape
  func winrmError(err error, v *tlspin.Verifier, ctx context.Context, sub string) error // Ruling 13; keeps winrs.ErrNotSent in the chain
  const (ReasonWinRMAuthRefused = "windows.winrm_auth_refused"; ReasonWinRMPasswordMissing = "windows.winrm_password_missing"
         ReasonWinRMFault = "windows.winrm_fault"; ReasonTransportImmutable = "windows.transport_immutable"
         ReasonWinRMPasswordInvalid = "windows.winrm_password_invalid")
  ```
  `winrmRun` does, in order:
  1. take `p.pool.Slot`;
  2. read the password (Ruling 8); a refusal here is not-sent;
  3. build `winrs.Client{TLS: verifier.TLSConfig(), User: ntlmUser(cfg.Username), Password: string(pw)}`;
  4. run `winrs.Call{Addr: JoinHostPort(cfg.Host, cfg.Port), Program: winproto.HelperPath, Args: []string{"ssh"}, Env: {"SSH_ORIGINAL_COMMAND": c.Line()}, Stdin: c.Input(), Timeout: c.Timeout(), MaxOutput: c.MaxOutput()}`;
  5. release the password (zeroed), then the slot, on every path;
  6. map with `winrmError`;
  7. return `linuxssh.Result{Stdout, ExitCode}` and `providers.TLSIdentity(PeerSPKI)`.
  `runWrite` treats `errors.Is(err, winrs.ErrNotSent)` as a refusal.
- Mirror: `ccs.go:50-82` (`s.cred.(providers.CCSPasswordSource)`, `ccsPasswordRefusal`), W6 Task 6's tests.

- [x] **Step 1: Write the failing tests**
  - `winrm_test.go` (over `wintest.NewWinRMServer`):
    - `TestSSHTransportIsW6` (Review Focus 5): no `transport`, or `ssh` → `Open` uses the pool, sends the same lines as before (the SSH emulator's log), and never calls `WinRMPassword` or `env.HostKeys`.
    - `TestWinRMCallShape` (Ruling 4): every call's log entry has Program `winproto.HelperPath`, Args `["ssh"]`, env names `["SSH_ORIGINAL_COMMAND"]`, and one connection per call (`TestEachWinRMCallUsesItsOwnConnection` as a subtest over `Discover`).
    - `TestWinRMIdentityFlow` (Review Focus 1, 4):
      - nothing pinned → `Open` fails `target.host_key_unconfirmed` with the fingerprint, the store saw the sighting, and the emulator saw no NTLM message;
      - pinned → `TestConnection` works, and `ConnectionReport.HostKey` is the TLS identity;
      - the emulator's WinRM certificate replaced with a new key → `target.host_key_changed`, and no request reached the emulator (its log);
      - the same key, new certificate → works.
    - `TestWinRMConfig`: port default 5986; `alice`, `.\alice`, `HOST\alice` and `CORP\alice` accepted under `winrm`; `.\alice` refused under `ssh`; `alice@corp.example` refused under both; an unknown transport refused; `ntlmUser` table (Ruling 6).
    - `TestWinRMPasswordMissing`: a source without the interface and `ErrNoWinRMPassword` → `windows.winrm_password_missing`; `ErrWinRMPasswordUnusable` → `internal.unexpected`; a database error → `windows.io_error` (retryable); nothing dialled in any case.
    - `TestWinRMErrorTable`: every row of Ruling 13's table, through emulator faults (`FailWinRM`), a wrong password (401), an access-denied fault at Create, a stalled Receive (a hook in the model), and an output flood. The reason, retryable flag, `transport=winrm` and `wsman_code` param are checked.
    - `TestWinRMWriteOutcomeTable` (Review Focus 3): `iis-deploy` with a fault at Create or a wrong password → refusal (`failed`, nothing changed); a fault after Command, or a timeout → uncertain (`providers.CheckDeployReturn` passes for every row).
    - `TestWinRMReleasesThePassword` (Review Focus 2): a counting fake source sees one release per acquire, and the `Plaintext` zeroed, after success, a timeout, a fault, an auth refusal and an identity refusal.
    - `TestWinRMListenerBindingStaysUnsupported` (Ruling 11): the demo's `0.0.0.0:5986` record is `win_foreign_app` over WinRM and over SSH; a deployment to it is refused before sending.
    - `TestWinRMDialTimeoutMatchesSSH`: `winrs`'s dial timeout constant equals `linuxssh.DefaultDialTimeout`.
  - `conformance_test.go`: the `providertest` suite also runs against a WinRM target on the emulator.
  - `windows_winrm_integration_test.go` (the engine on the emulator over WinRS):
    - `TestWindowsWinRMDeployAndRollback`: a binding deployment commits at level 2; with `StaleTLS` it rolls back, and `verify_old` passes.
    - `TestWindowsWinRMCrashTable` (Review Focus 3): a kill at each W2 journal point over WinRS, then the engine's recovery through `iis-status` and `iis-fence`.
    - `TestWindowsWinRMDiscoveryAndCleanup`: discovery finds the bindings, the CCS and the RDP listener; the W3 cleanup runs.
    - `TestWindowsWinRMIdentityChangeBlocks`: a changed listener identity blocks the target (`host_key_changed`), and no deployment is sent.
    - `TestWindowsWinRMAuthRefused`: the emulator's account password changed → the deployment fails `ALC-WIN-0024` with nothing sent; setting the new password in Alice makes the next deployment work.
    - `TestWindowsWinRMPasswordMissing`: a WinRM target without a password → the deployment fails `ALC-WIN-0025` with nothing dialled.
- [x] **Step 2: Run them to verify they fail**
Run: `go test ./internal/providers/windows/ -run 'WinRM|SSHTransport' && go test -tags integration ./internal/jobs/deployjobs/ -run WinRM`
Expected: FAIL.
- [x] **Step 3: Implement.** The three call sites change to `s.run(ctx, c)` and nothing else in them changes.
- [x] **Step 4: Run the tests**
Run: `go test -race -count=1 -cover ./internal/providers/windows/... ./internal/providers/tlspin/ && go test -race -count=1 -tags integration ./internal/jobs/deployjobs/ ./internal/jobs/driftjobs/ ./internal/jobs/winjobs/`
Expected: PASS; windows at least 95 %; every W1-W6 provider and engine test unchanged.
- [x] **Step 5: Commit**: `feat(providers/windows): the WinRM transport: one seam for every helper call, WinRS with NTLMv2 and the pinned listener SPKI, the same helper protocol and outcomes (R71)`.

---

### Task 7: The WinRM setup script, its real test, and the provider over real WinRS **[F32]**

**Files:**
- Modify: `internal/providers/windows/setup.go` (the shared fragments; `SetupScriptWinRM`), `setup_test.go`, `setup_windows_test.go` (the real tests below), `docs_setup_test.go` (the host guide quotes the WinRM script's account, listener and firewall lines), `internal/api/` target handler of Task 5 (calls `SetupScriptWinRM`), `.github/workflows/windows.yml` (the required list), `cmd/alice-winhelper/zz_runner_clean_windows_test.go` (the `Alice WinRM` firewall rule removed by the test's cleanup)

**Interfaces:**
- Consumes: Tasks 5, 6.
- Produces: `func SetupScriptWinRM(user, from string, allowUnverified bool) (string, error)` (Ruling 18). The user is in `$AliceUser = '<user>'`, checked against Ruling 6's rule before embedding; a `.\` user is embedded without the `.\`. The script embeds no secret; the password is asked with `Read-Host -AsSecureString` and never printed.
- Mirror: `SetupScript` (`setup.go:114-148`), its tests (`setup_test.go:65-224`), `TestRealSetupScript` (`setup_windows_test.go:432`).

- [x] **Step 1: Write the failing tests**
  - `setup_test.go`:
    - `TestSetupScriptUnchangedByTheRefactor`: `SetupScript`'s output for a fixed input equals a golden copy taken before the refactor (commit the golden file in this step, from the code before Step 3).
    - `TestSetupScriptWinRMSteps`: the script holds each of Ruling 18's steps in order, the helper checksum, the deny rights, `DONT_EXPIRE_PASSWORD`, `Read-Host -AsSecureString` and the password rule check. It holds no `Enable-PSRemoting`; no write of `Basic`, `Negotiate`, `Kerberos`, `CredSSP`, `CbtHardeningLevel`, `AllowUnencrypted` or a 5985 listener (only reads); no `ClientCertificate` mapping and no `TrustedPeople`; no `SeDenyNetworkLogonRight` write; no `sshd` and no `administrators_authorized_keys`.
    - `TestSetupScriptWinRMNeverPrintsThePassword` (the SSH test's twin): the password variable reaches only `SetPassword`, never `Write-Host`, `Write-Output`, a file or the transcript, and is removed after use.
    - `TestSetupScriptWinRMRefusesBadInput`: a `'` in the user, a user outside Ruling 6's rule → error.
    - `TestSetupScriptWinRMDomainAccount`: for `CORP\alice` the script creates no account and sets no password.
    - `TestSetupScriptWinRMFirewallAddress`: as the SSH test (`:188`).
  - `setup_windows_test.go` (skipped unless `ALICE_WIN_SETUP=1`):
    - `TestRealWinRMSetupScript` **[F32]**: it runs the script for `alice`, answering the password prompt from the test (a `crypto/rand` password on the script's stdin through a test-only `-PasswordFromStdin` harness switch that the product script does not have; the harness wraps the generated script). It then checks:
      - the helper is installed; the account has `PasswordNeverExpires`, the deny rights and Administrators membership;
      - a WinRS call with the password works;
      - `LocalAccountTokenFilterPolicy` is as F24 requires;
      - the firewall rule `Alice WinRM` exists;
      - the image's listener is kept, and Basic, `AllowUnencrypted` and Negotiate are as found;
      - the printed fingerprint equals `providers.TLSIdentity` of the certificate the client sees on 5986 and on an ECDSA listener on 45521 made by the test.
      Run twice: the second run with an empty answer changes nothing.
    - `TestRealWinRMProvider`: `windows.New(...)` with a WinRM target `127.0.0.1:5986`, a memory host-key store that is pinned after the first `host_key_unconfirmed`, and a fake `WinRMPasswordSource` with the fixture's password. Over real WinRS it runs `TestConnection`, `Discover`, an `iis-deploy` to an `alice-w7-` binding on `0.0.0.0:45522`, a failed verification's rollback, and the cleanup plan. The binding is removed in cleanup.
    - `TestRealBothTransportsShareTheHelper`: after `TestRealSetupScript` and `TestRealWinRMSetupScript`, `version` answers over SSH (key) and over WinRS (password) with the same helper.
    - `TestFidelityWinRM`: the same scenario list (version, win-facts, iis-dump, a refused `iis-deploy`, a wrong password, a fault at Command) against the emulator configured like the runner and against real WinRS. The answers are compared field by field (exit codes, helper JSON without messages, `winrs` error kinds and fault codes).
  - `windows.yml`: the four real tests join the required list.
- [x] **Step 2: Run them to verify they fail**
Run: `go test ./internal/providers/windows/ -run 'SetupScript' && GOOS=windows go test -c -o /dev/null ./internal/providers/windows/`
Expected: FAIL (unit tests); the Windows test binary builds.
- [x] **Step 3: Implement.** Factor the shared fragments (`helperCheck`, the install, the data directory, the event source, the account's creation, membership and deny rights) into constants used by both scripts. The SSH script keeps its random never-shown password; the WinRM script's account fragment asks for the password instead. Then write `SetupScriptWinRM`. The SPKI fingerprint is computed in PowerShell 5.1 from `$cert.PublicKey.Oid`, `EncodedParameters` and `EncodedKeyValue` with a small DER writer (SEQUENCE, OID, BIT STRING, lengths). F32 checks it.
- [ ] **Step 4: Run, then real Windows**
Run: `go test -race -count=1 -cover ./internal/providers/windows/ && make docs-check && actionlint .github/workflows/windows.yml && go test -count=1 ./internal/archtest/`
Expected: PASS. Then push (run 2 or 3; budget 10): both legs green with `windows-required` green. Record F32.
- [ ] **Step 5: Commit**: `feat(providers/windows): the WinRM setup script (account and password prompt, listener, firewall, printed SPKI fingerprint), sharing the SSH script's helper install; real WinRS tests and fidelity (R71)`.

---

### Task 8: Web and e2e

**Files:**
- Create: `web/e2e/windows-winrm.spec.ts`
- Modify:
  - `web/src/api/types.ts` (`TargetConfig.transport`, `Target.winrm_password_set_at`);
  - `web/src/api/endpoints.ts` (`getWinRMSetup`, `setWinRMPassword`, next to `setCCSPassword` `:175-177`);
  - `web/src/api/enums.ts` (the five reasons);
  - `web/src/components/AddServerModal.tsx` (Ruling 22);
  - `web/src/components/CCSPasswordPanel.tsx` (the `kind` prop, Ruling 22);
  - `web/src/components/HostKeyConfirm.tsx` (`tls-spki` label and help);
  - the target detail page that shows a Windows server's connection (`web/src/pages/TargetDetailPage.tsx`);
  - the error text helper that renders `ssh.*` reasons (the "(WinRM)" note);
  - `web/src/locales/{en,tr}.json` (including the audit label `target_winrm_password_set` next to `target_ccs_password_set`), `web/src/test/fixtures.ts`;
  - tests `AddServerModal.test.tsx`, `CCSPasswordPanel.test.tsx`, `HostKeyConfirm.test.tsx`, `TargetDetailPage.test.tsx`;
  - `web/e2e/windows.spec.ts` (counts, if the 9444 binding changes any).

**Interfaces:**
- Consumes: Task 5's API, Task 3's `ctl winrm-account`.
- Mirror: the Windows path of `AddServerModal.tsx` (setup script, then `HostKeyConfirm`), `CCSPasswordPanel.tsx` (step-up through `useStepUp().run`, the `If-Match` version, the answer's newer version), W6 Task 7.

- [x] **Step 1: Write the failing tests**
  - `AddServerModal.test.tsx`:
    - the transport choice defaults to OpenSSH;
    - WinRM sets port 5986 and shows the WN-26 warning text and the username help;
    - an `alice@corp.example` account under WinRM shows the field error; `.\alice` is accepted;
    - after creation, the WinRM setup script is fetched and shown, then the password step (step-up), then the identity confirm.
  - `CCSPasswordPanel.test.tsx`: with `kind="winrm"` the panel calls `setWinRMPassword` with the target's version through the step-up, shows "set on <date>" from `winrm_password_set_at`, and never shows the password after the answer; the CCS cases are unchanged.
  - `HostKeyConfirm.test.tsx`: a `tls-spki` key shows "TLS certificate key (SPKI SHA-256)" and the help that names the script's printed fingerprint.
  - `TargetDetailPage.test.tsx`: a WinRM target shows the transport, the account, the password panel ("not set" or the date) and "Show setup script again". An SSH target shows none of it.
  - The error text: `ssh.unreachable` with `transport=winrm` shows the WinRM note; `ALC-WIN-0024..0028` render.
  - `windows-winrm.spec.ts` (Ruling 23), in EN and TR.
- [x] **Step 2: Run them to verify they fail**
Run: `cd web && npx vitest run src/components/AddServerModal.test.tsx src/components/CCSPasswordPanel.test.tsx src/components/HostKeyConfirm.test.tsx src/pages/TargetDetailPage.test.tsx`
Expected: FAIL.
- [x] **Step 3: Implement**, EN and TR, help texts included: what WinRM needs on the server (the script and the password), that OpenSSH is recommended and why (WN-26), a different password per server, and how to compare the fingerprint.
- [x] **Step 4: Run the tests**
Run: `cd web && npx vitest run && npx tsc --noEmit && npm run lint && cd .. && make i18n-check && make web-coverage && make helper winhelper && E2E_PROJECT=alice-e2e-w7 ALICE_E2E_PORT=9985 make e2e-up && E2E_PROJECT=alice-e2e-w7 ALICE_E2E_PORT=9985 make e2e; E2E_PROJECT=alice-e2e-w7 make e2e-down`
Expected: PASS; the whole e2e suite green.
- [x] **Step 5: Commit**: `feat(web): the WinRM transport of a Windows server: the choice and its warning, the setup script, the password with step-up, the TLS identity confirm, the target page; English and Turkish (R71)`.

---

### Task 9: Documents

**Files:**
- Modify:
  - `docs/superpowers/rulings/windows-iis.md`: the heading `# W7 (R71)` at the end, with:
    - the owner's delegation (quoted) and the competitor research summary;
    - the rulings as built and the F24-F32 verdicts;
    - the runner-run table, the security review, acceptance and owner items (the Turkish texts quoted, R70's pattern);
    - "Deferred to W8+" (Ruling 27's list moved on).
  - `docs/superpowers/specs/alice-v1/00-decisions.md`: R71 after R70, in R69's form. R71's text names:
    - the transport setting and its immutability, the username forms (Ruling 6), and the per-target sealed password set with step-up (Ruling 7);
    - the WinRS subset with NTLMv2 through go-ntlmssp (direct), Basic never sent, the forced entry through `SSH_ORIGINAL_COMMAND`, and helper 1.2.0 unchanged;
    - the SPKI pin with the existing confirm flow, the refusals by construction, and the self-pin rule;
    - the setup script, WN-26's residual accepted as competitor parity, `ALC-WIN-0024..0028`, `WIN-68..75`, `WN-26..30`, and migration `00038`.
  - `docs/superpowers/specs/2026-10-21-windows-iis-target-design.md`:
    - §4.1 and §4.2 (W7 built, R71: username and password over NTLMv2 instead of certificate mapping, with the account caution kept; certificate mapping moved to deferred);
    - §8 (the transport seam; `SSH_ORIGINAL_COMMAND` through the WinRS environment; one connection per call, authenticated once);
    - §9 (Ruling 21's rows);
    - §13 W7 "built, R71, §22"; the F24-F32 rows of §14; "§22 Phase W7 as built" (a placeholder written in Task 9, filled in Task 10).
  - `docs/superpowers/specs/alice-v1/03-integrations.md`: §13A.20 "The WinRM transport: setting, password credential, setup script (amendment, R71)" and §13A.21 "WinRS calls, NTLMv2, the pin and the error mapping (amendment, R71)".
  - `04-security.md` §14.4: `WN-26`..`WN-30`. `06-quality.md` §24.7: heading gains "R71", and the rows below. `test/matrix/traceability.json` and `docs/security/traceability.md` (regenerated).
  - `CHANGELOG.md` ("Unreleased"; go-ntlmssp now a direct module).
  - `docs/admin-guide.md` ("Windows servers": choosing the transport, the WinRM caution, the username forms, setting and changing the password (step-up), the identity confirm, re-pinning after a listener renewal).
  - `docs/windows-host-preparation.md`: a section "## WinRM transport" before "## Troubleshooting" (`:363`). It covers:
    - what the script changes (Ruling 18) and that it asks for the password;
    - local and domain accounts, the username forms, and the hardened-baseline limit for local accounts (Ruling 6);
    - F24's verdicts (`LocalAccountTokenFilterPolicy`);
    - `PasswordNeverExpires`, and that changing the password on the server needs the same change in Alice (F31);
    - the settings Alice needs and never changes: Negotiate on, `CbtHardeningLevel` not Strict, NTLM not restricted (Ruling 31);
    - what Windows logs (Ruling 16), and how to revoke (disable the account or change its password);
    - how to compare the fingerprint; that the 5986 listener's binding is never deployed by Alice;
    - the WN-26 caution in the same words as the UI, and a different password per server.
  - `docs/troubleshooting.md`: `ALC-WIN-0024..0028`, plus "The connection test says the TLS identity changed", "WinRM: 401 after the setup script" (the password in Alice, the account's membership, Negotiate, `CbtHardeningLevel`, `LocalAccountTokenFilterPolicy`) and "WinRM: password not set".

| ID | Case | Tests |
|---|---|---|
| WIN-68 | The WS-Man codec: the six actions, the fixed options, strict and bounded parsing, faults by code only | `winrs:TestRequestsRoundTrip`, `TestRequestsCarryTheFixedOptions`, `TestRequestsRefuseBadInput`, `TestParseReceived`, `TestParseFault`, `TestParseRejectsHostileXML` |
| WIN-69 | Only NTLMv2 inside TLS to a pinned listener: Basic never sent, no HTTP, no 5985, no redirect or proxy, no client certificate; the pin before any request; key material only in Send; go-ntlmssp imported by `winrs` only | `winrs:TestWinRSRefusesEverythingButNTLMOverTLS`, `TestWinRSNeverSendsBasic`, `TestWinRSPinBeforeAnyRequest`, `TestWinRSKeyOnlyInSend`, `TestWinRSSendsOnlyTheHelper`; `wintest:TestNTLMv2Vector`, `TestNTLMServerAccepts`, `TestNTLMServerRefuses`; `archtest:TestOnlyWinRSImportsNTLMSSP`, `TestNoCodeAllowsBasicAuth`; `windows:TestWinRMCallShape` |
| WIN-70 | One shell per call: one authenticated connection, stdin chunks, the Receive loop, bounds, timeouts with Signal and Delete, the not-sent stages | `winrs:TestWinRSRunsOneShellPerCall`, `TestWinRSNotSentStages`, `TestWinRSAlwaysDeletesTheShell`, `TestWinRSBounds`, `TestWinRSShellIdle`; `linuxssh:TestPoolSlot` |
| WIN-71 | The transport setting, its immutability, the username forms, the per-target sealed password set with step-up and its source; migration 00038 | `inventory:TestWinRMPasswordRuleIsTheCCSRule`, `TestSetWinRMPassword`, `TestSetWinRMPasswordRefuses`, `TestWinRMPasswordForeign`, `TestWinRMTargetWithoutPassword`, `TestTransportImmutable`; `windows:TestWinRMConfig`, `TestWinRMPasswordMissing`; `migrations:TestMigration00038` |
| WIN-72 | The provider over WinRS: the same protocol and outcomes, the identity flow, the error table, the password released, the listener binding never deployable; an SSH target unchanged | `windows:TestSSHTransportIsW6`, `TestWinRMIdentityFlow`, `TestWinRMErrorTable`, `TestWinRMWriteOutcomeTable`, `TestWinRMReleasesThePassword`, `TestWinRMListenerBindingStaysUnsupported`; `deployjobs:TestWindowsWinRMDeployAndRollback`, `TestWindowsWinRMCrashTable`, `TestWindowsWinRMIdentityChangeBlocks`, `TestWindowsWinRMAuthRefused`, `TestWindowsWinRMPasswordMissing` |
| WIN-73 | The WinRM setup script: its steps, the password asked and never printed, domain accounts untouched, the SSH script unchanged, the fingerprint (F32), both transports on one server | `windows:TestSetupScriptWinRMSteps`, `TestSetupScriptWinRMNeverPrintsThePassword`, `TestSetupScriptWinRMDomainAccount`, `TestSetupScriptUnchangedByTheRefactor`, `TestRealWinRMSetupScript`, `TestRealBothTransportsShareTheHelper` |
| WIN-74 | Real Windows: F24-F31, the provider over real WinRS, fidelity, the runner left clean | `winrs:TestRealWinRMNTLMAuth`, `TestRealWinRMRunsTheForcedEntry`, `TestRealWinRMStdin`, `TestRealWinRMCost`, `TestRealWinRMListenerIdentity`, `TestRealWinRMExitCodes`, `TestRealWinRMAuthOffer`, `TestRealWinRMAccountRights`; `windows:TestRealWinRMProvider`, `TestFidelityWinRM`; `cmd/alice-winhelper:TestRealRunnerIsClean` |
| WIN-75 | The WinRM journey in the browser, in English and Turkish | `web/e2e/windows-winrm.spec.ts` |

- [x] **Step 1: Write the failing check**: add the rows above to `06-quality.md` §24.7.
Run: `make matrix-check MATRIXCHECK_FLAGS=-strict`
Expected: FAIL only on rows whose tests are missing from `traceability.json`.
- [x] **Step 2: Write the documents** and `traceability.json`, then regenerate: `go run ./tools/matrixcheck -spec docs/superpowers/specs/alice-v1/06-quality.md -map test/matrix/traceability.json -doc docs/security/traceability.md -update`.
- [x] **Step 3: Run**
Run: `make matrix-check MATRIXCHECK_FLAGS=-strict && make docs-check && make i18n-check && go test -count=1 ./internal/providers/windows/ -run 'Docs|Preparation'`
Expected: PASS; 0 gaps, 0 pending.
- [x] **Step 4: Commit**: `docs: Windows servers phase W7 (R71): decision, rulings, design as built, security and quality amendments, WIN-68..WIN-75, admin and host guides, troubleshooting, changelog`.

---

### Task 10: Final gates

**Files:** none new. Fixes go to the task that owns the code.

- [ ] **Step 1: Full local gates**
Run: `go mod tidy && git diff --exit-code go.mod go.sum && make lint && make test && make i18n-check && make matrix-check MATRIXCHECK_FLAGS=-strict && make docs-check && make helper winhelper && make build && make coverage`
Expected: PASS; `go.mod` as Task 2 left it (go-ntlmssp direct, nothing else changed against `main`: `git diff main -- go.mod` shows one line moved), `go.sum` unchanged against `main`; every floor met, `winrs` at least 95, none lowered.
- [ ] **Step 2: Windows build and vet**
Run: the Windows line of "Verification commands".
Expected: PASS.
- [ ] **Step 3: e2e and image.** Only when no other `make ci` or Docker-based run is active on the machine: `E2E_PROJECT=alice-e2e-w7 ALICE_E2E_PORT=9985 make ci`. Otherwise run Task 8's e2e when the machine frees, and list `make ci` as pending in the acceptance report.
Expected: PASS; the e2e totals are recorded.
- [ ] **Step 4: Real Windows.** The `windows.yml` run of the branch's code head is green on windows-2022 and windows-2025, with `windows-required` green (runs counted, at most 10). If it cannot be, the rulings file lists it as an owner item and the acceptance report says it is pending.
- [ ] **Step 5: gitleaks** over the whole range `<branch base>..HEAD`. Use R70's fixed `make secrets-scan`, which scans commits in a worktree (R70 C3); if it is not on `main`, use W6's way: export with `git log -p`, scan in `dir` mode with `.gitleaks.toml`. Fingerprint any finding in `.gitleaksignore` without key material. No test password may be a literal (tests generate them).
- [ ] **Step 6: The transport security review (Ruling 26)**, then the independent review of `<branch base>..HEAD` against Review Focus 1-6 and Rulings 4, 6-16, 28, 31. Both are made by reviewers that did not write the code. Fix or decline every finding with a reason in the rulings file ("Security review (W7)", "Final review fixes (W7)").
- [ ] **Step 7: Acceptance check against design §4.2 (as amended by R71) and §13 W7**, one line each in the rulings file, then fill "§22 Phase W7 as built":
  - the same helper and protocol over WinRS (Ruling 4, F25; `TestWinRMCallShape`, `TestRealWinRMProvider`);
  - username and password authentication over NTLMv2, the password sealed and set with step-up (Rulings 6-8, 28, F24, F31);
  - the listener's certificate pinned by SPKI with the shared TLS pinning (Ruling 9, F28, F32);
  - Basic and unencrypted HTTP refused (Rulings 12, 28, F30);
  - the security analysis states that the account is not limited to the helper (Ruling 21, WN-26, accepted by the owner);
  - the transport review (Ruling 26).

  Hand the branch `windows-w7` to the coordinator. Do not merge or push `main`.

---

## Execution notes for the implementer

- Task 0 first: `main` must hold R70.
- **Dispatch order:** 0 → 1 → 2 → (3 ∥ 4 ∥ 5) → 6 → 7 → 8 → 9 → 10. Tasks 3, 4 and 5 touch disjoint files:
  - Task 3: `wintest` (except `ntlm.go`, which Task 2 owns) and `cmd/alice-fakewindows`;
  - Task 4: `winrs/*_windows_test.go`, `winrs/testdata`, `cmd/alice-winhelper/zz_runner_clean_windows_test.go`, `windows.yml`;
  - Task 5: `migrations`, `internal/inventory`, `internal/notify`, `internal/api`, `api/openapi.yaml`, `internal/providers/groundwork.go`, `locales/common`.
  Task 7 also edits `windows.yml` and the clean test: it runs after Task 4 is in.
- **Runner runs (budget 10):**
  - Run 1 right after Task 2, with Task 4's fact tests, so F24-F31 are known before Task 6 relies on the username forms, the token policy and F25. It also carries Task 2's `go.mod` change (a Windows path).
  - Run 2 after Task 4's fixes. Run 3 after Task 7 (F32, the provider over real WinRS, fidelity). Run 4 after the final review's fixes.
  - That leaves 6 runs spare.
  - A documents-only commit outside `.github/windows-paths.txt` may be pushed without spending a run. `docs/windows-host-preparation.md` is on that list, so push it with a code change.
- **Review gates:** after Tasks 2, 5, 6 and 7, a review against Review Focus 1-6 before the next dependent task. Task 2's review includes Ruling 26's checklist for `winrs` and `wintest/ntlm.go`. Every finding is fixed in the task that owns the code, with its own commit.
- Record every ruling made during execution in `docs/superpowers/rulings/windows-iis.md` under "W7 (R71)", one line each: the ruling, then why.
- Commit with `git -c user.name="Eren Altan" -c user.email="erenaltan@gmail.com" commit --only ...` and the trailer `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`. Subjects end with `(R71)`.

## Left for later phases

- **W7+ (deferred by this plan, Ruling 27):**
  - PSRP and a JEA endpoint (the only way to limit the WinRM account);
  - Kerberos (and UPN usernames), CredSSP, client-certificate mapping;
  - NTLM channel binding (`CbtHardeningLevel` Strict, Ruling 31);
  - tlspin's CA-bundle mode for a WinRM listener;
  - Alice rotating the Windows password; removing a WinRM password; changing a target's transport;
  - refusing a second target for one host on the other transport;
  - a domain account tested on a runner; Server Core and Windows Server 2019 over WinRM (manual matrix).
- **Carried unchanged** (Ruling 27): "Not in W6", W5's deferred items, R70's class B and C boundary, R70's declined items, and the W6 owner items and residual risks.

## Owner decisions and items still to confirm

**The delegation (2026-10-29).** The owner wrote: "sorularin cevaplarini bilmiyorum. rakipler nasil yapmissa sende ole yap. w7 ye basla" ("I do not know the answers to the questions. Do it the way the competitors did. Start W7."). The open rulings of the 2026-10-28 draft were therefore decided by competitor parity.

**The competitor research (coordinator, 2026-10-29).** Keyfactor's IIS Universal Orchestrator, Venafi TLS Protect's agentless IIS driver and AppViewX CERT+ for IIS all reach IIS servers over WinRM with a stored username and password of a local administrator or a domain service account: Keyfactor defaults to Kerberos; Venafi's examples use HTTPS with NTLM and offer a `WinRMSkipCACheck` option; AppViewX takes a username and password or a vault reference. None uses client-certificate mapping, and all accept full-administrator accounts. Hence R71: username and password over HTTPS with NTLMv2 (Rulings 6-8, 28); Kerberos, certificate mapping, PSRP/JEA and CredSSP deferred; Basic, 5985 and `AllowUnencrypted` refused by construction; WN-26 accepted. Alice keeps a stricter server-identity rule than the `SkipCACheck` style (the SPKI pin with Administrator confirmation, Ruling 9).

**Decided by the delegation (recorded in the rulings file, no further owner action):**
1. Ruling 1: the in-house WinRS client with go-ntlmssp for NTLMSSP only; masterzen/winrm rejected.
2. Rulings 6-8: username and password over NTLMv2; local and domain accounts; the password sealed per target, set with step-up, never readable; a target may exist before its password.
3. Ruling 4: the helper stays 1.2.0 (F25's fallback, helper 1.3.0, only if F25 fails).
4. Rulings 21 and 31: WN-26's High residual accepted as competitor parity; no channel binding in W7.
5. Ruling 29: go-ntlmssp becomes a direct module.

**Still for the owner to confirm:**
1. **The Turkish texts** of the WN-26 caution, the transport choice, the username help, the password dialog and the five new error reasons (the rulings file quotes them, as R70's owner table does).
2. **Ruling 18, the setup script's password prompt:** the script asks the operator for the password (and keeps the current one on an empty answer) instead of generating one, so the operator types the same password twice: once on the server, once in Alice. The alternative, a generated password printed once, breaks the scripts' rule of never showing a password.
3. **Ruling 18's server changes:** `LocalAccountTokenFilterPolicy` = 1 for a local account only if F24 shows it is needed; the script never changes Negotiate, Basic, `CbtHardeningLevel`, `AllowUnencrypted` or 5985 (it warns, or stops when Negotiate is off).
4. **Ruling 3's gap:** W7 does not refuse a second live Windows target for the same host on the other transport. The licence then counts it twice, and both targets manage the same bindings, with the helper's lock and compare-and-swap keeping them safe.
5. **Ruling 5:** a WinRM target's `targets.credential_id` still names the platform key (unused), so the database's target-credential rule is unchanged.
6. **Ruling 24 and Global Constraints:** the runner tests change WinRM and LSA settings on the hosted runners (`Service\Auth` values, `LocalAccountTokenFilterPolicy`, `LmCompatibilityLevel`, a network deny right, test listeners on 45520-45539, a local account `alice-w7`) and restore everything as found.
7. **The F24-F32 verdicts** once measured, especially F24 (whether the token policy must change, which changes WN-30), F25 (whether the helper must change) and F30 (`CbtHardeningLevel` Strict).
8. **A domain account over WinRM** is accepted by syntax and by the emulator only; the first real test is on a customer's or the owner's domain (manual matrix), like the AD sign-in item.

## Self-review notes (for the executor)

- **Spec coverage:**
  - §4.2 "the helper and its protocol do not change": Ruling 4, Global Constraints "Protocol and helper", F25.
  - "the transport would be WinRS" (authentication amended by R71 to username and password over NTLMv2): Rulings 1, 6-8, 12, 28; Tasks 1-2, 5-6; F24, F30, F31.
  - "the listener's certificate pinned by SPKI (the shared TLS pinning)": Ruling 9, Task 6 (`tlspin`); F28, F32.
  - "Basic and unencrypted HTTP refused": Rulings 12, 28, Task 2 `TestWinRSRefusesEverythingButNTLMOverTLS`, `TestWinRSNeverSendsBasic`, F30. (§4.2's "NTLM refused" is amended by R71: NTLMv2 is the method.)
  - "the account is not limited to the helper unless PSRP and a JEA endpoint are built": Ruling 21 (WN-26), Ruling 22 (the UI text), Task 9 (§9, host guide).
  - §4.3 account: Rulings 6, 18; F31. §6.1 setup script: Ruling 18, Task 7. §8 one connection per call and `SSH_ORIGINAL_COMMAND`: Rulings 4, 10, 12; `TestWinRSRunsOneShellPerCall`, `TestWinRMCallShape`.
  - §14 F3, F8 and F12 (the token policy, the 5986 listener): Rulings 11, 18, 20; F24, F28. §15 Q1: the header's caution.
- **Names used across tasks:**
  - `winrs`:
    - codec: `ResourceCmd`, `Action*`, `SignalTerminate`, `StateDone`, `ContentType`, `MaxEnvelopeSize`, `MaxResponseBody`, `MaxSendChunk`, `Header`, the `*Request` builders, `ParseShellCreated`, `ParseCommandStarted`, `Received`, `ParseReceived`, `FaultError`, `ParseFault`, `ErrProtocol`;
    - server half: `Request`, `ParseRequest`, the `*Response` builders;
    - client: `Client` (`TLS`, `User`, `Password`, `Dial`), `Call`, `Result`, `Run`, `ErrBadConfig`, `ErrAuthRefused`, `ErrTimeout`, `ErrUnreachable`, `ErrOutputTooLarge`, `ErrNotSent`, `ShellIdleSlack`.
  - `linuxssh`: `HelperCommand.Input/Timeout/MaxOutput`, `Pool.Slot`.
  - `wintest`: `NTLMServer`, `NTLMAccount`, `OfferBasicOnly`, `Model.SetWinRMAccount/ClearWinRMAccount/FailWinRM/WinRMLog`, `WinRMRequest`, `NewWinRMServer`, `WinRMServer`.
  - `providers`: `WinRMPasswordSource`, `ErrNoWinRMPassword`, `ErrWinRMPasswordUnusable`.
  - `inventory`: `SetWinRMPassword`, `platformCredentials.WinRMPassword`, `validWinRMPassword`, `Service.WinRMSetup`, `WinRMSetup`, `Target.WinRMPasswordSetAt`, `ErrTransportImmutable`, `ErrWinRMPasswordInvalid`, `purposeWinWinRM`, `kindWinRMPassword`.
  - `windows`: `Config`, `TransportSSH`, `TransportWinRM`, `DefaultWinRMPort`, `ParseConfig`, `ntlmUser`, `session.run/sshRun/winrmRun/winrmPassword`, `winrmError`, `Reason{WinRMAuthRefused,WinRMPasswordMissing,WinRMFault,TransportImmutable,WinRMPasswordInvalid}`, `SetupScriptWinRM`.
  - `api`: `ErrWIN{WinRMAuthRefused,WinRMPasswordMissing,WinRMFault,TransportImmutable,WinRMPasswordInvalid}`; routes `PUT /api/v1/targets/{id}/winrm-password`, `GET /api/v1/targets/{id}/winrm-setup`.
  - web: `setWinRMPassword`, `getWinRMSetup`, `CCSPasswordPanel` `kind`, `winrm_password_set_at`.
