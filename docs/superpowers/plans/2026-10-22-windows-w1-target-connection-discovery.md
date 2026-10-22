# Windows Servers, Phase W1 (Target, Connection and Discovery) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An Administrator adds a Windows server (target type `windows`) with the platform SSH key, confirms its host key, sees its facts (OS build, IIS, elevation, stores, OpenSSH), and sees every http.sys SSL binding as a location (kind `win_sslbinding`) with the IIS sites that use it as its servers, foreign applications and CCS bindings unsupported with their reason, and each binding's certificate linked to the inventory by fingerprint. Nothing is deployed in W1.

**Architecture:** A new protocol package `internal/providers/windows/winproto` (standard library and `helperproto` only) is shared by Alice and the Windows helper. The helper's decisions live in a platform-neutral package `internal/providers/windows/winhelper` behind a `Host` interface. The real helper `cmd/alice-winhelper` (GOOS=windows only) implements `Host` with `httpapi.dll`, crypt32 and `appcmd.exe`; the emulator `internal/providers/windows/wintest` implements it with a modelled host, real TLS listeners and the `linuxsshtest` SSH server. The provider `internal/providers/windows` reuses linuxssh's pool, dial and host-key pinning, sends bare forced-command lines (no sudo, no path), and converts the dump into locations Alice-side (as `webserver/convert.go` does for Nginx). Inventory, API and web learn the type `windows`; no migration is needed.

**Tech Stack:** Go 1.27.3 (`golang.org/x/crypto/ssh`, `golang.org/x/sys/windows`, pgx/v5, testcontainers), PostgreSQL, React 18 + Mantine + TanStack Query + i18next, Vitest, Playwright, Docker images pinned by digest, GitHub Actions `windows-2022` / `windows-2025` runners.

**Spec:** `docs/superpowers/specs/2026-10-21-windows-iis-target-design.md` (the design; this phase is §13 "Phase W1" and its acceptance list; it draws on §5, §6.1, §6.2, §7, §8, §9, §11, §12 items 1, 2, 4, 5, 7, §14, §15). Shared groundwork as built: `docs/superpowers/specs/2026-10-21-deployment-targets-roadmap.md` §1 and §5, rulings `docs/superpowers/rulings/deployment-targets-groundwork.md`. Model plan for format: `docs/superpowers/plans/2026-10-17-haproxy-provider.md`. The owner approved the design with the §15 defaults on 2026-10-22.

## Before you start: W0 facts

Phase W0 (the real-Windows spike, branch `windows-w0-spike`, tooling `tools/winspike/`) confirms facts F1-F8 of design §14 and amends the design on `main`. **Its results were not available when this plan was written.** Before starting any task marked **[W0: Fx]** below, re-read §14 (and every section W0 amended, `git log -p -- docs/superpowers/specs/2026-10-21-windows-iis-target-design.md`) and adjust the task. If W0 is not merged yet, do the tasks without a W0 mark first (1, 2, 6, 8, 12, 13, 14) and wait. Record every adjustment as a ruling in `docs/superpowers/rulings/windows-iis.md`.

| Fact | What W1 relies on | Tasks |
|---|---|---|
| F2 | The record shapes of `HttpQueryServiceConfiguration` for `HttpServiceConfigSslCertInfo`, `...SslSniCertInfo`, `...SslCcsCertInfo` on 2019/2022/2025 (which flags and extended parameters exist and are readable), so `winproto.SSLBinding` dumps every setting W2 must preserve. | 1, 3, 5, 7 |
| F3 | A key-based OpenSSH logon of an administrator gets an elevated token (domain account; local account without UAC filtering); how the token's elevation is read; whether SYSTEM's access to a key can be checked from the helper. | 4, 5, 10, 11 |
| F4 | Whether a key imported with `CRYPT_MACHINE_KEYSET` is usable by http.sys without extra ACLs; what "key usable by SYSTEM" means for `key_inaccessible`. | 5 |
| F6 | `appcmd list site /config /xml` output shape, shared configuration resolution, availability on Server Core. | 3, 5, 11 |
| F7 | OpenSSH Server install time on the GitHub images (capability vs. pinned Win32-OpenSSH MSI). | 10, 11 |
| F8 | The application ids of IIS, WinRM, AD FS and SSTP bindings (`win_foreign_app` names). | 1, 5, 9 |

## Global Constraints

- **Branch.** Cut `windows-w1` from `main` after W0 merged (or from `05bbf07d` plus whatever W0 merged). Never switch branches inside a task. Fast-forward merge to `main` locally at the end; do not push (the owner pushes).
- **Commits.**
  - `git -c user.name="Eren Altan" -c user.email="erenaltan@gmail.com" commit --only -m "<subject>" -m "Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>" -- <paths>`.
  - New files: `git add -- <path>` first. Never `git add -A` or `git add .`. Check `git status --short` before each commit.
  - Never touch `.claude/`, the untracked PDFs (`Alice-Proje-Dokumani.pdf`, ...), `alice-helper` (untracked binary at the root) or `docs/security/reviews/independent-audit*` and the other untracked review files.
  - `.gitleaksignore` is pinned to commit hashes: never rebase, squash or amend a commit that is pushed. A test that needs a key generates it at run time (`internal/testutil/pki`); never commit PEM key material. If gitleaks flags a test table, follow commit `4d5f2eff` (fingerprint in `.gitleaksignore`, no key material).
- **Security guards that must stay green.**
  - `StrictHostKeyChecking=no` or `ssh.InsecureIgnoreHostKey` anywhere in the repository (including the e2e image, the workflow and docs code blocks outside `docs/`) fails `TestNoCodeAcceptsAnyHostKey` (`internal/providers/linuxssh/guard_test.go:54`). The Windows workflow's `ssh` smoke test pins the host key with `-o UserKnownHostsFile=<file>` written from `ssh-keyscan`.
  - `tools/pincheck` (`make lint`) refuses unpinned actions and images: every `uses:` is `owner/repo@<40 hex> # vX.Y.Z` (copy the SHAs from `.github/workflows/ci.yml:21-25`), every Dockerfile `FROM` has `@sha256:` (reuse the digests of `test/images/fakefleet/Dockerfile`).
  - `TestOnlyTheTypeListNamesWebServerTypes` (`internal/archtest/webserver_test.go`): only `internal/inventory/types.go` names the web-server type constants.
  - `TestImportRules` (`internal/archtest/arch_test.go:300`) with the new rules of Task 1, 2, 7.
- **Protocol.** `winproto.Protocol = 1`, `winproto.MinProtocol = 1`, `winproto.Version = "0.1.0"` (helper version string; W2 sets `"1.0.0"`). Subcommands of W1: `version`, `win-facts`, `iis-dump`, `tls-probe`, plus the forced-command entry `ssh`. Exit codes equal `helperproto.Exit*` (0, 2, 3, 4).
- **Paths.** Helper `C:\Program Files\Alice\alice-helper.exe` (`winproto.HelperPath`), data `C:\ProgramData\Alice\helper` (`winproto.DataDir`), event source `Alice Helper`, IIS's `%windir%\system32\inetsrv\appcmd.exe`.
- **Helper rules (design §7).** `GOOS=windows`, `GOARCH` amd64 and arm64, `CGO_ENABLED=0`, `golang.org/x/sys/windows` for crypt32/ncrypt/token/registry and a hand-written `httpapi.dll` binding (`HttpInitialize`, `HttpQueryServiceConfiguration`, `HttpTerminate`; the update/set calls come in W2). No PowerShell, no .NET, no `cmd.exe` at run time. The Linux helper (`cmd/alice-helper`, `helperproto`) is not changed.
- **Error codes.** `ALC-WIN-0001` `windows.helper_missing` (502), `ALC-WIN-0002` `windows.helper_outdated` (502), `ALC-WIN-0003` `windows.not_elevated` (502). New area `WIN`.
- **No migration.** `targets.type` `windows` and `certificate_locations.kind` `win_sslbinding` exist since `00031`; problem and reason codes are only a regex in `00006`; `targets.config` needs `host` and `port`, which W1 keeps (Ruling 1). If a task finds it needs schema, stop and add a ruling; the next free number is `00032`.
- **Decision.** R60 "Windows server target, phase W1" in `docs/superpowers/specs/alice-v1/00-decisions.md` (last entry is R59). Rulings file `docs/superpowers/rulings/windows-iis.md` (W2-W7 append to it).
- **Coverage floors** (`coverage-floors.json`; never lower an existing one): `alice/internal/providers/windows/winproto` 100, `alice/internal/providers/windows/winhelper` 95, `alice/internal/providers/windows` 95, `alice/internal/providers/windows/wintest` 90, `alice/cmd/alice-fakewindows` 90. **No floor for `alice/cmd/alice-winhelper`**: it is not in the Linux profile and `tools/covercheck` fails a floor without coverage data (`tools/covercheck/main.go:56-61`); its tests run on the Windows job.
- **Locales.** EN and TR, `locales/common/{en,tr}.json` (server texts, error codes, provider labels) and `web/src/locales/{en,tr}.json` (UI), identical keys and placeholders (`make i18n-check`). Display names: "Windows server" / "Windows sunucusu", software "IIS". Turkish never puts a suffix on `{{software}}`. The disabled deploy note keeps the pinned shape "Not available for {{software}} servers yet" / "{{software}} sunucularında henüz kullanılamıyor".
- **e2e.** Run the stack as `E2E_PROJECT=alice-e2e-w1 ALICE_E2E_PORT=9973 make e2e-up e2e; make e2e-down` (phase G used 9963, the DNS providers 9953). The `fakewindows` service publishes nothing. Docker-based Go runs and Playwright never run at the same time.
- **Verification commands.**
  - `go build ./... && go vet ./... && go vet -tags integration ./...`
  - `GOOS=windows GOARCH=amd64 go build ./cmd/alice-winhelper/ ./internal/providers/windows/... && GOOS=windows go vet ./cmd/alice-winhelper/ ./internal/providers/windows/...` (Windows-only files are invisible to the Linux commands)
  - `go test -race -count=1 ./<pkgs>`; `go test -race -count=1 -tags integration ./<pkgs>`
  - `make lint`, `make test`, `make i18n-check`, `make matrix-check`, `make docs-check`; final `make coverage` and `make ci`
  - web: `cd web && npx vitest run <files> && npx tsc --noEmit && npm run lint`
  - A helper change regenerates checksums: `make helper winhelper`.

## Rulings (where the spec is silent; each goes into `docs/superpowers/rulings/windows-iis.md` for the owner to confirm)

1. **Config names follow the Linux path.** `targets.config` keeps `host`, `port`, `username` (what `inventory.CreateTarget` passes, `internal/inventory/targets.go:145-146`, and the `00005` CHECK requires), not §8's `address`/`os_user`; the UI labels `username` "Windows account". `discovery_interval` is the existing `targets.discovery_interval_seconds` column, not config. Default user `alice`; accepted names `^([A-Za-z0-9][A-Za-z0-9-]{0,14}\\)?[A-Za-z0-9][A-Za-z0-9._-]{0,19}$` (optional NetBIOS domain of at most 15, then a SAM name of at most 20), stored as typed.
2. **Protocol 1 spans W1 and W2.** Nothing is released between them, so W2 adds `iis-deploy`, `iis-restore`, `iis-status`, `iis-fence`, `iis-cleanup` to protocol 1; W1's helper answers `UNKNOWN_SUBCOMMAND` for them. If a release happens between W1 and W2, W2 bumps to protocol 2 and `MinProtocol` rules apply.
3. **Elevation gate.** `version`, `win-facts` and `tls-probe` run without an elevated token (Linux's `version` and `tls-probe` run without sudo); `win-facts` reports `elevated`. `iis-dump` (and every W2 subcommand) refuses with `NOT_ELEVATED` (exit 2). `TestConnection` fails with `windows.not_elevated` when `win-facts` says `elevated:false`, so the target's last error names it.
4. **Shared decision code.** The helper's platform-neutral logic (command split, dispatch, elevation gate, budget, dump assembly and bounds, appcmd XML parsing, probe) is `internal/providers/windows/winhelper` behind `winhelper.Host`. The real helper and the emulator run the same code; the fidelity test then checks the hosts' raw readings. Matching IIS bindings to http.sys entries is Alice-side (`internal/providers/windows/convert.go`), as Nginx's server-to-file matching is (`internal/providers/webserver/convert.go:208`).
5. **Forced command line.** Alice sends `<sub> <arg> ...`: tokens joined by one ASCII space, each `^[A-Za-z0-9._:@+-]{1,253}$`, at most 16 tokens, at most 4096 bytes (`winproto.ValidToken`, `JoinCommandLine`, `SplitCommandLine`). No quoting: sshd passes the line verbatim in `SSH_ORIGINAL_COMMAND` and the helper splits it itself. `linuxssh` gains one audited constructor for such lines (`linuxssh.ForcedCommand`), so `HelperCommand` stays constructor-only (SEC-063).
6. **Locator.** As §5: `{"type":"hostnameport","host":<folded>,"port":N,"app_id":<id>}`, `{"type":"ipport","ip":<canonical>,"port":N,"app_id":<id>}`, `{"type":"ccs","port":N,"app_id":<id>}`; host names folded to ASCII lower case, IPs in `netip` canonical form, app ids lower case in braces. Canonical text `http.sys/hostnameport/www.example.com:443`, `http.sys/ipport/0.0.0.0:443`, `http.sys/ipport/[::]:443`, `http.sys/ccs/443`. An IIS https binding with no http.sys entry gets a location whose locator carries the IIS application id (what IIS Manager writes when a certificate is chosen there), so the row is the same location once a certificate is bound. Consequence for review: an http.sys entry re-created by another application (new app id) is "another location with the same text": inventory skips and counts it (groundwork ruling 3) and the old row is not marked missing.
7. **Matching IIS bindings to http.sys entries.** `bindingInformation` `ip:port:host` (IPv6 `[addr]:port:host`) with `sslFlags`: bit `0x2` (CCS) matches `ccs:<port>`; bit `0x1` (SNI) matches `hostnameport <host>:<port>`; otherwise `ipport`: `*` matches `0.0.0.0:<port>` and also `[::]:<port>` when present; a specific IP matches `<ip>:<port>`, else falls back to `0.0.0.0:<port>` (http.sys's own lookup order). Host names compared after ASCII folding. Stopped sites are still servers.
8. **Supported, in this order.** `ccs` → unsupported `win_ccs`; no IIS binding uses the entry → `win_foreign_app` (details `application` names it from the F8 table, else ""); store other than `My`/`WebHosting` (case-insensitive) → `win_store_unsupported`; else supported. **`win_ctl` is a location warning, not an unsupported reason**: §5 calls it "deployable, warned", and an unsupported location cannot be deployable (`00006` CHECK `NOT supported OR unsupported_reason = ''`). It is set when the entry has a CTL identifier or store, or client-certificate negotiation / mapping flags.
9. **Problems.** `cert_missing` (the binding names a hash not in its store, or an IIS binding has no entry) goes into `Problem`; `key_missing` and `key_inaccessible` into `KeyProblem`. Inventory's existing rule (`internal/inventory/locations.go:158-160`) then makes such a location `file_problem`, unsupported. The certificate of a key problem is still linked (it is readable). W2 decides whether a key problem should stay deployable (a new key fixes it).
10. **The certificate half of a Windows target.** `configUsable` (`internal/inventory/locations.go:373`) accepts `Software == "iis"` without `Found`: http.sys bindings exist without IIS, and foreign applications are still listed when IIS is missing (§11 "IIS not installed"). A Windows scan has no SSH half; the certificate scan sets `last_discovery_at` (else every test would queue a first discovery again, `internal/jobs/targetjobs/targetjobs.go:164`).
11. **Type predicates.** `inventory.IsServer` keeps its meaning "SSH keys" (Linux and web servers): Windows has no SSH key inventory (§2 non-goal), so the key routes and `internal/sshkeys` refuse a Windows target as today. New `inventory.IsSSHTarget(typ)` (Linux, web servers, Windows: platform key, host keys, connection tests; used by `validateNewTarget`) and `inventory.HasCertificateLocations(typ)` (web servers and Windows: the certificate half of `Reconcile`). Windows is not added to `webServerTypes` (it does not deploy in W1, and `deployTypes` must not offer it).
12. **appcmd failure fails the dump.** When IIS is installed and `appcmd` fails, times out or its XML does not parse, `iis-dump` answers `IO_ERROR` (exit 4) and nothing is stored (the previous scan stays): without the sites every IIS binding would look foreign.
13. **Only three new error codes.** Every other helper refusal stays `ssh.helper_refused` with its `helper_code` param, as on Linux. `UNKNOWN_SUBCOMMAND` from the helper maps to `windows.helper_outdated`.
14. **W1 capabilities** are `test_connection` and `discover_certificates` only (a provider advertises only what it implements; W2 adds `deploy_certificate` and `verify_deployment`).
15. **Setup script.** The administrator copies `alice-winhelper-windows-<arch>.exe` as `.\alice-helper.exe` into the directory the script runs in (Linux's model, `internal/providers/linuxssh/setup.go:126`). The script edits `$AliceUser = 'alice'` (or `DOMAIN\alice-svc`), checks the helper hash for `$env:PROCESSOR_ARCHITECTURE` (`AMD64`, `ARM64`), and the firewall rule's remote address is the `from=` of the key line when the guide was asked with `?from=`, else `Any` with a printed notice. The key line is `restrict` (plus `,from="<ip>"`) and the key. `inventory.SetupGuide` keeps its all-or-nothing rule: the `windows` profile without a script is `ErrNoSetupScript` (so the image build must embed the Windows checksums too, Task 6).
16. **Checksums.** Separate target `make winhelper` writing `bin/alice-winhelper-windows-amd64.exe`, `bin/alice-winhelper-windows-arm64.exe` and `bin/alice-winhelper.sha256`; linker variables `alice/internal/providers/windows.helperSHA256WindowsAMD64/ARM64`. `make build`, `deploy/Dockerfile`, `deploy/dev/reproducible-check.sh` and `make image-check` include them. Shipping the helper in the release bundle and `SHA256SUMS` stays W4.
17. **Real-Windows workflow.** A separate `.github/workflows/windows.yml` (path-filtered push and pull request, nightly, manual), not required; W4 makes it required.
18. **UI.** A Windows server uses the shared locations panel (`web/src/components/WebsitesPanel.tsx`) with the site column "IIS site", software "IIS", one row per binding sorted by certificate then canonical text (the grouping of §15 Q5 waits for W2, when deployment needs it), and the deploy control disabled by capability.
19. **OS facts.** `win-facts` fills both `providers.OSRelease` (`ID "windows"`, `VersionID` = build, `PrettyName` = product, so the existing OS fact shows) and the new `providers.WindowsFacts`.
20. **Dump bounds.** `MaxBindings 1000`, `MaxCertificates 1000`, `MaxSites 2000`, `MaxSiteBindings 10000`, `MaxChainCerts 20` (= `helperproto.MaxProbeChainCerts`), `MaxCertDER 64 KiB`, `MaxAppcmdOutput 32 MiB`, `DumpOutput 16 MiB` (= `helperproto.ServerDumpOutput`). A cut list sets `truncated` and the warning `list_truncated`; the provider then adds `locations_dropped` so inventory marks nothing missing (`internal/inventory/locations.go:364`). The budget (`winproto.HelperBudget` = 50 s) ending answers `IO_ERROR`.
21. **Test IDs.** `WIN-01..WIN-14` in a new `06-quality.md` §24.7 "Windows servers (R60)"; `tools/matrixcheck` learns the `WIN` prefix (its row pattern is `(?:SR|[LFSRAOX])-\d+`, `tools/matrixcheck/main.go:89`).
22. **e2e fake.** `cmd/alice-fakewindows` (`serve --listen :22 --ctl 127.0.0.1:9093`, `ctl ping|prepare|hostkey`) wraps `wintest` with a fixed demo host; `ctl prepare` reads the Windows setup script on stdin and authorizes the key line it carries (the counterpart of `alice-e2e-prepare`).

## Review Focus

1. **A domain account name** `CORP\alice-svc` (backslash, upper case) typed in the form must reach the API, inventory, `targets.config`, the SSH dial and the setup script verbatim; a Linux name rule must not reject it, and a Linux target must still refuse it. Tests: Task 8 `TestParseConfigTakesDomainAccounts`, Task 12 `TestCreateWindowsTargetKeepsTheDomainAccount`.
2. **A cut dump** (more than 1000 bindings, or the output cap) must never mark stored locations missing. Tests: Task 3 `TestDumpCutsAtItsBounds`, Task 9 `TestDiscoverTruncatedDumpDropsLocations`, Task 12 `TestWindowsTruncatedScanMarksNothingMissing`.
3. **IIS not installed**: the WinRM or AD FS binding of a plain Windows server must still be listed (unsupported, `win_foreign_app`), the facts must say IIS is not installed, and nothing may be supported. Tests: Task 9 `TestDiscoverWithoutIISListsForeignBindings`, Task 12 `TestWindowsScanWithoutIISStoresForeignLocations`.
4. **Binding matching edge cases**: an IIS host header in upper case against http.sys's entry, `*` against `0.0.0.0` and `[::]`, a specific IP without its own entry falling back to the wildcard entry, an SNI flag with a missing host. Test: Task 9 `TestDiscoverMatchesIISBindings` (table).
5. **sshd without the forced command** (setup half done: the key works but `ForceCommand` is missing, so the login shell runs Alice's line): Alice must report `windows.helper_missing` from `version` and send nothing else. Test: Task 8 `TestOpenWithoutForcedCommandIsHelperMissing` (the emulator answers like `cmd.exe`: exit 1, text on stderr, nothing on stdout).

---

### Task 1: `winproto` protocol 1

**Files:**
- Create: `internal/providers/windows/winproto/winproto.go`, `internal/providers/windows/winproto/winproto_test.go`
- Modify: `internal/archtest/arch_test.go:47-49` (add the rule `"alice/internal/providers/windows/winproto": {"alice/internal/providers/linuxssh/helperproto"}` next to apacheconf's, with the comment "the Windows helper's protocol: pure, imported by the Windows helper"), and a `TestAllowed` row (`arch_test.go:460-470` pattern) for winproto → helperproto allowed and winproto → providers refused
- Modify: `coverage-floors.json` (`"alice/internal/providers/windows/winproto": 100`)

**Interfaces:**
- Produces (all in package `winproto`; mirror the layout of `internal/providers/linuxssh/helperproto/helperproto.go:21-226, 382-400, 660-730`):
  - `const Protocol = 1; MinProtocol = 1; Version = "0.1.0"; HelperPath = `C:\Program Files\Alice\alice-helper.exe`; DataDir = `C:\ProgramData\Alice\helper`; HelperBudget = 50 * time.Second`
  - Subcommands `SubSSH = "ssh"`, `SubVersion = "version"`, `SubWinFacts = "win-facts"`, `SubIISDump = "iis-dump"`, `SubTLSProbe = "tls-probe"`
  - Exits `ExitOK = 0, ExitRefused = 2, ExitPrecondition = 3, ExitFailed = 4`
  - Codes `CodeUsage "USAGE"`, `CodeUnknownSubcommand "UNKNOWN_SUBCOMMAND"`, `CodeInvalidArgument "INVALID_ARGUMENT"`, `CodeNotElevated "NOT_ELEVATED"`, `CodeIOError "IO_ERROR"`, `CodeProbeFailed "PROBE_FAILED"`, `CodeOutputTooLarge "OUTPUT_TOO_LARGE"`, `CodeStoreError "STORE_ERROR"`
  - Binding types `BindingIPPort "ipport"`, `BindingHostnamePort "hostnameport"`, `BindingCCS "ccs"`
  - Warnings (dump, server level): `WarnListTruncated "list_truncated"`, `WarnSharedConfig "win_shared_config"`, `WarnAutoCertRebind "win_autocertrebind"`, `WarnCCSEnabled "win_ccs_enabled"`, `WarnExpiredInStore "win_expired_in_store"`; location level `WarnCTL "win_ctl"`
  - `AppIDIIS = "{4dc3e181-e14b-4a21-b022-59fc669b0914}"` and `var KnownApps = map[string]string{AppIDIIS: "iis", "{afebb9ad-9b97-4a91-9ab5-daf4d59122f6}": "winrm", "{5d89a20c-beab-4389-9447-324788eb944a}": "adfs", "{ba195980-cd49-458b-9e23-c84ee0adcd75}": "sstp"}` **[W0: F8 — replace with the confirmed ids]**
  - Bounds of Ruling 20: `MaxBindings, MaxCertificates, MaxSites, MaxSiteBindings, MaxChainCerts, MaxCertDER, MaxAppcmdOutput, DumpOutput`, plus `MaxTokens = 16`, `MaxLineBytes = 4096`, `MaxText = 256` (names, friendly names, versions)
  - `type ErrorResponse struct{ OK bool `json:"ok"`; Code string `json:"code"`; Message string `json:"message"` }` and `type VersionResponse struct{ OK bool; Helper string; Protocol int }` with the JSON tags of `helperproto` (`ok`, `helper`, `protocol`) so `linuxssh.DecodeHelper` reads them.
  - `type IISFacts struct{ Installed bool `json:"installed"`; Version string `json:"version"`; SharedConfig bool `json:"shared_config"`; CCSEnabled bool `json:"ccs_enabled"`; CCSPath string `json:"ccs_path"`; AutoCertRebind bool `json:"autocertrebind"` }`
  - `type WinFactsResponse struct{ OK bool `json:"ok"`; OSBuild string `json:"os_build"`; OSProduct string `json:"os_product"`; InstallationType string `json:"installation_type"`; Elevated bool `json:"elevated"`; IIS IISFacts `json:"iis"`; Stores []string `json:"stores"`; OpenSSHVersion string `json:"openssh_version"` }`
  - `type SSLBinding struct{ Type, IP, Host string; Port int; AppID, CertSHA1, Store string; Flags, CertCheckMode, RevocationFreshnessTime, URLRetrievalTimeout uint32; CTLIdentifier, CTLStore string }` with tags `type, ip,omitempty, host,omitempty, port, app_id, cert_sha1, store, flags, cert_check_mode, revocation_freshness_time, url_retrieval_timeout, ctl_identifier,omitempty, ctl_store,omitempty` **[W0: F2 — add every field W0 found readable and settable (2022+ extended params such as the TLS 1.3/legacy TLS flags), named after the Win32 member]**
  - `type StoreCertificate struct{ Store, SHA1, SHA256, DER string; Chain []string; FriendlyName, NotAfter string; HasKey bool; KeyProvider string; KeyExportable bool; KeyUsableBySystem *bool; KeyProblem string }` with tags `store, sha1, sha256, der, chain, friendly_name, not_after, has_key, key_provider, key_exportable, key_usable_by_system, key_problem,omitempty` (DER and chain standard base64; chain = what `CertGetCertificateChain` built after the leaf, root excluded; `KeyProblem` "" | `key_missing` | `key_inaccessible`)
  - `type SiteBinding struct{ Protocol string `json:"protocol"`; Information string `json:"binding_information"`; SSLFlags int `json:"ssl_flags"` }`, `type Site struct{ Name string `json:"name"`; ID int64 `json:"id"`; State string `json:"state"`; Bindings []SiteBinding `json:"bindings"` }`
  - `type IISDumpResponse struct{ OK bool `json:"ok"`; IIS IISFacts `json:"iis"`; Bindings []SSLBinding `json:"bindings"`; Certificates []StoreCertificate `json:"certificates"`; Sites []Site `json:"sites"`; ExpiredInStore map[string]int `json:"expired_in_store"`; Warnings []string `json:"warnings"`; Truncated bool `json:"truncated"` }`
  - `type TLSProbeResponse = helperproto.TLSProbeResponse` (shared answer, design §7)
  - Validators: `func ValidToken(s string) bool`, `func SplitCommandLine(line string) ([]string, bool)`, `func JoinCommandLine(tokens []string) (string, bool)`, `func ValidSHA1(s string) bool` (40 lower hex), `func ValidAppID(s string) bool` (lower case, braces), `func CanonicalAppID(s string) (string, bool)` (accepts upper case or no braces, returns the lower braced form), `func ValidStore(s string) bool` (`^[A-Za-z0-9 ._-]{1,64}$`)
  - Journal phases `PhaseNone ... PhaseRestoreForbidden` with the values of `providers.Phase*` (`internal/providers/types.go:716-731`), declared now so the W2 journal and the test exist from protocol 1.

- [ ] **Step 1: Write the failing tests** in `winproto_test.go`:
  - `TestExitCodesAndPhasesEqualTheLinuxOnes`: each `winproto.Exit*` equals `helperproto.Exit*`; each `winproto.Phase*` equals `providers.Phase*` (the test may import `providers`; only the package may not).
  - `TestSplitCommandLine` table: `"version"` → `["version"]`; `"tls-probe --addr 10.0.0.5 --port 443 --sni www.example.com --key-type any"` → 9 tokens; refused (`ok == false`): `""`, `" version"`, `"version "`, `"a  b"`, `"a\tb"`, `"iis-dump \"x\""`, `"a&b"`, `"a|b"`, `"a%PATH%"`, `"a^b"`, `"a<b"`, 17 tokens, a 4097-byte line, a token of 254 bytes, non-ASCII `"ver\u00e7ion"`, NUL.
  - `TestJoinCommandLineRoundTrips`: `JoinCommandLine(SplitCommandLine(x))` is `x` for every accepted line above; a token that fails `ValidToken` is refused.
  - `TestCanonicalAppID`: `"{4DC3E181-E14B-4A21-B022-59FC669B0914}"` and `"4dc3e181-e14b-4a21-b022-59fc669b0914"` → `AppIDIIS`; `"{4dc3e181}"`, `"not-a-guid"` refused.
  - `TestDumpJSONShape`: a filled `IISDumpResponse` marshals with exactly the tags above (golden map of keys); `KeyUsableBySystem` nil marshals as `null`, `KeyProblem` "" is omitted.
  - `TestKnownAppsAreCanonical`: every key of `KnownApps` passes `ValidAppID`.
- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./internal/providers/windows/winproto/`
Expected: FAIL (package does not exist).
- [ ] **Step 3: Implement** `winproto.go` (package doc as `helperproto.go:1-4`: "standard library and helperproto only, because the Windows helper imports it"). Add the archtest rule and the floor.
- [ ] **Step 4: Run the tests**
Run: `go test -race -count=1 ./internal/providers/windows/winproto/ ./internal/archtest/ && go test -cover ./internal/providers/windows/winproto/`
Expected: PASS, coverage 100.0%.
- [ ] **Step 5: Commit**: `feat(winproto): protocol 1 of the Windows helper: subcommands, codes, dump shapes, forced-command vocabulary (R60)` with `internal/providers/windows/winproto/`, `internal/archtest/arch_test.go`, `coverage-floors.json`.

---

### Task 2: `winhelper` core: dispatch, elevation gate, budget, `version`, `win-facts`, `tls-probe`

**Files:**
- Create: `internal/providers/windows/winhelper/winhelper.go` (Host, Run, RunForced, reply), `internal/providers/windows/winhelper/facts.go`, `internal/providers/windows/winhelper/probe.go`, `internal/providers/windows/winhelper/winhelper_test.go`, `internal/providers/windows/winhelper/fakehost_test.go`
- Modify: `internal/archtest/arch_test.go` (rule `"alice/internal/providers/windows/winhelper": {"alice/internal/providers/windows/winproto", "alice/internal/providers/linuxssh/helperproto"}`), `coverage-floors.json` (`winhelper` 95)

**Interfaces:**
- Consumes: Task 1's `winproto` names.
- Produces:
  ```go
  type OSFacts struct{ Build, Product, InstallationType, OpenSSHVersion string }
  type Host interface {
      Elevated() (bool, error)
      OSFacts(ctx context.Context) (OSFacts, error)
      IISFacts(ctx context.Context) (winproto.IISFacts, error)
      Stores(ctx context.Context) ([]string, error)
      SSLBindings(ctx context.Context) ([]winproto.SSLBinding, error)
      // Certificate reads one certificate by store and SHA-1; found is false when the store has none.
      Certificate(ctx context.Context, store, sha1 string) (cert winproto.StoreCertificate, found bool, err error)
      ExpiredInStore(ctx context.Context, store string) (int, error)
      // AppcmdSites is the output of "appcmd list site /config /xml", at most winproto.MaxAppcmdOutput bytes.
      AppcmdSites(ctx context.Context) ([]byte, error)
      Dial(ctx context.Context, network, addr string) (net.Conn, error)
  }
  var ErrIISNotInstalled = errors.New("winhelper: IIS is not installed")
  // Run executes one call (args[0] is the subcommand) under winproto.HelperBudget, prints exactly one JSON line and
  // returns the exit code.
  func Run(ctx context.Context, h Host, args []string, stdin io.Reader, stdout io.Writer) int
  // RunForced is the "ssh" entry: it splits SSH_ORIGINAL_COMMAND with winproto.SplitCommandLine and runs it.
  func RunForced(ctx context.Context, h Host, originalCommand string, stdin io.Reader, stdout io.Writer) int
  ```
- Mirror: `cmd/alice-helper/run.go:14-121` (helperError, the command table with a per-command flag, `reply`, `writeJSON`, `cmdVersion`) with `privileged` replaced by `elevated`; `cmd/alice-helper/probe.go:21-55` for `tls-probe` (same fixed eight-argument vector and `helperproto` validators, `helperproto.ProbeTLSConfig`, `helperproto.ProbeChain`, a 15 s probe timeout variable tests lower).

- [ ] **Step 1: Write the failing tests** (`fakehost_test.go` holds a `fakeHost` with settable fields and error injection):
  - `TestRunVersion`: `Run(.., ["version"])` exits 0 with exactly `{"ok":true,"helper":"0.1.0","protocol":1}\n`; `["version","x"]` exits 2 `USAGE`.
  - `TestRunRefusesUnknownAndEmpty`: `[]` → 2 `USAGE`; `["iis-deploy"]` → 2 `UNKNOWN_SUBCOMMAND` (Ruling 2); `["ssh"]` through `Run` → 2 `UNKNOWN_SUBCOMMAND` (`ssh` is only the entry point).
  - `TestRunForcedSplitsTheOriginalCommand`: `RunForced(.., "version")` answers version; `RunForced(.., "version && whoami")`, `""`, `"version\x00"` → 2 `INVALID_ARGUMENT`, and the host is never called (the fake counts calls).
  - `TestElevationGate`: with `Elevated() == false`, `iis-dump` → 2 `NOT_ELEVATED` and no host read happens; `version`, `win-facts`, `tls-probe` still answer; `Elevated()` returning an error → 4 `IO_ERROR` for `iis-dump`.
  - `TestWinFacts`: the fake's OS, IIS and stores appear in `WinFactsResponse` with `elevated` true/false; a product of 300 bytes is cut to `MaxText` runes; control and bidi characters are dropped (the `cleanValue` rule of `internal/providers/linuxssh/dial.go:792`); `IISFacts` returning `ErrIISNotInstalled` gives `iis.installed:false` and exit 0.
  - `TestTLSProbe`: against a `httptest`-free `tls.Listen` on 127.0.0.1 with a `pki` leaf and SNI routing (two certificates by name): the answer's `leaf_sha256` is the right leaf for each `--sni`, `chain_length` 2, `chain` decodes with `helperproto.DecodeProbeChain`; a wrong vector → 2 `USAGE`; `--addr 10.0.0.300` → 2 `INVALID_ARGUMENT`; a refused dial → 4 `PROBE_FAILED`.
  - `TestBudgetEndsTheCall`: a host whose `SSLBindings` blocks until ctx ends, with the budget variable lowered to 50 ms → 4 `IO_ERROR`, within 1 s.
  - `TestAnswerIsOneLine`: every answer of the tests above is exactly one line ending in `\n` and decodes with `json.Decoder` with no trailing data.
- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./internal/providers/windows/winhelper/`
Expected: FAIL (package does not exist).
- [ ] **Step 3: Implement** the three files. `iis-dump` is registered in the command table but its handler returns `failed(CodeIOError, ...)` until Task 3. The budget is a package variable `commandBudget = winproto.HelperBudget`. Messages are fixed texts, never OS error text (run.go:14-21 rule).
- [ ] **Step 4: Run the tests**
Run: `go test -race -count=1 ./internal/providers/windows/winhelper/ ./internal/archtest/ && GOOS=windows go vet ./internal/providers/windows/...`
Expected: PASS.
- [ ] **Step 5: Commit**: `feat(winhelper): the Windows helper's platform-neutral core: forced-command split, elevation gate, budget, version, win-facts, tls-probe (R60)`.

---

### Task 3: `winhelper` `iis-dump`: assembly, bounds, appcmd XML **[W0: F2, F6]**

**Files:**
- Create: `internal/providers/windows/winhelper/dump.go`, `internal/providers/windows/winhelper/appcmd.go`, `internal/providers/windows/winhelper/dump_test.go`, `internal/providers/windows/winhelper/appcmd_test.go`, `internal/providers/windows/winhelper/testdata/appcmd-*.xml`
- Modify: `internal/providers/windows/winhelper/winhelper.go` (wire `iis-dump`)

**Interfaces:**
- Consumes: Task 2's `Host`.
- Produces: `func ParseAppcmdSites(xml []byte) ([]winproto.Site, error)` (only `https` bindings kept; `encoding/xml`, no DTD, no entity expansion beyond the standard five, input capped at `MaxAppcmdOutput`); `func BuildDump(ctx context.Context, h Host) (winproto.IISDumpResponse, error)` (called by the `iis-dump` handler; no arguments accepted).

- [ ] **Step 1: Write the failing tests**
  - `appcmd_test.go`, `TestParseAppcmdSites`: fixture `testdata/appcmd-two-sites.xml` (the shape of `appcmd list site /config /xml`: `<appcmd><SITE SITE.NAME=... SITE.ID=... STATE=...><site name= id=><bindings><binding protocol="https" bindingInformation="*:443:www.example.test" sslFlags="1"/>...`) gives two sites with their https bindings only (http dropped), ids and states; `sslFlags` absent → 0. Refused: a DOCTYPE (`<!DOCTYPE` anywhere → error), not well-formed XML, a site name of 300 bytes (cut to `MaxText` and cleaned), more than `MaxSites` sites (the first `MaxSites` kept, `truncated` returned through `BuildDump`). **[W0: F6 — replace the fixture with a captured 2022 and a 2025 output, and a Server Core one if W0 ran it]**
  - `dump_test.go`, `TestBuildDumpReadsEachCertificateOnce`: three bindings naming two (store, sha1) pairs → two `Certificate` calls, both certificates in the answer, ordered by (store, sha1).
  - `TestBuildDumpMissingCertificateIsNotAnError`: a binding whose certificate `found == false` stays in `bindings`, nothing in `certificates`.
  - `TestBuildDumpWithoutIIS`: `IISFacts` → `ErrIISNotInstalled`: `iis.installed:false`, `sites` empty, `AppcmdSites` never called, bindings still listed.
  - `TestBuildDumpAppcmdFailureFailsTheDump` (Ruling 12): IIS installed and `AppcmdSites` errors (or returns XML that does not parse) → `BuildDump` error → exit 4 `IO_ERROR`.
  - `TestDumpCutsAtItsBounds`: 1001 bindings → 1000 kept, `truncated:true`, `warnings` has `list_truncated`; 1001 distinct certificates likewise; a certificate DER over `MaxCertDER` or a chain over `MaxChainCerts` is dropped (the binding stays, the certificate is not listed) with `list_truncated`; the encoded answer over `DumpOutput` → exit 4 `OUTPUT_TOO_LARGE`.
  - `TestBuildDumpWarnings`: shared config, AutoCertRebind and CCS enabled facts give `win_shared_config`, `win_autocertrebind`, `win_ccs_enabled`; `ExpiredInStore` of `My` 3 and `WebHosting` 0 gives `expired_in_store {"My":3,"WebHosting":0}` and the warning `win_expired_in_store`.
  - `TestBuildDumpDropsInvalidRecords`: a binding with an invalid app id, a non-hex hash, an unknown type or port 0 is dropped and counted into `list_truncated` (never sent to Alice raw); a binding of type `ccs` keeps `cert_sha1` "".
- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./internal/providers/windows/winhelper/ -run 'Appcmd|BuildDump|DumpCuts'`
Expected: FAIL (undefined `ParseAppcmdSites`, `BuildDump`).
- [ ] **Step 3: Implement** `appcmd.go` and `dump.go`; read order of design §6.2 (bindings, certificates per distinct hash, sites, warning facts); stop with `IO_ERROR` once ctx is done.
- [ ] **Step 4: Run the tests**
Run: `go test -race -count=1 -cover ./internal/providers/windows/winhelper/`
Expected: PASS, coverage at least 95%.
- [ ] **Step 5: Commit**: `feat(winhelper): iis-dump: http.sys bindings, their certificates once each, IIS sites from appcmd XML, bounded with list_truncated (R60)`.

---

### Task 4: `cmd/alice-winhelper`: entry point, token elevation, OS and IIS facts **[W0: F3]**

**Files:**
- Create (every file `//go:build windows`): `cmd/alice-winhelper/main.go`, `cmd/alice-winhelper/host_windows.go` (the `Host` type and its facts methods), `cmd/alice-winhelper/token_windows.go`, `cmd/alice-winhelper/facts_windows_test.go`
- Modify: `internal/archtest/buildtags_test.go:450-482` (`TestReleaseBinariesLinkNoTestPackages`: add a `goListDeps` variant with `GOOS=windows` for `./cmd/alice-winhelper` and assert no `testOnlyImports`; new `TestWindowsHelperLinksOnlyItsProtocol`: its non-standard dependencies are exactly `golang.org/x/sys/windows`, `golang.org/x/sys/windows/registry` (and their internal packages), `alice/internal/providers/windows/winproto`, `alice/internal/providers/windows/winhelper`, `alice/internal/providers/linuxssh/helperproto`)

**Interfaces:**
- Consumes: `winhelper.Host`, `winhelper.Run`, `winhelper.RunForced`.
- Produces: `main()`: `alice-helper.exe ssh` → `winhelper.RunForced(ctx, newHost(), os.Getenv("SSH_ORIGINAL_COMMAND"), os.Stdin, os.Stdout)`; any other first argument (`version`, `win-facts`, ... for local runs by an administrator) → `winhelper.Run(ctx, newHost(), os.Args[1:], ...)`; exit with the returned code. `type host struct{...}` with `Elevated` (`windows.GetCurrentProcessToken().IsElevated()`), `OSFacts` (registry `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`: `CurrentMajorVersionNumber`, `CurrentMinorVersionNumber`, `CurrentBuildNumber`, `UBR`, `ProductName`, `InstallationType`; OpenSSH version from the `ProductVersion` of `%windir%\System32\OpenSSH\sshd.exe`'s version resource, "" when absent), `IISFacts` (`HKLM\SOFTWARE\Microsoft\InetStp` `MajorVersion`/`MinorVersion`, missing key → `ErrIISNotInstalled`; shared configuration from `%windir%\system32\inetsrv\config\redirection.config`'s `enabled` attribute, read with `encoding/xml`; CCS from `HKLM\SOFTWARE\Microsoft\IIS\CentralCertProvider` `Enabled`/`CertStoreLocation`; AutoCertRebind from the `Enabled` element of the task XML `%windir%\System32\Tasks\Microsoft\Windows\CertificateServicesClient\AutoCertRebind`, read with `encoding/xml`), `Stores` (the system stores `My`, `WebHosting`, `CA`, `Root` that open with `CERT_STORE_OPEN_EXISTING_FLAG|CERT_STORE_READONLY_FLAG` in `CERT_SYSTEM_STORE_LOCAL_MACHINE`), `Dial` (`net.Dialer{Timeout: 5 s}`). **[W0: F3 — use the elevation check W0 confirmed for a key-based OpenSSH logon; if W0 found AutoCertRebind or shared configuration easier to read another way, use that]**
- Mirror: `cmd/alice-helper/main.go:25-29` (no init magic; `keepRunning` has no Windows counterpart: a dropped SSH channel on Windows closes the pipes, writes then fail, which `writeJSON` ignores).

- [ ] **Step 1: Write the failing tests** (`facts_windows_test.go`, run only on Windows; `t.Skip` unless `ALICE_WIN_REAL=1`, so a developer's Windows box does not run them by accident; the workflow of Task 11 sets it and fails on a skip):
  - `TestRealHostIsElevated`: on the runner (an elevated administrator) `Elevated()` is true.
  - `TestRealOSFactsMatchTheRegistryReadIndependently`: `OSFacts` equals what `Get-CimInstance Win32_OperatingSystem` (run with `exec.Command("powershell", ...)` in the test only) reports for `Version`/`BuildNumber` and caption; `InstallationType` is `Server`.
  - `TestRealIISFacts`: after the workflow installed IIS, `Installed` true and `Version` `10.0`.
  - `TestMainRefusesAShellLine`: run the built binary (`go build -o` into `t.TempDir()`) with `ssh` and `SSH_ORIGINAL_COMMAND="version & whoami"` → exit 2, `INVALID_ARGUMENT`; with `version` → protocol 1.
- [ ] **Step 2: Run them to verify they fail to build**
Run: `GOOS=windows go vet ./cmd/alice-winhelper/`
Expected: FAIL (undefined `newHost`, ...).
- [ ] **Step 3: Implement** the three files (`SSLBindings`, `Certificate`, `ExpiredInStore` and `AppcmdSites` return a "not implemented" error until Task 5; the tests above do not call them). Every `windows` call result is checked; no error text reaches the answer.
- [ ] **Step 4: Verify**
Run: `GOOS=windows GOARCH=amd64 go build -o /dev/null ./cmd/alice-winhelper/ && GOOS=windows GOARCH=arm64 go build -o /dev/null ./cmd/alice-winhelper/ && GOOS=windows go vet ./cmd/alice-winhelper/ && go test -count=1 ./internal/archtest/`
Expected: PASS (the real-host tests run in Task 11's workflow).
- [ ] **Step 5: Commit**: `feat(alice-winhelper): the Windows helper's entry point (forced command), token elevation and OS, IIS and store facts (R60)`.

---

### Task 5: `cmd/alice-winhelper`: http.sys bindings, certificate stores, appcmd **[W0: F2, F3, F4, F6, F8]**

**Files:**
- Create (`//go:build windows`): `cmd/alice-winhelper/httpapi_windows.go` (hand-written binding), `cmd/alice-winhelper/stores_windows.go`, `cmd/alice-winhelper/appcmd_windows.go`, `cmd/alice-winhelper/stores_windows_test.go`, `cmd/alice-winhelper/httpapi_windows_test.go`
- Modify: `cmd/alice-winhelper/host_windows.go` (wire the four methods)

**Interfaces:**
- Produces (unexported):
  - `httpapi_windows.go`: `windows.NewLazySystemDLL("httpapi.dll")` procs `HttpInitialize`, `HttpQueryServiceConfiguration`, `HttpTerminate`; the structs `HTTP_SERVICE_CONFIG_SSL_QUERY`, `HTTP_SERVICE_CONFIG_SSL_SNI_QUERY`, `HTTP_SERVICE_CONFIG_SSL_CCS_QUERY`, `HTTP_SERVICE_CONFIG_SSL_SET` (and the SNI/CCS variants), `HTTP_SERVICE_CONFIG_SSL_PARAM` laid out exactly as `http.h` (pointer-sized fields as `uintptr`, the SNI key's `SOCKADDR_STORAGE` as a 128-byte array); `func sslBindings() ([]winproto.SSLBinding, error)` enumerates with `HttpServiceConfigQueryNext` and `dwToken` 0,1,2... for each of the three config ids until `ERROR_NO_MORE_ITEMS`, growing the buffer on `ERROR_INSUFFICIENT_BUFFER`, bounded at `MaxBindings + 1` records per id; hash bytes → lower hex SHA-1, store name `UTF-16` → string (empty → `My`, http.sys's default), app id GUID → `winproto.CanonicalAppID`. `HttpInitialize(HTTPAPI_VERSION_1, HTTP_INITIALIZE_CONFIG)` once per call, `HttpTerminate` deferred. **[W0: F2 — exact struct layouts, the extended parameters to read on 2022/2025, and whether `HttpServiceConfigSslCertInfoEx`/`...SniCertInfoEx` must be used]**
  - `stores_windows.go`: `func certificate(store, sha1 string) (winproto.StoreCertificate, bool, error)`: `CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_LOCAL_MACHINE|CERT_STORE_OPEN_EXISTING_FLAG|CERT_STORE_READONLY_FLAG, store)`, `CertFindCertificateInStore(..., CERT_FIND_SHA1_HASH, ...)`; DER and its SHA-256; friendly name (`CERT_FRIENDLY_NAME_PROP_ID`); chain with `CertGetCertificateChain(HCCE_LOCAL_MACHINE, ...)` taking the simple chain's elements after the leaf, dropping a self-signed last element; key facts with `CryptAcquireCertificatePrivateKey(CRYPT_ACQUIRE_SILENT_FLAG|CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG|CRYPT_ACQUIRE_CACHE_FLAG)`: none → `has_key:false`, `key_problem:key_missing`; provider name and `NCRYPT_EXPORT_POLICY_PROPERTY` via `NCryptGetProperty`; `key_usable_by_system`: **[W0: F3/F4 — the check W0 confirmed (the key's security descriptor `NCRYPT_SECURITY_DESCR_PROPERTY` granting SYSTEM read, or nil when not decidable); `key_problem:key_inaccessible` when it is false]**. `func expiredInStore(store string) (int, error)` counts certificates with `NotAfter` before now.
  - `appcmd_windows.go`: `func appcmdSites(ctx) ([]byte, error)`: `exec.CommandContext` on the absolute `%windir%\system32\inetsrv\appcmd.exe` (`windows.GetSystemDirectory` + `inetsrv\appcmd.exe`, never `PATH`), arguments exactly `list site /config /xml`, empty environment except `SystemRoot`, 30 s timeout, stdout capped at `MaxAppcmdOutput`, stderr discarded; a missing appcmd while IIS is installed is an error (Ruling 12). **[W0: F6]**
- Mirror: the Linux helper's guarded program run, `cmd/alice-helper/program.go:60-67` (fixed program, fixed arguments, capped output).

- [ ] **Step 1: Write the failing tests** (Windows only, `ALICE_WIN_REAL=1`; each creates and removes its own fixtures with names prefixed `alice-w1-` and ports 44300-44399):
  - `TestRealBindingsListAnSNIAndAnIPBinding`: the test imports a `pki` leaf with its key into `LocalMachine\My` (PowerShell `Import-PfxCertificate` from the test, never from the helper), adds `netsh http add sslcert hostnameport=alice-w1.test:44301 certhash=<sha1> appid=<AppIDIIS> certstorename=MY` and `ipport=0.0.0.0:44302`; `sslBindings()` contains both with the hash, store `MY`/`My` normalised as http.sys reports it, app id canonical; cleanup deletes both.
  - `TestRealCertificateFacts`: for the imported leaf: DER SHA-256 equals the `pki` leaf's, `chain` holds the intermediate (the test adds it to `LocalMachine\CA`), `has_key` true, provider `Microsoft Software Key Storage Provider` or what W0 found **[W0: F4]**; a certificate imported without its key (`Import-Certificate` of the `.cer`) → `key_problem:key_missing`; an absent hash → `found:false`.
  - `TestRealAppcmdSites`: a site `alice-w1-site` with binding `https *:44301:alice-w1.test` sslFlags 1 (created with `appcmd add site` and `appcmd set site` from the test) appears in `ParseAppcmdSites(appcmdSites())`.
  - `TestRealForeignBinding`: an `ipport=0.0.0.0:44303` entry with the WinRM app id of `KnownApps` is listed with that id. **[W0: F8]**
- [ ] **Step 2: Run them to verify they fail to build**
Run: `GOOS=windows go vet ./cmd/alice-winhelper/`
Expected: FAIL (undefined `sslBindings`, `certificate`, `appcmdSites`).
- [ ] **Step 3: Implement** the three files and wire them into `host`.
- [ ] **Step 4: Verify**
Run: `GOOS=windows GOARCH=amd64 go build -o /dev/null ./cmd/alice-winhelper/ && GOOS=windows GOARCH=arm64 go build -o /dev/null ./cmd/alice-winhelper/ && GOOS=windows go vet ./cmd/alice-winhelper/`
Expected: PASS (the real tests run on the runner, Task 11).
- [ ] **Step 5: Commit**: `feat(alice-winhelper): http.sys SSL bindings through httpapi.dll, machine store certificates with chain and key facts, IIS sites through appcmd (R60)`.

---

### Task 6: Build: `make winhelper`, checksums, image, reproducibility, Windows lint

**Files:**
- Modify: `Makefile:104-114` (`WINHELPER_SUM`, `WINHELPER_LDFLAGS`, `build: web helper winhelper` and its checksum guard for both files), `Makefile:190-194` (new `winhelper` target after `helper`), `Makefile:216-219` (`image-check` passes `WINHELPER_SHA256_AMD64/ARM64`), `Makefile:300-312` (`lint` adds `GOOS=windows golangci-lint run ./cmd/alice-winhelper/... ./internal/providers/windows/...`)
- Modify: `deploy/Dockerfile:23-38` (build both Windows helpers for their checksums, refuse an image without them, add the two `-X` flags), `deploy/dev/reproducible-check.sh:23-40` (the two `.exe` files built and compared, sums into alice's ldflags), `deploy/dev/check-image.sh` (the Windows checksums embedded in the image equal the given ones, like the Linux ones)
- Create: `internal/providers/windows/checksums.go` (`var helperSHA256WindowsAMD64, helperSHA256WindowsARM64 string`; `func HelperChecksumsKnown() bool`), `internal/providers/windows/checksums_test.go`

**Interfaces:**
- Produces: `make winhelper` → `bin/alice-winhelper-windows-amd64.exe`, `bin/alice-winhelper-windows-arm64.exe`, `bin/alice-winhelper.sha256` (two `sha256sum` lines); `WINHELPER_LDFLAGS = -X alice/internal/providers/windows.helperSHA256WindowsAMD64=$(call WINHELPER_SUM,amd64) -X alice/internal/providers/windows.helperSHA256WindowsARM64=$(call WINHELPER_SUM,arm64)`; `windows.HelperChecksumsKnown()`.
- Mirror: the `helper` target, `Makefile:190-194` (`CGO_ENABLED=0 GOOS=windows GOARCH=amd64 GOAMD64=v1 go build -trimpath -buildvcs=false -ldflags "-s -w" -o bin/alice-winhelper-windows-amd64.exe ./cmd/alice-winhelper`; arm64 with `GOARM64=v8.0`); `linuxssh.HelperChecksumsKnown`, `internal/providers/linuxssh/setup.go:178-216`.

- [ ] **Step 1: Write the failing test** `checksums_test.go`, `TestHelperChecksumsKnown`: false with the variables empty or one of them not 64 lower hex; true with both set (the test sets and restores them).
- [ ] **Step 2: Run it to verify it fails**
Run: `go test ./internal/providers/windows/ -run Checksums`
Expected: FAIL (package has no such function).
- [ ] **Step 3: Implement** the Makefile, Dockerfile and script changes and `checksums.go` (package `windows` doc: "the Windows server provider (design 2026-10-21-windows-iis-target-design.md §8)").
- [ ] **Step 4: Verify**
Run: `make winhelper && cat bin/alice-winhelper.sha256 && make winhelper && sha256sum -c bin/alice-winhelper.sha256 && make build && go version -m bin/alice >/dev/null && ./deploy/dev/reproducible-check.sh && GOOS=windows golangci-lint run ./cmd/alice-winhelper/... ./internal/providers/windows/... && go test -count=1 ./internal/providers/windows/`
Expected: two identical builds (checksums pass), `reproducible-check` reports equal bytes for every file, lint clean.
- [ ] **Step 5: Commit**: `build: make winhelper builds alice-helper.exe for Windows amd64 and arm64 reproducibly; its checksums are linked into alice and the image (R60)`.

---

### Task 7: `wintest`: the emulated Windows host

**Files:**
- Create: `internal/providers/windows/wintest/model.go` (model and `winhelper.Host`), `internal/providers/windows/wintest/tls.go` (listeners with http.sys's selection), `internal/providers/windows/wintest/server.go` (`Handler`, `NewServer`), `internal/providers/windows/wintest/demo.go` (the fixed demo host of e2e), `internal/providers/windows/wintest/wintest_test.go`
- Modify: `internal/providers/linuxssh/linuxsshtest/server.go:138-155` (extract `func Listen(addr string, hostKey ssh.Signer, h Handler) (*Server, error)` and `func (s *Server) Close()`; `NewServer` calls `Listen` with `NewHostKey(t)` and registers `Close` as cleanup; behaviour unchanged)
- Modify: `internal/archtest/buildtags_test.go:34-57` (`testOnlyImports` and `testOnlyDirs` add `alice/internal/providers/windows/wintest`), `internal/archtest/arch_test.go` (rule `"alice/internal/providers/windows/wintest": {platform, "alice/internal/providers/windows/...", "alice/internal/providers/linuxssh/linuxsshtest", "alice/internal/providers/linuxssh/helperproto"}` plus `alice/internal/testutil/pki` if `demo.go` uses it), `coverage-floors.json` (`wintest` 90)

**Interfaces:**
- Consumes: `winhelper.Host`, `winhelper.RunForced`, `winproto.*`, `linuxsshtest.Server`.
- Produces:
  ```go
  type Model struct{ /* mutex-guarded state */ }
  func NewModel() *Model                                  // elevated, Server 2022 Datacenter facts, IIS 10.0 installed, stores My WebHosting CA Root
  func (m *Model) SetOS(f winhelper.OSFacts)
  func (m *Model) SetElevated(bool)
  func (m *Model) SetIIS(f winproto.IISFacts)            // Installed false: AppcmdSites refuses with winhelper.ErrIISNotInstalled
  func (m *Model) AddCertificate(store string, chainPEM, keyPEM []byte, o CertOptions) (sha1 string) // keyPEM nil: no key
  type CertOptions struct{ FriendlyName string; KeyProvider string; Exportable bool; KeyUsableBySystem *bool }
  func (m *Model) AddIntermediate(certPEM []byte)        // LocalMachine\CA: the chain the model builds
  func (m *Model) RemoveCertificate(store, sha1 string)
  func (m *Model) AddBinding(b winproto.SSLBinding)
  func (m *Model) AddSite(s winproto.Site)
  func (m *Model) SetExpired(store string, n int)
  func (m *Model) FailAppcmd(bool)
  func (m *Model) SetHelperMissing(bool)                 // every line: exit 1, text on stderr only (cmd.exe's "is not recognized")
  func (m *Model) SetNoForcedCommand(bool)               // the login shell runs the line: same answer as missing (Review Focus 5)
  func (m *Model) SetProtocol(p int)                     // version answers p
  func (m *Model) Delay(sub string, d time.Duration)     // a slow subcommand
  func (m *Model) Host() winhelper.Host
  func (m *Model) Handler() linuxsshtest.Handler         // winhelper.RunForced on the model
  func (m *Model) Serve(ctx context.Context, bind string) error // one TLS listener per distinct binding port on bind (127.0.0.1 in tests, 0.0.0.0 in the container)
  func (m *Model) Endpoint(port int) string              // the listener's real address for a binding port (tests use random ports)
  func (m *Model) Served(ip string, port int, sni string) (leafSHA256 string, chainLength int, ok bool)
  func NewServer(t testing.TB, m *Model) *linuxsshtest.Server // with m.Serve and cleanup
  func Demo(now time.Time) (*Model, error)               // the e2e host of Task 15
  ```
  `Model.Dial` maps a binding address `ip:port` to `Endpoint(port)`, so the helper's `tls-probe` through the model reaches the model's listeners. TLS selection mirrors http.sys: a `hostnameport` entry for (SNI, port), else an `ipport` entry for (ip, port), else `0.0.0.0:port` (and `[::]:port`), else `ccs` (served as no certificate: handshake failure); a binding whose certificate is missing or whose key is missing or not usable by SYSTEM fails the handshake (design §11 "key unusable").
- Mirror: `internal/providers/linuxssh/linuxsshtest/emulator.go:45-120, 251-266, 344-432` (state, `Handler`, `answer`/`refuse`), `nginx_probe.go:56-195` (served selection), `server.go:24-46` (`Response`).

- [ ] **Step 1: Write the failing tests** (`wintest_test.go`, real SSH through `linuxssh.Dialer` is Task 8; here the handler is called directly):
  - `TestModelDumpMatchesWhatWasAdded`: two certificates, an SNI, an IP, a WinRM and a ccs binding, two sites; `Handler()("iis-dump", nil)` decodes to those bindings, the two certificates with chains (the intermediate added), the sites.
  - `TestModelElevationAndFaults`: `SetElevated(false)` → `iis-dump` exit 2 `NOT_ELEVATED`; `FailAppcmd(true)` → exit 4 `IO_ERROR`; `SetHelperMissing(true)` → exit 1, empty stdout, stderr text; `SetProtocol(0)` → version protocol 0; `Delay("iis-dump", d)` delays the answer.
  - `TestModelServesHTTPSysSelection`: after `Serve`, a real `tls.Dial` to `Endpoint(443)` with SNI `www.example.test` gets the SNI binding's leaf; without SNI gets the `0.0.0.0:443` binding's leaf; a key-missing binding's port fails the handshake; `Served` agrees with every dial.
  - `TestModelTLSProbeThroughTheHelperCode`: `Handler()("tls-probe --addr 127.0.0.1 --port 443 --sni www.example.test --key-type any", nil)` answers the same leaf and chain as the direct dial.
  - `TestDemoHost`: `Demo` builds the host Task 15 documents (sites, bindings, certificates, foreign WinRM entry, ccs entry) without error.
  - `linuxsshtest`: the existing package tests stay green unchanged (proof that `NewServer` did not move).
- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./internal/providers/windows/wintest/`
Expected: FAIL (package does not exist).
- [ ] **Step 3: Implement** the files and the `linuxsshtest.Listen` extraction.
- [ ] **Step 4: Run the tests**
Run: `go test -race -count=1 -cover ./internal/providers/windows/wintest/ ./internal/providers/linuxssh/... ./internal/archtest/`
Expected: PASS, wintest coverage at least 90%.
- [ ] **Step 5: Commit**: `test(wintest): emulated Windows host: http.sys bindings, machine stores and IIS sites answered by the helper's own code, real TLS listeners with http.sys selection (R60)`.

---

### Task 8: Provider: `linuxssh.ForcedCommand`, `Open`, `TestConnection`, errors, registration

**Files:**
- Modify: `internal/providers/linuxssh/command.go:21-34, 334-361` (field `bare bool`; `Line()` renders a bare command as its tokens joined by one space, no `sudo -n`, no helper path; new constructor below), `internal/providers/linuxssh/command_test.go`
- Modify: `internal/providers/types.go:17-26` (`ConnectionReport.Windows *WindowsFacts`; new `type WindowsFacts struct{ Build, Product, InstallationType string; Elevated, IISInstalled bool; IISVersion string; Stores []string; OpenSSHVersion string }` with JSON tags `build, product, installation_type, elevated, iis_installed, iis_version, stores, openssh_version`), `internal/providers/types.go:247-262` (`WebServerFacts.Software` comment: "or `iis` on a Windows server")
- Create: `internal/providers/windows/provider.go`, `internal/providers/windows/config.go`, `internal/providers/windows/errors.go`, `internal/providers/windows/provider_test.go`, `internal/providers/windows/helpers_test.go`
- Modify: `cmd/alice/providers.go:25-45` (register `windows.New(windows.Options{Pool: sshPool, AllowUnverifiedHelper: dev})`, the checksum warning extended to the Windows helper), `cmd/alice/wiring.go:12` (`providers.KindWindows` in `shippedProviders`), `cmd/alice/wiring_test.go:257` (assert it), `coverage-floors.json` (`windows` 95)

**Interfaces:**
- Consumes: `linuxssh.Pool.Acquire/AcquireFresh` (`internal/providers/linuxssh/pool.go:152-160`), `linuxssh.Config`, `(*linuxssh.Conn).Run` (`dial.go:638`), `linuxssh.DecodeHelper` (`dial.go:899`), `winproto`, `wintest.NewServer`.
- Produces:
  ```go
  // linuxssh: one audited constructor for a target whose sshd forces every session to one program (a Windows
  // server's alice-helper.exe): the line is the subcommand and its arguments, nothing else.
  func ForcedCommand(tokens []string, stdin []byte, timeout time.Duration, maxOutput int64) (HelperCommand, error)
  // each token ^[A-Za-z0-9._:@+-]{1,253}$, 1..16 tokens, line <= 4096 bytes; else ErrInvalidArgument. stdin copied (owned).

  package windows
  const DefaultUser = "alice"
  type Options struct{ Pool *linuxssh.Pool; AllowUnverifiedHelper bool }
  func New(o Options) *Provider                     // Kind KindWindows, DisplayNameKey "provider.windows.name", caps test_connection + discover_certificates
  func ParseConfig(cfg providers.TargetConfig) (linuxssh.Config, []validate.FieldError) // host, port (22), username (DefaultUser), Ruling 1's rule
  func ValidUser(s string) bool
  func (p *Provider) ConfigSchema() providers.ConfigSchema   // host, port, username with labels provider.windows.fields.*
  func (p *Provider) CredentialSchema() providers.CredentialSchema // empty: the platform key
  func (p *Provider) Open(ctx, t, cred, env) (providers.Session, error)
  func (p *Provider) ForgetTarget(id uuid.UUID)             // providers.ConnectionCache through the pool
  // errors.go
  func mapHelper(err error) error                            // Ruling 13
  func cmd(sub string, args ...string) (linuxssh.HelperCommand, error) // winproto.JoinCommandLine check, then linuxssh.ForcedCommand
  ```
  Command budgets: `version` and `win-facts` `linuxssh.DefaultCommandTimeout` and 64 KiB; `iis-dump` `linuxssh.LongCommandTimeout` and `winproto.DumpOutput`; `tls-probe` the default timeout and 128 KiB.
- Mirror: `linuxssh.(*Provider).Open` (`internal/providers/linuxssh/provider.go:97-125`: config check `target.invalid_config`, `Acquire`/`AcquireFresh` by `env.FreshConnection`, `version` decoded, `MinProtocol` check, session struct with `release`), `session.Close/open` (`provider.go:144-159`), `session.TestConnection` (`provider.go:163-182`), `linuxssh.ParseConfig` (`dial.go:98-130`), `TestProviderConformance` (`internal/providers/linuxssh/provider_test.go:133`), the env of `internal/providers/nginx/helpers_test.go:156-260` (fake credential, `memHostKeys`, a real `linuxssh.Dialer` + `Pool` against the emulator server).

- [ ] **Step 1: Write the failing tests**
  - `command_test.go`, `TestForcedCommandLine`: `ForcedCommand([]string{"iis-dump"}, nil, ...)` has `Line() == "iis-dump"` and `Subcommand() == "iis-dump"`; with `tls-probe` and its eight arguments, the line is the nine tokens joined by single spaces; refused: a token with a space, quote, `&`, `%`, an empty token, 17 tokens; `Format`/`LogValue` print the line only (stdin never), as `TestDeployKeyIsNeverOutsideStdin` (`internal/providers/linuxssh/command_test.go:257`) does for the Linux commands.
  - `provider_test.go`:
    - `TestWindowsProviderDescribesItself` and `TestWindowsConformance`: `providertest.CheckProvider`; `providertest.CheckUnsupported` on an open session with the two capabilities.
    - `TestParseConfigTakesDomainAccounts` (Review Focus 1): `alice`, `CORP\alice-svc`, `A1\b.c-d_e` accepted and kept verbatim; `corp\`, `\alice`, `a\b\c`, `alice@corp.example`, a 16-character domain, a 21-character name, `ali ce`, `al'ice` refused (`username`, `validate.Pattern`); a missing username is `alice`; port default 22.
    - `TestOpenSendsBareCommands`: against `wintest.NewServer`, `Open` then `TestConnection`: the server's `Commands()` are exactly `["version", "win-facts"]` (no `sudo`, no path) and the SSH user is the configured one.
    - `TestTestConnectionReport`: host key = the server's; helper `0.1.0`, protocol 1; `OS{ID:"windows", VersionID:<build>, PrettyName:<product>}`; `Windows` facts from the model; `WebServer{Software:"iis", Version:"10.0", Found:true, ConfigValid:true}`; without IIS: `Found:false` and the warning `web_server_not_found`.
    - `TestOpenHelperMissing`: `SetHelperMissing(true)` → `*providers.Error` code `windows.helper_missing`, param `exit_code` `1`.
    - `TestOpenWithoutForcedCommandIsHelperMissing` (Review Focus 5): `SetNoForcedCommand(true)` → `windows.helper_missing`, and the server saw exactly one command, `version`.
    - `TestOpenHelperOutdated`: `SetProtocol(0)` → `windows.helper_outdated` with `helper_protocol` 0, `required_protocol` 1.
    - `TestTestConnectionNotElevated`: `SetElevated(false)` → `windows.not_elevated`.
    - `TestUnknownSubcommandIsOutdated`: a helper answering `UNKNOWN_SUBCOMMAND` to `win-facts` (model hook) → `windows.helper_outdated`.
    - `TestOpenRefusesAnInvalidConfig`, `TestAClosedSessionRunsNothing`, `TestOpenWithFreshConnectionDials`, `TestHostKeyChangedRefuses` (a re-keyed server → `target.host_key_changed`, from the shared dial): as the Linux tests of the same names.
  - `cmd/alice/wiring_test.go`: `KindWindows` is shipped and registered.
- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./internal/providers/linuxssh/ -run ForcedCommand && go test ./internal/providers/windows/ ./cmd/alice/ -run 'Windows|Wiring|Shipped'`
Expected: FAIL (undefined `ForcedCommand`, `windows.New`).
- [ ] **Step 3: Implement.** `Open` keeps the session's `version` answer (helper version cleaned to 40 runes) and the target's host for later probes; `TestConnection` decodes `win-facts` and fills the report (Ruling 19, cleaned strings, at most 16 stores). `providers.types.go` gains `WindowsFacts`; the `providers` package keeps 100% coverage (add a JSON round-trip test in `internal/providers/providers_test.go`).
- [ ] **Step 4: Run the tests**
Run: `go build ./... && go test -race -count=1 ./internal/providers/... ./cmd/alice/ && go test -run TestNoCodeAcceptsAnyHostKey ./internal/providers/linuxssh/`
Expected: PASS.
- [ ] **Step 5: Commit**: `feat(providers/windows): a Windows server over OpenSSH with the forced command: bare helper lines on the shared pool and host-key pinning, connection test with its facts, helper missing, outdated and not elevated named (R60)`.

---

### Task 9: Provider `Discover`: http.sys bindings become locations **[W0: F8]**

**Files:**
- Create: `internal/providers/windows/discover.go`, `internal/providers/windows/convert.go`, `internal/providers/windows/discover_test.go`, `internal/providers/windows/convert_test.go`

**Interfaces:**
- Consumes: `winproto.IISDumpResponse`, Rulings 6-9, 20.
- Produces: `session.Discover(ctx, req)`: `req.Certificates` false → `providers.ErrUnsupported` when `req.SSHKeys` is false too, else an empty result (a Windows server has no SSH half; the discovery job always asks `SSHKeys: true`); otherwise `iis-dump` → `convert(d)`.
  ```go
  func convert(d winproto.IISDumpResponse) (certs []providers.DiscoveredCertificate, warns []providers.Warning, facts providers.WebServerFacts)
  func canonical(b winproto.SSLBinding) (text string, loc providers.Locator, ok bool)
  func parseSiteBinding(info string, sslFlags int) (siteKey, bool)   // ip, port, host, sni, ccs
  ```
  Each location: `Kind: providers.LocationWinSSLBinding`, `Locator`, `CertPath` canonical text, `Servers` (`Names` = [host] or none, `Listens` = [{Addr: ip or "*", Port}], `Section` = site name; at most 500 per location, more → `list_truncated` on the location), `Supported`/`Unsupported` by Ruling 8, `Problem`/`KeyProblem` by Ruling 9, `Warnings` (`win_ctl`), `Details` (`store`, `cert_sha1`, `app_id`, `application`, `friendly_name`, `key_provider`, `key_exportable`, `key_usable_by_system`, `flags`, `cert_check_mode`, `ctl_identifier`, `ctl_store`; must pass `providers.CanonicalDetails`), `PEMChain` = leaf then `chain` re-encoded as PEM (only when the certificate is listed and decodes), `FileSHA256` = the leaf's DER SHA-256 (the CAS token, `internal/providers/types.go:502-507`). Result: `WebServer` = `facts` (`Software "iis"`, `Version`, `Found = iis.installed`, `ConfigValid true`), dump warnings passed through when they match `^[a-z][a-z_]{0,39}$` (others dropped; `win_expired_in_store` with param `count` = the sum), `web_server_not_found` when IIS is not installed, `list_truncated` **and** `locations_dropped` when the dump was truncated or convert dropped a binding.
- Mirror: `webserver.(*Session).Discover` (`internal/providers/webserver/webserver.go:276-317`), `convert` and its helpers (`internal/providers/webserver/convert.go:66-112` cleaning, `168-206` servers, `208-286` grouping, `479+` warnings); tests mirror `internal/providers/nginx/discover_test.go:23-475`.

- [ ] **Step 1: Write the failing tests**
  - `convert_test.go`, `TestCanonical` table: hostnameport `WWW.Example.COM:443` → `http.sys/hostnameport/www.example.com:443`, locator host folded; ipport `0.0.0.0:443`; ipport `::` → `http.sys/ipport/[::]:443`; ipport `::ffff:10.0.0.5` → unmapped `10.0.0.5`; ccs 443 → `http.sys/ccs/443`; an invalid IP, port 0 or 70000, a host with `/` → not ok.
  - `TestDiscoverMatchesIISBindings` (Review Focus 4), table of (http.sys entries, IIS bindings) → servers per location: `*:443:www.example.com` sslFlags 1 against `hostnameport www.example.com:443`; `*:443:WWW.EXAMPLE.COM` sslFlags 1 against the same (folded); `*:443:` sslFlags 0 against `0.0.0.0:443` and against `[::]:443`; `10.0.0.5:443:` against `10.0.0.5:443` when present, else against `0.0.0.0:443`; `[2001:db8::1]:443:` against its own entry; `*:443:` sslFlags 3 (SNI+CCS) against `ccs:443`; sslFlags 1 with an empty host (IIS refuses it, a hostile dump) → no match, the binding is dropped with `list_truncated`.
  - `TestDiscoverSupportedRules` (Ruling 8 order): ccs → `win_ccs`; an entry no IIS binding uses with the WinRM id → `win_foreign_app`, details `application` `winrm`; with an unknown id → `win_foreign_app`, `application` ""; store `Root` → `win_store_unsupported`; store `webhosting` (lower case) supported; a CTL identifier → supported with the location warning `win_ctl`.
  - `TestDiscoverProblems` (Ruling 9): a binding whose certificate is not listed → `Problem cert_missing`, no `PEMChain`, `FileSHA256` ""; `key_problem key_missing` → `KeyProblem key_missing`, `PEMChain` present; an IIS https binding with no entry → a location with the IIS app id in its locator and `cert_missing`.
  - `TestDiscoverCertificateChainAndToken`: `PEMChain` parses to leaf + intermediate; `FileSHA256` equals `sha256(DER)`; a `der` that is not base64 or not a certificate → `Problem not_a_certificate` (the existing code), no `PEMChain`, no `FileSHA256`.
  - `TestDiscoverWithoutIISListsForeignBindings` (Review Focus 3): model with IIS not installed and a WinRM entry → one location, unsupported `win_foreign_app`, `WebServer.Found` false, warning `web_server_not_found`.
  - `TestDiscoverTruncatedDumpDropsLocations` (Review Focus 2): a dump with `truncated:true` → warnings carry both `list_truncated` and `locations_dropped`.
  - `TestDiscoverCleansHostileText`: a site name and friendly name with `\x1b[31m`, U+202E and 300 bytes → cleaned and cut to 253/256; an app id `{BAD}` → the binding dropped with `list_truncated`; a dump of 1000 bindings with 500+ servers on one → servers cut at 500 with the location warning `list_truncated`.
  - `discover_test.go`, `TestDiscoverListsBindingsWithSites` (end to end over SSH with `wintest.NewServer`): the demo-like model gives the expected locations; `TestDiscoverNotElevated` → `windows.not_elevated`; `TestDiscoverAppcmdFailure` → `ssh.helper_refused` with `helper_code IO_ERROR`, retryable; `TestDiscoverIgnoresTheSSHHalf`: `DiscoverRequest{SSHKeys: true, Certificates: true}` sends only `iis-dump` (after `version`), and `DiscoverRequest{SSHKeys: true}` sends nothing and returns an empty result.
- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./internal/providers/windows/ -run 'Discover|Canonical'`
Expected: FAIL (undefined `convert`, `canonical`).
- [ ] **Step 3: Implement** `discover.go` and `convert.go`. Deterministic output: locations sorted by canonical text, servers by (site, binding information).
- [ ] **Step 4: Run the tests**
Run: `go test -race -count=1 -cover ./internal/providers/windows/`
Expected: PASS, coverage at least 95%.
- [ ] **Step 5: Commit**: `feat(providers/windows): discovery: every http.sys SSL binding a location with its IIS sites, foreign applications, CCS and other stores unsupported, the bound certificate by its DER hash (R60)`.

---

### Task 10: Setup snippet, setup guide and host preparation guide **[W0: F3, F7]**

**Files:**
- Create: `internal/providers/windows/setup.go`, `internal/providers/windows/setup_test.go`, `internal/providers/windows/docs_setup_test.go`, `docs/windows-host-preparation.md`
- Modify: `internal/providers/windows/provider.go` (`SetupSnippets`, `HelperInfo`: `providers.SetupGuide`), `internal/providers/provider.go:190-201` (comments: profile `"windows"`; `SetupSnippet.Sudoers` is "" for it and `Script` is PowerShell)
- Modify: `internal/inventory/platformkey.go:158-207` (`windowsAuthorizedKeysLine(publicKey, from)`; `SetupGuide` also asks the registered `KindWindows` provider, when it is registered and is a `providers.SetupGuide`, with that line and merges its `windows` profile; the all-or-nothing script check stays), `internal/inventory/platformkey_test.go` or the existing guide tests (`TestWindowsKeyLineEqualsTheProvidersLine`, as Task 16's equality test of the Linux line)
- Modify: `tools/docscheck/required.txt` (the guide's required sentences: "Run it once in an elevated PowerShell" and the Match block heading), `docs/README.md` (link the guide)

**Interfaces:**
- Produces:
  ```go
  func AuthorizedKeysLine(publicKey, from string) string // "restrict " + key, or `restrict,from="<from>" ` + key; "" when from fails linuxssh.ValidateFrom
  func SetupScript(authorizedKeysLine string, allowUnverified bool) (string, error) // ErrHelperUnverified, errBadKeyLine (a ' or a control character)
  func (p *Provider) SetupSnippets(line string) map[string]providers.SetupSnippet  // {"windows": {Profile: "windows", Script: ...}}
  func (p *Provider) HelperInfo() (string, int)                                     // winproto.HelperPath, winproto.Protocol
  const MatchBlock = "Match User __USER__\n    ForceCommand \"C:\\Program Files\\Alice\\alice-helper.exe\" ssh\n    AuthenticationMethods publickey\n    PermitTTY no\n    AllowTcpForwarding no\n    AllowStreamLocalForwarding no\n    X11Forwarding no\n    PermitTunnel no\n"
  ```
  The script, in order (design §6.1; PowerShell 5.1 compatible; `#Requires -RunAsAdministrator`, `Set-StrictMode -Version 3`, `$ErrorActionPreference = 'Stop'`; idempotent):
  1. `$AliceUser = 'alice'` (comment: set `DOMAIN\alice-svc` for the domain setup of design §4.3), `$AliceAddress` (the `from=` of the line, else `'Any'` and a printed notice), `$AuthorizedKey = '<line>'`, the two embedded SHA-256 values.
  2. `.\alice-helper.exe` exists; `Get-FileHash -Algorithm SHA256` equals the value for `$env:PROCESSOR_ARCHITECTURE` (`AMD64`, `ARM64`; anything else refused); a mismatch stops with the message of `internal/providers/linuxssh/setup.go` `helperVerify` in Windows words. Unverified builds print the warning of `helperUnverified` instead.
  3. OpenSSH Server: `Get-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0'`, `Add-WindowsCapability` when not installed (air-gapped: the message names the Win32-OpenSSH MSI and to run the script again); `Set-Service sshd -StartupType Automatic`; `Start-Service sshd`. **[W0: F7 — if the capability is slow or absent on the images, the guide documents the pinned MSI path and the script accepts an installed MSI]**
  4. Account: a local `$AliceUser` without a domain part is created when missing with a random 32-character password from `[System.Security.Cryptography.RandomNumberGenerator]`, never printed, `-PasswordNeverExpires`; it (or the domain account) is added to the group with SID `S-1-5-32-544` (locale-independent); the rights `SeDenyInteractiveLogonRight` and `SeDenyRemoteInteractiveLogonRight` are granted through `secedit /export` → edited INF → `secedit /configure /areas USER_RIGHTS`. **[W0: F3 — if the local account's key logon is not elevated, the script prints the domain-account advice and the guide documents `LocalAccountTokenFilterPolicy` as the last resort; the script never sets it]**
  5. `C:\ProgramData\ssh\administrators_authorized_keys`: the line added once (exact line match), ACL `icacls <file> /inheritance:r /grant '*S-1-5-32-544:F' '*S-1-5-18:F'`.
  6. `sshd_config`: the block between `# BEGIN Alice` and `# END Alice` replaced or appended with `MatchBlock` (user substituted), `& "$env:WINDIR\System32\OpenSSH\sshd.exe" -t` must pass before `Restart-Service sshd`; a failing test restores the previous file.
  7. Helper: `C:\Program Files\Alice\alice-helper.exe` copied, directory ACL Administrators and SYSTEM full control, inheritance removed; `C:\ProgramData\Alice\helper` created with the same ACL.
  8. Firewall rule `Alice-SSH-In` (inbound TCP 22, `-RemoteAddress $AliceAddress`), replaced when present.
  9. Event source `Alice Helper` in the Application log (`[System.Diagnostics.EventLog]::SourceExists` / `CreateEventSource`).
  10. Prints the host key fingerprints (`ssh-keygen.exe -lf` on each `C:\ProgramData\ssh\ssh_host_*_key.pub`) so the Administrator compares them with the confirmation in Alice, then "This server is ready for Alice."
- Mirror: `linuxssh.SetupScript`, `helperCheck`, `AuthorizedKeysLine` (`internal/providers/linuxssh/setup.go:115-262`); `TestSetupSnippetsForEveryProfile` (`internal/providers/linuxssh/provider_test.go:203`); `TestPreparationGuideQuotesTheSudoersFile` (`internal/providers/linuxssh/docs_sudoers_test.go`).

- [ ] **Step 1: Write the failing tests**
  - `setup_test.go`:
    - `TestAuthorizedKeysLine`: `restrict ssh-ed25519 AAAA...`; with from `192.0.2.10`: `restrict,from="192.0.2.10" ssh-ed25519 AAAA...`; a from with a quote → "".
    - `TestSetupScriptEmbedsTheHelperChecksums`: with both checksum variables set, the script contains both values next to `AMD64` and `ARM64`, the key line inside single quotes, `MatchBlock` with `alice`, `#Requires -RunAsAdministrator`; without checksums and `allowUnverified` false → `ErrHelperUnverified`; with `allowUnverified` → the warning text and no hash check.
    - `TestSetupScriptRefusesALineItCannotQuote`: a line with `'`, CR, LF, NUL → `errBadKeyLine`.
    - `TestSetupScriptFirewallAddress`: a line with `from="192.0.2.10"` → `$AliceAddress = '192.0.2.10'`; without → `'Any'` and the notice.
    - `TestSetupScriptNeverPrintsThePassword`: the script never writes the password variable to the output (no `Write-Host`/`Write-Output`/`echo` of it; a regexp over the script's lines).
    - `TestSetupSnippets`: exactly the profile `windows`, `Sudoers` "", the script.
  - `docs_setup_test.go`, `TestPreparationGuideQuotesTheMatchBlock`: `docs/windows-host-preparation.md` holds a fenced block equal to `MatchBlock` with `alice`, byte for byte.
  - inventory: `TestSetupGuideHasTheWindowsProfile` (unit with a registry holding linuxssh and windows): `Profiles["windows"].Script` non-empty, its key line starts with `restrict`; a windows provider without checksums in a non-dev build → `ErrNoSetupScript` for the whole guide (Ruling 15); `TestWindowsKeyLineEqualsTheProvidersLine`.
- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./internal/providers/windows/ -run 'Setup|AuthorizedKeys|Preparation' && go test ./internal/inventory/ -run 'SetupGuide|WindowsKeyLine'`
Expected: FAIL (undefined `SetupScript`, missing guide).
- [ ] **Step 3: Implement** `setup.go`, the provider methods, the inventory merge, and write `docs/windows-host-preparation.md` in the style of `docs/haproxy-host-preparation.md`: what Alice reads on a Windows server (read-only in this release), supported systems (Windows Server 2019, 2022, 2025, Desktop Experience and Server Core, IIS 10), the two account setups of design §4.3, steps (copy the helper for the processor as `alice-helper.exe`, open **Servers** → **Prepare a server for Alice** → **Windows server**, run the script once in an elevated PowerShell, add the server with the account name, compare the printed host key fingerprint), the exact `MatchBlock`, what the script changes and how to undo it, troubleshooting for `ALC-WIN-0001..0003` (UAC remote restrictions, `LocalAccountTokenFilterPolicy` as a last resort), antivirus exclusion of the helper path.
- [ ] **Step 4: Run the tests**
Run: `go test -race -count=1 ./internal/providers/windows/ ./internal/inventory/ -run 'Setup|AuthorizedKeys|Preparation|WindowsKeyLine' && make docs-check`
Expected: PASS.
- [ ] **Step 5: Commit**: `feat(providers/windows): the PowerShell setup snippet with the embedded helper checksums, the windows profile of the setup guide, and the Windows host preparation guide (R60)`.

---

### Task 11: Real Windows: fidelity test, setup smoke test, workflow **[W0: F3, F6, F7]**

**Files:**
- Create: `cmd/alice-winhelper/emulator_fidelity_windows_test.go`, `internal/providers/windows/setup_windows_test.go` (build tag `windows`), `.github/workflows/windows.yml`
- Modify: none outside these (if W0 left a spike workflow on `main`, delete it here in the same commit and say so in the message)

**Interfaces:**
- Consumes: the real host (Tasks 4-5), `wintest.Model` (Task 7), `windows.SetupScript` (Task 10).
- Produces: the fidelity harness `type twin struct{ t *testing.T; real winhelper.Host; model *wintest.Model; cleanup []func() }` with `func (tw *twin) same(args ...string) map[string]any` (runs `winhelper.Run` on both hosts, normalises, requires equal exit codes and equal answers, returns the real one) and mirrored fixture helpers `addCertificate(store, leaf)`, `addBinding(b)`, `addSite(name, bindings...)`, `removeCertificate(store, sha1)`, each changing the machine (PowerShell/`netsh`/`appcmd` from the test) and the model alike.
- Mirror: `cmd/alice-helper/emulator_fidelity_test.go:27-245` (the twin, `same`, `normalize`, mirrored changes; "the helper is the specification: a difference means the emulator is wrong").

- [ ] **Step 1: Write the tests** (all `t.Skip` unless `ALICE_WIN_REAL=1`; the workflow fails a run whose expected tests did not PASS, below):
  - Normalisation: the real dump is filtered to the test's own fixtures (ports 44300-44399, sites `alice-w1-*`, certificates those fixtures name); `win-facts`' `os_*` and `openssh_version` are copied from the real answer into the model before the comparison (`TestFidelityWinFacts` checks them separately against Task 4's independent reading); `message` is dropped.
  - `TestFidelityVersionAndRefusals`: `version`; `["version","x"]`; `["iis-deploy"]`; `["tls-probe","--addr"]` — equal exit codes and codes.
  - `TestFidelityWinFacts`: `elevated`, `iis`, `stores` equal.
  - `TestFidelityDumpSNIAndIPBindings`: an SNI binding with a site, a `0.0.0.0` binding with a site, an IIS binding without an entry, a `WebHosting` binding, a foreign (WinRM id) binding: the filtered dumps are equal field by field (bindings, certificates with chain and key facts, sites).
  - `TestFidelityDumpCertificateRemoved`: after `certutil -delstore My <sha1>` on both, the binding stays and the certificate is gone on both (`cert_missing` Alice-side). **[W0: F2 — if `netsh` refuses to bind a hash it cannot find, delete after binding as written]**
  - `TestFidelityDumpKeyMissing`: a certificate without its key bound with `netsh` (if W0 shows `netsh` refuses, this scenario stays emulator-only and the rulings file says so). **[W0: F4]**
  - `TestFidelityTLSProbe`: the IIS site started; `tls-probe` against `127.0.0.1:44301` with SNI `alice-w1.test` answers the same `leaf_sha256`, `chain_length` and `chain` on both (the model's listener and real http.sys/schannel). **[W0: F5 — if schannel's chain differs, the model is configured with the chain the real dump reported]**
  - `setup_windows_test.go`, `TestRealSetupScript` (skip unless `ALICE_WIN_SETUP=1`): renders `SetupScript` for a fresh ed25519 key with the checksum of the helper built in the job (the test sets the package variables), runs it with `powershell -NoProfile -ExecutionPolicy Bypass -File`, then: `sshd -T` shows the Match block for `alice`; `administrators_authorized_keys` ACL has only Administrators and SYSTEM; `C:\Program Files\Alice\alice-helper.exe` hash equals; `ssh -i <key> -o UserKnownHostsFile=<pinned file from ssh-keyscan> alice@localhost version` prints protocol 1; `... alice@localhost "version & whoami"` exits 2; running the script twice changes nothing (file hashes equal). **[W0: F3, F7]**
  - `.github/workflows/windows.yml`:
    - `on`: `push` and `pull_request` with `paths: [cmd/alice-winhelper/**, internal/providers/windows/**, internal/providers/linuxssh/helperproto/**, internal/providers/linuxssh/linuxsshtest/**, .github/workflows/windows.yml, go.mod, go.sum]`; `schedule: - cron: '41 2 * * *'`; `workflow_dispatch`. `permissions: contents: read`; `concurrency` as `ci.yml:11-14`.
    - Job `helper` with `strategy.matrix.os: [windows-2022, windows-2025]`, `runs-on: ${{ matrix.os }}`, `timeout-minutes: 45`; steps: checkout and setup-go pinned exactly as `ci.yml:21-23`; `Install-WindowsFeature Web-Server,Web-Mgmt-Console,Web-Scripting-Tools` (shell `pwsh`); `go build` both architectures; `go test -count=1 -v ./cmd/alice-winhelper/... ./internal/providers/windows/...` with `ALICE_WIN_REAL=1` and `ALICE_WIN_SETUP=1`, piped through a PowerShell check that fails the step when any of `TestRealHostIsElevated`, `TestRealBindingsListAnSNIAndAnIPBinding`, `TestFidelityDumpSNIAndIPBindings`, `TestFidelityTLSProbe`, `TestRealSetupScript` did not print `--- PASS` (the rule of `SSH_MATRIX_PASSED`, `Makefile:34`).
- [ ] **Step 2: Verify locally what can be verified**
Run: `GOOS=windows go vet ./cmd/alice-winhelper/ ./internal/providers/windows/... && actionlint .github/workflows/windows.yml && go run ./tools/pincheck && go test -run TestNoCodeAcceptsAnyHostKey ./internal/providers/linuxssh/`
Expected: PASS.
- [ ] **Step 3: Run on real Windows.** Push the branch to a fork or ask the owner to run `workflow_dispatch` on `windows-w1` (the plan never pushes to `origin/main`); both matrix legs green. If no run is possible before merge, record "real-runner run pending" as an owner item in the rulings file and do not claim acceptance item 4.
- [ ] **Step 4: Fix** every fidelity difference in the emulator (the helper is the specification), commit fixes in the task that owns the code.
- [ ] **Step 5: Commit**: `test(windows): the fidelity test of the read subcommands, the setup script smoke test and a path-filtered real-Windows workflow on windows-2022 and windows-2025 (R60)`.

---

### Task 12: Inventory: the `windows` type, its scan and its facts

**Files:**
- Modify: `internal/inventory/types.go:26-45` (`TypeWindows = providers.TargetTypeWindows`; `IsSSHTarget(typ) bool` = `IsServer(typ) || typ == TypeWindows`; `HasCertificateLocations(typ) bool` = `IsWebServer(typ) || typ == TypeWindows`; `Facts.Windows *providers.WindowsFacts json:"windows,omitempty"` at `types.go:128-145`)
- Modify: `internal/inventory/validate.go:27-29` (`typeValues` lists `windows`), `validate.go:151-180` (`IsSSHTarget`; Windows default user `alice` and Ruling 1's rule as `windowsUserRE`, equal to `windows.ValidUser` by a test since inventory may not import the provider)
- Modify: `internal/inventory/capabilities_sync.go:23` (add `TypeWindows`)
- Modify: `internal/inventory/sshkeys.go:154` (`!HasCertificateLocations(t.Type)`), `sshkeys.go:243-256` (`last_discovery_at` also when `t.Type == TypeWindows && res.WebServer != nil`, Ruling 10)
- Modify: `internal/inventory/locations.go:364-375` (`configUsable` accepts `Software == "iis"` without `Found`; constant `softwareIIS = "iis"`)
- Modify: `internal/inventory/status.go:120-125` (`RecordConnectionOK` stores `r.Windows` cleaned: strings through `clean`, at most 16 stores)
- Create: `internal/inventory/windows_integration_test.go`, `internal/inventory/windows_test.go`

**Interfaces:**
- Consumes: `providers.WindowsFacts`, `providers.LocationWinSSLBinding`, the groundwork's kind locations (`prepareKindLocation`, `locations.go:126`).
- Produces: `inventory.TypeWindows`, `IsSSHTarget`, `HasCertificateLocations`, `Facts.Windows`.

- [ ] **Step 1: Write the failing tests**
  - `windows_test.go`: `TestWindowsUserRuleEqualsTheProviders` (table shared with Task 8's), `TestTypePredicates` (`linux` SSH target, server, no certificates; `nginx` all three; `windows` SSH target and certificates, not `IsServer`, not `IsWebServer`; `azure_key_vault` none), `TestConfigUsableForIIS` (iis without `Found` usable; nginx without `Found` not).
  - `windows_integration_test.go` (tag `integration`, the harness of `internal/inventory/groundwork_integration_test.go`, a registry with the windows provider):
    - `TestCreateWindowsTargetKeepsTheDomainAccount` (Review Focus 1): `CreateTarget{Type: "windows", Username: "CORP\\alice-svc"}` stores it verbatim in `targets.config.username`; empty username → `alice`; a Linux target with `CORP\alice-svc` → 422 `username`; the target counts toward the license (an evaluation install with 5 targets refuses a sixth Windows server, L-74).
    - `TestWindowsScanStoresBindingLocations`: `Reconcile` with a `DiscoveryResult` like Task 9's output stores `win_sslbinding` rows with locator, canonical `cert_path`, empty `key_path`, `servers` (with `section`), `details`, `cert_file_sha256` = the DER hash, `certificate_id` set and the certificate's fingerprint equal to the leaf's (the network-discovery link: `discovery.certificateStatusSQL` reads it `managed`, checked with a `discovered_certificates` row of the same fingerprint); `last_discovery_at` is set; `facts.ssh` stays empty; no `ssh_key_locations` row.
    - `TestWindowsScanWithoutIISStoresForeignLocations` (Review Focus 3): `WebServer{Software:"iis", Found:false, ConfigValid:true}` and one foreign location → stored, unsupported `win_foreign_app`; facts say IIS not found.
    - `TestWindowsTruncatedScanMarksNothingMissing` (Review Focus 2): a first full scan of three locations, then a scan of one with `locations_dropped` → none marked missing; then a full scan of one → two marked missing.
    - `TestWindowsProblemsAreFileProblems` (Ruling 9): `cert_missing` → unsupported `file_problem`, no certificate; `KeyProblem key_inaccessible` → unsupported `file_problem`, certificate linked.
    - `TestRecordConnectionOKStoresWindowsFacts`: the facts round-trip through `GetTarget`; a product with a NUL is cleaned.
    - `TestWindowsTargetHasNoSSHKeyRoutes`: `GET /api/v1/targets/{id}/key-files`-equivalent inventory call refuses with `ErrNotAServer` (`internal/sshkeys/deploy.go:217` keeps refusing).
    - `TestSyncCapabilitiesCoversWindows`.
- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./internal/inventory/ -run 'Windows|TypePredicates|ConfigUsable' && go test -count=1 -tags integration ./internal/inventory/ -run Windows`
Expected: FAIL.
- [ ] **Step 3: Implement** the changes listed in Files.
- [ ] **Step 4: Run the tests**
Run: `go test -race -count=1 ./internal/inventory/ ./internal/archtest/ && go test -race -count=1 -tags integration ./internal/inventory/ ./internal/jobs/targetjobs/`
Expected: PASS; every existing inventory and targetjobs test unchanged.
- [ ] **Step 5: Commit**: `feat(inventory): the windows target type: domain accounts, http.sys binding locations from its scan with certificates linked by fingerprint, Windows facts (R60)`.

---

### Task 13: API: error codes, texts, OpenAPI, facts

**Files:**
- Modify: `internal/api/errors.go:283-287` region (new block `ErrWINHelperMissing = ErrorCode{Code: "ALC-WIN-0001", Reason: "windows.helper_missing", Status: http.StatusBadGateway}`, `ErrWINHelperOutdated` `ALC-WIN-0002`, `ErrWINNotElevated` `ALC-WIN-0003`), `errors.go` `AllErrorCodes()` list, the params allowlist near `errors.go:1303` (`exit_code`, `helper_protocol`, `required_protocol` already allowed: check the new reasons use only those)
- Modify: `locales/common/en.json`, `locales/common/tr.json` (`errors.windows.{helper_missing,helper_outdated,not_elevated}.{title,cause,action}`; `provider.windows.name` "Windows server" / "Windows sunucusu"; `provider.windows.fields.{host,port,username}.{label,help}` — username label "Windows account" / "Windows hesabı", help "alice, or DOMAIN\\alice-svc for a domain account" in both languages' words)
- Modify: `docs/troubleshooting.md` (the error table rows and a section per code, as `## ALC-SSH-0004: ...` at `docs/troubleshooting.md:1130`)
- Modify: `internal/api/inventory_dto.go:97-152` (`factsDTO.Windows *windowsFactsDTO json:"windows,omitempty"`), `api/openapi.yaml` (target `type` enums at lines 1106-1113, 7909, 7987 add `windows`; `SetupGuide.profiles` at 8452-8457 adds `windows`; the provider `kind` enum at 8493 adds `windows`; `software` at 8526 adds `iis` with "iis on a Windows server"; the location server type description at 8703-8704 drops "windows ... reserved"; facts schema `WindowsFacts`)
- Create: `internal/api/errors_windows_test.go`, extend `internal/api/targets_handlers_test.go`

**Interfaces:**
- Consumes: the reasons of Task 8.
- Mirror: `internal/api/errors_webserver_test.go` (codes, statuses, catalogue, texts), commit `ee1eaba7` (the files an error-code addition touches).

- [ ] **Step 1: Write the failing tests**
  - `errors_windows_test.go`, `TestWindowsErrorCodes`: each of the three reasons maps to its code and 502, is in `AllErrorCodes`, has EN and TR title/cause/action and a troubleshooting section (the catalogue test does the last two once the codes exist).
  - `targets_handlers_test.go`, `TestCreateWindowsTarget`: `POST /api/v1/targets` with `type: windows`, `username: CORP\\alice-svc` → 201 with the username verbatim; `GET /api/v1/targets/{id}` shows `facts.windows` after a recorded test; `GET /api/v1/platform-key` has `profiles.windows.script`.
  - The OpenAPI conformance tests (`internal/api/openapi_test.go`) pass with the new enum values.
- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./internal/api/ -run 'Windows|OpenAPI|Catalogue'`
Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the tests**
Run: `go test -race -count=1 ./internal/api/ && go test -race -count=1 -tags integration ./internal/api/ -run 'Target|OpenAPI|Roles|Windows' && make i18n-check`
Expected: PASS.
- [ ] **Step 5: Commit**: `feat(api): ALC-WIN-0001..0003 for a missing, outdated or not elevated Windows helper, the windows type, its setup profile and facts in the API (R60)`.

---

### Task 14: Web: add a Windows server, setup script, facts, locations

**Files:**
- Modify: `web/src/api/webServer.ts:4-14` (`isWindows(type)`, `isServerType` includes `windows`, `hasCertificateLocations(type)` = `isWebServer(type) || isWindows(type)`; `WEB_SERVER_TYPES` unchanged)
- Modify: `web/src/api/types.ts:546` (`profiles` gains `windows: SetupSnippet`), the `Facts` type (`windows?: WindowsFacts`), `web/src/api/enums.ts:94-125` (`UNSUPPORTED_REASONS` + `win_foreign_app`, `win_ccs`, `win_store_unsupported`; `FILE_PROBLEMS` + `cert_missing`, `key_missing`, `key_inaccessible`; location warning `win_ctl`; server warnings `win_shared_config`, `win_autocertrebind`, `win_ccs_enabled`, `win_expired_in_store`), `web/src/api/enums.test.ts`
- Modify: `web/src/components/software.ts` (`softwareName(t, 'windows')` → `t('webServer.software.iis')`; `siteColumnLabel` for `windows` → "IIS site")
- Modify: `web/src/components/AddServerModal.tsx:25, 51-55, 170-189, 227-247` (type choice "Windows server"; switching to `windows` sets the user field to `alice` when it still holds the Linux default, and back; username `maxLength` 36 for windows; `ProfileScript` shows `profiles.windows.script` labelled "PowerShell setup script", with the note "Run it once in an elevated PowerShell on the server, in the folder that holds alice-helper.exe")
- Modify: `web/src/components/PlatformKeyPanel.tsx:14-48` (profile `windows`)
- Modify: `web/src/pages/TargetDetailPage.tsx:76, 132, 376-412` (locations shown for `hasCertificateLocations`; a Windows facts block: Windows version (`product`, `build`), installation type, IIS version or "IIS is not installed", elevated "Yes"/"No", stores, OpenSSH version; operations text for Windows: "Alice reads the http.sys bindings and IIS sites of this server; deployment comes in a later release")
- Modify: `web/src/components/WebsitesPanel.tsx:192-206` (Windows rows: site names from `section`, names, listens; the canonical text in the place of the file path)
- Modify: `web/src/locales/en.json`, `web/src/locales/tr.json` (every new key; `webServer.software.iis` "IIS"; `webServer.siteColumn.windows` "IIS site" / "IIS sitesi"; `targets.typeLabel.windows`; `targets.form.typeWindows`; `locations.unsupported.win_*`, `locations.problems.{cert_missing,key_missing,key_inaccessible}`, `warnings.win_*`, the facts labels), `web/src/locales/.i18n-identical.json` if a value is identical in both (e.g. "IIS")
- Modify: `web/src/test/fixtures.ts` (a Windows target fixture and two locations)
- Tests: `web/src/components/AddServerModal.test.tsx`, `web/src/pages/TargetDetailPage.test.tsx`, `web/src/components/WebsitesPanel.test.tsx` (or the file that tests it), `web/src/pages/TargetsPage.test.tsx`

**Interfaces:**
- Consumes: the API of Task 13.
- Mirror: the HAProxy UI addition, `docs/superpowers/plans/2026-10-17-haproxy-provider.md` Task 9 ("the Frontend column"), and `web/src/components/LocationSettingsDialog.tsx` for the non-file location rules of phase G.

- [ ] **Step 1: Write the failing tests**
  - `AddServerModal.test.tsx`, `windows type`: choosing "Windows server" shows the PowerShell script from `profiles.windows`, sets the user to `alice`; submitting sends `{type:'windows', username:'CORP\\alice-svc'}` verbatim; switching back to Linux restores `alice-svc` only if the user did not edit it.
  - `TargetDetailPage.test.tsx`, `windows facts`: the fixture shows "Windows Server 2022 Datacenter", the build, "IIS 10.0", "Elevated: Yes"; without IIS "IIS is not installed"; the locations panel lists `http.sys/hostnameport/www.example.test:443` with site "Default Web Site", a foreign binding with "This binding belongs to another application (winrm)..." text and a ccs binding with its text; the deploy control is disabled with "Not available for IIS servers yet" (EN) and the TR note.
  - `enums.test.ts`: every new code has a key in both locales.
  - Accessibility: the existing axe checks of these pages run with the Windows fixture.
- [ ] **Step 2: Run them to verify they fail**
Run: `cd web && npx vitest run src/components/AddServerModal.test.tsx src/pages/TargetDetailPage.test.tsx src/api/enums.test.ts`
Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run the tests**
Run: `cd web && npx vitest run && npx tsc --noEmit && npm run lint && cd .. && make i18n-check && make web-coverage`
Expected: PASS, web coverage thresholds of `web/vite.config.ts` met.
- [ ] **Step 5: Commit**: `feat(web): add a Windows server with its PowerShell setup script, its Windows and IIS facts, and its http.sys bindings with IIS sites, English and Turkish (R60)`.

---

### Task 15: e2e: the emulated Windows host and a Playwright journey

**Files:**
- Create: `cmd/alice-fakewindows/main.go`, `cmd/alice-fakewindows/main_test.go`, `test/images/fakewindows/Dockerfile`, `web/e2e/windows.spec.ts`
- Modify: `deploy/docker-compose.e2e.yml` (service `fakewindows` after `fakefleet`; `alice.depends_on` adds it healthy), `cmd/alice/compose_test.go` (the fake publishes nothing, is test-only, non-root, read-only), `internal/archtest/buildtags_test.go:54-57` (`testOnlyDirs` adds `cmd/alice-fakewindows`; `TestReleaseBinariesLinkNoTestPackages` asserts `./cmd/alice` never links `wintest` and `./cmd/alice-fakewindows` does), `web/e2e/helpers.ts:827-842` (`windowsExec(args, input)` = `composeExec('fakewindows', ['/alice-fakewindows', ...args], input)`), `coverage-floors.json` (`alice/cmd/alice-fakewindows` 90)

**Interfaces:**
- Consumes: `wintest.Demo`, `linuxsshtest.Listen`.
- Produces: `alice-fakewindows serve --listen :22 --tls-bind 0.0.0.0 --ctl 127.0.0.1:9093` (a fresh ed25519 host key per start; TLS listeners on the demo's binding ports 443, 8443, 5986 with a test CA generated at start); `alice-fakewindows ctl ping`; `ctl prepare` (stdin: the Windows setup script; extracts the `$AuthorizedKey = '...'` line, authorizes its key, prints `{"ok":true}`; refuses a script without exactly one such line); `ctl hostkey` (prints the SHA256 fingerprint). Demo host: Windows Server 2022 Datacenter `10.0.20348.2700`, IIS 10.0; sites `Default Web Site` (`https *:443:www.win.example.test` sslFlags 1) and `Intranet` (`https *:8443:` sslFlags 0); http.sys entries `hostnameport www.win.example.test:443` (IIS id, `My`), `ipport 0.0.0.0:8443` (IIS id, `WebHosting`), `ipport 0.0.0.0:5986` (WinRM id: foreign), `ccs 443`.
- Mirror: `cmd/alice-fakefleet` (serve/ctl split, loopback control API), `test/images/fakefleet/Dockerfile` (two pinned stages, distroless static, `USER 65532:65532`), the `fakefleet` compose service (`read_only`, `cap_drop: [ALL]`, `no-new-privileges`, `net.ipv4.ip_unprivileged_port_start: "0"`, `mem_limit`, `pids_limit`, healthcheck `ctl ping`), `web/e2e/webservers.spec.ts` (structure, translator, both languages).

- [ ] **Step 1: Write the failing tests**
  - `main_test.go`: `serve` on 127.0.0.1:0 answers SSH with an authorized key after `ctl prepare` with a script rendered by `windows.SetupScript`; `ctl prepare` refuses a script without the line or with two; `ctl hostkey` equals the server's key fingerprint.
  - `compose_test.go`: `TestFakeWindowsIsTestOnlyAndUnpublished` (no `ports`, test image name, user 65532, read-only, on `backend` only).
  - `web/e2e/windows.spec.ts` (EN and TR, as `webservers.spec.ts`): reset; wizard; **Servers → Add server**, type "Windows server": the PowerShell script is shown and contains the helper SHA-256 (64 hex next to `AMD64`); `windowsExec(['ctl','prepare'], script)`; name `e2e-windows`, address `fakewindows`, port 22, account `alice`; the host key confirmation shows the fingerprint `windowsExec(['ctl','hostkey'])` prints; confirm; the server page shows "Windows Server 2022 Datacenter", "IIS 10.0", elevated; after the first discovery the locations panel lists `http.sys/hostnameport/www.win.example.test:443` (site "Default Web Site"), `http.sys/ipport/0.0.0.0:8443` ("Intranet"), the WinRM binding unsupported with the foreign-application text, the ccs binding with its text; **Certificates** lists `www.win.example.test` as found on `e2e-windows`; `expectAccessible` on the server page.
- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./cmd/alice-fakewindows/ ./cmd/alice/ -run 'FakeWindows|Compose'`
Expected: FAIL.
- [ ] **Step 3: Implement** the command, image, compose service and journey.
- [ ] **Step 4: Run**
Run: `go test -race -count=1 ./cmd/alice-fakewindows/ ./cmd/alice/ ./internal/archtest/ && go run ./tools/pincheck && E2E_PROJECT=alice-e2e-w1 ALICE_E2E_PORT=9973 make e2e-up && E2E_PROJECT=alice-e2e-w1 ALICE_E2E_PORT=9973 make e2e; E2E_PROJECT=alice-e2e-w1 make e2e-down`
Expected: PASS, the whole e2e suite green (no existing journey changed).
- [ ] **Step 5: Commit**: `test(e2e): an emulated Windows host container and a journey that adds a Windows server, confirms its host key and sees its http.sys bindings (R60)`.

---

### Task 16: Decision, rulings, specification amendments, test IDs, changelog

**Files:**
- Create: `docs/superpowers/rulings/windows-iis.md` (the 22 rulings above as built, every W0 adjustment, owner items)
- Modify: `docs/superpowers/specs/alice-v1/00-decisions.md` (append R60 after line 159: "R60 (owner approval of the Windows design with its §15 defaults, 2026-10-22; phase W1 of `docs/superpowers/specs/2026-10-21-windows-iis-target-design.md`; rulings in `docs/superpowers/rulings/windows-iis.md`) Windows server target, phase W1: ..." summarising type, transport and forced command, `winproto` 1 and its subcommands, the helper and its elevation rule, the locator and canonical text, the unsupported reasons and problems, `win_ctl` as a warning, the three error codes, no migration)
- Modify: `docs/superpowers/specs/alice-v1/02-architecture.md:335` (a "Windows servers" paragraph after the groundwork one: provider `windows`, package layout, data flow of a scan), `docs/superpowers/specs/alice-v1/03-integrations.md` (new section `## 13A. Windows servers and IIS over SSH (amendment, R60)` after §13: transport, account, forced command, setup, `winproto` 1, discovery algorithm and matching rules, bounds, failure cases of §11 that W1 covers, explicit W1 limits), `docs/superpowers/specs/alice-v1/04-security.md` (§14.4 new table "#### Windows connector and helper (amendment, R60)" with rows `WN-1`..`WN-8` from design §9: forced command (E), password theft (I), first contact MITM (S), key exposure on the server (I; W2), logs (I), helper replaced (T), UAC filtering (E, `NOT_ELEVATED`), shared IIS configuration (T), plus "a shell without the forced command" (E, bare validated tokens only); §15.11 a paragraph "(Amendment, R60.)" for target access: the platform key line with `restrict`, the Match block, the account rights, the helper hash check)
- Modify: `docs/superpowers/specs/alice-v1/06-quality.md` (after §24.6: `### 24.7 Windows servers (R60)` with rows `WIN-01`..`WIN-14`, below), `tools/matrixcheck/main.go:1-3, 89` (prefix `WIN` in the comment and `idRowRe` `^\|\s*((?:SR|WIN|[LFSRAOX])-\d+)\s*\|`), `tools/matrixcheck/main_test.go` (a fixture row `WIN-01` is found), `test/matrix/traceability.json` (one entry per ID), `docs/security/traceability.md` (regenerated with `-update`)
- Modify: `CHANGELOG.md` ("Unreleased": "Windows servers (discovery): ..."), `docs/admin-guide.md` (section "Windows servers": what W1 offers, a link to `docs/windows-host-preparation.md`, "deployment, drift and cleanup follow in a later release"), `docs/superpowers/specs/2026-10-21-windows-iis-target-design.md` (status line: "W1 built (R60)"; a short "§16 Phase W1 as built" table like the roadmap's §5), `docs/superpowers/specs/2026-10-21-deployment-targets-roadmap.md` (the Windows row's status)

The WIN rows (ID | Failure or case injected | Expected behaviour; tests in parentheses go into `traceability.json`):

| ID | Case | Tests |
|---|---|---|
| WIN-01 | A Windows server is added with a local or a domain account | `internal/inventory:TestCreateWindowsTargetKeepsTheDomainAccount`, `internal/providers/windows:TestParseConfigTakesDomainAccounts`, `web/e2e/windows.spec.ts:Windows server` |
| WIN-02 | First contact shows the host key; a changed key blocks the server | `internal/providers/windows:TestHostKeyChangedRefuses`, e2e |
| WIN-03 | Helper missing, or sshd without the forced command | `internal/providers/windows:TestOpenHelperMissing`, `TestOpenWithoutForcedCommandIsHelperMissing` |
| WIN-04 | Helper outdated, or a subcommand unknown to it | `TestOpenHelperOutdated`, `TestUnknownSubcommandIsOutdated` |
| WIN-05 | Token not elevated | `internal/providers/windows:TestTestConnectionNotElevated`, `internal/providers/windows/winhelper:TestElevationGate`, `cmd/alice-winhelper:TestRealHostIsElevated` |
| WIN-06 | A shell line through `SSH_ORIGINAL_COMMAND` | `internal/providers/windows/winhelper:TestRunForcedSplitsTheOriginalCommand`, `cmd/alice-winhelper:TestMainRefusesAShellLine`, `TestRealSetupScript` |
| WIN-07 | Every http.sys binding listed with its IIS sites | `TestDiscoverMatchesIISBindings`, `TestDiscoverListsBindingsWithSites`, `cmd/alice-winhelper:TestFidelityDumpSNIAndIPBindings` |
| WIN-08 | Foreign application, CCS and other store bindings unsupported | `TestDiscoverSupportedRules`, `TestDiscoverWithoutIISListsForeignBindings` |
| WIN-09 | Certificate missing from the store, key missing or not usable | `TestDiscoverProblems`, `internal/inventory:TestWindowsProblemsAreFileProblems`, `cmd/alice-winhelper:TestFidelityDumpCertificateRemoved` |
| WIN-10 | A cut dump marks nothing missing | `internal/providers/windows/winhelper:TestDumpCutsAtItsBounds`, `TestDiscoverTruncatedDumpDropsLocations`, `internal/inventory:TestWindowsTruncatedScanMarksNothingMissing` |
| WIN-11 | appcmd fails while IIS is installed | `TestBuildDumpAppcmdFailureFailsTheDump`, `TestDiscoverAppcmdFailure` |
| WIN-12 | The bound certificate is linked by fingerprint (managed in network discovery) | `internal/inventory:TestWindowsScanStoresBindingLocations` |
| WIN-13 | Hostile helper output is cleaned or dropped | `TestDiscoverCleansHostileText`, `TestBuildDumpDropsInvalidRecords`, `TestParseAppcmdSites` |
| WIN-14 | The emulator answers as the real helper (read subcommands) | `cmd/alice-winhelper:TestFidelityVersionAndRefusals`, `TestFidelityWinFacts`, `TestFidelityTLSProbe` |

- [ ] **Step 1: Write the failing test** `tools/matrixcheck/main_test.go`, `TestSpecIDsFindWindowsRows`: a section-24 fixture with `| WIN-01 | ... |` yields `WIN-01`.
- [ ] **Step 2: Run it to verify it fails**
Run: `go test ./tools/matrixcheck/ -run Windows`
Expected: FAIL.
- [ ] **Step 3: Write** the documents and the regex change; regenerate the traceability document: `go run ./tools/matrixcheck -spec docs/superpowers/specs/alice-v1/06-quality.md -map test/matrix/traceability.json -doc docs/security/traceability.md -update`.
- [ ] **Step 4: Verify**
Run: `go test ./tools/matrixcheck/ && make matrix-check MATRIXCHECK_FLAGS=-strict && make docs-check && make i18n-check`
Expected: PASS, 0 gaps, 0 pending.
- [ ] **Step 5: Commit**: `docs: Windows servers phase W1 (R60): decision, rulings, architecture, integration and security amendments, WIN test IDs, host preparation and admin guide, changelog`.

---

### Task 17: Final gates

**Files:** none new; fixes go to the task that owns the code.

- [ ] **Step 1: Full local gates**
Run: `make lint && make test && make i18n-check && make matrix-check MATRIXCHECK_FLAGS=-strict && make docs-check && make helper winhelper && make build && make coverage`
Expected: PASS; `covercheck` shows the five new floors met and no existing floor lower.
- [ ] **Step 2: Windows build and vet**
Run: `GOOS=windows GOARCH=amd64 go build ./cmd/alice-winhelper/ ./internal/providers/windows/... && GOOS=windows GOARCH=arm64 go build ./cmd/alice-winhelper/ && GOOS=windows go vet ./cmd/alice-winhelper/ ./internal/providers/windows/...`
Expected: PASS.
- [ ] **Step 3: e2e and image**
Run: `E2E_PROJECT=alice-e2e-w1 ALICE_E2E_PORT=9973 make ci` (or, when `make ci` cannot run here, `make image-check` and the e2e run of Task 15)
Expected: PASS.
- [ ] **Step 4: Real Windows**: the `windows.yml` run of Task 11 is green on both runners, or the rulings file lists it as an owner item and the acceptance report says acceptance item 4 is pending.
- [ ] **Step 5: Acceptance check against design §13 W1**, one line each in the rulings file: added, host key confirmed, facts shown, missing/old/not-elevated named (Tasks 8, 13, 14, 15); every binding listed, IIS sites as servers, foreign and CCS unsupported, truncation warns (Tasks 3, 9, 12); certificate linked by fingerprint (Task 12); real-runner helper and fidelity tests (Task 11). Merge `windows-w1` into `main` with `git merge --ff-only`; do not push.

---

## Self-review notes (for the executor)

- **Spec coverage.** §5 data model: Tasks 9, 12 (no migration: Global Constraints). §6.1: Tasks 8, 10, 14, 15. §6.2: Tasks 3, 5, 9. §7: Tasks 1-6. §8: Tasks 6, 8, 9, 10 (capabilities limited by Ruling 14). §9: Task 16's STRIDE rows, Tasks 8, 10. §11 rows W1 covers: unreachable/host key (Task 8, shared dial), helper missing/old (8), not elevated (2, 8), IIS not installed (9, 12). §12 items 1, 2, 4, 5, 7: Tasks 1-3, 7, 11, 15. §14 facts: the W0 table above. Deferred to W2+: deploy subcommands, `verify_deployment`, journal, `win.chain_differs`, the locations grouping (Ruling 18), release bundle (W4).
- **Names used across tasks.** `winproto.IISDumpResponse`, `winproto.SSLBinding`, `winproto.StoreCertificate`, `winproto.Site`, `winhelper.Host`, `winhelper.RunForced`, `wintest.Model`, `wintest.NewServer`, `wintest.Demo`, `linuxssh.ForcedCommand`, `linuxsshtest.Listen`, `windows.New`, `windows.ParseConfig`, `windows.ValidUser`, `windows.SetupScript`, `windows.AuthorizedKeysLine`, `windows.MatchBlock`, `windows.HelperChecksumsKnown`, `providers.WindowsFacts`, `inventory.TypeWindows`, `inventory.IsSSHTarget`, `inventory.HasCertificateLocations`.
