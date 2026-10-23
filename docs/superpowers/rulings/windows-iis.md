# Rulings: Windows servers and IIS, phase W1 (R60)

Owner decision 2026-10-22: the owner approved implementing the Windows design
([2026-10-21-windows-iis-target-design.md](../specs/2026-10-21-windows-iis-target-design.md)) with its §15 defaults,
phases W0-W4 in order. W1 (target, connection and discovery) was built on branch `windows-w1` from the plan
`docs/superpowers/plans/2026-10-22-windows-w1-target-connection-discovery.md` (17 tasks), after the W0 spike on real
Windows (branch `windows-w0-spike`, results in design §14 and §14.1). Spec: R60 in
`docs/superpowers/specs/alice-v1/00-decisions.md`, `02-architecture.md` ("Windows servers"), `03-integrations.md`
§13A, `04-security.md` §14.4 (WN-1..WN-9) and §15.11, `06-quality.md` §24.7 (WIN-01..WIN-14). Phases W2-W7 append
their rulings to this file.

None of the rulings below is a pricing decision. The security-relevant ones the owner should confirm are listed in
[Owner items](#owner-items).

## The plan's rulings as built

The plan's 22 rulings stand as written, except where an entry says "Amended".

1. **Config names follow the Linux path.** `targets.config` keeps `host`, `port`, `username` (not §8's `address` and
   `os_user`); the UI labels `username` "Windows account"; the discovery interval is the existing column. Default
   user `alice`; accepted names `^([A-Za-z0-9][A-Za-z0-9-]{0,14}\\)?[A-Za-z0-9][A-Za-z0-9._-]{0,19}$` (an optional
   NetBIOS domain, then a SAM name), stored as typed (`CORP\alice-svc` stays upper case in Alice). Amended (Task 10):
   the `Match User` line of `sshd_config` carries the name in lower case, because Win32-OpenSSH compares lower-cased
   names, also `domain\user`.
2. **Protocol 1 spans W1 and W2.** W2 adds `iis-deploy`, `iis-restore`, `iis-status`, `iis-fence`, `iis-cleanup` to
   protocol 1; W1's helper answers `UNKNOWN_SUBCOMMAND` for them. A release between W1 and W2 would make W2 protocol 2.
   W2 may also add fields to the protocol 1 shapes (see the SSLBinding ruling under Task 1).
3. **Elevation gate.** `version`, `win-facts` and `tls-probe` run without an elevated token; `win-facts` reports
   `elevated`; `iis-dump` refuses with `NOT_ELEVATED` (exit 2). `TestConnection` fails with `windows.not_elevated` when
   `win-facts` says `elevated:false`. Amended (Tasks 4+5): a non-elevated `win-facts` treats a fact file only
   administrators can read (`redirection.config`, the AutoCertRebind task) as absent, so it still answers and reports
   `elevated:false` instead of failing.
4. **Shared decision code.** `internal/providers/windows/winhelper` behind `winhelper.Host` holds the command split,
   dispatch, elevation gate, budget, dump assembly and bounds, appcmd XML parsing and the probe; the real helper and the
   emulator run it; matching IIS bindings to http.sys entries is Alice-side (`internal/providers/windows/convert.go`).
5. **Forced command line.** Alice sends `<sub> <arg> ...`: tokens of `^[A-Za-z0-9._:@+-]{1,253}$` joined by one
   space, at most 16 tokens and 4096 bytes, no quoting; the helper splits `SSH_ORIGINAL_COMMAND` itself
   (`winproto.ValidToken`, `JoinCommandLine`, `SplitCommandLine`); `linuxssh.ForcedCommand` is the one audited
   constructor (SEC-063). Amended (W0 §8, Tasks 7 and 8): **one fresh SSH connection per helper call**
   (`Pool.AcquireFresh`, one `Run`, the connection closed afterwards, never idle in the pool), because Windows OpenSSH
   gives every later session on a connection the first session's `SSH_ORIGINAL_COMMAND`. `linuxsshtest` models the bug
   (`StickyFirstCommand`), `wintest` turns it on, and a provider test asserts one connection per call. `ForcedCommand`
   also refuses a zero timeout or output bound.
6. **Locator.** `hostnameport` (host folded to ASCII lower case), `ipport` (`netip` canonical), `ccs`, each with the
   lower-case braced `app_id`; canonical text `http.sys/<type>/<address>:<port>`. An IIS https binding without an
   http.sys entry carries the IIS application id. An entry re-created by another application is another location with
   the same text (groundwork ruling 3: skipped and counted, the old row not marked missing).
7. **Matching IIS bindings to http.sys entries.** CCS flag → `ccs:<port>`; SNI flag → `hostnameport <host>:<port>`;
   else `ipport`: `*` matches `0.0.0.0:<port>` and `[::]:<port>`; a specific IP matches its own entry, else falls back
   to the wildcard. Hosts compared after ASCII folding; stopped sites are still servers. Amended (Task 9): a specific
   IPv6 address falls back to `[::]:<port>` before `0.0.0.0:<port>`; `*` with only one wildcard entry matches that one,
   and with none the missing location is `ipport 0.0.0.0:<port>` only. The emulator's wildcard fallback is
   family-agnostic (Task 7; tests and e2e use IPv4 loopback).
8. **Supported, in this order.** `ccs` → `win_ccs`; no IIS binding uses the entry → `win_foreign_app` (details
   `application` from `winproto.KnownApps`, else ""); store other than `My`/`WebHosting` → `win_store_unsupported`;
   else supported. `win_ctl` is a location warning, not a reason. Amended (W0 F2/F8, Tasks 1 and 3): `KnownApps` is
   IIS `{4dc3e181-e14b-4a21-b022-59fc669b0914}` (`iis`), IIS Express `{214124cd-d05b-4309-9af9-9caa44b2b74a}`
   (`iisexpress`), WinRM `{afebb9ad-9b97-4a91-9ab5-daf4d59122f6}` (`winrm`), SSTP
   `{ba195980-cd49-458b-9e23-c84ee0adcd75}` (`sstp`); the plan's guessed AD FS id is removed (the raw id is shown). A
   NULL or empty store name is `MY`, and every store comparison (supported rule, dedupe, certificate lookup) folds case.
9. **Problems.** `cert_missing` goes into `Problem`; `key_missing` and `key_inaccessible` into `KeyProblem`; such a
   location is `file_problem`, unsupported; the certificate of a key problem is still linked. Amended (Task 9): the
   provider sets `file_problem` itself (as the web-server `finish` does; the stored result is the same), and problems
   are computed for unsupported locations too (the WinRM certificate is linked and expiry-watched). Amended (Task 12):
   inventory treats `cert_missing` as "certificate gone", so a removed store certificate does not keep its old link.
10. **The certificate half of a Windows target.** `configUsable` accepts `Software == "iis"` without `Found`; a Windows
    scan has no SSH half and sets `last_discovery_at`. Amended (Task 12): `Reconcile` ignores an SSH half reported for
    a target that is not `IsServer` (keys, read files, accounts).
11. **Type predicates.** `inventory.IsServer` keeps "SSH keys" (Windows not included); new `IsSSHTarget` (Linux, web
    servers, Windows) and `HasCertificateLocations` (web servers, Windows); Windows is not a web-server type and
    `deployTypes` does not offer it.
12. **appcmd failure fails the dump.** With IIS installed, an appcmd failure, timeout or unparsable XML answers
    `IO_ERROR` and nothing is stored. Amended (Tasks 4+5, runner run 2): appcmd runs by absolute path with an
    allow-list of system environment variables (no `PATH`, `PATHEXT`, `PSModulePath`, `SSH_*`), not `SystemRoot`
    alone, because with `SystemRoot` alone every site state read `Unknown` on the runners.
13. **Only three new error codes.** `ALC-WIN-0001` `windows.helper_missing`, `ALC-WIN-0002` `windows.helper_outdated`,
    `ALC-WIN-0003` `windows.not_elevated` (502); other refusals stay `ssh.helper_refused` with `helper_code`.
    `UNKNOWN_SUBCOMMAND` maps to `windows.helper_outdated`. As built (Task 8): that mapping carries `subcommand` and
    `helper_code`, not the protocol parameters (the helper's protocol was accepted), so the message texts have no
    placeholders; `NOT_ELEVATED` from `iis-dump` maps to `windows.not_elevated` too.
14. **W1 capabilities** are `test_connection` and `discover_certificates`.
15. **Setup script.** The administrator copies `alice-winhelper-windows-<arch>.exe` as `.\alice-helper.exe` next to
    the script; `$AliceUser` is edited; the helper hash is checked for `AMD64`/`ARM64`; the firewall rule's remote
    address is the key line's `from=`, else `Any` with a notice; the key line is `restrict[,from="..."]` and the key;
    a `windows` profile without a script is `ErrNoSetupScript`. Amended by the Task 10 rulings below, and by the final
    review (C1): the key line is `restrict,command="\"C:\Program Files\Alice\alice-helper.exe\" ssh"[,from="..."]`
    and the key.
16. **Checksums.** `make winhelper` writes `bin/alice-winhelper-windows-{amd64,arm64}.exe` and
    `bin/alice-winhelper.sha256`; linker variables `helperSHA256WindowsAMD64/ARM64`; `make build`, the Dockerfile,
    `reproducible-check.sh` and `make image-check` include them; the release bundle waits for W4.
17. **Real-Windows workflow.** `.github/workflows/windows.yml` (path-filtered push and pull request, nightly, manual),
    not required until W4. Amended: a plain checkout (after the `nul.go` rename below, not the spike's sparse checkout);
    windows-2022 and windows-2025; real-runner fixtures use ports **45300-45399**, never the images' IIS Express range
    44300-44399, and never assume an empty http.sys table.
18. **UI.** The shared locations panel with the column "IIS site", software "IIS", one row per binding sorted by
    certificate then canonical text, the deploy control disabled by capability.
19. **OS facts.** `win-facts` fills `providers.OSRelease` (`ID "windows"`, build, product) and `providers.WindowsFacts`.
20. **Dump bounds.** `MaxBindings 1000`, `MaxCertificates 1000`, `MaxSites 2000`, `MaxSiteBindings 10000`,
    `MaxChainCerts 20`, `MaxCertDER 64 KiB`, `MaxAppcmdOutput 32 MiB`, `DumpOutput 16 MiB`; a cut list sets
    `list_truncated` and the provider adds `locations_dropped`; the 50 s budget ending answers `IO_ERROR`.
21. **Test IDs.** `WIN-01..WIN-14` in `06-quality.md` §24.7; `tools/matrixcheck` takes the `WIN` prefix
    (`TestSpecIDsFindWindowsRows`).
22. **e2e fake.** `cmd/alice-fakewindows` (`serve`, `ctl ping|prepare|hostkey`) wraps `wintest` with a fixed demo host
    (sticky first command on); `ctl prepare` reads the setup script on stdin and authorizes the key line it carries.
    Built by Task 15.

## W0 adjustments

Each W0 verdict (design §14, §14.1) and the task it changed.

| W0 fact | Adjustment | Task |
|---|---|---|
| §8 changed: later sessions on one connection get the first session's command | One fresh connection per helper call; `StickyFirstCommand` in `linuxsshtest`, on in `wintest`; a provider test counts connections (Ruling 5) | 7, 8 |
| F2: ipport may be IPv6 | IPv6 `[::]:443` decoded from `SOCKADDR_IN6`; tests with IPv6 and noisy runner records | 3 (W0 revisit), 5 |
| F2: NULL store = MY, case varies | `BuildDump` maps an empty store to `MY`; dedupe and every lookup fold case (Ruling 8) | 3 (W0 revisit), 9 |
| F2: ccs record has an app id and flags, no hash, NULL store | ccs accepted with an empty hash and store, any host-sent hash or store dropped; the ccs address is its `LocalAddress` IP | 3, 5 |
| F2: struct sizes and `HttpInitialize` 2.0, ULONG results | The spike's layouts (pointers as `uintptr`), sizes asserted in a test; version 2.0; results from the return value; non-Ex queries (their read-back kept every setting, `DefaultFlags` carries the 2022+ switches) | 5 |
| F2: runner images hold about 100 IIS Express records and a WinRM listener | Real fixtures on ports 45300-45399; no test assumes an empty table (Ruling 17) | 4, 5, 11 |
| F3: a local administrator's key logon is elevated without `LocalAccountTokenFilterPolicy` | Elevation read through `TOKEN_ELEVATION` (`GetTokenInformation`, error checked: a failure is `IO_ERROR`, never "not elevated"); the setup script never sets the policy; the `not_elevated` text names the domain-account setup | 4, 10, 13 |
| F4: PFX import lands in the software KSP, key DACL SYSTEM + Administrators | `KeyProvider` from `CERT_KEY_PROV_INFO`; `key_usable_by_system` from the key's DACL (see Tasks 4+5); `CryptAcquireCertificatePrivateKey` bound with a `*uint32` BOOL (x/sys bug) | 5 |
| F6: appcmd XML shape, shared configuration honoured, present with Web-Server alone | Fixtures `appcmd-ws2022.xml`/`ws2025.xml` from the spike run; the runner installs `Web-Server` only | 3, 11 |
| F7: OpenSSH capability 25-35 s on 2022, preinstalled on 2025 | The workflow installs nothing; the setup script installs the capability on 2022; no MSI fallback | 10, 11 |
| F8: IIS, IIS Express, WinRM, SSTP ids; AD FS unknown | `KnownApps` as in Ruling 8, AD FS shown by raw id | 1 (W0 revisit), 9, 14 |
| Checkout fails on `internal/api/nul.go` (reserved device name) | Renamed, see below | W0 revisit |

**The Windows reserved-name rename.** `internal/api/nul.go` and `nul_test.go` became `unstorable.go` and
`unstorable_test.go` (commit `7705d120`), so a plain Windows checkout works; `internal/archtest/windowsnames_test.go`
(`TestNoWindowsReservedFileNames`) refuses a tracked path with a reserved device name (CON, PRN, AUX, NUL, COM1-9,
LPT1-9, with any extension), a character Windows refuses, or an element ending in a space or a dot.

## Rulings made during execution

One line each: the ruling, then why.

### Controller (order and process)

- Execution order 1, 2, 3, 6, 7, 8, 9, 12, 13, 14, 10, 4+5, 11, 15, 16, 17: Tasks 7 and 8 need Task 3, and the
  W0-heaviest tasks went last so W0 could land first.
- Tasks 4+5 ran as one dispatch in parallel with Task 13, and Tasks 10 and 14 in parallel: disjoint files.
- Runner-relevant minors were folded into the fix rounds of Tasks 4+5 and 10: each would otherwise cost a Windows
  runner round trip.

### Task 1 (winproto)

- `SSLBinding` keeps the plan's fields (the members of the 80-byte `HTTP_SERVICE_CONFIG_SSL_PARAM`); the TLS extended
  parameters of the Ex records are not read in W1: W2 must read and preserve them before writing (protocol 1 may grow).

### Task 3 (iis-dump)

- A store name is passed through verbatim from the host (after the empty-is-`MY` rule); folding is Alice-side: the
  certificate entry is listed under the first binding's spelling.
- Host names pass through cleaned, not folded; folding is Alice-side (Ruling 6).
- A certificate read error fails the whole dump with `STORE_ERROR`: a silently missing certificate would look like
  `cert_missing` on a binding that has one.
- An `ExpiredInStore` error leaves that store out of the warning: it is a warning fact, not worth failing the dump.
- An invalid DER, chain or `key_problem` from the host drops that certificate and sets `truncated`: the record cannot
  be trusted, and a cut list marks nothing missing.

### Task 6 (checksums)

- Task 6 created a placeholder `cmd/alice-winhelper` (main and a stub host) so `make winhelper` built before Task 4:
  the plan listed Task 6 as independent but it builds Task 4's package.
- `check-image.sh` skipped the Windows checksum assertions until `alice` linked the Windows provider; Task 8 removed the
  skip: a self-removing gap.

### Task 7 (wintest emulator)

- `Serve` with a bare host listens on the binding ports themselves (the e2e container), `host:0` on a random port per
  binding (tests): deterministic in both cases.
- A dial to `10.0.0.5:443` reaches the listener of port 443 but remembers the meant address, so an `ipport 10.0.0.5:443`
  entry is selected through `tls-probe`: the emulator needs no real interface per address.
- A modelled key with `KeyUsableBySystem` unset counts as usable; no key is `key_missing`: the real helper's defaults.
- The expired-in-store count is a stored number, not computed: it is a fact the dump reports, not a decision.

### Task 8 (provider: Open, TestConnection)

- The host key in the connection report is the `win-facts` connection's: every call dials and is pinned.
- Fact bounds: 16 stores, store names 64 runes, other facts 200 runes (linuxssh's bound), helper version 40.
- `Options.AllowUnverifiedHelper` is used by the setup guide only (a development build without checksums gets a
  script that says it cannot verify the helper): the connection itself never depends on it.
- Task 8's minimal `Discover` (an empty result) was superseded by Task 9: it only kept the provider complete before
  discovery was built.

### Task 9 (discovery)

- A listed certificate whose SHA-1 differs from the binding's thumbprint is `not_a_certificate`: only a hostile dump
  can do that.
- A certificate with no key and no stated problem is `key_missing`; an unknown key problem value is `unknown`.
- Host names accept Unicode letters and digits plus `.-_*` (IDN U-labels and wildcard host headers are listed), folded
  in ASCII only: W2 must check host tokens against the ASCII forced-command vocabulary before deploying.
- A zoned IPv6 address (`fe80::1%3`) is dropped with `locations_dropped`: a locator cannot hold a zone.
- A duplicate canonical text keeps the first entry and drops the second with `locations_dropped`: impossible in
  http.sys, so hostile.
- A dropped IIS site binding (for example SNI without a host) also adds `locations_dropped`: it could hide a missing
  entry location. More than 32 dump warning codes adds only `list_truncated`.
- Discovery facts: `ConfigValid` always true, version cleaned to 64, `Found` = IIS installed; facts are returned without
  IIS so foreign locations are stored.
- `details` holds no revocation freshness or URL timeout (the brief's list is explicit); `key_usable_by_system` is a
  bool or null when unknown.

### Task 10 (setup script and guide)

- `Match User` in lower case: Win32-OpenSSH compares lower-cased names.
- The Alice block is always appended at the end of `sshd_config` (an old one removed first; an unmatched
  `# BEGIN Alice` stops the script): no global option can end up inside it.
- A key line with the same key blob is replaced, other administrators' lines are kept: an old line without `from=`
  must not bypass a new restriction.
- `SetupScript` accepts only `AuthorizedKeysLine`'s shape in ASCII: the script must stay ASCII for PowerShell 5.1
  without a BOM.
- `from=` is split on commas into a firewall address list; a `from=` with `*`, `?` or `!` becomes `Any` with the
  notice: the firewall cannot express sshd's pattern syntax.
- The local account is created through ADSI (WinNT provider), not `New-LocalUser`: the LocalAccounts module is
  unreliable in pwsh 7; an existing account keeps its password; membership is added only when not a direct member.
- The deny rights are set through a minimal INF (existing holders kept), and `secedit /configure` runs only when a
  right changes: re-applying a whole export could change other policy.
- For a local account the script warns when "Deny access to this computer from the network" holds S-1-5-113/114 and
  points to the domain setup: it cannot test the key logon itself.
- `C:\Program Files\Alice` grants the account read and execute besides Administrators and SYSTEM full control, so a
  filtered token can still start the helper and Alice reports `windows.not_elevated` instead of `helper_missing`; the
  data directory stays Administrators and SYSTEM only. (Owner to confirm.)
- The helper is hashed in place first, then staged in the protected directory and hashed again before the move (the
  Linux A-3 TOCTOU rule).
- ACLs: owner Administrators, `/reset`, then `/inheritance:r /grant:r`; reparse points under `C:\ProgramData\Alice`
  refused and nothing done recursively (fix round 1: users can create folders in ProgramData, and `icacls /T` follows
  planted junctions).
- The script accepts the running administrator's own SID as owner of existing Alice directories: an elevated
  administrator's default owner can be its own SID, and it widens nothing. (Owner to confirm.)
- OpenSSH's own firewall rule `OpenSSH-Server-In-TCP` is left as it is, with a warning when Alice's address is set and
  that rule is enabled: removing it could cut other administrators off.
- Inventory merges only the `windows` snippet of the Windows provider; `Guide.AuthorizedKeysLine` stays the Linux line
  (the Windows line is inside the script).
- Fix round: no `icacls /T` anywhere: a recursive grant follows junctions a user planted under ProgramData.
- Fix round: an existing Alice directory is refused unless it is owned by Administrators, SYSTEM or the running
  administrator and holds no reparse point: a user-created directory must not be adopted.
- Fix round: the script body runs inside `& { }`: pasted into a console it runs as one block and stops at the first
  error instead of continuing line by line.
- Administrators membership is compared by SID, and "already a member" (0x80070562) is success: the runner's second
  run of the script failed on the name comparison and the duplicate add (commit `b5312cda`).

### Task 12 (inventory)

- `cert_missing` is inventory's constant `problemCertMissing`, checked against `windows.ProblemCertMissing` by a test:
  the providers package stays unchanged.
- `typeValues` order is `linux, nginx, apache, haproxy, windows`; `TestNginxTargets`' refused-type list includes
  `windows`.
- `RecordConnectionOK` replaces `Facts.Windows` only when the report carries one (as `WebServer`).
- The plan's `TestWindowsTargetHasNoSSHKeyRoutes` became `TestWindowsTargetIsNoKeyServer`: the key routes and
  `internal/sshkeys` gate on `inventory.IsServer`, so the test checks the predicates and that a Windows target has no
  key files or keys.
- A Windows scan's warnings are its facts' warnings (fix round 1: they were never stored).

### Task 13 (API, locales)

- `vaultTypes` (the allowed values of `GET /targets?type=`, a historical name) gains `windows`: otherwise Windows
  servers could not be filtered.
- The tests are `internal/api/errors_winserver_test.go` and `targets_winserver_test.go`: a `_windows_test.go` suffix
  is a GOOS constraint and would silently not run on Linux.
- The three messages have no placeholders (Task 8's mapping); the `not_elevated` text states the W0 verdict.

### Task 14 (web)

- Tests live in `TargetsPage.test.tsx` (no `AddServerModal.test.tsx` exists) and no axe checks were added (the repo has
  none for these pages; the e2e accessibility check partly covers it): the brief named files that do not exist.
- The Linux key-problem text now reads "Key file:" (the shared panel shows a key problem on its own line).

### Tasks 4+5 (real helper)

- `key_usable_by_system` counts SYSTEM and the groups in SYSTEM's token (Administrators, Everyone, Authenticated
  Users): the first ACE for such a SID whose mask covers read (`GENERIC_READ`, `GENERIC_ALL` or `FILE_READ_DATA`)
  decides; no such ACE is `key_inaccessible`; a NULL DACL is usable; an unreadable descriptor is unknown. Why: a DACL
  granting Administrators only is usable by SYSTEM. (Owner to confirm; strict SYSTEM-only is three deleted SIDs.)
- A key the elevated helper may not open, or that CNG refuses (a legacy CSP key), is `has_key:true` with unknown
  facts, not a problem; only the "key not there" codes are `key_missing`. W2 decides whether such a key is deployable.
- The chain is built with `CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL` (never the network within the budget); a failed chain
  call fails the certificate and the dump is `STORE_ERROR`; an untrusted chain still succeeds.
- `IISFacts` takes a present `InetStp` key with `MajorVersion` as installed (the brief's rule; requiring appcmd.exe as
  well is a possible refinement).
- A FILETIME past 2262 (a NotAfter of 9999-12-31) is converted without wrapping into the past, and a store fails
  on any error other than "not found" (fix round 1).
- Runner finding (run 2): appcmd with only `SystemRoot` reports every site state `Unknown`; the helper passes an
  allow-list of 22 system variables, never `PATH`, `PATHEXT`, `PSModulePath` or `SSH_*` (Ruling 12): a planted path
  entry or a variable from the SSH session must not reach appcmd.

### Task 11 (real-Windows tests and workflow)

- Fixture ports 45310-45320 plus an http host-header binding on 45399 per site; the other real tests use 45301-45304.
- The intermediate goes into `LocalMachine\CA` before `netsh http add sslcert`; the root is in no store, so the
  expected served chain is leaf + intermediate (W0 F5).
- Key-missing scenario: bound with the key present, then the certificate removed without `-DeleteKey` and the bare
  `.cer` imported again; cert-removed: `certutil -delstore My <sha1>` after binding.
- Two separate `ssh` processes (fresh connections); the host key pinned from `ssh-keyscan` and cross-checked against
  `ssh_host_ed25519_key.pub`; nothing sets `StrictHostKeyChecking=no`.
- Leaves use ECDSA P-256: a CNG KSP key is guaranteed (RSA could land in a legacy CSP).
- Real-Windows tests start Windows PowerShell 5.1 without pwsh 7's `PSModulePath` (run 1: the Cert drive and the
  Security module were missing).
- The fidelity test compares netsh's defaults, the installation type and the store order instead of copying them
  (review); `wintest` lists stores in the helper's order.
- The setup smoke test checks `sshd_config` text, `sshd -t` and behaviour over real connections (forced command, a
  shell line refused, no TTY, no forwarding, no password) instead of `sshd -T`: Win32-OpenSSH's `-T -C user=` cannot
  resolve the local account (run 2).
- The smoke test accepts the client ending a session whose PTY sshd refused (`PermitTTY no`) and still requires no
  shell output: the Windows ssh client closes such a session itself (run 4).
- IIS is installed with `Web-Server` only: W0 F6 showed appcmd is present without the `Web-Mgmt-*` features.
- The model's http.sys records use netsh's documented defaults, independent of the helper: copying the helper's
  readings into the model would make the fidelity test compare the helper with itself.
- The log-only diagnostic `TestRealAppcmdStateByEnvironment` stays as a record of the appcmd environment finding
  (Ruling 12): a later image change shows in its log.

### Task 15 (e2e)

- The fake accepts Alice's key for any user name and does not enforce `restrict` or `from=`: that is sshd's job, which
  the real-runner smoke test proves; the fake models the helper. (Final review: `ctl prepare` refuses a key line
  without the helper's `command=` option, so the e2e proves the line Alice ships carries it.)
- `alice-fakewindows ctl endpoints` was added: the journey needs the binding endpoints the fake serves.
- The Makefile's `E2E_PROJECT :=` ignores the environment, so the e2e ran as project `alice-e2e` (the owner's `alice`
  stack untouched), not `alice-e2e-w1`; the owner may want `?=`. (Final review: now `?=`.)

## Final review fixes

- **C1 (security): the key line forces the helper.** `C:\ProgramData\ssh\administrators_authorized_keys` is read by
  the default `Match Group administrators` block for every member of Administrators, `restrict` does not block exec,
  and `ForceCommand` applied only under `Match User <account>`: anyone holding Alice's private key could sign in as
  any other administrator (or a domain account whose `Match User` pattern did not match) and run any command. The
  line is now `restrict,command="\"C:\Program Files\Alice\alice-helper.exe\" ssh"[,from="<from>"] <key>` (OpenSSH
  un-escapes only `\"` inside a quoted option value, so the path is written as it is; built from
  `winproto.HelperPath`); sshd applies `command=` whatever the account and still sets `SSH_ORIGINAL_COMMAND`. The
  `Match User` block stays as a second layer. The setup script takes the key blob from Go (`$keyBlob`): the forced
  command holds spaces, so splitting the line on spaces no longer finds it. `TestRealSetupScript` creates a second
  local administrator `alice-w1-other`, signs in as it with Alice's key and requires the helper's
  `UNKNOWN_SUBCOMMAND` for `whoami` and the helper's answer for `version`, then removes the account.
- **I1**: the Add-server dialog's Windows script carries the typed account (`$AliceUser = '<typed>'`) when it passes
  the form's Windows account rule (which excludes quotes), else `alice`.
- **I2**: a Windows server without IIS (`web_server_not_found`) shows a neutral note, not the stale-scan alert.
- **M1**: the OpenAPI target `username` is at most 36 characters (15 + `\` + 20).
- **M2**: an http.sys entry with IIS's application id that no IIS site uses keeps reason `win_foreign_app` with
  details `application` `iis_unused` ("No IIS site uses this binding"); the UI names known applications (IIS, IIS
  Express, WinRM, SSTP).
- **M3**: a certificate the helper dropped for its bounds (chain over 20, DER over 64 KiB) is listed in the dump's
  `dropped_certificates` (protocol 1 grows, Ruling 2); a binding naming it reads `leaf_unreadable`, not `cert_missing`.
- **M4 and chores**: the Windows workflow's path filter adds `internal/providers/*.go` and `internal/platform/**`;
  `E2E_PROJECT ?=`; the hardening check covers the fakewindows service; stale comments fixed; an archtest guard lets
  only `internal/providers/windows` (and linuxssh itself) call `linuxssh.ForcedCommand`.

## Deferred to W2

- The Ex records' TLS extended parameters (Task 1 ruling) and preserve-settings taken from the dump, not `details`.
- Whether a key problem (or an unknown legacy CSP key) stays deployable (Ruling 9, Tasks 4+5).
- A cut scan can relabel an IIS location `win_foreign_app` or `cert_missing`: nothing is marked missing, but W2 must not
  block a deployment on a cut scan.
- Run's handler goroutine continues after the budget fires: mutating W2 handlers must honour the context.
- Host tokens checked against the ASCII vocabulary before deploying (Task 9).
- `helperReason` maps Windows codes such as `HASH_MISMATCH` to `ssh.*` today.

## Owner items

- **Windows Server 2019**: not on GitHub's images; check discovery by hand (`winspike osinfo` prints the httpapi
  export; design §14 F2).
- **A domain account under the hardened baseline**: the domain-account setup (`CORP\alice-svc` in a GPO-managed local
  Administrators group, "Deny access to this computer from the network" holding S-1-5-114) and that the lower-case
  domain user in the `Match User` line matches the sign-in.
- **Server Core**: appcmd and the helper on a Server Core installation (F6).
- **AD FS**: its application id is unknown; an AD FS binding shows the raw id. Send the id when a server shows it.
- **Antivirus**: Defender real-time protection is off on the runners; check the helper and the setup script with
  Defender (or the customer's EDR) on.
- **Confirm** Task 10's grant of read and execute on `C:\Program Files\Alice` to the account, and the setup script
  accepting the running administrator's SID as owner of existing Alice directories.
- **Confirm** `key_usable_by_system` counting SYSTEM's groups (Administrators, Everyone, Authenticated Users), not
  SYSTEM's SID only.
- Groundwork ruling 7 (a probe address for the web-server providers later or never) is still open.
- **M5, a release between W1 and W4**: the Windows server type is visible from W1, but the release bundle and
  `SHA256SUMS` gain `alice-winhelper-windows-*.exe` only in W4. If a release is cut before W4, either ship the two
  helper files by hand with the release (the image already embeds their checksums) or hide the type for that release.
- **Confirm** the key line's `command=` (final review C1) on Server 2019 and with a domain account (the runners prove
  it on 2022 and 2025 with a second local administrator).
- Real-runner acceptance (design §13 W1 item 4): met — windows.yml green on windows-2022 and windows-2025, run
  39778045600 (5th run; runs 1-4 fixed PSModulePath in tests, site state via appcmd env, sshd -T, PTY expectation,
  group-membership idempotency): <https://github.com/erenmeren/alice/actions/runs/39778045600>; after the final-review
  fixes (C1's `command=` key line with the cross-account check) again green in run 39826796065 (7th of 7 runs; run 6
  failed only in the test's own second-administrator setup, rewritten with net.exe):
  <https://github.com/erenmeren/alice/actions/runs/39826796065>.
- **`make ci` vuln stage**: `osv-scanner` fails on vite 8.3.1 (a dev dependency in `web/package-lock.json`, unchanged
  by W1, the same on `main`): six advisories fixed in 8.3.3. W1 does not bump it; a lockfile update (Dependabot) is
  the owner's call. Every other `make ci` stage passed locally (e2e 158 passed, hardening check, image check and scan).
- `make secrets-scan` run from a git worktree scans no commits (the container cannot follow `.git` to the main
  repository); the full-history scan with the main `.git` mounted found only the setup test's fake key blob, now
  fingerprinted in `.gitleaksignore`.

## Acceptance (design §13 W1)

- A Windows server is added, its host key confirmed, its facts shown; a missing, old or not elevated helper is named
  (ALC-WIN-0001..0003): Tasks 8, 13, 14, 15 (e2e journey EN and TR).
- Discovery lists every http.sys binding; IIS bindings are their servers; foreign applications and CCS bindings are
  unsupported with their reason; truncation warns and marks nothing missing: Tasks 3, 9, 12.
- The certificate of each binding is linked to inventory by fingerprint (managed in network discovery): Task 12
  (`TestWindowsScanStoresBindingLocations`), e2e Certificates page.
- Real-runner helper tests and the fidelity test pass for the read subcommands: Task 11, runs above.

# W2 (R61)

Phase W2 (deployment, verification and rollback) was built on branch `windows-w2` from the plan
`docs/superpowers/plans/2026-10-22-windows-w2-deployment-verification-rollback.md` (16 tasks), on the owner's
approval of W0-W4 with the §15 defaults (2026-10-22). Spec: R61 in `docs/superpowers/specs/alice-v1/00-decisions.md`,
`02-architecture.md` ("Windows servers"), `03-integrations.md` §13A.4 and §13A.8-§13A.10, `04-security.md` §14.4
(WN-1 and WN-4 amended, WN-10..WN-13), `06-quality.md` §24.7 (WIN-15..WIN-28), design §14 (F9, F10), §14.1 and §17.
No migration. None of the rulings below is a pricing decision; the security-relevant ones the owner should confirm are
listed under [Owner items (W2)](#owner-items-w2).

## The plan's rulings as built (W2)

The plan's 24 rulings stand as written, except where an entry says "Amended".

1. **Decision R61, no migration.** As written: the schema of `00031` carries everything; error codes
   `ALC-WIN-0004`..`ALC-WIN-0012`; test IDs `WIN-15`..`WIN-28`.
2. **Protocol 1, helper 0.2.0.** As written: `winproto.Version` `0.2.0`, `1.0.0` kept for the first released helper
   (W4); a 0.2.0 helper answers `iis-cleanup` `UNKNOWN_SUBCOMMAND` (W3).
3. **A W1 helper is outdated for writing.** As written (`winproto.WriteMinVersion` `0.2.0`, `VersionAtLeast`: missing
   parts count as zero, an unparsable version is below). Amended (Tasks 7, 8): every write method, `VerifyDeployment`
   included, also returns `ErrUnsupported` on a session without its capability (never fires in production); a dial
   failure or a context that ended before Run is `no_change` (nothing reached the helper).
4. **Command line and standard input.** As written. Amended (Tasks 1, 3): `RestoreInput` is bounded by
   `winproto.MaxRestoreInput` (32 KiB); all six `DeployInput` members are required (the lists have no `omitempty`);
   JSON syntax, missing, duplicate or unknown members and bad PEM are `BAD_CONTENT`, a value Alice does not deploy to
   (a locator, a hash, a list) is `INVALID_ARGUMENT`; the key PEM body may not contain spaces or tabs.
5. **ASCII host tokens.** As written. Amended (Task 1): `ValidHost` also refuses `_`, a bare `*`, `*.` alone and a
   wildcard anywhere but the leading label (the 253 bytes count the `*.`); `Locator.Canonical()` is strict, not
   normalising (lower-case braced app id, netip-canonical unmapped IP, no host on an ipport, no IP on a hostnameport),
   and equals W1's discovery text (`TestWriteLocatorCanonicalEqualsDiscovery`).
6. **Helper codes get Windows reasons.** As written. Amended (Tasks 7, 8, 10): `OPERATION_EXISTS` from `iis-deploy`
   is uncertain (an earlier send may have committed; the engine reads the status), not `no_change`; the transport's
   `ssh.output_too_large` keeps its name; a restore that fails maps by its class (`backup_missing`, `key_unusable`,
   `store_error` to their Windows reasons, `io_error` to `windows.io_error`, every other class
   `deployment.rollback_failed`); `windows.helper_missing` met on an uncertain path (a killed helper: exit 255, no
   JSON) is recorded as `deployment.interrupted`, as Linux records `ssh.helper_missing`.
7. **Mutating handlers honour their context; the budget never lies.** As written. Amended (Task 2 and its review):
   once `enter` succeeded, **every** error a handler returns is answered `OUTCOME_UNKNOWN` (exit 4), not only the
   budget's end: a handler that meets a failure after `enter` records it in the journal and answers with a phase; a
   refusal before `enter` passes through. A kill at a point answers **nothing** (no line on stdout, like a dead
   process): `winhelper.ExitKilled` 137 in process, `wintest.KilledExit` 255 at the SSH layer (an ssh client sees no
   exit status). Standard input is read before the elevation check, so an oversized input from an unelevated caller
   is `TOO_LARGE`. Precision (final review Minor 1): when the budget ends, the real helper answers `OUTCOME_UNKNOWN`
   at once and `main` exits with that answer, so a handler past `enter` is cut there and the journal decides what
   happened (safe). The `WriteGrace` bound (8 s) on finishing a step therefore applies only to an in-process host,
   the emulator and the e2e fake: there the abandoned call may keep writing for up to 8 s after the answer, holding
   the lock, and may commit after `OUTCOME_UNKNOWN`, which a real host cannot. That gap is latent: no test fault makes
   a host slow (Task 4 review minor 2; deferred to W3 below).
8. **Journal and binding records.** As written. Amended (Tasks 2, 3): exit codes 2 (`USAGE`, `INVALID_ARGUMENT`,
   `BAD_CONTENT`, `TOO_LARGE`, `NOT_ELEVATED`), 3 (`HASH_MISMATCH`, `FENCED`, `OPERATION_EXISTS`, `RECOVERY_PENDING`
   with `pending_op`, `BINDING_NOT_FOUND`, `KEY_UNUSABLE`, `BACKUP_MISSING`, `UNKNOWN_OP`, `SUPERSEDED`), 4 (`BUSY`,
   `JOURNAL_FAILED`, `IO_ERROR`, `STORE_ERROR`, `OUTCOME_UNKNOWN`); any known operation id is `OPERATION_EXISTS`, a
   prepared one too (Linux restarts a prepared operation; on Windows recovery fences it); the binding record is
   `{"binding": <canonical text>, "op": <op>, "chain": [...]}` (`op` "" clears); a tombstone is `{op, phase fenced,
   prev_record}` and tombstones are not bounded (WriteHost has no listing; W3); `imports.json` keeps at most 1024
   entries, oldest dropped; state files are read up to `winhelper.MaxStateBytes` (512 KiB) from a regular file, never
   through a reparse point; the journal gains `forbidden_final` and `cause_error` (Ruling 12), cross-checked on read.
9. **Import.** Amended: the one-time PFX password is **32 printable ASCII characters (192 random bits)**, not 32 raw
   bytes: `PFXImportCertStore` takes a wide string and the PBES2 key and the BMPString MAC must agree on the text.
   PBKDF2 and the PKCS #12 KDF run over `[]byte` so their buffers can be cleared (HMAC's internal pad state cannot,
   like Go's parsed keys, WN-4). Keys accepted: PKCS #8, PKCS #1, SEC 1, RSA or ECDSA (Ed25519 or an encrypted key is
   `BAD_CONTENT`). `ImportPFX` of a certificate the store already holds returns its SHA-1, leaves the copy alone and
   deletes the key the import had just persisted (`NCryptDeleteKey`, silent); a copy without a usable key is refused
   `KEY_UNUSABLE` before the gate. F10's primary route held (below), so no fallback route was built.
10. **Bind.** Amended: `unchanged` needs three things: the record names the new certificate, no intermediate was
    added, **and the binding record's `chain` (leaf and intermediate DER SHA-256s of Alice's last committed bind)
    equals this deployment's chain**; otherwise a same-hash write (W0 F5: schannel serves the chain of the record's
    last write). A deployment takes the binding record without a chain at `prepared`, writes its chain after
    `committed`, and every restore write clears it, so a kill anywhere leaves the next deployment a same-hash write.
    F9 (below): the real helper's strategy `exRepair` updates the base record, reads the Ex parameters back and
    rewrites only what changed (none on 2022 and 2025); the real dump reads no Ex parameters (only the deploy and
    restore paths' live read does: run 1 showed an Ex read error dropped every binding); an Ex parameter type the
    helper cannot decode is left out of the record and never written; types 0-5 are read. The record vanishing at
    the bind is `restore_failed`, `failed_step bind`, `error file_changed`; any other update error is "maybe written":
    the self-restore runs and the answer carries `error io_error`. http.sys's 1312 at the bind writes nothing: the
    record is unchanged, the answer is `restored`, `failed_step bind`, `error key_unusable`, with no restore and no
    guard check (only a read-back mismatch takes the guarded self-restore).
11. **The lists are checked by the helper on every restore path.** As written. Precision (Task 2): on Windows the
    guard checks the certificate's SPKI (the key belongs to the store certificate; a different key cannot complete a
    handshake for it); with both lists empty an unparsable DER is not forbidden (Linux's `guard.empty()`).
12. **Restore preconditions.** Amended: **`restore_forbidden` is monotonic**: the guard that forbade (journal lists ∪
    the input's) is kept in the journal, so a re-sent restore with smaller lists stays forbidden; past `MaxForbidden`
    the journal is marked `forbidden_final`; a failed write of the grown guard is `OUTCOME_UNKNOWN`, never
    `restore_forbidden`. **`BACKUP_MISSING` in `iis-restore` is refused before the gate without a journal write** (a
    later restore can still succeed); in the deploy's self-restore the same condition is `restore_failed`, `error
    backup_missing`. "Usable" means found, with a key, no key problem, and its DER SHA-256 equal to the journal's
    `previous_sha256`. For a `committed` journal a record naming the previous hash counts as restored without a write;
    for a half-written one (writing, restoring, restore_failed, restore_forbidden) only an exact match counts. A later
    `restored` answers the original cause (`cause_step`, `cause_error`).
13. **Event Log.** Amended (Task 3): 1001 `operation <op> binding <canonical> old <prev sha256> new <new sha256>`, 1002 the
    same with old and new swapped, written only after an actual write-back (a `restored` that needed no write, the
    record already naming the previous certificate, logs no event; the plan said "after `restored`"); the helper never registers the source
    (the setup script does; without it Event Viewer shows "description not found" next to the text).
14. **Alice imported or not.** As written: a key problem stays `file_problem`, unsupported.
15. **Verification.** Amended (Tasks 5, 8): `tlsverify` may import `platform/clock` and `platform/netaddr` and joins
    the providers' allow list; `Options.Log`; the probe errors read `tls probe: ...`; Alice's probe is a fresh
    handshake for Nginx too (no session cache, tickets off: it never resumed, nothing measured changes); the IIS host
    headers give SNI for both ipport forms; the helper's `tls-probe` address is `127.0.0.1` for hostnameport and
    `0.0.0.0`, `::1` for `[::]`, the IP itself for a specific address; endpoints are deduplicated by (port, SNI), at
    most 10; an Administrator's probe address stands for every endpoint, a specific-IP binding included; an ipport
    wildcard probes the port without telling `0.0.0.0` from `[::]` (as Nginx and W1 Ruling 7): a probe that reaches
    the other family's record fails and rolls back (safe side).
16. **`win.chain_differs`.** As written; the params ride on the verify step whenever `built_chain_length` > 0 differs
    from the deployed length, on success and on failure.
17. **Rollback info.** Amended: `providers.RollbackRequest` gains `Backup BackupRef` (the start record's rollback info),
    because the location's details are "as last discovered" and may already show the new certificate (Task 7
    review); `previous_sha256` is the send's compare-and-swap token; `store` and `previous_sha1` are written only while
    the location's `cert_file_sha256` still equals the token (a scan in between may have seen a rebind); `backup_dir`
    stays in the API, empty, beside the new `backup_store` and `backup_sha1` (`^(?i:my|webhosting)$`). Notices and
    e-mails of a Windows deployment name the previous certificate (`<store> \ <sha1>`) instead of a backup folder
    (`*_windows` texts, not deferred: an e-mail sending a Windows administrator to `/var/lib/alice-helper/backups`
    is wrong advice); the e-mail names the store only when it is `My` or `WebHosting` (the API's rule, final review
    Minor 3). After a successful deployment the location's `details.cert_sha1` is the deployed leaf's thumbprint
    (`leafThumbprint`: the SHA-1 of the stored chain's first certificate, only when its DER SHA-256 is the token),
    written with `cert_file_sha256`, so the next deployment's rollback info names the certificate Alice deployed (Task
    14, found by the e2e journey); when it cannot be derived the old thumbprint is removed, never kept beside the new
    token (final review Minor 2); a rolled-back deployment leaves it as it was.
18. **A cut scan does not block a deployment.** Amended (Task 8): per verdict: `win_foreign_app` is dropped only when
    the sites may be cut, a `cert_missing` only when the entries or certificates may be cut, Alice's own drops
    counted as cuts; `leaf_unreadable` stays.
19. **One unreadable certificate no longer fails the dump.** As written; `winhelper.ErrStore` marks "the store could
    not be opened" (fails the dump), every other certificate error drops that certificate.
20. **Engine unchanged.** As written: `internal/jobs/deployjobs` has no production change. Amended (Tasks 8, 10, 11):
    `providertest.CheckLocationTarget`'s empty-guard rollback runs on a fresh operation and checks the forbidden one
    stays unrestored (monotonic guard); `ListDeployableLocations` lists any non-file location of a deploying type by
    its kind (F5 and Kubernetes must gate deployment per location kind); the token recorded after a Windows deployment
    is the new leaf's DER SHA-256 (`newCertSHA256`, Task 11 fix), not the PEM's; the provider reads a stored locator
    whose port is a `json.Number` (Task 11 fix).
21. **UI grouping (§15 Q5).** As written. Amended (Task 13): the grouped picker is `DeployDialog`'s location mode (fed
    by the panel's bindings); "Select all bindings of this certificate" replaces the selection with that group's
    deployable bindings; the "No certificate" group has no such control; with several bindings picked, a certificate
    is offered only when it fits every one; a deployment is shown as Windows when it has `backup_store` or its path
    starts with `http.sys/`; `io_error` is a fifth Windows step class.
22. **Runner hygiene.** As written. Amended (Task 9): the last check is `TestRealRunnerIsClean` in
    `zz_runner_clean_windows_test.go` (go test runs files in name order; no TestMain, which the lock-holder child would
    also run) and also fails on any machine key file created after the test binary started (`Crypto\Keys` and
    `Crypto\RSA\MachineKeys`); the keep-everything record has no CTL (http.sys refuses a CTL the machine lacks, W0 F2).
23. **e2e forced rollback.** As written (`ctl stale-tls-on` / `ctl stale-tls-off`); Task 14's report adds its rulings.
24. **Test IDs.** As written: `WIN-15`..`WIN-28`, `WN-10`..`WN-13`, WN-1 and WN-4 amended.

## W2 facts measured on real runners

Runs of `.github/workflows/windows.yml` (windows-2022 = Windows Server 2022 Datacenter, windows-2025 = Windows Server
2025 Datacenter, Desktop Experience).

- **F9: CONFIRMED on windows-2022 and windows-2025** (runs
  <https://github.com/erenmeren/alice/actions/runs/39855366097> and
  <https://github.com/erenmeren/alice/actions/runs/39857454542>). `HttpUpdateServiceConfiguration` of an ipport or
  hostnameport base record keeps every extended parameter the record holds (HTTP/2 window and limits, performance,
  TLS restrictions, error headers); the helper's `exRepair` strategy (base update, read the Ex parameters back,
  rewrite only what changed) made no Ex write on either image. Precisions: both images report types 0-4 as set on
  ipport and hostnameport records (with their defaults when nobody set them); the images differ only beyond them:
  type 5 is `ERROR_NOT_FOUND` (1168) on 2022 and "not supported" on 2025, type 6 is 1168 on 2022 and undecodable on
  2025, types 7-9 are 1168 on both (a type not set is 1168, not the plan's `ERROR_FILE_NOT_FOUND`); the helper reads
  only 0-5. Type 2 (performance) is an aggregate of six entries with absolute pointers; on a
  hostnameport record its reported size includes the SNI host's padding, so the helper takes its extent from the
  entries (run 1's "reset" verdict was an artefact of those pointers). An Ex type the helper cannot decode is left
  out and never written, which is safe because F9 holds. `TestFidelityDeployKeepsEverySetting` adds: a deployment and
  its restore keep client-certificate negotiation, the revocation values, the TLS flags and a set HTTP/2 window, on
  the real machine and on the emulator (the fidelity tests passed in runs 4-6).
- **F10: CONFIRMED on both images** (runs <https://github.com/erenmeren/alice/actions/runs/39855366097> and
  <https://github.com/erenmeren/alice/actions/runs/39857454542>). `PFXImportCertStore(CRYPT_MACHINE_KEYSET |
  PKCS12_ALWAYS_CNG_KSP)` of the standard-library PFX into a memory store, then
  `CertAddCertificateContextToStore(CERT_STORE_ADD_NEW)` into `LocalMachine\My`, keeps the key link: the key is in
  the Microsoft Software Key Storage Provider, not exportable (`NCryptExportKey` refused with 0x80090029), and
  http.sys binds the certificate without 1312. The fallback routes were not needed.
- **W0 F5 between the import and the write** (run 4 onwards): an intermediate the helper imported is not served
  until the record is written (a deployment killed at `deploy.writing` still serves the leaf alone on both hosts);
  only a write changes the served chain, hence the binding record's `chain` (Ruling 10).

### Runner runs used (9 of 20)

| Run | Head | Result | What it found |
|---|---|---|---|
| 1 <https://github.com/erenmeren/alice/actions/runs/39853315055> | `0e144e16` | failed, both images | W1 dump fidelity regressions (an Ex read error dropped every binding: the dump now reads no Ex); update and import bind `Element not found` (1168: an unset Ex type); F9 looked like "reset" on 2025 (an artefact of the performance aggregate's pointers); F10's import lands in the software KSP, not exportable |
| 2 <https://github.com/erenmeren/alice/actions/runs/39855366097> | `47fa5060` | failed | F9 and F10 confirmed (above); 2025 hostnameport Ex type 2 did not decode (329 bytes: the aggregate's extent, fixed in `5c36ac9c`); 2022 `TestRealSetupScript` first `version` timed out (a W1 test; flake) |
| 3 <https://github.com/erenmeren/alice/actions/runs/39857454542> | `5c36ac9c` | failed | F9 on ipport and hostnameport on both images, F10 on both; only failure W1's `TestFidelityVersionAndRefusals` sending `iis-deploy` expecting W1's unknown (swapped to `iis-cleanup` in Task 9) |
| 4 <https://github.com/erenmeren/alice/actions/runs/39860675538> | `4654e471` | **green** on both images | Every Task 6 and Task 9 test passed (not skipped), `TestRealRestoreForbidden` and `TestRealRunnerIsClean` included |
| 5 <https://github.com/erenmeren/alice/actions/runs/39863868398> | `7c2b08d1` | 2022 green; 2025 failed | Only `TestRealSetupScript`'s first `version` after setup did not end (second occurrence): hardened in `95b3e817` (wait for sshd's banner, diagnostics, one retry at 60 s); every Task 9 fidelity test passed on both images |
| 6 <https://github.com/erenmeren/alice/actions/runs/39866197908> | `90f83ad8` | **green** on both images | The binding record chain (Task 3 fix rounds 3-4) on real Windows |
| 7 <https://github.com/erenmeren/alice/actions/runs/39879604187> | `fcf85df8` | **green** on both images | Every test of the branch after Tasks 11, 13 and 14 and the e-mail texts, on both images |
| 8 <https://github.com/erenmeren/alice/actions/runs/39888002949> (attempt 1) | `b5afa7ce` | 2025 green; 2022 failed | Only `TestRealSetupScript`: the W1 setup script (OpenSSH capability install) hung until `go test`'s 10 min timeout, a runner flake outside W2 code |
| 9 <https://github.com/erenmeren/alice/actions/runs/39888002949> (attempt 2) | `b5afa7ce` | **green** on both images | The final-review fixes; the branch head's code |

The `ci.yml` runs of the branch: 39853314997 at `0e144e16` (gitleaks flagged the redaction test's fake PEM in
`winproto_test.go`, fingerprinted in `.gitleaksignore` by the controller; `internal/notify`
`TestF62UntrustedCertificateAndThePin` failed once and passes locally, untouched by W2); 39860675128 at `4654e471`
(go, secrets, web, ssh-matrix, licensectl green; coverage and stack cancelled by the next push).

Final gates (Task 16):

- **Local `make ci`** at `fcf85df8` (`E2E_PROJECT=alice-e2e-w2 ALICE_E2E_PORT=9975`): exit 0. It ran lint, test,
  coverage (every floor met), perf, test-backup-cycle, test-ssh, build, release-symcheck, i18n-check, web-lint,
  web-coverage, vuln (no vulnerabilities), secrets-scan, fs-scan, e2e-hardening-check, e2e, image-check and image-scan
  (0 findings).
- **e2e**: 158 passed, 4 skipped, 0 failed (48.8 min) in that `make ci`; Task 14's own full run had the same totals
  (48.9 min). The Windows journey is `web/e2e/windows.spec.ts` ("add a Windows server, confirm its host key, see its
  http.sys bindings and IIS sites, deploy and roll back", EN and TR).
- **gitleaks over the whole range** `fc43d4db..HEAD` (the worktree's own scan sees no commits): two `generic-api-key`
  findings, both operation UUIDs in `cmd/alice-fakewindows/main_test.go` (`469a584f`); their fingerprints are in
  `.gitleaksignore` (`6acf54e1`, no key material), and the range is clean.
- **Real Windows**: run 7 green on windows-2022 and windows-2025.
- **Final review** of `fc43d4db..fcf85df8`: ready to merge, no Critical or Important finding; its minors are under
  [Final review fixes (W2)](#final-review-fixes-w2).
- Final CI on origin at `b5afa7ce`: `ci.yml` green (all jobs, stack included),
  <https://github.com/erenmeren/alice/actions/runs/39888002907>; `windows.yml` green on windows-2022 and
  windows-2025, <https://github.com/erenmeren/alice/actions/runs/39888002949> (attempt 2: attempt 1 was green on
  windows-2025 and timed out on windows-2022 inside W1's setup script, the OpenSSH capability install, a runner
  flake outside W2 code). 9 of the 20 budgeted runs used.

## Rulings made during execution (W2)

One line each: the ruling, then why (and the cost if wrong where it is not obvious).

### Controller (order and process)

- Commit trailer `Co-Authored-By: Claude Opus 5.5`: the commits are written by that model and only the owner's own
  instructions may override the session's attribution rule (cost: the coordinator rewrites unpushed trailers or
  accepts them).
- Order 1 → (2 → 3 → 4) ∥ 5 → 6 ∥ 7 → 8 → 9 → 10 ∥ 12 → 11 → 13 → 14 → 15 → 16, with Task 6 starting after Task 2's
  review (it needs only `WriteHost`; an early runner run measures F9/F10 sooner), Task 3 in parallel with Task 2's
  re-review, Task 9 in parallel with Tasks 7 and 8, Task 12 after Task 7, Task 15 in parallel with Task 14: disjoint
  files in each pair.
- `windows-w2` pushed at `0e144e16` for runner run 1, before Task 9: F9 and F10 measured with Task 6's own tests.
- The controller committed the `.gitleaksignore` fingerprint itself (as W1 `03f467c0`): a pushed commit cannot be
  rewritten.
- The server-side notification and e-mail texts of a Windows deployment got Windows wording in W2 (`2db347aa`), not
  W3: a Windows administrator sent to a Linux backup folder is wrong advice.
- `TestRealSetupScript` retries a timed-out first `version` once with 60 s and logs diagnostics: runs 2 and 5 hung on
  the first sign-in of the just-created account with sshd already answering (cost: one real one-off hang is masked
  once; the second timeout still fails).
- The gitleaks findings of the whole range (two operation UUIDs in the fake's stale-TLS test, `469a584f`) were
  fingerprinted by the controller (`6acf54e1`), as the earlier one: a pushed commit cannot be rewritten.
- The final review's minors 1, 2, 3, 6 and 7 were fixed in one wave after the local `make ci`; 4 and 5 were accepted
  (below).

### Task 1 (winproto)

- `ValidHost` and `Locator.Canonical()` as in Rulings 5 (strict, not normalising): the locator comes from Alice's
  stored, canonical W1 locator or from stdin, and must never address another record than its text names.
- `Canonical()` lives in `winproto` (convert.go's is unexported in package windows); equality pinned by a test.
- `ValidOpID` refuses the nil UUID; `ValidForbidden` is helperproto's rule; `WriteGrace < HelperBudget` is asserted.

### Task 2 (winhelper write core)

- A `write` command is elevated whatever its `elevated` field says (safety by construction).
- The four subcommands were registered only by Task 3 (a stub would answer something else than
  `UNKNOWN_SUBCOMMAND`).
- `OUTCOME_UNKNOWN` is exit 4, message "the call took too long after the first change".
- The journal's `Previous` is the record as read (raw store, "" for NULL), `Store` the effective one; a journal that
  `readJournal` would refuse is never written; the previous record's own canonical text must equal the journal's
  binding (http.sys spellings folded).
- `handBack` returns the binding record only after an operation that changed nothing (prepared, unchanged, fenced),
  as Linux's `releaseRecord`.
- `ErrStore` is the store-open sentinel the real host must wrap; any other certificate error drops that certificate.
- `NewPFXPassword` has no error result: `crypto/rand.Read` never fails since Go 1.24.

### Task 3 (iis-deploy, iis-restore, iis-status, iis-fence)

- No `WriteHost` method added: `built_chain_length` is `1 + len(Certificate(store, newSHA1).Chain)` read after both
  imports (0 when that read fails after the gate).
- A record that cannot go into a journal (Ex over bounds, invalid store, a host that does not canonicalise) is
  `IO_ERROR` before the gate; one naming no valid SHA-1 or a certificate its store lacks is `HASH_MISMATCH`.
- Journal and binding-record write failures while the record is untouched are `OUTCOME_UNKNOWN` (Task 2's gate rule);
  a failed `committed` write rolls back with `failed_step journal`; outcome journals are best effort.
- A failure of `import_chain` or `import_certificate` ends `restored` with that `failed_step` and the record untouched.
- The binding record is written right after the `prepared` journal and names the operation from then on; an
  `unchanged` journal keeps it.
- The import inventory is best effort (a failed `recordImport` only means W3 leaves that certificate alone); an import
  that answers another SHA-1 than the leaf's is recorded too.
- A binding whose latest operation's journal cannot be decoded is `RECOVERY_PENDING`; an I/O error reading it is
  `IO_ERROR` (retryable).
- Existing-copy race (residual): a third party adding the identical certificate between the check and `ImportPFX`
  under the lock is recorded `alice_imported:true` (W3 may add an "existed" result).
- Friendly name `Alice <first DNS SAN, else IP SAN, else CN> <notAfter yyyy-mm-dd> <op8>`, cleaned and bounded.
- `forbidden_final` and `cause_error` are new journal fields (Ruling 12); journals without them read false and "".
- The grown guard's journal write is load-bearing (`OUTCOME_UNKNOWN` when it fails), security-relevant.
- The binding record's `chain` lifecycle (Ruling 10); residual: a third party's same-hash write is not seen, but it
  can only make what is served fresher.

### Task 4 (wintest write half)

- A killed call answers exit 255 with nothing on stdout (an ssh client's "no exit status").
- The model decodes the PFX with go-pkcs12 (already a direct dependency; the helper does not link wintest) and accepts
  only a single leaf with a matching RSA or ECDSA key.
- The model's dump strips `Extended`, its live `Binding` read keeps it (the real helper's rule); its Ex reset on a
  base update is stricter than F9 (documented).
- An unwritten record builds its chain at its first handshake, then it is cached; a same-hash write rebuilds it.
- `FailImport` is a level, `FailUpdate` and `KillAt` one-shot; `CorruptReadBack` arms the next update.
- `Points`, `SetLockWait` and `SetDataDirUnsafe` added for the kill-point completeness check, quick `BUSY` tests and
  `JOURNAL_FAILED`. Review minor (accepted, latent): the abandoned-handler path has no slow-host fault yet.

### Task 5 (tlsverify)

- The archtest rule, `Options.Log`, the moved context check, skip and empty endpoint list, the re-check of a server
  probe's answer, the exported `ProbeOnce` and `ASCIILower`, nginx's own `TLSProber` struct delegating (nginx's tests
  unchanged), the fresh handshake and the `tls probe:` texts (Ruling 15).
- One line of nginx's `guard_test.go` changed: the file `TestOnlyProbeTLSConfigSkipsVerification` reads moved to
  `tlsverify.go` (keeping the text in a comment would have emptied the guard).

### Task 6 (cmd/alice-winhelper)

- Ex data has a portable form: the 32-byte `PARAM_EX` with each pointer replaced by an offset into Data, followed by
  the pointed-to bytes; the reserved pointers of TLS restrictions and session ticket keys have no documented size, so
  a record with one set is refused (`IO_ERROR` before any change) and dropped from the dump.
- A hostnameport record's key address is `0.0.0.0` with the port (the spike's route); an empty store or CTL string is
  written back NULL.
- `ERROR_INVALID_PARAMETER`, `ERROR_NOT_SUPPORTED` and (run 2) `ERROR_NOT_FOUND` from an Ex query mean "not set".
- `DataDirSafe` checks the data directory, `journal\` and `bindings\` (made with the inherited ACL, owner set to
  Administrators, then every owner re-checked); a missing data directory is `JOURNAL_FAILED` (the setup script makes
  it, the helper never does).
- `helper.lock` is one locked byte (`LockFileEx` exclusive, fail-immediately, retried every 200 ms up to `LockWait`).
- http.sys input arenas are `//go:noinline` heap objects (a stack pointer must never reach the kernel); state files
  are read with full sharing and the replace-rename retries on a sharing violation.
- A failed or repeated import deletes the key it persisted; `BuildPFX` names no key container, which makes that safe.

### Task 7 (provider: errors, gate, rollback, status, fence)

- The restore_failed shapes the provider accepts (failed_step `restore` with a class, or `bind`/`bind`/`file_changed`);
  anything else is uncertain, the safe side.
- Status `none` and `fenced` must carry no journal fields (else `ssh.protocol_error`); a fence answering fenced with
  `Active` is a protocol error, as on Nginx.
- `RECOVERY_PENDING` carries only `operation_id`; `windows.helper_refused` always carries `helper_code`;
  `binding_changed`, `busy` and `io_error` are retryable.

### Task 8 (provider: deploy, verify, capabilities)

- Capabilities `test_connection`, `discover_certificates`, `deploy_certificate`, `verify_deployment`; `RollbackTraits
  {Backup: BackupOnTarget, SelfRestores: true}`; `guardsRollback` true from protocol 1.
- A restored answer's class must be one of the mapped ones (`""` or `file_changed` is uncertain); restore_forbidden
  and restore_failed in a deploy answer must name a cause.
- The rollback failure's params come from the start record's backup, else the deploy answer's validated values; a
  malformed store or SHA-1 is left out.
- A helper probe's refusal or an undecodable answer is "not reached"; an SSH failure is the error (unverifiable).

### Task 9 (real Windows: fidelity of the write subcommands)

- The kill on the real helper is in process (the `alicetest` build's `Point` returns an error), exactly what a killed
  process leaves behind; journal write-through is checked by `TestRealStateFiles`.
- The test kill hook lives in `point_alicetest_windows.go` (build tag `alicetest`); the shipped helper's `Point` is
  the plain `return nil` of `point_windows.go`, and archtest proves the hook file is absent from the release binary
  (security-relevant: no kill switch ships).
- The model is given the record as the real helper reads it after netsh (the base reading is W1's twin's job).
- netsh options an image refuses are dropped from the end and logged; the positive controls still require
  client-certificate negotiation, the revocation mode bit, the freshness time, the URL timeout and the Ex window.
- The intermediate is not pre-imported for W2 deploys: the helper's `import_chain` must do it.
- `TestRealRestoreForbidden`'s last step asserts a re-sent restore of the same operation stays `restore_forbidden`,
  then a later deployment's restore succeeds (the plan's "a restore without lists then restores" contradicts the
  monotonic guard); netsh's own `show sslcert` text is an independent oracle after deploy and restore.
- The finding behind Ruling 10's chain (an interrupted same-certificate deployment that imported an intermediate left
  schannel's short chain served forever) was fixed in the helper, not pinned.

### Task 10 (inventory)

- `RollbackRequest.Backup` is filled for every non-file kind, never for a file (Nginx unaffected); only
  `win_sslbinding` gets the Windows-shaped rollback info.
- `errorParamKeys` gains `helper_version`, `required_version`, `store`, `previous_sha1`; `stepParamKeys` gains
  `chain_differs`, `deployed_chain`, `built_chain`.
- Review minor (accepted): every deployment's start transaction reads the location kind with one extra SELECT.

### Task 11 (engine and jobs on the emulator)

- The two production bugs it found were fixed in the packages that own them (`32a7bdab` locator port, `6b4b6d1e`
  token), minimal: without them no Windows deployment from the database works, or none after the first.
- The Windows token rule is keyed on `win_sslbinding` only (F5 and Kubernetes keep `sha256(PEM)` until their phases).
- `TestWindowsHashMismatchChangesNothing` re-points the binding through a session wrap right before the send:
  re-pointing it earlier fails the engine's pre-check first, and the helper's compare-and-swap would never be reached.
- The kill matrix turns `StaleTLS` off before the reboot (a website that never takes a change is another property);
  the incident for the guard rows is inserted by SQL.
- Review minor (accepted): after `restore_forbidden` the location's token stays the old DER hash while the binding
  names the new certificate, as on Nginx; the next discovery corrects it.
- Fix round (`2b37aa53`, `fcf85df8`, with Task 14's review minors): the stored locator deployed in a provider unit
  test; rolled-back crash rows read the journal restored; one recorded phase per fenced row; the thumbprint recorded
  after a deployment only when the chain's leaf is the token's certificate (`leafThumbprint`), a rollback leaving it
  as it was; the forbidden-rollback notice checked in the text of the deployment's kind.

### Task 12 (API)

- No Windows text has a placeholder (each reason comes from several helper answers); `helper_version` is shown when it
  is a short version-like token (an unparsable version is exactly what makes a helper outdated).
- `chain_differs` must be exactly `true`, the chain lengths 1-99.
- `target.invalid_config` stays unregistered (shared with linuxssh since W1; the API validates the config first).

### Task 13 (web)

- A deployment is recognised as Windows by its `backup_store` or the `http.sys/` path prefix, because the
  Deployment DTO has no location kind (review minor 4: exposing `location_kind` there is left for W3).
- The step texts are "Import the chain", "Import the certificate", "Bind", "Verify" (TR "Bağlamayı güncelleme" for
  bind); the chain note is a page-level notice (`win-chain-differs`).
- Windows wording for every deployment reason whose shared text names Nginx, files or the backup folder is a web-side
  override (`deployments.windowsErrors.<reason>`); `rollback_forbidden` keeps its shared title with a Windows cause
  and action; the ssh transport reasons kept in W2 get Windows actions.

### Notices and e-mails (`2db347aa`)

- The Windows switch is in `notifyDeployment` (the one path every deployment e-mail takes); 9 `*_windows` texts, Linux
  texts byte-identical; one param `previous_certificate` composed in Go (`<store> \ <sha1>`, else the SHA-1, else
  `SHA-256 <hex>`, else `-`); the Windows `rollback_forbidden` text never names the previous certificate (R48).

### Task 14 (e2e)

- The journey extends W1's test in `web/e2e/windows.spec.ts` (one test per language, EN and TR): upload, the grouped
  bindings and the grouped picker, a deployment committed and verified at level 3 ("Trusted"), then `ctl
  stale-tls-on`, a deployment whose verification fails and is rolled back, the page naming the previous certificate
  `My \ <SHA-1>`; `beforeEach` and `afterEach` run `ctl stale-tls-off`. The TR run starts from EN's rolled-back
  certificate (the fake's state carries over; tolerated). Timeout 8 min.
- `alice-fakewindows ctl stale-tls-on|off` (no arguments; `POST /stale-tls-on|off` on the loopback control API) calls
  `wintest.Model.StaleTLS`; `TestCtlStaleTLSKeepsTheListenerOnTheOldCertificate` runs a real `iis-deploy` over SSH.
- After a successful Windows deployment the location's `details.cert_sha1` is the deployed leaf's thumbprint (Ruling
  17; `21d052ec`): the journey found the rollback's "Previous certificate" naming the certificate before the last
  deployment, because only discovery wrote the details. The rollback itself was right (the helper restores from its
  journal). Other details (the friendly name) stay as discovered until the next scan (cost if wrong: none).
- No CA trust plumbing for the fake: the uploaded chain carries its root, which the trust policy takes as the
  `uploaded_root` anchor, so level 3 is reached (cost if wrong: a journey deploying a certificate without its root
  would read "Served").
- The deployjobs tests broken by the `*_windows` e-mail templates (`2db347aa`) were fixed in the tests.
- Review minor 4 (accepted, note): a run that dies mid-deployment can leave a `writing` journal on the fake, and its
  retry then fails loudly with `RECOVERY_PENDING`; a future `ctl reset` would clear it.

## Final review fixes (W2)

The final whole-branch review of `fc43d4db..fcf85df8` found no Critical or Important issue (Rulings 4, 7, 10 and 11
and Review Focus 1-6 hold end to end). Its minors:

1. **The write grace on the real helper**: the text of Ruling 7 now says that the real helper answers
   `OUTCOME_UNKNOWN` and exits at once when the budget ends, so `WriteGrace` bounds only in-process hosts; the
   emulator's abandoned call may write for up to 8 s (latent, no slow-host fault; deferred to W3 below).
2. **A thumbprint that cannot be derived after a deployment** is removed from the location's details instead of
   kept beside the new token (Ruling 17; `TestASuccessWithoutADerivableThumbprintDropsTheOldOne`).
3. **The e-mail's previous certificate** names the store under the API's rule `^(?i:my|webhosting)$`, not the
   record's looser one (`TestPreviousCertificateText`).
4. Accepted: `winhelper.Run`, `RunForced` and `reply` are used only by tests now (the real helper and wintest call
   `Execute` and `ExecuteForced`); they stay as documented test conveniences.
5. Accepted: the SHA-256 hex validator exists twice (`windows.isHexSHA256`, `winhelper.validSHA256`); a
   `winproto.ValidSHA256` can join them later.
6. **A damaged binding record** (`C:\ProgramData\Alice\helper\bindings\<hash>.json`) blocks its binding with the
   retryable `IO_ERROR` until the recovery escalates (fails closed); `docs/troubleshooting.md` `ALC-WIN-0007` now says
   what the operator does (check that no journal of that binding is `writing` or `restoring`, move the file aside,
   try again; the first deployment then writes even an already bound certificate).
7. **`parseRestoreInput` refuses anything but white space after the JSON value** (one trailing `}` or `]` was
   accepted, `dec.More()` being false before a closing bracket) (`TestRestoreInputRefusals`,
   `TestRestoreInputAcceptsSurroundingWhiteSpace`).

## Acceptance (design §13 W2)

- Manual deploy to an SNI and an IP binding, committed at level 3 (public-CA chain), 2 (private CA without root) and
  1 (skip): Tasks 8 (`TestDeployOutcomeTable`), 11 (`TestWindowsManualDeployment`, `TestWindowsDeploymentLevels`),
  14 (the e2e journey `web/e2e/windows.spec.ts`, EN and TR: committed, verified, level "Trusted" in the browser).
- A hash mismatch changes nothing; an unchanged certificate answers unchanged: Tasks 3
  (`TestDeployRefusalsChangeNothing`, `TestDeployUnchanged`), 11 (`TestWindowsHashMismatchChangesNothing`,
  `TestWindowsUnchanged`).
- A failed verification rolls back; a forbidden backup restores nothing and ends `rollback_failed` with
  `deployment.rollback_forbidden`; the helper's own refusal on a real runner: Tasks 3 (`TestRestoreForbiddenOnEveryPath`),
  8 (`TestWindowsLocationTargetContract`), 9 (`TestRealRestoreForbidden`, runs 4, 6 and 7 green on both images), 11
  (`TestWindowsFailedVerificationRollsBack`, `TestWindowsRollbackGuardRows`), 14 (the e2e journey's rollback after
  `ctl stale-tls-on`: rolled back, restore ok, the previous certificate named).
- The crash table passes on the emulator; the fidelity test passes for every write subcommand on real Windows: Tasks 4
  (`TestModelKillAtEveryPoint`), 3 (`TestRecoveryAfterAKillAtEveryPoint`), 11
  (`TestWindowsDeploymentSurvivesAKillAtEveryPoint`), 9 (`TestFidelity*` of the write subcommands, runs 4, 6 and 7).
- ACME and Key Vault automatic deployment reach a Windows location; the scoped-access trust check applies: Tasks 10,
  11 (`TestWindowsACMEAutomaticDeployment`, `TestWindowsKeyVaultAutomaticDeployment`,
  `TestWindowsCrossServiceNeedsTrust`).
- Final gates (Task 16): local `make ci` at `fcf85df8` exit 0 (every coverage floor met, no vulnerabilities, image
  scan 0); e2e 158 passed, 4 skipped, 0 failed; real-Windows run 7
  (<https://github.com/erenmeren/alice/actions/runs/39879604187>) green on both images; gitleaks over
  `fc43d4db..HEAD` clean after the fingerprints of `6acf54e1`; `make matrix-check MATRIXCHECK_FLAGS=-strict`,
  `make docs-check` and `make i18n-check` pass at the final commit (see
  [Runner runs used](#runner-runs-used-7-of-20)).

## Owner items (W2)

- **Confirm the security-relevant rulings**: `restore_forbidden` monotonic in the helper (Ruling 12); the guard checks
  the certificate's SPKI on Windows (Ruling 11); the PFX password of 192 bits (Ruling 9); `unchanged` only with the
  recorded chain (Ruling 10); an Ex parameter type the helper cannot decode left out and never written (Ruling 10,
  safe while F9 holds: a later Windows that resets Ex parameters on a base update would lose that one setting
  silently); the dual-wildcard probe (Ruling 15); key problems stay unsupported (Ruling 14).
- **Windows Server 2019, Server Core, a domain account**: the write path (`HttpUpdateServiceConfiguration`, F9 and
  F10) is measured on 2022 and 2025 only; the owner's manual matrix (W4) covers 2019 and Server Core.
- **Antivirus**: Defender real-time protection is off on the runners. A deployment writes the journal under
  `C:\ProgramData\Alice\helper` and machine keys under `C:\ProgramData\Microsoft\Crypto\Keys`; check a deployment with
  Defender (or the customer's EDR) on.
- **First connection to a freshly prepared server**: runs 2 and 5 saw the first sign-in of a just-created account hang
  past its timeout once (profile creation or Defender's first scan suspected); Alice's first **Test connection** may
  time out once. The diagnostics of the retry say which when it fires again.
- **A Windows recovery stuck on a missing helper** reads "interrupted" until the recovery escalates to needs attention
  (Task 10 ruling): a server set up wrong (cmd.exe answering, sshd without the forced command) shows that reason for a
  few recovery rounds.
- **Commit trailers**: the W2 commits carry `Co-Authored-By: Claude Opus 5.5` (controller ruling), not the plan's.
- **Not deployable yet, by design**: IDN host headers in their U-label form (Ruling 5), a binding whose only problem is
  its key (Ruling 14), CCS bindings (W5); a manual "roll back this deployment" action exists for no target.
- **`internal/notify` `TestF62UntrustedCertificateAndThePin`** failed once on CI (passes locally; untouched by W2).

## Deferred to W3

- A real kill between `ImportPFX` and `recordImport` leaves an imported certificate and key that `imports.json` does
  not list; only the prepared journal's `new_sha1` names it: W3's cleanup must also read journals.
- The binding record stores the input chain, not schannel's built chain: an intermediate a third party adds after
  Alice's commit makes a redeploy answer `unchanged` with `built_chain_length` longer than served (`win.chain_differs`
  shows it); W3's cleanup of Alice-imported intermediates must clear binding-record chains naming them.
- `ImportPFX` reports no "existed" result (the existing-copy race of Task 3); W3's cleanup could otherwise remove a
  certificate someone else added in that window.
- Tombstones (`iis-fence`) are not bounded; W3's cleanup can bound them.
- `location.drift_*` e-mails for Windows bindings still say "file"; `needsAttentionTemplate` picks the lost-connection
  text only for `ssh.*` causes, so a Windows deployment whose connection was lost gets the unconfirmed text.
- `location_kind` on the API's Deployment DTO, so the web page need not guess a Windows deployment from
  `backup_store` or the `http.sys/` prefix (Task 13 review minor 4).
- The dump does not show `alice_imported` (W3's cleanup does); intermediates Alice added stay in `CA` (design §6.7).
- R52 drift for Windows locations, `iis-cleanup`, the incident cleanup rule (Q7), as planned.
- When a slow-host fault is added to the emulator, the wintest handler must mark its host dead on `o.Abandoned`: an
  in-process abandoned call can write for up to `WriteGrace` (8 s) after `OUTCOME_UNKNOWN`, which a real helper
  cannot (Ruling 7, final review Minor 1).
