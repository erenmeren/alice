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

# W3 (R62)

Phase W3 (drift and cleanup) was built on branch `windows-w3` from the plan
`docs/superpowers/plans/2026-10-23-windows-w3-drift-and-cleanup.md` (13 tasks), on the owner's approval of W0-W4 with
the §15 defaults (2026-10-22). Spec: R62 in `docs/superpowers/specs/alice-v1/00-decisions.md`, `02-architecture.md`
("Windows servers"), `03-integrations.md` §13A.12-§13A.14, `04-security.md` §14.4 (WN-12 amended, WN-14..WN-17),
`06-quality.md` §24.7 (WIN-29..WIN-38), design §14 (F11, F12) and §18. **One migration, `00032`** (the plan said none;
amended by the coordinator, Ruling 1). None of the rulings below is a pricing decision; the security-relevant ones the
owner should confirm are listed under [Owner items (W3)](#owner-items-w3).

## The plan's rulings as built (W3)

The plan's 24 rulings stand as written, except where an entry says "Amended".

1. **Decision R62.** Amended (coordinator, Task 10 rework `f5fb07f7`): **one migration, `00032`**: a dedicated column
   `targets.certificate_cleanup boolean NOT NULL DEFAULT true` and `GRANT UPDATE (certificate_cleanup) ON targets TO
   alice_app` (that column only). Why: `alice_app` may not update `targets.config` (`00005`), so a switch kept in the
   config could only be set when a server is added. Refused alternative: `GRANT UPDATE (config) ON targets`, because
   the config holds the connection (host, port, account) and the application would gain write access to all of it.
   Down revokes the grant and drops the column (an off switch is lost on a downgrade, accepted). As written otherwise:
   drift uses the existing columns (`changed_outside_at`, `problem`, `key_problem`, `location_observations`), the
   import inventory and journals are server files, no new `alerts.kind` (the Q7 notice's dedupe is Ruling 9's);
   error codes `ALC-WIN-0013`, `ALC-WIN-0014`; test IDs `WIN-29`..`WIN-38`; STRIDE `WN-14`..`WN-17`.
2. **Protocol 1, helper 0.3.0, `CleanupMinVersion` 0.3.0.** As written. Amended (Task 6): Alice's own cut of an
   `iis-cleanup` call is `linuxssh.LongCommandTimeout` (60 s, above the helper's 50 s budget, as `iis-dump`: an equal
   cut would race the helper's `OUTCOME_UNKNOWN`); the W2 provider tests that probed "a subcommand without a budget"
   with `iis-cleanup` now probe `rdp-deploy`, as W1's fidelity test does.
3. **Command line and standard input; no operation id.** As written. Amended (Task 3): the input is decoded strictly
   (a member twice, a member name outside the exact list, encoding/json's case-insensitive match and trailing data are
   `BAD_CONTENT`; a bad ref or item, a reason `forced`, 0 or more than `MaxCleanupItems` items, more than
   `MaxForbidden` watch refs are `INVALID_ARGUMENT`); `--apply` reads the bindings, the listeners and the journals
   once per call under the lock, not again before each item.
4. **Two judges, both must agree.** As written.
5. **Alice imported (rule 1).** As written. Amended (Tasks 2, 3): (b) also needs the journal's own `alice_imported`
   true (after the existing-copy race a journal has `existed:false`, `alice_imported:false`); a journal with
   `existed:true` and `alice_imported:true` is invalid; in (a) and (b) the entry's SHA-256 must equal the store copy's
   DER SHA-256; a certificate that only a 0.3.0 journal names is **adopted** into `imports.json` by the plan when rule
   1 holds (else the fence's tombstone would erase the only evidence and the certificate could never be cleaned).
6. **In use (rule 2).** As written; F12 confirmed (below). Amended (Task 5): an RDP value that is not 20 bytes, a
   WinRM `certThumbprint` that is not 40 hex digits after removing spaces, or more than 1024 listener keys is an
   error, so that server's plan and apply refuse (`IO_ERROR`) and remove nothing until it is fixed.
7. **Live journals (rule 3, helper half).** As written. Amended (Task 3): an unreadable journal also **clears every
   `unbound_since` stamp** of that run (it counts as "in use"), so the wait restarts after it is pruned; the helper
   reads at most 4096 journals per run and an unread one counts as unreadable; files not named `<op>.json` (a `.tmp`,
   a README) are neither read nor pruned.
8. **Age (rule 4) and the rollback window (§15 Q6).** As written (`winproto.CleanupMinAge` and
   `inventory.CleanupRollbackWindow` 7 days); candidates are listed oldest stamp first.
9. **Incident rule (§15 Q7).** Amended (Task 7 fix rounds `1d9588e2`, `552763b4`, controller and coordinator
   rulings): **every final state** of an incident place on a Windows server with the `cleanup_certificates`
   capability (verified, unverified, failed, skipped; skipped ones when the incident starts) queues its **own**
   `windows.cleanup` with `incident_id` (dedupe `windows.cleanup:<target>:incident:<incident>:<location>`, queued in
   the transaction that settles the place); the job sends `windows.compromised_in_store` only when **no place of that
   incident on that server is still pending or deploying**, and at most once per incident and certificate (it looks
   for an outbox row of that template with the same `incident_id` and `thumbprint`, as `sshkeys.lastPreviewMail`
   does); "compromised" is `certificates.compromised_at` on the certificate itself (a certificate that only shares a
   compromised key is not watched); a compromised candidate is removed even when a location still names it (the
   helper's rule 2 still protects a bound one). Coordinator fix: the incident engine and the impact view now decide
   deployability with the deployment engine's own rule (`deployLocation.deployable()`, `deployableColumns`), not a
   Unix-path regex, so an IIS binding is an incident place at all (without it Q7 could never fire).
10. **Removal.** Amended (Task 3 fix `483950cf`): per certificate the CNG key, then the certificate, then the `chain`
    of every binding record naming its DER SHA-256 is cleared, **then** its `imports.json` entry is dropped, then event
    1003; the next plan heals an interrupted removal (for an entry whose certificate no store holds it clears the
    chains first, then drops the entry). F11 confirmed (below): the key is deleted through
    `CryptAcquireCertificatePrivateKey(ONLY_NCRYPT|SILENT)` and `NCryptDeleteKey`; the container-name route was not
    built. A key already gone removes the certificate alone; any other key error, or a key handle the context owns,
    leaves the certificate in place (never an orphan key). As written: intermediates are never removed.
11. **Journal and tombstone bounds.** As written. Amended (Task 3 fix): while any binding record cannot be listed, read
    or decoded nothing is pruned and the plan warns `binding_record_unreadable`; "a journal a binding record still
    needs" follows the latest operation through prepared, unchanged and fenced journals to their `prev_record`; an
    unread journal is never pruned.
12. **Bounds.** As written. Amended (Task 3 fix): once the budget has ended no new removal starts (`OUTCOME_UNKNOWN`);
    the step under way finishes its bookkeeping. A cleanup apply ending `OUTCOME_UNKNOWN` records no Alice audit row
    for what the helper may have removed (event 1003 on the server is the trace; owner item).
13. **The job.** Amended (coordinator, `f5fb07f7`): the switch is the column `targets.certificate_cleanup` (Ruling 1),
    shown and changed on the server's page and with `PATCH /targets/{id}` (`certificate_cleanup`, boolean) only for a
    server with the `cleanup_certificates` capability (`validation.pattern` otherwise, as `poll_interval_minutes` on a
    server), audited `target.updated`; it is not a field of the Windows config schema. Amended (Task 7): `windows.cleanup`
    has one attempt and raises no `job.dead` e-mail when exhausted (a server that is down would mail daily); the job
    refuses a server without the capability before dialling (`internal.unexpected`). As written otherwise: off, the
    job still plans and applies nothing; `windows.cleanup_schedule` hourly (never on the wall clock in the e2e build);
    each removal audited `windows.certificate_removed`.
14. **Drift: one Windows scan rule.** As written. Precision (Task 8): "bound" is R52's `boundLocationWhere` (an ACME
    or Key Vault binding); "had none before" means both stored problems empty (a binding that stays broken is marked
    once); the `location.changed_outside` audit row carries the cause under `problem` (the audit's secret-key check
    refuses a `key_problem` key). Assumption: an Alice deployment never leaves a binding with an unusable key, else the
    "changed outside Alice" mail would misattribute it (owner item).
15. **Drift cause, derived.** As written. Amended (Task 10 review): `autocertrebind` is true only on a drifted Windows
    binding with a known cause on a server running the task (the hint explains a drift).
16. **Windows drift e-mails.** As written; `windows_note=autocertrebind` rides on all seven texts.
17. **Lost connection for Windows.** As written.
18. **`location_kind` on the Deployment DTO.** As written.
19. **The dump shows `alice_imported`.** As written; reading the journals for it is now partial (one unreadable
    journal no longer drops the others).
20. **UI.** As written, except that the switch is a setting of the server's page (Ruling 13), not a provider config
    field.
21. **e2e.** As written; the switch is saved off and on through the server's page (Task 11).
22. **Runner hygiene.** As written: ports 45390 (F11), 45391 and 45392 (fidelity), 45398 (plain http of the fixture
    sites); `TestRealRunnerIsClean` checks 45330-45398, `alice-w3-` certificates and sites and
    `inetpub\alice-w3-fidelity`; the clock offset lives in `now_alicetest_windows.go` and archtest proves neither test
    hook file nor its environment variable ships.
23. **W2 items deferred to W3, settled.** As written.
24. **Test IDs.** As written: `WIN-29`..`WIN-38`, `WN-14`..`WN-17`, WN-12 amended.

## W3 facts measured on real runners

Runs of `.github/workflows/windows.yml` (windows-2022 = Windows Server 2022 Datacenter, windows-2025 = Windows Server
2025 Datacenter, Desktop Experience).

- **F11: CONFIRMED on windows-2022 and windows-2025** (run 1,
  <https://github.com/erenmeren/alice/actions/runs/39912110730>, head `efb5c13f`; `TestRealCleanupRemovesKeyAndCertificate`
  passed, not skipped). `CryptAcquireCertificatePrivateKey(CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG |
  CRYPT_ACQUIRE_SILENT_FLAG)` then `NCryptDeleteKey` removed the imported certificate's key file (exactly one machine
  key file gone, none created; `NCryptOpenKey` of its container then 0x80090016), and
  `CertDeleteCertificateFromStore` of a duplicated context removed the certificate; the other certificates kept their
  keys and the binding kept serving. The fallback route (the `CERT_KEY_PROV_INFO_PROP_ID` container through
  `NCryptOpenKey`) was not needed.
- **F12: CONFIRMED on both images** (the same run; `TestRealProtectedThumbprints` passed). The WinRM HTTPS listener's
  `WSMAN\Listener\*+HTTPS` value `certThumbprint` equals the hash of the http.sys record `0.0.0.0:5986`, and the
  helper's readings equal PowerShell's. `RDP-Tcp` `SSLCertificateSHA1Hash` is **absent on both images** (RDP uses its
  self-signed certificate), so the RDP route is proven only for "absent"; a set value is covered by unit tests and the
  emulator. The http.sys-only fallback for WinRM was not needed.
- `TestFidelityCleanup` (the emulator and the real helper side by side, the age through the `alicetest` clock offset)
  passed on both images in run 1.

### Runner runs used (3 of 10)

| Run | Head | Result | What it found |
|---|---|---|---|
| 1 <https://github.com/erenmeren/alice/actions/runs/39912110730> | `efb5c13f` | **green** on both images | F11 and F12 confirmed; `TestRealCleanupRemovesKeyAndCertificate`, `TestRealProtectedThumbprints` and `TestFidelityCleanup` passed (not skipped), `TestRealRunnerIsClean` included |
| 2 <https://github.com/erenmeren/alice/actions/runs/39926856807> | `f5fb07f7` | **green** on both images | Every test of the branch at that head after Tasks 7-10, the F11 and F12 tests included |
| 3 <https://github.com/erenmeren/alice/actions/runs/39941100782> | `f622cf6b` | **green** on both images | The final review's fixes, the listing refusal of `iis-cleanup` included: `TestRealCleanupRemovesKeyAndCertificate`, `TestRealProtectedThumbprints`, `TestFidelityCleanup` and `TestRealRunnerIsClean` passed, F11 and F12 confirmed again |

The `ci.yml` runs of the branch: 39912110868 at `efb5c13f` failed only in the web job (`enums.test.ts` counted the
cleanup plan's warnings as dump warnings: fixed in `37574e52`, plus the web's `cleanup_certificates` capability in
`c86aaadd`); 39926856788 at `f5fb07f7`: go, coverage, web, secrets, ssh-matrix and licensectl green (the web fix
`37574e52`/`c86aaadd` confirmed; the stack job green too); 39941100921 at `f622cf6b`: green (all jobs).

Final gates (Task 13):

- **Local `make ci`** at `f622cf6b` (`E2E_PROJECT=alice-e2e-w3 ALICE_E2E_PORT=9976`): exit 0 (lint, test, coverage with
  every floor met: `winjobs` 100.0 (floor 95), `windows` 99.2, `winhelper` 97.4, `winproto` 100.0, `wintest` 97.4; perf,
  backup cycle, ssh, build, release-symcheck, i18n, web lint and coverage, vuln, secrets and fs scans, e2e hardening,
  e2e, image check and scan).
- **e2e**: 158 passed, 4 skipped, 0 failed (52.4 min) in that `make ci`; Task 11's own full run had the same totals
  (53.1 min), and its fix round re-ran `web/e2e/windows.spec.ts` (2 of 2, EN and TR).
- **Windows build and vet** at `d84edb61` and again in `make ci`: amd64 and arm64 builds, `go vet` with and without
  `alicetest`.
- **gitleaks over the whole range** `e21e1ba3..d84edb61` (v8.30.1, the repository's rules): no leaks. The worktree's
  own git-mode scan sees no commits, so the range was exported with `git log -p` and scanned in `dir` mode; the
  remaining fix commits `2202e1c9..f622cf6b` were scanned by `ci.yml`'s secrets job (git mode, green in 39941100921).
  `.gitleaksignore` needed no new fingerprint.
- **Real Windows**: run 3 green on windows-2022 and windows-2025 at `f622cf6b`, the code head of the branch (the
  rulings commit after it changes no file `windows.yml` watches).
- **Final review** of `e21e1ba3..d84edb61`: "ready after fixes" (one Critical, two Important, minors); every finding
  fixed in `2202e1c9..f622cf6b` and re-reviewed (approve). See [Final review fixes (W3)](#final-review-fixes-w3).
- 3 of the 10 budgeted runner runs used.

## Rulings made during execution (W3)

One line each: the ruling, then why (and the cost if wrong where it is not obvious).

### Controller (order and process)

- Commit trailers name the model of the session that wrote the commit (`Claude Opus 5.5` for the controller, the
  subagent's own attribution, for example `Claude Sonnet 5.5` on `16b11acb`), not the plan's "Fable 5.1": W2's
  precedent, the session attribution rule yields only to the owner's instructions (cost: the coordinator normalises
  unpushed trailers).
- Task 4 also exposes `Model.RemoveCertificate` (it already existed; it now drops the key too): Task 9 must remove a
  bound certificate outside Alice.
- `winjobs.Inventory` holds the four cleanup methods plus `TargetRef`, `Credentials`, `HostKeyStore`,
  `RecordConnectionFailure`: Task 7's "five methods" was a miscount.
- Tasks 7 and 8 ran one after the other in the plan's intent but overlapped in time with disjoint commits (`commit
  --only`); they share `notify.go` and the common locales (cost: wall-clock only).
- Tasks 4, 6, 5 ran in that order with Task 5's runner wait; Task 2 started during Task 1's review, Task 4 during Task
  3's review, Tasks 9 and 10 in parallel, Task 12 in parallel with Task 11: disjoint files in each pair.
- No `-tags integration` or Docker run while main's `make ci` (alice-e2e-main) ran; integration evidence of earlier
  tasks was taken by the next implementer once the machine was free (cost: later failure discovery).
- Task 3's choices accepted, all on the safe side: journal-only certificates adopted, an unreadable journal clears
  the stamps, one watched verdict per store, partial journal reading capped at 4096 (cost: up to 7 more days of waiting
  after a transient unreadable journal).
- Task 3's review minors 1-3 fixed at once, not deferred (no removal after the budget, `binding_record_unreadable`,
  chains before the inventory entry): they make the real host's behaviour concrete before Tasks 4-5.
- `providers.CleanupPlan` carries `Warnings` (the brief omitted it), so the job records `journal_unreadable` and
  `binding_record_unreadable`.
- `windows-w3` pushed at `efb5c13f` for runner run 1 right after Task 5: F11 and F12 measured with Task 5's own tests
  before the code that depends on them was claimed done.
- The web's enum test excludes the cleanup plan's warnings by an explicit pinned list (no UI labels): they never reach
  a location or a server (ci.yml run 39912110868).
- The incident cleanup is queued for every final place state, the notice waits until no place of the incident on the
  server is open (Ruling 9): a second place still deploying would otherwise raise a false "still in store" alarm, and a
  last place ending failed must still report (cost: one extra cleanup job per failed place).
- The incident hook queues only for a server with `cleanup_certificates`, and `winjobs` checks it before opening a
  session: a W2 helper's job would otherwise fail `internal.unexpected`.
- A cleanup apply ending `OUTCOME_UNKNOWN` records no audit rows (Ruling 12): Alice cannot know which items the helper
  removed, the server's event 1003 is the trace and the next plan sees them absent; accepted gap, owner item.
- The `location.changed_outside` audit detail for a broken binding is named `problem` (Ruling 14): the audit's
  secret-key check refuses any detail key containing `key`.
- Ruling 14's scan rule assumes an Alice deployment never leaves an unusable key; not guarded in code because Alice
  never changes a key's ACL and verifies the binding after each write (cost: a misattributed "changed outside Alice" mail; owner item).
- Task 9 re-points a binding with `Host().UpdateBinding`, not `AddBinding`: `AddBinding` adds a second record that
  loses to the first, so nothing would be re-pointed.
- The observation's `autocertrebind` is true only on a drifted Windows binding with a known cause (Ruling 15), pinned
  by test: the hint explains a drift and has no meaning on a binding in sync.
- The ACME bindings panel keeps the file wording for a Windows binding: the ACME binding DTO has no location kind;
  carried to W4 (cost: a misleading "file" sentence on that page only).
- The final review's fixes ran as one wave of eight commits and one re-review, and the local `make ci` was restarted
  at the fixed head: a `make ci` of the reviewed head would not have tested the Critical fix.

### Coordinator

- The incident deployability is fixed in W3 by reusing the deployment engine's deployable-location rule (no second
  rule): Q7 cannot work otherwise (Ruling 9).
- The `windows.compromised_in_store` notice is deduped per incident and certificate through the outbox (no notifier
  dedupe exists, an `alerts.kind` needs a migration); the gaps are owner items.
- Only a certificate itself marked compromised is removed at once (Ruling 9): every certificate sharing the incident's
  key is marked compromised by the incident, so none escapes, and nothing else is removed without its age.
- The switch is a column of its own (migration `00032`), changed with `PATCH /targets/{id}`; this supersedes Task 10's
  create-only switch (`a3eeb628`, reverted in `f5fb07f7`) and the refused `GRANT UPDATE (config)` (Rulings 1, 13).
- Proceed through Tasks 7-13 without stopping; report only after Task 13: the plan settles every open question by a
  ruling, and the phase's evidence is complete only after Task 13's gates.

### Task 1 (winproto)

- `winproto.ValidSHA256` (lower-case 64 hex) added beside `ValidSHA1`, as W2's final review minor 5 anticipated.
- The package comment says protocol 1 spans W1-W3 and `1.0.0` is W4's: W3 adds a subcommand, not a protocol change,
  so a W2 Alice and a W3 helper still agree.

### Task 2 (winhelper core)

- `StateFile.Name` is relative to the listed directory; `RemoveState` takes the full state name (`journal/<op>.json`),
  as `ReadState` does: one form of name for reading and removing, so no caller joins paths.
- A stamp `unbound_since` is exactly RFC 3339 UTC with whole seconds (`stamp(t)`); anything else makes the inventory
  invalid. Recording an import again keeps its stamp (duplicates compared without it): one exact form compares and
  orders without parsing, and a repeated import must not restart the 7-day wait.
- After the existing-copy race (`ImportPFX` answers `existed`) the deployment commits, sets `alice_imported` false and
  records no inventory entry: the copy in the store is not Alice's, so cleanup must never take it.
- The dump marks `alice_imported` best effort: an unreadable `imports.json` marks none, journals are read only when an
  inventory match is missing: the dump is a read for discovery, which an unreadable file must not fail.

### Task 3 (iis-cleanup)

- A certificate read error before the gate is a refusal (`STORE_ERROR` or `IO_ERROR`); after it `OUTCOME_UNKNOWN`:
  before the gate nothing was written, after it Alice cannot know what was (Ruling 12).
- An `imports.json` that cannot be decoded refuses plan and apply (`IO_ERROR`): rewriting it would destroy the
  inventory.
- A `RemoveCertificate` that answers "not removed" (someone else removed it after the judgement) still runs the
  bookkeeping and answers `absent` without an event: the server ends in the state the removal wanted, and the event
  would claim a removal Alice did not make.
- The plan's watch looks in `My` and `WebHosting` and answers one verdict per store holding the certificate: those are
  the stores Alice deploys to, and a copy in each is a separate thing to report.

### Task 4 (wintest cleanup half)

- The model's clock is the system clock plus a skew (`SetNow`, `Advance`); state files carry model-clock times: the
  age rules can be shown without waiting days, and the files agree with the helper's own clock.
- `FailProtected` fails the whole `ProtectedThumbprints`, as the real helper errors on any unreadable value: the
  emulator must refuse where the real helper refuses (fidelity), never answer a partial list that would let a used
  certificate look unused. `FailAfterKey` fails the next removal once between the key and the certificate, to show the
  gate's `OUTCOME_UNKNOWN` between the two steps.

### Task 5 (cmd/alice-winhelper)

- `RemoveCertificate` refuses (error, certificate kept) when the key handle is owned by the certificate context or the
  delete fails, rather than falling back to the container route; it states that the key container belongs to this
  certificate alone (every Alice import makes a fresh container, `CERT_STORE_ADD_NEW` never replaces a third party's
  copy).
- `ListState` lists only `journal/` and `bindings/`, skips directories, reparse points and devices, at most 65536
  entries; `RemoveState` refuses a directory, reparse point or device and treats an absent file as removed: an
  elevated helper must never follow a link out of its data directory, and a second removal is not an error.
- Only the helper's `Now` moves with the test clock offset; store reads and lock deadlines keep the real clock: the
  test moves the age rules only, Windows itself sees the real time.
- The F11 and F12 verdict lines are logged last and only when the test did not fail (review fix `b6311da2`);
  `TestRealProtectedThumbprints` uses a private data directory: a failed test must not log a CONFIRMED verdict, and
  the test must not touch the runner's real helper state.

### Task 6 (providers, Windows cleanup)

- `CheckProvider` cannot see the session, so the "a `cleanup_certificates` session must be a `CertificateCleaner`"
  check lives in `providertest.CheckSession` and `CheckUnsupported` (type check only: a plan writes on the target).
- The cleanup value constants live in `providers` (equal to winproto's, pinned by test), because archtest forbids
  inventory from importing `providers/windows/...`.
- Only `OUTCOME_UNKNOWN` maps to `windows.cleanup_outcome_unknown`; a transport error after the send keeps its mapped
  reason; the next plan settles either way: only that code says the helper passed the gate, a transport error already
  has a reason the operator can act on, and both end the same way because the next plan reads the server as it is.
- Answer validation is strict (closed sets of stores, states, reasons and warnings); a future helper adding one needs
  Alice to learn it (protocol 1 contract).

### Task 7 (inventory and winjobs)

- The cleanup switch helper moved to `providers` and later to the column (Ruling 13): archtest forbids inventory from
  importing the Windows provider, and the column replaced the config field.
- `RecordCleanup` refuses an apply result whose SHA-256s do not match its items in order: a mismatched answer would
  record the removal of a different certificate.
- The cleanup is queued in the same transaction as the incident place update: a failed queue rolls the update back
  and the next tick retries.
- `ScheduleWindowsCleanup` takes Windows servers with status ok and the capability and no `windows.cleanup` job of any
  kind in the last 24 hours, at most 500 per run, `FOR UPDATE SKIP LOCKED`: one plan a day per server whatever queued
  it, no session to a server that cannot answer, a bounded run, and two schedulers never take the same server.

### Task 8 (drift rule, cause, e-mails)

- `driftCause` treats any key problem as `key_unusable`; the scan rule's `bindingBroken` uses only `cert_missing`,
  `key_missing` and `key_inaccessible` (Rulings 14, 15): no key problem is repairable by re-pointing, but only those
  three mean the binding cannot serve.
- An approve-mode drift with an unrepairable cause gets the detected text of its cause; `auto` mails it once after
  `DriftAutoNoticeAfter` (unchanged engine): the operator learns why the repair is not offered, and the engine's
  notice rule stays the one every provider shares.
- Turkish says "{{cert_path}} bağlaması" so no suffix touches the binding text.

### Task 9 (engine and jobs on the emulator)

- The renewal in the cleanup test uses a 90-day leaf renewed when due, so 6 days later the old certificate is not yet
  expired and `too_young` and `rollback_window` can be shown.
- `too_young` is shown as the helper's own verdict through a direct `ApplyCleanup` (the job never asks Alice about a
  candidate the helper is still waiting on).
- `cleanupNow` queues the job directly with a unique dedupe key (the helper-only clock step does not pass the
  schedule's 24-hour gap); the schedule is covered by winjobs' tests.

### Task 10 (API)

- `repair_available` is false for `cert_removed` and `key_unusable`; `ErrDriftNotRepairable` maps to `ALC-WIN-0013`
  (409), `windows.cleanup_outcome_unknown` to `ALC-WIN-0014` (502, retryable): re-pointing cannot fix those causes, a
  refused repair is a state conflict, and the next plan settles an unknown outcome.
- The target DTO shows `certificate_cleanup` only for a server with the capability; a non-boolean in the PATCH is 400:
  a switch a W2 helper cannot honour must not be offered, and the column holds only true or false.
- The `windows.compromised_in_store` text also names "a deployment to the server is still running with it" (Task 7
  review minor), and the `cert_removed` drift text covers a binding with no http.sys record (Task 8 review minor).

## Final review fixes (W3)

The final review of `e21e1ba3..d84edb61` (verdict "ready after fixes") and its fixes, re-reviewed together (approve):

- **Critical**: `iis-cleanup` trusted an incomplete http.sys listing (the helper reads at most `MaxBindings`+1 records
  per table, and an undecodable record became an empty binding), so a certificate bound in a missing record could look
  unused. It now refuses with `IO_ERROR`, before anything is written, on a record with no type or a table with more
  than `MaxBindings` records, for `--plan` and `--apply` (`2202e1c9`, `TestCleanupRefusals`); run 3 green.
- **Important**: the `windows.compromised_in_store` text no longer says Alice took the certificate out of the bindings
  (it is also sent after a failed or skipped place) (`d5babeaa`); run 2 and its `ci.yml` run filled in, every
  execution ruling gives its reason (`55812041`).
- **Minor**: the incident dedupe-key comment names the place (`e8b8befa`); an incident's notice tells only of
  certificates of that incident's key (`04b084e3`); the switch's help text names what Alice checks and when it does
  not wait (`d7741e0e`); owner notes for the shared key container, cleanup held in a licence lock and the duplicate
  notice (`329e5aa6`); a test field typo (`f622cf6b`).
- The deferred minors of the task reviews were triaged by the final review: none other must be fixed before merge.

## Acceptance (design §13 W3)

- A binding re-pointed outside Alice is `drifted`, `auto` repairs it, flapping backs off: Tasks 8
  (`TestBrokenBindingIsDriftedNotRepaired`), 9 (`TestWindowsDriftObservedIsReported`, `TestWindowsDriftAutoIsRepaired`,
  `TestWindowsDriftFlappingBacksOff`); a removed certificate or unusable key is reported and never repaired: Task 9
  (`TestWindowsDriftCertRemovedIsReportedNotRepaired`), Task 10 (`TestObservationDriftCause`).
- Cleanup removes only Alice-imported, unreferenced, aged certificates: Tasks 3 (`TestUnboundSinceRules`,
  `TestApplyRemovesAndRecords`), 7 (`TestJudgeCleanupRules`), 9 (`TestWindowsCleanupAfterRenewal`); a certificate bound
  by a foreign application, RDP, WinRM or a live journal is kept (table test on the emulator): Tasks 3
  (`TestCleanupKeepsEveryUsedCertificate`, `TestApplyJudgesAgainUnderTheLock`), 4, 9 (`TestWindowsCleanupKeepsRows`);
  one real-runner case: Task 5 (`TestFidelityCleanup`, `TestRealCleanupRemovesKeyAndCertificate`, run 1 green on both
  images).
- Q7: Tasks 7 (`TestIncidentQueuesWindowsCleanup`, `TestRecordCleanupAuditsAndNotifiesOnce`), 9
  (`TestWindowsIncidentRemovesTheCompromisedCertificate`).
- Final gates evidence: local `make ci` exit 0 at `f622cf6b` (e2e 158 passed, 4 skipped, 0 failed), every coverage
  floor met (`winjobs` 100.0), runner run 3 green on windows-2022 and windows-2025 at `f622cf6b`, `ci.yml` green at
  `f622cf6b`, no secret in the range.

## Owner items (W3)

- **Confirm the security-relevant rulings**: the two judges, both of which must agree before a removal (Ruling 4);
  the removal order key, certificate, chains, inventory entry (Ruling 10); the incident rule, removal at once with no
  age and no rollback window, and the notice when a compromised certificate stays (Ruling 9); the switch **on by
  default** for every Windows server, existing ones included (Rulings 1, 13); the dedicated column with its
  column-only grant instead of `UPDATE (config)` (Ruling 1).
- **Accepted gaps** (confirm or ask for a fix):
  - A cleanup apply that ends `OUTCOME_UNKNOWN` records no Alice audit row for a certificate the helper may have
    removed; the server's event 1003 is the trace and the next plan sees it absent.
  - `windows.compromised_in_store` dedupe: a notice with no recipients writes no outbox row, so a later job tries
    again; once outbox retention prunes the row, a repeat can send again.
  - An incident cancelled while places on the server are still open queues no later cleanup, so no store notice is
    sent (the daily cleanup still removes Alice's copy once it is eligible, but no longer at once).
  - A copy of Alice's certificate in another store that names the same key container (made by hand, for example a
    store-to-store copy) loses its key when Alice removes its own copy, if that copy is not bound (Ruling 10; bound
    copies are protected by rule 2).
  - Ruling 14 assumes an Alice deployment never leaves a binding with an unusable key; if a W2 verify or rollback gap
    ever did, the "changed outside Alice" e-mail would be misleading.
  - A removal deletes the key container the certificate names (Ruling 10). A **different** certificate that shares
    that container (for example one renewed with the same key and imported into it) loses its key when Alice removes
    the old one, even when that other certificate is the bound one (rule 2 keeps the bound certificate, not a container
    it shares with an unbound one, which then breaks the binding). Alice's own imports
    always create a fresh container, so this needs a third-party import or a deliberate key reuse on the server.
  - Two incident cleanup jobs of the same incident and server running at the same moment could both find no notice in
    the outbox and both queue one, so the store notice is sent twice (no lock on the outbox check; accepted).
- **Cleanup while the licence is locked** (owner decision): `jobs.WindowsCleanup` is `ClassChange`, so every cleanup
  run is held while the licence is locked, including the at-once removal of a compromised certificate after an
  incident (Q7). Keep it so (a locked licence changes nothing on servers), or class the incident's removal as allowed
  in lock (`ClassAlways` or `ClassContinuity`, as `incident.advance` is `ClassAlways`).
- **RDP with its own certificate**: F12's RDP half was measured only as "absent" on the runners; a server whose RDP
  listener uses a CA certificate should be checked in the W4 manual matrix (the certificate must be kept `rdp`).
- **Defender on**: the W4 manual matrix now includes a cleanup run with Defender (or the customer's EDR) on.
- **Commit trailers**: the W3 commits carry the writing model's trailer (controller ruling), not the plan's.
- **Downgrade**: migration `00032`'s Down drops the column, so a server whose switch was off is on again after an
  upgrade that follows a downgrade.

## Deferred to W4

- **W4**: `windows.yml` required for the Windows paths; the helper in the release bundle and `SHA256SUMS`; helper
  version `1.0.0`; the owner's manual matrix (2019, a domain account, Server Core, Defender on), now including a cleanup
  run with Defender on and an RDP listener with its own certificate.
- **W5-W7**: CCS (`win_ccs_file`), RDP deployment (`win_rdp`; W3 only reads the RDP listener's thumbprint to keep its
  certificate), WinRM transport.
- Carried from W2, not decided in W3: a third party's intermediate added after Alice's commit makes a redeploy answer
  `unchanged` with `win.chain_differs`; the emulator's slow-host fault and the abandoned-call marking it needs (Ruling
  23); deploying to a binding whose only problem is its key (W2 Ruling 14); IDN host headers in their U-label form (W2
  Ruling 5); a manual "roll back this deployment" action.
- Not built: removing intermediates Alice added to `CA` (design §6.7: never); counting or removing expired
  certificates Alice did not import beyond `win.expired_in_store`; a cleanup history page.
- Minors deferred during W3: the plan's heal step may clear a chain for a DER still present in another store (benign:
  the next deployment rewrites it); no test of the `maxImports` trim of adopted entries; `cleanup.go` (725 lines) not
  split; the provider's plan check does not reject duplicate candidates; `UpdateTarget` writes `certificate_cleanup`
  back on every edit (harmless); a skipped incident place queues a cleanup at incident start (one extra dial).

# W4 (R63)

Phase W4 (real-Windows CI and release) was built on branch `windows-w4` from the plan
`docs/superpowers/plans/2026-10-23-windows-w4-ci-and-release.md` (7 tasks), on the owner's approval of W0-W4 with the
§15 defaults (2026-10-22). Spec: R63 in `docs/superpowers/specs/alice-v1/00-decisions.md`, `04-security.md` §14.4
(WN-6 amended, WN-18) and §17.5, `06-quality.md` §24.7 (WIN-39..WIN-45), design §14 (F13, F14) and §19. No migration,
no new error code. None of the rulings below is a pricing decision; the ones the owner should confirm or act on are
listed under [Owner items (W4)](#owner-items-w4).

## The plan's rulings as built (W4)

The plan's 22 rulings stand as written, except where an entry says "Amended" or "Precision".

1. **Decision R63: no migration, no error code.** As written: test IDs `WIN-39`..`WIN-45`, STRIDE `WN-18` added and
   `WN-6` amended; the only product changes are the helper's version string (Ruling 2) and `location_kind` on the
   ACME binding (Ruling 17).
2. **Helper 1.0.0, protocol 1, minimums unchanged.** As written (`winproto.Version` `1.0.0`, `Protocol` and
   `MinProtocol` 1, `WriteMinVersion` 0.2.0, `CleanupMinVersion` 0.3.0; `TestReleasedHelperVersion`,
   `TestCleanupNeedsHelper030`).
3. **`internal/api/nul.go`: nothing to do in W4.** As written: plain checkout, `TestNoWindowsReservedFileNames` keeps
   reserved names out of the tree.
4. **One required check, `windows-required`.** As written. Precision (Task 2): the gate checks that `changes`
   succeeded before it reads `windows` (GitHub passes an empty output when `changes` failed), so `cancelled true
   skipped skipped` fails; unknown job results are refused (exit 2).
5. **Change detection without trigger filters.** Amended (controller ruling 3, Task 3 review I-1): a push to a branch
   other than the default branch diffs `git merge-base origin/<default> HEAD`..`HEAD` (the whole branch, on every
   push); a push to the default branch keeps `before`, and an empty, all-zeros or unknown `before` there answers
   `true` directly (the merge base on the default branch is HEAD itself, an empty diff). Precision (controller ruling
   4): the names come from `git diff --no-renames --name-only -z` and `windows-ci.sh changed` reads NUL-delimited
   names only. Precision (controller ruling 1): `push` has `branches: ['**']`, so a tag push does not start the
   workflow directly. As written otherwise: no `paths:`, no third-party filter action, every `${{ }}` value through
   `env:`.
6. **The watched list is complete by test.** As written (`TestWindowsWorkflowWatchesEveryDependency`); the list has
   the seven fixed entries and the package entries the test demanded, among them `internal/providers/providertest`,
   `apacheconf`, `haproxyconf`, `nginx/nginxconf`, `internal/secrets` and `internal/testutil/pki`.
7. **Every real test is required by name.** As written. Precision (controller ruling 6, Task 3): nine real tests that
   existed but were not in `$required` were added so the exact-set test holds; run 1 showed all pass on both images.
8. **Concurrency.** Amended (controller rulings 2 and 3): `cancel-in-progress` is true only for a `push` or
   `pull_request` that is neither a tag ref (a called workflow sees the caller's event `push`, and a release call is
   never cancelled) nor the default branch (a cancelled default-branch run would leave its change untested). Amended
   (final review I-1): a push to the default branch has a group of its own per commit, `windows-main-<sha>`, because
   GitHub keeps one pending run per group and cancels it when a newer one queues, whatever `cancel-in-progress` says.
   As written otherwise: the literal `windows-` prefix and the `nightly` group.
9. **Nightly stays in `windows.yml`.** As written (cron `41 2 * * *`, both legs; the 60-day pause is in
   `docs/dev/windows-ci.md`).
10. **Cross-host reproducibility (F13) and one set of build flags.** As written; F13 confirmed (below), so the
    fallback warning was not built: a difference fails the leg. Precision (controller ruling 7, Task 3 review M-4):
    `TestWindowsHelperBuildFlagsAgree` also checks `deploy/Dockerfile`'s Windows helper build, since the image embeds
    those checksums.
11. **Release package layout.** As written (Task 4): `helper/` carries both `.exe` files and `alice-winhelper.sha256`;
    `make release` needs `winhelper`; the stage checks both checksum files and names the make target in its refusal.
12. **`release.yml` waits for real Windows.** As written: job `windows` (`uses: ./.github/workflows/windows.yml`,
    `with: { all: true }`, `permissions: contents: read`), `stage.needs: [gates, zap-full, fuzz, windows]`
    (`TestReleaseWorkflowWaitsForWindows`); no Windows gate in `make release-gates`.
13. **No Authenticode (§15 Q2).** As written: the gap is in the host guide ("Code signing"), the security overview,
    `SECURITY-REPORT.md` KI-42 and WN-18; owner decision below.
14. **The setup script's behaviour is unchanged.** As written; Task 6 made the script's header comment name "the
    helper folder of the Alice package" as its messages do (no behaviour change).
15. **Repository settings are the owner's.** As written: `docs/dev/windows-ci.md` holds the check names, the `gh api`
    ruleset command and the UI steps; release-checklist row 1.47; nothing was run against the repository settings.
16. **Pull requests run twice.** As written.
17. **ACME bindings panel.** As written (Task 5): `inventory.ACMEBinding.LocationKind`, `acmeBindingDTO.LocationKind`
    (`location_kind`), the panel passes `windows` for a `win_sslbinding` binding.
18. **No new real fixture.** As written; ports 45321-45329 and `alice-w4-` stay unused.
19. **The owner's manual matrix is a release-checklist section.** As written: section "8. Windows servers before
    release", rows 8.1-8.8, row 1.48, `WIN-45` with status `owner`.
20. **Every item marked for W4 in W1-W3, settled.** As written; the declined W3 minors and the W2 items carried again
    are under [Deferred to W5+](#deferred-to-w5).
21. **ARM64 is built but not run on real Windows.** As written: built, checksummed and byte-compared on every run;
    row 8.8.
22. **Docs.** As written (Task 6).

## W4 facts measured on real runners

Runs of `.github/workflows/windows.yml` (windows-2022 = Windows Server 2022 Datacenter, windows-2025 = Windows Server
2025 Datacenter, Desktop Experience).

- **F13: CONFIRMED on windows-2022 and windows-2025** (run 1,
  <https://github.com/erenmeren/alice/actions/runs/39956839820>, head `96ace632`; again in run 2). The helper built on
  each Windows leg with the flags of `make winhelper` equals the `linux-build` job's `make winhelper` byte for byte:
  amd64 `fd09f74e720dcb1958898091fd7f02a08c2d89232b5ea3e15fd56515dc2d8e5b`, arm64
  `dba2d5b3962324d94c621e34f480cf5c7086701693751693145fd48688491b38`, identical on Linux, windows-2022 and windows-2025
  and equal to a local `make winhelper` with go1.27.3. The fallback (a warning) was not needed.
- **F14: the run path CONFIRMED (W4), the skipped path CONFIRMED after the push of `main` ([F14 skipped path (W4 coordinator)](#f14-skipped-path-w4-coordinator)).** Run 1: `windows-required` ran with `if: always()` after
  green legs and passed, under exactly the context name `windows-required`. The skipped path (`changes` answers
  `false`, both legs `skipped`, `windows-required` success) cannot be observed on `windows-w4`: with Ruling 5 as
  amended a branch push diffs against `origin/main`, which is `e21e1ba3` (W3 not yet pushed), so `changes` always
  answered `true`. The plan's run 2 (a rulings-only push expecting skipped legs) was dropped. It is a coordinator check
  after `main` is pushed (controller ruling 5, [Owner items (W4)](#owner-items-w4)).

### Runner runs used (4 of 6)

| Run | Head | Result | What it found |
|---|---|---|---|
| 1 <https://github.com/erenmeren/alice/actions/runs/39956839820> | `96ace632` | **green**: `changes` (windows=true, a watched path changed since `e21e1ba3`), `linux-build`, `helper (windows-2022)`, `helper (windows-2025)`, `windows-required` | F13 confirmed on both images (the hashes above); F14's run path; the nine newly required real tests passed |
| 2 <https://github.com/erenmeren/alice/actions/runs/39958574455> | `b7beebc6` | **green** (all five jobs) | Tasks 4-5 (the setup script texts under a watched path); F13 confirmed again with the same two hashes |
| 3 <https://github.com/erenmeren/alice/actions/runs/39963473648> | `53ca1185` | **green** (all five jobs) | The final review's fixes (the per-commit default-branch group, `$WINDOWS` passed as is, the `helper` checkout without a token): the code head of the branch; F13 confirmed again with the same two hashes on both images |
| 4 <https://github.com/erenmeren/alice/actions/runs/40071646690> | `a0931a01` | **green** (all five jobs) | The docs tip: a rulings-only change, but a branch push diffs against `origin/main` (`e21e1ba3`), so the legs ran again; F13 confirmed again. It could not show F14's skipped path; see [F14 skipped path (W4 coordinator)](#f14-skipped-path-w4-coordinator) |

The `ci.yml` runs of the branch: 39956839548 at `96ace632` (superseded by the next push: go, coverage and stack
cancelled; web, secrets, ssh-matrix and both licensectl legs green); 39958574391 at `b7beebc6` (coverage failed on
`TestListACMEBindingsCarriesTheLocationKind`, the kind-shape violation fixed in `86ae97ef`; stack cancelled by the
next push; the other jobs green); 39963473554 at `53ca1185`: **green**, all jobs (go, coverage with the integration
tests, web, secrets, ssh-matrix, both licensectl legs, stack).

## Rulings made during execution (W4)

One line each: the ruling, then why (and the cost if wrong where it is not obvious).

### Controller (order and process)

- `windows.yml`'s `push:` has `branches: ['**']` (no paths, no tags): a tag push must not start a second direct run
  in the concurrency group of `release.yml`'s call, which could cancel the release's Windows job and skip the stage
  (cost if wrong: a tag no longer runs `windows.yml` directly; `release.yml` calls it with `all: true`).
- `cancel-in-progress` also requires `!startsWith(github.ref, 'refs/tags/')`: a called workflow sees the caller's
  event `push`, and Ruling 8 says a release call is never cancelled.
- Plan Ruling 5 amended (Task 3 review I-1): a push to a branch other than the default branch diffs the whole branch
  from the merge base, a push to the default branch keeps `before` and is never cancelled (and, after the final
  review's I-1, never displaced while pending: its concurrency group is per commit), and on the default branch
  an unusable `before` answers true: with `before`, a Windows push superseded (cancelled) by a docs-only push left the
  head green without testing the Windows change (cost if wrong: every push of a branch carrying any Windows change
  runs both legs, more runner minutes).
- `deploy/dev/windows-ci.sh changed` reads NUL-delimited names only, and callers use `git diff --no-renames
  --name-only -z` (Task 2 review): git quotes unusual names in plain output, which then match nothing, and a rename
  otherwise lists only the new path; the `gate` checks a failed `changes` before it reads `windows`, because GitHub
  passes an empty output then (cost if wrong: a hand run needs `printf '\0'`).
- F14's skipped path is a coordinator verification after `main` is pushed and the plan's run 2 (a rulings-only push)
  was dropped: on `windows-w4` the merge base with `origin/main` (`e21e1ba3`) always includes Windows changes (cost if
  wrong: `windows-required` would fail every non-Windows change until the F14 fallback of the plan's table, legs that
  always run and exit early, is applied).
- Nine real tests that existed but were not in `$required` were added (`TestRealAppcmdSites`,
  `TestRealAppcmdStateByEnvironment`, `TestRealCertificateFacts`, `TestRealExpiredInStore`, `TestRealForeignBinding`,
  `TestRealIISFacts`, `TestRealStateFilesLockHolder`, `TestRealStoresListTheMachineStores`,
  `TestRealWinFactsWithUnreadableFactFiles`): Ruling 7's exact-set test requires them; run 1 showed all pass on both
  images.
- `TestWindowsHelperBuildFlagsAgree` also checks `deploy/Dockerfile`'s Windows helper build (Task 3 review M-4),
  beyond the three places Ruling 10 names: the image embeds the checksums of that build.
- Task 2's commit trailer was corrected by amending the unpushed commit (content unchanged): the owner's instruction
  names the trailer `Claude Fable 5.1` for this phase (this differs from W3's controller ruling on trailers).
- Task 5 ran while Task 4's review ran (disjoint files); runner run 2 was taken at Task 5's head so one run covered
  Tasks 4 and 5.
- No Docker run while another `make ci` held the machine: `make shellcheck`, Task 5's `-tags integration` ACME test,
  `make release-test`, the e2e run and `make ci` were left to Task 7 (cost: later failure discovery).

### Task 1 (winproto)

- No execution ruling.

### Task 2 (watched list and decision script)

- The gate checks `changes` = success first (any other result fails), then decides on `windows`: Ruling 4(b) as the
  controller reads it, and it covers `cancelled true skipped skipped` → fail.
- An entry is refused (exit 2) for more forms than the brief lists (a trailing `/`, a `.` or empty path element, and
  `*`, `?` or `[` anywhere except the final `/**` or `/*`): all are "an entry of another form" under Ruling 6, and
  refusing them keeps the matcher simple and literal.
- Surrounding white space and a trailing CR on a list line or an input name are trimmed, white space inside an entry
  is refused: tolerates editor and CRLF artefacts without accepting odd forms.
- Blank input names are skipped: `git diff` output with a trailing separator must behave.
- The dependency test maps an external test package's import path (`winproto_test`) to the directory of the package
  it tests: such a path names no directory of its own.
- A local wrapper `windowsTestDeps` is used instead of extending `goListDepsFor`: that function has no `-test`
  support, and changing it would touch other guards.
- The implementer's commit carried the session's trailer; superseded by the controller's trailer ruling above.
- (Round 1) A name containing a newline under `dir/*` matches when it has no `/` after `dir/`: only `/` separates
  directories in git paths.
- (Round 1) A last name without a trailing NUL is still read: robust, and `-z` output always ends in a NUL anyway.
- (Round 1) Unknown job results are validated (exit 2) before the `changes` decision; only the `windows` check moved
  after it: GitHub never sends an empty result, only an empty output.

### Task 3 (workflow)

- The nine missing `TestReal*` names were added to `$required` despite the "keep `$required` unchanged" carry: Ruling
  7 and the brief's own test require exact set equality (`TestRealStateFilesLockHolder` returns early without its
  lock-dir variable, so it prints `--- PASS` in a plain run; run 1 confirmed all nine).
- `changes` writes the `git diff -z` output to `$RUNNER_TEMP/changed-names` and redirects that file into
  `windows-ci.sh changed` instead of a pipe: a failed `git diff` must answer true and never feed the matcher a partial
  list, and under `pipefail` a pipe would make the two exit codes ambiguous.
- `GOAMD64: v1` and `GOARM64: v8.0` are both set in the one build step's `env:`: Go reads only `GO$GOARCH`, so each
  applies to its own architecture and the bytes stay those of `make winhelper`.
- `${ALL:-false}` guards the `inputs.all` value, empty on events other than a call; `${WINDOWS:-false}` in the gate
  step (superseded by the final review's m-1: the gate passes `$WINDOWS` as is).
- `linux-build` validates each SHA-256 as 64 hex digits before it outputs it, and the compare step fails on an empty
  or malformed Linux value: an error, never a silent pass.
- `TestWindowsWorkflowGate` reads the cron through a YAML re-marshal of `on.schedule` with a substring check: good
  enough for one cron line.

### Task 4 (release package and release.yml)

- `helperSets` carries the make target (`make helper`, `make winhelper`) named in the refusal: deriving it from the
  file name would be implicit.
- The per-set checks live in a new `helperSetEntries`, called by `helperEntries` for each set: the Linux logic stays
  unchanged, only parameterised.
- Only the setup script's two thrown messages changed (Ruling 14 names only them); the header comment was aligned by
  Task 6.
- `TestStageRefusesAMissingInput` checks refusal texts through a `refusalNames` table (rows without an entry keep the
  plain error check) and also pins the existing Linux row's texts.

### Task 5 (ACME bindings panel)

- The ACME binding web type lives in `web/src/api/acme.ts` (not `types.ts` as the brief said), so the field was added
  there, with `LocationKind` imported from `types.ts`.
- `npm ci` was run in `web/` (the worktree had no `node_modules`; ignored by git).
- The integration test first changed an existing location's kind with an `UPDATE`; the review found it violates the
  kind-shape check, and the fix (`86ae97ef`) builds a Windows location that satisfies it (passed in `ci.yml`
  39963473554's coverage job and in the local `make ci` at `53ca1185`).

### Task 6 (docs)

- `docs/dev/windows-ci.md` describes the workflow as built (`.github/workflows/windows.yml`), not the plan's Ruling 5
  table: the amended base, the default-branch rule and the tag rule changed what runs when.
- Run 2's result was taken from the controller's ledger (`progress.md`), which records it green; the `ci.yml` run at
  `b7beebc6` stays pending.
- The operator guide's update step copies the new `alice-helper.exe` over `C:\Program Files\Alice\alice-helper.exe`
  by hand instead of re-running the setup script: the script of the Alice version still installed embeds the old
  helper's checksum and would refuse the new helper before Alice is updated (see Owner items).
- Release-checklist section 8 is placed after section 7 with the vendor sign-off line moved to the end of the file,
  so the sign-off stays the last line.
- The admin guide gains "Where the helper comes from", "Helper versions" and "What is tested on real Windows" as
  bullets of its "Windows servers" list, matching that section's form.
- The `go test ./internal/providers/windows/ -run Docs` step of the brief matches no test (the guide's test is
  `TestPreparationGuideQuotesTheMatchBlock`); the whole package was run instead.

## Final review fixes (W4)

The final review of `2ec69c8c..4e786c29` (verdict "ready after fixes") and its fixes:

- **Important I-1**: GitHub keeps one pending run per concurrency group and cancels it when a newer one queues,
  whatever `cancel-in-progress` says, so a queued default-branch push could be displaced and the next push, diffing
  from it, left its Windows change untested. A default-branch push now has a group per commit (`windows-main-<sha>`;
  schedule keeps `nightly`, everything else its ref), `TestWindowsWorkflowGate` requires `github.sha` in the group
  (`1437a3bb`); `docs/dev/windows-ci.md` (including the false "a push cancels a manual run" on the default branch),
  design §19 and Ruling 8 above say so (`022a0ee9`, this commit).
- **Important I-2**: the guides, `SECURITY-REPORT.md`, `CHANGELOG.md`, release-checklist row 1.46, WN-18, design F13
  and §19 no longer say every real test runs the shipped helper: the legs build the shipped bytes and compare them with
  the Linux release build, `TestRealSetupScript` installs them and calls the helper over SSH, the other real tests and
  the fidelity tests run the same source built by the test (`022a0ee9`; the docscheck pin of row 1.46 follows the
  corrected text, `9a5f9322`). No test change.
- **Important I-3**: the operator guide's helper update starts with checking the package's signature
  (`install-guide.md` section 3) and says its two checks are the only ones on that path; WN-18's and KI-42's residuals
  name that hand copy, which bypasses the setup script's embedded-hash check; the admin guide's "Helper versions"
  links the operator guide's Updates (`022a0ee9`).
- **Minor**: m-1 the gate passes `$WINDOWS` as is, m-2 the `helper` job's checkout has `persist-credentials: false`
  and is in the archtest loop (`1437a3bb`); m-5 ARM64 and AD FS are checked "when available; otherwise the release
  notes say so" in the security overview, admin guide and host guide, m-6 KI-42's mitigation names the ruleset of row
  1.47 (`022a0ee9`); the OpenAPI `location_kind` of the ACME binding names R63 (`aa190a56`).
- **Declined** m-3 (the stage does not compare its helper hashes with the Windows legs' Linux build): F13 proved the
  builds byte-identical across hosts with the `go.mod` Go, `release.yml`'s stage uses setup-go from `go.mod` as
  `linux-build` does, and release-checklist row 3.4 (`make reproducible-check`) compares the CI stage with the release
  machine (cost if wrong: a toolchain drift between jobs of one release run goes unnoticed until reproducible-check).
- **Declined** m-4 (`helperSetEntries` accepts extra or duplicate lines) for W4: pre-existing logic shared with the
  Linux set, and a listed binary still must match; carried to [Deferred to W5+](#deferred-to-w5).
- **Declined**: `buildHelper` taking the shipped bytes from `ALICE_WIN_HELPER_DIR` for the real tests: no test change
  in W4; the docs now say precisely which test runs the shipped bytes.

## Acceptance (design §13 W4)

- The jobs are required for changes under the Windows paths: the one check `windows-required` passes only on green
  legs for a Windows change or on no Windows change (Tasks 2-3: `TestWindowsChangedScript`, `TestWindowsGateDecision`,
  `TestWindowsWorkflowGate`; runs 1 and 2 green); the watched list covers every package the Windows tests build and
  every real test is required (`TestWindowsWorkflowWatchesEveryDependency`, `TestWindowsWorkflowRequiresEveryRealTest`);
  the repository setting that makes it required is the owner's (row 1.47, `docs/dev/windows-ci.md`).
- The helper in the release artifacts and `SHA256SUMS`: Task 4 (`TestStageLayout`, `TestStageRefusesAMissingInput`,
  `TestStageListsTheWindowsHelpersInSHA256SUMS`, `TestReleaseWorkflowWaitsForWindows`); the legs build the shipped
  bytes and compare them with the Linux release build: Task 3 (`TestWindowsHelperBuildFlagsAgree`, the legs' "Compare
  with the Linux build", F13), and `TestRealSetupScript` installs those bytes and calls the helper over SSH (the other
  real tests and the fidelity tests run the same source built by the test).
- Helper 1.0.0: Task 1 (`TestReleasedHelperVersion`, `TestCleanupNeedsHelper030`).
- The ACME bindings panel: Task 5 (`TestACMEBindingDTOHasLocationKind`, `TestListACMEBindingsCarriesTheLocationKind`,
  the web test "speaks of a Windows binding as a binding, and keeps the file wording for a certificate file (R63)").
- Documentation and `make matrix-check`: Task 6 (`make matrix-check MATRIXCHECK_FLAGS=-strict`: 288 IDs, 278 by tests,
  7 partial, 0 pending, 1 owner, 2 deferred, 0 gaps).
- The owner's manual matrix is listed as an owner step: release-checklist section 8 (rows 8.1-8.8), row 1.48,
  `WIN-45` status `owner`.
- Final gates (Task 7), at the code head `53ca1185`:
  - **Local `make ci`** (`E2E_PROJECT=alice-e2e-w4 ALICE_E2E_PORT=9977`): exit 0 (lint, test, coverage with every
    floor met and none lowered: `winjobs` 100.0 (floor 95), `winhelper` 97.4 (95), `winproto` 100.0 (100), `wintest`
    97.4 (90); perf, backup cycle, ssh, build, release-symcheck, i18n, web lint and coverage (164 files, 2622 tests),
    vuln, secrets and fs scans, e2e hardening, e2e, image check (117 checks ok) and scan).
  - **e2e**: 158 passed, 4 skipped, 0 failed (49.8 min) in that `make ci`.
  - **ShellCheck**: `make shellcheck` green (the new `deploy/dev/windows-ci.sh` included); the bash `run:` scripts of
    `windows.yml` extracted and checked with the same pinned ShellCheck image: clean. `actionlint` and `pincheck` clean.
  - **Windows build and vet**: amd64 and arm64 builds, `go vet` with and without `alicetest`, at `4e786c29` and in
    `make ci`.
  - **Test release**: `make release-test VERSION=1.0.0-rc.90` exit 0; the package holds
    `alice/helper/alice-winhelper-windows-amd64.exe`, `alice/helper/alice-winhelper-windows-arm64.exe` and
    `alice/helper/alice-winhelper.sha256`, its `SHA256SUMS` lists all three, and the two `.exe` hashes equal F13's
    (`fd09f74e…`, `dba2d5b3…`), the bytes the runners compared; the rc.90 outputs and images were removed afterwards.
  - **gitleaks over the whole range** `2ec69c8c..53ca1185` (v8.30.1, the repository's rules, `git log -p` exported and
    scanned in `dir` mode as in W3): no leaks; `.gitleaksignore` needed no new fingerprint.
  - **Real Windows**: run 3 green on windows-2022 and windows-2025 with `windows-required` green at `53ca1185`, the code
    head; `ci.yml` 39963473554 green at the same head. 4 of the 6 budgeted runs used (run 4 is the docs tip).
  - **Final review** of `2ec69c8c..4e786c29`: "ready after fixes" (three Important, minors); every finding fixed or
    declined with a reason in `1437a3bb..53ca1185` and re-reviewed (all addressed). See
    [Final review fixes (W4)](#final-review-fixes-w4).
  - **Not proven in W4**: a real tag run of `release.yml` (no tag is pushed in W4; the call is checked by `actionlint`,
    `TestReleaseWorkflowWaitsForWindows` and `make release-test` only). F14's skipped path, left open by the branch,
    was confirmed by the coordinator after the push of `main` ([F14 skipped path (W4 coordinator)](#f14-skipped-path-w4-coordinator)).

## F14 skipped path (W4 coordinator)

The check that `windows-w4` could not show (controller ruling 5). After `main` was pushed at `95873255` (W4 merged
at `a0931a01`, then the lockfile bump `322c4d0c` and `.dockerignore` `95873255`; `ci.yml` 40083713156 and `windows.yml`
40083713209 on that push), the branch `windows-w4-f14` was cut from it with this section as its only change (a file
under `docs/superpowers/`, not a watched path of `.github/windows-paths.txt`). Expected on its push: `changes` with
`windows=false`, `linux-build` and both `helper` legs `skipped`, `windows-required` success under exactly that name.
The verdict is recorded in the next commit of this branch, and the fast-forward of the branch onto `main` is a second
observation: a push to the default branch diffs against its before commit (`95873255`), again with no watched path.

**Verdict: CONFIRMED.** `windows.yml` run <https://github.com/erenmeren/alice/actions/runs/40083821806> at `c3070656`
(2026-10-24 09:54 UTC): `changes` success with the output `windows=false: no watched path changed since 95873255`,
`linux-build` skipped, `helper` skipped (the matrix shows as one skipped check run named `helper`), `windows-required`
**success**, listed on the commit's check runs under exactly that name. The plan's F14 fallback (legs that always run
and exit early) is not needed. The check can be required (owner item, Ruling 15).

**The default-branch route, also CONFIRMED.** The fast-forward of the branch onto `main` (`c7a3096e`, before
`95873255`) ran `windows.yml` <https://github.com/erenmeren/alice/actions/runs/40083935311>: `changes` success with
`windows=false`, `linux-build` and `helper` skipped, `windows-required` success. Both bases of Ruling 5 as amended (the
merge base for a branch, the before commit for the default branch) skip the legs for a non-Windows change and run them
for a Windows one (the push of `main` at `95873255`, before `2ec69c8c`, ran all five jobs).

## Owner items (W4)

- **Require the check** (Ruling 15): create the ruleset of `docs/dev/windows-ci.md` (`gh api --method POST
  repos/erenmeren/alice/rulesets ...` or the UI steps there), check it with `gh api
  repos/erenmeren/alice/rules/branches/main`, and record release-checklist row 1.47. Choose whether `ci.yml`'s checks
  join the same rule (listed there as a recommendation).
- **Confirm the bypass choice**: the ruleset lets the repository admin role bypass the check (`actor_id 5`,
  `bypass_mode: always`) so you can keep pushing `main` directly; the coordinator's flow pushes the phase branch
  first, so a commit fast-forwarded onto `main` already has a green `windows-required`. Without the bypass, `main`
  takes changes only through pull requests.
- **F14's skipped path** (controller ruling 5): **done by the coordinator**, no owner action. The branch
  `windows-w4-f14` cut from the pushed `main` with a docs-only change showed `changes` → `windows=false`, `linux-build`
  and `helper` skipped and `windows-required` success under exactly that name (run 40083821806; see
  [F14 skipped path (W4 coordinator)](#f14-skipped-path-w4-coordinator)). The fallback is not needed; the check can be
  required.
- **The first release tag** (Ruling 12): no tag was pushed in W4. On the first `v*` tag, check that `release.yml`'s
  job `windows` calls `windows.yml` with `all: true` (both legs run, `windows-required` green) and that `stage` waits
  for it; record the run in release-checklist row 1.46.
- **The manual matrix** (Ruling 19): release-checklist section 8, rows 8.1-8.8 (Windows Server 2019, Server Core, a
  domain-joined server under the security baseline with `CORP\alice-svc`, Defender or the customer's EDR on with a
  cleanup run that removes a certificate, an RDP listener with its own CA certificate kept by cleanup, the helper from
  the signed package, AD FS, ARM64), before each release (row 1.48).
- **Authenticode** (Ruling 13, design §15 Q2): decide before the first customer that runs WDAC or AppLocker, and
  before general availability, whether `alice-helper.exe` is signed (a code-signing certificate and a signing step on
  the offline machine). Until then the guides tell customers to use a hash rule.
- **Updating the helper before Alice**: the guidance "update the helpers first, then Alice" meets the setup script's
  embedded checksum: the script shown by the installed (older) Alice refuses the newer helper. The operator guide
  therefore tells the administrator to copy the checked file over `C:\Program Files\Alice\alice-helper.exe` by hand;
  the host guide's `ALC-WIN-0002` text ("repeat steps 1 to 3 with the helper of this Alice version") fits only after
  Alice was updated. Confirm the procedure, or ask for a script option that installs a newer helper.
- **The image check outside CI**: `deploy/dev/check-image.sh` skips the four embedded-checksum checks when the host's
  Go differs from the Go that built the image's binary, except in CI, where a difference fails (pre-existing). On the
  release build machine release-checklist row 3.4 (the CI stage's binaries equal to the local ones) holds only when
  that machine builds with the `go.mod` Go, so a skipped image check there cannot hide a mismatch; build the release
  with the `go.mod` Go.
- **The W3 owner decisions stay open**: cleanup while the licence is locked (`jobs.WindowsCleanup` is `ClassChange`,
  so even an incident's at-once removal waits for the lock to end), and the accepted gaps listed under "Owner items
  (W3)" (no audit row after `OUTCOME_UNKNOWN`, the notice dedupe limits, a shared key container, the Ruling 14
  assumption, a duplicate incident notice).
- **Commit trailers**: the W4 commits carry `Claude Fable 5.1` per the owner's instruction for this phase (W3 used
  the writing model's trailer).

## Deferred to W5+

- **W5-W7, on demand**: CCS (`win_ccs_file`), RDP deployment (`win_rdp`), WinRM transport.
- **Carried from W2 and W3, not decided in W4**: a third party's intermediate added after Alice's commit makes a
  redeploy answer `unchanged` with `win.chain_differs`; the emulator's slow-host fault and the abandoned-call marking
  it needs; deploying to a binding whose only problem is its key; IDN host headers in their U-label form; a manual
  "roll back this deployment" action.
- **W3's deferred minors, declined in W4 (known debt, unchanged behaviour)**: the heal step may clear a chain for a DER
  still present in another store; no test of the `maxImports` trim of adopted entries; `cleanup.go` not split; the
  provider's plan check accepts duplicate candidates; `UpdateTarget` writes `certificate_cleanup` back on every edit; a
  skipped incident place queues one extra cleanup.
- **Minors deferred during W4**: the helper version literal is asserted in several tests (the next bump touches
  several places); `TestReleasedHelperVersion`'s "numeric, not text" case does not discriminate (for example 0.10.0
  against 0.9.0); the dependency test's `_test` suffix strip would also strip a real directory ending in `_test` (none
  exists); the Dockerfile subtest of `TestWindowsHelperBuildFlagsAgree` matches an exact indented string; no
  releasebuild row for a checksum file missing one `.exe` line (the logic refuses it); the `refusalNames` table is
  keyed by subtest names; ShellCheck of the workflow's `run:` scripts; `helperSetEntries` accepts extra or duplicate
  lines in a checksum file (pre-existing, shared with the Linux set; final review m-4).
- **Not built**: a real-Windows ARM64 leg (no hosted Windows Server ARM64 runner); `ci.yml` checks made required (the
  owner's choice); a Windows gate in `make release-gates`; a `merge_group` trigger (add it if a merge queue is enabled);
  removing intermediates Alice added to `CA` (design §6.7: never); a cleanup history page.

# W5 (R68)

Phase W5 (Centralized Certificate Store) was built on branch `windows-w5` from the plan
`docs/superpowers/plans/2026-10-27-windows-w5-ccs.md` (10 tasks), assigned by the coordinator on 2026-10-27 under the
owner's approval of the Windows design with its §15 defaults. Spec: R68 in `docs/superpowers/specs/alice-v1/00-decisions.md`,
`03-integrations.md` §13A.15-13A.17, `04-security.md` §14.4 (WN-19..WN-22) and §15.11, `06-quality.md` §24.7
(WIN-46..WIN-55), design §13 W5, §14 (F15-F18) and §20. One migration, `00036`; error codes `ALC-WIN-0015`..`ALC-WIN-0020`.
None of the rulings below is a pricing decision; the ones the owner should confirm or act on are listed under
[Owner items (W5)](#owner-items-w5).

## The plan's rulings as built (W5)

The plan's 26 rulings stand as written, except where an entry says "Amended" or "Precision".

1. **Decision R68; one migration, `00036`.** As written: the six CHECKs widened with `win_ccs_file`, purpose `win_ccs`
   and kind `win_ccs_password`. Precision (Task 6): the Down refuses with SQLSTATE `Z1034` (the next free code after
   00035's `Z1033`) while a `win_ccs_file` location, deployment or `win_ccs` credential exists.
2. **Helper 1.1.0, protocol 1, `CCSMinVersion` 1.1.0; two new subcommands only.** As written: every site that asserted
   the helper's own version reads `1.1.0` (Task 1, the W4 deferred minor), `TestReleasedHelperVersion` gained a case
   that discriminates numerically, `TestFidelityVersionAndRefusals` still probes `rdp-deploy`.
3. **Supported layout: a local CCS folder.** As written. Precision (Tasks 1, 3): `ValidCCSPath` is an ASCII drive
   letter, `:\`, at most 240 bytes, one trailing backslash, no `:` or `/` after the drive and no `.` or `..` segment;
   since the final review (M3) no segment that ends in `.` or a space either (Win32 strips both, so `C:\CCS.` would
   name `C:\CCS`). Precision (Task 2): a folder that is a reparse point is the sentinel `ErrCCSFolderUnsupported`,
   answered `local: false`, so discovery warns `win_ccs_path_unsupported` (a UNC path warns `win_ccs_remote`).
   Precision (final review M2): only the CCS folder itself is checked for a reparse point, not its parent folders; a
   junction above it is followed. The registry value that names the folder is writable by Administrators only, who can
   point IIS anywhere already, so the parent check was not built (found, not fixed; owner item).
4. **The path comes from the server only.** As written. Precision (Task 3): the registry checks run disabled, then
   unsupported, then changed (a UNC registry path is `CCS_PATH_UNSUPPORTED`); `ccs-deploy` lists the folder before the
   read so a reparse-point folder is refused; a derived name holding `:`, `\` or `/` is `INVALID_ARGUMENT`. Precision
   (W5-7): a CCS file that is a reparse point answers `INVALID_ARGUMENT` through the sentinel `ErrCCSFileUnsupported`.
5. **File-name rule.** As written. Precision (Task 1): `CCSHost` folds ASCII only (Unicode folding maps the Kelvin sign
   to `k`); `CCSFileName` replaces only a leading `*.`. Precision (Task 3): `ignored` counts every host-less name, also
   past the cut.
6. **One location per file; links derived by Alice.** **Amended (W5-13, F17 measured):** the exact `<host>.pfx` first,
   otherwise the nearest `_.<suffix>.pfx` found by stripping leftmost labels, at any depth, the suffix keeping at least
   two labels, never the wildcard's own parent; the emulator's TLS lookup is the same. Precision (Task 7): `cert_path`
   is the canonical lower-case name, `file_name` the name as listed; a binding without a valid host header links
   nothing; a listing Alice cut gives no `cert_missing` location.
7. **No file creation in W5.** As written: the absent marker in `expect_sha256` is `INVALID_ARGUMENT`. Precision
   (W5-14): a new host's first file may not be served by IIS for minutes; Alice only replaces existing files.
8. **An unlinked file is deployable.** **Amended (W5-8):** the location warning is `win_ccs_unlinked` (the plan's
   `win.ccs_unlinked` would be dropped by inventory's code rule). **Amended (W5-15):** inventory accepts the skipped
   verification of a `win_ccs_file` location whose stored servers are `[]` as a success, besides `skip_verify`.
9. **One CCS password per Windows server.** As written. Precision (Task 6): setting it bumps `targets.version`; the
   answer is the bare target DTO; `public_info` is `{}`; a soft-deleted or unknown target is 404.
10. **Password rule.** As written. Precision (Task 6): inventory checks the rule itself, pinned to
    `winproto.ValidCCSPassword` by `TestCCSPasswordRuleEqualsTheHelpers`, before the target's type (deferred minor).
11. **Password transport.** As written. **Amended (Task 7 review, hardened):** `providers.ErrNoCCSPassword` (no row) and
    `providers.ErrCCSPasswordUnusable` (a foreign row or one that does not decrypt) are wrapped by inventory; any other
    error says nothing about the password. The foreign-credential error text is neutral.
12. **Alice never reads IIS's stored password.** As written. Precision (W5-12): a corrupt PFX that Windows answers with
    86 is `ccs_password_mismatch`, as a wrong password.
13. **Token = the leaf's DER SHA-256.** As written.
14. **`ccs-deploy` transaction.** **Amended: step 7 is built** (F15 route (a), W5-10): after every CCS replace and every
    CCS restore the helper makes a same-record base update of every http.sys `ccs` record of the server (keyed by the
    record's own `SOCKADDR_STORAGE`); a failure is the answer field `ccs_refresh_failed` (kept in the journal), the step
    param `ccs_refresh_failed` on `write_file` or `restore`, and never a rollback trigger; `CCSPickupWait` stays 0.
    **Amended (W5-2):** the backup is `<file>.alice-<last 8 hex digits of the op>.bak`. Precision (Task 3): `unchanged`
    writes no journal; a file that is not a PFX or has no key is `HASH_MISMATCH`, one over `MaxCCSFile`
    `INVALID_ARGUMENT`; the new bytes' hash is written with the `writing` journal; a failed `ReplaceCCS` is followed by
    a read of the file (unwritten, or self-restore); event 1004 carries the leaf hashes; `BuiltChainLength` is 0.
15. **Rollback through `iis-restore`.** As written. Precision (Task 3): `SUPERSEDED` only for a committed journal, an
    interrupted one over a third party's file ends `restore_failed` `file_changed`; an interrupted journal without its
    backup answers `BACKUP_MISSING` and stays `writing`; the restore never opens the backup (it has no password) and
    removes the temporary file; it acts in the journal's folder and refuses one that became a reparse point
    (`CCS_PATH_UNSUPPORTED`). Precision (W5-10): every restore that ends `restored` refreshes, `restoreDone` included.
16. **Backups, temporary files and W3 cleanup.** **Amended (W5-1, coordinator-approved):** a final CCS journal older than
    7 days that its file record still needs keeps the journal and loses its `.tmp` and `.bak`; `iis-restore` then
    answers `BACKUP_MISSING` with nothing written. Why: WN-22 and owner item 6 promise a backup lives at most 7 days,
    and the rule as written kept the latest backup of every file forever. Precision (Task 3): these removals run after
    the normal prunes, outside `MaxPrunePerRun`, not counted in `Pruned`, with no marker; the leftovers are read before
    the gate; a backup that cannot be read keeps its journal. Precision (W5-3): `ListCCS` of a missing folder is empty.
17. **CCS turned off, or its path changed.** As written. Precision (Task 3): the `WriteHost` folder contract is
    "CCSConfig's folder, or the folder of a valid journal".
18. **Discovery.** As written. **Amended (Task 7 review, hardened):** `ErrNoCCSPassword` gives
    `win_ccs_password_missing`; `ErrCCSPasswordUnusable`, any other password read error and a password the helper
    would refuse give `list_truncated` and `locations_dropped` with no `ccs-dump` sent (nothing is marked missing); the
    end of the context is the scan's error. Precision (Tasks 2, 7): an answer over `DumpOutput` is a failed dump; the
    dump's own budget is 40 s (`truncated`); the files are sorted by name; a host problem outside the `CCSProblem*` list
    drops the file.
19. **The http.sys `ccs` record location stays.** As written; its text and `win_ccs_enabled` point to the files and the
    password panel (Task 8).
20. **Verification endpoints.** As written. Precision (Task 7, F18): the served chain is compared with the deployed
    chain and `win.chain_differs` is never reported for a CCS file; endpoints are deduplicated by port, SNI and listen
    address; route (a) needs no longer verification window.
21. **Engine and inventory.** As written, except the notify line. **Amended (W5-5):** a CCS deployment keeps the file
    e-mail texts except `rollback_failed`, `outcome_unknown` and `restored_unverified`, which have `_windows_ccs` texts
    (the file path, the `.bak` beside it, IIS Manager) with `previous_certificate` instead of `backup_dir`; the
    `restored_unverified` text names no `.bak` (the restore consumed it). Precision (Task 7): `ccs_unlinked` and
    `ccs_refresh_failed` are on inventory's and the API's step-param allowlists.
22. **Drift.** As written.
23. **Interactions.** As written.
24. **Test IDs and STRIDE.** As written: `WIN-46`..`WIN-55`, `WN-19`..`WN-22`.
25. **e2e.** As written. Precision (Tasks 4, 8): the demo's CCS binding is the site "CCS Site" (id 3, `https
    *:443:ccs.example.test`, sslFlags 3) on the existing TLS port and `ccs` record, so no compose change; `ctl
    stale-tls-on` also switches `ServeStaleCCS`; the journey forces step-up with `advanceClock`.
26. **Runner hygiene and budget.** As written, with precisions (Task 5): one shared CCS folder and one site
    `alice-w5-ccs` on 45480 per test binary, made before any CCS handshake, torn down by `TestRealCCSSharedFolderRemoved`
    (W5-11 and fix 3); the fixture sets `PollingInterval` to 10 s and the teardown restores the key as found; the
    account `alice-w5-ccs` is added to BUILTIN\Users; the helper package's `go test` has `-timeout 30m`.

## W5 facts measured on real runners

Runs of `.github/workflows/windows.yml` (windows-2022 = Windows Server 2022 Datacenter, windows-2025 = Windows Server
2025 Datacenter, Desktop Experience). Each verdict holds on both images.

- **F15: route (a).** Runs 1-5 (<https://github.com/erenmeren/alice/actions/runs/40479436831>,
  <https://github.com/erenmeren/alice/actions/runs/40484509608>,
  <https://github.com/erenmeren/alice/actions/runs/40488480626>). A plain `ReplaceFileW` of a CCS file was not picked
  up within 2 minutes (run 1) nor within 10 s (runs 2-5); the replace followed by a same-record update of the
  `ccs:<port>` record was served after 8-12 ms. The file keeps its ACL; the backup holds the replaced bytes; `.bak` and
  `.tmp` files are never served. An appcmd binding with `sslFlags=3` creates no `ccs` record (the fixture adds it with
  netsh). Ruling W5-10. The no-op proof of the refresh (every `ccs` record, base and extended parameters, equal before
  and after) passed in run 6 (<https://github.com/erenmeren/alice/actions/runs/40499784360>, `e0752599`, both images):
  `F15: refresh no-op: 1 ccs records read the same, base and extended parameters, after RefreshCCSRecords`.
- **F16: confirmed.** Runs 2 and 4 (<https://github.com/erenmeren/alice/actions/runs/40484509608>,
  <https://github.com/erenmeren/alice/actions/runs/40491733346>). IIS serves a `BuildPFX` file; a file under another
  password is not served (HttpEvent 15301/15302, no Application event of IIS); `PFXImportCertStore(PKCS12_NO_PERSIST_KEY)`
  leaves no key file (properties 5 and 79 set); another password and a corrupt file both answer 86 (W5-12); a
  certificates-only PFX is `key_missing`. No fallback route needed.
- **F17: amended.** Runs 3-5, final run 5 (<https://github.com/erenmeren/alice/actions/runs/40494994143>). The exact
  file wins; a wildcard serves a name any number of labels below it, never its own parent; names compared without
  case; `ReplaceFileW` leaves the replacement's spelling; an explicit `hostnameport` record wins over the CCS binding
  (no `win.ccs_shadows`). `PollingInterval` defaults to 300 s and reads back 10 when set; a file for a host IIS had
  not served was not served within 40 s even at 10 s, while files present before IIS's first lookups are. Rulings
  W5-13 and W5-14.
- **F18: the PFX's intermediates.** Runs 4 and 5 (<https://github.com/erenmeren/alice/actions/runs/40491733346>,
  <https://github.com/erenmeren/alice/actions/runs/40494994143>). A file carrying the intermediate sends it; an
  intermediate only in `LocalMachine\CA` is sent only after a refresh, or for a file first served after the import.
  `import_chain` stays; the chain comparison uses the deployed chain.

The coordinator accepted F15 route (a), F16 and F18, and ruled F17 as above (change Ruling 6 to the measured rule,
exact first; keep at least one runner run for the final code head).

### Runner runs used (8 of 8)

| Run | windows.yml | Head | windows-2022 / windows-2025 | What it found |
|---|---|---|---|---|
| 1 | <https://github.com/erenmeren/alice/actions/runs/40479436831> | `1e77429a` | fail / fail | F15 route (a) measured; ACL kept; `.bak`/`.tmp` never served; appcmd creates no `ccs` record; F17 partial (hostnameport wins, names without case, the replacement's spelling); F16/F18 unmeasured (fixtures in a new folder never served); `TestRealRunnerIsClean` passed |
| 2 | <https://github.com/erenmeren/alice/actions/runs/40484509608> | `57b3dc71` | fail / fail | F15 confirmed with the refresh (12 ms; plain replace not within 10 s); F16 (86 for another password and a corrupt file, `key_missing`, no key file); fixtures in a new folder not served (W5-11); the junction test's error passthrough bug; `TestFidelityCCS` and `TestRealRunnerIsClean` passed |
| 3 | <https://github.com/erenmeren/alice/actions/runs/40488480626> | `b0e60d22` | fail / fail | F15 again (9-10 ms); a second folder served 5 s after Enable and a refresh (W5-11's premise wrong, the shared folder kept as harmless); a new port's first serve dead for about 150 s; F17: a wildcard served two labels down |
| 4 | <https://github.com/erenmeren/alice/actions/runs/40491733346> | `30294923` | fail / fail | Only `TestRealCCSNameRules` and `TestRealCCSServedChain` failed; F16 fully measured; F18 measured; DIAG named `PollingInterval` |
| 5 | <https://github.com/erenmeren/alice/actions/runs/40494994143> | `632c6ef5` | **pass / pass** | F17 and F18 final (pre-placed files, `PollingInterval` 10 s) |
| 6 | <https://github.com/erenmeren/alice/actions/runs/40499784360> | `e0752599` | **pass / pass** | `windows-required` green; the refresh no-op proven (`F15: refresh no-op: 1 ccs records read the same, base and extended parameters, after RefreshCCSRecords`); W5-13 in the emulator, the step params and W5-15 green |
| 7 | <https://github.com/erenmeren/alice/actions/runs/40505803226> | `cc4247af` | **pass / pass** | `windows-required` green; the final review's fixes (Ruling P8) |
| 8 | <https://github.com/erenmeren/alice/actions/runs/40509514838> | `c879b032` | **pass / pass** | `windows-required` green; the final code head |

The `ci.yml` runs of the same pushes:

| Run | ci.yml | go | coverage | web |
|---|---|---|---|---|
| 1 | 40479436681 | pass | fail: `TestServeStartsOnAPhase3Database` expected migration 35, now 36 (fixed in `362b7893`) | fail: the enum and label tests (fixed by Task 8) |
| 2 | 40484509526 | pass | fail: `internal/inventory` 88.9 % < 89 | fail (Task 8 in progress) |
| 3 | 40488480505 | pass | fail: the `internal/inventory` floor | fail (Task 8 in progress) |
| 4 | 40491733481 | pass | fail: the `internal/inventory` floor | fail (Task 8 in progress) |
| 5 | 40494994086 | pass | fail: the `internal/inventory` floor | fail (until Task 8) |
| 6 | 40499784357 | pass | fail: `internal/inventory` 89.0 % shown, below its floor of 89 (closed by the inventory coverage test `76a62ecc`) | pass (`stack` cancelled by a newer push) |
| 7 | 40505803113 | pass | cancelled by the next push | pass (ssh-matrix, secrets and licensectl pass; `stack` cancelled by the next push) |
| 8 | 40509514817 | pass | pass | pass (every job: go, web, coverage, ssh-matrix, secrets, licensectl, stack) |

## Rulings made during execution (W5)

One line each: the ruling, then why (and the cost if wrong where it is not obvious).

### Controller (order and process)

- P1: Tasks 4, 5 and 6 ran one after another (4, 5, 6), not in parallel; Task 6 ran while runner run 1 was in flight —
  the skill forbids parallel implementers in one worktree and Task 5's `TestFidelityCCS` needs Task 4's emulator (cost:
  wall-clock only).
- P2: runner run 1 was pushed once Task 5's runner tests existed, not right after Task 3 — Task 3's code alone has no
  real CCS test to run; F15-F18 were still known before Task 7 needed them.
- P3: Task 2's implementer was dispatched while Task 1's review ran — the reviewer is read-only and Task 2 touches no
  `winproto` file.
- P4: commit `39b58279` carries the trailer "Claude Opus 5.5"; it was not amended (no history surgery), and later
  dispatches state C4 explicitly — the subagent followed its harness attribution rule over C4; cosmetic (owner item).
- P5: Task 6 was dispatched in parallel with Task 3's review — disjoint files, the reviewer read-only.
- P6: Task 7 ran concurrently with Task 5, with the F15, F17 and F18 dependent spots kept in single named functions
  (`pickupAttempts`, `ccsFileFor`, `comparedChain`) and adjusted after the runs — it saved hours of serial wait.
- P7: Task 8 was dispatched while Task 5's runner fixes and Task 7's re-review ran — `web/**` is disjoint; the e2e may
  need a rerun after the emulator's refresh change.
- P8: Task 5's refresh fix and Task 7's W5-13 emulator change go to the runner together as run 6; run 7 is reserved for
  the final head after the final review's fixes; run 8 is spare.
- P9: Task 9 (these documents) started before the Task 5 and Task 7 follow-up re-reviews closed — the documents are as
  built, and a late code change gets a docs touch in the final fix wave (cost: one doc edit).
- W5-1: a CCS backup lives at most 7 days after its journal is final, even when the record still needs the journal
  (Ruling 16 amended; coordinator-approved) — WN-22 and owner item 6 promise 7 days; cost: no rollback of an operation
  older than 7 days (verification is immediate, so none in practice).
- W5-2: the backup name uses the last 8 hex digits of the operation id — ids are UUIDv7, whose first 8 hex digits are
  time bits, so two operations on one file within about 65 s would share a name.
- W5-3: `ListCCS` of a missing folder answers an empty list (real host and emulator) — a journal whose folder was
  removed after a path change can still be restored or pruned.
- W5-4: the emulator compares CCS file names without case (NTFS) and folders with ASCII case folded and one trailing
  backslash trimmed — as Windows does (confirmed by F17).
- W5-5: the CCS `rollback_failed`, `outcome_unknown` and `restored_unverified` e-mails get Windows CCS texts (Ruling 21
  amended) — those mails reach an operator who must act by hand, and Linux/Nginx steps there are an operations hazard;
  cost: 3 texts in 2 languages.
- W5-6: Task 4 fixed `TestDiscoverListsBindingsWithSites`, which its demo change broke (scope widened to
  `discover_test.go`).
- W5-7: a CCS file that is a reparse point answers `INVALID_ARGUMENT` (Ruling 4) through the sentinel
  `winhelper.ErrCCSFileUnsupported` of the real host and the emulator — before it every `ReadCCS` error was
  `IO_ERROR` (exit 1, the "outcome uncertain" class).
- W5-8: the location warning code is `win_ccs_unlinked`, not `win.ccs_unlinked` — inventory's `codeRE`
  `^[a-z][a-z_]{0,39}$` (`locations.go:49`, the column CHECK) drops dotted codes.
- W5-9: a cut `iis-dump` site list may leave a partial-site `win_ccs_unlinked` warning beside `locations_dropped` —
  accepted: a warning only, corrected by the next full scan. **Superseded (final review I1):** a cut site list (the
  helper's cut of the `iis-dump`, or a site binding Alice cannot read) now cuts every CCS file location
  (`list_truncated`, never `win_ccs_unlinked`), because an unlinked file's verification is skipped.
- W5-10: F15 route (a): after every CCS replace and every CCS restore the helper makes a same-record update of every
  http.sys `ccs:<port>` record (the helper does not know the links; the update is idempotent); `CCSPickupWait` stays 0
  — measured on both images; cost: an extra http.sys write per deployment.
- W5-11: the real tests share one CCS folder per test binary — run 2 showed fixtures in a new folder not served; run 3
  showed the premise wrong (a second folder was served after Enable and a refresh), and the shared folder stays as
  harmless test design.
- W5-12: a corrupt PFX that Windows answers with 86 stays `ccs_password_mismatch` — Windows cannot distinguish it from
  a wrong password; cost: a damaged file counted in the mismatch warning.
- W5-13 (F17): Ruling 6's linking is the exact file first, else the nearest `_.<suffix>.pfx` stripping leftmost labels
  (any depth, suffix of at least two labels, never the parent); the emulator's TLS lookup is the same — measured on
  both images; cost if wrong: the order between two wildcards (nearest first) is not measured.
- W5-14 (F17, product fact): a CCS file for a host IIS has not served before may not be served for minutes (not within
  40 s even at `PollingInterval` 10); Alice only replaces existing files (Ruling 7), whose replacement is served at once
  after the refresh — documented in the host guide; no cost to Alice's flow.
- W5-15: inventory accepts a skipped verification success for a `win_ccs_file` location whose stored servers are `[]`
  (Ruling 8, read-back only), besides `skip_verify` — `FinishDeployment`'s `errSkipNotAllowed` made every unlinked CCS
  deployment end uncertain; the exception rests on what discovery stored, not on the provider's word; cost: an
  unlinked file deploys without a probe, as Ruling 8 intends.
- Task 1's `ValidCCSPath` minors (`:` after the drive, `.` segments) were carried into Task 3 and fixed there; the
  empty segment and a trailing dot or space stay deferred (the path comes from the registry only).
- Task 2's carried minors (the host problem allowlist, the `ignored` count) were fixed in Task 3; the whole `ccs-dump`
  answer's size is bounded on the provider side (`DumpOutput`, Task 7); the test PFX reader's padding and iteration
  bound moved to Task 4 (`maxPFXIterations` 100000).
- Task 4's reparse-point gap was closed in its fix round (`Model.SetCCSReparse`); Task 5's review minors went into its
  post-run fix commit.

### Coordinator

- C1: Docker and the gate are free (nothing else runs on the machine); never two Docker-based runs at once, and a known
  load-sensitive test gets the staged fallback (run alone, captured with `-v`) instead of a weaker proof.
- C2: the executor may push `windows-w5` only; never `main`, no pull request, no repository setting, no tag.
- C3: the backup stays in the CCS folder as planned (Ruling 16); the owner decides (owner item 6); the
  `C:\ProgramData\Alice\helper` alternative was not built.
- C4: every commit trailer is `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`, every subject ends `(R68)`,
  staging by explicit path only.
- C5: Playwright picks up `web/e2e/windows-ccs.spec.ts` (`testDir ./e2e`, no `testMatch`), and `cmd/alice-fakewindows`
  is the same compose service, so no compose change is needed.
- C6: `graphify query` before the first grep or source read of a codebase question; the graph reflects `main`
  `e15fad4b`, so files new on this branch are read directly; no `graphify update`.
- Approved W5-1 (Ruling 16 amended), with the reason WN-22 / owner item 6, and asked that an engine test show a restore
  after pruning fails closed (`BACKUP_MISSING`, nothing written): Task 7's crash-table subtest and
  `TestCCSRollbackDeployment`.
- Ruled commit `39b58279`'s trailer stays as it is (W2 and W3 precedent), listed under owner items.
- Accepted F15 route (a), F16 and F18; ruled F17 (Ruling 6 changed to the measured rule if run 5 confirmed it, exact
  first) and asked to keep at least one runner run for the final code head.

### Task 1 (winproto)

- `CCSHost` folds ASCII only (a manual loop, not `strings.ToLower`) — Unicode lower-casing maps U+212A (Kelvin) to `k`
  and would accept a name the folder comparison never meant.
- `ValidCCSPath` requires `X:\` with an ASCII drive letter, allows one trailing backslash and counts bytes (at most 240)
  — Ruling 4's comparison trims one backslash.
- `CCSFileName` replaces only a leading `*.` — `ValidHost` allows `*` only there, so the inverse stays exact.
- `CCSPickupWait` is a typed `time.Duration` constant, 0 (route (a) kept it so).

### Task 2 (winhelper: CCS host surface, BuildPFX, ccs-dump)

- The shared PFX reader is `pki.OpenPFX` in `internal/testutil/pki/pfxread.go` — archtest already allows `wintest` to
  import the test PKI; the release helper links no test package; go-pkcs12 takes the first certBag as the leaf.
- A CCS folder that is a reparse point is `ErrCCSFolderUnsupported`, answered `local: false` — Ruling 3 wants it
  unmanaged, not an I/O failure.
- `ccs-dump`'s time budget is `HelperBudget*4/5` (40 s) on the host clock, ending the list with `truncated` — the
  answer must leave before `Execute`'s call budget ends.
- A file whose read or open fails with a host error, or whose certificates exceed the bounds, is dropped with
  `truncated`; a file that vanished after the list is skipped — as iis-dump's dropped certificate (nothing marked
  missing).
- A `too_large` file has no `file_sha256`, and its size is the listed size — the helper never reads past
  `MaxCCSFile+1`.
- The files are sorted by name before the bounds apply; ignored names do not count toward `MaxCCSFiles` — a
  deterministic answer and cut.
- `Execute` reads standard input before the elevation check (the common path), so 4 KiB + 1 is `TOO_LARGE`; a
  non-elevated call is still refused before any parse or host read.

### Task 3 (winhelper: ccs-deploy, restore, status, fence, pruning)

- The journal's folder field is `ccsJournal.Path` (JSON `path`), not `Folder` — W2's `TestJournalHoldsNoKeyMaterial`
  refuses any field name containing "der".
- An `OpenPFX` problem outside the three `CCSProblem*` values is an error for that file (dump: dropped, `truncated`;
  deploy: `IO_ERROR`) — a host's words never reach the answer.
- The registry order is disabled, then unsupported, then changed — a UNC registry path is `CCS_PATH_UNSUPPORTED`.
- `ccs-deploy` lists the folder before the read to refuse a reparse-point folder — `ReadCCS` guards only the file.
- `unchanged` writes nothing, not even a journal — Ruling 14 places it before the prepared journal.
- A non-PFX or keyless file is `HASH_MISMATCH`; a file over `MaxCCSFile` is `INVALID_ARGUMENT` — the token cannot
  match, and discovery already marks both as problems.
- `expect_sha256` is the leaf DER SHA-256, and the absent marker is `INVALID_ARGUMENT` (Rulings 7, 13); the
  `CCSDeployInput` comment was corrected to say so (fix 1).
- `NewFileSHA256` is written with the `writing` journal, after the PFX is built — restore and status then recognise
  exactly the bytes this operation wrote.
- A failed `ReplaceCCS` is followed by a read of the file: the previous bytes mean unwritten (temporary file removed,
  `restored`, `failed_step write_file`), anything else a self-restore — `ReplaceFileW` can fail after moving the file
  (`ERROR_UNABLE_TO_MOVE_REPLACEMENT_2`).
- The restore checks the guard on the journal's previous leaf and SPKI hashes and never opens the backup — it has no
  password; the backup's bytes must equal the previous file's.
- A restore that ends `restored` removes the operation's temporary file (best effort) — the kill between the temporary
  write and the replace.
- A kill after `prepared` is recovered by `iis-fence`, as in W2.
- Kill points: `ccs.locked`, `ccs.prepared`, `ccs.import_chain`, `ccs.writing`, `ccs.temp_written`, `ccs.replaced`,
  `ccs.read_back`, `ccs.committed`; the restore points keep W2's names.
- Event 1004 is `ccs file <name> sha256 <old leaf> -> <new leaf> op <op>` — the token's hashes, not the bytes'.
- `BuiltChainLength` is 0 for CCS — no `WriteHost` method builds a chain for a leaf outside a store; F18 made it moot.
- `deployTx` is reused for CCS and the `import_chain` loop is shared as `importChain` — one transaction type.
- Fix 1: the WN-22 removals run after the normal prunes, outside `MaxPrunePerRun`, not counted in `Pruned`, with no
  journal marker — a journal a record always needs would otherwise take a slot on every plan.
- Fix 2: `SUPERSEDED` only for a committed journal; an interrupted one over a foreign file ends `restore_failed`
  `file_changed` — as in W2; the next deployment's compare-and-swap decides.
- Fix 2: an interrupted CCS journal whose backup is missing or changed answers `BACKUP_MISSING` before any write and
  stays `writing` — as W2 does for a missing previous certificate.
- Fix 2: a read-back that lastingly finds neither the previous nor the new bytes ends `restore_failed` `file_changed` —
  nothing is moved over bytes of unknown origin.
- Fix 2: restore and prune use the journal's folder after a path change and list it first; a folder that became a
  reparse point is refused (restore `CCS_PATH_UNSUPPORTED`; prune keeps the journal and its files).
- Fix 2: prune reads a CCS journal's leftovers before the gate and enters the gate only to remove something.

### Task 4 (wintest and cmd/alice-fakewindows)

- `ListCCS` of a missing folder is empty, `ReadCCS` not found and `RemoveCCS` nil (W5-3).
- File names compared without case, folders with ASCII case folded (W5-4).
- IIS's private-key password is model state (`Model.SetCCSPassword`, `Model.CCSPassword`) — TLS must decide whether
  IIS opens a file, and `ctl ccs-password` prints the demo's password.
- `PutCCSFile` writes `BuildPFX`'s format and TLS reads every file with `pki.OpenPFXKey` under the store password — one
  path serves third-party files and files the helper wrote.
- TLS selection is `hostnameport`, then the port's `ccs` record (CCS on and an SNI given), then `ipport`, without
  falling through once the `ccs` record is selected — F17 confirmed `hostnameport` wins.
- The chain served from a CCS file is the PFX's own intermediates — as F18 then measured.
- `ServeStaleCCS` pins the bytes served before the first replace or restore while stale, keyed by the folded file name
  (fix round: it follows the host across a path change) — mirrors `StaleTLS` so a rollback under stale TLS verifies.
- `ctl stale-tls-on` and `stale-tls-off` also switch `ServeStaleCCS`; no separate ctl command — Ruling 25 step 5.
- The demo's CCS binding is the site "CCS Site" (id 3, `https *:443:ccs.example.test`, sslFlags 3) on the existing
  `ccs` 443 record and TLS port — no new port, no compose change.
- `pki.maxPFXIterations` is 100000 — `BuildPFX` writes 10000 and 2048; 2^31 would hang a test.
- Fix round: `Model.SetCCSReparse` models a reparse-point folder or file.

### Task 5 (cmd/alice-winhelper, the real CCS half)

- W5-7 as specified: `ErrCCSFileUnsupported` is `INVALID_ARGUMENT` in `ccs-deploy` and "not listed" in `ccs-dump`; the
  other `ReadCCS` callers treat it as an ordinary error — a link in place of a file Alice wrote should stop, not be
  followed.
- Only the folder itself is checked for a reparse point, not its parent components — Ruling 3 names "a folder that is a
  reparse point", and a parent junction still resolves to one folder.
- `OpenPFX` returns the non-leaf certificates in chain order (issuer upward, then the rest) — a memory store's order is
  not documented; this keeps `unchanged` working.
- `PFXImportCertStore` judges the password; a corrupt PFX is a mismatch only on `ERROR_INVALID_PASSWORD`, otherwise
  `not_a_pfx` (fix 1; then W5-12 for 86).
- `hasKey` accepts any key property or a key `CryptAcquireCertificatePrivateKey` reaches — which property
  `PKCS12_NO_PERSIST_KEY` sets is not documented (F16 logged 5 and 79).
- `OpenPFX` uses `PKCS12_NO_PERSIST_KEY` only, without `PKCS12_ALWAYS_CNG_KSP` — F16 found no leftover key file.
- `RemoveCCS` refuses a reparse point, as `RemoveState` does, and `RestoreCCS` refuses a backup that is one — a planted
  link is never removed or moved into the file's place.
- `ReplaceCCS` retries on sharing violation, access denied and `ERROR_UNABLE_TO_REMOVE_REPLACED` — IIS may hold the file
  while it reads it, and each leaves both files under their own names.
- `writeFlushed` gains a `flags` argument — the state-file writer is reused for the temporary file.
- The helper package's `go test` has `-timeout 30m` — F15's polling can exceed the default 10 minutes.
- The CCS fixture account is added to BUILTIN\Users (S-1-5-32-545) — `New-LocalUser` does not add it.
- `TestFidelityCCS` drops `modified_at` and `file_sha256` after checking each host's hash against its own bytes —
  `BuildPFX` salts every write.
- Fix 1: a failed refresh is the response field `ccs_refresh_failed` (and the journal's `refresh_failed`), not a step —
  `winproto.Step` has no params, and a new step name would make every answer undecodable to an older provider.
- Fix 1: the refresh runs after the replace and before the read-back; every restore that ends `restored` refreshes,
  `restoreDone` included.
- Fix 1: `refreshCCSRecords` is base-only, one update per `ccs` record — F9 showed a base update keeps the extended
  parameters; `keyOf` still refuses `ccs`, so no deploy path reaches a `ccs` record.
- Fix 1: the emulator pins the served bytes on every helper replace or restore and a refresh clears the pins; a third
  party's `PutRawCCSFile` is served at once (deliberate, deferred) — models IIS as measured without breaking staged
  files.
- Fix 1: the emulator's `ReplaceCCS` spells the file as the helper gave the name (F17, run 1); `RestoreCCS` keeps its
  spelling rule (unmeasured).
- Fix 1: a certificates-only PFX is not staged in `TestFidelityCCS`; the emulator answers `not_a_pfx` where Windows
  answers `key_missing` — both map to `HASH_MISMATCH` in `ccs-deploy`; only the dump's word differs.
- Fix 2: one CCS folder for the whole test binary, torn down by `TestRealCCSSharedFolderRemoved` (required by name),
  `TestMain` as a safety net — the teardown runs before `TestRealRunnerIsClean`.
- Fix 2: `ccsFilePath` and `ReadCCS` pass `ccsDir`'s error through — a reparse-point folder is
  `ErrCCSFolderUnsupported` for every host method.
- Fix 3: one shared site `alice-w5-ccs` on 45480 made before any CCS handshake; DIAG lines on a failed serve — a new
  port's first serve was dead for about 150 s.
- Fix 4: the fixture sets `PollingInterval` to 10 s and pre-places the F17 and F18 files before the site exists — F17's
  first-serve delay.
- Fix 5: the refresh writes each `ccs` record over its own `SOCKADDR_STORAGE` — a key rebuilt from decoded text could
  name another record (an IPv4-mapped IPv6 address); an undecodable record counts as a refresh failure.
- Fix 5: the no-op proof compares the extended-parameter query answers as text, query errors included — an
  unsupported table must answer the same both times.

### Task 6 (migration, inventory, API)

- Inventory implements the password rule itself, pinned to `winproto.ValidCCSPassword` by
  `TestCCSPasswordRuleEqualsTheHelpers` — archtest does not let inventory import `winproto`.
- 00036's Down refuses with `Z1034` — each refusing Down has its own code.
- The `ALC-WIN-0015..0020` troubleshooting sections were written in Task 6 — `TestWindowsErrorCodes` requires a
  section for every registered code.
- Setting the password bumps `targets.version` and `updated_at` — the ETag and `ccs_password_set_at` change.
- `public_info` of a `win_ccs` row is `{}` — nothing about the password is public; the date is `created_at`.
- The route answers the bare target DTO — there is no job or access report to carry.
- The rule check (422) comes before the licence check inside inventory — the route already gates ClassChange.
- Kind and step-name tests in `groundwork_test.go`, the DTO field in `inventory_dto.go`, the target field in
  `types.go` — where those lists and types live.
- W5-5 texts: `restored_unverified_windows_ccs` names no `.bak` and no `previous_certificate` — the restore moved the
  backup onto the file.
- The backup is named in the e-mail text as `.alice-<id>.bak` ("the last 8 characters of the operation"), not as a
  computed param — inventory may not import the helper's name rule.

### Task 7 (Windows provider and engine tests)

- The server warnings are `win_ccs_password_missing`, `win_ccs_helper_outdated` and `win_ccs_password_mismatch`
  (`count`); `win_ccs_remote`, `win_ccs_path_unsupported` and `win_ccs_files_ignored` (`count`) are `winproto`'s.
- Discovery checks CCS on, the folder (`ValidCCSPath`: UNC `win_ccs_remote`, else `win_ccs_path_unsupported`), the
  helper version, then the password; CCS turned off between the two calls means no files and no warning.
- A failed `ccs-dump` (error, undecodable, refused, over `DumpOutput`) keeps the `iis-dump` result with
  `list_truncated` and `locations_dropped`; the end of the context is the scan's error.
- File problems map: `ccs_password_mismatch` stays, `not_a_pfx` is `not_a_certificate`, `too_large` stays,
  `key_missing` is the key problem; every problem makes the location unsupported `file_problem` without chain or
  token.
- A folder listing Alice cut (truncated, a duplicate host, more than `MaxCCSFiles`) gives no `cert_missing` locations.
- The CCS backup reference is `{OperationID, PreviousSHA256}` in the provider too; a CCS `rollback_failed` has params
  `{}`.
- The verification of an unlinked file is `{OK, skipped, installed, ccs_unlinked}` and `verifyNew` copies `ccs_unlinked`
  onto the verify step — `StepParams()` alone drops params on an OK result.
- A non-ASCII CCS password is refused before sending with `certificate.invalid` — inventory never stores one.
- Fix 1: `ErrCCSPasswordUnusable` keeps foreign or undecryptable rows final (`internal.unexpected`); in discovery it is
  the `locations_dropped` path, not `win_ccs_password_missing` — a password is set.
- Fix 1: a deployment's password refusal: no password `windows.ccs_password_missing` (final), the end of the context
  `ssh.timeout`, unusable `internal.unexpected` (final), any other error `windows.io_error` (retryable); none sends.
- Fix 2: the flag `ccs_refresh_failed` goes on `write_file` for a `ccs-deploy` answer (even after the helper's own
  restore) and on `restore` for an `iis-restore` answer — the step of the change the answer is about.
- Fix 3: W5-13 in `ccsFileFor` and the emulator (`shortcut:` comment: nearest-first between two wildcards is not
  measured); `ccs_unlinked` and `ccs_refresh_failed` on inventory's `stepParamKeys` and the API's `stepParamRules`
  (`^true$`); W5-15.

### Task 8 (web and e2e)

- `api/openapi.yaml` names `write_file` among the step names — `enums.test.ts` compares the step list with the Go
  sources and the spec.
- `setCCSPassword` lives in `web/src/api/endpoints.ts` — every target call is there.
- The panel shows when the scan warning `win_ccs_enabled` is present — `WindowsFacts` has no CCS field.
- The panel is shown to anyone who can see the server, the field only with `credentials.manage` — the API enforces the
  permission and the date is useful to Operators.
- The field is emptied on every submit, also after a refusal — the password is never kept after submit.
- `isWindowsDeployment` stays binding-only and the CCS kind has `isCCSDeployment` — a CCS file is a file; the binding
  texts must not apply.
- The `windows.ccs_*` reasons are excluded from the binding-wording check and get a check of their own — they speak of
  a file.
- `enums.test.ts` also reads the `Warn*` constants of `internal/providers/windows/ccs.go` — those codes come from the
  provider.
- The e2e forces step-up with `advanceClock(STEP_UP_SECONDS + 1)` — Ruling 25 requires that setting the password asks
  for step-up.
- Fix round: the deploy dialog's summary follows the location it was opened from; "Select all bindings of this
  certificate" keeps its wording (deferred minor).

## Final review fixes (W5)

The coordinator's independent final review of `e15fad4b..e0752599` (verdict: fix first, no security blocker). One line
per finding: the finding, what was done, why.

- **I1 (Important, Review Focus 3, WN-21):** `convertCCS` skipped an https binding it could not read (or one past
  `maxMembershipsPerDump`) silently, and ignored the helper's own cut of the `iis-dump` (`truncated` or
  `list_truncated`: sites past `MaxSites`, bindings past `MaxSiteBindings`, a binding with bad `sslFlags`), so a file
  whose only binding was skipped or cut became `win_ccs_unlinked` and its deployment skipped the probe. Fixed (`b7d0f286`,
  round 2 `a0db6b3f`): such a skip, and the helper's cut (`dumpCut`, the same expression the binding conversion uses),
  set `list_truncated` and `locations_dropped` and cut every file location (`list_truncated`, no `win_ccs_unlinked`);
  the helper's cut also leaves out the `cert_missing` locations (a shadowing `hostnameport` record may be the entry
  cut); `unlinkedCCS` never answers true for a location with
  `list_truncated`, so its verification probes (no endpoint known: `verify_unreachable`, the house rule, and the
  backup is restored); the deployment material now carries the stored location warnings of a location that is not a
  file, so the provider sees the cut at deploy time and W5-15's inventory exception (`servers = '[]'`) is never
  reached for such a location (`TestConvertCCSUnreadableBindingIsNotUnlinked`,
  `TestWindowsCCSCutBindingIsNeverSkipped`). Why: a write IIS cannot open must never stay unverified. Trade-off: a cut
  CCS file with no binding read has no endpoint, so its deployment ends `verify_unreachable` and the backup is
  restored (the house rule for a location without endpoints); the next full scan, without a cut, makes the file
  deployable again (linked, or `win_ccs_unlinked`).
- **I2 (Important):** the Task 9 rulings were written before run 6 finished. Fixed: run 6's row, the F15 no-op verdict,
  the owner item and the `ci.yml` results are filled in. Why: the as-built record must hold the measured verdicts.
- **M1 (Minor, F17):** the measured `hostnameport` precedence was recorded only. Fixed: a CCS binding whose host and
  port have an http.sys `hostnameport` record is linked to no file and makes no `cert_missing` location, and the file
  it would use gets the location warning `win_ccs_shadowed` (EN and TR texts); a file left with no binding is
  `win_ccs_unlinked` as well (`TestConvertCCSHostnamePortShadows`). Ruling: the `hostnameport` location itself gets no
  warning, because it serves the host and its own deployment is probed correctly; the plan's `win.ccs_shadows` was
  for the outcome F17 measured false. Why: a deployment to the file would otherwise probe the `hostnameport`
  record's certificate and roll back every time.
- **M2 (Minor):** the helper checks only the CCS folder itself for a reparse point, not its parents. Not fixed:
  recorded in Ruling 3 as built and under owner items. Why: the folder comes from a registry value only
  Administrators can write.
- **M3 (Minor):** `ValidCCSPath` accepted a segment that ends in `.` or a space, which Win32 strips. Fixed: refused,
  with new table rows in `TestValidCCSPath` (`winproto` coverage stays 100 %). Why: the name checked must be the name
  Windows opens.
- **M4 (Minor):** the `BACKUP_MISSING` answer of a CCS restore used the certificate-store text. Fixed: a CCS journal
  answers the fixed text "the CCS file's backup is missing or was changed" (no path, no password;
  `TestCCSRestoreRules`). Why: the message must name what is missing.
- **M5 (Minor):** the CCS password field help omitted "printable ASCII". Fixed in EN and TR, as the API, the 422 text
  and the troubleshooting entry say. Why: the help must state the whole rule.

Found, not fixed:

- The CCS folder's parent folders are not checked for a reparse point (M2 above; Ruling 3 as built).
- Tooling, outside W5: `make ci`'s own gitleaks step scans 0 commits inside a git worktree (the mounted `.git` file
  points outside the container), so it proves nothing for a worktree branch. The W5 range was scanned separately (see
  [Acceptance (design §13 W5)](#acceptance-design-13-w5)).

## Acceptance (design §13 W5)

Status: **met** at the final code head `c879b032`.

- A CCS location belongs to the Windows server that hosts the folder (Tasks 6-7): **met**. One `win_ccs_file` location
  per file of that server's own folder (`TestDiscoverCCSLinks`, `TestWindowsCCSLocationTargetContract`); the password
  is the server's own credential (`TestCCSPasswordForeign`).
- Kind `win_ccs_file`, named `<host>.pfx` or `_.<domain>.pfx` (Task 1): **met**. `TestCCSFileNameRule`, migration
  `00036` (`TestMigration00036WindowsCCS`).
- Written with the CCS password an Administrator enters with step-up (Task 6): **met**. `TestSetCCSPassword`,
  `TestCCSPasswordNeverEchoed`, `TestCCSPasswordIsNeverOutsideStdin`; the e2e journey asks for step-up.
- Atomically, with a backup kept for rollback (Tasks 3, 5; F15 route (a)): **met**. `TestCCSDeployCommits`,
  `TestCCSKillAtEveryPoint`, `TestCCSFailedVerificationRestoresBackup`; `TestRealCCSReplaceIsPickedUp` on both images.
- The IIS servers' `ccs` bindings linked for verification (Task 7, W5-13): **met**. `TestCCSFileFor`, `TestCCSEndpoints`,
  F17 measured on both images.
- No double hop (Ruling 3): **met**. The helper writes a local path only; a UNC folder lists no files
  (`TestDiscoverCCSFolderNotManaged`, `TestCCSDeployRefusesBeforeAnyWrite`).

Final gates:

- **Local `make ci`** on `c879b032` (`E2E_PROJECT=alice-e2e-w5 ALICE_E2E_PORT=9982`): exit 0. e2e 167 passed, 4 skipped,
  0 failed (52.9 min). Coverage floors met, none lowered: `winproto` 100.0, `winhelper` 97.4, `windows` 99.0, `wintest`
  97.5, `cmd/alice-fakewindows` 93.1, `winjobs` 100.0, `inventory` 89.3 (floor 89).
- **gitleaks over the whole range**: the `e15fad4b..HEAD` patch log exported (1.14 MB) and scanned with gitleaks v8.30.1
  in `dir` mode with `.gitleaks.toml`: no leaks found. `ci.yml`'s secrets job also passed on every push. `make ci`'s own
  gitleaks step scans no commits in a worktree ("Found, not fixed" above).
- **Real Windows**: run 8 (<https://github.com/erenmeren/alice/actions/runs/40509514838>) green on windows-2022 and
  windows-2025, with `windows-required` green at the final code head `c879b032`. All 8 budgeted runs used.
- **`ci.yml`**: run 40509514817 green at `c879b032`, every job.

## Owner items (W5)

From the plan:

1. **Ruling 3:** only a local CCS folder on the IIS server itself is managed in W5; the shared-folder farm layout is
   deferred.
2. **Ruling 7:** Alice never creates a CCS file in W5. The first file for a host is placed by the administrator; Alice
   then manages it.
3. **Ruling 9:** one CCS password per Windows server (not per location), set through the API with step-up,
   append-only, with no delete in W5.
4. **Ruling 10:** the password must be 12-128 printable ASCII characters without spaces. A CCS whose configured
   password does not meet that cannot be managed.
5. **Ruling 12:** Alice does not read IIS's stored password. A wrong password shows as files it cannot open, and a
   wrong write is caught by the probe of a linked host. An unlinked file is checked by read-back only (Ruling 8).
6. **Rulings 14-16, WN-22:** each write leaves a backup `<file>.alice-<8 hex>.bak` (the last 8 hex digits of the
   operation, W5-2) in the CCS folder for at most 7 days (pruned by the daily `windows.cleanup`). It holds the previous
   private key, encrypted with the CCS password, under the folder's ACL. If that is not acceptable, the alternative is
   a backup under `C:\ProgramData\Alice\helper` (same volume only, F15); it was not built (C3).
7. **Ruling 2:** restore, status and fence of CCS operations reuse the `iis-*` subcommands by journal kind, instead of
   adding `ccs-restore` and `ccs-status`.
8. **Ruling 26:** the runner tests install `Web-CertProvider` and leave it installed on the hosted runner images (they
   are discarded after each job).
9. **The F15-F18 verdicts** ([W5 facts measured on real runners](#w5-facts-measured-on-real-runners)), especially F15
   route (a): Alice rewrites the http.sys `ccs` records after every write and restore.

Added during execution:

- **Commit `39b58279`'s trailer** reads "Claude Opus 5.5" instead of "Claude Fable 5.1" (P4); the coordinator ruled it
  stays as it is (W2/W3 precedent, no history surgery).
- **Ruling 16 amended (W5-1):** a backup lives at most 7 days even for the latest operation of a file, whose journal is
  kept; a rollback of an operation older than 7 days then fails closed (`BACKUP_MISSING`, nothing written). Confirm the
  bound.
- **W5-13:** between two wildcard files that both match a host (`_.b.example.com.pfx` and `_.example.com.pfx` for
  `a.b.example.com`), Alice links the nearest; IIS's order there was not measured.
- **W5-14:** a new host's first CCS file may not be served by IIS for minutes (not within 40 s even at a 10 s
  `PollingInterval`). Alice only replaces existing files, so its own deployments are not affected; the host guide tells
  administrators to place the first file before the site's first request.
- **The refresh touches every http.sys `ccs` record of the server** (W5-10), not only the linked ports, with each
  record's own values. The runner proved the update changes no record and no extended parameter in run 6
  (<https://github.com/erenmeren/alice/actions/runs/40499784360>, both images: `F15: refresh no-op: 1 ccs records read
  the same, base and extended parameters, after RefreshCCSRecords`), and again at the final head in run 8
  (<https://github.com/erenmeren/alice/actions/runs/40509514838>); a failure of another application's record
  reports `ccs_refresh_failed` on the deployment.
- **The CCS folder's parents are not checked for a reparse point** (final review M2, Ruling 3 as built): only the
  folder itself is. The registry value that names it is Administrator-owned. Confirm, or ask for the parent check.
- **`win_ccs_shadowed` (final review M1):** a CCS binding that an http.sys `hostnameport` record serves is linked to no
  file; the file says `win_ccs_shadowed`, and the `hostnameport` location gets no warning. Confirm.
- **The W4 owner items stay open** (the ruleset, the first release tag, the manual matrix, Authenticode, the helper
  update procedure): a 1.1.0 helper needs the same "update the helpers first, then Alice" step.

## Deferred to W6+

- **W6-W7, on demand**: RDP deployment (`win_rdp`), WinRM transport.
- **Deferred by W5**: the farm layout (a CCS folder on a share of another server, the file server as the target, links
  across targets, the share-to-folder resolution; Ruling 3); creating a CCS file for an IIS CCS binding that has none
  (Ruling 7); removing or clearing the CCS password; a CCS whose password Alice's rule refuses (Ruling 10);
  `win.ccs_shadows` (not needed: `hostnameport` wins, F17).
- **Carried from W2-W4, not decided in W5**: a third party's intermediate added after Alice's commit makes a redeploy
  answer `unchanged` with `win.chain_differs`; the emulator's slow-host fault and the abandoned-call marking it needs;
  deploying to a binding whose only problem is its key; IDN host headers in their U-label form; a manual "roll back
  this deployment" action; W3's deferred minors (the heal step may clear a chain for a DER still present in another
  store; no test of the `maxImports` trim of adopted entries; `cleanup.go` not split; the provider's plan check accepts
  duplicate candidates; `UpdateTarget` writes `certificate_cleanup` back on every edit; a skipped incident place queues
  one extra cleanup); W4's minors other than the two closed in W5 (the helper version literal sites and the numeric
  case of `TestReleasedHelperVersion`); not built in W4 (a real-Windows ARM64 leg, `ci.yml` checks required, a Windows
  gate in `make release-gates`, a `merge_group` trigger, removing intermediates from `CA`, a cleanup history page).
- **Minors deferred during W5 (known debt)**:
  - `ValidCCSPath` accepts an empty segment (`C:\a\\b`) — the path comes from the registry only (Task 1); a trailing
    dot or space is refused since the final review (M3).
  - `CCSHost` maps a literal `*.example.com.pfx` to `*.example.com` — unreachable on NTFS (Task 1).
  - A test uses an all-zero 8-digit operation instead of a UUID in the temporary-file case (Task 1).
  - The reparse-folder check on a restore runs before the gate, not just before `RestoreCCS` (a time-of-check gap, as
    in W2's planning design; Task 3).
  - `SetCCSPassword` checks the password rule before the target's type, so a bad password on an Nginx target is 422,
    not 409 (Task 6).
  - The database does not tie a `win_ccs` credential to a Windows target; inventory checks it on write and read
    (accepted, Ruling 1).
  - The emulator's `ReadCCS` with a negative limit would panic (unreachable); the model has no way to delete a CCS
    folder or file (Task 4).
  - The emulator serves a third party's `PutRawCCSFile` at once, where real IIS would not without a refresh
    (deliberate); its `RestoreCCS` spelling rule is unmeasured; it answers `not_a_pfx` for a certificates-only PFX
    where Windows answers `key_missing` (Task 5).
  - `ccsDir` checks the leaf folder only; a parent junction is followed (Task 5 ruling).
  - The real fixture adopts a pre-existing `ccs:45480` record on a dirty runner (Task 5).
  - The web's `win_ccs_enabled` text stays after the password is set; a busy double submit of the password panel is
    possible (nil risk, per the review); the deploy dialog's summary follows the opening location's
    kind; "Select all bindings of this certificate" also selects CCS files (Task 8).
  - A cut `iis-dump` site list may leave a partial-site `win_ccs_unlinked` warning (W5-9) — closed by final review I1.
  - `internal/inventory/drift_observe.go` builds the location to probe without its stored warnings (line 151, the
    `IsFile` branch), so a cut CCS file with no servers is drift-observed as skipped where a deployment would end
    `verify_unreachable` (final review I1). Read-only: the drift view understates. Found by the re-review of
    `e0752599..1682b186` after the main gate had started; carried to the next small batch (coordinator ruling).

# W6 (R69)

Phase W6 (Remote Desktop certificate) was built on branch `windows-w6` from the plan
`docs/superpowers/plans/2026-10-28-windows-w6-rdp.md` (8 tasks), approved by the owner on 2026-10-28. Spec: R69 in
`docs/superpowers/specs/alice-v1/00-decisions.md`, `03-integrations.md` §13A.18-13A.19, `04-security.md` §14.4
(WN-23..WN-25), `06-quality.md` §24.7 (WIN-56..WIN-64), design §13 W6, §14 (F19-F23) and §21. One migration, `00037`;
error codes `ALC-WIN-0021`..`ALC-WIN-0023`. None of the rulings below is a pricing decision; the ones the owner should
confirm or act on are listed under [Owner items (W6)](#owner-items-w6).

## The plan's rulings as built (W6)

The plan's 28 rulings stand as written, except where an entry says "Amended" or "Precision".

1. **Decision R69; one migration, `00037`.** As written: `00037_windows_rdp.sql` widens
   `certificate_locations_kind_check` and `deployments_location_kind_check` with `win_rdp`; its Down restores 00036's
   lists and refuses with SQLSTATE `Z1035` while a `win_rdp` location or deployment exists.
2. **Helper 1.2.0, protocol 1, `RDPMinVersion` 1.2.0; two new subcommands and one flag.** As written: every site that
   asserted the helper's own version reads `1.2.0` (Task 1), and the four tests that used `rdp-deploy` as an unknown
   subcommand use `winrm-deploy`. Precision (Task 6): `win_rdp_helper_outdated` is added for every helper below 1.2.0,
   1.0.0 included (Ruling 2 read literally).
3. **One location per server: the `RDP-Tcp` listener.** As written. Precision (Task 6): a listener port outside
   1-65535 leaves the `win_rdp` location out with `locations_dropped` (W2 Ruling 18: nothing marked missing).
   **Amended (final review I1):** the locator is `{"type":"rdp","listener":"RDP-Tcp"}`; the port is the detail
   `port`, refreshed by every scan. Why: a port in the stored locator froze the location after a port change
   (`locatorConflict` skipped every later scan, so the details, the certificate and the verified port stayed old),
   and fixing it after a release would need a data migration.
4. **The listener's current certificate and the token.** As written; F19 confirmed that the certificate served while
   the value is absent is the single certificate of `Remote Desktop`. Precision (pre-flight): `rdp-deploy` with none
   or two self-signed certificates and the value absent answers `HASH_MISMATCH` (no token can match).
5. **Effective settings are read the way Windows applies them.** As written. Precision (Task 6): `win_rdp_autoenroll`
   is stored as a location warning (Task 5's carry).
6. **The store of an RDP import: always `LocalMachine\My`.** As written; F20 confirmed it: a certificate only in
   `Remote Desktop` is not served when named.
7. **W3 cleanup and RDP.** As written. `TestWindowsRDPSharedCertificateCleanup` and `TestRealRDPSharedWithBinding`
   cover the kept certificate.
8. **`rdp-deploy` input.** As written (`TestRDPDeployInputHasNoLocator`).
9. **`rdp-deploy` transaction.** As written, with the order changes of the Task 2 rulings below: the journal goes
   `writing` before the grant when `key_read_had` is false, and step 7 deletes and sets a value the listener already
   holds (Ruling 14 amended).
10. **The NETWORK SERVICE key grant.** **Amended (F21, Task 2 review I1, Task 4 review Minors 1, 2 and 6):** the grant
    writes the mask the KSP stores for `GENERIC_READ`, `0x80120089`, with flags 0, before the first inherited ACE; it
    is read back, and a grant the KSP merged into another ACE is undone and fails the grant. The revoke removes only
    non-inherited access-allowed ACEs for S-1-5-20 with flags 0 and that exact mask (deny ACEs, other masks, other
    trustees and inherited ACEs stay), then reads the key again: a key NETWORK SERVICE can still read, or whose read
    fails, sets `rdp_key_acl_left`. "Can read" stays an allow ACE for S-1-5-20 or S-1-1-0 with `GENERIC_READ` or
    `GENERIC_ALL`. **Amended (security review I1):** a copy of the new certificate already in `My` whose key is
    exportable, or whose export policy the helper cannot read, is refused with `KEY_UNUSABLE` before the gate
    (nothing changed), so NETWORK SERVICE is never given access to an exportable key.
11. **Rollback through `iis-restore` on an RDP journal.** **Amended (Task 2):** a committed journal over an absent
    previous value answers `restored` (not `SUPERSEDED`) when a third party deleted the value. The revoke does not run
    on `restore_failed` `io`/`read_back`, on `BACKUP_MISSING` or on `restore_forbidden`. An interrupted journal whose
    listener names neither certificate revokes the grant, then ends `restore_failed` `file_changed`.
12. **Recovery after a reboot or a kill.** **Amended (Task 2):** the journal goes `writing` before the grant when
    `key_read_had` is false, so a kill after the grant is rolled back and revoked; a kill right after `prepared` answers
    `prepared` and the engine fences it, as in W2.
13. **Journal shape.** **Amended (Task 2, Ruling 14 fix):** `KeyReadHad` may be nil in `prepared` or `restored`;
    `rdp.rebuild` is valid only in an RDP journal, never in `prepared`, never over an absent previous value, and only
    when `previous_sha1` equals `new_sha1`.
14. **Unchanged.** **Amended (F20):** the unchanged rule stands; when it does not hold and the listener already names
    the new SHA-1, `set_listener` deletes the value and sets it again, because a same-value write does not rebuild
    the served chain (Task 2 rulings below).
15. **The RDP probe mode.** As written; F22 confirmed the bytes and F23 that the probe needs no credentials.
16. **Verification endpoints of a `win_rdp` location.** As written (`TestRDPEndpoints`,
    `TestRDPVerifyFallsBackToTheHelper`). **Amended (final review I1):** the port is `details.port` (the last
    scan's), not the locator's; the Administrator's verify port still replaces it.
17. **Pickup.** As written: `winproto.RDPPickupWait` stays 0 (F20 route (a), at most 17 ms; Task 4 ruling).
18. **Discovery call order.** As written (`TestDiscoverWithoutRDPIsW5`, `TestConvertRDP`).
19. **Engine and inventory sites.** As written (Task 5). Precision (Task 6): `rdp_key_acl_left` is logged as the step
    param `rdp_key_acl_left` `"true"` on the restore step, or on `grant_key_read` when the outcome has no restore step.
20. **Notices and e-mails.** As written (Task 5). **Amended (final review M1, security review M2):** the e-mails and
    the API name the store `Remote Desktop` of a self-signed previous certificate; the RDP rollback_failed and
    outcome_unknown texts say to delete `SSLCertificateSHA1Hash` when the previous certificate is in that store, and,
    when the operation gave NETWORK SERVICE read access (`rdp_key_granted` on the grant or restore step), that it
    should be removed once the listener no longer uses the certificate.
21. **Drift.** As written (`TestWindowsRDPDriftRepaired`, `TestDriftCauseRDP`).
22. **Interactions, unchanged.** As written.
23. **Emulator model.** As written (Task 3). The model keeps one "NETWORK SERVICE can read" flag per key (Ruling 23
    allows it).
24. **Test IDs and STRIDE.** As written: `WIN-56`..`WIN-64`, `WN-23`..`WN-25`.
25. **e2e.** As written: `web/e2e/windows-rdp.spec.ts`, EN and TR.
26. **Runner hygiene and budget.** As written. Precision (coordinator): the fixture may start a stopped TermService
    and stop it again; it never restarts a running one, and it changes no firewall rule. It was not needed: both
    images ship RDP on.
27. **The dedicated security review.** Task 8 step 6; see [Security review (W6)](#security-review-w6).
28. **"Deferred to W6+": settled or carried.** As written; see [Deferred to W7+](#deferred-to-w7).

## W6 facts measured on real runners

Runs of `.github/workflows/windows.yml` (windows-2022 = Windows Server 2022 Datacenter, windows-2025 = Windows Server
2025 Datacenter). Each verdict holds on both images.

- **F19: confirmed.** Runs 1-3 (<https://github.com/erenmeren/alice/actions/runs/40644188468>, <https://github.com/erenmeren/alice/actions/runs/40648774432>). Both images ship RDP on: `fDenyTSConnections` 0, TermService running (start Manual, account NetworkService), port 3389, `SecurityLayer` 2, `UserAuthentication` 1, `SSLCertificateSHA1Hash` absent, the policy key holding only `KeepAliveEnable`/`KeepAliveInterval`. The firewall is on and the Remote Desktop rules are enabled; the tests changed neither. `fDenyTSConnections` 1 stops the listener within 3-255 ms and 0 brings it back within 255 ms, with no restart. `Remote Desktop` holds one certificate, and the listener serves it while the value is absent (Ruling 4 stands). The fixture's TermService start path was not needed on either image.
- **F20: route (a).** Runs 1-3. A raw write of the value is served at the next fresh handshake after 6-17 ms, and a delete serves the self-signed certificate again after 7-14 ms. The served chain equals `built_chain_length` (2). `Win32_TSGeneralSetting.SSLCertificateSHA1Hash` reports the named hash (`SSLCertificateSHA1HashType` 3, `CertificateName` the subject) and the self-signed one (type 1) while the value is absent. A certificate only in `Remote Desktop` is not served when named; the self-signed one stays, so Ruling 6 (always My) stands.
- **F21: confirmed, with the measured stored mask.** Runs 1-2 (<https://github.com/erenmeren/alice/actions/runs/40644188468>, <https://github.com/erenmeren/alice/actions/runs/40646627907>). With F4's DACL (`D:P(A;OICI;0xd01f01ff;;;SY)(A;OICI;0xd01f01ff;;;BA)`, verified on both images) TermService resets the connection, and Schannel logs 36870 (0x8009030D, `svchost[TermService]`). After the grant the certificate is served within 10-12 ms, without a rewrite. `GENERIC_READ` is enough, but the Microsoft Software KSP stores it as `0x80120089` (`GENERIC_READ` plus `FILE_GENERIC_READ`). The KSP also normalises a written `0x1` to `0x80000001` and, in run 1, merged a new NETWORK SERVICE allow ACE into an existing one. The key stays not exportable.
- **F22: confirmed.** Runs 1-3. The Connection Confirm is 19 bytes, `03 00 00 13 0e d0 00 00 12 34 00 02 <flags> 08 00 02 00 00 00`, with flags `0x1f`, `0x2f` or `0x0f` (they vary by image and NLA). It carries `RDP_NEG_RSP` with `selectedProtocol` 2 (HYBRID) for this request, with NLA on and off, and a TLS ClientHello then completes. `helperproto.RDPNegotiate` accepts every measured answer unchanged. `SecurityLayer` 0 was not measured, because the tests never write it (Global Constraints); the emulator-side tests cover `RDP_NEG_FAILURE`.
- **F23: confirmed.** Runs 1-3. With `UserAuthentication` 1, the TLS handshake completes before CredSSP, and ten probes leave no Security 4625 or 4740 event. The Logon subcategory audits Success and Failure on both images, so the absence is meaningful.

The coordinator accepted F19, F21, F22 and F23, and F20 route (a); for F20's same-value rewrite it chose option (a)
of Task 4's report (Ruling 14 amended, below).

### Runner runs used (8 of 8)

| Run | windows.yml | Head | windows-2022 / windows-2025 | What it found |
|---|---|---|---|---|
| 1 | <https://github.com/erenmeren/alice/actions/runs/40644188468> | `90c2c8cf` | fail / fail | Only `TestRealRDPKeyReadForNetworkService` failed (both images alike). F19: RDP already on (`fDenyTSConnections` 0, TermService running, manual, as NetworkService), port 3389, `SecurityLayer` 2, NLA 1, policy key holds only `KeepAliveEnable`/`KeepAliveInterval`, one certificate in `Remote Desktop`, served while the value is absent. F20: `rdp-deploy` served after 10-13 ms, the delete after 6-17 ms; served chain 2 = `built_chain_length` 2; a same-value rewrite does not rebuild the served chain (20 s); a certificate only in `Remote Desktop` is not served when named (the self-signed one is). F21: without the grant the handshake is reset (Schannel 36870, 0x8009030D, `svchost[TermService]`); after the grant it is served at once; the KSP stores `GENERIC_READ` as `0x80120089`, so the revoke's exact-mask match found nothing; it also normalises a written `0x1` to `0x80000001` and merges a new NETWORK SERVICE allow ACE into an existing one. F22: 19-byte confirm, `RDP_NEG_RSP`, `selectedProtocol` 2 with NLA on and off. F23: 0 events 4625 after ten probes (Logon auditing on). `TestRealRDPSharedWithBinding` and `TestRealRunnerIsClean` passed |
| 2 | <https://github.com/erenmeren/alice/actions/runs/40646627907> | `2e7415c1` | fail / fail | Only `TestFidelityRDP` failed, on its own assertions (it read the error code from `error`, not `code`; it restored an older operation after a newer one, which both hosts answer `SUPERSEDED`): every answer compared equal on both hosts. F21 fixed: the grant stored as `(A;;0x80120089;;;NS)`, the revoke gives F4's DACL back byte for byte; a NETWORK SERVICE deny ACE, another trustee's allow ACE and a NETWORK SERVICE `DELETE` allow ACE survive grant and revoke (no merge with a `DELETE` ACE). F19: `fDenyTSConnections` 1 stops the listener within 3-253 ms, 0 brings it back within 255 ms, no restart. F20: a delete then set of the value rebuilds the served chain (2 after 9-10 ms); a same-value rewrite still does not (20 s) |
| 3 | <https://github.com/erenmeren/alice/actions/runs/40648774432> | `8d668f06` | **pass / pass** | `windows-required` green; every RDP real test and `TestFidelityRDP` pass on both images; F19-F23 as in run 2 (pickups 7-15 ms) |
| 4 | <https://github.com/erenmeren/alice/actions/runs/40667566229> | `98e265c5` | **pass / pass** | The code head after the final review fixes. `windows-required` green; every RDP real test (with the exportable-key refusal in `TestRealRDPKeyReadForNetworkService`), the DACL bounds test, `TestFidelityRDP` and `TestRealRunnerIsClean` pass on both images |
| 5 | <https://github.com/erenmeren/alice/actions/runs/40671263696> | `ad9b7ee4` | **pass / pass** | After the flaky-test fix `f229223e` (a Windows-paths change): `windows-required` green, every RDP real test and `TestFidelityRDP` pass on both images |
| 6 | <https://github.com/erenmeren/alice/actions/runs/40673844653> | `5a1b0a59` | **pass / pass** | After the go-jose bump `e656143d` (`go.mod` is a Windows path): `windows-required` green on both images |
| 7 | <https://github.com/erenmeren/alice/actions/runs/40685266649> | `b2c730c4` | **pass / pass** | A documents-only push (the final gates record). The Windows legs ran anyway: a branch push is diffed against `main`, not against its previous push, so every push of a branch that touches a Windows path spends a run. `windows-required` green |
| 8 | <https://github.com/erenmeren/alice/actions/runs/40697994891> | `2d86c053` | **pass / pass** | After the coordinator review's four fixes (`a01fc50f`, `21111254`, `fd6ef31e`, `55d78795`, `2d86c053`): `windows-required` green; the new `systemCanRead` bound runs in every real test that dumps a store |

## Rulings made during execution (W6)

One line each: the ruling, then why (and the cost if wrong where it is not obvious).

### Controller (order and process)

- P1 (pre-flight): the tasks run in the order 1-8; runner run 1 was pushed during Task 4, once its real tests were
  written, not right after Task 2 — Task 2's code alone has no real RDP test to run (cost: a little wall time).
- P2 (pre-flight, Ruling 4): `rdp-deploy` with none or two self-signed certificates and the value absent answers
  `HASH_MISMATCH`, as Task 2's test list says — no token can match (cost: low).
- P3: Tasks 3, 4 and 5 ran in parallel on the coordinator's instruction (it overrides the one-implementer rule);
  their paths are disjoint and each committed only its own paths — cost: possible transient build breaks.
- P4: Task 6 started (base `319ff83a`) while Task 4's runner run 1 was in flight, reading `RDPPickupWait` as a
  constant — W5 precedent; cost: a follow-up if F20 or F23 changed provider behaviour (none did).
- P5: Task 6's commit `14ae89b1` carried the trailer "Claude Opus 5.5"; it was not yet pushed, so the controller
  amended its message only (`3c5d2403`, same tree).
- P6: Task 7 was split: 7a (web and e2e) ran while Task 4 ran; 7b (these documents) ran after Task 4's F19-F23
  verdicts, in parallel with 7a's finish on disjoint paths (`docs/`, `CHANGELOG.md`, `test/matrix` against `web/`,
  `api/openapi.yaml`, `cmd/alice-fakewindows`) — the documents need the facts (cost: two commits).

### Coordinator

- C1 (F19): the fixture may start a stopped TermService (recorded, stopped again in Cleanup), never restart a running
  one; it records the firewall state and changes no rule. The F19 fallback applies only if RDP cannot answer on
  `127.0.0.1` on both images after that.
- C2 (F20): the test logs the pickup delay in ms, the served chain length, and whether a same-value rewrite rebuilds
  the served chain (Ruling 14). Route (b) would have stopped for a coordinator decision.
- C3 (F21): a handshake that works without the grant on either image would have stopped for a decision, with the
  SDDL as imported and TermService's account.
- C4: the review gates of Tasks 2, 4, 5 and 6 use a reviewer who is not the implementer, with the Review Focus and the
  commit range; each finding and its fix commit are recorded here.
- C5: each runner run is recorded in the run table as soon as it is read.

### Task 1 (winproto, helperproto, tlsverify)

No ruling. Two minors were deferred (see [Deferred to W7+](#deferred-to-w7)).

### Review gate (Task 1)

The review of `a005c6ae..87d74673` found 0 critical, 0 important and 2 minor issues; both were deferred: tlsverify's
RDP negotiation honours the context only through the connection deadline (at most 10 s), and only `RDPFailure(2)`
maps to `ErrRDPNoTLS` (to revisit with F22's measured codes; F22 measured no failure, because `SecurityLayer` 0 is
never written on a runner).

### Task 2 (winhelper)

- **The key revoke removes only the grant's own ACE (amends Ruling 10, review I1).** `SetRDPKeyRead(..., false)` removes only non-inherited access-allowed ACEs for S-1-5-20 whose mask equals the grant's mask exactly (`GENERIC_READ`, or the mask F21 measures). Deny ACEs, other masks, other trustees, the owner, the group and the SACL stay unchanged. Why: `key_read_had` false only means "no allow ACE with the read bits". Removing every non-inherited NETWORK SERVICE ACE would also delete ACEs the operation never added, including a deny ACE, and widen the key's access past where it started.
- **The journal goes `writing` before the grant when `key_read_had` is false (amends Ruling 12).** `key_read_had` false and phase `writing` are written before `SetRDPKeyRead(grant)`. A kill after the grant then leaves an operation that `iis-restore` rolls back and revokes. A kill right after `prepared` (before any grant) answers `prepared`, and the engine fences it, as in W2. Why: `iis-fence` tombstones only `prepared` journals, and `iis-restore` answers `prepared` without acting. A grant under a `prepared` journal could therefore leave an ACE whose record the tombstone erases.
- **`KeyReadHad` may be nil in `prepared` or `restored` (amends Ruling 13).** Why: a failed `import_chain`, a failed `import_certificate` or a failed `RDPKeyRead` read ends `restored` before the grant step knew the field.
- **A committed journal over an absent previous value answers `restored` when a third party deleted the value (amends Ruling 11).** It does not answer `SUPERSEDED`. Why: W2's rule that a listener already on the previous certificate counts as done applies, and the grant is revoked because the listener no longer uses the key. The machine ends in the same state either way; only the engine's label differs.
- **`rdp_key_acl_left` travels as a response flag.** It is `RDPKeyACLLeft` on `DeployResponse` and `RestoreResponse`, following W5's `ccs_refresh_failed` pattern. Task 6 maps it onto the restore step's param `rdp_key_acl_left`. Why: `winproto.Step` has no params.
- **The revoke does not run on `restore_failed` `io`/`read_back`, on `BACKUP_MISSING` or on `restore_forbidden`.** Why: the listener names, or may name, the new certificate, so revoking would break RDP. A later successful restore revokes.
- **Ruling 14 amended (F20): `set_listener` deletes and then sets a value the listener already holds.** This happens when the listener names the new SHA-1 but the unchanged rule does not hold (the key was unreadable, an intermediate was added, or another chain is recorded). The step makes two `SetRDPCertificate` calls, `""` and then the SHA-1. A value that differs is still one set. The `writing` journal records `rdp.rebuild` true before the delete. While the operation is not `committed`, a restore reads an absent value as this operation's interrupted rebuild: it sets the previous value back (here the same SHA-1), with the guard, the read-back and the Ruling 10 revoke when `key_read_had` is false, and `iis-status` names the new leaf (`rdpNamesNew`). Once `committed`, an absent value was deleted by someone else: the status names no leaf and the restore answers `SUPERSEDED`. `valid` refuses `rebuild` over an absent previous value and in `prepared`; `rebuild` exists only in an RDP journal. Why: on the runners a same-value rewrite never makes Schannel rebuild the served chain (an added intermediate stays unsent after 20 s), and deleting then setting the value rebuilds it within about 10 ms, with about 10 ms of the self-signed certificate in between (run 3: <https://github.com/erenmeren/alice/actions/runs/40648774432>). Accepted edge (rebuild review Minor 3): an interrupted rebuild killed after the set, whose value a third party then deletes, is read as the interrupted delete; the restore writes the pre-operation value back instead of answering `file_changed`. The two cannot be told apart without one more journal write, and the result is the value the listener had before the operation.
- **A rebuild journal names the same certificate before and after (rebuild review Minor 1).** `valid` refuses `rdp.rebuild` unless `previous_sha1` equals `new_sha1`. Why: `runRDP` sets it only then, and a restore over an absent value must never write a certificate this operation did not find on the listener.
- **Only an interrupted phase reads an absent value as this rebuild's (rebuild review Minor 4).** `rdpNamesNew` excludes `committed` and `restored`. Why: after either, an absent value was deleted by someone else, so `iis-status` must not name the new leaf.
- **A revoke that leaves NETWORK SERVICE able to read the key is never silent (Task 4 review Minor 2, Ruling 27).** After the revoke (on a restore, and on the take-back of a failed grant), `revokeKeyRead` reads the key again. If `RDPKeyRead` still answers readable, or cannot answer, for a key whose journal says `key_read_had` false, `ACLLeft` is set and answered as `rdp_key_acl_left`. Why: the KSP can merge the grant into an existing NETWORK SERVICE ACE (F21). The exact-mask revoke then finishes without error but cannot take the merge apart.
- **A restore after a kill between the rebuild's delete and set puts the previous value back (rebuild review).** The
  value is set back, and the ACE is revoked when `key_read_had` is false. Why: that is the state before the
  deployment (Ruling 10); intended, no cost.
- **A failed `RDPKeyRead` after a successful revoke is reported as `rdp_key_acl_left` (fix round 3).** Why: unknown
  counts as left, never silent. Cost: a false "left" note after a rare read failure.

### Review gate (Task 2)

The review of `87d74673..cabd6323` found 0 critical, 1 important and 5 minor issues. All were fixed in this commit:
- I1: a revoke removed NETWORK SERVICE ACEs the operation did not add. Fixed by the tightened `SetRDPKeyRead` contract (`write.go`), the fake's per-key ACE list and `TestRDPRevokeKeepsOtherACEs`.
- M1: the Ruling 12 and 13 deviations are recorded above.
- M2: an existing-copy kill variant at `rdp.granted` and `rdp.grant_key_read` (`TestRDPKillOverAnExistingCopy`).
- M3: the key methods refuse any store other than My (the contract, the fake, `TestRDPKeyMethodsRefuseOtherStores`).
- M4: the Ruling 11 amendment is recorded above.
- M5: `parseDeployFields` computes the canonical text from the locator only when there is one.

### Review gate (Ruling 14 fix)

The review of `d397372e` (the rebuild) found 0 critical, 0 important and 4 minor issues. All were fixed or recorded in this commit:
- Minor 1: `valid` requires `previous_sha1` = `new_sha1` for a rebuild (one new journal case in `TestRDPRebuild`).
- Minor 2: `TestRDPRebuildKillPoints` covers `rdp.writing`, `rdp.deleted`, `rdp.set` and `rdp.read_back`, for both `key_read_had` values.
- Minor 3: accepted, and recorded in the Ruling 14 amendment.
- Minor 4: `rdpNamesNew` excludes `restored`.

### Review gate (Task 2 fix round 3)

The re-review of `40ee756b..2cebc837` (the rebuild review's Minors 1, 2 and 4 and Task 4 review Minor 2) found every
item addressed and none open. Two minors were deferred: one long comment line in `write.go`, and the take-back of a
failed grant may report `rdp_key_acl_left` after a read error (the ruling above).

### Task 3 (wintest and cmd/alice-fakewindows)

No ruling. Task 3's commit `cb90a58e` landed after Task 4's `90c2c8cf` (parallel tasks, P3).

### Review gate (Task 3)

The review of `cb90a58e` approved it with 0 critical, 0 important and 5 minor issues, all deferred (see
[Deferred to W7+](#deferred-to-w7)). `golangci-lint` of `wintest` and `cmd/alice-fakewindows` reported 0 issues at
`319ff83a`; the forbidigo report seen during Task 5 was against files still being written.

### Task 4 (alice-winhelper, the real RDP half)

- **The grant writes `0x80120089`, and a revoke removes exactly that mask (F21, applies "the measured mask is used").** Why: the KSP stores a written `GENERIC_READ` as `0x80120089`, so in run 1 (<https://github.com/erenmeren/alice/actions/runs/40644188468>) the exact-mask revoke found nothing and the ACE stayed. With the stored form written, run 2 (<https://github.com/erenmeren/alice/actions/runs/40646627907>) gives F4's DACL back byte for byte. "Can read" stays "an allow ACE for NETWORK SERVICE or Everyone with `GENERIC_READ` or `GENERIC_ALL`", which matches the stored form.
- **A grant is read back; if the KSP does not keep it as one ACE of its own, the DACL as it was is written back and the grant fails (`errKeyMerged`, then `restored` with `key_acl`).** Why: run 1 (<https://github.com/erenmeren/alice/actions/runs/40644188468>) showed the KSP merging a new NETWORK SERVICE allow ACE into an existing one, which no revoke could take back alone. That would break Ruling 10's "only the grant's own ACE". Run 2 (<https://github.com/erenmeren/alice/actions/runs/40646627907>) shows that a deny ACE, another trustee's ACE and a NETWORK SERVICE `DELETE` allow ACE all survive grant and revoke, with no merge.
- **The ACE is built with `windows.ACLFromEntries` alone and spliced into the DACL bytes. It is never merged by `SetEntriesInAcl`.** Why: `GRANT_ACCESS` merging would fold the grant into (or change) an ACE the trustee already has, against the contract in `write.go`. `ToAbsolute` keeps the descriptor's control bits, so the DACL stays protected (`D:P`).
- **`winproto.RDPPickupWait` stays 0 (F20 route (a)).** Why: the measured maximum is 17 ms (runs 1-3). Its +50 % (26 ms) would not change `verifyAttempts`, because `pickupAttempts` keeps the provider's attempts. This is W5's precedent for `CCSPickupWait` (8-12 ms, kept 0), and `winproto_test.go` (Task 1) asserts 0.
- **Coordinator to decide: Ruling 14's same-value write does not rebuild the served chain (F20).** In runs 1-3, adding the leaf's intermediate to `CA` and rewriting the same value still serves a chain of 1 after 20 s. Deleting the value and setting it again serves the full chain within 9-11 ms, with about 10 ms of self-signed fallback in between. So Ruling 14's "write even when it is the same" does not make an added intermediate reach the client. Options: (a) when an intermediate was added, `set_listener` deletes and then sets the value; (b) keep the rewrite and let the verification report `win.chain_differs`; (c) the unchanged rule ignores intermediates for RDP. Recommendation: (a). Decided: (a), see the Ruling 14 amendment under Task 2.
- **`TestFidelityRDP` compares the hosts as F19 found the runner.** The model gets the runner's self-signed certificate without its key, so its dump entry is the real one once DER and hashes match. `RDP_TLS_OFF` and `BINDING_NOT_FOUND` are not produced on a runner (`SecurityLayer` and the key are never written). Run 3 (<https://github.com/erenmeren/alice/actions/runs/40648774432>) found no fidelity difference, so the emulator needed no fix.
- **Residual, for the security review: if the KSP merges the grant and the write-back of the old DACL also fails, a
  merged NETWORK SERVICE ACE stays and the grant fails `key_acl`.** Not observed on the runners. Since Task 2's fix
  round 3 the take-back reads the key again and reports `rdp_key_acl_left` (`TestRDPMergedGrantIsNeverSilent`), so it
  is never silent. Cost: a NETWORK SERVICE read ACE left on that key.
- **Task 4 review: Minors 1, 3, 4, 5 and 6 fixed in a Task 4 fix round; Minor 2 routed to Task 2's restore code.**
  Why: they are security-relevant and cheap.

### Review gate (Task 4)

The review of `49630752..11ddde52` (Task 4 paths) found 0 critical, 0 important and 6 minor issues. The minors were fixed in `2da81ba8`, except Minor 2:
- Minor 1: the revoke matched any non-inherited ACE. It now matches the grant's own flags (0), so an inherit-only NETWORK SERVICE ACE of the same mask is kept. The `write.go` contract says "flags 0".
- Minor 2: if the grant's merge write-back also failed, an unrecorded NETWORK SERVICE read could remain. Not fixed here: it belongs to Task 2's restore code, and is carried to the Task 8 security review (Ruling 27).
  Fixed in Task 2's fix round 3 (`2cebc837`): the revoke is verified by `RDPKeyRead`, and a key that is still readable sets `rdp_key_acl_left` (`TestRDPMergedGrantIsNeverSilent`).
- Minor 3: the F21 test now asserts that a key the helper imported has F4's DACL.
- Minor 4: `TestFidelityRDP` now also compares UNKNOWN_OP (and `iis-status` of an unknown op), SUPERSEDED asserted by code, and a deployment whose restore is `restore_forbidden`. The file comment names why the input refusals and BUSY are not compared.
- Minor 5: the fidelity normalisation copies only the self-signed entry's key facts from the real answer. Every other field is compared, and the model is given the certificate's friendly name.
- Minor 6: the grant goes before the first inherited ACE (canonical order), with the read-back expecting that place. The self-relative descriptor minimum is 20 bytes. `TestRealRunnerIsClean` asserts TermService as the first fixture found it.

These are verified locally only (builds, vet, lint, archtest). The next runner run covers them.

### Task 5 (migration, inventory, API, e-mails)

No ruling. Carried to Task 6: log `rdp_key_acl_left` `"true"` on the restore step's params, and store
`win_rdp_autoenroll` as a location warning (both done). Carried to Task 7: the web labels for `win_rdp`, the step
names and the codes (`enums.test.ts`).

### Review gate (Task 5)

The review of `319ff83a` approved it with 0 critical, 0 important and 3 minor issues, all deferred (see
[Deferred to W7+](#deferred-to-w7)); the e-mail minor is also an owner item.

### Task 6 (Windows provider and engine tests)

- **`TestWindowsRDPKeyACLFails` ends `rolled_back` (not `failed`, as the plan's brief said)** with reason
  `windows.rdp_key_acl_failed`, `failed_step` `grant_key_read` and the listener untouched. Why: the helper answers
  `restored`, and every W2 and W5 `restored` answer is `rolled_back`; a special case would break the pattern. Cost:
  the owner reads "rolled back" for a deployment that never touched the listener.
- **A listener port outside 1-65535 leaves the `win_rdp` location out with `locations_dropped`.** Why: W2 Ruling 18
  (nothing marked missing). Cost: none in practice.
- **`win_rdp_helper_outdated` for every helper below 1.2.0, 1.0.0 included.** Why: Ruling 2 read literally. Cost: one
  more warning on very old helpers.
- **`rdp_key_acl_left` goes on the `grant_key_read` step when the outcome has no restore step** (the take-back of a
  failed grant). Why: that step is where the ACE was left. Cost: the UI and e-mail show it on another step row.

### Review gate (Task 6)

The review of `2e7415c1..3c5d2403` approved it with 0 critical, 0 important and 6 minor issues: one settled by the
`grant_key_read` ruling above, five deferred (see [Deferred to W7+](#deferred-to-w7)).

### Task 7 (web, e2e and documents)

- **The manual matrix no longer lists "an RDP listener with its own certificate"** (W3's item; release checklist row
  8.5, WIN-45, the admin guide's "What is tested on real Windows"). Why: Ruling 26 settles it on the runners
  (`TestRealRDPSharedWithBinding`, WIN-63, both images). Row 8.5 stays numbered, marked as no longer a hand check.

- **Every test the plan's WIN-56..WIN-64 table names exists under that exact name**, so `test/matrix/traceability.json`
  maps each row to the plan's tests with no substitution. The short package names of the table resolve to
  `internal/providers/windows` (`windows:`), `internal/providers/windows/winhelper` (`winhelper:`),
  `internal/jobs/deployjobs` (`deployjobs:`), `internal/inventory`, `internal/providers/linuxssh/helperproto`,
  `internal/providers/tlsverify`, `cmd/alice-winhelper` and `internal/providers/windows/winproto`; WIN-64 maps to the
  journey's test title in `web/e2e/windows-rdp.spec.ts`. Why: `make matrix-check` resolves each name.
- **The §24.7 rows keep the section's columns.** The plan's table gave the case and the tests; the rows carry the
  case verbatim and an expected behaviour written from the rulings as built, and the tests live in the traceability
  map. Why: §24.7's columns are the case and the expected behaviour.

### Review gate (Task 7b)

The review of `2cebc837..afbef83f` (the documents) approved it with 0 critical, 0 important and 6 minor issues.
Minors 1-5 were fixed in the next docs commit:
- Minor 1: 13A.19 put the unchanged rule among the refusals; it now follows `grant_key_read` and says the listener
  and the key do not change, while the journal and the binding record are written.
- Minor 2: the admin guide says each deployment is event 1005 and a restore 1002.
- Minor 3: the troubleshooting entry uses the status label **Succeeded**.
- Minor 4: "Windows makes a new one if it was removed" is marked as not measured in 13A.19 and the host guide (owner
  item 6 keeps it).
- Minor 5: the manual matrix's RDP item is removed (the Task 7 ruling above).
- Minor 6: `docs/security/traceability.md` is the generator's output; no change.

## Security review (W6)

Reviewer: a fresh reviewer who wrote none of the code (Ruling 27). Range `7432cfd5..edebc095`, read-only; nothing run
on Windows (the runner facts from runs 1-3). Counts: 0 critical, 1 important, 2 minor. Report:
`.superpowers/sdd/2026-10-28-windows-w6-rdp/security-review.md`.

Checklist verdicts:
1. **The ACE is exactly Ruling 10's; nothing else changes; parsing is bounds-safe:** the ACE and the rest of the
   descriptor pass; bounds safety was partial (M1).
2. **No input reaches a SID, a store, a key or a registry name:** pass; journal content selects which My key a
   restore revokes on, within the WN-24 envelope (an administrator's write to the journal directory; residual 6).
3. **Every restore path revokes this operation's grant when `key_read_had` is false, and only that grant:** pass,
   within the amended Rulings 10 and 11.
4. **A kill between the grant and the journal write cannot leave an unrecorded ACE:** pass.
5. **The key stays not exportable:** pass for Alice's imports; fail for an existing exportable copy (I1).

Findings:
- **I1, NETWORK SERVICE got read access to an existing, exportable key:** fixed in `5f903ecb` (`rdp-deploy` refuses
  such a copy, or one whose export policy cannot be read, with `KEY_UNUSABLE` before the gate; fake-host,
  fidelity and real tests; admin and host guides).
- **M1, the DACL parser trusted the KSP's offsets:** fixed in `434adcd7` (SE_SELF_RELATIVE required, the DACL and
  every ACE bounded inside the buffer; `TestCheckRelativeDACL`, `TestEachACEStaysInsideTheACL` on every Windows run).
- **M2, a failed or unknown restore left the grant without any notice:** fixed in `42ea6a51` (`rdp_key_granted`
  from the helper, through the step param, to a note on the RDP rollback_failed and outcome_unknown e-mails).

Residual risks for the owner:
1. WN-23 as accepted: every NETWORK SERVICE service can use the RDP key for TLS; the ACE stays after a later
   deployment replaces the certificate (cleanup removes it with Alice's import; a third party's copy keeps it).
2. An unrecoverable KSP merge (the write-back fails too) leaves a merged NS ACE, reported as `rdp_key_acl_left`;
   not observed on runners.
3. A DACL change by another administrator in the milliseconds between the grant's two reads is reverted.
4. A KSP that canonicalises a non-canonical DACL on the write-back may change it; the grant still fails closed.
5. The revoke removes every identical NS ACE (flags 0, mask `0x80120089`), also one an administrator added later.
6. Journal tampering (Administrators/SYSTEM write to `C:\ProgramData\Alice\helper\`) can make a restore revoke the
   exact ACE on another My key, set another usable certificate or delete the value; never a grant, another SID,
   store or registry path. The helper checks the directory's owner only.
7. "Can read" ignores deny ACEs and group membership: an NS deny with an Everyone allow reads as readable (RDP then
   fails verification and rolls back); a key readable through Users reads as not readable (a redundant ACE, revoked
   on rollback).
8. Not measured on runners: `SecurityLayer` 0, `RDP_NEG_FAILURE`, and whether `GENERIC_READ` lets NS export an
   exportable key (moot after I1's refusal).
9. A TermService account other than NETWORK SERVICE needs another trustee: verification fails and the deployment
   rolls back.

## Final review fixes (W6)

The independent final review of `7432cfd5..edebc095` (`.superpowers/sdd/2026-10-28-windows-w6-rdp/final-review.md`)
found 0 critical, 1 important and 5 minor issues ("ready to merge: with fixes").

- **I1, a change of the RDP port froze the `win_rdp` location:** fixed in `04cea854` (Rulings 3 and 16 amended: the
  port is `details.port`; `TestConvertRDP`, `TestRDPEndpoints`, `TestRDPPortChangeUpdatesTheLocation`).
- **M1, a self-signed previous certificate lost its store in the e-mails and the API; the RDP rollback_failed text
  gave the wrong recovery:** fixed in `42ea6a51` (`remote desktop` in `mailStoreRE` and `paramStoreRE`, the
  `SSLCertificateSHA1Hash` sentence in both RDP texts, EN and TR, `api/openapi.yaml`'s `backup_store` and
  `backup_sha1`). The web already showed the store.
- **M2, the shared `errors.windows.*` titles use the binding wording for RDP e-mails and API problems:** deferred
  (wording; the RDP note is appended and the web overrides; the next small batch can add `*_rdp` titles).
- **M3, a helper downgraded below 1.2.0 marks an existing `win_rdp` location missing:** deferred (rare; the row comes
  back on the next 1.2.0 scan; adding `locations_dropped` there would change W5 on every 1.1.0 server).
- **M4, the cleanup's protection depended on reading the whole listener:** fixed in `a13342b3` (a narrow read of
  `SSLCertificateSHA1Hash`; a bad hash value still fails the cleanup closed).
- **M5, `iis-status` names the previous leaf for an absent value even after Windows made a new self-signed
  certificate:** deferred (the outcome is right, `restored_unverified`; owner item 6 keeps the regeneration
  unmeasured).

Deferred-minor triage: of the 23 items, two were fixed with M1 (the RDP e-mails' self-signed store, the openapi
description), three carries were found done (the `rdp_key_acl_left` param, the web labels, the documents), and the
rest stay deferred as known debt (listed under [Deferred to W7+](#deferred-to-w7)).

The fix wave (`04cea854`, `5f903ecb`, `434adcd7`, `a13342b3`, `42ea6a51`, `98e265c5`) had one scoped re-review by a
reviewer that wrote none of it: all five items addressed, no new important finding. Two residual minors are parked
(no second fix wave): the admin guide's refusal sentences sit inside the deployment steps (`docs/admin-guide.md`
around 1536-1539), and the real exportable-key test asserts only the code `KEY_UNUSABLE`, which the older "no usable
key" refusal also answers (the winhelper fake test proves the new check's path).

After the fix wave, ci.yml run 40667566328 (`98e265c5`) found two failures:
- `go`: `TestDiscoverWithoutRDPIsW5` compared a CCS file's `modified_at` across two discoveries that straddled a
  second; fixed in `f229223e` (the field is dropped from both sides before the comparison).
- `secrets`: trivy reports `github.com/go-jose/go-jose/v4` v4.1.5, CVE-2026-116587 (HIGH, fixed in 4.1.6). The
  dependency is not W6's, but the vulnerability also stops the local `make ci` at `make vuln` (osv-scanner,
  GHSA-mgcc-cww5-fp2q) before the e2e, so the branch bumps it to v4.1.6 in its own commit `e656143d` (go.mod and
  go.sum only; the Windows helper's checksums are unchanged, so go-jose is not linked into it). The coordinator may
  take that commit to `main` on its own or drop it. The same job failed for the same reason on run 3's ci.yml
  (40648774421).

Found during W6 and not fixed (outside its scope): `systemCanRead` in `cmd/alice-winhelper/stores_windows.go` reads a
key's descriptor offsets without the bounds `434adcd7` added for the RDP grant (W1 code; fixed later by the
coordinator review, item 2); the deploy picker shows a raw `{{application}}` for the WinRM binding (seen by the web
implementer, pre-existing).

### Coordinator review (W6)

The coordinator's independent review of `7432cfd5..b7cb4db3` was "ready to merge" with four minors, each fixed in its
own commit:

1. **The exportable-key check on an existing copy in `My` ran before the gate:** a copy added with an exportable key
   after that check made `ImportPFX` answer `existed`, and the grant went on that key (security review I1's residual
   race). Fixed in `a01fc50f`: after the import, a copy that is not Alice's is read again, and an exportable key or an
   unreadable export policy ends `grant_key_read` `key_acl` before any ACE (`TestRDPDeployExportableCopyAfterCheck`).
2. **`systemCanRead` followed the key descriptor's DACL offset and `GetAce` without bounds** (W1 code): fixed in
   `21111254` (`checkRelativeDACL` before `IsValid`; a descriptor that fails it reads as unknown).
3. **The host-preparation guide named only an older chain as the reason for the delete-and-set rebuild:** fixed in
   `fd6ef31e` (a key access or chain change); the admin guide had the same sentence, fixed in `2d86c053`.
4. **Ruling 11 did not say what an interrupted `file_changed` restore does with the grant:** fixed in `55d78795` (it revokes
   the grant, then ends `restore_failed` `file_changed`).

Runner run 8 (`2d86c053`, the last of the budget) is green on windows-2022 and windows-2025 with `windows-required` green: <https://github.com/erenmeren/alice/actions/runs/40697994891>.

## Acceptance (design §13 W6)

- Location kind `win_rdp` for the RDP-Tcp listener (Tasks 5-6): **met**. Migration `00037` (Down `Z1035`), `providers.LocationWinRDP`, `convertRDP`, the locator `{"type":"rdp","listener":"RDP-Tcp"}` with the port in `details.port` (final review I1, `04cea854`); `TestConvertRDP`, `TestRDPPortChangeUpdatesTheLocation`, `TestDiscoverWithoutRDPIsW5`.
- Import as in §6.3 (Task 2, W2's code): **met**. `rdp-deploy` reuses `import_chain` and `import_certificate` (store `My`, Ruling 6); `TestRDPDeployCommits`; an existing copy whose key is exportable is refused before any change (security review I1, `5f903ecb`).
- Read on the key granted to NETWORK SERVICE (Tasks 2, 4; F21): **met**. One ACE `(A;;0x80120089;;;NS)` (the KSP's stored form of `GENERIC_READ`), inserted before the first inherited ACE, read back, revoked by every restore of its operation (exact mask, flags 0), never silent when left (`rdp_key_acl_left`); F4's DACL comes back byte for byte on both images (runs 2-4).
- The listener's hash set, `SSLCertificateSHA1Hash` (Tasks 2, 4; F20): **met**. Raw registry write, served in at most 17 ms (route (a), `RDPPickupWait` 0); a value the listener already holds is deleted then set so Schannel rebuilds the chain (Ruling 14 amended).
- Verified by a TLS handshake on 3389 after the RDP security-layer negotiation (Tasks 1, 6; F22, F23): **met**. `helperproto.RDPNegotiate`, `tlsverify.TLSProber{RDP: true}`, `tls-probe --rdp` as the fallback; no CredSSP, no event 4625 (F23).
- The key ACL's own review (Ruling 27): **met**. [Security review (W6)](#security-review-w6): 0 critical, 1 important (fixed), 2 minor (fixed); the final fix wave's re-review passed all five items.
- Real Windows: runner run 4 (`98e265c5`, the code head of the fix wave) green on windows-2022 and windows-2025 with `windows-required` green.
- Real Windows at the code head: runner run 6 (`5a1b0a59`, after the go-jose bump) green on both images with `windows-required` green; 7 of 8 runs used (run 7, a documents-only push at `b2c730c4`, is green too).
- Final gates (Task 8): `E2E_PROJECT=alice-e2e-w6 ALICE_E2E_PORT=9983 make ci` exit 0 at `5a1b0a59` (lint, test, coverage with every floor met: windows 98.8, winhelper 97.2, winproto 100, helperproto 100, tlsverify 98.9, wintest 97.6, alice-fakewindows 93.4, inventory 89.2; vuln, secrets-scan, fs-scan, e2e 169 passed, 4 skipped, 0 failed; image-check and image-scan). ci.yml run 40673844627 at `5a1b0a59` green in every job, `stack` included. `make matrix-check MATRIXCHECK_FLAGS=-strict`: 368 IDs, 0 gaps, 0 pending. The leak scan (dir mode over the patch of `7432cfd5..98e265c5`, `.gitleaks.toml`): no leaks found.

## Owner items (W6)

From the plan:

1. **Ruling 3:** only the `RDP-Tcp` listener is managed, one location per server; other WinStations, RD Gateway and
   the other RDS roles are not.
2. **Ruling 4:** an absent `SSLCertificateSHA1Hash` is a deployable location whose current certificate is Windows'
   self-signed one from `LocalMachine\Remote Desktop`; with none or several there, the location is not deployable
   (`win_rdp_cert_unknown`).
3. **Ruling 5:** RDP off or RDP security (no TLS) makes the location not deployable; Alice never turns RDP on or
   changes its security layer. An RDP autoenrolment policy is a warning, not a refusal.
4. **Ruling 6:** RDP certificates are always imported into `LocalMachine\My`.
5. **Ruling 10:** the exact grant: one access-allowed ACE for NETWORK SERVICE, with the mask F21 measured
   (`0x80120089`, the KSP's form of `GENERIC_READ`), on the RDP certificate's key only, revoked by every rollback of
   the operation that added it, removed with the key by cleanup. It is not revoked when a later deployment replaces
   the certificate, so a third party's certificate keeps it.
6. **Ruling 11:** a rollback of a first deployment deletes the value, and RDP goes back to its self-signed certificate
   (Windows makes a new one if it was removed).
7. **Ruling 2:** restore, status and fence of RDP operations reuse the `iis-*` subcommands by journal kind; `tls-probe`
   gains `--rdp`.
8. **Ruling 20:** three RDP e-mail texts of their own; every other RDP e-mail is the Windows text with an RDP note.
9. **Ruling 26:** the runner tests turn RDP on (`fDenyTSConnections`) and toggle NLA on the hosted runners, and
   restore both. They never change the port or the security layer.
10. **The F19-F23 verdicts** ([W6 facts measured on real runners](#w6-facts-measured-on-real-runners)): F20 took route
    (a), so no WMI route; F21 showed the grant is needed.
11. **Ruling 2's warning:** every Windows server with a helper below 1.2.0 shows `win_rdp_helper_outdated` until its
    helper is updated (the W4 "update the helpers first, then Alice" step applies).

Added during execution:

- **Ruling 10 amended:** the revoke removes only non-inherited access-allowed NETWORK SERVICE ACEs with flags 0 and
  the exact stored grant mask; a NETWORK SERVICE ACE the operation did not add (a deny ACE, another mask, an inherited
  one) stays. A revoke that leaves the key readable (a KSP merge) sets `rdp_key_acl_left` instead of failing the
  restore. Confirm.
- **Ruling 11 amended:** a committed journal over an absent previous value answers `restored` when a third party
  deleted the value.
- **Ruling 12 amended:** the journal goes `writing` before the grant, so a kill after the grant is rolled back and
  revoked, and a kill right after `prepared` is fenced.
- **Ruling 13 amended:** `KeyReadHad` may be nil in `prepared` or `restored`; `rdp.rebuild` is journalled for the
  rebuild.
- **Ruling 14 amended (F20):** a value the listener already holds is deleted and set again, so Remote Desktop serves
  its self-signed certificate for about 10 ms during such a deployment. Confirm the window.
- **A failed grant ends `rolled_back`** (`windows.rdp_key_acl_failed`) although the listener was never touched
  (Task 6 ruling). Confirm the label.
- **`rdp_key_acl_left` on `grant_key_read`** when the outcome has no restore step (Task 6 ruling).
- **The RDP e-mails name a self-signed previous certificate by its SHA-1 only:** fixed at the final review (M1): the
  store `Remote Desktop` is named and the RDP texts say to delete `SSLCertificateSHA1Hash` for it.
- **Ruling 3/16 amended (final review I1):** the listener's port is a detail, not part of the locator, so a port
  change updates the same location. Confirm.
- **Ruling 10 amended (security review I1):** Alice never gives NETWORK SERVICE access to an exportable key. A copy
  of the certificate already in `My` whose key is exportable (or whose export policy cannot be read) makes the
  deployment fail `windows.key_unusable` with nothing changed; the administrator must replace that copy or import it
  again non-exportable. Confirm.
- **WN-23 residuals** ([Security review (W6)](#security-review-w6), residual risks 1-9): accept or act on them.
- **The helper-outdated warning** shows on every helper below 1.2.0, 1.0.0 included (Task 6 ruling).
- **The W4 and W5 owner items stay open** (the ruleset, the first release tag, the manual matrix, Authenticode, the
  helper update procedure): a 1.2.0 helper needs the same "update the helpers first, then Alice" step.

## Deferred to W7+

- **W7, on demand**: the WinRM transport.
- **Settled by W6** (Ruling 28): RDP deployment (`win_rdp`); the helper version literal sites; F12's set-value half
  and W3's manual-matrix RDP item (measured on the runners, Ruling 26).
- **Not in W6**: listeners other than `RDP-Tcp` (custom WinStations), RD Gateway, RD Web Access, RD Connection Broker
  and RemoteApp certificates; changing any Remote Desktop setting; Group Policy and autoenrolment writers of the RDP
  certificate (Alice warns); `SecurityLayer` 0's negotiation answer and Windows Server 2019 on a runner.
- **Carried unchanged from [Deferred to W6+](#deferred-to-w6)**: W5's deferred items (the farm layout, CCS file
  creation, removing the CCS password, a CCS password Alice's rule refuses); every "Carried from W2-W4" item; every
  "Minor deferred during W5", including the `drift_observe.go:151` warning gap (a CCS read-only understatement the
  coordinator assigned to the next small batch; W6's RDP endpoints do not read stored warnings).
- **Minors deferred during W6 (known debt)**:
  - tlsverify's RDP negotiation honours the context only through the connection deadline (at most 10 s) (Task 1).
  - Only `RDPFailure(2)` maps to `ErrRDPNoTLS`; F22 measured no failure code (Task 1).
  - The take-back test's grant fails before appending (the fake only); the real `RDPKeyRead` "contains the read bits"
    and the revoke's "exact mask" must stay distinct (Task 2).
  - One long comment line in `write.go`; the take-back may report `rdp_key_acl_left` after a read error (Task 2 fix
    round 3).
  - The emulator answers a Connection Request without `RDP_NEG_REQ` with a failure, not a plain confirm (Task 3).
  - The emulator's stale pin stays nil when the certificate lookup errors (Task 3).
  - The "closed unanswered" test also passes on a read timeout (Task 3).
  - Re-adding an existing `My` certificate in the emulator drops its NETWORK SERVICE read flag (fidelity risk;
    Task 3).
  - The emulator's NETWORK SERVICE state is one bool per key (Ruling 23 allows it); NLA off selects SSL there, while
    F22 measured HYBRID with NLA on and off (Task 3).
  - The migration test never proves the `deployments` EXISTS of the Down on its own (Task 5).
  - Final review M2: the shared `errors.windows.*` titles use the binding wording in RDP e-mails and API problems.
  - Final review M3: a helper downgraded below 1.2.0 marks an existing `win_rdp` location missing.
  - Final review M5: `iis-status` reads an absent value as the previous self-signed leaf without checking the
    `Remote Desktop` store.
  - `TestRDPDeployOutcomeTable`'s refusal rows do not assert that nothing changed (the value, the imports) (Task 6).
  - `logSteps` builds a per-step map literal; two `if`s would be simpler (Task 6).
  - `TestConvertRDP`'s failed `rdp-dump` has no budget or undecodable rows (Task 6).
  - `TestWindowsRDPCrashTable` runs only with the previous certificate in `My`, not a self-signed `previous_absent`
    (Task 6).
  - `discover.go:51` appends to a slice it may alias (harmless; Task 6).
- **Minors and residual 7 settled in R70** (`docs/superpowers/rulings/fixes-2026-10-28.md`).

# W7 (R71)

Phase W7 (the WinRM transport) was built on branch `windows-w7` from the plan
`docs/superpowers/plans/2026-10-28-windows-w7-winrm.md` (10 tasks), approved by the owner on 2026-10-28; the owner
delegated its open decisions to competitor parity on 2026-10-29. Spec: R71 in
`docs/superpowers/specs/alice-v1/00-decisions.md`, `03-integrations.md` §13A.20-13A.21, `04-security.md` §14.4
(WN-26..WN-30), `06-quality.md` §24.7 (WIN-68..WIN-75), design §4.1, §4.2, §8, §9, §13 W7, §14 (F24-F32) and §22. One
migration, `00038`; error codes `ALC-WIN-0024`..`ALC-WIN-0028`. The helper stays `1.2.0`. None of the rulings below is
a pricing decision; the ones the owner should confirm or act on are listed under [Owner items (W7)](#owner-items-w7).

## The owner's delegation and the competitor research (W7)

**The delegation (2026-10-29).** The owner wrote: "sorularin cevaplarini bilmiyorum. rakipler nasil yapmissa sende ole
yap. w7 ye basla" ("I do not know the answers to the questions. Do it the way the competitors did. Start W7."). The
open rulings of the 2026-10-28 draft were therefore decided by competitor parity.

**The competitor research (coordinator, 2026-10-29).** Keyfactor's IIS Universal Orchestrator, Venafi TLS Protect's
agentless IIS driver and AppViewX CERT+ for IIS all reach IIS servers over WinRM with a stored username and password of
a local administrator or a domain service account: Keyfactor defaults to Kerberos; Venafi's examples use HTTPS with
NTLM and offer a `WinRMSkipCACheck` option; AppViewX takes a username and password or a vault reference. None uses
client-certificate mapping, and all accept full-administrator accounts. Hence R71: username and password over HTTPS
with NTLMv2; Kerberos, certificate mapping, PSRP/JEA and CredSSP deferred; Basic, 5985 and `AllowUnencrypted` refused
by construction; WN-26's residual accepted. Alice keeps a stricter server-identity rule than the `SkipCACheck` style:
the listener's SPKI pinned with an Administrator's confirmation (Ruling 9).

## The plan's rulings as built (W7)

The plan's 31 rulings stand as written, except where an entry says "Amended", "Precision" or "Confirmed".

1. **The client library: an in-house WinRS subset with go-ntlmssp for NTLMSSP only.** As written:
   `internal/providers/windows/winrs` (`wsman.go`, `client.go`), go-ntlmssp v0.1.1 direct; masterzen/winrm not used.
2. **The transport is a target setting.** As written. Precision (Task 5): only `transport: winrm` is stored in
   `targets.config` (an SSH server's config JSON stays W6's byte for byte); `Target.Transport` reads `ssh` or `winrm`
   for a Windows server and `""` for any other type; the API carries `transport` at the top level of the target and of
   the create body. `ConfigSchema`'s port default stays 22 (the form sets 5986 under WinRM; deferred minor).
3. **The transport is fixed when the target is created.** As written. Precision (Task 5 review): a patch whose only
   member is another transport is `ALC-WIN-0027`; a patch with the target's own transport alone is the empty-patch
   answer (422, version unchanged); a `transport` value other than `ssh` or `winrm` is the field error `transport`
   `one_of` before any read; a `transport` on a non-Windows target is the field error `transport` `pattern`.
4. **The helper does not change; the line reaches it through `SSH_ORIGINAL_COMMAND`.** **Amended (F25, runs 5 and 6;
   Needs coordinator):** the environment variable reaches the helper's forced entry, and the helper stays `1.2.0` with
   no `WinRMMinVersion`. But WinRS starts the program through `cmd.exe` even with `WINRS_SKIP_CMD_SHELL` TRUE: the
   helper's parent is `cmd.exe`, whose command line is `cmd.exe /C "C:\Program Files\Alice\alice-helper.exe" ssh`, and
   the helper's own command line is the program path without its quotes. `cmd.exe` parses only that constant line;
   the subcommand line stays in the environment, never on a command line. The plan's fallback (helper 1.3.0 with a
   `winrs` entry) would not remove `cmd.exe`, which WinRS inserts itself, so it was not taken. The Command element
   carries the program's quotes raw: element text escapes only `&`, `<` and `>`, because Windows does not decode
   `&#34;` in `rsp:Command` (run 5: the escaped form reached `cmd.exe` as `&`).
5. **One migration, `00038`.** As written (`TestMigration00038WindowsWinRM`, `TestMigration00038Down`; Down `Z1036`).
6. **The accounts and their username forms.** As written. F24 (run 6, both images): `alice-w7-1`, `HOST\alice-w7-1`
   and `.\alice-w7-1` sent raw all sign in; Alice still strips `.\`. Precision (Task 7): the setup script treats
   `HOST\name`, where HOST is the computer's name, as the local account `name` (Go cannot tell a computer name from a
   domain name).
7. **The WinRM password.** As written. Precision (Task 5 review): the CCS and WinRM password code is one
   implementation (`targetPasswordSpec`, `setTargetPassword`, `targetPassword` in inventory; one API helper), so the
   seal, zeroing, foreign-row and order rules cannot drift apart; every refusal zeroes the given `Plaintext`.
8. **The credential source.** As written (`providers.WinRMPasswordSource`; `winrmPassword` released by `defer`
   before the slot, so it is zeroed first on every path, the output overflow included).
9. **The listener is pinned by its SPKI, with the existing flow.** As written; F28 confirmed (runs 2, 3, 6).
10. **The transport seam.** As written. Precision (Task 6): `sshRun` marks a connection it could not open (or a
    context ended before `Run`) with `winrs.ErrNotSent` on top of the same `*providers.Error`, so `runWrite`'s refusal
    rule is one test, `errors.Is(err, winrs.ErrNotSent)`, for both transports; `sshRun` checks the context after the
    acquire for all three call sites.
11. **The WinRM listener's own binding is never deployable.** As written (`TestWinRMListenerBindingStaysUnsupported`;
    `TestRealWinRMProvider` lists the `0.0.0.0:5986` record as `win_foreign_app`).
12. **The WinRS client's rules.** **Amended:**
    - **Dials (F24 (d), run 2):** Windows closes the connection after the anonymous 401, so the sign-in needs a second
      connection. `maxDialsPerCall` is 2, and the second dial is allowed only while the Create request (the sign-in)
      is in flight; after Create's answer any dial is refused (`ErrUnreachable`), so Send still goes only on the
      connection that authenticated.
    - **Credentials only on Create (Ruling 28 amended):** `req.SetBasicAuth` is set on the Create request only; later
      requests carry none, so a 401 after Create ends the call (`ErrAuthRefused`, no new exchange, stdin never sent
      again) and the cleanup is tried once, best effort. F24 measured that the connection stays authenticated (later
      requests take one round trip each).
    - **Port 5985 is refused** (`ErrBadConfig`, before any dial), so "Alice never dials 5985" holds by construction.
    - **Bounds:** `MaxResponseHeaderBytes` 64 KiB on the call's transport (the Negotiator drains a 401's body).
    - **Receive:** `OperationTimeout` is min(20 s, the call's remaining budget), at least 1 s, so the timeout path can
      still Signal and Delete on the one connection; a `w:TimedOut` fault (2150858793) at Receive is asked again.
    - Requests run detached from the call's context and the caller stops waiting at its end, so Signal and Delete
      queue on the same connection with their own 5 s budgets.
    - F26 (run 6): `MaxSendChunk` 96 KiB stays; the listener's `MaxEnvelopeSizekb` is 500, and a Send of about 615 KB
      is answered HTTP 413, not a WS-Man fault.
13. **Error mapping under WinRM.** **Amended:**
    - `winrs.FaultError` carries `Action`, the request the fault answered (set by the client, never by the parser), so
      the code-2 row is exact: code 2 maps to `ssh.helper_missing` only at Command; any other fault after Create is
      `windows.winrm_fault` with `wsman_code`.
    - **F29 (run 6; confirmation in run 7 pending):** a missing program is not a WS-Man fault: WinRS's `cmd.exe`
      answers "is not recognized" and the command finishes with exit code 9009 and no output. `winrmRun` maps exit 9009
      with an empty stdout to `ssh.helper_missing` (then `windows.helper_missing`, as over SSH); the Command was sent,
      so a write stays uncertain. The emulator answers a missing helper the same way.
    - F31 (run 3): an account removed from Administrators is refused with a 401 (`ErrAuthRefused`), not an
      access-denied fault, so no fault code is mapped to `winrm_auth_refused`. An access-denied fault (5) after Create
      is `windows.winrm_fault` with `wsman_code` 5; a 401 or 403 after Create is `windows.winrm_auth_refused` and
      uncertain for a write. `ErrBadConfig` (Alice's own construction error) is `internal.unexpected`.
    - The params `transport` (`^(ssh|winrm)$`) and `wsman_code` (`^[0-9]{1,10}$`) pass the allow-lists of the API, the
      inventory's deployment records and the deployment jobs, so the e-mail variant and the record keep them.
    - The e-mail variant lookup (`reasonTitle` in `internal/notify/sender.go`) takes `reason_variant` first, then the
      param `transport`; `title_winrm` exists for `ssh.unreachable`, `ssh.timeout`, `ssh.output_too_large` and
      `ssh.protocol_error`; `transport` is never rendered.
14. **Slots.** As written (`Pool.Slot`, `TestPoolSlot`).
15. **`HelperCommand` accessors.** As written.
16. **What Windows logs under WinRM.** **Amended (F25, F31):** no PowerShell runs. Security 4688 (with command lines)
    records `cmd.exe /C "C:\Program Files\Alice\alice-helper.exe" ssh` and the helper's own line (the same constant
    path, unquoted, and `ssh`): never the subcommand, which stays in the environment. Security 4624 of a call is logon
    type 3, package NTLM, `LmPackageName` `NTLM V2`, elevated; a wrong password is 4625 (status `0xc000006d`,
    sub-status `0xc000006a`). `Microsoft-Windows-WinRM/Operational` records each shell's creation (event 91 names the
    user), never the streams.
17. **Discovery, deployment, verification, rollback, drift and cleanup are unchanged.** As written.
18. **The WinRM setup script.** **Amended (Task 7, its review and runs 4-6):**
    - Negotiate is read from the registry (`HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service`, value
      `auth_negotiate`; absent means on) right after the checks, before any change or WinRM call; off stops the
      script. Measured: with Negotiate off WinRM refuses even its own local client, so the `WSMan:` drive cannot read it.
    - The helper's install, data directory and event source run after the account (the ACL names the account's SID).
    - A domain account is never added to Administrators by this script; it warns when the account is not a direct
      member. The SSH script still adds it.
    - A password outside Alice's rule, or two entries that differ, stop the script ("run again") instead of asking
      again.
    - `LocalAccountTokenFilterPolicy` is set to 1 for a local account when it is 0 or absent; both images ship 1
      (the script prints `LocalAccountTokenFilterPolicy found: 1; not changed.`).
    - The firewall rule is `Alice-WinRM-In`, display name `Alice WinRM (TCP 5986)`, from `$AliceAddress`.
    - The script prints every HTTPS listener (address, port, SPKI fingerprint, SHA-1 thumbprint), not one.
    - The shared deny-rights fragment compares secedit's export, which names a resolvable account by name, with the
      account's `*SID`, so every run sets the two rights again and prints "Denying ...": the result is the same
      right (W1 code, shared with the SSH script; fixing it changes the SSH script's golden; deferred).
19. **The setup endpoint.** **Amended (Task 7 review):** `GET /api/v1/targets/{id}/winrm-setup` takes the optional
    query parameter `from`, validated as the SSH guide's (one shared check; a zone or 4in6 address is the field error
    `from`), and passes it to the firewall rule. The API reaches the script through `providers.WinRMSetupGuide`
    (inventory resolves the provider), not an import, because the archtest rule forbids `api` to import
    `providers/windows`. The web passes no `from` yet (owner item).
20. **Emulator model.** As written. Precisions (Task 3): the demo host's computer name is `WIN-DEMO01`; the demo
    binding `0.0.0.0:9444` (site "WinRM Journey") is the journey's; the fault codes the runners did not measure stay
    placeholders (bad request 87, unknown shell 2150858843, `MaxShellsPerUser` 2150859173, envelope too large
    2150858817); a missing helper is exit 9009 (F29), not fault 2.
21. **Security analysis and STRIDE `WN-26`..`WN-30`.** As written, with WN-28 amended for the `cmd.exe` that WinRS
    inserts (Ruling 16) and WN-30 for F24's verdict.
22. **UI.** As written. Precisions (Task 8): the "(WinRM)" note is the catalogue's `title_winrm` variant, chosen when
    `params.transport` is `winrm`; after a WinRM create the dialog shows the script, then the password panel, and runs
    the connection test when the password is saved; the client refuses a username outside the rule (a UPN too) under
    WinRM only.
23. **e2e.** As written (`web/e2e/windows-winrm.spec.ts`, EN and TR). Precision: `test/images/fakewindows/Dockerfile`
    copies the packages the emulator now links (`winrs`, `netaddr` and others).
24. **Real-runner tests and hygiene.** **Amended (runs 3-4):** each real test signs in as its own account
    `alice-w7-<n>`; a name created again right after its deletion was refused at Create (`E_ACCESSDENIED`,
    2147942405) for seconds. `TestRealRunnerIsClean` checks that no local account named like `alice-w7%` is left. A
    WinRM setting the `WSMan:` drive cannot restore (Negotiate off) is restored through a registry export of
    `WSMAN\Service` and a WinRM restart. The providers test line runs with `-p 1` and `-timeout 30m`.
25. **Test IDs.** As written: `WIN-68`..`WIN-75`.
26. **The dedicated security review of the transport.** Task 10 step 6; see [Security review (W7)](#security-review-w7).
27. **"Deferred to W7+": settled or carried.** As written; see [Deferred to W8+](#deferred-to-w8).
28. **The Negotiator wrapping.** **Amended (Task 2 review):** the credentials go in through `req.SetBasicAuth` on the
    Create request only (Ruling 12); the Negotiator removes that header before the anonymous first try, so Basic never
    leaves the process (`TestWinRSNeverSendsBasic`, `TestWinRSSignsInOnCreateOnly`).
29. **The direct-module rule.** As written.
30. **The username is configuration, not a secret.** As written.
31. **NTLM channel binding is not available.** **Confirmed (F30, run 3):** with `CbtHardeningLevel` Strict the sign-in
    is refused; the image ships Relaxed.

## W7 facts measured on real runners

Runs of `.github/workflows/windows.yml` (windows-2022 = Windows Server 2022 Datacenter, windows-2025 = Windows Server
2025 Datacenter). Each verdict holds on both images unless stated.

- **F24: confirmed, with (d).** Runs 2, 3 and 6 (<https://github.com/erenmeren/alice/actions/runs/41182325826>,
  <https://github.com/erenmeren/alice/actions/runs/41183745215>, <https://github.com/erenmeren/alice/actions/runs/41187834322>).
  A local administrator signs in with NTLMv2 to the image's `0.0.0.0:5986` listener: the first request of a call
  takes 3 requests (anonymous 401 offering `Negotiate` and `Basic realm="WSMAN"`, type 1, type 3), later requests one
  each without credentials (the connection stays authenticated). Windows closes the connection after the anonymous
  401, so a call takes 2 dials: (d) applies, `maxDialsPerCall` = 2 (Ruling 12). `version` answers and the token is
  elevated with `LocalAccountTokenFilterPolicy` 1 as the images ship it; (a) did not apply. The forms `alice-w7-1`,
  `HOST\alice-w7-1` and `.\alice-w7-1` (raw) all sign in. The result with the policy set to 0 is logged by
  `TestRealWinRMNTLMAuth` and not yet read into this record (run 7+, pending).
- **F25: the forced entry works; `cmd.exe` is inserted (Needs coordinator).** Runs 5 and 6
  (<https://github.com/erenmeren/alice/actions/runs/41186388742>, <https://github.com/erenmeren/alice/actions/runs/41187834322>).
  `SSH_ORIGINAL_COMMAND` reaches the helper (`version` answers `{"ok":true,"helper":"1.2.0","protocol":1}`), but WinRS
  runs the program through `cmd.exe` despite `WINRS_SKIP_CMD_SHELL` TRUE (parent `cmd.exe /C "<program>" ssh`; the
  child's command line unquoted). The escaped `&#34;` form of the quotes reached `cmd.exe` as `&` (run 5); raw quotes
  work. Ruling 4 amended; the helper stays 1.2.0.
- **F26: confirmed.** Run 6. 1 byte, 96 KiB, 96 KiB + 1 and 256 KiB of stdin arrive with equal SHA-256;
  `MaxEnvelopeSizekb` 500; a Send of about 615 KB is answered HTTP 413 (no WS-Man fault). `MaxSendChunk` stays 96 KiB.
- **F27: confirmed for the cost; the reaping not measured.** Runs 4 and 6. 20 sequential `version` calls: p50 49-67 ms,
  maximum 54-114 ms (run 4: p50 57 ms, maximum 64 ms), far under the 3 s threshold, so no budget changes.
  `MaxShellsPerUser` 2147483647. Enumerating shells as the test account was refused ("A security error occurred"), so
  the `IdleTimeOut` clamp and the reaping of an undeleted shell were not measured (Alice deletes every shell it
  creates).
- **F28: confirmed.** Runs 2, 3 and 6. The image's 5986 SPKI is unchanged after `Restart-Service WinRM`; a test listener
  renewed with a new key is refused at the handshake before any HTTP request (no 4624 or 4625, no WinRM Operational
  event); renewed with the same key it is accepted; an expired certificate with the pinned key is accepted.
- **F29: confirmed for exit codes; a missing program is cmd.exe's exit 9009 (confirmation in run 7 pending).** Run 6.
  Exits 0, 2, 3 and 4 pass through as Receive's `ExitCode`; `iis-status` with a bad `--op` answers exit 2 with its JSON.
  A program path that does not exist is not a WS-Man fault at Command: the command finishes with `cmd.exe`'s exit
  code, 9009 (Ruling 13 amended). The `alicetest` kill at `deploy.prepared` is logged only (not yet read into this
  record).
- **F30: confirmed.** Runs 2-4. The image offers `Negotiate` and `Basic realm="WSMAN"`; it has an HTTP listener on 5985
  (enabled), `Service\Auth` Basic true, Kerberos true, Negotiate true, Certificate false, CredSSP false,
  `CbtHardeningLevel` Relaxed, `AllowUnencrypted` false, `LmCompatibilityLevel` absent. (a) Negotiate off and Basic on:
  only Basic is offered, Alice's client sends one request without `Authorization` and fails `ErrAuthRefused` after one
  dial. (b) A wrong password fails after 3 requests. (c) `LmCompatibilityLevel` 5 works. `CbtHardeningLevel` Strict
  refuses (Ruling 31 confirmed). The registry value WinRM reads for Negotiate is `auth_negotiate` under
  `WSMAN\Service`.
- **F31: confirmed.** Runs 3 and 6. With "Deny log on locally", "Deny log on through Remote Desktop Services" and
  `PasswordNeverExpires`, the call signs in: 4624 logon type 3, package NTLM, `LmPackageName` `NTLM V2`, elevated. A wrong
  password is 4625 (`0xc000006d`, `0xc000006a`). After a password change the old password is refused and the new one
  works. "Deny access to this computer from the network" holding S-1-5-114 refuses a local account. An account removed
  from Administrators is refused with a 401.
- **F32: confirmed.** Runs 4 and 6. The script's printed SPKI fingerprint equals `providers.TLSIdentity` of the
  certificate Alice's client sees, for the image's RSA listener on 5986 and an ECDSA P-256 listener on 45521.

### Runner runs used (6 of 10 so far)

| Run | windows.yml | Head | windows-2022 / windows-2025 | What it found |
|---|---|---|---|---|
| 1 | <https://github.com/erenmeren/alice/actions/runs/41181076117> | `978935d3` | fail / fail | No fact measured: `[ADSI]::Exists` throws for an absent account (fixture and clean test). The as-found settings were read: `LocalAccountTokenFilterPolicy` 1, `LmCompatibilityLevel` absent, Basic, Kerberos and Negotiate true, `CbtHardeningLevel` Relaxed, `AllowUnencrypted` false, S-1-5-114 not denied network logon |
| 2 | <https://github.com/erenmeren/alice/actions/runs/41182325826> | `8c191ae8` | fail / fail | F24 (d): Windows closes the connection after the anonymous 401 (2 dials; Create 3 requests, later requests 1 each); most calls failed on the one-dial rule. F28: SPKI unchanged after a restart. F30: the offer, the 5985 listener and the `Service\Auth` values; (a) passed. Negotiate left off by a failed restore broke the later tests |
| 3 | <https://github.com/erenmeren/alice/actions/runs/41183745215> | `3095a34e` | fail / fail | The sign-in works (2 dials, 4624 `NTLM V2`, elevated); F28, F30 (wrong password, Strict refused) and F31 (4625, password change, S-1-5-114, out of Administrators) measured. Every program exited 1 with no output; some Creates faulted `E_ACCESSDENIED` after an account was created again under the same name. `TestRealRunnerIsClean` passed |
| 4 | <https://github.com/erenmeren/alice/actions/runs/41184960052> | `0c108a36` | fail / fail | The diagnostic matrix: every Create right after a same-name recreate faulted `E_ACCESSDENIED`; programs still exited 1. F27 cost, F30 and F28 passed; the setup script ran cleanly (refusals, policy found 1, firewall rule, ECDSA listener printed) |
| 5 | <https://github.com/erenmeren/alice/actions/runs/41186388742> | `b8820bc1` | fail / fail | Decisive: the escaped `&#34;` around the program reached `cmd.exe` as `&`; unquoted and raw-quote forms work, `SSH_ORIGINAL_COMMAND` is delivered and the helper answers `version` |
| 6 | <https://github.com/erenmeren/alice/actions/runs/41187834322> | `a594ffec` | fail / fail | Nearly every fact measured: F24 forms, F25 (`cmd.exe` inserted), F26, F27, F28, F29 (exits; a missing program is not a fault), F32. Left failing: F25's `cmd.exe` assertions, F29's missing program, the fidelity fault at Command, and a leftover `C:\ProgramData\alice-w7-<n>` |
| 7 | pending | pending | pending | pending |
| 8 | pending | pending | pending | pending |
| 9 | pending | pending | pending | pending |
| 10 | pending | pending | pending | pending |

## Rulings made during execution (W7)

One line each: the ruling, then why (and the cost if wrong where it is not obvious).

### Controller (order and process)

- P1: the execution workspace was outside `.superpowers/` (the coordinator forbids touching it) — costs nothing.
- P2 (pre-flight): Task 5 took the config half of Task 6 (`windows.Config`, `TransportSSH`/`TransportWinRM`,
  `DefaultWinRMPort`, the `transport` enum, the port default, the `.\` form, `TestWinRMConfig`) — Task 5's inventory
  tests need a WinRM target to exist; cost if wrong: Task 6 touches `config.go` again.
- P3 (pre-flight): Task 5 added `SetupScriptWinRM` as a minimal function and Task 7 completed it — the endpoint test
  needs a script; costs nothing.
- P4: Tasks 3, 4 and 5 ran in parallel in one worktree on disjoint paths (the coordinator allowed it).
- P5: Task 6 started before run 1 measured F25 — the environment variable is the documented sshd contract the helper
  already uses; cost if wrong: Task 6's seam reworked for helper 1.3.0 (it was not).
- P6: Task 8 (web and e2e) ran early, in parallel with Task 4's fixes and Task 6's minors — it needed only Tasks 3 and
  5.
- P7: `docs_setup_test.go`'s WinRM lines moved from Task 7 to Task 9, which writes the host guide.
- P8: only the controller pushed the branch for runner runs; Task 4 did not push.

### Task 1-2 (winrs codec and client, the emulator's NTLMv2 check, linuxssh)

- The Command element carries the program quoted and `ParseRequest` strips the quotes; each argument is its own
  `rsp:Arguments` element (pywinrm's form); programs and arguments holding `"` are refused, at most 16 arguments.
- The Create body is InputStreams, OutputStreams, IdleTimeOut, then Environment (pywinrm's order); the shell ID is read
  from the ResourceCreated selector and `rsp:Shell/rsp:ShellId`, which must agree.
- `ParseReceived` is strict (any other element, a second `CommandState` or another `CommandId` is `ErrProtocol`); the
  runners did not need it loosened.
- `winrs.DefaultDialTimeout` (10 s) and `winrs.DefaultHandshakeTimeout` (15 s) are exported, so a test in
  `internal/providers/windows` can compare them with linuxssh's values.
- `Client.check` also refuses a nil TLS config, a TLS `MaxVersion` below 1.2, a user holding `:`, a non-positive
  timeout or output limit, an address without a port, and anything the codec would refuse (`ErrBadConfig`).
- A 401 or 403 after the dialer refused a dial is `ErrUnreachable`, not `ErrAuthRefused` — go-ntlmssp returns the first
  401 when its handshake round trip fails, which would otherwise read as a wrong password.
- A non-200 answer that is neither 401/403 nor a SOAP fault (a 302, a bare 500) is `ErrProtocol`.
- The emulator's NTLM server keeps a fresh state per request without its `ConnContext` (it never authenticates then);
  its domain is the account's, or the computer name in a workgroup.
- Port 5985 refused, credentials only on Create, `MaxResponseHeaderBytes` 64 KiB, `maxDialsPerCall` = 2: see Ruling 12.
- Element text escapes only `&`, `<` and `>`; attribute values keep `xml.EscapeText` (run 5, Ruling 4).

### Review gate (Task 1-2)

The review of `8475ecf8..b20f3d69` found 1 important issue (the proxy test could not fail: Go never proxies loopback;
fixed in `83b7b161` with a non-loopback name and a recording proxy) and minors: 5985 not refused (`bb9be052`), the Send
body resent in a re-authentication (`ca650e12`, credentials on Create only), header and 401-drain bounds (`5031b126`),
a test comment (`8f96aea5`), a constant assertion (`9a3ece4c`). Declined: `ntlm.go`'s `int(uint32)` on 32-bit (test-only
emulator, CI is 64-bit).

### Task 3 (wintest and cmd/alice-fakewindows)

- The fault codes the runners did not measure are placeholders, none 5 or 2, so Ruling 13's auth and helper rows are
  never hit by accident (Ruling 20).
- Create faults unless its environment is exactly `SSH_ORIGINAL_COMMAND` (a stricter emulator catches client drift).
- A Receive waits up to its `OperationTimeout`, then answers `w:TimedOut`, so `Model.Delay` drives the client's timeout
  path as on Windows.
- With no account set the NTLM exchange still runs and ends in 401, so the request count matches a wrong password.
- The demo binding `0.0.0.0:9444` has an IIS site "WinRM Journey", so discovery lists it as deployable; four
  assertions in `internal/providers/windows` tests and two e2e counts changed with it.

The review approved it; three minors were fixed in `b817d610` (sorted environment names in the log, the package
comment's counts, a comment on the shared context key).

### Task 4 (real-runner facts F24-F31)

- Request counts are measured on a hand-driven connection that wraps go-ntlmssp's Negotiator as `winrs` does — the
  client builds its transport inside `Run`.
- The password change of F31 uses ADSI `SetPassword` with the password on standard input, not `net user` — no password
  on a command line.
- Account rights are changed through the LSA API, atomic per SID and right, so the setup script test's concurrent
  `secedit` is never clobbered.
- The as-found settings cross to `TestRealRunnerIsClean` through `%TEMP%\alice-w7-settings-as-found.txt`, read with one
  script on both sides.
- F29's kill is a real `alicetest` helper killed at `deploy.prepared` over a hand-built shell (two variables), logged
  only.
- `-p 1` and `-timeout 30m` on the workflow's providers line.
- Each test signs in as a new account `alice-w7-<n>` (Ruling 24 amended).
- A WinRM setting the drive cannot restore is restored through a registry export of `WSMAN\Service` and a WinRM restart;
  a value that differs afterwards fails loudly.

### Review gate (Task 4)

The review found 2 important issues (F29's kill was a program exiting 137, a tautology: replaced by the real kill in
`faf27bf6`; `deleteAccount` could strand the account: rewritten in `c812a371`) and minors fixed in `4fa92cab`,
`762bcd3d`, `818a3ab9`, `faddd75d`, `8c191ae8`.

### Task 5 (migration, inventory, API, error codes)

- Only `transport: winrm` is stored; `Target.Transport` reads `ssh`, `winrm` or `""` (Ruling 2).
- A `transport` member on a non-Windows target is the field error `transport` `pattern`; another transport on a Windows
  server is `ErrTransportImmutable` (Ruling 3).
- `ConfigSchema`'s username pattern stays the SSH rule; the `.\` form under WinRM is `ParseConfig`'s alone.
- The setup script reaches the API through `providers.WinRMSetupGuide` (Ruling 19).
- `reasonTitle` takes `reason_variant`, then `transport` (Ruling 13); `title_winrm` for the four reused `ssh.*` reasons.
- `SetWinRMPassword` wraps `ErrNotWindowsTarget` with ": its transport is not winrm" for an SSH Windows server (still
  409 `ALC-WIN-0011`).
- The shared A06 session test expects 409 for `GET .../winrm-setup` (its fixture target is an SSH server).

### Review gate (Task 5)

The review found 2 important issues: a transport-only patch answered 422 (fixed in `9657952d`, Ruling 3) and the
password code copied the CCS code (shared in `e895fd03`, Ruling 7). Minors fixed: a bad transport value is a field
error (`57904f95`), `transport` is never rendered (`0d9205e1`), zeroing on every refusal (`921e081d`, `f3b8124b`).
Deferred: `ConfigSchema`'s port default.

### Task 6 (the provider's transport seam)

- `ErrBadConfig` maps to `internal.unexpected`, not retryable, not sent.
- An access-denied fault after Create is `windows.winrm_fault`; a 401 or 403 after Create is `winrm_auth_refused` and
  uncertain (Ruling 13).
- The `transport` and `wsman_code` allow-lists also go into the inventory's and the deployment jobs' param lists.
- `internal/providers/tlspin/**` is a Windows path (`.github/windows-paths.txt`): the provider now imports it.

### Review gate (Task 6)

Approved; minors fixed: `FaultError.Action` (`e8c97911`), the slot and `tlspin.New` errors carry the params
(`e72f309e`), the password released by `defer` (`cefca020`). Deferred: `sshRun`'s context-after-acquire branch
untested; the crash table does not assert "sent once"; a WinRM error returns an empty `HostKey`.

### Task 7 (the setup script, its real tests, fidelity)

- The helper's install runs after the account; the account's creation is not shared with the SSH script (a prompted
  password and the domain branch); a domain account is never added to Administrators (Ruling 18).
- `HOST\name` with HOST the computer's name is the local account (Ruling 6).
- A bad password or two different entries stop the script.
- `TestSetupScriptWinRMDomainAccount` is structural: every `Read-Host`, `Create('User')` and `SetPassword` sits in the
  functions only the local branch calls.
- The script prints every HTTPS listener.
- The four real tests need `ALICE_WIN_SETUP=1` and live in `setup_winrm_windows_test.go`.
- `TestFidelityWinRM` compares `win-facts` and `iis-dump` by field names, `ok` and `elevated`.
- The firewall rule is `Alice-WinRM-In` / `Alice WinRM (TCP 5986)`, mirroring `Alice-SSH-In`.

### Review gate (Task 7)

The review found 3 important issues: the Negotiate stop was unreachable (moved to a registry read before any change,
`22355fce`); the product script opened 5986 from any address (the endpoint's `from`, Ruling 19); the docs test had no
owner (moved to Task 9, P7). Minors fixed: the OID shortcut comment (`b44326e2`), the netsh cleanup failure
(`57ce0e1b`). From run 4: the deny-rights check takes a holder by name or SID, and F32 is compared before the first
WinRS call (`3c376783`).

### Task 8 (web and e2e)

- The "(WinRM)" note is the `title_winrm` variant (Ruling 22).
- After a WinRM create the dialog does not wait for the first connection job; the test runs when the password is saved.
- The client refuses a username outside the rule under WinRM only.
- `test/images/fakewindows/Dockerfile` gains the COPY lines the emulator needs.
- `deployments.rdpErrors.ssh.output_too_large` gets its own RDP text: the source-scanning test now sees the reason in
  `winrm.go`.

The review approved it. Deferred: no hint after a failed connection test after the password; leaving the WinRM phase
leaves the password missing; the RDP text added for a source-scanning test is a brittle coupling; the web passes no
`from` (owner item).

### Task 9 (documents)

- `docs_setup_test.go` checks that the host guide quotes the WinRM script's `$AliceUser`, `$AliceAddress`, listener and
  firewall lines as the script writes them for `alice` without an address
  (`TestPreparationGuideQuotesTheWinRMScript`).
- The traceability map names the migration tests by their full names (`TestMigration00038WindowsWinRM`,
  `TestMigration00038Down`); the plan's table wrote `TestMigration00038`.

## Needs coordinator (W7)

- **F25, `cmd.exe` under WinRS.** WinRS starts the helper through `cmd.exe /C "<program>" ssh` although Alice sends
  `WINRS_SKIP_CMD_SHELL` TRUE. The controller ruled that the helper stays 1.2.0: the forced entry works, `cmd.exe`
  parses only the constant quoted program line, and the plan's fallback (helper 1.3.0 with a `winrs` entry) would not
  remove `cmd.exe`. Ruling 16 and WN-28 say so. Confirm, or order the fallback task. Cost if wrong: one helper task.
- **F29, exit 9009.** A missing helper is `cmd.exe`'s exit 9009 with no output, mapped to `windows.helper_missing`;
  confirmation in run 7 pending.

## Security review (W7)

Pending: Task 10 step 6 (Ruling 26).

## Acceptance (design §13 W7)

Pending: Task 10 step 7.

## Owner items (W7)

From the plan (decided by the delegation, recorded, no further action): Ruling 1 (the in-house client), Rulings 6-8
(username and password over NTLMv2, the sealed per-target password), Ruling 4 (the helper stays 1.2.0), Rulings 21 and
31 (WN-26 accepted, no channel binding), Ruling 29 (go-ntlmssp direct).

Still for the owner to confirm:

1. **The Turkish texts** below (the WN-26 caution, the transport choice, the username help, the password dialog and
   the five error reasons).
2. **Ruling 18, the password prompt:** the script asks the operator for the password (an empty answer keeps the
   current one) instead of generating one, so the operator types it twice: on the server and in Alice.
3. **Ruling 18's server changes:** `LocalAccountTokenFilterPolicy` = 1 for a local account when it is 0 or absent
   (both images ship 1, so the runners never exercised the change); the script never changes Negotiate, Basic,
   `CbtHardeningLevel`, `AllowUnencrypted` or the 5985 listener: it warns, or stops when Negotiate is off. A domain
   account is never added to Administrators by the WinRM script (the SSH script still adds it).
4. **Ruling 3's gap:** W7 does not refuse a second live Windows target for the same host on the other transport; the
   licence counts it twice.
5. **Ruling 5:** a WinRM target's `targets.credential_id` still names the platform key, unused.
6. **Ruling 24:** the runner tests change WinRM and LSA settings on the hosted runners and create local accounts
   `alice-w7-<n>`, test listeners on 45520-45539 and `C:\ProgramData\alice-w7-<n>`, and restore everything as found.
7. **The F24-F32 verdicts** ([W7 facts measured on real runners](#w7-facts-measured-on-real-runners)): F24 (a) did not
   apply; F25 inserts `cmd.exe` (Needs coordinator); F30 Strict refuses.
8. **A domain account over WinRM** is accepted by syntax and by the emulator only; the first real test is on a
   customer's or the owner's domain (manual matrix).

Added during execution:

- **Ruling 4 and 16 amended (F25):** Windows' process-creation log shows `cmd.exe /C "C:\Program Files\Alice\alice-helper.exe" ssh`
  and the helper's own line for every WinRM call; never the subcommand or key material. Confirm.
- **Ruling 12 amended (F24 (d)):** a call may open a second connection during its sign-in, never after.
- **Ruling 19 amended:** the setup endpoint takes Alice's address (`from`), but the web does not pass it yet, so the
  script shown in the web opens 5986 from any address with a warning to edit `$AliceAddress`. Decide whether the web
  asks for the address.
- **The deny-rights fragment is not idempotent** (Ruling 18): every run of either script sets the two deny rights
  again and prints "Denying ...". Harmless; fixing it changes the SSH script's text.
- **The WN-26..WN-30 residuals** ([Security review (W7)](#security-review-w7), once written): WN-26 High accepted as
  competitor parity.
- **The W4, W5 and W6 owner items stay open** (the ruleset, the first release tag, the manual matrix, Authenticode,
  the helper update procedure).

The new Turkish texts (EN/TR pairs as shipped; the coordinator checks them, R70's C6):

| key | EN | TR |
|---|---|---|
| `targets.form.transport` (web) | Connection | Bağlantı |
| `targets.form.transportHelp` (web) | OpenSSH is recommended. Choose WinRM only when the server cannot run OpenSSH. | OpenSSH önerilir. WinRM'yi yalnızca sunucuda OpenSSH çalıştırılamıyorsa seçin. |
| `targets.form.transportSsh` (web) | OpenSSH (recommended) | OpenSSH (önerilen) |
| `targets.form.transportWinrm` (web) | WinRM over HTTPS | HTTPS üzerinden WinRM |
| `targets.form.portWinrm` (web) | WinRM HTTPS port | WinRM HTTPS bağlantı noktası |
| `targets.form.winrmWarning` (web, WN-26) | Under WinRM, anyone with this account's password can run any command on the server as an administrator. With OpenSSH, Alice's key can run only alice-helper.exe. | WinRM'de bu hesabın parolasını bilen herkes sunucuda yönetici olarak her komutu çalıştırabilir. OpenSSH'de Alice'in anahtarı yalnızca alice-helper.exe'yi çalıştırabilir. |
| `targets.form.usernameWinrmHelp` (web) | alice, .\alice, SERVER\alice or DOMAIN\alice. The account must be a member of Administrators. | alice, .\alice, SUNUCU\alice ya da ALANADI\alice. Hesap Administrators grubunun üyesi olmalıdır. |
| `targets.form.usernameWinrmInvalid` (web) | Write the account as alice, .\alice, SERVER\alice or DOMAIN\alice. Over WinRM, Alice cannot sign in with an e-mail-style name such as alice@corp.example. | Hesabı alice, .\alice, SUNUCU\alice ya da ALANADI\alice biçiminde yazın. Alice, WinRM üzerinden alice@corp.example gibi e-posta biçimindeki bir adla oturum açamaz. |
| `targets.form.winrmScriptLater` (web) | After you add the server, Alice shows its WinRM setup script and asks for the account's password. | Sunucuyu ekledikten sonra Alice, WinRM kurulum betiğini gösterir ve hesabın parolasını ister. |
| `targets.winrm.setupTitle` (web) | WinRM setup script | WinRM kurulum betiği |
| `targets.winrm.setupHelp` (web) | Run it once in an elevated PowerShell on the server, in the folder that holds alice-helper.exe. It installs the helper, prepares the account and asks for its password, creates an HTTPS listener on port 5986 when there is none, lets Alice's address through the firewall, and prints the listener's fingerprint. Keep that fingerprint: you compare it in the last step. | Sunucuda, alice-helper.exe dosyasının bulunduğu klasörde, yönetici olarak açılmış bir PowerShell içinde bir kez çalıştırın. Betik yardımcı aracı kurar, hesabı hazırlar ve parolasını sorar, yoksa 5986 numaralı bağlantı noktasında bir HTTPS dinleyicisi oluşturur, güvenlik duvarında Alice'in adresine izin verir ve dinleyicinin parmak izini yazdırır. Bu parmak izini saklayın: son adımda karşılaştıracaksınız. |
| `targets.winrm.passwordStep` (web) | Then enter the same password here. Alice tests the connection as soon as the password is saved. | Ardından aynı parolayı buraya girin. Parola kaydedilir kaydedilmez Alice bağlantıyı sınar. |
| `targets.winrm.showScript` (web) | Show setup script again | Kurulum betiğini yeniden göster |
| `targets.page.facts.transport` (web) | Transport | Bağlantı yöntemi |
| `targets.page.facts.transportWinrm` (web) | WinRM (HTTPS, NTLM) | WinRM (HTTPS, NTLM) (identical, allow-listed) |
| `hostKeys.tlsLabel` (web) | TLS certificate key (SPKI SHA-256) | TLS sertifika anahtarı (SPKI SHA-256) |
| `hostKeys.tlsHelp` (web) | Alice received this fingerprint of a TLS certificate key from {{host}}. Compare it with the listener fingerprint the WinRM setup script printed on the server (the value that starts with SHA256:). You can also run the command below, with the server's address and port, from a machine that reaches the server. | Alice, bir TLS sertifika anahtarının bu parmak izini {{host}} adresinden aldı. Bunu, WinRM kurulum betiğinin sunucuda yazdırdığı dinleyici parmak iziyle (SHA256: ile başlayan değer) karşılaştırın. Aşağıdaki komutu, sunucunun adresi ve bağlantı noktasıyla, sunucuya erişebilen bir makinede de çalıştırabilirsiniz. |
| `hostKeys.tlsCommandLabel` (web) | Command to run from a machine that reaches the server | Sunucuya erişebilen bir makinede çalıştırılacak komut |
| `winrm.title` (web) | WinRM password | WinRM parolası |
| `winrm.help` (web, the password dialog) | Alice signs in to this server over WinRM with the password of its account. The password stays sealed on the Alice server, is used only while Alice is connected, and is never shown again. Enter the password the setup script set on the server, and use a different password on every server. | Alice bu sunucuda WinRM üzerinden hesabın parolasıyla oturum açar. Parola Alice sunucusunda mühürlü saklanır, yalnızca Alice bağlıyken kullanılır ve bir daha gösterilmez. Kurulum betiğinin sunucuda ayarladığı parolayı girin ve her sunucuda farklı bir parola kullanın. |
| `winrm.field` (web) | WinRM password | WinRM parolası |
| `winrm.fieldHelp` (web) | The password of the account on the server: 12 to 128 characters of printable ASCII, no spaces. | Sunucudaki hesabın parolası: boşluksuz, yazdırılabilir ASCII karakterlerden oluşan 12 ile 128 karakter. |
| `winrm.saved` (web) | Saved. Use Test connection to check it. | Kaydedildi. Denetlemek için Bağlantıyı sına'yı kullanın. |
| `audit.actions.target_winrm_password_set` (web) | WinRM password of a Windows server set | Bir Windows sunucusunun WinRM parolası ayarlandı |
| `deployments.rdpErrors.ssh.output_too_large.action` (web) | Check the server for unusually large content in what Alice reads there: the Remote Desktop listener's settings or the certificate stores. | Sunucuda Alice'in okuduklarında olağandışı büyük içerik olup olmadığını denetleyin: Uzak Masaüstü dinleyicisinin ayarları ya da sertifika depoları. |
| `provider.windows.fields.transport.label` | Connection | Bağlantı |
| `provider.windows.fields.transport.help` | OpenSSH (recommended), or WinRM over HTTPS with the account's password. | OpenSSH (önerilir) ya da hesabın parolasıyla HTTPS üzerinden WinRM. |
| `errors.windows.winrm_auth_refused.title` | The Windows server refused Alice's WinRM sign-in. | Windows sunucusu Alice'in WinRM oturum açmasını reddetti. |
| `errors.windows.winrm_auth_refused.cause` | The password set in Alice differs from the account's password on the server, the account is not a member of Administrators, or the server refuses NTLM (Negotiate authentication is off, CbtHardeningLevel is Strict, or a policy restricts NTLM). Nothing was sent to the helper. | Alice'te girilen parola sunucudaki hesabın parolasından farklı, hesap Administrators grubunun üyesi değil ya da sunucu NTLM'i reddediyor (Negotiate kimlik doğrulaması kapalı, CbtHardeningLevel Strict ya da bir ilke NTLM'i kısıtlıyor). Yardımcı programa hiçbir şey gönderilmedi. |
| `errors.windows.winrm_auth_refused.action` | Check the account and its password on the server, set the same password in Alice on the server's page, and check the server's WinRM authentication settings. Then test the connection again. | Sunucudaki hesabı ve parolasını kontrol edin, aynı parolayı Alice'te sunucunun sayfasında girin ve sunucunun WinRM kimlik doğrulama ayarlarını kontrol edin. Ardından bağlantıyı yeniden sınayın. |
| `errors.windows.winrm_password_missing.title` | Alice has no WinRM password for this server. | Alice'te bu sunucu için WinRM parolası yok. |
| `errors.windows.winrm_password_missing.cause` | This server is reached over WinRM, which signs in with the account's password, and no password was set in Alice. Alice did not connect. | Bu sunucuya, hesabın parolasıyla oturum açan WinRM üzerinden ulaşılıyor ve Alice'te parola girilmemiş. Alice bağlanmadı. |
| `errors.windows.winrm_password_missing.action` | An Administrator sets the password on the server's page in Alice (the one the WinRM setup script set on the server). Then test the connection again. | Bir Yönetici parolayı Alice'te sunucunun sayfasında girer (WinRM kurulum betiğinin sunucuda belirlediği parola). Ardından bağlantıyı yeniden sınayın. |
| `errors.windows.winrm_fault.title` | The server's WinRM service refused the request. | Sunucunun WinRM hizmeti isteği reddetti. |
| `errors.windows.winrm_fault.cause` | The WinRM service on the server answered with a fault, for example because of a quota, a WinRM setting or a policy. The fault's code is in the details. | Sunucudaki WinRM hizmeti bir hatayla yanıt verdi; örneğin bir kota, bir WinRM ayarı ya da bir ilke nedeniyle. Hatanın kodu ayrıntılarda yer alır. |
| `errors.windows.winrm_fault.action` | Check the server's WinRM settings and the Microsoft-Windows-WinRM/Operational event log, then try again. | Sunucunun WinRM ayarlarını ve Microsoft-Windows-WinRM/Operational olay günlüğünü kontrol edin, ardından yeniden deneyin. |
| `errors.windows.transport_immutable.title` | The connection type of a server cannot be changed. | Bir sunucunun bağlantı türü değiştirilemez. |
| `errors.windows.transport_immutable.cause` | A server's connection (OpenSSH or WinRM) is chosen when it is added, because the pinned server identity and the credential differ between the two. Nothing was changed. | Sunucunun bağlantısı (OpenSSH ya da WinRM) sunucu eklenirken seçilir; çünkü sabitlenen sunucu kimliği ve kimlik bilgisi ikisinde farklıdır. Hiçbir şey değiştirilmedi. |
| `errors.windows.transport_immutable.action` | To use the other connection, add the server again with it, then remove the old entry. | Diğer bağlantıyı kullanmak için sunucuyu o bağlantıyla yeniden ekleyin, ardından eski kaydı kaldırın. |
| `errors.windows.winrm_password_invalid.title` | This WinRM password cannot be used. | Bu WinRM parolası kullanılamaz. |
| `errors.windows.winrm_password_invalid.cause` | Alice accepts a WinRM password of 12 to 128 characters of printable ASCII without spaces. The password was not stored. | Alice, boşluksuz ve yazdırılabilir ASCII karakterlerden oluşan, 12 ile 128 karakter arasında bir WinRM parolası kabul eder. Parola saklanmadı. |
| `errors.windows.winrm_password_invalid.action` | Set a password that follows this rule for the account on the server (the WinRM setup script asks for it), then enter the same password here. | Sunucudaki hesap için bu kurala uyan bir parola belirleyin (WinRM kurulum betiği bunu sorar), ardından aynı parolayı buraya girin. |
| `errors.ssh.unreachable.title_winrm` | Alice cannot reach the server's WinRM HTTPS listener. | Alice sunucunun WinRM HTTPS dinleyicisine ulaşamıyor. |
| `errors.ssh.timeout.title_winrm` | The server took too long to answer over WinRM. | Sunucunun WinRM üzerinden yanıt vermesi çok uzun sürdü. |
| `errors.ssh.output_too_large.title_winrm` | The server sent more data over WinRM than Alice accepts. | Sunucu WinRM üzerinden Alice'in kabul ettiğinden fazla veri gönderdi. |
| `errors.ssh.protocol_error.title_winrm` | Alice could not understand the server's WinRM answer. | Alice sunucunun WinRM yanıtını anlayamadı. |

## Deferred to W8+

- **Settled by W7** (Ruling 27): the WinRM transport (§13 W7), with username and password over NTLMv2.
- **New in W7's deferred list:** PSRP and a JEA endpoint (the only way to limit the WinRM account); Kerberos (and UPN
  usernames); CredSSP; client-certificate mapping; NTLM channel binding (`CbtHardeningLevel` Strict); tlspin's
  CA-bundle mode for a WinRM listener; Alice rotating the Windows password; removing a WinRM password; changing a
  target's transport; refusing a second target for one host across transports; a domain account tested on a runner;
  Server Core and Windows Server 2019 over WinRM (manual matrix); the reaping of an undeleted shell and the
  `IdleTimeOut` clamp (F27, not measurable as the test account).
- **Carried unchanged from [Deferred to W7+](#deferred-to-w7):** everything under "Not in W6"; W5's deferred items;
  R70's "Not in this batch" boundary (class B and C); the items R70 declined; the W6 owner items and W6 residual risks
  1-6, 8 and 9.
- **Minors deferred during W7 (known debt):**
  - `ConfigSchema`'s port default is 22 under WinRM too; the form sets 5986 (Task 5).
  - `ntlm.go`'s `field()` converts a `uint32` to `int` (32-bit only; test-only emulator; Task 1-2).
  - `sshRun`'s context-ended-after-acquire branch is untested; the WinRM crash table does not assert "sent once"; a
    WinRM error returns an empty `HostKey` (Task 6).
  - The emulator answers an oversized Send with a WS-Man fault; Windows answers HTTP 413 (F26); the other emulator
    fault codes are placeholders (Task 3).
  - The shared deny-rights fragment is not idempotent (Ruling 18; W1 code).
  - No hint after a failed connection test that follows the password; leaving the WinRM phase of the dialog leaves
    the password missing; the RDP `output_too_large` text was added for a source-scanning test; the web passes no
    `from` (Task 8).
  - `WinRMSetupScript`'s doc comment still says "without an address restriction" although it takes `from` (Task 7).
