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
    a `windows` profile without a script is `ErrNoSetupScript`. Amended by the Task 10 rulings below.
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
- Real-runner acceptance (design §13 W1 item 4): pending — filled in by Task 17
