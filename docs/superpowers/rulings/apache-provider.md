# Rulings: Apache httpd provider, discovery only (Phase B)

Spec `docs/superpowers/specs/2026-10-17-web-server-providers-design.md` (§8 binds), plan
`docs/superpowers/plans/2026-10-17-apache-provider.md`. The plan's Rulings 1–15 stand as written, except that plan
Ruling 5 was amended in the plan itself (Ruling 3 below) and is qualified by Ruling 8 below, and plan Ruling 9's
wording is corrected by Ruling 5 below. Branch `apache-provider` from main 22a2bfcf.

## Rulings made during execution

Each entry: the decision, why, and the cost if it is wrong.

1. **Root-only helper suite is an owner step.** `sudo -E env "PATH=$PATH" go test -count=1 ./cmd/alice-helper/...`
   was not run: sudo needs a password on the build machine. Why: the plan's Global Constraints allow recording it
   instead of skipping it silently. Cost if wrong: a root-only regression of `apache-dump` (or of the shared
   `finishDump`) found later by the owner.
2. **Transient web test failure between Task 1 and Task 3.** `web/src/api/enums.test.ts` failed (3 cases) while the
   new Go `Warn*`/`Unsupported*` constants had no web entries yet; Task 3 owned the web side and had to leave it
   green (it did). Why: the web vocabulary belonged to one task. Cost if wrong: one extra fix round in Task 3.
3. **Plan Ruling 5 amended from real Debian 12 / Rocky 9 probes**
   (`.superpowers/sdd/2026-10-17-apache-provider/apache-probe/`). The Red Hat family runs `/usr/sbin/httpd` directly,
   because its `apachectl` refuses any argument; `-t` does not check that certificate files exist (but see Ruling 8);
   Task 12's invalid-configuration step uses an unknown directive. Why: evidence from the real programs. Cost if
   wrong: none.
4. **`config_file_writable` copy.** "A configuration file used by {{software}} can be changed by users other than
   root: {{path}}" / tr "{{software}} tarafından kullanılan bir yapılandırma dosyası root dışındaki kullanıcılar
   tarafından değiştirilebiliyor: {{path}}". Why: the plan's copy had an article ("A Nginx") that cannot agree with
   every software name. Cost if wrong: a copy tweak.
5. **Plan Ruling 9 wording corrected to mod_ssl's index merge.** The effective certificate and key lists of a
   `<VirtualHost>` follow `modssl_ctx_cfg_merge_certkeys_array`: position by position, so a vhost with one
   `SSLCertificateFile` still inherits the main server's second and later entries. The plan said "the vhost's own
   list, else the main server's". Why: verified in the httpd source; the implementation was right. Cost if wrong:
   none.
6. **Task 6 minors folded into its fix round.** `${}` in a directive name is uncertain, the define seed is "maybe",
   once a list holds a conditional entry every later entry of it is conditional (index shift), an `SSLEngine` with an
   address form is uncertain, a wildcard vhost's name inheritance, and `[::]` becomes `""`. Why: cheap fidelity on
   hostile input. Cost if wrong: slightly more conservative results (more `conditional` places).
7. **`envvars` sourcing is an accepted, documented risk, not pre-checked in Phase B.** The helper runs
   `apache2ctl`/`httpd` as root without first checking that the control program, `/etc/apache2/envvars` and the
   `apache2` binary are root-controlled, as it runs Nginx's binary. Why: the reviewer showed no new privilege
   boundary: Apache's `LoadModule` (like Nginx's `load_module`) already runs configuration-chosen code as root at
   `-t`. A writable `envvars` is not reported. Recorded in `SECURITY-REPORT.md` KI-40 and the guide (keep them
   root-only). Cost if wrong: a later hardening task adding root-control pre-checks for the Nginx and Apache programs
   together.
8. **A missing `SSLCertificateFile` target is version-dependent in dump mode.** Apache 2.4.52 (Ubuntu 22.04):
   `-D DUMP_* -t` refuses, so Alice reports the configuration invalid (`syntax`) with no locations. Apache 2.4.62
   (Rocky 9) and 2.4.68 (Debian 12): the dump runs pass and the location's certificate is `missing`. A plain `-t`
   refuses on all three. Accepted and documented (guide, KI-40); no fifth plain `-t` run. Why: both outcomes are
   truthful, and a plain `-t` would hide the `missing` location detail on newer versions. Cost if wrong: an extra run
   added later. `internal/providers/apache:TestRealApache` pins the verdict per image (`raChecksCertInDump`).

## Accepted deviations from the plan

- **Task 2:** reopened once (fix round 1) after Task 4 found `internal/api:TestJobResultReasonsAreRegistered`
  failing; the fix was a test-only `notReasons` entry.
- **Task 5 (`apacheconf` output and lexer):** `\\` becomes `\` inside quotes, as Apache's `substring_conf` does;
  section balance is checked per file; a blank line in the tool output is strict `ErrOutput`.
- **Task 6 (`apacheconf.Parse`):** the index shift of Ruling 6; `MaxPairs = 65536` (more pairs across all servers
  is `ErrTooComplex`); a relative SSL path without `ServerRoot` in `DUMP_RUN_CFG` is `path_not_allowed` (the input
  carries no `HTTPD_ROOT`, and `DUMP_RUN_CFG` always prints `ServerRoot`).
- **Task 7 (`apache-dump`):**
  - New `apacheconf.ErrName` separates a well-formed include line with a path the helper cannot use (unsupported
    `name_not_allowed`) from malformed output (`ErrOutput`, untrusted `unexpected_text`).
  - The describe loop is shared by `nginx-dump` and `apache-dump` (`finishDump`) instead of a copy; the emulator
    keeps its own loop (plan Ruling 12 still holds).
  - An empty `-V` configuration path is unsupported `no_conf_path`, as for Nginx.
  - A `-V` failure other than "missing" or "killed" is `IO_ERROR`, as for Nginx.
  - After a writable file was read, every later read failure and every parse failure is untrusted `changed` naming
    that file (masking ported from Nginx's `authenticate`).
  - `TestApacheDumpWritesNothing` compares mtime, size and mode, not ctime.
  - `openLinked(true)` accepts a hard-linked configuration file that is parsed (Nginx only compares): a hard link
    needs a writable directory, and the walk accepts only root-controlled ones.
- **Task 11:** the "Settings" control is named "Verification settings: …" in the UI; the conditional row has no
  Deploy control at all (unsupported rows have none).
- **Task 12:** step 5 is pinned per image (Ruling 8); `TestRealApache` was added to `test/matrix/traceability.json`
  F-20 in Task 14, not Task 12.
- **Task 13:** fixes outside the brief: `web/e2e/phase4.spec.ts` expects helper protocol 8; the release harness
  copies `internal/providers/apacheconf` into the e2e-target build context. The e2e Apache vhosts declare
  `Listen 8443`; `afterAll` restores the Nginx profile with the script captured during the test.
- **Commit trailers:** commits `a05a5cfc` (Task 8) and `2cfff217` (Task 9) carry "Claude Sonnet 5.5" instead of the
  rules file's trailer; they cannot be amended on a shared branch.

## Deferred minors

### Fixed in Task 14 (comments only, no behaviour change)

- `internal/providers/types.go`: the `WebServerFacts.Software` comment names `apache` as shipped.
- `cmd/alice-helper/rootpath.go`: the `openLinked` comment says `anyLinks` also covers Apache's parsed include-tree
  files, and why that is safe.
- `internal/providers/apache/containers_integration_test.go`: the `readOnly` comment says Apache's runtime and lock
  directories under `/run` and `/var` are out of its scope.
- `internal/providers/linuxssh/setup.go`: the sudoers header comment names the three profiles.

### Fix later

- `apacheconf`: a continuation line after a double backslash is not verified against `ap_cfg_getline_core` (Task 5).
- `apacheconf`: a conditional entry in a vhost's list may shift the inherited main-server entries in the merge
  without marking them conditional; a hidden section name that expands to `VirtualHost` is only uncertain (Task 6).
- `TestApacheDumpWritesNothing` ignores ctime (the chmod round trip of its outcomes changes it) (Task 7).
- Emulator: the include tree lists `emu.conf` only when sites exist; `SetApacheConfig` overrides are never cleared
  (Task 8).
- `raChecksCertInDump` is pinned per image while the distribution packages are unpinned: a package update can flip
  the verdict and fail `make test-ssh` until the table is updated (Task 12).
- e2e: the "no deploy wording" check is a heuristic (the first word of `deploy.submit`, with the SSH-keys table
  carved out) (Task 13).
- `web/src/theme.test.ts`: the Tooltip colour check is convoluted (Task 3).
- e2e flakes seen once in the full run, both green alone: `phase5.spec.ts:610` (tr, colour contrast at 640 px) and
  `phase9.spec.ts:225` (en, clipped focus ring on `/key-vaults` at 390 px).

### Dropped (with reason)

- Guard bridge (`ReasonConditional` as a literal, no `os.Stat` fallback): done in Task 6.
- `HelperProtocol` concurrent first calls may both ask `version`: harmless, the answer is the same.
- `AuditPage.test.tsx` `PHASE3_ACTIONS` comment now covers a Phase B action: the test still labels every action;
  cosmetic.
- Theoretical startup lock order of the capability sync against the audit chain lock: only another process could
  contend, and v1 runs one `alice` process (KI-39).
- `CodeSoftwareNotFound` gofmt realignment noise: gofmt output.
- `types.ts` `apache?` optional: tightened in Task 11 (`Record<'linux' | WebServerType, SetupSnippet>`).
- Repository doc paths as plain text in locale actions: the existing convention of every error text.

## Carried to Phase C (HAProxy)

- **Owner decision 2026-10-17: do not start Phase C after Phase B** until the owner says so.
- Pin `migrations/00017_apache.sql` in `migrations/frozen_test.go` in Phase C's first task (as 00016 was pinned in
  Phase B Task 1); every Phase C schema change goes in a new migration. `migrations/roles_integration_test.go`'s
  `hasApacheType` matches the `targets_type_check` text with `LIKE`: re-check it when the CHECK gains `haproxy`.
- Helper: protocol 9 / 1.8.0 per the spec; reuse `SOFTWARE_NOT_FOUND`, `webserver.Spec.NotFoundCode` and
  `MinProtocol`; `helper_too_old` and the `web_server_helper_too_old` warning work for any kind.
- The single type list (`inventory.webServerTypes`, `WEB_SERVER_TYPES`), `providers.KindForTargetType`, registration
  in `cmd/alice`, the vocabulary guard's union (`webserver/guard_test.go`) and the TS source guard must gain the new
  type; capability sync covers it without a migration.
- If HAProxy is discovery only too, `DISCOVERY_ONLY_TEXTS` and the disabled note already follow
  `can(target, 'deploy_certificate')`.
- The root-control pre-check of the control programs (Ruling 7) should cover Nginx, Apache and HAProxy together.
- A fifth plain `-t` run (Ruling 8) remains an option if the version-dependent verdict confuses customers.
- The e2e and real-matrix images' Nginx owns ports 80 and 443 and Apache is never started: HAProxy fixtures need the
  same discipline (other ports, never started, or started only in an isolated step).

## Owner steps

1. Run the root-only helper suite on a machine where sudo works:
   `sudo -E env "PATH=$PATH" go test -count=1 ./cmd/alice-helper/...` (Ruling 1).
2. Review a real customer Apache configuration with `apache-dump`: compare the websites and certificates Alice lists
   with what the running Apache serves, especially configurations with `<If>`, `Use`/`<Macro>`, `envvars`
   variables, command-line defines (`$OPTIONS`, `-DFOREGROUND`) and certificates inherited from the main server.
3. Reinstall `alice-helper` 1.7.0 on servers that will be Apache servers (CHANGELOG upgrade notes).

## Final gates (Task 15, 2026-10-17)

- Static and unit: `go build`, `go vet` (both tag sets), `make lint`, `make test`, `make i18n-check`: pass.
- `make test-integration`: pass. `make coverage`: pass on the second run. The first run failed once in
  `internal/backup` `TestStopLeavesNoSession` (a session of closed pools still listed under load; unrelated, passes
  alone and in `make test-integration`). Floors: `apache` 100.0 (98), `apacheconf` 100.0 (92), `webserver` 98.6 (98),
  `cmd/alice-helper` 91.0 (90).
- `make test-ssh`: pass (OpenSSH, Nginx and Apache real matrices, none skipped).
- `make helper` checksums: linux-amd64 `e758ca8b92d9cb9eca5a5220fb070fc22e18c6cdcebd3d29db049fa86cba9df4`,
  linux-arm64 `504190c8cba8167c1da36d03b267bcc73b73574a633d41cbbd4374dbb953f8c9`. The root-only helper suite
  was not run (sudo needs a password): owner step 1 stays open.
- `make fuzz-apache FUZZTIME=5m`: both targets pass, no crasher.
- `make web-lint web-coverage`: pass (statements 96.42 %, branches 92.73 %). `make e2e`: 143 passed, 4 skipped
  (the design-evidence specs, skipped by design), no failures or retries.
- Grep checks: both print nothing.
