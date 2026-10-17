# Apache httpd Provider (Phase B, discovery only) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Apache httpd as a discovery-only web-server target type `apache`. Alice connects over SSH, shows the software, its version and whether its configuration is valid, and lists the certificate files Apache uses (with their sites) in the inventory, alerts and reports like Nginx's. The page is Nginx's, with deployment shown disabled. Before that, the four Phase A Important items settled by spec §8 are implemented.

**Architecture:** First, the shared layer changes (§8.1–8.4): `targets.capabilities` is rewritten from the registry at startup; `webserver.Spec` works without a test subcommand and gains `NotFoundCode` and `MinProtocol` (helper too old becomes `<kind>.helper_too_old`); the disabled-feature note can be reached by keyboard; shared texts follow `can(target, 'deploy_certificate')`. Then Apache. A pure parser package `internal/providers/apacheconf` reads what `apachectl` prints (`-V`, `-D DUMP_INCLUDES -t`, `-D DUMP_MODULES -t`, `-D DUMP_RUN_CFG -t`) and the configuration files the helper reads through its root-controlled walk. The new read-only helper subcommand `apache-dump` (protocol 8, helper 1.7.0) answers `helperproto.ServerDumpResponse`. `internal/providers/apache` is a `webserver.Spec` plus registration. Migration 00017 adds the type and the grant the capability sync needs.

**Tech Stack:** Go 1.27 (pgx/v5, goose, testcontainers), PostgreSQL, React 18 + Mantine + TanStack Query + i18next, Vitest, Playwright, Docker images pinned by digest.

**Spec:** `docs/superpowers/specs/2026-10-17-web-server-providers-design.md` (Phase B row of §2; §1, §4, §4.1, §5, §6, §7, and §8, which binds this phase). Phase A results and carries: `docs/superpowers/rulings/web-server-standard.md`. Conventions: `docs/superpowers/plans/2026-10-17-web-server-standard.md`.

## Global Constraints

- Branch `apache-provider` (already checked out). Never switch branches. Phase B must not add `haproxy` anything (Phase C).
- Helper: `helperproto.Protocol = 8`, `helperproto.Version = "1.7.0"`, `helperproto.MinProtocol` stays `6`, new `helperproto.ApacheMinProtocol = 8`. The new subcommand is `apache-dump` (`helperproto.SubApacheDump`). It takes no arguments, runs as root through sudo, and is **read-only**: it writes, renames and chmods nothing. The control script it runs may create Apache's own runtime directory, as on every start. Helper code is "software not installed" = `helperproto.CodeSoftwareNotFound = "SOFTWARE_NOT_FOUND"` (spec §8.2). Nginx keeps `NGINX_NOT_FOUND` and every `nginx-*` name. JSON tags of `ServerDumpResponse` and its parts stay unchanged.
- Any helper change needs, before its task closes: the root-only suite (`sudo -E env "PATH=$PATH" go test -count=1 ./cmd/alice-helper/...`), `make helper` (new `bin/alice-helper.sha256`; `bin/` is not tracked), and `make test-ssh` (Task 12 adds Apache to it). If the agent cannot run sudo without a password, it records the root-only run as an owner step in the rulings file and does not skip it silently.
- Migrations `00001`–`00015` are pinned in `migrations/frozen_test.go:18-34`. **00016 gets pinned in Task 1.** Ruling: the spec forbids editing an earlier phase's migration (§3.2 "never an edit of an earlier one"), and pinning enforces that. Every Phase B schema change goes in `migrations/00017_apache.sql`, which stays unpinned. It is written like 00016 (`-- +goose Up`/`-- +goose Down`; `StatementBegin/End` only around `DO` bodies) and runs as `alice_owner`.
- Commits: `git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only -m "..." -- <paths>` (`-m` before `--`). Stage only by explicit path. A new file is `git add -- <path>` first. Never `git add -A`/`.`. Check `git status --short` before committing. Never touch `.claude/`, `Alice-Proje-Dokumani.pdf` or the untracked files under `docs/security/reviews/`. Every message ends with a blank line and `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Verification commands: `go build ./... && go vet ./... && go vet -tags integration ./...`; `go test -race -count=1 ./<pkgs>`; `go test -race -count=1 -tags integration ./<pkgs>` (Docker); `make lint` (pincheck, shellcheck, docs-check, matrix-check `-strict`, golangci-lint with build-tag variants); `make test`; `make test-integration`; `make coverage` (enforces `coverage-floors.json`); `make i18n-check`; web: `cd web && npx vitest run <files>`, `npm run lint`, `npx tsc --noEmit`, `make web-coverage`; e2e: `make e2e-up && make e2e; make e2e-down`; real matrix: `make test-ssh` (`ALICE_SSH_IMAGES=ubuntu22` limits it while iterating).
- Docker-based Go runs (`-tags integration`, `make test-integration`, `make coverage`, `make test-ssh`, `make perf`) never run while Playwright runs, and the other way round.
- Coverage floors are never lowered. New floors: `"alice/internal/providers/apache": 98`, `"alice/internal/providers/apacheconf": 92`. Existing ones stay: `webserver` 98, `nginx` 98, `providers` 100, `helperproto` 100, `targetjobs` 100, `cmd/alice-helper` 90, `linuxssh` 93. Web thresholds in `web/vite.config.ts` are never lowered.
- Build inputs stay pinned (`tools/pincheck` in `make lint`). No new base image. Distribution packages are added to the existing digest-pinned images the way nginx was (unversioned `apt-get`/`dnf` names in the same `RUN`). `StrictHostKeyChecking=no` anywhere fails a test (existing guard).
- There is one list of web-server types: Go `inventory.webServerTypes` (`internal/inventory/types.go:33`) and TS `WEB_SERVER_TYPES` (`web/src/api/webServer.ts:4`). Phase B also extends `providers.KindForTargetType` (`internal/providers/provider.go:41`), the `targets.type` CHECK (00017) and registration (`cmd/alice/providers.go`, `cmd/alice/wiring.go:12`). No component or handler decides availability by a type literal.
- Locale texts exist in `en` and `tr`, in `locales/common` (server) and `web/src/locales` (web), with identical keys and placeholders. Turkish never puts a suffix on `{{software}}` ("{{software}} yapılandırması", never "{{software}}'nin"). The display name of the software is `Apache` (`webServer.software.apache`). The disabled note stays exactly `"Not available for {{software}} servers yet"` / `"{{software}} sunucularında henüz kullanılamıyor"`.
- Error codes `ALC-APC-0001` `apache.not_found` (502), `ALC-APC-0002` `apache.config_invalid` (409), `ALC-APC-0003` `apache.profile_missing` (502), `ALC-APC-0004` `apache.helper_too_old` (502). Each has `errors.<reason>.{title,cause,action}` in `locales/common` en/tr and a section in `docs/troubleshooting.md`.
- `test/matrix/traceability.json` names tests by package. Existing names stay. After editing it, regenerate with `go run ./tools/matrixcheck -spec docs/superpowers/specs/alice-v1/06-quality.md -map test/matrix/traceability.json -doc docs/security/traceability.md -update`.

## Rulings (where the spec leaves room or does not match the code)

1. **Capability sync (§8.1):** `inventory.(*Service).SyncCapabilities(ctx) (changed int, err error)` runs in `serve` right after `checkWiring` (`cmd/alice/main.go:301`) and before `runner.Recover`. In one transaction it sets `capabilities` to the registered provider's `Sorted()` set for each type `KindForTargetType` maps to a registered kind, with `UPDATE … WHERE type = $1 AND deleted_at IS NULL AND capabilities IS DISTINCT FROM $2`. When the sum of rows affected is above 0, it appends one audit row: `Actor: audit.SystemActor("startup")`, `Action: "target.capabilities_synced"`, `Result: Success`, `Details{"targets": "<n>"}`. `version` and `updated_at` do not change: capabilities are not part of the editable resource. `alice_app` has no UPDATE on `targets.capabilities` today (`migrations/00005_inventory_jobs.sql:212-213`), so 00017 adds `GRANT UPDATE (capabilities) ON targets TO alice_app`.
2. **Migration 00017** (`00017_apache.sql`). Up: replace `targets_type_check` with `type IN ('nginx', 'apache', 'linux', 'azure_key_vault')` and add the grant. Down: a `DO` block raises `Z1008` (`'cannot migrate down: Apache servers exist (targets of type apache, deleted ones included); restore a backup taken before 00017'`) when any `targets` row has `type = 'apache'`. Targets are never hard-deleted, so the Down cannot remove them without losing history. Otherwise the Down revokes the grant and restores the 00016 CHECK. This follows 00008's precedent (`migrations/00008_key_vault.sql:284-296`).
3. **`webserver.Spec` (§8.2):** `Test` is optional. New field `NotFoundCode string` is required. New field `MinProtocol int` is required, and `NewBase` panics below `helperproto.MinProtocol`. Nginx's spec gets `NotFoundCode: helperproto.CodeNginxNotFound, MinProtocol: helperproto.MinProtocol`. `ServerDumpResponse` has no `Found` field: a found server is a successful dump, and "not found" is the helper error `NotFoundCode`.
4. **Helper too old:** `Session` reads the protocol of its connection through the new `linuxssh.(*Conn).HelperProtocol(ctx) (int, error)`. This refactors `requireHTTP01`'s lookup, `internal/providers/linuxssh/http01.go:70-87`. Below `Spec.MinProtocol`, `Discover` (certificate half) returns `providers.NewError(kind.Reason("helper_too_old"), false, nil, {"helper_protocol", "required_protocol"})`. `TestConnection` does **not** fail ("not a failure", §4): it returns the linuxssh report, adds the warning `web_server_helper_too_old` and leaves `WebServer` nil. `jobs/targetjobs` treats `<kind>.helper_too_old` like `<kind>.profile_missing`: SSH keys are still scanned, no facts, and the warning `web_server_helper_too_old` is added. Web `DeployBlock` gains `'helper_too_old'`, ordered after `profile_missing`.
5. **Control program invocations (amended 2026-10-17 from real Debian 12 / Rocky 9 output, `.superpowers/sdd/2026-10-17-apache-provider/apache-probe/`).** Debian/Ubuntu: `/usr/sbin/apache2ctl` when `lstat` finds it (it sources `/etc/apache2/envvars` and passes every argument to `apache2`). RHEL family: **`/usr/sbin/httpd` directly** — Rocky 9's `apachectl` refuses any extra argument ("Passing arguments to httpd using apachectl is no longer supported", exit 1), so it is never used. Neither present: `SOFTWARE_NOT_FOUND`. It runs through the existing `runProgram` (fixed env `PATH`, `LANG=C`, dir `/`, umask 022, 30 s, stdout capped at `MaxServerConfig`). The four runs, in order, are `-V`, `-D DUMP_INCLUDES -t`, `-D DUMP_MODULES -t` and `-D DUMP_RUN_CFG -t` (`-D` first, harmless for both). stderr carries `AH00558` notices and `Syntax OK` and is never used. A `-V` without a parsable `Server version: Apache/<v>` line means `SOFTWARE_NOT_FOUND` (precondition). A non-zero exit of the `DUMP_INCLUDES` run means the configuration is invalid with class `syntax` (§8.2: nothing else of the output is used). A non-zero exit of a later run is also `syntax`, since the configuration changed between runs. A killed or timed-out run is `IO_ERROR`. **`-t` does not check that certificate files exist** (a missing `SSLCertificateFile` target still exits 0): such a pair is a location whose certificate file is `missing`, as for Nginx.
6. **Parsing the tool output** (`apacheconf`):
   - `ParseV`: version from `Server version: Apache/<v> …`, with nginx's version character rule. ConfPath is `-D SERVER_CONFIG_FILE="…"`, joined to `-D HTTPD_ROOT="…"` when relative, and `""` unless `helperproto.ValidPath`.
   - `ParseIncludes`: the header `Included configuration files:`, then one line per file. Each line is `2+2k` spaces, then `(*)` (root, exactly once, first) or `(<n>)` (the line number in the parent file of the `Include`/`IncludeOptional` that loaded it), a space, and the absolute path. Depth `k` may grow by at most 1 per line. The parent is the nearest earlier line at depth `k-1`. A line exactly `Syntax OK` is ignored. Anything else is `ErrOutput`.
   - `ParseModules`: lines ` <name> (static|shared)` after `Loaded Modules:`.
   - `ParseRunConfig`: `ServerRoot: "<path>"`, and `Define: NAME` or `Define: NAME=VALUE` lines. `DUMP_RUN_CFG` and the other `DUMP_*` defines are dropped. Other lines are ignored.
7. **Reading the configuration.** The helper reads every file of the include tree through `walkRoot` and `openLinked(true)`, the same way as nginx's configuration sections (`cmd/alice-helper/nginx.go:264-288`). Limits: at most `apacheconf.MaxFiles = 4096` tree entries and `MaxServerConfig` bytes in total. The tree's root must equal the `-V` ConfPath, otherwise the result is untrusted `wrong_first_file`. A walk failure is untrusted, with `walkReason`, naming the file through `carried`. A name outside the vocabulary is unsupported `name_not_allowed`. A file listed twice is parsed twice: Apache allows that, so it is not `duplicate_file`. **Writable files:** if any loaded file is owned by someone other than root or is group/other-writable, every supported pair becomes `config_file_writable` (`apacheconf.MarkWritable`), and `Writable` lists those files. This is coarser than nginx's per-pair rule because Apache's `Define`/`Include` reach is global. It is acceptable for a discovery-only provider (documented).
8. **Parser semantics** (`apacheconf.Parse`):
   - Logical lines join a trailing `\` with the next line.
   - `#` starts a comment only as the first non-blank character.
   - Arguments follow `ap_getword_conf`: whitespace splits, `"…"` or `'…'` group words, and inside quotes a backslash before the quote character is that character (any other backslash is literal).
   - Directive and section names are case-insensitive.
   - An `Include`/`IncludeOptional` directive whose **last** physical line is `n` is replaced by the tree children of that file with line `n`, in tree order (Apache reports the last line of a continued directive). A tree child that matches no `Include` directive the parser reached is `ErrIncludeMismatch`, which the helper reports as untrusted `changed`.
   - `<IfModule [!]x>` is true when `x` (as `x_module`, or `mod_foo.c` mapped by `ModuleName`) is among the `(static)` modules of `-M` or was named by an earlier `LoadModule` in read order. This is Apache's own read-time rule. `ModuleName` maps `mod_<x>.c` to `<x>_module` and has a fixed table: `core.c`→`core_module`, `http_core.c`→`http_module`, `prefork.c`→`mpm_prefork_module`, `worker.c`→`mpm_worker_module`, `event.c`→`mpm_event_module`. A name it cannot map makes the region **uncertain**.
   - `<IfDefine [!]X>` is evaluated against the defines in read order. The seed is the `DUMP_RUN_CFG` defines that no `Define` directive of the configuration sets (these come from the command line). `Define X [v]` and `UnDefine X` apply as read.
   - `<IfVersion [!][op] v>` is evaluated for `=`, `==`, `<`, `<=`, `>`, `>=` against the `-V` version. A regex form (`~`, `/…/`) is uncertain.
   - `<If>`, `<ElseIf>`, `<Else>`, `<IfFile>`, `<IfDirective>`, `<IfSection>` and any other `<If…>` are uncertain.
   - A pair whose cert or key directive lies in an uncertain region (at any depth) is unsupported `conditional`. A false region is skipped, except that its `Include` lines must have no tree children.
   - Other sections (`<Directory>`, `<Location>`, `<Files>`, `<Proxy>`, `<Macro>`, …) are descended for `Include` splicing only. `Use`/`<Macro>` are not expanded (documented limitation).
   - `${VAR}` expands from the current defines in `SSLCertificate*File`, `ServerName`, `ServerAlias` and `<VirtualHost>` arguments. An undefined one makes the pair `variable`, keeps a name raw, and drops the listen.
   - Relative SSL paths resolve against `RunConfig.ServerRoot` (or the directory of `HTTPD_ROOT` when absent) with nginx's `resolvePath` rule (no `.`/`..` segment, `ValidPath`, not `/`). A failure is `path_not_allowed`.
9. **Servers and pairs.**
   - A `<VirtualHost a[:p] …>` is listed when its effective `SSLEngine` is `on` (case-insensitive; `optional` is not on) and it has at least one effective `SSLCertificateFile`. Effective follows mod_ssl's merge: the vhost's own `SSLEngine`/certificate list/key list when it sets one, else the main server's. `Inherited` is true when a list came from the main server.
   - Pair `i` is `(cert[i], key[i])`. Without `key[i]`, the key is in the certificate file (`Key = Cert`, spec §4.1): a supported pair, **not** nginx's `combined_file`.
   - `File`/`Line` are the `<VirtualHost` line. `Names` are `ServerName` (scheme and `:port` stripped) followed by the `ServerAlias` arguments.
   - `Listens` hold one entry per address. `*`, `_default_` and `0.0.0.0` become `""`. `[v6]:p` is unwrapped. A missing or `*` port drops the entry. `Default` is true for `_default_` and for the first vhost of each addr:port in read order (Apache's default-vhost rule).
   - The main server is listed (`Main: true`) only when it has its own `SSLEngine on` and certificates. Its `File`/`Line` are its first `SSLCertificateFile`, its names its `ServerName`, and its `Listens` empty.
10. **`SSLCertificateChainFile`** is parsed and ignored: it is not described, not a location, and not on the wire. The location's chain is the certificate file's chain (documented). The wire format stays unchanged.
11. **What does not apply to Apache:** `stream`, `mail_tls`/`stream_tls`, `data_value`, `engine_key`, `password_file` (`SSLPassPhraseDialog` is not read), `key_missing` and `combined_file`. The new unsupported reason is `providers.UnsupportedConditional = "conditional"`, used by `apacheconf` only. `webserver.pairReasons` gains it. The vocabulary guard (`internal/providers/webserver/guard_test.go:67-77`) compares `pairReasons` with the union of `nginxconf.Reason*` and `apacheconf.Reason*`.
12. **Emulator and helper share the wire mapping:** `apacheconf.ToWire(Server) helperproto.DumpServer` and `Config.CertPaths/KeyPaths` are pure and used by both. Each side keeps its own describe loop, ported from the nginx one, and the fidelity test compares the two.
13. **e2e and the real matrix never start Apache.** Discovery only reads the configuration, and the images' Nginx owns ports 80/443. The e2e Apache vhosts use port 8443.
14. **Texts that follow capabilities (§8.4).** `web/src/api/capabilities.ts` gets `capabilityText(target, key): string`. It returns `DISCOVERY_ONLY_TEXTS[key]` when the target cannot `deploy_certificate` and the key is in that map, else `key`. The map covers `warnings.web_server_config_invalid`, `locations.configInvalid`, `locations.intro` and `targets.page.operationsText`. `locations.deployUnavailable` is not rendered for a discovery-only target. `warnings.config_file_writable` is reworded with `{{software}}` (Phase A Ruling 11). Exact new copy is in Task 3.
15. **Setup UI options come from the type list.** `AddServerModal` and `PlatformKeyPanel` build their web-server options from `WEB_SERVER_TYPES` with `t('targets.form.typeWebServer', { software })` / `t('targets.prepare.profileWebServer', { software })` ("{{software}} server" / "{{software}} sunucusu"). `typeNginx`/`profileNginx` are removed: the rendered English is unchanged. The TS source guard (`web/src/api/webServer.test.ts`) then checks every type of `WEB_SERVER_TYPES`, and its allow-list shrinks to `api/webServer.ts`.

## Review Focus

1. **An existing installation upgrades and restarts twice.** The first start brings every live target's capabilities to its provider's set (for example an Nginx target whose stored set lacks a capability) with exactly one audit row. The second start changes nothing and writes no audit row. Deleted targets are untouched (Task 2: `TestSyncCapabilitiesIsIdempotentAndAuditedOnce`).
2. **One host runs both Nginx and Apache and is added as both types** (`targets_endpoint_live` is per type). Each target lists only its own software's websites. A certificate file both use is one certificate with two locations (Task 8: `TestApacheAndNginxOnOneHostStaySeparate`).
3. **Apache is installed but `mod_ssl` is not loaded** (Debian's default). The server is found, the configuration is valid, there are no websites and no warning. The page shows the empty-websites state, not an error (Task 6 parser case `ssl_module not loaded`; Task 12 matrix checks the Debian state before `a2enmod ssl`).
4. **A server keeps an older helper (protocol 7).** The connection test succeeds with "update the helper", SSH keys are still scanned, and nothing says Apache is missing (Task 1 `TestHelperTooOldIsAWarningNotAFailure`; Task 1 targetjobs `TestScanFallsBackForEveryWebServerKind` gains the `helper_too_old` case; Task 3 block text).
5. **A combined certificate+key file readable by everyone** (`SSLCertificateFile` only, mode 0644). The location is supported, its certificate is in the inventory, it warns `key_mode_open`, and it is never offered for deployment (Task 9 `TestDiscoverCombinedFileIsSupportedAndWarns`; Task 11 page test: its row's Deploy is disabled with the note).

---

### Task 1: Shared web-server layer for dump-only providers, helper protocol check, Phase A Go carries

**Files:**
- Modify: `internal/providers/webserver/webserver.go:23-63,87-101,167-246` (Spec, SharedReason, NewBase, TestConnection, Discover, package comment)
- Modify: `internal/providers/webserver/convert.go:19-58` (export `MaxChainCerts`, add `UnsupportedConditional` to `pairReasons`, Nginx wording in comments at `:25`, `:51`, `:163`)
- Modify: `internal/providers/nginx/provider.go:20-28` (spec gains `NotFoundCode`, `MinProtocol`), `internal/providers/nginx/verify.go:18-20` (use `webserver.MaxChainCerts`, delete the local const)
- Modify: `internal/providers/provider.go:30-35` (`ReasonHelperTooOld`), `internal/providers/types.go:340-359,404-411` (`UnsupportedConditional`, `WarnWebServerHelperTooOld`; stale "Nginx" comments of `CertLocation`/`DiscoveredCertificate`)
- Modify: `internal/providers/linuxssh/http01.go:70-87`, `internal/providers/linuxssh/dial.go:557-559` (new `HelperProtocol`)
- Modify: `internal/providers/linuxssh/helperproto/helperproto.go:492` (`ServerDumpResponse` doc comment: "answers a web server's dump subcommand")
- Modify: `internal/jobs/targetjobs/targetjobs.go:227-243`
- Modify: `migrations/frozen_test.go:18-34` (pin 00016), `migrations/web_server_integration_test.go:114-118` (`UpTo(16)`)
- Test: `internal/providers/webserver/webserver_test.go`, `internal/providers/webserver/chainrange_test.go`, `internal/providers/linuxssh/http01_test.go`, `internal/jobs/targetjobs/targetjobs_test.go:693-730`, `internal/providers/nginx/provider_test.go`

**Interfaces:**
- Produces (package `webserver`): `type Spec struct { Kind providers.Kind; DisplayNameKey string; Dump, Test func() linuxssh.HelperCommand; NotFoundCode string; MinProtocol int; Subcommands, UsualFolders []string }` (`Test` may be nil); `const MaxChainCerts = 20`.
- Produces (package `providers`): `ReasonHelperTooOld = "helper_too_old"`, `WarnWebServerHelperTooOld = "web_server_helper_too_old"`, `UnsupportedConditional = "conditional"`.
- Produces (package `linuxssh`): `func (c *Conn) HelperProtocol(ctx context.Context) (int, error)`: the protocol stored at `Open`, else asks `version` once and stores it.

- [ ] **Step 1: Write the failing tests** (in `internal/providers/webserver/webserver_test.go` unless noted)
  - `TestNewBaseRefusesAnIncompleteSpec`: drop the "nil Test" panic row and add a `NotPanics` row with `Test = nil`. Add panic rows "empty NotFoundCode" and "MinProtocol below helperproto.MinProtocol" (`s.MinProtocol = helperproto.MinProtocol - 1`). `testSpec()` (`helpers_test.go:36-41`) gains `NotFoundCode: helperproto.CodeNginxNotFound, MinProtocol: helperproto.MinProtocol`.
  - `TestTestConnectionFromTheDump`: a spec with `Test: nil` and `Dump: linuxssh.CmdNginxDump` against `newEnv(t, true)` gives `rep.WebServer == &providers.WebServerFacts{Software: "nginx", Found: true, Version: "1.22.1", ConfPath: <emulator conf path>, ConfigValid: true}` and no warnings. With `emu.SetConfigInvalid(helperproto.ConfigErrSyntax)` (`linuxsshtest/nginx.go:370`) it gives `ConfigValid: false`, `ConfigError: "syntax"` and the warning `web_server_config_invalid`. With `newEnv(t, false)` it gives `WebServer == &{Software: "nginx"}` and the warning `web_server_not_found`.
  - `TestSharedReasonUsesTheSpecsNotFoundCode`: a spec with `NotFoundCode: "SOFTWARE_NOT_FOUND"` maps a `helper_code=SOFTWARE_NOT_FOUND` refusal to `nginx.not_found` and leaves `NGINX_NOT_FOUND` unmapped (nil).
  - `TestHelperTooOldIsAWarningNotAFailure`: `emu.SetProtocol(helperproto.MinProtocol)`, spec `MinProtocol: helperproto.MinProtocol + 1`. `TestConnection` returns `err == nil`, a nil `WebServer` and warning codes `["web_server_helper_too_old"]`. `Discover(Certificates: true)` returns a `*providers.Error` with `Code == "nginx.helper_too_old"` and `Params == {"helper_protocol": "6", "required_protocol": "7"}`, and the emulator saw no `nginx-dump` call (count the calls through the emulator's command log, as the existing tests do). `Discover(SSHKeys only)` still succeeds.
  - `internal/providers/linuxssh/http01_test.go`: `TestHelperProtocolIsAskedOnce`. A `Conn` that did not go through `Open` asks `version` once; a second call reuses the stored value.
  - `chainrange_test.go`: `MaxChainCerts == 20`. `nginx/verify_test.go`: a probe reporting `ChainLength = webserver.MaxChainCerts + 1` is refused (rename the existing assertion's constant).
  - `targetjobs_test.go:693` `TestScanFallsBackForEveryWebServerKind`: add `run(providers.KindNginx, inventory.TypeNginx, "nginx.helper_too_old")`, which gives no error, 2 requests, nil `WebServer`, and warning `web_server_helper_too_old`.

- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./internal/providers/webserver/ ./internal/providers/linuxssh/ ./internal/jobs/targetjobs/ ./internal/providers/nginx/`
Expected: FAIL (`unknown field NotFoundCode`, `undefined: MaxChainCerts`, `undefined: (*Conn).HelperProtocol`).

- [ ] **Step 3: Implement**
  - `Spec` fields as in Interfaces. `NewBase` panics on `NotFoundCode == ""` and `MinProtocol < helperproto.MinProtocol`.
  - `SharedReason` uses `s.NotFoundCode` where it used `CodeNginxNotFound` (`webserver.go:57`).
  - `requireProtocol(ctx)` on `Session` returns `<kind>.helper_too_old` below `MinProtocol`. `Discover` calls it before the dump. `TestConnection` calls it after linuxssh's test and turns that error into the warning (Ruling 4).
  - `TestConnection` with `Test == nil` runs `Dump`, decodes `ServerDumpResponse`, uses `webServerFacts` for the facts, and warns `config_invalid` when not valid. With `Test != nil` it keeps today's path but checks `NotFoundCode`.
  - `HelperProtocol`: `requireHTTP01` becomes `p, err := c.HelperProtocol(ctx)` plus its comparison.
  - targetjobs: add `isCode(err, kind.Reason(providers.ReasonHelperTooOld))` to the fallback condition. The warning is `WarnWebServerHelperTooOld` when that code matched, and no facts are set.
  - Pin 00016: add `"00016_web_server_standard.sql": "<sha256sum of the file on this branch>"` to `frozen`. Change `web_server_integration_test.go:114` `p.Up(ctx)` to `p.UpTo(ctx, 16)`.

- [ ] **Step 4: Run the tests**
Run: `go build ./... && go vet ./... && go test -race -count=1 ./internal/providers/... ./internal/jobs/targetjobs/ ./migrations/ -run 'Frozen|.' && go test -race -count=1 -tags integration ./migrations/ -run 'WebServer|Frozen'`
Expected: PASS.

- [ ] **Step 5: Commit** (files above): `feat(webserver): a Spec may test from its dump, names its not-found code and minimum helper protocol; helper_too_old is a warning (spec §8.2)`

---

### Task 2: Migration 00017 and the startup capability sync (spec §8.1)

**Files:**
- Create: `migrations/00017_apache.sql`, `migrations/apache_integration_test.go`
- Create: `internal/inventory/capabilities_sync.go`, `internal/inventory/capabilities_sync_integration_test.go`
- Modify: `migrations/roles_integration_test.go:165-166` (`capabilities` in the targets UPDATE columns)
- Modify: `cmd/alice/main.go:299-303`, `cmd/alice/serve_integration_test.go`
- Modify: `web/src/locales/en.json`, `web/src/locales/tr.json` (`audit.actions.target_capabilities_synced`), `web/src/pages/AuditPage.test.tsx` (the action is labelled)
- Modify: `web/src/api/capabilities.ts:33-36` (comment: the server refreshes the set at startup)

**Interfaces:**
- Consumes: `providers.KindForTargetType`, `providers.Registry.Get`, `CapabilitySet.Sorted()`.
- Produces: `func (s *Service) SyncCapabilities(ctx context.Context) (int, error)`; audit action `target.capabilities_synced`.

- [ ] **Step 1: Write the failing tests**
  - `migrations/apache_integration_test.go`, `TestMigration00017`:
    - After `UpTo(17)`, an `apache` target inserts, and `UPDATE targets SET capabilities = …` as `alice_app` succeeds. Use non-empty warning `Params` in its seeded facts (Phase A carry): `'{"warnings":[{"Code":"web_server_not_found","Params":{"software":"apache"}}]}'`.
    - `DownTo(16)` with that row fails with SQLSTATE `Z1008`.
    - With no apache row, `DownTo(16)` succeeds: a type `apache` insert is refused, `alice_app` can no longer update `capabilities` (`permission denied`), and `grantProblems` is empty.
    - `Up` again succeeds.
  - `capabilities_sync_integration_test.go`, `TestSyncCapabilitiesIsIdempotentAndAuditedOnce`:
    - Seed a live nginx target with `{"test_connection"}`, a deleted nginx target with `{}`, and a vault with its correct set. The registry is the harness's fake nginx with `nginxCaps + CapHTTP01` and fake azurekv.
    - The first call returns `1`, the live target holds the sorted set, the deleted one keeps `{}`, and exactly one `target.capabilities_synced` row exists with `Details["targets"] == "1"`.
    - A second call returns `0` with no new audit row.
    - Neither call changes `version` or `updated_at`.
  - `serve_integration_test.go`: `TestServeSyncsCapabilitiesAtStartup`. A target seeded with a stale set has the registry's set after `serve` starts.

- [ ] **Step 2: Run them to verify they fail**
Run: `go test -count=1 -tags integration ./migrations/ -run 00017 ./internal/inventory/ -run SyncCapabilities`
Expected: FAIL (migration file missing; `SyncCapabilities` undefined).

- [ ] **Step 3: Implement** the migration (Ruling 2), `SyncCapabilities` (Ruling 1; one `db.InTx`, one `UPDATE` per type of `append([]string{TypeLinux, TypeAzureKeyVault}, webServerTypes...)`, skipping a type `providerFor` does not find; Task 9's `TypeApache` joins through `webServerTypes`), and the call in `serve` (`if _, err := svc.inventory.SyncCapabilities(ctx); err != nil { return err }`). Locale: en `"Server capabilities updated"`, tr `"Sunucu özellikleri güncellendi"`.

- [ ] **Step 4: Run the tests**
Run: `go build ./... && go test -race -count=1 -tags integration ./migrations/ ./internal/inventory/ -run '00017|Roles|Grant|SyncCapabilities' && go test -race -count=1 -tags integration ./cmd/alice/ -run Serve && cd web && npx vitest run src/pages/AuditPage.test.tsx && cd .. && make i18n-check`
Expected: PASS.

- [ ] **Step 5: Commit**: `feat(inventory): startup rewrites target capabilities from the provider registry; migration 00017 adds the apache type and the grant (spec §8.1)`

---

### Task 3: Web: keyboard-reachable disabled note, capability-driven texts, Phase A web carries

**Files:**
- Modify: `web/src/components/DisabledFeature.tsx`, `web/src/components/DisabledFeature.test.tsx`
- Modify: `web/src/api/capabilities.ts` (`capabilityText`, `DISCOVERY_ONLY_TEXTS`), `web/src/api/webServer.ts:20-45` (`DeployBlock` gains `'helper_too_old'`; `webServerState` checks the warning after `profile_missing`)
- Modify: `web/src/components/WebsitesPanel.tsx:66-104` (`BLOCK_KEYS.helper_too_old`, `capabilityText`, no `deployUnavailable` without deploy), `web/src/pages/TargetDetailPage.tsx:246,412`
- Modify: `web/src/api/warnings.ts:41-46` (`web_server_helper_too_old: []`)
- Modify: `web/src/components/AddServerModal.tsx:23,170-176`, `web/src/components/PlatformKeyPanel.tsx:12,42-48` (Ruling 15)
- Modify: `web/src/api/webServer.test.ts:60-72` (guard from `WEB_SERVER_TYPES`), `web/src/theme.test.ts` (pin the Tooltip class)
- Modify: `web/src/locales/en.json`, `web/src/locales/tr.json`; `api/openapi.yaml` (`TargetFacts.warnings` description lists `web_server_helper_too_old`)
- Test: `web/src/pages/TargetDetailPage.test.tsx`, `web/src/components/WebsitesPanel.test.tsx` (or where the panel is tested today), `web/src/api/webServer.test.ts`, `web/src/api/enums.test.ts`

**Interfaces:**
- Produces: `capabilityText(target: Pick<Target, 'capabilities'>, key: string): string` and `DISCOVERY_ONLY_TEXTS: Readonly<Record<string, string>>` in `web/src/api/capabilities.ts`; `DeployBlock` value `'helper_too_old'`.

- [ ] **Step 1: Write the failing tests**
  - `DisabledFeature.test.tsx`, `it('stays focusable, ignores activation and shows the note on focus')`. A wrapped `<Button onClick={spy}>Deploy</Button>` without the capability: `userEvent.tab()` focuses it; it has `aria-disabled="true"`, is `not.toBeDisabled()`, and its `aria-describedby` names an element with the exact note; after focus the tooltip with the note is visible; a click and `{Enter}` do not call `spy`. With the capability: no `aria-disabled`, and the click calls `spy`.
  - `theme.test.ts`: `theme.components.Tooltip.classNames.tooltip === classes.tooltip`, and `mantine.module.css`'s `.tooltip` rule uses only `var(--…)` colours.
  - `webServer.test.ts`: the literal guard iterates `WEB_SERVER_TYPES` (one regex per type) with allow-list `['api/webServer.ts']`. `webServerState` gives `'helper_too_old'` for the warning `web_server_helper_too_old`, after `profile_missing` and before `server_not_found`.
  - `TargetDetailPage.test.tsx`, `it('a server that cannot deploy reads as discovery-only')`. Render `nginxTargetWith({ capabilities: ['test_connection','discover_certificates','discover_ssh_keys','authorized_keys','key_login'] }, { warnings: [{code:'web_server_config_invalid',params:{}}], web_server: webServerFacts({config_valid:false}) })` with one unsupported and one supported location. The visible text outside `[data-testid="disabled-feature"]` and the hidden notes matches neither `/deploy/i` (en) nor `/dağıt/i` (tr). The operations, intro, config-invalid and warning texts are the discovery-only ones. The same page with `deploy_certificate` keeps today's texts.
  - `enums.test.ts`: `web_server_helper_too_old` is in `webServerOnly` and has a source.

- [ ] **Step 2: Run them to verify they fail**
Run: `cd web && npx vitest run src/components/DisabledFeature.test.tsx src/api/webServer.test.ts src/pages/TargetDetailPage.test.tsx src/theme.test.ts src/api/enums.test.ts`
Expected: FAIL.

- [ ] **Step 3: Implement**
  - `DisabledFeature`: `cloneElement(children, { 'aria-disabled': true, 'data-disabled': true, 'aria-describedby': id, onClick: (e) => e.preventDefault() })` with no `disabled`. The wrapping span stays for layout. `<Tooltip label={note} events={{ hover: true, focus: true, touch: true }}>`.
  - New copy (en / tr):
    - `warnings.web_server_config_invalid_discovery`: "{{software}}'s configuration has an error, so Alice cannot read its websites until it is fixed." / "{{software}} yapılandırmasında bir hata var; düzeltilene kadar Alice web sitelerini okuyamaz."
    - `locations.configInvalidDiscovery`: "{{software}}'s configuration on this server has an error. The websites below are as Alice last read them." / "Bu sunucudaki {{software}} yapılandırmasında bir hata var. Aşağıdaki web siteleri Alice'in son okuduğu hâliyle gösteriliyor."
    - `locations.introDiscovery`: "Each row is a certificate file that {{software}} uses. Alice reads these files and never changes them." / "Her satır {{software}} tarafından kullanılan bir sertifika dosyasıdır. Alice bu dosyaları okur, hiçbir zaman değiştirmez."
    - `targets.page.operationsTextDiscovery`: "Alice reads the certificate files {{software}} uses through its restricted helper. It never changes {{software}} files or configuration." / "Alice, {{software}} tarafından kullanılan sertifika dosyalarını kısıtlı yardımcısıyla okur. {{software}} dosyalarını ve yapılandırmasını hiçbir zaman değiştirmez."
    - `warnings.web_server_helper_too_old`: "The alice-helper on this server is too old to read {{software}}. Update the helper; SSH keys are still read." / "Bu sunucudaki alice-helper, {{software}} bilgilerini okumak için çok eski. Yardımcıyı güncelleyin; SSH anahtarları okunmaya devam ediyor."
    - `locations.unavailable.helper_too_old`: "The alice-helper on this server is too old for {{software}}." / "Bu sunucudaki alice-helper {{software}} için çok eski."
    - `warnings.config_file_writable` reworded: "A {{software}} configuration file can be changed by users other than root: {{path}}" / "Bir {{software}} yapılandırma dosyası root dışındaki kullanıcılar tarafından değiştirilebiliyor: {{path}}"
    - `targets.form.typeWebServer` / `targets.prepare.profileWebServer`: "{{software}} server" / "{{software}} sunucusu". Delete `typeNginx` and `profileNginx`.
  - `capabilityText` maps `warnings.web_server_config_invalid`, `locations.configInvalid`, `locations.intro` and `targets.page.operationsText` to the `…Discovery` keys. Every call site of those four keys goes through it.

- [ ] **Step 4: Run the tests**
Run: `cd web && npx vitest run && npm run lint && npx tsc --noEmit && cd .. && make i18n-check`
Expected: PASS.

- [ ] **Step 5: Commit**: `feat(web): the disabled-feature note is reachable by keyboard; discovery-only servers get texts that never promise deployment (spec §8.3, §8.4)`

---

### Task 4: Helper protocol 8 vocabulary, `apache` sudoers profile and setup snippets

**Files:**
- Modify: `internal/providers/linuxssh/helperproto/helperproto.go:20-49` (Protocol 8, Version 1.7.0, `ApacheMinProtocol`, comment), `:137-155` (`SubApacheDump`, `CodeSoftwareNotFound`), `:492` (doc: "answers nginx-dump and apache-dump")
- Modify: `internal/providers/linuxssh/helperproto/helperproto_test.go:376,471`, `acme_test.go:15-17`
- Modify: `internal/providers/linuxssh/command.go:138-147` (`CmdApacheDump`), `command_test.go`
- Modify: `internal/providers/linuxssh/setup.go:10-69` (`sudoersApacheOnly`, profile `apache`, error text), `setup_test.go`, `internal/providers/linuxssh/provider.go:76-86`, `provider_test.go`
- Modify: `internal/providers/provider.go:179,185` (comments: profiles linux, nginx, apache)
- Modify: `internal/providers/linuxssh/docs_sudoers_test.go` (table over both guides)
- Create: `docs/apache-host-preparation.md` (skeleton: title, "The Apache profile" with the quoted block; Task 14 completes it)
- Modify: `api/openapi.yaml:6436-6442` (`profiles` requires and lists `apache`), `web/src/api/types.ts:442` (`profiles: Record<'linux' | WebServerType, SetupSnippet>`; `WebServerType` gains `apache` in Task 11, so type it as `{ linux; nginx; apache }` here)

**Interfaces:**
- Produces: `helperproto.SubApacheDump = "apache-dump"`, `helperproto.CodeSoftwareNotFound = "SOFTWARE_NOT_FOUND"`, `helperproto.ApacheMinProtocol = 8`, `Protocol = 8`, `Version = "1.7.0"`; `func CmdApacheDump() linuxssh.HelperCommand` (privileged, `LongCommandTimeout`, `ServerDumpOutput`); `linuxssh.Sudoers("apache")`.

- [ ] **Step 1: Write the failing tests**
  - `helperproto_test.go`: `Protocol == 8`, `Version == "1.7.0"`, `MinProtocol == 6`, `ApacheMinProtocol == 8`, `SubApacheDump == "apache-dump"`, `CodeSoftwareNotFound == "SOFTWARE_NOT_FOUND"`.
  - `command_test.go`: `CmdApacheDump().Subcommand() == "apache-dump"`, with no arguments and the output limit `ServerDumpOutput`.
  - `setup_test.go`, `TestSudoersApacheProfile`: `Sudoers("apache")` equals `sudoersHead + "\nCmnd_Alias ALICE_APACHE_ONLY = \\\n    /usr/local/libexec/alice-helper apache-dump\n" + "\nalice-svc ALL=(root) NOPASSWD: ALICE_COMMON, ALICE_APACHE_ONLY\n"`. `Sudoers("haproxy")` is `errUnknownProfile`. `SetupScript("apache", line, true)` contains `profile: apache`.
  - `provider_test.go`: `SetupSnippets` has keys `linux`, `nginx`, `apache`.
  - `docs_sudoers_test.go`: a table `{guide: "nginx-host-preparation.md", alias: "ALICE_NGINX_ONLY", profile: "nginx"}, {guide: "apache-host-preparation.md", alias: "ALICE_APACHE_ONLY", profile: "apache"}`, same suffix assertion.

- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./internal/providers/linuxssh/...`
Expected: FAIL.

- [ ] **Step 3: Implement** as in Interfaces. The protocol comment: "Protocol 8 (Apache, Phase B): apache-dump; nothing else changed: a protocol 6 helper serves every other operation (MinProtocol)". The new doc's sudoers section quotes the block exactly as generated.

- [ ] **Step 4: Run the tests**
Run: `go build ./... && go test -race -count=1 ./internal/providers/... ./internal/api/ && cd web && npx tsc --noEmit`
Expected: PASS. Fix any other assertion on the protocol (`grep -rn 'Protocol)' --include=*_test.go`) to read `helperproto.Protocol`, not a literal.

- [ ] **Step 5: Commit**: `feat(helperproto): protocol 8 / helper 1.7.0 names apache-dump and SOFTWARE_NOT_FOUND; the apache sudoers profile`

---

### Task 5: `apacheconf`: tool-output parsers and the configuration lexer

**Files:**
- Create: `internal/providers/apacheconf/apacheconf.go` (package doc, limits, errors, reasons), `output.go` (`ParseV`, `ParseIncludes`, `ParseModules`, `ParseRunConfig`, `ModuleName`), `lexer.go`
- Create: `internal/providers/apacheconf/output_test.go`, `lexer_test.go`, `fuzz_test.go` (`FuzzParseApacheIncludes`), `race_on_test.go`/`race_off_test.go` (copy of nginxconf's)
- Modify: `internal/archtest/arch_test.go:34-39,430-440` (rule `"alice/internal/providers/apacheconf": {"alice/internal/providers/linuxssh/helperproto"}`; rows "apacheconf to helperproto allowed", "apacheconf to platform/db denied")
- Modify: `coverage-floors.json` (`apacheconf: 92`), `Makefile:363-365,408-413` (`fuzz-apache` target; add it to `fuzz-nightly`/`fuzz-release` and update their counts: 30 targets, 300 minutes / about 15 hours), `.github/workflows/release.yml:83` (`fuzz-apache` in the matrix)

**Interfaces:**
- Produces: `func ParseV(out []byte) (version, confPath string)`; `type Included struct { Path string; Parent int; Line int }` (`Parent == -1` for the root, `Line == 0` for the root); `func ParseIncludes(out []byte) ([]Included, error)`; `type Modules struct { Static, Loaded map[string]bool }`; `func ParseModules(out []byte) (Modules, error)`; `type RunConfig struct { ServerRoot string; Defines map[string]string }`; `func ParseRunConfig(out []byte) (RunConfig, error)`; `func ModuleName(arg string) (string, bool)`; unexported `lex(file string, data []byte) ([]line, error)` where `line{first, last int; name string; args []string; section, closing bool}`. Errors: `ErrTooLarge, ErrLineTooLong, ErrTooComplex, ErrTooDeep, ErrSyntax, ErrNUL, ErrOutput, ErrIncludeMismatch`. Reasons: `ReasonVariable = "variable"`, `ReasonConditional = "conditional"`, `ReasonPathNotAllowed = "path_not_allowed"`, `ReasonConfigFileWritable = helperproto.WarnConfigFileWritable`. Limits: `MaxInput = 20 << 20`, `MaxFiles = 4096`, `MaxDepth = 100`, `MaxLine = 1 << 20`, `MaxTokens = 1 << 20`.

- [ ] **Step 1: Write the failing table tests**
  - `TestParseV`: Debian `-V` text → `("2.4.57", "/etc/apache2/apache2.conf")`. RHEL (`HTTPD_ROOT="/etc/httpd"`, `SERVER_CONFIG_FILE="conf/httpd.conf"`) → `"/etc/httpd/conf/httpd.conf"`. A version with a space or over 40 characters → `""`. A relative root → confPath `""`.
  - `TestParseIncludes`:
    - The Debian sample (`(*) /etc/apache2/apache2.conf`, children at 4 spaces `(146) …mods-enabled/ssl.load`, a grandchild at 6 spaces) gives the parents and lines. A trailing `Syntax OK` is ignored.
    - Each of these gives `ErrOutput`: no header, two roots, a child before the root, a jump of two levels, odd indentation, `(x)`, a relative path.
    - 4097 entries give `ErrTooComplex`.
  - `TestParseModules`: `ssl_module (shared)` lands in `Loaded`, `core_module (static)` in `Static` and `Loaded`. A malformed line is `ErrOutput`.
  - `TestParseRunConfig`: `ServerRoot: "/etc/httpd"`, `Define: DUMP_RUN_CFG` dropped, `Define: FOO` gives `{"FOO": ""}`, `Define: CERTS=/etc/ssl/a b` gives `{"CERTS": "/etc/ssl/a b"}`.
  - `TestModuleName`: `mod_ssl.c`→`ssl_module`; `ssl_module`→`ssl_module`; the five table entries of Ruling 8; `weird` → `("", false)`.
  - `TestLex`: a continuation `SSLCertificateFile \⏎ /a.pem` gives one line with `first=1, last=2`; `"a b"` and `'a b'` are one argument; `"a\"b"` gives `a"b`; `"a\b"` gives `a\b`; `  # c` is a comment; `x # y` keeps `#` and `y` as arguments; `<VirtualHost *:443>` is a section; `</virtualhost>` closes it; `<If "%{X} == 'a'">` keeps its expression as one argument; an unterminated quote is `ErrSyntax`; NUL is `ErrNUL`; a 1 MiB+1 line is `ErrLineTooLong`.
  - `FuzzParseApacheIncludes` seeds with the samples above and asserts no panic. Every returned entry has a valid parent index and `helperproto.ValidPath`-clean paths.

- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./internal/providers/apacheconf/`
Expected: FAIL (package does not exist).

- [ ] **Step 3: Implement** per Rulings 6 and 8 (lexing part). The package is pure: standard library plus `helperproto` (for `ValidPath`, `WarnConfigFileWritable`). Its package comment states that its input is hostile.

- [ ] **Step 4: Run the tests**
Run: `go test -race -count=1 ./internal/providers/apacheconf/ ./internal/archtest/ && go test -count=1 -run '^$' -fuzz FuzzParseApacheIncludes -fuzztime 60s ./internal/providers/apacheconf/`
Expected: PASS, no crasher.

- [ ] **Step 5: Commit**: `feat(apacheconf): parse apachectl -V, DUMP_INCLUDES, DUMP_MODULES, DUMP_RUN_CFG and lex Apache configuration lines`

---

### Task 6: `apacheconf.Parse`: include splicing, conditionals, virtual hosts and pairs

**Files:**
- Create: `internal/providers/apacheconf/parse.go`, `parse_test.go`, `testdata/` (Debian- and RHEL-shaped trees)
- Modify: `internal/providers/apacheconf/fuzz_test.go` (`FuzzParseApacheConfig`), `Makefile` (`fuzz-apache` runs both targets)
- Modify: `internal/providers/webserver/guard_test.go:67-77` (union of the two parsers' `Reason*`)

**Interfaces:**
- Consumes: Task 5's outputs.
- Produces: `type Input struct { Includes []Included; Files map[string][]byte; Modules Modules; Run RunConfig; Version string }`; `func Parse(in Input) (Config, error)`; `type Config struct { Servers []Server; Files []string }`; `type Server struct { File string; Line int; Names []string; Listens []Listen; Pairs []Pair; Main bool }`; `type Listen struct { Addr string; Port int; Default bool }`; `type Pair struct { Cert, Key, CertRaw, KeyRaw string; Inherited bool; Unsupported string }`; `func (c Config) CertPaths() []string`; `func (c Config) KeyPaths() []string` (supported pairs, distinct, in order); `func MarkWritable(c *Config)`; `func ToWire(s Server) helperproto.DumpServer` (slices never nil; `Raw` = `CertRaw` cut to 200 runes only when unsupported; `Stream` false).

- [ ] **Step 1: Write the failing table tests** (`TestParse`, one row each, asserting `Servers` exactly)
  - Two vhosts on `*:443` in a spliced `sites-enabled` file inside `<IfModule mod_ssl.c>`: names, listens `{"",443,Default:true}` then `{"",443,false}`, and the pair paths.
  - RSA+ECDSA: two `SSLCertificateFile` and two `SSLCertificateKeyFile` give two pairs in order.
  - Combined: certificate only gives `Key == Cert` and is supported.
  - Inherited: main-level cert/key with vhost `SSLEngine on` gives `Inherited: true`. A vhost with its own cert and the main's key gives the mixed pair, `Inherited: true`.
  - `SSLEngine optional` or missing: no server.
  - Main server with its own `SSLEngine on` + pair: `Main: true`, empty listens.
  - `<IfModule !mod_ssl.c>` skipped; `ssl_module not loaded` (`<IfModule ssl_module>` with `ssl_module` neither static nor `LoadModule`d) gives no servers; `LoadModule ssl_module …` *after* the `<IfModule>` → still false (read order).
  - `<IfDefine X>` with `X` from `DUMP_RUN_CFG` gives true. `<IfDefine !X>` gives false. A `Define X` before and an `UnDefine X` later in the file follow read order.
  - `<IfVersion >= 2.4>` is true for `2.4.57`; `< 2.4` is false; `~ ^2` makes the region uncertain, so the pair is `conditional`. `<If "…">` around a pair gives `conditional`. `<IfModule weird>` gives `conditional`.
  - `${CERTS}/a.pem` with `Define CERTS /etc/ssl/alice` expands. An undefined variable gives `variable` with `CertRaw` kept.
  - A relative `ssl/a.pem` with ServerRoot `/etc/httpd` gives `/etc/httpd/ssl/a.pem`. `../a.pem` gives `path_not_allowed`.
  - `Include` inside `<VirtualHost>` splices its child's `SSLCertificateFile` into that vhost. A continued `Include` matches the tree line of its **last** physical line. A tree child at a line with no `Include` gives `ErrIncludeMismatch`. A tree child under an `Include` in a false region also gives `ErrIncludeMismatch`.
  - Case: `sslcertificatefile` and `<virtualhost>` work. `ServerName https://www.example.test:443` gives `www.example.test`. `<VirtualHost [::1]:8443 _default_:443>` gives listens `{"::1",8443}` and `{"",443,Default:true}`.
  - `SSLCertificateChainFile` gives no extra pair and no extra path in `CertPaths`.
  - Limits: nesting 101 gives `ErrTooDeep`; tokens over `MaxTokens` give `ErrTooComplex`; total input over `MaxInput` gives `ErrTooLarge`.
  - `TestMarkWritable`: every supported pair becomes `config_file_writable`; unsupported ones keep their reason.
  - `TestToWire`: empty slices, not nil; `Raw` only when unsupported.
  - `webserver/guard_test.go`: `withPrefix(nginxconf ∪ apacheconf, "Reason") == sorted(pairReasons)`.
  - `FuzzParseApacheConfig(data []byte)`: a one-file tree (`(*) /etc/apache2/apache2.conf`) with `data` as its content, `ssl_module` loaded. Asserts no panic; every supported pair has `ValidPath` cert and key; every `Line` ≥ 1.

- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./internal/providers/apacheconf/ ./internal/providers/webserver/`
Expected: FAIL.

- [ ] **Step 3: Implement** per Rulings 8–11. A region state is `active | inactive | uncertain`, kept on a stack across spliced files. Each directive carries the strongest region state above it. Collect at main and vhost level only.

- [ ] **Step 4: Run the tests**
Run: `go test -race -count=1 ./internal/providers/apacheconf/ ./internal/providers/webserver/ && go test -count=1 -run '^$' -fuzz FuzzParseApacheConfig -fuzztime 120s ./internal/providers/apacheconf/ && go test -cover ./internal/providers/apacheconf/`
Expected: PASS; coverage ≥ 92 %.

- [ ] **Step 5: Commit**: `feat(apacheconf): evaluate the include tree, IfModule/IfDefine/IfVersion and virtual hosts into certificate pairs`

---

### Task 7: Helper subcommand `apache-dump`

**Files:**
- Create: `cmd/alice-helper/apache.go`, `cmd/alice-helper/apache_test.go`
- Modify: `cmd/alice-helper/run.go:43-63` (register `SubApacheDump`, privileged), `cmd/alice-helper/sys.go:20-66` (`runApache` field), `cmd/alice-helper/main.go:40-75` (`runApache: runApacheCtl`), `cmd/alice-helper/nginx.go:100-109` (rename `nginxMeta` → `dumpMeta`, mechanical)
- Modify: `test/images/e2e-target/Dockerfile:16-19` (`COPY internal/providers/apacheconf/ internal/providers/apacheconf/` in the helper stage)

**Interfaces:**
- Consumes: Tasks 4–6 (`SubApacheDump`, `CodeSoftwareNotFound`, `apacheconf.*`), existing `runProgram`, `walkRoot`/`openLinked`, `walkReason`, `carried`, `describeCert`, `describeKey`, `owners`, `groupNames`.
- Produces: `const apache2ctlPath = "/usr/sbin/apache2ctl"`, `httpdPath = "/usr/sbin/httpd"`; `func runApacheCtl(ctx context.Context, args ...string) ([]byte, []byte, error)`; `sys.runApache func(ctx context.Context, args ...string) (stdout, stderr []byte, err error)`; `func (s *sys) apacheConfig(ctx context.Context) (apacheconf.Config, dumpMeta, error)`; `func cmdApacheDump(ctx context.Context, s *sys, args []string) (any, error)`.

- [ ] **Step 1: Write the failing tests** (`apache_test.go`, fixture tree under the test's root plus a fake `runApache` that answers from a table keyed by `strings.Join(args, " ")`)
  - `TestApacheDumpRunsTheFourCommandsInOrder`: the calls are exactly `-V`, `-D DUMP_INCLUDES -t`, `-D DUMP_MODULES -t`, `-D DUMP_RUN_CFG -t`.
  - `TestApacheDumpListsTwoSites`: the Debian fixture (apache2.conf, a `sites-enabled/alice.conf` with two SSL vhosts, cert/key files 0644/0600 root's). The answer has `ok`, `version`, `conf_path`, `config_valid: true`, two servers with names and listens, `files` describing two certs (PEM, SHA-256) and two keys (stat only, no content), and `warnings: []`.
  - `TestApacheDumpNotInstalled`: `fs.ErrNotExist` from `runApache` gives exit precondition with code `SOFTWARE_NOT_FOUND`. A `-V` without `Server version:` gives the same.
  - `TestApacheDumpInvalidConfiguration`: `DUMP_INCLUDES` exit 1 gives `config_valid: false`, `config_error: "syntax"`, empty servers/files, and nothing of stderr in the answer.
  - `TestApacheDumpKilledIsIOError`: `errProgramKilled` gives `IO_ERROR`.
  - `TestApacheDumpUntrustedFiles`:
    - Tree root ≠ ConfPath gives `untrusted`/`wrong_first_file`.
    - A file in a group-writable directory gives `untrusted`/`not_root_controlled` naming it.
    - A file missing gives `untrusted`/`missing`.
    - A tree name with a space gives `unsupported`/`name_not_allowed`.
    - An include mismatch gives `untrusted`/`changed`.
    - Parser limits give `unsupported`/`too_large`|`too_complex`.
  - `TestApacheDumpWritableConfigMarksEveryPair`: one included file 0666 gives `writable: [that file]`, warning `config_file_writable`, every pair `unsupported: "config_file_writable"`, and no files described.
  - `TestApacheDumpRefusesArguments`: `apache-dump x` gives `USAGE`.
  - `TestApacheDumpWritesNothing`: snapshot `(path, size, mtime, mode)` of the whole fixture root before and after a dump with every outcome above; the snapshots are equal.
  - `TestApacheCtlChoice` (unit of `runApacheCtl`'s choice, with the paths injected through an unexported `apacheCtlPaths` var): apache2ctl when both exist, httpd when only it exists, `fs.ErrNotExist` when neither exists; `/usr/sbin/apachectl` is never chosen.

- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./cmd/alice-helper/ -run Apache`
Expected: FAIL.

- [ ] **Step 3: Implement** per Rulings 5, 7 and 12.
  - `apacheConfig` parses `-V`, runs `DUMP_INCLUDES` (validity), then modules and run config. It reads each tree file (`walkRoot` + `openLinked(true)`, bounded), records the writable ones, then runs `apacheconf.Parse` and, when needed, `MarkWritable`.
  - `cmdApacheDump` mirrors `cmdNginxDump` (`cmd/alice-helper/nginx.go:358-427`): syslog `SubApacheDump`, `ToWire`, the describe loops with `MaxServerFiles` and `dumpBudget`, and `json.RawMessage`.
  - Map parser errors with a `apacheParseError` like `parseError` (`nginx.go:137-151`). `ErrIncludeMismatch` maps to untrusted `changed`. `ErrOutput` maps to untrusted `unexpected_text`.

- [ ] **Step 4: Run the tests**
Run: `go vet ./cmd/alice-helper/ && go test -race -count=1 ./cmd/alice-helper/... && sudo -E env "PATH=$PATH" go test -count=1 ./cmd/alice-helper/... && make helper && go test -count=1 -run TestStatic ./cmd/alice-helper/`
Expected: PASS (the static-binary test still sees only `golang.org/x/crypto` and `golang.org/x/sys`).

- [ ] **Step 5: Commit**: `feat(alice-helper): apache-dump reads the Apache configuration Apache loads and describes its certificate files, read-only (protocol 8, 1.7.0)`

---

### Task 8: Emulator `apache-dump` and the fidelity test

**Files:**
- Create: `internal/providers/linuxssh/linuxsshtest/apache.go` (state and exported API), `apache_dump.go` (port of `cmdApacheDump`), `apache_test.go`
- Modify: `internal/providers/linuxssh/linuxsshtest/emulator.go:341-370` (dispatch `isApacheSub`)
- Modify: `internal/archtest/arch_test.go:39` (linuxsshtest may import `alice/internal/providers/apacheconf`) and its row table
- Create: `cmd/alice-helper/apache_fidelity_test.go`

**Interfaces:**
- Consumes: `apacheconf.*`, the emulator's file table (`nginxHost.content/meta`, `describeCert`, `describeKey`: one file table for both web servers).
- Produces: `type ApacheSite struct { Names []string; Port int; CertPath, KeyPath string }` (`KeyPath == ""` = combined file); `func (e *Emulator) EnableApache(version string)`; `SetApacheProfile(installed bool)`; `AddApacheSite(s ApacheSite, certPEM, keyPEM []byte)`; `SetApacheConfig(path, text string)`; `SetApacheConfigInvalid(invalid bool)`; `SetApacheKilled(killed bool)`. Conf path `/etc/apache2/apache2.conf`; generated site file `/etc/apache2/sites-enabled/emu.conf`, included at a fixed line of the generated `apache2.conf`; modules `core_module (static)`, `so_module (static)`, `ssl_module (shared)`; ServerRoot `/etc/apache2`.

- [ ] **Step 1: Write the failing tests**
  - `apache_test.go`:
    - Without `EnableApache`, `sudo alice-helper apache-dump` answers `SOFTWARE_NOT_FOUND`.
    - With the profile off, sudo refuses (exit 1).
    - `apache-dump x` is refused by sudo (argument).
    - Two sites answer two servers with described files.
    - `SetApacheConfigInvalid(true)` gives `syntax`.
    - A protocol 7 emulator (`SetProtocol(7)`) still answers `version` 7.
  - `TestApacheAndNginxOnOneHostStaySeparate`: `EnableNginx` + `AddSite(www)` and `EnableApache` + `AddApacheSite(shop)`. `nginx-dump` lists only `www`, `apache-dump` only `shop`. A shared certificate path appears in both answers with the same `sha256`.
  - `apache_fidelity_test.go`, `TestApacheEmulatorFidelity`: the same scenarios on the real helper (temporary root, fake `runApache` answering from the fixture tree, written independently of the emulator) and on the emulator. The scenarios are: not installed, two sites, combined file, cert missing, key mode 0644 (`key_group_open`), writable config file, invalid configuration, killed. Compare exit code, error code, `config_*`, server names/listens/pairs (file and line normalized as in `emulator_fidelity_test.go:37-40`), files (owner/group normalized), warnings and `writable`.

- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./internal/providers/linuxssh/linuxsshtest/ ./cmd/alice-helper/ -run 'Apache'`
Expected: FAIL.

- [ ] **Step 3: Implement**: port `cmdApacheDump` the way `nginx_dump.go:506-573` ports `cmdNginxDump`. The emulator builds its `-V`, include tree, modules and run config from its state, so the real `apacheconf.Parse` decides. `sudoersAllows(SubApacheDump, args)` is `len(args) == 0`.

- [ ] **Step 4: Run the tests**
Run: `go test -race -count=1 ./internal/providers/linuxssh/... ./cmd/alice-helper/... ./internal/archtest/`
Expected: PASS.

- [ ] **Step 5: Commit**: `test(linuxsshtest): the emulated host answers apache-dump through the real parser; fidelity test against the helper`

---

### Task 9: Provider `apache`, the target type and registration

**Files:**
- Create: `internal/providers/apache/provider.go`, `provider_test.go`, `discover_test.go`, `helpers_test.go`
- Modify: `internal/providers/provider.go:22-27,41-52` (`KindApache`, `KindForTargetType("apache")`), `internal/providers/providers_test.go`
- Modify: `internal/inventory/types.go:22-33` (`TypeApache = "apache"`; `webServerTypes = []string{TypeNginx, TypeApache}`; comment: "the only place that names the web-server types"), `internal/inventory/validate.go:28` (unchanged code; its test expects `linux, nginx, apache`)
- Modify: `internal/archtest/webserver_test.go` (rename to `TestOnlyTheTypeListNamesWebServerTypes`, checking the idents `TypeNginx` and `TypeApache`; no traceability row names the old test)
- Modify: `cmd/alice/providers.go:9,23-37`, `cmd/alice/wiring.go:12`, `cmd/alice/providers_test.go:30-66`
- Modify: `locales/common/en.json:12`, `locales/common/tr.json` (`provider.apache.name`: "Apache server" / "Apache sunucusu")
- Modify: `coverage-floors.json` (`apache: 98`), `internal/testutil/seed/seed.go:23` (comment)
- Modify: `test/matrix/traceability.json` F-20 (`internal/providers/apache:TestDiscoverWithoutApacheFails`), then regenerate `docs/security/traceability.md`
- Test: `internal/inventory/targets_integration_test.go:239` (next to `TestNginxTargetsCountTowardTheLicense`)

**Interfaces:**
- Consumes: `webserver.NewBase/Spec/BaseCapabilities`, `linuxssh.CmdApacheDump`, `helperproto.{SubApacheDump, CodeSoftwareNotFound, ApacheMinProtocol}`.
- Produces: package `apache`: `type Options struct { SSH *linuxssh.Provider }`; `func New(o Options) *Provider`; `type Provider struct { webserver.Base; caps providers.CapabilitySet }`; `Capabilities()`; `Open(...) (providers.Session, error)` (returns the `*webserver.Session`, never a typed nil). The spec is `{Kind: KindApache, DisplayNameKey: "provider.apache.name", Dump: linuxssh.CmdApacheDump, Test: nil, NotFoundCode: helperproto.CodeSoftwareNotFound, MinProtocol: helperproto.ApacheMinProtocol, Subcommands: []string{helperproto.SubApacheDump}, UsualFolders: {"/etc/ssl/", "/etc/apache2/", "/etc/httpd/", "/etc/pki/", "/etc/letsencrypt/"}}`. Capabilities: `webserver.BaseCapabilities()` only.

- [ ] **Step 1: Write the failing tests**
  - `provider_test.go`:
    - `TestApacheProviderDescribesItself`: kind `apache`, display key, capabilities exactly the five base ones (no deploy, verify or HTTP-01).
    - `TestApacheConformance`: `providertest.CheckProvider` and the session conformance.
    - `TestTestConnectionReadsTheDump`: emulator, version, conf path, valid.
    - `TestTestConnectionChecksTheApacheProfile`: profile off gives `apache.profile_missing`.
    - `TestApacheNotInstalledIsAWarning`.
    - `TestApacheHelperTooOld`: emulator protocol 7 gives the warning; `Discover` gives `apache.helper_too_old`.
  - `discover_test.go`:
    - `TestDiscoverTwoSites`: locations, servers, `Software: "apache"`.
    - `TestDiscoverWithoutApacheFails`: `apache.not_found`, no partial data.
    - `TestDiscoverCombinedFileIsSupportedAndWarns`: `KeyPath == CertPath`, `Supported`, PEM chain present, `key_mode_open` with mode 0644.
    - `TestDiscoverConditionalPairIsUnsupported` (`SetApacheConfig` with `<IfVersion ~ ^2>`): `Unsupported: "conditional"`.
    - `TestDiscoverCustomLocation`: a cert under `/srv/certs` is `CustomLocation`.
  - `providers_test.go`: `KindForTargetType("apache") == (KindApache, true)`.
  - `cmd/alice/providers_test.go`: `TestRegisterProvidersShipsLinuxSSHNginxApacheAndAzureKV` (4 providers; apache's capability set; `providertest.CheckProvider`; `ConnectionCache`). `TestEveryWebServerTypeHasARegisteredKind`: for each `inventory.WebServerTypes()`, `KindForTargetType` is ok and the registry has the kind (Phase A carry).
  - `TestApacheTargetsCountTowardTheLicense`: an `apache` target counts toward the license like an `nginx` one; a deleted one does not.

- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./internal/providers/... ./cmd/alice/ ./internal/archtest/`
Expected: FAIL.

- [ ] **Step 3: Implement**: the provider is about 30 lines, modelled on `internal/providers/nginx/provider.go:19-101` without deployment. Register it next to nginx in `registerProviders` on the same `ssh`, and add `providers.KindApache` to `shippedProviders`.

- [ ] **Step 4: Run the tests**
Run: `go build ./... && go test -race -count=1 ./internal/providers/... ./internal/inventory/ ./internal/jobs/... ./cmd/alice/ ./internal/archtest/ && go test -race -count=1 -tags integration ./internal/inventory/ -run 'Count|Create' && make matrix-check MATRIXCHECK_FLAGS=-strict`
Expected: PASS.

- [ ] **Step 5: Commit**: `feat(apache): the Apache httpd provider (discovery only) and the target type apache`

---

### Task 10: API surface: error codes, OpenAPI enums, server texts, scan fallback for Apache

**Files:**
- Modify: `internal/api/errors.go:252-268,460-500` (`ErrApacheNotFound/ConfigInvalid/ProfileMissing/HelperTooOld` per Global Constraints, listed in `AllErrorCodes`)
- Modify: `internal/api/errors_test.go:92` (`reasonShapeRE` gains `apache`), new `internal/api/errors_webserver_test.go`
- Modify: `locales/common/en.json`, `locales/common/tr.json` (`errors.apache.<reason>.{title,cause,action}`)
- Modify: `docs/troubleshooting.md` (sections `ALC-APC-0001`…`0004`, after the `ALC-NGX-*` ones)
- Modify: `api/openapi.yaml:743-747` (type filter enum and description), `:5900` (create type enum), `:5976` (target type), `:6478` (provider kind), `:6511` (`software` enum `[nginx, apache]`), the `CertificateLocation.unsupported_reason` known values (`conditional`)
- Modify: `internal/jobs/targetjobs/targetjobs_test.go:693-730` (an `apache` row)
- Test: `internal/api/inventory_handlers_test.go` (or where `POST /targets` validation is tested)

**Interfaces:**
- Produces: the four `ErrorCode`s; OpenAPI enums with `apache`.

- [ ] **Step 1: Write the failing tests**
  - `errors_webserver_test.go`, `TestWebServerReasonsAreRegistered`: a table `{nginx: not_found, profile_missing, config_invalid}`, `{apache: not_found, profile_missing, config_invalid, helper_too_old}` → `codeForReason(kind + "." + r) != ErrUnexpected`, and apache's codes are `ALC-APC-000{1..4}` in that order. The existing tests (`TestEveryErrorCodeIsWellFormedUniqueAndTranslated`, `…DocumentedInTroubleshooting`) cover the texts and the docs.
  - targetjobs: `run(providers.KindApache, inventory.TypeApache, "apache.not_found")` falls back with `WebServer == &{Software: "apache"}`; `"apache.profile_missing"` and `"apache.helper_too_old"` fall back with their warnings.
  - API: `POST /api/v1/targets` with `type: "apache"` is accepted. `type: "haproxy"` gives 422 `validation.one_of` with `values: "linux, nginx, apache"`.

- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./internal/api/ ./internal/jobs/targetjobs/`
Expected: FAIL.

- [ ] **Step 3: Implement**: the codes, English and Turkish texts (title / cause / action naming Apache and the guide `docs/apache-host-preparation.md`), the troubleshooting sections, and the OpenAPI enums.

- [ ] **Step 4: Run the tests**
Run: `go test -race -count=1 ./internal/api/ ./internal/jobs/... && make i18n-check && go test -count=1 -tags integration ./internal/api/ -run 'OpenAPI|Target'`
Expected: PASS.

- [ ] **Step 5: Commit**: `feat(api): ALC-APC-0001..0004 and the apache type in the API contract`

---

### Task 11: Web: the Apache server page

**Files:**
- Modify: `web/src/api/webServer.ts:4` (`WEB_SERVER_TYPES = ['nginx', 'apache'] as const`)
- Modify: `web/src/api/enums.ts:83-96` (`UNSUPPORTED_REASONS` gains `conditional`), `web/src/api/enums.test.ts:164,200` (`internal/providers/apache` among `webServerWarnings` dirs; `software` enum equals `WEB_SERVER_TYPES`)
- Modify: `web/src/api/types.ts:442` (`profiles: Record<'linux' | WebServerType, SetupSnippet>`)
- Modify: `web/src/locales/en.json`, `web/src/locales/tr.json`: `webServer.software.apache` "Apache"; `targets.typeLabel.apache` "Apache server" / "Apache sunucusu"; `locations.unsupported.conditional` "This file is set inside a conditional section of the configuration (<If>, or a test Alice cannot evaluate), so Alice cannot tell when it is used." / "Bu dosya yapılandırmanın koşullu bir bölümünde (<If> ya da Alice'in değerlendiremediği bir test) tanımlanmış; Alice dosyanın ne zaman kullanıldığını bilemez."
- Modify: `web/src/test/fixtures.ts:595-615` (`apacheTargetFixture`: type `apache`, the five base capabilities, `web_server.software: 'apache'`, conf path `/etc/apache2/apache2.conf`)
- Test: `web/src/pages/TargetDetailPage.test.tsx`, `web/src/pages/TargetsPage.test.tsx`, `web/src/components/software.test.ts`

**Interfaces:**
- Consumes: Task 3 (`capabilityText`, `DisabledFeature`), Task 4 (`profiles.apache`).

- [ ] **Step 1: Write the failing tests**
  - `TargetsPage.test.tsx`: the Add server type select offers `linux`, `nginx`, `apache` labelled "Linux server", "Nginx server", "Apache server". Choosing `apache` shows `profiles.apache.script` and posts `type: 'apache'`. The prepare panel offers the apache profile.
  - `TargetDetailPage.test.tsx`, `it('an Apache server shows its facts and websites with deployment disabled')`:
    - Facts: platform "Apache server" and "Apache version" 2.4.57.
    - The websites table shows the combined-file row (`KeyPath == CertPath`, warning `key_mode_open`).
    - Each row's Deploy and Settings controls have `aria-disabled="true"`, are reachable by `tab`, and carry "Not available for Apache servers yet".
    - A `conditional` row shows the new reason text.
    - The Turkish render shows "Apache sunucularında henüz kullanılamıyor".
  - `software.test.ts`: `softwareName(t, 'apache') === 'Apache'`.

- [ ] **Step 2: Run them to verify they fail**
Run: `cd web && npx vitest run src/pages/TargetDetailPage.test.tsx src/pages/TargetsPage.test.tsx src/components/software.test.ts src/api/enums.test.ts`
Expected: FAIL.

- [ ] **Step 3: Implement** the list, enum, texts and fixture. Nothing else should need code: every component reads `WEB_SERVER_TYPES`, `softwareName` and `can()`.

- [ ] **Step 4: Run the tests**
Run: `cd web && npx vitest run && npm run lint && npx tsc --noEmit && cd .. && make i18n-check web-coverage`
Expected: PASS.

- [ ] **Step 5: Commit**: `feat(web): Apache servers: add, prepare, facts and websites, with deployment shown disabled`

---

### Task 12: Real matrix `TestRealApache` (Ubuntu 22.04, Debian 12, Rocky 9)

**Files:**
- Modify: `test/images/sshd/ubuntu22.Dockerfile`, `debian12.Dockerfile` (add `apache2` to the existing `apt-get install`; header comment: Apache installed, never started; mod_ssl is enabled by the test), `rocky9.Dockerfile` (add `httpd mod_ssl` to the `dnf install`; comment: `ssl.conf`'s `localhost` pair is written by the test, never in a layer)
- Create: `internal/providers/apache/containers_integration_test.go`
- Modify: `Makefile:34-40` (help text names Apache; one more line `set -o pipefail; ALICE_REAL_MATRIX=1 go test -count=1 -v -timeout 30m -tags integration -ldflags "$(HELPER_LDFLAGS)" -run '^TestRealApache' ./internal/providers/apache/ $(call SSH_MATRIX_PASSED,TestRealApache)`)
- Modify: `test/matrix/traceability.json` only if a row already names `TestRealNginx` for discovery-only behaviour (F-20: add `internal/providers/apache:TestRealApache`), then regenerate the doc

**Interfaces:**
- Consumes: the setup script of profile `apache` (`linuxssh.SetupScript`), `apache.New`, the built helper (`bin/alice-helper-linux-amd64`, verified like `rnHelper` in `internal/providers/nginx/containers_integration_test.go:92-110`).

- [ ] **Step 1: Write the test** `TestRealApache`, one subtest per image (`ALICE_SSH_IMAGES` filter, skip without `ALICE_REAL_MATRIX=1` as `TestRealNginx` does). Its own small host helper, modelled on `rnHost` (`containers_integration_test.go:121-300`) but without deploy. Steps:
  1. Prepare with the `apache` profile script. `sudo -n alice-helper apache-dump extra` is refused by sudo (its text), and `sudo -n alice-helper nginx-dump` is refused (not in this profile).
  2. Debian/Ubuntu before `a2enmod ssl`: TestConnection gives `Found`, version `^2\.4\.\d+$`, ConfPath `/etc/apache2/apache2.conf`, valid. Discover gives zero locations and no warning (Review Focus 3).
  3. Fixture (test CA, keys root:root 0600, written through `h.write`):
     - `a.example.test` with RSA+ECDSA pairs in `/etc/ssl/alice/`.
     - `b.example.test` with a combined file.
     - A `Define CERTDIR /etc/ssl/alice` used as `${CERTDIR}`.
     - An `<IfDefine !NOPE>` wrapper.
     - On Debian/Ubuntu: `/etc/apache2/sites-enabled/alice.conf` plus `a2enmod ssl`.
     - On Rocky: `/etc/httpd/conf.d/alice.conf` plus `/etc/pki/tls/certs/localhost.crt` and `/etc/pki/tls/private/localhost.key` for `ssl.conf`'s `_default_:443`.
  4. Discover gives exactly the expected cert paths (Rocky adds `localhost.crt`). Servers have names and listens 443, `Supported`, SHA-256 equal to `sha256sum` on the host, and `b`'s `KeyPath == CertPath`.
  5. An unknown directive (`AliceNoSuchDirective on`) added gives ConfigValid false, ConfigError `syntax`, the warning, and no certificates. Then restore. A `SSLCertificateFile /nonexistent.pem` vhost instead stays valid and gives a location whose certificate is `missing` (`-t` does not open certificate files).
  6. A config file `chmod 0666` gives every location `config_file_writable`. Then restore.
  7. The linux profile installed gives `apache.profile_missing`.
  8. `mv` the control program away (`apache2ctl` on Debian/Ubuntu, `httpd` on Rocky) gives `apache.not_found`. Then restore.
  9. After every step, `find /etc /var/lib/alice-helper -newer <stamp>` shows only the test's own writes (read-only check).

- [ ] **Step 2: Run it** on one image first
Run: `ALICE_SSH_IMAGES=debian12 make test-ssh`
Expected: PASS. If an `apachectl` output differs from Ruling 6, fix the parser in a separate commit with a table case taken from the real output, and record it in the rulings file.

- [ ] **Step 3: Run the whole matrix**
Run: `make test-ssh`
Expected: `TestRealOpenSSH`, `TestRealNginx` and `TestRealApache` PASS on all three images (the image changes must not break Nginx).

- [ ] **Step 4: Commit**: `test(apache): real Apache on Ubuntu 22.04, Debian 12 and Rocky 9 in make test-ssh`

---

### Task 13: e2e: an Apache server journey

**Files:**
- Modify: `test/images/e2e-target/Dockerfile` (add `apache2` to the `apt-get install`; `a2enmod ssl`; `a2dissite 000-default`; `COPY test/images/e2e-target/apache-sites.conf /etc/apache2/sites-enabled/alice-e2e.conf`; Apache never started)
- Create: `test/images/e2e-target/apache-sites.conf` (vhosts `*:8443`: `apache.example.test` with separate files `/etc/apache2/ssl/apache.crt` and `apache.key`, and `combined.example.test` with `/etc/apache2/ssl/combined.pem`)
- Modify: `test/images/e2e-target/alice-e2e-pki` (subcommand `apache`: issue both from the test CA, keys root:root 0600, combined file 0600), `test/images/e2e-target/alice-e2e-start` (call `alice-e2e-pki apache` after `init`)
- Modify: `deploy/docker-compose.e2e.yml:42-53` (comment: the target also has Apache, configured and not running)
- Create: `web/e2e/webservers.spec.ts`

**Interfaces:**
- Consumes: e2e helpers (`resetInstall`, `runWizard`, `apiAs`, `targetExec`, `drainJobs`, `translator`, `expectAccessible`, `tabTo`).

- [ ] **Step 1: Write the journey**, `test.describe('Web server providers: Apache (en|tr)')`:
  1. Prepare with the Apache profile script from the Servers page (`field(page, t('targets.prepare.profile')).selectOption('apache')`, run through `alice-e2e-prepare`). Check that the target's sudoers holds the `apache-dump` line.
  2. Add the server with type `apache` in the UI, confirm the fingerprint, and drain jobs.
  3. The server page shows "Apache server", the Apache version and the valid configuration.
  4. Websites shows `apache.example.test` and `combined.example.test`. The Certificates page lists both certificates.
  5. On a row, `tabTo` the Deploy control: it is focused, has `aria-disabled="true"`, and the tooltip shows the note in the page language.
  6. No text on the page outside the disabled controls mentions deploying (the copy is read from the locale files).
  7. `expectAccessible(page, 'apache server')`.
  8. `afterAll` runs the nginx profile script again (`key.profiles.nginx.script` through `alice-e2e-prepare`), so later specs find the target as they expect.

- [ ] **Step 2: Run it**
Run: `make e2e-up && (cd web && npx playwright test e2e/webservers.spec.ts) ; make e2e-down`
Expected: PASS in both languages.

- [ ] **Step 3: Run the whole e2e suite** (no Docker Go tests meanwhile)
Run: `make e2e-up && make e2e; make e2e-down`
Expected: PASS (phase4 and phase10 unaffected).

- [ ] **Step 4: Commit**: `test(e2e): add an Apache server, see its websites and certificates, deploy controls disabled with the note`

---

### Task 14: Documentation, security report, changelog, rulings

**Files:**
- Modify: `docs/apache-host-preparation.md`. Complete it on the model of `docs/nginx-host-preparation.md`: the setup commands, the apache profile and its sudoers block (already quoted), the helper version (1.7.0, protocol 8) and "Updating the helper", what Alice reads (the four apachectl runs, the files of the include tree, certificate files; key files only stat'ed), what it never changes, the read-only note about the control script, and "Configurations Alice cannot read". That last section lists: `<If>` regions and untestable conditions (`conditional`), `Use`/`<Macro>` not expanded, environment variables (`APACHE_*` of `envvars`) not expanded, defines passed only on the service command line (`-DFOREGROUND`, `$OPTIONS`) not known, `SSLCertificateChainFile` not read, any user-writable configuration file making every place `config_file_writable`, and no deployment.
- Modify: `docs/README.md:18` (row for Apache administrators), `docs/operator-guide.md:470-` ("Websites on a web server", one paragraph on discovery-only servers and the disabled controls), `docs/admin-guide.md` (server types list), `docs/troubleshooting.md` (an entry "Apache: the helper is too old" pointing at ALC-APC-0004; Phase A's `web_server_*` entries name Apache too)
- Modify: `SECURITY-REPORT.md` §3 (one paragraph: `apache-dump`, read-only, fixed control scripts, root-controlled walk, the same limits) and §7 (new row `KI-40`: "Apache discovery items": the control script runs as root and may create Apache's runtime directory; a user-writable configuration file makes every place unsupported, while server names from files it includes are still listed (existence oracle, as KI-29); conditions Alice cannot evaluate; Residual Low; Mitigation: as in the guide; Recommendation: keep Apache configuration root-only)
- Modify: `CHANGELOG.md` (new top section `## Unreleased — Apache httpd (discovery only)` with Added, Changed (API), Helper and Upgrade notes)
- Create: `docs/superpowers/rulings/apache-provider.md` (rulings made during execution, carries to Phase C, owner steps: root-only suite if not run, a real customer Apache config review)
- Modify: `tools/docscheck/required.txt` (one required sentence of the new guide, the way the nginx guide has its own, if the nginx guide has one there)

- [ ] **Step 1: Write the docs.** The CHANGELOG entry names: the target type `apache`; capability sync at startup (audit `target.capabilities_synced`); `alice-helper` 1.7.0 / protocol 8 with `apache-dump` ("reinstall the helper on servers that will be Apache servers; Nginx and Linux servers keep working with 1.6.x"); migration `00017`; `ALC-APC-0001..0004`; `web_server_helper_too_old`; unsupported reason `conditional`; and the keyboard-reachable disabled note.
- [ ] **Step 2: Verify**
Run: `make docs-check && go test ./internal/providers/linuxssh/ -run Preparation && go test ./internal/api/ -run Troubleshooting && make matrix-check MATRIXCHECK_FLAGS=-strict`
Expected: PASS.
- [ ] **Step 3: Commit**: `docs: Apache host preparation, guides, security report KI-40, changelog and Phase B rulings`

---

### Task 15: Final gates

**Files:** none new. Fix-ups only, each committed with its own message.

- [ ] **Step 1: Static and unit**
Run: `go build ./... && go vet ./... && go vet -tags integration ./... && make lint && make test && make i18n-check`
Expected: PASS.
- [ ] **Step 2: Docker Go suites** (no Playwright meanwhile)
Run: `make test-integration && make coverage && make test-ssh`
Expected: PASS; `coverage-floors.json` holds for `apache` (98), `apacheconf` (92), `webserver` (98) and `cmd/alice-helper` (90).
- [ ] **Step 3: Helper root suite and checksums**
Run: `sudo -E env "PATH=$PATH" go test -count=1 ./cmd/alice-helper/... && make helper && cat bin/alice-helper.sha256`
Expected: PASS; two checksums.
- [ ] **Step 4: Fuzz smoke**
Run: `make fuzz-apache FUZZTIME=5m`
Expected: no crasher.
- [ ] **Step 5: Web and e2e**
Run: `make web-lint web-coverage && make e2e-up && make e2e; make e2e-down`
Expected: PASS.
- [ ] **Step 6: Grep checks**
Run: `grep -rn "'nginx'" web/src --include=*.ts --include=*.tsx | grep -v test | grep -v api/webServer.ts; grep -rn 'TypeNginx\|TypeApache' --include=*.go internal cmd | grep -v _test | grep -v internal/inventory/types.go`
Expected: both print nothing.
- [ ] **Step 7: Update the rulings file** with the gate results and commit it: `docs(rulings): Apache provider (Phase B) gates`.
