# Web Server Standard (Phase A "Standardize") Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the Nginx-only layer that is not about deployment into one shared web-server layer (names, data, provider package, capability-driven checks and UI) so Phases B (Apache) and C (HAProxy) only add a target type, a `Spec`, a parser and registration, with no visible change for users except the API/JSON renames.

**Architecture:** Go: `providers.WebServerFacts` and `Facts.WebServer` replace the Nginx facts; a new package `internal/providers/webserver` holds what every web-server provider does the same way (open, test, discover, dump conversion, shared helper-error mapping) and `nginx` embeds it and keeps deployment; every "type is nginx" check becomes either `inventory.IsWebServer` or a provider-capability check (`CapDeployCertificate`, new `CapHTTP01`). Migration 00016 rewrites the stored data. Web: `api/webServer.ts` (`isWebServer`, `webServerState`), `api/capabilities.ts` (`can(target, capability)`) and a `DisabledFeature` wrapper decide availability in one place.

**Tech Stack:** Go 1.27 (pgx/v5, goose), PostgreSQL migrations, React 18 + Mantine + TanStack Query + i18next, Vitest, Playwright.

**Spec:** `docs/superpowers/specs/2026-10-17-web-server-providers-design.md` (this plan covers §3 and §5 only; Phase A row of §2).

## Global Constraints

- Branch `web-server-standard` (already checked out). Never switch branches. Phase A must not add the `apache` or `haproxy` target types, providers, helper subcommands or setup profiles (Phases B/C).
- No behaviour change for users except the API/JSON renames of spec §3.2 (no release exists: no compatibility shims). Every existing test keeps passing, updated only for renames. Rendered English texts stay byte-identical (the `{{software}}` interpolation yields "Nginx").
- Helper wire format and versions are unchanged: `helperproto.Protocol` stays 7, `helperproto.Version` stays `"1.6.1"`, `MinProtocol` 6; every JSON tag of the dump types stays as it is. Deployment keeps its Nginx names: `nginx-deploy`/`-restore`/`-status`/`-fence`, `Sub*`, `NginxTestResponse`, `NginxDeploy*`, `NginxStep`, `NginxStatusResponse`, `CodeNginxNotFound` (`"NGINX_NOT_FOUND"`), the `nginx.*` reasons (`nginx.not_found`, `nginx.profile_missing`, `nginx.config_invalid` included) and `ALC-NGX-*` codes, `inventory.ErrNginxConfigInvalid`, `linuxssh.CmdNginxDump/CmdNginxTest`, the sudoers profiles `linux`/`nginx`.
- Migrations `00001`–`00015` are frozen by `migrations/frozen_test.go` (SHA-256 pins; a new file is only logged as "not frozen yet", so 00016 needs **no** pin and must **not** be added to `frozen`). Schema/data changes go in `migrations/00016_web_server_standard.sql`, written like 00015 (`-- +goose Up` / `-- +goose Down`, plain statements, `StatementBegin/End` only around `DO`/function bodies); migrations run as `alice_owner` (no `GRANT` needed: no new table or column).
- Commits: `git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only -m "..." -- <paths>` (`-m` before `--`: after `--` it is read as a path). Several agents share the index and working tree: stage by explicit path only; a new file is `git add -- <path>` first, a moved file `git mv`; never `git add -A`/`.`; check `git status --short` before committing. Never touch `.claude/`; never commit `Alice-Proje-Dokumani.pdf` or the untracked files under `docs/security/reviews/`. Every commit message ends with a blank line and `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Verification commands (real targets): `go build ./... && go vet ./...`; `go test -race -count=1 ./<pkgs>` (unit); `go test -race -count=1 -tags integration ./<pkgs>` (Docker); `make lint` (pincheck, shellcheck, docs-check, matrix-check `-strict`, golangci-lint v2.14.0 with the build-tag variants); `make test`; `make test-integration`; `make coverage` (enforces `coverage-floors.json`); `make i18n-check` (identical keys and placeholders in `locales/common` and `web/src/locales` en/tr); `make authz-doc` only when routes change (none here); web: `cd web && npx vitest run <files>`, `npm run lint`, `npx tsc --noEmit`, `make web-coverage` (thresholds in `web/vite.config.ts`); e2e: `make e2e-up && make e2e; make e2e-down`.
- Docker-based Go runs (`make test-integration`, `make coverage`, `make perf`, any `-tags integration`) never run while Playwright e2e runs, and vice versa.
- `coverage-floors.json` floors are never lowered (`alice/internal/providers/nginx` stays 98, `alice/internal/jobs/targetjobs` 100, `alice/internal/providers` 100, `alice/internal/providers/linuxssh/helperproto` 100); the new package gets `"alice/internal/providers/webserver": 98`. Web thresholds in `web/vite.config.ts` are never lowered.
- `test/matrix/traceability.json` names tests by package (`internal/providers/nginx:TestDiscoverWithoutNginxFails`, `…:TestDiscoverSharedDualAndUnsupportedLocations`, `…:TestTestConnectionChecksTheNginxProfile`, `…:TestOpenRefusesAnOutdatedHelper`, …): keep those tests in `internal/providers/nginx` under the same names (`make matrix-check` is strict).
- Locale texts exist in `en` and `tr`; Turkish is natural Turkish and never puts a suffix directly on `{{software}}` (write "{{software}} tarafından kullanılan", not "{{software}}'in"). The disabled-feature note is exactly `"Not available for {{software}} servers yet"` / `"{{software}} sunucularında henüz kullanılamıyor"`.
- The single list of web-server types: Go `inventory.webServerTypes` (read through `IsWebServer`/`WebServerTypes`), TS `WEB_SERVER_TYPES` in `web/src/api/webServer.ts`. Phases B/C extend only these lists, `providers.KindForTargetType`, the `targets.type` CHECK (their own migration) and provider registration. No component or handler checks a target type to decide availability.

## Rulings (where the spec leaves room or does not match the code)

1. **One CHECK, not two.** §3.2 says 00016 "replaces both CHECKs", but only `certificate_locations_kind_check` changes in Phase A; `targets_type_check` changes in the B and C migrations (spec says so in the same sentence). 00016 also rewrites what the spec does not mention but the code needs: the warning codes stored in `targets.facts.warnings` and the `http01_challenge` capability of existing Nginx targets.
2. **Stored warnings have Go field names.** `providers.Warning` has no JSON tags, so `targets.facts.warnings` holds `{"Code": …, "Params": …}`; the migration rewrites `Code`.
3. **`targets.capabilities` is a snapshot** taken when the target was added (`inventory/targets.go:152`). The UI reads it (`can()`), the server checks the registry (`canDeploy` style). 00016 adds `http01_challenge` to every `nginx` target, sorted in byte order like `CapabilitySet.Sorted()`.
4. **Reason prefix = provider kind.** `internal/jobs/...` may not import `internal/providers/webserver` (archtest rule `alice/internal/jobs/...`), so the spec's `Spec.ReasonPrefix` and `Spec.Software` are not fields: the prefix is `string(Kind)` through `providers.Kind.Reason(r)`, and `Spec.Software()` returns `string(Kind)` (spec §3.1: software equals type and kind).
5. **`Spec.DumpSub/TestSub` are command constructors** (`Dump, Test func() linuxssh.HelperCommand`); the subcommand name comes from `HelperCommand.Subcommand()`. `Spec.Subcommands` lists every subcommand of the profile (a sudo refusal of one of them is `<kind>.profile_missing`).
6. **`MinProtocol` and `<prefix>.helper_too_old` are deferred to Phase B**: no Phase A subcommand needs them.
7. **Dump types renamed with the response:** `NginxDumpResponse→ServerDumpResponse`, `NginxServer→DumpServer`, `NginxListen→DumpListen`, `NginxPair→DumpPair`, `NginxFile→DumpFile`, `MaxNginxConfig→MaxServerConfig`, `MaxNginxFiles→MaxServerFiles`, `NginxDumpOutput→ServerDumpOutput`. JSON tags unchanged (pinned by a test).
8. **The deployable-locations list is a deploy check, not a web-server check.** §3.4 puts `locations_list` SQL under `IsWebServer`, but `ListDeployableLocations` is "websites a binding/deployment may use … whose provider deploys" (`locations_list.go:17-20`): it filters by the types whose registered provider has `CapDeployCertificate`.
9. **ACME binding actions and deployment history in the UI.** The server page has no deployments panel today, and binding dialogs list websites from `ListDeployableLocations` (Ruling 8), so a non-deploying server's websites never reach them. Phase A wraps what exists on a web server's page: the row **Deploy** button (`deploy_certificate`) and the row **Settings** button (verification settings, `verify_deployment`), plus the HTTP-01 server choice (`http01_challenge`). B/C wrap any panel they add.
10. **Warning codes are constants.** `providers.WarnWebServerNotFound/ProfileMissing/ConfigInvalid` in `internal/providers/types.go`; the web completeness test reads them from there. The `software` text parameter is supplied by the page from the target type (`softwareName`), not by the server (not in `WARNING_PARAMS`).
11. **`warnings.config_file_writable` keeps naming Nginx** in Phase A ("An Nginx configuration file …" does not interpolate cleanly; B rewords it). Every other shared text listed in Task 7 takes `{{software}}`.
12. **Test fixtures' capability strings are wrong today** (`web/src/test/fixtures.ts:610` `'discover_certs', 'deploy_certs'`): they become the real values.

## Review Focus

1. An upgraded installation: `facts.nginx` written by Go (`omitempty` pointer, possibly a JSON `null`), warnings stored as `{"Code","Params"}`, a non-array `warnings`, locations of kind `nginx_file` — after 00016 the server page shows the same facts and warnings, and a Down restores the 00015 shape (Task 4 migration test).
2. Nginx targets added before 00016 lack `http01_challenge` in `targets.capabilities` — after 00016 they have it exactly once, sorted, and the HTTP-01 server choice stays enabled (Task 4 migration test, Task 8 UI test).
3. A web-server type whose registered provider lacks `deploy_certificate` / `http01_challenge` — deploy, KV binding, ACME binding and HTTP-01 creation are refused with the existing "not supported" errors and its websites are not in the deployable list (Tasks 2 and 3 tests with a fake `nginx` provider without the capability).
4. `facts.web_server.software` is set by every producer (dump, connection test, test "not found", the scan job's fallback) and survives a merge with older facts; a report without it never blanks it (Tasks 5 and 6 tests).
5. A target lacking a capability: the control is rendered disabled (not hidden) with the exact note in English and Turkish as its accessible description, and the row's other actions still work (Task 8 tests).

---

### Task 1: Server dump wire types renamed (helper, emulator, provider)

**Files:**
- Modify: `internal/providers/linuxssh/helperproto/helperproto.go:212-221` (limits), `:448-507` (dump types), comments at `:126`, `:162`, `:238`
- Modify: `internal/providers/linuxssh/helperproto/helperproto_test.go:169,218,247-248`
- Modify: `internal/providers/linuxssh/command.go:138-142` (`CmdNginxDump` uses `ServerDumpOutput`), `command_test.go:186`
- Modify: `cmd/alice-helper/main.go:50`, `cmd/alice-helper/nginx.go:356-440,476-583`, `cmd/alice-helper/sys.go:33`, `cmd/alice-helper/nginx_test.go`, `cmd/alice-helper/emulator_fidelity_test.go`
- Modify: `internal/providers/linuxssh/linuxsshtest/nginx_dump.go:284,520-698`, `linuxsshtest/nginx.go`, `linuxsshtest/nginx_test.go`
- Modify: `internal/providers/nginx/discover.go`, `nginx/convert_test.go`, `nginx/discover_test.go`, `nginx/deploy_test.go`, `nginx/chainrange_test.go`, `nginx/helpers_test.go`, `nginx/nginxconf/nginxconf_test.go` (comments)
- Modify: `internal/inventory/certificates.go:113` (comment), `internal/api/{certificates,keyvault,keyvault_leak,nginx_fixture}_integration_test.go`, `internal/jobs/deployjobs/{acme,deployjobs,harness,kv}_integration_test.go`

**Interfaces:**
- Produces (package `helperproto`): `type ServerDumpResponse`, `DumpServer`, `DumpListen`, `DumpPair`, `DumpFile` (fields and JSON tags exactly as the old types); consts `MaxServerConfig = 20 << 20`, `MaxServerFiles = 1000`, `ServerDumpOutput = 16 << 20`. Old names removed.

- [ ] **Step 1: Write the failing wire test** in `helperproto_test.go`:

```go
// The dump types were renamed for every web server (Phase A); the helper's answer is byte-identical.
func TestServerDumpWireNamesAreUnchanged(t *testing.T) {
	b, err := json.Marshal(ServerDumpResponse{OK: true, Servers: []DumpServer{{Listens: []DumpListen{{}}, Pairs: []DumpPair{{}}}}, Files: []DumpFile{{}}})
	require.NoError(t, err)
	assert.JSONEq(t, `{"ok":true,"version":"","conf_path":"","config_valid":false,"config_error":"","config_error_reason":"","config_error_file":"",`+
		`"servers":[{"file":"","line":0,"names":null,"listens":[{"addr":"","port":0,"default_server":false}],`+
		`"pairs":[{"cert":"","key":"","inherited":false,"unsupported":"","raw":""}],"stream":false}],`+
		`"files":[{"path":"","kind":"","exists":false,"resolved":"","symlinked":false,"mode":"","owner":"","group":"","size":0,`+
		`"sha256":"","pem":"","problem":"","free_bytes":0}],"warnings":null,"writable":null}`, string(b))
	assert.Equal(t, 20<<20, MaxServerConfig)
	assert.Equal(t, 1000, MaxServerFiles)
	assert.Equal(t, 16<<20, ServerDumpOutput)
	assert.Equal(t, 7, Protocol)
	assert.Equal(t, "1.6.1", Version)
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/providers/linuxssh/helperproto/ -run TestServerDumpWireNamesAreUnchanged`
Expected: FAIL (build error: `undefined: ServerDumpResponse`).

- [ ] **Step 3: Rename** the eight identifiers of Ruling 7 in `helperproto.go` (declarations and comments), then everywhere: `gofmt -r 'helperproto.NginxDumpResponse -> helperproto.ServerDumpResponse' -w <files>` (and the same for the other seven), plus a word-boundary `sed` for unqualified uses inside `helperproto` and for comments. Change nothing else (no `Sub*`, no deploy type).

- [ ] **Step 4: Run the tests**

Run: `go build ./... && go vet ./... && go test -race -count=1 ./internal/providers/linuxssh/... ./internal/providers/nginx/... ./cmd/alice-helper/... && go vet -tags integration ./internal/... && grep -rnE 'NginxDumpResponse|NginxServer\b|NginxPair\b|NginxFile\b|NginxListen\b|MaxNginx|NginxDumpOutput' --include=*.go . ; echo "grep exit $?"`
Expected: all PASS; grep prints nothing and `grep exit 1`.

- [ ] **Step 5: Commit** the files listed above: `refactor(helperproto): the dump types and limits are named for every web server; wire format unchanged`.

---

### Task 2: Capability `http01_challenge` decides the ACME HTTP-01 server

**Files:**
- Modify: `internal/providers/capability.go:13-27,60-64`
- Modify: `internal/providers/nginx/provider.go:48-54` (advertise `CapHTTP01`)
- Modify: `internal/inventory/deployments.go:502-506` (generalize `canDeploy`)
- Modify: `internal/inventory/acme_certificates.go:253-266`
- Modify: `internal/jobs/acmejobs/acmejobs.go:451-470`
- Test: `internal/providers/providers_test.go`, `internal/providers/nginx/provider_test.go:22`, `cmd/alice/providers_test.go:46`, `internal/inventory/acme_certificates_integration_test.go` (`newCertWorld` registry), `internal/inventory/harness_integration_test.go:121-123` (`nginxCaps`), `internal/jobs/acmejobs/acmejobs_test.go:366,380,508,660`, `internal/jobs/acmejobs/harness_integration_test.go:119`

**Interfaces:**
- Produces: `providers.CapHTTP01 Capability = "http01_challenge"` (in `knownCapabilities`); `func (s *Service) can(typ string, c providers.Capability) bool` in `internal/inventory/deployments.go` (registered provider of the type has `c`); `canDeploy(typ)` becomes `s.can(typ, providers.CapDeployCertificate)`.

- [ ] **Step 1: Write the failing tests**
  - `providers_test.go`: `TestHTTP01IsAKnownCapability` — `providers.CapHTTP01 == "http01_challenge"`, and registering `fake.New(providers.KindNginx, providers.CapHTTP01)` in a fresh registry does not panic.
  - `nginx/provider_test.go:22` and `cmd/alice/providers_test.go:46`: the expected nginx capability lists gain `providers.CapHTTP01`.
  - `acme_certificates_integration_test.go`: `TestACMEHTTP01NeedsAProviderThatPublishes` — a service whose registry holds the harness linuxssh fake plus `fake.New(providers.KindNginx, nginxCaps...)` **without** `CapHTTP01` refuses `CreateACMECertificate{Challenge: "http01", HTTPTargetID: &web}` with `errors.Is(err, inventory.ErrACMEChallengeUnavailable)`; with `CapHTTP01` it is accepted. `newCertWorld` builds its registry with the nginx fake carrying `append(nginxCaps, providers.CapHTTP01)` so the existing HTTP-01 cases keep passing.
  - `acmejobs_test.go`: `TestOpenPublisherNeedsTheHTTP01Capability` — a registry `pubProvider{Provider: fake.New(providers.KindNginx, providers.CapTestConnection)}` (no `CapHTTP01`) makes `openPublisher` answer `inventory.ErrACMEChallengeUnavailable` and records no `Open` call; the existing fakes at `:366,:380,:508,:660` and `harness_integration_test.go:119` gain `providers.CapHTTP01`.

- [ ] **Step 2: Run them to verify they fail**

Run: `go test -run 'HTTP01|Capabilit|Provider' ./internal/providers/ ./internal/providers/nginx/ ./internal/jobs/acmejobs/ ./cmd/alice/`
Expected: FAIL (`undefined: providers.CapHTTP01`).

- [ ] **Step 3: Implement**
  - `capability.go`: the const with comment `// CapHTTP01: publish and remove an ACME HTTP-01 token on the server (http01.Publisher; spec 2026-10-17 §3.4).`, added to `knownCapabilities`.
  - `nginx.New`: add `providers.CapHTTP01`.
  - `acme_certificates.go:264`: replace `typ != TypeNginx` with `!s.can(typ, providers.CapHTTP01)` (comment: only a provider that publishes HTTP-01 tokens — the nginx profile's sudoers lines — may be the HTTP-01 server).
  - `acmejobs.go` `openPublisher`: after the two error cases, look up `p, ok := h.d.Registry.Get(ref.Kind)`; `!ok || !p.Capabilities().Has(providers.CapHTTP01)` returns `inventory.ErrACMEChallengeUnavailable` at the place of today's `t.Type != inventory.TypeNginx` case (before the status cases, so precedence is unchanged); reuse `p` for `Open`.

- [ ] **Step 4: Run the tests**

Run: `go test -race -count=1 ./internal/providers/... ./internal/jobs/acmejobs/ ./cmd/alice/ && go test -race -count=1 -tags integration ./internal/inventory/ ./internal/jobs/acmejobs/ -run 'ACME|Acme|HTTP01'`
Expected: PASS.

- [ ] **Step 5: Commit** (files above): `feat(providers): capability http01_challenge decides which servers may publish an ACME HTTP-01 token`.

---

### Task 3: `IsWebServer` and capability-driven deploy checks (Go)

**Files:**
- Modify: `internal/inventory/types.go:21-28` (lists), `:139` (comment)
- Modify: `internal/inventory/deployments.go:472`, `bindings.go:306`, `acme_bindings.go:217`
- Modify: `internal/inventory/locations_list.go:17-20,82-130` (deploy types parameter)
- Modify: `internal/inventory/sshkeys.go:148-151`, `validate.go:27,157`
- Modify: `internal/api/sshkeys_handlers.go:376`, `internal/api/vaults_handlers.go:369`, `internal/sshkeys/deploy.go:215`
- Create: `internal/inventory/types_test.go` (if absent; else add to the existing unit test file of the package), `internal/archtest/webserver_test.go`
- Test: `internal/inventory/bindings_integration_test.go` (or the deploy fixture file), any integration test listing deployable locations without a deploying nginx provider (`grep -rn ListDeployableLocations internal --include=*_integration_test.go`)

**Interfaces:**
- Consumes: `(*Service).can(typ, providers.Capability)` (Task 2).
- Produces (package `inventory`): `func IsWebServer(typ string) bool`; `func IsServer(typ string) bool` (`TypeLinux` or a web server); `func WebServerTypes() []string` (a copy of the one list `var webServerTypes = []string{TypeNginx}`); `func (s *Service) deployTypes() []string` (web-server types whose provider has `CapDeployCertificate`).

- [ ] **Step 1: Write the failing tests**
  - `TestWebServerTypes`: `IsWebServer("nginx")` true; `IsWebServer("linux")`, `("azure_key_vault")`, `("")`, `("NGINX")` false; `IsServer("linux")` and `IsServer("nginx")` true, `IsServer("azure_key_vault")` false; `WebServerTypes()` equals `[]string{"nginx"}` and mutating the result does not change the next call.
  - Integration `TestAWebServerWhoseProviderDoesNotDeployIsRefused`: harness with the linuxssh fake and `fake.New(providers.KindNginx, providers.CapTestConnection, providers.CapDiscoverSSHKeys, providers.CapAuthorizedKeys, providers.CapDiscoverCerts)` (no deploy); a supported location on an `nginx` target: `RequestDeployment` → `ErrLocationUnsupported`; `ListDeployableLocations(LocationFilter{})` has no item; with `withNginxProvider()` the same location is listed and deployable (the existing tests).
  - `internal/archtest/webserver_test.go` `TestOnlyTheTypeListNamesNginx`: walk non-test `.go` files under `internal/` and `cmd/` (pattern of `targets_test.go`), fail on any identifier `TypeNginx` outside `internal/inventory/types.go` (report file:line).

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/inventory/ -run TestWebServerTypes; go test ./internal/archtest/ -run TestOnlyTheTypeListNamesNginx`
Expected: FAIL (`undefined: inventory.IsWebServer`; archtest lists `deployments.go:472`, `bindings.go:306`, …).

- [ ] **Step 3: Implement**
  - `deployments.go:472`, `bindings.go:306`, `acme_bindings.go:217`: the clause `t.Type != TypeNginx || !s.canDeploy(t.Type)` becomes `!s.canDeploy(t.Type)` (a type without a registered deploying provider, Linux included, is refused exactly as before).
  - `locations_list.go`: comment "of web servers whose provider deploys"; SQL `t.type = 'nginx'` → `t.type = ANY($N::text[])` with `s.deployTypes()` (an empty list matches nothing).
  - `sshkeys.go:148`: `!IsWebServer(t.Type)` (comment: certificates belong to web servers only).
  - `validate.go`: allowed types = `TypeLinux` plus `WebServerTypes()`; `typeValues()` joins the same list with ", ".
  - `api/sshkeys_handlers.go:376`, `sshkeys/deploy.go:215`: `!inventory.IsServer(t.Type)`; `api/vaults_handlers.go:369`: `vaultTypes` built from `TypeLinux`, `inventory.WebServerTypes()...`, `TypeAzureKeyVault`.
  - Give `withNginxProvider()` to any integration test that lists deployable websites with a registry lacking a deploying nginx provider.

- [ ] **Step 4: Run the tests**

Run: `go build ./... && go test -race -count=1 ./internal/inventory/ ./internal/archtest/ ./internal/api/ ./internal/sshkeys/... && go test -race -count=1 -tags integration ./internal/inventory/ ./internal/sshkeys/... ./internal/api/ -run 'Deploy|Binding|Location|Target|Key'`
Expected: PASS.

- [ ] **Step 5: Commit**: `refactor(inventory): web-server types come from one list; deploy and binding checks ask the provider's capability`.

---

### Task 4: Facts, warning codes and location kind renamed end to end, with migration 00016

One atomic task: the Go JSON tags, the stored data, the API, `openapi.yaml`, the web types and the web completeness test (`web/src/api/enums.test.ts` reads Go sources and `openapi.yaml`) must change together.

**Files:**
- Create: `migrations/00016_web_server_standard.sql`, `migrations/web_server_integration_test.go`
- Modify: `internal/providers/types.go:23,50,246-272,379-405` (facts type, report/result fields, warning consts)
- Modify: `internal/inventory/types.go:105`, `status.go:122-150`, `sshkeys.go:119-151,218-230,262-283`, `locations.go:36-37,300-322`, `deployments.go:476`, `deployment_records.go:228`
- Modify: `internal/providers/nginx/provider.go:160-195`, `nginx/discover.go:85-100,163-175`, `internal/providers/fake/fake.go:197-203,417`, `internal/jobs/targetjobs/targetjobs.go:223-238`
- Modify: `internal/api/certs_dto.go:395-411`, `internal/api/inventory_dto.go:105,148`, `api/openapi.yaml:5952-5968,6506-6525`
- Modify: `cmd/alice/serve_integration_test.go:54,82` (version 15 → 16, comment)
- Modify (web): `web/src/api/types.ts:297-319`, `web/src/api/nginx.ts:12,21-26`, `web/src/api/warnings.ts:10,41-44`, `web/src/components/WebsitesPanel.tsx:65-83`, `web/src/pages/TargetDetailPage.tsx:357-367`, `web/src/test/fixtures.ts:38,599-615`, `web/src/api/enums.test.ts:145-252`, `web/src/components/WebsitesPanel.test.tsx`, `web/src/pages/TargetDetailPage.test.tsx`, `web/src/locales/en.json` and `tr.json` (`warnings.nginx_*` keys renamed, texts unchanged)
- Modify (tests, renames only): every file from `grep -rlnE 'NginxFacts|\.Nginx\b|nginx_file|nginx_not_found|nginx_profile_missing|nginx_config_invalid|mergeNginxFacts' --include=*.go .` (today: `internal/alerts/alerts_integration_test.go`, `internal/api/{deployments_handlers_test,discovery_integration_test,perf_integration_test,perf_netdisco_integration_test,phase7_integration_test,session_integration_test}.go`, `internal/backup/{acme,f85}_integration_test.go`, `internal/discovery/store_integration_test.go`, `internal/inventory/{acme_certificates,certificates,sshkeys,targets}_integration_test.go`, `internal/inventory/locations_test.go`, `internal/jobs/kvjobs/kvjobs_integration_test.go`, `internal/jobs/targetjobs/targetjobs_test.go`, `internal/providers/fake/fake_test.go`, `internal/providers/nginx/*_test.go`, `internal/providers/linuxssh/linuxsshtest/nginx_test.go`, `internal/testutil/seed/seed.go`, `migrations/{certificates,keyvault}_integration_test.go` — rows inserted at the latest version use `server_file`, rows inserted after `DownTo(n)` with `n < 16` keep `nginx_file`)

**Interfaces:**
- Consumes: nothing new.
- Produces:
  - `providers.WebServerFacts` = old `NginxFacts` fields and tags plus first field `Software string \`json:"software"\`` ("nginx" | "apache" | "haproxy"; equals the provider kind).
  - `providers.ConnectionReport.WebServer *WebServerFacts`, `providers.DiscoveryResult.WebServer *WebServerFacts`.
  - `providers.WarnWebServerNotFound = "web_server_not_found"`, `WarnWebServerProfileMissing = "web_server_profile_missing"`, `WarnWebServerConfigInvalid = "web_server_config_invalid"`.
  - `inventory.Facts.WebServer *providers.WebServerFacts \`json:"web_server,omitempty"\``; `func mergeWebServerFacts(old *providers.WebServerFacts, n providers.WebServerFacts) *providers.WebServerFacts` (as today, plus: `n.Software == ""` takes `old.Software`; `Software` is cleaned); `configUsable(*providers.WebServerFacts)`; `locationKind = "server_file"`.
  - API: `webServerFactsDTO`/`webServerFactsJSON`, `TargetFacts.web_server`; OpenAPI schema `WebServerFacts` (adds required `software`, `enum: [nginx]`).
  - Web: `interface WebServerFacts` (adds `software: 'nginx'`), `TargetFacts.web_server?: WebServerFacts`; fixture `webServerFacts()` (renamed from `nginxFacts()`, `software: 'nginx'`).

- [ ] **Step 1: Write the failing migration test** `migrations/web_server_integration_test.go` (`//go:build integration`, package `migrations_test`, same helpers as `ldap_integration_test.go`): `TestMigration00016RewritesWebServerDataAndDownRestoresIt`:
  - `p.DownTo(ctx, 15)`; insert as owner: a credential, an `nginx` target A with `capabilities '{authorized_keys,deploy_certificate,discover_certificates,discover_ssh_keys,key_login,test_connection,verify_deployment}'` and facts `{"os":{…},"nginx":{"version":"1.24.0","conf_path":"/etc/nginx/nginx.conf","config_valid":true,"config_error":"","config_error_reason":"","config_error_file":"","found":true},"warnings":[{"Code":"nginx_profile_missing","Params":{}},{"Code":"stream_tls","Params":{}}]}`; an `nginx` target B with `{"nginx":null,"warnings":"x"}`; a `linux` target C with `{"warnings":[{"Code":"keys_managed_elsewhere","Params":{}}]}`; one certificate and a location of A with kind `nginx_file`.
  - `p.Up(ctx)` → version 16; A's facts: no key `nginx`, `web_server` = the old object plus `"software":"nginx"`, warnings codes `["web_server_profile_missing","stream_tls"]` in order with `Params` kept; A's capabilities = the old list plus `http01_challenge` in byte order (`…,discover_ssh_keys,http01_challenge,key_login,…`); B's facts have neither `nginx` nor `web_server` and `warnings` is still `"x"`; C unchanged; the location's kind is `server_file`; inserting another location with kind `nginx_file` fails with SQLSTATE `23514`.
  - `p.DownTo(ctx, 15)`: A's facts equal the inserted `nginx` object (no `software`), warning code back to `nginx_profile_missing`, capabilities equal the inserted list, kind `nginx_file`; then `p.Up(ctx)` again succeeds and `http01_challenge` appears exactly once in A's capabilities.

- [ ] **Step 2: Run it to verify it fails**

Run: `go test -count=1 -tags integration ./migrations/ -run TestMigration00016`
Expected: FAIL (version stays 15; facts unchanged).

- [ ] **Step 3: Write `migrations/00016_web_server_standard.sql` verbatim:**

```sql
-- +goose Up
-- Web server providers, Phase A "Standardize" (spec docs/superpowers/specs/2026-10-17-web-server-providers-design.md §3.2;
-- plan docs/superpowers/plans/2026-10-17-web-server-standard.md, Task 4). The Nginx-only names that are not about
-- deployment become the shared web-server ones; deployment keeps its Nginx names. targets.type is unchanged: the apache
-- (Phase B) and haproxy (Phase C) types come with their own migrations.

-- The facts key nginx becomes web_server and names its software. A JSON null (Alice never writes one) is dropped.
UPDATE targets
SET facts = (facts - 'nginx') || jsonb_build_object('web_server', (facts -> 'nginx') || '{"software": "nginx"}'::jsonb)
WHERE jsonb_typeof(facts -> 'nginx') = 'object';
UPDATE targets SET facts = facts - 'nginx' WHERE facts ? 'nginx';

-- The scan's server-level warning codes. facts.warnings holds providers.Warning as Go writes it (no JSON tags: "Code",
-- "Params"); the order is kept.
UPDATE targets t
SET facts = jsonb_set(t.facts, '{warnings}', (
    SELECT jsonb_agg(CASE WHEN e.w ->> 'Code' IN ('nginx_not_found', 'nginx_profile_missing', 'nginx_config_invalid')
                          THEN jsonb_set(e.w, '{Code}', to_jsonb('web_server_' || substr(e.w ->> 'Code', 7)))
                          ELSE e.w END ORDER BY e.n)
    FROM jsonb_array_elements(t.facts -> 'warnings') WITH ORDINALITY AS e (w, n)))
WHERE jsonb_typeof(t.facts -> 'warnings') = 'array'
  AND EXISTS (SELECT 1 FROM jsonb_array_elements(t.facts -> 'warnings') AS x (w)
              WHERE x.w ->> 'Code' IN ('nginx_not_found', 'nginx_profile_missing', 'nginx_config_invalid'));

-- targets.capabilities is the provider's set when the target was added: Nginx targets gain the ACME HTTP-01 capability
-- (providers.CapHTTP01), in the byte order of CapabilitySet.Sorted.
UPDATE targets
SET capabilities = ARRAY(SELECT u.c FROM unnest(capabilities || '{http01_challenge}'::text[]) AS u (c) ORDER BY u.c COLLATE "C")
WHERE type = 'nginx' AND NOT ('http01_challenge' = ANY (capabilities));

-- A certificate file of any web server (was nginx_file).
ALTER TABLE certificate_locations DROP CONSTRAINT certificate_locations_kind_check;
UPDATE certificate_locations SET kind = 'server_file' WHERE kind = 'nginx_file';
ALTER TABLE certificate_locations ADD CONSTRAINT certificate_locations_kind_check CHECK (kind IN ('server_file'));

-- +goose Down
-- Restores the 00015 shape. Correct while only Nginx is a web server (Phases B and C add their own Down first).
ALTER TABLE certificate_locations DROP CONSTRAINT certificate_locations_kind_check;
UPDATE certificate_locations SET kind = 'nginx_file' WHERE kind = 'server_file';
ALTER TABLE certificate_locations ADD CONSTRAINT certificate_locations_kind_check CHECK (kind IN ('nginx_file'));

UPDATE targets SET capabilities = array_remove(capabilities, 'http01_challenge') WHERE type = 'nginx';

UPDATE targets t
SET facts = jsonb_set(t.facts, '{warnings}', (
    SELECT jsonb_agg(CASE WHEN e.w ->> 'Code' IN ('web_server_not_found', 'web_server_profile_missing', 'web_server_config_invalid')
                          THEN jsonb_set(e.w, '{Code}', to_jsonb('nginx_' || substr(e.w ->> 'Code', 12)))
                          ELSE e.w END ORDER BY e.n)
    FROM jsonb_array_elements(t.facts -> 'warnings') WITH ORDINALITY AS e (w, n)))
WHERE jsonb_typeof(t.facts -> 'warnings') = 'array'
  AND EXISTS (SELECT 1 FROM jsonb_array_elements(t.facts -> 'warnings') AS x (w)
              WHERE x.w ->> 'Code' IN ('web_server_not_found', 'web_server_profile_missing', 'web_server_config_invalid'));

UPDATE targets
SET facts = (facts - 'web_server') || jsonb_build_object('nginx', (facts -> 'web_server') - 'software')
WHERE jsonb_typeof(facts -> 'web_server') = 'object';
UPDATE targets SET facts = facts - 'web_server' WHERE facts ? 'web_server';
```

- [ ] **Step 4: Run the migration test**

Run: `go test -count=1 -tags integration ./migrations/ -run 'TestMigration00016|TestReleasedMigrationsAreFrozen'`
Expected: PASS (the frozen test logs `00016_web_server_standard.sql is not frozen yet`).

- [ ] **Step 5: Write the failing Go and web tests**
  - `inventory/locations_test.go` (unit): `configUsable` table on `*providers.WebServerFacts`; new `TestMergeWebServerFactsKeepsTheSoftware` (in a `status_test.go` unit file of package `inventory`): old `{Software:"nginx",Found:true,Version:"1.24.0",ConfPath:"/etc/nginx/nginx.conf"}` merged with `{Found:true,ConfigValid:true}` gives `Software "nginx"`, version and path kept; a report with `Software:"nginx"` and `Found:false` replaces version/path with "".
  - `targetjobs_test.go`: the not-found fallback stores `WebServer == &providers.WebServerFacts{Software: "nginx"}` and warning `providers.WarnWebServerNotFound`; the profile case warns `providers.WarnWebServerProfileMissing` and leaves `WebServer` nil.
  - `nginx/provider_test.go`: `TestTestConnectionChecksTheNginxProfile` and the not-found/invalid cases expect `rep.WebServer.Software == "nginx"` and the new warning codes.
  - `web/src/api/enums.test.ts`: `nginxWarnings` reads `goFiles('internal/providers/nginx')` **and** `goFiles('internal/providers/webserver')` when the directory exists (guard with `existsSync`); `jobWarnings` is removed (the codes are `Warn*` constants now, read by `typesWarnings`); the openapi sentence regex becomes `/Phase 4 values for web servers include ([^;]*?); a newer/` with `\b(web_server_[a-z_]+|[a-z]+_[a-z_]+)\b`; `nginxOnly` lists `web_server_not_found`, `web_server_profile_missing`, `web_server_config_invalid` (rename the const `webServerOnly`); `knownValues('WebServerFacts', …)`; the `arrayContaining` check expects `web_server_profile_missing`; add `eq(enumOf('WebServerFacts', 'software'), ['nginx'])`.

- [ ] **Step 6: Run them to verify they fail**

Run: `go test ./internal/inventory/ ./internal/jobs/targetjobs/ ./internal/providers/nginx/ 2>&1 | tail -5; cd web && npx vitest run src/api/enums.test.ts`
Expected: FAIL (build errors / unknown schema `WebServerFacts`).

- [ ] **Step 7: Implement the renames** (exact names in Interfaces):
  - `providers/types.go`: rename the type and fields; comments say "web server"; the three `Warn*` constants join the warnings block (comment: server-level codes of every web-server provider and of the scan job).
  - Producers set `Software`: `nginx/provider.go` TestConnection (`&providers.WebServerFacts{Software: "nginx"}` when not found; `Found: true, Software: "nginx"` otherwise), `nginx/discover.go` `nginxFacts` (`Software: "nginx"`; renamed `webServerFacts` in Task 5), `targetjobs.go:236` (`&providers.WebServerFacts{Software: string(providers.KindNginx)}`; generalized in Task 6). Warning literals become the constants.
  - Inventory: `Facts.WebServer`, `mergeWebServerFacts`, `configUsable`, `res.WebServer`/`r.WebServer` everywhere listed; `deployments.go:476` and `deployment_records.go:228` read `WebServer`; `locationKind = "server_file"` (comment: a certificate file of a web server).
  - API: DTO with `Software string \`json:"software"\`` first; `TargetFacts.WebServer *webServerFactsDTO \`json:"web_server,omitempty"\`` (comment: web servers only).
  - `openapi.yaml`: schema `NginxFacts` → `WebServerFacts` (description "Present for web servers that were tested or scanned", `required` gains `software`, property `software: { type: string, enum: [nginx], description: 'The web server software; equals the target type' }`); `TargetFacts.nginx` → `web_server: { $ref: "#/components/schemas/WebServerFacts" }`; warnings description: `Phase 4 values for web servers include web_server_not_found, web_server_profile_missing, locations_dropped, list_truncated, too_many_files, stream_tls, mail_tls and config_file_writable (params.path); a newer server may add others.`
  - Web: types and fixture renames; `nginx.ts` reads `target.facts.web_server` and the codes `web_server_config_invalid`/`web_server_profile_missing`/`web_server_not_found` (file rename comes in Task 7); `warnings.ts` keys renamed (comment "Web servers"); locales: move `warnings.nginx_not_found|nginx_profile_missing|nginx_config_invalid` to `warnings.web_server_not_found|web_server_profile_missing|web_server_config_invalid` in both files with the same texts.
  - `cmd/alice/serve_integration_test.go`: `int64(16)`, message `"serve applied 00006 to 00016"`, comment.

- [ ] **Step 8: Run everything touched**

Run: `go build ./... && go vet ./... && go vet -tags integration ./... && go test -race -count=1 ./internal/... ./cmd/... && make i18n-check && (cd web && npx tsc --noEmit && npx vitest run && npm run lint) && go test -race -count=1 -tags integration ./migrations/ ./internal/inventory/ ./internal/jobs/... ./internal/api/ ./internal/backup/... ./internal/alerts/... ./internal/discovery/... ./cmd/alice/ && grep -rnE 'NginxFacts|\bnginx_file\b|nginx_(not_found|profile_missing|config_invalid)|mergeNginxFacts' --include=*.go --include=*.yaml internal cmd api migrations; grep -nE 'NginxFacts|nginx_(not_found|profile_missing|config_invalid)' web/src/api/warnings.ts web/src/api/types.ts`
Expected: all PASS; grep prints nothing (the web `DeployBlock` value and `locations.unavailable.nginx_not_found` key are renamed in Task 7).

- [ ] **Step 9: Commit** (all files above; the new two with `git add --` first): `refactor!: facts.web_server, web_server_* warning codes and server_file locations replace the Nginx-only names (migration 00016)`.

---

### Task 5: Shared provider package `internal/providers/webserver`; `nginx` embeds it

**Files:**
- Create: `internal/providers/webserver/webserver.go` (Spec, Base, Session, shared reasons), `internal/providers/webserver/convert.go` (moved from `nginx/discover.go`: bounds, closed sets, `clean`, `cleanPath`, `shownPath`, `invalidPath`, `knownOrEmpty`, `knownOrDefault`, `build`, `pairState`, `certServer`, `sameServer`, `convert`, `finish`, `descriptionOf`, `resolvedOutsideVocabulary`, `fileProblem`, `certificateChain`, `cleanMode`, `customLocation`, `locationWarnings`, `dumpWarnings`, `webServerFacts`)
- Move: `internal/providers/nginx/convert_test.go` → `internal/providers/webserver/convert_test.go` (`git mv`; package `webserver`; `convert(d)` → `convert(d, nginxFolders)`)
- Create: `internal/providers/webserver/webserver_test.go`, `internal/providers/webserver/helpers_test.go` (minimal env on `linuxsshtest`, copied from `nginx/helpers_test.go:42-85,182-235`)
- Delete: `internal/providers/nginx/discover.go` (its `Discover` moves to `webserver.Session`)
- Modify: `internal/providers/nginx/provider.go` (embed `webserver.Base`; session embeds `*webserver.Session`; TestConnection, `warning`, `isHelperCode`, `isNginxSub` and the three shared cases of `mapHelper` go), `nginx/deploy.go`, `nginx/verify.go` (`s.conn` → `s.Conn()`, `s.open()` → `s.Live()`; own `const maxChainCerts = 20` in `verify.go`), `nginx/*_test.go` (accessors)
- Modify: `internal/providers/provider.go:20-41` (shared reasons), `internal/providers/providers_test.go`
- Modify: `coverage-floors.json` (add `"alice/internal/providers/webserver": 98`)
- Modify: `web/src/api/enums.test.ts` (drop the `existsSync` guard from Task 4)

**Interfaces:**
- Consumes: `providers.WebServerFacts`, `WarnWebServer*` (Task 4); `helperproto.ServerDumpResponse` & co (Task 1).
- Produces:
  - `providers`: consts `ReasonNotFound = "not_found"`, `ReasonProfileMissing = "profile_missing"`, `ReasonConfigInvalid = "config_invalid"`; `func (k Kind) Reason(r string) string` (`string(k) + "." + r`).
  - `webserver`:
    ```go
    type Spec struct {
        Kind           providers.Kind
        DisplayNameKey string
        Dump, Test     func() linuxssh.HelperCommand // Dump answers helperproto.ServerDumpResponse, Test helperproto.NginxTestResponse
        Subcommands    []string                      // every helper subcommand of the provider's sudoers profile
        UsualFolders   []string                      // a resolved certificate outside them is custom_location
    }
    func (s Spec) Software() string                                  // string(s.Kind)
    func (s Spec) SharedReason(err error, sub string) *providers.Error // nil when err is not a shared answer
    func BaseCapabilities() []providers.Capability                   // test_connection, discover_ssh_keys, authorized_keys, discover_certificates, key_login
    type Base struct{ /* ssh *linuxssh.Provider; spec Spec */ }
    func NewBase(ssh *linuxssh.Provider, spec Spec) Base             // panics on nil ssh, empty Kind/DisplayNameKey, nil Dump/Test, no Subcommands
    func (b Base) Kind() providers.Kind
    func (b Base) DisplayNameKey() string
    func (b Base) ConfigSchema() providers.ConfigSchema
    func (b Base) CredentialSchema() providers.CredentialSchema
    func (b Base) ValidateConfig(cfg providers.TargetConfig) []validate.FieldError
    func (b Base) ForgetTarget(target uuid.UUID)
    func (b Base) OpenSession(ctx context.Context, t providers.TargetRef, cred providers.CredentialSource, env providers.Env) (*Session, error)
    type Session struct{ providers.Session /* + conn, spec, closed */ }
    func (s *Session) Conn() *linuxssh.Conn
    func (s *Session) Live() error // ssh.unreachable once closed
    func (s *Session) Close() error
    func (s *Session) TestConnection(ctx context.Context) (providers.ConnectionReport, error)
    func (s *Session) Discover(ctx context.Context, req providers.DiscoverRequest) (providers.DiscoveryResult, error)
    func IsHelperCode(err error, code string) bool
    ```
  - `SharedReason` maps: `ssh.helper_missing` with `exit_code "1"` and `sub` in `Subcommands` → `NewError(Kind.Reason(ReasonProfileMissing), false, err, {"subcommand": sub, "profile": Software()})`; `ssh.helper_refused`/`ssh.file_changed` with `helper_code` `CodeNginxNotFound` → `Kind.Reason(ReasonNotFound)`, `CodeConfigInvalid` → `Kind.Reason(ReasonConfigInvalid)`; anything else nil.
  - `nginx`: unexported `var spec = webserver.Spec{Kind: providers.KindNginx, DisplayNameKey: "provider.nginx.name", Dump: linuxssh.CmdNginxDump, Test: linuxssh.CmdNginxTest, Subcommands: []string{SubNginxDump, SubNginxTest, SubNginxDeploy, SubNginxRestore, SubNginxStatus, SubNginxFence}, UsualFolders: []string{"/etc/ssl/", "/etc/nginx/", "/etc/pki/", "/etc/letsencrypt/"}}`; `mapHelper(err, sub)` first returns `spec.SharedReason(err, sub)` when non-nil, then the Nginx-only codes as today.

- [ ] **Step 1: Write the failing tests** (`internal/providers/webserver`, `providers_test.go`):
  - `TestKindReason`: `providers.KindNginx.Reason(providers.ReasonNotFound) == "nginx.not_found"`, same for `profile_missing`, `config_invalid`.
  - `TestNewBaseRefusesAnIncompleteSpec`: table (nil ssh, empty Kind, empty DisplayNameKey, nil Dump, nil Test, no Subcommands) each `assert.Panics`.
  - `TestSharedReason`: sudo refusal of `nginx-deploy` → `nginx.profile_missing` with params `{"subcommand":"nginx-deploy","profile":"nginx"}`; sudo refusal of `acme-challenge-put` → nil; `NGINX_NOT_FOUND` → `nginx.not_found`; `CONFIG_INVALID` → `nginx.config_invalid`; `BUSY` → nil; a non-provider error → nil.
  - `TestTestConnectionReportsTheWebServer` (emulator): valid → `WebServer{Software:"nginx",Found:true,ConfigValid:true}`, no warning; invalid → `ConfigValid:false`, known `ConfigError`, warning `web_server_config_invalid`; no nginx → `WebServer{Software:"nginx"}` and warning `web_server_not_found`, no error; sudoers without the nginx lines → error code `nginx.profile_missing`.
  - `TestDiscoverHalves` (emulator): certificates-only runs no SSH-key discovery and returns `WebServer.Software "nginx"` and the certificates; SSH-only runs no dump command; no nginx → error `nginx.not_found`; invalid config → result with warning `web_server_config_invalid` and no certificates.
  - `TestClosedSessionIsNotLive`: after `Close`, `Live()`, `TestConnection` and `Discover` answer `ssh.unreachable`.
  - `convert_test.go` (moved) `TestWebServerFactsOfTheDump` (renamed from `TestNginxFactsOfTheDump`) also asserts `Software`.

- [ ] **Step 2: Run them to verify they fail**

Run: `go test ./internal/providers/ ./internal/providers/webserver/`
Expected: FAIL (`undefined: providers.ReasonNotFound`; package `webserver` has no non-test files).

- [ ] **Step 3: Implement** per the Interfaces. `Session.Discover` is today's `nginx` `Discover` with `s.spec.Dump()`, `DecodeHelper[helperproto.ServerDumpResponse](out, cmd.Subcommand())`, `res.WebServer = &facts` from `webServerFacts(s.spec.Software(), d)`, `convert(d, s.spec.UsualFolders)` and `mapHelper` replaced by: shared reason if any, else the error unchanged. `Session.TestConnection` is today's nginx TestConnection with `s.spec.Test()` and the warning constants. `nginx.Provider` embeds `webserver.Base` (built with `webserver.NewBase(o.SSH, spec)`), keeps `Capabilities()` (`BaseCapabilities()` + `CapDeployCertificate`, `CapVerifyDeployment`, `CapHTTP01`), `Open` wraps `OpenSession` and adds `host`, `clock`, `log`. Keep every test named in `test/matrix/traceability.json` in `internal/providers/nginx`. Add the coverage floor.

- [ ] **Step 4: Run the tests and coverage of both packages**

Run: `go build ./... && go vet ./... && go test -race -count=1 ./internal/providers/... ./cmd/alice/ ./internal/archtest/ && go test -count=1 -tags integration -cover ./internal/providers/webserver/ ./internal/providers/nginx/ && go run ./tools/matrixcheck -spec docs/superpowers/specs/alice-v1/06-quality.md -map test/matrix/traceability.json -doc docs/security/traceability.md -strict && (cd web && npx vitest run src/api/enums.test.ts)`
Expected: PASS; coverage `webserver` ≥ 98.0 % and `nginx` ≥ 98.0 % (if `nginx` drops below, add tests for its remaining deploy/verify branches; never lower a floor).

- [ ] **Step 5: Commit** (`git add -- internal/providers/webserver/webserver.go internal/providers/webserver/convert.go internal/providers/webserver/webserver_test.go internal/providers/webserver/helpers_test.go`; `git mv` and `git rm` already staged): `refactor(providers): the shared web-server layer (open, test, discovery, dump conversion, shared reasons) moves to providers/webserver; nginx embeds it`.

---

### Task 6: The scan job treats every web-server kind alike

**Files:**
- Modify: `internal/jobs/targetjobs/targetjobs.go:180-238`
- Test: `internal/jobs/targetjobs/targetjobs_test.go:520-600`

**Interfaces:**
- Consumes: `inventory.IsWebServer` (Task 3), `providers.Kind.Reason`, `providers.ReasonNotFound/ReasonProfileMissing` (Task 5), `providers.WarnWebServerNotFound/ProfileMissing`, `providers.WebServerFacts` (Task 4).

- [ ] **Step 1: Write the failing test** `TestScanFallsBackForEveryWebServerKind`: a fake provider registered under `providers.KindNginx` whose certificate discovery fails with `providers.NewError("nginx.not_found", …)` gets the SSH half scanned and `WebServer == &providers.WebServerFacts{Software: "nginx"}`; a linux target whose (fake) discovery fails with `nginx.not_found` is **not** given the fallback (the error is returned as today: `jobs.FromProvider`); a web-server error of another kind's prefix (`apache.not_found` from the nginx fake) is not treated as this kind's.

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/jobs/targetjobs/ -run TestScanFallsBackForEveryWebServerKind`
Expected: FAIL (the linux case takes the fallback today).

- [ ] **Step 3: Implement**: `kind, _ := providers.KindForTargetType(t.Type)`; the fallback condition is `req.Certificates && inventory.IsWebServer(t.Type) && (isCode(err, kind.Reason(providers.ReasonNotFound)) || isCode(err, kind.Reason(providers.ReasonProfileMissing)))`; the not-found facts are `&providers.WebServerFacts{Software: string(kind)}`; comments say "web server".

- [ ] **Step 4: Run the tests with coverage**

Run: `go test -race -count=1 -cover ./internal/jobs/targetjobs/ && go test -race -count=1 -tags integration -cover ./internal/jobs/targetjobs/`
Expected: PASS, coverage 100.0 % (floor 100).

- [ ] **Step 5: Commit**: `refactor(targetjobs): the certificate fallback applies to every web-server kind by its reason prefix`.

---

### Task 7: Web module `webServer.ts`, `can()` and `{{software}}` texts

**Files:**
- Move: `web/src/api/nginx.ts` → `web/src/api/webServer.ts` (`git mv`)
- Create: `web/src/api/capabilities.ts`, `web/src/api/webServer.test.ts`, `web/src/components/software.ts`
- Modify: `web/src/api/types.ts:257,300-319,345` (`TargetType`, `WebServerFacts.software`, `TargetCreateRequest.type` use `WebServerType`), `web/src/api/endpoints.ts:304` (comment)
- Modify: `web/src/components/WebsitesPanel.tsx` (imports, `BLOCK_KEYS`, `{ software }` on every shared text), `web/src/components/DeployDialog.tsx:11`, `SiteName.tsx:2`, `useSiteLabel.ts:2`, `useLocations.ts:6`, `web/src/pages/TargetDetailPage.tsx:9,69,124,136,193,244,357-381,408`, `web/src/pages/TargetsPage.tsx:137`, `web/src/components/DeployKeyDialog.tsx:22`
- Modify: `web/src/locales/en.json`, `web/src/locales/tr.json`; tests `WebsitesPanel.test.tsx`, `TargetDetailPage.test.tsx`, `web/src/api/enums.test.ts` (capability list)

**Interfaces:**
- Consumes: `WebServerFacts` & codes (Task 4).
- Produces:
  - `webServer.ts`: `export const WEB_SERVER_TYPES = ['nginx'] as const; export type WebServerType = (typeof WEB_SERVER_TYPES)[number]; export function isWebServer(type: string): type is WebServerType; export function isServerType(type: string): boolean` (linux or a web server); `export type DeployBlock = 'status' | 'profile_missing' | 'server_not_found' | 'config_invalid' | 'last_error' | 'discovery_failed'; export interface WebServerState { block; stale; configInvalid }; export function webServerState(target: Target, discoveryFailed = false): WebServerState`; `firstServerName`, `serverNames`, `listenAddrs`, `canDeployTo` unchanged.
  - `capabilities.ts`: `export type Capability = 'test_connection' | 'discover_certificates' | 'discover_ssh_keys' | 'discover_kv_keys' | 'discover_kv_secret_metadata' | 'deploy_certificate' | 'import_certificate' | 'authorized_keys' | 'verify_deployment' | 'read_certificate_secret' | 'key_login' | 'http01_challenge'; export const CAPABILITIES: readonly Capability[]; export function can(target: Pick<Target, 'capabilities'>, capability: Capability): boolean`.
  - `software.ts`: `export function softwareName(t: TFunction, type: string): string` → `t(\`webServer.software.${type}\`)`.

- [ ] **Step 1: Write the failing tests**
  - `webServer.test.ts`: `isWebServer('nginx')` true, `'linux'`/`'azure_key_vault'`/`''` false; `isServerType('linux')` and `('nginx')` true, `('azure_key_vault')` false; `webServerState` cases moved from the old tests with `'server_not_found'`; `can({capabilities: ['deploy_certificate']}, 'deploy_certificate')` true and `can({capabilities: []}, 'deploy_certificate')` false.
  - Source guard `it('no component decides availability by a web-server type literal')`: every non-test `.ts/.tsx` under `web/src` (via `goSources` style `readdirSync`) matching `/(['"\`])nginx\1/` is one of `api/webServer.ts`, `components/AddServerModal.tsx`, `components/PlatformKeyPanel.tsx` (the type and profile pickers).
  - `enums.test.ts`: `eq(goConsts('internal/providers/capability.go', /^Cap/), CAPABILITIES)`.
  - `TargetDetailPage.test.tsx`: existing English expectations stay ("Nginx version", "Nginx was not found on this server."); add a Turkish render expecting `Nginx sürümü`.

- [ ] **Step 2: Run them to verify they fail**

Run: `cd web && npx vitest run src/api/webServer.test.ts src/api/enums.test.ts`
Expected: FAIL (module `./webServer` not found).

- [ ] **Step 3: Implement** the module moves and renames (`nginxState`→`webServerState`, `NginxState`→`WebServerState`, `nginx_not_found`→`server_not_found`); replace the type checks: `TargetDetailPage` `useLocations(…, isWebServer(type))`, `const webServer = isWebServer(tg.type)` for the panel and the Discover label, `operationsText` chosen by `can(tg, 'deploy_certificate')`, the facts list reads `f.web_server` when `isWebServer(target.type)`; `TargetsPage:137`, `DeployKeyDialog:22` use `isServerType`; pass `software: softwareName(t, target.type)` with every text below and with `t(warningKey(w), { ...w.params, software })` at `TargetDetailPage:408`. Locale changes (keys renamed where shown; both files; leave `warnings.config_file_writable` and the deployment texts as they are):

| key | en | tr |
|---|---|---|
| `webServer.software.nginx` (new) | `Nginx` | `Nginx` |
| `warnings.web_server_config_invalid` | `{{software}}'s configuration has an error. Alice will not deploy until it is fixed.` | `{{software}} yapılandırmasında bir hata var. Hata giderilene kadar Alice dağıtım yapmaz.` |
| `warnings.web_server_not_found` | `{{software}} was not found on this server.` | `Bu sunucuda {{software}} bulunamadı.` |
| `warnings.web_server_profile_missing` | `The {{software}} permissions are not installed on this server, so Alice cannot read its websites. Run the {{software}} commands for server preparation, then choose Discover.` | `Bu sunucuda {{software}} izinleri kurulu değil, bu yüzden Alice web sitelerini okuyamıyor. Sunucu hazırlığı için {{software}} komutlarını çalıştırın, ardından Keşfet düğmesini seçin.` |
| `targets.facts.webServerStale` (was `nginxStale`) | `The {{software}} details below may be out of date. Alice last read websites from this server on {{time}}.` | `Aşağıdaki {{software}} bilgileri güncel olmayabilir. Alice bu sunucudan web sitelerini en son {{time}} tarihinde okudu.` |
| `targets.facts.webServerNotFound` (was `nginxNotFound`) | `{{software}} was not found on this server.` | `Bu sunucuda {{software}} bulunamadı.` |
| `targets.page.facts.webServer` (was `nginx`) | `{{software}} version` | `{{software}} sürümü` |
| `targets.page.operationsText` | `Alice updates certificate and key files through its restricted helper. {{software}} configuration remains under your control.` | `Alice, kısıtlı yardımcı aracı üzerinden sertifika ve anahtar dosyalarını günceller. {{software}} yapılandırması sizin kontrolünüzdedir.` |
| `locations.intro` | `Each row is a certificate file that {{software}} uses. Alice never changes the {{software}} configuration, only these files.` | `Her satır {{software}} tarafından kullanılan bir sertifika dosyasıdır. Alice {{software}} yapılandırmasını hiçbir zaman değiştirmez, yalnızca bu dosyaları değiştirir.` |
| `locations.configInvalid` | `{{software}}'s configuration on this server has an error. Alice will not deploy until it is fixed.` | `Bu sunucudaki {{software}} yapılandırmasında bir hata var. Hata giderilene kadar Alice dağıtım yapmaz.` |
| `locations.unavailable.profile_missing` | `The {{software}} permissions are not installed on this server.` | `Bu sunucuda {{software}} izinleri kurulu değil.` |
| `locations.unavailable.server_not_found` (was `nginx_not_found`) | `{{software}} was not found on this server.` | `Bu sunucuda {{software}} bulunamadı.` |
| `locations.unavailable.config_invalid` | `{{software}}'s configuration has an error.` | `{{software}} yapılandırmasında bir hata var.` |

- [ ] **Step 4: Run the web checks**

Run: `make i18n-check && cd web && npx tsc --noEmit && npx vitest run && npm run lint`
Expected: PASS; the existing English assertions in `WebsitesPanel.test.tsx` and `TargetDetailPage.test.tsx` pass unchanged.

- [ ] **Step 5: Commit**: `refactor(web): webServer module, can() and software-named texts; no component checks a web-server type`.

---

### Task 8: `DisabledFeature`: unbuilt features shown disabled with the note

**Files:**
- Create: `web/src/components/DisabledFeature.tsx`, `web/src/components/DisabledFeature.test.tsx`
- Modify: `web/src/components/WebsitesPanel.tsx:22-45,268-279` (`RowButton` accepts `aria-describedby`; Deploy and Settings wrapped)
- Modify: `web/src/components/acme/issued.tsx:27-28,105` (`WEB_SERVERS_KEY`, `useWebServers`), `web/src/components/acme/GetCertificateDialog.tsx:27,66,82,362-370`, `web/src/pages/AcmeCertificatePage.tsx:26,68,145`
- Modify: `web/src/test/fixtures.ts:196,610` (real capability strings), `web/src/locales/en.json`, `tr.json`
- Test: `WebsitesPanel.test.tsx`, `acme/GetCertificateDialog.test.tsx`, `AcmeCertificatePage.test.tsx` (query key / handler for `/api/v1/targets` unfiltered)

**Interfaces:**
- Consumes: `can`, `Capability` (Task 7), `softwareName` (Task 7), `isWebServer`, `listAllServers` (`endpoints.ts:305`).
- Produces:
  - `export function unavailableNote(t: TFunction, target: Pick<Target, 'type'>): string` → `t('webServer.notAvailable', { software: softwareName(t, target.type) })`.
  - `export function DisabledFeature({ target, capability, children }: { target: Pick<Target, 'type' | 'capabilities'>; capability: Capability; children: ReactElement<{ disabled?: boolean; 'aria-describedby'?: string }> }): ReactElement` — with the capability: `children` unchanged; without: `children` cloned with `disabled: true` and `aria-describedby` = a `useId()` id, inside a Mantine `Tooltip` (label = the note) on a wrapping `<span data-testid="disabled-feature">` (Mantine's disabled-button pattern), plus `<VisuallyHidden id={id}>{note}</VisuallyHidden>`.
  - `export const WEB_SERVERS_KEY = ['targets', 'list', 'web-servers'] as const; export const useWebServers = (enabled = true) => useQuery({ queryKey: WEB_SERVERS_KEY, queryFn: async () => { const all = await listAllServers(); return { ...all, items: all.items.filter((s) => isWebServer(s.type)) }; }, enabled })` (replaces `NGINX_SERVERS_KEY`/`useNginxServers`).
  - Locale key `webServer.notAvailable`: en `Not available for {{software}} servers yet`, tr `{{software}} sunucularında henüz kullanılamıyor`.

- [ ] **Step 1: Write the failing tests**
  - `DisabledFeature.test.tsx`: with `{type:'nginx', capabilities:['deploy_certificate']}` the button is enabled and has no description; with `capabilities: []` it is disabled and `toHaveAccessibleDescription('Not available for Nginx servers yet')`; in Turkish (`i18n.changeLanguage('tr')`) the description is `Nginx sunucularında henüz kullanılamıyor`.
  - `WebsitesPanel.test.tsx` `it('shows Deploy and Settings disabled with the note when the server cannot deploy')`: `nginxTargetWith({ capabilities: ['test_connection','discover_ssh_keys','authorized_keys','discover_certificates','key_login'] })` renders the row's Deploy and Settings buttons disabled, both described by the note; the certificate link in the row still navigates.
  - `GetCertificateDialog.test.tsx`: the targets handler returns `nginxTargetFixture` and a second nginx target `web-2` without `http01_challenge`; the server select's option `web-2` is disabled and its label contains `Not available for Nginx servers yet`; choosing `web-nginx` still posts `http_target_id` (existing test).

- [ ] **Step 2: Run them to verify they fail**

Run: `cd web && npx vitest run src/components/DisabledFeature.test.tsx src/components/WebsitesPanel.test.tsx src/components/acme/GetCertificateDialog.test.tsx`
Expected: FAIL (module `./DisabledFeature` not found).

- [ ] **Step 3: Implement**: the component and note; `WebsitesPanel` wraps the Deploy `RowButton` (still shown only for `canDeploy && canDeployTo(l)`, disabled also when `blocked`) in `<DisabledFeature target={target} capability="deploy_certificate">` and the Settings `RowButton` in `capability="verify_deployment"` (pass `target` to `LocationRow`); `GetCertificateDialog` uses `useWebServers`, options `{ value: s.id, label: can(s, 'http01_challenge') ? s.name : \`${s.name} — ${unavailableNote(t, s)}\`, disabled: !can(s, 'http01_challenge') }`, the `noServer` notice when no web server exists; `AcmeCertificatePage` uses `useWebServers`. Fixtures: `targetFixture.capabilities` stays the linux set; `nginxTargetFixture.capabilities = ['authorized_keys','deploy_certificate','discover_certificates','discover_ssh_keys','http01_challenge','key_login','test_connection','verify_deployment']`.

- [ ] **Step 4: Run the web checks**

Run: `make i18n-check && cd web && npx tsc --noEmit && npx vitest run && npm run lint && npm run coverage`
Expected: PASS; coverage thresholds of `web/vite.config.ts` met.

- [ ] **Step 5: Commit**: `feat(web): features a server's provider lacks are shown disabled with "Not available for {{software}} servers yet"`.

---

### Task 9: CHANGELOG and full verification

**Files:**
- Modify: `CHANGELOG.md` (section `## Unreleased — Prod-readiness fixes`, new group `**Changed (API)**` above `**Release and process**`)

**Interfaces:**
- Consumes: everything above.

- [ ] **Step 1: Write the CHANGELOG entry** (three bullets): (1) target facts `facts.nginx` → `facts.web_server` with `software`; warning codes `nginx_not_found`, `nginx_profile_missing`, `nginx_config_invalid` → `web_server_not_found`, `web_server_profile_missing`, `web_server_config_invalid`; OpenAPI schema `NginxFacts` → `WebServerFacts`; (2) new capability `http01_challenge` (only servers with it may be the ACME HTTP-01 server); (3) migration `00016` rewrites stored facts, warnings, Nginx capabilities and `certificate_locations.kind` (`nginx_file` → `server_file`); the helper is unchanged (protocol 7, 1.6.1).

- [ ] **Step 2: Run the full Go and web gates** (no Playwright meanwhile)

Run: `make lint && make test && make coverage && make i18n-check && make web-lint && make web-coverage`
Expected: all PASS; `covercheck` reports `alice/internal/providers/webserver` ≥ 98 and no floor below its value.

- [ ] **Step 3: Run e2e** (no Docker-based Go tests meanwhile)

Run: `make e2e-up && make e2e; status=$?; make e2e-down; exit $status`
Expected: PASS (the Nginx journeys in `web/e2e/phase4.spec.ts`, `phase5.spec.ts`, `phase10.spec.ts` unchanged).

- [ ] **Step 4: Check the residue**

Run: `grep -rnE 'TypeNginx' --include=*.go internal cmd | grep -v 'internal/inventory/types.go'; grep -rnE "facts\.nginx|nginx_file|NginxFacts|useNginxServers|api/nginx'" internal cmd web/src api migrations/*.go`
Expected: no output.

- [ ] **Step 5: Commit**: `docs(changelog): web-server standard (Phase A) API renames and migration 00016`.
