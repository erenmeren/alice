# Web server providers: Apache httpd and HAProxy (discovery only)

Date: 2026-10-17. Owner decision (Turkish, paraphrased): add Apache and HAProxy without growing the
project much; discovery only for now; their pages look like Nginx's, with every feature that is not
built yet (buttons, tables, panels) shown disabled, to be enabled as features land; where the
providers work the same way, make it one standard.

This document is the authority for the three phases below. It amends `alice-v1/00-decisions.md:49`
and `01-product.md:189` (Apache and HAProxy move from "Later" to "discovery in 1.x"); IIS and
Windows stay deferred.

## 1. Scope

In scope for Apache httpd and HAProxy targets:

- Add the server (SSH, same settings and credentials as a Linux or Nginx server), test the
  connection, show the software, its version and whether its configuration is valid.
- Discover the certificate files the configuration uses, with the sites/frontends using them: the
  certificates enter the inventory, expiry alerts and reports exactly like Nginx's.
- Everything a Linux server has: SSH key discovery, authorized_keys management, key login.

Out of scope (shown disabled, see §5): certificate deployment, rollback, deployment verification,
recovery and fence, ACME HTTP-01 publishing and ACME bindings to these servers.

## 2. Phases

| Phase | Content | Behaviour change |
|---|---|---|
| A. Standardize | Turn the Nginx-only layer that is not about deployment into a shared web-server layer (§3); capability-driven checks and UI (§5). | None for users; API/JSON renames (no release exists yet). |
| B. Apache | Provider, helper `apache-dump`, parser, setup profile, tests, docs. | New target type `apache`. |
| C. HAProxy | Provider, helper `haproxy-dump`, parser, setup profile, tests, docs. | New target type `haproxy`. |

Each phase is its own branch, fully green (`make ci` stages, e2e) and fast-forward merged into
`main` before the next starts.

## 3. The shared web-server layer (Phase A)

### 3.1 Vocabulary

- **Web server target**: a target of type `nginx`, `apache` or `haproxy` (Go:
  `inventory.IsWebServer(type)`, TS: `isWebServer(type)`).
- **Software**: `nginx | apache | haproxy`, equal to the target type and provider kind.

### 3.2 Renames (no compatibility shims; there is no release yet)

| Today | Standard |
|---|---|
| `providers.NginxFacts` | `providers.WebServerFacts`, plus field `Software string` (`json:"software"`) |
| `inventory.Facts.Nginx` (`json:"nginx"`) | `Facts.WebServer` (`json:"web_server"`) |
| `ConnectionReport.Nginx`, `DiscoveryResult.Nginx` | `.WebServer` |
| OpenAPI `NginxFacts`, `facts.nginx` | `WebServerFacts`, `facts.web_server` |
| location kind `nginx_file` | `server_file` |
| warning codes `nginx_not_found`, `nginx_profile_missing`, `nginx_config_invalid` | `web_server_not_found`, `web_server_profile_missing`, `web_server_config_invalid` |
| web `api/nginx.ts` (`nginxState`, `NginxState`, `DeployBlock` value `nginx_not_found`) | `api/webServer.ts` (`webServerState`, `WebServerState`, `server_not_found`) |

Migration `00016` (a new migration; 00001–00015 are frozen by `migrations/frozen_test.go`):
rewrites `targets.facts` key `nginx` to `web_server` with `"software":"nginx"`, rewrites
`certificate_locations.kind` `nginx_file` to `server_file` and replaces both CHECKs; the
`targets.type` CHECK gains `apache` and `haproxy` in Phase B and C migrations respectively (one
migration per phase, never an edit of an earlier one).

Kept as is: everything about deployment (`nginx-deploy`/`-restore`/`-status`/`-fence`, the `nginx.*`
deployment reasons and `ALC-NGX-*` codes, deployment texts naming `nginx -t`), because only Nginx
deploys. Locale texts that describe Nginx-only behaviour keep naming Nginx; texts shared by all
web servers name the software through an interpolated `{{software}}`.

### 3.3 Shared provider package `internal/providers/webserver`

Holds what all three providers do the same way, moved out of `internal/providers/nginx`:

- A `Base` that wraps `*linuxssh.Provider` (Open, TestConnection delegation, SSH-key operations,
  key login, config/credential schema), parameterized by a `Spec`:
  `{Kind, Software, DisplayNameKey, DumpSub, TestSub, ReasonPrefix, UsualFolders, MinProtocol}`.
- `Discover`: runs the spec's dump subcommand and converts the shared dump answer
  (`helperproto.ServerDumpResponse`, renamed from `NginxDumpResponse`) into
  `DiscoveredCertificate`s and warnings, with the hostile-server bounds that `nginx/discover.go`
  has today.
- Helper error mapping for the shared codes (`<prefix>.not_found`, `<prefix>.profile_missing`,
  `<prefix>.config_invalid`, `<prefix>.helper_too_old`).

`nginx` embeds `webserver.Base` and adds deploy, verify, rollback, status, fence and HTTP-01.
`apache` and `haproxy` are a `Spec` each plus registration.

`jobs/targetjobs` treats `<prefix>.not_found` / `<prefix>.profile_missing` of any web-server kind
the way it treats Nginx's today and writes `Facts.WebServer`.

### 3.4 Capability-driven checks

Every check that today says "type is nginx" means one of two things and is rewritten accordingly:

- "this is a web server" (facts, websites panel, certificate locations, `locations_list` SQL,
  `mergeNginxFacts`, sshkeys "certificates only for nginx") becomes `IsWebServer`.
- "Alice can deploy / publish here" (`canDeploy`, bindings, ACME bindings, deployment records,
  HTTP-01) becomes a capability check: `CapDeployCertificate` for deployment and bindings, and a
  new capability `CapHTTP01` ("http01_challenge", Nginx only) for ACME HTTP-01. The API refuses
  with the existing "not supported for this target" error when the capability is missing.

## 4. Helper (Phases B and C)

- Protocol 8, helper version 1.7.0 (B) and 1.8.0 (C, protocol 9) — each phase that adds a
  subcommand bumps both; `MinProtocol` stays 6. A server whose helper is older than the
  subcommand's protocol gets `<prefix>.helper_too_old` ("update the helper"), not a failure.
- New subcommands, each no-argument, read-only, run as root through sudo, answering
  `ServerDumpResponse`: `apache-dump` (B), `haproxy-dump` (C). Each also reports
  version and config validity (so no separate `-test` subcommand).
- Every configuration file read goes through the existing root-controlled path walk (`rootpath.go`)
  and the same size/count limits as Nginx (`MaxNginxConfig` → `MaxServerConfig`,
  `MaxNginxFiles` → `MaxServerFiles`); certificate and key files are described with the existing
  `describeCert`/`describeKey`.
- Binaries are fixed paths, not discovered (like `nginxPath`).
- Sudoers: new setup profiles `apache` and `haproxy` = the `linux` lines plus the one dump line
  (no arguments). `docs/*-host-preparation.md` quote them; the existing byte-for-byte doc test
  covers them.

### 4.1 Apache (`cmd/alice-helper` + parser package `internal/providers/apacheconf`)

- Control script: `/usr/sbin/apache2ctl` (Debian/Ubuntu, sources `envvars`), else
  `/usr/sbin/apachectl` (RHEL family). Neither present: `NOT_FOUND`.
- Facts: `-v` (version), `-t` (config valid; error class only, never raw output).
- Ask Apache, do not re-implement it: `-t -D DUMP_INCLUDES` gives the files Apache actually loads
  (Include/IncludeOptional with globs and conditionals already evaluated), `-M` the loaded modules,
  `-t -D DUMP_RUN_CFG` the `Define`d variables; `-V` gives `HTTPD_ROOT`/`SERVER_CONFIG_FILE`.
- The parser reads those files (authenticated) and tracks `<VirtualHost addr:port …>` blocks with
  `ServerName`, `ServerAlias`, `SSLEngine`, `SSLCertificateFile`, `SSLCertificateKeyFile`,
  `SSLCertificateChainFile`. `<IfModule>` is evaluated against `-M`, `<IfDefine>` against the
  defines, `<IfVersion>` against the version. `${VAR}` expands from the defines; an undefined one
  makes the pair unsupported (`variable`). `<If>`/`<ElseIf>`/`<Else>` regions: pairs inside are
  unsupported (`conditional`). Server-level SSL directives are inherited by virtual hosts that set
  none (`Inherited`). A `SSLCertificateFile` without a key file means the key is in the same file
  (`KeyPath = CertPath`).
- `CertServer` mapping: Names = ServerName + ServerAliases, Listens = the vhost addresses with
  `SSLEngine on`, File/Line = the `<VirtualHost` line.

### 4.2 HAProxy (`cmd/alice-helper` + parser package `internal/providers/haproxyconf`)

- Binary `/usr/sbin/haproxy`; configuration `/etc/haproxy/haproxy.cfg` (fixed; other `-f` paths
  are a documented limitation). Facts: `-v`, `-c -f <cfg>` (valid).
- The parser reads `global` (`crt-base`), `frontend` and `listen` sections and every `bind` with
  `ssl`: its `crt <path>` (file or directory; a directory contributes each regular file except
  `.key`, `.ocsp`, `.issuer`, `.sctl`) and `crt-list <file>` (each line `path [opts] [sni…]`).
  `"$VAR"`/`${VAR}` in a path makes the pair unsupported (`variable`).
- Key: in the same PEM, or `<path>.key` next to it (HAProxy's default `ssl-load-extra-files`).
- `CertServer` mapping: Names = the crt-list SNI filters (empty otherwise; the UI then shows the
  frontend name and the certificate's subject names), Listens = the bind address:port,
  File/Line = the `bind` line.

## 5. UI: same pages, unbuilt features disabled

- Add-server modal and setup-profile picker offer Nginx, Apache and HAProxy.
- A web-server target's detail page is the Nginx page for every software: facts (software and
  version, config validity), the websites panel (for HAProxy the column header reads "Frontend"),
  certificates, SSH keys.
- A feature the target's `capabilities` lack is rendered disabled, not hidden: the deploy
  button(s), the deployments table/history panel, ACME binding actions and the HTTP-01 server
  choice. Each disabled control carries the same tooltip/inline note: "Not available for
  {{software}} servers yet" / "{{software}} sunucularında henüz kullanılamıyor".
- The rule lives in one place (TS helper `can(target, capability)` plus a `DisabledFeature`
  wrapper component); no component checks the target type to decide availability.

## 6. Tests

- Parser packages: table tests plus fuzz targets (added to `make fuzz-release`).
- Helper: unit tests for each dump subcommand with a fake filesystem/runner, like the Nginx ones.
- Emulator (`linuxsshtest`): answers `apache-dump`/`haproxy-dump` by running the real parser over
  its fake filesystem; a fidelity test checks the emulator against the helper.
- Real matrix: `TestRealApache`, `TestRealHAProxy` in `make test-ssh` on Ubuntu 22.04, Debian 12 and
  Rocky 9 (`test/images/sshd/*` gain apache2/httpd and haproxy, with config-test/version shims as
  needed), each discovering a two-site fixture configuration.
- e2e: the e2e target gains Apache and HAProxy; one spec adds each kind of server, sees its
  websites and certificates, and finds the deploy controls disabled with the note.
- Provider conformance: `providertest` for the three providers.

## 7. Other rulings

- Licensing: Apache and HAProxy targets are counted like Nginx targets.
- Error codes: `ALC-APC-0001..` and `ALC-HAP-0001..` for the four shared reasons of §3.3.
- Network discovery (`internal/discovery`) is unaffected.
- Docs: `docs/apache-host-preparation.md`, `docs/haproxy-host-preparation.md` (setup, sudoers,
  what is discovered, limitations), operator/admin guide mentions, troubleshooting entries, the
  OpenAPI enums, SECURITY-REPORT threat-model delta (two new root subcommands, read-only).
- Known limitations to record: HAProxy config path fixed; Apache `<If>` regions unsupported;
  no deployment for either.
