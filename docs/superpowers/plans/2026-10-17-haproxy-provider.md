# HAProxy Provider (Phase C, discovery only) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add HAProxy as a discovery-only web-server target type `haproxy`. Alice connects over SSH and shows the software, its version and whether its configuration is valid. It lists the certificate files HAProxy's frontends and listen sections use (with the frontend and SNI names) in the inventory, alerts and reports, as it does for Nginx and Apache. The page is the shared web-server page: the site column reads "Frontend" and deployment is shown disabled.

**Architecture:** A pure parser package `internal/providers/haproxyconf` reads `/etc/haproxy/haproxy.cfg` the way HAProxy's `parse_line` does: sections, `.if` blocks, `crt-base`, `ssl-load-extra-*` and `bind … ssl` lines. Through two callbacks it also reads the `crt-list` files and lists the `crt` directories that the configuration names. The parser never does I/O itself. The new read-only helper subcommand `haproxy-dump` (protocol 9, helper 1.8.0) runs `haproxy -v` and `haproxy -c -f /etc/haproxy/haproxy.cfg`, reads the files through the root-controlled walk and answers `helperproto.ServerDumpResponse`. The answer gains one optional field, `section`, which carries the frontend name. `internal/providers/haproxy` is a `webserver.Spec` plus registration. Migration 00018 adds the type. Before the helper work, the Phase B carry lands: all three web-server programs (Nginx, Apache and HAProxy) get a root-control pre-check.

**Tech Stack:** Go 1.27 (pgx/v5, goose, testcontainers), PostgreSQL, React 18 + Mantine + TanStack Query + i18next, Vitest, Playwright, Docker images pinned by digest.

**Spec:** `docs/superpowers/specs/2026-10-17-web-server-providers-design.md`. This phase is row C of §2 and draws on §1, §4, §4.2, §5, §6 and §7. §8 binds it. Phase B rulings and Phase C carries: `docs/superpowers/rulings/apache-provider.md`. Phase A rulings: `docs/superpowers/rulings/web-server-standard.md`. Model plan: `docs/superpowers/plans/2026-10-17-apache-provider.md`. The owner started Phase C with the request of 2026-10-17, which lifts the Phase B hold ("do not start Phase C until the owner says so").

## Global Constraints

- **Branch.** Work on `haproxy-provider` (cut from main `beb8c538`; already checked out) and never switch branches.
- **Helper version and subcommand.**
  - `helperproto.Protocol = 9` and `helperproto.Version = "1.8.0"`. `helperproto.MinProtocol` stays `6`. A new `helperproto.HAProxyMinProtocol = 9`.
  - The new subcommand is `haproxy-dump` (`helperproto.SubHAProxyDump`). It takes no arguments, runs as root through sudo, and is read-only: it writes, renames and chmods nothing.
  - "Software not installed" is the existing `helperproto.CodeSoftwareNotFound`.
  - The JSON tags of `ServerDumpResponse` stay as they are. The one addition is `DumpServer.Section` (`json:"section,omitempty"`), so Nginx and Apache answers stay byte-identical.
- **Before any helper task closes**, run:
  - the root-only suite: `sudo -E env "PATH=$PATH" go test -count=1 ./cmd/alice-helper/...`;
  - `make helper`;
  - `make test-ssh` (Task 10 adds HAProxy to it).

  If sudo needs a password, record the root-only run as an owner step in the rulings file. Do not skip it silently.
- **Migrations.**
  - Migrations `00001`–`00016` are pinned in `migrations/frozen_test.go:19-36`. **Task 1 pins `00017_apache.sql`**: the spec forbids editing an earlier phase's migration (§3.2).
  - Every Phase C schema change goes in `migrations/00018_haproxy.sql`, which stays unpinned. Write it like 00017.
- **Commits.**
  - Command: `git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only -m "..." -- <paths>`, with `-m` before `--`.
  - Stage only by explicit path. For a new file, run `git add -- <path>` first. Never run `git add -A` or `git add .`. Check `git status --short` before each commit.
  - Never touch `.claude/`, `Alice-Proje-Dokumani.pdf` or the untracked files under `docs/security/reviews/`.
  - Every message ends with a blank line and `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- **Verification commands.** These are the same as Phase B:
  - `go build ./... && go vet ./... && go vet -tags integration ./...`
  - `go test -race -count=1 ./<pkgs>`
  - `go test -race -count=1 -tags integration ./<pkgs>`
  - `make lint`, `make test`, `make test-integration`, `make coverage`, `make i18n-check`
  - web: `cd web && npx vitest run <files>`, `npm run lint`, `npx tsc --noEmit`, `make web-coverage`
  - e2e: `make e2e-up && make e2e; make e2e-down`
  - real matrix: `make test-ssh`; `ALICE_SSH_IMAGES=ubuntu22` limits it.

  Docker-based Go runs and Playwright never run at the same time.
- **Coverage floors** are never lowered.
  - New floors: `"alice/internal/providers/haproxy": 98` and `"alice/internal/providers/haproxyconf": 92`.
  - Existing floors stay: `webserver` 98, `apache` 98, `apacheconf` 92, `nginx` 98, `providers` 100, `helperproto` 100, `targetjobs` 100, `cmd/alice-helper` 90, `linuxssh` 93.
  - Web thresholds in `web/vite.config.ts` are never lowered.
- **Build inputs stay pinned** (`tools/pincheck`). No new base image. `haproxy` is added unversioned to the existing `apt-get`/`dnf` lines of the digest-pinned images.
- **HAProxy is never started** in `test/images/sshd/*` or `test/images/e2e-target` (Phase B carry). Nginx owns ports 80 and 443, and Apache's e2e vhosts declare 8443. HAProxy fixtures bind 9443, 9444 and 9445 only.
- **One list of web-server types:** Go `inventory.webServerTypes` (`internal/inventory/types.go:33`) and TS `WEB_SERVER_TYPES` (`web/src/api/webServer.ts:4`). Phase C also extends:
  - `providers.KindForTargetType`;
  - the `targets.type` CHECK (00018);
  - registration (`cmd/alice/providers.go`, `cmd/alice/wiring.go:12`);
  - the vocabulary guard (`internal/providers/webserver/guard_test.go`).

  No component or handler decides availability by a type literal. The capability sync (spec §8.1) covers the new type without a data migration.
- **Locale texts** exist in `en` and `tr`, in `locales/common` and `web/src/locales`, with identical keys and placeholders.
  - Turkish never puts a suffix on `{{software}}`.
  - The display name is `HAProxy` (`webServer.software.haproxy`).
  - The disabled note stays exactly `"Not available for {{software}} servers yet"` / `"{{software}} sunucularında henüz kullanılamıyor"`.
- **Error codes:** `ALC-HAP-0001` `haproxy.not_found` (502), `ALC-HAP-0002` `haproxy.config_invalid` (409), `ALC-HAP-0003` `haproxy.profile_missing` (502), `ALC-HAP-0004` `haproxy.helper_too_old` (502).
- **Traceability:** `test/matrix/traceability.json` names tests by package. After editing it, regenerate with `go run ./tools/matrixcheck -spec docs/superpowers/specs/alice-v1/06-quality.md -map test/matrix/traceability.json -doc docs/security/traceability.md -update`.

## Rulings

Rulings 3, 5–7 and 9–12 rest on probes run on 2026-10-17 in throwaway containers built from the matrix images' pinned digests:

| Image | HAProxy |
|---|---|
| Ubuntu 22.04 | 2.4.30-0ubuntu0.22.04.2 |
| Debian 12 | 2.6.12-1+deb12u3 |
| Rocky 9 | 2.8.14 |

The official `haproxy:2.4`, `2.5` and `2.6` images were added for the dotfile boundary. "Verified" below means the behaviour was seen on all three distribution builds.

1. **Helper version (§4, §8.2).**
   - `Protocol = 9`, `Version = "1.8.0"`, `SubHAProxyDump = "haproxy-dump"`, `HAProxyMinProtocol = 9`, and `CodeSoftwareNotFound` is reused.
   - A protocol 6–8 helper gives `haproxy.helper_too_old`: `TestConnection` turns it into the warning `web_server_helper_too_old`, and SSH keys are still read.
   - The protocol comment reads: "Protocol 9 (HAProxy, Phase C): haproxy-dump; nothing else changed: a protocol 6 helper serves every other operation (MinProtocol)".
2. **Fixed paths.**
   - Program `/usr/sbin/haproxy` (`haproxyPath`). Configuration `/etc/haproxy/haproxy.cfg` (`haproxyConfPath`), which is also the reported `ConfPath`.
   - The helper never reads `/etc/default/haproxy`, `/etc/sysconfig/haproxy` or the systemd unit.
   - **Rocky 9's packaged unit runs `-f /etc/haproxy/haproxy.cfg -f /etc/haproxy/conf.d`** (Debian 12 and Ubuntu 22.04 pass only the file). The spec fixes the path (§4.2), so `conf.d` is not read. It is never silent, though: when `/etc/haproxy/conf.d` is a root-controlled directory holding a regular entry named `*.cfg`, the dump carries the server warning `config_dir_not_read` (new `helperproto.WarnConfigDirNotRead`). A walk or listing failure gives no warning.
3. **The two runs.**
   - Both go through the guarded `runProgram` of Task 3: fixed environment, `/`, umask 022, 30 s, stdout capped at `MaxServerConfig`.
   - **`-v`:** the version is the `<v>` of a first line `HAProxy version <v> ` (or `HA-Proxy version <v> `), with apacheconf's rule `[A-Za-z0-9.+-]{1,40}`. No such line means `SOFTWARE_NOT_FOUND`. A missing program also means `SOFTWARE_NOT_FOUND`.
   - **`-c -f /etc/haproxy/haproxy.cfg`:**
     - Exit **0 or 2** means valid. Exit 2 is "Configuration file has no error but will not start (no listener)", verified for a frontend without `bind`.
     - Any other exit means invalid, class `syntax` (§8.2; stderr is never used).
     - `-c` loads every certificate, key, `crt-list`, `crt` directory, CA and CRL file, and resolves `server` host names (all verified). So a missing certificate, a key that is in neither the PEM nor its companion file, or an unresolvable server name is a `syntax` configuration error. This differs from Apache, where a missing certificate is a `missing` place.
     - Killed or timed out means `IO_ERROR`. Output over the cap means unsupported `too_large`.
     - On an invalid configuration nothing is read, and servers and files are empty.
   - `-c` writes nothing. Verified: a whole-filesystem `(path, mtime, ctime, size, mode)` snapshot was equal before and after a run of a configuration with `chroot`, `stats socket`, `pidfile`, `user` and `daemon`.
4. **Reading after a valid `-c`.**
   - **The configuration file** is read through `walkRoot` and `openLinked(true)`, as Apache's include tree is: at most `haproxyconf.MaxInput`.
   - **`crt-list` files** use the same walk. Each distinct file is read once, and all files together are at most `MaxServerConfig`.
   - **`crt` directories** are listed through the new `(*sys).listRootDir`: the directory must be root-controlled, and links and directories inside are not followed for listing.
   - **Writable files.** When `haproxy.cfg` or a read `crt-list` is owned by someone other than root, or is group- or other-writable, every supported pair becomes `config_file_writable` (`haproxyconf.MarkWritable`, Apache's coarse rule: `setenv`/`crt-base` reach the whole configuration). `Writable` lists those files. After a writable file was read, every later failure is untrusted `changed` naming it (Apache's masking).
   - **Failures.**
     - A walk failure of `haproxy.cfg` or a `crt-list` is untrusted `walkReason` naming the file.
     - A `crt` path whose walk fails is treated as a file, not a directory: `describeCert` then reports its problem.
     - A directory that walks but cannot be listed is untrusted `walkReason`.
5. **The configuration lexer follows HAProxy's `parse_line` (verified).**
   - Blanks separate words.
   - `#` outside quotes starts a comment anywhere, even without a space before it.
   - `"…"` groups words and HAProxy expands `$NAME` and `${NAME}` inside it. `'…'` is literal. Quoted parts concatenate with adjacent text.
   - Outside single quotes, a backslash escapes as follows: `\\`, `\"`, `\'`, `\#`, `\$` and `\ ` give the character, `\t`, `\r` and `\n` give the control character, and `\xHH` gives the byte. Any other escape is `ErrSyntax`.
   - There is no line continuation: `\` at the end of a line is a word.
   - NUL is `ErrNUL`. Keywords and section names are case-sensitive (`BIND` is refused by HAProxy).
   - **Any `$` in a path word makes the pair `variable`, whatever its quoting.** HAProxy expands only inside double quotes, but an unquoted `${X}` that `-c` accepted is a literal file name, and Alice does not guess which case applies.
   - `-c` runs with the helper's fixed environment, not the service's `EnvironmentFile`. A configuration whose paths need those variables is therefore reported invalid, which is documented.
6. **Sections.**
   - `global`, `defaults`, `frontend <name>` and `listen <name>` are read.
   - These are other sections, whose lines are skipped: `backend` (HAProxy ignores `bind` there, verified), `peers`, `log-forward`, `resolvers`, `userlist`, `mailers`, `program`, `http-errors`, `ring`, `cache`, `fcgi-app`, `crt-store`, `traces` and `acme`. Binds in `peers` and `log-forward` are not listed (limitation).
   - Nothing reaches a `bind` from `defaults` or `default-server`. HAProxy refuses `bind` in `defaults` (verified), and `default-server` only shapes `server` lines. Client certificates of `server … crt` are not read (limitation).
   - A `disabled` line in a frontend or listen in an active region omits that section's servers. In an uncertain region it makes the section's pairs `conditional`. `-c` still loads a disabled section's certificates (verified), and they are not served.
   - A `disabled` or `enabled` line in any `defaults` makes the pairs of every later frontend or listen that sets neither itself `conditional`.
7. **Conditional blocks `.if`/`.elif`/`.else`/`.endif`** exist on 2.4, 2.6 and 2.8 (verified, also indented).
   - Each region is active, inactive or uncertain.
   - A condition is evaluated only when it is empty (false) or one word without `$` that matches `^-?[0-9]+$` (true when it is not 0). Verified: `.if 0` false, `.if 1`/`-1`/`"1"` true, empty false.
   - Everything else is uncertain: `defined()`, `feature()`, `version_atleast()`, `streq()`, operators and `!`. 2.4 refuses `.if !0` while 2.8 accepts it.
   - `.elif`/`.else` after a taken branch are inactive; after an uncertain one they are uncertain. An unbalanced block is `ErrSyntax`. `.diag`, `.notice`, `.warning` and `.alert` lines are ignored.
   - A section header in an inactive region is skipped, and its lines stay in the previous section, as HAProxy does (verified). A header in an uncertain region makes the current section uncertain until the next certain header: its pairs are `conditional` and its name is `""`.
   - A pair is `conditional` when:
     - its `bind` lies in an uncertain region;
     - a `crt-base`, `ssl-load-extra-files` or `ssl-load-extra-del-ext` it depends on was set in one.
8. **Binds.**
   - Only `bind` lines of frontend and listen sections that carry the keyword `ssl` are read.
   - Arguments are read with the keyword arity table `haproxyconf.bindArity`, the union of the `haproxy -dKall` bind lists of 2.6.12 and 2.8.14, plus 2.4's `process` and the QUIC keywords. (`ssl` is listed explicitly here because `-dKall` does not print it.)
     - **0 arguments:** `accept-proxy defer-accept tfo transparent v4v6 v6only ssl allow-0rtt force-sslv3 force-tlsv10 force-tlsv11 force-tlsv12 force-tlsv13 generate-certificates no-alpn no-ca-names no-sslv3 no-tls-tickets no-tlsv10 no-tlsv11 no-tlsv12 no-tlsv13 prefer-client-ciphers strict-sni quic-force-retry`.
     - **1 argument:** `accept-netscaler-cip backlog expose-fd gid group id interface level maxconn mode mss name namespace nice process proto severity-output shards tcp-ut thread uid user alpn ca-file ca-ignore-err ca-sign-file ca-sign-pass ca-verify-file ciphers ciphersuites client-sigalgs crl-file crt crt-ignore-err crt-list curves ecdhe npn sigalgs ssl-max-ver ssl-min-ver tls-ticket-keys verify quic-cc-algo quic-socket`.
   - The table matters: `bind … ssl name crt crt /a.pem` is valid HAProxy (verified).
   - An unknown keyword stops the reading of that line. Every pair of the bind (including those already read) becomes `unknown_keyword`: a new reason, `haproxyconf.ReasonUnknownKeyword`, with `providers.UnsupportedUnknownKeyword`. Because `-c` passed, the keyword belongs to a newer HAProxy, for example 3.0's `default-crt`.
   - A bind without `ssl` is not listed. HAProxy loads its `crt` (verified) but serves no TLS on it.
9. **Paths (verified).**
   - A relative `crt` is joined to the `crt-base` in effect at that line. Global sections are read in order: a later `global` does not change an earlier bind.
   - A `crt-list` file path is **never** joined to `crt-base`, and a relative one is `path_not_allowed`, with one unsupported pair whose `CertRaw` is the argument.
   - `crt-list` entries are joined to `crt-base`.
   - The following are `path_not_allowed`: no `crt-base` or a relative one; `.`/`..` segments; not `helperproto.ValidPath`; `/`. This is nginx's `resolvePath` rule.
10. **`crt` directories.**
    - `Input.ReadDir` says whether the path is a directory and gives the names of its regular entries, with a link counted when the walk resolves it to a regular file.
    - The parser keeps names not ending in `.key`, `.ocsp`, `.issuer` or `.sctl`, in bytewise order. Each kept name is a pair of the bind's `crt` server. There is no bundle magic: `x.pem.rsa` is loaded as itself (verified). Subdirectories are skipped.
    - **Dotfiles are loaded below 2.6 and skipped from 2.6 on.** Verified: 2.4.30 and the official 2.5.14 load them, while 2.6.12, 2.6.35 and 2.8.14 skip them. For a version the parser cannot read as `major.minor`, a dotfile pair is `conditional`.
    - A `crt-list` line naming a directory is `path_not_allowed`: HAProxy refuses it (verified).
11. **`crt-list` syntax (verified).**
    - A line is a comment only when its first byte is `#`; an indented `#` is a path. Blank lines are skipped and leading blanks are allowed.
    - Words split on blanks. There are no quotes (a `"` is part of the path) and no escapes.
    - The first word is the path. An optional `[…]` option block, which may span words, is skipped. The remaining words are SNI filters.
    - `Names` are the filters without the `!` ones, in order. A trailing `# x` is filters, as HAProxy keeps it. A `$` in the path makes the pair `variable`.
12. **Keys (verified).**
    - HAProxy takes the key from the certificate PEM first; otherwise it looks for a companion file.
    - The parser sets `Pair.KeyBeside` to that companion, `"<cert>.key"`, when key lookup is on. Lookup is on when the `ssl-load-extra-files` in effect contains `all` or `key`; the default is `all`, and `none`, `ocsp` and `bundle` alone switch it off.
    - With `ssl-load-extra-del-ext`, a path ending in `.crt` instead gets `<path without .crt>.key`; other extensions keep `.key` appended.
    - `haproxyconf.ResolveKeys(c, keyInCert)` sets `Key = Cert` when `keyInCert(Cert)` or when `KeyBeside == ""`, else `Key = KeyBeside`.
    - The helper's `keyInCert` reads the certificate file through `resolveRoot` and `open` with describeCert's rules (at most `MaxCertFileSize`). It answers whether a line matches `-----BEGIN [A-Z ]*PRIVATE KEY-----`, clears its buffer and returns no key bytes.
    - A combined PEM is a supported pair with `KeyPath == CertPath`, as for Apache, never nginx's `combined_file`.
13. **Servers on the wire.**
    - One `Server` per bind holds all its `crt` pairs (files and directory entries), with empty `Names`.
    - Each `crt-list` line is a further `Server` with that line's filters.
    - All of them carry `File = /etc/haproxy/haproxy.cfg`, `Line` = the `bind` line and `Section` = the frontend or listen name.
    - `Listens`:
      - The bind's first word is split on `,`.
      - These prefixes are stripped: `ipv4@ ipv6@ tcp@ tcp4@ tcp6@ udp@ udp4@ udp6@ quic4@ quic6@`.
      - These give no listen: `unix@ abns@ fd@ sockpair@ uxst@ uxdg@` and `/…`.
      - `[v6]:p` and `v6:p` are split at the last colon.
      - `*`, the empty string, `0.0.0.0` and `::` become `""`.
      - The port must be decimal 1–65535: ranges, `+` and `$` drop the entry.
      - `Default` is always false.
    - `Inherited` is always false.
    - `Section` travels as `DumpServer.Section` and `providers.CertServer.Section` (both `json:"section,omitempty"`). `sameServer` compares it, and OpenAPI `CertificateServer.section` is optional. The `servers` jsonb needs no migration.
14. **Hostile-input bounds (`haproxyconf`).** These sit on top of the helper's `MaxServerConfig` read budget, `MaxServerFiles` and `dumpBudget`. Each `crt-list` and each directory is fetched once however many binds name it, so the work is bounded by `MaxPairs`, not by binds × lines.

    | Limit | Value | Over it |
    |---|---|---|
    | `MaxInput` (one file) | 20 MiB | `ErrTooLarge` |
    | `MaxLine` | 1 MiB | `ErrLineTooLong` |
    | `MaxTokens` (all words of all files) | 1<<20 | `ErrTooComplex` |
    | `MaxDepth` (`.if` nesting) | 100 | `ErrTooDeep` |
    | `MaxCrtLists` (distinct files) | 256 | `ErrTooComplex` |
    | `MaxDirs` (distinct directories) | 256 | `ErrTooComplex` |
    | `MaxDirEntries` (per directory) | 4096 | `ErrTooComplex` |
    | `MaxPairs` (pairs across all servers) | 1<<16 | `ErrTooComplex` |
    | `MaxServers` | 1<<16 | `ErrTooComplex` |
    | `MaxNames` (filters across all servers) | 1<<17 | `ErrTooComplex` |

    The helper maps errors as Apache's do: `too_large`, `too_complex`, `nul_byte`, and `syntax` for `ErrSyntax`. A callback error is returned unchanged (wrapped with `%w`), and the helper recovers its `*configError` with `errors.As`.
15. **Root-control pre-check of the web-server programs (Phase B carry, Ruling 7).**
    - Before running `/usr/sbin/nginx`, `/usr/sbin/apache2ctl` (plus `/etc/apache2/envvars` and `/usr/sbin/apache2`, which it sources and runs), `/usr/sbin/httpd` or `/usr/sbin/haproxy`, the helper calls `(*sys).trustedProgram(paths...)`.
    - Each path that exists must walk (`walkRoot`) and be a regular file owned by root with no group or other write bit. A missing path passes, so the not-found logic is unchanged.
    - A failure is `errProgramUntrusted`, wrapped by `*programError{path}`. It maps as follows:
      - the three dumps: configuration invalid, untrusted `not_root_controlled`, naming the file;
      - `nginx-test`: `Valid: false, Error: "untrusted"`;
      - the deploy step's `configTest`: class `""` with the step failed, like a killed run.
    - `systemctl` is not covered (it is not a web-server program; KI-40 says so).
16. **Writable configuration and existence oracle.** These follow Apache (KI-40): the server names of a writable configuration are still listed. Recorded as KI-41.
17. **The "Frontend" column (spec §5, §8.4).**
    - New locale keys `webServer.siteColumn.<software>` (en: nginx and apache "Website", haproxy "Frontend"; tr: nginx and apache "Web sitesi", haproxy "Frontend", since it is HAProxy's own keyword).
    - `siteColumnLabel(t, type)` in `web/src/components/software.ts` reads them. This is a label, not an availability decision.
    - The website cell shows the SNI names. When a server has a `section`, it also shows `locations.frontend` ("Frontend: {{name}}" / "Frontend: {{name}}").
    - `useSiteLabel` falls back to the first server's `section` before "(no server name)".
    - The certificate's subject stays in the Certificate column (spec §4.2: "the frontend name and the certificate's subject names").
18. **Real-matrix pinning.** `TestRealHAProxy` pins the dotfile verdict per image (`rhDotfilesLoaded`: `ubuntu22` true, `debian12` false, `rocky9` false), as Phase B pinned `raChecksCertInDump`.
19. **Phase B carry "a fifth plain `-t` run" (Apache Ruling 8).** Not taken: no customer report exists. The rulings file of Task 12 keeps it as an owner option.

## Review Focus

1. **A Rocky 9 server whose frontends live in `/etc/haproxy/conf.d/*.cfg`.** Alice lists only `haproxy.cfg`'s frontends and the page shows the warning `config_dir_not_read`. It never shows an empty list silently.
   - Pinned by Task 6 `TestHAProxyDumpWarnsAboutConfDir`.
   - Pinned by Task 10 step 7 (on all images).
2. **A certificate with its key in `<cert>.key` (mode 0644), and a combined PEM.** The companion location's key path is the `.key` file with `key_mode_open`. The combined one has `KeyPath == CertPath`. Neither is offered for deployment.
   - Pinned by Task 5 `TestResolveKeys`.
   - Pinned by Task 7 `TestDiscoverCompanionAndCombinedKeys`.
   - Pinned by Task 10 step 4.
3. **A `crt` directory with a `.key`, an `.issuer`, a subdirectory and a dotfile.** Each certificate is listed once, `.key` files are never certificates, and the dotfile follows the version.
   - Pinned by Task 5 parser rows `crt directory` and `dotfiles by version`.
   - Pinned by Task 10 step 4 (`rhDotfilesLoaded`).
   - Over `MaxDirEntries`, the result is `too_complex`, not a hang: Task 6 `TestHAProxyDumpBounds`.
4. **One `crt-list` named by two frontends.** It is read once. Its certificate shows one location with both frontends' names and the SNI names, under the "Frontend" header.
   - Pinned by Task 5 parser row `shared crt-list`.
   - Pinned by Task 6 `TestHAProxyDumpReadsEachCrtListOnce`.
   - Pinned by Task 9 page test.
5. **A server still on helper 1.7.0 (protocol 8, installed for Apache).** The connection test succeeds with "update the helper", SSH keys are still scanned, and nothing says HAProxy is missing.
   - Pinned by Task 7 `TestHAProxyHelperTooOld`.
   - Pinned by Task 8 targetjobs row.

---

### Task 1: Helper protocol 9 vocabulary, `haproxy` sudoers profile and setup snippets; 00017 pinned

**Files:**
- Modify: `internal/providers/linuxssh/helperproto/helperproto.go`:
  - `:36-39`: Protocol 9, Version 1.8.0, comment.
  - `:53-54`: add `HAProxyMinProtocol`.
  - `:155-163`: `SubHAProxyDump`; the `CodeSoftwareNotFound` comment names haproxy-dump.
  - `:125-138`: `WarnConfigDirNotRead`.
  - `:501`: doc comment.
- Modify: `internal/providers/linuxssh/helperproto/helperproto_test.go`; `internal/providers/linuxssh/command.go:144-148` (`CmdHAProxyDump`); `command_test.go`
- Modify: `internal/providers/linuxssh/setup.go:10-75` (`sudoersHAProxyOnly`, profile `haproxy`, error text), `setup_test.go`, `internal/providers/linuxssh/provider.go:80` (profiles loop), `provider_test.go`
- Modify: `internal/providers/provider.go:183,189` (comments: profiles linux, nginx, apache, haproxy)
- Modify: `internal/providers/linuxssh/docs_sudoers_test.go` (table row for the HAProxy guide)
- Create: `docs/haproxy-host-preparation.md`, a skeleton with a title and "The HAProxy profile" with the quoted block. Task 12 completes it.
- Modify: `api/openapi.yaml:6440-6445` (`profiles` requires and lists `haproxy`)
- Modify: `web/src/api/types.ts`: profiles become `{ linux; nginx; apache; haproxy: SetupSnippet }` until Task 9 restores the `Record`. Also `web/src/test/fixtures.ts:274` (a `haproxy` snippet).
- Modify: `migrations/frozen_test.go:35` (pin `00017_apache.sql` with its SHA-256 on this branch)

**Interfaces:**
- Produces:
  - in `helperproto`: `SubHAProxyDump = "haproxy-dump"`, `HAProxyMinProtocol = 9`, `WarnConfigDirNotRead = "config_dir_not_read"`, `Protocol = 9`, `Version = "1.8.0"`;
  - `func CmdHAProxyDump() linuxssh.HelperCommand`: privileged, `LongCommandTimeout`, `ServerDumpOutput`;
  - `linuxssh.Sudoers("haproxy")`.

- [ ] **Step 1: Write the failing tests**
  - `helperproto_test.go`: `Protocol == 9`, `Version == "1.8.0"`, `MinProtocol == 6`, `ApacheMinProtocol == 8`, `HAProxyMinProtocol == 9`, `SubHAProxyDump == "haproxy-dump"`, `WarnConfigDirNotRead == "config_dir_not_read"`.
  - `command_test.go`: `CmdHAProxyDump().Subcommand() == "haproxy-dump"`, with no arguments and output limit `ServerDumpOutput`.
  - `setup_test.go`, `TestSudoersHAProxyProfile`:
    - `Sudoers("haproxy")` equals `sudoersHead + "\nCmnd_Alias ALICE_HAPROXY_ONLY = \\\n    /usr/local/libexec/alice-helper haproxy-dump\n" + "\nalice-svc ALL=(root) NOPASSWD: ALICE_COMMON, ALICE_HAPROXY_ONLY\n"`.
    - `Sudoers("iis")` is `errUnknownProfile`, whose text names the four profiles.
    - `SetupScript("haproxy", line, true)` contains `profile: haproxy`.
  - `provider_test.go`: `SetupSnippets` has the keys `linux`, `nginx`, `apache` and `haproxy`.
  - `docs_sudoers_test.go`: add the row `{guide: "haproxy-host-preparation.md", alias: "ALICE_HAPROXY_ONLY", profile: "haproxy"}`.
  - `migrations/frozen_test.go`: the new `frozen` entry (the existing test then checks it).
- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./internal/providers/linuxssh/... ./migrations/ -run 'Frozen|.'`
Expected: FAIL (`undefined: SubHAProxyDump`, protocol 8 != 9, unknown profile).
- [ ] **Step 3: Implement** as in Interfaces. Change every other test that asserts the protocol as a literal (`grep -rn 'Protocol)' --include=*_test.go`) to read `helperproto.Protocol`. `web/e2e/phase4.spec.ts:208-211` expects protocol 9; update its comment to "HTTP-01 needs 7, Apache 8, HAProxy 9".
- [ ] **Step 4: Run the tests**
Run: `go build ./... && go test -race -count=1 ./internal/providers/... ./internal/api/ ./migrations/ && cd web && npx tsc --noEmit && npx vitest run src/api`
Expected: PASS.
- [ ] **Step 5: Commit**: `feat(helperproto): protocol 9 / helper 1.8.0 names haproxy-dump; the haproxy sudoers profile; pin migration 00017`

---

### Task 2: The frontend name on the wire and in locations (`section`)

**Files:**
- Modify: `internal/providers/linuxssh/helperproto/helperproto.go:474-481` (`DumpServer.Section string json:"section,omitempty"`)
- Modify: `internal/providers/types.go:328-333` (`CertServer.Section string json:"section,omitempty"`, with a comment: the HAProxy frontend or listen name, `""` for the other web servers)
- Modify: `internal/providers/webserver/convert.go:167-196`:
  - `certServer` copies `clean(s.Section, maxNameLength)`;
  - `sameServer` compares `Section`;
  - the `maxNamesPerDump` accounting counts a non-empty section as one name.
- Modify: `api/openapi.yaml:6603-6620` (`CertificateServer.section`: optional string, "HAProxy: the frontend or listen section; absent for Nginx and Apache")
- Modify: `web/src/api/types.ts:543-548` (`section?: string`)
- Test: `internal/providers/webserver/convert_test.go`, `internal/providers/linuxssh/helperproto/helperproto_test.go`, `internal/inventory/locations_integration_test.go` (or wherever `servers` round-trips today)

**Interfaces:**
- Produces: `helperproto.DumpServer.Section`, `providers.CertServer.Section`.

- [ ] **Step 1: Write the failing tests**
  - `helperproto_test.go`, `TestDumpServerSectionIsOmittedWhenEmpty`:
    - `json.Marshal(DumpServer{Names: []string{}, Listens: []DumpListen{}, Pairs: []DumpPair{}})` has no `"section"` key.
    - With `Section: "fe_https"` the JSON has `"section":"fe_https"`.
  - `convert_test.go`, `TestConvertKeepsTheSection`:
    - Two dump servers with the same file, line, names and listens but sections `fe_a` and `fe_b`, sharing one certificate, give one location with two `CertServer`s with those sections.
    - A section of 300 bytes is cut to 253.
    - A section with a control character is cleaned.
  - Integration test `TestLocationServersKeepTheSection`: a discovered location whose server has `Section: "fe_https"` is stored, and `GET /api/v1/targets/{id}/locations` returns `servers[0].section == "fe_https"`. An Nginx location's JSON has no `section` key.
- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./internal/providers/... && go test -count=1 -tags integration ./internal/inventory/ ./internal/api/ -run Section`
Expected: FAIL (`unknown field Section`).
- [ ] **Step 3: Implement** as in Files. The Nginx and Apache emulator and fidelity tests must stay green unchanged, which is the proof that their wire format did not move.
- [ ] **Step 4: Run the tests**
Run: `go build ./... && go test -race -count=1 ./internal/providers/... ./cmd/alice-helper/ && go test -race -count=1 -tags integration ./internal/inventory/ ./internal/api/ -run 'Section|Location|OpenAPI' && cd web && npx tsc --noEmit`
Expected: PASS.
- [ ] **Step 5: Commit**: `feat(webserver): a dump server may name its section (HAProxy frontend); stored and served as servers[].section`

---

### Task 3: Root-control pre-check of the web-server programs (Phase B carry, Ruling 15)

**Files:**
- Create: `cmd/alice-helper/program.go`, `cmd/alice-helper/program_test.go`
- Modify: `cmd/alice-helper/main.go:49-56` (`runNginx` goes through `s.runGuarded`; `runApache` becomes `s.runApacheCtl`)
- Modify: `cmd/alice-helper/apache.go:35-49` (`runApacheCtl` becomes a `*sys` method that guards the chosen program, plus `envvars` and `apache2` for `apache2ctl`); `:69-86`, `:93-101` (map `errProgramUntrusted`)
- Modify: `cmd/alice-helper/nginx.go:162-190` (`nginxConfig`), `:638-652` (`cmdNginxTest`); `cmd/alice-helper/deploy.go:605-615` (`configTest`)
- Modify: `cmd/alice-helper/apache_test.go`, `nginx_test.go`, `deploy_test.go` (mapping rows)

**Interfaces:**
- Produces:
  - `var errProgramUntrusted = errors.New("the program or a file it loads can be changed by a user other than root")`;
  - `type programError struct{ path string }`, whose `Unwrap` returns `errProgramUntrusted`;
  - `func (s *sys) trustedProgram(paths ...string) error`;
  - `func (s *sys) runGuarded(ctx context.Context, program string, also []string, outLimit int, args ...string) ([]byte, []byte, error)`, which checks `program` and `also`, then calls `runProgram` on the program path under `s.root`;
  - `func (s *sys) runApacheCtl(ctx context.Context, args ...string) ([]byte, []byte, error)`.
- Consumes: `walkRoot`, `openLinked`, `dirOK`.

- [ ] **Step 1: Write the failing tests** (`program_test.go`, in a temporary root with `rootUID` set to the test's uid)
  - `TestTrustedProgram`: these pass:
    - a 0755 file in 0755 directories;
    - a missing path (nil);
    - a root-owned link to a 0755 file.

    These are `errProgramUntrusted` naming the path, through `errors.As` on `*programError`:
    - a 0775 file;
    - a 0757 file;
    - a file in a 0777 directory;
    - a FIFO.
  - `TestRunGuardedRunsATrustedProgram`: a `#!/bin/sh` script printing `ok` (0755) runs and returns `ok\n`. After `chmod 0775`, it is not run: a marker file the script would create stays absent, and the error is `errProgramUntrusted`.
  - `TestApacheCtlGuardsEnvvarsAndBinary`: with `apache2ctl` 0755 and `/etc/apache2/envvars` 0666, `runApacheCtl` returns `errProgramUntrusted` naming `/etc/apache2/envvars`. With `httpd` only, envvars is not checked.
  - Mapping rows (fake runners returning `&programError{path: "/usr/sbin/nginx"}`):
    - `nginx-dump` gives `config_valid: false`, `config_error: "untrusted"`, `config_error_reason: "not_root_controlled"`, `config_error_file: "/usr/sbin/nginx"`.
    - `nginx-test` gives `{ok: true, valid: false, error: "untrusted"}`.
    - `configTest` gives class `""` and a non-nil error.
    - `apache-dump` gives the same configuration answer as `nginx-dump`, naming `/usr/sbin/apache2ctl`.
- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./cmd/alice-helper/ -run 'Trusted|Guarded|ApacheCtlGuards|Untrusted'`
Expected: FAIL (undefined).
- [ ] **Step 3: Implement** per Ruling 15. `trustedProgram` uses `walkRoot(p)` then an `Fstatat(dirfd, name, AT_SYMLINK_NOFOLLOW)` check: regular, `Uid == rootUID`, `Mode&0o022 == 0`. Hard links are allowed; programs are not read. In `nginxConfig` and `apacheConfig`, `errors.As(err, &pe)` becomes `invalid(untrusted(helperproto.ConfigReasonNotRootControlled, pe.path))` for every run.
- [ ] **Step 4: Run the tests**
Run: `go vet ./cmd/alice-helper/ && go test -race -count=1 ./cmd/alice-helper/... && sudo -E env "PATH=$PATH" go test -count=1 ./cmd/alice-helper/... && make helper`
Expected: PASS. The Nginx and Apache emulator fidelity tests are unchanged, because the emulator does not model program trust.
- [ ] **Step 5: Commit**: `fix(alice-helper): run nginx, apache2ctl/httpd only when they (and envvars, apache2) are root-controlled (Phase B carry)`

---

### Task 4: `haproxyconf`: version line, configuration lexer, `crt-list` and address parsers

**Files:**
- Create: `internal/providers/haproxyconf/haproxyconf.go`: package doc (the input is hostile; the parser is pure), limits, errors, reasons, `bindArity`.
- Create: `internal/providers/haproxyconf/lexer.go` (`lex`), `crtlist.go` (`parseCrtList`), `addr.go` (`parseListens`), `version.go` (`ParseV`, `minorAtLeast`)
- Create: `internal/providers/haproxyconf/lexer_test.go`, `crtlist_test.go`, `addr_test.go`, `version_test.go`, `fuzz_test.go` (`FuzzParseCrtList`), `race_on_test.go` and `race_off_test.go` (copied from apacheconf)
- Modify: `internal/archtest/arch_test.go:40-45,439-445`:
  - rule `"alice/internal/providers/haproxyconf": {"alice/internal/providers/linuxssh/helperproto"}`;
  - rows "haproxyconf to helperproto allowed" and "haproxyconf to platform/db denied".
- Modify: `coverage-floors.json` (`haproxyconf: 92`)

**Interfaces:**
- Produces:
  - `func ParseV(out []byte) string`;
  - `func minorAtLeast(version string, major, minor int) (yes, known bool)`;
  - `type word struct { text string; dollar bool }` (`dollar`: the raw word held a `$`);
  - `type line struct { n int; words []word }`;
  - `func lex(data []byte) ([]line, error)`;
  - `type crtListLine struct { n int; path string; names []string }`;
  - `func parseCrtList(data []byte) ([]crtListLine, error)`;
  - `type Listen struct { Addr string; Port int }`;
  - `func parseListens(arg string) []Listen`;
  - `var bindArity map[string]int`.
- Errors: `ErrTooLarge`, `ErrLineTooLong`, `ErrTooComplex`, `ErrTooDeep`, `ErrSyntax`, `ErrNUL`.
- Reasons: `ReasonVariable = "variable"`, `ReasonConditional = "conditional"`, `ReasonPathNotAllowed = "path_not_allowed"`, `ReasonUnknownKeyword = "unknown_keyword"`, `ReasonConfigFileWritable = helperproto.WarnConfigFileWritable`.
- Limits: as in Ruling 14.

- [ ] **Step 1: Write the failing table tests**
  - `TestParseV`:
    - `HAProxy version 2.4.30-0ubuntu0.22.04.2 2026/06/19 - https://haproxy.org/\nStatus: …` gives `2.4.30-0ubuntu0.22.04.2`.
    - `HAProxy version 2.8.14-c23fe91 2025/01/29 - …` gives `2.8.14-c23fe91`.
    - `HA-Proxy version 1.8.30 2021/04/02` gives `1.8.30`.
    - Each of these gives `""`: no such first line, a 41-character version, a version with `/`, and a CR anywhere.
  - `TestMinorAtLeast`:
    - `("2.4.30-0ubuntu…", 2, 6)` gives `(false, true)`.
    - `("2.6.12-1+deb12u3", 2, 6)` gives `(true, true)`.
    - `("2.8.14", 2, 6)` gives `(true, true)`.
    - `("10.0", 2, 6)` gives `(true, true)`.
    - `("x", 2, 6)` gives `(false, false)`.
  - `TestLex` (each row is the words and their `dollar` flags):
    - `bind :443 ssl crt /a.pem # crt /b.pem` gives 4 words.
    - `crt /a.pem#crt /b` gives 2 words.
    - `crt "/a b.pem"` gives `/a b.pem`.
    - `crt '/a$b'` gives `/a$b` with `dollar`.
    - `crt "${D}/a.pem"` gives `dollar`.
    - `crt ${D}/a.pem` gives `dollar`.
    - `crt /a\ b` gives `/a b`.
    - `crt /cer\ts` gives `/cer<TAB>s`.
    - `crt /a\x41` gives `/aA`.
    - `crt /a\q` gives `ErrSyntax`.
    - `crt "/a` gives `ErrSyntax`.
    - `crt /a "b"c` gives `/a` and `bc`.
    - A trailing `\` is a word `\`.
    - NUL gives `ErrNUL`.
    - A 1 MiB+1 line gives `ErrLineTooLong`.
    - 1<<20+1 words give `ErrTooComplex`.
    - 20 MiB+1 gives `ErrTooLarge`.
    - Line numbers count blank and comment lines.
  - `TestParseCrtList` (the verified sample of Ruling 11, line for line):
    - `# comment` is skipped.
    - `/probe/certs/a.pem` gives `{2, "/probe/certs/a.pem", []}`.
    - `h.pem [alpn h2 ssl-min-ver TLSv1.2] h.example.test *.h.example.test !nope.h.example.test` gives `{3, "h.pem", ["h.example.test", "*.h.example.test"]}`.
    - `/b.pem b.example.test other.example.test # trailing comment` gives names `["b.example.test", "other.example.test", "#", "trailing", "comment"]`.
    - `   ` is skipped.
    - `  /a.pem indented.example.test` gives path `/a.pem`.
    - `   # indented` gives path `#`.
    - `"/a.pem" x` gives path `"/a.pem"`.
    - `[a b` with no closing bracket gives `ErrSyntax`.
  - `TestParseListens`:
    - `*:443` gives `{"",443}`.
    - `:443,127.0.0.1:8443` gives two listens.
    - `[::1]:9443` gives `{"::1",9443}`.
    - `:::9443` gives `{"",9443}`.
    - `ipv4@10.0.0.1:443` gives `{"10.0.0.1",443}`.
    - `quic4@:443` gives `{"",443}`.
    - `unix@/run/x.sock`, `/run/x.sock`, `fd@3`, `:443-445`, `:${P}` and `:0` each give `[]`.
  - `TestBindArityCoversTheProbedKeywords`: every keyword of Ruling 8 is present with its arity, and `crt`, `crt-list` and `name` take 1.
  - `FuzzParseCrtList(data []byte)`: no panic. Every returned line has `n >= 1`, a non-empty path, and no name starting with `!`.
- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./internal/providers/haproxyconf/`
Expected: FAIL (the package does not exist).
- [ ] **Step 3: Implement** per Rulings 5, 8, 11 and 13 (the lexing parts). The package imports only the standard library and `helperproto`. The lexer walks bytes without recursion and copies only the words it returns.
- [ ] **Step 4: Run the tests**
Run: `go test -race -count=1 ./internal/providers/haproxyconf/ ./internal/archtest/ && go test -count=1 -run '^$' -fuzz FuzzParseCrtList -fuzztime 60s ./internal/providers/haproxyconf/`
Expected: PASS, no crasher.
- [ ] **Step 5: Commit**: `feat(haproxyconf): read haproxy -v, lex haproxy.cfg as parse_line does, parse crt-list lines and bind addresses`

---

### Task 5: `haproxyconf.Parse`: sections, `.if` blocks, globals, binds, `crt-list`s, directories and keys

**Files:**
- Create: `internal/providers/haproxyconf/parse.go`, `keys.go` (`ResolveKeys`, `MarkWritable`, `CertPaths`, `KeyPaths`, `ToWire`), `parse_test.go`, `keys_test.go`
- Modify: `internal/providers/haproxyconf/fuzz_test.go` (`FuzzParseHAProxyConfig`)
- Modify: `internal/providers/types.go:344-356` (`UnsupportedUnknownKeyword = "unknown_keyword"`)
- Modify: `internal/providers/webserver/convert.go:51-53` (`pairReasons` gains it; the comment names haproxyconf), `internal/providers/webserver/guard_test.go:67-77` (union of nginxconf, apacheconf and haproxyconf `Reason*`)
- Modify: `web/src/api/enums.ts:83-96` (`UNSUPPORTED_REASONS` gains `unknown_keyword`), `web/src/locales/en.json`, `web/src/locales/tr.json`:
  - `locations.unsupported.unknown_keyword`, en: "This certificate is on a bind line with an option Alice does not know, so Alice cannot tell which files that line uses."
  - tr: "Bu sertifika, Alice'in tanımadığı bir seçenek içeren bir bind satırında; Alice bu satırın hangi dosyaları kullandığını bilemez."
- Modify: `api/openapi.yaml` (`unsupported_reason` known values gain `unknown_keyword`)
- Modify: `Makefile:368-372,414-420` (new `fuzz-haproxy` with both targets; `fuzz-nightly`/`fuzz-release` gain it, "33 targets, 330 minutes" / "33 targets, about 16.5 hours"), `.github/workflows/release.yml:83` (`fuzz-haproxy` in the matrix)

**Interfaces:**
- Consumes: Task 4's outputs.
- Produces:
  - `type Input struct { Path string; Data []byte; Version string; ReadFile func(path string) ([]byte, error); ReadDir func(path string) (names []string, isDir bool, err error) }`;
  - `type Config struct { Servers []Server }`;
  - `type Server struct { File string; Line int; Section string; Names []string; Listens []Listen; Pairs []Pair }`;
  - `type Pair struct { Cert, Key, CertRaw, KeyBeside, Unsupported string }` (`Key == Cert` until `ResolveKeys`);
  - `func Parse(in Input) (Config, error)`;
  - `func ResolveKeys(c *Config, keyInCert func(cert string) bool)`;
  - `func MarkWritable(c *Config)`;
  - `func (c Config) CertPaths() []string` and `func (c Config) KeyPaths() []string` (supported pairs, distinct, in order);
  - `func ToWire(s Server) helperproto.DumpServer`: slices are never nil; `Raw` is `CertRaw` cut to 200 runes, only when the pair is unsupported; `Section` is cleaned to 253 bytes; `Stream` is false; `DefaultServer` is false.

- [ ] **Step 1: Write the failing table tests** (`TestParse`, one row each, asserting `Servers` exactly; `ReadFile` and `ReadDir` come from an in-memory map that counts calls)
  - **Two frontends and a listen.**
    - `frontend fe_https` with `bind *:9443 ssl crt /c/a.pem crt /c/b.pem` gives one server: `Section: "fe_https"`, `Line` = the bind line, `Names: []`, two pairs, `KeyBeside: "/c/a.pem.key"` and `"/c/b.pem.key"`.
    - `listen li` with an ssl bind is read.
    - `backend be` with an ssl bind gives nothing.
  - **crt-base.**
    - `global` `crt-base /c` then `crt a.pem` gives `/c/a.pem`.
    - A later `global` with `crt-base /x` does not change an earlier bind.
    - `crt a.pem` with no crt-base gives `path_not_allowed`.
    - `crt-base c` (relative) gives `path_not_allowed`.
    - `crt /c/../a.pem` gives `path_not_allowed`.
  - **crt-list.**
    - `crt-list /l/list.txt` (Ruling 11 sample) gives one server per entry line, `Names` per line, paths joined to `crt-base`.
    - `crt-list l.txt` gives one pair `path_not_allowed` with `CertRaw: "l.txt"`, and `ReadFile` is not called.
    - A line naming a directory gives `path_not_allowed`.
  - **shared crt-list.** Two frontends name `/l/list.txt`: `ReadFile` is called once, and both frontends' servers list its entries.
  - **crt directory.**
    - `ReadDir("/c/dir")` gives `[".old.pem", "a.pem", "a.pem.key", "b.crt", "x.ocsp", "y.issuer", "z.sctl", "w.pem.rsa"]` with `isDir`.
    - With version `2.6.12` the pairs are `a.pem`, `b.crt` and `w.pem.rsa`, in that order.
    - `ReadDir` is called once per distinct directory.
  - **dotfiles by version.** For the same directory:
    - `2.4.30` includes `/c/dir/.old.pem` first;
    - `2.5.14` includes it;
    - `"weird"` gives that pair `conditional`.
  - **ssl-load-extra-files.**
    - `none`, `ocsp` and `ocsp bundle` give `KeyBeside: ""`.
    - `ocsp key` and `all` give the companion.
    - `ssl-load-extra-del-ext` with `crt /c/x.crt` gives `KeyBeside: "/c/x.key"`.
    - `ssl-load-extra-del-ext` with `crt /c/x.pem` gives `/c/x.pem.key`.
  - **Variables.**
    - `crt "${D}/a.pem"`, `crt "$D/a.pem"` and `crt '${D}/a.pem'` give `variable` with `CertRaw` kept.
    - A crt-list entry `$X/a.pem` gives `variable`.
  - **`.if` blocks.**
    - `.if 0 … .endif` skips its binds.
    - `.if 1` and `.if "1"` keep them.
    - `.if` alone skips.
    - `.if defined(X)`, `.if !0`, `.if version_atleast(2.4)` and `.if "$X"` give `conditional`.
    - `.if 0` / `.elif 1` takes the elif.
    - `.if 1` / `.else` skips the else.
    - `.if X` / `.else` gives an uncertain else.
    - Nested `.if 0` / `.if 1` skips.
    - An unclosed `.if` gives `ErrSyntax`.
    - 101 nested levels give `ErrTooDeep`.
    - `.if 0` around `frontend fe2` keeps the following bind in the previous section.
    - `.if X` around a section header makes the following binds `conditional` with `Section: ""` until the next header.
    - `crt-base` set inside `.if X` makes later relative crt pairs `conditional`.
  - **disabled.**
    - `disabled` in a frontend omits its servers.
    - `disabled` inside `.if X` in a frontend gives `conditional`.
    - `disabled` in `defaults` makes later frontends' pairs `conditional`, unless the frontend says `enabled`.
  - **Arity.**
    - `bind :443 ssl name crt crt /c/a.pem` gives exactly one pair `/c/a.pem`.
    - `bind :443 ssl crt /c/a.pem default-crt /c/b.pem` gives one pair `unknown_keyword`.
    - `bind :443 crt /c/a.pem` (no ssl) gives no server.
    - `ssl` after `crt` counts.
  - **Bounds.**
    - 257 distinct crt-lists give `ErrTooComplex`.
    - 4097 directory entries give `ErrTooComplex`.
    - A crt-list of 1<<16+1 lines gives `ErrTooComplex`.
    - 1<<17+1 names give `ErrTooComplex`.
    - A callback error `errFake` is returned so that `errors.Is(err, errFake)` holds.
  - `keys_test.go`:
    - `TestResolveKeys`: `keyInCert` true gives `Key == Cert`; false with a companion gives `Key == KeyBeside`; false without a companion gives `Key == Cert`; unsupported pairs are untouched.
    - `TestMarkWritable`.
    - `TestToWire`: empty slices, not nil; `Raw` only when unsupported; `Section` kept.
    - `TestCertAndKeyPaths`: distinct, in order, supported only.
  - `webserver/guard_test.go`: `withPrefix(nginxconf ∪ apacheconf ∪ haproxyconf, "Reason") == sorted(pairReasons)`.
  - `web/src/api/enums.test.ts` (existing checks): `unknown_keyword` has a text in en and tr.
  - `FuzzParseHAProxyConfig(data []byte)`:
    - The input is `data` as `haproxy.cfg`, version `2.6.12`. `ReadFile` returns `data` for any path; `ReadDir` returns `["a.pem", ".b.pem", "c.key"]` with `isDir` for paths ending `/d`.
    - Asserts no panic.
    - Every supported pair has a `ValidPath` cert and `KeyBeside` (when set).
    - Every `Line >= 1`.
    - The servers number at most `MaxServers`.
- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./internal/providers/haproxyconf/ ./internal/providers/webserver/ && cd web && npx vitest run src/api/enums.test.ts`
Expected: FAIL.
- [ ] **Step 3: Implement** per Rulings 6–14. The region state is `active | inactive | uncertain`, kept on a stack. Each directive carries the strongest state above it. The global settings (`crt-base`, `ssl-load-extra-files`, `ssl-load-extra-del-ext`) are a value plus an "uncertain" flag, updated in read order. The `crt-list` and directory results are cached by path inside one `Parse`. The walk is iterative.
- [ ] **Step 4: Run the tests**
Run: `go test -race -count=1 ./internal/providers/haproxyconf/ ./internal/providers/webserver/ && go test -count=1 -run '^$' -fuzz FuzzParseHAProxyConfig -fuzztime 120s ./internal/providers/haproxyconf/ && go test -cover ./internal/providers/haproxyconf/ && cd web && npx vitest run src/api && cd .. && make i18n-check`
Expected: PASS, coverage ≥ 92 %.
- [ ] **Step 5: Commit**: `feat(haproxyconf): evaluate sections, .if blocks, crt-base, crt-list files, crt directories and key files into certificate pairs`

---

### Task 6: Helper subcommand `haproxy-dump`

**Files:**
- Create: `cmd/alice-helper/haproxy.go`, `cmd/alice-helper/haproxy_test.go`
- Create: `cmd/alice-helper/rootdir.go` (`listRootDir`) and its tests in `rootpath_test.go`
- Modify: `cmd/alice-helper/run.go:59` (register `SubHAProxyDump`, privileged), `cmd/alice-helper/sys.go:36-39` (`runHAProxy` field), `cmd/alice-helper/main.go` (`runHAProxy` through `runGuarded(haproxyPath)`)
- Modify: `test/images/e2e-target/Dockerfile:16-21` (`COPY internal/providers/haproxyconf/ …` in the helper stage), `test/release/harness_test.go:204` (copy `internal/providers/haproxyconf`)

**Interfaces:**
- Consumes:
  - from Tasks 1–5: `SubHAProxyDump`, `WarnConfigDirNotRead`, `runGuarded`, `programError` and `haproxyconf.*`;
  - existing helpers: `walkRoot`/`openLinked`, `resolveRoot`, `walkReason`, `untrusted`, `unsupported`, `dumpMeta` and `finishDump`.
- Produces:
  - constants `haproxyPath = "/usr/sbin/haproxy"`, `haproxyConfPath = "/etc/haproxy/haproxy.cfg"`, `haproxyConfDir = "/etc/haproxy/conf.d"`;
  - `sys.runHAProxy func(ctx context.Context, args ...string) (stdout, stderr []byte, err error)`;
  - `func (s *sys) listRootDir(dir string) (names []string, isDir bool, err error)`: regular entries, or links the walk resolves to regular files; at most `haproxyconf.MaxDirEntries+1` names; `isDir` false for a non-directory or a walk failure;
  - `func (s *sys) keyInCert(p string) bool`;
  - `func (s *sys) haproxyConfig(ctx context.Context) (haproxyconf.Config, dumpMeta, error)`;
  - `func cmdHAProxyDump(ctx context.Context, s *sys, args []string) (any, error)`.

- [ ] **Step 1: Write the failing tests** (`haproxy_test.go`). The fixture tree lives under the test's root. A fake `runHAProxy` answers from a table keyed by `strings.Join(args, " ")`. The fixture is two frontends: a combined `/etc/haproxy/certs/a.pem`, `b.pem` with `b.pem.key`, and a crt-list with SNI.
  - `TestHAProxyDumpRunsTwoCommandsInOrder`: the calls are exactly `-v` and `-c -f /etc/haproxy/haproxy.cfg`.
  - `TestHAProxyDumpListsTwoFrontends`:
    - The answer has `ok` and `version: "2.6.12-1+deb12u3"`.
    - `conf_path` is `/etc/haproxy/haproxy.cfg` and `config_valid` is true.
    - Servers carry `section` `fe_https` and `li_sni`, the SNI names and listens 9443/9444.
    - Pairs have `key` `a.pem` (combined) and `b.pem.key` (companion).
    - `files` describe the certificates (PEM, SHA-256) and keys (stat only).
    - `warnings` is `[]`.
  - `TestHAProxyDumpValidity`:
    - Exit 2 of `-c` gives `config_valid: true`.
    - Exit 1 gives `config_valid: false`, `config_error: "syntax"`, empty servers and files, and nothing of stderr in the answer.
    - Neither `haproxy.cfg` nor any crt-list is opened after exit 1 (count the reads).
  - `TestHAProxyDumpNotInstalled`: an `fs.ErrNotExist` run, or a `-v` without `HAProxy version`, gives a precondition with `SOFTWARE_NOT_FOUND`.
  - `TestHAProxyDumpKilledIsIOError`.
  - `TestHAProxyDumpUntrusted`. Each case maps as follows:

    | Case | Result |
    |---|---|
    | `haproxy.cfg` in a group-writable directory | untrusted `not_root_controlled` naming it |
    | `haproxy.cfg` missing after a valid `-c` | untrusted `missing` |
    | a crt-list missing | untrusted `missing` naming it |
    | a program error from `runGuarded` | untrusted `not_root_controlled` naming `/usr/sbin/haproxy` |
    | parser `ErrTooComplex` | unsupported `too_complex` |
    | parser `ErrSyntax` | syntax |
  - `TestHAProxyDumpWritableConfigMarksEveryPair`: a 0666 crt-list gives `writable: [it]`, the warning `config_file_writable`, every pair `config_file_writable`, and no files described. A writable `haproxy.cfg` followed by a missing crt-list gives untrusted `changed` naming `haproxy.cfg`.
  - `TestHAProxyDumpReadsEachCrtListOnce`: two frontends name one crt-list, and it is opened once.
  - `TestHAProxyDumpWarnsAboutConfDir`:
    - `/etc/haproxy/conf.d/extra.cfg` (regular, root's) gives the warning `config_dir_not_read`.
    - These give no warning: only `README`; a `conf.d` that is a 0777 directory; no `conf.d`.
  - `TestKeyInCert`: a combined PEM (`-----BEGIN PRIVATE KEY-----`, `RSA PRIVATE KEY` and `EC PRIVATE KEY` variants) gives true. A certificate-only file gives false. A missing file gives false.
  - `TestListRootDir`: entries `a.pem`, `sub/`, `link.pem → a.pem` (root's) and `fifo` give `["a.pem", "link.pem"]`, `true`. A file path gives `false`. A 0777 directory gives `false`.
  - `TestHAProxyDumpBounds`: a directory with 4097 entries gives unsupported `too_complex`.
  - `TestHAProxyDumpRefusesArguments`: `haproxy-dump x` gives `USAGE`.
  - `TestHAProxyDumpWritesNothing`: a `(path, size, mtime, mode)` snapshot of the whole fixture root, taken before and after a dump for every outcome above, stays equal.
- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./cmd/alice-helper/ -run 'HAProxy|KeyInCert|ListRootDir'`
Expected: FAIL.
- [ ] **Step 3: Implement** per Rulings 2–4 and 12–14.
  - `haproxyConfig` runs `-v` and then `-c`.
  - It reads `haproxy.cfg` with `readApacheFile`'s pattern; generalize that function to `readConfigFile` with a mechanical rename, keeping Apache's behaviour.
  - It calls `haproxyconf.Parse`:
    - `ReadFile` is the same reader, which records writable files and masks errors.
    - `ReadDir` is `listRootDir`.
  - Then `ResolveKeys(&cfg, s.keyInCert)`, and then `MarkWritable` when needed.
  - `cmdHAProxyDump` mirrors `cmdApacheDump`. It adds the `conf.d` warning before `finishDump`.
- [ ] **Step 4: Run the tests**
Run: `go vet ./cmd/alice-helper/ && go test -race -count=1 ./cmd/alice-helper/... && sudo -E env "PATH=$PATH" go test -count=1 ./cmd/alice-helper/... && make helper && go test -count=1 -run TestStatic ./cmd/alice-helper/`
Expected: PASS. The static-binary test still sees only `golang.org/x/crypto` and `golang.org/x/sys`.
- [ ] **Step 5: Commit**: `feat(alice-helper): haproxy-dump reads haproxy.cfg, its crt-lists and crt directories and describes the certificate files, read-only (protocol 9, 1.8.0)`

---

### Task 7: Emulator `haproxy-dump`, fidelity test, provider `haproxy`, target type and migration 00018

**Files:**
- Create: `internal/providers/linuxssh/linuxsshtest/haproxy.go`, `haproxy_dump.go`, `haproxy_test.go`; `cmd/alice-helper/haproxy_fidelity_test.go`
- Modify: `internal/providers/linuxssh/linuxsshtest/emulator.go:66,365` (`hx *haproxyHost`, dispatch `isHAProxySub`); `internal/archtest/arch_test.go:40,439` (linuxsshtest may import haproxyconf)
- Create: `internal/providers/haproxy/provider.go`, `provider_test.go`, `discover_test.go`, `helpers_test.go`
- Create: `migrations/00018_haproxy.sql`, `migrations/haproxy_integration_test.go`
- Modify: `migrations/roles_integration_test.go:318-325`. `hasApacheType`'s `LIKE '%''apache''%'` must still match only `apache`; add a comment saying so and add `hasHAProxyType` only if a roles assertion needs it.
- Modify: `internal/providers/provider.go:22-52` (`KindHAProxy`, `KindForTargetType("haproxy")`), `internal/providers/providers_test.go`
- Modify: `internal/inventory/types.go:22-33` (`TypeHAProxy = "haproxy"`, `webServerTypes = []string{TypeNginx, TypeApache, TypeHAProxy}`, comment), `internal/inventory/validate_test.go` (one_of values `linux, nginx, apache, haproxy`)
- Modify: `internal/archtest/webserver_test.go` (the ident `TypeHAProxy` is allowed only in `types.go`)
- Modify: `cmd/alice/providers.go:16-37`, `cmd/alice/wiring.go:12`, `cmd/alice/providers_test.go:31-66` (rename to `TestRegisterProvidersShipsEveryProvider`; 5 providers)
- Modify: `locales/common/en.json`, `locales/common/tr.json` (`provider.haproxy.name`: "HAProxy server" / "HAProxy sunucusu")
- Modify: `coverage-floors.json` (`haproxy: 98`); `test/matrix/traceability.json` F-20 (`internal/providers/haproxy:TestDiscoverWithoutHAProxyFails`), then regenerate the doc
- Test: `internal/inventory/targets_integration_test.go` (next to `TestApacheTargetsCountTowardTheLicense`)

**Interfaces:**
- Consumes: Tasks 1–6; `webserver.NewBase/Spec/BaseCapabilities`.
- Produces (emulator):
  - `type HAProxySite struct { Frontend string; Port int; CertPath string; KeyBeside bool; SNI []string }`. `KeyBeside` means the key is written to `CertPath+".key"` and not into the PEM. Sites with SNI are served through the generated crt-list `/etc/haproxy/emu.crtlist`.
  - `func (e *Emulator) EnableHAProxy(version string)`;
  - `SetHAProxyProfile(installed bool)`;
  - `AddHAProxySite(s HAProxySite, certPEM, keyPEM []byte)`;
  - `SetHAProxyConfig(text string)`;
  - `SetHAProxyFile(p string, content []byte)`;
  - `SetHAProxyConfigInvalid(invalid bool)`;
  - `SetHAProxyKilled(killed bool)`;
  - `SetHAProxyConfDir(names ...string)`.

  The generated `haproxy.cfg` has one `frontend` per distinct `Frontend`, with `bind :<port> ssl crt <path>` per site without SNI and one `bind :<port> ssl crt-list /etc/haproxy/emu.crtlist` for the SNI sites. The version defaults to `2.6.12`.
- Produces (provider):
  - package `haproxy`: `type Options struct { SSH *linuxssh.Provider }`, `func New(o Options) *Provider`, `type Provider struct { webserver.Base; caps providers.CapabilitySet }`, `Capabilities()` and `Open(...)`. `Open` returns the `*webserver.Session`, never a typed nil.
  - The spec is `{Kind: KindHAProxy, DisplayNameKey: "provider.haproxy.name", Dump: linuxssh.CmdHAProxyDump, Test: nil, NotFoundCode: helperproto.CodeSoftwareNotFound, MinProtocol: helperproto.HAProxyMinProtocol, Subcommands: []string{helperproto.SubHAProxyDump}, UsualFolders: []string{"/etc/ssl/", "/etc/haproxy/", "/etc/pki/", "/etc/letsencrypt/"}}`.
  - Capabilities: `webserver.BaseCapabilities()` only.
- Migration 00018:
  - Up: `targets_type_check` becomes `type IN ('nginx', 'apache', 'haproxy', 'linux', 'azure_key_vault')`.
  - Down: a `DO` block raises `Z1008` `'cannot migrate down: HAProxy servers exist (targets of type haproxy, deleted ones included); restore a backup taken before 00018'` while any `haproxy` row exists. Otherwise it restores 00017's CHECK.

- [ ] **Step 1: Write the failing tests**
  - `linuxsshtest/haproxy_test.go`:
    - Without `EnableHAProxy`, the dump gives `SOFTWARE_NOT_FOUND`.
    - With the profile off, sudo refuses with exit 1.
    - `haproxy-dump x` is refused by sudo.
    - Two sites (one combined, one `KeyBeside`, one with SNI) give servers with sections and keys resolved.
    - `SetHAProxyConfigInvalid(true)` gives `syntax`.
    - `SetHAProxyConfDir("extra.cfg")` gives the warning.
    - `SetProtocol(8)` answers `version` 8.
  - `cmd/alice-helper/haproxy_fidelity_test.go`, `TestHAProxyEmulatorFidelity`:
    - Each scenario runs on the real helper (a temporary root, and a fake `runHAProxy` written independently of the emulator) and on the emulator.
    - The scenarios: not installed, two frontends (file and crt-list), combined, companion key, crt directory, key mode 0644, writable crt-list, invalid, killed, and the `conf.d` warning.
    - Compare exit, code, `config_*`, servers with `section` (file and line normalized as `emulator_fidelity_test.go:37-40` does), files (owner and group normalized), warnings and `writable`.
  - `TestHAProxyAndApacheOnOneHostStaySeparate`: each dump lists only its own sites. A shared certificate has the same `sha256` in both.
  - `haproxy/provider_test.go`:
    - `TestHAProxyProviderDescribesItself`: kind, key, the five base capabilities.
    - `TestHAProxyConformance` (`providertest`).
    - `TestTestConnectionReadsTheDump`.
    - `TestTestConnectionChecksTheHAProxyProfile` (`haproxy.profile_missing`).
    - `TestHAProxyNotInstalledIsAWarning`.
    - `TestHAProxyHelperTooOld`: an emulator at protocol 8 gives the warning `web_server_helper_too_old`. `Discover` gives `haproxy.helper_too_old` with `{"helper_protocol": "8", "required_protocol": "9"}`, and no `haproxy-dump` call is made.
  - `haproxy/discover_test.go`:
    - `TestDiscoverTwoFrontends`: locations, `servers[].section`, SNI names, `Software: "haproxy"`.
    - `TestDiscoverWithoutHAProxyFails`: `haproxy.not_found`, with no partial data.
    - `TestDiscoverCompanionAndCombinedKeys`: the companion's `KeyPath` is `CertPath+".key"`, with `key_mode_open` at 0644. The combined file has `KeyPath == CertPath`. Both are `Supported`.
    - `TestDiscoverConditionalPairIsUnsupported`: `SetHAProxyConfig` with `.if defined(X)` gives `conditional`.
    - `TestDiscoverCustomLocation`: a certificate under `/srv/certs` is a custom location.
  - `providers_test.go`: `KindForTargetType("haproxy") == (KindHAProxy, true)`.
  - `cmd/alice/providers_test.go`: 5 providers; haproxy's capability set; `CheckProvider`; `TestEveryWebServerTypeHasARegisteredKind` covers `haproxy`.
  - `migrations/haproxy_integration_test.go`, `TestMigration00018`:
    - After `UpTo(18)` a `haproxy` target inserts, with non-empty warning `Params` in its facts.
    - `DownTo(17)` fails with `Z1008`.
    - Without a haproxy row, `DownTo(17)` succeeds and a haproxy insert is refused.
    - `Up` again succeeds.
  - `TestHAProxyTargetsCountTowardTheLicense`.
- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./internal/providers/... ./cmd/alice-helper/ ./cmd/alice/ ./internal/archtest/ && go test -count=1 -tags integration ./migrations/ -run 00018`
Expected: FAIL.
- [ ] **Step 3: Implement**
  - Port `cmdHAProxyDump` into the emulator the way `apache_dump.go` ports `cmdApacheDump`. The emulator's `ReadFile`, `ReadDir` and `keyInCert` read its file table, so the real `haproxyconf.Parse` decides. `sudoersAllows(SubHAProxyDump, args)` is `len(args) == 0`.
  - The provider is modelled on `internal/providers/apache/provider.go`. Register it next to apache on the same `ssh` provider, and add `providers.KindHAProxy` to `shippedProviders`.
- [ ] **Step 4: Run the tests**
Run: `go build ./... && go test -race -count=1 ./internal/providers/... ./internal/inventory/ ./internal/jobs/... ./cmd/alice/ ./cmd/alice-helper/... ./internal/archtest/ && go test -race -count=1 -tags integration ./migrations/ ./internal/inventory/ -run '00018|Roles|Grant|Count|Create' && make matrix-check MATRIXCHECK_FLAGS=-strict`
Expected: PASS.
- [ ] **Step 5: Commit**: `feat(haproxy): the HAProxy provider (discovery only), its emulated host with a fidelity test, and the target type haproxy (migration 00018)`

---

### Task 8: API surface: error codes, OpenAPI enums, server texts, scan fallback

**Files:**
- Modify: `internal/api/errors.go:270-275,499` (`ErrHAProxyNotFound`, `ErrHAProxyConfigInvalid`, `ErrHAProxyProfileMissing`, `ErrHAProxyHelperTooOld` per Global Constraints; listed in `AllErrorCodes`)
- Modify: `internal/api/errors_test.go` (`reasonShapeRE` gains `haproxy`), `internal/api/errors_webserver_test.go`
- Modify: `locales/common/en.json`, `locales/common/tr.json` (`errors.haproxy.<reason>.{title,cause,action}`, naming HAProxy and `docs/haproxy-host-preparation.md`)
- Modify: `docs/troubleshooting.md` (sections `ALC-HAP-0001`…`0004`, after `ALC-APC-*`)
- Modify: `api/openapi.yaml`: type filter `:743-747`, create type `:5900`, target type `:5977`, provider kind `:6480`, `software` `:6513`, location `target_type` `:6671`. Each gains `haproxy`.
- Modify: `internal/jobs/targetjobs/targetjobs_test.go` (`TestScanFallsBackForEveryWebServerKind` rows for haproxy)

**Interfaces:**
- Produces: the four `ErrorCode`s; OpenAPI enums with `haproxy`.

- [ ] **Step 1: Write the failing tests**
  - `TestWebServerReasonsAreRegistered` gains `{haproxy: not_found, profile_missing, config_invalid, helper_too_old}`, whose codes are `ALC-HAP-000{1..4}` in that order.
  - targetjobs:
    - `run(providers.KindHAProxy, inventory.TypeHAProxy, "haproxy.not_found")` falls back with `WebServer == &{Software: "haproxy"}`.
    - `haproxy.profile_missing` and `haproxy.helper_too_old` fall back with their warnings.
  - API:
    - `POST /api/v1/targets` with `type: "haproxy"` is accepted.
    - `type: "iis"` gives 422 `validation.one_of` with `values: "linux, nginx, apache, haproxy"`.
- [ ] **Step 2: Run them to verify they fail**
Run: `go test ./internal/api/ ./internal/jobs/targetjobs/`
Expected: FAIL.
- [ ] **Step 3: Implement** the codes, texts, troubleshooting sections and enums.
- [ ] **Step 4: Run the tests**
Run: `go test -race -count=1 ./internal/api/ ./internal/jobs/... && make i18n-check && go test -count=1 -tags integration ./internal/api/ -run 'OpenAPI|Target'`
Expected: PASS.
- [ ] **Step 5: Commit**: `feat(api): ALC-HAP-0001..0004 and the haproxy type in the API contract`

---

### Task 9: Web: the HAProxy server page and the "Frontend" column

**Files:**
- Modify: `web/src/api/webServer.ts:4` (`WEB_SERVER_TYPES = ['nginx', 'apache', 'haproxy'] as const`), `web/src/api/types.ts` (profiles back to `Record<'linux' | WebServerType, SetupSnippet>`)
- Modify: `web/src/components/software.ts` (`siteColumnLabel`), `web/src/components/WebsitesPanel.tsx:116,206-235` (header and website cell), `web/src/components/useSiteLabel.ts` (section fallback)
- Modify: `web/src/api/warnings.ts` (`config_dir_not_read: []`), `web/src/api/enums.test.ts:165,214` (`internal/providers/haproxy` among the webServerWarnings dirs; `config_dir_not_read` among `webServerOnly`; the `software` enum equals `WEB_SERVER_TYPES`)
- Modify: `internal/providers/types.go` (`WarnConfigDirNotRead = "config_dir_not_read"`, comment: the dump's warning; the shared layer passes it through), `api/openapi.yaml` (`TargetFacts.warnings` description lists `config_dir_not_read`)
- Modify: `web/src/locales/en.json`, `web/src/locales/tr.json`:
  - `webServer.software.haproxy` "HAProxy".
  - `targets.typeLabel.haproxy` "HAProxy server" / "HAProxy sunucusu".
  - `webServer.siteColumn.{nginx,apache,haproxy}` (Ruling 17).
  - `locations.frontend` "Frontend: {{name}}" / "Frontend: {{name}}".
  - `warnings.config_dir_not_read`, en: "{{software}} on this server also has configuration files in /etc/haproxy/conf.d. Alice reads only /etc/haproxy/haproxy.cfg, so websites defined there are not listed."
  - tr: "Bu sunucudaki {{software}} için /etc/haproxy/conf.d içinde de yapılandırma dosyaları var. Alice yalnızca /etc/haproxy/haproxy.cfg dosyasını okur; orada tanımlanan web siteleri listelenmez."
- Modify: `web/src/test/fixtures.ts:617-640` (`haproxyTargetFixture`: type `haproxy`, the five base capabilities, `web_server.software: 'haproxy'`, version `2.6.12-1+deb12u3`, conf path `/etc/haproxy/haproxy.cfg`)
- Test: `web/src/pages/TargetDetailPage.test.tsx`, `web/src/pages/TargetsPage.test.tsx`, `web/src/components/software.test.ts`, `web/src/api/webServer.test.ts`

**Interfaces:**
- Consumes: Task 2 (`CertServer.section`), Task 1 (`profiles.haproxy`), `capabilityText`, `DisabledFeature`.
- Produces: `siteColumnLabel(t: TFunction, type: string): string`, which is `t('webServer.siteColumn.' + type)` for a web server and `t('locations.columns.website')` otherwise.

- [ ] **Step 1: Write the failing tests**
  - `TargetsPage.test.tsx`: Add server offers `linux`, `nginx`, `apache` and `haproxy`, the last labelled "HAProxy server". Choosing it shows `profiles.haproxy.script` and posts `type: 'haproxy'`. The prepare panel offers the haproxy profile.
  - `TargetDetailPage.test.tsx`, `it('an HAProxy server shows frontends with deployment disabled')`:
    - The column header reads "Frontend" in en and tr. An Nginx and an Apache page still read "Website" / "Web sitesi".
    - A location whose servers are `{section: 'fe_https', names: []}` and `{section: 'li_sni', names: ['sni.example.test']}` shows "Frontend: fe_https", "Frontend: li_sni" and `sni.example.test`, and not "(no server name)".
    - The row's Deploy and Settings controls are `aria-disabled="true"`, reachable by `tab`, and carry "Not available for HAProxy servers yet" / "HAProxy sunucularında henüz kullanılamıyor".
    - The warning `config_dir_not_read` shows its text.
    - An `unknown_keyword` row shows its reason.
    - No visible text outside the disabled controls matches `/deploy/i` (en) or `/dağıt/i` (tr). This proves the Phase B carry: `DISCOVERY_ONLY_TEXTS` already covers HAProxy.
  - `software.test.ts`: `softwareName(t, 'haproxy') === 'HAProxy'`; `siteColumnLabel(t, 'haproxy') === 'Frontend'`; `siteColumnLabel(t, 'linux') === 'Website'`.
  - `webServer.test.ts`: the literal guard covers `'haproxy'` (it iterates `WEB_SERVER_TYPES`).
  - `useSiteLabel`: a location without names whose first server has a section gives that section.
- [ ] **Step 2: Run them to verify they fail**
Run: `cd web && npx vitest run src/pages/TargetDetailPage.test.tsx src/pages/TargetsPage.test.tsx src/components/software.test.ts src/api/enums.test.ts src/api/webServer.test.ts`
Expected: FAIL.
- [ ] **Step 3: Implement** the list, label helper, cell, fallback, texts and fixture. Nothing else should need code: components read `WEB_SERVER_TYPES`, `softwareName` and `can()`.
- [ ] **Step 4: Run the tests**
Run: `cd web && npx vitest run && npm run lint && npx tsc --noEmit && cd .. && make i18n-check web-coverage && go test ./internal/api/ -run OpenAPI`
Expected: PASS.
- [ ] **Step 5: Commit**: `feat(web): HAProxy servers: add, prepare, facts and frontends under a "Frontend" column, with deployment shown disabled`

---

### Task 10: Real matrix `TestRealHAProxy` (Ubuntu 22.04, Debian 12, Rocky 9)

**Files:**
- Modify: `test/images/sshd/ubuntu22.Dockerfile`, `debian12.Dockerfile`, `rocky9.Dockerfile`. Add `haproxy` to the existing `apt-get install` / `dnf install`. Header comment: "haproxy is the distribution's package with its default configuration: installed, never started (discovery only; Nginx owns 80 and 443); the test writes its fixture configuration on ports 9443-9445".
- Create: `internal/providers/haproxy/containers_integration_test.go`
- Modify: `Makefile:36-42`. The help text names HAProxy. Add one line: `set -o pipefail; ALICE_REAL_MATRIX=1 go test -count=1 -v -timeout 30m -tags integration -ldflags "$(HELPER_LDFLAGS)" -run '^TestRealHAProxy' ./internal/providers/haproxy/ $(call SSH_MATRIX_PASSED,TestRealHAProxy)`.
- Modify: `test/matrix/traceability.json` F-20 (`internal/providers/haproxy:TestRealHAProxy`), then regenerate the doc

**Interfaces:**
- Consumes: the `haproxy` profile setup script, `haproxy.New`, and the built helper (verified like `raHelper`, `internal/providers/apache/containers_integration_test.go:86-102`).
- Produces: `rhDotfilesLoaded = map[string]bool{"ubuntu22": true, "debian12": false, "rocky9": false}`.

- [ ] **Step 1: Write the test** `TestRealHAProxy`, one subtest per image. It filters with `ALICE_SSH_IMAGES` and skips without `ALICE_REAL_MATRIX=1`. Its host helper `rhHost` is modelled on `raHost` (`:109-310`). Each step that writes restores afterwards.
  1. **Profile.** Prepare with the `haproxy` profile script. Sudo refuses `sudo -n alice-helper haproxy-dump extra` and `sudo -n alice-helper apache-dump`.
  2. **Default configuration.**
     - TestConnection gives `Found`, a version matching `^2\.(4|6|8)\.\d+`, ConfPath `/etc/haproxy/haproxy.cfg` and valid.
     - Discover gives zero locations and no warning. Rocky's default `frontend main` binds `*:5000` without ssl.
  3. **Fixture.** It uses a test CA. Keys are root:root 0600, written through `h.write`. `/etc/haproxy/haproxy.cfg` is the distribution's `global` and `defaults` plus:
     - `crt-base /etc/haproxy/certs`;
     - `frontend fe_https` with `bind *:9443 ssl crt a.pem crt /etc/haproxy/certs/b.pem`: `a.pem` is combined, and `b.pem` has `b.pem.key` at 0644;
     - `listen li_sni` with `bind 127.0.0.1:9444 ssl crt-list /etc/haproxy/alice.crtlist`, whose line is `c.pem [alpn h2] c.example.test *.c.example.test`;
     - `frontend fe_dir` with `bind :9445 ssl crt /etc/haproxy/certs/dir`, holding `d.pem` (combined), `e.crt` with `e.crt.key`, and `.old.pem` (combined);
     - `.if 0` around a bind naming `/nonexistent.pem`;
     - `.if defined(ALICE_NOPE)` around a bind naming `/etc/haproxy/certs/a.pem`.
  4. **Discover.**
     - The certificate paths are exactly `a.pem`, `b.pem`, `c.pem`, `dir/d.pem` and `dir/e.crt`, plus `dir/.old.pem` when `rhDotfilesLoaded[image]`.
     - The sections are `fe_https`, `li_sni` and `fe_dir`. `c.pem`'s server names are the two filters. The listens are 9443, 9444 ({"127.0.0.1",9444}) and 9445.
     - Each SHA-256 equals `sha256sum` on the host. `a.pem` has `KeyPath == CertPath`. `b.pem` has `KeyPath` `b.pem.key` with `key_mode_open`.
     - One `conditional` location exists for the `.if defined` bind.
     - No location exists for `/nonexistent.pem`.
  5. **Missing certificate.** `rm c.pem` gives ConfigValid false, ConfigError `syntax`, the warning, and no certificates (Ruling 3; unlike Apache).
  6. **Writable configuration.** `chmod 0666 /etc/haproxy/alice.crtlist` makes every location `config_file_writable`.
  7. **conf.d.** `/etc/haproxy/conf.d/extra.cfg` (root 0644) gives the warning `config_dir_not_read`; Rocky's `conf.d` directory exists already. Then remove the file.
  8. **Linux profile.** With it installed, the result is `haproxy.profile_missing`.
  9. **Missing program.** `mv /usr/sbin/haproxy` away gives `haproxy.not_found`.
  10. **Writable program.** `chmod g+w /usr/sbin/haproxy` gives ConfigValid false with `untrusted`/`not_root_controlled` naming `/usr/sbin/haproxy` (Task 3).
  11. **Read-only check.** After every step, `find /etc /var/lib/alice-helper /var/lib/haproxy -newer <stamp>` shows only the test's own writes.
- [ ] **Step 2: Run it** on one image first.
Run: `ALICE_SSH_IMAGES=debian12 make test-ssh`
Expected: PASS. If HAProxy's behaviour differs from a ruling, fix the parser in a separate commit with a table case taken from the real output, and record it in the rulings file.
- [ ] **Step 3: Run the whole matrix**
Run: `make test-ssh`
Expected: `TestRealOpenSSH`, `TestRealNginx`, `TestRealApache` and `TestRealHAProxy` PASS on all three images.
- [ ] **Step 4: Commit**: `test(haproxy): real HAProxy 2.4, 2.6 and 2.8 on Ubuntu 22.04, Debian 12 and Rocky 9 in make test-ssh`

---

### Task 11: e2e: an HAProxy server journey

**Files:**
- Modify: `test/images/e2e-target/Dockerfile`. Add `haproxy` to the `apt-get install`. Then `COPY test/images/e2e-target/haproxy.cfg /etc/haproxy/haproxy.cfg` and `COPY test/images/e2e-target/haproxy.crtlist /etc/haproxy/alice-e2e.crtlist`. HAProxy is never started. Update the header comment.
- Create: `test/images/e2e-target/haproxy.cfg`. It holds the distribution's `global`/`defaults` (with `crt-base /etc/haproxy/certs`) plus:
  - `frontend fe_https` with `bind *:9443 ssl crt haproxy.pem` (combined);
  - `listen li_sni` with `bind *:9444 ssl crt-list /etc/haproxy/alice-e2e.crtlist`.
- Create: `test/images/e2e-target/haproxy.crtlist` (`sni.pem sni.example.test`)
- Modify: `test/images/e2e-target/alice-e2e-pki` (subcommand `haproxy`: issue `/etc/haproxy/certs/haproxy.pem` as a combined file and `sni.pem` with `sni.pem.key`, keys root:root 0600), `test/images/e2e-target/alice-e2e-start` (call `alice-e2e-pki haproxy` after `apache`)
- Modify: `deploy/docker-compose.e2e.yml:42-53` (comment: the target also has HAProxy, configured and not running)
- Modify: `web/e2e/webservers.spec.ts` (a second `describe` per language for HAProxy, sharing the helpers)

**Interfaces:**
- Consumes: the e2e helpers (`resetInstall`, `runWizard`, `apiAs`, `targetExec`, `translator`, `expectAccessible`, `tabTo`), and the spec's `websiteRow` and `sudoers`.

- [ ] **Step 1: Write the journey**, `test.describe('Web server providers: HAProxy (en|tr)')`, pinning the note `'Not available for HAProxy servers yet'` / `'HAProxy sunucularında henüz kullanılamıyor'`:
  1. Prepare with the HAProxy profile script. The sudoers holds `/usr/local/libexec/alice-helper haproxy-dump`.
  2. Add the server with type `haproxy`, confirm the fingerprint, and drain the jobs.
  3. The page shows "HAProxy server", the HAProxy version and the valid configuration.
  4. The websites table's header reads `t('webServer.siteColumn.haproxy')`. The rows show `t('locations.frontend', {name: 'fe_https'})` and `sni.example.test`. The Certificates page lists both certificates.
  5. `tabTo` reaches a row's Deploy control: it is focused and `aria-disabled="true"`, and the tooltip shows the pinned note.
  6. No text outside the disabled controls mentions deploying.
  7. `expectAccessible(page, 'haproxy server')`.
  8. `afterAll` runs the nginx profile script again.
- [ ] **Step 2: Run it**
Run: `make e2e-up && (cd web && npx playwright test e2e/webservers.spec.ts) ; make e2e-down`
Expected: PASS in both languages, Apache and HAProxy.
- [ ] **Step 3: Run the whole e2e suite** (no Docker Go tests meanwhile)
Run: `make e2e-up && make e2e; make e2e-down`
Expected: PASS (phase4 expects protocol 9).
- [ ] **Step 4: Commit**: `test(e2e): add an HAProxy server, see its frontends and certificates, deploy controls disabled with the note`

---

### Task 12: Documentation, security report, changelog, rulings

**Files:**
- Modify: `docs/haproxy-host-preparation.md`. Complete it on the model of `docs/apache-host-preparation.md` with these sections:
  - steps;
  - the haproxy profile (already quoted);
  - the helper version (1.8.0, protocol 9) and "Updating the helper";
  - what Alice reads: `-v`, `-c -f /etc/haproxy/haproxy.cfg`, `haproxy.cfg`, the `crt-list` files, the `crt` directory listings and the certificate files; key files are only stat'ed, and certificate files are read once more to see whether they hold the key;
  - what Alice never changes;
  - "A configuration error": `-c` loads certificates and resolves server names, so a missing certificate, a missing key or an unresolvable server reads as a configuration error with class `syntax`, and environment variables of the service are not set for the check;
  - "Configurations Alice cannot read". This section lists:
    - other `-f` paths, including Red Hat's `/etc/haproxy/conf.d` (warning `config_dir_not_read`);
    - `.if` conditions other than plain numbers (`conditional`);
    - any `$` in a path (`variable`);
    - relative `crt-list` paths and paths without `crt-base` (`path_not_allowed`);
    - bind options of a newer HAProxy (`unknown_keyword`);
    - `peers` and `log-forward` binds;
    - backend client certificates;
    - a writable `haproxy.cfg` or `crt-list` making every place `config_file_writable`;
    - no deployment.
- Modify:
  - `docs/README.md:19`: a row for HAProxy administrators.
  - `docs/operator-guide.md:480`: an HAProxy paragraph covering the Frontend column, frontend names and SNI names.
  - `docs/admin-guide.md:1187-1196`: server types.
  - `docs/troubleshooting.md`: "HAProxy: the helper is too old" (ALC-HAP-0004), "HAProxy: configuration error although HAProxy runs" (`-c` environment, DNS, conf.d) and the `config_dir_not_read` warning.
  - `docs/nginx-host-preparation.md` and `docs/apache-host-preparation.md`: one sentence each on the program pre-check (Task 3).
- Modify: `SECURITY-REPORT.md`:
  - §3: one paragraph on `haproxy-dump`: read-only, a fixed program, the root-controlled walk, the same limits, `-c` running configuration-chosen code such as `lua-load` as root, as `LoadModule` does.
  - §7 KI-40: the pre-check now exists for nginx, apache2ctl (with envvars and apache2), httpd and haproxy; systemctl is not covered.
  - §7, a new row **KI-41** "HAProxy discovery items":
    - `-c` resolves server names and runs with the helper's environment;
    - `conf.d` and other `-f` paths are not read (a warning);
    - writable `haproxy.cfg` or `crt-list` (existence oracle, as KI-29);
    - conditions not evaluated;
    - Residual Low;
    - Recommendation: keep `/etc/haproxy` root-only.
- Modify: `CHANGELOG.md`, a new top section `## Unreleased — HAProxy (discovery only)` with:
  - Added: the type `haproxy`, the Frontend column, the warning `config_dir_not_read`, the reason `unknown_keyword`;
  - Changed (API): `servers[].section`, the enums, `ALC-HAP-0001..0004`;
  - Security: the program pre-check;
  - Helper: 1.8.0 / protocol 9 with `haproxy-dump`;
  - Upgrade notes: reinstall the helper on servers that will be HAProxy servers (others keep working with 1.6.x/1.7.x); migration 00018.
- Create: `docs/superpowers/rulings/haproxy-provider.md`. It records:
  - the rulings made during execution;
  - accepted deviations;
  - deferred minors;
  - carried items, including "a fifth plain `-t` run for Apache" kept as an owner option (Ruling 19);
  - owner steps:
    - the root-only suite if it was not run;
    - a real customer HAProxy configuration review (`crt-list` options, `.if` use, conf.d on Red Hat);
    - reinstall helper 1.8.0;
  - the gate results (Task 13).

- [ ] **Step 1: Write the docs** as listed.
- [ ] **Step 2: Verify**
Run: `make docs-check && go test ./internal/providers/linuxssh/ -run Preparation && go test ./internal/api/ -run Troubleshooting && make matrix-check MATRIXCHECK_FLAGS=-strict`
Expected: PASS.
- [ ] **Step 3: Commit**: `docs: HAProxy host preparation, guides, security report KI-41, changelog and Phase C rulings`

---

### Task 13: Final gates

**Files:** none new. Fix-ups only, each committed with its own message.

- [ ] **Step 1: Static and unit checks**
Run: `go build ./... && go vet ./... && go vet -tags integration ./... && make lint && make test && make i18n-check`
Expected: PASS.
- [ ] **Step 2: Docker Go suites** (no Playwright meanwhile)
Run: `make test-integration && make coverage && make test-ssh`
Expected: PASS. `coverage-floors.json` holds for `haproxy` (98), `haproxyconf` (92), `webserver` (98) and `cmd/alice-helper` (90).
- [ ] **Step 3: Helper root suite and checksums**
Run: `sudo -E env "PATH=$PATH" go test -count=1 ./cmd/alice-helper/... && make helper && cat bin/alice-helper.sha256`
Expected: PASS and two checksums. If sudo needs a password, record it as an owner step.
- [ ] **Step 4: Fuzz smoke**
Run: `make fuzz-haproxy FUZZTIME=5m`
Expected: no crasher.
- [ ] **Step 5: Web and e2e**
Run: `make web-lint web-coverage && make e2e-up && make e2e; make e2e-down`
Expected: PASS.
- [ ] **Step 6: Grep checks**
Run: `grep -rn "'nginx'\|'apache'\|'haproxy'" web/src --include=*.ts --include=*.tsx | grep -v test | grep -v api/webServer.ts; grep -rn 'TypeNginx\|TypeApache\|TypeHAProxy' --include=*.go internal cmd | grep -v _test | grep -v internal/inventory/types.go`
Expected: both print nothing.
- [ ] **Step 7: Update the rulings file** with the gate results and commit it: `docs(rulings): HAProxy provider (Phase C) gates`.
