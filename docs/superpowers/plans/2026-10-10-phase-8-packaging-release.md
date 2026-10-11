# Phase 8: Packaging and Release — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An IT administrator copies `alice-1.0.0.tar.gz` (with `alice-1.0.0.tar.gz.sha256` and its Ed25519 signature) to a fresh Ubuntu 22.04, Debian 12 or Rocky 9 server that has Docker and no internet, runs `tar xzf alice-1.0.0.tar.gz && cd alice && sudo ./install.sh`, and gets a running, hardened two-container installation in `/opt/alice` (preflight with plain `[ OK ]`/`[FAIL]` lines, the package signature and every image checked before loading, a non-superuser database owner, migrations in a one-shot container, the one-time setup code printed once). The browser wizard now has every step of §18.5 — language, administrator with authenticator, recovery passphrase, **HTTPS certificate** (keep the temporary one or upload PEM/PFX, applied without a restart), **mail server** (skip allowed), license, first server — with **Back** on every step after the administrator exists and a resume after a reload; whatever is skipped shows on the dashboard as **Finish setting up**. Alice backs itself up every day at 02:30 (time, zone and the number kept are settings; 14 by default), as one file encrypted to the installation's X25519 backup key (R4, SEC-048: chunked AES-256-GCM, the private key inside the file wrapped by the recovery passphrase); a failed backup is e-mailed, and after 48 hours without a good backup Administrators see a red banner. Operators use `/opt/alice/alicectl backup | backup list | backup verify [--deep] | restore | selfcheck | audit verify | setup-token --reset | support-bundle`; `install.sh --restore-mode` plus `alicectl restore` rebuilds an installation on an empty server with the same data, the same Installation ID and the same license; a wrong passphrase, a damaged, truncated, foreign or newer file changes nothing. `alice-update.sh` updates with a verified signature, an automatic pre-update backup, migrations, `selfcheck`, and an automatic return to the previous version when anything fails — including a migration that errors or is killed halfway (F-68). Audit events can be forwarded to syslog (RFC 5424 over TLS) in chain order. The release is built reproducibly, carries a CycloneDX SBOM, third-party notices and an Ed25519 signature made offline with a release key separate from the license key; the documentation set, `SECURITY-REPORT.md` and the release checklist ship with it. Everything that one Linux machine with Docker can prove is proven by `make` targets; what needs real virtual machines, the production keys, a public host, a browser the machine cannot run, or a human signature is one command and one empty result row for the owner.

**Architecture:** Three new packages carry the backup: `internal/backup/format` (the encrypted container: clear header, ephemeral X25519 to the backup public key, HKDF-SHA256 file key, 64 KiB AES-256-GCM chunks with a counter nonce and a final-chunk flag — no database, fuzzed), `internal/backup/dump` (a framed payload stream and a Go-native, consistent logical dump of every table with PostgreSQL's binary `COPY` inside one `REPEATABLE READ READ ONLY` transaction, and its load into a database migrated to the dump's schema version with `session_replication_role = replica`) and `internal/backup` (create, list, verify, retention, the daily schedule, the failure e-mail and the 48-hour alarm, and restore into a fresh database `alice_restore` that is verified and then swapped in). The distroless image has no `pg_dump`, and the daily backup runs inside the `alice` process, so the dump is Go code (R43 row 1). `internal/audit/forward` forwards the audit log from a cursor to syslog. `internal/platform/tlscert` gains a reloadable certificate store (upload, validation, hot reload, renewal of the temporary certificate by a periodic task). `internal/setup` gains the HTTPS and mail steps, server-side passphrase strength and the derived wizard position. `cmd/alice` gains the operator subcommands (`backup`, `restore`, `selfcheck`, `support-bundle`) and the wiring of the three new periodic tasks (`backup.schedule`, `tls.renew`, `audit.forward`) and a scheduler heartbeat. Packaging lives in `deploy/release/` (production `docker-compose.yml` with the one-shot `migrate` service and the `alice-admin` tools service, the PostgreSQL role script, `.env.template`, and the three host scripts `install.sh`, `alice-update.sh`, `alicectl` sharing `lib/alice-lib.sh`), unit-tested with stub commands on `PATH` and end-to-end by a release harness (`test/release`, build tag `release`) that installs the real tarball inside Ubuntu 22.04, Debian 12 and Rocky 9 containers with no network, driving the host's Docker engine under its own compose project names. Release tooling: `make release` (image bundle, helper, SBOM by the pinned Trivy, notices by `tools/notices`, checksums), signing by `licensectl release-sign` (production, offline) or `tools/releasesign` (test key, generated at test time), verification on hosts by `openssl pkeyutl -verify -rawin` (OpenSSL 3), and `make reproducible-check`. Static and dynamic gates are added as targets (`osv-scanner`, `tools/lockcheck`, shellcheck, actionlint, `tools/matrixcheck` over the matrices of §23–§25, ZAP, testssl, a real-systemd Nginx job, three-browser Playwright, mutation testing), with `nightly.yml` and `release.yml` workflows for the owner's future remote.

**Tech Stack:** Go 1.27.2 (standard library `crypto/ecdh`, `crypto/hkdf`, `crypto/aes`, `crypto/cipher`, `compress/gzip`, `time/tzdata`); existing modules only (pgx v5 `PgConn().CopyTo/CopyFrom`, goose v3 `Provider.UpTo`, `golang.org/x/crypto/argon2`, `golang.org/x/term`, `go.yaml.in/yaml/v3` in tests); React 18 + TypeScript 6 + Vite 8, Mantine 8, Vitest, Playwright 1.63 (Chromium, Firefox, WebKit projects); bash 4 scripts checked by ShellCheck 0.11.0; Docker Engine 24+ with compose v2 on hosts (this machine: Docker 29.9.0, Compose v5.5.0, containerd image store). New pinned tools: `github.com/google/osv-scanner/v2/cmd/osv-scanner@v2.6.0`, `github.com/go-gremlins/gremlins/cmd/gremlins@v0.6.0`, `github.com/rhysd/actionlint/cmd/actionlint@v1.7.12`. New pinned images: `docker:29.9.0-cli@sha256:1a4c7cb63513f349bdad01fcc6e0f3f2f67d37b9da86f14dc0d4a0942eecda00` (a static Docker CLI and compose plugin for the install test images), `ghcr.io/zaproxy/zaproxy:2.17.0@sha256:7aaa659b0d43078febd82e29bad112285c370727e86ab8340444220e17d9f0d2`, `ghcr.io/testssl/testssl.sh:3.2@sha256:51918b1e954df0acee8c08d3ad5ce306710e4fefe49ed0e0f92728ecf9e7ff34`, `koalaman/shellcheck:v0.11.0@sha256:bb596a0d169b85ddd81d8b6d3a2ff6d5baf5fca10b97f575ebc647c3dff62b3d` (the digest of the local `koalaman/shellcheck:stable`, which reports version 0.11.0; Task 14 confirms the tag resolves to it), plus the base images already pinned in the repository (`ubuntu:22.04@sha256:5ec03bb3441e8b0bf3b4f9cd4629a1ae763010dc3035bb8da3ae6cf026486401`, `debian:12@sha256:f37a335e82bca302e955fa39f9dfe28f1be618f016f8a2b56318e5a5111afc26`, `rockylinux/rockylinux:9@sha256:8101994123cf3d0a8fee517bee7f39e555c7d92bd2d9eb3303cc988a0eeed00f`, `postgres:16-alpine@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea`, Trivy `aquasec/trivy:0.74.0@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969`). No new Go module, no new npm package.

**Spec:** `docs/superpowers/specs/alice-v1/` — `06-quality.md` §26.10 (the authority: deliverables, tests that must pass, owner steps 1–6, exit criteria), §22.3 (real-systemd job), §22.7 (stages 5 and 6), §23–§25 (the matrices that must be "green"; F-68, F-70, F-80..F-88, F-92, F-96, F-97 are new here), §25.6 (`FuzzBackupHeader`, `FuzzOpenAPIInputs`, release fuzzing), §25.7 (ZAP, testssl, nuclei, SBOM); `05-operations.md` §18 (tarball, host requirements, `install.sh`, compose, wizard), §20 (update, backup contents, schedule, retention, CLI, restore, fresh host, drill, the CI backup test), §21 (documentation plan and quality gates); `04-security.md` B-1..B-4, U-1..U-4, SCH-1..SCH-4, SEC-030..SEC-037, SEC-042, SEC-048, SEC-071..SEC-073, SEC-084..SEC-090, SEC-101..SEC-107, §16.7 (release key), §17.1, §17.2 (Phase 8 gate), §17.5 (signing), §17.6 (`SECURITY-REPORT.md`), §17.7 (pre-release checklist); `02-architecture.md` lines 341 and 389 (backup key, owner role); `00-decisions.md` R4, R5, R6, R7, R15, R16, R20, R35 (and addendum: Back and resume in Phase 8; installer pre-creates the master key), R36 items 1 and 9, R37 item 2 (helper in the bundle), R38 item 16 (real-systemd job), R39 (pinning, `osv-scanner` deferred to Phase 8), R42 rows 14, 20, 27. `00-decisions.md` wins on conflict; this plan proposes **R43** (written in Task 19) for the conflicts listed under "Spec conflicts resolved by this plan". Carry sources: `docs/superpowers/rulings/phase-7.md` "Carried to later phases", `phase-6.md` (carries 4 and 14), `audit-remediation.md`, `docs/security/reviews/phase-1.md` (P1-01, P1-02, P1-08 and the Phase 8 known limitations), `phase-3.md` "Packaging (Phase 8)", the owner's memory note of carries. Format and style reference: `docs/superpowers/plans/2026-10-07-phase-7-alerts-dashboard-sso.md`.

**Plan verification:** written against the base branch `master` at `8d681a7` (Phases 0–7 and the audit remediation merged; toolchain Go 1.27.2 — `go.mod` says `go 1.27.2` and coverage is measured under 1.27.2; `make ci` green at that tree in two parts, `perf` included); branch `phase-8` is `master` plus this plan's commits. **Amended after the pre-flight** (scan M-1..M-28 and security review S-1..S-40 in `.superpowers/sdd/2026-10-10-phase-8-packaging-release/preflight-{scan,security}.md`; what was applied where: `preflight-rulings.md` in the same directory). Checked with `grep`/`sed` in that tree: `cmd/alice/main.go` (`run` and its commands `serve`, `migrate`, `healthcheck`, `setup-token`, `audit`, `admin`, `license`, `version`; `serve` migrates through `cfg.MigrationURL()` before opening the app pool; `tlscert.EnsureSelfSigned(cfg.KeysDir, hosts, now)` once at start; `healthcheck` GETs `http://<ALICE_HEALTH_ADDR>/healthz`), `cmd/alice/cli.go` (`withPool`, `withServices`, `cliActor = "cli"`, `runAudit`, `runSetupToken`), `cmd/alice/services.go` (`buildServices`, `buildScheduler` with `jobs.Task{Type, Every, Run, Retry}`), `cmd/alice/wiring.go` (`periodicTypes`, `checkWiring`), `internal/platform/config` (`ALICE_DATABASE_URL`, `ALICE_MIGRATE_DATABASE_URL`, `ALICE_KEYS_DIR` default `/opt/alice/keys`, `ALICE_STATE_DIR` default `/opt/alice/state`, `ALICE_TLS_HOSTS`, `MigrationURL`, `SeparateMigrationRole`, `RequireDatabase`, the redacting `String`/`LogValue`), `internal/platform/db.Migrate` (goose provider, `p.Up`), `internal/platform/tlscert` (`EnsureSelfSigned` writing `tls.crt`/`tls.key` in the keys directory, 90-day validity, renewal 7 days before the end, `Organization = "Alice temporary certificate"`, `ServerConfig`), `internal/secrets` (`WrappedBackupKey{Version, PublicKey, KDF, Salt, Nonce, Ciphertext}`, `NewBackupKey`, `Unwrap` returning `ErrDecrypt`, `BackupKDF = {64 MiB, 3, 4}`, `maxKDFMemoryKiB = 1 GiB`, `MasterKeyFile = "master.key"` (base64 of 32 bytes plus newline), `LoadOrCreateMasterKey` adopting an installer's file), `internal/setup` (settings keys `backup.key`, `setup.completed_at`, `setup.license_choice`, `Status{AdminExists, RecoveryPassphraseSet, LicenseChosen, Completed, DefaultLocale}`), `internal/license` (`HWMFileName = "hwm.dat"` in the state directory), `internal/audit` (`Event{Actor, Action, ObjectType, ObjectID, Result, Details}`, `Verify(ctx, q)`, `Report{Intact, Checked, HeadSeq, HeadHash, FirstBadSeq, Problem}`, `Service.Verify`), `internal/notify.AdminNotifier.NotifyAdmins(ctx, tx, template, params)`, `internal/jobs` (`Register(name, class)`, `license.ClassAlways`), `internal/api` (`route{method, pattern, perm, limit, lic, handler}`, `limitDownload` 5/min), `internal/rbac` (`SettingsManage`, `SSOManage`; no backup permission yet), migrations `00001`–`00011` (`citext` is the only extension; `00002` creates `alice_app NOLOGIN` only if missing), `migrations/roles_integration_test.go` (`alice_app` holds SELECT on every table), `internal/testutil/pgtest` (owner = the container's superuser `alice`), `deploy/docker-compose.yml` (named volumes, the superuser owner URL in the `alice` container, the "Phase 8 fix" comment), `deploy/Dockerfile` (distroless, `/usr/local/bin/alice`, helper built for its checksums only), `deploy/postgres/initdb/10-alice-app-role.sh`, `web/src/pages/SetupPage.tsx` (`WizardStep = 'code' | 'language' | 'admin' | 'totp' | 'codes' | 'passphrase' | 'license' | 'platform' | 'done'`), `web/src/pages/setup/*`, `tools/testcerts`, `.gitleaks.toml` (the npm lockfile note), `.github/workflows/ci.yml`, the Makefile targets (`build`, `helper`, `image`, `image-check`, `release-symcheck`, `release-keycheck`, `lint`, `vuln`, `secrets-scan`, `fs-scan`, `image-scan`, `e2e*`, `fuzz-*`, `coverage`, `perf`, `ci`). On this machine: Docker 29.9.0 with the containerd image store, Compose v5.5.0 as a static plugin in `~/.docker/cli-plugins`, the host's `docker` CLI is dynamically linked (so the install test images take a static CLI from `docker:29.9.0-cli`), `koalaman/shellcheck:stable` is pulled (0.11.0), Playwright's cache holds `firefox-1543` and `webkit-2359`, the Go proxy and the registries answer (the digests above were read from the registries on 2026-10-10). Nothing in this plan has been compiled: before Task 1 the controller runs the usual pre-flight (apply each task's sketches in a scratch worktree, compile, list conflicts); every task's red/green steps are the real check. Where a sketch says "as `<name>` does", the implementer reads that code first.

## Global Constraints

- Go module path is `alice`; toolchain `go 1.27.2`. Every shell step assumes `export PATH="$HOME/.local/go/bin:$HOME/go/bin:$PATH"` and the repository root as working directory.
- All code, identifiers, comments, file names, commit messages and technical docs are in English. Turkish appears only as translation values in `tr.json` files.
- **Commits:** Conventional Commits, made with `git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only -m "<message>" -m "Co-Authored-By: <the model that wrote the commit> <noreply@anthropic.com>" -- <paths>` (`-m` before `--`). Several agents share one working tree and one git index: stage new files with `git add -- <paths>` and commit **only** your paths; never `git add -A`, `git add .`, `git commit -a`, a bare `git commit`, `git stash`, `git reset` of paths you did not write, or `git rm --cached -r`. Never squash, rebase or amend: `.gitleaksignore` is pinned to commit hashes, so the branch merges into `master` fast-forward only. The commit snippets in the tasks show `Claude Opus 5.5` in the trailer; substitute the model that wrote the commit.
- **Never read, edit, move, add or commit** `docs/security/reviews/independent-audit-2026-10-04.md`, `docs/security/reviews/independent-audit-2026-10-04-poc/` or `.claude/` (also never grep into `.claude/`: add `--exclude-dir=.claude` to recursive greps).
- **Docker safety:** the owner's live compose project `alice` (image `alice:dev`, volumes `alice_*`) and the containers `pt-footbar-pg` and `slaveofai-postgres` are never touched: no `make up`, `make down`, `make reset`, `make logs`, `make setup-token`, `make unlock`, `make hardening-check`, no `docker compose` without an explicit `-p alice-e2e`, `-p alice-rel-<name>` or `-p alice-zap`, no `docker system/volume/image prune`, no `docker rm`/`stop`/`image rm` of anything you did not create. Allowed: testcontainers, `docker run --rm` throwaway containers, the e2e project `alice-e2e` (`make e2e-up`, `make e2e`, `make e2e-down`; ports `127.0.0.1:9443`, `127.0.0.1:9444`), the release harness projects `alice-rel-*` (ports `127.0.0.1:19440`–`19449`; the harness removes its own projects, volumes, networks, containers and the image tags it created — `alice:1.0.0-rc.1`..`rc.4`, `alice-postgres:1.0.0-rc.1`..`rc.4`, `alice-test/install-*:phase8`; its `TestMain` fails at once when one of these tags exists before the run, so it never removes an image it did not create), the real-systemd containers `alice-sysd-<random>` (Task 15, privileged, removed by their test), and the scan project `alice-zap` (Task 15; release image `alice:ci`; port `127.0.0.1:9445`) with the ZAP and testssl containers that scan it. Images built by this phase never use the tag `alice:dev`. **Never run Docker test containers (integration tests, `make coverage`, `make perf`, `make test-ssh`, `make test-release`, `make test-systemd`) while Playwright runs**: Chromium aborts requests whenever a host network interface changes (`net::ERR_NETWORK_CHANGED`). Tasks marked "Docker alone" run with no other agent using Docker. The final `make ci` runs with no other Docker user at all. From Task 14 on `make lint` runs ShellCheck in a container: never run `make lint` while Playwright runs. Every step that runs Docker says so.
- **Build machine networking:** containers on Docker's default bridge cannot reach the LAN DNS on this machine. An image build that needs the network is primed with `docker build --network host` (same Dockerfile, same tag); trivy runs as `make ci TRIVY_IMAGE="--network host aquasec/trivy:0.74.0@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969"`. Image pulls by the daemon work.
- **Helper rule (R21, R37, R38):** this plan changes **no** `alice-helper` code and no helper protocol: `helperproto.Protocol` stays `6`, `Version` stays `1.5.0`; the release bundle ships the binaries `make helper` builds. Should an implementer find a helper change unavoidable, they stop and report (a change needs the root-only suites, `make test-ssh`, new checksums and a protocol bump).
- **Pinning:** build inputs are pinned by version or `sha256` digest; `go run ./tools/pincheck` (first step of `make lint`) refuses unpinned ones. Every new image of this plan is pinned by tag and digest (Tech Stack); every new Go tool by version in the Makefile (`make tools`). The release bundle pins its two images by **image ID** (R43 row 22).
- **Secret rule (security-critical; SEC-044, SEC-048, SEC-084, SEC-086, B-1..B-4, F-87):** the recovery passphrase, the backup private key, the backup sender private key (`backup.sender`, R43 row 41), the file key, the master key, the database passwords, the one-time setup code and the release/license signing keys never appear in a log line, an argument list, an environment variable, an API answer, an error, an audit row, a job payload, an e-mail, a test artefact or a support bundle. The passphrase is read from the terminal (no echo) or from standard input (`--passphrase-stdin`, which the host wrapper feeds from `--passphrase-file`); it lives in a `[]byte` zeroed after use. A backup is streamed: no plaintext dump or payload file is ever written to disk; a backup file is created `0600` with `O_EXCL` as `.<name>.partial` and renamed only after it was written, synced and re-hashed; a failed backup leaves no partial file (F-70). A restore writes plaintext only into the staging database and into the staging key directory inside the keys volume (`0700`, files `0400`). Database passwords exist on the host only in `/opt/alice/secrets/` (root `0700`) and reach containers only as compose secret files. Test keys and passphrases are generated at test time or are allowlisted fixtures (`.gitleaks.toml`); no private key is committed (SEC-105). In the host scripts the passphrase reaches a child process only through the bash builtin `printf '%s\n' "$pass" | …`; the variable is never exported and is `unset` after use; no `set -x`, `BASH_XTRACEFD` or here-string (`<<<`) anywhere; a `--passphrase-file` that is group- or world-readable is refused (S-25). The setup code is printed to the terminal only, never to `install.log` or any file (S-4). `clear()` of Go byte slices is best effort (R43 row 53). The canary tests of Tasks 4, 5, 6, 11 and 13 prove this.
- **Never-lose-data rule (trust-critical; F-68, F-70, F-80..F-83, F-88, U-3):** a backup that fails never deletes an older one; retention deletes only `auto` backups that were verified when written; a restore that fails at any point leaves the current database, keys and state as they were; the update script keeps the pre-update backup and the previous image and never deletes a backup file, also when its own rollback fails.
- No SQL string building (SEC-060). The exceptions (R43 row 48) are the dump's `COPY` statements, built from catalog identifiers quoted with `pgx.Identifier{…}.Sanitize()` in one function with a `//nolint:gosec // G202: …` reason (Task 2), and the restore's `CREATE DATABASE`, `ALTER DATABASE … RENAME TO` and `DROP DATABASE` statements (DDL cannot take bind parameters; Task 5), built in one function from names derived from `SELECT current_database()` plus the fixed suffixes `_restore` and `_previous_<ts>`, quoted the same way, with the same nolint reason. SQL time comes from the injected clock as a bind parameter.
- Code blocks are gofmt-clean except for column alignment of consecutive one-line declarations and struct fields: run `gofmt -w` (or `make lint`) on every changed Go file before committing. Shell scripts pass `make shellcheck` (Task 14 adds it; Task 11 runs the same `docker run` command before the target exists).
- Tests: Go stdlib `testing` plus testify `require`/`assert` only; small hand fakes, no mock frameworks. Integration tests carry `//go:build integration`, call `pgtest.Main` from `TestMain` and get a fresh database per test from `pgtest.New(t)`. New build tags of this plan: `release` (the release harness, `test/release`), `systemd` (the real-systemd job). Existing tags: `integration`, `perf`, `e2e`, `testlicense`, `releasecheck`, `azure`. A red step in a brand-new package may fail with "no non-test Go files"; that is the expected failure.
- Lint is golangci-lint v2 (`make lint`): gosec, errorlint, forbidigo, bodyclose, misspell, noctx, gofmt, goimports (`local-prefixes: alice`). Forbidden: `fmt.Print*` (CLI output uses `fmt.Fprint*` to the writer `run` passes), `strings.ToUpper`/`ToLower`/`Title`, `time.Now` outside `internal/platform/clock` and tests, `ssh.InsecureIgnoreHostKey`. `InsecureSkipVerify` appears in exactly one new place, `selfcheck`'s TLS probe, with a `//nolint:gosec // G402: …` reason: it accepts only the leaf whose bytes equal `keys/tls.crt`. No `//nolint` without a reason.
- **Module import rules** (`internal/archtest`): Task 1 adds every Phase 8 rule at once (before the packages exist): `"alice/internal/backup/format": {"alice/internal/secrets"}` (pure: `denied` platform and db; `deniedStd` = `pureDenied` — the package works on `io.Reader`/`io.Writer` only and never opens a file, a socket or a database), `"alice/internal/backup/dump": {platform}` (no other Alice module), `"alice/internal/backup/...": {platform, "alice/internal/audit/...", "alice/internal/secrets/...", "alice/internal/notify/...", "alice/internal/license/...", "alice/migrations"}`, `"alice/internal/audit/forward": {platform, "alice/internal/audit"}`; `"alice/internal/backup/..."` is added to the `api` rule; `"alice/internal/notify/..."` is added to the `alice/internal/setup/...` rule (Task 8 reads the mail settings through `notify.Settings`). `TestAllowed` gets positive and negative cases for each.
- API JSON conventions from Phase 1 (snake_case, UTC RFC 3339, error body `code`, `reason`, `message_key`, `message`, `request_id`, `retryable`, `params`, `details`; lists `{items, next_cursor}`); every new code `ALC-<AREA>-<NNNN>` has `errors.<reason>.title|cause|action` in `locales/common/{en,tr}.json`, a section in `docs/troubleshooting.md` and an entry in `AllErrorCodes()` (Phase 8 adds `phase8Table`). Every new route is in the route table with a permission and (for non-GET methods) a license class, in `api/openapi.yaml` with the same `x-permission`, in `docs/authz-matrix.md` (`make authz-doc`) and in the authz tests. A `PUT` of a setting needs a strong `If-Match`.
- Audit detail keys pass the denylist of `internal/audit/audit.go`: this plan uses `name`, `kind`, `reason`, `size`, `error_code`, `backup_name`, `backup_created_at`, `alice_version`, `schema_version`, `deleted_count`, `subject`, `not_after`, `fingerprint`, `temporary`, `host`, `port`, `transport`, `enabled`, `ca_set`, `time`, `zone`, `retention`, `choice`, `previous_audit_seq`, `previous_audit_hash`, `safety_backup`, `no_safety_backup`; never `passphrase*`, `key*` (except `*_id`), `password*`, `secret*`.
- i18n: every user-visible string is a key in English and Turkish (`make i18n-check`); placeholders `{{name}}` without spaces; no sentence assembly; formal-polite Turkish ("siz"); plural forms `_one`/`_other`. Terminology (fixed for EN and TR, existing terms kept): **Backups** / "Yedekler", **Back up now** / "Şimdi yedekle", **Download** / "İndir", **recovery passphrase** / "kurtarma parolası", **HTTPS certificate** / "HTTPS sertifikası", **Keep the temporary certificate** / "Geçici sertifikayı kullanmaya devam et", **Audit forwarding** / "Denetim kaydı iletimi", **Finish setting up** / "Kurulumu tamamlayın", **Back** / "Geri", **Skip** / "Atla", **No successful backup for 48 hours** / "48 saattir başarılı yedek yok". File names, paths, fingerprints, host names and image IDs are rendered with `<Code>`, never translated. Host-side script and CLI messages are English only (§21: documentation and operator tooling are English; R7 dropped the Turkish quick-start).
- Accessibility: new screens and dialogs have no serious or critical axe violation at 640, 1280 and 1920 px (`expectAccessible`) and at 375 px for the wizard steps (`expectWide`), in English and Turkish, keyboard usable, no horizontal page scroll.
- Frontend: no `dangerouslySetInnerHTML`, no `toUpperCase`/`toLowerCase`; a PFX password and an uploaded private key live only in component state of their form and are cleared after the request; they are never in a query key, the query cache, `localStorage` or a log. A backup download is a plain link that the step-up dialog unlocks (no blob in memory).
- **Coverage floors in `coverage-floors.json` are never lowered.** New packages get floors in Task 19: `internal/backup/format` and `internal/backup/dump` at their measured values rounded down but at least 95 and 90, `internal/backup`, `internal/audit/forward`, `internal/testutil/fakesyslog` at their measured values rounded down. Thin floors this phase touches: `internal/secrets`, `internal/setup`, `internal/platform/tlscert`, `internal/platform/config`, `internal/audit`, `internal/api` 94, `cmd/alice` 90, `internal/rbac` 98: every line a task adds there carries its tests.
- **Parallel work:** at most three agents at once, grouped by ownership so that two agents never edit one package, one locale file or the Makefile at the same time; the schedule is in "Task index". `Makefile` belongs to Task 12, then 14, then 13, then 15, then 19 (Task 3 adds no target; Task 6 adds none; Task 16 adds none). `locales/common/{en,tr}.json` to Task 4 (the two backup e-mails), then Task 9. `web/src/locales/{en,tr}.json` to Task 10 only. `cmd/alice` to Task 3, then Task 6, then Task 9 (the `newAPIDeps` line only). `tools/pincheck` to Task 3, then Task 12, then Task 14. `internal/secrets` to Task 1 (backup key v2), then Task 6 (`CheckMasterKey`). `internal/setup` to Task 1 (the `SetRecoveryPassphrase` call of the v2 key only), then Task 8. `docs/troubleshooting.md` to Task 9 (code sections, its first commit), then Task 17. `tools/docscheck/required.txt` is created by Task 14; Tasks 17 and 18 each append their own lines. A task that needs a key in a file it does not own lists it in its report and the owner adds it.
- **E2E rules:** a full page load right after the language switch cancels `PUT /auth/locale` — wait for that response before navigating; Playwright tests that download a backup run with `trace: 'off'`, `video: 'off'`, `screenshot: 'off'` and delete the file in a `finally` block.
- **Honest results rule:** a gate that cannot run on this machine is never marked passed. Its row in the evidence tables says `NOT RUN (owner)` or `NOT RUN (CI)` with the one command that runs it; a gate that ran and failed says `FAILED` with the finding; nothing is edited to make a tool pass except a real fix or a recorded, dated, reasoned ignore that the spec allows (`.zap/rules.tsv`, `.trivyignore` with expiry).

## Review Focus

1. **The backup file under attack** — a stolen file (no passphrase), a flipped byte in the magic, header length, header JSON, KDF parameters, salt, wrapped key, ephemeral key, each chunk and at each chunk boundary, a truncated file (cut inside a chunk, at a chunk boundary, the final chunk removed), two chunks swapped, a chunk from another backup spliced in, a header with Argon2 memory of 4 GiB or 1,000 iterations, a 100 MiB header length, an empty file, a text file, a file of a newer format, a wrong passphrase, **a file forged by someone who copied the clear wrapped key and recipient key of a genuine file** (R43 row 41). Expected: never a panic, never unbounded memory, never a partial restore, the two messages "This is not an Alice backup." / "The passphrase is wrong or the file is damaged. Nothing was changed.", and no customer data or secret in the clear header. Tests: Task 1 (`TestRoundTrip`, `TestKnownAnswer`, `TestEveryFlippedByteFails`, `TestTruncationAndReorderFail`, `TestHeaderBounds`, `TestWrongPassphrase`, `TestForgedBackupWithCopiedWrappedKeyFails`, `TestWrappedKeyV2BindsSender`, `FuzzBackupHeader`, `FuzzBackupStream`), Task 4 (`TestF87NoPlaintextInTheFile`, `TestCreateRefusesV1BackupKey`), Task 5 (`TestF80WrongPassphraseChangesNothing`, `TestF81FlippedByteChangesNothing`, `TestF82TruncatedChangesNothing`, `TestF83ForeignAndNewer`).
2. **A restore that can only succeed completely or not at all** — a restore killed after the staging database is filled, after the key files are staged, between the database swap and the key-file rename; a backup whose audit chain is broken; a backup of an older schema (F-84); a restore onto a host that already has data; the update rollback (`--db-only`). Expected: the previous database, master key, TLS files and time record stay in force until the single swap point (both database renames in one transaction), a second run finishes or cleans up — staged files are applied only when the live database carries the staging's restore ID, and no cleanup ever drops the only copy —, a restore never lowers the license time record, sessions are ended, `system.restored` continues the chain (F-97), the Installation ID and license survive (F-85). Tests: Task 5 (`TestRestoreIsAllOrNothing`, `TestFinishIgnoresStaleStaging`, `TestCleanupNeverDropsTheOnlyCopy`, `TestRestoreKeepsTheNewerTimeRecord`, `TestRestoreCleansUpAfterADatabaseError`, Task 6's `TestServeFinishesAnInterruptedRestore`, `TestF84OlderSchemaMigratesForward`, `TestF85FullCycle`, `TestF97RestoreContinuesTheChain`, `TestRestoreRefusesABrokenChain`), Task 13 (`TestReleaseF85Drill`, `TestReleaseRestoreNegatives`).
3. **Root-run host scripts** — paths with spaces, a tarball whose checksum or signature is wrong, a tarball signed by another key, a downgrade, an unsupported upgrade path, a second `install.sh` over an installation, `--uninstall` without `--purge`, a purge without the typed `DELETE`, an update whose migration fails or is killed, an update whose new container never becomes healthy, an update whose rollback fails, Ctrl-C at every step, a tarball swapped by its owner between the check and the extraction, a package with an unlisted file or a symlink, a planted symlink in a container-writable directory, `.env` values with `$` or newlines, a caller environment with `ALICE_IMAGE`/`DOCKER_HOST`, a fingerprint the operator did not confirm, a test-signed package. Expected: the exact messages of C4, no `eval`, no sourcing of package files, every variable quoted, the root scripts never touch `keys/`, `state/`, `backups/` or `data/` after creating them, nothing deleted that holds data, the update either reports "Alice is now version X" or leaves the previous version running with the data of the pre-update backup (or prints the manual restore command and exits 3). Tests: Task 11 (`TestPreflightMessages`, `TestInstallRefusesAnExistingInstallation`, `TestUninstallKeepsData`, `TestPurgeNeedsTypedDelete`, `TestUpdateRefusesTamperedAndDowngrade`, `TestUpdateVerifiesACopy`, `TestSignatureChecks`, `TestScriptsNeverTouchContainerDirs`, `TestInstallValidatesEnvValues`, `TestComposeIgnoresCallerEnvironment`, `TestInstallNeedsTheFingerprintConfirmed`, `TestVersionCompare`, `TestScriptsNeverSourcePackageFiles`), Task 13 (`TestReleaseInstallMatrix`, `TestReleaseUpdateAndRollback`, `TestReleaseRefusesTamperedAndDowngrade`).
4. **Least privilege in the running installation** — the `alice` container must hold no database owner credential (P1-01), PostgreSQL must run read-only as a non-root user with no published port, the secrets must reach only the containers that need them, a backup must be taken with the application role, the restore must need the owner role and a stopped `alice`. Tests: Task 3 (`TestReleaseComposeIsHardened`, `TestAliceServiceHoldsNoOwnerCredential`, `TestMigrationsRunAsNonSuperuserOwner`, `TestServeRefusesAStaleSchemaWhenMigrationsAreExternal`), Task 13 (`TestReleaseInstallMatrix` runs the hardening checks on the installed stack).
5. **Who may back up, download, change HTTPS and forwarding** — Operator and Auditor sessions, `read`/`operate` tokens, an Administrator without step-up, against every new route; a backup name with `../`, a URL-encoded slash, a name of another directory. Expected: the matrix of C12; Administrators with step-up only; downloads 5 per minute, audited before the first byte; names validated by the exact pattern of C8. Tests: Task 9 (`TestPhase8RoutesAuthz`, `TestBackupDownloadRefusesPathTricks`, `TestBackupDownloadIsAuditedFirst`).

---
## Spec conflicts resolved by this plan (proposed R43, written in Task 19)

Each row: the conflict, the decision, why, and the cost if the decision is wrong. Task 19 writes them, corrected to the built code, as **R43** in `00-decisions.md`.

| # | Conflict | Decision | Why | Cost if wrong |
|---|---|---|---|---|
| 1 | §20.2 "PostgreSQL dump (`pg_dump` custom format via the alice container)"; the image is distroless (SEC-089) and the daily backup runs inside the `alice` process | A Go-native logical dump (`internal/backup/dump`): every ordinary table of schema `public` except `goose_db_version`, as PostgreSQL binary `COPY` output, read in one `REPEATABLE READ READ ONLY` transaction with the application role (which holds SELECT on every table), plus every sequence's value; the schema is not dumped — a restore migrates an empty database to the dump's schema version with the migrations of the restoring binary, loads the rows with `session_replication_role = replica`, then migrates forward | No `pg_dump` in the image and no shell; one consistent snapshot (F-86); the restore owns the schema, so a restore into a newer version is the normal migration path (F-84) | A backup cannot be read with `pg_restore`; restoring needs an Alice binary whose migrations include the backup's schema version (every later version does) |
| 2 | Backup crypto parameters: §20.2 (1 MiB chunks, Argon2id 256 MB, magic `ALICEBAK`) vs SEC-048/B-1 (64 KiB chunks, Argon2id m=64 MiB t=3 p=4, magic `ALICEBK1`) and the built `secrets.BackupKDF` | SEC-048: magic `ALICEBK1`, 64 KiB chunks, the existing wrapped key (64 MiB, t=3, p=4); a reader refuses KDF memory above 256 MiB, more than 10 iterations or more than 16 lanes before running Argon2 | SEC-048 is the security section's exact design and matches the key created by every existing installation's wizard | A weaker passphrase KDF than §20.2 describes (the 16-character minimum and the strength check remain) |
| 3 | §20.2 clear header "holds magic, format version, KDF parameters, salt, and Alice version … no customer data"; the manifest names the host and the Installation ID | Clear: magic, format version, Alice version, creation time, kind, the recipient and ephemeral X25519 public keys, the wrapped private key (with its KDF parameters, salt and the installation's sender public key, row 41), chunk size, nonce prefix. Encrypted (first frame of the payload): the manifest (Installation ID, host name, schema version, table row counts, audit head, file list) | The spec's own rule "no customer data in the header"; F-83's "newer version" message needs only the clear Alice version | `backup list` without the passphrase shows name, kind, size, time and Alice version, not the host or Installation ID |
| 4 | SEC-084 "verifies each by checking header and last chunk tag" without the passphrase — impossible: the chunk keys need the private key | `backup verify` (no passphrase): header parses within bounds, the size fits the chunk framing, the `.sha256` file matches; the writer additionally re-reads and re-hashes the file before renaming it; `backup verify --deep` decrypts everything with the passphrase and checks the manifest | Only the holder of the passphrase can check tags; a hash written at creation detects later damage | A file replaced together with its `.sha256` passes the shallow check (the deep check and every restore still refuse it) |
| 5 | §20.2 backup contents list a platform SSH key file and TLS files in `tls/`; R37 moved the platform key into the database; R39 added the time record `state/hwm.dat` | The payload holds: manifest, the dump, `keys/master.key`, `keys/tls.crt`, `keys/tls.key`, `state/hwm.dat` (each when present); the TLS files stay in the keys directory where `tlscert` keeps them | The installation must come back with the same keys, certificate and clock evidence; the license's time record has two copies | none known |
| 6 | §18.3 host layout (`tls/`, `keys/ssh_ed25519`, one `secrets/db_password`, `secrets/setup_token`) | Layout of C2: `keys/` (`master.key`, `tls.crt`, `tls.key`), `state/`, `backups/`, `data/postgres/`, `secrets/` with three passwords (`db_postgres_password`, `db_owner_password`, `db_app_password`), `rollback/`, `release-keys/`, `lib/`, `helper/`; no setup-token file (row 19) | Matches the built code (R37, R39) and the role split of row 7 | Docs and support must use the new layout (Task 17 rewrites them) |
| 7 | §18.4 runs PostgreSQL with `POSTGRES_USER: alice` (a superuser) and one password; P1-01 (Phase 1 review): the superuser owner URL sits in the `alice` container | Production compose (`deploy/release/docker-compose.yml`): superuser `postgres` known only to the `postgres` container; `alice_owner` (LOGIN, CREATEDB, not superuser, owns database `alice`, granted `SET` on `session_replication_role`) used only by the one-shot `migrate` service and the `alice-admin` tools service; `alice_app` used by `alice`, which has no owner credential and does not migrate (`ALICE_MIGRATE=external`: it refuses to start when the schema is not current). Passwords from secret files (`ALICE_DATABASE_PASSWORD_FILE`, `ALICE_MIGRATE_DATABASE_PASSWORD_FILE`). The development compose (`deploy/docker-compose.yml`) is unchanged except a backups volume | Fixes P1-01: code execution in `alice` no longer yields a role that can disable the audit triggers; `citext` is a trusted extension, so a non-superuser owner can run every migration | The owner password is on the host (root-only) and in the tools container while it runs; a restore or migration is a deliberate host-root action |
| 8 | SEC-085 "restores into a fresh schema, verifies the audit chain, and swaps"; F-80 "decrypts to a temp area and validates before swapping"; B-4 "no plaintext temp files" | The restore creates database `alice_restore`, migrates it to the backup's schema version, loads it, verifies (audit chain intact and its head equal to the manifest's — a broken chain is restored only with `--accept-broken-audit-log`, recorded in `system.restored`, so disaster recovery is never blocked by tampering it must reveal — row counts equal to the manifest's, the restored master key opens the stored key check, the installation seal verifies), migrates it forward, writes the key files into a staging directory in the keys volume, writes a safety backup of the current installation (`…-pre-restore.alicebak`) when there is one, then swaps. Crash safety: the load writes a random 128-bit restore ID into the staging database (setting `backup.restore_id`) and into `.restore-staging/RESTORE_ID` of both staging directories; the live `master.key`, `tls.*` and `hwm.dat` are first copied to `.restore-staging/previous/`; both database renames (`alice` → `alice_previous_<ts>`, `alice_restore` → `alice`) run in **one transaction** on the maintenance connection; the staged files are renamed over the live ones only when the live database's `backup.restore_id` equals `RESTORE_ID` — any other value, or none, means the staging is stale: it is removed and the live files are not touched; `alice_previous_<ts>` is dropped only after the file renames are synced; a cleanup never drops `alice_restore` while no database `alice` exists (it finishes the rename instead). The next `Restore`, or `serve` at start (with its app pool open), applies the same rule through `FinishInterruptedRestore` | One swap point; a database is the only "temp area" that is not a plaintext file | A restore needs free disk for two copies of the database while it runs |
| 9 | §20.3/§20.4: restore runs while "only postgres is running"; `alicectl restore` "asks passphrase … requires typing RESTORE"; the update rollback restores unattended | `alicectl restore` first deep-verifies the file with the passphrase while `alice` runs, then stops the `alice` service, ends leftover sessions of `alice_app`/`alice_owner` on the database as the postgres superuser (for example a killed `migrate`), runs `alice restore` in the `alice-admin` container (owner role; it waits up to 150 s for other sessions to end), and a `trap` always starts `alice` again and runs `selfcheck`, whether the restore succeeded or not; the confirmation is typed `RESTORE` or given as `--confirm RESTORE` (used by `alice-update.sh`); the passphrase comes from the terminal or, through the wrapper, from `--passphrase-file` (fed on standard input, never an argument); the file must be inside `<dir>/backups` | A restore replaces the master key: it must not race the running process; automation needs a non-interactive form without putting the passphrase in an argument | An operator must copy a backup into `backups/` first (the message says so) |
| 10 | §20.2 "daily at 02:30 server-local time"; the container's clock is UTC and distroless has no time-zone data | Settings key `backup.schedule` = time of day (`HH:MM`, default `02:30`), IANA zone (default `ALICE_TZ`, else `UTC`; the installer writes the host's zone from `timedatectl` into `.env` when it can) and retention (7–60, default 14); `time/tzdata` is embedded; the task `backup.schedule` checks every 5 minutes whether the latest scheduled instant has no successful automatic backup (so a missed run happens at the next start, §20.2) | Testable with the fake clock (`TestDueAcrossDaylightSaving`); explicit zone instead of guessing | The binary grows by about 450 KB |
| 11 | F-70 "Backup fails with alert"; R7/F-88 "48 h without success → admin alarm"; two backups at once | A failed scheduled backup e-mails Administrators once per failure episode (`backup.failed`); 48 hours without a successful backup e-mails once (`backup.alarm`) and raises the dashboard state and the red banner for Administrators until a success; one backup at a time per installation (advisory lock; `ALC-BAK-0001`) | Tells the administrator early without a mail per 5-minute retry | none known |
| 12 | §20.2 retention ("14 newest `auto`; `manual` and `pre-upgrade` never auto-deleted") | Kinds `auto`, `manual`, `pre-upgrade-<version>`, `pre-restore`; only `auto` files are pruned, only after a successful backup, only files whose `.sha256` matches, each deletion audited (`backup.deleted`); a backup that fails deletes nothing | Spec, plus the new safety kind | Disk use grows with manual and safety backups (the operator guide says how to remove them) |
| 13 | §20.2 "Download" button | `GET /api/v1/backups/{name}/download`: Administrator with step-up, 5 per minute (SEC-022), audited `backup.downloaded` before the first byte, streamed with `Cache-Control: no-store`; API tokens are refused (SEC-025) | The file is encrypted, but its download is a sensitive act | none known |
| 14 | §18.3 step 4: the installer creates the self-signed certificate with `openssl` in the image, 397 days; SEC-036 and the built `tlscert`: 90 days, renewed at start | Alice creates and renews its temporary certificate itself (90 days, renewed 7 days before the end); the new periodic task `tls.renew` (every 6 hours) renews it and the HTTPS listener reloads it without a restart (closes the Phase 1 limitation "renewed only at container start"); `install.sh --hostname` writes `ALICE_TLS_HOSTS` | One owner of the certificate; no `openssl` in the image (SEC-089) | Browsers warn every 90 days until a certificate is uploaded (the wizard and the checklist push the upload) |
| 15 | §18.5 step 4 "upload certificate chain + private key (PEM/PFX, validated and matched) … the HTTPS listener reloads without restart" | `PUT /api/v1/settings/https` (wizard and Settings): PEM chain plus PEM key, or PFX plus its password; the leaf must match the key, be valid now and for at least 1 more day, have an RSA ≥ 2048 or ECDSA P-256/P-384 key, and the chain is reordered leaf-first; the files are replaced atomically (`tls.key` 0400) and the listener's `GetCertificate` serves the new pair to the next handshake; audited `https.certificate_replaced`; refusals `ALC-TLS-0001..0005` | SEC-036, SEC-064 | A certificate without Alice's address in its names is accepted with a warning (the browser will complain) |
| 16 | §18.5 "Back" and server-side position (R35 addendum: with the Phase 8 install wizard); SMTP step (Phase 7 carry 21) | Wizard order: code → language → administrator → authenticator → recovery codes → recovery passphrase → **HTTPS certificate** → **mail server** → license → first server → finish. The position is derived from server state (`setup` settings `setup.https_choice` = `uploaded`/`temporary`, `setup.mail_choice` = `configured`/`skipped`, plus the existing ones); a reload resumes at the first unfinished step; while the setup session cookie is valid a reload before the administrator exists resumes at language/administrator; **Back** is on every step after the administrator exists and shows a finished step in its done state (the recovery passphrase cannot be changed there); the mail step reuses the Phase 7 mail settings and test e-mail | No new table; nothing to get out of sync | A reload before the administrator exists without a valid setup cookie still asks for the setup code |
| 17 | P1-08: the passphrase strength check runs only in the browser | `setup.PassphraseStrength` (Go) rates exactly like `passphraseStrength` of `web/src/pages/setup/strength.ts` (`tooShort`, `fair`, `good`, `strong`; shared vectors in `internal/setup/testdata/strength.json`, read by both test suites); the server refuses `tooShort` (as today) and now also `fair` (`ALC-SET-0010`), and the browser's submit button follows the same rule | B-1 says "with strength check"; the server is the authority | A passphrase the browser shows as weak cannot be forced by a crafted request (intended) |
| 18 | §20.2 "last successful backup age is on the dashboard; banner red after 48 h"; §18.5 "Finish setting up" checklist; R42 row 14 deferred both to Phase 8 | `GET /dashboard/summary` gains `backup` (last success time, age, failing, alarm; Administrators and Auditors) and `setup_checklist` (Administrators: recovery passphrase and HTTPS certificate marked required, mail, license, first server); the red banner **No successful backup for 48 hours** for Administrators | Spec | none known |
| 19 | §18.3 step 3: the installer writes `secrets/setup_token` and stores its hash in `install.log` | `install.sh` runs `alice setup-token --reset` in the started container and prints the code; nothing about the code is written to disk: `install.log` records only `Setup code printed to the terminal (not logged).`, and `alicectl setup-token --reset` tees nothing into a log | The built setup code lives in the database (R35); a file would outlive its use | none known |
| 20 | Release signature: SEC-107 (`SHA256SUMS` + `SHA256SUMS.sig`, Ed25519), §18.1 (`.tar.gz.sig`), §17.1 ("cosign or minisign") | Ed25519 raw signatures. `SHA256SUMS` (every file in the tarball) is signed into `SHA256SUMS.sig`; the outer `alice-<v>.tar.gz.sha256` is signed into `alice-<v>.tar.gz.sha256.sig`. Production signing: `licensectl release-keygen` / `licensectl release-sign` on the offline machine with a release key separate from the license key (key IDs `rk-YYYY-NN`, a key file that `licensectl issue` refuses, and the other way round). Host verification: `openssl pkeyutl -verify -pubin -inkey <key.pem> -rawin` (OpenSSL 3, present on the three supported systems through `ca-certificates`). Test signing: `tools/releasesign` with a key generated at test time | No new host dependency beyond OpenSSL 3; the same Ed25519 handling as licenses; signing a checksum file avoids reading a 500 MB tarball into memory | A host without OpenSSL 3 cannot install (`[FAIL]` names the package) |
| 21 | §20.1 `cd /path/to/new/alice-1.1.0 && sudo ./alice-update.sh …` runs the new package's own script, which a tampered package controls | The installed copy updates: `cd /opt/alice && sudo ./alice-update.sh /path/to/alice-1.1.0.tar.gz`; it verifies the signature with the public keys installed by the previous release (`/opt/alice/release-keys/`) before extracting, and a successful update installs the new release's scripts and keys (a new release key is trusted only when it arrives in a package signed by an already trusted key; a successful update **replaces** `release-keys/` with the new package's set, so a release can retire a key) | Only an already trusted script can decide whether to trust a package | The documented command differs from §20.1 (owner step 5 works from `/opt/alice`) |
| 22 | §18.3 step 5 pins `POSTGRES_IMAGE=postgres@sha256:…`; a `docker load` of a digest reference does not keep a pullable reference on every engine | The bundle tags its images `alice:<v>` and `alice-postgres:<v>`, records each image ID in `RELEASE`; install and update compare `docker image inspect --format '{{.Id}}'` with it before starting anything; compose sets `pull_policy: never` and the scripts never pull; `.env` holds `COMPOSE_PROJECT_NAME` (default `alice`; `install.sh --project` for side-by-side test installations) and `ALICE_BIND` (`install.sh --bind`, default every address) | An image ID is the content address; air-gapped hosts never pull | none known |
| 23 | §20.1 step 1 "downgrade refused"; U-2 "unless `--allow-downgrade`"; step 2's 60-second banner and "drain" without a maintenance command (R6 cut it) | No downgrade at all ("Going back to an older version is only possible by restoring a backup."); `RELEASE` carries `MIN_UPGRADE_FROM`; drain = `docker compose stop alice` (Alice finishes running jobs within 60 s of SIGTERM, §8.8; `stop_grace_period: 90s`); no in-app "update in progress" banner in v1 | Stricter and simpler; no new subcommand | Users see Alice disappear for a few minutes without notice (the upgrade guide says to announce it) |
| 24 | §20.1 step 9 `selfcheck` "TLS listener answering, background jobs running" | `alice selfcheck` (inside the container): database reachable; schema version equals the binary's latest; the master key opens the stored key check; the audit chain verifies (read-only); the license evaluates; a TLS handshake on `127.0.0.1:8443` presents exactly `keys/tls.crt`; the scheduler heartbeat (`jobs.heartbeat`, written once as soon as the scheduler runs and then every minute by the leader) is under 5 minutes old; `selfcheck` retries that one line every 5 s for up to 90 s, because a restored database carries an old heartbeat and a new process writes its first within seconds | Every item is a fact the binary can check itself | A stalled scheduler is noticed after 5 minutes, not at once |
| 25 | §21 support bundle "version, health, redacted config, last 1000 log lines" | `alicectl support-bundle [--out FILE]` (host): `docker compose ps`, the last 1,000 log lines of each container, `alice support-bundle` JSON (version, redacted configuration, selfcheck results, schema version, row counts per table, license phase, job queue counts), `docker version`, `df -h` of the installation directory, `.env` with values of `*PASSWORD*`/`*SECRET*` names removed; a `tar.gz` with mode 0600; a canary test proves no secret enters it | Spec; logs are already secret-free (leak suites) | Host names and addresses in logs reach support (customer's choice to send it) |
| 26 | SBOM: §18.1 `alice-1.0.0.spdx.json`; §17.1/§25.7/SEC-104 CycloneDX by syft | CycloneDX JSON made by the already pinned Trivy image: `sbom/alice-<v>.cdx.json` (the alice image), `sbom/postgres-<v>.cdx.json`, `sbom/source-<v>.cdx.json` (go.mod and the npm lockfile); no syft | One pinned scanner for scanning and SBOM | A security team that needs SPDX converts it |
| 27 | §21: documents "rendered to PDF", screenshots produced by Playwright | Markdown only in v1 (`docs/` in the tarball); no screenshots; `licenses/THIRD_PARTY_NOTICES.md` generated by `tools/notices` from the Go modules linked into `alice` and `alice-helper` and the npm packages bundled into the web UI | No PDF toolchain can be pinned on the build machine; images go stale | Customers read Markdown files |
| 28 | §26.10 "install on clean Ubuntu 22.04, Debian 12 and Rocky 9 VMs (no internet for the air-gapped variant, checked by blocking outbound traffic)" | On this machine: `TestReleaseInstallMatrix` runs the real `install.sh` from the real tarball inside Ubuntu 22.04, Debian 12 and Rocky 9 containers started with `--network none`, driving the host's engine through its socket under project `alice-rel-<distro>` (no pull is possible from the installer, and compose is told never to pull); real VMs with blocked egress are the owner's runbook (`docs/release-checklist.md`, one command per VM) | Proves the scripts on each distribution's userland and the air-gap property of the scripts; VMs need a hypervisor this machine lacks | Kernel-, systemd- and firewall-specific behaviour of a real host is proven only by the owner's run |
| 29 | F-85 / §20.6 seed set ("a test license", "one rotation in progress", dockerized targets) vs a release image that trusts no test license key | Split: `TestF85FullCycle` (Task 5, integration, `testlicense`) seeds the full §20.6 set through the services (3 users per role with TOTP, 10 targets including a real OpenSSH container, 50 certificates with keys, 20 SSH keys, a rotation in `overlap`, 500 audit rows, a test license, the SMTP password) and proves every §20.6 step-6 check; `TestReleaseF85Drill` (Task 13) does the same cycle with the release tarball and the release image through the public API (wizard, users, an SSH target container, uploaded certificates, the SMTP password, the evaluation license) | Each fact is proven where it can be; the release path is proven end to end | The full data set is not restored through the release image itself (the code path is the same binary) |
| 30 | §20.6 step 8 "install N-1, update to N; a deliberately broken migration in N" with no previous release | The harness builds three releases from the same commit (`1.0.0-rc.1`, `1.0.0-rc.2`, and `1.0.0-rc.3` whose image carries an extra test-only migration that fails, plus `1.0.0-rc.4` whose extra migration sleeps so the harness can kill it), signed with a test key; the broken images are built from a temporary copy of the tree and never tagged for release. The same script (`deploy/dev/build-broken-release.sh`, `make release-broken`) builds the owner's broken-update package for the VM test of owner step 5 (test-signed for a test-signed VM, or staged unsigned for the offline signing ceremony) | Proves F-68 for both failure kinds on real containers | The first real N-1 → N update is the owner's (1.0.0 → 1.0.1, release checklist) |
| 31 | SEC-073 "forwarding to syslog (RFC 5424 over TLS TCP; UDP only when explicitly chosen) and JSON webhook … from a local outbox"; F-96 "backlog metric shown" | `internal/audit/forward`: syslog only, RFC 5424 with octet counting over TLS (system roots plus an optional CA bundle) by default, plain TCP or UDP only when chosen; the outbox is the audit log itself read from a cursor (`audit.forwarding.state`), in sequence order, each message carrying `seq`, `hash` and `prev_hash`; the daily checkpoint is forwarded as its own message (F-92); backlog = head − cursor, shown in Settings and on the dashboard; the local write never waits for it; delivery is **at most once** (a returned TCP/TLS write is only in the kernel buffer, so a connection reset can lose messages) and each message's `seq`/`prev_hash` lets the collector see a gap | No second copy of the log to keep consistent; chain order for free | A JSON-webhook-only SIEM needs a syslog collector (webhook: v1.x) |
| 32 | Keyed audit chain and the app-writable `jobs.audit_verify` (Phase 3 review, R42 row 27, carried to Phase 8) | Re-deferred to v2: SEC-071 defines the unkeyed chain; the external anchors the spec asks for now exist (syslog forwarding with each hash, the head hash in every backup manifest, the dashboard head hash) | A keyed chain changes the format of every existing row and every verifier | Whoever holds `alice_app` can still append rows that verify and suppress the `audit.broken` e-mail; forwarding shows the divergence outside Alice |
| 33 | §22.7 stages 5 (nightly) and 6 (release) on GitHub Actions; no remote exists | `.github/workflows/nightly.yml` and `release.yml` (actions pinned by SHA, checked by actionlint) and the local equivalents `make nightly` and `make release-gates`; the workflows are first run by the owner after creating a remote | Same `make` targets locally and in CI (§22.7) | Until then nightly runs only when someone types `make nightly` |
| 34 | §25.7 ZAP baseline + API scan (nightly) and full active scan (release); nuclei; testssl grade A | `make zap-baseline` (passive scan and API scan, unauthenticated and as Admin, Operator and Auditor with a scripted TOTP login, against the e2e stack) and `make testssl` (against the e2e stack's published port; grade parsed from the JSON) run here; `make zap-full` (active scan) is the same harness against a disposable stack, run by the owner or CI before a release; `.zap/rules.tsv` ignores carry a reason and an expiry date checked by `tools/zaprules`; nuclei is re-deferred (its templates are downloaded at run time) | The passive gates are cheap and deterministic; an active scan takes hours | A nuclei-only finding is missed until v1.x |
| 35 | §25.6 release fuzzing (30 minutes per target) and nightly (10 minutes) | `make fuzz-nightly` (10 minutes per target) and `make fuzz-release` (30 minutes per target) list every target, including the new `FuzzBackupHeader`, `FuzzBackupStream` and `FuzzOpenAPIInputs`; the release run is the owner's/CI's (about 7 hours); this phase runs each new target for 5 minutes | A seven-hour run does not fit an implementation session | A crash that needs more than 5 minutes to find in a new target is found by the first release run |
| 36 | §22.3 "Firefox and WebKit nightly"; §26.10 "full Playwright on three browsers" | `web/playwright.config.ts` gains `firefox` and `webkit` projects used by `make e2e-browsers` (all specs, EN and TR); `make e2e` stays Chromium (the PR set); a browser that cannot start on this host is recorded `NOT RUN (CI)` | Spec | none known |
| 37 | §26.10 "the whole matrices in 23, 24 and 25 green" with no list of which test proves which ID | `test/matrix/traceability.json` maps every ID of §23–§25 (L-, F-, S-, R-, A-, O-, X-) to the tests that prove it (`package:TestName`), or to an owner step, or to a ruling that defers it; `tools/matrixcheck` (in `make lint` from Task 19 on; until then `make matrix-check` counts named tests that do not exist yet as `pending`, and only `-strict` fails on them) refuses an ID missing from the file, an unknown ID, or (with `-strict`) a named test that does not exist, and regenerates `docs/security/traceability.md` | "Green" becomes checkable | Mapping a test to an ID is a human judgement (reviewed in Task 14) |
| 38 | Supply-chain carries: lockfile secret scanning (audit remediation R-5), `osv-scanner` (R39), mutation testing | `tools/lockcheck` (in `make lint`): every value of `web/package-lock.json` and every line of `go.sum` matches its allowed shape (names, versions, `https://registry.npmjs.org/` URLs, `sha512-` integrity, licences, `h1:` hashes), so a secret cannot hide there; `osv-scanner` v2.6.0 over `go.mod` and the npm lockfile in `make vuln`; gremlins v0.6.0 as `make mutation` (advisory, nightly, score recorded) | The shape check decides R-5 without copying gitleaks' rules | none known |
| 39 | R38 item 16: "the real-systemd job moves to Phase 8"; §22.3 "privileged runner" | `make test-systemd` runs `TestRealSystemdNginx` (`-tags systemd`): a privileged Ubuntu 22.04 container with systemd as PID 1, the distribution's Nginx under real `systemctl`, the release-built helper installed by the setup script, then discovery, a deployment, a failed `nginx -t` and the rollback, compared with the shim's results; if this engine refuses a privileged container with systemd, the result is `NOT RUN (CI)` | Spec | none known |
| 40 | Error areas | New `ALC-BAK-0001..0004`, `ALC-TLS-0001..0005`, `ALC-AUD-0002..0004`, `ALC-SET-0010` | §9.3 | — |
| 41 | SEC-048/B-1 describe the hybrid scheme only (ephemeral X25519 to the backup public key, private key wrapped by the passphrase); B-3 "malicious backup restored". With the recipient key and the wrapped key in every clear header, anyone who has seen one file can build another file that the real passphrase opens (a chosen `master.key`, administrators, a self-consistent audit chain); the restore's checks are keyed by the master key the file itself carries (pre-flight S-2) | Backups are **origin-authenticated** (HPKE Auth-mode style), container format **2** from the start (nothing is released, so no format 1 exists to keep): the recovery-passphrase step also creates an installation **sender** key pair S (X25519); its private half is a master-key envelope in `setting_secrets` (key `backup.sender`); the wrapped key is `WrappedBackupKey{Version: 2, …, SenderPublicKey}` with the wrap AAD `"alice/backup-key/v2" ‖ public_key ‖ sender_public_key`, so the passphrase authenticates S_pub; file key = HKDF-SHA256(X25519(e, R) ‖ X25519(S, R), salt = e ‖ R ‖ S_pub, info `"alice/backup/v2"`); a reader takes S_pub only from a wrapped key it unwrapped with the passphrase (`OpenWithKey` takes the trusted sender key as an argument), and `Unwrap` also checks that the private key's public half equals `public_key`. **Restore on a fresh server needs only the passphrase**: it unwraps R from the file's own wrapped key (which authenticates S_pub), derives the file key with R and S_pub, and the restored database and `master.key` bring `backup.key` and `backup.sender` back, so backups made after the move open with the same passphrase. `backup.Create` refuses a `backup.key` of version 1, or a missing or mismatched sender key, with `ErrNotConfigured` (development installations re-run the wizard) | Forging now needs S's private half or the passphrase; key commitment is not an issue with one recipient and an HKDF key | Residual (in `SECURITY-REPORT.md`): a compromised `alice` process, or anyone holding the database and `master.key`, holds S and can still forge a backup that the passphrase opens |
| 42 | B-3 "roll back … license" and L-55: a restore replaces both copies of the license time record (`time.hwm`, `state/hwm.dat`) with the backup's older, validly sealed ones | Before the swap the restore reads the live time record (live master key, both stores, highest valid `Seq`); when its `At` is newer than the backup's, it re-seals `max(At)` with `Seq = max(Seq)+1` under the restored master key into the staging database and the staged `hwm.dat`; a fresh host (no live record) keeps the backup's record | Restoring an old backup must not reset clock-rollback detection | A host whose clock once ran ahead keeps that later time after a restore |
| 43 | SEC-107 "the fingerprint is published" while §18.3 verifies the package with keys shipped inside it (trust on first use); nothing marks a test-signed package | `install.sh` prints the release-key fingerprint before any change and asks `Does this fingerprint match the one your vendor published? Type yes to continue: ` (`--non-interactive` requires `--fingerprint <64 hex>`, which must match); the install guide first verifies the outer `.sha256.sig` with the vendor-published key. Test signing: key IDs `rk-test-NN`, `RELEASE` carries `TEST_SIGNED=1` and both scripts print `[WARN] This package is signed with a TEST key. Never install it for production.`; `make release-test` refuses a version without `-rc.N`; `tools/releasebuild stage` without `-test` accepts only `rk-YYYY-NN` keys equal to the set in `deploy/release/keys/`; release and license public keys must be disjoint (`make release-keycheck`) | The published fingerprint is SEC-107's control and has to be compared, not only shown | One more prompt at install; unattended installs carry the fingerprint |
| 44 | §20.1 makes the backup (step 3) while Alice runs and drains later (step 6); §20.3's `alicectl restore` stops Alice before anything is checked | The update stops `alice` first, then backs up through `alice-admin`, deep-verifies, copies the rollback state, loads the images and migrates; a failure before the migration starts the installed version again (`The update was stopped before any change; Alice is running version <installed> again.`, exit 1). `alicectl restore` deep-verifies with the passphrase while `alice` runs and stops it only then (row 9) | A rollback must not silently drop audit rows written during the update; a wrong passphrase must not cause downtime | The update's outage begins before the backup (a few minutes longer) |
| 45 | B-3 "the rollback must be evident"; the safety backup exists only when a backup key exists | `system.restored` details add `previous_audit_seq` and `previous_audit_hash` (the live head read before the swap; absent on an empty host) and `safety_backup` (name or `none`); a live installation with data but no backup key refuses the restore unless `--no-safety-backup` is given, which the event records (`no_safety_backup`) | The replaced history is named in the chain that replaces it | One more flag for an operator restoring over an installation without a passphrase |
| 46 | §20.2 never prunes manual backups; a restore needs two copies of the database; both share the database's disk | `Create` refuses (`ErrWrite`, code `disk_full`, before opening a file) when free space in the backups directory is under 2 × the newest backup + 1 GiB, and the Backups tab shows the free space; `alicectl restore` passes the free space of `data/postgres` (`--free-bytes`), and the restore refuses under 2 × the live database size + 1 GiB (`Not enough free disk space for a restore: <n> GB free, <m> GB needed.`); any load error, PostgreSQL's `disk_full` included, drops the staging database and directories before returning | A full disk stops PostgreSQL, which is worse than a refused backup | A nearly full host cannot back up by hand until space is freed |
| 47 | `GET /setup/status` is public; the new fields would tell anyone, forever, whether the temporary certificate is in use and mail is missing | After setup completion the anonymous answer is `{completed, default_locale}` only; `https_chosen`, `mail_chosen` and `next_step` go to callers while setup is open or to signed-in sessions; `keep-temporary` and `mail/skip` after completion return the status and change nothing (no audit row) | No anonymous reconnaissance | none known |
| 48 | SEC-060 "no SQL string building" | Two exceptions, each in one function with a `//nolint:gosec // G202:` reason and identifiers quoted by `pgx.Identifier{…}.Sanitize()`: the dump's `COPY` statements (catalog identifiers) and the restore's `CREATE DATABASE`, `ALTER DATABASE … RENAME TO`, `DROP DATABASE` (names from `current_database()` plus the fixed suffixes `_restore`, `_previous_<ts>`) | PostgreSQL cannot bind identifiers in DDL | A quoting mistake there would be an injection; both functions have direct tests |
| 49 | §24.5's expected messages for F-80..F-84 differ in wording from C7 | C7's exact sentences are the product's messages; the matrix rows are proven by behaviour (nothing changed, the right refusal) and C7's text | One set of sentences in the plan's style | A reader comparing §24.5 word for word finds other wording |
| 50 | §21 operator guide "rotating the recovery passphrase"; SEC-042 master-key rotation | Neither can be changed in v1 (carry 18); the operator guide says so and what an exposed passphrase means | Not in R6 or §26.10; a rotation re-wraps R (and S) and, for the master key, re-seals every envelope | An exposed passphrase plus a copy of a backup opens that backup; old files stay readable with the old passphrase |
| 51 | §18.1 package contents (`SECURITY-REPORT.md`, the signed checklist) do not exist when the harness first builds packages (Tasks 12–13 run before Tasks 17–18) | `make release-test` stages with `-allow-draft`: a missing `SECURITY-REPORT.md` becomes the placeholder line `SECURITY-REPORT.md: not part of this test package`; `licenses/LICENSE` comes from `deploy/release/LICENSE.txt` (the vendor replaces its text before release); `RELEASE-CHECKLIST-SIGNED.txt` comes from `bin/release-gates.log` or says `No gate was recorded for this package.`; `make release` (production) refuses a missing report or an empty gates log | The real scripts are exercised long before the documents are final | A test package's documents are placeholders (never shipped: test-signed) |
| 52 | §17.1/§26.10 "reproducible build"; SEC-104 names syft | `make reproducible-check` compares the `alice` and helper binaries only; `SECURITY-REPORT.md` says "the binaries are reproducible", not "the release"; a CI-built stage is only compared with the release machine's build and is never what the offline key signs (row 26 covers the SBOM tool) | Image layers carry build metadata | A customer cannot rebuild the image byte for byte |
| 53 | SEC-086 "secrets zeroed after use" | `clear()` on every `[]byte` the code owns (passphrase, file key, ECDH secrets, unwrapped key bytes); Go cannot reliably zero `*ecdh.PrivateKey` internals, `bufio` copies or memory the runtime moved; `SECURITY-REPORT.md` says "best effort" | The language gives no stronger guarantee | A memory dump of a running process may still hold key material |

## Carries and deferred items

| # | Carry | Decision | Where |
|---|---|---|---|
| 1 | Superuser migration URL in the `alice` container (P1-01, Medium) | **Included** (R43 row 7) | Task 3 |
| 2 | PostgreSQL with a writable root filesystem, default capabilities, passwords in environment variables (Phase 1 known limitation) | **Included** in the production compose; the development compose keeps it (documented) | Task 3 |
| 3 | Audit checkpoint in the same database (P1-02, Medium) | **Eased**: the head hash is forwarded to syslog and stored in every backup manifest; stays a known limitation | Tasks 4, 7 |
| 4 | Server-side passphrase strength (P1-08) | **Included** (R43 row 17) | Task 8 |
| 5 | Wizard "Back" and server-side resume (R35 addendum); SMTP as a wizard step (Phase 7 carry 21); HTTPS step (Phase 1 limitation) | **Included** (R43 rows 15–16) | Tasks 8, 10 |
| 6 | The temporary certificate renewed only at container start (Phase 1) | **Included** (`tls.renew`, R43 row 14) | Tasks 8, 6 |
| 7 | Setup code printed by `install.sh` (Phase 1, §26.1.10) | **Included** (R43 row 19) | Task 11 |
| 8 | Helper binaries in the release bundle (R37 item 2, Phase 3 "Packaging") | **Included** (`helper/` in the tarball) | Task 12 |
| 9 | Real-systemd Nginx job (R38 item 16; Phase 4 review) | **Included** (R43 row 39) | Task 15 |
| 10 | Nightly pipeline (Phase 6 carry 14) | **Included** as workflow files and `make nightly` (R43 row 33); first run is the owner's | Task 15 |
| 11 | `osv-scanner` (R39), lockfile secret scanning (audit remediation R-5), mutation testing | **Included** (R43 row 38) | Tasks 14, 15 |
| 12 | Syslog/SIEM forwarding (SEC-073; Phase 7 carry 17) | **Included** (R43 row 31) | Task 7 |
| 13 | Keyed audit chain, app-writable `jobs.audit_verify` (Phase 7 carry 17) | **Re-deferred to v2** (R43 row 32) | — |
| 14 | `FuzzOpenAPIInputs` (§25.6, never built) | **Included** | Task 14 |
| 15 | Helper scans all accounts more than once per key change (Phase 6 carry 4) | **Re-deferred to v1.x**: performance only (about four scans per rotated place, inside the 60 s budget at 200 accounts); a fix changes the helper protocol, which every customer server would have to follow, and this plan changes no helper | — |
| 16 | Certificate (TLS) private-key download (Phase 6 carry 11, Phase 7 carry 1) | **Re-deferred to v1.x**: no §26.10 deliverable; needs the PKCS #8/PFX format decision and its own S-09 suite | — |
| 17 | Microsoft Graph lookup for the Entra overage (R42 row 20) | **Re-deferred to v1.x** (air-gapped customers; the action text explains the application-groups option) | — |
| 18 | Master-key rotation (`alice keys rotate-master`, SEC-042; Phase 3 review) and recovery-passphrase rotation (§21 operator guide) | **Re-deferred to v1.x**: neither is in R6's subcommand list or §26.10; the operator guide states that neither can be changed in v1 and what an exposed passphrase means (cost: an exposed passphrase plus a copy of a backup file opens that backup; old files stay readable with the old passphrase forever) | — |
| 19 | R-04 statistical timing test (P1-03) | **Re-deferred to v1.x** and listed `deferred` in the traceability file: a 200-sample timing test is flaky on shared runners | Task 14 |
| 20 | JSON webhook forwarding (SEC-073), nuclei (§25.7), the "update in progress" banner (§20.1 step 2), PDF documents and screenshots (§21) | **Re-deferred to v1.x** (R43 rows 23, 27, 31, 34) | — |
| 21 | Phase 7 parked items (final review 2–27; the SSO, alerts, reports, web and test-gap lists), Phase 6 parked items (F1–F4, L1–L13, N2, N15–N17, I-5, D22–D28, FB-4, FB-7, P6-28, property schedules, web minors), Phase 5 parked items, the Nginx helper items, uncoalesced refusal rows, recovery codes lost with the completing answer, e2e hooks for the route error page / `unverified` banner / locale fallback, `facts.nginx.scanned_at`, a `users.timezone` UI, SSH limits and `nginx.backup_retention_days` as settings, the Phase 5 settings items | **Re-deferred, unassigned** (listed in `SECURITY-REPORT.md` "Known issues" where a customer could notice them) — except where `tools/matrixcheck` shows that one of them is the only gap of a spec ID, in which case Task 14 records it there | Tasks 14, 18 |
| 22 | Owner items: a git remote and the first workflow run, the production license key (`make release-keycheck`), the walkthroughs of Phases 1–7 and the remediation, the real-Azure suite, the Turkish tone review, the peer crypto sign-off, a clean-machine `make ci` | **Owner only**; Phase 8 adds the production release key, the offline signing ceremony, the VM installs, the active ZAP scan, the release fuzz run, an external penetration test, the first-run test by a newcomer (§21), the repetition of every phase's owner steps on the release candidate, and the signatures of `SECURITY-REPORT.md` and the release checklist | Tasks 18, 19 |

## Spec coverage map (§26.10) and where each item can be proven

Class **A**: built and verified on this machine (Docker, containers). Class **B**: built here (script, target, workflow or runbook) but run and signed by the owner or a CI runner; its result table stays empty until then.

| §26.10 item | Class | Task(s) | Proof |
|---|---|---|---|
| `install.sh` and the tarball with bundled images (air-gapped install) | A (containers, `--network none`) + B (real VMs, blocked egress) | 11, 12, 13 | `TestPreflightMessages`, `TestReleaseInstallMatrix`; owner table "VM installs" |
| Wizard steps complete (HTTPS certificate, SMTP, license, first target) | A | 8, 9, 10, 16 | `TestInstallHotReloads`, `TestWizardPositionIsDerived`, `TestWizardHTTPSAndMailRoutes`, `SetupPage.test.tsx`, `web/e2e/phase8.spec.ts` |
| `alice-update.sh` with automatic backup, migration, health check and automatic rollback | A (rc versions) + B (1.0.0 → 1.0.1 on a VM) | 11, 13 | `TestUpdate*` (stubs), `TestReleaseUpdateAndRollback` |
| `alicectl` subcommands and `install.sh --restore-mode` / `--uninstall` | A | 6, 11, 13 | `TestCLI*`, `TestReleaseF85Drill`, `TestReleaseUninstallKeepsData` |
| Daily backups, retention 14, hybrid X25519 encryption (R4) | A | 1, 2, 4, 6 | `TestKnownAnswer`, `TestDueAcrossDaylightSaving`, `TestF88Retention`, `TestScheduledBackupRunsOncePerDay` |
| Signed release tarball | A (test key) + B (production release key, offline ceremony) | 12, 13 | `TestOpenSSLVerifiesReleaseSignatures`, `TestReleaseRefusesTamperedAndDowngrade`; `make release-keycheck` (fails until the key exists) |
| Documentation set (install, admin, user, troubleshooting, API, security) | A (+ B: the newcomer test of §21) | 17 | `tools/docscheck` in `make lint` |
| `SECURITY-REPORT.md` | A (draft with evidence) + B (sign-off) | 18, 19 | review |
| Release checklist | A (every item mapped to a command or owner row) + B (ticking and signing) | 18, 19 | `docs/release-checklist.md` |
| SBOM and signatures | A | 12 | `TestStageLayout`, `TestPackIsDeterministic`, `TestOpenSSLVerifiesReleaseSignatures`, `make release-test` |
| Tests: install on three distributions, air-gapped | A + B | 13 | as above |
| Update from the previous release incl. a forced migration failure (F-68) | A + B | 13 | `TestReleaseUpdateAndRollback/failing-migration`, `/killed-migration` |
| Backup, wipe, restore, verify (F-85) and F-80..F-88 | A | 1, 4, 5, 13 | `TestF80…`–`TestF88…`, `TestF85FullCycle`, `TestReleaseF85Drill` |
| The whole matrices of §23, §24, §25 green | A (mapping + every automated test in `make ci`/`make release-gates`) + B (IDs whose proof is an owner step) | 14, 19 | `make matrix-check`, `docs/security/traceability.md` |
| ZAP baseline and full active scan without Medium/High | A (baseline + API) + B (active) | 15 | `make zap-baseline`; `make zap-full` |
| Full Playwright on three browsers in EN and TR | A (Chromium, Firefox; WebKit if it starts here) + B (otherwise) | 15, 16 | `make e2e-browsers` |
| `testssl.sh` A-grade | A (e2e stack) + B (the customer-like host with a real certificate) | 15 | `make testssl` |
| Release binary has the production public key and no test tags | A (no test tags: `release-symcheck`, `image-check`) + B (production keys) | 12 | `make release-symcheck`, `make release-keycheck` |
| Reproducible build check | A | 12 | `make reproducible-check` |
| Owner steps 1–6 | B | 19 | owner table in `docs/security/reviews/phase-8.md` |
| Exit: checklist ticked; no open High/Critical; owner steps of all phases repeated on the release candidate; known issues and residual risks in `SECURITY-REPORT.md`; vendor sign-off | A (no open High in the review; report written) + B (the rest) | 18, 19 | review, tables |

### Owner and CI items (class B) at a glance

1. Install the release candidate on clean Ubuntu 22.04, Debian 12 and Rocky 9 (SELinux enforcing) VMs, once with outbound traffic blocked (`docs/release-checklist.md` § "VM installs": one command per VM, then `sudo /opt/alice/alicectl selfcheck`); on the first VM confirm that the image IDs in `RELEASE` survive `docker load` on a fresh engine.
2. Create the production release key and the production license key on the offline machine (`licensectl release-keygen`, `licensectl keygen`), commit the public halves (`deploy/release/keys/`, `internal/license/keys/production.json`) so `make release-keycheck` passes, publish the release key's SHA-256 fingerprint where customers can compare it (R43 row 43), and sign the release (`licensectl release-sign`, §17.5 ceremony).
3. Run `make zap-full` against a disposable stack, `make fuzz-release` (about 7 hours), `make e2e-browsers` where WebKit runs, `make testssl TESTSSL_TARGET=<host>:443 TESTSSL_CA=<ca file>` against the release candidate on a real host with the customer-like certificate.
4. Create a git remote and let `ci.yml`, `nightly.yml` and `release.yml` run once.
5. Update test 1.0.0 → 1.0.1 on a VM (owner step 5) with the real packages, then the broken-update package built by `make release-broken` and signed in the ceremony (R43 row 30).
6. External penetration test (§17.3 item 13), the newcomer test of the first-run guide (§21), the Turkish tone review, the peer crypto review of the backup format, the repetition of every phase's owner steps on the release candidate, the signatures of `SECURITY-REPORT.md` and the release checklist.

---

## File Structure

```
internal/archtest/arch_test.go             Phase 8 rules and TestAllowed cases (Task 1)
internal/secrets/backupkey.go              WrappedBackupKey v2 with SenderPublicKey, NewBackupKey returning the sender key (Task 1)
internal/setup/passphrase.go               stores the sender key as backup.sender (Task 1); refuses "fair" (Task 8)
internal/backup/format/                    format.go (Magic, Version, ChunkSize, Header, Meta, NewWriter, Writer, ReadHeader,
                                           Open, OpenWithKey, Reader, Err*), bounds.go; tests, KAT vectors in testdata/,
                                           FuzzBackupHeader, FuzzBackupStream; testdata/kat-v2.json (Task 1)
internal/platform/db/db.go                 MigrateTo, SchemaVersion, LatestVersion (Task 3)
internal/backup/dump/                      frames.go (Encoder, Decoder, Frame kinds), dump.go (Dump, Tables), load.go (Load,
                                           Sequences); tests (Task 2)
deploy/release/docker-compose.yml          production compose (postgres, migrate, alice, alice-admin) (Task 3)
deploy/release/env.template                .env template (Task 3)
deploy/release/postgres/initdb/10-alice-roles.sh   roles alice_owner, alice_app, database alice (Task 3)
internal/platform/config/config.go         *_PASSWORD_FILE (LoadWith), ALICE_MIGRATE, ALICE_BACKUP_DIR, ALICE_TZ (Task 3)
cmd/alice/main.go                          serve with ALICE_MIGRATE=external; time/tzdata (Task 3)
cmd/alice/releasecompose_test.go           compose and role tests (Task 3)
migrations/nonsuperuser_integration_test.go  TestMigrationsRunAsNonSuperuserOwner (Task 3)
deploy/docker-compose.yml                  backups volume for the development and e2e stacks (Task 3)
deploy/Dockerfile, deploy/dev/check-image.sh   /opt/alice/backups owned by 10001, mode 0700 (Task 3)
tools/pincheck/                            ${ALICE_IMAGE}/${POSTGRES_IMAGE} in the release compose only (Task 3); digest-pinned
                                           $(<NAME>_IMAGE) Makefile operands (Task 12); *_IMAGE variables and test Dockerfiles (Task 14)
internal/backup/                           service.go (Service, Config, Create, List, Verify, VerifyDeep, Prune), names.go,
                                           schedule.go (Schedule, Due, LastScheduled), state.go (State, alarm), task.go
                                           (RunScheduled), manifest.go, templates.go (Task 4); restore.go, swap.go, staging.go
                                           (Task 5)
locales/common/{en,tr}.json                email.backup.failed, email.backup.alarm (Task 4); errors (Task 9)
cmd/alice/                                 backup_cli.go, restore_cli.go, selfcheck.go, supportbundle.go, passphrase.go,
                                           services.go, wiring.go, main.go usage (Task 6)
internal/jobs/types.go                     BackupSchedule, TLSRenew, AuditForward, JobsHeartbeat (Task 6)
internal/audit/forward/                    forward.go (Forwarder, Settings, State, Run, Test), syslog.go (RFC 5424
                                           framing); tests (Task 7)
internal/testutil/fakesyslog/              TLS/TCP/UDP syslog receiver (Task 7)
internal/platform/tlscert/                 store.go (Store, GetCertificate, Install, Info, Renew), upload.go (ParseUpload) (Task 8)
internal/setup/                            https.go, mail.go, position.go, strength.go, testdata/strength.json (Task 8)
web/src/pages/setup/strength.test.ts       reads testdata/strength.json (Task 8)
internal/rbac/rbac.go                      backup.manage (Task 9)
internal/api/                              backup_handlers.go, https_handlers.go, forwarding_handlers.go, setup additions,
                                           dashboard additions, phase8_dto.go, errors.go, server.go (Task 9)
api/openapi.yaml, docs/authz-matrix.md     new operations (Task 9)
web/src/                                   pages/setup/{HttpsStep,MailStep}.tsx, SetupPage.tsx (Back, resume),
                                           components/settings/{BackupsTab,HttpsTab,ForwardingTab}.tsx,
                                           components/dashboard/{BackupCard,SetupChecklist}.tsx, BackupBanner.tsx (Task 10)
deploy/release/                            install.sh, alice-update.sh, alicectl, lib/alice-lib.sh; scripts_test.go,
                                           testdata/stubs/ (Task 11)
deploy/release/keys/README.md              where the production release public keys go (Task 12)
deploy/release/LICENSE.txt                 placeholder licence text for test packages (Task 12; the vendor replaces it)
deploy/dev/build-broken-release.sh         builds a package with a failing or sleeping extra migration (Task 12; Task 13, owner step 5)
cmd/licensectl/                            release-keygen, release-sign, release-verify (Task 12)
internal/license/issuer/                   key purpose (license | release) (Task 12)
tools/releasebuild/, tools/releasesign/, tools/notices/   stage and pack; test signer; third-party notices (Task 12)
deploy/dev/reproducible-check.sh           (Task 12)
Makefile                                   release, release-pack, release-test, release-broken, sbom, notices, reproducible-check,
                                           release-keycheck (Task 12); shellcheck, lockcheck, matrix-check, actionlint, docs-check, osv,
                                           fuzz targets (Task 14); test-release (Task 13); zap-*, testssl, test-systemd, e2e-browsers,
                                           mutation, nightly, release-gates (Task 15); matrix-check joins lint (Task 19)
test/images/install/                       {ubuntu22,debian12,rocky9}.Dockerfile (Task 13)
test/release/                              harness (build tag release) (Task 13)
tools/lockcheck/, tools/matrixcheck/, tools/docscheck/ (with required.txt), tools/pincheck (extended), osv-scanner.toml   (Task 14)
test/matrix/traceability.json, docs/security/traceability.md   (Task 14)
internal/api/fuzz_openapi_integration_test.go   FuzzOpenAPIInputs (Task 14)
.zap/rules.tsv, tools/zaprules/, tools/zapsession/, deploy/dev/zap-stack.sh, test/images/systemd/ubuntu22.Dockerfile,
internal/providers/nginx/systemd_test.go, .github/workflows/{nightly,release}.yml,
web/playwright.config.ts                   (Task 15)
web/e2e/phase8.spec.ts, web/e2e/helpers.ts (Task 16)
docs/                                      install-guide.md, backup-restore.md, upgrade.md, security-overview.md, api.md,
                                           README.md, operator-guide.md, admin-guide.md, first-run.md, troubleshooting.md (Task 17)
SECURITY-REPORT.md, docs/release-checklist.md   (Task 18)
docs/security/reviews/phase-8.md, docs/superpowers/rulings/phase-8.md, 00-decisions.md (R43), CHANGELOG.md,
coverage-floors.json                       (Task 19)
```

Task order is bottom-up: the backup format and dump (1–2), the production deployment shape (3), the backup service and restore (4–5), CLI and wiring (6), forwarding (7), TLS store and wizard backend (8), HTTP (9), web (10), host scripts (11), release build (12), release harness (13), static gates (14), dynamic gates (15), end-to-end (16), documentation (17), security report and checklist (18), close (19). Each task leaves the repository green (`make lint`, `make test`, the integration packages it touches, `make web-test` and `make i18n-check` where it touches the web).

### Task index

1. `internal/backup/format`: the encrypted backup container (R4, SEC-048); known-answer, tamper, truncation and bound tests; `FuzzBackupHeader`, `FuzzBackupStream`; Phase 8 archtest rules; backup key v2 with the installation sender key (R43 row 41) — **A**
2. `internal/backup/dump`: framed payload and the consistent logical dump and load — **A**
3. Production deployment: release compose, non-superuser owner, one-shot migrations, password files, `ALICE_MIGRATE=external` (P1-01); `db.MigrateTo`, `SchemaVersion`, `LatestVersion` — **A**
4. `internal/backup` part 1: create, list, verify, retention, the daily schedule, failure e-mail and 48-hour alarm (F-70, F-86..F-88) — **A**
5. `internal/backup` part 2: restore into a fresh database, verify, swap; `--db-only`; F-80..F-85, F-97 — **A**
6. Operator CLI and wiring: `alice backup|restore|selfcheck|support-bundle`, `migrate --to-latest`, the periodic tasks and the heartbeat — **A**
7. `internal/audit/forward`: syslog forwarding in chain order (SEC-073, F-92, F-96); `fakesyslog` — **A**
8. `tlscert.Store` (upload, hot reload, renewal) and the wizard backend (HTTPS and mail steps, position, server-side strength) — **A**
9. API: backups, backup settings, download, HTTPS, forwarding, wizard routes, dashboard backup age and checklist; codes, OpenAPI, authz — **A**
10. Web: Settings → Backups, HTTPS, Audit forwarding; wizard HTTPS and mail steps, Back and resume; dashboard backup card, checklist and banner — **A**
11. Host scripts: `install.sh`, `alice-update.sh`, `alicectl`, `lib/alice-lib.sh`, with stub-command tests — **A**
12. Release build: `make release`, bundle layout, SBOM, notices, release signing (`licensectl release-*`, `tools/releasesign`), test-signed packages, `make release-broken`, `reproducible-check`, `release-keycheck` — **A** (+ **B**: production release key, the ceremony-signed broken package)
13. Release harness: install matrix in three distributions without network, F-85 drill, restore negatives, update and rollback (F-68), tampered and downgrade, uninstall (`make test-release`; **no Playwright**) — **A** (+ **B**: VMs)
14. Static gates: `osv-scanner`, `tools/lockcheck`, ShellCheck, actionlint, `tools/docscheck`, `FuzzOpenAPIInputs`, fuzz targets, the matrix traceability (`tools/matrixcheck`) — **A**
15. Dynamic gates and pipelines: ZAP baseline/API (A) and full (B), testssl (A/B), real-systemd job (A), three-browser Playwright (A/B), mutation (A), `nightly.yml`/`release.yml` (B), `make nightly`, `make release-gates` (**Docker alone**) — mixed
16. End-to-end: Phase 8 journeys in EN and TR, accessibility (**Docker alone**) — **A**
17. Documentation set and `tools/docscheck` content — **A** (+ **B**: newcomer test)
18. `SECURITY-REPORT.md` and the release checklist — **A** draft (+ **B**: sign-off)
19. Coverage floors, R43, security review, rulings, CHANGELOG, `make ci`, `make release-gates` (**Docker alone**) — **A** (+ **B** tables)

**Schedule (at most three agents; ownership):**

| Wave | Agent A | Agent B | Agent C | Docker |
|---|---|---|---|---|
| 1 | Task 1 (`internal/backup/format`, `internal/archtest`, `internal/secrets/backupkey*.go`, `internal/setup/passphrase.go` and `setup_integration_test.go`) | Task 3 (`deploy/release/docker-compose.yml`, `env.template`, `postgres/initdb`, `roles_integration_test.go`, `deploy/docker-compose.yml`, `deploy/Dockerfile`, `deploy/dev/check-image.sh`, `tools/pincheck`, `internal/platform/config`, `internal/platform/db`, `cmd/alice/main.go` serve part, `migrations/nonsuperuser_integration_test.go`) | Task 11 (`deploy/release/{install.sh,alice-update.sh,alicectl,lib/,scripts_test.go,testdata/}`; against C3–C5 only) | A, B: testcontainers; C: `docker run --rm` ShellCheck |
| 2 | Task 2 (`internal/backup/dump`) → Task 4 (`internal/backup`, `locales/common`) | Task 7 (`internal/audit/forward`, `internal/testutil/fakesyslog`) → Task 8 (`internal/platform/tlscert`, `internal/setup`, `web/src/pages/setup/strength.test.ts`, the fixtures with a `fair` passphrase) | Task 12 (`Makefile`, `cmd/licensectl`, `internal/license/issuer`, `tools/releasebuild`, `tools/releasesign`, `tools/notices`, `tools/pincheck`, `deploy/release/keys/`, `deploy/release/LICENSE.txt`, `deploy/dev/reproducible-check.sh`, `deploy/dev/build-broken-release.sh`, `docs/vendor/licensing-vendor.md`) | testcontainers; C builds images (`make image`) |
| 3 | Task 5 (`internal/backup` restore files) | Task 10 (`web/src`; msw against C12–C13; `make web-test` waits for Task 9's first commit, M-15) | Task 14 (`Makefile`, `tools/{lockcheck,matrixcheck,docscheck,pincheck}`, `tools/docscheck/required.txt`, `test/matrix`, `docs/security/traceability.md`, `internal/api/fuzz_openapi_integration_test.go`, `osv-scanner.toml`; `make test-backup-cycle` runs last, after Task 5's commit) | testcontainers |
| 4 | Task 6 (`cmd/alice`, `internal/jobs/types.go`, `internal/secrets/masterkey.go`; after Tasks 3, 4, 5, 7, 8) → Task 9 (first commit: `internal/api/errors.go` codes, `locales/common` error entries, `docs/troubleshooting.md` code sections, `rbac.BackupManage`; then `internal/api`, `api/openapi.yaml`, `docs/authz-matrix.md`, the `newAPIDeps` line of `cmd/alice/main.go`) | Task 10 (continued; its `make web-test` after Task 9's first commit) → Task 17 (`docs/*.md`; `docs/troubleshooting.md` only after Task 9's commit, appending below the code sections; its lines in `tools/docscheck/required.txt`) | Task 13 (`Makefile` target `test-release`, `test/release`, `test/images/install`; after Tasks 6, 11, 12) | A: testcontainers; C: release harness — **no Playwright anywhere** |
| 5 | Task 16 (`web/e2e`; after Tasks 9, 10) | Task 18 (`SECURITY-REPORT.md`, `docs/release-checklist.md`, its lines in `tools/docscheck/required.txt`; no `make lint` while Task 16 runs Playwright) | — | **Docker alone** (Playwright) |
| 6 | Task 15 (`Makefile`, `.zap`, `tools/zaprules`, `tools/zapsession`, `deploy/dev/zap-stack.sh`, `test/images/systemd`, `internal/providers/nginx/systemd_test.go`, `web/playwright.config.ts`, `.github/workflows`) | — | — | **Docker alone** |
| 7 | Task 19 | — | — | **Docker alone** |

Web Task 10 compiles against the DTOs of C12 with msw; its tests never need the server. Task 17 documents commands whose exact form is fixed in C3–C5, so it can start before Task 13 runs them; Task 19 re-reads the guides against the final scripts (`make docs-check`).

Recommended execution: subagent-driven, one reviewer per task, an additional security reviewer on Tasks 1, 3, 4, 5, 6, 8, 11, 12 and 13 (the crypto container and the sender key, the roles, the never-lose-data paths, the TLS store, the root-run scripts and the release signing). Tasks 2→4 and 7→8 each keep one implementer.

---
## Cross-task contract

Every task's **Interfaces** block repeats the parts of this contract it consumes or produces. When a task and this section disagree, this section wins and the task is a plan defect to fix at execution time (record it in the task's report).

### C1. Names

- Packages: `alice/internal/backup/format`, `alice/internal/backup/dump`, `alice/internal/backup`, `alice/internal/audit/forward`, `alice/internal/testutil/fakesyslog`.
- Job types (`internal/jobs/types.go`, Task 6), all `license.ClassAlways`, all periodic tasks of the leader: `jobs.BackupSchedule = Register("backup.schedule", …)` every 5 minutes; `jobs.TLSRenew = Register("tls.renew", …)` every 6 hours; `jobs.AuditForward = Register("audit.forward", …)` every 15 seconds; `jobs.JobsHeartbeat = Register("jobs.heartbeat", …)` every minute. All four join `periodicTypes`.
- Settings keys (table `settings`, JSON values): `backup.schedule` (`{"time":"02:30","zone":"UTC","retention":14,"version":1}`), `backup.state` (C8 `State`), `audit.forwarding` (C10 `Settings`), `audit.forwarding.state` (C10 `State`), `setup.https_choice` (`"uploaded"` or `"temporary"`), `setup.mail_choice` (`"configured"` or `"skipped"`), `jobs.heartbeat` (`{"at":"<RFC 3339 UTC>"}`), `backup.restore_id` (`"<32 hex>"`, written by a restore into the staging database only; R43 row 8). `setting_secrets` key `backup.sender`: the installation's backup sender private key (32 bytes, a master-key envelope; R43 row 41; written by `setup.SetRecoveryPassphrase`, read by `backup.Create`). Existing and read: `backup.key` (`secrets.WrappedBackupKey`, **version 2** from Task 1 on), `setup.completed_at`, `setup.license_choice`.
- Permission: `rbac.BackupManage = "backup.manage"` (Administrator, step-up required, API tokens refused).
- Database roles (production): `postgres` (superuser, postgres container only), `alice_owner` (LOGIN CREATEDB NOSUPERUSER, owns database `alice`, `GRANT SET ON PARAMETER session_replication_role`), `alice_app` (LOGIN). Development and `pgtest`: unchanged (owner = superuser `alice`).
- Staging names: for a live database `<db>` (production: `alice`), the staging database `<db>_restore` and the previous one `<db>_previous_<yyyymmddThhmmssZ>`; staging directories `<keys>/.restore-staging/` and `<state>/.restore-staging/` (0700), each holding the restore-ID file `RESTORE_ID` (32 hex, equal to the staging database's `backup.restore_id`) and `previous/` (copies of the live files taken before the swap); there is no `SWAPPED` marker.
- Environment (C3 lists the full set): `ALICE_DATABASE_PASSWORD_FILE`, `ALICE_MIGRATE_DATABASE_PASSWORD_FILE`, `ALICE_MIGRATE` (`on-start` default, or `external`), `ALICE_BACKUP_DIR` (default `/opt/alice/backups`), `ALICE_TZ` (default `UTC`).
- Make targets (new): `release`, `release-pack`, `release-test`, `release-broken`, `sbom`, `notices`, `reproducible-check` (Task 12); `shellcheck`, `lockcheck`, `matrix-check`, `docs-check`, `actionlint`, `fuzz-backup`, `fuzz-api`, `fuzz-nightly`, `fuzz-release` (Task 14); `test-release` (Task 13); `zap-baseline`, `zap-full`, `testssl`, `test-systemd`, `e2e-browsers`, `mutation`, `nightly`, `release-gates` (Task 15). Changed: `lint` (Task 14 adds `shellcheck lockcheck docs-check actionlint` after `pincheck`; Task 19 adds `matrix-check` once every named test exists), `vuln` (Task 14 adds `osv`), `tools` (Task 14 adds the three tools), `release-keycheck` (Task 12 adds the release key).

### C2. Host layout (production; created by `install.sh`)

```
/opt/alice/                         0750 root:root   (--dir changes the path; everything below is relative)
  VERSION, RELEASE                  0644 root        (RELEASE: C5)
  docker-compose.yml                0644 root
  .env                              0640 root        COMPOSE_PROJECT_NAME, ALICE_IMAGE, POSTGRES_IMAGE, ALICE_BIND, ALICE_PORT,
                                                     ALICE_TLS_HOSTS, ALICE_TZ (no secret)
  install.sh, alice-update.sh, alicectl   0755 root
  lib/alice-lib.sh                  0644 root
  release-keys/rk-*.pem             0644 root        release public keys trusted for updates
  helper/                           0755 root        files 0644: alice-helper-linux-amd64, alice-helper-linux-arm64, alice-helper.sha256
  docs/, licenses/, sbom/, CHANGELOG.md   copies from the package
  secrets/                          0700 root
    db_postgres_password            0400 70:70       superuser password (postgres container only)
    db_owner_password               0440 70:10001    alice_owner (postgres initdb, migrate, alice-admin)
    db_app_password                 0440 70:10001    alice_app (postgres initdb, alice, migrate, alice-admin)
  keys/                             0700 10001:10001 master.key (0400), tls.crt (0644), tls.key (0400)
  state/                            0700 10001:10001 hwm.dat
  backups/                          0700 10001:10001 *.alicebak (0600), *.alicebak.sha256 (0600)
  data/postgres/                    0700 70:70
  rollback/<version>/               0700 root        docker-compose.yml, .env, RELEASE, VERSION, scripts, lib, release-keys
  .update-<ts>/                     0700 root        in/ (verified copies of the package files), pkg/ (extraction); removed on
                                                     every exit except exit 3
  install.log, update-<ts>.log, support-bundle-<ts>.tar.gz   0600 root
```

Passwords: 32 bytes from `/dev/urandom`, base64url without padding (43 characters), written with `umask 077` and then `chown`/`chmod` as above (a bind-mounted secret file keeps its host owner and mode; the host directory's mode does not matter inside the container). `master.key`: `head -c 32 /dev/urandom | base64` plus a newline (the format `secrets.LoadOrCreateMasterKey` adopts), 0400, owner 10001, written in normal install mode only (never by `--restore-mode`).

**Container-writable directories (S-8).** After the install's own layout and key step, the host scripts never read, write, `chown` or `chmod` anything inside `keys/`, `state/`, `backups/` or `data/` (code running in a container could have planted symlinks there); every such action runs in a container (`alice-admin`). The only host-side use is `realpath -e` plus a prefix check of a backup path, followed by passing the container path. Directories are created with `install -d -o … -g … -m …` only when the path does not exist, and an existing symlink is refused (`[[ -L ]]`). `--dir` is refused (usage error, exit 2) unless every ancestor is owned by root and not group- or world-writable.

### C3. Containers and configuration (production compose, Task 3)

`deploy/release/docker-compose.yml` (no `name:`; the project name is `COMPOSE_PROJECT_NAME` from `.env`):

| Service | Image | User | Networks | Mounts | Notes |
|---|---|---|---|---|---|
| `postgres` | `${POSTGRES_IMAGE}` | `70:70` | `backend` | `./data/postgres:/var/lib/postgresql/data`, `./lib/initdb:/docker-entrypoint-initdb.d:ro` (the role script, copied there by the installer), secrets `db_postgres_password`, `db_owner_password`, `db_app_password` | `read_only: true`; `tmpfs: [/tmp, /var/run/postgresql]`; `cap_drop: [ALL]`; `no-new-privileges`; `POSTGRES_PASSWORD_FILE=/run/secrets/db_postgres_password`; no `ports`; healthcheck `pg_isready -h 127.0.0.1 -U postgres -d alice`; `command: ["postgres", "-c", "log_error_verbosity=terse", "-c", "password_encryption=scram-sha-256"]` (the image's default `pg_hba` with `scram-sha-256` host rules is kept); `pull_policy: never`; limits 2 CPU, 2 GiB, 512 pids; json-file logs 20m×5 |
| `migrate` | `${ALICE_IMAGE}` | `10001:10001` | `backend` | secrets `db_owner_password`, `db_app_password` | `profiles: ["admin"]` (never started by `up`; the scripts run it with `docker compose run --rm migrate`); `command: ["migrate"]`; `restart: "no"`; `read_only`; `cap_drop: [ALL]`; `no-new-privileges`; `depends_on: postgres (service_healthy)`; env `ALICE_DATABASE_URL=postgres://alice_app@postgres:5432/alice?sslmode=disable`, `ALICE_DATABASE_PASSWORD_FILE=/run/secrets/db_app_password`, `ALICE_MIGRATE_DATABASE_URL=postgres://alice_owner@postgres:5432/alice?sslmode=disable`, `ALICE_MIGRATE_DATABASE_PASSWORD_FILE=/run/secrets/db_owner_password` (if `config.Load` lets `migrate` run without `ALICE_DATABASE_URL`, the app URL and `db_app_password` are dropped from this service; the implementer reads `RequireDatabase` first) |
| `alice` | `${ALICE_IMAGE}` | `10001:10001` | `frontend`, `backend` | `./keys:/opt/alice/keys`, `./state:/opt/alice/state`, `./backups:/opt/alice/backups`, secret `db_app_password` | `ports: ["${ALICE_BIND:-0.0.0.0}:${ALICE_PORT:-443}:8443"]`; `read_only`; `tmpfs: ["/tmp:rw,noexec,nosuid,size=64m"]`; `cap_drop: [ALL]`; `no-new-privileges`; `ulimits: {core: 0}`; `stop_grace_period: 90s`; `restart: unless-stopped`; `depends_on: postgres (service_healthy)` (migrations are run by the scripts before `alice` starts; a stale schema makes `alice` refuse to start with the C3 message); env `ALICE_DATABASE_URL` (app, no password), `ALICE_DATABASE_PASSWORD_FILE`, `ALICE_MIGRATE=external`, `ALICE_TLS_HOSTS`, `ALICE_TZ`, `ALICE_STATE_DIR=/opt/alice/state`, `ALICE_BACKUP_DIR=/opt/alice/backups`; **no** `ALICE_MIGRATE_DATABASE_*`; healthcheck `["CMD","/usr/local/bin/alice","healthcheck"]`; limits 2 CPU, 1 GiB, 512 pids; `pull_policy: never` |
| `alice-admin` | `${ALICE_IMAGE}` | `10001:10001` | `backend` | as `alice` plus secret `db_owner_password` | `profiles: ["admin"]`; `entrypoint: ["/usr/local/bin/alice"]`; `restart: "no"`; `read_only`; `tmpfs /tmp`; `cap_drop: [ALL]`; env as `migrate` plus `ALICE_KEYS_DIR`, `ALICE_STATE_DIR`, `ALICE_BACKUP_DIR`, `ALICE_TZ`; used only through `docker compose run --rm alice-admin <args>` |

Networks: `frontend: {}`, `backend: {internal: true}`. Secrets: `file: ./secrets/<name>`.

Configuration (Task 3, `internal/platform/config`):
- `ALICE_DATABASE_PASSWORD_FILE` / `ALICE_MIGRATE_DATABASE_PASSWORD_FILE`: when set, the file's content without one trailing newline becomes the password of `ALICE_DATABASE_URL` / `ALICE_MIGRATE_DATABASE_URL`; the URL must not already carry a password (error `ALICE_DATABASE_URL already contains a password; remove it or remove ALICE_DATABASE_PASSWORD_FILE`); an unreadable or empty file is an error naming the variable, never the content. The file is read once: `config.Load(getenv)` keeps its signature and calls the new `config.LoadWith(getenv, readFile func(string) ([]byte, error))` with `os.ReadFile`; the password-file tests call `LoadWith` with a fake reader, and no other call site changes.
- `ALICE_MIGRATE`: `on-start` (default: today's behaviour) or `external`. With `external`, `serve` opens no owner connection; it reads the applied version (`db.SchemaVersion`) through the app pool and refuses to start when it differs from `db.LatestVersion(migrations.FS)`: `database schema is at version 11 but this Alice needs 12: run the migrate service first (docker compose run --rm migrate)`. The single-role warning is not printed with `external`.
- `ALICE_BACKUP_DIR` (default `/opt/alice/backups`), `ALICE_TZ` (an IANA zone; default `UTC`; an unknown zone is a configuration error). `cmd/alice/main.go` imports `_ "time/tzdata"`.

### C4. Host scripts (Task 11)

Common: `#!/usr/bin/env bash`, `set -Eeuo pipefail`, `umask 077`, `LC_ALL=C`; every message of this table is printed exactly (one line, or as shown); checks print `[ OK ] <label>`, `[WARN] <message>` or `[FAIL] <message>`; all output is also appended to the log file, except the setup code (S-4); no `eval`, no `source` of any file from a package (only `lib/alice-lib.sh` of the **running** script's own directory is sourced, with a `# shellcheck source=lib/alice-lib.sh` line), every expansion quoted. Every `docker`/`docker compose` call goes through `alice_docker`/`alice_compose`, which run `env -i PATH="$PATH" HOME=/root LC_ALL=C docker …` so `ALICE_IMAGE`, `POSTGRES_IMAGE`, `COMPOSE_*`, `DOCKER_HOST` or `DOCKER_CONFIG` in the caller's environment never reach compose (S-6). The passphrase rule of the Global Constraints applies (S-25). The two test overrides `ALICE_PROC_DIR` and `ALICE_DOCKER_SOCK` are read in preflight only, never passed to `docker`, and when either is set the script prints and logs `[WARN] Test override <name> is set; results of this check are not real.` (S-24). Values written into `.env` are validated first (S-9): host names `^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$` (a comma-separated list), `--bind` an IPv4 or IPv6 literal, `--port` 1..65535, `--project` `^[a-z0-9][a-z0-9_-]{0,62}$`, the zone from `timedatectl` `^[A-Za-z0-9/_+-]{1,64}$` (else `UTC` with `[WARN] The time zone of this server could not be read; Alice uses UTC.`); a bad flag value is a usage error (exit 2). A `RELEASE` with `TEST_SIGNED=1` makes both `install.sh` and `alice-update.sh` print `[WARN] This package is signed with a TEST key. Never install it for production.` (S-11). Exit codes: `0` success, `1` failure (nothing changed, or rolled back), `2` usage, `3` the update failed and the automatic return also failed.

`install.sh [--dir DIR] [--port N] [--bind ADDRESS] [--hostname NAME] [--non-interactive [--fingerprint HEX]] [--restore-mode] [--uninstall [--purge] [--confirm DELETE]] [--project NAME]` (defaults `/opt/alice`, 443, every address (`0.0.0.0`), the output of `hostname -f`, interactive, project `alice`; `--bind` limits the published port to one local address, which the release harness uses with `127.0.0.1`). Steps: 1 preflight (all checks, then stop at the first failure after listing every failure; no change is made), 2 package check in this order (S-7): (a) verify `SHA256SUMS.sig` with the package's `release-keys/*.pem`, (b) `sha256sum -c --strict --quiet SHA256SUMS`, (c) the sorted output of `find . -type f ! -name SHA256SUMS ! -name SHA256SUMS.sig` equals the sorted names in `SHA256SUMS` and `find . ! -type f ! -type d` prints nothing (no symlink, no special file), (d) only then is anything else read; then the fingerprint line and its confirmation (S-23, R43 row 43): interactive `Does this fingerprint match the one your vendor published? Type yes to continue: ` (anything but `yes` prints `Nothing was changed.`, exit 1); `--non-interactive` needs `--fingerprint <64 hex>` (missing: usage error, exit 2; different: `The package fingerprint does not match --fingerprint. Nothing was changed.`, exit 1); 3 layout (C2; `lib/initdb/10-alice-roles.sh` copied by name, never by glob), 4 secrets and `master.key` (not in `--restore-mode`), 5 load images (`docker load -i`, then compare image IDs with `RELEASE`), 6 start (`docker compose up -d --wait --wait-timeout 180 postgres`, then `docker compose run --rm migrate`, then `docker compose up -d --wait --wait-timeout 180 alice`; only `postgres` in `--restore-mode`), 7 setup code (`docker compose exec -T alice /usr/local/bin/alice setup-token --reset`, whose first output line is `One-time setup code: <code>`; the script parses that line) and the closing text of §18.3 step 7 with the real address, port and code, printed to the terminal only; `install.log` gets `Setup code printed to the terminal (not logged).` (S-4).

| Check (label) | `[FAIL]` message |
|---|---|
| Running as root | `This installer must be run with administrator rights. Run it again as: sudo ./install.sh` |
| Linux x86_64 | `Alice needs a 64-bit Intel/AMD Linux server. This machine is <uname -m>.` |
| Docker installed and running | `Docker is not installed or not running. Install Docker Engine 24 or newer (see docs/install-guide.md), then run this installer again.` |
| Docker 24 or newer with the compose plugin | `Your Docker is too old (found <version>). Alice needs version 24 or newer.` / `The Docker compose plugin is missing. Install docker-compose-plugin (see docs/install-guide.md), then run this installer again.` |
| Docker socket restricted | `The Docker socket /var/run/docker.sock can be used by every user on this server. Restrict it to the docker group (chmod 660), then run this installer again.` |
| OpenSSL 3 | `OpenSSL 3 is needed to check the package signature. Install the openssl package, then run this installer again.` |
| Free disk ≥ 20 GB | `Not enough free disk space in <parent of dir>: <n> GB free, 20 GB needed.` |
| Memory ≥ 4 GB, CPU ≥ 2 | `This server has <n> GB of memory. Alice needs at least 4 GB.` (`[WARN]` with the same text when ≥ 3 GB) / `This server has <n> CPU. Alice needs at least 2.` |
| Port free | `Another program is already using port <port> (<process>, pid <pid>). Stop it or run the installer with --port 8443.` |
| Clock sane | `The server clock looks wrong (it says <year>). Fix the date/time first; licenses depend on it.`; when `timedatectl` is missing or says `NTPSynchronized=no`: `[WARN] Alice could not confirm that the clock is synchronised. Make sure NTP is running; licenses depend on the time.` |
| Package complete | `The installation package is damaged or incomplete. Download it again and compare the checksum.` |
| Package signature (checked before the checksums) | `The package signature is not valid. Do not install this package; download it again and check it with your vendor.` then, on success, `Package signed by release key <key id> (SHA-256 fingerprint <64 hex>). Compare this fingerprint with the one your vendor published.` and the confirmation of step 2 |
| Package lists exactly its files | `The installation package is damaged or incomplete. Download it again and compare the checksum.` (an unlisted file, a symlink or a special file) |
| Installation directory safe | `The installation directory <dir> has a parent that other users can change (<path>). Choose another --dir.` (exit 2) |
| No installation yet | `Alice is already installed in <dir>. To upgrade use ./alice-update.sh.` |

Start failure: the last 30 log lines of each container, then `Alice did not start. Send <dir>/install.log to support.`. `--uninstall`: `docker compose down` (no `-v`), then `Alice was stopped and its containers removed. Your data and backups are still in <dir>.`; with `--purge`: prompt `This deletes <dir> with all data and backups. Type DELETE to continue: ` (or `--confirm DELETE`); anything else prints `Nothing was deleted.` and exits 1. `--restore-mode` ends with `Alice is ready for a restore. Copy the backup file into <dir>/backups, then run: sudo <dir>/alicectl restore <dir>/backups/<file>`.

`alice-update.sh <tarball | extracted directory> [--passphrase-file FILE] [--non-interactive]` (must run from the installation directory: `cd /opt/alice && sudo ./alice-update.sh …`; the installation directory is the script's own directory). Flow (log `<dir>/update-<yyyymmddThhmmssZ>.log`):
1. Preflight and package intake: root; Docker; an installation (`VERSION`, `docker-compose.yml`); the current stack healthy (`alicectl selfcheck`); free disk ≥ 2 × the database size + 5 GB. The package is never read in place (S-3): a tarball, its `.sha256` and `.sha256.sig` (beside it) are first copied with `install -m 0600` into `<dir>/.update-<ts>/in/` (root, 0700); the signature of the **copied** `.sha256` is verified with `<dir>/release-keys/*.pem`; the hash of the **copied** tarball (`sha256sum < copy`) is compared with the signed hex (never `sha256sum -c` against a name read from the file); then the copy is extracted with `tar --no-same-owner -xzf` into `.update-<ts>/pkg/`. An extracted-directory argument is copied with `cp -a --no-preserve=ownership` into `.update-<ts>/pkg/` before any check. Inside `pkg/`: the S-7 order of the install step 2 with `<dir>/release-keys/*.pem` (never the package's own keys); the new `VERSION` newer than the installed one; the installed version ≥ the package's `MIN_UPGRADE_FROM`; the `TEST_SIGNED` warning. `.update-<ts>/` is removed on every exit path except exit 3. Nothing is changed in this step.
2. Passphrase: from `--passphrase-file` (refused, exit 2, when group- or world-readable), else asked on the terminal (no echo), kept in an unexported shell variable of this run only and passed to `alicectl` on standard input (S-25); step 4's deep verification of the file it just wrote proves it, so a wrong passphrase stops the update before any change to the installation.
3. Drain: `docker compose stop alice`, then end leftover sessions on the database (Alice is stopped, so these can only be leftovers such as a killed `migrate`; the superuser is the only role that may end them): `docker compose exec -T postgres psql -U postgres -d postgres -v ON_ERROR_STOP=1 -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = 'alice' AND usename IN ('alice_app','alice_owner')"` (S-15, M-4).
4. Pre-update backup with `alice` stopped: `alicectl backup --reason pre-upgrade-<new version>` (kind `pre-upgrade-<installed version>` in the name; `alicectl` uses `alice-admin` because `alice` is not running), then `alicectl backup verify <file> --deep` with the passphrase.
5. Rollback state: copy `docker-compose.yml`, `.env`, `RELEASE`, `VERSION`, the scripts, `lib/` and `release-keys/` to `rollback/<installed version>/`.
6. Load and check the new images (IDs as in the new `RELEASE`).
7. New compose file and `.env` (image tags from the new `RELEASE`; other values kept), then `docker compose run --rm migrate`.
8. `docker compose up -d --wait --wait-timeout 180 alice`, then `alicectl selfcheck`.
9. On success: install the new scripts and `lib/`, **replace** `release-keys/` with the new package's set (S-35: a release can retire a key), install `RELEASE`, `VERSION`, docs; print `Alice is now version <new>.`; exit 0.
10. On a failure in steps 3–6 (nothing in the installation changed yet): `up -d --wait alice`; print `The update was stopped before any change; Alice is running version <installed> again.`; exit 1. If `alice` does not start again: `Alice could not be started again. Details: <log>. Please send this file to support.`; exit 3.
11. On a failure in steps 7–8 (also a killed migrate container or a timeout): stop `alice`; end leftover sessions as in step 3; restore the compose file, `.env`, `RELEASE`, `VERSION` from `rollback/<installed>/`; `alicectl restore <pre-update file> --db-only --confirm RESTORE` with the passphrase on standard input (the installed version's binary restores its own backup; `alicectl`'s trap starts `alice` again and runs `selfcheck`); print `The update to <new> failed and Alice was returned to <installed>. Your data is unchanged as of <backup time UTC>. Details: <log>. Please send this file to support.`; exit 1. If the return fails: `The update to <new> failed and Alice could not be returned to <installed> automatically. Your backup is <file>. Restore it by hand: cd <dir> && sudo ./alicectl restore <file>   (details: <log>)`; exit 3.

Preflight messages of the update: `This installation is already at version <v>.` / `Going back to an older version is only possible by restoring a backup.` / `Alice <installed> cannot be updated directly to <new>. Install <min> first.` / `The update package signature is not valid. Do not install this package; download it again and check it with your vendor.` / `Not enough free disk space in <dir>: <n> GB free, <m> GB needed for the update.` / `Alice is not healthy now (selfcheck failed). Fix it before updating; see <dir>/update-<ts>.log.`

`alicectl <command> [args]` (wrapper, C6): `backup [--out FILE] [--reason TEXT]`, `backup list`, `backup verify FILE [--deep] [--passphrase-file FILE]`, `restore FILE [--db-only] [--passphrase-file FILE] [--confirm RESTORE] [--accept-broken-audit-log] [--no-safety-backup]`, `selfcheck`, `audit verify`, `setup-token --reset`, `support-bundle [--out FILE]`, `help`. A `FILE` must resolve inside `<dir>/backups` (`realpath -e` plus a prefix check; a symlink that leaves the directory is refused: `The backup file must be in <dir>/backups. Copy it there first.`, exit 2); the wrapper passes the container path `/opt/alice/backups/<name>`. While `alice` runs, commands use `docker compose exec` (`-T` unless standard input is a terminal); when it does not, `docker compose run --rm alice-admin`. `restore` (S-16, S-22, M-4): (1) `alice backup verify FILE --deep --passphrase-stdin` (through `exec` while `alice` runs, else `run --rm alice-admin`) — a wrong passphrase or a bad file stops here and `alice` keeps running; (2) the free space of `data/postgres` (`df -B1 --output=avail`) is passed as `--free-bytes N`; (3) `docker compose stop alice`, the leftover-session cleanup of the update's step 3, `run --rm alice-admin restore … --passphrase-stdin`; (4) a `trap` always runs `up -d --wait alice` and `selfcheck` afterwards, whether the restore succeeded or failed (except in `--restore-mode`, where `alice` never existed: there it runs only after a successful restore). `--passphrase-file` is read by the wrapper and fed on standard input with `--passphrase-stdin`. `setup-token --reset` prints the code to the terminal only and tees nothing into a log (S-4). `support-bundle` builds the bundle in `mktemp -d` under `<dir>` (0700) and installs it with `install -m 0600` to `--out` (default `<dir>/support-bundle-<ts>.tar.gz`); an existing `--out` path, a symlink included, is refused: `The file <out> already exists.`, exit 2 (S-10).

Version comparison (`lib/alice-lib.sh: alice_version_cmp A B` → prints `-1`, `0` or `1`): versions match `^[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$` (anything else is a usage error); numeric comparison of the three parts; a pre-release is lower than its release; `rc.N` compares numerically.

### C5. Release package (Task 12)

```
alice-<v>.tar.gz                    the package          alice-<v>.tar.gz.sha256      "<hex>  alice-<v>.tar.gz\n"
                                                         alice-<v>.tar.gz.sha256.sig  raw 64-byte Ed25519 signature
alice/
  install.sh, alice-update.sh, alicectl, lib/alice-lib.sh, lib/initdb/10-alice-roles.sh
  docker-compose.yml, .env.template, VERSION, RELEASE
  release-keys/rk-YYYY-NN.pem       release public keys (PKIX PEM, comment line "key-id: rk-YYYY-NN"; test packages: rk-test-NN)
  helper/alice-helper-linux-amd64, helper/alice-helper-linux-arm64, helper/alice-helper.sha256
  images/alice-<v>.tar, images/postgres-<v>.tar, images/images.sha256
  sbom/alice-<v>.cdx.json, sbom/postgres-<v>.cdx.json, sbom/source-<v>.cdx.json
  docs/*.md, SECURITY-REPORT.md, licenses/THIRD_PARTY_NOTICES.md, licenses/LICENSE (Alice's own terms, from the vendor;
                                    deploy/release/LICENSE.txt until the vendor replaces it)
  CHANGELOG.md, RELEASE-CHECKLIST-SIGNED.txt
  SHA256SUMS                        sha256sum of every file above (relative paths, sorted), excluding itself and its .sig
  SHA256SUMS.sig                    raw 64-byte Ed25519 signature of SHA256SUMS
```

`RELEASE` (key=value lines, read with `grep`/`sed`, never sourced): `VERSION=1.0.0`, `MIN_UPGRADE_FROM=1.0.0-rc.1`, `SCHEMA_VERSION=<goose version>`, `ALICE_IMAGE=alice:1.0.0`, `ALICE_IMAGE_ID=sha256:<64 hex>` (the config digest, from the saved tar's `manifest.json`), `ALICE_IMAGE_DIGEST=sha256:<64 hex>` (the manifest or index digest, from its `index.json`), `POSTGRES_IMAGE=alice-postgres:1.0.0`, `POSTGRES_IMAGE_ID=sha256:<64 hex>`, `POSTGRES_IMAGE_DIGEST=sha256:<64 hex>` (Task 12 review I-1: a classic image store reports the config digest as `.Id` after `docker load`, a containerd store the manifest digest; install.sh and alice-update.sh accept either, and an empty `*_DIGEST` of an older RELEASE means only the ID), `BUILD_COMMIT=<40 hex>`, `BUILD_TIME=<RFC 3339>`, `RELEASE_KEY_ID=rk-YYYY-NN` (`rk-test-NN` in a test package), and `TEST_SIGNED=1` only in a package staged with `-test` (R43 row 43). The postgres image is `postgres:16-alpine@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea` re-tagged. `RELEASE-CHECKLIST-SIGNED.txt` is written by `tools/releasebuild stage` from `bin/release-gates.log` (written by `make release-gates`): the commit, each gate with its exit status and tool version, and the line `Signed: <empty until the vendor signs the checklist>`; without that log it holds `No gate was recorded for this package.` and the `Signed:` line; it never claims a gate that did not run.

Stage inputs (M-6; `tools/releasebuild stage` and its tests enforce the list): `deploy/release/{install.sh,alice-update.sh,alicectl,lib/alice-lib.sh}`, `deploy/release/docker-compose.yml`, `deploy/release/env.template` (written as `.env.template`), `deploy/release/postgres/initdb/10-alice-roles.sh` (written as `lib/initdb/10-alice-roles.sh`), `-keys` (`rk-*.pem` into `release-keys/`), the `docs/*.md` that exist, `CHANGELOG.md`, `SECURITY-REPORT.md`, `deploy/release/LICENSE.txt` (as `licenses/LICENSE`), the notices, the helper, the SBOMs and the two images. `-allow-draft` (set by `make release-test` only) accepts a missing `SECURITY-REPORT.md` and writes the placeholder line `SECURITY-REPORT.md: not part of this test package`; `make release` (production) refuses a missing `SECURITY-REPORT.md` or an empty gates log. `-test` (set by `make release-test` only) accepts `rk-test-NN` keys and writes `TEST_SIGNED=1`; without it every key file must be `rk-YYYY-NN` and the set must equal `deploy/release/keys/`. The stage refuses a symlink among its inputs (S-7, S-11).

Signature verification command (used by both scripts; the test asserts these exact arguments): `openssl pkeyutl -verify -pubin -inkey "$key" -rawin -in "$file" -sigfile "$sig"`; a file is trusted when one key in the trusted set verifies it. Fingerprint: SHA-256 of the DER public key (`openssl pkey -pubin -in "$key" -outform DER | sha256sum`).

### C6. Operator CLI (in the container, Task 6)

```
alice backup [--out PATH] [--reason TEXT]
      → stdout "Backup written: <path> (<size in MiB, one decimal> MiB)"; exit 0. Kind manual; when --reason starts with
        "pre-upgrade-" the kind is pre-upgrade-<this binary's version> and the reason stays in the manifest (§20.1
        step 3: --reason pre-upgrade-1.1.0 on 1.0.0 writes …-pre-upgrade-1.0.0.alicebak). --out must be inside ALICE_BACKUP_DIR.
alice backup list
      → "NAME  KIND  SIZE  CREATED (UTC)  ALICE  CHECK" then one row per file, newest first; CHECK is ok, missing
        checksum, checksum mismatch or unreadable header.
alice backup verify FILE [--deep] [--passphrase-stdin]
      → "The backup file looks complete (header, size and checksum are correct)." or with --deep
        "The backup opens with this passphrase and is complete: <manifest line>."; exit 0, else the C7 messages, exit 1.
alice restore FILE [--db-only] [--passphrase-stdin] [--confirm RESTORE] [--accept-broken-audit-log] [--no-safety-backup]
            [--free-bytes N] [--wait-for-sessions DURATION]
      → C7 flow and messages. --free-bytes is the free space the host wrapper measured (0 or absent: not checked);
        --wait-for-sessions defaults to 150s.
alice selfcheck
      → seven lines "[ OK ] <label>" or "[FAIL] <label>: <reason>" (C9), exit 0 when all are OK, else 1 (the heartbeat line
        is retried every 5 s for up to 90 s before it fails).
alice support-bundle
      → one JSON document on stdout (C9).
alice migrate [--to-latest]        (the flag is accepted and is the default)
```

The passphrase is read with `term.ReadPassword` from `/dev/tty` when standard input is a terminal, else only with `--passphrase-stdin` (one line, at most 1,024 bytes, trailing newline removed); otherwise `A passphrase is needed. Run this command in a terminal, or pass --passphrase-file to alicectl.` and exit 2.

### C7. Backup file, payload and restore messages (Tasks 1, 2, 4, 5)

**File** (`internal/backup/format`):

```
File   = Header Chunk*  (at least one chunk; the last one is final)
Header = "ALICEBK1" | uint16 BE version (=2) | uint32 BE n (1 ≤ n ≤ 65,536) | n bytes of JSON (HeaderJSON)
HeaderJSON (unknown fields refused, every field required):
  {"alice_version":"1.0.0","created_at":"2026-10-10T02:30:00Z","kind":"auto",
   "recipient":"<base64 32>","ephemeral":"<base64 32>",
   "wrapped_key":{"version":2,"public_key":"<base64 32>","kdf":{"memory_kib":65536,"time":3,"threads":4},
                  "salt":"<base64 16>","nonce":"<base64 12>","ciphertext":"<base64 48>",
                  "sender_public_key":"<base64 32>"},
   "chunk_size":65536,"nonce_prefix":"<base64 4>"}
Bounds: wrapped_key.version == 2; wrapped_key.public_key == recipient; sender_public_key != recipient;
        kdf.memory_kib 8,192..262,144; kdf.time 1..10; kdf.threads 1..16;
        chunk_size == 65,536; kind matches ^(auto|manual|pre-restore|pre-upgrade-[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?)$;
        alice_version matches ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ or "dev".
Wrapped key (secrets.WrappedBackupKey v2, R43 row 41): ciphertext = AES-256-GCM(Argon2id(passphrase, salt, kdf),
                       recipient private key, AAD = "alice/backup-key/v2" || public_key || sender_public_key);
                       Unwrap also checks that the private key's public half equals public_key.
File key = HKDF-SHA256(secret = X25519(ephemeral private, recipient) || X25519(sender private, recipient),
                       salt = ephemeral || recipient || sender_public_key, info = "alice/backup/v2", length 32)
           The reader computes X25519(recipient private, ephemeral) || X25519(recipient private, sender_public_key),
           taking sender_public_key only from the wrapped key it unwrapped with the passphrase (OpenWithKey: from its
           caller). A restore on a fresh server therefore needs the passphrase and nothing else.
Chunk i (i = 0, 1, …) = AES-256-GCM(file key, nonce = nonce_prefix || uint64 BE i, plaintext,
                       AAD = SHA-256(the header bytes from "ALICEBK1" to the end of the JSON) || final flag byte)
  every chunk but the last carries exactly 65,536 plaintext bytes and flag 0x00; the last carries 0..65,535 bytes and
  flag 0x01 (a payload that ends on a chunk boundary is followed by an empty final chunk; an empty payload is one final
  chunk of 16 bytes).
```

Errors (`format`): `ErrNotBackup` (shorter than 14 bytes or wrong magic), `ErrNewerFormat` (version > 2), `ErrHeader` (version < 2, bad length, JSON, bounds), `ErrDecrypt` (the wrapped key does not open, or a chunk tag fails), `ErrTruncated` (the stream ends without a final chunk), `ErrTrailingData` (bytes after the final chunk). The reader holds at most one chunk (65,552 bytes) in memory.

**Payload** (inside the encryption): `gzip` (level 6) of a frame stream (`internal/backup/dump`):

```
Frame = kind byte | uint16 BE name length | name (UTF-8, ≤ 255 bytes) | uint32 BE data length (≤ 1 MiB) | data
Kinds: 'M' manifest (JSON, first frame, name "manifest.json")
       'T' table start (JSON {"name":"audit_log","columns":["seq","at",…]}), name = table
       'D' COPY BINARY data of the current table (any number, each ≤ 1 MiB)
       'E' table end (JSON {"rows":N}), name = table
       'Q' sequences (JSON {"public.<seq>": <last_value or null>}), name "sequences.json"
       'F' file (name "keys/master.key", "keys/tls.crt", "keys/tls.key", "state/hwm.dat"; data ≤ 1 MiB)
       'Z' end (JSON {"tables":N,"files":N}), name "end"
Order: M, then T D* E per table (names strictly ascending), Q, F*, Z. Anything else is ErrPayload. Load (Task 2) also
       requires the T names to equal Tables(target) and the Q keys to equal the target's public sequences, else
       ErrSchemaMismatch. The restore (Task 5) maps F names through the fixed four-entry table above, never a path join
       of the name, and refuses an unknown or repeated name (ErrDamaged).
```

Manifest (`backup.Manifest`): `{"format":1,"alice_version":"…","schema_version":12,"created_at":"…","kind":"auto","reason":"","installation_id":"ALICE-…","hostname":"…","tables":{"<name>":<rows>,…},"audit_head":{"seq":N,"hash":"<hex>"},"files":["keys/master.key",…]}` — the row counts and the audit head are read inside the dump's snapshot.

**File names:** `alice-backup-<ID8>-<yyyymmddThhmmssZ>-<kind>.alicebak` with `<ID8>` = the first 8 characters of the Installation ID after removing the `ALICE-` prefix and the dashes (`ALICE-7F3K-92QD-…` → `7F3K92QD`); pattern `^alice-backup-[0-9A-Z]{8}-[0-9]{8}T[0-9]{6}Z-(auto|manual|pre-restore|pre-upgrade-[0-9A-Za-z.-]+)\.alicebak$`; `--out` may give another name ending in `.alicebak` without `/`, NUL or a leading dot. Beside each: `<name>.sha256` = `<64 hex>  <name>\n`.

**Restore messages** (CLI, exact):

| Case | Output | Exit |
|---|---|---|
| Wrong magic, empty or text file (F-83) | `This is not an Alice backup.` | 1 |
| Newer format, newer Alice version in the header, or newer schema in the manifest (F-83) | `This backup was created by a newer Alice version (<v>). Install Alice <v> or newer, then restore.` | 1 |
| Wrong passphrase, any tag failure, truncation, trailing data, bad payload (F-80..F-82) | `The passphrase is wrong or the file is damaged. Nothing was changed.` | 1 |
| Verification of the staged data failed (counts, key check, seal) | `The backup could not be verified (<reason>). Nothing was changed.` | 1 |
| The backup's audit log is broken | `The audit log in this backup is damaged at entry <n>. Nothing was changed. To restore it anyway, run the command again with --accept-broken-audit-log (the damage stays visible in Alice).` | 1 |
| Manifest shown before the confirmation | `Backup from <yyyy-mm-dd hh:mm> UTC, Alice <v>, host <host>, installation <ID>.` then `Type RESTORE to replace all current data: ` | — |
| Not confirmed | `Restore cancelled. Nothing was changed.` | 1 |
| The live installation has data but no recovery passphrase, so no safety backup can be made (S-17) | `This installation has data but no recovery passphrase, so no safety backup can be made first. Nothing was changed. To restore anyway, run the command again with --no-safety-backup (the current data is then replaced without a copy).` | 1 |
| Not enough free disk (S-22) | `Not enough free disk space for a restore: <n> GB free, <m> GB needed.` | 1 |
| Other sessions on the database after the wait (M-4) | `Alice is still connected to the database. Stop it first.` | 1 |
| Done | `Restore finished. Everyone must sign in again. Users and API tokens are as they were when the backup was made; review them.` | 0 |
| `--db-only` done | `Database restored from <name>.` | 0 |

### C8. `internal/backup` (Tasks 4–5)

```go
package backup

type Config struct {
	Pool        *pgxpool.Pool // app role: dumps and state
	Audit       *audit.Log
	Notifier    notify.AdminNotifier
	Clock       clock.Clock
	Dir         string // ALICE_BACKUP_DIR
	KeysDir     string
	StateDir    string
	Version     string // the binary's version
	Hostname    func() (string, error)
	Log         *slog.Logger
	Keyring     *secrets.Keyring // opens the sender key backup.sender (R43 row 41)
	create      func(name string) (writeFile, error) // tests: disk-full injection (export_test.go)
	statfs      func(dir string) (free uint64, err error) // tests: free-space hook (export_test.go); syscall.Statfs
}
type Service struct{ /* … */ }
func New(c Config) *Service

type Kind string // "auto", "manual", "pre-restore", "pre-upgrade-<v>"
type Info struct {
	Name, Path string; Kind Kind; Size int64; CreatedAt time.Time; AliceVersion string
	Check string // "ok", "missing checksum", "checksum mismatch", "unreadable header"
}
type CreateInput struct{ Kind Kind; Reason string; Out string /* "" = standard name */; Actor audit.Actor }
func (s *Service) Create(ctx context.Context, in CreateInput) (Info, error)        // ErrRunning, ErrNotConfigured, ErrWrite
func (s *Service) FreeBytes() (uint64, error)                                      // free space of Dir (Backups tab, S-21)
func (s *Service) List(ctx context.Context) ([]Info, error)
func (s *Service) Verify(ctx context.Context, path string) (Info, error)          // shallow (R43 row 4)
func (s *Service) VerifyDeep(ctx context.Context, path string, passphrase []byte) (Manifest, error)
func (s *Service) Prune(ctx context.Context, keep int, actor audit.Actor) (int, error)
func (s *Service) Open(ctx context.Context, name string) (*os.File, Info, error)  // for the download; ErrNotFound
func (s *Service) Schedule(ctx context.Context) (Schedule, error)
func (s *Service) SaveSchedule(ctx context.Context, a audit.Actor, version int, in Schedule) (Schedule, error) // ErrVersion; audited
func (s *Service) State(ctx context.Context) (State, error)
func (s *Service) RunScheduled(ctx context.Context) error                          // the backup.schedule task

type Schedule struct{ Time string; Zone string; Retention int; Version int }      // "02:30", "Europe/Istanbul", 14
func LastScheduled(now time.Time, loc *time.Location, hhmm string) time.Time       // pure
func Due(now time.Time, loc *time.Location, hhmm string, lastAutoSuccess time.Time) bool // pure

type State struct {
	LastSuccessAt time.Time; LastSuccessName string; LastAutoSuccessAt time.Time
	LastFailureAt time.Time; LastErrorCode string; ConsecutiveFailures int
	FailureNotified bool; AlarmNotified bool
}
func (st State) Alarm(now time.Time) bool // no success for 48 h (counted from LastSuccessAt, or from the installation's
                                          // setup completion when there was never one)

// Task 5
type RestoreInput struct {
	Path string; Passphrase []byte; DBOnly bool; AcceptBrokenAudit bool
	NoSafetyBackup bool              // S-17: restore over a live installation that has data but no backup key
	FreeBytes int64                  // S-22: free space measured by the host wrapper; 0 = not checked
	WaitForSessions time.Duration    // M-4: wait for other sessions on the live database (CLI default 150 s; tests 0)
	Confirm func(m Manifest) bool   // CLI: prints the manifest line, reads RESTORE
	OwnerURL string                  // owner role, database "alice"; the service derives the maintenance URL (database "postgres")
}
type RestoreResult struct{ Manifest Manifest; SafetyBackup string }
func Restore(ctx context.Context, cfg Config, in RestoreInput) (RestoreResult, error)
// errors: format.ErrNotBackup, *ErrNewer{Version}, ErrDamaged (wraps format.ErrDecrypt/ErrTruncated/…), *ErrNotVerified{Reason},
//         *ErrAuditBroken{Seq}, ErrCancelled, ErrDatabaseInUse ("Alice is still connected to the database. Stop it first."),
//         ErrNoSafetyBackup, *ErrNoSpace{Free, Need}
// FinishInterruptedRestore applies staged files only when the live database's backup.restore_id equals the staging's
// RESTORE_ID; otherwise the staging is stale and removed without touching the live files (R43 row 8). q is the app pool
// (serve opens it first) or the restore's maintenance-side connection to the live database.
func FinishInterruptedRestore(ctx context.Context, q db.Querier, keysDir, stateDir string) (bool, error)

var (
	ErrRunning       = errors.New("backup: another backup is running")              // ALC-BAK-0001
	ErrNotConfigured = errors.New("backup: no recovery passphrase has been set")    // ALC-BAK-0002
	ErrNotFound      = errors.New("backup: no such backup")                         // ALC-BAK-0003
	ErrWrite         = errors.New("backup: the backup file could not be written")   // ALC-BAK-0004
	ErrVersion       = errors.New("backup: the schedule was changed meanwhile")     // ALC-SYS-0008
)
const AlarmAfter = 48 * time.Hour
```

(`SaveSchedule` has the shape of `notify.Settings.SaveSMTP(ctx, a audit.Actor, version int, in SMTPInput)` and `alerts.Service.SaveThresholds`: optimistic version, one `backup.settings_changed` audit row, `ErrVersion` on a stale version.)

Create sequence: advisory lock `pg_try_advisory_lock(hashtext('alice.backup'))` on a dedicated connection (else `ErrRunning`); read `backup.key` — it must be version 2 — and the sender key `backup.sender` through `Keyring.GetSetting`, whose public half must equal `SenderPublicKey` (any of these missing or different: `ErrNotConfigured`, state code `not_configured`; R43 row 41); free-space check (S-21, R43 row 46): free space of `Dir` under 2 × the size of the newest backup + 1 GiB → `ErrWrite` with code `disk_full` before any file is opened; open `.<name>.partial` (`O_CREATE|O_EXCL|O_WRONLY`, 0600); `format.NewWriter(w, wrapped, sender, meta)` → gzip → frame encoder; `BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY`; manifest (schema version from `goose_db_version`, counts per table, audit head `SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1`, Installation ID from `license`); `dump.Dump`; files (`tls.crt`/`tls.key` through one helper that re-reads the pair until the key matches the certificate, at most 3 tries, else both are left out with a log line, S-14); end frame; close (final chunk); `fsync`; re-open, SHA-256, compare with the hash computed while writing; rename to `<name>`; write `<name>.sha256` (same partial-then-rename rule); `fsync` the directory; audit `backup.created` (`name`, `kind`, `size`, `reason`); update `backup.state`; for `auto`: `Prune(retention)`. Any error: remove the partial files, audit `backup.failed` (`kind`, `error_code`), update `backup.state`, return the error.

### C9. Selfcheck and support bundle (Task 6)

| Label | OK when |
|---|---|
| `Database reachable` | the app pool pings within 5 s |
| `Database schema is current (version <n>)` | `db.SchemaVersion == db.LatestVersion(migrations.FS)` |
| `Master key opens the stored key check` | `secrets.LoadOrCreateMasterKey`'s check path succeeds without creating anything (a read-only variant `secrets.CheckMasterKey(ctx, q, dir)` added by Task 6) |
| `Audit log intact (<n> entries, head <first 16 hex>)` | `audit.Verify(ctx, pool)` intact (read-only; no checkpoint, no audit row) |
| `License readable (<phase>)` | `license.Service.Snapshot()` returns an evaluation |
| `HTTPS listener answers with the installed certificate` | a TLS handshake to `127.0.0.1:<listen port>` within 5 s presents a leaf whose DER equals the first certificate of `<keys>/tls.crt` |
| `Background jobs running (last heartbeat <hh:mm> UTC)` | `jobs.heartbeat` is less than 5 minutes old; the check waits up to 90 s (every 5 s) for a heartbeat that is (a restored database carries the old one; `serve` writes its first as soon as the scheduler runs) |

`alice support-bundle` JSON: `{"version":{…},"config":<the redacted config LogValue>,"selfcheck":[{"label":…,"ok":…,"reason":…}],"schema_version":n,"tables":{"<name>":rows},"license":{"phase":…,"days_left":…},"jobs":{"queued":n,"running":n,"failed_24h":n,"dead_24h":n},"backup":{"last_success_at":…,"failing":…},"forwarding":{"enabled":…,"backlog":n}}` — no customer name, no Installation ID, no host names of targets, no secret.

### C10. `internal/audit/forward` (Task 7)

```go
package forward

type Transport string // "tls" (default), "tcp", "udp"
type Settings struct {
	Enabled bool; Host string; Port int; Transport Transport; CAPEM string; Version int
}
type State struct {
	CursorSeq int64; CheckpointSeq int64; LastSentAt time.Time; LastErrorCode string; LastErrorAt time.Time; Backlog int64
}
type Config struct {
	Pool *pgxpool.Pool; Audit *audit.Log; Clock clock.Clock; Log *slog.Logger
	Dial func(ctx context.Context, network, addr string) (net.Conn, error) // production: a closure over netaddr.DialContext(ctx, dialer, network, addr)
	Hostname string; AppName string // "alice"
	RootCAs *x509.CertPool          // nil = system roots
}
type Forwarder struct{ /* … */ }
func New(c Config) *Forwarder
func (f *Forwarder) Settings(ctx context.Context) (Settings, State, error)
func (f *Forwarder) Save(ctx context.Context, in Settings, version int, actor audit.Actor) (Settings, error) // audited audit.forwarding_changed; ErrVersion when stale
func (f *Forwarder) Test(ctx context.Context, in Settings) error   // one test message; ErrAddressRefused, ErrUnreachable, ErrUntrusted
func (f *Forwarder) Run(ctx context.Context) error                  // the audit.forward task: send up to 500 rows from the cursor
const MaxBatch = 500
var ErrAddressRefused, ErrUnreachable, ErrUntrusted, ErrVersion error // ALC-AUD-0002, -0003, -0004, ALC-SYS-0008
```

Message (RFC 5424, octet-counting framing for TCP/TLS, one datagram for UDP, at most 8 KiB, details cut to fit): `<PRI>1 <timestamp> <hostname> alice - <action> [alice@32473 seq="<seq>" hash="<hex>" prev_hash="<hex>" actor="<actor>" result="<result>"] <JSON of object and details>`; PRI = facility `auth` (4), severity `notice` (5) for success, `warning` (4) for failure and denied, `critical` (2) for `audit.verified` with a failure. A checkpoint (`audit.checkpoint` setting written by `audit.Service.Verify`) is forwarded once per new checkpoint as action `audit.checkpoint` with its seq and hash (F-92). The cursor moves only after the write returned (TCP/TLS) or the datagram was sent (UDP); a returned write is only in the kernel buffer, so delivery is **at most once** and a connection reset can lose messages — the `seq`/`prev_hash` fields let the collector see the gap (R43 row 31). A failure records `LastErrorCode`, keeps the cursor and is retried at the next tick; the audit write path never touches the forwarder (F-96).

### C11. TLS store and wizard backend (Task 8)

```go
package tlscert
type Store struct{ /* atomic pointer to the current tls.Certificate; one mutex serialising Install and Renew (S-13) */ }
func NewStore(dir string, hosts []string, clk func() time.Time) (*Store, error) // wraps EnsureSelfSigned; first repairs an
// interrupted Install: tls.crt.new matching tls.key → finish the rename; a live pair that does not match while the .prev pair
// does → restore .prev; it never regenerates over a key that is not the temporary one
func (s *Store) Recovered() string // "" or what NewStore repaired ("finished", "restored_previous"); serve logs it and audits
                                   // https.certificate_recovered (Task 6)
func (s *Store) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)
func (s *Store) Info() Info // Subject, DNSNames, IPs, NotBefore, NotAfter, FingerprintSHA256, Temporary
func (s *Store) Install(u Upload) (Info, error)  // under the mutex: validates, hard-links the pair to tls.crt.prev/tls.key.prev,
                                                 // writes tls.key.new (0400) and tls.crt.new (0644), renames key then certificate, swaps
func (s *Store) Renew() (renewed bool, err error) // under the mutex, re-reading the files: the temporary certificate only; tls.renew task
type Upload struct{ CertPEM, KeyPEM, PFX, PFXPassword []byte }
func ParseUpload(u Upload, now time.Time) (tls.Certificate, Info, []string /*warnings*/, error)
var ErrKeyMismatch, ErrNotValidNow, ErrWeakKey, ErrPFXPassword, ErrUnreadable error // ALC-TLS-0001..0005
func ServerConfigFor(s *Store) *tls.Config // ServerConfig with GetCertificate instead of Certificates
```

Warnings: `name_mismatch` (none of `ALICE_TLS_HOSTS` and the request host is in the certificate's names), `chain_incomplete` (the chain does not verify against the system roots plus the uploaded intermediates), `expires_soon` (less than 30 days).

```go
package setup
func (s *Service) KeepTemporaryCertificate(ctx context.Context, p auth.Principal, m auth.Meta) (Status, error) // setup.https_choice=temporary
func (s *Service) RecordCertificateUploaded(ctx context.Context, tx pgx.Tx, p auth.Principal) error          // =uploaded (called by the API after Store.Install)
func (s *Service) SkipMail(ctx context.Context, p auth.Principal, m auth.Meta) (Status, error)              // setup.mail_choice=skipped
// Status gains HTTPSChosen, MailChosen bool and NextStep string ("passphrase","https","mail","license","platform","done");
// mail counts as chosen when notify mail settings exist (configured) or it was skipped.
type Strength string                           // "tooShort", "fair", "good", "strong"
func PassphraseStrength(p string) Strength      // the rules of web/src/pages/setup/strength.ts, rune for rune
var ErrPassphraseTooWeak = errors.New("setup: the recovery passphrase is too easy to guess") // "fair": ALC-SET-0010
```

### C12. API (Task 9)

| Method and path | Permission | Limit | License class | Answer |
|---|---|---|---|---|
| `GET /api/v1/backups` | `backup.manage` | default | — | `{items: BackupDTO[], state: BackupStateDTO, schedule: BackupScheduleDTO}` |
| `POST /api/v1/backups` | `backup.manage` | `limitDownload` (5/min) | `ClassAlways` | 201 `BackupDTO`; 409 `ALC-BAK-0001`/`0002`; 500 `ALC-BAK-0004` |
| `GET /api/v1/backups/{name}/download` | `backup.manage` | `limitDownload` | — | 200 `application/octet-stream`, `Content-Disposition: attachment; filename="<name>"`, `Cache-Control: no-store`; 404 `ALC-BAK-0003` |
| `GET /api/v1/settings/backups` | `settings.manage` | default | — | `BackupScheduleDTO` + `ETag` |
| `PUT /api/v1/settings/backups` | `settings.manage` | default | `ClassAlways` | `If-Match`; body `{time, zone, retention}`; 422 field errors |
| `GET /api/v1/settings/https` | `settings.manage` | default | — | `HTTPSInfoDTO` |
| `PUT /api/v1/settings/https` | `settings.manage` | `limitDownload` | `ClassAlways` | body `{cert_pem, key_pem}` or `{pfx_base64, pfx_password}`; 200 `HTTPSInfoDTO` with `warnings`; 422 `ALC-TLS-000x` |
| `POST /api/v1/setup/https/keep-temporary` | `settings.manage` | default | `ClassAlways` | `SetupStatusDTO` |
| `POST /api/v1/setup/mail/skip` | `settings.manage` | default | `ClassAlways` | `SetupStatusDTO` |
| `GET /api/v1/settings/audit-forwarding` | `settings.manage` | default | — | `ForwardingDTO` (settings + state) + `ETag` |
| `PUT /api/v1/settings/audit-forwarding` | `settings.manage` | default | `ClassAlways` | `If-Match`; 422 field errors, `ALC-AUD-0002` |
| `POST /api/v1/settings/audit-forwarding/test` | `settings.manage` | `limitDownload` | `ClassAlways` | 204, or 502 `ALC-AUD-0003`/`0004`, 422 `ALC-AUD-0002` |
| `GET /api/v1/dashboard/summary` (changed) | `read` | — | — | gains `backup` (Administrators and Auditors) and `setup_checklist` (Administrators) |
| `GET /api/v1/setup/status` (changed) | as today | — | — | gains `https_chosen`, `mail_chosen`, `next_step` while setup is open or for a signed-in session; after completion the anonymous answer is exactly `{completed, default_locale}` (S-18, R43 row 47) |

`{name}` must match the C7 file-name rule or the `--out` rule; anything else is 404 `ALC-BAK-0003` without touching the file system. DTOs: `BackupDTO {name, kind, size, created_at, alice_version, check}`, `BackupStateDTO {last_success_at, last_success_name, age_hours, failing, alarm, configured, free_bytes}`, `BackupScheduleDTO {time, zone, retention, next_at}`, `HTTPSInfoDTO {subject, dns_names, ip_addresses, not_before, not_after, fingerprint_sha256, temporary, warnings}`, `ForwardingDTO {enabled, host, port, transport, ca_set, backlog, cursor_seq, last_sent_at, last_error_code, last_error_at}` (the CA PEM is write-only: `ca_pem` in requests, `ca_set` in answers).

Codes (reason in the existing `area.name` form, HTTP, retryable): `ALC-BAK-0001 backup.running` 409 yes; `ALC-BAK-0002 backup.not_configured` 409 no; `ALC-BAK-0003 backup.not_found` 404 no; `ALC-BAK-0004 backup.write_failed` 500 yes; `ALC-TLS-0001 tls.key_mismatch` 422; `ALC-TLS-0002 tls.not_valid_now` 422; `ALC-TLS-0003 tls.weak_key` 422; `ALC-TLS-0004 tls.pfx_password` 422; `ALC-TLS-0005 tls.unreadable` 422; `ALC-AUD-0002 audit.forwarding_address_refused` 422; `ALC-AUD-0003 audit.forwarding_unreachable` 502 yes; `ALC-AUD-0004 audit.forwarding_untrusted` 502 no; `ALC-SET-0010 setup.passphrase_too_weak` 422. `POST /setup/https/keep-temporary` and `POST /setup/mail/skip` after completion return the status and change nothing (no audit row; S-39).

### C13. UI copy (Task 10; `web/src/locales/{en,tr}.json`)

| Key | English | Turkish |
|---|---|---|
| `settings.tabs.backups` | Backups | Yedekler |
| `backups.backUpNow` | Back up now | Şimdi yedekle |
| `backups.download` | Download | İndir |
| `backups.lastSuccess` | Last successful backup: {{time}} | Son başarılı yedek: {{time}} |
| `backups.never` | No backup has been made yet. | Henüz yedek alınmadı. |
| `backups.alarm` | No successful backup for 48 hours | 48 saattir başarılı yedek yok |
| `backups.notConfigured` | Backups start after the recovery passphrase is set. | Yedekleme, kurtarma parolası belirlendikten sonra başlar. |
| `backups.schedule.time` | Daily backup time | Günlük yedekleme saati |
| `backups.schedule.zone` | Time zone | Saat dilimi |
| `backups.schedule.retention` | Automatic backups to keep | Saklanacak otomatik yedek sayısı |
| `backups.offHost` | Backups are stored on this server only. Copy them to another machine regularly. | Yedekler yalnızca bu sunucuda saklanır. Bunları düzenli olarak başka bir makineye kopyalayın. |
| `backups.restoreHint` | Restoring is done on the server with alicectl restore. | Geri yükleme sunucuda alicectl restore komutuyla yapılır. |
| `backups.freeSpace` | Free disk space for backups: {{size}} | Yedekler için boş disk alanı: {{size}} |
| `settings.tabs.https` | HTTPS certificate | HTTPS sertifikası |
| `https.temporary` | Alice is using a temporary certificate. Browsers will warn until you upload your own. | Alice geçici bir sertifika kullanıyor. Kendi sertifikanızı yükleyene kadar tarayıcılar uyarı gösterecek. |
| `https.upload` | Upload certificate | Sertifika yükle |
| `https.keepTemporary` | Keep the temporary certificate | Geçici sertifikayı kullanmaya devam et |
| `https.applied` | The new certificate is in use. | Yeni sertifika kullanımda. |
| `settings.tabs.forwarding` | Audit forwarding | Denetim kaydı iletimi |
| `forwarding.backlog` | Entries waiting to be sent: {{count}} | Gönderilmeyi bekleyen kayıtlar: {{count}} |
| `forwarding.test` | Send test message | Test mesajı gönder |
| `setup.back` | Back | Geri |
| `setup.skip` | Skip | Atla |
| `setup.mail.title` | Mail server (optional) | E-posta sunucusu (isteğe bağlı) |
| `setup.https.title` | HTTPS certificate | HTTPS sertifikası |
| `dashboard.checklist.title` | Finish setting up | Kurulumu tamamlayın |
| `dashboard.checklist.passphrase` | Set the recovery passphrase | Kurtarma parolasını belirleyin |
| `dashboard.checklist.https` | Install your HTTPS certificate | HTTPS sertifikanızı yükleyin |
| `dashboard.checklist.mail` | Set up the mail server | E-posta sunucusunu ayarlayın |
| `dashboard.checklist.license` | Add a license | Lisans ekleyin |
| `dashboard.checklist.target` | Add your first server | İlk sunucunuzu ekleyin |
| `dashboard.backup.title` | Backups | Yedekler |

Test IDs: `backups-table`, `backup-now`, `backup-download-<name>`, `backup-alarm-banner`, `https-upload-form`, `https-keep-temporary`, `forwarding-form`, `setup-back`, `setup-skip`, `setup-checklist`.

### C14. Audit actions and e-mails

Audit actions (web labels under `audit.actions.<action with dots as underscores>`, Task 10): `backup.created`, `backup.failed`, `backup.deleted`, `backup.downloaded`, `backup.settings_changed`, `system.restored`, `https.certificate_replaced`, `https.temporary_renewed`, `https.certificate_recovered` (S-13; details `fingerprint`, `temporary`, `reason`), `audit.forwarding_changed`, `setup.https_kept_temporary`, `setup.mail_skipped`. Actor of CLI actions: `audit.SystemActor("cli")`; of scheduled ones: `audit.SystemActor("scheduler")`. `system.restored` details: `backup_name`, `backup_created_at`, `alice_version`, `schema_version`, `audit_intact`, `previous_audit_seq`, `previous_audit_hash` (absent on an empty host), `safety_backup` (name or `none`), `no_safety_backup` (only when given) (S-17, R43 row 45).

E-mails (templates in `locales/common/{en,tr}.json`, Task 4; rendered by `notify`, sent through `NotifyAdmins` inside the transaction that records the state):

| Template | Subject (EN / TR) | Body parameters |
|---|---|---|
| `backup.failed` | Alice could not make its daily backup / Alice günlük yedeğini alamadı | `time` (UTC), `error_code`, `dashboard_url` |
| `backup.alarm` | Alice has had no successful backup for 48 hours / Alice'in 48 saattir başarılı bir yedeği yok | `last_success` (UTC or "never"/"hiç"), `dashboard_url` |

---
### Task 1: `internal/backup/format`: the encrypted backup container (R4, SEC-048); known-answer, tamper, truncation and bound tests; `FuzzBackupHeader`, `FuzzBackupStream`; Phase 8 archtest rules; backup key v2 with the installation sender key (R43 row 41)

**Files:**
- Create: `internal/backup/format/format.go`, `internal/backup/format/bounds.go`, `internal/backup/format/export_test.go`, `internal/backup/format/format_test.go`, `internal/backup/format/fuzz_test.go`, `internal/backup/format/testdata/kat-v2.json`
- Modify: `internal/archtest/arch_test.go` (every Phase 8 rule of the Global Constraints, with `TestAllowed` cases), `internal/secrets/backupkey.go`, `backupkey_test.go` (v2 wrapped key with the sender key) and `export_test.go` (the v2 sealing helper for `TestUnwrapChecksThePublicKey`), `internal/setup/passphrase.go` (`SetRecoveryPassphrase` stores the sender key as `backup.sender`), `internal/setup/setup_integration_test.go`

**Interfaces:**
- Consumes: `secrets.KDFParams`, `secrets.Keyring.PutSetting`/`GetSetting`, `secrets.NewPlaintext` (`internal/secrets`).
- Produces: `secrets.WrappedBackupKey{Version (=2), PublicKey, KDF, Salt, Nonce, Ciphertext, SenderPublicKey}`, `secrets.NewBackupKey(passphrase []byte, p KDFParams) (WrappedBackupKey, *ecdh.PrivateKey /*sender*/, error)`, `(WrappedBackupKey).Unwrap(passphrase) (*ecdh.PrivateKey, error)` (v2 only); the `setting_secrets` key `backup.sender` (C1). C7: `format.Magic = "ALICEBK1"`, `Version = 2`, `ChunkSize = 65536`, `MaxHeaderLen = 65536`, `Meta{AliceVersion, CreatedAt, Kind}`, `Header{Meta, Recipient, Ephemeral, WrappedKey, ChunkSize, NoncePrefix}`, `NewWriter(w io.Writer, wrapped secrets.WrappedBackupKey, sender *ecdh.PrivateKey, m Meta) (*Writer, error)` (refuses a sender whose public half is not `wrapped.SenderPublicKey`), `(*Writer).Write`, `(*Writer).Close`, `ReadHeader(r io.Reader) (Header, error)`, `Open(r io.Reader, passphrase []byte) (*Reader, Header, error)`, `OpenWithKey(r io.Reader, priv *ecdh.PrivateKey, sender *ecdh.PublicKey) (*Reader, Header, error)` (the caller passes a sender key it trusts; a header whose `sender_public_key` differs → `ErrDecrypt`), `(*Reader).Read`, errors `ErrNotBackup`, `ErrNewerFormat`, `ErrHeader`, `ErrDecrypt` (wraps `secrets.ErrDecrypt` for a wrong passphrase), `ErrTruncated`, `ErrTrailingData`; KDF bounds `MinKDFMemoryKiB = 8192`, `MaxKDFMemoryKiB = 262144`, `MaxKDFTime = 10`, `MaxKDFThreads = 16`.

- [ ] **Step 1: Archtest rules first**

In `internal/archtest/arch_test.go` add to `rules`: `"alice/internal/backup/format": {"alice/internal/secrets"}`, `"alice/internal/backup/dump": {platform}`, `"alice/internal/backup/...": {platform, "alice/internal/audit/...", "alice/internal/secrets/...", "alice/internal/notify/...", "alice/internal/license/...", "alice/migrations"}`, `"alice/internal/audit/forward": {platform, "alice/internal/audit"}`; to the `api` rule `"alice/internal/backup/..."`; to `denied` `"alice/internal/backup/format": {platform, "alice/internal/platform/db"}` (read how `alerts/expiry` is listed and copy the form); `deniedStd["alice/internal/backup/format"] = pureDenied`. (The most specific rule wins in `allowed`: read its matching code first; if `.../...` and an exact key both match, the existing precedence is what `alerts/expiry` relies on.) To the `alice/internal/setup/...` rule add `"alice/internal/notify/..."` (Task 8 reads the mail settings through `notify.Settings`; M-10). `TestAllowed` cases: format → secrets allowed, format → platform/db denied, format → `os` denied, dump → `alice/internal/audit` denied, backup → `alice/migrations` allowed, backup → `alice/internal/inventory` denied, forward → audit allowed, forward → notify denied, api → backup allowed, setup → notify allowed.

Run: `go test ./internal/archtest/ -count=1`
Expected: PASS (the rules name packages that do not exist yet; `TestAllowed` exercises the pure function).

- [ ] **Step 1b: Backup key v2 with the installation sender key (R43 row 41, pre-flight S-2)**

Tests first. `internal/secrets/backupkey_test.go` (update the existing tests to the new signature, never drop one): `TestNewBackupKeyReturnsTheSenderKey` (the returned key's public half equals `SenderPublicKey` and differs from `PublicKey`; `Version` is 2), `TestWrappedKeyV2BindsSender` (changing `SenderPublicKey` or `PublicKey` in the clear makes `Unwrap` return `ErrDecrypt`), `TestUnwrapRefusesVersion1` (`Version: 1`, or a missing `SenderPublicKey` → `ErrDecrypt`), `TestUnwrapChecksThePublicKey` (a record whose ciphertext, sealed with the v2 AAD through an `export_test.go` helper, holds another private key → `ErrDecrypt`). `internal/setup/setup_integration_test.go`: the existing `Unwrap` assertions keep passing; new `TestRecoveryPassphraseStoresTheSenderKey` (after the step, `backup.sender` opens through the keyring to 32 bytes whose X25519 public key equals `backup.key`'s `sender_public_key`; the raw `setting_secrets` row does not contain those bytes; a second call still returns `ErrPassphraseAlreadySet` and writes nothing).

Implement. `internal/secrets/backupkey.go`: `WrappedBackupKey` gains `SenderPublicKey []byte` with the tag `json:"sender_public_key"` as its last field; `NewBackupKey(passphrase, p)` generates the recipient pair R and the sender pair S, wraps R's private key under Argon2id(passphrase) with the AAD `"alice/backup-key/v2" ‖ R_pub ‖ S_pub`, and returns `Version: 2` plus S's private key (it stores nothing); `Unwrap` accepts only `Version == 2` with 32-byte `PublicKey` and `SenderPublicKey` (anything else `ErrDecrypt`), opens with the v2 AAD and checks that the unwrapped key's public half equals `PublicKey` (else `ErrDecrypt`); the v1 AAD constant goes (no format-1 file or key exists outside development databases). `internal/setup/passphrase.go`: `SetRecoveryPassphrase` takes the sender key from `NewBackupKey` and, in the same transaction as `backup.key`, stores its 32 bytes with `s.keyring.PutSetting(ctx, tx, "backup.sender", secrets.NewPlaintext(…), now)` (as `notify.Settings` stores the SMTP password), then clears them. Development databases that already hold a v1 `backup.key` stop backing up (`ErrNotConfigured` in Task 4) until the wizard is re-run; the e2e stack resets per test.

Run: `go test ./internal/secrets/ -count=1 && go test -tags integration ./internal/setup/ -count=1` (Docker: testcontainers)
Expected: FAIL before the change (unknown field, wrong number of results), `ok` after it.

- [ ] **Step 2: Write the failing tests**

`internal/backup/format/export_test.go`:

```go
package format

import (
	"crypto/ecdh"
	"io"
)

// NewWriterWithRand builds a writer whose ephemeral key and nonce prefix come from rnd (known-answer tests).
func NewWriterWithRand(w io.Writer, wrapped WrappedKey, sender *ecdh.PrivateKey, m Meta, rnd io.Reader) (*Writer, error) {
	return newWriter(w, wrapped, sender, m, rnd)
}

// BufferCap is the capacity of the reader's chunk buffer (the one-chunk memory bound).
func (r *Reader) BufferCap() int { return cap(r.buf) }
```

(`WrappedKey` is a type alias `type WrappedKey = secrets.WrappedBackupKey` declared in `format.go`.)

`internal/backup/format/format_test.go` (the essential cases; add table rows freely, never remove one):

```go
package format_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/rand/v2"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/backup/format"
	"alice/internal/secrets"
)

var (
	pass    = []byte("correct-horse-battery-2026 backup")
	fastKDF = secrets.KDFParams{MemoryKiB: 8 * 1024, Time: 1, Threads: 1}
	meta    = format.Meta{AliceVersion: "1.0.0", CreatedAt: time.Date(2026, 10, 10, 2, 30, 0, 0, time.UTC), Kind: "auto"}
)

// installKey is what the recovery-passphrase step stores: the wrapped key (backup.key) and the sender key (backup.sender).
type installKey struct {
	w secrets.WrappedBackupKey
	s *ecdh.PrivateKey
}

func wrapped(t testing.TB) installKey {
	t.Helper()
	w, s, err := secrets.NewBackupKey(pass, fastKDF)
	require.NoError(t, err)
	return installKey{w: w, s: s}
}

func seal(t testing.TB, k installKey, plain []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	wr, err := format.NewWriter(&out, k.w, k.s, meta)
	require.NoError(t, err)
	_, err = wr.Write(plain)
	require.NoError(t, err)
	require.NoError(t, wr.Close())
	return out.Bytes()
}

func open(file, passphrase []byte) ([]byte, error) {
	r, _, err := format.Open(bytes.NewReader(file), passphrase)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

func payload(n int) []byte {
	p := make([]byte, n)
	rnd := rand.New(rand.NewPCG(1, uint64(n)))
	for i := range p {
		p[i] = byte(rnd.Uint32())
	}
	return p
}

func TestRoundTrip(t *testing.T) {
	w := wrapped(t)
	for _, n := range []int{0, 1, format.ChunkSize - 1, format.ChunkSize, format.ChunkSize + 1, 3 * format.ChunkSize, 1<<20 + 3} {
		plain := payload(n)
		file := seal(t, w, plain)
		got, err := open(file, pass)
		require.NoError(t, err, "size %d", n)
		assert.Equal(t, plain, got, "size %d", n)
		chunks := n/format.ChunkSize + 1 // a payload that fills its last chunk gets an empty final chunk
		hdr, err := format.ReadHeader(bytes.NewReader(file))
		require.NoError(t, err)
		assert.Equal(t, headerLen(t, file)+n+16*chunks, len(file), "size %d: framing", n)
		assert.Equal(t, meta.Kind, hdr.Kind)
	}
}

func headerLen(t testing.TB, file []byte) int {
	t.Helper()
	require.GreaterOrEqual(t, len(file), 14)
	return 14 + int(binary.BigEndian.Uint32(file[10:14]))
}

// TestKnownAnswer rebuilds a file with an independent reference implementation of C7 (written here from the
// primitives, not from the package) and requires byte equality; the committed SHA-256 catches format drift.
// Everything is deterministic: fixed recipient and sender keys, a fixed wrapped-key record (the writer only copies it)
// and a seeded ChaCha8 stream for the ephemeral key and the nonce prefix.
func TestKnownAnswer(t *testing.T) {
	var kat struct {
		Seed       byte   `json:"seed"`
		PlainSize  int    `json:"plain_size"`
		FileSHA256 string `json:"file_sha256"`
	}
	raw, err := os.ReadFile("testdata/kat-v2.json")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &kat))

	priv, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{0x42}, 32))
	require.NoError(t, err)
	sender, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{0x43}, 32))
	require.NoError(t, err)
	w := secrets.WrappedBackupKey{Version: 2, PublicKey: priv.PublicKey().Bytes(), KDF: fastKDF,
		Salt: bytes.Repeat([]byte{1}, 16), Nonce: bytes.Repeat([]byte{2}, 12), Ciphertext: bytes.Repeat([]byte{3}, 48),
		SenderPublicKey: sender.PublicKey().Bytes()}
	plain := payload(kat.PlainSize)
	rnd := func() io.Reader { return rand.NewChaCha8([32]byte{kat.Seed}) }

	var got bytes.Buffer
	wr, err := format.NewWriterWithRand(&got, w, sender, meta, rnd())
	require.NoError(t, err)
	_, err = wr.Write(plain)
	require.NoError(t, err)
	require.NoError(t, wr.Close())

	require.Equal(t, reference(t, w, sender, plain, rnd()), got.Bytes(), "the package and the reference implementation disagree")
	sum := sha256.Sum256(got.Bytes())
	assert.Equal(t, kat.FileSHA256, hex.EncodeToString(sum[:]), "the file bytes changed: a format change needs Version 3")

	r, _, err := format.OpenWithKey(bytes.NewReader(got.Bytes()), priv, sender.PublicKey())
	require.NoError(t, err)
	back, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.Equal(t, plain, back)
}

// reference is C7 written out by hand. It never checks that sender matches w.SenderPublicKey, so the forgery test can
// use it as an attacker's writer.
func reference(t testing.TB, w secrets.WrappedBackupKey, sender *ecdh.PrivateKey, plain []byte, rnd io.Reader) []byte {
	t.Helper()
	seed := make([]byte, 32) // the ephemeral private key: 32 bytes from rnd (GenerateKey ignores its reader since Go 1.26)
	_, err := io.ReadFull(rnd, seed)
	require.NoError(t, err)
	eph, err := ecdh.X25519().NewPrivateKey(seed)
	require.NoError(t, err)
	prefix := make([]byte, 4)
	_, err = io.ReadFull(rnd, prefix)
	require.NoError(t, err)
	recipient, err := ecdh.X25519().NewPublicKey(w.PublicKey)
	require.NoError(t, err)
	shared, err := eph.ECDH(recipient)
	require.NoError(t, err)
	authShared, err := sender.ECDH(recipient) // the second Diffie-Hellman: origin authentication (R43 row 41)
	require.NoError(t, err)
	salt := append(append(append([]byte{}, eph.PublicKey().Bytes()...), w.PublicKey...), w.SenderPublicKey...)
	key, err := hkdf.Key(sha256.New, append(shared, authShared...), salt, "alice/backup/v2", 32)
	require.NoError(t, err)

	hj, err := json.Marshal(struct {
		AliceVersion string                   `json:"alice_version"`
		CreatedAt    string                   `json:"created_at"`
		Kind         string                   `json:"kind"`
		Recipient    []byte                   `json:"recipient"`
		Ephemeral    []byte                   `json:"ephemeral"`
		WrappedKey   secrets.WrappedBackupKey `json:"wrapped_key"`
		ChunkSize    int                      `json:"chunk_size"`
		NoncePrefix  []byte                   `json:"nonce_prefix"`
	}{meta.AliceVersion, meta.CreatedAt.Format(time.RFC3339), meta.Kind, w.PublicKey, eph.PublicKey().Bytes(), w,
		format.ChunkSize, prefix})
	require.NoError(t, err)
	var out bytes.Buffer
	out.WriteString("ALICEBK1")
	out.Write(binary.BigEndian.AppendUint16(nil, 2))
	out.Write(binary.BigEndian.AppendUint32(nil, uint32(len(hj))))
	out.Write(hj)
	hh := sha256.Sum256(out.Bytes())

	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)
	for i := uint64(0); ; i++ {
		// A chunk is final when fewer than ChunkSize bytes remain before sealing it, so a payload that ends on a
		// chunk boundary is followed by an empty final chunk.
		final := len(plain) < format.ChunkSize
		n := min(format.ChunkSize, len(plain))
		flag := byte(0)
		if final {
			flag = 1
		}
		nonce := binary.BigEndian.AppendUint64(append([]byte{}, prefix...), i)
		out.Write(gcm.Seal(nil, nonce, plain[:n], append(hh[:], flag)))
		plain = plain[n:]
		if final {
			return out.Bytes()
		}
	}
}
```

The package's header struct marshals its fields in exactly this order with these tags (`[]byte` fields as standard base64), so the bytes are equal.

```go
func TestHeaderCarriesNoPayloadOrSecret(t *testing.T) {
	w := wrapped(t)
	canary := []byte("CANARY-installation-ALICE-7F3K-host-alice01")
	file := seal(t, w, bytes.Repeat(canary, 100))
	hdr := file[:headerLen(t, file)]
	assert.NotContains(t, string(hdr), "CANARY")
	assert.NotContains(t, string(file), string(pass))
	assert.NotContains(t, string(file), "CANARY")
}

func TestWrongPassphrase(t *testing.T) {
	file := seal(t, wrapped(t), payload(1000))
	_, err := open(file, []byte("not the passphrase at all"))
	require.ErrorIs(t, err, format.ErrDecrypt)
}

// R43 row 41 (pre-flight S-2): whoever copied the clear wrapped key of a genuine file cannot build a file that the
// passphrase opens; without the installation's sender private key the second Diffie-Hellman differs.
func TestForgedBackupWithCopiedWrappedKeyFails(t *testing.T) {
	k := wrapped(t)
	hdr, err := format.ReadHeader(bytes.NewReader(seal(t, k, payload(10))))
	require.NoError(t, err)
	attacker, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{0x66}, 32))
	require.NoError(t, err)
	plain := []byte("CANARY a chosen master.key and administrators")

	// The copied wrapped key unchanged, the attacker's own key for the second Diffie-Hellman.
	forged := reference(t, hdr.WrappedKey, attacker, plain, rand.NewChaCha8([32]byte{9}))
	got, err := open(forged, pass)
	require.ErrorIs(t, err, format.ErrDecrypt)
	assert.Nil(t, got)

	// The copied wrapped key with the attacker's sender public key put in: the passphrase no longer opens it.
	swapped := hdr.WrappedKey
	swapped.SenderPublicKey = attacker.PublicKey().Bytes()
	forged = reference(t, swapped, attacker, plain, rand.NewChaCha8([32]byte{9}))
	got, err = open(forged, pass)
	require.ErrorIs(t, err, format.ErrDecrypt)
	assert.Nil(t, got)
}

func TestWriterRefusesAnotherSenderKey(t *testing.T) {
	k, other := wrapped(t), wrapped(t)
	_, err := format.NewWriter(io.Discard, k.w, other.s, meta)
	require.Error(t, err)
}

func TestNotBackupAndNewer(t *testing.T) {
	file := seal(t, wrapped(t), payload(10))
	newer := append([]byte{}, file...)
	binary.BigEndian.PutUint16(newer[8:10], 3)
	older := append([]byte{}, file...)
	binary.BigEndian.PutUint16(older[8:10], 1) // no format 1 was ever released (R43 row 41)
	for name, c := range map[string]struct {
		in   []byte
		want error
	}{
		"empty":   {nil, format.ErrNotBackup},
		"text":    {[]byte("hello, this is a text file\n"), format.ErrNotBackup},
		"pdf":     {[]byte("%PDF-1.7\n%âãÏÓ\n1 0 obj"), format.ErrNotBackup},
		"magic":   {file[:8], format.ErrNotBackup},
		"newer":   {newer, format.ErrNewerFormat},
		"older":   {older, format.ErrHeader},
	} {
		_, err := open(c.in, pass)
		assert.ErrorIs(t, err, c.want, name)
	}
}

// F-81: one flipped byte anywhere fails; no altered plaintext is ever returned.
func TestEveryFlippedByteFails(t *testing.T) {
	w := wrapped(t)
	plain := payload(2*format.ChunkSize + 1000)
	file := seal(t, w, plain)
	hl := headerLen(t, file)
	chunk := format.ChunkSize + 16
	positions := []int{}
	for i := 0; i < hl; i++ { // every header byte: magic, version, length, JSON (KDF, salt, keys, prefix)
		positions = append(positions, i)
	}
	for _, b := range []int{hl, hl + chunk, hl + 2*chunk} { // around every chunk boundary
		for d := -16; d < 16; d++ {
			if p := b + d; p >= hl && p < len(file) {
				positions = append(positions, p)
			}
		}
	}
	positions = append(positions, hl+chunk/2, len(file)-1)
	for _, p := range positions {
		bad := append([]byte{}, file...)
		bad[p] ^= 0x01
		got, err := open(bad, pass)
		require.Error(t, err, "flipped byte %d was accepted", p)
		assert.Nil(t, got)
		assert.True(t, errors.Is(err, format.ErrNotBackup) || errors.Is(err, format.ErrNewerFormat) ||
			errors.Is(err, format.ErrHeader) || errors.Is(err, format.ErrDecrypt) || errors.Is(err, format.ErrTruncated),
			"byte %d: unexpected error %v", p, err)
	}
}

// F-82 and B-2: truncation anywhere, a missing final chunk, reordered or foreign chunks, trailing data.
func TestTruncationAndReorderFail(t *testing.T) {
	w := wrapped(t)
	file := seal(t, w, payload(3*format.ChunkSize+5))
	other := seal(t, w, payload(3*format.ChunkSize+5)) // same recipient, another ephemeral key
	hl, chunk := headerLen(t, file), format.ChunkSize+16
	c := func(f []byte, i int) []byte { return f[hl+i*chunk : min(hl+(i+1)*chunk, len(f))] }
	cases := map[string][]byte{
		"inside header":        file[:hl-1],
		"no chunk":             file[:hl],
		"inside first chunk":   file[:hl+100],
		"at a chunk boundary":  file[:hl+2*chunk],
		"final chunk removed":  file[:hl+3*chunk],
		"one byte short":       file[:len(file)-1],
		"swapped chunks":       concat(file[:hl], c(file, 1), c(file, 0), c(file, 2), c(file, 3)),
		"foreign chunk":        concat(file[:hl], c(other, 0), c(file, 1), c(file, 2), c(file, 3)),
		"duplicated chunk":     concat(file[:hl], c(file, 0), c(file, 0), c(file, 1), c(file, 2), c(file, 3)),
		"trailing data":        concat(file, []byte{0}),
		"final chunk repeated": concat(file, c(file, 3)),
	}
	for name, f := range cases {
		got, err := open(f, pass)
		assert.Error(t, err, name)
		assert.Nil(t, got, name)
	}
}

func concat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

// FuzzBackupHeader's bounds, as a table (§25.6: a hostile header never makes Argon2 or the reader allocate unbounded memory).
func TestHeaderBounds(t *testing.T) {
	w := wrapped(t)
	file := seal(t, w, payload(10))
	hl := headerLen(t, file)
	var h map[string]any
	require.NoError(t, json.Unmarshal(file[14:hl], &h))
	mutate := func(f func(map[string]any)) []byte {
		c := deepCopy(t, h)
		f(c)
		j, err := json.Marshal(c)
		require.NoError(t, err)
		out := append([]byte{}, file[:10]...)
		out = binary.BigEndian.AppendUint32(out, uint32(len(j)))
		return append(append(out, j...), file[hl:]...)
	}
	kdf := func(k string, v float64) func(map[string]any) {
		return func(m map[string]any) { m["wrapped_key"].(map[string]any)["kdf"].(map[string]any)[k] = v }
	}
	cases := map[string][]byte{
		"memory 4 GiB":        mutate(kdf("memory_kib", 4<<20)),
		"memory 1 KiB":        mutate(kdf("memory_kib", 1)),
		"1000 iterations":     mutate(kdf("time", 1000)),
		"64 lanes":            mutate(kdf("threads", 64)),
		"1 MiB chunks":        mutate(func(m map[string]any) { m["chunk_size"] = 1 << 20 }),
		"unknown field":       mutate(func(m map[string]any) { m["extra"] = true }),
		"missing field":       mutate(func(m map[string]any) { delete(m, "ephemeral") }),
		"recipient mismatch":  mutate(func(m map[string]any) { m["recipient"] = m["ephemeral"] }),
		"wrapped key v1":      mutate(func(m map[string]any) { m["wrapped_key"].(map[string]any)["version"] = 1 }),
		"no sender key":       mutate(func(m map[string]any) { delete(m["wrapped_key"].(map[string]any), "sender_public_key") }),
		"sender is recipient": mutate(func(m map[string]any) { m["wrapped_key"].(map[string]any)["sender_public_key"] = m["recipient"] }),
		"short nonce prefix":  mutate(func(m map[string]any) { m["nonce_prefix"] = "AAA=" }),
		"bad kind":            mutate(func(m map[string]any) { m["kind"] = "../../etc" }),
		"header length 0":     append(append(append([]byte{}, file[:10]...), 0, 0, 0, 0), file[hl:]...),
		"header length 65537": append(append([]byte{}, file[:10]...), 0, 1, 0, 1),
		"header length 4 GiB": append(append([]byte{}, file[:10]...), 0xff, 0xff, 0xff, 0xff),
	}
	for name, f := range cases {
		_, err := format.ReadHeader(bytes.NewReader(f))
		assert.ErrorIs(t, err, format.ErrHeader, name)
	}
}

func TestReaderHoldsOneChunk(t *testing.T) {
	w := wrapped(t)
	r, _, err := format.Open(bytes.NewReader(seal(t, w, payload(5*format.ChunkSize))), pass)
	require.NoError(t, err)
	_, err = io.Copy(io.Discard, r)
	require.NoError(t, err)
	assert.LessOrEqual(t, r.BufferCap(), format.ChunkSize+16)
}

func TestWriterRejectsUseAfterClose(t *testing.T) {
	var out bytes.Buffer
	k := wrapped(t)
	wr, err := format.NewWriter(&out, k.w, k.s, meta)
	require.NoError(t, err)
	require.NoError(t, wr.Close())
	require.NoError(t, wr.Close()) // idempotent
	_, err = wr.Write([]byte("x"))
	require.Error(t, err)
}
```

(`deepCopy` round-trips through JSON. `testdata/kat-v2.json` holds `{"seed": 7, "plain_size": 200000, "file_sha256": ""}` until Step 4 writes the hash the first green run prints.)

`internal/backup/format/fuzz_test.go`:

```go
package format_test

// FuzzBackupHeader (§25.6): any input either parses within the bounds of C7 or is refused with one of the
// documented errors; never a panic, never a header longer than MaxHeaderLen read into memory.
func FuzzBackupHeader(f *testing.F) {
	w := wrapped(f)
	file := seal(f, w, payload(10))
	f.Add(file)
	f.Add(file[:20])
	f.Add([]byte("ALICEBK1"))
	f.Fuzz(func(t *testing.T, b []byte) {
		h, err := format.ReadHeader(bytes.NewReader(b))
		if err != nil {
			if !(errors.Is(err, format.ErrNotBackup) || errors.Is(err, format.ErrNewerFormat) || errors.Is(err, format.ErrHeader)) {
				t.Fatalf("undocumented error %v", err)
			}
			return
		}
		k := h.WrappedKey.KDF
		if k.MemoryKiB < format.MinKDFMemoryKiB || k.MemoryKiB > format.MaxKDFMemoryKiB || k.Time > format.MaxKDFTime ||
			k.Threads > format.MaxKDFThreads || h.ChunkSize != format.ChunkSize {
			t.Fatalf("header outside the bounds was accepted: %+v", k)
		}
	})
}

// FuzzBackupStream: whatever happens to a valid file, Open either fails or returns exactly the original payload.
func FuzzBackupStream(f *testing.F) {
	w := wrapped(f)
	priv, err := w.w.Unwrap(pass)
	require.NoError(f, err)
	plain := payload(2*format.ChunkSize + 77)
	file := seal(f, w, plain)
	f.Add(file, uint32(0), byte(0), uint32(len(file)))
	f.Fuzz(func(t *testing.T, base []byte, pos uint32, xor byte, cut uint32) {
		b := append([]byte{}, file...)
		if len(base) > 0 { // let the fuzzer also try arbitrary files
			b = base
		}
		if len(b) > 0 {
			b[int(pos)%len(b)] ^= xor
			b = b[:int(cut)%(len(b)+1)]
		}
		r, _, err := format.OpenWithKey(bytes.NewReader(b), priv, w.s.PublicKey())
		if err != nil {
			return
		}
		got, err := io.ReadAll(r)
		if err == nil && !bytes.Equal(got, plain) {
			t.Fatalf("a modified file decrypted to other data (%d bytes)", len(got))
		}
	})
}
```

Run: `go test ./internal/backup/format/ -count=1`
Expected: FAIL (`package alice/internal/backup/format: no non-test Go files` or undefined names).

- [ ] **Step 3: Implement**

`format.go`: the types and errors of the Interfaces block; `newWriter` refuses a `sender` whose public half is not `wrapped.SenderPublicKey` (an error naming no key bytes), reads 32 bytes from `rnd` for the ephemeral private key (`ecdh.X25519().NewPrivateKey`; `GenerateKey` ignores its reader since Go 1.26, so it cannot give known answers), then the 4-byte nonce prefix; `NewWriter` passes `crypto/rand.Reader`, derives the file key with `hkdf.Key(sha256.New, X25519(e,R) || X25519(S,R), e||R||S_pub, "alice/backup/v2", 32)` (C7), writes the header (an ordered struct marshalled by `encoding/json`, `Version` = 2 big-endian, length big-endian), keeps `SHA-256(header bytes)` as the AAD base, buffers plaintext up to `ChunkSize`, seals a full buffer with flag 0 only when more data arrives; on `Close` a buffer of fewer than `ChunkSize` bytes (possibly none) is sealed with flag 1, and a **full** buffer is sealed with flag 0 followed by an empty chunk with flag 1 (so a payload that ends on a boundary carries one extra 16-byte chunk, as `TestRoundTrip` and the reference implementation expect; M-8); the file key and both ECDH secrets are cleared (`clear`) on `Close`. `ReadHeader` reads exactly 14 bytes, checks magic (`ErrNotBackup`), version (> 2 `ErrNewerFormat`, < 2 `ErrHeader`), length `1..MaxHeaderLen` (`ErrHeader`, checked **before** allocating), then `json.Decoder.DisallowUnknownFields` into a struct whose fields are pointers or carry a `required` check (missing field → `ErrHeader`), then `bounds.go` (all C7 bounds, base64 lengths 32/32/32/16/12/48/4, `wrapped_key.version == 2`, `wrapped_key.public_key == recipient`, `sender_public_key != recipient`, `kind`/`alice_version` patterns). `Open` = `ReadHeader` + `WrappedKey.Unwrap(passphrase)` (any failure → `ErrDecrypt`; a successful unwrap authenticates `SenderPublicKey`) + `OpenWithKey(r, priv, that sender key)`; `OpenWithKey` checks that `priv.PublicKey()` equals `Recipient` and that the header's `sender_public_key` equals its `sender` argument (else `ErrDecrypt`), derives the key and returns a `Reader` that reads `ChunkSize+16` bytes at a time with one byte of look-ahead to know whether a chunk is the last: a short read (fewer than `ChunkSize+16` bytes) or a full block followed by EOF is opened with flag 1, a full block followed by more data with flag 0; an open failure is `ErrDecrypt`; EOF without any final chunk is `ErrTruncated`; data after a chunk that opened with flag 1 is `ErrTrailingData`. A failed `Read` keeps returning the same error. Header errors wrap the cause (`fmt.Errorf("%w: kdf memory %d KiB", ErrHeader, …)`); messages never contain key material.

- [ ] **Step 4: Run the tests, write the golden hash**

Run: `go test ./internal/backup/format/ -count=1 -run TestKnownAnswer -v`
Expected: the package/reference equality passes and the golden comparison fails with the actual hash; write that hash into `testdata/kat-v2.json`, then:

Run: `go test ./internal/backup/format/ -count=1 -race`
Expected: `ok  alice/internal/backup/format`.

Run (5 minutes each): `go test -count=1 -run '^$' -fuzz FuzzBackupHeader -fuzztime 5m ./internal/backup/format/ && go test -count=1 -run '^$' -fuzz FuzzBackupStream -fuzztime 5m ./internal/backup/format/`
Expected: `PASS` twice; a crasher found is fixed and its `testdata/fuzz/…` file committed as a regression case.

Run: `go test ./internal/archtest/ ./internal/secrets/ -count=1 && go test -tags integration ./internal/setup/ -count=1 && golangci-lint run ./internal/backup/... ./internal/archtest/... ./internal/secrets/... ./internal/setup/...` (Docker: testcontainers)
Expected: `ok` and no findings.

- [ ] **Step 5: Commit**

```bash
git add -- internal/backup/format
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(backup): encrypted backup container v2 (R4, SEC-048, R43 row 41): X25519 to the backup key plus the installation sender key, HKDF file key, 64 KiB AES-256-GCM chunks with final flag; bounded header; KAT, tamper, truncation, forgery tests; FuzzBackupHeader, FuzzBackupStream" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- internal/backup/format internal/archtest/arch_test.go \
  internal/secrets/backupkey.go internal/secrets/backupkey_test.go internal/secrets/export_test.go \
  internal/setup/passphrase.go internal/setup/setup_integration_test.go
```

---

### Task 2: `internal/backup/dump`: framed payload and the consistent logical dump and load

**Files:**
- Create: `internal/backup/dump/frames.go`, `dump.go`, `load.go`, `frames_test.go`, `fuzz_test.go`, `dump_integration_test.go`

**Interfaces:**
- Consumes: `db.SchemaVersion`, `db.MigrateTo` (Task 3 — if Task 3 has not landed when Step 3 starts, the implementer waits for its commit; Steps 1–2 do not need it), `pgtest.New`, `pgx.Identifier`.
- Produces (C7): `dump.Kind` constants `Manifest = 'M'`, `TableStart = 'T'`, `Data = 'D'`, `TableEnd = 'E'`, `Sequences = 'Q'`, `File = 'F'`, `End = 'Z'`; `MaxName = 255`, `MaxData = 1 << 20`; `Encoder` (`NewEncoder(io.Writer)`, `Frame(kind Kind, name string, data []byte) error`, `JSON(kind Kind, name string, v any) error`); `Decoder` (`NewDecoder(io.Reader)`, `Next() (Frame, error)`, `Frame{Kind, Name string; Data []byte}`); `ErrPayload`; `Table{Name string; Columns []string}`; `Tables(ctx, q db.Querier) ([]Table, error)`; `Counts(ctx, q, tables) (map[string]int64, error)`; `Dump(ctx context.Context, tx pgx.Tx, enc *Encoder, tables []Table) (Stats, error)` (T/D/E per table, then Q); `Load(ctx context.Context, conn *pgx.Conn, dec *Decoder, first Frame) (Stats, error)` (consumes T/D/E…Q and returns on the first frame of another kind, which `Stats.Next` holds; the `T` names must be strictly ascending and equal to `Tables` of the target, and the `Q` keys equal to the target's public sequences, else `ErrSchemaMismatch` — S-14); `Stats{Tables int; Rows map[string]int64; Next Frame}`; `ErrSchemaMismatch`.

- [ ] **Step 1: Write the failing tests**

`frames_test.go`: `TestFramesRoundTrip` (every kind, empty data, a 1 MiB data frame, a 255-byte UTF-8 name), `TestDecoderRefuses` (table: unknown kind, name of 256 bytes, data length 1 MiB + 1 (refused before allocating), truncated length field, truncated data, invalid UTF-8 name, a `D` frame before any `T`, an `E` whose name differs from the open `T`, a second `M`, anything after `Z`) → `ErrPayload`. `fuzz_test.go`: `FuzzDecoder` (seed: a valid stream; property: never panics, never allocates a frame above `MaxData`, `Next` on an error keeps returning an error).

`dump_integration_test.go` (`//go:build integration`, `TestMain` → `pgtest.Main`):

- `TestTablesListsEveryOrdinaryTable`: `Tables` returns every relation of `pg_class` with `relkind IN ('r','p')` in schema `public` except `goose_db_version`, sorted by name, each with its non-dropped, non-generated columns in `attnum` order; the test computes the same list with its own catalog query.
- `TestDumpLoadRoundTripsEveryTable`: on database A (`pgtest.New`) insert at least one row into every table that the setup and seed helpers can fill (users with MFA, settings, audit rows through `audit.Log`, targets and certificates through `internal/testutil/seed`, a `jobs` row, a `setting_secrets` envelope); dump with the **app** pool inside `BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY`; load into database B (a fresh `pgtest.New`: migrations seed nothing, so it is empty; the test asserts every row count is 0 and does not truncate, because `audit_log_no_truncate` refuses TRUNCATE outside `session_replication_role = replica` — M-26) with the owner pool under `SET session_replication_role = replica`; for every table, `SELECT md5(coalesce(string_agg(t::text, ',' ORDER BY t::text), '')) FROM <table> t` is equal in A and B; every sequence's `last_value` is equal where the app role can read it; `audit.Verify` on B is intact with the same head.
- `TestF86ConsistentSnapshot`: start a dump whose encoder writes into a pipe that the test drains slowly; while the first table is being copied, 50 goroutines append audit rows and insert `jobs` rows through the app pool and commit; when the dump ends, the rows of each table in the payload equal `Counts` taken in the same transaction at its start, and the loaded `audit_log` verifies (no half-appended chain).
- `TestLoadRefusesASchemaMismatch`: a `T` frame naming a column that B's table lacks, or lacking one B has → `ErrSchemaMismatch`, nothing committed (Load runs inside the caller's transaction; the test rolls it back and checks B is still empty).
- `TestLoadRefusesMissingDuplicateOrUnorderedTables` (S-14): a stream that leaves one table out, repeats one, or orders two the other way → `ErrSchemaMismatch` (missing, unordered) or `ErrPayload` (repeated), nothing committed.
- `TestLoadRefusesMissingSequences` (S-14): a `Q` frame lacking one of the target's public sequences, or naming one it does not have → `ErrSchemaMismatch` (on today's schema, which has no sequence, the test creates one as owner in both databases).
- `TestCopyStatementsQuoteIdentifiers`: as owner, create `public."odd ""table"" name"` with a column `"col ""x"""`, insert a row, dump, load into B (where the test creates the same table) → equal; the generated statement is `COPY public."odd ""table"" name" ("col ""x""") TO STDOUT (FORMAT binary)`.

Run: `go test ./internal/backup/dump/ -count=1 && go test -tags integration ./internal/backup/dump/ -count=1`
Expected: FAIL (no non-test Go files).

- [ ] **Step 2: Implement the frames**

`frames.go`: big-endian lengths, `Encoder` with a 64 KiB `bufio.Writer` and `Flush`, `JSON` marshals then frames; `Decoder` checks kind, name length, UTF-8, data length **before** reading the data, and the order of C7 (it tracks the open table and whether `M` was seen and `Z` reached).

Run: `go test ./internal/backup/dump/ -count=1 -race`
Expected: `ok` for the frame tests.

- [ ] **Step 3: Implement dump and load**

`dump.go`: `Tables` (one catalog query with bind parameters); `copyOut(t Table) string` and `copyIn(t Table) string` build `COPY public.<ident> (<cols>) TO STDOUT (FORMAT binary)` / `… FROM STDIN (FORMAT binary)` with `pgx.Identifier{"public", t.Name}.Sanitize()` and per-column `pgx.Identifier{c}.Sanitize()` joined by `, ` — the single function carries `//nolint:gosec // G202: identifiers are read from pg_catalog and quoted by pgx.Identifier; no value is interpolated`; `Dump` writes `T` (JSON `{name, columns}`), runs `tx.Conn().PgConn().CopyTo(ctx, w, copyOut(t))` with `w` an `io.Writer` that cuts the stream into `D` frames of at most `MaxData`, then `E` (JSON `{rows}` from the command tag), and finally `Q` from `SELECT sequencename, last_value FROM pg_sequences WHERE schemaname = 'public' ORDER BY 1`. `load.go`: `Load` checks each `T` against `Tables` of the target (same name, same column list, names strictly ascending, and at the `Q` frame no target table left unseen, else `ErrSchemaMismatch`), checks the `Q` keys against the target's public sequences (`ErrSchemaMismatch`), feeds `CopyFrom` with an `io.Reader` that yields the `D` frames of that table and stops at its `E`, compares the copied row count with `E.rows` (`ErrPayload` if different), then applies `Q` with `SELECT setval($1::regclass, $2, true)` for non-null values (the name is passed as a bind parameter, quoted with `pgx.Identifier{"public", name}.Sanitize()`), and returns at the first frame of another kind. `Load` never sets `session_replication_role` itself: the caller (Task 5) owns the connection's settings and transaction.

Run: `go test -tags integration -race ./internal/backup/dump/ -count=1`
Expected: `ok  alice/internal/backup/dump`.

Run: `go test -count=1 -run '^$' -fuzz FuzzDecoder -fuzztime 2m ./internal/backup/dump/ && golangci-lint run ./internal/backup/...`
Expected: `PASS`, no findings.

- [ ] **Step 4: Commit**

```bash
git add -- internal/backup/dump
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(backup): framed payload stream and a consistent logical dump and load of every table (binary COPY in one REPEATABLE READ snapshot; F-86)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- internal/backup/dump
```

---

### Task 3: Production deployment: release compose, non-superuser owner, one-shot migrations, password files, `ALICE_MIGRATE=external` (P1-01); `db.MigrateTo`, `SchemaVersion`, `LatestVersion`

**Files:**
- Create: `deploy/release/docker-compose.yml`, `deploy/release/env.template`, `deploy/release/postgres/initdb/10-alice-roles.sh`, `cmd/alice/releasecompose_test.go`, `migrations/nonsuperuser_integration_test.go`, `deploy/release/roles_integration_test.go` (package `release`, test-only directory package)
- Modify: `internal/platform/db/db.go` (+ tests), `internal/platform/config/config.go` (+ `config_test.go`; `Load(getenv)` keeps its signature and calls the new `LoadWith(getenv, readFile)`, M-11), `cmd/alice/main.go` (`serve` with `ALICE_MIGRATE=external`; `_ "time/tzdata"`), `cmd/alice/serve_integration_test.go`, `deploy/docker-compose.yml` (volume `alice-backups` mounted at `/opt/alice/backups`, `ALICE_BACKUP_DIR`), `cmd/alice/compose_test.go` (the new volume), `deploy/Dockerfile` and `deploy/dev/check-image.sh` (the image creates `/opt/alice/backups`, M-2), `tools/pincheck/main.go` (+ `main_test.go`: the release compose's image variables, M-1)

**Interfaces:**
- Consumes: goose v3 `Provider.UpTo`, `migrations.FS`, `pgtest`, testcontainers.
- Produces: C3 (compose, configuration), C2 (the role part), `db.MigrateTo(ctx, pool, fsys, version int64) error`, `db.SchemaVersion(ctx, q db.Querier) (int64, error)` (`SELECT coalesce(max(version_id), 0) FROM goose_db_version WHERE is_applied`), `db.LatestVersion(fsys fs.FS) (int64, error)` (the highest `NNNNN_*.sql`), `config.Config{DatabasePasswordFile, MigratePasswordFile string; Migrate string; BackupDir string; TZ *time.Location}`, `config.Load(getenv)` (unchanged signature) and `config.LoadWith(getenv func(string) string, readFile func(string) ([]byte, error))`.

- [ ] **Step 1: Write the failing tests**

`internal/platform/db` (unit + integration): `TestLatestVersionReadsFileNames` (fstest.MapFS with `00001_a.sql`, `00012_b.sql`, `README.md` → 12; a malformed name → error), `TestMigrateToStopsAtVersion` (integration: a fresh database migrated `UpTo(10)` has `SchemaVersion` 10, then `Migrate` → latest).

`internal/platform/config/config_test.go` (the password-file tests call `LoadWith` with a fake reader): `TestDatabasePasswordFromFile` (URL without password + file `s3cret-pw\n` → `DatabaseURL` carries the password, `String()` and `LogValue()` show `xxxxx` (as today), `TestPasswordFileWithPasswordInURLIsRefused`, `TestEmptyOrUnreadablePasswordFileIsRefused` (the error names the variable and not the content), `TestMigrateMode` (`""` → `on-start`, `external`, anything else → error), `TestTimeZone` (`Europe/Istanbul` ok, `Mars/Olympus` → error naming `ALICE_TZ`), `TestBackupDirDefault`.

`cmd/alice/releasecompose_test.go` (parses `deploy/release/docker-compose.yml` with `go.yaml.in/yaml/v3` as `compose_test.go` does):
- `TestReleaseComposeIsHardened`: `postgres` has `command: ["postgres", "-c", "log_error_verbosity=terse", "-c", "password_encryption=scram-sha-256"]` and the healthcheck `pg_isready -h 127.0.0.1 -U postgres -d alice` (S-19); every service has `read_only: true`, `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`, a numeric non-root `user` (`70:70` for postgres, `10001:10001` otherwise), `pull_policy: never`, json-file logging with size limits; `postgres` and `migrate` and `alice-admin` have no `ports`; `alice` publishes exactly `${ALICE_BIND:-0.0.0.0}:${ALICE_PORT:-443}:8443`; `postgres` is only on `backend`; `backend` is `internal: true`; `alice-admin` and `migrate` have `profiles: [admin]`; `migrate` has `restart: "no"`; `alice` depends only on `postgres` (`service_healthy`).
- `TestAliceServiceHoldsNoOwnerCredential`: the `alice` service has no environment key starting with `ALICE_MIGRATE_DATABASE`, no `db_owner_password` or `db_postgres_password` secret, `ALICE_MIGRATE=external`, and its `ALICE_DATABASE_URL` names `alice_app` without a password; only `migrate` and `alice-admin` get `db_owner_password`; only `postgres` gets `db_postgres_password`.
- `TestReleaseComposeMountsMatchTheLayout`: the bind mounts of C3 exactly (`./keys`, `./state`, `./backups`, `./data/postgres`, `./lib/initdb`), secrets are `file: ./secrets/<name>`.
- `TestEnvTemplateHasNoSecret`: `deploy/release/env.template` holds exactly the keys of C2's `.env` and no `PASSWORD`, `SECRET` or `KEY` name.
- `TestRolesScriptKeepsPasswordsOutOfArguments` (S-20): `deploy/release/postgres/initdb/10-alice-roles.sh` contains no `-v .*_pw=` and reads both passwords with psql's `\set … \`cat /run/secrets/…\``.

`cmd/alice/compose_test.go`: the development compose mounts the named volume `alice-backups` at `/opt/alice/backups` and sets `ALICE_BACKUP_DIR` (M-2). `tools/pincheck/main_test.go`: `TestProductionComposeImageVariables` (M-1): in `deploy/release/docker-compose.yml` only, a service image that is exactly `${ALICE_IMAGE}` or `${POSTGRES_IMAGE}` passes (the scripts compare the loaded image IDs with `RELEASE` before starting; R43 row 22); any other unpinned image there, and the same variables in any other compose file, still fail.

`migrations/nonsuperuser_integration_test.go`: `TestMigrationsRunAsNonSuperuserOwner`: as the container superuser create role `t_owner LOGIN CREATEDB NOSUPERUSER PASSWORD '0wner-pw'`, `GRANT SET ON PARAMETER session_replication_role TO t_owner`, `CREATE DATABASE t_nonsuper OWNER t_owner`; open it as `t_owner`; `db.Migrate` succeeds (citext is trusted; `alice_app` already exists cluster-wide from the template); `SET session_replication_role = replica` succeeds as `t_owner`; `CREATE DATABASE t_nonsuper_copy` succeeds as `t_owner` and is dropped; the grant guard's `grantProblems` (reuse it) is empty for this database.

`deploy/release/roles_integration_test.go` (`//go:build integration`): `TestReleaseRolesScript` starts `postgres:16-alpine@sha256:721873c3…` with testcontainers as user `70:70`, the role script mounted at `/docker-entrypoint-initdb.d/10-alice-roles.sh`, the three secret files mounted at `/run/secrets/…` (fixture passwords `0wner-pw`, `app-test-pw`, `s3cret-pw`), `POSTGRES_PASSWORD_FILE`; then as `postgres`: `alice_owner` has `rolsuper = false`, `rolcreatedb = true`, `rolcanlogin = true`; `alice_app` can log in and is not superuser; database `alice` is owned by `alice_owner`; `has_parameter_privilege('alice_owner', 'session_replication_role', 'SET')`; connecting as `alice_owner` and as `alice_app` with the file passwords works; `PUBLIC` has no `CREATE` on schema `public`; the server runs with the compose `command` of C3 and `SHOW log_error_verbosity` is `terse`; every `host` rule in `pg_hba_file_rules` has `auth_method = 'scram-sha-256'` (S-19).

`cmd/alice/serve_integration_test.go`: `TestServeRefusesAStaleSchemaWhenMigrationsAreExternal` (a database migrated `UpTo(latest-1)`; `serve` with `ALICE_MIGRATE=external` and no migrate URL returns the C3 error naming both versions and never opens an owner connection — the test's owner URL is not in the configuration at all) and `TestServeWithExternalMigrationsStartsOnACurrentSchema` (migrated to latest → `/healthz` answers 200; no single-role warning in the log).

Run: `go test ./internal/platform/... ./cmd/alice/ ./tools/pincheck/ -count=1 -run 'TestLatestVersion|TestDatabasePassword|TestPasswordFile|TestEmptyOrUnreadable|TestMigrateMode|TestTimeZone|TestBackupDir|TestReleaseCompose|TestAliceServiceHolds|TestEnvTemplate|TestRolesScript|TestCompose|TestProductionComposeImageVariables'`
Expected: FAIL (undefined names; missing files).

- [ ] **Step 2: Implement**

`db.go`: the three functions (goose `NewProvider` as `Migrate` does, `p.UpTo(ctx, version)`). `config.go`: the new fields and checks of C3 (the URL is parsed with `net/url`; the password is set with `url.UserPassword`); `LoadWith(getenv func(string) string, readFile func(string) ([]byte, error))` holds the logic and `Load(getenv)` calls it with `os.ReadFile`, so no existing caller changes (M-11). `deploy/Dockerfile`: `&& mkdir -p /out/keys /out/opt-alice/state && chmod 0700 /out/keys /out/opt-alice/state` becomes `&& mkdir -p /out/keys /out/opt-alice/state /out/opt-alice/backups && chmod 0700 /out/keys /out/opt-alice/state /out/opt-alice/backups` (the existing `COPY --from=build --chown=10001:10001 /out/opt-alice/ /opt/alice/` carries it, so the named volume is 10001-owned on first use); `deploy/dev/check-image.sh` asserts `/opt/alice/backups` exists with mode 0700 and owner 10001. `tools/pincheck`: the release-compose exception of `TestProductionComposeImageVariables`. `main.go`: `serve` branches on `cfg.Migrate == "external"` before the current `migrateWith` call; `import _ "time/tzdata"`. `deploy/release/docker-compose.yml` exactly as C3; `env.template`:

```
# Written by install.sh; no secret belongs in this file.
COMPOSE_PROJECT_NAME=alice
ALICE_IMAGE=alice:VERSION
POSTGRES_IMAGE=alice-postgres:VERSION
ALICE_BIND=0.0.0.0
ALICE_PORT=443
ALICE_TLS_HOSTS=
ALICE_TZ=UTC
```

`10-alice-roles.sh` (runs once inside the postgres entrypoint on an empty data directory; reads the passwords from the secret files; psql variables quoted with `:'var'`):

```sh
#!/bin/sh
# Alice production roles (R43 row 7): a non-superuser owner for migrations and restores, the application role, and the
# database. Runs once, as the postgres image initialises an empty data directory.
set -eu
# The passwords never enter an argument list (S-20): psql reads the secret files itself.
psql -v ON_ERROR_STOP=1 --username postgres --dbname postgres <<'SQL'
\set owner_pw `cat /run/secrets/db_owner_password`
\set app_pw `cat /run/secrets/db_app_password`
CREATE ROLE alice_owner LOGIN CREATEDB NOSUPERUSER NOCREATEROLE NOREPLICATION PASSWORD :'owner_pw';
CREATE ROLE alice_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD :'app_pw';
GRANT SET ON PARAMETER session_replication_role TO alice_owner;
CREATE DATABASE alice OWNER alice_owner;
SQL
psql -v ON_ERROR_STOP=1 --username postgres --dbname alice <<'SQL'
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
ALTER SCHEMA public OWNER TO alice_owner;
SQL
```

(The postgres image's entrypoint runs scripts of `/docker-entrypoint-initdb.d` with the superuser while it listens on a local socket only; psql runs the backquoted `cat` itself, strips the trailing newline and quotes `:'…'` values.)

Run: the Step 1 command again, then `go test -tags integration -count=1 ./internal/platform/db/ ./migrations/ ./deploy/release/ && go test -tags integration -count=1 -run 'TestServeRefusesAStaleSchema|TestServeWithExternalMigrations' ./cmd/alice/` (Docker: testcontainers)
Expected: `ok` for each.

Run: `docker run --rm -v "$PWD/deploy/release/postgres/initdb:/s:ro" koalaman/shellcheck:v0.11.0@sha256:bb596a0d169b85ddd81d8b6d3a2ff6d5baf5fca10b97f575ebc647c3dff62b3d -s sh /s/10-alice-roles.sh && make image image-check && make lint && make test` (Docker: image build)
Expected: no ShellCheck output; lint and tests green.

- [ ] **Step 3: Commit**

```bash
git add -- deploy/release/docker-compose.yml deploy/release/env.template deploy/release/postgres deploy/release/roles_integration_test.go \
  cmd/alice/releasecompose_test.go migrations/nonsuperuser_integration_test.go
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(deploy): production compose with a non-superuser owner, one-shot migrations and password files; the alice container holds no owner credential (P1-01)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- deploy/release/docker-compose.yml deploy/release/env.template \
  deploy/release/postgres deploy/release/roles_integration_test.go cmd/alice/releasecompose_test.go \
  migrations/nonsuperuser_integration_test.go internal/platform/db internal/platform/config cmd/alice/main.go \
  cmd/alice/serve_integration_test.go cmd/alice/compose_test.go deploy/docker-compose.yml deploy/Dockerfile \
  deploy/dev/check-image.sh tools/pincheck
```

---

### Task 4: `internal/backup` part 1: create, list, verify, retention, the daily schedule, failure e-mail and 48-hour alarm (F-70, F-86..F-88)

**Files:**
- Create: `internal/backup/service.go`, `names.go`, `schedule.go`, `state.go`, `manifest.go`, `task.go`, `templates.go`, `export_test.go`, `schedule_test.go`, `names_test.go`, `state_test.go`, `service_integration_test.go`
- Modify: `locales/common/en.json`, `locales/common/tr.json` (`email.backup.failed.*`, `email.backup.alarm.*`), `internal/notify` template registry if templates are registered there (read how `alerts` registers `alert.*` templates and do the same)

**Interfaces:**
- Consumes: `format` (Task 1), `dump` (Task 2), `db.SchemaVersion` (Task 3), `settings.Get/Set`, `audit.Log.Append`, `notify.AdminNotifier.NotifyAdmins`, `secrets.WrappedBackupKey` v2 (setting `backup.key`) and the sender key (`Keyring.GetSetting("backup.sender")`, Task 1), `license` installation row (read the Installation ID with the query `license` uses), `secrets.MasterKeyFile`, `license.HWMFileName`.
- Produces: C8 (everything except restore), C14 (`backup.created`, `backup.failed`, `backup.deleted`, `backup.settings_changed`; the two e-mails), C7 file names and manifest.

- [ ] **Step 1: Write the failing unit tests**

`schedule_test.go`:

```go
package backup_test

func mustLoc(t *testing.T, name string) *time.Location {
	t.Helper()
	l, err := time.LoadLocation(name)
	require.NoError(t, err)
	return l
}

func TestLastScheduled(t *testing.T) {
	ist := mustLoc(t, "Europe/Istanbul") // UTC+3, no daylight saving
	now := time.Date(2026, 10, 10, 1, 0, 0, 0, time.UTC) // 04:00 in Istanbul
	assert.Equal(t, time.Date(2026, 10, 9, 23, 30, 0, 0, time.UTC), backup.LastScheduled(now, ist, "02:30"))
	now = time.Date(2026, 10, 9, 23, 29, 0, 0, time.UTC) // 02:29 local: the previous day's run
	assert.Equal(t, time.Date(2026, 10, 8, 23, 30, 0, 0, time.UTC), backup.LastScheduled(now, ist, "02:30"))
}

func TestDueAcrossDaylightSaving(t *testing.T) {
	ny := mustLoc(t, "America/New_York")
	// 2026-03-08: 02:30 does not exist in New York; Go resolves it to 01:30 EST, which is 06:30Z; the run happens once, at that instant.
	spring := time.Date(2026, 3, 8, 8, 0, 0, 0, time.UTC) // 04:00 EDT
	assert.Equal(t, time.Date(2026, 3, 8, 6, 30, 0, 0, time.UTC), backup.LastScheduled(spring, ny, "02:30"))
	// 2026-11-01: 01:30 happens twice; the first one counts and the second does not run again.
	first := time.Date(2026, 11, 1, 5, 30, 0, 0, time.UTC) // 01:30 EDT
	second := time.Date(2026, 11, 1, 6, 40, 0, 0, time.UTC) // 01:40 EST, after the repeat of 01:30
	assert.True(t, backup.Due(first, ny, "01:30", time.Date(2026, 10, 31, 5, 31, 0, 0, time.UTC)))
	assert.False(t, backup.Due(second, ny, "01:30", first.Add(time.Minute)))
}

func TestDue(t *testing.T) {
	utc := time.UTC
	now := time.Date(2026, 10, 10, 10, 0, 0, 0, utc)
	assert.True(t, backup.Due(now, utc, "02:30", time.Time{}), "never backed up")
	assert.True(t, backup.Due(now, utc, "02:30", now.Add(-48*time.Hour)), "missed run catches up at the next check (§20.2)")
	assert.False(t, backup.Due(now, utc, "02:30", time.Date(2026, 10, 10, 2, 31, 0, 0, utc)), "already done today")
	assert.True(t, backup.Due(now, utc, "02:30", time.Date(2026, 10, 10, 2, 29, 0, 0, utc)), "a run before the instant does not count")
	assert.False(t, backup.Due(time.Date(2026, 10, 10, 2, 29, 0, 0, utc), utc, "02:30", time.Date(2026, 10, 9, 2, 31, 0, 0, utc)))
}
```

`names_test.go`: `TestNameFromParts` (`ALICE-7F3K-92QD-M4XT-A81P` + `2026-10-01T02:30:00Z` + `auto` → `alice-backup-7F3K92QD-20261001T023000Z-auto.alicebak`; `pre-upgrade-1.0.0`, `pre-restore`), `TestNameRules` (accepted: the standard names and `before-firewall-change.alicebak`; refused: `../x.alicebak`, `a/b.alicebak`, `.hidden.alicebak`, `x.alicebak\x00`, `x.tar`, a 256-byte name). `state_test.go`: `TestAlarmAfter48Hours` (boundary at exactly 48 h from the last success; with no success ever, from the setup completion time; never before setup is complete).

Run: `go test ./internal/backup/ -count=1`
Expected: FAIL (undefined).

- [ ] **Step 2: Write the failing integration tests**

`service_integration_test.go` (`//go:build integration`; `pgtest.Main`; the service built with the app pool, `clock.NewFake`, `t.TempDir()` directories holding a real `master.key` (from `secrets.LoadOrCreateMasterKey`), `tls.crt`/`tls.key` (from `tlscert.EnsureSelfSigned`) and an `hwm.dat` (a byte fixture); the recovery passphrase set through `setup` with a fast KDF (`setup.Config.BackupKDF = {8 MiB, 1, 1}`), and a recording `notify` sender):

- `TestCreateWritesAVerifiedFile`: `Create(manual)` → the file and its `.sha256` exist with mode 0600, no `.partial` remains, `Verify` says `ok`, `VerifyDeep(passphrase)` returns a manifest whose `tables` equal `dump.Counts` of the database, whose `audit_head` equals the newest audit row (before `backup.created` was appended), whose `installation_id` equals the license row, and whose `files` are the four of C7; one `backup.created` audit row with `name`, `kind`, `size`.
- `TestCreateNeedsTheRecoveryPassphrase`: before the passphrase step → `ErrNotConfigured`, no file.
- `TestCreateRefusesV1BackupKey` (R43 row 41): a `backup.key` of version 1 written into the settings by the test, or a v2 key whose `backup.sender` envelope is missing or belongs to another key → `ErrNotConfigured`, no file, `backup.state.last_error_code = "not_configured"`.
- `TestCreateRefusesWhenTheDiskIsNearlyFull` (S-21, R43 row 46): the `statfs` hook reports less than 2 × the newest backup + 1 GiB → `ErrWrite`, no `.partial` was ever opened, `last_error_code = "disk_full"`, one `backup.failed` row; `FreeBytes` returns the hooked value.
- `TestOneBackupAtATime`: two `Create` calls whose first is held inside the dump by a test hook → the second returns `ErrRunning`.
- `TestF70DiskFullLeavesNothing`: the `create` hook returns a writer that fails with `syscall.ENOSPC` after 100 KiB → `ErrWrite`, no file of that name and no `.partial`, the two earlier backups untouched (bytes and `.sha256`), `backup.state` has `last_error_code = "disk_full"` and one more consecutive failure, one `backup.failed` row.
- `TestF86BackupWhileJobsRun`: 20 goroutines insert jobs and audit rows during `Create` → `VerifyDeep` succeeds and the manifest's table counts equal the counts of the rows in the payload (decode the payload with `dump.Decoder` and count `E.rows`).
- `TestF87NoPlaintextInTheFile`: seed canaries — a user's TOTP secret, the SMTP password (through `notify.Settings.SaveSMTP`), a managed private key (through the certificate upload service with a `pki` key), an OIDC client secret (through `oidc` provider creation if reachable from the test, else a `setting_secrets` envelope via `secrets.Keyring.Seal`), the master key bytes (raw and base64), the passphrase — then `Create`; the file contains none of them (raw, base64, hex) and no `-----BEGIN`; the clear header contains neither the Installation ID nor the host name.
- `TestF88Retention`: with the fake clock, 20 days of `RunScheduled` ticks every 5 minutes → exactly 14 `auto` files remain (the newest), a `manual` and a `pre-upgrade-1.0.0` file made on day 1 remain, six `backup.deleted` rows (`deleted_count` 1 each) exist; then a failing run (disk full) deletes nothing.
- `TestScheduledBackupRunsOncePerDay`: zone `Europe/Istanbul`, time `02:30`, three days of 5-minute ticks → three `auto` backups whose `created_at` is 23:30 UTC ± 5 minutes; a restart (a new service on the same database) in the middle does not add one.
- `TestFailureEmailOncePerEpisodeAndAlarmAt48Hours`: failing creates for 49 hours of ticks → exactly one `backup.failed` e-mail (queued at the first failure) and one `backup.alarm` (queued when 48 hours without success pass), `State.Alarm` true; then a success → state reset, and a new failure later queues `backup.failed` again.
- `TestVerifyShallow`: `missing checksum`, `checksum mismatch` (one byte of the file changed), `unreadable header` (a text file named `x.alicebak`).
- `TestListNewestFirst`, `TestScheduleSettings` (defaults; `SaveSchedule` validates `HH:MM`, a loadable zone and 7–60, bumps the version, audits `backup.settings_changed` with `time`, `zone`, `retention`; a stale version → `ErrVersion`).
- `TestBackupTemplatesRenderInBothLanguages`: `notify.Render` of both templates in `en` and `tr` with every parameter; no `{{` left; subjects one line.

Run: `go test -tags integration ./internal/backup/ -count=1` (Docker: testcontainers)
Expected: FAIL.

- [ ] **Step 3: Implement**

Follow C8's create sequence. Notes: the payload pipeline is `format.Writer` ← `gzip.Writer` ← `dump.Encoder`, written through an `io.MultiWriter` with a `sha256` hash into the partial file; the manifest frame is written first (inside the snapshot transaction, after the counts and the audit head were read); files are read with `os.ReadFile` (each at most 1 MiB, else `ErrWrite` with code `file_too_large`); missing `tls.*` or `hwm.dat` are left out of `files`. Error codes in `backup.state.last_error_code`: `disk_full` (ENOSPC, or the free-space check of C8), `not_configured` (no v2 key or no matching sender key), `database`, `io`, `file_too_large`. `Config.Keyring` opens `backup.sender`; the 32 bytes are cleared after the writer derived its keys. `RunScheduled`: reads the schedule and state, returns at once unless `Due`; a failure records state and e-mails in the same transaction as the state update (`NotifyAdmins`), as `alerts` does. `Prune` runs after each successful `auto` backup with the schedule's retention. Templates: the subjects and bodies in both catalogs (C14), parameters flattened by `notify` as for every other template.

Run: Step 1 and Step 2 commands
Expected: `ok` for both.

Run: `make i18n-check && golangci-lint run ./internal/backup/... && make test`
Expected: green.

- [ ] **Step 4: Commit**

```bash
git add -- internal/backup/service.go internal/backup/names.go internal/backup/schedule.go internal/backup/state.go \
  internal/backup/manifest.go internal/backup/task.go internal/backup/templates.go internal/backup/export_test.go \
  internal/backup/schedule_test.go internal/backup/names_test.go internal/backup/state_test.go internal/backup/service_integration_test.go
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(backup): encrypted backups of database, keys and time record; daily schedule with catch-up, retention of 14, failure e-mail and 48-hour alarm (F-70, F-86..F-88)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- internal/backup locales/common/en.json locales/common/tr.json
```

---

### Task 5: `internal/backup` part 2: restore into a fresh database, verify, swap; `--db-only`; F-80..F-85, F-97

**Files:**
- Create: `internal/backup/restore.go`, `swap.go`, `staging.go`, `restore_integration_test.go`, `f85_integration_test.go` (`//go:build integration && testlicense`)

**Interfaces:**
- Consumes: Task 4's service internals, `format.Open`, `dump.Decoder`/`Load`, `db.MigrateTo`, `db.Migrate`, `db.SchemaVersion`, `db.LatestVersion`, `migrations.FS`, `audit.Verify`, `secrets.LoadOrCreateMasterKey` (read-only check variant, Task 6 adds `secrets.CheckMasterKey`; until then the test calls the key-check path through a small local helper — Task 6 replaces it), the license installation seal check (read the function `license` uses to verify `installation_seal`).
- Produces: C8 restore part, C7 restore messages (as errors; the CLI prints them in Task 6), `system.restored` (the C14 details, including `previous_audit_seq`, `previous_audit_hash`, `safety_backup`, `no_safety_backup`), `FinishInterruptedRestore(ctx, q, keysDir, stateDir)` with the restore-ID rule (R43 row 8), the DDL function of R43 row 48.

- [ ] **Step 1: Write the failing tests**

`restore_integration_test.go` (`//go:build integration`). A helper `snapshot(t, db, keysDir, stateDir)` returns the per-table `md5` of every table, the SHA-256 of every file in the keys and state directories, and the list of databases on the server; `requireUnchanged(t, before, after)` compares them.

- `TestRestoreRoundTrip`: seed, back up, change data (delete a user, add a target), restore → the database equals the snapshot taken right before the backup except `sessions` (empty) and `audit_log` (one more row, `system.restored`); key and state files equal the backed-up ones; `Restore` returns the manifest and a safety backup path whose file verifies.
- `TestF80WrongPassphraseChangesNothing`, `TestF81FlippedByteChangesNothing` (subtests `header`, `salt`, `ciphertext`, `chunk-boundary`: the byte at `14+n-5`, inside the wrapped key's salt, at the middle of chunk 0, and at the first byte of chunk 1), `TestF82TruncatedChangesNothing` (cut inside chunk 1; final chunk removed): each returns `ErrDamaged`, `requireUnchanged`, no `<db>_restore` database left, no `.restore-staging` directory, no safety backup written (the safety backup is written only after the staged data verified).
- `TestF83ForeignAndNewer`: empty file and a text file → `format.ErrNotBackup` and the passphrase callback was never called; a backup whose header says `alice_version` `9.0.0` (made with a service whose `Version` is `9.0.0`) restored by a service of version `1.0.0` → `*ErrNewer{Version: "9.0.0"}` before the passphrase; a backup whose manifest `schema_version` is `LatestVersion+1` (a test hook in `export_test.go` sets it) → `*ErrNewer`; all `requireUnchanged`.
- `TestF84OlderSchemaMigratesForward`: a database migrated `UpTo(LatestVersion-1)` and seeded with rows valid there, backed up by a service on it; restored into a current database → `SchemaVersion` is the latest, the rows are there, `audit.Verify` intact.
- `TestRestoreRefusesABrokenChain`: before the backup, as owner with `session_replication_role = replica`, change one audit row's `details` → restore → `*ErrAuditBroken{Seq: n}`, `requireUnchanged`; with `AcceptBrokenAudit` → restored, and the `system.restored` row has `audit_intact=false`.
- `TestRestoreIsAllOrNothing`: test hooks fail at each point — after the staging load, after `RESTORE_ID` is written, after verification, after the safety backup, after the staging files, after the `previous/` copies and before the database renames, between the two `ALTER`s (only when the fallback without one transaction is in use), after the database renames and before the files, after the files and before the `DROP` → for every point before the database renames: `requireUnchanged` (apart from a safety backup file when the failure came after it) and a following successful `Restore` works; for every later point: after one more `Restore` or a `FinishInterruptedRestore` (what `serve` runs at start) the installation is fully the restored one (`requireUnchanged` against the restored snapshot) and no `_restore`/`_previous_` database or staging directory remains.
- `TestFinishIgnoresStaleStaging` (S-1): staging directories whose `RESTORE_ID` the live database does not carry (another ID, or no `backup.restore_id`) → `FinishInterruptedRestore` returns false, the live files are byte-equal, the staging is gone.
- `TestCleanupNeverDropsTheOnlyCopy` (S-1): no `<db>` database and a `<db>_restore` database (the state between two renames) → the next `Restore`'s cleanup renames it to `<db>`, never drops it.
- `TestRestoreRefusesWhileTheDatabaseIsInUse`: an extra app connection open on the live database with `WaitForSessions: 0` → `ErrDatabaseInUse`, `requireUnchanged`. `TestRestoreWaitsForALeftoverSession` (M-4): a session that ends after 3 s with `WaitForSessions: 10*time.Second` → the restore succeeds.
- `TestRestoreOnAnEmptyServerNeedsOnlyThePassphrase` (R43 row 41): back up; restore into an empty database (no settings at all) with empty keys and state directories, giving only the file and the passphrase → restored; `backup.key` and `backup.sender` are back, and a new `Create` writes a file that opens with the same passphrase and carries the same `sender_public_key`.
- `TestRestoreKeepsTheNewerTimeRecord` (S-5): live time record at T+10d, backup's at T → after the restore both stores decode to T+10d with a higher `Seq`; on an empty host the backup's record is kept.
- `TestRestoreRefusesUnknownFileFrames` (S-14): payloads (built with `dump.Encoder` and the format writer in the test) with an `F` frame named `keys/../../x`, `keys/other`, or a second `keys/master.key` → `ErrDamaged`, `requireUnchanged`, nothing written outside the staging directories. `TestRestoreDropsAMismatchedTLSPair`: a backup whose `tls.key` does not match `tls.crt` → restored, both TLS files absent from the staging and a warning returned.
- `TestRestoreWithoutBackupKeyNeedsTheFlag` (S-17): a live installation with data and no `backup.key` → `ErrNoSafetyBackup`, `requireUnchanged`; with `NoSafetyBackup` → restored, `system.restored` has `safety_backup = none` and `no_safety_backup = true`.
- `TestRestoreCleansUpAfterADatabaseError` (S-22): a hook makes `CopyFrom` return a `53100` `PgError` → the error is returned, `requireUnchanged`, no `_restore` database, no staging. `TestRestoreRefusesWithoutFreeSpace`: `FreeBytes` below 2 × the live database size + 1 GiB → `*ErrNoSpace`, nothing created.
- `TestRestoreWithANonSuperuserOwner`: roles created as in Task 3's `TestMigrationsRunAsNonSuperuserOwner`; `RestoreInput.OwnerURL` uses that owner → works; the previous database is dropped at the end.
- `TestDBOnlyKeepsFiles`: `DBOnly` restore → the database is restored; key and state files are untouched.
- `TestF97RestoreContinuesTheChain`: after a restore, the last audit row is `system.restored` with the backup's name, time, versions, `audit_intact=true`, `previous_audit_seq`/`previous_audit_hash` equal to the live head read before the restore and `safety_backup` naming the `pre-restore` file (S-17); `audit.Verify` is intact; an `audit.Log.Append` afterwards gets the next sequence number.
- `TestRestoreEndsSessions`: sessions and setup sessions of the backup are gone after the restore.

`f85_integration_test.go` (`//go:build integration && testlicense`): `TestF85FullCycle` — seed the §20.6 set through the services and seed helpers: 3 users per role, each with TOTP enrolled; 10 targets (fake provider) with host keys; 50 certificates with private keys (upload service with `pki` pairs); 20 SSH keys (platform-managed and discovered); one rotation in `overlap` (reuse the fixture code of `cmd/alice/rotation_fixture_integration_test.go` or of the `sshkeyjobs` tests; if neither is importable, create it through `sshkeys` service calls with the fake provider); 500 audit rows; a test license (`licensetest` signer) installed; the SMTP password in mail settings. Record: rows per table; the SHA-256 of the decrypted plaintext of every envelope (credentials, managed private keys, TOTP secrets, `setting_secrets`); the audit head; the Installation ID; the license snapshot (phase, license ID, days left). Back up; **wipe**: drop the database and recreate it empty (owner), delete the keys and state directories; restore with the passphrase. Verify: rows per table equal (sessions empty; audit one more row); every decrypted secret's hash equal (proves the master key came back); audit verifies and the head before `system.restored` equals the recorded one; a seeded Operator signs in with password and a TOTP code computed from the restored secret; Installation ID and license snapshot equal; the platform key's envelope decrypts to a private key whose public half equals the recorded platform public key (the live SSH login is `TestReleaseF85Drill`'s); one runner step of the in-progress rotation and one deployment job run against the fake provider and succeed.

Run: `go test -tags integration -count=1 -run 'TestRestore|TestF8|TestDBOnly|TestF97|TestFinish|TestCleanup' ./internal/backup/ && go test -tags 'integration testlicense' -count=1 -run '^TestF85' ./internal/backup/` (Docker: testcontainers)
Expected: FAIL (undefined).

- [ ] **Step 2: Implement**

`restore.go` follows C8/R43 rows 8–9, 41, 42, 45, 46: `ReadHeader` (newer → `ErrNewer`, before asking anything); passphrase → `format.Open` (any error → `ErrDamaged`); the restore prompt passes the raw typed passphrase (stdin: exactly one trailing `\n` stripped), and NFKC normalisation happens only inside `secrets` (Task 1 review I-1). That is all the key material a restore needs: the recipient private key and the authenticated sender public key both come from the file's own wrapped key, so a fresh server with an empty database and no `master.key` restores with the passphrase alone (R43 row 41). Read the manifest frame (newer schema → `ErrNewer`); open the maintenance connection (`OwnerURL` with database `postgres`); wait for other sessions on the live database to end (poll `pg_stat_activity` every 2 s for at most `WaitForSessions`), then refuse `ErrDatabaseInUse` (M-4); when `FreeBytes > 0`, refuse `*ErrNoSpace` below 2 × `pg_database_size(<db>)` + 1 GiB (S-22); the leftover cleanup of `staging.go` (below); `CREATE DATABASE <db>_restore OWNER CURRENT_USER` (through the one DDL function of R43 row 48); `db.MigrateTo(manifest.schema_version)` on it; one connection, one transaction, `SET LOCAL session_replication_role = replica`, `dump.Load`, and in the same transaction the setting `backup.restore_id` = a random 128-bit ID in hex (S-1). Then the `F` frames unless `DBOnly`, mapped through a fixed four-entry table (`keys/master.key`, `keys/tls.crt`, `keys/tls.key` → `<keys>/.restore-staging/<base>`, `state/hwm.dat` → `<state>/.restore-staging/hwm.dat`), never a path join of the name; an unknown or repeated name → `ErrDamaged` (S-14); directories 0700, `master.key`, `tls.key`, `hwm.dat` 0400, `tls.crt` 0644 (E15); each staging directory gets `RESTORE_ID`; contents checked: `master.key` decodes to 32 bytes, `hwm.dat` decodes, `tls.crt`/`tls.key` parse and match — a mismatched pair is dropped with a restore warning so Alice creates a temporary certificate. The `Z` frame must follow (`ErrDamaged` otherwise) and the reader must reach EOF without error (that is where truncation and tag failures surface — nothing has touched the live installation yet). Verification on the staging database (row counts against the manifest, `audit.Verify` intact or `AcceptBrokenAudit`, the audit head equal to the manifest's, the staged `master.key` opens `master_key_versions.key_check`, the installation seal verifies with it) → `*ErrNotVerified`/`*ErrAuditBroken`; `db.Migrate` forward; `DELETE FROM sessions; DELETE FROM setup_sessions; DELETE FROM oidc_login_states`. Time record (S-5, R43 row 42): read the live record (live master key, both stores, highest valid `Seq`; read `internal/license/hwm.go` for the seal); when its `At` is newer than the backup's, re-seal `max(At)` with `Seq = max(Seq)+1` under the restored master key into the staging database's `time.hwm` and the staged `hwm.dat` (no live record: keep the backup's). Read the live audit head (`previous_audit_seq`, `previous_audit_hash`; none on an empty host) and append `system.restored` with the C14 details (as `alice_owner` through `audit.Log.Append` on the staging pool); `Confirm(manifest)` (false → clean up, `ErrCancelled`). Safety backup of the live installation when its database has an installation row (the Task 4 service on the live database, kind `pre-restore`; a database without Alice's tables — the empty one `install.sh --restore-mode` creates — has none, and the missing relation is not an error); a live installation with an installation row but no backup key (`ErrNotConfigured` from the safety backup) refuses with `ErrNoSafetyBackup` unless `NoSafetyBackup` (S-17); the pool opened for the safety backup is closed before the first rename (M-25). `swap.go` (S-1, R43 row 8): copy the live `master.key`, `tls.crt`, `tls.key` and `hwm.dat` into `.restore-staging/previous/` and `fsync`; `BEGIN; ALTER DATABASE <db> RENAME TO <db>_previous_<ts>; ALTER DATABASE <db>_restore RENAME TO <db>; COMMIT` on the maintenance connection (the test proves PostgreSQL 16 accepts both in one transaction; if it does not, the two statements run one after the other and the cleanup rule "no `<db>` while `<db>_restore` exists → finish the rename, never drop" covers the gap — record it in the report); then `FinishInterruptedRestore(ctx, <connection to the new live database>, keys, state)`: the staged files are renamed over the live ones (`os.Rename`, then `fsync` of each directory) only if the live database's `backup.restore_id` equals `RESTORE_ID`, then the staging directories are removed; only after that `DROP DATABASE <db>_previous_<ts>`. `staging.go`: the cleanup at the start of every `Restore` — staging directories present: `FinishInterruptedRestore` against the live database (stale staging, whose `RESTORE_ID` the live database does not carry, is removed without touching the live files); `<db>_restore` while `<db>` exists: dropped; `<db>_restore` while no `<db>` exists: renamed to `<db>`, never dropped; a `<db>_previous_*` while `<db>` exists and no staging remains: dropped. Any error after `CREATE DATABASE` — a `Load` error such as PostgreSQL's `53100 disk_full` included — drops `<db>_restore` and removes the staging directories before returning (S-22). The passphrase and the unwrapped private key are cleared when `Restore` returns.

Run: the Step 1 commands
Expected: `ok` for both.

Run: `golangci-lint run ./internal/backup/... && make test`
Expected: green.

- [ ] **Step 3: Commit**

```bash
git add -- internal/backup/restore.go internal/backup/swap.go internal/backup/staging.go internal/backup/restore_integration_test.go internal/backup/f85_integration_test.go
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(backup): restore into a fresh database, verified before one swap point; db-only for the update rollback; F-80..F-85, F-97" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- internal/backup
```

---

### Task 6: Operator CLI and wiring: `alice backup|restore|selfcheck|support-bundle`, `migrate --to-latest`, the periodic tasks and the heartbeat

**Files:**
- Create: `cmd/alice/backup_cli.go`, `restore_cli.go`, `selfcheck.go`, `supportbundle.go`, `passphrase.go`, `backup_cli_integration_test.go`, `selfcheck_integration_test.go`, `supportbundle_integration_test.go`
- Modify: `cmd/alice/main.go` (commands, usage text, serve: the app pool is opened first, then `backup.FinishInterruptedRestore(ctx, pool, keysDir, stateDir)` runs before the master key is loaded (S-1); the `tlscert.Store` and `ServerConfigFor` instead of `EnsureSelfSigned` + `ServerConfig`, and a non-empty `Store.Recovered()` is logged and audited as `https.certificate_recovered` (S-13); `jobs.heartbeat` is written once as soon as the scheduler runs (M-3)), `cmd/alice/services.go` (`backup`, `forward`, `tlsStore` in `services`; four periodic tasks in `buildScheduler`), `cmd/alice/wiring.go` (`periodicTypes`), `cmd/alice/wiring_test.go`, `internal/jobs/types.go` (the four types of C1), `internal/secrets/masterkey.go` (`CheckMasterKey(ctx, q, dir) error`: the existing load-and-compare path, never creating a file or a row) with a test, `cmd/alice/testapi_e2e.go` (`/test/reset` also removes the files of the backups directory)

**Interfaces:**
- Consumes: C8 (Tasks 4–5), C10 (Task 7), C11 (Task 8), `config` (Task 3).
- Produces: C6, C9, C1 job types; `services.backup *backup.Service`, `services.forward *forward.Forwarder`, `services.tlsStore *tlscert.Store` (used by Task 9's `newAPIDeps`).

- [ ] **Step 1: Write the failing tests**

`backup_cli_integration_test.go` (`//go:build integration`; uses `run(args, getenv, stdout, stderr)` with a `getenv` map as the existing CLI tests do, and a stdin injection: `run` gains `stdin io.Reader` — update every caller):

- `TestCLIBackupListVerify`: `alice backup` prints `Backup written: /…/alice-backup-…-manual.alicebak (… MiB)` and exits 0; `backup list` prints the header line and one row with `ok`; `backup verify <file>` prints the shallow sentence; `backup verify <file> --deep --passphrase-stdin` with the passphrase on stdin prints the deep sentence; with a wrong passphrase prints the C7 damaged sentence and exits 1.
- `TestCLIBackupOutMustStayInTheBackupDir`: `--out /tmp/x.alicebak` → exit 2 with `The backup file must be in /opt/alice/backups (ALICE_BACKUP_DIR).`.
- `TestCLIRestoreMessages`: one subtest per C7 row (not a backup, newer, damaged, broken audit, not confirmed (stdin `restore\n` lowercase), no safety backup possible, not enough disk (`--free-bytes 1`), still connected (`--wait-for-sessions 0s` with an extra session), done, db-only done) with the exact text and exit code; `--confirm RESTORE` skips the prompt; `--no-safety-backup` passes `NoSafetyBackup`; the default wait is 150 s.
- `TestCLIPassphraseNeverFromArgsOrEnv`: `restore FILE --passphrase x` → usage error (exit 2); `ALICE_PASSPHRASE` in the environment is ignored (with stdin not a terminal and no `--passphrase-stdin` the C6 "A passphrase is needed…" message, exit 2).
- `TestCLIMigrateToLatest`: `migrate --to-latest` behaves as `migrate`.

`selfcheck_integration_test.go`: start `serve` in-process as `serve_integration_test.go` does (TLS on a random port, `ALICE_LISTEN_ADDR`), wait for `/healthz`, then `alice selfcheck` → seven `[ OK ]` lines and exit 0 without waiting for a scheduler tick. `TestSelfcheckPassesRightAfterStartAndAfterRestore` (M-3): a stale `jobs.heartbeat` (2 hours old, as a restored database carries) in the settings, a fresh `serve` → `selfcheck` prints seven `[ OK ]` lines within 90 s. `TestSelfcheckReportsEachFailure`: the database stopped (pool to a closed port) → `[FAIL] Database reachable: …`; schema one behind → `[FAIL] Database schema is current …`; a different `master.key` → `[FAIL] Master key opens the stored key check: …`; one audit row changed (owner, replica role) → `[FAIL] Audit log intact …`; no listener → `[FAIL] HTTPS listener …`; a `tls.crt` replaced on disk after start → `[FAIL] HTTPS listener answers with the installed certificate: …`; heartbeat 6 minutes old and no scheduler running (the 90-second wait shortened through a test hook) → `[FAIL] Background jobs running …`; exit 1 each time.

`supportbundle_integration_test.go`: `TestSupportBundleHasNoSecrets`: seed the canaries of `TestF87NoPlaintextInTheFile` plus the database passwords of the configuration; `alice support-bundle` JSON parses, holds the C9 keys, and contains none of the canaries, no Installation ID, no customer name, no target host name.

`wiring_test.go`: `TestPhase8PeriodicTasksAreWired` (the four types are in `periodicTypes` and `checkWiring` fails when one is missing). `TestServeFinishesAnInterruptedRestore` (integration; staging directories whose `RESTORE_ID` equals the live database's `backup.restore_id` and staged files → `serve` renames them before loading the master key; with another ID the live files stay byte-equal and the staging is removed — S-1). `TestServeAuditsARecoveredCertificate` (an interrupted `Install` left `tls.crt.new` → after start one `https.certificate_recovered` row).

`internal/secrets`: `TestCheckMasterKeyNeverCreates` (no row and no file → error, still no file; matching file → nil; other file → `ErrMasterKeyMismatch`).

Run: `go test -tags integration -count=1 -run 'TestCLI|TestSelfcheck|TestSupportBundle|TestServeFinishes|TestServeAudits' ./cmd/alice/ && go test -count=1 -run 'TestPhase8PeriodicTasks' ./cmd/alice/ && go test -count=1 -run TestCheckMasterKey ./internal/secrets/` (Docker: testcontainers)
Expected: FAIL.

- [ ] **Step 2: Implement**

`passphrase.go`: C6 reading rules (`term.IsTerminal(int(os.Stdin.Fd()))` → `term.ReadPassword` from `/dev/tty` with the prompt `Recovery passphrase: ` on stderr; else `--passphrase-stdin` only), the returned slice is cleared by the caller (`defer clear(p)`). `backup_cli.go`/`restore_cli.go`: flag parsing with `flag.NewFlagSet` (`ContinueOnError`, output to stderr), error-to-message mapping of C7, the confirmation prompt reading one line from stdin. `selfcheck.go`: C9 (the TLS probe dials `127.0.0.1:<port of ALICE_LISTEN_ADDR>`; the one `InsecureSkipVerify` of this plan with its `//nolint:gosec // G402:` reason and a `VerifyPeerCertificate` that compares the leaf DER with `keys/tls.crt`'s first block). `supportbundle.go`: C9 JSON (`json.Encoder` with indentation). `services.go`: build `backup.New` (with the keyring, for `backup.sender`), `forward.New` (dial through a closure over `netaddr.DialContext`), `tlscert.NewStore`; tasks `{BackupSchedule, 5m, svc.backup.RunScheduled}`, `{TLSRenew, 6h, renew-and-audit}`, `{AuditForward, 15s, svc.forward.Run}`, `{JobsHeartbeat, 1m, write jobs.heartbeat}`; `serve` also writes `jobs.heartbeat` once, as soon as the scheduler runs (before the first tick), through the same function (M-3). `selfcheck.go`: the heartbeat line alone is retried every 5 s for up to 90 s before it reports `[FAIL]`. `restore_cli.go`: `--wait-for-sessions` (default 150 s), `--free-bytes`, `--no-safety-backup`. `main.go`: usage lines for the new commands (exact text of C6's first lines), `serve` changes listed under Files.

Run: the Step 1 commands
Expected: `ok`.

Run: `make lint && make test && make release-symcheck`
Expected: green (the release build links the new commands; no e2e symbol leaks).

- [ ] **Step 3: Commit**

```bash
git add -- cmd/alice/backup_cli.go cmd/alice/restore_cli.go cmd/alice/selfcheck.go cmd/alice/supportbundle.go cmd/alice/passphrase.go \
  cmd/alice/backup_cli_integration_test.go cmd/alice/selfcheck_integration_test.go cmd/alice/supportbundle_integration_test.go
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(cli): alice backup, backup list, backup verify [--deep], restore, selfcheck, support-bundle; daily backup, certificate renewal, audit forwarding and heartbeat tasks" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- cmd/alice internal/jobs/types.go internal/secrets
```

---

### Task 7: `internal/audit/forward`: syslog forwarding in chain order (SEC-073, F-92, F-96); `fakesyslog`

**Files:**
- Create: `internal/testutil/fakesyslog/server.go` (+ `server_test.go`), `internal/audit/forward/forward.go`, `syslog.go`, `settings.go`, `syslog_test.go`, `forward_integration_test.go`

**Interfaces:**
- Consumes: `audit` (rows by sequence: read the existing iterator `audit.Service.Iterate` or the query the export uses; the checkpoint setting `audit.checkpoint` and its struct), `settings.Get/Set`, `netaddr.DialContext` (the address rule; `ErrAddressRefused` maps its refusal), `internal/testutil/pki` (test CA).
- Produces: C10; `fakesyslog.Server{Start(t, Options{TLS bool, UDP bool}), Addr(), CAPEM(), Messages() []string, Down(), Up()}`.

- [ ] **Step 1: Write the failing tests**

`syslog_test.go` (unit): `TestRFC5424Message` (exact bytes for a fixed entry: `<37>1 2026-10-10T02:30:00Z alice01 alice - backup.created [alice@32473 seq="42" hash="ab…" prev_hash="cd…" actor="cli" result="success"] {"object_type":"backup","object_id":"…","details":{…}}`), `TestSDParamEscaping` (`"`, `\`, `]` escaped with a backslash), `TestOctetCounting` (`<len> <msg>` for TCP/TLS), `TestMessageIsCutToEightKiB` (the JSON part is cut at a UTF-8 boundary and marked `…"truncated":true}`), `TestSeverity` (success notice, failure/denied warning, failed `audit.verified` critical).

`forward_integration_test.go` (`//go:build integration`): `fakesyslog` TLS receiver with a `pki` CA; the forwarder configured with the CA bundle and the fake's address (`Dial` = a plain dialer in the test, so loopback is reachable; one subtest uses `netaddr.DialContext` with a link-local address):
- `TestForwardsInChainOrderWithHashes`: 1,200 audit rows → three `Run` calls deliver them in sequence order, each with its `seq`, `hash` and `prev_hash` equal to the database row, cursor at the head, backlog 0.
- `TestF96ReceiverDownNeverBlocksTheLocalWrite`: the receiver down → 1,000 `audit.Log.Append` calls finish within the same time as with forwarding disabled (± 50 %; the append path never calls the forwarder), `Run` returns an error, `State.LastErrorCode = "unreachable"`, the cursor does not move, backlog 1,000; receiver up → the next `Run` calls deliver each row exactly once, in order.
- `TestF92CheckpointIsForwarded`: `audit.Service.Verify` stores a checkpoint → the next `Run` sends one `audit.checkpoint` message with its `seq` and `hash`; a second `Run` sends none.
- `TestUntrustedCertificateIsRefused`: the receiver's CA not configured → `ErrUntrusted`, cursor unchanged.
- `TestAddressRule`: host `169.254.169.254` → `ErrAddressRefused` from `Save` and from `Test`.
- `TestUDPAndTCPOnlyWhenChosen`: default transport is `tls`; `udp` and `tcp` deliver to the fake's UDP/TCP listeners.
- `TestSettingsAreAuditedAndVersioned`: `Save` audits `audit.forwarding_changed` (`enabled`, `host`, `port`, `transport`, `ca_set`), a stale version → `ErrVersion`, `ca_pem` never appears in an audit row or in `Settings()`'s answer (it returns `CASet`).

Run: `go test ./internal/audit/forward/ ./internal/testutil/fakesyslog/ -count=1 && go test -tags integration ./internal/audit/forward/ -count=1`
Expected: FAIL.

- [ ] **Step 2: Implement**

`fakesyslog`: listeners on `127.0.0.1:0` (TLS with a `pki` server certificate, plain TCP, UDP), octet-counting parser, a mutex-protected message list, `Down` closes the listeners and refuses connections, `Up` re-listens on the same port. `forward`: `Run` reads `audit.forwarding` (disabled → return nil), the state, then up to `MaxBatch` rows with `seq > cursor ORDER BY seq`, opens one connection (TLS 1.2+, `RootCAs` = system pool plus `CAPEM`), writes each framed message, and after each successful write advances an in-memory cursor; at the end (or on the first error) it stores the cursor and state in one `settings.Set`. A new checkpoint (its `seq` greater than the state's `CheckpointSeq`, a field the state gains) is sent after the rows. Errors map to `unreachable`, `untrusted`, `refused_address`, `write`.

Run: Step 1 commands
Expected: `ok`.

Run: `golangci-lint run ./internal/audit/... ./internal/testutil/fakesyslog/...`
Expected: no findings.

- [ ] **Step 3: Commit**

```bash
git add -- internal/audit/forward internal/testutil/fakesyslog
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(audit): forward the audit log to syslog (RFC 5424 over TLS) in chain order with hashes and checkpoints; never blocks the local write (SEC-073, F-92, F-96)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- internal/audit/forward internal/testutil/fakesyslog
```

---

### Task 8: `tlscert.Store` (upload, hot reload, renewal) and the wizard backend (HTTPS and mail steps, position, server-side strength)

**Files:**
- Create: `internal/platform/tlscert/store.go`, `upload.go`, `store_test.go`, `upload_test.go`; `internal/setup/https.go`, `mail.go`, `position.go`, `strength.go`, `strength_test.go`, `testdata/strength.json`, `wizard_integration_test.go`
- Modify: `internal/setup/setup.go` (`Status` fields), `internal/setup/passphrase.go` (refuse `fair`; keep Task 1's storage of the sender key `backup.sender` in the same transaction), `web/src/pages/setup/strength.test.ts` (reads `internal/setup/testdata/strength.json` with the existing `readRepoFile` helper of `web/src/test/goSources.ts`, through `node:fs` as other web tests read repository files — E10), and the test fixtures whose passphrase rates `fair` (found by the grep in Step 2; at least `web/e2e/helpers.ts`, `internal/api` and `cmd/alice` fixtures are checked — M-24)

**Interfaces:**
- Consumes: `tlscert.EnsureSelfSigned`, `tlscert.ServerConfig`, `software.sslmate.com/src/go-pkcs12` (already a dependency), `internal/testutil/pki`, `notify.Settings.SMTP` (mail configured?), the `setup` settings helpers.
- Produces: C11.

- [ ] **Step 1: Write the failing tests**

`upload_test.go`: `TestParseUploadPEM` (leaf + intermediate in any order + PKCS #8, PKCS #1 and SEC 1 keys → the chain leaf-first, `Info` filled), `TestParseUploadPFX` (with and without the intermediate; the `pki` PFX with password `alice-test`), `TestParseUploadRefusals` (table → error: key of another certificate `ErrKeyMismatch`; expired, not yet valid, valid for less than one more day `ErrNotValidNow`; RSA 1024, a P-224 key, an Ed25519 key `ErrWeakKey`; wrong PFX password `ErrPFXPassword`; garbage, an empty upload, a CSR, both PEM and PFX given, PEM larger than 1 MiB `ErrUnreadable`), `TestWarnings` (`name_mismatch`, `chain_incomplete`, `expires_soon`).

`store_test.go`: `TestStoreStartsWithTheTemporaryCertificate` (empty directory → `Info().Temporary`), `TestInstallHotReloads` (a TLS server built with `ServerConfigFor(store)` on `127.0.0.1:0`; 50 goroutines handshake in a loop while `Install` runs; no handshake fails; after `Install` every new handshake presents the uploaded leaf; `tls.key` has mode 0400 and `tls.crt` 0644; no temporary file remains), `TestInstallIsAtomicOnDisk` (a failing write of `tls.crt` — directory made read-only between the two writes through a test hook — leaves the old pair in force on disk and in memory), `TestStoreRecoversAnInterruptedInstall` (S-13: a hook stops `Install` between the two renames; a new `NewStore` serves the uploaded pair and `Recovered()` says `finished`; with a damaged `.new` certificate it restores the `.prev` pair and says `restored_previous`; it never writes a temporary certificate over a key that is not the temporary one), `TestInstallAndRenewDoNotRace` (S-13: `-race`, 100 iterations of `Install` against `Renew` on a temporary certificate near its end → the customer leaf always survives), `TestRenewOnlyTheTemporary` (a customer certificate 3 days from its end is never touched; the temporary certificate 6 days from its end is renewed and served; one 30 days from its end is not), `TestStoreLoadsACustomerCertificateAtStart`.

`strength_test.go` and `testdata/strength.json` (≥ 30 vectors, among them: 15 characters `tooShort`; `aaaaaaaaaaaaaaaa` `fair`; `correct horse battery staple` `strong`; 16 characters with three classes `good`; 20 characters one class `good`; 28 characters one class `strong`; Turkish letters counted as one rune each (`ğüşöçıİ` repeated); a string of 16 emoji runes `fair`; leading and trailing spaces): `TestPassphraseStrengthVectors`. `web/src/pages/setup/strength.test.ts` gains `it('rates the shared vectors exactly like the server', …)` over the same file.

`wizard_integration_test.go` (`//go:build integration`): `TestWizardPositionIsDerived` (table: no admin → `NextStep` `""` (the code/language/admin part is the browser's); admin without passphrase → `passphrase`; passphrase set → `https`; HTTPS chosen → `mail`; mail configured (through `notify.Settings.SaveSMTP`) or skipped → `license`; license chosen → `platform`; completed → `done`), `TestKeepTemporaryAndSkipMailAreAudited` (`setup.https_kept_temporary`, `setup.mail_skipped` with `choice`; idempotent: a second call writes no second row), `TestRecordCertificateUploaded`, `TestServerRefusesAFairPassphrase` (`SetRecoveryPassphrase` with `aaaaaaaaaaaaaaaa` → `ErrPassphraseTooWeak`, nothing stored: neither `backup.key` nor `backup.sender`), `TestCompleteStillNeedsOnlyPassphraseAndLicense` (Finish works with HTTPS and mail unchosen; the dashboard checklist shows them — Task 9), `TestKeepTemporaryAndSkipMailAfterCompletionChangeNothing` (S-39: after `Complete`, both return the status, write no setting and no audit row).

Run: `go test -race ./internal/platform/tlscert/ ./internal/setup/ -count=1 && go test -tags integration ./internal/setup/ -count=1 && cd web && npx vitest run src/pages/setup/strength.test.ts`
Expected: FAIL.

- [ ] **Step 2: Implement**

`upload.go`: parse with the standard library and `pkcs12.DecodeChain`; key match by comparing public keys; validity against `now` with one day of margin; key rules of R43 row 15; chain ordering by issuer/subject; warnings by `x509.Verify` against the system pool plus the uploaded intermediates and by matching `ALICE_TLS_HOSTS` (the store keeps them). `store.go`: an `atomic.Pointer[tls.Certificate]` and one `sync.Mutex` held by `Install` and `Renew` (S-13); `Install` hard-links the current pair to `tls.crt.prev`/`tls.key.prev`, writes `tls.key.new` (0400) and `tls.crt.new` (0644) with `O_EXCL`, `fsync`, renames the key then the certificate, `fsync`s the directory, then swaps the pointer; on any error removes the `.new` files and keeps the old pair; `Renew` re-reads the files under the lock and is `EnsureSelfSigned` plus a pointer swap only while the served certificate is the temporary one; `NewStore` first repairs an interrupted `Install` as C11 says and records it for `Recovered()` (the API package audits nothing here; `serve` does, Task 6). `setup`: C11 functions; `Status` reads `setup.https_choice`, `setup.mail_choice` and `notify` mail settings; `NextStep` order of R43 row 16; `strength.go` ports `passphraseStrength` rune for rune (`unicode` classes equal to the JavaScript regular expressions: `[a-z]`, `[A-Z]`, `[0-9]` are ASCII-only, "other" is any rune that is not an ASCII letter, digit or whitespace; words split on Unicode white space); `passphrase.go` refuses `fair` (before `NewBackupKey`, so no key or sender key is generated or stored); `KeepTemporaryCertificate` and `SkipMail` after completion return the status unchanged (S-39).

Run: Step 1 commands
Expected: `ok`; the Vitest file passes.

Run: `grep -rn --exclude-dir=node_modules --exclude-dir=.claude -E "passphrase|PASSPHRASE" web/e2e internal/api cmd/alice | grep -E "'[^']{16,19}'"` and check each fixture passphrase used by a test of the setup flow rates `good` or better (change a fixture that rates `fair`, in this task); then `make test && make web-test`
Expected: green.

- [ ] **Step 3: Commit**

```bash
git add -- internal/platform/tlscert/store.go internal/platform/tlscert/upload.go internal/platform/tlscert/store_test.go \
  internal/platform/tlscert/upload_test.go internal/setup/https.go internal/setup/mail.go internal/setup/position.go \
  internal/setup/strength.go internal/setup/strength_test.go internal/setup/testdata/strength.json internal/setup/wizard_integration_test.go
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(setup): reloadable HTTPS certificate store with upload and renewal; wizard HTTPS and mail steps, derived position, server-side passphrase strength (P1-08)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- internal/platform/tlscert internal/setup web/src/pages/setup/strength.test.ts \
  <the fixture files changed by the Step 2 grep, listed by path>
```

---

### Task 9: API: backups, backup settings, download, HTTPS, forwarding, wizard routes, dashboard backup age and checklist; codes, OpenAPI, authz

**Files:**
- Create: `internal/api/backup_handlers.go`, `https_handlers.go`, `forwarding_handlers.go`, `phase8_dto.go`, `phase8_integration_test.go`, `phase8_authz_test.go`
- Modify: `internal/rbac/rbac.go` (+ tests: `BackupManage` for Administrator with step-up, no token scope), `internal/api/server.go` (routes, `Deps` gains `Backup`, `Forward`, `TLSStore`), `internal/api/errors.go` (C12 codes, `phase8Table`), `internal/api/setup_handlers.go` (status fields, the two wizard routes; `ErrPassphraseTooWeak` → `ALC-SET-0010`), `internal/api/dashboard_handlers.go` (the handler adds the `backup` and `setup_checklist` sections from `Deps.Backup` and `Deps.Setup`, role-filtered as R43 row 18 says; `internal/reports` is not changed, so its import rule stays), `api/openapi.yaml`, `docs/authz-matrix.md` (`make authz-doc`), `locales/common/{en,tr}.json` (`errors.<reason>.*` for the 13 new codes), `docs/troubleshooting.md` (one section per new code), `cmd/alice/main.go` (the `newAPIDeps` line only)

**Interfaces:**
- Consumes: C8, C10, C11, `rbac`, the Phase 7 helpers (`etag`, `ifMatch`, `decodeExact`, `writeJSON`, `fail`, `allowRate`, step-up policy), the dashboard summary handler.
- Produces: C12; `TestPhase8RoutesAuthz`.

- [ ] **Step 1: Write the failing tests**

`phase8_authz_test.go`: `TestPhase8RoutesAuthz`, the generated matrix for every C12 route × {anonymous, Administrator with step-up, Administrator without step-up, Operator, Auditor, `read` token, `operate` token} — only "Administrator with step-up" is allowed on every new route; the two changed GET routes keep their rules; `TestAuthzMatrixDocIsCurrent` passes after `make authz-doc`.

`phase8_integration_test.go` (`//go:build integration`, the existing stack harness `installed(t)`):
- `TestSetupStatusAfterCompletionRevealsNothing` (S-18): an anonymous `GET /setup/status` after Finish returns exactly the keys `completed` and `default_locale`; before completion, and for a signed-in Administrator after it, the answer carries `https_chosen`, `mail_chosen`, `next_step`.
- `TestBackupRoutes`: `POST /backups` → 201 with a `BackupDTO`; `GET /backups` lists it with `state.configured = true` and `state.free_bytes` > 0; a second `POST` while the first is held → 409 `ALC-BAK-0001`; before the passphrase step → 409 `ALC-BAK-0002`.
- `TestBackupDownloadIsAuditedFirst`: the audit row `backup.downloaded` (`name`) is committed before the first body byte (the test reads the audit table from a hook in the response writer's first `Write`); headers `Content-Disposition`, `Cache-Control: no-store`; the body equals the file.
- `TestBackupDownloadRefusesPathTricks`: names `..%2f..%2fetc%2fpasswd`, `%2e%2e`, `x/../../y.alicebak`, `.alice-backup-x.alicebak.partial`, an existing file name of another directory, a name with NUL → 404 `ALC-BAK-0003`, and no `open` syscall outside the backups directory (the service's `Open` is wrapped in the test to record paths).
- `TestBackupDownloadRateLimit`: the sixth download within a minute → 429.
- `TestBackupScheduleSettings`: `If-Match` required (428 without), 422 per field (`time` `25:00`, `zone` `Mars/Olympus`, `retention` 6 and 61), 200 bumps the `ETag`.
- `TestHTTPSRoutes`: `GET` shows `temporary: true`; `PUT` a `pki` pair → 200 with `warnings` containing `name_mismatch` (the test's names differ), the next TLS handshake to the test server presents it; each `ALC-TLS-000x` refusal; the private key is not in any answer or audit row.
- `TestWizardHTTPSAndMailRoutes`: `keep-temporary` and `mail/skip` → `next_step` advances; both audited; after completion both answer 200 with the status and add no audit row (S-39).
- `TestForwardingRoutes`: `PUT` with the fake's address and CA → 200, `GET` shows `ca_set: true` and no PEM; `POST …/test` → 204 with the fake up, 502 `ALC-AUD-0003` with it down, 502 `ALC-AUD-0004` without the CA, 422 `ALC-AUD-0002` for `169.254.169.254`.
- `TestDashboardBackupAndChecklist`: as Administrator: `backup.alarm` false after a fresh backup and true after the fake clock moves 49 hours; `setup_checklist` lists `https` and `mail` as not done after the wizard was finished with "keep temporary" and "skip"; as Auditor: `backup` present, `setup_checklist` absent; as Operator: both absent.
- `TestPhase8ErrorCodesAreCatalogued` (via `phase8Table` in the existing catalogue tests).

Run: `go test ./internal/api/ ./internal/rbac/ -count=1 -run 'Phase8|Authz' && go test -tags integration -count=1 -run 'TestBackup|TestHTTPS|TestWizardHTTPS|TestForwarding|TestDashboardBackup' ./internal/api/` (Docker: testcontainers)
Expected: FAIL.

- [ ] **Step 2: Implement**

First commit (M-15: Task 10's web tests check every code they mock against `internal/api/errors.go`, and Task 17 appends to `docs/troubleshooting.md` after this commit): the 13 codes of C12 and `phase8Table` in `internal/api/errors.go` (with `TestPhase8ErrorCodesAreCatalogued`), the `errors.<reason>.title|cause|action` entries in `locales/common/{en,tr}.json`, the code sections of `docs/troubleshooting.md`, and `rbac.BackupManage` with its tests; `make i18n-check && go test ./internal/api/ ./internal/rbac/ -count=1 -run 'Catalog|Phase8ErrorCodes|Rbac|BackupManage'` green; then

```bash
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(api): Phase 8 error codes (ALC-BAK, ALC-TLS, ALC-AUD, ALC-SET-0010) with locale entries and troubleshooting sections; backup.manage permission" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- internal/api/errors.go internal/api/errors_test.go internal/rbac \
  locales/common/en.json locales/common/tr.json docs/troubleshooting.md
```

(adjust the test file name to the one that holds the catalogue tests). Then the rest: routes and DTOs exactly as C12; the setup status handler drops `https_chosen`, `mail_chosen` and `next_step` from an anonymous answer once setup is complete (S-18); `BackupStateDTO.free_bytes` from `svc.backup.FreeBytes()`; the download handler: validate the name with the C7 patterns, `svc.backup.Open`, append the audit row in its own transaction, then `http.ServeContent`-free streaming with `io.Copy` (no range requests: `Accept-Ranges: none`); HTTPS `PUT`: decode (`decodeExact`, 2 MiB cap for this route only — the PFX is base64), `ParseUpload`, `Store.Install`, `setup.RecordCertificateUploaded` and the `https.certificate_replaced` audit row (`subject`, `not_after`, `fingerprint`) in one transaction after the install succeeded; zero the decoded key and password buffers. OpenAPI: every route with `x-permission`, schemas, the error codes; troubleshooting sections with title, cause and action matching the catalogue.

Run: Step 1 commands, then `make authz-doc && make i18n-check && make lint && make test`
Expected: green.

- [ ] **Step 3: Commit**

```bash
git add -- internal/api/backup_handlers.go internal/api/https_handlers.go internal/api/forwarding_handlers.go internal/api/phase8_dto.go \
  internal/api/phase8_integration_test.go internal/api/phase8_authz_test.go
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(api): backups (list, back up now, audited download), backup schedule, HTTPS certificate, audit forwarding, wizard HTTPS and mail steps, dashboard backup age and setup checklist" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- internal/api internal/rbac api/openapi.yaml docs/authz-matrix.md \
  locales/common/en.json locales/common/tr.json docs/troubleshooting.md cmd/alice/main.go
```

---

### Task 10: Web: Settings → Backups, HTTPS, Audit forwarding; wizard HTTPS and mail steps, Back and resume; dashboard backup card, checklist and banner

**Files:**
- Create: `web/src/pages/setup/HttpsStep.tsx`, `web/src/pages/setup/MailStep.tsx`, `web/src/components/settings/BackupsTab.tsx`, `HttpsTab.tsx`, `ForwardingTab.tsx`, `web/src/components/dashboard/BackupCard.tsx`, `SetupChecklist.tsx`, `web/src/components/BackupBanner.tsx`, and a `*.test.tsx` beside each
- Modify: `web/src/pages/SetupPage.tsx` (steps, Back, resume from `next_step`), `SetupPage.test.tsx`, `web/src/pages/SettingsPage.tsx` (three tabs), `web/src/pages/DashboardPage.tsx`, `web/src/layout/AppLayout.tsx` (banner), `web/src/api/{endpoints.ts,types.ts,queryKeys.ts}`, `web/src/test/server.ts` (msw handlers), `web/src/locales/{en,tr}.json` (C13, the audit labels of C14, the error texts the UI shows)

**Interfaces:**
- Consumes: C12 DTOs, C13 copy, C14 labels; the Phase 7 `SettingsPage` tab pattern, `StepUpProvider`, the existing mail settings form component (reused inside `MailStep` — read `components/settings/*` and reuse the form, not copy it).
- Produces: the screens Task 16 drives.

- [ ] **Step 1: Write the failing tests (Vitest + msw)**

- `SetupPage.test.tsx`: the step order of R43 row 16 for a fresh status; a status with `next_step: "mail"` opens the mail step directly (resume); **Back** from the mail step shows the HTTPS step in its done state ("Keep the temporary certificate" chosen); **Skip** on the mail step calls `POST /setup/mail/skip` and goes to the license step; the passphrase step's submit button stays disabled for a `fair` passphrase and the message explains why; both languages render every new step (no raw key).
- `HttpsStep.test.tsx`: PEM upload (two file inputs) and PFX upload (file + password) send the C12 body; a 422 `ALC-TLS-0001` shows the catalogue title; success shows `https.applied`; the PFX password field is cleared after the request (state inspection through the input's value).
- `BackupsTab.test.tsx`: the table (`backups-table`) with name in `<Code>`, kind, size, time in the browser zone; **Back up now** posts and refreshes; **Download** opens the step-up dialog and then sets `window.location` to the download URL (no `fetch` of the file); the schedule form validates time, zone (a `Select` of `Intl.supportedValuesOf('timeZone')`) and retention 7–60; `backups.offHost`, `backups.restoreHint` and `backups.freeSpace` (from `state.free_bytes`, S-21) are shown.
- `HttpsTab.test.tsx`, `ForwardingTab.test.tsx` (CA PEM textarea is write-only: after saving, the field is empty and "A CA certificate is set" is shown; **Send test message** maps 502/422 codes to their texts; the backlog line).
- `BackupCard.test.tsx` (last success, age; Auditor sees it; Operator's summary has no `backup` and nothing renders), `SetupChecklist.test.tsx` (items, required ones marked, each links to the right Settings tab), `BackupBanner.test.tsx` (Administrators only, `backup-alarm-banner`, text `backups.alarm`).
- `labels.test.ts` passes with the new audit actions (the existing test scans `backendAuditActions`).

Run: `cd web && npx vitest run src/pages/SetupPage.test.tsx src/pages/setup src/components/settings src/components/dashboard src/components/BackupBanner.test.tsx`
Expected: FAIL.

- [ ] **Step 2: Implement** the components to the tests; TanStack Query keys for backups, HTTPS info, forwarding; no secret in a query key or cache (the upload and the CA PEM are mutation inputs only).

Run: `make web-test && make web-lint && make i18n-check && make web`
Expected: green — once Task 9's first commit (the error codes) is on the branch; before it, `errorPairs.test.ts` fails on the mocked `ALC-TLS-000x`/`ALC-AUD-000x` codes, so wait for that commit rather than changing the test (M-15).

- [ ] **Step 3: Commit**

```bash
git add -- web/src/pages/setup/HttpsStep.tsx web/src/pages/setup/MailStep.tsx web/src/components/settings/BackupsTab.tsx \
  web/src/components/settings/HttpsTab.tsx web/src/components/settings/ForwardingTab.tsx web/src/components/dashboard/BackupCard.tsx \
  web/src/components/dashboard/SetupChecklist.tsx web/src/components/BackupBanner.tsx
git add -- 'web/src/pages/setup/*.test.tsx' 'web/src/components/settings/*.test.tsx' 'web/src/components/dashboard/*.test.tsx' web/src/components/BackupBanner.test.tsx
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(web): wizard HTTPS and mail steps with Back and resume; Settings backups, HTTPS and audit forwarding; dashboard backup card, setup checklist and the 48-hour banner (EN/TR)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- web/src
```

---

### Task 11: Host scripts: `install.sh`, `alice-update.sh`, `alicectl`, `lib/alice-lib.sh`, with stub-command tests

**Files:**
- Create: `deploy/release/install.sh`, `deploy/release/alice-update.sh`, `deploy/release/alicectl`, `deploy/release/lib/alice-lib.sh`, `deploy/release/scripts_test.go` (package `release`), `deploy/release/testdata/stubs/{docker,chown,ss,timedatectl,uname,id,nproc,df}` (executable bash stubs; each records its arguments **and its environment**), `deploy/release/testdata/swap-openssl/openssl` (a wrapper that runs the real `openssl` and then replaces the original tarball, for `TestUpdateVerifiesACopy`)

**Interfaces:**
- Consumes: C2, C3 (compose services and names), C4 (every message, flag, step and exit code), C5 (`RELEASE`, `SHA256SUMS`, signatures, the `openssl` command), C6 (in-container commands).
- Produces: the three scripts the package ships (Task 12 copies them) and the release harness runs (Task 13).

- [ ] **Step 1: Write the failing tests**

`scripts_test.go` builds, per test, a temporary **package directory** (copies of the three scripts and `lib/`, a `RELEASE` file, two small fake image tar files, `images/images.sha256`, `docker-compose.yml`, `.env.template`, `release-keys/rk-test-01.pem` and `SHA256SUMS` + `SHA256SUMS.sig` signed with an Ed25519 key generated in the test and written as PKIX PEM — the same `openssl` command of C5 must verify it), a temporary **installation directory**, and a `PATH` that puts `testdata/stubs` first. The stubs log every invocation (arguments and, for `docker`, standard input) to `$STUB_LOG` and answer from environment variables: `STUB_UID` (`id -u`), `STUB_ARCH` (`uname -m`), `STUB_DOCKER` (`missing`, `down`, `old`, `nocompose`, `ok`), `STUB_DOCKER_VERSION`, `STUB_IMAGE_IDS` (what `docker image inspect` prints), `STUB_COMPOSE_FAIL` (a compose sub-command that fails, e.g. `run migrate`), `STUB_PORT_BUSY` (`ss` prints a listener), `STUB_NTP` (`yes`, `no`, `missing`), `STUB_DISK_GB` (`df`), `STUB_CPUS` (`nproc`), `STUB_SOCK_MODE`. Memory is read from `${ALICE_PROC_DIR:-/proc}/meminfo`, and the docker socket path from `${ALICE_DOCKER_SOCK:-/var/run/docker.sock}` (the only two test overrides the scripts accept, documented in the script header as test-only; read in preflight only, never passed to `docker`, and announced with a `[WARN]` when set — S-24). Passphrase files of the tests are mode 0600 (S-25). The non-interactive installs pass `--fingerprint <SHA-256 of the test key's DER>` (S-23).

- `TestPreflightMessages`: one subtest per row of C4's table — the failing condition set through the stubs → standard output contains the exact `[FAIL] …` line, every earlier check's `[ OK ]` line, and the script exits 1 without creating the installation directory; the memory warning case prints `[WARN] …` and continues.
- `TestPreflightListsEveryFailureBeforeStopping`: three failing checks → three `[FAIL]` lines, then exit 1.
- `TestInstallHappyPath`: `install.sh --dir <inst> --port 19443 --bind 127.0.0.1 --hostname alice.test --non-interactive --fingerprint <hex> --project alice-unit` → the C2 layout exists (modes checked with `os.Stat`; owners through the recorded `chown` calls: `10001:10001` for `keys`, `state`, `backups`; `70:70` for `data/postgres` and `db_postgres_password`; `70:10001` for the two other passwords), the three password files hold 43 base64url characters each, `master.key` holds 44 base64 characters plus a newline with mode 0400, `.env` holds `COMPOSE_PROJECT_NAME=alice-unit` and no secret, `docker load` ran for both tars, `docker image inspect` was compared with `RELEASE`, the compose calls ran in the order `up -d --wait --wait-timeout 180 postgres`, `run --rm migrate`, `up -d --wait --wait-timeout 180 alice`, each with `--project-name alice-unit` and `-f <inst>/docker-compose.yml`, the setup code from the stubbed `exec … setup-token --reset` (first line `One-time setup code: <code>`) is printed in the closing text and is **not** in `install.log`, which holds `Setup code printed to the terminal (not logged).` instead (S-4), and nothing was ever pulled (no `pull` in the log; compose was called with `--pull never` where the sub-command accepts it).
- `TestImageIDMismatchStopsTheInstall`: `STUB_IMAGE_IDS` differs → `[FAIL] The installation package is damaged or incomplete. …`, no `compose up`.
- `TestSignatureChecks` (S-7): tampered `SHA256SUMS` (one checksum changed) → the signature failure, because the signature is checked first (not the damaged-package message); a signature made by another key → the signature failure; an unlisted file (`lib/initdb/20-x.sh`, `release-keys/rk-evil.pem`) → the package-complete failure and nothing copied; a symlink anywhere in the package → the package-complete failure; one tar image whose bytes differ from `SHA256SUMS` → the package-complete failure; `openssl` removed from `PATH` (a `PATH` without it) → the OpenSSL failure; a valid package → the fingerprint line with the 64-hex SHA-256 of the DER key.
- `TestInstallNeedsTheFingerprintConfirmed` (S-23): interactive answer `no` → `Nothing was changed.`, exit 1, no installation directory; `--non-interactive` without `--fingerprint` → exit 2; with a wrong one → the mismatch sentence, exit 1.
- `TestInstallWarnsOnTestSignedPackage` (S-11): `TEST_SIGNED=1` in `RELEASE` → the `[WARN] … TEST key …` line from `install.sh` and from `alice-update.sh`.
- `TestInstallValidatesEnvValues` (S-9): `--hostname 'a$(id)'`, `--hostname 'a\nb'`, `--project 'A B'`, `--bind 1.2.3`, `--port 70000` → usage error, exit 2, nothing created; a `timedatectl` zone containing a newline → `UTC` and the `[WARN]` line.
- `TestInstallRefusesAnUnsafeDir` (S-8): a `--dir` whose parent has mode 0777, or is owned by uid 1000 → the C4 message, exit 2.
- `TestComposeIgnoresCallerEnvironment` (S-6): with `ALICE_IMAGE=evil:1`, `DOCKER_HOST=tcp://x`, `COMPOSE_FILE=/x` exported, the stub records an environment without them for every `docker` call.
- `TestTestOverridesAreAnnounced` (S-24): `ALICE_PROC_DIR` or `ALICE_DOCKER_SOCK` set → the `[WARN] Test override …` line on the terminal and in `install.log`; neither appears in any recorded `docker` environment.
- `TestInstallRefusesAnExistingInstallation`, `TestRestoreModeStartsOnlyPostgres` (no `master.key`, `up` only for `postgres`, the closing text of `--restore-mode`), `TestUninstallKeepsData` (`down` without `-v`; every directory remains), `TestPurgeNeedsTypedDelete` (`yes` → `Nothing was deleted.` and exit 1; `DELETE` → the directory is gone; `--confirm DELETE` works without a terminal).
- `TestVersionCompare`: table of C4 (`1.0.0` vs `1.0.0-rc.9` → 1; `1.0.0-rc.10` vs `1.0.0-rc.9` → 1; `1.10.0` vs `1.9.9` → 1; equal → 0; `1.0` → usage error exit 2).
- `TestUpdateRefusesTamperedAndDowngrade`: an installation stub (`VERSION`, `RELEASE`, `release-keys/`, scripts) at `1.0.0-rc.2`; packages: tampered outer `.sha256`, outer signature by an unknown key, inner `SHA256SUMS` signed only by a key that the package itself ships (not installed) → each the signature message and nothing changed (no `stop`, no backup call); version `1.0.0-rc.1` → the downgrade message; `1.0.0-rc.2` → "already at version"; `MIN_UPGRADE_FROM=1.0.0-rc.3` with a `1.0.0-rc.4` package → "Install 1.0.0-rc.3 first".
- `TestUpdateHappyPathOrder` (S-15): a valid newer package → the recorded calls in this order: `selfcheck`, `stop alice`, the `pg_terminate_backend` call through `exec -T postgres psql`, `run --rm alice-admin backup --reason pre-upgrade-<new>`, `run --rm alice-admin backup verify … --deep --passphrase-stdin` with the passphrase on standard input (never in any argument or environment of any call), rollback copy, `load` ×2, `run --rm migrate`, `up -d --wait … alice`, `selfcheck`; the new scripts installed and `release-keys/` **replaced** (a key only the old set had is gone, S-35); `Alice is now version <new>.`; exit 0; `.update-<ts>/` removed.
- `TestUpdateVerifiesACopy` (S-3): with `testdata/swap-openssl` first on `PATH`, the original tarball is replaced right after its signature was checked → the update proceeds with the verified bytes (the extracted `VERSION` is the signed one) and the script never reads the original path again. `TestUpdateDirectoryWithAnExtraFileIsRefused`: an extracted-directory argument with one file not listed in `SHA256SUMS` → the signature/package message, nothing changed.
- `TestUpdateRestartsAliceWhenTheBackupFails` (S-15): the backup call fails (stub) → `up -d --wait alice`, `The update was stopped before any change; Alice is running version <installed> again.`, exit 1, no rollback copy used.
- `TestUpdateRollsBackWhenMigrationFails`: `STUB_COMPOSE_FAIL="run migrate"` → after the failure: `stop alice`, the `pg_terminate_backend` session cleanup (M-4), the previous compose file and `.env` restored byte for byte, `run --rm alice-admin restore /opt/alice/backups/<pre-update name> --db-only --confirm RESTORE --passphrase-stdin` with the passphrase on standard input, `up -d --wait`, `selfcheck`; the C4 rollback message; exit 1; the pre-update backup is never deleted (no `rm` of it in the log).
- `TestUpdateExit3WhenTheRollbackFails`: the restore also fails → the manual-command message naming the backup; exit 3.
- `TestUpdateInterruptedAfterStopRollsBack`: the stub `docker` sleeps during `run migrate`; the test sends `SIGINT` to the script → the rollback path runs, exit 1.
- `TestAlicectl`: `backup` → `exec -T alice /usr/local/bin/alice backup`; `backup --reason pre-upgrade-1.1.0 --out x.alicebak` passes both options; `restore <inst>/backups/x.alicebak --passphrase-file f` → `exec -T alice … backup verify /opt/alice/backups/x.alicebak --deep --passphrase-stdin`, `stop alice`, the session cleanup, `run --rm alice-admin restore /opt/alice/backups/x.alicebak --free-bytes <n> --passphrase-stdin` with the file's content on stdin, `up -d --wait alice`, `exec … selfcheck` (S-16, S-22, M-4); `--no-safety-backup` is passed through; a file outside `<inst>/backups` → the C4 message, exit 2; `setup-token --reset` prints the code and no log file contains it (S-4); the passphrase canary appears in no recorded argument list or environment (S-25); `backup list` while `alice` is not running (stub `compose ps --status running --services` prints nothing) → `run --rm alice-admin backup list`; `support-bundle` → a `tar.gz` with mode 0600 holding `ps.txt`, `logs-alice.txt`, `logs-postgres.txt`, `bundle.json`, `docker-version.txt`, `df.txt`, `env.txt` without lines whose name contains `PASSWORD`, `SECRET` or `KEY`.
- `TestAlicectlWrongPassphraseNeverStopsAlice` (S-16): the deep verify fails → the C7 damaged sentence, exit 1, no `stop alice` in the log. `TestAlicectlRestartsAliceAfterAFailedRestore`: the `run --rm alice-admin restore` call fails → `up -d --wait alice` and `selfcheck` still run, exit 1.
- `TestAlicectlRefusesASymlinkedBackup` (S-8): `<inst>/backups/x.alicebak` is a symlink to a file outside `<inst>/backups` → the C4 message, exit 2, no `docker` call.
- `TestSupportBundleRefusesExistingOut` (S-10): `--out` naming an existing regular file, or a symlink (also a dangling one) → `The file <out> already exists.`, exit 2, the target untouched.
- `TestScriptsNeverTouchContainerDirs` (S-8, static): after the layout step no `chown`, `chmod`, `cp`, `cat`, `rm` or `>` with a path under `keys/`, `state/`, `backups/` or `data/` in the three scripts and the library.
- `TestScriptsNeverSourcePackageFiles`: a static check of the three scripts and the library: no `eval`; the only `source`/`.` line is `. "$here/lib/alice-lib.sh"` with `here` computed from `${BASH_SOURCE[0]}` through `cd -P`; no unquoted `$var` in command position (a regular expression for `[^"]\$[A-Za-z_]` outside `$(( ))`, assignments and `[[ ]]` — the test lists its allowed exceptions explicitly); every script starts with `set -Eeuo pipefail` and `umask 077`; no `curl`, `wget`, `docker pull` or `apt`/`dnf`/`yum` anywhere; no `set -x`, no `BASH_XTRACEFD`, no here-string `<<<`, no `export` of a variable whose name contains `pass` (S-25); every `docker` call goes through `alice_docker`/`alice_compose` (S-6).

Run: `go test ./deploy/release/ -count=1`
Expected: FAIL (scripts missing).

- [ ] **Step 2: Implement** the scripts to C4/C5 with the library holding: `alice_log`, `alice_ok`/`alice_warn`/`alice_fail`, `alice_version_cmp`, `alice_release_get KEY FILE` (`sed -n 's/^KEY=\(.*\)$/\1/p'` with a key allowlist), `alice_verify_sig FILE SIG KEYDIR` (C5 command, trying each `*.pem`), `alice_fingerprint KEY`, `alice_docker` and `alice_compose` (`env -i PATH="$PATH" HOME=/root LC_ALL=C docker compose --project-name "$project" -f "$dir/docker-compose.yml" --env-file "$dir/.env"`, S-6), `alice_wait_healthy`, `alice_random_password`, `alice_validate_env_values` (S-9), `alice_check_package DIR KEYDIR` (the S-7 order), `alice_terminate_leftover_sessions` (M-4). The scripts source the library with a `# shellcheck source=lib/alice-lib.sh` line above the `.` line. Interrupt handling: `trap` on `INT TERM` — before any change `Interrupted. Nothing was changed.`; during an update after `stop alice`, the rollback path.

Run: `go test ./deploy/release/ -count=1 -race` and `docker run --rm -v "$PWD/deploy/release:/s:ro" koalaman/shellcheck:v0.11.0@sha256:bb596a0d169b85ddd81d8b6d3a2ff6d5baf5fca10b97f575ebc647c3dff62b3d -x -P /s/lib /s/install.sh /s/alice-update.sh /s/alicectl /s/lib/alice-lib.sh /s/testdata/stubs/* /s/testdata/swap-openssl/openssl` (Docker: a throwaway container)
Expected: `ok`; no ShellCheck findings (a `# shellcheck disable=SCxxxx` needs a reason comment on the line above).

- [ ] **Step 3: Commit**

```bash
git add -- deploy/release/install.sh deploy/release/alice-update.sh deploy/release/alicectl deploy/release/lib \
  deploy/release/scripts_test.go deploy/release/testdata
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(deploy): install.sh, alice-update.sh with automatic backup and rollback, and the alicectl wrapper; stub-command tests for every message" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- deploy/release/install.sh deploy/release/alice-update.sh deploy/release/alicectl \
  deploy/release/lib deploy/release/scripts_test.go deploy/release/testdata
```

---

### Task 12: Release build: `make release`, bundle layout, SBOM, notices, release signing, `reproducible-check`, `release-keycheck`

**Files:**
- Create: `tools/releasebuild/main.go` (+ `main_test.go`), `tools/releasesign/main.go` (+ `main_test.go`), `tools/notices/main.go` (+ `main_test.go`), `deploy/release/keys/README.md`, `deploy/release/LICENSE.txt` (the text `Licensed to the customer under the terms of the signed order form; see your vendor.`; the vendor replaces it before release — M-6), `deploy/dev/reproducible-check.sh`, `deploy/dev/build-broken-release.sh` (M-27), `cmd/licensectl/release.go` (+ `release_test.go`), `internal/license/issuer/purpose_test.go`
- Modify: `internal/license/issuer/issuer.go` (key purpose), `cmd/licensectl/main.go` (usage, dispatch), `Makefile` (targets of C1 for this task), `tools/pincheck/main.go` (+ `main_test.go`: a docker image operand `$(<NAME>_IMAGE)` passes when the Makefile defines that variable with `?=` or `:=` as a digest-pinned literal, and `"$<NAME>_IMAGE"` in a shell script passes when the same script assigns it a digest-pinned default — moved here from Task 14 so Tasks 12, 14 and 15 all pass `go run ./tools/pincheck`, M-21), `docs/vendor/licensing-vendor.md` (the release key: generation, storage, ceremony, rotation — §16.7 rules apply), `.gitleaks.toml` (only if a new test fixture string needs it; the release test passphrase is `amber canyon violet orbit lantern harbor`, already matched by the existing allowlist entry)

**Interfaces:**
- Consumes: `issuer.GenerateKey`, `issuer.OpenKey`, `issuer.WriteKeyPair`, `make image`, `make helper`, the pinned Trivy image, `docker save`, `docker image inspect`.
- Produces: C5; `make release VERSION=x.y.z` (stage, unsigned), `make release-pack VERSION=x.y.z` (after `SHA256SUMS.sig` exists: tarball, outer checksum), `make release-test VERSION=x.y.z-rc.N` (stage with `-test -allow-draft`, sign with the test key, pack, sign the outer checksum — one command for the harness; a version without `-rc.N` is refused, S-11), `make release-broken VERSION=… BROKEN=fail|sleep SIGN=test|offline` (M-27), `make sbom`, `make notices`, `make reproducible-check`, `release-keycheck` extended; `licensectl release-keygen --out DIR --key-id rk-YYYY-NN`, `licensectl release-sign --key FILE FILE…` (writes `FILE.sig`), `licensectl release-verify --pub FILE FILE SIG`; `go run ./tools/releasesign generate DIR` / `sign DIR/test-release.key FILE…`.

- [ ] **Step 1: Write the failing tests**

- `internal/license/issuer/purpose_test.go`: `TestKeyPurposeSeparatesLicenseAndReleaseKeys` (a key file written with purpose `release` has the PEM header `Alice-Key-Purpose: release`; `OpenKey` for a license signature refuses it (`ErrWrongPurpose`); a release-signing open refuses a license key; a key file without the header (every existing one) is a license key).
- `cmd/licensectl/release_test.go`: `TestReleaseKeygenRefusesOverwriteAndLicenseIDs` (`--key-id vk-2026-01` refused: release IDs are `rk-YYYY-NN`; `--out` naming the license key directory refused, S-12), `TestReleaseSignAsksOnceAndSignsEachFile`, `TestOpenSSLVerifiesReleaseSignatures` (sign a file with a generated release key, write the PKIX public key, run the exact C5 `openssl pkeyutl` command → exit 0 and `Signature Verified Successfully`; one changed byte → non-zero; this machine and every CI runner have OpenSSL 3 — the test fails, never skips, without it).
- `tools/releasebuild/main_test.go`: `TestStageLayout` (fixture inputs in a temp dir → exactly the C5 file list, `env.template` written as `.env.template` and the role script as `lib/initdb/10-alice-roles.sh`, `RELEASE` keys and values, `SHA256SUMS` sorted, complete and excluding itself and its signature, the scripts executable `0755`, everything else `0644`), `TestPackIsDeterministic` (two packs of the same stage → identical bytes: sorted entries, `mtime` = `BUILD_TIME`, uid/gid 0, names `root`, gzip without a name or time), `TestPackRefusesAnUnsignedStage`, `TestStageRefusesAMissingInput` (the production path: no `SECURITY-REPORT.md`, or an empty gates log, is refused), `TestStageDraftPlaceholders` (M-6: with `-allow-draft`, the `SECURITY-REPORT.md` placeholder line, `licenses/LICENSE` from `LICENSE.txt`, and without a gates log `RELEASE-CHECKLIST-SIGNED.txt` saying `No gate was recorded for this package.`), `TestStageRefusesSymlinks` (S-7), `TestStageRefusesTestKeysWithoutTestFlag` (S-11: an `rk-test-01.pem` without `-test`, or a production key set that differs from `deploy/release/keys/` → refused; with `-test` the stage accepts `rk-test-NN` and writes `TEST_SIGNED=1`), `TestReleaseTestNeedsAnRCVersion` (runs `make -s release-test VERSION=1.0.0` → exit 2 with the usage line before anything is built), `TestReleaseAndLicenseKeysAreDisjoint` (S-12: the `keycheck` subcommand fails when a public key of `deploy/release/keys/*.pem` equals one in `internal/license/keys/production.json`; a fixture with the same key in both places).
- `tools/notices/main_test.go`: `TestNoticesCoverEveryLinkedModule` (on a fixture `go version -m` output and a fixture module cache: every `dep` line has a section with its license text; a module without a license file fails the tool), `TestNoticesCoverBundledNpmPackages` (packages of `web/package-lock.json` without `"dev": true`).
- `tools/releasesign/main_test.go`: `TestGenerateAndSign` (the key file is unencrypted and named `test-release.key`, the public key `rk-test-01.pem`; the tool refuses to write into `deploy/release/keys`).

Run: `go test ./internal/license/issuer/ ./cmd/licensectl/ ./tools/releasebuild/ ./tools/releasesign/ ./tools/notices/ ./tools/pincheck/ -count=1`
Expected: FAIL.

- [ ] **Step 2: Implement** the tools and the `licensectl` commands; then the Makefile:

```make
RELEASE_DIR      ?= bin/release
RELEASE_KEYS     ?= deploy/release/keys
RELEASE_TEST_KEY ?= bin/release-test-key
RELEASE_COMMIT   ?= $(shell git rev-parse HEAD 2>/dev/null)
RELEASE_STAGE_FLAGS ?=
# Every 1.0.x release accepts an update from the first release candidate on; raise it when a release needs an intermediate one.
MIN_UPGRADE_FROM ?= 1.0.0-rc.1
POSTGRES_RELEASE_IMAGE := postgres:16-alpine@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea

.PHONY: release
# One build time for the image and RELEASE (BUILD_TIME is a recursive ?= and would be re-evaluated per use).
release: BUILD_TIME := $(BUILD_TIME)
release: helper notices ## Stage an unsigned release in $(RELEASE_DIR)/alice-$(VERSION) (VERSION=x.y.z; sign SHA256SUMS offline, then make release-pack)
	@echo "$(VERSION)" | grep -Eqx '[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?' || { echo "make release needs VERSION=x.y.z or x.y.z-rc.N"; exit 2; }
	@test -n "$(RELEASE_COMMIT)" || { echo "make release needs RELEASE_COMMIT (no .git here)"; exit 2; }
	$(MAKE) image IMAGE_TAG=$(VERSION) VERSION=$(VERSION) BUILD_TIME=$(BUILD_TIME)
	docker image inspect $(POSTGRES_RELEASE_IMAGE) >/dev/null 2>&1 || docker pull postgres:16-alpine@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea
	docker tag $(POSTGRES_RELEASE_IMAGE) alice-postgres:$(VERSION)
	$(MAKE) sbom VERSION=$(VERSION)
	go run ./tools/releasebuild stage $(RELEASE_STAGE_FLAGS) -version $(VERSION) -out $(abspath $(RELEASE_DIR))/alice-$(VERSION) -keys $(RELEASE_KEYS) \
	  -alice-image alice:$(VERSION) -postgres-image alice-postgres:$(VERSION) -sbom $(abspath $(RELEASE_DIR))/sbom-$(VERSION) \
	  -notices bin/THIRD_PARTY_NOTICES.md -helper bin -commit $(RELEASE_COMMIT) -build-time $(BUILD_TIME) \
	  -gates-log bin/release-gates.log -license deploy/release/LICENSE.txt -min-upgrade-from $(MIN_UPGRADE_FROM)

.PHONY: release-pack
release-pack: ## Pack a signed stage into alice-$(VERSION).tar.gz with its checksum (sign the .sha256 offline afterwards)
	go run ./tools/releasebuild pack -stage $(abspath $(RELEASE_DIR))/alice-$(VERSION) -out $(abspath $(RELEASE_DIR))

.PHONY: release-test
release-test: ## Build, sign with a test key and pack a release (VERSION=x.y.z-rc.N only); never for customers
	@echo "$(VERSION)" | grep -Eqx '[0-9]+\.[0-9]+\.[0-9]+-rc\.[0-9]+' || { echo "make release-test needs VERSION=x.y.z-rc.N (a test-signed package is never a customer version)"; exit 2; }
	@test -f $(RELEASE_TEST_KEY)/test-release.key || go run ./tools/releasesign generate $(RELEASE_TEST_KEY)
	$(MAKE) release VERSION=$(VERSION) RELEASE_KEYS=$(RELEASE_TEST_KEY) RELEASE_STAGE_FLAGS="-test -allow-draft"
	go run ./tools/releasesign sign $(RELEASE_TEST_KEY)/test-release.key $(abspath $(RELEASE_DIR))/alice-$(VERSION)/alice/SHA256SUMS
	$(MAKE) release-pack VERSION=$(VERSION)
	go run ./tools/releasesign sign $(RELEASE_TEST_KEY)/test-release.key $(abspath $(RELEASE_DIR))/alice-$(VERSION).tar.gz.sha256

.PHONY: release-broken
release-broken: ## A package whose image carries a failing (BROKEN=fail) or sleeping (BROKEN=sleep) extra migration, for the update rollback test (SIGN=test: test-signed, rc versions; SIGN=offline: unsigned stage for the ceremony)
	./deploy/dev/build-broken-release.sh "$(VERSION)" "$(BROKEN)" "$(SIGN)" "$(abspath $(RELEASE_DIR))" "$(abspath $(RELEASE_TEST_KEY))"

.PHONY: sbom
sbom: ## CycloneDX SBOMs of the alice and postgres images and the source tree (pinned Trivy)
	mkdir -p $(abspath $(RELEASE_DIR))/sbom-$(VERSION)
	docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$(abspath $(RELEASE_DIR))/sbom-$(VERSION):/out" $(TRIVY_IMAGE) image --format cyclonedx --output /out/alice-$(VERSION).cdx.json alice:$(VERSION)
	docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$(abspath $(RELEASE_DIR))/sbom-$(VERSION):/out" $(TRIVY_IMAGE) image --format cyclonedx --output /out/postgres-$(VERSION).cdx.json alice-postgres:$(VERSION)
	docker run --rm -v "$(CURDIR):/src:ro" -v "$(abspath $(RELEASE_DIR))/sbom-$(VERSION):/out" -w /src $(TRIVY_IMAGE) fs --scanners vuln --format cyclonedx --output /out/source-$(VERSION).cdx.json --skip-dirs '**/node_modules',.claude,.superpowers,.git,bin .

.PHONY: notices
notices: build ## Third-party notices of the Go modules in bin/alice and the helper, and the bundled npm packages
	go run ./tools/notices -binaries bin/alice,bin/alice-helper-linux-amd64 -lockfile web/package-lock.json -node-modules web/node_modules -out bin/THIRD_PARTY_NOTICES.md

.PHONY: reproducible-check
reproducible-check: ## Build alice and the helpers twice from clean copies of HEAD in different paths and compare the bytes
	./deploy/dev/reproducible-check.sh
```

`deploy/dev/reproducible-check.sh` (new; ShellCheck-clean): `git archive HEAD` into `$(mktemp -d)/a/src` and `$(mktemp -d)/b/other/path/src`; in each `npm ci --ignore-scripts && npm run build` (in `web/`), then the helper and `alice` builds with `-trimpath -buildvcs=false` and the ldflags of `make build` with `VERSION=reproducible`, `COMMIT=$(git rev-parse --short HEAD)`, `BUILD_TIME=$(git log -1 --format=%cI)` and the helper checksums computed in that copy; compare `sha256sum` of `alice`, `alice-helper-linux-amd64`, `alice-helper-linux-arm64`; print `reproducible-check: ok (<three hashes>)` or the differing files and exit 1; remove both directories. The check covers the binaries only (R43 row 52).

`deploy/dev/build-broken-release.sh VERSION fail|sleep test|offline RELEASE_DIR RELEASE_TEST_KEY` (new; ShellCheck-clean; M-27): `git archive HEAD` into `$(mktemp -d)`; adds `migrations/99990_phase8_broken_test.sql` (Up: `SELECT 1/0;`) for `fail` or `migrations/99991_phase8_slow_test.sql` (Up: `SELECT pg_sleep(120);`) for `sleep`; copies this tree's `bin/release-gates.log` when it exists; runs inside the copy `make web-install` and then, with `RELEASE_COMMIT=<HEAD of this tree>`, `RELEASE_DIR=<RELEASE_DIR>` and `RELEASE_TEST_KEY=<RELEASE_TEST_KEY>` (both absolute), either `make release-test VERSION=…` (`test`: needs an `-rc.N` version) or `make release VERSION=…` (`offline`: an unsigned stage the vendor signs in the ceremony, then `make release-pack`); removes the copy. The broken migrations never exist in this tree. Task 13's harness and the owner's VM test (release checklist, owner step 5) both call it through `make release-broken`.

`release-keycheck` gains its release-key lines first (S-12):

```make
	@ls $(RELEASE_KEYS)/rk-*.pem >/dev/null 2>&1 || { echo "release-keycheck: no production release public key in $(RELEASE_KEYS) (docs/vendor/licensing-vendor.md, 'Release key')"; exit 1; }
	go run ./tools/releasebuild keycheck -release $(RELEASE_KEYS) -license internal/license/keys/production.json
```

Run: Step 1 command → `ok`. Then (Docker: image builds; Trivy pulls its DB on first use — run with the networking rule) `make release-test VERSION=1.0.0-rc.1 TRIVY_IMAGE="--network host aquasec/trivy:0.74.0@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969"`
Expected: `bin/release/alice-1.0.0-rc.1.tar.gz`, its `.sha256` and `.sha256.sig`; `tar tzf` lists exactly the C5 layout (with the draft placeholders of R43 row 51 and `TEST_SIGNED=1` in `RELEASE`); `cd bin/release/alice-1.0.0-rc.1/alice && sha256sum -c --strict SHA256SUMS` passes; the C5 `openssl` command verifies both signatures with `bin/release-test-key/rk-test-01.pem`.

Run: `make reproducible-check`
Expected: `reproducible-check: ok (…)`. If it is not, find the cause (embedded time, map order, Vite chunk names) and fix it in this task; never weaken the check.

Run: `make release-keycheck; echo exit=$?`
Expected: `release-keycheck: no production release public key …` and `exit=2` — the honest state until the owner commits the key (B).

- [ ] **Step 3: Commit**

```bash
git add -- tools/releasebuild tools/releasesign tools/notices deploy/release/keys/README.md deploy/release/LICENSE.txt cmd/licensectl/release.go \
  cmd/licensectl/release_test.go internal/license/issuer/purpose_test.go deploy/dev/reproducible-check.sh deploy/dev/build-broken-release.sh
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "build(release): release bundle with images, helper, SBOM, notices and checksums; Ed25519 release keys separate from license keys; test-signed packages marked; broken-update package script; reproducible-check; release-keycheck needs the release key" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- tools/releasebuild tools/releasesign tools/notices tools/pincheck deploy/release/keys \
  deploy/release/LICENSE.txt cmd/licensectl internal/license/issuer Makefile docs/vendor/licensing-vendor.md deploy/dev/reproducible-check.sh \
  deploy/dev/build-broken-release.sh
```

---

### Task 13: Release harness: install matrix in three distributions without network, F-85 drill, restore negatives, update and rollback (F-68), tampered and downgrade, uninstall (`make test-release`; **no Playwright**)

**Files:**
- Create: `test/images/install/ubuntu22.Dockerfile`, `debian12.Dockerfile`, `rocky9.Dockerfile`, `test/release/harness_test.go`, `install_test.go`, `drill_test.go`, `update_test.go` (all `//go:build release`)
- Modify: `Makefile` (target `test-release`)

**Interfaces:**
- Consumes: `make release-test` (Task 12), the scripts (Task 11), the CLI (Task 6), the e2e target image `test/images/e2e-target` (an SSH and Nginx server for the drill), the public API (wizard, users, targets, certificate upload, mail settings; TOTP computed in the test from the enrolment secret as the e2e helpers do).
- Produces: `make test-release`; the evidence for R43 rows 28–30.

- [ ] **Step 1: Images and harness**

Each install image: `FROM` the pinned base, `RUN` the distribution's `openssl`, `iproute2`/`iproute`, `procps`/`procps-ng`, `tar`, `gzip`, `coreutils` (Rocky: `--allowerasing` for `coreutils`), then `COPY --from=docker:29.9.0-cli@sha256:1a4c7cb63513f349bdad01fcc6e0f3f2f67d37b9da86f14dc0d4a0942eecda00 /usr/local/bin/docker /usr/local/bin/docker` and `COPY --from=… /usr/local/libexec/docker/cli-plugins/docker-compose /usr/local/libexec/docker/cli-plugins/docker-compose` (the implementer checks those two paths in the pinned image first with `docker run --rm --entrypoint ls <image> -l /usr/local/bin /usr/local/libexec/docker/cli-plugins` and uses the paths it shows). Built with `docker build --network host -t alice-test/install-<distro>:phase8 -f test/images/install/<distro>.Dockerfile test/images/install` (the build needs the package mirrors; the containers that run the installer have no network).

`harness_test.go`: `TestMain` first fails at once when one of the tags it would create (`alice:1.0.0-rc.1`..`rc.4`, `alice-postgres:1.0.0-rc.1`..`rc.4`, `alice-test/install-*:phase8`) already exists (it never removes an image it did not create, M-22) and when the file system of `bin/release-work/` has under 25 GB free (the message shows the free space, M-23); then it builds `1.0.0-rc.1`, `1.0.0-rc.2` (`make release-test VERSION=…`), and the two broken releases through `make release-broken VERSION=1.0.0-rc.3 BROKEN=fail SIGN=test` and `make release-broken VERSION=1.0.0-rc.4 BROKEN=sleep SIGN=test` (Task 12's `deploy/dev/build-broken-release.sh`: a `git archive HEAD` copy with the extra migration, built with `RELEASE_COMMIT=<HEAD of this tree>` and this tree's absolute `RELEASE_DIR` and `RELEASE_TEST_KEY`, so the broken migrations never exist in this tree and all four releases share one test key — M-7, M-27), image tags `alice:1.0.0-rc.3` and `alice:1.0.0-rc.4`. Every install passes `--fingerprint <SHA-256 of bin/release-test-key/rk-test-01.pem>` and expects the `TEST_SIGNED` warning. A helper `installIn(t, distro, workdir, args…)` (`workdir` is a directory under `bin/release-work/` of this tree, not `t.TempDir()`, M-23) runs `docker run --rm --network none -v /var/run/docker.sock:/var/run/docker.sock -v <workdir>:<workdir> -w <workdir>/alice alice-test/install-<distro>:phase8 ./install.sh --dir <workdir>/opt --port 1944N --bind 127.0.0.1 --hostname alice-rel.test --non-interactive --project alice-rel-<name> …` (the bind paths are identical inside and outside, so compose's relative mounts resolve on the host). `t.Cleanup`: `docker compose -p alice-rel-<name> … down -v --remove-orphans`, then the work directory is removed through a root container (`docker run --rm -v <workdir>:<workdir> alice-test/install-ubuntu22:phase8 rm -rf <workdir>`), then the image tags this run created. `stack(t, name)` returns an HTTPS client for `https://127.0.0.1:1944N` that trusts the installation's `keys/tls.crt`.

- [ ] **Step 2: Write the tests**

- `TestReleaseInstallMatrix` (subtests `ubuntu22`, `debian12`, `rocky9`, run one after another): the installer's output contains every preflight `[ OK ]`, the fingerprint line, and the closing text with a setup code; `docker compose -p … ps` shows `postgres` and `alice` healthy (the installer's `run --rm migrate` exited 0); the hardening of C3 holds on the **running** containers (`docker inspect`: users, read-only root, no capabilities, `no-new-privileges`, no published port on postgres, `alice` without any `ALICE_MIGRATE_DATABASE_*` variable, the secrets mounted only where C3 says); `alicectl selfcheck` (run through the same distro container) prints seven `[ OK ]` lines; the setup code opens `POST /api/v1/setup/session`; the installer container had `--network none` and no `pull` happened (`docker events --since <start> --until <end> --filter type=image --filter event=pull --filter image=alice --filter image=alice-postgres --filter image=ubuntu --filter image=debian --filter image=rockylinux/rockylinux` is empty; pulls by other Docker users, for example a parallel task's testcontainers, are not counted — M-17).
- `TestReleaseF85Drill` (Ubuntu image): install `rc.2`; run the wizard through the API (administrator with TOTP, recovery passphrase `amber canyon violet orbit lantern harbor`, upload a `pki` HTTPS certificate, mail settings with a password, evaluation license, a first SSH target: an `e2e-target` container attached to the installation's `frontend` network, its host key confirmed); create 3 users per role with TOTP; upload 10 certificates with keys; produce 500 audit rows (sign-ins and reads); record the facts of §20.6 step 2 through the API and `alicectl audit verify` (head hash) and a database row count query run with `docker compose exec postgres psql -U postgres -d alice` (counts only); `alicectl backup`; copy the file out; check it with `grep -c` for the mail password, the PEM header and the passphrase (zero); `alicectl restore` with a wrong passphrase → the C7 damaged sentence, counts unchanged; **wipe** (`down -v`, the installation directory removed through the root container); `install.sh --restore-mode`; copy the file into `backups/`; `alicectl restore … --passphrase-file … --confirm RESTORE`; verify: counts equal (sessions 0; audit + 1), the audit head before `system.restored` equal, every seeded user signs in with password and TOTP, Installation ID and license phase equal, **Test connection** to the SSH target succeeds with the restored platform key, a deployment of one uploaded certificate to the target succeeds.
- `TestReleaseRestoreNegatives` (Ubuntu image, on the drill's installation or a fresh one): through `alicectl restore`: a flipped byte in the header, in the salt, in the ciphertext, at a chunk boundary (F-81), a truncated file (F-82), an empty file and a text file (F-83), a file whose header says Alice `9.0.0` (made by a test-only option of the harness that rewrites the header and recomputes nothing — it is refused before the passphrase anyway) → the exact C7 sentences, exit 1, and the row counts and `keys/` hashes unchanged.
- `TestReleaseUpdateAndRollback` (Debian image): install `rc.1`, seed a little (wizard, two users, one certificate); `cd <inst> && ./alice-update.sh <path>/alice-1.0.0-rc.2.tar.gz --passphrase-file …` → `Alice is now version 1.0.0-rc.2.`, `selfcheck` OK, data present, a `pre-upgrade` backup exists; subtest `failing-migration`: update to `rc.3` → the C4 rollback sentence, exit 1, version `1.0.0-rc.2` running, `selfcheck` OK, row counts equal to before the attempt (F-68); subtest `killed-migration`: update to `rc.4` in the background, `docker kill` the `migrate` container 10 seconds after it starts → the orphaned `pg_sleep` backend is ended by the update's session cleanup (M-4), the rollback sentence, exit 1, `rc.2` running and healthy, `selfcheck` OK, counts equal (no exit 3); subtest `stopped-before-change`: a copy of the `rc.3` stage whose `RELEASE` names another `ALICE_IMAGE_ID`, with `SHA256SUMS` re-made and signed again with the test key and packed → the image check fails after the backup → `The update was stopped before any change; Alice is running version 1.0.0-rc.2 again.`, exit 1, `rc.2` running, counts equal (S-15).
- `TestReleaseRefusesTamperedAndDowngrade` (Rocky image): a copy of the `rc.2` package with one byte changed in `images/alice-*.tar` and a re-made `SHA256SUMS` but the old signature → the signature sentence; the original `rc.2` package with a `.sha256.sig` from another test key → the signature sentence; on an `rc.2` installation `alice-update.sh` with `rc.1` → the downgrade sentence; nothing changed (`docker compose ps` and `VERSION`).
- `TestReleaseUninstallKeepsData`: `install.sh --uninstall` → containers gone, every directory and backup present; `install.sh --uninstall --purge --confirm DELETE` → the installation directory gone.

`Makefile`:

```make
.PHONY: test-release
test-release: ## Release harness: install, backup/restore drill, update and rollback in Ubuntu 22.04, Debian 12, Rocky 9 containers (Docker; no Playwright meanwhile; ~30 min)
	set -o pipefail; go test -count=1 -timeout 90m -tags release -v ./test/release/ 2>&1 | tee bin/test-release.log
```

Run (**Docker; no Playwright anywhere**): `make test-release`
Expected: `ok  alice/test/release`; the log shows every subtest `PASS`. A subtest that cannot run because this engine refuses something (for example the socket mount) fails with the engine's message — it is never skipped; the controller then decides with the owner.

- [ ] **Step 3: Commit**

```bash
git add -- test/images/install test/release
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "test(release): install matrix in Ubuntu 22.04, Debian 12 and Rocky 9 containers without network; backup-wipe-restore drill; update with failing and killed migrations rolls back (F-68); tampered and downgrade refused" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- test/images/install test/release Makefile
```

---

### Task 14: Static gates: `osv-scanner`, `tools/lockcheck`, ShellCheck, actionlint, `tools/docscheck`, `FuzzOpenAPIInputs`, fuzz targets, the matrix traceability (`tools/matrixcheck`)

**Files:**
- Create: `tools/lockcheck/main.go` (+ test), `tools/matrixcheck/main.go` (+ test), `tools/docscheck/main.go` (+ test), `tools/docscheck/required.txt` (lines `<file>\t<required text>`; empty at first — Tasks 17 and 18 append theirs), `test/matrix/traceability.json`, `docs/security/traceability.md` (generated), `internal/api/fuzz_openapi_integration_test.go` (`//go:build integration`), `osv-scanner.toml`
- Modify: `Makefile` (`tools`, `lint`, `vuln`, targets `shellcheck`, `lockcheck`, `matrix-check`, `docs-check`, `actionlint`, `fuzz-backup`, `fuzz-api`, `fuzz-nightly`, `fuzz-release`, `test-backup-cycle`; the existing `fuzz-*` targets take `FUZZTIME ?= 60s`; `ci` gains `test-backup-cycle`), `tools/pincheck/main.go` (+ test: every `*_IMAGE ?=` variable of the Makefile and every `FROM`/`COPY --from=` of `test/images/**/*Dockerfile` must be pinned by tag and digest; the `$(<NAME>_IMAGE)` operand rule itself is Task 12's, M-21), shell scripts that ShellCheck flags (fixes only)

**Interfaces:**
- Consumes: §23–§25 tables of `06-quality.md` (IDs `L-\d+`, `F-\d+`, `S-\d+`, `R-\d+`, `A-\d+`, `O-\d+`, `X-\d+` at the start of a table row), every test function in the tree, the guides.
- Produces: the targets of C1; `test/matrix/traceability.json` entries `{"id":"F-80","status":"test|owner|deferred|gap","tests":["internal/backup:TestF80WrongPassphraseChangesNothing", …],"owner":"docs/security/reviews/phase-8.md#owner-verification","ruling":"R43 row 35","note":"…"}`.

- [ ] **Step 1: Write the failing tests**

- `tools/lockcheck`: `TestAcceptsTheRealLockfiles` (the repository's `web/package-lock.json` and `go.sum` pass), `TestRefusesAHiddenSecret` (a fixture lockfile built in the test with an extra field whose value is `"ghp_" + strings.Repeat("a", 36)` — never a token-shaped literal in a committed file, M-20 —, a `resolved` URL to another host, an `integrity` that is not `sha512-` base64, a `go.sum` line with a fourth field) → each reported with file and line. Allowed shapes: top-level keys `name`, `version`, `lockfileVersion`, `requires`, `packages`; per package the keys npm writes (`version`, `resolved`, `integrity`, `dev`, `optional`, `peer`, `devOptional`, `license`, `engines`, `dependencies`, `devDependencies`, `optionalDependencies`, `peerDependencies`, `peerDependenciesMeta`, `bin`, `funding`, `cpu`, `os`, `libc`, `hasInstallScript`, `deprecated`, `inBundle`, `bundleDependencies`, `link`, `name`), values: versions and ranges by pattern, `resolved` only `https://registry.npmjs.org/…`, `integrity` only `sha512-[A-Za-z0-9+/]+={0,2}`, `license` an SPDX-like token, `funding` URLs only; `go.sum`: `^\S+ v\S+(/go\.mod)? h1:[A-Za-z0-9+/]{43}=$`.
- `tools/matrixcheck`: `TestExtractsEveryMatrixID` (on a fixture spec), `TestRefusesMissingUnknownAndBrokenEntries` (an ID missing from the file; an entry for an ID the spec lacks; status `deferred` without `ruling`; `owner` without `owner` — errors in both modes), `TestPendingTestsFailOnlyWhenStrict` (M-5: a named test that does not exist yet is counted `pending` without `-strict` and is an error with it), `TestStrictRefusesGaps`, `TestDocIsCurrent` (`docs/security/traceability.md` equals the generated text; `-update` rewrites it).
- `tools/docscheck`: `TestCommandsInGuidesExist` (every `alicectl <word>`, `alice <word>`, `install.sh --flag`, `alice-update.sh --flag` and `make <target>` in a fenced block or inline code of `docs/**/*.md`, `SECURITY-REPORT.md` and `CHANGELOG.md` (from its Phase 8 entry on) is accepted by the scripts' usage text, the `alice` usage text and the Makefile's target list), `TestRelativeLinksResolve`, `TestRequiredTextIsPresent` (every line of `tools/docscheck/required.txt` names an existing file that contains its text; S-23, S-26).
- `FuzzOpenAPIInputs` (§25.6): one installed stack (`installed(f)`); the corpus is one valid body per create/update route from `api/openapi.yaml`'s examples; the fuzz function picks a route by an index argument and sends the bytes as the JSON body with the Administrator's session (step-up done) → the status is never 500 and the server never panics (the harness's recovered-panic counter stays 0).

Run: `go test ./tools/lockcheck/ ./tools/matrixcheck/ ./tools/docscheck/ ./tools/pincheck/ -count=1`
Expected: FAIL.

- [ ] **Step 2: Implement the tools; fill the traceability file**

`traceability.json` gets one entry per ID of §23–§25. For each ID, search the tests (`grep -rn --include='*_test.go' --exclude-dir=.claude -E 'func Test.*<IDdigits>|<ID>[^0-9]'`) and the phase plans' coverage maps and reviews (`docs/superpowers/plans/*`, `docs/security/reviews/phase-*.md`, never the independent audit files) for the tests that prove it; read each candidate test to confirm it asserts the matrix row's expected behaviour before listing it. IDs proven only by an owner walkthrough get `owner`; IDs the rulings deferred (for example R-04 statistical timing, P1-03; the real-Azure parts of F-4x) get `deferred` with the ruling; anything else without a proving test is a `gap` with a one-line note of what is missing. Report the gap list to the controller (it decides in Task 19: a fix task or a ruling).

Makefile (names and placement as C1; the tool versions in `tools`):

```make
OSV_SCANNER_VERSION ?= v2.6.0
GREMLINS_VERSION    ?= v0.6.0
ACTIONLINT_VERSION  ?= v1.7.12
SHELLCHECK_IMAGE    ?= koalaman/shellcheck:v0.11.0@sha256:bb596a0d169b85ddd81d8b6d3a2ff6d5baf5fca10b97f575ebc647c3dff62b3d
SHELL_SCRIPTS       := $(shell git ls-files -- '*.sh' deploy/release/alicectl 'deploy/release/testdata/stubs/*' deploy/release/testdata/swap-openssl/openssl test/images/e2e-target/systemctl test/images/e2e-target/nginx-wrapper)
FUZZTIME            ?= 60s

.PHONY: shellcheck lockcheck matrix-check docs-check actionlint osv test-backup-cycle fuzz-backup fuzz-api fuzz-nightly fuzz-release
shellcheck: ## ShellCheck every shell script (pinned image)
	docker run --rm -v "$(CURDIR):/src:ro" -w /src $(SHELLCHECK_IMAGE) -x $(SHELL_SCRIPTS)
lockcheck: ## Refuse anything but package data in web/package-lock.json and go.sum (secret-scan substitute, R43 row 38)
	go run ./tools/lockcheck web/package-lock.json go.sum
matrix-check: ## Every ID of the §23–§25 matrices maps to existing tests, an owner step or a ruling
	go run ./tools/matrixcheck -spec docs/superpowers/specs/alice-v1/06-quality.md -map test/matrix/traceability.json -doc docs/security/traceability.md
docs-check: ## Commands named in the guides exist; relative links resolve
	go run ./tools/docscheck
actionlint: ## Lint the GitHub workflows
	actionlint .github/workflows/*.yml
osv: ## osv-scanner over go.mod and the npm lockfile (High/Critical with a fix fail)
	osv-scanner scan source --config osv-scanner.toml -L go.mod -L web/package-lock.json
test-backup-cycle: ## F-85 full cycle with a test license (integration, testlicense)
	go test -race -count=1 -tags 'integration testlicense' -run '^TestF85' -v ./internal/backup/
fuzz-backup: ## Fuzz the backup header, stream and payload decoder ($(FUZZTIME) each)
	go test -count=1 -run '^$$' -fuzz FuzzBackupHeader -fuzztime $(FUZZTIME) ./internal/backup/format/
	go test -count=1 -run '^$$' -fuzz FuzzBackupStream -fuzztime $(FUZZTIME) ./internal/backup/format/
	go test -count=1 -run '^$$' -fuzz FuzzDecoder -fuzztime $(FUZZTIME) ./internal/backup/dump/
fuzz-api: ## Fuzz every create/update body (needs Docker; $(FUZZTIME))
	go test -count=1 -tags integration -run '^$$' -fuzz FuzzOpenAPIInputs -fuzztime $(FUZZTIME) ./internal/api/
fuzz-nightly: ## Every fuzz target for 10 minutes (§25.6 nightly)
	$(MAKE) fuzz-license fuzz-ssh fuzz-oidc fuzz-nginx fuzz-certs fuzz-backup fuzz-api FUZZTIME=10m
fuzz-release: ## Every fuzz target for 30 minutes (§25.6 release; about 7 hours)
	$(MAKE) fuzz-license fuzz-ssh fuzz-oidc fuzz-nginx fuzz-certs fuzz-backup fuzz-api FUZZTIME=30m
```

(The `osv-scanner` v2 flag spelling is checked with `osv-scanner scan source --help` after `make tools`; adjust the line to the help text, keeping the two lockfiles and the config.) `lint` runs, after `go run ./tools/pincheck`: `$(MAKE) shellcheck lockcheck docs-check actionlint`; `matrix-check` joins `lint` in Task 19 Step 2, after every named test exists (M-5). `vuln` gains `$(MAKE) osv`. `osv-scanner.toml` starts empty except a comment: an ignore needs `id`, `reason` and `ignoreUntil` (at most 90 days).

Run: Step 1 command → `ok`. Then `make tools && make lint && make vuln` (Docker: ShellCheck; network: the vulnerability databases)
Expected: green; `make matrix-check` (run by hand here, not yet in `lint`) prints `matrix-check: <n> IDs, <t> by tests, <p> pending, <o> owner, <d> deferred, <g> gaps` and passes (pending tests and gaps fail only with `-strict`, which Task 19 and `release-gates` use). A real finding of `osv` or ShellCheck is fixed in this task (dependency bump through the usual rules of `docs/dev/dependency-updates.md`, script fix) or reported to the controller.

Run: `go test -tags integration -count=1 -run '^$' -fuzz FuzzOpenAPIInputs -fuzztime 5m ./internal/api/` (Docker: testcontainers)
Expected: `PASS`; any 500 found is a bug fixed in the owning handler (its own commit) with the input as a regression seed.

Run, as the last step of this task and only after Task 5's commit is on the branch (same wave): `make test-backup-cycle` (Docker) → `ok`.

- [ ] **Step 3: Commit**

```bash
git add -- tools/lockcheck tools/matrixcheck tools/docscheck test/matrix docs/security/traceability.md internal/api/fuzz_openapi_integration_test.go osv-scanner.toml
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "build: osv-scanner, lockfile shape check, ShellCheck, actionlint, docs check and the §23–§25 traceability check in make lint/vuln; FuzzOpenAPIInputs; fuzz-nightly and fuzz-release" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- tools/lockcheck tools/matrixcheck tools/docscheck tools/pincheck test/matrix \
  docs/security/traceability.md internal/api/fuzz_openapi_integration_test.go osv-scanner.toml Makefile
```

(Script fixes ShellCheck asked for are committed separately, `fix(scripts): …`, with their own paths.)

---

### Task 15: Dynamic gates and pipelines: ZAP, testssl, real-systemd job, three-browser Playwright, mutation testing, `nightly.yml`/`release.yml`, `make nightly`, `make release-gates` (**Docker alone**)

**Files:**
- Create: `.zap/rules.tsv`, `tools/zaprules/main.go` (+ test), `tools/zapsession/main.go` (+ test), `test/images/systemd/ubuntu22.Dockerfile`, `internal/providers/nginx/systemd_test.go` (`//go:build systemd`), `.github/workflows/nightly.yml`, `.github/workflows/release.yml`, `deploy/dev/zap-stack.sh`
- Modify: `Makefile` (targets of C1 for this task), `web/playwright.config.ts` (projects `chromium`, `firefox`, `webkit`; `make e2e` keeps `--project=chromium`)

**Interfaces:**
- Consumes: `make image` (`alice:ci`, the release build), the development compose file under project `alice-zap` on `127.0.0.1:9445` (`deploy/dev/zap-stack.sh up|down`: `ALICE_VERSION=ci ALICE_PORT=9445 docker compose -p alice-zap -f deploy/docker-compose.yml -f <out>/compose.loopback.yml --env-file deploy/.env up -d --wait`, where `compose.loopback.yml` is a small override written by the script that publishes `127.0.0.1:9445:8443` only (the development compose publishes on every address) — the release image, no `/test` routes; `down -v` removes it; the script reads the scanner images from `ZAP_IMAGE`/`TESTSSL_IMAGE` with digest-pinned defaults assigned in the script, never from positional arguments, M-21), the public API (wizard and users, as Task 13's drill does), `internal/providers/nginx` real-Nginx test helpers.
- Produces: `make zap-baseline`, `make zap-full`, `make testssl`, `make test-systemd`, `make e2e-browsers`, `make mutation`, `make nightly`, `make release-gates`; the two workflows.

- [ ] **Step 1: ZAP and testssl**

`tools/zapsession` (`go run ./tools/zapsession -base https://127.0.0.1:9445 -ca <file> -setup-code <code> -out <dir>`): runs the wizard through the API on the fresh `alice-zap` stack, creates an Operator and an Auditor with TOTP, signs each role in (TOTP computed from the enrolment secret), performs step-up for the Administrator, and writes `<dir>/<role>.env` with `COOKIE=__Host-alice_session=…` and `CSRF=…` for ZAP's replacer; tests: `TestWritesOneSessionPerRole` against an in-process server of the API test harness. `tools/zaprules`: `.zap/rules.tsv` lines `<rule id>\t<IGNORE|WARN|FAIL>\t<reason>\t<expires YYYY-MM-DD>`; refuses a missing reason, an expiry more than 180 days ahead, an expired line; test with fixtures.

Makefile:

```make
ZAP_IMAGE     ?= ghcr.io/zaproxy/zaproxy:2.17.0@sha256:7aaa659b0d43078febd82e29bad112285c370727e86ab8340444220e17d9f0d2
TESTSSL_IMAGE ?= ghcr.io/testssl/testssl.sh:3.2@sha256:51918b1e954df0acee8c08d3ad5ce306710e4fefe49ed0e0f92728ecf9e7ff34
ZAP_OUT       := bin/zap
TESTSSL_TARGET ?=
TESTSSL_CA     ?=
export ZAP_IMAGE TESTSSL_IMAGE

.PHONY: zap-baseline zap-full testssl test-systemd e2e-browsers mutation nightly release-gates
zap-baseline: image ## ZAP passive baseline and API scan of the release image, unauthenticated and as Admin, Operator, Auditor (Docker)
	go run ./tools/zaprules .zap/rules.tsv
	@status=0; ./deploy/dev/zap-stack.sh up $(ZAP_OUT) && ./deploy/dev/zap-stack.sh scan baseline $(ZAP_OUT) || status=$$?; ./deploy/dev/zap-stack.sh down; exit $$status
zap-full: image ## ZAP full active scan against a disposable stack (hours; release gate; owner/CI)
	go run ./tools/zaprules .zap/rules.tsv
	@status=0; ./deploy/dev/zap-stack.sh up $(ZAP_OUT) && ./deploy/dev/zap-stack.sh scan full $(ZAP_OUT) || status=$$?; ./deploy/dev/zap-stack.sh down; exit $$status
testssl: ## testssl.sh, grade A or A+ required: the release image on the zap stack, or TESTSSL_TARGET=host:port (TESTSSL_CA=file) without a stack (Docker)
	@if [ -n "$(TESTSSL_TARGET)" ]; then ./deploy/dev/zap-stack.sh testssl-target "$(TESTSSL_TARGET)" "$(TESTSSL_CA)" $(ZAP_OUT); \
	else status=0; $(MAKE) image && ./deploy/dev/zap-stack.sh up $(ZAP_OUT) && ./deploy/dev/zap-stack.sh testssl $(ZAP_OUT) || status=$$?; ./deploy/dev/zap-stack.sh down; exit $$status; fi
```

`deploy/dev/zap-stack.sh`: `up` (start, wait, read the setup code with `docker compose -p alice-zap exec -T alice /usr/local/bin/alice setup-token --reset`, copy `keys/tls.crt` out with `docker compose cp`, run `tools/zapsession`), `scan baseline` (four `zap-baseline.py -t https://127.0.0.1:9445 -c rules.tsv -J <role>.json -r <role>.html` runs — the three authenticated ones with `-z "-config replacer.full_list(0).description=session -config replacer.full_list(0).enabled=true -config replacer.full_list(0).matchtype=REQ_HEADER -config replacer.full_list(0).matchstr=Cookie -config replacer.full_list(0).replacement=<cookie> …"` plus the CSRF header as a second replacer rule — then `zap-api-scan.py -t /zap/wrk/openapi.yaml -f openapi -c rules.tsv` as Administrator, with `api/openapi.yaml` copied into the work directory and its server URL set to the stack), `scan full` (`zap-full-scan.py` as Administrator), each with `--network host`, the output directory mounted at `/zap/wrk`; exit non-zero when any report has a Medium or High alert not ignored by `rules.tsv`; `testssl` (`--add-ca /out/tls.crt --jsonfile-pretty /out/testssl.json https://127.0.0.1:9445`, then the grade from the JSON's `rating` section must be `A` or `A+`); `testssl-target HOST:PORT [CA] OUT` (the same check against a host the owner names, with `--add-ca` only when a CA file is given; no stack is started — M-28); `down` (`down -v --remove-orphans`).

Run (**Docker alone**): `make zap-baseline; echo zap=$?; make testssl; echo testssl=$?`
Expected: each prints its summary and exits 0. A Medium/High alert or a grade below A is a finding: fixed in the owning code (header, cookie, TLS setting) in its own commit, or — only where the spec allows — an ignore line with reason and expiry, recorded for the security review. Record the outputs (alert counts per level and role, the grade) for Task 18.

- [ ] **Step 2: Real-systemd job**

`test/images/systemd/ubuntu22.Dockerfile`: `FROM ubuntu:22.04@sha256:5ec03bb3441e8b0bf3b4f9cd4629a1ae763010dc3035bb8da3ae6cf026486401`; install `systemd systemd-sysv dbus openssh-server sudo nginx openssl ca-certificates procps`; mask `getty@.service`, `systemd-logind` as needed for containers; `STOPSIGNAL SIGRTMIN+3`; `CMD ["/sbin/init"]`; built with `--network host`. `systemd_test.go` (`//go:build systemd`): `TestRealSystemdNginx` starts the image with `--privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock` (container name `alice-sysd-<random>`, removed in `t.Cleanup`), waits for `systemctl is-system-running` to answer `running` or `degraded`, installs the release-built helper with the setup script (as `TestRealNginx` does — read `internal/providers/nginx/containers_integration_test.go` and reuse its setup functions; move shared helpers into a file both build tags include if needed), then: discovery lists the default site's certificate pair after the test enables TLS on it; a deployment of a new `pki` pair ends `committed` and the TLS handshake on port 443 presents it; `systemctl is-active nginx` is `active` after the reload; a deployment that makes `nginx -t` fail ends `restored` with the old pair served; the outcomes equal those of the same scenario under the shim (`TestRealNginx`'s expectations).

```make
test-systemd: helper ## Real-systemd Nginx job (R38 item 16): privileged Ubuntu 22.04 container with systemd as PID 1 (Docker)
	go test -count=1 -v -timeout 20m -tags systemd -ldflags "$(HELPER_LDFLAGS)" -run '^TestRealSystemdNginx$$' ./internal/providers/nginx/
```

Run (**Docker alone**): `make test-systemd`
Expected: `ok`. If the engine refuses the privileged container or systemd does not boot (cgroup errors), the target fails with the engine's message; the controller records `NOT RUN (CI)` for this machine and the job stays in `nightly.yml`.

- [ ] **Step 3: Browsers, mutation, pipelines**

`web/playwright.config.ts`: `projects: [{name: 'chromium', use: devices['Desktop Chrome']}, {name: 'firefox', use: devices['Desktop Firefox']}, {name: 'webkit', use: devices['Desktop Safari']}]`; the Makefile `e2e` recipe adds `--project=chromium`.

```make
e2e-browsers: ## Every Playwright spec on Chromium, Firefox and WebKit in EN and TR (make e2e-up first; nightly and release)
	cd web && npx playwright install chromium firefox webkit && port="$${ALICE_E2E_PORT:-}" && set -a && { [ ! -f ../deploy/.env ] || . ../deploy/.env; } && set +a && { [ -z "$$port" ] || ALICE_E2E_PORT="$$port"; } && export ALICE_E2E_PORT && ALICE_E2E_PROJECT=$(E2E_PROJECT) npx playwright test --project=chromium --project=firefox --project=webkit
mutation: ## Mutation testing of the security-critical pure packages (advisory; nightly)
	gremlins unleash --tags '' ./internal/backup/format
	gremlins unleash --tags '' ./internal/license
	gremlins unleash --tags '' ./internal/rbac
nightly: ## The nightly set (§22.7 stage 5) on this machine; hours; Docker alone
	$(MAKE) fuzz-nightly test-release test-systemd zap-baseline testssl mutation
	@status=0; $(MAKE) e2e-up e2e-browsers || status=$$?; $(MAKE) e2e-down; exit $$status
release-gates: ## Every release gate that runs on one machine (§22.7 stage 6, §17.7); hours; Docker alone
	$(MAKE) ci
	go run ./tools/matrixcheck -strict -spec docs/superpowers/specs/alice-v1/06-quality.md -map test/matrix/traceability.json -doc docs/security/traceability.md
	$(MAKE) reproducible-check test-release test-systemd zap-baseline testssl test-backup-cycle
	@status=0; $(MAKE) e2e-up e2e-browsers || status=$$?; $(MAKE) e2e-down; exit $$status
	$(MAKE) release-keycheck
```

(`release-gates` records each gate it ran in `bin/release-gates.log`, one line `<gate>\t<exit status>\t<tool version>`, which `tools/releasebuild stage` turns into `RELEASE-CHECKLIST-SIGNED.txt` (M-6, C5); if the recipe gets unreadable, the loop lives in `deploy/dev/release-gates.sh`. `zap-full` and `fuzz-release` are not in `release-gates`: they run on the owner's or CI's machine for hours; the release checklist lists them. `release-keycheck` is last so that every other gate's result is known before it fails on the missing production key.)

`.github/workflows/nightly.yml` (`on: schedule: cron '17 2 * * *'` and `workflow_dispatch`; jobs on `ubuntu-latest` with the actions pinned by the SHAs `ci.yml` uses: `fuzz` (`make fuzz-nightly`), `release-harness` (`make test-release`), `systemd` (`make test-systemd`), `dast` (`make zap-baseline testssl`), `browsers` (`make e2e-up`, `npx playwright install --with-deps`, `make e2e-browsers`, `make e2e-down`), `mutation` (`make tools mutation`, continue-on-error), `azure` (`make test-azure` only when `secrets.ALICE_AZURE_TEST_CLIENT_ID != ''`); `permissions: contents: read`). `.github/workflows/release.yml` (`on: push: tags: ['v*']`; `make release-gates` without the key check, `make zap-full`, `make fuzz-release`, `make release VERSION=${GITHUB_REF_NAME#v}`, upload of the unsigned stage and the reports as artifacts; a closing step that prints "Sign SHA256SUMS on the offline machine (docs/release-checklist.md)" — no signing key in CI, §17.1).

Run: `make actionlint && go test ./tools/zaprules/ ./tools/zapsession/ -count=1 && cd web && npx playwright test --list --project=firefox | tail -1`
Expected: green; the list shows the specs for Firefox.

Run (**Docker alone**): `make e2e-up && make e2e-browsers; echo browsers=$?; make e2e-down`
Expected: Chromium and Firefox pass. WebKit either passes or fails to launch because this host lacks its system libraries (Playwright names the missing ones): in that case record `NOT RUN (CI)` for WebKit with the message; a WebKit **test** failure (the browser started) is a real finding to fix.

Run: `make tools && make mutation 2>&1 | tail -20`
Expected: three efficacy and coverage summaries; record them (advisory, no threshold).

- [ ] **Step 4: Commit**

```bash
git add -- .zap/rules.tsv tools/zaprules tools/zapsession test/images/systemd internal/providers/nginx/systemd_test.go \
  .github/workflows/nightly.yml .github/workflows/release.yml deploy/dev/zap-stack.sh
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "build: ZAP baseline/API/full scans, testssl, the real-systemd Nginx job, three-browser Playwright, mutation testing; nightly and release workflows; make nightly and make release-gates" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- .zap tools/zaprules tools/zapsession test/images/systemd \
  internal/providers/nginx/systemd_test.go .github/workflows deploy/dev/zap-stack.sh Makefile web/playwright.config.ts
(add `deploy/dev/release-gates.sh` to both lists if it was created)
```

---

### Task 16: End-to-end: Phase 8 journeys in EN and TR, accessibility (**Docker alone**)

**Files:**
- Create: `web/e2e/phase8.spec.ts`
- Modify: `web/e2e/helpers.ts` (helpers `uploadHttpsPair`, `downloadBackup` if shared)

**Interfaces:**
- Consumes: the e2e stack (`make e2e-up`; Task 3 gave it a backups volume, Task 6's `/test/reset` empties it), `resetInstall`, `runWizard` (extended for the two new steps — read it and add the steps with the default choices "keep temporary" and "skip", so every older spec keeps working), `signIn`, `freshCode`, `advanceClock`, `runScheduled`, `expectAccessible`, `expectWide`, `translator`, `COPY`, the certificate pack the Phase 4 specs use for uploads.
- Produces: `web/e2e/phase8.spec.ts`.

- [ ] **Step 1: Write the journeys** (each in `en` and `tr`, `test.describe.configure({ mode: 'serial' })` where they share an installation):
  1. **Wizard with every step**: reset; setup code → language → administrator with TOTP → recovery codes → recovery passphrase (a `fair` one keeps **Continue** disabled with the explanation; a good one continues) → HTTPS step: upload the pack's PEM pair → `https.applied`; **Back** → the passphrase step shows its done state; forward again → mail step: **Skip** → license: evaluation → first server: skip → finish; reload in the middle (after the HTTPS step) resumes at the mail step; `expectWide` at 375 px on the HTTPS and mail steps; `expectAccessible` on each new step.
  2. **Finish setting up**: after a wizard with "keep the temporary certificate" and "skip", the dashboard shows `setup-checklist` with `https` (marked required) and `mail`; their links open the right Settings tabs.
  3. **Backups**: Settings → Backups (step-up) → **Back up now** → a row with kind `manual` and check `ok`; **Download** asks the authenticator code, then the browser downloads a file whose first 8 bytes are `ALICEBK1` (`trace`, `video`, `screenshot` off; the file deleted in `finally`); the schedule form refuses retention 61 with the catalogue text and saves 21; the dashboard's backup card shows the last success.
  4. **48-hour banner**: `advanceClock(49h)` with no backup in between (the scheduled task is not run: `runScheduled` is not called) → Administrators see `backup-alarm-banner` with `backups.alarm`; an Operator does not; after **Back up now** it disappears.
  5. **Audit forwarding**: saving `169.254.169.254` shows the `ALC-AUD-0002` title; saving `127.0.0.1` port 1 and **Send test message** shows the `ALC-AUD-0003` title; the backlog line is visible.
  6. **HTTPS in Settings**: the tab shows the temporary state; a wrong PFX password shows the `ALC-TLS-0004` title; a valid upload shows the new fingerprint, and a new page load (the browser's next TLS handshake to the e2e port) still works.

Run (**Docker alone**: no testcontainers anywhere, and no `make lint` by any agent — it runs ShellCheck in a container): `make e2e-up && cd web && ALICE_E2E_PROJECT=alice-e2e npx playwright test e2e/phase8.spec.ts --project=chromium; cd .. && make e2e-down`
Expected: every test passes in both languages.

Run (**Docker alone**): `make e2e-up && make e2e; make e2e-down`
Expected: the whole suite passes (the extended `runWizard` keeps the older specs green).

- [ ] **Step 2: Commit**

```bash
git add -- web/e2e/phase8.spec.ts
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "test(e2e): Phase 8 journeys in EN and TR: full wizard with Back and resume, finish-setting-up, backups and download, 48-hour banner, audit forwarding, HTTPS certificate" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- web/e2e/phase8.spec.ts web/e2e/helpers.ts
```

---

### Task 17: Documentation set and `tools/docscheck` content

**Files:**
- Create: `docs/install-guide.md`, `docs/backup-restore.md`, `docs/upgrade.md`, `docs/security-overview.md`, `docs/api.md`, `docs/README.md`
- Modify: `tools/docscheck/required.txt` (this task's lines: `docs/install-guide.md` must contain `openssl pkeyutl -verify` — S-23), `docs/operator-guide.md` (production layout C2; `alicectl` reference of C4/C6 with each command's output; restore on the same and on a fresh host (the passphrase is all a fresh host needs, R43 row 41); after a restore, review users and API tokens — they are as they were when the backup was made (S-33) — and expect the forwarding collector to receive rows again and `system.restored` as a visible fork (S-32); the update (Alice stops before the pre-update backup, R43 row 44); a monthly `alicectl backup verify --deep` of the newest backup (S-29); logs; health; disk (the free-space refusals of R43 row 46); replacing the TLS certificate in Settings; changing SMTP in Settings; reboot behaviour; monitoring recommendations (what to alert on: `selfcheck`, the backup alarm, forwarding backlog, the dashboard conditions); user off-boarding; moving to a new host; that the recovery passphrase and the master key cannot be changed in v1 (R43 carry 18); the development stack vs the production compose), `docs/admin-guide.md` (Backups page with the free-space line, HTTPS certificate, Audit forwarding with a SIEM example (rsyslog with TLS) and its at-most-once delivery — watch `seq` gaps at the collector (R43 row 31), the setup checklist), `docs/first-run.md` (the full wizard of R43 row 16, the "before you begin" checklist with the passphrase, certificate, mail details and license request), `docs/troubleshooting.md` (edited only after Task 9's first commit is on the branch, appending below the code sections and never reordering them — M-16; sections "Install and start problems" — every `[FAIL]` line of C4 with its fix, the fingerprint confirmation and the TEST-key warning —, "Backup failed" (including `disk_full` and `not_configured` after a v1 key), "Restore refused" — the C7 sentences, the safety-backup and free-space ones included —, "Update rolled back" and "Update stopped before any change", "How to create a support bundle"), `docs/licensing.md` (moving to new hardware through a restore keeps the license)

**Interfaces:**
- Consumes: C2–C9, C12, C13 texts, the scripts' usage texts.
- Produces: the §21 set; `make docs-check` passes.

- [ ] **Step 1: Write the guides** in the existing style (short sentences, numbered steps with an expected result, exact button names of C13, every command exactly as C4/C6 define it). Required content per new file:
  - `install-guide.md`: host requirements (§18.2 table), Docker Engine and the compose plugin on Ubuntu 22.04, Debian 12, Rocky 9 (online and an offline-package note), OpenSSL 3, firewall ports, DNS name, NTP; verifying the package before extracting, as the **first** step (the C5 commands: the `openssl pkeyutl -verify -pubin -inkey <vendor key> -rawin -in alice-<v>.tar.gz.sha256 -sigfile alice-<v>.tar.gz.sha256.sig` check with the vendor's published release key, then `sha256sum -c alice-<v>.tar.gz.sha256`, then comparing the fingerprint the installer prints and confirming it — `--fingerprint` for unattended installs, R43 row 43); running `install.sh` and every option; each preflight message and its fix; the setup code; `--uninstall` and `--purge`.
  - `backup-restore.md`: what is backed up (C7), schedule and retention settings, the passphrase (what losing it means), off-host copy recipes (rsync with `--ignore-existing`, scp, SMB, S3 with a CLI of the customer's choice) and the 3-2-1 rule, `backup verify` vs `--deep`, restore on the same host and on a fresh host (§20.4 with `--restore-mode`), the disaster-recovery drill with an RTO/RPO log template (§20.5).
  - `upgrade.md`: pre-upgrade checklist (a recent good backup, the passphrase at hand, a quiet period, announce the short outage — R43 row 23), `cd /opt/alice && sudo ./alice-update.sh <tarball>`, what the automatic backup and rollback do, reading `update-<ts>.log`, exit codes 0/1/3, supported paths (`MIN_UPGRADE_FROM`), going back = restoring a pre-upgrade backup.
  - `security-overview.md`: architecture and data-flow diagram (Mermaid or ASCII), trust boundaries (TB0–TB6), stored data and where, encryption (envelope, master key, Argon2id, AES-256-GCM, the backup format), authentication and MFA, RBAC (link `authz-matrix.md`), audit hash chain and forwarding, network ports, container hardening (C3), no telemetry, supply chain (SBOM, signatures, scanners), threat model summary, residual risks (summary of `SECURITY-REPORT.md`), a KVKK/BDDK-oriented control mapping table (control area → Alice feature → evidence), vulnerability reporting and patch policy (§17.4).
  - `api.md`: base URL, authentication with personal API tokens (scopes `read`, `operate`), CSRF rules for browsers, error body, pagination, `curl` examples for listing certificates and targets and for the audit export, the OpenAPI file location, what tokens cannot do (step-up routes, backups).
  - `README.md`: the "Which document do I need?" table by role and task.

A guide may name a `make` target that a parallel task has not committed yet (`test-release`, Task 13): `docs-check` then fails on it; wait for that commit rather than removing the reference.

Run: `make docs-check && make lint`
Expected: green.

- [ ] **Step 2: Commit**

```bash
git add -- docs/install-guide.md docs/backup-restore.md docs/upgrade.md docs/security-overview.md docs/api.md docs/README.md
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "docs: install, backup and restore, upgrade, security overview, API and index guides; operator, admin, first-run, troubleshooting and licensing updated for packaging" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- docs/install-guide.md docs/backup-restore.md docs/upgrade.md \
  docs/security-overview.md docs/api.md docs/README.md docs/operator-guide.md docs/admin-guide.md docs/first-run.md \
  docs/troubleshooting.md docs/licensing.md tools/docscheck/required.txt
```

---

### Task 18: `SECURITY-REPORT.md` and the release checklist

**Files:**
- Create: `SECURITY-REPORT.md` (repository root; Task 12's stage copies it), `docs/release-checklist.md`
- Modify: `tools/docscheck/required.txt` (this task's line: `docs/release-checklist.md` must contain `make reproducible-check` — S-26)

**Interfaces:**
- Consumes: every phase review (`docs/security/reviews/phase-1.md` … `phase-7.md`, `audit-remediation.md`; never the independent-audit files), the rulings, R34–R43, the outputs recorded by Tasks 12–14 (Task 15 runs later; its cells stay `PENDING-FINAL-RUN`), `docs/security/traceability.md`.
- Produces: the two documents; the class-B tables the owner fills.

- [ ] **Step 1: `SECURITY-REPORT.md`** with exactly the ten sections of §17.6: (1) metadata (version `1.0.0` candidate, date, commit — filled in Task 19 —, authors, reviewers: empty); (2) scope and methodology (STRIDE §14, the tools and their pinned versions from the Makefile); (3) one-page architecture summary; (4) scan results summary — gosec (golangci-lint), govulncheck, osv-scanner, npm audit, Trivy fs and image, gitleaks, ShellCheck, ZAP baseline/API per role, testssl grade — each row with the count by severity **as last run**, the date and the command, cells `PENDING-FINAL-RUN` until Task 19 and `NOT RUN (owner)` for `zap-full` and `fuzz-release`; (5) dependency and SBOM summary (module and package counts from the SBOMs; accepted vulnerabilities with justification and expiry — the `osv-scanner.toml`/`.trivyignore`/`rules.tsv` entries); (6) penetration test summary: "No external penetration test has been performed yet (release checklist item; owner)"; (7) known issues and residual risks: one table (ID, description, severity, mitigation, customer guidance) consolidating every phase review's "Known limitations" and open Medium/Low findings that still apply, and at least the six §17.6 subjects (single-host key storage SS-2 High, platform compromise P3-01/P4-01 High residual, license bypass §16.6, audit chain limits incl. R43 row 32, clock heuristics, TOFU) plus the Phase 8 ones (owner credential on the host, shallow verify, the restore's two database copies, no update banner, the matrix gaps Task 14 listed, a compromised `alice` process can forge backups with the sender key (R43 row 41), `alice_app` can rewrite `backup.key` and `audit.forwarding` (re-point future backups, switch forwarding off; mitigated by the deep verify of every update and a monthly `verify --deep` — S-29), forwarding is at most once (R43 row 31), forwarding targets may be loopback or private addresses (a rate-limited, audited connect oracle for a step-up Administrator — S-31, accepted), anyone in the `docker` group can re-tag images after the install's ID check (root-equivalent anyway — S-36), zeroing of key material is best effort (R43 row 53), the binaries — not the images or the tarball — are reproducible (R43 row 52)); (8) customer hardening recommendations (host OS updates, full-disk encryption REQUIRED (R15), firewall, the `from=` restriction, SIEM forwarding, off-host backups, Docker socket permissions, NTP); (9) security-relevant configuration and defaults (every `ALICE_*` variable of the production compose and the settings of C1 with their secure defaults); (10) sign-off: developer, reviewer, date — empty.

- [ ] **Step 2: `docs/release-checklist.md`**: every §17.7 item as a row: item, how it is proven (`make` target or document), class A/B, result, date, initials — results empty; then the sections "VM installs" (for each of Ubuntu 22.04, Debian 12, Rocky 9 — Rocky with SELinux enforcing, a row of its own: prepare a clean VM with Docker 24+, copy the package, verify it (install guide), `sudo ./install.sh`, open the address, complete the wizard, `sudo /opt/alice/alicectl selfcheck`; on the first VM a row confirming that `docker image inspect --format '{{.Id}}'` after the installer's `docker load` equals `RELEASE`'s IDs on a fresh engine (F28); the air-gapped variant: the same with outbound traffic blocked by the hypervisor's network or `nft add rule inet filter output ip daddr != <admin subnet> drop` before the install — results table), "Offline signing ceremony" (§17.5 and `docs/vendor/licensing-vendor.md`: stage with `make release` on the release build machine from the signed tag — never sign a CI-built stage; a CI-built stage is used only to compare: its `alice` and helper binary hashes must equal the local build, checked with `make reproducible-check` (S-26, R43 row 52) —, publish the release key's fingerprint on the vendor's channel, carry `SHA256SUMS` to the offline machine, `licensectl release-sign`, carry back `SHA256SUMS.sig`, `make release-pack`, sign the outer `.sha256` the same way, verify both with `openssl` on a third machine), "Update 1.0.0 → 1.0.1 on a VM" (owner step 5 with real packages; the broken-update package is built with `make release-broken VERSION=1.0.2-rc.1 BROKEN=fail SIGN=offline` and signed in the ceremony for a production-key VM, or `SIGN=test` for a VM installed from a test-signed package — which key signs which package, the commands, and empty result rows; M-27), "Owner steps of every phase on the release candidate" (one row per phase 0–8 pointing to that phase's owner table), "Long gates" (`make zap-full`, `make fuzz-release`, `make e2e-browsers` with WebKit, `make testssl TESTSSL_TARGET=<host>:443 TESTSSL_CA=<ca file>` against the release candidate on a real host (M-28), the first `nightly.yml`/`release.yml` runs, the real-Azure suite), "Human gates" (external penetration test, newcomer test of `docs/first-run.md`, Turkish tone review, peer crypto review of the backup format v2 with its sender key and of the release signing, vendor sign-off).

Run: `make docs-check`
Expected: green.

- [ ] **Step 3: Commit**

```bash
git add -- SECURITY-REPORT.md docs/release-checklist.md
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "docs(security): SECURITY-REPORT.md (§17.6) and the release checklist (§17.7) with the owner's VM, signing and human gates" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- SECURITY-REPORT.md docs/release-checklist.md tools/docscheck/required.txt
```

---

### Task 19: Coverage floors, R43, security review, rulings, CHANGELOG, `make ci`, `make release-gates` (**Docker alone**)

**Files:**
- Modify: `Makefile` (`lint` gains `matrix-check`, M-5), `coverage-floors.json`, `CHANGELOG.md`, `docs/superpowers/specs/alice-v1/00-decisions.md` (**R43**), `docs/superpowers/specs/alice-v1/06-quality.md` (one pointer line after §26.10), `docs/superpowers/specs/alice-v1/04-security.md` (one pointer line after §17.7: "(Phase 8, R43: the checklist with its evidence is `docs/release-checklist.md`.)"), `SECURITY-REPORT.md` (the `PENDING-FINAL-RUN` cells), `docs/security/traceability.md` and `test/matrix/traceability.json` (the controller's gap decisions)
- Create: `docs/security/reviews/phase-8.md`, `docs/superpowers/rulings/phase-8.md`

**Interfaces:**
- Consumes: everything.
- Produces: the phase close.

- [ ] **Step 1: Coverage floors** (**Docker alone**: `make coverage` starts testcontainers)

Run: `make coverage`
Expected: every existing floor holds. Add floors for `alice/internal/backup/format` (measured, rounded down, at least 95), `alice/internal/backup/dump` (at least 90), `alice/internal/backup`, `alice/internal/audit/forward`, `alice/internal/testutil/fakesyslog` (measured, rounded down); `alice/internal/secrets` and `alice/internal/setup` keep or raise theirs (Task 1 and Task 8 changed them); raise an existing floor whose measured value rose by a whole point. Run `make coverage` again: PASS.

- [ ] **Step 2: Matrix gaps.** Read Task 14's gap list. For each gap: either a fix task (a test in the owning package, committed separately with its review) or a ruling in `docs/superpowers/rulings/phase-8.md` and the entry's status `deferred` with that ruling. `go run ./tools/matrixcheck -strict …` must pass before Step 5. Then `lint` gains `matrix-check` (after `docs-check`, M-5) and `make lint` passes.

- [ ] **Step 3: Guides, CHANGELOG**

`CHANGELOG.md`:

```markdown
## Unreleased — Phase 8: Packaging and release

**Upgrade notes**
- Production installations use `deploy/release/docker-compose.yml` through `install.sh`; the development stack
  (`make up`) is unchanged except a new volume for backups (`alice-backups`, mounted at `/opt/alice/backups`).
- The production database owner is no longer a superuser and the `alice` container holds no owner credential:
  migrations run in the one-shot `migrate` service, restores in `alice-admin` (`ALICE_MIGRATE=external`).
- New settings: the daily backup (time, zone, retention), audit forwarding. Backups need the recovery passphrase
  (set in the wizard); installations without it show "Finish setting up".
- The recovery passphrase must now be rated "good" or better (a "fair" one is refused, `ALC-SET-0010`).
- Development installations whose recovery passphrase was set before Phase 8 hold a version 1 backup key and make no
  backup until the wizard is run again on a fresh database (R43 row 41).
- No helper change: `alice-helper` stays at protocol 6 (1.5.0); the release bundle ships it in `helper/`.

### Added
- `install.sh` (preflight, signature and image checks, offline image load, hardened two-container stack, setup code),
  `alice-update.sh` (signed packages only, automatic pre-update backup, migrations, selfcheck, automatic return to
  the previous version), `alicectl` (backup, backup list, backup verify [--deep], restore, selfcheck, audit verify,
  setup-token --reset, support-bundle), `install.sh --restore-mode`, `--uninstall [--purge]`.
- Encrypted backups (X25519 to the installation's backup key, authenticated by the installation's sender key, AES-256-GCM
  chunks, the private key inside the file under the recovery passphrase; container format 2), daily at 02:30 with 14 kept, a failure e-mail and a 48-hour alarm; restore into a
  fresh database with one swap point.
- Wizard steps "HTTPS certificate" and "Mail server", Back on every step, resume after a reload; the dashboard's
  "Finish setting up" checklist and backup card; Settings → Backups, HTTPS certificate, Audit forwarding.
- Audit forwarding to syslog (RFC 5424 over TLS) in chain order with each hash.
- Release bundle with SBOMs, third-party notices and Ed25519 signatures; `make reproducible-check`, `make release-gates`,
  `make nightly`; ZAP, testssl, real-systemd, three-browser, mutation and osv-scanner gates; the §23–§25 traceability.
- Documents: install guide, backup and restore, upgrade, security overview, API, index; `SECURITY-REPORT.md`; the
  release checklist.
- Codes `ALC-BAK-0001..0004`, `ALC-TLS-0001..0005`, `ALC-AUD-0002..0004`, `ALC-SET-0010`; permission `backup.manage`.

### Security
- P1-01 closed in production (non-superuser owner, no owner credential in the application container); PostgreSQL
  read-only, non-root, no published port; secrets as files; the temporary HTTPS certificate renewed without a restart.
```

- [ ] **Step 4: R43, the spec pointers, the rulings**

`00-decisions.md`: append **R43** (Phase 8, approved with the Phase 8 plan; corrected to the built code at the end of Phase 8) with items 1–53 = the rows of "Spec conflicts resolved by this plan" as built (rows 41–53 and the amended rows 3, 8, 9, 19, 21, 24, 30, 31, 37 come from the pre-flight rulings, `.superpowers/sdd/2026-10-10-phase-8-packaging-release/preflight-rulings.md`), and an addendum for the decisions made while building. `06-quality.md`, after §26.10: "(Phase 8, R43: the named tests are `TestKnownAnswer`, `TestEveryFlippedByteFails`, `TestTruncationAndReorderFail`, `TestHeaderBounds`, `TestForgedBackupWithCopiedWrappedKeyFails`, `FuzzBackupHeader`, `FuzzBackupStream` in `internal/backup/format`; `TestF70DiskFullLeavesNothing`, `TestF86BackupWhileJobsRun`, `TestF87NoPlaintextInTheFile`, `TestF88Retention`, `TestF80WrongPassphraseChangesNothing`, `TestF81FlippedByteChangesNothing`, `TestF82TruncatedChangesNothing`, `TestF83ForeignAndNewer`, `TestF84OlderSchemaMigratesForward`, `TestF85FullCycle`, `TestF97RestoreContinuesTheChain`, `TestRestoreIsAllOrNothing`, `TestFinishIgnoresStaleStaging`, `TestCleanupNeverDropsTheOnlyCopy`, `TestRestoreKeepsTheNewerTimeRecord` in `internal/backup`; `TestF92CheckpointIsForwarded`, `TestF96ReceiverDownNeverBlocksTheLocalWrite` in `internal/audit/forward`; `FuzzOpenAPIInputs` in `internal/api`; the release harness `TestReleaseInstallMatrix`, `TestReleaseF85Drill`, `TestReleaseRestoreNegatives`, `TestReleaseUpdateAndRollback` (F-68), `TestReleaseRefusesTamperedAndDowngrade` (`make test-release`); `TestRealSystemdNginx` (`make test-systemd`); the end-to-end journeys are `web/e2e/phase8.spec.ts`; the matrix map is `docs/security/traceability.md`. The VM installs, the production keys and signature, the active ZAP scan, the release fuzz run and owner steps 1–6 are the owner's tables in `docs/security/reviews/phase-8.md` and `docs/release-checklist.md`.)". `docs/superpowers/rulings/phase-8.md`: the controller's rulings during execution in the format of `phase-7.md` (before the tasks, per area, the gap decisions of Step 2, final review, process, status at phase close, carried to later phases — this plan's re-deferred carries with their reasons).

- [ ] **Step 5: Security review and the final runs**

`docs/security/reviews/phase-8.md` in the format of `phase-7.md`: Method; **Evidence** table (rows: `make test`, `make test-integration`, `make test-backup-cycle`, `make test-release` (each subtest), `make test-systemd`, `make reproducible-check`, `make zap-baseline` (per role), `make testssl` (grade), `make e2e`, `make e2e-browsers` (per browser), `make mutation` (scores), `make fuzz-backup`/`fuzz-api` (5-minute runs), `make coverage`, `make ci`, `make secrets-scan`, `make vuln` (with `osv`), `make fs-scan`, `make image-scan`, `matrix-check -strict`, `make release-keycheck` (expected FAILED until the owner's key); cells `PENDING-FINAL-RUN` until the runs below fill them; `NOT RUN (owner)` / `NOT RUN (CI)` for `zap-full`, `fuzz-release`, the VM installs, the workflows); **Threat notes** (§17.2 Phase 8 gate: installer (root, preflight, no pull, image IDs), update script (signature with installed keys, downgrade, rollback, exit 3), signature verification (Ed25519, release key separation, the first-install trust anchor), backup/restore (B-1..B-4, F-80..F-88, the one swap point, the owner role), the deployment's least privilege (P1-01), audit forwarding and its limits, supply chain (SBOM, osv, lockfile shape, pinning, reproducibility), DAST and TLS results); **Review checklist** (§17.2: "Release checklist (17.7) complete; SECURITY-REPORT.md signed off" — the first column states which items are proven here and which are the owner's); **Findings** (with severities; no open High — a High found here blocks the phase close and goes to the controller); **Known limitations** (at least: the owner credential lives on the host and in the tools container; shallow verify trusts a replaced `.sha256`; restore needs two database copies of disk; Go strings of passwords read from files cannot be cleared, and zeroing is best effort (R43 row 53); a compromised `alice` process can forge a backup with the sender key (R43 row 41); forwarding is at most once; no update banner; no JSON webhook; keyed chain deferred (row 32); recovery passphrase and master key not changeable; the matrix gaps deferred in Step 2; WebKit, VMs, the active scan and the release fuzz are the owner's); **Owner verification** — the empty table of §26.10 owner steps 1–6:

| # | Step (§26.10) | Expected | Result | Date | Notes |
|---|---|---|---|---|---|
| 1 | On a fresh server: `tar xzf alice-1.0.0.tar.gz && cd alice && sudo ./install.sh`; open the printed address | The installer ends with the address and a setup code; the page opens (certificate warning expected) | | | |
| 2 | Complete the wizard in your language: administrator, authenticator code, recovery passphrase, HTTPS certificate, mail server (skip allowed), license (evaluation), first server | Every step has a plain explanation; Back works; the dashboard opens | | | |
| 3 | `sudo /opt/alice/alicectl backup`; on a second empty server `install.sh --restore-mode`, copy the file, `alicectl restore` with the passphrase; sign in there | Same data, same Installation ID, same license | | | |
| 4 | Restore with a wrong passphrase | "The passphrase is wrong or the file is damaged. Nothing was changed." | | | |
| 5 | `cd /opt/alice && sudo ./alice-update.sh alice-1.0.1.tar.gz`; then the "broken update" test package | Alice back within minutes at 1.0.1; with the broken package Alice returns to the previous version by itself and works | | | |
| 6 | Read `SECURITY-REPORT.md` and `docs/release-checklist.md` | Every item ticked with a date | | | |

followed by the table "Owner and CI gates" (the six items of "Owner and CI items (class B)" of this plan, each with Result/Date empty) and **Sign-off** (empty).

Final runs (**Docker alone**, no other Docker user, Playwright not running except inside the targets that start it):

Run: `make ci TRIVY_IMAGE="--network host aquasec/trivy:0.74.0@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969"`
Expected: exit code 0 (use the Makefile's pinned `TRIVY_IMAGE` verbatim if a task changed it).

Run, one after another, recording each result: `go run ./tools/matrixcheck -strict -spec docs/superpowers/specs/alice-v1/06-quality.md -map test/matrix/traceability.json -doc docs/security/traceability.md`, `make reproducible-check`, `make test-release`, `make test-systemd`, `make zap-baseline`, `make testssl`, `make e2e-up && make e2e-browsers; make e2e-down`, `make release-keycheck`
Expected: all exit 0 except `release-keycheck` (fails on the missing production release and license keys — the documented owner item) and any target this machine cannot run (recorded `NOT RUN` with its message, never `PASS`). Fill the Evidence cells and the `SECURITY-REPORT.md` cells with the results, counts and the commit hash.

- [ ] **Step 6: Commit**

```bash
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "docs: Phase 8 — R43 and spec pointers; changelog; coverage floors; matrix gap decisions; SECURITY-REPORT evidence" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- Makefile coverage-floors.json CHANGELOG.md \
  docs/superpowers/specs/alice-v1/00-decisions.md docs/superpowers/specs/alice-v1/06-quality.md \
  docs/superpowers/specs/alice-v1/04-security.md SECURITY-REPORT.md docs/security/traceability.md test/matrix/traceability.json
git add -- docs/security/reviews/phase-8.md docs/superpowers/rulings/phase-8.md
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "docs(security): Phase 8 review with the evidence, the owner verification and gate tables; controller rulings" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- docs/security/reviews/phase-8.md docs/superpowers/rulings/phase-8.md
```

---

## Self-review (done while writing this plan)

1. **Spec coverage (§26.10 item by item).** Deliverables: `install.sh` and the air-gapped tarball — Tasks 11, 12, 13 (R43 rows 6, 19–22, 28); wizard steps complete — Tasks 8, 9, 10, 16 (rows 14–17); `alice-update.sh` with backup, migration, health check and rollback — Tasks 11, 13 (rows 21, 23, 30); `alicectl` subcommands, `--restore-mode`, `--uninstall` — Tasks 6, 11, 13 (R5, R6, rows 9, 24, 25); daily backups, retention 14, hybrid X25519 (R4) — Tasks 1, 2, 4, 6 (rows 1–5, 10–12); signed release tarball — Task 12 (row 20; the production key is the owner's); documentation set — Task 17 (row 27); `SECURITY-REPORT.md` and the release checklist — Task 18; SBOM and signatures — Task 12 (row 26). Tests: install on three distributions, air-gapped — Task 13 (A) and the owner's VM runbook (B, row 28); update with a forced migration failure (F-68) — Task 13 for an erroring and a killed migration (row 30); F-85 and F-80..F-88 — Tasks 1, 4, 5, 13 (row 29); the whole matrices — Task 14's traceability and Task 19's gap decisions (row 37); ZAP — Task 15 (baseline/API A, full B; row 34); three browsers — Task 15 (row 36); testssl — Task 15 (A on the release image here, B on a real host); production key and no test tags — the existing `release-symcheck` and `image-check` (A) and `release-keycheck` extended to the release key (B); reproducible build — Task 12. Owner steps 1–6 and the exit criteria — Task 19's tables (B). Carries: every Phase 8 carry of the memory note and the Phase 6/7 rulings is in "Carries and deferred items" as included or re-deferred with a reason (helper scans, lockfile scanning, osv-scanner, the real-systemd job, the nightly pipeline, mutation testing, the keyed chain and `jobs.audit_verify`, syslog forwarding, the TLS private-key download, the Entra Graph lookup, ZAP and the other DAST tools, P1-01, P1-02, P1-08, Back/resume, the SMTP step).
2. **Placeholders.** None intended. Three values are produced by a step on purpose and say so: the KAT hash in `testdata/kat-v2.json` (Task 1 Step 4: written from the first run whose output already equals the independent reference implementation), the `osv-scanner` v2 flag spelling (Task 14: checked against the pinned tool's `--help`), and the two paths inside `docker:29.9.0-cli` (Task 13: listed from the pinned image first). Where a step must read existing code first (the archtest precedence, `runWizard`, the real-Nginx test helpers, the seal check, the template registry, the rotation fixtures), it names the file and the behaviour to keep.
3. **Type and name consistency.** Defined once in the contract and used with the same spelling in the tasks: `secrets.{WrappedBackupKey (Version 2, SenderPublicKey), NewBackupKey (returns the sender key), Unwrap}` and the `setting_secrets` key `backup.sender` (C1, R43 row 41, Task 1; consumed by Tasks 4, 5, 8); `format.{Magic, Version (=2), ChunkSize, MaxHeaderLen, Meta, Header, NewWriter (wrapped, sender, meta), Writer, ReadHeader, Open, OpenWithKey (priv, sender public key), Reader, ErrNotBackup, ErrNewerFormat, ErrHeader, ErrDecrypt, ErrTruncated, ErrTrailingData, MinKDFMemoryKiB, MaxKDFMemoryKiB, MaxKDFTime, MaxKDFThreads}` (C7, Task 1); `dump.{Encoder, Decoder, Frame, Kind constants, MaxName, MaxData, Tables, Counts, Dump, Load, Stats, ErrPayload, ErrSchemaMismatch}` (C7, Task 2); `db.{MigrateTo, SchemaVersion, LatestVersion}` and `config.{Load (unchanged), LoadWith}` (Task 3); `backup.{Config (with Keyring), Service, New, Kind, Info, CreateInput, Create, FreeBytes, List, Verify, VerifyDeep, Prune, Open, Schedule, SaveSchedule, State, RunScheduled, LastScheduled, Due, Alarm, AlarmAfter, RestoreInput (with NoSafetyBackup, FreeBytes, WaitForSessions), RestoreResult, Restore, FinishInterruptedRestore (ctx, q, keysDir, stateDir), Manifest, ErrRunning, ErrNotConfigured, ErrNotFound, ErrWrite, ErrVersion, ErrNewer, ErrDamaged, ErrNotVerified, ErrAuditBroken, ErrCancelled, ErrDatabaseInUse, ErrNoSafetyBackup, ErrNoSpace}`, the settings key `backup.restore_id` and the file `RESTORE_ID` (C1, C8, Tasks 4–5, used by Task 6's `serve`); `forward.{Transport, Settings, State (with CheckpointSeq), Config, Forwarder, New, Save, Test, Run, MaxBatch, ErrAddressRefused, ErrUnreachable, ErrUntrusted, ErrVersion}` (C10, Task 7); `tlscert.{Store, NewStore, Recovered, GetCertificate, Info, Install, Renew, Upload, ParseUpload, ServerConfigFor, ErrKeyMismatch, ErrNotValidNow, ErrWeakKey, ErrPFXPassword, ErrUnreadable}` and `setup.{KeepTemporaryCertificate, RecordCertificateUploaded, SkipMail, Strength, PassphraseStrength, ErrPassphraseTooWeak}` with `Status.{HTTPSChosen, MailChosen, NextStep}` (C11, Task 8); `secrets.CheckMasterKey` (Task 6); `rbac.BackupManage`, the routes, DTOs and codes of C12 with `area.name` reasons (Task 9; the codes in its first commit); the job types of C1 (Task 6); the script interface of C4 and the package of C5 (Tasks 11–13), with `--fingerprint`, `--no-safety-backup`, `--free-bytes`, `TEST_SIGNED`, `-allow-draft`/`-test` and `make release-broken` (`deploy/dev/build-broken-release.sh`, used by Task 13 and the owner); `tools/docscheck/required.txt` (Task 14 creates it, Tasks 17 and 18 append). Checks made while writing: the restore's database names are relative to the live database (`<db>_restore`, `<db>_previous_<ts>`), so the `pgtest` databases and production's `alice` follow one rule; `alicectl` passes container paths (`/opt/alice/backups/<name>`) while users type host paths; the update's pre-upgrade kind names the installed version and the reason the new one (§20.1 step 3); the backup's schema version is the goose version (`db.SchemaVersion`), the same number `RELEASE`'s `SCHEMA_VERSION` carries.
4. **Contradictions with the spec, resolved.** Every place where this plan departs from `05-operations.md` or `04-security.md` is a row of R43 (dump tool, crypto parameters, header contents, shallow verify, layout, roles, restore mechanics, schedule zone, retention kinds, certificate generation, signature scheme, updater location, image pinning, downgrade and banner, SBOM format, documents, test environment, F-85 split, forwarding scope, keyed chain; and, from the pre-flight, origin-authenticated backups (row 41), the time record on restore (42), fingerprint confirmation and test-signed packages (43), the update order (44), the evident rollback (45), the disk-space refusals (46), the public setup status (47), the DDL exception to SEC-060 (48), message wording (49), no rotation in v1 (50), draft test packages (51), the reproducibility claim (52) and best-effort zeroing (53)); where §20.2 and SEC-048 disagree with each other, SEC-048 (the security section and the built code) wins and the row says why. `00-decisions.md` R4–R7 are kept exactly (hybrid encryption, `--restore-mode`, `--uninstall` with typed purge, the eight `alicectl` subcommands and no `maintenance`, 14 backups, the 48-hour alarm, the signed tarball and SBOM).
5. **What needs the owner.** Collected in "Owner and CI items (class B) at a glance" and turned into tables by Tasks 18–19: the VM installs (with and without egress, Rocky 9 with SELinux enforcing, the image-ID check on a fresh engine), the production release and license keys, the published release-key fingerprint and the offline signing (including the broken-update package of owner step 5), the active ZAP scan, the release fuzz run, WebKit where it cannot start here, the first workflow runs on a remote, the 1.0.0 → 1.0.1 update, the external penetration test, the newcomer test of the first-run guide, the Turkish review, the crypto peer review, the repetition of every phase's owner steps, and the signatures. No task marks any of them done.
6. **Risks to execution the controller should expect.** (a) The release harness drives the host's Docker engine from inside containers through the socket — if this engine or a security profile refuses it, Task 13 fails loudly and the controller decides (R43 row 28 allows nothing weaker silently). (b) The real-systemd job needs a privileged container with systemd as PID 1 on cgroup v2. (c) WebKit may not start on this Arch-based host. (d) `make reproducible-check` may reveal a non-deterministic Vite or Go input that needs a fix. (e) Task 14's traceability work may surface spec IDs without a proving test; they are decided in Task 19, not hidden. (f) Several targets need the network on the build machine (Trivy's database, `osv-scanner`, image pulls, `go install` of the tools); the customer-side scripts never do. (g) Whether PostgreSQL 16 runs the two `ALTER DATABASE … RENAME` in one transaction is proven by Task 5's test; the fallback and its cleanup rule are written down (R43 row 8). (h) Development databases with a pre-Phase-8 (version 1) backup key stop backing up until the wizard is re-run (R43 row 41); the e2e stack resets per test, the owner's live `alice` project is never touched by this phase.
7. **Pre-flight amendments.** The scan (M-1..M-28) and the security review (S-1..S-40) were applied as `preflight-rulings.md` records: the task order and waves are unchanged; Task 1 grew by the backup key v2 (`internal/secrets`, the `SetRecoveryPassphrase` call) and runs testcontainers; Task 3 also owns `deploy/Dockerfile`, `deploy/dev/check-image.sh` and the first `tools/pincheck` change; Task 12 the second `tools/pincheck` change, `deploy/release/LICENSE.txt` and `deploy/dev/build-broken-release.sh`; Task 9 commits its codes first so Task 10's web tests and Task 17's troubleshooting edits can follow inside wave 4; `matrix-check` joins `make lint` only in Task 19.
