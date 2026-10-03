# Phase 4: Nginx Certificate Discovery and Deploy — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An administrator prepares an Nginx server with the `nginx` setup profile, adds it as an **Nginx server**, and Alice discovers every website's certificate (through `nginx -T`, without ever reading a private key) and lists it with its expiry; people upload certificates (PEM or PFX) or create a signing request in Alice, deploy a certificate to one or more websites, watch the steps **Backup → Write → Check → Reload → Verify** turn green, and every failure — a key that does not match, a configuration error, a failed reload, the wrong certificate served, a dropped connection, a killed Alice — ends with the old certificate live or the new one live and verified, never a mismatched pair; the deployment history keeps every attempt and its steps.

**Architecture:** `alice-helper` protocol 4 adds five root subcommands that only ever touch the certificate and key files the server's own Nginx configuration names: `nginx-dump` (runs `nginx -T`, parses it with the new pure package `internal/providers/nginx/nginxconf`, and returns the parsed summary plus the `CERTIFICATE` blocks of every referenced certificate file — never raw configuration text, never key content), `nginx-test`, `nginx-deploy` (backup, write key, write certificate, `nginx -t`, reload, `is-active` and automatic rollback as **one root-side transaction** with an on-disk journal, so a dropped SSH connection or a killed Alice never leaves a half-written pair), `nginx-restore` and `nginx-status`; plus the unprivileged `tls-probe`. Every path is resolved by a new descriptor walk in which every directory and link must be root's. `internal/providers/nginx` is the `nginx` provider built on `linuxssh` (one session, the same pool): discovery, the TLS verification probe from Alice (with the helper's probe as fallback), deploy, rollback and status. `internal/certs` (pure) parses and validates uploads, PFX, chains and signing requests; `internal/testutil/pki` generates every certificate fixture at test time. Migration `00006` adds certificates, locations, managed private keys, signing requests, deployments and their steps; `internal/inventory` reconciles discovered certificates and owns uploads, signing requests and deployment records; `internal/jobs/deployjobs` runs `certificate.deploy` (ClassChange) and `certificate.deploy_recover` (ClassAlways, so a rollback is never blocked by the license) with crash recovery from the helper journal. The API adds certificates, signing requests, locations and deployments routes; the SPA adds Certificates, Deployment history, the websites panel on an Nginx server and the deploy dialog with live steps.

**Tech Stack:** Go 1.27.1 (stdlib `crypto/x509`, `crypto/tls`, `encoding/pem`, `crypto/ecdsa`, `crypto/rsa`, `golang.org/x/sys/unix` in the helper), `software.sslmate.com/src/go-pkcs12` (new runtime dependency, approved by R23), pgx v5, goose v3, testify, testcontainers-go v0.44 (Ubuntu 22.04, Debian 12, Rocky 9 images now also run Nginx with a `systemctl` shim); React 18 + TypeScript 6 + Vite 8, Mantine 8, React Router 7, TanStack Query 5, i18next, Vitest 5 + Testing Library + msw 2, Playwright 1.63 + axe-core.

**Spec:** `docs/superpowers/specs/2026-09-29-alice-v1-design.md` and `docs/superpowers/specs/alice-v1/` — especially `00-decisions.md` ("Nginx over SSH", "Certificate sourcing", Security, R9, R13, R21, R23, R24, R29, R33, R36 item 6, R37 — all of it, it records what Phase 3 built), `01-product.md` S3, S4, §3.1, `02-architecture.md` §6 (provider interface, deploy and rollback contract, registry, `linuxssh` connector, remote command surface), §7.2 (`managed_private_keys`), §7.3 (`certificates`, `certificate_locations`, `csr_requests`), §7.4 (`deployments`, `deployment_steps`), §8 (job types, retries, lock gating, in-flight operations, crash recovery), §9 (conventions, errors, endpoint groups), `03-integrations.md` §12 (all of it), `04-security.md` §14.4 (Job runner, SSH connector and target helper, SC-7), §15.4, SEC-023, SEC-037, SEC-040..SEC-047, SEC-050..SEC-052, SEC-060..SEC-065, SEC-080..SEC-082, §17.2 (Phase 4 gate), `05-operations.md` §21, `06-quality.md` §22.3 (Nginx images and the `systemctl` shim), §22.6 (PKI and Nginx fixtures), §23.8 (L-80..L-82), §24.1 (F-01..F-21), §24.4 (F-66), §25.1, §25.2 (S-01..S-05), §25.4 (A-11, A-12, A-13), §25.6 (`FuzzParseNginxConfig`, `FuzzParseCertificateUpload`), §26.1, §26.6. `00-decisions.md` wins on conflict; this plan proposes **R38** (written in Task 24) for the conflicts listed under "Spec conflicts resolved by this plan". `docs/superpowers/rulings/phase-3.md` ("Parked / carried to Phase 4") and `docs/security/reviews/phase-3.md` ("Known limitations") are the carry sources; `docs/superpowers/plans/2026-10-01-phase-3-ssh-targets.md` is the style reference.

**Plan verification:** the tasks were written against branch `phase-4` at `31e1df3` (Phases 0–3 merged). Every existing symbol, path, route, Make target and command a task uses was checked with `grep` in that tree, among them: `helperproto.{Protocol,Version,HelperPath,BackupRoot,HelperBudget,ValidArg,ValidPath,ValidOpID,ValidSHA256,ValidUser,AbsentSHA256,Exit*,Code*,Warn*,AuthKeysListResponse,UserFiles}`, `linuxssh.{HelperCommand,quoteArg,privileged,CmdVersion,CmdSSHDDump,CmdAuthKeysList,CmdAuthKeysRead,CmdAuthKeysWrite,CmdCleanup,Sudoers,SetupScript,AuthorizedKeysLine,DecodeHelper,Conn.Run,Conn.Healthy,Conn.HostKey,Provider,Options,New,ParseConfig,Pool.Acquire,Pool.AcquireFresh,DefaultCommandTimeout,LongCommandTimeout,DefaultMaxOutput,cleanValue,warn,isHelperCode}`, the helper's `sys` fields, `scan`, `toScan`, `loginShell`, `accounts`, `openStateDir`, `openBackupRoot`, `subdir`, `writeNewAt`, `removeAt`, `openLockFile`, `flockWait`, `lockWait`, `sameFile`, `copySELinux`, `sweepBackups`, `sweepLocks`, `commands`, `commandBudget`, `refused/precondition/failed`; `providers.{Session,UnsupportedSession,DiscoverRequest,DiscoveryResult,ConnectionReport,StepLogger,StepStatus,Cap*,KindNginx,KindForTargetType,ConnectionCache,SetupGuide,Error,NewError,ErrUnsupported}`, `providertest.{CheckProvider,CheckUnsupported,CheckSession}`, `fake.{Config,Provider,New}`; `jobs.{Register,Type,Spec,Job,Queue.Add,Queue.EnqueueTx,Runner.Handle,HandlerFunc,StepRecorder,Retry,Fail,Attention,FromProvider,MaxAttemptsFor,Task,Scheduler,Kind*,Status*}`; `inventory.{Service,Config,Actor,Target,Facts,NewTarget,Reconcile,RequestKeyRemoval,JobRequest,Enqueuer,Notifier,Templates,Status*,Err*}`, `targetjobs.{Register,Deps,Inventory}`; `audit.{Log.Append,Event,SystemActor,Success,Failure,Denied,sensitiveSegments}`; `secrets.{Keyring.Seal,Keyring.Open,Location,Envelope,Plaintext}`; `api.{route,server.apiRoutes,ErrorCode,AllErrorCodes,errorMap,codeForReason,providerParamKeys,writeErrorWith,fail,pathUUID,pageLimit,optionalUUID}`, `authz_test.go` (`expectedMatrix`, `routeRuleViolations`, `lockRefused`, `TestSensitiveRoutesHaveTheirFixedPermissions`), `migrations/roles_integration_test.go` (`explicitGrants`, `explicitColumnGrants`), `cmd/alice/{providers.go,services.go,testapi_e2e.go:resetSQL}`, the Make targets `test`, `test-integration`, `test-ssh`, `helper`, `build`, `coverage`, `fuzz-ssh`, `e2e-up`, `e2e`, `e2e-down`, `ci`, and the web `waitForJob`, `useAbort`, `SCREENS`, `renderRoute`, `targetExec`, `settle`, `drainJobs`, `expectAccessible`. Where this plan quotes existing code it is the code at `31e1df3`. The plan has **not** been compiled: before Task 1 the controller runs the pre-flight scan Phase 3 used (apply each task's code in a scratch worktree and compile it), and every task's red/green steps are the real check.

## Global Constraints

- Go module path is `alice`; toolchain `go 1.27.1`. Every shell step assumes `export PATH="$HOME/.local/go/bin:$HOME/go/bin:$PATH"` and the repository root as working directory.
- All code, identifiers, comments, file names, commit messages and technical docs are in English. Turkish appears only as translation values in `tr.json` files.
- Commits: Conventional Commits, made with `git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit`, the message ending with a `Co-Authored-By:` line that names the model that wrote the commit (for this model: `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`). Never squash or rebase the branch: `.gitleaksignore` is pinned to commit hashes.
- Code blocks in this plan are gofmt-clean except for column alignment of consecutive one-line declarations and struct fields: run `gofmt -w` (or `make lint`) on every changed Go file before committing.
- Tests: Go stdlib `testing` plus testify `require`/`assert` only; small hand fakes, no mock frameworks. Integration tests carry `//go:build integration`, call `pgtest.Main` from `TestMain` and get a fresh database per test from `pgtest.New(t)` (pools `Owner` and `App`; the application always uses `App`). A red step in a brand-new package may fail with "no non-test Go files"; that is the expected failure.
- Build tags: `integration` (PostgreSQL and container tests), `e2e` (test-only `/test/*` endpoints, demo clock), `testlicense`, `releasecheck`. Release images are built with no tag; the e2e image with `e2e testlicense`.
- Lint is golangci-lint v2 (`make lint`): gosec, errorlint, forbidigo, bodyclose, misspell, noctx, gofmt, goimports (`local-prefixes: alice`). Forbidden: `fmt.Print*`, `strings.ToUpper`/`ToLower`/`Title`, `time.Now` outside `internal/platform/clock` and tests (`cmd/alice-helper` reads time only through `sys.now`), `ssh.InsecureIgnoreHostKey`. `helperproto.ProbeTLSConfig` (Task 4) is the only place with `InsecureSkipVerify: true`, with `//nolint:gosec // G402: the probe only compares the served leaf's SHA-256 with the expected certificate (spec §12.8 item 3); it never trusts the connection or sends data`; both TLS probes (Alice's in `internal/providers/nginx/probe.go`, the helper's `tls-probe`) use it, and a test in Task 11 greps the repository and fails on any other `InsecureSkipVerify`. No `//nolint` without a reason.
- Module import rules are enforced by `internal/archtest`. Phase 4 adds: `"alice/internal/certs/...": {platform, "alice/internal/secrets/..."}` (pure: no database, no providers); `inventory` may also import `alice/internal/certs/...`; `providers/*` may import `providers/nginx/...` (own subpackages are already allowed) and `providers/linuxssh/...`; `jobs/...` is unchanged (`deployjobs` uses `inventory` and `providers` only); `api` never imports `certs` (inventory defines the input types). `cmd/alice-helper` imports only the standard library, `golang.org/x/crypto/ssh`, `golang.org/x/sys/unix` and the pure packages `alice/internal/providers/linuxssh/{helperproto,sshdconf}` and `alice/internal/providers/nginx/nginxconf` (`nginxconf` imports only the standard library and `helperproto`); `TestHelperIsStatic` keeps checking the linked modules.
- Runtime Go dependencies of `alice`: Phase 3's set plus `software.sslmate.com/src/go-pkcs12` (R23). No new web dependency.
- No SQL string building (SEC-060). SQL time comes from the injected clock as a bind parameter. `alice_app` gets explicit grants for every new table; the grant guard (`migrations/roles_integration_test.go`) lists every non-default and column-level grant set.
- **Remote command rule (security-critical, R13, SEC-063):** Alice sends only `cat /etc/os-release`, `/usr/local/libexec/alice-helper version`, `/usr/local/libexec/alice-helper tls-probe …` (both without sudo) and `sudo -n /usr/local/libexec/alice-helper <subcommand> [args]` built by the constructors in `internal/providers/linuxssh/command.go`, every argument through `helperproto.ValidArg` and `quoteArg`. The `nginx` provider never builds a command line itself: it calls the `linuxssh` constructors and `Conn.Run`. Private key material crosses the SSH connection only as `nginx-deploy`'s stdin (JSON), never on a command line, in a log, an error, a job payload or result, an audit detail or an API response; sudoers keeps `log_output` and never gets `log_input` (Task 7 test).
- **Helper rule (security-critical, the Phase 3 Critical finding's lesson):** every new helper subcommand that touches a file resolves it with `resolveRoot` (Task 5): a walk from `/` by descriptor with `openat(O_NOFOLLOW)`, where every directory must be owned by root and not writable by group or others and every symbolic link must be owned by root; the file is then opened relative to its directory descriptor with `O_NOFOLLOW`, must be a regular file with exactly one link, and is written only through a temporary file in the same directory (`O_EXCL`, 0600), `fsync`, `renameat` and a directory `fsync`, after a compare-and-swap of its SHA-256 and a root-only backup. Paths come only from the helper's own parse of `nginx -T` (a supported `ssl_certificate`/`ssl_certificate_key` pair), never from the caller alone. Argument vectors are fixed and mirrored by narrow sudoers lines; output is bounded; external programs run by absolute path (`/usr/sbin/nginx`, `/usr/bin/systemctl`) with a clean environment. Each helper task's tests include attack tests (symlink swaps, user-writable directories, hard links, `/etc/shadow` targets, oversized and hostile input), not only happy paths.
- **Helper change procedure (every task marked HELPER):** (1) `go test ./cmd/alice-helper -count=1` as a normal user; (2) the root-only tests as uid 0 in a throwaway container: `CGO_ENABLED=0 go test -c -o /tmp/alice-helper.test ./cmd/alice-helper && docker run --rm --network none -v /tmp/alice-helper.test:/alice-helper.test:ro debian:12 /alice-helper.test -test.count=1 -test.run 'AsRoot|Attack|Root'` (Docker; a throwaway container, never the owner's stack); (3) `make helper` (new `bin/alice-helper.sha256`, so `make build` and the image embed the new checksums); (4) `make test-ssh` (Docker: testcontainers images `alice-test/sshd-*`) once Task 20 exists, and for Tasks 5–6 the `TestRealOpenSSH` subset with `ALICE_SSH_IMAGES=ubuntu22`. The protocol bumps once, to 4, in Task 4; later helper tasks stay on protocol 4 (unreleased product).
- **Docker safety:** the owner runs the compose project `alice` (image `alice:dev`, volumes `alice_*`). No task touches it: tests use testcontainers, `docker run --rm` throwaway containers, or the e2e project `alice-e2e` (`make e2e-up`, `make e2e`, `make e2e-down`, port 9443); CI builds `alice:ci`. Every step that runs Docker says so.
- **Secrets in the repository:** no private key, certificate or password is committed. Certificates, keys and PFX files are generated at test time by `internal/testutil/pki` (Go tests), by `alice-e2e-newcert` inside the e2e target (Playwright) or by `go run ./tools/testcerts` (owner). Strings that look like PEM private-key markers are built at run time (`"-----BEGIN " + "PRIVATE KEY-----"`), as Phase 3 did for its leak needles. If `make secrets-scan` still flags a test file, add the finding to `.gitleaksignore` with the new commit hash in the same task.
- API JSON conventions from Phase 1 (snake_case, UTC RFC 3339, error body `code`, `reason`, `message_key`, `message`, `request_id`, `retryable`, `params`, `details`; lists `{items, next_cursor}`); every new code `ALC-<AREA>-<NNNN>` has `errors.<reason>.title|cause|action` in `locales/common/{en,tr}.json` and a section in `docs/troubleshooting.md` (enforced by `internal/api/errors_test.go`).
- Every new route is in the route table with a permission and (for non-GET methods) a license class, in `api/openapi.yaml` with the same `x-permission`, in `docs/authz-matrix.md` (`make authz-doc`) and in the authz tests. Long operations answer `202` with job ids.
- Audit detail keys pass the Phase 1 denylist (`key`, `private`, `secret`, `token`, `password`, `code`, … segments are refused): use `cert_path`, `location_id`, `fingerprint`, `new_fingerprint`, `previous_fingerprint`, `algorithm`, `outcome`, `reason`, `failed_step`, never `key_path` or `private_key_id`.
- i18n: every user-visible string is a key in English and Turkish (`make i18n-check`); placeholders `{{name}}` without spaces; no sentence assembly; no suffix attached to a placeholder (rephrase as "Label: {{value}}"); formal-polite Turkish ("siz"), jobs are "iş"; plural forms `_one`/`_other` in both languages. The "UI copy" table in the contract is exact and is what the Vitest and Playwright tests match.
- Accessibility: new screens and dialogs have no serious or critical axe violation at 640, 1280 and 1920 px (`expectAccessible`) and at 375 px for the Certificates, Deployment history and server pages (tables scroll inside their own container), in English and Turkish, keyboard usable, no horizontal page scroll.
- Frontend: no `dangerouslySetInnerHTML`, no `toUpperCase`/`toLowerCase`; fingerprints, paths, host and domain names, PEM text and certificate subjects are rendered with `<Code>`/monospace styling, never translated or case-transformed, always as text (A-11).

## Review Focus

1. **Certificate files laid out the way real servers lay them out** — Let's Encrypt `live/<name>/fullchain.pem` symlinks into `../../archive/<name>/fullchain3.pem`, Debian's `/etc/ssl/private` (0710 root:ssl-cert) with a 0640 key, a key and certificate in one combined file, a path with a space, a certificate path inherited from the `http` block, one file shared by three `server` blocks, RSA and ECDSA certificates side by side in one server. Expected: links owned by root are followed and the write lands on the link's target (the link stays), `/etc/ssl/private` keys stay 0640 root:ssl-cert after a deploy, the combined file and the path with a space are listed as "not supported" with a plain reason and are never written, the shared file is one location verified on all three servers, and the dual RSA/ECDSA server gives two locations each verified with its own key type. Tests: Task 5 (`TestResolveRootFollowsRootOwnedLetsEncryptLinks`, `TestNginxDumpDescribesTheReferencedFiles`), Task 6 (`TestDeployKeyModes`, `TestDeployWritesThroughTheLinkTarget`), Task 3 (`TestFixtureTable` with `letsencrypt.conf`, `combined.conf`, `dual.conf`, `shared.conf`, `space-path.conf`), Task 10 (`TestDiscoverSharedDualAndUnsupportedLocations`), Task 20 (`TestRealNginx/<distro>/letsencrypt_links`, `dual_rsa_ecdsa`).
2. **A local user on the managed server who wants root** — plants a symlink to `/etc/shadow` or `/root/.ssh/authorized_keys` in a directory they can write that an Nginx `include` or a certificate path passes through, replaces a directory between `nginx-dump` and `nginx-deploy`, makes a hard link, or holds the helper's lock. Expected: a path through any directory or link not owned by root, or a group/other-writable directory, is "not supported" and never read or written; a hard link is refused; `/etc/shadow` content never reaches Alice (only `CERTIFICATE` blocks are ever returned, and the file has none); a held lock answers `BUSY` within the helper's budget; nothing is ever written outside the referenced pair. Tests: Task 5 (`TestAttackSymlinkToShadowIsNeverRead`, `TestAttackUserWritableDirectoryOnThePath`, `TestAttackUserOwnedLinkAndDirectoryAsRoot`, `TestAttackHardLinkIsRefused`), Task 6 (`TestAttackDirectorySwappedBeforeTheRename`, `TestDeployRefusesBeforeChangingAnything` cases "pair not in the configuration" and "user-writable directory", `TestDeployAnswersBusyWhenTheLockIsHeld`, `TestDeployAsRootSetsOwnersAndRefusesUserDirectories`), Task 20 (`TestRealNginx/<distro>/user_owned_directory`, `hard_link`).
3. **The connection or Alice dies in the middle of a deployment** — SSH dropped while `nginx-deploy` runs, Alice killed after the backup, after the key write, after `nginx -t`, after the reload, the helper itself killed between the two renames, the license locking while it runs. Expected: the helper finishes its transaction on its own (commit or rollback), Alice's recovery reads the journal (`nginx-status`) and ends with "old certificate live" or "new certificate live and verified", never a mismatched pair; a recovery that cannot reach the server retries and says so; recovery runs in lock. Tests: Task 6 (`TestDeployKilledAtEveryStepRecovers` table), Task 16 (`TestDeploymentSurvivesProcessKillAtEveryStep`, `TestL80InFlightDeployFinishesAcrossLock`, `TestL82RollbackRunsDespiteLock`), Task 11 (`TestDeployConnectionDropIsUncertain`), Task 20 (`TestRealNginx/<distro>/F-08_connection_dropped`).
4. **Uploads as people really have them** — a PEM with Windows line endings and a UTF-8 BOM, the chain in reverse order, the leaf not first, a PFX from Windows with an empty password, a PFX with the wrong password, an encrypted PEM key, a key that belongs to another certificate, a certificate that expired yesterday, an RSA 1024 key, a SHA-1 signed intermediate, 10 certificates in one paste, a 5 MiB body. Expected: line endings and BOM are accepted, the leaf is the certificate whose key is uploaded and the chain is reordered from it, the wrong pair and the expired leaf are refused before anything is stored with the exact messages, the encrypted key gets "remove the password or upload a PFX", weak keys and signatures are refused, an oversized body is 413. Tests: Task 2 (`TestValidateUploadTable`, `FuzzParseCertificateUpload`), Task 18 (`TestUploadJourneyRefusesWithExactMessages`).
5. **A website Alice cannot see directly** — behind a load balancer, on port 8443, a `listen 10.0.0.5:443` address, a wildcard `*.example.com` name, a default server `_`, a firewall that blocks Alice. Expected: the SNI is chosen per spec §12.8 (`alice-check.example.com`, the certificate's first name for `_`), the port comes from `listen`, an Administrator can set the port and name to check per website, Alice falls back to the helper's probe on the server itself ("checked from the server itself"), and when nothing can confirm the certificate Alice changes nothing (or, if the website became unreachable after the write, rolls back) with "Could not reach port 443 from Alice". Tests: Task 11 (`TestSNIForTable`, `TestEndpoints`, `TestVerifyFallsBackToTheServerProbe`, `TestVerifyReportsWhatIsServed`, `TestDeployFailureCatalogue` rows F-06 and F-07), Task 16 (`TestDeployPrecheckRefusalsChangeNothing` rows F-06 and F-07), Task 20 (`TestRealNginx/<distro>/F-07_verify_local`).

---

## Spec conflicts resolved by this plan (proposed R38, written in Task 24)

| # | Conflict | Resolution |
|---|---|---|
| 1 | §12.3 helper surface (`stat`, `read-cert`, `install-cert`, `backup`, `restore`, `nginx-reload`, each a separate SSH call; `nginx-dump` returns raw `nginx -T` text) vs §12.6/F-08/F-09/F-66 (no half-written pair under connection loss or crash) and the hostile-target model (SC-4; `nginx -T` text can carry customer secrets such as `proxy_set_header Authorization`) | Helper protocol 4 (helper 1.3.0): `nginx-dump` (sudo) parses `nginx -T` itself and returns only the parsed summary (servers, names, SSL listens, supported/unsupported pairs, configuration file names) plus, per referenced file, stat data and the `CERTIFICATE` blocks of certificate files — never raw configuration, never key content (key files are only stat'ed); `nginx-test` (sudo); `nginx-deploy` (sudo) is one root-side transaction (backup, write key, write certificate, `nginx -t`, `systemctl reload nginx`, `systemctl is-active nginx`, automatic rollback) with a journal in the operation's backup directory, ignoring SIGHUP/SIGPIPE so it completes after a dropped connection; `nginx-restore` and `nginx-status` (sudo) restore and report an operation from its journal; `tls-probe` (no sudo) is the server-side TLS check. `stat`, `read-cert`, `install-cert`, `backup`, `restore`, `nginx-reload` are not built; the `ALICE_NGINX_ONLY` sudoers lines are narrowed to exactly these five commands. Alice requires protocol 4 (helpers of Phase 3 answer `ssh.helper_outdated`) |
| 2 | §12.3 rule 3 (any path below `/etc/ssl`, `/etc/nginx`, `/etc/pki` is writable) and §12.6 step 2 (a new location's file may be created; rollback deletes it) | The helper writes only the two files of a supported `ssl_certificate`/`ssl_certificate_key` pair of its own `nginx -T` parse (the "allowed roots" are not needed: Alice never creates directives and never writes a path Nginx does not name), and both files must exist already (a valid configuration always has them; rollback is always a restore). Paths are resolved by the helper's own descriptor walk: every directory on the way and every symbolic link must be owned by root, directories not group/other writable (Let's Encrypt's `../../archive` links work; `..` is resolved against the walked descriptors); the file must be regular with one link, and the resolved name must end in `.pem`, `.crt`, `.cer`, `.cert`, `.key`, `.chained` or `.fullchain` |
| 3 | §12.3 `install-cert` owner/mode/SELinux rules; F-13 | The replacement keeps the replaced file's owner and group; the key's mode is 0600, except a key that was 0640 stays 0640 (Debian `ssl-cert` group); the certificate keeps its mode limited to 0644; the SELinux label is copied from the replaced file (`security.selinux` xattr, as `authkeys-write` does); `restorecon` is not run (no extra program) |
| 4 | §12.4 step 4 "relative path resolved against `--prefix`" | Relative `ssl_certificate` paths are resolved against the directory of `--conf-path` (what Nginx does for configuration-relative files); combined certificate+key files, `ssl_password_file`, `engine:` keys, `data:` values, variables, TLS in `stream {}` and paths outside the helper's argument vocabulary (for example with a space) are unsupported locations with a reason |
| 5 | §12.1 "nginx path stored per target from `command -v nginx`" | Fixed `/usr/sbin/nginx` and `/usr/bin/systemctl` (the standard packages on every supported distribution); `nginx-dump` answers `NGINX_NOT_FOUND` (F-20) when `/usr/sbin/nginx` is missing |
| 6 | §12.8 item 6 (fallback `openssl s_client` as the service user) vs §6.6 ("`cat /etc/os-release` is the only non-helper command") | The fallback is the helper's own Go TLS probe `tls-probe --addr --port --sni --key-type` run without sudo as `alice-svc` (no openssl, no sudoers line). Verification probes each SSL `listen` port of every server block of the location (deduplicated, at most 10 endpoints), 5 attempts 2 s apart, remote first, local on a connection failure; the certificate served before the change is probed in the precheck and stored as `previous_fingerprint`; a location Alice can verify neither way gets no change ("Could not reach port N from Alice"); an Administrator may set the port and name to check, or skip verification, per location (audited). The leaf's SHA-256 identifies the certificate; item 5's chain-length and `notAfter` comparisons are not made |
| 7 | Deployment states: §7.4 statuses, §12.6 state names and the F-catalogue's job outcome names differ | `deployments.state` ∈ `queued, precheck, deploying, recovering, done`; `deployments.status` ∈ `pending, running, succeeded, unchanged, failed, rolled_back, rollback_failed, needs_attention`. F-names map: `failed_no_change` = `failed`, `failed_rolled_back` = `rolled_back`, `failed_needs_attention` = `rollback_failed` (files not restored, or restored but Nginx did not reload, F-04) or `needs_attention` (the server cannot be reached to finish, F-09; still active); `partial` (F-16) is a UI summary of several deployments. `deployment_steps` are append-only events (one row per `started`/`ok`/`failed`); `deployments` keeps a snapshot of the certificate and key paths; `binding_id` arrives in Phase 5 |
| 8 | §8.8 crash recovery vs the license gate (a re-queued `ClassChange` deploy job is paused in lock, which would leave a half-changed server) and F-09 "on the next successful connection a recovery step runs before any new operation" | `certificate.deploy_recover` is a `ClassAlways` job (rollback is never blocked, L-82). It is queued at once after an uncertain outcome, and a per-minute scheduler task `deployment.recovery_sweep` (ClassAlways) queues it for every deployment in `deploying`/`recovering` whose deploy job is not running; while the server cannot be reached it is retried every 15 minutes (status `needs_attention`). A deploy job that runs again after a crash never deploys again: it reads the journal (`nginx-status`) and completes or rolls back. "Before any new operation" is enforced for deployments (a new deployment to a target with a deployment being recovered is refused, ALC-DEP-0002); discovery and SSH key work still run |
| 9 | Uploads in lock (§11.7 "database-only changes stay possible") vs R36 item 6 (every state-changing route under `/certificates`, `/locations`, `/deployments` is gated) | R36 item 6 wins: upload, signing requests and location settings are `ClassChange` and refused in lock with `license.locked`; reads stay available. Phase 5 revisits bindings |
| 10 | F-01 "nginx -t fails after the files are written (cert and key mismatch)" and the owner's "deploy a broken pair" vs F-18 (a mismatched pair is refused at upload) and §12.6 PRECHECK (Alice validates the pair) | A mismatched pair never reaches a server through Alice: the upload is refused with "The new certificate does not match its key. Nothing was changed." (owner step 4). F-01's write-then-`nginx -t`-fails path is proven at the provider and helper level (Tasks 6, 11, 20) with a pair handed to the provider directly; the e2e rollback is demonstrated with a reload failure injected on the e2e target (F-03) |
| 11 | Upload validation details (SEC-064, §22.6) | Accepted: PEM (certificate with chain, key PKCS#1/PKCS#8/SEC1, CRLF and a UTF-8 BOM tolerated) and PFX (`software.sslmate.com/src/go-pkcs12`, empty password allowed). Refused: a key that matches no certificate, an expired leaf, a leaf not yet valid is accepted with a warning, RSA below 2048 bits, ECDSA curves other than P-256/P-384, Ed25519, MD5/SHA-1 signatures on the leaf or an intermediate, encrypted PEM keys ("remove the password or upload a PFX file"), more than one private key, bodies over 1 MiB. The chain is reordered from the leaf; "complete" = it verifies to a self-signed certificate in the upload or a system root. Deploying an incomplete chain needs `confirm_incomplete_chain` from an Administrator (F-17) |
| 12 | Permissions for the new routes (§15.4: Admin and Operator deploy, generate CSRs and upload) | New `certificates.operate` (Admin, Operator; operate tokens) for upload, signing requests and deploy; location verification settings need `targets.manage` (Admin); reads use `read` |
| 13 | §9.6 `/certificates/{id}/private-key/download`, `/deployments/{id}/actions/retry|rollback` | Not built in Phase 4. Deploying again is the retry; undoing a successful deployment is deploying the earlier certificate (when Alice holds its key) or the documented manual restore from the helper's backup. Private-key download (Admin, reason, step-up) arrives with Phase 6, for TLS and SSH keys together |
| 14 | §12.6 step 8 (`cleanup --op` after 7 days) | Alice does not call `cleanup`. The helper's sweep removes an Nginx operation's backups 7 days after a committed, unchanged or restored outcome and 30 days otherwise (the Phase 3 hard cap); the `nginx.backup_retention_days` setting waits for Phase 7 Settings |
| 15 | "Alert to admins" on every deployment failure (§24 header) before the Phase 7 alert engine | Emails to every Administrator: `deployment.failed` (nothing changed or restored), `deployment.rollback_failed` (manual action) and, once per deployment, `deployment.needs_attention` (the server cannot be reached to finish; Alice retries every 15 minutes). A recovery job that runs out of attempts ends "needs attention" without the `job.dead` email, so an unreachable server does not send one email per retry |
| 16 | §26.6 "The Nginx real-systemd nightly job runs green" | There is no nightly pipeline before Phase 8; the `systemctl` shim of §22.3 is used in every test image and the real-systemd job moves to Phase 8 with the nightly and release pipelines |
| 17 | Target type of an existing Linux server that runs Nginx | The type is chosen when the server is added (**Linux server** or **Nginx server**) and cannot be changed (delete and add again, R37 item 10); Nginx servers count toward the license |
| 18 | §12.6 "a location (or list of locations)" and F-16 | One deploy request may name up to 20 locations of one certificate; each gets its own deployment and job, independent of the others |
| 19 | Change detection between discovery and deploy | Discovery records the certificate file's SHA-256 (never the key's); `nginx-deploy` takes it as `--expect-cert-sha256` and answers `HASH_MISMATCH` (ALC-NGX-0006) when the file changed since; `CONFIG_CHANGED` when the pair is no longer in the configuration (ALC-NGX-0003) |
| 20 | Phase 3 carries (R37 items 4 and 9) | `authkeys-list` also reports every `/etc/passwd` account name (`accounts`, `accounts_complete`); a key location of a user no longer in that list is marked missing only when the list is complete (no `too_many_users`, no `directory_users_not_listed`, at most 5000 names); an empty shell field counts as a login shell; every uid-0 account with a login shell and an existing home is scanned; inventory's last-root-key pre-check covers every uid-0 account of the last scan; the key list carries `missing` |
| 21 | Error codes and audit actions (none fixed by the spec except `nginx.config_test_failed`) | `ALC-NGX-0001..0009`, `ALC-CRT-0001..0013`, `ALC-DEP-0001..0011` (contract table); audit actions `certificate.uploaded`, `certificate.upload_rejected`, `certificate.key_attached`, `csr.created`, `csr.completed`, `csr.cancelled`, `location.updated`, `location.changed_outside`, `deployment.requested`, `deployment.denied`, `deployment.succeeded`, `deployment.unchanged`, `deployment.failed`, `deployment.rolled_back`, `deployment.rollback_failed`, `deployment.recovery_started`, `deployment.needs_attention`. A rolled-back deployment writes `deployment.failed` (with `failed_step`) and `deployment.rolled_back` (L-82 "audit shows both events") |

## Carries from Phase 3 and deferred items

Sources: `docs/superpowers/rulings/phase-3.md` ("Parked / carried to Phase 4") and `docs/security/reviews/phase-3.md` ("Known limitations").

| # | Carry | Decision | Where |
|---|---|---|---|
| 1 | Keys of OS users deleted from a server keep showing as present | Included: `authkeys-list` reports every valid `/etc/passwd` account name and whether the list is complete; `Reconcile` marks the locations of a user missing from a complete list as missing (never deleted). Complete = `/etc/passwd` read, no `too_many_users`, no `directory_users_not_listed`, at most 5000 names | Tasks 4, 5 (helper), 7 (provider), 13 (inventory) |
| 2 | An empty shell field is skipped although sshd uses `/bin/sh` | Included: `loginShell("")` is true | Task 5 (helper) |
| 3 | Last-root-key pre-check matches the name `root` only; the helper lists no other uid-0 account | Included: the helper also scans every uid-0 account with a login shell and an existing home (Task 5); the provider reports `UID0Users`; inventory stores them in `facts.uid0_users` and its pre-check treats each like `root` (Task 1) | Tasks 1, 5 |
| 4 | No "missing" mark on key-list rows | Included: `GET /api/v1/ssh-keys` items carry `missing` (every location of the key that matched the filter is missing or removed); the list shows the badge **No longer found** | Task 1 |
| 5 | No e2e for **The server still shows the previous fingerprint** | Included in `web/e2e/phase3.spec.ts` | Task 23 |
| 6 | L-80, L-81, L-82 and the real-job parts of L-29 for deploy jobs | Included with the real `certificate.deploy` job (L-80, L-82 with a blocking provider; L-81 blocked, then confirmed; L-29: no remote command in lock, upload, deploy, signing-request and location routes refused) | Tasks 16, 18 |
| 7 | L-83..L-86, L-88 (rotation runner), L-87 (Key Vault poll) | **Re-deferred** to Phases 6 and 5: their jobs do not exist yet; their gate parts stay covered by `internal/jobs/stubjobs_test.go` | — |
| 8 | Restore primitive for a removed `authorized_keys` key whose verification failed (`ALC-KEY-0005` stops for a person) | **Re-deferred to Phase 6.** Phase 4's restore is file-level for Nginx pairs with a root journal; an `authorized_keys` restore has a different conflict model (another writer may have changed the file after Alice's write, and restoring would revert that writer too) and belongs with Phase 6's key add and rotation, which need the same verify-then-restore step | — |
| 9 | A manual **Test connection** merged into a live scheduled re-test ends without the dead-task email | **Re-deferred to Phase 7** (alert engine); the failure is visible on the server's page | — |
| 10 | Web: the host-keys query keyed by status has no placeholder data (the re-pin dialog can flash "no candidate") | Included: `placeholderData: keepPreviousData` on that query | Task 22 |
| 11 | Web: `waitForJob` retries any `TypeError` until its deadline | Included: `client.ts` wraps a failed `fetch` in `NetworkError`; `waitForJob` retries `NetworkError` and retryable API errors only; any other error (a `TypeError` from our own code) rejects at once | Task 21 |
| 12 | Web: one test relies on a real 3 s poll | Included: that test uses `vi.useFakeTimers({ shouldAdvanceTime: true })` and advances 3 s | Task 22 |
| 13 | `make e2e` lets `deploy/.env` override a shell-exported `ALICE_E2E_PORT` | Included: the recipe saves a shell value before sourcing `deploy/.env` and restores it | Task 19 |
| 14 | Audit chain unkeyed; `jobs.audit_verify` writable by `alice_app` | **Re-deferred to Phase 7** (external anchors, keyed chain) | — |
| 15 | Forged `license_history` notices can be displayed; a late OK report can reject a just-seen candidate; re-pin/dismiss would re-enable a disabled target | **Re-deferred** (no new information; nothing sets `disabled` yet; the audit log stays authoritative) | — |
| 16 | Test-only: fake `Config.clone` shallow, drain off-by-one at the deadline, weak debounce test | **Re-deferred** (test code only, no product behaviour) | — |
| 17 | Owner-pending: production license key, owner walkthroughs of Phases 1–3, Turkish tone review, crypto sign-off | Owner only; Phase 4 adds its own walkthrough table | Task 24 |
| — | Mutation testing of `rbac`, nightly fuzzing, the real-systemd Nginx job | **Re-deferred to Phase 8** (nightly pipeline, R38 item 16) | — |
| — | `ALICE_SSH_*` and `nginx.*` settings (connection limits, backup retention) | **Re-deferred to Phase 7** (Settings); constants now | — |

---

## File Structure

```
internal/testutil/pki/                    generated CA, leaf, PFX, CSR and broken-pair fixtures (Task 2)
tools/testcerts/                          owner test pack: a good pair, a broken pair, a PFX (Task 2)
internal/certs/                           pure upload/PFX/chain/CSR validation, FuzzParseCertificateUpload (Task 2)
internal/providers/nginx/nginxconf/       pure nginx -T parser, FuzzParseNginxConfig (Task 3)
test/testdata/nginx/*.conf                nginx -T fixtures (Task 3)
internal/providers/linuxssh/helperproto/  protocol 4 vocabulary (Task 4)
cmd/alice-helper/                         accounts carry, rootpath.go, nginx.go (nginx-dump, nginx-test), probe.go (tls-probe)
                                          (Task 5); deploy.go, journal.go (nginx-deploy, nginx-restore, nginx-status), sweep (Task 6)
internal/providers/linuxssh/              command.go (constructors), setup.go (narrowed nginx sudoers), discover.go (accounts,
                                          uid-0), provider.go (protocol 4, ConnOf) (Tasks 1, 7)
internal/providers/                       types.go, provider.go, unsupported.go: certificate and deploy types and methods;
                                          providertest, fake (Task 8)
internal/providers/linuxssh/linuxsshtest/ nginx.go: emulated Nginx world for the fake SSH server (Tasks 9, 16)
internal/providers/nginx/                 provider.go, discover.go (Task 10); deploy.go, verify.go, probe.go (Task 11);
                                          containers_integration_test.go (Task 20)
migrations/00006_certificates.sql         certificates, locations, keys, CSRs, deployments, steps, grants (Task 12)
internal/inventory/                       certificates.go, locations.go (Task 13); uploads.go, csr.go (Task 14);
                                          deployments.go, sweep.go (Task 15); sshkeys.go, removal.go (Tasks 1, 13)
internal/jobs/types.go                    job types (Task 15)
internal/jobs/deployjobs/                 certificate.deploy and certificate.deploy_recover handlers (Task 16)
internal/rbac/rbac.go                     certificates.operate (Task 17)
internal/api/                             certificates_handlers.go, deployments_handlers.go, certs_dto.go, errors.go (Task 17);
                                          integration suites (Task 18)
api/openapi.yaml, docs/authz-matrix.md    new operations (Task 17)
locales/common/{en,tr}.json               error texts (Task 17), email templates (Task 15)
docs/troubleshooting.md                   new codes (Task 17)
cmd/alice/                                providers.go, services.go, testapi_e2e.go (Task 19)
test/images/e2e-target/                   Nginx, systemctl shim, alice-e2e-newcert, alice-e2e-reload-mode (Task 19)
test/images/sshd/                         Nginx and the systemctl shim on Ubuntu 22.04, Debian 12, Rocky 9 (Task 20)
deploy/docker-compose.e2e.yml, Makefile   e2e target healthcheck, fuzz-nginx, test-ssh, e2e port carry (Task 19)
web/src/                                  API, Certificates pages, upload and CSR dialogs (Task 21); server websites panel,
                                          deploy dialog, location settings, Deployment history, add-server type (Task 22)
web/e2e/phase4.spec.ts, phase3.spec.ts    EN/TR journeys (Task 23)
docs/                                     nginx-host-preparation.md, operator/admin guides, troubleshooting, CHANGELOG,
                                          security/reviews/phase-4.md, R38, coverage floors (Task 24)
```

Task order is bottom-up: carries without the helper (1), pure packages (2–4), helper (5–6), connector and framework (7–8), test world (9), provider (10–11), schema (12), inventory (13–15), deploy engine (16), HTTP (17–18), wiring and the e2e target (19), real Nginx matrix (20), web (21–22), end-to-end (23), documentation and verification (24). Each task leaves the repository green. Tasks that change `alice-helper` are marked **HELPER** and follow the helper change procedure of the Global Constraints.

### Task index

1. Carries without a helper change: uid-0 accounts in the last-root-key pre-check, `missing` on key-list rows
2. Test PKI, owner test pack and the pure `certs` package (upload, PFX, chain, CSR; `FuzzParseCertificateUpload`)
3. Pure `nginx -T` parser `nginxconf` with fixtures and `FuzzParseNginxConfig`
4. Helper protocol 4 vocabulary (`helperproto`)
5. **HELPER** part 1: accounts carry, root-controlled path walk, `nginx-dump`, `nginx-test`, `tls-probe`
6. **HELPER** part 2: `nginx-deploy`, `nginx-restore`, `nginx-status` (journal, backups, atomic replace, rollback, kill points), backup retention
7. `linuxssh`: protocol 4 constructors, narrowed `nginx` sudoers, accounts in discovery, `ConnOf`
8. Provider framework: certificate, deploy, rollback, verify and status types and methods; conformance suite; fake provider
9. Test world: emulated Nginx for the fake SSH server
10. `nginx` provider part 1: provider, test connection (profile check, F-14), discovery (F-20, F-21)
11. `nginx` provider part 2: deploy, inline rollback, verification and probes, status (F-01..F-13 at provider level)
12. Migration `00006`: certificates, locations, managed keys, signing requests, deployments, steps, grants
13. Inventory: certificate reconciliation, queries, locations, Nginx targets, accounts-based missing marking
14. Inventory: uploads, signing requests, location settings
15. Deployment records, requests (F-15, F-17, F-19), recovery sweep, emails and job types
16. Deploy engine: `certificate.deploy` and `certificate.deploy_recover` handlers (F-66, L-80..L-82)
17. API: routes, DTOs, `certificates.operate`, error codes, OpenAPI, authz matrix
18. API integration: Nginx journeys with the fake SSH server, secret-leak suite with TLS keys (S-01..S-05), lock (L-29, L-81)
19. Wiring: providers, runner and scheduler, e2e target with Nginx, Dockerfiles, Makefile
20. Real Nginx matrix on Ubuntu 22.04, Debian 12, Rocky 9 (F-01..F-13, A-13 variants, connection drop)
21. Web: API layer, Certificates list and detail, upload dialog, signing requests, navigation, audit labels
22. Web: Nginx server websites panel, deploy dialog with live steps, verification settings, Deployment history, add-server type
23. End-to-end: Phase 4 owner journeys in EN and TR, the Phase 3 dismissal carry, accessibility
24. Coverage floors, documentation, R38, security review, `make ci`

Recommended execution: subagent-driven (the tasks share many interfaces and a shipped mistake in the helper is a root-level defect), one reviewer per task, with an additional security reviewer on Tasks 5, 6, 7, 11 and 16.

---

## Cross-task contract

Every task's **Interfaces** block repeats the parts of this contract it consumes or produces. When a task and this section disagree, this section wins and the task is a plan defect to fix at execution time.

### Database (migration `00006_certificates.sql`, Task 12)

```sql
-- +goose Up
-- Phase 4: certificates, Nginx certificate locations, private keys held by Alice, signing requests,
-- deployments and their steps (spec §7.2–§7.4, §12; R38).

-- Private keys uploaded into Alice or generated for a signing request (spec §7.2). Envelope
-- columns as credentials (AAD managed_private_keys/<id>/ciphertext); append-only for the app.
CREATE TABLE managed_private_keys (
    id                uuid PRIMARY KEY,
    owner_type        text NOT NULL CHECK (owner_type IN ('certificate', 'csr')),
    algorithm         text NOT NULL CHECK (algorithm IN ('rsa', 'ecdsa')),
    bits              integer NOT NULL CHECK (bits > 0),
    public_key_sha256 text NOT NULL CHECK (public_key_sha256 ~ '^[0-9a-f]{64}$'), -- not unique: a renewal may reuse a key
    ciphertext        bytea NOT NULL,
    nonce             bytea NOT NULL CHECK (octet_length(nonce) = 12),
    wrapped_dek       bytea NOT NULL,
    key_version       integer NOT NULL CHECK (key_version >= 1),
    created_by        uuid REFERENCES users (id),
    created_at        timestamptz NOT NULL
);

CREATE INDEX managed_private_keys_public_key ON managed_private_keys (public_key_sha256);

CREATE TABLE certificates (
    id                 uuid PRIMARY KEY,
    fingerprint_sha256 text NOT NULL UNIQUE CHECK (fingerprint_sha256 ~ '^[0-9a-f]{64}$'), -- SHA-256 of the leaf DER
    subject_cn         text NOT NULL DEFAULT '',
    subject            text NOT NULL DEFAULT '',
    issuer             text NOT NULL DEFAULT '',
    serial             text NOT NULL DEFAULT '',
    sans               text[] NOT NULL DEFAULT '{}',
    not_before         timestamptz NOT NULL,
    not_after          timestamptz NOT NULL,
    key_algorithm      text NOT NULL CHECK (key_algorithm IN ('rsa', 'ecdsa', 'ed25519', 'other')),
    key_bits           integer NOT NULL DEFAULT 0,
    public_key_sha256  text NOT NULL CHECK (public_key_sha256 ~ '^[0-9a-f]{64}$'),
    pem_chain          text NOT NULL,                       -- leaf first, then the chain; public
    chain_complete     boolean NOT NULL DEFAULT false,
    self_signed        boolean NOT NULL DEFAULT false,
    source             text NOT NULL CHECK (source IN ('discovered', 'uploaded', 'csr', 'azure_kv')),
    label              text NOT NULL DEFAULT '' CHECK (char_length(label) <= 100),
    private_key_id     uuid UNIQUE REFERENCES managed_private_keys (id),
    first_seen_at      timestamptz NOT NULL,
    last_seen_at       timestamptz NOT NULL,
    created_by         uuid REFERENCES users (id),
    created_at         timestamptz NOT NULL
);
CREATE INDEX certificates_not_after ON certificates (not_after, id);
CREATE INDEX certificates_sans ON certificates USING gin (sans);
CREATE INDEX certificates_public_key ON certificates (public_key_sha256);

CREATE TABLE csr_requests (
    id             uuid PRIMARY KEY,
    private_key_id uuid NOT NULL UNIQUE REFERENCES managed_private_keys (id),
    common_name    text NOT NULL CHECK (char_length(common_name) BETWEEN 1 AND 64),
    sans           text[] NOT NULL DEFAULT '{}',
    csr_pem        text NOT NULL,
    status         text NOT NULL CHECK (status IN ('pending', 'completed', 'cancelled')),
    certificate_id uuid REFERENCES certificates (id),
    created_by     uuid REFERENCES users (id),
    created_at     timestamptz NOT NULL,
    finished_at    timestamptz,
    CHECK ((status = 'completed') = (certificate_id IS NOT NULL))
);

-- One row per certificate file an Nginx target uses (spec §7.3, §12.4 step 6: a file shared by
-- several server blocks is one location; its server blocks are in servers).
CREATE TABLE certificate_locations (
    id                   uuid PRIMARY KEY,
    target_id            uuid NOT NULL REFERENCES targets (id),
    kind                 text NOT NULL CHECK (kind IN ('nginx_file')),
    cert_path            text NOT NULL,
    key_path             text NOT NULL DEFAULT '',
    certificate_id       uuid REFERENCES certificates (id),       -- NULL: no readable certificate in the file
    key_type             text NOT NULL DEFAULT '' CHECK (key_type IN ('', 'rsa', 'ecdsa')),
    servers              jsonb NOT NULL DEFAULT '[]',              -- providers.CertServer list
    supported            boolean NOT NULL,
    unsupported_reason   text NOT NULL DEFAULT '',
    problem              text NOT NULL DEFAULT '',
    inherited            boolean NOT NULL DEFAULT false,
    custom_location      boolean NOT NULL DEFAULT false,
    symlinked            boolean NOT NULL DEFAULT false,
    cert_file_sha256     text NOT NULL DEFAULT '' CHECK (cert_file_sha256 = '' OR cert_file_sha256 ~ '^[0-9a-f]{64}$'),
    key_exists           boolean NOT NULL DEFAULT false,
    key_mode             text NOT NULL DEFAULT '',
    key_owner            text NOT NULL DEFAULT '',
    warnings             text[] NOT NULL DEFAULT '{}',
    deployed_fingerprint text NOT NULL DEFAULT '',                -- the leaf Alice last deployed here
    changed_outside_at   timestamptz,
    verify_port          integer CHECK (verify_port BETWEEN 1 AND 65535),
    verify_sni           text CHECK (verify_sni IS NULL OR char_length(verify_sni) BETWEEN 1 AND 253),
    skip_verify          boolean NOT NULL DEFAULT false,
    first_seen_at        timestamptz NOT NULL,
    last_seen_at         timestamptz NOT NULL,
    missing_since        timestamptz,
    version              integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    UNIQUE (target_id, kind, cert_path)
);
CREATE INDEX certificate_locations_certificate ON certificate_locations (certificate_id);

-- One deployment of one certificate to one location (spec §7.4). Its id is also the helper's
-- operation id (backups in /var/lib/alice-helper/backups/<id>).
CREATE TABLE deployments (
    id                   uuid PRIMARY KEY,
    certificate_id       uuid NOT NULL REFERENCES certificates (id),
    location_id          uuid NOT NULL REFERENCES certificate_locations (id),
    target_id            uuid NOT NULL REFERENCES targets (id),
    job_id               uuid REFERENCES jobs (id) ON DELETE SET NULL,
    trigger              text NOT NULL CHECK (trigger IN ('manual', 'kv_renewal', 'retry')),
    requested_by         uuid REFERENCES users (id),
    state                text NOT NULL CHECK (state IN ('queued', 'precheck', 'deploying', 'recovering', 'done')),
    status               text NOT NULL CHECK (status IN ('pending', 'running', 'succeeded', 'unchanged', 'failed',
                                                         'rolled_back', 'rollback_failed', 'needs_attention')),
    new_fingerprint      text NOT NULL CHECK (new_fingerprint ~ '^[0-9a-f]{64}$'),
    previous_fingerprint text NOT NULL DEFAULT '',
    cert_path            text NOT NULL,
    key_path             text NOT NULL,
    confirm_incomplete_chain boolean NOT NULL DEFAULT false,
    rollback_info        jsonb,                                    -- providers.BackupRef, written before the first change
    verified             text NOT NULL DEFAULT '' CHECK (verified IN ('', 'remote', 'local', 'skipped')),
    error_code           text NOT NULL DEFAULT '',
    error_params         jsonb NOT NULL DEFAULT '{}',
    failed_step          text NOT NULL DEFAULT '',
    recover_after        timestamptz,
    created_at           timestamptz NOT NULL,
    started_at           timestamptz,
    finished_at          timestamptz,
    CHECK ((state = 'done') = (finished_at IS NOT NULL)),
    CHECK ((state = 'done') = (status NOT IN ('pending', 'running', 'needs_attention')))
);
CREATE UNIQUE INDEX deployments_one_active ON deployments (location_id) WHERE state <> 'done';
CREATE INDEX deployments_target ON deployments (target_id, created_at DESC, id DESC);
CREATE INDEX deployments_certificate ON deployments (certificate_id, created_at DESC, id DESC);
CREATE INDEX deployments_created ON deployments (created_at DESC, id DESC);
CREATE INDEX deployments_unfinished ON deployments (recover_after) WHERE state IN ('deploying', 'recovering');

-- Append-only step events (R38 item 7): one row per started/ok/failed/skipped.
CREATE TABLE deployment_steps (
    id            uuid PRIMARY KEY,
    deployment_id uuid NOT NULL REFERENCES deployments (id) ON DELETE CASCADE,
    n             integer NOT NULL CHECK (n >= 1),
    name          text NOT NULL CHECK (name ~ '^[a-z][a-z_]{0,39}$'),
    status        text NOT NULL CHECK (status IN ('started', 'ok', 'failed', 'skipped')),
    at            timestamptz NOT NULL,
    params        jsonb NOT NULL DEFAULT '{}',
    UNIQUE (deployment_id, n)
);

-- Keys and steps are append-only for the application; certificates, locations, signing requests
-- and deployments are never deleted (history) and are updated only in the columns listed.
GRANT SELECT, INSERT ON managed_private_keys, certificates, csr_requests, certificate_locations, deployments,
    deployment_steps TO alice_app;
GRANT UPDATE (label, private_key_id, last_seen_at, pem_chain, chain_complete) ON certificates TO alice_app;
GRANT UPDATE (status, certificate_id, finished_at) ON csr_requests TO alice_app;
GRANT UPDATE (key_path, certificate_id, key_type, servers, supported, unsupported_reason, problem, inherited,
    custom_location, symlinked, cert_file_sha256, key_exists, key_mode, key_owner, warnings, deployed_fingerprint,
    changed_outside_at, verify_port, verify_sni, skip_verify, last_seen_at, missing_since, version)
    ON certificate_locations TO alice_app;
GRANT UPDATE (job_id, state, status, previous_fingerprint, rollback_info, verified, error_code, error_params,
    failed_step, recover_after, started_at, finished_at) ON deployments TO alice_app;

-- +goose Down
DROP TABLE deployment_steps;
DROP TABLE deployments;
DROP TABLE certificate_locations;
DROP TABLE csr_requests;
DROP TABLE certificates;
DROP TABLE managed_private_keys;
```

Envelope location of a managed key: `secrets.Location{Table: "managed_private_keys", RowID: <id>, Column: "ciphertext"}`; payload = the PKCS#8 DER of the key. The `jobs.target_id` foreign key already exists; `deployments.job_id` uses `ON DELETE SET NULL` so `maintenance.cleanup`'s prune of 90-day-old jobs keeps working.

### Helper protocol 4 (`internal/providers/linuxssh/helperproto`, Task 4)

Additions to `helperproto.go` (existing names unchanged; `Protocol` and `Version` change):

```go
const (
	Protocol = 4
	Version  = "1.3.0"
)

// Phase 4 subcommands (spec §12.3, R38 item 1). tls-probe runs without sudo (like version).
const (
	SubNginxDump    = "nginx-dump"
	SubNginxTest    = "nginx-test"
	SubNginxDeploy  = "nginx-deploy"
	SubNginxRestore = "nginx-restore"
	SubNginxStatus  = "nginx-status"
	SubTLSProbe     = "tls-probe"
)

// Phase 4 error codes.
const (
	CodeNginxNotFound = "NGINX_NOT_FOUND" // /usr/sbin/nginx does not exist (F-20)
	CodeConfigInvalid = "CONFIG_INVALID"  // nginx -T/-t fails before anything changed (F-02)
	CodeConfigChanged = "CONFIG_CHANGED"  // the paths are not a supported pair of the current configuration
	CodeNoSpace       = "NO_SPACE"        // less free space than the new files plus MinFreeBytes (F-10, F-11)
	CodeBadContent    = "BAD_CONTENT"     // stdin is not one certificate file and one unencrypted private key
	CodeBusy          = "BUSY"            // another nginx-deploy or nginx-restore holds the lock
	CodeUnknownOp     = "UNKNOWN_OP"      // nginx-restore: no journal for this operation
	CodeProbeFailed   = "PROBE_FAILED"    // tls-probe could not connect or complete the handshake
)

// Phase 4 warnings of nginx-dump.
const (
	WarnStreamTLS          = "stream_tls"           // TLS in stream {} is listed but not supported (F-21, R23)
	WarnConfigFileWritable = "config_file_writable" // a configuration file can be changed by users other than root
	WarnTooManyFiles       = "too_many_files"       // more referenced files than MaxNginxFiles
)

// Accounts carry (R38 item 20).
const MaxAccountNames = 5000

// Phase 4 limits.
const (
	MaxNginxConfig   = 20 << 20  // nginx -T output the helper reads
	MaxCertFileSize  = 256 << 10 // a certificate or key file
	MaxDeployInput   = 512 << 10 // nginx-deploy stdin
	MaxNginxFiles    = 1000      // referenced certificate and key files nginx-dump describes
	MinFreeBytes     = 10 << 20  // free space kept after a write (spec §12.6 step 1)
	NginxDumpOutput  = 16 << 20  // nginx-dump's answer: certificates are public and small
	NginxBackupKeep  = 7 * 24 * time.Hour
)

// Configuration error classes of nginx -t (never the raw text).
const (
	ConfigErrKeyMismatch = "key_mismatch"
	ConfigErrFileMissing = "file_missing"
	ConfigErrCertLoad    = "cert_load"
	ConfigErrKeyLoad     = "key_load"
	ConfigErrSyntax      = "syntax"
)

// File problems of nginx-dump (also providers.CertProblem*).
const (
	FileMissing           = "missing"
	FileNotRootControlled = "not_root_controlled"
	FileNotRegular        = "not_regular"
	FileHardLinked        = "hard_linked"
	FileTooLarge          = "too_large"
	FileNotACertificate   = "not_a_certificate"
	FileUnreadable        = "unreadable"
	FileBadName           = "bad_name" // the resolved name has no certificate or key extension
)

// Deployment journal phases (nginx-status, nginx-deploy outcome).
const (
	PhaseNone          = "none"           // no journal: nothing happened for this operation
	PhasePrepared      = "prepared"       // backups written; nothing renamed
	PhaseWriting       = "writing"        // between the first rename and the end of the reload: interrupted when not active
	PhaseCommitted     = "committed"      // both files written, nginx -t passed, reload and is-active passed
	PhaseUnchanged     = "unchanged"      // the files already held the new content; nothing written, no reload
	PhaseRestoring     = "restoring"      // a rollback is under way: interrupted when not active
	PhaseRestored      = "restored"       // the backups are back and Nginx reloaded
	PhaseRestoreFailed = "restore_failed" // the rollback could not finish
)

// Deploy step names (nginx-deploy and nginx-restore report them in order).
const (
	StepBackup             = "backup"
	StepWriteKey           = "write_key"
	StepWriteCert          = "write_cert"
	StepConfigTest         = "config_test"
	StepReload             = "reload"
	StepRestore            = "restore"
	StepRollbackConfigTest = "rollback_config_test"
	StepRollbackReload     = "rollback_reload"
)

type NginxListen struct {
	Addr          string `json:"addr"` // "" = any address
	Port          int    `json:"port"`
	DefaultServer bool   `json:"default_server"`
}

type NginxPair struct {
	Cert        string `json:"cert"`
	Key         string `json:"key"`
	Inherited   bool   `json:"inherited"`
	Unsupported string `json:"unsupported"` // "" or an nginxconf.Reason*
	Raw         string `json:"raw"`         // the directive's argument when unsupported (cleaned, at most 200 runes)
}

type NginxServer struct {
	File    string        `json:"file"`
	Line    int           `json:"line"`
	Names   []string      `json:"names"`
	Listens []NginxListen `json:"listens"` // SSL listens only
	Pairs   []NginxPair   `json:"pairs"`
	Stream  bool          `json:"stream"`
}

type NginxFile struct {
	Path        string `json:"path"`
	Kind        string `json:"kind"` // "cert" | "key"
	Exists      bool   `json:"exists"`
	Resolved    string `json:"resolved"`
	Symlinked   bool   `json:"symlinked"`
	Mode        string `json:"mode"`  // "0644"
	Owner       string `json:"owner"` // account name or uid
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256"` // certificate files only
	PEM         string `json:"pem"`    // certificate files only: CERTIFICATE blocks, nothing else
	Problem     string `json:"problem"`
	FreeBytes   int64  `json:"free_bytes"`
}

type NginxDumpResponse struct {
	OK          bool          `json:"ok"`
	Version     string        `json:"version"`
	ConfPath    string        `json:"conf_path"`
	ConfigValid bool          `json:"config_valid"`
	ConfigError string        `json:"config_error"` // a ConfigErr* class when !ConfigValid
	Servers     []NginxServer `json:"servers"`
	Files       []NginxFile   `json:"files"`
	Warnings    []string      `json:"warnings"`
	Writable    []string      `json:"writable"` // configuration files others than root can change
}

type NginxTestResponse struct {
	OK    bool   `json:"ok"`
	Valid bool   `json:"valid"`
	Error string `json:"error"`
}

type NginxStep struct {
	Name   string `json:"name"`
	Status string `json:"status"` // "ok" | "failed"
	Error  string `json:"error"`  // a ConfigErr* class or "" (never raw text)
}

type NginxDeployInput struct {
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem"`
}

type NginxDeployResponse struct {
	OK         bool        `json:"ok"`
	Phase      string      `json:"phase"` // PhaseCommitted, PhaseUnchanged, PhaseRestored, PhaseRestoreFailed
	FailedStep string      `json:"failed_step"`
	Error      string      `json:"error"`
	Steps      []NginxStep `json:"steps"`
	BackupDir  string      `json:"backup_dir"`
}

type NginxRestoreResponse struct {
	OK    bool        `json:"ok"`
	Phase string      `json:"phase"` // PhaseRestored, PhaseRestoreFailed, or PhasePrepared/PhaseUnchanged (nothing to restore)
	Error string      `json:"error"`
	Steps []NginxStep `json:"steps"`
}

type NginxStatusResponse struct {
	OK                bool   `json:"ok"`
	Phase             string `json:"phase"`
	Active            bool   `json:"active"` // a helper process holds the Nginx lock now
	NewCertSHA256     string `json:"new_cert_sha256"`
	CurrentCertSHA256 string `json:"current_cert_sha256"`
	BackupDir         string `json:"backup_dir"`
}

type TLSProbeResponse struct {
	OK          bool   `json:"ok"`
	LeafSHA256  string `json:"leaf_sha256"` // hex SHA-256 of the served leaf's DER
	ChainLength int    `json:"chain_length"`
	NotAfter    string `json:"not_after"` // RFC 3339 UTC
}

// AuthKeysListResponse gains (accounts carry):
//	Accounts         []string `json:"accounts"`          // every valid /etc/passwd name, sorted, deduplicated
//	AccountsComplete bool     `json:"accounts_complete"` // see R38 item 20

// ValidPort reports whether s is a decimal TCP port 1..65535 without leading zeros.
func ValidPort(s string) bool

// ValidSNI reports whether s is a DNS name Alice may send as SNI: 1..253 bytes of
// [a-z0-9.-] (lower case), no leading or trailing dot or hyphen in a label, no empty label.
func ValidSNI(s string) bool

// ValidIP reports whether s is an IPv4 or IPv6 literal without a zone (netip.ParseAddr) in its
// canonical form (netip.Addr.String() == s).
func ValidIP(s string) bool

// KeyTypes of tls-probe.
const (
	ProbeAny   = "any"
	ProbeRSA   = "rsa"
	ProbeECDSA = "ecdsa"
)

// NoSNI is the --sni value of tls-probe that sends no server name (ValidArg accepts it,
// ValidSNI does not, so it can never be a real name).
const NoSNI = "_"

// ProbeTLSConfig is the client configuration of both verification probes (Alice's and the
// helper's tls-probe): no certificate verification (the served leaf's fingerprint is compared,
// spec §12.8 item 3), TLS 1.2 or later; keyType rsa or ecdsa limits the probe to TLS 1.2 with
// ECDHE_RSA or ECDHE_ECDSA suites so a dual-certificate server shows the one of that type
// (spec §12.8 item 4). sni "" or NoSNI sends no server name.
func ProbeTLSConfig(sni, keyType string) *tls.Config
```

### Helper wire behaviour (`cmd/alice-helper`, Tasks 5 and 6)

| Command line (after sudo) | stdin | Answer (exit 0) | Refusals |
|---|---|---|---|
| `alice-helper nginx-dump` | — | `NginxDumpResponse`. Runs `/usr/sbin/nginx -T` (stdout ≤ `MaxNginxConfig`, stderr discarded except for the error class) and `/usr/sbin/nginx -V` (stderr: version, `--conf-path`); parses with `nginxconf.Parse(out, dir(conf-path))`. When `-T` fails: `config_valid=false`, `config_error` set, `servers`/`files` empty. For each supported pair: one `NginxFile` per distinct certificate path (`kind cert`: stat + `CERTIFICATE` blocks + file SHA-256) and per distinct key path (`kind key`: stat only, the content is never read) | 2 `USAGE` (any argument); 3 `NGINX_NOT_FOUND`; 4 `IO_ERROR` |
| `alice-helper nginx-test` | — | `NginxTestResponse` (`/usr/sbin/nginx -t`; `error` = class) | 2 `USAGE`; 3 `NGINX_NOT_FOUND` |
| `alice-helper nginx-deploy --op <uuid> --cert <path> --key <path> --expect-cert-sha256 <sha256> --content-sha256 <sha256>` | `NginxDeployInput` JSON, ≤ `MaxDeployInput` bytes, SHA-256 = `--content-sha256` | `NginxDeployResponse` (phase `committed`, `unchanged`, `restored` — a rolled-back failure — or `restore_failed`; `failed_step`, `error` set for the last two) | 2 `USAGE`, `INVALID_ARGUMENT`, `PATH_NOT_ALLOWED`, `NOT_REGULAR_FILE`, `UNSAFE_FILE`, `BAD_CONTENT`, `TOO_LARGE`; 3 `CONTENT_MISMATCH`, `CONFIG_INVALID`, `CONFIG_CHANGED`, `HASH_MISMATCH`, `NOT_FOUND`, `NO_SPACE`, `NGINX_NOT_FOUND`; 4 `BUSY`, `IO_ERROR` — every refusal means nothing changed |
| `alice-helper nginx-restore --op <uuid>` | — | `NginxRestoreResponse` | 2 `USAGE`, `INVALID_ARGUMENT`; 3 `UNKNOWN_OP`, `HASH_MISMATCH` (a file is neither the deployed nor the backed-up content: nothing restored); 4 `BUSY`, `IO_ERROR` |
| `alice-helper nginx-status --op <uuid>` | — | `NginxStatusResponse` (`phase none` when no journal) | 2 `USAGE`, `INVALID_ARGUMENT`; 4 `IO_ERROR` |
| `alice-helper tls-probe --addr <ip> --port <n> --sni <name> --key-type <any\|rsa\|ecdsa>` (no sudo) | — | `TLSProbeResponse` | 2 `USAGE`, `INVALID_ARGUMENT`; 4 `PROBE_FAILED` |

Fixed program paths: `/usr/sbin/nginx`, `/usr/bin/systemctl` (`reload nginx`, then `is-active --quiet nginx`), each run with `exec.CommandContext`, environment `PATH=/usr/sbin:/usr/bin:/sbin:/bin`, `LANG=C`, stdout/stderr capped. Lock: `/var/lib/alice-helper/locks/nginx.lock` (root-private, `openLockFile`), waited for at most `lockWait`. Journal: `<BackupRoot>/<op>/journal.json` (0600, replaced through `journal.tmp` + `renameat` + directory `fsync`); backups `<BackupRoot>/<op>/cert.bak` and `key.bak` (0600). The helper ignores `SIGHUP` and `SIGPIPE` for every subcommand (a dropped SSH connection never stops a transaction half-way). Every privileged call still runs `sweepBackups` (7 days for an Nginx operation in phase `committed`, `unchanged`, `restored` or `prepared`; 30 days otherwise) and `sweepLocks`.

### `linuxssh` command constructors and sudoers (Task 7)

```go
func CmdNginxDump() HelperCommand // sudo, LongCommandTimeout, max output helperproto.NginxDumpOutput
func CmdNginxTest() HelperCommand // sudo, LongCommandTimeout, smallOutput
func CmdNginxDeploy(op uuid.UUID, certPath, keyPath, expectCertSHA256 string, input []byte) (HelperCommand, error)
	// sudo, LongCommandTimeout, smallOutput; stdin = input (≤ MaxDeployInput); --content-sha256 = sha256(input)
func CmdNginxRestore(op uuid.UUID) (HelperCommand, error) // sudo, LongCommandTimeout, smallOutput
func CmdNginxStatus(op uuid.UUID) (HelperCommand, error)  // sudo, DefaultCommandTimeout, smallOutput
func CmdTLSProbe(addr string, port int, sni, keyType string) (HelperCommand, error) // no sudo, DefaultCommandTimeout, smallOutput
func (c HelperCommand) WipeInput() // overwrites the stdin bytes with zeros (the key travels there)
func ConnOf(s providers.Session) (*Conn, bool) // the connection of a linuxssh session (for the nginx provider)
```

Exact command lines (asserted by `TestCommandLinesAreExact`):

```
sudo -n /usr/local/libexec/alice-helper nginx-dump
sudo -n /usr/local/libexec/alice-helper nginx-test
sudo -n /usr/local/libexec/alice-helper nginx-deploy --op '<op>' --cert '<cert>' --key '<key>' --expect-cert-sha256 '<sha>' --content-sha256 '<sha>'
sudo -n /usr/local/libexec/alice-helper nginx-restore --op '<op>'
sudo -n /usr/local/libexec/alice-helper nginx-status --op '<op>'
/usr/local/libexec/alice-helper tls-probe --addr '<ip>' --port '<n>' --sni '<name>' --key-type '<t>'
```

The `nginx` sudoers profile (replaces `sudoersNginxOnly` in `setup.go`; the `linux` profile is unchanged):

```
Cmnd_Alias ALICE_NGINX_ONLY = \
    /usr/local/libexec/alice-helper nginx-dump, \
    /usr/local/libexec/alice-helper nginx-test, \
    /usr/local/libexec/alice-helper nginx-deploy --op * --cert /* --key /* --expect-cert-sha256 * --content-sha256 *, \
    /usr/local/libexec/alice-helper nginx-restore --op *, \
    /usr/local/libexec/alice-helper nginx-status --op *
```

A sudo refusal of an `nginx-*` subcommand (exit 1, not a helper exit) on a session whose `sshd-dump` succeeded is the missing `nginx` profile: the `nginx` provider reports `nginx.profile_missing` with params `subcommand`, `profile=nginx` (F-14).

### `nginxconf` (`internal/providers/nginx/nginxconf`, Task 3)

```go
const (
	MaxInput = 20 << 20 // equal to helperproto.MaxNginxConfig
	MaxDepth = 100
	MaxLine  = 1 << 20
)

var (
	ErrTooLarge    = errors.New("nginxconf: the configuration dump is larger than 20 MiB")
	ErrTooDeep     = errors.New("nginxconf: blocks are nested deeper than 100 levels")
	ErrLineTooLong = errors.New("nginxconf: a line is longer than 1 MiB")
	ErrSyntax      = errors.New("nginxconf: unbalanced braces or an unterminated directive or string")
)

// Reasons a pair is not supported (also providers.Unsupported*).
const (
	ReasonVariable       = "variable"
	ReasonDataValue      = "data_value"
	ReasonEngineKey      = "engine_key"
	ReasonKeyMissing     = "key_missing"
	ReasonPasswordFile   = "password_file"
	ReasonPathNotAllowed = "path_not_allowed"
	ReasonStream         = "stream"
	ReasonCombinedFile   = "combined_file"
)

type Listen struct {
	Addr          string // "" = any
	Port          int
	SSL           bool
	DefaultServer bool
}

type Pair struct {
	Cert, Key       string // cleaned absolute paths; "" when unsupported for a path reason
	CertRaw, KeyRaw string // the directive arguments as written
	Inherited       bool   // either path came from the http block
	Unsupported     string
}

type Server struct {
	File    string // configuration file of the server block ("" before the first marker)
	Line    int    // line of "server" within that file (1-based)
	Names   []string
	Listens []Listen // every listen (Listen.SSL marks the SSL ones; "ssl on;" sets SSL on all)
	Pairs   []Pair
	Stream  bool
}

type Config struct {
	Servers  []Server // only servers with at least one SSL listen and at least one certificate
	Files    []string // "# configuration file <path>:" markers in order
	Warnings []string // helperproto.WarnStreamTLS
}

func Parse(dump []byte, confDir string) (Config, error)
func (c Config) HasPair(cert, key string) bool // a supported, non-stream pair with exactly these paths
func (c Config) CertPaths() []string           // distinct certificate paths of supported pairs, in order
func (c Config) KeyPaths() []string            // distinct key paths of supported pairs, in order
func SSLListens(s Server) []Listen             // the listens of s that serve TLS
```

### `certs` (`internal/certs`, Task 2)

```go
const MaxInputSize = 256 << 10 // per PEM field and for a PFX file

var (
	ErrInvalid        = errors.New("certs: not a certificate Alice can read")
	ErrKeyMismatch    = errors.New("certs: the private key does not belong to any of the certificates")
	ErrExpired        = errors.New("certs: the certificate has expired")
	ErrKeyEncrypted   = errors.New("certs: the private key is protected with a password")
	ErrPFXPassword    = errors.New("certs: the PFX password is wrong or the file is damaged")
	ErrWeak           = errors.New("certs: weak key or signature")
	ErrUnsupportedKey = errors.New("certs: only RSA and ECDSA (P-256, P-384) keys are supported")
	ErrNoKey          = errors.New("certs: no private key was given")
	ErrTooLarge       = errors.New("certs: the input is larger than 256 KiB")
	ErrCSRMismatch    = errors.New("certs: the certificate was not issued for this signing request's key")
)

type Parsed struct {
	Leaf            *x509.Certificate
	Chain           []*x509.Certificate // after the leaf, in issuing order
	PEMChain        string              // leaf then chain, re-encoded as CERTIFICATE blocks
	Fingerprint     string              // hex SHA-256 of the leaf DER
	Algorithm       string              // "rsa" | "ecdsa" | "ed25519" | "other"
	Bits            int                 // RSA modulus bits, ECDSA curve bits (256, 384)
	PublicKeySHA256 string              // hex SHA-256 of the leaf's PKIX public key
	SubjectCN       string
	Subject, Issuer string              // RFC 2253 strings
	Serial          string              // the serial number as upper-case hex without separators (fmt.Sprintf("%X", serial))
	SANs            []string            // DNS names then IP addresses, as text
	NotBefore       time.Time
	NotAfter        time.Time
	SelfSigned      bool
}

type Validated struct {
	Parsed
	PrivateKeyDER secrets.Plaintext // PKCS#8; the caller zeroes it
	ChainComplete bool
	Warnings      []string // "not_yet_valid", "chain_incomplete"
}

type Upload struct {
	CertificatePEM []byte
	PrivateKeyPEM  []byte
	PFX            []byte
	PFXPassword    string
}

type CSRRequest struct {
	CommonName string
	SANs       []string
	KeyType    string // "ecdsa-p256" | "rsa-3072" | "rsa-4096"
}

type KeyInfo struct {
	Algorithm       string // "rsa" | "ecdsa"
	Bits            int
	PublicKeySHA256 string
}

func ParseChainPEM(data []byte) (Parsed, error)                                            // CERTIFICATE blocks only, first = leaf
func ValidateUpload(u Upload, now time.Time, roots *x509.CertPool) (Validated, error)
func ValidateSigned(certPEM []byte, key KeyInfo, now time.Time, roots *x509.CertPool) (Parsed, bool, error) // CSR completion; bool = chain complete
func NewCSR(rnd io.Reader, r CSRRequest) (csrPEM string, keyDER secrets.Plaintext, info KeyInfo, err error)
func KeyPEM(der secrets.Plaintext) (secrets.Plaintext, error)  // PKCS#8 DER -> "PRIVATE KEY" PEM
func KeyInfoOf(der secrets.Plaintext) (KeyInfo, error)
func ChainComplete(p Parsed, roots *x509.CertPool, now time.Time) bool
func SystemRoots() *x509.CertPool // x509.SystemCertPool(), or an empty pool when the system has none
func SANMatches(sans []string, name string) bool // RFC 6125 wildcard matching of one left-most label
func ValidDNSName(s string) bool                 // for CSR names: 1..253, labels [a-z0-9-] (an optional leading "*." label)
```

### Package `alice/internal/providers` (Tasks 1, 8)

Additions to `types.go` (Task 1 adds only `UID0Users`; Task 7 adds `Accounts`, `AccountsComplete`; Task 8 adds the rest):

```go
// DiscoverRequest selects what Discover reads.
type DiscoverRequest struct{ SSHKeys, Certificates bool }

// DiscoveryResult gains:
//	UID0Users        []string                // listed accounts with uid 0 (Task 1)
//	Accounts         []string                // every /etc/passwd account name (Task 7)
//	AccountsComplete bool                    // Accounts is the whole list (Task 7)
//	Certificates     []DiscoveredCertificate // Task 8
//	Nginx            *NginxFacts             // nil when certificates were not read

// ConnectionReport gains:
//	Nginx *NginxFacts // nil for linuxssh

// NginxFacts is what Alice shows about Nginx on a server.
type NginxFacts struct {
	Version     string `json:"version"`
	ConfPath    string `json:"conf_path"`
	ConfigValid bool   `json:"config_valid"`
	ConfigError string `json:"config_error"`
	Found       bool   `json:"found"`
}

// DiscoveredCertificate is one certificate file Nginx uses.
type DiscoveredCertificate struct {
	Location   CertLocation
	PEMChain   []byte // CERTIFICATE blocks of the file in file order; empty when Location.Problem != ""
	FileSHA256 string
}

// CertLocation is a certificate/key file pair of an Nginx server and the server blocks using it.
type CertLocation struct {
	CertPath         string
	KeyPath          string
	ResolvedCertPath string
	Servers          []CertServer
	Inherited        bool
	Symlinked        bool
	CustomLocation   bool // resolved outside /etc/ssl, /etc/nginx, /etc/pki, /etc/letsencrypt
	Supported        bool
	Unsupported      string // Unsupported* reason when !Supported
	Problem          string // CertProblem* code of the certificate file
	KeyExists        bool
	KeyMode          string
	KeyOwner         string
	KeyProblem       string // CertProblem* code of the key file
	Warnings         []string
	FreeBytes        int64
}

// CertServer is one server block using a location (only its SSL listens).
type CertServer struct {
	Names   []string     `json:"names"`
	Listens []CertListen `json:"listens"`
	File    string       `json:"file"`
	Line    int          `json:"line"`
}

// CertListen is one SSL listen of a server block.
type CertListen struct {
	Addr          string `json:"addr"`
	Port          int    `json:"port"`
	DefaultServer bool   `json:"default_server"`
}

// Unsupported reasons (nginxconf's plus the ones the provider and inventory add).
const (
	UnsupportedVariable       = "variable"
	UnsupportedDataValue      = "data_value"
	UnsupportedEngineKey      = "engine_key"
	UnsupportedKeyMissing     = "key_missing"
	UnsupportedPasswordFile   = "password_file"
	UnsupportedPathNotAllowed = "path_not_allowed"
	UnsupportedStream         = "stream"
	UnsupportedCombinedFile   = "combined_file"
	UnsupportedKeyConflict    = "key_conflict"    // one certificate file used with different key files
	UnsupportedFile           = "file_problem"    // see Problem / KeyProblem
	UnsupportedKeyType        = "unsupported_key" // the certificate is not RSA or ECDSA (set by inventory)
)

// Certificate file problems (helperproto.File* plus key problems).
const (
	CertProblemMissing           = "missing"
	CertProblemNotRootControlled = "not_root_controlled"
	CertProblemNotRegular        = "not_regular"
	CertProblemHardLinked        = "hard_linked"
	CertProblemTooLarge          = "too_large"
	CertProblemNotACertificate   = "not_a_certificate"
	CertProblemUnreadable        = "unreadable"
	CertProblemBadName           = "bad_name"
)

// Location warnings.
const (
	WarnKeyModeOpen    = "key_mode_open"   // key file mode allows more than 0640
	WarnSymlinked      = "symlinked"       // another tool (certbot) may replace the file
	WarnCustomLocation = "custom_location"
)

// VerifyOptions are a location's verification settings (Administrator, R38 item 6).
type VerifyOptions struct {
	Port int    // 0 = the ports of the SSL listens
	SNI  string // "" = derived from server_name and the certificate (spec §12.8 item 1)
	Skip bool
}

// DeployRequest asks for one deployment of a certificate file pair (spec §6.3).
type DeployRequest struct {
	OperationID      uuid.UUID // = deployment id = the helper's operation id
	Location         CertLocation
	ExpectCertSHA256 string            // the certificate file's SHA-256 from the last discovery
	CertificatePEM   []byte            // leaf first, then the chain (public)
	PrivateKeyPEM    secrets.Plaintext // the caller zeroes it after the call
	Fingerprint      string            // hex SHA-256 of the new leaf
	SANs             []string
	KeyType          string // "rsa" | "ecdsa"
	OldFingerprint   string // served before the change ("" when verification is skipped)
	OldSANs          []string
	Verify           VerifyOptions
}

// DeployResult is how a deployment ended on the server.
type DeployResult string

// Deploy results.
const (
	DeployCommitted      DeployResult = "committed"       // new files live and verified
	DeployUnchanged      DeployResult = "unchanged"       // the files already held this certificate
	DeployNoChange       DeployResult = "no_change"       // refused or failed before anything changed
	DeployRolledBack     DeployResult = "rolled_back"     // changed, failed, previous files restored and verified
	DeployRollbackFailed DeployResult = "rollback_failed" // changed, failed, and the restore did not finish
	DeployUncertain      DeployResult = "uncertain"       // the connection was lost: read the outcome with DeploymentStatus
)

// DeployOutcome is the result of DeployCertificate.
type DeployOutcome struct {
	Result     DeployResult
	FailedStep string
	Reason     string // stable reason (ALC code) when Result is not committed/unchanged
	Params     map[string]string
	Verified   string // "remote" | "local" | "skipped" | ""
	Backup     BackupRef
}

// BackupRef is persisted in deployments.rollback_info before the first change (spec §6.3 item 3).
type BackupRef struct {
	OperationID uuid.UUID `json:"operation_id"`
	Dir         string    `json:"dir,omitempty"`
}

// RollbackRequest restores the files an operation replaced and checks the old certificate.
type RollbackRequest struct {
	OperationID    uuid.UUID
	Location       CertLocation
	OldFingerprint string
	OldSANs        []string
	KeyType        string
	Verify         VerifyOptions
}

// RollbackOutcome is the result of RollbackDeployment.
type RollbackOutcome struct {
	Result   DeployResult // DeployRolledBack, DeployRollbackFailed, DeployNoChange (nothing to restore) or DeployUncertain
	Reason   string
	Verified string
}

// VerifyRequest checks which certificate the location's websites serve.
type VerifyRequest struct {
	Location            CertLocation
	Fingerprint         string // expected leaf; "" = report what is served
	PreviousFingerprint string // the leaf served before the change: a mismatch equal to it is verify_failed (F-05), another is verify_other (F-06)
	SANs                []string
	KeyType             string
	Verify              VerifyOptions
}

// VerifyResult is the result of VerifyDeployment.
type VerifyResult struct {
	OK     bool
	Mode   string // "remote" | "local" | "skipped"
	Served string // the fingerprint served (first mismatching endpoint, or the first endpoint when Fingerprint == "")
	Reason string // "deployment.verify_failed" | "deployment.verify_other" | "deployment.verify_unreachable"
	Params map[string]string
}

// Deployment phases of DeploymentState (the nginx provider reports the helper journal's phases,
// whose names are the same: a test in Task 11 compares them with helperproto.Phase*). jobs may not
// import helperproto (archtest), so the engine uses these.
const (
	PhaseNone          = "none"
	PhasePrepared      = "prepared"
	PhaseWriting       = "writing"
	PhaseCommitted     = "committed"
	PhaseUnchanged     = "unchanged"
	PhaseRestoring     = "restoring"
	PhaseRestored      = "restored"
	PhaseRestoreFailed = "restore_failed"
)

// DeploymentState is what the server knows about an operation (helper journal).
type DeploymentState struct {
	Phase             string // Phase*
	Active            bool
	NewCertSHA256     string
	CurrentCertSHA256 string
	BackupDir         string
}
```

`Session` gains four methods (and `UnsupportedSession` stubs answering `ErrUnsupported`):

```go
DeployCertificate(ctx context.Context, req DeployRequest, log StepLogger) (DeployOutcome, error)   // CapDeployCertificate
RollbackDeployment(ctx context.Context, req RollbackRequest, log StepLogger) (RollbackOutcome, error) // CapDeployCertificate
DeploymentStatus(ctx context.Context, op uuid.UUID) (DeploymentState, error)                       // CapDeployCertificate
VerifyDeployment(ctx context.Context, req VerifyRequest) (VerifyResult, error)                     // CapVerifyDeployment
```

Contract (in addition to spec §6.3): `DeployCertificate` never returns a non-nil error together with a change it knows about: a known change is an outcome; a transport failure after the request was sent is `DeployUncertain` with the error. Step names reported to the `StepLogger`, in order: `backup`, `write_key`, `write_cert`, `config_test`, `reload` (from the helper), `verify` (provider), and on a rollback `restore`, `rollback_config_test`, `rollback_reload`, `verify_old`. Step params are allowlisted primitives (`error`, `port`, `mode`, `served`).

### Package `alice/internal/providers/nginx` (Tasks 10, 11)

```go
// Prober probes a TLS endpoint from Alice (production: a crypto/tls dial).
type Prober interface {
	Probe(ctx context.Context, host string, port int, sni, keyType string) (Probe, error)
}

// Probe is one TLS answer.
type Probe struct {
	LeafSHA256  string
	ChainLength int
	NotAfter    time.Time
}

// ErrProbeUnreachable wraps every connection failure of a probe (dial, refused, timeout before the
// handshake); other failures (handshake refused) are ErrProbeFailed.
var (
	ErrProbeUnreachable = errors.New("nginx: the endpoint cannot be reached")
	ErrProbeFailed      = errors.New("nginx: the TLS handshake failed")
)

type Options struct {
	SSH        *linuxssh.Provider
	Prober     Prober        // nil = TLSProber{}
	RetryWait  time.Duration // between verification attempts; 0 = 2 s
	Attempts   int           // verification attempts per endpoint; 0 = 5
}

func New(o Options) *Provider // Kind nginx; caps: test_connection, discover_ssh_keys, authorized_keys,
                              // discover_certificates, deploy_certificate, verify_deployment
type TLSProber struct{ DialTimeout time.Duration } // 0 = 5 s; handshake 10 s

func SNIFor(names, sans []string) string          // spec §12.8 item 1 (contract below)
func Endpoints(loc providers.CertLocation, v providers.VerifyOptions, sans []string) []Endpoint // at most 10
type Endpoint struct {
	Port int
	SNI  string
	Addr string // the listen address for the local probe ("" = 127.0.0.1)
}
```

`SNIFor` rules: the first `names` entry that is not `""`, not `_`, does not start with `~` and has no `*` except a leading `*.`: `*.example.com` → `alice-check.example.com`, `.example.com` → `example.com`, otherwise the name itself; if none qualifies, the same rules over `sans`; else `""`.

### Package `alice/internal/inventory` (Tasks 1, 13, 14, 15)

```go
// Task 1
// Facts gains: UID0Users []string `json:"uid0_users,omitempty"`
// SSHKey gains: Missing bool (every matched location is missing or removed)

// Task 13
// Facts gains: Nginx *providers.NginxFacts `json:"nginx,omitempty"`
// NewTarget.Type accepts "linux" and "nginx".
const (
	TypeLinux = "linux"
	TypeNginx = "nginx"
)

type CertificateRef struct {
	ID          uuid.UUID
	SubjectCN   string
	Label       string
	Fingerprint string
	NotAfter    time.Time
}

type Certificate struct {
	ID            uuid.UUID
	Fingerprint   string
	SubjectCN     string
	Subject       string
	Issuer        string
	Serial        string
	SANs          []string
	NotBefore     time.Time
	NotAfter      time.Time
	KeyAlgorithm  string
	KeyBits       int
	PEMChain      string
	ChainComplete bool
	SelfSigned    bool
	Source        string
	Label         string
	HasPrivateKey bool
	LocationCount int
	FirstSeenAt   time.Time
	LastSeenAt    time.Time
	Locations     []CertificateLocation // GetCertificate only
}

type CertificateLocation struct {
	ID                  uuid.UUID
	TargetID            uuid.UUID
	TargetName          string
	CertPath            string
	KeyPath             string
	KeyType             string
	Certificate         *CertificateRef
	Servers             []providers.CertServer
	Supported           bool
	UnsupportedReason   string
	Problem             string
	Inherited           bool
	CustomLocation      bool
	Symlinked           bool
	CertFileSHA256      string
	KeyExists           bool
	KeyMode             string
	KeyOwner            string
	Warnings            []string
	DeployedFingerprint string
	ChangedOutsideAt    *time.Time
	VerifyPort          *int
	VerifySNI           string
	SkipVerify          bool
	FirstSeenAt         time.Time
	LastSeenAt          time.Time
	MissingSince        *time.Time
	Version             int
	ActiveDeploymentID  *uuid.UUID
}

type CertificateFilter struct {
	TargetID uuid.UUID
	Source   string // "" | "discovered" | "uploaded" | "csr"
	Query    string
	Expiry   string // "" | "expired" | "30" | "60"
	Cursor   string
	Limit    int // 1..200, default 50
}

type CertificatePage struct {
	Items      []Certificate
	NextCursor string
}

// ReconcileSummary gains: Certificates, Locations, NewLocations, MissingLocations int

func (s *Service) ListCertificates(ctx context.Context, f CertificateFilter) (CertificatePage, error)
func (s *Service) GetCertificate(ctx context.Context, id uuid.UUID) (Certificate, error)
func (s *Service) ListLocations(ctx context.Context, targetID uuid.UUID, includeMissing bool) ([]CertificateLocation, error)
func (s *Service) GetLocation(ctx context.Context, id uuid.UUID) (CertificateLocation, error)

// Task 14
type UploadInput struct {
	CertificatePEM string
	PrivateKeyPEM  string
	PFXBase64      string
	PFXPassword    string
	Label          string
}

type CSRInput struct {
	CommonName string
	SANs       []string
	KeyType    string // "ecdsa-p256" | "rsa-3072" | "rsa-4096"
}

type CSR struct {
	ID            uuid.UUID
	CommonName    string
	SANs          []string
	KeyAlgorithm  string
	KeyBits       int
	CSRPEM        string
	Status        string
	CertificateID *uuid.UUID
	CreatedAt     time.Time
	FinishedAt    *time.Time
}

type LocationPatch struct {
	VerifyPort *int    // 0 clears
	VerifySNI  *string // "" clears
	SkipVerify *bool
}

func (s *Service) UploadCertificate(ctx context.Context, a Actor, in UploadInput) (Certificate, []string, error)
func (s *Service) CreateCSR(ctx context.Context, a Actor, in CSRInput) (CSR, error)
func (s *Service) ListCSRs(ctx context.Context) ([]CSR, error)
func (s *Service) GetCSR(ctx context.Context, id uuid.UUID) (CSR, error)
func (s *Service) CompleteCSR(ctx context.Context, a Actor, id uuid.UUID, certificatePEM, label string) (Certificate, []string, error)
func (s *Service) CancelCSR(ctx context.Context, a Actor, id uuid.UUID) (CSR, error)
func (s *Service) UpdateLocation(ctx context.Context, a Actor, id uuid.UUID, ifVersion int, p LocationPatch) (CertificateLocation, error)

// Errors (Task 14): the api errorMap maps them to the codes of the error table. The upload and
// CSR errors are the certs package's sentinels re-exported (api may not import certs).
var (
	ErrCertificateDuplicate = errors.New("inventory: Alice already holds this certificate with its key")
	ErrCSRNotPending        = errors.New("inventory: the signing request is no longer open")
	ErrLocationUnsupported  = errors.New("inventory: certificates cannot be deployed to this location")
	ErrCertificateInvalid   = certs.ErrInvalid
	ErrKeyMismatch          = certs.ErrKeyMismatch
	ErrCertificateExpired   = certs.ErrExpired // also returned by RequestDeployment (Task 15)
	ErrKeyEncrypted         = certs.ErrKeyEncrypted
	ErrPFXPassword          = certs.ErrPFXPassword
	ErrWeakCertificate      = certs.ErrWeak
	ErrUnsupportedKey       = certs.ErrUnsupportedKey
	ErrCSRMismatch          = certs.ErrCSRMismatch
	ErrCertificateTooLarge  = certs.ErrTooLarge
)

// Task 15
const (
	JobCertificateDeploy = "certificate.deploy"
	JobDeployRecover     = "certificate.deploy_recover"
)

const (
	DeployStateQueued     = "queued"
	DeployStatePrecheck   = "precheck"
	DeployStateDeploying  = "deploying"
	DeployStateRecovering = "recovering"
	DeployStateDone       = "done"
)

const (
	DeployStatusPending        = "pending"
	DeployStatusRunning        = "running"
	DeployStatusSucceeded      = "succeeded"
	DeployStatusUnchanged      = "unchanged"
	DeployStatusFailed         = "failed"
	DeployStatusRolledBack     = "rolled_back"
	DeployStatusRollbackFailed = "rollback_failed"
	DeployStatusNeedsAttention = "needs_attention"
)

// Email templates (also in Templates()).
const (
	TemplateDeploymentFailed         = "deployment.failed"          // params target_name, cert_path, deployment_id
	TemplateDeploymentRollbackFailed = "deployment.rollback_failed" // params target_name, cert_path, deployment_id, backup_dir
	TemplateDeploymentNeedsAttention = "deployment.needs_attention" // params target_name, cert_path, deployment_id
)

type DeployRequestInput struct {
	CertificateID          uuid.UUID
	LocationIDs            []uuid.UUID // 1..20
	ConfirmIncompleteChain bool
}

type RequestedDeployment struct {
	ID         uuid.UUID
	JobID      uuid.UUID
	LocationID uuid.UUID
	Warnings   []string // "san_mismatch"
}

type DeploymentStep struct {
	N      int
	Name   string
	Status string
	At     time.Time
	Params map[string]string
}

type Deployment struct {
	ID                  uuid.UUID
	CertificateID       uuid.UUID
	CertificateName     string // label, else subject CN, else fingerprint prefix
	LocationID          uuid.UUID
	TargetID            uuid.UUID
	TargetName          string
	CertPath            string
	KeyPath             string
	JobID               *uuid.UUID
	Trigger             string
	RequestedBy         *uuid.UUID
	RequestedByName     string
	State               string
	Status              string
	NewFingerprint      string
	PreviousFingerprint string
	ConfirmIncompleteChain bool
	Backup              *providers.BackupRef
	Verified            string
	ErrorCode           string
	ErrorParams         map[string]string
	FailedStep          string
	CreatedAt           time.Time
	StartedAt           *time.Time
	FinishedAt          *time.Time
	Steps               []DeploymentStep // Deployment(...) only
}

type DeploymentFilter struct {
	TargetID      uuid.UUID
	CertificateID uuid.UUID
	LocationID    uuid.UUID
	Cursor        string
	Limit         int
}

type DeploymentPage struct {
	Items      []Deployment
	NextCursor string
}

// Material is what a deploy job needs; PrivateKeyPEM is empty unless withKey.
type Material struct {
	Deployment         Deployment
	Location           providers.CertLocation
	CertificatePEM     []byte
	PrivateKeyPEM      secrets.Plaintext
	Fingerprint        string    // the new leaf
	SANs               []string  // the new leaf's
	NotAfter           time.Time // the new leaf's
	KeyType            string    // "rsa" | "ecdsa" (the new leaf's algorithm)
	CurrentFingerprint string    // the leaf in the location's file at the last discovery ("" when unknown)
	OldSANs            []string  // that leaf's SANs (SNI for default servers when checking the old certificate)
	ExpectCertSHA256   string    // the certificate file's SHA-256 at the last discovery
	Verify             providers.VerifyOptions
	ConfigValid        bool
}

type DeploymentFinish struct {
	Status     string // a terminal status
	ErrorCode  string
	Params     map[string]string
	FailedStep string
	Verified   string
	Backup     *providers.BackupRef
}

var (
	ErrDeploymentInProgress   = errors.New("inventory: another deployment to this location is in progress")
	ErrRecoveryPending        = errors.New("inventory: an earlier deployment on this server is being recovered")
	ErrNoPrivateKey           = errors.New("inventory: Alice does not hold this certificate's private key")
	ErrKeyTypeMismatch        = errors.New("inventory: the certificate's key type does not fit the location")
	ErrChainUnconfirmed       = errors.New("inventory: an Administrator must confirm the incomplete chain")
	ErrNginxConfigInvalid     = errors.New("inventory: the server's Nginx configuration has an error")
	ErrTargetNotReady         = errors.New("inventory: the server is not connected")
)

func (s *Service) RequestDeployment(ctx context.Context, a Actor, in DeployRequestInput) ([]RequestedDeployment, error)
func (s *Service) Deployment(ctx context.Context, id uuid.UUID) (Deployment, error)
func (s *Service) ListDeployments(ctx context.Context, f DeploymentFilter) (DeploymentPage, error)
func (s *Service) DeploymentMaterial(ctx context.Context, id uuid.UUID, withKey bool) (Material, error)
func (s *Service) BeginDeployment(ctx context.Context, id uuid.UUID) (Deployment, error) // queued -> precheck (idempotent)
func (s *Service) StartDeployment(ctx context.Context, id uuid.UUID, previousFingerprint string, backup providers.BackupRef) error
func (s *Service) RecordDeploymentStep(ctx context.Context, id uuid.UUID, name string, status providers.StepStatus, params map[string]string) error
func (s *Service) FinishDeployment(ctx context.Context, id uuid.UUID, f DeploymentFinish) error
func (s *Service) MarkRecovering(ctx context.Context, id uuid.UUID, retryAt time.Time, needsAttention bool) error
func (s *Service) RequestRecovery(ctx context.Context, id uuid.UUID) (uuid.UUID, error)
func (s *Service) SweepDeployments(ctx context.Context) (int, error)
```

### Package `alice/internal/jobs` (Task 15) and `jobs/deployjobs` (Task 16)

```go
// internal/jobs/types.go
var (
	CertificateDeploy       = Register(inventory.JobCertificateDeploy, license.ClassChange)
	CertificateDeployRecover = Register(inventory.JobDeployRecover, license.ClassAlways)
	DeploymentRecoverySweep = Register("deployment.recovery_sweep", license.ClassAlways)
)
// MaxAttemptsFor: certificate.deploy 3, certificate.deploy_recover 5.

// internal/jobs/deployjobs
type Inventory interface {
	TargetRef(ctx context.Context, id uuid.UUID) (providers.TargetRef, inventory.Target, error)
	Credentials() providers.CredentialSource
	HostKeyStore() providers.HostKeyStore
	RecordConnectionFailure(ctx context.Context, id uuid.UUID, reason string) error
	Deployment(ctx context.Context, id uuid.UUID) (inventory.Deployment, error)
	DeploymentMaterial(ctx context.Context, id uuid.UUID, withKey bool) (inventory.Material, error)
	BeginDeployment(ctx context.Context, id uuid.UUID) (inventory.Deployment, error)
	StartDeployment(ctx context.Context, id uuid.UUID, previousFingerprint string, backup providers.BackupRef) error
	RecordDeploymentStep(ctx context.Context, id uuid.UUID, name string, status providers.StepStatus, params map[string]string) error
	FinishDeployment(ctx context.Context, id uuid.UUID, f inventory.DeploymentFinish) error
	MarkRecovering(ctx context.Context, id uuid.UUID, retryAt time.Time, needsAttention bool) error
	RequestRecovery(ctx context.Context, id uuid.UUID) (uuid.UUID, error)
}

type Deps struct {
	Inventory Inventory
	Registry  *providers.Registry
	Clock     clock.Clock
	Log       *slog.Logger
	// RecoverAfter is the delay before an uncertain deployment's first recovery and between
	// recoveries of an unreachable server; zero = 10 s and 15 min.
	FirstRecovery, RetryRecovery time.Duration
}

func Register(r *jobs.Runner, d Deps) // certificate.deploy, certificate.deploy_recover
```

### API (Task 17)

| Method and path | Permission | Lock class | Body / answer |
|---|---|---|---|
| `GET /api/v1/certificates` | `read` | — | `?target_id&source&q&expiry&cursor&limit` → `{items: [certificate], next_cursor}` |
| `GET /api/v1/certificates/{id}` | `read` | — | certificate with `pem_chain` and `locations` |
| `POST /api/v1/certificates/upload` | `certificates.operate` | change | `{label?, certificate_pem?, private_key_pem?, pfx_base64?, pfx_password?}` → 201 `{certificate, warnings}` |
| `POST /api/v1/certificates/{id}/deploy` | `certificates.operate` | change | `{location_ids: [uuid] (1..20), confirm_incomplete_chain?: bool}` → 202 `{deployments: [{id, job_id, location_id, status_url, warnings}]}` |
| `GET /api/v1/certificates/csr` | `read` | — | `{items: [csr]}` (pending first, then the 50 newest finished) |
| `POST /api/v1/certificates/csr` | `certificates.operate` | change | `{common_name, sans?: [string] (≤ 50), key_type}` → 201 csr |
| `GET /api/v1/certificates/csr/{id}` | `read` | — | csr |
| `POST /api/v1/certificates/csr/{id}/actions/complete` | `certificates.operate` | change | `{certificate_pem, label?}` → 201 `{certificate, warnings}` |
| `POST /api/v1/certificates/csr/{id}/actions/cancel` | `certificates.operate` | change | → 200 csr |
| `GET /api/v1/targets/{id}/certificate-locations` | `read` | — | `?missing=true` → `{items: [location]}` |
| `PATCH /api/v1/locations/{id}` | `targets.manage` | change | `If-Match: "<version>"`; `{verify_port?: int (0 clears), verify_sni?: string ("" clears), skip_verify?: bool}` → location |
| `GET /api/v1/deployments` | `read` | — | `?target_id&certificate_id&location_id&cursor&limit` → `{items: [deployment], next_cursor}` |
| `GET /api/v1/deployments/{id}` | `read` | — | deployment with `steps` |

`certificates.operate` policy: `{Roles: [Admin, Operator], TokenScope: ScopeOperate}` (same matrix row as `inventory.operate`). `routeRuleViolations` gains: non-GET under `/api/v1/certificates` → `certificates.operate`; non-GET under `/api/v1/locations` → `targets.manage`; GET under `/api/v1/certificates`, `/api/v1/locations`, `/api/v1/deployments` → `read`. DTO field names (JSON, snake_case): certificate `{id, fingerprint, subject_cn, subject, issuer, serial, sans, not_before, not_after, key_algorithm, key_bits, source, label, has_private_key, chain_complete, self_signed, location_count, first_seen_at, last_seen_at, pem_chain?, locations?}`; location `{id, target_id, target_name, cert_path, key_path, key_type, certificate: {id, subject_cn, label, fingerprint, not_after} | null, servers: [{names, listens: [{addr, port, default_server}], file, line}], supported, unsupported_reason, problem, inherited, custom_location, symlinked, key_exists, key_mode, key_owner, warnings, deployed_fingerprint, changed_outside_at, verify_port, verify_sni, skip_verify, first_seen_at, last_seen_at, missing_since, version, active_deployment_id}`; deployment `{id, certificate_id, certificate_name, location_id, target_id, target_name, cert_path, job_id, trigger, state, status, new_fingerprint, previous_fingerprint, verified, error: {code, reason, params} | null, failed_step, backup_dir, requested_by, requested_by_name, created_at, started_at, finished_at, steps?: [{n, name, status, at, params}]}`; csr `{id, common_name, sans, key_algorithm, key_bits, csr_pem, status, certificate_id, created_at, finished_at}`. `providerParamKeys` gains `port`, `failed_step`, `profile`, `phase`.

### Error codes (Tasks 15, 17; EN and TR texts exact)

| Code | Reason | HTTP | Retry | EN title / cause / action | TR title / cause / action |
|---|---|---|---|---|---|
| ALC-NGX-0001 | `nginx.not_found` | 502 | no | Nginx was not found on this server. / Alice looked for /usr/sbin/nginx, where the standard packages install it. / Install Nginx from your distribution or nginx.org, or add this server as a Linux server. | Bu sunucuda Nginx bulunamadı. / Alice, standart paketlerin kurduğu /usr/sbin/nginx dosyasını aradı. / Nginx'i dağıtımınızdan veya nginx.org'dan kurun ya da bu sunucuyu Linux sunucu olarak ekleyin. |
| ALC-NGX-0002 | `nginx.config_invalid` | 409 | no | Nginx's configuration already has an error, so Alice will not make it worse. / The command nginx -t fails on this server before Alice changed anything. / Run nginx -t on the server, fix the error, then choose Discover again. | Nginx yapılandırmasında zaten bir hata var, bu yüzden Alice durumu daha kötüleştirmeyecek. / Alice hiçbir şeyi değiştirmeden önce nginx -t komutu bu sunucuda başarısız oluyor. / Sunucuda nginx -t komutunu çalıştırın, hatayı giderin, sonra Keşfet'i yeniden seçin. |
| ALC-NGX-0003 | `nginx.config_changed` | 409 | no | The Nginx configuration changed since Alice last looked. / This website no longer uses the certificate and key files Alice found. / Choose Discover on the server's page, then deploy again. | Alice son baktığından bu yana Nginx yapılandırması değişti. / Bu web sitesi artık Alice'in bulduğu sertifika ve anahtar dosyalarını kullanmıyor. / Sunucunun sayfasında Keşfet'i seçin, sonra yeniden dağıtın. |
| ALC-NGX-0004 | `nginx.profile_missing` | 502 | no | This server is not prepared for Nginx work. / The Alice account may run alice-helper for SSH keys only (Linux profile), not for certificates. / On the Servers page choose Server type Nginx server, copy the commands and run them on the server again. | Bu sunucu Nginx işleri için hazırlanmamış. / Alice hesabı alice-helper'ı sertifikalar için değil, yalnızca SSH anahtarları için çalıştırabiliyor (Linux profili). / Sunucular sayfasında Sunucu türü olarak Nginx sunucu seçeneğini seçin, komutları kopyalayın ve sunucuda yeniden çalıştırın. |
| ALC-NGX-0005 | `nginx.no_space` | 502 | no | The server has no free disk space. / Alice needs room for the new files and a backup of the old ones. Nothing was changed. / Free some space on the server, then deploy again. | Sunucuda boş disk alanı yok. / Alice'in yeni dosyalar ve eski dosyaların yedeği için yere ihtiyacı var. Hiçbir şey değiştirilmedi. / Sunucuda biraz yer açın, sonra yeniden dağıtın. |
| ALC-NGX-0006 | `nginx.file_changed` | 409 | no | The certificate file changed since Alice last looked. / Someone or another tool replaced the file after the last discovery. Nothing was changed. / Choose Discover on the server's page, check the website, then deploy again. | Alice son baktığından bu yana sertifika dosyası değişti. / Son keşiften sonra biri veya başka bir araç dosyayı değiştirdi. Hiçbir şey değiştirilmedi. / Sunucunun sayfasında Keşfet'i seçin, web sitesini denetleyin, sonra yeniden dağıtın. |
| ALC-NGX-0007 | `nginx.location_unsupported` | 409 | no | Alice cannot change certificates at this place. / The website's certificate setup is one Alice does not support; the reason is shown next to it. / Change the setup on the server if you want Alice to manage it, then choose Discover. | Alice bu konumdaki sertifikaları değiştiremez. / Web sitesinin sertifika düzeni Alice'in desteklemediği bir düzen; nedeni yanında gösterilir. / Alice'in yönetmesini istiyorsanız sunucudaki düzeni değiştirin, sonra Keşfet'i seçin. |
| ALC-NGX-0008 | `nginx.busy` | 409 | yes | Another certificate change is running on this server. / alice-helper changes one website at a time on a server. / Wait a minute and try again. | Bu sunucuda başka bir sertifika değişikliği sürüyor. / alice-helper bir sunucuda aynı anda tek bir web sitesini değiştirir. / Bir dakika bekleyip yeniden deneyin. |
| ALC-NGX-0009 | `nginx.write_failed` | 502 | no | Alice could not write the new files. Nothing was changed. / The helper could not create a file in this folder (for example a read-only file system): {{directory}} / Check that the folder is writable for root on the server, then deploy again. | Alice yeni dosyaları yazamadı. Hiçbir şey değiştirilmedi. / Yardımcı program bu klasörde dosya oluşturamadı (örneğin salt okunur bir dosya sistemi): {{directory}} / Klasörün sunucuda root için yazılabilir olduğunu denetleyin, sonra yeniden dağıtın. |
| ALC-CRT-0001 | `certificate.invalid` | 422 | no | This is not a certificate Alice can read. / Alice expects PEM text with BEGIN CERTIFICATE blocks, or a PFX file. / Check that you chose the certificate file, not a request or another file. | Bu, Alice'in okuyabildiği bir sertifika değil. / Alice, BEGIN CERTIFICATE blokları içeren PEM metni veya bir PFX dosyası bekler. / İmzalama isteğini veya başka bir dosyayı değil, sertifika dosyasını seçtiğinizden emin olun. |
| ALC-CRT-0002 | `certificate.key_mismatch` | 422 | no | The new certificate does not match its key. Nothing was changed. / The private key belongs to another certificate. / Upload the key that was created together with this certificate. | Yeni sertifika anahtarıyla eşleşmiyor. Hiçbir şey değiştirilmedi. / Özel anahtar başka bir sertifikaya ait. / Bu sertifikayla birlikte oluşturulan anahtarı yükleyin. |
| ALC-CRT-0003 | `certificate.expired` | 422 | no | This certificate has already expired. / Its validity period has ended, so browsers would refuse it. / Get a renewed certificate from your certificate authority and upload that one. | Bu sertifikanın süresi zaten doldu. / Geçerlilik süresi sona erdi, bu yüzden tarayıcılar sertifikayı reddeder. / Sertifika yetkilinizden yenilenmiş bir sertifika alın ve onu yükleyin. |
| ALC-CRT-0004 | `certificate.key_encrypted` | 422 | no | The private key is protected with a password. / Alice cannot store a key it cannot read. / Remove the password from the key, or upload a PFX file and enter its password. | Özel anahtar bir parolayla korunuyor. / Alice okuyamadığı bir anahtarı saklayamaz. / Anahtardaki parolayı kaldırın ya da bir PFX dosyası yükleyip parolasını girin. |
| ALC-CRT-0005 | `certificate.pfx_password` | 422 | no | The PFX password is wrong or the file is damaged. / Alice could not open the PFX file with this password. / Check the password, or export the PFX file again. | PFX parolası yanlış veya dosya bozuk. / Alice PFX dosyasını bu parolayla açamadı. / Parolayı denetleyin ya da PFX dosyasını yeniden dışa aktarın. |
| ALC-CRT-0006 | `certificate.weak` | 422 | no | This certificate uses a weak key or signature. / RSA keys shorter than 2048 bits and MD5 or SHA-1 signatures are no longer safe. / Ask your certificate authority for a certificate with a stronger key and a SHA-256 signature. | Bu sertifika zayıf bir anahtar veya imza kullanıyor. / 2048 bitten kısa RSA anahtarları ile MD5 veya SHA-1 imzaları artık güvenli değil. / Sertifika yetkilinizden daha güçlü anahtarlı ve SHA-256 imzalı bir sertifika isteyin. |
| ALC-CRT-0007 | `certificate.unsupported_key` | 422 | no | Alice supports RSA and ECDSA certificates only. / This certificate uses another key type (for example Ed25519) or curve. / Use an RSA (2048 bits or more) or ECDSA P-256 or P-384 certificate. | Alice yalnızca RSA ve ECDSA sertifikalarını destekler. / Bu sertifika başka bir anahtar türü (örneğin Ed25519) veya eğri kullanıyor. / RSA (2048 bit veya daha uzun) ya da ECDSA P-256 veya P-384 sertifikası kullanın. |
| ALC-CRT-0008 | `certificate.duplicate` | 409 | no | Alice already has this certificate with its key. / The same certificate and key were uploaded before. / Open the certificate in the list and deploy it from there. | Bu sertifika ve anahtarı Alice'te zaten var. / Aynı sertifika ve anahtar daha önce yüklendi. / Listede sertifikayı açın ve oradan dağıtın. |
| ALC-CRT-0009 | `certificate.no_private_key` | 409 | no | Alice does not have the private key of this certificate. / Alice found this certificate on a server, and private keys are never read from servers. / Upload the certificate together with its key, then deploy it. | Alice bu sertifikanın özel anahtarına sahip değil. / Alice bu sertifikayı bir sunucuda buldu ve özel anahtarlar sunuculardan hiçbir zaman okunmaz. / Sertifikayı anahtarıyla birlikte yükleyin, sonra dağıtın. |
| ALC-CRT-0010 | `certificate.key_type_mismatch` | 409 | no | This certificate's key type does not fit this place. / The website expects a {{expected}} certificate here; this one is {{actual}}. / Choose a certificate with the same key type, or the website's other certificate place. | Bu sertifikanın anahtar türü bu konuma uymuyor. / Web sitesi burada şu türde bir sertifika bekliyor: {{expected}}. Bu sertifikanın türü: {{actual}}. / Aynı anahtar türünde bir sertifika ya da web sitesinin diğer sertifika konumunu seçin. |
| ALC-CRT-0011 | `certificate.chain_unconfirmed` | 409 | no | An administrator must confirm the incomplete chain of this certificate. / The certificate chain does not reach a trusted root, so some browsers may not trust it. / Ask an administrator to deploy it and confirm the chain. | Bu sertifikanın eksik zincirini bir yöneticinin onaylaması gerekir. / Sertifika zinciri güvenilir bir köke ulaşmıyor, bu yüzden bazı tarayıcılar sertifikaya güvenmeyebilir. / Sertifikayı dağıtıp zinciri onaylaması için bir yöneticiye başvurun. |
| ALC-CRT-0012 | `csr.not_pending` | 409 | no | This signing request is no longer open. / It was completed or cancelled. / Create a new signing request if you need one. | Bu imzalama isteği artık açık değil. / İstek tamamlandı veya iptal edildi. / Gerekiyorsa yeni bir imzalama isteği oluşturun. |
| ALC-CRT-0013 | `csr.certificate_mismatch` | 422 | no | This certificate was not issued for this signing request. / Its public key is not the one Alice created for the request. / Paste the certificate your certificate authority returned for this request. | Bu sertifika bu imzalama isteği için düzenlenmedi. / Sertifikanın açık anahtarı, Alice'in bu istek için oluşturduğu anahtar değil. / Sertifika yetkilinizin bu istek için döndürdüğü sertifikayı yapıştırın. |
| ALC-DEP-0001 | `deployment.in_progress` | 409 | yes | Another deployment to this website is in progress. / Alice runs one deployment per certificate file at a time. / Wait until it finishes; its progress is in the deployment history. | Bu web sitesine başka bir dağıtım sürüyor. / Alice bir sertifika dosyasına aynı anda tek bir dağıtım yapar. / Bitmesini bekleyin; ilerlemesi dağıtım geçmişinde görünür. |
| ALC-DEP-0002 | `deployment.recovery_pending` | 409 | yes | Alice is still finishing an interrupted deployment on this server. / The connection was lost during an earlier deployment, and Alice must first check the server. / Wait until that deployment shows its result in the deployment history. | Alice bu sunucuda yarım kalan bir dağıtımı hâlâ tamamlıyor. / Önceki bir dağıtım sırasında bağlantı kesildi ve Alice'in önce sunucuyu denetlemesi gerekiyor. / O dağıtımın sonucu dağıtım geçmişinde görünene kadar bekleyin. |
| ALC-DEP-0003 | `deployment.verify_failed` | 502 | no | The server is still presenting the old certificate. / Nginx reloaded, but the website kept serving the previous certificate (for example another server block answers). Your server was restored to its previous certificate. / Check which server block answers for this name, then deploy again. | Sunucu hâlâ eski sertifikayı sunuyor. / Nginx yeniden yüklendi ancak web sitesi önceki sertifikayı sunmaya devam etti (örneğin başka bir server bloğu yanıt veriyor). Sunucunuz önceki sertifikasına geri döndürüldü. / Bu ad için hangi server bloğunun yanıt verdiğini denetleyin, sonra yeniden dağıtın. |
| ALC-DEP-0004 | `deployment.verify_other` | 502 | no | Alice could not confirm the new certificate. / The website served a certificate that is neither the old nor the new one, for example from a load balancer in front of it, so Alice left the previous certificate in place. / An administrator can set the port and name to check in the website's verification settings. | Alice yeni sertifikayı doğrulayamadı. / Web sitesi ne eski ne de yeni olan bir sertifika sundu, örneğin önündeki bir yük dengeleyiciden; bu yüzden Alice önceki sertifikayı yerinde bıraktı. / Bir yönetici, web sitesinin doğrulama ayarlarında denetlenecek bağlantı noktasını ve adı belirleyebilir. |
| ALC-DEP-0005 | `deployment.verify_unreachable` | 502 | no | Could not reach port {{port}} from Alice. / Alice could not connect to the website, neither directly nor from the server itself, so it could not check the certificate and left the previous one in place. / Allow Alice to reach the port, or ask an administrator to change the website's verification settings. | Alice'ten şu bağlantı noktasına erişilemedi: {{port}}. / Alice web sitesine ne doğrudan ne de sunucunun kendisinden bağlanabildi; bu yüzden sertifikayı denetleyemedi ve öncekini yerinde bıraktı. / Alice'in bu bağlantı noktasına erişmesine izin verin ya da bir yöneticiden web sitesinin doğrulama ayarlarını değiştirmesini isteyin. |
| ALC-DEP-0006 | `deployment.reload_failed` | 502 | no | Nginx did not reload. / systemctl reload nginx failed after the new files were written. Your server was restored to its previous certificate. / Run systemctl status nginx on the server to see why. | Nginx yeniden yüklenmedi. / Yeni dosyalar yazıldıktan sonra systemctl reload nginx komutu başarısız oldu. Sunucunuz önceki sertifikasına geri döndürüldü. / Nedenini görmek için sunucuda systemctl status nginx komutunu çalıştırın. |
| ALC-DEP-0007 | `deployment.config_test_failed` | 502 | no | Nginx rejected the new files. / nginx -t failed after the new certificate and key were written. Your server was restored to its previous certificate. / Check the certificate file format and the chain, then deploy again. | Nginx yeni dosyaları reddetti. / Yeni sertifika ve anahtar yazıldıktan sonra nginx -t başarısız oldu. Sunucunuz önceki sertifikasına geri döndürüldü. / Sertifika dosyasının biçimini ve zinciri denetleyin, sonra yeniden dağıtın. |
| ALC-DEP-0008 | `deployment.rollback_failed` | 502 | no | Automatic restore failed. Manual action is needed. / The deployment failed and Alice could not put the previous files back. The backup is on the server in {{backup_dir}}. / Check the website now; copy the files from the backup on the server, then run nginx -t and systemctl reload nginx. | Otomatik geri yükleme başarısız oldu. Elle müdahale gerekiyor. / Dağıtım başarısız oldu ve Alice önceki dosyaları geri koyamadı. Yedek sunucuda şu klasörde: {{backup_dir}}. / Web sitesini hemen denetleyin; dosyaları sunucudaki yedekten kopyalayın, sonra nginx -t ve systemctl reload nginx komutlarını çalıştırın. |
| ALC-DEP-0009 | `deployment.rollback_reload_failed` | 502 | no | Files are back in place but Nginx did not reload. / Alice restored the previous certificate and key, but systemctl reload nginx failed again. / Run systemctl status nginx on the server. | Dosyalar yerine geri kondu ancak Nginx yeniden yüklenmedi. / Alice önceki sertifikayı ve anahtarı geri yükledi ancak systemctl reload nginx yine başarısız oldu. / Sunucuda systemctl status nginx komutunu çalıştırın. |
| ALC-DEP-0010 | `deployment.interrupted` | 502 | no | The deployment was interrupted. / The connection to the server or Alice itself stopped during the deployment. Alice checked the server afterwards and left it with its previous certificate. / Deploy again when the server is reachable. | Dağıtım yarıda kesildi. / Dağıtım sırasında sunucuyla bağlantı veya Alice'in kendisi durdu. Alice sonrasında sunucuyu denetledi ve sunucuyu önceki sertifikasıyla bıraktı. / Sunucuya erişilebildiğinde yeniden dağıtın. |
| ALC-DEP-0011 | `deployment.target_not_ready` | 409 | no | Alice cannot deploy to this server now. / The server is not connected (its status is not Connected), or its fingerprint has changed. / Open the server's page, solve the problem shown there, then deploy again. | Alice şu anda bu sunucuya dağıtım yapamaz. / Sunucu bağlı değil (durumu Bağlı değil) veya parmak izi değişti. / Sunucunun sayfasını açın, orada gösterilen sorunu çözün, sonra yeniden dağıtın. |

The F-01 message (owner step 4) is `certificate.key_mismatch`: a deployment whose `nginx -t` fails with the `key_mismatch` class after the write ends `rolled_back` with this reason.

### Audit actions (all tasks)

`certificate.uploaded` (details `certificate_id`, `fingerprint`, `source`), `certificate.upload_rejected` (result `failure`, `reason`), `certificate.key_attached` (`certificate_id`, `fingerprint`), `csr.created` (`csr_id`, `common_name`, `algorithm`), `csr.completed` (`csr_id`, `certificate_id`, `fingerprint`), `csr.cancelled` (`csr_id`), `location.updated` (`location_id`, `verify_port`, `verify_sni`, `skip_verify`), `location.changed_outside` (system; `location_id`, `cert_path`, `previous_fingerprint`, `fingerprint`), `deployment.requested` (`deployment_id`, `certificate_id`, `location_id`, `cert_path`, `job_id`, `confirm_incomplete_chain`), `deployment.denied` (result `denied`; `certificate_id`, `location_id`, `reason`), `deployment.succeeded` (`deployment_id`, `new_fingerprint`, `previous_fingerprint`, `verified`), `deployment.unchanged`, `deployment.failed` (result `failure`; `reason`, `failed_step`), `deployment.rolled_back` (result `failure`; `reason`), `deployment.rollback_failed` (result `failure`; `reason`, `failed_step`), `deployment.recovery_started` (system), `deployment.needs_attention` (system, result `failure`). Object types `certificate`, `csr`, `certificate_location`, `deployment`.

### Email templates (Task 15; `locales/common` `email.deployment.*`, EN and TR exact)

| Template | EN subject / body | TR subject / body |
|---|---|---|
| `deployment.failed` | Certificate deployment failed on {{target_name}} / Alice could not deploy a certificate on the server {{target_name}} (file {{cert_path}}). The server keeps its previous certificate.\n\nThe deployment history in Alice shows each step, the reason and what to do. Deployment: {{deployment_id}} | {{target_name}} sunucusunda sertifika dağıtımı başarısız oldu / Alice {{target_name}} sunucusunda bir sertifikayı dağıtamadı (dosya: {{cert_path}}). Sunucu önceki sertifikasını kullanmaya devam ediyor.\n\nAlice'teki dağıtım geçmişi her adımı, nedeni ve yapılması gerekenleri gösterir. Dağıtım: {{deployment_id}} |
| `deployment.rollback_failed` | Manual action needed: certificate restore failed on {{target_name}} / Alice deployed a certificate on the server {{target_name}} (file {{cert_path}}). The change failed, and the automatic restore failed too.\n\nThe previous files are on the server in {{backup_dir}}. Check the website now, then run nginx -t and systemctl status nginx on the server. The deployment history in Alice shows each step. Deployment: {{deployment_id}} | Elle müdahale gerekiyor: {{target_name}} sunucusunda sertifika geri yüklenemedi / Alice {{target_name}} sunucusunda bir sertifika dağıttı (dosya: {{cert_path}}). Değişiklik başarısız oldu ve otomatik geri yükleme de başarısız oldu.\n\nÖnceki dosyalar sunucuda şu klasörde: {{backup_dir}}. Web sitesini hemen denetleyin, sonra sunucuda nginx -t ve systemctl status nginx komutlarını çalıştırın. Alice'teki dağıtım geçmişi her adımı gösterir. Dağıtım: {{deployment_id}} |
| `deployment.needs_attention` | Alice cannot finish a deployment on {{target_name}} / The connection to the server {{target_name}} was lost during a certificate deployment (file {{cert_path}}), and Alice cannot reach the server to finish or undo it.\n\nAlice tries again every 15 minutes. Until then, check the website and the server's connection. Deployment: {{deployment_id}} | Alice {{target_name}} sunucusundaki bir dağıtımı tamamlayamıyor / Bir sertifika dağıtımı sırasında {{target_name}} sunucusuyla bağlantı kesildi (dosya: {{cert_path}}) ve Alice dağıtımı tamamlamak veya geri almak için sunucuya erişemiyor.\n\nAlice 15 dakikada bir yeniden dener. O zamana kadar web sitesini ve sunucunun bağlantısını denetleyin. Dağıtım: {{deployment_id}} |

### UI copy (exact; `web/src/locales/{en,tr}.json`, Tasks 21–22; the Playwright tests of Task 23 match it)

Keys are relative to the namespace in the first column. Placeholders are never followed by a suffix.

| Key | English | Turkish |
|---|---|---|
| `nav.certificates` | Certificates | Sertifikalar |
| `nav.deployments` | Deployment history | Dağıtım geçmişi |
| `certificates.title` | Certificates | Sertifikalar |
| `certificates.intro` | Certificates Alice found on your servers or that you added. A certificate used on several servers is listed once. | Alice'in sunucularınızda bulduğu veya sizin eklediğiniz sertifikalar. Birden çok sunucuda kullanılan bir sertifika bir kez listelenir. |
| `certificates.upload` | Upload certificate | Sertifika yükle |
| `certificates.createRequest` | Create signing request | İmzalama isteği oluştur |
| `certificates.search` | Search | Ara |
| `certificates.searchHelp` | Name, domain name or fingerprint | Ad, alan adı veya parmak izi |
| `certificates.server` | Server | Sunucu |
| `certificates.allServers` | All servers | Tüm sunucular |
| `certificates.source` | Source | Kaynak |
| `certificates.sourceAll` | All sources | Tüm kaynaklar |
| `certificates.sourceDiscovered` | Found on servers | Sunucularda bulunan |
| `certificates.sourceUploaded` | Uploaded | Yüklenen |
| `certificates.sourceCsr` | From a signing request | İmzalama isteğinden |
| `certificates.expiry` | Expiry | Geçerlilik sonu |
| `certificates.expiryAll` | Any date | Tüm tarihler |
| `certificates.expiryExpired` | Expired | Süresi dolmuş |
| `certificates.expiry30` | Within 30 days | 30 gün içinde |
| `certificates.expiry60` | Within 60 days | 60 gün içinde |
| `certificates.columns.name` | Name | Ad |
| `certificates.columns.expires` | Expires | Bitiş |
| `certificates.columns.daysLeft` | Days left | Kalan gün |
| `certificates.columns.usedOn` | Used on | Kullanıldığı yer |
| `certificates.columns.key` | Private key | Özel anahtar |
| `certificates.daysLeft_one` | {{count}} day | {{count}} gün |
| `certificates.daysLeft_other` | {{count}} days | {{count}} gün |
| `certificates.expired` | Expired | Süresi doldu |
| `certificates.usedOn_one` | {{count}} website | {{count}} web sitesi |
| `certificates.usedOn_other` | {{count}} websites | {{count}} web sitesi |
| `certificates.keyHeld` | In Alice | Alice'te |
| `certificates.keyNotHeld` | Not in Alice | Alice'te değil |
| `certificates.noName` | (no name) | (adsız) |
| `certificates.empty` | No certificates match these filters. | Bu filtrelere uyan sertifika yok. |
| `certificates.loadMore` | Show more | Daha fazla göster |
| `certificates.detail.backToList` | Back to certificates | Sertifikalara dön |
| `certificates.detail.subject` | Subject | Konu |
| `certificates.detail.issuer` | Issuer | Düzenleyen |
| `certificates.detail.names` | Domain names | Alan adları |
| `certificates.detail.serial` | Serial number | Seri numarası |
| `certificates.detail.validFrom` | Valid from | Geçerlilik başlangıcı |
| `certificates.detail.validUntil` | Valid until | Geçerlilik sonu |
| `certificates.detail.key` | Key | Anahtar |
| `certificates.detail.keyValue` | {{algorithm}}, {{bits}} bit | {{algorithm}}, {{bits}} bit |
| `certificates.detail.fingerprint` | SHA-256 fingerprint | SHA-256 parmak izi |
| `certificates.detail.source` | Source | Kaynak |
| `certificates.detail.chainComplete` | The certificate chain is complete. | Sertifika zinciri eksiksiz. |
| `certificates.detail.chainIncomplete` | The certificate chain is incomplete: some browsers may not trust this certificate. | Sertifika zinciri eksik: bazı tarayıcılar bu sertifikaya güvenmeyebilir. |
| `certificates.detail.selfSigned` | Self-signed certificate | Kendinden imzalı sertifika |
| `certificates.detail.usedWhere` | Where this certificate is used | Bu sertifikanın kullanıldığı yerler |
| `certificates.detail.notUsed` | This certificate is not used on any server that Alice knows. | Bu sertifika Alice'in bildiği hiçbir sunucuda kullanılmıyor. |
| `certificates.detail.deploy` | Deploy | Dağıt |
| `certificates.detail.deployments` | Deployments | Dağıtımlar |
| `certificates.detail.noDeployments` | This certificate has not been deployed yet. | Bu sertifika henüz dağıtılmadı. |
| `certificates.detail.noKey` | Alice does not have the private key of this certificate, so it cannot deploy it. | Alice bu sertifikanın özel anahtarına sahip değil, bu yüzden sertifikayı dağıtamaz. |
| `certificates.detail.expiredNoDeploy` | This certificate has expired and cannot be deployed. | Bu sertifikanın süresi doldu ve dağıtılamaz. |
| `certificates.upload.title` | Upload a certificate | Sertifika yükleyin |
| `certificates.upload.help` | Upload the certificate with its chain and its private key. Alice checks that they belong together before it stores them. The private key is stored encrypted and is never shown again. | Sertifikayı zinciriyle ve özel anahtarıyla birlikte yükleyin. Alice saklamadan önce bunların birbirine ait olduğunu denetler. Özel anahtar şifrelenmiş olarak saklanır ve bir daha gösterilmez. |
| `certificates.upload.format` | File format | Dosya biçimi |
| `certificates.upload.formatPem` | PEM text | PEM metni |
| `certificates.upload.formatPfx` | PFX file | PFX dosyası |
| `certificates.upload.certificate` | Certificate and chain (PEM) | Sertifika ve zincir (PEM) |
| `certificates.upload.privateKey` | Private key (PEM) | Özel anahtar (PEM) |
| `certificates.upload.pfxFile` | PFX file | PFX dosyası |
| `certificates.upload.pfxPassword` | PFX password | PFX parolası |
| `certificates.upload.label` | Name (optional) | Ad (isteğe bağlı) |
| `certificates.upload.submit` | Upload | Yükle |
| `certificates.upload.cancel` | Cancel | Vazgeç |
| `certificates.upload.uploaded` | Certificate uploaded. | Sertifika yüklendi. |
| `certificates.upload.chainWarning` | The chain is incomplete. An administrator must confirm before this certificate is deployed. | Zincir eksik. Bu sertifika dağıtılmadan önce bir yöneticinin onaylaması gerekir. |
| `certificates.upload.notYetValid` | This certificate is not valid yet. Websites would show an error until its start date. | Bu sertifika henüz geçerli değil. Başlangıç tarihine kadar web siteleri hata gösterir. |
| `certificates.upload.secretWarning` | Paste a private key only into this form, never into a comment or reason field. | Özel anahtarı yalnızca bu forma yapıştırın, hiçbir zaman bir açıklama veya gerekçe alanına yapıştırmayın. |
| `certificates.csr.title` | Create a signing request | İmzalama isteği oluşturun |
| `certificates.csr.help` | Alice creates a new private key and a signing request (CSR). Send the request to your certificate authority, then add the certificate it returns here. The private key never leaves Alice. | Alice yeni bir özel anahtar ve bir imzalama isteği (CSR) oluşturur. İsteği sertifika yetkilinize gönderin, sonra döndürdüğü sertifikayı buraya ekleyin. Özel anahtar Alice'ten hiç çıkmaz. |
| `certificates.csr.commonName` | Main domain name | Ana alan adı |
| `certificates.csr.otherNames` | Other domain names (one per line) | Diğer alan adları (her satıra bir tane) |
| `certificates.csr.keyType` | Key type | Anahtar türü |
| `certificates.csr.keyEcdsa` | ECDSA P-256 (recommended) | ECDSA P-256 (önerilen) |
| `certificates.csr.keyRsa3072` | RSA 3072 | RSA 3072 |
| `certificates.csr.keyRsa4096` | RSA 4096 | RSA 4096 |
| `certificates.csr.submit` | Create request | İstek oluştur |
| `certificates.csr.created` | Signing request created. Copy it and send it to your certificate authority. | İmzalama isteği oluşturuldu. Kopyalayıp sertifika yetkilinize gönderin. |
| `certificates.csr.copy` | Copy request | İsteği kopyala |
| `certificates.csr.copied` | Copied | Kopyalandı |
| `certificates.csr.pendingTitle` | Open signing requests | Açık imzalama istekleri |
| `certificates.csr.createdAt` | Created: {{time}} | Oluşturulma: {{time}} |
| `certificates.csr.complete` | Add signed certificate | İmzalı sertifikayı ekle |
| `certificates.csr.completeTitle` | Add the signed certificate | İmzalı sertifikayı ekleyin |
| `certificates.csr.completeHelp` | Paste the certificate your certificate authority returned, with its chain. Request: {{name}} | Sertifika yetkilinizin döndürdüğü sertifikayı zinciriyle birlikte yapıştırın. İstek: {{name}} |
| `certificates.csr.completeSubmit` | Add certificate | Sertifikayı ekle |
| `certificates.csr.cancelRequest` | Cancel request | İsteği iptal et |
| `certificates.csr.cancelTitle` | Cancel this signing request? | Bu imzalama isteği iptal edilsin mi? |
| `certificates.csr.cancelHelp` | You can no longer add a certificate for this request. | Bu istek için artık sertifika ekleyemezsiniz. |
| `certificates.csr.keep` | Keep request | İsteği koru |
| `locations.title` | Websites on this server | Bu sunucudaki web siteleri |
| `locations.intro` | Each row is a certificate file that Nginx uses. Alice never changes the Nginx configuration, only these files. | Her satır Nginx'in kullandığı bir sertifika dosyasıdır. Alice Nginx yapılandırmasını hiçbir zaman değiştirmez, yalnızca bu dosyaları değiştirir. |
| `locations.discover` | Discover | Keşfet |
| `locations.empty` | Alice has not found any certificates on this server yet. Choose Discover. | Alice bu sunucuda henüz sertifika bulmadı. Keşfet düğmesini seçin. |
| `locations.columns.website` | Website | Web sitesi |
| `locations.columns.port` | Port | Bağlantı noktası |
| `locations.columns.file` | Certificate file | Sertifika dosyası |
| `locations.columns.expires` | Expires | Bitiş |
| `locations.columns.state` | State | Durum |
| `locations.columns.actions` | Actions | İşlemler |
| `locations.defaultServer` | (default server) | (varsayılan sunucu) |
| `locations.ready` | Ready | Hazır |
| `locations.notSupported` | Not supported | Desteklenmiyor |
| `locations.missing` | No longer found | Artık bulunmuyor |
| `locations.deploying` | Deployment in progress | Dağıtım sürüyor |
| `locations.deploy` | Deploy certificate | Sertifika dağıt |
| `locations.deployNamed` | Deploy certificate: {{site}} | Sertifika dağıt: {{site}} |
| `locations.settings` | Verification settings | Doğrulama ayarları |
| `locations.settingsNamed` | Verification settings: {{site}} | Doğrulama ayarları: {{site}} |
| `locations.noCertificate` | No readable certificate | Okunabilir sertifika yok |
| `locations.inherited` | The certificate is set for all websites in the http block. | Sertifika http bloğundaki tüm web siteleri için ayarlanmış. |
| `locations.changedOutside` | The certificate changed outside Alice. | Sertifika Alice dışında değiştirildi. |
| `locations.definedIn` | Defined in {{file}}, line {{line}} | Tanımlandığı yer: {{file}}, satır {{line}} |
| `locations.showMissing` | Show websites that are no longer found | Artık bulunmayan web sitelerini göster |
| `locations.configInvalid` | Nginx's configuration on this server has an error. Alice will not deploy until it is fixed. | Bu sunucudaki Nginx yapılandırmasında bir hata var. Hata giderilene kadar Alice dağıtım yapmaz. |
| `locations.warnings.symlinked` | This file is a link. Another tool (for example certbot) may replace it. | Bu dosya bir bağlantı. Başka bir araç (örneğin certbot) dosyayı değiştirebilir. |
| `locations.warnings.custom_location` | Custom location: outside the usual certificate folders. | Özel konum: alışılmış sertifika klasörlerinin dışında. |
| `locations.warnings.key_mode_open` | The private key file can be read by more users than needed: {{mode}} | Özel anahtar dosyasını gerekenden fazla kullanıcı okuyabiliyor: {{mode}} |
| `locations.warnings.certificate_expired` | The certificate has expired. | Sertifikanın süresi doldu. |
| `locations.warnings.san_mismatch` | The certificate does not name this website: {{site}} | Sertifika bu web sitesini içermiyor: {{site}} |
| `locations.unsupported.variable` | The path uses a variable, so Alice cannot know which file is used. | Yol bir değişken kullanıyor, bu yüzden Alice hangi dosyanın kullanıldığını bilemez. |
| `locations.unsupported.data_value` | The certificate is written into the configuration itself. | Sertifika doğrudan yapılandırmanın içine yazılmış. |
| `locations.unsupported.engine_key` | The private key is kept in a hardware module. | Özel anahtar bir donanım modülünde tutuluyor. |
| `locations.unsupported.key_missing` | No private key file is set for this certificate. | Bu sertifika için özel anahtar dosyası ayarlanmamış. |
| `locations.unsupported.password_file` | The private key is protected with a password file. | Özel anahtar bir parola dosyasıyla korunuyor. |
| `locations.unsupported.path_not_allowed` | The path contains characters Alice cannot pass safely. | Yol, Alice'in güvenle iletemeyeceği karakterler içeriyor. |
| `locations.unsupported.stream` | TLS in stream blocks is not supported in this version. | Stream bloklarındaki TLS bu sürümde desteklenmiyor. |
| `locations.unsupported.combined_file` | The certificate and the key are in one file. | Sertifika ve anahtar tek bir dosyada. |
| `locations.unsupported.key_conflict` | This certificate file is used with different key files. | Bu sertifika dosyası farklı anahtar dosyalarıyla kullanılıyor. |
| `locations.unsupported.unsupported_key` | Alice supports RSA and ECDSA certificates only. | Alice yalnızca RSA ve ECDSA sertifikalarını destekler. |
| `locations.unsupported.file_problem` | Alice cannot use the files at this place. | Alice bu konumdaki dosyaları kullanamaz. |
| `locations.problems.missing` | The file does not exist. | Dosya yok. |
| `locations.problems.not_root_controlled` | A folder or link on the path can be changed by users other than root. | Yol üzerindeki bir klasör veya bağlantı root dışındaki kullanıcılar tarafından değiştirilebiliyor. |
| `locations.problems.not_regular` | The path is not a regular file. | Yol normal bir dosya değil. |
| `locations.problems.hard_linked` | The file has more than one name (hard link). | Dosyanın birden fazla adı var (sabit bağlantı). |
| `locations.problems.too_large` | The file is larger than 256 KiB. | Dosya 256 KiB'tan büyük. |
| `locations.problems.not_a_certificate` | The file does not contain a certificate. | Dosya bir sertifika içermiyor. |
| `locations.problems.unreadable` | Alice could not read the file. | Alice dosyayı okuyamadı. |
| `locations.problems.bad_name` | The file name does not end in .pem, .crt, .cer, .cert, .key, .chained or .fullchain. | Dosya adı .pem, .crt, .cer, .cert, .key, .chained veya .fullchain ile bitmiyor. |
| `locations.verify.title` | Verification settings | Doğrulama ayarları |
| `locations.verify.help` | After a deployment Alice connects to the website and checks that the new certificate is served. Change these only when Alice cannot reach the website directly, for example behind a load balancer. | Bir dağıtımdan sonra Alice web sitesine bağlanır ve yeni sertifikanın sunulduğunu denetler. Bu ayarları yalnızca Alice web sitesine doğrudan erişemediğinde değiştirin, örneğin bir yük dengeleyicinin arkasındaysa. |
| `locations.verify.port` | Port to check (empty: the port from the configuration) | Denetlenecek bağlantı noktası (boş: yapılandırmadaki bağlantı noktası) |
| `locations.verify.sni` | Name to check (empty: from the configuration) | Denetlenecek ad (boş: yapılandırmadan) |
| `locations.verify.skip` | Skip the check for this website | Bu web sitesi için denetimi atla |
| `locations.verify.skipHelp` | Not recommended: a wrong certificate would not be noticed or restored automatically. | Önerilmez: yanlış bir sertifika fark edilmez ve otomatik olarak geri alınmaz. |
| `locations.verify.save` | Save | Kaydet |
| `locations.verify.saved` | Settings saved. | Ayarlar kaydedildi. |
| `locations.verify.cancel` | Cancel | Vazgeç |
| `deploy.title` | Deploy a certificate | Sertifika dağıtın |
| `deploy.certificate` | Certificate | Sertifika |
| `deploy.chooseCertificate` | Choose a certificate | Bir sertifika seçin |
| `deploy.noCandidates` | Alice holds no certificate with a private key that fits this website. Upload one first. | Alice'te bu web sitesine uyan, özel anahtarı olan bir sertifika yok. Önce bir sertifika yükleyin. |
| `deploy.websites` | Websites | Web siteleri |
| `deploy.summary` | Alice backs up the current files, writes the new certificate and key, checks the Nginx configuration, reloads Nginx and checks that the new certificate is served. If any step fails, Alice restores the previous files. | Alice mevcut dosyaları yedekler, yeni sertifikayı ve anahtarı yazar, Nginx yapılandırmasını denetler, Nginx'i yeniden yükler ve yeni sertifikanın sunulduğunu denetler. Herhangi bir adım başarısız olursa Alice önceki dosyaları geri yükler. |
| `deploy.confirmChain` | I confirm that this incomplete chain is intended | Bu eksik zincirin bilerek kullanıldığını onaylıyorum |
| `deploy.chainAdminOnly` | The chain of this certificate is incomplete. An administrator must deploy it. | Bu sertifikanın zinciri eksik. Sertifikayı bir yöneticinin dağıtması gerekir. |
| `deploy.submit` | Deploy | Dağıt |
| `deploy.cancel` | Cancel | Vazgeç |
| `deploy.close` | Close | Kapat |
| `deploy.working` | Alice is deploying the certificate… | Alice sertifikayı dağıtıyor… |
| `deploy.succeeded` | The new certificate is live and verified. | Yeni sertifika yayında ve doğrulandı. |
| `deploy.verifiedLocally` | Alice checked it from the server itself because it cannot reach the website directly. | Alice web sitesine doğrudan erişemediği için denetimi sunucunun kendisinden yaptı. |
| `deploy.unchanged` | This certificate was already in place. Nothing was changed. | Bu sertifika zaten yerindeydi. Hiçbir şey değiştirilmedi. |
| `deploy.rolledBack` | Your server was restored to its previous certificate. | Sunucunuz önceki sertifikasına geri döndürüldü. |
| `deploy.noChange` | Nothing was changed on the server. | Sunucuda hiçbir şey değiştirilmedi. |
| `deploy.rollbackFailed` | Automatic restore failed. Manual action is needed. | Otomatik geri yükleme başarısız oldu. Elle müdahale gerekiyor. |
| `deploy.recovering` | The connection to the server was lost. Alice will check the server and finish or undo the change. | Sunucuyla bağlantı kesildi. Alice sunucuyu denetleyip değişikliği tamamlayacak veya geri alacak. |
| `deploy.stillWorking` | Alice is still working on this. Open the deployment history in a minute to see the result. | Alice bu iş üzerinde çalışmaya devam ediyor. Sonucu görmek için bir dakika sonra dağıtım geçmişini açın. |
| `deploy.openHistory` | Open deployment history | Dağıtım geçmişini aç |
| `deploy.partial` | Updated websites: {{ok}} of {{total}} | Güncellenen web siteleri: {{ok}} / {{total}} |
| `deployments.title` | Deployment history | Dağıtım geçmişi |
| `deployments.intro` | Every certificate deployment with its result. Open one to see each step. | Sonuçlarıyla birlikte tüm sertifika dağıtımları. Her adımı görmek için birini açın. |
| `deployments.columns.when` | When | Zaman |
| `deployments.columns.server` | Server | Sunucu |
| `deployments.columns.file` | Certificate file | Sertifika dosyası |
| `deployments.columns.certificate` | Certificate | Sertifika |
| `deployments.columns.result` | Result | Sonuç |
| `deployments.empty` | No deployments yet. | Henüz dağıtım yok. |
| `deployments.loadMore` | Show more | Daha fazla göster |
| `deployments.open` | Open | Aç |
| `deployments.detailTitle` | Deployment | Dağıtım |
| `deployments.backToList` | Back to deployment history | Dağıtım geçmişine dön |
| `deployments.requestedBy` | Requested by: {{name}} | İsteyen: {{name}} |
| `deployments.requestedBySystem` | Requested by: Alice | İsteyen: Alice |
| `deployments.previous` | Previous certificate: {{fingerprint}} | Önceki sertifika: {{fingerprint}} |
| `deployments.new` | New certificate: {{fingerprint}} | Yeni sertifika: {{fingerprint}} |
| `deployments.backup` | Backup on the server: {{path}} | Sunucudaki yedek: {{path}} |
| `deployments.stepsTitle` | Steps | Adımlar |
| `deployments.steps.verify_current` | Check the current certificate | Mevcut sertifikayı denetleme |
| `deployments.steps.backup` | Backup | Yedekleme |
| `deployments.steps.write` | Write | Yazma |
| `deployments.steps.config_test` | Check | Denetim |
| `deployments.steps.reload` | Reload | Yeniden yükleme |
| `deployments.steps.verify` | Verify | Doğrulama |
| `deployments.steps.restore` | Restore | Geri yükleme |
| `deployments.steps.rollback_config_test` | Check again | Yeniden denetim |
| `deployments.steps.rollback_reload` | Reload again | Yeniden yükleme (geri alma) |
| `deployments.steps.verify_old` | Verify the previous certificate | Önceki sertifikayı doğrulama |
| `deployments.stepStatus.started` | Running | Çalışıyor |
| `deployments.stepStatus.ok` | Done | Tamam |
| `deployments.stepStatus.failed` | Failed | Başarısız |
| `deployments.stepStatus.skipped` | Skipped | Atlandı |
| `deployments.stepStatus.waiting` | Waiting | Bekliyor |
| `enum.deploymentStatus.pending` | Waiting | Bekliyor |
| `enum.deploymentStatus.running` | Running | Sürüyor |
| `enum.deploymentStatus.succeeded` | Succeeded | Başarılı |
| `enum.deploymentStatus.unchanged` | No change needed | Değişiklik gerekmedi |
| `enum.deploymentStatus.failed` | Failed, nothing changed | Başarısız, değişiklik yok |
| `enum.deploymentStatus.rolled_back` | Failed, restored | Başarısız, geri yüklendi |
| `enum.deploymentStatus.rollback_failed` | Restore failed | Geri yükleme başarısız |
| `enum.deploymentStatus.needs_attention` | Needs attention | İlgilenilmesi gerekiyor |
| `targets.form.type` | Server type | Sunucu türü |
| `targets.form.typeLinux` | Linux server | Linux sunucu |
| `targets.form.typeNginx` | Nginx server | Nginx sunucu |
| `targets.form.typeHelp` | Choose Nginx server to manage its certificates too. Prepare the server with the Nginx commands first. | Sertifikalarını da yönetmek için Nginx sunucu seçeneğini seçin. Sunucuyu önce Nginx komutlarıyla hazırlayın. |
| `targets.typeLabel.linux` | Linux server | Linux sunucu |
| `targets.typeLabel.nginx` | Nginx server | Nginx sunucu |
| `targets.facts.nginx` | Nginx version: {{version}} | Nginx sürümü: {{version}} |
| `sshKeys.missingBadge` | No longer found | Artık bulunmuyor |
| `jobs.types.certificate_deploy` | Deploy a certificate | Sertifika dağıtımı |
| `jobs.types.certificate_deploy_recover` | Finish an interrupted deployment | Yarım kalan dağıtımı tamamlama |
| `warnings.stream_tls` | TLS in stream blocks is not supported in this version. The websites in http blocks are still listed. | Stream bloklarındaki TLS bu sürümde desteklenmiyor. http bloklarındaki web siteleri yine de listelenir. |
| `warnings.nginx_config_invalid` | Nginx's configuration has an error. Alice will not deploy until it is fixed. | Nginx yapılandırmasında bir hata var. Hata giderilene kadar Alice dağıtım yapmaz. |
| `warnings.nginx_not_found` | Nginx was not found on this server. | Bu sunucuda Nginx bulunamadı. |
| `warnings.config_file_writable` | An Nginx configuration file can be changed by users other than root: {{path}} | Bir Nginx yapılandırma dosyası root dışındaki kullanıcılar tarafından değiştirilebiliyor: {{path}} |
| `warnings.too_many_files` | This server uses more certificate files than Alice lists, so some were not read. | Bu sunucu Alice'in listelediğinden fazla sertifika dosyası kullanıyor, bu yüzden bazıları okunmadı. |
| `audit.actions.certificate_uploaded` | Certificate uploaded | Sertifika yüklendi |
| `audit.actions.certificate_upload_rejected` | Certificate upload refused | Sertifika yüklemesi reddedildi |
| `audit.actions.certificate_key_attached` | Private key added to a certificate | Sertifikaya özel anahtar eklendi |
| `audit.actions.csr_created` | Signing request created | İmzalama isteği oluşturuldu |
| `audit.actions.csr_completed` | Signed certificate added | İmzalı sertifika eklendi |
| `audit.actions.csr_cancelled` | Signing request cancelled | İmzalama isteği iptal edildi |
| `audit.actions.location_updated` | Verification settings changed | Doğrulama ayarları değiştirildi |
| `audit.actions.location_changed_outside` | Certificate changed outside Alice | Sertifika Alice dışında değiştirildi |
| `audit.actions.deployment_requested` | Deployment requested | Dağıtım istendi |
| `audit.actions.deployment_denied` | Deployment refused | Dağıtım reddedildi |
| `audit.actions.deployment_succeeded` | Certificate deployed | Sertifika dağıtıldı |
| `audit.actions.deployment_unchanged` | Deployment: no change needed | Dağıtım: değişiklik gerekmedi |
| `audit.actions.deployment_failed` | Deployment failed | Dağıtım başarısız oldu |
| `audit.actions.deployment_rolled_back` | Previous certificate restored | Önceki sertifika geri yüklendi |
| `audit.actions.deployment_rollback_failed` | Automatic restore failed | Otomatik geri yükleme başarısız oldu |
| `audit.actions.deployment_recovery_started` | Interrupted deployment being finished | Yarım kalan dağıtım tamamlanıyor |
| `audit.actions.deployment_needs_attention` | Deployment needs attention | Dağıtımla ilgilenilmesi gerekiyor |

UI step grouping (Deploy dialog and deployment detail): the five owner-visible steps are **Backup** (`backup`), **Write** (`write_key` and `write_cert`: `ok` when both are `ok`, `failed` when either failed), **Check** (`config_test`), **Reload** (`reload`), **Verify** (`verify`); `verify_current` is shown before them only in the detail page; `restore`, `rollback_config_test`, `rollback_reload`, `verify_old` appear below a rolled-back deployment. A step with no event yet shows `deployments.stepStatus.waiting`.

### Owner test pack (Task 2)

`go run ./tools/testcerts -out <dir> -name <domain>` writes `ca.pem` (test root), `good.pem` (leaf + intermediate + root: a complete chain), `good.key`, `good.pfx` (password `alice-test`), `broken.pem` (a valid leaf) and `broken.key` (a key of another certificate), each generated fresh; it prints the file names and refuses an existing output directory.

### e2e environment (Tasks 19, 23)

The e2e target `sshtarget` (Ubuntu 22.04) also runs Nginx: a test CA and the certificate of `www.example.test` are generated at image build (`/etc/nginx/ssl/www.crt` 0644, `/etc/nginx/ssl/www.key` 0600, root:root), `/etc/nginx/conf.d/www.conf` serves `www.example.test` on `listen 443 ssl;`, and a second server block `files.example.test` uses `ssl_certificate /etc/nginx/ssl/$ssl_server_name.crt;` (an unsupported location with reason `variable`). `/usr/bin/systemctl` is the shim: `reload nginx` runs `nginx -s reload` unless `/etc/alice-e2e/reload-mode` says `fail-once` (exit 1, then the mode becomes `ok`), `fail` (exit 1) or `noop` (exit 0 without reloading); `is-active --quiet nginx` checks the master process. Scripts: `alice-e2e-newcert <name> [--broken]` prints a fresh certificate (leaf + test intermediate) and its key — or another key with `--broken` — between the marker lines `-----ALICE CERT-----`, `-----ALICE KEY-----`, `-----ALICE END-----`; `alice-e2e-reload-mode <ok|fail-once|fail|noop>`; `alice-e2e-served <name>` prints the SHA-256 fingerprint (lower-case hex, no colons) of the certificate served for that name on `127.0.0.1:443`. Alice reaches the websites at `sshtarget:443` on the internal network, so verification is remote. The Phase 3 target keys, users and scripts are unchanged; the healthcheck checks both `sshd` and `nginx`.

---

### Task 1: Carries without a helper change — uid-0 accounts in the last-root-key pre-check, `missing` on key-list rows

Phase 3 left two inventory gaps that need no helper change. (1) The provider guards the last key of every uid-0 account its listing reported, but inventory's pre-check (before a removal is queued) looks at the name `root` only (`docs/security/reviews/phase-3.md`, "Last-key guard for uid-0 accounts"). The listing already carries each user's uid (`helperproto.UserFiles.UID`), so the provider reports the uid-0 names, inventory keeps them in the target's facts, and the pre-check treats each of them like `root`. Task 5 makes the helper list every uid-0 account with a login shell, so the guard becomes effective for `toor`-style accounts then. (2) **Show keys that are no longer found** adds keys to the list without marking them; the list item gets `missing`.

**Files:**
- Modify: `internal/providers/types.go` (`DiscoveryResult.UID0Users`)
- Modify: `internal/providers/linuxssh/discover.go` (`Discover` fills `UID0Users`)
- Modify: `internal/inventory/types.go` (`Facts.UID0Users`), `internal/inventory/sshkeys.go` (`Reconcile` stores it; `SSHKey.Missing`; `ListSSHKeys` computes it), `internal/inventory/removal.go` (pre-check)
- Modify: `internal/api/inventory_dto.go` (`sshKeyDTO.Missing`), `api/openapi.yaml` (`SSHKey.missing`, required boolean)
- Modify: `web/src/api/types.ts` (`SSHKey.missing`), `web/src/pages/SSHKeysPage.tsx` (badge), `web/src/locales/{en,tr}.json` (`sshKeys.missingBadge`), `web/src/test/fixtures.ts` (`sshKeyFixture` default `missing: false`)
- Test: `internal/providers/linuxssh/provider_test.go`, `internal/inventory/removal_integration_test.go`, `internal/inventory/sshkeys_integration_test.go`, `internal/api/sshkeys_handlers_test.go`, `web/src/pages/SSHKeysPage.test.tsx`

**Interfaces:**
- Consumes: `helperproto.UserFiles.UID`, `session.listAuthKeys`, `inventory.Reconcile`, `RequestKeyRemoval`, `ListSSHKeys`, `sshKeyJSON`.
- Produces: `providers.DiscoveryResult.UID0Users []string`; `inventory.Facts.UID0Users []string` (JSON `uid0_users`, omitted when empty); `inventory.SSHKey.Missing bool`; API `missing` on every SSH key item; web `SSHKey.missing: boolean`.

- [ ] **Step 1: Write the failing provider test**

Add to `internal/providers/linuxssh/provider_test.go` (it uses the file's `newProvEnv` fixture: an emulator `e.emu`, a fake SSH server, the provider `e.prov`, the target `e.ref` and the credential `e.cred`):

```go
// Carry 3: Discover names the listed accounts with uid 0 so inventory's pre-check can protect the
// last key of every one of them, not only of "root".
func TestDiscoverReportsUID0Users(t *testing.T) {
	e := newProvEnv(t)
	e.emu.AddUser("toor", 0, "/var/toor")
	s, err := e.prov.Open(context.Background(), e.ref, e.cred, providers.Env{})
	require.NoError(t, err)
	defer func() { _ = s.Close() }()
	res, err := s.Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true})
	require.NoError(t, err)
	assert.Equal(t, []string{"root", "toor"}, res.UID0Users)
}
```

- [ ] **Step 2: Run it to see it fail**

Run: `go test ./internal/providers/linuxssh -run TestDiscoverReportsUID0Users -count=1`
Expected: FAIL — `res.UID0Users undefined`.

- [ ] **Step 3: Implement**

In `internal/providers/types.go` add to `DiscoveryResult`, after `ReadFiles`:

```go
	UID0Users []string // listed accounts with uid 0 (root and any other); their last key is guarded like root's
```

In `internal/providers/linuxssh/discover.go`, inside `Discover` after the `for _, w := range list.Warnings` loop and before the `for _, u := range list.Users` loop:

```go
	for _, u := range list.Users {
		if u.UID == 0 && helperproto.ValidUser(u.User) {
			res.UID0Users = append(res.UID0Users, u.User)
		}
	}
	slices.Sort(res.UID0Users)
```

(add `"slices"` to the imports).

- [ ] **Step 4: Run it to see it pass**

Run: `go test ./internal/providers/linuxssh -count=1`
Expected: PASS.

- [ ] **Step 5: Write the failing inventory tests**

Add to `internal/inventory/removal_integration_test.go`:

```go
// Carry 3: the pre-check treats every uid-0 account of the last scan like root.
func TestRequestKeyRemovalGuardsTheLastKeyOfEveryUID0Account(t *testing.T) {
	f := newRemovalFixture(t)
	h := f.h
	const toorFile = "/var/toor/.ssh/authorized_keys"
	_, err := h.svc.Reconcile(h.ctx, f.target.ID, providers.DiscoveryResult{SSHKeys: []providers.DiscoveredSSHKey{
		dk("deploy", deployFile, 1, "SHA256:dep0000000000000000000000000000000000000000", "deploy@laptop"),
		dk("root", rootFile, 1, "SHA256:root000000000000000000000000000000000000000", "root@bastion"),
		dk("toor", toorFile, 1, "SHA256:toor000000000000000000000000000000000000000", "toor@x"),
	}, SSHD: sshdRead, ReadFiles: []string{deployFile, rootFile, toorFile}, UID0Users: []string{"root", "toor"}})
	require.NoError(t, err)
	toor := locations(t, h, f.target.ID, false)["toor SHA256:toor000000000000000000000000000000000000000"].ID

	_, err = h.svc.RequestKeyRemoval(h.ctx, f.operator, toor, false)
	require.ErrorIs(t, err, inventory.ErrLastRootKey)
	_, err = h.svc.RequestKeyRemoval(h.ctx, f.admin, toor, true)
	require.NoError(t, err, "an Administrator may confirm, as for root")
	d := h.auditDetails("sshkey.remove.denied")
	require.Len(t, d, 1)
	assert.Equal(t, "last_root_key", d[0]["reason"])
	assert.Equal(t, "toor", d[0]["os_user"])

	// A later scan without the uid-0 list (an older helper) keeps the guard for root only.
	var facts map[string]any
	require.NoError(t, h.db.App.QueryRow(h.ctx, "SELECT facts FROM targets WHERE id = $1", f.target.ID).Scan(&facts))
	assert.Equal(t, []any{"root", "toor"}, facts["uid0_users"])
}
```

Add to `internal/inventory/sshkeys_integration_test.go` (use the file's existing target/reconcile helpers; the names below are those of `removal_integration_test.go`, which is in the same package):

```go
// Carry 4: a key whose every matching location is missing carries Missing; a key present
// somewhere does not.
func TestListSSHKeysMarksMissingKeys(t *testing.T) {
	f := newRemovalFixture(t)
	h := f.h
	_, err := h.svc.Reconcile(h.ctx, f.target.ID, providers.DiscoveryResult{SSHKeys: []providers.DiscoveredSSHKey{
		dk("root", rootFile, 1, "SHA256:root000000000000000000000000000000000000000", "root@bastion"),
	}, SSHD: sshdRead, ReadFiles: []string{deployFile, rootFile}})
	require.NoError(t, err)
	page, err := h.svc.ListSSHKeys(h.ctx, inventory.KeyFilter{IncludeMissing: true})
	require.NoError(t, err)
	missing := map[string]bool{}
	for _, k := range page.Items {
		missing[k.Fingerprint] = k.Missing
	}
	assert.True(t, missing["SHA256:dep0000000000000000000000000000000000000000"], "deploy's key is no longer in its file")
	assert.False(t, missing["SHA256:root000000000000000000000000000000000000000"])
	page, err = h.svc.ListSSHKeys(h.ctx, inventory.KeyFilter{})
	require.NoError(t, err)
	for _, k := range page.Items {
		assert.False(t, k.Missing, "without missing keys requested no item is missing: %s", k.Fingerprint)
	}
}
```

- [ ] **Step 6: Run them to see them fail**

Run: `go test -tags integration ./internal/inventory -run 'UID0Account|MarksMissingKeys' -count=1` (Docker: testcontainers PostgreSQL)
Expected: FAIL — `unknown field UID0Users`, `k.Missing undefined`.

- [ ] **Step 7: Implement**

`internal/inventory/types.go`, `Facts` gains (after `Unreadable`):

```go
	UID0Users []string `json:"uid0_users,omitempty"` // listed accounts with uid 0 (last-root-key guard)
```

`internal/inventory/sshkeys.go`:
- `SSHKey` gains `Missing bool` after `TargetCount`.
- In `Reconcile`, replace `f.SSHD, f.HostKeys, f.Warnings, f.Unreadable = &sshd, res.HostKeys, res.Warnings, res.UnreadableLines` with:

```go
		f.SSHD, f.HostKeys, f.Warnings, f.Unreadable = &sshd, res.HostKeys, res.Warnings, res.UnreadableLines
		f.UID0Users = append([]string(nil), res.UID0Users...)
```

- In `ListSSHKeys`, the select list `k.first_seen_at, count(*), count(DISTINCT l.target_id), (array_agg(...))[1]` becomes:

```sql
    k.first_seen_at, count(*), count(DISTINCT l.target_id), (array_agg(l.comment ORDER BY l.last_seen_at DESC, l.id DESC))[1],
    bool_and(l.missing_since IS NOT NULL OR l.removed_by_alice_at IS NOT NULL)
```

and the `Scan` gains `&k.Missing` last. In `GetSSHKey`, after the locations are loaded, set `k.Missing = len(k.Locations) > 0 && every location has MissingSince != nil || RemovedAt != nil` (a loop).

`internal/inventory/removal.go`, in `RequestKeyRemoval` replace the block starting `if loc.OSUser == "root" && !allowLastRoot {` with:

```go
		if (loc.OSUser == "root" || slices.Contains(t.Facts.UID0Users, loc.OSUser)) && !allowLastRoot {
			var others int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM ssh_key_locations
WHERE target_id = $1 AND os_user = $4 AND file_path = $2 AND id <> $3 AND missing_since IS NULL AND removed_by_alice_at IS NULL`,
				loc.TargetID, loc.FilePath, loc.ID, loc.OSUser).Scan(&others); err != nil {
				return fmt.Errorf("inventory: count root keys: %w", err)
			}
			if others == 0 {
				return &denial{reason: "last_root_key", err: ErrLastRootKey, loc: loc}
			}
		}
```

The denial audit already carries `os_user` (check `auditDenial`; add `"os_user": d.loc.OSUser` to its details if it is not there).

- [ ] **Step 8: Run the inventory tests**

Run: `go test -tags integration ./internal/inventory -count=1` (Docker)
Expected: PASS (all inventory tests, including Phase 3's).

- [ ] **Step 9: API field, failing test first**

Add to `internal/api/sshkeys_handlers_test.go` (the file's fake inventory answers `ListSSHKeys`; give one item `Missing: true`):

```go
func TestListSSHKeysCarriesMissing(t *testing.T) {
	d := testDeps(t, nil)
	inv := d.Inventory.(*fakeInventory)
	inv.keys = []inventory.SSHKey{{ID: uuid.New(), Fingerprint: "SHA256:" + strings.Repeat("a", 43), Missing: true}}
	rec := call(newServer(d).handler(newServer(d).apiRoutes()), http.MethodGet, "/api/v1/ssh-keys?missing=true", "auditor", "")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `"missing":true`)
}
```

(Use the fake's real field name for the key list — `fakes_test.go` defines it.) Run: `go test ./internal/api -run TestListSSHKeysCarriesMissing -count=1` → FAIL. Then add `Missing bool \`json:"missing"\`` to `sshKeyDTO` (after `TargetCount`) and `Missing: k.Missing` in `sshKeyJSON`; add `missing: {type: boolean}` to the `SSHKey` schema in `api/openapi.yaml` and to its `required` list. Run `go test ./internal/api -count=1` → PASS.

- [ ] **Step 10: Web badge, failing test first**

Add to `web/src/pages/SSHKeysPage.test.tsx` (inside its existing `describe`, whose `beforeEach` installs a signed-in session and the targets handler; add `server.use(...sessionHandlers(operatorSession))` to the test if that file sets the session per test):

```tsx
it('marks keys that are no longer found', async () => {
  server.use(
    http.get('/api/v1/ssh-keys', () =>
      HttpResponse.json({ items: [sshKeyFixture({ id: 'k1', missing: true }), sshKeyFixture({ id: 'k2', fingerprint: 'SHA256:' + 'b'.repeat(43) })], next_cursor: null }),
    ),
  );
  await renderRoute('/ssh-keys');
  const rows = await screen.findAllByRole('row');
  expect(within(rows[1]).getByText('No longer found')).toBeInTheDocument();
  expect(within(rows[2]).queryByText('No longer found')).not.toBeInTheDocument();
});
```

Run: `cd web && npx vitest run src/pages/SSHKeysPage.test.tsx` → FAIL. Then: add `missing: boolean;` to `SSHKey` in `types.ts`; default `missing: false` in `sshKeyFixture`; in the key row of `SSHKeysPage.tsx`, next to the existing flag badges, render `{k.missing && <Badge color="gray" variant="light">{t('sshKeys.missingBadge')}</Badge>}`; add `sshKeys.missingBadge` to both locale files (contract copy). Run the test again → PASS; `make i18n-check` → ok.

- [ ] **Step 11: Full check and commit**

Run: `make lint && go test ./internal/... -count=1 && make web-test && make i18n-check`
Expected: all pass.

```bash
git add internal/providers/types.go internal/providers/linuxssh/discover.go internal/providers/linuxssh/provider_test.go \
  internal/inventory internal/api/inventory_dto.go internal/api/sshkeys_handlers_test.go api/openapi.yaml \
  web/src/api/types.ts web/src/pages/SSHKeysPage.tsx web/src/pages/SSHKeysPage.test.tsx web/src/locales web/src/test/fixtures.ts
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "fix(inventory): guard the last key of every uid-0 account and mark missing keys in the list

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 2: Test PKI, owner test pack and the pure `certs` package

Every certificate fixture is generated at test time (§22.6; nothing for gitleaks to find, no expiring fixtures). `internal/testutil/pki` builds CAs, leaves, PFX files, signing requests and broken pairs; `tools/testcerts` gives the owner the "test pack" of §26.6 owner steps 2 and 4. `internal/certs` is the pure validation core used by inventory: parsing PEM chains (discovered files and uploads), PFX through `software.sslmate.com/src/go-pkcs12` (R23), the leaf/key match, chain reordering and completeness, refusals of weak or unsupported material, and CSR generation.

**Files:**
- Create: `internal/testutil/pki/pki.go`, `internal/testutil/pki/pki_test.go`
- Create: `tools/testcerts/main.go`, `tools/testcerts/main_test.go`
- Create: `internal/certs/certs.go` (parse, fingerprints), `internal/certs/upload.go` (ValidateUpload, PFX, key parsing), `internal/certs/chain.go` (order, completeness, SAN matching), `internal/certs/csr.go`
- Test: `internal/certs/certs_test.go`, `internal/certs/upload_test.go`, `internal/certs/chain_test.go`, `internal/certs/csr_test.go`, `internal/certs/fuzz_test.go` (+ `internal/certs/testdata/fuzz/FuzzParseCertificateUpload/` seeds written by the test, see Step 9)
- Modify: `go.mod`, `go.sum` (`software.sslmate.com/src/go-pkcs12`), `internal/archtest/arch_test.go` (rule for `certs`; `inventory` may import it), `Makefile` (`fuzz-certs`)

**Interfaces:**
- Consumes: `secrets.Plaintext` (`NewPlaintext`, `Bytes`, `Zero`).
- Produces: the `certs` API of the contract; `pki`:

```go
package pki

type KeyType string

const (
	RSA1024  KeyType = "rsa1024" // weak, for refusal tests
	RSA2048  KeyType = "rsa2048"
	RSA3072  KeyType = "rsa3072"
	RSA4096  KeyType = "rsa4096"
	ECDSA256 KeyType = "ecdsa256"
	ECDSA384 KeyType = "ecdsa384"
	ECDSA521 KeyType = "ecdsa521" // unsupported curve
	Ed25519  KeyType = "ed25519"  // unsupported key type
)

type CA struct {
	Root, Intermediate       *x509.Certificate
	RootKey, IntermediateKey crypto.Signer
	RootPEM, IntermediatePEM []byte
}

type Opts struct {
	CommonName string
	SANs       []string
	KeyType    KeyType   // default ECDSA256
	NotBefore  time.Time // default now-1h
	NotAfter   time.Time // default now+90d
	Key        crypto.Signer // reuse a key (CSR completion tests)
}

type Leaf struct {
	Cert         *x509.Certificate
	Key          crypto.Signer
	CertPEM      []byte // leaf only
	FullchainPEM []byte // leaf + intermediate
	KeyPEM       []byte // PKCS#8 "PRIVATE KEY"
}

func NewCA(name string, kt KeyType, now time.Time) *CA          // panics on a crypto failure (test helper)
func (ca *CA) Issue(o Opts, now time.Time) Leaf
func SelfSigned(cn string, kt KeyType, now time.Time) Leaf
func NewKey(kt KeyType) crypto.Signer
func KeyPEMPKCS1(k *rsa.PrivateKey) []byte
func KeyPEMSEC1(k *ecdsa.PrivateKey) []byte
func EncryptedKeyPEM(l Leaf) []byte                 // a PEM block with "Proc-Type: 4,ENCRYPTED" (legacy encryption)
func PFX(l Leaf, ca *CA, password string) []byte     // pkcs12.Modern.Encode with the intermediate as CA cert
func CSRFor(cn string, sans []string, key crypto.Signer) *x509.CertificateRequest
func Fingerprint(c *x509.Certificate) string        // hex SHA-256 of the DER
```

- [ ] **Step 1: Add the dependency and the archtest rule**

Run: `go get software.sslmate.com/src/go-pkcs12@latest && go mod tidy`
Expected: `go.mod` lists `software.sslmate.com/src/go-pkcs12` (record the version in the commit message body).

In `internal/archtest/arch_test.go`: add `"alice/internal/certs/...": {platform, "alice/internal/secrets/..."},` to `rules`; append `"alice/internal/certs/..."` to the `alice/internal/inventory/...` list; and, because `platform` also covers `platform/db` while `certs` must stay pure, add `"alice/internal/certs/...": {"alice/internal/platform/db/..."},` to `denied` (as Phase 3 did for providers). Add two cases to the rules table test: `{"certs to secrets allowed", "alice/internal/certs", "alice/internal/secrets", true}` and `{"certs to platform/db denied", "alice/internal/certs", "alice/internal/platform/db", false}`.

Run: `go test ./internal/archtest -count=1` → PASS.

- [ ] **Step 2: Write the failing PKI tests**

Create `internal/testutil/pki/pki_test.go`:

```go
package pki

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"software.sslmate.com/src/go-pkcs12"
)

var now = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

func TestIssueBuildsAVerifiableChain(t *testing.T) {
	ca := NewCA("Alice Test", ECDSA256, now)
	l := ca.Issue(Opts{CommonName: "www.example.test", SANs: []string{"www.example.test", "example.test"}}, now)
	roots, inter := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(ca.Root)
	inter.AddCert(ca.Intermediate)
	_, err := l.Cert.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: now, DNSName: "example.test"})
	require.NoError(t, err)
	b, _ := pem.Decode(l.KeyPEM)
	require.NotNil(t, b)
	assert.Equal(t, "PRIVATE KEY", b.Type)
	blocks := 0
	for rest := l.FullchainPEM; ; {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		blocks++
	}
	assert.Equal(t, 2, blocks)
	assert.Len(t, Fingerprint(l.Cert), 64)
}

func TestKeyTypesAndValidity(t *testing.T) {
	ca := NewCA("Alice Test", RSA2048, now)
	for _, kt := range []KeyType{RSA1024, RSA2048, RSA3072, ECDSA256, ECDSA384, ECDSA521, Ed25519} {
		l := ca.Issue(Opts{CommonName: "x.example.test", KeyType: kt}, now)
		assert.NotNil(t, l.Key, kt)
	}
	exp := ca.Issue(Opts{CommonName: "old.example.test", NotBefore: now.AddDate(0, -3, 0), NotAfter: now.AddDate(0, 0, -1)}, now)
	assert.True(t, exp.Cert.NotAfter.Before(now))
}

func TestPFXRoundTrip(t *testing.T) {
	ca := NewCA("Alice Test", ECDSA256, now)
	l := ca.Issue(Opts{CommonName: "www.example.test"}, now)
	key, cert, cas, err := pkcs12.DecodeChain(PFX(l, ca, "pw"), "pw")
	require.NoError(t, err)
	assert.NotNil(t, key)
	assert.Equal(t, l.Cert.Raw, cert.Raw)
	require.Len(t, cas, 1)
	_, _, _, err = pkcs12.DecodeChain(PFX(l, ca, "pw"), "wrong")
	assert.Error(t, err)
}

func TestEncryptedKeyPEMIsMarked(t *testing.T) {
	ca := NewCA("Alice Test", RSA2048, now)
	b, _ := pem.Decode(EncryptedKeyPEM(ca.Issue(Opts{CommonName: "x", KeyType: RSA2048}, now)))
	require.NotNil(t, b)
	assert.Equal(t, "4,ENCRYPTED", b.Headers["Proc-Type"])
}
```

Run: `go test ./internal/testutil/pki -count=1` → FAIL (no package).

- [ ] **Step 3: Implement `pki`**

Create `internal/testutil/pki/pki.go` with the API above. Key points (every crypto error panics with a short message; this is a test helper):
- `NewKey`: RSA via `rsa.GenerateKey(rand.Reader, bits)`; ECDSA via `ecdsa.GenerateKey(elliptic.P256()|P384()|P521(), rand.Reader)`; Ed25519 via `ed25519.GenerateKey` (wrap the private key, which implements `crypto.Signer`).
- `NewCA`: root (self-signed, `IsCA`, `BasicConstraintsValid`, `KeyUsageCertSign|KeyUsageCRLSign`, 10 years from `now-1h`), intermediate signed by the root (5 years), both with random 128-bit serials (`rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))`), `SubjectKeyId` set, CN `name + " Root"`/`name + " Intermediate"`.
- `Issue`: leaf with `ExtKeyUsageServerAuth`, `KeyUsageDigitalSignature` (plus `KeyUsageKeyEncipherment` for RSA), DNS SANs (entries that `net.ParseIP` accepts go to `IPAddresses`), signed by the intermediate with the default algorithm. (No SHA-1 fixture: the standard library does not create SHA-1 signatures; `certs` checks the signature algorithm field, which Step 5's `TestWeakSignatureAlgorithms` tests directly.)
- `KeyPEM` is PKCS#8 (`x509.MarshalPKCS8PrivateKey`), `KeyPEMPKCS1` and `KeyPEMSEC1` the other encodings.
- `EncryptedKeyPEM`: a `pem.Block{Type: "RSA PRIVATE KEY", Headers: {"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-256-CBC,00112233445566778899AABBCCDDEEFF"}, Bytes: <random 256 bytes>}` (Alice must refuse it before trying to decrypt; the content need not be a real encryption).
- `PFX`: `pkcs12.Modern.Encode(l.Key, l.Cert, []*x509.Certificate{ca.Intermediate}, password)`.
- `CSRFor`: `x509.CreateCertificateRequest` then `x509.ParseCertificateRequest`.
- Never write a file; never log key material.

Run: `go test ./internal/testutil/pki -count=1` → PASS.

- [ ] **Step 4: Owner test pack, failing test first**

Create `tools/testcerts/main_test.go`:

```go
package main

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWritesAGoodAndABrokenPair(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pack")
	require.NoError(t, run([]string{"-out", dir, "-name", "www.example.test"}, os.Stdout))
	for _, f := range []string{"ca.pem", "good.pem", "good.key", "good.pfx", "broken.pem", "broken.key"} {
		st, err := os.Stat(filepath.Join(dir, f))
		require.NoError(t, err, f)
		assert.Equal(t, os.FileMode(0o600), st.Mode().Perm(), f)
	}
	_, err := tls.LoadX509KeyPair(filepath.Join(dir, "good.pem"), filepath.Join(dir, "good.key"))
	assert.NoError(t, err, "the good pair belongs together")
	_, err = tls.LoadX509KeyPair(filepath.Join(dir, "broken.pem"), filepath.Join(dir, "broken.key"))
	assert.Error(t, err, "the broken pair does not")
	assert.Error(t, run([]string{"-out", dir, "-name", "www.example.test"}, os.Stdout), "an existing directory is refused")
}
```

Run: `go test ./tools/testcerts -count=1` → FAIL. Implement `tools/testcerts/main.go`: `func main() { if err := run(os.Args[1:], os.Stdout); err != nil { … os.Exit(1) } }` (write errors to `os.Stderr` with `fmt.Fprintln(os.Stderr, …)` — `fmt.Fprint*` to an explicit writer is allowed); `run` parses `-out` and `-name` with a `flag.FlagSet`, refuses an existing `-out` (`os.Mkdir(out, 0o700)` must succeed), uses `pki.NewCA("Alice Test Pack", pki.ECDSA256, time.Now())` (`//nolint:forbidigo // a developer tool, not product code`), writes the six files with `os.WriteFile(…, 0o600)` — `good.pem` is the leaf, the intermediate and the root (a complete chain, so the owner's deploy needs no chain confirmation), `broken.pem` the same chain of another leaf —, `good.pfx` with password `alice-test`, and prints one line per file. Run the test → PASS.

- [ ] **Step 5: Write the failing `certs` tests**

Create `internal/certs/upload_test.go`:

```go
package certs

import (
	"bytes"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/testutil/pki"
)

var now = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

func rootsOf(ca *pki.CA) *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.Root)
	return p
}

// Review Focus 4: uploads as people really have them.
func TestValidateUploadTable(t *testing.T) {
	ca := pki.NewCA("Alice Test", pki.ECDSA256, now)
	rsaCA := pki.NewCA("Alice RSA", pki.RSA2048, now)
	good := ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, now)
	other := ca.Issue(pki.Opts{CommonName: "other.example.test"}, now)
	expired := ca.Issue(pki.Opts{CommonName: "old.example.test", NotBefore: now.AddDate(0, -3, 0), NotAfter: now.Add(-24 * time.Hour)}, now)
	future := ca.Issue(pki.Opts{CommonName: "soon.example.test", NotBefore: now.Add(48 * time.Hour), NotAfter: now.AddDate(0, 3, 0)}, now)
	weak := rsaCA.Issue(pki.Opts{CommonName: "weak.example.test", KeyType: pki.RSA1024}, now)
	p521 := ca.Issue(pki.Opts{CommonName: "p521.example.test", KeyType: pki.ECDSA521}, now)
	ed := ca.Issue(pki.Opts{CommonName: "ed.example.test", KeyType: pki.Ed25519}, now)
	crlf := bytes.ReplaceAll(good.FullchainPEM, []byte("\n"), []byte("\r\n"))
	bom := append([]byte("\xef\xbb\xbf"), good.FullchainPEM...)
	reversed := append(append([]byte{}, ca.IntermediatePEM...), good.CertPEM...)
	withRoot := append(append([]byte{}, good.FullchainPEM...), ca.RootPEM...)
	twoKeys := append(append([]byte{}, good.KeyPEM...), other.KeyPEM...)

	for _, tc := range []struct {
		name     string
		in       Upload
		err      error
		complete bool
		warnings []string
	}{
		{"fullchain and key", Upload{CertificatePEM: good.FullchainPEM, PrivateKeyPEM: good.KeyPEM}, nil, true, nil},
		{"CRLF line endings", Upload{CertificatePEM: crlf, PrivateKeyPEM: good.KeyPEM}, nil, true, nil},
		{"UTF-8 BOM", Upload{CertificatePEM: bom, PrivateKeyPEM: good.KeyPEM}, nil, true, nil},
		{"chain before the leaf", Upload{CertificatePEM: reversed, PrivateKeyPEM: good.KeyPEM}, nil, true, nil},
		{"root included", Upload{CertificatePEM: withRoot, PrivateKeyPEM: good.KeyPEM}, nil, true, nil},
		{"leaf only", Upload{CertificatePEM: good.CertPEM, PrivateKeyPEM: good.KeyPEM}, nil, false, []string{"chain_incomplete"}},
		{"SEC1 key", Upload{CertificatePEM: good.FullchainPEM, PrivateKeyPEM: pki.KeyPEMSEC1(mustEC(t, good))}, nil, true, nil},
		{"PFX with password", Upload{PFX: pki.PFX(good, ca, "pw"), PFXPassword: "pw"}, nil, true, nil},
		{"PFX with empty password", Upload{PFX: pki.PFX(good, ca, ""), PFXPassword: ""}, nil, true, nil},
		{"not yet valid", Upload{CertificatePEM: future.FullchainPEM, PrivateKeyPEM: future.KeyPEM}, nil, true, []string{"not_yet_valid"}},
		{"key of another certificate", Upload{CertificatePEM: good.FullchainPEM, PrivateKeyPEM: other.KeyPEM}, ErrKeyMismatch, false, nil},
		{"expired", Upload{CertificatePEM: expired.FullchainPEM, PrivateKeyPEM: expired.KeyPEM}, ErrExpired, false, nil},
		{"PFX wrong password", Upload{PFX: pki.PFX(good, ca, "pw"), PFXPassword: "nope"}, ErrPFXPassword, false, nil},
		{"encrypted PEM key", Upload{CertificatePEM: good.FullchainPEM, PrivateKeyPEM: pki.EncryptedKeyPEM(weak)}, ErrKeyEncrypted, false, nil},
		{"RSA 1024", Upload{CertificatePEM: weak.FullchainPEM, PrivateKeyPEM: weak.KeyPEM}, ErrWeak, false, nil},
		{"P-521", Upload{CertificatePEM: p521.FullchainPEM, PrivateKeyPEM: p521.KeyPEM}, ErrUnsupportedKey, false, nil},
		{"Ed25519", Upload{CertificatePEM: ed.FullchainPEM, PrivateKeyPEM: ed.KeyPEM}, ErrUnsupportedKey, false, nil},
		{"two private keys", Upload{CertificatePEM: good.FullchainPEM, PrivateKeyPEM: twoKeys}, ErrInvalid, false, nil},
		{"no key", Upload{CertificatePEM: good.FullchainPEM}, ErrNoKey, false, nil},
		{"garbage", Upload{CertificatePEM: []byte("hello"), PrivateKeyPEM: good.KeyPEM}, ErrInvalid, false, nil},
		{"a key in the certificate field", Upload{CertificatePEM: good.KeyPEM, PrivateKeyPEM: good.KeyPEM}, ErrInvalid, false, nil},
		{"too large", Upload{CertificatePEM: bytes.Repeat([]byte("a"), MaxInputSize+1), PrivateKeyPEM: good.KeyPEM}, ErrTooLarge, false, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, err := ValidateUpload(tc.in, now, rootsOf(ca))
			if tc.err != nil {
				require.True(t, errors.Is(err, tc.err), "got %v", err)
				return
			}
			require.NoError(t, err)
			defer v.PrivateKeyDER.Zero()
			assert.Equal(t, pki.Fingerprint(good.Cert) == v.Fingerprint || tc.name == "not yet valid", true)
			assert.Equal(t, tc.complete, v.ChainComplete)
			assert.Equal(t, tc.warnings, v.Warnings)
			assert.True(t, strings.HasPrefix(v.PEMChain, "-----BEGIN CERTIFICATE-----\n"), "re-encoded, leaf first")
			assert.NotContains(t, v.PEMChain, "PRIVATE KEY")
		})
	}
}

func TestValidatedFieldsOfAnRSALeaf(t *testing.T) {
	ca := pki.NewCA("Alice RSA", pki.RSA2048, now)
	l := ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test", "10.0.0.5"}, KeyType: pki.RSA3072}, now)
	v, err := ValidateUpload(Upload{CertificatePEM: l.FullchainPEM, PrivateKeyPEM: l.KeyPEM}, now, rootsOf(ca))
	require.NoError(t, err)
	defer v.PrivateKeyDER.Zero()
	assert.Equal(t, "rsa", v.Algorithm)
	assert.Equal(t, 3072, v.Bits)
	assert.Equal(t, "www.example.test", v.SubjectCN)
	assert.Equal(t, []string{"www.example.test", "10.0.0.5"}, v.SANs)
	assert.Len(t, v.Chain, 1)
	assert.Len(t, v.PublicKeySHA256, 64)
	assert.Regexp(t, `^[0-9A-F]+$`, v.Serial)
	info, err := KeyInfoOf(v.PrivateKeyDER)
	require.NoError(t, err)
	assert.Equal(t, KeyInfo{Algorithm: "rsa", Bits: 3072, PublicKeySHA256: v.PublicKeySHA256}, info)
}
```

(`mustEC(t, l)` is a small helper in the test file: `k, ok := l.Key.(*ecdsa.PrivateKey); require.True(t, ok); return k`.)

Create `internal/certs/chain_test.go`:

```go
func TestParseChainPEMTakesCertificatesOnly(t *testing.T) {
	ca := pki.NewCA("Alice Test", pki.ECDSA256, now)
	l := ca.Issue(pki.Opts{CommonName: "www.example.test"}, now)
	mixed := append(append([]byte{}, l.FullchainPEM...), l.KeyPEM...)
	p, err := ParseChainPEM(mixed)
	require.NoError(t, err)
	assert.Equal(t, pki.Fingerprint(l.Cert), p.Fingerprint, "the first CERTIFICATE block is the leaf")
	assert.NotContains(t, p.PEMChain, "PRIVATE KEY")
	_, err = ParseChainPEM(l.KeyPEM)
	assert.ErrorIs(t, err, ErrInvalid)
}

// §22.6 "SHA-1 signature": the leaf and every intermediate are checked by algorithm.
func TestWeakSignatureAlgorithms(t *testing.T) {
	for alg, weak := range map[x509.SignatureAlgorithm]bool{
		x509.MD5WithRSA: true, x509.SHA1WithRSA: true, x509.ECDSAWithSHA1: true, x509.DSAWithSHA1: true, x509.DSAWithSHA256: true,
		x509.SHA256WithRSA: false, x509.ECDSAWithSHA384: false, x509.SHA256WithRSAPSS: false, x509.PureEd25519: false,
	} {
		assert.Equal(t, weak, weakSignature(&x509.Certificate{SignatureAlgorithm: alg}), alg.String())
	}
}

func TestSANMatches(t *testing.T) {
	sans := []string{"www.example.test", "*.shop.example.test"}
	for name, want := range map[string]bool{
		"www.example.test": true, "WWW.Example.TEST": true, "a.shop.example.test": true, "shop.example.test": false,
		"a.b.shop.example.test": false, "example.test": false, "": false,
	} {
		assert.Equal(t, want, SANMatches(sans, name), name)
	}
}

func TestChainCompleteWithSystemRootsOrSelfSigned(t *testing.T) {
	ca := pki.NewCA("Alice Test", pki.ECDSA256, now)
	l := ca.Issue(pki.Opts{CommonName: "www.example.test"}, now)
	p, err := ParseChainPEM(l.FullchainPEM)
	require.NoError(t, err)
	assert.False(t, ChainComplete(p, x509.NewCertPool(), now), "the root is neither uploaded nor trusted")
	assert.True(t, ChainComplete(p, rootsOf(ca), now))
	self := pki.SelfSigned("self.example.test", pki.ECDSA256, now)
	ps, err := ParseChainPEM(self.CertPEM)
	require.NoError(t, err)
	assert.True(t, ps.SelfSigned)
	assert.True(t, ChainComplete(ps, x509.NewCertPool(), now), "a self-signed certificate is its own chain")
}
```

Create `internal/certs/csr_test.go`:

```go
func TestNewCSRAndValidateSigned(t *testing.T) {
	for _, kt := range []string{"ecdsa-p256", "rsa-3072", "rsa-4096"} {
		t.Run(kt, func(t *testing.T) {
			csrPEM, der, info, err := NewCSR(rand.Reader, CSRRequest{CommonName: "www.example.test", SANs: []string{"example.test"}, KeyType: kt})
			require.NoError(t, err)
			defer der.Zero()
			b, _ := pem.Decode([]byte(csrPEM))
			require.NotNil(t, b)
			require.Equal(t, "CERTIFICATE REQUEST", b.Type)
			csr, err := x509.ParseCertificateRequest(b.Bytes)
			require.NoError(t, err)
			require.NoError(t, csr.CheckSignature())
			assert.Equal(t, []string{"www.example.test", "example.test"}, csr.DNSNames, "the common name is also a SAN")
			key, err := x509.ParsePKCS8PrivateKey(der.Bytes())
			require.NoError(t, err)
			ca := pki.NewCA("Alice Test", pki.ECDSA256, now)
			signed := ca.Issue(pki.Opts{CommonName: "www.example.test", Key: key.(crypto.Signer)}, now)
			p, complete, err := ValidateSigned(signed.FullchainPEM, info, now, rootsOf(ca))
			require.NoError(t, err)
			assert.True(t, complete)
			assert.Equal(t, info.PublicKeySHA256, p.PublicKeySHA256)
			other := ca.Issue(pki.Opts{CommonName: "www.example.test"}, now)
			_, _, err = ValidateSigned(other.FullchainPEM, info, now, rootsOf(ca))
			assert.ErrorIs(t, err, ErrCSRMismatch)
		})
	}
	_, _, _, err := NewCSR(rand.Reader, CSRRequest{CommonName: "bad name", KeyType: "ecdsa-p256"})
	assert.ErrorIs(t, err, ErrInvalid)
	_, _, _, err = NewCSR(rand.Reader, CSRRequest{CommonName: "x.example.test", KeyType: "rsa-1024"})
	assert.ErrorIs(t, err, ErrUnsupportedKey)
}

func TestKeyPEMIsPKCS8(t *testing.T) {
	_, der, _, err := NewCSR(rand.Reader, CSRRequest{CommonName: "x.example.test", KeyType: "ecdsa-p256"})
	require.NoError(t, err)
	p, err := KeyPEM(der)
	require.NoError(t, err)
	defer p.Zero()
	b, _ := pem.Decode(p.Bytes())
	require.NotNil(t, b)
	assert.Equal(t, "PRIVATE KEY", b.Type)
	assert.Equal(t, "[redacted]", fmt.Sprint(p), "the key never prints")
}

func TestValidDNSName(t *testing.T) {
	for in, want := range map[string]bool{"www.example.test": true, "*.example.test": true, "a-b.c": true, "localhost": true,
		"": false, "bad name": false, "a..b": false, "-a.b": false, "a.b-": false, "*.*.b": false, "a.*.b": false,
		"ÖRNEK.com": false, strings.Repeat("a", 64) + ".b": false} {
		assert.Equal(t, want, ValidDNSName(in), in)
	}
}
```

Run: `go test ./internal/certs -count=1` → FAIL (no package).

- [ ] **Step 6: Implement `certs`**

Rules the code must follow (complete list; the tests above pin each one):

`certs.go`:
- `ParseChainPEM(data)`: strip a leading UTF-8 BOM, normalise `\r\n` to `\n`, cap at `MaxInputSize` (`ErrTooLarge`); decode every PEM block in order, keep only `Type == "CERTIFICATE"` with `x509.ParseCertificate` success (a block that fails to parse makes the whole input `ErrInvalid`); none → `ErrInvalid`; the first is the leaf; `Chain` = the rest in file order; fill `Parsed` with `describe(leaf)`.
- `describe(c)`: `Fingerprint` = hex `sha256.Sum256(c.Raw)`; `PublicKeySHA256` = hex SHA-256 of `c.RawSubjectPublicKeyInfo`; `Algorithm`/`Bits`: `*rsa.PublicKey` → `rsa`, `N.BitLen()`; `*ecdsa.PublicKey` → `ecdsa`, `Curve.Params().BitSize`; `ed25519.PublicKey` → `ed25519`, 256; else `other`, 0; `SubjectCN = c.Subject.CommonName`; `Subject = c.Subject.String()`, `Issuer = c.Issuer.String()`; `Serial = fmt.Sprintf("%X", c.SerialNumber)`; `SANs` = `c.DNSNames` then each `c.IPAddresses[i].String()`; `SelfSigned` = `bytes.Equal(c.RawIssuer, c.RawSubject) && c.CheckSignatureFrom(c) == nil`; `PEMChain` = `pem.EncodeToMemory` of the leaf then the chain.

`upload.go`, `ValidateUpload(u, now, roots)`:
1. Exactly one source: PFX (`len(u.PFX) > 0`) or PEM fields; each input ≤ `MaxInputSize` (`ErrTooLarge`).
2. PFX: `pkcs12.DecodeChain(u.PFX, u.PFXPassword)`; `errors.Is(err, pkcs12.ErrIncorrectPassword)` or any decode error → `ErrPFXPassword`; certificates = leaf + CA certs; key = the returned key.
3. PEM: certificates from `u.CertificatePEM` as in `ParseChainPEM` but without taking the first as the leaf; `u.PrivateKeyPEM` empty → `ErrNoKey`; decode its blocks: any block with `Proc-Type: 4,ENCRYPTED` header or type `ENCRYPTED PRIVATE KEY` → `ErrKeyEncrypted`; private-key blocks are `PRIVATE KEY` (PKCS#8), `RSA PRIVATE KEY` (PKCS#1), `EC PRIVATE KEY` (SEC1; skip `EC PARAMETERS` blocks); zero or more than one key block → `ErrInvalid` (zero with other content), `ErrNoKey` (empty after trimming); a parse failure → `ErrInvalid`. A certificate field whose blocks include no `CERTIFICATE` → `ErrInvalid`.
4. Key checks: `*rsa.PrivateKey` with `N.BitLen() < 2048` → `ErrWeak`; `*ecdsa.PrivateKey` with a curve other than P-256/P-384 → `ErrUnsupportedKey`; `ed25519.PrivateKey` or another type → `ErrUnsupportedKey`.
5. Leaf = the certificate whose public key equals the key's public key (`pub.Equal`); none → `ErrKeyMismatch`. Chain = order the remaining certificates from the leaf by `CheckSignatureFrom` (issuer of the current is the next whose `RawSubject` equals the current's `RawIssuer` and whose signature verifies); certificates not on the path are dropped; a self-signed root at the end is kept.
6. Signatures: `weakSignature(c *x509.Certificate) bool` is true for `MD2WithRSA`, `MD5WithRSA`, `SHA1WithRSA`, `ECDSAWithSHA1`, `DSAWithSHA1`, `DSAWithSHA256`; the leaf or any non-self-signed chain certificate with a weak signature → `ErrWeak`.
7. Validity: `!now.Before(leaf.NotAfter)` → `ErrExpired`; `now.Before(leaf.NotBefore)` → warning `not_yet_valid`.
8. `ChainComplete(p, roots, now)` false → warning `chain_incomplete`.
9. `PrivateKeyDER` = `x509.MarshalPKCS8PrivateKey(key)` wrapped in `secrets.NewPlaintext`; every intermediate buffer holding key bytes is cleared with `clear(...)` before return.
- `KeyInfoOf(der)`: parse PKCS#8, algorithm/bits as above, `PublicKeySHA256` = hex SHA-256 of `x509.MarshalPKIXPublicKey(pub)`.
- `KeyPEM(der)`: `pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der.Bytes()})` in a new `Plaintext`.

`chain.go`:
- `ChainComplete`: true when the last certificate of leaf+chain is self-signed, or `leaf.Verify(x509.VerifyOptions{Roots: roots (plus nothing), Intermediates: pool of p.Chain, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})` succeeds.
- `SystemRoots()`: `x509.SystemCertPool()`; on error an empty `x509.NewCertPool()`.
- `SANMatches(sans, name)`: case-insensitive ASCII compare (`strings.EqualFold`), a SAN `*.rest` matches exactly one extra left-most label (`name` has a dot, its part after the first dot equals `rest`, and the first label is not empty); `""` never matches.

`csr.go`:
- `ValidDNSName(s)`: 1..253 bytes; optional leading `*.`; labels 1..63 of `[a-z0-9-]` (ASCII lower case only; reject upper case — the API lower-cases input with `strings.EqualFold`-safe ASCII folding before calling), not starting or ending with `-`, no empty label.
- `NewCSR`: common name and each SAN must pass `ValidDNSName` (else `ErrInvalid`); key types `ecdsa-p256` (P-256), `rsa-3072`, `rsa-4096`, anything else `ErrUnsupportedKey`; keys from `rnd`; template `Subject: {CommonName}`, `DNSNames` = common name first then the SANs without duplicates; `x509.CreateCertificateRequest(rnd, …)`; returns the PEM (`CERTIFICATE REQUEST`), the PKCS#8 DER as `Plaintext` and `KeyInfoOf`.
- `ValidateSigned(certPEM, key, now, roots)`: `ParseChainPEM`; the leaf's `PublicKeySHA256` must equal `key.PublicKeySHA256` (`ErrCSRMismatch`); weak signatures, expiry and key checks as in `ValidateUpload` (steps 4, 6, 7 on the leaf's public key); returns the parsed chain (re-ordered from the leaf) and `ChainComplete`.

Run: `go test ./internal/certs -count=1`
Expected: PASS.

- [ ] **Step 7: Leak-safety test**

Add to `internal/certs/upload_test.go`:

```go
// SEC-044: errors and the validated value never render key material.
func TestNothingPrintsTheKey(t *testing.T) {
	ca := pki.NewCA("Alice Test", pki.ECDSA256, now)
	l := ca.Issue(pki.Opts{CommonName: "www.example.test"}, now)
	other := ca.Issue(pki.Opts{CommonName: "other.example.test"}, now)
	v, err := ValidateUpload(Upload{CertificatePEM: l.FullchainPEM, PrivateKeyPEM: l.KeyPEM}, now, rootsOf(ca))
	require.NoError(t, err)
	out := fmt.Sprintf("%v %+v %#v", v, v, v)
	marker := "PRIVATE" + " KEY"
	assert.NotContains(t, out, marker)
	assert.NotContains(t, out, string(l.KeyPEM[40:80]))
	_, err = ValidateUpload(Upload{CertificatePEM: l.FullchainPEM, PrivateKeyPEM: other.KeyPEM}, now, rootsOf(ca))
	assert.NotContains(t, err.Error(), string(other.KeyPEM[40:80]))
	v.PrivateKeyDER.Zero()
	assert.Equal(t, make([]byte, len(v.PrivateKeyDER.Bytes())), v.PrivateKeyDER.Bytes(), "Zero clears the key")
}
```

Run it → PASS (fix `Validated`'s printing if not: it embeds `Parsed` (public) and `Plaintext` (redacts)).

- [ ] **Step 8: Fuzz target, failing first**

Create `internal/certs/fuzz_test.go`:

```go
// §25.6 FuzzParseCertificateUpload: hostile PEM/PFX/DER never panics, never takes unbounded
// memory, and never accepts a pair whose key does not match.
func FuzzParseCertificateUpload(f *testing.F) {
	ca := pki.NewCA("Alice Fuzz", pki.ECDSA256, now)
	l := ca.Issue(pki.Opts{CommonName: "www.example.test"}, now)
	f.Add(l.FullchainPEM, l.KeyPEM, []byte(nil), "")
	f.Add([]byte(nil), []byte(nil), pki.PFX(l, ca, "pw"), "pw")
	f.Add([]byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"), l.KeyPEM, []byte(nil), "")
	f.Add(l.Cert.Raw, l.KeyPEM, []byte(nil), "")
	f.Fuzz(func(t *testing.T, cert, key, pfx []byte, pw string) {
		v, err := ValidateUpload(Upload{CertificatePEM: cert, PrivateKeyPEM: key, PFX: pfx, PFXPassword: pw}, now, x509.NewCertPool())
		if err != nil {
			return
		}
		defer v.PrivateKeyDER.Zero()
		info, err := KeyInfoOf(v.PrivateKeyDER)
		if err != nil || info.PublicKeySHA256 != v.PublicKeySHA256 {
			t.Fatalf("accepted a key that does not match the leaf")
		}
	})
}
```

Run: `go test ./internal/certs -run FuzzParseCertificateUpload -count=1` → PASS (seed corpus). Then `go test ./internal/certs -run '^$' -fuzz FuzzParseCertificateUpload -fuzztime 60s` → no crasher (commit any crasher in `testdata/fuzz/` as a regression input after fixing). Add to the `Makefile` after `fuzz-ssh`:

```make
.PHONY: fuzz-certs
fuzz-certs: ## Fuzz the certificate upload parser for 60 s (spec §25.6)
	go test -count=1 -run '^$$' -fuzz FuzzParseCertificateUpload -fuzztime 60s ./internal/certs/
```

- [ ] **Step 9: Full check and commit**

Run: `make lint && go test ./internal/certs ./internal/testutil/pki ./tools/testcerts ./internal/archtest -count=1 && make secrets-scan`
Expected: all pass; the secrets scan finds nothing (no key is committed).

```bash
git add go.mod go.sum internal/testutil/pki internal/certs tools/testcerts internal/archtest/arch_test.go Makefile
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "feat(certs): validate uploads, PFX, chains and signing requests; generated test PKI and owner test pack

Adds software.sslmate.com/src/go-pkcs12 (R23).

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 3: Pure `nginx -T` parser `nginxconf` with fixtures and `FuzzParseNginxConfig`

The helper (Tasks 5–6) decides which files it may read and write from its own parse of `nginx -T`, so the parser is security-relevant and is fuzzed (§25.6). It follows spec §12.4 step 2–4: a tokenizer for comments, single/double quoted strings with escapes, `;`, `{`, `}` and `${var}`; the `# configuration file <path>:` markers of `-T`; a block tree; `http > server` and `stream > server`; `ssl_certificate`/`ssl_certificate_key` inherited from `http` when a server has none; pairing by index; SSL listens (the `ssl` flag, or every listen with `ssl on;`); and the unsupported constructs of §12.4 step 4 plus R38 item 4. It imports only the standard library and `helperproto` (for `ValidPath`).

**Files:**
- Create: `internal/providers/nginx/nginxconf/nginxconf.go`
- Create: `test/testdata/nginx/` fixtures: `single.conf`, `many.conf`, `includes.conf`, `variables.conf`, `stream.conf`, `whitespace.conf`, `inherited.conf`, `dual.conf`, `shared.conf`, `listen-forms.conf`, `relative.conf`, `password.conf`, `combined.conf`, `letsencrypt.conf`, `space-path.conf`
- Test: `internal/providers/nginx/nginxconf/nginxconf_test.go`, `internal/providers/nginx/nginxconf/fuzz_test.go`
- Modify: `Makefile` (`fuzz-nginx`)

**Interfaces:**
- Consumes: `helperproto.ValidPath`, `helperproto.WarnStreamTLS`.
- Produces: the `nginxconf` API of the contract (used by the helper in Tasks 5–6 and by the fuzz target).

- [ ] **Step 1: Write the fixtures**

Each fixture is the stdout of `nginx -T` (the "syntax is ok" lines go to stderr and are not part of it). Create them exactly; the first three in full here, the rest as described (one or two server blocks each, `# configuration file` markers as `nginx -T` prints them).

`test/testdata/nginx/single.conf`:

```nginx
# configuration file /etc/nginx/nginx.conf:
user www-data;
events { worker_connections 768; }
http {
    include /etc/nginx/conf.d/*.conf;
}

# configuration file /etc/nginx/conf.d/www.conf:
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name www.example.test example.test;
    ssl_certificate /etc/nginx/ssl/www.crt;
    ssl_certificate_key /etc/nginx/ssl/www.key;
    location / { root /var/www/html; }
}
server {
    listen 80;
    server_name www.example.test;
    return 301 https://$host$request_uri;
}
```

`test/testdata/nginx/letsencrypt.conf`:

```nginx
# configuration file /etc/nginx/nginx.conf:
http {
    include /etc/nginx/sites-enabled/*;
}

# configuration file /etc/nginx/sites-enabled/shop:
server {
    listen 443 ssl;
    server_name shop.example.test;
    ssl_certificate /etc/letsencrypt/live/shop.example.test/fullchain.pem; # managed by Certbot
    ssl_certificate_key /etc/letsencrypt/live/shop.example.test/privkey.pem; # managed by Certbot
    include /etc/letsencrypt/options-ssl-nginx.conf;
}

# configuration file /etc/letsencrypt/options-ssl-nginx.conf:
ssl_session_cache shared:le_nginx_SSL:10m;
ssl_protocols TLSv1.2 TLSv1.3;
```

`test/testdata/nginx/whitespace.conf`:

```nginx
# configuration file /etc/nginx/nginx.conf:
http{server{listen 8443   ssl  default_server;server_name
    "quoted.example.test"   'single.example.test'  ;  # trailing comment with { and } and ;
ssl_certificate   "/etc/nginx/ssl/q.crt"  ;
ssl_certificate_key '/etc/nginx/ssl/q.key';
add_header X-Note "a \"quoted\" value; with { braces }";
}}
```

The others:
- `many.conf`: 3 server blocks in 2 files, each with its own pair (`/etc/ssl/certs/a.pem`+`/etc/ssl/private/a.key`, `b`, `c`), one with `listen 443 ssl default_server;` and `server_name _;`.
- `includes.conf`: `nginx.conf` with `include conf.d/*.conf;` followed by two files `conf.d/one.conf`, `conf.d/two.conf` (markers), each a server; checks `Server.File` and `Server.Line` (line of `server` within its file).
- `variables.conf`: `ssl_certificate /etc/nginx/ssl/$ssl_server_name.crt; ssl_certificate_key /etc/nginx/ssl/${ssl_server_name}.key;` → one pair, `Unsupported: variable`, `CertRaw` kept.
- `stream.conf`: an `http` server with a normal pair and `stream { server { listen 993 ssl; ssl_certificate /etc/ssl/mail.crt; ssl_certificate_key /etc/ssl/mail.key; proxy_pass imap; } }` → the stream server is listed with `Stream: true`, its pair `Unsupported: stream`, warning `stream_tls`.
- `inherited.conf`: `http { ssl_certificate /etc/nginx/ssl/all.crt; ssl_certificate_key /etc/nginx/ssl/all.key; server { listen 443 ssl; server_name a.example.test; } server { listen 443 ssl; server_name b.example.test; ssl_certificate /etc/nginx/ssl/b.crt; ssl_certificate_key /etc/nginx/ssl/b.key; } server { listen 80; server_name c.example.test; } }` → `a` inherits (`Inherited: true`), `b` has its own, `c` is skipped (no SSL listen).
- `dual.conf`: one server with `ssl_certificate /etc/nginx/ssl/rsa.crt; ssl_certificate_key /etc/nginx/ssl/rsa.key; ssl_certificate /etc/nginx/ssl/ec.crt; ssl_certificate_key /etc/nginx/ssl/ec.key;` → two pairs in order.
- `shared.conf`: three server blocks (`a`, `b`, `c.example.test`) using the same `/etc/nginx/ssl/shared.crt`/`.key` → three servers, `CertPaths()` = one path.
- `listen-forms.conf`: one server per form: `listen 443 ssl;`, `listen 10.0.0.5:8443 ssl;`, `listen [::1]:9443 ssl;`, `listen *:4443 ssl;`, `listen localhost:5443 ssl;`, `listen unix:/run/x.sock ssl;`, `listen 7443;` with `ssl on;`, `listen 6443 ssl default;`, `listen 70000 ssl;` (invalid, ignored).
- `relative.conf` (conf dir `/etc/nginx`): `ssl_certificate ssl/rel.crt; ssl_certificate_key ../nginx/ssl/rel.key;` → `/etc/nginx/ssl/rel.crt`, `/etc/nginx/ssl/rel.key`.
- `password.conf`: a server with a pair and `ssl_password_file /etc/nginx/pass.txt;` → `Unsupported: password_file`.
- `combined.conf`: `ssl_certificate /etc/nginx/ssl/both.pem; ssl_certificate_key /etc/nginx/ssl/both.pem;` → `Unsupported: combined_file`; plus a second server with `ssl_certificate_key engine:pkcs11:id_45;` → `engine_key`, and a third with `ssl_certificate data:$cert_pem;` → `data_value`, and a fourth with a certificate and no key → `key_missing`.
- `space-path.conf`: `ssl_certificate "/etc/nginx/my certs/a.crt"; ssl_certificate_key "/etc/nginx/my certs/a.key";` → `Unsupported: path_not_allowed`.

- [ ] **Step 2: Write the failing parser tests**

Create `internal/providers/nginx/nginxconf/nginxconf_test.go`:

```go
package nginxconf

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "test", "testdata", "nginx", name))
	require.NoError(t, err)
	return b
}

func parse(t *testing.T, name string) Config {
	t.Helper()
	c, err := Parse(fixture(t, name), "/etc/nginx")
	require.NoError(t, err)
	return c
}

func TestSingle(t *testing.T) {
	c := parse(t, "single.conf")
	require.Len(t, c.Servers, 1, "the port-80 redirect has no SSL listen")
	s := c.Servers[0]
	assert.Equal(t, "/etc/nginx/conf.d/www.conf", s.File)
	assert.Equal(t, 1, s.Line)
	assert.Equal(t, []string{"www.example.test", "example.test"}, s.Names)
	assert.Equal(t, []Listen{{Port: 443, SSL: true}, {Addr: "::", Port: 443, SSL: true}}, SSLListens(s))
	assert.Equal(t, []Pair{{Cert: "/etc/nginx/ssl/www.crt", Key: "/etc/nginx/ssl/www.key",
		CertRaw: "/etc/nginx/ssl/www.crt", KeyRaw: "/etc/nginx/ssl/www.key"}}, s.Pairs)
	assert.Equal(t, []string{"/etc/nginx/nginx.conf", "/etc/nginx/conf.d/www.conf"}, c.Files)
	assert.True(t, c.HasPair("/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key"))
	assert.False(t, c.HasPair("/etc/nginx/ssl/www.crt", "/etc/shadow"))
	assert.False(t, c.HasPair("/etc/nginx/ssl/www.key", "/etc/nginx/ssl/www.crt"), "order matters")
}

func TestFixtureTable(t *testing.T) {
	for _, tc := range []struct {
		file        string
		servers     int
		certPaths   []string
		unsupported []string // Unsupported of every pair, in order
		warnings    []string
	}{
		{"letsencrypt.conf", 1, []string{"/etc/letsencrypt/live/shop.example.test/fullchain.pem"}, []string{""}, nil},
		{"whitespace.conf", 1, []string{"/etc/nginx/ssl/q.crt"}, []string{""}, nil},
		{"many.conf", 3, []string{"/etc/ssl/certs/a.pem", "/etc/ssl/certs/b.pem", "/etc/ssl/certs/c.pem"}, []string{"", "", ""}, nil},
		{"includes.conf", 2, []string{"/etc/nginx/ssl/one.crt", "/etc/nginx/ssl/two.crt"}, []string{"", ""}, nil},
		{"variables.conf", 1, nil, []string{ReasonVariable}, nil},
		{"stream.conf", 2, []string{"/etc/nginx/ssl/www.crt"}, []string{"", ReasonStream}, []string{"stream_tls"}},
		{"inherited.conf", 2, []string{"/etc/nginx/ssl/all.crt", "/etc/nginx/ssl/b.crt"}, []string{"", ""}, nil},
		{"dual.conf", 1, []string{"/etc/nginx/ssl/rsa.crt", "/etc/nginx/ssl/ec.crt"}, []string{"", ""}, nil},
		{"shared.conf", 3, []string{"/etc/nginx/ssl/shared.crt"}, []string{"", "", ""}, nil},
		{"relative.conf", 1, []string{"/etc/nginx/ssl/rel.crt"}, []string{""}, nil},
		{"password.conf", 1, nil, []string{ReasonPasswordFile}, nil},
		{"combined.conf", 4, nil, []string{ReasonCombinedFile, ReasonEngineKey, ReasonDataValue, ReasonKeyMissing}, nil},
		{"space-path.conf", 1, nil, []string{ReasonPathNotAllowed}, nil},
	} {
		t.Run(tc.file, func(t *testing.T) {
			c := parse(t, tc.file)
			assert.Len(t, c.Servers, tc.servers)
			assert.Equal(t, tc.certPaths, c.CertPaths())
			var reasons []string
			for _, s := range c.Servers {
				for _, p := range s.Pairs {
					reasons = append(reasons, p.Unsupported)
				}
			}
			assert.Equal(t, tc.unsupported, reasons)
			assert.Equal(t, tc.warnings, c.Warnings)
		})
	}
}

func TestInheritedPairIsMarked(t *testing.T) {
	c := parse(t, "inherited.conf")
	assert.True(t, c.Servers[0].Pairs[0].Inherited)
	assert.False(t, c.Servers[1].Pairs[0].Inherited)
}

func TestListenForms(t *testing.T) {
	c := parse(t, "listen-forms.conf")
	var got []Listen
	for _, s := range c.Servers {
		got = append(got, SSLListens(s)...)
	}
	assert.Equal(t, []Listen{
		{Port: 443, SSL: true}, {Addr: "10.0.0.5", Port: 8443, SSL: true}, {Addr: "::1", Port: 9443, SSL: true},
		{Port: 4443, SSL: true}, {Addr: "localhost", Port: 5443, SSL: true}, {Port: 7443, SSL: true},
		{Port: 6443, SSL: true, DefaultServer: true},
	}, got, "unix sockets and invalid ports are ignored; ssl on makes every listen SSL")
}

func TestServerLinesAreWithinTheirFile(t *testing.T) {
	c := parse(t, "includes.conf")
	assert.Equal(t, "/etc/nginx/conf.d/one.conf", c.Servers[0].File)
	assert.Equal(t, "/etc/nginx/conf.d/two.conf", c.Servers[1].File)
	assert.Equal(t, 1, c.Servers[1].Line)
}

func TestLimitsAndSyntax(t *testing.T) {
	for _, tc := range []struct {
		in  string
		err error
	}{
		{strings.Repeat("a", MaxInput+1), ErrTooLarge},
		{"http {" + strings.Repeat("x {", MaxDepth) + strings.Repeat("}", MaxDepth) + "}", ErrTooDeep},
		{"http { server { listen 443 ssl; ", ErrSyntax},
		{"http { } }", ErrSyntax},
		{`http { server_name "unterminated; }`, ErrSyntax},
		{"http { listen 443 ssl }", ErrSyntax},
		{"# x\n" + strings.Repeat("a", MaxLine+1) + ";", ErrLineTooLong},
	} {
		_, err := Parse([]byte(tc.in), "/etc/nginx")
		assert.True(t, errors.Is(err, tc.err), "%.40q: %v", tc.in, err)
	}
	c, err := Parse([]byte(""), "/etc/nginx")
	require.NoError(t, err)
	assert.Empty(t, c.Servers)
}

func TestEscapesAndQuotedSemicolons(t *testing.T) {
	c, err := Parse([]byte(`http { server { listen 443 ssl; server_name "a;b" 'c\'d' e\;f;
ssl_certificate /etc/nginx/ssl/x.crt; ssl_certificate_key /etc/nginx/ssl/x.key; } }`), "/etc/nginx")
	require.NoError(t, err)
	assert.Equal(t, []string{"a;b", "c'd", "e;f"}, c.Servers[0].Names)
}

func TestRelativeWithoutConfDirIsNotAllowed(t *testing.T) {
	c, err := Parse(fixture(t, "relative.conf"), "")
	require.NoError(t, err)
	assert.Equal(t, ReasonPathNotAllowed, c.Servers[0].Pairs[0].Unsupported)
}
```

Run: `go test ./internal/providers/nginx/nginxconf -count=1`
Expected: FAIL (no package).

- [ ] **Step 3: Implement the parser**

Create `internal/providers/nginx/nginxconf/nginxconf.go`:

```go
// Package nginxconf parses the output of "nginx -T" into the server blocks and certificate file
// pairs Alice manages (spec §12.4). It is pure (standard library and helperproto only): the root
// helper uses it to decide which files it may touch, and it is fuzzed (§25.6). Its input is
// hostile: a compromised server writes it.
package nginxconf

import (
	"errors"
	"path/filepath"
	"strconv"
	"strings"

	"alice/internal/providers/linuxssh/helperproto"
)

// Limits (§25.6: deep nesting and huge lines are refused cleanly).
const (
	MaxInput = 20 << 20
	MaxDepth = 100
	MaxLine  = 1 << 20
)

// Errors.
var (
	ErrTooLarge    = errors.New("nginxconf: the configuration dump is larger than 20 MiB")
	ErrTooDeep     = errors.New("nginxconf: blocks are nested deeper than 100 levels")
	ErrLineTooLong = errors.New("nginxconf: a line is longer than 1 MiB")
	ErrSyntax      = errors.New("nginxconf: unbalanced braces or an unterminated directive or string")
)

// Reasons a pair is not supported (spec §12.4 step 4, R38 item 4).
const (
	ReasonVariable       = "variable"
	ReasonDataValue      = "data_value"
	ReasonEngineKey      = "engine_key"
	ReasonKeyMissing     = "key_missing"
	ReasonPasswordFile   = "password_file"
	ReasonPathNotAllowed = "path_not_allowed"
	ReasonStream         = "stream"
	ReasonCombinedFile   = "combined_file"
)

// Listen is one listen directive.
type Listen struct {
	Addr          string // "" = any address
	Port          int
	SSL           bool
	DefaultServer bool
}

// Pair is the i-th ssl_certificate with the i-th ssl_certificate_key of a server block.
type Pair struct {
	Cert, Key       string // cleaned absolute paths; "" when the pair is unsupported for a path reason
	CertRaw, KeyRaw string // the directive arguments as written
	Inherited       bool   // either path came from the http block
	Unsupported     string // "" or a Reason*
}

// Server is one server block that serves TLS with at least one certificate.
type Server struct {
	File    string
	Line    int
	Names   []string
	Listens []Listen
	Pairs   []Pair
	Stream  bool
}

// Config is the part of the configuration Alice uses.
type Config struct {
	Servers  []Server
	Files    []string
	Warnings []string
}

const markerPrefix = "# configuration file "

type token struct {
	text   string
	quoted bool
	file   string
	line   int // line within file, 1-based
}

type node struct {
	name     string
	args     []token
	file     string
	line     int
	block    bool
	children []node
}

// tokenize splits the dump into tokens, following nginx's ngx_conf_read_token: '#' starts a
// comment outside quotes, "..." and '...' are one token (\" \' \\ \t \r \n escapes), a backslash
// escapes the next character in a word, and "${" inside a word is a variable, not a block.
func tokenize(data []byte) ([]token, []string, error) {
	var (
		toks      []token
		files     []string
		file      string
		line      = 1 // line in the dump
		fileStart = 1 // dump line where the current file starts
		col       = 0 // bytes since the last newline
	)
	fileLine := func() int { return line - fileStart + 1 }
	n := len(data)
	for i := 0; i < n; {
		c := data[i]
		switch {
		case c == '\n':
			line++
			col = 0
			i++
			continue
		case c == ' ' || c == '\t' || c == '\r':
			i++
			col++
			continue
		case c == '#':
			start := i
			for i < n && data[i] != '\n' {
				i++
			}
			if i-start > MaxLine {
				return nil, nil, ErrLineTooLong
			}
			text := string(data[start:i])
			if col == 0 && strings.HasPrefix(text, markerPrefix) && strings.HasSuffix(text, ":") {
				file = strings.TrimSuffix(strings.TrimPrefix(text, markerPrefix), ":")
				files = append(files, file)
				fileStart = line + 1
			}
			continue
		case c == ';' || c == '{' || c == '}':
			toks = append(toks, token{text: string(c), file: file, line: fileLine()})
			i++
			col++
			continue
		case c == '"' || c == '\'':
			q := c
			startLine := fileLine()
			var b strings.Builder
			i++
			closed := false
			for i < n {
				ch := data[i]
				if ch == '\\' && i+1 < n {
					switch next := data[i+1]; next {
					case '"', '\'', '\\':
						b.WriteByte(next)
					case 't':
						b.WriteByte('\t')
					case 'r':
						b.WriteByte('\r')
					case 'n':
						b.WriteByte('\n')
					default:
						b.WriteByte('\\')
						b.WriteByte(next)
					}
					i += 2
					continue
				}
				if ch == q {
					closed = true
					i++
					break
				}
				if ch == '\n' {
					line++
				}
				b.WriteByte(ch)
				i++
				if b.Len() > MaxLine {
					return nil, nil, ErrLineTooLong
				}
			}
			if !closed {
				return nil, nil, ErrSyntax
			}
			toks = append(toks, token{text: b.String(), quoted: true, file: file, line: startLine})
			col++
			continue
		}
		// A word.
		var b strings.Builder
		startLine := fileLine()
		for i < n {
			ch := data[i]
			if ch == '\\' && i+1 < n && data[i+1] != '\n' {
				b.WriteByte(data[i+1])
				i += 2
				continue
			}
			if ch == '$' && i+1 < n && data[i+1] == '{' {
				end := i + 2
				for end < n && data[end] != '}' && data[end] != '\n' {
					end++
				}
				if end >= n || data[end] != '}' {
					return nil, nil, ErrSyntax
				}
				b.Write(data[i : end+1])
				i = end + 1
				continue
			}
			if ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' || ch == ';' || ch == '{' || ch == '}' || ch == '#' {
				break
			}
			b.WriteByte(ch)
			i++
			if b.Len() > MaxLine {
				return nil, nil, ErrLineTooLong
			}
		}
		toks = append(toks, token{text: b.String(), file: file, line: startLine})
		col++
	}
	return toks, files, nil
}

type parser struct {
	toks []token
	i    int
}

// block reads directives until the matching "}" (closing) or the end of input (top level).
func (p *parser) block(depth int, closing bool) ([]node, error) {
	if depth > MaxDepth {
		return nil, ErrTooDeep
	}
	var out []node
	var cur []token
	for p.i < len(p.toks) {
		t := p.toks[p.i]
		p.i++
		if !t.quoted {
			switch t.text {
			case ";":
				if len(cur) > 0 {
					out = append(out, node{name: cur[0].text, args: cur[1:], file: cur[0].file, line: cur[0].line})
				}
				cur = nil
				continue
			case "{":
				if len(cur) == 0 {
					return nil, ErrSyntax
				}
				children, err := p.block(depth+1, true)
				if err != nil {
					return nil, err
				}
				out = append(out, node{name: cur[0].text, args: cur[1:], file: cur[0].file, line: cur[0].line, block: true, children: children})
				cur = nil
				continue
			case "}":
				if !closing || len(cur) > 0 {
					return nil, ErrSyntax
				}
				return out, nil
			}
		}
		cur = append(cur, t)
	}
	if closing || len(cur) > 0 {
		return nil, ErrSyntax
	}
	return out, nil
}

// Parse parses an "nginx -T" dump. confDir resolves relative certificate paths (the directory of
// --conf-path); "" makes relative paths unsupported.
func Parse(dump []byte, confDir string) (Config, error) {
	if len(dump) > MaxInput {
		return Config{}, ErrTooLarge
	}
	toks, files, err := tokenize(dump)
	if err != nil {
		return Config{}, err
	}
	p := &parser{toks: toks}
	tree, err := p.block(0, false)
	if err != nil {
		return Config{}, err
	}
	c := Config{Files: files}
	for _, n := range tree {
		switch {
		case n.block && n.name == "http":
			c.http(n.children, confDir)
		case n.block && n.name == "stream":
			c.stream(n.children)
		}
	}
	return c, nil
}

type sslDirs struct {
	certs, keys []string
	password    bool
}

func collect(nodes []node) sslDirs {
	var d sslDirs
	for _, n := range nodes {
		if n.block || len(n.args) == 0 {
			continue
		}
		switch n.name {
		case "ssl_certificate":
			d.certs = append(d.certs, n.args[0].text)
		case "ssl_certificate_key":
			d.keys = append(d.keys, n.args[0].text)
		case "ssl_password_file":
			d.password = true
		}
	}
	return d
}

func (c *Config) http(children []node, confDir string) {
	top := collect(children)
	for _, n := range children {
		if !n.block || n.name != "server" {
			continue
		}
		own := collect(n.children)
		s := server(n)
		if !hasSSL(s) {
			continue
		}
		certs, inhC := own.certs, false
		if len(certs) == 0 {
			certs, inhC = top.certs, true
		}
		keys, inhK := own.keys, false
		if len(keys) == 0 {
			keys, inhK = top.keys, true
		}
		if len(certs) == 0 {
			continue
		}
		password := own.password || top.password
		for i, cr := range certs {
			pr := Pair{CertRaw: cr, Inherited: inhC || (inhK && len(top.keys) > 0)}
			if i < len(keys) {
				pr.KeyRaw = keys[i]
			}
			pr.Cert, pr.Key, pr.Unsupported = resolvePair(pr.CertRaw, pr.KeyRaw, confDir, password)
			s.Pairs = append(s.Pairs, pr)
		}
		c.Servers = append(c.Servers, s)
	}
}

func (c *Config) stream(children []node) {
	for _, n := range children {
		if !n.block || n.name != "server" {
			continue
		}
		own := collect(n.children)
		if len(own.certs) == 0 {
			continue
		}
		s := server(n)
		s.Stream = true
		for i, cr := range own.certs {
			pr := Pair{CertRaw: cr, Unsupported: ReasonStream}
			if i < len(own.keys) {
				pr.KeyRaw = own.keys[i]
			}
			s.Pairs = append(s.Pairs, pr)
		}
		c.Servers = append(c.Servers, s)
		if !contains(c.Warnings, helperproto.WarnStreamTLS) {
			c.Warnings = append(c.Warnings, helperproto.WarnStreamTLS)
		}
	}
}

func server(n node) Server {
	s := Server{File: n.file, Line: n.line}
	sslOn := false
	for _, d := range n.children {
		if d.block {
			continue
		}
		switch d.name {
		case "server_name":
			for _, a := range d.args {
				s.Names = append(s.Names, a.text)
			}
		case "listen":
			if l, ok := parseListen(d.args); ok {
				s.Listens = append(s.Listens, l)
			}
		case "ssl":
			sslOn = len(d.args) == 1 && d.args[0].text == "on"
		}
	}
	if len(s.Listens) == 0 {
		s.Listens = []Listen{{Port: 80}}
	}
	if sslOn {
		for i := range s.Listens {
			s.Listens[i].SSL = true
		}
	}
	return s
}

func hasSSL(s Server) bool { return len(SSLListens(s)) > 0 }

// SSLListens returns the listens of s that serve TLS.
func SSLListens(s Server) []Listen {
	var out []Listen
	for _, l := range s.Listens {
		if l.SSL {
			out = append(out, l)
		}
	}
	return out
}

func parseListen(args []token) (Listen, bool) {
	if len(args) == 0 {
		return Listen{}, false
	}
	a := args[0].text
	if strings.HasPrefix(a, "unix:") {
		return Listen{}, false
	}
	l := Listen{Port: 80}
	port := ""
	switch {
	case strings.HasPrefix(a, "["):
		end := strings.Index(a, "]")
		if end < 0 {
			return Listen{}, false
		}
		l.Addr = a[1:end]
		if rest := a[end+1:]; strings.HasPrefix(rest, ":") {
			port = rest[1:]
		} else if rest != "" {
			return Listen{}, false
		}
	case isDigits(a):
		port = a
	case strings.Contains(a, ":"):
		i := strings.LastIndex(a, ":")
		l.Addr, port = a[:i], a[i+1:]
	default:
		l.Addr = a
	}
	if port != "" {
		v, err := strconv.Atoi(port)
		if err != nil || !isDigits(port) || v < 1 || v > 65535 {
			return Listen{}, false
		}
		l.Port = v
	}
	if l.Addr == "*" {
		l.Addr = ""
	}
	for _, f := range args[1:] {
		switch f.text {
		case "ssl":
			l.SSL = true
		case "default_server", "default":
			l.DefaultServer = true
		}
	}
	return l, true
}

func isDigits(s string) bool {
	if s == "" || len(s) > 5 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// resolvePair turns the raw arguments into paths or a reason.
func resolvePair(certRaw, keyRaw, confDir string, password bool) (cert, key, reason string) {
	switch {
	case strings.HasPrefix(certRaw, "data:") || strings.HasPrefix(keyRaw, "data:"):
		return "", "", ReasonDataValue
	case strings.Contains(certRaw, "$") || strings.Contains(keyRaw, "$"):
		return "", "", ReasonVariable
	case strings.HasPrefix(keyRaw, "engine:"):
		return "", "", ReasonEngineKey
	case keyRaw == "":
		c, ok := resolvePath(certRaw, confDir)
		if !ok {
			return "", "", ReasonPathNotAllowed
		}
		return c, "", ReasonKeyMissing
	case password:
		return "", "", ReasonPasswordFile
	}
	c, ok1 := resolvePath(certRaw, confDir)
	k, ok2 := resolvePath(keyRaw, confDir)
	switch {
	case !ok1 || !ok2:
		return "", "", ReasonPathNotAllowed
	case c == k:
		return c, k, ReasonCombinedFile
	}
	return c, k, ""
}

func resolvePath(raw, confDir string) (string, bool) {
	p := raw
	if !filepath.IsAbs(p) {
		if confDir == "" || !filepath.IsAbs(confDir) {
			return "", false
		}
		p = filepath.Join(confDir, p)
	}
	p = filepath.Clean(p)
	return p, helperproto.ValidPath(p) && p != "/"
}

// HasPair reports whether cert and key are a supported pair of an http server block.
func (c Config) HasPair(cert, key string) bool {
	for _, s := range c.Servers {
		if s.Stream {
			continue
		}
		for _, p := range s.Pairs {
			if p.Unsupported == "" && p.Cert == cert && p.Key == key {
				return true
			}
		}
	}
	return false
}

// CertPaths returns the distinct certificate paths of supported pairs, in order.
func (c Config) CertPaths() []string { return c.paths(func(p Pair) string { return p.Cert }) }

// KeyPaths returns the distinct key paths of supported pairs, in order.
func (c Config) KeyPaths() []string { return c.paths(func(p Pair) string { return p.Key }) }

func (c Config) paths(get func(Pair) string) []string {
	var out []string
	for _, s := range c.Servers {
		for _, p := range s.Pairs {
			if p.Unsupported == "" && !contains(out, get(p)) {
				out = append(out, get(p))
			}
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
```

`Pair.Inherited` is true when the certificate or the key of the pair came from the `http` block (`inhC` implies `top.certs` is not empty, because `certs` is). Nginx inherits `ssl_certificate` and `ssl_certificate_key` independently, so a server with its own certificate and the http block's key is "inherited" too.

Run: `go test ./internal/providers/nginx/nginxconf -count=1`
Expected: PASS. Fix the fixtures (not the expectations) if a line number or a path in a fixture you typed differs from the table.

- [ ] **Step 4: Fuzz target**

Create `internal/providers/nginx/nginxconf/fuzz_test.go`:

```go
// §25.6 FuzzParseNginxConfig: never panics; output paths come only from ssl_certificate and
// ssl_certificate_key arguments and are valid helper paths; parsing is deterministic.
func FuzzParseNginxConfig(f *testing.F) {
	entries, err := os.ReadDir(filepath.Join("..", "..", "..", "..", "test", "testdata", "nginx"))
	if err != nil {
		f.Fatal(err)
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "test", "testdata", "nginx", e.Name()))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Add([]byte("http { server { listen 443 ssl; ssl_certificate \"/a b\"; ssl_certificate_key ${x}; } }"))
	f.Fuzz(func(t *testing.T, in []byte) {
		c1, err1 := Parse(in, "/etc/nginx")
		c2, err2 := Parse(in, "/etc/nginx")
		if (err1 == nil) != (err2 == nil) || !reflect.DeepEqual(c1, c2) {
			t.Fatalf("Parse is not deterministic")
		}
		if err1 != nil {
			return
		}
		for _, s := range c1.Servers {
			for _, p := range s.Pairs {
				for _, path := range []string{p.Cert, p.Key} {
					if path != "" && !helperproto.ValidPath(path) {
						t.Fatalf("invalid path %q", path)
					}
				}
				// Without escapes every supported path's file name appears in the input as written.
				if p.Unsupported == "" && (p.Cert == "" || p.Key == "" ||
					(!bytes.ContainsRune(in, '\\') && !bytes.Contains(in, []byte(filepath.Base(p.Cert))))) {
					t.Fatalf("a supported pair whose certificate path is not in the input: %+v", p)
				}
			}
		}
	})
}
```

Run: `go test ./internal/providers/nginx/nginxconf -count=1` → PASS; then `go test ./internal/providers/nginx/nginxconf -run '^$' -fuzz FuzzParseNginxConfig -fuzztime 60s` → no crasher and every input under 1 s (a slow input is a bug: the parser is linear). Add to the `Makefile`:

```make
.PHONY: fuzz-nginx
fuzz-nginx: ## Fuzz the nginx -T parser for 60 s (spec §25.6)
	go test -count=1 -run '^$$' -fuzz FuzzParseNginxConfig -fuzztime 60s ./internal/providers/nginx/nginxconf/
```

- [ ] **Step 5: Full check and commit**

Run: `make lint && go test ./internal/providers/nginx/... ./internal/archtest -count=1`
Expected: PASS.

```bash
git add internal/providers/nginx/nginxconf test/testdata/nginx Makefile
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "feat(nginx): parse nginx -T into server blocks and certificate pairs (fuzzed)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 4: Helper protocol 4 vocabulary (`helperproto`)

Adds the protocol 4 names, codes, limits, response types and three validators of the contract to the pure package both sides share, and raises `Protocol` to 4 / `Version` to `1.3.0`. The helper and the provider move to protocol 4 in Tasks 5–7; until then nothing uses the new names except tests, and the emulator answers `version` with `helperproto.Protocol`, so the repository stays green.

**Files:**
- Modify: `internal/providers/linuxssh/helperproto/helperproto.go`
- Modify: `internal/providers/linuxssh/provider_test.go` (`TestOpenHelperOutdated` expects protocol 4)
- Test: `internal/providers/linuxssh/helperproto/helperproto_test.go`

**Interfaces:**
- Produces: everything listed under "Helper protocol 4" in the contract.

- [ ] **Step 1: Write the failing tests**

Add to `helperproto_test.go`:

```go
func TestProtocol4(t *testing.T) {
	assert.Equal(t, 4, Protocol)
	assert.Equal(t, "1.3.0", Version)
	assert.Equal(t, 20<<20, MaxNginxConfig)
	assert.Equal(t, 7*24*time.Hour, NginxBackupKeep)
}

func TestValidPort(t *testing.T) {
	for in, want := range map[string]bool{"1": true, "443": true, "65535": true, "0": false, "65536": false, "0443": false,
		"": false, "-1": false, "4a": false, "443 ": false} {
		assert.Equal(t, want, ValidPort(in), in)
	}
}

func TestValidSNI(t *testing.T) {
	for in, want := range map[string]bool{"www.example.test": true, "alice-check.example.test": true, "localhost": true,
		"WWW.example.test": false, "": false, ".a": false, "a.": false, "a..b": false, "-a.b": false, "a-.b": false,
		"*.a.b": false, "a b": false, "a_b.c": false, strings.Repeat("a", 64) + ".b": false, "ö.example": false} {
		assert.Equal(t, want, ValidSNI(in), in)
	}
}

func TestValidIP(t *testing.T) {
	for in, want := range map[string]bool{"127.0.0.1": true, "::1": true, "10.0.0.5": true, "2001:db8::5": true,
		"fe80::1%eth0": false, "::ffff:127.0.0.1": true, "2001:DB8::5": false, "localhost": false, "": false, "1.2.3": false} {
		assert.Equal(t, want, ValidIP(in), in)
	}
}

func TestProtocol4WireNames(t *testing.T) {
	b, err := json.Marshal(NginxDeployResponse{OK: true, Phase: PhaseCommitted, Steps: []NginxStep{{Name: StepBackup, Status: "ok"}},
		BackupDir: BackupRoot + "/x"})
	require.NoError(t, err)
	assert.JSONEq(t, `{"ok":true,"phase":"committed","failed_step":"","error":"","steps":[{"name":"backup","status":"ok","error":""}],
		"backup_dir":"/var/lib/alice-helper/backups/x"}`, string(b))
	b, err = json.Marshal(AuthKeysListResponse{OK: true, Users: []UserFiles{}, Warnings: []string{}, Accounts: []string{"a"}, AccountsComplete: true})
	require.NoError(t, err)
	assert.Contains(t, string(b), `"accounts":["a"],"accounts_complete":true`)
	b, err = json.Marshal(NginxFile{Path: "/p", Kind: "key", Exists: true})
	require.NoError(t, err)
	assert.JSONEq(t, `{"path":"/p","kind":"key","exists":true,"resolved":"","symlinked":false,"mode":"","owner":"","size":0,
		"sha256":"","pem":"","problem":"","free_bytes":0}`, string(b))
}
```

(`TestWireNames` asserts `Protocol == 3`; change that line to `assert.Equal(t, 4, Protocol)`.)

Run: `go test ./internal/providers/linuxssh/helperproto -count=1` → FAIL.

- [ ] **Step 2: Implement**

Apply the "Helper protocol 4" block of the contract to `helperproto.go`: change `Protocol` and `Version`; add the subcommand, code, warning, limit, error-class, file-problem, phase and step constants; the `Nginx*`, `TLSProbeResponse` and `NginxDeployInput` types; add `Accounts []string \`json:"accounts"\`` and `AccountsComplete bool \`json:"accounts_complete"\`` to `AuthKeysListResponse` after `Warnings`; and implement:

```go
// ValidPort reports whether s is a decimal TCP port 1..65535 without leading zeros.
func ValidPort(s string) bool {
	if s == "" || len(s) > 5 || s[0] == '0' {
		return false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
		n = n*10 + int(s[i]-'0')
	}
	return n >= 1 && n <= 65535
}

// ValidSNI reports whether s is a lower-case DNS name Alice may send as SNI.
func ValidSNI(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// ValidIP reports whether s is an IP literal without a zone in its canonical form.
func ValidIP(s string) bool {
	a, err := netip.ParseAddr(s)
	return err == nil && a.Zone() == "" && a.String() == s
}
```

(imports `net/netip`). `"::ffff:127.0.0.1"` is canonical for `netip` (`Addr.String()` keeps the 4-in-6 form), hence `true` in the test.

And the shared probe configuration (imports `crypto/tls`):

```go
// ProbeTLSConfig is the client configuration of both verification probes (see the contract).
func ProbeTLSConfig(sni, keyType string) *tls.Config {
	c := &tls.Config{ //nolint:gosec // G402: the probe only compares the served leaf's SHA-256 with the expected certificate (spec §12.8 item 3); it never trusts the connection or sends data
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}
	if sni != "" && sni != NoSNI {
		c.ServerName = sni
	}
	switch keyType {
	case ProbeRSA:
		c.MaxVersion = tls.VersionTLS12
		c.CipherSuites = []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256}
	case ProbeECDSA:
		c.MaxVersion = tls.VersionTLS12
		c.CipherSuites = []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256}
	}
	return c
}
```

Add its test:

```go
func TestProbeTLSConfig(t *testing.T) {
	c := ProbeTLSConfig("www.example.test", ProbeAny)
	assert.True(t, c.InsecureSkipVerify)
	assert.Equal(t, "www.example.test", c.ServerName)
	assert.Equal(t, uint16(tls.VersionTLS12), c.MinVersion)
	assert.Zero(t, c.MaxVersion)
	assert.Empty(t, ProbeTLSConfig(NoSNI, ProbeAny).ServerName)
	r := ProbeTLSConfig("", ProbeRSA)
	assert.Equal(t, uint16(tls.VersionTLS12), r.MaxVersion)
	assert.Contains(t, r.CipherSuites, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
	assert.NotContains(t, r.CipherSuites, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
	e := ProbeTLSConfig("", ProbeECDSA)
	assert.Contains(t, e.CipherSuites, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
}
```

In `internal/providers/linuxssh/provider_test.go`, `TestOpenHelperOutdated` now loops over `[]int{0, 1, 2, 3}` and expects `required_protocol` `"4"` (the provider compares with `helperproto.Protocol`, so from this commit on Phase 3 helpers are outdated; the emulator and the container tests build the helper from source and report 4).

Run: `go test ./internal/providers/linuxssh/... ./cmd/alice-helper -count=1`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add internal/providers/linuxssh/helperproto internal/providers/linuxssh
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "feat(helperproto): protocol 4 vocabulary for Nginx certificates and the accounts list

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 5: **HELPER** part 1 — accounts carry, root-controlled path walk, `nginx-dump`, `nginx-test`, `tls-probe`

This task gives the root helper its read side for Nginx and closes the Phase 3 accounts carries. The central piece is `resolveRoot` (Global Constraints, "Helper rule"): a path is walked from `/` by descriptor, every directory must be root's and not writable by group or others, every link must be root's, and `..` in a link target is resolved against the walked descriptors (Let's Encrypt's `live → ../../archive` links work) — so nothing a local user can change ever redirects a read or, in Task 6, a write. `nginx-dump` runs `nginx -T` and `nginx -V`, parses with `nginxconf`, and describes every referenced file: certificate files are read (only their `CERTIFICATE` blocks leave the helper), key files are only stat'ed. `tls-probe` is the unprivileged server-side TLS check. No path argument exists in this task's subcommands: every path comes from the helper's own parse.

**Files:**
- Modify: `cmd/alice-helper/accounts.go` (empty shell, uid-0 accounts, `accountNames`), `cmd/alice-helper/authkeys.go` (`cmdAuthKeysList` reports `accounts`, `accounts_complete`)
- Create: `cmd/alice-helper/rootpath.go` (`rootFile`, `resolveRoot`, `open`, `certName`, `problemOf`)
- Create: `cmd/alice-helper/nginx.go` (`runProgram`, `nginxConfig`, `classifyNginxError`, `cmdNginxDump`, `cmdNginxTest`, `describeCert`, `describeKey`, `writableConfigs`)
- Create: `cmd/alice-helper/probe.go` (`cmdTLSProbe`)
- Modify: `cmd/alice-helper/sys.go` (fields `runNginx`, `runSystemctl`, `dial`, `statfs`), `cmd/alice-helper/main.go` (production values), `cmd/alice-helper/run.go` (`commands` entries)
- Modify: `test/images/e2e-target/Dockerfile` (the helper build copies `internal/providers/nginx/nginxconf/` too)
- Test: `cmd/alice-helper/nginx_test.go`, `cmd/alice-helper/rootpath_test.go`, `cmd/alice-helper/probe_test.go`, `cmd/alice-helper/helper_test.go` (accounts carry, privileged list)

**Interfaces:**
- Consumes: Task 3 `nginxconf.Parse`, `Config.CertPaths`, `KeyPaths`, `Files`, `Servers`; Task 4 `helperproto` protocol 4 names, `ProbeTLSConfig`, `NoSNI`, `ValidIP`, `ValidPort`, `ValidSNI`; Phase 3 helper internals `sys`, `accounts`, `owners`, `toScan`, `loginShell`, `directoryUsers`, `errEscaped`, `errUnsafe`, `errNotRegular`, `errTooLarge`, `sameFile`, `hexSHA`, `capWriter`, `maxRootLinks`, `refused`, `precondition`, `failed`, test fixture `newFixture`, `(*fixture).run/write/mkdir/host/read`.
- Produces (for Task 6): `func (s *sys) resolveRoot(p string) (rootFile, error)`, `rootFile{dirfd int; name, resolved string; symlinked bool}`, `func (f rootFile) close()`, `func (f rootFile) open() (*os.File, unix.Stat_t, error)` (regular file, one link, no link followed), `func certName(name string) bool`, `func (s *sys) nginxConfig(ctx context.Context) (nginxconf.Config, nginxMeta, error)` with `nginxMeta{version, confPath string; valid bool; class string}`, `func classifyNginxError(stderr []byte) string`, `const nginxPath = "/usr/sbin/nginx"`, `const systemctlPath = "/usr/bin/systemctl"`, `sys.runNginx func(ctx context.Context, args ...string) (stdout, stderr []byte, err error)`, `sys.runSystemctl func(ctx context.Context, args ...string) error`, `sys.statfs func(fd int) (int64, error)`, `sys.dial func(ctx context.Context, network, addr string) (net.Conn, error)`; wire behaviour of `nginx-dump`, `nginx-test`, `tls-probe` (contract table) and `authkeys-list`'s `accounts`/`accounts_complete`.

- [ ] **Step 1: Write the failing accounts tests**

Add to `cmd/alice-helper/helper_test.go`:

```go
// Carry 1: every valid account name is reported, and whether the list is complete.
func TestAuthKeysListReportsEveryAccountName(t *testing.T) {
	f := newFixture(t)
	code, m := f.run("authkeys-list")
	require.Equal(t, 0, code, "%v", m)
	assert.Equal(t, []any{"alice-svc", "daemon", "deploy", "ghost", "nobody", "nologin", "root"}, m["accounts"],
		"sorted; Bad Name and the broken line are not account names")
	assert.Equal(t, true, m["accounts_complete"])

	f.write("/etc/nsswitch.conf", "passwd: files sss\n", 0o644)
	_, m = f.run("authkeys-list")
	assert.Equal(t, false, m["accounts_complete"], "directory users may exist")
}

func TestAccountsIncompleteWhenTooMany(t *testing.T) {
	f := newFixture(t)
	var b strings.Builder
	b.WriteString(f.read("/etc/passwd"))
	for i := 0; i < helperproto.MaxAccountNames; i++ {
		fmt.Fprintf(&b, "u%d:x:%d:%d::/nonexistent:/usr/sbin/nologin\n", i, 20000+i, 20000+i)
	}
	f.write("/etc/passwd", b.String(), 0o644)
	_, m := f.run("authkeys-list")
	assert.Len(t, m["accounts"], helperproto.MaxAccountNames)
	assert.Equal(t, false, m["accounts_complete"])
}

// Carry 2: an empty shell field is /bin/sh for sshd, so the account is scanned.
func TestEmptyShellIsALoginShell(t *testing.T) {
	f := newFixture(t)
	f.mkdir("/home/sh", 0o755)
	f.write("/etc/passwd", f.read("/etc/passwd")+"sh:x:1010:1010::/home/sh:\n", 0o644)
	_, m := f.run("authkeys-list")
	assert.NotNil(t, listUser(t, m, "sh"))
	assert.True(t, loginShell(""))
	assert.False(t, loginShell("/usr/sbin/nologin"))
}

// Carry 3: every uid-0 account with a login shell and a home is scanned (its last key is guarded).
func TestUID0AccountsAreScanned(t *testing.T) {
	f := newFixture(t)
	f.mkdir("/var/toor", 0o755)
	f.write("/etc/passwd", f.read("/etc/passwd")+"toor:x:0:0::/var/toor:/bin/sh\nlocked:x:0:0::/var/toor:/usr/sbin/nologin\n", 0o644)
	_, m := f.run("authkeys-list")
	u := listUser(t, m, "toor")
	assert.Equal(t, float64(0), u["uid"])
	for _, x := range m["users"].([]any) {
		assert.NotEqual(t, "locked", x.(map[string]any)["user"], "no login shell")
	}
}
```

(If `listUser` fails the test when the user is missing, the `locked` check above is written with a loop instead; keep it so.)

Run: `go test ./cmd/alice-helper -run 'EveryAccountName|TooMany|EmptyShell|UID0Accounts' -count=1`
Expected: FAIL.

- [ ] **Step 2: Implement the accounts carry**

`accounts.go`:

```go
func loginShell(shell string) bool {
	// An empty field is /bin/sh for sshd and login (passwd(5)).
	return !strings.HasSuffix(shell, "/nologin") && !strings.HasSuffix(shell, "/false")
}
```

In `toScan`, the condition becomes:

```go
		ok := (a.name == "root" && a.uid == 0) || (sudo != "" && a.name == sudo) ||
			(a.uid == 0 && loginShell(a.shell) && s.isDir(a.home)) ||
			(a.uid >= 1000 && a.uid != nobodyUID && loginShell(a.shell) && s.isDir(a.home))
```

Add:

```go
// accountNames returns every valid account name, sorted and deduplicated, at most
// helperproto.MaxAccountNames; fits is false when there were more.
func accountNames(accts []account) (names []string, fits bool) {
	seen := map[string]bool{}
	for _, a := range accts {
		if helperproto.ValidUser(a.name) && !seen[a.name] {
			seen[a.name] = true
			names = append(names, a.name)
		}
	}
	sort.Strings(names)
	if len(names) > helperproto.MaxAccountNames {
		return names[:helperproto.MaxAccountNames], false
	}
	return names, true
}
```

`scanResult` gains `names []string` and `namesFit bool`, filled in `scan` from `accounts()`. In `cmdAuthKeysList` set:

```go
	resp.Accounts = r.names
	resp.AccountsComplete = r.namesFit && !slices.Contains(r.warnings, helperproto.WarnTooManyUsers) &&
		!slices.Contains(r.warnings, helperproto.WarnDirectoryUsers)
```

(`resp.Accounts` must be `[]string{}` when empty, never `null`.) Run the Step 1 tests and the whole package: `go test ./cmd/alice-helper -count=1` → PASS (update `TestAuthKeysListUsersAndFiles` if it lists users and now sees none extra: the fixture's accounts are unchanged, so it should not).

- [ ] **Step 3: Write the failing path-walk tests**

Create `cmd/alice-helper/rootpath_test.go`:

```go
//go:build linux

package main

import (
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func (f *fixture) symlink(target, guest string) {
	f.t.Helper()
	require.NoError(f.t, os.Symlink(target, f.host(guest)))
}

func TestResolveRootPlainFile(t *testing.T) {
	f := newFixture(t)
	f.mkdir("/etc/nginx", 0o755)
	f.mkdir("/etc/nginx/ssl", 0o755)
	f.write("/etc/nginx/ssl/www.crt", "x", 0o644)
	rf, err := f.s.resolveRoot("/etc/nginx/ssl/www.crt")
	require.NoError(t, err)
	defer rf.close()
	assert.Equal(t, "/etc/nginx/ssl/www.crt", rf.resolved)
	assert.Equal(t, "www.crt", rf.name)
	assert.False(t, rf.symlinked)
	file, st, err := rf.open()
	require.NoError(t, err)
	defer func() { _ = file.Close() }()
	assert.Equal(t, int64(1), int64(st.Size))
}

// Review Focus 1: certbot's live/ links lead into ../../archive.
func TestResolveRootFollowsRootOwnedLetsEncryptLinks(t *testing.T) {
	f := newFixture(t)
	for _, d := range []string{"/etc/letsencrypt", "/etc/letsencrypt/live", "/etc/letsencrypt/live/shop.example.test",
		"/etc/letsencrypt/archive", "/etc/letsencrypt/archive/shop.example.test"} {
		f.mkdir(d, 0o755)
	}
	f.write("/etc/letsencrypt/archive/shop.example.test/fullchain3.pem", "x", 0o644)
	f.symlink("../../archive/shop.example.test/fullchain3.pem", "/etc/letsencrypt/live/shop.example.test/fullchain.pem")
	rf, err := f.s.resolveRoot("/etc/letsencrypt/live/shop.example.test/fullchain.pem")
	require.NoError(t, err)
	defer rf.close()
	assert.Equal(t, "/etc/letsencrypt/archive/shop.example.test/fullchain3.pem", rf.resolved)
	assert.True(t, rf.symlinked)
}

func TestResolveRootAbsoluteLinkStaysInTheRoot(t *testing.T) {
	f := newFixture(t)
	f.mkdir("/etc/nginx", 0o755)
	f.mkdir("/srv", 0o755)
	f.write("/srv/x.crt", "x", 0o644)
	f.symlink("/srv/x.crt", "/etc/nginx/x.crt")
	f.symlink("../../../../../../srv/x.crt", "/etc/nginx/y.crt")
	for _, p := range []string{"/etc/nginx/x.crt", "/etc/nginx/y.crt"} {
		rf, err := f.s.resolveRoot(p)
		require.NoError(t, err, p)
		assert.Equal(t, "/srv/x.crt", rf.resolved, "an absolute link and too many .. both stay inside the guest root")
		rf.close()
	}
}

func TestResolveRootRefusals(t *testing.T) {
	f := newFixture(t)
	f.mkdir("/etc/nginx", 0o755)
	f.mkdir("/etc/nginx/ssl", 0o755)
	f.mkdir("/etc/nginx/dir.crt", 0o755)
	f.symlink("b.crt", "/etc/nginx/a.crt")
	f.symlink("a.crt", "/etc/nginx/b.crt")
	f.write("/etc/nginx/file", "x", 0o644)
	for _, tc := range []struct {
		path string
		want error
	}{
		{"/etc/nginx/a.crt", errTooManyLinks},
		{"/etc/nginx/dir.crt", errNotRegular},
		{"/etc/nginx/file/x.crt", unix.ENOTDIR},
		{"relative/x.crt", errEscaped},
		{"/", errEscaped},
	} {
		_, err := f.s.resolveRoot(tc.path)
		assert.True(t, errors.Is(err, tc.want), "%s: %v", tc.path, err)
	}
	rf, err := f.s.resolveRoot("/etc/nginx/ssl/missing.crt")
	require.NoError(t, err, "a missing last element is resolved; opening it reports ENOENT")
	_, _, err = rf.open()
	assert.True(t, errors.Is(err, unix.ENOENT))
	rf.close()
}

// Review Focus 2: a directory others can write is never trusted.
func TestAttackUserWritableDirectoryOnThePath(t *testing.T) {
	f := newFixture(t)
	f.mkdir("/etc/nginx", 0o755)
	f.mkdir("/etc/nginx/ssl", 0o777)
	f.write("/etc/nginx/ssl/www.crt", "x", 0o644)
	_, err := f.s.resolveRoot("/etc/nginx/ssl/www.crt")
	assert.ErrorIs(t, err, errNotRootControlled)
	require.NoError(t, os.Chmod(f.host("/etc/nginx/ssl"), 0o775))
	_, err = f.s.resolveRoot("/etc/nginx/ssl/www.crt")
	assert.ErrorIs(t, err, errNotRootControlled, "group-writable is refused too")
}

func TestAttackHardLinkIsRefused(t *testing.T) {
	f := newFixture(t)
	f.mkdir("/etc/nginx", 0o755)
	f.write("/etc/nginx/www.crt", "x", 0o644)
	require.NoError(t, os.Link(f.host("/etc/nginx/www.crt"), f.host("/etc/nginx/other.crt")))
	rf, err := f.s.resolveRoot("/etc/nginx/www.crt")
	require.NoError(t, err)
	defer rf.close()
	_, _, err = rf.open()
	assert.ErrorIs(t, err, errUnsafe)
}

// Root only: a link or a directory owned by another user on the path is refused.
func TestAttackUserOwnedLinkAndDirectoryAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root (lchown)")
	}
	f := newFixture(t)
	f.s.rootUID = 0
	f.mkdir("/etc/nginx", 0o755)
	f.mkdir("/etc/nginx/ssl", 0o755)
	f.write("/etc/nginx/ssl/www.crt", "x", 0o644)
	f.symlink("ssl/www.crt", "/etc/nginx/link.crt")
	require.NoError(t, os.Lchown(f.host("/etc/nginx/link.crt"), 1000, 1000))
	_, err := f.s.resolveRoot("/etc/nginx/link.crt")
	assert.ErrorIs(t, err, errNotRootControlled, "a user's link")
	require.NoError(t, os.Chown(f.host("/etc/nginx/ssl"), 1000, 1000))
	_, err = f.s.resolveRoot("/etc/nginx/ssl/www.crt")
	assert.ErrorIs(t, err, errNotRootControlled, "a user's directory, even 0755")
}

func TestCertName(t *testing.T) {
	for name, want := range map[string]bool{"www.crt": true, "fullchain1.pem": true, "a.key": true, "a.cer": true, "a.cert": true,
		"a.chained": true, "a.fullchain": true, "shadow": false, "a.crt.bak": false, "a.conf": false, "": false, ".pem": false} {
		assert.Equal(t, want, certName(name), name)
	}
}
```

Run: `go test ./cmd/alice-helper -run 'ResolveRoot|AttackUserWritable|AttackHardLinkIsRefused|AttackUserOwned|CertName' -count=1`
Expected: FAIL — `f.s.resolveRoot undefined`.

- [ ] **Step 4: Implement `rootpath.go`**

```go
//go:build linux

package main

import (
	"errors"
	"os"
	"strings"

	"golang.org/x/sys/unix"

	"alice/internal/providers/linuxssh/helperproto"
)

var (
	// errNotRootControlled: a directory or link on the path can be changed by a user other than root.
	errNotRootControlled = errors.New("a directory or link on the path is not controlled by root")
	// errTooManyLinks: more than maxRootLinks links (a loop).
	errTooManyLinks = errors.New("too many symbolic links")
)

// rootFile is a file whose every directory and link, from "/" down, belongs to root: nothing a
// user can change redirects an operation on it. dirfd is the directory that holds it; name is its
// name there. Operations use dirfd (openat, renameat), never the path again.
type rootFile struct {
	dirfd     int
	name      string
	resolved  string // the guest path with every link resolved
	symlinked bool
}

func (f rootFile) close() { _ = unix.Close(f.dirfd) }

// open opens the file for reading without following a link: it must be a regular file with
// exactly one link (a hard link could be another name of /etc/shadow).
func (f rootFile) open() (*os.File, unix.Stat_t, error) {
	var st unix.Stat_t
	fd, err := unix.Openat(f.dirfd, f.name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, st, err
	}
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return nil, st, err
	}
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFREG:
		_ = unix.Close(fd)
		return nil, st, errNotRegular
	case st.Nlink != 1:
		_ = unix.Close(fd)
		return nil, st, errUnsafe
	}
	return os.NewFile(uintptr(fd), f.name), st, nil
}

// dirOK: a directory nobody but root can change.
func (s *sys) dirOK(st unix.Stat_t) bool { return int(st.Uid) == s.rootUID && st.Mode&0o022 == 0 }

// resolveRoot resolves the absolute guest path p by descriptor, from "/": every directory it
// passes must be root's and not writable by group or others, every link must be root's (its
// directory was checked, so nobody else can replace it either). A link's target is resolved the
// same way; ".." steps back to the previous directory descriptor and never above "/". The last
// element is not opened (the caller opens it relative to dirfd with O_NOFOLLOW); a missing last
// element is returned as such and fails at the open with ENOENT.
func (s *sys) resolveRoot(p string) (rootFile, error) {
	if !helperproto.ValidPath(p) || p == "/" {
		return rootFile{}, errEscaped
	}
	rootfd, err := unix.Open(s.host("/"), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return rootFile{}, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(rootfd, &st); err != nil || !s.dirOK(st) {
		_ = unix.Close(rootfd)
		return rootFile{}, errNotRootControlled
	}
	stack := []int{rootfd}
	var names []string
	fail := func(err error) (rootFile, error) {
		for _, fd := range stack {
			_ = unix.Close(fd)
		}
		return rootFile{}, err
	}
	pending := strings.Split(strings.TrimPrefix(p, "/"), "/")
	links, symlinked := 0, false
	for len(pending) > 0 {
		c := pending[0]
		pending = pending[1:]
		switch c {
		case "", ".":
			continue
		case "..":
			if len(stack) > 1 {
				_ = unix.Close(stack[len(stack)-1])
				stack, names = stack[:len(stack)-1], names[:len(names)-1]
			}
			continue
		}
		cur := stack[len(stack)-1]
		last := len(pending) == 0
		var cst unix.Stat_t
		if err := unix.Fstatat(cur, c, &cst, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			if last && errors.Is(err, unix.ENOENT) {
				return keepLast(stack, names, c, symlinked), nil
			}
			return fail(err)
		}
		switch cst.Mode & unix.S_IFMT {
		case unix.S_IFLNK:
			if int(cst.Uid) != s.rootUID {
				return fail(errNotRootControlled)
			}
			links++
			if links > maxRootLinks {
				return fail(errTooManyLinks)
			}
			target, err := readlinkAt(cur, c)
			if err != nil {
				return fail(errEscaped)
			}
			symlinked = true
			if strings.HasPrefix(target, "/") {
				for _, fd := range stack[1:] {
					_ = unix.Close(fd)
				}
				stack, names = stack[:1], nil
			}
			pending = append(strings.Split(target, "/"), pending...)
		case unix.S_IFDIR:
			if last {
				return fail(errNotRegular)
			}
			if !s.dirOK(cst) {
				return fail(errNotRootControlled)
			}
			fd, err := unix.Openat(cur, c, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err != nil {
				return fail(err)
			}
			var got unix.Stat_t
			if err := unix.Fstat(fd, &got); err != nil || !sameFile(got, cst) || !s.dirOK(got) {
				_ = unix.Close(fd)
				return fail(errEscaped)
			}
			stack, names = append(stack, fd), append(names, c)
		default:
			if !last {
				return fail(unix.ENOTDIR)
			}
			return keepLast(stack, names, c, symlinked), nil
		}
	}
	return fail(errEscaped) // the path ended at a directory ("x/.." or a link to a directory's "..")
}

// keepLast keeps the current directory open for the file c and closes the others.
func keepLast(stack []int, names []string, c string, symlinked bool) rootFile {
	for _, fd := range stack[:len(stack)-1] {
		_ = unix.Close(fd)
	}
	parts := append(append([]string{}, names...), c)
	return rootFile{dirfd: stack[len(stack)-1], name: c, resolved: "/" + strings.Join(parts, "/"), symlinked: symlinked}
}

func readlinkAt(dirfd int, name string) (string, error) {
	buf := make([]byte, 4096)
	n, err := unix.Readlinkat(dirfd, name, buf)
	if err != nil {
		return "", err
	}
	if n == 0 || n >= len(buf) {
		return "", errEscaped
	}
	return string(buf[:n]), nil
}

// certExtensions are the file name endings the helper reads or writes as certificates or keys
// (spec §12.3 rule 4): a link that resolves to /etc/shadow or a configuration file never qualifies.
var certExtensions = []string{".pem", ".crt", ".cer", ".cert", ".key", ".chained", ".fullchain"}

func certName(name string) bool {
	for _, ext := range certExtensions {
		if len(name) > len(ext) && strings.HasSuffix(name, ext) {
			return true
		}
	}
	return false
}

// problemOf maps a resolve or open error to a helperproto.File* code.
func problemOf(err error) string {
	switch {
	case errors.Is(err, unix.ENOENT):
		return helperproto.FileMissing
	case errors.Is(err, errNotRootControlled), errors.Is(err, errEscaped):
		return helperproto.FileNotRootControlled
	case errors.Is(err, errUnsafe):
		return helperproto.FileHardLinked
	case errors.Is(err, errNotRegular), errors.Is(err, unix.ENOTDIR), errors.Is(err, unix.ELOOP):
		return helperproto.FileNotRegular
	case errors.Is(err, errTooLarge):
		return helperproto.FileTooLarge
	default:
		return helperproto.FileUnreadable
	}
}
```

Run the Step 3 tests → PASS (the root-only test skips as a normal user).

- [ ] **Step 5: Write the failing `nginx-dump`/`nginx-test` tests**

Create `cmd/alice-helper/nginx_test.go`. The tests inline their `nginx -T` text (no repository files: the root-only test binary runs in a container without the source tree) and generate certificates with `internal/testutil/pki`:

```go
//go:build linux

package main

import (
	"context"
	"encoding/pem"
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/testutil/pki"
)

const nginxV = `nginx version: nginx/1.22.1
built with OpenSSL 3.0.11 19 Sep 2023
TLS SNI support enabled
configure arguments: --with-cc-opt='-g -O2' --prefix=/usr/share/nginx --conf-path=/etc/nginx/nginx.conf --http-log-path=/var/log/nginx/access.log
`

const wwwDump = `# configuration file /etc/nginx/nginx.conf:
http { include /etc/nginx/conf.d/*.conf; }

# configuration file /etc/nginx/conf.d/www.conf:
server {
    listen 443 ssl;
    server_name www.example.test;
    ssl_certificate /etc/nginx/ssl/www.crt;
    ssl_certificate_key /etc/nginx/ssl/www.key;
}
server {
    listen 443 ssl;
    server_name both.example.test;
    ssl_certificate /etc/nginx/ssl/both.pem;
    ssl_certificate_key /etc/nginx/ssl/both.pem;
}
`

type nginxWorld struct {
	f        *fixture
	dump     string
	tFails   string // stderr of a failing "nginx -t"/"-T"; "" = success
	missing  bool   // /usr/sbin/nginx does not exist
	calls    []string
	leaf     pki.Leaf
}

func newNginxWorld(t *testing.T) *nginxWorld {
	f := newFixture(t)
	for _, d := range []string{"/etc/nginx", "/etc/nginx/conf.d", "/etc/nginx/ssl"} {
		f.mkdir(d, 0o755)
	}
	ca := pki.NewCA("Helper Test", pki.ECDSA256, testNow)
	w := &nginxWorld{f: f, dump: wwwDump, leaf: ca.Issue(pki.Opts{CommonName: "www.example.test"}, testNow)}
	f.write("/etc/nginx/nginx.conf", "x", 0o644)
	f.write("/etc/nginx/conf.d/www.conf", "x", 0o644)
	f.write("/etc/nginx/ssl/www.crt", string(w.leaf.FullchainPEM), 0o644)
	f.write("/etc/nginx/ssl/www.key", string(w.leaf.KeyPEM), 0o600)
	f.s.runNginx = func(_ context.Context, args ...string) ([]byte, []byte, error) {
		w.calls = append(w.calls, strings.Join(args, " "))
		if w.missing {
			return nil, nil, &fs.PathError{Op: "fork/exec", Path: nginxPath, Err: fs.ErrNotExist}
		}
		switch args[0] {
		case "-V":
			return nil, []byte(nginxV), nil
		case "-T":
			if w.tFails != "" {
				return nil, []byte(w.tFails), errors.New("exit status 1")
			}
			return []byte(w.dump), []byte("nginx: the configuration file /etc/nginx/nginx.conf syntax is ok\n"), nil
		case "-t":
			if w.tFails != "" {
				return nil, []byte(w.tFails), errors.New("exit status 1")
			}
			return nil, nil, nil
		}
		return nil, nil, errors.New("unexpected nginx arguments")
	}
	f.s.statfs = func(int) (int64, error) { return 1 << 30, nil }
	return w
}

func TestNginxDumpDescribesTheReferencedFiles(t *testing.T) {
	w := newNginxWorld(t)
	code, m := w.f.run("nginx-dump")
	require.Equal(t, 0, code, "%v", m)
	assert.Equal(t, "1.22.1", m["version"])
	assert.Equal(t, "/etc/nginx/nginx.conf", m["conf_path"])
	assert.Equal(t, true, m["config_valid"])
	assert.Equal(t, []string{"-V", "-T"}, w.calls)
	files := m["files"].([]any)
	require.Len(t, files, 2, "the combined pair is unsupported, so its file is not described")
	cert, key := files[0].(map[string]any), files[1].(map[string]any)
	assert.Equal(t, "cert", cert["kind"])
	assert.Equal(t, hexOf(string(w.leaf.FullchainPEM)), cert["sha256"])
	assert.Equal(t, string(w.leaf.FullchainPEM), cert["pem"])
	assert.Equal(t, "", cert["problem"])
	assert.Equal(t, "key", key["kind"])
	assert.Equal(t, "0600", key["mode"])
	assert.Equal(t, "", key["pem"])
	assert.Equal(t, "", key["sha256"], "a key file is never read")
	assert.NotContains(t, w.f.out.String(), string(w.leaf.KeyPEM[30:70]))
	servers := m["servers"].([]any)
	require.Len(t, servers, 2)
	pairs := servers[1].(map[string]any)["pairs"].([]any)
	assert.Equal(t, "combined_file", pairs[0].(map[string]any)["unsupported"])
	assert.Contains(t, w.f.loggedLines(), "nginx-dump ")
}

// A certificate file that also holds a private key: only the CERTIFICATE blocks leave the helper.
func TestNginxDumpNeverOutputsKeyBlocks(t *testing.T) {
	w := newNginxWorld(t)
	w.f.write("/etc/nginx/ssl/www.crt", string(w.leaf.FullchainPEM)+string(w.leaf.KeyPEM), 0o644)
	_, m := w.f.run("nginx-dump")
	out := m["files"].([]any)[0].(map[string]any)["pem"].(string)
	for rest := []byte(out); ; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		assert.Equal(t, "CERTIFICATE", b.Type)
	}
	assert.NotContains(t, w.f.out.String(), "PRIVATE"+" KEY")
}

// Review Focus 2, A-13: a link to /etc/shadow is resolved (root made it) but nothing but
// CERTIFICATE blocks would ever be returned, and shadow's name has no certificate extension.
func TestAttackSymlinkToShadowIsNeverRead(t *testing.T) {
	w := newNginxWorld(t)
	w.f.write("/etc/shadow", "root:$6$secret-hash:19000:0:99999:7:::\n", 0o600)
	require.NoError(t, os.Remove(w.f.host("/etc/nginx/ssl/www.crt")))
	require.NoError(t, os.Symlink("/etc/shadow", w.f.host("/etc/nginx/ssl/www.crt")))
	_, m := w.f.run("nginx-dump")
	cert := m["files"].([]any)[0].(map[string]any)
	assert.Equal(t, helperproto.FileBadName, cert["problem"])
	assert.Equal(t, "", cert["pem"])
	assert.NotContains(t, w.f.out.String(), "secret-hash")
}

func TestNginxDumpReportsFileProblems(t *testing.T) {
	w := newNginxWorld(t)
	require.NoError(t, os.Chmod(w.f.host("/etc/nginx/ssl"), 0o777))
	_, m := w.f.run("nginx-dump")
	for _, x := range m["files"].([]any) {
		assert.Equal(t, helperproto.FileNotRootControlled, x.(map[string]any)["problem"])
	}
	require.NoError(t, os.Chmod(w.f.host("/etc/nginx/ssl"), 0o755))
	w.f.write("/etc/nginx/ssl/www.crt", "not a certificate", 0o644)
	_, m = w.f.run("nginx-dump")
	assert.Equal(t, helperproto.FileNotACertificate, m["files"].([]any)[0].(map[string]any)["problem"])
	w.f.write("/etc/nginx/ssl/www.crt", strings.Repeat("a", helperproto.MaxCertFileSize+1), 0o644)
	_, m = w.f.run("nginx-dump")
	assert.Equal(t, helperproto.FileTooLarge, m["files"].([]any)[0].(map[string]any)["problem"])
	require.NoError(t, os.Remove(w.f.host("/etc/nginx/ssl/www.key")))
	_, m = w.f.run("nginx-dump")
	key := m["files"].([]any)[1].(map[string]any)
	assert.Equal(t, false, key["exists"])
	assert.Equal(t, helperproto.FileMissing, key["problem"])
}

func TestNginxDumpInvalidConfiguration(t *testing.T) {
	w := newNginxWorld(t)
	w.tFails = "nginx: [emerg] SSL_CTX_use_PrivateKey(\"/etc/nginx/ssl/www.key\") failed (SSL: error:05800074:x509 certificate routines::key values mismatch)\n"
	code, m := w.f.run("nginx-dump")
	require.Equal(t, 0, code)
	assert.Equal(t, false, m["config_valid"])
	assert.Equal(t, helperproto.ConfigErrKeyMismatch, m["config_error"])
	assert.Empty(t, m["servers"])
	assert.NotContains(t, w.f.out.String(), "/etc/nginx/ssl/www.key", "nginx's text never leaves the helper")
}

func TestNginxNotFound(t *testing.T) {
	w := newNginxWorld(t)
	w.missing = true
	for _, sub := range []string{"nginx-dump", "nginx-test"} {
		code, m := w.f.run(sub)
		assert.Equal(t, helperproto.ExitPrecondition, code, sub)
		assert.Equal(t, helperproto.CodeNginxNotFound, m["code"], sub)
	}
}

func TestNginxDumpFlagsWritableConfigurationFiles(t *testing.T) {
	w := newNginxWorld(t)
	require.NoError(t, os.Chmod(w.f.host("/etc/nginx/conf.d/www.conf"), 0o666))
	_, m := w.f.run("nginx-dump")
	assert.Equal(t, []any{"/etc/nginx/conf.d/www.conf"}, m["writable"])
	assert.Contains(t, m["warnings"], helperproto.WarnConfigFileWritable)
}

func TestNginxSubcommandsTakeNoArguments(t *testing.T) {
	w := newNginxWorld(t)
	for _, sub := range []string{"nginx-dump", "nginx-test"} {
		code, m := w.f.run(sub, "/etc/shadow")
		assert.Equal(t, helperproto.ExitRefused, code)
		assert.Equal(t, helperproto.CodeUsage, m["code"])
	}
}

func TestNginxTest(t *testing.T) {
	w := newNginxWorld(t)
	code, m := w.f.run("nginx-test")
	require.Equal(t, 0, code)
	assert.Equal(t, true, m["valid"])
	w.tFails = "nginx: [emerg] unknown directive \"sll_certificate\" in /etc/nginx/conf.d/www.conf:5\n"
	_, m = w.f.run("nginx-test")
	assert.Equal(t, false, m["valid"])
	assert.Equal(t, helperproto.ConfigErrSyntax, m["error"])
}

func TestClassifyNginxError(t *testing.T) {
	for in, want := range map[string]string{
		"SSL_CTX_use_PrivateKey(...) failed (SSL: error:...:key values mismatch)":                        helperproto.ConfigErrKeyMismatch,
		`cannot load certificate "/x.crt": BIO_new_file() failed (SSL: error:...:No such file or directory)`: helperproto.ConfigErrFileMissing,
		`cannot load certificate "/x.crt": PEM_read_bio_X509_AUX() failed`:                               helperproto.ConfigErrCertLoad,
		`cannot load certificate key "/x.key": PEM_read_bio_PrivateKey() failed`:                          helperproto.ConfigErrKeyLoad,
		`unexpected "}" in /etc/nginx/nginx.conf:9`:                                                      helperproto.ConfigErrSyntax,
	} {
		assert.Equal(t, want, classifyNginxError([]byte(in)), in)
	}
}
```

Update `TestPrivilegedSubcommandsNeedRoot` to include `nginx-dump` and `nginx-test`.

Run: `go test ./cmd/alice-helper -run 'Nginx|ClassifyNginx|SymlinkToShadow' -count=1`
Expected: FAIL.

- [ ] **Step 6: Implement `nginx.go`**

`sys.go` gains:

```go
	// runNginx runs /usr/sbin/nginx with fixed arguments (-V, -T, -t); stdout is capped at
	// helperproto.MaxNginxConfig, stderr at 64 KiB. A missing binary is an fs.ErrNotExist error.
	runNginx func(ctx context.Context, args ...string) (stdout, stderr []byte, err error)
	// runSystemctl runs /usr/bin/systemctl with fixed arguments (Task 6).
	runSystemctl func(ctx context.Context, args ...string) error
	// statfs returns the bytes available to root in the file system of a descriptor.
	statfs func(fd int) (int64, error)
	// dial opens the TCP connection of tls-probe.
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
```

`main.go`'s `productionSys` sets them:

```go
		runNginx: func(ctx context.Context, args ...string) ([]byte, []byte, error) {
			return runProgram(ctx, nginxPath, helperproto.MaxNginxConfig, args...)
		},
		runSystemctl: func(ctx context.Context, args ...string) error {
			_, _, err := runProgram(ctx, systemctlPath, 64<<10, args...)
			return err
		},
		statfs: func(fd int) (int64, error) {
			var st unix.Statfs_t
			if err := unix.Fstatfs(fd, &st); err != nil {
				return 0, err
			}
			return int64(st.Bavail) * st.Bsize, nil //nolint:gosec // G115: block counts fit an int64
		},
		dial: (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
```

`nginx.go`:

```go
//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"

	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/providers/nginx/nginxconf"
)

// The fixed programs of the nginx subcommands (spec §12.1, R38 item 5).
const (
	nginxPath     = "/usr/sbin/nginx"
	systemctlPath = "/usr/bin/systemctl"
	stderrLimit   = 64 << 10
)

// runProgram runs a fixed program with a clean environment; stdout is capped at outLimit
// (errTooLarge over it), stderr at stderrLimit (kept only for classification, never returned to Alice).
func runProgram(ctx context.Context, path string, outLimit int, args ...string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, path, args...) //nolint:gosec // G204: fixed program and fixed arguments
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	cmd.Stdin = nil
	out := &capWriter{max: outLimit}
	errOut := &capWriter{max: stderrLimit}
	cmd.Stdout, cmd.Stderr = out, errOut
	err := cmd.Run()
	if out.over {
		return nil, errOut.buf, errTooLarge
	}
	return out.buf, errOut.buf, err
}

// classifyNginxError reduces nginx's error text to a class (never the text: it names files and
// may quote configuration).
func classifyNginxError(stderr []byte) string {
	s := string(stderr)
	switch {
	case strings.Contains(s, "key values mismatch"):
		return helperproto.ConfigErrKeyMismatch
	case strings.Contains(s, "No such file or directory"):
		return helperproto.ConfigErrFileMissing
	case strings.Contains(s, "cannot load certificate key"), strings.Contains(s, "SSL_CTX_use_PrivateKey"), strings.Contains(s, "PEM_read_bio_PrivateKey"):
		return helperproto.ConfigErrKeyLoad
	case strings.Contains(s, "cannot load certificate"), strings.Contains(s, "PEM_read_bio_X509"), strings.Contains(s, "SSL_CTX_use_certificate"):
		return helperproto.ConfigErrCertLoad
	default:
		return helperproto.ConfigErrSyntax
	}
}

type nginxMeta struct {
	version  string
	confPath string
	valid    bool
	class    string
}

var errNginxMissing = errors.New("nginx is not installed")

// nginxConfig runs "nginx -V" and "nginx -T" and parses the configuration. An invalid
// configuration is not an error: meta.valid is false and the Config is empty.
func (s *sys) nginxConfig(ctx context.Context) (nginxconf.Config, nginxMeta, error) {
	var meta nginxMeta
	_, verr, err := s.runNginx(ctx, "-V")
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, exec.ErrNotFound) {
		return nginxconf.Config{}, meta, errNginxMissing
	}
	if err != nil {
		return nginxconf.Config{}, meta, err
	}
	meta.version, meta.confPath = parseNginxV(verr)
	out, terr, err := s.runNginx(ctx, "-T")
	switch {
	case errors.Is(err, errTooLarge):
		return nginxconf.Config{}, meta, errTooLarge
	case err != nil:
		meta.class = classifyNginxError(terr)
		return nginxconf.Config{}, meta, nil
	}
	confDir := ""
	if helperproto.ValidPath(meta.confPath) {
		confDir = filepath.Dir(meta.confPath)
	}
	cfg, err := nginxconf.Parse(out, confDir)
	if err != nil {
		meta.class = helperproto.ConfigErrSyntax
		return nginxconf.Config{}, meta, nil
	}
	meta.valid = true
	return cfg, meta, nil
}

// parseNginxV reads the version and --conf-path from "nginx -V" (stderr). The default conf path
// of the standard packages applies when the build does not name one.
func parseNginxV(b []byte) (version, confPath string) {
	confPath = "/etc/nginx/nginx.conf"
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "nginx version: nginx/"); ok {
			version, _, _ = strings.Cut(v, " ")
		}
		if rest, ok := strings.CutPrefix(line, "configure arguments:"); ok {
			for _, arg := range strings.Fields(rest) {
				if p, ok := strings.CutPrefix(arg, "--conf-path="); ok {
					confPath = p
				}
			}
		}
	}
	if len(version) > 40 {
		version = version[:40]
	}
	return version, filepath.Clean(confPath)
}

func cmdNginxDump(ctx context.Context, s *sys, args []string) (any, error) {
	if len(args) != 0 {
		return nil, refused(helperproto.CodeUsage, "nginx-dump takes no arguments")
	}
	s.syslog(helperproto.SubNginxDump, "")
	cfg, meta, err := s.nginxConfig(ctx)
	switch {
	case errors.Is(err, errNginxMissing):
		return nil, precondition(helperproto.CodeNginxNotFound, "nginx is not installed at /usr/sbin/nginx")
	case err != nil:
		return nil, failed(helperproto.CodeIOError, "nginx could not be run")
	}
	resp := helperproto.NginxDumpResponse{OK: true, Version: meta.version, ConfPath: meta.confPath, ConfigValid: meta.valid,
		ConfigError: meta.class, Servers: []helperproto.NginxServer{}, Files: []helperproto.NginxFile{},
		Warnings: append([]string{}, cfg.Warnings...), Writable: []string{}}
	if !meta.valid {
		return resp, nil
	}
	names := map[int]string{}
	if accts, err := s.accounts(); err == nil {
		names = owners(accts)
	}
	for _, sv := range cfg.Servers {
		resp.Servers = append(resp.Servers, toWire(sv))
	}
	n := 0
	for _, p := range cfg.CertPaths() {
		if n++; n > helperproto.MaxNginxFiles {
			resp.Warnings = append(resp.Warnings, helperproto.WarnTooManyFiles)
			break
		}
		resp.Files = append(resp.Files, s.describeCert(p, names))
	}
	for _, p := range cfg.KeyPaths() {
		if n++; n > helperproto.MaxNginxFiles {
			if !slices.Contains(resp.Warnings, helperproto.WarnTooManyFiles) {
				resp.Warnings = append(resp.Warnings, helperproto.WarnTooManyFiles)
			}
			break
		}
		resp.Files = append(resp.Files, s.describeKey(p, names))
	}
	resp.Writable = s.writableConfigs(cfg.Files)
	if len(resp.Writable) > 0 {
		resp.Warnings = append(resp.Warnings, helperproto.WarnConfigFileWritable)
	}
	return resp, nil
}
```

`toWire(sv nginxconf.Server) helperproto.NginxServer` copies `File`, `Line`, `Names` (each name truncated to 253 bytes), the SSL listens only (`nginxconf.SSLListens`), the pairs (`Raw` = `CertRaw` for an unsupported pair, truncated to 200 runes, control characters dropped), `Stream`; slices are never `nil` (empty arrays on the wire).

```go
// describeCert reads a certificate file through resolveRoot and returns its CERTIFICATE blocks.
func (s *sys) describeCert(p string, names map[int]string) helperproto.NginxFile {
	fi := helperproto.NginxFile{Path: p, Kind: "cert"}
	rf, err := s.resolveRoot(p)
	if err != nil {
		fi.Exists = !errors.Is(err, unix.ENOENT)
		fi.Problem = problemOf(err)
		return fi
	}
	defer rf.close()
	fi.Resolved, fi.Symlinked = rf.resolved, rf.symlinked
	fi.FreeBytes, _ = s.statfs(rf.dirfd)
	if !certName(rf.name) {
		fi.Exists, fi.Problem = true, helperproto.FileBadName
		return fi
	}
	f, st, err := rf.open()
	if err != nil {
		fi.Exists = !errors.Is(err, unix.ENOENT)
		fi.Problem = problemOf(err)
		return fi
	}
	defer func() { _ = f.Close() }()
	fi.Exists, fi.Size = true, st.Size
	fi.Mode, fi.Owner = fmt.Sprintf("%04o", st.Mode&0o777), ownerName(names, int(st.Uid))
	if st.Size > helperproto.MaxCertFileSize {
		fi.Problem = helperproto.FileTooLarge
		return fi
	}
	data, err := io.ReadAll(io.LimitReader(f, helperproto.MaxCertFileSize+1))
	defer clear(data)
	if err != nil || len(data) > helperproto.MaxCertFileSize {
		fi.Problem = helperproto.FileUnreadable
		return fi
	}
	fi.SHA256 = hexSHA(data)
	if blocks := certBlocks(data); blocks != "" {
		fi.PEM = blocks
	} else {
		fi.Problem = helperproto.FileNotACertificate
	}
	return fi
}

// certBlocks returns only the CERTIFICATE blocks of data, re-encoded; every other block (a
// private key in a combined file) is dropped.
func certBlocks(data []byte) string {
	var b bytes.Buffer
	for rest := bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")); ; {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type == "CERTIFICATE" && len(blk.Headers) == 0 {
			_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: blk.Bytes})
		}
	}
	return b.String()
}

// describeKey stats a key file through resolveRoot; its content is never opened.
func (s *sys) describeKey(p string, names map[int]string) helperproto.NginxFile {
	fi := helperproto.NginxFile{Path: p, Kind: "key"}
	rf, err := s.resolveRoot(p)
	if err != nil {
		fi.Exists = !errors.Is(err, unix.ENOENT)
		fi.Problem = problemOf(err)
		return fi
	}
	defer rf.close()
	fi.Resolved, fi.Symlinked = rf.resolved, rf.symlinked
	var st unix.Stat_t
	if err := unix.Fstatat(rf.dirfd, rf.name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		fi.Exists = !errors.Is(err, unix.ENOENT)
		fi.Problem = problemOf(err)
		return fi
	}
	fi.Exists, fi.Size = true, st.Size
	fi.Mode, fi.Owner = fmt.Sprintf("%04o", st.Mode&0o777), ownerName(names, int(st.Uid))
	switch {
	case !certName(rf.name):
		fi.Problem = helperproto.FileBadName
	case st.Mode&unix.S_IFMT != unix.S_IFREG:
		fi.Problem = helperproto.FileNotRegular
	case st.Nlink != 1:
		fi.Problem = helperproto.FileHardLinked
	}
	return fi
}

func ownerName(names map[int]string, uid int) string {
	if n := names[uid]; n != "" {
		return n
	}
	return fmt.Sprint(uid)
}

// writableConfigs lists configuration files a user other than root could change (their own
// mode, owner, or a directory or link on their path).
func (s *sys) writableConfigs(files []string) []string {
	out := []string{}
	for _, p := range files {
		rf, err := s.resolveRoot(p)
		if errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			out = append(out, p)
			continue
		}
		var st unix.Stat_t
		err = unix.Fstatat(rf.dirfd, rf.name, &st, unix.AT_SYMLINK_NOFOLLOW)
		rf.close()
		if err == nil && (int(st.Uid) != s.rootUID || st.Mode&0o022 != 0) {
			out = append(out, p)
		}
	}
	return out
}

func cmdNginxTest(ctx context.Context, s *sys, args []string) (any, error) {
	if len(args) != 0 {
		return nil, refused(helperproto.CodeUsage, "nginx-test takes no arguments")
	}
	s.syslog(helperproto.SubNginxTest, "")
	_, stderr, err := s.runNginx(ctx, "-t")
	switch {
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, exec.ErrNotFound):
		return nil, precondition(helperproto.CodeNginxNotFound, "nginx is not installed at /usr/sbin/nginx")
	case err != nil:
		return helperproto.NginxTestResponse{OK: true, Valid: false, Error: classifyNginxError(stderr)}, nil
	}
	return helperproto.NginxTestResponse{OK: true, Valid: true}, nil
}
```

`run.go` `commands` gains:

```go
	helperproto.SubNginxDump: {privileged: true, handle: cmdNginxDump},
	helperproto.SubNginxTest: {privileged: true, handle: cmdNginxTest},
	helperproto.SubTLSProbe:  {handle: cmdTLSProbe},
```

The fixture's `sys` must set `runNginx`, `statfs` and `dial` defaults (a `runNginx` that answers `fs.ErrNotExist`, `statfs` 1 GiB, `dial` = `net.Dialer.DialContext`) so Phase 3 tests that never touch Nginx keep working.

Run: `go test ./cmd/alice-helper -count=1`
Expected: PASS.

- [ ] **Step 7: `tls-probe`, failing test first**

Create `cmd/alice-helper/probe_test.go`:

```go
//go:build linux

package main

import (
	"crypto/tls"
	"net"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/testutil/pki"
)

// startTLS serves leaf on 127.0.0.1 and returns the port.
func startTLS(t *testing.T, leaf pki.Leaf) string {
	t.Helper()
	cert, err := tls.X509KeyPair(leaf.FullchainPEM, leaf.KeyPEM)
	require.NoError(t, err)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = c.(*tls.Conn).Handshake(); _ = c.Close() }()
		}
	}()
	return strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
}
```

```go
func TestTLSProbeReportsTheServedLeaf(t *testing.T) {
	f := newFixture(t)
	f.s.euid = func() int { return 1000 } // runs without sudo
	ca := pki.NewCA("Probe", pki.ECDSA256, testNow)
	leaf := ca.Issue(pki.Opts{CommonName: "www.example.test"}, testNow)
	port := startTLS(t, leaf)
	code, m := f.run("tls-probe", "--addr", "127.0.0.1", "--port", port, "--sni", "www.example.test", "--key-type", "any")
	require.Equal(t, 0, code, "%v", m)
	assert.Equal(t, pki.Fingerprint(leaf.Cert), m["leaf_sha256"])
	assert.Equal(t, float64(2), m["chain_length"])
	code, m = f.run("tls-probe", "--addr", "127.0.0.1", "--port", port, "--sni", helperproto.NoSNI, "--key-type", "ecdsa")
	require.Equal(t, 0, code, "%v", m)
}

func TestTLSProbeFailuresAndArguments(t *testing.T) {
	f := newFixture(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	closedPort := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	require.NoError(t, ln.Close())
	code, m := f.run("tls-probe", "--addr", "127.0.0.1", "--port", closedPort, "--sni", "a.example.test", "--key-type", "any")
	assert.Equal(t, helperproto.ExitFailed, code)
	assert.Equal(t, helperproto.CodeProbeFailed, m["code"])
	for _, args := range [][]string{
		{"--addr", "localhost", "--port", "443", "--sni", "a.b", "--key-type", "any"},
		{"--addr", "127.0.0.1", "--port", "0", "--sni", "a.b", "--key-type", "any"},
		{"--addr", "127.0.0.1", "--port", "443", "--sni", "A.B", "--key-type", "any"},
		{"--addr", "127.0.0.1", "--port", "443", "--sni", "a.b", "--key-type", "dsa"},
		{"--port", "443", "--addr", "127.0.0.1", "--sni", "a.b", "--key-type", "any"},
	} {
		code, m := f.run(append([]string{"tls-probe"}, args...)...)
		assert.Equal(t, helperproto.ExitRefused, code, "%v", args)
		assert.Contains(t, []any{helperproto.CodeUsage, helperproto.CodeInvalidArgument}, m["code"])
	}
}
```

Run → FAIL. Implement `cmd/alice-helper/probe.go`:

```go
//go:build linux

package main

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"alice/internal/providers/linuxssh/helperproto"
)

const probeTimeout = 15 * time.Second

// cmdTLSProbe connects to a TLS endpoint on the server itself and reports the served leaf
// (spec §12.8 item 6, R38 item 6). It runs without sudo; it sends no application data.
func cmdTLSProbe(ctx context.Context, s *sys, args []string) (any, error) {
	if len(args) != 8 || args[0] != "--addr" || args[2] != "--port" || args[4] != "--sni" || args[6] != "--key-type" {
		return nil, refused(helperproto.CodeUsage, "usage: tls-probe --addr <ip> --port <port> --sni <name|_> --key-type <any|rsa|ecdsa>")
	}
	addr, port, sni, kt := args[1], args[3], args[5], args[7]
	if !helperproto.ValidIP(addr) || !helperproto.ValidPort(port) || (sni != helperproto.NoSNI && !helperproto.ValidSNI(sni)) ||
		(kt != helperproto.ProbeAny && kt != helperproto.ProbeRSA && kt != helperproto.ProbeECDSA) {
		return nil, refused(helperproto.CodeInvalidArgument, "an argument is not allowed")
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	conn, err := s.dial(ctx, "tcp", net.JoinHostPort(addr, port))
	if err != nil {
		return nil, failed(helperproto.CodeProbeFailed, "the endpoint cannot be reached")
	}
	defer func() { _ = conn.Close() }()
	tc := tls.Client(conn, helperproto.ProbeTLSConfig(sni, kt))
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, failed(helperproto.CodeProbeFailed, "the TLS handshake failed")
	}
	cs := tc.ConnectionState()
	if len(cs.PeerCertificates) == 0 {
		return nil, failed(helperproto.CodeProbeFailed, "the server sent no certificate")
	}
	leaf := cs.PeerCertificates[0]
	return helperproto.TLSProbeResponse{OK: true, LeafSHA256: hexSHA(leaf.Raw), ChainLength: len(cs.PeerCertificates),
		NotAfter: leaf.NotAfter.UTC().Format(time.RFC3339)}, nil
}
```

Run: `go test ./cmd/alice-helper -count=1` → PASS.

- [ ] **Step 8: e2e image build context**

In `test/images/e2e-target/Dockerfile`, after `COPY internal/providers/linuxssh/sshdconf/ internal/providers/linuxssh/sshdconf/` add `COPY internal/providers/nginx/nginxconf/ internal/providers/nginx/nginxconf/`. (`deploy/Dockerfile` copies the whole tree.)

- [ ] **Step 9: Helper change procedure**

Run, in order (Global Constraints):
1. `go test ./cmd/alice-helper -count=1` → PASS (root-only tests skip).
2. `CGO_ENABLED=0 go test -c -o /tmp/alice-helper.test ./cmd/alice-helper && docker run --rm --network none -v /tmp/alice-helper.test:/alice-helper.test:ro debian:12 /alice-helper.test -test.count=1 -test.run 'AsRoot|Attack|Root'` (Docker: a throwaway container) → PASS, including `TestAttackUserOwnedLinkAndDirectoryAsRoot` and Phase 3's root tests.
3. `go test ./cmd/alice-helper -run TestHelperIsStatic -count=1` → PASS (only `golang.org/x/crypto` and `golang.org/x/sys` modules).
4. `make helper` → new `bin/alice-helper.sha256` (not committed; `bin/` is ignored) so `make build` embeds the new checksums.
5. `ALICE_SSH_IMAGES=ubuntu22 make test-ssh` (Docker: testcontainers) → PASS: the Phase 3 matrix still works with the protocol 4 helper (built from source by the test; the provider requires protocol 4 since Task 4).

- [ ] **Step 10: Commit**

```bash
git add cmd/alice-helper test/images/e2e-target/Dockerfile
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "feat(helper): nginx-dump, nginx-test and tls-probe on a root-controlled path walk; report every account name

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 6: **HELPER** part 2 — `nginx-deploy`, `nginx-restore`, `nginx-status`, backup retention

The write side. `nginx-deploy` is one root-side transaction (R38 item 1): under the helper's Nginx lock it re-reads the configuration (`nginx -T` must pass: F-02; the pair must still be in it), resolves both files with `resolveRoot`, compares the certificate file with the hash Alice saw at discovery, checks free space (F-10, F-11), backs both files up into the root-only operation directory, writes a journal, writes the key and then the certificate through staged files and `renameat` in the resolved directory (owner, group, SELinux label kept; key 0600 or 0640, certificate at most 0644: F-13), runs `nginx -t`, `systemctl reload nginx` and `systemctl is-active nginx`, and on any failure after the first rename restores both files from the backup, re-tests and reloads. From the first rename on it runs to its end even if Alice or the connection goes away (it ignores `SIGHUP`/`SIGPIPE` and stops using the request's deadline). The journal is the truth for `nginx-status` and `nginx-restore` after any interruption, including a kill of the helper itself between two renames.

**Files:**
- Create: `cmd/alice-helper/journal.go` (`journal`, `opDir`, `readJournal`, `writeJournal`, `nginxLock`)
- Create: `cmd/alice-helper/deploy.go` (`cmdNginxDeploy`, `cmdNginxRestore`, `cmdNginxStatus`, `readTarget`, `replaceFile`, `restoreOp`, `reload`, mode rules)
- Modify: `cmd/alice-helper/sys.go` (`afterDeployStep`), `cmd/alice-helper/main.go` (ignore `SIGHUP`, `SIGPIPE`), `cmd/alice-helper/run.go` (`commands` entries), `cmd/alice-helper/cleanup.go` (`sweepBackups` keeps Nginx operations 7 or 30 days)
- Test: `cmd/alice-helper/deploy_test.go`

**Interfaces:**
- Consumes: Task 5 `resolveRoot`, `rootFile`, `certName`, `nginxConfig`, `classifyNginxError`, `sys.runNginx`, `sys.runSystemctl`, `sys.statfs`; Phase 3 `openBackupRoot`, `subdir`, `writeNewAt`, `removeAt`, `openStateDir`, `lockDirName`, `openLockFile`, `flockWait`, `lockWait`, `sameFile`, `copySELinux`, `sys.chown`, `sys.beforeRename`, `hexSHA`, `backupRetention`.
- Produces: the wire behaviour of `nginx-deploy`, `nginx-restore`, `nginx-status` (contract table and phases); backup layout `<BackupRoot>/<op>/{journal.json,cert.bak,key.bak}`.

- [ ] **Step 1: Write the failing tests**

Create `cmd/alice-helper/deploy_test.go`. It builds on `newNginxWorld` (Task 5) with `wwwDump`, adds a `runSystemctl` fake and a recorder for `chown`:

```go
//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/testutil/pki"
)

const opA = "0190f5a0-0000-7000-8000-0000000000d1"

type deployWorld struct {
	*nginxWorld
	newLeaf    pki.Leaf
	reloads    int
	reloadFail int // fail the next n reloads
	testFail   int // fail the next n "nginx -t" (after nginx -T passed)
	chowns     []chownCall
}

func newDeployWorld(t *testing.T) *deployWorld {
	w := &deployWorld{nginxWorld: newNginxWorld(t)}
	ca := pki.NewCA("Deploy Test", pki.ECDSA256, testNow)
	w.newLeaf = ca.Issue(pki.Opts{CommonName: "www.example.test"}, testNow)
	inner := w.f.s.runNginx
	w.f.s.runNginx = func(ctx context.Context, args ...string) ([]byte, []byte, error) {
		if args[0] == "-t" && w.testFail > 0 {
			w.testFail--
			return nil, []byte("SSL_CTX_use_PrivateKey failed (key values mismatch)"), errors.New("exit status 1")
		}
		return inner(ctx, args...)
	}
	w.f.s.runSystemctl = func(_ context.Context, args ...string) error {
		if args[0] == "reload" {
			w.reloads++
			if w.reloadFail > 0 {
				w.reloadFail--
				return errors.New("exit status 1")
			}
		}
		return nil
	}
	w.f.s.chown = func(f *os.File, uid, gid int) error {
		w.chowns = append(w.chowns, chownCall{name: f.Name(), uid: uid, gid: gid})
		return nil
	}
	return w
}

// input is the stdin of nginx-deploy for the new pair (or any other content).
func input(certPEM, keyPEM []byte) string {
	b, _ := json.Marshal(helperproto.NginxDeployInput{CertPEM: string(certPEM), KeyPEM: string(keyPEM)})
	return string(b)
}

func (w *deployWorld) deploy(op string, in string, expect string) (int, map[string]any) {
	return w.f.runWith(in, "nginx-deploy", "--op", op, "--cert", "/etc/nginx/ssl/www.crt", "--key", "/etc/nginx/ssl/www.key",
		"--expect-cert-sha256", expect, "--content-sha256", hexOf(in))
}

func (w *deployWorld) oldSHA() string { return hexOf(string(w.leaf.FullchainPEM)) }

// The pair on disk is always one of the two consistent pairs.
func (w *deployWorld) assertPair(t *testing.T, newPair bool) {
	t.Helper()
	cert, key := w.f.read("/etc/nginx/ssl/www.crt"), w.f.read("/etc/nginx/ssl/www.key")
	if newPair {
		assert.Equal(t, string(w.newLeaf.FullchainPEM), cert)
		assert.Equal(t, string(w.newLeaf.KeyPEM), key)
		return
	}
	assert.Equal(t, string(w.leaf.FullchainPEM), cert)
	assert.Equal(t, string(w.leaf.KeyPEM), key)
}

func TestDeployCommits(t *testing.T) {
	w := newDeployWorld(t)
	code, m := w.deploy(opA, input(w.newLeaf.FullchainPEM, w.newLeaf.KeyPEM), w.oldSHA())
	require.Equal(t, 0, code, "%v", m)
	assert.Equal(t, helperproto.PhaseCommitted, m["phase"])
	assert.Equal(t, helperproto.BackupRoot+"/"+opA, m["backup_dir"])
	var steps []string
	for _, s := range m["steps"].([]any) {
		steps = append(steps, s.(map[string]any)["name"].(string)+":"+s.(map[string]any)["status"].(string))
	}
	assert.Equal(t, []string{"backup:ok", "write_key:ok", "write_cert:ok", "config_test:ok", "reload:ok"}, steps)
	w.assertPair(t, true)
	assert.Equal(t, 1, w.reloads)
	assert.Equal(t, string(w.leaf.KeyPEM), w.f.read(helperproto.BackupRoot+"/"+opA+"/key.bak"), "the old key is backed up root-only")
	st, err := os.Stat(w.f.host(helperproto.BackupRoot + "/" + opA + "/key.bak"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), st.Mode().Perm())
	ks, err := os.Stat(w.f.host("/etc/nginx/ssl/www.key"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), ks.Mode().Perm())
	cs, err := os.Stat(w.f.host("/etc/nginx/ssl/www.crt"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o644), cs.Mode().Perm())
	assert.NotContains(t, w.f.out.String(), string(w.newLeaf.KeyPEM[30:70]), "no key material in the answer")
	entries, err := os.ReadDir(w.f.host("/etc/nginx/ssl"))
	require.NoError(t, err)
	assert.Len(t, entries, 2, "no staging file remains")
	assert.Contains(t, w.f.loggedLines(), "nginx-deploy /etc/nginx/ssl/www.crt")
}

// F-13 and Review Focus 1: a 0644 key becomes 0600; a 0640 key (ssl-cert group) stays 0640.
func TestDeployKeyModes(t *testing.T) {
	for _, tc := range []struct{ before, after os.FileMode }{{0o644, 0o600}, {0o640, 0o640}, {0o600, 0o600}, {0o400, 0o600}} {
		w := newDeployWorld(t)
		require.NoError(t, os.Chmod(w.f.host("/etc/nginx/ssl/www.key"), tc.before))
		code, m := w.deploy(opA, input(w.newLeaf.FullchainPEM, w.newLeaf.KeyPEM), w.oldSHA())
		require.Equal(t, 0, code, "%v", m)
		st, err := os.Stat(w.f.host("/etc/nginx/ssl/www.key"))
		require.NoError(t, err)
		assert.Equal(t, tc.after, st.Mode().Perm(), "from %o", tc.before)
	}
}

func TestDeployKeepsOwnerAndGroup(t *testing.T) {
	w := newDeployWorld(t)
	code, _ := w.deploy(opA, input(w.newLeaf.FullchainPEM, w.newLeaf.KeyPEM), w.oldSHA())
	require.Equal(t, 0, code)
	require.Len(t, w.chowns, 2, "key then certificate")
	st, err := os.Stat(w.f.host(helperproto.BackupRoot + "/" + opA + "/key.bak"))
	require.NoError(t, err)
	uid, gid := owner(st)
	assert.Equal(t, uid, w.chowns[0].uid)
	assert.Equal(t, gid, w.chowns[0].gid)
}

// Review Focus 1: the write lands on the link's target; the link stays a link.
func TestDeployWritesThroughTheLinkTarget(t *testing.T) {
	w := newDeployWorld(t)
	w.f.mkdir("/etc/nginx/archive", 0o755)
	require.NoError(t, os.Rename(w.f.host("/etc/nginx/ssl/www.crt"), w.f.host("/etc/nginx/archive/www3.crt")))
	require.NoError(t, os.Symlink("../archive/www3.crt", w.f.host("/etc/nginx/ssl/www.crt")))
	code, m := w.deploy(opA, input(w.newLeaf.FullchainPEM, w.newLeaf.KeyPEM), w.oldSHA())
	require.Equal(t, 0, code, "%v", m)
	target, err := os.Readlink(w.f.host("/etc/nginx/ssl/www.crt"))
	require.NoError(t, err)
	assert.Equal(t, "../archive/www3.crt", target)
	assert.Equal(t, string(w.newLeaf.FullchainPEM), w.f.read("/etc/nginx/archive/www3.crt"))
}

func TestDeployIsIdempotentPerOperation(t *testing.T) {
	w := newDeployWorld(t)
	in := input(w.newLeaf.FullchainPEM, w.newLeaf.KeyPEM)
	code, _ := w.deploy(opA, in, w.oldSHA())
	require.Equal(t, 0, code)
	code, m := w.deploy(opA, in, w.oldSHA())
	require.Equal(t, 0, code, "the journal answers a repeated operation")
	assert.Equal(t, helperproto.PhaseCommitted, m["phase"])
	assert.Equal(t, 1, w.reloads, "nothing is done twice")
}

// §12.9 "Same cert already deployed": no write, no reload.
func TestDeployUnchangedWhenTheFilesAlreadyMatch(t *testing.T) {
	w := newDeployWorld(t)
	code, m := w.deploy(opA, input(w.leaf.FullchainPEM, w.leaf.KeyPEM), w.oldSHA())
	require.Equal(t, 0, code, "%v", m)
	assert.Equal(t, helperproto.PhaseUnchanged, m["phase"])
	assert.Equal(t, 0, w.reloads)
}

// Every refusal changes nothing (F-02, F-10, F-11, F-12, A-13, CAS).
func TestDeployRefusesBeforeChangingAnything(t *testing.T) {
	type tc struct {
		name  string
		setup func(w *deployWorld) (in string, args []string)
		exit  int
		code  string
	}
	std := func(w *deployWorld, in string) []string {
		return []string{"--op", opA, "--cert", "/etc/nginx/ssl/www.crt", "--key", "/etc/nginx/ssl/www.key",
			"--expect-cert-sha256", w.oldSHA(), "--content-sha256", hexOf(in)}
	}
	good := func(w *deployWorld) string { return input(w.newLeaf.FullchainPEM, w.newLeaf.KeyPEM) }
	for _, c := range []tc{
		{"content mismatch", func(w *deployWorld) (string, []string) {
			in := good(w)
			a := std(w, in)
			a[9] = strings.Repeat("0", 64)
			return in, a
		}, helperproto.ExitPrecondition, helperproto.CodeContentMismatch},
		{"key in the certificate", func(w *deployWorld) (string, []string) {
			in := input(w.newLeaf.KeyPEM, w.newLeaf.KeyPEM)
			return in, std(w, in)
		}, helperproto.ExitRefused, helperproto.CodeBadContent},
		{"certificate in the key", func(w *deployWorld) (string, []string) {
			in := input(w.newLeaf.FullchainPEM, w.newLeaf.FullchainPEM)
			return in, std(w, in)
		}, helperproto.ExitRefused, helperproto.CodeBadContent},
		{"two keys", func(w *deployWorld) (string, []string) {
			in := input(w.newLeaf.FullchainPEM, append(append([]byte{}, w.newLeaf.KeyPEM...), w.leaf.KeyPEM...))
			return in, std(w, in)
		}, helperproto.ExitRefused, helperproto.CodeBadContent},
		{"unknown JSON field", func(w *deployWorld) (string, []string) {
			in := `{"cert_pem":"x","key_pem":"y","extra":1}`
			return in, std(w, in)
		}, helperproto.ExitRefused, helperproto.CodeBadContent},
		{"configuration already broken (F-02)", func(w *deployWorld) (string, []string) {
			w.tFails = "unexpected \"}\""
			in := good(w)
			return in, std(w, in)
		}, helperproto.ExitPrecondition, helperproto.CodeConfigInvalid},
		{"pair not in the configuration", func(w *deployWorld) (string, []string) {
			in := good(w)
			a := std(w, in)
			a[3], a[5] = "/etc/nginx/ssl/www.key", "/etc/nginx/ssl/www.crt"
			return in, a
		}, helperproto.ExitPrecondition, helperproto.CodeConfigChanged},
		{"file changed since discovery", func(w *deployWorld) (string, []string) {
			in := good(w)
			a := std(w, in)
			a[7] = strings.Repeat("a", 64)
			return in, a
		}, helperproto.ExitPrecondition, helperproto.CodeHashMismatch},
		{"no free space (F-10; F-11: the backup directory is checked the same way)", func(w *deployWorld) (string, []string) {
			w.f.s.statfs = func(int) (int64, error) { return 1 << 20, nil }
			in := good(w)
			return in, std(w, in)
		}, helperproto.ExitPrecondition, helperproto.CodeNoSpace},
		{"user-writable directory", func(w *deployWorld) (string, []string) {
			require.NoError(t, os.Chmod(w.f.host("/etc/nginx/ssl"), 0o777))
			in := good(w)
			return in, std(w, in)
		}, helperproto.ExitRefused, helperproto.CodePathNotAllowed},
		{"hard link", func(w *deployWorld) (string, []string) {
			require.NoError(t, os.Link(w.f.host("/etc/nginx/ssl/www.key"), w.f.host("/etc/nginx/key-copy.key")))
			in := good(w)
			return in, std(w, in)
		}, helperproto.ExitRefused, helperproto.CodeUnsafeFile},
		{"same path twice", func(w *deployWorld) (string, []string) {
			in := good(w)
			a := std(w, in)
			a[5] = a[3]
			return in, a
		}, helperproto.ExitRefused, helperproto.CodeInvalidArgument},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := newDeployWorld(t)
			in, args := c.setup(w)
			code, m := w.f.runWith(in, append([]string{"nginx-deploy"}, args...)...)
			assert.Equal(t, c.exit, code, "%v", m)
			assert.Equal(t, c.code, m["code"])
			_ = os.Chmod(w.f.host("/etc/nginx/ssl"), 0o755)
			w.assertPair(t, false)
			assert.Equal(t, 0, w.reloads)
		})
	}
}

// F-01 at helper level: nginx -t fails after the write; both files come back.
func TestDeployRollsBackWhenConfigTestFails(t *testing.T) {
	w := newDeployWorld(t)
	w.testFail = 1
	code, m := w.deploy(opA, input(w.newLeaf.FullchainPEM, w.newLeaf.KeyPEM), w.oldSHA())
	require.Equal(t, 0, code, "%v", m)
	assert.Equal(t, helperproto.PhaseRestored, m["phase"])
	assert.Equal(t, helperproto.StepConfigTest, m["failed_step"])
	assert.Equal(t, helperproto.ConfigErrKeyMismatch, m["error"])
	w.assertPair(t, false)
	assert.Equal(t, 1, w.reloads, "the rollback reload")
}

// F-03 and F-04.
func TestDeployReloadFailures(t *testing.T) {
	w := newDeployWorld(t)
	w.reloadFail = 1
	_, m := w.deploy(opA, input(w.newLeaf.FullchainPEM, w.newLeaf.KeyPEM), w.oldSHA())
	assert.Equal(t, helperproto.PhaseRestored, m["phase"])
	assert.Equal(t, helperproto.StepReload, m["failed_step"])
	w.assertPair(t, false)

	w = newDeployWorld(t)
	w.reloadFail = 2
	_, m = w.deploy(opA, input(w.newLeaf.FullchainPEM, w.newLeaf.KeyPEM), w.oldSHA())
	assert.Equal(t, helperproto.PhaseRestoreFailed, m["phase"])
	assert.Equal(t, helperproto.StepRollbackReload, m["failed_step"])
	w.assertPair(t, false) // "Files are back in place but Nginx did not reload"
}

// Review Focus 3, F-66 on the server side: the helper dies after each step; status and restore
// always end with a consistent pair.
func TestDeployKilledAtEveryStepRecovers(t *testing.T) {
	for _, tc := range []struct {
		step      string
		phase     string // nginx-status after the kill
		newPair   bool   // the pair on disk before the restore
		restored  string // nginx-restore's phase
	}{
		{helperproto.StepBackup, helperproto.PhasePrepared, false, helperproto.PhasePrepared},
		{helperproto.StepWriteKey, helperproto.PhaseWriting, false, helperproto.PhaseRestored},
		{helperproto.StepWriteCert, helperproto.PhaseWriting, true, helperproto.PhaseRestored},
		{helperproto.StepConfigTest, helperproto.PhaseWriting, true, helperproto.PhaseRestored},
		{helperproto.StepReload, helperproto.PhaseWriting, true, helperproto.PhaseRestored},
	} {
		t.Run(tc.step, func(t *testing.T) {
			w := newDeployWorld(t)
			w.f.s.afterDeployStep = func(step string) error {
				if step == tc.step {
					return errKilled
				}
				return nil
			}
			code, _ := w.deploy(opA, input(w.newLeaf.FullchainPEM, w.newLeaf.KeyPEM), w.oldSHA())
			require.Equal(t, helperproto.ExitFailed, code)
			w.f.s.afterDeployStep = nil
			_, st := w.f.run("nginx-status", "--op", opA)
			assert.Equal(t, tc.phase, st["phase"])
			assert.Equal(t, false, st["active"])
			if tc.step == helperproto.StepWriteKey {
				// Killed after the key's rename: the key is new, the certificate old — the one moment a
				// mixed pair exists on disk, and exactly what nginx-restore repairs.
				assert.Equal(t, string(w.newLeaf.KeyPEM), w.f.read("/etc/nginx/ssl/www.key"))
			} else {
				w.assertPair(t, tc.newPair)
			}
			code, r := w.f.run("nginx-restore", "--op", opA)
			require.Equal(t, 0, code, "%v", r)
			assert.Equal(t, tc.restored, r["phase"])
			w.assertPair(t, false)
		})
	}
}

func TestRestoreAfterACommitAndItsRefusals(t *testing.T) {
	w := newDeployWorld(t)
	code, _ := w.deploy(opA, input(w.newLeaf.FullchainPEM, w.newLeaf.KeyPEM), w.oldSHA())
	require.Equal(t, 0, code)
	code, r := w.f.run("nginx-restore", "--op", opA)
	require.Equal(t, 0, code, "%v", r)
	assert.Equal(t, helperproto.PhaseRestored, r["phase"])
	w.assertPair(t, false)
	code, r = w.f.run("nginx-restore", "--op", opA)
	require.Equal(t, 0, code, "idempotent")
	assert.Equal(t, helperproto.PhaseRestored, r["phase"])

	w = newDeployWorld(t)
	code, _ = w.deploy(opA, input(w.newLeaf.FullchainPEM, w.newLeaf.KeyPEM), w.oldSHA())
	require.Equal(t, 0, code)
	w.f.write("/etc/nginx/ssl/www.crt", "someone else's certificate", 0o644)
	code, r = w.f.run("nginx-restore", "--op", opA)
	assert.Equal(t, helperproto.ExitPrecondition, code)
	assert.Equal(t, helperproto.CodeHashMismatch, r["code"])
	assert.Equal(t, "someone else's certificate", w.f.read("/etc/nginx/ssl/www.crt"), "never clobbered")

	code, r = w.f.run("nginx-restore", "--op", "0190f5a0-0000-7000-8000-0000000000ee")
	assert.Equal(t, helperproto.ExitPrecondition, code)
	assert.Equal(t, helperproto.CodeUnknownOp, r["code"])
	_, st := w.f.run("nginx-status", "--op", "0190f5a0-0000-7000-8000-0000000000ee")
	assert.Equal(t, helperproto.PhaseNone, st["phase"])
}

// Review Focus 2: a held lock answers BUSY within the budget; status reports it as active.
func TestDeployAnswersBusyWhenTheLockIsHeld(t *testing.T) {
	w := newDeployWorld(t)
	old := lockWait
	lockWait = 100 * time.Millisecond
	defer func() { lockWait = old }()
	lock, err := w.f.s.nginxLock(context.Background())
	require.NoError(t, err)
	code, m := w.deploy(opA, input(w.newLeaf.FullchainPEM, w.newLeaf.KeyPEM), w.oldSHA())
	assert.Equal(t, helperproto.ExitFailed, code)
	assert.Equal(t, helperproto.CodeBusy, m["code"])
	_, st := w.f.run("nginx-status", "--op", opA)
	assert.Equal(t, true, st["active"])
	require.NoError(t, lock.Close())
	w.assertPair(t, false)
}

// Review Focus 2: the directory is replaced by a link to a root-only directory right before the
// rename. The write still lands in the directory the helper opened, never in /root.
func TestAttackDirectorySwappedBeforeTheRename(t *testing.T) {
	w := newDeployWorld(t)
	w.f.mkdir("/root/.ssh", 0o700)
	w.f.write("/root/.ssh/www.crt", "root's file", 0o600)
	swapped := false
	w.f.s.beforeRename = func() error {
		if !swapped {
			swapped = true
			require.NoError(t, os.Rename(w.f.host("/etc/nginx/ssl"), w.f.host("/etc/nginx/ssl.old")))
			require.NoError(t, os.Symlink("/root/.ssh", w.f.host("/etc/nginx/ssl")))
		}
		return nil
	}
	_, _ = w.deploy(opA, input(w.newLeaf.FullchainPEM, w.newLeaf.KeyPEM), w.oldSHA())
	assert.Equal(t, "root's file", w.f.read("/root/.ssh/www.crt"))
	_, err := os.Stat(w.f.host("/root/.ssh/www.key"))
	assert.True(t, errors.Is(err, os.ErrNotExist), "nothing was written into /root")
}

func TestSweepKeepsNginxBackups(t *testing.T) {
	w := newDeployWorld(t)
	code, _ := w.deploy(opA, input(w.newLeaf.FullchainPEM, w.newLeaf.KeyPEM), w.oldSHA())
	require.Equal(t, 0, code)
	dir := w.f.host(helperproto.BackupRoot + "/" + opA)
	eightDays := testNow.Add(-8 * 24 * time.Hour)
	require.NoError(t, os.Chtimes(dir, eightDays, eightDays))
	w.f.s.sweepBackups()
	_, err := os.Stat(dir)
	assert.True(t, errors.Is(err, os.ErrNotExist), "a committed operation is kept 7 days")

	w = newDeployWorld(t)
	w.reloadFail = 2
	_, _ = w.deploy(opA, input(w.newLeaf.FullchainPEM, w.newLeaf.KeyPEM), w.oldSHA())
	dir = w.f.host(helperproto.BackupRoot + "/" + opA)
	require.NoError(t, os.Chtimes(dir, eightDays, eightDays))
	w.f.s.sweepBackups()
	_, err = os.Stat(dir)
	assert.NoError(t, err, "a failed restore keeps its backup for the 30-day cap")
}

func TestDeployArguments(t *testing.T) {
	w := newDeployWorld(t)
	for _, args := range [][]string{
		{"--cert", "/etc/nginx/ssl/www.crt", "--op", opA},
		{"--op", "../../etc", "--cert", "/a.crt", "--key", "/a.key", "--expect-cert-sha256", strings.Repeat("a", 64), "--content-sha256", strings.Repeat("b", 64)},
		{"--op", opA, "--cert", "rel.crt", "--key", "/a.key", "--expect-cert-sha256", strings.Repeat("a", 64), "--content-sha256", strings.Repeat("b", 64)},
		{"--op", opA, "--cert", "/a.crt", "--key", "/a.key", "--expect-cert-sha256", "absent", "--content-sha256", strings.Repeat("b", 64)},
	} {
		code, m := w.f.run(append([]string{"nginx-deploy"}, args...)...)
		assert.Equal(t, helperproto.ExitRefused, code, "%v", args)
		assert.Contains(t, []any{helperproto.CodeUsage, helperproto.CodeInvalidArgument}, m["code"])
	}
	for _, sub := range []string{"nginx-restore", "nginx-status"} {
		code, _ := w.f.run(sub, "--op", "x")
		assert.Equal(t, helperproto.ExitRefused, code, sub)
	}
}

// Root only: owners are really set, and a user-owned directory on the path is refused.
func TestDeployAsRootSetsOwnersAndRefusesUserDirectories(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root (chown)")
	}
	w := newDeployWorld(t)
	w.f.s.rootUID = 0
	w.f.s.chown = func(f *os.File, uid, gid int) error { return f.Chown(uid, gid) }
	require.NoError(t, os.Chown(w.f.host("/etc/nginx/ssl/www.key"), 0, 4321))
	require.NoError(t, os.Chmod(w.f.host("/etc/nginx/ssl/www.key"), 0o640))
	code, m := w.deploy(opA, input(w.newLeaf.FullchainPEM, w.newLeaf.KeyPEM), w.oldSHA())
	require.Equal(t, 0, code, "%v", m)
	st, err := os.Stat(w.f.host("/etc/nginx/ssl/www.key"))
	require.NoError(t, err)
	_, gid := owner(st)
	assert.Equal(t, 4321, gid)
	assert.Equal(t, os.FileMode(0o640), st.Mode().Perm())

	w = newDeployWorld(t)
	w.f.s.rootUID = 0
	require.NoError(t, os.Chown(w.f.host("/etc/nginx/ssl"), 1000, 1000))
	code, m = w.deploy(opA, input(w.newLeaf.FullchainPEM, w.newLeaf.KeyPEM), w.oldSHA())
	assert.Equal(t, helperproto.ExitRefused, code)
	assert.Equal(t, helperproto.CodePathNotAllowed, m["code"])
}
```

`chownCall` is the type Phase 3's `write_test.go` already declares; `runWith` too. Add `nginx-deploy`, `nginx-restore`, `nginx-status` to `TestPrivilegedSubcommandsNeedRoot`.

Run: `go test ./cmd/alice-helper -run 'Deploy|Restore|Sweep|AttackDirectorySwapped' -count=1`
Expected: FAIL (undefined: `errKilled`, `nginxLock`, …).

- [ ] **Step 2: Implement `journal.go`**

```go
//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"

	"alice/internal/providers/linuxssh/helperproto"
)

// errBusy: another nginx-deploy or nginx-restore holds the lock.
var errBusy = errors.New("another certificate change is running")

// errKilled is returned by tests' afterDeployStep to simulate the helper dying at that step.
var errKilled = errors.New("killed (test)")

const (
	journalName  = "journal.json"
	journalTmp   = "journal.tmp"
	journalLimit = 64 << 10
	certBackup   = "cert.bak"
	keyBackup    = "key.bak"
	nginxLockName = "nginx.lock"
)

type fileMeta struct {
	Mode uint32 `json:"mode"`
	UID  int    `json:"uid"`
	GID  int    `json:"gid"`
}

// journal is the on-disk record of one nginx-deploy operation; nginx-status and nginx-restore
// read it after any interruption.
type journal struct {
	Op           string                  `json:"op"`
	Phase        string                  `json:"phase"`
	CertPath     string                  `json:"cert_path"`
	KeyPath      string                  `json:"key_path"`
	CertResolved string                  `json:"cert_resolved"`
	KeyResolved  string                  `json:"key_resolved"`
	OldCertSHA   string                  `json:"old_cert_sha256"`
	OldKeySHA    string                  `json:"old_key_sha256"`
	NewCertSHA   string                  `json:"new_cert_sha256"`
	NewKeySHA    string                  `json:"new_key_sha256"`
	CertMeta     fileMeta                `json:"cert_meta"`
	KeyMeta      fileMeta                `json:"key_meta"`
	FailedStep   string                  `json:"failed_step"`
	Error        string                  `json:"error"`
	Steps        []helperproto.NginxStep `json:"steps"`
}

// opDir opens (with create: makes) <BackupRoot>/<op>, root-only (0700), never through a link.
func (s *sys) opDir(op string, create bool) (*os.File, error) {
	root, err := s.openBackupRoot(create)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	return subdir(root, op, create)
}

// readJournal reads the journal of an operation directory; ok is false when there is none.
func readJournal(dir *os.File) (journal, bool, error) {
	var j journal
	fd, err := unix.Openat(int(dir.Fd()), journalName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0) //nolint:gosec // G115: a descriptor fits an int
	if errors.Is(err, unix.ENOENT) {
		return j, false, nil
	}
	if err != nil {
		return j, false, err
	}
	f := os.NewFile(uintptr(fd), journalName)
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, journalLimit+1))
	if err != nil || len(data) > journalLimit {
		return j, false, errTooLarge
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&j); err != nil {
		return j, false, err
	}
	return j, true, nil
}

// writeJournal replaces the journal atomically: journal.tmp (O_EXCL), fsync, renameat, directory fsync.
func writeJournal(dir *os.File, j journal) error {
	raw, err := json.Marshal(j)
	if err != nil {
		return err
	}
	dfd := int(dir.Fd()) //nolint:gosec // G115: a descriptor fits an int
	_ = unix.Unlinkat(dfd, journalTmp, 0)
	if err := writeNewAt(dir, journalTmp, raw); err != nil {
		return err
	}
	if err := unix.Renameat(dfd, journalTmp, dfd, journalName); err != nil {
		return err
	}
	return dir.Sync()
}

// nginxLock serializes nginx-deploy and nginx-restore on a server (a root-private lock file).
func (s *sys) nginxLock(ctx context.Context) (*os.File, error) {
	locks, err := s.openStateDir(lockDirName, true)
	if err != nil {
		return nil, err
	}
	defer func() { _ = locks.Close() }()
	f, err := openLockFile(int(locks.Fd()), nginxLockName, true) //nolint:gosec // G115: a descriptor fits an int
	if err != nil {
		return nil, err
	}
	wctx, cancel := context.WithTimeout(ctx, lockWait)
	defer cancel()
	if err := flockWait(wctx, int(f.Fd())); err != nil { //nolint:gosec // G115: a descriptor fits an int
		_ = f.Close()
		return nil, errBusy
	}
	return f, nil
}

// nginxLockHeld reports whether a helper process holds the Nginx lock now (nginx-status).
func (s *sys) nginxLockHeld() bool {
	locks, err := s.openStateDir(lockDirName, false)
	if err != nil {
		return false
	}
	defer func() { _ = locks.Close() }()
	f, err := openLockFile(int(locks.Fd()), nginxLockName, false) //nolint:gosec // G115: a descriptor fits an int
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil { //nolint:gosec // G115: a descriptor fits an int
		return true
	}
	_ = unix.Flock(int(f.Fd()), unix.LOCK_UN) //nolint:gosec // G115: a descriptor fits an int
	return false
}
```

`sys.go` gains:

```go
	// afterDeployStep runs after each step of nginx-deploy (nil in production); a test returns
	// errKilled to simulate the helper dying right there (no rollback, the journal stays).
	afterDeployStep func(step string) error
```

- [ ] **Step 3: Implement `deploy.go`**

```go
//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"time"

	"golang.org/x/sys/unix"

	"alice/internal/providers/linuxssh/helperproto"
)

// stepTimeout bounds nginx -t, the reload and is-active once the transaction can no longer stop.
const stepTimeout = 30 * time.Second

// target is a certificate or key file found under the lock, with the descriptor it was read from.
type target struct {
	rf   rootFile
	f    *os.File
	st   unix.Stat_t
	data []byte
}

func (t *target) close() {
	clear(t.data)
	if t.f != nil {
		_ = t.f.Close()
	}
	t.rf.close()
}

// readTarget resolves and reads one existing file of the pair (regular, one link, at most
// MaxCertFileSize, a certificate or key file name).
func (s *sys) readTarget(p string) (*target, error) {
	rf, err := s.resolveRoot(p)
	if err != nil {
		return nil, err
	}
	if !certName(rf.name) {
		rf.close()
		return nil, errBadName
	}
	f, st, err := rf.open()
	if err != nil {
		rf.close()
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, helperproto.MaxCertFileSize+1))
	if err != nil || len(data) > helperproto.MaxCertFileSize {
		clear(data)
		_ = f.Close()
		rf.close()
		return nil, errTooLarge
	}
	return &target{rf: rf, f: f, st: st, data: data}, nil
}

var errBadName = errors.New("the file name has no certificate or key extension")

// targetError maps a readTarget error to the answer (nothing has changed yet).
func targetError(err error) error {
	switch {
	case errors.Is(err, unix.ENOENT):
		return precondition(helperproto.CodeNotFound, "the certificate or key file does not exist")
	case errors.Is(err, errUnsafe):
		return refused(helperproto.CodeUnsafeFile, "the file is hard-linked")
	case errors.Is(err, errNotRegular), errors.Is(err, unix.ENOTDIR), errors.Is(err, unix.ELOOP):
		return refused(helperproto.CodeNotRegularFile, "the path is not a regular file")
	case errors.Is(err, errTooLarge):
		return refused(helperproto.CodeTooLarge, "the file is too large")
	default:
		return refused(helperproto.CodePathNotAllowed, "the path leaves the directories root controls or has no certificate name")
	}
}

// Modes of the replacement (R38 item 3, F-13): a key 0640 (ssl-cert group) stays 0640, every
// other key becomes 0600; a certificate keeps its mode without write or execute bits for others.
func keyMode(old uint32) uint32 {
	if old&0o777 == 0o640 {
		return 0o640
	}
	return 0o600
}

func certMode(old uint32) uint32 { return old & 0o644 }

// checkDeployContent: the certificate input holds only CERTIFICATE blocks (at least one); the
// key input holds exactly one unencrypted private key block and nothing else.
func checkDeployContent(certPEM, keyPEM []byte) error {
	n := 0
	for rest := certPEM; ; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			if len(bytes.TrimSpace(rest)) != 0 {
				return errBadContent
			}
			break
		}
		if b.Type != "CERTIFICATE" || len(b.Headers) != 0 {
			return errBadContent
		}
		n++
	}
	if n == 0 {
		return errBadContent
	}
	b, rest := pem.Decode(keyPEM)
	if b == nil || len(bytes.TrimSpace(rest)) != 0 || len(b.Headers) != 0 {
		return errBadContent
	}
	switch b.Type {
	case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
		return nil
	}
	return errBadContent
}

var errBadContent = errors.New("bad content")

func stepOK(name string) helperproto.NginxStep { return helperproto.NginxStep{Name: name, Status: "ok"} }

func stepFailed(name, class string) helperproto.NginxStep {
	return helperproto.NginxStep{Name: name, Status: "failed", Error: class}
}

func (s *sys) hook(step string) error {
	if s.afterDeployStep != nil {
		return s.afterDeployStep(step)
	}
	return nil
}

func cmdNginxDeploy(ctx context.Context, s *sys, args []string) (any, error) {
	if len(args) != 10 || args[0] != "--op" || args[2] != "--cert" || args[4] != "--key" ||
		args[6] != "--expect-cert-sha256" || args[8] != "--content-sha256" {
		return nil, refused(helperproto.CodeUsage, "usage: nginx-deploy --op <id> --cert <path> --key <path> --expect-cert-sha256 <sha256> --content-sha256 <sha256>")
	}
	op, certPath, keyPath, expect, want := args[1], args[3], args[5], args[7], args[9]
	if !helperproto.ValidOpID(op) || !helperproto.ValidPath(certPath) || !helperproto.ValidPath(keyPath) || certPath == keyPath ||
		!helperproto.ValidSHA256(expect) || expect == helperproto.AbsentSHA256 ||
		!helperproto.ValidSHA256(want) || want == helperproto.AbsentSHA256 {
		return nil, refused(helperproto.CodeInvalidArgument, "an argument is not allowed")
	}
	raw, err := io.ReadAll(io.LimitReader(s.stdin, helperproto.MaxDeployInput+1))
	defer clear(raw)
	switch {
	case err != nil:
		return nil, failed(helperproto.CodeIOError, "the new content cannot be read")
	case len(raw) > helperproto.MaxDeployInput:
		return nil, refused(helperproto.CodeTooLarge, "the new content is too large")
	case hexSHA(raw) != want:
		return nil, precondition(helperproto.CodeContentMismatch, "the new content arrived incomplete")
	}
	var in helperproto.NginxDeployInput
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		return nil, refused(helperproto.CodeBadContent, "the new content is not a certificate and a key")
	}
	certPEM, keyPEM := []byte(in.CertPEM), []byte(in.KeyPEM)
	defer clear(keyPEM)
	if err := checkDeployContent(certPEM, keyPEM); err != nil {
		return nil, refused(helperproto.CodeBadContent, "the new content is not a certificate and a key")
	}
	s.syslog(helperproto.SubNginxDeploy, certPath)
	lock, err := s.nginxLock(ctx)
	if err != nil {
		return nil, failed(helperproto.CodeBusy, "another certificate change is running on this server")
	}
	defer func() { _ = lock.Close() }()
	dir, err := s.opDir(op, true)
	if err != nil {
		return nil, failed(helperproto.CodeIOError, "the backup directory cannot be opened")
	}
	defer func() { _ = dir.Close() }()

	// One operation, one outcome: a journal from an earlier run of this operation answers it; an
	// interrupted one is rolled back first (the helper that wrote it died). A prepared one wrote
	// nothing and starts again.
	j, found, err := readJournal(dir)
	if err != nil {
		return nil, failed(helperproto.CodeIOError, "the journal cannot be read")
	}
	if found && j.Phase != helperproto.PhasePrepared {
		if j.Phase == helperproto.PhaseWriting || j.Phase == helperproto.PhaseRestoring {
			j = s.restoreOp(context.WithoutCancel(ctx), dir, j)
		}
		return deployAnswer(j), nil
	}
	cfg, meta, err := s.nginxConfig(ctx)
	switch {
	case errors.Is(err, errNginxMissing):
		return nil, precondition(helperproto.CodeNginxNotFound, "nginx is not installed at /usr/sbin/nginx")
	case err != nil:
		return nil, failed(helperproto.CodeIOError, "nginx could not be run")
	case !meta.valid:
		return nil, precondition(helperproto.CodeConfigInvalid, "the nginx configuration already has an error")
	case !cfg.HasPair(certPath, keyPath):
		return nil, precondition(helperproto.CodeConfigChanged, "the files are not a certificate and key pair of the current configuration")
	}
	cert, err := s.readTarget(certPath)
	if err != nil {
		return nil, targetError(err)
	}
	defer cert.close()
	key, err := s.readTarget(keyPath)
	if err != nil {
		return nil, targetError(err)
	}
	defer key.close()
	if cert.rf.resolved == key.rf.resolved {
		return nil, refused(helperproto.CodePathNotAllowed, "the certificate and the key are one file")
	}
	if hexSHA(cert.data) != expect {
		return nil, precondition(helperproto.CodeHashMismatch, "the certificate file changed since it was read")
	}
	j = journal{Op: op, Phase: helperproto.PhasePrepared, CertPath: certPath, KeyPath: keyPath,
		CertResolved: cert.rf.resolved, KeyResolved: key.rf.resolved, OldCertSHA: hexSHA(cert.data), OldKeySHA: hexSHA(key.data),
		NewCertSHA: hexSHA(certPEM), NewKeySHA: hexSHA(keyPEM),
		CertMeta: fileMeta{Mode: uint32(cert.st.Mode & 0o777), UID: int(cert.st.Uid), GID: int(cert.st.Gid)},
		KeyMeta:  fileMeta{Mode: uint32(key.st.Mode & 0o777), UID: int(key.st.Uid), GID: int(key.st.Gid)},
		Steps:    []helperproto.NginxStep{}}
	if bytes.Equal(cert.data, certPEM) && bytes.Equal(key.data, keyPEM) {
		j.Phase = helperproto.PhaseUnchanged
		if err := writeJournal(dir, j); err != nil {
			return nil, failed(helperproto.CodeIOError, "the journal cannot be written")
		}
		return deployAnswer(j), nil
	}
	need := int64(len(certPEM)+len(keyPEM)) + helperproto.MinFreeBytes
	if !s.spaceFor(cert.rf.dirfd, need) || !s.spaceFor(key.rf.dirfd, need) ||
		!s.spaceFor(int(dir.Fd()), int64(len(cert.data)+len(key.data))+helperproto.MinFreeBytes) { //nolint:gosec // G115: a descriptor fits an int
		return nil, precondition(helperproto.CodeNoSpace, "the server has not enough free disk space")
	}
	if ctx.Err() != nil {
		return nil, failed(helperproto.CodeIOError, "the time budget ended before anything was changed")
	}

	// 1. Backup (nothing changed if it fails).
	if err := writeBackups(dir, cert.data, key.data); err != nil {
		if errors.Is(err, unix.ENOSPC) {
			return nil, precondition(helperproto.CodeNoSpace, "the server has no free disk space for the backup")
		}
		return nil, failed(helperproto.CodeIOError, "the backup cannot be written")
	}
	j.Steps = append(j.Steps, stepOK(helperproto.StepBackup))
	if err := writeJournal(dir, j); err != nil {
		return nil, failed(helperproto.CodeIOError, "the journal cannot be written")
	}
	if err := s.hook(helperproto.StepBackup); err != nil {
		return nil, failed(helperproto.CodeIOError, "stopped")
	}

	// From the first rename on, the transaction runs to its end whatever happens to the caller.
	tctx := context.WithoutCancel(ctx)
	j.Phase = helperproto.PhaseWriting
	if err := writeJournal(dir, j); err != nil {
		return nil, failed(helperproto.CodeIOError, "the journal cannot be written")
	}

	// 2. Key, then certificate (spec §12.6 steps 3–4).
	renamed, err := s.replaceFile(key, keyPEM, keyMode(j.KeyMeta.Mode), j.KeyMeta)
	if err != nil {
		if !renamed {
			j.Phase = helperproto.PhasePrepared
			j.Steps = append(j.Steps, stepFailed(helperproto.StepWriteKey, ""))
			_ = writeJournal(dir, j)
			if errors.Is(err, unix.ENOSPC) {
				return nil, precondition(helperproto.CodeNoSpace, "the server has no free disk space")
			}
			return nil, failed(helperproto.CodeIOError, "the key file cannot be written")
		}
		return deployAnswer(s.fail(tctx, dir, j, helperproto.StepWriteKey, "")), nil
	}
	j.Steps = append(j.Steps, stepOK(helperproto.StepWriteKey))
	if err := s.hook(helperproto.StepWriteKey); err != nil {
		return nil, failed(helperproto.CodeIOError, "stopped")
	}
	if _, err := s.replaceFile(cert, certPEM, certMode(j.CertMeta.Mode), j.CertMeta); err != nil {
		return deployAnswer(s.fail(tctx, dir, j, helperproto.StepWriteCert, "")), nil
	}
	j.Steps = append(j.Steps, stepOK(helperproto.StepWriteCert))
	if err := s.hook(helperproto.StepWriteCert); err != nil {
		return nil, failed(helperproto.CodeIOError, "stopped")
	}

	// 3. nginx -t (F-01).
	if class, err := s.configTest(tctx); err != nil {
		return deployAnswer(s.fail(tctx, dir, j, helperproto.StepConfigTest, class)), nil
	}
	j.Steps = append(j.Steps, stepOK(helperproto.StepConfigTest))
	if err := s.hook(helperproto.StepConfigTest); err != nil {
		return nil, failed(helperproto.CodeIOError, "stopped")
	}

	// 4. Reload and is-active (F-03).
	if err := s.reload(tctx); err != nil {
		return deployAnswer(s.fail(tctx, dir, j, helperproto.StepReload, "")), nil
	}
	j.Steps = append(j.Steps, stepOK(helperproto.StepReload))
	if err := s.hook(helperproto.StepReload); err != nil {
		return nil, failed(helperproto.CodeIOError, "stopped")
	}
	j.Phase = helperproto.PhaseCommitted
	_ = writeJournal(dir, j)
	return deployAnswer(j), nil
}

// fail records the failed step and rolls back.
func (s *sys) fail(ctx context.Context, dir *os.File, j journal, step, class string) journal {
	j.Steps = append(j.Steps, stepFailed(step, class))
	j.FailedStep, j.Error = step, class
	return s.restoreOp(ctx, dir, j)
}

func (s *sys) spaceFor(fd int, need int64) bool {
	free, err := s.statfs(fd)
	return err == nil && free >= need
}

func writeBackups(dir *os.File, cert, key []byte) error {
	dfd := int(dir.Fd()) //nolint:gosec // G115: a descriptor fits an int
	for _, name := range []string{certBackup, keyBackup, journalTmp} {
		_ = unix.Unlinkat(dfd, name, 0) // a prepared run that is started again
	}
	if err := writeNewAt(dir, certBackup, cert); err != nil {
		return err
	}
	if err := writeNewAt(dir, keyBackup, key); err != nil {
		return err
	}
	return dir.Sync()
}

func (s *sys) configTest(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, stepTimeout)
	defer cancel()
	_, stderr, err := s.runNginx(ctx, "-t")
	if err != nil {
		return classifyNginxError(stderr), err
	}
	return "", nil
}

func (s *sys) reload(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, stepTimeout)
	defer cancel()
	if err := s.runSystemctl(ctx, "reload", "nginx"); err != nil {
		return err
	}
	return s.runSystemctl(ctx, "is-active", "--quiet", "nginx")
}

// replaceFile stages content next to t's file (O_EXCL, 0600), sets owner, group, mode and the
// SELinux label of the replaced file, syncs, and renames it over the file in the directory the
// walk opened; then it syncs the directory. renamed reports whether the rename happened.
func (s *sys) replaceFile(t *target, content []byte, mode uint32, meta fileMeta) (renamed bool, err error) {
	var rnd [8]byte
	_, _ = rand.Read(rnd[:])
	tmp := ".alice-" + hex.EncodeToString(rnd[:])
	fd, err := unix.Openat(t.rf.dirfd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return false, err
	}
	f := os.NewFile(uintptr(fd), tmp)
	defer func() {
		_ = f.Close()
		if !renamed {
			_ = unix.Unlinkat(t.rf.dirfd, tmp, 0)
		}
	}()
	if _, err := f.Write(content); err != nil {
		return false, err
	}
	if err := s.chown(f, meta.UID, meta.GID); err != nil {
		return false, err
	}
	if err := unix.Fchmod(fd, mode); err != nil {
		return false, err
	}
	copySELinux(int(t.f.Fd()), fd) //nolint:gosec // G115: a descriptor fits an int
	if err := f.Sync(); err != nil {
		return false, err
	}
	if s.beforeRename != nil {
		if err := s.beforeRename(); err != nil {
			return false, err
		}
	}
	var now unix.Stat_t
	if err := unix.Fstatat(t.rf.dirfd, t.rf.name, &now, unix.AT_SYMLINK_NOFOLLOW); err != nil || !sameFile(now, t.st) {
		return false, errUnsafe // the name no longer refers to the file that was read and backed up
	}
	if err := unix.Renameat(t.rf.dirfd, tmp, t.rf.dirfd, t.rf.name); err != nil {
		return false, err
	}
	renamed = true
	if err := unix.Fsync(t.rf.dirfd); err != nil {
		return true, err
	}
	return true, nil
}

// restoreOp puts the backups back for both files (certificate first, then key: the reverse of
// the writes), tests and reloads. A file holding the deployed content is restored; one holding
// the backed-up content is left; anything else was changed by someone else and is never
// clobbered (the operation then stays as it was, answered with HASH_MISMATCH by nginx-restore).
func (s *sys) restoreOp(ctx context.Context, dir *os.File, j journal) journal {
	j.Phase = helperproto.PhaseRestoring
	_ = writeJournal(dir, j)
	for _, f := range []struct {
		path, resolved, oldSHA, newSHA, backup string
		meta                                 fileMeta
	}{
		{j.CertPath, j.CertResolved, j.OldCertSHA, j.NewCertSHA, certBackup, j.CertMeta},
		{j.KeyPath, j.KeyResolved, j.OldKeySHA, j.NewKeySHA, keyBackup, j.KeyMeta},
	} {
		if err := s.restoreFile(dir, f.path, f.resolved, f.oldSHA, f.newSHA, f.backup, f.meta); err != nil {
			j.Steps = append(j.Steps, stepFailed(helperproto.StepRestore, ""))
			j.Phase, j.Error = helperproto.PhaseRestoreFailed, restoreClass(err)
			if j.FailedStep == "" {
				j.FailedStep = helperproto.StepRestore
			}
			_ = writeJournal(dir, j)
			return j
		}
	}
	j.Steps = append(j.Steps, stepOK(helperproto.StepRestore))
	if class, err := s.configTest(ctx); err != nil {
		j.Steps = append(j.Steps, stepFailed(helperproto.StepRollbackConfigTest, class))
		j.Phase, j.FailedStep, j.Error = helperproto.PhaseRestoreFailed, helperproto.StepRollbackConfigTest, class
		_ = writeJournal(dir, j)
		return j
	}
	j.Steps = append(j.Steps, stepOK(helperproto.StepRollbackConfigTest))
	if err := s.reload(ctx); err != nil {
		j.Steps = append(j.Steps, stepFailed(helperproto.StepRollbackReload, ""))
		j.Phase, j.FailedStep = helperproto.PhaseRestoreFailed, helperproto.StepRollbackReload
		_ = writeJournal(dir, j)
		return j
	}
	j.Steps = append(j.Steps, stepOK(helperproto.StepRollbackReload))
	j.Phase = helperproto.PhaseRestored
	_ = writeJournal(dir, j)
	return j
}

var errChangedByOthers = errors.New("the file was changed by someone else")

func restoreClass(err error) string {
	if errors.Is(err, errChangedByOthers) {
		return "file_changed"
	}
	return ""
}

// restoreFile puts one backup back with the file's original owner, group and mode.
func (s *sys) restoreFile(dir *os.File, path, resolved, oldSHA, newSHA, backup string, meta fileMeta) error {
	t, err := s.readTarget(path)
	if err != nil {
		return err
	}
	defer t.close()
	if t.rf.resolved != resolved {
		return errChangedByOthers // the link now leads elsewhere
	}
	switch hexSHA(t.data) {
	case oldSHA:
		return nil
	case newSHA:
	default:
		return errChangedByOthers
	}
	data, err := readBackup(dir, backup)
	if err != nil {
		return err
	}
	defer clear(data)
	if hexSHA(data) != oldSHA {
		return errors.New("the backup does not match its journal")
	}
	_, err = s.replaceFile(t, data, meta.Mode, meta)
	return err
}

func readBackup(dir *os.File, name string) ([]byte, error) {
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0) //nolint:gosec // G115: a descriptor fits an int
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, helperproto.MaxCertFileSize+1))
	if err != nil || len(data) > helperproto.MaxCertFileSize {
		clear(data)
		return nil, errTooLarge
	}
	return data, nil
}

func deployAnswer(j journal) helperproto.NginxDeployResponse {
	return helperproto.NginxDeployResponse{OK: true, Phase: j.Phase, FailedStep: j.FailedStep, Error: j.Error,
		Steps: append([]helperproto.NginxStep{}, j.Steps...), BackupDir: helperproto.BackupRoot + "/" + j.Op}
}

func cmdNginxRestore(ctx context.Context, s *sys, args []string) (any, error) {
	if len(args) != 2 || args[0] != "--op" {
		return nil, refused(helperproto.CodeUsage, "usage: nginx-restore --op <operation id>")
	}
	if !helperproto.ValidOpID(args[1]) {
		return nil, refused(helperproto.CodeInvalidArgument, "the operation id is not allowed")
	}
	s.syslog(helperproto.SubNginxRestore, helperproto.BackupRoot+"/"+args[1])
	lock, err := s.nginxLock(ctx)
	if err != nil {
		return nil, failed(helperproto.CodeBusy, "another certificate change is running on this server")
	}
	defer func() { _ = lock.Close() }()
	dir, err := s.opDir(args[1], false)
	if errors.Is(err, unix.ENOENT) {
		return nil, precondition(helperproto.CodeUnknownOp, "there is no deployment with this operation id")
	}
	if err != nil {
		return nil, failed(helperproto.CodeIOError, "the backup directory cannot be opened")
	}
	defer func() { _ = dir.Close() }()
	j, found, err := readJournal(dir)
	switch {
	case err != nil:
		return nil, failed(helperproto.CodeIOError, "the journal cannot be read")
	case !found:
		return nil, precondition(helperproto.CodeUnknownOp, "there is no deployment with this operation id")
	}
	switch j.Phase {
	case helperproto.PhasePrepared, helperproto.PhaseUnchanged, helperproto.PhaseRestored:
		return helperproto.NginxRestoreResponse{OK: true, Phase: j.Phase, Steps: []helperproto.NginxStep{}}, nil
	}
	before := len(j.Steps)
	j = s.restoreOp(context.WithoutCancel(ctx), dir, j)
	if j.Phase == helperproto.PhaseRestoreFailed && j.Error == "file_changed" {
		return nil, precondition(helperproto.CodeHashMismatch, "a file was changed after the deployment; it is left as it is")
	}
	return helperproto.NginxRestoreResponse{OK: true, Phase: j.Phase, Error: j.Error, Steps: append([]helperproto.NginxStep{}, j.Steps[before:]...)}, nil
}

func cmdNginxStatus(_ context.Context, s *sys, args []string) (any, error) {
	if len(args) != 2 || args[0] != "--op" {
		return nil, refused(helperproto.CodeUsage, "usage: nginx-status --op <operation id>")
	}
	if !helperproto.ValidOpID(args[1]) {
		return nil, refused(helperproto.CodeInvalidArgument, "the operation id is not allowed")
	}
	resp := helperproto.NginxStatusResponse{OK: true, Phase: helperproto.PhaseNone, Active: s.nginxLockHeld(),
		BackupDir: helperproto.BackupRoot + "/" + args[1]}
	dir, err := s.opDir(args[1], false)
	if errors.Is(err, unix.ENOENT) {
		return resp, nil
	}
	if err != nil {
		return nil, failed(helperproto.CodeIOError, "the backup directory cannot be opened")
	}
	defer func() { _ = dir.Close() }()
	j, found, err := readJournal(dir)
	if err != nil {
		return nil, failed(helperproto.CodeIOError, "the journal cannot be read")
	}
	if !found {
		return resp, nil
	}
	resp.Phase, resp.NewCertSHA256 = j.Phase, j.NewCertSHA
	if t, err := s.readTarget(j.CertPath); err == nil {
		resp.CurrentCertSHA256 = hexSHA(t.data)
		t.close()
	}
	return resp, nil
}
```

Notes the implementer must keep:
- `nginx-restore` writes `restore_failed` with `error: "file_changed"` into the journal when it refuses to clobber; `TestRestoreAfterACommitAndItsRefusals` expects the files untouched and `HASH_MISMATCH`.
- After a kill at `write_key` the journal phase is `writing` with the key new and the certificate old; `restoreOp` restores the key (new hash) and leaves the certificate (old hash): `TestDeployKilledAtEveryStepRecovers` pins it.

`run.go` `commands` gains `nginx-deploy`, `nginx-restore`, `nginx-status` (privileged). `main.go`: at the start of `main`, `signal.Ignore(syscall.SIGHUP, syscall.SIGPIPE)` (imports `os/signal`), with the comment "a dropped SSH connection must never stop a transaction half-way (R38 item 1)".

`cleanup.go`, `sweepBackups`: before removing an operation directory older than `backupRetention`, nothing changes; additionally, an operation directory older than `helperproto.NginxBackupKeep` whose journal phase is `committed`, `unchanged`, `restored` or `prepared` is removed (open it with `subdir(root, name, false)` and `readJournal`; a directory without a journal is an `authorized_keys` operation and keeps the 30-day rule).

Run: `go test ./cmd/alice-helper -count=1`
Expected: PASS.

- [ ] **Step 4: Helper change procedure**

1. `go test ./cmd/alice-helper -count=1` → PASS.
2. `CGO_ENABLED=0 go test -c -o /tmp/alice-helper.test ./cmd/alice-helper && docker run --rm --network none -v /tmp/alice-helper.test:/alice-helper.test:ro debian:12 /alice-helper.test -test.count=1 -test.run 'AsRoot|Attack|Root|Deploy'` (Docker: throwaway container) → PASS, including `TestDeployAsRootSetsOwnersAndRefusesUserDirectories`.
3. `go test ./cmd/alice-helper -run TestHelperIsStatic -count=1` → PASS.
4. `make helper` → new checksums.
5. `ALICE_SSH_IMAGES=ubuntu22 make test-ssh` (Docker) → PASS (no SSH-key behaviour changed).

- [ ] **Step 5: Commit**

```bash
git add cmd/alice-helper
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "feat(helper): nginx-deploy as one journaled root transaction with automatic rollback; nginx-restore and nginx-status

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 7: `linuxssh` — protocol 4 constructors, narrowed `nginx` sudoers, accounts in discovery, `ConnOf`

Alice's side of protocol 4 in the connector: the command constructors and exact command lines (A-12), the `nginx` sudoers profile narrowed to exactly the five commands (P3-06 closed), the setup script unchanged otherwise, `Discover` reporting the accounts list (carry 1), a way for the `nginx` provider to run helper commands on a `linuxssh` session's connection (`ConnOf`), and `WipeInput` for the key that travels in `nginx-deploy`'s stdin. (`Open` refuses Phase 3 helpers since Task 4 raised `helperproto.Protocol` to 4.)

**Files:**
- Modify: `internal/providers/linuxssh/command.go` (constructors, `WipeInput`), `internal/providers/linuxssh/setup.go` (`sudoersNginxOnly`), `internal/providers/linuxssh/discover.go` (accounts), `internal/providers/linuxssh/provider.go` (`ConnOf`)
- Modify: `internal/providers/types.go` (`DiscoveryResult.Accounts`, `AccountsComplete`)
- Modify: `internal/providers/linuxssh/linuxsshtest/emulator.go` (accounts in `authkeys-list`; `SetAccounts`; the flag names of protocol 4 in `parseLine`; `tls-probe` without sudo)
- Test: `internal/providers/linuxssh/command_test.go`, `internal/providers/linuxssh/setup_test.go`, `internal/providers/linuxssh/provider_test.go`

**Interfaces:**
- Consumes: Task 4 `helperproto` protocol 4 names; Phase 3 `privileged`, `quoteArg`, `HelperCommand`, `smallOutput`, `session`, `Conn`.
- Produces: the constructors and `ConnOf` of the contract; `providers.DiscoveryResult.Accounts []string`, `AccountsComplete bool`; `linuxsshtest.(*Emulator).SetAccounts(names []string, complete bool)`.

- [ ] **Step 1: Write the failing command tests**

Add to `command_test.go`:

```go
func TestNginxCommandLinesAreExact(t *testing.T) {
	sha := strings.Repeat("ab", 32)
	input := []byte(`{"cert_pem":"c","key_pem":"k"}`)
	h := sha256.Sum256(input)
	deploy, err := CmdNginxDeploy(testOp, "/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key", sha, input)
	require.NoError(t, err)
	restore, err := CmdNginxRestore(testOp)
	require.NoError(t, err)
	status, err := CmdNginxStatus(testOp)
	require.NoError(t, err)
	probe, err := CmdTLSProbe("127.0.0.1", 443, "www.example.test", helperproto.ProbeRSA)
	require.NoError(t, err)
	probeNoSNI, err := CmdTLSProbe("::1", 8443, "", helperproto.ProbeAny)
	require.NoError(t, err)
	op := "'0190f5a0-0000-7000-8000-0000000000aa'"
	for _, tc := range []struct {
		cmd  HelperCommand
		line string
		sub  string
		sudo bool
	}{
		{CmdNginxDump(), "sudo -n /usr/local/libexec/alice-helper nginx-dump", "nginx-dump", true},
		{CmdNginxTest(), "sudo -n /usr/local/libexec/alice-helper nginx-test", "nginx-test", true},
		{deploy, "sudo -n /usr/local/libexec/alice-helper nginx-deploy --op " + op + " --cert '/etc/nginx/ssl/www.crt' --key '/etc/nginx/ssl/www.key' --expect-cert-sha256 '" + sha + "' --content-sha256 '" + hex.EncodeToString(h[:]) + "'", "nginx-deploy", true},
		{restore, "sudo -n /usr/local/libexec/alice-helper nginx-restore --op " + op, "nginx-restore", true},
		{status, "sudo -n /usr/local/libexec/alice-helper nginx-status --op " + op, "nginx-status", true},
		{probe, "/usr/local/libexec/alice-helper tls-probe --addr '127.0.0.1' --port '443' --sni 'www.example.test' --key-type 'rsa'", "tls-probe", false},
		{probeNoSNI, "/usr/local/libexec/alice-helper tls-probe --addr '::1' --port '8443' --sni '_' --key-type 'any'", "tls-probe", false},
	} {
		assert.Equal(t, tc.line, tc.cmd.Line())
		assert.Equal(t, tc.sub, tc.cmd.Subcommand())
		assert.Equal(t, tc.sudo, tc.cmd.sudo)
	}
	assert.Equal(t, input, deploy.stdin)
	assert.Equal(t, int64(helperproto.NginxDumpOutput), CmdNginxDump().maxOutput)
	assert.Equal(t, LongCommandTimeout, deploy.timeout)
	assert.Equal(t, LongCommandTimeout, restore.timeout)
	assert.Equal(t, DefaultCommandTimeout, status.timeout)
	assert.Equal(t, DefaultCommandTimeout, probe.timeout)
}

func TestNginxCommandsRefuseHostileValues(t *testing.T) {
	sha := strings.Repeat("ab", 32)
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"deploy relative cert", func() error { _, e := CmdNginxDeploy(testOp, "etc/x.crt", "/k.key", sha, nil); return e }()},
		{"deploy dotdot", func() error { _, e := CmdNginxDeploy(testOp, "/etc/../shadow", "/k.key", sha, nil); return e }()},
		{"deploy same path", func() error { _, e := CmdNginxDeploy(testOp, "/a.pem", "/a.pem", sha, nil); return e }()},
		{"deploy absent hash", func() error { _, e := CmdNginxDeploy(testOp, "/a.crt", "/a.key", helperproto.AbsentSHA256, nil); return e }()},
		{"deploy shell", func() error { _, e := CmdNginxDeploy(testOp, "/a.crt;rm -rf /", "/a.key", sha, nil); return e }()},
		{"deploy nil op", func() error { _, e := CmdNginxDeploy(uuid.Nil, "/a.crt", "/a.key", sha, nil); return e }()},
		{"deploy too large", func() error {
			_, e := CmdNginxDeploy(testOp, "/a.crt", "/a.key", sha, make([]byte, helperproto.MaxDeployInput+1))
			return e
		}()},
		{"probe hostname", func() error { _, e := CmdTLSProbe("localhost", 443, "a.b", "any"); return e }()},
		{"probe zone", func() error { _, e := CmdTLSProbe("fe80::1%eth0", 443, "a.b", "any"); return e }()},
		{"probe port", func() error { _, e := CmdTLSProbe("127.0.0.1", 0, "a.b", "any"); return e }()},
		{"probe sni", func() error { _, e := CmdTLSProbe("127.0.0.1", 443, "a b", "any"); return e }()},
		{"probe sni injection", func() error { _, e := CmdTLSProbe("127.0.0.1", 443, "$(id)", "any"); return e }()},
		{"probe key type", func() error { _, e := CmdTLSProbe("127.0.0.1", 443, "a.b", "dsa"); return e }()},
		{"restore op", func() error { _, e := CmdNginxRestore(uuid.Nil); return e }()},
	} {
		assert.ErrorIs(t, tc.err, ErrInvalidArgument, tc.name)
	}
}

func TestWipeInputClearsTheKey(t *testing.T) {
	c, err := CmdNginxDeploy(testOp, "/a.crt", "/a.key", strings.Repeat("ab", 32), []byte("secret key bytes"))
	require.NoError(t, err)
	c.WipeInput()
	assert.Equal(t, make([]byte, len("secret key bytes")), c.stdin)
}
```

Add to `setup_test.go`: replace `goldenSudoersNginx`'s `ALICE_NGINX_ONLY` block with the contract's five lines, and add:

```go
func TestNginxSudoersMatchesEveryBuiltCommand(t *testing.T) {
	sha := strings.Repeat("ab", 32)
	deploy, err := CmdNginxDeploy(testOp, "/etc/letsencrypt/live/a/fullchain.pem", "/etc/letsencrypt/live/a/privkey.pem", sha, []byte("{}"))
	require.NoError(t, err)
	restore, err := CmdNginxRestore(testOp)
	require.NoError(t, err)
	status, err := CmdNginxStatus(testOp)
	require.NoError(t, err)
	patterns := sudoersPatterns(t, "nginx")
	require.Len(t, patterns, 11)
	for _, cmd := range []HelperCommand{CmdNginxDump(), CmdNginxTest(), deploy, restore, status} {
		args := sudoArgs(t, cmd)
		n := 0
		for _, p := range patterns {
			if sudoGlob(p, args) {
				n++
			}
		}
		assert.Equal(t, 1, n, "%q matches exactly one sudoers line", args)
	}
	probe, err := CmdTLSProbe("127.0.0.1", 443, "a.b", "any")
	require.NoError(t, err)
	assert.False(t, strings.HasPrefix(probe.Line(), "sudo"), "tls-probe runs without sudo and is not in sudoers")
	for _, bad := range []string{"nginx-dump -c /tmp/x", "nginx-test -c /tmp/x", "nginx-deploy --cert /x --op y",
		"nginx-restore /x", "stat /etc/shadow", "read-cert /etc/shadow", "install-cert /etc/x", "backup /etc/x", "restore /etc/x",
		"nginx-reload", "tls-probe --addr 1.1.1.1"} {
		for _, p := range patterns {
			assert.False(t, sudoGlob(p, bad), "%q must not match %q", bad, p)
		}
	}
	linux := sudoersPatterns(t, "linux")
	for _, cmd := range []HelperCommand{CmdNginxDump(), deploy} {
		for _, p := range linux {
			assert.False(t, sudoGlob(p, sudoArgs(t, cmd)), "a Linux server never gets nginx subcommands")
		}
	}
}

// The key travels in nginx-deploy's stdin: sudo must never record input.
func TestSudoersNeverLogsInput(t *testing.T) {
	for _, profile := range []string{"linux", "nginx"} {
		s, err := Sudoers(profile)
		require.NoError(t, err)
		assert.NotContains(t, s, "log_input")
		assert.Contains(t, s, "Defaults:alice-svc log_output")
	}
}
```

(`sudoersPatterns`, `sudoArgs`, `sudoGlob` are Phase 3 helpers in `setup_test.go`; `TestSudoersMatchesEveryBuiltCommand` keeps checking the `linux` profile's 6 lines.)

Run: `go test ./internal/providers/linuxssh -run 'Nginx|WipeInput|SudoersNeverLogsInput' -count=1`
Expected: FAIL.

- [ ] **Step 2: Implement the constructors and the sudoers lines**

In `command.go` (after `CmdCleanup`):

```go
// CmdNginxDump returns the parsed Nginx configuration and the referenced certificate files.
func CmdNginxDump() HelperCommand {
	return privileged(helperproto.SubNginxDump, LongCommandTimeout, helperproto.NginxDumpOutput)
}

// CmdNginxTest runs nginx -t.
func CmdNginxTest() HelperCommand { return privileged(helperproto.SubNginxTest, LongCommandTimeout, smallOutput) }

// CmdNginxDeploy replaces a certificate/key pair in one helper transaction. input is the JSON
// helperproto.NginxDeployInput (it carries the private key): it goes on stdin only, with its
// SHA-256 on the command line (--content-sha256), so a dropped connection never deploys a prefix.
func CmdNginxDeploy(op uuid.UUID, certPath, keyPath, expectCertSHA256 string, input []byte) (HelperCommand, error) {
	if op == uuid.Nil || !helperproto.ValidOpID(op.String()) || !helperproto.ValidPath(certPath) || !helperproto.ValidPath(keyPath) ||
		certPath == keyPath || !helperproto.ValidSHA256(expectCertSHA256) || expectCertSHA256 == helperproto.AbsentSHA256 {
		return HelperCommand{}, ErrInvalidArgument
	}
	if len(input) > helperproto.MaxDeployInput {
		return HelperCommand{}, fmt.Errorf("%w: input is larger than %d bytes", ErrInvalidArgument, helperproto.MaxDeployInput)
	}
	sum := sha256.Sum256(input)
	tokens, err := quoteAll(op.String(), certPath, keyPath, expectCertSHA256, hex.EncodeToString(sum[:]))
	if err != nil {
		return HelperCommand{}, err
	}
	c := privileged(helperproto.SubNginxDeploy, LongCommandTimeout, smallOutput,
		"--op", tokens[0], "--cert", tokens[1], "--key", tokens[2], "--expect-cert-sha256", tokens[3], "--content-sha256", tokens[4])
	c.stdin = append([]byte(nil), input...)
	return c, nil
}

// CmdNginxRestore restores the files an operation replaced.
func CmdNginxRestore(op uuid.UUID) (HelperCommand, error) { return opCommand(helperproto.SubNginxRestore, op, LongCommandTimeout) }

// CmdNginxStatus reports an operation's journal.
func CmdNginxStatus(op uuid.UUID) (HelperCommand, error) { return opCommand(helperproto.SubNginxStatus, op, DefaultCommandTimeout) }

func opCommand(sub string, op uuid.UUID, timeout time.Duration) (HelperCommand, error) {
	if op == uuid.Nil || !helperproto.ValidOpID(op.String()) {
		return HelperCommand{}, ErrInvalidArgument
	}
	qo, err := quoteArg(op.String())
	if err != nil {
		return HelperCommand{}, err
	}
	return privileged(sub, timeout, smallOutput, "--op", qo), nil
}

// CmdTLSProbe checks a TLS endpoint from the server itself (no sudo; spec §12.8 item 6).
// sni "" sends no server name.
func CmdTLSProbe(addr string, port int, sni, keyType string) (HelperCommand, error) {
	if sni == "" {
		sni = helperproto.NoSNI
	}
	ps := strconv.Itoa(port)
	if !helperproto.ValidIP(addr) || !helperproto.ValidPort(ps) || (sni != helperproto.NoSNI && !helperproto.ValidSNI(sni)) ||
		(keyType != helperproto.ProbeAny && keyType != helperproto.ProbeRSA && keyType != helperproto.ProbeECDSA) {
		return HelperCommand{}, ErrInvalidArgument
	}
	t, err := quoteAll(addr, ps, sni, keyType)
	if err != nil {
		return HelperCommand{}, err
	}
	return HelperCommand{sub: helperproto.SubTLSProbe, tokens: []string{"--addr", t[0], "--port", t[1], "--sni", t[2], "--key-type", t[3]},
		timeout: DefaultCommandTimeout, maxOutput: smallOutput}, nil
}

func quoteAll(values ...string) ([]string, error) {
	out := make([]string, 0, len(values))
	for _, v := range values {
		q, err := quoteArg(v)
		if err != nil {
			return nil, err
		}
		out = append(out, q)
	}
	return out, nil
}

// WipeInput overwrites the command's stdin (the private key of nginx-deploy) with zeros. The
// command keeps its own copy of the input, so the caller wipes it after Run (SEC-044, best effort).
func (c HelperCommand) WipeInput() { clear(c.stdin) }
```

(imports `strconv`). In `setup.go` replace `sudoersNginxOnly` with:

```go
const sudoersNginxOnly = `
Cmnd_Alias ALICE_NGINX_ONLY = \
    /usr/local/libexec/alice-helper nginx-dump, \
    /usr/local/libexec/alice-helper nginx-test, \
    /usr/local/libexec/alice-helper nginx-deploy --op * --cert /* --key /* --expect-cert-sha256 * --content-sha256 *, \
    /usr/local/libexec/alice-helper nginx-restore --op *, \
    /usr/local/libexec/alice-helper nginx-status --op *
`
```

Run: `go test ./internal/providers/linuxssh -count=1` → the new tests PASS except those that need the emulator changes below.

- [ ] **Step 3: Protocol 4 in the provider tests and the emulator**

In `linuxsshtest/emulator.go`:
- `parseLine` treats `--cert`, `--key`, `--expect-cert-sha256`, `--addr`, `--port`, `--sni`, `--key-type` as literal flag tokens like `--op` (Task 9 adds the Nginx subcommands themselves).
- The `not sudo → NOT_ROOT` rule exempts `tls-probe` as it exempts `version`.
- `listLocked` fills `Accounts` (the names of its users plus `daemon` and `nobody`, sorted) and `AccountsComplete` (true), unless `SetAccounts(names, complete)` set them.

Run: `go test ./internal/providers/linuxssh/... -count=1` → PASS.

- [ ] **Step 4: Accounts in discovery, failing test first**

Add to `provider_test.go`:

```go
// Carry 1: Discover passes the helper's account list on; inventory decides with it.
func TestDiscoverReportsTheAccountList(t *testing.T) {
	e := newProvEnv(t)
	e.emu.SetAccounts([]string{"alice-svc", "deploy", "root"}, true)
	s, err := e.prov.Open(context.Background(), e.ref, e.cred, providers.Env{})
	require.NoError(t, err)
	defer func() { _ = s.Close() }()
	res, err := s.Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true})
	require.NoError(t, err)
	assert.Equal(t, []string{"alice-svc", "deploy", "root"}, res.Accounts)
	assert.True(t, res.AccountsComplete)

	e.emu.SetAccounts([]string{"root", "Bad Name", "deploy"}, true)
	res, err = s.Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true})
	require.NoError(t, err)
	assert.Equal(t, []string{"deploy", "root"}, res.Accounts, "invalid names are dropped")
	assert.False(t, res.AccountsComplete, "a list with an invalid entry is not trusted as complete")

	res, err = s.Discover(context.Background(), providers.DiscoverRequest{})
	require.NoError(t, err)
	assert.Nil(t, res.Accounts, "without SSH keys no list is read")
	assert.False(t, res.AccountsComplete)
}
```

Run → FAIL. Implement: `providers.DiscoveryResult` gains (after `UID0Users`):

```go
	Accounts         []string // every account name of /etc/passwd the helper reported (carry 1)
	AccountsComplete bool     // Accounts is the whole list; only then may inventory mark vanished users' keys missing
```

In `Discover`, right after `list, err := s.listAuthKeys(ctx)`:

```go
	res.AccountsComplete = list.AccountsComplete
	for _, a := range list.Accounts {
		if !helperproto.ValidUser(a) {
			res.AccountsComplete = false
			continue
		}
		res.Accounts = append(res.Accounts, a)
	}
	if len(res.Accounts) > helperproto.MaxAccountNames {
		res.Accounts, res.AccountsComplete = res.Accounts[:helperproto.MaxAccountNames], false
	}
	slices.Sort(res.Accounts)
```

Run → PASS.

- [ ] **Step 5: `ConnOf`, failing test first**

```go
func TestConnOf(t *testing.T) {
	e := newProvEnv(t)
	s, err := e.prov.Open(context.Background(), e.ref, e.cred, providers.Env{})
	require.NoError(t, err)
	c, ok := ConnOf(s)
	require.True(t, ok)
	res, err := c.Run(context.Background(), CmdVersion())
	require.NoError(t, err)
	assert.Contains(t, string(res.Stdout), `"protocol":4`)
	require.NoError(t, s.Close())
	_, ok = ConnOf(s)
	assert.False(t, ok, "a closed session's connection may serve another session")
	_, ok = ConnOf(providers.UnsupportedSession{})
	assert.False(t, ok)
}
```

Implement in `provider.go`:

```go
// ConnOf returns the connection of an open linuxssh session; the nginx provider runs its helper
// commands on it (spec §6.6: nginx is built on the linuxssh connector).
func ConnOf(s providers.Session) (*Conn, bool) {
	ls, ok := s.(*session)
	if !ok || ls.closed.Load() {
		return nil, false
	}
	return ls.conn, true
}
```

Run: `go test ./internal/providers/... -count=1` → PASS.

- [ ] **Step 6: Real OpenSSH check and commit**

Run: `ALICE_SSH_IMAGES=ubuntu22 make test-ssh` (Docker: testcontainers) → PASS (the container helper is built from source at protocol 4; the `linux` profile is unchanged).

```bash
git add internal/providers
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "feat(linuxssh): protocol 4 commands, narrowed nginx sudoers, accounts in discovery

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 8: Provider framework — certificate, deploy, rollback, verify and status types and methods

Adds the certificate discovery and deploy contract of spec §6.2–§6.3 to `internal/providers` as the contract defines it: the types, four `Session` methods with `UnsupportedSession` stubs, the conformance checks for them, and a configurable fake so inventory and job tests can run without SSH.

**Files:**
- Modify: `internal/providers/types.go`, `internal/providers/provider.go` (`Session`), `internal/providers/unsupported.go`
- Modify: `internal/providers/providertest/providertest.go` (`CheckUnsupported`, `sessionOps`)
- Modify: `internal/providers/fake/fake.go` (`Config.Deploy`, `Config.Rollback`, `Config.Verify`, `Config.Status` and their errors; `Call.Deploy`)
- Modify: `internal/providers/linuxssh/provider.go` (nothing to add: `session` embeds `UnsupportedSession`; a compile-time assertion keeps it a `providers.Session`)
- Test: `internal/providers/providers_test.go`, `internal/providers/providertest/providertest_test.go`, `internal/providers/fake/fake_test.go`

**Interfaces:**
- Consumes: `secrets.Plaintext`.
- Produces: everything under "Package `alice/internal/providers`" in the contract (including the `Phase*` constants); `fake.Config` gains:

```go
	Deploy       func(req providers.DeployRequest) (providers.DeployOutcome, error) // nil = committed, verified "remote"
	Rollback     func(req providers.RollbackRequest) (providers.RollbackOutcome, error) // nil = rolled_back
	Verify       func(req providers.VerifyRequest) (providers.VerifyResult, error)     // nil = OK, Served = req.Fingerprint
	Status       func(op uuid.UUID) (providers.DeploymentState, error)               // nil = phase none
	DeploySteps  []string // steps reported (ok) before Deploy's outcome; nil = the five helper steps and verify
```

and `Call` gains `Deploy providers.DeployRequest` (with `PrivateKeyPEM` replaced by `secrets.Plaintext{}`: the fake never keeps a key) and `Op uuid.UUID`.

- [ ] **Step 1: Write the failing tests**

Add to `internal/providers/providers_test.go`:

```go
func TestUnsupportedSessionAnswersErrUnsupportedForDeployMethods(t *testing.T) {
	var s providers.Session = providers.UnsupportedSession{}
	ctx := context.Background()
	_, err := s.DeployCertificate(ctx, providers.DeployRequest{}, nil)
	assert.ErrorIs(t, err, providers.ErrUnsupported)
	_, err = s.RollbackDeployment(ctx, providers.RollbackRequest{}, nil)
	assert.ErrorIs(t, err, providers.ErrUnsupported)
	_, err = s.VerifyDeployment(ctx, providers.VerifyRequest{})
	assert.ErrorIs(t, err, providers.ErrUnsupported)
	_, err = s.DeploymentStatus(ctx, uuid.New())
	assert.ErrorIs(t, err, providers.ErrUnsupported)
}

func TestDeployRequestNeverPrintsTheKey(t *testing.T) {
	req := providers.DeployRequest{PrivateKeyPEM: secrets.NewPlaintext([]byte("KEY-MATERIAL-CANARY"))}
	for _, out := range []string{fmt.Sprintf("%v", req), fmt.Sprintf("%+v", req), fmt.Sprintf("%#v", req)} {
		assert.NotContains(t, out, "KEY-MATERIAL-CANARY")
	}
	b, err := json.Marshal(req)
	require.NoError(t, err)
	assert.NotContains(t, string(b), "KEY-MATERIAL-CANARY")
}

func TestBackupRefJSON(t *testing.T) {
	id := uuid.MustParse("0190f5a0-0000-7000-8000-0000000000aa")
	b, err := json.Marshal(providers.BackupRef{OperationID: id, Dir: "/var/lib/alice-helper/backups/" + id.String()})
	require.NoError(t, err)
	assert.JSONEq(t, `{"operation_id":"0190f5a0-0000-7000-8000-0000000000aa","dir":"/var/lib/alice-helper/backups/0190f5a0-0000-7000-8000-0000000000aa"}`, string(b))
}
```

Add to `providertest_test.go` a case where a session advertising `CapDeployCertificate` but answering `ErrUnsupported` from `DeployCertificate` is reported by `CheckSession`, and one where a session without the capability that implements `DeployCertificate` anyway is reported by `CheckUnsupported` (follow the file's existing recording-`testing.TB` pattern). Add to `fake_test.go`:

```go
func TestFakeDeployRecordsWithoutTheKey(t *testing.T) {
	p := fake.New(providers.KindNginx, providers.CapDeployCertificate, providers.CapVerifyDeployment)
	s, err := p.Open(context.Background(), providers.TargetRef{ID: uuid.New()}, nil, providers.Env{})
	require.NoError(t, err)
	var steps []string
	out, err := s.DeployCertificate(context.Background(), providers.DeployRequest{OperationID: uuid.New(),
		PrivateKeyPEM: secrets.NewPlaintext([]byte("k"))}, stepFunc(func(n string, st providers.StepStatus, _ map[string]string) {
		steps = append(steps, n+":"+string(st))
	}))
	require.NoError(t, err)
	assert.Equal(t, providers.DeployCommitted, out.Result)
	assert.Equal(t, []string{"backup:ok", "write_key:ok", "write_cert:ok", "config_test:ok", "reload:ok", "verify:ok"}, steps)
	calls := p.Calls()
	require.Equal(t, "DeployCertificate", calls[len(calls)-1].Method)
	assert.Empty(t, calls[len(calls)-1].Deploy.PrivateKeyPEM.Bytes())
}
```

(`stepFunc` is a small adapter type in the test implementing `providers.StepLogger`.)

Run: `go test ./internal/providers/... -count=1`
Expected: FAIL (undefined methods and types).

- [ ] **Step 2: Implement**

Apply the contract's type block to `types.go` (it adds `"alice/internal/secrets"` to the imports; `DeployRequest` marshals without the key because `secrets.Plaintext` marshals as `"[redacted]"`). Add the four methods to `Session` in `provider.go` with their comments from the contract and update its doc comment ("Later phases add deploy and import methods" → "Phase 5 adds import."). Add the stubs to `unsupported.go`:

```go
// DeployCertificate is not supported.
func (UnsupportedSession) DeployCertificate(context.Context, DeployRequest, StepLogger) (DeployOutcome, error) {
	return DeployOutcome{}, ErrUnsupported
}

// RollbackDeployment is not supported.
func (UnsupportedSession) RollbackDeployment(context.Context, RollbackRequest, StepLogger) (RollbackOutcome, error) {
	return RollbackOutcome{}, ErrUnsupported
}

// VerifyDeployment is not supported.
func (UnsupportedSession) VerifyDeployment(context.Context, VerifyRequest) (VerifyResult, error) {
	return VerifyResult{}, ErrUnsupported
}

// DeploymentStatus is not supported.
func (UnsupportedSession) DeploymentStatus(context.Context, uuid.UUID) (DeploymentState, error) {
	return DeploymentState{}, ErrUnsupported
}
```

`providertest`: `CheckUnsupported` checks the four methods when `CapDeployCertificate` / `CapVerifyDeployment` are absent, and `Discover` with `DiscoverRequest{Certificates: true}` when `CapDiscoverCerts` is absent and `CapDiscoverSSHKeys` too; `sessionOps` gains `DeploymentStatus` (cap `CapDeployCertificate`, a random op) and `VerifyDeployment` (cap `CapVerifyDeployment`, an empty request). `DeployCertificate` and `RollbackDeployment` are not called by `CheckSession` with a live counterpart (they change servers); Task 11's own tests cover them.

`fake`: `session` implements the four methods from `Config` (recording a `Call` per method; the recorded `DeployRequest` copy has `PrivateKeyPEM: secrets.Plaintext{}`); `DeployCertificate` first reports each of `DeploySteps` (default `backup`, `write_key`, `write_cert`, `config_test`, `reload`, `verify`) once with status `ok` to the logger (when the logger is not nil), then returns `Config.Deploy(req)` or the default committed outcome with `Verified: "remote"`, `Backup: BackupRef{OperationID: req.OperationID}`. A test that needs a failing step sets `DeploySteps` to the steps before the failure and returns the failed outcome from `Deploy`.

Run: `go test ./internal/providers/... ./internal/inventory/... ./internal/jobs/... -count=1`
Expected: PASS (`linuxssh.session` embeds `UnsupportedSession`, so it gains the stubs).

- [ ] **Step 3: Commit**

```bash
git add internal/providers
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "feat(providers): certificate discovery and deploy, rollback, verify and status contract

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 9: Test world — emulated Nginx for the fake SSH server

The Phase 3 emulator answers `alice-helper` command lines with the helper's JSON shapes and exit codes, from a model rather than a filesystem. This task adds an Nginx model to it, so the `nginx` provider (Tasks 10–11), API journeys (Task 18) and the deploy engine (Task 16, including the F-66 kill test across processes) run without containers. It models the helper's *decisions* (Task 6 is the truth): the pair must be in the configuration, the certificate hash must match, the journal phases, rollback, idempotence per operation, `BUSY`, `NO_SPACE`; and "Nginx" itself: which leaf each port and name serves after the last successful reload, `nginx -t` checking that each key matches its certificate.

**Files:**
- Create: `internal/providers/linuxssh/linuxsshtest/nginx.go`
- Modify: `internal/providers/linuxssh/linuxsshtest/emulator.go` (dispatch of the six subcommands; `nginx` sudoers profile switch), `internal/providers/linuxssh/linuxsshtest/server.go` (`Response.Hangup`)
- Test: `internal/providers/linuxssh/linuxsshtest/nginx_test.go`

**Interfaces:**
- Consumes: Task 4 `helperproto`; Task 2 `pki` (tests only).
- Produces:

```go
// Response gains:
//	Hangup bool // close the whole SSH connection instead of answering (a dropped connection, F-08)

type NginxSite struct {
	Names    []string
	Port     int
	Default  bool
	CertPath string
	KeyPath  string
}

func (e *Emulator) EnableNginx(version string)                       // /usr/sbin/nginx exists; the nginx profile is installed
func (e *Emulator) SetNginxProfile(installed bool)                   // false: sudo refuses every nginx-* subcommand (exit 1)
func (e *Emulator) AddSite(s NginxSite, certPEM, keyPEM []byte)       // config, files, and serves the leaf (as if reloaded)
func (e *Emulator) AddUnsupported(names []string, port int, raw, reason string) // a pair nginx-dump reports as unsupported
func (e *Emulator) SetNginxFile(path string, content []byte)         // a change outside Alice (not reloaded)
func (e *Emulator) NginxFile(path string) []byte
func (e *Emulator) Served(port int, sni string) string               // hex SHA-256 of the leaf served, "" when nothing
func (e *Emulator) SetConfigInvalid(class string)                    // nginx -T and -t fail with that class; "" = valid
func (e *Emulator) FailConfigTest(n int)                             // the next n "nginx -t" inside a deploy fail (class syntax)
func (e *Emulator) FailReload(n int)                                 // the next n reloads fail
func (e *Emulator) NoopReload(on bool)                               // reload "succeeds" but Nginx keeps serving the old files (F-05)
func (e *Emulator) ServeOther(port int, leafSHA256 string)           // something else answers on port (a load balancer, F-06)
func (e *Emulator) ServeOtherAfterReload(port int, leafSHA256 string) // from the next successful reload on, until the reload after it
func (e *Emulator) SetFreeBytes(n int64)                             // NO_SPACE below the need (F-10)
func (e *Emulator) SetFileProblem(path, problem string)              // nginx-dump reports it; nginx-deploy refuses the file
func (e *Emulator) FailWriteIn(dir string)                           // nginx-deploy cannot create files in dir (IO_ERROR, F-12)
func (e *Emulator) HangupAfter(step string)                          // complete the transaction to step's end, then hang up (F-08)
func (e *Emulator) KillAt(step string)                               // stop after step, journal left (a killed helper)
func (e *Emulator) HoldLock(on bool)                                 // BUSY; nginx-status active
func (e *Emulator) LocalProbeFails(on bool)                          // tls-probe answers PROBE_FAILED
func (e *Emulator) Reloads() int
func (e *Emulator) DeployCount() int                                 // nginx-deploy calls that reached the transaction
func (e *Emulator) DeployStdins() [][]byte                           // stdin of every nginx-deploy (tests assert the key went only there)
```

- [ ] **Step 1: Write the failing emulator tests**

Create `internal/providers/linuxssh/linuxsshtest/nginx_test.go`. They call the emulator's handler directly with command lines built by hand (this package cannot import `linuxssh`):

```go
package linuxsshtest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/testutil/pki"
)

const emuOp = "0190f5a0-0000-7000-8000-0000000000e1"

func hexSum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func deployLine(e *Emulator, certPath, keyPath, expect string, in []byte) string {
	return "sudo -n " + helperproto.HelperPath + " nginx-deploy --op '" + emuOp + "' --cert '" + certPath + "' --key '" + keyPath +
		"' --expect-cert-sha256 '" + expect + "' --content-sha256 '" + hexSum(in) + "'"
}

func TestEmulatedNginxDeployAndRollback(t *testing.T) {
	now := time.Now()
	ca := pki.NewCA("Emu", pki.ECDSA256, now)
	old, nw := ca.Issue(pki.Opts{CommonName: "www.example.test"}, now), ca.Issue(pki.Opts{CommonName: "www.example.test"}, now)
	e := NewEmulator()
	e.EnableNginx("1.22.1")
	e.AddSite(NginxSite{Names: []string{"www.example.test"}, Port: 443, CertPath: "/etc/nginx/ssl/www.crt", KeyPath: "/etc/nginx/ssl/www.key"},
		old.FullchainPEM, old.KeyPEM)
	assert.Equal(t, pki.Fingerprint(old.Cert), e.Served(443, "www.example.test"))

	dump := e.handle("sudo -n "+helperproto.HelperPath+" nginx-dump", nil)
	require.Equal(t, 0, dump.Exit)
	var d helperproto.NginxDumpResponse
	require.NoError(t, json.Unmarshal(dump.Stdout, &d))
	require.Len(t, d.Files, 2)
	assert.Equal(t, string(old.FullchainPEM), d.Files[0].PEM)
	assert.Empty(t, d.Files[1].PEM, "key files are never read")

	in, _ := json.Marshal(helperproto.NginxDeployInput{CertPEM: string(nw.FullchainPEM), KeyPEM: string(nw.KeyPEM)})
	r := e.handle(deployLine(e, "/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key", hexSum(old.FullchainPEM), in), in)
	require.Equal(t, 0, r.Exit, string(r.Stdout))
	assert.Equal(t, pki.Fingerprint(nw.Cert), e.Served(443, "www.example.test"))
	assert.Equal(t, 1, e.Reloads())

	// The same operation again answers from the journal.
	r = e.handle(deployLine(e, "/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key", hexSum(old.FullchainPEM), in), in)
	require.Equal(t, 0, r.Exit)
	assert.Equal(t, 1, e.Reloads())

	r = e.handle("sudo -n "+helperproto.HelperPath+" nginx-restore --op '"+emuOp+"'", nil)
	require.Equal(t, 0, r.Exit, string(r.Stdout))
	assert.Equal(t, pki.Fingerprint(old.Cert), e.Served(443, "www.example.test"))
	assert.Equal(t, old.KeyPEM, e.NginxFile("/etc/nginx/ssl/www.key"))
}

func TestEmulatedNginxConfigTestChecksThePair(t *testing.T) {
	now := time.Now()
	ca := pki.NewCA("Emu", pki.ECDSA256, now)
	old, nw, other := ca.Issue(pki.Opts{CommonName: "a"}, now), ca.Issue(pki.Opts{CommonName: "a"}, now), ca.Issue(pki.Opts{CommonName: "b"}, now)
	e := NewEmulator()
	e.EnableNginx("1.22.1")
	e.AddSite(NginxSite{Names: []string{"a.example.test"}, Port: 443, CertPath: "/etc/nginx/ssl/a.crt", KeyPath: "/etc/nginx/ssl/a.key"},
		old.FullchainPEM, old.KeyPEM)
	in, _ := json.Marshal(helperproto.NginxDeployInput{CertPEM: string(nw.FullchainPEM), KeyPEM: string(other.KeyPEM)})
	r := e.handle(deployLine(e, "/etc/nginx/ssl/a.crt", "/etc/nginx/ssl/a.key", hexSum(old.FullchainPEM), in), in)
	require.Equal(t, 0, r.Exit)
	var resp helperproto.NginxDeployResponse
	require.NoError(t, json.Unmarshal(r.Stdout, &resp))
	assert.Equal(t, helperproto.PhaseRestored, resp.Phase)
	assert.Equal(t, helperproto.StepConfigTest, resp.FailedStep)
	assert.Equal(t, helperproto.ConfigErrKeyMismatch, resp.Error)
	assert.Equal(t, old.FullchainPEM, e.NginxFile("/etc/nginx/ssl/a.crt"))
}

func TestEmulatedNginxRefusals(t *testing.T) {
	now := time.Now()
	ca := pki.NewCA("Emu", pki.ECDSA256, now)
	old, nw := ca.Issue(pki.Opts{CommonName: "a"}, now), ca.Issue(pki.Opts{CommonName: "a"}, now)
	in, _ := json.Marshal(helperproto.NginxDeployInput{CertPEM: string(nw.FullchainPEM), KeyPEM: string(nw.KeyPEM)})
	for _, tc := range []struct {
		name  string
		setup func(e *Emulator)
		exit  int
		code  string
	}{
		{"profile missing", func(e *Emulator) { e.SetNginxProfile(false) }, 1, ""},
		{"config invalid", func(e *Emulator) { e.SetConfigInvalid(helperproto.ConfigErrSyntax) }, helperproto.ExitPrecondition, helperproto.CodeConfigInvalid},
		{"file changed", func(e *Emulator) { e.SetNginxFile("/etc/nginx/ssl/a.crt", []byte("x")) }, helperproto.ExitPrecondition, helperproto.CodeHashMismatch},
		{"no space", func(e *Emulator) { e.SetFreeBytes(1) }, helperproto.ExitPrecondition, helperproto.CodeNoSpace},
		{"busy", func(e *Emulator) { e.HoldLock(true) }, helperproto.ExitFailed, helperproto.CodeBusy},
		{"cannot write", func(e *Emulator) { e.FailWriteIn("/etc/nginx/ssl") }, helperproto.ExitFailed, helperproto.CodeIOError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := NewEmulator()
			e.EnableNginx("1.22.1")
			e.AddSite(NginxSite{Names: []string{"a.example.test"}, Port: 443, CertPath: "/etc/nginx/ssl/a.crt", KeyPath: "/etc/nginx/ssl/a.key"},
				old.FullchainPEM, old.KeyPEM)
			tc.setup(e)
			r := e.handle(deployLine(e, "/etc/nginx/ssl/a.crt", "/etc/nginx/ssl/a.key", hexSum(old.FullchainPEM), in), in)
			assert.Equal(t, tc.exit, r.Exit)
			if tc.code != "" {
				var er helperproto.ErrorResponse
				require.NoError(t, json.Unmarshal(r.Stdout, &er))
				assert.Equal(t, tc.code, er.Code)
			}
			assert.Equal(t, 0, e.Reloads())
		})
	}
}

func TestEmulatedHangupAndKill(t *testing.T) {
	now := time.Now()
	ca := pki.NewCA("Emu", pki.ECDSA256, now)
	old, nw := ca.Issue(pki.Opts{CommonName: "a"}, now), ca.Issue(pki.Opts{CommonName: "a"}, now)
	in, _ := json.Marshal(helperproto.NginxDeployInput{CertPEM: string(nw.FullchainPEM), KeyPEM: string(nw.KeyPEM)})
	setup := func() *Emulator {
		e := NewEmulator()
		e.EnableNginx("1.22.1")
		e.AddSite(NginxSite{Names: []string{"a.example.test"}, Port: 443, CertPath: "/etc/nginx/ssl/a.crt", KeyPath: "/etc/nginx/ssl/a.key"},
			old.FullchainPEM, old.KeyPEM)
		return e
	}
	e := setup()
	e.HangupAfter(helperproto.StepWriteCert)
	r := e.handle(deployLine(e, "/etc/nginx/ssl/a.crt", "/etc/nginx/ssl/a.key", hexSum(old.FullchainPEM), in), in)
	assert.True(t, r.Hangup)
	st := e.handle("sudo -n "+helperproto.HelperPath+" nginx-status --op '"+emuOp+"'", nil)
	assert.Contains(t, string(st.Stdout), `"phase":"committed"`, "the helper finished on its own")

	e = setup()
	e.KillAt(helperproto.StepWriteKey)
	r = e.handle(deployLine(e, "/etc/nginx/ssl/a.crt", "/etc/nginx/ssl/a.key", hexSum(old.FullchainPEM), in), in)
	assert.Equal(t, helperproto.ExitFailed, r.Exit)
	st = e.handle("sudo -n "+helperproto.HelperPath+" nginx-status --op '"+emuOp+"'", nil)
	assert.Contains(t, string(st.Stdout), `"phase":"writing"`)
	r = e.handle("sudo -n "+helperproto.HelperPath+" nginx-restore --op '"+emuOp+"'", nil)
	require.Equal(t, 0, r.Exit)
	assert.Equal(t, old.KeyPEM, e.NginxFile("/etc/nginx/ssl/a.key"))
}
```

Run: `go test ./internal/providers/linuxssh/linuxsshtest -count=1`
Expected: FAIL.

- [ ] **Step 2: Implement the model**

`server.go`: `Response` gains `Hangup bool`; the exec handler closes the underlying network connection (not just the channel) when it is set — `Conn.Run` then sees a transport error (`ssh.unreachable`).

`nginx.go` holds, under the emulator's mutex: `nginx bool`, `profile bool`, `version string`, `sites []NginxSite`, `unsupported []` (names, port, raw, reason), `files map[string][]byte`, `loaded map[string][]byte` (the files at the last successful reload), `configInvalid string`, `failTest`, `failReload int`, `noopReload bool`, `other map[int]string`, `free int64` (default 1 GiB), `problems map[string]string`, `failWrite map[string]bool`, `hangupAfter`, `killAt string`, `locked bool`, `localProbeFails bool`, `reloads`, `deploys int`, `stdins [][]byte`, `journals map[string]*emuJournal` (op → phase, paths, old/new content, steps). The rules:
- `nginx-dump`: missing Nginx → exit 3 `NGINX_NOT_FOUND`; `configInvalid` → `config_valid=false` with the class; else one `NginxServer` per site (`File` `/etc/nginx/conf.d/emu.conf`, `Line` 1 + 10 × the site's index, its names, the SSL listen `{Port, DefaultServer}`, the pair) and per `AddUnsupported` entry (pair with `Unsupported`, `Raw`), and the files: per distinct certificate path a `cert` file with `PEM` = only the `CERTIFICATE` blocks of the stored content (`encoding/pem`), `SHA256` of the content, `Mode` `0644`, `Owner` `root`, `Problem` from `problems`; per key path a `key` file without content (`Mode` `0600`, `Owner` `root`).
- `nginx-test`: `configInvalid` → `{valid:false, error:class}`; else `nginx -t` of the current files (below).
- "`nginx -t`" of the model: valid when `configInvalid == ""` and, for every site, the key's public key matches the certificate's first block (`tls.X509KeyPair(cert, key)` succeeds); a mismatch is class `key_mismatch`; `failTest > 0` consumes one and fails with class `syntax`.
- `nginx-deploy`: argument and stdin checks as the helper (`CONTENT_MISMATCH`, `BAD_CONTENT` via a copy of `checkDeployContent`'s rules); `!profile` → sudo refusal (`Response{Exit: 1, Stderr: "sudo: a password is required"}`); `locked` → exit 4 `BUSY`; a journal for the op → its answer (a `writing`/`restoring` one is rolled back first); `configInvalid` → `CONFIG_INVALID`; the pair not a site's → `CONFIG_CHANGED`; a `problems` entry → `PATH_NOT_ALLOWED`; `sha(files[cert]) != expect` → `HASH_MISMATCH`; same content → phase `unchanged`; `free < need` → `NO_SPACE`; `failWrite[dir(key)]` → exit 4 `IO_ERROR` (nothing changed); then backup → write key → write cert → test → reload, appending steps, honouring `killAt` (stop after that step: exit 4, journal left) and `hangupAfter` (finish the whole transaction, then `Response{Hangup: true}`); a failed test or reload restores both files, runs the model's test again and reloads (`failReload` may fail it again → `restore_failed`, failed step `rollback_reload`); a successful reload copies `files` to `loaded` unless `noopReload`, and switches a pending `ServeOtherAfterReload` on (the next successful reload switches it off again). `deploys++`, `stdins` appended.
- `nginx-restore`: as `cmdNginxRestore` (`UNKNOWN_OP`, `HASH_MISMATCH` when a file is neither the new nor the old content, idempotent).
- `nginx-status`: phase from the journal (`none` without one), `active` = `locked`.
- `tls-probe` (no sudo): `localProbeFails` → exit 4 `PROBE_FAILED`; else `Served(port, sni)` as `leaf_sha256`.
- `Served(port, sni)`: `other[port]` when set; else the site on `port` whose names contain `sni` (or the `Default` site, or the first site on the port), its certificate from `loaded`, first `CERTIFICATE` block's DER, hex SHA-256.

Run: `go test ./internal/providers/linuxssh/... -count=1`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add internal/providers/linuxssh/linuxsshtest
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "test(linuxsshtest): emulated Nginx for the fake SSH server

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 10: `nginx` provider part 1 — provider, test connection (F-14), discovery (F-20, F-21)

The `nginx` provider is the `linuxssh` provider plus certificates (spec §6.6 "Composition"): `Open` opens a `linuxssh` session (the same pool, host-key pinning and helper version check) and keeps its connection (`linuxssh.ConnOf`); SSH-key methods are the `linuxssh` session's; `TestConnection` also proves the `nginx` sudoers profile (`nginx-test`); `Discover` adds `nginx-dump`'s certificates. All helper reasons of the Nginx subcommands are mapped to `nginx.*` reasons here.

**Files:**
- Create: `internal/providers/nginx/provider.go` (`Provider`, `Options`, `New`, `session`, `Open`, `TestConnection`, error mapping)
- Create: `internal/providers/nginx/discover.go` (`Discover`, `convert`)
- Test: `internal/providers/nginx/provider_test.go`, `internal/providers/nginx/discover_test.go`, `internal/providers/nginx/helpers_test.go` (fixture: emulator, fake SSH server, `linuxssh` pool and provider, `emuProber`)
- Modify: `locales/common/{en,tr}.json` (`provider.nginx.name`: "Nginx server" / "Nginx sunucu"; the `warnings.*` of the UI copy table that the backend renders: none — warnings are rendered by the SPA)

**Interfaces:**
- Consumes: Task 7 `linuxssh.ConnOf`, `CmdNginxDump`, `CmdNginxTest`, `DecodeHelper`, `ParseConfig`, `Provider.Open`, `Provider.ConfigSchema/ValidateConfig/ForgetTarget`; Task 8 types; Task 9 emulator.
- Produces: `nginx.New`, `nginx.Options`, `nginx.Prober`, `nginx.Probe`, `nginx.ErrProbeUnreachable`, `nginx.ErrProbeFailed` (Task 11 completes the prober); `providers.DiscoveryResult.Certificates` and `.Nginx` for Nginx targets; reasons `nginx.not_found`, `nginx.profile_missing` (params `subcommand`, `profile`), `nginx.config_invalid`, `nginx.config_changed`, `nginx.file_changed`, `nginx.no_space`, `nginx.busy`, `nginx.write_failed` (params `directory`), `nginx.location_unsupported` (from `mapHelper(err error, sub string) error`).

- [ ] **Step 1: Write the fixture and the failing tests**

`helpers_test.go` builds what Phase 3's `newProvEnv` builds (emulator, `linuxsshtest.NewServer`, a fake credential, pinned host key, `linuxssh.NewPool`, `linuxssh.New`), then `nginx.New(Options{SSH: lp, Prober: emuProber{emu}, RetryWait: time.Millisecond})`, enables Nginx in the emulator and adds the site `www.example.test` on 443 with a fresh `pki` pair. `emuProber.Probe` answers `Probe{LeafSHA256: emu.Served(port, sni)}`, or `ErrProbeUnreachable` while `remoteDown` is set. Copy the small credential and host-key helpers from `internal/providers/linuxssh/helpers_test.go` (they are in another package's test files).

`provider_test.go`:

```go
func TestNginxProviderDescribesItself(t *testing.T) {
	e := newEnv(t)
	providertest.CheckProvider(t, e.prov)
	assert.Equal(t, providers.KindNginx, e.prov.Kind())
	assert.Equal(t, []providers.Capability{providers.CapAuthorizedKeys, providers.CapDeployCertificate, providers.CapDiscoverCerts,
		providers.CapDiscoverSSHKeys, providers.CapTestConnection, providers.CapVerifyDeployment}, e.prov.Capabilities().Sorted())
	var _ providers.ConnectionCache = e.prov
}

func TestNginxConformance(t *testing.T) {
	e := newEnv(t)
	providertest.CheckSession(t, providertest.SessionHarness{
		Capabilities: e.prov.Capabilities(),
		Open:         func(ctx context.Context) (providers.Session, error) { return e.prov.Open(ctx, e.ref, e.cred, providers.Env{}) },
		Secrets:      []string{e.keyCanary},
	})
}

// F-14: a server prepared with the Linux profile only.
func TestTestConnectionChecksTheNginxProfile(t *testing.T) {
	e := newEnv(t)
	s := e.open(t)
	rep, err := s.TestConnection(context.Background())
	require.NoError(t, err)
	require.NotNil(t, rep.Nginx)
	assert.True(t, rep.Nginx.Found)
	assert.True(t, rep.Nginx.ConfigValid)
	require.NoError(t, s.Close())

	e.emu.SetNginxProfile(false)
	s = e.open(t)
	_, err = s.TestConnection(context.Background())
	var pe *providers.Error
	require.ErrorAs(t, err, &pe)
	assert.Equal(t, "nginx.profile_missing", pe.Code)
	assert.Equal(t, map[string]string{"subcommand": "nginx-test", "profile": "nginx"}, pe.Params)
}

func TestTestConnectionWarnsWhenNginxIsMissingOrInvalid(t *testing.T) {
	e := newEnv(t)
	e.emu.SetConfigInvalid(helperproto.ConfigErrSyntax)
	rep, err := e.open(t).TestConnection(context.Background())
	require.NoError(t, err)
	assert.False(t, rep.Nginx.ConfigValid)
	assert.Contains(t, warningCodes(rep.Warnings), "nginx_config_invalid")

	e = newEnv(t, withoutNginx())
	rep, err = e.open(t).TestConnection(context.Background())
	require.NoError(t, err)
	assert.False(t, rep.Nginx.Found)
	assert.Contains(t, warningCodes(rep.Warnings), "nginx_not_found")
}

func TestOpenRefusesAnOutdatedHelper(t *testing.T) {
	e := newEnv(t)
	e.emu.SetProtocol(3)
	_, err := e.prov.Open(context.Background(), e.ref, e.cred, providers.Env{})
	var pe *providers.Error
	require.ErrorAs(t, err, &pe)
	assert.Equal(t, "ssh.helper_outdated", pe.Code, "F-14: the deploy never starts with an old helper")
}
```

`discover_test.go`:

```go
func TestDiscoverListsWebsitesWithCertificates(t *testing.T) {
	e := newEnv(t)
	res, err := e.open(t).Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true, Certificates: true})
	require.NoError(t, err)
	require.NotNil(t, res.Nginx)
	assert.Equal(t, "1.22.1", res.Nginx.Version)
	require.Len(t, res.Certificates, 1)
	c := res.Certificates[0]
	assert.Equal(t, "/etc/nginx/ssl/www.crt", c.Location.CertPath)
	assert.Equal(t, "/etc/nginx/ssl/www.key", c.Location.KeyPath)
	assert.True(t, c.Location.Supported)
	assert.Equal(t, []providers.CertServer{{Names: []string{"www.example.test"}, Listens: []providers.CertListen{{Port: 443}}, File: "/etc/nginx/conf.d/emu.conf", Line: 1}},
		c.Location.Servers)
	assert.Equal(t, string(e.leaf.FullchainPEM), string(c.PEMChain))
	assert.NotEmpty(t, res.SSHKeys, "an Nginx server's SSH keys are discovered too")
	out, _ := json.Marshal(res)
	assert.NotContains(t, string(out), string(e.leaf.KeyPEM[30:70]), "key files are never read")
}

func TestDiscoverSharedDualAndUnsupportedLocations(t *testing.T) {
	e := newEnv(t)
	other := e.ca.Issue(pki.Opts{CommonName: "shop.example.test", KeyType: pki.RSA2048}, e.now)
	e.emu.AddSite(linuxsshtest.NginxSite{Names: []string{"api.example.test"}, Port: 8443, CertPath: "/etc/nginx/ssl/www.crt", KeyPath: "/etc/nginx/ssl/www.key"},
		e.leaf.FullchainPEM, e.leaf.KeyPEM)
	e.emu.AddSite(linuxsshtest.NginxSite{Names: []string{"shop.example.test"}, Port: 443, CertPath: "/etc/nginx/ssl/shop-rsa.crt", KeyPath: "/etc/nginx/ssl/shop-rsa.key"},
		other.FullchainPEM, other.KeyPEM)
	e.emu.AddUnsupported([]string{"files.example.test"}, 443, "/etc/nginx/ssl/$ssl_server_name.crt", "variable")
	e.emu.AddUnsupported([]string{"mail.example.test"}, 993, "/etc/ssl/mail.crt", "stream")
	res, err := e.open(t).Discover(context.Background(), providers.DiscoverRequest{Certificates: true})
	require.NoError(t, err)
	byPath := map[string]providers.DiscoveredCertificate{}
	for _, c := range res.Certificates {
		byPath[c.Location.CertPath] = c
	}
	assert.Len(t, byPath["/etc/nginx/ssl/www.crt"].Location.Servers, 2, "one file shared by two server blocks is one location")
	assert.True(t, byPath["/etc/nginx/ssl/shop-rsa.crt"].Location.Supported)
	v := byPath["/etc/nginx/ssl/$ssl_server_name.crt"]
	assert.False(t, v.Location.Supported)
	assert.Equal(t, providers.UnsupportedVariable, v.Location.Unsupported)
	assert.Equal(t, providers.UnsupportedStream, byPath["/etc/ssl/mail.crt"].Location.Unsupported)
	assert.Contains(t, warningCodes(res.Warnings), "stream_tls", "F-21: a warning, the http websites are still listed")
}

// F-20: no Nginx, no partial data: the whole discovery fails.
func TestDiscoverWithoutNginxFails(t *testing.T) {
	e := newEnv(t, withoutNginx())
	_, err := e.open(t).Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true, Certificates: true})
	var pe *providers.Error
	require.ErrorAs(t, err, &pe)
	assert.Equal(t, "nginx.not_found", pe.Code)
}

func TestDiscoverInvalidConfigurationListsNothing(t *testing.T) {
	e := newEnv(t)
	e.emu.SetConfigInvalid(helperproto.ConfigErrSyntax)
	res, err := e.open(t).Discover(context.Background(), providers.DiscoverRequest{Certificates: true})
	require.NoError(t, err)
	assert.False(t, res.Nginx.ConfigValid)
	assert.Empty(t, res.Certificates)
	assert.Contains(t, warningCodes(res.Warnings), "nginx_config_invalid")
}

func TestDiscoverFileProblemsAndKeyConflicts(t *testing.T) {
	e := newEnv(t)
	e.emu.SetFileProblem("/etc/nginx/ssl/www.crt", helperproto.FileNotRootControlled)
	e.emu.AddSite(linuxsshtest.NginxSite{Names: []string{"b.example.test"}, Port: 443, CertPath: "/etc/nginx/ssl/b.crt", KeyPath: "/etc/nginx/ssl/b1.key"},
		e.leaf.FullchainPEM, e.leaf.KeyPEM)
	e.emu.AddSite(linuxsshtest.NginxSite{Names: []string{"c.example.test"}, Port: 443, CertPath: "/etc/nginx/ssl/b.crt", KeyPath: "/etc/nginx/ssl/b2.key"},
		e.leaf.FullchainPEM, e.leaf.KeyPEM)
	res, err := e.open(t).Discover(context.Background(), providers.DiscoverRequest{Certificates: true})
	require.NoError(t, err)
	for _, c := range res.Certificates {
		switch c.Location.CertPath {
		case "/etc/nginx/ssl/www.crt":
			assert.False(t, c.Location.Supported)
			assert.Equal(t, providers.UnsupportedFile, c.Location.Unsupported)
			assert.Equal(t, providers.CertProblemNotRootControlled, c.Location.Problem)
			assert.Empty(t, c.PEMChain)
		case "/etc/nginx/ssl/b.crt":
			assert.Equal(t, providers.UnsupportedKeyConflict, c.Location.Unsupported)
		}
	}
}

func TestDiscoverWithoutCertificatesRunsNoNginxCommand(t *testing.T) {
	e := newEnv(t)
	_, err := e.open(t).Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true})
	require.NoError(t, err)
	for _, line := range e.srv.Commands() {
		assert.NotContains(t, line, "nginx-")
	}
}

func TestLocationWarnings(t *testing.T) {
	assert.Equal(t, []string{providers.WarnKeyModeOpen}, locationWarnings(helperproto.NginxFile{}, helperproto.NginxFile{Mode: "0644"}))
	assert.Empty(t, locationWarnings(helperproto.NginxFile{}, helperproto.NginxFile{Mode: "0640"}))
	assert.Equal(t, []string{providers.WarnSymlinked, providers.WarnCustomLocation},
		locationWarnings(helperproto.NginxFile{Symlinked: true, Resolved: "/srv/certs/a.pem"}, helperproto.NginxFile{Mode: "0600"}))
	assert.Empty(t, locationWarnings(helperproto.NginxFile{Symlinked: true, Resolved: "/etc/letsencrypt/archive/a/fullchain1.pem"},
		helperproto.NginxFile{Mode: "0600"})[1:], "letsencrypt is a usual folder")
}
```

(`e.srv.Commands()` is the Phase 3 server's command log — use its real name in `server.go`. `warningCodes` collects `Warning.Code`. `withoutNginx()` is a fixture option that does not call `EnableNginx`.)

Run: `go test ./internal/providers/nginx -count=1`
Expected: FAIL (no package).

- [ ] **Step 2: Implement `provider.go`**

```go
// Package nginx is the nginx provider (spec §6.6, §12): a linuxssh session plus certificate
// discovery and deployment through alice-helper's nginx subcommands.
package nginx

// Options are the provider's dependencies.
type Options struct {
	SSH       *linuxssh.Provider
	Prober    Prober        // nil = TLSProber{}
	RetryWait time.Duration // between verification attempts; 0 = 2 s
	Attempts  int           // verification attempts per endpoint; 0 = 5
}

// Provider is the nginx provider.
type Provider struct {
	ssh       *linuxssh.Provider
	prober    Prober
	retryWait time.Duration
	attempts  int
	caps      providers.CapabilitySet
}

var (
	_ providers.Provider        = (*Provider)(nil)
	_ providers.ConnectionCache = (*Provider)(nil)
	_ providers.Session         = (*session)(nil)
)

func New(o Options) *Provider {
	p := &Provider{ssh: o.SSH, prober: o.Prober, retryWait: o.RetryWait, attempts: o.Attempts,
		caps: providers.NewCapabilitySet(providers.CapTestConnection, providers.CapDiscoverSSHKeys, providers.CapAuthorizedKeys,
			providers.CapDiscoverCerts, providers.CapDeployCertificate, providers.CapVerifyDeployment)}
	if p.prober == nil {
		p.prober = TLSProber{}
	}
	if p.retryWait <= 0 {
		p.retryWait = 2 * time.Second
	}
	if p.attempts <= 0 {
		p.attempts = 5
	}
	return p
}

func (p *Provider) Kind() providers.Kind                       { return providers.KindNginx }
func (p *Provider) DisplayNameKey() string                     { return "provider.nginx.name" }
func (p *Provider) Capabilities() providers.CapabilitySet      { return p.caps.Clone() }
func (p *Provider) ConfigSchema() providers.ConfigSchema       { return p.ssh.ConfigSchema() }
func (p *Provider) CredentialSchema() providers.CredentialSchema { return p.ssh.CredentialSchema() }
func (p *Provider) ValidateConfig(cfg providers.TargetConfig) []validate.FieldError { return p.ssh.ValidateConfig(cfg) }
func (p *Provider) ForgetTarget(target uuid.UUID)              { p.ssh.ForgetTarget(target) }

// Open opens a linuxssh session (pinned host key, helper protocol 4) and keeps its connection.
func (p *Provider) Open(ctx context.Context, t providers.TargetRef, cred providers.CredentialSource, env providers.Env) (providers.Session, error) {
	cfg, errs := linuxssh.ParseConfig(t.Config)
	if len(errs) > 0 {
		return nil, providers.NewError("target.invalid_config", false, validate.Errors(errs), nil)
	}
	s, err := p.ssh.Open(ctx, t, cred, env)
	if err != nil {
		return nil, err
	}
	conn, ok := linuxssh.ConnOf(s)
	if !ok {
		_ = s.Close()
		return nil, providers.NewError("ssh.unreachable", true, errors.New("nginx: no connection"), nil)
	}
	clk := env.Clock
	if clk == nil {
		clk = clock.Real{}
	}
	return &session{Session: s, conn: conn, host: cfg.Host, p: p, clock: clk}, nil
}

// session is a linuxssh session with the certificate methods.
type session struct {
	providers.Session
	conn  *linuxssh.Conn
	host  string
	p     *Provider
	clock clock.Clock
}

// TestConnection is linuxssh's test plus nginx-test, which proves the nginx sudoers profile (F-14).
func (s *session) TestConnection(ctx context.Context) (providers.ConnectionReport, error) {
	rep, err := s.Session.TestConnection(ctx)
	if err != nil {
		return rep, err
	}
	res, err := s.conn.Run(ctx, linuxssh.CmdNginxTest())
	if err != nil {
		return rep, err
	}
	t, err := linuxssh.DecodeHelper[helperproto.NginxTestResponse](res, helperproto.SubNginxTest)
	switch {
	case isHelperCode(err, helperproto.CodeNginxNotFound):
		rep.Nginx = &providers.NginxFacts{}
		rep.Warnings = append(rep.Warnings, providers.Warning{Code: "nginx_not_found", Params: map[string]string{}})
		return rep, nil
	case err != nil:
		return rep, mapHelper(err, helperproto.SubNginxTest)
	}
	rep.Nginx = &providers.NginxFacts{Found: true, ConfigValid: t.Valid, ConfigError: t.Error}
	if !t.Valid {
		rep.Warnings = append(rep.Warnings, providers.Warning{Code: "nginx_config_invalid", Params: map[string]string{}})
	}
	return rep, nil
}
```

`mapHelper(err error, sub string) error`: for a `*providers.Error` it returns a new `providers.NewError(reason, retryable, err, params)`:

| Input | Reason | Params |
|---|---|---|
| `ssh.helper_missing` with `exit_code` `1` (sudo refused) on an `nginx-*` subcommand | `nginx.profile_missing` | `subcommand`, `profile=nginx` |
| helper code `NGINX_NOT_FOUND` | `nginx.not_found` | — |
| `CONFIG_INVALID` | `nginx.config_invalid` | — |
| `CONFIG_CHANGED` | `nginx.config_changed` | — |
| `HASH_MISMATCH` (DecodeHelper reports it as `ssh.file_changed`) | `nginx.file_changed` | — |
| `NO_SPACE` | `nginx.no_space` | — |
| `BUSY` | `nginx.busy` (retryable) | — |
| `IO_ERROR` from `nginx-deploy` | `nginx.write_failed` | `directory` = the key file's directory (passed by the caller) |
| `PATH_NOT_ALLOWED`, `UNSAFE_FILE`, `NOT_REGULAR_FILE`, `NOT_FOUND`, `TOO_LARGE` | `nginx.location_unsupported` | — |
| `BAD_CONTENT` | `certificate.invalid` | — |
| anything else | unchanged | unchanged |

`isHelperCode(err, code)`: the error is a `*providers.Error` whose `Params["helper_code"] == code` (any reason).

- [ ] **Step 3: Implement `discover.go`**

```go
// Discover is linuxssh's discovery plus, when asked, the certificates of nginx-dump (spec §12.4).
// Nginx missing fails the whole discovery (F-20: no partial data).
func (s *session) Discover(ctx context.Context, req providers.DiscoverRequest) (providers.DiscoveryResult, error) {
	res, err := s.Session.Discover(ctx, providers.DiscoverRequest{SSHKeys: req.SSHKeys})
	if err != nil || !req.Certificates {
		return res, err
	}
	out, err := s.conn.Run(ctx, linuxssh.CmdNginxDump())
	if err != nil {
		return providers.DiscoveryResult{}, err
	}
	d, err := linuxssh.DecodeHelper[helperproto.NginxDumpResponse](out, helperproto.SubNginxDump)
	if err != nil {
		return providers.DiscoveryResult{}, mapHelper(err, helperproto.SubNginxDump)
	}
	res.Nginx = &providers.NginxFacts{Found: true, Version: d.Version, ConfPath: d.ConfPath, ConfigValid: d.ConfigValid, ConfigError: d.ConfigError}
	if !d.ConfigValid {
		res.Warnings = append(res.Warnings, providers.Warning{Code: "nginx_config_invalid", Params: map[string]string{}})
		return res, nil
	}
	certs, warns := convert(d)
	res.Certificates = certs
	res.Warnings = append(res.Warnings, warns...)
	return res, nil
}
```

`convert(d helperproto.NginxDumpResponse) ([]providers.DiscoveredCertificate, []providers.Warning)`:
1. Index `d.Files` by `kind + "\x00" + path`.
2. Walk servers in order; for each pair the location key is `pair.Cert` when set, else `pair.Raw`; create the location on first sight (order kept); append the server (`Names`, `Listens` → `CertListen{Addr, Port, DefaultServer}`, `File`, `Line`) unless an identical one is already there; remember the pair's key path; a second, different key path for the same certificate path makes the location `UnsupportedKeyConflict`; a stream server's or unsupported pair's reason is the location's `Unsupported` (nginxconf reasons equal the `providers.Unsupported*` constants).
3. For a location with a supported pair: `cf := files["cert\x00"+certPath]`, `kf := files["key\x00"+keyPath]`; `Problem = cf.Problem`, `KeyExists = kf.Exists`, `KeyMode = kf.Mode`, `KeyOwner = kf.Owner`, `KeyProblem = kf.Problem` (`missing` when the key file is absent), `ResolvedCertPath = cf.Resolved`, `Symlinked = cf.Symlinked`, `FreeBytes = cf.FreeBytes`, `CustomLocation` = the resolved path is not below `/etc/ssl/`, `/etc/nginx/`, `/etc/pki/` or `/etc/letsencrypt/`; `Supported = Problem == "" && KeyProblem == "" && KeyExists`; otherwise `Unsupported = UnsupportedFile`; `PEMChain = []byte(cf.PEM)` and `FileSHA256 = cf.SHA256` only when `Problem == ""`; `Warnings = locationWarnings(cf, kf)`.
4. `locationWarnings(cf, kf)`: `key_mode_open` when the key mode (octal) has a bit outside `0640`; `symlinked` when `cf.Symlinked`; `custom_location` as above (in this order; `nil` when none).
5. Dump warnings → `providers.Warning{Code: w}` (codes matching `^[a-z][a-z_]{0,39}$` only); each `d.Writable` path → `Warning{Code: "config_file_writable", Params: {"path": cleaned path}}`.
All strings from the dump are cleaned like `linuxssh`'s `cleanValue` (control characters dropped, length limited): names 253, paths 4096, file names 4096.

Run: `go test ./internal/providers/nginx -count=1`
Expected: PASS.

- [ ] **Step 4: Archtest and commit**

Run: `go test ./internal/archtest ./internal/providers/... -count=1` (the `providers/...` rule already allows `providers/nginx` to import `providers/linuxssh/...` and its own `nginxconf`).

```bash
git add internal/providers/nginx locales/common
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "feat(nginx): provider with profile check and certificate discovery

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 11: `nginx` provider part 2 — deploy, inline rollback, verification and probes, status

The provider side of spec §6.3 and §12.6–§12.8. `DeployCertificate` sends the pair to `nginx-deploy` (one helper transaction), reports the helper's steps, then verifies the new certificate (§12.8) and, when verification fails, restores through `nginx-restore` and verifies the old one — so the provider ends with a known outcome or `DeployUncertain` (connection lost: the journal decides, through `DeploymentStatus`). Verification probes from Alice first and falls back to the helper's `tls-probe` on the server itself (R38 item 6). Every F-case of §24.1 that the provider owns has a test here against the emulator.

**Files:**
- Create: `internal/providers/nginx/deploy.go` (`DeployCertificate`, `RollbackDeployment`, `DeploymentStatus`, outcome mapping)
- Create: `internal/providers/nginx/verify.go` (`VerifyDeployment`, `SNIFor`, `Endpoints`, `probeEndpoint`)
- Create: `internal/providers/nginx/probe.go` (`TLSProber`)
- Test: `internal/providers/nginx/deploy_test.go`, `internal/providers/nginx/verify_test.go`, `internal/providers/nginx/probe_test.go`, `internal/providers/nginx/guard_test.go`

**Interfaces:**
- Consumes: Task 7 `linuxssh.CmdNginxDeploy`, `CmdNginxRestore`, `CmdNginxStatus`, `CmdTLSProbe`, `HelperCommand.WipeInput`, `DecodeHelper`; Task 4 `helperproto.ProbeTLSConfig`, phases and steps; Task 8 types; Task 10 `session`, `mapHelper`, `isHelperCode`.
- Produces: `(*session).DeployCertificate/RollbackDeployment/VerifyDeployment/DeploymentStatus` with the contract's semantics; `nginx.SNIFor`, `nginx.Endpoints`, `nginx.Endpoint`, `nginx.TLSProber`. Outcome reasons: `certificate.key_mismatch` (config test failed with `key_mismatch`), `deployment.config_test_failed`, `deployment.reload_failed`, `deployment.verify_failed`, `deployment.verify_other`, `deployment.verify_unreachable` (param `port`), `deployment.rollback_failed` (param `backup_dir`), `deployment.rollback_reload_failed`, `deployment.interrupted`, plus the `mapHelper` reasons for refusals.

- [ ] **Step 1: Write the failing verification tests**

`verify_test.go`:

```go
func TestSNIForTable(t *testing.T) {
	for _, tc := range []struct {
		names, sans []string
		want        string
	}{
		{[]string{"www.example.test", "example.test"}, nil, "www.example.test"},
		{[]string{"_"}, []string{"a.example.test"}, "a.example.test"},
		{[]string{""}, []string{"*.example.test"}, "alice-check.example.test"},
		{[]string{"*.example.test"}, nil, "alice-check.example.test"},
		{[]string{".example.test"}, nil, "example.test"},
		{[]string{"~^www\\d+\\.example\\.test$", "WWW.Example.TEST"}, nil, "www.example.test"},
		{[]string{"www.*"}, []string{"b.example.test"}, "b.example.test"},
		{[]string{"_"}, []string{"10.0.0.5"}, ""},
		{nil, nil, ""},
	} {
		assert.Equal(t, tc.want, SNIFor(tc.names, tc.sans), "%v %v", tc.names, tc.sans)
	}
}

func TestEndpoints(t *testing.T) {
	loc := providers.CertLocation{Servers: []providers.CertServer{
		{Names: []string{"a.example.test"}, Listens: []providers.CertListen{{Port: 443}, {Addr: "::", Port: 443}, {Addr: "10.0.0.5", Port: 8443}}},
		{Names: []string{"a.example.test"}, Listens: []providers.CertListen{{Port: 443}}},
		{Names: []string{"_"}, Listens: []providers.CertListen{{Port: 443, DefaultServer: true}}},
	}}
	assert.Equal(t, []Endpoint{
		{Port: 443, SNI: "a.example.test", Addr: "127.0.0.1"},
		{Port: 8443, SNI: "a.example.test", Addr: "10.0.0.5"},
		{Port: 443, SNI: "b.example.test", Addr: "127.0.0.1"},
	}, Endpoints(loc, providers.VerifyOptions{}, []string{"b.example.test"}), "deduplicated by port and name")
	assert.Equal(t, []Endpoint{{Port: 9443, SNI: "check.example.test", Addr: "127.0.0.1"}},
		Endpoints(loc, providers.VerifyOptions{Port: 9443, SNI: "check.example.test"}, nil), "an override maps every listen to one endpoint")
	many := providers.CertLocation{}
	for i := 0; i < 30; i++ {
		many.Servers = append(many.Servers, providers.CertServer{Names: []string{fmt.Sprintf("s%d.example.test", i)}, Listens: []providers.CertListen{{Port: 443}}})
	}
	assert.Len(t, Endpoints(many, providers.VerifyOptions{}, nil), 10)
}
```

```go
func TestVerifyFallsBackToTheServerProbe(t *testing.T) {
	e := newEnv(t)
	e.prober.remoteDown = true
	s := e.open(t)
	vr, err := s.VerifyDeployment(context.Background(), providers.VerifyRequest{Location: e.location(t), Fingerprint: pki.Fingerprint(e.leaf.Cert)})
	require.NoError(t, err)
	assert.True(t, vr.OK)
	assert.Equal(t, "local", vr.Mode)
	assert.Contains(t, strings.Join(e.srv.Commands(), "\n"), "/usr/local/libexec/alice-helper tls-probe --addr '127.0.0.1' --port '443' --sni 'www.example.test'")
}

func TestVerifyReportsWhatIsServed(t *testing.T) {
	e := newEnv(t)
	s := e.open(t)
	cur := pki.Fingerprint(e.leaf.Cert)
	vr, err := s.VerifyDeployment(context.Background(), providers.VerifyRequest{Location: e.location(t)})
	require.NoError(t, err)
	assert.True(t, vr.OK)
	assert.Equal(t, cur, vr.Served)
	assert.Equal(t, "remote", vr.Mode)

	vr, err = s.VerifyDeployment(context.Background(), providers.VerifyRequest{Location: e.location(t), Fingerprint: strings.Repeat("a", 64), PreviousFingerprint: cur})
	require.NoError(t, err)
	assert.False(t, vr.OK)
	assert.Equal(t, "deployment.verify_failed", vr.Reason)
	vr, err = s.VerifyDeployment(context.Background(), providers.VerifyRequest{Location: e.location(t), Fingerprint: strings.Repeat("a", 64), PreviousFingerprint: strings.Repeat("b", 64)})
	require.NoError(t, err)
	assert.Equal(t, "deployment.verify_other", vr.Reason)

	e.prober.remoteDown = true
	e.emu.LocalProbeFails(true)
	vr, err = s.VerifyDeployment(context.Background(), providers.VerifyRequest{Location: e.location(t), Fingerprint: cur})
	require.NoError(t, err)
	assert.False(t, vr.OK)
	assert.Equal(t, "deployment.verify_unreachable", vr.Reason)
	assert.Equal(t, map[string]string{"port": "443"}, vr.Params)

	vr, err = s.VerifyDeployment(context.Background(), providers.VerifyRequest{Location: e.location(t), Fingerprint: cur, Verify: providers.VerifyOptions{Skip: true}})
	require.NoError(t, err)
	assert.Equal(t, providers.VerifyResult{OK: true, Mode: "skipped"}, vr)
}
```

(`e.location(t)` returns the `CertLocation` of the fixture site from a discovery.)

`probe_test.go`: `TestTLSProberAgainstALocalServer` — a `tls.Listen` server with a `pki` leaf answers `LeafSHA256 == pki.Fingerprint(leaf.Cert)`, `ChainLength 2`; a closed port answers an error matching `ErrProbeUnreachable`; a plain TCP listener that closes at once answers `ErrProbeFailed`; with `keyType "rsa"` against an ECDSA-only server the handshake fails (`ErrProbeFailed`).

`guard_test.go`:

```go
// Global constraint: helperproto.ProbeTLSConfig is the only certificate check Alice skips.
func TestOnlyProbeTLSConfigSkipsVerification(t *testing.T) {
	root, err := filepath.Abs("../../..")
	require.NoError(t, err)
	needle := "InsecureSkip" + "Verify"
	var found []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "node_modules" || d.Name() == "bin") {
			return filepath.SkipDir
		}
		if d.IsDir() || filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path) //nolint:gosec // G304: walking the repository in a test
		if err != nil {
			return err
		}
		if strings.Contains(string(b), needle) {
			rel, _ := filepath.Rel(root, path)
			found = append(found, rel)
		}
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"internal/providers/linuxssh/helperproto/helperproto.go"}, found)
}
```

Run: `go test ./internal/providers/nginx -run 'SNI|Endpoints|Verify|Prober|OnlyProbe' -count=1`
Expected: FAIL.

- [ ] **Step 2: Implement `verify.go` and `probe.go`**

`probe.go`:

```go
// TLSProber probes a TLS endpoint from Alice. It sends no data and trusts nothing: only the
// served leaf's fingerprint is used (spec §12.8 item 3).
type TLSProber struct{ DialTimeout time.Duration }

func (p TLSProber) Probe(ctx context.Context, host string, port int, sni, keyType string) (Probe, error) {
	timeout := p.DialTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	conn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return Probe{}, fmt.Errorf("%w: %w", ErrProbeUnreachable, err)
	}
	defer func() { _ = conn.Close() }()
	hctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tc := tls.Client(conn, helperproto.ProbeTLSConfig(sni, keyType))
	if err := tc.HandshakeContext(hctx); err != nil {
		return Probe{}, fmt.Errorf("%w: %w", ErrProbeFailed, err)
	}
	cs := tc.ConnectionState()
	if len(cs.PeerCertificates) == 0 {
		return Probe{}, ErrProbeFailed
	}
	leaf := cs.PeerCertificates[0]
	h := sha256.Sum256(leaf.Raw)
	return Probe{LeafSHA256: hex.EncodeToString(h[:]), ChainLength: len(cs.PeerCertificates), NotAfter: leaf.NotAfter.UTC()}, nil
}
```

`verify.go`:

```go
const maxEndpoints = 10

// Endpoint is one (port, name) Alice checks after a deployment.
type Endpoint struct {
	Port int
	SNI  string
	Addr string // where the server-side probe connects
}

// SNIFor chooses the name to send (spec §12.8 item 1; contract).
func SNIFor(names, sans []string) string {
	for _, list := range [][]string{names, sans} {
		for _, n := range list {
			if sni := sniCandidate(n); sni != "" {
				return sni
			}
		}
	}
	return ""
}

func sniCandidate(n string) string {
	n = asciiLower(n)
	switch {
	case n == "" || n == "_" || strings.HasPrefix(n, "~"):
		return ""
	case strings.HasPrefix(n, "*."):
		n = "alice-check." + n[2:]
	case strings.HasPrefix(n, "."):
		n = n[1:]
	}
	if strings.Contains(n, "*") || !helperproto.ValidSNI(n) {
		return ""
	}
	return n
}

// asciiLower lower-cases ASCII letters only (host names; strings.ToLower is not used on purpose:
// it is locale-blind but forbidden by the lint rule for user-visible text).
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// localAddr is where tls-probe connects on the server for a listen address.
func localAddr(addr string) string {
	switch {
	case addr == "" || addr == "0.0.0.0" || addr == "*":
		return "127.0.0.1"
	case addr == "::":
		return "::1"
	case helperproto.ValidIP(addr):
		return addr
	default:
		return "127.0.0.1"
	}
}

// Endpoints lists the (port, name) pairs of a location to verify, at most maxEndpoints.
func Endpoints(loc providers.CertLocation, v providers.VerifyOptions, sans []string) []Endpoint {
	var out []Endpoint
	seen := map[string]bool{}
	for _, srv := range loc.Servers {
		sni := v.SNI
		if sni == "" {
			sni = SNIFor(srv.Names, sans)
		}
		for _, l := range srv.Listens {
			port := l.Port
			if v.Port != 0 {
				port = v.Port
			}
			k := strconv.Itoa(port) + "\x00" + sni
			if seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, Endpoint{Port: port, SNI: sni, Addr: localAddr(l.Addr)})
			if len(out) == maxEndpoints {
				return out
			}
		}
	}
	return out
}

// VerifyDeployment probes every endpoint (spec §12.8): from Alice first, from the server itself
// when Alice cannot connect; up to Attempts tries RetryWait apart while the expected leaf is not
// served yet (old workers answer for a moment after a graceful reload).
func (s *session) VerifyDeployment(ctx context.Context, req providers.VerifyRequest) (providers.VerifyResult, error) {
	if req.Verify.Skip {
		return providers.VerifyResult{OK: true, Mode: "skipped"}, nil
	}
	eps := Endpoints(req.Location, req.Verify, req.SANs)
	if len(eps) == 0 {
		return providers.VerifyResult{Reason: "deployment.verify_unreachable", Params: map[string]string{"port": "443"}}, nil
	}
	res := providers.VerifyResult{OK: true, Mode: "remote"}
	for i, ep := range eps {
		served, local, err := s.probeEndpoint(ctx, ep, req.KeyType, req.Fingerprint)
		if err != nil {
			if ctx.Err() != nil {
				return providers.VerifyResult{}, providers.NewError("ssh.timeout", true, ctx.Err(), nil)
			}
			var pe *providers.Error
			if errors.As(err, &pe) {
				return providers.VerifyResult{}, err // the SSH connection failed during the local probe
			}
			return providers.VerifyResult{Reason: "deployment.verify_unreachable", Params: map[string]string{"port": strconv.Itoa(ep.Port)}}, nil
		}
		if local {
			res.Mode = "local"
		}
		if i == 0 && req.Fingerprint == "" {
			res.Served = served
		}
		if req.Fingerprint != "" && served != req.Fingerprint {
			reason := "deployment.verify_other"
			if req.PreviousFingerprint != "" && served == req.PreviousFingerprint {
				reason = "deployment.verify_failed"
			}
			return providers.VerifyResult{Mode: res.Mode, Served: served, Reason: reason, Params: map[string]string{"port": strconv.Itoa(ep.Port)}}, nil
		}
	}
	return res, nil
}

// probeEndpoint returns the served leaf of one endpoint. errUnreachable means neither Alice nor
// the server itself could complete a handshake.
func (s *session) probeEndpoint(ctx context.Context, ep Endpoint, keyType, expect string) (served string, local bool, err error) {
	kt := keyType
	if kt == "" {
		kt = helperproto.ProbeAny
	}
	for attempt := 1; attempt <= s.p.attempts; attempt++ {
		if !local {
			pr, perr := s.p.prober.Probe(ctx, s.host, ep.Port, ep.SNI, kt)
			switch {
			case perr == nil:
				served = pr.LeafSHA256
			case errors.Is(perr, ErrProbeUnreachable):
				local = true
			default:
				return "", false, errUnreachable
			}
		}
		if local {
			cmd, cerr := linuxssh.CmdTLSProbe(ep.Addr, ep.Port, ep.SNI, kt)
			if cerr != nil {
				return "", true, errUnreachable
			}
			out, rerr := s.conn.Run(ctx, cmd)
			if rerr != nil {
				return "", true, rerr
			}
			r, derr := linuxssh.DecodeHelper[helperproto.TLSProbeResponse](out, helperproto.SubTLSProbe)
			if derr != nil {
				return "", true, errUnreachable
			}
			served = r.LeafSHA256
		}
		if expect == "" || served == expect || attempt == s.p.attempts {
			return served, local, nil
		}
		select {
		case <-ctx.Done():
			return "", local, ctx.Err()
		case <-s.clock.After(s.p.retryWait):
		}
	}
	return served, local, nil
}

var errUnreachable = errors.New("nginx: the website could not be checked")
```

Run the Step 1 tests → PASS.

- [ ] **Step 3: Write the failing deploy tests**

`deploy_test.go` (each test opens a fresh session from the fixture; `e.req(t, leaf)` builds a `DeployRequest` for the fixture location with `ExpectCertSHA256` = the current file's SHA-256, `OldFingerprint` = the current leaf, the new leaf's fingerprint and SANs, `KeyType` `ecdsa`, the key in a `secrets.Plaintext`; `steps` is a recording `StepLogger` returning `"name:status"` strings):

```go
func TestDeployCommitsAndVerifies(t *testing.T) {
	e := newEnv(t)
	nw := e.ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, e.now)
	log := &steps{}
	out, err := e.open(t).DeployCertificate(context.Background(), e.req(t, nw), log)
	require.NoError(t, err)
	assert.Equal(t, providers.DeployCommitted, out.Result)
	assert.Equal(t, "remote", out.Verified)
	assert.Equal(t, helperproto.BackupRoot+"/"+e.op.String(), out.Backup.Dir)
	assert.Equal(t, []string{"backup:ok", "write_key:ok", "write_cert:ok", "config_test:ok", "reload:ok", "verify:started", "verify:ok"}, log.list())
	assert.Equal(t, pki.Fingerprint(nw.Cert), e.emu.Served(443, "www.example.test"))
	for _, line := range e.srv.Commands() {
		assert.NotContains(t, line, string(nw.KeyPEM[30:60]), "the key never travels on a command line")
	}
	stdins := e.emu.DeployStdins()
	require.Len(t, stdins, 1)
	assert.Contains(t, string(stdins[0]), "PRIVATE KEY", "the key travels only on stdin")
}

// §26.6 "deploy idempotence test (run twice)" and §12.9 "Same cert already deployed".
func TestDeployTwiceIsIdempotent(t *testing.T) {
	e := newEnv(t)
	nw := e.ca.Issue(pki.Opts{CommonName: "www.example.test"}, e.now)
	req := e.req(t, nw)
	out, err := e.open(t).DeployCertificate(context.Background(), req, nil)
	require.NoError(t, err)
	require.Equal(t, providers.DeployCommitted, out.Result)
	out, err = e.open(t).DeployCertificate(context.Background(), req, nil)
	require.NoError(t, err)
	assert.Equal(t, providers.DeployCommitted, out.Result, "the same operation answers from the helper's journal")
	assert.Equal(t, 1, e.emu.Reloads())

	again := e.req(t, nw) // a new operation with the files already in place
	again.OperationID = uuid.New()
	again.ExpectCertSHA256 = hexSHA(nw.FullchainPEM)
	out, err = e.open(t).DeployCertificate(context.Background(), again, nil)
	require.NoError(t, err)
	assert.Equal(t, providers.DeployUnchanged, out.Result)
	assert.Equal(t, 1, e.emu.Reloads(), "no reload when nothing changed")
}

func TestDeployFailureCatalogue(t *testing.T) {
	for _, tc := range []struct {
		name     string // F-number
		setup    func(e *env, nw *pki.Leaf)
		result   providers.DeployResult
		reason   string
		failed   string
		served   string // "old" | "new"
	}{
		{"F-01 key mismatch", func(e *env, nw *pki.Leaf) {
			other := e.ca.Issue(pki.Opts{CommonName: "x"}, e.now)
			nw.KeyPEM = other.KeyPEM
		}, providers.DeployRolledBack, "certificate.key_mismatch", "config_test", "old"},
		{"F-02 configuration already broken", func(e *env, _ *pki.Leaf) { e.emu.SetConfigInvalid(helperproto.ConfigErrSyntax) },
			providers.DeployNoChange, "nginx.config_invalid", "", "old"},
		{"F-03 reload fails", func(e *env, _ *pki.Leaf) { e.emu.FailReload(1) }, providers.DeployRolledBack, "deployment.reload_failed", "reload", "old"},
		{"F-04 rollback reload fails too", func(e *env, _ *pki.Leaf) { e.emu.FailReload(2) },
			providers.DeployRollbackFailed, "deployment.rollback_reload_failed", "rollback_reload", "old"},
		{"F-05 old certificate still served", func(e *env, _ *pki.Leaf) { e.emu.NoopReload(true) },
			providers.DeployRolledBack, "deployment.verify_failed", "verify", "old"},
		{"F-06 another certificate served after the reload", func(e *env, _ *pki.Leaf) { e.emu.ServeOtherAfterReload(443, strings.Repeat("c", 64)) },
			providers.DeployRolledBack, "deployment.verify_other", "verify", "old"},
		{"F-07 unreachable both ways after the write", func(e *env, _ *pki.Leaf) { e.prober.remoteDown = true; e.emu.LocalProbeFails(true) },
			providers.DeployRolledBack, "deployment.verify_unreachable", "verify", "old"},
		{"F-10 no space", func(e *env, _ *pki.Leaf) { e.emu.SetFreeBytes(1) }, providers.DeployNoChange, "nginx.no_space", "", "old"},
		{"F-12 directory not writable", func(e *env, _ *pki.Leaf) { e.emu.FailWriteIn("/etc/nginx/ssl") },
			providers.DeployNoChange, "nginx.write_failed", "", "old"},
		{"changed since discovery", func(e *env, _ *pki.Leaf) { e.emu.SetNginxFile("/etc/nginx/ssl/www.crt", e.leaf.CertPEM) },
			providers.DeployNoChange, "nginx.file_changed", "", "old"},
		{"F-14 profile missing", func(e *env, _ *pki.Leaf) { e.emu.SetNginxProfile(false) },
			providers.DeployNoChange, "nginx.profile_missing", "", "old"},
		{"busy", func(e *env, _ *pki.Leaf) { e.emu.HoldLock(true) }, providers.DeployNoChange, "nginx.busy", "", "old"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			nw := e.ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, e.now)
			old := pki.Fingerprint(e.leaf.Cert)
			tc.setup(e, &nw)
			req := e.req(t, nw)
			req.OldFingerprint = old
			out, err := e.open(t).DeployCertificate(context.Background(), req, nil)
			require.NoError(t, err)
			assert.Equal(t, tc.result, out.Result)
			assert.Equal(t, tc.reason, out.Reason)
			assert.Equal(t, tc.failed, out.FailedStep)
			if tc.served == "old" {
				assert.Equal(t, string(e.leaf.FullchainPEM), string(e.emu.NginxFile("/etc/nginx/ssl/www.crt")), "the old files are in place")
				assert.Equal(t, string(e.leaf.KeyPEM), string(e.emu.NginxFile("/etc/nginx/ssl/www.key")))
			}
		})
	}
}
```

F-06 and F-07 here are the cases where something changes *after* the write (a load balancer starts answering, the network to the website breaks): the provider rolls back. The engine's precheck (Task 16) is what refuses, with no change, a location that already serves another certificate or cannot be reached before anything is written. After a rollback whose old-certificate check cannot reach the website, the outcome is still `DeployRolledBack` (the helper restored and reloaded) with `Verified` empty; only a check that sees a *wrong* certificate makes it `DeployRollbackFailed`.

```go
// F-08: the connection drops after the helper finished; the provider reports uncertainty and the
// journal (DeploymentStatus on a new connection) tells the truth.
func TestDeployConnectionDropIsUncertain(t *testing.T) {
	e := newEnv(t)
	nw := e.ca.Issue(pki.Opts{CommonName: "www.example.test"}, e.now)
	e.emu.HangupAfter(helperproto.StepReload)
	out, err := e.open(t).DeployCertificate(context.Background(), e.req(t, nw), nil)
	require.Error(t, err)
	assert.Equal(t, providers.DeployUncertain, out.Result)
	st, err := e.open(t).DeploymentStatus(context.Background(), e.op)
	require.NoError(t, err)
	assert.Equal(t, helperproto.PhaseCommitted, st.Phase)
	assert.Equal(t, hexSHA(nw.FullchainPEM), st.NewCertSHA256)
}

func TestRollbackDeployment(t *testing.T) {
	e := newEnv(t)
	nw := e.ca.Issue(pki.Opts{CommonName: "www.example.test"}, e.now)
	_, err := e.open(t).DeployCertificate(context.Background(), e.req(t, nw), nil)
	require.NoError(t, err)
	rb := providers.RollbackRequest{OperationID: e.op, Location: e.location(t), OldFingerprint: pki.Fingerprint(e.leaf.Cert), KeyType: "ecdsa"}
	log := &steps{}
	out, err := e.open(t).RollbackDeployment(context.Background(), rb, log)
	require.NoError(t, err)
	assert.Equal(t, providers.DeployRolledBack, out.Result)
	assert.Equal(t, "remote", out.Verified)
	assert.Equal(t, []string{"restore:ok", "rollback_config_test:ok", "rollback_reload:ok", "verify_old:started", "verify_old:ok"}, log.list())
	out, err = e.open(t).RollbackDeployment(context.Background(), rb, nil)
	require.NoError(t, err)
	assert.Equal(t, providers.DeployRolledBack, out.Result, "idempotent")
	assert.Equal(t, 2, e.emu.Reloads(), "the second call restores nothing and does not reload")

	_, err = e.open(t).RollbackDeployment(context.Background(), providers.RollbackRequest{OperationID: uuid.New(), Location: e.location(t)}, nil)
	require.NoError(t, err)

	e = newEnv(t)
	_, err = e.open(t).DeployCertificate(context.Background(), e.req(t, nw), nil)
	require.NoError(t, err)
	e.emu.SetNginxFile("/etc/nginx/ssl/www.crt", []byte("someone else"))
	out, err = e.open(t).RollbackDeployment(context.Background(), providers.RollbackRequest{OperationID: e.op, Location: e.location(t)}, nil)
	require.NoError(t, err)
	assert.Equal(t, providers.DeployRollbackFailed, out.Result)
	assert.Equal(t, "nginx.file_changed", out.Reason)
}

// The engine (jobs may not import helperproto) uses providers.Phase*; they must be the helper's names.
func TestPhaseNamesMatchTheHelper(t *testing.T) {
	assert.Equal(t, []string{helperproto.PhaseNone, helperproto.PhasePrepared, helperproto.PhaseWriting, helperproto.PhaseCommitted,
		helperproto.PhaseUnchanged, helperproto.PhaseRestoring, helperproto.PhaseRestored, helperproto.PhaseRestoreFailed},
		[]string{providers.PhaseNone, providers.PhasePrepared, providers.PhaseWriting, providers.PhaseCommitted,
			providers.PhaseUnchanged, providers.PhaseRestoring, providers.PhaseRestored, providers.PhaseRestoreFailed})
}

func TestDeploymentStatusPhases(t *testing.T) {
	e := newEnv(t)
	st, err := e.open(t).DeploymentStatus(context.Background(), e.op)
	require.NoError(t, err)
	assert.Equal(t, helperproto.PhaseNone, st.Phase)
	nw := e.ca.Issue(pki.Opts{CommonName: "www.example.test"}, e.now)
	e.emu.KillAt(helperproto.StepWriteCert)
	_, _ = e.open(t).DeployCertificate(context.Background(), e.req(t, nw), nil)
	st, err = e.open(t).DeploymentStatus(context.Background(), e.op)
	require.NoError(t, err)
	assert.Equal(t, helperproto.PhaseWriting, st.Phase)
	assert.False(t, st.Active)
}
```

Run: `go test ./internal/providers/nginx -count=1`
Expected: FAIL.

- [ ] **Step 4: Implement `deploy.go`**

```go
// DeployCertificate runs one nginx-deploy transaction, then verifies; a failed verification is
// rolled back here (spec §6.3 item 3: the provider first attempts its own inline rollback).
func (s *session) DeployCertificate(ctx context.Context, req providers.DeployRequest, log providers.StepLogger) (providers.DeployOutcome, error) {
	out := providers.DeployOutcome{Backup: providers.BackupRef{OperationID: req.OperationID,
		Dir: helperproto.BackupRoot + "/" + req.OperationID.String()}}
	input, err := json.Marshal(helperproto.NginxDeployInput{CertPEM: string(req.CertificatePEM), KeyPEM: string(req.PrivateKeyPEM.Bytes())})
	defer clear(input)
	if err != nil {
		return out, providers.NewError("internal.unexpected", false, err, nil)
	}
	cmd, err := linuxssh.CmdNginxDeploy(req.OperationID, req.Location.CertPath, req.Location.KeyPath, req.ExpectCertSHA256, input)
	if err != nil {
		out.Result, out.Reason = providers.DeployNoChange, "nginx.location_unsupported"
		return out, nil
	}
	defer cmd.WipeInput()
	res, err := s.conn.Run(ctx, cmd)
	if err != nil {
		out.Result = providers.DeployUncertain // the request may have reached the helper: its journal knows
		return out, err
	}
	d, err := linuxssh.DecodeHelper[helperproto.NginxDeployResponse](res, helperproto.SubNginxDeploy)
	if err != nil {
		var pe *providers.Error
		if errors.As(err, &pe) && pe.Code != "ssh.protocol_error" {
			// A refusal: the helper changed nothing (every refusal precedes the first rename).
			mapped := mapHelperIn(err, helperproto.SubNginxDeploy, filepath.Dir(req.Location.KeyPath))
			var me *providers.Error
			errors.As(mapped, &me)
			out.Result, out.Reason, out.Params = providers.DeployNoChange, me.Code, me.Params
			return out, nil
		}
		out.Result = providers.DeployUncertain // a garbled answer: the journal knows
		return out, err
	}
	logSteps(log, d.Steps)
	switch d.Phase {
	case helperproto.PhaseRestored:
		out.Result, out.FailedStep = providers.DeployRolledBack, d.FailedStep
		out.Reason = failedReason(d.FailedStep, d.Error)
		return s.checkOld(ctx, req, log, out), nil
	case helperproto.PhaseRestoreFailed:
		out.Result, out.FailedStep = providers.DeployRollbackFailed, d.FailedStep
		out.Reason, out.Params = rollbackReason(d.FailedStep), map[string]string{"backup_dir": d.BackupDir}
		return out, nil
	case helperproto.PhaseUnchanged, helperproto.PhaseCommitted:
	default:
		out.Result = providers.DeployUncertain
		return out, providers.NewError("ssh.protocol_error", false, errors.New("nginx: unexpected phase"), map[string]string{"subcommand": helperproto.SubNginxDeploy})
	}
	unchanged := d.Phase == helperproto.PhaseUnchanged
	step(log, "verify", providers.StepStarted, nil)
	vr, err := s.VerifyDeployment(ctx, providers.VerifyRequest{Location: req.Location, Fingerprint: req.Fingerprint,
		PreviousFingerprint: req.OldFingerprint, SANs: req.SANs, KeyType: req.KeyType, Verify: req.Verify})
	if err != nil {
		step(log, "verify", providers.StepFailed, nil)
		out.Result = providers.DeployUncertain
		return out, err
	}
	if vr.OK {
		step(log, "verify", providers.StepOK, map[string]string{"mode": vr.Mode})
		out.Verified = vr.Mode
		out.Result = providers.DeployCommitted
		if unchanged {
			out.Result = providers.DeployUnchanged
		}
		return out, nil
	}
	step(log, "verify", providers.StepFailed, map[string]string{"port": vr.Params["port"]})
	if unchanged {
		// Alice wrote nothing; the files already were the new ones and something else is served.
		out.Result, out.Reason, out.Params = providers.DeployNoChange, vr.Reason, vr.Params
		return out, nil
	}
	rb, err := s.RollbackDeployment(ctx, providers.RollbackRequest{OperationID: req.OperationID, Location: req.Location,
		OldFingerprint: req.OldFingerprint, OldSANs: req.OldSANs, KeyType: req.KeyType, Verify: req.Verify}, log)
	out.FailedStep = "verify"
	switch {
	case err != nil:
		out.Result = providers.DeployUncertain
		return out, err
	case rb.Result == providers.DeployRolledBack:
		out.Result, out.Reason, out.Params, out.Verified = providers.DeployRolledBack, vr.Reason, vr.Params, rb.Verified
	default:
		out.Result, out.Reason = providers.DeployRollbackFailed, rb.Reason
		out.Params = map[string]string{"backup_dir": out.Backup.Dir}
	}
	return out, nil
}

// checkOld verifies that the old certificate is served after the helper's own rollback; when it
// is not, the rollback did not really restore the website.
func (s *session) checkOld(ctx context.Context, req providers.DeployRequest, log providers.StepLogger, out providers.DeployOutcome) providers.DeployOutcome {
	if req.OldFingerprint == "" || req.Verify.Skip {
		return out
	}
	step(log, "verify_old", providers.StepStarted, nil)
	vr, err := s.VerifyDeployment(ctx, providers.VerifyRequest{Location: req.Location, Fingerprint: req.OldFingerprint,
		SANs: req.OldSANs, KeyType: req.KeyType, Verify: req.Verify})
	if err == nil && vr.OK {
		step(log, "verify_old", providers.StepOK, map[string]string{"mode": vr.Mode})
		out.Verified = vr.Mode
		return out
	}
	step(log, "verify_old", providers.StepFailed, nil)
	if err == nil && vr.Reason == "deployment.verify_unreachable" {
		return out // restored and reloaded by the helper; the website cannot be checked (Verified stays "")
	}
	out.Result, out.Reason = providers.DeployRollbackFailed, "deployment.rollback_failed"
	out.Params = map[string]string{"backup_dir": out.Backup.Dir}
	return out
}

func failedReason(step, class string) string {
	switch {
	case step == helperproto.StepConfigTest && class == helperproto.ConfigErrKeyMismatch:
		return "certificate.key_mismatch" // F-01's message
	case step == helperproto.StepConfigTest:
		return "deployment.config_test_failed"
	case step == helperproto.StepReload:
		return "deployment.reload_failed"
	default:
		return "deployment.interrupted"
	}
}

func rollbackReason(step string) string {
	if step == helperproto.StepRollbackReload {
		return "deployment.rollback_reload_failed" // F-04: files back, Nginx not reloaded
	}
	return "deployment.rollback_failed"
}

// RollbackDeployment restores an operation's files through nginx-restore and checks the old
// certificate (idempotent; nothing to restore is DeployNoChange).
func (s *session) RollbackDeployment(ctx context.Context, req providers.RollbackRequest, log providers.StepLogger) (providers.RollbackOutcome, error) {
	cmd, err := linuxssh.CmdNginxRestore(req.OperationID)
	if err != nil {
		return providers.RollbackOutcome{}, providers.NewError("internal.unexpected", false, err, nil)
	}
	res, err := s.conn.Run(ctx, cmd)
	if err != nil {
		return providers.RollbackOutcome{Result: providers.DeployUncertain}, err
	}
	r, err := linuxssh.DecodeHelper[helperproto.NginxRestoreResponse](res, helperproto.SubNginxRestore)
	switch {
	case isHelperCode(err, helperproto.CodeUnknownOp):
		return providers.RollbackOutcome{Result: providers.DeployNoChange}, nil
	case isHelperCode(err, helperproto.CodeHashMismatch):
		return providers.RollbackOutcome{Result: providers.DeployRollbackFailed, Reason: "nginx.file_changed"}, nil
	case isHelperCode(err, helperproto.CodeBusy):
		return providers.RollbackOutcome{Result: providers.DeployUncertain}, mapHelper(err, helperproto.SubNginxRestore)
	case err != nil:
		return providers.RollbackOutcome{Result: providers.DeployUncertain}, mapHelper(err, helperproto.SubNginxRestore)
	}
	logSteps(log, r.Steps)
	switch r.Phase {
	case helperproto.PhasePrepared, helperproto.PhaseUnchanged:
		return providers.RollbackOutcome{Result: providers.DeployNoChange}, nil
	case helperproto.PhaseRestoreFailed:
		return providers.RollbackOutcome{Result: providers.DeployRollbackFailed, Reason: rollbackReason(lastFailed(r.Steps))}, nil
	}
	out := providers.RollbackOutcome{Result: providers.DeployRolledBack}
	if req.OldFingerprint == "" || req.Verify.Skip {
		return out, nil
	}
	step(log, "verify_old", providers.StepStarted, nil)
	vr, err := s.VerifyDeployment(ctx, providers.VerifyRequest{Location: req.Location, Fingerprint: req.OldFingerprint,
		SANs: req.OldSANs, KeyType: req.KeyType, Verify: req.Verify})
	if err != nil {
		step(log, "verify_old", providers.StepFailed, nil)
		return providers.RollbackOutcome{Result: providers.DeployUncertain}, err
	}
	if !vr.OK {
		step(log, "verify_old", providers.StepFailed, nil)
		if vr.Reason == "deployment.verify_unreachable" {
			return out, nil // restored and reloaded; the website cannot be checked (Verified stays "")
		}
		return providers.RollbackOutcome{Result: providers.DeployRollbackFailed, Reason: "deployment.rollback_failed"}, nil
	}
	step(log, "verify_old", providers.StepOK, map[string]string{"mode": vr.Mode})
	out.Verified = vr.Mode
	return out, nil
}

// DeploymentStatus reads an operation's journal on the server.
func (s *session) DeploymentStatus(ctx context.Context, op uuid.UUID) (providers.DeploymentState, error) {
	cmd, err := linuxssh.CmdNginxStatus(op)
	if err != nil {
		return providers.DeploymentState{}, providers.NewError("internal.unexpected", false, err, nil)
	}
	res, err := s.conn.Run(ctx, cmd)
	if err != nil {
		return providers.DeploymentState{}, err
	}
	r, err := linuxssh.DecodeHelper[helperproto.NginxStatusResponse](res, helperproto.SubNginxStatus)
	if err != nil {
		return providers.DeploymentState{}, mapHelper(err, helperproto.SubNginxStatus)
	}
	return providers.DeploymentState{Phase: r.Phase, Active: r.Active, NewCertSHA256: r.NewCertSHA256,
		CurrentCertSHA256: r.CurrentCertSHA256, BackupDir: r.BackupDir}, nil
}
```

Helpers: `step(log, name, status, params)` calls `log.Step` when `log != nil`; `logSteps(log, steps)` reports each helper step once with `ok` or `failed` (params `{"error": class}` when set); `lastFailed(steps)` returns the name of the last failed step; `mapHelperIn(err, sub, dir)` is `mapHelper` with the `directory` param for `nginx.write_failed`; `hexSHA` in the test file.

Note: in the rollback-reload-fails case (F-04) the helper answers `restore_failed` with `failed_step` `rollback_reload`; `DeployCertificate` returns `DeployRollbackFailed` with `deployment.rollback_reload_failed` — the table row's `failed` column is `rollback_reload`.

Run: `go test ./internal/providers/nginx -count=1`
Expected: PASS.

- [ ] **Step 5: Lint and commit**

Run: `make lint && go test ./internal/providers/... -count=1`
Expected: PASS (the only `InsecureSkipVerify` is in `helperproto`).

```bash
git add internal/providers/nginx
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "feat(nginx): deploy with verification, inline rollback and journal status; TLS probes from Alice and from the server

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 12: Migration `00006` — certificates, locations, managed keys, signing requests, deployments, steps, grants

**Files:**
- Create: `migrations/00006_certificates.sql` (exactly the SQL of the contract)
- Modify: `migrations/roles_integration_test.go` (`explicitGrants`, `explicitColumnGrants`), `migrations/down_integration_test.go` (down to 5 and up again)
- Create: `migrations/certificates_integration_test.go`
- Modify: `cmd/alice/testapi_e2e.go` (`resetSQL` truncates the new tables; they reference `users` and `targets`)

**Interfaces:**
- Produces: the tables, constraints and grants of the contract.

- [ ] **Step 1: Write the failing schema tests**

Create `migrations/certificates_integration_test.go` (same package and harness as `inventory_integration_test.go`: `pgtest.New(t)`, `d.Owner`, `d.App`):

```go
//go:build integration

package migrations_test

// seedCertWorld inserts, as the owner role, a credential (dummy envelope bytes), an Nginx
// target, a certificate and one location of it.
func seedCertWorld(t *testing.T, d *pgtest.DB) (target, cert, loc uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	cred, target, cert, loc := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO credentials (id, purpose, kind, ciphertext, nonce, wrapped_dek, key_version, created_at)
VALUES ($1, 'platform_ssh', 'ssh_private_key', 'x', '123456789012', 'x', 1, now())`, []any{cred}},
		{`INSERT INTO targets (id, name, type, config, credential_id, status, created_at, updated_at)
VALUES ($1, 'web-01', 'nginx', '{"host":"10.0.0.1","port":22,"username":"alice-svc"}', $2, 'ok', now(), now())`, []any{target, cred}},
		{`INSERT INTO certificates (id, fingerprint_sha256, not_before, not_after, key_algorithm, public_key_sha256, pem_chain, source,
first_seen_at, last_seen_at, created_at) VALUES ($1, $2, now(), now() + interval '90 days', 'ecdsa', $3, '', 'discovered', now(), now(), now())`,
			[]any{cert, strings.Repeat("a", 64), strings.Repeat("b", 64)}},
		{`INSERT INTO certificate_locations (id, target_id, kind, cert_path, key_path, certificate_id, supported, first_seen_at, last_seen_at)
VALUES ($1, $2, 'nginx_file', '/etc/nginx/ssl/www.crt', '/etc/nginx/ssl/www.key', $3, true, now(), now())`, []any{loc, target, cert}},
	} {
		_, err := d.Owner.Exec(ctx, q.sql, q.args...)
		require.NoError(t, err)
	}
	return target, cert, loc
}

// seedManagedKey inserts a managed key row with dummy envelope bytes as the owner role.
func seedManagedKey(t *testing.T, d *pgtest.DB) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := d.Owner.Exec(context.Background(), `INSERT INTO managed_private_keys (id, owner_type, algorithm, bits, public_key_sha256,
ciphertext, nonce, wrapped_dek, key_version, created_at) VALUES ($1, 'csr', 'ecdsa', 256, $2, 'x', '123456789012', 'x', 1, now())`,
		id, strings.Repeat("c", 64))
	require.NoError(t, err)
	return id
}

func TestOneActiveDeploymentPerLocation(t *testing.T) {
	d := pgtest.New(t)
	target, cert, loc := seedCertWorld(t, d)
	insert := func(state, status string, finished *time.Time) error {
		_, err := d.App.Exec(context.Background(), `INSERT INTO deployments (id, certificate_id, location_id, target_id, trigger, state,
status, new_fingerprint, cert_path, key_path, created_at, finished_at) VALUES ($1, $2, $3, $4, 'manual', $5, $6, $7, '/a.crt', '/a.key', now(), $8)`,
			uuid.New(), cert, loc, target, state, status, strings.Repeat("a", 64), finished)
		return err
	}
	now := time.Now()
	require.NoError(t, insert("done", "succeeded", &now))
	require.NoError(t, insert("queued", "pending", nil))
	assert.True(t, db.IsUniqueViolation(insert("deploying", "running", nil)), "F-15: one active deployment per location")
	assert.Error(t, insert("done", "running", &now), "a finished deployment has a terminal status")
	assert.Error(t, insert("deploying", "succeeded", nil), "an unfinished deployment has no terminal status")
	assert.Error(t, insert("done", "succeeded", nil), "a finished deployment has finished_at")
}

func TestCertificateConstraints(t *testing.T) {
	d := pgtest.New(t)
	_, cert, _ := seedCertWorld(t, d)
	ctx := context.Background()
	_, err := d.App.Exec(ctx, `UPDATE certificates SET fingerprint_sha256 = $2 WHERE id = $1`, cert, strings.Repeat("b", 64))
	assert.Error(t, err, "identity columns are never updated")
	_, err = d.App.Exec(ctx, `DELETE FROM certificates WHERE id = $1`, cert)
	assert.Error(t, err, "certificates are never deleted")
	_, err = d.App.Exec(ctx, `UPDATE certificates SET label = 'x' WHERE id = $1`, cert)
	assert.NoError(t, err)
	_, err = d.App.Exec(ctx, `UPDATE managed_private_keys SET ciphertext = 'x'`)
	assert.Error(t, err, "managed keys are append-only")
	_, err = d.App.Exec(ctx, `UPDATE deployment_steps SET status = 'ok'`)
	assert.Error(t, err, "steps are append-only")
	_, err = d.App.Exec(ctx, `INSERT INTO certificates (id, fingerprint_sha256, not_before, not_after, key_algorithm, public_key_sha256,
pem_chain, source, first_seen_at, last_seen_at, created_at) VALUES ($1, 'SHA256:x', now(), now(), 'rsa', $2, '', 'uploaded', now(), now(), now())`,
		uuid.New(), strings.Repeat("c", 64))
	assert.Error(t, err, "fingerprints are hex SHA-256")
}

func TestCompletedCSRNamesItsCertificate(t *testing.T) {
	d := pgtest.New(t)
	_, cert, _ := seedCertWorld(t, d)
	key := seedManagedKey(t, d)
	_, err := d.App.Exec(context.Background(), `INSERT INTO csr_requests (id, private_key_id, common_name, csr_pem, status, created_at)
VALUES ($1, $2, 'a.example.test', 'x', 'completed', now())`, uuid.New(), key)
	assert.Error(t, err, "completed without a certificate")
	_, err = d.App.Exec(context.Background(), `INSERT INTO csr_requests (id, private_key_id, common_name, csr_pem, status, certificate_id,
created_at) VALUES ($1, $2, 'a.example.test', 'x', 'completed', $3, now())`, uuid.New(), key, cert)
	assert.NoError(t, err)
}

// maintenance.cleanup prunes old jobs: a deployment keeps its row and loses only the job link.
func TestPrunedJobLeavesTheDeployment(t *testing.T) {
	d := pgtest.New(t)
	target, cert, loc := seedCertWorld(t, d)
	ctx := context.Background()
	job, dep := uuid.New(), uuid.New()
	_, err := d.Owner.Exec(ctx, `INSERT INTO jobs (id, type, class, kind, payload_mac, target_id, status, run_at, max_attempts, created_at)
VALUES ($1, 'certificate.deploy', 'change', 'user', $2, $3, 'succeeded', now(), 3, now())`, job, make([]byte, 32), target)
	require.NoError(t, err)
	_, err = d.Owner.Exec(ctx, `INSERT INTO deployments (id, certificate_id, location_id, target_id, job_id, trigger, state, status,
new_fingerprint, cert_path, key_path, created_at, finished_at) VALUES ($1, $2, $3, $4, $5, 'manual', 'done', 'succeeded', $6,
'/etc/nginx/ssl/www.crt', '/etc/nginx/ssl/www.key', now(), now())`, dep, cert, loc, target, job, strings.Repeat("a", 64))
	require.NoError(t, err)
	_, err = d.App.Exec(ctx, `DELETE FROM jobs WHERE id = $1`, job)
	require.NoError(t, err)
	var jobID *uuid.UUID
	require.NoError(t, d.App.QueryRow(ctx, `SELECT job_id FROM deployments WHERE id = $1`, dep).Scan(&jobID))
	assert.Nil(t, jobID)
}
```

(`seedManagedKey` inserts a `managed_private_keys` row with dummy envelope bytes as the owner role.)

In `roles_integration_test.go` add to `explicitGrants`:

```go
	// Phase 4: private keys and step events are append-only for the application; certificates,
	// locations, signing requests and deployments are history and are never deleted.
	"public.managed_private_keys":  {"INSERT", "SELECT"},
	"public.certificates":          {"INSERT", "SELECT"},
	"public.csr_requests":          {"INSERT", "SELECT"},
	"public.certificate_locations": {"INSERT", "SELECT"},
	"public.deployments":           {"INSERT", "SELECT"},
	"public.deployment_steps":      {"INSERT", "SELECT"},
```

and to `explicitColumnGrants` the four sets of the contract's `GRANT UPDATE (…)` lines, each list sorted alphabetically (the guard compares sorted columns):

```go
	"public.certificates": {"UPDATE": {"chain_complete", "label", "last_seen_at", "pem_chain", "private_key_id"}},
	"public.csr_requests": {"UPDATE": {"certificate_id", "finished_at", "status"}},
	"public.certificate_locations": {"UPDATE": {"cert_file_sha256", "certificate_id", "changed_outside_at", "custom_location",
		"deployed_fingerprint", "inherited", "key_exists", "key_mode", "key_owner", "key_path", "key_type", "last_seen_at",
		"missing_since", "problem", "servers", "skip_verify", "supported", "symlinked", "unsupported_reason", "verify_port",
		"verify_sni", "version", "warnings"}},
	"public.deployments": {"UPDATE": {"error_code", "error_params", "failed_step", "finished_at", "job_id", "previous_fingerprint",
		"recover_after", "rollback_info", "started_at", "state", "status", "verified"}},
```

Run: `go test -tags integration ./migrations -count=1` (Docker: testcontainers PostgreSQL)
Expected: FAIL (tables missing).

- [ ] **Step 2: Create the migration**

Create `migrations/00006_certificates.sql` with the contract's SQL, verbatim.

Run: `go test -tags integration ./migrations -count=1`
Expected: PASS, including the down/up test (extend it: migrate down to version 5, check the six tables are gone, migrate up again).

- [ ] **Step 3: e2e reset**

In `cmd/alice/testapi_e2e.go`, `resetSQL` becomes:

```go
const resetSQL = `TRUNCATE users, user_mfa, recovery_codes, sessions, api_tokens, setup_sessions, settings, audit_log,
license, license_files, license_history, notifications_outbox,
target_locks, job_attempts, jobs, ssh_key_locations, ssh_keys, host_keys,
deployment_steps, deployments, certificate_locations, csr_requests, certificates, managed_private_keys,
targets, credentials`
```

Run: `go test -tags "integration e2e testlicense" ./cmd/alice -run TestE2E -count=1` (Docker) → PASS (the reset test truncates everything).

- [ ] **Step 4: Commit**

```bash
git add migrations cmd/alice/testapi_e2e.go
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "feat(db): certificates, Nginx locations, managed keys, signing requests and deployments (00006)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 13: Inventory — certificate reconciliation, queries, locations, Nginx targets, accounts-based missing marking

Discovery results now carry certificates (Tasks 10–11); inventory stores them as spec §12.4 steps 6–9 describe, in the same transaction as the SSH keys (`Reconcile`): one `certificates` row per leaf fingerprint (the same certificate on several servers is one row), one `certificate_locations` row per certificate file of a target, updated rather than duplicated on every run (S3 AC4), locations no longer in a valid configuration marked missing (never deleted), a fingerprint Alice did not deploy flagged "changed outside Alice" and audited, the sanity warnings (expired, name mismatch, key file mode). It also closes carry 1 (keys of users no longer in `/etc/passwd` are marked missing when the list is complete), lets a target be an **Nginx server**, keeps the Nginx facts, and answers the certificate and location queries of the API.

**Files:**
- Create: `internal/inventory/certificates.go` (types, `upsertCertificate`, `ListCertificates`, `GetCertificate`), `internal/inventory/locations.go` (`reconcileLocations`, `ListLocations`, `GetLocation`, warnings)
- Modify: `internal/inventory/sshkeys.go` (`Reconcile`: accounts carry; calls `reconcileLocations`; summary), `internal/inventory/types.go` (`Facts.Nginx`, `TypeLinux`, `TypeNginx`), `internal/inventory/validate.go` and `targets.go` (type `nginx`), `internal/inventory/status.go` (`RecordConnectionOK` stores `rep.Nginx`), `internal/inventory/service.go` (`Config.Roots *x509.CertPool`)
- Modify: `internal/jobs/targetjobs/targetjobs.go` (`discover` asks for certificates when the target can discover them; result counts)
- Test: `internal/inventory/certificates_integration_test.go`, `internal/inventory/sshkeys_integration_test.go`, `internal/inventory/targets_integration_test.go`, `internal/jobs/targetjobs/targetjobs_test.go`

**Interfaces:**
- Consumes: Task 2 `certs.ParseChainPEM`, `certs.ChainComplete`, `certs.SANMatches`, `certs.SystemRoots`; Task 7 `DiscoveryResult.Accounts/AccountsComplete`; Task 8 `DiscoveredCertificate`, `CertLocation`, `NginxFacts`, `Unsupported*`, `Warn*`; Task 12 tables.
- Produces: the Task 13 part of the inventory contract (`Certificate`, `CertificateLocation`, `CertificateRef`, `CertificateFilter`, `CertificatePage`, `ListCertificates`, `GetCertificate`, `ListLocations`, `GetLocation`, `Facts.Nginx`, `TypeLinux`, `TypeNginx`, `ReconcileSummary.{Certificates, Locations, NewLocations, MissingLocations}`), audit `location.changed_outside`.

- [ ] **Step 1: Write the failing tests**

Create `internal/inventory/certificates_integration_test.go` (it uses `newHarness`, `okTarget`, and `internal/testutil/pki`; `cl(path, key, names...)` builds a supported `providers.CertLocation` with one server on port 443; `dc(loc, leaf)` a `DiscoveredCertificate` with `PEMChain = leaf.FullchainPEM` and `FileSHA256 = sha(leaf.FullchainPEM)`; `nginxOK` is `&providers.NginxFacts{Found: true, ConfigValid: true, Version: "1.22.1"}`):

```go
func TestReconcileStoresCertificatesAndLocations(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	web1, web2 := okTarget(t, h, admin, "web-01"), okTarget(t, h, admin, "web-02")
	ca := pki.NewCA("Inv", pki.ECDSA256, h.clock.Now())
	shared := ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, h.clock.Now())
	for _, tg := range []inventory.Target{web1, web2} {
		_, err := h.svc.Reconcile(h.ctx, tg.ID, providers.DiscoveryResult{Nginx: nginxOK,
			Certificates: []providers.DiscoveredCertificate{dc(cl("/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key", "www.example.test"), shared)}})
		require.NoError(t, err)
	}
	page, err := h.svc.ListCertificates(h.ctx, inventory.CertificateFilter{})
	require.NoError(t, err)
	require.Len(t, page.Items, 1, "the same certificate on two servers is one certificate")
	c := page.Items[0]
	assert.Equal(t, pki.Fingerprint(shared.Cert), c.Fingerprint)
	assert.Equal(t, "discovered", c.Source)
	assert.Equal(t, 2, c.LocationCount)
	assert.False(t, c.HasPrivateKey, "a discovered certificate never brings its key")
	locs, err := h.svc.ListLocations(h.ctx, web1.ID, false)
	require.NoError(t, err)
	require.Len(t, locs, 1)
	assert.Equal(t, "ecdsa", locs[0].KeyType)
	assert.Equal(t, pki.Fingerprint(shared.Cert), locs[0].Certificate.Fingerprint)
	assert.True(t, locs[0].Supported)

	// A second identical run updates, never duplicates (S3 AC4).
	_, err = h.svc.Reconcile(h.ctx, web1.ID, providers.DiscoveryResult{Nginx: nginxOK,
		Certificates: []providers.DiscoveredCertificate{dc(cl("/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key", "www.example.test"), shared)}})
	require.NoError(t, err)
	assert.Equal(t, 2, h.count("SELECT count(*) FROM certificate_locations"))
	assert.Equal(t, 1, h.count("SELECT count(*) FROM certificates"))
}

func TestReconcileMissingChangedOutsideAndInvalidConfiguration(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	web := okTarget(t, h, admin, "web-01")
	ca := pki.NewCA("Inv", pki.ECDSA256, h.clock.Now())
	a, b, a2 := ca.Issue(pki.Opts{CommonName: "a.example.test"}, h.clock.Now()), ca.Issue(pki.Opts{CommonName: "b.example.test"}, h.clock.Now()),
		ca.Issue(pki.Opts{CommonName: "a.example.test"}, h.clock.Now())
	locA, locB := cl("/etc/nginx/ssl/a.crt", "/etc/nginx/ssl/a.key", "a.example.test"), cl("/etc/nginx/ssl/b.crt", "/etc/nginx/ssl/b.key", "b.example.test")
	_, err := h.svc.Reconcile(h.ctx, web.ID, providers.DiscoveryResult{Nginx: nginxOK, Certificates: []providers.DiscoveredCertificate{dc(locA, a), dc(locB, b)}})
	require.NoError(t, err)

	// An invalid configuration changes no location (F-20 spirit: no partial data).
	sum, err := h.svc.Reconcile(h.ctx, web.ID, providers.DiscoveryResult{Nginx: &providers.NginxFacts{Found: true, ConfigValid: false}})
	require.NoError(t, err)
	assert.Zero(t, sum.MissingLocations)
	locs, _ := h.svc.ListLocations(h.ctx, web.ID, false)
	assert.Len(t, locs, 2)

	// b disappears; a's file now holds another certificate Alice did not deploy.
	sum, err = h.svc.Reconcile(h.ctx, web.ID, providers.DiscoveryResult{Nginx: nginxOK, Certificates: []providers.DiscoveredCertificate{dc(locA, a2)}})
	require.NoError(t, err)
	assert.Equal(t, 1, sum.MissingLocations)
	locs, _ = h.svc.ListLocations(h.ctx, web.ID, true)
	byPath := map[string]inventory.CertificateLocation{}
	for _, l := range locs {
		byPath[l.CertPath] = l
	}
	assert.NotNil(t, byPath["/etc/nginx/ssl/b.crt"].MissingSince)
	assert.NotNil(t, byPath["/etc/nginx/ssl/a.crt"].ChangedOutsideAt)
	d := h.auditDetails("location.changed_outside")
	require.Len(t, d, 1)
	assert.Equal(t, pki.Fingerprint(a.Cert), d[0]["previous_fingerprint"])
	assert.Equal(t, pki.Fingerprint(a2.Cert), d[0]["fingerprint"])

	// b comes back: no longer missing.
	_, err = h.svc.Reconcile(h.ctx, web.ID, providers.DiscoveryResult{Nginx: nginxOK, Certificates: []providers.DiscoveredCertificate{dc(locA, a2), dc(locB, b)}})
	require.NoError(t, err)
	l, err := h.svc.GetLocation(h.ctx, byPath["/etc/nginx/ssl/b.crt"].ID)
	require.NoError(t, err)
	assert.Nil(t, l.MissingSince)
}

func TestReconcileUnsupportedLocationsAndWarnings(t *testing.T) {
	h := newHarness(t)
	web := okTarget(t, h, h.user("ada", rbac.Admin, ""), "web-01")
	ca := pki.NewCA("Inv", pki.ECDSA256, h.clock.Now())
	expired := ca.Issue(pki.Opts{CommonName: "old.example.test", SANs: []string{"old.example.test"},
		NotBefore: h.clock.Now().AddDate(0, -3, 0), NotAfter: h.clock.Now().Add(-time.Hour)}, h.clock.Now())
	other := ca.Issue(pki.Opts{CommonName: "x.example.test", SANs: []string{"x.example.test"}}, h.clock.Now())
	ed := ca.Issue(pki.Opts{CommonName: "ed.example.test", KeyType: pki.Ed25519}, h.clock.Now())
	variable := providers.CertLocation{CertPath: "/etc/nginx/ssl/$ssl_server_name.crt", Unsupported: providers.UnsupportedVariable,
		Servers: []providers.CertServer{{Names: []string{"files.example.test"}, Listens: []providers.CertListen{{Port: 443}}}}}
	openKey := cl("/etc/nginx/ssl/x.crt", "/etc/nginx/ssl/x.key", "www.example.test")
	openKey.KeyMode, openKey.Warnings = "0644", []string{providers.WarnKeyModeOpen}
	_, err := h.svc.Reconcile(h.ctx, web.ID, providers.DiscoveryResult{Nginx: nginxOK, Certificates: []providers.DiscoveredCertificate{
		{Location: variable},
		dc(cl("/etc/nginx/ssl/old.crt", "/etc/nginx/ssl/old.key", "old.example.test"), expired),
		dc(openKey, other),
		dc(cl("/etc/nginx/ssl/ed.crt", "/etc/nginx/ssl/ed.key", "ed.example.test"), ed),
	}})
	require.NoError(t, err)
	locs, _ := h.svc.ListLocations(h.ctx, web.ID, false)
	byPath := map[string]inventory.CertificateLocation{}
	for _, l := range locs {
		byPath[l.CertPath] = l
	}
	v := byPath["/etc/nginx/ssl/$ssl_server_name.crt"]
	assert.False(t, v.Supported)
	assert.Equal(t, providers.UnsupportedVariable, v.UnsupportedReason)
	assert.Nil(t, v.Certificate)
	assert.Contains(t, byPath["/etc/nginx/ssl/old.crt"].Warnings, "certificate_expired")
	assert.ElementsMatch(t, []string{providers.WarnKeyModeOpen, "san_mismatch"}, byPath["/etc/nginx/ssl/x.crt"].Warnings)
	assert.False(t, byPath["/etc/nginx/ssl/ed.crt"].Supported)
	assert.Equal(t, providers.UnsupportedKeyType, byPath["/etc/nginx/ssl/ed.crt"].UnsupportedReason)
}

// Carry 1: keys of users that left /etc/passwd become missing, only with a complete list.
func TestReconcileMarksKeysOfVanishedUsersMissing(t *testing.T) {
	f := newRemovalFixture(t)
	h := f.h
	keys := providers.DiscoveryResult{SSHKeys: []providers.DiscoveredSSHKey{
		dk("root", rootFile, 1, "SHA256:root000000000000000000000000000000000000000", "root@bastion"),
	}, SSHD: sshdRead, ReadFiles: []string{rootFile}}
	keys.Accounts, keys.AccountsComplete = []string{"alice-svc", "root"}, false
	_, err := h.svc.Reconcile(h.ctx, f.target.ID, keys)
	require.NoError(t, err)
	assert.Nil(t, mustLocation(t, h, f.deploy).MissingSince, "an incomplete list proves nothing")
	keys.AccountsComplete = true
	sum, err := h.svc.Reconcile(h.ctx, f.target.ID, keys)
	require.NoError(t, err)
	assert.NotNil(t, mustLocation(t, h, f.deploy).MissingSince, "deploy is no longer an account")
	assert.Nil(t, mustLocation(t, h, f.own).MissingSince, "alice-svc is in the list")
	assert.Equal(t, 2, sum.Missing, "deploy's key and its cert-authority line")
}

func TestListCertificatesFilters(t *testing.T) {
	// Seeds: expired, expiring in 10 days, in 45 days, in 200 days (discovered on web-01), one uploaded
	// (source set directly as the owner role), subject CNs "İzmir.example.test", "istanbul.example.test", ….
	// Asserts: Expiry "expired" → 1; "30" → expired + 10 days (the window includes expired ones, sorted by not_after);
	// "60" → + 45 days; Source "uploaded" → 1; TargetID web-01 → the four discovered; Query "ISTANBUL" and "izmir" find their
	// certificates (case- and dotted-I-insensitive, as the SSH key search); Limit 2 pages through with NextCursor; an
	// invalid Expiry or a bad cursor is a validate.Errors with fields "expiry", "cursor".
}

func TestNginxTargets(t *testing.T) {
	h := newHarness(t, withNginxProvider())
	admin := h.user("ada", rbac.Admin, "")
	tg, _, err := h.svc.CreateTarget(h.ctx, admin, inventory.NewTarget{Name: "web-nginx", Type: inventory.TypeNginx, Host: "10.0.0.9"})
	require.NoError(t, err)
	assert.Equal(t, "nginx", tg.Type)
	assert.Contains(t, tg.Capabilities, "discover_certificates")
	_, _, err = h.svc.CreateTarget(h.ctx, admin, inventory.NewTarget{Name: "x", Type: "apache", Host: "10.0.0.10"})
	var verrs validate.Errors
	require.ErrorAs(t, err, &verrs)
	assert.Equal(t, map[string]string{"values": "linux, nginx"}, verrs[0].Params)
	require.NoError(t, h.svc.RecordConnectionOK(h.ctx, tg.ID, providers.ConnectionReport{HostKey: h.pinnedKey(tg.ID),
		Nginx: &providers.NginxFacts{Found: true, ConfigValid: true}}))
	got, err := h.svc.GetTarget(h.ctx, tg.ID)
	require.NoError(t, err)
	require.NotNil(t, got.Facts.Nginx)
	assert.True(t, got.Facts.Nginx.ConfigValid)
}
```

Write `TestListCertificatesFilters` in full from its comment (it is a table of `CertificateFilter` → expected subject CNs). `withNginxProvider()` is a new `harnessOption` that replaces `c.Registry` with a fresh registry holding the existing fake `linuxssh` provider (`c.Registry.Get(providers.KindLinuxSSH)`) and a `fake.New(providers.KindNginx, …the six nginx capabilities…)`, frozen; `h.pinnedKey` pins and returns the target's key as the existing status tests do (reuse their helper). `mustLocation` reads one SSH key location (exists in the sshkeys tests; add it if not).

Add to `internal/jobs/targetjobs/targetjobs_test.go`:

```go
func TestDiscoverReadsCertificatesOfNginxTargets(t *testing.T) {
	// A target whose Capabilities contain discover_certificates gets Discover{SSHKeys: true, Certificates: true};
	// a linux target gets Discover{SSHKeys: true}. The job result carries certificate_count and location_count.
}
```

(Write it with the file's fake inventory and fake provider: record the `DiscoverRequest` the fake session received.)

Run: `go test -tags integration ./internal/inventory -run 'Certificates|Locations|Vanished|NginxTargets|Reconcile' -count=1 && go test ./internal/jobs/targetjobs -count=1` (Docker)
Expected: FAIL.

- [ ] **Step 2: Implement**

`types.go`: `const (TypeLinux = "linux"; TypeNginx = "nginx")`; `Facts.Nginx *providers.NginxFacts \`json:"nginx,omitempty"\``. `validate.go`: `in.Type` must be `TypeLinux` or `TypeNginx` (`validate.OneOf` with `{"values": "linux, nginx"}`); the same values in `CreateTarget`'s "no provider" branch. `status.go`: `RecordConnectionOK` stores `r.Nginx` in the facts it already writes (the facts JSON of a connection test keeps the earlier discovery facts and replaces `os`, `helper_*`, `warnings` and, when `r.Nginx != nil`, `nginx`). `service.go`: `Config.Roots *x509.CertPool`; `New` uses `certs.SystemRoots()` when nil.

`Reconcile` (in `sshkeys.go`), inside its transaction after the existing missing-key update:

```go
		if res.AccountsComplete {
			tag, err := tx.Exec(ctx, `UPDATE ssh_key_locations SET missing_since = $2
WHERE target_id = $1 AND missing_since IS NULL AND removed_by_alice_at IS NULL AND NOT (os_user = ANY($3))`, id, now, res.Accounts)
			if err != nil {
				return fmt.Errorf("inventory: mark keys of removed accounts missing: %w", err)
			}
			sum.Missing += int(tag.RowsAffected())
		}
		if res.Nginx != nil {
			f.Nginx = res.Nginx
			if res.Nginx.ConfigValid {
				cs, err := s.reconcileLocations(ctx, tx, t, res.Certificates, now)
				if err != nil {
					return err
				}
				sum.Certificates, sum.Locations, sum.NewLocations, sum.MissingLocations = cs.Certificates, cs.Locations, cs.NewLocations, cs.MissingLocations
			}
		}
```

(the facts update that follows already marshals `f`). The `target.discovered` audit gains `certificate_count`, `location_count`, `new_location_count`, `missing_location_count` (all `…_count`, allowed by the denylist).

`certificates.go`:
- `upsertCertificate(ctx, tx, p certs.Parsed, complete bool, now)`: `INSERT … ON CONFLICT (fingerprint_sha256) DO UPDATE SET last_seen_at = EXCLUDED.last_seen_at RETURNING id, (xmax = 0)`, with `source 'discovered'`, `key_algorithm` from `p.Algorithm`, `public_key_sha256`, `pem_chain` = `p.PEMChain`, `chain_complete`, `self_signed`; lock rows in fingerprint order (sort the discovered certificates by fingerprint before upserting, as `upsertKeys` does, so two scans sharing a certificate cannot deadlock).
- `ListCertificates`: validation (limit 1..200 default 50; `Source` in `""|discovered|uploaded|csr`; `Expiry` in `""|expired|30|60`; `Query` ≤ 200 runes; cursor = base64 of `not_after|id`); SQL over `certificates c` with `LocationCount` = `count(l.id) FILTER (WHERE l.missing_since IS NULL AND t.deleted_at IS NULL)` from a `LEFT JOIN certificate_locations l ON l.certificate_id = c.id LEFT JOIN targets t ON t.id = l.target_id`; filters: `$target::uuid IS NULL OR EXISTS (SELECT 1 FROM certificate_locations x WHERE x.certificate_id = c.id AND x.target_id = $target AND x.missing_since IS NULL)`, `expiry`: `expired` → `c.not_after <= $now`, `30`/`60` → `c.not_after < $now + interval` (the bound computed in Go and passed as a timestamp), source equality, query: the folded `translate(…)` pattern of `ListSSHKeys` over `subject_cn`, `label`, `fingerprint_sha256` and `array_to_string(sans, ' ')`; order `c.not_after, c.id`; keyset `(c.not_after, c.id) > ($cursorAt, $cursorID)`; `HasPrivateKey = private_key_id IS NOT NULL`. `now` is the injected clock.
- `GetCertificate`: the row plus `Locations` (every location on a live target, missing ones included, newest first).

`locations.go`:
- `reconcileLocations(ctx, tx, t Target, found []providers.DiscoveredCertificate, now) (certSummary, error)`: for each discovered location: parse `PEMChain` when present (`certs.ParseChainPEM`; a parse error makes the location unsupported with `UnsupportedFile` and problem `not_a_certificate`); upsert the certificate; `key_type` = `rsa`/`ecdsa` from the leaf, else `''` and `UnsupportedKeyType`; warnings = the provider's plus `certificate_expired` (`!now.Before(leaf.NotAfter)`) and `san_mismatch` (any server name that is not `_`, not empty, not a regex `~…`, and that `certs.SANMatches(leaf SANs, name)` rejects); upsert the location by `(target_id, 'nginx_file', cert_path)` with every column of the discovered location, `missing_since = NULL`, `last_seen_at = now`, `version = version + 1` on update; compare the previous `certificate_id`'s fingerprint with the new one: when they differ, the previous was not NULL and the new fingerprint is not `deployed_fingerprint`, set `changed_outside_at = now` and audit `location.changed_outside` (actor `jobs`); then `UPDATE certificate_locations SET missing_since = $now WHERE target_id = $1 AND missing_since IS NULL AND NOT (id = ANY($seen))`.
- `ListLocations(targetID, includeMissing)`: locations of the target with `Certificate` (`CertificateRef` from the joined certificate) and `ActiveDeploymentID` (`SELECT id FROM deployments WHERE location_id = l.id AND state <> 'done'`), ordered by the first server name then `cert_path`; `GetLocation(id)` one row (`ErrNotFound` when absent or its target is deleted).

`targetjobs.discover`: `req := providers.DiscoverRequest{SSHKeys: true, Certificates: slices.Contains(t.Capabilities, string(providers.CapDiscoverCerts))}` (the target comes from `h.open`'s second return value); result map adds `certificate_count` and `location_count` from the summary.

Run the Step 1 commands → PASS; then `go test -tags integration ./internal/inventory/... ./internal/jobs/... -count=1` (Docker) → PASS.

- [ ] **Step 3: Commit**

```bash
git add internal/inventory internal/jobs/targetjobs
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "feat(inventory): reconcile Nginx certificates and locations; Nginx targets; keys of removed accounts are missing

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 14: Inventory — uploads, signing requests, location settings

**Files:**
- Create: `internal/inventory/uploads.go` (`UploadCertificate`, `storeKey`, `loadKey`), `internal/inventory/csr.go` (`CreateCSR`, `ListCSRs`, `GetCSR`, `CompleteCSR`, `CancelCSR`), `internal/inventory/location_settings.go` (`UpdateLocation`)
- Modify: `internal/inventory/errors.go` (the Task 14 errors of the contract)
- Test: `internal/inventory/uploads_integration_test.go`, `internal/inventory/csr_integration_test.go`, `internal/inventory/location_settings_integration_test.go`

**Interfaces:**
- Consumes: Task 2 `certs.ValidateUpload`, `ValidateSigned`, `NewCSR`, `KeyInfoOf`, `Upload`, `CSRRequest`, `ValidDNSName`; `secrets.Keyring.Seal/Open`, `secrets.Location`; Task 12 tables; Task 13 `upsertCertificate`, `GetCertificate`, `GetLocation`.
- Produces: the Task 14 part of the inventory contract; `func (s *Service) loadKey(ctx context.Context, q db.Querier, id uuid.UUID) (secrets.Plaintext, error)` (PKCS#8 DER; Task 15 uses it); audit `certificate.uploaded`, `certificate.upload_rejected`, `certificate.key_attached`, `csr.created`, `csr.completed`, `csr.cancelled`, `location.updated`.

- [ ] **Step 1: Write the failing tests**

`uploads_integration_test.go`:

```go
func TestUploadStoresTheKeyEncrypted(t *testing.T) {
	h := newHarness(t)
	op := h.user("oya", rbac.Operator, "")
	ca := pki.NewCA("Up", pki.ECDSA256, h.clock.Now())
	l := ca.Issue(pki.Opts{CommonName: "www.example.test"}, h.clock.Now())
	c, warnings, err := h.svc.UploadCertificate(h.ctx, op, inventory.UploadInput{CertificatePEM: string(l.FullchainPEM),
		PrivateKeyPEM: string(l.KeyPEM), Label: "Web 2026"})
	require.NoError(t, err)
	assert.Equal(t, []string{"chain_incomplete"}, warnings, "the test root is not a system root")
	assert.Equal(t, "uploaded", c.Source)
	assert.True(t, c.HasPrivateKey)
	assert.Equal(t, "Web 2026", c.Label)
	var ct []byte
	require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT ciphertext FROM managed_private_keys").Scan(&ct))
	assert.NotContains(t, string(ct), "PRIVATE", "S-04: only ciphertext")
	d := h.auditDetails("certificate.uploaded")
	require.Len(t, d, 1)
	assert.Equal(t, pki.Fingerprint(l.Cert), d[0]["fingerprint"])
	var details string // every audit row's details, as text
	require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT coalesce(string_agg(details::text, ' '), '') FROM audit_log").Scan(&details))
	assert.NotContains(t, details, string(l.KeyPEM[30:70]))
}

func TestUploadRefusalsAreAuditedAndStoreNothing(t *testing.T) {
	h := newHarness(t)
	op := h.user("oya", rbac.Operator, "")
	ca := pki.NewCA("Up", pki.ECDSA256, h.clock.Now())
	l, other := ca.Issue(pki.Opts{CommonName: "a"}, h.clock.Now()), ca.Issue(pki.Opts{CommonName: "b"}, h.clock.Now())
	for _, tc := range []struct {
		in     inventory.UploadInput
		err    error
		reason string
	}{
		{inventory.UploadInput{CertificatePEM: string(l.FullchainPEM), PrivateKeyPEM: string(other.KeyPEM)}, inventory.ErrKeyMismatch, "key_mismatch"},
		{inventory.UploadInput{PFXBase64: base64.StdEncoding.EncodeToString(pki.PFX(l, ca, "pw")), PFXPassword: "no"}, inventory.ErrPFXPassword, "pfx_password"},
		{inventory.UploadInput{PFXBase64: "!!!"}, inventory.ErrCertificateInvalid, "invalid"},
	} {
		_, _, err := h.svc.UploadCertificate(h.ctx, op, tc.in)
		assert.ErrorIs(t, err, tc.err)
	}
	var verrs validate.Errors
	_, _, err := h.svc.UploadCertificate(h.ctx, op, inventory.UploadInput{})
	require.ErrorAs(t, err, &verrs, "neither PEM nor PFX")
	_, _, err = h.svc.UploadCertificate(h.ctx, op, inventory.UploadInput{CertificatePEM: "x", PFXBase64: "eA=="})
	require.ErrorAs(t, err, &verrs, "both PEM and PFX")
	assert.Equal(t, 0, h.count("SELECT count(*) FROM certificates"))
	assert.Equal(t, 0, h.count("SELECT count(*) FROM managed_private_keys"))
	var reasons []string
	for _, d := range h.auditDetails("certificate.upload_rejected") {
		reasons = append(reasons, d["reason"])
	}
	assert.Equal(t, []string{"key_mismatch", "pfx_password", "invalid"}, reasons)
}

// The key of a certificate found on a server can be added later; the same pair twice is refused.
func TestUploadAttachesTheKeyOfADiscoveredCertificate(t *testing.T) {
	// Reconcile a location holding leaf L (no key) → UploadCertificate(L + key) → the same certificate id, HasPrivateKey true,
	// source still "discovered", audit certificate.key_attached; uploading again → ErrCertificateDuplicate.
}
```

`csr_integration_test.go`:

```go
func TestSigningRequestLifecycle(t *testing.T) {
	h := newHarness(t)
	op := h.user("oya", rbac.Operator, "")
	csr, err := h.svc.CreateCSR(h.ctx, op, inventory.CSRInput{CommonName: "www.example.test", SANs: []string{"example.test"}, KeyType: "ecdsa-p256"})
	require.NoError(t, err)
	assert.Equal(t, "pending", csr.Status)
	assert.Contains(t, csr.CSRPEM, "BEGIN CERTIFICATE REQUEST")
	b, _ := pem.Decode([]byte(csr.CSRPEM))
	req, err := x509.ParseCertificateRequest(b.Bytes)
	require.NoError(t, err)

	// The CA signs the request's key.
	ca := pki.NewCA("CSR", pki.ECDSA256, h.clock.Now())
	signed := ca.IssueForCSR(req, h.clock.Now()) // pki helper: issues a leaf for the CSR's public key and names
	c, _, err := h.svc.CompleteCSR(h.ctx, op, csr.ID, string(signed.FullchainPEM), "")
	require.NoError(t, err)
	assert.Equal(t, "csr", c.Source)
	assert.True(t, c.HasPrivateKey)
	got, err := h.svc.GetCSR(h.ctx, csr.ID)
	require.NoError(t, err)
	assert.Equal(t, "completed", got.Status)
	_, _, err = h.svc.CompleteCSR(h.ctx, op, csr.ID, string(signed.FullchainPEM), "")
	assert.ErrorIs(t, err, inventory.ErrCSRNotPending)

	other, err := h.svc.CreateCSR(h.ctx, op, inventory.CSRInput{CommonName: "b.example.test", KeyType: "rsa-3072"})
	require.NoError(t, err)
	_, _, err = h.svc.CompleteCSR(h.ctx, op, other.ID, string(signed.FullchainPEM), "")
	assert.ErrorIs(t, err, inventory.ErrCSRMismatch)
	_, err = h.svc.CancelCSR(h.ctx, op, other.ID)
	require.NoError(t, err)
	_, err = h.svc.CancelCSR(h.ctx, op, other.ID)
	assert.ErrorIs(t, err, inventory.ErrCSRNotPending)
	assert.Equal(t, 1, h.audits("csr.completed"))
	assert.Equal(t, 1, h.audits("csr.cancelled"))

	var verrs validate.Errors
	_, err = h.svc.CreateCSR(h.ctx, op, inventory.CSRInput{CommonName: "bad name", KeyType: "ecdsa-p256"})
	require.ErrorAs(t, err, &verrs)
	assert.Equal(t, "common_name", verrs[0].Field)
	_, err = h.svc.CreateCSR(h.ctx, op, inventory.CSRInput{CommonName: "a.example.test", KeyType: "dsa"})
	require.ErrorAs(t, err, &verrs)
	assert.Equal(t, "key_type", verrs[0].Field)
}
```

Add `func (ca *CA) IssueForCSR(r *x509.CertificateRequest, now time.Time) Leaf` to `internal/testutil/pki` (a leaf for `r.PublicKey`, `r.Subject.CommonName`, `r.DNSNames`; `Key` nil, `KeyPEM` empty) with a unit test in `pki_test.go`.

`location_settings_integration_test.go`:

```go
func TestUpdateLocationVerificationSettings(t *testing.T) {
	// Admin sets verify_port 8443 and verify_sni "check.example.test" with the current version → version+1, audit location.updated
	// (details location_id, verify_port "8443", verify_sni, skip_verify "false"); a stale version → ErrVersionMismatch;
	// port 70000 → validate field "verify_port"; SNI "Bad Name" → field "verify_sni"; port 0 and sni "" clear both (NULL);
	// skip_verify true is stored and audited; an unknown id → ErrNotFound.
}
```

Run: `go test -tags integration ./internal/inventory -run 'Upload|SigningRequest|UpdateLocation' -count=1 && go test ./internal/testutil/pki -count=1` (Docker)
Expected: FAIL.

- [ ] **Step 2: Implement**

`uploads.go`:
- `UploadCertificate(ctx, a, in)`: field checks first (`validate.Errors`): exactly one of `CertificatePEM` (with `PrivateKeyPEM`) or `PFXBase64` (fields `certificate_pem`, `private_key_pem`, `pfx_base64` with `validate.Required`); `Label` ≤ 100 runes, no control characters (`label`); `PFXBase64` that does not decode → `ErrCertificateInvalid`. Then `certs.ValidateUpload(certs.Upload{…}, s.clock.Now(), s.roots)` (zero the input byte slices you created after the call). A validation error is audited in its own short transaction (`detachedTimeout`, as `auditLicenseDenial`) as `certificate.upload_rejected` with `reason` = the error's short name (`invalid`, `key_mismatch`, `expired`, `key_encrypted`, `pfx_password`, `weak`, `unsupported_key`, `too_large`) and returned unchanged (it *is* the `inventory.Err*` value, since those alias `certs`).
- In one transaction: `SELECT id, private_key_id FROM certificates WHERE fingerprint_sha256 = $1 FOR UPDATE`. Existing with a key → audit `certificate.upload_rejected` (`reason` `duplicate`) after rollback, return `ErrCertificateDuplicate`. Existing without a key → `storeKey(tx, "certificate", v)` and `UPDATE certificates SET private_key_id = $2, label = CASE WHEN label = '' THEN $3 ELSE label END, pem_chain = $4, chain_complete = $5` (the upload's chain replaces a discovered file's chain only when it is complete and the old one was not), audit `certificate.key_attached`. New → `storeKey` then `INSERT INTO certificates … source 'uploaded', created_by`, audit `certificate.uploaded`. Return `GetCertificate` and `v.Warnings`. Always `v.PrivateKeyDER.Zero()`.
- `storeKey(ctx, tx, ownerType string, der secrets.Plaintext, info certs.KeyInfo, by uuid.UUID) (uuid.UUID, error)`: new UUIDv7 id; `s.keyring.Seal(secrets.Location{Table: "managed_private_keys", RowID: id.String(), Column: "ciphertext"}, der.Bytes())`; insert with `algorithm`, `bits`, `public_key_sha256`.
- `loadKey(ctx, q, id)`: select the envelope, `s.keyring.Open(...)`; never logs.

`csr.go`:
- `CreateCSR`: validate (`common_name` via `certs.ValidDNSName` after ASCII lower-casing; at most 50 `sans`, each valid, field `sans`; `key_type` one of the three) → `certs.NewCSR(s.rand, …)` (the service's `Rand`, guarded by `randMu`) → one transaction: `storeKey(tx, "csr", …)`, `INSERT INTO csr_requests` (`pending`), audit `csr.created` (`csr_id`, `common_name`, `algorithm`). Zero the key.
- `ListCSRs`: pending ones (newest first) then the 50 newest finished. `GetCSR`: one, `ErrNotFound`.
- `CompleteCSR(a, id, pem, label)`: transaction: lock the row (`FOR UPDATE`); not pending → `ErrCSRNotPending`; key info from `managed_private_keys` (`algorithm`, `bits`, `public_key_sha256`) → `certs.ValidateSigned(pem, info, now, roots)` (errors pass through, audited `certificate.upload_rejected` with the reason, `csr_mismatch` for `ErrCSRMismatch`); a certificate with that fingerprint that already has a key → `ErrCertificateDuplicate`; an existing keyless one → attach the CSR's key (`private_key_id` = the CSR's key id); else insert `source 'csr'` with that `private_key_id`; `UPDATE csr_requests SET status = 'completed', certificate_id = $2, finished_at = $3`; audit `csr.completed` (`csr_id`, `certificate_id`, `fingerprint`).
- `CancelCSR`: pending → `cancelled`, `finished_at`; audit `csr.cancelled`; else `ErrCSRNotPending`.

`location_settings.go`, `UpdateLocation(ctx, a, id, ifVersion, p)`: validation (`verify_port` 0..65535 where 0 clears; `verify_sni` empty clears, else ASCII-lower-cased and `helperproto`-style DNS name rules — use `certs.ValidDNSName` without the wildcard: refuse a leading `*.`); `UPDATE certificate_locations SET verify_port = $3, verify_sni = $4, skip_verify = $5, version = version + 1 WHERE id = $1 AND version = $2 RETURNING …` (zero rows: `ErrNotFound` when the row is absent or its target deleted, else `ErrVersionMismatch`); audit `location.updated` with the new values as strings.

Run the Step 1 commands → PASS.

- [ ] **Step 3: Commit**

```bash
git add internal/inventory internal/testutil/pki
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "feat(inventory): certificate uploads with encrypted keys, signing requests and verification settings

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 15: Deployment records, requests, recovery sweep, emails and job types

Inventory owns the deployment records (spec §7.4) and every decision that needs the database: who may deploy what where (F-15, F-17, F-19, key type, unsupported locations, targets not ready, a recovery pending), the state machine's writes (`queued → precheck → deploying → recovering → done`), the append-only steps, the terminal outcome with its audit rows and emails, and the per-minute sweep that hands interrupted deployments to recovery (R38 item 8). The job handlers that talk to servers follow in Task 16.

**Files:**
- Create: `internal/inventory/deployments.go` (types, `RequestDeployment`, `Deployment`, `ListDeployments`, `DeploymentMaterial`, `BeginDeployment`, `StartDeployment`, `RecordDeploymentStep`, `FinishDeployment`, `MarkRecovering`, `RequestRecovery`), `internal/inventory/sweep.go` (`SweepDeployments`)
- Modify: `internal/inventory/jobs.go` (`JobCertificateDeploy`, `JobDeployRecover`), `internal/inventory/notify.go` (three templates, `Templates()`), `internal/inventory/errors.go` (Task 15 errors, `KeyTypeMismatchError`)
- Modify: `internal/jobs/types.go` (`CertificateDeploy`, `CertificateDeployRecover`, `DeploymentRecoverySweep`; `MaxAttemptsFor`)
- Modify: `locales/common/{en,tr}.json` (`email.deployment.failed|rollback_failed|needs_attention.subject|body`, exact contract texts)
- Test: `internal/inventory/deployments_integration_test.go`, `internal/jobs/types_test.go` (or the existing registry test file), `internal/notify/render_test.go` (the three templates render in EN and TR)

**Interfaces:**
- Consumes: Task 12 tables; Task 13 `GetLocation`, location columns; Task 14 `loadKey`; Task 2 `certs.KeyPEM`, `certs.SANMatches`; `Enqueuer.EnqueueTx`; `audit.Log.Append`; `Notifier.NotifyAdmins`.
- Produces: the Task 15 part of the inventory contract and the job types of the contract; `type KeyTypeMismatchError struct{ Expected, Actual string }` with `Error()` and `Is(target error) bool` (`errors.Is(err, ErrKeyTypeMismatch)`).

- [ ] **Step 1: Write the failing request tests**

Create `internal/inventory/deployments_integration_test.go`. Fixture `newDeployFixture(t)`: a harness with the nginx fake provider (`withNginxProvider()`), an Administrator and an Operator, two connected Nginx targets (`status ok`, facts with `Nginx.ConfigValid = true`) each with one location (`www.crt`/`www.key`, ECDSA leaf `old`) reconciled through `Reconcile`, and an uploaded ECDSA certificate `nw` with its key (`UploadCertificate`), its chain made complete by giving the harness `Config.Roots` the test CA root.

```go
func TestRequestDeploymentQueuesOneJobPerLocation(t *testing.T) {
	f := newDeployFixture(t)
	got, err := f.h.svc.RequestDeployment(f.h.ctx, f.operator, inventory.DeployRequestInput{CertificateID: f.cert.ID,
		LocationIDs: []uuid.UUID{f.loc1, f.loc2}})
	require.NoError(t, err)
	require.Len(t, got, 2)
	reqs := f.h.jobs.requests()
	require.Len(t, reqs, 2)
	assert.Equal(t, inventory.JobCertificateDeploy, reqs[0].Type)
	assert.Equal(t, map[string]string{"deployment_id": got[0].ID.String()}, reqs[0].Payload, "ids only, never key material")
	assert.Equal(t, "certificate.deploy:"+got[0].ID.String(), reqs[0].DedupeKey)
	d, err := f.h.svc.Deployment(f.h.ctx, got[0].ID)
	require.NoError(t, err)
	assert.Equal(t, inventory.DeployStateQueued, d.State)
	assert.Equal(t, inventory.DeployStatusPending, d.Status)
	assert.Equal(t, "/etc/nginx/ssl/www.crt", d.CertPath)
	assert.Equal(t, pki.Fingerprint(f.nw.Cert), d.NewFingerprint)
	assert.Equal(t, 2, f.h.audits("deployment.requested"))
}

func TestRequestDeploymentRefusals(t *testing.T) {
	f := newDeployFixture(t)
	ctx := f.h.ctx
	req := func(a inventory.Actor, cert uuid.UUID, confirm bool, locs ...uuid.UUID) error {
		_, err := f.h.svc.RequestDeployment(ctx, a, inventory.DeployRequestInput{CertificateID: cert, LocationIDs: locs, ConfirmIncompleteChain: confirm})
		return err
	}
	// F-15: one active deployment per location.
	require.NoError(t, req(f.operator, f.cert.ID, false, f.loc1))
	assert.ErrorIs(t, req(f.operator, f.cert.ID, false, f.loc1), inventory.ErrDeploymentInProgress)
	// A discovered certificate without its key.
	assert.ErrorIs(t, req(f.operator, f.discovered.ID, false, f.loc2), inventory.ErrNoPrivateKey)
	// F-19: expired.
	f.h.clock.Advance(400 * 24 * time.Hour)
	assert.ErrorIs(t, req(f.operator, f.cert.ID, false, f.loc2), inventory.ErrCertificateExpired)
	f.h.clock.Advance(-400 * 24 * time.Hour)
	// Key type: an RSA certificate into an ECDSA place.
	err := req(f.operator, f.rsaCert.ID, false, f.loc2)
	var kt *inventory.KeyTypeMismatchError
	require.ErrorAs(t, err, &kt)
	assert.Equal(t, inventory.KeyTypeMismatchError{Expected: "ecdsa", Actual: "rsa"}, *kt)
	// F-17: an incomplete chain needs an Administrator's confirmation.
	assert.ErrorIs(t, req(f.operator, f.incomplete.ID, true, f.loc2), inventory.ErrChainUnconfirmed, "an Operator's confirmation does not count")
	assert.ErrorIs(t, req(f.admin, f.incomplete.ID, false, f.loc2), inventory.ErrChainUnconfirmed)
	require.NoError(t, req(f.admin, f.incomplete.ID, true, f.loc2))
	// Unsupported, missing, not ready, invalid configuration, recovery pending.
	assert.ErrorIs(t, req(f.admin, f.cert.ID, false, f.unsupported), inventory.ErrLocationUnsupported)
	f.setTargetStatus(f.target2, "host_key_changed")
	assert.ErrorIs(t, req(f.admin, f.cert.ID, false, f.loc3onTarget2), inventory.ErrTargetNotReady)
	f.setTargetStatus(f.target2, "ok")
	f.setConfigValid(f.target2, false)
	assert.ErrorIs(t, req(f.admin, f.cert.ID, false, f.loc3onTarget2), inventory.ErrNginxConfigInvalid)
	f.setConfigValid(f.target2, true)
	f.markRecovering(f.target2)
	assert.ErrorIs(t, req(f.admin, f.cert.ID, false, f.loc3onTarget2), inventory.ErrRecoveryPending)
	// All or nothing: a refused location queues none of the others.
	before := len(f.h.jobs.requests())
	assert.Error(t, req(f.admin, f.cert.ID, false, f.loc3onTarget2, f.unsupported))
	assert.Len(t, f.h.jobs.requests(), before)
	var verrs validate.Errors
	require.ErrorAs(t, req(f.admin, f.cert.ID, false), &verrs, "no location")
	reasons := []string{}
	for _, d := range f.h.auditDetails("deployment.denied") {
		reasons = append(reasons, d["reason"])
	}
	assert.Subset(t, reasons, []string{"no_private_key", "expired", "key_type_mismatch", "chain_unconfirmed", "location_unsupported",
		"target_not_ready", "config_invalid", "recovery_pending"})
}

func TestRequestDeploymentWarnsAboutNames(t *testing.T) {
	// A certificate for other.example.test deployed to www.example.test is allowed with the warning "san_mismatch".
}
```

(Fixture helpers `setTargetStatus`, `setConfigValid` (updates `facts->nginx->config_valid` as the owner role), `markRecovering` (inserts a deployment of another location of the target in state `recovering`) are written in the test file; `f.unsupported` is a location reconciled with `UnsupportedVariable`; `f.loc3onTarget2` a second location on target 2; `f.discovered`, `f.rsaCert`, `f.incomplete` are certificates set up by the fixture — a discovered one without a key, an uploaded RSA one, and an uploaded one whose chain is not complete.)

```go
func TestDeploymentStateMachine(t *testing.T) {
	f := newDeployFixture(t)
	ctx := f.h.ctx
	got, err := f.h.svc.RequestDeployment(ctx, f.admin, inventory.DeployRequestInput{CertificateID: f.cert.ID, LocationIDs: []uuid.UUID{f.loc1}})
	require.NoError(t, err)
	id := got[0].ID
	d, err := f.h.svc.BeginDeployment(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, inventory.DeployStatePrecheck, d.State)
	m, err := f.h.svc.DeploymentMaterial(ctx, id, true)
	require.NoError(t, err)
	assert.Contains(t, string(m.PrivateKeyPEM.Bytes()), "PRIVATE KEY")
	assert.Equal(t, "/etc/nginx/ssl/www.key", m.Location.KeyPath)
	assert.Equal(t, pki.Fingerprint(f.old.Cert), m.CurrentFingerprint)
	assert.Equal(t, sha(f.old.FullchainPEM), m.ExpectCertSHA256)
	assert.True(t, m.ConfigValid)
	m.PrivateKeyPEM.Zero()
	m2, err := f.h.svc.DeploymentMaterial(ctx, id, false)
	require.NoError(t, err)
	assert.Empty(t, m2.PrivateKeyPEM.Bytes())

	require.NoError(t, f.h.svc.StartDeployment(ctx, id, pki.Fingerprint(f.old.Cert), providers.BackupRef{OperationID: id}))
	require.NoError(t, f.h.svc.RecordDeploymentStep(ctx, id, "backup", providers.StepOK, nil))
	require.NoError(t, f.h.svc.RecordDeploymentStep(ctx, id, "write_key", providers.StepOK, nil))
	require.NoError(t, f.h.svc.FinishDeployment(ctx, id, inventory.DeploymentFinish{Status: inventory.DeployStatusSucceeded, Verified: "remote",
		Backup: &providers.BackupRef{OperationID: id, Dir: "/var/lib/alice-helper/backups/" + id.String()}}))
	require.NoError(t, f.h.svc.FinishDeployment(ctx, id, inventory.DeploymentFinish{Status: inventory.DeployStatusFailed}), "a second finish changes nothing")
	d, err = f.h.svc.Deployment(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, inventory.DeployStateDone, d.State)
	assert.Equal(t, inventory.DeployStatusSucceeded, d.Status)
	assert.Equal(t, []string{"backup:ok", "write_key:ok"}, stepNames(d.Steps))
	loc, err := f.h.svc.GetLocation(ctx, f.loc1)
	require.NoError(t, err)
	assert.Equal(t, pki.Fingerprint(f.nw.Cert), loc.DeployedFingerprint, "a later discovery of this leaf is not 'changed outside Alice'")
	assert.Equal(t, 1, f.h.audits("deployment.succeeded"))
}

// L-82 wording: a rolled-back deployment shows the failure and the rollback.
func TestFinishDeploymentAuditsAndEmails(t *testing.T) {
	// rolled_back → audits deployment.failed (reason, failed_step) and deployment.rolled_back; email deployment.failed to every Administrator.
	// rollback_failed → audits deployment.rollback_failed; email deployment.rollback_failed with backup_dir.
	// failed (nothing changed) → audit deployment.failed; email deployment.failed.
	// unchanged → audit deployment.unchanged; no email.
	// Emails are rows of notifications_outbox with template and params (assert the params map exactly).
}

func TestMarkRecoveringEmailsOnce(t *testing.T) {
	// MarkRecovering(id, t1, false) → state recovering, status running, recover_after t1, no email;
	// MarkRecovering(id, t2, true) twice → status needs_attention, one deployment.needs_attention email and one audit row.
}

func TestSweepDeployments(t *testing.T) {
	// Seeds (as the owner role): A — state deploying, its deploy job dead, recover_after NULL;
	// B — state recovering, recover_after in the future; C — state deploying, its job running;
	// D — state queued, its job dead with last_error_code ssh.unreachable; E — state queued, its job blocked_license.
	// SweepDeployments → 1 recovery requested (A: recover job queued with dedupe certificate.deploy_recover:<A>, state recovering,
	// recover_after now+15m), D finished failed with error_code ssh.unreachable, B/C/E untouched; returns 2.
	// Running it again at once requests nothing new (A's recover_after is in the future).
}

func TestListDeploymentsAndDetail(t *testing.T) {
	// Three deployments over two targets; filters target_id, certificate_id, location_id; newest first; cursor paging with limit 2;
	// Deployment(id) carries Steps in order and RequestedByName; an unknown id is ErrNotFound.
}
```

Write the five commented tests out in full from their comments.

Run: `go test -tags integration ./internal/inventory -run 'Deployment|Sweep|MarkRecovering' -count=1` (Docker)
Expected: FAIL.

- [ ] **Step 2: Implement**

`jobs.go`: add `JobCertificateDeploy = "certificate.deploy"` and `JobDeployRecover = "certificate.deploy_recover"`. `internal/jobs/types.go`:

```go
// Phase 4 job types (spec §8.2, §8.6, §8.7): a deployment changes a server (refused and paused in
// lock); finishing or undoing an interrupted one is never blocked (L-82, R38 item 8); the sweep
// that finds them runs in every state.
var (
	CertificateDeploy        = Register(inventory.JobCertificateDeploy, license.ClassChange)
	CertificateDeployRecover = Register(inventory.JobDeployRecover, license.ClassAlways)
	DeploymentRecoverySweep  = Register("deployment.recovery_sweep", license.ClassAlways)
)
```

and in `MaxAttemptsFor`: `case inventory.JobCertificateDeploy: return 3`, `case inventory.JobDeployRecover: return 5`. Add a registry test asserting the three classes.

`notify.go`: the three template constants; `Templates()` returns all five.

`deployments.go`, behaviour by function (SQL uses the injected clock's time as a bind parameter):
- `RequestDeployment(ctx, a, in)`: `validate.Errors` for `location_ids` (1..20, `validate.OutOfRange` `{"min":"1","max":"20"}`; duplicates `validate.Pattern`). One transaction: load the certificate (`ErrNotFound`); refusals in this order, each audited `deployment.denied` (result `denied`, details `certificate_id`, `location_id` when known, `reason`) in a detached transaction after the rollback: no private key → `ErrNoPrivateKey` (`no_private_key`); `!now.Before(not_after)` → `ErrCertificateExpired` (`expired`); `!chain_complete && !(in.ConfirmIncompleteChain && a.Role == rbac.Admin)` → `ErrChainUnconfirmed` (`chain_unconfirmed`). Then lock the targets of the locations in id order (`getTarget(…, true)`), then the locations (`SELECT … FROM certificate_locations WHERE id = ANY($1) ORDER BY id FOR UPDATE`); for each location: absent, target deleted → `ErrNotFound`; `missing_since` set or `!supported` → `ErrLocationUnsupported` (`location_unsupported`); target type not `nginx` → `ErrLocationUnsupported`; target status not in `ok`, `unreachable`, `checking` → `ErrTargetNotReady` (`target_not_ready`); `facts.nginx` absent or `!config_valid` → `ErrNginxConfigInvalid` (`config_invalid`); `key_type != ""` and `!= certificate key_algorithm` → `&KeyTypeMismatchError{Expected: key_type, Actual: algorithm}` (`key_type_mismatch`); a deployment of the same target in state `recovering` → `ErrRecoveryPending` (`recovery_pending`). Insert the deployment (`state queued`, `status pending`, `trigger manual`, `requested_by`, the location's `cert_path`/`key_path`, `new_fingerprint`, `confirm_incomplete_chain`); a unique violation of `deployments_one_active` → `ErrDeploymentInProgress` (`in_progress`). `EnqueueTx` a `certificate.deploy` job (`TargetID` the target, `Kind` `a.jobKind()`, `CreatedBy`, `CreatedByRole`, `Payload {"deployment_id"}`, `DedupeKey "certificate.deploy:<id>"`), `UPDATE deployments SET job_id`; warnings: `san_mismatch` when a server name of the location (not `_`, not empty, not a regex) is not matched by the certificate's SANs (`certs.SANMatches`); audit `deployment.requested`.
- `Deployment(ctx, id)`, `ListDeployments(ctx, f)`: rows joined with the certificate (`CertificateName` = label, else subject CN, else the first 16 hex of the fingerprint), the target (`TargetName`), the requester (`RequestedByName` = display name, empty for none); `ListDeployments` orders by `created_at DESC, id DESC` with a keyset cursor (base64 `created_at|id`), limit 1..200 default 50; `Deployment` adds `Steps` ordered by `n`. `Backup` decodes `rollback_info`.
- `DeploymentMaterial(ctx, id, withKey)`: the deployment, its location (columns → `providers.CertLocation`: `CertPath`, `KeyPath`, `Servers` from `servers`, `Supported`, `Symlinked`, `CustomLocation`), the certificate (`pem_chain` → `CertificatePEM`, `Fingerprint`, `SANs`, `NotAfter`, `KeyType` = `key_algorithm`), the location's current certificate (`CurrentFingerprint`, `OldSANs`), `ExpectCertSHA256 = cert_file_sha256`, `Verify` from `verify_port`/`verify_sni`/`skip_verify`, `ConfigValid` from the target facts. With `withKey`: `loadKey` of the certificate's `private_key_id` → `certs.KeyPEM` (the DER is zeroed at once); no key → `ErrNoPrivateKey`.
- `BeginDeployment`: `UPDATE deployments SET state = 'precheck', status = 'running', started_at = coalesce(started_at, $2) WHERE id = $1 AND state IN ('queued', 'precheck') RETURNING …`; zero rows → return the current row unchanged.
- `StartDeployment`: `UPDATE … SET state = 'deploying', previous_fingerprint = $2, rollback_info = $3 WHERE id = $1 AND state = 'precheck'`; zero rows → `ErrNotFound`.
- `RecordDeploymentStep`: `INSERT INTO deployment_steps (id, deployment_id, n, name, status, at, params) SELECT $1, $2, coalesce(max(n), 0) + 1, $3, $4, $5, $6 FROM deployment_steps WHERE deployment_id = $2`; on a unique violation (two writers) retry once; params are allowlisted string maps (keys `error`, `port`, `mode`, `served`; others dropped).
- `FinishDeployment(ctx, id, f)`: one transaction, row lock; already `done` → no-op; `state = 'done'`, `status = f.Status`, `error_code`, `error_params`, `failed_step`, `verified`, `rollback_info` (when `f.Backup != nil`), `finished_at`, `recover_after = NULL`; for `succeeded`/`unchanged`: `UPDATE certificate_locations SET deployed_fingerprint = $2, changed_outside_at = NULL WHERE id = $1`. Audits (actor `jobs`, object `deployment`): `succeeded` → `deployment.succeeded` (`new_fingerprint`, `previous_fingerprint`, `verified`); `unchanged` → `deployment.unchanged`; `failed` → `deployment.failed` (`reason`, `failed_step`); `rolled_back` → `deployment.failed` then `deployment.rolled_back` (`reason`); `rollback_failed` → `deployment.rollback_failed` (`reason`, `failed_step`). Emails (inside the transaction, through `Notifier`): `failed`, `rolled_back` → `deployment.failed`; `rollback_failed` → `deployment.rollback_failed` with `backup_dir` = `f.Backup.Dir` or `/var/lib/alice-helper/backups/<id>`.
- `MarkRecovering(ctx, id, retryAt, needsAttention)`: `state = 'recovering'`, `status = 'needs_attention'` or `'running'`, `recover_after = retryAt`, only for unfinished rows; the first transition to `needs_attention` audits `deployment.needs_attention` and emails `deployment.needs_attention`.
- `RequestRecovery(ctx, id)`: `EnqueueTx` a `certificate.deploy_recover` job (`Kind system`, payload `{"deployment_id"}`, dedupe `certificate.deploy_recover:<id>`, the deployment's target), audit `deployment.recovery_started`.

`sweep.go`, `SweepDeployments(ctx)` — one transaction, at most 100 rows each (`FOR UPDATE OF d SKIP LOCKED`):
1. `state IN ('deploying', 'recovering') AND (recover_after IS NULL OR recover_after <= $now) AND NOT EXISTS (SELECT 1 FROM jobs j WHERE j.id = d.job_id AND j.status = 'running') AND NOT EXISTS (SELECT 1 FROM jobs r WHERE r.dedupe_key = 'certificate.deploy_recover:' || d.id::text AND r.status IN ('queued', 'running'))` → `state = 'recovering'`, `recover_after = $now + 15 minutes`, queue the recovery as `RequestRecovery` does (same transaction).
2. `state IN ('queued', 'precheck') AND (job_id IS NULL OR EXISTS (SELECT 1 FROM jobs j WHERE j.id = d.job_id AND j.status IN ('failed', 'dead', 'cancelled')))` → finish `failed` with `error_code` = the job's `last_error_code` or `deployment.interrupted` (nothing was changed before `deploying`), audited as `FinishDeployment` does, without an email when the code is `license.locked`.
Returns the number of rows handled.

`locales/common/{en,tr}.json`: `email.deployment.failed|rollback_failed|needs_attention` with `subject` and `body` from the contract; `internal/notify/render_test.go` renders every template of `inventory.Templates()` in both languages with all params (it already iterates `Templates()`; check that it does and that no `{{` survives).

Run the Step 1 command and `go test ./internal/jobs ./internal/notify -count=1` → PASS.

- [ ] **Step 3: Commit**

```bash
git add internal/inventory internal/jobs/types.go internal/jobs locales/common internal/notify
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "feat(inventory): deployment requests, records, recovery sweep and failure emails

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 16: Deploy engine — `certificate.deploy` and `certificate.deploy_recover` handlers; F-66, L-80..L-82

The handlers that connect a deployment record to a server (spec §12.6, §8.7, §8.8). `certificate.deploy`: precheck (the material, expiry and configuration again at run time, the served certificate before the change — refusing a website Alice cannot check or that serves something other than its file: F-06, F-07 before any change), then `StartDeployment` (the backup reference is persisted before the first mutation, §6.3 item 3), `DeployCertificate`, and the outcome; an uncertain outcome goes to recovery at once. A deploy job that runs again (after a crash, a lost lease) never deploys again: it recovers. `certificate.deploy_recover` reads the helper journal (`DeploymentStatus`) and ends with the new certificate verified or the old one restored; it is `ClassAlways`, so a rollback is never blocked by the license (L-82).

**Files:**
- Create: `internal/jobs/deployjobs/deployjobs.go`, `internal/jobs/deployjobs/recover.go`
- Test: `internal/jobs/deployjobs/deployjobs_test.go` (fakes), `internal/jobs/deployjobs/deployjobs_integration_test.go` (real queue, runner, inventory, the emulated Nginx over the fake SSH server), `internal/jobs/deployjobs/crash_integration_test.go` (F-66 with a killed child process)

**Interfaces:**
- Consumes: Task 15 inventory deployment functions and job types; Task 8 provider types; Task 11 the `nginx` provider (integration tests); `jobs.Runner`, `jobs.Job`, `jobs.Retry/Fail/Attention`, `jobs.StepRecorder`.
- Produces: `deployjobs.Register(r *jobs.Runner, d Deps)`, `deployjobs.Deps`, `deployjobs.Inventory` (contract).

- [ ] **Step 1: Write the failing unit tests**

`deployjobs_test.go` uses a fake `Inventory` (records calls; returns configured `Deployment` and `Material`; `Material.PrivateKeyPEM` a `secrets.Plaintext` the test keeps to assert it was zeroed) and a `fake` provider of kind `nginx` (Task 8) registered in a registry:

```go
func TestDeploySucceeds(t *testing.T) {
	f := newFixture(t)
	res, err := f.h.deploy(f.ctx, f.job(), f.steps)
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"outcome": "succeeded", "verified": "remote"}, res)
	assert.Equal(t, []string{"Deployment", "BeginDeployment", "DeploymentMaterial", "StartDeployment", "FinishDeployment"}, f.inv.calls())
	assert.Equal(t, inventory.DeploymentFinish{Status: inventory.DeployStatusSucceeded, Verified: "remote",
		Backup: &providers.BackupRef{OperationID: f.id}}, f.inv.finish)
	assert.Equal(t, f.current, f.inv.startedWith, "the served certificate before the change is stored before the first mutation")
	assert.Equal(t, []string{"verify_current:started", "verify_current:ok", "backup:ok", "write_key:ok", "write_cert:ok", "config_test:ok",
		"reload:ok", "verify:ok"}, f.inv.stepNames())
	assert.Equal(t, make([]byte, len(f.key)), f.material.PrivateKeyPEM.Bytes(), "the key is zeroed after use")
}

func TestDeployPrecheckRefusalsChangeNothing(t *testing.T) {
	for _, tc := range []struct {
		name   string
		setup  func(f *fixture)
		reason string
	}{
		{"F-19 expired at run time", func(f *fixture) { f.material.NotAfter = f.now.Add(-time.Minute) }, "certificate.expired"},
		{"configuration invalid", func(f *fixture) { f.material.ConfigValid = false }, "nginx.config_invalid"},
		{"F-07 cannot be checked", func(f *fixture) { f.verify = providers.VerifyResult{Reason: "deployment.verify_unreachable", Params: map[string]string{"port": "443"}} },
			"deployment.verify_unreachable"},
		{"F-06 something else answers", func(f *fixture) { f.verify = providers.VerifyResult{OK: true, Mode: "remote", Served: strings.Repeat("c", 64)} },
			"deployment.verify_other"},
		{"host key changed", func(f *fixture) { f.target.Status = inventory.StatusHostKeyChanged }, "target.host_key_changed"},
		{"F-14 helper outdated", func(f *fixture) { f.openErr = providers.NewError("ssh.helper_outdated", false, nil, nil) }, "ssh.helper_outdated"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			tc.setup(f)
			_, err := f.h.deploy(f.ctx, f.job(), f.steps)
			var jf *jobs.Failure
			require.ErrorAs(t, err, &jf)
			assert.Equal(t, jobs.Permanent, jf.Class)
			assert.Equal(t, tc.reason, jf.Reason)
			assert.NotContains(t, f.inv.calls(), "StartDeployment", "nothing was changed")
			assert.Zero(t, f.prov.Count("DeployCertificate"))
			assert.Equal(t, inventory.DeployStatusFailed, f.inv.finish.Status)
		})
	}
}

func TestDeployRetriesAConnectionFailureBeforeAnyChange(t *testing.T) {
	f := newFixture(t)
	f.openErr = providers.NewError("ssh.unreachable", true, nil, nil)
	_, err := f.h.deploy(f.ctx, f.job(), f.steps) // attempt 1 of 3
	var jf *jobs.Failure
	require.ErrorAs(t, err, &jf)
	assert.Equal(t, jobs.Retryable, jf.Class)
	assert.NotContains(t, f.inv.calls(), "FinishDeployment", "the deployment stays in precheck")
	j := f.job()
	j.Attempt = 3
	_, err = f.h.deploy(f.ctx, j, f.steps)
	require.ErrorAs(t, err, &jf)
	assert.Equal(t, jobs.Permanent, jf.Class)
	assert.Equal(t, inventory.DeployStatusFailed, f.inv.finish.Status)
}

func TestDeployOutcomes(t *testing.T) {
	for _, tc := range []struct {
		out    providers.DeployOutcome
		status string
		class  jobs.FailureClass // -1 = success
	}{
		{providers.DeployOutcome{Result: providers.DeployUnchanged, Verified: "local"}, inventory.DeployStatusUnchanged, -1},
		{providers.DeployOutcome{Result: providers.DeployNoChange, Reason: "nginx.no_space"}, inventory.DeployStatusFailed, jobs.Permanent},
		{providers.DeployOutcome{Result: providers.DeployRolledBack, Reason: "certificate.key_mismatch", FailedStep: "config_test"}, inventory.DeployStatusRolledBack, jobs.Permanent},
		{providers.DeployOutcome{Result: providers.DeployRollbackFailed, Reason: "deployment.rollback_reload_failed", FailedStep: "rollback_reload"},
			inventory.DeployStatusRollbackFailed, jobs.NeedsAttention},
	} {
		f := newFixture(t)
		f.prov.Configure(func(c *fake.Config) { c.Deploy = func(providers.DeployRequest) (providers.DeployOutcome, error) { return tc.out, nil } })
		_, err := f.h.deploy(f.ctx, f.job(), f.steps)
		assert.Equal(t, tc.status, f.inv.finish.Status)
		assert.Equal(t, tc.out.Reason, f.inv.finish.ErrorCode)
		assert.Equal(t, tc.out.FailedStep, f.inv.finish.FailedStep)
		if tc.class < 0 {
			assert.NoError(t, err)
			continue
		}
		var jf *jobs.Failure
		require.ErrorAs(t, err, &jf)
		assert.Equal(t, tc.class, jf.Class)
	}
}

func TestUncertainOutcomeStartsRecovery(t *testing.T) {
	f := newFixture(t)
	f.prov.Configure(func(c *fake.Config) {
		c.Deploy = func(providers.DeployRequest) (providers.DeployOutcome, error) {
			return providers.DeployOutcome{Result: providers.DeployUncertain}, providers.NewError("ssh.unreachable", true, nil, nil)
		}
	})
	_, err := f.h.deploy(f.ctx, f.job(), f.steps)
	var jf *jobs.Failure
	require.ErrorAs(t, err, &jf)
	assert.Equal(t, jobs.NeedsAttention, jf.Class)
	assert.Equal(t, "deployment.interrupted", jf.Reason)
	assert.Equal(t, []string{"MarkRecovering(false)", "RequestRecovery"}, f.inv.recoveryCalls())
	assert.NotContains(t, f.inv.calls(), "FinishDeployment")
}

// §8.8: a deploy job that runs again after a crash never deploys again.
func TestRerunAfterACrashRecoversInsteadOfDeploying(t *testing.T) {
	f := newFixture(t)
	f.deployment.State = inventory.DeployStateDeploying
	f.status = providers.DeploymentState{Phase: providers.PhaseCommitted}
	res, err := f.h.deploy(f.ctx, f.job(), f.steps)
	require.NoError(t, err)
	assert.Equal(t, "succeeded", res["outcome"])
	assert.Zero(t, f.prov.Count("DeployCertificate"))
	assert.Equal(t, 1, f.prov.Count("DeploymentStatus"))
}

func TestRecoveryDecisions(t *testing.T) {
	for _, tc := range []struct {
		phase    string
		active   bool
		verifyOK bool
		status   string // "" = retried
		rollback bool
	}{
		{providers.PhaseNone, false, false, inventory.DeployStatusFailed, false},
		{providers.PhasePrepared, false, false, inventory.DeployStatusFailed, false},
		{providers.PhaseCommitted, false, true, inventory.DeployStatusSucceeded, false},
		{providers.PhaseCommitted, false, false, inventory.DeployStatusRolledBack, true},
		{providers.PhaseUnchanged, false, true, inventory.DeployStatusUnchanged, false},
		{providers.PhaseWriting, false, false, inventory.DeployStatusRolledBack, true},
		{providers.PhaseRestoring, false, false, inventory.DeployStatusRolledBack, true},
		{providers.PhaseRestored, false, false, inventory.DeployStatusRolledBack, true},
		{providers.PhaseRestoreFailed, false, false, inventory.DeployStatusRollbackFailed, false},
		{providers.PhaseWriting, true, false, "", false},
	} {
		f := newFixture(t)
		f.deployment.State = inventory.DeployStateRecovering
		f.status = providers.DeploymentState{Phase: tc.phase, Active: tc.active}
		f.verifyOK(tc.verifyOK)
		_, _ = f.h.recoverJob(f.ctx, f.recoverJob(), f.steps)
		assert.Equal(t, tc.status, f.inv.finish.Status, tc.phase)
		assert.Equal(t, tc.rollback, f.prov.Count("RollbackDeployment") == 1, tc.phase)
	}
}

func TestRecoveryUnreachableRetriesThenNeedsAttention(t *testing.T) {
	f := newFixture(t)
	f.deployment.State = inventory.DeployStateRecovering
	f.openErr = providers.NewError("ssh.unreachable", true, nil, nil)
	_, err := f.h.recoverJob(f.ctx, f.recoverJob(), f.steps)
	var jf *jobs.Failure
	require.ErrorAs(t, err, &jf)
	assert.Equal(t, jobs.Retryable, jf.Class)
	assert.Equal(t, []string{"MarkRecovering(false)"}, f.inv.recoveryCalls())
	j := f.recoverJob()
	j.Attempt = j.MaxAttempts
	_, err = f.h.recoverJob(f.ctx, j, f.steps)
	require.ErrorAs(t, err, &jf)
	assert.Equal(t, jobs.NeedsAttention, jf.Class, "no job.dead email per retry")
	assert.Equal(t, []string{"MarkRecovering(false)", "MarkRecovering(true)"}, f.inv.recoveryCalls())
}
```

Run: `go test ./internal/jobs/deployjobs -count=1`
Expected: FAIL (no package).

- [ ] **Step 2: Implement the handlers**

`deployjobs.go`:

```go
// Package deployjobs runs certificate deployments (spec §12.6) and their recovery (§8.8).
package deployjobs

// Register registers the deploy and recovery handlers.
func Register(r *jobs.Runner, d Deps) {
	h := newHandlers(d)
	r.Handle(jobs.CertificateDeploy, h.deploy)
	r.Handle(jobs.CertificateDeployRecover, h.recoverJob)
}

type handlers struct{ d Deps }

func newHandlers(d Deps) *handlers {
	if d.Log == nil {
		d.Log = slog.New(slog.DiscardHandler)
	}
	if d.FirstRecovery <= 0 {
		d.FirstRecovery = 10 * time.Second
	}
	if d.RetryRecovery <= 0 {
		d.RetryRecovery = 15 * time.Minute
	}
	return &handlers{d: d}
}

func (h *handlers) deploy(ctx context.Context, j jobs.Job, steps jobs.StepRecorder) (map[string]any, error) {
	id, err := uuid.Parse(j.Payload["deployment_id"])
	if err != nil {
		return nil, jobs.Fail("system.not_found", nil, err)
	}
	d, err := h.d.Inventory.Deployment(ctx, id)
	switch {
	case errors.Is(err, inventory.ErrNotFound):
		return nil, jobs.Fail("system.not_found", nil, err)
	case err != nil:
		return nil, jobs.Retry("internal.unexpected", nil, err)
	}
	switch d.State {
	case inventory.DeployStateDone:
		return resultOf(d)
	case inventory.DeployStateDeploying, inventory.DeployStateRecovering:
		return h.recoverDeployment(ctx, j, d, steps) // never deploy blindly again (§8.4, §8.8)
	}
	if _, err := h.d.Inventory.BeginDeployment(ctx, id); err != nil {
		return nil, jobs.Retry("internal.unexpected", nil, err)
	}
	m, err := h.d.Inventory.DeploymentMaterial(ctx, id, true)
	if err != nil {
		reason, _ := reasonOf(err)
		return h.noChange(ctx, d, reason, nil)
	}
	defer m.PrivateKeyPEM.Zero()
	switch {
	case !h.d.Clock.Now().Before(m.NotAfter):
		return h.noChange(ctx, d, "certificate.expired", nil) // F-19, also at run time
	case !m.ConfigValid:
		return h.noChange(ctx, d, "nginx.config_invalid", nil)
	}
	sess, err := h.open(ctx, d.TargetID)
	if err != nil {
		return h.beforeChange(ctx, j, d, err)
	}
	defer h.close(sess)
	rec := &recorder{inv: h.d.Inventory, id: id, next: steps, log: h.d.Log}
	prev := ""
	if !m.Verify.Skip {
		rec.Step("verify_current", providers.StepStarted, nil)
		vr, err := sess.VerifyDeployment(ctx, providers.VerifyRequest{Location: m.Location, SANs: m.OldSANs, KeyType: m.KeyType, Verify: m.Verify})
		if err != nil {
			rec.Step("verify_current", providers.StepFailed, nil)
			return h.beforeChange(ctx, j, d, err)
		}
		if !vr.OK {
			rec.Step("verify_current", providers.StepFailed, vr.Params)
			return h.noChange(ctx, d, vr.Reason, vr.Params) // F-07: nothing is changed on a website Alice cannot check
		}
		if m.CurrentFingerprint != "" && vr.Served != m.CurrentFingerprint && vr.Served != m.Fingerprint {
			rec.Step("verify_current", providers.StepFailed, nil)
			return h.noChange(ctx, d, "deployment.verify_other", nil) // F-06: something other than this file answers
		}
		rec.Step("verify_current", providers.StepOK, map[string]string{"mode": vr.Mode})
		prev = vr.Served
	}
	if err := h.d.Inventory.StartDeployment(ctx, id, prev, providers.BackupRef{OperationID: id}); err != nil {
		return nil, jobs.Retry("internal.unexpected", nil, err)
	}
	out, err := sess.DeployCertificate(ctx, providers.DeployRequest{OperationID: id, Location: m.Location, ExpectCertSHA256: m.ExpectCertSHA256,
		CertificatePEM: m.CertificatePEM, PrivateKeyPEM: m.PrivateKeyPEM, Fingerprint: m.Fingerprint, SANs: m.SANs, KeyType: m.KeyType,
		OldFingerprint: prev, OldSANs: m.OldSANs, Verify: m.Verify}, rec)
	if err != nil || out.Result == providers.DeployUncertain {
		return h.uncertain(ctx, d, err)
	}
	return h.finish(ctx, d, out)
}
```

Helpers in the same file:
- `open(ctx, target)`: as `targetjobs.open` with `needConfirmed` (refuse `host_key_changed` → `jobs.Fail("target.host_key_changed")`, `pending_host_key` → `target.host_key_unconfirmed`, `disabled` → `target.disabled`, deleted → `system.not_found`), the provider of the target's kind, `Env{Clock, HostKeys, Log}`; a provider failure is recorded on the target (`RecordConnectionFailure`) and returned classified (`jobs.FromProvider`).
- `beforeChange(ctx, j, d, err)`: a `Retryable` failure with `j.Attempt < j.MaxAttempts` is returned as is (the deployment stays in `precheck`); otherwise `noChange` with its reason.
- `noChange(ctx, d, reason, params)`: `FinishDeployment{Status: failed, ErrorCode: reason, Params: params}`; returns `map{"outcome": "failed"}` and `jobs.Fail(reason, params, nil)`. A `FinishDeployment` error → `jobs.Retry("internal.unexpected")` (nothing was changed; a retry is safe).
- `uncertain(ctx, d, err)`: `MarkRecovering(id, now + FirstRecovery, false)`, `RequestRecovery(id)` (errors logged by type only); returns `map{"outcome": "uncertain"}` and `jobs.Attention("deployment.interrupted", nil, err)`.
- `finish(ctx, d, out)`: `committed` → `succeeded`; `unchanged` → `unchanged`; `no_change` → `failed`; `rolled_back` → `rolled_back`; `rollback_failed` → `rollback_failed`; `FinishDeployment` with `ErrorCode = out.Reason`, `Params`, `FailedStep`, `Verified`, `Backup = &out.Backup`; for `rollback_failed` the params always carry `backup_dir` (`out.Backup.Dir`, else `/var/lib/alice-helper/backups/<id>`) because ALC-DEP-0008's text names it; returns `map{"outcome": status, "verified": out.Verified}` and nil for the first two, `jobs.Fail(reason)` for `failed`/`rolled_back`, `jobs.Attention(reason)` for `rollback_failed`. A `FinishDeployment` error after a remote change → `jobs.Retry("internal.unexpected")`: the next attempt finds the deployment in `deploying` and recovers (idempotent).
- `resultOf(d)`: a finished deployment answers its stored outcome the same way (`succeeded`/`unchanged` → success; others → their failure class).
- `recorder`: implements `providers.StepLogger`; forwards to the job's `StepRecorder` and persists with `RecordDeploymentStep` (an error is logged with its type only and does not stop the deployment).
- `reasonOf(err)`: `*jobs.Failure` → its reason; `*providers.Error` → its code; inventory sentinels → `certificate.no_private_key` (`ErrNoPrivateKey`), `system.not_found` (`ErrNotFound`); otherwise `internal.unexpected`.

`recover.go`:

```go
func (h *handlers) recoverJob(ctx context.Context, j jobs.Job, steps jobs.StepRecorder) (map[string]any, error) {
	id, err := uuid.Parse(j.Payload["deployment_id"])
	if err != nil {
		return nil, jobs.Fail("system.not_found", nil, err)
	}
	d, err := h.d.Inventory.Deployment(ctx, id)
	switch {
	case errors.Is(err, inventory.ErrNotFound):
		return nil, jobs.Fail("system.not_found", nil, err)
	case err != nil:
		return nil, jobs.Retry("internal.unexpected", nil, err)
	case d.State == inventory.DeployStateDone:
		return map[string]any{"outcome": d.Status}, nil // finished meanwhile: nothing to recover
	}
	return h.recoverDeployment(ctx, j, d, steps)
}

// recoverDeployment ends an interrupted deployment from the helper's journal (§8.8): the new
// certificate live and verified, or the old one restored; never a deploy.
func (h *handlers) recoverDeployment(ctx context.Context, j jobs.Job, d inventory.Deployment, steps jobs.StepRecorder) (map[string]any, error) {
	m, err := h.d.Inventory.DeploymentMaterial(ctx, d.ID, false)
	if err != nil {
		return nil, jobs.Retry("internal.unexpected", nil, err)
	}
	sess, err := h.open(ctx, d.TargetID)
	if err != nil {
		return h.unreachable(ctx, j, d, err)
	}
	defer h.close(sess)
	st, err := sess.DeploymentStatus(ctx, d.ID)
	if err != nil {
		return h.unreachable(ctx, j, d, err)
	}
	if st.Active {
		return nil, jobs.Retry("nginx.busy", nil, nil) // the helper is still running the transaction
	}
	rec := &recorder{inv: h.d.Inventory, id: d.ID, next: steps, log: h.d.Log}
	backup := &providers.BackupRef{OperationID: d.ID, Dir: st.BackupDir}
	rb := providers.RollbackRequest{OperationID: d.ID, Location: m.Location, OldFingerprint: d.PreviousFingerprint, OldSANs: m.OldSANs,
		KeyType: m.KeyType, Verify: m.Verify}
	rollback := func(reason string) (map[string]any, error) {
		out, err := sess.RollbackDeployment(ctx, rb, rec)
		if err != nil {
			return h.unreachable(ctx, j, d, err)
		}
		switch out.Result {
		case providers.DeployRolledBack, providers.DeployNoChange:
			return h.finish(ctx, d, providers.DeployOutcome{Result: providers.DeployRolledBack, Reason: reason, Verified: out.Verified, Backup: *backup})
		default:
			return h.finish(ctx, d, providers.DeployOutcome{Result: providers.DeployRollbackFailed, Reason: out.Reason, Backup: *backup})
		}
	}
	switch st.Phase {
	case providers.PhaseNone, providers.PhasePrepared:
		return h.finish(ctx, d, providers.DeployOutcome{Result: providers.DeployNoChange, Reason: "deployment.interrupted"})
	case providers.PhaseRestoreFailed:
		return h.finish(ctx, d, providers.DeployOutcome{Result: providers.DeployRollbackFailed, Reason: "deployment.rollback_failed", Backup: *backup})
	case providers.PhaseCommitted, providers.PhaseUnchanged:
		vr, err := sess.VerifyDeployment(ctx, providers.VerifyRequest{Location: m.Location, Fingerprint: d.NewFingerprint,
			PreviousFingerprint: d.PreviousFingerprint, SANs: m.SANs, KeyType: m.KeyType, Verify: m.Verify})
		if err != nil {
			return h.unreachable(ctx, j, d, err)
		}
		if vr.OK {
			result := providers.DeployCommitted
			if st.Phase == providers.PhaseUnchanged {
				result = providers.DeployUnchanged
			}
			return h.finish(ctx, d, providers.DeployOutcome{Result: result, Verified: vr.Mode, Backup: *backup})
		}
		return rollback(vr.Reason)
	default: // writing, restoring, restored: put the old files back (idempotent) and check them
		return rollback("deployment.interrupted")
	}
}

// unreachable: a recovery that cannot reach the server retries; after its last attempt the
// deployment needs attention (one email) and the sweep tries again every RetryRecovery.
func (h *handlers) unreachable(ctx context.Context, j jobs.Job, d inventory.Deployment, err error) (map[string]any, error) {
	reason, params := reasonOf(err)
	last := j.Attempt >= j.MaxAttempts
	retryAt := h.d.Clock.Now().Add(jobs.Backoff(j.Attempt, 0))
	if last {
		retryAt = h.d.Clock.Now().Add(h.d.RetryRecovery)
	}
	if merr := h.d.Inventory.MarkRecovering(context.WithoutCancel(ctx), d.ID, retryAt, last); merr != nil {
		h.d.Log.Error("could not record a deployment recovery", "deployment_id", d.ID.String(), "error_type", fmt.Sprintf("%T", merr))
	}
	if last {
		return nil, jobs.Attention(reason, params, err)
	}
	return nil, jobs.Retry(reason, params, err)
}
```

(`jobs.Backoff(attempt, jitter)` is the runner's exported backoff; with `jitter` 0 it is the base delay.)

Run: `go test ./internal/jobs/deployjobs -count=1` → PASS.

- [ ] **Step 3: Integration and lock tests**

`deployjobs_integration_test.go` (`//go:build integration`): a real database (`pgtest`), `audit`, a `license` service with a test license (`licensetest`), `jobs.Queue`, `jobs.Runner` with `RunOnce`, `inventory.Service` with the real `nginx` provider over a `linuxsshtest.Server` + emulator (as Task 10's fixture), `deployjobs.Register` and `targetjobs.Register`. Tests:
- `TestDeployJourneyThroughTheQueue`: an Nginx target is added, its host key confirmed, the connection test and discovery run (`RunOnce` until no job), a certificate is uploaded, `RequestDeployment` → `RunOnce` → the deployment is `succeeded` (verified `remote`), its steps are `verify_current`, `backup`, `write_key`, `write_cert`, `config_test`, `reload`, `verify` (`started`/`ok` as reported), the location's `deployed_fingerprint` is the new leaf, the emulator serves it, audits `deployment.requested` and `deployment.succeeded` exist, and the job result holds no key material (`SELECT result::text FROM jobs` does not contain a line of the key).
- `TestF15DeploymentsToOneServerNeverOverlap`: two locations on one target and one on another; three requests; `RunOnce` from two goroutines; the emulator records at most one `nginx-deploy` in flight per target (`DeployCount` with an in-flight counter in the emulator) and all three end `succeeded`.
- `TestF16OneServerFailsTheOtherSucceeds`: one request for locations on two targets; the second target's emulator `FailReload(1)`; outcomes `succeeded` and `rolled_back`, independent.
- `TestF17IncompleteChainNeedsAnAdministrator`, `TestF19ExpiredCertificateIsRefusedAndAudited`: through `RequestDeployment` and the audit log.
- `TestDeploySameCertificateTwice`: a second request of the same certificate to the same location after success ends `unchanged` with no second reload.
- `TestL80InFlightDeployFinishesAcrossLock`: the provider's `DeployCertificate` is wrapped (a test provider decorating the `nginx` one) to block on a channel at `config_test`; while blocked the license moves to lock (`licensetest` with the fake clock past grace, `license.Tick`); the deploy completes (`succeeded`), and a second deploy job queued meanwhile is `blocked_license` after the runner's lock sweep (L-81 part).
- `TestL81QueuedDeployIsBlockedThenConfirmed`: queued before lock → `blocked_license`; after a renewal it stays blocked until `Queue.Confirm` by an Administrator; then it runs and succeeds.
- `TestL82RollbackRunsDespiteLock`: the decorated provider answers `DeployUncertain` (after the emulator committed and `NoopReload` makes the verification fail later); the license locks; `RunOnce` runs the `certificate.deploy_recover` job (ClassAlways) which verifies, rolls back and ends `rolled_back`; the audit log has `deployment.failed` and `deployment.rolled_back`; no `certificate.deploy` job ran in lock.
- `TestSweepHandsInterruptedDeploymentsToRecovery`: a deployment left in `deploying` with its job dead (set as the owner role) → `SweepDeployments` → `RunOnce` → recovered from the emulator's journal.

`crash_integration_test.go` (`//go:build integration`), F-66 "proven under process kill", with the pattern of `internal/jobs/crash_integration_test.go`: the parent test `TestDeploymentSurvivesProcessKillAtEveryStep` runs PostgreSQL, the fake SSH server and the emulator; `TestDeployCrashChild` (skipped unless `ALICE_DEPLOY_CRASH_CHILD=1`) builds a runner and the `nginx` provider connecting to the parent's server (address, the server's host key and the client key PEM passed in environment variables; test-only keys generated by the parent), with `Lease` 1 s and `Heartbeat` 200 ms, and a step recorder hook that writes a marker file and sleeps forever when it sees the step named by `ALICE_DEPLOY_CRASH_AT`. The parent table:

| `ALICE_DEPLOY_CRASH_AT` | Where Alice dies | Expected final state after recovery |
|---|---|---|
| `verify_current` (ok) | before `StartDeployment` | `failed` (`deployment.interrupted`), old pair, nothing written |
| `backup` | the helper transaction is running in the emulator (the emulator delays 2 s after `backup`) | the emulator finishes on its own → `committed` → recovery verifies → `succeeded`, new pair |
| `reload` | helper finished, verification not started | `succeeded`, new pair |
| `verify` (started) with `NoopReload` | verification running | recovery verification fails → rolled back → `rolled_back`, old pair, old certificate served |

For each row the parent kills the child (`SIGKILL`) at the marker, waits until PostgreSQL closed the child's sessions, then in-process: `runner.Recover` (the lease expired), `inventory.SweepDeployments`, `RunOnce` until idle; asserts the final state, that the emulator's certificate and key files are a matching pair (`tls.X509KeyPair`), that `Served` equals the file's leaf, and `job.recovered` or `deployment.recovery_started` in the audit log. (The emulator gains `DelayAfter(step string, d time.Duration)` for the second row.)

Run: `go test -tags integration ./internal/jobs/deployjobs -count=1` (Docker: testcontainers PostgreSQL)
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/jobs/deployjobs internal/providers/linuxssh/linuxsshtest
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "feat(jobs): certificate deploy and recovery handlers with crash and lock tests (F-15..F-19, F-66, L-80..L-82)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 17: API — routes, DTOs, `certificates.operate`, error codes, OpenAPI, authz matrix

**Files:**
- Modify: `internal/rbac/rbac.go` (`CertificatesOperate`), `internal/rbac/rbac_test.go`
- Create: `internal/api/certificates_handlers.go` (certificates, upload, deploy, CSR, locations), `internal/api/deployments_handlers.go`, `internal/api/certs_dto.go`
- Modify: `internal/api/server.go` (`InventoryService` gains the methods below; `apiRoutes` appends `certificateRoutes()` and `deploymentRoutes()`), `internal/api/errors.go` (codes, `AllErrorCodes`, `errorMap`, `fail` for `*inventory.KeyTypeMismatchError`, `providerParamKeys`), `internal/api/targets_handlers.go` (create accepts `type` `nginx`; `GET /targets/{id}/certificate-locations`), `internal/api/inventory_dto.go` (`factsDTO.nginx`, target `type`), `internal/api/fakes_test.go`
- Modify: `api/openapi.yaml`, `docs/authz-matrix.md` (`make authz-doc`), `docs/troubleshooting.md` (one section per new code), `locales/common/{en,tr}.json` (`errors.<reason>.title|cause|action` exact from the contract; `provider.nginx.name` exists since Task 10)
- Test: `internal/api/certificates_handlers_test.go`, `internal/api/deployments_handlers_test.go`, `internal/api/authz_test.go`, `internal/api/errors_test.go` (runs as is)

**Interfaces:**
- Consumes: Tasks 13–15 inventory methods and errors.
- Produces: the API table of the contract; `rbac.CertificatesOperate = "certificates.operate"`; `api.InventoryService` gains:

```go
	ListCertificates(ctx context.Context, f inventory.CertificateFilter) (inventory.CertificatePage, error)
	GetCertificate(ctx context.Context, id uuid.UUID) (inventory.Certificate, error)
	UploadCertificate(ctx context.Context, a inventory.Actor, in inventory.UploadInput) (inventory.Certificate, []string, error)
	CreateCSR(ctx context.Context, a inventory.Actor, in inventory.CSRInput) (inventory.CSR, error)
	ListCSRs(ctx context.Context) ([]inventory.CSR, error)
	GetCSR(ctx context.Context, id uuid.UUID) (inventory.CSR, error)
	CompleteCSR(ctx context.Context, a inventory.Actor, id uuid.UUID, certificatePEM, label string) (inventory.Certificate, []string, error)
	CancelCSR(ctx context.Context, a inventory.Actor, id uuid.UUID) (inventory.CSR, error)
	ListLocations(ctx context.Context, targetID uuid.UUID, includeMissing bool) ([]inventory.CertificateLocation, error)
	UpdateLocation(ctx context.Context, a inventory.Actor, id uuid.UUID, ifVersion int, p inventory.LocationPatch) (inventory.CertificateLocation, error)
	RequestDeployment(ctx context.Context, a inventory.Actor, in inventory.DeployRequestInput) ([]inventory.RequestedDeployment, error)
	ListDeployments(ctx context.Context, f inventory.DeploymentFilter) (inventory.DeploymentPage, error)
	Deployment(ctx context.Context, id uuid.UUID) (inventory.Deployment, error)
```

- [ ] **Step 1: Permission, failing test first**

In `internal/api/authz_test.go` add the row `rbac.CertificatesOperate: row(unau, unau, unau, unau, unau, allw, allw, forb, allw, allw, forb, forb, allw, forb, allw),`; in `routeRuleViolations` add, before the generic read case:

```go
		case under(p, "/api/v1/certificates") && !safeMethod(rt.method):
			want = rbac.CertificatesOperate
		case under(p, "/api/v1/locations") && !safeMethod(rt.method):
			want = rbac.TargetsManage
```

and add `under(p, "/api/v1/certificates"), under(p, "/api/v1/locations"), under(p, "/api/v1/deployments")` to the `want = rbac.Read` case. Append to `TestSensitiveRoutesHaveTheirFixedPermissions`'s list every route of the contract's API table, and to `TestRouteRuleViolationsCatchesWeakPermissions`'s `bad` list `{POST /api/v1/certificates/upload, rbac.InventoryOperate}`, `{POST /api/v1/certificates/{id}/deploy, rbac.Read}`, `{PATCH /api/v1/locations/{id}, rbac.CertificatesOperate}`, `{GET /api/v1/deployments, rbac.CertificatesOperate}` and to `good` their correct permissions. Add to `rbac_test.go` the policy expectation for `CertificatesOperate`.

Run: `go test ./internal/api ./internal/rbac -count=1` → FAIL (`undefined: rbac.CertificatesOperate`; missing routes).

Implement in `rbac.go`:

```go
	CertificatesOperate Permission = "certificates.operate" // upload, signing requests, deploy: Admin and Operator (§15.4)
```

with policy `CertificatesOperate: {Roles: []Role{Admin, Operator}, TokenScope: ScopeOperate},`.

- [ ] **Step 2: Handlers, failing tests first**

`certificates_handlers_test.go` (fake inventory in `fakes_test.go` records the inputs and answers configured values; `call(h, method, path, identity, body)` is the existing helper):

```go
func TestUploadCertificate(t *testing.T) {
	d := testDeps(t, nil)
	inv := d.Inventory.(*fakeInventory)
	inv.uploaded = inventory.Certificate{ID: uuid.New(), Fingerprint: strings.Repeat("a", 64), Source: "uploaded", HasPrivateKey: true}
	inv.uploadWarnings = []string{"chain_incomplete"}
	h := newServer(d).handler(newServer(d).apiRoutes())
	rec := call(h, http.MethodPost, "/api/v1/certificates/upload", "operator",
		`{"label":"Web","certificate_pem":"-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n","private_key_pem":"k"}`)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	var body struct {
		Certificate map[string]any `json:"certificate"`
		Warnings    []string       `json:"warnings"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, []string{"chain_incomplete"}, body.Warnings)
	assert.Equal(t, true, body.Certificate["has_private_key"])
	assert.Equal(t, "Web", inv.uploadInput.Label)
	assert.NotContains(t, rec.Body.String(), `"k"`, "the key never comes back")
	rec = call(h, http.MethodPost, "/api/v1/certificates/upload", "operator", `{"certificate_pem":"x","unknown":1}`)
	assert.Equal(t, http.StatusBadRequest, rec.Code, "strict decoding")
}

func TestCertificateErrorsMapToCodes(t *testing.T) {
	for _, tc := range []struct {
		err    error
		code   string
		status int
		params map[string]string
	}{
		{inventory.ErrKeyMismatch, "ALC-CRT-0002", 422, nil},
		{inventory.ErrCertificateExpired, "ALC-CRT-0003", 422, nil},
		{inventory.ErrKeyEncrypted, "ALC-CRT-0004", 422, nil},
		{inventory.ErrPFXPassword, "ALC-CRT-0005", 422, nil},
		{inventory.ErrCertificateDuplicate, "ALC-CRT-0008", 409, nil},
		{&inventory.KeyTypeMismatchError{Expected: "ecdsa", Actual: "rsa"}, "ALC-CRT-0010", 409, map[string]string{"expected": "ecdsa", "actual": "rsa"}},
		{inventory.ErrChainUnconfirmed, "ALC-CRT-0011", 409, nil},
		{inventory.ErrDeploymentInProgress, "ALC-DEP-0001", 409, nil},
		{inventory.ErrRecoveryPending, "ALC-DEP-0002", 409, nil},
		{inventory.ErrLocationUnsupported, "ALC-NGX-0007", 409, nil},
		{inventory.ErrCertificateTooLarge, "ALC-SYS-0007", 413, nil},
	} {
		d := testDeps(t, nil)
		d.Inventory.(*fakeInventory).deployErr = tc.err
		h := newServer(d).handler(newServer(d).apiRoutes())
		rec := call(h, http.MethodPost, "/api/v1/certificates/"+uuid.NewString()+"/deploy", "admin", `{"location_ids":["`+uuid.NewString()+`"]}`)
		e := decodeErr(t, rec)
		assert.Equal(t, tc.status, rec.Code, tc.code)
		assert.Equal(t, tc.code, e.Error.Code)
		assert.Equal(t, tc.params, e.Error.Params)
	}
}

func TestDeployAnswersAcceptedWithJobs(t *testing.T) {
	// The fake returns two RequestedDeployment rows; the answer is 202 with
	// {"deployments":[{"id","job_id","location_id","status_url":"/api/v1/jobs/<job_id>","warnings":[]}, …]};
	// an Operator's confirm_incomplete_chain is passed on as sent (inventory decides);
	// 21 location ids → 422 field location_ids; a non-UUID id in the path → 404.
}

func TestCertificateListQueryValidation(t *testing.T) {
	// ?expiry=90 → 422 field expiry; ?source=kv → 422 field source; ?limit=0 → 422; ?target_id=x → 422; ?q of 201 runes → 422;
	// a valid query reaches the fake with every filter field set.
}

func TestCSRRoutes(t *testing.T) {
	// POST create → 201 with csr_pem; GET list → items; POST complete → 201 {certificate, warnings};
	// POST cancel → 200; an Auditor gets 403 on every POST and 200 on the GETs.
}

func TestUpdateLocationNeedsIfMatch(t *testing.T) {
	// PATCH without If-Match, with a weak validator (W/"3") or with "*" → 412 ALC-SYS-0008 (the handler uses ifMatch, as PATCH
	// /targets/{id} does); with If-Match "3" the fake receives ifVersion 3 and the patch fields; the answer carries ETag "4";
	// verify_port 70000 → 422 field verify_port (validated by inventory, passed through).
}
```

`deployments_handlers_test.go`: `GET /api/v1/deployments` with filters and paging, `GET /api/v1/deployments/{id}` with steps and an `error` object rendered from `error_code` (`{code, reason, params}` through `codeForReason` and the allowlisted params), an unknown id → 404.

Write the commented tests out in full from their comments.

Run: `go test ./internal/api -count=1` → FAIL.

Implement:
- Routes (`certificateRoutes`, `deploymentRoutes`, plus `GET /api/v1/targets/{id}/certificate-locations` in `targetRoutes`), permissions and lock classes exactly as the contract table; handlers decode with the existing strict JSON decoder (1 MiB cap, unknown fields 400), build `inventory.Actor` from the principal as the Phase 3 handlers do, call the service, and write the DTOs. `POST …/deploy` answers 202 `{"deployments": [...]}` with `status_url` `/api/v1/jobs/<job_id>`.
- `certs_dto.go`: `certificateDTO`, `locationDTO`, `deploymentDTO`, `csrDTO` with the contract's JSON names; slices never `null`; times UTC; `deploymentDTO.error` is `null` when `error_code` is empty, else `{code, reason, params}` with `providerParams`; `backup_dir` from `Backup.Dir`; `pem_chain` and `locations` only on `GET /certificates/{id}`.
- `errors.go`: one `ErrorCode` per row of the contract's error table (variable names `ErrNginxNotFound`, `ErrNginxConfigInvalid`, `ErrNginxConfigChanged`, `ErrNginxProfileMissing`, `ErrNginxNoSpace`, `ErrNginxFileChanged`, `ErrNginxLocationUnsupported`, `ErrNginxBusy`, `ErrNginxWriteFailed`, `ErrCertInvalid`, `ErrCertKeyMismatch`, `ErrCertExpired`, `ErrCertKeyEncrypted`, `ErrCertPFXPassword`, `ErrCertWeak`, `ErrCertUnsupportedKey`, `ErrCertDuplicate`, `ErrCertNoPrivateKey`, `ErrCertKeyTypeMismatch`, `ErrCertChainUnconfirmed`, `ErrCSRNotPending`, `ErrCSRCertificateMismatch`, `ErrDeployInProgress`, `ErrDeployRecoveryPending`, `ErrDeployVerifyFailed`, `ErrDeployVerifyOther`, `ErrDeployVerifyUnreachable`, `ErrDeployReloadFailed`, `ErrDeployConfigTestFailed`, `ErrDeployRollbackFailed`, `ErrDeployRollbackReloadFailed`, `ErrDeployInterrupted`, `ErrDeployTargetNotReady`), all appended to `AllErrorCodes`; `errorMap` entries for every inventory sentinel of Tasks 14–15 (`ErrCertificateTooLarge` → `ErrBodyTooLarge`); `fail` handles `*inventory.KeyTypeMismatchError` like `*license.TargetLimitError` (params `expected`, `actual`); `providerParamKeys` gains `port`, `failed_step`, `profile`, `phase`, `directory`, `backup_dir`, `expected`, `actual`, `mode`.
- `targets_handlers.go`: the create request's `type` defaults to `linux` and accepts `nginx`; the target DTO's facts gain `nginx` (`{version, conf_path, config_valid, config_error, found}` or omitted).
- `locales/common/{en,tr}.json`: `errors.<reason>.title|cause|action` for the 33 codes, exactly the contract texts (`{{port}}`, `{{expected}}`, `{{actual}}`, `{{backup_dir}}`, `{{directory}}` are the only placeholders).
- `docs/troubleshooting.md`: a `## ALC-…: <short title>` section per code with the title, cause and action in English, in code order (the errors test checks presence).
- `api/openapi.yaml`: the 13 operations with `x-permission`, request bodies, the four schemas, `202` for deploy, error responses referencing `Error`; the `Target` schema's `type` enum gains `nginx`, its facts `nginx`. Then `make authz-doc`.

Run: `go test ./internal/api ./internal/rbac -count=1 && make authz-doc && git diff --stat docs/authz-matrix.md && make i18n-check`
Expected: PASS; the matrix document lists the new routes.

- [ ] **Step 3: Commit**

```bash
git add internal/rbac internal/api api/openapi.yaml docs/authz-matrix.md docs/troubleshooting.md locales/common
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "feat(api): certificates, signing requests, locations and deployments routes with error codes

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 18: API integration — Nginx journeys, secret-leak suite with TLS keys, lock

**Files:**
- Create: `internal/api/certificates_integration_test.go`
- Modify: `internal/api/leak_integration_test.go` (TLS key canaries and flows), `internal/api/targets_integration_test.go` (L-29 lock test gains the new routes), `internal/api/stack_integration_test.go` (the stack registers the `nginx` provider over the emulator and the `deployjobs` handlers)

**Interfaces:**
- Consumes: everything of Tasks 10–17; the Phase 3 API stack fixture (real services, fake SSH server, emulator, `runJobs` helper that drains the queue).

- [ ] **Step 1: Journeys**

`certificates_integration_test.go` (`//go:build integration`), through HTTP only (as an Administrator and an Operator with sessions and CSRF from the stack fixture):
- `TestNginxJourney` (owner steps 1–3, 5): prepare (`GET /ssh-keys/platform-key` → `nginx` profile has the five `nginx-*` lines), add an Nginx server (`POST /targets` `{"type":"nginx",…}`), confirm the host key, drain jobs → `GET /targets/{id}/certificate-locations` lists `www.example.test` with its certificate and `not_after`; `POST /certificates/upload` (Operator) → 201; `POST /certificates/{id}/deploy` → 202; drain → `GET /deployments/{id}` is `succeeded` with steps `verify_current`, `backup`, `write_key`, `write_cert`, `config_test`, `reload`, `verify` ok; the emulator serves the new leaf; `GET /deployments?target_id=` lists it.
- `TestUploadJourneyRefusesWithExactMessages` (Review Focus 4, owner step 4): the broken pair → 422 `ALC-CRT-0002` whose `message` (EN) is "The new certificate does not match its key. Nothing was changed. Upload the key that was created together with this certificate." and with `Accept-Language: tr` the Turkish title and action; an expired leaf → `ALC-CRT-0003`; an encrypted key → `ALC-CRT-0004`; a PFX with a wrong password → `ALC-CRT-0005`; a CRLF+BOM PEM → 201; a 2 MiB body → 413 `ALC-SYS-0007`.
- `TestDeployFailureJourneys`: with the emulator's `FailReload(1)` → `rolled_back`, error `ALC-DEP-0006`; `FailReload(2)` → `rollback_failed`, error `ALC-DEP-0009`, an email `deployment.rollback_failed` in the test mailbox with `backup_dir`; `SetConfigInvalid` before the request → 409 `ALC-NGX-0002` at the request (the target facts say invalid after a discovery).
- `TestSigningRequestJourney`: create (Operator) → complete with a certificate issued by `pki` for the CSR → the certificate has a key → deploy succeeds.
- `TestLocationSettingsAreAdminOnly`: Operator `PATCH /locations/{id}` → 403; Administrator → 200 and `location.updated` audited.

- [ ] **Step 2: Secret leak (S-01..S-05 with TLS keys)**

Extend `leak_integration_test.go`: the canary set gains TLS private keys — an ECDSA key and an RSA key generated per run, each in PKCS#8, PKCS#1/SEC1 PEM, as DER (base64 body lines are the needles, as for SSH keys), a PFX password canary `CANARY-<random>`, and the generated CSR key (read back from `managed_private_keys` with the test keyring after `POST /certificates/csr`). Flows exercised: upload (good, mismatched — the canary key belongs to another certificate —, PFX with the canary password right and wrong, encrypted key), CSR create and complete, deploy (success and rollback through the emulator; the emulator receives the key on stdin, which is the server side and is excluded), job results, deployment steps, audit rows, emails in the test mailbox, every HTTP response and header, the server log (S-01..S-03, S-05). S-04: `managed_private_keys.ciphertext` contains no canary and no PEM marker (`"-----BEGIN " + "PRIVATE"`), two uploads of the same key produce different ciphertexts and different `wrapped_dek`. S-08 still passes (no response field named `private_key`).

- [ ] **Step 3: Lock (L-29, L-81)**

In the L-29 test: in lock, `POST /certificates/upload`, `POST /certificates/csr`, `POST /certificates/csr/{id}/actions/complete|cancel`, `POST /certificates/{id}/deploy`, `PATCH /locations/{id}` answer 403 `ALC-LIC-0001` and are audited `request.denied_license`; every new GET answers 200; the fake SSH server's command log shows no `nginx-*` command during the lock. L-81 through HTTP: a deploy queued just before the lock becomes `blocked_license`, appears in `GET /jobs?status=blocked_license`, and after a renewal runs only after `POST /jobs/{id}/actions/confirm`.

- [ ] **Step 4: Run and commit**

Run: `go test -tags integration ./internal/api -count=1` (Docker: testcontainers PostgreSQL)
Expected: PASS.

```bash
git add internal/api
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "test(api): Nginx certificate journeys, TLS key leak suite and lock behaviour

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 19: Wiring — providers, runner and scheduler, e2e target with Nginx, Dockerfiles, Makefile

**Files:**
- Modify: `cmd/alice/providers.go` (register `nginx`), `cmd/alice/providers_test.go`, `cmd/alice/services.go` (`deployjobs.Register`; scheduler task `DeploymentRecoverySweep` every minute running `inventory.SweepDeployments`; `inventory.Config.Roots` = `certs.SystemRoots()` is the default, nothing to pass), `cmd/alice/services_test.go`
- Modify: `test/images/e2e-target/Dockerfile` (Nginx, openssl, the shim, scripts, fixture certificates), create `test/images/e2e-target/systemctl`, `alice-e2e-newcert`, `alice-e2e-reload-mode`, `alice-e2e-served`, `alice-e2e-start`, `nginx-www.conf`
- Modify: `deploy/docker-compose.e2e.yml` (healthcheck covers Nginx), `Makefile` (`test-ssh` runs the Nginx matrix too; `e2e` keeps a shell-exported `ALICE_E2E_PORT`; `ci` unchanged), `.github/workflows/ci.yml` (nothing new: `make coverage` already runs integration tests)
- Test: `cmd/alice/providers_test.go`, `cmd/alice/services_test.go`, `cmd/alice/compose_test.go` (the e2e overlay still adds only `sshtarget`)

**Interfaces:**
- Consumes: Tasks 10–16.
- Produces: the running product; the e2e environment of the contract.

- [ ] **Step 1: Providers and jobs, failing tests first**

`providers_test.go`: `registerProviders` registers `linuxssh` and `nginx`; the `nginx` provider's capabilities are the six of the contract; both share one pool (deleting a target closes its connections through either provider: `ForgetTarget` on the `nginx` provider reaches the `linuxssh` pool). `services_test.go`: in `cmd/alice/testapi_e2e_integration_test.go` (which already builds the real services with `buildRunner` and `buildScheduler`), add `TestWiringRunsDeployJobs`: a `certificate.deploy_recover` job queued for an unknown deployment id is claimed by the built runner (`RunOnce` returns true: a runner only claims types it has handlers for) and ends `failed` with `system.not_found`; the same for `certificate.deploy`; and `sched.RunNow(ctx, "deployment.recovery_sweep")` returns nil (the task is registered).

Run: `go test ./cmd/alice -count=1 && go test -tags "integration e2e testlicense" ./cmd/alice -run TestWiringRunsDeployJobs -count=1` (Docker) → FAIL. Implement in `providers.go`:

```go
	ssh := linuxssh.New(linuxssh.Options{Pool: sshPool, AllowUnverifiedHelper: dev})
	reg.Register(ssh)
	reg.Register(nginx.New(nginx.Options{SSH: ssh}))
	reg.Freeze()
```

(update the doc comment: "nginx (Phase 4) is built on linuxssh; azurekv (Phase 5) is added here."). In `services.go`: `deployjobs.Register(runner, deployjobs.Deps{Inventory: svc.inventory, Registry: svc.registry, Clock: clk, Log: log})` next to `targetjobs.Register`, and the scheduler task:

```go
		jobs.Task{Type: jobs.DeploymentRecoverySweep, Every: time.Minute, Run: func(ctx context.Context) error {
			_, err := svc.inventory.SweepDeployments(ctx)
			return err
		}},
```

Run: `go test ./cmd/alice -count=1 && go test -tags "e2e testlicense" ./cmd/alice -count=1` → PASS.

- [ ] **Step 2: e2e target with Nginx**

`test/images/e2e-target/Dockerfile`: install `nginx openssl` with the other packages; then (still at build time) create a test CA and the `www.example.test` certificate with `openssl` (`openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes …` for the CA, a CSR and `openssl x509 -req … -CA` for the leaf with `subjectAltName=DNS:www.example.test`, 90 days), keep the CA key at `/opt/alice-test-ca/ca.key` (0600 root: the e2e target is a throwaway test container; the key never leaves it) and the CA certificate at `/opt/alice-test-ca/ca.pem`; write `/etc/nginx/ssl/www.crt` (leaf + CA, 0644) and `/etc/nginx/ssl/www.key` (0600); remove `/etc/nginx/sites-enabled/default`; `COPY nginx-www.conf /etc/nginx/conf.d/www.conf`; install the shim as `/usr/bin/systemctl` (0755) and the scripts in `/usr/local/sbin`; `mkdir -p /etc/alice-e2e && echo ok > /etc/alice-e2e/reload-mode`; `CMD ["/usr/local/sbin/alice-e2e-start"]`.

`nginx-www.conf`:

```nginx
server {
    listen 443 ssl;
    server_name www.example.test;
    ssl_certificate /etc/nginx/ssl/www.crt;
    ssl_certificate_key /etc/nginx/ssl/www.key;
    location / { return 200 "www\n"; }
}
server {
    listen 443 ssl;
    server_name files.example.test;
    ssl_certificate /etc/nginx/ssl/$ssl_server_name.crt;
    ssl_certificate_key /etc/nginx/ssl/$ssl_server_name.key;
    location / { return 200 "files\n"; }
}
```

(Nginx 1.15.9+ accepts variables in these directives; Ubuntu 22.04 ships 1.18. Variable certificate files load per connection, so `nginx -t` passes without the files; `files.example.test` is the unsupported row.)

`systemctl` (shim of §22.3, test only):

```sh
#!/bin/sh
# Test-only systemctl for containers without systemd (spec §22.3): reload and is-active for nginx.
mode=$(cat /etc/alice-e2e/reload-mode 2>/dev/null || echo ok)
case "$1 $2 $3" in
"reload nginx ") [ "$mode" = fail-once ] && { echo ok > /etc/alice-e2e/reload-mode; exit 1; }
    [ "$mode" = fail ] && exit 1
    [ "$mode" = noop ] && exit 0
    exec /usr/sbin/nginx -s reload ;;
"is-active --quiet nginx") pgrep -x nginx >/dev/null ;;
*) echo "systemctl shim: unsupported: $*" >&2; exit 1 ;;
esac
```

`alice-e2e-reload-mode` writes its argument (`ok`, `fail-once`, `fail` or `noop`; anything else exits 2) to `/etc/alice-e2e/reload-mode`. `alice-e2e-start` runs `/usr/sbin/nginx` (daemonized) and then `exec /usr/sbin/sshd -D -e`. `alice-e2e-newcert <name> [--broken]` creates a fresh EC key and a leaf for `<name>` signed by the test CA in a `mktemp -d` directory, prints `-----ALICE CERT-----`, the leaf and the CA certificate, `-----ALICE KEY-----`, the key (with `--broken`: a second, unrelated key), `-----ALICE END-----`, and deletes the directory. `alice-e2e-served <name>` prints `openssl s_client -connect 127.0.0.1:443 -servername <name> </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256` reduced to lower-case hex without colons (`tr -d : | tr 'A-F' 'a-f'`, after `cut -d= -f2`).

`deploy/docker-compose.e2e.yml`: the `sshtarget` healthcheck becomes `["CMD-SHELL", "pgrep -x sshd && pgrep -x nginx"]`; update its comment (Phase 4 journeys use its Nginx).

- [ ] **Step 3: Makefile**

`test-ssh`:

```make
test-ssh: ## Run the real OpenSSH and Nginx matrix (Ubuntu 22.04, Debian 12, Rocky 9; needs Docker). ALICE_SSH_IMAGES=ubuntu22 limits it
	go test -count=1 -tags integration -run TestRealOpenSSH ./internal/providers/linuxssh/
	go test -count=1 -tags integration -run TestRealNginx ./internal/providers/nginx/
```

`e2e` (carry 13): replace `set -a && { [ ! -f ../deploy/.env ] || . ../deploy/.env; } && set +a &&` with
`port="$${ALICE_E2E_PORT:-}" && set -a && { [ ! -f ../deploy/.env ] || . ../deploy/.env; } && set +a && { [ -z "$$port" ] || ALICE_E2E_PORT="$$port"; } && export ALICE_E2E_PORT &&` so a value exported in the shell wins over `deploy/.env`, as compose does.

- [ ] **Step 4: Bring up the e2e stack once and commit**

Run (Docker: the `alice-e2e` project only): `make e2e-up && make e2e-hardening-check`, then `docker compose -p alice-e2e exec -T sshtarget /usr/local/sbin/alice-e2e-served www.example.test` prints 64 hex digits, then `make e2e` (the Phase 1–3 suites stay green), then `make e2e-down`.

```bash
git add cmd/alice test/images/e2e-target deploy/docker-compose.e2e.yml Makefile
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "feat: wire the nginx provider and deploy jobs; e2e target serves Nginx

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 20: Real Nginx matrix — Ubuntu 22.04, Debian 12, Rocky 9

The deploy engine against real OpenSSH, sudo, the real helper and real Nginx on the three distributions of §22.3, with the `systemctl` shim (`reload`, `is-active`, a failure mode). It proves on real systems what Tasks 6 and 11 prove on models: discovery, a verified deploy, F-01..F-05, F-07 (local probe), F-08 (a dropped connection), F-10, F-13, idempotence, Let's Encrypt links and dual RSA/ECDSA certificates, and the user-owned-directory and hard-link attacks.

**Files:**
- Modify: `test/images/sshd/ubuntu22.Dockerfile`, `debian12.Dockerfile` (`apt-get install … nginx openssl`), `rocky9.Dockerfile` (`dnf install -y nginx openssl`); all three `COPY systemctl-shim /usr/bin/systemctl` (0755) and `RUN mkdir -p /etc/alice-test && echo ok > /etc/alice-test/reload-mode`
- Create: `test/images/sshd/systemctl-shim` (the e2e shim of Task 19 with `/etc/alice-test/reload-mode`)
- Modify: `internal/providers/linuxssh/containers_integration_test.go` (image tag `phase4`: the images changed)
- Create: `internal/providers/nginx/containers_integration_test.go`

**Interfaces:**
- Consumes: the `nginx` provider, `linuxssh.SetupScript("nginx", …, true)`, `pki`.

- [ ] **Step 1: Images**

`test/images/sshd/systemctl-shim`:

```sh
#!/bin/sh
# Test-only systemctl for containers without systemd (spec §22.3).
mode=$(cat /etc/alice-test/reload-mode 2>/dev/null || echo ok)
case "$1 $2 $3" in
"reload nginx ") [ "$mode" = fail-once ] && { echo ok > /etc/alice-test/reload-mode; exit 1; }
    [ "$mode" = fail ] && exit 1
    [ "$mode" = noop ] && exit 0
    exec /usr/sbin/nginx -s reload ;;
"is-active --quiet nginx") pgrep -x nginx >/dev/null ;;
*) echo "systemctl shim: unsupported: $*" >&2; exit 1 ;;
esac
```

On Ubuntu and Debian install with `DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server sudo procps nginx openssl` and remove `/etc/nginx/sites-enabled/default`; on Rocky 9 `dnf install -y nginx openssl`. Nginx is not started by the image (the test starts it after writing its configuration). Keep `CMD ["/usr/sbin/sshd", "-D", "-e"]`.

- [ ] **Step 2: Write the matrix**

`internal/providers/nginx/containers_integration_test.go` (`//go:build integration`). Its fixture mirrors `startCtrHost` of `linuxssh` (that one is in another package's test files; copy what is needed: `ctrSelectedDistros` reading `ALICE_SSH_IMAGES`, building the helper with `go build -trimpath -o <tmp>/alice-helper ./cmd/alice-helper` from the repository root, the container from `test/images/sshd/<image>.Dockerfile` with tag `phase4`, exposed `22/tcp` and `443/tcp`, a `tmpfs` at `/etc/nginx/small` of 256 KiB through the request's `HostConfigModifier`, the setup script of the **nginx** profile, a pinned host key store, the `linuxssh` pool and provider, and `nginx.New(Options{SSH: …, RetryWait: 200 * time.Millisecond})`). Helpers:
- `h.writeSite(name, certPath, keyPath string, leaf pki.Leaf, keyMode os.FileMode)`: copies the files into the container (root:root, cert 0644) and `/etc/nginx/conf.d/<name>.conf` with one `server` on `listen 443 ssl;` for `name`.
- `h.reloadNginx()`: `nginx -t && (nginx -s reload || nginx)`.
- `h.served(sni)`: the fingerprint served on the container's `127.0.0.1:443` through `docker exec … openssl s_client` (as `alice-e2e-served` does).
- `h.verifyPort()`: the mapped host port of `443/tcp`; every `DeployRequest`/`VerifyRequest` uses `Verify: providers.VerifyOptions{Port: h.verifyPort()}` so Alice's probe reaches the container (the listen port inside is 443).
- `h.pair(certPath, keyPath)`: reads both files back and asserts `tls.X509KeyPair` accepts them (never a mismatched pair).

```go
func TestRealNginx(t *testing.T) {
	helper := buildHelper(t)
	for _, image := range selectedDistros(t) {
		t.Run(image, func(t *testing.T) {
			h := startNginxHost(t, image, helper)
			ca := pki.NewCA("Real", pki.ECDSA256, time.Now())
			old := ca.Issue(pki.Opts{CommonName: "www.example.test", SANs: []string{"www.example.test"}}, time.Now())
			h.writeSite("www.example.test", "/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key", old, 0o644)
			h.reloadNginx()

			t.Run("discovery", func(t *testing.T) { … one supported location, PEM equals old.FullchainPEM, KeyMode "0644" with warning key_mode_open,
				Nginx.Version not empty, SSH keys of the fixture users present })
			t.Run("deploy_verified", func(t *testing.T) { … a new leaf; DeployCertificate → DeployCommitted, Verified "remote";
				h.served("www.example.test") is the new leaf; key mode is now 0600 (F-13); h.pair ok; a second call with the same
				operation answers DeployCommitted and the reload count (shim log line count) does not grow })
			t.Run("F-01_key_mismatch", func(t *testing.T) { … pair with another key → DeployRolledBack, certificate.key_mismatch;
				previous leaf served; h.pair ok })
			t.Run("F-02_broken_config", func(t *testing.T) { … write /etc/nginx/conf.d/zz-broken.conf with "server {"; DeployNoChange
				nginx.config_invalid; files unchanged; remove the file })
			t.Run("F-03_reload_fails_once", func(t *testing.T) { … reload-mode fail-once: DeployRolledBack deployment.reload_failed,
				failed step reload; the old leaf served; h.pair ok })
			t.Run("F-04_rollback_reload_fails", func(t *testing.T) { … reload-mode fail: DeployRollbackFailed
				deployment.rollback_reload_failed (files restored, Nginx not reloaded); set mode ok; h.pair ok; the old leaf still
				served (Nginx never loaded the new files) })
			t.Run("F-05_noop_reload", func(t *testing.T) { … mode noop: DeployRolledBack deployment.verify_failed; mode ok })
			t.Run("F-07_verify_local", func(t *testing.T) { … a provider whose Prober always answers ErrProbeUnreachable:
				DeployCommitted with Verified "local" })
			t.Run("F-08_connection_dropped", func(t *testing.T) { … DeployCertificate with a context cancelled 100 ms after the call
				starts (the helper is mid-transaction): DeployUncertain; after 5 s a new session's DeploymentStatus is committed or
				restored, never writing or restoring; h.pair ok; the served leaf matches the files })
			t.Run("F-10_no_space", func(t *testing.T) { … a site whose files live on the 256 KiB tmpfs /etc/nginx/small:
				DeployNoChange nginx.no_space; files unchanged })
			t.Run("letsencrypt_links", func(t *testing.T) { … /etc/letsencrypt/live/le.example.test/{fullchain,privkey}.pem linking to
				../../archive/le.example.test/{fullchain1,privkey1}.pem (root-owned): discovery Symlinked; deploy commits; the links are
				still links and the archive files hold the new pair })
			t.Run("dual_rsa_ecdsa", func(t *testing.T) { … one server with an RSA and an ECDSA pair: two locations; deploying the RSA
				one verifies with KeyType rsa and leaves the ECDSA certificate served to an ECDSA-only client unchanged })
			t.Run("user_owned_directory", func(t *testing.T) { … chown 1000:1000 /etc/nginx/userdir with a site in it (Nginx loads it
				as root): discovery lists it unsupported with problem not_root_controlled and no PEM; DeployNoChange
				nginx.location_unsupported; files unchanged })
			t.Run("hard_link", func(t *testing.T) { … ln /etc/nginx/ssl/hl.key /root/hl-copy.key: the location is unsupported
				(key problem hard_linked); deploy refused })
		})
	}
}
```

Replace every `…` body above with real code following its description; each subtest restores the shim mode `ok`, removes its configuration files and reloads Nginx before it ends.

- [ ] **Step 3: Run the matrix**

Run: `make test-ssh` (Docker: testcontainers images `alice-test/sshd-{ubuntu22,debian12,rocky9}:phase4`)
Expected: PASS for `TestRealOpenSSH` and `TestRealNginx` on all three distributions.

- [ ] **Step 4: Commit**

```bash
git add test/images/sshd internal/providers/nginx/containers_integration_test.go internal/providers/linuxssh/containers_integration_test.go
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "test(nginx): real Nginx matrix on Ubuntu 22.04, Debian 12 and Rocky 9

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 21: Web — API layer, Certificates list and detail, upload dialog, signing requests, navigation, audit labels

**Files:**
- Modify: `web/src/api/types.ts` (types below), `web/src/api/endpoints.ts` (functions below), `web/src/api/queryKeys.ts` (`CERTIFICATES_KEY`, `certificateKey(id)`, `CSRS_KEY`, `DEPLOYMENTS_KEY`, `deploymentKey(id)`, `locationsKey(targetId)`), `web/src/api/client.ts` and `web/src/api/jobs.ts` (carry 11: `NetworkError`)
- Create: `web/src/pages/CertificatesPage.tsx`, `web/src/pages/CertificateDetailPage.tsx`, `web/src/components/UploadCertificateDialog.tsx`, `web/src/components/CreateCSRDialog.tsx`, `web/src/components/PendingCSRs.tsx`, `web/src/components/Expiry.tsx` (date + days left + expired badge)
- Modify: `web/src/router.tsx` (`/certificates`, `/certificates/:id`), `web/src/layout/AppLayout.tsx` (nav item **Certificates** for every role), `web/src/locales/{en,tr}.json` (the contract's `nav.certificates`, `certificates.*`, `audit.actions.*`, `jobs.types.*`, `enum.deploymentStatus.*` rows), `web/src/test/fixtures.ts` (`certificateFixture`, `csrFixture`), `web/src/test/screens.ts` (both pages)
- Test: `web/src/pages/CertificatesPage.test.tsx`, `web/src/pages/CertificateDetailPage.test.tsx`, `web/src/components/UploadCertificateDialog.test.tsx`, `web/src/components/CreateCSRDialog.test.tsx`, `web/src/api/jobs.test.ts`

**Interfaces:**
- Consumes: the API of Task 17.
- Produces (used by Task 22):

```ts
export type CertificateSource = 'discovered' | 'uploaded' | 'csr' | 'azure_kv';
export interface Certificate {
  id: string; fingerprint: string; subject_cn: string; subject: string; issuer: string; serial: string; sans: string[];
  not_before: string; not_after: string; key_algorithm: 'rsa' | 'ecdsa' | 'ed25519' | 'other'; key_bits: number;
  source: CertificateSource; label: string; has_private_key: boolean; chain_complete: boolean; self_signed: boolean;
  location_count: number; first_seen_at: string; last_seen_at: string; pem_chain?: string; locations?: CertificateLocation[];
}
export interface CertificateRef { id: string; subject_cn: string; label: string; fingerprint: string; not_after: string }
export interface CertListen { addr: string; port: number; default_server: boolean }
export interface CertServer { names: string[]; listens: CertListen[]; file: string; line: number }
export interface CertificateLocation {
  id: string; target_id: string; target_name: string; cert_path: string; key_path: string; key_type: '' | 'rsa' | 'ecdsa';
  certificate: CertificateRef | null; servers: CertServer[]; supported: boolean; unsupported_reason: string; problem: string;
  inherited: boolean; custom_location: boolean; symlinked: boolean; key_exists: boolean; key_mode: string; key_owner: string;
  warnings: string[]; deployed_fingerprint: string; changed_outside_at: string | null; verify_port: number | null;
  verify_sni: string | null; skip_verify: boolean; first_seen_at: string; last_seen_at: string; missing_since: string | null;
  version: number; active_deployment_id: string | null;
}
export type DeploymentStatus = 'pending' | 'running' | 'succeeded' | 'unchanged' | 'failed' | 'rolled_back' | 'rollback_failed' | 'needs_attention';
export interface DeploymentStep { n: number; name: string; status: 'started' | 'ok' | 'failed' | 'skipped'; at: string; params: Record<string, string> }
export interface Deployment {
  id: string; certificate_id: string; certificate_name: string; location_id: string; target_id: string; target_name: string;
  cert_path: string; job_id: string | null; trigger: string; state: string; status: DeploymentStatus; new_fingerprint: string;
  previous_fingerprint: string; verified: '' | 'remote' | 'local' | 'skipped'; error: JobError | null; failed_step: string;
  backup_dir: string; requested_by: string | null; requested_by_name: string; created_at: string; started_at: string | null;
  finished_at: string | null; steps?: DeploymentStep[];
}
export interface CSR { id: string; common_name: string; sans: string[]; key_algorithm: string; key_bits: number; csr_pem: string;
  status: 'pending' | 'completed' | 'cancelled'; certificate_id: string | null; created_at: string; finished_at: string | null }
export interface CertificateQuery { target_id?: string; source?: CertificateSource | ''; q?: string; expiry?: '' | 'expired' | '30' | '60'; cursor?: string | null }
export interface UploadRequest { label?: string; certificate_pem?: string; private_key_pem?: string; pfx_base64?: string; pfx_password?: string }
export interface UploadResult { certificate: Certificate; warnings: string[] }
export interface DeployResult { deployments: { id: string; job_id: string; location_id: string; status_url: string; warnings: string[] }[] }

// endpoints.ts
export function listCertificates(q?: CertificateQuery): Promise<{ items: Certificate[]; next_cursor: string | null }>;
export const getCertificate: (id: string) => Promise<Certificate>;
export const uploadCertificate: (req: UploadRequest) => Promise<UploadResult>;
export const deployCertificate: (id: string, locationIds: string[], confirmIncompleteChain: boolean) => Promise<DeployResult>;
export const listCSRs: () => Promise<{ items: CSR[] }>;
export const createCSR: (req: { common_name: string; sans: string[]; key_type: 'ecdsa-p256' | 'rsa-3072' | 'rsa-4096' }) => Promise<CSR>;
export const completeCSR: (id: string, certificatePem: string, label?: string) => Promise<UploadResult>;
export const cancelCSR: (id: string) => Promise<CSR>;
export const listLocations: (targetId: string, missing?: boolean) => Promise<{ items: CertificateLocation[] }>;
export const updateLocation: (id: string, version: number, patch: { verify_port?: number; verify_sni?: string; skip_verify?: boolean }) => Promise<CertificateLocation>;
export function listDeployments(q?: { target_id?: string; certificate_id?: string; location_id?: string; cursor?: string | null }): Promise<{ items: Deployment[]; next_cursor: string | null }>;
export const getDeployment: (id: string) => Promise<Deployment>;

// components/Expiry.tsx
export function daysLeft(notAfter: string, now: number): number; // whole days, floor; negative when expired
export function Expiry(props: { notAfter: string }): JSX.Element; // locale date, "N days"/"Expired" badge (red expired, orange ≤ 30, yellow ≤ 60)
```

- [ ] **Step 1: Carry 11 (`waitForJob`), failing test first**

In `web/src/api/jobs.test.ts` add:

```ts
it('treats only network failures and retryable API errors as transient', () => {
  expect(isTransient(new NetworkError('offline', { cause: new TypeError('Failed to fetch') }))).toBe(true);
  expect(isTransient(new TypeError("Cannot read properties of undefined (reading 'status')"))).toBe(false);
  expect(isTransient(new ApiError(503, { code: 'ALC-SYS-0002', reason: 'system.unavailable', retryable: true } as ApiErrorBody['error']))).toBe(true);
  expect(isTransient(new ApiError(404, { code: 'ALC-SYS-0001', reason: 'system.not_found', retryable: false } as ApiErrorBody['error']))).toBe(false);
});
it('retries a network failure until the job ends', async () => {
  let calls = 0;
  server.use(http.get('/api/v1/jobs/j2', () => (++calls < 3 ? HttpResponse.error() : HttpResponse.json(jobFixture({ id: 'j2', status: 'succeeded' })))));
  await expect(waitForJob('j2', { intervalMs: 1 })).resolves.toMatchObject({ status: 'succeeded' });
  expect(calls).toBe(3);
});
```

(`ApiError` is exported by `client.ts`, `ApiErrorBody` by `types.ts`.) Implement: `client.ts` exports `class NetworkError extends Error` (`name = 'NetworkError'`) and `apiFetch` rethrows a rejected `fetch` as `new NetworkError('network failure', { cause: e })`; `jobs.ts` exports `isTransient(e: unknown): boolean` = `isApiError(e) ? e.retryable : e instanceof NetworkError` and `waitForJob` uses it. Run `cd web && npx vitest run src/api` → PASS (adapt any test that expected a raw `TypeError` from a failed fetch to `NetworkError`).

- [ ] **Step 2: Certificates list, failing test first**

`CertificatesPage.test.tsx` (session `operator` through `sessionHandlers(operatorSession)`; fixed time with `vi.setSystemTime(new Date('2026-10-03T12:00:00Z'))`):

```tsx
it('lists certificates with days left, expired ones marked', async () => {
  server.use(...sessionHandlers(operatorSession),
    http.get('/api/v1/targets', () => HttpResponse.json({ items: [targetFixture], next_cursor: null })),
    http.get('/api/v1/certificates/csr', () => HttpResponse.json({ items: [] })),
    http.get('/api/v1/certificates', () => HttpResponse.json({ items: [
      certificateFixture({ id: 'c1', subject_cn: 'www.example.test', not_after: '2026-10-15T12:00:00Z', location_count: 2, has_private_key: true }),
      certificateFixture({ id: 'c2', subject_cn: 'old.example.test', not_after: '2026-09-01T00:00:00Z', location_count: 1 }),
    ], next_cursor: null })));
  await renderRoute('/certificates');
  const rows = await screen.findAllByRole('row');
  expect(within(rows[1]).getByText('www.example.test')).toBeInTheDocument();
  expect(within(rows[1]).getByText('12 days')).toBeInTheDocument();
  expect(within(rows[1]).getByText('2 websites')).toBeInTheDocument();
  expect(within(rows[1]).getByText('In Alice')).toBeInTheDocument();
  expect(within(rows[2]).getByText('Expired')).toBeInTheDocument();
  expect(within(rows[2]).getByText('Not in Alice')).toBeInTheDocument();
});

it('sends the filters to the server', async () => {
  const seen: string[] = [];
  server.use(...sessionHandlers(operatorSession), /* targets, csr as above */
    http.get('/api/v1/certificates', ({ request }) => { seen.push(new URL(request.url).search); return HttpResponse.json({ items: [], next_cursor: null }); }));
  await renderRoute('/certificates');
  await userEvent.selectOptions(await screen.findByLabelText('Expiry'), '30');
  await userEvent.selectOptions(screen.getByLabelText('Source'), 'uploaded');
  await waitFor(() => expect(seen.at(-1)).toBe('?source=uploaded&expiry=30'));
  expect(await screen.findByText('No certificates match these filters.')).toBeInTheDocument();
});

it('shows Upload and Create signing request to Operators but not to Auditors', async () => { /* auditor: neither button */ });
```

Run: `cd web && npx vitest run src/pages/CertificatesPage.test.tsx` → FAIL. Implement `CertificatesPage` as `SSHKeysPage` is built (filters in the query key, `useInfiniteQuery`, `Show more`): filters **Search** (debounced, `q`), **Server**, **Source** (`sourceAll`/`sourceDiscovered`/`sourceUploaded`/`sourceCsr`), **Expiry** (`expiryAll`/`expiryExpired`/`expiry30`/`expiry60`); table columns **Name** (`label` or `subject_cn` or `noName`, a link to `/certificates/:id`), **Expires** (`<Expiry>`), **Days left**, **Used on** (`usedOn_one/_other`), **Private key** (`keyHeld`/`keyNotHeld`); the buttons **Upload certificate** and **Create signing request** for `admin` and `operator`; `<PendingCSRs>` below the filters when there are pending requests. The table sits in a horizontally scrolling container (`WRAP`), never the page. The query string order is fixed: `target_id`, `source`, `q`, `expiry`, `cursor`, `limit` (empty values omitted) — `listCertificates` builds it in that order.

- [ ] **Step 3: Detail page, upload and CSR dialogs, failing tests first**

`CertificateDetailPage.test.tsx`: renders subject, issuer, names, serial, validity, key (`ECDSA, 256 bit`), fingerprint in `<Code>`, the chain message (complete/incomplete), the table **Where this certificate is used** (target name link, first server name, `cert_path`), the deployments list (latest five from `GET /deployments?certificate_id=`), **Deploy** shown only when `has_private_key`, not expired and the role is `admin`/`operator` (it opens Task 22's dialog; in this task the button links to `/servers/:target_id` of the first location — Task 22 replaces it), `noKey` and `expiredNoDeploy` notices.

`UploadCertificateDialog.test.tsx`:

```tsx
it('uploads PEM text and shows the chain warning', async () => {
  let body: unknown;
  server.use(...sessionHandlers(operatorSession), http.post('/api/v1/certificates/upload', async ({ request }) => {
    body = await request.json();
    return HttpResponse.json({ certificate: certificateFixture({ id: 'c9' }), warnings: ['chain_incomplete'] }, { status: 201 });
  }));
  const onDone = vi.fn();
  await renderApp(<UploadCertificateDialog opened onClose={() => {}} onUploaded={onDone} />);
  await userEvent.type(screen.getByLabelText('Certificate and chain (PEM)'), 'CERT');
  await userEvent.type(screen.getByLabelText('Private key (PEM)'), 'KEY');
  await userEvent.click(screen.getByRole('button', { name: 'Upload' }));
  expect(await screen.findByText('The chain is incomplete. An administrator must confirm before this certificate is deployed.')).toBeInTheDocument();
  expect(body).toEqual({ certificate_pem: 'CERT', private_key_pem: 'KEY' });
  expect(onDone).toHaveBeenCalledWith('c9');
});

it('shows the server message for a key that does not match', async () => {
  server.use(...sessionHandlers(operatorSession), http.post('/api/v1/certificates/upload', () =>
    errorResponse(422, 'ALC-CRT-0002', 'certificate.key_mismatch')));
  await renderApp(<UploadCertificateDialog opened onClose={() => {}} onUploaded={() => {}} />);
  await userEvent.type(screen.getByLabelText('Certificate and chain (PEM)'), 'CERT');
  await userEvent.type(screen.getByLabelText('Private key (PEM)'), 'KEY');
  await userEvent.click(screen.getByRole('button', { name: 'Upload' }));
  expect(await screen.findByText('The new certificate does not match its key. Nothing was changed.')).toBeInTheDocument();
  expect(screen.getByLabelText('Private key (PEM)')).toHaveValue('', 'the key field is cleared after a refused upload');
});

it('reads a PFX file as base64', async () => { /* FileInput with a 3-byte File; body has pfx_base64 "AQID" and pfx_password */ });
```

`CreateCSRDialog.test.tsx`: submit `www.example.test`, other names `example.test\n\nshop.example.test ` → body `{common_name: 'www.example.test', sans: ['example.test', 'shop.example.test'], key_type: 'ecdsa-p256'}`; the created request's PEM is shown in a read-only `Textarea` with **Copy request**; `PendingCSRs` lists pending requests with **Add signed certificate** (opens a dialog that posts `complete`) and **Cancel request** (confirmation dialog with **Keep request**/**Cancel request**).

Run → FAIL. Implement the components with Mantine `Modal` through the project's `AppModal`, `Textarea` (`autosize`, monospace, `spellCheck={false}`, `autoComplete="off"`), `FileInput` (accept `.pfx,.p12`), `SegmentedControl` for the format, `ErrorAlert` for API errors; the private key and PFX password fields are cleared on every response (success or error) and never stored outside the component state; `secretWarning` is shown under the key field. All copy from the contract.

Register the routes, the nav item (after **Servers**), the screens in `SCREENS` (`/certificates` ready "Certificates"/"Sertifikalar"; `/certificates/c1` ready "Where this certificate is used"/"Bu sertifikanın kullanıldığı yerler"), the audit labels and job type labels.

Run: `cd web && npm test && npm run lint && cd .. && make i18n-check`
Expected: PASS (the screens i18n test renders the new pages in EN and TR with no raw keys).

- [ ] **Step 4: Commit**

```bash
git add web/src
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "feat(web): certificates list and detail, upload and signing requests

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 22: Web — Nginx server websites panel, deploy dialog with live steps, verification settings, Deployment history, add-server type

**Files:**
- Create: `web/src/components/WebsitesPanel.tsx`, `web/src/components/DeployDialog.tsx`, `web/src/components/DeploymentSteps.tsx`, `web/src/components/LocationSettingsDialog.tsx`, `web/src/pages/DeploymentsPage.tsx`, `web/src/pages/DeploymentDetailPage.tsx`
- Modify: `web/src/pages/TargetDetailPage.tsx` (Nginx servers show `<WebsitesPanel>`; the scan button reads **Discover** for Nginx servers; the facts line `targets.facts.nginx`; carry 10: the host-keys query keeps previous data), `web/src/components/AddServerModal.tsx` (**Server type**), `web/src/pages/CertificateDetailPage.tsx` (**Deploy** opens `<DeployDialog>`), `web/src/router.tsx` (`/deployments`, `/deployments/:id`), `web/src/layout/AppLayout.tsx` (nav **Deployment history**), `web/src/locales/{en,tr}.json` (the remaining contract rows: `locations.*`, `deploy.*`, `deployments.*`, `targets.form.type*`, `targets.typeLabel.*`, `targets.facts.nginx`, `warnings.*`), `web/src/test/screens.ts`
- Test: `web/src/components/WebsitesPanel.test.tsx`, `web/src/components/DeployDialog.test.tsx`, `web/src/components/LocationSettingsDialog.test.tsx`, `web/src/pages/DeploymentsPage.test.tsx`, `web/src/pages/DeploymentDetailPage.test.tsx`, `web/src/components/AddServerModal` tests in `TargetsPage.test.tsx`, carry 12 in `TargetDetailPage.test.tsx`

**Interfaces:**
- Consumes: Task 21 types, endpoints, `Expiry`; `waitForJob`, `useAbort`.
- Produces: `DeployDialog` props `{ opened: boolean; onClose(): void; certificate?: Certificate; location?: CertificateLocation }` (from a certificate: choose websites; from a website: choose a certificate), `DeploymentSteps` props `{ steps: DeploymentStep[]; status: DeploymentStatus; detailed?: boolean }`.

- [ ] **Step 1: Write the failing tests**

`DeployDialog.test.tsx` (the heart of owner step 2):

```tsx
it('deploys to a website and shows the five steps turning green', async () => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
  const steps: DeploymentStep[] = [];
  let status: DeploymentStatus = 'running';
  server.use(...sessionHandlers(operatorSession),
    http.get('/api/v1/certificates', () => HttpResponse.json({ items: [certificateFixture({ id: 'new', subject_cn: 'www.example.test',
      has_private_key: true, key_algorithm: 'ecdsa' })], next_cursor: null })),
    http.post('/api/v1/certificates/new/deploy', () => HttpResponse.json({ deployments: [{ id: 'd1', job_id: 'j1', location_id: 'l1',
      status_url: '/api/v1/jobs/j1', warnings: [] }] }, { status: 202 })),
    http.get('/api/v1/deployments/d1', () => HttpResponse.json(deploymentFixture({ id: 'd1', status, steps: [...steps] }))));
  await renderApp(<DeployDialog opened onClose={() => {}} location={locationFixture({ id: 'l1', key_type: 'ecdsa' })} />);
  await userEvent.selectOptions(await screen.findByLabelText('Certificate'), 'new');
  await userEvent.click(screen.getByRole('button', { name: 'Deploy' }));
  const list = await screen.findByRole('list', { name: 'Steps' });
  for (const name of ['Backup', 'Write', 'Check', 'Reload', 'Verify']) {
    expect(within(list).getByText(name)).toBeInTheDocument();
  }
  expect(within(list).getAllByText('Waiting')).toHaveLength(5);
  steps.push(...['backup', 'write_key', 'write_cert', 'config_test', 'reload'].map((n, i) => step(i + 1, n, 'ok')));
  await vi.advanceTimersByTimeAsync(1_000);
  expect(await within(list).findAllByText('Done')).toHaveLength(4);
  steps.push(step(6, 'verify', 'ok'));
  status = 'succeeded';
  await vi.advanceTimersByTimeAsync(1_000);
  expect(await screen.findByText('The new certificate is live and verified.')).toBeInTheDocument();
  expect(within(list).getAllByText('Done')).toHaveLength(5);
  vi.useRealTimers();
});

it('reports a rollback with the reason and the restore steps', async () => {
  // deployment status rolled_back, error {code ALC-DEP-0006, reason deployment.reload_failed}, steps backup/write ok, reload failed,
  // restore, rollback_config_test, rollback_reload ok, verify_old ok:
  // shows "Nginx did not reload." (the error title), "Your server was restored to its previous certificate.", Reload "Failed",
  // and the restore rows under the five steps.
});

it('offers only certificates with a key and the same key type', async () => {
  // certificates: ecdsa with key, rsa with key, ecdsa without key, expired ecdsa with key → only the first is an option;
  // no candidate → "Alice holds no certificate with a private key that fits this website. Upload one first."
});

it('needs an Administrator for an incomplete chain', async () => {
  // operator: the certificate with chain_complete false shows deploy.chainAdminOnly and the Deploy button is disabled;
  // admin: the checkbox "I confirm that this incomplete chain is intended" must be ticked; the request body has confirm_incomplete_chain true.
});

it('deploys one certificate to several websites and summarizes', async () => {
  // from a certificate: two websites ticked → body location_ids ['l1', 'l2']; one ends succeeded, one rolled_back →
  // "Updated websites: 1 of 2" (deploy.partial) and a link "Open deployment history".
});
```

`WebsitesPanel.test.tsx`: an Nginx target with locations → rows with the website name (the first server name, `(default server)` for `_`), the ports (`443`), `cert_path` in `<Code>`, `<Expiry>`, state **Ready** or **Not supported** with the reason text (`locations.unsupported.<reason>`, and for `file_problem` the `locations.problems.<problem>` text), warnings (`symlinked`, `custom_location`, `key_mode_open` with `{{mode}}`, `certificate_expired`, `san_mismatch` with `{{site}}` = the website), **Deploy certificate** (accessible name "Deploy certificate: www.example.test") for `admin`/`operator` on supported rows only, **Verification settings** for `admin` only, `deploying` badge when `active_deployment_id` is set; the **Discover** button posts `/targets/{id}/actions/discover` and waits for the job; the `configInvalid` alert when `target.facts.nginx.config_valid` is false; **Show websites that are no longer found** adds `?missing=true`.

`LocationSettingsDialog.test.tsx`: PATCH with `If-Match: "3"`, body only the changed fields, `0` and `""` clear; 412 shows the existing "changed while you were editing" error; the skip switch shows `skipHelp`.

`DeploymentsPage.test.tsx` / `DeploymentDetailPage.test.tsx`: list rows (time in the user's format, server, `cert_path`, certificate name, the status label), **Show more** pages with `next_cursor`; detail shows the steps (`DeploymentSteps detailed`, including `verify_current`), requester, previous/new fingerprints, `backup_dir` for `rollback_failed`, the error title/cause/action through `ErrorAlert`.

`TargetsPage.test.tsx`: the Add server modal has **Server type** (**Linux server**/**Nginx server**, help `typeHelp`); choosing Nginx sends `type: 'nginx'`. `TargetDetailPage.test.tsx`: carry 10 — the re-pin dialog does not flash "no candidate" while the host-keys query refetches (the query uses `placeholderData: keepPreviousData`; assert the candidate stays visible during a refetch); carry 12 — the test that waited a real 3 s poll uses fake timers.

Run: `cd web && npx vitest run src/components src/pages` → FAIL.

- [ ] **Step 2: Implement**

- `DeploymentSteps`: an ordered `<List aria-label={t('deployments.stepsTitle')}>` (accessible name "Steps"/"Adımlar") of the five owner-visible steps (contract "UI step grouping"), each with an icon (`Loader` running, check `ok`, cross `failed`, dash `waiting`/`skipped`) and the status label from `deployments.stepStatus.*`; with `detailed`, `verify_current` first and the rollback steps after. Status for a grouped step: the last event of its member steps.
- `DeployDialog`: the certificate select lists `listCertificates()` items with `has_private_key`, not expired (`daysLeft > 0`), and `key_algorithm === location.key_type` (or any when `key_type` is `''`); from a certificate, a checkbox list of its supported locations (from `getCertificate`). After **Deploy** it shows `deploy.working`, polls `getDeployment` every second (through `useAbort`; stops on unmount) until a terminal status, then the outcome text: `succeeded` (+ `verifiedLocally` when `verified === 'local'`), `unchanged`, `failed` (`noChange` + the error), `rolled_back` (`rolledBack` + the error), `rollback_failed` (`rollbackFailed` + the error with `backup_dir`), `needs_attention` (`recovering`); after 120 s without an end, `stillWorking` with `openHistory`. Several deployments: one `DeploymentSteps` per website and `deploy.partial`. `san_mismatch` warnings from the 202 answer are shown with `locations.warnings.san_mismatch`.
- `WebsitesPanel`, `LocationSettingsDialog`, `DeploymentsPage`, `DeploymentDetailPage` as the tests describe; tables in `WRAP` containers; fingerprints and paths in `<Code>`, never case-transformed.
- `TargetDetailPage`: `target.type === 'nginx'` renders `<WebsitesPanel target={target} />` above the SSH keys and labels the scan button `locations.discover`; the facts list adds `targets.facts.nginx` when `facts.nginx.version` is set; the host-keys `useQuery` gets `placeholderData: keepPreviousData`.
- `AddServerModal`: `NativeSelect` **Server type** (default `linux`), sent as `type`.
- Routes, nav item **Deployment history** (after **Certificates**), `SCREENS` entries (`/deployments` ready "Deployment history"/"Dağıtım geçmişi"; `/deployments/d1` ready "Steps"/"Adımlar"; `/servers/<nginx target>` ready "Websites on this server"/"Bu sunucudaki web siteleri").

Run: `cd web && npm test && npm run lint && cd .. && make i18n-check`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add web/src
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "feat(web): Nginx websites, deploy with live steps, verification settings and deployment history

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 23: End-to-end — Phase 4 owner journeys in EN and TR, the Phase 3 dismissal carry, accessibility

**Files:**
- Create: `web/e2e/phase4.spec.ts`
- Modify: `web/e2e/helpers.ts` (`newCert(name, broken?)`, `reloadMode(mode)`, `served(name)`, `fingerprintHex(pem)`), `web/e2e/phase3.spec.ts` (carry 5)
- Modify: `test/images/e2e-target/alice-e2e-rotate-hostkey` (saves the previous key files in `/root/hostkeys.prev` first); create `test/images/e2e-target/alice-e2e-restore-hostkey` (puts them back and sends `SIGHUP` to the listening sshd) and copy it in the `Dockerfile`

**Interfaces:**
- Consumes: the e2e target of Task 19 (`alice-e2e-prepare`, `alice-e2e-newcert`, `alice-e2e-reload-mode`, `alice-e2e-served`), the UI copy of Tasks 21–22, `settle`, `drainJobs`, `expectAccessible`, `expectWide`, `advanceClock`.

- [ ] **Step 1: Helpers**

In `helpers.ts`:

```ts
export interface PemPair { cert: string; key: string }

// newCert asks the e2e target for a fresh certificate (leaf + test CA) and key for name; broken
// returns a key of another certificate (owner step 4).
export function newCert(name: string, broken = false): PemPair {
  const out = targetExec(['/usr/local/sbin/alice-e2e-newcert', name, ...(broken ? ['--broken'] : [])]);
  const m = out.match(/-----ALICE CERT-----\n([\s\S]+?)-----ALICE KEY-----\n([\s\S]+?)-----ALICE END-----/);
  expect(m, 'alice-e2e-newcert output').not.toBeNull();
  return { cert: m![1], key: m![2] };
}

export function reloadMode(mode: 'ok' | 'fail-once' | 'fail' | 'noop'): void {
  targetExec(['/usr/local/sbin/alice-e2e-reload-mode', mode]);
}

// served is the SHA-256 (lower-case hex) of the certificate the target serves for name.
export function served(name: string): string {
  return targetExec(['/usr/local/sbin/alice-e2e-served', name]).trim();
}
```

and `fingerprintHex(pem: string): string` computing the SHA-256 of the first certificate's DER with Node's `crypto.X509Certificate` (`new X509Certificate(pem).fingerprint256` without colons, lower-cased with `toLocaleLowerCase('en-US')` — test code, ASCII only).

- [ ] **Step 2: Write the journeys**

`phase4.spec.ts`, for each language (`for (const lang of ['en', 'tr'] as Lang[])`, as `phase3.spec.ts`), with a copy table `P4[lang]` taken verbatim from the contract's UI copy (EN and TR columns) and the error texts of `ALC-CRT-0002` and `ALC-DEP-0006`:

1. `owner journey: discover, upload, deploy, verify, broken pair, rollback, history` (§26.6 owner steps 1–5):
   - `resetInstall`, wizard, sign in as the Administrator; **Servers** → **Prepare a server for Alice** → **Server type** **Nginx server** → **Copy commands** (read the script from the page as phase 3 does) → `targetExec(['/usr/local/sbin/alice-e2e-prepare'], script)`.
   - **Add server** with **Server type** **Nginx server**, address `sshtarget`; confirm the fingerprint (compare with `ssh-keygen -lf` on the target, as phase 3); `settle` until **Connected**.
   - On the server's page choose **Discover**; `settle`; the panel **Websites on this server** lists `www.example.test` with a days-left value (`/\d+ (days|gün)/`) and **Ready**, and `files.example.test` with **Not supported** and the `variable` reason text.
   - **Certificates** → **Upload certificate** → paste `newCert('www.example.test')` (leaf and the self-signed test CA: a complete chain) → **Upload** → **Certificate uploaded.**, no chain warning; the certificate appears with **In Alice**.
   - Back on the server, **Deploy certificate: www.example.test** → choose the uploaded certificate → **Deploy** → `settle` until **The new certificate is live and verified.**; the steps list shows **Backup**, **Write**, **Check**, **Reload**, **Verify** each **Done**; `served('www.example.test')` equals `fingerprintHex(cert)` (owner step 3).
   - Broken pair (owner step 4): **Upload certificate** with `newCert('www.example.test', true)` → the dialog shows "The new certificate does not match its key. Nothing was changed." (TR title in Turkish); `served` is unchanged.
   - Automatic rollback (the e2e substitute for F-01, R38 item 10): upload another good pair, `reloadMode('fail-once')`, deploy it → the dialog ends with **Your server was restored to its previous certificate.** and the reload error title; **Reload** shows **Failed**, **Restore** **Done**; `served` still equals the previously deployed certificate; `reloadMode('ok')`.
   - **Deployment history** (owner step 5) lists exactly two deployments (the broken pair was refused at upload, so it never became one): the success and the rollback (**Failed, restored**); open the rolled-back one: its steps include **Restore** and **Verify the previous certificate**.
   - The audit log (Administrator) shows **Certificate uploaded**, **Certificate upload refused**, **Deployment requested**, **Certificate deployed**, **Deployment failed**, **Previous certificate restored**.
2. `an Operator deploys, an Auditor only reads`: an Operator (created on **Users**) sees **Deploy certificate** but not **Verification settings**, uploads `newCert('www.example.test')` and deploys it to `www.example.test` (**The new certificate is live and verified.**); an Auditor sees neither **Upload certificate** nor **Deploy certificate** and reads the certificate, server and history pages.
3. `verification settings (Administrator)`: open **Verification settings** for `www.example.test`, set port `443` and name `www.example.test`, **Save** → **Settings saved.**; the audit log shows **Verification settings changed**.
4. `lock refuses deployments and keeps the certificates readable (L-29)`: move the demo clock past the evaluation (as phase 3's L-26 test does), the Certificates page and the server's websites still load, **Upload certificate** answers the `license.locked` message.
5. Accessibility: `expectAccessible` on **Certificates**, the certificate page, the server page with websites, the deploy dialog (open, and after the outcome), the upload dialog, the signing-request dialog, **Deployment history** and a deployment page, at 640/1280/1920 px; `expectWide` (375 px, no horizontal page scroll) on **Certificates**, **Deployment history** and the server page.

- [ ] **Step 3: Phase 3 carry 5**

In `phase3.spec.ts`, a new test `a dismissed identity change: the server still shows the previous fingerprint` (both languages): after the changed-host-key step, restore the previous host keys on the target with `alice-e2e-restore-hostkey`, open **Review the new fingerprint**, choose **The server still shows the previous fingerprint**, enter a reason, confirm with step-up; expect **Connected** after `settle`, the audit entry for the dismissal, and no candidate left in the dialog.

- [ ] **Step 4: Run**

Run (Docker: the `alice-e2e` project only): `make e2e-up && make e2e-hardening-check && make e2e`, then `make e2e-down`.
Expected: all Phase 1–4 suites pass in EN and TR.

- [ ] **Step 5: Commit**

```bash
git add web/e2e test/images/e2e-target
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "test(e2e): Phase 4 certificate journeys in English and Turkish; dismissal of an identity change

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 24: Coverage floors, documentation, R38, security review, `make ci`

**Files:**
- Modify: `coverage-floors.json`
- Modify: `docs/nginx-host-preparation.md` (the `nginx` profile: what each of the five `nginx-*` lines allows, what `tls-probe` does without sudo, the files the helper reads and writes and how it decides — referenced pairs only, root-controlled paths, backups in `/var/lib/alice-helper/backups/<deployment id>` kept 7/30 days; how to restore a backup by hand; changing a Linux server to an Nginx server = re-run the setup with the Nginx profile, delete and add the server again)
- Modify: `docs/operator-guide.md` (Certificates, upload and signing requests, deploying, what each step means, the outcomes and what to do, Deployment history, interrupted deployments), `docs/admin-guide.md` (verification settings, incomplete chains, the emails), `docs/troubleshooting.md` (already has the codes; add the "Deployments" section of symptoms), `CHANGELOG.md` (Unreleased — Phase 4)
- Modify: `docs/superpowers/specs/alice-v1/00-decisions.md` (R38), `docs/superpowers/specs/alice-v1/03-integrations.md` (a "(Phase 4, R38 …)" note under §12.3 and §12.6, as R37 notes were added)
- Create: `docs/security/reviews/phase-4.md`

- [ ] **Step 1: Coverage**

Run: `make coverage` (Docker: integration tests)
Then add floors for the new packages at their measured values rounded down, and raise (never lower) existing floors that rose: `alice/internal/certs`, `alice/internal/providers/nginx`, `alice/internal/providers/nginx/nginxconf`, `alice/internal/jobs/deployjobs` (`internal/testutil/pki` has no floor). Run `make coverage` again → every package ok.

- [ ] **Step 2: R38**

Append to `00-decisions.md` a line `- R38 (Phase 4, approved with the Phase 4 plan; corrected to the built code at the end of Phase 4) Accepted Phase 4 implementation decisions: (1) … (21) …` that restates each row of this plan's "Spec conflicts resolved" table as built (helper protocol 4 and its subcommands, path rules, modes, unsupported constructs, relative paths, fixed binaries, verification and probes, deployment states, recovery and the sweep, lock classes of the certificate routes, F-01 and the e2e substitute, upload rules, permissions, what is not built, backups, emails, the nightly job, target types, multi-location deploys, change detection, the Phase 3 carries, codes and audit actions) — corrected to what was actually built, as R37 was.

- [ ] **Step 3: Security review**

Create `docs/security/reviews/phase-4.md` with the structure of `phase-3.md`: scope (§17.2 Phase 4: atomic deploy, rollback, path validation, private key handling; exit: fault-injection tests leave the server unchanged), an **Evidence** table (commands and expected results: helper unit and root tests — including the attack tests —, `make test-ssh`, `go test ./internal/providers/nginx/...`, `make fuzz-nginx`, `make fuzz-certs`, `go test -tags integration ./internal/jobs/deployjobs/...` (F-66, L-80..L-82), the inventory and API integration suites, the leak suite with TLS keys, the authz matrix and lock rules, migrations grants, coverage, e2e), a **Review checklist** (the Helper rule of the Global Constraints point by point; key material only on stdin and in envelopes; `log_input` never set; the only `InsecureSkipVerify` in `helperproto.ProbeTLSConfig`; nginx's own error text never leaves the helper; no raw `nginx -T` text leaves the server; recovery is `ClassAlways`; the sweep cannot deploy), **Findings** (at least: P4-01 High residual — whoever controls Alice, or the database and master key, can deploy any certificate and key to every referenced path of every Nginx server and so serve any website's TLS; same trust boundary as P3-01; P4-02 Medium — a local user who can edit an Nginx `include` file can make the helper write a certificate or key to any existing root-controlled file with a certificate or key extension that the configuration names; mitigated by the extension rule, the "custom location" mark and the `config_file_writable` warning; P4-03 Low — the verification probe dials the target's address on any port named by the configuration or an Administrator; P4-04 Low — key material in the helper's memory is cleared best-effort only (Go strings from JSON); P4-05 Info — backups of private keys stay root-only on the server for 7–30 days), **Known limitations** (Phase 4: no private-key download yet; no retry/rollback buttons on a deployment; the real-systemd job waits for Phase 8; `restorecon` not run; F-03 and F-04 are distinguished on real Nginx only with the shim's `fail-once`; a recovery that cannot reach the server retries every 15 minutes indefinitely and emails once; combined certificate/key files, encrypted keys, engine keys, variables and stream TLS are not managed; the `nginx` binary path is fixed; verification reaches websites from Alice's network or from the server's loopback only; Phase 1–3 limitations still apply), and an **Owner verification** section with the §26.6 owner steps written for the owner (prepare an Nginx test server with `make helper` and the Nginx commands, add it as an **Nginx server**, **Discover**, upload the good pair from `go run ./tools/testcerts -out ~/alice-test-pack -name <your test site>`, **Deploy**, check the website in a browser, upload the broken pair, **Deployment history**) and an empty results table:

| Step | Result (pass, or what differed) | Date and tester |
|---|---|---|
| 1 | | |
| 2 | | |
| 3 | | |
| 4 | | |
| 5 | | |

Sign-off left empty.

- [ ] **Step 4: Full CI**

Run: `make ci` (Docker: `alice:ci` image and the `alice-e2e` project only; it ends with `make e2e-down`)
Expected: every stage passes (`lint`, `test`, `coverage`, `build`, `release-symcheck`, `i18n-check`, `web-lint`, `web-test`, `vuln`, `secrets-scan`, `fs-scan`, the e2e stack with hardening check and Playwright, `image-scan`). If `secrets-scan` flags a test fixture, add the finding to `.gitleaksignore` with the commit hash in this task.

- [ ] **Step 5: Commit**

```bash
git add coverage-floors.json docs CHANGELOG.md
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "docs: Phase 4 guides, R38, security review and coverage floors

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```
