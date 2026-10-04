# Audit Remediation (independent audit of 2026-10-04) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close every open finding of the owner's independent audit (`docs/security/reviews/independent-audit-2026-10-04.md`, AUD-01..AUD-25) that the Phase 4 fix wave did not close, so that: every account sshd accepts keys for is either inventoried or visibly reported (never silently skipped); an unattended browser tab is signed out after 30 minutes however often the web UI polls; the license gate cannot be held open by stopping its evaluation; and the smaller hardening, robustness, supply-chain and build-gate findings are fixed or recorded with a reason.

**Architecture:** One helper change (protocol 6, `alice-helper` 1.5.0) carries both helper findings: `authkeys-list` lists account names of a wider, explicit grammar (`helperproto.ValidAccount`), reports every `/etc/passwd` entry it cannot list (`unlisted`, uid and reason only) and marks the account list incomplete, and returns the content of the files it already reads for their hash (`inline`), so a discovery needs one root scan instead of one per file. The session layer separates a person's activity from background polling: only state-changing requests and reads marked `X-Alice-Activity: 1` by the web UI (which marks the first request after a real input event) slide the idle timeout. The license gate stops trusting a snapshot blindly: it advances the last evaluation's trusted time by monotonic uptime and locks at `LocksAt` by itself, fails closed (`license.unverified`) when no evaluation succeeded for 3 hours, and `license.evaluate` runs in every process with bounded lock waits. The remaining findings are local fixes in `internal/api`, `internal/auth`, `internal/license`, `internal/setup`, `internal/secrets`, a new `internal/platform/netaddr`, the web UI, `deploy/`, the `Makefile`, the CI workflow and a new `tools/pincheck`.

**Tech Stack:** unchanged from Phase 4 (Go 1.27.1, pgx v5, goose v3, testify, testcontainers-go; React 18 + TypeScript 6 + Vite 8, Mantine 8, TanStack Query 5, i18next, Vitest 5 + msw 2, Playwright 1.63). One new web dev dependency: `@vitest/coverage-v8` 5.0.3 (Task 16, spec §22.7 TS coverage gate).

**Sources:** the audit (read it whole; it is in Turkish; findings in §4, order in §7) and its proof-of-concept tests in `docs/security/reviews/independent-audit-2026-10-04-poc/*.txt` (the regression tests of this plan are adapted from them under new names; the `.txt` files are never copied in as they are). The audit file and the PoC directory are **untracked and never edited, moved or committed**. Spec: `docs/superpowers/specs/alice-v1/` — `00-decisions.md` (R35, R36 addendum (j), R37, R38 — this plan adds **R39**), `04-security.md` (SEC-004, SEC-019, SEC-020, SEC-062, SEC-065, SEC-070, SEC-075, SEC-089, SEC-103), `06-quality.md` (§22.7, §25.3, §25.4 A-02, §26.6), `02-architecture.md` (sessions table). Earlier rulings: `docs/superpowers/rulings/phase-4.md` ("Final review and fix wave", "Parked / carried to Phase 5"). Style reference: `docs/superpowers/plans/2026-10-03-phase-4-nginx-certificates.md`.

**Plan verification:** written against branch `audit-remediation` at `57b11fb` (= `master`, Phases 0–4 merged). Every path, symbol, route, Make target and command was checked with `grep`/`sed` in that tree, among them: `helperproto.{Protocol,Version,ValidUser,ValidPath,ValidArg,AuthKeysListResponse,UserFiles,FileInfo,MaxAccountNames,MaxAuthorizedKeysSize,WarnTooManyUsers,WarnDirectoryUsers}`, the helper's `account`, `accounts`, `toScan`, `accountNames`, `loginShell`, `nobodyUID`, `maxUsers`, `scan`, `scanResult`, `fileInfo`, `readCandidate`, `cmdAuthKeysList`, `sudoUserName`, the helper `fixture` (`newFixture`, `run`, `write`, `read`, `mkdir`, `sshdCalls`, `uid`, `skipOddUID`, `filesOf`, `listUser`), `linuxssh.{Discover,discoverFile,readFile,readFileOwner,warn,warningCodeRE,maxDiscoverWarnings,precheck,Dialer.handshake,Dialer.NetDial}`, `linuxsshtest.{Emulator.AddUser,SetAccounts,FailRead,listLocked,scanLocked,Server.SetHandler}`, `provEnv`/`newProvEnv`, `auth.{Service.Authenticate,SessionIdle,Login,lockLoginName,Hasher.DummyVerify,ResetPassword,RevokeSessions,revokeUserSessions,adminChange,BootstrapAdmin}`, `auth` `export_test.go` (`SetCredentialSlotHook`, `LoginNameLockNamespace`), the auth `env` (`newEnv`, `bootstrap`, `principal`, `countAction`, `setFailures`), `api.{guard,authenticate,allowRate,auditDenied,auditLicenseDenied,licenseAllows,gated,decodeBody,decodeExact,exportAudit,writeAuditCSV,verifyAudit,probeRoutes,newServer,ResetLimits,errorMap,classify,AuthService,LicenseService}`, the API `stack`/`client` (`installed`, `installedWithOperator`, `freshClient`, `deps`, `handler`, `logs`, `signIn`, `stepUp`, `count`, `countWhere`, `withHeader`, `withoutHeader`, `requireError`, `requireStatus`), `fakeAuth`, `fakeSetup`, `testDeps`, `license.{Service.Allow,allowIn,Snapshot,tickLocked,loadInstallation,ensureInstallation,sealUnsealed,everSealed,ParseFile,checkStructure,Banners,ErrLocked}`, the license `env` (`newEnv`, `tickAt`, `restart`, `upload`, `payload`, `ownerExec`, `countWhere`, `auditCount`, `auditDetails`, `day`, `installedAt`), `jobs.{Scheduler.loopWith,LicenseEvaluate,NewLeader}`, `setup.{CreateAdmin,ResetToken,Authenticate}`, `secrets.createKeyFile`, `inventory.{checkAddr,notAServer,decodeCursor}`, `jobs.decodeCursor`, `ratelimit.Limiter`, `cmd/alice/compose_test.go`, the web `apiFetch`, `onUnauthorized`, `LicenseBanners`, `StepUpProvider`, `BlockedJobsPanel`, `AuditPage`, `WARNING_PARAMS`, `main.tsx`, `router.tsx`, the e2e helpers (`runWizard`, `signIn`, `advanceClock`, `either`, `ADMIN`), and the Make targets `test`, `test-integration`, `test-ssh`, `helper`, `build`, `lint`, `vuln`, `secrets-scan`, `fs-scan`, `image`, `image-scan`, `release-symcheck`, `i18n-check`, `web-install`, `web-test`, `web-lint`, `coverage`, `authz-doc`, `e2e-up`, `e2e`, `e2e-down`, `e2e-hardening-check`, `ci`. The plan has **not** been compiled: before Task 1 the controller runs the pre-flight scan earlier phases used (apply each task's code in a scratch worktree and compile it); every task's red/green steps are the real check. Where a sketch says "mirror" or names a grep, the implementer reads the code named before writing.

---

## Status of the audit's findings (verified at 57b11fb)

### Already closed in the Phase 4 fix wave — not planned again

Each was checked in the code, not only in the review documents.

| AUD | Evidence in the tree | Closed? |
|---|---|---|
| AUD-04 (a) discovery unbounded, no job time limit | `internal/providers/linuxssh/discover.go:22-38` (`maxDiscoverUsers` 200, `maxDiscoverFiles` 1000, `maxDiscoverKeys` 10000, `maxDiscoverWarnings` 500, `discoverBudget` 10 min, `list_truncated`); `internal/jobs/targetjobs/targetjobs.go:186` (`discoveryTimeout = 20 * time.Minute`); commits d375100, 73e71c8; P4-45 | Yes |
| AUD-04 (b) huge RSA certificate, parsing inside the row lock | `internal/certs/certs.go:25-27,119-126` (`maxRSABits = 16384` checked before any signature check); files parsed before the scan's transaction (1191814, `TestDiscoveryParsesFilesCheaplyAndOutsideTheTransaction`); P4-26 | Yes |
| AUD-05 late-starting helper | `nginx-fence` (`helperproto.SubNginxFence`, protocol 5), `internal/providers/nginx/deploy.go:846` `FenceDeployment`, used by `internal/jobs/deployjobs/recover.go` and `deployjobs.go`; the 60-second rule is gone; commits 83522dd, 59601fe, d44d50f (real matrix), e0cd19e; P4-38, P4-49 | Yes |
| AUD-07 e2e port on all interfaces | `deploy/docker-compose.e2e.yml` publishes `127.0.0.1:${ALICE_E2E_PORT:-9443}:8443`; pinned by `cmd/alice/compose_test.go` (`TestE2ETargetIsTestOnlyAndUnpublished`) and by `deploy/dev/check-hardening.sh:49-51` ("alice (e2e) publishes only on 127.0.0.1") | Yes |
| AUD-10 handshake drop classified as auth failure | `internal/providers/linuxssh/dial.go:361-408,450-457,482` (EOF/reset/closed → `ssh.unreachable`, retryable); commits 4abe22d, 02fbc36, 79d0382; P4-44, P4-50 | Yes |
| AUD-14 signing-request key generation | `internal/inventory/csr.go:72-92,157` (generation slots, `ErrCSRBusy`, `maxPendingCSRs`, nothing generated once the caller has gone); commits 715c908, 8a163c9; P4-27 | Yes |
| AUD-17 chain rewritten by a scan; completion | 92c5e10, 1191814, 2854564 (held certificate's chain only from a person; attach takes the uploader's chain, trigger `Z1004`), a6a5ee7 (re-upload with a complete chain completes it, `certificate.chain_completed`); P4-25, P4-46 | Yes |

### Planned here

AUD-01, AUD-02, AUD-03, AUD-06, AUD-08 (the part without a remote), AUD-09, AUD-11, AUD-12, AUD-13, AUD-15, AUD-16, AUD-18, AUD-19, AUD-20, AUD-21, AUD-22, AUD-23, AUD-24, AUD-25 (a)–(d). Each was re-verified in the current tree; the task that fixes it quotes the current file and line. None no longer applies. Two differ from the audit's text: AUD-13's cursor cases (`TestZZAuditQueryBytesAnswer500` logs them) are real for `internal/jobs/queue.go:346` and `internal/inventory/sshkeys.go:420` (`time.UnixMicro` of any int64 reaches PostgreSQL), and AUD-23's "real-systemd job" deferral is already recorded in R38 item 16 — only the spec text of §26.6 still states it as a Phase 4 criterion (Task 17 adds the note).

### Process gaps and owner-pending items (no task, recorded in Task 17's review document)

- **AUD-08 remote and first CI run (owner):** create a remote, push `master` and the phase branches, watch the first run of `.github/workflows/ci.yml` (including the `ssh-matrix` job and the `licensectl` job on macOS, spec §26.4, which has never run), and set branch protection with the CI jobs as required checks. Pushing or creating remotes is the owner's decision; Task 16 only makes the workflow run on every branch.
- **Production license key** (`internal/license/keys/production.json` is empty; `make release-keycheck` fails by design, R36).
- **Owner walkthroughs** of Phases 1–4 (the result tables in `docs/security/reviews/phase-*.md` are empty), the Turkish tone review and the crypto sign-off.
- **A full green `make ci` on a clean, idle machine**, including `image-scan` (the audit observed 54/56 Playwright passes under load and no image scan). Task 17 runs `make ci` on the implementer's machine; the clean-machine run stays with the owner.
- **Real-systemd Nginx job:** deferred to Phase 8 by R38 item 16; Task 17 adds the pointer to spec §26.6.

---

## Global Constraints

- Go module path is `alice`; toolchain `go 1.27.1`. Every shell step assumes `export PATH="$HOME/.local/go/bin:$HOME/go/bin:$PATH"` and the repository root as working directory.
- All code, identifiers, comments, file names, commit messages and technical docs are in English. Turkish appears only as translation values in `tr.json` files.
- Commits: Conventional Commits, made with `git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit`, the message ending with a `Co-Authored-By:` line that names the model that wrote the commit (for this model: `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`). Every commit body names the findings it closes as `Refs: AUD-NN[, AUD-NN]` (Task 17 builds the review document's commit map from `git log --grep 'AUD-'`). Never squash, rebase or amend: `.gitleaksignore` is pinned to commit hashes, so the branch merges into `master` fast-forward only.
- **Never add** `docs/security/reviews/independent-audit-2026-10-04.md`, `docs/security/reviews/independent-audit-2026-10-04-poc/` or `.claude/` (use explicit paths with `git add`, never `git add -A` or `git add .`).
- **Docker safety:** the owner's live compose project `alice` (image `alice:dev`, volumes `alice_*`) is never touched: no `make up`, `make down`, `make reset`, `make logs`, `make setup-token`, `make unlock`, `make hardening-check`, no `docker compose` without `-p alice-e2e`, no `docker system/volume/image prune`, no `docker rm` of containers you did not create. Allowed: testcontainers (integration tests), `docker run --rm` throwaway containers, `docker create`/`docker cp`/`docker rm` of a container created from `alice:ci` in the same step, `docker buildx imagetools inspect` (read-only registry query), and the e2e project `alice-e2e` (`make e2e-up`, `make e2e`, `make e2e-down`, port 127.0.0.1:9443). Never run Docker test containers (integration tests, `make test-ssh`, the root helper suite) while Playwright runs: Chromium aborts requests whenever a host interface changes. Every step that runs Docker says so.
- **Helper change procedure (Tasks 2 and 3, marked HELPER):** (1) `go test ./cmd/alice-helper -count=1` as a normal user; (2) the root-only tests as uid 0 in a throwaway container: `CGO_ENABLED=0 go test -c -o /tmp/alice-helper.test ./cmd/alice-helper && docker run --rm --network none -v /tmp/alice-helper.test:/alice-helper.test:ro debian:12 /alice-helper.test -test.count=1` (the whole suite as root, Docker); (3) `make helper` (new `bin/alice-helper.sha256`; `make build` and the image embed the new checksums); (4) `make test-ssh` (Docker; the real OpenSSH and Nginx matrices); (5) the emulator and its fidelity tests (`go test ./cmd/alice-helper -run Fidelity -count=1`). The protocol bumps **once**, to 6 (`alice-helper` 1.5.0), in Task 1; Tasks 2 and 3 stay on it. The sudoers lines do not change.
- **Secrets in the repository:** no private key, certificate or password is committed; test PKI comes from `internal/testutil/pki`, SSH keys from `ssh-keygen` at image build time (`test/images/sshd/fixtures.sh`). If `make secrets-scan` flags a test file, add the finding to `.gitleaksignore` with the new commit hash in the same task (Task 16 narrows the lockfile path exemption).
- Lint is golangci-lint v2 (`make lint`): gosec, errorlint, forbidigo, bodyclose, misspell, noctx, gofmt, goimports (`local-prefixes: alice`). Forbidden: `fmt.Print*`, `strings.ToUpper`/`ToLower`/`Title`, `time.Now` outside `internal/platform/clock` and tests (use the injected clock; for an absolute network deadline use `clock.Real{}.Now()`), `ssh.InsecureIgnoreHostKey`. No `//nolint` without a reason. Run `gofmt -w` on every changed Go file.
- Tests: stdlib `testing` plus testify `require`/`assert`; small hand fakes; integration tests carry `//go:build integration` and use `pgtest`. Coverage floors in `coverage-floors.json` are **never lowered** (`internal/providers/linuxssh/helperproto` is at 100: every new branch there needs a test).
- Module import rules (`internal/archtest`) hold; Task 13's `internal/platform/netaddr` is under `alice/internal/platform/...`, which every rule allows.
- API JSON conventions from Phase 1 (error body `code`, `reason`, `message_key`, `message`, `request_id`, `retryable`, `params`, `details`). Every new code `ALC-<AREA>-<NNNN>` gets `errors.<reason>.title|cause|action` in `locales/common/{en,tr}.json`, a section in `docs/troubleshooting.md` and an entry wherever its neighbours are listed (enforced by `internal/api/errors_test.go` and `errors_catalogue_test.go`).
- i18n: every user-visible string is a key in English and Turkish (`make i18n-check`); placeholders `{{name}}` without spaces; no suffix attached to a placeholder; formal-polite Turkish ("siz").
- Audit detail keys pass the denylist of `internal/audit/audit.go:216` (`password`, `token`, `key`, `session`, `code`, … segments are refused unless the key ends in `id`, `prefix` or `count`): this plan uses `suppressed_count`, `revoked_token_count`, `reason`, `class`.
- Frontend: no `dangerouslySetInnerHTML`, no `toUpperCase`/`toLowerCase`; account names, paths and fingerprints are rendered as text with `<Code>`/monospace, never case-transformed.

## Decisions made in this plan

Each: decision — why — cost if wrong. They are restated in R39 (Task 17) so they can be reversed.

1. **AUD-01, what counts as activity:** a full session slides its idle timeout only on a state-changing request (any method but GET/HEAD) or on a read carrying `X-Alice-Activity: 1`; every other authenticated read is answered without touching `idle_expires_at` or `last_seen_at`. The web UI sets the header on every non-GET request and on the first request after a trusted `pointerdown`, `keydown`, `wheel` or `touchstart` event (and on the first request after a page load); pointer movement and focus changes do not count. — why: the server cannot tell a poll from a person by route (the same `GET /jobs/{id}` is both); a client marker that is absent by default is fail-safe (a request that forgets it can only shorten a session, never extend it), and the only party able to forge it is the client being timed out, which can keep any session alive today by sending requests — the idle timeout protects an unattended screen, not against its own user; "input since the last marked request" needs no time window, so it is deterministic in tests; synthetic `mousemove` events that browsers fire when content moves under a resting pointer would defeat the rule. — cost if wrong: a person who reads one page for 30 minutes without clicking, typing or scrolling is signed out (the same as the spec's definition of idle); a non-browser client that uses the session cookie (none is supported; API automation uses tokens) never slides.
2. **AUD-01, typing without requests:** no separate heartbeat request; the minute-by-minute license status poll carries the marker after any input. — why: it is mounted on every signed-in page (`web/src/layout/AppLayout.tsx` → `LicenseBanners`) and adds no request. — cost: if that poll is ever removed or made conditional, long form-filling without requests would be signed out; Task 5's Vitest pins the coupling.
3. **AUD-02, gate semantics:** `Allow` (a) advances the last evaluation's effective time by the monotonic uptime since that evaluation and refuses gated work (`ErrLocked`) once that time reaches `LocksAt`, and (b) refuses gated work with `license.ErrUnverified` (which wraps `ErrLocked`, so every existing "held in lock" path treats it the same) when no evaluation has succeeded for `MaxEvaluationAge` = 3 h of uptime. `ClassAlways` work is never refused; before `Start` completes the gate stays closed as today. `license.evaluate` runs in every process regardless of the scheduling leader lock; every license row lock waits at most 30 s (`lock_timeout`) and a `Tick` at most 2 minutes. API answer for (b): new `ALC-LIC-0009 license.unverified` (503, retryable) and a red banner `unverified` for everyone. — why: the gate's correctness then no longer depends on the evaluation running (the held row lock and the foreign advisory lock of the PoCs both stop it); monotonic uptime cannot be moved by the clock attacks the HWM guard already handles; 3 h is two missed hourly evaluations plus margin, short enough that a stalled evaluation is visible the same morning, long enough that a single failed run or a brief database maintenance does not stop changes. — cost if wrong: a database outage longer than 3 h pauses changes to managed systems until the next successful hourly evaluation after it ends (at most 1 h later); a license that ends between two evaluations locks at the exact minute instead of up to an hour later.
4. **AUD-03, account grammar:** a new `helperproto.ValidAccount` for names read from a server's `/etc/passwd`: 1–32 bytes, letters of either case, digits, `_`, `.`, `-`, not starting with `.` or `-`, an optional final `$`, not all digits. `ValidUser` (SEC-062's `^[a-z_][a-z0-9_-]{0,31}$`) stays for names Alice itself configures (the SSH login user, the sudo user). — why: this is what shadow-utils' `useradd` accepts on RHEL and Debian (dots, capitals, a leading digit, Samba's trailing `$`), what sshd matches, and what POSIX calls portable; it can never hold a comma (the `sshd -T -C user=<name>,…` argument), `/`, a space, a quote or a control character; a `$` or anything else outside `helperproto.ValidArg` that reaches an expanded path is already refused there and reported as `unsupported_path`. — cost if wrong: an account with a name longer than 32 bytes or with other characters (spaces, non-ASCII) is not inventoried — but always reported, never silent.
5. **AUD-03, what is reported:** every `/etc/passwd` entry whose name fails `ValidAccount`, and every entry the selection rule would scan whose home directory is not absolute, contains a `..` element or is not a valid helper path after removing repeated and trailing `/` and `.` elements, goes into `unlisted` (uid and reason only, at most 100), and makes `accounts_complete` false. Alice turns each into a server warning (`account_name_unsupported` / `account_home_unsupported`, parameter `uid`). — why: the brief and the audit require that names outside the grammar are never silent; a `..` home is not cleaned lexically because through a symbolic link it names another directory than sshd opens; only the uid leaves the server because the name may contain any byte. — cost if wrong: a server with an odd system account (for example a name with a space) shows a permanent warning and Alice stops marking keys of deleted users as missing there (the documented consequence of an incomplete list).
6. **AUD-22, one scan per discovery:** `authkeys-list` returns the content of each file it already read for its hash (`inline`), while the total stays within 4 MiB; Alice reads only the rest with `authkeys-read`. `authkeys-read`/`authkeys-write` keep scanning all accounts (a write is still two scans: Alice's read and the write). — why: the helper already opens, checks and reads every listed file in `fileInfo` with the same checks as `readCandidate` (`cmd/alice-helper/safeopen.go:168`), so returning it changes no trust decision; the rejected alternative, `authkeys-read --user <name>` scanning one account, would let a file shared by two accounts (an absolute `AuthorizedKeysFile` pattern) resolve to the named account instead of the first one in uid order, weakening the last-root-key guard. — cost: `authkeys-list` answers grow to at most about 5.4 MiB (within the existing 8 MiB `DefaultMaxOutput`).
7. **AUD-03 + AUD-22, one protocol step:** protocol 6, `alice-helper` 1.5.0, required by Alice (older helpers answer `ssh.helper_outdated`). The sudoers file is unchanged. — why: an Alice that accepted protocol 5 would keep reporting silently skipped accounts as complete for every un-updated server. — cost: every managed server needs the new helper (the setup script installs it) before Alice talks to it again.
8. **AUD-06, denial audit rows:** `authz.denied` and `request.denied_license` are written once per (subject, permission or license class, reason) per 10 minutes; the next row after the window carries `suppressed_count`. Verification stays a full recomputation from seq 1; verify and export run one at a time per process and an export may write for up to 10 minutes. — why: the same subject repeating the same refused request carries no new information, while each row costs a chain-lock append and is kept and re-read forever; incremental verification from a checkpoint would no longer detect edits of rows older than the checkpoint (F-91/F-92), which matters while the chain is unkeyed (Phase 7). — cost: SEC-070's "every authorization failure writes a row" holds only per window (R39); a count of left-out denials reaches the log only when that subject is refused again (in memory per process; lost on restart); verification time keeps growing linearly.
9. **AUD-12, API tokens:** an administrator's **Set a new password** and **Sign out everywhere** also revoke every API token of that user (counted in the audit row as `revoked_token_count`; the dialogs say so); a user changing their own password keeps their tokens. — why: these two are the administrator's incident actions, and a token is another way in for up to 365 days; the token model (SEC-026: per user, hashed, scoped, expiring) has no other bulk revocation; a separate opt-in would be the one forgotten in an incident. — cost: an administrator who resets a forgotten password also breaks that user's automation, which then needs new tokens.
10. **AUD-13, unstorable text:** a query parameter (key or value) that is not valid UTF-8 or contains NUL, and a JSON body whose decoded strings contain NUL, are refused with `ALC-SYS-0004` (400) before any handler runs; such a sign-in is not audited (like any malformed body). `auth.Login` additionally treats a username it cannot store as an unknown user (same work, audited as `unknown_user`) for callers other than the HTTP layer. Cursors whose time is outside 1970–9999 are a validation error. — why: one rule at the edge covers every current and future route; a body PostgreSQL cannot store is malformed input, which SEC-070 does not cover today either (invalid JSON is not audited). — cost: a NUL inside a legitimate text field is refused (no supported field needs one).
11. **AUD-16, lookups before rate limits:** a request that presents a credential consults a per-IP failed-credential bucket (60 per minute, no token taken) before any lookup and takes a token only when its credential does not resolve; `/healthz` on the public listener gets the anonymous per-IP limit (60 per minute); the container-local health listener stays unlimited. — why: valid sessions never pay, and garbage cookies can no longer buy two database lookups per request; the container healthcheck uses the internal listener. — cost: clients behind one NAT address share the failed-credential bucket (as they share the anonymous bucket today); an external monitor polling the public `/healthz` more than once a second is throttled.
12. **AUD-18, the seal:** fix the code, not only the FAQ: an installation row without a seal is always tampering (`seal_missing`); the "sealed on the first start after the upgrade" path (`sealUnsealed`, `everSealed`) is removed. — why: every installation the current code creates is sealed at creation, and no customer installation predates the seal (the product is unreleased; development databases were all sealed by their first start after Phase 2); the upgrade path was exactly the hole. — cost: a development database created before the seal existed and never started since would read as tampered (evaluation ended) and needs `make reset`. The FAQ keeps naming the residual: whoever controls the database owner role and rewrites the unkeyed audit chain (Phase 7).
13. **AUD-20:** `createKeyFile` syncs the keys directory (and its parent when it created the directory) after the file's own `fsync`; it keeps creating the file in place with `O_EXCL`. — why: smallest fix of the reported gap; a temporary file plus `link`/`renameat2` would add a failure mode on file systems without hard links or `RENAME_NOREPLACE`. — cost: a crash in the middle of the very first write still leaves a short key file, which the next start refuses (fails closed, as today).
14. **AUD-25 (a), resolved addresses:** every TCP connection Alice opens to a managed server (SSH dial, Nginx TLS probe) refuses, at connect time (`net.Dialer.Control`), the addresses target validation refuses today (link-local incl. 169.254.169.254 and its IPv6 forms, multicast, unspecified, broadcast); new `ALC-SSH-0012 ssh.address_not_allowed`. Names stay accepted when a target is added. — why: checked after resolution, it also covers DNS rebinding and names such as `metadata.google.internal`; resolving at add time would freeze a moving address. — cost: none known; loopback and private addresses stay allowed as before.
15. **AUD-25 (b), lockout scope:** documented, not changed: the per-account counter also blocks `StepUp` and `ChangePassword`, and `alice admin unlock` is undone by the attacker's next attempts. — why: separating the counters needs a schema change and the SEC-020 semantics recorded in R35's addendum; the alerting that makes a lockout visible arrives in Phase 7. — cost: an unauthenticated attacker who knows an administrator's name can keep that administrator from step-up actions while the attack lasts.
16. **AUD-25 (c), CSV export:** the CSV export starts (after the BOM) with one line `# alice audit export: intact=<true|false> checked=<n> head_seq=<n> head_hash=<hex>[ first_bad_seq=<n> problem=<p>]` before the header row. — why: SEC-075 asks that the file carries the verification status; a comment line is the only place a CSV can carry it without a column per row. — cost: a strict CSV reader sees one extra one-cell row (documented).
17. **AUD-09, pins:** GitHub Actions by full commit SHA with a `# vX.Y.Z` comment; every `FROM`, compose `image:` that is pulled, the scanner images of the `Makefile` and the testcontainers PostgreSQL image by `@sha256:` index digest next to the tag; `tools/pincheck` (run by `make test` and `make lint`) refuses anything else; Dependabot (weekly) keeps them updatable; `docs/dev/dependency-updates.md` documents the manual procedure. Go tools stay `go install …@vX` (verified against the Go checksum database); the testcontainers Ryuk image and Playwright's browser download are not pinned. — why: digests make a moved tag harmless; the check is offline (patterns only), so tests never reach a registry; Go's module checksum database already makes `@version` immutable. — cost: updates become explicit commits (Dependabot PRs once a remote exists); Ryuk and the browser download stay trust-on-tag (recorded).
18. **AUD-23, image check and gates:** `make image-check` (in `make ci` before `image-scan`) copies the binary out of `alice:ci`, refuses build tags in its build info and the test-license key label in its data, and runs `alice version` in the image (no `+e2e`, no `+testlicense`); `release-symcheck` also checks build tags; `npm ci --ignore-scripts`; `go mod verify`; Dependabot; Vitest coverage with a threshold; coverage floors for `internal/setup`, `internal/platform/tlscert` and `cmd/alice`; `osv-scanner` is deferred to Phase 8 (release pipeline). — why: the build info and the version string are what a release binary cannot hide; a `/test/clock` probe needs a running stack with a database, and an e2e build without the tag cannot contain those handlers. — cost: `osv-scanner`'s extra advisory sources stay unused until Phase 8 (`govulncheck` and `npm audit` remain).
19. **AUD-08:** the workflow runs on `push` to every branch and on pull requests. — why: the project works on `master` and `phase-*`. — cost: more CI minutes once a remote exists.
20. **AUD-24:** the `COMPOSE` variable of the `Makefile` adds `deploy/docker-compose.override.yml` when that file exists (the e2e project never does); the alice service passes `ALICE_TRUSTED_PROXIES` and `ALICE_LOG_LEVEL`; both new files are ignored by git. — why: the documented SMTP override must work with `make up`. — cost: none.

## R39 (written in Task 17): changes relative to the spec

| # | Spec text | Change |
|---|---|---|
| 1 | SEC-019, A-02 "activity resets the idle timer" | Activity = state-changing request or `X-Alice-Activity: 1`; background reads never slide (Decisions 1, 2) |
| 2 | §16.6, R9 gate "from the snapshot" | Time-aware gate, `license.unverified` after 3 h without a successful evaluation, evaluation in every process, bounded lock waits (Decision 3) |
| 3 | SEC-062 user name pattern | `ValidAccount` for names listed from servers; `unlisted` accounts; protocol 6 (Decisions 4–7) |
| 4 | SEC-070 "every authorization failure" | One row per subject, permission/class and reason per 10 minutes with `suppressed_count` (Decision 8) |
| 5 | SEC-019 "password change revoke server-side" | Admin reset and sign-out-everywhere also revoke API tokens (Decision 9) |
| 6 | R36 addendum (j), P2-10 (unsealed installations sealed on upgrade) | No unsealed installation is trusted (Decision 12) |
| 7 | SEC-075 "includes verification status" | CSV comment line (Decision 16) |
| 8 | SEC-065 | Checked again on the resolved address at connect time (Decision 14) |
| 9 | SEC-089, SEC-103, §22.7 | Digests and SHAs, pin check, `--ignore-scripts`, `go mod verify`, Dependabot, TS coverage threshold, `osv-scanner` deferred (Decisions 17, 18) |

## Review Focus

1. **An account sshd accepts is never silently missing** — `john.doe`, `Deploy2`, `host$`, a home `/home/trail/`, a home `/home/x/../y`, a name with a comma or a space. Expected: the first four are listed with their keys; the last three are in `unlisted` (uid and reason), `accounts_complete` is false and the server shows a warning naming the uid. Tests: Task 2 (`TestAccountsOutsideTheOldGrammarAreListed`, `TestUnlistedAccountsAreReportedNeverSilent`), Task 3 (`TestDiscoverReportsUnlistedAccounts`, `TestEmulatorFidelityAuthKeysList`, `TestRealOpenSSH` fixtures).
2. **An unattended tab** — a signed-in page left visible, polling every minute, is signed out 30 minutes after the last real input; a person who scrolls once stays signed in. Tests: Task 4 (`TestBackgroundPollsDoNotExtendTheIdleTimeout`, `TestA02BackgroundPollsDoNotKeepASessionAlive`), Task 5 (`phase1.spec.ts` "a page left open …").
3. **Holding the license open** — a held license row lock, a foreign scheduling lock, a stalled evaluation. Expected: changes refused at `LocksAt` and after 3 h without an evaluation; recovery and rollback (`ClassAlways`) still run. Tests: Task 6 (`TestGateLocksAtLocksAtWhileTheRowIsHeld`, `TestGateFailsClosedWhenEvaluationsStop`, `TestForeignLeaderLockDoesNotStopEvaluation`).
4. **Hostile input at the edge** — NUL and invalid UTF-8 in every text parameter, extreme cursors, garbage cookies at volume. Expected: 4xx, never 5xx; bounded lookups. Tests: Tasks 9, 10.

---

## File Structure

```
internal/providers/linuxssh/helperproto/   protocol 6: ValidAccount, CleanHome, UnlistedAccount, inline file content (Task 1)
cmd/alice-helper/                          accounts.go, authkeys.go: grammar, unlisted accounts, inline content (Task 2)
internal/providers/linuxssh/               discover.go, keyops.go: unlisted warnings, ValidAccount, inline content (Task 3)
internal/providers/linuxssh/linuxsshtest/  emulator.go mirrors Task 2 (Task 3)
test/images/sshd/fixtures.sh               accounts with dots, capitals, a trailing-slash home, unlisted entries (Task 3)
web/src/api/warnings.ts, locales           account warnings (Task 3); activity marking (Task 5); banners, codes (Tasks 6, 11, 13)
internal/auth/                             sessions.go (Task 4); login.go, users.go, password.go (Task 11)
internal/api/                              guard.go, server.go (Tasks 4, 6, 8, 9, 10); denials.go (Task 8); audit_handlers.go (Task 8);
                                           httpx.go (Task 10); errors.go (Tasks 6, 13)
web/src/api/activity.ts, client.ts, main.tsx; web/e2e/phase1.spec.ts (Task 5)
internal/license/                          service.go, tick.go, errors.go, banners.go (Task 6); installation.go, file.go (Task 7)
internal/jobs/scheduler.go                 license.evaluate in every process (Task 6)
internal/auth/ratelimit/ratelimit.go       Limiter.Blocked (Task 9)
internal/platform/validate/                StorableText (Task 10)
internal/inventory/sshkeys.go, internal/jobs/queue.go   cursor ranges (Task 10)
internal/setup/admin.go; internal/secrets/masterkey.go (Task 12)
internal/platform/netaddr/                 address rule shared by inventory, linuxssh and the Nginx probe (Task 13)
web/src/                                   router error element, locale fallback, blocked jobs paging, step-up close, audit columns (Task 14)
tools/pincheck/, .github/dependabot.yml, docs/dev/dependency-updates.md, digests everywhere (Task 15)
.github/workflows/ci.yml, Makefile, deploy/, .gitleaks.toml, .gitignore, web/vite.config.ts, web/package.json (Task 16)
docs/, CHANGELOG.md, coverage-floors.json, 00-decisions.md (R39), 06-quality.md, docs/security/reviews/audit-remediation.md (Task 17)
```

### Task index

1. Helper protocol 6 vocabulary — `ValidAccount`, `CleanHome`, unlisted accounts, inline file content (AUD-03, AUD-22)
2. **HELPER**: accounts of every valid name are listed, the others are reported; `authkeys-list` returns the files it read (AUD-03, AUD-22)
3. **HELPER** (Alice side): unlisted accounts become warnings, inline content replaces per-file reads; emulator, fidelity, real matrix (AUD-03, AUD-22)
4. Sessions: only a person's activity slides the idle timeout (server) (AUD-01)
5. Web: activity marking and the unattended-tab journey (AUD-01)
6. License gate: time-aware, fails closed without evaluations, evaluation in every process (AUD-02)
7. License: an unsealed installation is never trusted; a newer format with new fields asks for an update (AUD-18, AUD-19)
8. Audit rows of refusals: coalesced and written on a detached context; bounded export and verification; CSV verification line (AUD-06, AUD-15, AUD-25 c)
9. Rate limits before credential lookups; `/healthz` limited on the public listener (AUD-16)
10. Text PostgreSQL cannot store is refused at the edge; cursor ranges (AUD-13)
11. Sign-in timing under the name lock; password reset and sign-out-everywhere revoke API tokens (AUD-11, AUD-12)
12. Setup code reset wins against a running admin creation; the master key's directory is synced (AUD-21, AUD-20)
13. Resolved addresses are checked when Alice connects (AUD-25 a)
14. Web robustness: route error page, locale fallback, all held jobs, step-up closes with the session, audit object and details (AUD-25 d)
15. Supply chain: SHAs and digests everywhere, the pin check, Dependabot, the update procedure (AUD-09)
16. CI and build gates: every branch, the image check, build-tag checks, `--ignore-scripts`, `go mod verify`, TS coverage, gitleaks narrowing, Compose override (AUD-08, AUD-23, AUD-24)
17. Coverage floors, documentation, R39, the remediation review, `make ci` (all; AUD-25 b)

Recommended execution: subagent-driven, one reviewer per task, an additional security reviewer on Tasks 2, 3, 4, 6, 9, 10 and 13. Tasks 1–3 are consecutive and form the single helper change. Every task leaves the tree green (`make lint`, `make test`, the integration packages it touches, `make web-test` and `make i18n-check` where it touches the web).

---

### Task 1: Helper protocol 6 vocabulary — `ValidAccount`, `CleanHome`, unlisted accounts, inline file content

The audit's AUD-03 is in `cmd/alice-helper/accounts.go:60` (`!helperproto.ValidUser(a.name) || !helperproto.ValidPath(a.home)` skips the account without a trace), `:96` (the same names are dropped from `accounts`) and `cmd/alice-helper/authkeys.go:301-303` (`AccountsComplete` ignores both). `ValidUser` is SEC-062's `^[a-z_][a-z0-9_-]{0,31}$` (`helperproto.go:519`). AUD-22 is `cmd/alice-helper/authkeys.go:85-132` (every `authkeys-read` and `authkeys-write` runs `scan`, one `sshd -T -C` per listed account). This task adds the protocol vocabulary only; nothing uses it yet, so the tree stays green.

**Files:**
- Modify: `internal/providers/linuxssh/helperproto/helperproto.go`
- Test: `internal/providers/linuxssh/helperproto/helperproto_test.go`

**Interfaces:**
- Produces: `Protocol = 6`, `Version = "1.5.0"`; `ValidAccount(string) bool`; `CleanHome(string) (string, bool)`; `UnlistedAccount{UID int; Reason string}`, `UnlistedName = "name"`, `UnlistedHome = "home"`, `MaxUnlistedAccounts = 100`; `AuthKeysListResponse.Unlisted []UnlistedAccount` (JSON `unlisted`); `FileInfo.ContentB64 string` (JSON `content_b64,omitempty`), `FileInfo.Inline bool` (JSON `inline`); `MaxListInline = 4 << 20`; warnings `WarnAccountNameUnsupported = "account_name_unsupported"`, `WarnAccountHomeUnsupported = "account_home_unsupported"` (Alice's codes, here so the web completeness test finds them with the other helper warnings).

- [ ] **Step 1: Write the failing tests**

Add to `helperproto_test.go`:

```go
func TestValidAccount(t *testing.T) {
	for _, tc := range []struct {
		in string
		ok bool
	}{
		{"deploy", true}, {"john.doe", true}, {"Deploy2", true}, {"_svc", true}, {"1abc", true}, {"a", true},
		{"a.b-c_d", true}, {"host$", true}, {strings.Repeat("a", 32), true}, {strings.Repeat("a", 31) + "$", true},
		{"", false}, {"$", false}, {"123", false}, {"123$", false}, {"-a", false}, {".hidden", false}, {"a b", false},
		{"a,b", false}, {"a/b", false}, {"a:b", false}, {"kullanıcı", false}, {"a\n", false}, {"a\x00", false},
		{strings.Repeat("a", 33), false}, {strings.Repeat("a", 32) + "$", false}, {"a$$", false}, {"a$b", false},
	} {
		assert.Equal(t, tc.ok, ValidAccount(tc.in), "%q", tc.in)
	}
	// Every name ValidUser accepts is an account name too.
	for _, n := range []string{"deploy", "_svc", "alice-svc", "root", strings.Repeat("a", 32)} {
		assert.True(t, ValidUser(n) && ValidAccount(n), n)
	}
}

func TestCleanHome(t *testing.T) {
	for _, tc := range []struct {
		in, out string
		ok      bool
	}{
		{"/home/x", "/home/x", true}, {"/home/x/", "/home/x", true}, {"/home//x", "/home/x", true},
		{"/home/./x", "/home/x", true}, {"/", "/", true}, {"/root", "/root", true},
		{"", "", false}, {"home/x", "", false}, {"/home/x/../y", "", false}, {"/..", "", false},
		{"/home/a b", "", false}, {"/home/a;b", "", false},
	} {
		out, ok := CleanHome(tc.in)
		assert.Equal(t, tc.ok, ok, "%q", tc.in)
		assert.Equal(t, tc.out, out, "%q", tc.in)
	}
}

func TestProtocol6WireShapes(t *testing.T) {
	b, err := json.Marshal(AuthKeysListResponse{OK: true, Users: []UserFiles{{User: "john.doe", Files: []FileInfo{
		{Path: "/home/john.doe/.ssh/authorized_keys", Exists: true, SHA256: "ab", Inline: true, ContentB64: "eA=="}, {Path: "/x"}}}},
		Unlisted: []UnlistedAccount{{UID: 1009, Reason: UnlistedName}}})
	require.NoError(t, err)
	s := string(b)
	assert.Contains(t, s, `"unlisted":[{"uid":1009,"reason":"name"}]`)
	assert.Contains(t, s, `"inline":true,"content_b64":"eA=="`)
	assert.Contains(t, s, `{"path":"/x","exists":false`)
	assert.NotContains(t, s[strings.Index(s, `"/x"`):], "content_b64", "an empty content is omitted")
	assert.Equal(t, 6, Protocol)
	assert.Equal(t, "1.5.0", Version)
}
```

(Add `"encoding/json"` to the test imports if missing; the field order in the second `Contains` follows the struct order below — `Inline` before `ContentB64`.)

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/providers/linuxssh/helperproto -count=1`
Expected: FAIL — `undefined: ValidAccount`, `undefined: CleanHome`, `unknown field Unlisted`.

- [ ] **Step 3: Implement**

In `helperproto.go`:
- Extend the protocol comment and set `Protocol = 6`, `Version = "1.5.0"`:

```go
	// Protocol 6 (AUD-03, AUD-22): authkeys-list lists account names of ValidAccount (not only
	// ValidUser), reports the /etc/passwd entries it cannot list (unlisted) and returns the
	// content of the files it read (inline) so a discovery needs no authkeys-read for them.
	Protocol   = 6
	Version    = "1.5.0"
```

- After `WarnTooManyUsers`, in the same `const` block:

```go
	// Alice's warnings for AuthKeysListResponse.Unlisted (parameter uid).
	WarnAccountNameUnsupported = "account_name_unsupported"
	WarnAccountHomeUnsupported = "account_home_unsupported"
```

- After `MaxAccountNames`:

```go
// Protocol 6 limits and reasons (AUD-03, AUD-22).
const (
	MaxUnlistedAccounts = 100     // entries of AuthKeysListResponse.Unlisted
	MaxListInline       = 4 << 20 // total raw bytes of inline file content in one authkeys-list answer
	UnlistedName        = "name"  // the name is not a ValidAccount
	UnlistedHome        = "home"  // the account would be scanned, but its home is not a path the helper accepts
)

// UnlistedAccount is an /etc/passwd entry authkeys-list did not list. Only the uid leaves the
// server: the name may hold any byte.
type UnlistedAccount struct {
	UID    int    `json:"uid"`
	Reason string `json:"reason"` // UnlistedName or UnlistedHome
}
```

- `FileInfo` gains, after `Unsupported`:

```go
	// Inline is true when ContentB64 holds the file's content (protocol 6): the helper read the
	// file for SHA256 and returns it while the answer's inline total stays within MaxListInline.
	// SHA256 is the hash of exactly this content. Files without it are read with authkeys-read.
	Inline     bool   `json:"inline"`
	ContentB64 string `json:"content_b64,omitempty"`
```

- `AuthKeysListResponse` gains, after `AccountsComplete`, and its comment on `Accounts` changes "every valid" to "every `ValidAccount`":

```go
	// Unlisted names every entry the helper could not list (at most MaxUnlistedAccounts, never
	// null); AccountsComplete is false when it is not empty (AUD-03).
	Unlisted []UnlistedAccount `json:"unlisted"`
```

- Next to `ValidUser`:

```go
// ValidAccount reports whether s is an account name the helper lists from /etc/passwd and Alice
// stores and shows (protocol 6, AUD-03, R39): 1 to 32 bytes of ASCII letters of either case,
// digits, "_", "." and "-", not starting with "." or "-", an optional final "$" (Samba machine
// accounts), and not all digits (it would read as a uid). That is what shadow-utils' useradd
// accepts on Debian and RHEL within 32 bytes. It never holds a comma, "/", a space, a quote or a
// control character, so it is safe in "sshd -T -C user=<name>,…"; a "$" that reaches an expanded
// path is refused there by ValidPath. Names Alice itself configures keep ValidUser (SEC-062).
func ValidAccount(s string) bool {
	if len(s) == 0 || len(s) > 32 {
		return false
	}
	body := strings.TrimSuffix(s, "$")
	if body == "" {
		return false
	}
	digits := true
	for i := 0; i < len(body); i++ {
		c := body[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '_':
			digits = false
		case (c == '.' || c == '-') && i > 0:
			digits = false
		default:
			return false
		}
	}
	return !digits
}

// CleanHome returns an /etc/passwd home directory as the helper names paths: absolute, without
// repeated or trailing "/" and "." elements (the kernel and sshd read them the same way), and a
// ValidPath. A ".." element is refused, never cleaned: through a symbolic link it names another
// directory than the lexical result (AUD-03).
func CleanHome(h string) (string, bool) {
	if !strings.HasPrefix(h, "/") || slices.Contains(strings.Split(h, "/"), "..") {
		return "", false
	}
	c := filepath.Clean(h)
	if !ValidPath(c) {
		return "", false
	}
	return c, true
}
```

(add `"slices"` to the imports.)

- [ ] **Step 4: Run them to see them pass, with full coverage**

Run: `go test ./internal/providers/linuxssh/helperproto -count=1 -cover`
Expected: PASS, `coverage: 100.0% of statements`.

- [ ] **Step 5: The tree stays green**

Run: `make lint && go test ./... -count=1`
Expected: PASS. (Alice and the emulator compare against `helperproto.Protocol`, so the bump alone changes no test; the real matrix runs in Task 3 after the helper is rebuilt.)

- [ ] **Step 6: Commit**

```bash
git add internal/providers/linuxssh/helperproto
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "feat(helperproto): protocol 6 vocabulary for account names, unlisted accounts and inline file content

Refs: AUD-03, AUD-22

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 2: **HELPER** — accounts of every valid name are listed, the others are reported; `authkeys-list` returns the files it read

**Files:**
- Modify: `cmd/alice-helper/accounts.go` (`toScan`, `accountNames`, `groupNames`)
- Modify: `cmd/alice-helper/authkeys.go` (`scanResult.unlisted`, `scan`, `cmdAuthKeysList`, `fileInfo`)
- Create: `cmd/alice-helper/accounts_test.go`
- Modify: `cmd/alice-helper/helper_test.go` (expectations the new rule changes)

**Interfaces:**
- Consumes: Task 1's vocabulary.
- Produces: `func (s *sys) toScan(accts []account) (out []account, unlisted []helperproto.UnlistedAccount, truncated bool)`; `func (s *sys) fileInfo(c candidate, names map[int]string, inline *int) helperproto.FileInfo`.

- [ ] **Step 1: Write the failing tests (adapted from the audit's helper PoC)**

Create `cmd/alice-helper/accounts_test.go`:

```go
//go:build linux

package main

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/providers/linuxssh/helperproto"
)

func listedUsers(m map[string]any) []string {
	var users []string
	for _, u := range m["users"].([]any) {
		users = append(users, u.(map[string]any)["user"].(string))
	}
	return users
}

// AUD-03: names that Linux and sshd accept but the old pattern refused (a dot, a capital letter,
// a Samba "$") and a home written with a trailing slash are listed with their files.
func TestAccountsOutsideTheOldGrammarAreListed(t *testing.T) {
	skipOddUID(t)
	f := newFixture(t)
	f.write("/etc/passwd", "root:x:0:0:root:/root:/bin/bash\n", 0o644)
	var passwd strings.Builder
	passwd.WriteString(f.read("/etc/passwd"))
	for _, n := range []string{"john.doe", "Deploy2", "trail"} {
		f.mkdir("/home/"+n, 0o755)
		f.mkdir("/home/"+n+"/.ssh", 0o700)
		f.write("/home/"+n+"/.ssh/authorized_keys", "ssh-ed25519 AAAA "+n+"@laptop\n", 0o600)
	}
	fmt.Fprintf(&passwd, "john.doe:x:%d:%d::/home/john.doe:/bin/bash\n", f.uid, f.uid)
	fmt.Fprintf(&passwd, "Deploy2:x:%d:%d::/home/Deploy2:/bin/bash\n", f.uid, f.uid)
	fmt.Fprintf(&passwd, "trail:x:%d:%d::/home/trail/:/bin/bash\n", f.uid, f.uid)
	fmt.Fprintf(&passwd, "WS01$:x:%d:%d::/nonexistent:/usr/sbin/nologin\n", f.uid+1, f.uid+1)
	f.write("/etc/passwd", passwd.String(), 0o644)

	code, m := f.run("authkeys-list")
	require.Equal(t, 0, code, "%v", m)
	users := listedUsers(m)
	assert.Subset(t, users, []string{"john.doe", "Deploy2", "trail"})
	assert.Equal(t, "/home/trail", listUser(t, m, "trail")["home"], "the home is cleaned")
	assert.Equal(t, []any{}, m["unlisted"])
	assert.Equal(t, true, m["accounts_complete"])
	assert.Subset(t, m["accounts"], []any{"Deploy2", "WS01$", "john.doe", "trail"})

	code, r := f.run("authkeys-read", "/home/john.doe/.ssh/authorized_keys")
	require.Equal(t, 0, code, "%v", r)
	assert.Equal(t, "john.doe", r["owner"])
	code, _ = f.run("authkeys-read", "/home/trail/.ssh/authorized_keys")
	assert.Equal(t, 0, code)
}

// AUD-03: an entry the helper cannot list is reported with its uid and reason, and the account
// list is incomplete. Nothing is silent.
func TestUnlistedAccountsAreReportedNeverSilent(t *testing.T) {
	skipOddUID(t)
	f := newFixture(t)
	f.write("/etc/passwd", f.read("/etc/passwd")+
		"bad,name:x:1009:1009::/home/deploy:/bin/bash\n"+
		"dotdot:x:1010:1010::/home/x/../dotdot:/bin/bash\n"+
		"relhome:x:1011:1011::home/relhome:/bin/bash\n"+
		"svc:x:500:500::home/svc:/usr/sbin/nologin\n", 0o644) // never scanned: a bad home does not matter
	code, m := f.run("authkeys-list")
	require.Equal(t, 0, code, "%v", m)
	assert.ElementsMatch(t, []any{
		map[string]any{"uid": 1004.0, "reason": "name"}, // "Bad Name" of the base fixture
		map[string]any{"uid": 1009.0, "reason": "name"},
		map[string]any{"uid": 1010.0, "reason": "home"},
		map[string]any{"uid": 1011.0, "reason": "home"},
	}, m["unlisted"])
	assert.Equal(t, false, m["accounts_complete"])
	assert.NotContains(t, listedUsers(m), "dotdot")
	assert.NotContains(t, f.out.String(), "bad,name", "an unlisted name never leaves the server")
}

func TestUnlistedAccountsAreBounded(t *testing.T) {
	f := newFixture(t)
	var b strings.Builder
	b.WriteString(f.read("/etc/passwd"))
	for i := 0; i < helperproto.MaxUnlistedAccounts+20; i++ {
		fmt.Fprintf(&b, "bad name %d:x:%d:%d::/home/deploy:/bin/bash\n", i, 30000+i, 30000+i)
	}
	f.write("/etc/passwd", b.String(), 0o644)
	_, m := f.run("authkeys-list")
	assert.Len(t, m["unlisted"], helperproto.MaxUnlistedAccounts)
	assert.Equal(t, false, m["accounts_complete"])
}

// AUD-22: authkeys-list returns the files it read, so a discovery needs one scan; the sshd runs
// of a listing grow with the accounts, not with accounts times files.
func TestAuthKeysListInlinesWhatItRead(t *testing.T) {
	skipOddUID(t)
	f := newFixture(t)
	const n = 60
	var b strings.Builder
	b.WriteString(f.read("/etc/passwd"))
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("u%d", i)
		f.mkdir("/home/"+name, 0o755)
		f.mkdir("/home/"+name+"/.ssh", 0o700)
		f.write("/home/"+name+"/.ssh/authorized_keys", "ssh-ed25519 AAAA "+name+"\n", 0o600)
		fmt.Fprintf(&b, "%s:x:%d:%d::/home/%s:/bin/bash\n", name, f.uid, f.uid, name)
	}
	f.write("/etc/passwd", b.String(), 0o644)
	code, m := f.run("authkeys-list")
	require.Equal(t, 0, code)
	inline := 0
	for _, u := range m["users"].([]any) {
		for _, fi := range filesOf(u.(map[string]any)) {
			if fi["exists"] != true || fi["unsupported"] == true {
				continue
			}
			require.Equal(t, true, fi["inline"], fi["path"])
			raw, err := base64.StdEncoding.DecodeString(fi["content_b64"].(string))
			require.NoError(t, err)
			assert.Equal(t, hexSHA(raw), fi["sha256"], "the inline content is what was hashed")
			inline++
		}
	}
	assert.GreaterOrEqual(t, inline, n)
	assert.LessOrEqual(t, f.sshdCalls.Load(), int64(len(m["users"].([]any))+1), "one sshd -T per account plus the global one")
}

func TestInlineContentStopsAtItsBudget(t *testing.T) {
	skipOddUID(t)
	f := newFixture(t)
	big := strings.Repeat("ssh-ed25519 AAAA "+strings.Repeat("x", 60)+"\n", 12000) // ~ 950 KiB per file
	var b strings.Builder
	b.WriteString(f.read("/etc/passwd"))
	for i := 0; i < 6; i++ { // ~ 5.6 MiB in total: more than MaxListInline
		name := fmt.Sprintf("big%d", i)
		f.mkdir("/home/"+name, 0o755)
		f.mkdir("/home/"+name+"/.ssh", 0o700)
		f.write("/home/"+name+"/.ssh/authorized_keys", big, 0o600)
		fmt.Fprintf(&b, "%s:x:%d:%d::/home/%s:/bin/bash\n", name, f.uid, f.uid, name)
	}
	f.write("/etc/passwd", b.String(), 0o644)
	_, m := f.run("authkeys-list")
	total, without := 0, 0
	for _, u := range m["users"].([]any) {
		for _, fi := range filesOf(u.(map[string]any)) {
			if fi["exists"] != true {
				continue
			}
			if fi["inline"] == true {
				raw, _ := base64.StdEncoding.DecodeString(fi["content_b64"].(string))
				total += len(raw)
			} else {
				without++
				assert.NotEmpty(t, fi["sha256"], "a file over the budget still has its hash")
			}
		}
	}
	assert.LessOrEqual(t, total, helperproto.MaxListInline)
	assert.Positive(t, without)
}
```

(`hexSHA` is the helper's own function; `listUser` and `filesOf` are `helper_test.go`'s.)

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./cmd/alice-helper -run 'OutsideTheOldGrammar|UnlistedAccounts|Inline' -count=1`
Expected: FAIL — `john.doe` not listed, `m["unlisted"]` nil, no `inline` field.

- [ ] **Step 3: Implement `toScan`**

Replace `toScan` in `accounts.go` (and add `"alice/internal/providers/linuxssh/helperproto"` stays imported):

```go
// toScan selects the accounts whose keys are inventoried (spec §13.1): root, every other uid-0
// account and every normal account (uid >= 1000, not nobody) with an existing home and a login
// shell, and the account that runs the helper through sudo (alice-svc) so Alice's own key appears.
// unlisted names every entry that cannot be listed (AUD-03): a name outside ValidAccount, or an
// account the rule would select whose home is not a path the helper accepts (CleanHome). Nothing
// is skipped silently. Homes are reported cleaned.
func (s *sys) toScan(accts []account) (out []account, unlisted []helperproto.UnlistedAccount, truncated bool) {
	sudo := s.sudoUserName()
	seen := map[string]bool{}
	for _, a := range accts {
		if !helperproto.ValidAccount(a.name) {
			unlisted = append(unlisted, helperproto.UnlistedAccount{UID: a.uid, Reason: helperproto.UnlistedName})
			continue
		}
		if seen[a.name] {
			continue
		}
		isRoot, isSudo := a.name == "root" && a.uid == 0, sudo != "" && a.name == sudo
		normal := a.uid == 0 || (a.uid >= 1000 && a.uid != nobodyUID)
		if !isRoot && !isSudo && !(normal && loginShell(a.shell)) {
			continue
		}
		home, ok := helperproto.CleanHome(a.home)
		if !ok {
			unlisted = append(unlisted, helperproto.UnlistedAccount{UID: a.uid, Reason: helperproto.UnlistedHome})
			continue
		}
		a.home = home
		if !isRoot && !isSudo && !s.isDir(a.home) {
			continue
		}
		seen[a.name] = true
		out = append(out, a)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].uid != out[j].uid {
			return out[i].uid < out[j].uid
		}
		return out[i].name < out[j].name
	})
	if len(unlisted) > helperproto.MaxUnlistedAccounts {
		unlisted = unlisted[:helperproto.MaxUnlistedAccounts]
	}
	if len(out) > maxUsers {
		return out[:maxUsers], unlisted, true
	}
	return out, unlisted, false
}
```

In `accountNames` and `groupNames` replace `helperproto.ValidUser` by `helperproto.ValidAccount` (update their comments: "every ValidAccount name"). `sudoUserName` (`sys.go:88`) keeps `ValidUser`.

- [ ] **Step 4: Implement the listing**

In `authkeys.go`:
- `scanResult` gains `unlisted []helperproto.UnlistedAccount`.
- In `scan`, `selected, truncated := s.toScan(accts)` becomes `selected, unlisted, truncated := s.toScan(accts)` followed by `r.unlisted = unlisted`.
- In `cmdAuthKeysList`, the response gets `Unlisted: []helperproto.UnlistedAccount{}` (then `append(resp.Unlisted, r.unlisted...)`), `AccountsComplete` gains `&& len(r.unlisted) == 0`, and a budget `inline := helperproto.MaxListInline` is passed as `s.fileInfo(it.c, r.owners, &inline)`.
- `fileInfo` takes `inline *int`; the read branch becomes:

```go
	if st.Size() > helperproto.MaxAuthorizedKeysSize {
		fi.TooLarge = true
	} else if data, err := io.ReadAll(io.LimitReader(f, helperproto.MaxAuthorizedKeysSize+1)); err == nil && len(data) <= helperproto.MaxAuthorizedKeysSize {
		fi.SHA256 = hexSHA(data)
		// AUD-22: the same descriptor, checks and bytes authkeys-read would use (readCandidate).
		if inline != nil && len(data) <= *inline {
			fi.Inline, fi.ContentB64 = true, base64.StdEncoding.EncodeToString(data)
			*inline -= len(data)
		}
	}
```

- [ ] **Step 5: Update the tests the new rule changes**

`helper_test.go`'s base fixture keeps `Bad Name:x:1004:…` (it now produces `unlisted`). Update, with a comment naming AUD-03:
- `TestAuthKeysListReportsEveryAccountName`: `accounts_complete` is now `false` and `unlisted` is `[{uid: 1004, reason: name}]`; add a second run with the `Bad Name` line removed that expects `true`, then the `nsswitch` case.
- `TestAccountsAreAnEmptyListNotNull`: also assert `"unlisted":[{"uid":1004,"reason":"name"}]` appears and that `"unlisted":[]` is written for a passwd with only `root`.
- Every other assertion on `accounts_complete == true` (grep `accounts_complete` in `cmd/alice-helper/*_test.go`) runs on a fixture without the `Bad Name` line or expects `false`.

Run: `go test ./cmd/alice-helper -count=1`
Expected: PASS (root-only tests skip).

- [ ] **Step 6: Helper change procedure**

Run (Docker, a throwaway container): `CGO_ENABLED=0 go test -c -o /tmp/alice-helper.test ./cmd/alice-helper && docker run --rm --network none -v /tmp/alice-helper.test:/alice-helper.test:ro debian:12 /alice-helper.test -test.count=1`
Expected: `PASS` (as root the `skipOddUID` tests run too).

Run: `make helper && cat bin/alice-helper.sha256`
Expected: two new checksums (`make test-ssh` runs in Task 3, after Alice and the emulator speak protocol 6).

- [ ] **Step 7: Full check and commit**

Run: `make lint && go test ./... -count=1`
Expected: PASS (Alice's emulator still answers the old shapes; Task 3 aligns it).

```bash
git add cmd/alice-helper
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "fix(helper): list every valid account name, report the entries it cannot list, return the files it read

An account whose name has a dot or a capital letter, or whose home ends in a slash, was
skipped without a warning while the account list said it was complete.

Refs: AUD-03, AUD-22

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 3: **HELPER** (Alice side) — unlisted accounts become warnings, inline content replaces per-file reads; emulator, fidelity, real matrix

Current code: `internal/providers/linuxssh/discover.go:216,244,289` and `keyops.go:159` filter OS account names with `ValidUser`; `discoverFile` (`discover.go:287`) reads every existing file with `authkeys-read` (`readFile`, `discover.go:120`); `linuxsshtest/emulator.go:453` mirrors the old helper rule.

**Files:**
- Modify: `internal/providers/linuxssh/discover.go`, `internal/providers/linuxssh/keyops.go`
- Modify: `internal/providers/linuxssh/linuxsshtest/emulator.go`
- Modify: `cmd/alice-helper/emulator_fidelity_test.go` (new `TestEmulatorFidelityAuthKeysList`)
- Modify: `test/images/sshd/fixtures.sh`, `internal/providers/linuxssh/containers_integration_test.go`
- Modify: `web/src/api/warnings.ts`, `web/src/locales/{en,tr}.json`, `web/src/api/enums.test.ts` (the SSH warning set)
- Modify: `docs/nginx-host-preparation.md` (:26, :196-201, :345), `docs/troubleshooting.md` (:634 and the warnings section near :651)
- Test: `internal/providers/linuxssh/provider_test.go`

- [ ] **Step 1: Write the failing provider tests**

Add to `provider_test.go`:

```go
// AUD-03: entries the helper could not list become warnings with the uid, and the account list is
// not complete (inventory then never marks a vanished user's keys missing on this server).
func TestDiscoverReportsUnlistedAccounts(t *testing.T) {
	e := newProvEnv(t)
	e.emu.AddUser("john.doe", 1005, "/home/john.doe")
	e.emu.AddUser("bad name", 1009, "/home/bad")
	e.emu.AddUser("dotdot", 1010, "/home/x/../dotdot")
	s, err := e.prov.Open(context.Background(), e.ref, e.cred, providers.Env{})
	require.NoError(t, err)
	defer func() { _ = s.Close() }()
	res, err := s.Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true})
	require.NoError(t, err)
	assert.False(t, res.AccountsComplete)
	assert.Contains(t, res.Accounts, "john.doe")
	assert.Contains(t, res.Warnings, providers.Warning{Code: helperproto.WarnAccountNameUnsupported, Params: map[string]string{"uid": "1009"}})
	assert.Contains(t, res.Warnings, providers.Warning{Code: helperproto.WarnAccountHomeUnsupported, Params: map[string]string{"uid": "1010"}})
}

// A hostile helper cannot make Alice keep a wrong reason or an unbounded list.
func TestDiscoverBoundsUnlistedAccounts(t *testing.T) {
	e := newProvEnv(t)
	list := helperproto.AuthKeysListResponse{OK: true, Users: []helperproto.UserFiles{}, AuthorizedKeysCommand: "none",
		Warnings: []string{}, Accounts: []string{"root"}, AccountsComplete: true}
	for i := 0; i < 1000; i++ {
		list.Unlisted = append(list.Unlisted, helperproto.UnlistedAccount{UID: 2000 + i, Reason: helperproto.UnlistedName})
	}
	list.Unlisted = append(list.Unlisted, helperproto.UnlistedAccount{UID: -1, Reason: "x"})
	raw, err := json.Marshal(list)
	require.NoError(t, err)
	emu := e.emu.Handler()
	e.srv.SetHandler(func(cmd string, stdin []byte) linuxsshtest.Response {
		if strings.Contains(cmd, " authkeys-list") {
			return linuxsshtest.Response{Stdout: raw}
		}
		return emu(cmd, stdin)
	})
	s, err := e.prov.Open(context.Background(), e.ref, e.cred, providers.Env{})
	require.NoError(t, err)
	defer func() { _ = s.Close() }()
	res, err := s.Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true})
	require.NoError(t, err)
	assert.False(t, res.AccountsComplete)
	n := 0
	for _, w := range res.Warnings {
		if w.Code == helperproto.WarnAccountNameUnsupported || w.Code == helperproto.WarnAccountHomeUnsupported {
			n++
		}
	}
	assert.Equal(t, helperproto.MaxUnlistedAccounts, n)
}

// AUD-22: inline content is used; no authkeys-read is sent for it; a mismatching hash is refused.
func TestDiscoverUsesInlineContent(t *testing.T) {
	e := newProvEnv(t)
	line, fp := keyLine(t, "ed25519", "", "deploy@laptop")
	e.emu.SetFile("/home/deploy/.ssh/authorized_keys", []byte(line+"\n"))
	var reads atomic.Int64
	emu := e.emu.Handler()
	e.srv.SetHandler(func(cmd string, stdin []byte) linuxsshtest.Response {
		if strings.Contains(cmd, " authkeys-read ") {
			reads.Add(1)
		}
		return emu(cmd, stdin)
	})
	s, err := e.prov.Open(context.Background(), e.ref, e.cred, providers.Env{})
	require.NoError(t, err)
	defer func() { _ = s.Close() }()
	res, err := s.Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true})
	require.NoError(t, err)
	assert.Zero(t, reads.Load(), "every listed file came inline")
	found := false
	for _, k := range res.SSHKeys {
		found = found || k.Fingerprint == fp
	}
	assert.True(t, found)
}
```

(Use the file's existing `keyLine` helper and whatever user the default emulator world lists — read `newProvEnv` and the existing `TestDiscoverListsKeysWithUsersAndFlags` first and use its user and path; the fingerprint helper's return order is the file's. Add `"sync/atomic"`, `"encoding/json"`, `"strings"` and the `linuxsshtest` import if missing.) Add a third case to `TestDiscoverUsesInlineContent` or a separate test where the handler rewrites one file's `sha256` in the list answer and expects `Discover` to fail with reason `ssh.protocol_error`.

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/providers/linuxssh -run 'Unlisted|InlineContent' -count=1`
Expected: FAIL — the emulator lists no `john.doe`, no warnings; reads are sent.

- [ ] **Step 3: Implement in `discover.go` and `keyops.go`**

- `discover.go:216`, `:244`, `:289` and `keyops.go:159`: `helperproto.ValidUser` → `helperproto.ValidAccount` (OS account names; `dial.go:119`, the SSH login user, keeps `ValidUser`).
- After the accounts block (before `for _, w := range list.Warnings`):

```go
	// AUD-03: what the helper could not list is shown, by uid only, and the list is not complete.
	unlisted := list.Unlisted
	if len(unlisted) > 0 {
		res.AccountsComplete = false
	}
	if len(unlisted) > helperproto.MaxUnlistedAccounts {
		unlisted = unlisted[:helperproto.MaxUnlistedAccounts]
	}
	for _, u := range unlisted {
		code := ""
		switch u.Reason {
		case helperproto.UnlistedName:
			code = helperproto.WarnAccountNameUnsupported
		case helperproto.UnlistedHome:
			code = helperproto.WarnAccountHomeUnsupported
		}
		if code == "" || u.UID < 0 {
			continue
		}
		res.Warnings = append(res.Warnings, warn(code, "uid", strconv.Itoa(u.UID)))
	}
```

- In `discoverFile`, replace `content, _, exists, err := s.readFile(ctx, f.Path)` and its two following `if` blocks with:

```go
	var content []byte
	if f.Inline {
		// AUD-22: the helper read this file for its hash; the content must be exactly that.
		raw, err := base64.StdEncoding.DecodeString(f.ContentB64)
		h := sha256.Sum256(raw)
		if err != nil || len(raw) > helperproto.MaxAuthorizedKeysSize || hex.EncodeToString(h[:]) != f.SHA256 {
			return providers.NewError("ssh.protocol_error", false, errors.New("linuxssh: inline content does not match its hash"),
				map[string]string{"subcommand": helperproto.SubAuthKeysList})
		}
		content = raw
	} else {
		c, _, exists, err := s.readFile(ctx, f.Path)
		if err != nil {
			if !s.fileUnreadable(ctx, err) {
				return err
			}
			res.Partial = true
			res.Warnings = append(res.Warnings, warn("file_unreadable", "user", u.User, "path", f.Path))
			return nil
		}
		if !exists {
			res.ReadFiles = append(res.ReadFiles, f.Path) // removed since it was listed
			return nil
		}
		content = c
	}
```

(keep the code after it — `ParseAuthorizedKeys(content)` — unchanged.)

- [ ] **Step 4: Mirror the helper in the emulator**

In `linuxsshtest/emulator.go`:
- `scanLocked`: users whose name fails `ValidAccount` go to `s.unlisted` with `UnlistedName`; users whose home fails `helperproto.CleanHome` go there with `UnlistedHome`; the others are kept with the cleaned home (the emulator's users have no shell: every added user counts as selected). Cap at `MaxUnlistedAccounts`.
- `listLocked`: `Unlisted: append([]helperproto.UnlistedAccount{}, s.unlisted...)`; the default account names use `ValidAccount`; `AccountsComplete` gains `&& len(s.unlisted) == 0`; a readable file that is not in the `FailRead` set and fits the remaining `MaxListInline` budget gets `Inline: true` and `ContentB64` (the helper inlines what it read; a `FailRead` file stands for one the helper could hash but not return, so discovery falls back to `authkeys-read` and keeps reporting `file_unreadable`).
- `emuScan` gains `unlisted []helperproto.UnlistedAccount`.

Run: `go test ./internal/providers/linuxssh/... -count=1`
Expected: PASS. Fix existing tests whose emulator world now inlines (a test that counts `authkeys-read` calls for files the emulator inlines sets `FailRead` or asserts the lower count, with a comment naming AUD-22).

- [ ] **Step 5: Fidelity**

Add `TestEmulatorFidelityAuthKeysList` to `cmd/alice-helper/emulator_fidelity_test.go` (comment: "AUD-03, AUD-22: authkeys-list on both, for the same accounts and files: users, cleaned homes, paths, hashes, inline content, accounts, accounts_complete, unlisted and warnings are equal"; `skipOddUID(t)` first). The existing fidelity tests compare Nginx subcommands through `twin`; this one needs no `twin`: the helper side uses `newFixture`, replaces `/etc/passwd` with `root`, `john.doe` (home `/home/john.doe`), `trail` (home `/home/trail/`), `bad name` (uid 1009) and `dotdot` (home `/home/x/../dotdot`), and writes one `authorized_keys` per listed home; the emulator side (`linuxsshtest.NewEmulator()`, then its `Handler()` called with the line `sudo -n /usr/local/libexec/alice-helper authkeys-list`) calls `AddUser` with the same values, `SetFile` with the same contents and `SetSSHD` with the fixture's `globalSSHD`. Decode both answers into `map[string]any` and compare `users[*].{user,home,files[*].{path,exists,sha256,inline,content_b64}}`, `accounts`, `accounts_complete`, `unlisted`, `warnings`. If the emulator's defaults cannot express the fixture's root account exactly, normalize that one user away and say why in a comment.

Run: `go test ./cmd/alice-helper -run Fidelity -count=1`
Expected: PASS.

- [ ] **Step 6: Real matrix fixtures**

Append to `test/images/sshd/fixtures.sh` (before the final `for u in …` ownership loop, and add the new users to that loop where they own a file):

```sh
# AUD-03: names Linux and sshd accept beyond SEC-062's pattern, a home written with a trailing
# slash, and entries the helper must report instead of listing. useradd refuses some of these
# names on Debian and Ubuntu, so the entries are written directly.
passwd_user() { # passwd_user <name> <uid> <home> <shell>
	printf '%s:x:%s:%s::%s:%s\n' "$1" "$2" "$2" "$3" "$4" >> /etc/passwd
	printf '%s:x:%s:\n' "$1" "$2" >> /etc/group
	printf '%s:!:19000::::::\n' "$1" >> /etc/shadow
}
passwd_user john.doe 1005 /home/john.doe /bin/bash
passwd_user Deploy2 1006 /home/Deploy2 /bin/bash
passwd_user trail 1007 /home/trail/ /bin/bash
for u in john.doe Deploy2 trail; do
	install -d -m 0755 -o "$u" -g "$u" "/home/$u"
	install -d -m 0700 -o "$u" -g "$u" "/home/$u/.ssh"
	k="$(newkey ed25519 - "$u@laptop")"
	printf '%s\n' "$k" > "/home/$u/.ssh/authorized_keys"
	chown "$u:$u" "/home/$u/.ssh/authorized_keys"
	chmod 0600 "/home/$u/.ssh/authorized_keys"
	record "$u" "$k"
done
passwd_user 'bad,name' 1009 /home/badname /bin/bash   # unlisted: name
passwd_user dotdot 1010 /home/x/../dotdot /bin/bash   # unlisted: home
```

(`/etc/shadow` permissions differ by distribution; if `printf >>` changes its mode on one image, use `chmod --reference` or skip the shadow line there — sshd key authentication of these users is not exercised, only the listing.) In `TestRealOpenSSH`, after the "inventory matches the seeded fixtures exactly" assertion, add:

```go
			// AUD-03: the accounts outside SEC-062's pattern are listed (they are in the fixture keys
			// above); the two that cannot be are reported by uid, and the account list is incomplete.
			assert.False(t, res.AccountsComplete)
			assert.Contains(t, res.Warnings, providers.Warning{Code: helperproto.WarnAccountNameUnsupported, Params: map[string]string{"uid": "1009"}})
			assert.Contains(t, res.Warnings, providers.Warning{Code: helperproto.WarnAccountHomeUnsupported, Params: map[string]string{"uid": "1010"}})
```

Run (Docker): `make test-ssh`
Expected: `TestRealOpenSSH` and `TestRealNginx` PASS on Ubuntu 22.04, Debian 12 and Rocky 9 (the images are rebuilt from the changed fixtures).

- [ ] **Step 7: Web warning texts**

`web/src/api/warnings.ts` `WARNING_PARAMS` gains `account_name_unsupported: ['uid']` and `account_home_unsupported: ['uid']`; `enums.test.ts`'s SSH warning set gains both codes. Locale texts (`warnings.*` in `web/src/locales/{en,tr}.json`):

| Key | EN | TR |
|---|---|---|
| `warnings.account_name_unsupported` | Alice did not list the SSH keys of the account with user ID {{uid}}: its name has characters Alice does not support. | Kullanıcı kimliği {{uid}} olan hesabın SSH anahtarları listelenmedi: hesap adında Alice'in desteklemediği karakterler var. |
| `warnings.account_home_unsupported` | Alice did not list the SSH keys of the account with user ID {{uid}}: its home directory in /etc/passwd is not a plain absolute path. | Kullanıcı kimliği {{uid}} olan hesabın SSH anahtarları listelenmedi: /etc/passwd içindeki ev dizini yalın bir mutlak yol değil. |

Run: `cd web && npx vitest run src/api && cd .. && make i18n-check`
Expected: PASS; `i18n-check` ok.

- [ ] **Step 8: Documentation**

- `docs/nginx-host-preparation.md`: the helper version (`:26`, `:345`) becomes protocol 6, `alice-helper` 1.5.0, with one sentence on what changed (account names with dots, capitals and a final `$` are listed; entries that cannot be listed are reported by user ID; a discovery reads the key files in one pass); `:196-201` ("every account") states the rule of Decision 4 and that an unlisted entry makes Alice stop marking deleted users' keys missing on that server until it is fixed. Updating: copy the new helper and run the setup commands again (the sudoers lines are unchanged).
- `docs/troubleshooting.md`: `:634` names protocol 6 / 1.5.0; next to `too_many_users` (`:651`) add the two warnings: what they mean, how to find the account (`getent passwd <uid>`), what to do (rename the account, or fix the home in `/etc/passwd`; a name longer than 32 characters cannot be listed).

Grep `1.4.0` and `protocol 5` in `docs/` (not in `docs/superpowers/` or `docs/security/reviews/`) and update the remaining current-state statements.

- [ ] **Step 9: Full check and commit**

Run: `make lint && go test ./... -count=1 && go test -tags integration ./internal/inventory/... ./internal/jobs/targetjobs/... -count=1 && make web-test && make i18n-check`
Expected: PASS (Docker for the integration packages).

```bash
git add internal/providers/linuxssh cmd/alice-helper/emulator_fidelity_test.go test/images/sshd/fixtures.sh \
  web/src/api/warnings.ts web/src/api/enums.test.ts web/src/locales docs/nginx-host-preparation.md docs/troubleshooting.md
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "fix(linuxssh): show accounts the helper could not list and read key files from one scan

Refs: AUD-03, AUD-22

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 4: Sessions — only a person's activity slides the idle timeout (server)

Current code: `internal/auth/sessions.go:86-131` — `Authenticate` moves `last_seen_at` and `idle_expires_at` on every call for a full session; `internal/api/guard.go:41,111-118` calls it for every request with a session cookie; `web/src/components/LicenseBanners.tsx:36` polls `GET /api/v1/license/status` every 60 s on every signed-in page (`AppLayout`). The audit's `TestZZAuditBackgroundPollDefeatsIdleTimeout` kept a session for 660 minutes.

**Files:**
- Modify: `internal/auth/sessions.go` (`authenticate`, `Authenticate`, `AuthenticatePassive`)
- Modify: `internal/api/server.go` (`AuthService.AuthenticatePassive`), `internal/api/guard.go` (`activityHeader`, `isActivity`, `authenticate`)
- Modify: `internal/api/fakes_test.go` (`fakeAuth.AuthenticatePassive`), `internal/api/stack_integration_test.go` (`client.do` marks activity by default)
- Modify: `api/openapi.yaml` (`info.description`)
- Test: `internal/auth/session_integration_test.go`, `internal/api/guard_test.go`, `internal/api/session_integration_test.go`

**Interfaces:**
- Produces: `func (s *Service) AuthenticatePassive(ctx context.Context, sessionToken string) (Principal, error)`; header `X-Alice-Activity: 1`; rule `isActivity(r) = !safeMethod(r.Method) || r.Header.Get(activityHeader) == "1"`.

- [ ] **Step 1: Write the failing auth test (adapted from the audit's PoC)**

Add to `internal/auth/session_integration_test.go`:

```go
// AUD-01: a background poll is answered but never extends the idle timeout.
func TestBackgroundPollsDoNotExtendTheIdleTimeout(t *testing.T) {
	e := newEnv(t)
	_, res := e.bootstrap(t) // the session's last activity is now
	alive := 0
	for range 60 {
		e.clk.Advance(time.Minute)
		if _, err := e.svc.AuthenticatePassive(e.ctx, res.Token); err != nil {
			break
		}
		alive++
	}
	assert.Equal(t, 29, alive, "valid until 30 minutes after the last activity, however often it is polled")
}

// AUD-01: a person's action slides the timer; a poll after it neither slides it nor moves last_seen_at.
func TestActivitySlidesAndPollsDoNotTouchTheSession(t *testing.T) {
	e := newEnv(t)
	_, res := e.bootstrap(t)
	lastSeen := func() time.Time {
		var at time.Time
		require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT last_seen_at FROM sessions WHERE kind = 'full'").Scan(&at))
		return at.UTC()
	}
	e.clk.Advance(20 * time.Minute)
	_, err := e.svc.Authenticate(e.ctx, res.Token) // a person's action
	require.NoError(t, err)
	seen := lastSeen()
	assert.True(t, seen.Equal(e.clk.Now().UTC()))
	e.clk.Advance(29 * time.Minute)
	_, err = e.svc.AuthenticatePassive(e.ctx, res.Token)
	require.NoError(t, err, "29 minutes after the action")
	assert.True(t, seen.Equal(lastSeen()), "a poll does not move last_seen_at")
	e.clk.Advance(time.Minute)
	_, err = e.svc.AuthenticatePassive(e.ctx, res.Token)
	assert.ErrorIs(t, err, auth.ErrUnauthenticated, "30 minutes after the action")
}
```

(`bootstrap` leaves exactly one full session; if it leaves more, filter by the token's hash as the file's other session tests do.)

- [ ] **Step 2: Run it to see it fail**

Run: `go test -tags integration ./internal/auth -run TestBackgroundPollsDoNotExtendTheIdleTimeout -count=1` (Docker)
Expected: FAIL — `undefined: AuthenticatePassive`.

- [ ] **Step 3: Implement in `sessions.go`**

Rename the body of `Authenticate` to `func (s *Service) authenticate(ctx context.Context, sessionToken string, slide bool) (Principal, error)` and guard the update:

```go
	p.Kind = rbac.PendingSession
	if kind == "full" {
		p.Kind = rbac.UserSession
		if slide {
			newIdle := now.Add(SessionIdle)
			if newIdle.After(expires) {
				newIdle = expires
			}
			if _, err := s.pool.Exec(ctx, "UPDATE sessions SET last_seen_at = $2, idle_expires_at = $3 WHERE id_hash = $1", h, now, newIdle); err != nil {
				return Principal{}, fmt.Errorf("touch session: %w", err)
			}
		}
	}
	return p, nil
}

// Authenticate resolves a session cookie for a request that is a person's action: a full session
// slides its idle timeout (SEC-019). Role and disabled state are read from users on every call
// (SEC-017); pending sessions never slide.
func (s *Service) Authenticate(ctx context.Context, sessionToken string) (Principal, error) {
	return s.authenticate(ctx, sessionToken, true)
}

// AuthenticatePassive resolves a session cookie for background work of the web UI (a poll). It
// answers like Authenticate but never moves last_seen_at or idle_expires_at, so polling alone
// cannot keep an unattended session alive (AUD-01, R39).
func (s *Service) AuthenticatePassive(ctx context.Context, sessionToken string) (Principal, error) {
	return s.authenticate(ctx, sessionToken, false)
}
```

Run the test again → PASS; `go test -tags integration ./internal/auth -count=1` → PASS.

- [ ] **Step 4: The guard — failing test first**

Add to `internal/api/guard_test.go`:

```go
// AUD-01: an unmarked read is background work; a marked read and every state-changing request
// are a person's action.
func TestOnlyActivitySlidesTheSession(t *testing.T) {
	var active, passive int
	d := testDeps(t, nil)
	p := auth.Principal{Kind: rbac.UserSession, UserID: uuid.New(), Role: rbac.Auditor, SessionHash: []byte("h")}
	d.Auth = &fakeAuth{
		AuthenticateFn:        func(context.Context, string) (auth.Principal, error) { active++; return p, nil },
		AuthenticatePassiveFn: func(context.Context, string) (auth.Principal, error) { passive++; return p, nil },
	}
	h := NewHandler(d)
	send := func(method, path string, mark bool) {
		req := httptest.NewRequest(method, path, nil)
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: "tok"})
		if mark {
			req.Header.Set(activityHeader, "1")
		}
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	send(http.MethodGet, "/api/v1/version", false)
	assert.Equal(t, [2]int{0, 1}, [2]int{active, passive}, "an unmarked read is background work")
	send(http.MethodGet, "/api/v1/version", true)
	assert.Equal(t, [2]int{1, 1}, [2]int{active, passive})
	send(http.MethodPost, "/api/v1/auth/logout", false) // whatever its answer: authentication comes first
	assert.Equal(t, [2]int{2, 1}, [2]int{active, passive})
}
```

(Use the imports `guard_test.go` already has; add `uuid` and `rbac` if missing.) Run: `go test ./internal/api -run TestOnlyActivitySlidesTheSession -count=1` → FAIL (`unknown field AuthenticatePassiveFn`).

- [ ] **Step 5: Implement the guard**

- `server.go` `AuthService` gains `AuthenticatePassive(ctx context.Context, sessionToken string) (auth.Principal, error)` after `Authenticate`.
- `fakes_test.go`: field `AuthenticatePassiveFn func(ctx context.Context, sessionToken string) (auth.Principal, error)` and

```go
func (f *fakeAuth) AuthenticatePassive(ctx context.Context, t string) (auth.Principal, error) {
	if f.AuthenticatePassiveFn != nil {
		return f.AuthenticatePassiveFn(ctx, t)
	}
	return f.Authenticate(ctx, t)
}
```

- `guard.go`:

```go
// activityHeader marks a read of the web UI that follows a person's input (AUD-01, R39).
const activityHeader = "X-Alice-Activity"

// isActivity reports whether r is a person's action for the idle timeout: every state-changing
// request, and a read the web UI marked. Unmarked reads (polls) never extend a session.
func isActivity(r *http.Request) bool {
	return !safeMethod(r.Method) || r.Header.Get(activityHeader) == "1"
}
```

and in `authenticate` the session branch becomes:

```go
	if tok := sessionTokenFrom(r); tok != "" {
		lookup := s.deps.Auth.AuthenticatePassive
		if isActivity(r) {
			lookup = s.deps.Auth.Authenticate
		}
		p, err := lookup(ctx, tok)
```

Every other implementation of `AuthService` (grep `AuthenticateToken(ctx context.Context` in `internal/api` and `cmd/alice`; the audit PoC's `cancelAfterAuth` is not in the tree) gains the method. Run: `go test ./internal/api -count=1` → PASS.

- [ ] **Step 6: API integration — failing test first**

In `stack_integration_test.go`'s `client.do`, before the `for _, o := range opts` loop, add `req.Header.Set(activityHeader, "1") // the integration clients act like a person; tests of background work remove it` . Add to `session_integration_test.go`:

```go
// AUD-01 (A-02): the web UI's minute-by-minute license poll alone does not keep a session open.
func TestA02BackgroundPollsDoNotKeepASessionAlive(t *testing.T) {
	s, c, _ := installed(t)
	requireStatus(t, c.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusOK) // the last action: the reference point
	poll := func() *httptest.ResponseRecorder {
		return c.do(http.MethodGet, "/api/v1/license/status", nil, withoutHeader(activityHeader))
	}
	for i := 1; i <= 29; i++ {
		s.clock.Advance(time.Minute)
		requireStatus(t, poll(), http.StatusOK)
	}
	s.clock.Advance(time.Minute) // 30 minutes after the last action
	requireError(t, poll(), http.StatusUnauthorized, "ALC-AUTH-0001")
}

// A person's read after polls slides the timer again (A-02 "activity resets the idle timer").
func TestA02ActivityAmongPollsSlides(t *testing.T) {
	s, c, _ := installed(t)
	s.clock.Advance(20 * time.Minute)
	requireStatus(t, c.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusOK) // marked
	for i := 0; i < 29; i++ {
		s.clock.Advance(time.Minute)
		requireStatus(t, c.do(http.MethodGet, "/api/v1/license/status", nil, withoutHeader(activityHeader)), http.StatusOK)
	}
}
```

Run: `go test -tags integration ./internal/api -run 'TestA0' -count=1` (Docker)
Expected: PASS (A-02, A-03 and the two new tests; `installed` ends with the administrator's creation, the last action).

- [ ] **Step 7: OpenAPI**

Append to `info.description` in `api/openapi.yaml`: ` A signed-in session's 30-minute idle timeout is extended only by state-changing requests and by reads that carry the header X-Alice-Activity: 1 (the web UI sends it after a person's input); other reads leave it unchanged.` Run `go test ./internal/api -run OpenAPI -count=1` → PASS.

- [ ] **Step 8: Full check and commit**

Run: `make lint && go test ./... -count=1 && go test -tags integration ./internal/auth/... ./internal/api/... -count=1`
Expected: PASS (Docker).

```bash
git add internal/auth/sessions.go internal/auth/session_integration_test.go internal/api/server.go internal/api/guard.go \
  internal/api/guard_test.go internal/api/fakes_test.go internal/api/stack_integration_test.go internal/api/session_integration_test.go api/openapi.yaml
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "fix(auth): only a person's activity extends a session's idle timeout

Background reads of the web UI (the license poll above all) kept an unattended session
alive until its 12-hour limit.

Refs: AUD-01

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 5: Web — activity marking and the unattended-tab journey

**Files:**
- Create: `web/src/api/activity.ts`, `web/src/api/activity.test.ts`
- Modify: `web/src/api/client.ts` (`apiFetch` sets the header), `web/src/main.tsx` (installs the listeners)
- Modify: `web/src/components/LicenseBanners.tsx` (comment only: the poll carries the marker, Decision 2)
- Test: `web/src/api/client.test.ts`, `web/src/components/LicenseBanners.test.tsx` (or the file that tests it — grep `LicenseBanners` in `web/src/**/*.test.tsx`), `web/e2e/phase1.spec.ts`

- [ ] **Step 1: Write the failing unit tests**

`web/src/api/activity.test.ts`:

```ts
import { installActivityListeners, resetActivity, takeActivity } from './activity';

describe('activity marking (AUD-01)', () => {
  beforeEach(() => resetActivity(false));

  it('marks the first request after a trusted input event only', () => {
    const remove = installActivityListeners(window);
    expect(takeActivity()).toBe(false);
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'a' })); // jsdom: isTrusted is false
    expect(takeActivity()).toBe(false);
    remove();
  });

  it('a page load counts as activity once', () => {
    resetActivity(true);
    expect(takeActivity()).toBe(true);
    expect(takeActivity()).toBe(false);
  });
});
```

Trusted events cannot be produced in jsdom, so the listener's decision is tested through the exported `noteInput(event: Event): void` that checks `event.isTrusted` and the type: test it with `{ isTrusted: true, type: 'pointerdown' } as unknown as Event` (marks) and with the types `pointermove`, `focus` and `visibilitychange` (none of which mark). Add to `client.test.ts`:

```ts
it('marks a read as activity only after input, and every state-changing request', async () => {
  const seen: (string | null)[] = [];
  server.use(http.all('/api/v1/echo', ({ request }) => { seen.push(request.headers.get('X-Alice-Activity')); return HttpResponse.json({}); }));
  resetActivity(false);
  await apiFetch('/api/v1/echo');
  noteInput({ isTrusted: true, type: 'keydown' } as unknown as Event);
  await apiFetch('/api/v1/echo');
  await apiFetch('/api/v1/echo');
  await apiFetch('/api/v1/echo', { method: 'POST', body: {} });
  expect(seen).toEqual([null, '1', null, '1']);
});
```

(write the casts as `{ isTrusted: true, type: 'keydown' } as unknown as Event`; import `noteInput` and `resetActivity` from `./activity`), and to the LicenseBanners test: a fake-timer test that renders the banner with a session, calls `noteInput` once, advances 60 s, and asserts the next `/api/v1/license/status` request carried `X-Alice-Activity: 1` (Decision 2's coupling).

Run: `cd web && npx vitest run src/api/activity.test.ts src/api/client.test.ts` → FAIL (module not found).

- [ ] **Step 2: Implement**

`web/src/api/activity.ts`:

```ts
// Activity marking (AUD-01, R39). The server extends a session's idle timeout only for
// state-changing requests and for reads marked X-Alice-Activity: 1. A read is marked when a person
// gave input (a click, a key, the wheel, a touch) since the last marked request; background polls
// after that are unmarked, so an unattended tab is signed out after 30 minutes. Pointer movement
// and focus do not count: browsers fire synthetic moves when content shifts under a resting pointer.
const INPUT_EVENTS = ['pointerdown', 'keydown', 'wheel', 'touchstart'] as const;

let pending = true; // a page load is a person's action

export function noteInput(e: Event): void {
  if (e.isTrusted && (INPUT_EVENTS as readonly string[]).includes(e.type)) pending = true;
}

// takeActivity reports whether the next request is a person's action, and consumes the mark.
export function takeActivity(): boolean {
  const p = pending;
  pending = false;
  return p;
}

export function resetActivity(value: boolean): void {
  pending = value;
}

export function installActivityListeners(target: Window): () => void {
  const opts = { capture: true, passive: true } as const;
  for (const type of INPUT_EVENTS) target.addEventListener(type, noteInput, opts);
  return () => {
    for (const type of INPUT_EVENTS) target.removeEventListener(type, noteInput, opts);
  };
}
```

In `client.ts` `apiFetch`, after the CSRF line:

```ts
  // AUD-01: see activity.ts. State-changing requests are always a person's action.
  if (takeActivity() || method !== 'GET') headers['X-Alice-Activity'] = '1';
```

(import `takeActivity` from `./activity`). In `main.tsx`, after `shareCspNonce(readCspNonce());`: `installActivityListeners(window);`. Run the Vitest files again → PASS; `make web-test && make web-lint` → PASS.

- [ ] **Step 3: The e2e journey**

Add inside the `Phase 1 owner journey (${lang})` describe of `web/e2e/phase1.spec.ts`:

```ts
    test('a page left open is signed out 30 minutes after the last input, although it keeps polling (AUD-01)', async ({ page, request }) => {
      const { totpSecret } = await runWizard(page, request, lang);
      // A refetch of the license status as TanStack Query makes it on a visibility change: no input.
      const poll = async () => {
        const req = page.waitForRequest((r) => r.url().endsWith('/api/v1/license/status'));
        const res = page.waitForResponse((r) => r.url().endsWith('/api/v1/license/status'));
        await page.evaluate(() => window.dispatchEvent(new Event('visibilitychange')));
        return { req: await req, res: await res };
      };
      await poll(); // the wizard's last click may still mark one request
      await advanceClock(request, 20 * 60);
      const bg = await poll();
      expect(bg.req.headers()['x-alice-activity']).toBeUndefined();
      expect(bg.res.status()).toBe(200);
      await advanceClock(request, 11 * 60); // 31 minutes after the last input
      await poll();
      await expect(page.getByRole('heading', { name: either('loginHeading') })).toBeVisible();
      await expect(page.getByText(either('sessionEnded'))).toBeVisible();

      // Positive control: one scroll is a person's activity.
      await signIn(page, request, ADMIN, totpSecret);
      await poll();
      await advanceClock(request, 20 * 60);
      await page.mouse.wheel(0, 40);
      const marked = await poll();
      expect(marked.req.headers()['x-alice-activity']).toBe('1');
      await advanceClock(request, 20 * 60); // 40 minutes after the sign-in, 20 after the scroll
      expect((await poll()).res.status()).toBe(200);
    });
```

Run (Docker; no other Docker work at the same time): `make e2e-up`, then `cd web && set -a && . ../deploy/.env && set +a && ALICE_E2E_PROJECT=alice-e2e npx playwright test e2e/phase1.spec.ts -g 'left open'`, then the whole suite `make e2e`, then `make e2e-down`.
Expected: the new test passes in EN and TR. If an existing journey advances the demo clock by 30 minutes or more in total without any input and expects to stay signed in, it was relying on the defect: add a real input (`await page.mouse.wheel(0, 1)`) at the point where a person would act, with a comment naming AUD-01 — do not weaken the server rule.

- [ ] **Step 4: Full check and commit**

Run: `make web-test && make web-lint && make i18n-check`
Expected: PASS.

```bash
git add web/src/api/activity.ts web/src/api/activity.test.ts web/src/api/client.ts web/src/api/client.test.ts web/src/main.tsx \
  web/src/components/LicenseBanners.tsx web/src/components/LicenseBanners.test.tsx web/e2e/phase1.spec.ts
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "fix(web): mark a person's activity so background polls no longer keep a session alive

Refs: AUD-01

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

(Add any e2e spec files changed in Step 3 to `git add`.)

### Task 6: License gate — time-aware, fails closed without evaluations, evaluation in every process

Current code: `internal/license/service.go:166-183` — `Allow` and `allowIn` read only the snapshot of the last evaluation; `tick.go:43-93` evaluates under the license row lock (`loadInstallation(ctx, tx, true)`, `installation.go:69`) with no lock timeout; `internal/jobs/scheduler.go:117-119` skips every task, `license.evaluate` included, when another session holds the leader advisory lock; `cmd/alice/services.go:181` schedules `Tick` hourly without a deadline. The audit's two PoCs left the gate open 29 and 40 days after the lock time.

**Files:**
- Modify: `internal/license/errors.go` (`ErrUnverified`), `internal/license/service.go` (`MaxEvaluationAge`, `Snapshot.EvaluatedUptime`, `Snapshot.Unverified`, `Allow`, `allowIn`, `sinceEvaluation`, `CheckCanAddTarget`, `staleLogged`, `rowLockTimeout`), `internal/license/tick.go` (`Tick` deadline, `EvaluatedUptime`), `internal/license/installation.go` (`loadInstallation` lock timeout), `internal/license/banners.go` (`unverified` banner), `internal/license/export_test.go` (`SetRowLockTimeout`)
- Modify: `internal/jobs/scheduler.go` (`loopWith`)
- Modify: `internal/api/errors.go` (`ErrLicenseUnverified`, `errorMap`, the code list), `internal/api/guard.go` (`licenseGate`, `licenseRefusal`, `auditLicenseDenied` detail `reason`)
- Modify: `locales/common/{en,tr}.json` (`errors.license.unverified.*`), `docs/troubleshooting.md` (`ALC-LIC-0009`), `web/src/locales/{en,tr}.json` (`license.banner.unverified`), `web/src/components/LicenseBanners.tsx` (`TIME_PARAMS` gains `last_checked`)
- Test: `internal/license/gate_integration_test.go` (new), `internal/license/state_test.go` or a new `gate_test.go` (unit), `internal/jobs/scheduler_test.go`, `internal/api/guard_test.go`
- Modify where needed: integration harnesses that advance the fake clock past 3 h with a real `license.Service` (Step 7)

**Interfaces:**
- Produces: `license.MaxEvaluationAge = 3 * time.Hour`; `license.ErrUnverified` (`errors.Is(ErrUnverified, ErrLocked)` is true); `Snapshot.EvaluatedUptime time.Duration`, `Snapshot.Unverified bool`; banner kind `unverified` (param `last_checked`, RFC 3339); API `ALC-LIC-0009 license.unverified` (503, retryable).

- [ ] **Step 1: Write the failing integration tests (the audit's PoCs, inverted)**

Create `internal/license/gate_integration_test.go`:

```go
//go:build integration

package license_test

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/jobs"
	"alice/internal/license"
)

// AUD-02: a session holding the license row stops every evaluation; the gate still locks at
// LocksAt, by the monotonic time since the last evaluation.
func TestGateLocksAtLocksAtWhileTheRowIsHeld(t *testing.T) {
	e := newEnv(t)
	license.SetRowLockTimeout(e.svc, 200*time.Millisecond)
	now := e.clk.Now()
	_, err := e.upload(e.payload("LIC-A", now, now.Add(24*time.Hour), 10))
	require.NoError(t, err)
	locksAt := now.Add(24*time.Hour + license.GracePeriod)
	e.tickAt(locksAt.Add(-time.Hour)) // grace, evaluated

	tx, err := e.db.App.Begin(e.ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(e.ctx) }()
	_, err = tx.Exec(e.ctx, "SELECT 1 FROM license WHERE id = 1 FOR UPDATE")
	require.NoError(t, err)

	e.clk.Set(locksAt.Add(time.Minute))
	require.Error(t, e.svc.Tick(e.ctx), "the evaluation gives up instead of waiting for ever")
	assert.Equal(t, license.PhaseGrace, e.svc.Snapshot().Eval.Phase, "the snapshot is stale")
	assert.ErrorIs(t, e.svc.Allow(license.ClassChange), license.ErrLocked, "but the gate locked at LocksAt")
	assert.NotErrorIs(t, e.svc.Allow(license.ClassChange), license.ErrUnverified, "61 minutes is not stale yet")
	assert.NoError(t, e.svc.Allow(license.ClassAlways), "recovery and rollback still run")
}

// AUD-02: no successful evaluation for MaxEvaluationAge closes the gate (fail closed); the next
// successful one opens it again.
func TestGateFailsClosedWhenEvaluationsStop(t *testing.T) {
	e := newEnv(t)
	license.SetRowLockTimeout(e.svc, 200*time.Millisecond)
	now := e.clk.Now()
	_, err := e.upload(e.payload("LIC-A", now, now.Add(365*24*time.Hour), 10))
	require.NoError(t, err)
	tx, err := e.db.App.Begin(e.ctx)
	require.NoError(t, err)
	_, err = tx.Exec(e.ctx, "SELECT 1 FROM license WHERE id = 1 FOR UPDATE")
	require.NoError(t, err)

	e.clk.Advance(license.MaxEvaluationAge - time.Minute)
	require.Error(t, e.svc.Tick(e.ctx))
	assert.NoError(t, e.svc.Allow(license.ClassChange), "not stale yet")
	e.clk.Advance(2 * time.Minute)
	require.Error(t, e.svc.Tick(e.ctx))
	err = e.svc.Allow(license.ClassChange)
	assert.ErrorIs(t, err, license.ErrUnverified)
	assert.ErrorIs(t, err, license.ErrLocked, "every lock-mode path treats it as lock")
	assert.NoError(t, e.svc.Allow(license.ClassAlways))
	assert.True(t, e.svc.Snapshot().Unverified)

	require.NoError(t, tx.Rollback(e.ctx))
	require.NoError(t, e.svc.Tick(e.ctx))
	assert.NoError(t, e.svc.Allow(license.ClassChange))
	assert.False(t, e.svc.Snapshot().Unverified)
}

// AUD-02: a foreign session holding the scheduling lock no longer stops license.evaluate.
func TestForeignLeaderLockDoesNotStopEvaluation(t *testing.T) {
	e := newEnv(t)
	now := e.clk.Now()
	_, err := e.upload(e.payload("LIC-A", now, now.Add(24*time.Hour), 10))
	require.NoError(t, err)
	conn, err := e.db.App.Acquire(e.ctx)
	require.NoError(t, err)
	defer conn.Release()
	_, err = conn.Exec(e.ctx, "SELECT pg_advisory_lock(7160927315633811303)") // jobs.leaderLockKey
	require.NoError(t, err)
	log := slog.New(slog.DiscardHandler)
	leader := jobs.NewLeader(e.db.App, log)
	sched := jobs.NewScheduler(e.clk, e.svc, log, jobs.Task{Type: jobs.LicenseEvaluate, Every: time.Hour, Run: e.svc.Tick}).WithLeader(leader)
	ctx, stop := context.WithCancel(e.ctx)
	done := make(chan struct{})
	go func() { sched.Run(ctx); close(done) }()
	defer func() { stop(); <-done; leader.Close() }()

	e.clk.Advance(40 * day)
	require.Eventually(t, func() bool {
		e.clk.Advance(time.Hour)
		return e.svc.Snapshot().Eval.Phase == license.PhaseLocked
	}, 10*time.Second, 100*time.Millisecond, "the evaluation ran although another session holds the leader lock")
	assert.False(t, leader.IsLeader(e.ctx))
}
```

(Check the leader lock key against `internal/jobs` before relying on the literal; if it is an unexported constant, export it through `internal/jobs/export_test.go` only if the test can import it — otherwise keep the literal with a comment naming the constant, as the audit's PoC did.)

- [ ] **Step 2: Run them to see them fail**

Run: `go test -tags integration ./internal/license -run 'TestGate|TestForeignLeader' -count=1` (Docker)
Expected: FAIL — `undefined: license.SetRowLockTimeout`, `license.MaxEvaluationAge`, `license.ErrUnverified`.

- [ ] **Step 3: Implement the gate**

`errors.go` (in the existing `var` block, after `ErrLocked`):

```go
	// ErrUnverified: no evaluation has succeeded for MaxEvaluationAge (AUD-02). Gated work is
	// refused as in lock mode until one succeeds: errors.Is(ErrUnverified, ErrLocked) is true.
	ErrUnverified = fmt.Errorf("%w: the license could not be checked recently", ErrLocked)
```

(add `"fmt"` to its imports if missing.) `service.go`:
- `const MaxEvaluationAge = 3 * time.Hour` with a comment restating Decision 3, and `const defaultRowLockTimeout = 30 * time.Second`, `const tickTimeout = 2 * time.Minute`.
- `Snapshot` gains:

```go
	// EvaluatedUptime is the process uptime when this snapshot was evaluated; the gate advances
	// Reading.Effective by the uptime since then (AUD-02).
	EvaluatedUptime time.Duration
	// Unverified is set by Service.Snapshot when no evaluation has succeeded for MaxEvaluationAge.
	Unverified bool
```

- `Service` gains `rowLockTimeout time.Duration` (set to `defaultRowLockTimeout` in `New`) and `staleLogged atomic.Bool` (`"sync/atomic"`).
- Replace `Snapshot`, `Allow`, `allowIn`:

```go
// Snapshot returns the state as of the last evaluation, with Unverified computed now.
func (s *Service) Snapshot() Snapshot {
	s.mu.Lock()
	snap := s.snap
	s.mu.Unlock()
	snap.Unverified = snap.Ready && s.sinceEvaluation(snap) > MaxEvaluationAge
	return snap
}

// sinceEvaluation is the monotonic time since snap was evaluated (never negative).
func (s *Service) sinceEvaluation(snap Snapshot) time.Duration {
	return max(0, s.uptime.Elapsed()-snap.EvaluatedUptime)
}

// Allow is the single lock-mode gate (spec §8.6, R9): the API guard calls it for routes of
// ClassChange, the scheduler before every task, and CheckCanAddTarget before every target
// insert. It returns ErrLocked while the license or the evaluation has ended,
// ErrUnclassified for work without a class, and fails closed before Start has completed. It does
// not trust a snapshot blindly (AUD-02): it locks once the last evaluation's time, advanced by the
// monotonic uptime since, reaches LocksAt, and returns ErrUnverified when no evaluation has
// succeeded for MaxEvaluationAge.
func (s *Service) Allow(c Class) error {
	snap := s.Snapshot()
	err := allowIn(snap, c, s.sinceEvaluation(snap))
	if errors.Is(err, ErrUnverified) && s.staleLogged.CompareAndSwap(false, true) {
		s.log.Error("the license could not be checked for more than "+MaxEvaluationAge.String()+
			"; changes to managed systems are paused until an evaluation succeeds (check the database)")
	}
	return err
}

// allowIn is the gate decision for one snapshot evaluated since ago.
func allowIn(snap Snapshot, c Class, since time.Duration) error {
	if !c.Valid() {
		return ErrUnclassified
	}
	if c == ClassAlways {
		return nil
	}
	if !snap.Ready || snap.Eval.Locked() {
		return ErrLocked
	}
	if !snap.Eval.LocksAt.IsZero() && !snap.Reading.Effective.Add(since).Before(snap.Eval.LocksAt) {
		return ErrLocked
	}
	if since > MaxEvaluationAge {
		return ErrUnverified
	}
	return nil
}
```

- `CheckCanAddTarget`: `snap := s.Snapshot(); if err := allowIn(snap, ClassChange, s.sinceEvaluation(snap)); err != nil`.
- `installation.go` `loadInstallation`, before the query when `forUpdate`:

```go
	if forUpdate {
		// AUD-02: a session holding the license row must not stop evaluations, uploads and the
		// shutdown save for ever; the gate fails closed on its own after MaxEvaluationAge.
		if _, err := q.Exec(ctx, "SELECT set_config('lock_timeout', $1, true)", strconv.FormatInt(s.rowLockTimeout.Milliseconds(), 10)+"ms"); err != nil {
			return installationRow{}, fmt.Errorf("set the license lock timeout: %w", err)
		}
		sql += " FOR UPDATE"
	}
```

- `tick.go`: `Tick` wraps `ctx, cancel := context.WithTimeout(ctx, tickTimeout); defer cancel()` before taking `evalMu`; in `tickLocked` capture `up := s.uptime.Elapsed()` and pass it to `g.Observe(s.clock.Now(), up)`, and after `snap = c.snap` set `snap.EvaluatedUptime = up`; after `s.publish(g, snap)` call `s.staleLogged.Store(false)`.
- `export_test.go`: `func SetRowLockTimeout(s *Service, d time.Duration) { s.rowLockTimeout = d }`.
- `banners.go` `Banners`, before `if !admin { return out }`:

```go
	if s.Unverified {
		out = append(out, Banner{Kind: "unverified", Severity: SeverityDanger, Params: map[string]string{"last_checked": ts(s.Reading.Effective)}})
	}
```

Add a unit test (`gate_test.go`, package `license` or `license_test` via an exported test helper) for `allowIn`'s table: invalid class, `ClassAlways` stale, not ready, locked phase, `LocksAt` reached by `since`, stale, fresh; and a banners test for `unverified`.

Run: `go test ./internal/license/... -count=1 && go test -tags integration ./internal/license -count=1` (Docker)
Expected: PASS.

- [ ] **Step 4: The scheduler**

In `scheduler.go` `loopWith`:

```go
			// license.evaluate runs in every process (AUD-02): it is serialized by the license row
			// lock and deduplicated by the history index, and a foreign session holding the leader
			// lock must not stop it.
			if s.leader != nil && t.Type != LicenseEvaluate && !s.leader.IsLeader(ctx) {
				continue // another process schedules (P2-06)
			}
```

Add to `scheduler_test.go` a test with a fake leader that is never the leader: `license.evaluate` runs on each tick, another task does not (read the file's existing leader tests and use their fake). Run: `go test ./internal/jobs -count=1` → PASS. Run the leader PoC test of Step 1 → PASS.

- [ ] **Step 5: The API**

`errors.go`: `ErrLicenseUnverified = ErrorCode{Code: "ALC-LIC-0009", Reason: "license.unverified", Status: http.StatusServiceUnavailable, Retryable: true}` next to `ErrLicenseTargetLimit`; add it to every list its neighbours are in (grep `ErrLicenseTargetLimit`); in `errorMap` insert `{license.ErrUnverified, ErrLicenseUnverified, nil},` **before** `{license.ErrLocked, ErrLicenseLocked, nil}`. `guard.go`: replace `licenseAllows` by

```go
// licenseGate asks the single lock gate (license.Service.Allow). Without a license service the
// answer is no: a misconfigured server fails closed.
func (s *server) licenseGate(c license.Class) error {
	if s.deps.License == nil {
		return license.ErrLocked
	}
	return s.deps.License.Allow(c)
}

// licenseRefusal is the answer to a refusal of the gate: unverified (AUD-02) or locked.
func licenseRefusal(err error) ErrorCode {
	if errors.Is(err, license.ErrUnverified) {
		return ErrLicenseUnverified
	}
	return ErrLicenseLocked
}
```

and in `guard`: `if gated(rt.lic) { if err := s.licenseGate(rt.lic); err != nil { s.auditLicenseDenied(r, rt, p, err); s.writeError(w, r, licenseRefusal(err)); return } }`; `auditLicenseDenied` gains the `err` parameter and the detail `"reason": "unverified"` or `"locked"`. Test in `guard_test.go`: a fake license service answering `license.ErrUnverified` makes a gated route answer `ALC-LIC-0009` with status 503 and `Retry-After` absent or present as the error writer does for retryable codes (read `writeError`). Texts:

| Key | EN | TR |
|---|---|---|
| `errors.license.unverified.title` | License not checked | Lisans denetlenemedi |
| `errors.license.unverified.cause` | Alice could not check its license for more than 3 hours, so changes to managed systems are paused. | Alice lisansını 3 saatten uzun süredir denetleyemedi; bu yüzden yönetilen sistemlerdeki değişiklikler duraklatıldı. |
| `errors.license.unverified.action` | Check that the database is reachable and not locked. Changes resume within an hour after the next successful check. | Veritabanına erişilebildiğini ve kilitli olmadığını denetleyin. Değişiklikler bir sonraki başarılı denetimden sonra bir saat içinde yeniden başlar. |
| `license.banner.unverified` (web) | Alice could not check its license since {{last_checked}}. Changes to managed systems are paused until the check succeeds. | Alice lisansını {{last_checked}} tarihinden beri denetleyemedi. Denetim başarılı olana kadar yönetilen sistemlerdeki değişiklikler duraklatıldı. |

`docs/troubleshooting.md` gets `## ALC-LIC-0009: License not checked` (symptom, cause, what to do: database reachability, a session holding the `license` row — `SELECT pid, query FROM pg_stat_activity WHERE …` as the database owner —, logs "the license could not be checked"). `LicenseBanners.tsx` `TIME_PARAMS` gains `'last_checked'`.

Run: `go test ./internal/api -count=1 && make i18n-check && make web-test`
Expected: PASS.

- [ ] **Step 6: The API gate integration**

Add to `internal/api/license_integration_test.go`: with the license row held by a test transaction and `license.SetRowLockTimeout` lowered, advance the stack clock by `license.MaxEvaluationAge + time.Minute`, run `s.license.Tick` (fails), and expect a gated route (for example `POST /api/v1/targets` with a valid body as the administrator) to answer `ALC-LIC-0009`, `GET /api/v1/license/status` to list the banner `unverified`, and `POST /api/v1/audit/verify` (`ClassAlways`) to answer 200.

- [ ] **Step 7: Harnesses that advance time without evaluating**

Run: `go test -tags integration ./internal/... -count=1` (Docker)
Any test that advances a fake clock by more than 3 hours with a real `license.Service` as gate and then expects gated work to run now meets `ErrUnverified` (known places: `internal/jobs/targetjobs/schedule_integration_test.go` advances by days; `internal/api/targets_integration_test.go:359` by 25 h; `internal/api/deploy_failures_integration_test.go:247` by 3 h). Fix each by evaluating after the advance (`require.NoError(t, e.lic.Tick(ctx))`, or a harness helper `advance(d)` that advances and ticks), never by raising `MaxEvaluationAge` or bypassing the gate. A test that advances past `LocksAt` and asserts something before its `Tick` now sees the lock earlier — adjust the assertion to the new rule with a comment naming AUD-02.

- [ ] **Step 8: Full check and commit**

Run: `make lint && go test ./... -count=1 && go test -tags integration ./internal/... -count=1 && make web-test && make i18n-check`
Expected: PASS (Docker).

```bash
git add internal/license internal/jobs/scheduler.go internal/jobs/scheduler_test.go internal/api locales/common docs/troubleshooting.md \
  web/src/locales web/src/components/LicenseBanners.tsx internal/jobs/targetjobs internal/inventory
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "fix(license): the lock gate no longer trusts a stale evaluation

The gate locks at the lock time by itself, fails closed after 3 hours without a successful
evaluation (ALC-LIC-0009), license.evaluate runs in every process, and every wait for the
license row is bounded.

Refs: AUD-02

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

(Stage only the harness files Step 7 actually changed.)

### Task 7: License — an unsealed installation is never trusted; a newer format with new fields asks for an update

Current code: `internal/license/installation.go:93-102` — a row without a seal is trusted and sealed at the next start (`sealUnsealed`, `:181-196`) unless the audit log holds `license.installation_sealed` (`everSealed`, `:55-62`); `ensureInstallation` (`:110-160`) seals new rows at creation but writes no such marker, so every installation created by the current code can be reset with `UPDATE license SET installation_seal = NULL, installed_at = now()` (audit PoC 3); `docs/licensing.md:99-103` says it cannot. `internal/license/file.go:142` runs `checkStructure` (unknown keys refused, `:274-275`) before the format is read (`:146-155`).

**Files:**
- Modify: `internal/license/installation.go` (remove `everSealed`, `sealUnsealed`, `installationRow.unsealed`; a missing seal is `seal_missing`), `internal/license/service.go` (`startLocked` no longer calls `sealUnsealed`)
- Modify: `internal/license/file.go` (`checkStructure(raw []byte, strictKeys bool)`, `ParseFile`)
- Modify: `internal/license/installation_integration_test.go` (the upgrade-sealing tests), `docs/licensing.md` (FAQ)
- Test: `internal/license/installation_integration_test.go`, `internal/license/file_test.go`

- [ ] **Step 1: Write the failing tests (the audit's PoCs, inverted)**

Add to `installation_integration_test.go`:

```go
// AUD-18: removing the seal of an installation is tampering, also on an installation the current
// code created (sealed at creation): the evaluation counts as ended, before and after a restart.
func TestRemovedSealIsTamperingOnEveryInstallation(t *testing.T) {
	e := newEnv(t)
	e.tickAt(installedAt.Add(29 * day))
	require.Equal(t, 1, e.svc.Snapshot().Eval.DaysLeft)

	e.ownerExec("UPDATE license SET installation_seal = NULL, installed_at = $1", installedAt.Add(29*day))
	e.tickAt(installedAt.Add(29*day + time.Hour))
	snap := e.svc.Snapshot()
	assert.True(t, snap.InstallationTampered)
	assert.Equal(t, license.PhaseEvaluationExpired, snap.Eval.Phase)

	e.restart()
	snap = e.svc.Snapshot()
	assert.True(t, snap.InstallationTampered, "never sealed again")
	assert.Equal(t, "seal_missing", e.auditDetails("license.installation_tampered")["problem"])
	assert.Zero(t, e.auditCount("license.installation_sealed"))
}
```

Add to `file_test.go`:

```go
// AUD-19 (L-45): a newer format is "please update Alice" also when it carries fields this version
// does not know; in the current format an unknown field is still invalid.
func TestNewerFormatWithNewFieldsAsksForAnUpdate(t *testing.T) {
	sig := base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	payload := `{"customer":"Example","features":[],"format":2,"installation_id":"ALICE-0000-0000-0000-0000",` +
		`"issued_at":"2026-09-29T09:00:00Z","license_id":"LIC-1","max_targets":10,` +
		`"valid_from":"2026-09-29T00:00:00Z","valid_until":"2027-09-29T00:00:00Z"`
	for name, raw := range map[string]string{
		"no new field":        `{"format":2,"key_id":"vk-2027-01","payload":` + payload + `},"signature":"` + sig + `"}`,
		"new payload field":   `{"format":2,"key_id":"vk-2027-01","payload":` + payload + `,"seats":5},"signature":"` + sig + `"}`,
		"new top-level field": `{"format":2,"key_id":"vk-2027-01","server":"x","payload":` + payload + `},"signature":"` + sig + `"}`,
	} {
		_, err := license.ParseFile([]byte(raw))
		assert.ErrorIs(t, err, license.ErrUnsupportedFormat, name)
	}
	current := strings.Replace(payload, `"format":2`, `"format":1`, 1)
	_, err := license.ParseFile([]byte(`{"format":1,"key_id":"vk-2027-01","server":"x","payload":` + current + `},"signature":"` + sig + `"}`))
	assert.ErrorIs(t, err, license.ErrInvalid, "an unknown field in the current format (FormatVersion 1)")
	_, err = license.ParseFile([]byte(`{"format":2,"format":2,"key_id":"k","payload":{},"signature":""}`))
	assert.ErrorIs(t, err, license.ErrInvalid, "duplicates are refused before the format is read")
}
```

(`file_test.go` is `package license_test`; add `crypto/ed25519`, `encoding/base64` and `strings` to its imports if missing.)

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/license -run TestNewerFormat -count=1 && go test -tags integration ./internal/license -run TestRemovedSeal -count=1` (Docker)
Expected: FAIL — `ErrInvalid` instead of `ErrUnsupportedFormat`; `InstallationTampered` false.

- [ ] **Step 3: Implement**

- `installation.go` `loadInstallation`: replace the `case stored == nil:` block with `case stored == nil: r.Tampered = problemSealMissing // every installation is sealed at creation (AUD-18, R39)`; delete `everSealed`, `sealUnsealed`, the `unsealed` field and their comments (the file header comment keeps the seal's purpose); `service.go` `startLocked` drops `if err := s.sealUnsealed(ctx); err != nil { return err }`. Grep `installation_sealed` and `sealUnsealed` for remaining uses (tests of the upgrade path become tests that an unsealed row is tampering; delete tests whose only purpose was the upgrade marker).
- `file.go`: `checkStructure(raw []byte, strictKeys bool)` refuses an unknown key only when `strictKeys` (`if strictKeys && !stack[n-1].allowed[key] { return invalid("fields") }`); `ParseFile` calls `checkStructure(raw, false)` first, reads the outer format as today, returns `ErrUnsupportedFormat` for a newer one, then calls `checkStructure(raw, true)` before `strictDecode`. Update every other caller of `checkStructure` (grep) to pass `true`.

Run: `go test ./internal/license/... -count=1 && go test -tags integration ./internal/license -count=1 && make fuzz-license`
Expected: PASS; no crasher.

- [ ] **Step 4: The FAQ**

`docs/licensing.md` FAQ "Can someone restart the evaluation by editing or deleting the installation record…": keep "No", and add: "This holds as long as the audit log is intact: someone who controls the database owner account and also rewrites the audit log could hide it; the audit log is protected by a keyed chain from Phase 7 on." Grep the operator guide for the upgrade-sealing text (`installation_sealed`) and remove it.

- [ ] **Step 5: Full check and commit**

Run: `make lint && go test ./... -count=1 && go test -tags integration ./internal/license/... ./internal/api/... -count=1`
Expected: PASS (Docker).

```bash
git add internal/license docs/licensing.md docs/operator-guide.md
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "fix(license): never trust an unsealed installation; a newer format with new fields asks for an update

Refs: AUD-18, AUD-19

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 8: Audit rows of refusals — coalesced and written on a detached context; bounded export and verification; CSV verification line

Current code: `internal/api/guard.go:183-203,216-230` writes `authz.denied` and `request.denied_license` for every refusal, with `r.Context()` (a client that disconnects leaves no row, audit PoC `TestZZAuditDeniedNotRecordedWhenClientDisconnects`); an Operator can add 300 rows a minute per session (`TestZZAuditOperatorGrowsAuditLog`); `internal/api/audit_handlers.go:139-176` exports after a full read-only verification, with the public server's 60 s `WriteTimeout` (`cmd/alice/main.go:256`), and `verifyAudit` (`:129`) has no concurrency bound; the CSV carries the verification only in the `X-Alice-Audit-Intact` header (`:149-216`, AUD-25 c).

**Files:**
- Create: `internal/api/denials.go` (`denialCoalescer`, `denialWindow`)
- Modify: `internal/api/guard.go` (`auditDenied`, `auditLicenseDenied`, `writeAuditDetached`), `internal/api/server.go` (`server.denials`, `server.chainScan`, `newServer`, `ResetLimits`), `internal/api/audit_handlers.go` (`verifyAudit`, `exportAudit`, `writeAuditCSV`)
- Modify: `docs/operator-guide.md` ("Checking an audit export outside Alice": the 60-second sentence, the CSV first line), `api/openapi.yaml` (export description)
- Test: `internal/api/denials_test.go`, `internal/api/audit_integration_test.go` or `session_integration_test.go` (the PoCs), `internal/api/audit_handlers_test.go`

- [ ] **Step 1: Write the failing tests**

`internal/api/denials_test.go`:

```go
package api

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"alice/internal/platform/clock"
)

func TestDenialCoalescer(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 4, 9, 0, 0, 0, time.UTC))
	c := newDenialCoalescer(clk)
	ok, n := c.admit("u:1|audit.read|permission")
	assert.True(t, ok)
	assert.Zero(t, n)
	for i := 0; i < 99; i++ {
		ok, _ = c.admit("u:1|audit.read|permission")
		assert.False(t, ok)
	}
	ok, _ = c.admit("u:2|audit.read|permission")
	assert.True(t, ok, "another subject has its own window")
	clk.Advance(denialWindow)
	ok, n = c.admit("u:1|audit.read|permission")
	assert.True(t, ok)
	assert.Equal(t, 99, n, "the next row carries what was left out")
}

func TestDenialCoalescerIsBounded(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 4, 9, 0, 0, 0, time.UTC))
	c := newDenialCoalescer(clk)
	for i := 0; i < maxDenialKeys+10; i++ {
		c.admit(fmt.Sprintf("u:%d|p|r", i))
	}
	assert.LessOrEqual(t, c.len(), maxDenialKeys)
}
```

(add `"fmt"`.) Integration (add to `session_integration_test.go`, which holds `installedWithOperator`):

```go
// AUD-06: an Operator's repeated refused requests add one audit row per window, and the next row
// after the window says how many were left out.
func TestRepeatedDenialsAreCoalesced(t *testing.T) {
	s, olga := installedWithOperator(t)
	before := s.countWhere("audit_log", "action = 'authz.denied'")
	for range 2 { // two sessions of the same user
		op := s.freshClient()
		s.signIn(op, olga)
		for range 290 {
			requireError(t, op.do(http.MethodGet, "/api/v1/audit", nil), http.StatusForbidden, "ALC-AUTH-0002")
		}
	}
	assert.Equal(t, before+1, s.countWhere("audit_log", "action = 'authz.denied'"))
	s.clock.Advance(10 * time.Minute)
	op := s.freshClient()
	s.signIn(op, olga)
	requireError(t, op.do(http.MethodGet, "/api/v1/audit", nil), http.StatusForbidden, "ALC-AUTH-0002")
	assert.Equal(t, before+2, s.countWhere("audit_log", "action = 'authz.denied'"))
	assert.Equal(t, 1, s.countWhere("audit_log", "action = 'authz.denied' AND details->>'suppressed_count' = '579'"))
}

```

Add `TestDenialIsRecordedWhenTheClientDisconnects` (comment: "AUD-15: a refusal is recorded even when the client disconnects before the audit write"), written fully from the audit's PoC `TestZZAuditDeniedNotRecordedWhenClientDisconnects` with its last two assertions inverted (the row is written; no "audit write failed" is logged) (`cancelAfterAuth` wraps `*auth.Service` and cancels the request context right after the lookup; it must also implement `AuthenticatePassive` after Task 4 — embed and override both). Note: the first denial in the PoC's baseline and the second one have the same subject, permission and reason, so the second would be coalesced — give the second request a different denied route (for example `POST /api/v1/audit/verify` as the Operator) so a row is due. `audit_handlers_test.go`: the CSV export's second line after the BOM starts with `# alice audit export: intact=true checked=` and contains `head_seq=`; a broken chain adds `first_bad_seq=` and `problem=`.

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/api -run 'Denial|Export' -count=1`, then `go test -tags integration ./internal/api -run 'Coalesced|Disconnects' -count=1` (Docker)
Expected: FAIL.

- [ ] **Step 3: Implement**

`internal/api/denials.go`:

```go
package api

import (
	"sync"
	"time"

	"alice/internal/platform/clock"
)

// denialWindow: within it, repeated refusals of one subject for one permission (or license class)
// and reason add no audit row; the next row after it carries suppressed_count (AUD-06, R39).
const denialWindow = 10 * time.Minute

// maxDenialKeys bounds the coalescer's memory; the oldest windows are dropped first.
const maxDenialKeys = 10000

type denialState struct {
	opened     time.Time
	suppressed int
}

type denialCoalescer struct {
	mu   sync.Mutex
	clk  clock.Clock
	seen map[string]*denialState
}

func newDenialCoalescer(clk clock.Clock) *denialCoalescer {
	return &denialCoalescer{clk: clk, seen: map[string]*denialState{}}
}

// admit reports whether a refusal for key gets an audit row now and how many refusals of that key
// were left out since its last row.
func (c *denialCoalescer) admit(key string) (bool, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.clk.Now()
	st, ok := c.seen[key]
	if ok && now.Sub(st.opened) < denialWindow {
		st.suppressed++
		return false, 0
	}
	left := 0
	if ok {
		left = st.suppressed
	} else if len(c.seen) >= maxDenialKeys {
		c.evict(now)
	}
	c.seen[key] = &denialState{opened: now}
	return true, left
}

// evict drops closed windows, then (if none) the oldest one. The caller holds c.mu.
func (c *denialCoalescer) evict(now time.Time) {
	var oldestKey string
	var oldest time.Time
	for k, st := range c.seen {
		if now.Sub(st.opened) >= denialWindow {
			delete(c.seen, k)
			continue
		}
		if oldestKey == "" || st.opened.Before(oldest) {
			oldestKey, oldest = k, st.opened
		}
	}
	if len(c.seen) >= maxDenialKeys {
		delete(c.seen, oldestKey)
	}
}

func (c *denialCoalescer) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.seen)
}

func (c *denialCoalescer) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seen = map[string]*denialState{}
}
```

`guard.go`:

```go
// auditWriteTimeout bounds an audit write that outlives its request (AUD-15).
const auditWriteTimeout = 5 * time.Second

// writeAuditDetached writes ev on a context that the client's disconnect does not cancel.
func (s *server) writeAuditDetached(r *http.Request, ev audit.Event) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), auditWriteTimeout)
	defer cancel()
	if err := s.deps.Audit.Write(ctx, ev); err != nil {
		s.deps.Log.Error("audit write failed", append([]any{"request_id", RequestID(r.Context()), "action", ev.Action}, errorAttrs(err)...)...)
	}
}

// denialSubject identifies who was refused, for coalescing.
func denialSubject(p auth.Principal) string {
	if p.Kind == rbac.APIToken {
		return "t:" + p.TokenID.String()
	}
	return "u:" + p.UserID.String()
}
```

`auditDenied` keeps its early return, then `ok, left := s.denials.admit(denialSubject(p) + "|" + string(rt.perm) + "|" + reason); if !ok { return }`, adds `"suppressed_count": strconv.Itoa(left)` when `left > 0`, and calls `s.writeAuditDetached(r, ev)`. `auditLicenseDenied` does the same with the key `denialSubject(p) + "|license:" + rt.lic.String() + "|" + reason`. `server` gains `denials *denialCoalescer` and `chainScan chan struct{}` (capacity 1), both set in `newServer`; `ResetLimits` calls `s.s.denials.reset()`.

`audit_handlers.go`:

```go
// exportWriteTimeout replaces the server's 60-second write limit for one export (AUD-06).
const exportWriteTimeout = 10 * time.Minute

// scanChain runs fn while no other verification or export of this process reads the whole chain.
func (s *server) scanChain(ctx context.Context, fn func() error) error {
	select {
	case s.chainScan <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-s.chainScan }()
	return fn()
}
```

`verifyAudit` wraps its `Verify` call in `s.scanChain`; `exportAudit` wraps everything from `VerifyReadOnly` to the end of the writing in `s.scanChain`, and first calls `_ = http.NewResponseController(w).SetWriteDeadline(clock.Real{}.Now().Add(exportWriteTimeout))` (an absolute network deadline; the error is ignored where the writer does not support it, as in `httptest`). `writeAuditCSV` takes the `audit.Report` and writes, right after the BOM:

```go
	line := fmt.Sprintf("# alice audit export: intact=%t checked=%d head_seq=%d head_hash=%x", report.Intact, report.Checked, report.HeadSeq, report.HeadHash)
	if !report.Intact {
		line += fmt.Sprintf(" first_bad_seq=%d problem=%s", report.FirstBadSeq, report.Problem)
	}
	if _, err := io.WriteString(w, line+"\n"); err != nil {
		return err
	}
```

Grep `authz.denied` and `request.denied_license` in tests: a test that expects one row per refused request now sends refusals that differ in permission or reason, or expects the coalesced count, with a comment naming AUD-06.

Run: `go test ./internal/api -count=1 && go test -tags integration ./internal/api -count=1` (Docker)
Expected: PASS.

- [ ] **Step 4: Documentation**

`docs/operator-guide.md`: replace "Very large logs may not finish within the server's 60-second response limit" by the 10-minute limit; describe the CSV's first line; note that repeated refusals of one person for one permission are recorded once per 10 minutes with the number left out. `api/openapi.yaml` export operation description: the CSV's first line.

- [ ] **Step 5: Full check and commit**

Run: `make lint && go test ./... -count=1 && go test -tags integration ./internal/api/... ./internal/audit/... -count=1`
Expected: PASS (Docker).

```bash
git add internal/api docs/operator-guide.md api/openapi.yaml
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "fix(api): coalesce repeated refusals in the audit log, record them after a disconnect, bound exports

Refs: AUD-06, AUD-15, AUD-25

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 9: Rate limits before credential lookups; `/healthz` limited on the public listener

Current code: `internal/api/guard.go:39-48` authenticates (a session lookup and a setup-session lookup, each a database query) before `allowRate`; the audit's `TestZZAuditRateLimitDoesNotBoundAuthLookups` saw 500 of each for 500 anonymous requests with garbage cookies. `internal/api/server.go:277` serves `/healthz` (a database check) with `limitNone` on the public listener too (`apiRoutes` includes `probeRoutes`, `:305`).

**Files:**
- Modify: `internal/auth/ratelimit/ratelimit.go` (`Limiter.Blocked`)
- Modify: `internal/api/server.go` (`server.badCreds`, `newServer`, `ResetLimits`, `probeRoutes(public bool)`), `internal/api/guard.go` (`guard`, `presentsCredential`)
- Modify: `api/openapi.yaml` (`/healthz` answers 429), `docs/operator-guide.md` (health endpoints)
- Test: `internal/auth/ratelimit/ratelimit_test.go`, `internal/api/guard_test.go`, `internal/api/server_test.go`

- [ ] **Step 1: Write the failing tests**

`ratelimit_test.go`:

```go
func TestBlockedTakesNoToken(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 4, 9, 0, 0, 0, time.UTC))
	l := New(clk, 2, time.Minute)
	blocked, _ := l.Blocked("ip")
	assert.False(t, blocked, "an unknown key is not blocked")
	l.Allow("ip")
	l.Allow("ip")
	blocked, wait := l.Blocked("ip")
	assert.True(t, blocked)
	assert.Equal(t, 30*time.Second, wait)
	for i := 0; i < 5; i++ {
		l.Blocked("ip") // never takes a token
	}
	clk.Advance(30 * time.Second)
	blocked, _ = l.Blocked("ip")
	assert.False(t, blocked)
}
```

`guard_test.go` (the audit's PoC, inverted):

```go
// AUD-16: garbage credentials buy at most one bucket of lookups per address and minute; a valid
// session never pays.
func TestCredentialLookupsAreRateLimitedBeforeTheLookup(t *testing.T) {
	d := testDeps(t, nil)
	sessionLookups, setupLookups := 0, 0
	d.Auth = &fakeAuth{
		AuthenticateFn:        func(context.Context, string) (auth.Principal, error) { sessionLookups++; return auth.Principal{}, auth.ErrUnauthenticated },
		AuthenticatePassiveFn: func(context.Context, string) (auth.Principal, error) { sessionLookups++; return auth.Principal{}, auth.ErrUnauthenticated },
	}
	d.Setup = &fakeSetup{AuthenticateFn: func(context.Context, string) error { setupLookups++; return setup.ErrSessionInvalid }}
	h := NewHandler(d)
	limited := 0
	for range 500 {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/version", nil)
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: "garbage"})
		req.AddCookie(&http.Cookie{Name: setupCookie, Value: "garbage"})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			limited++
			assert.NotEmpty(t, rec.Header().Get("Retry-After"))
		}
	}
	assert.Equal(t, 440, limited)
	assert.Equal(t, 60, sessionLookups)
	assert.Equal(t, 60, setupLookups)
}
```

and a second test: 500 requests with a cookie the fake resolves to a `UserSession` principal from one address are never answered 429 by the failed-credential bucket (they meet only the per-session limit of 300). `server_test.go`: 61 `GET /healthz` from one address on `NewHandler` → the 61st is 429; 200 on `NewHealthHandler` → never 429 (use the file's fake health checker).

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/auth/ratelimit ./internal/api -run 'Blocked|CredentialLookups|Healthz' -count=1`
Expected: FAIL.

- [ ] **Step 3: Implement**

`ratelimit.go`:

```go
// Blocked reports, without taking a token, whether key has none left, and how long until it has
// one (rounded up to whole seconds, at least 1 s). An unknown key is not blocked.
func (l *Limiter) Blocked(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		return false, 0
	}
	l.refill(b, l.clock.Now())
	if b.tokens >= 1 {
		return false, 0
	}
	return true, ceilSecond(time.Duration((1 - b.tokens) / l.limit * float64(l.per)))
}
```

`server.go`: `badCreds *ratelimit.Limiter // per IP: credentials that did not resolve, 60/min (AUD-16)` set to `ratelimit.New(d.Clock, 60, time.Minute)`; `ResetLimits` resets it. `probeRoutes(public bool)`: `/healthz` gets `limitDefault` when `public` (the anonymous per-IP limit) and `limitNone` otherwise; `apiRoutes` calls `s.probeRoutes(true)`, `NewHealthHandler` `s.probeRoutes(false)`; `/livez` stays `limitNone` (no dependency). `guard.go`:

```go
// presentsCredential reports whether r carries a session, setup-session or bearer credential.
func presentsCredential(r *http.Request) bool {
	return hasBearer(r) || sessionTokenFrom(r) != "" || setupTokenFrom(r) != ""
}
```

and in `guard`, the authentication block becomes:

```go
		ip := clientIP(r, s.deps.TrustedProxies)
		ipKey := ratelimit.IPKey(ip)
		p, csrfToken := auth.Principal{}, ""
		if !policy.Anonymous {
			creds := presentsCredential(r)
			// AUD-16: an address whose credentials keep failing gets no more lookups this minute.
			if blocked, retry := s.badCreds.Blocked(ipKey); creds && blocked {
				w.Header().Set("Retry-After", strconv.Itoa(int(retry/time.Second)))
				s.writeError(w, r, ErrRateLimited)
				return
			}
			var err error
			if p, csrfToken, err = s.authenticate(r); err != nil {
				s.authUnavailable(w, r, err)
				return
			}
			if creds && p.Kind == rbac.Anonymous {
				s.badCreds.Allow(ipKey)
			}
		}
		if !s.allowRate(w, r, rt.limit, p, ipKey) {
			return
		}
```

(`ipKey` replaces the later `ratelimit.IPKey(ip)` argument; keep the existing order of the CSRF and permission checks.)

Run: `go test ./internal/auth/ratelimit ./internal/api -count=1` → PASS; `go test ./internal/api -run OpenAPI -count=1` after adding `"429": { $ref: "#/components/responses/Error" }` to `/healthz` → PASS.

- [ ] **Step 4: Full check and commit**

Run: `make lint && go test ./... -count=1 && go test -tags integration ./internal/api -count=1`
Expected: PASS (Docker).

```bash
git add internal/auth/ratelimit internal/api api/openapi.yaml docs/operator-guide.md
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "fix(api): rate-limit failing credentials before their lookup; limit /healthz on the public listener

Refs: AUD-16

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 10: Text PostgreSQL cannot store is refused at the edge; cursor ranges

Current code: query text reaches SQL unchecked (`internal/api/audit_handlers.go:84` `actor`/`action`, `internal/api/sshkeys_handlers.go:74,81` `os_user`/`q`, the certificates `q`); JSON strings with `\u0000` decode into Go strings with NUL and reach PostgreSQL (`internal/api/auth_handlers.go:45` → `internal/auth/login.go:110,230` → SQLSTATE 22021, a 500 and no `auth.login` row; `internal/auth/profile.go:38`, `internal/auth/tokens.go:60-66`); `internal/jobs/queue.go:346` and `internal/inventory/sshkeys.go:420` decode a cursor's microseconds into any `time.Time`, which PostgreSQL cannot hold at the extremes.

**Files:**
- Create: `internal/platform/validate/text.go`, `internal/platform/validate/text_test.go` (`StorableText`)
- Create: `internal/api/nul.go` (`containsNUL`), `internal/api/nul_test.go`
- Modify: `internal/api/guard.go` (query check first), `internal/api/httpx.go` (`decodeBody`, `decodeExact`)
- Modify: `internal/auth/login.go` (`Login`)
- Modify: `internal/jobs/queue.go`, `internal/inventory/sshkeys.go` (`decodeCursor` ranges)
- Test: `internal/api/edge_integration_test.go` (new), `internal/auth/login_integration_test.go`, `internal/jobs/queue_test.go` or its cursor test, `internal/inventory/sshkeys_test.go` (or the package's unit cursor test)

- [ ] **Step 1: Write the failing tests (adapted from the audit's PoCs)**

`internal/api/edge_integration_test.go`:

```go
//go:build integration

package api

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func edgeCursor(sep, micros string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(micros + sep + "018f0000-0000-7000-8000-000000000000"))
}

// AUD-13: no text parameter and no cursor answers 5xx; NUL and invalid UTF-8 are 400 at the edge.
func TestUnstorableTextIsRefusedAtTheEdge(t *testing.T) {
	s, admin, acct := installed(t)
	for _, p := range []string{
		"/api/v1/audit?actor=" + url.QueryEscape("a\x00b"), "/api/v1/audit?action=a%00b", "/api/v1/audit?actor=%ff",
		"/api/v1/ssh-keys?os_user=a%00b", "/api/v1/ssh-keys?os_user=%ff", "/api/v1/ssh-keys?q=a%00b",
		"/api/v1/certificates?q=a%00b", "/api/v1/certificates?q=%ff", "/api/v1/audit?%ff=1",
	} {
		requireError(t, admin.do(http.MethodGet, p, nil), http.StatusBadRequest, "ALC-SYS-0004")
	}
	for _, p := range []string{
		"/api/v1/ssh-keys?cursor=" + edgeCursor(".", "-9223372036854775808"),
		"/api/v1/ssh-keys?cursor=" + edgeCursor(".", "9223372036854775807"),
		"/api/v1/certificates?cursor=" + edgeCursor(".", "-9223372036854775808"),
		"/api/v1/deployments?cursor=" + edgeCursor(".", "-9223372036854775808"),
		"/api/v1/jobs?cursor=" + edgeCursor("|", "-9223372036854775808"),
		"/api/v1/jobs?cursor=" + edgeCursor("|", "9223372036854775807"),
		"/api/v1/audit?cursor=9223372036854775807",
	} {
		rec := admin.do(http.MethodGet, p, nil)
		assert.Less(t, rec.Code, 500, p)
	}
	anon := s.freshClient()
	failed := s.countWhere("audit_log", "action LIKE 'auth.login%'")
	requireError(t, anon.do(http.MethodPost, "/api/v1/auth/login", map[string]string{"username": "a\x00b", "password": "whatever-password"}),
		http.StatusBadRequest, "ALC-SYS-0004")
	assert.Equal(t, failed, s.countWhere("audit_log", "action LIKE 'auth.login%'"), "a malformed body is not a sign-in attempt (Decision 10)")
	s.stepUp(admin, acct)
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{http.MethodPost, "/api/v1/users", map[string]string{"username": "nulx", "display_name": "a\x00b", "email": "", "role": "auditor", "password": "a long enough password 1"}},
		{http.MethodPost, "/api/v1/tokens", map[string]any{"name": "a\x00b", "scope": "read", "expires_in_days": 1}},
		{http.MethodPost, "/api/v1/targets", map[string]any{"name": "a\x00b", "type": "linux", "host": "192.0.2.10", "port": 22, "username": "alice-svc"}},
		{http.MethodPost, "/api/v1/certificates/csr", map[string]any{"common_name": "a\x00b", "key_type": "ecdsa-p256"}},
		{http.MethodPost, "/api/v1/license/preview", map[string]any{"license": "a\x00b"}},
		{http.MethodPost, "/api/v1/auth/password", map[string]any{"current_password": "a\x00b", "new_password": "a\x00b long enough password"}},
	} {
		requireError(t, admin.do(c.method, c.path, c.body), http.StatusBadRequest, "ALC-SYS-0004")
	}
	assert.NotContains(t, s.logs.String(), "request failed")
}
```

(Check each route and body shape against the route table before relying on it; replace any route that has moved. A route reached through `decodeExact` belongs in the table too — pick one of the Phase 4 certificate routes.) Add to `login_integration_test.go`:

```go
// AUD-13: a name PostgreSQL cannot store is an unknown user for callers below the HTTP layer:
// the generic answer, the same work, and an audit row.
func TestLoginTreatsAnUnstorableNameAsUnknown(t *testing.T) {
	e := newEnv(t)
	e.bootstrap(t)
	before := e.countAction(t, "auth.login", "failure")
	for _, name := range []string{"adm\x00in", "adm\xffin"} {
		_, err := e.svc.Login(e.ctx, name, "whatever it is", meta)
		assert.ErrorIs(t, err, auth.ErrInvalidCredentials)
	}
	assert.Equal(t, before+2, e.countAction(t, "auth.login", "failure"))
}
```

Unit tests: `StorableText` table (valid, NUL, `\xff`, empty is storable); `containsNUL` over a struct with a nested slice of structs, a map, a pointer, an interface holding a string, and a `json.RawMessage` holding `"\u0000"`; both `decodeCursor`s refuse `-1` and the `int64` extremes and accept `0` and a 2026 value.

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/platform/validate ./internal/api ./internal/jobs ./internal/inventory -count=1` and `go test -tags integration ./internal/api -run Unstorable -count=1 && go test -tags integration ./internal/auth -run Unstorable -count=1` (Docker)
Expected: FAIL (500s, `undefined: StorableText`).

- [ ] **Step 3: Implement**

`internal/platform/validate/text.go`:

```go
package validate

import (
	"strings"
	"unicode/utf8"
)

// StorableText reports whether s can be stored in a PostgreSQL text column: valid UTF-8 without
// a NUL character (AUD-13).
func StorableText(s string) bool { return utf8.ValidString(s) && !strings.ContainsRune(s, 0) }
```

`internal/api/nul.go`:

```go
package api

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
)

var rawMessageType = reflect.TypeOf(json.RawMessage(nil))

// containsNUL reports whether any string reachable from v holds a NUL, or a json.RawMessage holds
// the escape \u0000 (AUD-13: PostgreSQL cannot store it).
func containsNUL(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		return !v.IsNil() && containsNUL(v.Elem())
	case reflect.String:
		return strings.ContainsRune(v.String(), 0)
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).IsExported() && containsNUL(v.Field(i)) {
				return true
			}
		}
	case reflect.Slice:
		if v.Type() == rawMessageType {
			return bytes.Contains(v.Bytes(), []byte(`\u0000`))
		}
		fallthrough
	case reflect.Array:
		for i := 0; i < v.Len(); i++ {
			if containsNUL(v.Index(i)) {
				return true
			}
		}
	case reflect.Map:
		it := v.MapRange()
		for it.Next() {
			if containsNUL(it.Key()) || containsNUL(it.Value()) {
				return true
			}
		}
	}
	return false
}
```

(`[]byte` fields other than `json.RawMessage` are walked byte by byte as `uint8`, which is harmless; if a DTO carries large `[]byte`, add `case reflect.Slice` with `v.Type().Elem().Kind() == reflect.Uint8 → false` before the walk.) `httpx.go`: in `decodeBody` after the trailing-data check succeeds, and in `decodeExact` after `json.Unmarshal` succeeds: `if containsNUL(reflect.ValueOf(dst)) { s.writeError(w, r, ErrBadRequest); return false }`. `guard.go`, first statement inside the handler func:

```go
		if !storableQuery(r) {
			s.writeError(w, r, ErrBadRequest) // AUD-13: text PostgreSQL cannot store
			return
		}
```

with

```go
// storableQuery reports whether every query key and value is StorableText.
func storableQuery(r *http.Request) bool {
	for k, vs := range r.URL.Query() {
		if !validate.StorableText(k) {
			return false
		}
		for _, v := range vs {
			if !validate.StorableText(v) {
				return false
			}
		}
	}
	return true
}
```

(import `alice/internal/platform/validate`; the package may already be imported as `validate`.) `login.go` `Login`, first statement:

```go
	if !validate.StorableText(username) {
		// AUD-13: such a name cannot reach PostgreSQL; it is an unknown user (the same work, audited).
		username = "\uFFFD"
	}
```

Both `decodeCursor`s: after parsing the microseconds, `if micros < 0 || micros > maxCursorMicros { … bad cursor … }` with `var maxCursorMicros = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC).UnixMicro()` (in each package).

Run: the commands of Step 2 → PASS; then `go test -tags integration ./internal/api ./internal/auth ./internal/jobs ./internal/inventory -count=1` (Docker) → PASS.

- [ ] **Step 4: Full check and commit**

Run: `make lint && go test ./... -count=1`
Expected: PASS.

```bash
git add internal/platform/validate internal/api internal/auth/login.go internal/auth/login_integration_test.go internal/jobs/queue.go \
  internal/jobs/*_test.go internal/inventory/sshkeys.go internal/inventory/*_test.go
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "fix(api): refuse text PostgreSQL cannot store before any handler; bound cursor times

Refs: AUD-13

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

(Stage only the test files you changed.)

### Task 11: Sign-in timing under the name lock; password reset and sign-out-everywhere revoke API tokens

Current code: `internal/auth/login.go:239,246,281` — for an unknown or blocked account the dummy Argon2 run happens after the transaction released the per-name advisory lock, while a real account's verification runs under it (`:249`), so two parallel attempts for an unknown name finish in about T and for a real one in about 2T (audit AUD-11, PoC ratio 1.79). `internal/auth/users.go:329-349` — `ResetPassword` and `RevokeSessions` delete sessions only; API tokens keep working (PoC `TestZZAuditPasswordResetKeepsAPITokens`).

**Files:**
- Modify: `internal/auth/password.go` (`Hasher.dummyHook`), `internal/auth/export_test.go` (`SetDummyVerifyHook`), `internal/auth/login.go` (`Login`)
- Modify: `internal/auth/users.go` (`ResetPassword`, `RevokeSessions`, `revokeUserTokens`)
- Modify: `web/src/locales/{en,tr}.json` (`users.resetPasswordText`, `users.confirm.revokeText`), `api/openapi.yaml` (the two operations' descriptions), `docs/admin-guide.md` (users section)
- Test: `internal/auth/login_integration_test.go`, `internal/auth/users_integration_test.go`, `internal/auth/lockout_integration_test.go` (timing expectations, if any)

- [ ] **Step 1: Write the failing tests**

```go
// AUD-11: an unknown name's dummy check runs while the name lock is held, as a real check does, so
// parallel attempts take as long for unknown names as for real ones.
func TestDummyCheckRunsUnderTheNameLock(t *testing.T) {
	e := newEnv(t)
	e.bootstrap(t)
	var held []int
	auth.SetDummyVerifyHook(e.hasher, func() {
		var n int
		require.NoError(t, e.db.Owner.QueryRow(e.ctx, `SELECT count(*) FROM pg_locks
WHERE locktype = 'advisory' AND granted AND classid = $1::oid AND objsubid = 2`, int64(auth.LoginNameLockNamespace)).Scan(&n))
		held = append(held, n)
	})
	_, err := e.svc.Login(e.ctx, "ghost", "definitely not it", meta)
	require.ErrorIs(t, err, auth.ErrInvalidCredentials)
	// A blocked account is the second dummy path (setFailures clears locked_until, so block it here).
	_, err = e.db.Owner.Exec(e.ctx, "UPDATE users SET locked_until = $1 WHERE username = 'admin'", e.clk.Now().Add(time.Minute))
	require.NoError(t, err)
	_, err = e.svc.Login(e.ctx, "admin", "definitely not it", meta)
	require.ErrorIs(t, err, auth.ErrInvalidCredentials)
	assert.Equal(t, []int{1, 1}, held)
}
```

(`bootstrap` creates the administrator `admin`; check the name in `env_integration_test.go`.) Add to `users_integration_test.go` (the PoC, inverted):

```go
// AUD-12: an administrator's password reset and sign-out-everywhere also revoke the user's API
// tokens; a user's own password change does not.
func TestResetAndSignOutEverywhereRevokeAPITokens(t *testing.T) {
	e := newEnv(t)
	_, res := e.bootstrap(t)
	admin := e.principal(t, res.Token)
	tok, _, err := e.svc.CreateToken(e.ctx, admin, meta, auth.NewToken{Name: "ci", Scope: "read", ExpiresInDays: 30})
	require.NoError(t, err)
	require.NoError(t, e.svc.ResetPassword(e.ctx, admin, meta, admin.UserID, "a brand new long password"))
	_, err = e.svc.AuthenticateToken(e.ctx, tok)
	assert.ErrorIs(t, err, auth.ErrUnauthenticated)
}
```

Extend it in the same test with the file's existing helpers (`principal`, the sign-in used by `TestIdleTimeoutSlidesAndAbsoluteLimitHolds`, `ChangePassword`'s signature from `internal/auth/account.go`): sign in again with the new password, create a second token, `RevokeSessions` → that token is refused too; sign in again, create a third token, `ChangePassword` by the user → the third token still works; the audit rows `user.password_reset` and `user.sessions_revoked` carry `revoked_token_count` `1`.

- [ ] **Step 2: Run them to see them fail**

Run: `go test -tags integration ./internal/auth -run 'DummyCheck|RevokeAPITokens' -count=1` (Docker)
Expected: FAIL — `undefined: auth.SetDummyVerifyHook`; the token still authenticates.

- [ ] **Step 3: Implement**

- `password.go`: `Hasher` gains `dummyHook func() // tests only: runs at the start of DummyVerify`; `DummyVerify` starts with `if h.dummyHook != nil { h.dummyHook() }`. `export_test.go`: `func SetDummyVerifyHook(h *Hasher, f func()) { h.dummyHook = f }`.
- `login.go` `Login`: remove the `dummyVerify` variable and the post-transaction call; in the two branches call it inside the transaction, before the audit append:

```go
			if !found || a.hash == nil {
				failed = true
				// SEC-004, AUD-11: the dummy check runs under the name lock, like a real check, so
				// parallel attempts cost the same for unknown and real names.
				s.hasher.DummyVerify(ctx, pw)
				return s.auditFailure(ctx, tx, audit.Actor{Type: audit.ActorUser, Name: unknownUserName, IP: m.IP, RequestID: m.RequestID}, "auth.login", "", "unknown_user")
			}
			actor := userActor(a.id, a.name, m)
			if a.blocked(now) {
				// Not counted and the password is not checked; the dummy run keeps the timing.
				failed = true
				s.hasher.DummyVerify(ctx, pw)
				return s.auditFailure(ctx, tx, actor, "auth.login", a.id.String(), "locked")
			}
```

and update `Login`'s doc comment.
- `users.go`:

```go
// revokeUserTokens revokes every live API token of a user and returns how many (AUD-12).
func revokeUserTokens(ctx context.Context, q db.Querier, userID uuid.UUID, now time.Time) (int64, error) {
	tag, err := q.Exec(ctx, "UPDATE api_tokens SET revoked_at = $2 WHERE user_id = $1 AND revoked_at IS NULL", userID, now)
	if err != nil {
		return 0, fmt.Errorf("revoke tokens: %w", err)
	}
	return tag.RowsAffected(), nil
}
```

`ResetPassword` passes `details := map[string]string{}` to `adminChange` and, inside `fn` after `revokeUserSessions`, `n, err := revokeUserTokens(ctx, tx, id, now)`, `details["revoked_token_count"] = strconv.FormatInt(n, 10)`; `RevokeSessions` the same (with `now := s.clock.Now().UTC()`). Update both doc comments ("ends sessions and revokes API tokens (AUD-12, R39)").

Run: `go test -tags integration ./internal/auth -count=1` (Docker) → PASS.

- [ ] **Step 4: Texts and docs**

| Key | EN | TR |
|---|---|---|
| `users.resetPasswordText` | The person is signed out everywhere, their API tokens stop working, and they must use this password at the next sign-in. Give it to them in a safe way. | Kişi her yerden çıkış yapar, API belirteçleri çalışmaz olur ve bir sonraki girişte bu parolayı kullanması gerekir. Parolayı ona güvenli bir yoldan iletin. |
| `users.confirm.revokeText` | The person is signed out on every device and all their API tokens stop working. | Kişi tüm cihazlarda oturumdan çıkarılır ve tüm API belirteçleri çalışmaz olur. |

(Read the current TR values and keep their terms for "token" and "sign out" if the catalog already fixes them.) `api/openapi.yaml`: the reset-password and revoke-sessions operations' descriptions say tokens are revoked. `docs/admin-guide.md` users section: the same, and that a user's own password change keeps tokens. Run `cd web && npx vitest run src/pages/UsersPage.test.tsx && cd .. && make i18n-check` → PASS (update a test that matches the old text).

- [ ] **Step 5: Full check and commit**

Run: `make lint && go test ./... -count=1 && go test -tags integration ./internal/auth/... ./internal/api/... -count=1 && make web-test`
Expected: PASS (Docker).

```bash
git add internal/auth web/src/locales web/src/pages api/openapi.yaml docs/admin-guide.md
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "fix(auth): dummy checks under the name lock; reset and sign-out-everywhere revoke API tokens

Refs: AUD-11, AUD-12

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 12: Setup code reset wins against a running admin creation; the master key's directory is synced

Current code: `internal/setup/admin.go:64` authenticates the wizard session outside the transaction that creates the administrator (`internal/auth/bootstrap.go:50`), and the transaction's callback (`admin.go:98-101`) deletes all sessions without checking the caller's own still exists, so a `setup-token --reset` (`internal/setup/code.go:53-68`) between the two does not stop the creation (AUD-21). `internal/secrets/masterkey.go:120-150` `createKeyFile` syncs the file but never its directory (AUD-20; `internal/license/hwm.go:183-212` does).

**Files:**
- Modify: `internal/setup/admin.go` (`CreateAdmin` callback; `Service.beforeBootstrap`), `internal/setup/setup.go` (field), create `internal/setup/export_test.go`
- Modify: `internal/secrets/masterkey.go` (`createKeyFile`, `syncDir` variable, `syncDirectory`)
- Test: `internal/setup/setup_integration_test.go`, `internal/secrets/masterkey_test.go`

- [ ] **Step 1: Write the failing tests**

```go
// AUD-21: a setup code reset between the session check and the administrator's creation wins: no
// administrator is created and the old session is refused.
func TestResetDuringAdminCreationWins(t *testing.T) {
	e := newEnv(t)
	token := e.session(t)
	enr, err := e.setup.BeginAdminEnrollment(e.ctx, token, setup.AdminInput{Username: "admin", DisplayName: "A", Password: password})
	require.NoError(t, err)
	code, err := totp.GenerateCode(enr.Secret, e.clk.Now())
	require.NoError(t, err)
	setup.SetBeforeBootstrap(e.setup, func() {
		_, err := e.setup.ResetToken(e.ctx) // the host-root CLI, between the check and the creation
		require.NoError(t, err)
	})
	_, err = e.setup.CreateAdmin(e.ctx, token, code, ip1)
	require.ErrorIs(t, err, setup.ErrSessionInvalid)
	var users int
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT count(*) FROM users").Scan(&users))
	assert.Zero(t, users)
}
```

(`newEnv`, `session`, `password`, `ip1` and the `totp` import are `setup_integration_test.go`'s.) `masterkey_test.go`:

```go
// AUD-20: the new key file's directory is synced (and the parent of a directory that was created).
func TestCreateKeyFileSyncsItsDirectory(t *testing.T) {
	var synced []string
	old := syncDir
	syncDir = func(dir string) error { synced = append(synced, dir); return syncDirectory(dir) }
	defer func() { syncDir = old }()
	base := t.TempDir()
	dir := filepath.Join(base, "keys")
	require.NoError(t, createKeyFile(dir, filepath.Join(dir, "master.key")))
	assert.Equal(t, []string{dir, base}, synced)
}
```

(Use the real key file name constant of `masterkey.go`; the test file is `package secrets` — create it if it is not.)

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/secrets -run TestCreateKeyFileSyncs -count=1 && go test -tags integration ./internal/setup -run TestResetDuringAdminCreation -count=1` (Docker)
Expected: FAIL.

- [ ] **Step 3: Implement**

- `setup.go` `Service` gains `beforeBootstrap func() // tests only: runs between the session check and the creation (AUD-21)`; `export_test.go`: `package setup` with `func SetBeforeBootstrap(s *Service, f func()) { s.beforeBootstrap = f }`.
- `admin.go` `CreateAdmin`: before `s.auth.BootstrapAdmin(...)`, `if s.beforeBootstrap != nil { s.beforeBootstrap() }`; the callback becomes:

```go
	res, err := s.auth.BootstrapAdmin(ctx, in, m, func(tx pgx.Tx) error {
		// AUD-21: under the users lock, the caller's own session must still exist: a setup code reset
		// that committed since the check above deleted it, and wins.
		now := s.clock.Now().UTC()
		tag, err := tx.Exec(ctx, "DELETE FROM setup_sessions WHERE id_hash = $1 AND idle_expires_at > $2", idHash, now)
		if err != nil {
			return fmt.Errorf("delete setup session: %w", err)
		}
		if tag.RowsAffected() != 1 {
			return ErrSessionInvalid
		}
		if err := settings.Delete(ctx, tx, keyTokenHash); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "DELETE FROM setup_sessions"); err != nil {
			return fmt.Errorf("delete setup sessions: %w", err)
		}
		return nil
	})
```

- `masterkey.go`:

```go
// syncDir makes a new directory entry durable; tests replace it.
var syncDir = syncDirectory

func syncDirectory(dir string) error {
	d, err := os.Open(dir) //nolint:gosec // G304: the keys directory from configuration, or its parent
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}
```

`createKeyFile`: before `os.MkdirAll`, `_, statErr := os.Stat(dir); created := errors.Is(statErr, fs.ErrNotExist)`; after `f.Close()` succeeds: `if err := syncDir(dir); err != nil { return fmt.Errorf("sync keys directory %s: %w", dir, err) }` and, when `created`, `syncDir(filepath.Dir(dir))` likewise (AUD-20). Keep the existing `O_EXCL` creation and its comments.

Run: `go test ./internal/secrets -count=1 && go test -tags integration ./internal/setup -count=1` (Docker) → PASS.

- [ ] **Step 4: Full check and commit**

Run: `make lint && go test ./... -count=1`
Expected: PASS.

```bash
git add internal/setup internal/secrets
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "fix(setup): a setup code reset stops an admin creation in flight; sync the master key's directory

Refs: AUD-21, AUD-20

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 13: Resolved addresses are checked when Alice connects

Current code: `internal/inventory/validate.go:59-173` (`NormalizeHost`, `checkAddr`, `notAServer`, `localNAT64ToNonServer`) refuses link-local, multicast, unspecified and broadcast addresses only when they are typed as literals; `169.254.169.254.nip.io` and `metadata.google.internal` are stored (audit PoC 6); `internal/providers/linuxssh/dial.go:495-499` dials with a plain `net.Dialer` (`cmd/alice/services.go:108` sets no `NetDial`); `internal/providers/nginx/probe.go:52` likewise.

**Files:**
- Create: `internal/platform/netaddr/netaddr.go`, `internal/platform/netaddr/netaddr_test.go`
- Modify: `internal/inventory/validate.go` (`checkAddr` uses `netaddr.Allowed`; the moved helpers removed)
- Modify: `internal/providers/linuxssh/dial.go` (`handshake` default dialer, the two `dialErr` classifications), `internal/providers/nginx/probe.go`
- Modify: `internal/api/errors.go` (`ErrSSHAddressNotAllowed`, lists, reason mapping), `locales/common/{en,tr}.json`, `docs/troubleshooting.md`
- Test: `internal/providers/linuxssh/dial_test.go`, `internal/inventory/validate_test.go` (unchanged behaviour), `internal/api/errors_test.go`

- [ ] **Step 1: Write the failing tests**

`netaddr_test.go`: `Allowed` false for `169.254.169.254`, `::ffff:169.254.169.254`, `64:ff9b::a9fe:a9fe`, `2002:a9fe:a9fe::1`, `fd00:ec2::254`, `fe80::1`, `224.0.0.1`, `0.0.0.0`, `::`, `255.255.255.255`; true for `127.0.0.1`, `::1`, `10.0.0.5`, `192.0.2.10`, `2001:db8::1`; `Control("tcp4", "169.254.169.254:22", nil)` returns an error matching `ErrNotAllowed`, `Control("tcp4", "127.0.0.1:22", nil)` nil, an unparsable address an error. `dial_test.go`: `TestDialRefusesAResolvedLinkLocalAddress` (comment: "AUD-25 (a): a name that resolves to a refused address is refused when Alice connects, with its own reason, not retried") builds a `Dialer` the way the file's other tests do but leaves `NetDial` nil (the production path), dials target host `169.254.169.254`, and expects a `*providers.Error` with reason `ssh.address_not_allowed` and `Retryable` false. The connect is refused by `Control` before any packet is sent, so no network is needed; read `dial_test.go` for the constructor and the host-key store it uses before writing it.

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/platform/netaddr ./internal/providers/linuxssh -run 'Allowed|Control|ResolvedLinkLocal' -count=1`
Expected: FAIL.

- [ ] **Step 3: Implement**

`internal/platform/netaddr/netaddr.go`: package doc ("the address rule of SEC-065 shared by target validation and every connection Alice opens to a managed server"); move the `var` block of `internal/inventory/validate.go:114-120` (`nat64Prefix`, `nat64Local`, `sixToFour`, `awsIMDSv6`, `ipv4Broadcst`), `notAServer` and `localNAT64ToNonServer` here unchanged (with their comments), and turn the body of `checkAddr` into

```go
// Allowed reports whether a may be a managed server's address: not link-local (including the
// cloud metadata address 169.254.169.254 and its IPv6 forms: IPv4-mapped, NAT64 64:ff9b::/96 and
// 64:ff9b:1::/48, 6to4 2002::/16 and AWS's fd00:ec2::254), multicast, unspecified or the IPv4
// broadcast address. Loopback and private addresses are allowed.
func Allowed(a netip.Addr) bool {
	u := a.Unmap()
	if notAServer(u) || u == awsIMDSv6 || localNAT64ToNonServer(u) {
		return false
	}
	if u.Is6() {
		b := u.As16()
		var embedded netip.Addr
		switch {
		case nat64Prefix.Contains(u):
			embedded = netip.AddrFrom4([4]byte(b[12:16]))
		case sixToFour.Contains(u):
			embedded = netip.AddrFrom4([4]byte(b[2:6]))
		}
		if embedded.IsValid() && notAServer(embedded) {
			return false
		}
	}
	return true
}

// ErrNotAllowed is returned by Control for an address Allowed refuses.
var ErrNotAllowed = errors.New("netaddr: the address is not one of a managed server")

// Control is a net.Dialer.Control function: it refuses a connection to an address Allowed refuses,
// after name resolution and before anything is sent (AUD-25 a, DNS names and rebinding included).
func Control(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrNotAllowed, address)
	}
	if !Allowed(ap.Addr()) {
		return fmt.Errorf("%w: %s", ErrNotAllowed, ap.Addr())
	}
	return nil
}
```

`inventory/validate.go` `checkAddr`: `if !netaddr.Allowed(a) { return "", hostProblem(CodeHostNotAllowed, nil) }; return a.Unmap().String(), nil` (its comment points to `netaddr.Allowed`); its existing tests must pass unchanged. `linuxssh/dial.go` `handshake`: `dial = (&net.Dialer{Timeout: d.dialTimeout(), Control: netaddr.Control}).DialContext`; at both `dialErr` classifications (`:361`, `:450`) first:

```go
	if errors.Is(r.dialErr, netaddr.ErrNotAllowed) {
		return nil, providers.NewError("ssh.address_not_allowed", false, r.dialErr, nil)
	}
```

(the second site returns one value — adapt). `nginx/probe.go:52`: `(&net.Dialer{Timeout: dial, Control: netaddr.Control}).DialContext`. `api/errors.go`: `ErrSSHAddressNotAllowed = ErrorCode{Code: "ALC-SSH-0012", Reason: "ssh.address_not_allowed", Status: http.StatusBadGateway}` with every list and mapping `ErrSSHProtocol` is in (grep). Texts:

| Key | EN | TR |
|---|---|---|
| `errors.ssh.address_not_allowed.title` | Address not allowed | Adrese izin verilmiyor |
| `errors.ssh.address_not_allowed.cause` | The server's name resolves to an address Alice never connects to (link-local such as 169.254.169.254, multicast or unspecified). | Sunucunun adı, Alice'in hiçbir zaman bağlanmadığı bir adrese çözümleniyor (169.254.169.254 gibi bağlantı-yerel, çoklu yayın veya belirtilmemiş adres). |
| `errors.ssh.address_not_allowed.action` | Check the server's name in DNS, or enter its real address. | Sunucunun adını DNS'te denetleyin veya gerçek adresini girin. |

`docs/troubleshooting.md`: `## ALC-SSH-0012: Address not allowed`.

Run: `go test ./internal/platform/netaddr ./internal/inventory ./internal/providers/... ./internal/api -count=1 && make i18n-check && go test ./internal/archtest -count=1`
Expected: PASS.

- [ ] **Step 4: Full check and commit**

Run: `make lint && go test ./... -count=1 && go test -tags integration ./internal/inventory/... ./internal/api/... -count=1`
Expected: PASS (Docker).

```bash
git add internal/platform/netaddr internal/inventory/validate.go internal/providers/linuxssh/dial.go internal/providers/linuxssh/dial_test.go \
  internal/providers/nginx/probe.go internal/api/errors.go locales/common docs/troubleshooting.md
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "fix(linuxssh): refuse a resolved link-local or metadata address when Alice connects

Refs: AUD-25

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 14: Web robustness — route error page, locale fallback, all held jobs, step-up closes with the session, audit object and details

Current code (AUD-25 d): `web/src/router.tsx` has no `errorElement` (a render error leaves a blank page); `web/src/main.tsx:20` renders only after `createI18n` resolves, so a failed locale chunk renders nothing; `web/src/components/BlockedJobsPanel.tsx:24` reads the first page of `listJobs({ status: 'blocked_license' })` (50) and never follows `next_cursor`; `web/src/components/StepUpProvider.tsx` keeps its dialog open when the session ends; `web/src/pages/AuditPage.tsx:111-119` shows time, user, action, result and IP only.

**Files:**
- Create: `web/src/pages/RouteErrorPage.tsx`, `web/src/pages/RouteErrorPage.test.tsx`
- Modify: `web/src/router.tsx` (root `errorElement`), `web/src/main.tsx` (a `createI18n` failure falls back), `web/src/i18n.ts` (an exported fallback creator if needed)
- Modify: `web/src/components/BlockedJobsPanel.tsx` ("Show more" with the cursor), `web/src/components/StepUpProvider.tsx` (`onUnauthorized` closes and rejects), `web/src/pages/AuditPage.tsx` (object and details)
- Modify: `web/src/locales/{en,tr}.json`, `web/src/screens.i18n.test.tsx` if it enumerates screens
- Test: the components' existing test files

- [ ] **Step 1: Write the failing tests**

- `RouteErrorPage.test.tsx`: a route whose element throws renders the heading "Something went wrong" and a "Reload" button, in EN and TR, and no stack trace or error message text.
- `main` locale fallback: test the extracted `startApp(createI18nFn)` (move the render into an exported function in a new `web/src/start.tsx` so it can be tested): when `createI18nFn` rejects, the English bundle is used and the app renders the login route.
- `BlockedJobsPanel.test.tsx`: with two pages (`next_cursor` on the first), "Show more" appears, loads the second page and appends its rows; it disappears when `next_cursor` is null.
- `StepUpProvider.test.tsx`: a pending step-up dialog closes when a request answers `401 auth.unauthenticated`, and the waiting `run` rejects with the original error.
- `AuditPage.test.tsx`: a row shows its object (`object_type` and `object_id`, monospace) and a "Details" disclosure listing each `details` key and value as text.

- [ ] **Step 2: Run them to see them fail**

Run: `cd web && npx vitest run src/pages src/components`
Expected: FAIL.

- [ ] **Step 3: Implement**

- `RouteErrorPage`: uses `useRouteError` only to log nothing (never shows its text), Mantine `Title` + `Text` + `Button onClick={() => window.location.reload()}`; keys `routeError.title` ("Something went wrong" / "Bir sorun oluştu"), `routeError.text` ("This page could not be shown. Reload it; if it happens again, note the time and tell your administrator." / "Bu sayfa gösterilemedi. Sayfayı yeniden yükleyin; yine olursa saati not edip yöneticinize bildirin."), `routeError.reload` ("Reload" / "Yeniden yükle"). `router.tsx`: the top-level route object gets `errorElement: <RouteErrorPage />`.
- `start.tsx`/`main.tsx`: `createI18n(navigator.languages).catch(() => createI18n(['en']))` — and if that rejects too, render a static English "Alice could not load its texts. Reload the page." with a reload button (no i18n). Keep the CSP nonce sharing and the activity listeners of Task 5 in `main.tsx`.
- `BlockedJobsPanel`: switch the query to `useInfiniteQuery` keyed by `BLOCKED_JOBS_KEY` with `getNextPageParam: (p) => p.next_cursor ?? undefined` and `queryFn: ({ pageParam }) => listJobs({ status: 'blocked_license', cursor: pageParam })`; rows from all pages; a "Show more" button (`jobs.blocked.showMore`: "Show more" / "Daha fazla göster") while `hasNextPage`. Keep the existing invalidations working (they invalidate `BLOCKED_JOBS_KEY`).
- `StepUpProvider`: `useEffect(() => onUnauthorized(() => { setOpened(false); pending.current?.reject(pending.current.original); pending.current = null; }), [])`.
- `AuditPage`: columns `audit.columns.object` ("Object" / "Nesne") rendering `<Code>{type}</Code> <Code>{id}</Code>` when present, and `audit.columns.details` ("Details" / "Ayrıntılar") with a Mantine `Spoiler` or `Collapse` per row listing `key: value` pairs as text (no JSON string building in JSX; `Object.entries(details).sort()`). The table keeps scrolling inside its container at 375 px.

Run: `cd web && npx vitest run && cd .. && make web-lint && make i18n-check` → PASS.

- [ ] **Step 4: Accessibility spot check**

Run (Docker; no other Docker work at the same time): `make e2e-up`, then `cd web && set -a && . ../deploy/.env && set +a && ALICE_E2E_PROJECT=alice-e2e npx playwright test e2e/phase1.spec.ts e2e/phase2.spec.ts`, then `make e2e-down`.
Expected: PASS (these journeys run axe on the audit and license pages; fix any serious or critical violation the new columns or button introduce).

- [ ] **Step 5: Commit**

```bash
git add web/src
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "fix(web): error page for routes, locale fallback, all held jobs, step-up closes with the session, audit object and details

Refs: AUD-25

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 15: Supply chain — SHAs and digests everywhere, the pin check, Dependabot, the update procedure

Current code: `.github/workflows/ci.yml` uses `actions/checkout@v7`, `actions/setup-go@v7`, `actions/setup-node@v7`, `actions/upload-artifact@v7`; `deploy/Dockerfile:3,11,40` (`node:24-alpine`, `golang:1.27.1-alpine`, `gcr.io/distroless/static-debian12` without tag); `deploy/docker-compose.yml:5` (`postgres:16-alpine`; SEC-089 requires a digest); `test/images/e2e-target/Dockerfile:10,21`, `test/images/sshd/{ubuntu22,debian12,rocky9}.Dockerfile`; `internal/testutil/pgtest/pgtest.go:45` (`postgres:16-alpine`); `Makefile:190,194,198` (`ghcr.io/gitleaks/gitleaks:v$(GITLEAKS_VERSION)`, `aquasec/trivy:$(TRIVY_VERSION)`, the latter with the Docker socket).

**Files:**
- Create: `tools/pincheck/main.go`, `tools/pincheck/main_test.go`
- Create: `.github/dependabot.yml`, `docs/dev/dependency-updates.md`
- Modify: `.github/workflows/ci.yml`, `deploy/Dockerfile`, `deploy/docker-compose.yml`, `test/images/e2e-target/Dockerfile`, `test/images/sshd/*.Dockerfile`, `internal/testutil/pgtest/pgtest.go`, `Makefile` (`GITLEAKS_IMAGE`, `TRIVY_IMAGE`, `pin-check` in `lint`)

- [ ] **Step 1: Write the failing check**

`tools/pincheck/main.go` (package `main`): `func check(root string) []string` returns one message per unpinned reference:
- every `uses:` in `.github/workflows/*.yml` is `owner/repo[/path]@<40 lower-case hex>` followed by `# v<digits>[.<digits>]*` on the same line;
- every `FROM` in `deploy/Dockerfile` and `test/images/**/Dockerfile`/`*.Dockerfile`, except a reference to an earlier stage name of the same file and `scratch`, contains `@sha256:<64 hex>`;
- every `image:` in `deploy/docker-compose*.yml` of a service without `build:` contains `@sha256:<64 hex>`;
- the `Makefile` defines `GITLEAKS_IMAGE` and `TRIVY_IMAGE` with `@sha256:<64 hex>`, and every `docker run` line of it uses one of `$(GITLEAKS_IMAGE)`, `$(TRIVY_IMAGE)` or a locally built `alice:` image;
- `internal/testutil/pgtest/pgtest.go` names the same PostgreSQL reference (tag and digest) as `deploy/docker-compose.yml`.

`main` prints the messages and exits 1 when there are any. `main_test.go`:

```go
func TestRepositoryIsPinned(t *testing.T) {
	assert.Empty(t, check("../.."))
}

func TestCheckFindsUnpinnedReferences(t *testing.T) {
	// Build a temporary tree with one unpinned uses:, FROM, image:, docker run and pgtest reference
	// each, and one pinned of each; expect exactly the five unpinned ones.
}
```

Run: `go test ./tools/pincheck -count=1`
Expected: FAIL (`TestRepositoryIsPinned` lists every current reference).

- [ ] **Step 2: Pin (network: registry and GitHub queries only)**

For each action: `git ls-remote https://github.com/actions/checkout 'refs/tags/v7*'` → take the newest `v7.x.y` tag's peeled commit (the `^{}` line when the tag is annotated) → `uses: actions/checkout@<sha> # v7.x.y`. For each image: `docker buildx imagetools inspect <ref> | awk '/^Digest:/ {print $2; exit}'` (the index digest, so arm64 keeps working) → `<repo>:<tag>@sha256:<digest>`. The distroless base keeps its current variant (the image sets `USER 10001` itself) and is written `gcr.io/distroless/static-debian12:latest@sha256:<digest>`. In the `Makefile` replace `GITLEAKS_VERSION`/`TRIVY_VERSION` by `GITLEAKS_IMAGE ?= ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:<digest>` and `TRIVY_IMAGE ?= aquasec/trivy:0.74.0@sha256:<digest>` and use them in `secrets-scan`, `fs-scan`, `image-scan`; add `go run ./tools/pincheck` as the first line of `lint`.

Run: `go test ./tools/pincheck -count=1`
Expected: PASS.

- [ ] **Step 3: Dependabot and the procedure**

`.github/dependabot.yml` (version 2): weekly updates for `github-actions` (`/`), `docker` (`/deploy`, `/test/images/e2e-target`, `/test/images/sshd`), `docker-compose` (`/deploy`), `gomod` (`/`), `npm` (`/web`), each with `open-pull-requests-limit: 5`. `docs/dev/dependency-updates.md`: why everything is pinned (AUD-09, SEC-089, SEC-103), the commands of Step 2 for each kind, that the PostgreSQL digest appears twice (compose and `pgtest`), that `make lint` runs `tools/pincheck`, how to review a Dependabot PR (read the release notes; for images compare `docker buildx imagetools inspect` of tag and digest; run `make ci`), and what is not pinned and why (Go tools are `go install …@vX`, verified by the Go checksum database; the testcontainers Ryuk image; Playwright's browser download — Decision 17).

- [ ] **Step 4: Builds still work**

Run (Docker): `make image` and `make test-ssh` (`ALICE_SSH_IMAGES=ubuntu22` is enough here; Task 17 runs the whole matrix) and `go test -tags integration ./internal/audit -count=1` (pulls the pinned PostgreSQL).
Expected: PASS.

- [ ] **Step 5: Full check and commit**

Run: `make lint && go test ./... -count=1`
Expected: PASS.

```bash
git add tools/pincheck .github docs/dev/dependency-updates.md deploy/Dockerfile deploy/docker-compose.yml test/images internal/testutil/pgtest/pgtest.go Makefile
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "build: pin actions by commit and images by digest, check the pins, keep them updatable

Refs: AUD-09

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 16: CI and build gates — every branch, the image check, build-tag checks, `--ignore-scripts`, `go mod verify`, TS coverage, gitleaks narrowing, Compose override

Current code: `.github/workflows/ci.yml:3-6` runs on `push` to `main` only (AUD-08); `Makefile:82-88` `release-symcheck` greps only `main.*` symbols of a separately built binary, so a build with `testlicense` alone passes (AUD-23); nothing runs the built image; `Makefile:50` and `deploy/Dockerfile:7` use `npm ci` without `--ignore-scripts` (SEC-103); no `go mod verify`; no TS coverage threshold (`web/vite.config.ts:17-22`); `.gitleaks.toml:7` exempts the whole `web/package-lock.json` path while `.gitleaksignore` says never to exempt a path; `Makefile:100` `COMPOSE` ignores `deploy/docker-compose.override.yml` that `docs/operator-guide.md:413` tells operators to create, and `deploy/docker-compose.yml:44-62` passes neither `ALICE_TRUSTED_PROXIES` nor `ALICE_LOG_LEVEL` (AUD-24).

**Files:**
- Modify: `.github/workflows/ci.yml`, `Makefile` (`release-symcheck`, `image-check`, `ci`, `web-install`, `vuln`, `COMPOSE`), `deploy/Dockerfile` (`npm ci --ignore-scripts`), `deploy/docker-compose.yml` (two variables), `.gitignore`, `.gitleaks.toml`
- Modify: `web/package.json`, `web/package-lock.json` (`@vitest/coverage-v8` 5.0.3), `web/vite.config.ts` (coverage thresholds)
- Modify: `cmd/alice/compose_test.go` (environment and `COMPOSE` assertions)
- Modify: `docs/operator-guide.md` (override with `make up`; the two variables), `docs/dev/getting-started.md` if it documents `make web-install`

- [ ] **Step 1: Write the failing Compose test**

Add to `compose_test.go` (`composeService` gains `Environment map[string]string \`yaml:"environment"\``):

```go
// AUD-24: the variables the configuration reads reach the container, and make up uses the
// documented override file while the e2e project never does.
func TestComposePassesConfigurationAndUsesTheOverride(t *testing.T) {
	base := readCompose(t, "../../deploy/docker-compose.yml")
	env := base.Services["alice"].Environment
	assert.Equal(t, "${ALICE_TRUSTED_PROXIES:-}", env["ALICE_TRUSTED_PROXIES"])
	assert.Equal(t, "${ALICE_LOG_LEVEL:-}", env["ALICE_LOG_LEVEL"])
	mk, err := os.ReadFile("../../Makefile")
	require.NoError(t, err)
	var compose, composeE2E string
	for _, line := range strings.Split(string(mk), "\n") {
		switch {
		case strings.HasPrefix(line, "COMPOSE :="):
			compose = line
		case strings.HasPrefix(line, "COMPOSE_E2E :="):
			composeE2E = line
		}
	}
	assert.Contains(t, compose, "docker-compose.override.yml")
	assert.NotContains(t, composeE2E, "override")
}
```

Also extend the config test that lists every environment variable `internal/platform/config` reads (grep `getenv("ALICE_` there) to assert each appears in the compose file's alice environment, except the ones set elsewhere on purpose (list them in the test with a reason). Run: `go test ./cmd/alice -run Compose -count=1` → FAIL.

- [ ] **Step 2: Implement the Compose and workflow changes**

- `deploy/docker-compose.yml` alice `environment`, after `ALICE_STATE_DIR`: `ALICE_TRUSTED_PROXIES: ${ALICE_TRUSTED_PROXIES:-}` and `ALICE_LOG_LEVEL: ${ALICE_LOG_LEVEL:-}`, with a comment ("set in deploy/.env; see docs/operator-guide.md").
- `Makefile`: `COMPOSE := docker compose -f deploy/docker-compose.yml $(if $(wildcard deploy/docker-compose.override.yml),-f deploy/docker-compose.override.yml) --env-file deploy/.env` with a comment (AUD-24; `COMPOSE_E2E` never reads it). Do **not** run `make up` to try it.
- `.gitignore`: `/deploy/docker-compose.override.yml` and `/deploy/secrets/`.
- `.github/workflows/ci.yml`: `on: { push: {}, pull_request: {} }` written as

```yaml
on:
  # Every branch (AUD-08): the project works on master and phase-* branches.
  push:
  pull_request:
```

and in the `go` job, after `make tools`: `- run: go mod verify`.
- `docs/operator-guide.md`: `make up` reads the override when it exists; running Compose by hand from `deploy/` reads it on its own; `ALICE_TRUSTED_PROXIES` and `ALICE_LOG_LEVEL` in `deploy/.env` now reach Alice.

Run: `go test ./cmd/alice -count=1` → PASS.

- [ ] **Step 3: Build gates**

- `Makefile` `web-install`: `cd web && npm ci --ignore-scripts`; `deploy/Dockerfile`: `RUN cd web && npm ci --ignore-scripts`. Check nothing needs an install script: `grep -n hasInstallScript web/package-lock.json` lists only `fsevents` (macOS only) and `msw` (its postinstall copies a worker only when `msw.workerDirectory` is set in `package.json`, which it is not); then `make web-install && make web && make web-test` → PASS.
- `vuln`: first line `go mod verify`.
- `release-symcheck`: after the two builds, add

```make
	@! go version -m bin/.symcheck-release | grep -Eq '^\s+build\s+-tags=' || { echo "release-symcheck: the release build has build tags"; exit 1; }
	@go version -m bin/.symcheck-e2e | grep -Eq '^\s+build\s+-tags=.*testlicense' || { echo "release-symcheck: cannot see build tags in the build info"; exit 1; }
	@! grep -aq 'alice test license signing key v1' bin/.symcheck-release || { echo "release-symcheck: the release build trusts the test license key"; exit 1; }
```

(the label is `testKeyLabel` of `internal/license/keys_testlicense.go`; put it in a Make variable with a comment naming that constant).
- New target after `image`:

```make
.PHONY: image-check
image-check: image ## Check the built image: a release build without e2e or test-license code that reports a plain version (AUD-23)
	@set -e; id=$$(docker create alice:$(IMAGE_TAG)); docker cp "$$id":/usr/local/bin/alice bin/.image-alice; docker rm "$$id" >/dev/null; \
	  ! go version -m bin/.image-alice | grep -Eq '^\s+build\s+-tags=' || { echo "image-check: the image binary has build tags"; exit 1; }; \
	  ! grep -aq '$(TEST_LICENSE_LABEL)' bin/.image-alice || { echo "image-check: the image trusts the test license key"; exit 1; }; \
	  v=$$(docker run --rm --network none alice:$(IMAGE_TAG) version); echo "$$v"; \
	  ! echo "$$v" | grep -Eq '\+(e2e|testlicense)' || { echo "image-check: the image reports a test build"; exit 1; }; \
	  rm -f bin/.image-alice; echo "image-check: ok"
```

(If `alice version` needs a writable directory or configuration in the container, read `cmd/alice/main.go`'s `version` branch and pass only what it needs.) `ci`: the last line becomes `$(MAKE) image-check image-scan`.

Run (Docker): `make release-symcheck && make image-check`
Expected: `release-symcheck: ok`, `image-check: ok`.

- [ ] **Step 4: TS coverage (network: npm registry)**

`cd web && npm install --save-dev --save-exact @vitest/coverage-v8@5.0.3` (the version of the installed `vitest`; check `npm ls vitest`). `vite.config.ts` `test.coverage`: `{ provider: 'v8', include: ['src/**/*.{ts,tsx}'], exclude: ['src/**/*.test.{ts,tsx}', 'src/test/**'], thresholds: { lines: N, statements: N, functions: N, branches: N } }`. Measure with `npx vitest run --coverage`; set each threshold to 70 (§22.7) when the measured value is at least 70, otherwise to the measured value rounded down and record the gap in Task 17's review document. `package.json` script `"test": "vitest run --coverage"` so `make web-test` enforces it.

Run: `make web-test`
Expected: PASS with the coverage summary.

- [ ] **Step 5: Gitleaks narrowing (Docker)**

Replace `.gitleaks.toml`'s `[allowlist]` by two `[[allowlists]]` entries: the existing `regexes` (unchanged, its description kept), and

```toml
[[allowlists]]
description = "npm lockfile integrity hashes (sha512 of published packages) and nothing else in that file (AUD-23)"
condition = "AND"
paths = ['''^web/package-lock\.json$''']
regexTarget = "line"
regexes = ['''^\s*"integrity": "sha512-[A-Za-z0-9+/]+={0,2}",?\s*$''']
```

Run: `make secrets-scan`
Expected: `no leaks found`. If the scan reports other lines of `web/package-lock.json`, read each: a real secret stops the task (report it); a false positive gets a fingerprint line in `.gitleaksignore` with a comment (never a path).

- [ ] **Step 6: Full check and commit**

Run: `make lint && go test ./... -count=1 && make web-lint && make web-test && make vuln`
Expected: PASS.

```bash
git add .github/workflows/ci.yml Makefile deploy/Dockerfile deploy/docker-compose.yml .gitignore .gitleaks.toml .gitleaksignore \
  web/package.json web/package-lock.json web/vite.config.ts cmd/alice/compose_test.go docs/operator-guide.md docs/dev
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "build: CI on every branch, image and build-tag checks, install scripts off, TS coverage, narrower lockfile exemption, Compose override

Refs: AUD-08, AUD-23, AUD-24

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 17: Coverage floors, documentation, R39, the remediation review, `make ci`

**Files:**
- Modify: `coverage-floors.json`
- Modify: `docs/superpowers/specs/alice-v1/00-decisions.md` (R39), `docs/superpowers/specs/alice-v1/04-security.md` (a "(R39 item N)" note after SEC-019, SEC-062, SEC-065, SEC-070, SEC-075), `docs/superpowers/specs/alice-v1/06-quality.md` (§26.6: "(the real-systemd job moves to Phase 8, R38 item 16)"; A-02 row: "(activity as defined by R39 item 1)")
- Modify: `CHANGELOG.md` (a new top section `## Unreleased — Audit remediation`), `docs/troubleshooting.md` (sections not yet added), `docs/admin-guide.md`, `docs/operator-guide.md` (anything earlier tasks left)
- Create: `docs/security/reviews/audit-remediation.md`

- [ ] **Step 1: Coverage**

Run: `make coverage` (Docker)
Then add floors at the measured values rounded down for `alice/internal/setup`, `alice/internal/platform/tlscert`, `alice/cmd/alice` and `alice/internal/platform/netaddr`, and raise (never lower) any existing floor that rose. If a package fell below its floor, add tests for the new branches (the Phase 4 rule). Run `make coverage` again → every package ok.

- [ ] **Step 2: R39**

Append to `00-decisions.md` one line `- R39 (audit remediation, approved with the audit remediation plan; corrected to the built code) Accepted decisions of the remediation of the independent audit of 2026-10-04: (1) … (9) …` restating, as built, each row of this plan's "R39" table with the Decision it comes from (activity rule and header; time-aware gate, `MaxEvaluationAge`, `license.unverified`, evaluation in every process, lock waits; `ValidAccount`, `CleanHome`, `unlisted`, inline content, protocol 6 / helper 1.5.0; denial coalescing window and `suppressed_count`; token revocation on reset and sign-out-everywhere; no trusted unsealed installation; the CSV comment line; the connect-time address check and `ALC-SSH-0012`; pins, `--ignore-scripts`, `go mod verify`, Dependabot, the TS threshold as set, `osv-scanner` deferred to Phase 8) — corrected to what was actually built.

- [ ] **Step 3: The remediation review**

Create `docs/security/reviews/audit-remediation.md` with the structure of `phase-4.md`:
- **Scope:** the independent audit of 2026-10-04 (`independent-audit-2026-10-04.md`, kept as written, untracked) and its 25 findings; the decisions are R39.
- **Finding map** — one row per AUD id, columns: AUD | Severity (from the audit) | Outcome (fixed here / fixed in Phase 4 / recorded, not fixed / owner) | Commits (from `git log --format='%h %s' --grep='AUD-NN' master..HEAD`; for Phase 4 fixes the commits and P4 ids of `phase-4.md`) | Tests (the test names of this plan's tasks) | Decision or reason. AUD-25 gets one row per sub-item (a)–(d); AUD-08 names its owner-pending part; AUD-23 lists each gate and the deferred `osv-scanner`; AUD-25 (b) is "recorded, not fixed" with Decision 15's reason.
- **Evidence** table (command, expected, result): `go test ./cmd/alice-helper` as a user and as root (Docker), `make test-ssh`, the fidelity tests, `go test -tags integration ./internal/auth/... ./internal/license/... ./internal/api/... ./internal/setup/...`, `go test ./tools/pincheck`, `make release-symcheck`, `make image-check`, `make secrets-scan`, `make coverage`, `make e2e` (the AUD-01 journey), `make ci`.
- **Findings** of the remediation itself (new residual risks, with severity): at least R-1 Low — the activity marker is client-asserted (Decision 1); R-2 Low — the count of coalesced refusals is in memory and lost on restart (Decision 8); R-3 Info — a CSV reader sees one extra row (Decision 16); R-4 Low — the failed-credential bucket is shared behind NAT (Decision 11); R-5 Low — Ryuk image and the Playwright browser download are not pinned (Decision 17).
- **Known limitations:** AUD-25 (b) (Decision 15); verification stays a full recomputation (Decision 8); a database outage longer than 3 hours pauses changes (Decision 3); every managed server needs helper 1.5.0 (Decision 7); a 33-byte or non-ASCII account name is reported, not listed (Decision 4).
- **Owner-pending:** the list of this plan's "Process gaps and owner-pending items", with an empty results table (Item | Result | Date and person).

- [ ] **Step 4: CHANGELOG and documents**

`CHANGELOG.md` `## Unreleased — Audit remediation` with `### Security` (idle timeout, license gate, unlisted accounts visible, API tokens revoked, connect-time address check, refusals rate-limited before lookups, text refused at the edge, sign-in timing, setup reset race), `### Changed` (helper protocol 6 / `alice-helper` 1.5.0 required: update every managed server; repeated refusals coalesced in the audit log; CSV export first line; `/healthz` limited on the public port), `### Added` (`ALC-LIC-0009`, `ALC-SSH-0012`, the two account warnings, image check, pin check, Dependabot). Read `docs/troubleshooting.md`, `docs/admin-guide.md`, `docs/operator-guide.md` and `docs/licensing.md` once more for statements this plan made false (helper version, 60-second export limit, "every account", upgrade sealing, idle timeout wording) and correct them.

- [ ] **Step 5: Full CI**

Run: `make ci` (Docker: `alice:ci` and the `alice-e2e` project only; it ends with `make e2e-down`, then `image-check` and `image-scan`)
Expected: every stage passes (`lint` including `pincheck`, `test`, `coverage`, `test-ssh`, `build`, `release-symcheck`, `i18n-check`, `web-lint`, `web-test` with coverage, `vuln` with `go mod verify`, `secrets-scan`, `fs-scan`, the e2e stack with the hardening check and Playwright, `image-check`, `image-scan`). If `secrets-scan` flags a test fixture, add the finding to `.gitleaksignore` with its commit hash in this task. Record the result (and machine load, given the audit's §5 note) in the review's Evidence table.

- [ ] **Step 6: Commit**

```bash
git add coverage-floors.json docs/superpowers/specs/alice-v1/00-decisions.md docs/superpowers/specs/alice-v1/04-security.md \
  docs/superpowers/specs/alice-v1/06-quality.md docs/security/reviews/audit-remediation.md CHANGELOG.md docs/troubleshooting.md \
  docs/admin-guide.md docs/operator-guide.md docs/licensing.md .gitleaksignore
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit -m "docs: audit remediation review, R39, coverage floors and guides

Refs: AUD-01, AUD-02, AUD-03, AUD-06, AUD-08, AUD-09, AUD-11, AUD-12, AUD-13, AUD-15, AUD-16, AUD-18, AUD-19, AUD-20, AUD-21, AUD-22, AUD-23, AUD-24, AUD-25

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

(Never `git add docs/security/reviews/` as a directory: the audit file and its PoC directory live there untracked.)
