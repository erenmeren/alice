## 22. Test Strategy

### 22.1 Principles

- Test-driven: unit tests are written before the code for every module. A bug fix starts with a failing regression test.
- Everything that touches time uses an injected `Clock`. Nothing under `internal/` calls `time.Now()` directly. A lint rule (`forbidigo`) enforces this outside `internal/clock`.
- Everything external (Azure, SMTP, SSH hosts, Nginx) is either a container we control or an in-process fake. The default test suite needs no internet and no Azure account.
- Tests must be deterministic. Randomness (keys, IDs) is seeded or injected where the assertion depends on it. Flaky tests are quarantined within 24 hours and fixed within one sprint. A quarantine list of more than 3 tests blocks release.

### 22.2 Test pyramid

| Layer | Approx. share | Scope | Runs | Tooling |
|---|---|---|---|---|
| Unit (Go) | 65% | Pure logic: license math, parsers, RBAC policy, crypto envelope, rotation planner, i18n key checks | Every commit, < 60 s | `testing` + testify |
| Unit (TS) | 10% | React components, hooks, form validation, i18n rendering | Every commit, < 60 s | Vitest + Testing Library |
| Integration (Go) | 18% | Real PostgreSQL, real OpenSSH server, real Nginx, fake Key Vault, fake SMTP; jobs, providers, API handlers through `httptest` | Every PR, < 8 min | testcontainers-go |
| End-to-end | 5% | Browser drives the built single binary + PostgreSQL, EN and TR | Every PR (smoke subset, < 6 min); nightly (full) | Playwright |
| Security / DAST | 2% | Authz matrix, secret-leak, rate limit, fuzz, ZAP baseline | Authz/leak/rate on every PR; fuzz nightly; ZAP nightly and at release | Go test, `go test -fuzz`, OWASP ZAP |

A test belongs to the lowest layer that can prove the behavior. If a bug was found in E2E or integration, a unit test is added when the cause was logic.

### 22.3 Tool choices

**Go: standard `testing` plus `testify` (`require` and `assert` only).**
Reason: the standard library gives us subtests, `t.Parallel`, fuzzing, `httptest` and `t.TempDir` without any dependency. `testify` is added only for `require`/`assert` because the volume of table-driven assertions (license matrix, authz matrix) makes hand-written `if got != want` blocks noisy and error-prone for a solo vendor reading failures. Excluded: testify `suite` and `mock` packages (magic and reflection); we write small hand fakes against our own interfaces instead. `testify` is pinned and covered by `govulncheck` and Trivy like any other dependency. It is a test-only dependency and is not linked into the release binary (verified by a CI check on `go version -m alice`).

**testcontainers-go** for PostgreSQL 16, OpenSSH server and Nginx.
- PostgreSQL: one container per test package, one fresh database per test created from a template database with migrations applied (fast: about 30 ms per database). Tests never share data.
- OpenSSH: image `alice-test/sshd-{ubuntu22,debian12,rocky9}` built from `test/images/`. Contains a service user with the `alice-helper` static binary installed root-owned and the exact sudoers profiles the product documents (`nginx` and `linux`, selectable per test), plus a normal user with `authorized_keys`. Ports are random. Host key is generated at image build so tests can also rotate it by restarting with a new key volume.
- Nginx: same three images run Nginx with systemd replaced by a small `systemctl` shim that supports `reload` and `is-active` and can be told to fail. This keeps containers unprivileged. One additional job per release runs the Ubuntu image with real systemd (privileged runner) to confirm the shim is faithful.
- Containers are reaped by Ryuk. In CI, images are cached by digest.

**Vitest + React Testing Library + `@testing-library/user-event`** for frontend units. `msw` mocks the API in component tests. Components use the Mantine UI kit (its built-in accessibility semantics are asserted through Testing Library role queries). An `i18n` test renders every screen under both `en` and `tr` and fails on a missing key or a raw key string in the DOM.

**Playwright** (Chromium always, Firefox and WebKit nightly). Every user journey test is parameterized over `en` and `tr`. TOTP codes are computed in the test using the same secret shown in the wizard. Accessibility checks use `@axe-core/playwright` on every main screen; serious or critical violations fail the test.

**Other:** `golangci-lint`, `gosec`, `govulncheck`, Trivy, gitleaks (from the security process), `openapi` contract test (the generated client and the server are checked against the same `openapi.yaml`; drift fails CI).

### 22.4 Injectable Clock

```go
package clock

type Clock interface {
    Now() time.Time
    After(d time.Duration) <-chan time.Time
    NewTicker(d time.Duration) Ticker
}
```

- `clock.Real` is used in `main`. `clock.Fake` is used in tests: `Set(t)`, `Advance(d)`, and it fires timers and tickers deterministically when advanced.
- The license module receives the Clock plus the injected high-water-mark store (interface, in-memory fake in unit tests, real DB-plus-MAC implementation in integration tests) and a monotonic-uptime source (fake in tests). A `CertNotBeforeSource` (maximum `notBefore` across discovered certificates) feeds only the admin warning "system clock appears to be behind"; it is never an input to license math (R28).
- The scheduler, session expiry, rate limiter, rotation overlap timer and backup retention also use the Clock, so E2E tests that need "12 hours later" call a test-only admin endpoint `POST /test/clock` that exists only in the test-only "demo clock" build (`-tags e2e`). The demo clock build is never shipped; release binaries are built without the tag, and a CI test asserts the route is absent (404) in the release build.
- License matrix tests (section 23) are pure unit tests over `license.Evaluate(state, now)` plus a small number of integration tests that verify the effects (jobs stopped, banner state in API, emails sent).

### 22.5 Fake Azure Key Vault

An in-process `httptest.Server` in `internal/testutil/fakekv` emulates only the REST endpoints Alice uses, on `api-version=7.5`:

| Endpoint | Behavior |
|---|---|
| `GET /certificates` and `GET /certificates/{name}/versions` | Paged listing with `nextLink`, versions with `attributes.exp`, `nbf`, `enabled` |
| `GET /certificates/{name}/{version}` | Certificate metadata, `x5t`, `sid` (backing secret id), policy |
| `POST /certificates/{name}/import` | Accepts PFX or PEM, creates a new version |
| `GET /secrets/{name}/{version}` | Returns PFX/PEM only if the certificate's policy says exportable; otherwise 403 with the real error body shape |
| `GET /keys` | Key inventory (type, size, expiry, enabled) |
| `GET /secrets` | Metadata list only |

Also emulated: the Entra ID token endpoint (`/oauth2/v2.0/token`) for client secret and client certificate assertions (the fake validates the JWT client assertion structure and signature), and the Azure managed-identity endpoint (IMDS) at a configurable URL.

Fault injection is controlled per test: `kv.FailNext(path, status, body, retryAfter)`, `kv.SetLatency`, `kv.Renew("web-cert")` (creates a new version signed by the fixture CA, as KV auto-renewal would), `kv.SetExportable(name, false)`, `kv.RevokeRole("secrets/get")` (returns 403 `Forbidden` with `ForbiddenByRbac` or `ForbiddenByPolicy` depending on the vault model being tested). Response bodies and headers are copied from recorded real responses stored in `test/testdata/kv-recordings/`. The recordings are refreshed by the optional real-Azure suite.

**Optional real Azure suite** (`-tags azure`): runs nightly only if the repository secrets `AZURE_TEST_*` are set. It uses a dedicated test vault with one self-signed cert (1-day renewal policy) and checks that the fake and the real service still agree (contract test using the same assertions against both). It never runs on forks or PRs. Failure of this suite alerts the vendor but does not block release.

### 22.6 Fixtures

Generated at test time by `internal/testutil/pki` (never committed, so no expired-fixture rot and nothing for gitleaks to flag):

| Fixture | Description |
|---|---|
| `NewCA(name, keyType)` | Root CA and one intermediate. Key types: RSA 2048, RSA 4096, ECDSA P-256, ECDSA P-384 |
| `Issue(ca, opts)` | Leaf with SANs, `notBefore`/`notAfter` relative to the fake clock; options for wrong SAN, weak key (RSA 1024), SHA-1 signature, missing chain |
| `Expired`, `ExpiringIn(n days)` | Ready-made certificates for 60/30/14/7/1-day alert thresholds and already expired |
| `NotYetValid` | `notBefore` in the future (used for the clock-warning tests L-56 and L-57) |
| `PFX`, `PEM`, `EncryptedPEM` | Formats for upload and Key Vault import tests (PFX via `software.sslmate.com/src/go-pkcs12`); wrong password variants |
| `CSR` | Generated CSR for the in-platform CSR flow |
| SSH fixtures | Ed25519, RSA 3072, ECDSA keys; `authorized_keys` files with options, comments, duplicates, invalid lines; `sshd_config` samples including `AuthorizedKeysFile` and `AuthorizedKeysCommand` |
| Nginx configs | `test/testdata/nginx/*.conf`: single server, many server blocks, `include` globs, `ssl_certificate` with variables, `stream {}` blocks with TLS, unusual whitespace and comments |
| License fixtures | `licensetest.Signer` with a test Ed25519 key. The production public key is replaced by the test public key only via a build tag (`-tags testlicense`). The release build has no such tag, and CI asserts a test-signed license is rejected by the release binary |

### 22.7 CI execution and time budget

CI is GitHub Actions compatible (any runner that supports Docker works; the same `make` targets are used locally and in CI so the vendor can reproduce a failure on a laptop).

| Stage | Trigger | Content | Budget |
|---|---|---|---|
| 1. Fast | Every push | `golangci-lint`, `go vet`, unit tests (`-race`), Vitest, `gitleaks`, i18n key parity check (EN vs TR, shared catalog) | 4 min |
| 2. Integration | Every PR | testcontainers suites (parallel matrix: pg, ssh-nginx x 3 OS images, kv), authz matrix, secret-leak, rate-limit, session/CSRF, OIDC negative (fake IdP, from Phase 7) | 10 min |
| 3. E2E smoke | Every PR | Playwright smoke set (login+MFA, wizard, add target, deploy with rollback, license banner) x EN/TR, Chromium | 8 min |
| 4. Security scan | Every PR | `gosec`, `govulncheck`, Trivy fs and image | 5 min |
| 5. Nightly | Daily | Full Playwright (3 browsers), 10-minute Go fuzz per target, ZAP baseline, real Azure suite (if configured), Nginx real-systemd job, backup-wipe-restore | 60 min |
| 6. Release | Tag | Everything above, plus install.sh on clean Ubuntu, Debian, Rocky VMs; update and rollback test; ZAP full active scan against staging build; SBOM and signature; release checklist gate | 90 min |

Total time to a green PR: 15 minutes wall-clock (stages 2 to 4 run in parallel after stage 1). A stage that exceeds 150% of its budget for 3 consecutive runs is a defect to fix, not a budget to raise.

Coverage gates (advisory then enforced from Phase 2): Go statement coverage 80% overall and 95% for `license`, `secrets`, `auth`, `rbac`, `audit`; TS 70%. Coverage never substitutes for the matrices in sections 23 to 25.

---

## 23. License Behavior Test Matrix

### 23.1 Conventions

- All cases are unit tests on `license.Evaluate` with the Fake Clock unless marked (I) for integration.
- `E` = the license `valid_until` instant (UTC timestamp). Timing is instant-based (R25); there is no calendar-day or timezone arithmetic. "E+n h" means n hours after `E`.
- State names: `EVAL`, `EVAL_EXPIRED`, `ACTIVE`, `WARN(n)`, `EXPIRED_GRACE(n)` (n=1..7), `LOCK`.
- Rule used by the tests (R25): `ACTIVE` while now < E; `EXPIRED_GRACE` while E <= now < E+168h (red banner, everything works); `LOCK` when now >= E+168h. `EXPIRED_GRACE(n)` is the n-th 24-hour period after E (n = 1..7). Warnings at 60/30/14/7/1 days remaining are computed from E.
- Baseline: valid license, `max_targets=10`, 4 targets, installation ID matches, HWM store empty.
- Phase 2 status codes and names follow R36: `license.locked` is 403 (`ALC-LIC-0001`), the target limit 409 (`ALC-LIC-0008`); an unknown signing key has its own message (`ALC-LIC-0004`, R36 addendum c); banner severities follow §19.3 (R36 addendum d); grace day n follows L-22 (R36 item 11).

### 23.2 Evaluation mode

| ID | Setup | Action | Expected result |
|---|---|---|---|
| L-01 | Fresh install at T0 (installation timestamp stored with the installation ID), no license | Complete wizard with "evaluation" | State `EVAL`, `eval_started_at = T0`, 30 days remaining, limit 5 targets, banner "Evaluation, 30 days left" |
| L-02 | `EVAL` started T0 | Now = T0 + 29d 23h 59m | Still `EVAL`, 1 day remaining |
| L-03 | `EVAL` started T0 | Now = T0 + 30d | State `EVAL_EXPIRED`, treated as `LOCK` behavior (schedulers stop, allowed functions available), banner says "Evaluation ended, upload a license" |
| L-04 | `EVAL`, 5 targets | Add 6th target | Rejected with message "Evaluation allows 5 targets", no target created, audit event `target.add.denied_license` |
| L-05 | `EVAL` started T0, 3 days used | Upload valid license | State `ACTIVE` immediately; evaluation data retained; eval flag cleared; audit `license.activated` |
| L-06 | Evaluation used and expired; DB restored from a backup taken on day 2 of evaluation | Start | Installation timestamp from the backup is kept (no reset of the 30 days by restore). Result `EVAL_EXPIRED` |
| L-07 | `EVAL` started T0 | Now = T0+23d, T0+27d, T0+29d | Admin warnings at 7, 3 and 1 days before the end (one each); at T0+30d the state is `EVAL_EXPIRED` (Lock behavior, no grace); data preserved (R1) |

### 23.3 Warning thresholds

| ID | Setup | Action | Expected result |
|---|---|---|---|
| L-10 | Valid license, `E` known | Now = E-61d 12:00 | `ACTIVE`, no banner, no warning email |
| L-11 | Same | Now = E-60d | `WARN(60)`; admin banner appears; one email to each Admin; audit `license.warning.sent` |
| L-12 | `WARN(60)` sent | Advance scheduler hourly through E-31d | No repeat email; banner remains |
| L-13 | Same | Now = E-30d, E-14d, E-7d, E-1d in turn | Exactly one email per threshold (4 more); banner text updates to the current days left; banner severity escalates (info, warning, warning, critical) |
| L-14 | Warning at E-30d already sent | Restart Alice, re-run scheduler | No duplicate (sent-thresholds persisted in `license_status_history`) |
| L-15 | Non-admin users (Operator, Auditor) | Load the app at E-7d | No warning banner, no warning email for them (warning to admins only), the Operator gets no license state from `/license/status` beyond a boolean `expired`; the Auditor can read license status (read-only) but not settings (R3) |
| L-16 | Alice was down from E-31d to E-29d | Start at E-29d | Sends the 30-day warning once (catch-up), does not send 60-day again |
| L-17 | Renewal license uploaded at E-20d | Now = E-14d | Warnings restart relative to the new `valid_until`; no 14-day warning of the old license; sent-thresholds cleared |
| L-18 | SMTP not configured | Now = E-30d | Banner shown; email attempt skipped and recorded as `skipped_no_smtp`; no error to users |

### 23.4 Expiry, grace, and lock

| ID | Setup | Action | Expected result |
|---|---|---|---|
| L-20 | Valid | Now = E | `EXPIRED_GRACE(1)` red banner to all users; all features still work; scheduled jobs run; audit `license.expired` once |
| L-21 | Same | Now = E+23h 59m 59s | Same as L-20 |
| L-22 | `EXPIRED_GRACE` | Now = E+(n-1)*24h for n = 1..7 (one case each, 7 rows in test) | `EXPIRED_GRACE(n)`; banner says "n of 7 grace days used"; every scheduled job runs; deploy, discovery, rotation and adding targets (within limit) all succeed |
| L-23 | Grace period 7 | Now = E+167h 59m 59s | Still `EXPIRED_GRACE(7)` |
| L-24 | Grace | Now = E+168h | `LOCK`; audit `license.locked`; admin email "Alice is locked"; banner on all users |
| L-25 | `LOCK` | Try: log in, upload license, run backup, restore, export audit log, export inventory | All succeed |
| L-26 | `LOCK` | Try: add target, manual discovery, manual deploy, create rotation policy, start rotation, run SSH key add/remove | Rejected with the message "License expired, renew to continue", HTTP 402 and error code `license.locked` (R9); no external action; audit `*.denied_license`. Import (certificate or Key Vault) is refused the same way |
| L-27 | `LOCK` | Scheduler ticks for discovery, KV poll, auto-deploy, rotation, backup retention | Discovery, KV poll, auto-deploy and rotation do not execute (job rows not claimed). Daily backups still run (backup is an allowed function) |
| L-28 | `LOCK`, certificates expiring in 5 days and expired | Alert job runs | Expiry emails are sent, each with a "license expired" note and link to the license page; content otherwise as normal |
| L-29 | `LOCK` | Verify data integrity | No rows deleted; no certificate revoked; no target changed; no remote command executed (assert on the fake SSH server's command log: zero commands) |
| L-30 | `LOCK` | Upload valid renewal (`valid_until` in the future) | State `ACTIVE` immediately without restart; recurring read-only jobs (discovery, KV polling, expiry checks) resume on the next tick; pending external-change jobs (deploys, rotation removals) wait for Admin confirmation (R29); audit `license.renewed`; banner removed |
| L-31 | Grace day 3 | Upload valid renewal | `ACTIVE` immediately; grace banner removed; sent-thresholds reset |
| L-32 | `LOCK` | Upload a renewal that is itself already expired (E' in the past by less than 168 h) | Accepted as valid; state computed from E': `EXPIRED_GRACE`. If E' is 168 h or more in the past: accepted, state remains `LOCK`, message "This license has already expired" |
| L-33 | `LOCK` and an uploaded license for a different customer name but the same installation ID | Upload | Accepted (customer name is informational; installation ID is the binding); audit shows name change |

### 23.5 Integrity and binding

| ID | Setup | Action | Expected result |
|---|---|---|---|
| L-40 | Valid file | Change one byte in payload (e.g. `max_targets` 10 to 1000) | Rejected "License file is not valid"; audit `license.upload.invalid_signature`; previous license unaffected |
| L-41 | Valid file | Change one byte of the signature; truncate; empty file; base64 garbage; JSON with extra fields; duplicate keys | Each rejected with the same generic user message; no panic; specific reason only in the audit detail |
| L-42 | License signed by an unknown Ed25519 key | Upload | Rejected as invalid signature |
| L-43 | Valid signature, `installation_id` = other value | Upload | Rejected "This license was issued for a different installation"; shows the two IDs' last 6 characters |
| L-44 | Valid license on installation A; backup taken; restore onto a fresh machine | Restore | Installation ID is preserved; license still valid on the restored system |
| L-45 | Unsupported `format` version (e.g. 99) | Upload | Rejected with "Update Alice to use this license file" |
| L-46 | `valid_until` before `valid_from`, negative `max_targets`, zero `max_targets`, `max_targets` above 1,000,000 | Upload | Rejected as invalid; zero is invalid |
| L-47 | `features` contains unknown feature names | Upload | Accepted; unknown features ignored (forward compatible); audit lists them |
| L-48 | `valid_from` is 2 days in the future | Upload | Accepted and stored, state `PENDING` until `valid_from`; previous license (or evaluation) continues meanwhile |
| L-49 | Database row for the license is edited directly (max_targets changed) without re-signing | Restart | Alice re-verifies the stored signature at startup and hourly; row rejected; state falls back to the last valid stored license, else `EVAL_EXPIRED` behavior; admin banner "License data was modified" |

### 23.6 Clock manipulation

HWM = high-water mark, written hourly (encrypted and MAC'd with the master-key-derived key).

| ID | Setup | Action | Expected result |
|---|---|---|---|
| L-50 | Valid until E, now = E-100d, HWM written at E-100d | Advance to E-50d, HWM updated hourly | HWM = latest hour |
| L-51 | `ACTIVE`, HWM = E+3d (grace day 3) and system clock is set back to E-10d | Evaluate | Effective time = HWM (E+3d); state `EXPIRED_GRACE(3)`; admin banner "System clock is behind previous time"; audit `clock.rollback_detected` |
| L-52 | Same as L-51 but rollback is 30 minutes (within one HWM interval) | Evaluate | No warning (tolerance: 1 hour + 5 minutes of drift); state unchanged |
| L-53 | Clock rolled back; HWM file deleted | Start | HWM missing: effective time = max(clock, build-time floor). If discovered certificates show a `notBefore` later than the clock, only the admin warning "system clock appears to be behind" is raised; license state is not affected (R28) |
| L-54 | HWM record tampered (bit flip; wrong MAC) | Start | Record ignored, warning "Time record damaged", audit event; state computed from `max(clock, build-time floor, last valid HWM)` |
| L-55 | HWM record replaced with an old valid record (replay from backup) | Start | Accepted only if newer than the stored counter; older record ignored; the record contains a monotonic counter to make replay detectable |
| L-56 | Discovered certificate with `notBefore = E+10d`, system clock = E-30d, HWM missing | Evaluate | License state is computed from the clock (`ACTIVE`/`WARN`), not `LOCK`; admin warning "system clock appears to be behind" only (R28) |
| L-57 | Discovered certificate has `notBefore` in the far future (E+3 years; malformed or malicious) | Evaluate | Never affects license math: state and effective time are identical with and without the certificate (a hostile target cannot lock the platform); at most the admin warning "system clock appears to be behind" is raised, de-duplicated (R28) |
| L-58 | Clock rolled back, then Alice restarted 10 times | Each start | Effective time never decreases; HWM never moves backward |
| L-59 | Clock jumps forward from E-100d to E+100d in a single step (wall clock advanced more than 48 h beyond monotonic uptime since the last hourly HWM tick = "suspicious", R26) | Evaluate | Warn first, no immediate lock. State shown as `CLOCK_JUMP_SUSPECTED`; the new time may not trigger GRACE/LOCK until 24 h of monotonic uptime at the new time; admin banner and email "System time jumped forward by 200 days, confirm the time is correct"; audit `clock.forward_jump` |
| L-60 | L-59 | 24 h of monotonic uptime pass at the new time | The jump is accepted and the state evaluates from the new time (`LOCK` here) |
| L-61 | Forward jump then admin uploads a correction license (issued by the vendor with `replaces` set; may have an earlier `issued_at`; new `valid_until`) | Upload | Accepted; state `ACTIVE`; HWM stays at the new time (no rollback of HWM) |
| L-62 | Forward jump of 36 hours beyond uptime (NTP correction of a server that had been wrong) | Evaluate | Below the 48 h suspicious threshold (R26): accepted silently, just HWM advance |
| L-63 | NTP step backwards by 90 seconds | Evaluate | Within tolerance: no warning |

### 23.7 Target limit

| ID | Setup | Action | Expected result |
|---|---|---|---|
| L-70 | `max_targets=10`, 9 targets (mix of nginx, linux, KV) | Add a 10th | Success; count = 10 |
| L-71 | 10 of 10 | Add an 11th (each type: nginx, linux, KV) | Rejected 402 "Your license allows 10 targets"; no row created; existing targets fully functional; state is still `ACTIVE`, no lock |
| L-72 | 10 of 10 | Add 50 certificates and 200 SSH keys via discovery on existing targets | Allowed (certificates and keys do not count) |
| L-73 | 10 of 10 | Delete one target, then add one | Success |
| L-74 | 10 of 10 | Two admins add the 11th target concurrently (I) | Exactly one 402 or both rejected; count never exceeds limit (transactional check with row lock) |
| L-75 | 12 targets under an old license (`max_targets=15`) | Upload a renewal with `max_targets=10` | Accepted; no target is disabled, deleted or blocked; all 12 continue to be monitored and deployable; persistent banner "You use 12 of 10 targets; you cannot add more until you are within limit" with no end date; adding is blocked; state `ACTIVE` (R30) |
| L-76 | Same as L-75 | Remove 2 targets | Count 10 of 10; banner cleared |
| L-77 | 3 targets, license with `max_targets=10` | Renewal with `max_targets=100` | Limit becomes 100 immediately |
| L-78 | Evaluation limit 5 with 5 targets | Upload license with `max_targets=3` | Accepted with the same over-limit behavior as L-75 |
| L-79 | Discovery of an Azure subscription/vault list (v1 adds vaults one by one) | Any | No implicit target creation exists, so nothing can bypass the limit; test asserts every code path that inserts into `targets` goes through `license.CheckCanAddTarget` (static test using `go/ast` over the repository layer) |

### 23.8 In-flight operations at lock time

| ID | Setup | Action | Expected result |
|---|---|---|---|
| L-80 | Grace period 7, deployment job is `running` at the step "nginx -t" (fake clock advanced across E+168h while the job is inside a step) (I) | Clock crosses lock boundary | Job completes or rolls back on its own; either final state is consistent (new cert live and verified, or old cert restored); no half-written files; job final status recorded; no new jobs started |
| L-81 | Deploy job queued but not yet started at lock time | Lock enters | Job is not claimed; status `blocked_license`; it stays queued; after renewal it does not auto-run: it is shown to the Admin and runs only after confirmation (R29) |
| L-82 | Deploy job in flight fails at the reload step exactly as lock enters | Rollback | Rollback runs to completion despite lock (rollback is never blocked); audit shows both events |
| L-83 | Rotation in overlap phase (new key deployed and verified, old key not yet removed, 4 days remain) | Lock enters | Rotation stays in `OVERLAP`, flagged `paused_license` (R24); old key is not removed; the new key stays; the overlap timer ending during lock removes nothing |
| L-84 | Same as L-83 | Renewal uploaded after 20 days in lock | Removal is pending Admin confirmation (R29). The overdue overlap makes the removal due, but the runner first re-verifies the new key by logging in with it and sends a fresh dry-run notice; only after both, and the confirmation, is the old key removed |
| L-85 | Rotation at the "add new key" step, in flight at lock | Lock enters | Step completes; verification step also runs (it is part of the in-flight operation); removal step does not; rotation flagged `paused_license` |
| L-86 | Rotation with verification failing during lock | Verification fails | Rotation aborts, new key is removed only if it was added by this run (rollback of own additions), the old key is untouched; audit event |
| L-87 | KV polling job mid-request at lock | Lock | Request finishes; the result is stored (metadata only); no auto-deploy is triggered from it |
| L-88 | Lock enters at exactly the moment a scheduled rotation "dry-run notification" is due | Lock | Notification is not sent as rotation is paused; nothing else changes |

---

## 24. Failure-Mode Test Catalogue

Each case has an ID, is automated unless marked (M) manual, and lists observable expected behavior. "Auto-rollback" means: restore backed-up files, run `nginx -t`, reload, verify the old certificate is served again. Every failure produces an audit event with result `failed`, a job record with a plain-language reason (EN and TR), and an alert to admins. No private key or full command output containing key material may appear in any message.

### 24.1 Nginx deployment failures

| ID | Failure injected (test environment) | Expected behavior |
|---|---|---|
| F-01 | `nginx -t` fails after new files are written (cert and key mismatch) | Auto-rollback; job `failed_rolled_back`; message "The new certificate does not match its private key. Nothing was changed."; old certificate still served (checked by handshake) |
| F-02 | `nginx -t` fails because of unrelated config error already present before the deploy | Detected in a pre-flight `nginx -t` before writing anything; job `failed_no_change`; no file touched; message explains the server config is already broken |
| F-03 | `systemctl reload nginx` returns non-zero | Auto-rollback, second reload; if second reload succeeds, `failed_rolled_back`; verification of old cert |
| F-04 | Reload fails and the rollback reload also fails | Job `failed_needs_attention`; files restored on disk; critical alert to admins; UI shows the server with a red state and instructions ("Files are back in place but Nginx did not reload; run `systemctl status nginx`") |
| F-05 | Reload succeeds but handshake shows the old certificate (wrong cert served: e.g., other `server_name` block, or Nginx caching) | Deployment marked failed; auto-rollback; message "The server is still presenting the old certificate"; no false success |
| F-06 | Handshake shows a different certificate (neither old nor new; e.g., load balancer in front) | Failed; auto-rollback; message explains verification could not confirm; admin can set "verification endpoint" per location (SNI name and port) |
| F-07 | Handshake cannot connect (port closed, firewall) | Verification failed; rollback by default; result reason "Could not reach port 443 from Alice"; documented option for verify-by-SSH (`openssl s_client` on the host) tested as a separate case |
| F-08 | SSH connection drops during the write of the certificate file (container network cut mid-transfer) | Atomic write (temp file + rename) means no partial live file; temp file cleaned on the next connection; job `failed_no_change` or `failed_rolled_back` depending on the step; retry is safe (idempotent) |
| F-09 | SSH drops after the cert file is renamed but before the key file is written | Alice reconnects (3 attempts, backoff) and rolls back; if it cannot reconnect: job `failed_needs_attention` with a recovery instruction and the backup path on the host; on the next successful connection a recovery step runs automatically before any new operation |
| F-10 | Disk full while writing to the temp file | Write error caught, temp file removed, nothing renamed; job `failed_no_change`; message "The server has no free disk space" |
| F-11 | Disk full during backup creation (before write) | Aborts before any modification |
| F-12 | Target directory not writable by the service user (permission denied) | Fails at pre-flight permission check; no change; message names the directory |
| F-13 | Private key file mode is not 0600 after write (umask) | Post-write verification detects and corrects to 0600 or fails the deploy; test asserts final mode 0600 and owner as configured |
| F-14 | `alice-helper` missing, outdated, or its sudoers profile (`nginx` or `linux`) does not allow a subcommand Alice needs | Pre-flight `TestConnection` capability check reports exactly which helper subcommand or profile is missing; deploy does not start; Alice never tries to update the helper itself (R21) |
| F-15 | Concurrent deploy requests to the same target | Second job waits (per-target lock in DB) or is rejected with "Another deployment is in progress"; never runs in parallel |
| F-16 | Same certificate deployed to two servers; second fails | First remains successful and is not rolled back; overall job status `partial`, each location has its own result |
| F-17 | Uploaded certificate has an incomplete chain | Pre-flight validation warns (chain built from uploaded intermediates); deploy allowed only after admin confirms; no failure |
| F-18 | Certificate private key does not match certificate (upload) | Rejected at upload, before storage |
| F-19 | Certificate expires in the past at deploy time | Blocked with a clear message; audit denied event |
| F-20 | Nginx not installed or a different path from `nginx -T` | Discovery reports "Nginx was not found"; no partial data saved |
| F-21 | Config contains a `stream {}` block with TLS | Warning "TLS in stream blocks is not supported in v1"; the `http` certificates are still discovered; not a failure (R23) |

### 24.2 SSH, host key, and generic Linux

| ID | Failure injected | Expected behavior |
|---|---|---|
| F-30 | First connection to an unknown host | Fingerprint shown; no operations until the user confirms; nothing stored until confirmation; audit `hostkey.pinned` with the confirming user |
| F-31 | Host key changes after pinning (container recreated with a new key) | All operations on that target blocked immediately (including scheduled jobs and deployments); alert to admins with old and new fingerprints; connection is not established (asserted: no auth attempt reaches the server) |
| F-32 | Admin accepts the new host key | Requires Admin plus MFA step-up and a reason; old fingerprint kept in the history; operations resume; audit event |
| F-33 | Operator tries to accept a changed host key | Denied 403 (accepting is Admin only) |
| F-34 | Authentication fails (key removed on server) | Target state `unreachable/auth failed`; retries with backoff limited to prevent lockout on the server (no more than 3 attempts per hour); alert |
| F-35 | `AuthorizedKeysCommand` present in `sshd_config` | Warning shown on the target; key management on it skipped; inventory shows a "cannot manage" reason |
| F-36 | Attempt to remove Alice's own connection key (UI, API, or rotation) | Refused server-side with HTTP 409 and a plain-language message; audit denied; test includes the case of the same key with a different comment/options string (compared by key blob, not text) |
| F-37 | Add key to `authorized_keys` that has no trailing newline | The added entry starts on a new line; existing entries are intact |
| F-38 | File `authorized_keys` changes between read and write (race) | Compare-and-swap via checksum; conflict detected; re-read and retry once; fail with a message otherwise |
| F-39 | Slow host (10 s latency per command) | Timeouts honored per step; job fails cleanly with a timeout message; connection closed |

### 24.3 Azure Key Vault

| ID | Failure injected (fake KV) | Expected behavior |
|---|---|---|
| F-40 | 403 on certificate listing (Reader role missing) (verify: whether Key Vault Reader alone suffices for data-plane listing is confirmed by the real-Azure suite in Phase 5, R22) | Target state "No permission to read certificates"; the message names the required role ("Key Vault Reader") and both permission models (RBAC or access policy); polling continues at the normal interval; no crash loop |
| F-41 | 403 on secret get (deploy path) while listing works | Monitoring keeps working; deploy blocked with "Alice needs the Key Vault Secrets User role to deploy this certificate"; no rollback needed (nothing changed) |
| F-42 | 404 on a certificate that was in inventory (deleted in KV) | Marked "Removed from Key Vault"; bound Nginx deployments are left untouched (no removal from servers); alert to admins |
| F-43 | 404 on the vault itself (wrong name) at add time | Add-target wizard shows a clear error; target is not created and does not count towards the license |
| F-44 | 429 with `Retry-After` | Honors the header, exponential backoff with jitter, max 5 attempts per cycle; other vaults' polling are not delayed (per-vault limiter); a metric/log line records throttling; no error alert unless it persists 3 cycles |
| F-45 | Non-exportable private key (policy `exportable=false`) | Certificate can be monitored; "Deploy to Nginx" disabled with explanation; if attempted through the API, rejected with 422 before any remote action |
| F-46 | KV renewal produces a new version; the deployment to Nginx succeeds | Detected within one polling interval by the pair (current version id, X.509 thumbprint), with `Updated` only as a pre-filter (a touched-but-unchanged certificate creates no job, R23); job auto-created for every bound server; success recorded; old version retained in the history |
| F-47 | KV renewal produces a new version; deployment to one bound server fails | Failing server auto-rolls back (old cert stays); others continue; alert with the reason; next poll does not create duplicate storms (retry policy: 3 attempts, 1 h apart) |
| F-48 | Renewal event arrives while a previous deployment of the same certificate is running | Coalesced to the newest version; no parallel deploys |
| F-49 | Client secret expired (Entra returns `invalid_client`) | Target state "Credentials expired"; admin alert; message points to the credentials screen; no retry storm |
| F-50 | Azure token endpoint unreachable (air-gapped mistake) | Timeouts with a short connect timeout; target state "Cannot reach Azure"; no impact on other targets |
| F-51 | Vault firewall blocks Alice's IP (403 `ForbiddenByFirewall`) | Distinguished from RBAC 403; message mentions network rules |
| F-52 | Response is malformed JSON or truncated | Treated as a transient error; never persisted partially; no panic |

### 24.4 Email, database, process, and crash recovery

| ID | Failure injected | Expected behavior |
|---|---|---|
| F-60 | SMTP server down when an alert is due | Email queued in DB with retries (exponential backoff, up to 24 h); the in-app banner and dashboard show the alert regardless; the "notifications failing" admin banner appears after 3 failures; delivered once SMTP is back, exactly once |
| F-61 | SMTP accepts then rejects a recipient | Failure recorded per recipient; others delivered |
| F-62 | SMTP TLS certificate invalid | Send refused unless the admin explicitly configured "trust this certificate"; error is understandable |
| F-63 | SMTP credentials wrong | Test-mail button reports clearly; scheduled sends fail with alert; secrets not shown in the message |
| F-64 | PostgreSQL restarted (container restart) while a deployment job is running (I) | Alice's connection pool reconnects; running job either continues (if the lock is session-independent) or, if the job's DB lease is lost, is marked `interrupted` and recovered by the crash-recovery routine; the remote server is left in a consistent state (verified) |
| F-65 | PostgreSQL unavailable for 2 minutes | API returns a friendly 503 "Alice is having trouble reaching its database, retrying"; `/healthz` fails and `/livez` passes; jobs pause; nothing is lost after DB returns |
| F-66 | `alice` container killed (SIGKILL) at every deploy step (parametric test: after backup, after cert write, after key write, after `nginx -t`, after reload) (I) | On start, crash recovery finds jobs in `running` with an expired lease; for each, reads the recorded step and either finishes rollback (restoring backups) or verifies the live state and completes; final state is always "old cert live" or "new cert live and verified", never a mismatch of cert and key; audit records `job.recovered` |
| F-67 | Kill during rotation between "add new key" and "verify" | On restart, the runner verifies the new key; the old key remains; rotation resumes from the last recorded step; no key is ever removed by recovery without a passing verification |
| F-68 | Kill during a migration (update) | Update script restores from the automatic pre-update backup and starts the previous version; health check passes (E2E in release pipeline) |
| F-69 | Two Alice processes accidentally started against the same DB | The second refuses to start or runs read-only via an advisory lock; jobs never double-run (`SKIP LOCKED` proven by a test with 20 workers and 1000 jobs: each job executed exactly once) |
| F-70 | Disk full on Alice host during a backup or DB write | Backup fails with alert and the partial file is deleted; API returns a friendly error; existing backups untouched |
| F-71 | Master key file missing at start | Alice refuses to start with a clear log and UI-free message; does not generate a new key over existing encrypted data |
| F-72 | Master key file has wrong permissions | Start with a warning, or refuse if other users can read it (refuse; configurable only via an explicit flag) |

### 24.5 Backup, restore, and audit chain

| ID | Failure injected | Expected behavior |
|---|---|---|
| F-80 | Restore with the wrong passphrase | Unwrapping the embedded backup private key fails on the AEAD tag (R4); message "Wrong passphrase or damaged file"; nothing on the target modified (restore decrypts to a temp area and validates before swapping) |
| F-81 | Restore of a backup with one byte flipped (in the ciphertext, header, salt, and chunk boundaries: one case each) | Detected; same message; no partial restore; exit code non-zero |
| F-82 | Restore of a truncated backup | Detected; no change |
| F-83 | Restore of an empty file, of a text file, of a backup from a newer Alice version | Empty/text: "This is not an Alice backup"; newer version: "Backup was created by a newer Alice version" |
| F-84 | Restore of a backup made by an older supported version | Migrations run after restore; health check passes |
| F-85 | Full cycle: seed data, backup, wipe DB and volumes, restore, verify (release gate) | Same users, targets, certificates, encrypted credentials decrypt (a deployment works), audit chain verifies, installation ID identical, license still valid |
| F-86 | Backup taken while jobs are running | Consistent snapshot (single transaction `REPEATABLE READ` for the dump) |
| F-87 | Backup file inspected with `strings`/grep for known test secrets (private key, password, TOTP secret, master key bytes) | None found in the file; the file holds the X25519 backup private key only wrapped by the passphrase (Argon2id), and the host stores neither the passphrase nor a passphrase-derived key |
| F-88 | Retention: 20 daily backups created | Only newest 14 kept; a failed backup never deletes the older ones. With 48 h of no successful backup, an admin alarm is raised (R7) |
| F-90 | Audit log: modify one row's content directly in SQL | `alicectl audit verify` and the scheduled verifier report the first broken sequence number; admin alert; UI shows "Audit log integrity problem at entry N" |
| F-91 | Delete a row in the middle | Detected (gap in sequence and hash mismatch) |
| F-92 | Delete the last N rows (truncate the tail) | Detected via the periodically stored chain head checkpoint (also forwarded to syslog when configured, and shown as the daily audit head hash on the dashboard for offline recording, R16); if there is no checkpoint newer than the deletion, detection is not guaranteed (documented residual risk) |
| F-93 | Reorder two rows | Detected |
| F-94 | Application DB role attempts `UPDATE` or `DELETE` on `audit_log` | Denied by DB privileges (the app role only has INSERT and SELECT); test executes it |
| F-95 | Concurrent audit writes (100 goroutines) | Chain remains valid and contiguous (serialized by an advisory lock) |
| F-96 | Audit forwarding to syslog target down | Local write is never blocked; forwarder retries; a backlog metric is shown |
| F-97 | Restore then continue writing audit | The chain continues from the restored head; a `system.restored` event is recorded |

---

## 25. Security Test Plan

### 25.1 Authorization matrix (generated)

- The router registers every endpoint through `route.Register(method, path, handler, policy)`, where `policy` declares the minimum role or scope (`Public`, `Authenticated`, `Operator`, `Admin`, `AuditorOrAdmin`, `AdminStepUp`). There is no way to register a route without a policy (compile-time by the function signature; a lint test also greps that no `mux.Handle` call bypasses `Register`).
- The test `TestAuthzMatrix` iterates the route table and the OpenAPI document (both must list the same operations; a mismatch fails) and for each endpoint executes requests as: anonymous, expired session, Admin, Operator, Auditor, API token with each scope, API token with insufficient scope, user with a pending TOTP (password OK but MFA not done), and a disabled user.
- Expected result per (endpoint, identity) is computed from the declared policy and the documented role table in the decisions (Admin everything; Operator view, discovery, deploy, add/remove keys, view target metadata but never credentials; Auditor read-only plus audit log and license status, but not settings; Operator cannot see the audit log) (R3). The expected table is also written to `docs/authz-matrix.md` by `make authz-doc`, and a CI check ensures the committed file is up to date, so a policy change shows up as a reviewable diff.
- Assertions: forbidden returns 403 (401 when unauthenticated), the body carries no data from the resource, no side effect happened (DB row counts and fake SSH command log unchanged), and an audit `*.denied` event exists for authenticated denials.
- Additional object-level checks: an API token created by user A cannot be read or revoked by user B (unless Admin); a user cannot escalate their own role; the last Admin cannot be deleted, demoted or disabled; the wizard endpoints return 404 or 403 after setup completes.
- Sensitive operations requiring step-up (private key download, host key acceptance, backup download, user role change, SSO config, license upload, credential edit): tested without recent MFA (expect 401/403 with `mfa_required`), with a stale MFA older than the configured window, and with a fresh one.
- Mutation testing on the policy layer (`go-mutesting`, nightly, `rbac` package only): changing `>=` or a role constant must break at least one test.

### 25.2 Secret-leak tests

A set of canary secrets is created per test run and inserted everywhere secrets can enter: user password, TOTP secret, recovery codes, API token, SSH private key (PEM and OpenSSH formats), TLS private key (PEM, PKCS8, PFX password), Azure client secret, SMTP password, OIDC client secret, recovery passphrase, master key bytes, DEK bytes. Each value contains a recognizable marker (`CANARY-<random>`) plus a raw-form variant (private keys are matched by base64 body lines).

| ID | Test | Pass criterion |
|---|---|---|
| S-01 | Run the full integration suite and the E2E suite with log capture (zap/slog handler wrapping a buffer, plus container stdout collected) at DEBUG level | Zero occurrences of any canary in logs |
| S-02 | Response scanner middleware in test builds: every HTTP response body, header, and cookie is scanned for canaries and PEM markers (`-----BEGIN ... PRIVATE KEY-----`, `PuTTY-User-Key-File`, `OPENSSH PRIVATE KEY`) | None, except the single explicit "download private key" endpoint, which is only allowed for Admin with MFA step-up plus reason and is asserted separately |
| S-03 | Error paths: force failures (invalid key upload, wrong password for PFX, SSH failure, KV 403 echoing a body containing a canary) | Error responses, job messages, audit detail and logs contain no canary; upstream error bodies are sanitized |
| S-04 | Database inspection: after storing each secret, read the raw column values | All credentials and private keys are ciphertext (AES-GCM structure, no canary, no PEM marker); each has its own DEK; two identical secrets produce different ciphertexts |
| S-05 | Audit log content | Records the action, not the secret; reason text is stored but is scanned for canaries in a test (users pasting secrets into the reason field is mitigated by a UI warning; the server also rejects a reason containing a PEM block) |
| S-06 | Backup and update package scan | The backup file contains no plaintext canary (F-87); the release tarball and images contain no secrets (gitleaks and Trivy secret scan) |
| S-07 | Process and crash artifacts: trigger a panic with a canary in memory; check panic output and recovered error reporting | Panic handler logs stack without values; no core dumps (`ulimit -c 0`, verified in the container spec) |
| S-08 | Generated OpenAPI schema | No response schema exposes fields named `private_key`, `password`, `secret`, `token_hash` except in the explicit download or one-time creation responses (API token shown once at creation) |
| S-09 | Private key download | Requires Admin plus MFA step-up plus non-empty reason; audit event written before the response is sent; response has `Cache-Control: no-store`; second download attempt is also audited |
| S-10 | Print/debug endpoints | `/debug/pprof`, `/metrics` and `/test/*` are not reachable in release build without authentication (`/test/*` absent) |
| S-11 | Memory hygiene (best effort) | Decrypted key material is held in `[]byte` and zeroed after use (unit tests for the helper; no guarantee claimed against the Go GC) |

### 25.3 Rate limiting and lockout

| ID | Test | Expected result |
|---|---|---|
| R-01 | 5 failed logins for one account from one IP | Progressive delay begins (fake clock: 1 s, 2 s, 4 s, ...); response identical in shape to a normal failure |
| R-02 | 10 failed logins for one account within 10 minutes | Temporary lockout 15 minutes (values are configurable defaults); correct password during lockout is still rejected with the same generic message; after 15 min the account works; audit `auth.lockout` |
| R-03 | Credential stuffing: 1 IP tries 50 distinct usernames | Per-IP limit triggers; no account lockout for unknown or other accounts (lockout for a real account by a third-party IP is bounded so an attacker cannot lock the admin out permanently: per-account lockout never exceeds 15 minutes, and the OIDC/break-glass path is not affected) |
| R-04 | Username enumeration | Response body, status code and timing (statistical test, 200 samples, difference under a threshold) equal for existing vs non-existing users, including with wrong TOTP |
| R-05 | TOTP brute force: 10 wrong codes | TOTP attempts rate limited independently; the same code cannot be reused within its 30-second window (replay protection test); recovery codes are single use |
| R-06 | General API limit: 300 requests/min per token/session (default) | 429 with `Retry-After`; the limit is per identity, not global; `/livez` and `/healthz` are exempt |
| R-07 | Expensive endpoints (password hash, backup download, test connection) | Stricter limits; concurrent Argon2 operations bounded (memory DoS protection) |
| R-08 | `X-Forwarded-For` spoofing | Ignored unless a trusted proxy setting is configured; test attempts to rotate the header to evade the limit |
| R-09 | Restart behavior | Per-account lockout state (`login_attempts`) survives restart; IP and general API limiters are in memory for the single-host v1 and reset on restart (accepted, R20) |
| R-10 | Password reset / recovery by a locked user | Recovery-code login is also rate limited |

### 25.4 Session and CSRF

| ID | Test | Expected result |
|---|---|---|
| A-01 | Cookie attributes | `HttpOnly; Secure; SameSite=Strict; Path=/`, `__Host-` prefix; no session ID in URL or response body |
| A-02 | Idle timeout (fake clock) | 29 min idle: valid; 31 min idle: 401 and re-login; activity resets the idle timer (activity as defined by R39 item 1) |
| A-03 | Absolute timeout | 12 h after login: 401 even when active |
| A-04 | Session fixation | Session ID changes after login and after MFA completion; old ID invalid |
| A-05 | Logout | Server-side invalidation; reusing the cookie fails; "log out everywhere" works; role change or disable ends the user's sessions |
| A-06 | CSRF | State-changing requests without the CSRF token (double-submit or header token bound to session) get 403; with a cross-origin `Origin` header get 403; GET requests never change state (test walks the route table for GET routes that write) |
| A-07 | CORS | No `Access-Control-Allow-Origin` for foreign origins; preflight rejected |
| A-08 | Security headers | `Strict-Transport-Security`, `Content-Security-Policy` (no `unsafe-inline` scripts), `X-Content-Type-Options`, `Referrer-Policy`, `Cache-Control: no-store` on API responses |
| A-09 | API token auth | No token of any scope can retrieve a private key (R23); bearer token accepted only on `/api` and not on UI-session-only endpoints; expired token rejected; scope enforced; revoked token rejected immediately; token compared in constant time; only hash stored (S-04) |
| A-10 | HTTP on port 80 | Not served, or redirects to HTTPS only; TLS below 1.2 refused; test with `testssl.sh` in nightly |
| A-11 | XSS | Playwright injects `<script>`/HTML into certificate common name, server names, key comments, target names, and audit reasons (via test fixtures); the rendered pages show them as text; CSP prevents execution (checked with a script that would set a marker) |
| A-12 | Injection | Every string field crossing into SSH commands is validated or escaped; test with `; rm -rf`, backticks, newline, `$(...)` in file paths, usernames, server names: the fake SSH server's command log shows no injection; SQL injection payloads on all list/filter/sort parameters (parameterized queries; `sqlmap` in nightly ZAP job) |
| A-13 | Path traversal | Certificate paths outside allowed directories, `..`, symlinks on the remote server: rejected or resolved per policy; test uses symlink to `/etc/shadow` |
| A-14 | SSRF | Target host/URL inputs (Key Vault URL, OIDC issuer, SMTP host) can point only to what admins configure; KV URL must match `*.vault.azure.net`; redirects are not followed to other hosts |

### 25.5 OIDC negative tests

A fake IdP (`internal/testutil/fakeidp`, generates keys, discovery document and signed ID tokens) supports fault injection. Each case must end in a failed login, an audit `auth.oidc.denied` with a reason code, and no session.

| ID | Case |
|---|---|
| O-01 | ID token with invalid signature; signed with a different key; `alg=none`; `alg=HS256` using the public key as secret (algorithm confusion) |
| O-02 | Wrong `iss`; wrong `aud`; expired `exp`; `iat` in the future beyond skew; `nbf` in the future |
| O-03 | Missing or wrong `nonce`; replayed `nonce`; `state` missing, wrong, or reused; authorization code replay |
| O-04 | PKCE: missing verifier; wrong verifier |
| O-05 | Redirect URI mismatch, open redirect attempt through the `next` parameter |
| O-06 | User in no mapped group: login denied with the message "Your account has no access to Alice, contact your administrator"; no user is auto-created with any role |
| O-07 | Group claim overage (Entra ID `_claim_names` for more than 200 groups): Alice resolves via the Graph endpoint if configured, else denies safely; never grants a default role |
| O-08 | Group removed at the IdP: role is dropped at next login; existing sessions of OIDC users are re-evaluated at 15-minute refresh or end at the session limit (documented behaviour) |
| O-09 | Email claim changes for an existing subject: matching is by `iss`+`sub`, not e-mail (prevents account takeover through e-mail reuse) |
| O-10 | An OIDC user tries local login or has no password; a local user tries to be linked by an IdP with the same e-mail without admin approval: denied |
| O-11 | IdP discovery or JWKS unreachable: login fails with a clear message; local break-glass admin still works; JWKS cached per its cache headers with a size cap; key rotation at the IdP handled (unknown `kid` triggers one refetch, rate limited) |
| O-12 | IdP metadata over plain HTTP or with an invalid certificate: rejected at configuration |
| O-13 | Group mapped to Admin: mapping change requires MFA step-up, audited; a mapping that would grant Admin to "all users" (empty group value) is rejected; while the setting "SSO users may be Admin" is OFF (default, R19) any Admin mapping is refused and SSO users get at most Operator/Auditor |
| O-14 | Local MFA is not bypassed: local accounts cannot log in via the OIDC callback path; OIDC users are not required to have local TOTP (the IdP's MFA is the responsibility of the IdP; documented) |

### 25.6 Fuzzing

Go native fuzzing (`go test -fuzz`), with seed corpora committed under `testdata/fuzz/` and crashers automatically committed as regression tests. Nightly: 10 minutes per target. Release: 30 minutes per target. Any crash, hang (over 1 s per input), or out-of-memory blocks release.

| Target | Package | Properties asserted |
|---|---|---|
| `FuzzParseNginxConfig` / `FuzzNginxDiscovery` | `providers/nginx` | Never panics; parse time is linear; output paths are only from `ssl_certificate` and `ssl_certificate_key` directives; comments and quoted strings handled; deeply nested blocks (limit 100) and huge lines (limit 1 MB) rejected cleanly; parse-print of the extracted directives is stable |
| `FuzzParseAuthorizedKeys` | `providers/linuxssh` | Never panics; the parse then serialize round trip preserves the key blob and options for valid lines; invalid lines are preserved verbatim when Alice rewrites the file; option strings with quotes and escapes; very long lines; NUL bytes; CRLF |
| `FuzzParseSSHDConfig` | `providers/linuxssh` | `AuthorizedKeysFile` token expansion (`%h`, `%u`, `%%`) never escapes to unexpected paths; `Match` blocks handled |
| `FuzzParseLicense` | `license` | Never panics or allocates unbounded memory for any input up to 64 KB; no input except a genuinely signed file verifies (the harness signs a corpus with the test key; mutation of any byte must fail verification); signature check happens before JSON semantic use; duplicate keys, huge numbers, invalid UTF-8 rejected |
| `FuzzParseCertificateUpload` | `secrets` | PEM/PFX/DER handling of malformed and hostile ASN.1 (uses stdlib; asserts no panic and bounded memory) |
| `FuzzBackupHeader` | `backup` | Parsing of the header, salt, KDF parameters (bounded Argon2 memory to prevent a malicious file from causing memory exhaustion) |
| `FuzzOpenAPIInputs` | `api` | Random JSON bodies against every create endpoint schema: no 500 (any 500 is a bug), no panic |

### 25.7 DAST (OWASP ZAP baseline)

- Job `dast`: build the release-mode image (`-tags` none), start with a seeded database, and run `zap-baseline.py` (passive scan plus spider) against the HTTPS URL, first unauthenticated, then authenticated using a ZAP context that logs in as Admin (scripted login including TOTP from a test secret) and as Operator and Auditor (three runs).
- The OpenAPI file is imported so the API is covered (`zap-api-scan.py`).
- Policy file `.zap/rules.tsv`: all findings of level Medium and High fail the pipeline. Every ignored rule has a written reason and an expiry date in the file; expired ignores fail the pipeline. Informational and Low findings are listed in the report and reviewed at each release.
- Cadence: nightly baseline plus API scan; release runs the full active scan on a staging build (against a disposable environment only, never a customer system).
- Complementary: `testssl.sh` for the TLS configuration (nightly), `nuclei` default HTTP templates (release), Trivy image and filesystem scan on every PR, `govulncheck` on every PR, `gosec` on every PR, `gitleaks` on every push, SBOM (CycloneDX) generation on release.
- Findings that are accepted are recorded in `SECURITY-REPORT.md` under residual risk with an owner and date.

### 25.8 Other security tests

| ID | Test |
|---|---|
| X-01 | License bypass resistance: a unit test proves the license check gates (`CheckCanAddTarget`, `SchedulerAllowed`) are invoked by every job type; adding a new job type without registering its license class fails a test |
| X-02 | Container hardening check in CI: runs as non-root, read-only root FS (write attempt outside volumes fails), container UID 10001, no extra capabilities, PostgreSQL not published on host (compose file lint with `conftest`) |
| X-03 | Supply chain: `go.sum` verified, dependencies pinned, image digests pinned, release artifacts signed, SBOM present |
| X-04 | TOFU test with an active MITM (proxy presenting another host key after pinning) is F-31 |
| X-05 | Break-glass: with OIDC misconfigured or down, the local Admin with TOTP logs in |
| X-06 | Password policy: length 11 rejected, 12 accepted, listed breached password rejected (offline list), Argon2id parameters at least the documented minimum (test reads the stored hash prefix) |

---

## 26. Development Phases and Definition of Done

### 26.1 Global Definition of Done (applies to every phase and every change)

A change is done only when all of the following are true:

1. The code has been reviewed by the reviewer agent, and every blocking comment is resolved or explicitly deferred with a recorded reason.
2. All automated tests are green in CI: unit, integration, and the E2E smoke set for that phase. New behavior has new tests written first. No test is skipped or quarantined without an issue and an owner.
3. All new user-visible text has translation keys in both `locales/en.json` and `locales/tr.json`; the parity check passes; the Turkish text was reviewed for tone (plain language, no jargon without explanation).
4. Every new sensitive action writes an audit event (who, when, IP, what, result) and a test asserts it exists, including the denied path.
5. New endpoints are in `openapi.yaml`, registered with an explicit role policy, and the generated `authz-matrix.md` is committed.
6. Documentation is updated: user guide page, admin guide if configuration changed, API reference generated, and the changelog entry; every user-visible error has a code in the format `ALC-<AREA>-<NNNN>` and appears in the troubleshooting page.
7. `gosec`, `govulncheck`, Trivy, and `gitleaks` show no new High or Critical finding; new Medium findings are fixed or recorded in `SECURITY-REPORT.md` with a rationale.
8. Secret-leak and authz-matrix suites still pass (they run on every PR).
9. Accessibility: new screens pass the axe check, are usable by keyboard only, and work at 1280 px and 1920 px widths.
10. No manual step is needed to reproduce a fresh install of the phase result (`docker compose up` works from a clean checkout).
11. The owner's verification steps for the phase (below) were executed on a clean install by the coordinator and produced the stated outcome.

### 26.2 Phase 0: Skeleton and CI

**Deliverables:** repository layout with the modules from the architecture; Go `alice` binary serving `/livez`, `/healthz` and an embedded empty React UI (Mantine); `docker-compose.yml` (alice, postgres on an internal network); migration tooling; Clock interface; i18n plumbing with `en.json` and `tr.json` and a language switcher; OpenAPI skeleton; CI pipeline stages 1, 2 (empty suites), 4 with lint, unit, secret scan, dependency scan; `make` targets for local runs.

**Automated tests that must pass:** unit test harness runs in CI (`-race`); a smoke integration test starts Postgres via testcontainers and applies migrations; Vitest renders the app shell in EN and TR; i18n key parity check; Playwright smoke: page loads, language switch shows Turkish text; container hardening checks X-02; the test proving `/test/*` is absent in a release build; gosec, govulncheck, Trivy, gitleaks green.

**Owner verifies:**
1. On the server, run `docker compose up -d` in the project folder. Wait one minute.
2. Open `https://<server-address>` in a browser. Accept the temporary certificate warning. You should see a page titled "Alice" with a simple message.
3. Click the language selector and choose "Türkçe". The page text changes to Turkish. Choose English and it changes back.
4. Open the project page on the code host and check that the latest build has a green check mark.

**Exit criteria:** compose up works from a clean checkout on Ubuntu 22.04; CI green on main; the empty UI is in EN and TR; global DoD met.

### 26.3 Phase 1: Core (auth, MFA, RBAC, audit, secret store)

**Deliverables:** first-run wizard steps up to admin creation and recovery passphrase; local accounts with Argon2id and mandatory TOTP and recovery codes; sessions and CSRF; three roles and the route-policy registry; user management screen; personal API tokens; audit log with hash chain, viewer, export, verifier; envelope-encryption secret store with master key file; rate limiting and lockout; password policy with breached list; security headers. OIDC SSO is not part of this phase (delivered in Phase 7, R31); Phase 1 is local auth with TOTP only (TOTP via `pquerna/otp`).

**Automated tests that must pass:** authz matrix over all routes (25.1); secret-leak suite S-01 to S-10 (with what exists so far); R-01 to R-10; A-01 to A-10; audit chain F-90 to F-97; envelope encryption unit tests (round trip, tamper, wrong master key, unique DEKs, S-04); password policy X-06; E2E: wizard, login with TOTP, wrong TOTP, lockout, logout, idle timeout using the test clock, in EN and TR; coverage gates for `auth`, `rbac`, `audit`, `secrets`.

**Owner verifies:**
1. Open Alice for the first time. The setup wizard asks for your language, then your name and password. Use a long password (12 or more characters). Try a short one: Alice refuses it and explains why.
2. Scan the QR code with your authenticator app (Microsoft Authenticator or Google Authenticator). Type the 6-digit code. Save the recovery codes shown.
3. Choose a recovery passphrase and write it on paper and store it safely. The wizard tells you it cannot be recovered.
4. Log out and log in again: password first, then the code from the app.
5. Go to Users. Create two people: one "Operator", one "Auditor". Log in as each in a private window. Confirm: the Operator cannot see "Users" or "Audit log"; the Auditor can see the Audit log but has no buttons that change anything.
6. As the admin, open the Audit log. You will see your own logins and the two user creations. Click "Verify integrity": it says "The audit log is intact".
7. Enter a wrong password five times: Alice slows down and then temporarily blocks that account.

**Exit criteria:** all three roles behave differently as specified; the audit chain verifies; the leak suite finds nothing; the first security review completed with no High findings open.

### 26.4 Phase 2: Licensing and licensectl

**Deliverables:** `license` module with the Clock, HWM store, evaluation mode, states and banners, warning emails through `notify` (email sender exists in minimal form), license upload screen and API, target limit check function; `licensectl` CLI (keygen, issue, verify, inspect; correction licenses via `replaces`) with documented offline, passphrase-protected key handling (2 USB copies plus paper backup, R8); wizard license step; test-only build tags; `license status` view and history; lock-mode enforcement layer used by the job framework (scheduler gate).

**Automated tests that must pass:** every case L-01 to L-88 that applies at this phase (L-70 to L-79 target-count cases use a stub target repository until Phase 3; L-80 to L-88 use stub jobs until Phases 4 and 6; they are re-run against the real jobs then); `FuzzParseLicense`; a test that a license issued by `licensectl` verifies in the server and one signed with another key does not; a test that a release-tag build has the production public key and rejects test-signed files; E2E: evaluation banner, upload valid, upload tampered, upload wrong installation, banners at each threshold using the test clock, in EN and TR.

**Owner verifies:**
1. On the vendor computer run: `licensectl issue --installation <the ID shown in Alice> --customer "Test Company" --targets 10`. A file is created.
2. In Alice open License, click Upload and select the file. The page shows "Valid until <date>, 10 targets".
3. Edit the file with a text editor (change any number) and upload it again: Alice says the file is not valid, and the earlier license remains active.
4. Vendor step in a test environment only: start Alice in "demo clock" mode (the test build) and move the date forward. Check what you see at 60, 30, 14, 7 and 1 day(s) before the end: a yellow banner and an e-mail. On the last day and the 7 days after: a red banner but everything works. After the 7 grace days (168 hours after the end): the "locked" banner; try to add something and see a friendly message. Upload a renewed file: everything works again at once.
5. Move the date backward in demo mode: Alice shows "The system clock looks wrong" and does not extend the license.

**Exit criteria:** fake-clock scenarios in section 23 all green; lock and unlock demonstrated end to end; `licensectl` documented and tested on Linux and macOS; private key handling procedure written; security review has no High findings.

### 26.5 Phase 3: Provider framework and Linux SSH targets

**Deliverables:** provider interface with capability discovery and registry; `linuxssh` connector (connection pooling, timeouts, remote command surface limited to the root-owned `alice-helper` static Go binary with the `linux` and `nginx` sudoers profiles, installed by the admin through the setup snippet); platform SSH key generation and display in the wizard; host key pinning with confirm and changed-key blocking; target CRUD with license check; credential storage through the secret store; job framework (queue in PostgreSQL, leases, retries, crash recovery, per-target locks); scan of `authorized_keys`, custom `AuthorizedKeysFile`, `AuthorizedKeysCommand` detection; SSH key inventory screen with filters; refusal to remove own key.

**Automated tests that must pass:** SSH integration across Ubuntu, Debian, Rocky containers; F-30 to F-39; L-70 to L-79 against real target creation; job queue concurrency test F-69 and crash recovery unit tests F-66 (framework part); `FuzzParseAuthorizedKeys` and `FuzzParseSSHDConfig`; A-12 injection tests for the command runner; secret-leak tests with SSH keys; authz matrix updated; E2E: add host with host-key confirmation, inventory shows keys, changed host key blocks, in EN and TR.

**Owner verifies:**
1. Open the setup screen that shows Alice's own public key and the one-line command. Copy that command and run it on a test Linux server (the page explains what it does in plain words).
2. Click "Add server", enter the server address and the user name. Alice shows a "fingerprint". Compare it with the fingerprint that the server displays (the page shows the command). Click "Yes, this is my server".
3. Alice lists the SSH keys found on that server with the user names they belong to. Open one and see where it is used.
4. Try to remove Alice's own key: Alice refuses and explains.
5. On the test server, change the host key (instructions provided: `sudo ssh-keygen -A` after deleting the old ones) and restart the SSH service. In Alice click "Test connection": it stops and shows a red warning that the server's identity changed. Nothing else can be done on that server until an Admin confirms.
6. Add servers until you reach the license limit and see the friendly message on the next attempt.

**Exit criteria:** host trust rules proven by F-30 to F-33; job framework survives the kill test; inventory matches the seeded fixtures exactly; DoD met.

### 26.6 Phase 4: Nginx certificate discovery and deploy

**Deliverables:** `nginx` provider on top of `linuxssh`; discovery via `nginx -T` parsing (no private key reading); certificate inventory with expiry; manual upload of certificates and keys; CSR generation; deployment engine (backup, atomic write, `nginx -t`, reload, handshake verification, rollback); deployment history and per-step results; `alice-helper` `nginx` sudoers profile documentation and a helper/profile validation in Test connection.

**Automated tests that must pass:** F-01 to F-20; all nginx configs fixtures for discovery; `FuzzParseNginxConfig`; upload validation (matching key, chain, expired, formats); deploy idempotence test (run twice); crash-step test F-66 for deployment; A-13 path traversal; S-01 to S-05 with TLS keys; L-80 to L-82 with the real deploy job; E2E: discover, upload a certificate, deploy, then deploy a mismatching certificate and see the automatic rollback, in EN and TR. The Nginx real-systemd nightly job runs green (the real-systemd job moves to Phase 8, R38 item 16).

**Owner verifies:**
1. Add an Nginx test server. Click "Discover". The list shows each website with its certificate and the days left.
2. Click "Upload certificate" and choose a new certificate and its key (a test pair is provided). Then click "Deploy" on one website and confirm. Watch the steps turn green: "Backup", "Write", "Check", "Reload", "Verify".
3. Open the website in a browser and confirm it shows the new certificate.
4. Repeat with a deliberately wrong pair (the test pack contains one, marked "broken"). Alice reports "The new certificate does not match its key. Nothing was changed". The website still works and still shows the older certificate.
5. Open "History" to see both attempts.

**Exit criteria:** deploy failure cases at every step end in a working site; no scenario leaves cert and key mismatched; deployment and recovery proven under process kill; security review has no High findings.

### 26.7 Phase 5: Azure Key Vault

**Deliverables:** `azurekv` provider; Service Principal (secret or certificate) and Managed Identity authentication; add-vault wizard with a permission checker that tells which of the roles are missing; certificate and key inventory; polling every 15 minutes (configurable); new-version detection; binding of a KV certificate to Nginx locations; auto-deploy through the Phase 4 engine; import of uploaded certificates into KV; least-privilege documentation; fake KV server and optional real Azure suite.

**Automated tests that must pass:** F-40 to F-52 against the fake; contract test between fake and recorded responses; auth tests for the three credential types; per-vault limiter test; L-87; `FuzzParseCertificateUpload`; secret-leak tests with KV secret contents and client secrets; SSRF check A-14; E2E with the fake: add vault, see certificates and keys, "renew" in the fake, and observe the automatic deployment on the Nginx container; real Azure suite green when credentials are configured (advisory, not blocking; the recorded responses are reference shapes transcribed from the public REST reference for the API version the pinned SDK sends, and the real-Azure suite is opt-in for the owner and outside `make ci`: R40 items 30 and 2).

**Owner verifies:**
1. Follow the on-screen guide to give Alice a "Key Vault Reader" role on a test vault in the Azure portal. Add the vault in Alice; the permission checker shows green ticks for what works and a clear note for what is missing.
2. See the certificates and keys listed with their expiry dates. Non-exportable certificates are marked "Monitor only".
3. Bind one Key Vault certificate to a website on the test Nginx server.
4. In Azure, create a new version of that certificate (or use a test certificate with a 1-day renewal policy). Within 15 minutes, Alice shows "New version found" and deploys it, and the deployment appears in the history.
5. Remove the "Key Vault Secrets User" role in Azure, trigger another renewal: Alice reports, in plain words, which role is missing; the website is unchanged.

**Exit criteria:** end-to-end renewal to deployment works on the fake and, if credentials are provided, on real Azure; all KV failure modes are handled without crash loops; nothing in logs or responses contains vault secrets.

### 26.8 Phase 6: SSH key lifecycle and rotation

**Deliverables:** SSH key generation (Ed25519 default, RSA 3072/4096, ECDSA), private key storage and the audited download flow; deploy public key, remove key; rotation policies (admin only, disabled by default, overlap default 7 days, only platform-managed keys); dry-run preview and notification before each run; rotation runner (add, verify, overlap, remove) with recorded steps and rollback info; pause on lock; never remove the old key after an incomplete rotation.

**Automated tests that must pass:** F-36 to F-39 for rotation; F-67; L-83 to L-88 with the real rotation runner; rotation planner unit tests (only managed keys, never Alice's own key, overlap boundaries with the fake clock, dry-run equals actual plan); a property test that for any injected failure at any step the old key remains; S-09 for download; authz matrix for policy endpoints (Admin only); E2E: generate, deploy, verify login with the new key, run a manual rotation with a 1-minute overlap in the e2e build, see the old key removed only after the overlap, in EN and TR.

**Owner verifies:**
1. Click "Generate key", choose "Ed25519", and select a test server and user. Click "Deploy". Alice reports that it verified a login with the new key.
2. Try "Download private key": Alice asks for your code from the authenticator and for a reason. The download is recorded in the Audit log.
3. Create a rotation policy for that key ("every 90 days, keep the old one for 7 days"). It stays "Off" until you switch it on.
4. Click "Preview next run". Alice shows exactly which keys will change on which servers, and sends you an email.
5. Start a rotation manually. Both old and new keys are visible on the server during the overlap. Nothing is removed until the overlap has passed and the new key has been checked again.
6. Turn off the test server's network in the middle of a rotation: the old key stays in place and Alice reports the incomplete rotation.

**Exit criteria:** the "old key never removed on incomplete rotation" property holds under fault injection; pause and resume with license proven; security review has no High findings.

(Phase 6, R41: the named tests are `TestF36OwnKeyNeverRotated`, `TestF37RotationIntoFileWithoutNewline`, `TestF38RotationFileChangedBetweenReadAndWrite`, `TestF39SlowHostDuringRotation`, `TestF67KillBetweenAddAndVerify`, `TestKillAtEveryRecordedPoint`, `TestL83OverlapLockRemovesNothing`, `TestL84RenewalAfterTwentyDays`, `TestL85AddInFlightAtLock`, `TestL86VerifyFailsDuringLock`, `TestL88LockAtPreviewTime` and the property test `TestOldKeyRemainsUnderAnyInjectedFailure` in `internal/jobs/sshkeyjobs`; L-87 stays `TestL87PollInFlightAtLock` in `internal/jobs/kvjobs` (Phase 5); the planner's `TestOnlyManagedKeys`, `TestNeverAlicesOwnKey`, `TestOverlapBoundaries` and `TestPlanIsDeterministic` in `internal/sshkeys/plan`; over the API `TestS09PrivateKeyDownload`, `TestF36OwnKeyNeverRotatedOrDownloaded`, `TestDryRunEqualsActualPlan`, `TestSecretLeakSuiteWithGeneratedKeys`, `TestL83FlaggedWhenTheLockEnters`, `TestRotationInLockRunsNoCommand`, `TestLockDuringRemovingOldSendsNoCommand` and `TestPhase6RoutesAuthzOverTheWire` with the generated matrix and `TestRotationRoutesAuthz`; the end-to-end journeys are `web/e2e/phase6.spec.ts`. Owner steps 1–6 are the empty walkthrough table of `docs/security/reviews/phase-6.md`.)

### 26.9 Phase 7: Alerts, dashboard and SSO

**Deliverables:** expiry alert engine (certificates, KV certificates and keys, license, host key change, failed deployments, integrity problems); recipients and thresholds settings; email templates EN and TR including the "license expired" note in lock mode; deduplication and retries; dashboard (expiring soon, failed deployments, targets by status, license status, rotation upcoming); filters and saved views; CSV export of inventory; scheduled audit chain verification; OIDC SSO (Entra ID, AD FS, Keycloak) with group-to-role mapping, the setting "SSO users may be Admin" default OFF, MFA delegated to the IdP (R19, R31).

**Automated tests that must pass:** alert thresholds with the fake clock; no duplicates; catch-up after downtime; F-60 to F-63; L-28 and L-18; dashboard API tests with seeded data (exact counts); Vitest for dashboard widgets and filters; E2E in EN and TR: seeded environment shows the expected counts, a filter narrows the list, an expiring certificate triggers an e-mail captured by the fake SMTP (MailHog-compatible test container); export contains exactly the filtered rows; OIDC negative suite O-01 to O-14, X-05 and E2E SSO login with the fake IdP in EN and TR; performance test (R32) with 5,000 certificates and 500 targets: dashboard API p95 under 500 ms and list pages p95 under 300 ms on the CI runner.

**Owner verifies:**
1. Enter the mail server details in Settings and click "Send test e-mail". Confirm that the e-mail arrives.
2. In the test environment there is a certificate that expires in 7 days. Confirm that the dashboard lists it under "Expiring soon" and that you received an e-mail with the website name and the date.
3. Use the filter to show only certificates expiring within 30 days, then only one server. Click "Export" and open the file: it contains only what you see.
4. Turn the mail server off and wait for the next alert: the dashboard shows "E-mails could not be sent". Turn it on again: the e-mail arrives once.
5. Configure single sign-on with a test identity provider and map a group to "Operator". Log in through SSO: you get the Operator role. Mapping a group to "Admin" is refused until you switch on "SSO users may be Admin". The local administrator with the authenticator code still works if the IdP is down.

**Exit criteria:** every alert type sends once per threshold; the dashboard numbers match the database in tests; SSO login and its negative tests pass; the performance budget is met.

### 26.10 Phase 8: Packaging and release

**Deliverables:** `install.sh` and the tarball with bundled images for air-gapped install; wizard steps complete (HTTPS certificate, SMTP, license, first target); `alice-update.sh` with automatic backup, migration, health check and automatic rollback; `alicectl` subcommands (backup, backup list, backup verify [--deep], restore, selfcheck, audit verify, setup-token --reset, support-bundle) and `install.sh --restore-mode` / `--uninstall` (restore is CLI-only); daily backups with retention of 14, hybrid X25519 encryption (R4); signed release tarball; documentation set (install, admin, user, troubleshooting, API, security); `SECURITY-REPORT.md`; release checklist; SBOM and signatures.

**Automated tests that must pass:** install on clean Ubuntu 22.04, Debian 12 and Rocky 9 VMs (no internet for the air-gapped variant, checked by blocking outbound traffic); update from the previous release, including a forced migration failure that must roll back automatically (F-68); backup, wipe, restore and verify (F-85) plus F-80 to F-88; the whole matrices in 23, 24 and 25 green; ZAP baseline and full active scan without Medium or High findings; full Playwright on three browsers in EN and TR; `testssl.sh` A-grade or equivalent; the release binary contains the production public key and no test tags; the reproducible build check.

**Owner verifies:**
1. On a fresh server, copy the tarball, run `tar xzf alice-1.0.0.tar.gz && cd alice && sudo ./install.sh`. When finished, open the address that it prints.
2. Complete the wizard in your language: administrator, authenticator code, recovery passphrase, HTTPS certificate, mail server (skip is allowed), license (use evaluation), first server. Every step has a plain explanation.
3. Run `sudo /opt/alice/alicectl backup`, then run the restore (`install.sh --restore-mode`, then `alicectl restore`) on a second empty server with the passphrase. Log in there and see the same data and the same license.
4. Try the restore with a wrong passphrase: it fails with a clear message and changes nothing.
5. Run `sudo ./alice-update.sh alice-1.0.1.tar.gz` (a test update). Alice is back within a few minutes. Run it with the "broken update" test file: Alice returns to the previous version by itself and works.
6. Read the security report and the release checklist. Every item is ticked with a date.

**Exit criteria:** release checklist fully ticked; no open High or Critical findings; all owner steps of all phases repeated once on the release candidate by the coordinator; known issues list and residual risks in `SECURITY-REPORT.md`; the vendor signs off.
