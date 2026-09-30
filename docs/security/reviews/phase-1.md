# Security Review — Phase 1 (Core: local auth + TOTP, RBAC, audit, secret store)

Scope (spec §17.2, Phase 1): crypto design, sessions and CSRF, MFA, envelope encryption, audit chain, redaction.
Exit criteria: authz matrix test passes; leak test passes; audit chain verifies; peer crypto review sign-off; no
High finding open.

This note is the Phase 1 security report. `SECURITY-REPORT.md` (spec §26.1.7, R15) is created with packaging in
Phase 8 and takes over the Medium findings and accepted risks listed here.

## Evidence

All commands run from the repository root. Integration tests (`-tags integration`) need Docker.

| # | Check | Command | Expected |
|---|---|---|---|
| 1 | Authorization matrix over every route and identity (§25.1) | `go test ./internal/api -run 'TestAuthzMatrix\|TestRoutePermissionsMatchSpec\|TestNoRouteBypassesTable' -count=1` | ok |
| 2 | `docs/authz-matrix.md` is current | `go test ./internal/api -run TestAuthzMatrixDocIsCurrent -count=1` | ok |
| 3 | Secret-leak suite S-01..S-05, S-07 (panic), S-08, S-10, master-key and DEK canaries | `go test -tags integration ./internal/api -run 'TestSecretsNeverLeak\|TestHandlerPanicLeaksNoSecret\|TestUnexpectedErrorsAreLoggedWithoutTheirText\|TestOpenAPIResponsesExposeNoSecretFields' -count=1` and `go test -tags integration ./cmd/alice -run 'TestServeLogsNoDatabasePassword\|TestFailedStartupAndCLINameNoDatabasePassword' -count=1` | ok |
| 4 | Session, CSRF, rate limit, lockout (A-01..A-09, R-01..R-06, R-08..R-10) | `go test -tags integration ./internal/api -run 'Test[AR][0-9]' -count=1` | ok (18 tests) |
| 5 | Lockout under parallel attempts, last-admin race, TOTP replay, tokens (C6, C7, R10) | `go test -tags integration ./internal/auth/... -count=1` | ok |
| 6 | Audit chain F-90..F-95, F-97, tail truncation, golden vectors | `go test -tags integration ./internal/audit -count=1` | ok |
| 7 | App role cannot UPDATE/DELETE/TRUNCATE `audit_log`; triggers block the owner (F-94) | `go test -tags integration ./migrations -count=1` | ok |
| 8 | Envelope encryption round trip, tamper, swapped rows, wrap bound to key version, unique DEKs (S-04) | `go test -tags integration ./internal/secrets -count=1` | ok |
| 9 | Master key missing / mismatch / permissions / symlink / owner refuse startup (F-71, F-72) | same command as row 8 (`TestFirstStart…`, `TestMissingKeyFile…`, `TestDifferentKeyFile…`, `TestKeyFile…`) | ok |
| 10 | Password policy X-06, Argon2id parameters, bounded Argon2 work (R-07) | `go test ./internal/auth -run 'TestPassword\|TestProductionParametersMatchSpec\|TestHashAndVerify\|TestVerify\|TestDummyVerify' -count=1` | ok |
| 11 | TLS 1.2 minimum and curves (A-10, server side) | `go test ./internal/platform/tlscert -run TestServerConfig -count=1` | ok |
| 12 | Release build has no `/test/*` endpoint or demo clock | `go test ./cmd/alice -run TestRelease -count=1` | ok |
| 13 | Operator CLI (setup-token, audit verify, reset-mfa, unlock) | `go test -tags integration ./cmd/alice -run 'TestSetupTokenResetCLI\|TestAuditVerifyCLI\|TestAdminResetMFACLI\|TestAdminUnlockCLI' -count=1` | ok |
| 14 | Static analysis and dependencies | `make lint vuln secrets-scan fs-scan` | no findings |
| 15 | E2E owner journey EN/TR incl. axe at 1280/1920 px, keyboard-only sign-in, CSP violations | `make e2e-up && make e2e` | all passed |
| 16 | Container hardening incl. `ulimits: core: 0` | `make hardening-check` (running stack) | ok |

In the Command column, `\|` is how Markdown writes a `|` inside a table; type a plain `|` in the shell (for
example `-run 'TestAuthzMatrix|TestRoutePermissionsMatchSpec'`).

The whole set runs in `make ci`. On 2026-09-30 every command above passed on branch `phase-1` (base `c8091c0`
plus the documentation-only commit that adds this note), together with a full `make ci`.

### Coverage (advisory until Phase 2, §22.7)

`go test -tags integration -cover` on 2026-09-30:

| Package | Statements covered |
|---|---|
| `internal/auth` | 84.4 % |
| `internal/auth/ratelimit` | 95.6 % |
| `internal/auth/breached` | 100.0 % |
| `internal/rbac` | 96.1 % |
| `internal/audit` | 90.1 % |
| `internal/secrets` | 81.6 % |

## Crypto design review checklist

- [ ] AES-256-GCM with 96-bit random nonces for payload and DEK wrap; fresh DEK per secret (SEC-040).
- [ ] AAD binds table, row, column and (wrap layer) key version (SEC-041 as amended).
- [ ] Master key 256-bit, file 0400, refuse on wider permissions, symlinks, non-regular files and foreign owners,
      never regenerated over existing data (SEC-042).
- [ ] Sub-keys only via HKDF-SHA256 (`crypto/hkdf`) with the four fixed labels; master key never used directly as
      a MAC key (SEC-043).
- [ ] Argon2id m=64 MiB, t=3, p=2 for passwords; m=64 MiB, t=3, p=4 for the backup key; concurrency bounded.
- [ ] TOTP SHA-1/6 digits/30 s ±1 step, last step stored, replay rejected (SEC-006).
- [ ] Session tokens 256-bit, only SHA-256 stored, `__Host-` cookie, rotation on login, MFA, step-up and password
      change (SEC-018, SEC-019).
- [ ] CSRF token = HMAC-SHA256(K_csrf, session token), constant-time compare, Origin/Sec-Fetch-Site check (SEC-024).
- [ ] Constant-time comparison for tokens, codes and hashes (SEC-049).
- [ ] Audit hash = SHA-256(prev ‖ canonical JSON), zero genesis, gapless app-assigned `seq`, advisory lock before
      the head read (SEC-071 as amended by R35).

## Other review items

- [ ] Turkish UI text reviewed for tone and terminology by a native speaker (§26.1.3). The automated checks
      (`make i18n-check`, identical-value allow-list, E2E in Turkish) only prove completeness.
- [ ] Owner verification below completed.

## Findings

Severity High/Medium/Low. Phase exit requires no open High finding. There is none.

| ID | Severity | Description | Decision |
|---|---|---|---|
| P1-01 | Medium | The migration owner in the Compose stack is the PostgreSQL superuser `alice`, and its URL (`ALICE_MIGRATE_DATABASE_URL`) sits in the long-running `alice` container's environment. Code execution in `alice` therefore yields a superuser, which can bypass the audit append-only triggers (`SET session_replication_role = replica`, `ALTER TABLE … DISABLE TRIGGER`) and rewrite or truncate the log. An empty migrate URL also makes the app run as one role (startup warning). (preflight C14) | Accepted for the Phase 1 development stack (R35). Fix in Phase 8: dedicated non-superuser owner role and a one-shot migration container, so the app container holds no owner URL. |
| P1-02 | Medium | The audit checkpoint (last verified seq and hash) lives in the same database. An attacker with owner-level database access (see P1-01) can truncate the tail and rewrite the checkpoint without detection until external anchors exist. | Deferred: syslog/SIEM forwarding of the head hash (Phase 7) and the daily verification job (Phase 3). Interim: the admin guide asks administrators to record the head hash outside Alice. |
| P1-03 | Low | R-04 is covered by a same-shape/same-status test and an equal-work dummy Argon2 verify, not by the §25.3 200-sample statistical timing test. | Deferred to a later phase (preflight B22). |
| P1-04 | Low | `DELETE /tokens/{id}` answers faster for a token id that does not exist than for another user's token (the latter also writes an authorization-denial audit entry in a second transaction), so an authenticated user can learn whether a token id exists. Ids are random UUIDv7 values. | Accepted; revisit when token ids become visible to other users. |
| P1-05 | Low | `POST /auth/login` while holding a full session sets a new cookie without revoking the old server-side session; the old session stays valid until it expires or the user signs out everywhere. | Accepted for Phase 1; revoke the presented session on login in a later phase. |
| P1-06 | Low | The same-origin check compares `Origin` with `https://` + `Host` exactly (a `Host` with an explicit `:443` fails) and passes when both `Origin` and `Sec-Fetch-Site` are absent (non-browser clients; the CSRF token is still required). | Accepted: fails closed for browsers; CSRF token check is the primary control. |
| P1-07 | Low | Startup and CLI error messages keep the raw error text for operability (database passwords are proven absent by tests); a future data migration could quote row values in a "migration failed" message. 500 responses log only `error_type` and `sqlstate`, which makes some failures harder to debug. | Accepted; review data migrations for quoted values. |
| P1-08 | Low | The recovery passphrase strength meter runs only in the browser; the server enforces the 16-character minimum (spec threat B-1 mentions a strength check). | Accepted for Phase 1; server-side strength scoring can be added with backups in Phase 8. |
| P1-09 | Low | Audit details are guarded by a case-insensitive key-segment denylist, not a registered allowlist (SEC-070, §7.5). An unforeseen secret-bearing key name without a sensitive segment would not be rejected. | Accepted in R35; the details keys used in Phase 1 were checked against the list when it was written, and `audit.Append` rejects a sensitive key instead of storing it. |
| P1-10 | Low | `GET /audit/export` and `POST /audit/verify` are limited only by the general 300 requests/min per identity; each reads the whole log. | Accepted at Phase 1 log sizes; add a dedicated limit if logs grow large. |
| P1-11 | Info | `rbac.SetupFinish` (`setup.finish`, Admin without step-up) is no longer used by a route: the recovery-passphrase and complete routes use `settings.manage` (Admin + step-up). The test `TestRouteRuleViolationsCatchesWeakPermissions` uses it to prove those routes reject a weaker permission. | Kept deliberately; remove when a later phase confirms no wizard step needs it. Resolved in Phase 2 Task 1 (rbac.SetupFinish removed). |

## Known limitations

Carried to later phases; the owner report and `CHANGELOG.md` summarise them.

Product and operations:

- The setup code is created with `alice setup-token --reset` (`make setup-token`); `install.sh` printing it at
  install time arrives in Phase 8 (§26.1.10 manual step accepted in R35).
- The wizard ends after the recovery passphrase; HTTPS certificate upload, SMTP, license and first target are added
  by Phases 8, 7, 2 and 3. The temporary certificate is still renewed only at container start.
- The wizard has no "Back" button (§18.5) and keeps no server-side position before the administrator exists: a
  reload returns to the setup-code screen and the code is entered again. "Back" and full resume arrive with the
  Phase 8 install wizard (R35 addendum).
- Lockout and audit-integrity problems are recorded in the audit log but not emailed or forwarded to syslog
  (Phase 7), and there is no scheduled daily verification yet (Phase 3 jobs).
- A person created by an administrator is not forced to change the initial password at first sign-in (R35); the
  admin guide asks administrators to hand passwords over through a separate channel.
- API tokens have one scope (`read` or `operate`); in Phase 1 no route accepts `operate` beyond what `read`
  allows, because operate actions arrive with targets in Phase 3.
- In-memory IP, API and setup-code rate limits reset on restart (R20); the per-account lockout survives restarts.
- A block ends after 15 minutes, but the failed sign-in count stays at 10 or more until a complete sign-in, so one
  more wrong attempt starts a new block. Someone who knows a username can keep that account blocked, within the
  R33 caps (R35 addendum). Mitigation: an administrator's **Set a new password**, or for the only administrator
  the host-root, audited `alice admin unlock <username>`.
- PostgreSQL still runs with a writable root filesystem and default capabilities, and database passwords live in
  environment variables; container hardening of PostgreSQL and secret files arrive with packaging in Phase 8.
- Development stacks created in Phase 0 must be recreated once with `make reset` (the `alice_app` role is created
  only on a fresh database volume).
- No cleanup job yet: expired sessions, setup sessions and revoked or expired API token rows accumulate until the
  `maintenance.cleanup` job arrives with the job system (Phase 3).

Security (see Findings for details):

- Superuser migration URL in the `alice` container, including the trigger bypass (P1-01, Medium, Phase 8).
- Audit checkpoint in the same database; tail truncation by an owner-level attacker is undetected until external
  anchors arrive (P1-02, Medium, Phases 3 and 7).
- R-04 statistical timing test deferred (P1-03).
- `POST /audit/verify` is allowed for Auditors and read-scope API tokens (`audit.read`) by design: Auditors have
  **Verify integrity**. Each call adds a checkpoint and an `audit.verified` entry and is bounded only by the
  general request limit (see P1-10) (R35 addendum).
- The sign-in limit groups IPv6 addresses by /64. A client that controls a larger range (for example a /48, which
  holds 65,536 /64 networks) gets a separate 10-per-minute budget for each /64 and can keep the shared queue of
  password checks busy, so other people's sign-ins wait or fail with "try again" (`ALC-AUTH-0012`). A coarser
  prefix limit or a global sign-in budget is planned for a later phase.
- Token-id existence visible through revoke timing (P1-04); login over a full session does not revoke the old
  session (P1-05); strict same-origin rules (P1-06); raw startup/CLI error text and minimal 500 logs (P1-07);
  passphrase strength checked in the browser only (P1-08).

API and spec deviations:

- A missing step-up answers `403` with reason `auth.stepup_required` (`ALC-AUTH-0003`, as §9.2 says); §25.1 names
  it `mfa_required`.
- After an administrator exists, wizard routes that need a setup session answer `401 setup.session_expired`
  (`ALC-SET-0003`) instead of `404`/`403` (§25.1); `POST /setup/session` answers `404`. Neither carries data.
- Wrong setup-code attempts are rate-limited and logged with the client IP but not written to the audit log
  (R35).
- List responses carry no `total_estimate` and error bodies no `help_url` (R35).
- The audit export may be cut off by the 60-second server write timeout on very large logs; its verification
  result (`X-Alice-Audit-Intact`, `verification`) covers entries up to `head_seq` only, not entries appended while
  the export runs.
- The CSV export prefixes cells that start with `=`, `+`, `-`, `@`, tab or carriage return with an apostrophe
  (formula-injection protection), so offline re-hashing must use the JSON export. The re-hash mapping (null
  `actor_id`/`ip` as `""`, timestamps with exactly six fractional digits, Go JSON escaping) is in
  `docs/operator-guide.md`.

Documentation gaps:

- No rendered API reference: `api/openapi.yaml` is the reference in Phase 1 (§26.1.6).
- Auditors have a short section in `docs/admin-guide.md`, not a guide of their own.
- `SECURITY-REPORT.md` is created in Phase 8; this note is the Phase 1 report.
- The Turkish text has not yet been reviewed for tone by a native speaker (checklist above).
- Coverage gates are advisory; the numbers are recorded above (§22.7, §26.3).

## Owner verification

Spec §26.3 "Owner verifies". It needs a person with a phone authenticator and a browser, so it is done by the
owner, not by the build agents. Run it on a clean release-mode stack (no `e2e` build tag):

```bash
make reset          # deletes the development database and keys, starts a fresh release-mode stack
make setup-token    # prints the one-time setup code
```

Then in a browser at https://localhost (or https://localhost:$ALICE_PORT), following `docs/first-run.md`:

1. Wizard: enter the code, choose the language, create the admin; an 11-character password is refused with an
   explanation; a 12+ character password is accepted.
2. Scan the QR code with a phone authenticator, enter the 6-digit code, save the recovery codes.
3. Set the recovery passphrase; the wizard warns it cannot be recovered. Finish with **Go to the dashboard**.
4. Sign out and sign in again: password, then the code from the app.
5. **Users**: create one Operator and one Auditor. In private windows sign in as each (they enrol TOTP). The
   Operator sees neither **Users** nor **Audit log**. The Auditor sees **Audit log** (and may use **Verify
   integrity**) but not **Users**. Like everyone, the Auditor can create and revoke their own API tokens, change
   their own password and create new recovery codes on **My account**; only the actions that manage other people
   are absent.
6. As the admin open **Audit log**: the sign-ins and the two user creations are listed. Choose
   **Verify integrity**: it shows "The audit log is intact."
7. Enter a wrong password for the Operator, leaving time between attempts. After the fifth failure Alice makes
   each next attempt wait (1, 2, 4, 8, then 16 seconds); an attempt made during the wait is refused with the same
   message and is **not counted**, so from the sixth attempt on wait about 20 seconds before each one. Sign-in is
   also limited to 10 attempts per minute from one IP address: a "Too many requests in a short time." message
   (HTTP 429) means wait a minute and go on. After the tenth counted failure the account is blocked for
   15 minutes (the right password is refused with the same message meanwhile). Optional:
   `alice admin unlock <operator username>` ends the block at once.

Also run:

```bash
docker compose -f deploy/docker-compose.yml --env-file deploy/.env exec -T alice /usr/local/bin/alice audit verify
```

Expected: exit code 0 and "The audit log is intact: … entries checked, head entry …, head hash …".

Results (filled in by the owner):

| Step | Result |
|---|---|
| Date / commit | |
| 1 | |
| 2 | |
| 3 | |
| 4 | |
| 5 | |
| 6 | |
| 7 | |
| `alice audit verify` | |

## Sign-off

Reviewer, date and commit are filled in when the review is completed.
