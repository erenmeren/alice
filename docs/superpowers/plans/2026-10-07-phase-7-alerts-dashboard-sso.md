# Phase 7: Alerts, Dashboard and SSO — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An Administrator enters the mail server in **Settings** (the password is stored only as an envelope under the master key), clicks **Send test e-mail**, and — when the server's certificate is not trusted — sees its fingerprint and may choose **Trust this certificate**. Alice checks every 15 minutes which certificates in use on servers, Key Vault certificates, Key Vault keys and Key Vault client secrets reach an expiry threshold (60/30/14/7/1 days by default, editable, plus one notice when expired) and emails the configured recipients exactly once per threshold — across restarts, two processes, downtime (only the most urgent reached threshold is sent) and a license lock (the email then carries the note "Alice's license has expired"). Mail that cannot be sent is retried for 24 hours, per recipient, and after three failed attempts in a row Administrators see **E-mails could not be sent**. The new **Dashboard** shows expiring certificates (expired ones visually distinct), failed deployments of the last 7 days, servers and vaults by status, the license, upcoming rotations, the audit log's last verified head hash (Administrators and Auditors) and the conditions that need attention, with exact counts. The certificate and SSH key lists keep their filters in the address, can save them as personal views, and **Export** exactly the filtered rows as CSV (formula-safe, audited before the first byte, available in lock). Single sign-on works with any OpenID Connect provider (Entra ID, AD FS, Keycloak): Authorization Code with PKCE, a server-side single-use `state`/`nonce` bound to a browser cookie, users matched by issuer and subject only, IdP groups mapped to roles with Admin refused until **SSO users may be Admin** is switched on, MFA delegated to the IdP (step-up by a fresh IdP sign-in), and the local Administrator with the authenticator code always works when the IdP is down.

**Architecture:** Three pure packages carry the logic that must be exactly right: `internal/alerts/expiry` (which notice is due: thresholds, catch-up, no duplicates, dashboard buckets), `internal/auth/oidc/claims` (ID-token claim validation after the signature check, the groups claim and Entra overage, role resolution with the Admin cap, mapping validation, the safe `next` path, issuer validation, user names) and `internal/platform/csvx` (formula-safe CSV with a byte order mark; the audit export moves onto it). `internal/notify` gains the mail settings (in the `settings` table; the password in the new envelope table `setting_secrets`), the mailer source the sender reads at every drain, certificate pinning and an optional CA bundle, the synchronous test mail, the env import of `ALICE_SMTP_*`, 24-hour retries, the delivery state behind the failing banner, and the recipients setting that `NotifyAdmins` now honours (every existing email follows it). A new module `internal/alerts` owns the "monitored" definition (one SQL source for the scan and the dashboard), the thresholds setting and the `alerts.scan` task; the table `alerts` is the exactly-once ledger (unique per kind, object, expiry instant and threshold). A new read-only module `internal/reports` answers the dashboard, the attention conditions, saved views and the CSV exports (paging the inventory's own list functions, so an export is the list). OIDC lives in `internal/auth` (`SignInOIDC`, `StepUpOIDC`, `RefuseOIDC`, lockout email) and `internal/auth/oidc` (providers, discovery fixed at configuration time, a size- and rate-bounded JWKS key set, mappings, the global Admin switch, `Begin`/`Complete` over `oidc_login_states`), built on `github.com/coreos/go-oidc/v3` v3.21.0 and `golang.org/x/oauth2` v0.37.0. The e2e stack gains two test-only Go fakes as hardened containers: `alice-fakesmtp` (STARTTLS, MailHog-compatible message API, fault switches) and `alice-fakeidp` (discovery, JWKS, authorize, token; next-login and fault switches), the in-process `internal/testutil/fakesmtp` and `internal/testutil/fakeidp` (the spec's `fakeidp`) being their engines and the Go suites' fakes. A tagged performance test (R32) seeds 5,000 certificates and 500 targets.

**Tech Stack:** Go 1.27.1; new modules `github.com/coreos/go-oidc/v3` v3.21.0, `golang.org/x/oauth2` v0.37.0 and `github.com/go-jose/go-jose/v4` v4.1.5 (direct: the bounded key set parses JWKS and JWS with it); pgx v5, goose v3, testify, testcontainers-go v0.44; React 18 + TypeScript 6 + Vite 8, Mantine 8, React Router 7, TanStack Query 5, i18next, Vitest 5 + Testing Library + msw 2, Playwright 1.63 + axe-core. No new web dependency.

**Spec:** `docs/superpowers/specs/alice-v1/` — `06-quality.md` §26.9 (the authority: deliverables, tests that must pass, owner steps 1–5, exit criteria), §23.3–§23.4 (L-16, L-18, L-28), §24.4 (F-60..F-63), §24.5 (F-90..F-92), §25.1 (step-up for SSO config), §25.2 (canaries: SMTP password, OIDC client secret), §25.5 (O-01..O-14), §25.8 (X-05), §22.7 (budgets), R32; `00-decisions.md` lines 14, 60, 64, R2, R10, R11, R16, R19, R29, R31, R32, R35 (users.oidc_*; lockout email), R36 item 14 (SMTP until Phase 7), R37 items 14 and 17, R38 items 14–15, R39 items 7 and 15, R40 items 7, 20, 27, 31, R41 items 6, 15, 23 and addendum 50, 61, 66; `01-product.md` S2, S8 AC4–AC5, S10 AC3 and AC6, S11, §3.1; `02-architecture.md` §5.2 (go-oidc + x/oauth2), §5.3–§5.4 (modules and import rules), §7.1 (users, oidc_providers, oidc_group_mappings), §7.4 (alerts), §7.6 (settings, setting_secrets, notifications_outbox), §8.2–§8.6 (`alerts.evaluate`, `notify.send`, gating), §9.1–§9.6 (conventions, `/auth/oidc/...`, `/sso/*`, `/alerts`, `/dashboard/*`, `/settings/smtp`), §10.1–§10.5; `03-integrations.md` §11.3 (client-secret expiry alert), §11.6 (KV alerts in lock); `04-security.md` §14.4 AU-3, AU-4, §15.3 (SEC-010..SEC-015), SEC-009, SEC-020, SEC-037, SEC-065, SEC-072..SEC-075, §15.4 (role table), §17.2 (Phase 7 gate: OIDC flow, email header injection, output escaping, notification content leaks); `05-operations.md` §18.5 step 5, §19.3 (lock-mode note wording), §21. `00-decisions.md` wins on conflict; this plan proposes **R42** (written in Task 22) for the conflicts listed under "Spec conflicts resolved by this plan". Carry sources: `docs/superpowers/rulings/phase-6.md`, `phase-5.md`, `phase-4.md`, `audit-remediation.md` ("Carried to later phases", "Parked"), `docs/security/reviews/phase-6.md` "Known limitations". Format and style reference: `docs/superpowers/plans/2026-10-05-phase-6-ssh-key-rotation.md`.

**Plan verification:** written against branch `phase-7` at `aa7985b` (= `master`: Phases 0–6 and the audit remediation merged; `make ci` green at `dcf1ff9`). Every existing path, symbol, route, Make target and command a task uses was checked with `grep`/`sed` in that tree, among them: `notify.{AdminNotifier (field Clock), NotifyAdmins, Sender (Pool, Mailer, Catalog, Clock, Log), Drain, Render, Message, Mailer, MaxAttempts, baseBackoff, maxBackoff, sendTimeout, backoff, oneLine, SMTPConfig (Host, Port, From, Username, Password, TLSMode, RootCAs), SMTPMailer, NewSMTPMailer, Send, compose, ErrSMTPConnect, ErrSMTPTLS, ErrSMTPAuth, ErrSMTPRejected, ErrorCode, templatePattern}`, the `notifications_outbox` columns and statuses (`pending`, `sent`, `failed`, `skipped_no_smtp`), `config.SMTP (Host, Port, From, Username, PasswordFile, TLSMode, CAFile, Configured)`, `cmd/alice/services.go:{buildServices, buildRunner, buildScheduler, buildSender, newMailer, services (pool, keyring, auditLog, audit, auth, setup, license, queue, inventory, registry, sshPool, sshkeys)}`, `cmd/alice/wiring.go:{periodicTypes, checkWiring}`, `cmd/alice/testapi_e2e.go:{testMailbox, e2eMailbox, testMailer, resetSQL, sweepEvery, rotationPlanEvery, rotationSweepEvery, destroyRetiredEvery, azureCAFile, e2eClock}`, `cmd/alice/testapi_release.go`, `jobs.{Register, Type, Task (Type, Every, Run, Retry), NewScheduler, Scheduler.RunNow, Gate, AuditVerifyTask, AuditVerifyConfig, auditVerifyState (LastIntactAt, LastBrokenAt, AlertedBadSeq, AlertedProblem), auditVerifyStateKey "jobs.audit_verify", TemplateAuditBroken, TemplateJobDead, LicenseEvaluate, NotifySend, AuditVerify, MaintenanceCleanup, SSHKeyDestroyRetired}`, `license.{Class*, Snapshot (Eval), Evaluation.Locked, Service.Snapshot, Templates, mailTime}`, `audit.{Log, New, Append, Event, Actor, ActorType (ActorUser, ActorToken, ActorSystem), SystemActor, Success, Failure, Denied, sensitiveSegments, checkDetails, Verify, Report (Intact, Checked, HeadSeq, HeadHash, FirstBadSeq, Problem), checkpointKey "audit.checkpoint", checkpoint, Service.Iterate}`, `secrets.{Keyring, NewKeyring, Seal, Open, Location (Table, RowID, Column), Envelope, Plaintext, NewPlaintext}`, `settings.{Get, Set, Delete}` (`internal/platform/settings`), `netaddr.{Allowed, DialContext}`, `clock.{Clock, Fake, NewFake, Offset}`, `db.{InTx, Querier, IsUniqueViolation}`, `pgtest.{Main, New, DB (Owner, App, OwnerURL, AppURL)}`, `auth.{Service, Config (Pool, Keyring, Audit, Clock, Hasher, RecoveryHasher), Principal (Kind, UserID, Username, DisplayName, Role, Locale, SessionHash, StepUpUntil, TokenID, Scope), Meta, SessionResult, SessionInfo, startFullSession, rotateSession, resultFor, recordFailure, lockAdmins, ErrLastAdmin, StepUpWindow, SessionAbsolute, Login (lockAccountByNameSQL filters auth_source = 'local'), PruneExpired, CreateUser, UpdateUser, ResetMFA, ResetPassword}`, the `users` columns (`auth_source`, `role_source`, `is_break_glass`, `timezone`, `password_hash` nullable for `oidc`), `rbac.{Permission, Policy (Anonymous, Setup, Pending, Roles, TokenScope, StepUp), policies, Decide, Role (Admin, Operator, Auditor), Scope, Subject, SubjectKind}`, `api.{route (method, pattern, perm, limit, lic, handler), limitClass (limitDefault, limitNone, limitLogin, limitMFA, limitHealth, limitDownload), server.apiRoutes, guard, allowRate, ErrorCode, AllErrorCodes, codeForReason, errorMap, fail, writeError, writeErrorWith, writeJSON, decodeExact, pathUUID, meta, etag, ifMatch, issueSessionCookie, setCookie, sessionCookie "__Host-alice_session", csvSafe, csvVerificationLine, writeAuditCSV, pageLimit, nextCursor, Deps}`, the Phase 6 test helpers (`sshDeps`, `callWith`, `decodeErr`, `pathParamRE`, `identities`, `expectedMatrix`, `row`, `allw/unau/forb/step`, `routeRuleViolations`, `lockAvailable`, `lockRefused`, `lockAvailableRoutes`, `TestA06GETRoutesNeverChangeState`, `TestAuthzMatrixDocIsCurrent`, `phase6Table`), `inventory.{CertificateFilter (TargetID, Source, Query, Expiry, Cursor, Limit), CertificatePage, Certificate (…, LocationCount), ListCertificates, certificateSources, expiryWindows, certificateColumns, KeyFilter (TargetID, OSUser, Query, Flag, IncludeMissing, Cursor, Limit), KeyPage, SSHKey, ListSSHKeys, storeDetailedCerts (the per-certificate `SELECT certificate_id IS NULL FROM kv_certificate_versions` at kv_store.go:404), VaultInfo.SecretExpiresOn (`credentials.public_info->>'secret_expires_on'`)}`, `sshkeys.{RetiredKeyRetention (types.go:24), DestroyRetiredKeys (destroy.go:218)}`, migration conventions (`00010` header, SQLSTATEs up to `Z1014`, `migrations/roles_integration_test.go` `explicitGrants`/`explicitColumnGrants`, `down_integration_test.go` `TestMigration00006UpAndDownKeepPhase3Data`, `tableExists`, `grantProblems`), `internal/archtest/arch_test.go` (`rules`, `denied`, `deniedStd`, `pureDenied`, `TestAllowed`), the web (`router.tsx`, `layout/AppLayout.tsx` `NAV_ITEMS`, `LicenseBanners.tsx`, `pages/{HomePage, LoginPage, CertificatesPage, SSHKeysPage, UsersPage, AuditPage}.tsx`, `components/{ErrorAlert, AppModal, CodeText, StepUpProvider}.tsx`, `api/{client.ts (apiFetch, FetchOptions.responseType), endpoints.ts (listCertificates, auditExportUrl), types.ts (ExpiryFilter, CertificateSourceFilter, CertificateQuery, SSHKeyQuery), queryKeys.ts}`, `test/{render.tsx (renderRoute, renderWithAuth, renderWithStepUp), server.ts, fixtures.ts (sessionFor), goSources.ts (registeredJobTypes, backendAuditActions)}`), the e2e helpers (`composeExec`, `targetExec`, `azureExec`, `resetInstall`, `runWizard`, `signIn`, `signOut`, `freshCode`, `advanceClock`, `drainJobs`, `runScheduled`, `apiAs`, `expectAccessible`, `expectWide`, `PHONE_WIDTH`, `translator`, `browserLocale`, `COPY`, `ADMIN`), `deploy/docker-compose.e2e.yml` (service `fakeazure` as the hardening model; networks `frontend`, `backend` internal), `deploy/dev/check-hardening.sh` (the `fakeazure` block), `test/images/fakeazure/Dockerfile` (pinned `golang:1.27.1-alpine@sha256:8a59…` and `distroless/static-debian12@sha256:d75c…`), `cmd/alice/compose_test.go` (`TestE2EFakeAzureIsTestOnlyHardenedAndSharesItsCA`), `tools/pincheck`, the Makefile targets `test`, `test-integration`, `lint`, `vuln`, `build`, `release-symcheck` (`E2E_SYMBOLS`), `image-check`, `e2e-up`, `e2e`, `e2e-down`, `e2e-hardening-check`, `authz-doc`, `i18n-check`, `web-test`, `web-coverage`, `web-lint`, `coverage`, `secrets-scan`, `fs-scan`, `ci`, and `coverage-floors.json`. The three new modules and their sums were resolved in a scratch module (`go get github.com/coreos/go-oidc/v3@v3.21.0 golang.org/x/oauth2@v0.37.0 github.com/go-jose/go-jose/v4@v4.1.5`): `github.com/coreos/go-oidc/v3 v3.21.0 h1:wZo4Q9Pum8dYEj0eMUPrqR+kvuGkeUplbLpNCkBqoWM=`, `golang.org/x/oauth2 v0.37.0 h1:JUlcxA8oAtauLfiH8FX2/FkAWHAdi0QtGCGc+hofE98=`, `github.com/go-jose/go-jose/v4 v4.1.5 h1:RjgjO2LOtWOJKUC5wpwY9LR3B3vwVAz6JS2YHfYU6eA=`. Nothing in this plan has been compiled: before Task 1 the controller runs the pre-flight scan earlier phases used (apply each task's code in a scratch worktree and compile it); every task's red/green steps are the real check. Where a sketch says "as `<name>` does", the implementer reads the code named before writing.

## Global Constraints

- Go module path is `alice`; toolchain `go 1.27.1`. Every shell step assumes `export PATH="$HOME/.local/go/bin:$HOME/go/bin:$PATH"` and the repository root as working directory.
- All code, identifiers, comments, file names, commit messages and technical docs are in English. Turkish appears only as translation values in `tr.json` files.
- **Commits:** Conventional Commits, made with `git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only -m "<message>" -m "Co-Authored-By: <the model that wrote the commit> <noreply@anthropic.com>" -- <paths>` (`-m` before `--`: after it, `-m` is read as a path). Several agents share one working tree and one git index: stage new files with `git add -- <paths>` and commit **only** your paths; never `git add -A`, `git add .`, `git commit -a`, a bare `git commit`, `git stash`, `git reset` of paths you did not write, or `git rm --cached -r`. Never squash, rebase or amend: `.gitleaksignore` is pinned to commit hashes, so the branch merges into `master` fast-forward only.
- **Never read, edit, move, add or commit** `docs/security/reviews/independent-audit-2026-10-04.md`, `docs/security/reviews/independent-audit-2026-10-04-poc/` or `.claude/`.
- **Docker safety:** the owner's live compose project `alice` (image `alice:dev`, volumes `alice_*`) and the owner's other local containers are never touched: no `make up`, `make down`, `make reset`, `make logs`, `make setup-token`, `make unlock`, `make hardening-check`, no `docker compose` without `-p alice-e2e`, no `docker system/volume/image prune`, no `docker rm`/`stop` of a container you did not create. Allowed: testcontainers (integration tests), `docker run --rm` throwaway containers, `docker create`/`docker cp`/`docker rm` of a container created from `alice:ci` in the same step, and the e2e project `alice-e2e` (`make e2e-up`, `make e2e`, `make e2e-down`, ports `127.0.0.1:9443` and, new in this phase, `127.0.0.1:9444` for the fake identity provider; compose builds its Alice image as `alice:e2e` with the tags `e2e testlicense`, while `alice:ci` is the release image `make image` builds). **Never run Docker test containers (integration tests, `make coverage`, `make perf`, `make test-ssh`) while Playwright runs**: Chromium aborts requests whenever a host network interface changes (`net::ERR_NETWORK_CHANGED`). Tasks marked "Docker alone" run with no other agent using Docker. The final `make ci` runs with no other Docker user at all. Every step that runs Docker says so.
- **Build machine networking:** containers on Docker's default bridge cannot reach the LAN DNS on this machine. An image build that needs the network is primed with `docker build --network host` (same Dockerfile, same tag); trivy runs as `make ci TRIVY_IMAGE="--network host aquasec/trivy:0.74.0@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969"`.
- **Helper rule (R21, R37, R38):** this plan changes **no** `alice-helper` code and no helper protocol: `helperproto.Protocol` stays `6`, `Version` stays `1.5.0`, `bin/alice-helper.sha256` does not change. Should an implementer find a helper change unavoidable, they stop and report.
- **Pinning:** build inputs are pinned by version or `sha256` digest; `go run ./tools/pincheck` (first step of `make lint`) refuses unpinned ones. The two new e2e images reuse exactly the two base images `test/images/fakeazure/Dockerfile` pins. The three new Go modules are pinned by version in `go.mod` and by hash in `go.sum` (the exact lines are in Task 12).
- **Secret rule (security-critical; SEC-037, §25.2 canaries, S-01..S-05):** the SMTP password and every OIDC client secret exist in clear only (a) in the request body that sets them (a `secretText` the handler zeroes), (b) in a `secrets.Plaintext` from `Keyring.Open` for one SMTP `AUTH PLAIN` or one token exchange, zeroed by its owner on every path. They are stored only as envelopes in `setting_secrets` (AAD `setting_secrets/<key>/ciphertext`). They never appear in a log line (any level), an API answer (the DTOs carry `has_password` / `has_client_secret` only), an error, an audit row, a job payload, an email, a trace or a test artefact. The OIDC `state` and `nonce` are stored hashed or compared in constant time and never logged; the PKCE verifier lives only in `oidc_login_states` for at most 10 minutes and is deleted with the state; authorization codes, ID tokens and access tokens are never stored or logged. CSV export files are streamed, never written to disk or kept, and Playwright deletes downloaded exports in a `finally` block. Canary tests (Task 16) prove all of this.
- **Exactly-once rule (security- and trust-critical; §26.9 exit "every alert type sends once per threshold"):** an expiry notice is queued only by the transaction that inserted its `alerts` row (`ON CONFLICT DO NOTHING RETURNING`); the unique key is `(kind, object_id, expires_at, threshold_days)`. Only the most urgent reached threshold is ever queued (catch-up); a notice for a less urgent level is never sent after a more urgent one for the same expiry instant. A changed expiry instant (renewal) starts a new series. The outbox then delivers each queued row at most once per recipient (existing `FOR UPDATE SKIP LOCKED`).
- No SQL string building (SEC-060). SQL time comes from the injected clock as a bind parameter. `alice_app` gets explicit grants for every new table; the grant guard (`migrations/roles_integration_test.go`) lists every non-default grant.
- Code blocks are gofmt-clean except for column alignment of consecutive one-line declarations and struct fields: run `gofmt -w` (or `make lint`) on every changed Go file before committing.
- Tests: Go stdlib `testing` plus testify `require`/`assert` only; small hand fakes, no mock frameworks. Integration tests carry `//go:build integration`, call `pgtest.Main` from `TestMain` and get a fresh database per test from `pgtest.New(t)` (pools `Owner` and `App`; the application always uses `App`). The performance test carries `//go:build integration && perf` and runs only through `make perf` (Task 17). A red step in a brand-new package may fail with "no non-test Go files"; that is the expected failure.
- Build tags: `integration`, `perf` (new), `e2e`, `testlicense`, `releasecheck`, `azure`. Release images are built with no tag; the e2e image with `e2e testlicense`.
- Lint is golangci-lint v2 (`make lint`): gosec, errorlint, forbidigo, bodyclose, misspell, noctx, gofmt, goimports (`local-prefixes: alice`). Forbidden: `fmt.Print*`, `strings.ToUpper`/`ToLower`/`Title` (use ASCII folding), `time.Now` outside `internal/platform/clock` and tests, `ssh.InsecureIgnoreHostKey`. `InsecureSkipVerify` appears in exactly one new place, the pinned-certificate TLS config of `internal/notify` (`pinnedTLS`), with a `//nolint:gosec // G402: …` reason like `helperproto.ProbeTLSConfig`'s: the connection is accepted only when the leaf's SHA-256 equals the pin an Administrator set. `StrictHostKeyChecking=no` anywhere fails `TestNoCodeAcceptsAnyHostKey`. No `//nolint` without a reason.
- **Module import rules** (`internal/archtest`): Task 1 adds every Phase 7 rule at once (before any new package exists): `"alice/internal/alerts/...": {platform, "alice/internal/audit/...", "alice/internal/license/...", "alice/internal/notify/..."}`, `"alice/internal/alerts/expiry": {platform}` (pure: `denied` platform/db, `deniedStd` `pureDenied`), `"alice/internal/reports/...": {platform, "alice/internal/audit/...", "alice/internal/license/...", "alice/internal/inventory/...", "alice/internal/notify/...", "alice/internal/alerts/...", "alice/internal/jobs/...", "alice/internal/rbac/..."}`, `"alice/internal/auth/oidc/claims": {platform, "alice/internal/rbac/..."}` (pure: `denied` platform/db, `deniedStd` the new `pureDeniedURL` = `pureDenied` without `net/url`), `deniedStd["alice/internal/platform/csvx"] = pureDenied`; `"alice/internal/audit/..."` is added to the `notify` rule (the mail settings write audit rows) and `"alice/internal/alerts/..."`, `"alice/internal/reports/..."` to the `api` rule. `internal/auth/oidc` is covered by the existing `auth/...` rule (it imports `auth`, `audit`, `secrets`, `rbac`, `platform`). `TestAllowed` gets positive and negative cases for each.
- API JSON conventions from Phase 1 (snake_case, UTC RFC 3339, error body `code`, `reason`, `message_key`, `message`, `request_id`, `retryable`, `params`, `details`; lists `{items, next_cursor}`); every new code `ALC-<AREA>-<NNNN>` has `errors.<reason>.title|cause|action` in `locales/common/{en,tr}.json`, a section in `docs/troubleshooting.md` and an entry in `AllErrorCodes()` (enforced by `errors_test.go` and `errors_catalogue_test.go`; Phase 7 adds `phase7Table` beside `phase6Table`). Every new route is in the route table with a permission and (for non-GET methods) a license class, in `api/openapi.yaml` with the same `x-permission`, in `docs/authz-matrix.md` (`make authz-doc`) and in the authz tests. A `PUT`/`PATCH`/`DELETE` of a setting, provider or mapping set needs a strong `If-Match` (`etag`/`ifMatch`).
- Audit detail keys pass the denylist of `internal/audit/audit.go` (segments `password`, `passphrase`, `secret`, `private`, `token`, `code`, `totp`, `otp`, `key`, `dek`, `credential`, `cookie`, `session` are refused unless the key ends in `id`, `prefix` or `count`, or is `error_code`/`reason_code`): this plan uses `host`, `port`, `tls_mode`, `from`, `username`, `auth_changed`, `ca_count`, `fingerprint`, `subject`, `to`, `result`, `reason`, `administrators`, `address_count`, `thresholds`, `days`, `public_url`, `kind`, `object_id`, `threshold_days`, `expires_at`, `locked`, `emailed`, `suppressed_count`, `target_id`, `source`, `expiry`, `q`, `os_user`, `flag`, `missing`, `format`, `provider_id`, `name`, `issuer`, `client_id`, `client_auth_replaced`, `scopes`, `groups_claim`, `ca_set`, `enabled`, `mapping_id`, `group`, `role`, `from_role`, `to_role`, `demoted_count`, `ended_count`, `method`, `minutes`, `failed_logins`; never `password_*`, `secret_*`, `client_secret*`, `token*`, `code*`, `state*`, `nonce*`, `session*`.
- i18n: every user-visible string is a key in English and Turkish (`make i18n-check`); placeholders `{{name}}` without spaces; no sentence assembly; no suffix attached to a placeholder (rephrase as "Label: {{value}}"); formal-polite Turkish ("siz"); plural forms `_one`/`_other`. Terminology (fixed for EN and TR): **Dashboard** / "Pano", **Expiring soon** / "Süresi yakında dolacaklar", **Expired** / "Süresi doldu", **Settings** / "Ayarlar", **Send test e-mail** / "Test e-postası gönder", **Trust this certificate** / "Bu sertifikaya güven", **recipients** / "alıcılar", **threshold** / "eşik", **Export** / "Dışa aktar", **saved view** / "kayıtlı görünüm", **single sign-on (SSO)** / "çoklu oturum açma (SSO)", **identity provider** / "kimlik sağlayıcı", **group mapping** / "grup eşlemesi", **SSO users may be Admin** / "SSO kullanıcıları Yönetici olabilir", **E-mails could not be sent** / "E-postalar gönderilemedi". Fingerprints, host names, issuer URLs, client IDs, group values, e-mail addresses and file paths are rendered with `<Code>`/monospace, never translated or case-transformed, always as text (A-11). Emails render times as `2006-01-02 15:04 UTC` (R42 row 10). The "UI copy" tables of the contract are exact and are what the Vitest and Playwright tests match.
- Accessibility: new screens and dialogs have no serious or critical axe violation at 640, 1280 and 1920 px (`expectAccessible`) and at 375 px for the dashboard and the settings page (`expectWide`), in English and Turkish, keyboard usable, no horizontal page scroll; tables scroll inside their own named group, as Phase 5's.
- Frontend: no `dangerouslySetInnerHTML`, no `toUpperCase`/`toLowerCase`; the SMTP password and the OIDC client secret live only in component state of their form and are cleared after the request; they are never in a query key, the query cache, `localStorage` or a log. Filters live in the URL search parameters (`useSearchParams`), so a link, a saved view and the export reproduce the list exactly.
- **Coverage floors in `coverage-floors.json` are never lowered.** New packages get floors in Task 22: `internal/alerts/expiry` 100, `internal/auth/oidc/claims` 100, `internal/platform/csvx` 100 (pure), and `internal/alerts`, `internal/reports`, `internal/auth/oidc`, `internal/testutil/fakesmtp`, `internal/testutil/fakeidp` at their measured values rounded down. Thin floors this phase touches: `internal/notify` 85, `internal/auth` 84, `internal/inventory` 89, `internal/jobs` 89, `internal/audit` 89, `internal/sshkeys` 89, `internal/api` 94, `cmd/alice` 90, `internal/rbac` 98: every line a task adds there carries its tests.
- **Parallel work:** at most three agents at once, grouped by package ownership so that two agents never edit one package (or one locale file) at the same time; the schedule is in "Task index". The locale files `locales/common/{en,tr}.json` belong to Task 6 (the `email.notify.test` text its test renders), then Task 7 (`email.license_note`, `email.license_note_kv`), then Tasks 14–15 (errors and every other email text of C14) — never two at once; `web/src/locales/{en,tr}.json` to Tasks 18–19 in sequence; a task that needs a key in a file it does not own lists it in its report and the owner adds it.
- **E2E rules:** a full page load right after the language switch cancels `PUT /auth/locale` — wait for that response before navigating; Playwright tests that download an export or read a fake's CA run with `trace: 'off'`, `video: 'off'`, `screenshot: 'off'` and delete the file in a `finally` block; the fake identity provider is reached by the browser as `https://idp.alice-e2e.test:9444` through Chromium's `--host-resolver-rules` (Task 21), never through `/etc/hosts`.

## Review Focus

1. **SSO sign-in under a hostile or broken identity provider** — an ID token with a bad signature, signed by another key, `alg=none`, `alg=HS256` keyed with the public key, an unknown `kid` (and a JWKS flood), wrong `iss`/`aud`, several audiences without `azp`, expired, `iat`/`nbf` in the future, missing/wrong/replayed `nonce`, missing/wrong/reused `state`, a replayed authorization code, a wrong PKCE verifier, an IdP error answer, an open-redirect `next`, a user in no mapped group, an Entra overage claim, a changed e-mail for a known subject, an e-mail that belongs to a local account, a local user arriving through the callback, an IdP whose discovery or JWKS is down or served over plain HTTP or with an untrusted certificate. Expected: no session in every case, one `auth.oidc.denied` row with a closed reason, a plain message on the login page, never a default role, never a link to an existing local account; the local Administrator with the authenticator code signs in while the IdP is down. Tests: Task 2 (`TestValidateRefusesEachClaim`, `TestGroupsDetectsOverage`, `TestSafeNextRefusesOpenRedirects`), Task 12 (`TestO01Signatures`, `TestO02TimesIssuerAudience`, `TestO03StateNonceAndCodeReplay`, `TestO04PKCE`, `TestO05RedirectAndNext`, `TestO06NoMappedGroup`, `TestO07Overage`, `TestO09MatchBySubjectNotEmail`, `TestO10NoLinkToLocalAccounts`, `TestO11IdPDownAndKeyRotation`, `TestO12InsecureIssuerRefused`, `TestJWKSRefetchIsRateLimited`), Task 16 (`TestOIDCNegativeSuiteOverTheWire`, `TestX05BreakGlassWhileIdPDown`).
2. **Alert emails exactly once per threshold** — hourly ticks over 70 days, a restart between ticks, two scans at once, Alice down from 31 to 13 days before expiry, thresholds edited mid-series, a renewal (new expiry instant) mid-series, a certificate replaced on its server (old one no longer in use), a Key Vault certificate also deployed to Nginx, 500 certificates crossing a threshold together, a lock, no SMTP, SMTP down for 3 hours. Expected: one notice per reached threshold and one "expired" notice per expiry instant, never a less urgent notice after a more urgent one, at most 20 emails per kind and scan plus one summary, the lock note in lock, `skipped_no_smtp` without SMTP (L-18), delivery exactly once after the outage (F-60). Tests: Task 1 (`TestHourlyTicksSendEachThresholdOnce`, `TestDowntimeSendsOnlyTheMostUrgent`, `TestThresholdEditsNeverResend`), Task 8 (`TestScanIsExactlyOncePerThreshold`, `TestDowntimeCatchUp`, `TestConcurrentScansQueueOnce`, `TestRenewalStartsANewSeriesAndReplacedIsNotMonitored`, `TestKVKindsAreScanned`, `TestEmailCapAndSummary`, `TestL28LockNote`, `TestL18NoSMTP`), Task 7 (`TestF60OutageDeliversOnceAndRaisesFailing`).
3. **Secrets of mail and SSO, and what an email can carry** — the SMTP password and the OIDC client secret in every answer, log level, audit row, error, the e-mail of a test mail, the test artefacts; a certificate CN, website name, vault name or user name with CR/LF, `{{`, HTML or a 2,000-character value; an SMTP server that echoes the password in its error. Expected: only envelopes in the database (S-04), `has_password`/`has_client_secret` in answers, `ALC-NTF-*` codes with no server text, every e-mail parameter flattened to one line and the subject never gaining a header (§17.2 "Email header injection"). Tests: Task 6 (`TestSMTPPasswordIsAnEnvelope`, which also checks that a refused password's error carries neither the password nor the server's reply), Task 7 (`TestRenderFlattensHostileParams`), Task 12 (`TestClientSecretIsAnEnvelope`), Task 14 (`TestSMTPPasswordIsWriteOnly`), Task 15 (`TestProviderSecretIsWriteOnly`), Task 16 (`TestPhase7SecretsNeverLeak`).
4. **CSV export of hostile inventory values** — cells starting with `=`, `+`, `-`, `@`, TAB or CR, quotes, commas, embedded newlines, Turkish `İ`/`ı`, a label of 100 runes, 5,000 rows, a filter by server, a filter that matches nothing, a cursor in the query, an export during a lock, an export by an Auditor and by a `read` API token. Expected: a UTF-8 BOM, the header row, exactly the rows the list shows for the same filter in the same order, every formula prefix neutralised, one `inventory.exported` audit row committed before the first byte, 409 `ALC-RPT-0001` above 50,000 rows. Tests: Task 3 (`TestSafeNeutralisesFormulaPrefixes`, `TestWriterQuotesAndBOM`), Task 10 (`TestExportEqualsTheListPages`, `TestExportAuditsBeforeTheFirstByte`), Task 16 (`TestExportOverTheWireEqualsFilteredRows`), Task 21 (export equals the filtered table, EN and TR).
5. **Who may see and change what** — Operator and Auditor sessions, `read` and `operate` API tokens of an Administrator, an Administrator without step-up, an SSO Administrator (switch on) and an SSO Operator, against every settings, SSO, mapping, dashboard, view and export route; an Admin mapping while the switch is off; switching it off while Admin mappings exist; the dashboard's role-filtered parts (audit head hash, delivery state, license detail). Expected: the matrix of the contract; settings and SSO configuration only for an Administrator with step-up; an Admin mapping 409 `ALC-SSO-0002` while off; switching off 409 `ALC-SSO-0003` while Admin mappings exist; Operators never see the head hash, the delivery state or license details; a user's views are invisible to every other user. Tests: Task 9 (`TestSummaryIsRoleFiltered`), Task 10 (`TestViewsArePrivateAndBounded`), Task 12 (`TestAdminMappingRefusedWhileOff`), Task 14 (`TestPhase7RoutesAuthz`, `TestDashboardIsRoleFiltered`), Task 15 (`TestSSORoutesAuthz`, `TestAdminMappingRefusedWhileOffOverHTTP`), Task 16 (`TestDashboardOverTheWire`, `TestSSOLoginOverTheWire`).

---
## Spec conflicts resolved by this plan (proposed R42, written in Task 22)

Each row: the conflict, the decision, why, and the cost if the decision is wrong. Task 22 writes them, corrected to the built code, as **R42** in `00-decisions.md`.

| # | Conflict | Decision | Why | Cost if wrong |
|---|---|---|---|---|
| 1 | §5.4 has no module for the alert engine or the dashboard; `notify` may not read inventory (spec digest C16) | New module `internal/alerts` (the "monitored items" SQL, the thresholds setting, the scan) with the pure `internal/alerts/expiry`; new read-only module `internal/reports` (dashboard, attention conditions, saved views, exports) that queries other modules' tables but never writes them; OIDC in `internal/auth` and `internal/auth/oidc` with the pure `internal/auth/oidc/claims`; formula-safe CSV in `internal/platform/csvx` | One owner per concern with its own floor; the dashboard and the scan share one definition of "monitored" | `reports` reads tables it does not own: a schema change in `inventory`, `jobs` or `sshkeys` must update `reports` (its integration tests seed through the owners' functions where they exist, so most drift fails a test) |
| 2 | §7.4 `alerts` is an open/resolved table with `UNIQUE (kind, subject) WHERE resolved_at IS NULL` | `alerts` is the ledger of sent expiry notices: one row per `(kind, object_id, expires_at, threshold_days)`, append-only for `alice_app`; open conditions (host key changed, sign-in refused, failed deployments, a broken audit chain, failing e-mail) are computed live by `reports.Attention` from their owners' state, whose own emails stay where they are (once per transition, R37 item 14, R38 item 15) | Exactly-once needs a key per threshold and expiry instant; a resolved flag would let a renewal and a later expiry collide; the event emails already exist and are tested | No history of resolved conditions in v1 (the audit log has the events) |
| 3 | §26.9 "expiry alert engine (certificates, KV certificates and keys, license, host key change, failed deployments, integrity problems)"; §7.4 kinds; §8.2 `alerts.evaluate` | The scan (`alerts.scan`, every 15 minutes, class `always`) sends expiry notices for four kinds: certificates in use on servers, Key Vault certificates (unless their current version is the same certificate in use on a server), Key Vault keys, and Key Vault client secrets (the date the Administrator typed, R40 item 27); license warnings stay with `license.evaluate` (R36 item 3, L-10..L-17 unchanged); host-key, sign-in, deployment, audit-chain, dead-job and rotation emails stay with their owners; the dashboard lists every kind | Each source already has its exactly-once mechanism and tests; one engine for the four expiry kinds | An administrator looks for one "alert list" and finds two places (Dashboard → Needs attention, Audit log) |
| 4 | "Monitored certificate" is undefined; every certificate ever seen stays in inventory | A certificate is monitored while it has a live location (`certificate_locations.missing_since IS NULL` on a live target); a Key Vault certificate while it is not missing and enabled; a key while it is not missing and has an expiry; a client secret while the vault is not deleted and has `secret_expires_on`. Uploaded or signing-request certificates that are on no server are listed but not monitored | A replaced certificate stays in inventory and would otherwise send an "expired" email after every renewal | An uploaded certificate kept for later use is not alerted until it is deployed (documented) |
| 5 | R2 thresholds "configurable by Admin"; catch-up (L-16 analogue, §26.9) | Setting `alerts.thresholds_days`: 1–10 different whole days from 1 to 365 (default 60, 30, 14, 7, 1), plus one notice when expired; only the most urgent reached threshold is sent, and nothing at a level for which that level or a more urgent one was sent for the same expiry instant (`expiry.Due`) | No duplicates, no backlog after downtime, edits never resend | A notice skipped by downtime is never sent (by design) |
| 6 | §26.9 "recipients … settings"; §7.6 has no key; R41 item 15 "all Administrators until Phase 7" (digest C7) | Setting `notify.recipients`: `administrators` (default true: every enabled Administrator with an e-mail address, in their language) and up to 20 extra addresses, each with a language (`en`/`tr`); it applies to **every** email Alice sends to Administrators today (`NotifyAdmins` reads it inside the caller's transaction); at least one recipient source is required | One list, read where the email is queued, so every module follows it without change | An installation that wants different lists per kind cannot have them in v1 |
| 7 | F-60 "retries … up to 24 h" vs §8.4 "notify 10" and `notify.MaxAttempts = 10` (about 2 hours; digest C1) | The outbox retries a message with backoff 30 s doubling to at most 1 hour until 24 hours after it was queued, then marks it `failed` (`notify.gave_up`); `MaxAttempts` is removed | F-60 is the specific requirement | Up to about 30 attempts per message during a long outage |
| 8 | F-60 "the notifications failing admin banner appears after 3 failures" has no state | The settings key `notify.delivery` holds the consecutive failed send attempts (any message), the last failure time and code, and the last success; three or more in a row mean "failing" (dashboard section and the Administrators' banner **E-mails could not be sent**); a success resets it | A simple, restart-safe rule; it matches owner step 4 | One bad recipient address (F-61) can raise the banner while others are delivered (the banner says to check the dashboard's last error) |
| 9 | R36 item 14 "Settings in Phase 7"; §7.6 `setting_secrets` | Mail settings are the settings key `notify.smtp` (host, port, TLS mode, sender, user name, optional CA bundle, pinned certificate, version); the password is the row `notify.smtp.password` of the new envelope table `setting_secrets` (AAD `setting_secrets/<key>/ciphertext`); `ALICE_SMTP_*` are imported once at start when no mail settings exist (audited `settings.smtp_imported`), then ignored with a warning in the log | §7.6 names the table; the Phase 2 review promised it; one envelope table for every settings secret | An operator who keeps editing `deploy/.env` after the upgrade sees no effect (the warning and the upgrade note say so) |
| 10 | SEC-037 "plaintext … if the admin explicitly acknowledges" vs R36 item 14 TLS-only; F-62 "trust this certificate" (digest C11) | TLS only (`starttls` or `tls`), TLS 1.2+, no plaintext mode; a server certificate is accepted when it verifies against the system roots plus the optional CA bundle, or when its SHA-256 equals the pinned fingerprint an Administrator chose with **Trust this certificate** — only a fingerprint Alice saw in a failed test within the last hour can be pinned; changing host or port removes the pin; emails show times in UTC with the zone (`2006-01-02 15:04 UTC`), `users.timezone` is not used (digest C17) | F-62 needs an explicit, auditable trust step; R36's TLS-only rule is the stricter, newer decision | A mail relay without TLS cannot be used; a renewed self-signed relay certificate must be trusted again |
| 11 | A-14 SSRF names the SMTP host and the OIDC issuer; R39 item 8 covers managed servers only (digest C12) | SMTP and every OIDC connection dial through `netaddr.DialContext` (link-local and metadata addresses refused; loopback and private addresses allowed); OIDC HTTP never follows a redirect | One address rule for every outbound connection an administrator configures | none known |
| 12 | Lock-mode note: §19.3 wording vs §11.6 "data may be outdated" vs L-28 "link to the license page" (digest C2) | The renderer appends `email.license_note` ("Note: Alice's license has expired. Renew it to resume automatic deployment. License page: {{license_url}}") to every expiry email queued while the license is locked, and `email.license_note_kv` (the same plus "Key Vault data may be outdated while the license is expired.") to Key Vault ones; `license_url` is the general setting `general.public_url` + `/license`, or `/license` when no address is set | §19.3 is the customer-facing wording; L-28 asks for the link | A customer without the address setting sees a path instead of a link |
| 13 | §9.6 `/dashboard/summary` "includes the daily audit head hash", visible to Operators who "cannot see the audit log" (digest C10); "daily" undefined (C9) | The summary's audit section (last checkpoint's sequence number and hash, its time, intact or broken from `jobs.audit_verify`) is shown to Administrators and Auditors only; the license section is the Operators' `expired` flag and the phase, days and end for Administrators and Auditors (R36 item 12); the delivery section to Administrators only | R3 and R36 item 12 role rules | none known |
| 14 | §26.9 "dashboard (expiring soon, failed deployments, targets by status, license status, rotation upcoming)"; §20.2 backup age; §18.5 checklist (digest C22) | `GET /api/v1/dashboard/summary` and `GET /api/v1/dashboard/expiring` as in C13; buckets are exclusive (expired, within 7, 8–30, 31–60 days); failed deployments are those with status `failed`, `rolled_back`, `rollback_failed` or `needs_attention` whose `coalesce(finished_at, created_at)` is within 7 days; rotation upcoming is enabled policies due within 14 days plus running and needs-attention runs; no backup age (Phase 8 builds backups) and no "finish setting up" checklist (Phase 8 wizard) | The five widgets of §26.9 with exact, testable definitions | none known |
| 15 | §26.9 "filters and saved views" have no model (digest C21) | Saved views are private to their user, for the pages `certificates` and `ssh_keys`, at most 50 per user, a name of 1–60 runes unique per user and page (case-insensitive), the query an allow-listed map of that page's filter parameters; table `saved_views`; no audit row (a personal UI preference) | The smallest model that makes owner step 3 repeatable | Teams cannot share views in v1 |
| 16 | §9.4 "inventory export" route undefined; §15.4 "Export inventory: all roles"; SEC-075 for audit only (digest C20) | `GET /api/v1/certificates/export` and `GET /api/v1/ssh-keys/export`, CSV only, UTF-8 with BOM, the list's filter parameters (no cursor, no limit), permission `read` (all roles and `read` tokens), 10 per minute per identity, one `inventory.exported` audit row committed before the first byte, at most 50,000 rows (409 `ALC-RPT-0001` before any byte otherwise; the rows are read into memory first, so an export is never cut short), available in lock; machine-readable English column names | An export must be the list; the audit export's pattern | A strict reader that expects localized headers gets English ones |
| 17 | S2 AC2 "filters by expiry window, target and source (Nginx, Key Vault, uploaded)"; the certificate list accepts `expired|30|60` and three sources | `expiry` accepts `expired`, `7`, `14`, `30`, `60`, `90` (a window includes expired ones, as today) and `source` also `azure_kv` | Owner step 3 and S2 | none known |
| 18 | §9.2 `GET /auth/oidc/{provider}/start`; A-06 "GET requests never change state" | `POST /api/v1/auth/oidc/{id}/start` (JSON answer `{authorize_url}` plus the binding cookie) and `POST /api/v1/auth/oidc/stepup`; the callback stays `GET /api/v1/auth/oidc/{id}/callback` (the protocol requires it) and is the one documented exception of `TestA06GETRoutesNeverChangeState` (it consumes a state row, may create a session and writes exactly one audit row) | A-06 holds for every route the SPA calls | none known |
| 19 | §7.1 `oidc_providers` lacks the groups claim, CA bundle, endpoints and redirect URI; `sso.allow_admin_role` is global; `priority` vs "highest mapped role" (digest C14) | `oidc_providers` adds `groups_claim` (default `groups`), `ca_pem`, the three endpoints read by discovery **at configuration time** (and on **Refresh**), `version`; the client secret lives in `setting_secrets` (`sso.provider.<id>.client_secret`); the redirect URI is `general.public_url` + `/api/v1/auth/oidc/<id>/callback` (an address is required before a provider can be enabled); one global switch `sso.allow_admin_role` (default off); mappings have no priority: the highest mapped role wins; at most 5 providers and 200 mappings per provider | SEC-013 fixes endpoints at configuration time; AD FS often needs a private CA; SEC-014 says "highest" | A provider that moves its endpoints needs **Refresh** |
| 20 | O-07 "resolves via the Graph endpoint if configured" | No Graph lookup in v1: an overage claim (`_claim_names` naming the groups claim, or `hasgroups`) denies the sign-in with `ALC-SSO-0007`, whose action text explains Entra's "groups assigned to the application" option | Graph needs another token, permission and outbound host (air-gapped customers) | Tenants whose users have more than 200 groups must emit application groups only |
| 21 | O-08 "re-evaluated at 15-minute refresh or end at the session limit"; SEC-014 "at next login" (digest C13) | The role is recomputed at every SSO sign-in (written to `users.role`, which every session reads at once); a refused SSO sign-in of a known user (no mapped group, overage, disabled provider) ends all of that user's sessions; otherwise sessions end at their normal limits (30 minutes idle, 12 hours); no refresh tokens are kept | No token storage, the documented branch of O-08 | A group removed at the IdP keeps working in an open session for up to 12 hours unless the user signs in again or an Administrator disables them |
| 22 | SEC-009 "step-up … still applies to them [OIDC users]" with no local TOTP | An SSO user's step-up is a fresh sign-in at the IdP (`prompt=login`, `max_age=0`): the callback accepts it only for the same issuer and subject as the session's user and an `auth_time` at most 5 minutes old, then opens the session's step-up window | The IdP owns the user's MFA (R10) | An IdP that ignores `prompt=login` and sends an old `auth_time` makes step-up fail (clear message) |
| 23 | O-10 "a local user tries to be linked by an IdP with the same e-mail … denied"; SEC-015 | An SSO identity is never linked to a local account; a first SSO sign-in whose e-mail belongs to a local user is refused (`ALC-SSO-0008`); a local user can never sign in through the callback (matching is by `(oidc_issuer, oidc_subject)` only); SSO users have no password and no local MFA, cannot be the break-glass account, and their role, password and MFA cannot be changed by hand (`ALC-USR-0003`; disable and enable still work) | No account takeover by e-mail; SEC-015 | An organisation migrating a person from local to SSO deletes or renames the local account first |
| 24 | §25.5 O-13 "a mapping that would grant Admin to all users (empty group value) is rejected" | Every mapping needs a non-empty group value without control characters (at most 256 runes); switching **SSO users may be Admin** off is refused while Admin mappings exist (`ALC-SSO-0003`); switching it off demotes every SSO Administrator to Auditor and ends their sessions (their next sign-in recomputes the role); every mapping change and the switch need step-up | No silent privilege left behind; least privilege on the way down | none known |
| 25 | SEC-020 "lockout events … notify Admins (… Phase 7)"; R39 item 15 | The lockout transaction queues `auth.lockout` (user name, minutes) through `NotifyAdmins` | Spec | A lockout storm sends one email per account per block (bounded by the 15-minute block) |
| 26 | §26.9 performance test "on the CI runner" | `make perf` runs `TestR32DashboardAndListBudgets` (`-tags 'integration perf'`) against a seeded database (5,000 monitored certificates on 500 targets, 500 deployments, 5,000 audit rows); p95 over 100 measured requests after 10 warm-up requests; whether `make ci` runs it is decided in Task 22 from three runs on this machine (a ruling records the times) | A budget that flakes would block every PR | If it stays outside `make ci`, a regression is caught only when someone runs `make perf` (the release checklist lists it) |
| 27 | The scheduled audit chain verification (§26.9) exists since Phase 3 (`audit.verify`); external anchors (SEC-073 syslog, a keyed chain) promised "with Phase 7" by the Phase 3 review | The daily verification is unchanged; Phase 7 adds its result and the last checkpoint's head hash to the dashboard (R16) and the broken-chain condition to "Needs attention"; syslog forwarding and a keyed chain are re-deferred to Phase 8 (Carries row 17) | A chain format change needs a migration of existing chains and the backup verification Phase 8 builds | Whoever holds `alice_app` can still append rows that verify and suppress the `audit.broken` email until Phase 8 (unchanged known limitation) |
| 28 | Error areas | New area `ALC-SSO-0001..0016`, `ALC-RPT-0001..0003`; `ALC-NTF-0002..0009`; `ALC-USR-0003` | §9.3 | — |
| 29 | `/api/v1/settings/*` reads are `settings.manage` (Administrator, step-up) by the existing route rule | Kept for every new settings route; the Settings page asks for the authenticator code when it opens (StepUpProvider) | §15.4 "settings: Admin only", SEC-009 | One more code prompt per visit |
| 30 | The retired-key retention (R41 item 23) and Alice's own address have no settings home | The general settings key `general` holds `public_url` (an `https://` origin, used by emails and SSO) and `retired_key_retention_days` (1–3650, default 30), read through `settings.GetGeneral` | One small typed record | none known |

## Carries and deferred items

| # | Carry | Decision | Where |
|---|---|---|---|
| 1 | Certificate private-key download (§9.6; R41 item 6; Phase 6 carry 11) | **Re-deferred to Phase 8** (no §26.9 deliverable; needs the format decision for TLS keys — encrypted PKCS #8 or PFX — and its own S-09 suite); cost: a TLS key Alice holds still cannot be taken out | — |
| 2 | Notification recipients as a setting (Phase 6 [15], known limitation) | **Included** (`notify.recipients`, R42 row 6) | Tasks 7, 14, 19 |
| 3 | The 30-day retired-key retention as a setting (Phase 6 [23], known limitation) | **Included** (`general.retired_key_retention_days`; `sshkeys.DestroyRetiredKeys` reads it, the constant stays as the default) | Tasks 10, 14, 19 |
| 4 | The extra query per certificate in a Key Vault poll (`internal/inventory/kv_store.go:404`; Phase 5 parked, Phase 6 carry 7) | **Included**: the batch read of stored versions also selects `certificate_id IS NULL`, the per-certificate query goes; a query-counting tracer test pins it | Task 10 |
| 5 | Client-secret and key expiry emails (R40 item 27, §11.1, §11.3) | **Included** (kinds `kv_credential_expiry`, `kv_key_expiry`) | Task 8 |
| 6 | Phase 5 settings items: HTTPS proxy and CA bundle for Azure (R40 item 7), deployment windows (R40 item 31), wave limits (R40 item 20), sovereign clouds | **Re-deferred (v1.x, §3.2)**: none is a §26.9 deliverable; each touches the Azure provider (floor 98) or the planner; the costs of R40 items 7, 20 and 31 stay | — |
| 7 | Real-Azure items (`make test-azure`, `make record-azure`, `TestRealAzureReaderSufficiency`) | **Owner only**, unchanged | — |
| 8 | Phase 6 known limitation "scheduled rotation needs working email delivery" | **Unchanged rule; eased**: mail is now configured in Settings with a test button, and failing delivery is visible on the dashboard; the admin guide says so | Task 22 |
| 9 | `facts.nginx.scanned_at` (Phase 4) | **Re-deferred**: the dashboard uses `targets.last_discovery_at`; no Phase 7 screen needs it | — |
| 10 | Cross-server locations list (Phase 4) | **Closed in Phase 5** (`GET /api/v1/certificate-locations`); nothing to do | — |
| 11 | E2E hooks for the route error page, the `unverified` banner and the locale fallback (audit remediation) | **Re-deferred**: Vitest covers them; Phase 7 touches none of them | — |
| 12 | Uncoalesced inventory refusal rows (carry 12) | **Re-deferred**; the new `auth.oidc.denied` rows follow the same uncoalesced pattern, bounded by the sign-in rate limit (10 per minute per address) | — |
| 13 | Recovery codes lost with the completing answer (Phase 4, audit remediation) | **Re-deferred** (the local MFA flow is unchanged) | — |
| 14 | Lockout notification email (SEC-020, R35, R39 item 15) | **Included** (R42 row 25) | Tasks 11, 14 |
| 15 | SMTP from Settings instead of `ALICE_SMTP_*`; the password in `setting_secrets` (R36 item 14, P2-03) | **Included** (R42 rows 9–10) | Tasks 5, 6, 13 |
| 16 | L-28 and L-18 with real alerts (Phase 2 carry) | **Included** | Task 8 |
| 17 | Keyed audit chain, syslog/SIEM forwarding (SEC-073), the app-writable `jobs.audit_verify` (Phase 3 review "fixed together in Phase 7") | **Re-deferred to Phase 8** (R42 row 27); the dashboard shows the head hash for offline recording (R16) meanwhile | — |
| 18 | SSH limits and `ssh.max_parallel` (R37 item 17), `nginx.backup_retention_days` (R38 item 14) as settings | **Re-deferred (v1.x)**: constants stay, documented | — |
| 19 | The dead-task email of a manual Test connection merged into a live re-test (Phase 4 carry 9) | **Re-deferred** (unrelated to Phase 7's engine; the UI shows the failure) | — |
| 20 | `users.timezone` UI for the dashboard (Phase 1 plan) | **Re-deferred**: the web shows times in the browser's zone (§10.4 default), emails in UTC (R42 row 10) | — |
| 21 | SMTP as a wizard step (§18.5 step 5) | **Phase 8** (§26.10 "wizard steps complete"); Settings covers it now | — |
| 22 | Phase 6 parked items (F1–F4, L1–L13, N2, N15–N17, I-5, D22–D28, FB-4, FB-7, P6-28, the property schedules, the web minors) | **Re-deferred, unassigned**: no Phase 7 deliverable touches rotation | — |
| 23 | Phase 5 parked items and limitations (`kv.credential_unreadable` paths, disabled-vault wording, a held import blocking its name, the limiter counting attempts, a failing detail read discarding a listing, the one-vault fake) | **Re-deferred** | — |
| 24 | Nginx helper items (an unreadable journal, the dropped-certificate warning, a TLS block without `ssl` listen, host-name listens) | **Re-deferred** (no helper change) | — |
| 25 | Helper scans per key change (carry 4), lockfile secret scanning, `osv-scanner`, the real-systemd job, a nightly pipeline, mutation testing, packaging | **Re-deferred to Phase 8** | — |
| 26 | Owner items: a git remote and the first workflow run, the production license key, the walkthroughs of Phases 1–6 and the remediation, the real-Azure suite, the Turkish tone review, the crypto sign-off, a clean-machine `make ci` | **Owner only**; Phase 7 adds its own walkthrough table (§26.9 owner steps 1–5) | Task 22 |

## Spec coverage map (§26.9)

| §26.9 item | Task(s) | Test(s) |
|---|---|---|
| Expiry alert engine: certificates, KV certificates and keys | 1, 8 | `TestDueTable`, `TestScanIsExactlyOncePerThreshold`, `TestKVKindsAreScanned` |
| … license, host key change, failed deployments, integrity problems | 9 (conditions), existing owners | `TestAttentionConditions`, the existing `license`, `inventory`, `jobs` email tests (unchanged) |
| Recipients and thresholds settings | 7, 8, 14, 19 | `TestRecipientsSettingDecidesEveryEmail`, `TestThresholdSettings`, `SettingsPage.test.tsx` |
| Email templates EN and TR incl. the "license expired" note | 6, 7, 8, 14 | `TestAlertAndAuthTemplatesRenderInBothLanguages`, `TestRenderAddsTheLicenseNote`, `TestL28LockNote` |
| Deduplication and retries | 1, 7, 8 | `TestConcurrentScansQueueOnce`, `TestRetriesLastTwentyFourHours` |
| Dashboard (expiring soon, failed deployments, targets by status, license status, rotation upcoming) | 9, 14, 18 | `TestSummaryCountsMatchTheDatabase`, `DashboardPage.test.tsx` |
| Filters and saved views | 10, 14, 18 | `TestViewsArePrivateAndBounded`, `CertificatesPage.test.tsx` (URL filters), `SavedViews.test.tsx` |
| CSV export of inventory | 3, 10, 14, 18 | `TestExportEqualsTheListPages`, `TestExportOverTheWireEqualsFilteredRows` |
| Scheduled audit chain verification | (Phase 3) + 9, 18 | `TestAuditVerifyTaskTicksHourlyAndVerifiesOncePerDay`, `TestAuditVerifyTaskAlertsOncePerBreak` (unchanged), `TestSummaryAuditHead`, `TestReadAuditVerifyState` |
| OIDC SSO (Entra ID, AD FS, Keycloak), group-to-role mapping, "SSO users may be Admin" default off, MFA delegated | 2, 11, 12, 15, 19 | `TestResolveRoleCapsAdmin`, `TestSignInOIDCProvisionsAndMatchesBySubject`, `TestAdminMappingRefusedWhileOff`, `LoginPage.test.tsx` |
| Tests: alert thresholds with the fake clock; no duplicates; catch-up after downtime | 1, 8 | `TestHourlyTicksSendEachThresholdOnce`, `TestDowntimeSendsOnlyTheMostUrgent` |
| F-60..F-63 | 6, 7, 16 | `TestF60OutageDeliversOnceAndRaisesFailing`, `TestF60OverTheWire`, `TestF61PerRecipient`, `TestF62UntrustedCertificateAndThePin`, `TestTestMailSendsThroughTheSettingsAndTheTrust` (F-62), `TestSMTPPasswordIsAnEnvelope` and `TestMailSettingsOverTheWire` (F-63) |
| L-28, L-18 | 8 | `TestL28LockNote`, `TestL18NoSMTP` |
| Dashboard API tests with seeded data (exact counts) | 9, 16 | `TestSummaryCountsMatchTheDatabase`, `TestDashboardOverTheWire` |
| Vitest for dashboard widgets and filters | 18 | `DashboardPage.test.tsx`, `CertificatesPage.test.tsx`, `SSHKeysPage.test.tsx` |
| E2E EN/TR: seeded counts, a filter narrows, an expiring certificate's e-mail in the fake SMTP, export = filtered rows | 13, 20, 21 | `web/e2e/phase7.spec.ts` |
| OIDC negative suite O-01..O-14, X-05 | 2, 12, 16 | `TestO01Signatures`, `TestO02TimesIssuerAudience`, `TestO03StateNonceAndCodeReplay`, `TestO04PKCE`, `TestO05RedirectAndNext`, `TestO06NoMappedGroup`, `TestO07Overage`, `TestO08GroupRemovedEndsSessions`, `TestO09MatchBySubjectNotEmail`, `TestO10NoLinkToLocalAccounts`, `TestO11IdPDownAndKeyRotation`, `TestO12InsecureIssuerRefused`, `TestAdminMappingRefusedWhileOff` (O-13), `TestO14LocalMFANotBypassed`, `TestOIDCNegativeSuiteOverTheWire`, `TestX05BreakGlassWhileIdPDown` |
| E2E SSO login with the fake IdP in EN and TR | 20, 21 | `web/e2e/phase7.spec.ts` |
| Performance (R32): 5,000 certificates, 500 targets; dashboard p95 < 500 ms, lists p95 < 300 ms | 17, 22 | `TestR32DashboardAndListBudgets` (`make perf`) |
| Owner verification steps 1–5 | 22 | walkthrough table in `docs/security/reviews/phase-7.md` (empty, owner's) |
| Exit: every alert type once per threshold; dashboard numbers match the database; SSO and its negative tests; performance budget | 8, 9, 12, 16, 17, 22 | security review |

---

## File Structure

```
internal/alerts/expiry/                    expiry.go (Normalize, Level, Due, DaysLeft, BucketOf, Horizon); tests (Task 1)
internal/archtest/arch_test.go             Phase 7 rules and TestAllowed cases (Task 1)
internal/auth/oidc/claims/                 claims.go (Claims, Parse, Expect, Validate, Error, Reason*), groups.go (Groups,
                                           ErrOverage, Mapping, ResolveRole, ValidateMapping), urls.go (SafeNext,
                                           ValidateIssuer, Username); tests, FuzzParse (Task 2)
internal/platform/csvx/                    csvx.go (Safe, Writer, NewWriter); tests (Task 3)
internal/api/audit_handlers.go             uses csvx (Task 3)
internal/testutil/fakesmtp/                server.go (Server, Options, Start, New, Message, Down, Up, RejectRecipient),
                                           mailhog.go (Handler: MailHog v2 message API); tests (Task 4)
internal/testutil/fakeidp/                 server.go (Server, Options, Start, New, Login, NextLogin, Fault, SetFault,
                                           RotateKey, Down, Up, Stats, Authorize), tokens.go; tests (Task 4)
migrations/00011_alerts_dashboard_sso.sql  alerts, setting_secrets, saved_views, oidc_providers, oidc_group_mappings,
                                           users.oidc_*, oidc_login_states, grants, Down guard Z1015 (Task 5)
internal/platform/settings/general.go      General, GetGeneral, GeneralKey (Task 6)
internal/notify/                           settings.go, secrets.go, smtpsettings.go, testmail.go, pin.go, envimport.go,
                                           source.go (Task 6); delivery.go, recipients.go, sender.go, outbox.go,
                                           general.go (Task 7)
internal/alerts/                           service.go, monitored.go (the one SQL definition), scan.go, thresholds.go,
                                           templates.go (Task 8)
internal/testutil/seed/                    Target, Certificate, MoveLocations, KeyVault (Task 8), Deployment (Task 9)
internal/reports/                          service.go, summary.go, attention.go (Task 9); export.go, views.go (Task 10)
internal/audit/checkpoint.go               LastCheckpoint (Task 9); audit.go ActorOIDC (Task 11)
internal/jobs/auditverify.go               ReadAuditVerifyState (Task 9); types.go AlertsScan (Task 13)
internal/inventory/                        certificates.go (expiry windows, azure_kv source), kv_store.go (carry 4) (Task 10)
internal/sshkeys/destroy.go                retention from settings.GetGeneral (Task 10)
internal/auth/                             oidc_users.go, lockout.go, users.go, service.go, sessions.go (Task 11)
internal/auth/oidc/                        service.go, providers.go, discovery.go, keyset.go, httpclient.go, mappings.go,
                                           settings.go, login.go, states.go (Task 12)
go.mod, go.sum                             go-oidc v3.21.0, x/oauth2 v0.37.0, go-jose v4.1.5 (Task 12)
cmd/alice/                                 services.go, wiring.go, main.go, testapi_e2e.go, testapi_release.go (Task 13);
                                           compose_test.go (Task 20)
Makefile                                   E2E_SYMBOLS (Task 13), perf (Task 17)
internal/rbac/rbac.go                      sso.manage (Task 15)
internal/api/                              settings_handlers.go, dashboard_handlers.go, views_handlers.go,
                                           export_handlers.go, phase7_dto.go, errors.go, server.go, guard.go (Task 14);
                                           sso_handlers.go, oidc_handlers.go (Task 15); integration suites (Task 16);
                                           perf_integration_test.go (Task 17)
api/openapi.yaml, docs/authz-matrix.md     new operations (Tasks 14–15)
locales/common/{en,tr}.json                email.notify.test (Task 6), the license notes (Task 7), error texts and the other
                                           email texts (Tasks 14–15)
web/src/                                   pages/DashboardPage, components/dashboard/*, components/NotificationsBanner,
                                           components/SavedViews, components/ExportButton, hooks/useUrlFilters,
                                           CertificatesPage, SSHKeysPage, audit and job labels (Task 18); pages/SettingsPage,
                                           components/settings/*, components/sso/*, LoginPage, StepUpProvider, UsersPage (Task 19)
cmd/alice-fakesmtp/, cmd/alice-fakeidp/    e2e fakes (Task 20)
test/images/fakesmtp/, test/images/fakeidp/  Dockerfiles (Task 20)
deploy/docker-compose.e2e.yml              services fakesmtp, fakeidp (Task 20)
deploy/dev/check-hardening.sh              their blocks (Task 20)
web/e2e/phase7.spec.ts, web/e2e/helpers.ts EN/TR journeys (Task 21)
docs/                                      admin-guide.md, operator-guide.md, troubleshooting.md, first-run.md,
                                           security/reviews/phase-7.md, superpowers/rulings/phase-7.md, R42, CHANGELOG,
                                           coverage floors (Task 22)
```

Task order is bottom-up: pure packages (1–3), test fakes (4), schema (5), mail (6–7), alerts (8), reports (9–10), auth and OIDC (11–12), wiring (13), HTTP (14–16), performance (17), web (18–19), e2e images (20), end-to-end (21), documentation and verification (22). Each task leaves the repository green (`make lint`, `make test`, the integration packages it touches, `make web-test` and `make i18n-check` where it touches the web).

### Task index

1. `internal/alerts/expiry`: thresholds, the due notice, catch-up, buckets; Phase 7 archtest rules
2. `internal/auth/oidc/claims`: claim validation, groups and overage, role resolution, mapping rules, safe `next`, issuer, user names; `FuzzParse`
3. `internal/platform/csvx`: formula-safe CSV with BOM; the audit export moves onto it
4. Test fakes: `internal/testutil/fakesmtp` (MailHog-compatible API) and `internal/testutil/fakeidp` (discovery, JWKS, authorize, token, faults)
5. Migration `00011_alerts_dashboard_sso.sql`
6. `internal/notify` part 1: mail settings, `setting_secrets`, the mailer source, CA bundle and pinning, the test mail, the env import; `settings.GetGeneral`
7. `internal/notify` part 2: 24-hour retries, the delivery state and "failing", recipients, `NotifyAdmins` follows them, the license note in rendering, general settings
8. `internal/alerts`: monitored items, thresholds setting, the scan (four kinds, lock note, cap and summary), templates
9. `internal/reports` part 1: dashboard summary, expiring list, attention conditions; `audit.LastCheckpoint`, `jobs.ReadAuditVerifyState`
10. `internal/reports` part 2: CSV exports, saved views; inventory filters; the Key Vault poll carry; the retention setting in `sshkeys`
11. `internal/auth`: SSO users (`SignInOIDC`, `StepUpOIDC`, `RefuseOIDC`, demotion), SSO-user rules, `audit.ActorOIDC`, the lockout email
12. `internal/auth/oidc`: providers and discovery, the bounded key set, mappings and the Admin switch, `Begin`/`Complete`, state pruning; O-01..O-14 at service level; go.mod
13. Jobs and wiring: `alerts.scan`, the mailer source in `serve`, the env import, services, `POST /test/seed/dashboard`, reset, `E2E_SYMBOLS`
14. API part 1: settings, notifications status, alerts, dashboard, views, exports; limits; codes, email texts, OpenAPI, authz
15. API part 2: `sso.manage`, SSO administration, the OIDC sign-in and step-up routes, cookies, codes, OpenAPI, authz, the A-06 exception
16. API integration: dashboard exact counts, export equals rows, F-60..F-63 over the wire, the O-suite and X-05 over the wire, the Phase 7 secret-leak suite, A-06
17. Performance test (R32) and `make perf`
18. Web part 1: Dashboard, the failing banner, filters in the URL, saved views, Export; every Phase 7 audit and job label
19. Web part 2: Settings (mail, recipients, alerts, general), SSO administration, SSO sign-in, SSO step-up, Users
20. E2E images: `cmd/alice-fakesmtp`, `cmd/alice-fakeidp`, Dockerfiles, compose services, hardening checks, compose tests
21. End-to-end: Phase 7 journeys in EN and TR, accessibility (**Docker alone**)
22. Coverage floors, documentation, R42, security review, rulings, CHANGELOG, `make ci` (**Docker alone**)

**Schedule (at most three agents; package ownership):**

| Wave | Agent A | Agent B | Agent C | Docker |
|---|---|---|---|---|
| 1 | Task 1 → Task 3 (`archtest`, `alerts/expiry`, `platform/csvx`, `internal/api/audit_handlers.go` and its test) | Task 2 → Task 4 (`auth/oidc/claims`, `testutil/fakesmtp`, `testutil/fakeidp`) | Task 5 (`migrations`) | C uses testcontainers |
| 2 | Task 6 → Task 7 → Task 8 (`platform/settings`, `notify`, `alerts`) | Task 11 (`auth`, `audit/audit.go`; after Task 5) → Task 12 (`auth/oidc`, `go.mod`, `go.sum`; after Task 4) | Task 18 (`web/src`; msw against C13) | testcontainers only |
| 3 | Task 9 → Task 10 (`reports`, `audit/checkpoint.go`, `jobs/auditverify.go`, `inventory`, `sshkeys`; Task 9 starts after Tasks 8 and 11 are committed — Task 11 is the other writer of package `audit`) | Task 12 (continued) | Task 19 (`web/src`, after Task 18) | testcontainers only |
| 4 | Task 13 (`jobs/types.go`, `cmd/alice`, `Makefile`; after Tasks 10 and 12) | — | — | testcontainers only |
| 5 | Task 14 → Task 15 (`rbac`, `api`, `api/openapi.yaml`, `docs/authz-matrix.md`, `docs/troubleshooting.md`, `locales/common`, `internal/notify/render_test.go`, the `newAPIDeps` line of `cmd/alice/main.go`) | — | — | testcontainers only |
| 6 | Task 16 → Task 17 (`internal/api` integration tests, `Makefile` target `perf`) | Task 20 (`cmd/alice-fakesmtp`, `cmd/alice-fakeidp`, `test/images/fakesmtp`, `test/images/fakeidp`, `deploy/docker-compose.e2e.yml`, `deploy/dev/check-hardening.sh`, `cmd/alice/compose_test.go`, `internal/archtest/buildtags_test.go`; after Task 15, the last other writer of `cmd/alice`) | — | testcontainers and B's image builds (no Playwright anywhere); Task 17's `make perf` runs when B is not building |
| 7 | Task 21 (`web/e2e`) | — | — | **Docker alone** (Playwright; no testcontainers anywhere) |
| 8 | Task 22 (docs, floors, `make coverage`, `make perf`, `make ci`) | — | — | **Docker alone** (no other Docker user at all) |

Web Tasks 18–19 compile against the DTOs of C13 with msw; their own tests never need the server. Task 21 needs every other task.

Recommended execution: subagent-driven, one reviewer per task, an additional security reviewer on Tasks 2, 5, 6, 7, 8, 11, 12, 15 and 16. Tasks 1–3, 6–7, 9–10 and 14–15 each keep one implementer.

---
## Cross-task contract

Every task's **Interfaces** block repeats the parts of this contract it consumes or produces. When a task and this section disagree, this section wins and the task is a plan defect to fix at execution time (record it in the task's report).

### C1. Names

| Kind | Name | Value / meaning |
|---|---|---|
| Package | `alice/internal/alerts/expiry` | pure due-notice rules (Task 1) |
| Package | `alice/internal/auth/oidc/claims` | pure ID-token claim rules (Task 2) |
| Package | `alice/internal/platform/csvx` | pure formula-safe CSV (Task 3) |
| Package | `alice/internal/testutil/fakesmtp`, `alice/internal/testutil/fakeidp` | test fakes (Task 4) |
| Package | `alice/internal/alerts` | the expiry alert module (Task 8) |
| Package | `alice/internal/reports` | read-only dashboard, conditions, views, exports (Tasks 9–10) |
| Package | `alice/internal/auth/oidc` | providers, mappings, sign-in flow (Task 12) |
| Periodic task | `alerts.scan` (`jobs.AlertsScan`) | class `always`; every 15 minutes (e2e: never; `POST /test/scheduler/run`); `alerts.Service.Scan` |
| Periodic task (existing) | `maintenance.cleanup` | also `oidc.Service.PruneStates` (Task 13) |
| Permission | `sso.manage` (`rbac.SSOManage`) | Administrator, browser session, step-up; no API token |
| Permission (existing) | `settings.manage` | every `/api/v1/settings/*` route |
| Permission (existing) | `read` | dashboard, alerts, notifications status, exports |
| Permission (existing) | `session` | saved views; `POST /api/v1/auth/oidc/stepup` |
| Permission (existing) | `public` | `GET /api/v1/auth/oidc/providers`, `POST /api/v1/auth/oidc/{id}/start`, `GET /api/v1/auth/oidc/{id}/callback` |
| Rate limit | `limitTestMail` | 5 per minute per user (`"u:" + Principal.UserID`), besides the general limit |
| Rate limit | `limitExport` | 10 per minute per identity (user or token), besides the general limit |
| Rate limit (existing) | `limitLogin` | the OIDC start and callback (10 per minute per address) |
| Rate limit (existing) | `limitMFA` | the OIDC step-up start |
| Cookie | `__Host-alice_oidc` | the OIDC binding value (32 random bytes, base64url), `HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600`; cleared by the callback |
| Settings key | `notify.smtp` | mail settings (C7) |
| Settings key | `notify.recipients` | recipients (C7) |
| Settings key | `notify.delivery` | the delivery state (C7) |
| Settings key | `notify.smtp_seen_cert` | the certificate a failed test saw (C7) |
| Settings key | `alerts.thresholds_days` | thresholds (C8) |
| Settings key | `general` | `public_url`, `retired_key_retention_days` (C7) |
| Settings key | `sso.allow_admin_role` | the switch (C11) |
| Secret key | `notify.smtp.password`, `sso.provider.<uuid>.client_secret` | rows of `setting_secrets` |
| Constant | `expiry.DefaultThresholds` | `[]int{60, 30, 14, 7, 1}` |
| Constant | `alerts.ScanEvery` | `15 * time.Minute` |
| Constant | `alerts.MaxEmailsPerScan` | `20` per kind and scan, then one summary email |
| Constant | `notify.GiveUpAfter` | `24 * time.Hour` |
| Constant | `notify.FailingAfter` | `3` consecutive failed attempts |
| Constant | `notify.MaxExtraRecipients` | `20` |
| Constant | `notify.TestMailTimeout` | `30 * time.Second` |
| Constant | `notify.SeenCertValidFor` | `time.Hour` |
| Constant | `oidc.StateLifetime` | `10 * time.Minute` |
| Constant | `oidc.StepUpMaxAge` | `5 * time.Minute` |
| Constant | `oidc.HTTPTimeout` | `10 * time.Second` |
| Constant | `oidc.MaxProviders`, `oidc.MaxMappings` | `5`, `200` per provider |
| Constant | `oidc.JWKSRefetchEvery` | `time.Minute` (an unknown `kid` refetches at most once per minute) |
| Constant | `oidc.MaxResponseBytes` | `1 << 20` (discovery, JWKS and token answers) |
| Constant | `claims.Leeway` | `60 * time.Second` |
| Constant | `reports.MaxExportRows` | `50000` (rows are read before the first byte, so an export is all or nothing; 5,000 certificates is the R32 scale) |
| Constant | `reports.MaxViewsPerUser` | `50` |
| Constant | `reports.FailedWindow`, `reports.RotationWindow` | `7 * 24 * time.Hour`, `14 * 24 * time.Hour` |

### C2. Database (migration `00011_alerts_dashboard_sso.sql`, Task 5)

```sql
-- +goose Up
-- Phase 7: alerts, dashboard, saved views and OpenID Connect single sign-on (spec §7.1, §7.4, §7.6, §15.3,
-- §26.9; R42). Same conventions as 00006-00010: closed lists for values Alice owns, format checks for names,
-- no clock defaults.

-- The ledger of sent expiry notices (R42 rows 2-5). One row per kind, object, expiry instant and threshold
-- (0 = expired): the transaction that inserts the row is the only one that queues its email, so a notice is
-- queued once even when two scans run at once. Append-only for the application.
CREATE TABLE alerts (
    id             uuid PRIMARY KEY,
    kind           text NOT NULL CHECK (kind IN ('certificate_expiry', 'kv_certificate_expiry', 'kv_key_expiry',
                                                  'kv_credential_expiry')),
    object_id      uuid NOT NULL,
    subject        text NOT NULL CHECK (char_length(subject) BETWEEN 1 AND 300),
    expires_at     timestamptz NOT NULL,
    threshold_days integer NOT NULL CHECK (threshold_days BETWEEN 0 AND 365),
    license_locked boolean NOT NULL,
    emailed        boolean NOT NULL,
    created_at     timestamptz NOT NULL,
    UNIQUE (kind, object_id, expires_at, threshold_days)
);
CREATE INDEX alerts_created ON alerts (created_at DESC, id DESC);

-- Envelope secrets of settings (§7.6; R42 rows 9 and 19): the SMTP password and the client secret of each
-- identity provider. AAD setting_secrets/<key>/ciphertext. Nothing else may be stored here.
CREATE TABLE setting_secrets (
    key         text PRIMARY KEY CHECK (key ~ '^(notify\.smtp\.password|sso\.provider\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.client_secret)$'),
    ciphertext  bytea NOT NULL,
    nonce       bytea NOT NULL CHECK (octet_length(nonce) = 12),
    wrapped_dek bytea NOT NULL,
    key_version integer NOT NULL CHECK (key_version >= 1),
    updated_at  timestamptz NOT NULL
);

-- Personal saved views (R42 row 15): private to their user, two pages, names unique per user and page.
CREATE TABLE saved_views (
    id         uuid PRIMARY KEY,
    user_id    uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    page       text NOT NULL CHECK (page IN ('certificates', 'ssh_keys')),
    name       text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 60),
    query      jsonb NOT NULL CHECK (jsonb_typeof(query) = 'object'),
    created_at timestamptz NOT NULL
);
CREATE UNIQUE INDEX saved_views_name ON saved_views (user_id, page, lower(name));

-- Identity providers (§7.1; R42 row 19). The endpoints are read by discovery at configuration time and on
-- Refresh (SEC-013), never from a request; the client secret lives in setting_secrets.
CREATE TABLE oidc_providers (
    id                     uuid PRIMARY KEY,
    name                   text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 60),
    issuer_url             text NOT NULL CHECK (char_length(issuer_url) <= 500
                                               AND issuer_url ~ '^https://[^[:space:]/?#@]+(/[^[:space:]?#]*)?$'),
    client_id              text NOT NULL CHECK (char_length(client_id) BETWEEN 1 AND 255 AND client_id !~ '[[:cntrl:][:space:]]'),
    scopes                 text[] NOT NULL CHECK (cardinality(scopes) BETWEEN 1 AND 10 AND 'openid' = ANY (scopes)),
    groups_claim           text NOT NULL CHECK (groups_claim ~ '^[A-Za-z0-9_.:/-]{1,100}$'),
    ca_pem                 text NOT NULL DEFAULT '' CHECK (char_length(ca_pem) <= 65536),
    authorization_endpoint text NOT NULL CHECK (char_length(authorization_endpoint) <= 500 AND authorization_endpoint ~ '^https://'),
    token_endpoint         text NOT NULL CHECK (char_length(token_endpoint) <= 500 AND token_endpoint ~ '^https://'),
    jwks_uri               text NOT NULL CHECK (char_length(jwks_uri) <= 500 AND jwks_uri ~ '^https://'),
    enabled                boolean NOT NULL,
    version                integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    created_by             uuid REFERENCES users (id),
    created_at             timestamptz NOT NULL,
    updated_at             timestamptz NOT NULL
);
CREATE UNIQUE INDEX oidc_providers_name ON oidc_providers (lower(name));
CREATE UNIQUE INDEX oidc_providers_client ON oidc_providers (issuer_url, client_id);

-- Group-to-role mappings (SEC-014; R42 row 24): a non-empty group value, no "all users" mapping.
CREATE TABLE oidc_group_mappings (
    id                uuid PRIMARY KEY,
    provider_id       uuid NOT NULL REFERENCES oidc_providers (id) ON DELETE CASCADE,
    group_claim_value text NOT NULL CHECK (char_length(group_claim_value) BETWEEN 1 AND 256
                                           AND group_claim_value = btrim(group_claim_value)
                                           AND group_claim_value !~ '[[:cntrl:]]'),
    role              text NOT NULL CHECK (role IN ('admin', 'operator', 'auditor')),
    created_by        uuid REFERENCES users (id),
    created_at        timestamptz NOT NULL,
    UNIQUE (provider_id, group_claim_value)
);

-- SSO users (§7.1, SEC-015; R42 rows 21-23): matched by (oidc_issuer, oidc_subject) only; no password, never the
-- break-glass account, role always from the mapping. A local user has none of the three columns.
ALTER TABLE users ADD COLUMN oidc_provider_id uuid REFERENCES oidc_providers (id);
ALTER TABLE users ADD COLUMN oidc_issuer text CHECK (char_length(oidc_issuer) <= 500);
ALTER TABLE users ADD COLUMN oidc_subject text CHECK (char_length(oidc_subject) BETWEEN 1 AND 255);
ALTER TABLE users ADD CONSTRAINT users_oidc_identity CHECK (
    (auth_source = 'oidc') = (oidc_provider_id IS NOT NULL)
    AND (auth_source = 'oidc') = (oidc_issuer IS NOT NULL)
    AND (auth_source = 'oidc') = (oidc_subject IS NOT NULL));
ALTER TABLE users ADD CONSTRAINT users_oidc_not_local CHECK (auth_source <> 'oidc'
    OR (password_hash IS NULL AND NOT is_break_glass AND role_source = 'oidc_mapping'));
CREATE UNIQUE INDEX users_oidc_identity_unique ON users (oidc_issuer, oidc_subject) WHERE oidc_issuer IS NOT NULL;

-- One sign-in in flight (SEC-011): single use (deleted when used), at most 10 minutes, bound to the hash of the
-- browser's binding cookie; a step-up names the session and user it belongs to.
CREATE TABLE oidc_login_states (
    state_hash    bytea PRIMARY KEY CHECK (octet_length(state_hash) = 32),
    provider_id   uuid NOT NULL REFERENCES oidc_providers (id) ON DELETE CASCADE,
    binding_hash  bytea NOT NULL CHECK (octet_length(binding_hash) = 32),
    nonce         text NOT NULL CHECK (nonce ~ '^[A-Za-z0-9_-]{43}$'),
    code_verifier text NOT NULL CHECK (code_verifier ~ '^[A-Za-z0-9_-]{43,128}$'),
    purpose       text NOT NULL CHECK (purpose IN ('login', 'stepup')),
    session_hash  bytea CHECK (octet_length(session_hash) = 32),
    user_id       uuid REFERENCES users (id) ON DELETE CASCADE,
    next_path     text NOT NULL CHECK (char_length(next_path) BETWEEN 1 AND 2048 AND next_path ~ '^/'),
    created_at    timestamptz NOT NULL,
    expires_at    timestamptz NOT NULL,
    CHECK ((purpose = 'stepup') = (session_hash IS NOT NULL AND user_id IS NOT NULL)),
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '10 minutes')
);
CREATE INDEX oidc_login_states_expires ON oidc_login_states (expires_at);

GRANT SELECT, INSERT ON alerts TO alice_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON setting_secrets, saved_views, oidc_providers, oidc_group_mappings TO alice_app;
GRANT SELECT, INSERT, DELETE ON oidc_login_states TO alice_app;

-- +goose Down
-- Correct only on a database without Phase 7 data, as 00010's. The Down refuses, with a clear message and
-- SQLSTATE Z1015, when a sent notice, a settings secret, a saved view, an identity provider or an SSO user exists;
-- nothing is changed then. Mail and alert settings in the settings table are left as they are.
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM alerts) OR EXISTS (SELECT 1 FROM setting_secrets) OR EXISTS (SELECT 1 FROM saved_views)
            OR EXISTS (SELECT 1 FROM oidc_providers) OR EXISTS (SELECT 1 FROM users WHERE auth_source = 'oidc') THEN
        RAISE EXCEPTION 'cannot migrate down: Phase 7 data exists (sent notices, settings secrets, saved views, identity providers or SSO users); remove it first or restore a backup taken before 00011' USING ERRCODE = 'Z1015';
    END IF;
END $$;
-- +goose StatementEnd
DROP INDEX users_oidc_identity_unique;
ALTER TABLE users DROP CONSTRAINT users_oidc_not_local;
ALTER TABLE users DROP CONSTRAINT users_oidc_identity;
ALTER TABLE users DROP COLUMN oidc_subject;
ALTER TABLE users DROP COLUMN oidc_issuer;
ALTER TABLE users DROP COLUMN oidc_provider_id;
DROP TABLE oidc_login_states;
DROP TABLE oidc_group_mappings;
DROP TABLE oidc_providers;
DROP TABLE saved_views;
DROP TABLE setting_secrets;
DROP TABLE alerts;
```

Grant guard (`migrations/roles_integration_test.go`): `explicitGrants` gains `"public.alerts": {"INSERT", "SELECT"}` and `"public.oidc_login_states": {"DELETE", "INSERT", "SELECT"}` with a comment "Phase 7 (R42): the notice ledger is append-only; sign-in states are inserted and deleted, never changed". `setting_secrets`, `saved_views`, `oidc_providers` and `oidc_group_mappings` have the default table grants and are not listed.

### C3. `expiry` (Task 1)

```go
package expiry

var DefaultThresholds = []int{60, 30, 14, 7, 1}

const (
	MaxThresholds    = 10
	MaxThresholdDays = 365
	Expired          = 0 // the threshold of the notice sent once an item has expired
)

var ErrThresholds error // "expiry: thresholds must be 1 to 10 different whole days from 1 to 365"

func Normalize(days []int) ([]int, error)                          // validated copy, largest first
func Level(expiresAt, now time.Time, thresholds []int) (int, bool) // most urgent reached level; Expired once expiresAt <= now
func Due(expiresAt, now time.Time, thresholds, sent []int) (int, bool)
func DaysLeft(expiresAt, now time.Time) int                        // whole days left, rounded up; 0 once expired
func Horizon(thresholds []int) time.Duration                       // the largest threshold as a duration

type Bucket string

const (
	BucketExpired Bucket = "expired"
	Bucket7       Bucket = "7"     // 0 < left <= 7 days
	Bucket30      Bucket = "30"    // 7 days < left <= 30 days
	Bucket60      Bucket = "60"    // 30 days < left <= 60 days
	BucketLater   Bucket = "later" // more than 60 days left
)

func BucketOf(expiresAt, now time.Time) Bucket
```

`Due` sends only the most urgent reached level and nothing when `sent` (the thresholds already recorded for the same expiry instant) holds that level or a more urgent one (a smaller number; `Expired` is the most urgent).

### C4. `claims` (Task 2)

```go
package claims

const Leeway = 60 * time.Second

type Claims struct {
	Issuer            string
	Audience          []string
	AuthorizedParty   string    // azp
	Subject           string
	Nonce             string
	Expiry            time.Time
	IssuedAt          time.Time
	NotBefore         time.Time // zero: absent
	AuthTime          time.Time // zero: absent
	Email             string
	Name              string
	PreferredUsername string
	UPN               string
	// unexported: the raw claims, for Groups
}

func Parse(payload []byte) (Claims, error) // *Error{ReasonMalformed} on anything that is not a JSON object with the right types

type Expect struct {
	Issuer, ClientID, Nonce string
	Now                     time.Time
	MaxAuthAge              time.Duration // > 0 for a step-up: auth_time present and at most this old
}

type Reason string

const (
	ReasonMalformed Reason = "malformed"
	ReasonIssuer    Reason = "issuer"
	ReasonAudience  Reason = "audience"
	ReasonAzp       Reason = "azp"
	ReasonSubject   Reason = "subject"
	ReasonExpired   Reason = "expired"
	ReasonIssuedAt  Reason = "issued_at"
	ReasonNotBefore Reason = "not_before"
	ReasonNonce     Reason = "nonce"
	ReasonAuthTime  Reason = "auth_time"
)

type Error struct{ Reason Reason }

func (e *Error) Error() string
func Validate(c Claims, e Expect) error // nil or *Error

var (
	ErrOverage         error // the provider left the groups out (Entra overage)
	ErrGroupsMalformed error
)

const MaxGroups = 1000

func Groups(c Claims, claim string) ([]string, error) // a string or a list of strings; absent = none

type Mapping struct {
	Group string
	Role  rbac.Role
}

func ResolveRole(groups []string, mappings []Mapping, adminAllowed bool) (rbac.Role, bool) // highest; Admin capped to Operator when !adminAllowed

var (
	ErrGroupEmpty, ErrGroupTooLong, ErrGroupCharacters, ErrRole, ErrAdminNotAllowed error
)

const MaxGroupRunes = 256

func ValidateMapping(m Mapping, adminAllowed bool) error
func SafeNext(raw string) string    // a same-origin path, or "/"
func ValidateIssuer(raw string) error // ErrIssuer unless https://host[/path], no user info, query or fragment, at most 500 bytes
var ErrIssuer error
func Username(c Claims) string      // preferred_username, upn, email, else "sso-" + 12 hex of SHA-256(iss "\n" sub); [a-z0-9._@-], at most 64
```

### C5. `csvx` (Task 3)

```go
package csvx

func Safe(v string) string // prefixes ' to a value starting with = + - @ TAB or CR

type Writer struct{ /* unexported */ }

func NewWriter(w io.Writer) (*Writer, error) // writes the UTF-8 byte order mark
func (w *Writer) Write(record []string) error // Safe on every cell
func (w *Writer) Flush() error
```

### C6. Test fakes (Task 4)

```go
package fakesmtp

type Options struct {
	Implicit   bool   // TLS from the first byte (port 465 style); default STARTTLS
	NoStartTLS bool   // offer no STARTTLS (a downgrade test)
	Username   string // when set, AUTH PLAIN with Username/Password is required
	Password   string
	Hostname   string // the certificate's DNS name; default "127.0.0.1" (an IP SAN)
}

type Message struct {
	From    string
	To      []string
	Subject string // decoded (RFC 2047)
	Body    string // decoded (base64 transfer encoding)
	Raw     string
	Secure  bool
	Authed  bool
}

type Server struct{ /* unexported */ }

func New(o Options) (*Server, error)            // a self-signed ECDSA P-256 leaf, generated now
func Start(t testing.TB, o Options) *Server     // New + Listen("127.0.0.1:0"); closed by t.Cleanup
func (s *Server) Listen(addr string) error
func (s *Server) Addr() (host string, port int)
func (s *Server) CertPEM() []byte
func (s *Server) Fingerprint() string           // lower-case hex SHA-256 of the leaf DER
func (s *Server) Messages() []Message
func (s *Server) Clear()
func (s *Server) Down()                          // close the listener: connections are refused
func (s *Server) Up() error                      // listen again on the same address
func (s *Server) RejectRecipient(addr string)    // RCPT TO <addr> answers 550; "" clears
func (s *Server) Handler() http.Handler          // MailHog-compatible: GET /api/v2/messages, DELETE /api/v1/messages
func (s *Server) Close()
```

```go
package fakeidp

type Options struct {
	Plain bool             // serve http:// (for O-12); default TLS with its own CA
	Host  string           // the TLS name and issuer host; default "127.0.0.1"
	Now   func() time.Time // the token clock; default time.Now
}

type Login struct {
	Subject, Username, Name, Email string
	Groups                         []string
	Extra                          map[string]any // more claims, e.g. "upn"
}

type Fault struct {
	Alg              string        // "": RS256; "none"; "HS256" keyed with the public key's DER
	OtherKey         bool          // signed by a key that is not in the JWKS, same kid
	UnknownKid       bool
	Issuer           string        // overrides iss
	Audience         []string      // overrides aud
	Azp              string
	ExpIn            time.Duration // default 5 minutes; negative: already expired
	IatOffset        time.Duration
	NbfOffset        time.Duration // 0: no nbf claim
	Nonce            *string       // overrides the nonce
	OmitNonce        bool
	Overage          bool          // _claim_names/_claim_sources for the groups claim, no groups
	AuthTimeAgo      time.Duration // auth_time = now - this
	OmitAuthTime     bool
	AuthorizeError   string        // the authorize endpoint redirects with ?error=<value>
	ReplayCode       bool          // the token endpoint accepts a code twice
}

type Stats struct{ Discovery, JWKS, Authorize, Token int }

type Server struct{ /* unexported */ }

func New(o Options) (*Server, error)
func Start(t testing.TB, o Options) *Server
func (s *Server) Listen(addr string) error
func (s *Server) Issuer() string
func (s *Server) ClientID() string                 // "alice"
func (s *Server) ClientSecret() string             // random, generated by New
func (s *Server) CAPEM() []byte                    // the CA of the TLS certificate (nil when Plain)
func (s *Server) RegisterRedirect(uri string)      // allowed redirect URIs (exact match)
func (s *Server) RegisterRedirectPrefix(p string)  // allowed redirect URIs by prefix (the e2e container: https://localhost:)
func (s *Server) Client() *http.Client             // trusts the CA, never follows redirects
func (s *Server) NextLogin(l Login)                // the identity of the next authorize request
func (s *Server) SetFault(f Fault)                 // applies until the next SetFault
func (s *Server) RotateKey()                       // a new signing key with a new kid; the old one stays in the JWKS
func (s *Server) DropOldKeys()
func (s *Server) Down()                            // every endpoint answers 503
func (s *Server) Up()
func (s *Server) Stats() Stats
func (s *Server) LastTokenForm() url.Values        // the last token request's form (code_verifier, redirect_uri, …)
func (s *Server) Authorize(authorizeURL string) (callbackURL string, err error) // the browser's step at the IdP
func (s *Server) Handler() http.Handler
func (s *Server) Close()
```

### C7. `notify` additions (Tasks 6–7)

```go
// internal/platform/settings/general.go (Task 6)
const GeneralKey = "general"
const DefaultRetiredKeyRetentionDays = 30

type General struct {
	PublicURL               string `json:"public_url"`                 // "" or an https:// origin (no path, query or fragment)
	RetiredKeyRetentionDays int    `json:"retired_key_retention_days"` // 1..3650
	Version                 int    `json:"version"`                    // 0 = never saved
}

func GetGeneral(ctx context.Context, q db.Querier) (General, error) // defaults when absent
```

```go
// internal/notify (Tasks 6-7)
const (
	TLSModeSTARTTLS = "starttls"
	TLSModeTLS      = "tls"
	GiveUpAfter        = 24 * time.Hour
	FailingAfter       = 3
	MaxExtraRecipients = 20
	TestMailTimeout    = 30 * time.Second
	SeenCertValidFor   = time.Hour
	TemplateTestMail   = "notify.test"
)

var (
	ErrNotConfigured   error // no mail settings
	ErrVersion         error // If-Match does not match the stored version
	ErrCertNotSeen     error // a trust request for a fingerprint no failed test saw within SeenCertValidFor
	ErrAddressRefused  error // the SMTP host resolves to a refused address (netaddr)
	ErrSMTPUntrusted   error // wraps ErrSMTPTLS: the certificate did not verify and is not pinned
)

type CertInfo struct {
	Fingerprint string    // lower-case hex SHA-256 of the leaf DER
	Subject     string    // the leaf's subject, one line
	NotAfter    time.Time
}

type CertError struct{ Cert CertInfo } // errors.Is(err, ErrSMTPUntrusted) and errors.Is(err, ErrSMTPTLS)
func (e *CertError) Error() string
func (e *CertError) Unwrap() []error

type TrustedCert struct {
	CertInfo
	TrustedBy string // user name
	TrustedAt time.Time
}

type SMTPSettings struct {
	Host        string
	Port        int
	TLSMode     string
	From        string
	Username    string
	HasPassword bool
	CAPEM       string
	Trusted     *TrustedCert
	Version     int
	UpdatedAt   time.Time
}

type SMTPInput struct {
	Host, TLSMode, From, Username, CAPEM string
	Port                                 int
	Password                             *secrets.Plaintext // nil: keep; an empty Plaintext: remove; else replace
}

type Recipients struct {
	Administrators bool
	Addresses      []Address
	Version        int
}

type Address struct{ Email, Locale string } // Locale "en" or "tr"

type Delivery struct {
	ConsecutiveFailures int
	LastFailureAt       *time.Time
	LastFailureCode     string // the closed codes of ErrorCode
	LastSuccessAt       *time.Time
	Pending             int // pending outbox rows now
	Failed24h           int // rows that gave up in the last 24 hours
}

func (d Delivery) Failing() bool // ConsecutiveFailures >= FailingAfter

type SettingsConfig struct {
	Pool     *pgxpool.Pool
	Keyring  *secrets.Keyring
	Audit    *audit.Log
	Clock    clock.Clock
	Catalog  *i18n.Catalog
	Dial     func(ctx context.Context, network, addr string) (net.Conn, error) // nil: netaddr.DialContext
	Fallback Mailer       // used when no mail settings exist: the e2e mailbox; nil in release (skipped_no_smtp, L-18)
	Log      *slog.Logger // nil: discard (the env import's warning)
}

type Settings struct{ /* unexported */ }

func NewSettings(c SettingsConfig) *Settings
func (s *Settings) SMTP(ctx context.Context) (SMTPSettings, bool, error)
func (s *Settings) SaveSMTP(ctx context.Context, a audit.Actor, version int, in SMTPInput) (SMTPSettings, error)
func (s *Settings) DeleteSMTP(ctx context.Context, a audit.Actor, version int) error
func (s *Settings) TestMail(ctx context.Context, a audit.Actor, to, locale string) error // nil, *CertError, or an Err* sentinel
func (s *Settings) Trust(ctx context.Context, a audit.Actor, version int, fingerprint string) (SMTPSettings, error)
func (s *Settings) Untrust(ctx context.Context, a audit.Actor, version int) (SMTPSettings, error)
func (s *Settings) ImportEnv(ctx context.Context, c config.SMTP, readFile func(string) ([]byte, error)) (bool, error)
func (s *Settings) Mailer(ctx context.Context) (Mailer, func(), error) // MailerSource; the func zeroes the unsealed password
func (s *Settings) Recipients(ctx context.Context) (Recipients, error)
func (s *Settings) SaveRecipients(ctx context.Context, a audit.Actor, version int, r Recipients) (Recipients, error)
func (s *Settings) General(ctx context.Context) (settings.General, error)
func (s *Settings) SaveGeneral(ctx context.Context, a audit.Actor, version int, g settings.General) (settings.General, error)
func (s *Settings) Delivery(ctx context.Context) (Delivery, error)

type MailerSource interface {
	Mailer(ctx context.Context) (Mailer, func(), error) // nil Mailer: not configured
}

// Sender gains Source MailerSource (preferred over Mailer when set); Render appends email.license_note or
// email.license_note_kv when params["license_note"] is "true" or "kv" (the param itself is not rendered).
```

`SMTPMailer` gains `SMTPConfig.Pin string` (a fingerprint: verification by pin only) and `SMTPConfig.Dial` (nil: `netaddr.DialContext` with a `net.Dialer`); a failed verification returns `*CertError`. `AdminNotifier.NotifyAdmins` keeps its signature and reads `notify.recipients` with the caller's `tx`.

### C8. `alerts` (Task 8)

```go
package alerts

type Kind string

const (
	KindCertificate   Kind = "certificate_expiry"
	KindKVCertificate Kind = "kv_certificate_expiry"
	KindKVKey         Kind = "kv_key_expiry"
	KindKVCredential  Kind = "kv_credential_expiry"
)

func Kinds() []Kind // in this order

const (
	ScanEvery        = 15 * time.Minute
	MaxEmailsPerScan = 20
	ThresholdsKey    = "alerts.thresholds_days"
)

// Item is one monitored thing that expires (R42 row 4).
type Item struct {
	Kind        Kind
	ObjectID    uuid.UUID // certificates.id, kv_certificates.id, kv_keys.id or the vault's targets.id
	Name        string    // subject CN (else the label, else the fingerprint's first 16 characters), or the vault object's name, or the vault's name
	ExpiresAt   time.Time
	Fingerprint string    // certificates only
	Websites    []string  // certificates: server names of its live locations (sorted, at most 10)
	Servers     []string  // certificates: names of the targets of its live locations (sorted, at most 10)
	TargetIDs   []uuid.UUID
	Vault       string    // Key Vault kinds: the vault target's name
	VaultID     uuid.UUID
}

type Counts struct {
	Monitored, Expired, Within7, Within30, Within60 int // certificates (exclusive buckets of expiry.BucketOf)
	KVExpired, KVWithin30                           int // Key Vault certificates, keys and client secrets together
}

type ThresholdSettings struct {
	Days    []int
	Version int // 0: the defaults, never saved
}

type ScanResult struct {
	Queued     map[Kind]int // notices whose email was queued
	Suppressed map[Kind]int // notices recorded over MaxEmailsPerScan (one summary email per kind)
}

type LicenseState interface{ Snapshot() license.Snapshot }

type Notifier interface {
	NotifyAdmins(ctx context.Context, tx pgx.Tx, template string, params map[string]string) error
}

type Config struct {
	Pool     *pgxpool.Pool
	Audit    *audit.Log
	Clock    clock.Clock
	License  LicenseState
	Notifier Notifier
	Log      *slog.Logger
}

func New(c Config) *Service
func (s *Service) Thresholds(ctx context.Context) (ThresholdSettings, error)
func (s *Service) SaveThresholds(ctx context.Context, a audit.Actor, version int, days []int) (ThresholdSettings, error) // expiry.ErrThresholds, notify.ErrVersion
func (s *Service) Items(ctx context.Context, kinds []Kind, until time.Time, limit int) ([]Item, error) // soonest first, expired included
func (s *Service) Counts(ctx context.Context) (Counts, error)
func (s *Service) Scan(ctx context.Context) (ScanResult, error)
func Templates() []string
```

Templates (texts in C14): `alert.certificate_expiring`, `alert.certificate_expired`, `alert.kv_certificate_expiring`, `alert.kv_certificate_expired`, `alert.kv_key_expiring`, `alert.kv_key_expired`, `alert.kv_credential_expiring`, `alert.kv_credential_expired`, `alert.more`. While the license is locked (`License.Snapshot().Eval.Locked()`) every one carries the param `license_note` (`"true"` for certificates, `"kv"` for the three Key Vault kinds) and `license_url`.

### C9. `reports` (Tasks 9–10)

```go
package reports

type Viewer struct {
	UserID uuid.UUID
	Role   rbac.Role
}

type Summary struct {
	GeneratedAt   time.Time
	Certificates  alerts.Counts
	Deployments   DeploymentSummary
	Targets       TargetSummary
	License       LicenseSummary
	Rotation      RotationSummary
	Notifications *notify.Delivery // Administrators only
	Audit         *AuditHead       // Administrators and Auditors only
	Attention     int              // len(Attention(...)) for the same viewer
}

type DeploymentSummary struct {
	Failed7d int
	Recent   []FailedDeployment // at most 5, newest first
}

type FailedDeployment struct {
	ID              uuid.UUID
	CertificateName string
	TargetID        uuid.UUID
	TargetName      string
	Status          string // failed | rolled_back | rollback_failed | needs_attention
	ErrorCode       string
	At              time.Time // coalesce(finished_at, created_at)
}

type TargetSummary struct {
	Total    int
	ByStatus map[string]int // every status of a live target, also 0 for the seven known statuses and degraded
}

type LicenseSummary struct {
	Expired  bool
	Phase    string     // "" for Operators
	EndsAt   *time.Time // nil for Operators
	DaysLeft *int       // nil for Operators
}

type RotationSummary struct {
	Upcoming       []UpcomingRotation // at most 5, soonest first, enabled policies due within RotationWindow
	Running        int                // runs not finished (status not completed, aborted, cancelled, needs_attention)
	NeedsAttention int                // runs whose status is needs_attention
}

type UpcomingRotation struct {
	PolicyID  uuid.UUID
	SSHKeyID  uuid.UUID
	KeyLabel  string
	NextRunAt time.Time
}

type AuditHead struct {
	HeadSeq   int64
	HeadHash  string    // hex
	CheckedAt time.Time // the checkpoint's time
	Intact    bool      // false when jobs.audit_verify's last broken verification is newer than its last intact one
}

type Condition struct {
	Kind      string    // host_key_changed | auth_failed | deployment_failed | audit_broken | notifications_failing
	ObjectID  string    // target, deployment or "" for audit_broken / notifications_failing
	Name      string    // target name, certificate name or ""
	Since     time.Time
	ErrorCode string
}

type Config struct {
	Pool      *pgxpool.Pool
	Clock     clock.Clock
	Audit     *audit.Log
	License   alerts.LicenseState
	Alerts    *alerts.Service
	Delivery  interface{ Delivery(ctx context.Context) (notify.Delivery, error) }
	Inventory Inventory
}

type Inventory interface {
	ListCertificates(ctx context.Context, f inventory.CertificateFilter) (inventory.CertificatePage, error)
	ListSSHKeys(ctx context.Context, f inventory.KeyFilter) (inventory.KeyPage, error)
}

func New(c Config) *Service
func (s *Service) Summary(ctx context.Context, v Viewer) (Summary, error)
func (s *Service) Expiring(ctx context.Context, days, limit int) ([]alerts.Item, error) // days 1..365, limit 1..200
func (s *Service) Attention(ctx context.Context, v Viewer) ([]Condition, error)        // notifications_failing for Administrators only

// Task 10
const (
	MaxExportRows   = 50000
	MaxViewsPerUser = 50
	PageCertificates = "certificates"
	PageSSHKeys      = "ssh_keys"
)

var (
	ErrTooLarge   error // more than MaxExportRows rows: nothing written
	ErrViewLimit  error
	ErrViewName   error // name taken
	ErrNotFound   error
)

func (s *Service) ExportCertificates(ctx context.Context, a audit.Actor, f inventory.CertificateFilter, w io.Writer) (int, error)
func (s *Service) ExportSSHKeys(ctx context.Context, a audit.Actor, f inventory.KeyFilter, w io.Writer) (int, error)

type View struct {
	ID        uuid.UUID
	Page      string
	Name      string
	Query     map[string]string
	CreatedAt time.Time
}

func ViewQueryKeys(page string) []string // certificates: target_id, source, q, expiry; ssh_keys: target_id, os_user, q, flag, missing
func (s *Service) Views(ctx context.Context, userID uuid.UUID, page string) ([]View, error)
func (s *Service) CreateView(ctx context.Context, userID uuid.UUID, page, name string, query map[string]string) (View, error) // validate.Errors, ErrViewLimit, ErrViewName
func (s *Service) DeleteView(ctx context.Context, userID, id uuid.UUID) error // ErrNotFound also for another user's view
```

CSV columns (exact header row, after the BOM):
- certificates: `id,subject_cn,label,sans,issuer,serial,not_before,not_after,days_left,source,key_algorithm,key_bits,self_signed,chain_complete,fingerprint,location_count` (SANs joined with a space; times RFC 3339 UTC; `days_left` from `expiry.DaysLeft`).
- ssh keys: `id,fingerprint,key_type,bits,comment,managed,platform_key,weak,location_count,target_count,missing,retired,first_seen_at`.

Supporting reads (Task 9): `audit.LastCheckpoint(ctx context.Context, q db.Querier) (Checkpoint, bool, error)` with `type Checkpoint struct { Seq int64; Hash string; At time.Time }`; `jobs.ReadAuditVerifyState(ctx context.Context, q db.Querier) (AuditVerifyState, error)` with the exported `type AuditVerifyState struct { LastIntactAt, LastBrokenAt time.Time; AlertedBadSeq int64; AlertedProblem string }` (the existing unexported `auditVerifyState` becomes this type).

### C10. `auth` additions (Task 11)

```go
// internal/audit
const ActorOIDC ActorType = "oidc" // an identity provider's user before (or without) a session

// internal/auth
const TemplateLockout = "auth.lockout" // params username, minutes, failed_logins
func Templates() []string               // {TemplateLockout}

type Notifier interface {
	NotifyAdmins(ctx context.Context, tx pgx.Tx, template string, params map[string]string) error
}
// Config gains Notifier Notifier (nil: no lockout email).

type OIDCIdentity struct {
	ProviderID  uuid.UUID
	Issuer      string
	Subject     string
	Username    string // claims.Username
	DisplayName string
	Email       string
}

var (
	ErrOIDCEmailInUse   error // the e-mail belongs to a local user (O-10)
	ErrOIDCUserDisabled error
	ErrOIDCOtherUser    error // a step-up answered for another identity
	ErrNotSSOUser       error // an SSO step-up for a local user
	ErrSSOUser          error // a manual role change, password or MFA reset of an SSO user (ALC-USR-0003)
)

func (s *Service) SignInOIDC(ctx context.Context, id OIDCIdentity, role rbac.Role, m Meta) (SessionResult, error)
func (s *Service) StepUpOIDC(ctx context.Context, sessionHash []byte, userID uuid.UUID, id OIDCIdentity, m Meta) (SessionResult, error)
func (s *Service) RefuseOIDC(ctx context.Context, id OIDCIdentity, reason string, m Meta) error
func (s *Service) DemoteSSOAdmins(ctx context.Context, tx pgx.Tx, a audit.Actor) (demoted, ended int, err error)
```

`User`, `SessionInfo` and `Principal` gain `AuthSource string` (`local` | `oidc`); `User` and `SessionInfo` gain `SSOProviderID *uuid.UUID`. `GET /api/v1/auth/session` and the user DTOs carry `auth_source` and `sso_provider_id`.

`SignInOIDC` (one transaction): find the user by `(oidc_issuer, oidc_subject)`; if none, refuse `ErrOIDCEmailInUse` when a **local** user has the same non-empty e-mail, else insert one (`auth_source = 'oidc'`, `role_source = 'oidc_mapping'`, `password_hash` NULL, the user name made unique by suffixes `-2`, `-3`, … ; audit `user.provisioned`); refuse `ErrOIDCUserDisabled` for a disabled user; update role (audit `user.role_synced` when it changed), display name, e-mail and `last_login_at`; `startFullSession` (the step-up window opens at sign-in, the IdP just authenticated the user); audit `auth.login` with `method` `oidc`, `provider_id`, `role`. `RefuseOIDC` writes `auth.oidc.denied` (actor `oidc`, `reason`, `provider_id`) and, for a known user and the reasons `no_access`, `groups_overage`, `provider_disabled`, revokes all of that user's sessions (audit `user.sessions_ended`, `reason`, `ended_count`).

### C11. `auth/oidc` (Task 12)

```go
package oidc

const (
	StateLifetime    = 10 * time.Minute
	StepUpMaxAge     = 5 * time.Minute
	HTTPTimeout      = 10 * time.Second
	MaxProviders     = 5
	MaxMappings      = 200
	JWKSRefetchEvery = time.Minute
	MaxResponseBytes = 1 << 20
	AllowAdminKey    = "sso.allow_admin_role"
	CallbackPath     = "/api/v1/auth/oidc/%s/callback"
)

var SigningAlgs = []string{"RS256", "ES256", "PS256"} // SEC-012

type Endpoints struct{ Authorization, Token, JWKS string }

type Provider struct {
	ID              uuid.UUID
	Name            string
	IssuerURL       string
	ClientID        string
	HasClientSecret bool
	Scopes          []string
	GroupsClaim     string
	CAPEM           string
	Endpoints       Endpoints
	Enabled         bool
	RedirectURI     string // "" while general.public_url is unset
	Version         int
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type ProviderInput struct {
	Name, IssuerURL, ClientID, GroupsClaim, CAPEM string
	ClientSecret                                  secrets.Plaintext // required
	Scopes                                        []string          // nil: openid, profile, email
	Enabled                                       bool
}

type ProviderPatch struct {
	Name, IssuerURL, ClientID, GroupsClaim, CAPEM *string
	ClientSecret                                  *secrets.Plaintext
	Scopes                                        *[]string
	Enabled                                       *bool
}

type PublicProvider struct {
	ID   uuid.UUID
	Name string
}

type Mapping struct {
	ID         uuid.UUID
	ProviderID uuid.UUID
	Group      string
	Role       rbac.Role
	CreatedAt  time.Time
}

type SSOSettings struct {
	AllowAdminRole bool
	Version        int
}

type DiscoveryError struct{ Cause string } // connect | tls | status | document | issuer_mismatch | not_https | jwks
func (e *DiscoveryError) Error() string

var (
	ErrNotFound, ErrVersion, ErrTooMany, ErrProviderInUse, ErrPublicURLMissing error
	ErrAdminMappingDisabled, ErrAdminMappingsExist                             error
)

type LoginError struct {
	Reason string // C15 SSO reasons without the "sso." prefix
	StepUp bool   // the refused sign-in was a step-up (the callback returns to Next, not to the sign-in page)
	Next   string // the state's safe next path ("" when no state was found)
}
func (e *LoginError) Error() string

type Config struct {
	Pool    *pgxpool.Pool
	Keyring *secrets.Keyring
	Audit   *audit.Log
	Clock   clock.Clock
	Auth    *auth.Service
	Dial    func(ctx context.Context, network, addr string) (net.Conn, error) // nil: netaddr.DialContext
	Log     *slog.Logger
}

func New(c Config) *Service
func (s *Service) Providers(ctx context.Context) ([]Provider, error)
func (s *Service) Provider(ctx context.Context, id uuid.UUID) (Provider, error)
func (s *Service) PublicProviders(ctx context.Context) ([]PublicProvider, error) // enabled ones, by name
func (s *Service) CreateProvider(ctx context.Context, a audit.Actor, in ProviderInput) (Provider, error)
func (s *Service) UpdateProvider(ctx context.Context, a audit.Actor, id uuid.UUID, version int, p ProviderPatch) (Provider, error)
func (s *Service) RefreshProvider(ctx context.Context, a audit.Actor, id uuid.UUID, version int) (Provider, error)
func (s *Service) DeleteProvider(ctx context.Context, a audit.Actor, id uuid.UUID, version int) error
func (s *Service) Mappings(ctx context.Context, providerID uuid.UUID) ([]Mapping, error)
func (s *Service) CreateMapping(ctx context.Context, a audit.Actor, providerID uuid.UUID, group string, role rbac.Role) (Mapping, error)
func (s *Service) DeleteMapping(ctx context.Context, a audit.Actor, id uuid.UUID) error
func (s *Service) Settings(ctx context.Context) (SSOSettings, error)
func (s *Service) SaveSettings(ctx context.Context, a audit.Actor, version int, allowAdmin bool) (SSOSettings, error)

type BeginInput struct {
	ProviderID  uuid.UUID // ignored for a step-up (the user's own provider)
	Next        string    // claims.SafeNext applies
	StepUp      bool
	SessionHash []byte    // step-up only
	UserID      uuid.UUID // step-up only
}

type Begin struct {
	AuthorizeURL string
	Binding      string // the cookie value; only its SHA-256 is stored
}

func (s *Service) Begin(ctx context.Context, in BeginInput) (Begin, error)

type Completion struct {
	Session auth.SessionResult
	Next    string
	StepUp  bool
}

func (s *Service) Complete(ctx context.Context, providerID uuid.UUID, q url.Values, binding string, m auth.Meta) (Completion, error) // *LoginError
func (s *Service) PruneStates(ctx context.Context) (int, error)
```

`Complete`, in order: consume the state row (`DELETE … WHERE state_hash = $1 RETURNING …`; missing, expired, other provider or a binding hash that differs → `login_expired`); an `error` parameter from the IdP → `idp_error`; the provider must be enabled (`provider_disabled`); exchange the code (`oauth2.Config.Exchange` with `oauth2.VerifierOption(verifier)`, the provider's HTTP client; transport failures → `idp_unreachable`, an answer without `id_token` or an error answer → `login_invalid`); verify the signature with the bounded key set and `oidc.NewVerifier(issuer, keySet, &oidc.Config{ClientID, SupportedSigningAlgs: SigningAlgs, SkipExpiryCheck: true})` (all time checks are `claims.Validate`'s, with the injected clock); `claims.Parse` + `claims.Validate` (`MaxAuthAge` = `StepUpMaxAge` for a step-up) → `login_invalid`; for a step-up: `auth.StepUpOIDC` (`stepup_other_user`); else `claims.Groups` (`groups_overage`), `claims.ResolveRole` against the provider's mappings and `sso.allow_admin_role` (`no_access`), `auth.SignInOIDC` (`email_in_use`, `user_disabled`). Every refusal calls `auth.RefuseOIDC` with the closed reason once and returns `*LoginError`.

### C12. Jobs, wiring and the e2e build (Task 13)

- `internal/jobs/types.go`: `AlertsScan = Register("alerts.scan", license.ClassAlways)` in a "Phase 7" block; `cmd/alice/wiring.go` `periodicTypes` gains `jobs.AlertsScan`.
- `cmd/alice/services.go`: `services` gains `notifySettings *notify.Settings`, `alerts *alerts.Service`, `reports *reports.Service`, `oidc *oidc.Service`; `buildServices` builds them (auth's `Config.Notifier = notify.AdminNotifier{Clock: clk}`); `buildSender` sets `Sender.Source = svc.notifySettings` (the release build's `Fallback` is nil, the e2e build's `testMailer`); `buildScheduler` adds `jobs.Task{Type: jobs.AlertsScan, Every: alertsScanEvery, Run: …Scan}` and `maintenance.cleanup` also runs `svc.oidc.PruneStates`; at serve start `svc.notifySettings.ImportEnv(ctx, cfg.SMTP, os.ReadFile)` runs once before the scheduler.
- `testapi_release.go`: `alertsScanEvery = alerts.ScanEvery`; `testapi_e2e.go`: `alertsScanEvery = 100 * 365 * 24 * time.Hour` (never; `runScheduled`).
- `resetSQL` gains `alerts, saved_views, oidc_login_states, oidc_group_mappings, oidc_providers, setting_secrets` (in the same `TRUNCATE` as `users`).
- New e2e endpoint `POST /test/seed/dashboard` (body `{}`): seeds, through the owner pool, the fixed data set of C17 and answers its expected counts as JSON (C17). New `E2E_SYMBOLS` name: `serveSeedDashboard`; the data set is `seed.Dashboard` (`internal/testutil/seed/dashboard.go`), shared with Task 16.

### C13. API (Tasks 14–15)

| Method and path | Permission | License class | Limit | Body / query | Answer |
|---|---|---|---|---|---|
| `GET /api/v1/dashboard/summary` | `read` | — | default | — | `DashboardSummary` |
| `GET /api/v1/dashboard/expiring` | `read` | — | default | `?days` (1–365, default 30), `?limit` (1–200, default 50) | `{"items": [ExpiringItem]}` |
| `GET /api/v1/alerts` | `read` | — | default | — | `{"items": [Condition]}` (role-filtered as `reports.Attention`) |
| `GET /api/v1/notifications/status` | `read` | — | default | — | Administrators: `Delivery`; others: `{"failing": false}` |
| `GET /api/v1/certificates/export` | `read` | — | `limitExport` | `?target_id`, `?source`, `?q`, `?expiry` | 200 `text/csv; charset=utf-8`, `Content-Disposition: attachment; filename="alice-certificates-<yyyy-mm-dd>.csv"`, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff` |
| `GET /api/v1/ssh-keys/export` | `read` | — | `limitExport` | `?target_id`, `?os_user`, `?q`, `?flag`, `?missing` | as above, `alice-ssh-keys-<yyyy-mm-dd>.csv` |
| `GET /api/v1/views` | `session` | — | default | `?page` (`certificates`\|`ssh_keys`, required) | `{"items": [View]}` |
| `POST /api/v1/views` | `session` | always | default | `{"page", "name", "query": {string: string}}` (exact keys) | 201 `View` |
| `DELETE /api/v1/views/{id}` | `session` | always | default | — | 204 |
| `GET /api/v1/settings/smtp` | `settings.manage` | — | default | — | `SMTP`, `ETag: "<version>"` (`"0"` when not configured) |
| `PUT /api/v1/settings/smtp` | `settings.manage` | always | default | `{"host", "port", "tls_mode", "from", "username", "password" (optional: string; `""` removes; absent keeps), "ca_pem"}`; `If-Match` | `SMTP`, `ETag` |
| `DELETE /api/v1/settings/smtp` | `settings.manage` | always | default | `If-Match` | 204 |
| `POST /api/v1/settings/smtp/actions/test` | `settings.manage` | always | `limitTestMail` | `{"to": e-mail}` | 200 `{"sent": true}`; errors C15 (`ALC-NTF-0005` carries `fingerprint`, `subject`, `not_after`) |
| `POST /api/v1/settings/smtp/actions/trust` | `settings.manage` | always | default | `{"fingerprint": "<64 hex>"}`; `If-Match` | `SMTP`, `ETag` |
| `POST /api/v1/settings/smtp/actions/untrust` | `settings.manage` | always | default | `If-Match` | `SMTP`, `ETag` |
| `GET /api/v1/settings/notifications` | `settings.manage` | — | default | — | `Recipients`, `ETag` |
| `PUT /api/v1/settings/notifications` | `settings.manage` | always | default | `{"administrators": bool, "addresses": [{"email", "locale"}]}`; `If-Match` | `Recipients`, `ETag` |
| `GET /api/v1/settings/alerts` | `settings.manage` | — | default | — | `{"thresholds_days": [int], "version"}`, `ETag` |
| `PUT /api/v1/settings/alerts` | `settings.manage` | always | default | `{"thresholds_days": [int]}`; `If-Match` | same, `ETag` |
| `GET /api/v1/settings/general` | `settings.manage` | — | default | — | `{"public_url", "retired_key_retention_days", "version"}`, `ETag` |
| `PUT /api/v1/settings/general` | `settings.manage` | always | default | `{"public_url", "retired_key_retention_days"}`; `If-Match` | same, `ETag` |
| `GET /api/v1/sso/providers` | `sso.manage` | — | default | — | `{"items": [Provider]}` |
| `POST /api/v1/sso/providers` | `sso.manage` | always | default | `{"name", "issuer_url", "client_id", "client_secret", "scopes"?, "groups_claim"?, "ca_pem"?, "enabled"?}` | 201 `Provider`, `ETag` |
| `GET /api/v1/sso/providers/{id}` | `sso.manage` | — | default | — | `Provider`, `ETag` |
| `PATCH /api/v1/sso/providers/{id}` | `sso.manage` | always | default | any key of the create body; `If-Match` | `Provider`, `ETag` |
| `DELETE /api/v1/sso/providers/{id}` | `sso.manage` | always | default | `If-Match` | 204 |
| `POST /api/v1/sso/providers/{id}/actions/refresh` | `sso.manage` | always | default | `If-Match` | `Provider`, `ETag` |
| `GET /api/v1/sso/group-mappings` | `sso.manage` | — | default | `?provider_id` (required) | `{"items": [Mapping]}` |
| `POST /api/v1/sso/group-mappings` | `sso.manage` | always | default | `{"provider_id", "group", "role"}` | 201 `Mapping` |
| `DELETE /api/v1/sso/group-mappings/{id}` | `sso.manage` | always | default | — | 204 |
| `GET /api/v1/sso/settings` | `sso.manage` | — | default | — | `{"allow_admin_role", "version"}`, `ETag` |
| `PUT /api/v1/sso/settings` | `sso.manage` | always | default | `{"allow_admin_role": bool}`; `If-Match` | same, `ETag` |
| `GET /api/v1/auth/oidc/providers` | `public` | — | default | — | `{"items": [{"id", "name"}]}` |
| `POST /api/v1/auth/oidc/{id}/start` | `public` | always | `limitLogin` | `{"next"?: string}` | 200 `{"authorize_url"}` and `Set-Cookie: __Host-alice_oidc=…` |
| `GET /api/v1/auth/oidc/{id}/callback` | `public` | — | `limitLogin` | `?code`, `?state`, `?error` | 303: `Location: <next>` with the session cookie; refused: `Location: /login?sso_error=<reason>` (login) or `<next>?sso_error=<reason>` (step-up); the binding cookie is cleared in both |
| `POST /api/v1/auth/oidc/stepup` | `session` | always | `limitMFA` | `{"next"?: string}` | 200 `{"authorize_url"}` and the binding cookie; 409 `ALC-SSO-0016` for a local user |

DTOs (JSON, snake_case; times UTC RFC 3339):

- `DashboardSummary`: `{"generated_at", "certificates": {"monitored", "expired", "within_7", "within_30", "within_60", "kv_expired", "kv_within_30"}, "deployments": {"failed_7d", "recent": [{"id", "certificate_name", "target_id", "target_name", "status", "error_code", "at"}]}, "targets": {"total", "by_status": {status: n}}, "license": {"expired", "phase", "ends_at", "days_left"}, "rotation": {"upcoming": [{"policy_id", "ssh_key_id", "key_label", "next_run_at"}], "running", "needs_attention"}, "notifications": null | Delivery, "audit": null | {"head_seq", "head_hash", "checked_at", "intact"}, "attention"}`. For Operators `license.phase` is `""` and `ends_at`/`days_left` are `null`.
- `ExpiringItem`: `{"kind", "object_id", "name", "expires_at", "days_left", "expired", "fingerprint", "websites", "servers", "target_ids", "vault", "vault_id"}` (`vault_id` null for certificates).
- `Condition`: `{"kind", "object_id", "name", "since", "error_code"}`.
- `Delivery`: `{"failing", "consecutive_failures", "last_failure_at", "last_failure_code", "last_success_at", "pending", "failed_24h"}`.
- `View`: `{"id", "page", "name", "query", "created_at"}`.
- `SMTP`: `{"configured", "host", "port", "tls_mode", "from", "username", "has_password", "ca_pem", "trusted_certificate": null | {"fingerprint", "subject", "not_after", "trusted_by", "trusted_at"}, "version", "updated_at"}`. Never a password field (S-08).
- `Recipients`: `{"administrators", "addresses": [{"email", "locale"}], "version"}`.
- `Provider`: `{"id", "name", "issuer_url", "client_id", "has_client_secret", "scopes", "groups_claim", "ca_pem", "endpoints": {"authorization", "token", "jwks"}, "enabled", "redirect_uri", "version", "created_at", "updated_at"}`. Never a secret field.
- `Mapping`: `{"id", "provider_id", "group", "role", "created_at"}`.

Validation (422 with field details, `validate.*` codes): `host` 1–253 bytes without white space or `/`; `port` 1–65535; `tls_mode` `starttls`|`tls`; `from` and every address an RFC 5322 address of at most 254 bytes (`net/mail`); `username` at most 255 bytes, no control characters; `password` at most 1024 bytes; `ca_pem` at most 64 KiB, only `CERTIFICATE` blocks, 1–20 certificates that parse; `to` an address; `fingerprint` `^[0-9a-f]{64}$`; `addresses` at most 20, `locale` `en`|`tr`, at least one recipient source (`administrators` or an address: `validate.Required` on `addresses`); `thresholds_days` per `expiry.Normalize` (`validate.OutOfRange` with `min` 1 and `max` 365; a repeated value `validate.Duplicate`; more than 10 values `validate.TooLong` with `max` 10); `public_url` `""` or `https://host[:port]` (no path other than `/`, no query, fragment or user info); `retired_key_retention_days` 1–3650; `name` (views) 1–60 runes, no control/format characters; `query` keys only from `reports.ViewQueryKeys(page)`, values at most 200 runes; provider `name` 1–60 runes; `issuer_url` per `claims.ValidateIssuer`; `client_id` 1–255 bytes, no white space; `client_secret` 1–1024 bytes; `scopes` 1–10 values `^[A-Za-z0-9_.:/-]{1,64}$` including `openid`; `groups_claim` `^[A-Za-z0-9_.:/-]{1,100}$`; `ca_pem` as above; `group` per `claims.ValidateMapping`; `role` `admin`|`operator`|`auditor`.

### C14. Emails (texts in `locales/common/{en,tr}.json` under `email.*`: `notify.test` by Task 6, the two notes by Task 7, the rest by Task 14)

Parameters are strings, flattened to one line by `Sender.Render`; times are `2006-01-02 15:04 UTC`; lists (`websites`, `servers`) are joined with `", "` and end with `", …"` beyond 10 entries; an empty list renders as `-`.

| Template | Params | EN subject | EN body | TR subject | TR body |
|---|---|---|---|---|---|
| `notify.test` | — | `Alice test e-mail` | `This is a test e-mail from Alice. If you received it, Alice can send e-mails with the current mail settings.` | `Alice test e-postası` | `Bu, Alice'ten gönderilen bir test e-postasıdır. Bu e-postayı aldıysanız Alice geçerli posta ayarlarıyla e-posta gönderebilir.` |
| `alert.certificate_expiring` | `name`, `days`, `expires_at`, `websites`, `servers`, `fingerprint` | `Certificate expiring: {{name}} (days left: {{days}})` | `The certificate {{name}} expires at {{expires_at}}. Days left: {{days}}.\n\nWebsites: {{websites}}\nServers: {{servers}}\nFingerprint (SHA-256): {{fingerprint}}\n\nRenew it and deploy the new certificate before then. The Dashboard in Alice lists every certificate that expires soon.` | `Süresi dolmak üzere olan sertifika: {{name}} (kalan gün: {{days}})` | `{{name}} sertifikasının süresi şu zamanda doluyor: {{expires_at}}. Kalan gün: {{days}}.\n\nWeb siteleri: {{websites}}\nSunucular: {{servers}}\nParmak izi (SHA-256): {{fingerprint}}\n\nSertifikayı yenileyin ve yeni sertifikayı bu zamandan önce dağıtın. Alice'teki Pano, süresi yakında dolacak tüm sertifikaları listeler.` |
| `alert.certificate_expired` | `name`, `expires_at`, `websites`, `servers`, `fingerprint` | `Certificate expired: {{name}}` | `The certificate {{name}} expired at {{expires_at}} and is still in use.\n\nWebsites: {{websites}}\nServers: {{servers}}\nFingerprint (SHA-256): {{fingerprint}}\n\nVisitors of these websites now see a security warning. Deploy a valid certificate as soon as possible.` | `Süresi dolan sertifika: {{name}}` | `{{name}} sertifikasının süresi şu zamanda doldu ve sertifika hâlâ kullanılıyor: {{expires_at}}.\n\nWeb siteleri: {{websites}}\nSunucular: {{servers}}\nParmak izi (SHA-256): {{fingerprint}}\n\nBu web sitelerinin ziyaretçileri artık bir güvenlik uyarısı görüyor. Geçerli bir sertifikayı en kısa sürede dağıtın.` |
| `alert.kv_certificate_expiring` | `name`, `vault`, `days`, `expires_at` | `Key Vault certificate expiring: {{name}} (days left: {{days}})` | `The certificate {{name}} in the Key Vault {{vault}} expires at {{expires_at}}. Days left: {{days}}.\n\nIf the vault renews it automatically, Alice deploys the new version where it is connected. Otherwise renew it in Azure before then.` | `Süresi dolmak üzere olan Key Vault sertifikası: {{name}} (kalan gün: {{days}})` | `{{vault}} Key Vault'undaki {{name}} sertifikasının süresi şu zamanda doluyor: {{expires_at}}. Kalan gün: {{days}}.\n\nKasa sertifikayı kendiliğinden yeniliyorsa Alice yeni sürümü bağlı olduğu yerlere dağıtır. Aksi hâlde bu zamandan önce Azure'da yenileyin.` |
| `alert.kv_certificate_expired` | `name`, `vault`, `expires_at` | `Key Vault certificate expired: {{name}}` | `The certificate {{name}} in the Key Vault {{vault}} expired at {{expires_at}}.\n\nRenew it in Azure; Alice deploys the new version where it is connected.` | `Süresi dolan Key Vault sertifikası: {{name}}` | `{{vault}} Key Vault'undaki {{name}} sertifikasının süresi şu zamanda doldu: {{expires_at}}.\n\nSertifikayı Azure'da yenileyin; Alice yeni sürümü bağlı olduğu yerlere dağıtır.` |
| `alert.kv_key_expiring` | `name`, `vault`, `days`, `expires_at` | `Key Vault key expiring: {{name}} (days left: {{days}})` | `The key {{name}} in the Key Vault {{vault}} expires at {{expires_at}}. Days left: {{days}}.\n\nApplications that use this key stop working with it after that time. Create a new key version in Azure before then.` | `Süresi dolmak üzere olan Key Vault anahtarı: {{name}} (kalan gün: {{days}})` | `{{vault}} Key Vault'undaki {{name}} anahtarının süresi şu zamanda doluyor: {{expires_at}}. Kalan gün: {{days}}.\n\nBu anahtarı kullanan uygulamalar bu zamandan sonra onunla çalışamaz. Bu zamandan önce Azure'da yeni bir anahtar sürümü oluşturun.` |
| `alert.kv_key_expired` | `name`, `vault`, `expires_at` | `Key Vault key expired: {{name}}` | `The key {{name}} in the Key Vault {{vault}} expired at {{expires_at}}.\n\nCreate a new key version in Azure and update the applications that use it.` | `Süresi dolan Key Vault anahtarı: {{name}}` | `{{vault}} Key Vault'undaki {{name}} anahtarının süresi şu zamanda doldu: {{expires_at}}.\n\nAzure'da yeni bir anahtar sürümü oluşturun ve onu kullanan uygulamaları güncelleyin.` |
| `alert.kv_credential_expiring` | `vault`, `days`, `expires_at` | `Key Vault sign-in secret expiring: {{vault}} (days left: {{days}})` | `The client secret Alice uses to sign in to the Key Vault {{vault}} expires at {{expires_at}}. Days left: {{days}}.\n\nCreate a new client secret in Microsoft Entra ID and enter it on the vault's page in Alice before then. After that time Alice cannot read the vault.` | `Süresi dolmak üzere olan Key Vault oturum açma parolası: {{vault}} (kalan gün: {{days}})` | `Alice'in {{vault}} Key Vault'unda oturum açmak için kullandığı istemci parolasının süresi şu zamanda doluyor: {{expires_at}}. Kalan gün: {{days}}.\n\nMicrosoft Entra ID'de yeni bir istemci parolası oluşturun ve bu zamandan önce Alice'te kasanın sayfasına girin. Bu zamandan sonra Alice kasayı okuyamaz.` |
| `alert.kv_credential_expired` | `vault`, `expires_at` | `Key Vault sign-in secret expired: {{vault}}` | `The client secret Alice uses to sign in to the Key Vault {{vault}} expired at {{expires_at}}.\n\nCreate a new client secret in Microsoft Entra ID and enter it on the vault's page in Alice.` | `Süresi dolan Key Vault oturum açma parolası: {{vault}}` | `Alice'in {{vault}} Key Vault'unda oturum açmak için kullandığı istemci parolasının süresi şu zamanda doldu: {{expires_at}}.\n\nMicrosoft Entra ID'de yeni bir istemci parolası oluşturun ve Alice'te kasanın sayfasına girin.` |
| `alert.more` | `count` | `More expiry notices: {{count}}` | `In this check, {{count}} more items reached an expiry threshold. Alice did not send a separate e-mail for each of them.\n\nOpen the Dashboard in Alice to see them all.` | `Diğer süre dolumu bildirimleri: {{count}}` | `Bu denetimde {{count}} öğe daha bir süre dolumu eşiğine ulaştı. Alice bunların her biri için ayrı e-posta göndermedi.\n\nHepsini görmek için Alice'te Pano'yu açın.` |
| `auth.lockout` | `username`, `failed_logins`, `minutes` | `Sign-in blocked: {{username}}` | `After {{failed_logins}} failed sign-in attempts, Alice blocked sign-in for the account {{username}} for {{minutes}} minutes.\n\nIf this was not the account's owner, someone may be guessing the password. An administrator can end the block early on the host with the command alice admin unlock.` | `Oturum açma engellendi: {{username}}` | `{{failed_logins}} başarısız oturum açma denemesinden sonra Alice, {{username}} hesabı için oturum açmayı {{minutes}} dakika engelledi.\n\nBunlar hesabın sahibinin denemeleri değilse birisi parolayı tahmin etmeye çalışıyor olabilir. Bir yönetici engeli sunucuda alice admin unlock komutuyla daha erken kaldırabilir.` |

Notes appended by `Render` before `email.footer` (Task 7):

| Key | EN | TR |
|---|---|---|
| `email.license_note` | `Note: Alice's license has expired. Renew it to resume automatic deployment. License page: {{license_url}}` | `Not: Alice'in lisansının süresi doldu. Otomatik dağıtımı sürdürmek için lisansı yenileyin. Lisans sayfası: {{license_url}}` |
| `email.license_note_kv` | `Note: Alice's license has expired. Renew it to resume automatic deployment. License page: {{license_url}}\nKey Vault data may be outdated while the license is expired.` | `Not: Alice'in lisansının süresi doldu. Otomatik dağıtımı sürdürmek için lisansı yenileyin. Lisans sayfası: {{license_url}}\nLisansın süresi dolmuşken Key Vault verileri güncel olmayabilir.` |

### C15. Error catalogue (Tasks 14–15; `internal/api/errors.go`, `locales/common/{en,tr}.json` `errors.<reason>`, `docs/troubleshooting.md`)

| Code | Reason | HTTP | Retryable | Raised by |
|---|---|---|---|---|
| `ALC-NTF-0002` | `notify.smtp_not_configured` | 409 | no | `notify.ErrNotConfigured` |
| `ALC-NTF-0003` | `notify.smtp_connect` | 502 | yes | `notify.ErrSMTPConnect` |
| `ALC-NTF-0004` | `notify.smtp_tls` | 502 | no | `notify.ErrSMTPTLS` (not untrusted) |
| `ALC-NTF-0005` | `notify.smtp_untrusted` | 502 | no | `*notify.CertError` (params `fingerprint`, `subject`, `not_after`) |
| `ALC-NTF-0006` | `notify.smtp_auth` | 502 | no | `notify.ErrSMTPAuth` |
| `ALC-NTF-0007` | `notify.smtp_rejected` | 502 | no | `notify.ErrSMTPRejected` |
| `ALC-NTF-0008` | `notify.certificate_not_seen` | 409 | no | `notify.ErrCertNotSeen` |
| `ALC-NTF-0009` | `notify.smtp_address_refused` | 409 | no | `notify.ErrAddressRefused` |
| `ALC-SSO-0001` | `sso.discovery_failed` | 502 | yes | `*oidc.DiscoveryError` (param `cause`) |
| `ALC-SSO-0002` | `sso.admin_mapping_disabled` | 409 | no | `oidc.ErrAdminMappingDisabled` |
| `ALC-SSO-0003` | `sso.admin_mappings_exist` | 409 | no | `oidc.ErrAdminMappingsExist` |
| `ALC-SSO-0004` | `sso.public_url_missing` | 409 | no | `oidc.ErrPublicURLMissing` |
| `ALC-SSO-0005` | `sso.provider_in_use` | 409 | no | `oidc.ErrProviderInUse` |
| `ALC-SSO-0006` | `sso.no_access` | 403 | no | `LoginError{"no_access"}` |
| `ALC-SSO-0007` | `sso.groups_overage` | 403 | no | `LoginError{"groups_overage"}` |
| `ALC-SSO-0008` | `sso.email_in_use` | 403 | no | `LoginError{"email_in_use"}` |
| `ALC-SSO-0009` | `sso.idp_unreachable` | 502 | yes | `LoginError{"idp_unreachable"}` |
| `ALC-SSO-0010` | `sso.login_invalid` | 401 | no | `LoginError{"login_invalid"}` |
| `ALC-SSO-0011` | `sso.login_expired` | 401 | no | `LoginError{"login_expired"}` |
| `ALC-SSO-0012` | `sso.user_disabled` | 403 | no | `LoginError{"user_disabled"}` |
| `ALC-SSO-0013` | `sso.provider_disabled` | 403 | no | `LoginError{"provider_disabled"}` |
| `ALC-SSO-0014` | `sso.stepup_other_user` | 403 | no | `LoginError{"stepup_other_user"}` |
| `ALC-SSO-0015` | `sso.idp_error` | 401 | no | `LoginError{"idp_error"}` |
| `ALC-SSO-0016` | `sso.not_sso_user` | 409 | no | `auth.ErrNotSSOUser` |
| `ALC-RPT-0001` | `export.too_large` | 409 | no | `reports.ErrTooLarge` (param `max`) |
| `ALC-RPT-0002` | `views.limit_reached` | 409 | no | `reports.ErrViewLimit` (param `max`) |
| `ALC-RPT-0003` | `views.name_taken` | 409 | no | `reports.ErrViewName` |
| `ALC-USR-0003` | `users.sso_user` | 409 | no | `auth.ErrSSOUser` |

`notify.ErrVersion`, `oidc.ErrVersion` and `alerts` threshold version conflicts map to the existing precondition code `If-Match` answers use (the code `etag`/`ifMatch` return for a stale version, as `PATCH /rotation/policies/{id}`); `oidc.ErrNotFound` and `reports.ErrNotFound` to the existing 404; `oidc.ErrTooMany` (providers or mappings) to a 422 with `validate.OutOfRange` (`min` 1, `max` 5 or 200) on `name` or `group`; `expiry.ErrThresholds` to a 422 on `thresholds_days` (`validate.OutOfRange` with `min` 1, `max` 365).

Texts (title / cause / action):

| Reason | EN | TR |
|---|---|---|
| `notify.smtp_not_configured` | Mail settings are missing. / Alice has no mail server to send through. / Enter the mail server in Settings, then try again. | Posta ayarları eksik. / Alice'in e-posta gönderebileceği bir posta sunucusu yok. / Ayarlar'da posta sunucusunu girin, ardından yeniden deneyin. |
| `notify.smtp_connect` | Alice could not reach the mail server. / The server name or port may be wrong, the server may be down, or a firewall blocks the connection. / Check the server name and port, then send a test e-mail again. | Alice posta sunucusuna ulaşamadı. / Sunucu adı ya da bağlantı noktası yanlış olabilir, sunucu kapalı olabilir ya da bir güvenlik duvarı bağlantıyı engelliyor olabilir. / Sunucu adını ve bağlantı noktasını denetleyin, ardından yeniden test e-postası gönderin. |
| `notify.smtp_tls` | The encrypted connection to the mail server failed. / The server does not offer the selected encryption (STARTTLS or TLS), or the handshake failed. / Choose the encryption the server offers (port 587 usually uses STARTTLS, port 465 TLS), then try again. | Posta sunucusuyla şifreli bağlantı kurulamadı. / Sunucu seçilen şifrelemeyi (STARTTLS ya da TLS) sunmuyor ya da el sıkışma başarısız oldu. / Sunucunun sunduğu şifrelemeyi seçin (587 numaralı bağlantı noktası genellikle STARTTLS, 465 TLS kullanır), ardından yeniden deneyin. |
| `notify.smtp_untrusted` | Alice does not trust the mail server's certificate. / The certificate is not signed by a trusted authority, does not match the server name, or has expired. Its fingerprint is shown below. / Check with your mail administrator that the fingerprint is the server's, then choose Trust this certificate, or add your organisation's certificate authority. | Alice posta sunucusunun sertifikasına güvenmiyor. / Sertifika güvenilen bir kuruluş tarafından imzalanmamış, sunucu adıyla eşleşmiyor ya da süresi dolmuş. Parmak izi aşağıda gösteriliyor. / Parmak izinin sunucuya ait olduğunu posta yöneticinizle doğrulayın, ardından Bu sertifikaya güven'i seçin ya da kurumunuzun sertifika yetkilisini ekleyin. |
| `notify.smtp_auth` | The mail server rejected the user name or password. / The sign-in data in the mail settings are wrong or the account is locked at the mail server. / Enter the correct user name and password, then send a test e-mail again. | Posta sunucusu kullanıcı adını ya da parolayı reddetti. / Posta ayarlarındaki oturum açma bilgileri yanlış ya da hesap posta sunucusunda kilitli. / Doğru kullanıcı adını ve parolayı girin, ardından yeniden test e-postası gönderin. |
| `notify.smtp_rejected` | The mail server refused the message. / The sender or recipient address is not accepted by the server. / Check the sender address and the recipient, then try again. | Posta sunucusu iletiyi reddetti. / Gönderen ya da alıcı adresi sunucu tarafından kabul edilmiyor. / Gönderen adresini ve alıcıyı denetleyin, ardından yeniden deneyin. |
| `notify.certificate_not_seen` | Alice did not see this certificate recently. / Only a certificate that a test e-mail found in the last hour can be trusted. / Send a test e-mail again, then trust the certificate it shows. | Alice bu sertifikayı yakın zamanda görmedi. / Yalnızca son bir saat içinde bir test e-postasının bulduğu sertifikaya güvenilebilir. / Yeniden test e-postası gönderin, ardından gösterdiği sertifikaya güvenin. |
| `notify.smtp_address_refused` | Alice does not connect to this mail server address. / The server name points to a link-local or cloud metadata address, which Alice never contacts. / Use the mail server's normal address. | Alice bu posta sunucusu adresine bağlanmaz. / Sunucu adı, Alice'in hiçbir zaman bağlanmadığı bir bağlantı-yerel ya da bulut üst veri adresini gösteriyor. / Posta sunucusunun olağan adresini kullanın. |
| `sso.discovery_failed` | Alice could not read the identity provider's settings. / Its discovery document or key list could not be fetched or is not valid (reason: {{cause}}). / Check the issuer address and, for a private certificate authority, its certificate, then try again. | Alice kimlik sağlayıcının ayarlarını okuyamadı. / Keşif belgesi ya da anahtar listesi alınamadı veya geçerli değil (neden: {{cause}}). / Yayıncı adresini ve özel bir sertifika yetkilisi kullanılıyorsa onun sertifikasını denetleyin, ardından yeniden deneyin. |
| `sso.admin_mapping_disabled` | A group cannot be mapped to Administrator. / SSO users may be Admin is switched off, so single sign-on users can be at most Operators. / Switch on SSO users may be Admin first, or map the group to another role. | Bir grup Yönetici rolüne eşlenemez. / SSO kullanıcıları Yönetici olabilir ayarı kapalı; bu nedenle çoklu oturum açma kullanıcıları en çok Operatör olabilir. / Önce SSO kullanıcıları Yönetici olabilir ayarını açın ya da grubu başka bir role eşleyin. |
| `sso.admin_mappings_exist` | SSO users may be Admin cannot be switched off yet. / Some groups are still mapped to Administrator. / Remove those mappings, then switch the setting off. | SSO kullanıcıları Yönetici olabilir ayarı henüz kapatılamaz. / Bazı gruplar hâlâ Yönetici rolüne eşli. / Bu eşlemeleri kaldırın, ardından ayarı kapatın. |
| `sso.public_url_missing` | Alice's address is not set. / The identity provider sends users back to Alice's address, and Alice does not know it yet. / Enter Alice's address under Settings, General, then try again. | Alice'in adresi ayarlanmamış. / Kimlik sağlayıcı kullanıcıları Alice'in adresine geri gönderir ve Alice bu adresi henüz bilmiyor. / Ayarlar, Genel bölümünde Alice'in adresini girin, ardından yeniden deneyin. |
| `sso.provider_in_use` | This identity provider still has users. / People have signed in through it, so it cannot be deleted. / Switch the provider off instead, or remove its users first. | Bu kimlik sağlayıcının hâlâ kullanıcıları var. / Kişiler bu sağlayıcıyla oturum açtı; bu nedenle silinemez. / Bunun yerine sağlayıcıyı kapatın ya da önce kullanıcılarını kaldırın. |
| `sso.no_access` | Your account has no access to Alice, contact your administrator. / You signed in at your identity provider, but none of your groups is given a role in Alice. / Ask your administrator to add your group to Alice's group mappings. | Hesabınızın Alice'e erişimi yok, yöneticinize başvurun. / Kimlik sağlayıcınızda oturum açtınız, ancak gruplarınızdan hiçbirine Alice'te bir rol verilmemiş. / Yöneticinizden grubunuzu Alice'in grup eşlemelerine eklemesini isteyin. |
| `sso.groups_overage` | Your identity provider did not send your groups. / You are a member of more groups than it puts into a sign-in, so it left them all out. / Ask your administrator to send only the groups assigned to Alice's application (Microsoft Entra ID: "Groups assigned to the application"). | Kimlik sağlayıcınız gruplarınızı göndermedi. / Bir oturum açmaya koyabileceğinden daha fazla grubun üyesisiniz; bu nedenle hepsini dışarıda bıraktı. / Yöneticinizden yalnızca Alice uygulamasına atanmış grupların gönderilmesini istemesini isteyin (Microsoft Entra ID: "Uygulamaya atanmış gruplar"). |
| `sso.email_in_use` | Single sign-on was refused for this e-mail address. / A local Alice account already uses this e-mail address, and Alice never joins a single sign-on identity to a local account. / Ask your administrator to change or remove the local account's e-mail address, then sign in again. | Bu e-posta adresi için çoklu oturum açma reddedildi. / Yerel bir Alice hesabı bu e-posta adresini zaten kullanıyor ve Alice bir çoklu oturum açma kimliğini hiçbir zaman yerel bir hesapla birleştirmez. / Yöneticinizden yerel hesabın e-posta adresini değiştirmesini ya da kaldırmasını isteyin, ardından yeniden oturum açın. |
| `sso.idp_unreachable` | Alice could not reach the identity provider. / The identity provider is down or the network path to it is blocked. / Try again later. Administrators can still sign in with their local account and authenticator code. | Alice kimlik sağlayıcıya ulaşamadı. / Kimlik sağlayıcı kapalı ya da ona giden ağ yolu engelli. / Daha sonra yeniden deneyin. Yöneticiler yerel hesaplarıyla ve doğrulama kodlarıyla oturum açmaya devam edebilir. |
| `sso.login_invalid` | The sign-in answer of the identity provider was not accepted. / Alice could not confirm that the answer really came from your identity provider for this sign-in. / Sign in again. If this keeps happening, ask your administrator to check the single sign-on settings. | Kimlik sağlayıcının oturum açma yanıtı kabul edilmedi. / Alice yanıtın bu oturum açma için gerçekten kimlik sağlayıcınızdan geldiğini doğrulayamadı. / Yeniden oturum açın. Bu durum sürerse yöneticinizden çoklu oturum açma ayarlarını denetlemesini isteyin. |
| `sso.login_expired` | This sign-in has expired. / A sign-in must be finished within 10 minutes and in the same browser, and each one can be used only once. / Start the sign-in again. | Bu oturum açmanın süresi doldu. / Bir oturum açma 10 dakika içinde ve aynı tarayıcıda tamamlanmalıdır ve her biri yalnızca bir kez kullanılabilir. / Oturum açmayı yeniden başlatın. |
| `sso.user_disabled` | Your Alice account is disabled. / An administrator disabled your account. / Contact your administrator. | Alice hesabınız devre dışı. / Bir yönetici hesabınızı devre dışı bıraktı. / Yöneticinize başvurun. |
| `sso.provider_disabled` | This sign-in option is switched off. / An administrator switched off this identity provider in Alice. / Use another sign-in option or contact your administrator. | Bu oturum açma seçeneği kapalı. / Bir yönetici bu kimlik sağlayıcıyı Alice'te kapattı. / Başka bir oturum açma seçeneği kullanın ya da yöneticinize başvurun. |
| `sso.stepup_other_user` | The confirmation was made with another account. / You confirmed at the identity provider as a different person than the one signed in to Alice. / Confirm again with your own account. | Onay başka bir hesapla yapıldı. / Kimlik sağlayıcıda Alice'te oturum açmış olan kişiden farklı biri olarak onay verdiniz. / Kendi hesabınızla yeniden onaylayın. |
| `sso.idp_error` | The identity provider ended the sign-in. / It answered with an error, for example because the sign-in was cancelled or Alice's address is not registered there. / Try again. If this keeps happening, ask your administrator to check that Alice's address is registered at the identity provider. | Kimlik sağlayıcı oturum açmayı sonlandırdı. / Bir hatayla yanıt verdi; örneğin oturum açma iptal edildi ya da Alice'in adresi orada kayıtlı değil. / Yeniden deneyin. Bu durum sürerse yöneticinizden Alice'in adresinin kimlik sağlayıcıda kayıtlı olduğunu denetlemesini isteyin. |
| `sso.not_sso_user` | Your account does not use single sign-on. / Only single sign-on users confirm at the identity provider. / Confirm with your authenticator code instead. | Hesabınız çoklu oturum açma kullanmıyor. / Yalnızca çoklu oturum açma kullanıcıları kimlik sağlayıcıda onay verir. / Bunun yerine doğrulama kodunuzla onaylayın. |
| `export.too_large` | The export is too large. / An export holds at most {{max}} rows, and this filter matches more. / Narrow the filter, for example by server or expiry, then export again. | Dışa aktarım çok büyük. / Bir dışa aktarım en çok {{max}} satır içerir ve bu filtre daha fazlasıyla eşleşiyor. / Filtreyi daraltın, örneğin sunucuya ya da süre dolumuna göre, ardından yeniden dışa aktarın. |
| `views.limit_reached` | You have reached the limit of saved views. / A person can keep at most {{max}} saved views. / Delete a view you no longer need, then save again. | Kayıtlı görünüm sınırına ulaştınız. / Bir kişi en çok {{max}} kayıtlı görünüm tutabilir. / Artık gerekmeyen bir görünümü silin, ardından yeniden kaydedin. |
| `views.name_taken` | A saved view with this name already exists. / Each of your views on a page needs its own name. / Choose another name. | Bu ada sahip bir kayıtlı görünüm zaten var. / Bir sayfadaki görünümlerinizin her birinin kendi adı olmalıdır. / Başka bir ad seçin. |
| `users.sso_user` | This change is not possible for a single sign-on user. / The role of a single sign-on user comes from their groups, and they have no Alice password or authenticator. / Change the user's groups at the identity provider; disable the user here if they must stop at once. | Bu değişiklik çoklu oturum açma kullanıcısı için yapılamaz. / Çoklu oturum açma kullanıcısının rolü gruplarından gelir ve Alice parolası ya da doğrulayıcısı yoktur. / Kullanıcının gruplarını kimlik sağlayıcıda değiştirin; hemen durması gerekiyorsa kullanıcıyı burada devre dışı bırakın. |

### C16. Audit actions (written by Tasks 6–12; labels in `web/src/locales/{en,tr}.json` under `audit.actions.<action with dots as underscores>`, added early by Task 18 so `labels.test.ts` stays green while the backend tasks land)

| Action | Actor | Details | EN label | TR label |
|---|---|---|---|---|
| `settings.smtp_changed` | user | `host`, `port`, `tls_mode`, `from`, `username`, `auth_changed`, `ca_count` | Mail settings changed | Posta ayarları değiştirildi |
| `settings.smtp_removed` | user | — | Mail settings removed | Posta ayarları kaldırıldı |
| `settings.smtp_imported` | system | `host`, `port`, `tls_mode` | Mail settings imported from the environment | Posta ayarları ortam değişkenlerinden alındı |
| `settings.smtp_tested` | user | `to`, `result` (`sent`\|`failed`), `reason` (the closed `notify.ErrorCode` label or `smtp.untrusted`), `fingerprint` (untrusted only) | Test e-mail sent | Test e-postası gönderildi |
| `settings.smtp_trusted` / `settings.smtp_untrusted` | user | `fingerprint`, `subject` | Mail server certificate trusted / no longer trusted | Posta sunucusu sertifikasına güvenildi / artık güvenilmiyor |
| `settings.recipients_changed` | user | `administrators`, `address_count` | Alert recipients changed | Uyarı alıcıları değiştirildi |
| `settings.thresholds_changed` | user | `thresholds` (`60,30,14,7,1`) | Alert thresholds changed | Uyarı eşikleri değiştirildi |
| `settings.general_changed` | user | `public_url`, `days` | General settings changed | Genel ayarlar değiştirildi |
| `alert.sent` | system | `kind`, `object_id`, `threshold_days`, `expires_at`, `locked`, `emailed` | Expiry notice recorded | Süre dolumu bildirimi kaydedildi |
| `alert.summarized` | system | `kind`, `suppressed_count` | Expiry notices summarized | Süre dolumu bildirimleri özetlendi |
| `inventory.exported` | user/token | `kind` (`certificates`\|`ssh_keys`), `format` (`csv`), the filter fields given (`target_id`, `source`, `expiry`, `q`, `os_user`, `flag`, `missing`) | Inventory exported | Envanter dışa aktarıldı |
| `sso.provider_created` / `sso.provider_changed` / `sso.provider_deleted` | user | `provider_id`, `name`, `issuer`, `client_id`, `scopes`, `groups_claim`, `ca_set`, `enabled`, `client_auth_replaced` (changed only) | Identity provider added / changed / deleted | Kimlik sağlayıcı eklendi / değiştirildi / silindi |
| `sso.provider_refreshed` | user | `provider_id` | Identity provider settings read again | Kimlik sağlayıcı ayarları yeniden okundu |
| `sso.mapping_created` / `sso.mapping_deleted` | user | `mapping_id`, `provider_id`, `group`, `role` | Group mapping added / removed | Grup eşlemesi eklendi / kaldırıldı |
| `sso.mapping.denied` | user | `provider_id`, `group`, `role`, `reason` (`admin_disabled`) | Group mapping refused | Grup eşlemesi reddedildi |
| `sso.admin_role_allowed` / `sso.admin_role_disallowed` | user | `demoted_count`, `ended_count` (disallowed only) | SSO users may be Admin switched on / off | SSO kullanıcıları Yönetici olabilir açıldı / kapatıldı |
| `auth.login` (existing) | user | `method` `oidc`, `provider_id`, `role` | (existing label) | (existing label) |
| `auth.stepup` (existing) | user | `method` `oidc` | (existing label) | (existing label) |
| `auth.oidc.denied` | oidc | `provider_id`, `reason` (C15 SSO reason without `sso.`) | Single sign-on refused | Çoklu oturum açma reddedildi |
| `user.provisioned` | oidc | `provider_id`, `role` | User created by single sign-on | Kullanıcı çoklu oturum açmayla oluşturuldu |
| `user.role_synced` | oidc | `from_role`, `to_role` | Role updated from the identity provider | Rol kimlik sağlayıcıdan güncellendi |
| `user.sessions_ended` | system or user | `reason`, `ended_count` | Sessions ended | Oturumlar sonlandırıldı |
| `user.demoted` | user | `from_role`, `to_role` | SSO administrator demoted | SSO yöneticisinin rolü düşürüldü |

The `oidc` actor's `Name` is the identity's user name (or `sso-…` when none) and its `ID` the user's ID once known (else nil).

### C17. The e2e seed data set (`POST /test/seed/dashboard`, Task 13)

Inserted through the owner pool with the `internal/testutil/seed` functions (Task 8) and the e2e clock's `now`: plain certificate rows (`uploaded`, no PEM — the journey lists, filters and exports them and never opens one) with one live `certificate_locations` row each on the target named:

| Target (type linux, status) | Certificates (CN, expires) |
|---|---|
| `seed-web-1` (`ok`) | `www.seed.test` (now + 7 days − 1 hour), `api.seed.test` (now + 5 days), `old.seed.test` (now − 2 days), `shop.seed.test` (now + 20 days) |
| `seed-web-2` (`ok`) | `mail.seed.test` (now + 25 days), `docs.seed.test` (now + 45 days), `blog.seed.test` (now + 200 days) |
| `seed-web-3` (`host_key_changed`) | `intra.seed.test` (now + 29 days) |
| — (uploaded, no location: not monitored) | `spare.seed.test` (now + 3 days) |

The location of `www.seed.test` has `servers = [{"names": ["www.seed.test"], …}]` (the website name of owner step 2). Two finished deployments of `api.seed.test` to `seed-web-1`, both `failed` with error `ngx.reload_failed`: one at now − 1 day (inside the 7-day window) and one at now − 8 days (outside it). The answer:

```json
{"certificates": {"monitored": 8, "expired": 1, "within_7": 2, "within_30": 3, "within_60": 1},
 "targets": {"total": 3, "ok": 2, "host_key_changed": 1},
 "deployments": {"failed_7d": 1},
 "expiring_30": ["old.seed.test", "api.seed.test", "www.seed.test", "shop.seed.test", "mail.seed.test", "intra.seed.test"],
 "server_filter": {"target": "seed-web-1", "expiry_30": ["old.seed.test", "api.seed.test", "www.seed.test", "shop.seed.test"]}}
```

(`within_30` counts `shop`, `mail`, `intra`; `spare` is listed by the certificate page's 30-day filter but is not monitored, so the dashboard does not count it and the alert scan never emails it; the certificate page's `expiry=30` filter for all servers lists `old`, `spare`, `api`, `www`, `shop`, `mail`, `intra` — seven rows.)

### C18. UI copy (Tasks 18–19; `web/src/locales/{en,tr}.json`)

| Key | EN | TR |
|---|---|---|
| `nav.dashboard` | Dashboard | Pano |
| `nav.settings` | Settings | Ayarlar |
| `dashboard.title` | Dashboard | Pano |
| `dashboard.welcome` | Welcome, {{name}} | Hoş geldiniz, {{name}} |
| `dashboard.expiringSoon` | Expiring soon | Süresi yakında dolacaklar |
| `dashboard.expired` | Expired | Süresi doldu |
| `dashboard.within7` | Within 7 days | 7 gün içinde |
| `dashboard.within30` | In 8 to 30 days | 8 ile 30 gün arasında |
| `dashboard.within60` | In 31 to 60 days | 31 ile 60 gün arasında |
| `dashboard.monitored` | Certificates in use: {{count}} | Kullanımdaki sertifikalar: {{count}} |
| `dashboard.daysLeft_one` | {{count}} day left | {{count}} gün kaldı |
| `dashboard.daysLeft_other` | {{count}} days left | {{count}} gün kaldı |
| `dashboard.expiredOn` | Expired | Süresi doldu |
| `dashboard.noneExpiring` | Nothing expires within 30 days. | 30 gün içinde süresi dolan bir şey yok. |
| `dashboard.failedDeployments` | Failed deployments (last 7 days) | Başarısız dağıtımlar (son 7 gün) |
| `dashboard.targetsByStatus` | Servers and vaults by status | Durumlarına göre sunucular ve kasalar |
| `dashboard.license` | License | Lisans |
| `dashboard.rotationUpcoming` | Upcoming rotations | Yaklaşan yenilemeler |
| `dashboard.needsAttention` | Needs attention | İlgi bekleyenler |
| `dashboard.auditHead` | Audit log head | Denetim kaydının son durumu |
| `dashboard.auditHeadHelp` | Write down this value regularly outside Alice: it lets you prove later that no entry was removed. | Bu değeri düzenli olarak Alice dışında bir yere not edin: daha sonra hiçbir kaydın silinmediğini kanıtlamanızı sağlar. |
| `dashboard.kvExpiring` | Key Vault items expiring within 30 days: {{count}} | 30 gün içinde süresi dolacak Key Vault öğeleri: {{count}} |
| `notifications.failingTitle` | E-mails could not be sent | E-postalar gönderilemedi |
| `notifications.failingBody` | The last {{count}} attempts to send an e-mail failed. Last error: {{code}}. Alerts are still shown on the Dashboard. | Son {{count}} e-posta gönderme denemesi başarısız oldu. Son hata: {{code}}. Uyarılar Pano'da gösterilmeye devam ediyor. |
| `filters.export` | Export | Dışa aktar |
| `filters.views` | Saved views | Kayıtlı görünümler |
| `filters.saveView` | Save view | Görünümü kaydet |
| `filters.viewName` | Name of the view | Görünümün adı |
| `filters.deleteView` | Delete view {{name}} | {{name}} görünümünü sil |
| `filters.clear` | Clear filters | Filtreleri temizle |
| `certificates.expiry7` | Within 7 days | 7 gün içinde |
| `certificates.expiry14` | Within 14 days | 14 gün içinde |
| `certificates.expiry90` | Within 90 days | 90 gün içinde |
| `certificates.expiry30` (existing, unchanged) | Within 30 days | (existing) |
| `certificates.sourceAzureKv` | Key Vault | Key Vault |
| `settings.title` | Settings | Ayarlar |
| `settings.tabs.mail` | Email | E-posta |
| `settings.tabs.recipients` | Recipients | Alıcılar |
| `settings.tabs.alerts` | Alerts | Uyarılar |
| `settings.tabs.general` | General | Genel |
| `settings.tabs.sso` | Single sign-on | Çoklu oturum açma |
| `settings.mail.host` | Mail server | Posta sunucusu |
| `settings.mail.port` | Port | Bağlantı noktası |
| `settings.mail.tlsMode` | Encryption | Şifreleme |
| `settings.mail.from` | Sender address | Gönderen adresi |
| `settings.mail.username` | User name (optional) | Kullanıcı adı (isteğe bağlı) |
| `settings.mail.password` | Password | Parola |
| `settings.mail.passwordKept` | A password is stored. Leave the field empty to keep it. | Bir parola kayıtlı. Korumak için alanı boş bırakın. |
| `settings.mail.save` | Save mail settings | Posta ayarlarını kaydet |
| `settings.mail.testTo` | Send the test to | Testin gönderileceği adres |
| `settings.mail.sendTest` | Send test e-mail | Test e-postası gönder |
| `settings.mail.testSent` | The test e-mail was sent to {{to}}. | Test e-postası {{to}} adresine gönderildi. |
| `settings.mail.untrustedTitle` | The mail server's certificate is not trusted | Posta sunucusunun sertifikasına güvenilmiyor |
| `settings.mail.fingerprint` | Fingerprint (SHA-256) | Parmak izi (SHA-256) |
| `settings.mail.trust` | Trust this certificate | Bu sertifikaya güven |
| `settings.mail.trusted` | Trusted certificate: {{fingerprint}} | Güvenilen sertifika: {{fingerprint}} |
| `settings.mail.untrust` | Stop trusting this certificate | Bu sertifikaya güvenmeyi bırak |
| `settings.recipients.administrators` | Send alerts to every administrator with an e-mail address | Uyarıları e-posta adresi olan her yöneticiye gönder |
| `settings.recipients.addresses` | More addresses | Diğer adresler |
| `settings.recipients.add` | Add address | Adres ekle |
| `settings.recipients.save` | Save recipients | Alıcıları kaydet |
| `settings.alerts.thresholds` | Send an e-mail this many days before an expiry | Süre dolumundan bu kadar gün önce e-posta gönder |
| `settings.alerts.save` | Save alert thresholds | Uyarı eşiklerini kaydet |
| `settings.general.publicUrl` | Alice's address | Alice'in adresi |
| `settings.general.publicUrlHelp` | The address people use to open Alice, for example https://alice.example.com. Single sign-on and e-mails use it. | Kişilerin Alice'i açmak için kullandığı adres, örneğin https://alice.example.com. Çoklu oturum açma ve e-postalar bu adresi kullanır. |
| `settings.general.retention` | Keep the private key of a retired SSH key for this many days | Kullanımdan kaldırılan bir SSH anahtarının özel anahtarını bu kadar gün sakla |
| `settings.general.save` | Save general settings | Genel ayarları kaydet |
| `settings.saved` | Saved. | Kaydedildi. |
| `sso.providers` | Identity providers | Kimlik sağlayıcılar |
| `sso.addProvider` | Add identity provider | Kimlik sağlayıcı ekle |
| `sso.name` | Name shown on the sign-in page | Oturum açma sayfasında gösterilen ad |
| `sso.issuer` | Issuer address | Yayıncı adresi |
| `sso.clientId` | Client ID | İstemci kimliği |
| `sso.clientSecret` | Client secret | İstemci parolası |
| `sso.groupsClaim` | Groups claim | Grup talebi |
| `sso.caPem` | Certificate authority (optional, PEM) | Sertifika yetkilisi (isteğe bağlı, PEM) |
| `sso.enabled` | Allow sign-in with this provider | Bu sağlayıcıyla oturum açmaya izin ver |
| `sso.redirectUri` | Redirect address to register at the provider: {{uri}} | Sağlayıcıda kaydedilecek yönlendirme adresi: {{uri}} |
| `sso.save` | Save identity provider | Kimlik sağlayıcıyı kaydet |
| `sso.refresh` | Read the provider's settings again | Sağlayıcının ayarlarını yeniden oku |
| `sso.mappings` | Group mappings | Grup eşlemeleri |
| `sso.group` | Group | Grup |
| `sso.role` | Role in Alice | Alice'teki rol |
| `sso.addMapping` | Map group | Grubu eşle |
| `sso.removeMapping` | Remove mapping for {{group}} | {{group}} eşlemesini kaldır |
| `sso.allowAdmin` | SSO users may be Admin | SSO kullanıcıları Yönetici olabilir |
| `sso.allowAdminHelp` | Off by default: single sign-on users can then be at most Operators. The local administrator always signs in with the authenticator code. | Varsayılan olarak kapalı: çoklu oturum açma kullanıcıları bu durumda en çok Operatör olabilir. Yerel yönetici her zaman doğrulama koduyla oturum açar. |
| `sso.mfaNote` | Users who sign in with single sign-on confirm their identity at the identity provider. Make sure it requires multi-factor authentication. | Çoklu oturum açmayla oturum açan kullanıcılar kimliklerini kimlik sağlayıcıda doğrular. Kimlik sağlayıcının çok adımlı doğrulama istediğinden emin olun. |
| `login.ssoWith` | Sign in with {{name}} | {{name}} ile oturum açın |
| `login.or` | or | ya da |
| `stepUp.ssoTitle` | Confirm at your identity provider | Kimlik sağlayıcınızda onaylayın |
| `stepUp.ssoAction` | Continue to {{name}} | {{name}} sayfasına devam et |
| `users.sso` | Single sign-on | Çoklu oturum açma |
| `jobs.types.alerts.scan` (nested: `jobs` → `types` → `alerts` → `scan`, the lookup `labels.test.ts` uses) | Expiry check | Süre dolumu denetimi |

---

### Task 1: `internal/alerts/expiry`: thresholds, the due notice, catch-up, buckets; Phase 7 archtest rules

**Files:**
- Create: `internal/alerts/expiry/expiry.go`, `internal/alerts/expiry/expiry_test.go`
- Modify: `internal/archtest/arch_test.go` (every Phase 7 rule of Global Constraints, `pureDeniedURL`, the `denied`/`deniedStd` entries, `TestAllowed` cases)

**Interfaces:**
- Consumes: nothing.
- Produces: C3 exactly; the archtest rules every later task's packages need.

- [ ] **Step 1: Write the failing tests**

`internal/alerts/expiry/expiry_test.go`:

```go
package expiry

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var t0 = time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)

func days(n float64) time.Duration { return time.Duration(n * float64(24*time.Hour)) }

func TestNormalize(t *testing.T) {
	got, err := Normalize([]int{7, 60, 1, 30, 14})
	require.NoError(t, err)
	assert.Equal(t, []int{60, 30, 14, 7, 1}, got)
	in := []int{1, 2}
	got, err = Normalize(in)
	require.NoError(t, err)
	assert.Equal(t, []int{2, 1}, got)
	assert.Equal(t, []int{1, 2}, in, "the input is not changed")
	for _, bad := range [][]int{nil, {}, {0}, {-1}, {366}, {7, 7}, {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}} {
		_, err := Normalize(bad)
		assert.ErrorIs(t, err, ErrThresholds, "%v", bad)
	}
	got, err = Normalize([]int{365, 1, 2, 3, 4, 5, 6, 7, 8, 9})
	require.NoError(t, err)
	assert.Len(t, got, MaxThresholds)
	assert.Equal(t, []int{60, 30, 14, 7, 1}, DefaultThresholds)
}

func TestLevel(t *testing.T) {
	th := DefaultThresholds
	cases := []struct {
		left  time.Duration
		level int
		ok    bool
	}{
		{days(61), 0, false},
		{days(60) + time.Second, 0, false},
		{days(60), 60, true},
		{days(31), 60, true},
		{days(30), 30, true},
		{days(14.5), 30, true},
		{days(14), 14, true},
		{days(7), 7, true},
		{days(1) + time.Second, 7, true},
		{days(1), 1, true},
		{time.Second, 1, true},
		{0, Expired, true},
		{-days(400), Expired, true},
	}
	for _, c := range cases {
		level, ok := Level(t0.Add(c.left), t0, th)
		assert.Equal(t, c.ok, ok, "left %v", c.left)
		assert.Equal(t, c.level, level, "left %v", c.left)
	}
	level, ok := Level(t0.Add(days(10)), t0, []int{7, 30}) // order of the slice does not matter
	assert.True(t, ok)
	assert.Equal(t, 30, level)
}

func TestDueTable(t *testing.T) {
	th := DefaultThresholds
	cases := []struct {
		name  string
		left  time.Duration
		sent  []int
		want  int
		isDue bool
	}{
		{"nothing reached", days(90), nil, 0, false},
		{"first threshold", days(59), nil, 60, true},
		{"already sent at this level", days(59), []int{60}, 0, false},
		{"next level after an earlier one", days(29), []int{60}, 30, true},
		{"a more urgent one was sent: never the less urgent", days(29), []int{7}, 0, false},
		{"catch-up: only the most urgent reached level", days(13), []int{60}, 14, true},
		{"catch-up with nothing sent", days(0.5), nil, 1, true},
		{"expired after the last threshold", -time.Hour, []int{60, 30, 14, 7, 1}, Expired, true},
		{"expired sent once", -days(3), []int{1, Expired}, 0, false},
		{"expired with nothing sent", -days(30), nil, Expired, true},
	}
	for _, c := range cases {
		got, ok := Due(t0.Add(c.left), t0, th, c.sent)
		assert.Equal(t, c.isDue, ok, c.name)
		assert.Equal(t, c.want, got, c.name)
	}
}

// Review Focus 2: hourly ticks over 70 days send each threshold once, in order, and the expired notice once.
func TestHourlyTicksSendEachThresholdOnce(t *testing.T) {
	expires := t0.Add(days(65))
	var sent []int
	for now := t0; now.Before(expires.Add(days(5))); now = now.Add(time.Hour) {
		if level, ok := Due(expires, now, DefaultThresholds, sent); ok {
			sent = append(sent, level)
		}
	}
	assert.Equal(t, []int{60, 30, 14, 7, 1, Expired}, sent)
}

// Review Focus 2: Alice down from 31 to 13 days before the expiry sends the 14-day notice only (L-16's rule).
func TestDowntimeSendsOnlyTheMostUrgent(t *testing.T) {
	expires := t0.Add(days(70))
	var sent []int
	tick := func(now time.Time) {
		if level, ok := Due(expires, now, DefaultThresholds, sent); ok {
			sent = append(sent, level)
		}
	}
	for now := t0; now.Before(expires.Add(-days(31))); now = now.Add(time.Hour) {
		tick(now)
	}
	require.Equal(t, []int{60}, sent)
	for now := expires.Add(-days(13)); now.Before(expires.Add(days(1))); now = now.Add(time.Hour) {
		tick(now)
	}
	assert.Equal(t, []int{60, 14, 7, 1, Expired}, sent, "30 is never sent after the downtime")
}

// Review Focus 2: editing thresholds mid-series never resends a level and never sends a less urgent one; a new,
// more urgent level is sent once.
func TestThresholdEditsNeverResend(t *testing.T) {
	expires := t0.Add(days(40))
	sent := []int{60} // sent at 55 days left
	_, ok := Due(expires, t0.Add(days(1)), []int{90, 60, 30}, sent) // 39 days left: level 60, already sent
	assert.False(t, ok, "adding 90 (less urgent) sends nothing")
	level, ok := Due(expires, t0.Add(days(1)), []int{90, 60, 45, 30}, sent) // level 45, more urgent than 60
	require.True(t, ok)
	assert.Equal(t, 45, level)
	sent = append(sent, level)
	_, ok = Due(expires, t0.Add(days(2)), []int{90, 60, 45, 30}, sent)
	assert.False(t, ok, "45 is not sent twice")
	_, ok = Due(expires, t0.Add(days(3)), []int{60, 30}, sent)
	assert.False(t, ok, "removing 45 again sends 60 not again")
}

func TestDaysLeft(t *testing.T) {
	assert.Equal(t, 7, DaysLeft(t0.Add(days(7)), t0))
	assert.Equal(t, 7, DaysLeft(t0.Add(days(7)-time.Hour), t0))
	assert.Equal(t, 1, DaysLeft(t0.Add(time.Second), t0))
	assert.Equal(t, 0, DaysLeft(t0, t0))
	assert.Equal(t, 0, DaysLeft(t0.Add(-days(2)), t0))
}

func TestBucketOf(t *testing.T) {
	cases := map[time.Duration]Bucket{
		-time.Second: BucketExpired, 0: BucketExpired, time.Second: Bucket7, days(7): Bucket7,
		days(7) + time.Second: Bucket30, days(30): Bucket30, days(30) + time.Second: Bucket60, days(60): Bucket60,
		days(60) + time.Second: BucketLater,
	}
	for left, want := range cases {
		assert.Equal(t, want, BucketOf(t0.Add(left), t0), "left %v", left)
	}
}

func TestHorizon(t *testing.T) {
	assert.Equal(t, days(60), Horizon(DefaultThresholds))
	assert.Equal(t, days(365), Horizon([]int{1, 365, 7}))
	assert.Equal(t, time.Duration(0), Horizon(nil))
}
```

`internal/archtest/arch_test.go`: add to `rules` (after the `sshkeys` block, with a comment "Phase 7 (R42 row 1): the alert module, the read-only reports module and the pure packages"):

```go
	"alice/internal/alerts/...":       {platform, "alice/internal/audit/...", "alice/internal/license/...", "alice/internal/notify/..."},
	"alice/internal/alerts/expiry":    {platform},
	"alice/internal/reports/...": {platform, "alice/internal/audit/...", "alice/internal/license/...", "alice/internal/inventory/...",
		"alice/internal/notify/...", "alice/internal/alerts/...", "alice/internal/jobs/...", "alice/internal/rbac/..."},
	"alice/internal/auth/oidc/claims": {platform, "alice/internal/rbac/..."},
```

add `"alice/internal/audit/..."` to the `notify` rule and `"alice/internal/alerts/...", "alice/internal/reports/..."` to the `api` rule; add to `denied`:

```go
	"alice/internal/alerts/expiry":    {"alice/internal/platform/db/..."},
	"alice/internal/auth/oidc/claims": {"alice/internal/platform/db/..."},
	"alice/internal/platform/csvx":    {"alice/internal/platform/db/..."},
```

and to `deniedStd` (with the new list, `pureDenied` without `net/url`: `claims` parses URLs, which does no I/O):

```go
	"alice/internal/alerts/expiry":    pureDenied,
	"alice/internal/platform/csvx":    pureDenied,
	"alice/internal/auth/oidc/claims": pureDeniedURL,
```

```go
var pureDeniedURL = []string{"os/...", "net", "net/http/...", "net/rpc/...", "net/smtp", "net/textproto", "net/mail",
	"database/...", "syscall/...", "io/ioutil", "io/fs", "plugin", "unsafe", "runtime/...", "internal/..."}
```

`TestAllowed` gains:

```go
		{"alerts to notify allowed", "alice/internal/alerts", "alice/internal/notify", true},
		{"alerts to inventory denied", "alice/internal/alerts", "alice/internal/inventory", false},
		{"alerts to reports denied", "alice/internal/alerts", "alice/internal/reports", false},
		{"expiry to platform/db denied", "alice/internal/alerts/expiry", "alice/internal/platform/db", false},
		{"expiry to alerts denied", "alice/internal/alerts/expiry", "alice/internal/alerts", false},
		{"expiry to os denied", "alice/internal/alerts/expiry", "os", false},
		{"reports to alerts allowed", "alice/internal/reports", "alice/internal/alerts", true},
		{"reports to jobs allowed", "alice/internal/reports", "alice/internal/jobs", true},
		{"reports to auth denied", "alice/internal/reports", "alice/internal/auth", false},
		{"reports to api denied", "alice/internal/reports", "alice/internal/api", false},
		{"claims to rbac allowed", "alice/internal/auth/oidc/claims", "alice/internal/rbac", true},
		{"claims to net/url allowed", "alice/internal/auth/oidc/claims", "net/url", true},
		{"claims to net/http denied", "alice/internal/auth/oidc/claims", "net/http", false},
		{"claims to secrets denied", "alice/internal/auth/oidc/claims", "alice/internal/secrets", false},
		{"oidc to auth allowed", "alice/internal/auth/oidc", "alice/internal/auth", true},
		{"oidc to inventory denied", "alice/internal/auth/oidc", "alice/internal/inventory", false},
		{"csvx to os denied", "alice/internal/platform/csvx", "os", false},
		{"notify to audit allowed", "alice/internal/notify", "alice/internal/audit", true},
		{"notify to inventory denied", "alice/internal/notify", "alice/internal/inventory", false},
		{"api to reports allowed", "alice/internal/api", "alice/internal/reports", true},
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/alerts/expiry/ ./internal/archtest/`
Expected: FAIL — `expiry`: no non-test Go files / undefined `Normalize`; `archtest`: the new `TestAllowed` cases fail (no rule for `alice/internal/alerts`).

- [ ] **Step 3: Write the implementation**

`internal/alerts/expiry/expiry.go`:

```go
// Package expiry decides which expiry notice is due (spec §26.9, R2; R42 rows 4 and 5). It is pure: the caller
// passes every time and the thresholds; nothing is read or written. One rule gives both "no duplicates" and
// "catch-up after downtime": only the most urgent reached level is ever due, and only when no notice at that level
// or a more urgent one was sent for the same expiry instant.
package expiry

import (
	"errors"
	"slices"
	"time"
)

// DefaultThresholds are the days before an expiry at which a notice is sent (R2).
var DefaultThresholds = []int{60, 30, 14, 7, 1}

const (
	// MaxThresholds and MaxThresholdDays bound the thresholds setting.
	MaxThresholds    = 10
	MaxThresholdDays = 365
	// Expired is the level of the notice sent once an item has expired; it is more urgent than every threshold.
	Expired = 0

	day = 24 * time.Hour
)

// ErrThresholds refuses a thresholds setting.
var ErrThresholds = errors.New("expiry: thresholds must be 1 to 10 different whole days from 1 to 365")

// Normalize validates days and returns a new slice sorted from the largest to the smallest.
func Normalize(days []int) ([]int, error) {
	if len(days) == 0 || len(days) > MaxThresholds {
		return nil, ErrThresholds
	}
	out := slices.Clone(days)
	slices.Sort(out)
	for i, d := range out {
		if d < 1 || d > MaxThresholdDays || (i > 0 && out[i-1] == d) {
			return nil, ErrThresholds
		}
	}
	slices.Reverse(out)
	return out, nil
}

// Level is the most urgent level an item that expires at expiresAt has reached at now: Expired once
// expiresAt <= now, else the smallest threshold t with expiresAt - now <= t days. ok is false when the item
// has reached no threshold yet.
func Level(expiresAt, now time.Time, thresholds []int) (level int, ok bool) {
	left := expiresAt.Sub(now)
	if left <= 0 {
		return Expired, true
	}
	for _, t := range thresholds {
		if left <= time.Duration(t)*day && (!ok || t < level) {
			level, ok = t, true
		}
	}
	return level, ok
}

// Due returns the notice to send at now. sent holds the levels already recorded for the same expiry instant.
// Nothing is due when a notice at the reached level or a more urgent one (a smaller number) was sent: after
// downtime the skipped, less urgent notices are never sent, and no level is sent twice.
func Due(expiresAt, now time.Time, thresholds, sent []int) (int, bool) {
	level, ok := Level(expiresAt, now, thresholds)
	if !ok {
		return 0, false
	}
	for _, s := range sent {
		if s <= level {
			return 0, false
		}
	}
	return level, true
}

// DaysLeft is the number of whole days left, rounded up (6 days and 1 hour is 7), and 0 once expired.
func DaysLeft(expiresAt, now time.Time) int {
	left := expiresAt.Sub(now)
	if left <= 0 {
		return 0
	}
	return int((left + day - 1) / day)
}

// Horizon is how far ahead a scan must look: the largest threshold.
func Horizon(thresholds []int) time.Duration {
	if len(thresholds) == 0 {
		return 0
	}
	return time.Duration(slices.Max(thresholds)) * day
}

// Bucket is the dashboard group of an expiry; the windows exclude each other (R42 row 14).
type Bucket string

// Dashboard buckets.
const (
	BucketExpired Bucket = "expired"
	Bucket7       Bucket = "7"
	Bucket30      Bucket = "30"
	Bucket60      Bucket = "60"
	BucketLater   Bucket = "later"
)

// BucketOf places an expiry in its dashboard bucket.
func BucketOf(expiresAt, now time.Time) Bucket {
	switch left := expiresAt.Sub(now); {
	case left <= 0:
		return BucketExpired
	case left <= 7*day:
		return Bucket7
	case left <= 30*day:
		return Bucket30
	case left <= 60*day:
		return Bucket60
	default:
		return BucketLater
	}
}
```

Edit `internal/archtest/arch_test.go` as in Step 1.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -count=1 -race -cover ./internal/alerts/expiry/ ./internal/archtest/`
Expected: `ok … coverage: 100.0% of statements` for `expiry`; `ok` for `archtest` (`TestImportRules` passes: no Phase 7 package exists yet except `expiry`, which has its rule).

Run: `make lint`
Expected: no findings.

- [ ] **Step 5: Commit**

```bash
git add -- internal/alerts/expiry/expiry.go internal/alerts/expiry/expiry_test.go
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(alerts): pure expiry rules — thresholds, the due notice with catch-up, dashboard buckets; Phase 7 import rules" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- internal/alerts/expiry internal/archtest/arch_test.go
```

---

### Task 2: `internal/auth/oidc/claims`: claim validation, groups and overage, role resolution, mapping rules, safe `next`, issuer, user names; `FuzzParse`

**Files:**
- Create: `internal/auth/oidc/claims/claims.go`, `internal/auth/oidc/claims/groups.go`, `internal/auth/oidc/claims/urls.go`
- Create: `internal/auth/oidc/claims/claims_test.go`, `internal/auth/oidc/claims/groups_test.go`, `internal/auth/oidc/claims/urls_test.go`, `internal/auth/oidc/claims/fuzz_test.go`
- Modify: `Makefile` (new target `fuzz-oidc`, beside `fuzz-ssh`)

**Interfaces:**
- Consumes: `rbac.Role`, `rbac.Admin`, `rbac.Operator`, `rbac.Auditor` (`internal/rbac/rbac.go`).
- Produces: C4 exactly.

- [ ] **Step 1: Write the failing tests**

`internal/auth/oidc/claims/claims_test.go`:

```go
package claims

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var now = time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)

const (
	iss    = "https://login.example.com/tenant/v2.0"
	client = "alice"
	nonce  = "n-0123456789abcdefghijklmnopqrstuvwxyzABCDE"
)

func payload(t *testing.T, edit func(m map[string]any)) []byte {
	t.Helper()
	m := map[string]any{"iss": iss, "aud": client, "sub": "user-1", "nonce": nonce,
		"exp": now.Add(5 * time.Minute).Unix(), "iat": now.Unix(), "email": "ada@example.com",
		"name": "Ada Yılmaz", "preferred_username": "Ada.Yilmaz@Example.com"}
	if edit != nil {
		edit(m)
	}
	b, err := json.Marshal(m)
	require.NoError(t, err)
	return b
}

func expect() Expect { return Expect{Issuer: iss, ClientID: client, Nonce: nonce, Now: now} }

func reasonOf(err error) Reason {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return ""
}

func TestParseReadsStandardClaims(t *testing.T) {
	c, err := Parse(payload(t, func(m map[string]any) {
		m["aud"] = []string{client, "other"}
		m["azp"] = client
		m["nbf"] = now.Add(-time.Minute).Unix()
		m["auth_time"] = now.Add(-2 * time.Minute).Unix()
		m["upn"] = "ada@corp.example.com"
	}))
	require.NoError(t, err)
	assert.Equal(t, iss, c.Issuer)
	assert.Equal(t, []string{client, "other"}, c.Audience)
	assert.Equal(t, client, c.AuthorizedParty)
	assert.Equal(t, "user-1", c.Subject)
	assert.Equal(t, now.Add(5*time.Minute), c.Expiry)
	assert.Equal(t, now, c.IssuedAt)
	assert.Equal(t, now.Add(-time.Minute), c.NotBefore)
	assert.Equal(t, now.Add(-2*time.Minute), c.AuthTime)
	assert.Equal(t, "ada@example.com", c.Email)
	assert.Equal(t, "Ada Yılmaz", c.Name)
	assert.Equal(t, "ada@corp.example.com", c.UPN)
	c, err = Parse([]byte(`{"iss":"x","aud":"alice","sub":"s","exp":1790000000.9,"iat":1790000000}`))
	require.NoError(t, err)
	assert.Equal(t, []string{"alice"}, c.Audience)
	assert.Equal(t, time.Unix(1790000000, 0).UTC(), c.Expiry, "fractions are cut")
	assert.True(t, c.NotBefore.IsZero())
}

func TestParseRefusesMalformedPayloads(t *testing.T) {
	for _, raw := range []string{``, `null`, `[]`, `"x"`, `{"iss":1}`, `{"aud":{"a":1}}`, `{"aud":[1]}`, `{"exp":"soon"}`,
		`{"exp":1e300}`, `{"sub":["a"]}`, `{"iat":-1e20}`, `{"iss":"a"`} {
		_, err := Parse([]byte(raw))
		assert.Equal(t, ReasonMalformed, reasonOf(err), raw)
	}
}

func TestValidateAcceptsAGoodToken(t *testing.T) {
	c, err := Parse(payload(t, nil))
	require.NoError(t, err)
	assert.NoError(t, Validate(c, expect()))
}

// Review Focus 1, O-02 and O-03: every claim the provider could get wrong is refused with its own reason.
func TestValidateRefusesEachClaim(t *testing.T) {
	cases := []struct {
		name string
		edit func(m map[string]any)
		want Reason
	}{
		{"wrong issuer", func(m map[string]any) { m["iss"] = iss + "/" }, ReasonIssuer},
		{"issuer differs in case", func(m map[string]any) { m["iss"] = "https://LOGIN.example.com/tenant/v2.0" }, ReasonIssuer},
		{"wrong audience", func(m map[string]any) { m["aud"] = "someone-else" }, ReasonAudience},
		{"several audiences without azp", func(m map[string]any) { m["aud"] = []string{client, "x"} }, ReasonAzp},
		{"azp of another client", func(m map[string]any) { m["azp"] = "x" }, ReasonAzp},
		{"no subject", func(m map[string]any) { delete(m, "sub") }, ReasonSubject},
		{"subject too long", func(m map[string]any) { m["sub"] = string(make([]byte, 256)) }, ReasonSubject},
		{"expired beyond the leeway", func(m map[string]any) { m["exp"] = now.Add(-61 * time.Second).Unix() }, ReasonExpired},
		{"no expiry", func(m map[string]any) { delete(m, "exp") }, ReasonExpired},
		{"issued in the future beyond the leeway", func(m map[string]any) { m["iat"] = now.Add(61 * time.Second).Unix() }, ReasonIssuedAt},
		{"no issued-at", func(m map[string]any) { delete(m, "iat") }, ReasonIssuedAt},
		{"not yet valid beyond the leeway", func(m map[string]any) { m["nbf"] = now.Add(61 * time.Second).Unix() }, ReasonNotBefore},
		{"wrong nonce", func(m map[string]any) { m["nonce"] = nonce + "x" }, ReasonNonce},
		{"no nonce", func(m map[string]any) { delete(m, "nonce") }, ReasonNonce},
	}
	for _, c := range cases {
		cl, err := Parse(payload(t, c.edit))
		require.NoError(t, err, c.name)
		assert.Equal(t, c.want, reasonOf(Validate(cl, expect())), c.name)
	}
	cl, err := Parse(payload(t, nil))
	require.NoError(t, err)
	e := expect()
	e.Nonce = ""
	assert.Equal(t, ReasonNonce, reasonOf(Validate(cl, e)), "an empty expected nonce never matches")
}

func TestValidateLeewayEdges(t *testing.T) {
	ok := []func(m map[string]any){
		func(m map[string]any) { m["exp"] = now.Add(-59 * time.Second).Unix() },
		func(m map[string]any) { m["iat"] = now.Add(60 * time.Second).Unix() },
		func(m map[string]any) { m["nbf"] = now.Add(60 * time.Second).Unix() },
		func(m map[string]any) { m["aud"] = []string{client, "x"}; m["azp"] = client },
	}
	for i, edit := range ok {
		c, err := Parse(payload(t, edit))
		require.NoError(t, err)
		assert.NoError(t, Validate(c, expect()), "case %d", i)
	}
}

func TestValidateStepUpNeedsAFreshAuthTime(t *testing.T) {
	e := expect()
	e.MaxAuthAge = 5 * time.Minute
	for _, c := range []struct {
		authTime any
		ok       bool
	}{
		{now.Add(-4 * time.Minute).Unix(), true},
		{now.Add(-6 * time.Minute).Unix(), true}, // 5 minutes + 60 s leeway
		{now.Add(-6*time.Minute - 2*time.Second).Unix(), false},
		{now.Add(2 * time.Minute).Unix(), false}, // in the future
		{nil, false},
	} {
		cl, err := Parse(payload(t, func(m map[string]any) {
			if c.authTime == nil {
				delete(m, "auth_time")
			} else {
				m["auth_time"] = c.authTime
			}
		}))
		require.NoError(t, err)
		err = Validate(cl, e)
		if c.ok {
			assert.NoError(t, err, "%v", c.authTime)
		} else {
			assert.Equal(t, ReasonAuthTime, reasonOf(err), "%v", c.authTime)
		}
	}
}

func TestErrorTextNamesOnlyTheReason(t *testing.T) {
	err := Validate(Claims{Issuer: "x"}, expect())
	assert.Equal(t, "claims: the ID token was refused (issuer)", err.Error())
}
```

`internal/auth/oidc/claims/groups_test.go`:

```go
package claims

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/rbac"
)

func TestGroupsReadsListsAndSingleStrings(t *testing.T) {
	c, err := Parse(payload(t, func(m map[string]any) { m["groups"] = []string{"ops", "/alice/admins"} }))
	require.NoError(t, err)
	g, err := Groups(c, "groups")
	require.NoError(t, err)
	assert.Equal(t, []string{"ops", "/alice/admins"}, g)

	c, err = Parse(payload(t, func(m map[string]any) { m["group"] = "ADFS-Operators" })) // AD FS sends one group as a string
	require.NoError(t, err)
	g, err = Groups(c, "group")
	require.NoError(t, err)
	assert.Equal(t, []string{"ADFS-Operators"}, g)

	c, err = Parse(payload(t, nil))
	require.NoError(t, err)
	g, err = Groups(c, "groups")
	require.NoError(t, err)
	assert.Empty(t, g, "no claim: no groups")

	c, err = Parse(payload(t, func(m map[string]any) { m["groups"] = nil }))
	require.NoError(t, err)
	g, err = Groups(c, "groups")
	require.NoError(t, err)
	assert.Empty(t, g)
}

// Review Focus 1, O-07: an Entra overage answer is detected and never read as "no groups".
func TestGroupsDetectsOverage(t *testing.T) {
	c, err := Parse(payload(t, func(m map[string]any) {
		m["_claim_names"] = map[string]any{"groups": "src1"}
		m["_claim_sources"] = map[string]any{"src1": map[string]any{"endpoint": "https://graph.microsoft.com/v1.0/users/x/getMemberObjects"}}
	}))
	require.NoError(t, err)
	_, err = Groups(c, "groups")
	assert.ErrorIs(t, err, ErrOverage)

	c, err = Parse(payload(t, func(m map[string]any) { m["hasgroups"] = true }))
	require.NoError(t, err)
	_, err = Groups(c, "groups")
	assert.ErrorIs(t, err, ErrOverage)

	c, err = Parse(payload(t, func(m map[string]any) { m["_claim_names"] = map[string]any{"roles": "src1"} }))
	require.NoError(t, err)
	_, err = Groups(c, "groups")
	assert.NoError(t, err, "an overage of another claim does not matter")
}

func TestGroupsRefusesMalformedValues(t *testing.T) {
	big := make([]string, MaxGroups+1)
	for i := range big {
		big[i] = "g"
	}
	for _, v := range []any{42, []any{"a", 1}, map[string]any{"a": "b"}, big} {
		c, err := Parse(payload(t, func(m map[string]any) { m["groups"] = v }))
		require.NoError(t, err)
		_, err = Groups(c, "groups")
		assert.ErrorIs(t, err, ErrGroupsMalformed)
	}
}

func TestResolveRoleCapsAdmin(t *testing.T) {
	maps := []Mapping{{"ops", rbac.Operator}, {"audit", rbac.Auditor}, {"admins", rbac.Admin}}
	cases := []struct {
		groups []string
		allow  bool
		want   rbac.Role
		ok     bool
	}{
		{[]string{"audit"}, false, rbac.Auditor, true},
		{[]string{"audit", "ops"}, false, rbac.Operator, true},
		{[]string{"admins"}, true, rbac.Admin, true},
		{[]string{"admins", "audit"}, false, rbac.Operator, true}, // SEC-014: capped at Operator
		{[]string{"Ops"}, false, "", false},                       // exact, case-sensitive match
		{[]string{"unmapped"}, true, "", false},                   // O-06: no default role
		{nil, true, "", false},
	}
	for _, c := range cases {
		got, ok := ResolveRole(c.groups, maps, c.allow)
		assert.Equal(t, c.ok, ok, "%v", c.groups)
		assert.Equal(t, c.want, got, "%v", c.groups)
	}
}

// O-13: no "all users" mapping, no Admin while the switch is off.
func TestValidateMapping(t *testing.T) {
	long := make([]rune, MaxGroupRunes+1)
	for i := range long {
		long[i] = 'ğ'
	}
	cases := []struct {
		m     Mapping
		allow bool
		want  error
	}{
		{Mapping{"ops", rbac.Operator}, false, nil},
		{Mapping{"admins", rbac.Admin}, true, nil},
		{Mapping{"admins", rbac.Admin}, false, ErrAdminNotAllowed},
		{Mapping{"", rbac.Auditor}, true, ErrGroupEmpty},
		{Mapping{"   ", rbac.Auditor}, true, ErrGroupEmpty},
		{Mapping{" ops", rbac.Auditor}, true, ErrGroupCharacters},
		{Mapping{"ops\n", rbac.Auditor}, true, ErrGroupCharacters},
		{Mapping{"o‮ps", rbac.Auditor}, true, ErrGroupCharacters},
		{Mapping{"o\x00ps", rbac.Auditor}, true, ErrGroupCharacters},
		{Mapping{string([]byte{0xff}), rbac.Auditor}, true, ErrGroupCharacters},
		{Mapping{string(long), rbac.Auditor}, true, ErrGroupTooLong},
		{Mapping{"ops", rbac.Role("owner")}, true, ErrRole},
		{Mapping{"ops", ""}, true, ErrRole},
	}
	for _, c := range cases {
		err := ValidateMapping(c.m, c.allow)
		if c.want == nil {
			assert.NoError(t, err, "%q", c.m.Group)
		} else {
			assert.ErrorIs(t, err, c.want, "%q", c.m.Group)
		}
	}
}
```

`internal/auth/oidc/claims/urls_test.go`:

```go
package claims

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Review Focus 1, O-05: next never leaves Alice.
func TestSafeNextRefusesOpenRedirects(t *testing.T) {
	ok := []string{"/", "/certificates?expiry=30&target_id=0192e000-0000-7000-8000-000000000001", "/ssh-keys/abc", "/settings#mail"}
	for _, v := range ok {
		assert.Equal(t, v, SafeNext(v), v)
	}
	bad := []string{"", "https://evil.example", "//evil.example", "/\\evil.example", "\\\\evil", "/%0d%0aSet-Cookie:x",
		"javascript:alert(1)", "/ok\r\nLocation: x", "/ok\tx", "relative/path", "/api/v1/auth/logout", "/api", "https:/evil",
		"/" + strings.Repeat("a", 2048), "/ x"}
	for _, v := range bad {
		assert.Equal(t, "/", SafeNext(v), "%q", v)
	}
}

// O-12: plain HTTP and odd issuer addresses are refused at configuration time.
func TestValidateIssuer(t *testing.T) {
	for _, v := range []string{"https://login.microsoftonline.com/0192e000-0000-7000-8000-000000000001/v2.0",
		"https://adfs.example.com/adfs", "https://keycloak.example.com:8443/realms/corp", "https://idp.alice-e2e.test:9444"} {
		assert.NoError(t, ValidateIssuer(v), v)
	}
	for _, v := range []string{"", "http://idp.example.com", "https://", "https://user@idp.example.com", "https://idp.example.com?x=1",
		"https://idp.example.com#f", " https://idp.example.com", "https://idp.example.com/ x", "ftp://idp", "idp.example.com",
		"https://" + strings.Repeat("a", 500)} {
		assert.ErrorIs(t, ValidateIssuer(v), ErrIssuer, "%q", v)
	}
}

func TestUsername(t *testing.T) {
	assert.Equal(t, "ada.yilmaz@example.com", Username(Claims{PreferredUsername: "Ada.Yilmaz@Example.com", Subject: "s"}))
	assert.Equal(t, "ada@corp.example.com", Username(Claims{UPN: "ADA@corp.example.com", Subject: "s"}))
	assert.Equal(t, "ada@example.com", Username(Claims{Email: "ada@example.com", Subject: "s"}))
	assert.Equal(t, "dlmaz", Username(Claims{PreferredUsername: "İıöÖdlmaz", Subject: "s"}), "non-ASCII letters are dropped")
	u := Username(Claims{Issuer: "https://idp", Subject: "s", PreferredUsername: "@@@"})
	assert.Regexp(t, `^sso-[0-9a-f]{12}$`, u)
	assert.Equal(t, u, Username(Claims{Issuer: "https://idp", Subject: "s"}), "stable for the same identity")
	assert.NotEqual(t, u, Username(Claims{Issuer: "https://idp", Subject: "t"}))
	assert.Len(t, Username(Claims{PreferredUsername: strings.Repeat("a", 100)}), 64)
}
```

`internal/auth/oidc/claims/fuzz_test.go`:

```go
package claims

import (
	"testing"
	"time"
)

// FuzzParse: any payload either parses or is refused as malformed; parsing never panics, and Validate and Groups
// never panic on what Parse accepts.
func FuzzParse(f *testing.F) {
	f.Add([]byte(`{"iss":"https://idp","aud":["alice"],"sub":"s","exp":1790000000,"iat":1790000000,"nonce":"n","groups":["a"]}`))
	f.Add([]byte(`{"aud":"alice","_claim_names":{"groups":"s"},"hasgroups":true}`))
	f.Add([]byte(`{"groups":"one","exp":1.5e9}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		c, err := Parse(b)
		if err != nil {
			return
		}
		_ = Validate(c, Expect{Issuer: "https://idp", ClientID: "alice", Nonce: "n", Now: time.Unix(1790000000, 0), MaxAuthAge: time.Minute})
		_, _ = Groups(c, "groups")
		_ = Username(c)
	})
}
```

`Makefile`, after `fuzz-ssh`:

```make
.PHONY: fuzz-oidc
fuzz-oidc: ## Fuzz the ID token claim parser for 60 s (spec §25.6, Phase 7)
	go test -count=1 -run '^$$' -fuzz FuzzParse -fuzztime 60s ./internal/auth/oidc/claims/
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/auth/oidc/claims/`
Expected: FAIL — no non-test Go files / undefined `Parse`.

- [ ] **Step 3: Write the implementation**

`internal/auth/oidc/claims/claims.go`:

```go
// Package claims checks the claims of an OpenID Connect ID token after its signature was verified (spec §15.3
// SEC-012, §25.5 O-02 and O-03; R42 rows 18-24). It is pure: the caller passes the expected values and the time.
package claims

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"math"
	"slices"
	"time"
)

// Leeway is the clock skew accepted on exp, iat, nbf and auth_time (SEC-012).
const Leeway = 60 * time.Second

// Claims are the standard claims Alice reads; the raw claims are kept for Groups.
type Claims struct {
	Issuer            string
	Audience          []string
	AuthorizedParty   string
	Subject           string
	Nonce             string
	Expiry            time.Time
	IssuedAt          time.Time
	NotBefore         time.Time
	AuthTime          time.Time
	Email             string
	Name              string
	PreferredUsername string
	UPN               string

	raw map[string]json.RawMessage
}

// Reason is the closed reason of a refused token; it is safe to log and audit.
type Reason string

// Reasons.
const (
	ReasonMalformed Reason = "malformed"
	ReasonIssuer    Reason = "issuer"
	ReasonAudience  Reason = "audience"
	ReasonAzp       Reason = "azp"
	ReasonSubject   Reason = "subject"
	ReasonExpired   Reason = "expired"
	ReasonIssuedAt  Reason = "issued_at"
	ReasonNotBefore Reason = "not_before"
	ReasonNonce     Reason = "nonce"
	ReasonAuthTime  Reason = "auth_time"
)

// Error is a refused token. Its text names the reason only, never a claim value.
type Error struct{ Reason Reason }

func (e *Error) Error() string { return "claims: the ID token was refused (" + string(e.Reason) + ")" }

func fail(r Reason) error { return &Error{Reason: r} }

// Parse reads the claims of a payload whose signature was already checked.
func Parse(payload []byte) (Claims, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil || raw == nil {
		return Claims{}, fail(ReasonMalformed)
	}
	c := Claims{raw: raw}
	for key, dst := range map[string]*string{"iss": &c.Issuer, "azp": &c.AuthorizedParty, "sub": &c.Subject, "nonce": &c.Nonce,
		"email": &c.Email, "name": &c.Name, "preferred_username": &c.PreferredUsername, "upn": &c.UPN} {
		if v, ok := raw[key]; ok && !isNull(v) {
			if err := json.Unmarshal(v, dst); err != nil {
				return Claims{}, fail(ReasonMalformed)
			}
		}
	}
	if v, ok := raw["aud"]; ok && !isNull(v) {
		var one string
		if err := json.Unmarshal(v, &one); err == nil {
			c.Audience = []string{one}
		} else if err := json.Unmarshal(v, &c.Audience); err != nil {
			return Claims{}, fail(ReasonMalformed)
		}
	}
	for key, dst := range map[string]*time.Time{"exp": &c.Expiry, "iat": &c.IssuedAt, "nbf": &c.NotBefore, "auth_time": &c.AuthTime} {
		if v, ok := raw[key]; ok && !isNull(v) {
			var f float64
			if err := json.Unmarshal(v, &f); err != nil || math.IsNaN(f) || f < 0 || f > 1e11 {
				return Claims{}, fail(ReasonMalformed)
			}
			*dst = time.Unix(int64(f), 0).UTC()
		}
	}
	return c, nil
}

func isNull(v json.RawMessage) bool { return bytes.Equal(bytes.TrimSpace(v), []byte("null")) }

// Expect holds what a token must say.
type Expect struct {
	Issuer, ClientID, Nonce string
	Now                     time.Time
	MaxAuthAge              time.Duration
}

// Validate checks c against e and returns nil or an *Error.
func Validate(c Claims, e Expect) error {
	now := e.Now
	switch {
	case c.Issuer != e.Issuer:
		return fail(ReasonIssuer)
	case !slices.Contains(c.Audience, e.ClientID):
		return fail(ReasonAudience)
	case len(c.Audience) > 1 && c.AuthorizedParty != e.ClientID, c.AuthorizedParty != "" && c.AuthorizedParty != e.ClientID:
		return fail(ReasonAzp)
	case c.Subject == "" || len(c.Subject) > 255:
		return fail(ReasonSubject)
	case c.Expiry.IsZero() || !now.Before(c.Expiry.Add(Leeway)):
		return fail(ReasonExpired)
	case c.IssuedAt.IsZero() || c.IssuedAt.After(now.Add(Leeway)):
		return fail(ReasonIssuedAt)
	case !c.NotBefore.IsZero() && c.NotBefore.After(now.Add(Leeway)):
		return fail(ReasonNotBefore)
	case e.Nonce == "" || subtle.ConstantTimeCompare([]byte(c.Nonce), []byte(e.Nonce)) != 1:
		return fail(ReasonNonce)
	}
	if e.MaxAuthAge > 0 && (c.AuthTime.IsZero() || c.AuthTime.After(now.Add(Leeway)) || now.Sub(c.AuthTime) > e.MaxAuthAge+Leeway) {
		return fail(ReasonAuthTime)
	}
	return nil
}
```

`internal/auth/oidc/claims/groups.go`:

```go
package claims

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"alice/internal/rbac"
)

// MaxGroups bounds the groups claim; MaxGroupRunes a mapping's group value.
const (
	MaxGroups     = 1000
	MaxGroupRunes = 256
)

// Errors of Groups and ValidateMapping.
var (
	ErrOverage         = errors.New("claims: the identity provider left the groups out (too many groups)")
	ErrGroupsMalformed = errors.New("claims: the groups claim is not a list of names")
	ErrGroupEmpty      = errors.New("claims: a group mapping needs a group value")
	ErrGroupTooLong    = errors.New("claims: the group value is too long")
	ErrGroupCharacters = errors.New("claims: the group value has white space at its ends or invisible characters")
	ErrRole            = errors.New("claims: the role is not admin, operator or auditor")
	ErrAdminNotAllowed = errors.New("claims: groups cannot be mapped to Administrator while SSO users may not be Admin")
)

// Groups returns the values of the groups claim: a list of strings, or one string (AD FS sends a single group so).
// An Entra overage answer (the claim named in _claim_names, or hasgroups) is ErrOverage, never "no groups".
func Groups(c Claims, claim string) ([]string, error) {
	if v, ok := c.raw["_claim_names"]; ok {
		var names map[string]json.RawMessage
		if json.Unmarshal(v, &names) == nil {
			if _, over := names[claim]; over {
				return nil, ErrOverage
			}
		}
	}
	if v, ok := c.raw["hasgroups"]; ok && strings.TrimSpace(string(v)) == "true" {
		return nil, ErrOverage
	}
	v, ok := c.raw[claim]
	if !ok || isNull(v) {
		return nil, nil
	}
	var one string
	if json.Unmarshal(v, &one) == nil {
		return []string{one}, nil
	}
	var many []string
	if err := json.Unmarshal(v, &many); err != nil || len(many) > MaxGroups {
		return nil, ErrGroupsMalformed
	}
	return many, nil
}

// Mapping maps one group value to a role.
type Mapping struct {
	Group string
	Role  rbac.Role
}

func rank(r rbac.Role) int {
	switch r {
	case rbac.Admin:
		return 3
	case rbac.Operator:
		return 2
	case rbac.Auditor:
		return 1
	default:
		return 0
	}
}

// ResolveRole is the highest role mapped to any of the groups (exact, case-sensitive match). Administrator is
// capped at Operator unless adminAllowed (SEC-014). ok is false when no group is mapped: no default role (O-06).
func ResolveRole(groups []string, mappings []Mapping, adminAllowed bool) (rbac.Role, bool) {
	var best rbac.Role
	for _, m := range mappings {
		if rank(m.Role) > rank(best) && slices.Contains(groups, m.Group) {
			best = m.Role
		}
	}
	if best == "" {
		return "", false
	}
	if best == rbac.Admin && !adminAllowed {
		best = rbac.Operator
	}
	return best, true
}

// ValidateMapping refuses an empty or invisible-character group value, an unknown role, and Administrator while the
// switch is off (O-13).
func ValidateMapping(m Mapping, adminAllowed bool) error {
	switch {
	case strings.TrimSpace(m.Group) == "":
		return ErrGroupEmpty
	case !utf8.ValidString(m.Group) || m.Group != strings.TrimSpace(m.Group) || strings.IndexFunc(m.Group, invisible) >= 0:
		return ErrGroupCharacters
	case utf8.RuneCountInString(m.Group) > MaxGroupRunes:
		return ErrGroupTooLong
	case rank(m.Role) == 0:
		return ErrRole
	case m.Role == rbac.Admin && !adminAllowed:
		return ErrAdminNotAllowed
	}
	return nil
}

func invisible(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == utf8.RuneError }
```

`internal/auth/oidc/claims/urls.go`:

```go
package claims

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"strings"
	"unicode"
)

// ErrIssuer refuses an issuer (or endpoint) address.
var ErrIssuer = errors.New("claims: the issuer must be an https:// address without user name, query or fragment")

const maxNext = 2048

// SafeNext returns raw when it is a path inside Alice's web application, else "/". It refuses absolute and
// scheme-relative addresses, backslashes, white space and control characters, and API paths (O-05).
func SafeNext(raw string) string {
	if raw == "" || len(raw) > maxNext || raw[0] != '/' || strings.HasPrefix(raw, "//") || strings.HasPrefix(raw, "/\\") ||
		raw == "/api" || strings.HasPrefix(raw, "/api/") || strings.ContainsRune(raw, '\\') ||
		strings.IndexFunc(raw, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }) >= 0 {
		return "/"
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || u.Opaque != "" {
		return "/"
	}
	if dec, err := url.PathUnescape(u.EscapedPath()); err != nil || strings.ContainsAny(dec, "\r\n\\") || strings.HasPrefix(dec, "//") {
		return "/"
	}
	return raw
}

// ValidateIssuer accepts https://host[:port][/path] of at most 500 bytes without user info, query or fragment
// (SEC-013, O-12). Endpoints from discovery are checked with it too.
func ValidateIssuer(raw string) error {
	if raw == "" || len(raw) > 500 || strings.IndexFunc(raw, unicode.IsSpace) >= 0 {
		return ErrIssuer
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		u.Opaque != "" || strings.HasSuffix(raw, "?") || strings.HasSuffix(raw, "#") {
		return ErrIssuer
	}
	return nil
}

const maxUsername = 64

// Username derives an Alice user name from the claims: preferred_username, upn or email (folded to lower-case
// ASCII; other characters dropped), else "sso-" and 12 hex digits of SHA-256(iss "\n" sub).
func Username(c Claims) string {
	for _, v := range []string{c.PreferredUsername, c.UPN, c.Email} {
		if u := cleanName(v); u != "" {
			return u
		}
	}
	sum := sha256.Sum256([]byte(c.Issuer + "\n" + c.Subject))
	return "sso-" + hex.EncodeToString(sum[:6])
}

func cleanName(v string) string {
	var b strings.Builder
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '_', r == '-', r == '@':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + ('a' - 'A'))
		}
	}
	s := strings.Trim(b.String(), ".-_@")
	if len(s) > maxUsername {
		s = strings.TrimRight(s[:maxUsername], ".-_@")
	}
	return s
}
```

Notes for the implementer: `TestUsername` expects 64 characters for 100 `a`s (nothing to trim); the dropped-letters case `"İıöÖdlmaz"` folds to `dlmaz`. `TestSafeNextRefusesOpenRedirects` includes `"/%0d%0aSet-Cookie:x"`: the decoded path holds CR/LF, so it is refused by the `PathUnescape` check.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -count=1 -race -cover ./internal/auth/oidc/claims/ && go test -count=1 -run '^$' -fuzz FuzzParse -fuzztime 20s ./internal/auth/oidc/claims/ && go test ./internal/archtest/`
Expected: `ok … coverage: 100.0% of statements`; the fuzz run ends without a crasher; `archtest` `ok`. If a line stays uncovered, add the table row that reaches it (the floor is 100).

Run: `make lint`
Expected: no findings.

- [ ] **Step 5: Commit**

```bash
git add -- internal/auth/oidc/claims
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(auth): pure OIDC claim rules — validation with leeway, groups and overage, role cap, mapping rules, safe next" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- internal/auth/oidc/claims Makefile
```

---

### Task 3: `internal/platform/csvx`: formula-safe CSV with BOM; the audit export moves onto it

**Files:**
- Create: `internal/platform/csvx/csvx.go`, `internal/platform/csvx/csvx_test.go`
- Modify: `internal/api/audit_handlers.go` (`writeAuditCSV` uses `csvx.NewWriter`; `csvSafe` is deleted), `internal/api/audit_handlers_test.go` (`TestCSVSafe` becomes `TestAuditCSVUsesCsvx`, below)

**Interfaces:**
- Consumes: nothing.
- Produces: C5 exactly (`Safe`, `Writer`, `NewWriter`, `Write`, `Flush`).

- [ ] **Step 1: Write the failing tests**

`internal/platform/csvx/csvx_test.go`:

```go
package csvx

import (
	"bytes"
	"encoding/csv"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Review Focus 4: every formula prefix a spreadsheet evaluates is neutralised; nothing else changes.
func TestSafeNeutralisesFormulaPrefixes(t *testing.T) {
	for in, want := range map[string]string{
		"=1+1": "'=1+1", "+1": "'+1", "-1": "'-1", "@SUM(A1)": "'@SUM(A1)", "\tx": "'\tx", "\rx": "'\rx",
		"=HYPERLINK(\"http://x\")": "'=HYPERLINK(\"http://x\")",
		"admin": "admin", "": "", "İzmir": "İzmir", " =1": " =1", "a=1": "a=1", "'quoted": "'quoted",
	} {
		assert.Equal(t, want, Safe(in), "%q", in)
	}
}

// Review Focus 4: a BOM, then RFC 4180 records with quotes, commas and newlines intact and every cell made safe.
func TestWriterQuotesAndBOM(t *testing.T) {
	var b bytes.Buffer
	w, err := NewWriter(&b)
	require.NoError(t, err)
	require.NoError(t, w.Write([]string{"id", "label"}))
	require.NoError(t, w.Write([]string{"1", "=cmd|' /C calc'!A0"}))
	require.NoError(t, w.Write([]string{"2", "a,b \"c\"\nd"}))
	require.NoError(t, w.Write([]string{"3", "Iğdır İç Ağ"}))
	require.NoError(t, w.Flush())
	out := b.Bytes()
	require.True(t, bytes.HasPrefix(out, []byte("\xEF\xBB\xBF")), "UTF-8 byte order mark first")
	rows, err := csv.NewReader(bytes.NewReader(out[3:])).ReadAll()
	require.NoError(t, err)
	assert.Equal(t, [][]string{{"id", "label"}, {"1", "'=cmd|' /C calc'!A0"}, {"2", "a,b \"c\"\nd"}, {"3", "Iğdır İç Ağ"}}, rows)
	assert.True(t, strings.HasSuffix(string(out), "\n"))
}

type failWriter struct{ after int }

func (f *failWriter) Write(p []byte) (int, error) {
	if f.after <= 0 {
		return 0, errors.New("disk full")
	}
	f.after--
	return len(p), nil
}

func TestWriterReportsWriteErrors(t *testing.T) {
	_, err := NewWriter(&failWriter{after: 0})
	assert.Error(t, err, "the BOM write fails")
	w, err := NewWriter(&failWriter{after: 1})
	require.NoError(t, err)
	require.NoError(t, w.Write([]string{"x"})) // buffered
	assert.Error(t, w.Flush())
}
```

`internal/api/audit_handlers_test.go`: replace `TestCSVSafe` with

```go
// The audit export uses the shared formula-safe writer (Phase 7, Task 3): a hostile actor name is neutralised and the
// verification line still sits between the byte order mark and the header.
func TestAuditCSVUsesCsvx(t *testing.T) {
	report := audit.Report{Intact: true, Checked: 1, HeadSeq: 1, HeadHash: []byte{1}}
	fa := &fakeAudit{IterateFn: func(_ context.Context, fn func(audit.Entry) error) error {
		return fn(audit.Entry{Seq: 1, ActorType: audit.ActorUser, ActorName: "=HYPERLINK(\"x\")", Action: "auth.login",
			Result: audit.Success, Hash: []byte{1}})
	}}
	s := newServer(Deps{Audit: fa})
	rec := httptest.NewRecorder()
	require.NoError(t, s.writeAuditCSV(context.Background(), rec, report))
	body := rec.Body.String()
	assert.True(t, strings.HasPrefix(body, "\xEF\xBB\xBF# alice audit export: intact=true"), body)
	assert.Contains(t, body, "\nseq,at,actor_type,")
	assert.Contains(t, body, `"'=HYPERLINK(""x"")"`)
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/platform/csvx/ && go test -run 'TestAuditCSVUsesCsvx' ./internal/api/`
Expected: FAIL — no non-test Go files in `csvx`. `TestAuditCSVUsesCsvx` already passes against the current code: it is the guard that keeps the export's bytes while the helper moves (it must still pass after Step 3).

- [ ] **Step 3: Write the implementation**

`internal/platform/csvx/csvx.go`:

```go
// Package csvx writes CSV files that spreadsheet programs open safely: UTF-8 with a byte order mark (spec §10.5)
// and every cell that a spreadsheet would read as a formula prefixed with an apostrophe (formula injection; R42
// row 16). It is used by the audit export and the inventory exports.
package csvx

import (
	"encoding/csv"
	"io"
)

const bom = "\xEF\xBB\xBF"

// Safe neutralises spreadsheet formula injection: a value that starts with = + - @ TAB or CR is prefixed with an
// apostrophe. Other values are returned unchanged.
func Safe(v string) string {
	if v == "" {
		return v
	}
	switch v[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + v
	}
	return v
}

// Writer writes formula-safe CSV records.
type Writer struct{ cw *csv.Writer }

// NewWriter writes the byte order mark to w and returns a writer for the records.
func NewWriter(w io.Writer) (*Writer, error) {
	if _, err := io.WriteString(w, bom); err != nil {
		return nil, err
	}
	return &Writer{cw: csv.NewWriter(w)}, nil
}

// Write writes one record, every cell passed through Safe.
func (w *Writer) Write(record []string) error {
	safe := make([]string, len(record))
	for i, v := range record {
		safe[i] = Safe(v)
	}
	return w.cw.Write(safe)
}

// Flush writes buffered records and reports any write error.
func (w *Writer) Flush() error {
	w.cw.Flush()
	return w.cw.Error()
}
```

`internal/api/audit_handlers.go`, `writeAuditCSV`: replace the BOM write and `csv.NewWriter(w)` with

```go
	cw, err := csvx.NewWriter(w)
	if err != nil {
		return err
	}
	if _, err := io.WriteString(w, csvVerificationLine(report)); err != nil {
		return err
	}
```

— keeping the verification line between the BOM and the header: `csvx.NewWriter` writes only the BOM, and the CSV writer buffers, so the line written directly to `w` lands before the header (`csv.Writer` writes nothing before its first `Flush`). Drop the per-cell `csvSafe` loop (`cw.Write` applies `Safe`), replace the final `cw.Flush(); return cw.Error()` with `return cw.Flush()`, delete `csvSafe` and the `encoding/csv` import.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -count=1 -race -cover ./internal/platform/csvx/ && go test -count=1 -race ./internal/api/ ./internal/archtest/`
Expected: `ok … coverage: 100.0% of statements` for `csvx`; `ok` for `api` (every existing audit export test still passes: the first line, the header, the escaping) and `archtest`.

Run: `make lint`
Expected: no findings.

- [ ] **Step 5: Commit**

```bash
git add -- internal/platform/csvx
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(platform): csvx, formula-safe CSV with a byte order mark; the audit export uses it" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- internal/platform/csvx internal/api/audit_handlers.go internal/api/audit_handlers_test.go
```

---

### Task 4: Test fakes: `internal/testutil/fakesmtp` (MailHog-compatible API) and `internal/testutil/fakeidp` (discovery, JWKS, authorize, token, faults)

**Files:**
- Create: `internal/testutil/fakesmtp/server.go`, `internal/testutil/fakesmtp/mailhog.go`, `internal/testutil/fakesmtp/server_test.go`
- Create: `internal/testutil/fakeidp/server.go`, `internal/testutil/fakeidp/tokens.go`, `internal/testutil/fakeidp/server_test.go`

**Interfaces:**
- Consumes: `clock.Real` (`internal/platform/clock`). Standard library only otherwise (no JOSE library: the fake signs with `crypto/rsa` and `crypto/hmac`, so it never shares a bug with the verifier it tests).
- Produces: C6 exactly. Later users: Tasks 6–7 (`fakesmtp`), Tasks 12 and 16 (`fakeidp`), Task 20 (both, wrapped as e2e containers).

- [ ] **Step 1: Write the failing tests**

`internal/testutil/fakesmtp/server_test.go`:

```go
package fakesmtp

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/smtp"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const raw = "From: <alice@example.com>\r\nTo: <ops@example.com>\r\nSubject: =?utf-8?q?S=C3=BCre_doldu?=\r\n" +
	"MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n" +
	"U8O8cmUgZG9sZHU6IHd3dy5leGFtcGxlLnRlc3QK\r\n"

func send(t *testing.T, s *Server, auth smtp.Auth, to string) error {
	t.Helper()
	host, port := s.Addr()
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(s.CertPEM()))
	c, err := smtp.Dial(net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	if err := c.StartTLS(&tls.Config{ServerName: host, RootCAs: pool, MinVersion: tls.VersionTLS12}); err != nil {
		return err
	}
	if auth != nil {
		if err := c.Auth(auth); err != nil {
			return err
		}
	}
	if err := c.Mail("alice@example.com"); err != nil {
		return err
	}
	if err := c.Rcpt(to); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte(raw)); err != nil {
		return err
	}
	return w.Close()
}

func TestStoresDecodedMessagesOverSTARTTLS(t *testing.T) {
	s := Start(t, Options{})
	require.NoError(t, send(t, s, nil, "ops@example.com"))
	msgs := s.Messages()
	require.Len(t, msgs, 1)
	assert.Equal(t, "alice@example.com", msgs[0].From)
	assert.Equal(t, []string{"ops@example.com"}, msgs[0].To)
	assert.Equal(t, "Süre doldu", msgs[0].Subject)
	assert.Equal(t, "Süre doldu: www.example.test\n", msgs[0].Body)
	assert.True(t, msgs[0].Secure)
	assert.Regexp(t, `^[0-9a-f]{64}$`, s.Fingerprint())
	s.Clear()
	assert.Empty(t, s.Messages())
}

func TestRequiresAuthWhenConfigured(t *testing.T) {
	s := Start(t, Options{Username: "mailer", Password: "pw-1"})
	host, _ := s.Addr()
	assert.Error(t, send(t, s, nil, "ops@example.com"), "MAIL without AUTH")
	assert.Error(t, send(t, s, smtp.PlainAuth("", "mailer", "wrong", host), "ops@example.com"))
	require.NoError(t, send(t, s, smtp.PlainAuth("", "mailer", "pw-1", host), "ops@example.com"))
	assert.True(t, s.Messages()[0].Authed)
}

func TestFaultSwitches(t *testing.T) {
	s := Start(t, Options{})
	s.RejectRecipient("bad@example.com")
	assert.Error(t, send(t, s, nil, "bad@example.com"))
	require.NoError(t, send(t, s, nil, "ops@example.com"))
	s.Down()
	assert.Error(t, send(t, s, nil, "ops@example.com"), "connections are refused while down")
	require.NoError(t, s.Up())
	require.NoError(t, send(t, s, nil, "ops@example.com"))
	assert.Len(t, s.Messages(), 2)
}

func TestMailHogAPI(t *testing.T) {
	s := Start(t, Options{})
	require.NoError(t, send(t, s, nil, "ops@example.com"))
	h := s.Handler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v2/messages", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	var got struct {
		Total int `json:"total"`
		Items []struct {
			From    struct{ Mailbox, Domain string }
			Content struct {
				Headers map[string][]string
				Body    string
			}
		} `json:"items"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.Equal(t, 1, got.Total)
	assert.Equal(t, "alice", got.Items[0].From.Mailbox)
	assert.Equal(t, []string{"Süre doldu"}, got.Items[0].Content.Headers["Subject"])
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/api/v1/messages", nil))
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Empty(t, s.Messages())
}
```

`internal/testutil/fakeidp/server_test.go`:

```go
package fakeidp

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const redirect = "https://alice.example.test/api/v1/auth/oidc/p1/callback"

func authorizeURL(s *Server, challenge string) string {
	q := url.Values{"response_type": {"code"}, "client_id": {s.ClientID()}, "redirect_uri": {redirect}, "scope": {"openid email"},
		"state": {"st"}, "nonce": {"no"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}
	return s.Issuer() + "/authorize?" + q.Encode()
}

func challengeOf(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func exchange(t *testing.T, s *Server, code, verifier string) (int, map[string]any) {
	t.Helper()
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect}, "code_verifier": {verifier}}
	req, err := http.NewRequest(http.MethodPost, s.Issuer()+"/token", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(s.ClientID()), url.QueryEscape(s.ClientSecret()))
	res, err := s.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = res.Body.Close() }()
	var body map[string]any
	b, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(b, &body))
	return res.StatusCode, body
}

func login(t *testing.T, s *Server, verifier string) (int, map[string]any) {
	t.Helper()
	cb, err := s.Authorize(authorizeURL(s, challengeOf(verifier)))
	require.NoError(t, err)
	u, err := url.Parse(cb)
	require.NoError(t, err)
	require.Equal(t, "st", u.Query().Get("state"))
	return exchange(t, s, u.Query().Get("code"), verifier)
}

func decode(t *testing.T, part string, dst any) {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(part)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(b, dst))
}

func verifyRS256(t *testing.T, s *Server, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)
	var hdr struct{ Alg, Kid string }
	decode(t, parts[0], &hdr)
	require.Equal(t, "RS256", hdr.Alg)
	res, err := s.Client().Get(s.Issuer() + "/jwks")
	require.NoError(t, err)
	defer func() { _ = res.Body.Close() }()
	var set struct{ Keys []struct{ Kid, N, E string } }
	require.NoError(t, json.NewDecoder(res.Body).Decode(&set))
	for _, k := range set.Keys {
		if k.Kid != hdr.Kid {
			continue
		}
		n, _ := base64.RawURLEncoding.DecodeString(k.N)
		e, _ := base64.RawURLEncoding.DecodeString(k.E)
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
		sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		require.NoError(t, rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig))
		var claims map[string]any
		decode(t, parts[1], &claims)
		return claims
	}
	t.Fatalf("kid %s not in the JWKS", hdr.Kid)
	return nil
}

func start(t *testing.T) (*Server, *time.Time) {
	now := time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)
	s := Start(t, Options{Now: func() time.Time { return now }})
	s.RegisterRedirect(redirect)
	return s, &now
}

func TestDiscoveryAndAGoodLogin(t *testing.T) {
	s, now := start(t)
	res, err := s.Client().Get(s.Issuer() + "/.well-known/openid-configuration")
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, json.NewDecoder(res.Body).Decode(&doc))
	_ = res.Body.Close()
	assert.Equal(t, s.Issuer(), doc["issuer"])
	assert.Equal(t, s.Issuer()+"/jwks", doc["jwks_uri"])
	assert.True(t, strings.HasPrefix(s.Issuer(), "https://127.0.0.1:"))

	s.NextLogin(Login{Subject: "u-1", Username: "ada", Email: "ada@example.com", Groups: []string{"ops"}})
	status, body := login(t, s, strings.Repeat("v", 43))
	require.Equal(t, http.StatusOK, status, body)
	claims := verifyRS256(t, s, body["id_token"].(string))
	assert.Equal(t, s.Issuer(), claims["iss"])
	assert.Equal(t, s.ClientID(), claims["aud"])
	assert.Equal(t, "u-1", claims["sub"])
	assert.Equal(t, "no", claims["nonce"])
	assert.Equal(t, []any{"ops"}, claims["groups"])
	assert.Equal(t, float64(now.Add(5*time.Minute).Unix()), claims["exp"])
	assert.Equal(t, "code_verifier", firstKey(s.LastTokenForm(), "code_verifier"))
	st := s.Stats()
	assert.Equal(t, 1, st.Authorize)
	assert.Equal(t, 1, st.Token)
}

func firstKey(v url.Values, k string) string {
	if _, ok := v[k]; ok {
		return k
	}
	return ""
}

func TestPKCEAndSingleUseCodes(t *testing.T) {
	s, _ := start(t)
	cb, err := s.Authorize(authorizeURL(s, challengeOf(strings.Repeat("v", 43))))
	require.NoError(t, err)
	u, _ := url.Parse(cb)
	code := u.Query().Get("code")
	status, _ := exchange(t, s, code, strings.Repeat("w", 43))
	assert.Equal(t, http.StatusBadRequest, status, "wrong verifier")
	status, _ = exchange(t, s, code, strings.Repeat("v", 43))
	assert.Equal(t, http.StatusOK, status)
	status, _ = exchange(t, s, code, strings.Repeat("v", 43))
	assert.Equal(t, http.StatusBadRequest, status, "a code is used once")
	s.SetFault(Fault{ReplayCode: true})
	status, _ = login(t, s, strings.Repeat("x", 43))
	assert.Equal(t, http.StatusOK, status)
}

func TestAuthorizeRefusesUnknownRedirectsAndMissingPKCE(t *testing.T) {
	s, _ := start(t)
	bad := strings.Replace(authorizeURL(s, challengeOf("v")), url.QueryEscape(redirect), url.QueryEscape("https://evil.example/cb"), 1)
	_, err := s.Authorize(bad)
	assert.Error(t, err, "an unregistered redirect gets an error page, never a redirect")
	noPKCE := strings.Replace(authorizeURL(s, challengeOf("v")), "code_challenge_method=S256", "code_challenge_method=plain", 1)
	cb, err := s.Authorize(noPKCE)
	require.NoError(t, err)
	assert.Contains(t, cb, "error=invalid_request")
	s.SetFault(Fault{AuthorizeError: "access_denied"})
	cb, err = s.Authorize(authorizeURL(s, challengeOf("v")))
	require.NoError(t, err)
	assert.Contains(t, cb, "error=access_denied")
	assert.Contains(t, cb, "state=st")
}

func TestFaultsShapeTheToken(t *testing.T) {
	s, now := start(t)
	other := "other-nonce"
	s.SetFault(Fault{Issuer: "https://wrong", Audience: []string{"alice", "x"}, ExpIn: -time.Minute, IatOffset: 2 * time.Minute,
		NbfOffset: 3 * time.Minute, Nonce: &other, Overage: true, AuthTimeAgo: time.Hour, Azp: "x"})
	_, body := login(t, s, strings.Repeat("v", 43))
	claims := verifyRS256(t, s, body["id_token"].(string))
	assert.Equal(t, "https://wrong", claims["iss"])
	assert.Equal(t, []any{"alice", "x"}, claims["aud"])
	assert.Equal(t, float64(now.Add(-time.Minute).Unix()), claims["exp"])
	assert.Equal(t, float64(now.Add(2*time.Minute).Unix()), claims["iat"])
	assert.Equal(t, float64(now.Add(3*time.Minute).Unix()), claims["nbf"])
	assert.Equal(t, "other-nonce", claims["nonce"])
	assert.Equal(t, float64(now.Add(-time.Hour).Unix()), claims["auth_time"])
	assert.Equal(t, "x", claims["azp"])
	assert.Nil(t, claims["groups"])
	assert.NotNil(t, claims["_claim_names"])

	for _, f := range []Fault{{Alg: "none"}, {Alg: "HS256"}, {UnknownKid: true}, {OtherKey: true}} {
		s.SetFault(f)
		_, body := login(t, s, strings.Repeat("v", 43))
		parts := strings.Split(body["id_token"].(string), ".")
		var hdr struct{ Alg, Kid string }
		decode(t, parts[0], &hdr)
		switch {
		case f.Alg == "none":
			assert.Equal(t, "none", hdr.Alg)
			assert.Empty(t, parts[2])
		case f.Alg == "HS256":
			assert.Equal(t, "HS256", hdr.Alg)
		case f.UnknownKid:
			assert.Equal(t, "unknown", hdr.Kid)
		}
	}
}

func TestKeyRotationAndDown(t *testing.T) {
	s, _ := start(t)
	s.RotateKey()
	_, body := login(t, s, strings.Repeat("v", 43))
	verifyRS256(t, s, body["id_token"].(string)) // signed by the new key, found in the JWKS
	s.DropOldKeys()
	s.Down()
	res, err := s.Client().Get(s.Issuer() + "/jwks")
	require.NoError(t, err)
	_ = res.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, res.StatusCode)
	s.Up()
	res, err = s.Client().Get(s.Issuer() + "/jwks")
	require.NoError(t, err)
	_ = res.Body.Close()
	assert.Equal(t, http.StatusOK, res.StatusCode)
}

func TestPlainModeServesHTTP(t *testing.T) {
	s := Start(t, Options{Plain: true})
	assert.True(t, strings.HasPrefix(s.Issuer(), "http://127.0.0.1:"))
	assert.Nil(t, s.CAPEM())
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/testutil/fakesmtp/ ./internal/testutil/fakeidp/`
Expected: FAIL — no non-test Go files.

- [ ] **Step 3: Write the implementation**

`internal/testutil/fakesmtp/server.go`:

```go
// Package fakesmtp is an SMTP server for tests (spec §22.1; §26.9 "MailHog-compatible"): STARTTLS (or implicit TLS)
// with a self-signed certificate generated when it starts, optional AUTH PLAIN, a message store with decoded subject
// and body, fault switches (down, a refused recipient) and a MailHog-compatible HTTP API. It is the Go suites' fake
// and the engine of cmd/alice-fakesmtp (the e2e container). It holds no secret of Alice's.
package fakesmtp

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"io"
	"math/big"
	"mime"
	"net"
	"net/mail"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"alice/internal/platform/clock"
)

// Options configure the server.
type Options struct {
	Implicit   bool
	NoStartTLS bool
	Username   string
	Password   string
	Hostname   string
}

// Message is one accepted message.
type Message struct {
	From    string
	To      []string
	Subject string
	Body    string
	Raw     string
	Secure  bool
	Authed  bool
}

// Server is the fake.
type Server struct {
	opts    Options
	tlsCfg  *tls.Config
	certDER []byte

	mu       sync.Mutex
	ln       net.Listener
	addr     string
	messages []Message
	reject   string
}

// New generates the certificate. It does not listen yet.
func New(o Options) (*Server, error) {
	if o.Hostname == "" {
		o.Hostname = "127.0.0.1"
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := clock.Real{}.Now()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: o.Hostname},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if ip := net.ParseIP(o.Hostname); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{o.Hostname}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return &Server{opts: o, certDER: der, tlsCfg: &tls.Config{MinVersion: tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}}, nil
}

// Start is New and Listen on a free loopback port; t.Cleanup closes it.
func Start(t testing.TB, o Options) *Server {
	t.Helper()
	s, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

// Listen accepts connections on addr.
func (s *Server) Listen(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	if s.opts.Implicit {
		ln = tls.NewListener(ln, s.tlsCfg)
	}
	s.mu.Lock()
	s.ln, s.addr = ln, ln.Addr().String()
	s.mu.Unlock()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.session(c)
		}
	}()
	return nil
}

// Addr is the listening address.
func (s *Server) Addr() (string, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	host, port, _ := net.SplitHostPort(s.addr)
	p, _ := strconv.Atoi(port)
	return host, p
}

// CertPEM is the server certificate.
func (s *Server) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.certDER})
}

// Fingerprint is the lower-case hex SHA-256 of the certificate's DER.
func (s *Server) Fingerprint() string {
	sum := sha256.Sum256(s.certDER)
	return hex.EncodeToString(sum[:])
}

// Messages returns a copy of the stored messages.
func (s *Server) Messages() []Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Message(nil), s.messages...)
}

// Clear forgets every stored message.
func (s *Server) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.messages = nil
}

// Down closes the listener: new connections are refused until Up.
func (s *Server) Down() {
	s.mu.Lock()
	ln := s.ln
	s.ln = nil
	s.mu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
}

// Up listens again on the previous address.
func (s *Server) Up() error {
	s.mu.Lock()
	addr, up := s.addr, s.ln != nil
	s.mu.Unlock()
	if up {
		return nil
	}
	return s.Listen(addr)
}

// RejectRecipient makes RCPT TO addr answer 550; "" clears.
func (s *Server) RejectRecipient(addr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reject = addr
}

// Close stops the server.
func (s *Server) Close() { s.Down() }

func addrOf(arg string) string {
	_, v, _ := strings.Cut(arg, ":")
	return strings.Trim(strings.TrimSpace(v), "<>")
}

func (s *Server) session(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(clock.Real{}.Now().Add(time.Minute))
	tp := textproto.NewConn(conn)
	reply := func(format string, args ...any) { _ = tp.PrintfLine(format, args...) }
	secure, authed := s.opts.Implicit, false
	var from string
	var to []string
	reply("220 fakesmtp ESMTP")
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		verb, arg, _ := strings.Cut(line, " ")
		is := func(v string) bool { return strings.EqualFold(verb, v) }
		switch {
		case is("EHLO"), is("HELO"):
			lines := []string{"fakesmtp greets you"}
			if !secure && !s.opts.NoStartTLS {
				lines = append(lines, "STARTTLS")
			}
			if secure && s.opts.Username != "" {
				lines = append(lines, "AUTH PLAIN")
			}
			for i, l := range lines {
				sep := "-"
				if i == len(lines)-1 {
					sep = " "
				}
				reply("250%s%s", sep, l)
			}
		case is("STARTTLS"):
			if secure || s.opts.NoStartTLS {
				reply("503 5.5.1 TLS not available")
				continue
			}
			reply("220 2.0.0 ready")
			tc := tls.Server(conn, s.tlsCfg)
			if err := tc.Handshake(); err != nil {
				return
			}
			conn, tp, secure = tc, textproto.NewConn(tc), true
		case is("AUTH"):
			mech, payload, _ := strings.Cut(arg, " ")
			raw, err := base64.StdEncoding.DecodeString(payload)
			parts := strings.Split(string(raw), "\x00")
			if !strings.EqualFold(mech, "PLAIN") || !secure || err != nil || len(parts) != 3 ||
				parts[1] != s.opts.Username || parts[2] != s.opts.Password {
				reply("535 5.7.8 authentication failed")
				continue
			}
			authed = true
			reply("235 2.7.0 authenticated")
		case is("MAIL"):
			if s.opts.Username != "" && !authed {
				reply("530 5.7.0 authentication required")
				continue
			}
			from, to = addrOf(arg), nil
			reply("250 2.1.0 ok")
		case is("RCPT"):
			rcpt := addrOf(arg)
			s.mu.Lock()
			rejected := s.reject != "" && strings.EqualFold(rcpt, s.reject)
			s.mu.Unlock()
			if rejected {
				reply("550 5.1.1 mailbox unavailable")
				continue
			}
			to = append(to, rcpt)
			reply("250 2.1.5 ok")
		case is("DATA"):
			if from == "" || len(to) == 0 {
				reply("503 5.5.1 need MAIL and RCPT")
				continue
			}
			reply("354 go ahead")
			data, err := tp.ReadDotBytes()
			if err != nil {
				return
			}
			s.store(from, to, data, secure, authed)
			from, to = "", nil
			reply("250 2.0.0 queued")
		case is("RSET"):
			from, to = "", nil
			reply("250 2.0.0 ok")
		case is("NOOP"):
			reply("250 2.0.0 ok")
		case is("QUIT"):
			reply("221 2.0.0 bye")
			return
		default:
			reply("502 5.5.2 unknown command")
		}
	}
}

func (s *Server) store(from string, to []string, data []byte, secure, authed bool) {
	m := Message{From: from, To: to, Raw: string(data), Secure: secure, Authed: authed}
	if msg, err := mail.ReadMessage(bytes.NewReader(data)); err == nil {
		if subject, err := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject")); err == nil {
			m.Subject = subject
		}
		body, _ := io.ReadAll(msg.Body)
		if strings.EqualFold(msg.Header.Get("Content-Transfer-Encoding"), "base64") {
			if dec, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(string(body)), "")); err == nil {
				body = dec
			}
		}
		m.Body = strings.ReplaceAll(string(body), "\r\n", "\n")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.messages = append(s.messages, m)
}
```

`internal/testutil/fakesmtp/mailhog.go`:

```go
package fakesmtp

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

type mailhogPath struct{ Mailbox, Domain string }

type mailhogItem struct {
	ID      string
	From    mailhogPath
	To      []mailhogPath
	Content struct {
		Headers map[string][]string
		Body    string
	}
	Raw struct {
		From string
		To   []string
		Data string
	}
}

func pathOf(a string) mailhogPath {
	box, dom, _ := strings.Cut(a, "@")
	return mailhogPath{Mailbox: box, Domain: dom}
}

// Handler serves the MailHog API subset the e2e journeys and an operator's tools use: GET /api/v2/messages (the
// MailHog v2 shape; Content.Body is the decoded body) and DELETE /api/v1/messages.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v2/messages", func(w http.ResponseWriter, _ *http.Request) {
		msgs := s.Messages()
		items := make([]mailhogItem, 0, len(msgs))
		for i, m := range msgs {
			it := mailhogItem{ID: strconv.Itoa(i + 1), From: pathOf(m.From)}
			for _, t := range m.To {
				it.To = append(it.To, pathOf(t))
			}
			it.Content.Headers = map[string][]string{"Subject": {m.Subject}, "From": {m.From}, "To": m.To}
			it.Content.Body = m.Body
			it.Raw.From, it.Raw.To, it.Raw.Data = m.From, m.To, m.Raw
			items = append(items, it)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"total": len(items), "count": len(items), "start": 0, "items": items})
	})
	mux.HandleFunc("DELETE /api/v1/messages", func(w http.ResponseWriter, _ *http.Request) {
		s.Clear()
		w.WriteHeader(http.StatusOK)
	})
	return mux
}
```

`internal/testutil/fakeidp/server.go`:

```go
// Package fakeidp is an OpenID Connect identity provider for tests (spec §25.5: "generates keys, discovery document
// and signed ID tokens, supports fault injection"): discovery, JWKS, the authorization endpoint (it signs in the
// identity set by NextLogin without a form) and the token endpoint with PKCE S256, single-use codes and client
// authentication. It is the Go suites' fake and the engine of cmd/alice-fakeidp (the e2e container).
package fakeidp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"alice/internal/platform/clock"
)

// Options configure the provider.
type Options struct {
	Plain bool
	Host  string
	Now   func() time.Time
}

// Login is the identity the next authorization signs in.
type Login struct {
	Subject, Username, Name, Email string
	Groups                         []string
	Extra                          map[string]any
}

// Fault shapes the next tokens and answers (C6).
type Fault struct {
	Alg            string
	OtherKey       bool
	UnknownKid     bool
	Issuer         string
	Audience       []string
	Azp            string
	ExpIn          time.Duration
	IatOffset      time.Duration
	NbfOffset      time.Duration
	Nonce          *string
	OmitNonce      bool
	Overage        bool
	AuthTimeAgo    time.Duration
	OmitAuthTime   bool
	AuthorizeError string
	ReplayCode     bool
}

// Stats counts requests per endpoint.
type Stats struct{ Discovery, JWKS, Authorize, Token int }

type signingKey struct {
	kid string
	key *rsa.PrivateKey
}

type grant struct {
	login     Login
	nonce     string
	challenge string
	redirect  string
	authTime  time.Time
	used      bool
}

// Server is the provider.
type Server struct {
	opts     Options
	clientID string
	secret   string
	caPEM    []byte
	tlsCfg   *tls.Config
	client   *http.Client

	mu        sync.Mutex
	ln        net.Listener
	issuer    string
	keys      []signingKey
	redirects map[string]bool
	prefixes  []string
	next      Login
	fault     Fault
	grants    map[string]*grant
	down      bool
	stats     Stats
	lastForm  url.Values
}

func random(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// New makes the keys, the client secret and (unless Plain) a CA and the TLS certificate for Host.
func New(o Options) (*Server, error) {
	if o.Host == "" {
		o.Host = "127.0.0.1"
	}
	if o.Now == nil {
		o.Now = clock.Real{}.Now
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	s := &Server{opts: o, clientID: "alice", secret: random(32), keys: []signingKey{{kid: "k1", key: key}},
		redirects: map[string]bool{}, grants: map[string]*grant{}, next: Login{Subject: "user-1", Username: "user1"}}
	s.client = &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if o.Plain {
		return s, nil
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := clock.Real{}.Now()
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Alice e2e fake IdP CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	ca, _ := x509.ParseCertificate(caDER)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: o.Host},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if ip := net.ParseIP(o.Host); ip != nil {
		leafTmpl.IPAddresses = []net.IP{ip}
	} else {
		leafTmpl.DNSNames = []string{o.Host}
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	s.caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	s.tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}}}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	s.client.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	return s, nil
}

// Start is New and Listen on a free loopback port; t.Cleanup closes it.
func Start(t testing.TB, o Options) *Server {
	t.Helper()
	s, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

// Listen serves on addr; the issuer is scheme://Host:port.
func (s *Server) Listen(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	scheme := "https"
	if s.opts.Plain {
		scheme = "http"
	} else {
		ln = tls.NewListener(ln, s.tlsCfg)
	}
	s.mu.Lock()
	s.ln, s.issuer = ln, scheme+"://"+net.JoinHostPort(s.opts.Host, port)
	s.mu.Unlock()
	srv := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	return nil
}

// Close stops listening.
func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln != nil {
		_ = s.ln.Close()
	}
}

func (s *Server) Issuer() string       { s.mu.Lock(); defer s.mu.Unlock(); return s.issuer }
func (s *Server) ClientID() string     { return s.clientID }
func (s *Server) ClientSecret() string { return s.secret }
func (s *Server) CAPEM() []byte        { return s.caPEM }
func (s *Server) Client() *http.Client { return s.client }

func (s *Server) RegisterRedirect(uri string)          { s.mu.Lock(); defer s.mu.Unlock(); s.redirects[uri] = true }
func (s *Server) RegisterRedirectPrefix(prefix string) { s.mu.Lock(); defer s.mu.Unlock(); s.prefixes = append(s.prefixes, prefix) }
func (s *Server) NextLogin(l Login)                    { s.mu.Lock(); defer s.mu.Unlock(); s.next = l }
func (s *Server) SetFault(f Fault)                     { s.mu.Lock(); defer s.mu.Unlock(); s.fault = f }
func (s *Server) Down()                                { s.mu.Lock(); defer s.mu.Unlock(); s.down = true }
func (s *Server) Up()                                  { s.mu.Lock(); defer s.mu.Unlock(); s.down = false }
func (s *Server) Stats() Stats                         { s.mu.Lock(); defer s.mu.Unlock(); return s.stats }

// LastTokenForm is a copy of the last token request's form.
func (s *Server) LastTokenForm() url.Values {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := url.Values{}
	for k, v := range s.lastForm {
		out[k] = append([]string(nil), v...)
	}
	return out
}

// RotateKey adds a signing key with a new kid; the old ones stay in the JWKS until DropOldKeys.
func (s *Server) RotateKey() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys = append(s.keys, signingKey{kid: "k" + strconv.Itoa(len(s.keys)+1), key: key})
}

// DropOldKeys keeps only the newest signing key.
func (s *Server) DropOldKeys() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys = s.keys[len(s.keys)-1:]
}

// Authorize performs the browser's visit of authorizeURL and returns where the provider redirects it.
func (s *Server) Authorize(authorizeURL string) (string, error) {
	res, err := s.client.Get(authorizeURL)
	if err != nil {
		return "", err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusFound {
		return "", fmt.Errorf("fakeidp: authorize answered %d", res.StatusCode)
	}
	return res.Header.Get("Location"), nil
}

func (s *Server) redirectAllowed(uri string) bool {
	if s.redirects[uri] {
		return true
	}
	for _, p := range s.prefixes {
		if strings.HasPrefix(uri, p) {
			return true
		}
	}
	return false
}

// Handler serves the provider's endpoints.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", s.discovery)
	mux.HandleFunc("GET /jwks", s.jwks)
	mux.HandleFunc("GET /authorize", s.authorize)
	mux.HandleFunc("POST /token", s.token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		down := s.down
		s.mu.Unlock()
		if down {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) discovery(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	s.stats.Discovery++
	iss := s.issuer
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"issuer": iss, "authorization_endpoint": iss + "/authorize",
		"token_endpoint": iss + "/token", "jwks_uri": iss + "/jwks", "response_types_supported": []string{"code"},
		"subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"RS256"},
		"code_challenge_methods_supported": []string{"S256"}, "scopes_supported": []string{"openid", "profile", "email"}})
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (s *Server) jwks(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	s.stats.JWKS++
	keys := make([]map[string]string, 0, len(s.keys))
	for _, k := range s.keys {
		keys = append(keys, map[string]string{"kty": "RSA", "kid": k.kid, "use": "sig", "alg": "RS256",
			"n": b64(k.key.N.Bytes()), "e": b64(big.NewInt(int64(k.key.E)).Bytes())})
	}
	s.mu.Unlock()
	w.Header().Set("Cache-Control", "max-age=300")
	writeJSON(w, http.StatusOK, map[string]any{"keys": keys})
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.Authorize++
	redirect := q.Get("redirect_uri")
	if q.Get("client_id") != s.clientID || !s.redirectAllowed(redirect) {
		http.Error(w, "unknown client or redirect_uri", http.StatusBadRequest)
		return
	}
	target, err := url.Parse(redirect)
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	vals := target.Query()
	vals.Set("state", q.Get("state"))
	switch {
	case s.fault.AuthorizeError != "":
		vals.Set("error", s.fault.AuthorizeError)
	case q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" ||
		!strings.Contains(" "+q.Get("scope")+" ", " openid "):
		vals.Set("error", "invalid_request")
	default:
		code := random(24)
		s.grants[code] = &grant{login: s.next, nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), redirect: redirect,
			authTime: s.opts.Now()}
		vals.Set("code", code)
	}
	target.RawQuery = vals.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.Token++
	s.lastForm = r.PostForm
	id, secret, ok := r.BasicAuth()
	if ok {
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
	} else {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	if id != s.clientID || secret != s.secret {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	g := s.grants[r.PostForm.Get("code")]
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if g == nil || (g.used && !s.fault.ReplayCode) || r.PostForm.Get("redirect_uri") != g.redirect || b64(sum[:]) != g.challenge ||
		r.PostForm.Get("grant_type") != "authorization_code" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}
	g.used = true
	tok, err := s.idToken(g)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"access_token": random(24), "token_type": "Bearer", "expires_in": 300, "id_token": tok})
}

var errNoKey = errors.New("fakeidp: no signing key")
```

`internal/testutil/fakeidp/tokens.go`:

```go
package fakeidp

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"time"
)

// idToken builds the ID token of g with the current fault. The caller holds s.mu.
func (s *Server) idToken(g *grant) (string, error) {
	if len(s.keys) == 0 {
		return "", errNoKey
	}
	f, l, now := s.fault, g.login, s.opts.Now()
	expIn := 5 * time.Minute
	if f.ExpIn != 0 {
		expIn = f.ExpIn
	}
	claims := map[string]any{"iss": s.issuer, "aud": s.clientID, "sub": l.Subject, "nonce": g.nonce,
		"exp": now.Add(expIn).Unix(), "iat": now.Add(f.IatOffset).Unix(), "auth_time": g.authTime.Add(-f.AuthTimeAgo).Unix()}
	for k, v := range map[string]string{"email": l.Email, "name": l.Name, "preferred_username": l.Username} {
		if v != "" {
			claims[k] = v
		}
	}
	if f.Overage {
		claims["_claim_names"] = map[string]string{"groups": "src1"}
		claims["_claim_sources"] = map[string]any{"src1": map[string]string{"endpoint": "https://graph.microsoft.com/v1.0/users/" + l.Subject + "/getMemberObjects"}}
	} else if l.Groups != nil {
		claims["groups"] = l.Groups
	}
	for k, v := range l.Extra {
		claims[k] = v
	}
	if f.Issuer != "" {
		claims["iss"] = f.Issuer
	}
	switch len(f.Audience) {
	case 0:
	case 1:
		claims["aud"] = f.Audience[0]
	default:
		claims["aud"] = f.Audience
	}
	if f.Azp != "" {
		claims["azp"] = f.Azp
	}
	if f.NbfOffset != 0 {
		claims["nbf"] = now.Add(f.NbfOffset).Unix()
	}
	if f.Nonce != nil {
		claims["nonce"] = *f.Nonce
	}
	if f.OmitNonce {
		delete(claims, "nonce")
	}
	if f.OmitAuthTime {
		delete(claims, "auth_time")
	}
	signer := s.keys[len(s.keys)-1]
	alg, kid := "RS256", signer.kid
	switch {
	case f.Alg != "":
		alg = f.Alg
	case f.UnknownKid:
		kid = "unknown"
	}
	hdr, err := json.Marshal(map[string]string{"alg": alg, "typ": "JWT", "kid": kid})
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := b64(hdr) + "." + b64(body)
	switch alg {
	case "none":
		return input + ".", nil
	case "HS256":
		pub, err := x509.MarshalPKIXPublicKey(&signer.key.PublicKey)
		if err != nil {
			return "", err
		}
		mac := hmac.New(sha256.New, pub) // algorithm confusion: the public key as the HMAC secret (O-01)
		mac.Write([]byte(input))
		return input + "." + b64(mac.Sum(nil)), nil
	}
	key := signer.key
	if f.OtherKey {
		if key, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			return "", err
		}
	}
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return input + "." + b64(sig), nil
}
```

Notes: the one-line accessor methods are written on one line for brevity here; `gofmt` expands them (run `gofmt -w`). `TestDiscoveryAndAGoodLogin`'s `firstKey` check asserts the token form carried `code_verifier`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -count=1 -race -cover ./internal/testutil/fakesmtp/ ./internal/testutil/fakeidp/ ./internal/archtest/`
Expected: `ok` for all three (coverage is reported; the floors are set in Task 22).

Run: `make lint`
Expected: no findings (the fakes call `clock.Real{}.Now()`, never `time.Now`).

- [ ] **Step 5: Commit**

```bash
git add -- internal/testutil/fakesmtp internal/testutil/fakeidp
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "test(testutil): fakesmtp with a MailHog-compatible API and fakeidp with discovery, JWKS, PKCE and fault injection" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- internal/testutil/fakesmtp internal/testutil/fakeidp
```

---

### Task 5: Migration `00011_alerts_dashboard_sso.sql`

**Files:**
- Create: `migrations/00011_alerts_dashboard_sso.sql` (C2 exactly)
- Create: `migrations/phase7_integration_test.go`
- Modify: `migrations/roles_integration_test.go` (`explicitGrants`: `public.alerts`, `public.oidc_login_states`)

**Interfaces:**
- Consumes: the existing tables `users`, `settings`; helpers `sqlState`, `exec` (`migrations/inventory_integration_test.go`), `tableExists`, `grantProblems` (`migrations/down_integration_test.go`, `roles_integration_test.go`).
- Produces: C2 exactly; SQLSTATE `Z1015`.

- [ ] **Step 1: Write the failing tests**

`migrations/phase7_integration_test.go`:

```go
//go:build integration

package migrations_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/testutil/pgtest"
	"alice/migrations"
)

func seedUser(t *testing.T, d *pgtest.DB, name, email string) uuid.UUID {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	require.NoError(t, exec(t, d.App, `INSERT INTO users (id, username, display_name, email, password_hash, role, created_at, updated_at)
VALUES ($1, $2::text, $2::text, $3, '$argon2id$x', 'admin', now(), now())`, id, name, email))
	return id
}

func seedProvider(t *testing.T, d *pgtest.DB, name string) uuid.UUID {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	require.NoError(t, exec(t, d.App, `INSERT INTO oidc_providers (id, name, issuer_url, client_id, scopes, groups_claim,
authorization_endpoint, token_endpoint, jwks_uri, enabled, created_at, updated_at)
VALUES ($1, $2, 'https://idp.example.com/realms/corp', 'alice', '{openid,email}', 'groups', 'https://idp.example.com/a',
'https://idp.example.com/t', 'https://idp.example.com/j', true, now(), now())`, id, name))
	return id
}

func TestAlertsLedgerIsUniqueAndAppendOnly(t *testing.T) {
	d := pgtest.New(t)
	obj := uuid.New()
	insert := func(threshold int) error {
		return exec(t, d.App, `INSERT INTO alerts (id, kind, object_id, subject, expires_at, threshold_days, license_locked, emailed, created_at)
VALUES ($1, 'certificate_expiry', $2, 'www.example.com', '2026-12-01T00:00:00Z', $3, false, true, now())`, uuid.New(), obj, threshold)
	}
	require.NoError(t, insert(30))
	assert.Equal(t, "23505", sqlState(insert(30)), "one notice per kind, object, expiry instant and threshold")
	require.NoError(t, insert(0))
	assert.Equal(t, "23514", sqlState(insert(366)))
	assert.Equal(t, "23514", sqlState(exec(t, d.App, `INSERT INTO alerts (id, kind, object_id, subject, expires_at, threshold_days,
license_locked, emailed, created_at) VALUES ($1, 'license_expiry', $2, 'x', now(), 1, false, true, now())`, uuid.New(), obj)))
	assert.Equal(t, "42501", sqlState(exec(t, d.App, `UPDATE alerts SET emailed = false`)), "append-only for the application")
	assert.Equal(t, "42501", sqlState(exec(t, d.App, `DELETE FROM alerts`)))
}

func TestSettingSecretsHoldOnlyKnownKeys(t *testing.T) {
	d := pgtest.New(t)
	put := func(key string) error {
		return exec(t, d.App, `INSERT INTO setting_secrets (key, ciphertext, nonce, wrapped_dek, key_version, updated_at)
VALUES ($1, '\x01', decode(repeat('00', 12), 'hex'), '\x02', 1, now())`, key)
	}
	require.NoError(t, put("notify.smtp.password"))
	require.NoError(t, put("sso.provider."+uuid.NewString()+".client_secret"))
	for _, bad := range []string{"notify.smtp.user", "sso.provider.x.client_secret", "general", "NOTIFY.SMTP.PASSWORD"} {
		assert.Equal(t, "23514", sqlState(put(bad)), bad)
	}
}

func TestSSOUsersAreNeverLocal(t *testing.T) {
	d := pgtest.New(t)
	p := seedProvider(t, d, "Corp IdP")
	local := seedUser(t, d, "ada", "ada@example.com")
	ssoUser := func(name, sub string, password any, breakGlass bool, roleSource string) error {
		return exec(t, d.App, `INSERT INTO users (id, username, display_name, auth_source, password_hash, role, role_source, is_break_glass,
oidc_provider_id, oidc_issuer, oidc_subject, created_at, updated_at)
VALUES ($1, $2::text, $2::text, 'oidc', $3, 'operator', $6, $4, $5, 'https://idp.example.com/realms/corp', $7, now(), now())`,
			uuid.New(), name, password, breakGlass, p, roleSource, sub)
	}
	require.NoError(t, ssoUser("ada-sso", "sub-1", nil, false, "oidc_mapping"))
	assert.Equal(t, "23505", sqlState(ssoUser("other", "sub-1", nil, false, "oidc_mapping")), "one user per (issuer, subject)")
	assert.Equal(t, "23514", sqlState(ssoUser("pw", "sub-2", "$argon2id$x", false, "oidc_mapping")), "no password")
	assert.Equal(t, "23514", sqlState(ssoUser("bg", "sub-3", nil, true, "oidc_mapping")), "never break-glass")
	assert.Equal(t, "23514", sqlState(ssoUser("manual", "sub-4", nil, false, "manual")), "role from the mapping")
	assert.Equal(t, "23514", sqlState(exec(t, d.App, `UPDATE users SET oidc_issuer = 'https://idp.example.com/realms/corp',
oidc_subject = 'x', oidc_provider_id = $2 WHERE id = $1`, local, p)), "a local user has no SSO identity")
	assert.Equal(t, "23514", sqlState(exec(t, d.App, `INSERT INTO users (id, username, display_name, auth_source, role, role_source,
created_at, updated_at) VALUES ($1, 'half', 'half', 'oidc', 'auditor', 'oidc_mapping', now(), now())`, uuid.New())), "all three columns")
	assert.Equal(t, "23503", sqlState(exec(t, d.App, `DELETE FROM oidc_providers WHERE id = $1`, p)), "a provider with users stays")
}

func TestMappingsRefuseEmptyAndInvisibleGroups(t *testing.T) {
	d := pgtest.New(t)
	p := seedProvider(t, d, "Corp IdP")
	put := func(group, role string) error {
		return exec(t, d.App, `INSERT INTO oidc_group_mappings (id, provider_id, group_claim_value, role, created_at)
VALUES ($1, $2, $3, $4, now())`, uuid.New(), p, group, role)
	}
	require.NoError(t, put("ops", "operator"))
	assert.Equal(t, "23505", sqlState(put("ops", "auditor")))
	for _, bad := range []string{"", " ops", "ops ", "o\tps", "o\nps"} {
		assert.Equal(t, "23514", sqlState(put(bad, "auditor")), "%q", bad)
	}
	assert.Equal(t, "23514", sqlState(put("x", "owner")))
	require.NoError(t, exec(t, d.App, `DELETE FROM oidc_providers WHERE id = $1`, p), "mappings go with their provider")
}

func TestLoginStatesAreShortLivedAndSingleUse(t *testing.T) {
	d := pgtest.New(t)
	p := seedProvider(t, d, "Corp IdP")
	u := seedUser(t, d, "ada", "")
	put := func(purpose string, session []byte, user any, lifetime string) error {
		return exec(t, d.App, `INSERT INTO oidc_login_states (state_hash, provider_id, binding_hash, nonce, code_verifier, purpose,
session_hash, user_id, next_path, created_at, expires_at)
VALUES (decode(md5(random()::text) || md5(random()::text), 'hex'), $1, decode(repeat('ab', 32), 'hex'), repeat('n', 43),
repeat('v', 43), $2, $3, $4, '/', now(), now() + $5::interval)`, p, purpose, session, user, lifetime)
	}
	require.NoError(t, put("login", nil, nil, "10 minutes"))
	assert.Equal(t, "23514", sqlState(put("login", nil, nil, "11 minutes")))
	assert.Equal(t, "23514", sqlState(put("stepup", nil, nil, "5 minutes")), "a step-up names its session and user")
	require.NoError(t, put("stepup", make([]byte, 32), u, "5 minutes"))
	assert.Equal(t, "42501", sqlState(exec(t, d.App, `UPDATE oidc_login_states SET next_path = '/x'`)), "never changed")
	require.NoError(t, exec(t, d.App, `DELETE FROM oidc_login_states`))
}

func TestSavedViewsArePerUserAndPage(t *testing.T) {
	d := pgtest.New(t)
	u := seedUser(t, d, "ada", "")
	put := func(page, name string) error {
		return exec(t, d.App, `INSERT INTO saved_views (id, user_id, page, name, query, created_at) VALUES ($1, $2, $3, $4, '{}', now())`,
			uuid.New(), u, page, name)
	}
	require.NoError(t, put("certificates", "Expiring"))
	assert.Equal(t, "23505", sqlState(put("certificates", "EXPIRING")), "names are unique per user and page, ignoring case")
	require.NoError(t, put("ssh_keys", "Expiring"))
	assert.Equal(t, "23514", sqlState(put("targets", "x")))
	assert.Equal(t, "23514", sqlState(put("certificates", "")))
}

func TestMigration00011DownRefusesPhase7DataAndIsCleanWithout(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	p, err := goose.NewProvider(goose.DialectPostgres, stdlib.OpenDBFromPool(d.Owner), migrations.FS)
	require.NoError(t, err)
	_, err = p.DownTo(ctx, 10)
	require.NoError(t, err, "no Phase 7 data: the Down runs")
	for _, tbl := range []string{"alerts", "setting_secrets", "saved_views", "oidc_providers", "oidc_group_mappings", "oidc_login_states"} {
		assert.False(t, tableExists(t, d, tbl), tbl)
	}
	assert.Empty(t, grantProblems(t, d))
	_, err = p.Up(ctx)
	require.NoError(t, err)
	assert.Empty(t, grantProblems(t, d))
	seedProvider(t, d, "Corp IdP")
	_, err = p.DownTo(ctx, 10)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Z1015")
	assert.True(t, tableExists(t, d, "oidc_providers"), "nothing changed")
}
```

`migrations/roles_integration_test.go`, in `explicitGrants`:

```go
	// Phase 7 (R42): the notice ledger is append-only; sign-in states are inserted and deleted, never changed.
	"public.alerts":            {"INSERT", "SELECT"},
	"public.oidc_login_states": {"DELETE", "INSERT", "SELECT"},
```

- [ ] **Step 2: Run the tests to verify they fail** (Docker: testcontainers)

Run: `go test -count=1 -tags integration ./migrations/`
Expected: FAIL — relation `alerts` does not exist (and the grant guard names the two missing tables).

- [ ] **Step 3: Write the migration**

Create `migrations/00011_alerts_dashboard_sso.sql` with exactly the SQL of C2.

If `TestGrantGuardCatchesUnlistedRelations` asserts a fixed count of problems for its synthetic relations, it is unaffected (it creates its own relations). If `grantProblems` in `TestMigration00006UpAndDownKeepPhase3Data` (which goes down to 5 and up again) reports a Phase 7 table, the cause is a missing `explicitGrants` entry: add it, never relax the guard.

- [ ] **Step 4: Run the tests to verify they pass** (Docker: testcontainers)

Run: `go test -count=1 -tags integration ./migrations/`
Expected: `ok` (the new tests, the grant guard, and every earlier Up/Down test).

Run: `go test -count=1 -tags integration ./internal/notify/ ./internal/auth/`
Expected: `ok` (the new `users` columns are nullable and constrained only for `auth_source = 'oidc'`; existing inserts are untouched).

- [ ] **Step 5: Commit**

```bash
git add -- migrations/00011_alerts_dashboard_sso.sql migrations/phase7_integration_test.go
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(migrations): 00011 — alert ledger, settings secrets, saved views, identity providers, SSO users, sign-in states" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- migrations/00011_alerts_dashboard_sso.sql \
  migrations/phase7_integration_test.go migrations/roles_integration_test.go
```

---

### Task 6: `internal/notify` part 1: mail settings, `setting_secrets`, the mailer source, CA bundle and pinning, the test mail, the env import; `settings.GetGeneral`

**Files:**
- Create: `internal/secrets/settings.go` (`Keyring.PutSetting`, `Keyring.GetSetting`, `DeleteSetting`), `internal/secrets/settings_integration_test.go`
- Create: `internal/platform/settings/general.go`, `internal/platform/settings/general_integration_test.go`
- Create: `internal/notify/settings.go` (types, `Settings`, `NewSettings`, `SMTP`, `SaveSMTP`, `DeleteSMTP`, validation), `internal/notify/pin.go` (`pinnedTLS`, `infoOf`, `CertError`), `internal/notify/testmail.go` (`TestMail`, `Trust`, `Untrust`), `internal/notify/envimport.go` (`ImportEnv`), `internal/notify/source.go` (`MailerSource`, `Settings.Mailer`)
- Modify: `internal/notify/smtp.go` (`SMTPConfig.Pin`, `SMTPConfig.Dial`, certificate errors, `ErrSMTPUntrusted`, `ErrAddressRefused`, `ErrorCode` labels `smtp.untrusted` and `smtp.address_refused`), `internal/notify/sender.go` (`Sender.Source`; one mailer per `Drain`)
- Create: `internal/notify/pin_test.go`, `internal/notify/settings_integration_test.go`
- Modify: `locales/common/en.json`, `locales/common/tr.json` (`email.notify.test.subject|body` of C14)

**Interfaces:**
- Consumes: `secrets.{Keyring, Location, Envelope, Plaintext, NewPlaintext}`, `settings.{Get, Set}`, `netaddr.{DialContext, ErrNotAllowed}`, `audit.{Log, Append, Event, Actor, SystemActor, Success, Failure}`, `config.SMTP`, `i18n.Catalog`, `db.InTx`, `fakesmtp` (tests), the table `setting_secrets` (Task 5).
- Produces: C7's mail-settings part (`TLSMode*`, `TestMailTimeout`, `SeenCertValidFor`, `TemplateTestMail`, `ErrNotConfigured`, `ErrVersion`, `ErrCertNotSeen`, `ErrAddressRefused`, `ErrSMTPUntrusted`, `CertInfo`, `CertError`, `TrustedCert`, `SMTPSettings`, `SMTPInput`, `SettingsConfig`, `Settings`, `NewSettings`, `SMTP`, `SaveSMTP`, `DeleteSMTP`, `TestMail`, `Trust`, `Untrust`, `ImportEnv`, `Mailer`, `MailerSource`, `Sender.Source`); `settings.{General, GetGeneral, GeneralKey, DefaultRetiredKeyRetentionDays}`; `secrets.{Keyring.PutSetting, Keyring.GetSetting, DeleteSetting}`.

- [ ] **Step 1: Write the failing tests**

`internal/secrets/settings_integration_test.go`:

```go
//go:build integration

package secrets_test

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/secrets"
	"alice/internal/testutil/pgtest"
)

func TestMain(m *testing.M) { os.Exit(pgtest.Main(m)) }

func TestSettingSecretsRoundTripBoundToTheirKey(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	k, err := secrets.NewKeyring(1, bytes.Repeat([]byte{7}, 32))
	require.NoError(t, err)
	now := time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)
	require.NoError(t, k.PutSetting(ctx, d.App, "notify.smtp.password", secrets.NewPlaintext([]byte("CANARY-smtp-1")), now))
	got, ok, err := k.GetSetting(ctx, d.App, "notify.smtp.password")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "CANARY-smtp-1", string(got.Bytes()))
	got.Zero()

	var raw []byte
	require.NoError(t, d.Owner.QueryRow(ctx, "SELECT ciphertext FROM setting_secrets WHERE key = 'notify.smtp.password'").Scan(&raw))
	assert.NotContains(t, string(raw), "CANARY", "S-04: only ciphertext is stored")

	// Copied under another key, the envelope does not open (AAD setting_secrets/<key>/ciphertext).
	other := "sso.provider.0192e000-0000-7000-8000-000000000001.client_secret"
	_, err = d.Owner.Exec(ctx, `INSERT INTO setting_secrets (key, ciphertext, nonce, wrapped_dek, key_version, updated_at)
SELECT $1, ciphertext, nonce, wrapped_dek, key_version, updated_at FROM setting_secrets WHERE key = 'notify.smtp.password'`, other)
	require.NoError(t, err)
	_, _, err = k.GetSetting(ctx, d.App, other)
	assert.ErrorIs(t, err, secrets.ErrDecrypt)

	require.NoError(t, k.PutSetting(ctx, d.App, "notify.smtp.password", secrets.NewPlaintext([]byte("CANARY-smtp-2")), now))
	got, _, err = k.GetSetting(ctx, d.App, "notify.smtp.password")
	require.NoError(t, err)
	assert.Equal(t, "CANARY-smtp-2", string(got.Bytes()), "a put replaces")
	require.NoError(t, secrets.DeleteSetting(ctx, d.App, "notify.smtp.password"))
	_, ok, err = k.GetSetting(ctx, d.App, "notify.smtp.password")
	require.NoError(t, err)
	assert.False(t, ok)
}
```

(`secrets.ErrDecrypt` is the existing error of `Keyring.Open`; if `internal/secrets` already has a `TestMain`, add `pgtest.Main` to it instead of a second one.)

`internal/platform/settings/general_integration_test.go`:

```go
//go:build integration

package settings_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/settings"
	"alice/internal/testutil/pgtest"
)

func TestMain(m *testing.M) { os.Exit(pgtest.Main(m)) }

func TestGeneralDefaultsAndStoredValues(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	g, err := settings.GetGeneral(ctx, d.App)
	require.NoError(t, err)
	assert.Equal(t, settings.General{RetiredKeyRetentionDays: settings.DefaultRetiredKeyRetentionDays}, g)
	require.NoError(t, settings.Set(ctx, d.App, settings.GeneralKey,
		settings.General{PublicURL: "https://alice.example.com", RetiredKeyRetentionDays: 90, Version: 2}, time.Now()))
	g, err = settings.GetGeneral(ctx, d.App)
	require.NoError(t, err)
	assert.Equal(t, settings.General{PublicURL: "https://alice.example.com", RetiredKeyRetentionDays: 90, Version: 2}, g)
}
```

`internal/notify/pin_test.go`:

```go
package notify_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/notify"
	"alice/internal/platform/clock"
	"alice/internal/testutil/fakesmtp"
)

func smtpConfigFor(s *fakesmtp.Server) notify.SMTPConfig {
	host, port := s.Addr()
	return notify.SMTPConfig{Host: host, Port: port, From: "alice@example.com", TLSMode: "starttls"}
}

// F-62: an untrusted certificate is refused with its fingerprint; a pin accepts exactly that certificate.
func TestF62UntrustedCertificateAndThePin(t *testing.T) {
	s := fakesmtp.Start(t, fakesmtp.Options{})
	clk := clock.NewFake(time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC))
	m, err := notify.NewSMTPMailer(smtpConfigFor(s), clk)
	require.NoError(t, err)
	err = m.Send(context.Background(), notify.Message{To: "ops@example.com", Subject: "s", Body: "b"})
	var ce *notify.CertError
	require.True(t, errors.As(err, &ce), "%v", err)
	assert.Equal(t, s.Fingerprint(), ce.Cert.Fingerprint)
	assert.Contains(t, ce.Cert.Subject, "127.0.0.1")
	assert.ErrorIs(t, err, notify.ErrSMTPUntrusted)
	assert.ErrorIs(t, err, notify.ErrSMTPTLS)
	assert.Equal(t, "smtp.untrusted", notify.ErrorCode(err))
	assert.Empty(t, s.Messages())

	cfg := smtpConfigFor(s)
	cfg.Pin = s.Fingerprint()
	m, err = notify.NewSMTPMailer(cfg, clk)
	require.NoError(t, err)
	require.NoError(t, m.Send(context.Background(), notify.Message{To: "ops@example.com", Subject: "s", Body: "b"}))
	assert.Len(t, s.Messages(), 1)

	cfg.Pin = "00" + s.Fingerprint()[2:]
	m, err = notify.NewSMTPMailer(cfg, clk)
	require.NoError(t, err)
	err = m.Send(context.Background(), notify.Message{To: "ops@example.com", Subject: "s", Body: "b"})
	require.True(t, errors.As(err, &ce), "a pin that does not match is an untrusted certificate, with the one served")
	assert.Equal(t, s.Fingerprint(), ce.Cert.Fingerprint)
	assert.Len(t, s.Messages(), 1, "nothing was sent")
}

// A-14: an SMTP host on a refused address is never dialled.
func TestAddressRefused(t *testing.T) {
	clk := clock.NewFake(time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC))
	m, err := notify.NewSMTPMailer(notify.SMTPConfig{Host: "169.254.169.254", Port: 587, From: "alice@example.com"}, clk)
	require.NoError(t, err)
	err = m.Send(context.Background(), notify.Message{To: "ops@example.com", Subject: "s", Body: "b"})
	assert.ErrorIs(t, err, notify.ErrAddressRefused)
	assert.Equal(t, "smtp.address_refused", notify.ErrorCode(err))
}
```

`internal/notify/settings_integration_test.go` (in package `notify_test`, beside `outbox_integration_test.go`, sharing its `TestMain` and `addUser`):

```go
//go:build integration

package notify_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/i18n"
	"alice/internal/notify"
	"alice/internal/platform/clock"
	"alice/internal/platform/config"
	"alice/internal/platform/validate"
	"alice/internal/secrets"
	"alice/internal/testutil/fakesmtp"
	"alice/internal/testutil/pgtest"
	"alice/locales"
)

const canary = "CANARY-smtp-0b7c"

type harness struct {
	d   *pgtest.DB
	s   *notify.Settings
	clk *clock.Fake
	who audit.Actor
}

func newHarness(t *testing.T, fallback notify.Mailer) harness {
	t.Helper()
	d := pgtest.New(t)
	k, err := secrets.NewKeyring(1, bytes.Repeat([]byte{7}, 32))
	require.NoError(t, err)
	clk := clock.NewFake(time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC))
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	s := notify.NewSettings(notify.SettingsConfig{Pool: d.App, Keyring: k, Audit: audit.New(clk), Clock: clk,
		Catalog: cat, Fallback: fallback})
	return harness{d: d, s: s, clk: clk, who: audit.Actor{Type: audit.ActorUser, Name: "ada"}}
}

func input(srv *fakesmtp.Server, password *secrets.Plaintext) notify.SMTPInput {
	host, port := srv.Addr()
	return notify.SMTPInput{Host: host, Port: port, TLSMode: notify.TLSModeSTARTTLS, From: "alice@example.com",
		Username: "mailer", Password: password}
}

func pw(v string) *secrets.Plaintext { p := secrets.NewPlaintext([]byte(v)); return &p }

func TestSaveSMTPValidatesAndVersions(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	srv := fakesmtp.Start(t, fakesmtp.Options{})
	_, ok, err := h.s.SMTP(ctx)
	require.NoError(t, err)
	assert.False(t, ok)
	bad := input(srv, pw(canary))
	bad.Host, bad.Port, bad.TLSMode, bad.From = "a b", 0, "plain", "not-an-address"
	_, err = h.s.SaveSMTP(ctx, h.who, 0, bad)
	var verrs validate.Errors
	require.True(t, errors.As(err, &verrs), "%v", err)
	fields := map[string]bool{}
	for _, f := range verrs {
		fields[f.Field] = true
	}
	assert.Equal(t, map[string]bool{"host": true, "port": true, "tls_mode": true, "from": true}, fields)
	got, err := h.s.SaveSMTP(ctx, h.who, 0, input(srv, pw(canary)))
	require.NoError(t, err)
	assert.Equal(t, 1, got.Version)
	assert.True(t, got.HasPassword)
	_, err = h.s.SaveSMTP(ctx, h.who, 0, input(srv, nil))
	assert.ErrorIs(t, err, notify.ErrVersion, "If-Match of a stale version")
	got, err = h.s.SaveSMTP(ctx, h.who, 1, input(srv, nil))
	require.NoError(t, err)
	assert.True(t, got.HasPassword, "nil keeps the password")
	empty := secrets.NewPlaintext(nil)
	in := input(srv, &empty)
	in.Username = ""
	got, err = h.s.SaveSMTP(ctx, h.who, 2, in)
	require.NoError(t, err)
	assert.False(t, got.HasPassword, "an empty password removes it")
	require.NoError(t, h.s.DeleteSMTP(ctx, h.who, 3))
	_, ok, err = h.s.SMTP(ctx)
	require.NoError(t, err)
	assert.False(t, ok)
}

// Review Focus 3, S-04: the password is only an envelope; no settings value, audit row or error holds it.
func TestSMTPPasswordIsAnEnvelope(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	srv := fakesmtp.Start(t, fakesmtp.Options{Username: "mailer", Password: "right"})
	in := input(srv, pw(canary))
	in.CAPEM = string(srv.CertPEM()) // the certificate verifies, so the test reaches AUTH
	_, err := h.s.SaveSMTP(ctx, h.who, 0, in)
	require.NoError(t, err)
	var dump string
	require.NoError(t, h.d.Owner.QueryRow(ctx, `SELECT coalesce(string_agg(value::text, ' '), '') FROM settings`).Scan(&dump))
	assert.NotContains(t, dump, canary)
	require.NoError(t, h.d.Owner.QueryRow(ctx, `SELECT coalesce(string_agg(details::text, ' '), '') FROM audit_log`).Scan(&dump))
	assert.NotContains(t, dump, canary)
	assert.Contains(t, dump, `"auth_changed": "true"`)
	var ct []byte
	require.NoError(t, h.d.Owner.QueryRow(ctx, `SELECT ciphertext FROM setting_secrets WHERE key = 'notify.smtp.password'`).Scan(&ct))
	assert.NotContains(t, string(ct), canary)
	// F-63 and Review Focus 3: a refused password is reported without the password or the server's text.
	err = h.s.TestMail(ctx, h.who, "ops@example.com", "en")
	assert.ErrorIs(t, err, notify.ErrSMTPAuth)
	assert.NotContains(t, err.Error(), canary)
	assert.NotContains(t, err.Error(), "535")
}

func TestTestMailSendsThroughTheSettingsAndTheTrust(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	srv := fakesmtp.Start(t, fakesmtp.Options{Username: "mailer", Password: canary})
	_, err := h.s.SaveSMTP(ctx, h.who, 0, input(srv, pw(canary)))
	require.NoError(t, err)

	// F-62: the first test sees an untrusted certificate and remembers it for an hour.
	err = h.s.TestMail(ctx, h.who, "ops@example.com", "tr")
	var ce *notify.CertError
	require.True(t, errors.As(err, &ce))
	assert.Equal(t, srv.Fingerprint(), ce.Cert.Fingerprint)
	_, err = h.s.Trust(ctx, h.who, 1, strings.Repeat("ab", 32))
	assert.ErrorIs(t, err, notify.ErrCertNotSeen, "only the certificate Alice saw can be trusted")
	got, err := h.s.Trust(ctx, h.who, 1, srv.Fingerprint())
	require.NoError(t, err)
	require.NotNil(t, got.Trusted)
	assert.Equal(t, "ada", got.Trusted.TrustedBy)

	require.NoError(t, h.s.TestMail(ctx, h.who, "ops@example.com", "tr"))
	msgs := srv.Messages()
	require.Len(t, msgs, 1)
	assert.Equal(t, "Alice test e-postası", msgs[0].Subject, "rendered in the requested language")
	assert.True(t, msgs[0].Authed)

	// Changing the host or port drops the pin (it belongs to that server).
	in := input(srv, nil)
	in.Port++
	got, err = h.s.SaveSMTP(ctx, h.who, got.Version, in)
	require.NoError(t, err)
	assert.Nil(t, got.Trusted)

	// A certificate seen more than an hour ago cannot be trusted any more.
	in.Port--
	got, err = h.s.SaveSMTP(ctx, h.who, got.Version, in)
	require.NoError(t, err)
	require.Error(t, h.s.TestMail(ctx, h.who, "ops@example.com", "en"))
	h.clk.Advance(notify.SeenCertValidFor + time.Second)
	_, err = h.s.Trust(ctx, h.who, got.Version, srv.Fingerprint())
	assert.ErrorIs(t, err, notify.ErrCertNotSeen)
	assert.Equal(t, 3, countAudit(t, h.d, "settings.smtp_tested"), "one row per test mail")
}

// SEC-037: an administrator's CA bundle verifies a private certificate without a pin.
func TestCABundleTrustsAPrivateCA(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	srv := fakesmtp.Start(t, fakesmtp.Options{})
	in := input(srv, nil)
	in.Username, in.CAPEM = "", string(srv.CertPEM())
	_, err := h.s.SaveSMTP(ctx, h.who, 0, in)
	require.NoError(t, err)
	require.NoError(t, h.s.TestMail(ctx, h.who, "ops@example.com", "en"))
	in.CAPEM = "-----BEGIN " + "PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
	_, err = h.s.SaveSMTP(ctx, h.who, 1, in)
	require.Error(t, err, "only CERTIFICATE blocks")
	assert.Contains(t, err.Error(), "ca_pem")
}

func TestMailerSourceFallsBackWhenNotConfigured(t *testing.T) {
	fb := &fakeMailer{}
	h := newHarness(t, fb)
	m, release, err := h.s.Mailer(context.Background())
	require.NoError(t, err)
	defer release()
	assert.Same(t, fb, m, "the e2e mailbox (or nil in release) while no mail settings exist")
	h2 := newHarness(t, nil)
	m, release2, err := h2.s.Mailer(context.Background())
	require.NoError(t, err)
	defer release2()
	assert.Nil(t, m, "release without settings: skipped_no_smtp (L-18)")
}

func TestImportEnvOnce(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	files := map[string][]byte{"/run/secrets/smtp": []byte(canary + "\n")}
	read := func(p string) ([]byte, error) { return files[p], nil }
	cfg := config.SMTP{Host: "smtp.example.com", Port: 587, From: "alice@example.com", Username: "mailer",
		PasswordFile: "/run/secrets/smtp", TLSMode: "starttls"}
	done, err := h.s.ImportEnv(ctx, cfg, read)
	require.NoError(t, err)
	assert.True(t, done)
	got, ok, err := h.s.SMTP(ctx)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "smtp.example.com", got.Host)
	assert.True(t, got.HasPassword)
	assert.Equal(t, 1, countAudit(t, h.d, "settings.smtp_imported"))
	cfg.Host = "other.example.com"
	done, err = h.s.ImportEnv(ctx, cfg, read)
	require.NoError(t, err)
	assert.False(t, done, "settings exist: the environment is ignored")
	done, err = h.s.ImportEnv(ctx, config.SMTP{}, read)
	require.NoError(t, err)
	assert.False(t, done)
}

func countAudit(t *testing.T, d *pgtest.DB, action string) int {
	t.Helper()
	var n int
	require.NoError(t, d.Owner.QueryRow(context.Background(), `SELECT count(*) FROM audit_log WHERE action = $1`, action).Scan(&n))
	return n
}
```

(`fakeMailer` is the existing fake of `outbox_integration_test.go`. The three `settings.smtp_tested` rows are the untrusted first test, the successful one, and the untrusted test after the port went back — changing the port dropped the pin, and changing it back does not restore it.)

- [ ] **Step 2: Run the tests to verify they fail** (Docker: testcontainers)

Run: `go test ./internal/notify/ && go test -tags integration ./internal/secrets/ ./internal/platform/settings/ ./internal/notify/`
Expected: FAIL — undefined `notify.CertError`, `SMTPConfig.Pin`, `Keyring.PutSetting`, `settings.GetGeneral`, `notify.NewSettings`.

- [ ] **Step 3: Write the implementation**

`internal/secrets/settings.go`:

```go
package secrets

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"alice/internal/platform/db"
)

// The secrets of settings (the SMTP password, OIDC client secrets) live in setting_secrets, one envelope per key,
// bound to the key by the AAD setting_secrets/<key>/ciphertext (spec §7.6; R42 rows 9 and 19).
func settingLocation(key string) Location {
	return Location{Table: "setting_secrets", RowID: key, Column: "ciphertext"}
}

// PutSetting seals p under key, replacing any earlier value. The caller zeroes p.
func (k *Keyring) PutSetting(ctx context.Context, q db.Querier, key string, p Plaintext, now time.Time) error {
	env, err := k.Seal(settingLocation(key), p.Bytes())
	if err != nil {
		return err
	}
	_, err = q.Exec(ctx, `INSERT INTO setting_secrets (key, ciphertext, nonce, wrapped_dek, key_version, updated_at)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (key) DO UPDATE SET ciphertext = EXCLUDED.ciphertext, nonce = EXCLUDED.nonce, wrapped_dek = EXCLUDED.wrapped_dek,
key_version = EXCLUDED.key_version, updated_at = EXCLUDED.updated_at`,
		key, env.Ciphertext, env.Nonce, env.WrappedDEK, env.KeyVersion, now.UTC())
	if err != nil {
		return fmt.Errorf("secrets: store setting secret: %w", err)
	}
	return nil
}

// GetSetting opens the secret of key; ok is false when there is none. The caller zeroes the plaintext.
func (k *Keyring) GetSetting(ctx context.Context, q db.Querier, key string) (Plaintext, bool, error) {
	var env Envelope
	err := q.QueryRow(ctx, `SELECT ciphertext, nonce, wrapped_dek, key_version FROM setting_secrets WHERE key = $1`, key).
		Scan(&env.Ciphertext, &env.Nonce, &env.WrappedDEK, &env.KeyVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return Plaintext{}, false, nil
	}
	if err != nil {
		return Plaintext{}, false, fmt.Errorf("secrets: read setting secret: %w", err)
	}
	p, err := k.Open(settingLocation(key), env)
	if err != nil {
		return Plaintext{}, false, err
	}
	return p, true, nil
}

// DeleteSetting removes the secret of key; a missing key is not an error.
func DeleteSetting(ctx context.Context, q db.Querier, key string) error {
	if _, err := q.Exec(ctx, `DELETE FROM setting_secrets WHERE key = $1`, key); err != nil {
		return fmt.Errorf("secrets: delete setting secret: %w", err)
	}
	return nil
}
```

(`Plaintext{}` is the zero value of the existing type, returned only with `ok` false; callers never use it.)

`internal/platform/settings/general.go`:

```go
package settings

import (
	"context"

	"alice/internal/platform/db"
)

// GeneralKey holds Alice's own address and the retired-key retention (R42 row 30).
const (
	GeneralKey                     = "general"
	DefaultRetiredKeyRetentionDays = 30
)

// General is the general settings record.
type General struct {
	PublicURL               string `json:"public_url"`
	RetiredKeyRetentionDays int    `json:"retired_key_retention_days"`
	Version                 int    `json:"version"`
}

// GetGeneral reads the general settings, with the defaults when they were never saved.
func GetGeneral(ctx context.Context, q db.Querier) (General, error) {
	g := General{RetiredKeyRetentionDays: DefaultRetiredKeyRetentionDays}
	if _, err := Get(ctx, q, GeneralKey, &g); err != nil {
		return General{}, err
	}
	if g.RetiredKeyRetentionDays < 1 {
		g.RetiredKeyRetentionDays = DefaultRetiredKeyRetentionDays
	}
	return g, nil
}
```

`internal/notify/smtp.go` changes:

```go
// More classified failures (Phase 7).
var (
	ErrSMTPUntrusted  = errors.New("notify: the mail server's certificate is not trusted")
	ErrAddressRefused = errors.New("notify: the mail server's address is not one Alice connects to")
)

// ErrorCode adds, before the smtp.tls case: errors.Is(err, ErrSMTPUntrusted) → "smtp.untrusted";
// errors.Is(err, ErrAddressRefused) → "smtp.address_refused".

type SMTPConfig struct {
	Host     string
	Port     int
	From     string
	Username string // "" = no authentication
	Password secrets.Plaintext
	TLSMode  string         // "starttls" (default, port 587) or "tls" (implicit TLS, port 465)
	RootCAs  *x509.CertPool // nil = the system's trusted roots
	Pin      string         // lower-case hex SHA-256 of the one accepted leaf; "" = verify the chain (Phase 7)
	// Dial connects; nil = netaddr.DialContext with a net.Dialer (A-14, R42 row 11; Phase 7).
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}
```

`Send`: dial with `m.dial(ctx, "tcp", addr)` (`errors.Is(err, netaddr.ErrNotAllowed)` → `ErrAddressRefused`; any other dial error → `ErrSMTPConnect` as today); the TLS config is `m.tlsConfig()`:

```go
func (m *SMTPMailer) tlsConfig() *tls.Config {
	if m.cfg.Pin != "" {
		return pinnedTLS(m.cfg.Host, m.cfg.Pin)
	}
	return &tls.Config{ServerName: m.cfg.Host, MinVersion: tls.VersionTLS12, RootCAs: m.cfg.RootCAs}
}
```

and every TLS failure (the implicit handshake, `StartTLS`, and the `ehlo` that `StartTLS` sends) goes through `tlsFailure(err)`:

```go
// tlsFailure keeps a certificate problem's leaf (F-62: the Administrator sees what to trust) and nothing else of the
// server's answer.
func tlsFailure(err error) error {
	var ce *CertError
	if errors.As(err, &ce) {
		return ce
	}
	var ve *tls.CertificateVerificationError
	if errors.As(err, &ve) && len(ve.UnverifiedCertificates) > 0 {
		return &CertError{Cert: infoOf(ve.UnverifiedCertificates[0])}
	}
	return ErrSMTPTLS
}
```

`internal/notify/pin.go`:

```go
package notify

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"time"
)

// CertInfo describes a server certificate for the Administrator.
type CertInfo struct {
	Fingerprint string
	Subject     string
	NotAfter    time.Time
}

// CertError is a certificate Alice did not accept; it carries the leaf the server presented (F-62).
type CertError struct{ Cert CertInfo }

func (e *CertError) Error() string   { return "notify: the mail server's certificate is not trusted" }
func (e *CertError) Unwrap() []error { return []error{ErrSMTPUntrusted, ErrSMTPTLS} }

func fingerprintOf(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

func infoOf(c *x509.Certificate) CertInfo {
	return CertInfo{Fingerprint: fingerprintOf(c), Subject: oneLine(c.Subject.String()), NotAfter: c.NotAfter.UTC()}
}

// pinnedTLS accepts exactly the leaf whose SHA-256 is pin: the Administrator's "trust this certificate" (F-62, R42
// row 10). The chain and the name are not checked — the pin is the trust decision, made with step-up and audited.
// Nothing is sent before VerifyConnection passed.
func pinnedTLS(host, pin string) *tls.Config {
	return &tls.Config{
		ServerName:         host,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, //nolint:gosec // G402: VerifyConnection accepts only the leaf whose SHA-256 is the pin an Administrator set (F-62)
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return ErrSMTPTLS
			}
			leaf := cs.PeerCertificates[0]
			if subtle.ConstantTimeCompare([]byte(fingerprintOf(leaf)), []byte(pin)) != 1 {
				return &CertError{Cert: infoOf(leaf)}
			}
			return nil
		},
	}
}
```

`internal/notify/settings.go` (the store; sketch with the exact behaviour):

- Keys: `smtpKey = "notify.smtp"`, `seenKey = "notify.smtp_seen_cert"`, `passwordKey = "notify.smtp.password"`.
- Stored record `smtpRecord{Host, Port, TLSMode, From, Username, CAPEM string/int; Trusted *trustedRecord; Version int; UpdatedAt time.Time}` (JSON snake_case); `trustedRecord{Fingerprint, Subject string; NotAfter time.Time; TrustedBy string; TrustedAt time.Time}`.
- `SMTP(ctx)`: `settings.Get(smtpKey)` plus `SELECT EXISTS (SELECT 1 FROM setting_secrets WHERE key = 'notify.smtp.password')` → `SMTPSettings`.
- `SaveSMTP(ctx, a, version, in)`: `validateSMTP(in)` returns `validate.Errors` (rules of C13: `host`, `port`, `tls_mode`, `from`, `username`, `password` length, `ca_pem`; `password` `validate.Required` when `username` is set and no password exists or is given); one `db.InTx`: load the record (version 0 when absent) — `version` must equal it, else `ErrVersion`; build the new record (Trusted kept unless host or port changed); `Password` nil keeps, empty `DeleteSetting`, else `PutSetting` (the caller's plaintext is zeroed by the caller — the handler — and by `SaveSMTP` on every path through a `defer in.Password.Zero()` when non-nil); `Version+1`, `UpdatedAt` = clock; `settings.Set`; audit `settings.smtp_changed` (C16 details; `auth_changed` "true" when the password was set or removed; `ca_count` the number of certificates).
- `DeleteSMTP(ctx, a, version)`: version check; delete the record, the seen certificate and the password; audit `settings.smtp_removed`.
- `config(ctx, q, rec) (SMTPConfig, func(), error)`: opens the password (when a user name is set) into `SMTPConfig.Password`; `RootCAs` = `x509.SystemCertPool()` (a new pool when that fails) plus `CAPEM`; `Pin` = `rec.Trusted.Fingerprint`; `Dial` from the config. The returned func zeroes the password.

`internal/notify/testmail.go`:

- `TestMail(ctx, a, to, locale)`: validate `to` (`net/mail`, ≤ 254 bytes; else `validate.Errors{to: validate.Email}`); `ErrNotConfigured` without settings; build the mailer from `config`; render `TemplateTestMail` with `Sender{Catalog: s.catalog}.Render(to, TemplateTestMail, locale, nil)`; `Send` with `context.WithTimeout(ctx, TestMailTimeout)`; on `*CertError` store `seenRecord{Fingerprint, Subject, NotAfter, SeenAt}` under `seenKey`; audit `settings.smtp_tested` (`to`, `result` `sent`|`failed`, `reason` = `ErrorCode(err)` on failure, `fingerprint` for an untrusted certificate); return the classified error (never the server's text).
- `Trust(ctx, a, version, fingerprint)`: `^[0-9a-f]{64}$` (else `validate.Errors{fingerprint: validate.Pattern}`); in one transaction: version check; the seen record must exist, equal `fingerprint` and be at most `SeenCertValidFor` old (else `ErrCertNotSeen`); `Trusted` = it, with `TrustedBy` = `a.Name`, `TrustedAt` = now; `Version+1`; audit `settings.smtp_trusted`.
- `Untrust(ctx, a, version)`: version check; `Trusted = nil`; `Version+1`; audit `settings.smtp_untrusted`.

`internal/notify/envimport.go`: `ImportEnv(ctx, c, readFile)`: `false, nil` when `!c.Configured()` or a record exists (then log at Warn "ALICE_SMTP_* is set but the mail settings in Settings are used; remove the variables" — `SettingsConfig` gains `Log *slog.Logger`, nil = discard); else read `PasswordFile` (trim one trailing newline) and `CAFile` with `readFile`, save through the internal save path with `audit.SystemActor("startup")` and the action `settings.smtp_imported` (details `host`, `port`, `tls_mode`), zero the bytes read, return `true`.

`internal/notify/source.go`:

```go
// MailerSource gives the sender the mailer of the current settings at every drain.
type MailerSource interface {
	Mailer(ctx context.Context) (Mailer, func(), error)
}

// Mailer builds the mailer of the stored settings; without settings it is the fallback (the e2e mailbox, or nil in a
// release build: the sender records skipped_no_smtp, L-18). The returned func zeroes the unsealed password.
func (s *Settings) Mailer(ctx context.Context) (Mailer, func(), error) {
	rec, ok, err := s.load(ctx, s.pool)
	if err != nil {
		return nil, func() {}, err
	}
	if !ok {
		return s.fallback, func() {}, nil
	}
	cfg, release, err := s.config(ctx, s.pool, rec)
	if err != nil {
		return nil, func() {}, err
	}
	m, err := NewSMTPMailer(cfg, s.clock)
	if err != nil {
		release()
		return nil, func() {}, err
	}
	return m, release, nil
}
```

`internal/notify/sender.go`: `Sender` gains `Source MailerSource`; `Drain` gets the mailer once (`Source.Mailer` when `Source` is set, else the `Mailer` field), defers its release, and passes it to `one(ctx, mailer)`; a `Source` error is returned before any row is claimed (the scheduler logs it; nothing is marked).

`locales/common/{en,tr}.json`: add `email.notify.test.subject` and `email.notify.test.body` with the texts of C14 (nested under the existing `email` object).

- [ ] **Step 4: Run the tests to verify they pass** (Docker: testcontainers)

Run: `go test -count=1 -race ./internal/notify/ && go test -count=1 -race -tags integration ./internal/secrets/ ./internal/platform/settings/ ./internal/notify/ && make i18n-check`
Expected: `ok` for all (the existing outbox and SMTP tests unchanged: `Sender` without `Source` behaves as before).

Run: `make lint`
Expected: no findings; the one `InsecureSkipVerify` carries its `nolint` reason.

- [ ] **Step 5: Commit**

```bash
git add -- internal/secrets/settings.go internal/secrets/settings_integration_test.go internal/platform/settings/general.go \
  internal/platform/settings/general_integration_test.go internal/notify/settings.go internal/notify/pin.go internal/notify/testmail.go \
  internal/notify/envimport.go internal/notify/source.go internal/notify/pin_test.go internal/notify/settings_integration_test.go
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(notify): mail settings in Settings with the password in setting_secrets; test mail, CA bundle, trust this certificate" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- internal/secrets internal/platform/settings internal/notify \
  locales/common/en.json locales/common/tr.json
```

---

### Task 7: `internal/notify` part 2: 24-hour retries, the delivery state and "failing", recipients, `NotifyAdmins` follows them, the license note in rendering, general settings

**Files:**
- Create: `internal/notify/delivery.go` (`Delivery`, `Failing`, `recordDelivery`, `Settings.Delivery`), `internal/notify/recipients.go` (`Recipients`, `Address`, `Settings.Recipients`, `Settings.SaveRecipients`, `recipientsFor`), `internal/notify/general.go` (`Settings.General`, `Settings.SaveGeneral`)
- Modify: `internal/notify/sender.go` (retries until `GiveUpAfter`, `maxBackoff` 1 hour, `MaxAttempts` removed, delivery state, the license note in `Render`), `internal/notify/outbox.go` (`NotifyAdmins` reads `notify.recipients`)
- Modify: `locales/common/en.json`, `locales/common/tr.json` (`email.license_note`, `email.license_note_kv` of C14)
- Create: `internal/notify/delivery_integration_test.go`, `internal/notify/recipients_integration_test.go`, `internal/notify/note_test.go`
- Modify: `internal/notify/outbox_integration_test.go` (tests that relied on `MaxAttempts` now use `GiveUpAfter`)

**Interfaces:**
- Consumes: Task 6 (`Settings`, `fakesmtp`-backed settings in tests), `settings.{Get, Set, GetGeneral, General, GeneralKey}`.
- Produces: C7's delivery, recipients and general parts (`GiveUpAfter`, `FailingAfter`, `MaxExtraRecipients`, `Delivery`, `Delivery.Failing`, `Recipients`, `Address`, `Settings.{Delivery, Recipients, SaveRecipients, General, SaveGeneral}`); the `license_note` rendering rule; `NotifyAdmins` honouring recipients.

- [ ] **Step 1: Write the failing tests**

`internal/notify/note_test.go`:

```go
package notify_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/i18n"
	"alice/internal/license"
	"alice/internal/notify"
	"alice/locales"
)

// L-28: the license note is appended (before the footer) when the license is locked; "kv" adds the data-age line.
func TestRenderAddsTheLicenseNote(t *testing.T) {
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	s := &notify.Sender{Catalog: cat}
	base := map[string]string{"installation_id": "ALICE-X", "ends_at": "2027-10-01 00:00 UTC"}
	plain := s.Render("ada@example.com", license.TemplateLocked, "en", base)
	assert.NotContains(t, plain.Body, "Alice's license has expired. Renew it")
	with := map[string]string{"license_note": "true", "license_url": "https://alice.example.com/license"}
	for k, v := range base {
		with[k] = v
	}
	m := s.Render("ada@example.com", license.TemplateLocked, "en", with)
	assert.Contains(t, m.Body, "Note: Alice's license has expired. Renew it to resume automatic deployment. License page: https://alice.example.com/license")
	assert.NotContains(t, m.Body, "Key Vault data may be outdated")
	with["license_note"] = "kv"
	m = s.Render("ada@example.com", license.TemplateLocked, "tr", with)
	assert.Contains(t, m.Body, "Lisans sayfası: https://alice.example.com/license")
	assert.Contains(t, m.Body, "Key Vault verileri güncel olmayabilir")
	assert.Contains(t, m.Body, "Lütfen yanıtlamayın.", "the footer stays last")
}

// Review Focus 3: a hostile value never adds a header line or a paragraph, and is not expanded as a placeholder.
func TestRenderFlattensHostileParams(t *testing.T) {
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	m := (&notify.Sender{Catalog: cat}).Render("ada@example.com", license.TemplateExpiryWarning, "en", map[string]string{
		"ends_at": "x\r\nBcc: evil@example.com\n\n{{installation_id}}<script>", "installation_id": "ALICE-X", "days_left": "30"})
	assert.NotContains(t, m.Subject, "\n")
	assert.NotContains(t, m.Body, "\nBcc:")
	assert.Contains(t, m.Body, "x Bcc: evil@example.com {{installation_id}}<script>", "flattened, kept as text, not expanded")
}
```

`internal/notify/delivery_integration_test.go`:

```go
//go:build integration

package notify_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/i18n"
	"alice/internal/notify"
	"alice/internal/platform/clock"
	"alice/internal/testutil/fakesmtp"
	"alice/internal/testutil/pgtest"
	"alice/locales"
)

func mustCatalog(t *testing.T) *i18n.Catalog {
	t.Helper()
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	return cat
}

func senderFor(t *testing.T, h harness, src notify.MailerSource) *notify.Sender {
	t.Helper()
	return &notify.Sender{Pool: h.d.App, Source: src, Catalog: mustCatalog(t), Clock: h.clk}
}

// drainUntilQuiet advances the fake clock to the next due row and drains, up to n times.
func drainUntilQuiet(t *testing.T, d *pgtest.DB, s *notify.Sender, clk *clock.Fake, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		var next *time.Time
		require.NoError(t, d.Owner.QueryRow(context.Background(),
			`SELECT min(next_attempt_at) FROM notifications_outbox WHERE status = 'pending'`).Scan(&next))
		if next == nil {
			return
		}
		if next.After(clk.Now()) {
			clk.Set(*next)
		}
		_, err := s.Drain(context.Background())
		require.NoError(t, err)
	}
}

// F-60: a message is retried with backoff (30 s doubling, at most 1 hour) until 24 hours after it was queued.
func TestRetriesLastTwentyFourHours(t *testing.T) {
	h := newHarness(t, nil)
	addUser(t, h.d, "ada", "admin", "ada@example.com", "en", false)
	fail := &fakeMailer{fail: 1 << 30}
	s := &notify.Sender{Pool: h.d.App, Mailer: fail, Catalog: mustCatalog(t), Clock: h.clk}
	queue(t, h.d, h.clk, "license.locked")
	start := h.clk.Now()
	drainUntilQuiet(t, h.d, s, h.clk, 100)
	assert.Equal(t, map[string]int{"failed": 1}, statuses(t, h.d))
	var attempts int
	require.NoError(t, h.d.Owner.QueryRow(context.Background(), `SELECT attempts FROM notifications_outbox`).Scan(&attempts))
	assert.GreaterOrEqual(t, h.clk.Now().Sub(start), notify.GiveUpAfter)
	assert.Less(t, h.clk.Now().Sub(start), notify.GiveUpAfter+time.Hour)
	assert.Equal(t, attempts, fail.calls(), "every attempt was one send")
	assert.InDelta(t, 30, attempts, 4, "about 30 attempts over a day")
}

// F-60, owner step 4: SMTP down → retries, "failing" after three failed attempts; back up → each message once.
func TestF60OutageDeliversOnceAndRaisesFailing(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	addUser(t, h.d, "ada", "admin", "ada@example.com", "en", false)
	srv := fakesmtp.Start(t, fakesmtp.Options{})
	in := input(srv, nil)
	in.Username, in.CAPEM = "", string(srv.CertPEM())
	_, err := h.s.SaveSMTP(ctx, h.who, 0, in)
	require.NoError(t, err)
	s := senderFor(t, h, h.s)
	srv.Down()
	queue(t, h.d, h.clk, "license.locked")
	queue(t, h.d, h.clk, "license.grace")
	drainUntilQuiet(t, h.d, s, h.clk, 2)
	d, err := h.s.Delivery(ctx)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, d.ConsecutiveFailures, notify.FailingAfter)
	assert.True(t, d.Failing())
	assert.Equal(t, "smtp.connect", d.LastFailureCode)
	assert.Equal(t, 2, d.Pending)
	require.NoError(t, srv.Up())
	drainUntilQuiet(t, h.d, s, h.clk, 20)
	assert.Equal(t, map[string]int{"sent": 2}, statuses(t, h.d))
	assert.Len(t, srv.Messages(), 2, "exactly once each")
	d, err = h.s.Delivery(ctx)
	require.NoError(t, err)
	assert.False(t, d.Failing())
	require.NotNil(t, d.LastSuccessAt)
}

// F-61: one refused recipient does not stop the others.
func TestF61PerRecipient(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	addUser(t, h.d, "ada", "admin", "ada@example.com", "en", false)
	addUser(t, h.d, "bob", "admin", "bob@example.com", "tr", false)
	srv := fakesmtp.Start(t, fakesmtp.Options{})
	srv.RejectRecipient("bob@example.com")
	in := input(srv, nil)
	in.Username, in.CAPEM = "", string(srv.CertPEM())
	_, err := h.s.SaveSMTP(ctx, h.who, 0, in)
	require.NoError(t, err)
	queue(t, h.d, h.clk, "license.locked")
	_, err = senderFor(t, h, h.s).Drain(ctx)
	require.NoError(t, err)
	assert.Equal(t, map[string]int{"sent": 1, "pending": 1}, statuses(t, h.d))
	var code string
	require.NoError(t, h.d.Owner.QueryRow(ctx, `SELECT last_error_code FROM notifications_outbox WHERE to_address = 'bob@example.com'`).Scan(&code))
	assert.Equal(t, "smtp.rejected", code)
	require.Len(t, srv.Messages(), 1)
	assert.Equal(t, []string{"ada@example.com"}, srv.Messages()[0].To)
}
```

(`fakeMailer` of `outbox_integration_test.go` gains a `calls() int` method returning how many sends it saw, if it has no such counter yet.)

`internal/notify/recipients_integration_test.go`:

```go
//go:build integration

package notify_test

import (
	"context"
	"errors"
	"sort"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/notify"
	"alice/internal/platform/settings"
	"alice/internal/platform/validate"
)

func recipientsOfOneEmail(t *testing.T, h harness) []string {
	t.Helper()
	_, err := h.d.Owner.Exec(context.Background(), `DELETE FROM notifications_outbox`)
	require.NoError(t, err)
	queue(t, h.d, h.clk, "license.locked")
	rows, err := h.d.Owner.Query(context.Background(), `SELECT to_address || ':' || locale FROM notifications_outbox`)
	require.NoError(t, err)
	got, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(t, err)
	sort.Strings(got)
	return got
}

// R42 row 6: one recipients setting decides every email Alice sends to Administrators.
func TestRecipientsSettingDecidesEveryEmail(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	addUser(t, h.d, "ada", "admin", "ada@example.com", "tr", false)
	addUser(t, h.d, "op", "operator", "op@example.com", "en", false)
	assert.Equal(t, []string{"ada@example.com:tr"}, recipientsOfOneEmail(t, h), "default: every Administrator")

	r, err := h.s.SaveRecipients(ctx, h.who, 0, notify.Recipients{Administrators: true, Addresses: []notify.Address{
		{Email: "noc@example.com", Locale: "en"}, {Email: "ADA@example.com", Locale: "en"}}})
	require.NoError(t, err)
	assert.Equal(t, 1, r.Version)
	assert.Equal(t, []string{"ada@example.com:tr", "noc@example.com:en"}, recipientsOfOneEmail(t, h),
		"an address that is an Administrator's gets one email, in the Administrator's language")

	_, err = h.s.SaveRecipients(ctx, h.who, 1, notify.Recipients{Addresses: []notify.Address{{Email: "noc@example.com", Locale: "tr"}}})
	require.NoError(t, err)
	assert.Equal(t, []string{"noc@example.com:tr"}, recipientsOfOneEmail(t, h))

	for _, bad := range []notify.Recipients{
		{},
		{Addresses: []notify.Address{{Email: "not an address", Locale: "en"}}},
		{Addresses: []notify.Address{{Email: "a@example.com", Locale: "de"}}},
		{Addresses: []notify.Address{{Email: "a@example.com", Locale: "en"}, {Email: "A@example.com", Locale: "tr"}}},
		{Administrators: true, Addresses: make([]notify.Address, notify.MaxExtraRecipients+1)},
	} {
		_, err := h.s.SaveRecipients(ctx, h.who, 2, bad)
		var v validate.Errors
		assert.True(t, errors.As(err, &v), "%+v: %v", bad, err)
	}
	_, err = h.s.SaveRecipients(ctx, h.who, 1, notify.Recipients{Administrators: true})
	assert.ErrorIs(t, err, notify.ErrVersion)
	assert.Equal(t, 2, countAudit(t, h.d, "settings.recipients_changed"))
}

func TestSaveGeneralValidates(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	g, err := h.s.SaveGeneral(ctx, h.who, 0, settings.General{PublicURL: "https://alice.example.com/", RetiredKeyRetentionDays: 90})
	require.NoError(t, err)
	assert.Equal(t, "https://alice.example.com", g.PublicURL, "a trailing slash is dropped")
	assert.Equal(t, 1, g.Version)
	stored, err := settings.GetGeneral(ctx, h.d.App)
	require.NoError(t, err)
	assert.Equal(t, g, stored)
	for _, bad := range []settings.General{
		{PublicURL: "http://alice.example.com", RetiredKeyRetentionDays: 30},
		{PublicURL: "https://alice.example.com/app", RetiredKeyRetentionDays: 30},
		{PublicURL: "https://a@alice.example.com", RetiredKeyRetentionDays: 30},
		{PublicURL: "https://alice.example.com?x", RetiredKeyRetentionDays: 30},
		{PublicURL: "", RetiredKeyRetentionDays: 0},
		{PublicURL: "", RetiredKeyRetentionDays: 3651},
	} {
		_, err := h.s.SaveGeneral(ctx, h.who, 1, bad)
		var v validate.Errors
		assert.True(t, errors.As(err, &v), "%+v", bad)
	}
	_, err = h.s.SaveGeneral(ctx, h.who, 1, settings.General{PublicURL: "https://alice.example.com:9443", RetiredKeyRetentionDays: 30})
	require.NoError(t, err)
	assert.Equal(t, 2, countAudit(t, h.d, "settings.general_changed"))
}
```

In `outbox_integration_test.go`, every test that counted `notify.MaxAttempts` attempts now drives the clock past `notify.GiveUpAfter` (with `drainUntilQuiet`) and expects `failed`.

- [ ] **Step 2: Run the tests to verify they fail** (Docker: testcontainers)

Run: `go test -run 'TestRender' ./internal/notify/ && go test -count=1 -tags integration ./internal/notify/`
Expected: FAIL — the note text is missing, `GiveUpAfter`, `Delivery`, `SaveRecipients`, `SaveGeneral` are undefined.

- [ ] **Step 3: Write the implementation**

`internal/notify/sender.go`:

```go
// Retry policy (F-60, R42 row 7): 30 s, doubling up to 1 hour, until 24 hours after the message was queued; then the
// message is failed. Each attempt is one send to one recipient (F-61).
const (
	GiveUpAfter  = 24 * time.Hour
	FailingAfter = 3
	baseBackoff  = 30 * time.Second
	maxBackoff   = time.Hour
	sendTimeout  = 60 * time.Second
)
```

`one(ctx, mailer)` reads `created_at` with the row; after a failed send: `attempts++`; `status = "failed"` when `now.Sub(createdAt) >= GiveUpAfter`, else `pending` with `next_attempt_at = now + backoff(attempts)`; `recordDelivery(ctx, tx, false, code, now)` in the same transaction; after a success `recordDelivery(ctx, tx, true, "", now)`. A row skipped for missing SMTP changes no delivery state. `MaxAttempts` is deleted (every reference updated).

`Render`, between the body and the footer:

```go
	switch params["license_note"] {
	case "true":
		body += "\n\n" + s.Catalog.T(locale, "email.license_note", map[string]string{"license_url": clean["license_url"]})
	case "kv":
		body += "\n\n" + s.Catalog.T(locale, "email.license_note_kv", map[string]string{"license_url": clean["license_url"]})
	}
```

`internal/notify/delivery.go`:

```go
package notify

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"alice/internal/platform/settings"
)

const deliveryKey = "notify.delivery"

// Delivery is the state behind the "E-mails could not be sent" banner (F-60, R42 row 8).
type Delivery struct {
	ConsecutiveFailures int        `json:"consecutive_failures"`
	LastFailureAt       *time.Time `json:"last_failure_at"`
	LastFailureCode     string     `json:"last_failure_code"`
	LastSuccessAt       *time.Time `json:"last_success_at"`
	Pending             int        `json:"-"`
	Failed24h           int        `json:"-"`
}

// Failing reports whether the last FailingAfter or more send attempts all failed.
func (d Delivery) Failing() bool { return d.ConsecutiveFailures >= FailingAfter }

func recordDelivery(ctx context.Context, tx pgx.Tx, ok bool, code string, now time.Time) error {
	var d Delivery
	if _, err := settings.Get(ctx, tx, deliveryKey, &d); err != nil {
		return err
	}
	if ok {
		d.ConsecutiveFailures, d.LastSuccessAt = 0, &now
	} else {
		d.ConsecutiveFailures++
		d.LastFailureAt, d.LastFailureCode = &now, code
	}
	return settings.Set(ctx, tx, deliveryKey, d, now)
}

// Delivery reads the state and the outbox counts: pending rows now, and failed rows queued within the last 48 hours
// (they gave up at most 24 hours ago).
func (s *Settings) Delivery(ctx context.Context) (Delivery, error) {
	var d Delivery
	if _, err := settings.Get(ctx, s.pool, deliveryKey, &d); err != nil {
		return Delivery{}, err
	}
	err := s.pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE status = 'pending'),
count(*) FILTER (WHERE status = 'failed' AND created_at >= $1) FROM notifications_outbox`,
		s.clock.Now().UTC().Add(-2*GiveUpAfter)).Scan(&d.Pending, &d.Failed24h)
	return d, err
}
```

`internal/notify/recipients.go`:

- `const recipientsKey = "notify.recipients"; const MaxExtraRecipients = 20`.
- `Recipients{Administrators bool; Addresses []Address; Version int}` (JSON `administrators`, `addresses`, `version`), `Address{Email, Locale string}` (`email`, `locale`); the default (never saved) is `{Administrators: true}`.
- `Settings.Recipients(ctx)` reads it; `SaveRecipients(ctx, a, version, r)` validates (at most 20 addresses → `addresses` `validate.TooLong` with `max` 20; each `net/mail` address of at most 254 bytes → `addresses.<i>.email` `validate.Email`; locale `en`|`tr` → `addresses.<i>.locale` `validate.OneOf`; a repeated address, ignoring case → `addresses.<i>.email` `validate.Duplicate`; neither Administrators nor an address → `addresses` `validate.Required`), checks the version (`ErrVersion`), stores `Version+1`, audits `settings.recipients_changed` (`administrators` "true"/"false", `address_count`).
- `recipientsFor(ctx, tx) ([]recipient, error)`: the setting (default on absence); when `Administrators`, the current query of `NotifyAdmins` (enabled Administrators with an e-mail, by user name); then every address not already present (`strings.EqualFold` on the address), with its own locale.

`internal/notify/outbox.go`: `NotifyAdmins` uses `recipientsFor(ctx, tx)` instead of its own query; everything else (template check, params, one row per recipient) is unchanged. Its doc comment says "every enabled Administrator with an email address, and the extra addresses of the recipients setting (R42 row 6)".

`internal/notify/general.go`:

- `General(ctx)` = `settings.GetGeneral(ctx, s.pool)`.
- `SaveGeneral(ctx, a, version, g)`: `public_url` is `""` or `https://host[:port]` with an optional single trailing `/` (removed before storing), no user info, path, query or fragment (else `public_url` `validate.Pattern`); `retired_key_retention_days` 1–3650 (else `validate.OutOfRange` with `min`/`max`); version check against the stored `Version` (0 when never saved); store `Version+1` with `settings.Set(…, settings.GeneralKey, …)`; audit `settings.general_changed` (`public_url`, `days`).

`locales/common/{en,tr}.json`: `email.license_note` and `email.license_note_kv` of C14.

- [ ] **Step 4: Run the tests to verify they pass** (Docker: testcontainers)

Run: `go test -count=1 -race ./internal/notify/ && go test -count=1 -race -tags integration ./internal/notify/ && make i18n-check`
Expected: `ok`, `ok`, i18n check passes.

Run: `go test -count=1 ./... 2>&1 | grep -v '^ok' | grep -v 'no test files' || true`
Expected: no output (no other package referenced `notify.MaxAttempts`; if one did, it now uses `GiveUpAfter`).

Run: `make lint`
Expected: no findings.

- [ ] **Step 5: Commit**

```bash
git add -- internal/notify/delivery.go internal/notify/recipients.go internal/notify/general.go internal/notify/note_test.go \
  internal/notify/delivery_integration_test.go internal/notify/recipients_integration_test.go
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(notify): 24-hour retries, delivery state for the failing banner, recipients for every email, license note, general settings" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- internal/notify locales/common/en.json locales/common/tr.json
```

---

### Task 8: `internal/alerts`: monitored items, thresholds setting, the scan (four kinds, lock note, cap and summary), templates

**Files:**
- Create: `internal/alerts/service.go` (`Kind`, `Kinds`, constants, `Item`, `Counts`, `ThresholdSettings`, `ScanResult`, `LicenseState`, `Notifier`, `Config`, `Service`, `New`), `internal/alerts/monitored.go` (`Items`, `Counts`: the one SQL definition of "monitored", R42 row 4), `internal/alerts/thresholds.go` (`Thresholds`, `SaveThresholds`), `internal/alerts/scan.go` (`Scan`, `record`, `summarize`, `paramsOf`), `internal/alerts/templates.go` (`Templates`, template names)
- Create: `internal/testutil/seed/seed.go` (test data shared with Tasks 9, 10, 13, 16 and 17), `internal/alerts/alerts_integration_test.go`, `internal/alerts/templates_test.go`

**Interfaces:**
- Consumes: `expiry.{Due, DaysLeft, Horizon, Normalize, BucketOf, DefaultThresholds}` (Task 1), `settings.{Get, Set, GetGeneral}`, `license.Snapshot` (`Eval.Locked()`), `audit.{Log, Append, Event, SystemActor}`, `db.InTx`, `validate.Errors`, `notify.ErrVersion` (Task 6), the table `alerts` (Task 5), the existing tables `certificates`, `certificate_locations`, `targets`, `kv_certificates`, `kv_certificate_versions`, `kv_keys`, `credentials` (`public_info->>'secret_expires_on'`).
- Produces: C8 exactly; the `alert.*` template names (texts in Task 14).

- [ ] **Step 1: Write the failing tests**

`internal/testutil/seed/seed.go` (a new test-data package shared by the alerts, reports, API and performance suites and by the e2e seed endpoint of Task 13; it writes through the pool it is given — always the owner pool — and returns errors, so a non-test caller can use it):

```go
// Package seed inserts inventory rows for tests, the performance test and the e2e build's seed endpoint (Phase 7). It
// writes plain rows as the owner role; it is never linked into a release binary (only _test files, the perf test and
// the e2e build import it; release-symcheck and image-check keep it out).
package seed

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Hex is a stable 64-hex value derived from s.
func Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// Target inserts a live target of type typ ("linux", "nginx" or "azure_key_vault") with status, and its credential;
// a vault's credential carries secret_expires_on when secretExpires is set.
func Target(ctx context.Context, pool *pgxpool.Pool, name, typ, status string, secretExpires *time.Time) (uuid.UUID, error) {
	cred, id := uuid.New(), uuid.New()
	purpose, kind, info := "platform_ssh", "ssh_private_key", map[string]any{}
	config := map[string]any{"host": name + ".example.test", "port": 22, "username": "alice-svc"}
	var owner any
	if typ == "azure_key_vault" {
		purpose, kind, owner = "azure_vault", "azure_sp_secret", id
		info = map[string]any{"auth": "client_secret", "tenant_id": uuid.NewString(), "client_id": uuid.NewString()}
		if secretExpires != nil {
			info["secret_expires_on"] = secretExpires.UTC().Format(time.RFC3339)
		}
		config = map[string]any{"vault_url": "https://" + name + ".vault.azure.net", "host": name + ".vault.azure.net", "port": 443}
	}
	infoJSON, err := json.Marshal(info)
	if err != nil {
		return uuid.Nil, err
	}
	configJSON, err := json.Marshal(config)
	if err != nil {
		return uuid.Nil, err
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `INSERT INTO credentials (id, purpose, kind, public_info, ciphertext, nonce, wrapped_dek, key_version,
created_at, target_id) VALUES ($1, $2, $3, $4, '\x01', decode(repeat('00', 12), 'hex'), '\x02', 1, now(), $5)`,
		cred, purpose, kind, infoJSON, owner); err != nil {
		return uuid.Nil, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO targets (id, name, type, config, credential_id, status, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, now(), now())`, id, name, typ, configJSON, cred, status); err != nil {
		return uuid.Nil, err
	}
	return id, tx.Commit(ctx)
}

// Certificate inserts an uploaded certificate with CN cn expiring at notAfter and, on each target, one live location
// whose server block names websites. A certificate on no target is in inventory but not monitored.
func Certificate(ctx context.Context, pool *pgxpool.Pool, cn string, notAfter time.Time, targets []uuid.UUID, websites ...string) (uuid.UUID, error) {
	id := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO certificates (id, fingerprint_sha256, subject_cn, not_before, not_after, key_algorithm,
public_key_sha256, pem_chain, source, first_seen_at, last_seen_at, created_at)
VALUES ($1, $2, $3, $4 - interval '90 days', $4, 'ecdsa', $5, '', 'uploaded', now(), now(), now())`,
		id, Hex(id.String()), cn, notAfter, Hex("pk"+id.String())); err != nil {
		return uuid.Nil, err
	}
	if websites == nil {
		websites = []string{}
	}
	servers, err := json.Marshal([]map[string]any{{"names": websites, "listens": []any{}, "file": "/etc/nginx/conf.d/site.conf", "line": 1}})
	if err != nil {
		return uuid.Nil, err
	}
	for _, tg := range targets {
		if _, err := pool.Exec(ctx, `INSERT INTO certificate_locations (id, target_id, kind, cert_path, key_path, certificate_id, supported,
servers, first_seen_at, last_seen_at) VALUES ($1, $2, 'nginx_file', $3, $4, $5, true, $6, now(), now())`,
			uuid.New(), tg, "/etc/nginx/ssl/"+id.String()+".crt", "/etc/nginx/ssl/"+id.String()+".key", id, servers); err != nil {
			return uuid.Nil, err
		}
	}
	return id, nil
}

// MoveLocations points every location of from at to (a renewal was deployed).
func MoveLocations(ctx context.Context, pool *pgxpool.Pool, from, to uuid.UUID) error {
	_, err := pool.Exec(ctx, `UPDATE certificate_locations SET certificate_id = $2 WHERE certificate_id = $1`, from, to)
	return err
}

// KeyVault inserts a Key Vault certificate (its current version linked to linkCert, which may be nil) and a key.
func KeyVault(ctx context.Context, pool *pgxpool.Pool, vault uuid.UUID, certName string, certExpires time.Time, linkCert *uuid.UUID,
	keyName string, keyExpires time.Time) (kvCert, kvKey uuid.UUID, err error) {
	kvCert, kvKey = uuid.New(), uuid.New()
	version := Hex(kvCert.String())[:32]
	if _, err = pool.Exec(ctx, `INSERT INTO kv_certificates (id, target_id, name, current_version, current_thumbprint,
listed_thumbprint, enabled, key_type, content_type, expires, first_seen_at, last_seen_at)
VALUES ($1, $2, $3, $4, repeat('b', 40), repeat('b', 40), true, 'rsa', 'pkcs12', $5, now(), now())`,
		kvCert, vault, certName, version, certExpires); err != nil {
		return
	}
	if _, err = pool.Exec(ctx, `INSERT INTO kv_certificate_versions (id, kv_certificate_id, version, thumbprint, enabled, key_type,
content_type, detected_at, certificate_id) VALUES ($1, $2, $3, repeat('b', 40), true, 'rsa', 'pkcs12', now(), $4)`,
		uuid.New(), kvCert, version, linkCert); err != nil {
		return
	}
	_, err = pool.Exec(ctx, `INSERT INTO kv_keys (id, target_id, name, enabled, expires, first_seen_at, last_seen_at)
VALUES ($1, $2, $3, true, $4, now(), now())`, kvKey, vault, keyName, keyExpires)
	return
}
```

Task 9 adds `Deployment` and Task 10 nothing more; the alerts tests use small wrappers:

```go
//go:build integration

package alerts_test

// in alerts_integration_test.go
func seedTarget(t *testing.T, d *pgtest.DB, name, typ string, secretExpires *time.Time) uuid.UUID {
	t.Helper()
	id, err := seed.Target(context.Background(), d.Owner, name, typ, "ok", secretExpires)
	require.NoError(t, err)
	return id
}

func seedCert(t *testing.T, d *pgtest.DB, cn string, notAfter time.Time, targets []uuid.UUID, websites ...string) uuid.UUID {
	t.Helper()
	id, err := seed.Certificate(context.Background(), d.Owner, cn, notAfter, targets, websites...)
	require.NoError(t, err)
	return id
}

func moveLocations(t *testing.T, d *pgtest.DB, from, to uuid.UUID) {
	t.Helper()
	require.NoError(t, seed.MoveLocations(context.Background(), d.Owner, from, to))
}

func seedKV(t *testing.T, d *pgtest.DB, vault uuid.UUID, certName string, certExpires time.Time, linkCert *uuid.UUID,
	keyName string, keyExpires time.Time) {
	t.Helper()
	_, _, err := seed.KeyVault(context.Background(), d.Owner, vault, certName, certExpires, linkCert, keyName, keyExpires)
	require.NoError(t, err)
}
```

(These four wrappers go at the top of `alerts_integration_test.go`, which then also imports `alice/internal/testutil/seed`.)

`internal/alerts/alerts_integration_test.go`:

```go
//go:build integration

package alerts_test

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/alerts"
	"alice/internal/audit"
	"alice/internal/license"
	"alice/internal/notify"
	"alice/internal/platform/clock"
	"alice/internal/platform/settings"
	"alice/internal/testutil/pgtest"
)

func TestMain(m *testing.M) { os.Exit(pgtest.Main(m)) }

var t0 = time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)

const day = 24 * time.Hour

type queued struct {
	template string
	params   map[string]string
}

// recorder is the Notifier: it records what the scan queued (the outbox itself is notify's, tested there).
type recorder struct {
	mu   sync.Mutex
	got  []queued
	fail error
}

func (r *recorder) NotifyAdmins(_ context.Context, _ pgx.Tx, template string, params map[string]string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail != nil {
		return r.fail
	}
	r.got = append(r.got, queued{template, params})
	return nil
}

func (r *recorder) templates() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, q := range r.got {
		out = append(out, q.template)
	}
	return out
}

type lic struct{ locked bool }

func (l lic) Snapshot() license.Snapshot {
	s := license.Snapshot{}
	if l.locked {
		s.Eval.Phase = license.PhaseLocked
	} else {
		s.Eval.Phase = license.PhaseActive
	}
	return s
}

func newService(t *testing.T, d *pgtest.DB, clk clock.Clock, l lic, r *recorder) *alerts.Service {
	t.Helper()
	return alerts.New(alerts.Config{Pool: d.App, Audit: audit.New(clk), Clock: clk, License: l, Notifier: r})
}

func ledger(t *testing.T, d *pgtest.DB) map[string]int {
	t.Helper()
	rows, err := d.Owner.Query(context.Background(), `SELECT kind || ':' || threshold_days::text, count(*) FROM alerts GROUP BY 1`)
	require.NoError(t, err)
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var k string
		var n int
		require.NoError(t, rows.Scan(&k, &n))
		out[k] = n
	}
	return out
}

// Review Focus 2, §26.9 "no duplicates": hourly scans over 70 days queue each threshold once and the expiry once.
func TestScanIsExactlyOncePerThreshold(t *testing.T) {
	d := pgtest.New(t)
	clk := clock.NewFake(t0)
	r := &recorder{}
	s := newService(t, d, clk, lic{}, r)
	web := seedTarget(t, d, "web-01", "nginx", nil)
	seedCert(t, d, "www.example.com", t0.Add(65*day), []uuid.UUID{web}, "www.example.com", "example.com")
	for clk.Now().Before(t0.Add(70 * day)) {
		_, err := s.Scan(context.Background())
		require.NoError(t, err)
		clk.Advance(time.Hour)
	}
	assert.Equal(t, []string{"alert.certificate_expiring", "alert.certificate_expiring", "alert.certificate_expiring",
		"alert.certificate_expiring", "alert.certificate_expiring", "alert.certificate_expired"}, r.templates())
	assert.Equal(t, map[string]int{"certificate_expiry:60": 1, "certificate_expiry:30": 1, "certificate_expiry:14": 1,
		"certificate_expiry:7": 1, "certificate_expiry:1": 1, "certificate_expiry:0": 1}, ledger(t, d))
	first := r.got[0].params
	assert.Equal(t, "www.example.com", first["name"])
	assert.Equal(t, "60", first["days"])
	assert.Equal(t, "2026-12-11 09:00 UTC", first["expires_at"])
	assert.Equal(t, "example.com, www.example.com", first["websites"])
	assert.Equal(t, "web-01", first["servers"])
	assert.NotContains(t, first, "license_note")
}

// §26.9 "catch-up after downtime": Alice down from 31 to 13 days before expiry sends 14 only.
func TestDowntimeCatchUp(t *testing.T) {
	d := pgtest.New(t)
	clk := clock.NewFake(t0)
	r := &recorder{}
	s := newService(t, d, clk, lic{}, r)
	web := seedTarget(t, d, "web-01", "nginx", nil)
	seedCert(t, d, "www.example.com", t0.Add(40*day), []uuid.UUID{web}, "www.example.com")
	_, err := s.Scan(context.Background()) // 40 days left: the 60-day notice
	require.NoError(t, err)
	clk.Set(t0.Add(27 * day)) // 13 days left after the downtime
	_, err = s.Scan(context.Background())
	require.NoError(t, err)
	assert.Equal(t, map[string]int{"certificate_expiry:60": 1, "certificate_expiry:14": 1}, ledger(t, d))
}

// Review Focus 2: two processes scanning at once queue every notice once.
func TestConcurrentScansQueueOnce(t *testing.T) {
	d := pgtest.New(t)
	clk := clock.NewFake(t0)
	r := &recorder{}
	web := seedTarget(t, d, "web-01", "nginx", nil)
	for i := 0; i < 15; i++ {
		seedCert(t, d, "site-"+string(rune('a'+i))+".example.com", t0.Add(5*day), []uuid.UUID{web})
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := newService(t, d, clk, lic{}, r).Scan(context.Background())
			assert.NoError(t, err)
		}()
	}
	wg.Wait()
	assert.Len(t, r.templates(), 15)
	assert.Equal(t, map[string]int{"certificate_expiry:7": 15}, ledger(t, d))
}

// A renewal (a new expiry instant) starts a new series; a certificate no longer in use is not monitored.
func TestRenewalStartsANewSeriesAndReplacedIsNotMonitored(t *testing.T) {
	d := pgtest.New(t)
	clk := clock.NewFake(t0)
	r := &recorder{}
	s := newService(t, d, clk, lic{}, r)
	web := seedTarget(t, d, "web-01", "nginx", nil)
	old := seedCert(t, d, "www.example.com", t0.Add(5*day), []uuid.UUID{web}, "www.example.com")
	_, err := s.Scan(context.Background())
	require.NoError(t, err)
	renewed := seedCert(t, d, "www.example.com", t0.Add(50*day), nil)
	moveLocations(t, d, old, renewed) // the renewal was deployed on the server
	clk.Advance(10 * day)              // the old one has expired, but it is not in use any more
	_, err = s.Scan(context.Background())
	require.NoError(t, err)
	assert.Equal(t, map[string]int{"certificate_expiry:7": 1, "certificate_expiry:60": 1}, ledger(t, d),
		"no expired notice for the replaced certificate; the renewed one starts at 60")
}

// R42 row 4: a Key Vault certificate whose current version is the certificate in use on a server alerts once (as the
// certificate); keys and client secrets are scanned too.
func TestKVKindsAreScanned(t *testing.T) {
	d := pgtest.New(t)
	clk := clock.NewFake(t0)
	r := &recorder{}
	s := newService(t, d, clk, lic{}, r)
	web := seedTarget(t, d, "web-01", "nginx", nil)
	secretExp := t0.Add(20 * day)
	vault := seedTarget(t, d, "prod-vault", "azure_key_vault", &secretExp)
	deployed := seedCert(t, d, "shop.example.com", t0.Add(10*day), []uuid.UUID{web}, "shop.example.com")
	seedKV(t, d, vault, "shop-cert", t0.Add(10*day), &deployed, "signing-key", t0.Add(3*day))
	seedKV(t, d, vault, "other-cert", t0.Add(25*day), nil, "old-key", t0.Add(-1*day))
	_, err := s.Scan(context.Background())
	require.NoError(t, err)
	assert.Equal(t, map[string]int{"certificate_expiry:14": 1, "kv_certificate_expiry:30": 1, "kv_key_expiry:7": 1,
		"kv_key_expiry:0": 1, "kv_credential_expiry:30": 1}, ledger(t, d))
	byTpl := map[string]map[string]string{}
	for _, q := range r.got {
		byTpl[q.template+":"+q.params["name"]+q.params["vault"]] = q.params
	}
	assert.Contains(t, byTpl, "alert.kv_key_expired:old-keyprod-vault")
	assert.Contains(t, byTpl, "alert.kv_credential_expiring:prod-vault")
	assert.NotContains(t, byTpl, "alert.kv_certificate_expiring:shop-certprod-vault", "deployed: the certificate notice covers it")
}

// Review Focus 2: at most 20 emails per kind and scan; the rest are recorded and summarised in one email.
func TestEmailCapAndSummary(t *testing.T) {
	d := pgtest.New(t)
	clk := clock.NewFake(t0)
	r := &recorder{}
	s := newService(t, d, clk, lic{}, r)
	web := seedTarget(t, d, "web-01", "nginx", nil)
	for i := 0; i < 25; i++ {
		seedCert(t, d, "s"+uuid.NewString()[:8]+".example.com", t0.Add(time.Duration(i+1)*time.Hour), []uuid.UUID{web})
	}
	res, err := s.Scan(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 20, res.Queued[alerts.KindCertificate])
	assert.Equal(t, 5, res.Suppressed[alerts.KindCertificate])
	tpls := r.templates()
	require.Len(t, tpls, 21)
	assert.Equal(t, "alert.more", tpls[20])
	assert.Equal(t, "5", r.got[20].params["count"])
	var emailed, silent int
	require.NoError(t, d.Owner.QueryRow(context.Background(),
		`SELECT count(*) FILTER (WHERE emailed), count(*) FILTER (WHERE NOT emailed) FROM alerts`).Scan(&emailed, &silent))
	assert.Equal(t, [2]int{20, 5}, [2]int{emailed, silent})
	_, err = s.Scan(context.Background())
	require.NoError(t, err)
	assert.Len(t, r.templates(), 21, "suppressed notices are recorded: never sent later")
}

// L-28: in lock, expiry emails continue with the license note and the license page.
func TestL28LockNote(t *testing.T) {
	d := pgtest.New(t)
	clk := clock.NewFake(t0)
	r := &recorder{}
	s := newService(t, d, clk, lic{locked: true}, r)
	require.NoError(t, settings.Set(context.Background(), d.App, settings.GeneralKey,
		settings.General{PublicURL: "https://alice.example.com", RetiredKeyRetentionDays: 30, Version: 1}, t0))
	web := seedTarget(t, d, "web-01", "nginx", nil)
	vault := seedTarget(t, d, "prod-vault", "azure_key_vault", nil)
	seedCert(t, d, "www.example.com", t0.Add(5*day), []uuid.UUID{web}, "www.example.com")
	seedCert(t, d, "old.example.com", t0.Add(-day), []uuid.UUID{web}, "old.example.com")
	seedKV(t, d, vault, "kv-cert", t0.Add(5*day), nil, "kv-key", t0.Add(90*day))
	_, err := s.Scan(context.Background())
	require.NoError(t, err)
	require.Len(t, r.got, 3)
	for _, q := range r.got {
		assert.Equal(t, "https://alice.example.com/license", q.params["license_url"], q.template)
		if q.template == "alert.kv_certificate_expiring" {
			assert.Equal(t, "kv", q.params["license_note"])
		} else {
			assert.Equal(t, "true", q.params["license_note"], q.template)
		}
	}
	var locked bool
	require.NoError(t, d.Owner.QueryRow(context.Background(), `SELECT bool_and(license_locked) FROM alerts`).Scan(&locked))
	assert.True(t, locked)
}

// L-18: without SMTP the notice is recorded and its emails are skipped as skipped_no_smtp, with no error.
func TestL18NoSMTP(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	clk := clock.NewFake(t0)
	_, err := d.Owner.Exec(ctx, `INSERT INTO users (id, username, display_name, email, password_hash, role, locale, created_at, updated_at)
VALUES (gen_random_uuid(), 'ada', 'Ada', 'ada@example.com', '$argon2id$x', 'admin', 'tr', now(), now())`)
	require.NoError(t, err)
	s := alerts.New(alerts.Config{Pool: d.App, Audit: audit.New(clk), Clock: clk, License: lic{}, Notifier: notify.AdminNotifier{Clock: clk}})
	web := seedTarget(t, d, "web-01", "nginx", nil)
	seedCert(t, d, "www.example.com", t0.Add(6*day), []uuid.UUID{web}, "www.example.com")
	_, err = s.Scan(ctx)
	require.NoError(t, err)
	sender := &notify.Sender{Pool: d.App, Clock: clk} // no Mailer, no Source: SMTP is not configured
	n, err := sender.Drain(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	var status, tpl, locale string
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT status, template_key, locale FROM notifications_outbox`).Scan(&status, &tpl, &locale))
	assert.Equal(t, [3]string{"skipped_no_smtp", "alert.certificate_expiring", "tr"}, [3]string{status, tpl, locale})
	assert.Equal(t, map[string]int{"certificate_expiry:7": 1}, ledger(t, d), "the dashboard still has the notice")
}

func TestThresholdSettings(t *testing.T) {
	d := pgtest.New(t)
	clk := clock.NewFake(t0)
	s := newService(t, d, clk, lic{}, &recorder{})
	ctx := context.Background()
	got, err := s.Thresholds(ctx)
	require.NoError(t, err)
	assert.Equal(t, alerts.ThresholdSettings{Days: []int{60, 30, 14, 7, 1}}, got)
	got, err = s.SaveThresholds(ctx, audit.SystemActor("test"), 0, []int{3, 90, 21})
	require.NoError(t, err)
	assert.Equal(t, alerts.ThresholdSettings{Days: []int{90, 21, 3}, Version: 1}, got)
	_, err = s.SaveThresholds(ctx, audit.SystemActor("test"), 0, []int{5})
	assert.ErrorIs(t, err, notify.ErrVersion)
	for _, bad := range [][]int{nil, {0}, {366}, {5, 5}, {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}} {
		_, err := s.SaveThresholds(ctx, audit.SystemActor("test"), 1, bad)
		assert.Error(t, err, "%v", bad)
	}
	var n int
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action = 'settings.thresholds_changed'`).Scan(&n))
	assert.Equal(t, 1, n)
}

// The dashboard's counts come from the same definition (R42 rows 4 and 14).
func TestCountsAndItems(t *testing.T) {
	d := pgtest.New(t)
	clk := clock.NewFake(t0)
	s := newService(t, d, clk, lic{}, &recorder{})
	web := seedTarget(t, d, "web-01", "nginx", nil)
	for cn, left := range map[string]time.Duration{"a": -day, "b": 3 * day, "c": 7 * day, "d": 8 * day, "e": 30 * day,
		"f": 45 * day, "g": 200 * day} {
		seedCert(t, d, cn+".example.com", t0.Add(left), []uuid.UUID{web})
	}
	seedCert(t, d, "spare.example.com", t0.Add(2*day), nil) // on no server: not monitored
	c, err := s.Counts(context.Background())
	require.NoError(t, err)
	assert.Equal(t, alerts.Counts{Monitored: 7, Expired: 1, Within7: 2, Within30: 2, Within60: 1}, c)
	items, err := s.Items(context.Background(), []alerts.Kind{alerts.KindCertificate}, t0.Add(30*day), 3)
	require.NoError(t, err)
	require.Len(t, items, 3)
	assert.Equal(t, []string{"a.example.com", "b.example.com", "c.example.com"}, []string{items[0].Name, items[1].Name, items[2].Name})
}
```

`internal/alerts/templates_test.go`:

```go
package alerts

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTemplateNamesAreValid(t *testing.T) {
	pattern := regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`) // notify's templatePattern
	assert.Len(t, Templates(), 9)
	for _, tpl := range Templates() {
		assert.Regexp(t, pattern, tpl)
	}
	assert.Equal(t, []Kind{KindCertificate, KindKVCertificate, KindKVKey, KindKVCredential}, Kinds())
}
```

- [ ] **Step 2: Run the tests to verify they fail** (Docker: testcontainers)

Run: `go test ./internal/alerts/ && go test -tags integration ./internal/alerts/`
Expected: FAIL — no non-test Go files.

- [ ] **Step 3: Write the implementation**

`internal/alerts/service.go`: the types of C8; `New` keeps the config (a nil `Log` becomes a discard logger).

`internal/alerts/monitored.go` — the one definition of "monitored" (R42 row 4). `Items` runs one `UNION ALL` statement ordered by `expires_at, object_id` with `LIMIT` (no limit when `limit` is 0) and the kinds as a `text[]` parameter:

```sql
WITH live AS (
    SELECT l.certificate_id, l.servers, t.id AS target_id, t.name::text AS target_name
    FROM certificate_locations l JOIN targets t ON t.id = l.target_id AND t.deleted_at IS NULL
    WHERE l.missing_since IS NULL AND l.certificate_id IS NOT NULL
)
SELECT 'certificate_expiry', c.id, coalesce(nullif(c.subject_cn, ''), nullif(c.label, ''), left(c.fingerprint_sha256, 16)), c.not_after,
       c.fingerprint_sha256,
       array(SELECT DISTINCT n FROM live x, jsonb_array_elements(x.servers) s, jsonb_array_elements_text(s->'names') n
             WHERE x.certificate_id = c.id ORDER BY n LIMIT 11),
       array(SELECT DISTINCT x.target_name FROM live x WHERE x.certificate_id = c.id ORDER BY 1 LIMIT 11),
       array(SELECT DISTINCT x.target_id FROM live x WHERE x.certificate_id = c.id),
       '', NULL::uuid
FROM certificates c
WHERE 'certificate_expiry' = ANY ($1) AND c.not_after < $2 AND EXISTS (SELECT 1 FROM live x WHERE x.certificate_id = c.id)
UNION ALL
SELECT 'kv_certificate_expiry', kc.id, kc.name, kc.expires, '', '{}', '{}', '{}', t.name::text, t.id
FROM kv_certificates kc JOIN targets t ON t.id = kc.target_id AND t.deleted_at IS NULL
WHERE 'kv_certificate_expiry' = ANY ($1) AND kc.missing_since IS NULL AND kc.enabled AND kc.expires IS NOT NULL AND kc.expires < $2
  AND NOT EXISTS (SELECT 1 FROM kv_certificate_versions v JOIN live x ON x.certificate_id = v.certificate_id
                  WHERE v.kv_certificate_id = kc.id AND v.version = kc.current_version)
UNION ALL
SELECT 'kv_key_expiry', k.id, k.name, k.expires, '', '{}', '{}', '{}', t.name::text, t.id
FROM kv_keys k JOIN targets t ON t.id = k.target_id AND t.deleted_at IS NULL
WHERE 'kv_key_expiry' = ANY ($1) AND k.missing_since IS NULL AND k.enabled AND k.expires IS NOT NULL AND k.expires < $2
UNION ALL
SELECT 'kv_credential_expiry', t.id, t.name::text, (cr.public_info->>'secret_expires_on')::timestamptz, '', '{}', '{}', '{}', t.name::text, t.id
FROM targets t JOIN credentials cr ON cr.id = t.credential_id
WHERE 'kv_credential_expiry' = ANY ($1) AND t.type = 'azure_key_vault' AND t.deleted_at IS NULL
  AND cr.public_info ? 'secret_expires_on' AND (cr.public_info->>'secret_expires_on')::timestamptz < $2
ORDER BY 4, 2
```

(`Items` truncates `Websites` and `Servers` to 10 and keeps the eleventh only as the "more" marker for `paramsOf`.) `Counts` uses the same `live` definition in one statement:

```sql
WITH live AS (
    SELECT l.certificate_id FROM certificate_locations l JOIN targets t ON t.id = l.target_id AND t.deleted_at IS NULL
    WHERE l.missing_since IS NULL AND l.certificate_id IS NOT NULL
),
mon AS (SELECT c.not_after FROM certificates c WHERE EXISTS (SELECT 1 FROM live x WHERE x.certificate_id = c.id)),
kv AS (
    SELECT kc.expires FROM kv_certificates kc JOIN targets t ON t.id = kc.target_id AND t.deleted_at IS NULL
    WHERE kc.missing_since IS NULL AND kc.enabled AND kc.expires IS NOT NULL
      AND NOT EXISTS (SELECT 1 FROM kv_certificate_versions v JOIN live x ON x.certificate_id = v.certificate_id
                      WHERE v.kv_certificate_id = kc.id AND v.version = kc.current_version)
    UNION ALL
    SELECT k.expires FROM kv_keys k JOIN targets t ON t.id = k.target_id AND t.deleted_at IS NULL
    WHERE k.missing_since IS NULL AND k.enabled AND k.expires IS NOT NULL
    UNION ALL
    SELECT (cr.public_info->>'secret_expires_on')::timestamptz FROM targets t JOIN credentials cr ON cr.id = t.credential_id
    WHERE t.type = 'azure_key_vault' AND t.deleted_at IS NULL AND cr.public_info ? 'secret_expires_on'
)
SELECT (SELECT count(*) FROM mon),
       (SELECT count(*) FROM mon WHERE not_after <= $1),
       (SELECT count(*) FROM mon WHERE not_after > $1 AND not_after <= $1 + interval '7 days'),
       (SELECT count(*) FROM mon WHERE not_after > $1 + interval '7 days' AND not_after <= $1 + interval '30 days'),
       (SELECT count(*) FROM mon WHERE not_after > $1 + interval '30 days' AND not_after <= $1 + interval '60 days'),
       (SELECT count(*) FROM kv WHERE expires <= $1),
       (SELECT count(*) FROM kv WHERE expires > $1 AND expires <= $1 + interval '30 days')
```

with `$1` = the clock's now (the bucket edges are those of `expiry.BucketOf`; `TestCountsAndItems` pins them).

`internal/alerts/thresholds.go`: the setting `ThresholdsKey` holds `{"days": [...], "version": n}`; `Thresholds` returns the defaults with version 0 when absent. `SaveThresholds(ctx, a, version, days)` validates into `validate.Errors` on `thresholds_days` (`Required` when empty, `TooLong` with `max` 10, `OutOfRange` with `min` 1 and `max` 365, `Duplicate`), then `expiry.Normalize`; in one transaction checks the version (`notify.ErrVersion`), stores `Version+1`, audits `settings.thresholds_changed` (`thresholds` as `"90,21,3"`).

`internal/alerts/scan.go`:

```go
// Scan sends the due expiry notices (R42 rows 3-5, 12): for every monitored item that reaches a threshold within the
// largest threshold, the most urgent due level is recorded in the ledger; the transaction that inserted the row is the
// only one that queues the email, at most MaxEmailsPerScan per kind, and one summary per kind for the rest. It runs in
// every license state (class always): in lock the emails carry the license note (L-28).
func (s *Service) Scan(ctx context.Context) (ScanResult, error) {
	res := ScanResult{Queued: map[Kind]int{}, Suppressed: map[Kind]int{}}
	th, err := s.Thresholds(ctx)
	if err != nil {
		return res, err
	}
	now := s.clock.Now().UTC()
	items, err := s.Items(ctx, Kinds(), now.Add(expiry.Horizon(th.Days)), 0)
	if err != nil {
		return res, err
	}
	sent, err := s.sentLevels(ctx, items)
	if err != nil {
		return res, err
	}
	g, err := settings.GetGeneral(ctx, s.pool)
	if err != nil {
		return res, err
	}
	note := noteFor(s.license.Snapshot().Eval.Locked(), g.PublicURL)
	for _, it := range items {
		level, due := expiry.Due(it.ExpiresAt, now, th.Days, sent[keyOf(it)])
		if !due {
			continue
		}
		emailed := res.Queued[it.Kind] < MaxEmailsPerScan
		inserted, err := s.record(ctx, it, level, now, note, emailed)
		if err != nil {
			return res, err
		}
		switch {
		case !inserted: // another scan recorded this level first
		case emailed:
			res.Queued[it.Kind]++
		default:
			res.Suppressed[it.Kind]++
		}
	}
	for _, k := range Kinds() {
		if n := res.Suppressed[k]; n > 0 {
			if err := s.summarize(ctx, k, n, now, note); err != nil {
				return res, err
			}
		}
	}
	return res, nil
}
```

- `sentLevels`: one query `SELECT kind, object_id, expires_at, threshold_days FROM alerts WHERE object_id = ANY ($1)` → `map[key][]int` with `key{kind, object_id, expires_at.UTC()}`.
- `record(ctx, it, level, now, note, emailed)`: one `db.InTx`: `INSERT INTO alerts (…) VALUES (…) ON CONFLICT (kind, object_id, expires_at, threshold_days) DO NOTHING RETURNING id`; no row → `false, nil`; when `emailed`, `Notifier.NotifyAdmins(ctx, tx, templateFor(it.Kind, level), paramsOf(it, now, note))`; audit `alert.sent` (actor `audit.SystemActor("alerts")`, object type the kind, object id the item's id; details C16).
- `paramsOf`: C14's params: `name`, `vault`, `fingerprint`, `expires_at` (`2006-01-02 15:04 UTC`), `days` (`expiry.DaysLeft`, only for expiring templates), `websites`/`servers` (joined `", "`, `", …"` when an eleventh entry was read, `"-"` when empty); plus `license_note` (`"true"` for certificates, `"kv"` for the Key Vault kinds) and `license_url` when `note.locked`.
- `noteFor(locked, publicURL)`: `license_url` = `strings.TrimSuffix(publicURL, "/") + "/license"`, or `/license` when the address is empty.
- `templateFor(kind, level)`: `alert.<kind without _expiry>_expiring`, or `…_expired` for `expiry.Expired`; the kinds map to `certificate`, `kv_certificate`, `kv_key`, `kv_credential`.
- `summarize`: one transaction: `alert.more` with `count` (and the note params) through `NotifyAdmins`, audit `alert.summarized` (`kind`, `suppressed_count`).

`internal/alerts/templates.go`:

```go
// Templates lists every email template of the alerts module (texts in locales/common, Task 14).
func Templates() []string {
	return []string{"alert.certificate_expiring", "alert.certificate_expired", "alert.kv_certificate_expiring",
		"alert.kv_certificate_expired", "alert.kv_key_expiring", "alert.kv_key_expired", "alert.kv_credential_expiring",
		"alert.kv_credential_expired", "alert.more"}
}
```

- [ ] **Step 4: Run the tests to verify they pass** (Docker: testcontainers)

Run: `go test -count=1 -race ./internal/alerts/ && go test -count=1 -race -tags integration ./internal/alerts/ && go test ./internal/archtest/`
Expected: `ok` for all.

Run: `make lint`
Expected: no findings.

- [ ] **Step 5: Commit**

```bash
git add -- internal/alerts internal/testutil/seed
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(alerts): expiry alert scan for certificates in use and Key Vault certificates, keys and client secrets; exactly once per threshold" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- internal/alerts internal/testutil/seed
```

---

### Task 9: `internal/reports` part 1: dashboard summary, expiring list, attention conditions; `audit.LastCheckpoint`, `jobs.ReadAuditVerifyState`

**Files:**
- Create: `internal/reports/service.go` (`Config`, `Service`, `New`, `Viewer`, `Inventory`), `internal/reports/summary.go` (`Summary` and its parts, `Summary`, `Expiring`), `internal/reports/attention.go` (`Condition`, `Attention`)
- Create: `internal/audit/checkpoint.go` (`Checkpoint`, `LastCheckpoint`), `internal/audit/checkpoint_integration_test.go`
- Modify: `internal/jobs/auditverify.go` (the state type becomes the exported `AuditVerifyState`; `ReadAuditVerifyState`), `internal/jobs/auditverify_integration_test.go` (`TestReadAuditVerifyState`, below)
- Modify: `internal/testutil/seed/seed.go` (`Deployment`, `SetStatus`)
- Create: `internal/reports/summary_integration_test.go`

**Interfaces:**
- Consumes: C8 (`alerts.Service.{Counts, Items}`, `alerts.LicenseState`), C7 (`notify.Delivery`), `license.Snapshot` (`Eval.Phase`, `Eval.EndsAt`, `Eval.DaysLeft`, `Eval.Expired()`), `rbac.Role`, the tables `deployments`, `targets`, `rotation_policies`, `rotations`, `ssh_keys`, the settings `audit.checkpoint` and `jobs.audit_verify`.
- Produces: C9's Task 9 part; `audit.{Checkpoint, LastCheckpoint}`; `jobs.{AuditVerifyState, ReadAuditVerifyState}`; `seed.{Deployment, SetStatus}`.

- [ ] **Step 1: Write the failing tests**

`internal/audit/checkpoint_integration_test.go`:

```go
//go:build integration

package audit_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/platform/clock"
	"alice/internal/testutil/pgtest"
)

func TestLastCheckpoint(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	_, ok, err := audit.LastCheckpoint(ctx, d.App)
	require.NoError(t, err)
	assert.False(t, ok)
	clk := clock.NewFake(time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC))
	svc := audit.NewService(audit.New(clk), d.App)
	require.NoError(t, svc.Write(ctx, audit.Event{Actor: audit.SystemActor("test"), Action: "test.one", Result: audit.Success}))
	rep, err := svc.Verify(ctx, audit.SystemActor("test"))
	require.NoError(t, err)
	cp, ok, err := audit.LastCheckpoint(ctx, d.App)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, rep.HeadSeq, cp.Seq)
	assert.Regexp(t, `^[0-9a-f]{64}$`, cp.Hash)
	assert.Equal(t, clk.Now(), cp.At)
}
```

(`internal/audit` already has a `TestMain` with `pgtest.Main` in `audit_integration_test.go`; this file adds a test only.)

`internal/jobs/auditverify_integration_test.go` gains:

```go
func TestReadAuditVerifyState(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	st, err := jobs.ReadAuditVerifyState(ctx, d.App)
	require.NoError(t, err)
	assert.Equal(t, jobs.AuditVerifyState{}, st, "never verified")
	at := time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)
	want := jobs.AuditVerifyState{LastIntactAt: at, LastBrokenAt: at.Add(time.Hour), AlertedBadSeq: 7, AlertedProblem: "hash_mismatch"}
	require.NoError(t, settings.Set(ctx, d.App, "jobs.audit_verify", want, at))
	st, err = jobs.ReadAuditVerifyState(ctx, d.App)
	require.NoError(t, err)
	assert.Equal(t, want, st)
}
```

`internal/reports/summary_integration_test.go`:

```go
//go:build integration

package reports_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/alerts"
	"alice/internal/audit"
	"alice/internal/jobs"
	"alice/internal/license"
	"alice/internal/notify"
	"alice/internal/platform/clock"
	"alice/internal/platform/settings"
	"alice/internal/rbac"
	"alice/internal/reports"
	"alice/internal/testutil/pgtest"
	"alice/internal/testutil/seed"
)

func TestMain(m *testing.M) { os.Exit(pgtest.Main(m)) }

var t0 = time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)

const day = 24 * time.Hour

type lic struct{ eval license.Evaluation }

func (l lic) Snapshot() license.Snapshot { return license.Snapshot{Eval: l.eval} }

type delivery struct{ d notify.Delivery }

func (x delivery) Delivery(context.Context) (notify.Delivery, error) { return x.d, nil }

type world struct {
	svc            *reports.Service
	d              *pgtest.DB
	web1, web2, hk uuid.UUID
}

// newWorld seeds C17's data set (the e2e seed endpoint's) at t0.
func newWorld(t *testing.T, failing bool) world {
	t.Helper()
	d := pgtest.New(t)
	ctx := context.Background()
	clk := clock.NewFake(t0)
	must := func(id uuid.UUID, err error) uuid.UUID { require.NoError(t, err); return id }
	web1 := must(seed.Target(ctx, d.Owner, "seed-web-1", "linux", "ok", nil))
	web2 := must(seed.Target(ctx, d.Owner, "seed-web-2", "linux", "ok", nil))
	hk := must(seed.Target(ctx, d.Owner, "seed-web-3", "linux", "host_key_changed", nil))
	at := func(dd time.Duration) time.Time { return t0.Add(dd) }
	must(seed.Certificate(ctx, d.Owner, "www.seed.test", at(7*day-time.Hour), []uuid.UUID{web1}, "www.seed.test"))
	api := must(seed.Certificate(ctx, d.Owner, "api.seed.test", at(5*day), []uuid.UUID{web1}))
	must(seed.Certificate(ctx, d.Owner, "old.seed.test", at(-2*day), []uuid.UUID{web1}))
	must(seed.Certificate(ctx, d.Owner, "shop.seed.test", at(20*day), []uuid.UUID{web1}))
	must(seed.Certificate(ctx, d.Owner, "mail.seed.test", at(25*day), []uuid.UUID{web2}))
	must(seed.Certificate(ctx, d.Owner, "docs.seed.test", at(45*day), []uuid.UUID{web2}))
	must(seed.Certificate(ctx, d.Owner, "blog.seed.test", at(200*day), []uuid.UUID{web2}))
	must(seed.Certificate(ctx, d.Owner, "intra.seed.test", at(29*day), []uuid.UUID{hk}))
	must(seed.Certificate(ctx, d.Owner, "spare.seed.test", at(3*day), nil))
	must(seed.Deployment(ctx, d.Owner, api, web1, "failed", "ngx.reload_failed", at(-day)))
	must(seed.Deployment(ctx, d.Owner, api, web1, "failed", "ngx.reload_failed", at(-8*day))) // outside the window
	al := alerts.New(alerts.Config{Pool: d.App, Audit: audit.New(clk), Clock: clk, License: lic{}})
	del := notify.Delivery{}
	if failing {
		del = notify.Delivery{ConsecutiveFailures: 3, LastFailureCode: "smtp.connect"}
	}
	ends := t0.Add(40 * day)
	svc := reports.New(reports.Config{Pool: d.App, Clock: clk, Audit: audit.New(clk), Alerts: al, Delivery: delivery{del},
		License: lic{license.Evaluation{Phase: license.PhaseActive, EndsAt: ends, DaysLeft: 40}}})
	return world{svc: svc, d: d, web1: web1, web2: web2, hk: hk}
}

// §26.9 "dashboard API tests with seeded data (exact counts)"; exit "the dashboard numbers match the database".
func TestSummaryCountsMatchTheDatabase(t *testing.T) {
	w := newWorld(t, false)
	s, err := w.svc.Summary(context.Background(), reports.Viewer{Role: rbac.Admin})
	require.NoError(t, err)
	assert.Equal(t, alerts.Counts{Monitored: 8, Expired: 1, Within7: 2, Within30: 3, Within60: 1}, s.Certificates)
	assert.Equal(t, 3, s.Targets.Total)
	assert.Equal(t, 2, s.Targets.ByStatus["ok"])
	assert.Equal(t, 1, s.Targets.ByStatus["host_key_changed"])
	assert.Equal(t, 0, s.Targets.ByStatus["unreachable"], "every known status is present")
	assert.Equal(t, 1, s.Deployments.Failed7d)
	require.Len(t, s.Deployments.Recent, 1)
	assert.Equal(t, "api.seed.test", s.Deployments.Recent[0].CertificateName)
	assert.Equal(t, "seed-web-1", s.Deployments.Recent[0].TargetName)
	assert.Equal(t, "ngx.reload_failed", s.Deployments.Recent[0].ErrorCode)
	assert.Equal(t, string(license.PhaseActive), s.License.Phase)
	require.NotNil(t, s.License.DaysLeft)
	assert.Equal(t, 40, *s.License.DaysLeft)
	require.NotNil(t, s.Notifications)
	assert.False(t, s.Notifications.Failing())
	// The database agrees, counted independently.
	var monitored int
	require.NoError(t, w.d.Owner.QueryRow(context.Background(), `SELECT count(DISTINCT c.id) FROM certificates c
JOIN certificate_locations l ON l.certificate_id = c.id AND l.missing_since IS NULL`).Scan(&monitored))
	assert.Equal(t, monitored, s.Certificates.Monitored)
}

// Review Focus 5, R42 row 13: Operators see neither the audit head, nor the delivery state, nor license details.
func TestSummaryIsRoleFiltered(t *testing.T) {
	w := newWorld(t, true)
	ctx := context.Background()
	op, err := w.svc.Summary(ctx, reports.Viewer{Role: rbac.Operator})
	require.NoError(t, err)
	assert.Nil(t, op.Notifications)
	assert.Nil(t, op.Audit)
	assert.Empty(t, op.License.Phase)
	assert.Nil(t, op.License.EndsAt)
	aud, err := w.svc.Summary(ctx, reports.Viewer{Role: rbac.Auditor})
	require.NoError(t, err)
	assert.Nil(t, aud.Notifications)
	assert.Equal(t, string(license.PhaseActive), aud.License.Phase)
	adm, err := w.svc.Summary(ctx, reports.Viewer{Role: rbac.Admin})
	require.NoError(t, err)
	require.NotNil(t, adm.Notifications)
	assert.True(t, adm.Notifications.Failing())
}

func TestSummaryAuditHead(t *testing.T) {
	w := newWorld(t, false)
	ctx := context.Background()
	s, err := w.svc.Summary(ctx, reports.Viewer{Role: rbac.Auditor})
	require.NoError(t, err)
	assert.Nil(t, s.Audit, "no verification yet")
	clk := clock.NewFake(t0)
	asvc := audit.NewService(audit.New(clk), w.d.App)
	require.NoError(t, asvc.Write(ctx, audit.Event{Actor: audit.SystemActor("t"), Action: "test.one", Result: audit.Success}))
	rep, err := asvc.Verify(ctx, audit.SystemActor("scheduler"))
	require.NoError(t, err)
	require.NoError(t, settings.Set(ctx, w.d.App, "jobs.audit_verify", jobs.AuditVerifyState{LastIntactAt: t0}, t0))
	s, err = w.svc.Summary(ctx, reports.Viewer{Role: rbac.Auditor})
	require.NoError(t, err)
	require.NotNil(t, s.Audit)
	assert.Equal(t, rep.HeadSeq, s.Audit.HeadSeq)
	assert.True(t, s.Audit.Intact)
	require.NoError(t, settings.Set(ctx, w.d.App, "jobs.audit_verify",
		jobs.AuditVerifyState{LastIntactAt: t0, LastBrokenAt: t0.Add(time.Hour), AlertedBadSeq: 1, AlertedProblem: "hash_mismatch"}, t0))
	s, err = w.svc.Summary(ctx, reports.Viewer{Role: rbac.Admin})
	require.NoError(t, err)
	assert.False(t, s.Audit.Intact)
}

func TestExpiringListIsSoonestFirst(t *testing.T) {
	w := newWorld(t, false)
	items, err := w.svc.Expiring(context.Background(), 30, 50)
	require.NoError(t, err)
	var names []string
	for _, it := range items {
		names = append(names, it.Name)
	}
	assert.Equal(t, []string{"old.seed.test", "api.seed.test", "www.seed.test", "shop.seed.test", "mail.seed.test", "intra.seed.test"}, names)
	assert.Equal(t, []string{"www.seed.test"}, items[2].Websites)
	_, err = w.svc.Expiring(context.Background(), 0, 50)
	assert.Error(t, err)
	_, err = w.svc.Expiring(context.Background(), 30, 201)
	assert.Error(t, err)
}

func TestAttentionConditions(t *testing.T) {
	w := newWorld(t, true)
	ctx := context.Background()
	kinds := func(v reports.Viewer) []string {
		cs, err := w.svc.Attention(ctx, v)
		require.NoError(t, err)
		var out []string
		for _, c := range cs {
			out = append(out, c.Kind)
		}
		return out
	}
	assert.ElementsMatch(t, []string{"host_key_changed", "deployment_failed", "notifications_failing"}, kinds(reports.Viewer{Role: rbac.Admin}))
	assert.ElementsMatch(t, []string{"host_key_changed", "deployment_failed"}, kinds(reports.Viewer{Role: rbac.Operator}))
	s, err := w.svc.Summary(ctx, reports.Viewer{Role: rbac.Admin})
	require.NoError(t, err)
	assert.Equal(t, 3, s.Attention)
}
```

- [ ] **Step 2: Run the tests to verify they fail** (Docker: testcontainers)

Run: `go test -tags integration ./internal/reports/ ./internal/audit/ ./internal/jobs/`
Expected: FAIL — undefined `reports`, `audit.LastCheckpoint`, `jobs.AuditVerifyState`, `seed.Deployment`.

- [ ] **Step 3: Write the implementation**

`internal/audit/checkpoint.go`:

```go
package audit

import (
	"context"
	"time"

	"alice/internal/platform/db"
	"alice/internal/platform/settings"
)

// Checkpoint is the last verified chain head (R16: the dashboard shows it for offline recording).
type Checkpoint struct {
	Seq  int64
	Hash string
	At   time.Time
}

// LastCheckpoint reads the stored checkpoint; ok is false before the first verification.
func LastCheckpoint(ctx context.Context, q db.Querier) (Checkpoint, bool, error) {
	var cp checkpoint
	ok, err := settings.Get(ctx, q, checkpointKey, &cp)
	if err != nil || !ok {
		return Checkpoint{}, ok, err
	}
	return Checkpoint{Seq: cp.Seq, Hash: cp.Hash, At: cp.At.UTC()}, true, nil
}
```

(The field names of the unexported `checkpoint` are read from `verify.go`; adapt the three assignments to them.)

`internal/jobs/auditverify.go`: rename `auditVerifyState` to the exported `AuditVerifyState` (fields unchanged), and add

```go
// ReadAuditVerifyState reads what the daily verification remembers (the dashboard's integrity status, R42 row 27).
func ReadAuditVerifyState(ctx context.Context, q db.Querier) (AuditVerifyState, error) {
	var st AuditVerifyState
	_, err := settings.Get(ctx, q, auditVerifyStateKey, &st)
	return st, err
}
```

`internal/testutil/seed/seed.go` gains:

```go
// Deployment inserts a finished deployment of cert on target (status failed, rolled_back or rollback_failed, finished at
// at, as migrations' TestFinishedDeploymentIsFrozen inserts one) or an unfinished one (needs_attention, created at at).
// The certificate needs a location on the target.
func Deployment(ctx context.Context, pool *pgxpool.Pool, cert, target uuid.UUID, status, errorCode string, at time.Time) (uuid.UUID, error) {
	var loc uuid.UUID
	var fp string
	if err := pool.QueryRow(ctx, `SELECT l.id, c.fingerprint_sha256 FROM certificate_locations l JOIN certificates c ON c.id = l.certificate_id
WHERE l.certificate_id = $1 AND l.target_id = $2 LIMIT 1`, cert, target).Scan(&loc, &fp); err != nil {
		return uuid.Nil, err
	}
	id := uuid.Must(uuid.NewV7())
	state, finished := "done", &at
	if status == "needs_attention" {
		state, finished = "recovering", nil
	}
	_, err := pool.Exec(ctx, `INSERT INTO deployments (id, certificate_id, location_id, target_id, trigger, state, status, new_fingerprint,
cert_path, key_path, error_code, created_at, finished_at) VALUES ($1, $2, $3, $4, 'manual', $5, $6, $7, '/etc/nginx/ssl/seed.crt',
'/etc/nginx/ssl/seed.key', $8, $9, $10)`, id, cert, loc, target, state, status, fp, errorCode, at, finished)
	return id, err
}

// SetStatus sets a target's status (for example host_key_changed or auth_failed).
func SetStatus(ctx context.Context, pool *pgxpool.Pool, target uuid.UUID, status string) error {
	_, err := pool.Exec(ctx, `UPDATE targets SET status = $2, updated_at = now() WHERE id = $1`, target, status)
	return err
}
```

`internal/reports/summary.go`:

- `Summary(ctx, v)`: `now := s.clock.Now().UTC()`; `Certificates` = `s.alerts.Counts(ctx)`; deployments: `SELECT count(*) FROM deployments WHERE status IN ('failed', 'rolled_back', 'rollback_failed', 'needs_attention') AND coalesce(finished_at, created_at) >= $1` with `$1 = now - FailedWindow`, and the five newest of the same set joined to `certificates` (name: `coalesce(nullif(subject_cn, ''), nullif(label, ''), left(fingerprint_sha256, 16))`) and `targets` (`name::text`), ordered by `coalesce(finished_at, created_at) DESC, id DESC`; targets: `SELECT status, count(*) FROM targets WHERE deleted_at IS NULL GROUP BY status`, the map pre-filled with 0 for `pending_host_key`, `checking`, `ok`, `unreachable`, `host_key_changed`, `auth_failed`, `disabled`, `degraded`; license from `s.license.Snapshot().Eval`: `Expired` = `Eval.Expired()`, and for Administrators and Auditors `Phase` = `string(Eval.Phase)`, `EndsAt` = `&Eval.EndsAt`, `DaysLeft` = `&Eval.DaysLeft` (adapt to the field types of `license.Evaluation`; R36 item 12); rotation: `SELECT p.id, p.ssh_key_id, k.label, p.next_run_at FROM rotation_policies p JOIN ssh_keys k ON k.id = p.ssh_key_id WHERE p.enabled AND p.deleted_at IS NULL AND p.next_run_at <= $1 ORDER BY p.next_run_at, p.id LIMIT 5` with `$1 = now + RotationWindow`, `SELECT count(*) FILTER (WHERE status NOT IN ('completed', 'aborted', 'cancelled', 'needs_attention')), count(*) FILTER (WHERE status = 'needs_attention') FROM rotations`; `Notifications` = `s.delivery.Delivery(ctx)` for Administrators only; `Audit` for Administrators and Auditors: `audit.LastCheckpoint` (nil when none) and `Intact` = `!st.LastBrokenAt.After(st.LastIntactAt)` from `jobs.ReadAuditVerifyState`; `Attention` = `len(s.Attention(ctx, v))`.
- `Expiring(ctx, days, limit)`: `days` 1–365 and `limit` 1–200 (else `validate.Errors` on `days`/`limit` with `validate.OutOfRange`); `s.alerts.Items(ctx, alerts.Kinds(), now + days, limit)`.

`internal/reports/attention.go`: `Attention(ctx, v)` = targets with status `host_key_changed` or `auth_failed` (kind = the status, `ObjectID` the target, `Name` its name, `Since` its `updated_at`, `ErrorCode` its `last_error_code`); the failed deployments of `Summary`'s window (kind `deployment_failed`, `ObjectID` the deployment, `Name` the certificate's name, `ErrorCode` its code); for Administrators and Auditors `audit_broken` when the verify state is broken (`Since` = `LastBrokenAt`); for Administrators `notifications_failing` when `Delivery.Failing()` (`Since` = `LastFailureAt`, `ErrorCode` = `LastFailureCode`). Sorted by `Since` descending.

`internal/reports/service.go`: `Config` and `New` of C9 (`Inventory` and `Audit` are used by Task 10).

- [ ] **Step 4: Run the tests to verify they pass** (Docker: testcontainers)

Run: `go test -count=1 -race -tags integration ./internal/reports/ ./internal/audit/ ./internal/jobs/ && go test ./internal/archtest/`
Expected: `ok` for all (the jobs package's existing audit-verify tests pass with the renamed type).

Run: `make lint`
Expected: no findings.

- [ ] **Step 5: Commit**

```bash
git add -- internal/reports internal/audit/checkpoint.go internal/audit/checkpoint_integration_test.go
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(reports): dashboard summary with exact counts, expiring list and attention conditions; audit head and verify state readers" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- internal/reports internal/audit/checkpoint.go \
  internal/audit/checkpoint_integration_test.go internal/jobs/auditverify.go internal/jobs/auditverify_integration_test.go internal/testutil/seed/seed.go
```

---

### Task 10: `internal/reports` part 2: CSV exports, saved views; inventory filters; the Key Vault poll carry; the retention setting in `sshkeys`

**Files:**
- Create: `internal/reports/export.go` (`ExportCertificates`, `ExportSSHKeys`, the column lists), `internal/reports/views.go` (`View`, `ViewQueryKeys`, `Views`, `CreateView`, `DeleteView`)
- Create: `internal/reports/export_integration_test.go`, `internal/reports/views_integration_test.go`
- Modify: `internal/inventory/certificates.go` (`certificateSources` gains `azure_kv`; `expiryWindows` = `expired`, `7`, `14`, `30`, `60`, `90`), `internal/inventory/certificates_integration_test.go` (the new windows and the source)
- Modify: `internal/inventory/kv_store.go` (carry 4: the batch read of stored versions also selects `certificate_id IS NULL`; the per-certificate query goes), `internal/inventory/kv_reconcile_integration_test.go` (`TestPollReadsStoredVersionsInOneBatch`)
- Modify: `internal/sshkeys/destroy.go` (the retention from `settings.GetGeneral`; `RetiredKeyRetention` stays as the documented default), `internal/sshkeys/download_integration_test.go` (`TestDestroyFollowsTheRetentionSetting`)

**Interfaces:**
- Consumes: `inventory.{ListCertificates, CertificateFilter, CertificatePage, Certificate, ListSSHKeys, KeyFilter, KeyPage, SSHKey}`, `csvx.{NewWriter, Writer}` (Task 3), `expiry.DaysLeft` (Task 1), `audit.{Log, Append, Event, Actor}`, `settings.GetGeneral` (Task 6), `seed` (Tasks 8–9), the table `saved_views` (Task 5).
- Produces: C9's Task 10 part (`MaxExportRows`, `MaxViewsPerUser`, `PageCertificates`, `PageSSHKeys`, `ErrTooLarge`, `ErrViewLimit`, `ErrViewName`, `ErrNotFound`, `ExportCertificates`, `ExportSSHKeys`, `View`, `ViewQueryKeys`, `Views`, `CreateView`, `DeleteView`); the certificate filter values of R42 row 17.

- [ ] **Step 1: Write the failing tests**

`internal/reports/export_integration_test.go`:

```go
//go:build integration

package reports_test

import (
	"bytes"
	"context"
	"encoding/csv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/alerts"
	"alice/internal/audit"
	"alice/internal/inventory"
	"alice/internal/platform/clock"
	"alice/internal/reports"
	"alice/internal/testutil/pgtest"
	"alice/internal/testutil/seed"
)

func exportWorld(t *testing.T) (*reports.Service, *inventory.Service, *pgtest.DB, uuid.UUID) {
	t.Helper()
	w := newWorld(t, false)
	clk := clock.NewFake(t0)
	inv := inventory.New(inventory.Config{Pool: w.d.App, Clock: clk, Audit: audit.New(clk)})
	svc := reports.New(reports.Config{Pool: w.d.App, Clock: clk, Audit: audit.New(clk), Inventory: inv,
		Alerts: alerts.New(alerts.Config{Pool: w.d.App, Audit: audit.New(clk), Clock: clk, License: lic{}}), License: lic{}})
	return svc, inv, w.d, w.web1
}

func parse(t *testing.T, b []byte) [][]string {
	t.Helper()
	require.True(t, bytes.HasPrefix(b, []byte("\xEF\xBB\xBF")))
	rows, err := csv.NewReader(bytes.NewReader(b[3:])).ReadAll()
	require.NoError(t, err)
	return rows
}

// Review Focus 4, owner step 3: the export is exactly the list's rows for the same filter, in the same order.
func TestExportEqualsTheListPages(t *testing.T) {
	svc, inv, _, web1 := exportWorld(t)
	ctx := context.Background()
	admin := audit.Actor{Type: audit.ActorUser, ID: uuid.New(), Name: "ada"}
	for _, f := range []inventory.CertificateFilter{{}, {Expiry: "30"}, {Expiry: "30", TargetID: web1}, {Query: "seed"}, {Expiry: "expired"},
		{Query: "nothing-matches"}} {
		var b bytes.Buffer
		n, err := svc.ExportCertificates(ctx, admin, f, &b)
		require.NoError(t, err)
		rows := parse(t, b.Bytes())
		assert.Equal(t, []string{"id", "subject_cn", "label", "sans", "issuer", "serial", "not_before", "not_after", "days_left", "source",
			"key_algorithm", "key_bits", "self_signed", "chain_complete", "fingerprint", "location_count"}, rows[0])
		var want []string
		f.Limit = 2 // page through the list with tiny pages
		for {
			page, err := inv.ListCertificates(ctx, f)
			require.NoError(t, err)
			for _, c := range page.Items {
				want = append(want, c.ID.String())
			}
			if page.NextCursor == "" {
				break
			}
			f.Cursor = page.NextCursor
		}
		var got []string
		for _, r := range rows[1:] {
			got = append(got, r[0])
		}
		assert.Equal(t, want, got, "%+v", f)
		assert.Equal(t, len(want), n)
	}
}

func TestExportServerFilterMatchesC17(t *testing.T) {
	svc, _, _, web1 := exportWorld(t)
	var b bytes.Buffer
	_, err := svc.ExportCertificates(context.Background(), audit.SystemActor("t"), inventory.CertificateFilter{Expiry: "30", TargetID: web1}, &b)
	require.NoError(t, err)
	var cns []string
	for _, r := range parse(t, b.Bytes())[1:] {
		cns = append(cns, r[1])
	}
	assert.Equal(t, []string{"old.seed.test", "api.seed.test", "www.seed.test", "shop.seed.test"}, cns)
}

// auditCheckingWriter counts the committed inventory.exported rows when the first byte arrives.
type auditCheckingWriter struct {
	t               *testing.T
	d               *pgtest.DB
	started         bool
	rowsAtFirstByte int
	b               bytes.Buffer
}

func (w *auditCheckingWriter) Write(p []byte) (int, error) {
	if !w.started {
		w.started = true
		require.NoError(w.t, w.d.Owner.QueryRow(context.Background(),
			`SELECT count(*) FROM audit_log WHERE action = 'inventory.exported'`).Scan(&w.rowsAtFirstByte))
	}
	return w.b.Write(p)
}

// Review Focus 4: the audit row is committed before the first byte; a refused export writes nothing.
func TestExportAuditsBeforeTheFirstByte(t *testing.T) {
	svc, _, d, web1 := exportWorld(t)
	ctx := context.Background()
	w := &auditCheckingWriter{t: t, d: d}
	_, err := svc.ExportCertificates(ctx, audit.Actor{Type: audit.ActorUser, ID: uuid.New(), Name: "aud"},
		inventory.CertificateFilter{Expiry: "30", TargetID: web1, Query: "=cmd"}, w)
	require.NoError(t, err)
	assert.Equal(t, 1, w.rowsAtFirstByte, "committed before the first byte")
	var details string
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT details::text FROM audit_log WHERE action = 'inventory.exported'`).Scan(&details))
	assert.Contains(t, details, `"kind": "certificates"`)
	assert.Contains(t, details, `"expiry": "30"`)
	assert.Contains(t, details, `"q": "=cmd"`, "the filter is recorded as given (audit details are data, never a CSV)")
}

func TestExportRefusesTooManyRows(t *testing.T) {
	if testing.Short() {
		t.Skip("inserts 50,001 rows")
	}
	svc, _, d, _ := exportWorld(t)
	ctx := context.Background()
	_, err := d.Owner.Exec(ctx, `INSERT INTO certificates (id, fingerprint_sha256, subject_cn, not_before, not_after, key_algorithm,
public_key_sha256, pem_chain, source, first_seen_at, last_seen_at, created_at)
SELECT gen_random_uuid(), md5(i::text) || md5((i + 1)::text), 'bulk-' || i, now(), now() + interval '1 year', 'ecdsa',
md5('k' || i) || md5('l' || i), '', 'uploaded', now(), now(), now() FROM generate_series(1, $1) AS i`, reports.MaxExportRows+1)
	require.NoError(t, err)
	var b bytes.Buffer
	_, err = svc.ExportCertificates(ctx, audit.SystemActor("t"), inventory.CertificateFilter{}, &b)
	assert.ErrorIs(t, err, reports.ErrTooLarge)
	assert.Zero(t, b.Len(), "nothing written")
	var n int
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action = 'inventory.exported'`).Scan(&n))
	assert.Zero(t, n, "a refused export is not an export")
}

// Review Focus 4: hostile cell values are neutralised; the SSH key export has its own columns.
func TestExportNeutralisesFormulas(t *testing.T) {
	svc, _, d, web1 := exportWorld(t)
	ctx := context.Background()
	_, err := seed.Certificate(ctx, d.Owner, "=HYPERLINK(\"http://evil\")", t0.Add(10*24*time.Hour), []uuid.UUID{web1})
	require.NoError(t, err)
	var b bytes.Buffer
	_, err = svc.ExportCertificates(ctx, audit.SystemActor("t"), inventory.CertificateFilter{Query: "hyperlink"}, &b)
	require.NoError(t, err)
	rows := parse(t, b.Bytes())
	require.Len(t, rows, 2)
	assert.Equal(t, "'=HYPERLINK(\"http://evil\")", rows[1][1])
	b.Reset()
	_, err = svc.ExportSSHKeys(ctx, audit.SystemActor("t"), inventory.KeyFilter{}, &b)
	require.NoError(t, err)
	assert.Equal(t, []string{"id", "fingerprint", "key_type", "bits", "comment", "managed", "platform_key", "weak", "location_count",
		"target_count", "missing", "retired", "first_seen_at"}, parse(t, b.Bytes())[0])
}
```

`internal/reports/views_integration_test.go`:

```go
//go:build integration

package reports_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/validate"
	"alice/internal/reports"
)

func addUser(t *testing.T, w world, name string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := w.d.Owner.Exec(context.Background(), `INSERT INTO users (id, username, display_name, password_hash, role, created_at, updated_at)
VALUES ($1, $2::text, $2::text, '$argon2id$x', 'operator', now(), now())`, id, name)
	require.NoError(t, err)
	return id
}

// Review Focus 5, R42 row 15: views are private, bounded, named uniquely, and hold only the page's filter keys.
func TestViewsArePrivateAndBounded(t *testing.T) {
	w := newWorld(t, false)
	ctx := context.Background()
	ada, bob := addUser(t, w, "ada"), addUser(t, w, "bob")
	v, err := w.svc.CreateView(ctx, ada, reports.PageCertificates, "Expiring on web-1",
		map[string]string{"expiry": "30", "target_id": w.web1.String()})
	require.NoError(t, err)
	_, err = w.svc.CreateView(ctx, ada, reports.PageCertificates, "EXPIRING on WEB-1", map[string]string{})
	assert.ErrorIs(t, err, reports.ErrViewName)
	list, err := w.svc.Views(ctx, bob, reports.PageCertificates)
	require.NoError(t, err)
	assert.Empty(t, list, "another user's views are invisible")
	assert.ErrorIs(t, w.svc.DeleteView(ctx, bob, v.ID), reports.ErrNotFound)
	for _, bad := range []map[string]string{{"cursor": "x"}, {"os_user": "root"}, {"q": strings.Repeat("x", 201)}, {"q": "a\x00b"}} {
		_, err := w.svc.CreateView(ctx, ada, reports.PageCertificates, "bad", bad)
		var verrs validate.Errors
		assert.True(t, errors.As(err, &verrs), "%v", bad)
	}
	_, err = w.svc.CreateView(ctx, ada, "targets", "x", nil)
	assert.Error(t, err)
	for i := 1; i < reports.MaxViewsPerUser; i++ {
		_, err := w.svc.CreateView(ctx, ada, reports.PageSSHKeys, "v"+uuid.NewString()[:8], map[string]string{"os_user": "root"})
		require.NoError(t, err)
	}
	_, err = w.svc.CreateView(ctx, ada, reports.PageSSHKeys, "one too many", nil)
	assert.ErrorIs(t, err, reports.ErrViewLimit)
	require.NoError(t, w.svc.DeleteView(ctx, ada, v.ID))
	assert.Equal(t, []string{"target_id", "source", "q", "expiry"}, reports.ViewQueryKeys(reports.PageCertificates))
	assert.Equal(t, []string{"target_id", "os_user", "q", "flag", "missing"}, reports.ViewQueryKeys(reports.PageSSHKeys))
}
```

`internal/inventory/certificates_integration_test.go` gains `TestCertificateFilterWindowsAndKeyVaultSource`: certificates expiring in 5, 10, 20, 50, 80 and 100 days and one expired (inserted as the file's other tests insert certificates, one with `source = 'azure_kv'`); `Expiry: "7"` lists the expired one and the 5-day one, `"14"` adds the 10-day one, `"90"` everything but the 100-day one; `Source: "azure_kv"` lists exactly the Key Vault one; `Expiry: "45"` is a `validate.Errors` on `expiry`.

`internal/inventory/kv_reconcile_integration_test.go` gains:

```go
type queryLog struct {
	mu  sync.Mutex
	sql []string
}

func (q *queryLog) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.sql = append(q.sql, d.SQL)
	return ctx
}

func (q *queryLog) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

// Carry 4 (Phase 5 parked): storing a poll reads the stored versions in one batch; there is no query per certificate.
func TestPollReadsStoredVersionsInOneBatch(t *testing.T) {
	d := pgtest.New(t)
	cfg, err := pgxpool.ParseConfig(d.AppURL)
	require.NoError(t, err)
	log := &queryLog{}
	cfg.ConnConfig.Tracer = log
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	// Run exactly the scenario of TestAVersionFirstListedAsHistoryIsNewWhenItBecomesCurrent with a service built on
	// pool (its harness takes the pool; pass this one), and keep that test's assertions on the outcome.
	runHistoryBecomesCurrentScenario(t, d, pool)
	for _, q := range log.sql {
		assert.NotContains(t, q, "SELECT certificate_id IS NULL FROM kv_certificate_versions", "the per-certificate query is gone")
	}
}
```

`runHistoryBecomesCurrentScenario(t, d, pool)` is the body of `TestAVersionFirstListedAsHistoryIsNewWhenItBecomesCurrent` moved into a helper that takes the pool the service is built on; that test then calls it with `d.App`, so both run the same steps and assertions.

`internal/sshkeys/download_integration_test.go` gains:

```go
// Carry 3: the retention of a retired key's private key is the general setting (default 30 days).
func TestDestroyFollowsTheRetentionSetting(t *testing.T) {
	e := newEnv(t)
	k := e.generate("ci")
	e.retireAt(k.ID, e.clock.Now())
	require.NoError(t, settings.Set(e.ctx, e.db.App, settings.GeneralKey,
		settings.General{RetiredKeyRetentionDays: 7, Version: 1}, e.clock.Now()))
	e.clock.Advance(7*24*time.Hour - time.Second)
	n, err := e.svc.DestroyRetiredKeys(e.ctx)
	require.NoError(t, err)
	assert.Zero(t, n)
	e.clock.Advance(time.Second)
	n, err = e.svc.DestroyRetiredKeys(e.ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n, "destroyed after 7 days, not 30")
}
```

- [ ] **Step 2: Run the tests to verify they fail** (Docker: testcontainers)

Run: `go test -count=1 -tags integration ./internal/reports/ ./internal/inventory/ ./internal/sshkeys/`
Expected: FAIL — `ExportCertificates`, `CreateView` undefined; `expiry "7"` refused; the per-certificate query still runs; the key is not destroyed after 7 days.

- [ ] **Step 3: Write the implementation**

`internal/reports/export.go`:

```go
// ExportCertificates writes the CSV of every certificate the list shows for f (R42 row 16): it pages through
// inventory.ListCertificates (so the export is the list), refuses more than MaxExportRows before writing anything,
// commits one inventory.exported audit row, then writes the BOM, the header and the rows through csvx.
func (s *Service) ExportCertificates(ctx context.Context, a audit.Actor, f inventory.CertificateFilter, w io.Writer) (int, error) {
	f.Cursor, f.Limit = "", 200
	var items []inventory.Certificate
	for {
		page, err := s.inventory.ListCertificates(ctx, f)
		if err != nil {
			return 0, err
		}
		items = append(items, page.Items...)
		if len(items) > MaxExportRows {
			return 0, ErrTooLarge
		}
		if page.NextCursor == "" {
			break
		}
		f.Cursor = page.NextCursor
	}
	details := map[string]string{"kind": "certificates", "format": "csv"}
	for k, v := range map[string]string{"source": f.Source, "q": f.Query, "expiry": f.Expiry} {
		if v != "" {
			details[k] = v
		}
	}
	if f.TargetID != uuid.Nil {
		details["target_id"] = f.TargetID.String()
	}
	if err := s.auditExport(ctx, a, details); err != nil {
		return 0, err
	}
	cw, err := csvx.NewWriter(w)
	if err != nil {
		return 0, err
	}
	if err := cw.Write(certificateColumns); err != nil {
		return 0, err
	}
	now := s.clock.Now()
	for _, c := range items {
		if err := cw.Write([]string{c.ID.String(), c.SubjectCN, c.Label, strings.Join(c.SANs, " "), c.Issuer, c.Serial,
			c.NotBefore.UTC().Format(time.RFC3339), c.NotAfter.UTC().Format(time.RFC3339), strconv.Itoa(expiry.DaysLeft(c.NotAfter, now)),
			c.Source, c.KeyAlgorithm, strconv.Itoa(c.KeyBits), strconv.FormatBool(c.SelfSigned), strconv.FormatBool(c.ChainComplete),
			c.Fingerprint, strconv.Itoa(c.LocationCount)}); err != nil {
			return 0, err
		}
	}
	return len(items), cw.Flush()
}

var certificateColumns = []string{"id", "subject_cn", "label", "sans", "issuer", "serial", "not_before", "not_after", "days_left",
	"source", "key_algorithm", "key_bits", "self_signed", "chain_complete", "fingerprint", "location_count"}

var sshKeyColumns = []string{"id", "fingerprint", "key_type", "bits", "comment", "managed", "platform_key", "weak",
	"location_count", "target_count", "missing", "retired", "first_seen_at"}

func (s *Service) auditExport(ctx context.Context, a audit.Actor, details map[string]string) error {
	return db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		_, err := s.audit.Append(ctx, tx, audit.Event{Actor: a, Action: "inventory.exported", ObjectType: details["kind"],
			Result: audit.Success, Details: details})
		return err
	})
}
```

`ExportSSHKeys` is the same with `inventory.ListSSHKeys`/`KeyFilter` (details `kind` `ssh_keys`, `target_id`, `os_user`, `q`, `flag`, `missing` when set), `sshKeyColumns`, and the row `ID, Fingerprint, KeyType, Bits, Comment, Managed, IsPlatformKey, Weak, LocationCount, TargetCount, Missing, Retired, FirstSeenAt (RFC 3339 UTC)`. (Check the field names of `inventory.Certificate` — `Issuer`, `Serial`, `SANs`, `KeyBits` — and `inventory.SSHKey` in `certificates.go`/`sshkeys.go`; they are the ones listed in the plan's verification.)

`internal/reports/views.go`:

- `ViewQueryKeys(page)`: `certificates` → `target_id, source, q, expiry`; `ssh_keys` → `target_id, os_user, q, flag, missing`; any other page → nil.
- `CreateView(ctx, userID, page, name, query)`: `page` must have keys (else `validate.Errors{page: validate.OneOf}`); `name` trimmed, 1–60 runes, no control/format characters (`validate.Pattern`, `TooLong`, `Required`); every query key in `ViewQueryKeys(page)` (else `query.<key>` `validate.OneOf`), every value at most 200 runes and `validate.StorableText` (else `query.<key>` `TooLong`/`Pattern`); in one transaction: `SELECT 1 FROM users WHERE id = $1 FOR UPDATE` (serialises one user's creations), `count(*)` of the user's views ≥ `MaxViewsPerUser` → `ErrViewLimit`; insert (unique violation of `saved_views_name` → `ErrViewName`); return the view.
- `Views(ctx, userID, page)`: the user's views of the page ordered by `lower(name)`.
- `DeleteView(ctx, userID, id)`: `DELETE … WHERE id = $1 AND user_id = $2`; no row → `ErrNotFound`.

`internal/inventory/certificates.go`: `certificateSources = []string{"discovered", "uploaded", "csr", "azure_kv"}`, `expiryWindows = []string{"expired", "7", "14", "30", "60", "90"}`; the window switch becomes `case f.Expiry != "" && f.Expiry != "expired":` with `strconv.Atoi` (the value is already one of the list).

`internal/inventory/kv_store.go`: the batch statement selects `v.certificate_id IS NULL` as a fifth column into a new map `storedHistory map[[2]string]bool`; the block that ran the per-certificate query becomes `wasHistory := known && storedHistory[[2]string{certID.String(), d.version}]` (only when the version was stored — `has` — as before).

`internal/sshkeys/destroy.go`: before the retention comparison read `g, err := settings.GetGeneral(ctx, s.pool)` and use `retention := time.Duration(g.RetiredKeyRetentionDays) * 24 * time.Hour` in place of `RetiredKeyRetention`; `RetiredKeyRetention`'s comment says it is the default of `general.retired_key_retention_days`.

- [ ] **Step 4: Run the tests to verify they pass** (Docker: testcontainers)

Run: `go test -count=1 -race -tags integration ./internal/reports/ ./internal/inventory/ ./internal/sshkeys/ ./internal/api/`
Expected: `ok` for all (the API's certificate list tests accept the new windows; if one asserted that `expiry=7` is refused, it now asserts `expiry=45` is).

Run: `make lint`
Expected: no findings.

- [ ] **Step 5: Commit**

```bash
git add -- internal/reports/export.go internal/reports/views.go internal/reports/export_integration_test.go internal/reports/views_integration_test.go
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(reports): formula-safe CSV exports that equal the list, audited first; private saved views; certificate filters 7-90 days and Key Vault" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- internal/reports internal/inventory/certificates.go \
  internal/inventory/certificates_integration_test.go
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "perf(inventory): read the history flag of stored Key Vault versions in the batch (carry 4); retention of retired keys from Settings (carry 3)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- internal/inventory/kv_store.go internal/inventory/kv_reconcile_integration_test.go \
  internal/sshkeys/destroy.go internal/sshkeys/download_integration_test.go
```

---

### Task 11: `internal/auth`: SSO users (`SignInOIDC`, `StepUpOIDC`, `RefuseOIDC`, demotion), SSO-user rules, `audit.ActorOIDC`, the lockout email

**Files:**
- Modify: `internal/audit/audit.go` (`ActorOIDC ActorType = "oidc"`; the actor type check accepts it), `internal/audit/audit_test.go` (one case)
- Create: `internal/auth/oidc_users.go` (`OIDCIdentity`, `SignInOIDC`, `StepUpOIDC`, `RefuseOIDC`, `DemoteSSOAdmins`, errors), `internal/auth/lockout.go` (`Notifier`, `TemplateLockout`, `Templates`)
- Modify: `internal/auth/service.go` (`Config.Notifier`; `User`, `Principal`, `SessionInfo` gain `AuthSource`, `SSOProviderID`), `internal/auth/store.go` (`userColumns` reads `auth_source`, `oidc_provider_id`), `internal/auth/login.go` (`recordFailure` queues `auth.lockout` in its transaction when it locks), `internal/auth/users.go` (`ErrSSOUser` for a role change, `ResetPassword`, `ResetMFA` of an SSO user), `internal/auth/sessions.go` (session info carries the new fields)
- Modify: `internal/auth/env_integration_test.go` (`env.notes`, the recording notifier, `env.provider`)
- Create: `internal/auth/oidc_users_integration_test.go`

**Interfaces:**
- Consumes: the `users` columns of Task 5, `startFullSession`, `rotateSession`, `resultFor`, `lockAdmins`, `audit.Log.Append`, `rbac.Role`.
- Produces: C10 exactly; `auth.Templates()` (`auth.lockout`, texts in Task 14).

- [ ] **Step 1: Write the failing tests**

`internal/auth/env_integration_test.go`: `env` gains `notes *noteRecorder`; `newEnv` passes it as `auth.Config.Notifier`:

```go
// noteRecorder records the emails auth queues (the outbox is notify's).
type noteRecorder struct {
	mu  sync.Mutex
	got []string // template + " " + sorted params
}

func (n *noteRecorder) NotifyAdmins(_ context.Context, _ pgx.Tx, template string, params map[string]string) error {
	keys := make([]string, 0, len(params))
	for k, v := range params {
		keys = append(keys, k+"="+v)
	}
	sort.Strings(keys)
	n.mu.Lock()
	defer n.mu.Unlock()
	n.got = append(n.got, template+" "+strings.Join(keys, ","))
	return nil
}

func (n *noteRecorder) all() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.got...)
}

// provider inserts an identity provider row (the SSO users' foreign key).
func (e *env) provider(t *testing.T) uuid.UUID {
	t.Helper()
	id := uuid.Must(uuid.NewV7())
	_, err := e.db.Owner.Exec(e.ctx, `INSERT INTO oidc_providers (id, name, issuer_url, client_id, scopes, groups_claim,
authorization_endpoint, token_endpoint, jwks_uri, enabled, created_at, updated_at) VALUES ($1, 'Corp', 'https://idp.example.com',
'alice', '{openid}', 'groups', 'https://idp.example.com/a', 'https://idp.example.com/t', 'https://idp.example.com/j', true, now(), now())`, id)
	require.NoError(t, err)
	return id
}
```

`internal/auth/oidc_users_integration_test.go`:

```go
//go:build integration

package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/auth"
	"alice/internal/rbac"
)

func identity(p uuid.UUID, sub, user, email string) auth.OIDCIdentity {
	return auth.OIDCIdentity{ProviderID: p, Issuer: "https://idp.example.com", Subject: sub, Username: user, DisplayName: "Ada Yılmaz", Email: email}
}

// O-09: an SSO user is matched by issuer and subject; e-mail and role follow the provider at every sign-in.
func TestSignInOIDCProvisionsAndMatchesBySubject(t *testing.T) {
	e := newEnv(t)
	p := e.provider(t)
	res, err := e.svc.SignInOIDC(e.ctx, identity(p, "sub-1", "ada", "ada@example.com"), rbac.Operator, meta)
	require.NoError(t, err)
	pr := e.principal(t, res.Token)
	assert.Equal(t, rbac.Operator, pr.Role)
	assert.Equal(t, "oidc", pr.AuthSource)
	assert.True(t, pr.Subject(e.clk.Now()).StepUp, "the IdP just authenticated the user: the step-up window is open")
	var source, roleSource string
	var hash *string
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, `SELECT auth_source, role_source, password_hash FROM users WHERE id = $1`, pr.UserID).
		Scan(&source, &roleSource, &hash))
	assert.Equal(t, [2]string{"oidc", "oidc_mapping"}, [2]string{source, roleSource})
	assert.Nil(t, hash, "no password")

	res2, err := e.svc.SignInOIDC(e.ctx, identity(p, "sub-1", "ada.new", "ada@new.example.com"), rbac.Auditor, meta)
	require.NoError(t, err)
	pr2 := e.principal(t, res2.Token)
	assert.Equal(t, pr.UserID, pr2.UserID, "same issuer and subject: same user")
	assert.Equal(t, rbac.Auditor, pr2.Role, "the role follows the mapping")
	assert.Equal(t, rbac.Auditor, e.principal(t, res.Token).Role, "an open session reads the new role at once")
	u, err := e.svc.GetUser(e.ctx, pr.UserID)
	require.NoError(t, err)
	assert.Equal(t, "ada@new.example.com", u.Email)
	assert.Equal(t, "ada", u.Username, "the user name is kept")
	assert.Contains(t, e.actions(t), "user.provisioned:success")
	assert.Contains(t, e.actions(t), "user.role_synced:success")
	assert.Equal(t, 2, e.countAction(t, "auth.login", "success"))

	// Another subject with a taken user name gets a suffix.
	res3, err := e.svc.SignInOIDC(e.ctx, identity(p, "sub-2", "ada", ""), rbac.Auditor, meta)
	require.NoError(t, err)
	u3, err := e.svc.GetUser(e.ctx, e.principal(t, res3.Token).UserID)
	require.NoError(t, err)
	assert.Equal(t, "ada-2", u3.Username)
}

// O-10: never a link to a local account; local sign-in of an SSO user fails like any wrong password.
func TestO10NoLinkToLocalAccounts(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.adminPrincipal(t)
	local := e.createUser(t, admin, "ada", rbac.Operator)
	_, err := e.svc.UpdateUser(e.ctx, admin, meta, local.ID, auth.UserUpdate{Email: ptr("ada@example.com")})
	require.NoError(t, err)
	p := e.provider(t)
	_, err = e.svc.SignInOIDC(e.ctx, identity(p, "sub-1", "ada-corp", "ADA@example.com"), rbac.Operator, meta)
	assert.ErrorIs(t, err, auth.ErrOIDCEmailInUse)
	var n int
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, `SELECT count(*) FROM users WHERE auth_source = 'oidc'`).Scan(&n))
	assert.Zero(t, n, "nothing created")

	_, err = e.svc.SignInOIDC(e.ctx, identity(p, "sub-9", "sso-user", "sso@example.com"), rbac.Operator, meta)
	require.NoError(t, err)
	_, err = e.svc.Login(e.ctx, "sso-user", adminPassword, meta)
	assert.ErrorIs(t, err, auth.ErrInvalidCredentials, "an SSO user has no local sign-in")
}

func TestSSOUserRulesAndBreakGlass(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.adminPrincipal(t)
	p := e.provider(t)
	res, err := e.svc.SignInOIDC(e.ctx, identity(p, "sub-1", "boss", "boss@example.com"), rbac.Admin, meta)
	require.NoError(t, err)
	sso := e.principal(t, res.Token)
	_, err = e.svc.UpdateUser(e.ctx, admin, meta, sso.UserID, auth.UserUpdate{Role: ptr(rbac.Auditor)})
	assert.ErrorIs(t, err, auth.ErrSSOUser)
	_, err = e.svc.ResetPassword(e.ctx, admin, meta, sso.UserID)
	assert.ErrorIs(t, err, auth.ErrSSOUser)
	assert.ErrorIs(t, e.svc.ResetMFA(e.ctx, admin, meta, sso.UserID), auth.ErrSSOUser)
	_, err = e.svc.UpdateUser(e.ctx, admin, meta, sso.UserID, auth.UserUpdate{Disabled: ptr(true)})
	require.NoError(t, err, "an SSO user can be disabled")
	_, err = e.svc.UpdateUser(e.ctx, admin, meta, admin.UserID, auth.UserUpdate{Role: ptr(rbac.Operator)})
	assert.ErrorIs(t, err, auth.ErrLastAdmin, "an SSO Administrator is never the break-glass account")
}

// O-08, R42 row 21: a refused SSO sign-in of a known user ends that user's sessions.
func TestRefuseOIDCEndsSessions(t *testing.T) {
	e := newEnv(t)
	p := e.provider(t)
	id := identity(p, "sub-1", "ada", "")
	res, err := e.svc.SignInOIDC(e.ctx, id, rbac.Operator, meta)
	require.NoError(t, err)
	require.NoError(t, e.svc.RefuseOIDC(e.ctx, id, "no_access", meta))
	_, err = e.svc.Authenticate(e.ctx, res.Token)
	assert.ErrorIs(t, err, auth.ErrUnauthenticated)
	assert.Equal(t, map[string]int{"no_access": 1}, e.reasons(t, "auth.oidc.denied"))
	assert.Contains(t, e.actions(t), "user.sessions_ended:success")
	require.NoError(t, e.svc.RefuseOIDC(e.ctx, identity(p, "unknown", "x", ""), "login_invalid", meta), "an unknown identity is only audited")
}

// SEC-009, R42 row 22: an SSO user's step-up is a fresh IdP sign-in of the same identity.
func TestStepUpOIDC(t *testing.T) {
	e := newEnv(t)
	p := e.provider(t)
	id := identity(p, "sub-1", "ada", "")
	res, err := e.svc.SignInOIDC(e.ctx, id, rbac.Operator, meta)
	require.NoError(t, err)
	e.clk.Advance(auth.StepUpWindow + time.Second)
	pr := e.principal(t, res.Token)
	require.False(t, pr.Subject(e.clk.Now()).StepUp)
	_, err = e.svc.StepUpOIDC(e.ctx, pr.SessionHash, pr.UserID, identity(p, "sub-2", "x", ""), meta)
	assert.ErrorIs(t, err, auth.ErrOIDCOtherUser)
	up, err := e.svc.StepUpOIDC(e.ctx, pr.SessionHash, pr.UserID, id, meta)
	require.NoError(t, err)
	assert.True(t, e.principal(t, up.Token).Subject(e.clk.Now()).StepUp)
	admin, _ := e.adminPrincipal(t)
	_, err = e.svc.StepUpOIDC(e.ctx, admin.SessionHash, admin.UserID, id, meta)
	assert.ErrorIs(t, err, auth.ErrNotSSOUser)
}

// O-13, R42 row 24: switching SSO Administrators off demotes them to Auditor and ends their sessions.
func TestDemoteSSOAdmins(t *testing.T) {
	e := newEnv(t)
	p := e.provider(t)
	res, err := e.svc.SignInOIDC(e.ctx, identity(p, "sub-1", "boss", ""), rbac.Admin, meta)
	require.NoError(t, err)
	_, err = e.svc.SignInOIDC(e.ctx, identity(p, "sub-2", "op", ""), rbac.Operator, meta)
	require.NoError(t, err)
	tx, err := e.db.App.Begin(e.ctx)
	require.NoError(t, err)
	demoted, ended, err := e.svc.DemoteSSOAdmins(e.ctx, tx, audit.SystemActor("test"))
	require.NoError(t, err)
	require.NoError(t, tx.Commit(e.ctx))
	assert.Equal(t, [2]int{1, 1}, [2]int{demoted, ended})
	_, err = e.svc.Authenticate(e.ctx, res.Token)
	assert.ErrorIs(t, err, auth.ErrUnauthenticated)
	var role string
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, `SELECT role FROM users WHERE username = 'boss'`).Scan(&role))
	assert.Equal(t, "auditor", role)
}

// SEC-020, R42 row 25: a lockout queues auth.lockout once, in the lockout's transaction.
func TestLockoutEmailsTheAdministrators(t *testing.T) {
	e := newEnv(t)
	e.adminPrincipal(t)
	for i := 0; i < auth.LockThreshold; i++ {
		_, _ = e.svc.Login(context.Background(), "admin", "wrong password here", meta)
		e.clk.Advance(auth.MaxDelay)
	}
	assert.Equal(t, []string{"auth.lockout failed_logins=10,minutes=15,username=admin"}, e.notes.all())
}
```

(`e.svc.Authenticate(ctx, token)` and `ResetPassword`'s return values follow the existing signatures in `sessions.go` and `users.go` — read them; adapt the two calls if they differ. `TestRefuseOIDCEndsSessions` uses the existing `e.reasons` helper.)

`internal/audit/audit_test.go`: `TestOIDCActorIsAccepted` appends an event with `Actor{Type: audit.ActorOIDC, Name: "ada"}` through the existing unit seam the file uses for actor types and expects no error.

- [ ] **Step 2: Run the tests to verify they fail** (Docker: testcontainers)

Run: `go test ./internal/audit/ && go test -tags integration ./internal/auth/`
Expected: FAIL — undefined `ActorOIDC`, `SignInOIDC`, `Config.Notifier`, `Principal.AuthSource`.

- [ ] **Step 3: Write the implementation**

`internal/auth/lockout.go`:

```go
package auth

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// TemplateLockout is the email to Administrators when an account is blocked (SEC-020, R42 row 25).
const TemplateLockout = "auth.lockout"

// Templates lists every email template of the auth module.
func Templates() []string { return []string{TemplateLockout} }

// Notifier queues emails to the recipients of the notify settings; *notify.AdminNotifier.
type Notifier interface {
	NotifyAdmins(ctx context.Context, tx pgx.Tx, template string, params map[string]string) error
}
```

`login.go`, `recordFailure`, inside `if locked { … }` after the `auth.lockout` audit row:

```go
		if s.notifier != nil {
			var username string
			if err := tx.QueryRow(ctx, `SELECT username::text FROM users WHERE id = $1`, userID).Scan(&username); err != nil {
				return err
			}
			if err := s.notifier.NotifyAdmins(ctx, tx, TemplateLockout, map[string]string{"username": username,
				"minutes": strconv.Itoa(int(LockDuration / time.Minute)), "failed_logins": strconv.Itoa(n)}); err != nil {
				return err
			}
		}
```

(`n` is the failure count `recordFailure` computes; use its variable.)

`internal/auth/oidc_users.go` — the behaviour of C10:

- `SignInOIDC(ctx, id, role, m)`: one `credentialTx`-style transaction (as `VerifyMFA` uses): `SELECT … FROM users WHERE oidc_issuer = $1 AND oidc_subject = $2 FOR UPDATE`; when absent: refuse with `ErrOIDCEmailInUse` if `id.Email != ""` and `SELECT EXISTS (SELECT 1 FROM users WHERE auth_source = 'local' AND email = $1)` (citext comparison); pick the user name (`id.Username`, then `-2`, `-3`, … up to `-99`, checking `username` with `citext` equality; the name is cut to leave room for the suffix within 64 bytes); `INSERT INTO users (id, username, email, display_name, auth_source, password_hash, role, role_source, locale, oidc_provider_id, oidc_issuer, oidc_subject, created_at, updated_at) VALUES (…, 'oidc', NULL, $role, 'oidc_mapping', $locale, …)` with `locale` the `locale.default` setting (`en` when absent); audit `user.provisioned` (actor `ActorOIDC`). Existing user: `disabled_at IS NOT NULL` → `ErrOIDCUserDisabled`; `UPDATE users SET role = $2, email = $3, display_name = $4, last_login_at = $5, updated_at = $5`; a changed role → audit `user.role_synced` (`from_role`, `to_role`). Then `startFullSession(ctx, tx, userID, m)`, audit `auth.login` (`method` `oidc`, `provider_id`, `role`), `resultFor`.
- `StepUpOIDC(ctx, sessionHash, userID, id, m)`: the session's user must be `auth_source = 'oidc'` (else `ErrNotSSOUser`) with `oidc_issuer`/`oidc_subject` equal to `id`'s (else `ErrOIDCOtherUser`); `rotateSession(ctx, tx, sessionHash, userID, &stepUpUntil, m)` with `stepUpUntil = now + StepUpWindow`; audit `auth.stepup` (`method` `oidc`).
- `RefuseOIDC(ctx, id, reason, m)`: one transaction: audit `auth.oidc.denied` (actor `ActorOIDC`, name `id.Username`, details `provider_id`, `reason`); for a known user (by issuer and subject) and `reason` in {`no_access`, `groups_overage`, `provider_disabled`}: `UPDATE sessions SET revoked_at = $2 WHERE user_id = $1 AND revoked_at IS NULL` and audit `user.sessions_ended` (`reason`, `ended_count`).
- `DemoteSSOAdmins(ctx, tx, a)`: `UPDATE users SET role = 'auditor', updated_at = now WHERE auth_source = 'oidc' AND role = 'admin' RETURNING id`; revoke their sessions; audit `user.demoted` per user (`from_role` `admin`, `to_role` `auditor`) and return the counts.

`users.go`: `UpdateUser` with a role change, `ResetPassword` and `ResetMFA` load `auth_source` with the user (they already lock the row) and return `ErrSSOUser` for `oidc` before any change (audited as their existing failures with reason `sso_user`). `lockAdmins` keeps `auth_source = 'local'` (break-glass counts local Administrators only).

`audit.go`: `ActorOIDC ActorType = "oidc"` beside the other actor types; if `Append` checks the type against a list, the list gains it (the database CHECK already allows `oidc`).

- [ ] **Step 4: Run the tests to verify they pass** (Docker: testcontainers)

Run: `go test -count=1 -race ./internal/audit/ ./internal/auth/ && go test -count=1 -race -tags integration ./internal/auth/ ./internal/audit/ ./internal/setup/`
Expected: `ok` for all (local login, MFA, lockout, users and setup tests unchanged).

Run: `make lint`
Expected: no findings.

- [ ] **Step 5: Commit**

```bash
git add -- internal/auth/oidc_users.go internal/auth/lockout.go internal/auth/oidc_users_integration_test.go
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(auth): SSO users matched by issuer and subject, never linked to local accounts; IdP step-up; lockout email" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- internal/auth internal/audit/audit.go internal/audit/audit_test.go
```

---

### Task 12: `internal/auth/oidc`: providers and discovery, the bounded key set, mappings and the Admin switch, `Begin`/`Complete`, state pruning; O-01..O-14 at service level; go.mod

**Files:**
- Modify: `go.mod`, `go.sum` (three modules, pinned)
- Create: `internal/auth/oidc/service.go` (constants, errors, `Config`, `Service`, `New`, `RedirectURI`), `internal/auth/oidc/httpclient.go`, `internal/auth/oidc/keyset.go`, `internal/auth/oidc/discovery.go`, `internal/auth/oidc/providers.go`, `internal/auth/oidc/mappings.go`, `internal/auth/oidc/settings.go`, `internal/auth/oidc/login.go`, `internal/auth/oidc/states.go`
- Create: `internal/auth/oidc/harness_integration_test.go`, `internal/auth/oidc/providers_integration_test.go`, `internal/auth/oidc/negative_integration_test.go`, `internal/auth/oidc/keyset_test.go`

**Interfaces:**
- Consumes: C4 (`claims.*`), C6 (`fakeidp` in tests), C10 (`auth.{Service, OIDCIdentity, SignInOIDC, StepUpOIDC, RefuseOIDC, DemoteSSOAdmins, ErrOIDC*, ErrNotSSOUser, SessionResult, Meta}`), `secrets.{Keyring.PutSetting, GetSetting, DeleteSetting}` (Task 6), `settings.{Get, Set, GetGeneral}`, `netaddr.DialContext`, `audit.{Log, Append, Event, Actor}`, `db.InTx`, `validate.Errors`; `github.com/coreos/go-oidc/v3/oidc` (imported as `gooidc`: this package is also named `oidc`), `golang.org/x/oauth2`, `github.com/go-jose/go-jose/v4`.
- Produces: C11 exactly.

- [ ] **Step 1: Pin the modules**

Run: `go get github.com/coreos/go-oidc/v3@v3.21.0 golang.org/x/oauth2@v0.37.0 github.com/go-jose/go-jose/v4@v4.1.5`
Expected: `go: added github.com/coreos/go-oidc/v3 v3.21.0`, `go: added golang.org/x/oauth2 v0.37.0`, `go: added github.com/go-jose/go-jose/v4 v4.1.5` (the network is the host's; no container is involved).

Then (after Step 3 has files importing them) `go mod tidy` keeps the three as direct requirements. `go.sum` must contain exactly these lines for them (verify with `grep -E 'go-oidc|x/oauth2|go-jose' go.sum`):

```
github.com/coreos/go-oidc/v3 v3.21.0 h1:wZo4Q9Pum8dYEj0eMUPrqR+kvuGkeUplbLpNCkBqoWM=
github.com/coreos/go-oidc/v3 v3.21.0/go.mod h1:DYCf24+ncYi+XkIH97GY1+dqoRlbaSI26KVTCI9SrY4=
github.com/go-jose/go-jose/v4 v4.1.5 h1:RjgjO2LOtWOJKUC5wpwY9LR3B3vwVAz6JS2YHfYU6eA=
github.com/go-jose/go-jose/v4 v4.1.5/go.mod h1:x4oUasVrzR7071A4TnHLGSPpNOm2a21K9Kf04k1rs08=
golang.org/x/oauth2 v0.37.0 h1:JUlcxA8oAtauLfiH8FX2/FkAWHAdi0QtGCGc+hofE98=
golang.org/x/oauth2 v0.37.0/go.mod h1:IxwZNxUULJmpBFf9K/9NTMSIfZZuvuTy1gGxhigP/58=
```

(`go mod tidy` may also keep the `go.mod` line of `go-jose v4.1.4`, which go-oidc requires; that is normal.) `make vuln` (`go mod verify`, `govulncheck`) must stay clean; a reported vulnerability in one of the three stops the task (report it; do not pick another version without a ruling).

- [ ] **Step 2: Write the failing tests**

`internal/auth/oidc/keyset_test.go` (unit: the bounded key set against a local JWKS server):

```go
package oidc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/clock"
)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func signRS256(t *testing.T, key *rsa.PrivateKey, kid, alg string, payload string) string {
	t.Helper()
	hdr, _ := json.Marshal(map[string]string{"alg": alg, "kid": kid, "typ": "JWT"})
	input := b64(hdr) + "." + b64([]byte(payload))
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	require.NoError(t, err)
	return input + "." + b64(sig)
}

func jwksServer(t *testing.T, keys map[string]*rsa.PrivateKey, hits *atomic.Int32, big bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		var out []map[string]string
		for kid, k := range keys {
			out = append(out, map[string]string{"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
				"n": b64(k.N.Bytes()), "e": b64(new(big.Int).SetInt64(int64(k.E)).Bytes())})
		}
		if big {
			_, _ = w.Write([]byte(`{"keys":[` + strings.Repeat(`{"kty":"oct","k":"AAAA"},`, 60000) + `{}]}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": out})
	}))
}

// O-11: an unknown kid refetches the JWKS at most once per minute; O-01: only RS256, ES256 and PS256 are accepted.
func TestJWKSRefetchIsRateLimited(t *testing.T) {
	k1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	k2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	var hits atomic.Int32
	keys := map[string]*rsa.PrivateKey{"k1": k1}
	srv := jwksServer(t, keys, &hits, false)
	defer srv.Close()
	clk := clock.NewFake(time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC))
	ks := newKeySet(srv.Client(), srv.URL, clk)
	ctx := context.Background()
	payload, err := ks.VerifySignature(ctx, signRS256(t, k1, "k1", "RS256", `{"sub":"a"}`))
	require.NoError(t, err)
	assert.Equal(t, `{"sub":"a"}`, string(payload))
	assert.Equal(t, int32(1), hits.Load())
	_, err = ks.VerifySignature(ctx, signRS256(t, k1, "k1", "RS256", `{}`))
	require.NoError(t, err)
	assert.Equal(t, int32(1), hits.Load(), "a known kid is served from the cache")
	keys["k2"] = k2 // the provider rotates
	for i := 0; i < 5; i++ {
		_, err = ks.VerifySignature(ctx, signRS256(t, k2, "k2", "RS256", `{}`))
	}
	assert.Error(t, err, "within a minute of the last fetch an unknown kid does not refetch")
	assert.Equal(t, int32(1), hits.Load())
	clk.Advance(JWKSRefetchEvery)
	_, err = ks.VerifySignature(ctx, signRS256(t, k2, "k2", "RS256", `{}`))
	require.NoError(t, err, "after a minute one refetch finds the new key")
	assert.Equal(t, int32(2), hits.Load())

	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	_, err = ks.VerifySignature(ctx, signRS256(t, other, "k1", "RS256", `{}`))
	assert.Error(t, err, "signed by a key that is not in the set")
	for _, alg := range []string{"none", "HS256", "RS512"} {
		_, err = ks.VerifySignature(ctx, signRS256(t, k1, "k1", alg, `{}`))
		assert.Error(t, err, alg)
	}
}

func TestJWKSSizeIsBounded(t *testing.T) {
	var hits atomic.Int32
	srv := jwksServer(t, nil, &hits, true)
	defer srv.Close()
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	ks := newKeySet(limitedClient(srv.Client()), srv.URL, clock.NewFake(time.Now()))
	_, err := ks.VerifySignature(context.Background(), signRS256(t, k, "k1", "RS256", `{}`))
	assert.Error(t, err, "a JWKS beyond 1 MiB or 50 keys is refused")
}
```

(`limitedClient(c)` wraps `c.Transport` in the package's `limitTransport` so the test exercises the same response bound as `httpClient`.)

`internal/auth/oidc/harness_integration_test.go`:

```go
//go:build integration

package oidc_test

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/auth"
	"alice/internal/auth/oidc"
	"alice/internal/platform/clock"
	"alice/internal/platform/settings"
	"alice/internal/rbac"
	"alice/internal/secrets"
	"alice/internal/testutil/fakeidp"
	"alice/internal/testutil/pgtest"
)

func TestMain(m *testing.M) { os.Exit(pgtest.Main(m)) }

var meta = auth.Meta{IP: netip.MustParseAddr("192.0.2.10"), UserAgent: "test", RequestID: "req-1"}

type harness struct {
	ctx   context.Context
	d     *pgtest.DB
	clk   *clock.Fake
	idp   *fakeidp.Server
	auth  *auth.Service
	svc   *oidc.Service
	admin audit.Actor
	prov  oidc.Provider
}

const publicURL = "https://alice.example.test"

func newHarness(t *testing.T) *harness {
	t.Helper()
	d := pgtest.New(t)
	clk := clock.NewFake(time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC))
	idp := fakeidp.Start(t, fakeidp.Options{Now: clk.Now})
	kr, err := secrets.NewKeyring(1, bytes.Repeat([]byte{7}, 32))
	require.NoError(t, err)
	h := auth.NewHasher(auth.Argon2Params{MemoryKiB: 64, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}, 4)
	a := auth.NewService(auth.Config{Pool: d.App, Keyring: kr, Audit: audit.New(clk), Clock: clk, Hasher: h, RecoveryHasher: h})
	svc := oidc.New(oidc.Config{Pool: d.App, Keyring: kr, Audit: audit.New(clk), Clock: clk, Auth: a})
	require.NoError(t, settings.Set(context.Background(), d.App, settings.GeneralKey,
		settings.General{PublicURL: publicURL, RetiredKeyRetentionDays: 30, Version: 1}, clk.Now()))
	x := &harness{ctx: context.Background(), d: d, clk: clk, idp: idp, auth: a, svc: svc,
		admin: audit.Actor{Type: audit.ActorUser, ID: uuid.New(), Name: "ada"}}
	x.prov = x.createProvider(t, true)
	idp.RegisterRedirect(x.prov.RedirectURI)
	return x
}

func (x *harness) createProvider(t *testing.T, enabled bool) oidc.Provider {
	t.Helper()
	p, err := x.svc.CreateProvider(x.ctx, x.admin, oidc.ProviderInput{Name: "Corp IdP", IssuerURL: x.idp.Issuer(),
		ClientID: x.idp.ClientID(), ClientSecret: secrets.NewPlaintext([]byte(x.idp.ClientSecret())), CAPEM: string(x.idp.CAPEM()),
		Enabled: enabled})
	require.NoError(t, err)
	return p
}

func (x *harness) mapGroup(t *testing.T, group string, role rbac.Role) {
	t.Helper()
	_, err := x.svc.CreateMapping(x.ctx, x.admin, x.prov.ID, group, role)
	require.NoError(t, err)
}

// login runs the browser's round trip: Begin, the IdP's authorize step, Complete with the callback's query.
func (x *harness) login(t *testing.T, next string) (oidc.Completion, error) {
	t.Helper()
	b, err := x.svc.Begin(x.ctx, oidc.BeginInput{ProviderID: x.prov.ID, Next: next})
	require.NoError(t, err)
	cb, err := x.idp.Authorize(b.AuthorizeURL)
	require.NoError(t, err)
	u, err := url.Parse(cb)
	require.NoError(t, err)
	return x.svc.Complete(x.ctx, x.prov.ID, u.Query(), b.Binding, meta)
}

func (x *harness) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	require.NoError(t, x.d.Owner.QueryRow(x.ctx, sql, args...).Scan(&n))
	return n
}

func reasonOf(err error) string {
	var le *oidc.LoginError
	if errors.As(err, &le) {
		return le.Reason
	}
	return ""
}
```

`internal/auth/oidc/providers_integration_test.go`:

```go
//go:build integration

package oidc_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/auth/oidc"
	"alice/internal/platform/validate"
	"alice/internal/rbac"
	"alice/internal/secrets"
	"alice/internal/testutil/fakeidp"
)

func TestCreateProviderReadsDiscoveryOnce(t *testing.T) {
	x := newHarness(t)
	p := x.prov
	assert.Equal(t, x.idp.Issuer()+"/authorize", p.Endpoints.Authorization)
	assert.Equal(t, x.idp.Issuer()+"/jwks", p.Endpoints.JWKS)
	assert.Equal(t, publicURL+"/api/v1/auth/oidc/"+p.ID.String()+"/callback", p.RedirectURI)
	assert.True(t, p.HasClientSecret)
	assert.Equal(t, []string{"openid", "profile", "email"}, p.Scopes)
	assert.Equal(t, "groups", p.GroupsClaim)
	before := x.idp.Stats().Discovery
	_, err := x.login(t, "/")
	require.Error(t, err) // no mapping yet
	assert.Equal(t, before, x.idp.Stats().Discovery, "endpoints are fixed at configuration time, never read at sign-in")
	assert.Equal(t, 1, x.count(t, `SELECT count(*) FROM audit_log WHERE action = 'sso.provider_created'`))
}

// Review Focus 3: the client secret is only an envelope; nothing else holds it.
func TestClientSecretIsAnEnvelope(t *testing.T) {
	x := newHarness(t)
	var dump string
	require.NoError(t, x.d.Owner.QueryRow(x.ctx, `SELECT (SELECT string_agg(t::text, ' ') FROM oidc_providers t) ||
(SELECT coalesce(string_agg(details::text, ' '), '') FROM audit_log) || (SELECT coalesce(string_agg(value::text, ' '), '') FROM settings)`).Scan(&dump))
	assert.NotContains(t, dump, x.idp.ClientSecret())
	var ct []byte
	require.NoError(t, x.d.Owner.QueryRow(x.ctx, `SELECT ciphertext FROM setting_secrets WHERE key = $1`,
		"sso.provider."+x.prov.ID.String()+".client_secret").Scan(&ct))
	assert.NotContains(t, string(ct), x.idp.ClientSecret())
}

// O-12: plain HTTP and an untrusted certificate are refused at configuration.
func TestO12InsecureIssuerRefused(t *testing.T) {
	x := newHarness(t)
	plain := fakeidp.Start(t, fakeidp.Options{Plain: true})
	_, err := x.svc.CreateProvider(x.ctx, x.admin, oidc.ProviderInput{Name: "Plain", IssuerURL: plain.Issuer(), ClientID: "alice",
		ClientSecret: secrets.NewPlaintext([]byte("s"))})
	var v validate.Errors
	require.True(t, errors.As(err, &v), "%v", err)
	assert.Equal(t, "issuer_url", v[0].Field)
	_, err = x.svc.CreateProvider(x.ctx, x.admin, oidc.ProviderInput{Name: "No CA", IssuerURL: x.idp.Issuer(), ClientID: "other",
		ClientSecret: secrets.NewPlaintext([]byte("s"))})
	var de *oidc.DiscoveryError
	require.True(t, errors.As(err, &de), "%v", err)
	assert.Equal(t, "tls", de.Cause)
	_, err = x.svc.CreateProvider(x.ctx, x.admin, oidc.ProviderInput{Name: "Mismatch", IssuerURL: x.idp.Issuer() + "/realms/x",
		ClientID: "other", ClientSecret: secrets.NewPlaintext([]byte("s")), CAPEM: string(x.idp.CAPEM())})
	require.True(t, errors.As(err, &de))
	assert.Contains(t, []string{"status", "issuer_mismatch"}, de.Cause)
}

// O-13, R42 row 24.
func TestAdminMappingRefusedWhileOff(t *testing.T) {
	x := newHarness(t)
	_, err := x.svc.CreateMapping(x.ctx, x.admin, x.prov.ID, "admins", rbac.Admin)
	assert.ErrorIs(t, err, oidc.ErrAdminMappingDisabled)
	assert.Equal(t, 1, x.count(t, `SELECT count(*) FROM audit_log WHERE action = 'sso.mapping.denied'`))
	_, err = x.svc.CreateMapping(x.ctx, x.admin, x.prov.ID, " ", rbac.Operator)
	var v validate.Errors
	assert.True(t, errors.As(err, &v), "no all-users mapping")
	set, err := x.svc.SaveSettings(x.ctx, x.admin, 0, true)
	require.NoError(t, err)
	m, err := x.svc.CreateMapping(x.ctx, x.admin, x.prov.ID, "admins", rbac.Admin)
	require.NoError(t, err)
	_, err = x.svc.SaveSettings(x.ctx, x.admin, set.Version, false)
	assert.ErrorIs(t, err, oidc.ErrAdminMappingsExist)
	require.NoError(t, x.svc.DeleteMapping(x.ctx, x.admin, m.ID))
	_, err = x.svc.SaveSettings(x.ctx, x.admin, set.Version, false)
	require.NoError(t, err)
	assert.Equal(t, 1, x.count(t, `SELECT count(*) FROM audit_log WHERE action = 'sso.admin_role_disallowed'`))
}

func TestProviderLimitsAndDeletion(t *testing.T) {
	x := newHarness(t)
	x.mapGroup(t, "ops", rbac.Operator)
	x.idp.NextLogin(fakeidp.Login{Subject: "u1", Username: "ada", Groups: []string{"ops"}})
	_, err := x.login(t, "/")
	require.NoError(t, err)
	err = x.svc.DeleteProvider(x.ctx, x.admin, x.prov.ID, x.prov.Version)
	assert.ErrorIs(t, err, oidc.ErrProviderInUse)
	p, err := x.svc.UpdateProvider(x.ctx, x.admin, x.prov.ID, x.prov.Version, oidc.ProviderPatch{Enabled: ptrBool(false)})
	require.NoError(t, err)
	assert.False(t, p.Enabled)
	_, err = x.svc.UpdateProvider(x.ctx, x.admin, x.prov.ID, x.prov.Version, oidc.ProviderPatch{Enabled: ptrBool(true)})
	assert.ErrorIs(t, err, oidc.ErrVersion)
	public, err := x.svc.PublicProviders(x.ctx)
	require.NoError(t, err)
	assert.Empty(t, public, "a disabled provider is not offered on the sign-in page")
}

func ptrBool(v bool) *bool { return &v }
```

`internal/auth/oidc/negative_integration_test.go` — the O-suite at service level; every refusal is checked by `refused`:

```go
//go:build integration

package oidc_test

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/auth/oidc"
	"alice/internal/rbac"
	"alice/internal/testutil/fakeidp"
)

// refused: a failed sign-in (§25.5): the reason, one more auth.oidc.denied row, and no session at all.
func (x *harness) refused(t *testing.T, want string, run func() error) {
	t.Helper()
	sessions := x.count(t, `SELECT count(*) FROM sessions`)
	denied := x.count(t, `SELECT count(*) FROM audit_log WHERE action = 'auth.oidc.denied'`)
	err := run()
	assert.Equal(t, want, reasonOf(err), "%v", err)
	assert.Equal(t, sessions, x.count(t, `SELECT count(*) FROM sessions`), "no session")
	assert.Equal(t, denied+1, x.count(t, `SELECT count(*) FROM audit_log WHERE action = 'auth.oidc.denied'`))
}

func (x *harness) ready(t *testing.T) {
	t.Helper()
	x.mapGroup(t, "ops", rbac.Operator)
	x.idp.NextLogin(fakeidp.Login{Subject: "u1", Username: "ada", Email: "ada@example.com", Groups: []string{"ops"}})
}

func TestGoodLoginGivesTheMappedRole(t *testing.T) {
	x := newHarness(t)
	x.ready(t)
	c, err := x.login(t, "/certificates?expiry=30")
	require.NoError(t, err)
	assert.Equal(t, "/certificates?expiry=30", c.Next)
	pr, err := x.auth.Authenticate(x.ctx, c.Session.Token)
	require.NoError(t, err)
	assert.Equal(t, rbac.Operator, pr.Role)
	assert.Contains(t, x.idp.LastTokenForm(), "code_verifier", "O-04: the verifier is always sent")
}

func TestO01Signatures(t *testing.T) {
	x := newHarness(t)
	x.ready(t)
	for _, f := range []fakeidp.Fault{{Alg: "none"}, {Alg: "HS256"}, {OtherKey: true}, {UnknownKid: true}} {
		x.idp.SetFault(f)
		x.refused(t, "login_invalid", func() error { _, err := x.login(t, "/"); return err })
	}
}

func TestO02TimesIssuerAudience(t *testing.T) {
	x := newHarness(t)
	x.ready(t)
	for _, f := range []fakeidp.Fault{{Issuer: "https://evil.example"}, {Audience: []string{"someone-else"}},
		{Audience: []string{x.idp.ClientID(), "other"}}, {ExpIn: -2 * time.Minute}, {IatOffset: 2 * time.Minute},
		{NbfOffset: 2 * time.Minute}} {
		x.idp.SetFault(f)
		x.refused(t, "login_invalid", func() error { _, err := x.login(t, "/"); return err })
	}
}

func TestO03StateNonceAndCodeReplay(t *testing.T) {
	x := newHarness(t)
	x.ready(t)
	wrong := "n-wrong"
	for _, f := range []fakeidp.Fault{{Nonce: &wrong}, {OmitNonce: true}} {
		x.idp.SetFault(f)
		x.refused(t, "login_invalid", func() error { _, err := x.login(t, "/"); return err })
	}
	x.idp.SetFault(fakeidp.Fault{})
	b, err := x.svc.Begin(x.ctx, oidc.BeginInput{ProviderID: x.prov.ID, Next: "/"})
	require.NoError(t, err)
	cb, err := x.idp.Authorize(b.AuthorizeURL)
	require.NoError(t, err)
	u, _ := url.Parse(cb)
	q := u.Query()
	x.refused(t, "login_expired", func() error { _, err := x.svc.Complete(x.ctx, x.prov.ID, q, "other-browser", meta); return err })
	x.refused(t, "login_expired", func() error { _, err := x.svc.Complete(x.ctx, x.prov.ID, q, b.Binding, meta); return err })
	missing := url.Values{"code": q["code"]}
	x.refused(t, "login_expired", func() error { _, err := x.svc.Complete(x.ctx, x.prov.ID, missing, b.Binding, meta); return err })
	// An authorization code that was used once is refused when replayed under a fresh state.
	b1, err := x.svc.Begin(x.ctx, oidc.BeginInput{ProviderID: x.prov.ID, Next: "/"})
	require.NoError(t, err)
	cb1, err := x.idp.Authorize(b1.AuthorizeURL)
	require.NoError(t, err)
	u1, _ := url.Parse(cb1)
	_, err = x.svc.Complete(x.ctx, x.prov.ID, u1.Query(), b1.Binding, meta)
	require.NoError(t, err)
	b2, err := x.svc.Begin(x.ctx, oidc.BeginInput{ProviderID: x.prov.ID, Next: "/"})
	require.NoError(t, err)
	replay := url.Values{"code": u1.Query()["code"], "state": {mustState(t, b2.AuthorizeURL)}}
	x.refused(t, "login_invalid", func() error { _, err := x.svc.Complete(x.ctx, x.prov.ID, replay, b2.Binding, meta); return err })
	// A state older than 10 minutes is refused.
	b3, err := x.svc.Begin(x.ctx, oidc.BeginInput{ProviderID: x.prov.ID, Next: "/"})
	require.NoError(t, err)
	cb3, err := x.idp.Authorize(b3.AuthorizeURL)
	require.NoError(t, err)
	x.clk.Advance(oidc.StateLifetime + time.Second)
	u3, _ := url.Parse(cb3)
	x.refused(t, "login_expired", func() error { _, err := x.svc.Complete(x.ctx, x.prov.ID, u3.Query(), b3.Binding, meta); return err })
}

func mustState(t *testing.T, authorizeURL string) string {
	t.Helper()
	u, err := url.Parse(authorizeURL)
	require.NoError(t, err)
	return u.Query().Get("state")
}

func TestO04PKCE(t *testing.T) {
	x := newHarness(t)
	x.ready(t)
	b, err := x.svc.Begin(x.ctx, oidc.BeginInput{ProviderID: x.prov.ID, Next: "/"})
	require.NoError(t, err)
	au, _ := url.Parse(b.AuthorizeURL)
	assert.Equal(t, "S256", au.Query().Get("code_challenge_method"))
	assert.NotEmpty(t, au.Query().Get("code_challenge"))
	cb, err := x.idp.Authorize(b.AuthorizeURL)
	require.NoError(t, err)
	_, err = x.d.Owner.Exec(x.ctx, `UPDATE oidc_login_states SET code_verifier = repeat('w', 43)`) // a wrong verifier
	require.NoError(t, err)
	u, _ := url.Parse(cb)
	x.refused(t, "login_invalid", func() error { _, err := x.svc.Complete(x.ctx, x.prov.ID, u.Query(), b.Binding, meta); return err })
}

func TestO05RedirectAndNext(t *testing.T) {
	x := newHarness(t)
	x.ready(t)
	c, err := x.login(t, "https://evil.example/steal")
	require.NoError(t, err)
	assert.Equal(t, "/", c.Next, "next never leaves Alice")
	x.idp.SetFault(fakeidp.Fault{AuthorizeError: "invalid_request"})
	x.refused(t, "idp_error", func() error { _, err := x.login(t, "/"); return err })
	x.idp.SetFault(fakeidp.Fault{})
	other, err := x.svc.Begin(x.ctx, oidc.BeginInput{ProviderID: x.prov.ID, Next: "/"})
	require.NoError(t, err)
	_, err = x.idp.Authorize(strings.Replace(other.AuthorizeURL, url.QueryEscape(publicURL), url.QueryEscape("https://evil.example"), 1))
	assert.Error(t, err, "the provider refuses a redirect URI it does not know")
}

func TestO06NoMappedGroup(t *testing.T) {
	x := newHarness(t)
	x.mapGroup(t, "ops", rbac.Operator)
	x.idp.NextLogin(fakeidp.Login{Subject: "u1", Username: "ada", Groups: []string{"everyone"}})
	x.refused(t, "no_access", func() error { _, err := x.login(t, "/"); return err })
	assert.Zero(t, x.count(t, `SELECT count(*) FROM users`), "no user is created with any role")
}

func TestO07Overage(t *testing.T) {
	x := newHarness(t)
	x.ready(t)
	x.idp.SetFault(fakeidp.Fault{Overage: true})
	x.refused(t, "groups_overage", func() error { _, err := x.login(t, "/"); return err })
}

func TestO08GroupRemovedEndsSessions(t *testing.T) {
	x := newHarness(t)
	x.ready(t)
	c, err := x.login(t, "/")
	require.NoError(t, err)
	x.idp.NextLogin(fakeidp.Login{Subject: "u1", Username: "ada", Groups: []string{"none"}})
	x.refused(t, "no_access", func() error { _, err := x.login(t, "/"); return err })
	_, err = x.auth.Authenticate(x.ctx, c.Session.Token)
	assert.Error(t, err, "the earlier session ended")
}

func TestO09MatchBySubjectNotEmail(t *testing.T) {
	x := newHarness(t)
	x.ready(t)
	c1, err := x.login(t, "/")
	require.NoError(t, err)
	x.idp.NextLogin(fakeidp.Login{Subject: "u1", Username: "ada", Email: "changed@example.com", Groups: []string{"ops"}})
	c2, err := x.login(t, "/")
	require.NoError(t, err)
	p1, _ := x.auth.Authenticate(x.ctx, c1.Session.Token)
	p2, _ := x.auth.Authenticate(x.ctx, c2.Session.Token)
	assert.Equal(t, p1.UserID, p2.UserID)
	x.idp.NextLogin(fakeidp.Login{Subject: "u2", Username: "mallory", Email: "changed@example.com", Groups: []string{"ops"}})
	c3, err := x.login(t, "/")
	require.NoError(t, err)
	p3, _ := x.auth.Authenticate(x.ctx, c3.Session.Token)
	assert.NotEqual(t, p1.UserID, p3.UserID, "the same e-mail under another subject is another user")
}

func TestO10NoLinkToLocalAccounts(t *testing.T) {
	x := newHarness(t)
	x.mapGroup(t, "ops", rbac.Operator)
	_, err := x.d.Owner.Exec(x.ctx, `INSERT INTO users (id, username, display_name, email, password_hash, role, created_at, updated_at)
VALUES (gen_random_uuid(), 'ada', 'Ada', 'ada@example.com', '$argon2id$x', 'admin', now(), now())`)
	require.NoError(t, err)
	x.idp.NextLogin(fakeidp.Login{Subject: "u1", Username: "ada", Email: "ada@example.com", Groups: []string{"ops"}})
	x.refused(t, "email_in_use", func() error { _, err := x.login(t, "/"); return err })
}

func TestO11IdPDownAndKeyRotation(t *testing.T) {
	x := newHarness(t)
	x.ready(t)
	_, err := x.login(t, "/")
	require.NoError(t, err)
	x.idp.RotateKey()
	x.clk.Advance(oidc.JWKSRefetchEvery)
	_, err = x.login(t, "/")
	require.NoError(t, err, "an unknown kid after the rotation is fetched once")
	b, err := x.svc.Begin(x.ctx, oidc.BeginInput{ProviderID: x.prov.ID, Next: "/"})
	require.NoError(t, err)
	cb, err := x.idp.Authorize(b.AuthorizeURL)
	require.NoError(t, err)
	x.idp.Down()
	u, _ := url.Parse(cb)
	x.refused(t, "idp_unreachable", func() error { _, err := x.svc.Complete(x.ctx, x.prov.ID, u.Query(), b.Binding, meta); return err })
}

// O-14: SSO users need no local MFA; nothing of the callback reaches a local account.
func TestO14LocalMFANotBypassed(t *testing.T) {
	x := newHarness(t)
	x.ready(t)
	_, err := x.d.Owner.Exec(x.ctx, `INSERT INTO users (id, username, display_name, email, password_hash, role, created_at, updated_at)
VALUES (gen_random_uuid(), 'root-admin', 'Root', '', '$argon2id$x', 'admin', now(), now())`)
	require.NoError(t, err)
	x.idp.NextLogin(fakeidp.Login{Subject: "root-admin", Username: "root-admin", Groups: []string{"ops"}})
	c, err := x.login(t, "/")
	require.NoError(t, err)
	pr, err := x.auth.Authenticate(x.ctx, c.Session.Token)
	require.NoError(t, err)
	assert.Equal(t, "oidc", pr.AuthSource)
	assert.Equal(t, rbac.Operator, pr.Role, "a new SSO user, never the local Administrator")
	assert.Zero(t, x.count(t, `SELECT count(*) FROM sessions s JOIN users u ON u.id = s.user_id WHERE u.auth_source = 'local'`),
		"no session of a local account exists")
}

func TestStepUpViaIdP(t *testing.T) {
	x := newHarness(t)
	x.ready(t)
	c, err := x.login(t, "/")
	require.NoError(t, err)
	pr, err := x.auth.Authenticate(x.ctx, c.Session.Token)
	require.NoError(t, err)
	stepup := func() (oidc.Completion, error) {
		b, err := x.svc.Begin(x.ctx, oidc.BeginInput{StepUp: true, SessionHash: pr.SessionHash, UserID: pr.UserID, Next: "/settings"})
		require.NoError(t, err)
		au, _ := url.Parse(b.AuthorizeURL)
		assert.Equal(t, "login", au.Query().Get("prompt"))
		assert.Equal(t, "0", au.Query().Get("max_age"))
		cb, err := x.idp.Authorize(b.AuthorizeURL)
		require.NoError(t, err)
		u, _ := url.Parse(cb)
		return x.svc.Complete(x.ctx, x.prov.ID, u.Query(), b.Binding, meta)
	}
	x.idp.SetFault(fakeidp.Fault{AuthTimeAgo: 10 * time.Minute})
	x.refused(t, "login_invalid", func() error { _, err := stepup(); return err })
	x.idp.SetFault(fakeidp.Fault{})
	done, err := stepup()
	require.NoError(t, err)
	assert.True(t, done.StepUp)
	assert.Equal(t, "/settings", done.Next)
}

func TestPruneStates(t *testing.T) {
	x := newHarness(t)
	_, err := x.svc.Begin(x.ctx, oidc.BeginInput{ProviderID: x.prov.ID, Next: "/"})
	require.NoError(t, err)
	x.clk.Advance(oidc.StateLifetime)
	n, err := x.svc.PruneStates(x.ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
}
```



- [ ] **Step 3: Run the tests to verify they fail** (Docker: testcontainers)

Run: `go test ./internal/auth/oidc/ && go test -tags integration ./internal/auth/oidc/`
Expected: FAIL — no non-test Go files.

- [ ] **Step 4: Write the implementation**

`internal/auth/oidc/httpclient.go`:

```go
package oidc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"

	"alice/internal/platform/netaddr"
)

var errTooLarge = errors.New("oidc: the identity provider's answer is too large")

// httpClient is the client of one provider (SEC-013, A-14, R42 row 11): TLS 1.2+, the system roots plus the
// provider's CA bundle, every connection through netaddr, no proxy, no redirect, a 10-second budget, and answers cut at
// MaxResponseBytes.
func (s *Service) httpClient(caPEM string) (*http.Client, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	if caPEM != "" && !roots.AppendCertsFromPEM([]byte(caPEM)) {
		return nil, errCABundle
	}
	dial := s.dial
	if dial == nil {
		dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return netaddr.DialContext(ctx, &net.Dialer{Timeout: HTTPTimeout}, network, addr)
		}
	}
	tr := &http.Transport{DialContext: dial, Proxy: nil, ForceAttemptHTTP2: true, TLSHandshakeTimeout: HTTPTimeout,
		ResponseHeaderTimeout: HTTPTimeout, MaxResponseHeaderBytes: 64 << 10,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}}
	return limitedClient(&http.Client{Transport: tr, Timeout: HTTPTimeout}), nil
}

// limitedClient refuses redirects and bounds every answer body.
func limitedClient(c *http.Client) *http.Client {
	next := c.Transport
	if next == nil {
		next = http.DefaultTransport
	}
	out := *c
	out.Transport = limitTransport{next: next}
	out.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &out
}

type limitTransport struct{ next http.RoundTripper }

func (l limitTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	res, err := l.next.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	res.Body = &limitedBody{r: io.LimitReader(res.Body, MaxResponseBytes+1), c: res.Body}
	return res, nil
}

type limitedBody struct {
	r io.Reader
	c io.Closer
	n int64
}

func (b *limitedBody) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	b.n += int64(n)
	if b.n > MaxResponseBytes {
		return 0, errTooLarge
	}
	return n, err
}

func (b *limitedBody) Close() error { return b.c.Close() }
```

`internal/auth/oidc/keyset.go`:

```go
package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"alice/internal/platform/clock"
)

const maxKeys = 50

var errSignature = errors.New("oidc: the ID token's signature does not verify")

var allowedAlgs = []jose.SignatureAlgorithm{jose.RS256, jose.ES256, jose.PS256}

// keySet is a bounded JWKS cache that implements go-oidc's KeySet (SEC-012, O-01, O-11): compact JWS only, signed
// with RS256, ES256 or PS256 by a public key of the provider's JWKS; an unknown key ID refetches the JWKS at most once
// per JWKSRefetchEvery; the JWKS is at most MaxResponseBytes (the client's bound) and maxKeys keys.
type keySet struct {
	client *http.Client
	url    string
	clock  clock.Clock

	mu      sync.Mutex
	keys    []jose.JSONWebKey
	fetched time.Time
}

func newKeySet(client *http.Client, url string, clk clock.Clock) *keySet {
	return &keySet{client: client, url: url, clock: clk}
}

// VerifySignature returns the payload of jwt when one of the provider's keys verifies it.
func (k *keySet) VerifySignature(ctx context.Context, jwt string) ([]byte, error) {
	jws, err := jose.ParseSignedCompact(jwt, allowedAlgs)
	if err != nil || len(jws.Signatures) != 1 {
		return nil, errSignature
	}
	keys, err := k.keysFor(ctx, jws.Signatures[0].Header.KeyID)
	if err != nil {
		return nil, err
	}
	for _, key := range keys {
		if payload, err := jws.Verify(key.Key); err == nil {
			return payload, nil
		}
	}
	return nil, errSignature
}

func match(keys []jose.JSONWebKey, kid string) []jose.JSONWebKey {
	var out []jose.JSONWebKey
	for _, key := range keys {
		if kid == "" || key.KeyID == kid {
			out = append(out, key)
		}
	}
	return out
}

func (k *keySet) keysFor(ctx context.Context, kid string) ([]jose.JSONWebKey, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if m := match(k.keys, kid); len(m) > 0 {
		return m, nil
	}
	now := k.clock.Now()
	if !k.fetched.IsZero() && now.Sub(k.fetched) < JWKSRefetchEvery {
		return nil, errSignature
	}
	k.fetched = now
	keys, err := k.fetch(ctx)
	if err != nil {
		return nil, err
	}
	k.keys = keys
	if m := match(keys, kid); len(m) > 0 {
		return m, nil
	}
	return nil, errSignature
}

func (k *keySet) fetch(ctx context.Context) ([]jose.JSONWebKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.url, nil)
	if err != nil {
		return nil, err
	}
	res, err := k.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc: read the key set: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc: the key set answered %d", res.StatusCode)
	}
	var set jose.JSONWebKeySet
	if err := json.NewDecoder(res.Body).Decode(&set); err != nil {
		return nil, fmt.Errorf("oidc: the key set is not valid: %w", err)
	}
	if len(set.Keys) > maxKeys {
		return nil, errors.New("oidc: the key set has too many keys")
	}
	var keys []jose.JSONWebKey
	for _, key := range set.Keys {
		if key.Valid() && key.IsPublic() && (key.Use == "" || key.Use == "sig") {
			keys = append(keys, key)
		}
	}
	return keys, nil
}
```

(If `JSONWebKey.IsPublic` does not exist in go-jose v4.1.5, check the key type instead: `*rsa.PublicKey`, `*ecdsa.PublicKey` or `ed25519.PublicKey`.)

`internal/auth/oidc/discovery.go`: `discover(ctx, issuer, caPEM) (Endpoints, error)`: `httpClient(caPEM)` (`errCABundle` → `validate.Errors{ca_pem: validate.Pattern}`); `GET strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"`; a transport error is `DiscoveryError{"tls"}` when `errors.As` finds a `*tls.CertificateVerificationError`, `x509.UnknownAuthorityError` or `x509.HostnameError`, else `{"connect"}`; a status other than 200 `{"status"}`; a body that is not the JSON object `{issuer, authorization_endpoint, token_endpoint, jwks_uri}` `{"document"}`; `doc.Issuer != issuer` `{"issuer_mismatch"}`; an endpoint that fails `claims.ValidateIssuer` `{"not_https"}`; then one key set fetch (`newKeySet(...).fetch`) that must return at least one key, else `{"jwks"}`. Nothing of the provider's answer is kept in the error.

`internal/auth/oidc/providers.go`: the C11 methods. Validation (C13 rules) into `validate.Errors` with the JSON field names; `MaxProviders` → `ErrTooMany`; an enabled provider needs `general.public_url` (`ErrPublicURLMissing`); create: discovery, then one transaction (insert row, `PutSetting("sso.provider.<id>.client_secret", …)`, audit `sso.provider_created`); update: version check (`ErrVersion`), discovery again when `issuer_url` or `ca_pem` change, the secret replaced when given, audit `sso.provider_changed` (`client_auth_replaced` when the secret changed); refresh: discovery, endpoints updated, `version+1`, audit `sso.provider_refreshed`; delete: version check, `DELETE` (a foreign-key violation from `users.oidc_provider_id` → `ErrProviderInUse`), `DeleteSetting` of its secret, audit `sso.provider_deleted`. Every DTO's `RedirectURI` is `RedirectURI(general.public_url, id)` (`""` while the address is empty). The service keeps one `*keySet` per provider ID and version (a `sync.Map`), so the refetch bound holds across sign-ins.

`internal/auth/oidc/mappings.go`: `CreateMapping` validates with `claims.ValidateMapping(m, allowAdmin)`: `claims.ErrAdminNotAllowed` → audit `sso.mapping.denied` (`provider_id`, `group`, `role`, `reason` `admin_disabled`) in its own transaction and `ErrAdminMappingDisabled`; the other `claims` errors → `validate.Errors` on `group` or `role`; `MaxMappings` per provider → `ErrTooMany`; a duplicate group → `validate.Errors{group: validate.Duplicate}`; insert and audit `sso.mapping_created`. `DeleteMapping` audits `sso.mapping_deleted`. `Mappings` lists by group value.

`internal/auth/oidc/settings.go`: the key `AllowAdminKey` holds `{"allow": bool, "version": n}` (default off, version 0). `SaveSettings(ctx, a, version, allow)`: one transaction: version check; switching off while any mapping has role `admin` → `ErrAdminMappingsExist`; switching off calls `auth.DemoteSSOAdmins(ctx, tx, a)`; store `version+1`; audit `sso.admin_role_allowed` or `sso.admin_role_disallowed` (`demoted_count`, `ended_count`).

`internal/auth/oidc/login.go`:

```go
// Begin starts a sign-in (SEC-010, SEC-011): a 256-bit state, nonce and binding value, a PKCE S256 verifier, one
// oidc_login_states row holding the state's and the binding's SHA-256, and the provider's authorize URL. A step-up
// asks the provider for a fresh sign-in (prompt=login, max_age=0).
func (s *Service) Begin(ctx context.Context, in BeginInput) (Begin, error) {
	providerID := in.ProviderID
	if in.StepUp {
		if err := s.pool.QueryRow(ctx, `SELECT oidc_provider_id FROM users WHERE id = $1 AND auth_source = 'oidc'`, in.UserID).
			Scan(&providerID); err != nil {
			return Begin{}, auth.ErrNotSSOUser
		}
	}
	p, err := s.loadProvider(ctx, s.pool, providerID)
	if err != nil {
		return Begin{}, err
	}
	if !p.Enabled {
		return Begin{}, &LoginError{Reason: "provider_disabled"}
	}
	g, err := settings.GetGeneral(ctx, s.pool)
	if err != nil {
		return Begin{}, err
	}
	if g.PublicURL == "" {
		return Begin{}, ErrPublicURLMissing
	}
	state, nonce, binding := random32(), random32(), random32()
	verifier := oauth2.GenerateVerifier()
	purpose, session, user := "login", []byte(nil), any(nil)
	if in.StepUp {
		purpose, session, user = "stepup", in.SessionHash, in.UserID
	}
	now := s.clock.Now().UTC()
	if _, err := s.pool.Exec(ctx, `INSERT INTO oidc_login_states (state_hash, provider_id, binding_hash, nonce, code_verifier, purpose,
session_hash, user_id, next_path, created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		sum(state), p.ID, sum(binding), nonce, verifier, purpose, session, user, claims.SafeNext(in.Next), now, now.Add(StateLifetime)); err != nil {
		return Begin{}, fmt.Errorf("oidc: store the sign-in state: %w", err)
	}
	opts := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(verifier), gooidc.Nonce(nonce)}
	if in.StepUp {
		opts = append(opts, oauth2.SetAuthURLParam("prompt", "login"), oauth2.SetAuthURLParam("max_age", "0"))
	}
	return Begin{AuthorizeURL: s.oauthConfig(p, g.PublicURL, "").AuthCodeURL(state, opts...), Binding: binding}, nil
}
```

(`random32()` is 32 bytes from `crypto/rand` in base64url without padding — 43 characters, the CHECK of C2; `sum(v)` is SHA-256 of the string's bytes; `oauthConfig(p, publicURL, secret)` returns `oauth2.Config{ClientID, ClientSecret: secret, Endpoint: oauth2.Endpoint{AuthURL: p.Endpoints.Authorization, TokenURL: p.Endpoints.Token}, RedirectURL: RedirectURI(publicURL, p.ID), Scopes: p.Scopes}`.)

`Complete` follows the order of C11 exactly. The token exchange runs with `context.WithValue(ctx, oauth2.HTTPClient, client)`; a `*oauth2.RetrieveError` with a status of 500 or more, or any transport error, is `idp_unreachable`, another `RetrieveError` (`invalid_grant`, a wrong verifier, a replayed code) is `login_invalid`; the ID token is `tok.Extra("id_token").(string)` (absent → `login_invalid`). Verification: `gooidc.NewVerifier(p.IssuerURL, keySet, &gooidc.Config{ClientID: p.ClientID, SupportedSigningAlgs: SigningAlgs, SkipExpiryCheck: true}).Verify(ctx, raw)`, then `var payload json.RawMessage; idToken.Claims(&payload)`, `claims.Parse(payload)`, `claims.Validate(c, claims.Expect{Issuer: p.IssuerURL, ClientID: p.ClientID, Nonce: row.nonce, Now: s.clock.Now(), MaxAuthAge: StepUpMaxAge if step-up})`. The identity is `auth.OIDCIdentity{ProviderID: p.ID, Issuer: c.Issuer, Subject: c.Subject, Username: claims.Username(c), DisplayName: c.Name (else the user name), Email: c.Email}`. The client secret is opened with `GetSetting` for the exchange only and zeroed after it (the copy x/oauth2 keeps in its `Config` string cannot be cleared: known limitation, as P4-04). Every refusal calls `s.auth.RefuseOIDC(ctx, identity or {ProviderID, Issuer}, reason, m)` exactly once, logs at Info the closed reason and, for a token problem, the `claims.Reason` (never a claim value), and returns `&LoginError{Reason: reason}`.

`internal/auth/oidc/states.go`: `PruneStates(ctx)` = `DELETE FROM oidc_login_states WHERE expires_at <= $1` with the clock's now, returning the count.

`internal/auth/oidc/service.go`: the constants, errors and types of C11; `RedirectURI(publicURL, id)` = `strings.TrimSuffix(publicURL, "/") + fmt.Sprintf(CallbackPath, id)` (or `""` when `publicURL` is empty).

- [ ] **Step 5: Run the tests to verify they pass** (Docker: testcontainers)

Run: `go mod tidy && git diff --stat go.mod go.sum && go test -count=1 -race ./internal/auth/oidc/ && go test -count=1 -race -tags integration ./internal/auth/oidc/ && go test ./internal/archtest/`
Expected: `go.mod` gains the three requirements; `ok` for the unit and integration tests (every O-case refused with its reason, no session, one denied row each); `archtest` `ok`.

Run: `make lint && make vuln`
Expected: no findings; `go mod verify` "all modules verified"; govulncheck "No vulnerabilities found".

- [ ] **Step 6: Commit**

```bash
git add -- internal/auth/oidc
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(auth): OIDC SSO — providers fixed at configuration, bounded key set, PKCE and single-use state, group mappings, Admin switch" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- internal/auth/oidc go.mod go.sum
```

---

### Task 13: Jobs and wiring: `alerts.scan`, the mailer source in `serve`, the env import, services, `POST /test/seed/dashboard`, reset, `E2E_SYMBOLS`

**Files:**
- Modify: `internal/jobs/types.go` (`AlertsScan`)
- Modify: `cmd/alice/services.go` (`services.{notifySettings, alerts, reports, oidc}`, `buildServices`, `buildSender` uses `Source`, `newMailer` removed, `buildScheduler` adds `alerts.scan` and prunes sign-in states in `maintenance.cleanup`), `cmd/alice/wiring.go` (`periodicTypes`), `cmd/alice/main.go` (the env import before the scheduler starts; `newAPIDeps` fills the new `api.Deps` fields of Task 14 — until Task 14 lands they are set in `newAPIDeps` only when the fields exist, so this task adds them in Task 14's commit if Task 14 is not yet merged; see the note below)
- Create: `internal/testutil/seed/dashboard.go` (`DashboardAnswer`, `Dashboard`: C17's data set, shared by the e2e endpoint and the API suite of Task 16)
- Modify: `cmd/alice/testapi_e2e.go` (`alertsScanEvery`, `resetSQL`, `POST /test/seed/dashboard`, `seedDashboardHandler`, `serveSeedDashboard`), `cmd/alice/testapi_release.go` (`alertsScanEvery = alerts.ScanEvery`)
- Modify: `cmd/alice/wiring_test.go`, `cmd/alice/testapi_e2e_test.go`; Create: `cmd/alice/seed_e2e_integration_test.go`
- Modify: `Makefile` (`E2E_SYMBOLS` gains `serveSeedDashboard`; `release-symcheck` also fails when the release build links any `alice/internal/testutil/` symbol)

**Interfaces:**
- Consumes: Tasks 6–12 (`notify.NewSettings`, `Settings.ImportEnv`, `Sender.Source`, `alerts.New`, `alerts.ScanEvery`, `reports.New`, `oidc.New`, `oidc.Service.PruneStates`, `auth.Config.Notifier`), `seed.*` (Tasks 8–9), C17.
- Produces: a wired server; the periodic type `alerts.scan`; `seed.{Dashboard, DashboardAnswer, ServerFilter}`; the e2e endpoint `POST /test/seed/dashboard` (body `{}`; answer C17's JSON; 409 `{"error": "no database"}` without one).

Note on `api.Deps`: Task 14 adds `Deps.Settings`, `Deps.Alerts`, `Deps.Reports`, and Task 15 `Deps.SSO`; this task builds the services and keeps them on `services`; Tasks 14 and 15 each add the one line of `newAPIDeps` that passes their service (they own `cmd/alice/main.go`'s `newAPIDeps` for that line only, after this task is committed).

- [ ] **Step 1: Write the failing tests**

`cmd/alice/wiring_test.go`, in `TestCheckWiringRefusesAnIncompleteProduct`'s `noSweep` case:

```go
	assert.Contains(t, err.Error(), "periodic job type alerts.scan is not scheduled")
```

and a new test:

```go
// Phase 7: the expiry scan runs in every license state (class always), every 15 minutes in a release build.
func TestAlertsScanIsWired(t *testing.T) {
	assert.Equal(t, license.ClassAlways, jobs.AlertsScan.Class)
	assert.Contains(t, periodicTypes, jobs.AlertsScan)
	svc := wiringServices(t)
	sched := buildScheduler(svc, nil, clock.Real{}, slog.New(slog.DiscardHandler))
	assert.True(t, sched.Schedules(jobs.AlertsScan))
}
```

`cmd/alice/testapi_e2e_test.go` (`//go:build e2e`):

```go
func TestE2EBuildNeverTicksTheAlertScan(t *testing.T) {
	assert.Greater(t, alertsScanEvery, 50*365*24*time.Hour, "journeys run alerts.scan with POST /test/scheduler/run")
}

func TestSeedDashboardEndpoint(t *testing.T) {
	answer := seed.DashboardAnswer{Certificates: map[string]int{"monitored": 8}}
	h := seedDashboardHandler(func(context.Context) (seed.DashboardAnswer, error) { return answer, nil }, slog.New(slog.DiscardHandler))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/test/seed/dashboard", strings.NewReader(`{}`))
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"certificates":{"monitored":8},"targets":null,"deployments":null,"expiring_30":null,"server_filter":null}`, rec.Body.String())
	h = seedDashboardHandler(func(context.Context) (seed.DashboardAnswer, error) { return seed.DashboardAnswer{}, errNoTestDatabase },
		slog.New(slog.DiscardHandler))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/test/seed/dashboard", strings.NewReader(`{}`)))
	assert.Equal(t, http.StatusConflict, rec.Code)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/test/seed/dashboard", strings.NewReader(`{"x":1}`)))
	assert.Equal(t, http.StatusBadRequest, rec.Code, "the body is exactly {}")
}
```

(`TestResetSQLCoversPhase6Tables` already walks every `CREATE TABLE` of every migration: it fails until `resetSQL` lists the six Phase 7 tables — the expected red.)

`cmd/alice/seed_e2e_integration_test.go`:

```go
//go:build e2e && integration

package main

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/alerts"
	"alice/internal/audit"
	"alice/internal/license"
	"alice/internal/platform/clock"
	"alice/internal/rbac"
	"alice/internal/reports"
	"alice/internal/testutil/pgtest"
	"alice/internal/testutil/seed"
)

func TestMain(m *testing.M) { os.Exit(pgtest.Main(m)) }

type activeLicense struct{}

func (activeLicense) Snapshot() license.Snapshot {
	return license.Snapshot{Eval: license.Evaluation{Phase: license.PhaseActive}}
}

// The seed's answer is what the dashboard and the list really show (C17), so the e2e journey asserts true numbers.
func TestSeedDashboardMatchesTheDashboard(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)
	got, err := seed.Dashboard(ctx, d.Owner, now)
	require.NoError(t, err)
	assert.Equal(t, map[string]int{"monitored": 8, "expired": 1, "within_7": 2, "within_30": 3, "within_60": 1}, got.Certificates)
	assert.Equal(t, map[string]int{"total": 3, "ok": 2, "host_key_changed": 1}, got.Targets)
	assert.Equal(t, map[string]int{"failed_7d": 1}, got.Deployments)
	clk := clock.NewFake(now)
	al := alerts.New(alerts.Config{Pool: d.App, Audit: audit.New(clk), Clock: clk, License: activeLicense{}})
	sum, err := reports.New(reports.Config{Pool: d.App, Clock: clk, Audit: audit.New(clk), Alerts: al, License: activeLicense{}}).
		Summary(ctx, reports.Viewer{Role: rbac.Operator})
	require.NoError(t, err)
	assert.Equal(t, alerts.Counts{Monitored: 8, Expired: 1, Within7: 2, Within30: 3, Within60: 1}, sum.Certificates)
	assert.Equal(t, 1, sum.Deployments.Failed7d)
	assert.Equal(t, []string{"old.seed.test", "api.seed.test", "www.seed.test", "shop.seed.test", "mail.seed.test", "intra.seed.test"}, got.Expiring30)
}
```

- [ ] **Step 2: Run the tests to verify they fail** (Docker: testcontainers for the last command)

Run: `go test ./cmd/alice/ && go test -tags 'e2e testlicense' ./cmd/alice/ && go test -tags 'integration e2e testlicense' -run TestSeedDashboardMatchesTheDashboard ./cmd/alice/`
Expected: FAIL — undefined `jobs.AlertsScan`, `alertsScanEvery`, `seedDashboardHandler`, `seed.Dashboard`; `resetSQL` lacks the Phase 7 tables.

- [ ] **Step 3: Write the implementation**

`internal/jobs/types.go`, after the Phase 6 block:

```go
// Phase 7 periodic task (R42 rows 3 and 5; §8.2 alerts.evaluate, §8.6 "not gated"): the expiry scan sends notices in
// every license state (in lock with the license note, L-28).
var AlertsScan = Register("alerts.scan", license.ClassAlways)
```

`cmd/alice/services.go`:

- `services` gains `notifySettings *notify.Settings`, `alerts *alerts.Service`, `reports *reports.Service`, `oidc *oidc.Service`.
- `buildServices`: `auth.NewService(auth.Config{…, Notifier: notify.AdminNotifier{Clock: clk}})`; then
  `svc.notifySettings = notify.NewSettings(notify.SettingsConfig{Pool: pool, Keyring: svc.keyring, Audit: svc.auditLog, Clock: clk, Catalog: catalog, Fallback: testMailer, Log: log})` (`buildServices` gains a `catalog *i18n.Catalog` parameter: `main` now loads the catalog before it calls `buildServices`, and every caller of `buildServices` in the tests passes `i18n.Load(locales.FS)`'s catalog), `svc.alerts = alerts.New(alerts.Config{Pool: pool, Audit: svc.auditLog, Clock: clk, License: svc.license, Notifier: notify.AdminNotifier{Clock: clk}, Log: log})`, `svc.reports = reports.New(reports.Config{Pool: pool, Clock: clk, Audit: svc.auditLog, License: svc.license, Alerts: svc.alerts, Delivery: svc.notifySettings, Inventory: svc.inventory})`, `svc.oidc = oidc.New(oidc.Config{Pool: pool, Keyring: svc.keyring, Audit: svc.auditLog, Clock: clk, Auth: svc.auth, Log: log})`.
- `buildSender(pool, svc, catalog, clk, log)` returns `&notify.Sender{Pool: pool, Source: svc.notifySettings, Catalog: catalog, Clock: clk, Log: log}`; `newMailer` and its `ALICE_SMTP_PASSWORD_FILE`/`ALICE_SMTP_CA_FILE` reading are deleted (the import reads them once).
- `buildScheduler` adds `jobs.Task{Type: jobs.AlertsScan, Every: alertsScanEvery, Run: func(ctx context.Context) error { _, err := svc.alerts.Scan(ctx); return err }}`, and `maintenance.cleanup` also runs `_, oidcErr := svc.oidc.PruneStates(ctx)` joined into its error.
- `cmd/alice/main.go`, after `svc.license.Start(ctx)`: `if _, err := svc.notifySettings.ImportEnv(ctx, cfg.SMTP, os.ReadFile); err != nil { return err }` — a failed import (an unreadable password file) stops the start with the error, as the Phase 2 mailer did.
- `cmd/alice/wiring.go`: `periodicTypes` gains `jobs.AlertsScan`.
- `cmd/alice/testapi_release.go`: `alertsScanEvery = alerts.ScanEvery`; `cmd/alice/testapi_e2e.go`: `alertsScanEvery = 100 * 365 * 24 * time.Hour`.

`cmd/alice/testapi_e2e.go`:

- `resetSQL`: `TRUNCATE users, …` gains `alerts, saved_views, oidc_login_states, oidc_group_mappings, oidc_providers, setting_secrets` (one statement, so the foreign keys between `users` and `oidc_providers` are no obstacle).
- The seed data set lives in `internal/testutil/seed/dashboard.go`:

```go
// DashboardAnswer is the dashboard the seeded data must show (C17).
type DashboardAnswer struct {
	Certificates map[string]int `json:"certificates"`
	Targets      map[string]int `json:"targets"`
	Deployments  map[string]int `json:"deployments"`
	Expiring30   []string       `json:"expiring_30"`
	ServerFilter *ServerFilter  `json:"server_filter"`
}

// ServerFilter is the certificate page filtered by one server and the 30-day window.
type ServerFilter struct {
	Target   string   `json:"target"`
	Expiry30 []string `json:"expiry_30"`
}

// Dashboard inserts C17's data set through the owner pool with now as the reference time and returns what the
// dashboard and the certificate list must show for it.
func Dashboard(ctx context.Context, owner *pgxpool.Pool, now time.Time) (DashboardAnswer, error) {
	day := 24 * time.Hour
	ids := map[string]uuid.UUID{}
	for _, t := range []struct{ name, status string }{{"seed-web-1", "ok"}, {"seed-web-2", "ok"}, {"seed-web-3", "host_key_changed"}} {
		id, err := Target(ctx, owner, t.name, "linux", t.status, nil)
		if err != nil {
			return DashboardAnswer{}, err
		}
		ids[t.name] = id
	}
	certs := []struct {
		cn     string
		left   time.Duration
		target string
		sites  []string
	}{
		{"www.seed.test", 7*day - time.Hour, "seed-web-1", []string{"www.seed.test"}}, {"api.seed.test", 5 * day, "seed-web-1", nil},
		{"old.seed.test", -2 * day, "seed-web-1", nil}, {"shop.seed.test", 20 * day, "seed-web-1", nil},
		{"mail.seed.test", 25 * day, "seed-web-2", nil}, {"docs.seed.test", 45 * day, "seed-web-2", nil},
		{"blog.seed.test", 200 * day, "seed-web-2", nil}, {"intra.seed.test", 29 * day, "seed-web-3", nil},
		{"spare.seed.test", 3 * day, "", nil},
	}
	var api uuid.UUID
	for _, c := range certs {
		var on []uuid.UUID
		if c.target != "" {
			on = []uuid.UUID{ids[c.target]}
		}
		id, err := Certificate(ctx, owner, c.cn, now.Add(c.left), on, c.sites...)
		if err != nil {
			return DashboardAnswer{}, err
		}
		if c.cn == "api.seed.test" {
			api = id
		}
	}
	for _, at := range []time.Time{now.Add(-day), now.Add(-8 * day)} {
		if _, err := Deployment(ctx, owner, api, ids["seed-web-1"], "failed", "ngx.reload_failed", at); err != nil {
			return DashboardAnswer{}, err
		}
	}
	return DashboardAnswer{
		Certificates: map[string]int{"monitored": 8, "expired": 1, "within_7": 2, "within_30": 3, "within_60": 1},
		Targets:      map[string]int{"total": 3, "ok": 2, "host_key_changed": 1},
		Deployments:  map[string]int{"failed_7d": 1},
		Expiring30:   []string{"old.seed.test", "api.seed.test", "www.seed.test", "shop.seed.test", "mail.seed.test", "intra.seed.test"},
		ServerFilter: &ServerFilter{Target: "seed-web-1", Expiry30: []string{"old.seed.test", "api.seed.test", "www.seed.test", "shop.seed.test"}},
	}, nil
}
```

- The endpoint in `cmd/alice/testapi_e2e.go`:

```go
func seedDashboardHandler(run func(context.Context) (seed.DashboardAnswer, error), log *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { serveSeedDashboard(w, r, run, log) })
}

// serveSeedDashboard is the body of seedDashboardHandler: a function of its own so make release-symcheck finds its
// symbol (E2E_SYMBOLS) in the e2e build and refuses it in a release build.
func serveSeedDashboard(w http.ResponseWriter, r *http.Request, run func(context.Context) (seed.DashboardAnswer, error), log *slog.Logger) {
	var body struct{}
	if !decodeTest(w, r, &body) {
		return
	}
	a, err := run(r.Context())
	switch {
	case errors.Is(err, errNoTestDatabase):
		writeTestJSON(w, http.StatusConflict, map[string]string{"error": "no database"})
	case err != nil:
		log.Error("test seed failed", "error_type", fmt.Sprintf("%T", err))
		writeTestJSON(w, http.StatusInternalServerError, map[string]string{"error": "the seed failed"})
	default:
		writeTestJSON(w, http.StatusOK, a)
	}
}
```

  registered in `testHandler` beside the rotation overlap endpoint:

```go
	mux.Handle("POST /test/seed/dashboard", seedDashboardHandler(func(ctx context.Context) (seed.DashboardAnswer, error) {
		if d.OwnerURL == "" {
			return seed.DashboardAnswer{}, errNoTestDatabase
		}
		pool, err := pgxpool.New(ctx, d.OwnerURL)
		if err != nil {
			return seed.DashboardAnswer{}, err
		}
		defer pool.Close()
		return seed.Dashboard(ctx, pool, e2eClock.Now().UTC())
	}, d.Log))
```

  (`decodeTest` refuses unknown keys, which makes `{"x":1}` a 400.)
- `Makefile`: `E2E_SYMBOLS := main\.(…|serveRotationOverlap|setPolicyOverlap|serveSeedDashboard)$$`; `release-symcheck` gains, after the symbol loop, `@! grep -E ' alice/internal/testutil/' bin/.symcheck-release.nm || { echo "release-symcheck: the release build links test-data code"; exit 1; }` (the seed package is imported only by the e2e build).

- [ ] **Step 4: Run the tests to verify they pass** (Docker: testcontainers for the integration run)

Run: `go test -count=1 -race ./cmd/alice/ ./internal/jobs/ && go test -count=1 -tags 'e2e testlicense' ./cmd/alice/ && go test -count=1 -tags 'integration e2e testlicense' -run 'TestSeedDashboardMatchesTheDashboard' ./cmd/alice/ && make release-symcheck`
Expected: `ok` ×3; `release-symcheck: ok` (the two new symbols are in the e2e build only; `internal/testutil/seed` is linked only into the e2e build).

Run: `go test -count=1 -tags integration ./cmd/alice/`
Expected: `ok` (the serve integration tests start a fully wired server; with no `ALICE_SMTP_*` nothing is imported).

Run: `make lint`
Expected: no findings.

- [ ] **Step 5: Commit**

```bash
git add -- cmd/alice/seed_e2e_integration_test.go internal/testutil/seed/dashboard.go
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(alice): wire alerts, reports, mail settings and SSO; alerts.scan every 15 minutes; e2e dashboard seed and reset" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- internal/jobs/types.go cmd/alice Makefile internal/testutil/seed/dashboard.go
```

---

### Task 14: API part 1: settings, notifications status, alerts, dashboard, views, exports; limits; codes, email texts, OpenAPI, authz

**Files:**
- Modify: `internal/api/server.go` (`Deps.Mail`, `Deps.Alerts`, `Deps.Reports`; the three interfaces below; `limitTestMail`, `limitExport` and their limiters; `apiRoutes` gains `settingsRoutes`, `dashboardRoutes`, `viewRoutes`, and the two export routes in the certificate and SSH key groups), `internal/api/guard.go` (`allowRate` cases)
- Create: `internal/api/settings_handlers.go`, `internal/api/dashboard_handlers.go`, `internal/api/views_handlers.go`, `internal/api/export_handlers.go`, `internal/api/phase7_dto.go`
- Modify: `internal/api/errors.go` (codes `ALC-NTF-0002..0009`, `ALC-RPT-0001..0003`, `ALC-USR-0003`; `errorMap` entries; `AllErrorCodes`), `internal/api/fakes_test.go` (`fakeMail`, `fakeAlerts`, `fakeReports`), `internal/api/authz_test.go` (`routeRuleViolations`: `/api/v1/dashboard`, `/api/v1/alerts`, `/api/v1/notifications` → `read`, `/api/v1/views` → `session`; `lockAvailable` gains `/api/v1/dashboard`, `/api/v1/alerts`, `/api/v1/views`, `/api/v1/notifications`)
- Create: `internal/api/phase7_handlers_test.go`, `internal/api/errors_phase7_test.go`
- Modify: `cmd/alice/main.go` (`newAPIDeps`: `Mail: svc.notifySettings, Alerts: svc.alerts, Reports: svc.reports`)
- Modify: `api/openapi.yaml` (operations and schemas of C13 for these routes), `docs/authz-matrix.md` (`make authz-doc`)
- Modify: `locales/common/en.json`, `locales/common/tr.json` (C15 texts for the NTF, RPT and USR codes; C14 texts for `alert.*` and `auth.lockout`), `internal/notify/render_test.go` (`TestAlertAndAuthTemplatesRenderInBothLanguages`)
- Modify: `docs/troubleshooting.md` (one section per new code of this task, in the existing format)

**Interfaces:**
- Consumes: C7, C8, C9 (Tasks 6–10), C10 (`auth.ErrSSOUser`), `auth.Principal.{Actor, Role, Locale, UserID, Kind, TokenID}`, `principalFrom`, `s.meta`, `etag`, `secretText`, `decodeExact`, `writeJSON`, `s.fail`, `pageLimit`.
- Produces: the C13 routes of this task, C15's NTF/RPT/USR codes, the email texts.

```go
// internal/api/server.go

// MailService is *notify.Settings.
type MailService interface {
	SMTP(ctx context.Context) (notify.SMTPSettings, bool, error)
	SaveSMTP(ctx context.Context, a audit.Actor, version int, in notify.SMTPInput) (notify.SMTPSettings, error)
	DeleteSMTP(ctx context.Context, a audit.Actor, version int) error
	TestMail(ctx context.Context, a audit.Actor, to, locale string) error
	Trust(ctx context.Context, a audit.Actor, version int, fingerprint string) (notify.SMTPSettings, error)
	Untrust(ctx context.Context, a audit.Actor, version int) (notify.SMTPSettings, error)
	Recipients(ctx context.Context) (notify.Recipients, error)
	SaveRecipients(ctx context.Context, a audit.Actor, version int, r notify.Recipients) (notify.Recipients, error)
	General(ctx context.Context) (settings.General, error)
	SaveGeneral(ctx context.Context, a audit.Actor, version int, g settings.General) (settings.General, error)
	Delivery(ctx context.Context) (notify.Delivery, error)
}

// AlertsService is *alerts.Service.
type AlertsService interface {
	Thresholds(ctx context.Context) (alerts.ThresholdSettings, error)
	SaveThresholds(ctx context.Context, a audit.Actor, version int, days []int) (alerts.ThresholdSettings, error)
}

// ReportsService is *reports.Service.
type ReportsService interface {
	Summary(ctx context.Context, v reports.Viewer) (reports.Summary, error)
	Expiring(ctx context.Context, days, limit int) ([]alerts.Item, error)
	Attention(ctx context.Context, v reports.Viewer) ([]reports.Condition, error)
	ExportCertificates(ctx context.Context, a audit.Actor, f inventory.CertificateFilter, w io.Writer) (int, error)
	ExportSSHKeys(ctx context.Context, a audit.Actor, f inventory.KeyFilter, w io.Writer) (int, error)
	Views(ctx context.Context, userID uuid.UUID, page string) ([]reports.View, error)
	CreateView(ctx context.Context, userID uuid.UUID, page, name string, query map[string]string) (reports.View, error)
	DeleteView(ctx context.Context, userID, id uuid.UUID) error
}
```

Settings versions: the settings routes accept `If-Match: "0"` for a value never saved (the existing `ifMatch` accepts 1 and up only), through a new helper:

```go
var settingsIfMatchRE = regexp.MustCompile(`^"(0|[1-9][0-9]{0,9})"$`)

// settingsVersion reads the strong If-Match of a settings change; "0" names "never saved" (C13).
func settingsVersion(r *http.Request) (int, bool) {
	m := settingsIfMatchRE.FindStringSubmatch(r.Header.Get("If-Match"))
	if m == nil {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	return n, err == nil
}
```

The test-mail handler (the most delicate of this task):

```go
// testMail sends a test e-mail now (owner step 1). Limited to 5 per minute per user (limitTestMail). An untrusted
// certificate answers ALC-NTF-0005 with the fingerprint, subject and expiry of the certificate the server presented,
// so the page can offer "Trust this certificate" (F-62); no other text of the mail server reaches the answer (F-63).
func (s *server) testMail(w http.ResponseWriter, r *http.Request) {
	var req struct {
		To string `json:"to"`
	}
	if !s.decodeExact(w, r, &req, maxActionBody, "to") {
		return
	}
	p := principalFrom(r.Context())
	err := s.deps.Mail.TestMail(r.Context(), p.Actor(s.meta(r)), req.To, p.Locale)
	var ce *notify.CertError
	if errors.As(err, &ce) {
		s.writeErrorWith(w, r, ErrSMTPUntrusted, map[string]string{"fingerprint": ce.Cert.Fingerprint, "subject": ce.Cert.Subject,
			"not_after": ce.Cert.NotAfter.UTC().Format(time.RFC3339)}, nil)
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"sent": true})
}
```

The SMTP `PUT` handler decodes `password` as `*secretText` (`decodeExact` keys `host`, `port`, `tls_mode`, `from`, `username`, `password`, `ca_pem`): absent → `nil` (keep); present → `secrets.NewPlaintext(*req.Password)` (an empty string → an empty plaintext: remove); `defer` zeroes the slice on every path.

The export handlers write through a writer that sets the CSV headers on the first byte, so an error before any byte is still a JSON error answer:

```go
// csvResponse sets the download headers when the first byte is written (R42 row 16): until then nothing is sent and a
// refusal (ALC-RPT-0001, a validation error) is an ordinary JSON error.
type csvResponse struct {
	w       http.ResponseWriter
	name    string
	started bool
}

func (c *csvResponse) Write(p []byte) (int, error) {
	if !c.started {
		c.started = true
		h := c.w.Header()
		h.Set("Content-Type", "text/csv; charset=utf-8")
		h.Set("Content-Disposition", `attachment; filename="`+c.name+`"`)
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		c.w.WriteHeader(http.StatusOK)
	}
	return c.w.Write(p)
}

func (s *server) exportCertificates(w http.ResponseWriter, r *http.Request) {
	f, ok := s.certificateFilter(w, r) // the list handler's query parsing, moved into a function both use; no cursor, no limit
	if !ok {
		return
	}
	out := &csvResponse{w: w, name: "alice-certificates-" + s.deps.Clock.Now().UTC().Format("2006-01-02") + ".csv"}
	if _, err := s.deps.Reports.ExportCertificates(r.Context(), principalFrom(r.Context()).Actor(s.meta(r)), f, out); err != nil {
		if out.started {
			s.deps.Log.Error("inventory export failed", errorAttrs(err)...)
			panic(http.ErrAbortHandler) // never end a cut file as if it were complete
		}
		s.fail(w, r, err)
	}
}
```

(`certificateFilter` refuses `cursor` and `limit` on the export route with `validate.Errors` — an export is never a page; `sshKeyFilter` likewise for `exportSSHKeys`.)

The dashboard handlers pass `reports.Viewer{UserID: p.UserID, Role: p.Role}`; the DTO builders of `phase7_dto.go` produce exactly the JSON of C13 (UTC times; nil sections as `null`; `license.phase` `""` for Operators). `GET /api/v1/notifications/status` answers `Delivery` for Administrators and `{"failing": false}` for every other role (the dashboard banner's source; R42 row 13).

`errors.go`: the codes of C15 (NTF, RPT, USR) as `ErrorCode` values beside their areas (`ErrSMTPUntrusted` is the variable name for `ALC-NTF-0005`); `errorMap`: `notify.ErrNotConfigured` → NTF-0002, `notify.ErrSMTPConnect` → 0003, `notify.ErrSMTPUntrusted` (before the TLS entry) → 0005, `notify.ErrSMTPTLS` → 0004, `notify.ErrSMTPAuth` → 0006, `notify.ErrSMTPRejected` → 0007, `notify.ErrCertNotSeen` → 0008, `notify.ErrAddressRefused` → 0009, `notify.ErrVersion` → the precondition code `ifMatch` mismatches already use, `reports.ErrTooLarge` → RPT-0001 (params `max` = `strconv.Itoa(reports.MaxExportRows)`), `reports.ErrViewLimit` → RPT-0002 (`max` = 50), `reports.ErrViewName` → RPT-0003, `reports.ErrNotFound` → the existing 404, `auth.ErrSSOUser` → USR-0003. Each new code is appended to `AllErrorCodes()`.

`locales/common/{en,tr}.json`: `errors.<reason>.title|cause|action` of C15 for the codes of this task; `email.alert.*` (nine templates) and `email.auth.lockout` of C14.

`docs/troubleshooting.md`: one section per new code of this task, in the format of the existing `ALC-KEY-0005` section (**Meaning**, **Likely cause**, **What to do**, the texts of C15 in full sentences).

- [ ] **Step 1: Write the failing tests**

`internal/api/errors_phase7_test.go` (as `errors_phase6_test.go`):

```go
package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var phase7Table = []struct {
	code, reason string
	status       int
	retry        bool
}{
	{"ALC-NTF-0002", "notify.smtp_not_configured", 409, false}, {"ALC-NTF-0003", "notify.smtp_connect", 502, true},
	{"ALC-NTF-0004", "notify.smtp_tls", 502, false}, {"ALC-NTF-0005", "notify.smtp_untrusted", 502, false},
	{"ALC-NTF-0006", "notify.smtp_auth", 502, false}, {"ALC-NTF-0007", "notify.smtp_rejected", 502, false},
	{"ALC-NTF-0008", "notify.certificate_not_seen", 409, false}, {"ALC-NTF-0009", "notify.smtp_address_refused", 409, false},
	{"ALC-RPT-0001", "export.too_large", 409, false}, {"ALC-RPT-0002", "views.limit_reached", 409, false},
	{"ALC-RPT-0003", "views.name_taken", 409, false}, {"ALC-USR-0003", "users.sso_user", 409, false},
}

func TestPhase7CodeTable(t *testing.T) {
	all := map[string]ErrorCode{}
	for _, c := range AllErrorCodes() {
		all[c.Code] = c
	}
	for _, row := range phase7Table {
		c, ok := all[row.code]
		if assert.True(t, ok, row.code) {
			assert.Equal(t, row.reason, c.Reason, row.code)
			assert.Equal(t, row.status, c.Status, row.code)
			assert.Equal(t, row.retry, c.Retryable, row.code)
			assert.Equal(t, c, codeForReason(row.reason), row.code)
		}
	}
}
```

(Task 15 appends its SSO rows to `phase7Table`.)

`internal/api/phase7_handlers_test.go` — unit, with the fakes; the server built as `sshDeps` builds it:

```go
package api

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/inventory"
	"alice/internal/license"
	"alice/internal/notify"
	"alice/internal/rbac"
	"alice/internal/reports"
)

func phase7Deps(t *testing.T) (Deps, *fakeMail, *fakeAlerts, *fakeReports) {
	t.Helper()
	d := testDeps(t, nil)
	fm, fa, fr := &fakeMail{}, &fakeAlerts{}, &fakeReports{}
	d.Mail, d.Alerts, d.Reports = fm, fa, fr
	return d, fm, fa, fr
}

// phase7Calls are the routes of this task with a body and headers the handler accepts.
func phase7Calls() map[string]routeCall {
	v := map[string]string{"If-Match": `"1"`}
	return map[string]routeCall{
		"GET /api/v1/dashboard/summary":                 {},
		"GET /api/v1/dashboard/expiring":                {},
		"GET /api/v1/alerts":                            {},
		"GET /api/v1/notifications/status":              {},
		"GET /api/v1/certificates/export":               {},
		"GET /api/v1/ssh-keys/export":                   {},
		"GET /api/v1/views":                             {},
		"POST /api/v1/views":                            {body: `{"page":"certificates","name":"x","query":{}}`},
		"DELETE /api/v1/views/{id}":                     {},
		"GET /api/v1/settings/smtp":                     {},
		"PUT /api/v1/settings/smtp":                     {body: `{"host":"smtp.example.com","port":587,"tls_mode":"starttls","from":"a@example.com","username":"","ca_pem":""}`, hdr: v},
		"DELETE /api/v1/settings/smtp":                  {hdr: v},
		"POST /api/v1/settings/smtp/actions/test":       {body: `{"to":"ops@example.com"}`},
		"POST /api/v1/settings/smtp/actions/trust":      {body: `{"fingerprint":"` + strings.Repeat("ab", 32) + `"}`, hdr: v},
		"POST /api/v1/settings/smtp/actions/untrust":    {hdr: v},
		"GET /api/v1/settings/notifications":            {},
		"PUT /api/v1/settings/notifications":            {body: `{"administrators":true,"addresses":[]}`, hdr: v},
		"GET /api/v1/settings/alerts":                   {},
		"PUT /api/v1/settings/alerts":                   {body: `{"thresholds_days":[30,7]}`, hdr: v},
		"GET /api/v1/settings/general":                  {},
		"PUT /api/v1/settings/general":                  {body: `{"public_url":"","retired_key_retention_days":30}`, hdr: v},
	}
}

// phase7Queries are the query strings a route needs to be accepted.
var phase7Queries = map[string]string{"GET /api/v1/views": "?page=certificates"}

// Review Focus 5: every Phase 7 route of this task, as every identity, in and out of lock: a refused request never
// reaches a service; an allowed one does; settings need an Administrator with step-up; exports and the dashboard work
// in lock.
func TestPhase7RoutesAuthz(t *testing.T) {
	calls := phase7Calls()
	for _, locked := range []bool{false, true} {
		d, fm, fa, fr := phase7Deps(t)
		fm.succeed()
		fa.succeed()
		fr.succeed()
		if locked {
			d.License.(*fakeLicense).set(license.ErrLocked)
		}
		s := newServer(d)
		h := s.handler(s.apiRoutes())
		seen := 0
		for _, rt := range s.apiRoutes() {
			key := rt.method + " " + rt.pattern
			c, ok := calls[key]
			if !ok {
				continue
			}
			seen++
			target := pathParamRE.ReplaceAllString(rt.pattern, uuid.NewString()) + phase7Queries[key]
			for _, id := range identities {
				(&Server{s: s}).ResetLimits()
				fm.reset()
				fa.reset()
				fr.reset()
				rec := callWith(h, rt.method, target, id, c.body, c.hdr)
				want := expectedMatrix[rt.perm][id]
				name := key + " as " + id
				switch {
				case want == allw:
					assert.Less(t, rec.Code, 300, "%s (locked %v): %s", name, locked, rec.Body.String())
				case want == step:
					assert.Equal(t, "ALC-AUTH-0003", decodeErr(t, rec).Error.Code, name)
				default:
					assert.Equal(t, want, rec.Code, name)
				}
				if want != allw {
					assert.Zero(t, fm.calls()+fa.calls()+fr.calls(), "a refused request has no side effect: %s", name)
				}
			}
		}
		assert.Equal(t, len(calls), seen, "every Phase 7 route of this task is in the table")
	}
}

func TestDashboardIsRoleFiltered(t *testing.T) {
	d, _, _, fr := phase7Deps(t)
	fr.succeed()
	s := newServer(d)
	h := s.handler(s.apiRoutes())
	rec := callWith(h, http.MethodGet, "/api/v1/dashboard/summary", "operator", "", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, rbac.Operator, fr.lastViewer.Role, "the viewer is the caller")
	rec = callWith(h, http.MethodGet, "/api/v1/notifications/status", "operator", "", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"failing":false}`, rec.Body.String(), "only Administrators see the delivery state")
	rec = callWith(h, http.MethodGet, "/api/v1/dashboard/expiring?days=0", "admin", "", nil)
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
}

// F-62 over HTTP: an untrusted certificate is a 502 with the certificate's facts and nothing of the server's text.
func TestTestMailAnswers(t *testing.T) {
	d, fm, _, _ := phase7Deps(t)
	s := newServer(d)
	h := s.handler(s.apiRoutes())
	fm.TestMailFn = func(context.Context, audit.Actor, string, string) error {
		return &notify.CertError{Cert: notify.CertInfo{Fingerprint: strings.Repeat("cd", 32), Subject: "CN=mail.example.com",
			NotAfter: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)}}
	}
	rec := callWith(h, http.MethodPost, "/api/v1/settings/smtp/actions/test", "admin-stepup", `{"to":"ops@example.com"}`, nil)
	require.Equal(t, http.StatusBadGateway, rec.Code)
	e := decodeErr(t, rec).Error
	assert.Equal(t, "ALC-NTF-0005", e.Code)
	assert.Equal(t, strings.Repeat("cd", 32), e.Params["fingerprint"])
	assert.Equal(t, "2027-01-01T00:00:00Z", e.Params["not_after"])
	fm.TestMailFn = func(context.Context, audit.Actor, string, string) error { return notify.ErrSMTPAuth }
	rec = callWith(h, http.MethodPost, "/api/v1/settings/smtp/actions/test", "admin-stepup", `{"to":"ops@example.com"}`, nil)
	assert.Equal(t, "ALC-NTF-0006", decodeErr(t, rec).Error.Code)
	for i := 0; i < 5; i++ {
		callWith(h, http.MethodPost, "/api/v1/settings/smtp/actions/test", "admin-stepup", `{"to":"ops@example.com"}`, nil)
	}
	rec = callWith(h, http.MethodPost, "/api/v1/settings/smtp/actions/test", "admin-stepup", `{"to":"ops@example.com"}`, nil)
	assert.Equal(t, http.StatusTooManyRequests, rec.Code, "5 per minute per user")
}

// Review Focus 3: the SMTP password is write-only and zeroed on every path; the answer says only has_password.
func TestSMTPPasswordIsWriteOnly(t *testing.T) {
	d, fm, _, _ := phase7Deps(t)
	s := newServer(d)
	h := s.handler(s.apiRoutes())
	var seen []byte
	onSecretBytes = func(b []byte) { seen = b }
	t.Cleanup(func() { onSecretBytes = nil })
	fm.SaveSMTPFn = func(_ context.Context, _ audit.Actor, _ int, in notify.SMTPInput) (notify.SMTPSettings, error) {
		require.NotNil(t, in.Password)
		assert.Equal(t, "CANARY-pw", string(in.Password.Bytes()))
		return notify.SMTPSettings{Host: "smtp.example.com", Port: 587, TLSMode: "starttls", From: "a@example.com", HasPassword: true, Version: 1}, nil
	}
	rec := callWith(h, http.MethodPut, "/api/v1/settings/smtp", "admin-stepup",
		`{"host":"smtp.example.com","port":587,"tls_mode":"starttls","from":"a@example.com","username":"u","password":"CANARY-pw","ca_pem":""}`,
		map[string]string{"If-Match": `"0"`})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, `"1"`, rec.Header().Get("ETag"))
	assert.NotContains(t, rec.Body.String(), "CANARY")
	assert.Contains(t, rec.Body.String(), `"has_password":true`)
	assert.Equal(t, make([]byte, len("CANARY-pw")), seen, "the password bytes were zeroed")
	rec = callWith(h, http.MethodPut, "/api/v1/settings/smtp", "admin-stepup", `{"host":"x","port":1,"tls_mode":"tls","from":"a@example.com","username":"","ca_pem":""}`, nil)
	assert.Equal(t, http.StatusPreconditionFailed, rec.Code, "a change needs If-Match")
	assert.Equal(t, "ALC-SYS-0008", decodeErr(t, rec).Error.Code)
}

func TestExportHandlerHeadersAndRefusal(t *testing.T) {
	d, _, _, fr := phase7Deps(t)
	s := newServer(d)
	h := s.handler(s.apiRoutes())
	fr.ExportCertificatesFn = func(_ context.Context, _ audit.Actor, f inventory.CertificateFilter, w io.Writer) (int, error) {
		assert.Equal(t, "30", f.Expiry)
		_, err := w.Write([]byte("\xEF\xBB\xBFid\n"))
		return 0, err
	}
	rec := callWith(h, http.MethodGet, "/api/v1/certificates/export?expiry=30", "auditor", "", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "text/csv; charset=utf-8", rec.Header().Get("Content-Type"))
	assert.Regexp(t, `^attachment; filename="alice-certificates-\d{4}-\d{2}-\d{2}\.csv"$`, rec.Header().Get("Content-Disposition"))
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	fr.ExportCertificatesFn = func(context.Context, audit.Actor, inventory.CertificateFilter, io.Writer) (int, error) {
		return 0, reports.ErrTooLarge
	}
	rec = callWith(h, http.MethodGet, "/api/v1/certificates/export", "alice_read_auditor", "", nil)
	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.Equal(t, "ALC-RPT-0001", decodeErr(t, rec).Error.Code)
	assert.Empty(t, rec.Header().Get("Content-Disposition"))
	rec = callWith(h, http.MethodGet, "/api/v1/certificates/export?cursor=abc", "admin", "", nil)
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code, "an export is never a page")
}
```

(`fakeMail`, `fakeAlerts` and `fakeReports` in `fakes_test.go` follow `fakeSSHKeys`: one `XxxFn` field per method of their interface, a `calls()` counter, `reset()`, `succeed()` setting every function to a harmless success, and `fakeReports.lastViewer` recording the last viewer.)

`internal/notify/render_test.go` gains:

```go
func TestAlertAndAuthTemplatesRenderInBothLanguages(t *testing.T) {
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	s := &notify.Sender{Catalog: cat}
	params := map[string]string{"name": "www.example.com", "vault": "prod-vault", "days": "7", "expires_at": "2026-12-01 09:00 UTC",
		"websites": "www.example.com, example.com", "servers": "web-01", "fingerprint": strings.Repeat("ab", 32), "count": "5",
		"username": "ada", "failed_logins": "10", "minutes": "15", "license_note": "true", "license_url": "/license"}
	for _, tpl := range append(alerts.Templates(), auth.Templates()...) {
		for _, lang := range []string{"en", "tr"} {
			m := s.Render("ada@example.com", tpl, lang, params)
			assert.NotContains(t, m.Subject, "{{", "%s %s", tpl, lang)
			assert.NotContains(t, m.Body, "{{", "%s %s", tpl, lang)
			assert.NotContains(t, m.Subject, "email.", "%s %s: the key itself means a missing text", tpl, lang)
			assert.NotContains(t, m.Subject, "\n")
		}
	}
	m := s.Render("ada@example.com", "alert.certificate_expiring", "en", params)
	assert.Equal(t, "Certificate expiring: www.example.com (days left: 7)", m.Subject)
	assert.Contains(t, m.Body, "Websites: www.example.com, example.com")
	assert.Contains(t, m.Body, "2026-12-01 09:00 UTC", "owner step 2: the website name and the date")
}
```

(Add the `strings`, `alerts` and `auth` imports.)

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/api/ ./internal/notify/`
Expected: FAIL — `Deps.Mail` undefined; routes 404; the code table and the templates' texts are missing; `errors_test.go` and `errors_catalogue_test.go` fail on the new codes without texts and troubleshooting sections.

- [ ] **Step 3: Write the implementation**

As specified above and in C13 (routes, permissions, classes, limits), C15 (codes and texts), C14 (email texts). Route lines, for example:

```go
{method: http.MethodGet, pattern: "/api/v1/dashboard/summary", perm: rbac.Read, handler: s.dashboardSummary},
{method: http.MethodGet, pattern: "/api/v1/certificates/export", perm: rbac.Read, limit: limitExport, handler: s.exportCertificates},
{method: http.MethodPost, pattern: "/api/v1/views", perm: rbac.Session, lic: license.ClassAlways, handler: s.createView},
{method: http.MethodPut, pattern: "/api/v1/settings/smtp", perm: rbac.SettingsManage, lic: license.ClassAlways, handler: s.putSMTP},
{method: http.MethodPost, pattern: "/api/v1/settings/smtp/actions/test", perm: rbac.SettingsManage, limit: limitTestMail, lic: license.ClassAlways, handler: s.testMail},
```

`allowRate`: `limitTestMail` as `limitDownload` (per user of a browser session, `s.testMail` limiter 5/min); `limitExport` per identity: `"u:" + UserID` for a session, `"t:" + TokenID` for a token (`s.export` limiter 10/min). Both limiters reset with `ResetLimits`.

`api/openapi.yaml`: every operation of this task with `operationId`, `summary`, `x-permission`, parameters, request schemas (`additionalProperties: false`; `password` `writeOnly: true`, `maxLength: 1024`), responses (`200` `text/csv` for the exports with the escaping rule in the description; `default: $ref: "#/components/responses/Error"`), and the schemas `DashboardSummary`, `ExpiringItem`, `Condition`, `Delivery`, `View`, `SMTP`, `Recipients`, `AlertSettings`, `GeneralSettings`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -count=1 -race ./internal/api/ ./internal/notify/ && make authz-doc && make i18n-check`
Expected: `ok`, `ok`; `docs/authz-matrix.md` regenerated with the new routes (commit it); the i18n check passes.

Run: `make lint`
Expected: no findings.

- [ ] **Step 5: Commit**

```bash
git add -- internal/api/settings_handlers.go internal/api/dashboard_handlers.go internal/api/views_handlers.go internal/api/export_handlers.go \
  internal/api/phase7_dto.go internal/api/phase7_handlers_test.go internal/api/errors_phase7_test.go
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(api): mail, recipients, alert and general settings; test mail; dashboard, alerts, saved views, CSV exports; ALC-NTF/RPT codes" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- internal/api internal/notify/render_test.go cmd/alice/main.go \
  api/openapi.yaml docs/authz-matrix.md docs/troubleshooting.md locales/common/en.json locales/common/tr.json
```

---

### Task 15: API part 2: `sso.manage`, SSO administration, the OIDC sign-in and step-up routes, cookies, codes, OpenAPI, authz, the A-06 exception

**Files:**
- Modify: `internal/rbac/rbac.go` (`SSOManage`), `internal/rbac/rbac_test.go`
- Modify: `internal/api/server.go` (`Deps.SSO`, `SSOService`, `ssoRoutes`, the OIDC routes in `authRoutes`), `internal/api/httpx.go` (`oidcCookie = "__Host-alice_oidc"`, `setBindingCookie`, `clearBindingCookie`)
- Create: `internal/api/sso_handlers.go`, `internal/api/oidc_handlers.go`, `internal/api/sso_dto.go`, `internal/api/sso_handlers_test.go`
- Modify: `internal/api/errors.go` (`ALC-SSO-0001..0016`; `errorMap` for `*oidc.DiscoveryError`, the `oidc` sentinels, `*oidc.LoginError`, `auth.ErrNotSSOUser`), `internal/api/errors_phase7_test.go` (SSO rows), `internal/api/authz_test.go` (`expectedMatrix[rbac.SSOManage]` = the `SettingsManage` row; `routeRuleViolations`: `under(p, "/api/v1/sso")` → `SSOManage`, `/api/v1/auth/oidc/providers`, `…/{id}/start`, `…/{id}/callback` → `public`, `/api/v1/auth/oidc/stepup` → `session`; `lockAvailable` gains `/api/v1/sso`)
- Modify: `cmd/alice/main.go` (`newAPIDeps`: `SSO: svc.oidc`)
- Modify: `api/openapi.yaml`, `docs/authz-matrix.md` (`make authz-doc`), `locales/common/{en,tr}.json` (C15 texts of the SSO codes), `docs/troubleshooting.md` (one section per SSO code)

**Interfaces:**
- Consumes: C11 (`oidc.Service` and its types), `auth.ErrNotSSOUser`, `issueSessionCookie`, `setCookie`, `pathUUID`, `secretText`.
- Produces: `rbac.SSOManage`; the SSO and OIDC routes of C13; C15's SSO codes.

```go
// internal/rbac/rbac.go, after RotationOperate:
	// Phase 7 (SEC-009 "SSO configuration", §25.1, R42 row 24): identity providers, group mappings and the
	// "SSO users may be Admin" switch — an Administrator in a browser session with step-up; never an API token.
	SSOManage Permission = "sso.manage"
// in policies:
	SSOManage: {Roles: []Role{Admin}, StepUp: true},
```

```go
// internal/api/server.go

// SSOService is *oidc.Service.
type SSOService interface {
	Providers(ctx context.Context) ([]oidc.Provider, error)
	Provider(ctx context.Context, id uuid.UUID) (oidc.Provider, error)
	PublicProviders(ctx context.Context) ([]oidc.PublicProvider, error)
	CreateProvider(ctx context.Context, a audit.Actor, in oidc.ProviderInput) (oidc.Provider, error)
	UpdateProvider(ctx context.Context, a audit.Actor, id uuid.UUID, version int, p oidc.ProviderPatch) (oidc.Provider, error)
	RefreshProvider(ctx context.Context, a audit.Actor, id uuid.UUID, version int) (oidc.Provider, error)
	DeleteProvider(ctx context.Context, a audit.Actor, id uuid.UUID, version int) error
	Mappings(ctx context.Context, providerID uuid.UUID) ([]oidc.Mapping, error)
	CreateMapping(ctx context.Context, a audit.Actor, providerID uuid.UUID, group string, role rbac.Role) (oidc.Mapping, error)
	DeleteMapping(ctx context.Context, a audit.Actor, id uuid.UUID) error
	Settings(ctx context.Context) (oidc.SSOSettings, error)
	SaveSettings(ctx context.Context, a audit.Actor, version int, allowAdmin bool) (oidc.SSOSettings, error)
	Begin(ctx context.Context, in oidc.BeginInput) (oidc.Begin, error)
	Complete(ctx context.Context, providerID uuid.UUID, q url.Values, binding string, m auth.Meta) (oidc.Completion, error)
}
```

The callback (the only GET that writes, R42 row 18):

```go
// oidcCallback ends a sign-in or a step-up at the identity provider's redirect (SEC-010..SEC-015). The binding cookie
// is cleared whatever happens; a refusal goes back to the sign-in page (or, for a step-up, to the page that asked) with
// the closed reason, which the page maps to its text. Nothing of the provider's answer is shown.
func (s *server) oidcCallback(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(r, "id")
	if !ok {
		s.writeError(w, r, ErrNotFound)
		return
	}
	binding := ""
	if c, err := r.Cookie(oidcCookie); err == nil {
		binding = c.Value
	}
	clearBindingCookie(w)
	done, err := s.deps.SSO.Complete(r.Context(), id, r.URL.Query(), binding, s.meta(r))
	if err != nil {
		reason := "sso.login_invalid"
		target := "/login"
		var le *oidc.LoginError
		if errors.As(err, &le) {
			reason = "sso." + le.Reason
			if le.StepUp && le.Next != "" {
				target = le.Next
			}
		}
		http.Redirect(w, r, withQuery(target, "sso_error", reason), http.StatusSeeOther)
		return
	}
	// A sign-in creates the session; a step-up rotated it (A-04): either way the new token is the cookie now.
	s.issueSessionCookie(w, done.Session.Token)
	http.Redirect(w, r, done.Next, http.StatusSeeOther)
}
```

(`withQuery(path, key, value)` appends `key=value` with `?` or `&` to a path that `claims.SafeNext` already made safe.)

The start handler decodes `{"next"}` (optional; exact keys), calls `Begin`, sets the binding cookie and answers `{"authorize_url"}`:

```go
// setBindingCookie stores the sign-in's binding value for 10 minutes. SameSite=Lax (not Strict): the identity
// provider's redirect back to Alice is a cross-site top-level navigation, on which only Lax cookies are sent; the
// value alone is useless — the state row holds only its SHA-256 and is single use (SEC-011).
func setBindingCookie(w http.ResponseWriter, value string) {
	http.SetCookie(w, &http.Cookie{Name: oidcCookie, Value: value, Path: "/", MaxAge: 600, Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode})
}

func clearBindingCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: oidcCookie, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode})
}
```

The provider create/patch bodies decode `client_secret` as `secretText` (zeroed on every path; `ProviderInput.ClientSecret = secrets.NewPlaintext(...)`); answers carry `has_client_secret` only (S-08). `POST /api/v1/sso/group-mappings` maps `role` with `rbac.ParseRole`.

- [ ] **Step 1: Write the failing tests**

`internal/rbac/rbac_test.go`:

```go
func TestPhase7Policies(t *testing.T) {
	adminUp := rbac.Subject{Kind: rbac.UserSession, Role: rbac.Admin, StepUp: true}
	admin := rbac.Subject{Kind: rbac.UserSession, Role: rbac.Admin}
	tok := rbac.Subject{Kind: rbac.APIToken, Role: rbac.Admin, Scope: rbac.ScopeOperate}
	op := rbac.Subject{Kind: rbac.UserSession, Role: rbac.Operator, StepUp: true}
	assert.Equal(t, rbac.Allow, rbac.Decide(rbac.SSOManage, adminUp))
	assert.Equal(t, rbac.DenyStepUp, rbac.Decide(rbac.SSOManage, admin))
	assert.Equal(t, rbac.DenyForbidden, rbac.Decide(rbac.SSOManage, tok), "no token configures SSO")
	assert.Equal(t, rbac.DenyForbidden, rbac.Decide(rbac.SSOManage, op))
}
```

`internal/api/sso_handlers_test.go`:

```go
package api

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/auth"
	"alice/internal/auth/oidc"
	"alice/internal/rbac"
)

func ssoDeps(t *testing.T) (Deps, *fakeSSO) {
	t.Helper()
	d := testDeps(t, nil)
	fs := &fakeSSO{}
	d.SSO = fs
	return d, fs
}

func ssoCalls() map[string]routeCall {
	v := map[string]string{"If-Match": `"1"`}
	return map[string]routeCall{
		"GET /api/v1/sso/providers":                       {},
		"POST /api/v1/sso/providers":                      {body: `{"name":"Corp","issuer_url":"https://idp.example.com","client_id":"alice","client_secret":"s"}`},
		"GET /api/v1/sso/providers/{id}":                  {},
		"PATCH /api/v1/sso/providers/{id}":                {body: `{"enabled":false}`, hdr: v},
		"DELETE /api/v1/sso/providers/{id}":               {hdr: v},
		"POST /api/v1/sso/providers/{id}/actions/refresh": {hdr: v},
		"GET /api/v1/sso/group-mappings":                  {},
		"POST /api/v1/sso/group-mappings":                 {body: `{"provider_id":"` + uuid.NewString() + `","group":"ops","role":"operator"}`},
		"DELETE /api/v1/sso/group-mappings/{id}":          {},
		"GET /api/v1/sso/settings":                        {},
		"PUT /api/v1/sso/settings":                        {body: `{"allow_admin_role":true}`, hdr: v},
	}
}

var ssoQueries = map[string]string{"GET /api/v1/sso/group-mappings": "?provider_id=" + uuid.NewString()}

// Review Focus 5: SSO configuration only for an Administrator with step-up (SEC-009, §25.1), in every license state.
func TestSSORoutesAuthz(t *testing.T) {
	calls := ssoCalls()
	d, fs := ssoDeps(t)
	fs.succeed()
	s := newServer(d)
	h := s.handler(s.apiRoutes())
	seen := 0
	for _, rt := range s.apiRoutes() {
		key := rt.method + " " + rt.pattern
		c, ok := calls[key]
		if !ok {
			continue
		}
		seen++
		assert.Equal(t, rbac.SSOManage, rt.perm, key)
		target := pathParamRE.ReplaceAllString(rt.pattern, uuid.NewString()) + ssoQueries[key]
		for _, id := range identities {
			(&Server{s: s}).ResetLimits()
			fs.reset()
			rec := callWith(h, rt.method, target, id, c.body, c.hdr)
			want := expectedMatrix[rt.perm][id]
			switch want {
			case allw:
				assert.Less(t, rec.Code, 300, "%s as %s: %s", key, id, rec.Body.String())
			case step:
				assert.Equal(t, "ALC-AUTH-0003", decodeErr(t, rec).Error.Code, key+" as "+id)
				assert.Zero(t, fs.calls())
			default:
				assert.Equal(t, want, rec.Code, key+" as "+id)
				assert.Zero(t, fs.calls())
			}
		}
	}
	assert.Equal(t, len(calls), seen)
}

func TestAdminMappingRefusedWhileOffOverHTTP(t *testing.T) {
	d, fs := ssoDeps(t)
	fs.CreateMappingFn = func(context.Context, audit.Actor, uuid.UUID, string, rbac.Role) (oidc.Mapping, error) {
		return oidc.Mapping{}, oidc.ErrAdminMappingDisabled
	}
	s := newServer(d)
	rec := callWith(s.handler(s.apiRoutes()), http.MethodPost, "/api/v1/sso/group-mappings", "admin-stepup",
		`{"provider_id":"`+uuid.NewString()+`","group":"admins","role":"admin"}`, nil)
	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.Equal(t, "ALC-SSO-0002", decodeErr(t, rec).Error.Code)
}

func TestOIDCStartSetsTheBindingCookie(t *testing.T) {
	d, fs := ssoDeps(t)
	fs.BeginFn = func(_ context.Context, in oidc.BeginInput) (oidc.Begin, error) {
		assert.Equal(t, "/certificates", in.Next)
		return oidc.Begin{AuthorizeURL: "https://idp.example.com/authorize?x=1", Binding: "bind-value"}, nil
	}
	s := newServer(d)
	rec := callWith(s.handler(s.apiRoutes()), http.MethodPost, "/api/v1/auth/oidc/"+uuid.NewString()+"/start", "", `{"next":"/certificates"}`, nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.JSONEq(t, `{"authorize_url":"https://idp.example.com/authorize?x=1"}`, rec.Body.String())
	c := rec.Result().Cookies()
	require.Len(t, c, 1)
	assert.Equal(t, "__Host-alice_oidc", c[0].Name)
	assert.Equal(t, "bind-value", c[0].Value)
	assert.True(t, c[0].HttpOnly && c[0].Secure)
	assert.Equal(t, http.SameSiteLaxMode, c[0].SameSite)
	assert.Equal(t, "/", c[0].Path)
	assert.Equal(t, 600, c[0].MaxAge)
}

func TestOIDCCallbackRedirects(t *testing.T) {
	d, fs := ssoDeps(t)
	s := newServer(d)
	h := s.handler(s.apiRoutes())
	cb := "/api/v1/auth/oidc/" + uuid.NewString() + "/callback?code=c&state=s"
	fs.CompleteFn = func(_ context.Context, _ uuid.UUID, q url.Values, binding string, _ auth.Meta) (oidc.Completion, error) {
		assert.Equal(t, "c", q.Get("code"))
		assert.Equal(t, "bind", binding)
		return oidc.Completion{Session: auth.SessionResult{Token: "tok"}, Next: "/certificates"}, nil
	}
	rec := callWith(h, http.MethodGet, cb, "", "", map[string]string{"Cookie": "__Host-alice_oidc=bind"})
	require.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "/certificates", rec.Header().Get("Location"))
	cookies := map[string]*http.Cookie{}
	for _, c := range rec.Result().Cookies() {
		cookies[c.Name] = c
	}
	assert.Equal(t, "tok", cookies["__Host-alice_session"].Value)
	assert.Equal(t, -1, cookies["__Host-alice_oidc"].MaxAge, "the binding is cleared")

	fs.CompleteFn = func(context.Context, uuid.UUID, url.Values, string, auth.Meta) (oidc.Completion, error) {
		return oidc.Completion{}, &oidc.LoginError{Reason: "no_access"}
	}
	rec = callWith(h, http.MethodGet, cb, "", "", nil)
	assert.Equal(t, "/login?sso_error=sso.no_access", rec.Header().Get("Location"))
	assert.Empty(t, cookieNamed(rec, "__Host-alice_session"), "no session")
	fs.CompleteFn = func(context.Context, uuid.UUID, url.Values, string, auth.Meta) (oidc.Completion, error) {
		return oidc.Completion{}, &oidc.LoginError{Reason: "stepup_other_user", StepUp: true, Next: "/settings?tab=sso"}
	}
	rec = callWith(h, http.MethodGet, cb, "", "", nil)
	assert.Equal(t, "/settings?tab=sso&sso_error=sso.stepup_other_user", rec.Header().Get("Location"))
}

func cookieNamed(rec interface{ Result() *http.Response }, name string) string {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

// Review Focus 3: the client secret is write-only.
func TestProviderSecretIsWriteOnly(t *testing.T) {
	d, fs := ssoDeps(t)
	var seen []byte
	onSecretBytes = func(b []byte) { seen = b }
	t.Cleanup(func() { onSecretBytes = nil })
	fs.CreateProviderFn = func(_ context.Context, _ audit.Actor, in oidc.ProviderInput) (oidc.Provider, error) {
		assert.Equal(t, "CANARY-cs", string(in.ClientSecret.Bytes()))
		return oidc.Provider{ID: uuid.New(), Name: in.Name, HasClientSecret: true, Version: 1}, nil
	}
	s := newServer(d)
	rec := callWith(s.handler(s.apiRoutes()), http.MethodPost, "/api/v1/sso/providers", "admin-stepup",
		`{"name":"Corp","issuer_url":"https://idp.example.com","client_id":"alice","client_secret":"CANARY-cs"}`, nil)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	assert.NotContains(t, rec.Body.String(), "CANARY")
	assert.True(t, strings.Contains(rec.Body.String(), `"has_client_secret":true`))
	assert.Equal(t, make([]byte, len("CANARY-cs")), seen)
}
```

(`fakeSSO` in `fakes_test.go`: one `XxxFn` per method of `SSOService`, `calls()`, `reset()`, `succeed()`.)

`internal/api/errors_phase7_test.go`: `phase7Table` gains the sixteen SSO rows of C15.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/rbac/ ./internal/api/`
Expected: FAIL — `rbac.SSOManage` undefined; routes 404; SSO codes missing.

- [ ] **Step 3: Write the implementation**

As specified above, C13 and C15. Route lines:

```go
{method: http.MethodGet, pattern: "/api/v1/auth/oidc/providers", perm: rbac.Public, handler: s.oidcProviders},
{method: http.MethodPost, pattern: "/api/v1/auth/oidc/{id}/start", perm: rbac.Public, limit: limitLogin, lic: license.ClassAlways, handler: s.oidcStart},
{method: http.MethodGet, pattern: "/api/v1/auth/oidc/{id}/callback", perm: rbac.Public, limit: limitLogin, handler: s.oidcCallback},
{method: http.MethodPost, pattern: "/api/v1/auth/oidc/stepup", perm: rbac.Session, limit: limitMFA, lic: license.ClassAlways, handler: s.oidcStepUp},
{method: http.MethodPost, pattern: "/api/v1/sso/providers", perm: rbac.SSOManage, lic: license.ClassAlways, handler: s.createProvider},
```

`errorMap`: `*oidc.DiscoveryError` → SSO-0001 with param `cause`; `oidc.ErrAdminMappingDisabled` → 0002; `oidc.ErrAdminMappingsExist` → 0003; `oidc.ErrPublicURLMissing` → 0004; `oidc.ErrProviderInUse` → 0005; `*oidc.LoginError` → `codeForReason("sso." + Reason)` (0006–0015); `auth.ErrNotSSOUser` → 0016; `oidc.ErrNotFound` → 404; `oidc.ErrVersion` → `ErrPreconditionFailed`; `oidc.ErrTooMany` → 422 (`validate.OutOfRange` on `name` for providers, `group` for mappings).

`api/openapi.yaml`: the operations of this task (the callback documented with `303` and the `Location` header, never a JSON body; `client_secret` `writeOnly: true`), schemas `Provider`, `ProviderCreate`, `ProviderPatch`, `Mapping`, `SSOSettings`, `PublicProvider`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -count=1 -race ./internal/rbac/ ./internal/api/ && make authz-doc && make i18n-check`
Expected: `ok`, `ok`; the matrix regenerated with the SSO rows; the i18n check passes.

Run: `make lint`
Expected: no findings.

- [ ] **Step 5: Commit**

```bash
git add -- internal/api/sso_handlers.go internal/api/oidc_handlers.go internal/api/sso_dto.go internal/api/sso_handlers_test.go
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(api): SSO administration (sso.manage, step-up), OIDC sign-in start, callback and step-up; ALC-SSO codes" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- internal/rbac internal/api cmd/alice/main.go api/openapi.yaml \
  docs/authz-matrix.md docs/troubleshooting.md locales/common/en.json locales/common/tr.json
```

---

### Task 16: API integration: dashboard exact counts, export equals rows, F-60..F-63 over the wire, the O-suite and X-05 over the wire, the Phase 7 secret-leak suite, A-06

**Files:**
- Modify: `internal/api/stack_integration_test.go` (`stack` gains `mail *notify.Settings`, `alerts *alerts.Service`, `reports *reports.Service`, `sso *oidc.Service`, `idp *fakeidp.Server`, `smtp *fakesmtp.Server`; `start` builds them as `cmd/alice` does, with `auth.Config.Notifier = notify.AdminNotifier{Clock: …}`, the mailer source over the stack's `fakesmtp`; `deps` passes `Mail`, `Alerts`, `Reports`, `SSO`; `apiError.Error` gains a `Params` field (`map[string]string`, JSON `params`); the helpers `stackSMTPPassword`, `configureMail`, `drainMail`, `userID`)
- Create: `internal/api/phase7_integration_test.go`, `internal/api/oidc_integration_test.go`, `internal/api/phase7_leak_integration_test.go`
- Modify: `internal/api/session_integration_test.go` (`TestA06GETRoutesNeverChangeState`: `phase7Records`, the exports' and the callback's one audit row)

**Interfaces:**
- Consumes: the whole stack of Tasks 1–15; `seed.Dashboard` (Task 13).
- Produces: tests only (a defect found here is fixed in its owning package by this task's implementer, each in its own commit).

- [ ] **Step 1: Write the tests**

`internal/api/phase7_integration_test.go`:

```go
//go:build integration

package api

import (
	"bytes"
	"context"
	"encoding/csv"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/testutil/seed"
)

// §26.9 "dashboard API tests with seeded data (exact counts)", over HTTP for each role.
func TestDashboardOverTheWire(t *testing.T) {
	s, admin, adminAcct := installed(t)
	want, err := seed.Dashboard(context.Background(), s.db.Owner, s.clock.Now())
	require.NoError(t, err)
	rec := admin.do(http.MethodGet, "/api/v1/dashboard/summary", nil)
	requireStatus(t, rec, http.StatusOK)
	got := decodeBody[struct {
		Certificates map[string]int `json:"certificates"`
		Targets      struct {
			Total    int            `json:"total"`
			ByStatus map[string]int `json:"by_status"`
		} `json:"targets"`
		Deployments struct {
			Failed7d int `json:"failed_7d"`
		} `json:"deployments"`
		Notifications *struct{ Failing bool } `json:"notifications"`
	}](t, rec)
	for k, v := range want.Certificates {
		assert.Equal(t, v, got.Certificates[k], k)
	}
	assert.Equal(t, want.Targets["total"], got.Targets.Total)
	assert.Equal(t, want.Targets["host_key_changed"], got.Targets.ByStatus["host_key_changed"])
	assert.Equal(t, want.Deployments["failed_7d"], got.Deployments.Failed7d)
	assert.NotNil(t, got.Notifications)

	rec = admin.do(http.MethodGet, "/api/v1/dashboard/expiring?days=30", nil)
	requireStatus(t, rec, http.StatusOK)
	items := decodeBody[struct {
		Items []struct {
			Name    string `json:"name"`
			Expired bool   `json:"expired"`
		} `json:"items"`
	}](t, rec).Items
	var names []string
	for _, it := range items {
		names = append(names, it.Name)
	}
	assert.Equal(t, want.Expiring30, names)
	assert.True(t, items[0].Expired, "expired ones are marked (S2 AC3)")

	olga := s.createUser(admin, adminAcct, "olga", "operator", operatorPassword)
	op := s.client("198.51.100.60")
	s.firstSignIn(op, olga)
	rec = op.do(http.MethodGet, "/api/v1/dashboard/summary", nil)
	requireStatus(t, rec, http.StatusOK)
	assert.Contains(t, rec.Body.String(), `"notifications":null`)
	assert.Contains(t, rec.Body.String(), `"audit":null`)
}

// Review Focus 4, owner step 3: the export over HTTP has exactly the rows the list shows for the same filter.
func TestExportOverTheWireEqualsFilteredRows(t *testing.T) {
	s, admin, _ := installed(t)
	want, err := seed.Dashboard(context.Background(), s.db.Owner, s.clock.Now())
	require.NoError(t, err)
	var web1 string
	require.NoError(t, s.db.Owner.QueryRow(context.Background(), `SELECT id::text FROM targets WHERE name = 'seed-web-1'`).Scan(&web1))
	q := "?expiry=30&target_id=" + web1
	list := decodeBody[struct {
		Items []struct {
			SubjectCN string `json:"subject_cn"`
		} `json:"items"`
	}](t, admin.do(http.MethodGet, "/api/v1/certificates"+q, nil)).Items
	rec := admin.do(http.MethodGet, "/api/v1/certificates/export"+q, nil)
	requireStatus(t, rec, http.StatusOK)
	body := rec.Body.Bytes()
	require.True(t, bytes.HasPrefix(body, []byte("\xEF\xBB\xBF")))
	rows, err := csv.NewReader(bytes.NewReader(body[3:])).ReadAll()
	require.NoError(t, err)
	var fromList, fromCSV []string
	for _, c := range list {
		fromList = append(fromList, c.SubjectCN)
	}
	for _, r := range rows[1:] {
		fromCSV = append(fromCSV, r[1])
	}
	assert.Equal(t, fromList, fromCSV)
	assert.Equal(t, want.ServerFilter.Expiry30, fromCSV)
	assert.Equal(t, 1, s.countWhere("audit_log", "action = 'inventory.exported'"))
}

// F-62 and F-63 over HTTP: test mail through the stack's fake SMTP; trust the certificate; wrong credentials.
func TestMailSettingsOverTheWire(t *testing.T) {
	s, admin, adminAcct := installed(t)
	s.stepUp(admin, adminAcct)
	host, port := s.smtp.Addr()
	rec := admin.do(http.MethodPut, "/api/v1/settings/smtp", map[string]any{"host": host, "port": port, "tls_mode": "starttls",
		"from": "alice@example.com", "username": "mailer", "password": "wrong-pass", "ca_pem": ""}, ifMatchOf("0"))
	requireStatus(t, rec, http.StatusOK)
	assert.NotContains(t, rec.Body.String(), "wrong-pass")
	rec = admin.do(http.MethodPost, "/api/v1/settings/smtp/actions/test", map[string]string{"to": "ops@example.com"})
	requireError(t, rec, http.StatusBadGateway, "ALC-NTF-0005")
	fp := decodeBody[apiError](t, rec).Error.Params["fingerprint"]
	assert.Equal(t, s.smtp.Fingerprint(), fp)
	rec = admin.do(http.MethodPost, "/api/v1/settings/smtp/actions/trust", map[string]string{"fingerprint": fp}, ifMatchOf("1"))
	requireStatus(t, rec, http.StatusOK)
	rec = admin.do(http.MethodPost, "/api/v1/settings/smtp/actions/test", map[string]string{"to": "ops@example.com"})
	requireError(t, rec, http.StatusBadGateway, "ALC-NTF-0006") // F-63: the server's credentials are wrong
	assert.NotContains(t, rec.Body.String(), "wrong-pass")
	assert.NotContains(t, s.logs.String(), "wrong-pass")
	rec = admin.do(http.MethodPut, "/api/v1/settings/smtp", map[string]any{"host": host, "port": port, "tls_mode": "starttls",
		"from": "alice@example.com", "username": "mailer", "password": stackSMTPPassword, "ca_pem": ""}, ifMatchOf("2"))
	requireStatus(t, rec, http.StatusOK)
	rec = admin.do(http.MethodPost, "/api/v1/settings/smtp/actions/test", map[string]string{"to": "ops@example.com"})
	requireStatus(t, rec, http.StatusOK)
	require.Len(t, s.smtp.Messages(), 1)
}

// F-60 over the stack: an alert during an outage is delivered once after it; meanwhile the failing state is shown.
func TestF60OverTheWire(t *testing.T) {
	s, admin, adminAcct := installed(t)
	s.stepUp(admin, adminAcct)
	s.configureMail(admin) // as TestMailSettingsOverTheWire, ending with a trusted, working configuration
	_, err := seed.Dashboard(context.Background(), s.db.Owner, s.clock.Now())
	require.NoError(t, err)
	s.smtp.Down()
	_, err = s.alerts.Scan(context.Background())
	require.NoError(t, err)
	for i := 0; i < 3; i++ {
		s.drainMail()
		s.clock.Advance(time.Hour)
	}
	rec := admin.do(http.MethodGet, "/api/v1/notifications/status", nil)
	assert.Contains(t, rec.Body.String(), `"failing":true`)
	require.NoError(t, s.smtp.Up())
	s.clock.Advance(time.Hour)
	s.drainMail()
	sent := len(s.smtp.Messages())
	assert.Positive(t, sent)
	s.clock.Advance(time.Hour)
	s.drainMail()
	assert.Equal(t, sent, len(s.smtp.Messages()), "exactly once")
	assert.Contains(t, admin.do(http.MethodGet, "/api/v1/notifications/status", nil).Body.String(), `"failing":false`)
}
```

(`stackSMTPPassword`, `s.configureMail(c)` and `s.drainMail()` are added to the stack harness: the stack's `fakesmtp` requires user `mailer` with `stackSMTPPassword`; `configureMail` stores working settings and trusts the server's certificate through the API; `drainMail` runs the stack's `notify.Sender.Drain`.)

`internal/api/oidc_integration_test.go`:

```go
//go:build integration

package api

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/testutil/fakeidp"
)

// ssoReady configures the stack's identity provider through the API (public URL, provider, Operator mapping).
func (s *stack) ssoReady(t *testing.T, admin *client, adminAcct *account) string {
	t.Helper()
	s.stepUp(admin, adminAcct)
	requireStatus(t, admin.do(http.MethodPut, "/api/v1/settings/general",
		map[string]any{"public_url": "https://alice.test", "retired_key_retention_days": 30}, ifMatchOf("0")), http.StatusOK)
	rec := admin.do(http.MethodPost, "/api/v1/sso/providers", map[string]any{"name": "Corp IdP", "issuer_url": s.idp.Issuer(),
		"client_id": s.idp.ClientID(), "client_secret": s.idp.ClientSecret(), "ca_pem": string(s.idp.CAPEM()), "enabled": true})
	requireStatus(t, rec, http.StatusCreated)
	p := decodeBody[struct {
		ID          string `json:"id"`
		RedirectURI string `json:"redirect_uri"`
	}](t, rec)
	s.idp.RegisterRedirect(p.RedirectURI)
	requireStatus(t, admin.do(http.MethodPost, "/api/v1/sso/group-mappings",
		map[string]string{"provider_id": p.ID, "group": "alice-operators", "role": "operator"}), http.StatusCreated)
	return p.ID
}

// browserSSO runs the browser's round trip through the API: start (keeps the binding cookie), the IdP, the callback.
func (s *stack) browserSSO(t *testing.T, c *client, provider string) *httptest.ResponseRecorder {
	t.Helper()
	rec := c.do(http.MethodPost, "/api/v1/auth/oidc/"+provider+"/start", map[string]string{"next": "/certificates"})
	requireStatus(t, rec, http.StatusOK)
	authz := decodeBody[struct {
		AuthorizeURL string `json:"authorize_url"`
	}](t, rec).AuthorizeURL
	cb, err := s.idp.Authorize(authz)
	require.NoError(t, err)
	u, err := url.Parse(cb)
	require.NoError(t, err)
	return c.do(http.MethodGet, u.RequestURI(), nil)
}

func TestSSOLoginOverTheWire(t *testing.T) {
	s, admin, adminAcct := installed(t)
	p := s.ssoReady(t, admin, adminAcct)
	s.idp.NextLogin(fakeidp.Login{Subject: "u1", Username: "omer", Email: "omer@example.com", Groups: []string{"alice-operators"}})
	browser := s.freshClient()
	rec := s.browserSSO(t, browser, p)
	require.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "/certificates", rec.Header().Get("Location"))
	rec = browser.do(http.MethodGet, "/api/v1/auth/session", nil)
	requireStatus(t, rec, http.StatusOK)
	assert.Contains(t, rec.Body.String(), `"role":"operator"`)
	assert.Contains(t, rec.Body.String(), `"auth_source":"oidc"`)
	requireStatus(t, browser.do(http.MethodGet, "/api/v1/users", nil), http.StatusForbidden)
}

// O-01..O-14 over the wire: each refusal is a redirect to the sign-in page with the reason, no session cookie, and one
// auth.oidc.denied row.
func TestOIDCNegativeSuiteOverTheWire(t *testing.T) {
	s, admin, adminAcct := installed(t)
	p := s.ssoReady(t, admin, adminAcct)
	wrong := "wrong"
	cases := []struct {
		name   string
		login  fakeidp.Login
		fault  fakeidp.Fault
		reason string
	}{
		{"O-01 alg none", fakeidp.Login{Subject: "u", Groups: []string{"alice-operators"}}, fakeidp.Fault{Alg: "none"}, "sso.login_invalid"},
		{"O-01 HS256", fakeidp.Login{Subject: "u", Groups: []string{"alice-operators"}}, fakeidp.Fault{Alg: "HS256"}, "sso.login_invalid"},
		{"O-01 other key", fakeidp.Login{Subject: "u", Groups: []string{"alice-operators"}}, fakeidp.Fault{OtherKey: true}, "sso.login_invalid"},
		{"O-02 issuer", fakeidp.Login{Subject: "u", Groups: []string{"alice-operators"}}, fakeidp.Fault{Issuer: "https://evil"}, "sso.login_invalid"},
		{"O-02 audience", fakeidp.Login{Subject: "u", Groups: []string{"alice-operators"}}, fakeidp.Fault{Audience: []string{"x"}}, "sso.login_invalid"},
		{"O-02 expired", fakeidp.Login{Subject: "u", Groups: []string{"alice-operators"}}, fakeidp.Fault{ExpIn: -5 * time.Minute}, "sso.login_invalid"},
		{"O-03 nonce", fakeidp.Login{Subject: "u", Groups: []string{"alice-operators"}}, fakeidp.Fault{Nonce: &wrong}, "sso.login_invalid"},
		{"O-05 IdP error", fakeidp.Login{Subject: "u", Groups: []string{"alice-operators"}}, fakeidp.Fault{AuthorizeError: "access_denied"}, "sso.idp_error"},
		{"O-06 no group", fakeidp.Login{Subject: "u", Groups: []string{"nobody"}}, fakeidp.Fault{}, "sso.no_access"},
		{"O-07 overage", fakeidp.Login{Subject: "u"}, fakeidp.Fault{Overage: true}, "sso.groups_overage"},
		{"O-10 local e-mail", fakeidp.Login{Subject: "u", Email: "ada@example.com", Groups: []string{"alice-operators"}}, fakeidp.Fault{}, "sso.email_in_use"},
	}
	requireStatus(t, admin.do(http.MethodPatch, "/api/v1/users/"+s.userID("ada"), map[string]string{"email": "ada@example.com"}), http.StatusOK)
	for _, c := range cases {
		s.idp.NextLogin(c.login)
		s.idp.SetFault(c.fault)
		before := s.countWhere("audit_log", "action = 'auth.oidc.denied'")
		browser := s.freshClient()
		rec := s.browserSSO(t, browser, p)
		require.Equal(t, http.StatusSeeOther, rec.Code, c.name)
		assert.Equal(t, "/login?sso_error="+c.reason, rec.Header().Get("Location"), c.name)
		for _, ck := range responseCookies(rec) {
			assert.NotEqual(t, "__Host-alice_session", ck.Name, "%s: no session", c.name)
		}
		assert.Equal(t, before+1, s.countWhere("audit_log", "action = 'auth.oidc.denied'"), c.name)
	}
	// O-03: the callback without the browser's binding cookie (another browser, or a forged link) is refused.
	s.idp.SetFault(fakeidp.Fault{})
	s.idp.NextLogin(fakeidp.Login{Subject: "u", Groups: []string{"alice-operators"}})
	browser := s.freshClient()
	rec := browser.do(http.MethodPost, "/api/v1/auth/oidc/"+p+"/start", map[string]string{})
	authz := decodeBody[struct {
		AuthorizeURL string `json:"authorize_url"`
	}](t, rec).AuthorizeURL
	cb, err := s.idp.Authorize(authz)
	require.NoError(t, err)
	u, _ := url.Parse(cb)
	rec = s.freshClient().do(http.MethodGet, u.RequestURI(), nil)
	assert.Equal(t, "/login?sso_error=sso.login_expired", rec.Header().Get("Location"))
}

// X-05, R-03: with the identity provider down, the local Administrator with the authenticator code signs in.
func TestX05BreakGlassWhileIdPDown(t *testing.T) {
	s, admin, adminAcct := installed(t)
	p := s.ssoReady(t, admin, adminAcct)
	s.idp.Down()
	browser := s.freshClient()
	rec := browser.do(http.MethodPost, "/api/v1/auth/oidc/"+p+"/start", map[string]string{})
	requireStatus(t, rec, http.StatusOK) // the endpoints are known: starting needs no IdP call
	local := s.freshClient()
	s.signIn(local, adminAcct)
	requireStatus(t, local.do(http.MethodGet, "/api/v1/users", nil), http.StatusOK)
}
```

(`s.userID(name)` is a small harness helper that reads a user's ID through the owner pool.)

`internal/api/phase7_leak_integration_test.go`:

```go
//go:build integration

package api

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/testutil/fakeidp"
)

// Review Focus 3, §25.2: the SMTP password and the OIDC client secret appear in no answer, header, log line, audit row,
// settings value or outbox row; the database holds them only as envelopes (S-04).
func TestPhase7SecretsNeverLeak(t *testing.T) {
	s, admin, adminAcct := installed(t)
	s.stepUp(admin, adminAcct)
	const smtpCanary = "CANARY-smtp-pw-7a1f"
	host, port := s.smtp.Addr()
	requireStatus(t, admin.do(http.MethodPut, "/api/v1/settings/smtp", map[string]any{"host": host, "port": port,
		"tls_mode": "starttls", "from": "alice@example.com", "username": "mailer", "password": smtpCanary, "ca_pem": ""}, ifMatchOf("0")), http.StatusOK)
	admin.do(http.MethodPost, "/api/v1/settings/smtp/actions/test", map[string]string{"to": "ops@example.com"})
	p := s.ssoReady(t, admin, adminAcct)
	s.idp.NextLogin(fakeidp.Login{Subject: "u1", Groups: []string{"alice-operators"}})
	s.browserSSO(t, s.freshClient(), p)
	for _, secret := range []string{smtpCanary, s.idp.ClientSecret()} {
		for _, x := range s.recorded() {
			assert.NotContains(t, string(x.body), secret, "%s answer", x.key())
			for k, v := range x.header {
				assert.NotContains(t, strings.Join(v, " "), secret, "%s header %s", x.key(), k)
			}
		}
		assert.NotContains(t, s.logs.String(), secret, "DEBUG logs")
		var dump string
		require.NoError(t, s.db.Owner.QueryRow(context.Background(), `SELECT
(SELECT coalesce(string_agg(details::text, ' '), '') FROM audit_log) ||
(SELECT coalesce(string_agg(value::text, ' '), '') FROM settings) ||
(SELECT coalesce(string_agg(params::text, ' '), '') FROM notifications_outbox) ||
(SELECT coalesce(string_agg(encode(ciphertext, 'escape'), ' '), '') FROM setting_secrets) ||
(SELECT coalesce(string_agg(t::text, ' '), '') FROM oidc_providers t) ||
(SELECT coalesce(string_agg(t::text, ' '), '') FROM oidc_login_states t)`).Scan(&dump))
		assert.NotContains(t, dump, secret)
	}
}
```

(`exchange` is the harness's record of every request: `method`, `path`, `status`, `header`, `body`.)

`internal/api/session_integration_test.go`, `TestA06GETRoutesNeverChangeState`: before the loop, `phase7Records` stores what the Phase 7 GETs need (`seed.Dashboard` for the dashboard and exports; one saved view of the admin; one identity provider through the API, its ID substituted for `/api/v1/sso/providers/`); in the loop, the two exports expect exactly one `inventory.exported` row, and `GET /api/v1/auth/oidc/{id}/callback` (called without a state) expects status 303, `Location` `/login?sso_error=sso.login_expired` and exactly one `auth.oidc.denied` row (R42 row 18: the one GET that writes, by protocol); every other GET still changes nothing.

- [ ] **Step 2: Run the tests** (Docker: testcontainers)

Run: `go test -count=1 -race -tags integration ./internal/api/`
Expected: `ok`. A failure is a defect of the owning task's code: fix it there (own commit), never weaken a test.

- [ ] **Step 3: Run the whole integration suite once** (Docker: testcontainers)

Run: `make test-integration`
Expected: `ok` for every package.

- [ ] **Step 4: Commit**

```bash
git add -- internal/api/phase7_integration_test.go internal/api/oidc_integration_test.go internal/api/phase7_leak_integration_test.go
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "test(api): Phase 7 over the wire — exact dashboard counts, export equals rows, mail settings and F-60..F-63, OIDC negative suite, X-05, leaks" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- internal/api/stack_integration_test.go internal/api/phase7_integration_test.go \
  internal/api/oidc_integration_test.go internal/api/phase7_leak_integration_test.go internal/api/session_integration_test.go
```

---

### Task 17: Performance test (R32) and `make perf`

**Files:**
- Create: `internal/api/perf_integration_test.go` (`//go:build integration && perf`)
- Modify: `Makefile` (target `perf`)

**Interfaces:**
- Consumes: the stack harness (`installed`, `client.do`, `s.db.Owner`), the routes of Tasks 14 and the existing list routes.
- Produces: `TestR32DashboardAndListBudgets`; `make perf`.

- [ ] **Step 1: Write the test**

`internal/api/perf_integration_test.go`:

```go
//go:build integration && perf

package api

import (
	"context"
	"math"
	"net/http"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
)

const (
	perfWarmup   = 10
	perfRequests = 100
)

// seedR32 inserts 500 Nginx targets, 5,000 certificates in use (ten per target, expiries spread over 400 days, 5 %
// expired), 500 finished deployments and 5,000 audit rows, as the owner role, in a few set-based statements.
func seedR32(t *testing.T, s *stack) {
	t.Helper()
	ctx := context.Background()
	var cred string
	require.NoError(t, s.db.Owner.QueryRow(ctx, `SELECT id::text FROM credentials WHERE purpose = 'platform_ssh'`).Scan(&cred))
	for _, q := range []string{
		`INSERT INTO targets (id, name, type, config, credential_id, status, created_at, updated_at)
SELECT gen_random_uuid(), 'perf-' || i, 'nginx', jsonb_build_object('host', 'perf-' || i || '.example.test', 'port', 22,
'username', 'alice-svc'), '` + cred + `'::uuid, CASE WHEN i % 50 = 0 THEN 'unreachable' ELSE 'ok' END, now(), now()
FROM generate_series(1, 500) AS i`,
		`INSERT INTO certificates (id, fingerprint_sha256, subject_cn, not_before, not_after, key_algorithm, public_key_sha256, pem_chain,
source, first_seen_at, last_seen_at, created_at)
SELECT gen_random_uuid(), md5('c' || i) || md5('d' || i), 'site' || i || '.example.test', now() - interval '300 days',
now() + ((i % 400) - 20) * interval '1 day', 'ecdsa', md5('k' || i) || md5('l' || i), '', 'discovered', now(), now(), now()
FROM generate_series(1, 5000) AS i`,
		`INSERT INTO certificate_locations (id, target_id, kind, cert_path, key_path, certificate_id, supported, servers, first_seen_at,
last_seen_at)
SELECT gen_random_uuid(), t.id, 'nginx_file', '/etc/nginx/ssl/' || c.subject_cn || '.crt', '/etc/nginx/ssl/' || c.subject_cn || '.key',
c.id, true, jsonb_build_array(jsonb_build_object('names', jsonb_build_array(c.subject_cn), 'listens', '[]'::jsonb,
'file', '/etc/nginx/conf.d/site.conf', 'line', 1)), now(), now()
FROM (SELECT id, subject_cn, row_number() OVER (ORDER BY subject_cn) AS n FROM certificates WHERE subject_cn LIKE 'site%') c
JOIN (SELECT id, row_number() OVER (ORDER BY name) AS n FROM targets WHERE name LIKE 'perf-%') t ON t.n = (c.n - 1) % 500 + 1`,
		`INSERT INTO deployments (id, certificate_id, location_id, target_id, trigger, state, status, new_fingerprint, cert_path, key_path,
error_code, created_at, finished_at)
SELECT gen_random_uuid(), l.certificate_id, l.id, l.target_id, 'manual', 'done', CASE WHEN n % 10 = 0 THEN 'failed' ELSE 'succeeded' END,
c.fingerprint_sha256, l.cert_path, l.key_path, CASE WHEN n % 10 = 0 THEN 'ngx.reload_failed' ELSE '' END,
now() - (n % 14) * interval '1 day', now() - (n % 14) * interval '1 day'
FROM (SELECT l.*, row_number() OVER (ORDER BY l.cert_path) AS n FROM certificate_locations l) l
JOIN certificates c ON c.id = l.certificate_id WHERE l.n <= 500`,
	} {
		_, err := s.db.Owner.Exec(ctx, q)
		require.NoError(t, err)
	}
	for i := 0; i < 5000; i++ { // audit rows through the real chain (the list of the audit page is a measured list)
		require.NoError(t, s.auditSvc.Write(ctx, auditEventForPerf(i)))
	}
	_, err := s.db.Owner.Exec(ctx, `ANALYZE`)
	require.NoError(t, err)
}

func auditEventForPerf(i int) audit.Event {
	return audit.Event{Actor: audit.SystemActor("perf"), Action: "perf.row", Result: audit.Success,
		Details: map[string]string{"n": strconv.Itoa(i)}}
}

func p95(d []time.Duration) time.Duration {
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	return d[int(math.Ceil(0.95*float64(len(d))))-1]
}

// R32: dashboard API p95 < 500 ms, list pages p95 < 300 ms at 5,000 certificates and 500 targets, through the whole HTTP
// stack (authentication, authorization, rate limits, JSON).
func TestR32DashboardAndListBudgets(t *testing.T) {
	s, admin, _ := installed(t)
	seedR32(t, s)
	budgets := []struct {
		path   string
		budget time.Duration
	}{
		{"/api/v1/dashboard/summary", 500 * time.Millisecond},
		{"/api/v1/dashboard/expiring?days=30&limit=50", 500 * time.Millisecond},
		{"/api/v1/alerts", 500 * time.Millisecond},
		{"/api/v1/certificates", 300 * time.Millisecond},
		{"/api/v1/certificates?expiry=30", 300 * time.Millisecond},
		{"/api/v1/certificates?q=site42", 300 * time.Millisecond},
		{"/api/v1/targets", 300 * time.Millisecond},
		{"/api/v1/deployments", 300 * time.Millisecond},
		{"/api/v1/ssh-keys", 300 * time.Millisecond},
		{"/api/v1/audit", 300 * time.Millisecond},
	}
	for _, b := range budgets {
		var times []time.Duration
		for i := 0; i < perfWarmup+perfRequests; i++ {
			s.api.ResetLimits() // the general limit (300/min) is not what is measured
			start := time.Now()
			rec := admin.do(http.MethodGet, b.path, nil)
			elapsed := time.Since(start)
			require.Equal(t, http.StatusOK, rec.Code, "%s: %s", b.path, rec.Body.String())
			if i >= perfWarmup {
				times = append(times, elapsed)
			}
		}
		got := p95(times)
		t.Logf("R32 %-48s p95 %6.1f ms (budget %v)", b.path, float64(got.Microseconds())/1000, b.budget)
		assert.Less(t, got, b.budget, b.path)
	}
}
```

(The test calls `time.Now` and `time.Since`: `_test.go` files are exempt from the clock rule, and wall-clock time is what is measured. The audit action `perf.row` is written only by this tagged test, which the web's label scan does not read — it scans non-test Go files.)

`Makefile`, after `coverage`:

```make
.PHONY: perf
perf: ## Run the R32 performance test (5,000 certificates, 500 targets; needs Docker, nothing else using it)
	go test -count=1 -timeout 30m -tags 'integration perf' -run '^TestR32' -v ./internal/api/
```

- [ ] **Step 2: Run it** (Docker: testcontainers; no Playwright and no other integration run at the same time — timing)

Run: `make perf 2>&1 | grep -E 'R32|ok|FAIL'`
Expected: ten `R32 … p95 … ms` lines under their budgets and `ok`. If a budget fails, profile the query (`EXPLAIN ANALYZE` on the owner pool) and fix it in the owning package (an index in a new statement of migration `00011` is allowed until Task 22 closes the phase: the migration is not released yet), in its own commit; never raise a budget.

- [ ] **Step 3: Commit**

```bash
git add -- internal/api/perf_integration_test.go
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "test(api): R32 performance — dashboard p95 < 500 ms, lists p95 < 300 ms at 5,000 certificates and 500 targets; make perf" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- internal/api/perf_integration_test.go Makefile
```

---

### Task 18: Web part 1: Dashboard, the failing banner, filters in the URL, saved views, Export; every Phase 7 audit and job label

**Files:**
- Create: `web/src/api/phase7.ts` (types of C13 and the calls below), `web/src/api/phase7.test.ts`
- Modify: `web/src/api/queryKeys.ts` (a "Phase 7" group: `DASHBOARD_KEY = ['dashboard']`, `EXPIRING_KEY = ['dashboard', 'expiring']`, `ALERTS_KEY = ['alerts']`, `NOTIFICATIONS_KEY = ['notifications', 'status']`, `viewsKey(page)`), `web/src/api/types.ts` (`ExpiryFilter` gains `'7' | '14' | '90'`; `CertificateSourceFilter` gains `'azure_kv'`)
- Create: `web/src/hooks/useUrlFilters.ts`, `web/src/hooks/useUrlFilters.test.tsx`
- Create: `web/src/pages/DashboardPage.tsx`, `web/src/pages/DashboardPage.test.tsx`, `web/src/components/dashboard/{CertificateCounts,ExpiringList,FailedDeployments,TargetsByStatus,LicenseCard,RotationUpcoming,AuditHead,AttentionList}.tsx`
- Create: `web/src/components/NotificationsBanner.tsx`, `NotificationsBanner.test.tsx`, `SavedViews.tsx`, `SavedViews.test.tsx`, `ExportButton.tsx`, `ExportButton.test.tsx`
- Modify: `web/src/router.tsx` (index → `DashboardPage`; `HomePage.tsx` is deleted, its welcome line and server status move into the dashboard header), `web/src/layout/AppLayout.tsx` (`NAV_ITEMS` first entry `{ to: '/', labelKey: 'nav.dashboard', roles: ALL }`; `<NotificationsBanner />` after `<LicenseBanners />`)
- Modify: `web/src/pages/CertificatesPage.tsx`, `CertificatesPage.test.tsx`, `SSHKeysPage.tsx`, `SSHKeysPage.test.tsx` (filters in the URL, saved views, Export; the new expiry and source options)
- Modify: `web/src/locales/en.json`, `web/src/locales/tr.json` (C18 keys of this task; `audit.actions.*` for every action of C16; `jobs.types.alerts.scan`), `web/src/screens.i18n.test.tsx` (the dashboard is rendered in both languages)

**Interfaces:**
- Consumes: C13 routes and DTOs; `apiFetch`, `isApiError`; `ErrorAlert`, `CodeText`, `Expiry`, `WRAP`, `useAuth`, `formatDateTime`.
- Produces (used by Task 19 and the e2e): `api/phase7.ts` exports `DashboardSummary`, `ExpiringItem`, `Condition`, `Delivery`, `SavedView`, `getDashboardSummary()`, `getExpiring(days, limit)`, `getAlerts()`, `getNotificationStatus()`, `listViews(page)`, `createView(body)`, `deleteView(id)`, `exportUrl(kind, params)`; `useUrlFilters`; `SavedViews`; `ExportButton`; the `data-testid`s `dashboard-counts`, `expiring-list`, `failed-deployments`, `targets-by-status`, `license-card`, `rotation-upcoming`, `audit-head`, `attention-list`, `notifications-banner`.

```ts
// web/src/hooks/useUrlFilters.ts
import { useCallback, useMemo } from 'react';
import { useSearchParams } from 'react-router';

// useUrlFilters keeps a list page's filters in the address (R42 rows 15-17): a link, a saved view and the export
// reproduce the list exactly. Only the allowed keys are read; an empty value removes the key; replace keeps the
// browser history to one entry per page visit while a person types.
export function useUrlFilters<K extends string>(keys: readonly K[]): [Record<K, string>, (next: Partial<Record<K, string>>) => void, () => void] {
  const [params, setParams] = useSearchParams();
  const values = useMemo(() => {
    const out = {} as Record<K, string>;
    for (const k of keys) out[k] = params.get(k) ?? '';
    return out;
  }, [params, keys]);
  const set = useCallback(
    (next: Partial<Record<K, string>>) =>
      setParams(
        (prev) => {
          const p = new URLSearchParams(prev);
          for (const [k, v] of Object.entries(next) as [K, string | undefined][]) {
            if (v) p.set(k, v);
            else p.delete(k);
          }
          return p;
        },
        { replace: true },
      ),
    [setParams],
  );
  const clear = useCallback(() => setParams(new URLSearchParams(), { replace: true }), [setParams]);
  return [values, set, clear];
}
```

```ts
// web/src/api/phase7.ts (calls)
const v1 = '/api/v1';
export const getDashboardSummary = () => apiFetch<DashboardSummary>(`${v1}/dashboard/summary`);
export const getExpiring = (days = 30, limit = 10) => apiFetch<{ items: ExpiringItem[] }>(`${v1}/dashboard/expiring?days=${days}&limit=${limit}`);
export const getAlerts = () => apiFetch<{ items: Condition[] }>(`${v1}/alerts`);
export const getNotificationStatus = () => apiFetch<Delivery>(`${v1}/notifications/status`);
export const listViews = (page: ViewPage) => apiFetch<{ items: SavedView[] }>(`${v1}/views?page=${page}`);
export const createView = (body: { page: ViewPage; name: string; query: Record<string, string> }) =>
  apiFetch<SavedView>(`${v1}/views`, { method: 'POST', body });
export const deleteView = (id: string) => apiFetch<void>(`${v1}/views/${encodeURIComponent(id)}`, { method: 'DELETE' });

// exportUrl is the CSV download of a list with the same filters (no cursor, no limit). The browser downloads it with
// the session cookie; the file never passes through the page's memory.
export function exportUrl(kind: 'certificates' | 'ssh-keys', filters: Record<string, string>): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(filters)) if (v) p.set(k, v);
  const qs = p.toString();
  return `${v1}/${kind}/export${qs ? `?${qs}` : ''}`;
}
```

`ExportButton`: `<Button component="a" href={exportUrl(kind, filters)} download variant="default">{t('filters.export')}</Button>` (as the audit export link of `AuditPage`).

`SavedViews`: a Mantine `Menu` named **Saved views** listing the user's views of the page (`listViews`; each item applies the view by calling `set` of `useUrlFilters` with exactly the view's query — every other filter key cleared — and has a delete button labelled `filters.deleteView`); **Save view** opens an `AppModal` with one `TextInput` (`filters.viewName`, 1–60 characters) that posts the current filters; errors (`ALC-RPT-0002`, `ALC-RPT-0003`) show in `ErrorAlert`.

`DashboardPage`: header (`dashboard.title`; `dashboard.welcome`; the server status line of the former `HomePage`), then a responsive grid (`SimpleGrid cols={{ base: 1, md: 2, xl: 3 }}`) of the eight widgets; data from `useQuery(DASHBOARD_KEY, getDashboardSummary)`, `useQuery(EXPIRING_KEY, () => getExpiring(30, 10))` and `useQuery(ALERTS_KEY, getAlerts)`, refreshed every 60 s (`refetchInterval: 60_000`; background reads do not carry the activity mark, R39 item 1). Widgets:
- `CertificateCounts` (`data-testid="dashboard-counts"`): four lines with counts, each a link to the certificate list with the matching filter: **Expired** → `/certificates?expiry=expired` (red badge), **Within 7 days** → `?expiry=7` (orange), **In 8 to 30 days** → `?expiry=30` (yellow), **In 31 to 60 days** → `?expiry=60`; `dashboard.monitored`; `dashboard.kvExpiring` with `kv_within_30 + kv_expired` when not zero, linking to `/key-vaults`.
- `ExpiringList` (`data-testid="expiring-list"`): the items of `getExpiring(30, 10)` as a table inside `Table.ScrollContainer` (name as `Code`, websites, servers or vault, the date via `Expiry`), an expired row has the **Expired** badge in red (S2 AC3); empty → `dashboard.noneExpiring`.
- `FailedDeployments`: `failed_7d` and the five recent ones linking to `/deployments/<id>`.
- `TargetsByStatus`: one line per status with a non-zero count (the existing `enum.targetStatus.*` labels), linking to `/servers`.
- `LicenseCard`: Administrators and Auditors: phase, end date and days left (existing `license.*` labels); Operators: only "Expired" or nothing.
- `RotationUpcoming`: the upcoming list linking to `/ssh-keys/<ssh_key_id>`; running and needs-attention counts.
- `AuditHead` (Administrators and Auditors; `null` → hidden): sequence number, hash as `Code`, time, and `dashboard.auditHeadHelp`; a broken chain shows the existing `audit.broken` text in red.
- `AttentionList` (`data-testid="attention-list"`): the conditions with the existing labels for target statuses and deployment results, `audit.broken`, and `notifications.failingTitle`.

`NotificationsBanner` (Administrators only; `useQuery(NOTIFICATIONS_KEY, getNotificationStatus, { refetchInterval: 60_000 })`): when `failing`, a red `Alert` with `role="alert"`, `data-testid="notifications-banner"`, title `notifications.failingTitle` (**E-mails could not be sent**, owner step 4) and body `notifications.failingBody` (`count` = consecutive failures, `code` = last failure code as `Code`), and an anchor to `/settings?tab=mail` (Task 19's page).

`CertificatesPage`/`SSHKeysPage`: every filter comes from `useUrlFilters(['target_id', 'source', 'q', 'expiry'])` (SSH keys: `['target_id', 'os_user', 'q', 'flag', 'missing']`); the search input keeps its own draft state and writes `q` to the URL after the existing 300 ms debounce; the query key and `listCertificates` use the URL values; `SavedViews` and `ExportButton` sit above the table; `EXPIRIES` gains `7`, `14`, `90` (`certificates.expiry7`, `expiry14`, `expiry90`) in order expired, 7, 14, 30, 60, 90; `SOURCES` gains `azure_kv` (`certificates.sourceAzureKv`); **Clear filters** (`filters.clear`) empties the URL.

`web/src/locales/{en,tr}.json`: the C18 keys of this task; one `audit.actions.<action with underscores>` label per C16 action (EN and TR of C16); `jobs.types.alerts.scan` (nested). Labels for actions whose Go code lands in parallel are added now on purpose: `labels.test.ts` checks only that no written action lacks a label.

- [ ] **Step 1: Write the failing tests**

`web/src/pages/DashboardPage.test.tsx`:

```tsx
import { screen, within } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import { adminSession, auditorSession, operatorSession, sessionHandlers } from '../test/fixtures';
import { renderRoute } from '../test/render';
import { server } from '../test/server';

const summary = (over: Record<string, unknown> = {}) => ({
  generated_at: '2026-10-07T09:00:00Z',
  certificates: { monitored: 8, expired: 1, within_7: 2, within_30: 3, within_60: 1, kv_expired: 0, kv_within_30: 2 },
  deployments: { failed_7d: 1, recent: [{ id: 'd1', certificate_name: 'api.seed.test', target_id: 't1', target_name: 'seed-web-1', status: 'failed', error_code: 'ngx.reload_failed', at: '2026-10-06T09:00:00Z' }] },
  targets: { total: 3, by_status: { ok: 2, host_key_changed: 1, unreachable: 0 } },
  license: { expired: false, phase: 'active', ends_at: '2026-11-16T09:00:00Z', days_left: 40 },
  rotation: { upcoming: [{ policy_id: 'p1', ssh_key_id: 'k1', key_label: 'ci-deploy', next_run_at: '2026-10-10T09:00:00Z' }], running: 0, needs_attention: 0 },
  notifications: { failing: false, consecutive_failures: 0, last_failure_at: null, last_failure_code: '', last_success_at: null, pending: 0, failed_24h: 0 },
  audit: { head_seq: 42, head_hash: 'ab'.repeat(32), checked_at: '2026-10-07T03:00:00Z', intact: true },
  attention: 2,
  ...over,
});

function handlers(over: Record<string, unknown> = {}) {
  return [
    http.get('/api/v1/dashboard/summary', () => HttpResponse.json(summary(over))),
    http.get('/api/v1/dashboard/expiring', () =>
      HttpResponse.json({
        items: [
          { kind: 'certificate_expiry', object_id: 'c0', name: 'old.seed.test', expires_at: '2026-10-05T09:00:00Z', days_left: 0, expired: true, fingerprint: 'f', websites: [], servers: ['seed-web-1'], target_ids: ['t1'], vault: '', vault_id: null },
          { kind: 'certificate_expiry', object_id: 'c1', name: 'www.seed.test', expires_at: '2026-10-14T08:00:00Z', days_left: 7, expired: false, fingerprint: 'f', websites: ['www.seed.test'], servers: ['seed-web-1'], target_ids: ['t1'], vault: '', vault_id: null },
        ],
      }),
    ),
    http.get('/api/v1/alerts', () => HttpResponse.json({ items: [{ kind: 'host_key_changed', object_id: 't3', name: 'seed-web-3', since: '2026-10-06T09:00:00Z', error_code: '' }] })),
    http.get('/api/v1/notifications/status', () => HttpResponse.json({ failing: false })),
  ];
}

describe('DashboardPage', () => {
  it('shows the counts as links to the filtered certificate list', async () => {
    server.use(...sessionHandlers(adminSession), ...handlers());
    await renderRoute('/');
    const counts = await screen.findByTestId('dashboard-counts');
    expect(within(counts).getByRole('link', { name: /Expired.*1/ })).toHaveAttribute('href', '/certificates?expiry=expired');
    expect(within(counts).getByRole('link', { name: /Within 7 days.*2/ })).toHaveAttribute('href', '/certificates?expiry=7');
    expect(within(counts).getByRole('link', { name: /In 8 to 30 days.*3/ })).toHaveAttribute('href', '/certificates?expiry=30');
    expect(within(counts).getByText('Certificates in use: 8')).toBeInTheDocument();
  });

  it('lists what expires soon, the expired one marked', async () => {
    server.use(...sessionHandlers(adminSession), ...handlers());
    await renderRoute('/');
    const list = await screen.findByTestId('expiring-list');
    const rows = within(list).getAllByRole('row');
    expect(within(rows[1]).getByText('old.seed.test')).toBeInTheDocument();
    expect(within(rows[1]).getByText('Expired')).toBeInTheDocument();
    expect(within(rows[2]).getByText('www.seed.test')).toBeInTheDocument();
  });

  it('shows failed deployments, targets by status, the license and upcoming rotations', async () => {
    server.use(...sessionHandlers(adminSession), ...handlers());
    await renderRoute('/');
    expect(within(await screen.findByTestId('failed-deployments')).getByRole('link', { name: /api\.seed\.test/ })).toHaveAttribute('href', '/deployments/d1');
    expect(within(screen.getByTestId('targets-by-status')).getByText(/2/)).toBeInTheDocument();
    expect(within(screen.getByTestId('rotation-upcoming')).getByRole('link', { name: /ci-deploy/ })).toHaveAttribute('href', '/ssh-keys/k1');
    expect(within(screen.getByTestId('attention-list')).getByText('seed-web-3')).toBeInTheDocument();
  });

  it('shows the audit head to Auditors and not to Operators', async () => {
    server.use(...sessionHandlers(auditorSession), ...handlers({ notifications: null }));
    const { unmount } = await renderRoute('/');
    expect(within(await screen.findByTestId('audit-head')).getByText('ab'.repeat(32))).toBeInTheDocument();
    unmount();
    server.use(...sessionHandlers(operatorSession), ...handlers({ notifications: null, audit: null, license: { expired: false, phase: '', ends_at: null, days_left: null } }));
    await renderRoute('/');
    await screen.findByTestId('dashboard-counts');
    expect(screen.queryByTestId('audit-head')).not.toBeInTheDocument();
  });

  it('renders in Turkish', async () => {
    server.use(...sessionHandlers(adminSession), ...handlers());
    await renderRoute('/', { languages: ['tr-TR'] });
    expect(await screen.findByRole('heading', { name: 'Pano' })).toBeInTheDocument();
    expect(screen.getByText('Süresi yakında dolacaklar')).toBeInTheDocument();
  });
});
```

`web/src/components/NotificationsBanner.test.tsx`:

```tsx
import { screen } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import { adminSession, operatorSession, sessionHandlers } from '../test/fixtures';
import { renderRoute } from '../test/render';
import { server } from '../test/server';

describe('NotificationsBanner', () => {
  it('tells Administrators that e-mails could not be sent (owner step 4)', async () => {
    server.use(
      ...sessionHandlers(adminSession),
      http.get('/api/v1/notifications/status', () =>
        HttpResponse.json({ failing: true, consecutive_failures: 3, last_failure_at: '2026-10-07T09:00:00Z', last_failure_code: 'smtp.connect', last_success_at: null, pending: 2, failed_24h: 0 }),
      ),
    );
    await renderRoute('/account');
    const banner = await screen.findByTestId('notifications-banner');
    expect(banner).toHaveAttribute('role', 'alert');
    expect(banner).toHaveTextContent('E-mails could not be sent');
    expect(banner).toHaveTextContent('smtp.connect');
  });

  it('is not shown to other roles', async () => {
    server.use(...sessionHandlers(operatorSession), http.get('/api/v1/notifications/status', () => HttpResponse.json({ failing: false })));
    await renderRoute('/account');
    await screen.findByRole('heading', { level: 1 });
    expect(screen.queryByTestId('notifications-banner')).not.toBeInTheDocument();
  });
});
```

`web/src/pages/CertificatesPage.test.tsx` gains:

```tsx
  it('reads its filters from the address and writes them back (owner step 3)', async () => {
    const seen: string[] = [];
    server.use(
      ...sessionHandlers(operatorSession),
      targets,
      noCsrs,
      http.get('/api/v1/views', () => HttpResponse.json({ items: [] })),
      http.get('/api/v1/certificates', ({ request }) => {
        seen.push(new URL(request.url).search);
        return HttpResponse.json({ items: [], next_cursor: null });
      }),
    );
    const { router } = await renderRoute('/certificates?expiry=30&target_id=' + targetFixture.id);
    await waitFor(() => expect(seen).toContain(`?target_id=${targetFixture.id}&expiry=30`));
    expect(screen.getByLabelText('Expiry')).toHaveValue('30');
    expect(screen.getByRole('link', { name: 'Export' })).toHaveAttribute('href', `/api/v1/certificates/export?target_id=${targetFixture.id}&expiry=30`);
    await userEvent.selectOptions(screen.getByLabelText('Expiry'), '7');
    await waitFor(() => expect(router.state.location.search).toContain('expiry=7'));
    await waitFor(() => expect(seen.at(-1)).toContain('expiry=7'));
    await userEvent.click(screen.getByRole('button', { name: 'Clear filters' }));
    await waitFor(() => expect(router.state.location.search).toBe(''));
  });
```

(`vi.useFakeTimers({ toFake: ['Date'] })` of the file's `beforeEach` keeps timers real, so the debounce and `userEvent` work.)

`web/src/components/SavedViews.test.tsx`:

```tsx
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { operatorSession, sessionHandlers, targetFixture } from '../test/fixtures';
import { renderRoute } from '../test/render';
import { server } from '../test/server';

describe('SavedViews', () => {
  it('saves the current filters and applies a saved view', async () => {
    let posted: unknown;
    server.use(
      ...sessionHandlers(operatorSession),
      http.get('/api/v1/targets', () => HttpResponse.json({ items: [targetFixture], next_cursor: null })),
      http.get('/api/v1/certificates/csr', () => HttpResponse.json({ items: [] })),
      http.get('/api/v1/certificates', () => HttpResponse.json({ items: [], next_cursor: null })),
      http.get('/api/v1/views', () =>
        HttpResponse.json({ items: [{ id: 'v1', page: 'certificates', name: 'Web 1 soon', query: { expiry: '30', target_id: targetFixture.id }, created_at: '2026-10-07T09:00:00Z' }] }),
      ),
      http.post('/api/v1/views', async ({ request }) => {
        posted = await request.json();
        return HttpResponse.json({ id: 'v2', page: 'certificates', name: 'Expired', query: { expiry: 'expired' }, created_at: '2026-10-07T09:00:00Z' }, { status: 201 });
      }),
    );
    const { router } = await renderRoute('/certificates?expiry=expired');
    await userEvent.click(await screen.findByRole('button', { name: 'Save view' }));
    await userEvent.type(screen.getByLabelText('Name of the view'), 'Expired');
    await userEvent.click(screen.getByRole('button', { name: 'Save view' }));
    await waitFor(() => expect(posted).toEqual({ page: 'certificates', name: 'Expired', query: { expiry: 'expired' } }));
    await userEvent.click(screen.getByRole('button', { name: 'Saved views' }));
    await userEvent.click(await screen.findByRole('menuitem', { name: 'Web 1 soon' }));
    await waitFor(() => expect(new URLSearchParams(router.state.location.search).get('target_id')).toBe(targetFixture.id));
    expect(new URLSearchParams(router.state.location.search).get('expiry')).toBe('30');
  });
});
```

`web/src/hooks/useUrlFilters.test.tsx` (the hook in a tiny route: unknown keys ignored, empty values removed, `clear` empties), `ExportButton.test.tsx` (the `href` for both kinds, empty values dropped, the `download` attribute present), `web/src/api/phase7.test.ts` (each call hits its path; `exportUrl` builds the query) and `SSHKeysPage.test.tsx` (the URL filter test above, for `os_user` and `flag`) are written in the same style.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `make web-test`
Expected: FAIL — `DashboardPage`, `NotificationsBanner`, `SavedViews`, `useUrlFilters`, `ExportButton` do not exist; the labels test misses every new audit action whose Go code is already committed.

- [ ] **Step 3: Write the implementation**

As specified above and in C18. Accessibility: each widget is a `Paper` with a heading (`Title order={2}`), its table inside `Table.ScrollContainer` with an accessible name; colour is never the only signal (badges carry text).

- [ ] **Step 4: Run the tests to verify they pass**

Run: `make web-test && make web-coverage && make web-lint && make i18n-check`
Expected: all pass; the coverage thresholds of `vite.config.ts` hold.

- [ ] **Step 5: Commit**

```bash
git add -- web/src/api/phase7.ts web/src/api/phase7.test.ts web/src/hooks web/src/pages/DashboardPage.tsx web/src/pages/DashboardPage.test.tsx \
  web/src/components/dashboard web/src/components/NotificationsBanner.tsx web/src/components/NotificationsBanner.test.tsx \
  web/src/components/SavedViews.tsx web/src/components/SavedViews.test.tsx web/src/components/ExportButton.tsx web/src/components/ExportButton.test.tsx
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(web): Dashboard with exact counts and links, e-mail failing banner, filters in the address, saved views, CSV export; Phase 7 labels" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- web/src
```

---

### Task 19: Web part 2: Settings (mail, recipients, alerts, general), SSO administration, SSO sign-in, SSO step-up, Users

**Files:**
- Create: `web/src/api/settings.ts`, `web/src/api/sso.ts` (types of C13 and calls), `web/src/navigation.ts` (`goTo(url)`, the one place that leaves the SPA for the identity provider)
- Create: `web/src/pages/SettingsPage.tsx` (tabs `mail`, `recipients`, `alerts`, `general`, `sso` in `?tab=`), `web/src/components/settings/{MailSettings,TrustCertificateDialog,RecipientsSettings,AlertSettings,GeneralSettings}.tsx`, `web/src/components/sso/{SSOSettings,ProviderDialog,MappingsTable}.tsx`, and a `*.test.tsx` for the page and each form
- Modify: `web/src/router.tsx` (`/settings` inside `RequireRole roles={['admin']}`), `web/src/layout/AppLayout.tsx` (`NAV_ITEMS` gains `{ to: '/settings', labelKey: 'nav.settings', roles: ['admin'] }`; an `sso_error` in the address shows the error's texts in an `Alert`, then the parameter is removed)
- Modify: `web/src/pages/LoginPage.tsx`, `LoginPage.test.tsx` (SSO buttons; `?sso_error=`), `web/src/components/StepUpProvider.tsx`, `StepUpProvider.test.tsx` (SSO users confirm at the IdP), `web/src/pages/UsersPage.tsx`, `UsersPage.test.tsx` (the **Single sign-on** badge; no password, MFA or role actions for SSO users), `web/src/api/types.ts` (`User.auth_source`, `User.sso_provider_id`, `SessionInfo` the same), `web/src/test/fixtures.ts` (`ssoSessionFor(role)`)
- Modify: `web/src/locales/en.json`, `web/src/locales/tr.json` (the C18 keys of this task)

**Interfaces:**
- Consumes: C13 (settings, SSO and OIDC routes), C15 (error reasons for the texts), C18, Task 18 (`useUrlFilters` for `?tab=`), `useStepUp`, `ErrorAlert`, `AppModal`, `CodeText`.
- Produces: the Settings page and the SSO sign-in UI the e2e journey uses; accessible names exactly as C18.

```ts
// web/src/navigation.ts
// goTo leaves the single-page app for another site (the identity provider's sign-in page). Tests replace it.
export function goTo(url: string): void {
  window.location.assign(url);
}
```

```ts
// web/src/api/sso.ts (calls; types as C13)
const v1 = '/api/v1';
export const listPublicProviders = () => apiFetch<{ items: { id: string; name: string }[] }>(`${v1}/auth/oidc/providers`, { publicRoute: true });
export const startSSO = (id: string, next: string) =>
  apiFetch<{ authorize_url: string }>(`${v1}/auth/oidc/${encodeURIComponent(id)}/start`, { method: 'POST', body: { next }, publicRoute: true });
export const startSSOStepUp = (next: string) => apiFetch<{ authorize_url: string }>(`${v1}/auth/oidc/stepup`, { method: 'POST', body: { next } });
const ifMatch = (version: number) => ({ 'If-Match': `"${version}"` });
export const listProviders = () => apiFetch<{ items: Provider[] }>(`${v1}/sso/providers`);
export const createProvider = (body: ProviderCreate) => apiFetch<Provider>(`${v1}/sso/providers`, { method: 'POST', body });
export const updateProvider = (id: string, version: number, body: Partial<ProviderCreate>) =>
  apiFetch<Provider>(`${v1}/sso/providers/${encodeURIComponent(id)}`, { method: 'PATCH', body, headers: ifMatch(version) });
export const deleteProvider = (id: string, version: number) =>
  apiFetch<void>(`${v1}/sso/providers/${encodeURIComponent(id)}`, { method: 'DELETE', headers: ifMatch(version) });
export const refreshProvider = (id: string, version: number) =>
  apiFetch<Provider>(`${v1}/sso/providers/${encodeURIComponent(id)}/actions/refresh`, { method: 'POST', headers: ifMatch(version) });
export const listMappings = (providerId: string) =>
  apiFetch<{ items: Mapping[] }>(`${v1}/sso/group-mappings?provider_id=${encodeURIComponent(providerId)}`);
export const createMapping = (body: { provider_id: string; group: string; role: Role }) =>
  apiFetch<Mapping>(`${v1}/sso/group-mappings`, { method: 'POST', body });
export const deleteMapping = (id: string) => apiFetch<void>(`${v1}/sso/group-mappings/${encodeURIComponent(id)}`, { method: 'DELETE' });
export const getSSOSettings = () => apiFetch<{ allow_admin_role: boolean; version: number }>(`${v1}/sso/settings`);
export const saveSSOSettings = (version: number, allow: boolean) =>
  apiFetch<{ allow_admin_role: boolean; version: number }>(`${v1}/sso/settings`, { method: 'PUT', body: { allow_admin_role: allow }, headers: ifMatch(version) });
```

Settings requests send `If-Match` with the version the form was loaded with (`headers: { 'If-Match': `"${version}"` }`); a 412 (`ALC-SYS-0008`) reloads the form and shows `ErrorAlert`. The page opens inside `useStepUp().run(...)` (every `/settings/*` route needs step-up, R42 row 29): its first query is started through `run`, so the code prompt appears once on arrival.

`MailSettings`: fields of C18 (`settings.mail.*`), the password field empty with `settings.mail.passwordKept` when `has_password`; **Save mail settings**; **Send test e-mail** with `settings.mail.testTo` (prefilled with the user's e-mail) → on 200 `settings.mail.testSent`; on `ALC-NTF-0005` it opens `TrustCertificateDialog` showing the fingerprint (`Code`), the subject and the expiry from the error's params, the `errors.notify.smtp_untrusted.action` text, and **Trust this certificate** (posts `actions/trust` with the fingerprint and `If-Match`; then the page sends the test again only when the person clicks **Send test e-mail** again); a trusted certificate is listed with `settings.mail.trusted` and **Stop trusting this certificate**; other errors show in `ErrorAlert` (their C15 texts).

`RecipientsSettings`: the checkbox `settings.recipients.administrators`, a list of address rows (e-mail `TextInput`, language `NativeSelect` English/Türkçe, remove button), **Add address** (disabled at 20), **Save recipients**. `AlertSettings`: a `TagsInput`-free form: one `NumberInput` per threshold with add/remove (1–10 values), **Save alert thresholds**. `GeneralSettings`: `settings.general.publicUrl` (prefilled from `window.location.origin` when empty, with `settings.general.publicUrlHelp`) and `settings.general.retention`; **Save general settings**.

`SSOSettings` (the `sso` tab): the switch `sso.allowAdmin` with `sso.allowAdminHelp` (a refusal to switch off shows `ALC-SSO-0003`'s texts); `sso.mfaNote`; the providers table (name, issuer as `Code`, enabled, **Read the provider's settings again**), **Add identity provider** → `ProviderDialog` (`sso.name`, `sso.issuer`, `sso.clientId`, `sso.clientSecret` (password input; kept unless typed), `sso.groupsClaim` default `groups`, `sso.caPem` (textarea), `sso.enabled`; after saving, `sso.redirectUri` with the address to register at the provider, as `Code` with a copy button); per provider `MappingsTable` (group as `Code`, role label, remove `sso.removeMapping`) and a row to add (`sso.group`, `sso.role` with Administrator, Operator, Auditor; **Map group**); `ALC-SSO-0002` shows its texts next to the form (owner step 5).

`LoginPage`: under the password form, when `listPublicProviders` returns providers, the divider `login.or` and one button per provider `login.ssoWith` (`name`); a click calls `startSSO(id, returnTo)` and `goTo(authorize_url)`; `?sso_error=<reason>` (only a reason of the C15 SSO list is accepted) shows an `Alert` with `errors.<reason>.title` and `.action` above the form.

`StepUpProvider`: when the signed-in user's `auth_source` is `oidc`, the step-up modal shows `stepUp.ssoTitle` and one button `stepUp.ssoAction` (`name` = the provider's name from `listPublicProviders` by `sso_provider_id`) instead of the code field; the click calls `startSSOStepUp(current path and search)` and `goTo(authorize_url)` (the action is retried by the person after returning).

`UsersPage`: SSO users carry the badge `users.sso`; the actions reset password, reset MFA and the role select are not offered for them (the server refuses with `ALC-USR-0003` anyway); disable and enable stay.

- [ ] **Step 1: Write the failing tests**

`web/src/pages/SettingsPage.test.tsx` (the mail flow; the other forms have their own test files in the same style):

```tsx
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { adminSession, sessionHandlers } from '../test/fixtures';
import { renderRoute } from '../test/render';
import { server } from '../test/server';

const smtp = (over: Record<string, unknown> = {}) => ({
  configured: true, host: 'smtp.example.com', port: 587, tls_mode: 'starttls', from: 'alice@example.com', username: 'mailer',
  has_password: true, ca_pem: '', trusted_certificate: null, version: 1, updated_at: '2026-10-07T09:00:00Z', ...over,
});

describe('SettingsPage, mail', () => {
  it('sends a test e-mail and trusts the certificate the server presented (owner step 1, F-62)', async () => {
    let trusted: { body: unknown; ifMatch: string | null } | undefined;
    let tests = 0;
    server.use(
      ...sessionHandlers({ ...adminSession, step_up_until: '2099-01-01T00:00:00Z' }),
      http.get('/api/v1/settings/smtp', () => HttpResponse.json(smtp(), { headers: { ETag: '"1"' } })),
      http.post('/api/v1/settings/smtp/actions/test', () => {
        tests++;
        if (tests === 1) {
          return HttpResponse.json({ error: { code: 'ALC-NTF-0005', reason: 'notify.smtp_untrusted', message_key: 'errors.notify.smtp_untrusted',
            message: '', request_id: 'r', retryable: false, params: { fingerprint: 'ab'.repeat(32), subject: 'CN=smtp.example.com', not_after: '2027-01-01T00:00:00Z' } } },
            { status: 502 });
        }
        return HttpResponse.json({ sent: true });
      }),
      http.post('/api/v1/settings/smtp/actions/trust', async ({ request }) => {
        trusted = { body: await request.json(), ifMatch: request.headers.get('If-Match') };
        return HttpResponse.json(smtp({ version: 2, trusted_certificate: { fingerprint: 'ab'.repeat(32), subject: 'CN=smtp.example.com',
          not_after: '2027-01-01T00:00:00Z', trusted_by: 'ada', trusted_at: '2026-10-07T09:01:00Z' } }), { headers: { ETag: '"2"' } });
      }),
    );
    await renderRoute('/settings?tab=mail');
    await userEvent.click(await screen.findByRole('button', { name: 'Send test e-mail' }));
    const dialog = await screen.findByRole('dialog', { name: "The mail server's certificate is not trusted" });
    expect(dialog).toHaveTextContent('ab'.repeat(32));
    await userEvent.click(screen.getByRole('button', { name: 'Trust this certificate' }));
    await waitFor(() => expect(trusted).toEqual({ body: { fingerprint: 'ab'.repeat(32) }, ifMatch: '"1"' }));
    expect(await screen.findByText(`Trusted certificate: ${'ab'.repeat(32)}`)).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Send test e-mail' }));
    expect(await screen.findByText(/The test e-mail was sent to/)).toBeInTheDocument();
  });

  it('never shows the stored password, and sends one only when typed', async () => {
    let body: Record<string, unknown> | undefined;
    server.use(
      ...sessionHandlers({ ...adminSession, step_up_until: '2099-01-01T00:00:00Z' }),
      http.get('/api/v1/settings/smtp', () => HttpResponse.json(smtp(), { headers: { ETag: '"1"' } })),
      http.put('/api/v1/settings/smtp', async ({ request }) => {
        body = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json(smtp({ version: 2 }), { headers: { ETag: '"2"' } });
      }),
    );
    await renderRoute('/settings?tab=mail');
    expect(await screen.findByText('A password is stored. Leave the field empty to keep it.')).toBeInTheDocument();
    expect(screen.getByLabelText('Password')).toHaveValue('');
    await userEvent.click(screen.getByRole('button', { name: 'Save mail settings' }));
    await waitFor(() => expect(body).toBeDefined());
    expect(body).not.toHaveProperty('password');
  });
});
```

`web/src/components/sso/SSOSettings.test.tsx`:

```tsx
  it('refuses an Admin mapping while SSO users may not be Admin (owner step 5)', async () => {
    server.use(
      ...sessionHandlers({ ...adminSession, step_up_until: '2099-01-01T00:00:00Z' }),
      http.get('/api/v1/sso/settings', () => HttpResponse.json({ allow_admin_role: false, version: 0 }, { headers: { ETag: '"0"' } })),
      http.get('/api/v1/sso/providers', () => HttpResponse.json({ items: [providerFixture()] })),
      http.get('/api/v1/sso/group-mappings', () => HttpResponse.json({ items: [] })),
      http.post('/api/v1/sso/group-mappings', () => errorResponse(409, 'ALC-SSO-0002', 'sso.admin_mapping_disabled')),
    );
    await renderRoute('/settings?tab=sso');
    await userEvent.type(await screen.findByLabelText('Group'), 'alice-admins');
    await userEvent.selectOptions(screen.getByLabelText('Role in Alice'), 'admin');
    await userEvent.click(screen.getByRole('button', { name: 'Map group' }));
    expect(await screen.findByText('A group cannot be mapped to Administrator.')).toBeInTheDocument();
    expect(screen.getByRole('switch', { name: 'SSO users may be Admin' })).not.toBeChecked();
  });
```

(with the file's imports and a `providerFixture()` added to `test/fixtures.ts`.)

`web/src/pages/LoginPage.test.tsx` gains:

```tsx
  it('offers single sign-on and goes to the identity provider', async () => {
    const go = vi.spyOn(navigation, 'goTo').mockImplementation(() => {});
    server.use(
      ...sessionHandlers(null),
      http.get('/api/v1/auth/oidc/providers', () => HttpResponse.json({ items: [{ id: 'p1', name: 'Corp IdP' }] })),
      http.post('/api/v1/auth/oidc/p1/start', async ({ request }) => {
        expect(await request.json()).toEqual({ next: '/' });
        return HttpResponse.json({ authorize_url: 'https://idp.example.com/authorize?state=s' });
      }),
    );
    await renderRoute('/login');
    await userEvent.click(await screen.findByRole('button', { name: 'Sign in with Corp IdP' }));
    await waitFor(() => expect(go).toHaveBeenCalledWith('https://idp.example.com/authorize?state=s'));
  });

  it('explains a refused single sign-on (O-06)', async () => {
    server.use(...sessionHandlers(null), http.get('/api/v1/auth/oidc/providers', () => HttpResponse.json({ items: [] })));
    await renderRoute('/login?sso_error=sso.no_access');
    expect(await screen.findByText('Your account has no access to Alice, contact your administrator.')).toBeInTheDocument();
  });

  it('ignores an unknown sso_error value', async () => {
    server.use(...sessionHandlers(null), http.get('/api/v1/auth/oidc/providers', () => HttpResponse.json({ items: [] })));
    await renderRoute('/login?sso_error=<script>');
    await screen.findByRole('heading', { level: 1 });
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });
```

(Add `import * as navigation from '../navigation'`.)

`web/src/components/StepUpProvider.test.tsx` gains `it('sends an SSO user to the identity provider instead of asking for a code', …)`: a session from `ssoSessionFor('admin')`, an action that answers `ALC-AUTH-0003` once, the modal shows **Continue to Corp IdP**, a click posts `/api/v1/auth/oidc/stepup` with `{ next: <current path> }` and calls `goTo` with the answer's URL.

`web/src/pages/UsersPage.test.tsx` gains `it('marks SSO users and offers no password, MFA or role change for them', …)`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `make web-test`
Expected: FAIL — the Settings page, the SSO components, the login buttons and the SSO step-up do not exist.

- [ ] **Step 3: Write the implementation**

As specified above and in C18. Every form is keyboard usable (labels, `aria-describedby` for help texts, focus returns to the opener when a dialog closes, the `AppModal` behaviour); the client secret and the SMTP password are `PasswordInput`s whose state is cleared after the request; issuer URLs, client IDs, fingerprints and group values are shown with `Code translate="no"`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `make web-test && make web-coverage && make web-lint && make i18n-check`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add -- web/src/api/settings.ts web/src/api/sso.ts web/src/navigation.ts web/src/pages/SettingsPage.tsx web/src/pages/SettingsPage.test.tsx \
  web/src/components/settings web/src/components/sso
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "feat(web): Settings (mail with test and trust, recipients, thresholds, general), SSO providers and mappings, SSO sign-in and step-up" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- web/src
```

---

### Task 20: E2E images: `cmd/alice-fakesmtp`, `cmd/alice-fakeidp`, Dockerfiles, compose services, hardening checks, compose tests

**Files:**
- Create: `cmd/alice-fakesmtp/main.go`, `cmd/alice-fakesmtp/main_test.go`, `cmd/alice-fakeidp/main.go`, `cmd/alice-fakeidp/main_test.go`
- Create: `test/images/fakesmtp/Dockerfile`, `test/images/fakeidp/Dockerfile`
- Modify: `deploy/docker-compose.e2e.yml` (services `fakesmtp`, `fakeidp`; `alice.depends_on` both healthy), `deploy/dev/check-hardening.sh` (a block per service), `cmd/alice/compose_test.go` (`TestE2EFakeSMTPIsTestOnlyAndHardened`, `TestE2EFakeIdPIsTestOnlyHardenedAndLoopbackPublished`, `TestReleaseComposeNeverMentionsTheMailAndIdPFakes`, `TestMailAndIdPFakeDockerfilesReuseTheReleaseBaseImages`), `internal/archtest/buildtags_test.go` (`testOnlyDirs` gains `cmd/alice-fakesmtp`, `cmd/alice-fakeidp`)

**Interfaces:**
- Consumes: C6 (`fakesmtp`, `fakeidp`), the `fakeazure` patterns (`cmd/alice-fakeazure/main.go`: loopback-only admin API, `ctl` talking to loopback only; its Dockerfile's two pinned base images).
- Produces: the e2e services; the `ctl` commands Task 21's helpers call:
  - `alice-fakesmtp ctl ping` → `ok`; `ctl credentials` → `{"username": "mailer", "password": "<generated>"}`; `ctl messages` → the MailHog v2 JSON; `ctl clear`; `ctl down`; `ctl up`; `ctl reject <address>` (`""` clears); `ctl fingerprint` → the leaf's SHA-256 hex.
  - `alice-fakeidp ctl ping`; `ctl credentials` → `{"issuer": "https://idp.alice-e2e.test:9444", "client_id": "alice", "client_secret": "<generated>"}`; `ctl ca` → the CA PEM; `ctl next-user --sub S --username U --name N --email E --groups a,b`; `ctl down`; `ctl up`.

`alice-fakesmtp serve --listen :2525 --api 127.0.0.1:8025 --hostname fakesmtp`: `fakesmtp.New(Options{Hostname, Username: "mailer", Password: <32 random bytes, base64url>})`, `Listen(--listen)`; the admin API on `--api` (refused unless a loopback address) serves `Server.Handler()` (MailHog API) plus `GET /ctl/ping`, `GET /ctl/credentials`, `GET /ctl/fingerprint`, `POST /ctl/down`, `POST /ctl/up`, `POST /ctl/reject` (`{"address": …}`). Port 2525 is above 1024: no sysctl and no capability. `alice-fakeidp serve --listen :9444 --host idp.alice-e2e.test --admin 127.0.0.1:9091 --redirect-prefix https://localhost:`: `fakeidp.New(Options{Host})`, `RegisterRedirectPrefix`, `Listen(--listen)`; the admin API serves `GET /ctl/ping`, `GET /ctl/credentials`, `GET /ctl/ca`, `POST /ctl/next-user` (`fakeidp.Login` as JSON), `POST /ctl/down`, `POST /ctl/up`. Neither logs a secret; both stop on SIGTERM.

`test/images/fakesmtp/Dockerfile` (and `fakeidp` the same with its names):

```dockerfile
# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
# Test-only fake SMTP server for the Phase 7 journeys (compose service fakesmtp of deploy/docker-compose.e2e.yml).
# Never part of a release and never pushed. It holds no key material: its certificate and its SMTP password are
# generated when the container starts (cmd/alice-fakesmtp serve). Both base images are the ones deploy/Dockerfile pins.

FROM golang:1.27.1-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/alice-fakesmtp/ cmd/alice-fakesmtp/
COPY internal/platform/ internal/platform/
COPY internal/testutil/ internal/testutil/
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags "-s -w" -o /out/alice-fakesmtp ./cmd/alice-fakesmtp

FROM gcr.io/distroless/static-debian12:latest@sha256:d75cdd72874d4790092fcb1b058493ecf6bb5bf2b2b897045b00ff01d91843f2
COPY --from=build /out/alice-fakesmtp /alice-fakesmtp
USER 65532:65532
ENTRYPOINT ["/alice-fakesmtp"]
CMD ["serve"]
```

`deploy/docker-compose.e2e.yml` (after `fakeazure`; the comments in the file's style explain why each is test-only):

```yaml
  # Test-only SMTP server for the Phase 7 journeys (web/e2e/phase7.spec.ts): internal/testutil/fakesmtp as a
  # container. STARTTLS with a certificate it generates at start (the journey trusts it through Settings, F-62), AUTH
  # PLAIN with a password it generates (read with "ctl credentials"), a MailHog-compatible message API on loopback
  # inside the container ("docker compose exec fakesmtp /alice-fakesmtp ctl messages"). It publishes nothing.
  fakesmtp:
    image: alice-e2e-fakesmtp
    build:
      context: ..
      dockerfile: test/images/fakesmtp/Dockerfile
    command: ["serve", "--listen", ":2525", "--api", "127.0.0.1:8025", "--hostname", "fakesmtp"]
    user: "65532:65532"
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    mem_limit: 128m
    pids_limit: 128
    ulimits: { core: 0 }
    networks: [backend]
    healthcheck:
      test: ["CMD", "/alice-fakesmtp", "ctl", "ping"]
      interval: 5s
      timeout: 3s
      retries: 10
  # Test-only OpenID Connect provider for the Phase 7 SSO journeys: internal/testutil/fakeidp as a container. The
  # browser (Playwright, through Chromium's --host-resolver-rules) and Alice (through the network alias) both reach it
  # as https://idp.alice-e2e.test:9444, so it is published on loopback only and sits on the frontend network. Its CA is
  # read with "ctl ca" and pasted into the provider form (the feature AD FS customers use); nothing trusts it otherwise.
  fakeidp:
    image: alice-e2e-fakeidp
    build:
      context: ..
      dockerfile: test/images/fakeidp/Dockerfile
    command: ["serve", "--listen", ":9444", "--host", "idp.alice-e2e.test", "--admin", "127.0.0.1:9091", "--redirect-prefix", "https://localhost:"]
    user: "65532:65532"
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    mem_limit: 128m
    pids_limit: 128
    ulimits: { core: 0 }
    ports:
      - "127.0.0.1:9444:9444"
    networks:
      frontend:
        aliases: [idp.alice-e2e.test]
    healthcheck:
      test: ["CMD", "/alice-fakeidp", "ctl", "ping"]
      interval: 5s
      timeout: 3s
      retries: 10
```

and `alice.depends_on` gains `fakesmtp: { condition: service_healthy }`, `fakeidp: { condition: service_healthy }`.

`deploy/dev/check-hardening.sh`: a block per service in the style of the `fakeazure` block — `fakesmtp`: publishes no ports, only `${project}_backend`, read-only root, `["ALL"] null` capabilities, no-new-privileges, a non-root `N:N` user, pids limit 128, healthy; `fakeidp`: publishes exactly `127.0.0.1:9444` (`docker port "$idp"` prints `9444/tcp -> 127.0.0.1:9444` and nothing else), only `${project}_frontend`, and the same remaining checks.

- [ ] **Step 1: Write the failing tests**

`cmd/alice/compose_test.go`:

```go
func TestE2EFakeSMTPIsTestOnlyAndHardened(t *testing.T) {
	overlay := readCompose(t, "../../deploy/docker-compose.e2e.yml")
	fake, ok := overlay.Services["fakesmtp"]
	require.True(t, ok)
	assert.Empty(t, fake.Ports, "the fake SMTP server publishes nothing")
	assert.Equal(t, []string{"backend"}, fake.Networks.names())
	assert.True(t, fake.ReadOnly)
	assert.Equal(t, []string{"ALL"}, fake.CapDrop)
	assert.Empty(t, fake.CapAdd)
	assert.Empty(t, fake.Sysctls, "port 2525 needs no sysctl")
	assert.Equal(t, []string{"no-new-privileges:true"}, fake.SecurityOpt)
	assert.Regexp(t, `^[1-9][0-9]*:[1-9][0-9]*$`, fake.User)
	assert.Positive(t, fake.PidsLimit)
	assert.Equal(t, []string{"serve", "--listen", ":2525", "--api", "127.0.0.1:8025", "--hostname", "fakesmtp"}, fake.Command)
	assert.Equal(t, []string{"CMD", "/alice-fakesmtp", "ctl", "ping"}, fake.Healthcheck.Test)
	assert.Equal(t, "service_healthy", overlay.Services["alice"].DependsOn["fakesmtp"].Condition)
}

func TestE2EFakeIdPIsTestOnlyHardenedAndLoopbackPublished(t *testing.T) {
	overlay := readCompose(t, "../../deploy/docker-compose.e2e.yml")
	fake, ok := overlay.Services["fakeidp"]
	require.True(t, ok)
	assert.Equal(t, []string{"127.0.0.1:9444:9444"}, fake.Ports, "loopback only: the browser reaches it on this host")
	assert.Equal(t, []string{"frontend"}, fake.Networks.names())
	assert.Equal(t, []string{"idp.alice-e2e.test"}, fake.Networks["frontend"].Aliases)
	assert.True(t, fake.ReadOnly)
	assert.Equal(t, []string{"ALL"}, fake.CapDrop)
	assert.Equal(t, []string{"no-new-privileges:true"}, fake.SecurityOpt)
	assert.Regexp(t, `^[1-9][0-9]*:[1-9][0-9]*$`, fake.User)
	assert.Contains(t, fake.Command, "127.0.0.1:9091", "the admin API stays on loopback")
	assert.Equal(t, "service_healthy", overlay.Services["alice"].DependsOn["fakeidp"].Condition)
}

func TestReleaseComposeNeverMentionsTheMailAndIdPFakes(t *testing.T) {
	for _, f := range []string{"../../deploy/docker-compose.yml", "../../deploy/Dockerfile"} {
		raw, err := os.ReadFile(f)
		require.NoError(t, err)
		for _, word := range []string{"fakesmtp", "fakeidp", "idp.alice-e2e.test"} {
			assert.NotContains(t, string(raw), word, f)
		}
	}
}

func TestMailAndIdPFakeDockerfilesReuseTheReleaseBaseImages(t *testing.T) {
	release := dockerfileFroms(t, "../../deploy/Dockerfile")
	for _, f := range []string{"../../test/images/fakesmtp/Dockerfile", "../../test/images/fakeidp/Dockerfile"} {
		for _, from := range dockerfileFroms(t, f) {
			assert.Contains(t, release, from, "%s uses only base images the release build pins", f)
		}
	}
}
```

(`readCompose`, `Networks.names`, `dockerfileFroms` — the helpers `TestFakeAzureDockerfileReusesTheReleaseBaseImages` uses; if the FROM reader has another name there, use it.)

`cmd/alice-fakesmtp/main_test.go` and `cmd/alice-fakeidp/main_test.go`: `TestServeRefusesANonLoopbackAdminAddress`, `TestCtlRoundTrip` (start `serve` on free ports in-process, call each `ctl` command against the admin API, check the JSON answers: credentials, the MailHog list after one message sent with `net/smtp`, `down` refusing connections and `up` accepting them again; for the IdP: `credentials`, `ca` (one CERTIFICATE block), `next-user` then a sign-in through `fakeidp.Server.Authorize` gets that subject).

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./cmd/alice/ ./cmd/alice-fakesmtp/ ./cmd/alice-fakeidp/ ./internal/archtest/`
Expected: FAIL — the services and commands do not exist; `TestBuildTags`-style checks name the two new directories.

- [ ] **Step 3: Write the implementation**

As specified above, following `cmd/alice-fakeazure/main.go` (flag parsing, loopback check, `ctl` client with a 5 s timeout, signal handling, JSON output on stdout, errors on stderr with exit code 1).

- [ ] **Step 4: Run the tests and build the images** (Docker: image builds only; no Playwright running)

Run: `go test -count=1 -race ./cmd/alice/ ./cmd/alice-fakesmtp/ ./cmd/alice-fakeidp/ ./internal/archtest/ && go run ./tools/pincheck`
Expected: `ok` ×4; pincheck silent.

Run (host networking because of this machine's DNS): `docker build --network host -f test/images/fakesmtp/Dockerfile -t alice-e2e-fakesmtp . >/dev/null && docker build --network host -f test/images/fakeidp/Dockerfile -t alice-e2e-fakeidp . >/dev/null && echo built`
Expected: `built`.

Run: `make lint`
Expected: no findings.

- [ ] **Step 5: Commit**

```bash
git add -- cmd/alice-fakesmtp cmd/alice-fakeidp test/images/fakesmtp/Dockerfile test/images/fakeidp/Dockerfile
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "test(e2e): fake SMTP (MailHog-compatible) and fake OIDC provider containers, hardened; loopback-published IdP" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- cmd/alice-fakesmtp cmd/alice-fakeidp test/images/fakesmtp/Dockerfile \
  test/images/fakeidp/Dockerfile deploy/docker-compose.e2e.yml deploy/dev/check-hardening.sh cmd/alice/compose_test.go \
  internal/archtest/buildtags_test.go
```

---

### Task 21: End-to-end: Phase 7 journeys in EN and TR, accessibility (**Docker alone**)

**Files:**
- Create: `web/e2e/phase7.spec.ts`
- Modify: `web/e2e/helpers.ts` (the fakes' helpers below; `COPY[lang].p7` pinned texts of C18 and C14)

**Interfaces:**
- Consumes: the e2e stack (`make e2e-up`: compose project `alice-e2e`, `127.0.0.1:9443` and `127.0.0.1:9444`; images `alice:e2e`, `alice-e2e-sshtarget`, `alice-e2e-fakeazure`, `alice-e2e-fakesmtp`, `alice-e2e-fakeidp`), the helpers `resetInstall`, `runWizard`, `signIn`, `signOut`, `freshCode`, `advanceClock`, `runScheduled`, `apiAs`, `expectAccessibleAt`, `PHONE_WIDTH`, `translator`, `browserLocale`, `uiLang`, `field`, C17's seed answer.
- Produces: `phase7.spec.ts`.

`web/e2e/helpers.ts` gains (beside the Phase 5 Azure helpers, with the same `alice-e2e*` project guard of `composeExec`):

```ts
// --- Phase 7: the fake SMTP server (compose service fakesmtp) and the fake identity provider (fakeidp) ---

export function smtpCtl<T = Record<string, unknown>>(...args: string[]): T {
  return JSON.parse(composeExec('fakesmtp', ['/alice-fakesmtp', 'ctl', ...args])) as T;
}

export interface MailHogMessage {
  Content: { Headers: { Subject: string[] }; Body: string };
  Raw: { To: string[] };
}

export function smtpMessages(): MailHogMessage[] {
  return smtpCtl<{ items: MailHogMessage[] }>('messages').items;
}

export function idpCtl<T = Record<string, unknown>>(...args: string[]): T {
  return JSON.parse(composeExec('fakeidp', ['/alice-fakeidp', 'ctl', ...args])) as T;
}

export function idpCA(): string {
  return composeExec('fakeidp', ['/alice-fakeidp', 'ctl', 'ca']);
}

// seedDashboard inserts C17's data set (POST /test/seed/dashboard, e2e build only) and returns what it must show.
export async function seedDashboard(request: APIRequestContext): Promise<SeedAnswer> {
  const res = await request.post('/test/seed/dashboard', { data: {} });
  expect(res.ok(), `POST /test/seed/dashboard: ${await res.text()}`).toBe(true);
  return (await res.json()) as SeedAnswer;
}

export interface SeedAnswer {
  certificates: Record<'monitored' | 'expired' | 'within_7' | 'within_30' | 'within_60', number>;
  targets: Record<string, number>;
  deployments: { failed_7d: number };
  expiring_30: string[];
  server_filter: { target: string; expiry_30: string[] };
}
```

`web/e2e/phase7.spec.ts` — the journey per language (`for (const lang of ['en', 'tr'] as Lang[])`, as `phase6.spec.ts`), one `test.describe` with:

```ts
// The fake identity provider is https://idp.alice-e2e.test:9444 for Alice (network alias) and for the browser
// (Chromium maps the name to the loopback port compose publishes); nothing else resolves the name.
test.use({
  trace: 'off', video: 'off', screenshot: 'off', // SMTP and client secrets are typed, an export is downloaded
  ignoreHTTPSErrors: true,
  launchOptions: { args: ['--host-resolver-rules=MAP idp.alice-e2e.test 127.0.0.1'] },
});
```

and the steps (each with `COPY[lang]`/`translator(lang)` texts; times read from the server clock):

1. `resetInstall`; `runWizard(page, request, lang, { ...ADMIN, email: 'ada@example.test' }, { license: <a test license as phase6.spec.ts does> })`; `const seeded = await seedDashboard(request)`.
2. **Dashboard (owner step 2, §26.9 "seeded environment shows the expected counts")**: `page.goto('/')`; in `getByTestId('dashboard-counts')` the four links read the counts of `seeded.certificates` (`Expired` 1, `Within 7 days` 2, `In 8 to 30 days` 3, `In 31 to 60 days` 1, translated in TR) and `Certificates in use: 8`; `getByTestId('expiring-list')` rows equal `seeded.expiring_30` in order, the first row has the **Expired** badge; `www.seed.test` is listed **under Expiring soon**; `expectAccessibleAt(page, 'dashboard', [PHONE_WIDTH, 640, 1280, 1920])`.
3. **A filter narrows the list (owner step 3)**: open **Certificates** from the navigation; choose **Within 30 days** in **Expiry** (keyboard: `selectByKeyboard` as `phase6.spec.ts`) → the table lists exactly `old`, `spare`, `api`, `www`, `shop`, `mail`, `intra` (C17); choose the server `seed-web-1` → the table lists exactly `seeded.server_filter.expiry_30`; the address holds `expiry=30` and `target_id=`.
4. **Export equals the filtered rows**: `const [download] = await Promise.all([page.waitForEvent('download'), page.getByRole('link', { name: t('filters.export') }).click()])`; read it into memory (`readDownload`), check the BOM and the header row, compare column `subject_cn` of the rows with the table's names in order; `finally { await download.delete(); }`.
5. **Saved view**: **Save view** → `Web 1 soon` → **Clear filters** (the table grows) → **Saved views** → `Web 1 soon` → the table is again `seeded.server_filter.expiry_30`.
6. **Mail settings and the test mail (owner step 1, F-62)**: **Settings** → step-up code (`freshCode`) → **Email**: `fakesmtp`, `2525`, STARTTLS, `alice@example.test`, user name `mailer`, password from `smtpCtl('credentials').password` → **Save mail settings** → **Send test e-mail** → the dialog **The mail server's certificate is not trusted** shows `smtpCtl('fingerprint')`'s value → **Trust this certificate** → **Send test e-mail** → `The test e-mail was sent to ada@example.test.`; `smtpMessages()` holds one message with the subject `Alice test e-mail` (TR: `Alice test e-postası`); `expectAccessibleAt(page, 'settings-mail', [PHONE_WIDTH, 640, 1280, 1920])`.
7. **An expiring certificate's e-mail (owner step 2, §26.9)**: `runScheduled(request, 'alerts.scan')`, `runScheduled(request, 'notify.send')`; `smtpMessages()` contains exactly one message whose subject is `Certificate expiring: www.seed.test (days left: 7)` (TR from `translator`) whose body contains `www.seed.test` (the website) and the expiry date `YYYY-MM-DD HH:MM UTC` computed from `serverNow` + 7 days − 1 hour; running both tasks again adds no message for it (exactly once).
8. **E-mails could not be sent (owner step 4, F-60)**: `smtpCtl('down')`; `advanceClock(request, 6 * DAY_SECONDS)` (www reaches the 1-day threshold); `runScheduled(request, 'alerts.scan')`; three rounds of `advanceClock(request, 3600)` + `runScheduled(request, 'notify.send')`; reload → `getByTestId('notifications-banner')` shows **E-mails could not be sent** and the dashboard's **Needs attention** lists it; `smtpCtl('up')`; `advanceClock(request, 3600)`; `runScheduled(request, 'notify.send')` → exactly one new message for www (`days left: 1`), and after one more round still exactly one; reload → the banner is gone.
9. **SSO (owner step 5)**: **Settings** → **General**: **Alice's address** is prefilled with the page's origin → **Save general settings**; **Single sign-on**: **Add identity provider** with `Test IdP`, the issuer and client from `idpCtl('credentials')`, the client secret, the CA from `idpCA()`, **Allow sign-in with this provider** → **Save identity provider** → the redirect address is shown; map `alice-admins` to **Administrator** → the refusal text of `ALC-SSO-0002` (`A group cannot be mapped to Administrator.` / TR); map `alice-operators` to **Operator** → listed; `expectAccessibleAt(page, 'settings-sso', [PHONE_WIDTH, 640, 1280, 1920])`.
10. **SSO sign-in**: `idpCtl('next-user', '--sub', 'e2e-omer', '--username', 'omer', '--name', 'Ömer Çelik', '--email', 'omer@example.test', '--groups', 'alice-operators')`; `signOut(page)`; the sign-in page shows **Sign in with Test IdP** (`expectAccessibleAt(page, 'login-sso', [PHONE_WIDTH, 640, 1280, 1920])`); click it → the browser passes the IdP and lands signed in (the dashboard heading); the header shows `Ömer Çelik`; the navigation has no **Users** and no **Settings** (Operator).
11. **Break-glass (X-05)**: `signOut(page)`; `idpCtl('down')`; **Sign in with Test IdP** → the IdP answers with an error page (the browser stays there): go back to `/login`; `signIn(page, request, admin, totpSecret)` → the dashboard; `idpCtl('up')`.

The journey's texts that the contract pins are compared with `translator(lang)` at the start (as Phase 6 does), so a locale drift fails at once.

- [ ] **Step 1: Write the spec** (the journey above; the code below is the file, the helpers `selectByKeyboard` and `readDownload` copied from `phase6.spec.ts` into `helpers.ts` and exported)

```ts
import type { APIRequestContext, Page } from '@playwright/test';
import {
  ADMIN, COPY, PHONE_WIDTH, advanceClock, browserLocale, expect, expectAccessibleAt, field, freshCode, idpCA, idpCtl, readDownload,
  resetInstall, runScheduled, runWizard, seedDashboard, selectByKeyboard, serverNow, signIn, signOut, smtpCtl, smtpMessages, test,
  translator, type Account, type Lang, type SeedAnswer, type Translate,
} from './helpers';

const DAY_SECONDS = 24 * 3600;
const JOURNEY_TIMEOUT = 12 * 60_000;
const WIDTHS = [PHONE_WIDTH, 640, 1280, 1920] as const;
const ADA: Account = { ...ADMIN, email: 'ada@example.test' };

test.use({
  trace: 'off', video: 'off', screenshot: 'off',
  ignoreHTTPSErrors: true,
  launchOptions: { args: ['--host-resolver-rules=MAP idp.alice-e2e.test 127.0.0.1'] },
});

async function tableNames(page: Page, testId: string): Promise<string[]> {
  const rows = page.getByTestId(testId).locator('tbody tr');
  return rows.evaluateAll((trs) => trs.map((tr) => (tr.querySelector('code')?.textContent ?? '').trim()));
}

async function stepUpIfAsked(page: Page, request: APIRequestContext, lang: Lang, secret: string): Promise<void> {
  const dialog = page.getByRole('dialog', { name: COPY[lang].stepUpTitle });
  if (await dialog.isVisible().catch(() => false)) {
    await field(dialog, COPY[lang].stepUpCode).fill(await freshCode(request, secret));
    await dialog.getByRole('button', { name: COPY[lang].stepUpConfirm }).click();
    await expect(dialog).toBeHidden();
  }
}

function mailDate(at: number): string {
  return new Date(at).toISOString().slice(0, 16).replace('T', ' ') + ' UTC';
}

for (const lang of ['en', 'tr'] as Lang[]) {
  const t: Translate = translator(lang);

  test.describe(`Phase 7 alerts, dashboard and SSO (${lang})`, () => {
    test.use({ locale: browserLocale(lang), actionTimeout: 30_000 });
    test.beforeEach(async ({ request }) => {
      await resetInstall(request);
      smtpCtl('clear');
      smtpCtl('up');
      idpCtl('up');
    });

    test('§26.9 Phase 7: dashboard, filter, export, mail, expiry e-mail, failing banner, SSO, break-glass', async ({ page, request }) => {
      test.setTimeout(JOURNEY_TIMEOUT);
      expect(t('notifications.failingTitle')).toBe(COPY[lang].p7.failingTitle);
      expect(t('settings.mail.sendTest')).toBe(COPY[lang].p7.sendTest);
      const { totpSecret } = await runWizard(page, request, lang, ADA);
      const seeded: SeedAnswer = await seedDashboard(request);
      const now = await serverNow(request);

      // Owner step 2: the dashboard's counts and the certificate that expires in 7 days.
      await page.goto('/');
      const counts = page.getByTestId('dashboard-counts');
      await expect(counts.getByRole('link', { name: new RegExp(`${t('dashboard.expired')}.*${seeded.certificates.expired}`) })).toBeVisible();
      await expect(counts.getByRole('link', { name: new RegExp(`${t('dashboard.within7')}.*${seeded.certificates.within_7}`) })).toBeVisible();
      await expect(counts.getByRole('link', { name: new RegExp(`${t('dashboard.within30')}.*${seeded.certificates.within_30}`) })).toBeVisible();
      await expect(counts.getByText(t('dashboard.monitored', { count: seeded.certificates.monitored }))).toBeVisible();
      await expect.poll(() => tableNames(page, 'expiring-list')).toEqual(seeded.expiring_30);
      await expectAccessibleAt(page, 'dashboard', WIDTHS);

      // Owner step 3: a filter narrows the list; the export holds exactly the rows shown.
      await page.getByRole('link', { name: t('nav.certificates'), exact: true }).click();
      const expiry = page.getByLabel(t('certificates.expiry'));
      await expiry.focus();
      await selectByKeyboard(page, expiry, '30');
      await expect.poll(() => tableNames(page, 'certificates-table')).toEqual(
        ['old.seed.test', 'spare.seed.test', 'api.seed.test', 'www.seed.test', 'shop.seed.test', 'mail.seed.test', 'intra.seed.test']);
      await page.getByLabel(t('certificates.server')).selectOption({ label: seeded.server_filter.target });
      await expect.poll(() => tableNames(page, 'certificates-table')).toEqual(seeded.server_filter.expiry_30);
      await expect(page).toHaveURL(/expiry=30/);
      const [download] = await Promise.all([page.waitForEvent('download'), page.getByRole('link', { name: t('filters.export') }).click()]);
      try {
        const text = await readDownload(download);
        expect(text.startsWith('\uFEFF'), 'UTF-8 byte order mark').toBe(true);
        const lines = text.slice(1).trim().split('\n');
        expect(lines[0].startsWith('id,subject_cn,label,')).toBe(true);
        expect(lines.slice(1).map((l) => l.split(',')[1])).toEqual(await tableNames(page, 'certificates-table'));
      } finally {
        await download.delete();
      }

      // Saved view.
      await page.getByRole('button', { name: t('filters.saveView') }).click();
      await field(page.getByRole('dialog'), t('filters.viewName')).fill('Web 1 soon');
      await page.getByRole('dialog').getByRole('button', { name: t('filters.saveView') }).click();
      await page.getByRole('button', { name: t('filters.clear') }).click();
      await page.getByRole('button', { name: t('filters.views') }).click();
      await page.getByRole('menuitem', { name: 'Web 1 soon' }).click();
      await expect.poll(() => tableNames(page, 'certificates-table')).toEqual(seeded.server_filter.expiry_30);

      // Owner step 1, F-62: mail settings, the untrusted certificate, trust, the test e-mail.
      await page.goto('/settings?tab=mail');
      await stepUpIfAsked(page, request, lang, totpSecret);
      const creds = smtpCtl<{ username: string; password: string }>('credentials');
      await field(page, t('settings.mail.host')).fill('fakesmtp');
      await field(page, t('settings.mail.port')).fill('2525');
      await field(page, t('settings.mail.from')).fill('alice@example.test');
      await field(page, t('settings.mail.username')).fill(creds.username);
      await field(page, t('settings.mail.password')).fill(creds.password);
      await page.getByRole('button', { name: t('settings.mail.save') }).click();
      await expect(page.getByText(t('settings.saved'))).toBeVisible();
      await page.getByRole('button', { name: t('settings.mail.sendTest') }).click();
      const trust = page.getByRole('dialog', { name: t('settings.mail.untrustedTitle') });
      await expect(trust.getByText(smtpCtl<{ fingerprint: string }>('fingerprint').fingerprint)).toBeVisible();
      await trust.getByRole('button', { name: t('settings.mail.trust') }).click();
      await page.getByRole('button', { name: t('settings.mail.sendTest') }).click();
      await expect(page.getByText(t('settings.mail.testSent', { to: ADA.email! }))).toBeVisible();
      expect(smtpMessages().map((m) => m.Content.Headers.Subject[0])).toEqual([t('email.notify.test.subject')]);
      await expectAccessibleAt(page, 'settings-mail', WIDTHS);

      // Owner step 2 (e-mail), §26.9: the expiring certificate's e-mail, once.
      await runScheduled(request, 'alerts.scan');
      await runScheduled(request, 'notify.send');
      const subject = t('email.alert.certificate_expiring.subject', { name: 'www.seed.test', days: 7 });
      const wwwMail = () => smtpMessages().filter((m) => m.Content.Headers.Subject[0] === subject);
      expect(wwwMail()).toHaveLength(1);
      expect(wwwMail()[0].Content.Body).toContain('www.seed.test');
      expect(wwwMail()[0].Content.Body).toContain(mailDate(now + 7 * DAY_SECONDS * 1000 - 3600 * 1000));
      await runScheduled(request, 'alerts.scan');
      await runScheduled(request, 'notify.send');
      expect(wwwMail()).toHaveLength(1);

      // Owner step 4, F-60: mail server down, the banner; up again, the e-mail arrives once.
      smtpCtl('down');
      await advanceClock(request, 6 * DAY_SECONDS);
      await runScheduled(request, 'alerts.scan');
      for (let i = 0; i < 3; i++) {
        await advanceClock(request, 3600);
        await runScheduled(request, 'notify.send');
      }
      await page.goto('/');
      await expect(page.getByTestId('notifications-banner')).toContainText(t('notifications.failingTitle'));
      smtpCtl('up');
      await advanceClock(request, 3600);
      await runScheduled(request, 'notify.send');
      const lastDay = t('email.alert.certificate_expiring.subject', { name: 'www.seed.test', days: 1 });
      expect(smtpMessages().filter((m) => m.Content.Headers.Subject[0] === lastDay)).toHaveLength(1);
      await advanceClock(request, 3600);
      await runScheduled(request, 'notify.send');
      expect(smtpMessages().filter((m) => m.Content.Headers.Subject[0] === lastDay)).toHaveLength(1);
      await page.reload();
      await expect(page.getByTestId('notifications-banner')).toHaveCount(0);

      // Owner step 5: SSO provider, the Admin mapping refused, the Operator mapping.
      await page.goto('/settings?tab=general');
      await stepUpIfAsked(page, request, lang, totpSecret);
      await page.getByRole('button', { name: t('settings.general.save') }).click();
      await page.goto('/settings?tab=sso');
      await stepUpIfAsked(page, request, lang, totpSecret);
      const idp = idpCtl<{ issuer: string; client_id: string; client_secret: string }>('credentials');
      await page.getByRole('button', { name: t('sso.addProvider') }).click();
      const dlg = page.getByRole('dialog');
      await field(dlg, t('sso.name')).fill('Test IdP');
      await field(dlg, t('sso.issuer')).fill(idp.issuer);
      await field(dlg, t('sso.clientId')).fill(idp.client_id);
      await field(dlg, t('sso.clientSecret')).fill(idp.client_secret);
      await field(dlg, t('sso.caPem')).fill(idpCA());
      await dlg.getByLabel(t('sso.enabled')).check();
      await dlg.getByRole('button', { name: t('sso.save') }).click();
      await field(page, t('sso.group')).fill('alice-admins');
      await page.getByLabel(t('sso.role')).selectOption('admin');
      await page.getByRole('button', { name: t('sso.addMapping') }).click();
      await expect(page.getByText(t('errors.sso.admin_mapping_disabled.title'))).toBeVisible();
      await field(page, t('sso.group')).fill('alice-operators');
      await page.getByLabel(t('sso.role')).selectOption('operator');
      await page.getByRole('button', { name: t('sso.addMapping') }).click();
      await expect(page.getByText('alice-operators')).toBeVisible();
      await expectAccessibleAt(page, 'settings-sso', WIDTHS);

      // SSO sign-in with the fake identity provider: the Operator role.
      idpCtl('next-user', '--sub', 'e2e-omer', '--username', 'omer', '--name', 'Ömer Çelik', '--email', 'omer@example.test', '--groups', 'alice-operators');
      await signOut(page);
      const ssoButton = page.getByRole('button', { name: t('login.ssoWith', { name: 'Test IdP' }) });
      await expectAccessibleAt(page, 'login-sso', WIDTHS);
      await ssoButton.click();
      await expect(page.getByRole('heading', { name: t('dashboard.title') })).toBeVisible();
      await expect(page.getByText('Ömer Çelik')).toBeVisible();
      await expect(page.getByRole('link', { name: t('nav.users') })).toHaveCount(0);
      await expect(page.getByRole('link', { name: t('nav.settings') })).toHaveCount(0);

      // X-05: the identity provider is down; the local Administrator with the authenticator code signs in.
      await signOut(page);
      idpCtl('down');
      await page.goto('/login');
      await signIn(page, request, ADA, totpSecret);
      await expect(page.getByRole('heading', { name: t('dashboard.title') })).toBeVisible();
      idpCtl('up');
    });
  });
}
```

(`COPY[lang]` gains `p7: { failingTitle, sendTest }` with the C18 texts, and `stepUpTitle`, `stepUpCode`, `stepUpConfirm` if the existing COPY names the step-up dialog's texts otherwise — use the names `phase6.spec.ts`'s `answerStepUp` uses. The CSV comparison splits on commas because every seeded value is comma-free; the header line proves the column order.)

- [ ] **Step 2: Build and start the stack, run the spec** (**Docker alone**: no testcontainers, no other agent using Docker)

Run: `make e2e-up`
Expected: the compose project `alice-e2e` is up and healthy (`--wait`), with `fakesmtp` and `fakeidp` healthy; `curl -sk https://127.0.0.1:9443/livez` → `ok`; `curl -sk --resolve idp.alice-e2e.test:9444:127.0.0.1 https://idp.alice-e2e.test:9444/.well-known/openid-configuration` → JSON with `"issuer":"https://idp.alice-e2e.test:9444"`. If a build cannot download a module (this machine's DNS), prime the images with `docker build --network host` using exactly the `build:` sections of `deploy/docker-compose.e2e.yml` (context `..`, dockerfile, `args`, tagged with the `image:` name), then run `make e2e-up` again.

Run: `make e2e-hardening-check`
Expected: every check passes, including the `fakesmtp` and `fakeidp` blocks.

Run: `cd web && ALICE_E2E_PROJECT=alice-e2e npx playwright test phase7`
Expected: both language journeys pass.

- [ ] **Step 3: Run the whole suite once**

Run: `make e2e`
Expected: all specs pass (Phases 1–7). The Phase 2 and Phase 6 mail checks still read the in-process mailbox (`GET /test/mail`): they never configure mail settings, so the e2e build's fallback mailbox stays in use there.

- [ ] **Step 4: Stop the stack**

Run: `make e2e-down`
Expected: the `alice-e2e` project is removed; the owner's `alice` project is untouched (`docker compose -p alice ps` unchanged — read only).

- [ ] **Step 5: Commit**

```bash
git add -- web/e2e/phase7.spec.ts
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "test(e2e): Phase 7 — seeded dashboard counts, filter, export equals rows, test mail and trust, expiry e-mail in the fake SMTP, failing banner, SSO with the fake IdP, break-glass (EN, TR)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- web/e2e/phase7.spec.ts web/e2e/helpers.ts
```

---

### Task 22: Coverage floors, documentation, R42, security review, rulings, CHANGELOG, the perf ruling, `make ci` (**Docker alone**)

**Files:**
- Modify: `coverage-floors.json`
- Modify: `docs/admin-guide.md` (new sections "Dashboard", "Alerts and e-mail" — recipients, thresholds, what is alerted and what is not monitored, the license note, the failing banner — "Mail server" — Settings → Email, the test e-mail, trusting a certificate, the CA bundle — "Single sign-on" — Entra ID, AD FS, Keycloak set-up with the redirect address, the groups claim (Entra object IDs, AD FS `group` or `http://schemas.xmlsoap.org/claims/Group`, Keycloak group paths), the overage advice, "SSO users may be Admin", MFA at the IdP as a customer requirement, step-up through the IdP, break-glass — "Saved views and export"), `docs/operator-guide.md` ("Email" rewritten: Settings replaces `ALICE_SMTP_*`, the one-time import and the warning; `alerts.scan` in "Background jobs"; `setting_secrets` in "Master-key rotation"; the fake e2e services in the development notes; `make perf`), `docs/troubleshooting.md` (the FAQ lines "No e-mails arrive", "SSO sign-in refused" pointing to the code sections; the new audit actions in its action list), `docs/first-run.md` (mail and SSO are in Settings)
- Modify: `CHANGELOG.md` (a "Phase 7 — Alerts, dashboard and SSO" entry with **Upgrade notes**)
- Modify: `docs/superpowers/specs/alice-v1/00-decisions.md` (**R42**), `docs/superpowers/specs/alice-v1/06-quality.md` (one pointer line after §26.9 naming the tests), `docs/superpowers/specs/alice-v1/04-security.md` (one pointer line after §15.3: "(Phase 7, R42: …)")
- Create: `docs/security/reviews/phase-7.md`, `docs/superpowers/rulings/phase-7.md`
- Modify: `Makefile` (only if the perf ruling adds `perf` to `ci`)

**Interfaces:**
- Consumes: everything.
- Produces: the phase close.

- [ ] **Step 1: Coverage floors** (**Docker alone**: `make coverage` starts testcontainers)

Run: `make coverage`
Expected: every existing floor holds (`internal/notify` ≥ 85, `internal/auth` ≥ 84, `internal/inventory` ≥ 89, `internal/jobs` ≥ 89, `internal/audit` ≥ 89, `internal/sshkeys` ≥ 89, `internal/api` ≥ 94, `cmd/alice` ≥ 90, `internal/rbac` ≥ 98, `internal/secrets` ≥ 83). Then add to `coverage-floors.json`: `"alice/internal/alerts/expiry": 100`, `"alice/internal/auth/oidc/claims": 100`, `"alice/internal/platform/csvx": 100`, and `alice/internal/alerts`, `alice/internal/reports`, `alice/internal/auth/oidc`, `alice/internal/testutil/fakesmtp`, `alice/internal/testutil/fakeidp` at their measured values rounded down; raise any existing floor whose measured value rose by a whole point. Run `make coverage` again: PASS.

- [ ] **Step 2: The performance ruling** (**Docker alone**)

Run `make perf` three times in a row, nothing else running. Record the ten p95 values of each run in the rulings document. Ruling: if every run passes with every p95 at most 60 % of its budget, add `perf` to the first line of `ci` (`$(MAKE) lint test coverage perf test-ssh …`) — the margin absorbs CI noise; otherwise keep it outside `ci` and add it to the release checklist (`docs/superpowers/specs/alice-v1/04-security.md` §17.7 pointer line "`make perf` passes (R32)") with the times as the reason. Either way R42 row 26 states the outcome.

- [ ] **Step 3: Guides, troubleshooting, changelog**

Write the guide sections listed above in the style of the existing ones (plain language, the exact button names of C18). `CHANGELOG.md`:

```markdown
## Unreleased — Phase 7: Alerts, dashboard and SSO

**Upgrade notes**
- Migration `00011` runs at start (alert ledger, settings secrets, saved views, identity providers, SSO users, sign-in states). Once a notice, a saved view, a provider or an SSO user exists, it refuses to go down.
- **Mail settings move to Settings → Email.** At the first start, `ALICE_SMTP_*` (with `ALICE_SMTP_PASSWORD_FILE` and `ALICE_SMTP_CA_FILE`) are imported once; afterwards they are ignored with a warning in the log — remove them from `deploy/.env`. The password is stored encrypted in the database.
- **Alert recipients**: every e-mail Alice sends to administrators now goes to the recipients of Settings → Recipients (by default every administrator with an e-mail address, as before).
- The first expiry check after the upgrade sends one notice for each certificate in use, Key Vault certificate, key and client secret that has already reached a threshold (only the most urgent one), at most 20 per kind plus a summary.
- No helper change: `alice-helper` stays at protocol 6 (1.5.0).

### Added
- Dashboard: expiring soon (expired ones marked), failed deployments of the last 7 days, servers and vaults by status, license, upcoming rotations, needs attention, and the audit log's last verified head for offline recording.
- Expiry e-mails for certificates in use, Key Vault certificates, keys and client secrets at 60/30/14/7/1 days (editable) and once expired; exactly once per threshold; in lock with the license note.
- Settings: Email (test e-mail, trust this certificate, CA bundle), Recipients, Alerts, General (Alice's address, retired-key retention).
- Retries of e-mail for 24 hours and the "E-mails could not be sent" banner; the sign-in lockout e-mail.
- Filters in the address, saved views and CSV export (formula-safe, audited) for certificates and SSH keys; certificate filters for 7, 14 and 90 days and Key Vault.
- Single sign-on with OpenID Connect (Entra ID, AD FS, Keycloak): group mappings, "SSO users may be Admin" (off by default), step-up at the identity provider, break-glass with the local administrator.
- Codes `ALC-NTF-0002..0009`, `ALC-SSO-0001..0016`, `ALC-RPT-0001..0003`, `ALC-USR-0003`; `make perf` (R32).

### Changed
- The Home page is the Dashboard. The outbox retries for 24 hours instead of 10 attempts. Key Vault polls read stored versions in one batch.

### Security
- SMTP passwords and OIDC client secrets only as envelopes (`setting_secrets`); PKCE S256, single-use state and nonce bound to the browser; users matched by issuer and subject, never linked to local accounts; every SMTP and OIDC connection through the address rule.
```

- [ ] **Step 4: R42, the spec pointers, the rulings**

`00-decisions.md`: append **R42** (Phase 7, approved with the Phase 7 plan; corrected to the built code at the end of Phase 7) with items 1–30 = the rows of "Spec conflicts resolved by this plan" as built, and an addendum for the decisions made while building (from the task reports and the controller's rulings). `06-quality.md`, after §26.9: "(Phase 7, R42: the named tests are `TestHourlyTicksSendEachThresholdOnce`, `TestDowntimeSendsOnlyTheMostUrgent`, `TestScanIsExactlyOncePerThreshold`, `TestConcurrentScansQueueOnce`, `TestL28LockNote`, `TestL18NoSMTP`, `TestF60OutageDeliversOnceAndRaisesFailing`, `TestF61PerRecipient`, `TestF62UntrustedCertificateAndThePin`, `TestSMTPPasswordIsAnEnvelope`, `TestMailSettingsOverTheWire`, `TestSummaryCountsMatchTheDatabase`, `TestDashboardOverTheWire`, `TestExportOverTheWireEqualsFilteredRows`, `TestO01Signatures` to `TestO14LocalMFANotBypassed` (Task 12), `TestOIDCNegativeSuiteOverTheWire`, `TestX05BreakGlassWhileIdPDown`, `TestR32DashboardAndListBudgets` (`make perf`); the end-to-end journeys are `web/e2e/phase7.spec.ts`. Owner steps 1–5 are the empty walkthrough table of `docs/security/reviews/phase-7.md`.)". `docs/superpowers/rulings/phase-7.md`: the controller's rulings during execution, in the format of `phase-6.md` (before the tasks, per area, final review, process, status at phase close, carried to later phases — the re-deferred carries of this plan's "Carries and deferred items" with their reasons, and the perf ruling of Step 2).

- [ ] **Step 5: Security review**

`docs/security/reviews/phase-7.md` in the format of `phase-6.md`: Method; **Evidence** table (rows for `make test`, `make test-integration`, the O-suite count, `make perf` (three runs), `make e2e`, `make coverage`, `make ci`, `make secrets-scan`, `make vuln`, `make fs-scan`; cells marked `PENDING-FINAL-RUN` until Step 6 fills them); **Threat notes** (§17.2 Phase 7 gate: the OIDC flow SEC-010..SEC-015 — state, nonce, PKCE, binding cookie, issuer and audience, the bounded key set, algorithm restriction, `next`; e-mail header injection — every parameter flattened, subjects Q-encoded, the recipient list; output escaping — CSV formula injection, XSS in dashboard and settings (React text only); notification content leaks — what each e-mail names; the SMTP trust decision and the pin; secrets of settings at rest; SSRF of SMTP and OIDC through `netaddr`; the exactly-once ledger; the role filtering of the dashboard); **Review checklist** (§17.2 Phase 7 gate: "OIDC test suite passes; no secrets in emails; XSS tests on all rendered strings"); **Findings** (with severities; no open High); **Known limitations** (at least: Go strings — the `oauth2.Config` client secret, `smtp.PlainAuth`'s password string — cannot be cleared (P4-04 extended); `setting_secrets` must be re-wrapped by a future master-key rotation; a group removed at the IdP keeps an open session until it ends (up to 12 hours) unless the user signs in again or is disabled (R42 row 21); no Graph lookup for Entra overage (row 20); no plaintext SMTP; a renewed self-signed mail server certificate must be trusted again; uploaded certificates on no server are not alerted (row 4); a notice skipped by downtime is never sent (row 5); one bad recipient can raise the failing banner (row 8); the audit chain is still unkeyed and `jobs.audit_verify` writable by `alice_app` (carry 17, Phase 8); `auth.oidc.denied` rows are not coalesced (carry 12); emails show UTC (row 10); views are private (row 15); the e2e IdP is reached by the browser through Chromium's host-resolver rule only); **Owner verification** — the empty table of §26.9 owner steps 1–5:

| # | Step (§26.9) | Expected | Result | Date | Notes |
|---|---|---|---|---|---|
| 1 | Enter the mail server in Settings and click "Send test e-mail" | The e-mail arrives (an untrusted certificate is shown with its fingerprint and can be trusted) | | | |
| 2 | A certificate that expires in 7 days | The dashboard lists it under "Expiring soon"; an e-mail with the website name and the date arrives | | | |
| 3 | Filter: expiring within 30 days, then one server; click "Export" | The file contains exactly the rows shown | | | |
| 4 | Turn the mail server off and wait for the next alert; turn it on | "E-mails could not be sent" on the dashboard; afterwards the e-mail arrives once | | | |
| 5 | Configure SSO with a test identity provider; map a group to "Operator"; sign in through SSO; try mapping a group to "Admin"; take the IdP down and sign in locally | Operator role; the Admin mapping is refused until "SSO users may be Admin" is on; the local administrator with the authenticator code signs in | | | |

and **Sign-off** (empty).

- [ ] **Step 6: `make ci`** (**Docker alone**, no other Docker user at all; Playwright not running)

Run: `make ci TRIVY_IMAGE="--network host aquasec/trivy:0.74.0@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969"`
Expected: exit code 0 (the image reference is the Makefile's pinned `TRIVY_IMAGE`; if a task changed the pin, use the new value verbatim). Fill the Evidence cells with the results and the commit hash.

- [ ] **Step 7: Commit**

```bash
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "docs: Phase 7 — guides, troubleshooting, changelog, R42 and spec pointers; coverage floors; the perf ruling" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- coverage-floors.json docs/admin-guide.md docs/operator-guide.md \
  docs/troubleshooting.md docs/first-run.md CHANGELOG.md docs/superpowers/specs/alice-v1/00-decisions.md \
  docs/superpowers/specs/alice-v1/06-quality.md docs/superpowers/specs/alice-v1/04-security.md Makefile
git add -- docs/security/reviews/phase-7.md docs/superpowers/rulings/phase-7.md
git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only \
  -m "docs(security): Phase 7 review with the owner verification table; controller rulings" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- docs/security/reviews/phase-7.md docs/superpowers/rulings/phase-7.md
```

---

## Self-review (done while writing this plan)

1. **Spec coverage (§26.9 item by item).** Deliverables: expiry alert engine — Tasks 1 and 8 (certificates in use, Key Vault certificates, keys and client secrets), with license, host key change, failed deployments and integrity problems kept at their owners and listed by the dashboard (Task 9, R42 rows 2–3); recipients and thresholds settings — Tasks 7, 8, 14, 19; templates EN/TR with the license note — Tasks 6, 7, 14 (C14); deduplication and retries — Tasks 1, 7, 8; dashboard with its five widgets — Tasks 9, 14, 18 (R42 row 14 defines each count); filters and saved views — Tasks 10, 18 (R42 rows 15, 17); CSV export — Tasks 3, 10, 14, 18 (R42 row 16); scheduled audit chain verification — existing since Phase 3, surfaced by Tasks 9 and 18 (R42 row 27); OIDC SSO with mappings, the Admin switch off by default, MFA delegated — Tasks 2, 11, 12, 15, 19 (R42 rows 18–24). Tests that must pass: thresholds with the fake clock, no duplicates, catch-up — Tasks 1 and 8; F-60..F-63 — Tasks 6, 7, 16; L-28 and L-18 — Task 8; dashboard API with seeded data and exact counts — Tasks 9, 13, 16; Vitest for widgets and filters — Task 18; E2E EN/TR (counts, filter, e-mail in the fake SMTP, export equals rows, SSO with the fake IdP) — Tasks 20, 21; O-01..O-14 and X-05 — Tasks 2, 12, 16; performance R32 — Task 17 with the ruling of Task 22. Owner steps 1–5 — the table of Task 22. Exit criteria — Tasks 8, 9, 12, 16, 17, 22. Spec items deliberately not built are rows of "Carries and deferred items" (1, 6, 9, 11–13, 17–25) or R42 rows (20, 21, 27).
2. **Placeholders.** None intended: every step names files, code or exact contracts, commands and expected output. Where a step must read existing code first (harness helper names, the existing COPY keys of the step-up dialog, the `checkpoint` struct's field names), it names the file and the behaviour to keep. The web Tasks 18–19 give the full code of the hooks, calls and the tests that pin the contract; the component layout is specified by its texts, test IDs and behaviours.
3. **Type consistency.** Names used across tasks are defined once in the contract: `expiry.{Normalize, Level, Due, DaysLeft, Horizon, BucketOf, DefaultThresholds, Expired}` (C3); `claims.{Claims, Parse, Expect, Validate, Error, Reason*, Groups, ErrOverage, Mapping, ResolveRole, ValidateMapping, SafeNext, ValidateIssuer, Username, Leeway}` (C4); `csvx.{Safe, NewWriter, Writer}` (C5); `fakesmtp.*`, `fakeidp.*` (C6, with `RegisterRedirectPrefix` and `Client`); `notify.{Settings, SettingsConfig, SMTPSettings, SMTPInput, CertInfo, CertError, TrustedCert, Recipients, Address, Delivery, MailerSource, ErrNotConfigured, ErrVersion, ErrCertNotSeen, ErrAddressRefused, ErrSMTPUntrusted, GiveUpAfter, FailingAfter}` and `settings.{General, GetGeneral, GeneralKey}` (C7); `alerts.{Service, Kind*, Item, Counts, ThresholdSettings, ScanResult, Scan, Items, Counts, Thresholds, SaveThresholds, Templates, ScanEvery, MaxEmailsPerScan}` (C8); `reports.{Service, Viewer, Summary, Condition, Expiring, Attention, ExportCertificates, ExportSSHKeys, View, Views, CreateView, DeleteView, ViewQueryKeys, MaxExportRows (50,000), ErrTooLarge, ErrViewLimit, ErrViewName, ErrNotFound}`, `audit.{Checkpoint, LastCheckpoint, ActorOIDC}`, `jobs.{AuditVerifyState, ReadAuditVerifyState, AlertsScan}` (C9, C10, C12); `auth.{OIDCIdentity, SignInOIDC, StepUpOIDC, RefuseOIDC, DemoteSSOAdmins, ErrOIDCEmailInUse, ErrOIDCUserDisabled, ErrOIDCOtherUser, ErrNotSSOUser, ErrSSOUser, TemplateLockout, Templates, Notifier}` (C10); `oidc.{Service, Provider, ProviderInput, ProviderPatch, PublicProvider, Mapping, SSOSettings, DiscoveryError, LoginError (Reason, StepUp, Next), Begin, BeginInput, Completion, Complete, PruneStates, RedirectURI, SigningAlgs, StateLifetime, StepUpMaxAge, JWKSRefetchEvery}` (C11); `seed.{Target, Certificate, MoveLocations, KeyVault, Deployment, SetStatus, Dashboard, DashboardAnswer, ServerFilter}` (Tasks 8, 9, 13); `rbac.SSOManage` and the routes, limits and codes of C1, C13, C15. A check made while writing: the dashboard's exclusive buckets (C3 `BucketOf`, R42 row 14) and the certificate list's cumulative windows (R42 row 17) are different on purpose — the dashboard's links go to the list's windows, and C17 lists both.
4. **Review Focus.** The five items each name the tests that pin them in their owning tasks: 1 → Tasks 2, 12, 16; 2 → Tasks 1, 7, 8; 3 → Tasks 6, 7, 12, 14, 15, 16; 4 → Tasks 3, 10, 16, 21; 5 → Tasks 9, 14, 15, 16.
