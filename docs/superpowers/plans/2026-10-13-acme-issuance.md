# ACME Certificate Issuance and Renewal — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. One review per task, one whole-branch review at the end.

**Goal:** Alice requests, renews and deploys certificates from an ACME CA (Let's Encrypt, ZeroSSL, step-ca, EJBCA ACME, ACME gateways) for Nginx targets, without Azure Key Vault, and without weakening air-gap, secrecy, audit, licensing or the verified Nginx deploy sequence.

**Architecture:** An `internal/acme` package (RFC 8555 client wrapped around `golang.org/x/crypto/acme`, challenge solvers, ARI lookup, key/CSR generation) is driven by two job types and one periodic planner registered in `internal/jobs`. An issued chain becomes an ordinary `certificates` row (`source='acme'`) whose private key is a sealed `managed_private_keys` row, so it is deployed by the existing `inventory.RequestDeployment` → `deployjobs` → `nginx.DeployCertificate` path (same `deployments` rows, same rollback, same audit rows). Renewal auto-deploy copies the Key Vault planner (`PlanKVAutoDeploy`) pattern, with trigger `acme_renewal`. Account keys, EAB HMAC keys and DNS-hook secrets are sealed with `secrets.Keyring` and live in tables the backup dump already carries.

**Tech Stack:** Go 1.27.2, `golang.org/x/crypto/acme` (already a direct dependency at v0.57.0; **no new module**), PostgreSQL migration `00013`, React/Mantine UI, Playwright. New test tool `cmd/alice-fakeacme`.

**Spec:** `docs/superpowers/specs/alice-v1/{00-decisions,01-product,02-architecture,03-integrations,04-security,05-operations,06-quality}.md`, rulings in `docs/superpowers/rulings/`, `docs/authz-matrix.md`, `api/openapi.yaml`, `docs/design-gaps.md`, `alice-design/IMPLEMENTATION.md`. Facts below were read from the code on master `f369b83` by research agents (no tests run); each task re-verifies the facts it relies on.

**Plan verification:** written on branch `acme-issuance` from master `f369b83`. Review: Task 0 includes a plan-review gate before any code.

## Global Constraints

- Branch `acme-issuance` from master. Merge to master **fast-forward only**. No squash, rebase or amend (`.gitleaksignore` is pinned to commit hashes). **Never push.**
- Commits: Conventional Commits via `git -c user.name="Eren Altan" -c user.email=erenaltan@gmail.com commit --only <files> -m ...` with the `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>` trailer.
- Never read, edit, move or commit `docs/security/reviews/independent-audit-2026-10-04*`, `docs/security/reviews/outsider-multiagent-review-2026-10-12.md` or `.claude/`.
- Docker: never touch compose project `alice` / image `alice:dev` / volumes `alice_*`. E2E stack is project `alice-e2e` on 127.0.0.1:9443. `docker build --network host`. No testcontainers / `make coverage` / `make test-ssh` while Playwright runs. Long commands (`make ci` ≈ 40 min, e2e ≈ 25 min, `make coverage` ≈ 12 min) run in the background.
- **Air-gap:** no network call exists unless an Admin created an ACME provider (or a DNS hook). No preset is contacted until then. No telemetry, no update check, no OCSP/CRL fetch. Proxy variables stay ignored (carry, see below).
- **Secrets** (account key, EAB HMAC, DNS-hook bearer/HMAC secret, certificate private keys) are sealed with `secrets.Keyring.Seal` with a `Location{table,row,column}`, are `secrets.Plaintext` in memory (zeroed after use), never returned by the API, never in logs, audit details, job payloads, error text or the query cache. Audit-key denylist tests are extended.
- Every mutating action writes a hash-chained audit row. Roles: Admin / Operator / Auditor only. `docs/authz-matrix.md` is regenerated with `make authz-doc` and `expectedMatrix` rows are added by hand.
- Licensing: only managed targets count. ACME objects never count. In lock: `acme.schedule` / `acme.auto_deploy` tasks are paused by the scheduler gate; user routes that contact a CA or a target are `lic: ClassChange` and answer 403 `license.locked` (`ALC-LIC-0001`); the planner also calls `license.Allow(ClassChange)` itself like `PlanKVAutoDeploy`.
- Deployment reuses `inventory.RequestDeployment` / `insertDeployment`; **no second deploy path**. The only helper change allowed is Task 15 (HTTP-01 webroot), justified there.
- Error codes `ALC-ACM-NNNN`, registered in `internal/api/errors.go`, `locales/common/{en,tr}.json` (`errors.<reason>.{title,cause,action}`), `docs/troubleshooting.md`, and a pinned table test in the `errors_phase8_test.go` style.
- All user-facing text exists in `locales/common` and `web/src/locales` in en + tr (formal "siz"), written for non-technical readers; `make i18n-check` green.
- New package floors in `coverage-floors.json` are **added** (never lowered). `tools/pincheck` passes: any new image is digest-pinned. `StrictHostKeyChecking=no` appears nowhere. `InsecureSkipVerify` appears nowhere new (ACME verifies the CA with system roots + the provider's bundle; a guard test in `internal/acme` forbids it).
- Frontend: Phase 9 rules (Clarity tokens, one `<h1>`, 3 px focus ring, status = text + icon + color, no literal colors, `useStepUp().run`, no `dangerouslySetInnerHTML`, web coverage thresholds unchanged).

## Review Focus

1. **Secrets leaving the vault:** any path where an account key, EAB key, hook secret or issued private key reaches a log, audit row, API body, job payload, error string, or backup *unsealed*.
2. **Second deploy path:** nothing outside `inventory.RequestDeployment` may write to a target. The HTTP-01 helper command writes only a token file under a fixed root.
3. **SSRF through the CA directory URL and DNS hook URL:** every dial goes through `netaddr`, with redirects off, response size caps and timeouts.
4. **Licence lock:** no CA contact, no deploy, no planner activity in lock; user routes answer `license.locked`.
5. **Renewal safety:** a failed deploy rolls back and the old certificate keeps being served (integration + e2e proof); renewal cannot loop against CA rate limits.
6. **Helper change (Task 15)** — path confinement, token charset, size cap, root-only suites.

## Design decisions (answers to the nine questions)

| # | Question | Decision | Trade-off |
|---|----------|----------|-----------|
| 1 | Challenge types | **DNS-01 through an admin-configured webhook** (v1, also the only route for wildcards) and **HTTP-01 through a webroot token file** written by `alice-helper` into a fixed directory the admin has already published in Nginx (Task 15). **TLS-ALPN-01 is rejected**: it needs an `ssl_preread`/stream listener, i.e. nginx config edits. Alice never edits nginx config: the host-preparation guide gives the admin a 3-line `location /.well-known/acme-challenge/ { root /var/www/alice-acme; }` snippet to add themselves; Alice only drops and removes one token file (`AC3`, `03-integrations.md:373`). | A webhook is generic and air-gap friendly (works with an internal DNS automation, RFC 2136 proxy, PowerDNS API wrapper) but the customer must run a small endpoint; a built-in provider list (Cloudflare, Route53…) would add vendor code, secrets and outbound hosts, and is rejected for v1. Built-in RFC 2136 is a follow-up (needs a DNS library). |
| 2 | Where validation happens | The **ACME protocol conversation runs on the Alice server** (one place for account key, CA trust, rate limits, audit). Only the *publication* of a challenge touches the world: DNS-01 → webhook call from Alice; HTTP-01 → helper token write on the target that the domain points at. | Running the whole client on the target would put the account key on every host and need a large helper protocol; the chosen split needs one small helper bump (protocol 6 → 7) and only for HTTP-01. If Task 15 slips, DNS-01 ships alone and HTTP-01 is recorded as a carry. |
| 3 | Air-gap CAs, custom trust, EAB | `acme_providers` row = name, directory URL, optional **CA bundle PEM** (public certificate; appended to the system roots as `oidc` does, `internal/auth/oidc/httpclient.go`), optional **EAB key id + HMAC** (sealed), preset (`letsencrypt`, `letsencrypt_staging`, `zerossl`, `custom`) that only pre-fills the form. Outbound transport = `internal/acme/transport`: `Proxy: nil`, no redirect, `netaddr.DialContext`, 1 MiB body cap, 30 s budget, `https` only. The "proxy/custom CA" carry (rulings phase-5:170, phase-7:336) is **partly closed**: a CA bundle for ACME and for the hook; HTTPS proxy support stays a carry. | No proxy means public-CA customers behind a forward proxy cannot use Let's Encrypt in v1 (documented; same as Azure). |
| 4 | Account lifecycle | One account per provider. ECDSA P-256 account key generated by Alice (`crypto/rand`), sealed in `acme_accounts.key_*` with AAD `acme_accounts/<id>/key`. Registration requires the Admin to tick a ToS box that shows the directory's `termsOfService` URL; the audit row `acme.account.registered` records provider, ToS URL, contact, whether EAB was used, never keys. **Key rotation** uses `client.AccountKeyRollover` (RFC 8555 §7.3.5, present in x/crypto v0.57.0): new key sealed as a new row, old row kept `retired` until the CA confirms. **Deactivate** = `DeactivateReg`. Backup/restore: the tables are in the dump; the master key is in the backup; Task 1 adds a round-trip test and Task 19 runs `make test-backup-cycle`. | Rollover is atomic at the CA; if the CA lacks `keyChange`, the UI offers "register a new account" instead. |
| 5 | Library | **`golang.org/x/crypto/acme`**. Already a direct dep, BSD-3, no transitive growth, covers orders, EAB, rollover, deactivate, alternates, DNS-01/HTTP-01/TLS-ALPN-01 helpers, and takes an injectable `HTTPClient`. **lego** rejected: ~100 DNS-provider modules, large osv/notices surface, vendor outbound hosts. **Hand-rolled** rejected: JWS/nonce/`badNonce` retry bugs are exactly what the library already handles; we only hand-write **ARI** (RFC 9773 GET, ~60 lines, fuzzed), because v0.57.0 has no `RenewalInfo`. All use is behind `internal/acme.Client` so the library can be swapped. | Library lacks a high-level "obtain" loop: ~300 lines of order orchestration in `internal/acme/order.go`. |
| 6 | Renewal scheduling | Per certificate `renew_before_days` (default **30**, 1–60). Renew when `now ≥ not_after − min(renew_before, lifetime/3)` (so 90-day, 47-day and 6-day certificates all behave). **ARI:** if the directory has `renewalInfo`, use its suggested window start (never later than the rule above); if ARI fails, fall back silently. Failure backoff per certificate: 1 h, 2 h, 4 h … capped 24 h; `Retry-After` and `urn:ietf:params:acme:error:rateLimited` push `next_attempt_at`; after 3 consecutive failures an e-mail via `notify.AdminNotifier.NotifyAdmins` (`acme.renewal_failed`) and after `AutoDeployMaxFailed`-style stop (5) the auto-renew is stopped with `acme.auto_renew.stopped`. Expiry alerts need no change: the issued certificate is a normal monitored certificate once it has a location. Jobs: periodic `acme.schedule` (ReadOnly task, every minute, leader only, paused in lock) enqueues `acme.issue` (ClassChange job, 1 attempt: retries are owned by `next_attempt_at`, not the job queue); `acme.auto_deploy` (ReadOnly task, plans deployments under `Allow(ClassChange)`). | One attempt per job avoids hidden queue retries multiplying CA requests. |
| 7 | Binding model | `acme_certificates` (the ordered identity: provider, domains, key type, challenge, hook, renew window, auto_deploy, state, last/next attempt) and `acme_bindings(acme_certificate_id, location_id, auto_deploy)`. A successful order inserts a `certificates` row (`source='acme'`, `private_key_id` → a new sealed `managed_private_keys` row, new key per issuance by default) and links `acme_certificates.current_certificate_id`. Auto-deploy / "Deploy now" calls the **same** `insertDeployment` as manual requests with trigger `acme_renewal`, wave limits and stop-after-3 copied from `kv_autodeploy_plan.go` (`AutoDeployWave=5`). Key policy: ECDSA P-256 default, RSA 2048/3072/4096 optional, ECDSA P-384 optional. | Deploy waves reuse proven limits; `certificates.source` CHECK and `deployments.trigger` CHECK are extended by the migration. |
| 8 | UI | Settings → **Certificate authorities** (providers, accounts, hooks; Admin). New nav item **Issued certificates** (`/acme`, Admin+Operator write, Auditor read) with a list, a status page (`/acme/:id`: state, next renewal, last attempts, deployments) and a 4-step dialog wizard "Get a certificate" (CA → names → proof method → locations). A **Test run** button runs the order only to the point of validated authorizations (no certificate issued, no CA issuance rate-limit used, nothing deployed); Let's Encrypt staging is a one-click preset. | Dialog wizard matches `AddKeyVaultDialog` (local state machine), not a new framework. |
| 9 | Tests | `internal/testutil/fakeacme` (RFC 8555 server: directory, nonce, newAccount incl. EAB check, newOrder, authz, real HTTP-01/DNS-01 validation against configurable endpoints, finalize with CSR parse, issuance from a test CA, ARI, `Retry-After`, rateLimited, `badNonce` faults) + `cmd/alice-fakeacme` (serve / ctl, loopback admin, like `alice-fakeazure`, distroless digest-pinned image). Pebble rejected: no fault injection for hook/ARI, extra pinned image. Unit + integration (testcontainers Postgres + fakeacme + fake Nginx target from Phase 4 harness) + e2e + fuzz (`acme` problem documents, directory JSON, ARI JSON, hook responses, PEM chain parsing). Rollback proof: integration and e2e tests make `nginx -t` fail after the renewal write and assert `deployment.rolled_back` and that the previous leaf fingerprint is still served by the TLS probe. | |

## Spec conflicts resolved by this plan

| # | Conflict | Decision | Why | Cost if wrong |
|---|----------|----------|-----|---------------|
| C1 | `01-product.md:182,224` list ACME as v2 / out of scope | Build it in v1.x, flagged as a deviation in `docs/superpowers/rulings/acme-issuance.md` | Owner request; the specs' reason ("air-gapped customers cannot use it") is answered by internal CAs + DNS hook | Docs mention both |
| C2 | HTTP-01 needs a token reachable on :80 vs "Alice never edits nginx config" (`00-decisions.md:48`, `01-product.md` AC3) | Token *file* in a fixed admin-prepared webroot, config untouched | AC3 forbids config edits only | If rejected, ship DNS-01 only |
| C3 | Spec says every helper change needs bump | Protocol 6→7, version 1.5.0→1.6.0 | Only for HTTP-01 | Task 15 isolated |
| C4 | `certificates.source` allows discovered/uploaded/csr/azure_kv | Add `acme` | Distinguish origin | Down migration reverses |
| C5 | Outbound hosts are a fixed allow-list (azurekv) | ACME hosts are admin data, still behind `netaddr` and https-only | CAs are customer-chosen | Documented SSRF note |

## Carries and deferred items (recorded in the rulings file)

HTTPS proxy support; RFC 2136 / vendor DNS providers; TLS-ALPN-01; certificate **revocation UI** (follow-up proposal: revoke on key compromise, `RevokeCert` exists in the library); ACME profiles / short-lived (6-day) certificate presets; `acme-dns`/CNAME delegation helper; multi-account-per-CA.

## File Structure

```
migrations/00013_acme.sql                      tables + CHECK extensions (+ down)
internal/acme/                                 client.go order.go ari.go keys.go problem.go
internal/acme/transport/                       guarded http client (system roots + bundle)
internal/acme/solver/                          dns01 (webhook) http01 (helper) interface
internal/inventory/acme_*.go                   providers, accounts, certificates, bindings, planner
internal/jobs/acmejobs/                        acme.issue handler, ScheduleTask, AutoDeployTask
internal/api/acme_handlers.go                  routes, limitACME class
internal/testutil/fakeacme/  cmd/alice-fakeacme/  test/images/fakeacme/Dockerfile
cmd/alice-helper/acmechallenge.go              (Task 15) acme-challenge-put / -rm
web/src/pages/AcmePage.tsx AcmeDetailPage.tsx  web/src/pages/settings/CertificateAuthorities.tsx
web/src/components/acme/GetCertificateDialog.tsx
web/e2e/phase10.spec.ts
docs/superpowers/rulings/acme-issuance.md  docs/security/reviews/acme-issuance.md
```

## Cross-task contract

**Tables (migration 00013).** `acme_providers(id, name unique, directory_url, ca_bundle_pem, preset, eab_kid, eab_hmac_ct/nonce/wrapped_dek/key_version, created_at, deleted_at)`; `acme_accounts(id, provider_id, contact_email, account_url, tos_url, tos_accepted_by, tos_accepted_at, key_ct/nonce/wrapped_dek/key_version, state active|retired|deactivated)` one active per provider (partial unique index); `acme_hooks(id, name, url, secret sealed, ca_bundle_pem)`; `acme_certificates(id, provider_id, account_id, names text[], key_type, challenge dns01|http01, hook_id, renew_before_days, auto_renew, auto_deploy, state, current_certificate_id, failures, next_attempt_at, last_error_code, last_attempt_at)`; `acme_orders(id, acme_certificate_id, kind issue|test, state, started/finished, error_code, order_url)` append-only; `acme_bindings`. Triggers freeze finished orders (follow `deployments`, SQLSTATE Z10xx).

**Audit actions.** `acme.provider.created|updated|deleted`, `acme.account.registered|rolled_over|deactivated`, `acme.hook.created|updated|deleted`, `acme.certificate.created|updated|deleted`, `acme.order.started|succeeded|failed|test_succeeded|test_failed`, `acme.auto_renew.stopped`, `acme.binding.added|removed`. Details hold ids, names, ToS URL, error code; no secrets (denylist test).

**Error codes (area ACM).** 0001 provider unreachable, 0002 directory invalid, 0003 terms not accepted, 0004 account rejected (EAB), 0005 rate limited by CA, 0006 validation failed (DNS), 0007 validation failed (HTTP), 0008 hook refused, 0009 CA refused identifier, 0010 certificate not issued in time, 0011 key policy not allowed, 0012 provider in use, 0013 TLS trust failed (bundle), 0014 account key rollover unsupported. Final numbers fixed in Task 2.

**Permissions.** `AcmeView` (Admin, Operator, Auditor, read token), `AcmeOperate` (Admin, Operator: create/order/test/bind; `operate` token scope), `AcmeManage` (Admin: providers, accounts, hooks; step-up). **Rate limits:** new class `limitACME` (10/min per user for order/test), plus default 300/min.

**API.** `GET/POST /acme/providers`, `PATCH/DELETE /acme/providers/{id}`, `POST /acme/providers/{id}/account`, `POST /acme/accounts/{id}/rollover|deactivate`, `GET/POST/PATCH/DELETE /acme/hooks[...]`, `GET/POST /acme/certificates`, `GET/PATCH/DELETE /acme/certificates/{id}`, `POST /acme/certificates/{id}/order|test`, `GET /acme/certificates/{id}/orders`, `PUT/DELETE /acme/certificates/{id}/bindings/{locationId}`. All in `api/openapi.yaml` with `x-permission`.

## Tasks

### Task 0: Branch, plan review gate, library spike
- [ ] Commit this plan on `acme-issuance`. Dispatch a plan reviewer (fresh subagent, Plan agent type) with `Review Focus`; apply findings; record in the rulings file.
- [ ] Spike (throwaway test, deleted afterwards): with `x/crypto@v0.57.0` against an in-memory RFC 8555 stub, confirm `Register` with EAB, `AccountKeyRollover`, `AuthorizeOrder`/`WaitOrder`/`CreateOrderCert`, `DNS01ChallengeRecord`, `HTTP01ChallengePath`, injectable `HTTPClient` and that no `RenewalInfo` exists. Record the result in the rulings file.
- [ ] Verify the load-bearing facts: `RequestDeployment` accepts a `managed_private_keys`-backed certificate (Phase 4 upload/CSR path), `insertDeployment` trigger CHECK, `certificates.source` CHECK, `limitX` mechanics.

### Task 1: Migration 00013, backup round trip
- [ ] Failing integration test first (`migrations/*_integration_test.go` pattern, plus `down_integration_test.go` and `nonsuperuser_integration_test.go`).
- [ ] Write the migration with CHECK extensions (`certificates.source`, `deployments.trigger`), triggers, indexes; Down reverses.
- [ ] Backup test: create provider/account/certificate rows, `Service.Create` → `VerifyDeep` → `Restore` into staging, assert row counts in the manifest and that the sealed account key decrypts after restore (master key travels in the backup).

### Task 2: Error codes, permissions, job types, rate-limit class
- [ ] `errors.go` + `errors_acme_test.go` (pinned table), locales en/tr, `docs/troubleshooting.md` sections.
- [ ] `rbac` permissions + `expectedMatrix` rows + `make authz-doc`; `jobs.Register("acme.issue", ClassChange)`, `acme.schedule`/`acme.auto_deploy` (ReadOnly); wiring test passes.
- [ ] `limitACME` class: constant, limiter, `allowRate` case, test.

### Task 3: Guarded transport
- [ ] `internal/acme/transport`: system roots + optional CA bundle, `Proxy:nil`, redirects refused, `netaddr.DialContext`, body cap, https only. Tests: private IP allowed, 169.254.169.254 refused, redirect refused, oversize refused, bad bundle error `ALC-ACM-0013`. Archtest rule for the package; source guard forbids `InsecureSkipVerify`.

### Task 4: fakeacme and alice-fakeacme
- [ ] `internal/testutil/fakeacme` with the faults listed in design row 9, a control API, and unit tests of the fake itself (a fake that lies breaks every later test). `cmd/alice-fakeacme` (`serve --listen --admin --ca-out`, `ctl`), Dockerfile in `test/images/fakeacme` (digest-pinned like fakeazure), compose service with alias `acme.test.alice` on the `backend` network, `testOnlyDirs` entry in `buildtags_test.go`, e2e-build CA trust hook beside `azureCAFile` (release build never trusts it; `release-symcheck`/`image-check` cover this).

### Task 5: ACME client wrapper
- [ ] `internal/acme.Client`: `Discover`, `RegisterAccount(prompt)`, `Rollover`, `Deactivate`, `Order(names, csr, solver)`, `TestOrder` (stop after validated authorizations), `RenewalInfo` (ARI, hand-written, size/time-bounded). Problem documents map to `ALC-ACM-*`. Tests against fakeacme: success, EAB required/wrong, ToS unaccepted, rate-limited with `Retry-After`, `badNonce` retry, order timeout, wildcard requires dns01, identifier refused.
- [ ] Fuzz `ParseProblem`, `ParseARI`, directory JSON.

### Task 6: DNS-01 hook solver
- [ ] POST `{"action":"present|cleanup","fqdn","value","ttl"}` with `Authorization: Bearer <sealed secret>` and `X-Alice-Signature` HMAC; https only through the Task 3 transport; 200/204 = ok; cleanup always attempted (deferred) even on failure; propagation wait = hook-reported `ready` or bounded polling of the CA. Tests: refusal, timeout, secret never in error text.

### Task 7: Keys, CSR, issuance record
- [ ] Key generation per policy, CSR with SANs, seal into `managed_private_keys` (reuse `inventory/uploads.go` helper), insert `certificates` row `source='acme'` via the existing import normalisation (chain order, `chain_complete`, fingerprint). Tests: ECDSA/RSA, wildcard, IDN names, chain mismatch refused, key zeroed.

### Task 8: Inventory service — providers, accounts, hooks
- [ ] CRUD with audit, step-up on Admin changes, ToS gate (`ALC-ACM-0003`), provider-in-use refusal, EAB sealing, no secret in any response struct (reflection test that response types have no secret-bearing field names).

### Task 9: Certificates, orders, issue job, test run
- [ ] `acme_certificates` CRUD, `RequestOrder` (license `Allow(ClassChange)`, per-cert advisory lock, one active order), job handler `acme.issue`, dry-run kind `test`. Audit, state machine tests, restart recovery (order in `pending` after a crash resumes by `order_url` or fails cleanly).

### Task 10: Renewal planner and alerts
- [ ] `PlanACMERenewals` (pure decision function + SQL like `kv_autodeploy_plan.go`), ARI use, backoff table, CA rate-limit awareness, `acme.renewal_failed` e-mail templates en/tr, stop-after-5, `acme.schedule` task wired in `cmd/alice/services.go` (and **not** ticked in the e2e build, like KV), lock-mode test (no CA call, no deployment), leader-only test.

### Task 11: Bindings and auto-deploy
- [ ] `acme_bindings` + `PlanACMEAutoDeploy`: creates deployments with trigger `acme_renewal` through `insertDeployment`, waves of 5, stop after 3 failed deploys, `deployment.*` audit rows come from the engine unchanged. **Rollback proof (integration):** forced `nginx -t` failure after the write ⇒ `deployment.rolled_back`, `certificates.deployed_fingerprint` unchanged, TLS probe still returns the old leaf; the ACME certificate stays `issued` and the binding is marked `attention`.

### Task 12: API
- [ ] Routes, handlers, OpenAPI, authz notes, request validation (names: DNS labels, wildcard only first label, max 100 names; directory URL https only; contact `mailto:` only), unified error mapping, rate-limit and license tests, `TestEveryStateChangingRouteDeclaresALicenseClass` passes.

### Task 13: UI — certificate authorities settings
- [ ] Page under Settings (Admin): provider list/form with presets, CA bundle textarea (PEM validated server-side), EAB fields (write-only), ToS checkbox with link, account status, rollover/deactivate with step-up; hooks form. Unit tests, en/tr, empty and error states, a11y tests.

### Task 14: UI — Issued certificates, wizard, status, test run
- [ ] List, detail (state, next renewal, ARI note, last orders with plain-language error text and "what to do"), `GetCertificateDialog`, **Test run** button, bindings editor. Role gates from server data. Unit tests + `design-gaps.md` rows.

### Task 15: alice-helper HTTP-01 webroot (isolated, optional)
- [ ] Justification: the only way to publish an HTTP-01 token on the host the name points at without SSH file-write or config edits. `acme-challenge-put --token T` (stdin: key authorization) and `acme-challenge-rm --token T` write/remove `/var/www/alice-acme/.well-known/acme-challenge/<token>` (constant in `helperproto`): token `[A-Za-z0-9_-]{22,128}`, body ≤ 512 bytes, `O_NOFOLLOW`, directory must exist (the admin creates it; helper never creates the parent), mode 0644, no other path ever. Bump `Protocol` 7, `Version` 1.6.0; `linuxssh.Cmd*` constructors; setup script checksums; root-only suites; `make test-ssh` including a negative path test (traversal, symlink, oversize). Solver `solver/http01` calls it through the existing `linuxssh.Conn.Run`, and verifies the file with a probe from Alice before accepting the challenge. Docs: `docs/nginx-host-preparation.md` gets the snippet and port-80 requirement.
- [ ] If any root-only suite or `test-ssh` cannot be run on this machine, **stop this task**, leave HTTP-01 as a documented carry, and say so in the final report.

### Task 16: E2E
- [ ] `web/e2e/phase10.spec.ts`: add a provider against fakeacme (custom CA bundle + EAB), register account (ToS), order DNS-01 via a hook implemented in `fakeacme ctl`, deploy to the e2e Nginx target, verify served leaf; renewal via `acme tick` ctl; failed deploy keeps the old certificate; lock mode; Turkish run; axe scans; all three browsers; added to `phase9.spec.ts` route scans.

### Task 17: Fuzz and security tests
- [ ] `make fuzz-*` target for the five parsers; secret-leak test that runs an order and greps logs/audit/API/job payload for the account key, EAB HMAC, hook secret and private key bytes.

### Task 18: Documentation
- [ ] Admin guide (providers, EAB, CA bundle, hooks, host prep), operator guide (get, test, renew, deploy), `docs/troubleshooting.md`, security overview, `docs/security/reviews/acme-issuance.md` (method, threat notes, not verified against a real CA, known limitations), `docs/superpowers/rulings/acme-issuance.md` (every deviation C1–C5 and carry), `CHANGELOG.md`, `api/openapi.yaml`, `docs/authz-matrix.md`, `docs/design-gaps.md`, THIRD_PARTY notices unchanged (no new module; assert with `make notices`).

### Task 19: Final verification and whole-branch review
- [ ] `make ci` in the background; read the output; `make e2e-browsers` for chromium/firefox/webkit; `make perf` unchanged; coverage floors for every new package added; whole-branch review (requesting-code-review skill); fixes; merge fast-forward to master; report merge state.

## Not verifiable here (stated in the final report)

Behaviour against a real Let's Encrypt/ZeroSSL/step-ca/EJBCA endpoint; real DNS propagation; real CA rate-limit values; ARI against a production CA. These are covered only by the fake and RFC reading.

## Amendments after the plan review (binding; they override anything above that disagrees)

Source: adversarial review against master `f369b83` (blocking B1–B5, important I1–I9, minor M1–M5).

**A1 Helper protocol (B1, M3).** Bumping `helperproto.Protocol` to 7 would make `linuxssh.Open` refuse every existing target (`provider.go:115`, `ssh.helper_outdated`). Therefore: the required minimum stays **6**; the helper reports Protocol 7 / Version 1.6.0 and a new constant `HTTP01MinProtocol = 7` is checked only when a target is used for an HTTP-01 challenge (error: a plain-language "reinstall the helper on this server to use this proof method"). Task 15 moves **before** Task 12 (API); until it is merged the API and UI reject `challenge=http01` behind a single constant `http01Enabled`, so nothing exposes an unbuilt feature.

**A2 One deploy path, precisely (B2).** A person's "Deploy now" goes through `inventory.RequestDeployment` with trigger `manual`. Only the planner (`PlanACMEAutoDeploy`) uses `insertDeployment` with trigger `acme_renewal`, and it must first run `readDeployCertificate`, `lockDeployTargets` and `checkDeployLocation` exactly as `kv_autodeploy.go` does. A test asserts the planner has no code path that reaches `insertDeployment` without them. Planner rules copied from the KV planner (I6): `HoldRuleDetectedBeforeReopening` / `gateReopenedAt` (a certificate issued while Alice was unlicensed is held for an Admin, not auto-deployed unseen), once-only notice marks, batch 50, neutral failure reasons, wave 5, stop after 3.

**A3 Private-CA chains (B3).** `chain_complete` is computed with the provider's `ca_bundle_pem` **added** to the roots (the `complete` argument of `placeCertificate`), otherwise every step-ca/EJBCA auto-deploy fails `chain_unconfirmed`. Integration test with a private chain and a provider bundle.

**A4 Every `certificates.source` consumer (B4).** Task 1 and Task 7 update: `certificateSources` in `internal/api/certificates_handlers.go:66` and `internal/inventory/certificates.go:126`, `api/openapi.yaml`, `web/src/api/enums.ts`, `types.ts`, `enums.test.ts`, the filter in `CertificatesPage.tsx`, `UsageTopology.tsx`, `CertificateDetailPage.tsx`. `certificates_check_key` (Z1004) is checked for inserts with `source='acme'`. The **down migration re-maps** `acme` certificates to `uploaded` and `acme_renewal` deployments to `retry` before restoring the CHECKs; a down-migration test seeds both.

**A5 Rate limiting for tokens (B5).** `limitACME` copies the `limitExport` keying (`u:` for sessions, `t:` for tokens, `guard.go:313-324`), is in both `allowRate` and `s.actions`, and is tested for session and token callers.

**A6 Account rollover safety (I1).** Order: commit the new sealed key as `pending_rollover` → call the CA → flip `active/retired` in one transaction. Recovery tries both keys against the CA and settles the state. Crash test between CA success and commit.

**A7 Rate limits and retries (I2, M1).** `Client.RetryBackoff` returns 0 for 429/rate-limited so the library never sleeps on them; `Error.RetryAfter()` is read, capped at 24 h, and stored as `next_attempt_at`. Every CA call has a context deadline. ARI: the library has no `renewalInfo` in `Directory`, so Task 5 fetches the directory JSON itself (second GET), then does the hand-written ARI GET. `replaces` (RFC 9773 §5) cannot be sent with this library; limitation L-ACME-1 (renewals are not rate-limit-exempt at Let's Encrypt). The Task 0 spike no longer needs to check "no RenewalInfo".

**A8 Keys never orphaned or lost (I3).** The pending private key is sealed in a **deletable** column of `acme_orders` (`pending_key_*`) at order start; on success it is moved into `managed_private_keys` and the `certificates` row is inserted **in one transaction** (`certificates_check_key` needs both). Failed or abandoned orders delete the pending key. A crash after the CA issued but before the commit is recoverable because the order URL and the pending key are persisted; crash-recovery test.

**A9 Privilege (I4).** Decision D6: **Admin** creates, edits and deletes `acme_certificates` (step-up), with a per-provider and per-hook **name allow-list** (domain suffixes, e.g. `.corp.example.com`; empty list = refuse all). Operators may order a renewal now, run a Test run, request deployment (`RequestDeployment`) and edit bindings of existing ACME certificates; they cannot add names or change a provider. `AcmeOperate` therefore covers order/test/deploy/bind only; `AcmeManage` covers create/edit/providers/hooks/accounts. This is added to `04-security.md` threat notes (Operator "can deploy certificates"; now also "can trigger renewal of pre-approved names").

**A10 SSRF and secret details (I5).** https-only is enforced **inside the `RoundTripper`** for every URL, including URLs the CA returns (order, authz, finalize, certificate, ARI); a CA-supplied `http://` or metadata-address URL is refused (test). Hook URLs with userinfo are refused. CA and hook response bodies/headers are never copied into errors, audit rows, jobs or API responses (blind-SSRF read); only closed-set `ALC-ACM` codes and the RFC 8555 problem `type` URN (validated against a prefix) are kept. Secret handling is reworded: only the DER `secrets.Plaintext` is zeroed; Go's `ecdsa`/`rsa` key objects cannot be zeroed, so their lifetime is kept to the order function.

**A11 Restored clones (I7).** After a restore the ACME auto-renew switch is **off** until an Admin confirms (same mechanism as the license `reopened` state); `restorer` marks `acme_certificates.auto_renew=false` (like `holdChanges`) and the UI shows a banner. Test in the backup cycle.

**A12 Challenge cleanup in every license state (I8).** Presented DNS records / HTTP-01 token files are persisted in `acme_orders.presented jsonb`; a `acme.cleanup` job (**ClassAlways**, like `rotation.location`) removes them on success, failure, lock or crash recovery; sweep task removes leftovers older than 1 h. Test: lock mid-order, kill mid-order.

**A13 Registration checklist (I9, M4).** Task 2 also covers: job labels (literal `Register` calls, en/tr), `MaxAttemptsFor` → `acme.issue` returns 1, route groups in `lockAvailable`/`lockRuleViolations` (`authz_test.go:760-790`) and `tools/lockcheck`, `GRANT SELECT, INSERT` + column-level `UPDATE` to `alice_app` (pattern `00006:277-286`) with a non-superuser test, `05-operations.md` outbound table and `04-security.md` entries (specs are updated, listed as deviations), `fuzz-acme` Makefile target in `fuzz-nightly` and `fuzz-release`, EAB HMAC base64url decode with a bad-value test, concurrent `acme.issue` for one certificate yields one order (`DedupeKey`), concurrent writes to `failures`/`next_attempt_at`, `Location` has no UUID dependency that breaks restore. `key_type` of an issued certificate with bindings cannot be changed (M2; `KeyTypeMismatchError`); the UI says so. Per-task gates (M5): `make authz-doc`, `make i18n-check`, archtest, lint run in every task; `make ci` stays at the end.

**A14 Task order.** 0 gate · 1 migration (+ source consumers, down re-map, backup test) · 2 errors/permissions/jobs/rate class/registrations · 3 transport · 4 fakeacme · 5 client + ARI · 6 DNS-01 hook solver · **7 helper HTTP-01 (old Task 15)** · 8 keys/CSR/issuance record · 9 inventory (providers, accounts, hooks) · 10 certificates/orders/issue/cleanup · 11 renewal planner/alerts · 12 bindings/auto-deploy · 13 API · 14 UI settings · 15 UI issued certificates · 16 e2e · 17 fuzz/security · 18 docs · 19 final. (The task bodies above keep their original headings; execute in this order.)
