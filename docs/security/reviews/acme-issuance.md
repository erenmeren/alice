# Security Review — ACME certificate issuance and renewal

Scope (plan `docs/superpowers/plans/2026-10-13-acme-issuance.md`, "Review Focus" 1–6): Alice as an RFC 8555 client
of an administrator-chosen certificate authority (Let's Encrypt, ZeroSSL, step-ca, EJBCA or an ACME gateway):
migration `00013`; the guarded outbound client (`internal/acme/transport`); the client wrapper with orders, Test runs,
account key rollover, deactivation and the hand-written ARI lookup (`internal/acme`); the DNS-01 hook solver
(`solver/dns01`) and the HTTP-01 solver (`solver/http01`) with the helper's protocol 7 commands
(`cmd/alice-helper/acmechallenge.go`); key and CSR generation (`acme/keygen`); the inventory services for providers,
accounts, hooks, ACME certificates, orders, bindings, the renewal planner and the auto-deploy planner; the jobs
`acme.issue`, `acme.cleanup`, `acme.sweep`, `acme.schedule`, `acme.auto_deploy`; 29 API routes with four permissions
(`acme.view`, `acme.operate`, `acme.manage`, `acme.preview`) and a rate class; the Settings → Certificate authorities screens and the Issued certificates pages; the restore hook
that switches automatic renewal off.

**Nothing in this work was run against a real certificate authority, real DNS, a real ARI endpoint or the public
network.** Every protocol exchange ran against `fakeacme`, an in-process RFC 8555 server written for this work (and its
container `alice-fakeacme` in the e2e stack), whose fidelity gaps are listed under "Known limitations". The helper's
HTTP-01 commands ran against real Nginx and OpenSSH in Ubuntu 22.04, Debian 12 and Rocky 9 containers without
network. "Not verified" below lists what that leaves open.

The controller's rulings, with what each costs if wrong, are in `docs/superpowers/rulings/acme-issuance.md`; the
amendments to the specification are marked in `docs/superpowers/specs/alice-v1/04-security.md` and `05-operations.md`.

## Method

Built in 19 tasks on branch `acme-issuance` (base `master` f369b83; plan 64923b5, amendments dbb2a95, renumbering
b73ac29). Before any code two adversarial plan reviews ran against `Review Focus` (blocking B1–B5, important I1–I9,
minor M1–M5); their findings became amendments A1–A14 of the plan, which override the plan's body. A preflight scan of
the task pairs that share a file or an interface fixed the cross-task contract (ledger `.superpowers/sdd/2026-10-13-acme-issuance/progress.md`).
Every task was implemented by an agent and reviewed by another that did not write it; Important findings went back as
fix rounds (up to two per task) that were reviewed in scope. Implementers and reviewers mutated the code under test
(removing a gate, a lock, a check or a redaction) to see the named tests turn red, and recorded the red output in the
task reports. Task 17 added fuzz targets for every parser of CA- or hook-controlled bytes and a secret-leak suite
with positive controls; Task 16 drove the whole feature through the browser against the fake CA in three browsers.
This review was written in Task 18, before Task 19's `make ci` and the whole-branch review; their outcome is in the
"Final run" column below, the Findings table and the rulings (Task 19).

## Evidence

"Development runs" are the latest results the implementers recorded in their task reports, with the task named.
"Final run" is Task 19's: `make ci` exit 0 on its fifth run, after the fixes listed under Findings (T19); the full
Playwright suite on Chromium, Firefox and WebKit with `make e2e-up` then `make e2e-browsers`: 399 passed, 0 failed, 12
skipped (the opt-in design-evidence specs). The whole-branch review's fix wave (T19 W1–W8) came after that run; a sixth full `make ci` (including the Chromium
Playwright suite: 133 passed, 0 failed, 4 skipped design-evidence) exited 0 on the final branch. Firefox and WebKit were
not re-run after the wave (the wave changed one web label and one icon; covered by web unit tests). `NOT RUN (owner)` and `NOT RUN (CI)` cells are never a pass.

| # | Check | Command | Expected | Development runs | Final run |
|---|---|---|---|---|---|
| 1 | Unit tests of the touched packages, race detector | `go test -race ./internal/acme/... ./internal/inventory/... ./internal/jobs/... ./internal/api/... ./cmd/alice/... ./internal/archtest` | ok | ok in every report (Tasks 1–17) | ok (`make ci` `test`, fifth run) |
| 2 | Integration tests (testcontainers PostgreSQL, fakeacme, the emulated and real Nginx target) | `go test -tags integration` per package | ok | migrations, backup, inventory, jobs/*, api, alerts, notify ok (Tasks 1–13, 17) | ok (`make ci` `coverage`, every package with `-tags integration`) |
| 3 | Rollback proof of a renewal deployment | `TestACMERenewalDeployFailureRollsBack`, `TestACMERenewalStopsAfterThreeRolledBackDeployments` (`internal/jobs/deployjobs`) | `rolled_back`, previous leaf still served | PASS for `nginx -t`, reload and verify failures; deployed fingerprint, served and TLS-probe fingerprint all the previous leaf (Task 12) | ok (both tests in `make ci` `coverage`); the e2e rollback with `nginx -t` failing passed in all three browsers |
| 4 | Helper root-only suite (whole suite, uid 0, no network) | `alice-helper.test` in `debian:12` | PASS | 274 PASS incl. `TestACMEChallengeAsRoot`, `TestEmulatorFidelityACMEChallenge` (Task 7 fix round) | not re-run: `cmd/alice-helper` unchanged since the Task 7 fix round (57e23d0) |
| 5 | Real OpenSSH and Nginx matrix | `make test-ssh` | PASS | `TestRealOpenSSH`, `TestRealNginx` incl. `acme_http01_webroot` on ubuntu22, debian12, rocky9 (Task 7 fix round) | ok (`make ci` `test-ssh`) |
| 6 | Playwright Phase 10, three browsers | `npx playwright test e2e/phase10.spec.ts --project=chromium --project=firefox --project=webkit` | all pass | 21/21 (7 tests × 3 browsers) on 9bd4e73; Phase 10 + Phase 9 chromium 11/11 after ed8a158 (Task 16) | pass in all three browsers (`make e2e-up`, `make e2e-browsers`: 399 passed, 0 failed, 12 skipped for the whole suite) |
| 7 | Phase 7 and Phase 9 specs (Settings tab list and the scans changed) | `npx playwright test e2e/phase9.spec.ts e2e/phase7.spec.ts` | all pass | chromium, firefox, webkit pass for the selection run (Task 16) | pass: every spec (phases 1–10) in the same `make e2e-browsers` run; the Phase 4 helper expectation was corrected to protocol 7 first (6573e46) |
| 8 | Fuzzing, six ACME targets | `make fuzz-acme FUZZTIME=15s` | no crash | 6/6 ok, about 50–90k execs/s (Task 17); earlier 20 s and 10 s runs per target (Tasks 5, 6, 11) | `make fuzz-release`: NOT RUN (owner) |
| 9 | Secret-leak suite | `go test -tags integration -run TestACMESecretsNeverLeak ./internal/api/` | no canary found; every plant found | ok, `-count=3`; four mutation runs failed as intended (Task 17) | ok (`make ci` `coverage`) |
| 10 | Licence lock: no CA contact | lock tests in inventory, acmejobs, api and e2e | fakeacme `requests == 0` | ok (Tasks 9–13, 16) | ok (`make ci` and the three-browser e2e) |
| 11 | Authorization matrix and route rules | `go test ./internal/api -run 'Authz|OpenAPI|Spec'`; `make authz-doc` | ok; no diff | ok; no diff (Tasks 13, 18) | ok; no diff (`make ci` `lint`) |
| 12 | Coverage floors of the new packages | `make coverage` | every floor holds | acme 94.0, transport 93.1, solver 100, dns01 94.6, http01 98.4, keygen 94.8, renew 100, acmejobs 96.4–96.8, fakeacme 92.6; inventory 89.2–89.5 against its floor of 89 (Tasks 3–17) | every floor holds (`make ci` `coverage`); `internal/jobs` fell to 88.9 against 89 and is 90.3 after the queue error-path tests (2d750a7); no floor lowered |
| 13 | Lint, lock check, docs check, matrix check, pin check | `make lint` | exit 0 | exit 0 in every task | exit 0 (Task 18; `make ci` `lint` in Task 19) |
| 14 | No new Go module, notices unchanged | `make notices`; notices of master f369b83's binaries with the same tool | identical | `go.mod`, `go.sum`, the web lockfile unchanged since f369b83; `bin/THIRD_PARTY_NOTICES.md` byte-identical to the one built from f369b83's binaries (Task 18) | — |
| 15 | Release symbol check (the e2e CA trust never in a release build) | `make release-symcheck` | ok | ok (Tasks 4, 10–13, 16) | ok (`make ci` `release-symcheck`) |
| 16 | The whole local pipeline | `make ci` | exit 0 | not run in full before Task 19 | exit 0 on the fifth run; runs 1–4 failed on the serve migration-version test, `internal/jobs` coverage, the Phase 4 helper protocol expectation and a fakeacme slow-fault flake (fixed: 5e2b29f, 2d750a7, 6573e46, 4e18782) |
| 17 | Behaviour against a real CA, real DNS, real ARI | — | — | — | NOT RUN (owner) |

Other evidence recorded by the implementers and reviewers (their reports; not re-run here):

- Transport: `http`, userinfo and `ftp` URLs refused before any dial (0 dials); a redirect never followed (one hit);
  answers over 1 MiB refused, exactly 1 MiB accepted; 169.254.169.254, 169.254.1.1 and fd00:ec2::254 refused by
  `netaddr`; `HTTPS_PROXY`/`ALL_PROXY` ignored; `TestNoExportedDialSeam` (no exported way to replace the dialer);
  the `InsecureSkipVerify` source guard (Task 3).
- Library spike against fakeacme through the real transport, kept as regression tests (`internal/acme/library_test.go`):
  EAB key bytes, rollover, deactivation, order flow, the library's retry behaviour (Task 5).
- Rollover (A6): `TestACMERolloverUnknownThenSwitched`, `…ThenNotSwitched`, `TestACMERolloverIsSerializedAcrossProcesses`,
  `TestACMEProviderLockDoesNotStarveThePool` (Task 9).
- Orders: crash after present, crash after issue, lock mid-order, lock before finalize (no CSR sent), panic in a
  solver, lost commit acknowledgement, interrupted orders (Task 10).
- Renewal: 38-row decision table, 6-day and 90-day certificates, ARI earlier/later/hostile windows, rate-limit hold
  bounds, four concurrent planners (Task 11).
- Auto-deploy: `TestInsertDeploymentHasOnlyCheckedCallers` and `TestACMEFilesReachDeploymentsOnlyThroughTheCheckedPaths`
  (AST), `TestACMEQueuedDeploymentIsJudgedAgain` (7 cases through the real engine) (Task 12).
- API: step-up for switching unattended deployment on decided inside the transaction
  (`TestACMESwitchOnNeedsAStrictSessionInsideTheTransaction`, `TestACMEBindingSwitchOnRaceIsAnsweredWithTheStepUp`),
  read tokens change nothing, terms bound to what was shown (`TestACMERegisterIsBoundToTheShownTerms`) (Task 13).

## Threat notes

### SSRF through the directory URL, CA-returned URLs and the hook URL

Only an Administrator with step-up sets a directory or hook URL; the inventory refuses non-https, userinfo, query
and fragment, and a database CHECK refuses userinfo in a directory URL. Every request of the ACME client and of the hook solver goes through one client
(`internal/acme/transport.New`): https only, checked in the `RoundTripper` for every request URL including the order,
authorization, finalize, certificate and `renewalInfo` URLs the CA returns (a CA-supplied `http://` URL is refused as
`ALC-ACM-0002`); `netaddr.DialContext` on every connection (link-local, metadata, multicast, reserved and the
IPv4-carrying IPv6 forms refused; loopback and private allowed, as for managed servers); `Proxy: nil`; redirects
returned, never followed; 1 MiB answers; 30 s per exchange; TLS 1.2+, system roots plus the provider's or hook's
bundle. There is no exported way to swap the dialer. CA and hook answer bodies and headers never reach an error, a
log, an audit row, a job or an API answer: only closed-set `ALC-ACM` codes and a validated problem-type URN are kept
(blind SSRF read). The HTTP-01 self-check is plain HTTP to port 80 of the name (the CA's own check is plain HTTP), also
through `netaddr`, without proxy, keep-alive or redirects, 1 KiB, 5 s per try. Residual: an Administrator can aim
Alice at any https service Alice can reach, private ones included (C5).

### Challenge exposure: DNS records and HTTP-01 token files

A challenge's key authorization is public by design (the CA fetches it). The DNS hook gets only the record name, value
and TTL, signed with HMAC-SHA256 under the hook secret, which is also sent as a bearer token. The HTTP-01 token file is
written by `alice-helper acme-challenge-put` into one fixed root-owned directory
(`/var/www/alice-acme/.well-known/acme-challenge`), which the helper never creates: every directory from `/` down must
be root's and not group/other-writable and not a link (`O_NOFOLLOW` walk with `fstatat` and inode re-check); the token
is `[A-Za-z0-9_-]{22,128}`, the body exactly `token.<43 base64url>` and at most 512 bytes; write by temp file and
rename; no other path is ever written. The sudoers lines allow only `--token` with at least 22 characters. Records
are persisted in `acme_orders.presented` before they are published, and `acme.cleanup` (ClassAlways, so also in lock)
removes them after success, failure, lock or crash; the sweep re-queues a failed cleanup hourly for seven days. Alice
never edits the Nginx configuration (C2). Residual: a helper killed between create and rename leaves a harmless
`.alice-acme-*` temp file (public content, never a token name), not swept.

### Account key rollover races

Account operations of one provider are serialized across processes by a PostgreSQL session advisory lock taken with
`pg_try_advisory_lock` and a bounded retry that holds no pooled connection while waiting (busy → `ALC-ACM-0024`). A
rollover commits the new sealed key as `pending_rollover` before it calls the CA, then flips `active/retired` in one
transaction that also repoints the ACME certificates; an unknown outcome leaves the pending row, no signing happens
while it exists, and recovery asks the CA with the new key, then the old one, and refuses to give up a pending key
younger than 5 minutes (database time). A trigger allows only forward account states (Z1019) and deletion of pending
rows only (Z1018). Residuals: a wall-clock jump on the database host could age a pending key early; a provider
directory change does not take the advisory lock (its transaction re-checks state).

### Renewal information (ARI) and hostile windows

ARI (RFC 9773) is hand-written because the library has none: a second GET of the directory, then the `renewalInfo`
GET, both through the guarded client, size-bounded and fuzzed. A window is used only to renew earlier than the local
rule (`not_after − min(renew_before_days, lifetime/3)`), never later. Windows starting before 2000, ending at or before
the certificate's `not_before`, or ending more than 10 years ahead are ignored; ARI errors keep the cached window and
never count as failures; at most 10 lookups per planner run. Alice cannot send RFC 9773 `replaces` with
`golang.org/x/crypto/acme` v0.57.0 (L-ACME-1): renewals are not rate-limit-exempt at Let's Encrypt.

### Rate-limit storms and retry loops

Every `acme.issue` job has one attempt; retries are owned by the planner. The library's own retries are cut: the
client's `RetryBackoff` answers 0 for 429, 5xx and unexpected statuses (only `badNonce` is retried, three times).
Failure backoff 1, 2, 4, 8, 16, 24 hours; `Retry-After` and `rateLimited` push the next attempt (capped at 24 h);
15 minutes between two issue orders of one certificate; at most 5 orders per planner run; while one certificate of a
provider is rate-limited, the others of that provider wait (at most 24 h from the start of the series, never past the
middle of their window); stop after 5 failures with an e-mail at 3. A licence lock or an interrupted job is neutral (no
failure, no backoff). All ACME user actions share 10/min per person or token.

### Secrets leaving the vault

Account keys, EAB HMAC keys, hook secrets, pending order keys and issued private keys are sealed with
`secrets.Keyring` under per-row AAD, are `secrets.Plaintext` in memory and zeroed after use (Go's `ecdsa`/`rsa` key
objects cannot be zeroed; their lifetime is kept to the order function). They are write-only in the API (views carry
only `*_configured` booleans; a reflection test refuses secret-looking fields), redacted by `fmt`/`slog`/JSON, and
handler-owned request buffers are zeroed on every path. `TestACMESecretsNeverLeak` runs a journey with EAB,
registration, rollover, hook, Test run, order, renewal, binding, Deploy now, five failures with both e-mails and a
backup, and searches the redacted and the raw (pre-redaction) log, every API answer, every table row as JSON, every
bytea column, the rendered e-mails and the backup manifest for the keys in every encoding and in pieces, plus the DEKs
that seal them; positive controls plant four canaries in seven places and require each to be found. Residual: the
backup payload itself is checked only through its manifest (it holds the sealed rows and `master.key` by design).

### One deploy path and unattended deployment

A person's **Deploy now** calls `RequestDeployment` (trigger `manual`); only the planner inserts deployments itself
(trigger `acme_renewal`), and only through `prepareACMEDeployment`, which calls `readDeployCertificate`,
`lockDeployTargets` and `checkDeployLocation` before `insertDeployment` (AST tests pin the callers and the order). A
queued automatic deployment is judged again before the key is opened (`ALC-ACM-0030`–`0034`). Switching unattended
deployment on is Admin with a fresh step-up, decided inside the inventory transaction after the binding's state is
read under the row lock (ruling I2, the Key Vault rule S6). A failed renewal deployment is rolled back by the
unchanged engine (Evidence row 3; the e2e repeats it with `nginx -t` failing).

### Licence lock and restored clones

User routes that contact a CA or a server are `ClassChange` (403 `ALC-LIC-0001`); the planners call
`license.Allow(ClassChange)` themselves and are paused by the scheduler; the issue job asks the gate again before each
published challenge and before finalize, so a lock mid-order publishes nothing more and sends no CSR. Removing a
binding and deleting a definition are `ClassAlways`. A certificate issued before the licence last reopened is held for
an Administrator. A restore switches every ACME certificate's automatic renewal off (A11), holds queued
`acme.issue` jobs like every change job, ends the orders that were running at backup time (failed, `job.lease_expired`,
pending key deleted), clears every order's list of published challenge records and cancels the backup's `acme.cleanup`
jobs, so a clone neither resumes an order with the original's account key nor removes records the original may still
publish (T19 W1). Residual: a restored copy shares the CA accounts of the original, so a key
rollover or deactivation there affects the original (carry M8).

### Fuzzing

Six targets, split for the release job's timeout into `fuzz-acme-docs` (problem documents, ARI, directory) and
`fuzz-acme-order` (issued chain check with exact verdicts, order names, hook replies); properties include bounded
reads, https-only URLs, ARI windows after 2000 and the closed error mapping. Seeds are inline; no crasher was found.

## Review checklist

- [x] Secrets never leave the vault unsealed (Review Focus 1): leak suite and reflection tests (Evidence row 9).
- [x] No second deploy path (Focus 2): AST tests; the helper writes only the token file (Evidence rows 3–5).
- [x] SSRF guarded (Focus 3): one transport, https-only per request, `netaddr`, no redirects, size and time caps.
- [x] Licence lock (Focus 4): no CA contact, no deployment, no planner work; user routes answer `license.locked`.
- [x] Renewal safety (Focus 5): rollback proof in integration and e2e; backoff, spacing, wave, hold and stop.
- [x] Helper change (Focus 6): path confinement, token charset, size cap, root-only suite and the real-Nginx matrix.
- [x] (Task 19) `make ci` green and the whole-branch review's findings closed (T19 rows under Findings).
- [ ] (owner) A real CA, real DNS and ARI (see "Owner verification").

## Findings

Found by the plan reviews, the per-task reviews and their re-reviews, the e2e and the leak suite. None was rated
Critical; the plan reviews' blocking findings were design changes made before any code.

| ID | Area | Rating | Description | Decision |
|---|---|---|---|---|
| Plan B1 | Helper | Blocking (design) | A protocol bump to 7 would have made every existing target refuse (`ssh.helper_outdated`) | A1: minimum stays 6, `HTTP01MinProtocol = 7` checked only for HTTP-01 |
| Plan B2 | Deploy | Blocking (design) | The planner's deployments skipped the checks of a person's deployment | A2: read/lock/check before every insert, AST test |
| Plan B3 | Chains | Blocking (design) | Private-CA chains never complete, so every auto-deploy would fail | A3: the provider bundle completes the chain |
| Plan B4 | Data | Blocking (design) | Consumers of `certificates.source` not listed; down migration would fail | A4 |
| Plan B5 | Rate limit | Blocking (design) | Token callers not keyed | A5 |
| Plan I1–I9 | Various | Important | Rollover order, library retries, orphaned keys, Operator privilege, SSRF on CA URLs, KV planner rules, restored clones, cleanup in lock, registration checklist | A6–A13 |
| T3 | Transport | Important | An exported dial seam could bypass `netaddr` | Fixed 0e09c45 (sealed seam, archtest narrowed) |
| T4 I1 | fakeacme | Important | The fake's HTTP-01 prober was an SSRF gadget in the e2e network | Fixed 99611ae |
| T5 I1 | Client | Important | Registration demanded ToS acceptance from CAs without terms | Fixed 9763fc2 (ruling) |
| T6 | DNS-01 | Important | Hook waits and polls not bounded by the client's call deadline; secret charset; the name-refusal reason outside the registry | Fixed 13d462f (wait + poll ≤ 120 s also enforced by the inventory) |
| T7 | HTTP-01 | Important | Solver missing; guide's location block lost to `location ~ /\.` and server-level redirects | Fixed 62f965a, a8ce842, 57e23d0 |
| T9 I1–I3 | Accounts | Important | Rollover not serialized across processes; account states could move backwards; certificates not following a rollover | Fixed e4b59f7 |
| T9 R2 | Accounts | Important | The blocking advisory lock starved the pool | Fixed 964180c (try-lock, ALC-ACM-0024) |
| T10 I1, I2 | Orders | Important | Snapshot race under the row lock; the sweep abandoned resumable orders | Fixed 5b526b3..160d097 |
| T10 R2 | Orders | Important | Interrupted orders counted as failures | Fixed 2569a56..41408f9 (`AbandonACMEOrder`) |
| T11 I1, I2 | Renewal | Important | Unbounded provider rate-limit hold; hostile ARI windows | Fixed 24af671..c1cd450 |
| T12 I1 | Deploy | Important | Queued automatic deployments ran after their binding, switch or certificate changed | Fixed e81ec2b (ALC-ACM-0030..0034) |
| T12 I2 | Authz | Important | Operators could switch unattended deployment on | Ruling: Admin + fresh step-up (ca52a42, then 68253af) |
| T13 I1 | API | Important | The step-up decision for switch-on was taken outside the transaction | Fixed 68253af..38d08e4 |
| T13 R2 / T14 | Terms | Important | Terms of service could not be shown before consent | Preview endpoint and `accepted_terms_url` (69660f9, 32723d8, 655deff) |
| T16 | Web | Defect | "Run a test first" showed no result on the status page | Fixed 928b291 |
| T17 | Tests | High (test) / Medium | Release fuzz job would exceed its timeout; the leak suite's log channel was almost empty and only redacted | Fixed 037419d |
| T19 make ci | Tests | Defect (test) | `make ci` runs 1–4: the serve upgrade test expected the previous migration; `internal/jobs` coverage 88.9 under its floor; the Phase 4 e2e expected helper protocol 6; a fakeacme slow fault answered an empty 200 to a client that had left (flake) | Fixed 5e2b29f, 2d750a7 (queue error-path tests, 90.3), 6573e46, 4e18782 |
| T19 W1 | Restore | Important | A restored clone's sweep resumed an order running at backup time with the original's account key; the backup's cleanup jobs removed records the original may still use | Fixed: the restore ends running orders, clears `presented`, cancels `acme.cleanup` jobs (`TestRestoreEndsInFlightACMEOrders`) |
| T19 W2 | Accounts | Important | A discarded pending rollover key was deleted outside any audit transaction | Fixed: delete and `acme.account.rollover_discarded` in one transaction |
| T19 W3 | API/Web | Minor | Deployments of ACME certificates were labelled "Uploaded" | Fixed: deployment source `acme` (API, OpenAPI, web, en/tr) |
| T19 W4 | Accounts | Minor | A key rollover was not refused while an order of the provider ran | Fixed: `ALC-ACM-0016` (provider's certificates read FOR SHARE first) |
| T19 W5 | Data | Minor | A certificate definition read its provider, hook and server unlocked (race with their deletion) | Fixed: FOR SHARE (`TestACMECertificateCreateSeesAConcurrentDelete`) |
| T19 W6–W8 | Docs/Web/Data | Minor | This review said three permissions and had empty Final run cells; the usage view drew an ACME source as a file; the finished-order freeze compared only the key's ciphertext | Fixed: this document; `ShieldCheck` icon; 00013 compares all four key columns |

## Known limitations

- **Not verified against real services**: Let's Encrypt, ZeroSSL, step-ca, EJBCA or any real ACME server; real DNS
  propagation and real DNS hooks; real CA rate-limit values and their `Retry-After`; ARI against a production CA; the
  public network, firewalls and NAT between Alice, the CA and the targets. All of it ran against `fakeacme`.
- **fakeacme fidelity gaps**: no expiry of orders, authorizations or nonces; finalize with the account key not refused;
  `revokeCert` answers 501; no account `orders` list; ARI defaults and its `Retry-After` (6 h) are guesses;
  certificates not tied to account ownership beyond the key ID; no TLS-ALPN-01; DNS is a table, not a resolver.
- No HTTPS proxy support (environment proxies are ignored); no built-in DNS providers or RFC 2136; no TLS-ALPN-01;
  revocation only of certificates Alice ordered, signed with the account (added 2026-10-20,
  `docs/superpowers/rulings/certificate-revocation.md`; no revocation with the certificate key); no ACME profiles or short-lived presets; one account per CA; no `acme-dns`/CNAME helper.
- Renewals do not send ARI `replaces` (L-ACME-1).
- A restored copy shares the original's CA accounts (rollover or deactivation there affects the original).
- The account's contact e-mail is visible to every `acme.view` caller (Auditors and read tokens).
- In licence lock a binding's automatic deployment cannot be switched off (only removed).
- A failed automatic deployment marks the binding "Needs attention" only at the planner's next run (about a minute);
  the status page does not poll deployments after **Deploy now**.
- Expiry e-mails do not cover an ACME certificate before it is on a server (the renewal e-mails do).
- No per-run cap on ACME e-mails (one per certificate and kind).
- `.alice-acme-*` temp files of a killed helper are not swept.
- Inventory coverage is 89.2–89.5 % against its floor of 89.

## Owner verification

With a real CA (Let's Encrypt staging is enough for 1–5) and a test domain you control:

| # | Step | Expected | Result | Date | Notes |
|---|---|---|---|---|---|
| 1 | Add **Let's Encrypt (staging, for tests)**, register an account (read the terms link), add a DNS hook for your DNS | Terms shown before the tick; account Active; nothing contacted before **Register account** | | | |
| 2 | **Get a certificate** for two names (one wildcard) with the DNS proof; **Run a test first** | Test run succeeds; no certificate issued; TXT records removed afterwards | | | |
| 3 | **Get certificate now**; connect a website; **Deploy now** | Certificate issued with a complete chain; the website serves it | | | |
| 4 | HTTP-01 on a prepared Nginx server (helper 1.6.0) | Certificate issued; token file removed | | | |
| 5 | Shorten **Renew how many days** so renewal is due; switch both automatic deployment switches on (Admin) | Renewed by the planner, deployed automatically; ARI window shown if the CA publishes one | | | |
| 6 | Repeat 1–3 with your company CA (with its root in the bundle) and, if used, with ZeroSSL (external account binding) | As above | | | |
| 7 | `make fuzz-release` (includes `fuzz-acme-docs`, `fuzz-acme-order`) | No crash | | | |

## Sign-off

Reviewer, date and commit are filled in when the review is completed.

| Role | Name | Signature | Date | Commit |
|---|---|---|---|---|
| Reviewer | | | | |
| Owner | | | | |
