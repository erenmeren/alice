# ACME issuance — controller rulings

Decisions taken on the owner's behalf during autonomous execution of
docs/superpowers/plans/2026-10-13-acme-issuance.md on branch `acme-issuance` (base `master` f369b83; plan 64923b5,
amendments dbb2a95, renumbering b73ac29; owner instruction: run back to back, merge locally, no check-ins). Each line:
decision — why — cost if wrong — how to reverse it, where that is a file to change. Sources: the plan's "Spec
conflicts", "Carries" and Amendments A1–A14; every `Ruling:` line, deferred minor and carry of the ledger
`.superpowers/sdd/2026-10-13-acme-issuance/progress.md`; the rulings in the task reports
(`task-N-report.md` there). The evidence, the findings and the accepted limitations are in
docs/security/reviews/acme-issuance.md; the amendments to the specification are marked "(Amendment, ACME issuance
2026-10-13 …)" in docs/superpowers/specs/alice-v1/04-security.md and 05-operations.md.

**Nothing here was checked against a real certificate authority, real DNS, a real ARI endpoint or the public
network**: every protocol exchange ran against `fakeacme` (in process and as the `alice-fakeacme` e2e container). The
HTTP-01 helper commands ran against real OpenSSH and Nginx in Ubuntu 22.04, Debian 12 and Rocky 9 containers.

## Deviations from the specification

- **C1 — ACME in v1.x.** `01-product.md:182,224` list ACME as v2 / out of scope ("air-gapped customers cannot use
  it"). Built now — owner request; air-gapped customers use an internal CA (step-ca, EJBCA, an ACME gateway) and the
  DNS hook — cost: the product spec and the guides disagree about scope until the spec is revised — reverse: remove
  the feature (migration 00013 has a Down that re-maps `acme` certificates to `uploaded` and `acme_renewal`
  deployments to `retry`).
- **C2 — HTTP-01 without editing Nginx.** `00-decisions.md:48` and AC3 forbid config edits. Alice writes one token
  *file* into a fixed directory the administrator publishes with a 3-line `location ^~` block they add themselves —
  AC3 forbids config edits only — cost: the administrator prepares each HTTP-01 server by hand — reverse: ship DNS-01
  only (refuse `challenge=http01` in `checkACMECertRefs` and the API).
- **C3 — Helper protocol 7, version 1.6.0** (spec: every helper change needs a bump). Bumped; per A1 `linuxssh.Open`
  still requires protocol 6 and only HTTP-01 checks `HTTP01MinProtocol = 7` (`ALC-SSH-0013`) — cost: two minimums to
  keep in mind — reverse: raise `helperproto.MinProtocol`.
- **C4 — `certificates.source` gains `acme`, `deployments.trigger` gains `acme_renewal`.** To tell origin and
  automatic renewal deployments apart; every consumer updated (A4) — cost: one more enum value for API clients —
  reverse: the Down migration.
- **C5 — Outbound hosts are admin data.** Azure's are a fixed allow-list; ACME directory and hook URLs are what the
  Administrator types, still https-only and behind `netaddr` — CAs are customer-chosen — cost: an Administrator can
  aim Alice at any reachable https service (SSRF note AC-1 in 04-security) — reverse: an allow-list setting.
- **Specs amended, not rewritten** (A13, Task 18): `04-security.md` (actors, STRIDE table "ACME connector" AC-1..AC-7,
  RBAC rows, SEC-037 extension, sealed secrets after SEC-049) and `05-operations.md` (18.2 outbound table, 18.4 network
  note) carry marked amendments; `01-product.md` keeps its v2 wording (C1 is recorded here) — why: the specs are the
  history of decisions — cost: a reader of 01-product alone sees ACME as v2 — reverse: an owner revision of 01-product.

## Before the tasks (plan review, ledger preflight)

- Two adversarial plan reviews (blocking B1–B5, important I1–I9, minor M1–M5) became Amendments A1–A14, which override
  the plan's body: A1 helper minimum 6 / HTTP-01 7; A2 one deploy path, precisely (person = `RequestDeployment`
  trigger manual; planner = checked `insertDeployment`, trigger `acme_renewal`, KV planner rules copied); A3 the
  provider bundle completes private chains; A4 every `certificates.source` consumer and the Down re-map; A5
  `limitACME` keyed like `limitExport`; A6 rollover order pending → CA → flip, with recovery; A7 retries and
  `Retry-After` owned by Alice, L-ACME-1; A8 pending key in `acme_orders` and one-transaction finish; A9 Admin-only
  definitions with per-provider and per-hook name allow-lists; A10 https-only inside the RoundTripper, no CA text
  copied; A11 restored clones have auto-renew off; A12 challenge cleanup in every licence state; A13 registration
  checklist; A14 task order (helper task 7 before the API).
- Ruling: the Task 0 library spike is folded into Task 5 — nothing is built before the client — costs nothing.
- Ruling: briefs are terse and point the implementer to the plan's Global Constraints, Design decisions, Cross-task
  contract and Amendments — the briefs depend on them — cost: some extra reading per task.
- Ruling: execute in the shared working tree on `acme-issuance`, no separate worktree — the e2e stack and
  `node_modules` are per checkout and the owner's untracked files must stay put — cost: no parallel branches.
- Ruling: the Task 1 schema includes `acme_orders.pending_key_*` and `presented jsonb` (A8, A12) — Task 10 needs them —
  costs nothing.
- Ruling (preflight): the `Solver` interface is defined in Task 5 (`internal/acme/solver`); Task 7 flips HTTP-01 on
  only if the helper suites run (they did: HTTP-01 is **not** a carry).

## Tasks 1–4: schema, codes, transport, fake CA

- Task 1: the column and state names chosen by Task 1 bind later tasks (`key_ct/key_nonce/key_wrapped_dek/
  key_version`, `eab_hmac_*`, `secret_*`, `pending_key_*`; certificate states pending|issuing|active|failing|stopped;
  order states running|succeeded|failed; extra `allowed_suffixes`, `deleted_at`). Migration 00013 was amended in place
  by Tasks 9, 10, 11 and 12 (unreleased; a dev database at an older 00013 needs a reset).
  Deferred minors: the freeze trigger should compare all four `pending_key_*` columns (00013:620); comment typos
  (`testapi_e2e.go:114`, web `types.ts`). Done later: the `directory_url` CHECK refuses userinfo (Task 9).
- Task 2: 18 codes `ALC-ACM-0001..0018` (beyond the plan's 14: 0015 name not allowed, 0016 order running, 0017
  challenge unavailable, 0018 key type locked); no "lock" code — lock uses `ALC-LIC-0001`. Deferred, all done later:
  `acme.cleanup` MaxAttempts set explicitly (Task 10, 5); Turkish glosses for "kanca" and "harici hesap bağlama"
  (Task 14); lock route groups (Task 13); audit labels (Tasks 8–12).
- Task 3: `transport.New(caPEM)` is the only constructor; the dial and budget seams are unexported (review fix
  0e09c45). Deferred minor: `TestNoExportedDialSeam` ignores exported package variables, methods and other files.
- Task 4: `fakeacme` dials HTTP-01 only to admin-mapped names and refuses IP-shaped identifiers (review I1, 99611ae).
  Deferred minors (fidelity, listed as known limitations): no expiry of orders/authorizations/nonces, finalize with the
  account key not refused, `revokeCert` 501, no account orders list, tests never order the literal 169.254.169.254,
  the admin loopback check uses `RemoteAddr`. `acmeRoots()` (e2e trust of the fake CA) wired into every ACME client
  and hook config in Task 10 (`inventory.Config.ACMERoots`).

## Tasks 5–8: client, solvers, helper, keys

- Task 5 Ruling: `RegisterAccount` requires `tosAccepted` only when the directory advertises `termsOfService` — CAs
  without terms (some internal step-ca) must work — cost: one review fix round.
- Task 5: `x/crypto/acme` v0.57.0 has no `Error.RetryAfter()` (A7 assumed one): Alice parses `Retry-After` itself
  (seconds or date, capped 24 h); `RetryBackoff` answers 1 ms for status 400 up to 3 retries (badNonce) and 0 for
  everything else. Deferred minors: `ctx.Canceled` collapses into `not_issued_in_time` (Task 11 showed the job
  context already decides neutral vs counted); no dedicated codes for a local CSR mismatch (→ `key_policy_not_allowed`),
  a bad name (→ `identifier_refused`) and unknown CA problems (→ `directory_invalid`); `Order` returns the default
  chain only (alternates verified in the spike, not exposed); a Test run leaves validated authorizations and a pending
  order at the CA.
- Task 6 Ruling (parked item 7): wait + poll of a hook ≤ the client's call timeout (120 s) is validated at the
  settings/API boundary (Task 9, migration CHECK) rather than per solver call — real but minor. Deferred minors: no
  sub-reason for transport failures (TLS vs refused); no poll action in the hook contract (ready=false repeats
  `present`); no solver-level total budget across poll and propagation wait. Task 9 dropped the stored `auth_mode`:
  Alice always sends both the bearer token and the HMAC signature.
- Task 7: HTTP-01 shipped (the root-only suite and `make test-ssh` ran on all three images). The helper's body rule is
  stricter than the brief (exactly `token.<43 base64url>`, no newline). Deferred minors: `normDomain` accepts
  all-numeric labels (the allow-list and `netaddr` cover it); a killed helper may leave a harmless `.alice-acme-*` temp
  file (not swept: a sweep could race a concurrent put); commit 62f965a alone does not compile its test file (bisect
  only; no amend). The CHANGELOG entry was left to Task 18 (done).
- Task 8: the audit object type is `acme_certificate` and the actor of job-side rows is the system actor `jobs`.
  Acceptance criteria carried to Task 10 (all done there): abort on every non-success path with a detached context,
  sweep of running orders, key type read from the database, a key-generation slot (2). Deferred minor: concurrent
  double-Finish and mid-transaction rollback tests.

## Task 9: providers, accounts, hooks

- Ruling: the inventory may import `acme`, `acme/transport` and `acme/solver/dns01` (Task 8 had denied it) — the
  services drive the client — cost: a wider archtest rule — reverse: an adapter package.
- Account operations are serialized per provider by a PostgreSQL advisory lock taken with `pg_try_advisory_lock` and a
  2 s bounded retry (busy → `ALC-ACM-0024`, retryable) — the blocking lock starved the pool (fix round 2) — cost: a
  rare "try again".
- A pending rollover key younger than 5 minutes (database time) is never discarded by recovery; account states only
  move forward (Z1019); only pending rows may be deleted (Z1018); a rollover repoints the certificates.
- Contact privacy: the contact e-mail is stored in the account row only, never in the audit log; the API shows it to
  every `acme.view` caller (Auditors, read tokens; carry from Task 13).
- Deferred minors: M2 a CA account orphaned by other store failures; a provider directory change does not take the
  advisory lock (its transaction re-checks state); a wall-clock jump could age a pending key early; deactivation
  treats any `unauthorized` as "already gone". **Carry M8**: a restored clone's Rollover/Deactivate act on the
  original's CA account (documented in the admin guide and backup-restore; no gate).

## Task 10: certificates, orders, issue, cleanup, sweep

- `acme.issue` is ClassChange with 1 attempt; `acme.cleanup` ClassAlways, 5 attempts, no dead-job e-mail (the sweep
  re-queues hourly, a mail would repeat); `acme.sweep` new periodic ClassAlways task (leader only; release 1 min, e2e
  never ticks).
- A database failure of `FinishACMEOrder` (twice) after the CA issued leaves the order running with its key and URL
  for the sweep to finish (A8 exception, log `acme_order_left_running`); the sweep resumes for up to 24 h, then
  abandons.
- Fix round 2: an interrupted order (shutdown, lost lease, crash) is abandoned **without** counting a failure
  (`AbandonACMEOrder`); only a certificate the CA issued but Alice cannot store is counted. `StaleAfter` = 5 min
  (orders whose issue job is queued or running are never stale).
- A deleted hook's leftover records are cleaned with the record's own name as allow-list.
- Deferred: M4 → ruled in Task 11 (a licence lock is neutral); **carry M9**: no database link enforcing
  account ↔ provider (the code always re-resolves the provider's current active account); persistent pre-URL
  interruptions retry without backoff (Task 11's 15-minute spacing bounds them); the freeze trigger accepts
  `[a]` → `[a,a]` on a finished order's `presented` list (containment does not count duplicates; harmless, the
  cleanup removes by value).

## Task 11: renewal planner

Rulings recorded in the task report, adopted:

1. No automatic first issuance: the first order is always a person's.
2. ARI only pulls renewal earlier; ARI errors keep the cached window and never count; `ErrNoARI` clears it; a new
   issuance clears it.
3. E-mails and the stop apply to renewals only (an issued certificate with automatic renewal on); a person's failing
   order on a stopped certificate sends nothing more and keeps it stopped; only a successful order (or **Renew now**)
   makes it active again.
4. The 15-minute spacing counts every issue order, a person's too.
5. Provider-level rate-limit hold (fix round 1: at most 24 h from the start of the series, never past the middle of a
   candidate's window).
6. No account = a counted failure (`acme.account_state`), so a misconfigured provider produces backoff and e-mails
   instead of a silent skip each minute.
7. No `POST /test/acme/tick`: the e2e build drives planners with `/test/scheduler/run` and `/test/clock`.
8. Expiry e-mails: an ACME certificate is monitored once a location holds it; before that the renewal e-mails cover it.
   **Owner follow-up**: expiry mail for undeployed ACME certificates (`itemsSQL`).

- Hostile ARI windows (fix round 1): windows before 2000, ending at or before `not_before`, or more than 10 years
  ahead are ignored/refused.
- `ReArmACMEAutoRenew` (**Renew now**) resets failures and the notice mark and switches automatic renewal on; it does
  not order. Audit `acme.auto_renew.rearmed` (not in the plan's audit list; added).
- Deferred minors: a stopped or auto-renew-off neighbour can hold its provider ≤ 24 h; more than 150 candidates per
  tick wait for the next run; the e-mails name "Issued certificates" and the real buttons (Task 15 labels; corrected in the Task 18 fix round).

## Task 12: bindings and automatic deployment

- **Ruling I2 (stricter than A9)**: switching unattended deployment on — a binding's `auto_deploy`, the certificate's
  `auto_deploy`, creating a certificate with it — is **Admin + fresh step-up + licence**; Operators may bind with it
  off, switch it off, remove bindings and use Deploy now — the Key Vault rule S6 — cost: Admins must act on every
  switch-on — reverse: `unattendedAllowed` in `internal/inventory/acme_bindings.go`. Recorded in `04-security.md`.
- One ACME certificate per location (unique index), and a location follows either a Key Vault binding or an ACME
  binding, never both.
- Deliberate deviation from the KV planner: no "location serves a certificate that ends later" skip — an ACME binding
  is an explicit statement that the location follows this certificate.
- Queued `acme_renewal` deployments are judged again before the key is opened (`ALC-ACM-0030..0034`, neutral reasons)
  — fix round 1 I1.
- Licence hold: a certificate issued before the licence gate last reopened, deployed nowhere, with a binding that
  existed at the reopening, is held for an Administrator (**Release**); a chain hold is never released (Deploy now
  with confirmation).
- **M4 ruling**: no per-run e-mail cap (Key Vault has 20 + summary); at most one notice per current certificate and
  kind.
- The "Needs attention" mark is set by the planner at its next run (about a minute after the failure), not in the
  engine's transaction (by design; documented).
- Locations the planner's checks refuse (server not ready, key type, recovery pending) are skipped silently; the
  binding stays "Waiting for deployment" and the server page shows why (M3; documented).

## Task 13: API

- JSON is snake_case like the rest of the API (the brief said camelCase); contract paths kept (`/order`, `/test`,
  `/rearm`, `/deploy`, `/rollover/recover`) instead of `/actions/<verb>`; extra route `POST /certificates/{id}/release-hold`
  (Admin step-up).
- Licence classes: everything that contacts a CA or a server is ClassChange; `DELETE` of a certificate definition and
  of a binding are ClassAlways (they only reduce what Alice does); `DELETE` of a provider or hook stays ClassChange.
- `limitACME`: one 10/min bucket per identity for all ACME actions (order, test, deploy, rearm, account operations,
  preview, certificate PATCH — M1); each token has its own bucket.
- **Ruling (fix round 2)**: a separate permission `acme.preview` (Admin, no step-up, no token) for
  `POST /providers/{id}/preview` — least privilege; `acme.manage` always steps up — cost: a 28th permission — reverse:
  one line in the route table plus the matrix rows.
- Registration is bound to the terms that were shown (`accepted_terms_url`, exact string match: a CA that only changes
  the URL's spelling makes the Administrator look again — the safe direction).
- Carries: **M3** switching a binding's automatic deployment off is refused in lock (the PUT also creates bindings;
  `DELETE` of the binding is the lock-time way; a ClassAlways off-only route is a follow-up); list paging is done in the
  handler over the full inventory list; the contact e-mail is visible to Auditors and read tokens (04-security note).
- Deferred minors: the service does not itself refuse an unsafe terms URL when `accepted_terms_url` is omitted (the
  UI refuses); `PreviewACMEProvider`'s doc says one GET (it is two); OpenAPI lacks an explicit 401 (default covers).
- `http01Enabled` was never needed as a constant: HTTP-01 is accepted (Task 7's suites ran).

## Tasks 14–16: web UI and e2e

- Task 14: Settings → Certificate authorities is an Admin-only Settings tab (`/settings?tab=acme`); the component is
  read-only for other roles but no route shows it to them. "Accepted by" is not shown (the audit row holds the actor).
  The terms are shown before consent through the preview (fix round 1). Secrets live in form state and a ref, never in
  a query or mutation cache. Minor: a terms-changed re-read with no terms shows a slightly odd notice.
- Task 15: websites are not chosen in the wizard (the API binds only an issued certificate, `ALC-ACM-0027`); **Add
  websites** is one PUT per website, stopping at the first refusal; **Renew now** = rearm (Admin) and appears only in
  the stopped notice; the order button reads **Get certificate now** before the first issuance and **Order now**
  after; licence lock is derived client-side from `/license/status`; the next renewal is computed in the browser and
  may differ from the planner by its spacing rules. Concern adopted as a design-gap follow-up: two automatic
  deployment switches (certificate and website); the derived line "Will deploy automatically to N of M websites"
  (Task 16 polish) explains them.
- Task 16: the fake CA's issuing root is added to the e2e provider's bundle (`ctl ca`), as a private-CA admin would
  paste it; the e2e target gets the guide's port-80 block and the alias `www.example.test`. Defect found and fixed:
  "Run a test first" showed no result (928b291). Carries: **the status page does not poll deployments after Deploy
  now** (reload; design-gap follow-up); **"Needs attention" appears only at the planner's next run**; `make e2e-up`
  itself was not exercised (images built with `docker build --network host`); the older e2e specs (Phases 1–8) are
  re-run in Task 19; the renewal journey uses 30-minute certificates (90-day timing is covered by unit/integration
  tests).

## Task 17: fuzz and leak suite

- `fuzz-acme` split into `fuzz-acme-docs` and `fuzz-acme-order` (3 targets each, 90 minutes per release job) instead
  of raising the job timeout. Carry: the backup is scanned through its manifest only (the payload holds sealed rows
  and `master.key` by design). A secret logged under a secret-looking key is redacted by the logging handler; the leak
  suite therefore also scans a raw, pre-redaction log.

## Task 18: documentation

- Guides: admin guide "Certificate authorities (ACME)", operator guide "Issued certificates (ACME)", a topical
  troubleshooting section, the outbound table in `security-overview.md`, ACME notes in `api.md`, `backup-restore.md`,
  `licensing.md`, `nginx-host-preparation.md` (the removal text names the `location ^~` block; the Alice server must
  reach port 80 too), design-gap follow-ups. No Turkish documents exist (`docs/README.md`: the guides are English);
  Turkish parity is in the locales, which Tasks 2–16 kept (`make i18n-check`).
- Troubleshooting bodies corrected where they no longer matched the code (titles are pinned to the locales and were
  not changed): `ALC-ACM-0006` (no "hook test" exists), `ALC-ACM-0012` (an account also blocks removal),
  `ALC-ACM-0017` (HTTP-01 is enabled; the causes are wildcards and non-Nginx servers), `ALC-ACM-0027` (the button is
  **Get certificate now**).
- Fixed on the coordinator's request (Task 18 fix round): the product texts that said "Renew now" where an order is
  meant now name the real buttons in en and tr — `errors.acme.not_issued.action` (**Get certificate now**),
  `email.acme.renewal_failed` (**Order now**), and `email.acme.auto_renew_stopped` (**Order now** to renew at once,
  an Administrator's **Renew now** to re-arm); `ALC-ACM-0017` is retitled "This proof method cannot be used here"
  with its real causes (wildcard names, a server that is not a managed Nginx server); the troubleshooting heading
  follows the title.
- A11's "the UI shows a banner" after a restore was not built: the restore prints a warning and the certificates show
  automatic renewal "Off" (design-gap follow-up).
- No new Go module: `go.mod`, `go.sum` and the web lockfile are unchanged since f369b83, and `make notices` produced a
  `THIRD_PARTY_NOTICES.md` byte-identical to the one built from f369b83's binaries.

## Task 19: final run and whole-branch review

- `make ci` exit 0 on the fifth run. Runs 1–4 failed on, and were fixed by: the serve upgrade test still expecting
  migration 00012 (5e2b29f, it expects 00013 now); `internal/jobs` coverage 88.9 % against its floor of 89 on a full
  run, from timing-dependent runner branches — eleven deterministic queue error-path tests bring it to 90.3 % (2d750a7;
  no floor lowered); the Phase 4 e2e expecting helper protocol 6 where the HTTP-01 publisher installs 7 (6573e46); a
  fakeacme slow fault that answered an implicit empty 200 to a client that had already left, so the directory check
  read "not a directory" under load — the fake now aborts the connection (4e18782; a test double, not product).
- The full Playwright suite ran on Chromium, Firefox and WebKit with `make e2e-up` then `make e2e-browsers` (so both
  targets are exercised now; Task 16's carry): 399 passed, 0 failed, 12 skipped (the opt-in design-evidence specs).
- Whole-branch review fix wave (after that run; focused tests, `make lint`, then a sixth full `make ci` exit 0 with Chromium e2e 133 passed; Firefox/WebKit not re-run after the wave):
  - **W1 / M8 extended**: a restored clone no longer carries on the original's orders. In the restore transaction that
    switches automatic renewal off, running orders end as failed with the neutral `job.lease_expired` and no pending key
    (the abandon rules; their certificates leave `issuing`), every order's `presented` list is cleared (Z1017 allows a
    finished order's list to shrink) and the backup's live `acme.cleanup` jobs are cancelled. Cost: if the original is
    gone for good, leftover challenge records stay in DNS or the token directory (the restore warns; documented in
    backup-restore). M8 itself (a clone's rollover or deactivation act on the shared CA account) stays a documented
    carry.
  - W2: a discarded pending rollover key (refusal or recovery) is deleted and audited (`acme.account.rollover_discarded`)
    in one transaction.
  - W3: deployments of ACME certificates have source `acme` (were "Uploaded").
  - W4: a key rollover is refused with `ALC-ACM-0016` while an order of a certificate of the provider runs (it signs
    with the key being replaced); the provider's certificate rows are read FOR SHARE first, so an order starting
    meanwhile is either seen or finds the pending key. The existing code is reused; its text names the case.
  - W5: a definition reads its provider, hook and HTTP-01 server FOR SHARE (race with their deletion).
  - W7, W8: the usage view's ACME source icon; the finished-order freeze compares all four pending-key columns (00013
    amended in place, unreleased).
- **Contact e-mail (personal data)**: the account's contact e-mail stays visible to every `acme.view` caller, Auditors
  and read tokens included (Tasks 9 and 13). It is personal data; the owner may want it Admin-only (a view that omits
  it for non-Admins). Not changed on this branch — cost: an Auditor or a read token learns an operator's address.
- **M3 confirmed**: switching a binding's automatic deployment off is refused in licence lock (the PUT also creates
  bindings and is ClassChange); removing the binding is the lock-time way. A ClassAlways off-only route stays a
  follow-up.

## Carries and deferred items (open after this branch)

- HTTPS proxy support (environment proxies are ignored; "proxy/custom CA" carry of phase-5:170 and phase-7:336 is
  partly closed: CA bundles exist for ACME and hooks).
- RFC 2136 and vendor DNS providers (the hook is the adapter); an `acme-dns`/CNAME delegation helper.
- TLS-ALPN-01 (needs a stream listener, i.e. Nginx config edits: rejected).
- Certificate revocation UI (`RevokeCert` exists in the library; follow-up proposal: revoke on key compromise).
- ACME profiles and short-lived (6-day) certificate presets; more than one account per CA.
- L-ACME-1: ARI `replaces` cannot be sent with `x/crypto/acme` v0.57.0; renewals are not rate-limit-exempt.
- A ClassAlways route to switch a binding's automatic deployment off in lock (Task 13 M3).
- Status page polling of deployments; one combined automatic deployment control; a restore banner (design gaps).
- Expiry e-mails for ACME certificates not yet on a server (owner follow-up, Task 11 ruling 8).
- Restored clones acting on the original's CA account (Task 9 M8; in-flight orders and challenge records closed by Task 19
  W1); account ↔ provider database link (Task 10 M9).
- The contact e-mail visible to Auditors and read tokens (personal data; owner decision: Admin-only?).
- fakeacme fidelity gaps (Task 4); the Task 1, 3, 5, 6, 7, 8, 9, 13 deferred minors listed above.
- Inventory coverage 89.2–89.5 % against its floor of 89 (thin margin, not lowered).
- Behaviour against a real CA, real DNS and real ARI: owner verification in docs/security/reviews/acme-issuance.md.
