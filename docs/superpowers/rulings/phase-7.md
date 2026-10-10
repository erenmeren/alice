# Phase 7 — controller rulings

Decisions taken on the owner's behalf during autonomous execution of
docs/superpowers/plans/2026-10-07-phase-7-alerts-dashboard-sso.md on branch `phase-7` (base `master` aa7985b, plan
28b5498; owner instruction: run the phases back to back without waiting). Each line: decision — why — cost if wrong —
how to reverse it, where that is a file to change. Within a topic the order is the order in which they were made
(the times are the controller's ledger of 2026-10-07; the session was cut at about 14:37 and resumed from the ledger,
and the last entries are of 2026-10-10); where a later ruling replaced an earlier one, both are named. The decisions
as they apply to the product are R42 in docs/superpowers/specs/alice-v1/00-decisions.md (item numbers in brackets);
the evidence, the findings and the accepted limitations are in docs/security/reviews/phase-7.md.

Nothing here was checked against a real identity provider or a customer's mail server: single sign-on ran only
against the in-repository fake identity provider (`internal/testutil/fakeidp`, the e2e container `fakeidp`), e-mail
only against the fake mail server (`internal/testutil/fakesmtp`, the e2e container `fakesmtp`).

## Before the tasks

- 13:38 — the plan's 30 "spec conflicts resolved" are accepted as proposed R42, pending the pre-flight reviews; the
  plan changes no helper code and no helper protocol (protocol 6, helper 1.5.0) — why: the owner said not to wait —
  cost: the owner revises R42 later — reverse: each is an item of R42 [1–30] with its own cost.
- 13:38 — the plan (11,026 lines, 22 tasks) was not compiled by its author → a pre-flight consistency scan (Opus) and a
  pre-flight security design review (Fable) before Task 1, as in Phases 2 to 6. The code as built wins over the plan
  text. The workspace files `global-constraints.md`, `cross-task-contract.md` and `dispatch-common.md` were extracted
  from the plan for every dispatch.

## Pre-flight rulings on the design findings (S-1–S-13), 13:54

All thirteen were adopted as the review proposed them and made binding on every dispatch (preflight-rulings.md) —
why: each closes a privilege, lock-out or no-notice path at design time, cheaper than after build. Critical 0,
Important 4, Minor 9.

- S-1 — the SSO step-up callback requires a live session (not revoked, not idle-expired, same user) and re-evaluates
  groups → role exactly as a sign-in does; a session ended by `RefuseOIDC` or `DemoteSSOAdmins` is never resurrected
  [22] — cost if wrong: none identified.
- S-2 — the JWKS cache expires by the answer's cache headers (5 minutes to 24 hours, 1 hour by default); a withdrawn
  `kid` stops verifying at expiry; the unknown-`kid` refetch stays rate-limited [34].
- S-3 — the scan is per item; one unstorable or failing item is logged and skipped; the subject is cut to 300 runes
  before insert (never a CHECK failure) [31].
- S-4 — `settings.recipients_changed` records the addresses and `administrators`, in the same transaction [6].
- S-5 — mapping create and switching the Admin setting off lock the setting row `FOR UPDATE` [24]. S-6 — the seen
  certificate record is keyed by host and port and compared at pin time [10]. S-7 — the e-mail update at sign-in
  applies the O-10 collision rule [23]. S-8 — users are matched by `(oidc_provider_id, oidc_subject)` (the unique
  index changes; the issuer is stored for display) [23]. S-9 — the delivery state is one `UPDATE … SET` expression
  [8]. S-10 — exports stream after the audit row and the header, at most 50,000 rows, one export at a time per user
  [16]. S-11 — the callback is limited per state cookie, the start keeps the per-address sign-in limit [18]. S-12 —
  the env import runs only when no mail settings ever existed; a tombstone blocks re-import [9]. S-13 — `withQuery`
  inserts before the fragment; a `SafeNext` test with a fragment [35].

## Consistency scan rulings (B1–B20 and the FIX rows), 13:54

Every blocking and fix-round row of the scan was adopted with its "Merged" resolution; cosmetic rows were followed by
the task they name — why: name, shape, order and compile corrections against the real code — cost if wrong: a fix
round in the task concerned. The scan found 20 distinct BLOCK rows (compile errors in Tasks 3, 7, 9, 12, 13, 14, 15
and 20, the seed's platform credential, the e2e `TestMain` duplicate, F-60 over the wire without a recipient, the
public OIDC routes against `TestEveryDocumentedPathIsServed`, web selectors and e2e session expiry after clock moves)
and 53 FIX rows.

- B20 / schedule — Task 19 moves after Task 15 (it needs the SSO codes); Task 12 starts after Task 6 is committed (it
  consumes `PutSetting`, `GetSetting`, `DeleteSetting` and `settings.GetGeneral`); Task 18 keeps wave 2.
- Task 5 extends `resetSQL` in `cmd/alice/testapi_e2e.go` with the six new tables — why: `make test` stays green
  between Task 5 and Task 13 — cost: a merge conflict Task 13 resolves (none happened).
- B2 — `seed.Target` shares one platform credential per seed run (`credentials_one_platform_key`). B3 —
  `$4::timestamptz`.
- B5 — Task 10 widens `internal/reports` and `inventory` only and records the values; Task 14 widens the API copies
  and the OpenAPI enums [17].
- B11 — the stack's administrator gets `ada@example.com` and F-60 over the wire sets one explicit recipient.
- B13 — the public OIDC routes are served by `testDeps` with a fake SSO service; `TestEveryDocumentedPathIsServed`
  accepts a 303 for the callback only [18].
- B8 — the e2e seed integration test joins the existing `cmd/alice` e2e integration file (one `TestMain`).

## Rulings on the planner's open questions

- R42 row 20 (O-07 overage refused, no Graph) stands — why: Graph needs application credentials and consent the spec
  does not define — cost: Entra users in more than 200 groups cannot sign in until a later phase adds Graph [20].
- R42 row 1 of the carries (certificate private-key download) stays re-deferred to Phase 8 — why: the format decision
  and its own S-09 suite.
- R42 row 26 (perf in `make ci` only if every p95 ≤ 60 % of its budget over three runs) stands; the outcome is under
  "The performance ruling" below.

## Pure packages and fakes (Tasks 1–4)

- 14:20 — Task 1 carries resolved for Task 8: the `sent` set passed to `expiry.Due` is scoped to the ledger key's
  `expires_at`; an item first seen already expired gets its one Expired notice [5].
- 14:01 — Task 2: the `SafeNext` dot-segment and encoded-`/api` minors are hardening in the OIDC security core and are
  built in Task 12's session with tests (613cb66) — why: cheap, the package had no owner any more and Task 15 relies on
  it — cost: a few lines [35]. Carried: user-name collisions (Task 11), duplicate mappings refused (Task 12),
  `http.Redirect` with `SafeNext` only (Task 15).
- 14:03 — Task 4: fix round 1 for the fakes (I1: the HS256 confusion token's MAC verified, keyed with the DER by default
  and with the PEM text through `Fault.HMACKeyPEM`; I2: options and negative paths tested with pinned reply codes; I3:
  an absent nonce omitted, no empty `state`, the authorize query recorded) — closed in c77c309.

## Schema (Task 5)

- 14:01 — accepted as built: the S-8 index `(oidc_provider_id, oidc_subject)`, the S-3 300-character boundary in
  characters, `alerts` append-only for `alice_app`, CHECKs that stop local↔SSO identity switches, the down guard
  `Z1015`; Task 11 matches by provider ID and subject.

## Mail (Tasks 6–7)

- 14:11 — Task 6 fix round: `internal/secrets` was at 82.9 % under its floor 83 (error branches of `PutSetting` and
  `DeleteSetting`); minors 2 (the server-presented subject capped) and 5 (`ImportEnv` applies the
  user-name-needs-a-password rule; no unused envelope) included — why: cheap, same package, security-relevant [9],
  [10]. Carried to Task 13: `SettingsConfig.Dial` must be nil in release builds (SEC-065) [11].
- 14:14 — Task 7 fix round: an address with a display name passed `mail.ParseAddress` and defeated both duplicate
  checks → bare addresses only, compared as parsed case-folded mailboxes [6]; ruling: the give-up ERROR line carries
  `event=notify.gave_up` [7]. Carried: Administrators on with none holding an address queues nothing silently (Task 13
  logs `alerts.no_recipients`); the Phase 6 `rotation.paused_license` e-mail carries no license note (R42 row 12 limits
  the note to expiry e-mails — stands); Tasks 13 and 19 must not present `failed_24h` as an exact 24-hour figure.

## Alerts (Task 8)

- 14:23 — the over-cap notices were lost when the separate summary transaction failed → the spec's once-per-threshold
  wins: over-cap rows and `alert.more` commit in one transaction per kind, retried at the next scan; the cheap minors
  (thresholds normalized on read, an inclusive `Items` horizon) in the same round (c3e8e9d) [31], [5].
- 14:23 — minor 8: `k.enabled` stays in the Key Vault key definition — why: a disabled key is not in use — cost: a
  disabled key with an expiry is never alerted; R42 row 4 amended [4].
- 14:17 — the archtest exemption for `internal/testutil` in `TestEveryTargetInsertChecksTheLicense` is accepted —
  why: `buildtags_test` forbids release files importing test code.

## Dashboard and reports (Tasks 9–10, 18)

- 14:17 — the dashboard's certificate and Key Vault counts are **cumulative windows with the list filter's meaning**
  (Expired / Within 7 / Within 30 / Within 60 days, each equal to the rows its link opens); the contract's field names
  stay; the exclusive `expiry.BucketOf` stays internal — why: owner step 3 and the existing filter are cumulative, and
  a count must equal its list — cost: less information per card [14].
- 14:29 — Task 9 fix round: the counts were over monitored items with `<=` boundaries and counted in Go → one
  `count(*) FILTER` statement over every certificate row with the list's predicates (expired `<= now`, windows
  `< now + N days`) and an equality test against `inventory.ListCertificates`; the Key Vault line counts Key Vault keys
  and client secrets only (Key Vault certificates are certificates); a `needs_attention` deployment never ages out of
  the list — why: a count must equal its list and one statement meets R32 — cost: the dashboard counts certificates
  that are not in use (the list shows them too) [14].
- 14:37 — Task 10 follow-up (5b64bc0): the retention is clamped to 1–3650 on read and read once per destroy run (an
  overflow would have destroyed every retired key at once), a Views test with data, `row_count` in the export audit
  row — why: cheap, safety-relevant [16], [30].
- 14:32 — the export pages the list's own pages of 200 (the list's maximum, not the plan's 1,000) in two passes, and
  `reports.ErrExportBusy` is a new busy error — accepted [16].

## SSO (Tasks 11–12)

- 14:09 — a refused SSO sign-in (`RefuseOIDC`: no mapped group any more, overage, disabled provider) also revokes the
  user's API tokens — why: access ended at the IdP must end every credential Alice issued on it (O-08, SEC-014) — cost:
  a refused user re-creates tokens after a successful sign-in; demotion keeps tokens because a token is capped by its
  owner's current role at every request (verified in `tokens.go`) (ef98801) [21], [24].
- 14:15 — Task 11 review minors 1 (no recovery codes for SSO users), 2 (the Admin cap read `FOR SHARE` inside the
  sign-in transaction), 4 (a same-user step-up test) and 5 (subject and issuer length caps) are built in the Task 12
  session (666063d) — why: cheap, same package, close a time-of-check window [23], [24], [36]. Carried to Task 12: call
  `RefuseOIDC` for `email_in_use` and `user_disabled` too; to Task 15: map the SSO errors and the callback cookie flags.
- 14:09 — `StepUpOIDC` takes the resolved role (a contract change for Task 12) — why: S-1 needs it [22].
- 14:36 — Task 12: an issuer change on a provider with users re-bound them to another IdP (I-1) → refused while users
  exist (fix round; the first in-transaction check read a pre-wait snapshot and was split into lock-then-EXISTS, caught
  by the new race test); M-1 a JWKS fetch failure is `idp_unreachable`; M-3 the step-up locks in sign-in order; M-2
  (expired keys dropped on a failed refetch, fail closed) accepted as a documented deviation; M-4 (a disabled provider
  ends no session) parked (2b8b354) [19], [34], [42].
- 14:29 — Task 12 implementer rulings accepted: the token exchange uses `client_secret_basic` only (auto-detect would
  send the code twice and blur `login_invalid`); a missing switch row is created on first lock; `sso.mapping.denied`
  has result `denied`; the service does not zero the caller's secret [19], [24].
- 15:09 — parked: a sign-in verified against the old issuer may insert its user just after the issuer change commits
  — why: only an Administrator can open the window and it lasts one in-flight callback; closing it needs a
  provider-version check in the sign-in transaction — cost: one stale-issuer user row [42].

## Wiring and jobs (Task 13)

- 15:27 — the C17 seed counts become cumulative (within 7 days 4, within 30 days 7, within 60 days 8); Task 21 reads
  them from the seed answer [41]. `alerts.scan` runs one at a time under a database session lock [32].
- 15:35 — Task 13 fix round: `release-symcheck`'s test-code guard read `nm` symbols only and missed an import used for
  a constant or type → a `go list -deps` check with a positive control (0f5636c), then the controller's follow-up
  writes the listings to files so a failed `go list` fails the check (ebb6876) [39].

## API (Tasks 14–15)

- 16:38 — Task 14 fix round: the browser-session export limit was untested (I1); M6: HEAD on audited export GETs is
  405 without an export or audit row, new code `ALC-SYS-0009`; M2: Administrators' API tokens may read the delivery
  status, the OpenAPI says so (4138d1e) [16], [8]. ALC-RPT-0004 `export.busy` (409, `Retry-After: 5`) and the reason
  `user.sso_user` (C-s4-07) accepted [28].
- 17:20 — Task 15 fix round: a callback with a fresh random binding cookie per request was never rate limited → the
  per-address bound stays with the per-cookie 10 a minute inside (I-1); M-1 providers are created switched off; M-2
  `PUT /sso/settings` without `allow_admin_role` is 422 (never a silent demotion); M-5 `client_secret` forbidden in
  every response schema; M-6 HEAD on the callback is 405 (a HEAD consumed the single-use state); M-7 PATCH with a null
  `client_secret` is 400; M-8 A-06 asserts exactly one denied row; M-3 (404 unknown / 403 disabled on start) accepted
  and documented; M-4 (the guard's 429 on the callback is a JSON page) skipped (63e2439) [18], [19].
- 15:00 — Task 15 implementer rulings accepted: `DELETE /sso/group-mappings/{id}` needs `?provider_id=`; a bad
  callback path ID redirects as `login_invalid`; `SafeNext` applied again in the callback [19], [35].

## Integration and performance (Tasks 16–17)

- 18:38 — Task 16 found one defect outside its package: the nginx guard test's allow-list of `InsecureSkipVerify`
  lacked `notify.pinnedTLS` (3d5166f; the test now also requires the pin comparison there). Rulings on its concerns:
  (1) `PUT /settings/general` may clear Alice's address while a provider is on — starts then fail cleanly with 409
  `ALC-SSO-0004` — parked as a known limitation [42]; (2) a provider created before the address is set has an empty
  redirect URI → Task 19 follow-up: a hint and a link to Settings → General (e472744); (3) the Strict session cookie
  after a cross-site redirect chain → Task 21 verifies it in Chromium; (4) the nonce in clear while pending, as the plan
  allows.
- 18:55 — Task 16 fix round 1: export equality compared only 2/16 and 3/13 columns (I-1), no ID/access-token canary
  and no Basic/AUTH PLAIN spellings (I-2), F-61 and the scheduled half of F-63 not over the wire (I-3) → 41ed252,
  6df6071; round 2 (19:25): the SSH key seed kept several columns constant, so a column swap would pass → every column
  varies (313039a; sources set at INSERT because the `Z1004` trigger refuses a later source change; the second server
  is `seed-web-3`). Its Docker run waited for the controller's DOCKER OK while Task 21 owned Docker.
- 19:32 — Task 17: no alerts test covered the two "monitored" exclusions (a missing location, a deleted target) → one
  test (3748eb5), under the same DOCKER OK hold. The query change of 394ea97 (`NOT MATERIALIZED`) was proven
  equivalent by the review [38].

## Web (Tasks 18–19)

- 14:17 — Task 18 fix round: the cumulative relabel (above) and loading and per-query error states (55be7e7).
- 18:00 — Task 19 fix round: **Send test e-mail** bypassed the step-up wrapper (I1); switching **SSO users may be
  Admin** off had no confirmation although it demotes every SSO Administrator and ends their sessions (I2); minors:
  `gcTime: 0` on secret mutations (no `reset()`, because the saved note and errors read the mutation state), `goTo`
  accepts only `https` (or `http` on an `http` page), the mapping delete confirms, a loop test over every `sso_error`
  reason, **Save alert thresholds** disabled while a row is empty (1b4cc48).

## End-to-end (Tasks 20–21)

- 16:30 — Task 20 approved as built: the fakes' `ctl` commands, the IdP published on `127.0.0.1:9444` only; the fake
  IdP stamps tokens with the real time, so Task 21 does SSO steps before any clock move.
- Task 21 (Docker alone, Opus): the SSO journey is its own test per language (the fake IdP's real-time tokens against
  the e-mail journey's clock moves); the controller's verify items answered: `check-hardening.sh` passes for both
  fakes on the live stack (49 checks); after an SSO sign-in Chromium sends the Strict session cookie on the same-origin
  303 from the callback and the first write has its CSRF token, so Task 16's concern (3) does not happen.
- Task 21 defects fixed in their own commits with red tests (no active owner): D-1 the saved views menu (axe
  `aria-required-children`, contrast; 045c8e7); D-2 four status texts and the sign-in divider under 4.5:1 (7b3fa58 —
  ruling: fixed rather than reported, because the axe gate of every new screen cannot pass otherwise — cost: revert
  one commit); D-3 the Turkish switch-off confirmation equal to the close button's name (5606317); D-7 the jobs runner
  skipped the lock sweep while the last sweep lay in the future after the clock was set back (1fac017) [40].
- Reported, not fixed: D-4 (the provider dialog's focus falls to `<body>` after save), D-5 (the password field's error
  does not set `aria-invalid`), D-6 (the Users table scrolls the page sideways at 375 px; Phase 1 page, phone width not
  required there).

## The performance ruling (Task 22)

PENDING-FINAL-RUN: the ten p95 values of each of the three `make perf` runs, and the ruling (`perf` added to the first
line of `ci`, or kept outside with a release-checklist line in `04-security.md` §17.7) with its reason. Task 17
recorded, after its query fix, a highest p95 of 14 % of its budget (`certificates?q=`) over three runs on this machine;
its review noted that the R32 data set seeds no SSH keys (the SSH key list is measured almost empty) and that the
`q=` search is linear.

## Final review

PENDING-FINAL-RUN: the final whole-branch review of the phase, its findings and the rulings on them, ran in parallel
with this document.

## Process

- Models, as the ledger and the commit trailers state them: the plan by Opus 5.5; the pre-flight security review by
  Fable, the consistency scan by Opus. Implementers per the trailers: Sonnet 5.5 for Tasks 1 to 10, 18, 19 and 20
  (and their rounds), for Task 16's round 2 (313039a) and Task 17's round 1 (3748eb5); Opus 5.5 for Tasks 11, 12 (with
  the Task 11 follow-ups and the `SafeNext` hardening), 13, 14, 15, 16 (rounds 0 and 1), 17 and 21; the Task 13
  follow-up ebb6876 is the controller's (Fable 5.1); 4748c6a (coverage floors and the perf line) names Sonnet 5.5. Reviews: Opus for the security-sensitive tasks (2, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17), Sonnet
  for Tasks 1, 3, 4, 18, 19, 20 and every scoped re-review. Where a trailer and the ledger differ, the trailer is
  quoted.
- Every task was reviewed by an agent that did not write it; fix rounds went back to the package owner of the moment
  and were re-reviewed in scope. Fix rounds per task: Tasks 1, 2, 3, 5, 10, 11, 20: 0 (Task 10 and Task 11 had a
  follow-up commit covered by the final review); Tasks 4, 6, 7, 8, 9, 12, 13, 14, 15, 17, 18, 19: 1; Task 16: 2.
  No task reached the cap of 5.
- The session was cut at about 14:37: three agents (Task 12's fix round, Task 10's follow-up, Task 13) left
  uncommitted work in the shared tree (`go build ./...` still passed); fresh agents resumed each from the files and the
  ledger (14:58). The Task 12 resumer corrected the interrupted fix (the single-statement lock-and-check read a
  pre-wait snapshot).
- Docker ownership: Task 21 owned Docker alone; Task 16's round 2 and Task 17's round 1 wrote and vetted their tests
  meanwhile and ran their suites only after the controller's DOCKER OK.
- Test-first was not followed everywhere: Task 20's two binaries were written before their tests (red only for the
  compose and archtest tests); Task 16's suites were written against shipped code ("red" = first-run test mistakes,
  plus a mutation check of the leak scan); Task 11's review follow-up was red only as a compile failure.
- The controller's own wrong instructions, corrected: the Task 15 dispatch's carry 3 ("`limitLogin` must cover start
  and callback") contradicted the adopted S-11 (the ruling wins); the Task 14 dispatch asked for "the existing 409
  busy code" for a busy export (none fitted; `ALC-RPT-0004` was created).

## Status at phase close

Commits per task (from `git log` and the ledger; a range includes the fix rounds):

- Plan: 28b5498. Task 1: 472d718. Task 2: 053aa89; hardening 613cb66 (in Task 12's session). Task 3: 7950d66.
  Task 4: d8adf4d, c77c309. Task 5: 6e557d8, cf40eee, fcd1e7a.
- Task 6: 9312496, fadcc58. Task 7: d673884, 85e4dab. Task 8: 4421b7d, c3e8e9d.
- Task 9: b507638, 69bb580, 5a102aa. Task 10: 52a25d3, 9a8d7c8, 5b64bc0.
- Task 11: dc7a54b, ef98801, 666063d. Task 12: e4086fd, 2b8b354.
- Task 13: 828fa82, 0f5636c, ebb6876. Task 14: 59f53ca, 4138d1e. Task 15: d6e757f, 63e2439.
- Task 16: 2c65b4e, 3d5166f, 41ed252, 6df6071, 313039a. Task 17: 394ea97, d7c93db, 3748eb5.
- Task 18: a39b5b0, 55be7e7. Task 19: 4bc5ddf, d2c9b04, 1b4cc48, e472744.
- Task 20: 6f0080c. Task 21: 045c8e7, 7b3fa58, 5606317, 1fac017, 229f178.
- Task 22: 4748c6a (coverage floors, the perf line); the documentation commits of this task; PENDING-FINAL-RUN: the
  commit of the final `make ci` evidence and of the final review's fix round, if any.

## Carried to later phases

Re-deferred by the plan's "Carries and deferred items", with their reasons:

- Phase 8: the certificate private-key download (carry 1: the TLS key format and its own S-09 suite); the keyed audit
  chain, syslog/SIEM forwarding (SEC-073) and the app-writable `jobs.audit_verify` (carry 17, R42 [27]); SMTP as a
  wizard step (carry 21, §26.10); the helper scans per key change, lockfile secret scanning, `osv-scanner`, the
  real-systemd job, a nightly pipeline, mutation testing, packaging (carry 25); a Microsoft Graph lookup for the Entra
  overage (R42 [20]).
- v1.x, no phase named: the Phase 5 settings items (Azure proxy and CA bundle, deployment windows, wave limits,
  sovereign clouds; carry 6); SSH limits and `ssh.max_parallel`, `nginx.backup_retention_days` as settings (carry 18).
- Unassigned: `facts.nginx.scanned_at` (carry 9); e2e hooks for the route error page, the `unverified` banner and the
  locale fallback (carry 11); uncoalesced inventory refusal rows, now also `auth.oidc.denied` (carry 12); recovery
  codes lost with the completing answer (carry 13); the dead-task e-mail of a manual test merged into a live re-test
  (carry 19); a `users.timezone` UI (carry 20; e-mails stay UTC); the Phase 6 parked items F1–F4, L1–L13, N2,
  N15–N17, I-5, D22–D28, FB-4, FB-7, P6-28, the property schedules and the web minors (carry 22); the Phase 5 parked
  items (carry 23); the Nginx helper items (carry 24).
- Owner only: the real-Azure items (carry 7); a git remote and the first workflow run, the production license key,
  the walkthroughs of Phases 1–6 and the remediation, the real-Azure suite, the Turkish tone review, the crypto
  sign-off, a clean-machine `make ci` (carry 26), and now the Phase 7 walkthrough table of
  docs/security/reviews/phase-7.md.

Parked or deferred in Phase 7 (each also a known limitation or minor in docs/security/reviews/phase-7.md; no later
phase named unless given):

- SSO: the in-flight sign-in after an issuer change; a disabled provider ends no open session (M-4); Alice's address
  can be cleared while a provider is on; providers that accept only `client_secret_post` and endpoints with a query
  (AD FS `?api-version`) are refused; a new HTTP transport per exchange and key-set cache entries never evicted; the
  provider count checked outside the insert transaction (concurrent creates can exceed 5); `SaveSettings` audits and
  demotes when nothing changes; a step-up `Begin` maps any database error to `ErrNotSSOUser`; the user-name shape not
  enforced in `normalized`; token principals carry no `AuthSource`; `ended_count` counts unpruned expired sessions; two
  first sign-ins of different identities wanting the same free user name can race (one retries).
- Alerts and mail: a level reversal is possible only if two scans overlap (prevented by the session lock); a malformed
  row aborts the whole `Items` statement; retries of failed items can push a kind over 20 across scans and one
  persistently failing over-cap item fails its kind's summary every scan; `alert.sent` is audited for never-e-mailed
  over-cap rows; `failed_24h` is approximate; a corrupt `notify.recipients` row fails every caller's transaction
  (lockout, license tick); one refused recipient raises the failing banner; `smtp.PlainAuth` keeps the password as a
  Go string; the user-name-without-password warning repeats at every start; a stored legacy display-name recipient is
  delivered as its raw string; `warnIfNobodyIsEmailed` repeats notify's recipient SQL.
- Reports and exports: pass 2 can cut an export at 50,000 rows silently; actors without an ID share one export slot;
  `CreateView` accepts values the list refuses (a 422 when applied); headers are English; a failed deployment stays
  listed after a later success (no supersede rule, a spec question); a first verification that finds a broken chain
  stores no checkpoint; a manual **Verify** that finds a break does not update `jobs.audit_verify` until the next
  scheduled run; the R32 data set has no SSH keys and `certificates?q=` is a linear scan.
- Web: D-4, D-5, D-6 (above); the switch-off confirmation says SSO Administrators become Operators while the server
  makes them Auditors (found while writing these documents, P7-20 of the review); Settings screens not in the
  `screens.i18n` sweep; the mail form's 422 wording reuses shared field names and shows field errors twice; a cleared
  secret must be retyped after a failed save; trusting remounts the mail form and drops unsaved edits; the mail
  password stays in memory while the Mail tab is open after a save; `ALC-RPT-0004` shows no cooldown; `maxLength`
  counts UTF-16 units elsewhere; a 429 on the OIDC callback is a JSON page.
- Test gaps the reviews named: the 50,000-row boundary over the wire, O-14 with a real second provider, the remaining
  S-1 variants over the wire, the one-hour seen-record expiry over the wire, a failed refetch while cached keys are
  valid, a PKCS #1-keyed HS256 verifier, the fakes' shutdown (keep-alive goroutines; `fakesmtp.Up` re-listens on the
  old port) and their SMTP looseness (an accept-then-reject fault, several refused recipients, wire bytes).
