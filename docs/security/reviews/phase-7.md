# Security Review — Phase 7 (Alerts, dashboard and SSO)

Scope (spec §17.2, Phase 7: "OIDC flow, email header injection, output escaping, notification content leaks"; gate:
"OIDC test suite passes; no secrets in emails; XSS tests on all rendered strings"; §26.9): the OpenID Connect sign-in
and step-up (SEC-010 to SEC-015) and the SSO administration; the mail settings, their password and the trust of a mail
server's certificate; what an e-mail can carry; the exactly-once expiry notices; the dashboard and what each role sees
of it; saved views; the CSV export of the inventory; the secrets of settings at rest; outbound connections to mail
servers and identity providers; the two e-mail and identity fakes of the e2e stack.

**Nothing in this phase was run against a real identity provider or a customer's mail server.** Single sign-on was
exercised only against the in-repository fake identity provider (`internal/testutil/fakeidp`, and the e2e container
`fakeidp` built from it), whose discovery, keys, authorize and token endpoints follow the specification and inject the
faults of the O-suite; Microsoft Entra ID, AD FS and Keycloak were never contacted. E-mail ran only against
`internal/testutil/fakesmtp` and the e2e container `fakesmtp` (STARTTLS, a self-signed certificate, AUTH PLAIN). The
section "Known limitations" lists what that leaves open.

The decisions behind this phase are R42 in `docs/superpowers/specs/alice-v1/00-decisions.md`; R42 item numbers are
given in brackets below. The controller's rulings, with what each costs if wrong, are in
`docs/superpowers/rulings/phase-7.md`.

## Method

The phase was built in 22 tasks on branch `phase-7` (base `master` aa7985b, plan 28b5498). Every task was reviewed by
an agent that did not write it, and every finding went back to the implementer as a fix round that was reviewed again
in scope. The ledger names security reviews (spec, quality and security together, Opus) for the claim rules (Task 2),
the migration (Task 5), the mail settings and delivery (Tasks 6–7), the scan (Task 8), the reports (Tasks 9–10), the
SSO users and the OIDC service (Tasks 11–12), the wiring (Task 13), the API (Tasks 14–15), the integration suites
(Task 16) and the performance change (Task 17). Reviewers walked lock orders and interleavings, mutated code to see a
named test turn red (the binding comparison, the step-up role resolution, the scan lock, the recipient warning, the
export limit, the leak scan's allowed places) and swept answers, logs, tables and e-mails for canaries. Small
follow-ups after an approval (5b64bc0, e472744, ebb6876) were checked by the controller and go to the final review.

Before Task 1 a pre-flight security design review found 13 design findings (S-1 to S-13: Critical 0, Important 4,
Minor 9) and a consistency scan found 20 blocking and 53 fix-round defects of the plan; all were ruled on before the
first task. The Playwright journeys (Task 21) found four product defects and fixed them (D-1, D-2, D-3, D-7) and
reported three more (D-4 to D-6).

The final whole-branch review (2026-10-10, at 3748eb5: Critical 0, Important 2, Minor 27) is folded into the Findings
below; its two Important findings and three security-relevant minors were fixed before the final run. The cells marked
The final run is `make ci` of 2026-10-10 (commit dad4343).

## Evidence

All commands run from the repository root; `-tags integration` needs Docker (testcontainers). The column "Recorded
before the final run" holds the latest results the implementers recorded in their task reports, with the commit
named; they are their reports, not runs made for this review, which was written without Docker. The column "Final
run" holds the results of the final `make ci` (which runs `make coverage`) and of the final Playwright run.

| # | Check | Command | Expected | Recorded before the final run | Final run |
|---|---|---|---|---|---|
| 1 | Unit tests, all packages (pure rules: `expiry` 100 %, `claims` 100 % with `FuzzParse`, `csvx` 100 %; the API's handlers, codes, DTO goldens, authz matrix) | `make test` | ok | ok per package in every report; `claims` `FuzzParse` 20 s, about 2.5 million executions, no crasher (053aa89); api unit 95.9 % (63e2439) | ok (`make ci`, run 5, commit 97b198e) |
| 2 | Integration tests, all packages | `make test-integration` | ok | every package ok (64) except `internal/providers/nginx`, whose guard test lacked the one allowed `InsecureSkipVerify` place; fixed in 3d5166f and green (Task 16 report) | ok as part of `make coverage` (exit 0, 2026-10-10), with the final-review fixes |
| 3 | O-suite: O-01 to O-14 at service level and over the wire, X-05, S-1 | `go test -tags integration ./internal/auth/oidc ./internal/api -run 'TestO\|TestAdminMappingRefusedWhileOff\|TestOIDC\|TestX05\|TestS1\|TestSSO'` | every case refused with its closed reason, no session, one `auth.oidc.denied` row | `internal/auth/oidc`: 13 `TestO*` functions (O-01 to O-12, O-14; O-13 is `TestAdminMappingRefusedWhileOff`), 31 tests in the package, 87.0 % (2b8b354); over the wire `TestOIDCNegativeSuiteOverTheWire` (every O-row with its exact `Location`, no cookie, one denied row), `TestOIDCStepUpReevaluatesOverTheWire`, `TestOIDCLimitsOverTheWire`, `TestX05BreakGlassWhileIdPDown` (6df6071) | ok as part of `make coverage` (exit 0, 2026-10-10), including the new I-1 tests (a sign-in with an old `auth_time` gets no step-up window) and the I-2 token refusal over the wire |
| 4 | Performance R32: 5,000 certificates, 500 targets, p95 ≤ 500 ms (dashboard) and ≤ 300 ms (lists), three runs | `make perf` (×3) | every p95 within budget | after 394ea97: worst p95 `certificates?q=site42` 41.1 ms of 300 (14 %), `dashboard/expiring` 48.0 ms of 500 (10 %), `dashboard/summary` 7.9 ms; before it the expiring list was at 127–132 % (d7c93db, Task 17 report) | three runs, all passed; worst p95 per path across runs: dashboard/summary 8.2 ms (2 %), dashboard/expiring 47.7 ms (10 %), alerts 2.1 ms (0 %), certificates 1.8 ms (1 %), `expiry=30` 1.8 ms (1 %), `q=site42` 43.1 ms (14 %), targets 4.3 ms (1 %), deployments 3.9 ms (1 %), ssh-keys 0.8 ms (0 %), audit 1.3 ms (0 %); every p95 ≤ 60 % of budget, so `perf` joined `make ci` (4748c6a); per-run values in the rulings |
| 5 | Playwright: Phase 7 journeys in EN and TR (owner steps 1–5: seeded counts, filter, export = rows, saved view, test mail and trust, the expiry e-mail in the fake SMTP once, the failing banner, SSO refused / Operator / Administrator step-up, break-glass), axe and keyboard | `make e2e-up && make e2e-hardening-check && make e2e`, then `make e2e-down` | all passed | `phase7.spec.ts` 6 passed twice in a row (1.6 min each); full suite 110 passed in 26.8 min after 1fac017, no retry; hardening check 49 lines ok, both fakes included (Task 21 report) | 110 passed in 26.9 min, no retry; hardening check ok (`make ci` tail, commit dad4343) |
| 6 | Coverage floors, with new floors for `alerts/expiry` 100, `auth/oidc/claims` 100, `platform/csvx` 100 and `alerts`, `reports`, `auth/oidc`, `testutil/fakesmtp`, `testutil/fakeidp` at their measured values | `make coverage` | ok | `alerts` 91.3 % (394ea97), `reports` 81.9 % (5b64bc0), `auth/oidc` 87.0 % (2b8b354), `fakesmtp` 92.0 % (c77c309), `fakeidp` 92.6 % (41ed252); thin floors: `notify` 88.1 %, `auth` 84.9 %, `inventory` 89.1 %, `jobs` 89.0 %, `audit` 89.0 %, `sshkeys` 89.9 %, `secrets` 83.9 %, `api` 96.6 %, `cmd/alice` 91.4 %, `rbac` 98.0 % (implementers' reports); floors committed in 4748c6a | ok (exit 0): every earlier floor held; new floors at the measured values — `alerts` 91.3, `alerts/expiry` 100, `auth/oidc` 87.0, `auth/oidc/claims` 100, `platform/csvx` 100, `reports` 81.9, `testutil/fakesmtp` 92.0, `testutil/fakeidp` 92.6 (4748c6a) |
| 7 | The whole gate | `make ci` (with `TRIVY_IMAGE="--network host <the pinned image>"` on the build machine) | exit code 0 | not run | exit 0 in two parts on 2026-10-10: lint, test, coverage, perf, test-ssh, build, i18n, web, vuln and secrets-scan in one run; fs-scan, e2e and image-check/image-scan in a second run after `.claude` was excluded from fs-scan (dad4343) |
| 8 | No secret in the repository | `make secrets-scan` | no leaks | not recorded for this phase | no leaks found (three false positives in the Phase 7 documents ignored by fingerprint, b4874f0) |
| 9 | Go vulnerabilities (three new modules: `go-oidc/v3` v3.21.0, `x/oauth2` v0.37.0, `go-jose/v4` v4.1.5) | `make vuln` | none in the code | 0 vulnerabilities affecting the code; one module-level finding, `GO-2026-5932` in `golang.org/x/crypto` v0.57.0 (required before this phase, not called, no fix); none in the new modules (e4086fd, Task 12 report) | 0 vulnerabilities after Go 1.27.2 and `x/net` 0.60.0 (before: ten standard library findings in Go 1.27.1) |
| 10 | File system and image scan | `make fs-scan` | 0 HIGH/CRITICAL | not recorded for this phase | 0 HIGH/CRITICAL (source tree and image); the earlier HIGH in `x/net` 0.58.0 is fixed by 0.60.0 |

Other evidence recorded by the implementers and reviewers (their reports, not re-run here):

- `TestPhase7SecretsNeverLeak` plants three SMTP passwords, three client secrets, every authorization code, PKCE
  verifier, binding cookie, state and nonce, every ID and access token (whole, payload and signature parts), the master
  key and both `setting_secrets` data keys, and searches each in plain, hex and base64 spellings (also the Basic header
  and AUTH PLAIN forms) in every answer body and header, every DEBUG log line, every row of every table and every
  e-mail; the binding cookie, state and nonce are allowed only where they belong (the start and step-up answers), and a
  mutation that allows them nowhere fails at exactly those places (6df6071).
- Mutation: comparing the binding with itself fails `TestO03StateNonceAndCodeReplay`; skipping the step-up's role
  resolution fails `TestS1StepUpReevaluatesGroupsAndNeedsALiveSession`; the issuer-change check in one statement fails
  `TestIssuerChangeRefusedOnceAUserArrives`; ignoring the JWKS fetch probe fails `TestJWKSUnreachableIsIdPUnreachable`;
  removing the session line of the export limiter fails `TestExportLimitIsPerUserAndPerToken`; bypassing the scan lock
  or the recipient warning fails the two `cmd/alice` scan tests; a `{{days}}` in a template its sender does not fill
  fails `TestAlertAndAuthTemplatesRenderInBothLanguages`.
- The export is compared cell by cell with the list for every column (16 certificate columns, 13 SSH key columns) over
  15 filters, with more than 1,000 escaped cells (`TestExportOverTheWireEqualsFilteredRows`, 313039a); the audit row is
  committed while a blocked client has not received the first byte (`TestExportAuditedBeforeTheFirstByteAndOneAtATime`).

## Threat notes

### OIDC flow (SEC-010 to SEC-015)

- **Flow and state** (SEC-010, SEC-011) [18], [35]. Only the authorization code flow with PKCE S256 exists. `POST
  /auth/oidc/{id}/start` (and `/stepup`) stores a state row in `oidc_login_states` — the state hashed, the nonce,
  the PKCE verifier, `next`, the step-up flag — for at most 10 minutes, and sets the binding cookie `__Host-alice_oidc`
  (Secure, HttpOnly, SameSite=Lax, 600 s), whose hash is stored with the row. The callback deletes the row with
  `DELETE … RETURNING` before anything else, so a state is used once; a missing, expired, other-provider or
  other-browser state (the binding compared in constant time) is `login_expired`. The callback clears the binding
  cookie first and always answers 303. Pruning removes expired rows hourly. Codes, ID tokens and access tokens are
  never stored or logged. The callback is a `GET` because the protocol requires it: it is the one documented exception
  of A-06 (one state row consumed, at most one session, exactly one audit row); HEAD on it is 405.
- **Token validation** (SEC-012) [34]. go-oidc verifies the signature with Alice's bounded key set (compact JWS only;
  RS256, ES256, PS256; at most 50 keys, 1 MiB; the cache expires by the provider's `Cache-Control`/`Expires`, clamped
  to 5 minutes – 24 hours; an unknown `kid` refetches at most once a minute; a failed refetch drops expired keys), then
  `claims.Validate` checks `iss` exactly, `aud` contains the client ID, `azp` with several audiences, `exp`/`iat`/`nbf`
  with 60 s leeway on the injected clock, the nonce in constant time, and for a step-up `auth_time` at most 5 minutes
  old. `alg=none`, HS256 keyed with the public key (DER and PEM), another key and an unknown `kid` are refused
  (`TestO01Signatures`).
- **Issuer, endpoints and `next`** (SEC-013) [19], [35]. The issuer and the three endpoints are read by discovery when
  an Administrator saves or refreshes the provider, must be `https` without a query, and the discovery document must
  name exactly the configured issuer; nothing of a sign-in request chooses them. The redirect URI is derived from
  Alice's configured address. `next` passes `claims.SafeNext` twice (at start and in the callback): same-origin paths
  only, no `//`, backslash, control characters, `.`/`..` segments or `/api` paths, also after percent-decoding
  (`TestSafeNextRefusesOpenRedirects`, `TestSafeNextRefusesDotSegmentsAndDecodedAPIPaths`).
- **Groups and roles** (SEC-014) [20], [21], [24]. The groups claim is read as a string or a list (at most 1,000); an
  overage marker refuses (`groups_overage`); matching is exact; no mapped group refuses (`no_access`); the highest
  mapped role wins and Administrator is capped at Operator while **SSO users may be Admin** is off, read `FOR SHARE`
  inside the sign-in transaction while the switch and mapping creation lock it `FOR UPDATE`. A refusal of a known user
  for `no_access`, `groups_overage` or `provider_disabled` ends their sessions and revokes their API tokens.
- **Identity** (SEC-015) [23]. Users are matched by `(oidc_provider_id, oidc_subject)` only; a first sign-in whose
  e-mail is a local user's, and an e-mail change into one, are refused; a local user never signs in through the
  callback; SSO users cannot be break-glass and their role, password and MFA cannot be changed by hand. The local
  administrator signs in with password and code while every IdP is down (`TestX05BreakGlassWhileIdPDown`; e2e
  break-glass journey).
- **Step-up** [22]. An SSO user's step-up is a fresh IdP sign-in (`prompt=login`, `max_age=0`) accepted only on a live
  session of the same user and provider; it re-evaluates the role and never resurrects an ended session (S-1). An SSO
  **sign-in** opens the step-up window only when the ID token's `auth_time` is at most 5 minutes old (the window ends
  5 minutes after it); a silent sign-in at the IdP, or no `auth_time`, leaves it closed (final review I-1, bc1a234).
- **Credentials Alice issues** [21], [23]. SSO users cannot create API tokens (409 `ALC-USR-0003`, final review I-2,
  e0fa7b8), so de-provisioning at the IdP leaves no Alice credential behind except an open session (up to 12 hours).
- **Rate limits** [18]. The start keeps the per-address sign-in limit (10 a minute); the callback is limited to 10 a
  minute per binding cookie inside the anonymous 60 a minute per address (a fresh random cookie per request does not
  escape the address bound, Task 15 I-1). The start's shared 10 a minute per address is a known limitation behind NAT.

### E-mail header injection and content

Every e-mail parameter is flattened to one line (CR, LF and other line breaks replaced) before rendering; subjects are
Q-encoded (`mime.QEncoding`) and bodies base64, so a certificate CN, website name, vault name or user name with CR/LF,
`{{`, HTML or 2,000 characters never adds a header or a template expansion (`TestRenderFlattensHostileParams`,
`TestSMTPMailerKeepsTheSubjectOnOneLine`); the Subject is capped at 200 characters and folded between encoded words,
so no header line exceeds 998 octets (final review minor 14, 24fc606). The recipient list is built by Alice from bare addresses only (no display
names, angle brackets or comments; duplicates compared as parsed, case-folded mailboxes), and every message has
exactly one recipient. The test e-mail's recipient is checked with `net/mail`.

**What each e-mail names**: expiry e-mails — the item's name, its expiry in UTC, days left, up to 10 websites and
servers, the certificate's SHA-256 fingerprint, the vault name; the license note with Alice's license page; the
summary — a count and the kind; the lockout e-mail — the user name, the minutes and the number of failed attempts;
the test e-mail — a fixed text. None carries a password, a secret, a token, a private key, a session or an internal
error text; the SMTP password's canaries are absent from every e-mail (`TestPhase7SecretsNeverLeak`). Recipients are
whoever an Administrator configured: an extra address outside the organisation receives server and website names.

### Output escaping: CSV and the web

- **CSV formula injection** [16]. Every cell of the inventory and audit exports passes `csvx.Safe`: a cell starting
  with `=`, `+`, `-`, `@`, a tab or a carriage return gets a leading apostrophe; quotes, commas and newlines are quoted
  by `encoding/csv`; the file starts with a UTF-8 BOM (`TestSafeNeutralisesFormulaPrefixes`, `TestWriterQuotesAndBOM`,
  the e2e check of a certificate labelled `=cmd|calc` exported as `'=cmd|calc`). Leading whitespace before a formula
  character passes through, as the rule is written (see "Known limitations").
- **XSS in the dashboard and settings**. The web renders every server value as React text: `dangerouslySetInnerHTML`
  is refused by the lint rule, fingerprints, hosts, issuers, client IDs, group values and addresses are shown in
  `<Code>` as text, `sso_error` is looked up in a closed set (`<script>` in it shows the generic text,
  `LoginPage.test.tsx`, `AppLayout.test.tsx`), unknown condition kinds are skipped, and navigation to an IdP accepts
  only `https` (or `http` on an `http` page) URLs (`web/src/navigation.test.ts`). There is no per-widget test with hostile
  strings for every new screen (see the checklist).

### Notification content leaks and the failing state

The delivery status (`/notifications/status`, the dashboard section, the banner) gives Administrators only counts, the
last failure time and a closed error label (`smtp.connect`, `smtp.tls`, `smtp.untrusted`, `smtp.auth`,
`smtp.rejected`, `smtp.address_refused`), never the server's text; Operators and Auditors get `{"failing": false}`.
`ALC-NTF-*` answers carry no server text; `ALC-NTF-0005` carries the certificate's fingerprint, subject (cut to 300
runes) and expiry only.

### The SMTP trust decision and the pin [10]

TLS is mandatory (STARTTLS or implicit TLS, 1.2+). A certificate is accepted when it verifies against the system roots
plus the optional CA bundle, or when its SHA-256 equals the pin. The pin can be set only to a certificate a failed test
saw for the same host and port within the last hour, once; changing host or port removes it. `InsecureSkipVerify`
appears in `notify.pinnedTLS` alone, whose `VerifyConnection` compares the leaf's hash in constant time; the nginx
guard test requires exactly that place (3d5166f). Trust and untrust are audited with the fingerprint.

### Secrets of settings at rest

The SMTP password (`notify.smtp.password`) and every client secret (`sso.provider.<id>.client_secret`) are rows of
`setting_secrets`, sealed with the master key (AES-256-GCM, AAD `setting_secrets/<key>/ciphertext`). They exist in
clear only in the request body that sets them (a `secretText` the handler zeroes) and in a `secrets.Plaintext` opened
for one SMTP `AUTH PLAIN` or one token exchange. A stored secret is never sent to a new destination: a changed mail
server host or port, or a changed issuer, needs the secret again (422 on `password` / `client_secret`; final review
minor 11, 993d96a), so a stepped-up session cannot redirect it to a server it controls. Answers carry `has_password` / `has_client_secret` only (the OpenAPI
forbids `password` and `client_secret` in every response schema). The web keeps them only in its form's state
(`gcTime: 0` on the mutations). Go strings made by `smtp.PlainAuth` and `oauth2.Config` cannot be cleared (below).

### SSRF of SMTP and OIDC [11]

Mail servers and identity providers are reached through `netaddr.DialContext`: every resolved address is checked when
Alice connects, link-local and metadata addresses are refused, loopback and private ones allowed (Administrators
configure them). OIDC HTTP uses no proxy, keeps no idle connection (`DisableKeepAlives`, bab83f0), follows no redirect, has a 10 s budget and reads at most 1 MiB. The release
build passes no dialer override (`TestReleaseMailSettingsHaveNoDialerOverrideOrFallback`).

### The exactly-once ledger [2], [5], [31], [32]

A notice is queued only by the transaction that inserted its `alerts` row (`ON CONFLICT DO NOTHING RETURNING`), unique
per kind, object, expiry instant and threshold; only the most urgent reached threshold is queued and nothing less
urgent after it; a renewal starts a new series. Scans are per item and one at a time across processes (a session
lock); the summary of a kind commits with its over-cap rows. Hourly ticks over 70 days, downtime, threshold edits,
four concurrent scans, a lock and no SMTP are covered (`TestHourlyTicksSendEachThresholdOnce`,
`TestDowntimeSendsOnlyTheMostUrgent`, `TestThresholdEditsNeverResend`, `TestScanIsExactlyOncePerThreshold`,
`TestDowntimeCatchUp`, `TestConcurrentScansQueueOnce`, `TestL28LockNote`, `TestL18NoSMTP`); the outbox delivers each row
once per recipient (`TestF60OutageDeliversOnceAndRaisesFailing`, `TestF60OverTheWire`). `alerts` is append-only for
`alice_app`.

### Role filtering of the dashboard [13], [14]

Everyone sees counts, the expiring list, failed deployments, targets, rotations and the license's `expired` flag;
Administrators and Auditors also the license detail, the audit head and a broken chain; Administrators (and their API
tokens) the delivery state and the failing condition (`TestSummaryIsRoleFiltered`, `TestDashboardIsRoleFiltered`,
`TestDashboardOverTheWire` for three roles). Saved views are private per user (`TestViewsArePrivateAndBounded`).
Every settings route needs `settings.manage` and every SSO administration route `sso.manage` (Administrator, step-up,
never a token) (`TestPhase7RoutesAuthz`, `TestSSORoutesAuthz`, the generated matrix).

### The e2e fakes

`fakesmtp` and `fakeidp` are test-only (`internal/testutil` may not be linked into a release binary: `go list -deps`
in `make release-symcheck`, archtest `testOnlyDirs`), hardened like the other e2e containers (read-only root, no
capabilities, non-root, pids limit; `fakesmtp` on the internal network without ports, `fakeidp` published on
`127.0.0.1:9444` only), hold no committed key material (generated at start) and log no secret.

## Review checklist

- [ ] OIDC test suite passes: O-01 to O-14 at service level (`TestO01Signatures` … `TestO12InsecureIssuerRefused`,
      `TestAdminMappingRefusedWhileOff` for O-13, `TestO14LocalMFANotBypassed`) and over the wire
      (`TestOIDCNegativeSuiteOverTheWire`, `TestOIDCStepUpReevaluatesOverTheWire`, `TestOIDCLimitsOverTheWire`,
      `TestX05BreakGlassWhileIdPDown`); claims (`TestValidateRefusesEachClaim`, `TestGroupsDetectsOverage`,
      `FuzzParse`); the key set (`TestJWKSRefetchIsRateLimited`, `TestJWKSExpiresByCacheHeaders`); the e2e SSO
      journeys in EN and TR.
- [ ] No secrets in e-mails: `TestPhase7SecretsNeverLeak` (every e-mail searched), `TestSMTPPasswordIsAnEnvelope` (a
      refused password's error carries neither the password nor the server's reply), `TestRenderFlattensHostileParams`.
- [ ] XSS tests on all rendered strings: covered by construction (React text only, the lint rule against
      `dangerouslySetInnerHTML`, `<Code>` for technical values, the closed `sso_error` set with its `<script>` tests,
      the `goTo` protocol allow-list) and by the Turkish/English screen sweep of the dashboard; **there is no hostile
      string test per new widget and settings screen**, and the Settings screens are not in the `screens.i18n` sweep —
      the owner decides whether this meets the gate.
- [ ] Secrets of settings only as envelopes and write-only in the API (`TestSMTPPasswordIsAnEnvelope`,
      `TestClientSecretIsAnEnvelope`, `TestSMTPPasswordIsWriteOnly`, `TestProviderSecretIsWriteOnly`, the OpenAPI
      response-field check).
- [ ] Every alert type sends once per threshold (the tests of "The exactly-once ledger").
- [ ] The dashboard numbers match the database and the lists (`TestSummaryCountsMatchTheDatabase`,
      `TestDashboardOverTheWire`, `TestSeedDashboardMatchesTheDashboard`, the e2e count links).
- [ ] The export is exactly the list, formula-safe and audited first (`TestExportEqualsTheListPages`,
      `TestExportAuditsBeforeTheFirstByte`, `TestExportOverTheWireEqualsFilteredRows`,
      `TestExportAuditedBeforeTheFirstByteAndOneAtATime`, `TestExportCapHeadAndLimitOverTheWire`).
- [ ] Mail trust only by an explicit pin (`TestF62UntrustedCertificateAndThePin`, `TestSeenCertificateIsBoundToHostAndPort`,
      `TestMailSettingsOverTheWire`); F-60 to F-63 (`TestF60OutageDeliversOnceAndRaisesFailing`, `TestF61PerRecipient`,
      `TestF60OverTheWire`, `TestF60GivesUpAfter24Hours`, `TestF61F63ScheduledSendsOverTheWire`).
- [ ] Permissions: the generated matrix, `TestPhase7RoutesAuthz`, `TestSSORoutesAuthz`, A-06 with the callback as the
      only exception.
- [ ] The performance budget is met (`make perf`, row 4 of the Evidence table).
- [ ] The release binary links no test fake or e2e endpoint (`make release-symcheck`).

## Findings

Found by the pre-flight review, the per-task reviews and their re-reviews, the integration and performance suites,
the Playwright journeys and the writing of these documents, with the commits that closed them. The reviewers rated
findings Critical, Important or Minor; none was rated Critical or High. Open findings are marked; minor findings that
were parked are in "Known limitations" and in the rulings' "Carried to later phases", which lists every open minor of
the final whole-branch review by its number.

| ID | Area | Rating | Description | Decision |
|---|---|---|---|---|
| P7-01 | Design (OIDC) | Important | S-1: the planned step-up callback accepted a revoked or idle-expired session and did not re-evaluate groups, so a session ended by a refusal or a demotion could be resurrected with its old role. | Fixed by design: dc7a54b (`StepUpOIDC` on a live session, takes the resolved role), e4086fd; `TestS1StepUpReevaluatesGroupsAndNeedsALiveSession`, `TestStepUpOIDCNeedsALiveSession`. |
| P7-02 | Design (OIDC) | Important | S-2: the planned key set never expired a known `kid`, so a key withdrawn at the IdP kept verifying. | Fixed by design: e4086fd (expiry by the cache headers, clamped); `TestJWKSExpiresByCacheHeaders`, `TestJWKSCacheFollowsTheProvidersHeaders`. |
| P7-03 | Design (alerts) | Important | S-3: one unstorable item (a CN over the 300-character CHECK) stopped the whole scan for every item. | Fixed by design: 4421b7d (per item, truncation); `TestS3LongNameIsTruncated`, `TestS3OneFailingItemDoesNotStopTheRest`. |
| P7-04 | Design (mail) | Important | S-4: a recipients change was audited without the addresses. | Fixed by design: d673884; `TestRecipientsChangeAuditNamesTheAddresses`. |
| P7-05 | Test fakes | Important | The fake IdP's HS256 confusion token was never verified, brief-mandated options and negative paths were untested, an absent nonce was emitted empty and the authorize query unrecorded (Task 4 review). | Fixed: c77c309. |
| P7-06 | Secrets | Important | `internal/secrets` fell to 82.9 % under its floor 83 (the setting-secret error paths); the server-presented subject was unbounded; a user name without a password could be imported (Task 6 review). | Fixed: fadcc58. |
| P7-07 | Mail | Important | An address with a display name passed `mail.ParseAddress` and defeated both duplicate checks: one mailbox mailed twice and the audited address list ambiguous (Task 7 review). | Fixed: 85e4dab (bare addresses only, mailbox comparison; `notify.gave_up` event). |
| P7-08 | Alerts | Important | Over-cap notices were recorded but their summary was lost when its separate transaction failed: the notices were never e-mailed (Task 8 review). | Fixed: c3e8e9d (one transaction per kind, retried next scan); `TestFailedSummaryIsRetriedWithTheRightCount`. |
| P7-09 | Web (dashboard) | Important | Exclusive bucket counts linked to cumulative list filters (a count differed from the rows its link opened); no loading or partial-error state (Task 18 review). | Fixed: 55be7e7 (cumulative windows, controller ruling) [14]. |
| P7-10 | Reports | Important | The counts used another population and boundary than the list, were computed in Go from every item due within 60 days (R32), and a `needs_attention` deployment aged out after 7 days (Task 9 review). | Fixed: 5a102aa (one statement, equality test with `ListCertificates`) [14]. |
| P7-11 | SSO | Important (ruling) | A refused SSO user (no group any more) kept every API token Alice had issued. | Fixed: ef98801 (revoked with the sessions; demotion relies on the per-request role cap) [21]. |
| P7-12 | SSO | Minor | `SafeNext` kept dot segments and checked `/api` on the raw path only (Task 2 review). | Fixed: 613cb66 [35]. |
| P7-13 | SSO | Minor | SSO users could create recovery codes; the Admin cap was read outside the sign-in transaction; subject and issuer lengths unbounded (Task 11 review). | Fixed: 666063d. |
| P7-14 | SSO | Important | Changing a provider's issuer while it had users re-bound them to another identity provider (O-09) (Task 12 review I-1). | Fixed: 2b8b354 (refused while users exist, checked before discovery and under the provider row's lock); `TestIssuerChangeRefusedOnceAUserArrives`. One in-flight sign-in window parked (Known limitations). |
| P7-15 | Build | Important | `release-symcheck`'s guard against test code read `nm` symbols only and missed an import used only for a constant, type or inlined function (Task 13 review). | Fixed: 0f5636c (`go list -deps` with a positive control), ebb6876. |
| P7-16 | API | Important | The browser-session export limit was untested; HEAD on an audited export ran the export and wrote an audit row (Task 14 review). | Fixed: 4138d1e (`ALC-SYS-0009`); `TestExportLimitIsPerUserAndPerToken`, `TestHeadOnAuditedExportsIsRefused`. |
| P7-17 | API (OIDC) | Important | A callback with a fresh binding cookie per request escaped every rate limit and ran `Complete` with an audit row each time; providers were created switched on; a HEAD consumed the single-use state; `PUT /sso/settings` without the switch value silently demoted (Task 15 review). | Fixed: 63e2439. |
| P7-18 | Web (settings) | Important | **Send test e-mail** bypassed the step-up wrapper; switching **SSO users may be Admin** off had no confirmation although it demotes every SSO Administrator (Task 19 review). | Fixed: 1b4cc48. |
| P7-19 | Test code | Minor | The nginx guard's allow-list of `InsecureSkipVerify` places lacked `notify.pinnedTLS`, so the suite was red (Task 16). | Fixed: 3d5166f (the guard also requires the pin comparison there). |
| P7-20 | Web (text) | Minor | The confirmation **Switch off SSO users may be Admin?** said every SSO Administrator "becomes an Operator"; the server demotes them to **Auditor** (R42 [24]). Found while writing these documents. | Fixed: 969d82d ("becomes an Auditor" / "Denetçi olur"). |
| P7-21 | Test evidence | Important | The export equality compared 2 of 16 and 3 of 13 columns, the SSH key seed kept columns constant (a swap would pass); no ID/access-token canary and no Basic or AUTH PLAIN spellings; F-61 and the scheduled half of F-63 were not over the wire (Task 16 review, re-review). | Fixed (tests only): 41ed252, 6df6071, 313039a. |
| P7-22 | Alerts (performance) | Important | `GET /dashboard/expiring` had p95 650 ms against its 500 ms budget: the monitored-items CTE was materialized and scanned per certificate (Task 17). | Fixed: 394ea97 (`NOT MATERIALIZED`, proven equivalent by the review); p95 48 ms. |
| P7-23 | Test evidence | Important | No alerts test covered the two "monitored" exclusions (a missing location, a deleted target) (Task 17 review). | Fixed (tests only): 3748eb5. |
| P7-24 | SSH keys | Minor | A retention setting large enough to overflow a duration would have destroyed every retired key at once (Task 10 review). | Fixed: 5b64bc0 (clamped 1–3650, read once per run) [30]. |
| P7-25 | Web (WCAG) | Minor | Saved views menu: axe critical `aria-required-children` and serious contrast (D-1). | Fixed: 045c8e7. |
| P7-26 | Web (WCAG) | Minor | Four status texts and the sign-in "or" divider under 4.5:1 (D-2). | Fixed: 7b3fa58. |
| P7-27 | Web (TR) | Minor | The Turkish switch-off confirmation had the same name as the dialog's close button ("Kapat"), with opposite effects (D-3). | Fixed: 5606317. |
| P7-28 | Jobs (license lock) | Important (pre-existing) | After the clock was set back, the runner skipped the lock sweep while the last sweep lay in the future, so queued external-change work was not held in lock until the clock caught up (D-7; found because the Phase 4 L-29 journeys failed on a reused e2e container). | Fixed: 1fac017; `TestSweepDue`. |
| P7-29 | Web | Minor, **open** | D-4: after **Save identity provider** the focus falls to `<body>`; D-5: the password field's error sets no `aria-invalid`; D-6: the Users table scrolls the page sideways at 375 px (Phase 1 page). | Open, reported for their owners. |
| P7-30 | SSO (step-up) | Important | A silent sign-in at the IdP (an IdP session still open, no credential typed) opened the 5-minute step-up window, so "sign out, sign in again through SSO" skipped the SSO step-up for every SEC-009 action: providers, mappings, the Admin switch, API tokens, private-key downloads (final review I-1). | Fixed: bc1a234 (the window opens only for an `auth_time` at most 5 minutes old; amends C10 and R42 [22]). |
| P7-31 | SSO (credentials) | Important | An SSO user's API token (up to 365 days) outlived de-provisioning at the IdP: tokens were revoked only when the person signed in again and was refused (final review I-2). | Fixed: e0fa7b8 (SSO users cannot create API tokens, 409 `ALC-USR-0003`; the tokens page offers no create control) [21], [23]. |
| P7-32 | Mail and SSO (secrets) | Minor (security) | A stored SMTP password or client secret was kept when the host or port, or the issuer, changed: an Administrator or a hijacked stepped-up session could redirect it to a server they control (final review minor 11). | Fixed: 993d96a (a new destination needs the secret again, 422). |
| P7-33 | SSO | Minor | A new IdP transport per exchange or discovery kept an idle TLS connection and two goroutines (final review minor 1). | Fixed: bab83f0 (`DisableKeepAlives`). |
| P7-34 | Mail | Minor | `mime.QEncoding` never folds: a long non-ASCII CN gave a Subject line of 2–3 KB, which a strict MTA refuses (24 hours of retries and the banner) (final review minor 14). | Fixed: 24fc606 (capped at 200 characters, folded under 998 octets). |
| — | Final review, other minors | Minor | 24 minors (2–10, 12, 13, 15–27 of task-final-review.md). | Open, carried: listed by number in the rulings' "Carried to later phases"; minor 10 (the SSO start's shared limit) is a known limitation. |

## Known limitations

Scope and evidence:

- **Single sign-on was never run against a real identity provider**, e-mail never against a real mail server: the
  set-up notes for Entra ID, AD FS and Keycloak in `docs/admin-guide.md` are from their documentation, not from a test.
- The e2e identity provider is reached by the browser through Chromium's `--host-resolver-rules` only (no DNS, no
  `/etc/hosts`), and it signs with the real time while Alice's e2e clock can move: a journey does its SSO steps before
  any clock move.

SSO:

- **No Microsoft Graph lookup** for the Entra overage [20]: a person in more than 200 groups is refused
  (`ALC-SSO-0007`) unless the token carries only the application's groups (Phase 8 carry).
- **A group removed at the IdP keeps an open session** until it ends (up to 12 hours, 30 minutes idle) unless the
  person signs in or confirms again or an Administrator disables them [21]; a disabled provider ends no open session
  (parked M-4).
- A sign-in verified against a provider's old issuer may insert its user just after an issuer change commits (an
  Administrator opens the window, for one in-flight callback); `PUT /settings/general` may clear Alice's address while
  a provider is on, after which starts fail cleanly with `ALC-SSO-0004` [42].
- Providers that accept only `client_secret_post`, or whose endpoints carry a query, cannot be used [19].
- **Starting a single sign-on shares the sign-in limit of 10 a minute per address** (final review minor 10): behind
  one NAT address the 11th person starting SSO within a minute gets `ALC-SYS-0005`.
- **SSO users cannot create API tokens** (P7-31): scripts use a local account's token. An IdP that sends no
  `auth_time` always needs the IdP step-up before a protected action (P7-30).
- A successful test e-mail does not end **E-mails could not be sent** (only a real successful send does), and the
  outbox stalls silently when the mailer cannot be built (for example a password envelope sealed with another master
  key) (final review minors 12, 13).
- MFA of SSO users is the identity provider's; Alice cannot see whether it happened. An IdP that ignores
  `prompt=login` makes step-up fail [22].
- The Users API exposes no SSO subject (the web shows the provider's name); `auth.oidc.denied` rows are not coalesced
  (carry 12; bounded by the start's per-address limit of 10 a minute and the callback's limits).
- The pending nonce is stored in clear in `oidc_login_states` for at most 10 minutes (the state is hashed), as the
  plan allows.

Mail and alerts:

- **No plaintext SMTP**: a relay without TLS cannot be used [10].
- **A renewed self-signed mail server certificate must be trusted again**; until then e-mails fail with
  `smtp.untrusted` [10].
- **Uploaded certificates that are on no server are not alerted** (row 4), nor are disabled Key Vault keys and
  certificates [4].
- **A notice skipped by downtime is never sent** (only the most urgent reached threshold is) [5].
- **One bad recipient can raise the failing banner** while every other recipient gets their e-mails [8];
  `failed_24h` is approximate [7].
- **E-mails show UTC** (`2006-01-02 15:04 UTC`), not the person's time zone (row 10).
- A recipient list that produces no address leaves the notices recorded and only logs `alerts.no_recipients`; a
  corrupt `notify.recipients` row fails every caller that queues an e-mail in its transaction (the lockout, the
  license tick).
- Retries of failed items can push a kind over 20 e-mails across scans; one persistently failing over-cap item blocks
  its kind's summary every scan.

Memory and storage:

- **Go strings cannot be cleared** (P4-04, extended): the `oauth2.Config` client secret for one token exchange,
  `smtp.PlainAuth`'s password string for one send, and Go's HTTP and TLS buffers of the request that set a secret.
- **`setting_secrets` must be re-wrapped by a future master-key rotation** (with the other envelopes; see
  `docs/operator-guide.md`, "Master-key rotation"); a secret left under an old key fails its e-mail or sign-ins until
  re-entered.
- **The audit chain is still unkeyed and `jobs.audit_verify` is writable by `alice_app`** (carry 17, Phase 8):
  whoever holds the application role can append rows that verify and suppress the `audit.broken` e-mail; the
  dashboard's head hash is for offline recording (R42 [27]).

Reports and the web:

- **Views are private** (row 15): no shared views. Export headers are English (row 16).
- An export can stop at 50,000 rows without an error when rows are added between its count and its end; actors
  without an ID share one export slot.
- CSV cells that start with whitespace before a formula character are not prefixed (the `csvx` rule as written).
- No hostile-string test per new widget and settings screen (see the checklist); the Settings screens are not in the
  `screens.i18n` sweep.
- A failed deployment stays listed for 7 days after a later success (no supersede rule); a first verification that
  finds a broken chain stores no checkpoint (the dashboard then shows only the condition).
- D-4, D-5, D-6 and the carried minors of the final review are open.
- The R32 data set has no SSH keys, and `certificates?q=` is a linear scan (14 % of its budget at 5,000
  certificates).

## Owner verification

Spec §26.9 "Owner verifies", steps 1–5. You need:

- A development stack signed in as an Administrator with an authenticator app and an e-mail address on **Users**.
- A mail server you can switch off (for example a test relay), with its name, port, encryption and an account.
- A test identity provider (a Keycloak realm or an Entra ID test tenant) where you can create a group, put a test
  person in it and take the provider offline or block Alice's access to it.
- For step 2, a certificate that expires in 7 days deployed on a test server (or the e2e stack's seed).

Without your own mail server and identity provider, all five steps can be walked on the e2e stack (`make e2e-up`,
`POST /test/seed/dashboard`, the `fakesmtp` and `fakeidp` containers, see `docs/operator-guide.md`, "Development stack
reset"); write "e2e" in the notes. That proves the screens, not your mail server or identity provider.

1. **Mail.** **Settings → Email**: enter the mail server, choose **Save mail settings**, then **Send test e-mail**. If
   the certificate is not trusted, compare the fingerprint with the server's and choose **Trust this certificate**,
   then send the test again.
2. **Expiry.** Open **Dashboard**: the certificate is under **Expiring soon**. Wait for the next check (up to 15
   minutes) and look in your mailbox.
3. **Filter and export.** **Certificates**: **Expiry** → **Within 30 days**, then **Server** → one server. Choose
   **Export** and open the file in a spreadsheet and a text editor.
4. **Failing e-mail.** Switch the mail server off, wait for the next alert (or the next e-mail Alice sends) and three
   failed attempts, open **Dashboard**; switch it on again and wait.
5. **SSO.** **Settings → General**: Alice's address. **Settings → Single sign-on**: add the provider, register the
   redirect address at it, map a group to **Operator**, switch the provider on, sign in through it in a private window.
   Then try to map a group to **Administrator** (switch off, then on). Take the identity provider down and sign in as
   the local administrator with the authenticator code.

| # | Step (§26.9) | Expected | Result | Date | Notes |
|---|---|---|---|---|---|
| 1 | Enter the mail server in Settings and click "Send test e-mail" | The e-mail arrives (an untrusted certificate is shown with its fingerprint and can be trusted) | | | |
| 2 | A certificate that expires in 7 days | The dashboard lists it under "Expiring soon"; an e-mail with the website name and the date arrives | | | |
| 3 | Filter: expiring within 30 days, then one server; click "Export" | The file contains exactly the rows shown | | | |
| 4 | Turn the mail server off and wait for the next alert; turn it on | "E-mails could not be sent" on the dashboard; afterwards the e-mail arrives once | | | |
| 5 | Configure SSO with a test identity provider; map a group to "Operator"; sign in through SSO; try mapping a group to "Admin"; take the IdP down and sign in locally | Operator role; the Admin mapping is refused until "SSO users may be Admin" is on; the local administrator with the authenticator code signs in | | | |
| — | Turkish tone review of the new texts | Formal and natural | | | |

## Sign-off

Reviewer, date and commit are filled in when the review is completed.
