# Rulings: recovery of ACME renewals after an outage

Owner decision 2026-10-20, after an outside review: once a temporary DNS or CA outage cleared, automatic renewal waited
for a person (five failures of any kind stopped it), so a certificate could be forgotten and expire; with public TLS
lifetimes going to 100 and then 47 days this matters more. The change separates outages from causes that need a
person, recovers from outages by itself (bounded), lets an Administrator check again and resume in one step, reminds
the Administrators as the end nears, and shows how the last reminder was delivered. Spec: R45 in
`docs/superpowers/specs/alice-v1/00-decisions.md`, AC-5 and the ACME permissions paragraph in `04-security.md`, §8.4
in `02-architecture.md`; user text in `docs/admin-guide.md`, `docs/operator-guide.md` and `docs/troubleshooting.md`.

## The design as built

- `acme.FailureClass(err)` (`internal/acme/failure.go`) classifies an order's failure as `transient` or `permanent`
  from the `*acme.Error` the client already returns (RFC 8555 problem type, HTTP status, cause), and
  `inventory.ACMEOrderFailure` adds it to the closed code (`renew.ClassOfCode(code)` when the error does not say).
  The acme.issue/acme.renew handler and the sweep pass it to `FailACMEOrderClass`; `FailACMEOrder` (code only) keeps
  working with the code's class.
- Migration `00020` adds `acme_certificates.last_failure_class` ('' / transient / permanent) and
  `permanent_failures`, the alerts ledger kind `acme_renewal_expiry`, and an expression index on
  `notifications_outbox.params->>'acme_certificate_id'`.
- `renew` (pure policy): `ShouldStop(failures, permanent, expired)`, `RetryWait(failures, class, left)`,
  `RecoveryInterval(left)`, `ExpiryNoticeDays()` = 14, 7, 3, 1; `Decide` orders a stopped certificate with a transient
  last failure (`ReasonRecovery`).
- `POST /api/v1/acme/certificates/{id}/rearm` (the web's former **Renew now**, now **Check again and resume**)
  re-arms and orders at once; the certificate DTO gains `last_failure_class`, `permanent_failures`, `recovering` and,
  on the single GET, `last_notice`.

## Rulings made during execution

1. **The classification table.** Transient: `acme.ca_rate_limited` (Retry-After still honoured, capped at 24 h);
   `acme.provider_unreachable` (network errors, timeouts, CA 5xx, `serverInternal`, `badNonce`) except an address the
   network policy refuses (`netaddr.ErrNotAllowed`: a setting); `acme.not_issued_in_time` (order deadline, DNS
   propagation/readiness timeout of the hook, `orderNotReady`); a validation failure whose problem type is `dns`,
   `connection`, `serverInternal`, `rateLimited` or `badNonce`, or that carries a 408/429/5xx status or a network
   error/timeout in its chain (an HTTP-01 publisher whose SSH session timed out); a DNS hook that gave no answer
   (refused connection, timeout: `acme.ErrHookUnreachable`) or answered 408, 429 or 5xx; a `directory_invalid` with a
   408/429/5xx status; a bare timeout or network error outside an `*acme.Error`. Permanent: everything else, in
   particular `unauthorized`, `incorrectResponse`, `tls`, `caa`, `rejectedIdentifier`, `unsupportedIdentifier`,
   account problems (`accountDoesNotExist`, `externalAccountRequired`, `unauthorized` on the account, EAB),
   `userActionRequired`, `malformed` and other 4xx, key policy (`badCSR`, ...), TLS trust failures (of the CA or of the
   hook), a hook 4xx (wrong secret, 404), a name outside the allow-list, no usable challenge, no active account
   (`acme.account_state`), an unreadable secret, a chain that does not fit the order, and `internal.unexpected`. The
   code-only fallback (`ClassOfCode`) is transient for `acme.ca_rate_limited`, `acme.provider_unreachable`,
   `acme.not_issued_in_time`, `acme.order_abandoned` and `acme.rollover_pending`, permanent otherwise; a provider code
   of an HTTP-01 publisher counts as transient only when a network error or timeout is in its chain. Unknown means
   permanent: a wrong "permanent" costs a person's look, a wrong "transient" costs requests to the CA.
2. **The stop rule.** Five PERMANENT failures in a series (not necessarily in a row: `permanent_failures` counts them)
   stop automatic renewal, as five failures did before. Transient failures never stop it while the current
   certificate is valid. Once the certificate has expired, five failures of any class stop it (`ShouldStop`), so an
   expired certificate is not ordered indefinitely. The "renewal failed" e-mail still goes once at the third failure
   of any class. A success, Check again and resume and switching automatic renewal on again reset both counts and the
   class. Rejected alternatives: "stop after N consecutive permanent failures" (an alternating series would never stop
   before expiry) and "a much larger count of transient failures" (a count is a time bound in disguise; the expiry is
   the bound that matters).
3. **The recovery cadence.** After a transient failure the wait is `min(Backoff(failures), RecoveryInterval(left))`:
   the usual 1, 2, 4, 8, 16 h, then 24 h; never longer than 12 h within 7 days of the end, 6 h within 3 days, 2 h in the
   last day (`left` is measured at the failure). The CA's Retry-After wins when longer; the 15-minute spacing, the
   wave of 5 orders per run and the provider hold while a sibling is rate-limited stay. So one certificate in an
   outage costs at most one order a day until its last week and at most 12 orders in its last day, far below public
   CA limits (Let's Encrypt allows 5 failed validations per account, hostname and hour).
4. **Stopped certificates with a transient last failure recover by themselves.** A certificate can be stopped while
   its last failure is transient: a series stopped before this change (migration `00020` gives a series the class of
   its last code, all of its failures counting as that class, so five outages recover and five refusals stay
   stopped), or a person's order of a stopped certificate that failed in an outage. The planner orders such a
   certificate again at the same cadence until it expires (`ReasonRecovery`, state stays `stopped` until an order
   succeeds); no second stop row or e-mail is written. A recovery order that fails permanently ends the recovery.
   A permanent stop waits for a person.
5. **Check again and resume extends Renew now instead of adding a route.** In the web and the guides **Renew now** was
   `POST .../rearm` (Administrator, fresh step-up, never a token, `acme.manage`, licence class change, 10 a minute);
   it cleared the stop but only renewed "at the next planned time". It now also starts an order of the person at once
   (trigger manual, `acme.issue`, audit `acme.order.started` after `acme.auto_renew.rearmed`), in the same
   transaction, and is shown on a failing certificate as well as a stopped one. The permission, step-up, licence class
   and rate limit are unchanged; the button is renamed **Check again and resume** (TR "Yeniden dene ve sürdür").
   `POST .../order` (Operators: **Order now**) is unchanged. (`openapi.yaml` called `/order` "Renew now" too; its
   summary is left as it was, the web's labels decide.) No order is started for a certificate never issued (the first
   order stays **Get certificate now**). An order refused for the account (`ALC-ACM-0023`) or an unsettled key change
   (`ALC-ACM-0024`) refuses the whole act; a previous order's job still finishing leaves the re-arm without a new
   order (savepoint) and the planner orders at its next run. Switching automatic renewal on through PATCH still
   re-arms without ordering.
6. **Expiry reminders reuse the alerts ledger.** While `failures > 0` and automatic renewal is on, the renewal planner
   e-mails the Administrators (and extra recipients, `NotifyAdmins`) at 14, 7, 3 and 1 days before the current
   certificate's `not_after`, with the days left, the expiry time and the last reason; three templates by class and
   state: `acme.renewal_expiring_transient` (Alice keeps trying), `..._permanent` (Alice stops after 5 such failures)
   and `..._stopped` (a person must act). Each threshold is a row in `alerts` (kind `acme_renewal_expiry`, unique per
   certificate, expiry instant and threshold) inserted in the transaction that queues the e-mail, and as in
   `alerts/expiry.Due` only the most urgent reached threshold is ever due (no late 7-day reminder after a downtime
   past it). At most 20 reminders per run. They go with the planner, so they follow its licence gate (continuity):
   after the continuity window of a lock the general certificate expiry notices (R42) still go. No audit row: the
   ledger row is the record (the general expiry notices write `alert.sent`; these are reminders of a renewal that is
   already audited at each failure and stop).
7. **Delivery visibility is contained, so it is built.** The outbox already records each copy's outcome
   (`status`, `last_error_code`, `sent_at`). Every ACME renewal e-mail now carries the non-rendered param
   `acme_certificate_id`; `ACMENoticeDelivery` reads the newest batch for the certificate (one copy per recipient)
   through the new partial expression index (the pattern of `notifications_outbox_rotation_preview`), and the
   certificate page shows "Sent to N of M", "Still being tried", "Not delivered (smtp.*)" or "Not sent: no mail
   server is set". No new table or job. E-mails queued before the change carry no id and are not shown.
8. **What a reader sees.** `last_failure_class` is shown as "Temporary (an outage)" / "Needs a person"; the failing
   notice says Alice keeps trying (transient) or how many more such failures stop it (permanent, `5 -
   permanent_failures`); a stopped certificate that recovers says so and shows its next attempt (`recovering`
   is computed by the API at its clock: stopped, automatic renewal on, transient, not expired).

## Not done / open

- The e-mail reminders are not sent after the continuity window of a lock (the planner is gated); the general expiry
  notices cover that time.
- The classification of HTTP-01 publisher (SSH) failures depends on the provider error keeping its network cause in
  its chain; a provider code that hides it counts as permanent.
- No real CA outage was exercised; the fake CA and stubbed hooks cover the classes.
