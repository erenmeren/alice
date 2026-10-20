# Rulings: never retry before the CA said we may

Owner decision 2026-10-20 (approved while the owner was away; the defaults below were chosen during execution and are
recorded here for review). The bug: the ACME client capped a CA's `Retry-After` at 24 hours (`acme.MaxRetryAfter`), and
the renewal policy used one `renew.MaxBackoff` (24 h) for Alice's own backoff, the CA's wait and the ARI recheck; the
planner also "repaired" a `next_attempt_at` further than 24 h away to now + 24 h (meant for a clock that moved back).
So a CA that answered a rate limit with `Retry-After: 48h` saw a new order after 24 hours, which with public CAs can
only lengthen the limit. Spec: R47 in `docs/superpowers/specs/alice-v1/00-decisions.md`, AC-5 in `04-security.md`,
§8.4 in `02-architecture.md`; user text in `docs/admin-guide.md`, `docs/operator-guide.md` and
`docs/troubleshooting.md`.

## The design as built

- Three times are kept apart: Alice's own backoff end (`acme_certificates.next_attempt_at`, capped at 24 h and
  repaired after a clock step, as before), the CA's earliest retry time (`acme_certificates.ca_not_before`, migration
  `00022`) and the operational deadline (the current certificate's `not_after`). The next attempt is the latest of the
  backoff, the CA's time, the 15-minute spacing and the provider hold (`renew.Decide`, reason `ca_wait`).
- `acme.MaxRetryAfter` and `renew.MaxCAWait` are seven days (a test keeps them equal). A failed order with a
  Retry-After records `ca_not_before = now + min(Retry-After, 7 d)`, never earlier than it was (`GREATEST`); a test
  run's Retry-After is recorded the same way (a test run counts no failure and leaves `next_attempt_at` alone).
- The planner's candidate query skips a certificate whose `ca_not_before` is in the future; `startOrderTx` refuses
  every order before it (the planner's, a person's issue or test order, and the order of **Check again and resume**).
- `renew.NextARICheck` honours the CA's ARI Retry-After up to the same seven days (it was capped at 24 h too).
- `renew.CAWaitCritical`: a CA time after the middle of the renewal window (`due + (not_after - due) / 2`, the point
  from which the provider hold stops applying) e-mails the Administrators at once (`acme.renewal_ca_wait`).
- API: the ACME certificate gains `ca_not_before` (null unless a wait is running) and `ca_wait_critical`;
  `next_attempt_at` is now the later of the backoff and the CA's time. The web page shows "The certificate authority
  asked Alice to wait until …" (red with the certificate's end when critical) and keeps **Order now** and **Test run**
  disabled while it runs.

## Rulings made during execution

1. **The sanity bound is seven days.** Long enough for every documented public CA limit window we know of (Let's
   Encrypt's weekly certificate-per-domain window is the longest), short enough that a hostile or buggy CA cannot park
   renewal for months. A longer Retry-After is bounded at seven days when it is recorded; the local rule and the
   critical warning still apply. The ARI recheck uses the same bound (a long ARI Retry-After costs only the window
   lookups: the local rule renews without a window).
2. **The CA's time is never shortened by the local cap or by the clock-skew repair.** The repair of `next_attempt_at`
   (beyond 24 h means the clock moved back) touches only the local part. The CA's time has its own bound: a stored
   `ca_not_before` more than seven days from now can only come from a clock that was ahead when it was recorded; it is
   bounded to now + seven days (`RepairCANotBefore`). That is never earlier than what the CA asked for: the value was
   recorded as `recorded_now + d` with `d <= 7 d`, the CA's real time is `real_answer_time + d`, and
   `real_answer_time <= now`, so `real_answer_time + d <= now + 7 d`.
3. **A person does not override the CA either.** A person's **Order now**, **Get the certificate** and **Test run**
   are refused before the CA's time without contacting the CA, with the CA's own code `ALC-ACM-0005`
   (`acme.ca_rate_limited`, HTTP 503, retryable) and `Retry-After` = the time left; no new error code was needed (its
   text already says "ordering sooner only makes the wait longer"). **Check again and resume** re-arms and starts no
   order (as when an earlier order's job is still finishing); the planner orders once the time has come. Rejected:
   letting an Administrator override (the CA refuses the order anyway, and every refused order can lengthen a public
   CA's limit).
4. **Only a successful order clears the CA's time.** A re-arm, switching automatic renewal on or a changed setting
   keeps it (the CA said it about the account or the names, not about Alice's state). A failure without a
   Retry-After keeps the earlier time.
5. **When the wait is critical, Alice warns instead of ordering sooner.** "Critical" is the CA's time after the middle
   of the renewal window (for a 90-day certificate renewed 30 days before its end: a wait that ends within the last 15
   days; for a 6-day certificate: any wait past its last day but one). Then the Administrators get
   `acme.renewal_ca_wait` (TR/EN) at once, with the CA's time, the end of the certificate and the advice to use
   another authority if it cannot wait; the alerts ledger (kind `acme_renewal_ca_wait`, threshold = whole days left
   at the end of the wait) makes each such wait go once, and a new wait with fewer days left goes again. The R45
   reminders (14, 7, 3, 1 days) are unchanged and keep going while the renewal fails.
6. **The provider hold stays at 24 hours of a series** (`acmeRateLimitHold`). It holds the provider's OTHER
   certificates while one is rate-limited and was bounded at 24 h on purpose (fix round 1, I1: a certificate the CA
   limits for its own names must not starve a short-lived neighbour). It now looks at the later of `next_attempt_at`
   and `ca_not_before`; each certificate the CA limits gets its own `ca_not_before` from its own answer.
7. **Polling within an order is left to the library.** `golang.org/x/crypto/acme`'s `WaitOrder` and
   `WaitAuthorization` sleep for a `Retry-After` on a pending order or authorization, uncapped, within the order's
   deadline (10 minutes), so nothing polls earlier than the CA asked. A longer one ends the order as
   `acme.not_issued_in_time` (a transient failure, backed off as before). That Retry-After is a polling hint about
   one order, not a limit on new orders, so it does not become `ca_not_before`; no change was needed.
8. **Migration of existing rows.** A certificate whose last error was a rate limit and whose `next_attempt_at` is in
   the future takes it as `ca_not_before` (it held the CA's wait, capped at 24 h then). The Down puts a running CA wait
   back into `next_attempt_at`, capped at 24 h as the earlier code did.
9. **Voice of the page text.** The UI says "The certificate authority asked Alice to wait until …" (Alice's texts
   never say "we" or "us").

## Deferred

- The planner does not tell a CA's limit of the whole account from one of a set of names; the provider hold stays a
  heuristic bounded at 24 h.
- No setting for the seven-day bound; change `acme.MaxRetryAfter` and `renew.MaxCAWait` together if the owner wants
  another value.
