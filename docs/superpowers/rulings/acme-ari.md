# Rulings: ACME Renewal Information completed (R50)

Owner decision 2026-10-20 (approved while the owner was away; the defaults below were chosen during execution and are
recorded here for review). Before this work Alice fetched the CA's renewal information (RFC 9773) and used the window's
start only when it was earlier than the local rule; it did not choose a random time inside the window, kept nothing
chosen, and never sent `replaces` (L-ACME-1: `golang.org/x/crypto/acme` v0.57.0 cannot send the field). Spec: R50 in
`docs/superpowers/specs/alice-v1/00-decisions.md`, AC-4 in `04-security.md`, the ACME renewal paragraph and the
`acme_certificates` / `acme_orders` columns in `02-architecture.md`; user text in `docs/admin-guide.md` and
`docs/troubleshooting.md` (`ALC-ACM-0041`).

## The design as built

- **A random time inside the window, chosen once.** `renew.ChooseARIRenewAt` picks a uniformly random whole second in
  the part of the CA's suggested window that is not later than the local rule (`not_after − min(renew_before_days,
  lifetime/3)`), RFC 9773 section 4.2. The renewal planner stores it with the current certificate
  (`acme_certificates.ari_renew_at`, migration `00024`) in the certificate's own transaction, so a restart or the next
  run never moves it. It is chosen again only when it no longer lies inside the window (the CA moved it or shrank it
  past the time); a window that grows keeps it. A window already in the past gives a time in the past: due now. A new
  current certificate clears it (with the cached window), and so does a CA that stops advertising `renewalInfo`.
- **The local rule stays the bound.** A window that starts at or after the local rule is not used (the certificate
  renews at the local rule, as before); one that ends at or before the certificate's `not_before` is not about it.
  Without a window (never answered, no `renewalInfo`) the local rule decides exactly as before.
- **R47 is unchanged.** The CA's `Retry-After` of a renewal information answer (bounded at seven days) still sets
  `ari_next_check_at`; `ca_not_before` still gates every order.
- **The planner's candidate query** uses the stored time while it lies inside the cached window, and the window's start
  before a time is chosen (so the certificate is planned once and the time stored); its priority is the earlier of that
  and the local rule.
- **`replaces` in newOrder.** An issue order of an ACME certificate that has a current certificate sharing at least one
  name with the order sends the current certificate's RFC 9773 identifier (base64url authority key identifier `.`
  base64url DER serial, `acme.CertID`), when the CA's directory advertises `renewalInfo` and the predecessor was
  ordered with this account. The one newOrder request is signed by Alice (`internal/acme/jws.go`: ES256/ES384/ES512,
  RS256; a nonce from `newNonce`; `badNonce` retried three times as the library does); everything after it goes
  through the library as before. The order records the identifier and what became of it (`acme_orders.replaces`,
  `replaces_outcome`: `sent`, `adopted`, `no_ari`, `other_account`, `already_replaced`, `refused`) and the CA account
  it ran under (`acme_orders.account_url`, written with the order URL).
- **`alreadyReplaced`** (409): Alice first looks at its own earlier orders of the certificate that were created
  replacing the same certificate (outcome `sent` or `adopted`, with an order URL, started within seven days, newest
  first, at most three); the first one the CA still holds as pending or ready for exactly the same names is taken over
  (`adopted`: its URL becomes this order's, its challenges are answered again, it is finalized with this order's new
  key). Without one, the order is made once more without the field (`already_replaced`).
- **A CA that refuses the field itself** (`malformed`, `unauthorized`, or a 409 without a type) gets the order once more
  without it (`refused`). Any other refusal (a rate limit, a server error, a refused name) is the order's failure,
  classified as before, and is not retried (R47: no second request into a rate limit).
- **Error code.** `alreadyReplaced` reaching the caller (a CA that says it to an order without the field) is
  `acme.already_replaced`, `ALC-ACM-0041`, HTTP 409, retryable, class **transient** (R45): the order that replaces the
  certificate at the CA ends there by itself. TR/EN texts in `locales/common`, a section in `docs/troubleshooting.md`.
- **API and page.** The ACME certificate gains `renew_at` (when Alice renews it by itself) and `renew_at_source`
  (`ca_window` or `local`); an order gains `replaces` and `replaces_outcome`. The certificate page shows the time with
  "(a time Alice chose in the window the authority suggests)" and a note on why and how long it is kept (TR/EN).
- **fakeacme** checks `replaces` as RFC 9773 section 5 asks (a certificate it issued, to the same account, sharing a
  name), records it (`Replacements`, `GET /replacements`), answers `alreadyReplaced` to a second order replacing the same
  certificate while the first is not invalid, and takes a window per certificate (`SetARIWindowFor`,
  `POST /ari?serial=…`, `alice-fakeacme ctl ari certificate SERIAL START END`).

## Rulings made during execution

1. **The window is cut at the local rule, and the time is random inside the part that is left.** The security property
   of AC-4 (ARI only pulls a renewal earlier; a hostile window cannot make a certificate expire) is kept. Rejected:
   the whole window (a window ending near expiry would push renewal past the Administrator's setting); `min(local,
   random in the whole window)` (when the window spans the local time, half of the certificates would land exactly on
   the local time, which defeats the spreading). A window that starts at or after the local rule leaves nothing: the
   local rule decides. The ARI-earlier-than-local discontinuity this creates is the same as before this work.
2. **Only the chosen time is stored, not the window it came from.** The current window is cached already
   (`ari_window_start`, `ari_window_end`); "re-choose only when the window changes such that the stored time is
   outside it" is exactly "the stored time is not inside the cached window", so a second copy of the window would add
   nothing. A changed `renew_before_days` that moves the local rule before the stored time re-chooses it too.
3. **Whole seconds from `math/rand/v2`.** The choice spreads load; it is not a secret. Tests pass a deterministic source
   (`renew.Input.Rand`).
4. **A failed lookup keeps the last answer.** "If ARI fails, keep the local schedule exactly" is read as: a certificate
   for which the CA never answered (or that has no `renewalInfo`) renews by the local rule exactly; a lookup that fails
   after an answer keeps the cached window and the time chosen in it (the CA's last word, as before this work), and
   never counts as a failure. `ErrNoARI` clears both.
5. **Which orders send `replaces`.** Every issue order of an ACME certificate with a current certificate that shares a
   name: the planner's renewals, a person's **Order now**, **Check again and resume**, the replacement order of a
   key-compromise incident (R46), the R45 recovery. Never a first order (no predecessor) and never a **Test run**: a
   test run leaves a pending, never-finalized order at the CA, which would mark the certificate as replaced and make
   the real renewal meet `alreadyReplaced`.
6. **Same account is checked by its URL.** The predecessor's account is the `account_url` of the order that issued it
   (recorded from migration `00024` on); when it differs from the account the order runs with (a new account after a
   directory change), the field is not sent (`other_account`). A certificate issued before `00024` has no recorded
   account: the field is sent and a refusal is handled by ruling 8. A key rollover keeps the account URL, so it never
   counts as another account.
7. **What "find the order of a lost response" can do.** Alice can take over only an order whose URL it recorded (an
   interrupted run whose order the sweep abandoned, typically still pending at the CA). An order whose newOrder answer
   was lost entirely has no URL in Alice; RFC 8555's account `orders` list is not implemented by Let's Encrypt (Boulder)
   and is not used. A valid earlier order cannot be taken over (its certificate's private key was deleted with the
   failed order): skipped. At most three earlier orders, started within seven days (Let's Encrypt's order lifetime).
8. **The fallback without the field is one request, only for refusals of the field.** `malformed`, `unauthorized` or an
   untyped 409 after a request with the field: one more newOrder without it, recorded `refused`. A refusal that
   repeats without the field is the order's failure as usual (for example `unauthorized` of a deactivated account:
   `acme.account_rejected`).
9. **The outcome is recorded as soon as it is known**, also when the order made again without the field fails, so the
   order's page tells why the field was not used.
10. **`acme.already_replaced` is transient** (409, retryable): it can only clear by itself (the other order expires at
    the CA within days); five permanent failures must not stop automatic renewal for it.
11. **Migration number `00024`.** `00023` is reserved for a parallel branch. The scoped-access spec
    (`docs/superpowers/specs/2026-10-21-scoped-rbac-and-service-ownership-design.md`, R49) also names `00024` for its
    Phase 1: one of the two is renumbered at merge (the SQL here has no dependency on the number).
12. **The page shows the server's time.** `renew_at` is computed by the server (`renew.RenewalTime`, the same rule as
    the planner, without choosing); the web keeps its own computation only for an older server without the field. A
    revoked or compromised current certificate is still due at once (R46): the page shows the revocation separately.

## Deferred

- Not run against a real CA: Let's Encrypt staging's `renewalInfo`, its `replaces` checks and `alreadyReplaced`, and
  whether its replacement orders are exempt from its rate limits (owner verification).
- The web lists of orders do not show `replaces_outcome` (it is in the API).
- No setting for the choice (always random in the accepted part of the window).
