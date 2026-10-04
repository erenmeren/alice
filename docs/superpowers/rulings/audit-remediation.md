# Audit remediation — controller rulings

Decisions taken on the owner's behalf while fixing the open findings of the independent audit of 2026-10-04 (docs/security/reviews/independent-audit-2026-10-04.md) on branch `audit-remediation`, plan docs/superpowers/plans/2026-10-04-audit-remediation.md (owner instruction 2026-09-30: proceed without waiting). Each line: decision — why — cost if wrong. The decisions as they apply to the product are R39 in docs/superpowers/specs/alice-v1/00-decisions.md; accepted residuals are in docs/security/reviews/audit-remediation.md.

## Before the tasks

- remediation of the audit's open findings runs before Phase 5 — why: AUD-01/02/03 are security defects in shipped phases — cost: Phase 5 starts later; told to the owner twice, not confirmed.
- the plan-writer's 20 decisions are accepted as written (AUD-01 activity marker header + state-changing requests; AUD-02 3 h fail-closed gate, ALC-LIC-0009; AUD-03 wider account-name rule for names read from servers, protocol 6 / helper 1.5.0; AUD-06 coalesced denial rows; AUD-12 admin reset + sign-out-everywhere revoke API tokens; AUD-18 a missing seal is always tampering, upgrade-sealing path removed; …) — cost if wrong: each is recorded in R39 and reversible.
- discarding a job is allowed in every license state — why: it only reduces what Alice will do — cost: none known.
- loopback targets stay allowed in v1 (spec R37(24)); a name rebinding to 127.0.0.1 is still connected to — why: no existing switch, tests and tarball installs rely on it, exposure is an SSH banner/KEX or a TLS ClientHello to Alice's own host by an Administrator-added name — cost: residual risk recorded in the remediation review (Task 17).
- one audit count key `revoked_tokens_count` for all bulk token revocations (the key installed logs already have); per-token `token.revoked` rows also on disable — cost: deviates from the plan's new key name.
- certificates whose NotBefore/NotAfter are outside 0001–9999 UTC are refused at ingestion (upload refused; discovery treats the block as unreadable) — why: fail at the door, one vocabulary — cost: such exotic certificates cannot be managed. Fix round 2 dispatched to the Task 10 implementer.
- (amends S2) the recently-valid set's lifetime = session idle timeout (30 min, sliding), cap ~16k — why: membership only skips the block, and a shorter life strands hidden tabs behind a neighbour's flood — cost: ~1–2 MiB.

## Rulings on the plan's design findings (pre-flight scan)


- S1 — `ErrUnverified` (license gate without a fresh evaluation) must NOT be treated as locked by
  the job runner's lock sweep: queued read-only jobs are not cancelled and queued changes are not
  moved to `blocked_license`; they simply are not started until an evaluation succeeds. Why: the
  plan promises changes resume by themselves. Cost: a second "not started" reason in the runner.
- S2 — The per-address failed-credential block must not lock out people who hold valid sessions
  behind a shared address. Rule: a request whose credential was validated recently (bounded
  in-memory set keyed by a hash of the credential, entries a few minutes old at most) passes the
  block; the server clears a stale session cookie on 401 so a browser stops re-sending it. If that
  cannot be done in a contained way, the fallback is: only FAILED credential lookups count, valid
  requests are never refused by this bucket (lookups still happen), and the NAT caveat is
  documented. The implementer of Task 9 chooses and justifies. Cost: the limit protects the
  database a little less under a flood from one address that also holds a valid session.
- S3 — The coalescing key of denial audit rows includes the route (method + route template) in
  addition to subject, permission and reason, so the log still shows which routes were probed.
  Suppressed counts are flushed on shutdown best effort; losing them on a crash is accepted and
  documented. The hash chain stays append-only (a count is recorded by a later appended row, never
  by updating one).
- S4 — `ssh.address_not_allowed` is wired into the connection reasons and the target status
  mapping, and the Nginx TLS probe reports the refusal distinctly, not as plain unreachable.
- S5 — Alice requires helper protocol 6 after this change (no dual-protocol support): accepted
  because the product is pre-release. The documentation states the order: update the helpers
  first (the new helper works with the current Alice), then Alice; and what an operator sees
  otherwise (`ssh.helper_outdated`, deployments in recovery wait).
- S6 — An account or file-owner NAME leaves the server only if it passes the new account-name
  rule; otherwise the helper reports the uid only.
- S7 — no change.
- S8 — The helper's whole answer stays within Alice's output cap: the inline-content budget and
  the metadata are bounded together; on overflow the listing is truncated with a flag (the list
  is then incomplete, never a failed discovery and never silently complete).
- S9 — A license upload refused at the edge for NUL / invalid text still writes the
  `license.upload.invalid` audit row.

## Rulings made while the tasks ran

- The plan-writer's twenty decisions were accepted as written and are recorded, as built, in R39.
- Tasks 1–3 (helper protocol 6) were given to one implementer as one unit — why: the plan's claim that the tree stays green after Task 1 alone was false.
- Loopback targets stay allowed in v1 (spec R37(24)); a name that later resolves to 127.0.0.1 is still connected to — why: no existing switch, tests and tarball installs rely on it — cost: a residual recorded in the remediation review.
- Discarding a job is allowed in every license state — why: it only reduces what Alice will do.
- A lock that the license gate only estimates from its own clock pauses work and starts an evaluation; it never cancels or holds jobs — why: such a lock can be wrong (a pending license becoming valid).
- One audit count key for every bulk token revocation, `revoked_tokens_count` (the key installed logs already carry), and one `token.revoked` row per token, also when a user is disabled — cost: differs from the plan's key name.
- The set of recently valid credentials that pass the failed-credential block lives as long as the session idle timeout (30 minutes), not "a few minutes" — why: a shorter life strands a hidden tab behind a neighbour's flood; membership never authenticates.
- A failed credential lookup never gets its token back — why: a client that aborts requests would otherwise get unlimited lookups.
- Certificates dated outside years 1–9999 (UTC) are refused where they enter Alice — why: such a certificate could not be encoded in an API answer and cut the certificate list off — cost: such certificates cannot be managed.
- A state file that cannot be read stops the first start with an error instead of counting as evidence of a removed installation — why: a wrong volume permission would otherwise end the evaluation on day one.
- All API tokens of one person are one subject for coalesced refusal rows, and the token list refusal goes through the same coalescing — why: tokens are unlimited per person.
- Agents commit by explicit path on the shared index after two commits swept up another agent's staged changes (nothing was lost).
- The real-Nginx and OpenSSH matrices, coverage and browser runs were kept apart where possible; the final `make ci` ran with no other Docker user — why: Chromium aborts requests whenever a host interface changes.

## Found by reviews during the remediation and fixed before the merge

Each task was reviewed by another agent; the defects they found are listed with their commits in docs/security/reviews/audit-remediation.md. The ones that mattered most: a NUL byte in `/etc/passwd` could hide an account from the inventory while the list was called complete; the last-root-key guard did not know uid-0 accounts other than `root` in a fresh session; several `nsswitch.conf` forms and systemd userdb records were read as "local accounts only"; a lock estimated by the license gate cancelled and held jobs; a failed hourly license check displaced the pending retry; an API token created while its owner's sessions were being revoked survived; a cancelled request refunded its failed-credential token; clearing a stale cookie deleted the new cookie after step-up; a certificate dated in year 10000 cut the certificate list off; an unreadable state volume sealed a new installation with an ended evaluation; asking for another user's token list wrote an unbounded, uncoalesced audit row per request; a ten-minute export starved the shutdown flush of refusal counts.

## Parked / carried forward

- Owner: a git remote, the first run of the GitHub workflow (never run; `actionlint` once more there), branch protection; the production license key; the owner walkthroughs for Phases 1–4 and this branch; Turkish tone review; a full `make ci` on a clean machine.
- Product: an e2e hook to reach the route error page, the "license could not be checked" banner and the locale fallback (covered by unit tests only); a deployment id on deploy jobs; inventory's own refusal rows are not coalesced; lockfile secret scanning; `osv-scanner` (Phase 8); real systemd test (Phase 8); adding and removing a key still scans all accounts more than once; recovery codes lost when the completing request's answer is lost; the Phase 4 carries in docs/superpowers/rulings/phase-4.md.
