# Phase 6 — controller rulings

Decisions taken on the owner's behalf during autonomous execution of
docs/superpowers/plans/2026-10-05-phase-6-ssh-key-rotation.md on branch `phase-6` (base `master` 39838e7, plan
2e34517; owner instruction: run the phases back to back without waiting). Each line: decision — why — cost if wrong —
how to reverse it, where that is a file to change. Within a topic the order is the order in which they were made
(the times are the controller's ledger of 2026-10-05); where a later ruling replaced an earlier one, both are named.
The decisions as they apply to the product are R41 in docs/superpowers/specs/alice-v1/00-decisions.md (item numbers
in brackets); the evidence, the findings and the accepted limitations are in docs/security/reviews/phase-6.md.

Nothing here was checked on a customer's server: real OpenSSH ran only in the three containers of `make test-ssh`.

## Before the tasks

- 14:30 — the plan's 33 "spec conflicts resolved" are accepted as proposed R41, pending the pre-flight reviews; the
  plan changes no helper code and no helper protocol (protocol 6, helper 1.5.0) — why: the owner said not to wait —
  cost: the owner revises R41 later — reverse: each is an item of R41 [1–33] with its own cost.
- 14:30 — the plan (about 6,700 lines, 19 tasks) was not compiled by its author → a pre-flight consistency scan and a
  pre-flight security design review before Task 1, as in Phases 2 to 5. The code as built wins over the plan text.

## Pre-flight rulings on the design findings (S1–S13), 14:42

All thirteen were adopted as the review proposed them and made binding on every dispatch (preflight-rulings.md) —
why: each closes a concrete lock-out, no-record or no-notice path at design time, cheaper than after build.

- S1 — a scheduled run starts only after one *delivered* `rotation.preview` of that run; `skipped_no_smtp` is not
  "sent" (row 15 rewritten) [15] — cost if wrong: no scheduled rotation without working SMTP (Run now still works).
  The "cancelled after 24 hours" of the first text was replaced at 16:45 (M1, below).
- S2 — any edit of what an enabled policy does switches it off; switching on needs an Administrator with step-up (row
  24 amended) [35] — cost: one more step after an edit.
- S3 — an undo after an uncertain add waits until the add's send + helper budget + 30 s; the fake gets
  `FaultLateWrite` [56] — cost: a slower undo after an uncertain add.
- S4 — an add confirmed only by the login records the place and `sshkey.added` [56].
- S5 — a retired private key is destroyed only when the key has no live place; a key found live again is un-retired
  (`sshkey.reactivated`) (row 23 amended) [23].
- S6 — `verifying_new` pauses in lock and its 14-day timer stops; the first sweep after the renewal sends the notice
  before Continue is possible (rows 21, 26 amended) [21], [26].
- S7 — deploy refuses any file among the connection account's key files, not only that user; options are rebuilt from
  `from=` and `restrict` only [8].
- S8 — the planner skips places flagged `duplicate` or whose options hold U+FFFD [36].
- S9 — `CreatePolicy` refuses the new key of a live run [55].
- S10 — files shared by several users are skipped in Phase 6 (row 29 rewritten: skipped as a whole, never changed); the
  fake enforces the real provider's owner rule; one real-provider case [29] — cost if wrong: shared key files are never
  rotated in this phase.
- S11 — `kept_count` on the run, a `rotation.completed_partial` email, kept and skipped places on the run page [49].
- S12 — an undo lists the file first; where the old key is already gone it keeps the new key and ends `undo_failed`
  with `rotation.old_key_gone` (row 10 amended) [10].
- S13 — the property test adds Administrator actions, clock steps and lease loss at every call index, and the late
  write.
- Row 31 — **Finish now** emails the new removal time [31]. Task 15 adds the new e2e handler's symbol to
  `E2E_SYMBOLS`.
- Accepted as the plan had them: row 11 (no "confirm it works"), L-86 with §13.6 (pause when a verification passes,
  undo when one fails; the undo covers every place of the run), row 5 (download allowed in lock) — cost: as R41
  [5], [11].

## Consistency scan rulings (B1, F1–F13), 14:51

Every blocking and fix-round row of the scan was adopted with its proposed resolution; cosmetic rows were followed by
the task they name — why: all are name, shape or order corrections against the real code — cost if wrong: a fix round
in the task concerned.

- B1 — `fake.Config.Keys` already exists; the new field is `Config.World`.
- F1 — Task 8 creates `rotations.go` with the read Task 8 needs; Task 9 adds the rest. F2 — the state table gains
  `adding` and `RecordVerify{Reason}` → `verify_failed`. F3 — a session-open failure in the removal phase is
  `RecordReverify{Reason}` → `remove_failed`. F4 — the run DTO uses `errorRef{code, reason, params}`. F5 — `jobs.View`
  carries `ssh_key_id` and `rotation_id`. F6 — the audit-action labels move to Task 16. F7 — Task 16 adds the
  job-type labels; Task 10 registers literal names with a test. F8 — the deploy dialog tests use an existing code until
  Task 13's catalogue. F9 — the property test's settle jumps to the decision deadline, then by the renewal time. F10 —
  `FaultHang` subtests run under a 2 s timeout; F-39's outcome as built goes to R41 [46]. F11 — Task 14 edits no
  service or handler code and reports defects. F12 — `decode(repeat('00', 12), 'hex')`. F13 — the reason-registration
  test scans `sshkeys` and `sshkeyjobs` and knows the `rotation` area.

## Key material and planner (Tasks 1–2)

- 15:06 — m6: a root (or UID-0) place under `PermitRootLogin forced-commands-only` whose line has no `command=` is
  skipped by the planner (`root_forced_commands_only`) [36] — why: its test login can never pass, so every run would
  be undone — cost if wrong: such root keys are never rotated — reverse: `skipReason` in `internal/sshkeys/plan/plan.go`.
- 15:06 — contract C4's skip reasons gain `duplicate_lines`, `options_unreadable` (S8), `shared_file_skipped` (S10) and
  `root_forced_commands_only`; Tasks 13 and 17 add a text for every skip reason the planner exports.
- 15:13 — deferred minors of Task 1: inside quotes a backslash escapes any byte (sshd escapes only `\"`), so
  `HasOption` on stored options could disagree with sshd; the `onHold` test hook is a package variable; the archtest
  purity rule is a deny list — cost: an option sshd reads differently, a test race under `t.Parallel`, an import a deny
  list misses. Of Task 2: m1, the shared-file rule sees only recorded places by path string — a co-user Alice never
  recorded is protected only by the provider's owner check (carry: shared key files from the sshd facts).

## Provider and fake (Tasks 3–4 and follow-ups)

- 15:15 — the fake's fidelity gaps go into the Tasks 3–4 fix round (test-first) — why: the Task 12 property test runs
  against the fake — cost: one more round.
- 15:28 — the fake key world as of b423c6f binds every harness: an add to a file never put for that user is refused; an
  add does not add the file to the user's login set; for a shared file put it for every user, owner first;
  `FaultLateWrite` without a clock panics; `providertest.CheckKeyLifecycle` is the shared conformance script.
- 16:14 — deferred minor of Task 3: the fake is stricter than the real provider for a file never put, its root and
  connection-account rules are simpler, `from=`, `StrictModes` and file order are not modelled, the helper fidelity
  suite has no shared-file owner case — cost: a behaviour of a real server the fake does not show.
- 16:23 — discovery states each user's key-file completeness explicitly (a4c44d4, then edcff2e in the inventory: the
  flag is carried, cleaning that drops or truncates clears it, old-shape data reads incomplete) and deploy fails closed
  [8] — why: a shared file deployed as another user could otherwise open the connection account — cost if wrong:
  deploys are refused on servers whose connection-account key files cannot be fully listed — reverse:
  `connectionFilesKnown` in `internal/sshkeys/deploy.go`.
- 18:29 — listing coverage becomes explicit in the provider (complete, not read, partial, unknown) and the handlers
  fail closed (540651d) [37] — cost: a step retries where a file cannot be fully read.
- 19:44 — a file with any line the parser does not understand is partial coverage (1bae6ec) [37].

## Schema (Task 5) and inventory (Task 6)

- 15:16 — contract C2 is amended: the triggers enforce the C8 state machine and a `rotations_guard` is added — why: the
  plan's own C2 text was the defect (Critical findings P6-01, P6-02); the database is the last line of defence for the
  phase invariant — cost if wrong: store code in Tasks 8, 9 and 11 must follow stricter transitions (a fix round, not a
  lock-out) — reverse: none; do not.
- 15:16 — from Task 5 as built: a finished run freezes its places, so the store writes every place update before it
  moves the run to a finished status; `managed_private_keys_guard` blocks identity edits by every role. From Task 6:
  `inventory.ErrTargetDisabled` maps to `ALC-TGT-0006`.
- 16:35 — G1–G15 (guard-rulings-round2.md): loosened `added → add_failed`, a direct `undo_failed` when nothing was
  sent, `remove_failed → removing` through the full gate; tightened strict re-check ordering, no send while paused, the
  conditions of `completed` and `aborted`, the run's verification read from OLD, edges that respect the run status,
  every same-file place verified, one run per new key, `verified_at` immutable, the policy locked on a run insert,
  destroy and un-retire locking each other; kept the backward-clock fail-closed and no un-retire of a destroyed key
  [34] — why: the loosened edges never remove an old key, the tightened ones close paths the design never needs — cost
  if wrong: a run stuck where the design expected an edge, found by Tasks 9, 11 and 12 tests.
- 16:35 — G3's known limitation: after `needs_attention` the places of failed removals keep both keys and are cleaned
  by hand [42].
- 17:14 — G3' (a retry needs a strictly newer re-check, later than the failed send, a new send time and a new operation
  ID), G16 (`add_sent_at` set once on entering `adding`), G17 (no `verifying_new`, `removing_old` or `completed` over an
  `adding` place; `adding → undoing` in `rolling_back` through a real undo), G18 (any place of the run in the file that
  is not verified blocks every removal in it; those places end `kept_old`), G19 (insert order policy → run → places)
  — why: close the stale-re-check retry and the unrecorded late add, make the stuck `adding` row impossible — cost:
  store edges must match.
- 17:14 — Task 11: a removal re-sent after a crash and refused by the gate lists the file to learn whether the first
  send removed the key, and records the truth. Task 19: an operator-guide note on rolling back a master-key re-wrap
  (written).
- 17:31 — G18 as built is accepted: a sibling already `removing` or `removed` does not block its file (two verified
  siblings would otherwise block each other for ever); skipped, kept, unverifiable and failed siblings block — cost if
  wrong: none identified.
- 17:43 — G20–G25 and the outbox index: `reverified_at` never decreases and a retry needs a re-check later than a
  stamped failure time (`remove_failed_at`); undo columns required and never cleared; a `removing` sibling exempts a
  send only with a re-check within the same 15 minutes; operation IDs single-use (`rotation_op_ids`); no overlap while a
  place is planned, adding or added; an add re-send is a recorded statement (`add_resend_count`, `add_resent_at`); the
  index `notifications_outbox ((params->>'rotation_id')) WHERE template_key = 'rotation.preview'` [34], [61] — why:
  N9 is the case of an old key leaving on a login that predates a failed one; the rest only add refusals — cost: a
  store statement refused that worked before.
- 17:43 — the key-file path check stays strict (zero-width joiners, soft hyphens, direction marks, no-break spaces are
  refused; that account's list is incomplete) [59] — cost: deploys refused on such a server; known limitation.
  Deferred (Task 6, I-5): no character check on discovered places' paths and user names shown in previews.
- 18:09 — parked: N17, a verified sibling exempts a send however old its re-check — defence in depth only, the planner
  skips shared files — carried to the final review — cost if wrong: none while S10 holds.
- 18:18 — Task 5 complete after four rounds. Deferred: N15 (an undo failure may carry an inherited error code; history
  only), N16 (the stamped failure time above its floor is the application's `updated_at`), D22–D28 (the internal
  schema-rules text). N17 stays parked while the planner's shared-file rule is the only inserter; the same file under
  different path strings (a symlink) is invisible to planner and guard alike → known limitation [51]. Sent to the store:
  N14 (`BeginUndo`'s clock check against the latest re-send) and N18 (one transaction per place in the re-queue,
  fixed in 79af2e9).

## Service (Tasks 7–9)

- 16:23 — Task 10 queues a discovery after an `already_present` or `undo_failed` deploy outcome [58].
- 16:23 — a destroyed key found live again stays retired with audit `sshkey.live_after_destruction` (the `Z1014` guard
  forbids un-retiring it) [52] — cost: an Administrator removes those lines or replaces the key.
- 16:33 — **Run now** on a previewed scheduled run starts that run as built: the row keeps `trigger = scheduled` and its
  `planned_for`; the Administrator is in the audit row [47] — why: those columns are immutable to the application role
  by design, and a grant would loosen the run guard — cost if wrong: the run list shows "scheduled" for a run an
  Administrator started early.
- 16:33 — `insertRun` refuses an oversized plan with a closed reason before the database does
  (`rotation.plan_too_large`, `ALC-ROT-0019`) [62].
- 16:45 — M1: only a notice with `sent_at` ≤ `planned_for` counts; a late notice cancels the run — why: zero lead time
  defeats the notice — cost: one cancelled run when mail is slow. M3: a run Run now created is cancelled when its start
  fails — cost: the Administrator presses Run now again. M4: a notice-undelivered cancellation counts as that
  interval's run — why: no create-and-cancel loop — cost: with broken SMTP a policy silently skips intervals (visible
  as cancelled runs) [15], [47].
- 16:45 — N1: an own reason `sshkey.connection_files_unknown` (`ALC-KEY-0014`); after the upgrade every server refuses
  deploys until it is scanned again → release note [8]. N2: no age bound on a scan's key-file list → known limitation.
  N4: a connection account listed twice → deploy refused.
- 17:32 — I2: Continue is refused (`rotation.notice_pending`) until the sweep has queued the renewal notice for that
  pause; delivery is not required, because an Administrator acts in person [21] — cost if wrong: a one-sweep wait
  after the renewal before Continue. I3: `BeginUndo` is a database step before any network step; undo retries are
  bounded and end `undo_failed`. Late definite results after exhaustion are recorded as a `late_result` step + scan +
  email, never dropped [41]. Scheduled-start tests use an advancing clock (the delivered-notice lookup once compared two
  clock reads, P6-04).
- 17:59 — the planner skips places of servers whose connection-account files are not known completely
  (`connection_files_unknown`) or that are the connection account's files (`connection_account_file`), in the digest;
  `BeginAdd`'s check stays as a second line and fails the place at once with the same reason [36] — why: the dry run
  must equal the run and say the real cause — cost if wrong: none identified.
- 18:06 — in a license pause only Abort is offered and accepted; Keep old, Finish now and Continue are neither offered
  nor accepted in lock, and after the renewal not before the renewal notice was queued; `AllowedActions` shares one
  predicate per action with the decision [44] — cost if wrong: an Administrator cannot choose "keep both keys" during a
  lock.
- 18:18 — when the sweep gives up on an `adding` place whose undo jobs never got through, the place's undo columns are
  written although no undo was sent (G21 and G17 leave no other edge); the `undo_not_sent` step, the queued scan and
  the attention email carry the truth — accepted as built — cost if wrong: the place's columns alone overstate what was
  sent.
- 18:18 — a place already `adding` when the connection-files refusal is found becomes `add_failed` and the run rolls
  back (`adding → cancelled` is not an edge) — accepted, rare (needs a re-send after the scan changed).
- 18:30 — M4: one `notice_failed` step per pause. M6: a scheduled plan with every place skipped emails the
  Administrators once for that interval (`rotation.nothing_to_rotate`) [12] — cost: one more email type. M7: any planner
  skip reason found at send time ends that place `cancelled` at once [36].
- 18:45 — the durable deploy send record lives in the audit log (append-only, claim-fenced) rather than a new column
  [38] — why: the migration was closed to the store owner — cost if wrong: ownership of a deployed line depends on audit
  rows staying readable (they are never deleted).
- 18:57 — A-I1: ownership of a deployed line = a send on record **and** a listing with complete coverage taken before
  the first send that showed the line absent, stored with the send record; a line present before the first send is
  `already_present` and never removed; unknown coverage → ownership unknown → never removed [39] — why: the audit-log
  send record alone cannot prove the helper wrote anything — cost: one more listing per deploy. Task 9's fix round 4 went
  to a fresh implementer (the round-4 rule).
- 19:03 — the service's periodic task reconciles unfinished deploy sends (send on record, no finish, no live job, the
  wait over) with `sshkey.add_outcome_unknown` and a scan, once, removing nothing [40] — cost: the outcome is known only
  after the task runs.
- 19:23 — implementer rulings accepted: an `added` answer outranks a later "already present"; after downtime the next
  run is the first interval boundary whose notice is still ahead of now [12].
- 19:44 — the reconciliation has no age limit (oldest unreconciled first, in bounded batches, by a durable cursor);
  `Owned()` on the helper's "added" answer alone is accepted; a send known not to have written does not count; a deploy
  of the new key of an unfinished run is refused (`ALC-KEY-0018`) [40], [39], [53].
- 19:53 — T14-D1: the spec wins — the sweep flags the run at the first pass after the lock begins in every non-terminal
  status with work or a timer ahead, overlap included; one `rotation.paused_license` email per pause; the overlap timer
  does not run while paused and resumes from the remaining duration [43] — cost: Administrators get the pause email
  earlier (as specified).
- 20:00 — the fix-round cap for Task 9 was reached (round 5 of 5): a last scoped re-review of rounds 4–5 followed with
  the jobs round 2, and its residuals were adjudicated, not looped.
- 20:45 — parked: F1, a backward clock step or instance clock skew over an hour can leave an ended deploy behind the
  reconciliation cursor (never reconciled; the regular scan still records the line) — real, deferred (cheap later fix:
  start each walk 24 hours before the cursor) — cost: one missing audit row and an early scan.
- 20:45 — parked: F2, a place is labelled `rotation.listing_incomplete` from its last recorded step; a later unreachable
  attempt records none, so the cause text can be wrong — real, no safety effect, deferred.
- 20:45 — parked: F3, a run in `adding_new` whose only pending work is verifying already-added places gets no pause flag
  or email in lock (nothing is sent or removed) — real, deferred; known limitation [63].

## Job handlers and the property test (Tasks 10–12)

- 18:29 — listing coverage explicit and handlers fail closed (above, provider). I3: `ErrPaused` never changes a place's
  state. M4: F-39 follows the spec — a hung add is a retryable failure with reason `ssh.timeout` (replacing the
  first build's "job succeeded with `stopped: interrupted`") [46]. Ownership of a found line and the S3 anchor on a
  deploy come from a durable send record in the store.
- 19:03 — deviations accepted: an add that times out after the write started did not mark the server unreachable (later
  dropped: c3794c9 marks it again); a deploy waits the S3 time before a re-send, which uses one of its three attempts
  [46]. `late_result` is unreachable through the handlers (no directed test).
- 20:45 — parked: F4, if recording "not written" itself fails, that send still counts for ownership (needs three faults
  together) — real, deferred.
- 20:45 — deferred: two property schedules to add when the loop reopens (a second lock during a resumed overlap; Keep
  old on a shared file plus a hang at the first removal).
- 20:50 — T14-D2: the handlers consult the pause flag and the licence gate before any session or login; the undo after
  an Abort stays ungated (L-86); the property test's licence invariant covers every command including logins [45] —
  cost: none identified; a nil gate is refused by a wiring test.
- 20:59 — deferred: a job stopped by the lock before it reaches the store keeps the retry the sweep counted (at most one
  per lock entry; a store read `MaySend` would return it).
- Implementer rulings accepted from the reports: a definite add whose test login cannot connect stays `unverified`
  with `login_unavailable` in a deploy [9]; any store failure is a retryable job failure; an uncertain undo is left
  `undoing` for the next job to list the file; a login that cannot connect after a lost add is recorded at once; a
  removal found already done is recorded as `Removed: 1` (the audit row may say one line where two were removed); F-38
  as built: three compare-and-set attempts [46]. The first build's "an attempt after the first owns a found line" was
  replaced by A-I1.

## API (Task 13)

- 17:55 — abort is `rotation.manage` (Administrator, operate tokens allowed, no step-up) as plan row 24 says; the
  controller's dispatch text was wrong to list it under step-up [24] — why: stopping must never be harder than
  starting, and an undo only removes the new key — cost if wrong: a token can stop a run — reverse: the route's
  permission in `internal/api/rotation_handlers.go`, then `make authz-doc`.
- 17:55 — late results get their own email template `rotation.late_result` [41].
- 17:55 — download attempts counted before the permission check: accepted at first, overridden at 18:06.
- 18:06 — the download limiter charges only authenticated full browser sessions, per user [5] — cost: none identified.
- 18:31 — the API returns `actions_allowed` intersected with the caller's permissions [48] — why: the UI renders exactly
  that list — cost: none identified.
- 18:59 — Task 13 complete after one fix round and follow-ups; the later mapping and text commits (f8fd947, 88c858b,
  b5fdf0d) were not re-reviewed separately and go to the final review.
- Implementer rulings accepted from the report: delete policy stays `rotation.manage`; skip texts live in
  `locales/common` as `rotation.skip.<reason>`; emails carry the reason, not the ALC code (the service cannot import
  the API) [50]; an unexpected guard refusal answers `ALC-SYS-0003` and logs only its SQL state and constraint.

## Web (Tasks 16–17)

- 15:28 — the deploy dialog does not offer servers that are disabled or whose identity changed [57] — why: the UI must
  not offer what the server refuses — cost if wrong: an operator looks at the server page to learn why a server is
  missing.
- 16:16 — deferred minors of Task 16: `client.ts` compares the content type case-sensitively; the deploy dialog's
  failed-job alert would be green for a failed job whose result is verified or already present (not produced by the
  contract). Carried to Task 17: show the job result note; to Task 18: the octet-stream check against the real
  handler.
- 18:49 — parked (Task 17): a retried vault in the import history shows only its first page — accepted, a retry is a
  recovery path — cost: older rows of that vault need a page reload.
- 19:04 — no separate re-review of Task 17's round 3 — why: 47 changed lines, the controller read the whole diff — cost
  if wrong: the final whole-branch review re-reads the web.
- Implementer rulings accepted: the client drops the connection account's own entry and the files it lists (the server
  enforces); the download passphrase fields are wiped when the request body is built; **Download private key** is shown
  for a retired, not destroyed key (Administrators); after a successful generate the page navigates at once.

## Tasks 14 and 15

- 19:44 — Task 15's review minors (the periodic tasks' targets, a nil keyring, the symbol check on any one symbol,
  archtest only on `/test/clock`, a test name, the e2e tests not linted) went to a follow-up the controller verified by
  reading (3b26c23, 08a8e10).
- 19:53 — Task 14's test rulings accepted: a retired key can be downloaded until destroyed (the controller's dispatch
  had said "refused"; Task 7's rule and `ALC-KEY-0007` say so); no Viewer role exists (read tokens and the Auditor
  stand in).
- 21:03 — the documentation part of Task 19 runs beside Task 18 — why: disjoint files, and the docs agent uses no
  Docker — cost: sentences that depend on the e2e outcome are checked again after it.

## Final review (2026-10-07)

The phase was resumed by a new controller session (Fable 5.1) on 2026-10-07 after the usage-limit stop of 2026-10-05
21:23; Task 19's documentation commits had landed, Task 18 had been cut off mid-run with its files uncommitted.

- 10:54 — Task 18's first run (retries 0) on the stack restarted without a rebuild: 15 passed, 1 failed, 4 skipped.
  The e2e agent had marked two product defects `test.fixme`: D1, the rotation switch's track label "Off" at 2.55:1,
  and D2, the indigo link in the red paused banner at 4.36:1 (axe color-contrast, serious). The failure was the test's
  own race: a full page load right after the language choice cancelled `PUT /auth/locale`, and the next sign-in
  applied the account's English. Ruling: the controller fixed all of it itself (fc16ef8: the state is a text beside
  the switch, the AutoDeploySwitch pattern; the link black and underlined, the LicenseBanners pattern; f2eeb71:
  `chooseLanguage` waits for the save's answer, the fixme markers removed, three `no-useless-assignment` errors
  removed — `file = ''` cannot clear a JavaScript string, so the downloads are block-scoped constants with
  `.finally(delete)`) — why: four small mechanical changes in files no agent owned any more — cost if wrong: the
  rebuilt stack's runs show it. Three consecutive runs on the rebuilt image: 20 passed each.
- 11:14 — the final whole-branch review at 8854791 (final-branch-review.md, Opus, read-only): "mergeable after
  fixes"; Critical 0, Important 3, Minor 8. FB-1: old-key rule (2) was checked only among the run's own places in the
  overlap-end decision, the store's send gate and the database guard, so a live place of the old key discovered in
  the same file during the overlap (a new account reading a shared `AuthorizedKeysFile`) lost the old key without a
  login with the new key ever tried for it. FB-2 and FB-11: no index behind `locSelect`'s `rotation_steps` subqueries
  and the policy page's last-run lookup. FB-3: Task 18 uncommitted (closed above). FB-4: **Run now** loops on
  `ALC-ROT-0003` while a notified scheduled run holds an older digest. FB-5, FB-8: documentation wording. FB-6: the
  download dialog accepted reasons the server refuses, after wiping the passphrases. FB-7: every location job decodes
  the whole run. FB-9: the run list typed as full runs. FB-10: the plan's Review Focus names a test that does not exist
  (the two real tests pin the zeroing). Rulings: fix FB-1 in the three layers (the decision ends the place `kept_old`,
  the store refuses, the guard raises `Z1011`), FB-2, FB-11, FB-6, FB-9, FB-5 and FB-8 in one dispatch; park FB-4 —
  why: a scheduled run replans at its start and an Administrator can switch the policy off and on to cancel the
  planned run, then **Run now** — cost: a confusing 409 loop until then; park FB-7 — why: bounded by the plan limit
  and the job count, no safety effect — cost: a slow very large run; FB-10 needs no change (no document on the branch
  quotes the name).
- 11:40 — the fix round (fix-round-final-report.md, Opus): a76e747 (FB-1; red first at 8854791 in a detached
  worktree: `TestOverlapEndKeepsOldForASiblingOutsideTheRun`, `TestBeginRemoveRefusesASiblingOutsideTheRun`,
  `TestSiblingOfOldKeyDuringOverlapKeepsOld` — the old key left the file and one removal reached the server —,
  `TestRotationRemovalRefusesAPlaceOutsideTheRun`), 8b113ac (FB-2, FB-11; `TestRotationLookupIndexes` red first),
  a4359d2 (FB-6; Vitest red 3 first), fedc8c5 (FB-9), 5d6b45a (FB-5, FB-8). Green with `-race`: `sshkeys` 90.0 %,
  `sshkeyjobs` 86.8 %, `migrations`, `api` 95.8 %. Ruling on the implementer's concern — a sibling that appears between
  the sweep's decision and the removal job's send is refused by the store, and the place then ends `remove_failed`
  and the run `needs_attention` with the old key in place, not `kept_old` — accepted — why: the decision layer catches
  the ordinary case, the store and the guard are the backstop, and C8 has no `verified → kept_old` edge at send time
  — cost: a `needs_attention` run in a race that needs a scan between the decision and the send. Known limitation.
  The property test was not extended (its fault hook runs while the fake world is locked); the three targeted tests
  cover the rule at each layer.
- 11:40 — the committed spec's login check used `StrictHostKeyChecking=no`, which `TestNoCodeAcceptsAnyHostKey`
  (SEC-080) refuses; the controller pinned the target's host key through a `known_hosts` file written from
  `/etc/ssh/ssh_host_ed25519_key.pub` (9908446; a throwaway key reaches "Permission denied (publickey)" on the target,
  not a host-key failure).

## Process

- Models, as the ledger and the commit trailers state them: the plan was written by Opus 5.5; the pre-flight security
  review and the security reviews of Task 7, Task 9 and Tasks 10–12 (and their combined re-review) ran as Fable; the
  consistency scan as Opus. Implementers per the trailers: Sonnet 5.5 for Tasks 1–6 (and the Tasks 5–6 rounds 1–3),
  the provider follow-ups (a4c44d4, 540651d, 1bae6ec), the inventory follow-up (edcff2e) and the web Tasks 16–17;
  Opus 5.5 for Tasks 7–15, the Tasks 5–6 round 4 and the Task 9 round 4 (both fresh implementers under the round-4
  rule); the two controller commits carry Fable 5.1. The ledger names no model for the other reviewers or for Task 18.
- Every task or task group was reviewed by an agent that did not write it; fix rounds went back to the package owner
  of the moment and were re-reviewed in scope. Fix rounds per task: Task 1: 1; Task 2: 1; Tasks 3–4: 1, plus three
  provider follow-ups; Task 5: 4 (round 4 by a fresh implementer); Task 6: 4 with Task 5, plus one inventory
  follow-up; Task 7: 2; Task 8: 1; Task 9: 5 of 5 (the cap); Tasks 10–12: 3 (round 3 for T14-D2); Task 13: 1, plus
  four follow-up commits; Task 14: 2, plus one follow-up; Task 15: 0, plus one follow-up verified by the controller;
  Task 16: 1; Task 17: 3 (round 3 not separately re-reviewed).
- The fix loop that reached its cap: Task 9 (round 5 of 5, 31d0793). The last scoped re-review (task-7-12-final-rereview,
  at f703350) found four Minor items, F1–F4, and 13 limitations L1–L13; the controller parked F1–F4 with reasons and
  sent L1–L13 to this phase's security review, instead of a sixth round.
- Test-first was not followed everywhere; where it was not, the evidence is mutation (a test shown red under a changed
  line) or a red build: Task 2 (the first red was a compile error; mutation instead), Tasks 3–4 (code before tests,
  red only as compile failures; the fix round was red-first), the provider follow-up a4c44d4 (compile failure only;
  the always-true mutant is red), Task 12 (property and crash tests written against a finished handler; red by
  mutation), Task 13 (the email render and handler tests written after their code; 13 mutations), Task 16 (red-first
  only for the Deploy, Download and page tests), Task 17 (red-first only for the add-vault test; its round 1 had 20
  tests red first).
- The usage-limit interruption (20:31): the jobs owner (Tasks 10–12 round 2), the API owner (the codes round) and the
  Task 14 owner were cut off mid-work with uncommitted files in the shared tree (`go build ./...` still passed); all
  three were resumed at 20:31 with pointers to their files, and finished (195ed12, 2afb404, f703350; b5fdf0d; df265c1,
  c2aa0ac).
- The controller edited files itself twice: it added 11 fingerprints to `.gitleaksignore` after reading each flagged
  line (6a32c97: Go import paths in the archtest tables and the plan; same pattern as 8ad2ddc and 0386077), and it
  restored the `sshkey.add_sent` audit label to "about to be sent" in both locales (c9ae2ab).
- The controller's own wrong instructions, corrected: the Task 13 dispatch listed abort under step-up (ruled
  `rotation.manage`, 17:55); a dispatch said a retired key is refused for download (Task 7's rule and the Task 14
  ruling: downloadable until destroyed); the overlap endpoint was described as setting a run's overlap (it sets the
  policy's, as the brief and Task 18 expect; a run keeps its own); the web labels dispatch described `sshkey.add_sent`
  as "sent" (the row is written before the helper call; c9ae2ab restored the earlier label).
- Foreign failures during parallel work were not chased by the agent that saw them: the `cmd/alice` wiring test red
  until Task 15, the Task 14 unit tests red on the store's uncommitted names until the API codes round, the
  `TestL84RenewalAfterTwentyDays` clock steps until the jobs round 2, and one `sshkeys` suite hang that was the
  implementer's own test (a hook re-entering `sync.Once`; test pools then got a 5 s `lock_timeout`).

## Status at phase close

Commits per task (from `git log` and the ledger; a range includes the fix rounds):

- Plan: 2e34517. Task 1: d968e45, 12a0842. Task 2: a0ca1ac, 6c43ccf. Task 3: 1cd3a84, b423c6f; follow-ups a4c44d4,
  540651d, 1bae6ec. Task 4: 0a3ad4c, b423c6f.
- Task 5: b066b33, 95519af, 7d67576, 6b7e6a8, 94d7779. Task 6: 312bc59, edcff2e, 4c25ae6.
- Task 7: c72ad55, 0961220, 4bbb1d3. Task 8: b8a7aae, 9193d5d. Task 9: d016735, 7382414, 50f1c58, 3371ec2, c1f28ce,
  b484b26, 79af2e9, 82dad01, 31d0793 (4 parked).
- Task 10: f6d04b6, 17935e7, a0848fb, 1703a3d, c3794c9, 195ed12, f703350, b7eab4e (1 parked). Task 11: 94f4780 and
  the same fix rounds. Task 12: c06a4f6, 628ed61, 2afb404.
- Task 13: 58a0f0e, 2e691d5, da3dc1a, 6589a59, f8fd947, 88c858b, b5fdf0d. Task 14: 2355d10, df265c1, c2aa0ac,
  d8e030c, 03332df. Task 15: 802ab49, dfade43, 3b26c23, 08a8e10, 2c47749.
- Task 16: ed9ef93, 14f96f8. Task 17: 9b9a786, c28a2c5, 413d890, 754f8fc, e539f57, e2e8705. Controller: 6a32c97,
  c9ae2ab.
- Task 18 (Playwright): f2eeb71, 9908446, with fc16ef8 for the two contrast defects it found (controller commits,
  Fable 5.1); the e2e agent's model is not recorded.
- Task 19: 5decc05, 2eaaf89, a0d20da, 94672f8, 8854791 (the documentation, Opus 5.5); the final whole-branch review and
  its fix round a76e747, 8b113ac, a4359d2, fedc8c5, 5d6b45a (Opus 5.5); the coverage floors and the evidence of the
  final `make ci` in the commits that close the phase (controller, Fable 5.1).

## Carried to later phases

Parked or deferred in Phase 6 (no later phase is named by the ledger unless given; each is a known limitation in
docs/security/reviews/phase-6.md):

- F1 (reconciliation cursor behind a clock step; fix: start each walk 24 hours before the cursor), F2 (cause text of
  an exhausted place), F3 (no pause flag for an `adding_new` run with only verifications pending; fix: extend the
  condition to `added`), F4 (a failed "not written" record still counts for ownership) — unassigned.
- The 13 limitations L1–L13 of the last Tasks 7–12 re-review; L3 (a lock over 90 days prunes deploy jobs before
  reconciliation) needs a deploy-send table, that is a migration — unassigned.
- N17 (a verified sibling exempts a send whatever the age of its re-check; unreachable while S10 holds) and the
  symlinked key-file path; the shared-file rule from the sshd facts (Task 2 m1) — a later phase that rotates shared
  files.
- N15, N16, D22–D28 of the migration; I-5 (no character check on discovered places' paths); N2 (no age bound on a
  scan's key-file list); a job stopped by the lock keeps one counted retry; the audit-log send lookup on a large table;
  the two property schedules; Task 1's quoting, hook and deny-list minors; Task 3's fake fidelity; Task 16's two web
  minors; Task 17's retried-vault first page — unassigned.
- A scheduled policy with an oversized plan logs at every tick without an email; a `needs_attention` run leaves the
  policy on the old key — found while writing these documents; unassigned.
- From the final review: FB-4 (**Run now** answers `ALC-ROT-0003` while a notified scheduled run holds an older
  digest; switch the policy off and on, or wait for the scheduled start, which replans); FB-7 (every location job
  decodes the run's whole plan: quadratic on a run near the plan limit); a sibling place of the old key that appears
  between the sweep's decision and the removal's send ends `remove_failed` → `needs_attention` instead of
  `kept_old` — unassigned.
- Phase 7: the certificate private-key download (carry 11); notification recipients and the 30-day retention as
  settings; cron-like schedules and partial-location policies have no phase named.
- Phase 8: the helper scans all accounts more than once per key change (carry 4; about four scans per rotated place);
  lockfile secret scanning, `osv-scanner`, a real-systemd job, a nightly pipeline, mutation testing (carry 14).

Carries from earlier phases, as this phase left them:

- Closed: L-83, L-84, L-85, L-86 and L-88 with the real runner and scheduler (`internal/jobs/sshkeyjobs`, and over the
  wire in `internal/api`); L-29 real-job parts for rotation and deploy (`TestRotationInLockRunsNoCommand`,
  `TestLockDuringRemovingOldSendsNoCommand`); L-81 for `sshkey.add` (`TestDeployHeldInLockThenConfirmed`). L-87 stays
  the Phase 5 test.
- Closed, Phase 5 parked items, checked in the code: the import history no longer drops a vault whose read failed (an
  error line with **Try again** per vault, `web/src/components/ImportHistory.tsx`); the add-vault dialog shows both the
  roles text and the failed-check text (`web/src/components/AddKeyVaultDialog.tsx`); the OpenAPI sentence on the 412 of
  `PATCH /bindings/{id}` says a missing `If-Match` is answered first (`api/openapi.yaml`).
- Partly closed: an `authorized_keys` change whose read-back differs (Phase 3/4): deploys and rotations undo their own
  additions by fingerprint; the manual removal still stops for a person (carry 10).
- Re-deferred by the plan: the extra query per certificate in a Key Vault poll (Phase 7); the Nginx helper items (an
  unreadable journal blocking its pair, the dropped-certificate warning without the file, a TLS block without `ssl`
  listen, host-name listens; no helper change in this phase); uncoalesced inventory refusal rows (carry 12, with the
  three new refusal actions); `facts.nginx.scanned_at`, recovery codes lost with the completing answer, a certificate
  re-issued for a completed signing request's key, e2e hooks for the route error page, the `unverified` banner and the
  locale fallback, and the Phase 5 Key Vault limitations (carry 13).
- Owner: a git remote and the first workflow run, the production license key, the walkthroughs of Phases 1–5 and of
  the remediation, the real-Azure suite, the Turkish tone review, the crypto sign-off, a clean-machine `make ci`, and
  now the Phase 6 walkthrough table of docs/security/reviews/phase-6.md. Environment: containers on the build machine
  cannot reach the LAN DNS (image builds and trivy need host networking there).
