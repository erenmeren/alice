# Rulings: canary deployment and application health check (R65)

Built on branch `canary-deploy` from the plan
[2026-10-24-canary-deployment.md](../plans/2026-10-24-canary-deployment.md) (14 tasks) against the design
[2026-10-24-canary-deployment-design.md](../specs/2026-10-24-canary-deployment-design.md). The owner was away when the
design was written; every default of design §24 and every ruling below is marked **owner to confirm**.

## Numbers

Confirmed at Task 1, after `main` at `36a415af` (hardening batch 1, R64, merged) was merged into the branch:

| Item | Value | How it was confirmed |
|---|---|---|
| Decision | **R65** | the last entry of `alice-v1/00-decisions.md` is R64 |
| Migration | **`00035`** (`00036` free if a second one is needed) | the last migration is `00034_revocation_checks.sql` |
| Error codes | **`ALC-DEP-0031`..`0035`**, **`ALC-SVC-0020`** | the last codes in `internal` and `locales` are `ALC-DEP-0030` and `ALC-SVC-0019` (R64 took `ALC-CRT-0020`..`0026`, no DEP or SVC code); `ALC-SVC-0020` was registered by this branch's Task 2 |
| Down SQLSTATE | **`Z1033`** | the highest in `migrations/` is `Z1032` |
| Names | no collision | `canary`, `rollout` appear nowhere in `internal/jobs/types.go`, `locales/common/en.json` or `internal/api/errors.go` but this branch's `ALC-SVC-0020`; R64's `revocation.check`, `incident.*`, `certificate.revoked_by_authority*` are not used here |

No number of the design or the plan changed.

## Coordinator rulings at approval (R65)

- **C1. The check is a path plus an optional host and port, dialed at the location's own address (design decision
  12), not the free URL of the coordinator's original brief.** Why: on shared servers and behind load balancers one URL
  names one website, so a fixed URL would observe the wrong website for every other destination; and a URL the policy
  names would be an address Alice dials on an Administrator's word, an SSRF surface. Dialing only the location's
  verification address or its server's host (both already dialed by the post-deploy probe), through the SEC-065 rule,
  removes that surface: `check.host` is only the TLS server name and the `Host` header and is never resolved
  (`TestCheckNeverDialsTheHostName`). Cost if wrong: a service that wants to observe an application through a
  different front end (a CDN, a separate health endpoint host) cannot; it would need a new field.
- **C2. Decision 11 (an unknown round never passes; the rollout fails closed after hold + grace) and decision 17
  (`canary.advance` and `canary.check` are ClassAlways) are adopted.** Why: a canary that cannot observe must not
  release, and observation and revert protect production in every licence state, like recovery and `incident.advance`.
  Cost if wrong: an observation outage (SSH down) reverts wave 1 after the grace instead of waiting.
- **C3. Migration numbering `00035` (and `00036` if needed) after `main` has R64's `00033`/`00034`.** Confirmed above.
- **C4. Gate overlap.** Docker-based tests and `make ci` run only when `pgrep -af 'playwright|make ci'` shows no other
  run; the Task 14 gate waits for the coordinator's "gate free". e2e: `E2E_PROJECT=alice-e2e-canary
  ALICE_E2E_PORT=9979`.
- **C5. Defects outside the canary scope are not fixed here**; they are listed under "Found, not fixed".

## Design defaults (design §24, rulings 1-29, owner to confirm)

1. **A new deployment state `holding` instead of finishing wave 1 `succeeded` and reverting later.** Why: a done row is frozen and "rolled back after success" has no path; holding keeps `deployments_one_active`, the recovery machinery and the status meanings intact. Cost if wrong: a wave-1 deployment is `running` for the whole hold, so a person reads it as unfinished; reversible only with a new migration.
2. **The revert is a recovery with `revert_reason` (no new job type).** Why: it reuses the journal-driven, guard-checked, paced rollback that already handles every uncertain case. Cost if wrong: a revert waits on the recovery pacing (seconds); none found otherwise.
3. **Override always needs a fresh browser step-up; API tokens can never override or continue.** Why: bypassing a safety policy is a person's deliberate act, as R42 keeps tokens away from strict actions. Cost if wrong: an automation that must skip the canary cannot; it needs a person.
4. **Policy field `override: allowed|forbidden` (default allowed).** Why: some services want no escape hatch; most want one for emergencies. Cost if wrong: a service that wanted it forbidden by default must set it.
5. **Key-compromise incident replacements bypass the canary and preempt holds.** Why: a compromised key in service is worse than an unobserved replacement. Cost if wrong: an incident replacement is deployed everywhere at once, unobserved.
6. **Skip the canary when a destination's current certificate expires within hold + 24 h.** Why: the margin covers wave 2's own pace and the grace; the skip is audited. Cost if wrong: a soon-expiring website is deployed without a canary.
7. **An `unchanged` wave-1 outcome is not held, checked or reverted.** Why: nothing was written; nothing can be restored. Cost if wrong: a wave 1 that was already in place starts wave 2 without observation.
8. **The source service's policy decides (certificate's, ACME certificate's or vault's).** Why: consistent with R55: automatic deployment is judged on the source's service; the destinations keep their trust check. Cost if wrong: a destination service that wants a canary cannot ask for one.
9. **A snapshot of the policy at the rollout's creation.** Why: a rollout behaves as it was announced; an edit cannot extend or cancel a hold under way. Cost if wrong: a policy fix reaches only the next rollout.
10. **A failed wave-1 deployment fails the rollout and reverts the other wave-1 websites.** Why: wave 1 is one unit; a mixed wave 1 is what a canary avoids. Cost if wrong: a healthy first-wave website is put back with the failed one.
11. **Unknown rounds never pass; fail closed after hold + grace (max(2 x interval, 5 min)).** Why: a canary that cannot observe must not release (C2). Cost if wrong: an observation outage reverts wave 1.
12. **The HTTP check is a path (plus host and port) dialed at each location's own address, not a free URL.** Why: a fixed URL observes the wrong website on shared servers and behind load balancers, and it would be an SSRF surface (C1). Cost if wrong: an application observed through another front end cannot be checked.
13. **No proxy for the check.** Why: the destination is a managed server Alice reaches directly; a proxy would observe the proxy. Cost if wrong: a website reachable only through a proxy cannot be checked.
14. **Default failure threshold of 2 consecutive rounds.** Why: one lost packet must not roll production back; two failures 30 s apart still revert within about a minute. Cost if wrong: a flapping website passes when it never fails twice in a row.
15. **Providers are not special-cased; Apache and HAProxy inherit the canary when they deploy.** Why: one behaviour (design §21). Cost if wrong: none found.
16. **A manual wave 2 in a confirmed lock: release wave 1, stop, e-mail; transient gate answers wait up to 1 h.** Why: wave 1 passed and stays; a person's change waits for a person after the renewal (R29 spirit). Cost if wrong: the rest of a manual rollout must be deployed again after a renewal.
17. **`canary.check` and `canary.advance` are ClassAlways.** Why: observation and revert protect production in every licence state (C2). Cost if wrong: rounds keep running in lock.
18. **Continue needs step-up and the destinations' rights; abort needs neither step-up nor destination rights.** Why: the first widens the change, the second narrows it. Cost if wrong: a person of the source service can put back websites of other services they cannot deploy to (only to their previous certificate).
19. **Rounds are not audited individually; only the deciding failure and the transitions.** Why: keeps the audit chain proportional; the latest round is on the page. Cost if wrong: the history of passing rounds is not kept.
20. **No new e-mail for a failed canary; the `deployment.failed` e-mail carries the canary reason; one new template for the stopped manual rollout.** Why: the recipients already get that mail for a rolled-back deployment. Cost if wrong: one mail per first-wave website instead of one per rollout.
21. **Hold 1 min-24 h, interval 15 s-10 min, timeout 1-10 s, wave 1 at most 10 websites or 50 %.** Why: far below the helper's 7-day backup retention and the Windows rollback window; bounded job load. Cost if wrong: a service that wants a longer hold cannot set one.
22. **`first` is validated against the service's locations at save and ignored where stale at use.** Why: locations come and go; a stale entry must not block a deployment. Cost if wrong: a removed website silently stops leading.
23. **One rollout table, one observation table, four deployment columns.** Why: the minimum that keeps rollout state out of single deployments and wave 2 out of the table before it exists. Cost if wrong: none found.
24. **Automatic rollouts complete at release; the planner deploys the rest.** Why: the planners already own pacing, retries and stopping. Cost if wrong: wave 2 of an automatic rollout follows the planner's pace, not the rollout's.
25. **New codes `ALC-DEP-0031`..`0035`, `ALC-SVC-0020`.** Why: the next free numbers (confirmed at Task 1). Cost if wrong: a renumber at merge if a parallel branch took them.
26. **Rollout reads are visible like deployments; actions need `certificates.operate` on the source service, also for an ACME-sourced rollout.** Why: the people who could request the deployment can steer it; a test pins `acme.operate` = `certificates.operate`. Cost if wrong: a future split of the two permissions fails that test.
27. **Planners leave the locations of a live rollout alone; a failed person's rollout stops the matching automatic deployment.** Why: otherwise a planner would deploy wave 2 during a person's hold, or roll a failed certificate out again. Cost if wrong: an automatic deployment waits for a person's rollout to end.
28. **A revoked or compromised deployed certificate is reverted, never released, even under an incident.** Why: releasing it would make a forbidden certificate permanent (R48). Cost if wrong: none found.
29. **`preempted` and `stopped` automatic rollouts let the planner continue as after `completed`.** Why: the incident or the licence ended the canary, not the certificate's health. Cost if wrong: an automatic wave 2 follows without observation after an incident.

## Plan rulings (30-34, owner to confirm)

30. **Wave-2 jobs are `certificate.deploy` (ClassChange) with trigger `manual`**, `requested_by` the original requester. Why: they are part of a person's request; a lock that begins after insertion holds them for an Administrator as today. Cost if wrong: a wave 2 paused in lock needs `jobs.confirm`.
31. **The rollout row is inserted in the same transaction as the wave-1 deployments.** Why: a rollout without its deployments, or the reverse, must never be visible. Cost if wrong: none found.
32. **`holding` counts as sent wherever `sent(state)` is consulted.** Why: the operation id is recorded and the files changed. Cost if wrong: a holding row could be finished `failed` ("nothing written").
33. **The e2e health paths are static Nginx locations** (`/healthz` 200, `/canary-fail` 503 in `s1`..`s5`). Why: the real check runs end to end with no test seam. Cost if wrong: an image rebuild.
34. **`DeploymentView` shows `holding` as observation.** As built, the outcome reads "The new certificate is in place and verified; it is under observation before the other websites follow" with the round summary, instead of an extra step row (the outcome is where the page says what happened; the steps stay the deployment's own). Cost if wrong: a row in the step list.

## Rulings made during execution

- **Task 2. An unknown or foreign `first` id is `validate.Required` on `body.canary.first.N`**, not a new `not_found`
  code. Why: the house pattern for an unknown reference in a policy (`checkPolicyProviders`); `validate` has no
  not-found code. Cost if wrong: one code and its locale keys.
- **Task 2. Explicit default values are dropped from the stored document** (hold `10m`, interval `30s`, failures 2,
  count 1, override `allowed`, expect_status `[200]`, timeout `5s`, an empty `first`). Why: design §5.2 "defaults are
  not written into the document", and equal policies must have equal documents (`ChangedKeys`, the audit diff). Cost if
  wrong: none; the editor shows defaults either way.
- **Task 2. An empty duration string is the same as an absent one.** Why: the plan's `Hold string` cannot tell them
  apart. Cost if wrong: none.
- **Task 2. `CanarySettings` has a JSON form with readable durations** (`"hold":"10m"`), used for the rollout's
  snapshot. Why: readable rows and API answers. Cost if wrong: one marshal pair.
- **Task 2. `api/openapi.yaml` gains the `canary` schema and the troubleshooting entry of ALC-SVC-0015 stops listing
  `canary` in the same commit as the key.** Why: the documents stay true at every commit. Cost if wrong: none.
- **Task 4. Ports** (superseded after CI run 40215904071). `httpcheck`'s tests first used the fixed ports
  `127.0.0.1:45420`..`45431`; `45428` was in use on the CI runner (a fixed port inside Linux's ephemeral range meets
  another process's outgoing connection), so they now listen on a port the system chooses (`listen` on `:0`).
  `canaryjobs` keeps `45422`: its location row, which names the port, is written before the server starts. Cost if
  wrong: one fixed port left that can collide the same way (see "Found, not fixed").
- **Task 4. Reasons by phase.** A failure before the TLS connection is up is `canary.unreachable`, after it
  `canary.protocol`; a body cut by the timeout (slow-loris) is `canary.timeout` with the status kept; a cancelled
  context is `canary.timeout`. Why: design §9.3 lists the reasons, not where each applies. Cost if wrong: a reason text.
- **Task 4. The `Host` header carries no port** (the server name, or the bracketed address). Why: design §9.3 makes
  `Host` the server name; Nginx and http.sys match host names without the port. Cost if wrong: a virtual host keyed on
  `host:port` would not match.

- **Task 3. The holding CHECK is written `wave IS NOT DISTINCT FROM 1`.** Why: the design's `wave = 1` passes for a NULL
  wave (a CHECK of NULL is true). Cost if wrong: none.
- **Task 3. `migrations/frozen_test.go` is not changed.** Why: it freezes only the shipped migrations (00001-00017).
  Cost if wrong: one line later.
- **Task 3. `RequestRevert` queues the recovery job at once**; `recover_after` then follows the existing pacing. Why: the
  design says `recover_after = now`, and the job already exists. Cost if wrong: none.
- **Task 3. A hold refuses every engine write but the release** (MarkRecovering, RequestRecovery, an uncertain
  RecordOutcome, a failed or rolled-back finish answer `ErrDeploymentState`; a repeated success finish is a no-op), and
  a revert deployment never records a success. Why: defence in depth; the canary owns a hold. Cost if wrong: none found.
- **Task 3. Every rollback of a revert carries `revert_reason` as its error code** (also from the writing, restoring and
  restore-failed journals). Why: design §10 names the cause only for committed; one reason per revert is what people
  read. Cost if wrong: a text.
- **Task 3. `ReleaseHold` locks itself (location, then deployment) and refuses a revoked or compromised deployed
  certificate.** Why: design §20.3; Task 8 relies on it. Cost if wrong: none.
- **Tasks 5 and 6 are one commit** with both plan subjects. Why: they share fixtures and helpers; Task 5 alone would not
  compile its tests. Cost if wrong: one commit instead of two.
- **Task 5. `RequestDeployment`, `RequestKVDeployment` and `DeployACMENow` keep their signatures**; new `*WithRollout`
  variants answer the rollout. Why: the plan's signature change touches about 40 callers and test fakes for no
  behaviour. Cost if wrong: none (the API uses the variants).
- **Task 5. An override audits `deployment.canary_overridden` only** (not also `canary_skipped`); the expiry guard
  audits `canary_skipped`. Why: one row per decision. Cost if wrong: one audit row.
- **Task 6. `CanaryCheckSpec` (inventory) instead of `*httpcheck.Request` in `CanaryTarget`.** Why: inventory may not
  import `providers/httpcheck` (archtest); `canaryjobs` maps it. Cost if wrong: none.
- **Task 6. The check's server name is a copy of `tlsverify.SNIFor` in inventory (`sniFor`)**, pinned equal by
  `TestCanarySNIIsTheProbesName`. Why: inventory may not import `tlsverify`. Cost if wrong: drift, caught by the test.
- **Task 6. A round runs the HTTP check only when the TLS check did not fail**; a session refusal or a provider error is
  an unknown round with its reason. Why: design §9.5. Cost if wrong: a skipped request on an already failing round.
- **Task 6. A manual rollout whose wave 2 is refused entirely completes at once.** Why: design silent; nothing to wait
  for. Cost if wrong: none.
- **Task 6. The stop e-mail of an automatic rollout uses the existing ACME and Key Vault stop templates** with count =
  the wave-1 size and the revert reason. Why: design §12 (no new template). Cost if wrong: a count in a sentence.
- **Task 6. The clock-jump early release (design §15)** releases when a wave-2 current certificate ends before
  `hold_until` + 24 h (`reason_params.early = expiry`). Why: the condition the creation guard established. Cost if wrong:
  an early wave 2.
- **Task 7. Re-arming a stopped ACME certificate for the same certificate has no product action** (the next renewal
  re-arms); the integration test clears the mark directly to pin the partial unique index. Cost if wrong: none.
- **Task 8. Drift observation and repair and the Windows cleanup are pinned by a source test of their `state <> 'done'`
  predicates** (`TestDriftAndWindowsCleanupSeeAHoldAsUnfinished`), not by full fixtures. Why: their behaviour is unchanged
  by R65. Cost if wrong: weaker evidence.
- **Task 9. Rollout and round reasons are rendered through a reason-shaped allowlist (`reasonOrBlank`)**, not the
  step-code one. Cost if wrong: none.
- **Task 10. The "observed by time only" warning shows whenever the canary is on without an application check** (the
  location list carries no `skip_verify`). Cost if wrong: a warning also when every location verifies.
- **Task 11. `useOptionalStepUp`.** The deploy dialogs ask for a step-up only for "Deploy to all at once" and are also
  rendered outside the step-up provider (tests, older call sites); outside it the call goes as it is and the server's
  refusal is shown. Cost if wrong: none (the app shell provides the provider).
- **Task 11. The Key Vault dialog reads the vault's service from the vault as last read** (the query cache), the pattern
  `KVCertificatePage` already uses for permissions. Cost if wrong: no canary note when the vault was never read in the
  session (the server still makes the rollout).
- **Task 11. `canary.tls.none` reads "not checked yet"**, not "-" (i18n-check refuses a Turkish text equal to the
  English one); `canary.columns.http` and `.tls` are allow-listed as identical. Cost if wrong: a text.
- **CI fixes (run 40215904071).** The application check is an allowed `InsecureSkipVerify` site in both source guards
  (`tlsprobe`, `nginx`): it skips chain verification only to compare the served leaf with the deployed certificate in
  `VerifyConnection` (design §9.3). The backup round trip fills `deployment_rollouts` and `canary_checks`; the ACME
  backup test truncates with `CASCADE` (rollouts refer to ACME certificates, deployments to rollouts; the restore puts
  every table back); the e2e reset statement empties both tables; the serve test expects migration 35. Cost if wrong:
  none (tests only).
- **A restore keeps rollouts as they were.** A restored hold continues on the restored installation: its rounds run, and
  its wave 2 passes the licence gate like any deployment (`applyRolloutPlan`). Why: design silent; restore already holds
  jobs for the licence. Cost if wrong: a restored canary deploys its wave 2 after a restore (**owner to confirm**).
- **Commits of Tasks 5-11 were pushed in one push** (`c85c52a8`). Why: CI runs on the pushed tip only; intermediate
  commits group files by the earliest task that needs them (the web locales go with Task 10). Cost if wrong:
  intermediate commits are not individually green.
- **Task 12. The e2e journeys first put the certificate without its chain on s1..s3 (canary off), complete the stored
  chain and deploy it again from the UI.** Why: a certificate's page deploys only to websites that already use it (as
  `phase4.spec.ts` does); the new files are proven on the target by the chain length Nginx sends (1 before, 2 after),
  the leaf by its fingerprint. Rounds are driven by `advanceClock(16)` and `runScheduled('canary.advance')` inside
  `drainUntil`. Cost if wrong: none.
- **Task 13. `tools/matrixcheck` reads the `CAN` prefix** of §24.9, as R64 added `HB`
  (`TestSpecIDsFindCanaryRows`). Cost if wrong: none.
- **Task 13. SEC-110 is the next free requirement number** (SEC-109 was the last); the canary's STRIDE rows are a new
  `04-security.md` §14.4 block, and its accepted port item is KI-44. Cost if wrong: a renumber.

- **Integration fixes after the first full run.** A sign-in with MFA opens the 5-minute step-up window, so the API
  suite proves the refusal of Continue and of the override with a session whose sign-in is 6 minutes old; the generated
  GET-routes and scoped-IDOR suites plant one rollout (they refuse a route whose record or resolver kind no fixture
  provides). Cost if wrong: none (tests only).
- **Inventory coverage.** The person actions (`canary_api.go`) were proven only through the API package, which does not
  count for inventory's floor (89 %); inventory's own tests now cover them and the database-failure paths of every canary
  step (a trigger that raises, `TestCanaryStepsFailWhole` and siblings). Inventory ends at **89.0 %** (floor 89): no
  margin left for the next change (api 96.9 %, canaryjobs 95.1 %, deployjobs 99.2 %, httpcheck 97.8 %).
- **Task 12. A journey runs the advance once right after wave 1 holds**: the rollout starts its observation only on an
  advance (the e2e build never ticks the task). Cost if wrong: none.

## Final review fixes (R65)

Independent review of `917c568a` ("fix first"); each finding was fixed test first, one commit each.

- **C1. An automatic wave 1 larger than the planner's wave of 5, or with a website that stops being a candidate, no
  longer holds forever.** (a) Both planners count a holding deployment as busy for its website but not as in flight
  against `AutoDeployWave`: a hold is waiting, not working (`TestPlannersDeployAWaveOneLargerThanTheirWave`). (b) A
  rollout still in `wave1` whose wave-1 website has no deployment `CanaryWave1Limit` (1 hour) after its creation fails
  with `canary.wave1_incomplete` (ALC-DEP-0033, cause `wave1_incomplete`) and reverts its holds
  (`TestDecideRolloutFailsAWaveOneThatNeverCompletes`, `TestAWaveOneWebsiteThatStopsBeingACandidateFailsTheRollout`).
  Why: an age limit is one rule for every way a website can drop out (automatic deployment switched off, binding removed,
  a person deployed it, a lasting refusal), and it applies only while a website has no deployment, so a slow but
  started deployment is not cut short; a manual rollout inserts every wave-1 deployment at once and never meets it. Cost
  if wrong: an automatic first wave whose planner is slowed for more than an hour (a very large global batch) is put back
  and retried at the next renewal; the holds of a planner's wave count against no limit (at most 19).

- **C2. Wave 1 is capped at 19 websites (`authz.MaxCanaryWave1`) in `CanaryWaves`**, and the deploy dialogs' note counts
  the same way (`TestCanaryWavesCapWaveOne`, `CanaryChoice.test.ts`: 38 websites at 50 % give 19, 39 give 19, 200 at
  10 % give 19). Why: a Key Vault deploy takes up to 200 websites and the planners have no cap, so a percentage could ask
  for 20 or more and break the rollout table's CHECK (1..19), answering 500 to a person and failing every planner run;
  the cap keeps the CHECK of migration 00035 as shipped in this branch instead of relaxing it. Cost if wrong: a service
  that wants a larger first wave gets 19 (the admin guide says so).

- **I. An incident never releases a hold of a failed or aborted rollout.** `PreemptRolloutOf` decides through
  `preemptPlan`, which hands a failed or aborted rollout to `decideRollout` (the hold is reverted with the rollout's
  reason, as the next advance would) and releases holds only of a live rollout (then preempted) or a finished passing one
  (`TestPreemptPlan`, `TestPreemptionRevertsAHoldOfAFailedRollout`). Why: a website that was still sending when its
  rollout failed holds afterwards; an incident reaching it before the next advance recorded it `succeeded` with a
  certificate that failed its canary. Cost if wrong: none found; the incident then waits on the revert as on any busy
  place.

## Owner to confirm

- Every default of design §24 (rulings 1-29) and the plan's rulings 30-34, as written there.
- The coordinator rulings C1 (path, host and port at the location's address instead of a free URL) and C2 (unknown
  rounds never pass; ClassAlways).
- A restore keeps live rollouts (above).
- KI-44: an Administrator of a service can make Alice open a TLS connection to another port of a server it manages.

## Found, not fixed

- **Fixed test ports inside the ephemeral range.** `canaryjobs` (`45422`) and the Windows helper's fidelity tests
  (`cmd/alice-winhelper`, `45310`..`45399`, run on the Windows runner) listen on fixed `127.0.0.1` ports between 32768
  and 60999, Linux's ephemeral range (Windows': 49152-65535): an outgoing connection of another process can hold one,
  as `45428` did on CI. Fixed here only for `httpcheck`; the others are outside the
  canary scope (C5). Cost of leaving it: a rare flaky "address already in use".

