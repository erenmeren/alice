# Rulings: the continuity window of a licensed lock

Owner decision 2026-10-20: after a licensed lock begins, renewal and automatic deployment of certificates already
managed continue for 45 days ("continuity window"), then stop. Everything else stays as in lock before (no order,
certificate, target, import, upload, CSR, manual deploy, SSH key work or discovery started by a person). The evaluation
(`evaluation_expired`) gets no window. Spec: R44 in `docs/superpowers/specs/alice-v1/00-decisions.md`, §8.6 in
`02-architecture.md`, §16.1 in `04-security.md`, L-24 and L-27a to L-27c in `06-quality.md`, D6 in
`2026-09-29-alice-v1-design.md`; user text in `docs/licensing.md`.

## The design as built

- `license.ClassContinuity` ("continuity"), `license.ContinuityPeriod` = 45 days. `Evaluation.ContinuityEndsAt` =
  `LocksAt` + 45 days for a license, zero for the evaluation; `ContinuityDaysLeft` (rounded up) and `InContinuity()`
  while locked inside the window.
- `allowIn`: continuity is allowed wherever change is, and in a licensed lock whose window the evaluation found open.
  Unverified fails closed as before; lock-due for continuity is measured against `ContinuityEndsAt` (`LocksAt` for the
  evaluation). An evaluation that found the window ended (or an ended evaluation) is a confirmed `ErrLocked`.
- Job types of class continuity: `acme.renew`, `certificate.deploy_auto`, `kv.poll`, and the periodic
  `acme.schedule`, `acme.auto_deploy`, `kv.schedule`, `kv.auto_deploy` (a test pins the list). Migration `00019` adds
  the class to `jobs.class`.

## Rulings made during execution

1. **Separate job types, shared handlers and dedupe keys.** `acme.renew` runs the `acme.issue` handler and holds the
   same dedupe key (`acme.issue:<acme certificate id>`), so a certificate never has two orders' jobs; the planner's
   order (trigger `renewal`) gets `acme.renew`, every other order (first issuance, Renew now, test run: trigger
   `manual`) stays `acme.issue`. `certificate.deploy_auto` runs the `certificate.deploy` handler with the same
   `certificate.deploy:<deployment id>` key; `insertDeployment` chooses it for the planners' triggers (`acme_renewal`,
   `kv_renewal`), a person's deployment (trigger `manual`, including Key Vault Deploy now) stays `certificate.deploy`.
   The handler asks the gate for its own job's class (`orderRun.class`) before each publication and before finalize.
2. **The ACME sweep resumes an interrupted order under its order's class**: continuity for trigger `renewal`, change
   otherwise (`ACMEStaleOrder.Trigger`). `StaleACMEOrders` counts a live job of either type as holding the order.
3. **`kv.schedule` moves to continuity whole**, including the import sweep it also runs (`SweepImports`): that sweep
   only ends imports nothing else would end (Alice's own rows), so running it in the window is harmless.
4. **A Key Vault poll in the window records new certificates as it always does** (not contained: the reconcile
   pipeline stores listings, keys, secrets, missing marks and the vault's status in batches; filtering certificates
   Alice does not know yet would make a complete listing look incomplete and change the missing-mark logic). It is a
   read of a managed system and writes only Alice's inventory; nothing can deploy a new certificate in lock, since
   binding it to a website is a person's change (refused). The poll's hold rule asks the gate for **continuity**
   (`continuityClosedNow`), so a version renewed in Azure during the window is not held and the automatic deployment
   deploys it. Imports keep the change gate (`gateClosedNow`).
5. **After the window ends**, a queued continuity job is treated as its kind of work was before the window existed
   (`jobs.heldInLock`): one that changes something (`acme.renew`, `certificate.deploy_auto`) is held for an
   Administrator (`blocked_license`, audited `job.blocked_license`, run or discarded after a renewal under Waiting for
   an administrator, R29); the read-only one (`kv.poll`) is cancelled (`license.locked`) and queued again by
   `kv.schedule` once the gate allows it. Cancelling the poll matters: a held poll would keep its dedupe key
   (`kv.poll:<vault>`) and stop `kv.schedule` from queuing polls for that vault after the renewal. The same rule applies
   to a job claimed just before the end (`revert`). Consequences for half-finished work, all on existing paths:
   - a held renewal order's ACME order is abandoned by the ACME sweep after `StaleAfter` (a held job does not hold the
     order; nothing published, no failure counted); the confirmed job later finds its order ended and does nothing,
     and the planner orders again after the renewal;
   - an order running when the window ends asks the gate before its next publication or finalize and ends with
     `license.locked` (neutral: no failure, no backoff); what it published is cleaned up (`acme.cleanup` is
     ClassAlways);
   - a held automatic deployment stays `queued` (the deployment sweep leaves a never-sent deployment whose job is
     held); an Administrator runs or discards it after the renewal (discarded: `deployment.cancelled`, no failure
     email); a deployment already sending finishes or is recovered (`certificate.deploy_recover` is ClassAlways).
6. **The runner's claim** in a confirmed lock adds `continuity` to the claimed classes while `Allow(ClassContinuity)`
   is nil, and passes "the window ended" (a confirmed refusal of continuity) to the lock sweep; a lock-due or
   unverified answer for continuity leaves continuity work queued and decides nothing, as for changes.
7. **The renewal-reopening holds stay as they are.** After a renewal, the ACME planner holds a current certificate
   issued before the gate reopened with no deployment of it, and the Key Vault planner a version detected before
   then (`gateReopenedAt`). Certificates renewed and deployed in the window have deployments and are not held; one
   renewed in the window but not deployed by its end is held for an Administrator, which is the fail-safe answer.
8. **Upgrade.** Migration `00019` re-classes live `kv.poll` rows to continuity (the runner claims by the stored class;
   the payload MAC does not cover it). Queued `certificate.deploy` and `acme.issue` jobs the planners created before
   the upgrade keep class change: they were asked for under the old rules. The Down refuses (SQLSTATE `Z1008`, the
   repo's "cannot migrate down" code) while a live `acme.renew` or `certificate.deploy_auto` job exists (the payload MAC
   covers the type, so it cannot be renamed); otherwise it re-classes finished rows (`change` for the two types,
   `read_only` for the rest).
9. **Backup restore** holds the backup's unfinished `change` work and continuity work except `kv.poll`
   (`heldClass` in `internal/backup/restore.go`), as a confirmed lock does.
10. **No API route may declare continuity** (`register` panics); `gated()` counts the class so a route that did would
    still be refused by the guard. Confirming a held continuity job keeps the route class change (only after a
    renewal).
11. **Visibility.** `ContinuityEndsAt` is computed for every license, also before the lock (the grace email names it);
    `ContinuityDaysLeft` only in lock. Banners: `locked_continuity` (params `valid_until`, `continuity_ends_at`,
    `days_left`) inside the window, `locked` (params `valid_until`, `continuity_ended_at`) after it; the evaluation keeps
    `evaluation_ended`. The license detail API adds `continuity_ends_at` (null for the evaluation) and
    `continuity_days_left`. The License page shows the window's end in lock and says renewal stopped after it.
12. **Notices.** The lock notice (key `locked`, template `license.locked`) is due only inside the window and names its
    end (`continuity_ends_at`, `continuity_days_left`); a new notice (key `continuity_ended`, template
    `license.continuity_ended`) is due after it. As before only the current state's notice is sent (L-16), so after
    downtime spanning the whole window only the second is sent; its text stands on its own. An installation already
    locked past the window when it upgrades gets the second email once. Alice has no in-app inbox: "in-app" is the
    banner, the License page and the license history (notice `continuity_ended`, labelled in both languages).
13. **Expiry alert note.** The "license expired, renew to resume automatic deployment" note on expiry emails is left
    out inside the window, where automatic deployment still runs.
14. **Unchanged on purpose.** Switching unattended deployment on, releasing a held Key Vault version, Renew now, Deploy
    now, connecting websites and every ACME account action stay ClassChange (a person's request), refused in the
    window. Rotation, SSH key work and discovery are untouched.

## Not run / left for the owner

- The e2e journeys (`web/e2e`) were not run. `phase2.spec.ts` was updated for the new lock banner
  (`license-banner-locked_continuity`); other journeys that drive a lock past `LocksAt` with ACME or Key Vault
  automation may now see renewals and automatic deployments run in lock and need the clock moved past the window.
