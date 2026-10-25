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

## Design defaults (design §24, rulings 1-29)

The 29 defaults of design §24 stand as written there (each with its reason), owner to confirm.

## Plan rulings (30-34)

Rulings 30-34 of the plan stand as written there, owner to confirm.

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
- **Task 4. Ports.** `httpcheck` tests use `127.0.0.1:45420`, `45421`, `45423`..`45431`; `canaryjobs` keeps `45422`
  (the plan's) and `45432`..`45439`. Cost if wrong: a renumber.
- **Task 4. Reasons by phase.** A failure before the TLS connection is up is `canary.unreachable`, after it
  `canary.protocol`; a body cut by the timeout (slow-loris) is `canary.timeout` with the status kept; a cancelled
  context is `canary.timeout`. Why: design §9.3 lists the reasons, not where each applies. Cost if wrong: a reason text.
- **Task 4. The `Host` header carries no port** (the server name, or the bracketed address). Why: design §9.3 makes
  `Host` the server name; Nginx and http.sys match host names without the port. Cost if wrong: a virtual host keyed on
  `host:port` would not match.

## Found, not fixed

(none yet)
