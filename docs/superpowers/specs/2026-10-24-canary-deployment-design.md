# Canary deployment and application health check: design

Status: design, not built. Date: 2026-10-24. Written against `main` at `961f3bbb` (migrations up to `00032`). The
parallel "hardening batch 1" branch (R64) reserves migrations `00033` and `00034`, error codes `ALC-CRT-0020..0025`,
the package `internal/revocation`, the job type and settings key `revocation.check`, the e-mail templates `incident.*`
and `certificate.revoked_by_authority*`; this phase starts only after it is merged into `main`, takes migration
**`00035`** (and `00036` if a second one is needed; the next free number is confirmed at implementation time) and
decision **R65**. No name here collides with that branch's. Rulings file: `docs/superpowers/rulings/canary-deployment.md`.
Plan: `docs/superpowers/plans/2026-10-24-canary-deployment.md`.

The owner was away when this was written and told the coordinator to decide and record. Every open question is
answered by a numbered default with a one-line reason in §24 "Decisions taken by default"; the implementer records
each one again as a ruling marked "owner to confirm".

When accepted, R65 amends `alice-v1/00-decisions.md` (new entry), `alice-v1/02-architecture.md` (deployments state
machine, new table, new job types), `alice-v1/04-security.md` (new SEC row for the health check's egress, AC-8 for the
canary revert), `alice-v1/06-quality.md` (new subsection, test IDs `CAN-01..`), and the scoped RBAC design
`2026-10-21-scoped-rbac-and-service-ownership-design.md` §7.4 (the `canary` key leaves the reserved list).

## 1. Purpose and the why

An outside lifecycle review (2026-10-20) listed "canary deployment / application health checks" as the one lifecycle
item Alice does not address. Today a deployment to N websites queues N independent deployments at once
(`inventory.RequestDeployment`, `internal/inventory/deployments.go`): each is verified by the post-deploy TLS probe
(the provider verifies before it answers `committed`; R38 item 6, R51) and rolled back on its own if that probe fails.
That protects against "the server does not serve the new certificate". It does not protect against "the server serves
the new certificate and the application behind it breaks" (a client that pins the old intermediate, a backend that
re-validates mTLS with the new chain, a key type a load-balancer health monitor rejects), and when that happens it
happens on all N servers at once.

Canary deployment changes the shape of a multi-website deployment, when the service's policy asks for it: deploy to a
small subset first (wave 1), keep it under observation for a hold time (the TLS probe repeated, and optionally an HTTP
request to the application through the new certificate), and only then deploy to the rest (wave 2). If the
observation fails, wave 1 is put back exactly as the existing rollback does it, and wave 2 is never touched.

The scoped RBAC design reserved the hook: the service policy key `canary` ("deploy to a subset first") is refused
today with 422 `ALC-SVC-0015` (`authz.ReservedPolicyKeys`, `internal/authz/policy.go`).

## 2. Goals, non-goals, anti-goals

Goals:

- G1. A service policy can require canary deployment for every multi-website deployment whose key comes from that
  service: manual (a person's deploy, a Key Vault binding's or an ACME certificate's Deploy now) and automatic (the ACME
  and Key Vault planners).
- G2. Wave 2 starts only after every wave-1 deployment succeeded and verified, the hold elapsed, and the last check of
  every wave-1 website passed.
- G3. A failed check, a failed wave-1 deployment or a person's abort puts every wave-1 website back through the
  existing rollback path (the provider's `RollbackDeployment` of the deployment's own operation, the R48 rollback guard
  read again right before it) and touches nothing in wave 2.
- G4. One behaviour for every provider that deploys (Nginx and Windows today; Apache and HAProxy when they deploy, with
  no canary change).
- G5. An optional HTTP application check, through the new certificate, with the same address rule (SEC-065,
  `internal/platform/netaddr`) as every connection Alice opens to a managed server, the served leaf compared with the
  deployed one, no redirects, a body cap.
- G6. A person can see the waves, the hold countdown and the check results, and can continue early or abort, with
  rights on the service and (for continuing) a step-up.
- G7. Zero behaviour change while no policy enables `canary`.

Non-goals:

- Deployment windows (`windows` stays reserved), a post-deploy verification policy (`verification` stays reserved),
  per-service expiry thresholds (`thresholds`).
- More than two waves, progressive percentages (10 %, 50 %, 100 %), automatic promotion by metrics.
- Checking anything but HTTPS (no TCP-only probe, no gRPC, no response body matching).
- A canary for a single destination (there is nothing to protect), a drift repair (one location), a retry (one
  location) or a key-compromise incident's replacement (§6).
- Rolling back a deployment that already finished `succeeded` outside a canary (still "Left for later" from W2/W3).

Anti-goals (failure even if it technically works):

- A canary hold that lets a certificate expire on wave 2 while it waits (§15).
- A canary that can be used to make Alice send requests to hosts it does not manage (§20.1).
- A revert that re-installs a revoked or compromised certificate (R48 must hold on this path too).
- A second deployment engine: holds and reverts are states and rows of the existing one.
- A check that cannot run silently passing: an unknown result is never a pass (§9.5).

## 3. Vocabulary

- **Destinations**: the websites (certificate locations) one request or one planner decision names.
- **Rollout** (`deployment_rollouts`): one canary deployment of one certificate to its destinations, split into
  **wave 1** (the canary subset) and **wave 2** (the rest).
- **Holding**: the new deployment state of a wave-1 deployment whose send was committed and verified and which waits
  for the rollout's verdict. Its files hold the new certificate; it is not finished.
- **Round**: one observation of one holding deployment: the TLS baseline and, when configured, the HTTP check.
- **Release**: the rollout's verdict "wave 1 passed": every holding deployment finishes `succeeded`, wave 2 starts.
- **Revert**: the rollback of a holding deployment through the recovery path (§10); it ends `rolled_back` (or
  `rollback_failed` when the rollback could not put the files back).
- **Override**: a person's "deploy to all at once" for one request, bypassing the policy.
- **Source service**: the service whose key a deployment places: the certificate's own, the ACME certificate's for its
  deployments, the vault's for a Key Vault deployment (R49 §5.6; `deployCertificate.service`). Its policy decides.

## 4. What the existing engine gives us (and what this design relies on)

| Fact | Where | Used for |
|---|---|---|
| One `deployments` row and one `certificate.deploy` (or `certificate.deploy_auto`) job per location; up to 20 locations per request, all-or-nothing in one transaction | `inventory.RequestDeployment`, `insertDeployment` | wave 1 is a subset of those inserts; wave 2 is inserted later through the same `insertDeployment` |
| The provider verifies before it answers `committed`; a verification failure is rolled back inline | `deployjobs/deploy.go` decision table; `providers.DeployRequest` | wave-1 success already means "verified" (the baseline) |
| `deployments_one_active` (one unfinished deployment per location) | migration `00006` | a holding deployment keeps the location busy: no other deployment, drift repair or incident step can race the revert |
| A done row is frozen (`deployments_done_frozen`, Z1003) | migration `00006` | the hold must happen **before** done, hence the new state |
| Recovery restores a committed operation when its own verification failed; both helpers can undo a committed operation (`cmd/alice-helper` "to undo a committed one"; `winhelper/restore.go` handles `committed`) | `deployjobs/recover.go` | the revert is a recovery whose goal is "old certificate back" |
| The rollback guard (R48) is read right before every rollback | `inventory.RollbackGuard`, `recover.go` `rollback` | the revert inherits it unchanged |
| The helper keeps a committed operation's backup for 7 days; Windows keeps the previous certificate in the store while a deployment of the server is unfinished and for 7 days after (`CleanupKeptDeploymentRunning`, `CleanupRollbackWindow`) | `helperproto.NginxBackupKeep`, `inventory/windows_cleanup.go` | the hold maximum (24 h) is far below both |
| Jobs on one server never run concurrently (`target_locks`) | `jobs/runner.go` claim | a round's job on a server serializes with deploys and reverts there |
| Periodic decision tasks that ask the licence gate themselves | `incident.advance`, `acme.auto_deploy` | the `canary.advance` task follows `incident.advance` |
| The address rule of SEC-065 for every connection to a managed server (private and loopback allowed; link-local, metadata, multicast, unspecified, reserved refused; checked on the connected address, so DNS rebinding is covered) | `netaddr.DialContext` (used by `tlsverify`, `acme/transport`, `audit/forward`) | the HTTP check dials through it |
| Drift observation and drift repair skip a location with an unfinished deployment | `drift_observe.go:56`, `drift_repair.go:52` | no drift verdict during a hold |
| The deployment sweep only acts on `queued`/`precheck`/`deploying`/`recovering` and deleted servers | `inventory/sweep.go` `sweepWhere` | must be taught to leave `holding` to the canary (§8.4) |
| Apache and HAProxy providers are discovery only at `961f3bbb` (no `CapDeployCertificate`) | `internal/providers/apache`, `haproxy` | canary covers Nginx, Windows and the fake provider today, any future deploying provider without change |
| No metrics endpoint exists; observability is structured `slog`, audit rows and the jobs list | repository-wide | §18 |

## 5. The policy key `canary`

### 5.1 Schema

`canary` becomes a field of `authz.Policy` (schema stays 1: adding an optional field is not a breaking change, which is
why it was reserved) and leaves `authz.ReservedPolicyKeys` (which keeps `verification`, `drift`, `windows`,
`thresholds`).

```json
{
  "schema": 1,
  "canary": {
    "enabled": true,
    "subset": { "count": 1 },
    "first": ["<certificate_locations.id>", "..."],
    "hold": "10m",
    "interval": "30s",
    "failures": 2,
    "check": {
      "path": "/healthz",
      "host": "",
      "port": 0,
      "expect_status": [200],
      "timeout": "5s"
    },
    "override": "allowed"
  }
}
```

| Field | Values | Default | Meaning |
|---|---|---|---|
| `enabled` | bool | `false` | the canary applies; `false` keeps the stored settings without effect (the editor can switch it off and on) |
| `subset` | exactly one of `{"count": 1..10}` or `{"percent": 1..50}` | `{"count": 1}` | size of wave 1 (§7) |
| `first` | 0..20 location ids, distinct | `[]` | locations that go to wave 1 first when they are destinations (§7) |
| `hold` | duration `1m`..`24h` | `10m` | how long wave 1 is observed after its last deployment entered holding |
| `interval` | duration `15s`..`10m`, `<= hold` | `30s` | time between two rounds of one holding deployment |
| `failures` | 1..10 | `2` | consecutive failed rounds of one wave-1 website that fail the rollout |
| `check` | object or absent | absent | the optional HTTP application check (§9.3); absent = TLS baseline only |
| `check.path` | required inside `check`; starts with `/`, at most 512 bytes, RFC 3986 path and query characters only, no `#`, no control or space characters | — | the request target |
| `check.host` | DNS name (IDNA A-label, no wildcard, no IP literal, at most 253 bytes) or `""` | `""` | the TLS server name and `Host` header; `""` = the location's own name (§9.3) |
| `check.port` | 0 or 1..65535 | `0` | `0` = the location's port (§9.3) |
| `check.expect_status` | 1..10 distinct codes in 100..599 | `[200]` | the statuses that pass |
| `check.timeout` | duration `1s`..`10s`, `< interval` | `5s` | the whole request, connect to last body byte |
| `override` | `allowed` \| `forbidden` | `allowed` | whether a person may deploy to all at once (§13.1) |

Durations are a decimal number and one unit (`s`, `m`, `h`), regex `^[1-9][0-9]{0,4}(s|m|h)$`, stored normalized (the
largest unit that divides the value: `90s` stays `90s`, `120s` becomes `2m`). A Go duration with mixed units or
fractions is refused: the editor and the audit diff stay readable.

### 5.2 Validation and storage

- Parsed by `authz.ParsePolicy` with `DisallowUnknownFields` (an unknown sub-field is the generic 400 `ALC-SYS-0004`,
  as Phase 5 ruled for the other fields); out-of-range values are `validate.Errors` named `body.canary.<path>`
  (`body.canary.check.timeout`), 422 as the other policy fields.
- Cross-field rules: `interval <= hold`; `timeout < interval`; `subset` has exactly one member.
- `first`: each id must name a location of a live server **of this service** when the policy is saved (checked by
  `authz/services.Store.SetPolicy` in its transaction; `body.canary.first.<n>` with `validate.NotFound`). At use, ids
  that no longer exist or are not destinations are ignored.
- Normalization: defaults are **not** written into the document (absent means default, as the rest of the policy);
  `first` keeps its order; an `enabled: false` block with only defaults is dropped (so switching it off and saving
  leaves `{"schema":1}`).
- Who edits: `services.policy` (an Administrator of that service, step-up, never a token), as every policy field. No
  global-only part (unlike `domains`): a canary makes deployment safer, never wider.
- Versioning, history and the audit row (`service.policy_changed` with the changed top-level keys) are Phase 5's
  unchanged.

### 5.3 Snapshot at use

A rollout copies the effective canary settings (defaults filled in) and the policy version into its row when it is
created. A policy change during a rollout does not change it (Decision 9).

## 6. When the canary applies

The canary applies to a deployment request when **all** hold:

1. the source service's current policy has `canary.enabled: true`;
2. the request names **two or more** destinations (every one of them still passes the per-location checks
   (`checkDeployLocation`) or the whole request is refused, all-or-nothing as today);
3. the request is not an override (§13.1) and not exempt (table below);
4. the expiry guard passes (§15).

Otherwise the request deploys as today; when 1 holds but 4 does not, or the request was an override, the audit row says
why (`deployment.canary_skipped` with `reason` `expiry` / `override`).

| Deploy path | Code | Canary |
|---|---|---|
| A person's deploy (`POST /certificates/{id}/deploy`) | `RequestDeployment` | yes, override possible |
| ACME certificate Deploy now (`POST /acme/certificates/{id}/deploy`) | `acme_bindings.go` → `RequestDeployment` with `source` | yes, override possible |
| Key Vault binding Deploy now (`POST /bindings/{id}/actions/deploy`) | `RequestKVDeployment` | yes, override possible |
| ACME automatic deployment | `planACMEAutoDeploy` / `prepareACMEDeployment` | yes, never overridden (§12) |
| Key Vault automatic deployment | `planAutoDeploy` / `planBinding` | yes, never overridden (§12) |
| Key-compromise incident replacement | `requestIncidentDeployment` (`in.incident`) | **no**: replacing a compromised key must not wait (Decision 5) |
| Drift repair (manual and automatic) | `drift_repair.go` | **no**: one location |
| Retry of a failed deployment (`trigger retry`) | — | **no**: one location |

## 7. Waves and the subset

For destinations D (n = |D| >= 2), in this order:

1. order: the ids of `first` that are in D, in the policy's order; then the rest of D sorted by location id ascending
   (byte order of the UUID; the ids are UUIDv7, so this is roughly "oldest location first", stable across runs and
   processes);
2. k = `count` → min(count, n − 1); `percent` → clamp(ceil(n × percent / 100), 1, n − 1). Wave 2 is never empty;
3. wave 1 = the first k of the order, wave 2 = the rest (kept in the order).

The function is pure (`inventory.canaryWaves(dests []uuid.UUID, p authz.CanaryPolicy) (wave1, wave2 []uuid.UUID)`) and
table-tested. Wave membership is fixed at rollout creation (stored in the rollout row).

## 8. The engine: the `holding` state

### 8.1 State machine additions

```
precheck -> deploying -> (provider answers committed AND verified, deployment is wave 1 of a rollout)
                      -> holding [running]                    enterHold: every final value of a success except
                                                              state/status/finished_at; deployment.holding
holding  -> done [succeeded]                                  ReleaseHold (canary.advance on the rollout's release,
                                                              an incident's preemption, a deleted server): the
                                                              stored values, the location update a success does
holding  -> recovering [running] (revert_reason set)          RequestRevert (canary.advance on failure or abort):
                                                              recover_after = now, a certificate.deploy_recover job
recovering (revert) -> done [rolled_back | rollback_failed]   the recovery path, revert row of §10
                    -> recovering                             uncertain: paced like any recovery
```

Rules:

- **Which deployments hold.** A deployment with `rollout_id` set and `wave = 1` whose outcome maps to `succeeded`
  (`committed`, verified) enters `holding` instead of `done`. **Always**, whatever the rollout's state at that instant:
  the engine never reads the rollout (no lock order with it, §20.3); `canary.advance` decides what happens to every
  holding deployment. An outcome `unchanged` (the files already held the pair) finishes `done unchanged` as today: there
  is nothing to revert, and the location already served the certificate before the canary (Decision 7).
- **Where.** In `finishLocked` (`deployment_records.go`): the same allowed-from check, the same verified rule, the same
  UPDATE minus `state = 'done'`, `finished_at`; it writes `state = 'holding'`, `status = 'running'`,
  `held_cert_file_sha256` (the hash `CertFileSHA256` a success would write to the location), and does **not** update
  the location (§8.3). Audit `deployment.holding`; no e-mail. It inserts the deployment's `canary_checks` row with
  `next_check_at = now`.
- **Release.** `ReleaseHold(tx, id, cause)` runs `finishLocked(succeeded)` from `holding` with the stored values
  (result, phase, verified, trust, `held_cert_file_sha256` as the file hash): the location update, the
  `deployment.succeeded` audit row and every side effect of a success happen then. `allowedFrom(succeeded)` already
  accepts a sent row; the new state is added to "sent" (`sent(state)`).
- **Revert.** `RequestRevert(tx, id, reason)` moves `holding` to `recovering` with `revert_reason = reason`,
  `error_code = reason`, `recover_after = now`, and queues a recovery job (`requestRecoveryLocked`, dedupe
  `certificate.deploy_recover:<id>`), in one transaction with audit `deployment.revert_requested`. Refused
  (`ErrDeploymentState`) from any other state.

### 8.2 The job handlers

- `deployjobs.follow`: `holding` is a state "a send happened and was verified": the deploy job returns success
  `{outcome: "holding"}` (a re-run after a crash never re-sends, never recovers). `resultOf` maps `holding` to a
  success result.
- `deployjobs.recoverJob`: `holding` without `revert_reason` → success `{outcome: "holding"}`, nothing recorded (the
  canary owns it). `recovering` with `revert_reason` → `recoverDeployment` with the revert rows of §10.

### 8.3 Why the location is not updated while holding

The location's `certificate_id`, `deployed_fingerprint` and `cert_file_sha256` are what the next deployment's
pre-check and compare-and-swap expect, and what a rollback does not touch (a `rolled_back` finish leaves the location as
it was). Writing them at hold entry would make a reverted location claim the new certificate. During the hold no other
deployment can start there (`deployments_one_active`); discovery treats an unfinished deployment as an open outcome
(`aliceFingerprints`, `locations.go`); drift skips it. So the location is updated once, at release, exactly as a
success does today.

### 8.4 Sweep, deleted servers, discovery

- `sweepWhere` excludes `holding` explicitly (a holding row has an operation id and would otherwise be handed to a
  recovery after `recover_after`, or ended `rollback_failed` on a deleted server).
- A holding deployment whose server was deleted is released (`ReleaseHold`, cause `target_deleted`: it was verified,
  the row stays truthful) by `canary.advance`, which then treats the location as gone from wave 1 (§11).
- `CheckRecoveryPending` is unchanged (only `recovering` blocks the server). A revert is `recovering`, so a deployment
  requested on the same server waits for it, as for any recovery.

## 9. Hold and checks

### 9.1 Timeline

1. Wave-1 deployments run as usual. Each one that succeeds enters `holding` and starts its rounds at once.
2. **Hold start** = the moment the last wave-1 deployment finished or entered holding with no wave-1 deployment
   failed: `hold_started_at = now`, `hold_until = now + hold`.
3. Rounds continue every `interval` per holding deployment until the rollout's verdict.
4. **Release** when `now >= hold_until`, every holding deployment's last round passed and was taken at or after
   `hold_started_at`, and no failure threshold was reached.
5. **Fail** as soon as one holding deployment has `failures` consecutive failed rounds, any wave-1 deployment ends
   `failed` / `rolled_back` / `rollback_failed`, the deployed certificate is marked revoked or compromised, or the
   checks are unavailable past the grace (§9.5).

### 9.2 The TLS baseline (every round)

The provider's own `VerifyDeployment` with the deployment's `VerifyRequest` (`Material.VerifyRequest()`: the recorded
fingerprint and chain length, the location's verification settings, the R51 trust policy), exactly the probe the
deployment passed when it was sent. It fails when the new leaf is no longer served, the chain length changed, or (when
the trust policy is enforced) the chain no longer verifies; reason codes are the provider's (`deployment.verify_*`).
A location whose verification is skipped (`skip_verify`) has a baseline of `skipped` (neither pass nor fail; the HTTP
check, if configured, decides; with neither, the hold is time only and the editor warns, §19).

### 9.3 The HTTP application check (optional)

One HTTPS `GET` per round per holding deployment, from Alice:

| Part | Value |
|---|---|
| Address dialed | the location's verification address (`certificate_locations.verify_address`, R59 G4) if set, else the server's `targets.host`; **never** `check.host` |
| Port | `check.port`, else the location's verification port (`VerifyOptions.Port`), else the first SSL listen port of the location's servers (`CertServer.Listens`), else 443 |
| TLS server name and `Host` header | `check.host`, else the location's verification SNI (`VerifyOptions.SNI`), else `tlsverify.SNIFor(location names, certificate SANs)` (the name the post-deploy probe sends); "" (no SNI) when none is usable, then `Host` is the dialed address |
| Dial | `netaddr.DialContext` with a `net.Dialer{Timeout: min(timeout, 5s)}`: the SEC-065 rule on the connected address |
| TLS | `InsecureSkipVerify: true` with the leaf compared after the handshake: the served leaf's SHA-256 must equal the deployment's `new_fingerprint` (else `canary.served_other`, the request is not sent). Chain trust is the baseline's job. TLS 1.2 minimum. |
| HTTP | HTTP/1.1, method `GET`, `User-Agent: Alice-canary/<version>`, `Accept: */*`, no cookies, no `Authorization`, `Connection: close` (keep-alives off), proxy **off** (environment proxies ignored: the destination is a managed server, Decision 13) |
| Redirects | never followed (`CheckRedirect` returns `http.ErrUseLastResponse`); a 3xx passes only when listed in `expect_status` |
| Response | status compared with `expect_status`; headers capped at 16 KiB (`MaxResponseHeaderBytes`); body read and discarded up to 64 KiB, then the connection is closed (a larger body is not an error); body content is never stored or logged |
| Timeout | `check.timeout` for the whole request |
| Result | `{ok, reason, http_status, latency_ms, served_sha256}`; reasons: `canary.http_status` (param `status`), `canary.served_other`, `canary.unreachable` (dial or handshake failed), `canary.not_allowed` (the address rule refused: `netaddr.ErrNotAllowed`), `canary.timeout`, `canary.protocol` (malformed response) |

It lives in a new pure-ish package `internal/providers/httpcheck` (imports only `internal/platform/netaddr` and
`internal/platform/clock`; archtest rule like `tlsverify`'s), with a `Checker` interface so the job can be tested with
a fake.

**Windows binding vs Nginx/Apache/HAProxy location: no difference.** The check reads only location-level fields every
location kind has (verification address, port, SNI, server names and listens, from discovery) and the server's host.
The baseline is each provider's own `VerifyDeployment`, which already builds the endpoints its way (Nginx server blocks,
http.sys bindings: `tlsverify.Verify` underneath both). An http.sys `ipport` binding without a host name gets no SNI and
`Host` = the dialed address; a `hostnameport` binding gets its host name, as the post-deploy probe does. Nothing in the
canary code switches on the provider or the location kind.

### 9.4 Rounds as jobs

- `canary.check` (new job type, **ClassAlways**: it only reads managed systems and protects production, so it runs in
  every licence state like recovery), one job per holding deployment per round, `TargetID` = the deployment's server
  (so it serializes with deploys and reverts on that server), dedupe `canary.check:<deployment id>`, one attempt, never
  a dead-job e-mail (`MaxAttemptsFor` 1, `AlertsWhenExhausted` false).
- The handler (`internal/jobs/canaryjobs`) reads the deployment (must be `holding`; otherwise it records nothing),
  opens a session (the target checks of every connecting job: host key, disabled, deleted), runs the baseline, runs the
  HTTP check, and records the round with `RecordCanaryRound(deployment, result)`, fenced to its claim.
- `canary.advance` queues the job when `canary_checks.next_check_at <= now` and no live job holds the dedupe key; the
  record sets `next_check_at = now + interval`.

### 9.5 Pass, fail, unknown

A round is:

- **fail** when the baseline fails or the HTTP check fails;
- **unknown** when the session could not be opened, the job failed or timed out, or the provider returned an error
  rather than a result (and nothing failed);
- **pass** otherwise: the baseline passed or was skipped, and the HTTP check passed or is not configured (a location
  that skips verification and has no HTTP check is therefore observed by time only; the editor warns, §19). Unknown never counts as a pass and
never as a failure; it resets nothing. If at `hold_until + grace` (grace = max(2 × interval, 5 min)) some holding
deployment has no pass taken after `hold_started_at`, or its last round is unknown, the rollout **fails closed** with
`canary.check_unavailable` (Decision 11).

## 10. The revert (existing rollback path)

A revert is a recovery whose goal is "the previous certificate back". `recover.go`'s decision table gains the rows for
a deployment with `revert_reason` set:

| Journal (DeploymentStatus of the recorded operation) | Today | With `revert_reason` |
|---|---|---|
| `committed`, VerifyDeployment of the new certificate OK | succeeded | **rollback**, cause = `revert_reason` |
| `committed`, verification fails | rollback | rollback, cause = `revert_reason` (the verification failure recorded as today) |
| `unchanged` | unchanged / failed | cannot happen (unchanged never holds); if seen: `rollback_failed deployment.outcome_unknown` (defensive, tested) |
| `restored` (an earlier revert's restore finished, its record lost) | rollback | rollback (the helper answers it as done) |
| `restoring`, `restore_failed`, `restore_forbidden`, active, fenced, none/prepared | as today | as today |

`rollback` is the existing function: `RollbackDeployment` with the recorded previous fingerprint and chain length and
**the R48 guard read right before it**; mapped by `RollbackOutcomeRecord` with the cause. So:

- files back, old certificate verified → `done rolled_back`, `error_code = revert_reason` (`deployment.canary_check_failed`,
  `deployment.canary_aborted` or `deployment.canary_wave_failed`); the existing `deployment.failed` e-mail with the
  reason's title;
- the guard refuses (the previous certificate is now revoked or compromised) → `rollback_failed
  deployment.rollback_forbidden`, nothing restored, the website keeps the new certificate (security first, R48 G4);
- superseded, file changed, restore failed, uncertain → as today (recovery pacing, attention after
  `RecoveryAttentionAfter`, `rollback_failed` after `MaxRecoveryAttempts`).

The revert never needs the private key (`DeploymentMaterial(id, false)`) and never re-sends. For a Windows binding the
provider's `restore` re-points the binding to the previous thumbprint from the recorded `Backup` (W2 Ruling 17); the
previous certificate is still in the store because the cleanup keeps every certificate an unfinished deployment of the
server names (`CleanupKeptDeploymentRunning`) and for `CleanupRollbackWindow` after.

## 11. The rollout state machine

```
             (request or planner creates it, wave-1 deployments inserted in the same transaction)
                                   |
                                 wave1 ----------------------------------------------+
                                   | every wave-1 deployment holding or unchanged,   |
                                   | none failed                                     |
                                   v                                                 |
                                  hold --------------------------------------------- +--> failed  (revert every holding
                                   | now >= hold_until, last rounds pass             |             wave-1 deployment)
                                   | (or a person's continue)                        +--> aborted (person; revert)
                                   v                                                 +--> preempted (incident; release)
                  manual: wave2 (wave-2 deployments inserted if the gate allows)
                          | every wave-2 deployment done          \ gate refused (confirmed lock)
                          v                                        v
                       completed                                stopped (wave 1 released, no wave 2, e-mail)
                  automatic: completed at release (the planner deploys the rest under its own rules)
```

| State | Meaning | Left by |
|---|---|---|
| `wave1` | wave-1 deployments queued or running | all holding/unchanged → `hold`; a wave-1 deployment failed → `failed` (`canary.wave1_failed`); abort → `aborted`; revoked → `failed` (`canary.certificate_revoked`); incident → `preempted`; every wave-1 location gone → `failed` (`canary.wave_gone`) |
| `hold` | observing | release (auto or continue) → `wave2`/`completed`; failure → `failed` (`canary.check_failed`, `canary.check_unavailable`, `canary.certificate_revoked`); abort; incident |
| `wave2` | manual only: wave-2 deployments queued or running | all done → `completed` |
| `completed` | final | — |
| `failed`, `aborted` | final; every wave-1 deployment that was or becomes holding is reverted | — (a holding deployment of a final failed/aborted rollout is reverted by the next advance, which is how a wave-1 deployment that was still sending at the verdict is handled) |
| `stopped` | final; manual, wave 1 released, wave 2 not started (licence) | — |
| `preempted` | final; every holding deployment of the rollout whose deployed certificate is not revoked or compromised was released, no wave 2 (an automatic source then plans as after `completed`) | — |

Every transition takes the rollout row `FOR UPDATE` first (lock order §20.3), is one transaction with its audit row,
and is idempotent (a second advance finds the state already moved).

Wave 2 (manual): inserted by `canary.advance` through `insertDeployment` with trigger `manual`, `requested_by` the
original requester, audit actor the system (`jobs`), `rollout_id`, `wave = 2`, after `checkDeployLocation` again per
location (the server's readiness, trust (R49 §5.7: structural re-check), in-progress, key type...). A refused location
is recorded in the rollout's `skipped` list with its reason and audited `deployment.denied` (actor system); the others
are inserted. Wave-2 deployments are ordinary: no hold, no revert.

## 12. Automatic deployments (ACME and Key Vault planners)

Automatic deployments always follow the policy (no override). The planners stay the deciders; the rollout adds one
rule to each pure plan function (`planACMEAutoDeploy`, `planAutoDeploy`) through a new snapshot field:

- The **destinations** are the bound locations that need the current certificate (automatic deployment on for the
  binding, trusted (R49), not serving it and not having got it). With the policy enabled, two or more destinations, the
  expiry guard passing, and **no rollout** for (source, certificate) other than `failed`/`aborted` ones → the plan says
  "create rollout" with the waves of §7 and deploys wave 1 only (within the run's budget; a wave larger than the budget
  is completed by later runs).
- While the rollout is `wave1` or `hold`: only wave-1 locations not yet attempted are candidates; nothing else of that
  certificate is deployed. Wave-1 failures are not retried (the rollout fails).
- Rollout `failed` or `aborted`: `canary.advance` sets the existing stop mark (`acme_certificates.deploy_stopped_certificate_id`,
  `bindings.stopped_version`) in the same transaction, with the existing stop audit row and stop notice e-mail,
  `error_reason` = the rollout's reason (`deployment.canary_check_failed` ...). An Administrator's existing re-arm
  starts a new rollout (a failed one does not block a new one).
- Rollout `completed`, `preempted` or `stopped`: the planner plans as today over the remaining destinations
  (`AutoDeployWave`, retries, three-failures stop); no new rollout is made for that certificate (the unique index below
  keeps the finished one as the key's rollout).
- A rollout for an automatic source is keyed by (`acme_certificate_id`, `certificate_id`) or (`binding_id`,
  `kv_version_id`); a partial unique index admits one rollout per key that is not `failed` or `aborted`.
- **Reservation (a person's rollout and the planners).** While any rollout of any origin is in `wave1` or `hold`, its
  wave-1 and wave-2 locations are **reserved**: both planners leave them out of their candidates (no deployment, no
  attention mark, nothing counted), so a person's ACME or Key Vault Deploy now, or a plain deploy of the same
  certificate to bound locations, is never overtaken by the planner during the hold. The planners read the reserved set
  in their snapshot (one indexed query over `deployment_rollouts_active`).
- **A person's rollout that fails or is aborted** sets the same stop mark as an automatic one when the certificate is
  the current certificate of an ACME certificate with a binding at one of the rollout's locations, or the leaf of the
  version a Key Vault binding with one of the rollout's locations would deploy (the planner would otherwise roll the
  same certificate out again within the hour); the existing re-arm clears it.
- A Deploy now rollout has `origin manual` (a person asked) and records its source link (`acme_certificate_id` or
  `binding_id` + `kv_version_id`); `origin acme`/`key_vault` is only the planners'. Manual rollouts are outside the
  unique indexes.

The precheck of a queued automatic deployment (`acmeDeployPrecheck`, `KVDeployPrecheck`) is unchanged. The wave-1
deployments run as `certificate.deploy_auto` (ClassContinuity) as today.

## 13. People: override, continue, abort

### 13.1 Override ("deploy to all at once")

- Body field `canary_override: true` on `POST /certificates/{id}/deploy`, `POST /acme/certificates/{id}/deploy`,
  `POST /bindings/{id}/actions/deploy` (accepted, ignored, when no canary would apply).
- Needs, on top of the route's permission: a **browser session with a fresh step-up** (always; `strictActionFor(...,
  rbac.SessionStepUp)` on the path resource's service), so an API token can never bypass a canary (Decision 3); and the
  policy's `override: allowed`, else 422 `ALC-SVC-0020` `service.canary_override_forbidden`.
- Audited `deployment.canary_overridden` (actor the person, details: certificate, location ids, policy version), in
  the request's transaction; the deployments are ordinary.

### 13.2 Continue now

`POST /api/v1/deployment-rollouts/{id}/actions/continue`: allowed in `hold` (or `wave1` once every wave-1 deployment is
holding or unchanged) when every holding deployment's last round passed. Needs `certificates.operate` on the source
service (route), `certificates.operate` on every wave-2 location's service (design R49 §5.6 (b), `checkDestinationsOf`),
and a fresh step-up (it bypasses the remaining safety). Licence class ClassChange. Audited `deployment.rollout_continued`
with the remaining hold. Then the release of §11 runs in the same request.

### 13.3 Abort

`POST /api/v1/deployment-rollouts/{id}/actions/abort`: allowed in `wave1` and `hold`. Needs `certificates.operate` on
the source service; no step-up (it is a safety action, like a recovery). Licence class **ClassAlways** (a rollback must
be possible in lock). Audited `deployment.rollout_aborted`. Reverts every holding wave-1 deployment
(`deployment.canary_aborted`); wave-1 deployments still queued are ended `failed deployment.canary_aborted` (they never
sent: `FinishDeployment(failed)` from queued/precheck; a running deploy job finds the row done and stops, the existing
`follow` rule) and sending ones revert once they hold. In `wave2` and later: 409 `ALC-DEP-0034`.

## 14. Licence and the continuity window

- Deployment stays **ClassChange** for a person's request (refused in lock as today) and **ClassContinuity** for the
  planners' deployments. A rollout is not a licence operation of its own: there is no operation counter in
  `internal/license`; the hold, the rounds and the revert consume nothing.
- `canary.advance` is **ClassAlways** (it decides and reverts, like `incident.advance`); `canary.check` is
  **ClassAlways**; a revert is a `certificate.deploy_recover` job (ClassAlways). So a rollout in flight when the licence
  locks still observes and still reverts.
- Wave 2 asks the gate for the class of the rollout's deployments at the moment it would insert them: a manual rollout
  asks ClassChange, an automatic one ClassContinuity (through the planner, which asks it already):
  - allowed → wave 2 proceeds ("finishes its wave 2 if the continuity rules allow deployment");
  - confirmed refusal (`license.ErrLocked`) → manual: wave 1 is released (it passed), the rollout ends `stopped`
    (`license.locked`), audit `deployment.rollout_stopped`, e-mail `deployment.rollout_stopped` to the deployment
    e-mail recipients (R49 §7.2), listing the wave-2 websites; the person deploys them after the renewal. Automatic:
    the rollout completes at release as always and the planner's own gate pauses the rest (its existing held-licence
    rules and notices apply);
  - `ErrLockDue` / `ErrUnverified` (transient) → wait; the next advance asks again; after 1 h of transient answers the
    rollout ends `stopped` as above (Decision 16).
- `POST .../continue` is ClassChange (refused in lock); `POST .../abort` is ClassAlways.

## 15. The expiry guard

A canary must never let a certificate expire while wave 2 waits, nor revert wave 1 to an expired certificate. At
rollout creation, for every destination whose location currently holds a known certificate
(`certificate_locations.certificate_id`), if `not_after < now + hold + 24 h` the canary is **skipped** for the whole
request (all destinations deploy at once), audited `deployment.canary_skipped` reason `expiry` with the earliest
`not_after` and the location (Decision 6). The 24 h margin covers wave 2's own pace (automatic: 5 at a time, hourly
retries) and the grace of §9.5. A location with an unknown current certificate does not trigger the guard. The hold
cannot grow after creation (continue only shortens it; the grace is at most 10 min), so the guard need not be
re-evaluated during the hold; `canary.advance` asserts it and releases early (audited `reason expiry`) should a clock
jump make it false.

## 16. Persistence (migration `00035`, confirmed at implementation time)

Minimal schema: one rollout table, one per-deployment observation table, four deployment columns, one widened CHECK.

```sql
CREATE TABLE deployment_rollouts (
    id                  uuid PRIMARY KEY,
    certificate_id      uuid NOT NULL REFERENCES certificates (id),
    service_id          uuid REFERENCES services (id) ON DELETE SET NULL,   -- the source service whose policy applied
    policy_version      integer NOT NULL CHECK (policy_version >= 1),
    settings            jsonb NOT NULL CHECK (jsonb_typeof(settings) = 'object' AND octet_length(settings::text) <= 8192),
    origin              text NOT NULL CHECK (origin IN ('manual', 'acme', 'key_vault')),
    acme_certificate_id uuid REFERENCES acme_certificates (id),
    binding_id          uuid REFERENCES bindings (id) ON DELETE SET NULL,
    kv_version_id       uuid REFERENCES kv_certificate_versions (id),
    requested_by        uuid REFERENCES users (id),
    state               text NOT NULL CHECK (state IN ('wave1', 'hold', 'wave2', 'completed', 'failed', 'aborted', 'stopped', 'preempted')),
    reason              text NOT NULL DEFAULT '' CHECK (reason ~ '^[A-Za-z0-9._-]{0,100}$'),
    reason_params       jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(reason_params) = 'object' AND octet_length(reason_params::text) <= 4096),
    wave1_location_ids  uuid[] NOT NULL CHECK (cardinality(wave1_location_ids) BETWEEN 1 AND 19),
    wave2_location_ids  uuid[] NOT NULL CHECK (cardinality(wave2_location_ids) >= 1),
    skipped             jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(skipped) = 'array' AND octet_length(skipped::text) <= 8192),
    hold_started_at     timestamptz,
    hold_until          timestamptz,
    gate_waiting_since  timestamptz,
    created_at          timestamptz NOT NULL,
    finished_at         timestamptz,
    version             integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    CHECK ((state IN ('completed', 'failed', 'aborted', 'stopped', 'preempted')) = (finished_at IS NOT NULL)),
    CHECK (origin <> 'acme' OR acme_certificate_id IS NOT NULL),
    CHECK (origin <> 'key_vault' OR (binding_id IS NOT NULL AND kv_version_id IS NOT NULL)),
    CHECK (acme_certificate_id IS NULL OR kv_version_id IS NULL)
);
CREATE INDEX deployment_rollouts_active ON deployment_rollouts (created_at, id) WHERE finished_at IS NULL;
CREATE INDEX deployment_rollouts_certificate ON deployment_rollouts (certificate_id, created_at DESC);
CREATE UNIQUE INDEX deployment_rollouts_one_acme ON deployment_rollouts (acme_certificate_id, certificate_id)
    WHERE origin = 'acme' AND state NOT IN ('failed', 'aborted');
CREATE UNIQUE INDEX deployment_rollouts_one_kv ON deployment_rollouts (binding_id, kv_version_id)
    WHERE origin = 'key_vault' AND state NOT IN ('failed', 'aborted');

-- The observation of one holding wave-1 deployment (one row, rewritten per round).
CREATE TABLE canary_checks (
    deployment_id         uuid PRIMARY KEY REFERENCES deployments (id) ON DELETE CASCADE,
    rollout_id            uuid NOT NULL REFERENCES deployment_rollouts (id) ON DELETE CASCADE,
    rounds                integer NOT NULL DEFAULT 0 CHECK (rounds >= 0),
    passes                integer NOT NULL DEFAULT 0 CHECK (passes >= 0),
    consecutive_failures  integer NOT NULL DEFAULT 0 CHECK (consecutive_failures >= 0),
    next_check_at         timestamptz NOT NULL,
    last_at               timestamptz,
    last_result           text NOT NULL DEFAULT '' CHECK (last_result IN ('', 'pass', 'fail', 'unknown')),
    last_reason           text NOT NULL DEFAULT '' CHECK (last_reason ~ '^[A-Za-z0-9._-]{0,100}$'),
    last_tls              text NOT NULL DEFAULT '' CHECK (last_tls IN ('', 'pass', 'fail', 'skipped', 'unknown')),
    last_http_status      integer CHECK (last_http_status BETWEEN 100 AND 599),
    last_latency_ms       integer CHECK (last_latency_ms >= 0),
    last_pass_at          timestamptz,
    first_failure         jsonb CHECK (first_failure IS NULL OR (jsonb_typeof(first_failure) = 'object' AND octet_length(first_failure::text) <= 2048))
);
CREATE INDEX canary_checks_due ON canary_checks (next_check_at);

ALTER TABLE deployments
    ADD COLUMN rollout_id uuid REFERENCES deployment_rollouts (id),
    ADD COLUMN wave smallint CHECK (wave IN (1, 2)),
    ADD COLUMN held_cert_file_sha256 text NOT NULL DEFAULT '' CHECK (held_cert_file_sha256 ~ '^([0-9a-f]{64})?$'),
    ADD COLUMN revert_reason text NOT NULL DEFAULT '' CHECK (revert_reason ~ '^[A-Za-z0-9._-]{0,100}$'),
    ADD CONSTRAINT deployments_wave_rollout CHECK ((rollout_id IS NULL) = (wave IS NULL)),
    ADD CONSTRAINT deployments_holding_wave1 CHECK (state <> 'holding' OR (wave = 1 AND status = 'running'));
-- state CHECK widened with 'holding' (drop and re-add deployments_state_check; existing rows hold).
CREATE INDEX deployments_rollout ON deployments (rollout_id, wave) WHERE rollout_id IS NOT NULL;
```

- `deployments_done_frozen` is unchanged (every new column is written before or with the update that sets done).
- `deployments_one_active` is unchanged (`holding` is not `done`).
- Grants for `alice_app` in the house pattern: SELECT, INSERT on both new tables and column-level UPDATE on the columns
  the application writes (`deployment_rollouts` state, reason, reason_params, skipped, hold_started_at, hold_until,
  gate_waiting_since, finished_at, version; every `canary_checks` column but the keys); on `deployments`
  `GRANT UPDATE (held_cert_file_sha256, revert_reason)` (as `00023` and `00025` do; `rollout_id` and `wave` are written
  at insert only). No DELETE (a `canary_checks` row goes only with its deployment's cascade).
- Down: refuses (RAISE, a new SQLSTATE in the Z10xx series at the next free number) while a rollout is unfinished or a
  deployment is `holding`, or a deployment row has `rollout_id` (history would be lost silently: the down is for an
  installation that never used the feature); otherwise drops everything added and restores the CHECK.
- `migrations/frozen_test.go` gains the migration; `TestMigrationNNNNCanary` (up on a populated fixture: every row
  unchanged; down refused with a rollout; down works without one).

Why not columns on `deployments` only: the rollout has state of its own (hold times, waves, skipped, the policy
snapshot) that no single deployment owns, and wave-2 deployments do not exist before the release.

## 17. API

### 17.1 Routes

| Method | Path | Permission | Scope | Lock class |
|---|---|---|---|---|
| GET | `/api/v1/deployment-rollouts/{id}` | `read` | resource: new kind `rollout` (owning = source service; visible-from = the services of its locations' servers ∪ the certificate's service, as a deployment) | — |
| POST | `/api/v1/deployment-rollouts/{id}/actions/continue` | `certificates.operate` (+ step-up, + destinations) | cross | change |
| POST | `/api/v1/deployment-rollouts/{id}/actions/abort` | `certificates.operate` | resource: rollout | always |

Changed:

- `GET /api/v1/deployments` gains the filter `rollout_id`.
- `POST /certificates/{id}/deploy`, `POST /acme/certificates/{id}/deploy`, `POST /bindings/{id}/actions/deploy` accept
  `canary_override` (bool). Their 202 answer gains `rollout` (`null`, or `{id, state, wave1: [location ids], wave2:
  [location ids], settings}`); `deployments` lists the deployments created now (wave 1 only for a rollout).
- `GET /api/v1/certificate-locations` gains the filter `service_id` (repeatable; the policy editor's `first` picker
  needs it; R49 §15 listed the missing filter as a gap).
- Every deployment DTO gains `rollout`: `null` or `{id, wave, state}`; the detail DTO also `canary` for a wave-1
  deployment: the `canary_checks` row (`rounds`, `passes`, `consecutive_failures`, `last_at`, `last_result`,
  `last_reason`, `last_tls`, `last_http_status`, `last_latency_ms`, `next_check_at`).
- Rollout DTO: `id, state, reason, reason_params, origin, certificate {id, name}, service {id, name}|{outside},
  policy_version, settings, hold_started_at, hold_until, now` (the server's clock, for the countdown, because the
  e2e build moves it), `waves: [{wave, locations: [{location_id, target_id, target_name, site, deployment_id|null,
  deployment_state|null, deployment_status|null, canary|null}]}]`, `skipped: [{location_id, reason}]`,
  `allowed_actions: ["continue", "abort"]` (computed from state and the caller's rights, step-up not considered),
  `hidden_count` (locations outside the caller's reach, R49 §5.8).
- OpenAPI (`api/openapi.yaml`): the new routes with `x-permission` and `x-scope`; `docs/authz-matrix.md` regenerated;
  `TestScopedIDOR` covers the new routes through the route table (a resolver is mandatory).

### 17.2 Error codes (EN and TR in `locales/common`, error catalogue test)

| Code | Reason | Status | Where |
|---|---|---|---|
| `ALC-DEP-0031` | `deployment.canary_check_failed` | 502 | error code of a reverted wave-1 deployment; params `location_id`, `reason`, `http_status` of the round that failed the rollout |
| `ALC-DEP-0032` | `deployment.canary_aborted` | 409 | a reverted or never-sent wave-1 deployment of an aborted rollout |
| `ALC-DEP-0033` | `deployment.canary_wave_failed` | 409 | a reverted wave-1 deployment whose rollout failed for another reason; param `cause` (`deployment_failed`, `check_unavailable`, `certificate_revoked`, `wave_gone`) |
| `ALC-DEP-0034` | `deployment.rollout_state` | 409 | continue or abort not possible in the rollout's state (param `state`) |
| `ALC-DEP-0035` | `deployment.rollout_not_found` | 404 | the rollout resolver's not-found |
| `ALC-SVC-0020` | `service.canary_override_forbidden` | 422 | override refused by the policy |

`ALC-DEP-0031` to `0033` are in the deployment reason catalogue (`NeutralDeploymentReasons` is **not** extended: the
planners stop the certificate explicitly, §12). The rollout reasons (`canary.check_failed`, `canary.check_unavailable`,
`canary.wave1_failed`, `canary.certificate_revoked`, `canary.aborted`, `canary.wave_gone`, `canary.preempted_by_incident`,
`license.locked`) and the round reasons (`canary.http_status`, `canary.served_other`, `canary.unreachable`,
`canary.not_allowed`, `canary.timeout`, `canary.protocol`, and the provider's `deployment.verify_*`) are UI texts in
both catalogues, not API error codes.

### 17.3 Audit actions

`deployment.rollout_started` (waves, policy version, origin), `deployment.canary_skipped` (`reason` expiry|override),
`deployment.canary_overridden`, `deployment.holding` (per deployment), `deployment.rollout_hold_started`,
`deployment.rollout_check_failed` (the round that failed it; once), `deployment.revert_requested` (per deployment, with
the reason), `deployment.rollout_continued`, `deployment.rollout_released` (auto or continue; `early` flag),
`deployment.rollout_wave2_started` (inserted and skipped counts), `deployment.rollout_aborted`,
`deployment.rollout_failed`, `deployment.rollout_stopped`, `deployment.rollout_preempted`,
`deployment.rollout_completed`. Every row carries `details.service_id` (the source service, R53) and `rollout_id`;
rounds are **not** audited individually (only the failure that decides), to keep the chain small: the `canary_checks`
row holds the latest state.

## 18. Jobs, scheduling, observability

| Type | Class | Kind | Interval / attempts | Notes |
|---|---|---|---|---|
| `canary.advance` (periodic task) | ClassAlways | scheduler | release build every 10 s; e2e build never ticks (journeys run it with `POST /test/scheduler/run {"task": "canary.advance"}`) | leader-only (P2-06); one transaction per rollout with `FOR UPDATE SKIP LOCKED`; at most 100 rollouts per run; decisions of §9, §11, §12, §14, §15 |
| `canary.check` | ClassAlways | system | 1 attempt; no dead-job e-mail | one per holding deployment per round; `TargetID` = server |
| revert | (existing `certificate.deploy_recover`) | system | as today | dedupe `certificate.deploy_recover:<id>` |

Wiring: `jobs.Register` in `internal/jobs/types.go` (literal names, the web label guard reads them), the task in
`cmd/alice/services.go` `buildScheduler`, `checkWiring` lists it (`cmd/alice/wiring.go`), intervals in
`testapi_release.go` / `testapi_e2e.go` as `incidentAdvanceEvery` is. Web job labels (EN, TR) for both types.

Observability (no metrics system exists): `slog` lines with the house fields (`rollout_id`, `deployment_id`,
`job_type`, `error_type`; never a URL query value, a header or a body): one `Info` per rollout transition, one `Warn`
per failed round, one `Error` per advance failure. The jobs list shows every `canary.check`; the audit log every
transition; the deployment page the live state.

## 19. User interface (EN and TR)

- **Service page → Policy tab**: a "Canary deployment" section (`PolicyPanel`): switch, wave-1 size (count or
  percent), "Deploy here first" (a multi-select of the service's websites, `GET /certificate-locations?service_id=`),
  hold, interval, failures, an "Application check" sub-form (path, host, port, expected statuses, timeout) and
  "Allow deploying to all at once". Warnings: no check and some service locations skip verification ("these websites
  are only observed by time"). Version history shows `canary` as a changed key. Read-only without `services.policy`.
- **Deploy dialog** (`DeployDialog`, `KVDeployDialog`, the ACME Deploy now confirmation): when the source service's
  policy applies and two or more websites are chosen, a note "Deploys to N first, then waits 10 min" (the waves
  computed by the server are shown after submit); a checkbox "Deploy to all at once" (when `override: allowed`) that
  runs the step-up flow (`useStepUp`) before submitting.
- **Deployment detail page**: for a deployment with `rollout`, a "Canary" panel above the steps: state badge, reason
  (localized), the hold countdown (`hold_until − now`, from the server's `now`, refreshed with the page's polling),
  a table of both waves (website, server, deployment link and status, and for wave 1 the last round: result, TLS,
  HTTP status, latency, consecutive failures, time), skipped wave-2 websites with reasons, and **Continue now**
  (step-up) / **Abort** (confirmation) per `allowed_actions`. `DeploymentView` shows the `holding` state as "Under
  observation".
- **Deployments list**: a "Canary · wave 1/2" badge on rows with `rollout`; the status column shows "Under
  observation" for `holding`.
- Terms: Canary deployment / Kanarya dağıtımı; Wave / Dalga; Under observation / Gözlemde; Hold / Bekleme süresi;
  Application check / Uygulama denetimi; Continue now / Şimdi devam et; Abort / Durdur ve geri al; Deploy to all at
  once / Hepsine aynı anda dağıt. `make i18n-check` covers both catalogues.

## 20. Security review

### 20.1 SSRF through the check

- No free-form URL exists: the policy names a path, an optional server name and an optional port. The **dialed
  address is always the location's own verification address or its server's host**, both already dialed by the
  post-deploy probe and set by an Administrator (target validation and R59 G4 run on them). `check.host` is only the
  TLS server name and the `Host` header; it is never resolved.
- The dial goes through `netaddr.DialContext`: link-local (cloud metadata), multicast, unspecified, reserved and the
  tunnelled IPv6 forms are refused on the connected address after resolution (rebinding-proof); loopback and private
  addresses are allowed because managed servers live there (the same rule as SSH and the TLS probe). A refusal is a
  failed round (`canary.not_allowed`), never a silent pass.
- Port: any port of a managed server (a service Administrator, with step-up, could make Alice open a TLS connection to
  another port of a server Alice already manages). The request is sent only after the TLS handshake served the
  deployed leaf, so a non-TLS service, or another TLS service, receives a ClientHello and nothing else. Accepted and
  documented.
- No redirects, no proxy, no cookies, no credentials, header and body caps, a hard timeout; the response body is never
  stored, logged or shown (only the status, the latency and the served leaf's hash).
- Who can set it: `services.policy` (Administrator of the service, step-up, never a token), audited and versioned.

### 20.2 Hold vs certificate expiry

§15: skip the canary when any destination's current certificate expires within hold + 24 h; the hold is bounded at
24 h; continue only shortens it; the grace is at most 10 min; a clock jump releases early. Revert never restores an
expired certificate silently: the guard rule plus the expiry check make it unreachable in normal operation; if a clock
jump made it happen anyway the old certificate's verification (`verify_old`) records `rollback_failed` restored
unverified with its e-mail.

### 20.3 Rollback races

| Race | Resolution |
|---|---|
| Verdict vs a wave-1 deployment still sending | The engine always enters `holding`; the next advance reverts holding deployments of a failed/aborted rollout and releases those of a released one (rollout state decides, read under its lock). |
| Release vs revert vs abort vs continue | Every transition locks the rollout `FOR UPDATE` first, then each location `FOR NO KEY UPDATE`, then each deployment `FOR UPDATE` (id order): the order of `FinishDeployment` (location then deployment) with the rollout in front. The engine's own finish never touches the rollout, so no cycle. `ReleaseHold` and `RequestRevert` both require `state = 'holding'` under the deployment lock: exactly one wins. |
| Revert vs a new deployment of the location | `deployments_one_active`; holding and recovering are unfinished. |
| Revert vs the certificate being revoked or compromised meanwhile | The R48 guard is read right before `RollbackDeployment`; a forbidden previous certificate is never restored (`rollback_failed deployment.rollback_forbidden`). A deployed certificate marked revoked/compromised during the hold fails the rollout (`canary.certificate_revoked`) and reverts (to the previous one, guard permitting). |
| Revert vs a key-compromise incident at the same place | **A revoked or compromised deployed certificate always wins**: `ReleaseHold` refuses a holding deployment whose deployed certificate carries either mark (`ErrCertificateRevoked`/`ErrCertificateCompromised`), and `canary.advance` reverts it (`canary.certificate_revoked`) with the R48 guard on the previous certificate. Otherwise the incident engine, finding a `holding` deployment at an affected place (places are found from the location row, which still names the previous certificate during a hold), preempts the rollout: under the rollout lock every holding deployment of it whose deployed certificate is not forbidden is released (`ReleaseHold`, cause `incident`), the rollout ends `preempted` (no wave 2), and the place proceeds by the incident engine's existing rules on its next step (the location now names the released certificate). A holding deployment whose deployed certificate is the compromised one is never released: the incident waits on it as on any busy place until the revert ends it. A revert already in flight (`recovering`) is followed like any busy place. |
| Revert vs Windows cleanup | Cleanup keeps every certificate an unfinished deployment of the server names; after the revert, `CleanupRollbackWindow` (7 days) applies. |
| Revert vs drift repair / observation | Both skip a location with an unfinished deployment. |
| A crash between deciding to revert and sending the restore | `RequestRevert` commits `recovering` + `revert_reason` + the job before anything is sent; the recovery reads the journal and is idempotent (§10). |
| A stale `canary.check` run writes after the deployment moved | Fenced to its claim; `RecordCanaryRound` ignores a deployment that is no longer `holding`. |
| Two processes run `canary.advance` | Leader-only scheduling plus `FOR UPDATE SKIP LOCKED` per rollout. |
| Policy changed during a rollout | Snapshot (§5.3). |
| Server deleted during the hold | §8.4: released, the location leaves wave 1. |

### 20.4 Abuse of override and continue

Both need a fresh step-up in a browser session and are audited with the person; tokens cannot do either. Abort needs
only `certificates.operate` (making things safer is not gated behind step-up).

### 20.5 New STRIDE rows (SECURITY-REPORT.md)

`CN-1` SSRF via the check (mitigations §20.1), `CN-2` a canary that never ends holds a location busy (bounded hold +
grace, fail closed), `CN-3` revert re-installs a forbidden certificate (R48 on the revert path), `CN-4` override by
automation (step-up, tokens refused), `CN-5` information leak through check results (status, latency and hash only;
scoped `hidden_count`).

## 21. Providers: one behaviour

| | Nginx (helper) | Windows (winhelper) | Apache, HAProxy | Fake (tests, e2e) |
|---|---|---|---|---|
| Wave-1 send and verification | unchanged | unchanged | — (no deploy at `961f3bbb`) | unchanged |
| Holding | engine only | engine only | — | engine only |
| TLS baseline | `VerifyDeployment` (server blocks; helper `tls-probe` fallback) | `VerifyDeployment` (http.sys endpoints; helper probe fallback) | — | fake `VerifyDeployment` |
| HTTP check | `httpcheck` from Alice, location fields | same | — | e2e: the real check against `sshtarget` |
| Revert | `RollbackDeployment` → `nginx-restore` of the committed op (guard lists, protocol >= 10) | `RollbackDeployment` → `restore` (re-bind previous thumbprint) | — | fake honours the guard (G9) |

When Apache or HAProxy gain `CapDeployCertificate`, they get canary deployments with no canary change (Decision 15).

## 22. Interactions

- **Scoped access (R49):** the source service's policy decides; destinations in other services still need their trust
  (§5.6 (c)), re-checked when wave 2 is inserted; rollout reads filtered like deployments (`hidden_count`).
- **Notifications (R56):** reverted deployments send the existing `deployment.failed` e-mail (per deployment, with the
  canary reason's title); a stopped manual rollout sends `deployment.rollout_stopped`; automatic failures use the
  existing ACME/KV stop notices. Recipients per R49 §7.2 (`deployment.*`).
- **Incidents (R46):** exempt; preempt holds (§20.3).
- **Drift (R52):** no change; after a revert the newest succeeded deployment is the older one, which matches the files.
- **Rollback guard (R48):** unchanged and on the revert path.
- **Trust verification (R51):** the baseline is the R51 verification.
- **Windows cleanup (R62):** unchanged (asserted by a test).
- **Recovery sweep:** excludes `holding` (§8.4).
- **Licence continuity (R44):** §14.

## 23. Testing approach (IDs `CAN-01..CAN-32`, `alice-v1/06-quality.md` new subsection "Canary deployment (R65)")

- Pure: policy parse and validation (every bound, defaults, normalization, cross-field); `canaryWaves` (count, percent,
  `first`, n = 2, n = 20, stability); the rollout decision function (`decideRollout(snapshot) plan`) table-tested for
  every row of §9 and §11; the planners' new rules.
- `httpcheck` against local TLS servers on `127.0.0.1:45420-45439` (pass, wrong status, redirect not followed, served
  other leaf, timeout, huge body, huge headers, slowloris, plaintext port, refused address via the netaddr rule with a
  link-local name, no proxy taken from the environment).
- Engine (integration, Docker Postgres): enter holding; release with the location update; revert through recovery with
  the fake provider (rolled_back, guard refused, superseded, uncertain then resolved); sweep leaves holding; crash
  between revert request and restore.
- Advance (integration): every transition, gate refusals, expiry skip, revoked mid-hold, deleted server, incident
  preemption, stale checks, two advancers.
- API: routes, permissions, step-up, token refusal, IDOR (generated), error catalogue, OpenAPI.
- Web (Vitest): policy section, deploy dialog override, rollout panel (countdown, actions), list badge, EN/TR.
- e2e `web/e2e/canary.spec.ts` (project `alice-e2e-canary`, `ALICE_E2E_PORT=9979`): pass path to wave 2, check failure
  revert with wave 2 untouched (served certificates read on the target), abort, override with step-up, one journey in
  Turkish.

## 24. Decisions taken by default (owner to confirm; each recorded as a ruling in `canary-deployment.md`)

1. **New deployment state `holding` instead of finishing wave 1 `succeeded` and reverting later** — a done row is
   frozen and "rolled back after success" has no path today; holding keeps `deployments_one_active`, the recovery
   machinery and the status meanings intact.
2. **The revert is a recovery with `revert_reason`** (no new job type) — reuses the journal-driven, guard-checked,
   paced rollback that already handles every uncertain case.
3. **Override always needs a fresh browser step-up; API tokens can never override or continue** — bypassing a safety
   policy is a person's deliberate act, as R42 keeps tokens away from strict actions.
4. **Policy field `override: allowed|forbidden` (default allowed)** — some services want no escape hatch; most want one
   for emergencies.
5. **Key-compromise incident replacements bypass the canary and preempt holds** — a compromised key in service is
   worse than an unobserved replacement.
6. **Expiry guard: skip the canary when a destination's current certificate expires within hold + 24 h** — the margin
   covers wave 2's own pace and the grace; skipping is visible in the audit.
7. **An `unchanged` wave-1 outcome is not held, checked or reverted** — nothing was written, nothing can be restored.
8. **The source service's policy decides** (certificate's, ACME certificate's or vault's) — consistent with R55's
   "automatic deployment judged on the source's service"; the destinations' services keep their trust check.
9. **Policy snapshot at rollout creation** — a rollout behaves as it was announced; a policy edit cannot extend or
   cancel a hold under way.
10. **Wave-1 deployment failure fails the rollout and reverts the other wave-1 websites** — wave 1 is one unit; a mixed
    wave 1 is exactly the state a canary avoids.
11. **Unknown rounds never pass; fail closed after hold + grace (max(2 × interval, 5 min))** — a canary that cannot
    observe must not release.
12. **The HTTP check is a path (plus optional host and port) dialed at each location's own address, not a free URL** —
    on shared servers and behind load balancers a fixed URL would observe the wrong website; it also removes the SSRF
    surface. Departure from the brief's `url`, justified here.
13. **No proxy for the check** — the destination is a managed server Alice already reaches directly; a proxy would
    observe the proxy.
14. **Default failure threshold 2 consecutive rounds** — one lost packet must not roll production back; two failures
    30 s apart still revert within about a minute.
15. **Providers are not special-cased**; Apache/HAProxy inherit canary when they deploy.
16. **Manual wave 2 in a confirmed lock: release wave 1, stop, e-mail; transient gate answers wait up to 1 h** — wave 1
    passed and stays; a change a person asked for waits for a person after the renewal (R29 spirit); automatic rollouts
    follow the planner's continuity rules.
17. **`canary.check` and `canary.advance` are ClassAlways** — observation and revert protect production in every
    licence state, like recovery and `incident.advance`.
18. **Continue needs step-up and the destinations' rights; abort needs neither step-up nor destination rights** — the
    first widens the change, the second narrows it.
19. **Rounds are not audited individually; only the deciding failure and the transitions** — keeps the audit chain
    proportional; the latest round is on the page.
20. **No new e-mail for a failed canary; the per-deployment `deployment.failed` e-mail carries the canary reason** —
    the recipients already get exactly this mail for a rolled-back deployment; one new template only for the stopped
    manual rollout, which has no deployment of its own to mail about.
21. **Hold bounds 1 min–24 h, interval 15 s–10 min, timeout 1–10 s, wave 1 at most `count` 10 / 50 %** — far below the
    helper's 7-day backup retention and the Windows rollback window; keeps job load bounded (≤ 19 holding × 1 job per
    15 s).
22. **`first` is validated against the service's locations at save and ignored where stale at use** — locations come and
    go; a stale entry must not block a deployment.
23. **Migration: one rollout table, one observation table, four deployment columns** — the minimum that keeps rollout
    state out of individual deployments and wave 2 out of the table before it exists.
24. **Automatic rollouts complete at release; the planner deploys the rest** — the planners already own pacing,
    retries and stopping; a second pacer would fight them.
25. **New codes `ALC-DEP-0031..0035`, `ALC-SVC-0020`** — next free numbers at `961f3bbb`; renumber at merge if a parallel
    branch took them.
26. **Rollout reads are visible like deployments; actions need `certificates.operate` on the source service, also for
    an ACME-sourced rollout** — the people who could request the deployment can steer it; `acme.operate` and
    `certificates.operate` have identical role and token policies today (Admin, Operator; operate scope), and a test
    pins that equality so a future split fails loudly instead of silently changing who can abort.
27. **Planners leave the locations of a rollout in `wave1`/`hold` alone (reservation), and a failed person's rollout
    stops the matching ACME/Key Vault automatic deployment** — otherwise the planner would deploy wave 2 during a
    person's hold, or roll a failed certificate out again an hour later.
28. **A revoked or compromised deployed certificate is reverted, never released, even under an incident** — releasing
    it would make a forbidden certificate permanent, the anti-goal R48 exists for.
29. **`preempted` and `stopped` automatic rollouts let the planner continue as after `completed`** — the incident or
    the licence ended the canary, not the certificate's health; leaving wave 2 undeployed would be silent.

## 25. Left to the builder / not clear from the code

- Whether `insertDeployment`'s job for wave 2 should be `certificate.deploy` (person's, ClassChange) — this design says
  yes (trigger `manual`), so in a lock that begins after insertion the jobs are held for an Administrator as today.
- The exact place in `prepareACMEDeployment` / `planBinding` where the rollout row is inserted (inside the planner's
  transaction, before the first `insertDeployment`; the pure plan returns the waves).
- How `DeploymentView` names `holding` in its step list (one extra row "Under observation" is suggested).
- The `skip_verify` + no-check warning wording.
- Whether the e2e target's Nginx `/canary-fail` location is better switched by a control command than by a second
  path (this design uses two paths: `/healthz` answers 200, `/canary-fail` answers 503).
