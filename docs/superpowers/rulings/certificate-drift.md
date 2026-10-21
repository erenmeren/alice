# Rulings: what should be there, what Alice last deployed, and what is observed today

Owner approval 2026-10-21 (the work was approved while the owner was away; the defaults below were chosen during
execution and are recorded here for review). The gap: a binding's state `current` meant "the location serves, or
got, the current certificate" (`internal/inventory/acme_bindings.go`: a past succeeded or unchanged deployment of the
current certificate counted), and the automatic deployment planners (`acme_autodeploy.go`, `kv_autodeploy.go`) and
the location's re-evaluation after a scan (`locations.go`) relied on the same past success. Discovery already noticed
some external changes (`reconcileLocations` sets `changed_outside_at` and audits `location.changed_outside`), but
nothing acted on it: when Alice deployed C2 and someone later put C1 back on the server, Alice still showed the place
as current. Spec: R52 in `docs/superpowers/specs/alice-v1/00-decisions.md`; user text in `docs/admin-guide.md` ("Drift:
what should be there and what is there"), `docs/operator-guide.md` and `docs/troubleshooting.md` (ALC-DEP-0027 to
ALC-DEP-0030).

## The design as built

- **Four facts per bound location, each with its own time** (`inventory.LocationObservation`, `internal/inventory/
  drift.go`):
  - desired: the binding's certificate (an ACME certificate's `current_certificate_id`, a Key Vault binding's current
    version's `certificate_id`);
  - last deployment: the newest succeeded or unchanged deployment to the location, with the level it proved (R51), as
    before (`deployments`, `certificate_locations.deployed_fingerprint`);
  - file: `certificate_locations.certificate_id` as the last scan read it, and `file_observed_at` (migration `00027`),
    the time a scan last read the file's content (a certificate, or that the file holds none). `last_seen_at` stays
    what it was (every scan that names the location, also one that could not read the file); the two clocks are never
    the same field;
  - website: `location_observations.tls_*` (migration `00027`): what the location's endpoints served at the last probe
    that completed a handshake (the leaf of the first endpoint that did not serve the desired certificate, else the
    desired one), when, from where (`alice`: Alice's own probe; `helper`: the server itself, for at least one
    endpoint), the level (R51: served or trusted when the desired leaf was served) and the trust of the served chain,
    with the last attempt and its closed failure (`deployment.verify_unreachable`, or the provider's code such as
    `ssh.timeout`).
- **Health from the observations** (`locationHealth`, a pure function with a table test): `unmanaged` (nothing
  desired) → `pending` (a deployment runs, or the desired certificate never reached the location: no successful
  deployment of it and no observation, now or earlier, found it) → `drifted` (an observation newer than the desired
  certificate's last successful deployment disagrees) → `unreachable` (the last probe completed no handshake and is
  newer than the last one that did and than the deployment) → `stale` (the newest agreeing evidence is older than 24
  hours) → `in_sync`. A past success alone never makes a location in sync once a newer observation disagrees.
- **The observation** (`drift.schedule`, periodic, `ClassReadOnly`; `drift.observe`, queue, `ClassReadOnly`, one
  attempt, no `job.dead` mail; `internal/jobs/driftjobs`): the schedule (every 5 minutes; never in the e2e build) finds
  the bound locations whose `next_observe_at` passed (every 6 hours, `DriftObserveInterval`, spread over a tenth of it
  by the location's id), at most 200 per run and 20 per server, stamps the next time and queues one job per server
  (dedupe `drift.observe:<target>`). The job uses the existing paths only: the certificate half of a discovery
  (`Discover` with certificates only, stored by `Reconcile`, so the file observation, `changed_outside_at` and the
  compare-and-swap hash are the discovery's own) and the deployment engine's verification (`VerifyDeployment` with the
  desired leaf, its SANs, key type, the location's verification settings and the R51 trust policy of the desired
  chain). No second prober was built. `RecordDriftObservations` stores what it saw and the transition.
- **The repair** (`drift.repair`, periodic, `ClassContinuity`, every minute; never in the e2e build): for a drifted
  location in mode auto, a deployment of the desired certificate through `insertDeployment` (trigger `drift_repair`, the
  system actor, a `certificate.deploy_auto` job), after the checks of the automatic deployment planners
  (`readDeployCertificate`, `lockDeployTargets`, `checkDeployLocation`; for a Key Vault binding `versionRefusal` as an
  Operator, so a held version is never repaired). The deployment engine then applies its guards unchanged: the R48
  rollback guard, the R51 trust, the refusal of a revoked or compromised certificate (00021), the file's
  compare-and-swap. The job judges the repair again before it sends (`driftRepairPrecheck`: still desired, still auto;
  `deployment.drift_repair_superseded` ALC-DEP-0027, `deployment.drift_repair_off` ALC-DEP-0028).
- **Modes** (`location_observations.drift_mode`): `observe` (report and mail), `approve` (report and mail with the
  repair prepared; `POST /locations/{id}/actions/repair` is the one action), `auto` (repair through the engine).
  `PUT /locations/{id}/drift-mode` takes `observe`, `approve`, `auto` or `default`.
- **Notices** (outbox, TR and EN, in the alerts ledger of 00011 so each goes once): `location.drift_detected`,
  `location.drift_repair_ready`, `location.drift_repaired`, `location.drift_flapping`, `location.drift_repair_failing`;
  ledger kinds `location_drift` and `location_drift_repaired` (one per location and drift episode: `expires_at` is when
  the drift began) and `location_drift_backoff` (one per back-off). Audit `location.drift_detected`,
  `location.drift_resolved`, `location.drift_mode_changed`, `location.drift_repair_requested`, `location.drift_backoff`.
- **API and web**: `observation` on every location (`GET /targets/{id}/certificate-locations`) and every ACME binding;
  the ACME binding's `state` gains `drifted`. The issued certificate's websites and the server's certificate files
  show the health, the four facts with their times, the repair mode, Repair, and the summary line ("Live and verified
  on 17 of 20 places; 2 not reachable; 1 serves another certificate (it ends in 18 h)").

## Rulings made during execution

1. **Default mode.** A binding that exists when migration `00027` runs is `observe`: the upgrade changes nothing but
   the reporting. A binding made afterwards has no stored mode, and the default follows automatic deployment: `auto`
   when automatic deployment is on for the binding (for an ACME binding both the certificate's and the binding's
   switch), `observe` otherwise. Switching automatic deployment on was already an Administrator's act with a fresh
   step-up under the licence gate, so the default never makes Alice repair something no Administrator chose to have
   deployed unattended. The web says "Default (Repair automatically)" so the person sees what the default is.
2. **Permission of the mode selector** is the permission of switching automatic deployment on today: `observe` and
   `approve` change nothing on a server and are `certificates.operate` (Administrators and Operators, as editing a
   binding); `auto` (or a default that is auto), when automatic repair is not on already, is refused inside the
   inventory unless an Administrator's browser session with a fresh step-up asks (the rule of `unattendedAllowed`:
   `ErrAdminRequired`, `ErrAutoDeployNeedsStepUp`, the licence's `ClassChange`). The route is refused in lock
   (`ClassChange`), as the binding's PUT is. Any choice clears a back-off.
3. **The repair action is a person's deployment.** `RepairDrift` calls `DeployACMENow` (one location) or
   `RequestKVDeployment` of the binding's current version: every refusal, licence rule and audit row of Deploy now
   applies, trigger `manual`. It needs `certificates.operate` and works in every mode (in `approve` it is the
   prepared repair; in `observe` it is a shortcut for Deploy now of the right certificate). It answers ALC-DEP-0029
   (no binding) or ALC-DEP-0030 (not drifted).
4. **What counts as a disagreeing file.** A scan that read another certificate counts only when the scan itself judged
   it a change outside Alice (`changed_outside_at` newer than the deployment): `aliceFingerprints` already knows which
   certificates Alice's own deployments can have left, including a rollback's, so a deployment that failed and was
   undone is not a drift. A file the scan found without a certificate (missing, not a certificate) is not a drift by
   itself; the website's probe decides then. A disagreeing website always counts. Either one newer than the deployment
   is enough (a file changed and not yet reloaded is a drift that the next reload makes visible).
5. **Drift versus "not deployed yet".** A desired certificate that never reached the location (a renewal the planner
   holds, a binding made a moment ago) is `pending`, not drifted: the rollout belongs to the automatic deployment
   planners, the repair only to places that had the certificate. The planners are not changed: they still deploy each
   new current certificate once, and they do not count `drift_repair` deployments toward their three-failure stop.
6. **Flapping.** Two tools that manage one file would fight. A repair is planned only after an observation newer than
   the previous repair's end, and only when the file was scanned after the last deployment (the compare-and-swap needs
   the file's current hash; the observation job scans the file before it probes). Automatic repair backs off to
   `observe` when 3 (`DriftMaxRepairs`) repairs of the location within 24 hours (`DriftRepairWindow`) all succeeded and
   the drift came back again (`flapping`, mail "another tool keeps changing this file"), or all failed
   (`repair_failing`). At most three repairs per location per day therefore reach a server. A person switches it on
   again.
7. **When auto tells.** In mode auto the repair comes first: `location.drift_repaired` goes once the next observation
   sees the place in sync again, after a successful repair of the episode. A drift that no repair ended within an hour
   (the licence is locked, the certificate cannot be deployed unattended, the location is not ready) is mailed as
   `location.drift_detected`, once.
8. **One observation per location, not per endpoint.** The verification probes every endpoint of the location (at
   most 10) and reports the first that did not serve the desired leaf; the stored website observation is that one.
   Per-endpoint rows were not built (see Deferred).
9. **Error codes** continue the deployment series: ALC-DEP-0027 to ALC-DEP-0030 (`deployment.*` reasons, because the
   two stored ones end a deployment).
10. **Unbound rows are removed.** The schedule deletes the observation rows of locations that no longer follow a
    binding, so a mode chosen for an old binding does not come back with a new one.
11. **Key-compromise incidents win.** A location of an open incident is never repaired automatically: the incident
    decides what it gets.

## Deferred

- Per-endpoint observations (a location with several listens shows the first disagreeing one) and network discovery
  endpoints (`discovery_endpoints`) as observations of bound locations.
- A drift summary on the dashboard and in the certificate list.
- Repair of Apache and HAProxy locations: they are discovery only (no deployment), so they cannot be bound.
- Observation of a server whose SSH connection fails records the failure on its locations (unreachable), but Alice's
  own TLS probe alone is not tried without a session.
