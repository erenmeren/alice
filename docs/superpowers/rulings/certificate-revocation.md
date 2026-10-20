# Rulings: certificate revocation and key-compromise incidents

Owner decision 2026-10-20, after an outside review: Alice had no certificate revocation (the ACME directory model had no
`revokeCert`, the limitations list said "revoke at the authority"), and deleting an inventory entry revoked nothing. An
enterprise customer asks: "this private key leaked — which servers are affected and how do I replace them all
safely?". The change adds RFC 8555 revocation of the certificates Alice ordered, a per-source capability matrix, the
impact of a certificate (every place that holds it or its key) and a key-compromise incident that replaces the
certificate everywhere and revokes it afterwards. Spec: R46 in `docs/superpowers/specs/alice-v1/00-decisions.md`,
AC-8 and the incident permission in `04-security.md`, §7.6 and §8.4a in `02-architecture.md`; user text in
`docs/admin-guide.md`, `docs/operator-guide.md`, `docs/troubleshooting.md` (ALC-CRT-0018/0019, ALC-ACM-0037..0040,
ALC-INC-0001..0013).

## The design as built

- **ACME client** (`internal/acme/revoke.go`): `Directory.RevokeCert` (`revokeCert`, https only), `SupportsRevocation`,
  `Client.Revoke(ctx, leafDER, reason)`, signed with the account key (JWS `kid`), `RevocationReason` with the five
  subscriber reasons of RFC 5280 (`unspecified` 0, `keyCompromise` 1, `affiliationChanged` 3, `superseded` 4,
  `cessationOfOperation` 5). New reasons `acme.revoke_unsupported`, `acme.revoke_reason_refused`,
  `acme.revoke_unauthorized` (ALC-ACM-0038..0040).
- **Fake CA** (`internal/testutil/fakeacme/revoke.go`): `revokeCert` signed by the ordering account (`kid`) or by the
  certificate's own key (`jwk`), `alreadyRevoked`, `unauthorized` (another account, another key), `badRevocationReason`
  (reasons 2, 6, 7, 8, 9, 10), 404 `malformed` for a certificate it never issued, `CertificateStatus(serial)` and the
  control route `GET /certificate?serial=` (valid or revoked, reason, time), counter `revoked`.
- **Migration `00021`**: `certificates.revoked_at`, `revocation_reason`, `revoked_by`, `compromised_at`,
  `compromised_by` (final once set: Z1022); `discovery_certificates.public_key_sha256` (filled by the ingest, '' for
  rows from before until seen again); `certificate_incidents` and `certificate_incident_locations` (one open incident
  per certificate; a finished incident and its locations are frozen: Z1023). No DELETE grant on the new tables.
- **Deployment refusals**: `RequestDeployment`, Deploy now, the ACME and Key Vault planners, Key Vault deployments and
  the engine's material step (a queued deployment whose certificate was revoked or marked compromised before the first
  send) refuse a revoked (`certificate.revoked`, ALC-CRT-0018) or compromised (`certificate.compromised`,
  ALC-CRT-0019) certificate.
- **Revoke** (`inventory.RevokeACMECertificate`, `POST /api/v1/acme/certificates/{id}/revoke`): `acme.manage`
  (Administrator, fresh step-up, never a token), `ClassChange`, `limitACME`; audit `acme.certificate.revoked` /
  `acme.certificate.revoke_failed`. The web's **Revoke** dialog on the ACME page (version, reason, "I understand this
  cannot be undone").
- **Capability matrix** (`inventory.SourceCapabilities`, `CertificateCapabilities`): `discover`, `obtain`, `renew`,
  `deploy`, `verify`, `revoke`, `recovery`; per source in `GET /api/v1/certificates/capabilities` and per certificate
  in the certificate DTO (`capabilities`); the web's **What Alice can do with it** panel and the page's buttons follow it.
- **Impact** (`inventory.CertificateImpact`, `GET /api/v1/certificate-impact/{id}`): certificates with the same key,
  certificate files on live servers (by the file's certificate or Alice's last deployed fingerprint), Key Vault
  versions, discovery endpoints (present or unreachable since), each list capped at 1000.
- **Incidents** (`inventory/incidents.go`, `incidents_engine.go`; routes under `/api/v1/incidents` and
  `POST /api/v1/certificates/{id}/incidents`; permission `certificates.incident`; periodic task `incident.advance`).

## Rulings made during execution

1. **Revocation signs with the provider's active account, not with the certificate key.** RFC 8555 allows either.
   Alice holds both, but the owner asked for "the account key that ordered it": the account is what the CA links the
   certificate to, and a key rollover keeps the account (same `kid`). A provider whose account was deactivated or
   replaced after a directory change cannot revoke its old certificates through Alice (`acme.revoke_unauthorized` or
   `acme.account_state`); the person revokes at the CA. Revocation with the certificate key (the fake supports it) is
   left for later (deferred D1).
2. **`alreadyRevoked` is success.** `golang.org/x/crypto/acme` turns it into nil and the end state is the one asked
   for; Alice records the revocation with the reason it sent (the fake keeps the first reason; a real CA's recorded
   reason may differ). A 404 or 403 without a type, and `malformed` with 404, are `acme.revoke_unauthorized`.
3. **Expired versions are not revoked.** A CA no longer lists an expired certificate (RFC 5280 CRLs drop it), and an
   expired certificate is refused by every client anyway: `ErrCertificateExpired` before any request; an incident skips
   expired versions and counts "nothing left to revoke" as revoked.
4. **A revoked or compromised current certificate is due at once.** `renew.Input.Revoked` makes `Decide` order it now
   (`ReasonDueRevoked`), the planner's candidate query treats its `not_before` as its renewal time; the 15-minute spacing,
   the backoff and "automatic renewal off" still apply. Revoking does not switch automatic renewal off, not even with
   `cessationOfOperation`: the reason is what the CA publishes; to stop a certificate, switch renewal off or delete it.
5. **The incident's permission is new (`certificates.incident`)**, Administrator with a fresh step-up, never a token,
   like `acme.manage`. Starting one marks certificates compromised for good, replaces files on servers and revokes at a
   CA, for any source; `certificates.operate` (Operators, tokens) was too weak and `acme.manage` named the wrong thing.
   Reading incidents and the impact is `read`, except the network endpoints (next ruling).
6. **The impact hides the network map from callers without `discovery.view`.** The endpoints are the internal network
   map (D7): a read token gets `endpoints: []` and `endpoints_hidden: true`; servers, files and vaults stay visible as
   on the certificate's own page.
7. **Same key, two meanings.** The impact lists every place holding the certificate or another certificate made with
   the same key (`match` certificate / key). The incident replaces only the files that hold the compromised certificate
   itself (or that Alice last deployed it to) and the files bound to its ACME certificate; a file holding *another*
   certificate with the same key is listed `skipped` (`incident.other_certificate`): its names differ, so this
   incident's replacement would break it. Every certificate with the key is still marked compromised, so none of them is
   deployed again; the person starts an incident for that certificate too. Also skipped: a file bound to a Key Vault
   certificate (`incident.follows_key_vault`: replace it in the vault) or to another ACME certificate
   (`incident.follows_other_acme`), and a file Alice cannot deploy to (`incident.not_deployable`; also used when the
   file needs another key type, since a stored code carries no params).
8. **One open incident per certificate**, not per key: two certificates with one key can each have an incident (the
   previous ruling). Started while one is open: 409 ALC-INC-0001.
9. **Compromise is marked at the start, for every certificate with the key**, in the starting transaction, before
   anything is replaced: from that moment nothing deploys the leaked key again (a planner's queued deployment of it is
   refused at its first send). Places that still serve it keep serving it until replaced.
10. **The replacement of an ACME certificate is a new order of the same ACME certificate.** Every order generates a new
    key (`NewACMEOrderKey`), so the compromised key is never reused; the engine still refuses a replacement with the same
    public key hash (`incident.key_reused`). An order already running is waited for; a newer current certificate with
    another key issued after the incident began (the renewal planner got there first) is adopted. A failed order needs
    attention with the order's code; **Retry** orders again. A provider without a usable account refuses the start (409
    ALC-ACM-0023/0024).
11. **The replacement of another source is chosen by a person** (`awaiting_replacement`): a certificate Alice holds the
    key of, with another key, neither revoked nor compromised, valid now (`ErrIncidentReplacement`, 422 ALC-INC-0003).
    Alice cannot revoke it (`revocation: not_possible`); every screen and the API description say the issuing authority
    must.
12. **Deployments go through the person's path.** The engine calls `RequestDeployment` per pending location (trigger
    `manual`, the incident engine as the audit actor `incident`, no incomplete chain ever confirmed), so the engine's
    journals, verification and rollback apply unchanged. A location already deploying the replacement (the ACME
    automatic deployment) is followed instead. A busy location (another unfinished deployment, a recovery on the
    server, a server not ready) is asked again on the next runs, at most 30 times (`incident.location_busy`). Any other
    refusal fails the location with the refusal's reason; a failed deployment with the deployment's error code.
13. **Verified means verified.** A location counts as replaced when its deployment ended `succeeded` or `unchanged`
    with `verified` `remote` or `local`; a deployment whose verification was skipped (the location's Skip verification)
    is `unverified` and blocks the automatic revocation (`incident.deployments_unverified`): the person checks those
    websites and chooses **Revoke now regardless**.
14. **"Revoke now regardless"** sets `revoke_mode = now`: the engine revokes at its next run whatever the deployments'
    state (in any open state). Chosen at the start (a checkbox, ACME only) or later (`POST .../revoke-now`). When the
    incident waited only for that (unverified locations or a failed revocation), it moves to `revoking` and completes.
15. **Revocation failures**: a transient one (`acme.FailureClass`) is tried again after 1, 2, 4, 8 minutes (the CA's
    Retry-After when longer, at most an hour), up to 5 attempts; then, and at once for a permanent one, the incident
    needs attention with the code (`revocation: failed`); **Retry** tries again.
16. **The engine is a periodic task, not a job per step.** `incident.advance` (ClassAlways, every 30 s on the leader;
    in the e2e build only through `POST /test/scheduler/run`) advances every open incident a few steps per run, each in
    its own transaction from the stored state, so an incident survives restarts by construction (the record is the
    state; the deployments and the order it follows are durable jobs of their own). It asks the gate (ClassChange)
    before it requests a deployment, starts an order or revokes; in lock it only follows what runs. The actions that
    start work (start, retry, revoke now, replacement) are ClassChange routes; **Close** is ClassAlways (it only stops
    Alice's work). No e-mail is sent for an incident in this version (deferred D3).
17. **Audit trail**: `certificate.compromised` (with the number of certificates marked), `incident.started`,
    `incident.replacement_chosen`, `incident.deployed`, `incident.revoked`, `acme.certificate.revoked` (per version,
    with the incident id), `incident.needs_attention`, `incident.revoke_failed`, `incident.retried`,
    `incident.revoke_now`, `incident.completed`, `incident.closed`; each deployment keeps its `deployment.*` rows. Audit
    detail keys avoid the secret-looking words the audit log refuses (`spki_sha256`, `reason`, not `public_key_*` or
    `code`).
18. **The capability matrix is the certificate's, not the provider's.** `providers.Capability` describes a server type;
    a certificate source is another axis, so it is its own closed list with the same shape (sorted strings in the API,
    a TS copy kept equal to the Go constants by a test, the web disabling what is missing). A deployment needs both
    (`deploy` on the certificate, `deploy_certificate` on the server). `discovered`: discover only; `uploaded`, `csr`,
    `azure_kv`: discover, deploy, verify; `acme`: all seven. Per certificate, `deploy` and `verify` drop without a key
    (except a Key Vault leaf, whose key is read from the vault) and once revoked or compromised; `revoke` drops once
    revoked. `recovery` means the ACME renewal recovery of R45, nothing else.
19. **Discovered certificates get a public key hash** (the SHA-256 of the re-encoded SubjectPublicKeyInfo, as
    `internal/certs`), computed in `tlsprobe` (discovery may not import `certs`) and stored by the ingest; a row from
    before `00021` gets it when a scan sees the certificate again, until then it is found by fingerprint only.
20. **Routes**: `/api/v1/certificate-impact/{id}` instead of `/certificates/{id}/impact` (the mux refuses it beside
    `/certificates/csr/{id}`), `/api/v1/certificates/capabilities` (a literal path beside `{id}`).

## Not done / deferred

- D1: revocation signed with the certificate's own key (for a certificate whose ordering account is gone). The fake
  supports it; the client and the UI do not.
- D2: an incident list page (the API lists incidents; the web reaches an incident from its certificate's page).
- D3: e-mails about incidents (needs attention, completed); the audit log and the page are the record.
- D4: replacing places that hold another certificate made with the same key in the same incident (they are skipped
  with the reason; one incident per certificate).
- D5: OCSP/CRL checking of certificates found on servers or by discovery (Alice does not learn about revocations it did
  not make).
- The revocation was exercised only against `fakeacme`; no public or company CA, no real CRL/OCSP publication.

## Rollback guard (R48)

Owner decision 2026-10-20 (the owner approved the work and was not available; the implementer chose the defaults below
and records them here): a revoked or compromised certificate was refused by every *deploy* path, but the *rollback*
paths put back the files from before a change without that check, so during a key-compromise incident a failed
replacement could re-install the compromised key. No rollback path may ever do that. Spec: R48 in
`docs/superpowers/specs/alice-v1/00-decisions.md`, AC-8 in `04-security.md`, the deployments table in
`02-architecture.md`; user text in `docs/nginx-host-preparation.md` ("An undo never puts back a revoked or compromised
certificate") and `docs/troubleshooting.md` (ALC-DEP-0025, ALC-SSH-0014).

### The rollback paths found

1. **The engine** (`internal/jobs/deployjobs`): every recovery rollback (`recover.go` `rollback`: a journal `writing`,
   `restoring`, `restore_failed`, or `committed` whose own verification failed), the deploy job's one more restore after
   the helper's `restore_failed` (`deploy.go` `rollbackAgain`), and the restore of an earlier operation Alice does not
   track that blocks the files (`deploy.go` `recoverPending`).
2. **The Nginx provider** (`internal/providers/nginx/deploy.go`): the inline rollback after the new certificate's
   verification failed (`rollBack`) and `RollbackDeployment`; both send `nginx-restore`.
3. **The helper** (`cmd/alice-helper/deploy.go`): its own restore inside the `nginx-deploy` transaction (a failed
   `nginx -t`, reload, write or journal: `fail` → `restoreOp`), the restore of a re-sent interrupted operation
   (`writing`/`restoring` journal), and `nginx-restore`. The emulator (`linuxsshtest`) mirrors all three.
4. **None elsewhere**: the Apache and HAProxy providers are discovery only (no deployment, no restore); Alice never writes
   a certificate back to a Key Vault (an import adds a version, nothing restores an older one); the SSH key rotation's
   undo concerns `authorized_keys`, not certificates.

### Rulings

G1. **What is forbidden.** The leaf (SHA-256 of the DER) of a revoked or compromised certificate, and the public key
    (SHA-256 of the re-encoded SubjectPublicKeyInfo, as `internal/certs`) of every compromised certificate, so a key
    compromise covers every certificate made with that key. A certificate revoked for another reason forbids its leaf
    only. Marks are final (Z1022), so "forbidden once" is "forbidden for good".

G2. **The rollback target is recorded, not re-derived.** `StartDeployment` records, with the send values, the leaf and
    public key of the certificate the location's file held (`deployments.rollback_leaf_sha256`, `rollback_spki_sha256`,
    migration `00023`): the helper's compare-and-swap on the file's hash makes that exactly the backup. A discovery after
    the start changes nothing. Neither known: the target is unknown (`TargetUnknown`).

G3. **Computed at plan time, read again before every rollback.** `inventory.RollbackGuard(id)` checks the target
    against the marks every time it is asked: with the material (plan time; the `deployment.started` audit row says
    `rollback` = `allowed`, `forbidden` or `unknown`), before the provider's inline rollback (`DeployRequest.RecheckGuard`),
    before every recovery rollback and the deploy job's one more restore, and before the restore of an untracked
    operation. A compromise marked while the deployment runs therefore applies. A guard that cannot be read is no
    rollback at all: the deploy path ends uncertain, the recovery unresolved, and the next recovery reads it again.

G4. **Security first.** A rollback the guard refuses restores nothing. The files stay as the failed change left them
    (after an interrupted write that can be a new key with the old certificate), no `nginx -t` or reload runs, and the
    deployment ends `rollback_failed` with `deployment.rollback_forbidden` (ALC-DEP-0025), failed step `restore`,
    helper error `forbidden`, phase `restore_forbidden` when the helper recorded the refusal ("" when nothing was
    sent). It is never retried (only `restore_failed` is). Trade-off, accepted: **the website may stay broken** (Nginx
    keeps what it loaded until its next reload or restart) until a valid certificate is deployed; that is preferred to
    a compromised key in service. It is visible: its own e-mail `deployment.rollback_forbidden` (never the
    rollback-failed e-mail, whose advice is to restore the backup by hand, and without `backup_dir`), the deployment
    page's headline and "never restore it" next to the backup folder, and on an incident the place is `failed` with
    the reason, so the incident needs attention (`incident.deployments_failed`); **Retry** deploys again (a
    `restore_forbidden` operation does not block the files on the server).

G5. **The helper checks too (defence in depth).** Alice's knowledge of a backup may be wrong (and an untracked
    operation's backup is unknown to it), so the guard also carries the forbidden material: every compromised key
    and every unexpired revoked certificate, the backup's own entry first, newest first, at most 128 of each
    (`providers.MaxForbidden` = `helperproto.MaxForbidden`). `alice-helper` 1.9.0 (protocol 10) takes the lists in the
    `nginx-deploy` input, keeps them in the operation's journal, takes the current lists on `nginx-restore`'s standard
    input (the argument vector and the sudoers lines are unchanged), and before any restore reads both backups: the
    leaf, the leaf's public key and the key file's public key; listed, or (with a list) not readable as a certificate
    and its key, means nothing is restored and the journal says `restore_forbidden`, on all three restore paths. A
    helper that receives the restore records the refusal itself, which keeps the next deployment of the files possible.

G6. **Helper version skew.** The protocol is versioned (`helperproto.Protocol`, reported by `version` at every
    session); the guard needs `RollbackGuardMinProtocol` = 10. A deployment whose guard is *Required* is refused on an
    older helper before anything is sent (`ssh.helper_outdated_rollback_guard`, ALC-SSH-0014, params
    `helper_protocol`, `required_protocol`), because such a helper restores the backup unchecked after a failed reload.
    Required = the target is forbidden, or unknown while anything is forbidden, or the location is a pending or
    deploying place of an open incident (every incident replacement). Any other deployment still runs on an older
    helper, with the input it understands (no lists): the engine's own check (G3) is exact for the tracked backup, and
    refusing every deployment on every older helper as soon as one key anywhere is compromised would stop the fleet.
    An older helper never receives a restore the guard refuses (target forbidden, or unknown while anything is
    forbidden): nothing is sent and the outcome is G4's with phase "". Alternatives rejected: a new subcommand or
    argument (an older sudoers file would refuse it, and a refused `nginx-restore` reads as uncertain), and refusing
    old helpers outright (above).

G7. **Untracked operations.** The restore of an earlier operation that blocks the files uses its owner's recorded guard
    when Alice knows the owner (a finished `rollback_failed` deployment of the location), else this deployment's lists
    with an unknown target. A refused restore puts nothing back and the deployment ends
    `deployment.server_operation_pending` (nothing re-sent), as for any restore that does not finish.

G8. **A server that cannot be reached is never counted as cleaned.** An incident place counts as replaced only when its
    deployment ended succeeded or unchanged *and verified* (ruling 13). While the deployment is in recovery (sent, the
    outcome not confirmed: the server cannot be reached or the answer was lost) the place stays `deploying`, the
    incident neither revokes nor completes, and the API says `outcome_uncertain: true` with the deployment's reason; the
    page shows "Not confirmed: server not reached". When the recovery gives up the place is `failed`
    (`deployment.outcome_unknown`).

G9. **The fake provider honours the guard** by default (`RollbackDeployment` with `TargetForbidden` answers the
    helper's refusal), so engine tests and the e2e stack behave like a protocol 10 server.

G10. **Codes**: `deployment.rollback_forbidden` ALC-DEP-0025 (502) and `ssh.helper_outdated_rollback_guard` ALC-SSH-0014
    (502), the next free numbers of their families; they may be renumbered at merge.

### Residual risks and deferred items

- RG1: the helper's own restore inside the `nginx-deploy` transaction checks the lists sent with that deployment (plan
  time): a compromise marked during the at most 50 s of one `nginx-deploy` is caught only by later restores (the
  provider's inline rollback and every recovery read the guard again).
- RG2: an older helper doing a deployment that is not Required restores its own failed change unchecked; Alice's check
  covers only the restores it asks for. Update every helper to 1.9.0 before an incident (the docs say so).
- RG3: the backup holding the compromised key stays in `/var/lib/alice-helper/backups/<id>` until the 7-day sweep (or
  `alice-helper cleanup --op <id>`); deleting it at once is deferred.
- RG4: more than 128 compromised keys or revoked certificates: the helper's lists hold the backup's own entry and the
  newest 128; the engine's check stays exact for the tracked backup.
- RG5: a journal written by 1.9.0 with lists cannot be read by an older helper (strict decoding): downgrading the helper
  is not supported.
- RG6: nothing re-deploys automatically after a refused rollback; a person retries (incident **Retry** or Deploy).
- RG7: exercised against the helper's unit tests, the emulator (with its fidelity tests against the real helper) and
  the full stack on PostgreSQL; not against real servers, and the Playwright suite was not run for this change.
