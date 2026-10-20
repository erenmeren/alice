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
