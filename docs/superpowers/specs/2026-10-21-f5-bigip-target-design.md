# F5 BIG-IP as a deployment target: design

Status: design only, nothing built. Date: 2026-10-21. Written against `main` at `72fa1f9a` (migrations up to `00029`,
decisions up to R56; R57 and R58 are taken by parallel work). Decision number: **R59+ when implemented** (recorded in
`alice-v1/00-decisions.md` by the phase that builds it). Migration and error-code numbers: the next free ones at merge
time. Roadmap and shared groundwork: [2026-10-21-deployment-targets-roadmap.md](2026-10-21-deployment-targets-roadmap.md).
Sibling designs: [Windows and IIS](2026-10-21-windows-iis-target-design.md),
[Kubernetes](2026-10-21-kubernetes-target-design.md).

The implementation proceeds on the recommended defaults of §15 once the owner approves them in advance, as for
[the scoped access design](2026-10-21-scoped-rbac-and-service-ownership-design.md).

## 1. Purpose and agreed understanding

In the banks and large enterprises Alice sells to, public TLS often ends on an F5 BIG-IP (LTM) in front of the web
servers Alice already manages. The certificate on the BIG-IP is the one customers see, and today Alice can only find it
through network discovery. This design adds a **BIG-IP** target: Alice talks to the device's **iControl REST** API on the
management interface, discovers client SSL profiles and the virtual servers using them, installs new certificate and
key objects, switches the profiles to them in one **transaction**, synchronises an HA device group, verifies through the
virtual servers, and rolls back by switching back to the previous objects.

| Decision | Choice |
|---|---|
| API | iControl REST (`/mgmt/tm/...`, `/mgmt/shared/...`), HTTPS to the management address, token authentication. |
| Identity of the device | The management certificate pinned by SPKI on first contact (shared TLS pinning, groundwork), or a CA bundle. |
| Credential | A dedicated local or remote-auth user with the **Manager** role on the partitions it may change (Q2); its password is stored like every credential and used only to obtain short-lived tokens. |
| Location | One `certKeyChain` entry of one client SSL profile (kind `f5_clientssl`); its servers are the virtual servers that attach the profile. |
| Install | New objects with Alice names (`alice_<sha256-16>`), uploaded as a password-protected PKCS #12; existing objects are never overwritten. |
| Switch | One iControl transaction for all profiles of the deployment, committed atomically. |
| Rollback | A transaction that points the profile back to the previous objects, which stay until cleanup. |
| HA | The device group is one target; Alice changes one device, requires *In Sync* before, runs config-sync after, saves the configuration. |
| Versions | BIG-IP 16.1 and 17.x (Q5). |

## 2. Goals and non-goals

Goals:

- G1. Add a BIG-IP (standalone or a device group), pin its management certificate, check the role and the partitions.
- G2. Discover client SSL profiles in the allowed partitions, their certificate, key and chain objects, the virtual
  servers that use them (destination, SNI default, route domain), and the certificates' fingerprints and expiry.
- G3. Deploy to profiles manually and through ACME and Key Vault bindings, with the engine's outcome model.
- G4. Verify through the virtual servers with Alice's TLS probe (R51 levels); read back the configuration.
- G5. Roll back under the R48 guard; keep the device group in sync.
- G6. Observe drift (R52); clean up objects Alice created that nothing references.
- G7. Test everything in CI against a fake iControl server; a real BIG-IP VE in the owner's lab before release.

Non-goals:

- AS3, Declarative Onboarding, FAST templates, BIG-IQ: partitions and applications they own are discovery only (§6.2);
  writing AS3 declarations is a later design.
- iApps with strict updates: their objects are discovery only.
- Keys in a FIPS card, a network HSM or a cloud HSM (`security-type` other than `normal`): discovery only.
- Server SSL profiles, OCSP stapling objects, APM, ASM, GTM/DNS, management-interface certificates (later or never).
- `/mgmt/tm/util/bash` and any shell access: never used (it needs an Administrator and runs arbitrary commands).
- Creating virtual servers or profiles, changing ciphers or options.
- BIG-IP Next and F5 Distributed Cloud.

## 3. Vocabulary

| Term | Meaning |
|---|---|
| Partition | An administrative folder (`/Common`, `/Tenant_A`); roles are granted per partition. |
| Client SSL profile | `ltm profile client-ssl`: the TLS configuration a virtual server uses towards clients. Its `certKeyChain` holds one or more entries (RSA, ECDSA), each naming a certificate, key and chain object. A profile can inherit from a parent (`defaultsFrom`). |
| Certificate and key objects | `sys file ssl-cert`, `sys file ssl-key` (installed through `sys crypto`). |
| Virtual server | `ltm virtual`: destination address (with route domain `%n`) and port, with its profiles. One profile per virtual server may be the SNI default. |
| Device group | A sync-failover group of devices sharing configuration (config-sync, manual or automatic). |
| Transaction | `/mgmt/tm/transaction`: requests queued under a coordination id, validated and committed together. |
| Location | One `certKeyChain` entry of one client SSL profile. |

## 4. Transport and authentication

- HTTPS to the management address (`address`, port 443 by default; 8443 on single-NIC VE). TLS 1.2 or later; the
  certificate pinned by SPKI (`host_keys`, key type `tls-spki`, the existing confirm flow) or verified with a CA bundle
  the Administrator pastes; `insecure` is never offered.
- Token: `POST /mgmt/shared/authn/login` (`loginProviderName` `tmos` or the remote provider's name), the token's timeout
  raised to the session's need (at most one hour), deleted at `Close`. Basic authentication is not used. The password
  is decrypted only for the login call and zeroed.
- One session per device at a time (restjavad is single-threaded per request class and fragile under load); request
  budget 60 s, the whole deployment bounded like an SSH deployment; `503` and `429` retried with backoff within the
  budget; `401` mid-session re-logs in once.
- Least privilege (Q2): **Manager** on each partition Alice changes (Manager can create certificate and key objects and
  modify profiles; Certificate Manager alone cannot modify profiles), **Guest** or Auditor on partitions Alice only
  reads. `TestConnection` reads the user's partition access and names any partition where Alice can read but not write,
  and warns when the user is an Administrator (`f5.excess_rights`).

## 5. Data model

On the shared groundwork (location locator and details, TLS pinning, credential kinds):

- `targets.type`: `f5_bigip` (provider kind `f5bigip`). `targets.config`: `address`, `port`, `partitions` (1 to 50,
  required: Alice never reads every partition implicitly), `device_group` (discovered, read-only), `peers` (discovered
  management addresses), `save_config` (true), `sync` (`auto` | `manual`, discovered).
- Credential: kind `f5_password` (username and password), purpose `f5_device`.
- `certificate_locations.kind`: `f5_clientssl`; locator
  `{"partition": "Common", "profile": "/Common/www_clientssl", "entry": "default"}`; `cert_path` the canonical
  `/Common/www_clientssl#default`; `cert_file_sha256` the SHA-256 of the certificate object's DER (the compare-and-swap
  token, together with the object names in `details`); `servers` the virtual servers (`Names` from the SNI server name,
  `Section` the virtual server's full path, `Listens` the destination); `details`: certificate, key and chain object
  names, key type and `security-type`, parent profile, inherited, SNI default, owner (`as3`, `iapp`, none).
- `deployments.rollback_info`: `{"operation_id", "transaction": <id>, "previous": {"cert", "key", "chain"}}`.
- Nothing stored about objects Alice created beyond the deployments: the name prefix `alice_` plus the fingerprint in
  the name identify them, and the device is asked what references them.

## 6. Flows

### 6.1 Adding a device

The Administrator enters the management address, port, partitions and the credential. Alice shows the management
certificate's SPKI fingerprint for confirmation (the setup page tells how to read it on the device:
`tmsh list sys httpd ssl-certificate-file` and `openssl x509 -pubkey`), then reads `/mgmt/tm/sys/version`, the user's
role and partition access, the device and its device group (`/mgmt/tm/cm/device`, `/mgmt/tm/cm/device-group`,
`/mgmt/tm/cm/sync-status`) and whether AS3 is installed (`/mgmt/shared/appsvcs/info`). A device of a group lists its
peers; the target is the group (one target; Q3), reached through the address given; the peers' addresses are kept for
verification and failover of the management connection (Q4).

### 6.2 Discovery (read-only)

For each allowed partition: client SSL profiles with `certKeyChain` (`/mgmt/tm/ltm/profile/client-ssl?$select=...`),
virtual servers with their profiles (`/mgmt/tm/ltm/virtual?expandSubcollections=true`), certificate objects with
fingerprint, subject, SANs and expiry (`/mgmt/tm/sys/file/ssl-cert`), key objects with type and `security-type`.
Where the API does not return a certificate's PEM, the certificate is identified by its SHA-256 fingerprint and the
full chain is taken from a probe of a virtual server that uses it (F2 of §14). A profile inheriting its certificate
from a parent is `Inherited` (changing the parent changes the child), as Nginx's inherited locations.

Ownership checks per location (unsupported, deploy refused, listed): `f5_declarative` (the partition or application
belongs to AS3, BIG-IQ or FAST: an AS3 redeploy would undo Alice's change), `f5_iapp_strict`, `f5_hsm_key`,
`f5_foreign_partition` (the profile is in an allowed partition but its objects are in one Alice cannot write).

### 6.3 Deployment

1. Pre-check (the engine's) and a fresh read of the profile: its current entry must name the objects and certificate
   fingerprint discovery saw (otherwise `deployment.precondition`, nothing changed). The device group must be
   *In Sync* or standalone; *Changes Pending* from someone else refuses (`f5.sync_pending`): syncing would publish
   their unreviewed change, and not syncing would leave Alice's change to be overwritten.
2. Objects: names `alice_<first 16 hex of the leaf SHA-256>` for the certificate and key and
   `alice_chain_<first 16 hex of the chain SHA-256>` for the chain, in the profile's partition. If an object with that
   name exists and holds the same fingerprint, it is reused (an interrupted earlier attempt); if it holds anything else,
   refuse (`f5.object_conflict`). Upload: one PKCS #12 encrypted with a random one-time password through
   `/mgmt/shared/file-transfer/uploads/<random name>.p12` (chunked, `Content-Range`), installed with
   `sys crypto pkcs12 install` with that password; the chain uploaded as PEM and installed as a certificate object. The
   uploaded file is removed afterwards when the role allows it (F4); it is encrypted either way. Nothing is overwritten,
   so nothing served changes in this step.
3. Transaction: `POST /mgmt/tm/transaction`, then, with `X-F5-REST-Coordination-Id`, one `PATCH` per profile of the
   deployment replacing only the location's `certKeyChain` entry (other entries kept), then commit
   (`PATCH .../transaction/<id>` `state: VALIDATING`). The transaction id is recorded in `rollback_info` before the
   commit (the journal role: an uncertain commit is read back by id, `COMPLETED` or `FAILED`).
4. Config-sync: automatic sync → wait for *In Sync* (bounded, 60 s); manual sync → `config-sync to-group <group>`
   (`/mgmt/tm/cm` run) and wait. Then `save sys config` on the device (and on each peer when Q4 allows it).
5. Verification (§6.4). Failure → rollback (§6.5).

The step names reported to the `StepLogger`: `upload`, `install`, `commit`, `sync`, `save`, then the existing `verify`,
`restore`, `verify_old`.

### 6.4 Verification

Endpoints: each virtual server of the location, at its destination address and port, with SNI = the profile's server
name (or the certificate's, the `SNIFor` rule). A route-domain address (`10.0.0.5%2`) or a destination Alice cannot reach
uses the Administrator's probe address (groundwork) or is skipped (level 1). There is no on-device probe: `util/bash` is
never used. A read-back of the profile after the commit and after the sync proves the configuration in every case.
BIG-IP serves the configured chain object as is, so the R51 chain length comparison applies unchanged.

### 6.5 Rollback, recovery and fence

- **Rollback**: Alice checks the R48 guard against the previous certificate (its leaf and key SPKI hashes are known from
  discovery) before sending; a forbidden backup restores nothing (`rollback_failed`, `deployment.rollback_forbidden`).
  Otherwise one transaction points the entry back to the previous objects, then sync and save as in §6.3. The device
  never restores by itself, so `Required` guards are always satisfiable (groundwork: a provider that restores only on
  request).
- **Uncertain commit** (the connection dropped): `GET /mgmt/tm/transaction/<id>` and a profile read decide `committed`,
  `no_change` or still `uncertain`.
- **Fence** (AUD-05): a transaction not yet committed is deleted (`DELETE /mgmt/tm/transaction/<id>`); a committed one
  answers its state; an unknown id with the profile showing the previous objects answers `fenced`. Objects uploaded but
  not referenced are harmless and left to cleanup.

### 6.6 Drift (R52)

The scheduled observation reads the profile (the "file" fact: the objects and fingerprint it names now) and probes the
virtual servers (the "website" fact). Causes named in notices: profile re-pointed, object replaced under the same name
(fingerprint changed), the device group out of sync, the partition now owned by AS3.

### 6.7 Cleanup

A periodic job `f5.cleanup` (ClassChange, daily, on by default) deletes `alice_*` objects of the allowed partitions
that no profile references (Alice's read of every client SSL profile in the partitions it can see) and that are not the
previous objects of a deployment within its rollback period (7 days after final, as Windows). BIG-IP refuses to delete
an object something else references (another module, a partition Alice cannot read); that refusal is a skip, not an
error. Objects not named `alice_*` are never deleted. Then sync and save.

## 7. Provider (`internal/providers/f5bigip`)

- Kind `f5bigip`; capabilities `test_connection`, `discover_certificates`, `deploy_certificate`, `verify_deployment`.
- A small typed client over `net/http` (no F5 SDK): login, get, patch, transaction, upload, install, sync, save; every
  answer decoded into bounded structs (sizes capped, unknown fields ignored), every name validated against BIG-IP's
  object-name rules before it is sent (path injection: `/`, `~`, `%` handled explicitly).
- The pinned dialer and TLS configuration come from the groundwork's TLS-pinning helper (shared with Kubernetes).
- The outcome rules of `providers` (`CheckDeployReturn` and the rest) apply; the conformance suite runs against the fake.

## 8. Security analysis

| Threat | Mitigation |
|---|---|
| **Alice's BIG-IP credential stolen** | Manager on named partitions only (no Administrator, no bash, no `/Common` unless needed); tokens short-lived and deleted; the password decrypted only for login. The residual: an attacker can switch certificates on those partitions' profiles, which is what Alice is for. |
| **Man in the middle to the management interface** | SPKI pin confirmed by an Administrator, or a CA bundle; a changed certificate blocks the target until confirmed again (`host_key_changed`). |
| **Private key on the device's disk** | Uploaded only inside a PKCS #12 with a random one-time password; the upload file removed when permitted; installed as a normal key object protected by the device's master key. |
| **Overwriting someone else's objects** | Alice never writes an object it did not name; a name collision with other content refuses. |
| **Publishing another administrator's pending change** | *Changes Pending* refuses before anything is written. |
| **Undo by declarative tools** | AS3, BIG-IQ, FAST and strict iApp ownership make the location discovery only. |
| **Rollback reinstalling a compromised key** | R48 guard checked by Alice before every restore transaction; the device has no automatic restore. |
| **API injection through names** | Names validated and escaped; no free text from inventory reaches a URL path or a command argument. |
| **Excess rights silently accepted** | `TestConnection` warns on Administrator role and on partitions with more access than needed. |

## 9. Verification levels (R51)

1 installed: the profile names the new objects (read back on the device, after sync) and verification is skipped.
2 served and 3 trusted: as everywhere, through the virtual servers. 4 reserved.

## 10. Failure modes

| Failure | Outcome |
|---|---|
| Management interface unreachable, TLS pin mismatch | `f5.unreachable`, `host_key_changed`; nothing sent. |
| Login refused, token expired | `f5.auth_failed` (target status `auth_failed`); one re-login within a session. |
| Role lacks write on the partition | `f5.forbidden` before upload (checked from the role at `Open`), or the device's `401/403` mapped to the same code. |
| Profile changed since discovery | `deployment.precondition`, nothing changed. |
| Device group not in sync | `f5.sync_pending` or `f5.sync_failed`, nothing changed. |
| Upload or install fails | Nothing referenced yet: `no_change` with the reason; objects left to cleanup. |
| Transaction validation fails | `no_change` (the device refused as a whole). |
| Commit outcome unknown | `uncertain`, recovered through the transaction id and a profile read. |
| Sync after commit fails or times out | The change is live on one device: `rolled_back` after a guarded rollback transaction and a second sync attempt, or `rollback_failed` with `f5.sync_failed` when the group cannot be brought back (an e-mail names the device group). |
| Save fails | A warning on the deployment (`f5.save_failed`): the running configuration is right, a reboot would lose it; the next deployment or cleanup saves again. |
| Verification fails | Guarded rollback transaction, sync, save. |
| Failover during a deployment | The management address may now be the standby: the commit's state is read back on the peer when known (Q4), otherwise uncertain until it answers. |

## 11. Test strategy

1. **Fake iControl server** (`internal/testutil/fakebigip`, an `http.Handler` like `fakekv`, wrapped by
   `cmd/alice-fakebigip` for e2e): login and tokens with expiry; partitions and per-user partition roles; certificate,
   key and chain objects (fingerprints computed from real DER); `pkcs12 install` that really decrypts the uploaded file
   with the given password; client SSL profiles with `certKeyChain`, inheritance, AS3 and iApp ownership markers;
   virtual servers with a real TLS listener each, serving the profile's certificate and chain with SNI selection, so
   Alice's real probe and trust check run; transactions with validation and commit, state read by id, delete;
   device groups with sync status, auto and manual sync, sync failures; save. Fidelity rule as `fakekv`: answer shapes
   follow F5's public iControl REST reference, recorded examples (placeholders only) are committed in
   `test/testdata/bigip-recordings` and compared by a shape test; behaviour not documented is marked `GUESS` and listed
   in the security review.
2. **Faults**: token expiry mid-deployment, `503` storms, transaction commit failing, commit answer lost (connection cut
   after the device applied it), sync failing, save failing, object name collision, failover.
3. **Engine integration** (Postgres): the deployment world gains a BIG-IP on the fake: manual, ACME and Key Vault
   deployments, the crash table at every point, the rollback guard rows, drift, cleanup.
4. **Real device** (owner, before release; §15 Q6): BIG-IP VE 16.1 and 17.x with a lab or trial license, standalone and
   an HA pair, a scripted scenario list run against the device and against the fake with answers compared; the
   recordings refreshed from it.

## 12. Phases

### Phase F1 — Connection and discovery (size L, ~8 tasks)

Groundwork items (TLS pinning, credential kind, location kind and locator); `targets.type` `f5_bigip`; the client;
`TestConnection` with role and partition checks; discovery; the fake's read half; UI: add a BIG-IP, pin, partitions,
device group facts, locations with virtual servers and ownership reasons (TR/EN).

Acceptance:
- A device and a device group are added with a confirmed pin; a wrong pin, bad password and missing partition access
  are named precisely; Administrator rights warn.
- Every client SSL profile of the allowed partitions is a location with its virtual servers; AS3, iApp, HSM and foreign
  partition locations are unsupported with their reason; certificates link to inventory by fingerprint.

### Phase F2 — Deployment, verification, rollback (size L, ~9 tasks)

Upload and install, transactions, verification, guarded rollback, recovery and fence, step names, error codes; locations
bindable to ACME and Key Vault certificates.

Acceptance:
- A manual deployment to a standalone device commits atomically for every profile of the deployment and reaches level 3
  with a public-CA chain; a profile changed since discovery changes nothing.
- A failed verification switches back; a forbidden previous certificate restores nothing (`rollback_failed`).
- The crash table passes on the fake (kill before upload, after upload, after commit sent, after commit, during
  verification); a lost commit answer is recovered from the transaction id.

### Phase F3 — Device groups (size M, ~5 tasks)

Sync status precondition, auto and manual sync, save on peers (Q4), failover of the management connection, sync failure
handling.

Acceptance: deployments on an HA pair (fake; and the owner's VE pair) leave the group *In Sync*; *Changes Pending*
refuses; a sync failure after commit rolls back.

### Phase F4 — Drift, cleanup, documentation (size M, ~5 tasks)

R52 observation and repair for BIG-IP locations; `f5.cleanup`; admin guide "F5 BIG-IP", the least-privilege user setup,
security overview, `SECURITY-REPORT.md`, `06-quality.md` test IDs `F5-01..`, traceability.

Acceptance: a profile re-pointed outside Alice is `drifted` and repaired in `auto`; cleanup deletes only unreferenced
`alice_*` objects outside their rollback period.

## 13. Interactions with other work

- Scoped access (R49, R53-R56): a BIG-IP target belongs to a service like any target; a deployment of a certificate of
  another service needs the trust, unchanged. A device shared by many services is one target in one service; finer
  sharing (per partition) is a later question (Q7).
- License (R9, R44): discovery ClassReadOnly, deploy and cleanup ClassChange, automatic deployment ClassContinuity.
- Network discovery: a virtual server's certificate found by a scan is linked as managed once the BIG-IP location holds it.

## 14. Facts to confirm on a real device (Phase F1 start)

| # | Fact | If it is wrong |
|---|---|---|
| F1 | Manager on a partition can install certificate and key objects there and patch its client SSL profiles. | Document the role actually needed. |
| F2 | Whether `sys file ssl-cert` (or another endpoint the role may read) returns the certificate's PEM, or only its fingerprint and fields. | Fingerprint plus probe (as designed). |
| F3 | `sys crypto pkcs12 install` with a passphrase, from the upload directory, under Manager. | Upload key and certificate as PEM with a passphrase-protected key. |
| F4 | Whether Manager can remove the uploaded file. | Rely on encryption only; documented residual. |
| F5 | Transactions cover `ltm profile client-ssl` patches and roll back as a whole on validation failure. | One patch per profile with Alice-side compensation. |
| F6 | After config-sync, peers persist the synced configuration without a save of their own. | Save on each peer (Q4). |

## 15. Open questions for the owner (the implementation proceeds on the default)

| # | Question | Recommended default |
|---|---|---|
| Q1 | Imperative iControl REST, or AS3 declarations? | **Imperative REST** for devices configured by hand (the common case in the target market); AS3-owned locations discovery only; AS3 support is a later design. |
| Q2 | Which role does Alice's BIG-IP user get? | **Manager on the partitions it changes**, Guest/Auditor on the ones it only reads; never Administrator (warned). |
| Q3 | License: does an HA pair or a device group count as one target or one per device? | **One target per device group** (Alice manages it as one). A pricing decision: the owner may prefer per device. |
| Q4 | Does Alice keep the peers' management addresses and use them (failover of the API connection, save on peers)? | **Yes, discovered and read-only**, same credential; a peer is dialed only with its own confirmed pin. |
| Q5 | Supported versions? | **16.1 and 17.x** (the trains F5 supports at design time); 15.1 refused with a clear message. |
| Q6 | Real-device testing: who provides a BIG-IP VE lab license? | **The owner** (an F5 lab or trial license) before F2 is released; CI uses the fake only. |
| Q7 | One BIG-IP shared by several services? | **One target in one service in v1**; per-partition service ownership is a later design. |
| Q8 | Object retention after a replacement? | **7 days after the replacing deployment is final**, as Windows; keys of a compromised certificate are deleted at once after the replacement verified. |
