# Rulings: deployment targets groundwork, phase G (R59)

Owner decision 2026-10-21: the owner approved implementing the three target designs (Windows and IIS, F5 BIG-IP,
Kubernetes) with their documented defaults; this phase builds the shared groundwork G1-G7 of
[the roadmap](../specs/2026-10-21-deployment-targets-roadmap.md). The defaults below were chosen during execution and
are recorded for review; none is a security posture or a pricing decision. Spec: R59 in
`docs/superpowers/specs/alice-v1/00-decisions.md`, migration `00031` and the location kinds in `02-architecture.md`, the
held backups and API target credentials in `04-security.md` §15.7 and §15.11.

Acceptance of the phase: **no behaviour change** for Nginx, Apache, HAProxy and Key Vault. A certificate file keeps no
locator, no details and no probe address (a CHECK holds it); its provider request carries no kind or locator (the
material leaves them empty for a file); the web server's configuration still gates a file's deployment; the existing
unit, integration and e2e suites pass unchanged (one integration assertion names the new field `Backups`, one DTO test
the four new fields).

## The groundwork as built

- **G1 location kinds** (migration `00031`). `certificate_locations.kind` takes `server_file`, `win_sslbinding`,
  `f5_clientssl`, `k8s_tls_secret` (`win_ccs_file` and `win_rdp` wait for their phases: a CHECK widens with each).
  `locator jsonb` (a flat object, at most 1 KiB, unique per target and kind) and `details jsonb` (an object, at most
  16 KiB) are added; a location that is not a file has a locator, a canonical `cert_path` of at most 1024 characters, and
  no key path, resolved path, key mode, owner, group or symlink flag. `alice_app` may update `details` (and
  `verify_address`), never the locator. `deployments.location_kind` records the kind; a file keeps 00006's path rule, any
  other kind records its canonical text and an empty key path. In Go: `providers.LocationKind`, `providers.Locator` (one
  canonical JSON form: sorted keys, integers normalised, no HTML escaping), `CanonicalDetails`, `CertLocation.Kind`,
  `Locator`, `Details`; the nine step names of the new targets; `DeployRequest.ExpectCertSHA256` documented as each
  kind's compare-and-swap token.
- **Inventory**: a scan stores a non-file location by its kind and canonical text, checks that the stored row holds the
  same locator (a row whose locator differs, or a new text whose locator another row holds, is skipped and counted, and
  the stored row is not marked missing for it), drops details that do not fit with `list_truncated`, and marks every
  kind of the target missing after a complete scan (one provider reports all of a target's locations). The material,
  the drift probes and the location API carry kind, locator, details and the probe address.
- **G2 TLS identities**: `host_keys` stores `tls-spki` identities with the existing statuses and confirm flow
  (`providers.TLSIdentity`, `ValidTLSIdentity`; the inventory's sighting check accepts them; the verify command is an
  `openssl` pipeline). `internal/providers/tlspin` builds the client `tls.Config` from the pin (compared in
  `VerifyConnection`, no CA involved) or from a CA bundle (no pin), and `Refusal` records the sighting and answers
  `target.host_key_unconfirmed` / `target.host_key_changed`, the SSH codes, so the target status and the UI flow apply
  unchanged.
- **G3 credentials**: purposes `f5_device` (kind `f5_password`) and `kubernetes_cluster` (`k8s_token`,
  `k8s_client_cert`), owned by their target like a vault's; the credential trigger takes the three API-target types
  (a Windows server signs in with the platform key). `providers.TargetSecret` (redacting `Format`, `LogValue`, `Zero`)
  and `TargetSecretSource`; `inventory.TargetCredentials(id)` decrypts one for a session and refuses a row that does not
  suit its target.
- **G4 probe address**: `certificate_locations.verify_address` (a DNS name or an IP literal without a zone, folded and
  normalised), `VerifyOptions.Address`, `LocationPatch.verify_address` (`PATCH /api/v1/locations/{id}`, the existing
  route and permission), the settings dialog shows the field only for a location that is not a file. No engine change:
  polling for propagation stays inside a provider's own `VerifyDeployment`.
- **G5 backup models**: `providers.RollbackTraits{Backup, SelfRestores}` declared by a provider (`RollbackModel`;
  undeclared = `DefaultRollbackTraits`, the Linux helper's: on the target, restores by itself), `Validate` (a target that
  keeps nothing cannot restore by itself) and `RollbackGuard.SatisfiedBy` (a `Required` guard is satisfiable when the
  target never restores by itself or checks the guard itself). `deployment_backups` holds an Alice-held backup, sealed
  (AAD `deployment_backups/<deployment id>/ciphertext`), with the leaf and SPKI hashes in clear; the database refuses
  deleting one while its deployment is unfinished (Z1032); `maintenance.cleanup` deletes it 7 days after the deployment
  is final. `providers.HeldBackups` (Hold, Load) rides on every `DeployRequest` and `RollbackRequest` the engine builds.
- **G6 types**: `targets.type` takes `windows`, `f5_bigip`, `kubernetes`; `providers.KindForTargetType` maps them to
  the reserved kinds `windows`, `f5bigip`, `kubernetes`; nothing registers them, so no such target can be added yet.
- **G7 conformance**: `providertest.CheckLocationTarget` runs the outcome rules, `DeploymentState.Validate`, the fence
  contract, the guard contract and the held-backup contract against a target's fake; `providertest.MemoryBackups` is the
  engine's store without a database. A reference counterpart in the package's tests passes it, and one broken variant per
  rule fails it.

## Rulings made during execution

1. **Migration 00031, decision R59.** 00030 is reserved for the parallel DNS-provider work (goose tolerates the gap;
   `pgtest.PreviousVersion` handles it). SQLSTATE `Z1031` (the Down's refusal) and `Z1032` (a live backup) follow the
   migration's number rather than the next free code, so the parallel branch's codes cannot collide.
2. **One migration for the whole groundwork.** The roadmap says each target's types arrive with "each migration's
   Down"; the three types, kinds and purposes arrive together here because they share one trigger and one Down
   (which refuses while any of the new data exists), and no target phase then has to edit a shared CHECK again.
3. **Identity of a non-file location: the canonical text, checked against the locator.** The scan looks a location up
   by kind and `cert_path` (00006's path-hash index) and requires its stored locator to be the reported one, instead of
   a second lookup path by locator. Both are unique, so either identifies the row; one lookup keeps the reconciliation
   and its locks as they are. A provider that changes its canonical text for the same locator is a provider bug that
   the scan survives (skipped, never a failed transaction).
4. **The certificate half still needs web-server facts.** `Reconcile` stores certificates only for a web-server target
   type with usable `WebServerFacts`. G leaves that gate alone (no behaviour change); each target phase adds its type and
   its own notion of a usable answer. The groundwork's integration tests report non-file locations through an Nginx
   server for that reason: the kind is independent of the target type at this level.
5. **The web server's configuration gates files only.** `checkDeployLocation` and the material's `ConfigValid` apply the
   `config_invalid` refusal to certificate files; a provider of another kind refuses its own preconditions before it
   changes anything.
6. **`CredentialSource` is not widened.** The roadmap says it "gains one method"; as built, `TargetSecretSource` is a
   separate interface, as `AzureCredentialSource` is for a vault, so the fakes and the SSH sources need no new method and
   a provider asks for the interface it needs.
7. **The probe address is refused for a file in this phase** (`validate.Pattern`, and a CHECK). The web-server providers
   keep probing the server's own address; giving them the setting is an owner decision for later (it would change how
   an existing deployment is verified).
8. **A backup is held once per deployment.** A second `Hold` of the same deployment keeps the first: it is the content
   before any change of that deployment (a retried send must not replace it with Alice's own new certificate). The
   store checks that the chain starts with the certificate whose key is held (`checkHeldBackup`); the R48 guard reads the
   recorded rollback columns as for every provider.
9. **Retention by the existing cleanup task.** The 7 days (Kubernetes design Q5) are counted from the deployment's
   `finished_at`; the hourly `maintenance.cleanup` deletes the backups (ClassAlways: a lock does not keep old keys). No
   new job type.
10. **The new inventory errors stay internal** (`errHeldBackupInvalid`, `errHeldBackupUnreadable`,
    `errTargetSecretInvalid`, `errTargetCredentialUnreadable`): they reach a provider or the engine, never the API, so
    they have no ALC code.
11. **UI**: the step names of the new targets have EN and TR labels and are listed after the five grouped steps, as any
    step the server adds; the probe address field appears only for a location that is not a file. The UI copy of "server
    identity" for a TLS pin, the setup pages and the target forms are the target phases' (no such target can be added
    yet).

## Deferred to the target phases

- Registering the providers and their API routes, forms and setup pages (W1, K1, F1); widening `Reconcile` and the
  target-type gates (`IsWebServer`, `requireServer`) for their types.
- `win_ccs_file` and `win_rdp` kinds (W5, W6).
- Using `tlspin` in a client; WinRM (W7).
- `04-security.md` §14.4 STRIDE rows per connector and the `06-quality.md` test IDs `WIN-`, `F5-`, `K8S-`.

## Owner items

None required for G. For confirmation when convenient: ruling 7 (probe address for the web-server providers later or
never).
