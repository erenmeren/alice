# New deployment targets: roadmap and shared groundwork

Status: design only, nothing built. Date: 2026-10-21. Written against `main` at `72fa1f9a`. Decision number:
**R59+ when implemented**. No R-number is recorded in `alice-v1/00-decisions.md` for this work yet; R57 and R58 are
taken by parallel work, and each phase that is built records its own decision then.

| Design | Target | Recommended approach |
|---|---|---|
| [Windows and IIS](2026-10-21-windows-iis-target-design.md) | Windows Server 2019-2025, IIS 10 | OpenSSH Server with a forced command to a Go `alice-helper.exe`; import into the machine store, re-point the http.sys SSL binding, journal on the server. |
| [F5 BIG-IP](2026-10-21-f5-bigip-target-design.md) | BIG-IP 16.1, 17.x, standalone and device groups | iControl REST with tokens; new `alice_*` objects; one transaction per switch; config-sync and save; AS3-owned config discovery only. |
| [Kubernetes](2026-10-21-kubernetes-target-design.md) | Any conformant cluster | TLS Secrets with `resourceVersion` compare-and-swap, a strict namespaced Role; cert-manager and GitOps-owned Secrets discovery only. |

The approach of all three follows [the scoped access design](2026-10-21-scoped-rbac-and-service-ownership-design.md)'s
method: the owner approves the recommended defaults in advance, and each phase is built on them while the questions stay
open.

## 1. What the three have in common

Every deployment target today is a file pair on a Linux host reached over SSH, except the Key Vault, which is a source.
The three new targets break four file-centred assumptions of the engine and inventory. These are fixed once, in a
groundwork phase **G**, before any target phase.

### G1. Location kinds with a locator

`certificate_locations.kind` (only `nginx_file` today) gains `win_sslbinding`, `f5_clientssl`, `k8s_tls_secret`
(and later `win_ccs_file`, `win_rdp`). Two columns: `locator jsonb` (the kind's identity, validated by the provider,
unique per target with `kind`) and `details jsonb` (kind-specific facts shown in the UI, bounded). `cert_path` keeps a
human-readable canonical form of the locator; `key_path` and the Unix key columns stay empty for the new kinds.
`providers.CertLocation` gains `Kind`, `Locator` and `Details`. `DeployRequest.ExpectCertSHA256` is documented as the
provider's compare-and-swap token for the location's current content (a file hash for files, the bound certificate's
DER hash for Windows, the certificate object's hash for BIG-IP, the `tls.crt` hash plus `resourceVersion` for
Kubernetes). Step names gain the new targets' steps (`import_chain`, `import_certificate`, `bind`, `upload`, `install`,
`commit`, `sync`, `save`, `write_secret`), each documented in `providers`.

### G2. TLS identity pinning for API targets

`host_keys` keeps SSH host keys and also stores TLS server identities: key type `tls-spki`, fingerprint
`SHA256:<base64 of the SHA-256 of the SubjectPublicKeyInfo>` (the existing CHECK pattern already fits 43 base64
characters), the same statuses (`observed`, `pinned`, `superseded`, `rejected`) and the same confirm flow and
`host_key_changed` status. A target may instead carry a CA bundle in its config (verified chain, no pin). A shared
package (`internal/providers/tlspin`) builds the `tls.Config` from either, records sightings through
`providers.HostKeyStore`, and is used by BIG-IP, Kubernetes and a later WinRM transport. The UI calls both "server
identity".

### G3. Credential kinds

`credentials.kind` and `purpose` gain `f5_password` / `f5_device`, `k8s_token` and `k8s_client_cert` /
`kubernetes_cluster`. `providers.CredentialSource` gains one method for a generic secret (username and password, token,
client certificate and key), each type with redacting `Format` and `LogValue` and `Zero`, as `AzureIdentity` has.
Windows needs none: it uses the platform SSH key.

### G4. Verification without a helper

`VerifyOptions` gains `Address` (an Administrator's probe address per location: a load balancer's internal address, an
address without a route domain), stored next to `verify_port` and `verify_sni`. A provider without an on-target probe
(BIG-IP, Kubernetes) verifies with Alice's probe only; the R51 rules and levels do not change. Kubernetes adds polling
with a propagation timeout inside its own `VerifyDeployment`; the engine is unchanged.

### G5. Backup models and the rollback guard

Two models, declared by the provider:

- **On the target, by reference** (Windows: the previous certificate stays in the store; BIG-IP: the previous objects
  stay): `rollback_info` names what to point back to.
- **Held by Alice** (Kubernetes): a new `deployment_backups` table holds the previous certificate and key,
  envelope-encrypted like every key, written before the change and deleted 7 days after the deployment is final.

The R48 rule "a deployment that needs the guard must not run on a server that cannot check it itself" exists because a
Linux helper may restore by itself. A provider declares whether its target ever restores on its own: Windows does (its
helper, which checks the guard itself, like protocol 10), BIG-IP and Kubernetes never do (only Alice restores, after
checking the guard), so `Required` guards are satisfiable on all three. `GuardsRollback` keeps its meaning.

### G6. Types, capabilities, license and access

The `targets_type_check` gains `windows`, `f5_bigip`, `kubernetes` (each migration's Down refuses while a target of that
type exists, as `00018` does). Capabilities sync at startup unchanged. Each new target counts toward the license from
creation; job classes as today (discovery ClassReadOnly, deployment and cleanup ClassChange, automatic deployment and
drift repair ClassContinuity). Targets belong to a service (R49) like any target; the cross-service trust check and the
service policy apply unchanged.

### G7. Conformance

`providertest` runs its suite for non-file locations: the outcome rules, `DeploymentState.Validate`, the fence contract
and the guard contract against each target's fake.

## 2. Recommended order and sizes

| Order | Phase | Size | Depends on | Why here |
|---|---|---|---|---|
| 1 | G — shared groundwork (G1-G7) | M (~6 tasks) | — | Every target needs it; small and testable with the existing Nginx path (no behaviour change). |
| 2 | Windows W0 (spike on real Windows) | S | — (can run alongside G) | The design rests on Windows facts that must be confirmed first. |
| 3 | Windows W1-W4 | L + XL + M + M | G, W0 | Highest priority for the owner; the largest market of the three in the customer base; reuses the most (SSH, helper journal, emulator). |
| 4 | Kubernetes K1-K3 | M + L + M | G | Pure API, fully testable in CI (fake, envtest, kind), smallest of the three. |
| 5 | F5 BIG-IP F1-F4 | L + L + M + M | G, an owner-provided BIG-IP VE lab license | Common in banks, but confidence needs a real device that only the owner can provide. |
| later | Windows W5 (CCS), W6 (RDP), W7 (WinRM); K4; AS3 | M / M / L / M / L | the above | On customer demand. |

Rough total: groundwork M; Windows about 30 tasks; Kubernetes about 19; BIG-IP about 27. Kubernetes and BIG-IP may swap
places if a customer asks for BIG-IP first and the lab license is ready.

## 3. Decision placeholder

When a phase is built, it records **R59 or the next free number** in `alice-v1/00-decisions.md` with "owner approval of
the design with its defaults" and a rulings file in `docs/superpowers/rulings/` (`windows-iis.md`, `f5-bigip.md`,
`kubernetes.md`, `deployment-targets-groundwork.md`). It amends `alice-v1/02-architecture.md` (target types, location
kinds, tables), `alice-v1/03-integrations.md` (one section per target), `alice-v1/04-security.md` (§14.4 STRIDE rows for
each connector, §15.11 target access) and `alice-v1/06-quality.md` (test IDs `WIN-`, `F5-`, `K8S-`).

## 4. Questions the owner should look at first

From the three designs, the ones that cost money, change pricing or set the security posture:

1. Windows Q1: OpenSSH with a forced command instead of WinRM (customer acceptance of sshd on Windows).
2. Windows Q2: Authenticode signing of the Windows helper (a yearly certificate on a hardware token).
3. F5 Q3 and Kubernetes Q3: what counts as one licensed target (a device group, a cluster).
4. F5 Q6: who provides a BIG-IP VE lab license for real-device testing.
5. Kubernetes Q1: strict RBAC by default (named Secrets only) versus convenience.
