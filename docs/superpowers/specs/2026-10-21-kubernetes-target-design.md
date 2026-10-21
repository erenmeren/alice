# Kubernetes as a deployment target: design

Status: design only, nothing built. Date: 2026-10-21. Written against `main` at `72fa1f9a` (migrations up to `00029`,
decisions up to R56; R57 and R58 are taken by parallel work). Decision number: **R59+ when implemented** (recorded in
`alice-v1/00-decisions.md` by the phase that builds it). Migration and error-code numbers: the next free ones at merge
time. Roadmap and shared groundwork: [2026-10-21-deployment-targets-roadmap.md](2026-10-21-deployment-targets-roadmap.md).
Sibling designs: [Windows and IIS](2026-10-21-windows-iis-target-design.md),
[F5 BIG-IP](2026-10-21-f5-bigip-target-design.md).

The implementation proceeds on the recommended defaults of §15 once the owner approves them in advance, as for
[the scoped access design](2026-10-21-scoped-rbac-and-service-ownership-design.md).

## 1. Purpose and agreed understanding

Customers moving applications to Kubernetes (on premises with Rancher or OpenShift, or AKS, EKS, GKE) end TLS at an
ingress controller or a Gateway API implementation that reads its certificate from a **TLS Secret** in a namespace.
Many use cert-manager; many, especially with certificates from a corporate CA, DigiCert or Key Vault, paste Secrets by
hand. This design adds a **Kubernetes cluster** target: Alice writes TLS Secrets in the namespaces it is allowed into,
with the API server's optimistic concurrency as its compare-and-swap, verifies through the ingress endpoint, observes
drift, and stays out of the way of cert-manager and GitOps tools.

| Decision | Choice |
|---|---|
| What Alice writes | `Secret` objects of type `kubernetes.io/tls` (`tls.crt` = leaf and chain, `tls.key`), existing ones only in v1 (Q4). |
| What Alice never writes | Ingress, Gateway, Route or any workload object; Secrets managed by cert-manager, External Secrets, Sealed Secrets or a GitOps tool (§6.2). |
| API client | A small typed REST client over `net/http`; no `client-go` (Q6). |
| Authentication | A ServiceAccount token (Q2) with a least-privilege Role per namespace (§4.2); kubeconfig `exec`, `auth-provider`, file paths and `insecure-skip-tls-verify` are refused. |
| Server identity | The cluster CA bundle (from the kubeconfig) or the API server's SPKI pin (shared TLS pinning). |
| Location | One TLS Secret (kind `k8s_tls_secret`); its servers are the Ingress rules and Gateway listeners that reference it. |
| Compare-and-swap | `resourceVersion` precondition on update, plus the SHA-256 of `tls.crt` discovery saw. |
| Rollback | Alice keeps the previous `tls.crt` and `tls.key`, encrypted in its own database (the groundwork's Alice-held backup), and writes them back under the same precondition rule. |
| Verification | TLS probe of the ingress endpoint (load balancer address, SNI = host), polled until the controller picks the change up. |
| Target granularity | One target per cluster, with an allowlist of namespaces (Q3). |

## 2. Goals and non-goals

Goals:

- G1. Add a cluster with an API URL, a CA bundle or pin, a token and a namespace allowlist; show what the token may do
  (SelfSubjectRulesReview) and warn about excess rights.
- G2. Discover TLS Secrets in the allowed namespaces and what references them: Ingress (`networking.k8s.io/v1`),
  Gateway API listeners (`gateway.networking.k8s.io/v1`), with the host names and load balancer addresses.
- G3. Deploy (manually, ACME, Key Vault) by updating the Secret with the engine's outcome model.
- G4. Verify through the ingress or gateway endpoint (R51 levels), waiting for the controller's propagation.
- G5. Roll back under the R48 guard; fence an update that may arrive late.
- G6. Observe drift (R52): the Secret changed by someone else, or the endpoint serving another certificate.
- G7. Several clusters, each its own target, with services owning them as any target.
- G8. Test with an in-process fake API server, `envtest` and a nightly `kind` cluster with a real ingress controller.

Non-goals (cert-manager interplay explicitly):

- Replacing cert-manager, acting as a cert-manager issuer (external issuer, ACME server for the cluster), or writing
  cert-manager `Certificate` resources. Secrets cert-manager owns are discovery only; Alice reports them (expiry,
  issuer) but never writes them (§6.2).
- Restarting or rolling out workloads that mount a Secret as a file (Q7); Alice only updates the Secret.
- Creating Secrets an Ingress references but which do not exist, and editing Ingress or Gateway objects (Q4).
- OpenShift `Route` objects with inline certificates, Istio `credentialName` in the control plane namespace, service
  mesh workload certificates (later designs).
- The Secrets Store CSI driver, External Secrets, Sealed Secrets (discovery only: they own their Secrets).
- Cluster-wide access (`ClusterRole` on secrets in every namespace).
- Exec credential plugins (`aws-iam-authenticator`, `kubelogin`, `gke-gcloud-auth-plugin`): Alice never runs a binary
  named by a kubeconfig.

## 3. Vocabulary

| Term | Meaning |
|---|---|
| TLS Secret | `Secret` with `type: kubernetes.io/tls`, data `tls.crt`, `tls.key` (optional `ca.crt`, untouched). |
| Consumer | An Ingress rule (`spec.tls[].secretName` with its hosts) or a Gateway listener (`tls.certificateRefs`) that references a TLS Secret. |
| Endpoint | Where clients reach a consumer: the Ingress or Gateway `status` addresses (IP or host name) and port 443 (or the listener's port), with SNI = the host. |
| Owner marker | What says another tool manages a Secret: an owner reference to a cert-manager `Certificate`, cert-manager annotations, an `ExternalSecret` or `SealedSecret` owner, GitOps tracking labels or annotations (Argo CD, Flux), `immutable: true`. |
| Location | One TLS Secret (namespace and name). |

## 4. Authentication and least privilege

### 4.1 Credential

Accepted (Q2): a **ServiceAccount token** (the default: a long-lived token Secret of type
`kubernetes.io/service-account-token` for a dedicated ServiceAccount `alice` in a namespace the customer chooses,
revocable by deleting that Secret), or a client certificate and key. The Administrator pastes the API URL, the CA
bundle (or confirms the SPKI pin) and the token, or a kubeconfig from which Alice takes exactly those fields and refuses
the rest (`exec`, `auth-provider`, `tokenFile`, file paths, `insecure-skip-tls-verify`, `proxy-url` unless it matches
Alice's configured proxy). Stored as credential kind `k8s_token` or `k8s_client_cert`, purpose `kubernetes_cluster`.

Later (Q2): token rotation through the TokenRequest API (Alice requests a fresh bound token for its own ServiceAccount
before the current one expires; needs `serviceaccounts/token` `create` on itself), and Microsoft Entra workload
identity for AKS reusing Alice's Azure identity.

### 4.2 RBAC manifests (generated by Alice, applied by the customer)

Two profiles, rendered per namespace by the setup page from the target's allowlist (Q1):

**Strict (default)**: Alice can read and write only the Secrets it was told about, and lists only objects that carry no
secret data.

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: { name: alice-certificates, namespace: shop }
rules:
  - apiGroups: [""]
    resources: [secrets]
    resourceNames: [shop-tls, api-tls]        # rendered from discovery's references; updated by re-applying
    verbs: [get, update, patch]
  - apiGroups: [networking.k8s.io]
    resources: [ingresses]
    verbs: [get, list]
  - apiGroups: [gateway.networking.k8s.io]
    resources: [gateways]
    verbs: [get, list]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: { name: alice-certificates, namespace: shop }
roleRef: { apiGroup: rbac.authorization.k8s.io, kind: Role, name: alice-certificates }
subjects: [{ kind: ServiceAccount, name: alice, namespace: alice-system }]
```

Discovery in strict mode lists Ingresses and Gateways, collects the Secret names they reference, and reads those it
may `get`; names it may not read are shown with the line to add to the Role (`kubernetes.secret_not_granted`).

**Wide (opt-in)**: `get, list, update, patch` on `secrets` in the namespace (no `resourceNames`), so discovery also finds
TLS Secrets no consumer references. The security analysis states the cost: `list` returns every Secret's data in the
namespace (database passwords included), so a compromise of Alice exposes them. Alice lists with
`fieldSelector=type=kubernetes.io/tls` and keeps nothing of other Secrets, but RBAC cannot enforce that.

Neither profile has `delete` or `create` on secrets, nor any verb on workloads. `TestConnection` runs a
SelfSubjectRulesReview per namespace and warns about anything beyond the profile (`kubernetes.excess_rights`, for
example `cluster-admin`).

## 5. Data model

On the shared groundwork:

- `targets.type`: `kubernetes` (provider kind `kubernetes`). `targets.config`: `api_url`, `namespaces` (1 to 100,
  required), `rbac_profile` (`strict` | `wide`), `ingress_classes` (optional filter), `propagation_timeout_seconds`
  (default 120, 30 to 600).
- Credential kinds `k8s_token`, `k8s_client_cert`, purpose `kubernetes_cluster`; the CA bundle in `targets.config` (it
  is public), or the SPKI pin in `host_keys` (`tls-spki`).
- `certificate_locations.kind`: `k8s_tls_secret`; locator `{"namespace": "shop", "name": "shop-tls"}`; `cert_path`
  `shop/shop-tls`; `cert_file_sha256` the SHA-256 of `tls.crt`'s bytes; `servers` the consumers (`Names` the hosts,
  `Section` `Ingress/shop/web` or `Gateway/infra/public#https`, `Listens` the status addresses and port); `details`:
  `resourceVersion`, `uid`, owner markers, key PEM type (`PKCS1`, `PKCS8`, `SEC1`), `immutable`, whether `ca.crt` exists.
- `deployment_backups` (groundwork, Alice-held backups): the previous `tls.crt` and `tls.key`, envelope-encrypted like
  every private key in Alice, per deployment, deleted (zeroed and removed) 7 days after the deployment is final (Q5).
- `deployments.rollback_info`: `{"operation_id", "uid", "resource_version_before", "resource_version_after"}`.

## 6. Flows

### 6.1 Adding a cluster

Alice checks the API URL with the CA bundle or shows the SPKI for confirmation, reads `/version`, runs a
SelfSubjectRulesReview in each allowed namespace, and checks that the Ingress and Gateway APIs exist
(`/apis/networking.k8s.io/v1`, `/apis/gateway.networking.k8s.io/v1`). The setup page renders the RBAC manifest for the
chosen profile and namespaces (and again, with the Secret names discovery found, in strict mode).

### 6.2 Discovery (read-only)

Per namespace: list Ingresses and Gateways (status addresses, TLS hosts, Secret references, ingress class); in wide mode
list TLS Secrets; in strict mode get each referenced Secret Alice may read. For each Secret: parse `tls.crt` (bounded:
1 MiB, at most 20 certificates), link the leaf to inventory by fingerprint, check that `tls.key` matches the leaf
(public key comparison; the key is not kept). Unsupported locations (discovery only, with their reason):

| Reason | When |
|---|---|
| `k8s_cert_manager` | An owner reference to a cert-manager `Certificate`, or the annotation `cert-manager.io/certificate-name`. |
| `k8s_external_owner` | An owner reference to an `ExternalSecret`, `SealedSecret` or another controller. |
| `k8s_gitops` | Argo CD tracking (`argocd.argoproj.io/tracking-id` annotation or `app.kubernetes.io/instance` with Argo CD's instance label) or Flux labels (`kustomize.toolkit.fluxcd.io/name`, `helm.toolkit.fluxcd.io/name`): the next sync would undo Alice. An Administrator may override per location (Q8). |
| `k8s_immutable` | `immutable: true`. |
| `k8s_not_tls` | A referenced Secret of another type. |
| `k8s_cross_namespace` | A Gateway listener referencing a Secret in a namespace outside the allowlist (a `ReferenceGrant` case). |

A referenced Secret that does not exist is a location problem (`missing`) and shown; Alice does not create it in v1.

### 6.3 Deployment

1. Pre-check (the engine's) and a fresh `GET` of the Secret: `resourceVersion` and the SHA-256 of `tls.crt` must equal
   what the deployment planned against (otherwise `deployment.precondition`, nothing changed), the owner markers must
   still allow it, and `tls.crt` must not already be the new chain (`unchanged`).
2. Backup: the current `tls.crt` and `tls.key` stored encrypted in `deployment_backups` **before** the write (the
   R48 rollback columns record the replaced leaf and SPKI as for Nginx).
3. `PUT` the Secret with `metadata.resourceVersion` set to the value read (the API server refuses with `409 Conflict`
   if anything changed it in between), `?fieldManager=alice`, the new `tls.crt` (leaf then chain) and `tls.key` in the
   PEM type the old key had (PKCS #8 when unknown), every other key, label and annotation unchanged, plus the
   annotations `alice.io/operation` and `alice.io/fingerprint`. A `409` is `no_change` with `deployment.precondition`.
4. The answer's `resourceVersion` is recorded (`resource_version_after`).
5. Verification (§6.4); failure → rollback (§6.5).

Step names: `backup`, `write_secret`, then `verify`, `restore`, `verify_old`.

### 6.4 Verification and propagation

Ingress controllers watch Secrets and switch certificates without a restart (ingress-nginx serves certificates
dynamically, Traefik, HAProxy Ingress, Contour/Envoy through SDS, Gateway implementations similarly), but after a
delay of seconds to a minute. Pods that mount the Secret as a volume see the change after the kubelet's sync (about a
minute) and only if the application reloads it; a `subPath` mount never updates (a warning when discovery sees a pod
spec using one is out of scope, since Alice does not read pods).

The provider polls each endpoint of the location (status address, port, SNI = host) with fresh TLS sessions, backing off
from 2 s to 15 s, until the new leaf is served or `propagation_timeout_seconds` passes. Then the R51 rules: level 2
served, level 3 trusted, chain length compared with the deployed chain (the controllers send `tls.crt` as written).
Endpoints Alice cannot reach (a private load balancer, a `NodePort` setup) use the Administrator's probe address
(groundwork) or skip (level 1: the API read-back shows the new `resourceVersion` and data).

A consumer whose controller does not pick the change up (wrong ingress class, controller down) fails verification with
kind `certificate` (the old leaf still served) and rolls back.

### 6.5 Rollback, recovery and fence

- **Rollback**: Alice checks the R48 guard against the backup's leaf and SPKI before writing (no server restores by
  itself, so `Required` guards are always satisfiable); then `PUT` the backup data with `resourceVersion` =
  `resource_version_after`. A `409` means someone changed the Secret after Alice: nothing restored, `rollback_failed`
  with `file_changed`, as Nginx does for a changed file. The old certificate is then verified (`verify_old`).
- **Uncertain write** (the connection dropped after the `PUT` was sent): a `GET` decides: the new data with Alice's
  `alice.io/operation` = this operation → committed; the old `resourceVersion` → not applied yet.
- **Fence** (AUD-05): a write that could still reach the API server late carries the old `resourceVersion`
  precondition. The fence bumps the Secret's `resourceVersion` with a `PATCH` of one annotation
  (`alice.io/fence: <operation>`) under the old `resourceVersion`; afterwards the late `PUT` can only fail with `409`.
  If the fence itself gets `409`, the `GET` shows whether Alice's write landed (committed) or someone else's
  (`file_changed`).

### 6.6 Drift (R52)

The observation reads the Secret (the "file" fact: `tls.crt` hash and `resourceVersion`; a `resourceVersion` that moved
without a data change is not drift) and probes the endpoints (the "website" fact). Causes in notices: Secret data
replaced, owner marker appeared (cert-manager or GitOps took it over: the location becomes unsupported and its binding
holds, never repaired), consumer gone, endpoint serving another certificate (another controller, a default certificate).
Polling only in v1; a watch is a later optimisation.

### 6.7 Multiple clusters

Each cluster is its own target with its own credential, pin and namespaces; nothing is shared between clusters. The
same namespace name in two clusters is two locations (`cert_path` is per target). A certificate deployed to the same
host in several clusters (active-active) is several locations bound to the same certificate, verified per cluster
through each cluster's own endpoints (the probe address setting matters here, since the public name resolves to one of
them).

## 7. Provider (`internal/providers/kubernetes`)

- Kind `kubernetes`; capabilities `test_connection`, `discover_certificates`, `deploy_certificate`, `verify_deployment`.
- REST client over `net/http` with the groundwork's pinned TLS configuration: `GET`/`PUT`/`PATCH` of Secrets, list
  Ingresses and Gateways, SelfSubjectRulesReview, `/version`. Bounded answers (a list page at most 500 items with
  `continue`, each body at most 4 MiB), JSON decoded into Alice's own minimal structs; unknown API versions refused.
- The outcome rules of `providers` apply; the conformance suite runs against the fake.

## 8. Security analysis

| Threat | Mitigation |
|---|---|
| **Alice's token stolen** | Strict profile: only named TLS Secrets readable and writable, no `create`, `delete`, workloads or cluster scope; the token revocable by deleting its Secret; excess rights warned. |
| **Reading unrelated secrets** | Strict profile by default; wide mode is opt-in with the exposure stated on the setup page and in the security overview. |
| **Running code through a kubeconfig** | `exec` and `auth-provider` refused; no file paths followed. |
| **Man in the middle to the API server** | CA bundle or confirmed SPKI pin; `insecure-skip-tls-verify` refused; a changed pin blocks the target. |
| **Overwriting another tool's Secret** | Owner markers make the location discovery only; the precondition (`resourceVersion` and hash) refuses a Secret changed since the plan. |
| **Fighting a GitOps tool** | Discovery only by default; an override is per location, audited, and drift auto-repair backs off after three reverts (R52's rule). |
| **Old key kept by Alice** | Envelope-encrypted like every key Alice holds, deleted 7 days after the deployment is final; never downloadable. |
| **Rollback reinstalling a compromised key** | R48 guard checked by Alice before every restore write; the cluster never restores on its own. |
| **Secrets unencrypted in etcd** | The customer's control (EncryptionConfiguration); stated in the admin guide; not detectable by Alice. |
| **Data leaking through logs** | Secret data never logged; request logging prints method, path and status only. |

## 9. Verification levels (R51)

1 installed: the Secret holds the new data (API read-back) and verification is skipped. 2 served and 3 trusted: through
the endpoints after propagation. 4 reserved.

## 10. Failure modes

| Failure | Outcome |
|---|---|
| API unreachable, pin or CA mismatch | `kubernetes.unreachable`, `host_key_changed`; nothing sent. |
| Token expired or revoked (`401`) | `kubernetes.auth_failed`; target status `auth_failed`. |
| Not permitted (`403`) | `kubernetes.forbidden` with the missing verb and resource, before anything changed (SelfSubjectRulesReview at `Open`). |
| Secret changed since the plan (`409` or hash) | `no_change`, `deployment.precondition`. |
| Secret became managed by another tool | Refused before the write (`kubernetes.managed_elsewhere`). |
| Admission webhook or policy (Kyverno, Gatekeeper) refuses the write | `no_change` with `kubernetes.admission_denied` and the webhook's message (bounded, sanitised). |
| Write outcome unknown | `uncertain`, decided by a `GET` and, if needed, the fence. |
| Controller never picks the change up | Verification times out with the old leaf served: rollback. |
| Endpoint unreachable from Alice | `network` failure: rollback, unless the location uses a probe address or skip. |
| Someone changes the Secret during verification | Rollback finds `409`: `rollback_failed`, `file_changed`, notice. |
| API server load or throttling (`429`) | Retried with `Retry-After` within the budget. |

## 11. Test strategy

| Tool | What it gives | Cost | Use |
|---|---|---|---|
| In-process fake API server (`internal/testutil/fakekube`) | Fast, deterministic, fault injection (409, 403, 429, dropped answers, admission refusals), TLS listeners per Ingress endpoint serving the Secret's certificate after a configurable propagation delay. | Fidelity must be maintained: answer shapes recorded from `envtest` in `test/testdata/kube-recordings`, compared by a shape test; undocumented behaviour marked `GUESS`. | Provider unit tests, engine integration, e2e (`cmd/alice-fakekube`). |
| `envtest` (real `kube-apiserver` and `etcd` binaries, no controllers) | Real `resourceVersion`, `409`, field managers, RBAC with `--authorization-mode=RBAC`, SelfSubjectRulesReview, the strict manifest proven to work. | Binaries downloaded and pinned by SHA-256 in CI (about 100 MB); Linux only; no ingress, so no probe. | `integration` tag tests of the provider: the RBAC profiles, the CAS, the fence. |
| `kind` with ingress-nginx (and Traefik in a second run) | Real propagation and certificate switching, a real endpoint for the probe. | Docker, two to three minutes per cluster; images pinned by digest. | Nightly job: deploy, verify, roll back, drift; measures propagation for the default timeout. |

Real managed clusters (AKS, EKS, GKE, OpenShift) are an owner step before release (§15 Q9).

## 12. Phases

### Phase K1 — Connection and discovery (size M, ~6 tasks)

Groundwork items (TLS pinning, credential kinds, location kind and locator); `targets.type` `kubernetes`; the client;
kubeconfig import with refusals; `TestConnection` with SelfSubjectRulesReview; discovery with consumers and owner
markers; the RBAC manifest renderer; the fake's read half; UI: add a cluster, manifest, namespaces, locations with
consumers and reasons (TR/EN).

Acceptance:
- A kubeconfig with `exec`, a file path or `insecure-skip-tls-verify` is refused naming the field.
- In strict mode the generated manifest, applied in `envtest`, lets discovery read exactly the referenced Secrets;
  excess rights warn.
- cert-manager, External Secrets, GitOps and immutable Secrets are unsupported with their reason.

### Phase K2 — Deployment, verification, rollback (size L, ~8 tasks)

Backups table (groundwork), write with precondition, propagation polling, guarded rollback, uncertain recovery, fence,
step names, error codes; locations bindable to ACME and Key Vault certificates.

Acceptance:
- A deployment updates only `tls.crt`, `tls.key` and Alice's annotations; other keys, labels and annotations unchanged
  (envtest).
- A Secret changed between plan and write changes nothing; a late write after a fence fails with `409` (envtest).
- On `kind` with ingress-nginx: level 3 after propagation; a wrong ingress class rolls back; a forbidden backup restores
  nothing.
- The crash table passes on the fake.

### Phase K3 — Drift, multiple clusters, documentation (size M, ~5 tasks)

R52 observation and repair, owner-marker takeover handling, backup retention job, the admin guide "Kubernetes clusters"
(both RBAC profiles), security overview, `SECURITY-REPORT.md`, `06-quality.md` test IDs `K8S-01..`, traceability; the
nightly `kind` job.

Acceptance: a Secret replaced by hand is `drifted` and repaired in `auto`; a Secret taken over by cert-manager stops
being a deployable location and its binding holds; two clusters with the same namespace and Secret names stay apart.

### Phase K4 — Later, on demand

Token rotation through TokenRequest; AKS workload identity; creating referenced missing Secrets (Q4); OpenShift Routes;
Gateway `ReferenceGrant` across namespaces; a watch instead of polling.

## 13. Interactions with other work

- Scoped access: a cluster is one target in one service; a service per namespace would need per-location ownership,
  a later question (Q3).
- License: discovery ClassReadOnly, deployment ClassChange, automatic deployment and drift repair ClassContinuity.
- Key Vault: customers using the Secrets Store CSI driver with Key Vault already get renewed certificates through Key
  Vault; Alice manages the vault, not the CSI copy (discovery shows the Secret as externally owned).

## 14. Facts to confirm in Phase K1

| # | Fact | If it is wrong |
|---|---|---|
| F1 | `resourceNames` restricts `get`, `update`, `patch` on Secrets as designed, and `list` with a field selector still needs unrestricted `list`. | Adjust the strict profile. |
| F2 | ingress-nginx and Traefik pick up an updated Secret within 60 s by default. | Raise the default propagation timeout. |
| F3 | Argo CD and Flux markers listed in §6.2 are the ones current releases set. | Update the marker list. |

## 15. Open questions for the owner (the implementation proceeds on the default)

| # | Question | Recommended default |
|---|---|---|
| Q1 | RBAC profile by default: strict (named Secrets) or wide (all Secrets of the namespace)? | **Strict**; wide is opt-in with the exposure stated. |
| Q2 | Credential: long-lived ServiceAccount token, client certificate, or rotated bound tokens? | **Long-lived ServiceAccount token** (revocable, works on every distribution) in v1; TokenRequest rotation and AKS workload identity later. Exec plugins never. |
| Q3 | Target granularity and license: one target per cluster or per namespace? | **One target per cluster** with a namespace allowlist; a pricing decision for the owner. |
| Q4 | May Alice create a TLS Secret that an Ingress references but which does not exist? | **No in v1** (shown as a problem); later behind a per-target switch with `create` in the Role. |
| Q5 | Alice-held backups of the previous key: how long? | **7 days after the deployment is final**, then zeroed and deleted. |
| Q6 | Use `client-go`? | **No**: a dozen REST calls do not justify the dependency tree; a small typed client keeps the supply chain and binary small. |
| Q7 | Restart workloads that mount the Secret? | **No** (non-goal); the deployment page notes that mounted copies update on the kubelet's schedule. |
| Q8 | Secrets tracked by Argo CD or Flux: refuse, or allow per location? | **Refuse by default; an Administrator may allow a location** (audited), for customers whose GitOps ignores Secret data. |
| Q9 | Which distributions are tested before release? | **kind and envtest in CI; AKS and one on-premises distribution (Rancher or OpenShift) by the owner.** |
