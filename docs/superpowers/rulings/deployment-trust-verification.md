# Rulings: deployment verification proves trust

Owner approval 2026-10-20 (the work was approved while the owner was away; the defaults below were chosen during
execution and are recorded here for review). The gap: the Nginx provider's verification after a deployment
(`internal/providers/nginx/verify.go`) trusted only the served leaf's SHA-256 and the number of certificates presented
(`deployment.verify_chain`). A chain of the right length can still be wrong: another CA's intermediate, a chain that
leads to no trusted root, an expired intermediate, a name the certificate does not cover. Spec: R51 in
`docs/superpowers/specs/alice-v1/00-decisions.md`; user text in `docs/admin-guide.md` ("How Alice verifies a
deployment"), `docs/troubleshooting.md` (ALC-DEP-0026) and `docs/nginx-host-preparation.md` (helper 1.10.0).

## Every verification path

| Path | Where | Trust checked |
|---|---|---|
| Verification of the new certificate after the change (deploy job) | `nginx.deployment.verifyNew` → `VerifyDeployment` with `DeployRequest.Trust` | yes |
| The recovery's verification of a committed or unchanged journal | `deployjobs.verified` → `Material.VerifyRequest()` (carries `Trust`) | yes |
| The pre-check of the currently served certificate | `deployjobs.precheck` → `Material.PrecheckRequest()` | no: it only proves that Alice can check the website and what it serves; the old chain's trust is not this deployment's business |
| The previous certificate after a rollback (`verify_old`) | `nginx.session.checkOld` | no: an undo must not fail because the old chain was never trusted |
| Skipped verification (`skip_verify`) | `VerifyDeployment` returns at once | level installed, trust not measured |
| Alice's own probe (`remote`) and the in-target probe (`local`, `tls-probe`) | `probeOnce` | both: Alice's probe reports the presented chain, `tls-probe` from protocol 11 |
| Apache, HAProxy | discovery only (no `CapVerifyDeployment`) | not applicable |
| Key Vault deployments to Nginx | the same engine and provider | yes (the chain `KVDeployMaterial` filled) |
| Discovery probes (`internal/discovery/tlsprobe`) | out of scope; no code is shared | unchanged |

## The design as built

- `providers.CheckServedChain(served, policy, name, now)` verifies the served chain (DER, leaf first) with
  `crypto/x509`: roots from the policy only (a self-signed certificate the server sends is never an anchor),
  intermediates from the served chain only, the endpoint's server name, the probe time from the session clock, any
  extended key usage (as `certs.ChainComplete`). It returns `trusted`, `untrusted` with the first reason found, or
  `unchecked` for an empty chain.
- `providers.TrustPolicyFor(chain, roots, store, now)` builds the policy for the chain Alice deploys: a self-signed
  certificate at its end (a root uploaded with it, or a self-signed leaf) joins the roots; `Enforce` is whether that
  chain verifies against them (the anchor is known).
- `inventory.Material.TrustPolicy()` gives every request that verifies the new certificate its policy: the roots are
  `inventory.Config.Roots` (the system roots by default), with the ACME authority's `ca_bundle_pem` for a certificate
  an ACME order issued (the order of `acme_orders.certificate_id`, its certificate's provider), named `system`,
  `acme_bundle` or `uploaded_root`.
- `nginx.VerifyDeployment` judges every endpoint: the leaf and the chain length first (as before), then the trust. An
  enforced untrusted chain is `deployment.verify_untrusted` (params `port`, `trust_error`), measured again on every
  attempt like any other mismatch (old workers after a reload), and then rolled back by the existing path (the inline
  rollback with the R48 guard read again; the recovery's rollback). An untrusted chain that is not enforced, and a name
  mismatch, pass at level served with `Trust.Status` untrusted (a warning).
- `alice-helper` 1.10.0 (protocol 11): `tls-probe` answers `chain` (standard base64 DER, leaf first; at most 20
  certificates and 64 KiB of DER, else omitted). Alice reads at most 128 KiB of a probe answer. An answer without a
  chain, or whose chain disagrees with its own `chain_length`, leaves the trust `unchecked`.
- The record (`00026`): `deployments.trust_status`, `trust_error`, `trust_port`, `trust_store`, `trust_enforced`,
  written with the final update, for every status (a deployment rolled back for its chain keeps why). The level is not
  stored: `providers.VerificationLevel(verified, trust_status)` for a succeeded or unchanged deployment, none
  otherwise.
- API: `verification` {`level`, `trust` (null when not measured), `failure`} on every deployment; the verify step's
  params `trust` and `trust_error`; `ALC-DEP-0026`. Web: the deployment page's operation details show **Evidence**
  and **Certificate chain**; the outcome notice is a warning naming the fault for an untrusted success, adds "Alice also
  verified the website's certificate chain against a trusted root" for a trusted one and says when an older helper
  did not report the chain; the history marks an untrusted success with the warning tone; the technical panel names
  the kind of a failed verification.

## Rulings made during execution

1. **The trust anchor is "known" exactly when the chain Alice deploys verifies against the store.** The recommended
   default was "fail for ACME certificates whose anchor is known, warn for uploads from an unknown private CA". Tying
   it to the deployed chain itself gives that and more, without guessing from the source: an ACME certificate from a
   public CA (system roots) or from a private CA whose root is in the authority's CA bundle is enforced; an ACME
   authority without a bundle that issues from a private root is not (it was never trusted, so a rollback would only
   block its renewals); an upload from a public CA is enforced (Alice can prove the website should verify); an upload
   from a private CA with its root uploaded along is enforced against that root (`uploaded_root`); an upload from a
   private CA without its root (an incomplete chain an Administrator confirmed, F-17) is a warning. A deployment can
   therefore never be failed for a chain Alice itself could not verify.
2. **No new trust setting.** The ACME authority's CA bundle is already documented as "the root its issued
   certificates chain to" (it decides `chain_complete` for ACME certificates, A3) and the e2e journeys already paste
   the fake CA's issuing root into it. A per-target or global "custom CA bundle" for uploads was not added: an upload
   carries its own root when it is private, and `inventory.Config.Roots` stays the one installation-wide store.
   Deferred: an Administrator-managed extra trust bundle, if an installation needs to enforce trust for uploads from a
   private CA whose root it does not want to upload with each chain.
3. **A name mismatch is always a warning.** The name an endpoint is checked with comes from the server's
   configuration (`server_name`, else the certificate's first name, or the location's configured SNI), which the
   deployment did not change: an undo would not mend it, and failing would block every renewal of a website whose
   `server_name` lists a name the certificate never covered. It is checked last (only for a chain that verifies), so a
   name mismatch never hides a chain fault, and the level stays served.
4. **Wrong order is a fault, by the verified path.** The served intermediates must follow the order of a path
   `crypto/x509` verified (positions 1, 2, … of the chain; a root from the store need not be sent; extra certificates
   after the path are tolerated). Alice writes chains in order, so this catches a file someone else ordered differently.
5. **The precise reason is the first one found, in a fixed order:** unreadable (`invalid_chain`), the leaf's validity,
   an intermediate on the path out of its validity, `wrong_intermediate` (no certificate after the leaf issued it),
   `incomplete_chain` (the chain verifies once the deployed chain's intermediates are added), `unknown_authority`,
   any other x509 refusal (`invalid_chain`), `chain_order`, `name_mismatch`.
6. **The pre-check and the previous certificate's check after a rollback do not measure trust** (see the table). The
   trust is a property of the change being verified.
7. **An older helper is never a failure.** The in-target check of a helper before 1.10.0 cannot report the chain:
   the trust is `unchecked`, the level served, and the deployment page says that the chain was not checked. The helper
   protocol moves to 11; `MinProtocol` stays 6, so nothing else needs a reinstall.
8. **One timeout is not a verdict.** A connection of Alice's own probe that timed out no longer hands the endpoint to
   the server-side probe for the rest of the verification: the next attempt tries Alice's probe again (a refused
   connection or no route still does, as before, to keep the wait bounded). A failed handshake was already tried again.
   The bound stays `Options.Attempts` (5) attempts `RetryWait` (2 s) apart per endpoint. A failure records its kind:
   `network`, `certificate` or `trust` (`VerifyResult.Failure`; the API derives it from the stored reason).
9. **Level 4 is a hook, not a feature.** `providers.LevelHealthy` is reserved and documented; nothing measures it and
   the API's `level` never reports it yet.
10. **Numbers.** Migration `00026` (`00024` and `00025` are taken by parallel branches), error code ALC-DEP-0026 (the
    next free deployment code), decision R51 and helper protocol 11 / 1.10.0 may be renumbered when the branches are
    merged.

## Evidence

- Unit: `internal/providers/trust_test.go` (generated chains: good, with root, wildcard, no name, wrong intermediate,
  missing intermediate, wrong order, expired and not-yet-valid intermediate, expired leaf, name mismatch, unknown root,
  a self-signed root sent along, unreadable, empty; the policy builder; levels), `nginx/verify_trust_test.go` and
  `nginx/deploy_trust_test.go` (provider: levels, warnings, enforced failures with retries, in-target trust, an older
  helper, network versus certificate, a timeout measured again; a deployment rolled back for its chain),
  `cmd/alice-helper/probe_test.go` and the emulator fidelity test (the helper's chain), `helperproto` protocol 11,
  `internal/api/deployment_trust_test.go`, `web/src/components/DeploymentTrust.test.tsx` and
  `web/src/pages/DeploymentDetailPage.test.tsx`.
- Integration: `internal/jobs/deployjobs/trust_integration_test.go` (the record: trusted, an unknown anchor's warning,
  an uploaded root, an untrusted chain rolled back with its email, an older helper) and
  `migrations/deployment_trust_integration_test.go`.
