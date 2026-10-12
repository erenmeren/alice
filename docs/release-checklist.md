# Release Checklist

This checklist is the release gate of spec §17.7 and the exit criteria of spec §26.10
(`docs/superpowers/specs/alice-v1/04-security.md`, `06-quality.md`). A release is published only when every row
below has a result, a date and the initials of the person who checked it.

Rules:

- **Only the owner ticks.** The result, date and initials columns are filled in by the person named in the
  **Owner** column (or the vendor), never by a script or an assistant. An empty row is not done.
- **Class A** rows are automated gates that run on the release build machine (`bin/release-gates.log` keeps their
  output; the package carries it as `RELEASE-CHECKLIST-SIGNED.txt`). **Class B** rows need a person, a virtual
  machine, the production key, a CI runner or an outside party; their procedure is in the sections below.
- **Result** is `PASS`, `FAIL` (with a reference to the finding) or `N/A` with the reason. A `FAIL` blocks the
  release until fixed and re-run.
- `make release-gates` runs every class A gate that runs on one machine (`ci`, `matrix-check` with `-strict`,
  `reproducible-check`, `test-release`, `test-systemd`, `zap-baseline`, `testssl`, `test-backup-cycle`,
  `e2e-browsers`, `release-keycheck`) in that order and records each exit status in `bin/release-gates.log`; the
  production stage refuses the release unless every gate is recorded exactly once with exit 0. The Phase 8 review
  ([phase-8.md](security/reviews/phase-8.md)) records the development runs; they are not release results.

Release candidate: version ______ commit ______ (40 hex) built on ______ by ______

## 1. Pre-release checklist (spec §17.7)

| # | Item | How it is proven | Class | Owner | Result | Date | Initials |
|---|---|---|---|---|---|---|---|
| 1.1 | All CI gates green on the release commit (gofmt, vet, staticcheck, gosec, ESLint) | `make lint`, `make web-lint`, `make ci` on the release commit | A | Release engineer | | | |
| 1.2 | `govulncheck` reports no reachable vulnerability; `osv-scanner` and `npm audit` show no High/Critical with a fix | `make vuln` (runs govulncheck, npm audit and `make osv`) | A | Release engineer | | | |
| 1.3 | Trivy image and fs scans clean of High/Critical with a fix; exceptions recorded with expiry | `make fs-scan`, `make image-scan`; exceptions in [SECURITY-REPORT.md](../SECURITY-REPORT.md#5-dependency-and-sbom-summary) section 5 | A | Release engineer | | | |
| 1.4 | `gitleaks` clean on full history | `make secrets-scan` | A | Release engineer | | | |
| 1.5 | `gitleaks` clean on the release tarball contents | the gitleaks image of the Makefile (`GITLEAKS_IMAGE`) run as `docker run --rm -v <extracted package>:/scan:ro <GITLEAKS_IMAGE> dir /scan` on the extracted package | A | Release engineer | | | |
| 1.6 | SBOM generated for binary and images and included in the package | `make sbom` (run by `make release`); artefact: `sbom/` in the stage; `tools/releasebuild:TestStageLayout` | A | Release engineer | | | |
| 1.7 | Authorization matrix test passes for all routes; no route without a declared permission | `make test` (`internal/api:TestAuthzMatrix`, `TestRoutePermissionsMatchSpec`, `TestRouteTableMatchesSpec`, `TestPhase8RoutesAuthz`); `make authz-doc` leaves `docs/authz-matrix.md` unchanged | A | Release engineer | | | |
| 1.8 | Secret-leak-to-log test passes, including failure paths | `make test-integration` (the leak suites of `internal/api`, `internal/backup:TestF87NoPlaintextInTheFile`, `cmd/alice:TestSupportBundleHasNoSecrets`) | A | Release engineer | | | |
| 1.9 | Audit chain verifies after the full E2E run and after backup/restore | `make e2e`; `internal/backup:TestF97RestoreContinuesTheChain`; the release harness F-85 drill (`make test-release`, `TestReleaseF85Drill`) | A | Release engineer | | | |
| 1.10 | Backup → wipe → restore → verify passes; installation ID and license preserved | `make test-backup-cycle` (`TestF85FullCycle`); the release harness F-85 drill; on a VM: [section 4](#4-update-100--101-on-a-vm) step 3 | A + B | Release engineer; owner on the VM | | | |
| 1.11 | Update test from the previous release passes, including forced-failure rollback | the release harness update and rollback test (`make test-release`, `TestReleaseUpdateAndRollback`); on a VM: [section 4](#4-update-100--101-on-a-vm) | A + B | Release engineer; owner on the VM | | | |
| 1.12 | Update script rejects a tampered tarball and a downgrade | `make test` (`deploy/release:TestUpdateRefusesTamperedAndDowngrade`, `TestSignatureChecks`, `TestUpdateVerifiesACopy`); the release harness tamper test | A | Release engineer | | | |
| 1.13 | License tests pass: forged, wrong installation, rollback, jump, expiry, grace, lock; lock leaves data and targets untouched | `make test`, `make test-integration` (`internal/license`), `make fuzz-license`; IDs L-01..L-88 in [the traceability table](security/traceability.md) | A | Release engineer | | | |
| 1.14 | `licensectl` test vectors verify against the released binary; embedded public keys and key IDs match the vendor key register | `make release-keycheck`; compare the output of `alice license keys` (run in the installed container) with the vendor key register ([licensing-vendor.md](vendor/licensing-vendor.md#2-put-the-public-key-into-alice-builds-once-per-key)) | B | Vendor | | | |
| 1.15 | No debug endpoints, pprof, test accounts, default passwords or sample keys in the build; the demo-clock build is not shipped | `make release-symcheck`, `make image-check`; `cmd/alice:TestReleaseBuildHasNoTestEndpointsOrDemoClock`, `TestReleaseBinaryLinksNoTestOrVendorCode`; matrix row S-10 (partial, see [SECURITY-REPORT.md](../SECURITY-REPORT.md#7-known-issues-and-residual-risks) KI-20) | A | Release engineer | | | |
| 1.16 | Security headers and CSP verified on all responses | `make test` (`internal/api:TestSecurityHeadersOnEveryResponse`, `TestIndexGetsFreshNonceMatchingCSP`) | A | Release engineer | | | |
| 1.17 | `testssl.sh` grade A | `make testssl` (the release image on a disposable stack, certificate from a test CA); on a real host: [section 6](#6-long-gates) | A + B | Release engineer; owner on the host | | | |
| 1.18 | Container inspection: non-root, read-only FS, dropped caps, no DB port published, images pinned by digest | `make test` (`cmd/alice:TestReleaseComposeIsHardened`, `TestAliceServiceHoldsNoOwnerCredential`); `make image-check`; the release harness install matrix runs the hardening checks on the installed stack | A | Release engineer | | | |
| 1.19 | Rate-limit, lockout, session, CSRF and OIDC test suites pass | `make test-integration` (`internal/api`, `internal/auth`, `internal/auth/oidc`), `make fuzz-oidc`; IDs R-, S- and O- in [the traceability table](security/traceability.md) | A | Release engineer | | | |
| 1.20 | MFA cannot be bypassed; the wizard administrator is local + MFA; the recovery passphrase flow is tested | `make test-integration` (`internal/setup:TestServerRefusesAFairPassphrase` and the setup suite), `make e2e` | A | Release engineer | | | |
| 1.21 | A changed host key blocks operations; platform key removal is refused (UI and API) | `make test-integration` (`internal/jobs/targetjobs:TestChangedHostKeyBlocksEveryJob`), `make test-ssh`, `make e2e` | A | Release engineer | | | |
| 1.22 | Rotation failure-injection tests pass; an incomplete rotation never removes the old key | `make test-integration` (`internal/jobs/sshkeyjobs`, the rotation property test), `make test-ssh` | A | Release engineer | | | |
| 1.23 | Nginx deploy fault-injection tests pass and restore the original files | `make test-ssh` (real-Nginx matrix); `make test-systemd` | A | Release engineer | | | |
| 1.24 | Azure least-privilege table matches the code paths exercised (mock and real suite run) | mock: `make test-integration`; real: `make test-azure` against a real vault ([section 6](#6-long-gates)) | A + B | Owner | | | |
| 1.25 | Playwright E2E passes in English and Turkish; error messages contain no internal details | `make e2e`; three browsers: `make e2e-browsers` | A | Release engineer | | | |
| 1.26 | Penetration test findings High/Critical closed and re-tested | [section 7](#7-human-gates), external penetration test | B | Vendor; external tester | | | |
| 1.27 | `SECURITY-REPORT.md` completed and reviewed; residual risks updated | [SECURITY-REPORT.md](../SECURITY-REPORT.md) sections 4–7 filled, section 10 signed | B | Developer; reviewer | | | |
| 1.28 | Release notes list security fixes; advisory files updated in the package | `CHANGELOG.md` "Security" section of the release. Version 1 packages have no `advisories/` folder (package layout C5 of the Phase 8 plan): record `N/A` with that reason, or the advisory added | B | Developer | | | |
| 1.29 | `SHA256SUMS` signed offline with the release key; signature verified by `install.sh` on a clean machine | [section 3](#3-offline-signing-ceremony); [section 2](#2-vm-installs) (the installer verifies before any change) | B | Vendor | | | |
| 1.30 | Customer documentation covers hardening, key backup, passphrase custody and SIEM forwarding | `make docs-check`; [security-overview.md](security-overview.md), [backup-restore.md](backup-restore.md), [admin-guide.md](admin-guide.md); newcomer test in [section 7](#7-human-gates) | A + B | Developer; newcomer tester | | | |
| 1.31 | The package carries the notices of its two images and a written offer of the GPL/LGPL sources (final review B I-1; a release blocker for 1.0.0) | `make image-notices` (run by `make release`) writes `licenses/IMAGE_NOTICES.md` from the image SBOMs and the images' own files; the stage refuses a package without it (`tools/releasebuild:TestStageNeedsTheImageNotices`, `tools/notices:TestImageNotices`). The vendor reviews the offer's wording and closes the gaps the file reports: the rows "not in the images" (license texts the images do not carry, for example MIT and BSD notices of the Alpine packages) and the files in `/usr/local/bin` no SBOM component describes (PostgreSQL itself in the postgres image: its license text is in neither the SBOM nor the image) | B | Vendor | | | |

### Exit criteria of spec §26.10 not covered above

| # | Item | How it is proven | Class | Owner | Result | Date | Initials |
|---|---|---|---|---|---|---|---|
| 1.31 | The whole matrices of §23, §24 and §25 green | `make matrix-check MATRIXCHECK_FLAGS=-strict` (no gap, no partial row without a ruling); [the traceability table](security/traceability.md) | A | Release engineer | | | |
| 1.32 | ZAP baseline and API scan without Medium or High findings (unauthenticated, Administrator, Operator, Auditor) | `make zap-baseline` | A | Release engineer | | | |
| 1.33 | ZAP full active scan without Medium or High findings | `zap-full` target, [section 6](#6-long-gates) | B | Owner | | | |
| 1.34 | The release binary contains the production public keys and no test tags | `make release-keycheck` (fails until the production release and license keys are committed), `make release-symcheck` | A + B | Vendor | | | |
| 1.35 | Reproducible build check (the binaries; not the images or the tarball) | `make reproducible-check` on the release build machine | A | Release engineer | | | |
| 1.36 | Install on clean Ubuntu 22.04, Debian 12 and Rocky 9, also without network | the release harness install matrix (`make test-release`, `TestReleaseInstallMatrix`, containers with `--network none`); real VMs: [section 2](#2-vm-installs) | A + B | Release engineer; owner on the VMs | | | |
| 1.37 | Release fuzzing (30 minutes per target) without a crash | `make fuzz-release`, [section 6](#6-long-gates) | B | Owner | | | |
| 1.38 | No open High or Critical finding | `docs/security/reviews/phase-8.md` (written by the final release run) and every earlier review note | B | Reviewer | | | |
| 1.39 | Owner steps of every phase repeated once on the release candidate | [section 5](#5-owner-steps-of-every-phase-on-the-release-candidate) | B | Owner (coordinator) | | | |
| 1.40 | Known issues and residual risks in `SECURITY-REPORT.md` | [SECURITY-REPORT.md](../SECURITY-REPORT.md#7-known-issues-and-residual-risks) section 7 reviewed | B | Reviewer | | | |
| 1.41 | The vendor signs off | [section 7](#7-human-gates) | B | Vendor | | | |

## 2. VM installs

Use the final package and its three companions (`alice-<v>.tar.gz`, `.sha256`, `.sha256.sig`) and the vendor's
published release public key. On each VM, in this order:

1. Prepare a clean VM with Docker Engine 24 or newer and the compose plugin
   ([install-guide.md](install-guide.md#21-docker-engine-and-the-compose-plugin)). Nothing of Alice may be on it.
2. Copy the four files to the VM.
3. Verify the package as the customer does ([install-guide.md](install-guide.md#3-check-the-package-before-you-extract-it)):
   the fingerprint of the release key, `openssl pkeyutl -verify` of the `.sha256`, then `sha256sum -c`.
4. Install ([install-guide.md](install-guide.md#4-extract-and-install)):

   ```
   sudo mkdir -p /root/alice-1.0.0
   sudo tar --no-same-owner -xzf alice-1.0.0.tar.gz -C /root/alice-1.0.0
   sudo /root/alice-1.0.0/alice/install.sh --hostname <vm host name>
   ```

   Compare the printed fingerprint with the published one and type `yes`. Expected: the closing text with the
   address and the setup code, exit code 0.
5. Open the printed address and complete the wizard in Turkish on one VM and in English on the others
   ([first-run.md](first-run.md)): administrator, authenticator code, recovery passphrase, HTTPS certificate, mail
   server (skip is allowed), license (evaluation), first server.
6. Run `sudo /opt/alice/alicectl selfcheck`. Expected: seven `[ OK ]` lines and exit code 0.

On the first VM, also check that the image IDs survive `docker load` on a fresh engine (F28). The engine must be new
(no image of Alice loaded before), and note whether it uses Docker's containerd image store:

```
sudo docker image inspect --format '{{.Id}}' alice:1.0.0 alice-postgres:1.0.0
sudo grep -E '_IMAGE_(ID|DIGEST)=' /opt/alice/RELEASE
```

Expected: the alice ID printed by the first command equals `ALICE_IMAGE_ID` (classic image store) or
`ALICE_IMAGE_DIGEST` (containerd image store) of the second, and the postgres ID equals `POSTGRES_IMAGE_ID` or
`POSTGRES_IMAGE_DIGEST`. Record which of the two matched.

**Air-gapped variant.** Repeat steps 1–6 on one more VM of each distribution with outbound traffic blocked before
the install: either by the hypervisor's network (an isolated network with only the administrator's subnet), or on
the VM with `nft add rule inet filter output ip daddr != <admin subnet> drop` (after creating the `inet filter`
table with an `output` chain). Expected: the same results; the installer never needs the internet.

| VM | Distribution and version | SELinux | Network | Docker version (image store) | Package verified (step 3) | Install exit code | Wizard completed | `selfcheck` | Result | Date | Initials |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 2.1 | Ubuntu 22.04 | n/a | online | | | | | | | | |
| 2.2 | Debian 12 | n/a | online | | | | | | | | |
| 2.3 | Rocky 9 | **enforcing** (`getenforce` before the install) | online | | | | | | | | |
| 2.4 | Ubuntu 22.04 | n/a | outbound blocked | | | | | | | | |
| 2.5 | Debian 12 | n/a | outbound blocked | | | | | | | | |
| 2.6 | Rocky 9 | **enforcing** | outbound blocked | | | | | | | | |

| # | Check | Owner | Result | Date | Initials |
|---|---|---|---|---|---|
| 2.7 | First VM: image IDs after the installer's `docker load` on a fresh engine equal the IDs in `RELEASE` (F28); note the image store | Owner | | | |
| 2.8 | Rocky 9: no SELinux denial during install, wizard and `selfcheck` (`sudo ausearch -m avc -ts recent` prints nothing) | Owner | | | |
| 2.9 | Every VM: the installer's preflight line "Clock sane" is `[ OK ]` (the release harness containers have no `timedatectl` and prove only the `[WARN]` branch) | Owner | | | |
| 2.10 | First VM: "Port free" fails when the port is taken: start `sudo python3 -m http.server 443` in another terminal, run `install.sh` (expected `[FAIL]` naming the port, nothing changed), stop it and install (the harness containers see no host sockets) | Owner | | | |
| 2.11 | A VM whose engine uses the classic image store: the `ALICE_IMAGE_ID`/`POSTGRES_IMAGE_ID` branch matched (record it in 2.7; the harness engine proves only one branch) | Owner | | | |

## 3. Offline signing ceremony

Procedure of spec §17.5 and [licensing-vendor.md](vendor/licensing-vendor.md#signing-ceremony-every-release). The
release key never leaves the offline machine.

1. **Stage on the release build machine, from the signed tag.** Check out the signed release tag, run the release
   gates (their output goes to `bin/release-gates.log`), then `make release VERSION=1.0.0`. Never sign a stage built
   by CI.
2. **Compare with CI.** A CI-built stage is used only to compare: its `alice` and helper binaries must have the same
   SHA-256 as the local build (`sha256sum` of both stages' binaries), and `make reproducible-check` on the release
   build machine must print `reproducible-check: ok` (S-26, R43 row 52). The CI stage is then discarded.
3. **Publish the fingerprint.** The SHA-256 fingerprint of the release public key (`rk-YYYY-NN.pem`) is published on
   the vendor's channel (website and license e-mail) before the release; the install guide's first check compares
   against it.
4. **Sign the file list.** Carry `bin/release/alice-1.0.0/alice/SHA256SUMS` to the offline machine on a clean USB
   stick; run `licensectl release-sign` there; compare the SHA-256 it prints with `sha256sum SHA256SUMS` on the
   build machine; carry back `SHA256SUMS.sig` into the stage.
5. **Pack.** `make release-pack VERSION=1.0.0`.
6. **Sign the outer checksum** `alice-1.0.0.tar.gz.sha256` the same way, giving `alice-1.0.0.tar.gz.sha256.sig`.
7. **Verify on a third machine** (neither the build nor the offline machine) with only OpenSSL 3 and the published
   key:

   ```
   openssl pkeyutl -verify -pubin -inkey rk-2026-01.pem -rawin -in alice-1.0.0.tar.gz.sha256 -sigfile alice-1.0.0.tar.gz.sha256.sig
   sha256sum -c alice-1.0.0.tar.gz.sha256
   tar xzf alice-1.0.0.tar.gz alice/SHA256SUMS alice/SHA256SUMS.sig
   openssl pkeyutl -verify -pubin -inkey rk-2026-01.pem -rawin -in alice/SHA256SUMS -sigfile alice/SHA256SUMS.sig
   ```

   Expected: `Signature Verified Successfully` twice and `alice-1.0.0.tar.gz: OK`.

| # | Step | Evidence (artefact path or printed value) | Owner | Result | Date | Initials |
|---|---|---|---|---|---|---|
| 3.1 | Release tag signed and checked out on the release build machine | tag name and `git tag -v` output | Vendor | | | |
| 3.2 | Release gates recorded | `bin/release-gates.log` | Release engineer | | | |
| 3.3 | Stage built locally with `make release VERSION=<v>` | `bin/release/alice-<v>/` | Release engineer | | | |
| 3.4 | `make reproducible-check` ok; CI stage binaries equal the local ones | printed hashes | Release engineer | | | |
| 3.5 | Release key fingerprint published on the vendor channel | URL and fingerprint | Vendor | | | |
| 3.6 | `SHA256SUMS` signed offline; printed SHA-256 equal on both machines | `SHA256SUMS.sig` | Vendor | | | |
| 3.7 | `make release-pack` done; outer `.sha256` signed offline | `alice-<v>.tar.gz.sha256.sig` | Vendor | | | |
| 3.8 | Both signatures verified on a third machine with `openssl` | command output | Vendor | | | |

## 4. Update 1.0.0 → 1.0.1 on a VM

Owner step 5 of spec §26.10 with real packages. Use one VM from [section 2](#2-vm-installs) (or a new one installed
the same way) that runs 1.0.0, with a few users, a server and a certificate added.

Which key signs which package:

| Package | Built with | Signed by | Installable on |
|---|---|---|---|
| `alice-1.0.0` and `alice-1.0.1` (real releases) | `make release VERSION=<v>` on the release build machine | the production release key, in the ceremony of [section 3](#3-offline-signing-ceremony) | VMs installed from a production-signed package |
| Broken update for a production-key VM | `make release-broken VERSION=1.0.2-rc.1 BROKEN=fail SIGN=offline` (an unsigned stage with an extra migration that fails) | the production release key, in the ceremony (then `make release-pack VERSION=1.0.2-rc.1` and the outer signature) | the production-key VM only; never published to customers |
| Broken update for a test-signed VM | `make release-broken VERSION=1.0.2-rc.1 BROKEN=fail SIGN=test` | the test key in `bin/release-test-key/`, at build time | only a VM installed from a test-signed package of the same test key (`make release-test VERSION=1.0.0-rc.N`); the installer and the update print the TEST-key warning |

Steps (as root on the VM, files copied to `/root` with their `.sha256` and `.sha256.sig`):

1. Update to 1.0.1 ([upgrade.md](upgrade.md#run-the-update)):

   ```
   cd /opt/alice && sudo ./alice-update.sh /root/alice-1.0.1.tar.gz
   ```

   Expected: `Alice is now version 1.0.1.`, exit code 0, Alice back within a few minutes, the same data, and
   `sudo /opt/alice/alicectl selfcheck` all `[ OK ]`.
2. Run the broken update:

   ```
   cd /opt/alice && sudo ./alice-update.sh /root/alice-1.0.2-rc.1.tar.gz
   ```

   Expected: `The update to 1.0.2-rc.1 failed and Alice was returned to 1.0.1. …`, exit code 1, Alice running 1.0.1
   by itself with the same data, `selfcheck` all `[ OK ]` ([upgrade.md](upgrade.md#when-the-update-fails)).
3. Back up, then restore on a second empty VM (owner steps 3 and 4): `sudo /opt/alice/alicectl backup`, copy the
   file and prepare the second VM with `install.sh --restore-mode`, then restore it there with the passphrase
   ([backup-restore.md](backup-restore.md#restore-on-a-new-server)); once with a wrong passphrase first.

| # | Step | Owner | Exit code and message | Result | Date | Initials |
|---|---|---|---|---|---|---|
| 4.1 | 1.0.0 → 1.0.1 with the real packages | Owner | | | | |
| 4.2 | Broken update returns to 1.0.1 by itself | Owner | | | | |
| 4.3 | Data, users and license unchanged after 4.1 and 4.2 | Owner | | | | |
| 4.4 | Restore on a second empty VM: same data, same license, same installation ID | Owner | | | | |
| 4.5 | Restore with a wrong passphrase fails with a clear message and changes nothing | Owner | | | | |

## 5. Owner steps of every phase on the release candidate

The coordinator repeats every phase's owner steps once on the release candidate (spec §26.10 exit criteria). Each
row points to that phase's owner table; record the outcome here and in that table.

| # | Phase | Owner table | Owner | Result | Date | Initials |
|---|---|---|---|---|---|---|
| 5.0 | Phase 0: skeleton and CI | [spec §26.2](superpowers/specs/alice-v1/06-quality.md#262-phase-0-skeleton-and-ci) "Owner verifies" | Coordinator | | | |
| 5.1 | Phase 1: core (auth, MFA, RBAC, audit, secrets) | [phase-1.md](security/reviews/phase-1.md#owner-verification) | Coordinator | | | |
| 5.2 | Phase 2: licensing | [phase-2.md](security/reviews/phase-2.md#owner-verification) | Coordinator | | | |
| 5.3 | Phase 3: Linux servers over SSH | [phase-3.md](security/reviews/phase-3.md#owner-verification) | Coordinator | | | |
| 5.4 | Phase 4: Nginx certificates | [phase-4.md](security/reviews/phase-4.md#owner-verification) | Coordinator | | | |
| 5.5 | Phase 5: Azure Key Vault | [phase-5.md](security/reviews/phase-5.md#owner-verification) | Coordinator | | | |
| 5.6 | Phase 6: SSH key rotation | [phase-6.md](security/reviews/phase-6.md#owner-verification) | Coordinator | | | |
| 5.7 | Phase 7: alerts, dashboard, SSO | [phase-7.md](security/reviews/phase-7.md#owner-verification) | Coordinator | | | |
| 5.7a | Audit remediation | [audit-remediation.md](security/reviews/audit-remediation.md#owner-verification) | Coordinator | | | |
| 5.8 | Phase 8: packaging and release | [spec §26.10](superpowers/specs/alice-v1/06-quality.md#2610-phase-8-packaging-and-release) "Owner verifies" 1–6, and the owner table of `docs/security/reviews/phase-8.md` | Coordinator | | | |

## 6. Long gates

| # | Gate | Command | Where | Owner | Result | Date | Initials |
|---|---|---|---|---|---|---|---|
| 6.1 | ZAP full active scan, no Medium or High | `make zap-full` | a disposable stack of the release candidate | Owner | | | |
| 6.2 | Release fuzzing, 30 minutes per target (about 7 hours), no crash | `make fuzz-release` | release build machine or CI | Owner | | | |
| 6.3 | Playwright on three browsers in EN and TR, WebKit included | `make e2e-up && make e2e-browsers; make e2e-down` | a machine where WebKit starts | Owner | | | |
| 6.4 | testssl.sh grade A on a real host with the customer-like certificate | `make testssl TESTSSL_TARGET=<host>:443 TESTSSL_CA=<ca file>` | the release candidate on a VM of [section 2](#2-vm-installs) | Owner | | | |
| 6.5 | First run of the nightly workflow | `.github/workflows/nightly.yml` after a git remote exists | CI | Owner | | | |
| 6.6 | First run of the release workflow | `.github/workflows/release.yml` (record each job's duration: none was measured yet) | CI | Owner | | | |
| 6.7 | Real-Azure suite | `make test-azure` against a real vault ([azure-setup.md](azure-setup.md)) | owner's tenant | Owner | | | |

## 7. Human gates

| # | Gate | Evidence | Owner | Result | Date | Initials |
|---|---|---|---|---|---|---|
| 7.1 | External penetration test before 1.0 (spec §17.3 item 13); High/Critical findings closed and re-tested | tester's report; [SECURITY-REPORT.md](../SECURITY-REPORT.md#6-penetration-test-summary) section 6 filled | Vendor; external tester | | | |
| 7.2 | Newcomer test: someone who has never seen Alice installs it and finishes the wizard with only [first-run.md](first-run.md) and the install guide | notes of the tester | Owner; newcomer tester | | | |
| 7.3 | Turkish tone review of every user-visible text by a native speaker | reviewer's notes | Owner; Turkish reviewer | | | |
| 7.4 | Peer crypto review of the backup format 2 with its sender key (R43 row 41) | reviewer's notes on `internal/backup/format` and `internal/secrets` (backup key) | Reviewer | | | |
| 7.5 | Peer crypto review of the release signing (Ed25519 raw signatures over `SHA256SUMS` and the outer `.sha256`, key separation) | reviewer's notes on `cmd/licensectl` and the host scripts' check | Reviewer | | | |
| 7.6 | `SECURITY-REPORT.md` signed (developer, reviewer) | [SECURITY-REPORT.md](../SECURITY-REPORT.md#10-sign-off) section 10 | Developer; reviewer | | | |
| 7.7 | Vendor sign-off: every row of this checklist has a result, a date and initials | this file, signed below | Vendor | | | |

Vendor sign-off: name ______ signature ______ date ______
