# Alice Security Report

This report follows the structure of spec §17.6 (`docs/superpowers/specs/alice-v1/04-security.md`). Every statement
names its evidence: a test (`package:TestName`), a `make` target, a review note in `docs/security/reviews/`, or a
decision (R-number in `docs/superpowers/specs/alice-v1/00-decisions.md`, R43 row of the Phase 8 plan, or a pre-flight
ruling S-/M-number of Phase 8). Where no test or review stands behind a result, the cell says so:
`PENDING-FINAL-RUN` (a gate that the final release run fills in), `NOT RUN (owner)` (a gate run only by the owner or
a CI runner), or an empty table that the owner fills in. Nothing in an empty cell may be read as a pass.

## 1. Document metadata

| Field | Value |
|---|---|
| Product version | 1.0.0 (release candidate; this report is a draft until section 10 is signed) |
| Report date | 2026-10-11 (draft) |
| Commit | Release candidate da728cb1ccca868d09928926d22ffc9d55044291: the final Phase 8 gate run of 2026-10-12 (section 4; `docs/security/reviews/phase-8.md`). The release commit is recorded when 1.0.0 is built. |
| Authors | Eren Altan (vendor and developer); drafted with AI assistance from the phase reviews and the Phase 8 task reports |
| Reviewers | |
| Status | Draft. Not signed off. The release checklist (`docs/release-checklist.md`) is not ticked. |

## 2. Scope and methodology

### Scope

In scope: the `alice` binary (server, operator CLI, periodic tasks), the web UI it serves, `alice-helper` (the
root-run helper on managed servers), the release package (`install.sh`, `alice-update.sh`, `alicectl`,
`lib/alice-lib.sh`, the production `docker-compose.yml`, the two container images, the PostgreSQL role script,
SBOMs, notices, checksums and signatures) and the customer documentation in `docs/`. `licensectl` is in scope as a
vendor tool; it is never shipped to customers.

Out of scope for version 1 (spec §14.5): a malicious Administrator acting within granted powers; physical host
compromise with live memory access; side-channel attacks; compromise of the customer's identity provider beyond
group mapping.

### Method

- **Threat model:** STRIDE per component on the data-flow diagram of spec §14 (assets A1–A9, actors, trust
  boundaries, per-component threats with residual ratings). Section 7 lists the residuals.
- **Security review gate per phase** (spec §17.2): one review note per phase, each with findings, known
  limitations and an owner-verification table: [Phase 1](docs/security/reviews/phase-1.md),
  [Phase 2](docs/security/reviews/phase-2.md), [Phase 3](docs/security/reviews/phase-3.md),
  [Phase 4](docs/security/reviews/phase-4.md), [Phase 5](docs/security/reviews/phase-5.md),
  [Phase 6](docs/security/reviews/phase-6.md), [Phase 7](docs/security/reviews/phase-7.md) and the
  [audit remediation](docs/security/reviews/audit-remediation.md) of the independent audit of 2026-10-04. Phase 8
  (packaging and release) had a pre-flight security review (S-1..S-40) and a pre-flight scan (M-1..M-28) of its
  plan, and an independent review of every task; its review note is [phase-8.md](docs/security/reviews/phase-8.md).
- **Test types** of spec §17.3: authorization matrix, secret-leak canaries, rate limit and lockout, sessions, OIDC,
  crypto known-answer and tamper tests, audit chain, license, injection and fuzzing, failure injection, container
  inspection, backup and restore. The test matrices of spec §23–§25 are mapped ID by ID to the tests that prove them
  in [the traceability table](docs/security/traceability.md) (`make matrix-check`, in `make lint` with `-strict`): 202 IDs,
  of which 193 are proven by tests, 7 are proven in part (`partial`, each with a ruling), 2 are deferred by a ruling
  and none is a gap (section 7, KI-20; rulings G-1 to G-8 in `docs/superpowers/rulings/phase-8.md`).
- **Static and dynamic scanners**, pinned by version or digest (section 4 has the results):

| Tool | Version (pinned in the Makefile) | Run by | Gate (spec §17.1) |
|---|---|---|---|
| golangci-lint (gosec, staticcheck, govet, errorlint, forbidigo, gofmt, goimports) | v2.14.0 | `make lint` | any finding fails |
| govulncheck | v1.8.0 | `make vuln` | any reachable vulnerability fails |
| osv-scanner (go.mod, web lockfile) | v2.6.0 | `make osv` (part of `make vuln`) | any finding fails (stricter than §17.1) |
| npm audit (production dependencies) | toolchain npm | `make vuln` | High/Critical fail |
| Trivy fs and image; also the SBOM generator | aquasec/trivy:0.74.0 (by digest) | `make fs-scan`, `make image-scan`, `make sbom` | High/Critical with a fix fail |
| gitleaks | ghcr.io/gitleaks/gitleaks:v8.30.1 (by digest) | `make secrets-scan` | any finding fails |
| lockfile shape check (lockfile secret scan, R43 row 38) | in-tree `tools/lockcheck` | `make lockcheck` | any finding fails |
| ShellCheck | koalaman/shellcheck:v0.11.0 (by digest) | `make shellcheck` | any finding fails |
| actionlint | v1.7.12 | `make actionlint` | any finding fails |
| Pinning check | in-tree `tools/pincheck` | `make lint` | an unpinned build input fails |
| Fuzzing (`go test -fuzz`) | Go 1.27.2 | `make fuzz-nightly` (10 min per target), `make fuzz-release` (30 min per target) | a crash fails |
| Mutation testing | gremlins v0.6.0 | `make mutation` | advisory |
| OWASP ZAP baseline, API scan per role, full active scan | ghcr.io/zaproxy/zaproxy:2.17.0 (by digest) | `make zap-baseline`, `make zap-full` | Medium or higher fails |
| testssl.sh | ghcr.io/testssl/testssl.sh:3.2 (by digest) | `make testssl` | grade below A fails |

## 3. Security architecture summary

**Deployment.** One host runs Docker with the production compose project (`deploy/release/docker-compose.yml`):
`postgres` (internal `backend` network only, no published port, read-only root, all capabilities dropped,
uid 70), `alice` (uid 10001, read-only root, all capabilities dropped, `no-new-privileges`, core dumps off (compose setting, KI-18), the only
published port, 443 → 8443) and two one-shot services started only by the host scripts: `migrate` and
`alice-admin`. Proven by `cmd/alice:TestReleaseComposeIsHardened` and `deploy/release:TestReleaseRolesScript`.

**Database roles (R43 row 7, P1-01 closed).** `postgres` (superuser) is known only to the postgres container;
`alice_owner` (not superuser) owns the database and is used only by `migrate` and `alice-admin`; `alice_app` is the
only role of the running `alice` container, which holds no owner credential and refuses to start on a schema it did
not expect (`ALICE_MIGRATE=external`). Proven by `cmd/alice:TestAliceServiceHoldsNoOwnerCredential`,
`migrations:TestMigrationsRunAsNonSuperuserOwner`, `cmd/alice:TestServeRefusesAStaleSchemaWhenMigrationsAreExternal`.
Passwords reach the containers only as secret files (`ALICE_*_PASSWORD_FILE`).

**Keys.** A 256-bit master key (`keys/master.key`, 0400, a file on the host: KI-01) seals every stored secret
(platform SSH key, managed private keys, Azure credentials, SMTP and OIDC secrets) as envelopes with row-bound
associated data (Phase 1 crypto review, `docs/security/reviews/phase-1.md`). The recovery passphrase (16 characters
minimum, rated `good` or better by the server: `internal/setup:TestServerRefusesAFairPassphrase`) wraps the backup
private key with Argon2id. A backup is encrypted to the backup public key and authenticated by an installation
sender key (format 2, R43 row 41): `internal/backup/format:TestKnownAnswer` (independent Python cross-check recorded
in the Task 1 report), `TestForgedBackupWithCopiedWrappedKeyFails`, `internal/secrets:TestWrappedKeyV2BindsSender`.

**Backups and restore.** Daily encrypted backups inside the `alice` process (Go-native consistent dump, R43 row 1),
retention 14 (`internal/backup:TestF88Retention`), no plaintext in the file (`TestF87NoPlaintextInTheFile`). A
restore loads a fresh database, verifies it (audit chain, row counts, key check, installation seal) and swaps at one
point; any failure changes nothing (`TestRestoreIsAllOrNothing`, `TestF80WrongPassphraseChangesNothing`,
`TestF81FlippedByteChangesNothing`, `TestF82TruncatedChangesNothing`, `TestF83ForeignAndNewer`, `TestF85FullCycle`,
`TestF97RestoreContinuesTheChain`, `TestRestoreKeepsTheNewerTimeRecord`).

**Authentication and authorization.** Local accounts with Argon2id and mandatory TOTP, or OIDC (Phase 7); sessions
with CSRF protection and step-up for sensitive actions; four roles and two API token scopes. Every route has a
declared permission: `internal/api:TestAuthzMatrix`, `TestRoutePermissionsMatchSpec`, `TestPhase8RoutesAuthz`.

**Managed servers.** Alice reaches Linux and Nginx servers over SSH as `alice-svc` with pinned host keys
(`internal/jobs/targetjobs:TestChangedHostKeyBlocksEveryJob`) and a root helper behind a restricted sudoers profile
(Phases 3, 4 and 6). Whoever controls Alice controls those servers (KI-02, KI-03).

**Audit log.** An append-only SHA-256 hash chain in the database with daily verification, optional forwarding to
syslog over TLS with each entry's sequence and hashes (`internal/audit/forward:TestF92CheckpointIsForwarded`,
`TestF96ReceiverDownNeverBlocksTheLocalWrite`), and the head hash in every backup manifest (KI-05).

**Licensing.** Ed25519-signed license files bound to the installation ID, a sealed installation record and a
two-copy time record (Phase 2, audit remediation). Bypass by a host owner is an accepted residual (KI-04).

**Release integrity.** Release keys are separate from license keys (`make release-keycheck`). `SHA256SUMS` (every
file of the package) and the outer `.sha256` are signed offline with Ed25519 and checked with OpenSSL 3
(`cmd/licensectl:TestOpenSSLVerifiesReleaseSignatures`). The installer verifies before it changes anything, asks the
operator to compare the release-key fingerprint (`deploy/release:TestInstallNeedsTheFingerprintConfirmed`) and installs
from a root-only copy; the update verifies a copy with the already trusted keys and refuses tampered packages and
downgrades (`TestUpdateVerifiesACopy`, `TestUpdateRefusesTamperedAndDowngrade`, `TestSignatureChecks`). Release builds
contain no test endpoint, demo clock or test key (`cmd/alice:TestReleaseBuildHasNoTestEndpointsOrDemoClock`,
`TestReleaseBinaryLinksNoTestOrVendorCode`, `make release-symcheck`).

## 4. Scan results summary

Counts are by severity, Critical / High / Medium / Low, **as last run**: the final Phase 8 run on the release
candidate da728cb (2026-10-12); the release itself re-runs every gate on its commit (`make release-gates`); the raw outputs are kept in
`bin/release-gates.log`, which the package carries as `RELEASE-CHECKLIST-SIGNED.txt` (R43 row 51). The last column
shows the latest run recorded during Phase 8 development, for context only; it is not the release result.

| Scan | Command | C / H / M / L (final Phase 8 run) | Date | Latest development run |
|---|---|---|---|---|
| gosec and the other linters (golangci-lint) | `make lint` | 0 findings (every golangci-lint run "0 issues"; pincheck, ShellCheck, lockcheck, docs-check, matrix-check -strict, actionlint clean) (da728cb) | 2026-10-12 | 2026-10-11, Task 14: exit 0, every golangci-lint run "0 issues" |
| govulncheck | `make vuln` | 0 affecting the code (1 in a required module, not called) (da728cb) | 2026-10-12 | 2026-10-11, Task 14: 0 vulnerabilities |
| osv-scanner (go.mod, web lockfile) | `make osv` | 0 / 0 / 0 / 0 (da728cb) | 2026-10-12 | 2026-10-11, Task 14: 1 High (GHSA-68fv-2mgg-jv7q, source-map-js 1.2.1, development dependency) fixed in a4abe0f, then 0 |
| npm audit | `make vuln` | 0 vulnerabilities (da728cb) | 2026-10-12 | 2026-10-11, Task 14: 0 vulnerabilities |
| Trivy fs | `make fs-scan` | 0 / 0 (HIGH/CRITICAL; vulnerabilities and secrets) (da728cb) | 2026-10-12 | none recorded in Phase 8 |
| Trivy image (alice, postgres) | `make image-scan` | alice: 0 / 0 (HIGH/CRITICAL); postgres: not scanned by `make image-scan` (SBOM only) (da728cb) | 2026-10-12 | none recorded in Phase 8 |
| gitleaks (full history) | `make secrets-scan` | no leaks (11 false positives of Phase 8 allowlisted by fingerprint, 0ddf458) (da728cb) | 2026-10-12 | 2026-10-11, Task 15: 11 findings in older commits, all false positives (Task 19 triage) |
| gitleaks over the release tarball contents | release checklist row 1.5 | NOT RUN: no 1.0.0 package exists until the production keys are committed (owner) | | none recorded |
| Lockfile shape check | `make lockcheck` | clean (da728cb) | 2026-10-12 | 2026-10-11, Task 14: clean |
| ShellCheck (every tracked script) | `make shellcheck` | clean (da728cb) | 2026-10-12 | 2026-10-11, Task 14: clean |
| ZAP baseline, unauthenticated | `make zap-baseline` | 0 / 0 / 0 / 1 (Private IP Disclosure) (da728cb) | 2026-10-12 | 2026-10-11, Task 15: 0 High, 0 Medium |
| ZAP baseline and API scan as Administrator | `make zap-baseline` | 0 / 0 / 0 / 2 baseline (90004 COEP missing, Private IP Disclosure); API scan 0 / 0 / 0 / 3 (also 100001 Unexpected Content-Type) (da728cb) | 2026-10-12 | 2026-10-11, Task 15: 0 High, 0 Medium |
| ZAP baseline and API scan as Operator | `make zap-baseline` | 0 / 0 / 0 / 2 (90004, Private IP Disclosure) (da728cb) | 2026-10-12 | 2026-10-11, Task 15: 0 High, 0 Medium |
| ZAP baseline and API scan as Auditor | `make zap-baseline` | 0 / 0 / 0 / 2 (90004, Private IP Disclosure) (da728cb) | 2026-10-12 | 2026-10-11, Task 15: 0 High, 0 Medium |
| ZAP full active scan | `make zap-full` | NOT RUN (owner) | | |
| testssl.sh grade, release image (test-CA certificate) | `make testssl` | A+ (score 96) (da728cb) | 2026-10-12 | 2026-10-11, Task 15: A+ (score 96) |
| testssl.sh grade, release candidate on a real host | `make testssl TESTSSL_TARGET=… TESTSSL_CA=…` | NOT RUN (owner) | | |
| Fuzzing, nightly length | `make fuzz-nightly` | NOT RUN in Phase 8 (part of `make nightly`, not of `make release-gates`) | | each new Phase 8 target run 5 minutes by its task (R43 row 35) |
| Fuzzing, release length | `make fuzz-release` | NOT RUN (owner) | | |
| Matrix traceability, strict | `make matrix-check` with `-strict` | pass: 202 IDs, 193 test, 7 partial (ruled), 2 deferred, 0 gap (da728cb) | 2026-10-12 | 2026-10-11: 196 test, 1 deferred, 5 gap |

## 5. Dependency and SBOM summary

The package carries three CycloneDX SBOMs made by the pinned Trivy image (R43 row 26): `sbom/alice-<v>.cdx.json`
(the alice image), `sbom/postgres-<v>.cdx.json` (the postgres image) and `sbom/source-<v>.cdx.json` (go.mod and the
web lockfile), plus `licenses/THIRD_PARTY_NOTICES.md` generated by `tools/notices`. Proven by
`tools/releasebuild:TestStageLayout`.

Component counts. The 1.0.0 column is filled in when the 1.0.0 package is built with the production keys. The other column is read from the SBOMs of
the test-signed package `1.0.0-rc.1` built on 2026-10-11 (`bin/release/sbom-1.0.0-rc.1/`); it is not a release.

| SBOM | 1.0.0 | 1.0.0-rc.1 (test package) |
|---|---|---|
| alice image | not built yet (needs the production keys; owner) | 40 components: 33 Go modules, 5 Debian packages (distroless base), 1 operating system, 1 application |
| postgres image | not built yet (needs the production keys; owner) | 51 components: 45 Alpine packages, 4 Go modules, 1 operating system, 1 application |
| source (go.mod, web lockfile) | not built yet (needs the production keys; owner) | 126 components: 81 Go modules, 42 npm packages, 3 applications |

**Accepted vulnerabilities.** An exception needs an ID, a reason and an expiry at most 90 days away
(`osv-scanner.toml`, `docs/dev/dependency-updates.md`); a High or Critical finding with a fix is fixed, not ignored.
At the time of writing there is no exception: `osv-scanner.toml` lists none, there is no `.trivyignore`, and the ZAP
rules file `.zap/rules.tsv` holds no rule. The 90-day limit is checked by
review, not by a tool (Task 14 review M3).

| ID | Package or rule | Severity | Justification | Expiry | Source file |
|---|---|---|---|---|---|
| | | | | | |

**Supply-chain controls.** Build inputs pinned by version or digest (`tools/pincheck`); the web lockfile and `go.sum`
shape-checked so a secret cannot hide there (`tools/lockcheck`, R43 row 38); images loaded from the package and
compared by image ID, never pulled (R43 row 22). Residuals: KI-25.

## 6. Penetration test summary

No external penetration test has been performed yet (release checklist item; owner).

The independent audit of 2026-10-04 and its remediation are recorded in
[audit-remediation.md](docs/security/reviews/audit-remediation.md); it is not counted as the external penetration
test of spec §17.3 item 13. The table below is filled in when the external test has been run.

| Tester | Dates | Scope | Findings (C / H / M / L) | High/Critical closed and re-tested | Report reference |
|---|---|---|---|---|---|
| | | | | | |

## 7. Known issues and residual risks

Severity: the rating of the review that recorded the item (High, Medium, Low, Info). "Accepted" items are product
residuals; the others are open limitations or findings carried to a later version. Sources are in brackets. The
final release run re-checks every row against the release commit.

| ID | Description | Severity | Mitigation | Customer guidance |
|---|---|---|---|---|
| KI-01 | **Single-host key storage.** The master key is a file on the Alice host; anyone with root on the host or a copy of its disk and database reads every secret Alice holds. No boot passphrase, TPM or PKCS#11 in v1. [SS-2, R15] | High (accepted) | File mode 0400, dedicated uid, read-only container with all capabilities dropped (`cmd/alice:TestReleaseComposeIsHardened`), core dumps off in the compose; the keys directory is a separate mount point that can live on its own encrypted volume. | Full-disk encryption of the Alice host is **required**. Restrict root and `docker` group membership; keep backups off the host (section 8). |
| KI-02 | **Platform compromise, SSH targets.** Whoever controls Alice (or its database plus the master key) can sign in to every managed server as `alice-svc` and use the helper, which can write any listed account's `authorized_keys`, root's included. [P3-01, SC-6] | High (accepted) | Restricted sudoers profile; the helper validates every argument; host-key pinning; every action audited and forwardable. | Add the `from=` restriction to Alice's `authorized_keys` line on every server; forward the audit log to a SIEM; treat the Alice host as a tier-0 system. |
| KI-03 | **Platform compromise, Nginx certificates.** The same control lets an attacker deploy any certificate and key to every Nginx certificate/key pair Alice manages. [P4-01] | High (accepted) | The helper writes only pairs the Nginx configuration names, through root-controlled paths; every deployment audited; failure e-mails. | As KI-02. |
| KI-04 | **License bypass.** Binary patching, replacing the embedded key, clock manipulation with the master key, cloning, and restoring an older database plus state volume cannot be prevented on a host the customer controls. [§16.6, P2-01, P2-10 remaining bypasses, R-7, R-8] | Medium (accepted) | Signed licenses bound to the installation ID; sealed installation record; two-copy time record that a restore never lowers (`internal/backup:TestRestoreKeepsTheNewerTimeRecord`). | None needed; a bypass voids support and updates. |
| KI-05 | **Audit chain limits.** The chain is an unkeyed SHA-256 chain: whoever holds `alice_app` can append rows that verify and suppress the `audit.broken` e-mail (the verification state is writable by that role); someone with control of the whole host can cut the newest entries or put back an older database. A keyed chain is re-deferred to v2. [R43 row 32, P1-02, Phase 3 and Phase 7 limitations] | Medium | Alice holds no owner credential any more, so code execution in Alice cannot disable the append-only triggers (P1-01 closed, `cmd/alice:TestAliceServiceHoldsNoOwnerCredential`); syslog forwarding with each entry's `seq`, `hash` and `prev_hash` (`internal/audit/forward:TestF92CheckpointIsForwarded`); head hash in every backup manifest and on the dashboard. | Turn on audit forwarding to a collector Alice cannot write to; record the dashboard head hash outside Alice; investigate any gap in the forwarded sequence. |
| KI-06 | **Forwarding is at most once.** A returned TCP/TLS write is only in the kernel buffer, so a connection reset can lose messages; if saving the cursor fails after a send, that one batch is sent again. [R43 row 31, S-30, Task 7–8 review minor 6] | Low | Each message carries `seq` and `prev_hash`, so the collector sees a gap; the local log is authoritative and never waits for forwarding (`TestF96ReceiverDownNeverBlocksTheLocalWrite`). | Alert on gaps in `seq` at the collector; compare with **Verify integrity** in Alice. |
| KI-07 | **License clock heuristics.** A forward jump while Alice is stopped is not detected; a server clock set back more than about 30 s rejects authenticator codes until corrected; the 3-hour gate bound counts awake time. [P2-02, P2-05, R-7] | Low (accepted) | Time record with high-water mark; correction licenses. | Run NTP on the host. |
| KI-08 | **Trust on first use of server host keys.** An attacker between Alice and a new server at the moment it is added can present their own key. [P3-02, SC-1] | Medium (accepted) | Alice never pins without an Administrator's click and shows the command to read the fingerprint on the server; a changed key blocks every operation (`internal/jobs/targetjobs:TestChangedHostKeyBlocksEveryJob`). | Compare the fingerprint out of band before confirming a new server. |
| KI-09 | **Trust on first use of the release key.** The first install trusts the keys inside the package once their fingerprint is confirmed; later updates trust only already installed keys. [R43 rows 21, 43] | Medium | The installer prints the fingerprint and needs `yes` (or `--fingerprint` in unattended installs) (`deploy/release:TestInstallNeedsTheFingerprintConfirmed`); the install guide checks the outer signature with the vendor-published key first. | Compare the fingerprint with the one your vendor published on a separate channel; follow the three checks of the install guide before extracting. |
| KI-10 | **Database credentials on the host.** The owner password is a root-only file on the host and is present in the `migrate` and `alice-admin` containers while they run; the postgres container holds all three passwords; the image's entrypoint exports the superuser password into the postgres process environment; the `postgres` superuser can still log in over TCP from the internal network; the socket inside the postgres container is `trust`; PUBLIC keeps CONNECT and TEMP on the database; a role statement that failed during the very first initialisation could log its password. [R43 row 7 cost, Task 3 deviation 2, Task 3 review minors 4, 5, 6, 10] | Low | `secrets/` is root-only (0700); the backend network is internal; every TCP rule is SCRAM (`deploy/release:TestReleaseRolesScript`); the `alice` container holds only the application password. | Restrict root and `docker` group access; do not copy `secrets/` off the host except inside an encrypted backup of the host. |
| KI-11 | **Shallow backup check.** `alicectl backup verify` without `--deep` checks the header, the framing and the `.sha256` file; a file replaced together with its `.sha256` passes it. [R43 row 4] | Low | `--deep` decrypts everything with the passphrase; every restore and every update deep-verifies first (R43 rows 9, 44). | Once a month run `alicectl backup verify` with `--deep` on the newest file (operator guide). |
| KI-12 | **A restore needs room for two databases**, and a crash can leave a copy behind: after a crash between the swap and the cleanup, `<db>_previous_<ts>` stays until the next restore; a crash before staging on a fresh host leaves `<db>_restore` to drop by hand. [R43 rows 8, 46; Task 5 report] | Low | The restore refuses up front under 2 × the live database + 1 GiB of free space; backups refuse under 2 × the newest backup + 1 GiB; a cleanup never drops the only copy (`internal/backup:TestCleanupNeverDropsTheOnlyCopy`). | Keep free disk space; follow the operator guide after an interrupted restore. |
| KI-13 | **No "update in progress" banner.** Users see Alice disappear for a few minutes during an update. [R43 row 23] | Info | The update stops Alice, backs up, migrates and rolls back by itself on failure (`deploy/release:TestUpdateRollsBackWhenMigrationFails`). | Announce updates to users beforehand (upgrade guide). |
| KI-14 | **Backup forgery by an insider of the installation.** A compromised `alice` process, or anyone holding the database and `master.key`, holds the sender key and can build a backup that the passphrase opens; the passphrase holder can too (key-compromise impersonation, expected of the scheme). [R43 row 41, Task 1 review minor 7] | Medium | Format 2 is origin-authenticated: a file built from a copied wrapped key without the sender key is refused (`internal/backup/format:TestForgedBackupWithCopiedWrappedKeyFails`); a restore records the replaced audit head and the safety backup in `system.restored` (R43 row 45). | Restore only backups you made and stored write-protected off the host; investigate a restore you did not perform. |
| KI-15 | **The application role can re-point future backups and switch forwarding off.** `alice_app` can rewrite the `backup.key` and `audit.forwarding` settings: new backups would then open with another key, and forwarding could stop. [S-29] | Medium | Every update deep-verifies its pre-update backup with the real passphrase (R43 row 44); forwarding changes made through Alice are audited (`audit.forwarding_changed`); a collector sees forwarding stop. | Run the monthly `--deep` check (KI-11); alert at the collector when messages stop. |
| KI-16 | **Forwarding targets may be loopback or private addresses**, which gives a stepped-up Administrator a rate-limited, audited connection oracle from the Alice host. [S-31, accepted; R-6] | Low (accepted) | Link-local, metadata, multicast and unspecified addresses are refused (`ALC-AUD-0002`); the test is limited per user and audited. | None. |
| KI-17 | **The `docker` group can re-tag images** after the installer's image-ID check. [S-36, accepted] | Low (accepted) | Members of the `docker` group are root-equivalent anyway; install and update compare image IDs before they start anything (R43 row 22). | Keep the `docker` group to administrators of the host. |
| KI-18 | **Zeroing of key material is best effort.** Buffers Alice owns are cleared; Go strings, `big.Int` limbs, `*ecdh.PrivateKey` internals, AES key schedules and library and TLS buffers cannot be. [R43 row 53, S-28, P4-04 and its extensions in Phases 6 and 7, Task 4 review minor 13] | Low (accepted) | Core dumps disabled in the `alice` container (`ulimits: core: 0` in the production compose; not yet asserted by a test, Task 3 review minor 1). | Encrypt swap on the host (part of full-disk encryption). |
| KI-19 | **The binaries are reproducible; the images and the tarball are not** (image layers carry build metadata). [R43 row 52, S-38] | Info | `make reproducible-check` builds `alice` and both helper binaries twice from clean copies and compares the bytes; only a stage built on the release machine is signed, a CI stage is only compared (S-26). | A security team that rebuilds compares the binaries, not the images. |
| KI-20 | **Test matrix rows proven only in part, or deferred.** F-64 (PostgreSQL restarted under a running deployment job) and R-04's statistical timing test (P1-03) are deferred; A-10 (testssl is a gate, not a test), A-11 (the in-browser check under the CSP), A-12 (no SQL-injection sweep of every list, filter and sort parameter), F-65 (jobs pause and lose nothing after two minutes without the database), L-56 (R28's certificate-evidence clock warning is not built), R-07 (a server test connection has only the general limit) and S-06 (no scan of the packed tarball itself) are `partial`. [`docs/security/traceability.md`; rulings G-1 to G-8 of `docs/superpowers/rulings/phase-8.md`; Task 14 review I-1] | Low | Each partial row names the tests that prove the rest; parameterized SQL is enforced by `make lint` (gosec G201/G202); `make testssl`, `make secrets-scan`, `make fs-scan` and `make image-scan` are release gates; `make matrix-check -strict` in `make lint` fails on a gap or on a partial row without a ruling. | None; see the traceability table of the release. |
| KI-21 | **No rotation of the recovery passphrase or the master key in v1.** [R43 row 50, carry 18] | Medium | None in the product; backups stay readable only with the passphrase. | Protect the passphrase like the master key; an exposed passphrase plus a backup copy opens that backup, also every older one. |
| KI-22 | **Not verified on customer environments.** Nothing was run against Azure (Phase 5), a real identity provider or mail server (Phase 7), sshd variants beyond the three test containers (Phase 6), real systemd with Nginx before the real-systemd job, or real virtual machines (R43 row 28); the image IDs after `docker load` on a fresh engine (including Docker's containerd image store) are unconfirmed (F28). | Medium | Fakes and emulators with fidelity reviews; installs proven in three distributions' containers without network (release harness). | Treat these as not verified until the release checklist records them. |
| KI-23 | **An HTTPS certificate replacement can be left unaudited.** The new pair is live before the transaction that writes the audit row and the wizard choice; the transaction is retried once without the request's cancellation, and if the retry fails too the answer is an error, the new certificate stays in use and the log records `event=https.audit_failed` with the fingerprint (626df97, `internal/setup:TestCertificateInstallerLogsAnUnrecordedReplacement`). [Task 9 report deviation 2, Task 9 review M-2; re-checked by the final release run] | Low | The next read of the HTTPS settings shows the certificate in use; the log line names it. | Check **Settings → HTTPS** after an error during an upload. |
| KI-24 | **Development installations with a version 1 backup key make no backups** until the wizard runs again on a fresh database. [R43 row 41; owner item 5] | Info | `internal/backup:TestCreateRefusesV1BackupKey`; the dashboard shows the backup failing. | Not applicable to customer installations (no version 1 key was ever released). |
| KI-25 | **Supply-chain residuals.** The testcontainers Ryuk image and Playwright's browser download are not pinned (test tooling only); CI has never run on a remote (no remote exists yet); `pincheck` recognises only the forms it knows. [R-5, AUD-08, audit-remediation known limitations] | Low | The release is built from pinned inputs on the release machine; `make lint` runs `pincheck`. | None. |
| KI-26 | **Phase 1 findings still open.** Token-id existence visible through revoke timing; a sign-in over a full session does not revoke the old one; strict same-origin rule; raw startup and CLI error text; audit details guarded by a denylist; export and verify bounded only by the general limit; IPv6 sign-in limits per /64; someone who knows a username can keep it locked out within the caps. [P1-04, P1-05, P1-06, P1-07, P1-09, P1-10, phase-1 known limitations, AUD-25 (b)] | Low | As recorded in `docs/security/reviews/phase-1.md`. | Administrators unlock with **Set a new password** or `alice admin unlock` on the host. |
| KI-27 | **Phase 2 and vendor-side items.** Ledger tail removal not detectable from the ledger alone; `replaces` honoured for any license ID; `licensectl` is Unix-only. [P2-04, P2-07, P2-09] | Low (accepted) | Paper log of row count and chain head; yearly recovery test. | Not applicable. |
| KI-28 | **Phase 3 items.** The job payload MAC derives from the master key; LDAP/SSSD-only accounts are not inventoried; helper backups of `authorized_keys` stay up to 30 days; `Match Address`/`Match Host` blocks cannot be evaluated; key options are shown verbatim to every role that reads the inventory; accounts the helper skips are not reported. [P3-03, P3-05, P3-07, phase-3 known limitations, audit-remediation known limitations] | Low to Medium | As recorded in `docs/security/reviews/phase-3.md`. | Avoid secrets in `authorized_keys` options; see the operator guide. |
| KI-29 | **Phase 4 items.** Existence oracle under S7 for root-only files; sudoers `*` broader than the helper's argument check; a new key is as exposed as the old file's owner and group allow; a compromised service account can restore the latest kept operation; `tls-probe` can tell open from closed ports reachable from the server; a nested PFX key bag keeps an unchecked iteration count; host-name listens cannot be verified. [P4-02, P4-03, S5, S7, S10, phase-4 known limitations] | Low to Medium | As recorded in `docs/security/reviews/phase-4.md`. | Keep Nginx configuration and key files root-controlled; fix group-readable key files (`key_group_open`). |
| KI-30 | **Phase 5 items.** Managed identity lends the machine's identity to every Administrator who adds a vault; loopback and CGNAT addresses are dialled for a vault name; SDK strings hold secrets for a session; the import PFX uses 3DES/SHA-1 with an empty password; the e2e stack must never run on an Azure VM. [phase-5 known limitations] | Medium | TLS verifies the vault name; tokens never leave without it; outbound guard (P5-01..P5-04). | Give the identity only the roles of the Azure guide. |
| KI-31 | **Phase 6 items.** The test login proves authentication only; shared and symlinked `AuthorizedKeysFile` places are skipped or invisible; scheduled rotation needs working e-mail; the thirteen L1–L13 limitations. [phase-6 known limitations] | Low | As recorded in `docs/security/reviews/phase-6.md`. | Check servers kept on the old key after a run that needs attention. |
| KI-32 | **Phase 7 items.** A group removed at the IdP keeps an open session up to 12 hours; SSO start shares the sign-in limit; no plaintext SMTP; P7-29 accessibility items and 24 carried minors open; the OIDC nonce is stored in clear for at most 10 minutes. [P7-29, phase-7 known limitations] | Low | As recorded in `docs/security/reviews/phase-7.md`. | Disable a departing person in Alice as well as at the IdP. |
| KI-33 | **Audit-remediation items.** The activity marker is client-asserted; coalesced refusal counts live in memory; failed-credential buckets are shared behind one address; a small sign-in timing difference remains; glibc-only helper; every managed server needs the helper version that the Alice release expects before Alice works on it. [R-1, R-2, R-4, R-9, audit-remediation known limitations] | Low (accepted) | As recorded in `docs/security/reviews/audit-remediation.md`. | Set `ALICE_TRUSTED_PROXIES` behind a reverse proxy. |
| KI-34 | **Phase 8 review items still open.** Forwarding: control characters pass into syslog structured-data values, UDP messages up to 8 KiB fragment, the test message has no write deadline; TLS store: the keys directory needs hard links, PFX key-derivation and RSA size are not capped beyond 1 MiB (Administrator only); host scripts: `.update-<time>/` stays after a failed update until removed. [Task 7–8 review minors 3, 4, 5, 11, 12; Task 11 review minor 14; re-checked against the final release commit: all still open] | Low | Octet framing over TLS by default; Administrator with step-up for uploads; upgrade guide tells when to remove the directory. | Use TLS transport for forwarding. |
| KI-35 | **Not in version 1** (customer-visible). Download of TLS private keys; Microsoft Graph lookup for the Entra group overage; JSON-webhook forwarding; nuclei scanning; PDF documents; fewer helper scans per key change; bundled advisory files and the advisory banner of spec §17.4 (the package has no `advisories/` folder). [plan carries 15–17, 20; R43 rows 27, 31, 34 and addendum item 68; package layout C5, re-checked: no `advisories/` folder] | Info | Documented in the guides. | Use a syslog collector; use application-assigned groups in Entra. |

## 8. Customer hardening recommendations

1. **Host operating system.** Use a supported distribution (Ubuntu 22.04, Debian 12 or Rocky 9 with SELinux
   enforcing) and apply security updates regularly; reboot for kernel updates in a maintenance window.
2. **Full-disk encryption is required** (R15), including swap and the directory that holds `keys/`, `secrets/`,
   `data/` and `backups/` (KI-01, KI-18).
3. **Firewall.** Publish only the HTTPS port; allow SSH to the Alice host from administrators only; allow outbound
   traffic only to managed servers, Azure Key Vault, the identity provider, the mail server and the syslog collector
   that you use (`docs/install-guide.md`, "Firewall"). `install.sh --bind` restricts the published address.
4. **`from=` restriction.** Add `from="<Alice address>"` to Alice's line in every managed server's
   `authorized_keys` (KI-02).
5. **SIEM forwarding.** Turn on audit forwarding (syslog over TLS) to a collector Alice cannot write to; alert on
   gaps in the sequence and on silence (KI-05, KI-06, KI-15).
6. **Off-host backups.** Copy the daily backups to write-protected storage away from the host
   (`docs/backup-restore.md`), keep the recovery passphrase offline and apart from them, run the monthly `--deep`
   check, and rehearse a restore on a second server (KI-11, KI-14, KI-21).
7. **Docker socket and group.** Keep `/var/run/docker.sock` root-only (the installer refuses a socket others can
   write) and the `docker` group limited to host administrators (KI-17).
8. **Time.** Run NTP; set the host time zone before installing so the backup schedule follows it (KI-07).
9. **Release verification.** Verify every package with the vendor-published release key before you extract it, and
   compare the fingerprint the installer prints (KI-09).
10. **HTTPS certificate.** Upload your own certificate in the wizard or **Settings → HTTPS**; the temporary one is
    replaced every 90 days and browsers warn about it.

## 9. Security-relevant configuration and defaults

**Variables of the production compose** (`deploy/release/docker-compose.yml`; values from `.env`, written by
`install.sh`, which holds no secret: `cmd/alice:TestEnvTemplateHasNoSecret`).

| Variable | Services | Value or default | Security note |
|---|---|---|---|
| `ALICE_DATABASE_URL` | `alice`, `alice-admin` | `postgres://alice_app@postgres:5432/alice?sslmode=disable` | Application role, no password in the URL; internal network only. |
| `ALICE_DATABASE_PASSWORD_FILE` | `alice`, `alice-admin` | `/run/secrets/db_app_password` | Password from a secret file; a URL that already carries a password is refused. |
| `ALICE_MIGRATE_DATABASE_URL` | `migrate`, `alice-admin` | `postgres://alice_owner@postgres:5432/alice?sslmode=disable` | Owner role; never in the `alice` service (P1-01). |
| `ALICE_MIGRATE_DATABASE_PASSWORD_FILE` | `migrate`, `alice-admin` | `/run/secrets/db_owner_password` | As above. |
| `ALICE_MIGRATE` | `alice` | `external` | `alice` never migrates and refuses a schema other than its own. |
| `ALICE_TLS_HOSTS` | `alice` | from `install.sh --hostname` (default `hostname -f`) | Names of the temporary certificate. |
| `ALICE_TZ` | `alice`, `alice-admin` | host zone from `timedatectl`, else `UTC` | Backup schedule zone; `Local` is refused. |
| `ALICE_STATE_DIR` | `alice`, `alice-admin` | `/opt/alice/state` | License time record. |
| `ALICE_BACKUP_DIR` | `alice`, `alice-admin` | `/opt/alice/backups` | Encrypted backups only. |
| `ALICE_KEYS_DIR` | `alice-admin` (default in `alice`) | `/opt/alice/keys` | Master key 0400, TLS key 0400. |
| `ALICE_IMAGE`, `POSTGRES_IMAGE` | all | `alice:<version>`, `alice-postgres:<version>` | `pull_policy: never`; IDs compared with `RELEASE` before start. |
| `ALICE_BIND`, `ALICE_PORT` | `alice` | `0.0.0.0`, `443` | Only published port. |
| `COMPOSE_PROJECT_NAME` | all | `alice` | The installer refuses a project already in use. |

Variables not set by the production compose keep their defaults: `ALICE_LISTEN_ADDR` `:8443` inside the container,
`ALICE_LOG_LEVEL` `info`, `ALICE_TRUSTED_PROXIES` empty (no proxy is trusted).

**Settings stored by Phase 8** (C1 of the Phase 8 plan) and their defaults:

| Setting | Default | Security note |
|---|---|---|
| `backup.schedule` | `02:30`, zone `ALICE_TZ`, retention 14 (7–60) | Only `auto` backups are pruned, each deletion audited. |
| `backup.key` | written by the recovery-passphrase step; version 2 | Wrapped by the passphrase (Argon2id m=64 MiB, t=3, p=4); KI-15. |
| `backup.sender` (`setting_secrets`) | written by the recovery-passphrase step | Sender private key, sealed by the master key; KI-14. |
| `audit.forwarding` | off; transport TLS, port 6514 when turned on | The CA bundle is write-only; plain TCP or UDP only when chosen. |
| `setup.https_choice`, `setup.mail_choice` | unset until the wizard step | Not shown to anonymous callers after setup (`internal/api:TestSetupStatusAfterCompletionRevealsNothing`). |
| `jobs.heartbeat`, `backup.state`, `audit.forwarding.state` | written by Alice | Status only. |
| `backup.restore_id` | written by a restore | Crash-safe swap marker (R43 row 8). |

Other secure defaults (earlier phases, documented in `docs/admin-guide.md`): MFA required for local accounts,
session idle 30 minutes and absolute 12 hours, step-up for sensitive actions, API tokens at most 365 days,
backup download limited to 5 per minute and audited before the first byte
(`internal/api:TestBackupDownloadIsAuditedFirst`).

## 10. Sign-off

| Role | Name | Signature | Date |
|---|---|---|---|
| Developer | | | |
| Reviewer | | | |
| Vendor (release approval) | | | |
