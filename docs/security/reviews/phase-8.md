# Security Review — Phase 8 (Packaging and release)

Scope (spec §17.2, Phase 8: "installer, update script, signature verification, backup/restore, the deployment's least
privilege"; gate: "Release checklist (17.7) complete; SECURITY-REPORT.md signed off"; §26.10): `install.sh`,
`alice-update.sh`, `alicectl` and `lib/alice-lib.sh`; the production compose with its PostgreSQL roles; the encrypted
backup container, the dump, the backup service and the restore; the operator CLI (`alice backup|restore|selfcheck|
support-bundle`); the HTTPS certificate store and the wizard's HTTPS and mail steps; audit forwarding to syslog; the
release package, its signatures, SBOMs and notices; the static and dynamic gates (osv-scanner, lockfile shape,
ShellCheck, actionlint, the matrix traceability, ZAP, testssl, the real-systemd job, three browsers, mutation testing).

**Nothing in this phase was run on a real virtual machine, with the production release or license key, on a git
remote or by the owner.** Installs, backups, restores and updates ran from real packages inside Ubuntu 22.04, Debian 12
and Rocky 9 containers without network that drive the host's Docker engine (`make test-release`); signatures used keys
generated at test time (`rk-test-NN`, `TEST_SIGNED=1`); the real-systemd job ran in one privileged container; ZAP ran
passive and API scans only; testssl graded the release image with a certificate from a throw-away test CA. "Known
limitations" and the owner tables at the end list what that leaves open.

The decisions behind this phase are R43 in `docs/superpowers/specs/alice-v1/00-decisions.md` (items 1–53 and the
addendum 54–69; numbers in brackets below). The controller's rulings, with what each costs if wrong, are in
`docs/superpowers/rulings/phase-8.md`.

## Method

The phase was built in 19 tasks on branch `phase-8` (base `master` 8d681a7, plan 95b2563, pre-flight amendments
e1682c2). Before Task 1 a pre-flight security design review (S-1 to S-40: 2 BLOCK, 24 FIX, 14 NOTE) and a consistency
scan (M-1 to M-28 and the cosmetic rows) were ruled on; the two BLOCK findings changed the design (S-1: the restore ID
and one swap point; S-2: origin-authenticated backups, container format 2). Every task was reviewed by an agent that
did not write it; findings went back as fix rounds that were reviewed in scope. Several reviewers (Tasks 1, 5, 10,
14, 15) mutated code to see named tests turn red; the long harnesses were re-run in full after their fix rounds
(`make test-release` after f0206d7, the ZAP and testssl gates after Task 15's fixes, the three-browser suite after
Task 16's); the leak suites search answers, logs, tables, job parameters, support bundles and the backup file for
canaries.

Task 19 closed the matrix gaps (new tests for L-56/L-57, S-10 and A-11; the status `partial` with rulings G-1 to G-8),
set the coverage floors, folded the open review minors it owned (Task 16 M-1, M-2), triaged the gitleaks findings of
the history and ran the final gates. This review was written before the final whole-branch review; the controller adds
that review's outcome to the rulings.

## Evidence

All commands run from the repository root on the development machine (Arch-based, 4 CPUs, Docker 29.9.0 with the
containerd image store, cgroup v2), with nothing else using Docker. "Development runs" are the latest results the
implementers recorded in their task reports, with the commit named. "Final run" is the run of Task 19 on the commit
named in the cell; `make release-gates` writes `bin/release-gates.log`. `NOT RUN (owner)` and `NOT RUN (CI)` cells are
never a pass.

| # | Check | Command | Expected | Development runs | Final run |
|---|---|---|---|---|---|
| 1 | Unit tests, all packages, race detector | `make test` | ok | ok per package in every report | ok, every package (inside `make ci`, da728cb, 2026-10-12) |
| 2 | Integration tests, all packages | `make test-integration` (run inside `make coverage`) | ok | ok per package in every report | ok, every package (inside `make coverage`, da728cb); the two restore-test flakes fixed in 3d4bcaa and da728cb, the `sshkeys` one in a269e42 |
| 3 | F-85 full cycle with a test license | `make test-backup-cycle` | `--- PASS: TestF85FullCycle` | ok (Task 5, Task 15) | `--- PASS: TestF85FullCycle` (in `make ci` and as its own gate, da728cb) |
| 4 | Release harness: install matrix, F-85 drill, restore negatives, update and rollback (F-68), tampered and downgrade, uninstall | `make test-release` | every subtest PASS | ok in 1104 s after f0206d7 (Task 13 fix) | ok in 1027.9 s (da728cb): `TestReleaseInstallMatrix` (ubuntu22, debian12, rocky9), `TestReleaseF85Drill`, `TestReleaseRestoreNegatives` (10 cases), `TestReleaseUpdateAndRollback` (failing-migration, killed-migration, stopped-before-change), `TestReleaseRefusesTamperedAndDowngrade` (3 cases), `TestReleaseUninstallKeepsData` all PASS |
| 5 | Real-systemd Nginx job | `make test-systemd` | PASS | `TestRealSystemdNginx` PASS, systemd 249, nginx 1.18.0 (Task 15) | `TestRealSystemdNginx` PASS (discovery, deploy_committed_through_systemd, nginx_t_fails_restored; da728cb) |
| 6 | Reproducible binaries | `make reproducible-check` | identical bytes | ok (Task 12) | ok: `alice` sha256 3f007df6…a65846 and both helpers identical in two clean builds (da728cb) |
| 7 | ZAP baseline per role and API scan | `make zap-baseline` | no Medium or High | 0 High, 0 Medium; Low: 90004, 2, 100001 (Task 15, bb213fc; again after e3ad353) | exit 0, 0 High, 0 Medium in every role; Low: 90004 (admin, operator, auditor, api-admin), 2 Private IP Disclosure (all roles), 100001 (api-admin, 12); every authenticated scan kept its session (da728cb) |
| 8 | testssl.sh on the release image | `make testssl` | A or A+ | A+ (score 96) with the test-CA ECDSA P-256 leaf; B with the temporary certificate (not a CA) | A+, score 96 (protocol 100, key exchange 100, cipher 90), test-CA certificate (da728cb) |
| 9 | Playwright, Chromium (the `make ci` set) | `make e2e` (inside `make ci`) | all pass | 366/366 on three browsers (Task 16, 32efb61) | 122 passed in 29.1 min (da728cb) |
| 10 | Playwright, Chromium, Firefox and WebKit, EN and TR | `make e2e-up && make e2e-browsers; make e2e-down` | all pass | 366/366 (Task 16, 32efb61) | 366 passed in 1.7 h, Playwright 1.63.0 (da728cb); the run before on f768b68 had 6 failures, all the forwarding check of ff09d01, fixed in 5d28639 |
| 11 | Mutation testing (advisory) | `make mutation` | recorded | `backup/format` efficacy 100 %, `license` 90.75 %, `rbac` 100 % (Task 15) | not re-run (advisory; nightly) |
| 12 | Fuzzing, 5 minutes per new target | `go test -fuzz … -fuzztime 5m` | no crash | `FuzzOpenAPIInputs` 1,198,119 executions; `FuzzBackupHeader`, `FuzzBackupStream` and the payload decoder 5 minutes each (Tasks 1, 2, 14) | not re-run |
| 13 | Coverage floors (Go 1.27.2) | `make coverage` | every floor holds | `internal/jobs` 88.98 % under its floor of 89 (Task 19, first run) | every floor holds (da728cb; `internal/backup` 85.0 % over its 84, `internal/jobs` 89.2 %) |
| 14 | The whole local pipeline | `make ci TRIVY_IMAGE="--network host <pinned image>"` | exit 0 | not run in full before Task 19 | exit 0 as the `ci` gate of `make release-gates` (da728cb): lint (with `matrix-check -strict`), test, coverage, perf (worst p95 14 % of budget), test-backup-cycle, test-ssh, build, release-symcheck, i18n-check, web-lint, web-coverage (statements 94.75 %), vuln, secrets-scan, fs-scan, e2e-up, e2e-hardening-check, e2e, image-check, image-scan |
| 15 | Secrets in the history | `make secrets-scan` | no leaks | 11 false positives in 0d3c6b4 and 11c2bef (Task 15); allowlisted by fingerprint after triage (0ddf458), then no leaks | no leaks found (da728cb, 2026-10-12) |
| 16 | Go, npm and OSV vulnerabilities | `make vuln` (with `make osv`) | none | 0 after a4abe0f (Task 14) | `go mod verify` ok; govulncheck: 0 affecting the code (1 in a required module, not called); npm audit 0; osv-scanner 0 (da728cb) |
| 17 | Trivy, source tree | `make fs-scan` | 0 HIGH/CRITICAL | not recorded in Phase 8 | 0 HIGH/CRITICAL (go.mod, web/go.mod, web lockfile; da728cb) |
| 18 | Trivy, image | `make image-scan` | 0 HIGH/CRITICAL | not recorded in Phase 8 | 0 HIGH/CRITICAL in `alice:ci` (debian 12.15 packages and the Go binary; da728cb); the postgres image is not scanned by `make image-scan` (its SBOM is made by `make sbom`) |
| 19 | Matrix traceability, strict | `go run ./tools/matrixcheck -strict …` (also in `make lint`) | exit 0 | 5 gaps (Task 14) | exit 0: 202 IDs, 193 by tests, 7 partial, 0 pending, 0 owner, 2 deferred, 0 gaps (da728cb) |
| 20 | Production keys | `make release-keycheck` | FAILS until the owner commits the production release and license keys | fails: no `rk-*.pem` (Task 15) | exit 2 as expected: no production release public key in `deploy/release/keys` (da728cb) |
| 21 | Every one-machine release gate, logged | `make release-gates` | every gate 0 except `release-keycheck` | partial run only (Task 15) | `bin/release-gates.log` of da728cb (2026-10-12, 175 min): ci 0, matrix-check 0, reproducible-check 0, test-release 0, test-systemd 0, zap-baseline 0, testssl 0, test-backup-cycle 0, e2e-browsers 0, release-keycheck 2 (expected); tree unchanged during the run |
| 22 | ZAP full active scan | `make zap-full` | no Medium or High | — | NOT RUN (owner) |
| 23 | Release fuzzing, 30 minutes per target | `make fuzz-release` | no crash | — | NOT RUN (owner) |
| 24 | VM installs, air-gapped variant, Rocky 9 enforcing | release checklist section 2 | see there | — | NOT RUN (owner) |
| 25 | `nightly.yml`, `release.yml` | GitHub Actions | green within the job limits | actionlint clean; never run (no remote) | NOT RUN (CI) |

Other evidence recorded by the implementers and reviewers (their reports, not re-run here):

- Backup crypto: `TestKnownAnswer` matches an independent Python implementation of format 2 (Task 1 report);
  `TestForgedBackupWithCopiedWrappedKeyFails`, `TestWriterRefusesAnotherSenderKey`, `TestWrappedKeyV2BindsSender`,
  `TestUnwrapRefusesVersion1`, `TestUnwrapChecksThePublicKey`; every flipped byte, truncation and reorder fails
  (`TestEveryFlippedByteFails`, `TestTruncationAndReorderFail`); header bounds are checked before Argon2 runs
  (`TestHeaderBounds`).
- Restore: every crash point of the swap (`TestRestoreIsAllOrNothing`), stale staging (`TestFinishIgnoresStaleStaging`),
  the only copy (`TestCleanupNeverDropsTheOnlyCopy`), the newer time record (`TestRestoreKeepsTheNewerTimeRecord`), the
  database error cleanup and the disk refusals (`TestRestoreCleansUpAfterADatabaseError`,
  `TestRestoreRefusesWithoutFreeSpace`, `TestCreateRefusesWhenTheDiskIsNearlyFull`).
- Scripts: every message of C4 through stub commands (`deploy/release`), including the TOCTOU copy
  (`TestUpdateVerifiesACopy`), the fingerprint confirmation (`TestInstallNeedsTheFingerprintConfirmed`), validation of
  `.env` values (`TestInstallValidatesEnvValues`), no secret in argv or environment (canaries in the stubs' records)
  and `TestScriptsNeverTouchContainerDirs`.
- Leaks: the backup passphrase, the sender key, the database passwords and the SMTP password are searched in plain, hex
  and base64 spellings in answers, logs, tables, job parameters, the support bundle and the backup file
  (`TestF87NoPlaintextInTheFile`, `TestSupportBundleHasNoSecrets`, the API leak suites).

### Coverage (Task 19)

Measured with `make coverage` under Go 1.27.2. Floors are rounded down from the measured value and never lowered.

| Package | Floor before | Measured | Floor now |
|---|---|---|---|
| `alice/internal/backup/format` | — | 95.2 | 95 |
| `alice/internal/backup/dump` | — | 90.6 | 90 |
| `alice/internal/backup` | — | 85.0 in the first run; 84.8 in two runs after 3d4bcaa (the timing-dependent session poll no longer runs) | 84 |
| `alice/internal/audit/forward` | — | 93.5 | 93 |
| `alice/internal/testutil/fakesyslog` | — | 94.3 | 94 |
| `alice/internal/platform/config` | — | 98.4 | 98 |
| `alice/internal/platform/db` | — | 90.4 | 90 |
| `alice/cmd/licensectl` | — | 79.7 | 79 |
| `alice/tools/releasebuild` | — | 84.7 | 84 |
| `alice/tools/releasesign` | — | 78.7 | 78 |
| `alice/tools/notices` | — | 92.9 | 92 |
| `alice/tools/pincheck` | — | 90.8 | 90 |
| `alice/tools/lockcheck` | — | 79.4 | 79 |
| `alice/tools/matrixcheck` | — | 85.3 | 85 |
| `alice/tools/docscheck` | — | 91.3 | 91 |
| `alice/tools/zaprules` | — | 93.9 | 93 |
| `alice/tools/zapsession` | — | 80.3 | 80 |
| `alice/internal/secrets` | 83 | 86.5 | 86 |
| `alice/internal/setup` | 82 | 85.2 | 85 |
| `alice/internal/platform/tlscert` | 73 | 86.9 | 86 |
| `alice/internal/audit` | 89 | 93.0 | 92 |
| `alice/internal/api` | 94 | 95.8 | 95 |
| `alice/internal/notify` | 85 | 88.1 | 88 |
| `alice/internal/providers/linuxssh` | 92 | 93.2 | 93 |
| `alice/cmd/alice` | 90 | 91.1 | 91 |
| `alice/internal/jobs` | 89 | 88.98, then 89.2 with 0686aa8 | 89 |

## Threat notes

### Installer (root, preflight, no pull, image IDs)

`install.sh` runs as root and verifies before it changes anything: the outer signature is checked by the operator with
the vendor-published key (install guide), then the script verifies `SHA256SUMS.sig` with the keys inside the package,
checks the exact file list and refuses symlinks (preflight), and only then shows the fingerprint of the key that
verified it for the operator to confirm (`--fingerprint` for unattended installs) [43]; it installs from a root-only
copy (Task 11 review I-1, fc45ac8). The preflight
refuses an unsafe installation directory, a Docker socket that others can write, a compose project already in use and
taken ports; images are loaded from the package and compared by image ID with `RELEASE` (both the config digest and
the manifest digest are recorded, because the containerd image store reports the latter; fedcd79); compose never
pulls [22]. The setup code is printed, never written to disk [19]. Every `.env` value is validated [S-9]; compose runs
with a clean environment [S-6].

### Update script (signature with installed keys, downgrade, rollback, exit 3)

The installed copy of `alice-update.sh` verifies a copy of the new package with the already installed release keys,
refuses a downgrade and a version below `MIN_UPGRADE_FROM`, stops Alice, makes and deep-verifies a pre-update backup,
copies the rollback state, loads the images and migrates; a failure before the migration starts the installed version
again, a failure after it restores the backup and the previous images, and exit 3 means the rollback itself failed
(the operator guide's procedure) [21, 23, 44]. A successful update replaces `release-keys/` [21]. Proven on real
containers for a failing and a killed migration (`TestReleaseUpdateAndRollback`) and by stubs for every message.

### Signature verification (Ed25519, release key separation, the first-install trust anchor)

Ed25519 raw signatures over `SHA256SUMS` and the outer `.sha256`, verified with OpenSSL 3 on the host [20]. Release
keys (`rk-YYYY-NN`) and license keys are disjoint, and each tool refuses the other's key (`make release-keycheck`,
`TestReleaseAndLicenseKeysAreDisjoint`) [43]. Test-signed packages are marked (`TEST_SIGNED=1`, `rk-test-NN`, a
warning in both scripts) and can carry only `-rc.N` versions [43]. The production stage requires the keys committed
in `deploy/release/keys/` and a gates log of the same commit with every gate exactly once and exit 0 (a64ad60,
1cf18ab). The first install trusts the package's keys once their fingerprint is confirmed (KI-09); only a stage built
on the release machine is signed, a CI stage is only compared (S-26) [52].

### Backup and restore (B-1..B-4, F-80..F-88, the one swap point, the owner role)

B-1: X25519 to the installation's backup key and the sender key, HKDF, AES-256-GCM in 64 KiB chunks with a final
chunk and the header in the associated data; the private key in the file, wrapped by Argon2id of the recovery
passphrase; format 2 binds the sender key, so a file built from another installation's copied wrapped key fails
[2, 41]. B-2: no plaintext temp file; the restore's only temporary area is a database [8]. B-3: a restore is
verified (audit chain and head, row counts, key check, installation seal) before the one swap point; a broken chain is
restored only with `--accept-broken-audit-log`, recorded; `system.restored` names the replaced head and the safety
backup [45]; the time record never goes back [42]. B-4: the restore runs in `alice-admin` with the owner role while
`alice` is stopped and after a deep verify with the passphrase [9, 44]. F-80..F-88 are tests (`internal/backup`) and,
for F-85, also the release drill. Residuals: KI-11, KI-12, KI-14, KI-15.

### The deployment's least privilege (P1-01)

`alice` runs as uid 10001 with a read-only root, all capabilities dropped and `no-new-privileges`, and holds only the
application role's password file; the owner role (not a superuser) is used by `migrate` and `alice-admin` only;
`postgres` is uid 70, read-only, on an internal network with no published port, SCRAM on every TCP rule [7]. P1-01
is closed in production: code execution in `alice` cannot disable the audit triggers. The development compose keeps
its superuser (documented). Residual: KI-10.

### Audit forwarding and its limits

Syslog RFC 5424 with octet counting over TLS by default (system roots plus an optional CA bundle; plain TCP or UDP only
when chosen), in chain order from a cursor, each message with `seq`, `hash` and `prev_hash`, the daily checkpoint as
its own message; the local write never waits [31]. Delivery is at most once (KI-06); the address is refused for
link-local, metadata, multicast and unspecified targets (KI-16); open minors (KI-34). The keyed chain stays deferred
to v2 [32] (KI-05).

### Supply chain (SBOM, osv, lockfile shape, pinning, reproducibility)

Three CycloneDX SBOMs by the pinned Trivy image [26]; osv-scanner fails on any finding [38]; the npm lockfile and
`go.sum` are shape-checked so no secret can hide there [38]; every build input is pinned by version or digest
(`tools/pincheck` in `make lint`); `make reproducible-check` proves the `alice` and helper binaries byte for byte, not
the images [52]. The history's gitleaks findings were triaged one by one (rulings, "Gitleaks"). Residual: KI-25.

### DAST and TLS results

`make zap-baseline` scans the release image on a disposable stack unauthenticated and as Administrator, Operator and
Auditor (TOTP sign-in, sessions kept alive and checked), plus the OpenAPI scan as Administrator; Medium or High fails.
The first scan found rule 10055 on the OIDC callback, fixed in the owning code (8f488ae) [65]. testssl grades the
release image A+ with a test-CA certificate; the temporary certificate alone grades B (not a CA; replaced in the
wizard) [34]. The active scan and the real host are the owner's (rows 22 and 24 above, release checklist 6.1, 6.4).

## Review checklist

§17.2 Phase 8 gate: "Release checklist (17.7) complete; SECURITY-REPORT.md signed off". Neither can be completed by
this review: the checklist's class B rows and both signatures are the owner's. The first column says what is proven
here.

- [ ] (A, here) Every class A gate of the release checklist passes on one machine: `make release-gates` (Evidence row
      21), except `release-keycheck`, which fails until the owner commits the production keys.
- [ ] (A, here) The matrices of §23–§25 are green under `-strict` with every partial or deferred row ruled
      (Evidence row 19; KI-20).
- [ ] (A, here) No open High or Critical finding (Findings below).
- [ ] (B, owner) The VM installs, the offline signing ceremony, the 1.0.0 → 1.0.1 update, the long gates and the
      human gates of `docs/release-checklist.md`.
- [ ] (B, owner) Owner steps 1–6 below and the owner steps of every earlier phase repeated on the release candidate.
- [ ] (B, owner) `SECURITY-REPORT.md` sections 1 and 10 completed and signed.

## Findings

Found by the pre-flight review, the per-task reviews and their re-reviews, the harnesses and gates, and the writing of
these documents, with the commits that closed them. No finding was rated Critical or High; the pre-flight BLOCK
findings S-1 and S-2 were design changes made before any code. Open minors are in "Known limitations" and
`SECURITY-REPORT.md` KI-34.

| ID | Area | Rating | Description | Decision |
|---|---|---|---|---|
| S-1 | Restore | BLOCK (design) | A crash between the database swap and the file renames could pair a database with the wrong keys | Restore ID and one swap point [8]; built in Task 5 |
| S-2 | Backup format | BLOCK (design) | Anyone who saw one backup could build another that the passphrase opens | Sender key, format 2 [41]; built in Task 1 |
| T1 I-1 | Backup key | Important | The wrap normalised the passphrase to NFKC, the unwrap did not | Fixed 9c88f3d |
| T3 I-1 | Migrations | Important | Schema 12 asserted with 11 migrations | Resolved by Task 1's migration 00012 |
| T4 I-1, I-2 | Backup list | Important | Every list re-hashed every file; one unreadable file broke the list, prune and the tab | Fixed 611469d |
| T5 I-1, I-2 | Restore | Important | An ambiguous COMMIT could delete the staging of a swap that happened; two restores could run at once | Fixed d566ee3 |
| T6 I-1, I-2 | CLI | Important | The terminal could be left without echo; no test of the no-echo prompt | Fixed da43b64 (pty test) |
| T7–8 I-1 | Wizard | Important | The server accepted passphrases the browser rates too short | Fixed bcf4d87 |
| T9 I-1 | API | Important | The shipped HTTPS installer was not the code the tests ran | Fixed 626df97 (one installer) |
| T10 I-1, I-2 | Web | Important | A refused download navigated away; Back dropped typed mail fields | Fixed 0aa4f25 |
| T11 I-1, I-2, I-3 | Scripts | Important | Package verified in place then read again (TOCTOU); another project's containers could be taken over; a restore command that could not be confirmed | Fixed fc45ac8 |
| T12 I-1..I-7 | Release build | Important | Classic-store image IDs; `make release` deleted signed outputs; `-allow-draft` without `-test`; a broken package with a customer version; gates log not bound to the commit; the shipped image never inspected; a rotation text the updater refused | Fixed fedcd79, ee26e3a, 5b3d590, 9a804b5, a64ad60, c3f4c9b, ccdd7fe |
| T13 I-1, I-2 | Harness | Important | The update subtests allowed too much; the killed-migration case did not prove M-4 | Fixed f0206d7; I-3 moved to the checklist (rows 2.9–2.11) |
| T14 I-1 | Traceability | Important | Rows marked `test` that their tests prove only in part | Status `partial` with rulings, `-strict` in lint (305f4e2) |
| T14 I-2 | Gates | Important | `test-backup-cycle` could pass with no test run | Fixed 06d1023 |
| T15 I-1..I-4 | Gates | Important | A gates log missing gates was accepted; `release.yml` could not finish on a hosted runner; authenticated scans could silently become unauthenticated; a failing replacer did not stop the scan | Fixed 1cf18ab, 5ea2fbe, e3ad353, 526f6ee |
| ZAP 10055 | API | Medium (scanner) | The API CSP had no `form-action`/`base-uri` | Fixed 8f488ae |
| S-18 defect | Web | Minor (found by the journeys) | An anonymous visitor of a completed installation never reached the sign-in page | Fixed 677c268 |
| T16 M-1, M-2 | Tests | Minor | Two e2e-only functions not guarded by release-symcheck; an assertion not scoped to its form | Fixed ff09d01 |
| Matrix gaps | Tests | — | L-56, L-57, A-11, F-64, F-65 had no test | Tests e01135a, b806f35; rulings G-1 to G-8 |
| Coverage | Tests | — | `internal/jobs` one statement under its floor | Tests 0686aa8 |
| Flaky tests | Tests | — | Restore tests refused at random by a session of a just-closed pool or a passing server process (`WaitForSessions: 0`); `TestGenerateStoresAnEnvelope` checked a random ciphertext byte (1 in 256) | Fixed 3d4bcaa, da728cb, a269e42 (tests only; the CLI waits 150 s) |
| ff09d01 | Tests | Minor | Task 16 review M-2 scoped the refused-address check to the form, but the save's alert is outside it (6 failures in three browsers) | Fixed 5d28639 |

## Known limitations

- The owner credential lives on the host (a root-only file) and in the tools container while it runs (KI-10).
- A shallow `backup verify` trusts a `.sha256` file that was replaced together with the backup (KI-11).
- A restore needs disk for two copies of the database; a crash can leave `<db>_restore` or `<db>_previous_<ts>` behind
  (KI-12).
- Go strings of passwords read from files cannot be cleared, and zeroing is best effort [53] (KI-18).
- A compromised `alice` process, or anyone holding the database and `master.key`, holds the sender key and can forge a
  backup that the passphrase opens [41] (KI-14).
- Forwarding is at most once (KI-06); no JSON webhook; the keyed chain is deferred to v2 [32] (KI-05).
- No "update in progress" banner [23] (KI-13).
- The recovery passphrase and the master key cannot be changed in v1 [50] (KI-21).
- The matrix rows decided in Task 19: F-64 deferred; A-10, A-11, A-12, F-65, L-56, R-07 and S-06 partial (rulings G-1
  to G-8; KI-20).
- The temporary certificate grades B in testssl until a real certificate is uploaded.
- Not verified here: the VMs (and with them the real "Clock sane" and "Port free" checks, SELinux, the classic image
  store), the production keys and signatures, the active ZAP scan, the release fuzz run, the workflows on a remote
  (their job durations were never measured, and the ZAP exclusions were proven only by the session check of the
  local scans), a real syslog collector, a real host for testssl.
- Open review minors: KI-34 (forwarding, TLS store, `.update-<ts>/`).

## Owner verification

Spec §26.10 "Owner verifies", steps 1–6. You need two clean servers (Ubuntu 22.04, Debian 12 or Rocky 9 with Docker
24 or newer), the signed `alice-1.0.0.tar.gz` with its `.sha256` and `.sha256.sig`, the published release-key
fingerprint, a signed `alice-1.0.1.tar.gz` and the signed broken-update package (`make release-broken … SIGN=offline`,
release checklist section 3). The procedures are in `docs/release-checklist.md` sections 2 and 4.

| # | Step (§26.10) | Expected | Result | Date | Notes |
|---|---|---|---|---|---|
| 1 | On a fresh server: `tar xzf alice-1.0.0.tar.gz && cd alice && sudo ./install.sh`; open the printed address | The installer ends with the address and a setup code; the page opens (certificate warning expected) | | | |
| 2 | Complete the wizard in your language: administrator, authenticator code, recovery passphrase, HTTPS certificate, mail server (skip allowed), license (evaluation), first server | Every step has a plain explanation; Back works; the dashboard opens | | | |
| 3 | `sudo /opt/alice/alicectl backup`; on a second empty server `install.sh --restore-mode`, copy the file, `alicectl restore` with the passphrase; sign in there | Same data, same Installation ID, same license | | | |
| 4 | Restore with a wrong passphrase | "The passphrase is wrong or the file is damaged. Nothing was changed." | | | |
| 5 | `cd /opt/alice && sudo ./alice-update.sh alice-1.0.1.tar.gz`; then the "broken update" test package | Alice back within minutes at 1.0.1; with the broken package Alice returns to the previous version by itself and works | | | |
| 6 | Read `SECURITY-REPORT.md` and `docs/release-checklist.md` | Every item ticked with a date | | | |

### Owner and CI gates

| # | Item | Result | Date |
|---|---|---|---|
| 1 | VM installs on Ubuntu 22.04, Debian 12 and Rocky 9 (SELinux enforcing), each also with outbound traffic blocked; the image IDs after `docker load` on a fresh engine; the real "Clock sane" and "Port free" checks (release checklist section 2) | | |
| 2 | The production release and license keys committed (`make release-keycheck` passes); the release-key fingerprint published on a vendor channel; the offline signing of the package, its `.sha256` and the broken-update package (section 3) | | |
| 3 | `make zap-full` against a disposable stack of the release candidate, no Medium or High | | |
| 4 | `make fuzz-release` (about 7 hours), no crash; testssl against the real host (`make testssl TESTSSL_TARGET=<host>:443 TESTSSL_CA=<ca>`) | | |
| 5 | A git remote and the first runs of `nightly.yml` and `release.yml` (record each job's duration) | | |
| 6 | The update 1.0.0 → 1.0.1 and the broken update on a VM (section 4); the external penetration test, the newcomer test of the first-run guide, the Turkish review and the crypto peer review (section 7) | | |

## Sign-off

Reviewer, date and commit are filled in when the review is completed.

| Role | Name | Signature | Date | Commit |
|---|---|---|---|---|
| Reviewer | | | | |
| Owner | | | | |
