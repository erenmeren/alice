# Phase 8 — controller rulings

Decisions taken on the owner's behalf during autonomous execution of
docs/superpowers/plans/2026-10-10-phase-8-packaging-release.md on branch `phase-8` (base `master` 8d681a7, plan
95b2563, amended by the pre-flight in e1682c2; owner instruction: run the phases back to back without waiting). Each
line: decision — why — cost if wrong — how to reverse it, where that is a file to change. Within a topic the order is
the order in which they were made (the controller's ledger of 2026-10-10 and 2026-10-11). The decisions as they apply
to the product are R43 in docs/superpowers/specs/alice-v1/00-decisions.md (item numbers in brackets); the evidence, the
findings and the accepted limitations are in docs/security/reviews/phase-8.md.

Nothing here was checked on a real virtual machine, with the production release or license key, by an active ZAP scan,
on a git remote or by the owner: installs ran in Ubuntu 22.04, Debian 12 and Rocky 9 containers without network
(`make test-release`), signatures used keys generated at test time, and the real-systemd job ran in one privileged
container. Those results are the owner's tables in docs/release-checklist.md and docs/security/reviews/phase-8.md.

## Before the tasks

- 2026-10-10 — the plan's 40 "spec conflicts resolved" are accepted as proposed R43, pending the pre-flight reviews;
  the plan changes no helper code and no helper protocol (protocol 6, helper 1.5.0) — why: the owner said not to
  wait — cost: the owner revises R43 later — reverse: each is an item of R43 with its own cost.
- The plan (19 tasks) was not compiled by its author → a pre-flight consistency scan (M-1..M-28 and cosmetic rows) and
  a pre-flight security design review (S-1..S-40) before Task 1, as in Phases 2 to 7. The code as built wins over the
  plan text. The workspace files `global-constraints.md`, `cross-task-contract.md` and `dispatch-common.md` were
  extracted from the plan for every dispatch.

## Pre-flight rulings (2026-10-11 morning; `preflight-rulings.md` of the ledger)

- S-2 adopted: backups are origin-authenticated with an installation sender key; container and wrapped key are
  format 2 from the start (nothing was released, so no format 1 exists); a restore on a fresh server needs only the
  passphrase [41, 3] — why: without it anyone who saw one file could build another that the passphrase opens — cost:
  a compromised `alice` process can still forge (KI-14).
- S-1 adopted exactly as proposed: the restore ID replaces the `SWAPPED` marker; both renames in one transaction;
  files applied only on an ID match; nothing ever drops the only copy [8].
- M-27 adopted: `make release-broken` and `deploy/dev/build-broken-release.sh` build the broken-update package for
  the harness and for the owner's ceremony [30].
- Every other BLOCK and FIX row of both reviews was applied as `preflight-rulings.md` records, making R43 rows 41–53
  and amending rows 3, 8, 9, 19, 21, 24, 30, 31 and 37. Not applied, with reasons there: B8, D9, D10, E12 (no change
  proposed), S-27 (accepted), S-29 in part (no recipient-key fingerprint in the list; the deep verify detects a
  re-pointed key), S-31 and S-36 (accepted residuals, KI-16, KI-17), S-34 (optional UX), S-37 in part (no pg_hba
  reject rule for `postgres`, KI-10). Ownership changes: Task 1 adds the backup key v2 and runs testcontainers; Task 3
  owns `deploy/Dockerfile`, `check-image.sh` and the first pincheck change; Task 12 the second pincheck change,
  `LICENSE.txt` and the broken-release script; Task 9 commits its codes first; Task 19 adds `matrix-check` to `lint`.

## Backup format, dump and service (Tasks 1, 2, 4, 5)

- Task 1: a migration (`00012`) stores the sender key's envelope — the contract's `backup.sender` row could not
  exist otherwise — cost: another storage would change C1 for Tasks 4, 5 and 8 [54]. HKDF info is `alice/backup/v2`
  (not S-2's `v1`), because the container is format 2 [41]. Review I-1: the passphrase is NFKC-normalised inside the
  wrap and `Unwrap` (9c88f3d) and the server rates the NFKC form (bcf4d87).
- Task 2: the brief's snapshot query is kept unchanged; binary `COPY` in one `REPEATABLE READ READ ONLY` snapshot [1].
- Task 4 review: `List`/`Prune` cache the shallow check per file; an unreadable file is listed with a code
  (611469d) [57].
- Task 5: with no live database, cleanup renames `<db>_restore` live only when both staging directories carry its
  restore ID, otherwise refuses with `ErrUnfinishedStaging` and never drops it (replaces S-1's "always rename", which
  existed only for a two-ALTER fallback that PostgreSQL 16 does not need) — cost: after a crash before staging on a
  fresh host the operator drops `<db>_restore` by hand (operator guide) [8]. Review fixes d566ee3: a lost `COMMIT`
  reply keeps the staging; one restore at a time (advisory lock); `_previous_` kept when no files were applied.
- Carry from the Task 5 review: `TestRestoreKeepsWhatItCanOfDamagedOptionalFiles` failed once and was not reproduced.
  Task 19 ran it 20 times under the race detector (20 passes) and then saw `TestRestoreIsAllOrNothing/error/previous`
  fail once in `make coverage`. Cause, measured: right after a pool's `Close` its backend was still listed in
  `pg_stat_activity` in 4 of 300 closes, and the restore tests pass `WaitForSessions: 0`, so a restore refused with
  `ErrDatabaseInUse` before its safety backup. Fixed in the test helper, not the product (3d4bcaa): the tests' `stop()`
  waits until no session is listed (`TestStopLeavesNoSession`, red before the fix); the production CLI waits up to
  150 s [9]. `internal/backup`'s floor is 84: the first measurement (85.03 %) included that poll branch.

## Deployment, CLI and wiring (Tasks 3, 6)

- Task 3: `POSTGRES_INITDB_ARGS: --auth-host=scram-sha-256` — initdb's own `pg_hba.conf` in `postgres:16-alpine`
  trusts loopback (found by `TestReleaseRolesScript`) [7]. A binary refuses a newer schema [56].
- Task 6: the release binary links no `golang.org/x/term` (an existing guard forbids it); termios through
  `golang.org/x/sys/unix` [58]. `serve` audits a recovered certificate, because `tlscert` is a platform package
  (S-13) [59]. Task 5 review messages for the CLI: 684a47d; terminal restored on a signal: da43b64.

## Forwarding and TLS store (Tasks 7, 8)

- Task 7: the forwarding test message is named through a constant so the web's audit-label check does not take it
  for an action (9dba50c). Review fixes c988fd5: no panic when one object exceeds the syslog budget; F-96's bound is
  structural [60]. Minors 3, 4, 5 (no write deadline in `Test`, control characters in SD values, 8 KiB UDP) stay open
  (KI-34).
- Task 8: write-only CA through a `CASet` flag (C12). Review: the temporary certificate is recognised by a mark in
  `tls.key`, not by its organisation (5e8ef5e) [59]. Minors 11 and 12 (hard links required, PFX costs uncapped) stay
  open (KI-34).

## API and web (Tasks 9, 10)

- Task 9: a missing `If-Match` on the two new settings routes is 412 `ALC-SYS-0008` like every Phase 7 settings
  route, not 428 — cost: a new code and one branch in `settingsChange` [61]. The backup download shares the
  5-a-minute download bucket with private-key downloads; the three Phase 8 actions get a bucket each (review M-4).
  Review M-2: one `setup.CertificateInstaller` for the binary and the test stack, retrying and logging an unrecorded
  replacement (626df97; KI-23 narrowed, not closed). Review M-9: the HTTPS warning codes are in the OpenAPI enum;
  recorded in R43 [61], the ledger's contract is not edited after the phase.
- Task 10: DTO details where C12 is silent were agreed with Task 9 through the ledger (`version` in the schedule and
  forwarding DTOs, `BackupDTO.code`, the forwarding body with optional `ca_pem`, the dashboard `backup` and
  `setup_checklist`, HTTPS `warnings`). The zone field is a native select of the browser's zones plus `UTC` [62].
  Back is not on the passphrase step (the recovery codes are shown once) and the first-server step has no done state
  [16]. Review fix 0aa4f25. Task 9 review M-8 (the forwarding page cannot remove a stored CA) fixed in Task 16
  (f7856df).

## Host scripts, release build and harness (Tasks 11, 12, 13)

- Task 11: stubs read `stub.env`; directories made with `install -d -m` then `chown`; step 7 starts the new postgres
  image before `run --rm migrate`. Review fixes fc45ac8 (a root-only copy of the package; a compose project in use is
  refused). Minor 14 (`.update-<ts>/` stays after exit 3) is a known issue (KI-34).
- Task 12: the production stage also refuses the draft LICENSE, a missing guide and a non-zero gate [51];
  `RELEASE_KEY_ID` is the newest `rk-*.pem` [63]. Review fixes fedcd79, ee26e3a, c3f4c9b, 5b3d590, 9a804b5,
  a64ad60, 2a609e0 and the rotation note ccdd7fe [63]. S-11's "release-gates fails when staged keys differ" is
  enforced by the production stage itself.
- Task 13: `--fingerprint` is the SHA-256 of the DER public key; counts compared on stable tables with an allowlist of
  each attempt's own bookkeeping; the drill's audit head is the entry before `alicectl audit verify`'s own
  `audit.verified`; the restore negatives run on a fresh installation seeded with 40 RSA certificates [64]. In the
  containers "Clock sane" is `[WARN]` and "Port free" proves little; review I-3 moved the real checks to the release
  checklist (rows 2.9–2.11, added by Task 19) [64]. Review fix f0206d7, proven by a full `make test-release`.
  Review M-5 (`make lint` never compiled the `release` tag) was already closed by the lint line that Task 15 added.

## Static and dynamic gates (Tasks 14, 15)

- Task 14: `matrix-check` without `-strict` counted missing tests as pending (M-5); a real `osv-scanner` finding
  (source-map-js, High, dev dependency) fixed in a4abe0f; osv-scanner has no severity filter, so any finding fails
  [38]; routes not fuzzed by `FuzzOpenAPIInputs` are the setup routes, the credential routes and the routes that dial a
  host named in the body; `docs/superpowers/` and `docs/security/reviews/` are outside `docscheck`.
- Task 15: the API CSP gains `base-uri 'none'` and `form-action 'none'` (ZAP rule 10055, 8f488ae) [65]; testssl runs
  on a stack whose certificate comes from a test CA uploaded through the wizard — the temporary certificate is not a
  CA and caps the grade at B (cost: the temporary certificate stays at B until the operator uploads a real one;
  owner item 4 is the real host) [34]; `zapsession` is tested against a hand fake, the real API by three real scans;
  `release-gates` refuses a tree that differs from HEAD and runs every gate after a failure [65]. Review fixes
  1cf18ab (every gate exactly once with exit 0), 5ea2fbe, ba7d67b, 526f6ee, e3ad353 (the authenticated scans stay
  authenticated), dd24391.

## End-to-end and documents (Tasks 16, 17, 18)

- Task 16: `/test/reset` restores the temporary certificate (e2e build only) instead of ordering the journeys; the
  download's step-up is made real by moving the server clock; the journeys found the S-18 defect (an anonymous visitor
  of a completed installation never reached the sign-in page; 677c268) [47], a stale step-up on download (14f74a0)
  and Firefox's scrollable inline code (32efb61). Review M-1 and M-2 were folded into Task 19 (ff09d01).
- Task 17: the docs give `sudo /opt/alice/alicectl …` and `cd /opt/alice && sudo ./alice-update.sh`; a hand-copied
  backup is put in place with `install -o 10001 -g 10001 -m 0600` (reasoned, not tested on a host); the rsyslog example
  is marked as not run against Alice.
- Task 18: targets that did not exist yet were not written as `make X` (docscheck refuses an unknown target); Task 19
  rewrote those cells. §17.7's "advisory files updated in the package" has no mechanism in v1 (no `advisories/`
  folder): N/A with that reason, KI-35 [68].

## Matrix gap decisions (Task 19 Step 2)

Task 14 left five gaps (L-56, L-57, A-11, F-64, F-65) and its review (I-1) found seven rows marked `test` that their
tests prove only in part (S-06, S-10, R-07, A-10, A-12, X-02, X-03). Decision on I-1: `tools/matrixcheck` gains the
status `partial` (tests that exist, a note of what is missing, and a ruling or owner step; `-strict` refuses a partial
row without one), and `make lint` runs `matrix-check` with `-strict` (305f4e2) — why: a release gate must not be
green while a row is only partly proven, and a renamed test must fail at once — cost: a test rename now fails `lint`
until the map follows — reverse: `MATRIXCHECK_FLAGS=-strict` in the `lint` line of the Makefile.

Closed by new tests: L-57 (`internal/license:TestL56L57CertificateNotBeforeNeverAffectsTheLicense`, e01135a), S-10
(`cmd/alice:TestS10ReleaseServerHasNoDebugOrMetricsEndpoints`, `internal/archtest:TestS10ReleaseLinksNoDebugOrMetricsEndpoints`,
06b402f); X-02 and X-03 name the tests that prove the rest of the row (`TestReleaseComposeIsHardened`; the stage,
signing and harness tests).

- G-1 (A-11, partial) — `web/src/xss.test.tsx` (b806f35) renders the certificate, server, SSH key and audit pages with
  script and HTML in every name, label, comment, actor, object and reason and finds no element, handler or
  `javascript:` link; the CSP is tested (`csp.test.ts`, `TestSecurityHeadersOnEveryResponse`). The in-browser
  Playwright run with stored fixtures and a marker under the CSP is deferred to v1.x — why: React escapes every text
  node, `dangerouslySetInnerHTML` is banned by lint, and the CSP has no `unsafe-inline`; the stored-fixture journey
  needs hostile names accepted by every create route, which validation refuses for most of them — cost: an injection
  through a non-React path would be found only by review or the active ZAP scan.
- G-2 (L-56, partial) — the license state never depends on a certificate's `notBefore` (proven); R28's admin warning
  "system clock appears to be behind" from certificate evidence is not built; the `clock_behind` banner comes from the
  time record only — why: the warning is advisory, and a certificate-driven warning is exactly the signal a hostile
  target controls — cost: on a fresh installation whose clock is behind, nothing hints at it until the time record
  has a later value.
- G-3 (F-64, deferred) — no test restarts PostgreSQL under a running deployment job; the crash-recovery sweep and
  lease rules (F-66) cover an interrupted job — why: the `pgtest` container is shared by a package's tests, so a
  restart test needs its own container and a provider fake that blocks mid-job; deferred to v1.x — cost: a pool that
  does not reconnect after a database restart would be found in production (pgxpool reconnects by design).
- G-4 (F-65, partial) — the friendly 503, `/healthz` failing and `/livez` passing while the database is away are
  tested; that jobs pause and nothing is lost after two minutes without the database is not (same reason as G-3,
  deferred to v1.x) — cost: a job that fails instead of pausing would be retried by its attempt budget, and one that
  exhausts it needs attention by hand.
- G-5 (S-06, partial) — the backup canary is a test (F-87); the release package is the two scanned images plus
  repository files, and `make secrets-scan`, `make fs-scan` and `make image-scan` are gates of `make ci`; the scan of
  the packed tarball itself is release checklist row 1.5 (owner) — cost: a secret added by the stage step alone
  would be found only there.
- G-6 (A-10, partial) — TLS 1.2 minimum and "only the HTTPS port is published" are tests; the testssl grade is the
  `make testssl` gate (A+ on the release image), the real host is owner item 4.
- G-7 (A-12, partial) — shell injection is tested; SQL is parameterized everywhere (gosec G201/G202 in `make lint`,
  the two DDL/COPY exceptions quoted and tested [48]) and `FuzzOpenAPIInputs` fuzzes every create/update body; a
  payload sweep of every list, filter and sort parameter is deferred to v1.x, and the active ZAP scan (`make zap-full`,
  owner) includes SQL injection — cost: a hand-built query outside the lint rule would be missed.
- G-8 (R-07, partial) — Argon2 concurrency, the backup download and the Phase 8 action buckets and the per-target SSH
  bound are tested; a server's test connection has only the general per-identity limit and the SSH pool bound; no
  stricter route limit is built for it — cost: an Operator can start test connections at the general rate (300 a
  minute), each bounded by the pool.

## Coverage (Task 19 Step 1)

Measured under Go 1.27.2 with `make coverage`. `alice/internal/jobs` measured 88.98 % (759 of 853 statements) against
its floor of 89; one scheduler branch is timing-dependent. The floor was not lowered: two tests in the owning package
(0686aa8) raise it to 89.2 %. Raised floors and new floors are listed in docs/security/reviews/phase-8.md
("Coverage"); every new Phase 8 package has a floor, rounded down from the measured value.

## Gitleaks (Task 19)

The repository will be published, so the 11 findings of `make secrets-scan` in older commits were read one by one. All
are false positives and are allowlisted by fingerprint with a comment (0ddf458): one fake PEM block whose body is the
four characters `AAAA` (`internal/license/issuer/purpose_test.go`, a negative test of the release key parser, 0d3c6b4)
and ten Go test names in the traceability map and document (11c2bef). No path or rule is allowlisted.

## Final runs (Task 19, Docker alone)

- `make release-gates TRIVY_IMAGE="--network host <the pinned image>"` on f768b68 (2026-10-11): `ci` failed in
  `internal/sshkeys:TestGenerateStoresAnEnvelope` (a probabilistic assertion, fixed a269e42) and `e2e-browsers` had 6
  failures, all the forwarding check that ff09d01 had scoped to the form (fixed 5d28639); every other gate passed.
- The next run on 5d28639 failed in `make ci` on `TestRestoreIsAllOrNothing/error/staged` (a session that came and
  went; fixed in the tests, da728cb) and was stopped after the `ci` gate.
- Final: `make release-gates` on da728cb (2026-10-12, 175 minutes, nothing else using Docker): `ci` 0 (the whole
  `make ci`), `matrix-check` 0, `reproducible-check` 0, `test-release` 0, `test-systemd` 0, `zap-baseline` 0,
  `testssl` 0 (A+), `test-backup-cycle` 0, `e2e-browsers` 0 (366 passed), `release-keycheck` 2 (no production key:
  the owner's) — decision: the phase closes with `release-keycheck` the only failing gate, as the plan expects; the
  production stage (`make release`) stays impossible until the owner commits the keys — cost if wrong: none; the
  stage refuses the log by itself.

## Final review

Two read-only reviewers of the whole branch (part A: backup, restore, keys, TLS store, forwarding, CLI, API; part B:
deploy, release tooling, workflows, web routing, docs): no Critical finding, one Important (B I-1), thirteen Minor.
Every item was fixed by one fix agent, test-first where it is code; nothing was skipped. Rulings (what — why — cost if
wrong):

- A-1 (download context): Open and the `backup.downloaded` row run on `context.WithoutCancel` — a dropped connection
  during the full re-hash no longer loses the row and answers 500. The review's mechanism (HTTP/1.1 ReadTimeout
  cancelling the context) does not occur under Go 1.27: `startBackgroundRead` clears the read deadline; both are
  tested (`TestBackupDownloadSurvivesACancelledRequestContext`, `TestBackupDownloadOutlivesTheReadTimeout`) — cost if
  wrong: a download whose client vanished still re-hashes to its end and writes its row (the row was already written
  before the first byte).
- A-2 (job queue after a restore): queued and running jobs of class `change` in the staging database become
  `blocked_license` before the swap (a running one's attempt closed as the reaper closes it, its target lock released),
  `system.restored` records `held_jobs`, the restore warns, and backup-restore.md, admin-guide.md and operator-guide.md
  say where to run or discard them (`TestRestoreHoldsQueuedChanges`). Holding, not cancelling: the domain modules
  already treat `blocked_license` as live work waiting for an Administrator (L-81), so a rotation or deployment waits
  instead of seeing its job end; the UI's **Waiting for an administrator** panel lists every held job. Read-only and
  platform work, and work that falls due after the restore, run as usual — cost if wrong: a restore over an
  installation whose license is locked shows these jobs under the same "paused" panel as lock-held work; work that
  falls due after the restore (renewals, rotation steps) is not held, as documented.
- A-3 (`_previous_` kept by a failed apply): the rule is that a cleanup drops only `<db>_previous_<ts>`, the leftover of
  a swap whose files were applied (or whose final drop failed); a swap that applied no file renames its previous
  database to `<db>_kept_<ts>`, which no cleanup drops, and the error and operator-guide.md tell the operator to drop
  it by hand (`TestSwapKeepsThePreviousDatabaseWhenNoFileWasApplied` runs a second restore). If that rename fails, the
  error names the `_previous_` database and says to rename it before anything else — cost if wrong: a kept database
  stays until dropped by hand (disk space; KI-12 already asks for room for two copies).
- A-4: a forwarding test needs a host whatever `enabled` says (`TestTestRequiresAHost`).
- B I-1 (image notices, release blocker): `licenses/IMAGE_NOTICES.md` is generated by `tools/notices images` from each
  image's SBOM and an export of its files (`make image-notices`, run by `make release`); `releasebuild stage` refuses a
  package without the notices of its own two images and the written offer (`TestStageNeedsTheImageNotices`,
  `TestImageNotices`). Derived: every package with its declared SPDX license; the Debian copyright files and the
  common-licenses texts (GPL-2, GPL-3, LGPL-2, LGPL-2.1, MPL-2.0, Apache-2.0, …) that the distroless image carries,
  linked from every package of either image whose declared license names them; source package and version per
  GPL/LGPL component with snapshot.debian.org or the Alpine aports branch. Not derivable, and said so in the file and
  in release checklist row 1.31 (a vendor step before 1.0.0): the license text of PostgreSQL itself (built from
  source under `/usr/local` by the image's maintainers: not in the SBOM, no license file in the image; the file lists
  those `/usr/local/bin` files as "described by no SBOM component"), and the MIT/BSD-style notices of Alpine
  packages (the postgres image carries no license files: those rows say "not in the images"). The written offer's
  wording names the vendor of `licenses/LICENSE` and is for the vendor's legal review (row 1.31). The SBOM-to-text
  mapping never maps a license whose text names a copyright holder (BSD, MIT) to a generic file — cost if wrong: the
  vendor adds the missing texts by hand before 1.0.0; until then the package is not releasable to customers (the row
  is open).
- B M-1: a coarse free-space check (3 × package size + 1 GiB) runs before the package is copied
  (`TestUpdateChecksFreeSpaceBeforeTheCopy`); the exact check after the intake stays.
- B M-2: tested instead of listed as a limitation: `make release-broken BROKEN=unhealthy` builds a package (rc.5 in the
  harness) whose extra migration succeeds and breaks the audit chain, so the new version starts and fails its
  selfcheck; `TestReleaseUpdateAndRollback/unhealthy-after-migration` proves the old version's safety backup of the
  newer-schema database, the restore of the pre-update backup and the return (exit 1, data unchanged). The harness now
  builds five packages — cost if wrong: about 10 more minutes per `make test-release`.
- B M-3: `alice-update.sh` prints and logs the fingerprint of the installed key that signed the package and of every
  key the package brings (`TestUpdatePrintsReleaseKeyFingerprints`); licensing-vendor.md's leaked-key procedure now
  covers updates (install-guide section 3 before every update, compare the printed fingerprints). The update asks no
  question: an interactive confirmation would break `--non-interactive` updates — cost if wrong: a customer who does
  not read the output is protected only by the procedure.
- B M-4: `--uninstall` and `--purge` take the installation lock (`TestUninstallTakesTheLock`).
- B M-5: `VERSION` is written last in the layout and marks a complete layout; `install.log` without `VERSION` is a
  layout that stopped halfway, which a new install completes and `--uninstall [--purge]` accepts; a compose file
  without either is still refused (`TestInstallLayoutFailureIsRecoverable`) — cost if wrong: an installation whose
  `VERSION` was deleted by hand while `install.log` exists is treated as incomplete (nothing stopped by `--uninstall`
  without `--purge`).
- B M-6: SECURITY-REPORT.md and the Phase 8 review were changed to match the code (three roles; Rocky 9 with SELinux
  not verified; `--bind` left at its default in production; the Docker socket at Docker's 660 `root:docker`; the
  signature verified before the fingerprint is confirmed).
- B M-7: the smallest correct option: the package leaves out the vendor's `docs/release-checklist.md` (its signed
  result ships as `RELEASE-CHECKLIST-SIGNED.txt`), and upgrade.md takes the minimum version from `MIN_UPGRADE_FROM` in
  the package's `RELEASE`, which the update enforces and names, instead of the changelog. The development sections of
  operator-guide.md stay (they are labelled as development and contrast it with production) and the changelog keeps
  its developer wording until the 1.0.0 release notes are written — cost if wrong: a customer reads development
  notes in operator-guide.md.
- B M-8: `alice-update.sh` accepts the directory install-guide.md extracts into (a directory without `RELEASE` that
  holds `alice/`) as well as `alice/` (`TestUpdateAcceptsTheExtractionDirectory`); upgrade.md names both.
- B M-9: the current plans (Phases 6, 7, 8) and these rulings say "the owner's other local containers"; history is not
  rewritten. The plan's "Build machine networking" line stays: it is a build instruction, not a private detail.

## Process

- Several agents shared one working tree and index; every commit used `git commit --only <paths>`; no amend, rebase,
  squash, push or merge. Tasks that start Docker test containers and the Playwright runs never overlapped (Chromium
  aborts requests when a host interface changes); Tasks 13, 15, 16 and 19 ran with Docker alone.
- The owner's compose project `alice`, image `alice:dev`, volumes `alice_*` and the owner's other local containers
  were never touched; no prune.
- Every task had an independent review; Important findings were fixed before the next dependent task, Minor ones were
  fixed, carried to Task 19 or listed as known issues.

## Status at phase close

Commits per task (from `git log` and the ledger; a range includes the fix rounds):

- Plan: 95b2563, e1682c2 (pre-flight amendments).
- Task 1: 922f145, 9c88f3d. Task 2: b28225b. Task 3: d9b13fd. Task 4: 0737836, 611469d. Task 5: 9ded2de, d566ee3.
- Task 6: 5fb7c93, 684a47d, da43b64. Task 7: 3d1d87f, 9dba50c, c988fd5. Task 8: 8901573, bcf4d87, 5e8ef5e.
- Task 9: ca092cd, 746fd9a, 626df97. Task 10: 840157e, 0aa4f25. Task 11: 1ee0009, fc45ac8.
- Task 12: 0d3c6b4, fedcd79, ee26e3a, c3f4c9b, 5b3d590, 9a804b5, a64ad60, ccdd7fe, 2a609e0.
- Task 13: 0296750, bfe404c, f0206d7. Task 14: c4ca26d, a4abe0f, 73892b1, a47c002, 11c2bef, 06d1023.
- Task 15: 8f488ae, bb213fc, 1c8a9b4, 1cf18ab, 5ea2fbe, ba7d67b, 526f6ee, e3ad353, dd24391.
- Task 16: f7856df, 2bc4be5, 14f74a0, 677c268, 5283c31, 581b437, 344cfd0, 32efb61. Task 17: 9ebaed2. Task 18: 30d020c.
- Task 19: 0ddf458, e01135a, 06b402f, b806f35, ff09d01, 305f4e2, 0686aa8, 3d4bcaa, 41a49e9, f768b68, a269e42,
  5d28639, da728cb and the evidence commit.

## Carried to later phases

Re-deferred by the plan's "Carries and deferred items", with their reasons:

- v2: the keyed audit chain and the app-writable `jobs.audit_verify` (R43 row 32: a keyed chain changes every row and
  verifier; the external anchors now exist).
- v1.x: the helper's repeated scans per key change (a helper protocol change every server must follow); the TLS
  private-key download (format decision and its own S-09 suite); the Microsoft Graph lookup for the Entra overage;
  master-key and recovery-passphrase rotation [50]; R-04's statistical timing test (flaky on shared runners); JSON
  webhook forwarding, nuclei, the "update in progress" banner, PDF documents and screenshots [23, 27, 31, 34]; the
  matrix rows deferred or partial by G-1 to G-8; the open Phase 8 review minors of KI-34; the §17.4 advisory files
  and banner (KI-35).
- Unassigned (listed in `SECURITY-REPORT.md` known issues where a customer could notice them): the Phase 5, 6 and 7
  parked items and the other unassigned carries of `phase-7.md`.
- Owner only: a git remote and the first runs of `nightly.yml` and `release.yml` (job durations never measured; ZAP
  exclusions proven only by the session check of the local scans, never by a real CI log); the production release and
  license keys and `make release-keycheck`; the published release-key fingerprint; the offline signing ceremony,
  including the broken-update package; the six VM installs, Rocky 9 with SELinux enforcing, the image-ID check on a
  fresh engine (both image stores), the real "Clock sane" and "Port free" checks; `make zap-full` and
  `make fuzz-release`; testssl on the real host; the 1.0.0 → 1.0.1 update; an external penetration test; the
  newcomer test of the first-run guide; the Turkish review; the crypto peer review; the repetition of every phase's
  owner steps on the release candidate; the signatures of `SECURITY-REPORT.md` and the release checklist; owner
  steps 1–6 of §26.10 (docs/security/reviews/phase-8.md).
