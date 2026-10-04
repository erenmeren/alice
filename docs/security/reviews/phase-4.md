# Security Review — Phase 4 (Nginx certificate discovery, deployment and rollback)

Scope (spec §17.2, Phase 4): atomic deploy, rollback, path validation, private key handling. Exit criterion:
fault-injection tests leave the server unchanged (or back in its previous state); no High finding open.

The decisions behind this phase are R38 in `docs/superpowers/specs/alice-v1/00-decisions.md`; R38 item numbers are
given in brackets below.

## Evidence

All commands run from the repository root; `-tags integration` and `make test-ssh` need Docker (testcontainers).
"Recorded" means the result is taken from the run recorded while the phase was built (the commit is named), not
from a run made for this review.

| # | Check | Command | Expected | Result for this review |
|---|---|---|---|---|
| 1 | Helper as a normal user: argument vectors, the root-controlled walk, section authentication, existence oracle, refusals say why, `nginx-dump` never returns key blocks or configuration text, journal, crash matrices (as far as they run without root), retention, superseded operations, the emulator fidelity suite against the real helper code | `go test ./cmd/alice-helper -count=1` | ok (root-only tests skip) | ok, 189 tests passed, 11 skipped (root only) |
| 2 | Helper as root: owners and modes (`TestDeployAsRootSetsOwnersAndRefusesUserDirectories`, `TestDeployModes`), `TestAttackUserOwnedLinkAndDirectoryAsRoot`, `TestAttackUserOwnedLetsEncryptChainAsRoot`, `TestAttackUserOwnedConfigurationAsRoot`, `TestAttackKeyOutsideRootControl`, `TestAttackDirectorySwappedBeforeTheRename`, `TestAttackRestoreOverANewerDeployment`, the crash, re-send, interference and restore matrices (`TestDeployCrashMatrix`, `TestDeployCrashThenTheSameDeploymentAgain`, `TestDeployCertificateInterferenceMatrix`, `TestRestoreCrashMatrix`, `TestDeployKilledAtEveryStepRecovers`) | `CGO_ENABLED=0 go test -c -o /tmp/alice-helper.test ./cmd/alice-helper` then `docker run --rm --network none -v /tmp/alice-helper.test:/alice-helper.test:ro debian:12 /alice-helper.test -test.count=1` | ok (3 skips: two need a non-root user, one needs `go`) | recorded at 58f897a: 190 passed, 3 skipped; the helper has not changed since |
| 3 | Real OpenSSH and real Nginx on Ubuntu 22.04 (nginx 1.18), Debian 12 (1.22) and Rocky 9 (1.20): setup script with the checksum check, real `sudo` accepting every built line and refusing 28 variations, discovery of default and hostile layouts, deploy and verification (ECDSA with chain, RSA, 0640 `ssl-cert`, user-owned key, Let's Encrypt links, dual RSA/ECDSA, address-specific listens), F-01 with real `nginx -t`, F-02..F-05, F-07, F-08, F-10, hard link, user-owned link and directory, writable configuration file, busy lock, helper killed with SIGTERM and SIGKILL in `nginx-deploy` and `nginx-restore`, superseded operation, no staged file left | `make test-ssh` | ok, 35 Nginx subtests per distribution | recorded at 5d6379d and again after ea0a4bd: exit 0 (105 Nginx subtests, about 100 s) |
| 4 | Nginx provider: helper answers mapped through the legal outcome shapes (59 deploy rows, 27 rollback rows), uncertain outcomes, verification per listen address, chain length, inline rollback, the key never printed (`TestDeployNeverLeaksTheKey`, `TestAWrappedCommandNeverPrintsItsStdin`), `TestOnlyProbeTLSConfigSkipsVerification`; command builders and sudoers lines (`TestSudoers*`, `TestCmdNginx*`) | `go test ./internal/providers/... ./internal/certs/... -count=1` | ok | ok |
| 5 | Parsers fuzzed (§25.6) | `make fuzz-nginx` and `make fuzz-certs` | no crasher | ok: 6.9 M and 4.8 M executions in 60 s each |
| 6 | Deploy engine: at most one send per deployment, no success without a passed verification, no `failed` after a send unless the server proves nothing was written, every interrupted deployment ends; kills at every point (F-66: `TestDeploymentSurvivesAKillAtEveryPoint`, `TestDeploymentSurvivesAKillDuringRecovery`), stale runs after a lost lease (`TestStaleRun*`), L-80..L-82 (`TestL80InFlightDeployFinishesAcrossLock`, `TestL81QueuedDeployIsBlockedThenConfirmed`, `TestL82RollbackRunsDespiteLock`), `TestDeployAndRecoveryLeakNoKey` | `go test -tags integration ./internal/jobs/deployjobs/... -count=1` | ok | ok (in row 13's run) |
| 7 | Inventory: reconcile of hostile discovery data, incomplete scans, changed outside, uploads (`TestNoPrivateKeyOrPasswordLeaks`, `TestPFXDecodesAreCapped`, `TestUploadRefusalsAreAuditedAndStoreNothing`), signing requests and their races, deployment records, sweep, claim fencing (`TestEngineWritesAreFencedToTheJobClaim`) | `go test -tags integration ./internal/inventory/... -count=1` | ok | ok (in row 13's run) |
| 8 | API journeys: Nginx server end to end, upload refusals with the exact messages, deploy failures and rollback failures, pre-check refusals, interruptions and recovery, unreachable server during recovery, signing requests, roles; license lock refuses every certificate change and lets recovery run | `go test -tags integration ./internal/api -run 'Nginx\|Upload\|Deploy\|Rollback\|Precheck\|Helper\|Restart\|Unreachable\|Signing\|Location\|Auditor\|ObjectIds\|Lock\|InFlight' -count=1` | ok | ok (in row 13's run) |
| 9 | Secret leak with TLS keys: ECDSA and RSA canaries in every PEM and DER spelling, PFX passwords, every sealed key's plaintext and data-encryption key; all HTTP bodies and headers, logs, every table, rendered emails; refused uploads included | `go test -tags integration ./internal/api -run 'TestTLSKeysNeverLeak\|TestKeyScannerFlagsEverySpelling\|TestSecretsNeverLeak' -count=1` | ok | ok (in row 13's run) |
| 10 | Authorization matrix incl. `certificates.operate`; lock-group rules; certificate changes refused in lock before the body is read | `go test ./internal/api -run 'Authz\|RouteRule\|Lock\|Gated\|InfrastructureRoutes' -count=1` and `make authz-doc && git diff --exit-code docs/authz-matrix.md` | ok, no diff | ok, no diff |
| 11 | Error catalogue: every Phase 4 reason has a code, EN and TR texts that render with their parameters, and a troubleshooting section | `go test ./internal/api -run 'Catalogue\|Phase4\|Troubleshooting\|Discover' -count=1` | ok | ok |
| 12 | Grants and triggers: managed keys are envelopes only and append-only, a key cannot be replaced or detached (`Z1001`, `Z1002`), a finished deployment is frozen (`Z1003`, `TestFinishedDeploymentIsFrozen`), steps append-only, `00006` Down keeps Phase 3 data | `go test -tags integration ./migrations -count=1` | ok | ok (in row 13's run) |
| 13 | Coverage floors (also runs rows 6–9 and 12 under `-race`) | `make coverage` | every package ok | ok (exit 0, every floor met, new floors below) |
| 14 | E2E EN/TR incl. axe on the new screens, on the separate compose project `alice-e2e` | `make e2e-up && make e2e-hardening-check && make e2e`, then `make e2e-down` | all passed | run by `make ci` at the end of the phase (Playwright journeys of this phase were being added while this review was written) |

Coverage (row 13): `internal/api` 89.8 %, `internal/certs` 92.5 %, `internal/providers/nginx` 98.5 %,
`internal/providers/nginx/nginxconf` 92.7 %, `internal/jobs/deployjobs` 96.2 %, `cmd/alice-helper` 89.3 % (as a
normal user). The floors are the measured values rounded down (R38 item 46).

## Threat notes

### Atomic deploy

`nginx-deploy` is one root-side transaction (R38 item 1). Before the first file is replaced the helper has: taken
its lock, checked that stdin has the hash Alice announced (`CONTENT_MISMATCH` otherwise, so a dropped connection
never delivers half a key), checked that the stdin holds only `CERTIFICATE` blocks and one unencrypted key that
matches the leaf, run its own authenticated `nginx -T`, checked that the two paths are a supported pair of it,
re-read both files through the root-controlled walk and compared the certificate with `--expect-cert-sha256`,
written a `prepared` journal, the backups and the pair record, and made the journal say `writing` (all fsynced).
Each file is written to a staged file created root 0600 before any content, fsynced and renamed; right before each
rename the helper checks that both names still point at the inodes it read and that their bytes are unchanged.
Recovery after a crash is decided from file hashes, so the one intermediate state (new key, old certificate) is
repaired by `nginx-restore`. The helper catches SIGHUP and SIGPIPE and finishes after a dropped connection. Crash
injection at every point (journal, each backup, each staged file, each rename, each step, each rollback point:
over 250 subtests) leaves a state that `nginx-status` reports truthfully and that `nginx-restore` turns into the
complete old pair, with no staged file left.

Alice treats only a well-formed helper refusal as "nothing changed" (R38 item 23); anything else after the send
goes to recovery, which reads the journal and verifies, finishes or rolls back. A journal that says `committed` is
never taken as success without a verification of its own.

### Rollback

A failure after the first rename rolls back inside the same call: both files are put back with their old owner,
group and mode, then `nginx -t` and a reload. A failed verification after a commit makes the provider run
`nginx-restore` at once and verify the previous certificate (R38 item 44); after the helper's own
`restore_failed` the engine sends `nginx-restore` once more. If another program changed a file during the
deployment, the helper puts back only what it wrote and records `file_changed` (R38 item 45); a later
`nginx-restore` is all-or-nothing and never overwrites someone else's file. Only the operation that last replaced a
pair's files can be restored (R38 item 24), so a caller cannot walk back through kept operations to an older key.
Recovery runs in license lock (`ClassAlways`), is paced (30 s, then every 15 minutes) and ends after about a day
with an "outcome could not be confirmed" email (R38 item 27). Every engine write is fenced to the job claim, so a run
that lost its lease cannot record over another run's outcome or send after the deployment ended (R38 item 28).

### Path validation

The helper writes only the two files of a pair that its own `nginx -T` names (never a path chosen by the caller),
both existing, resolved through a descriptor walk in which every directory and link is root's, no directory is
group or other writable, nothing is on a pseudo or FUSE file system, and the file is regular with one link and a
certificate or key extension (R38 item 2). The `nginx -T` output is not trusted as such: every `# configuration
file` section is compared with the real file read through the same walk, sections no include reaches, repeated
names and text before the first marker are refused, and once a section from a non-root-writable file appeared every
later authentication failure is reported the same way (no existence oracle). A pair that a non-root-writable
configuration file touches (its server block, its directives, an include chain, or an earlier entry of an
http-level directive list) is unsupported and refused (`config_file_writable`, R38 item 22). Raw paths with `.` or
`..` segments are unsupported, so the reported path is the path the kernel opens.

### Private key handling, end to end

- **Browser.** The upload form sends the key in a JSON body over the session's TLS connection; its fields turn off
  autocomplete and ask password managers not to store the PFX password; the form drops the key, the PFX file and
  its password as soon as the server answers (a key pasted into the certificate field is refused and cleared). The
  key is never shown again; there is no download (Phase 6).
- **API.** Upload bodies are capped (768 KiB) and refused unread when larger; secret bodies are read into one
  buffer, decoded strictly and cleared; bodies are never logged. Validation runs in memory; at most two PFX files are
  decoded at once (R38 item 40).
- **At rest.** The key is stored as PKCS #8 DER in `managed_private_keys`, sealed with a per-row data-encryption key
  under the master key, bound to its row (AAD). The application role can only insert and read these rows; the
  certificate's key cannot be replaced or detached (`Z1001`, `Z1002`). The leak suite (row 9) finds no form of any
  key in any table, log, response or email.
- **To the server.** The engine unseals the key only for the send, checks that it is the certificate's key, builds
  the helper's stdin JSON in a buffer of its final size and clears it right after the command copied it; the
  command holds stdin behind two pointers so that no `fmt` verb or `slog` handler prints it, and it is rebuilt for
  every re-send. The key travels on SSH stdin only, never in an argument. `sudo` keeps an output log
  (`log_output`), never an input log (`log_input` is not set), so the key is not in sudo's I/O log.
- **Helper.** stdin is read into one pre-sized buffer, decoded by a strict hand-written JSON parser into
  fixed-capacity buffers, and cleared; the staged key file is root 0600 before any content; the old key's backup is
  `key.bak` (root 0600 in a 0700 directory). No answer, error, journal field or syslog line carries key material
  (`TestDeployNeverRevealsKeyMaterial`). `nginx-dump`, `nginx-test`, `nginx-status` and the backup sweep never open
  a key file.
- **On disk.** The new key gets the old key file's owner and group and 0600 (0640 kept) (R38 item 34).

### Logs, audit, email and database

The TLS-key leak suite (row 9) covers every Phase 4 flow: PEM and PFX uploads and all their refusals, signing
requests, deploy success, rollback, failed rollback, a lost answer and its recovery, and reads of every route. It
scans every HTTP body and header, the debug log, every table (job payloads and results, deployments, steps,
audit, outbox, ciphertext columns) and every rendered email, for every spelling of the canary keys and for each
sealed key's plaintext and data-encryption key. Its non-vacuity was shown with a planted leak. The deploy engine has
its own leak test (`TestDeployAndRecoveryLeakNoKey`), and job and deployment error parameters pass an allowlist with
value rules.

## Review checklist

- [ ] The helper's rules (Global Constraints): it is the enforcement point and treats every argument, every byte
      of stdin and every line of `nginx -T` as hostile; exact argument vectors (`TestNginxWriteArguments`); writes only
      the pair its own authenticated configuration names, through root-controlled paths; never follows a link it
      does not own as root; never writes a file with another extension; never writes after its budget before the
      first rename and always finishes after it; journal and backups durable before the first rename; runs only
      `/usr/sbin/nginx` and `/usr/bin/systemctl` with a minimal environment, directory `/` and umask 022.
- [ ] Key material is only on stdin and in envelopes; never in an argument, a log line, an error, a job row, an
      audit row, an email or a response.
- [ ] `log_input` is never set in the generated sudoers file (`TestSudoers*`).
- [ ] The only `InsecureSkipVerify` is in `helperproto.ProbeTLSConfig` (`TestOnlyProbeTLSConfigSkipsVerification`);
      the probe compares the served leaf's SHA-256 and the chain length and never trusts the connection.
- [ ] Nginx's own error text never leaves the helper: `nginx -t` failures are reduced to a closed class
      (`key_mismatch`, `file_missing`, `cert_load`, `key_load`, `syntax`, or none).
- [ ] No raw `nginx -T` text leaves the server: `nginx-dump` answers the parsed summary, stat data and parsed
      certificates only, at most 16 MiB.
- [ ] Recovery (`certificate.deploy_recover`, `deployment.recovery_sweep`) is `ClassAlways`; `certificate.deploy`
      is `ClassChange`.
- [ ] The sweep cannot deploy: it queues recovery jobs and ends deployments, and recovery never calls
      `nginx-deploy` (it reads `nginx-status`, verifies and calls `nginx-restore`).
- [ ] A deploy request runs every check under the location and target locks and is all-or-nothing; a deployment
      never sends twice.

## Findings

| ID | Severity | Description | Decision |
|---|---|---|---|
| P4-01 | High (residual) | Whoever controls Alice (or its database and the master key) can deploy any certificate and key to every referenced certificate/key pair of every Nginx server, and so serve any of those websites' TLS. Same trust boundary as P3-01. | Accepted residual risk of the product; mitigations: the helper writes only pairs Nginx names, through root-controlled paths, audit of every deployment, emails on failures. Recorded in `SECURITY-REPORT.md` (Phase 8). |
| P4-02 | Medium | A local user who can edit an Nginx `include` file could make the helper write a certificate or key to any existing root-controlled file with a certificate or key extension that the configuration then names. | Mitigated: pairs touched by a non-root-writable configuration file are unsupported and refused by the helper (`config_file_writable`, with a warning naming the file); the extension rule; the **Custom location** mark for files outside the usual folders. Residual: S7 (see "Known limitations"). |
| P4-03 | Low | The verification probe connects to the target's address (from Alice) or to a listen address (from the server) on any port the Nginx configuration or an Administrator names, at most 10 endpoints. | Accepted; it sends only a TLS client hello and closes; the port setting needs an Administrator and is audited. |
| P4-04 | Low | Key material in memory is cleared best-effort only: Go strings (request PEM text, PFX passwords), parsed key objects (`big.Int` in `crypto/*`) and, in the helper, the abandoned stdin buffer after a timeout cannot be zeroed. | Accepted; core dumps are disabled in the container, buffers Alice owns are cleared. |
| P4-05 | Info | Backups of replaced private keys stay root-only on the server for 7 days (30 days when a restore failed; longer while an interrupted operation is waiting for recovery). | Accepted; `/var/lib/alice-helper/backups` is 0700 root, files 0600; the guide explains manual restore and removal. |
| P4-06 | High (fixed) | `nginx -T` section markers are plain comments: a user who can edit one included file could forge a `# configuration file` marker and re-pair another site's key file (proof of concept). | Fixed before merge: the parser refuses repeated marker names (b8e253d) and the helper compares every section with the real file and refuses the whole dump on any mismatch (Phase 4 helper, 3025fe5..6b6bb34). |
| P4-07 | Medium (fixed) | Pairs brought in by a writable file through an `include`, and an index shift through http-level directive lists, were still reported as supported. | Fixed: 9ac8b1a, 6b6bb34 (`TestAttackWritableFileThatContributesToAPair`, `TestAttackIndexShiftThroughHTTPLevelArrays`). |
| P4-08 | Low (fixed) | Existence oracle: after a forged section from a writable file, the refusal reason told whether a root-only file existed (proof of concept with `/root/exists.txt` and `/root/nope.txt`); a forged section exactly matching an empty root-only file passed. | Fixed: 988ccfe (every later failure answers `changed`), ae7f89f (sections must be reached by an include). Residue under S7, see "Known limitations". |
| P4-09 | Medium (fixed) | `filepath.Clean` folded `..` textually, so the reported path could differ from the file the kernel opens; procfs, sysfs and FUSE paths were trusted. | Fixed: raw paths with `.`/`..` segments are unsupported (b8e253d); pseudo and FUSE file systems refused on an `O_PATH` descriptor before any open (6b6bb34, 988ccfe). |
| P4-10 | High (fixed) | The certificate was not re-checked before the key's rename: a concurrent edit left the new key with a foreign certificate that could not be restored (proof of concept). | Fixed: both files are checked right before the first rename; between the renames the rollback puts back only what the operation wrote (1c518b1). |
| P4-11 | Medium (fixed) | `cleanup --op` deleted the backups of a `restore_failed` operation whose pair was still mixed (proof of concept); a later fix kept some such operations forever. | Fixed: kept exactly while `nginx-restore` can act on them (1c518b1, 5839d92). |
| P4-12 | Medium (fixed) | Restore walk-back: the invoking account could restore an older kept operation after a newer one and reinstate an older key (proof of concept); a later relaxation reopened it after cleanup. | Fixed: only the latest operation of a pair is restorable, also after cleanup (1c518b1, 58f897a). |
| P4-13 | Medium (fixed) | The deploy command printed the private key under ordinary `fmt`/`slog` formatting, and still did through an unexported struct field; `secrets.Plaintext` likewise. | Fixed: e341df0, 179ba82, c6d2b4f (stdin behind two pointers; guard tests with wrapper structs). |
| P4-14 | Medium (fixed) | Alice's own probe ignored the listen address (another block could answer and pass or fail the check), and a request without a fingerprint was "verified" against nothing. | Fixed: e451b8a (probe where the listen is; the leaf's fingerprint is always computed and compared). |
| P4-15 | Medium (fixed) | The deploy engine's record writes were not fenced: after a lost lease a stale run could record success over a rollback, or send after another run recorded "nothing was written". | Fixed: a5f386a, 50ffc39 (writes fenced to the job claim; fenced check before every send and rollback). |
| P4-16 | Medium (fixed) | Finished deployments could be rewritten by the application role, and the values recovery relied on were frozen at insert instead of recorded at the send. | Fixed: f17298d (trigger `Z1003`; recorded send values), 9f38fcc (one start method). |
| P4-17 | Medium (fixed) | A PFX file with a huge key-derivation iteration count kept the upload busy for hours. | Fixed for the outer structures (3812e2c, limit 1,000,000); the nested key bag is a known limitation, mitigated by the decode cap (R38 item 40). |
| P4-18 | Low (fixed) | A deployment that was never sent could be pushed into recovery and end "rollback failed" for a website that was never touched; some "restore failed" emails were untrue. | Fixed: 9f38fcc, aa1f28d. |
| P4-19 | Low (fixed) | The helper's pair paths were not validated by Alice (a hostile helper could have a malformed path shown as supported or merged with a real one). | Fixed: 7883cac, 31de3c4. |
| P4-20 | Low (fixed) | A race between cancelling and completing a signing request was untested; a pasted certificate field that held a key was copied on the heap uncleared. | Fixed: 7f500fc, e11ea56. |
| P4-21 | Low (fixed) | The web deploy dialog polled each deployment every second (20 websites ≈ 1,200 requests per minute against the 300 per minute session limit). | Fixed: 48ebf91 (one bounded loop per batch, `Retry-After` honoured). |

No High finding is open except the documented product residual P4-01.

## Known limitations

- **S5: sudoers is broader than the helper's argument check.** sudo's `*` also matches spaces, so for the two path
  arguments of `nginx-deploy` (and Phase 3's path lines) sudo lets a few extra words through. The helper's exact
  argument check refuses them (`USAGE`/`INVALID_ARGUMENT`); on the real matrix 28 variations are refused by sudo
  itself and 5 by the helper.
- **S7: `nginx -T` and `nginx -t` run as root over a configuration a non-root user may be able to write.** A
  configuration file another user can write already means code running as root at the next reload, independently
  of Alice. Alice surfaces it (`config_file_writable`, and a whole-server refusal when a configuration directory is
  not root-controlled) and refuses such pairs. Residue under S7: a forged section that exactly matches a root-only
  file, and the `duplicate_file` refusal, can still show whether such a file exists, only through Alice's
  discovery result.
- **PFX nested key bag.** A shrouded key bag nested inside an encrypted PFX content keeps an unchecked
  key-derivation iteration count (`go-pkcs12` v0.7.3 exposes nothing between decryption and key derivation). It
  needs the password and a valid MAC, so only a signed-in Administrator or Operator (or someone who hands them a file
  and its password) can use it; the effect is one CPU core busy per upload, at most two at once (the decode cap),
  until Alice restarts, and other PFX uploads answer `ALC-CRT-0015` meanwhile. To do: ask upstream for a
  maximum-iterations option, or vendor a patched copy.
- **S10: a new key is as exposed as the old one.** Owner, group and a 0640 mode are kept, so a key file owned by a
  user or readable by a group (Debian's `ssl-cert` included) gives that user or group the new key; the staged file
  is given the key's owner just before the rename, so such an owner could keep a copy even if the deployment is
  rolled back. Discovery warns (`key_group_open`).
- **A compromised Alice service account can restore the latest kept operation** of a pair (putting the previous key
  back while the backup exists, at most 7 days after a success) and delete backups with `cleanup`; it cannot reach
  older operations (R38 item 24) or write anything but supported pairs.
- **Host-name listens.** A `listen <host name>:port` whose name resolves to a non-loopback address of the server
  cannot be verified: the server-side probe goes to 127.0.0.1, Nginx bound the resolved address, so the pre-check
  refuses every deployment (`ALC-DEP-0005`). The only remedy today is to skip verification for that website (or
  change the `listen` to an address or a wildcard). The text of `ALC-DEP-0005` ("allow Alice to reach this port")
  does not fit this case.
- **Another server block on the target's own address and port.** Nginx sends every connection for that address to
  the address-specific block whatever the name, so Alice's probe sees that block: the pre-check refuses
  (`ALC-DEP-0004`); a deployment sent past the pre-check ends "files restored, not confirmed" (`ALC-DEP-0019`, the
  `restored_unverified` email). Never a false success.
- **Strict configuration rules refuse whole servers.** An `include` spelled through `..`, a configuration file name
  with a space or another character outside the helper's vocabulary, a configuration below a directory that is not
  root-controlled, a line at column 0 that looks like a
  `# configuration file` marker, or a missing `--conf-path` makes the server's configuration `untrusted` or
  `unsupported`: no website of that server can be deployed until it is changed. The page names the reason and, where
  it can, the file.
- **Group-writable site configurations are not managed** (S1): pairs touched by them are unsupported until the
  permissions are tightened.
- **Dropped certificate blocks.** When the helper drops a block that Go cannot parse (or labelled differently), the
  warning `certificate_block_dropped` is server-wide and does not name the file, and if it was the first block the
  next certificate in the file is shown as the website's certificate (the compare-and-swap hash still covers the
  whole file).
- **Untested environments.** Real systemd (`reload`, `is-active` unit state) is not tested: every test environment
  uses the `systemctl` shim, and `/usr/sbin/nginx` is a pass-through wrapper there; the real-systemd job is Phase 8.
  No NAT or firewall scenario is tested (the matrix reaches containers on Docker's bridge and needs a routable
  bridge, so it does not run on Docker Desktop); one helper instance per host; a real out-of-space error during a
  write is not reached (only the free-space threshold); the kill point between the key's and the certificate's
  rename is covered by the helper's root suites, not by the real-Nginx matrix; F-03 and F-04 are distinguished on
  real Nginx only with the shim's fault modes; `not_regular` and `special_filesystem` cannot be produced on a real
  host whose configuration is valid.
- **CI.** The new `ssh-matrix` job of `.github/workflows/ci.yml` has never run on GitHub (no remote run yet).
- **The same dropped connection can show different codes**: `ALC-SSH-0001` or `ALC-SSH-0003` (a recovery job could
  not reach the server) or `ALC-DEP-0010` (on the deployment), depending on how the transport reported it.
- **Large installations.** `nginx-dump` answers at most 16 MiB and describes at most 1000 referenced files
  (`too_many_files`); location lists show at most 1000 entries (`truncated`); the helper keeps at most 1000
  operations (`NO_SPACE`). Very large servers need a paging design later.
- **After the latest operation's backups are gone** (cleanup or the 7-day sweep) there is no helper-side restore for
  that pair; undoing means deploying the earlier certificate again.
- **A long Alice outage.** If Alice stays down longer than the helper keeps a journal (7 days after a success, 30
  days otherwise), the recovery of an unfinished deployment finds no journal and records it as failed with nothing
  written; the next discovery then reports the website as changed outside Alice if the new certificate is in place.
- **A crashing recovery job is visible only through the deployment** (its state, attempts and the audit row): a
  recovery job never sends the `job.dead` email.
- **Lease-loss residue.** The instant between a fenced check and the command it guards, and a command already in
  flight when the lease ends, are not fenced (the helper's lock serialises the commands and the live run reads the
  journal). A slow fenced write (`FOR SHARE` on the job row) can delay the heartbeat.
- **Stale website lists.** Alice does not store when it last read a server's websites (`facts.nginx.scanned_at`); the
  "websites as of" time is derived from the locations' last-seen times, and none is shown when no website was ever
  read. A failed certificate scan that is not a connection problem leaves no durable flag on the server.
- **Deploying from the certificate page** reaches only websites that already use that certificate; a renewal for a
  website that uses another certificate starts from the server's **Websites on this server** (the page shows a hint).
- **Verification reach.** Websites are checked from Alice's network or from the server itself; TLS 1.0/1.1-only and
  RSA-key-exchange-only websites cannot be verified (the probe needs TLS 1.2 or later); at most 10 endpoints are
  checked per location; a verification can take several minutes in the worst case (10 endpoints, 5 attempts, a
  probe from Alice and from the server each time).
- **Not managed:** combined certificate/key files, encrypted keys (`ssl_password_file`), engine keys, `data:` values,
  paths with variables, TLS in `stream {}` and `mail {}`; the Nginx binary path is fixed (`/usr/sbin/nginx`); a
  configuration path relative to the Nginx prefix (no `--conf-path`) is refused; `restorecon` is not run (the label
  is copied from the replaced file).
- **Not built in Phase 4:** private-key download (Phase 6); retry and rollback actions on a deployment (deploy again,
  or deploy the earlier certificate); the `nginx.backup_retention_days` setting and other Nginx settings (Phase 7);
  KV-bound deployments (Phase 5).
- **Signing requests.** The key of a cancelled or abandoned signing request stays sealed in the database (no
  deletion). A completed request accepts a certificate whose names differ from the request, with a warning.
- **Upload retries.** If the answer to a successful upload is lost, uploading again answers "Alice already has this
  certificate" (`ALC-CRT-0008`).
- **A deploy request is all-or-nothing** and names only the first website that stops it.
- **Held deployments.** A deployment queued before the license locked stays held (and its website reserved) until an
  Administrator runs or discards it.
- **sudo I/O logs.** `log_output` now also records `nginx-dump` answers (public certificates, paths); they grow with
  every scan and are the server administrator's to rotate.
- **Smaller items deferred** (no security effect): the issuer choice in a chain can drop a valid uploaded root when a
  still-valid cross-sign comes first; `chain_certificate_expired` also fires for an expired old copy of the leaf with
  the same key; a BER-encoded PFX is reported as a wrong password; after two helper crashes, cleaning up a
  passed-over operation can make the true latest one `SUPERSEDED`; the sweep's stat-only key decision can keep a
  backup longer than needed; an I/O error reading the pair records fails an otherwise unchanged deployment; the
  changed-outside check looks at the latest finished deployment only (a rare false "changed outside").
- **Coverage of root-only helper paths.** `make coverage` runs as a normal user; the root suites (row 2) and the
  real-Nginx matrix (row 3) exercise the helper as root.
- The Phase 1–3 findings and limitations still open stay as recorded in their review notes.

## Owner verification

Spec §26.6 "Owner verifies". You need:

- A **disposable** test server (a virtual machine with Ubuntu 22.04, Debian 12 or Rocky Linux 9) that the Alice
  machine can reach over SSH and on port 443, where you can become root and that runs Nginx from the distribution's
  packages (`sudo apt install nginx` or `sudo dnf install nginx`, then `sudo systemctl enable --now nginx`). Never use
  a production server.
- A development stack on the Alice machine (`make up`, or `make reset` for a fresh installation, which **deletes the
  development database, keys and license state**), signed in as an administrator, with the evaluation started.
- A host name for the test website that your browser resolves to the test server (a DNS entry or a line in your
  computer's `hosts` file), here `<your test site>`.

1. **Prepare the server and add it.** On the test server create a test website with an ECDSA certificate (the test
   pack's certificates are ECDSA), as root:

       mkdir -m 0755 -p /etc/nginx/alice-test
       openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 \
         -subj "/CN=<your test site>" -keyout /etc/nginx/alice-test/site.key -out /etc/nginx/alice-test/site.crt
       chmod 0600 /etc/nginx/alice-test/site.key

   and a file `/etc/nginx/conf.d/alice-test.conf` with
   `server { listen 443 ssl; server_name <your test site>; ssl_certificate /etc/nginx/alice-test/site.crt; ssl_certificate_key /etc/nginx/alice-test/site.key; }`,
   then `nginx -t && systemctl reload nginx`. On the Alice machine run `make helper` and copy
   `bin/alice-helper-linux-amd64` (or `-arm64`) to the server as `alice-helper` in a new directory only you can
   write. In Alice open **Servers**, choose **Server type** **Nginx server** and **Copy commands**; on the server save
   them next to `alice-helper` and run `sudo sh ./prepare-alice.sh`. Then **Add server** with **Server type**
   **Nginx server**, compare and confirm the fingerprint.
   Expected: "This server is ready for Alice."; `sudo -l -U alice-svc` lists the `nginx-dump`, `nginx-test`,
   `nginx-deploy`, `nginx-restore` and `nginx-status` lines; the server shows **Connected**.
2. **Discover.** On the server's page choose **Discover**.
   Expected: **Websites on this server** lists `<your test site>`, port 443, the file
   `/etc/nginx/alice-test/site.crt`, state **Ready**; **Certificates** lists the self-signed certificate with
   **Private key** "Not in Alice".
3. **Upload and deploy the good pair.** On the Alice machine run
   `go run ./tools/testcerts -out ~/alice-test-pack -name <your test site>`. On **Certificates** choose **Upload
   certificate**, **PEM text**, paste `good.pem` into **Certificate and chain (PEM)** and `good.key` into **Private
   key (PEM)**, **Upload**. On the server's page choose **Deploy certificate** in the website's row, pick the
   uploaded certificate and choose **Deploy**.
   Expected: "Certificate uploaded."; then "The new certificate is live and verified."; in a browser,
   `https://<your test site>` now shows the certificate issued by "Alice Test Pack" (the browser warns because the
   test root is not trusted: that is expected); on the server `ls -l /etc/nginx/alice-test` shows `site.key` still
   `-rw-------` root.
4. **Upload the broken pair.** **Upload certificate** with `broken.pem` and `broken.key`.
   Expected: "The certificate does not match its private key." and nothing is stored (the list is unchanged); the
   **Audit log** shows the refused upload.
5. **Deployment history.** Open **Deployment history** and the deployment of step 3.
   Expected: status **Succeeded**, **Verification** "Checked from Alice" (or "Checked from the server itself" if
   Alice cannot reach port 443), the steps **Check the current certificate**, **Backup**, **Write the private key**,
   **Write the certificate**, **Check**, **Reload**, **Verify** all **Done**, and **Backup on the server**
   `/var/lib/alice-helper/backups/<deployment ID>`.

Clean-up on the test server: see "Removing Alice from a server" in `docs/nginx-host-preparation.md`, then
`rm -rf /etc/nginx/alice-test /etc/nginx/conf.d/alice-test.conf && systemctl reload nginx`.

| Step | Result (pass, or what differed) | Date and tester |
|---|---|---|
| 1 | | |
| 2 | | |
| 3 | | |
| 4 | | |
| 5 | | |

## Sign-off

Reviewer, date and commit are filled in when the review is completed.
