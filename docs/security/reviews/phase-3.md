# Security Review — Phase 3 (Provider framework, Linux/SSH targets, alice-helper)

Scope (spec §17.2, Phase 3): host-key TOFU and change handling, the remote command allowlist, sudoers, injection
fuzzing. Exit criteria: the fuzz corpus is clean; a changed host key blocks all operations; no High finding open.

The decisions behind this phase are R37 in `docs/superpowers/specs/alice-v1/00-decisions.md`.

## Evidence

All commands run from the repository root; `-tags integration` needs Docker.

| # | Check | Command | Expected |
|---|---|---|---|
| 1 | Host-key pinning: an unconfirmed key stops before authentication, a changed key and a missing algorithm block, a failing host-key store is not a connection, a server that skips the client key is refused, a re-pin drops pooled connections (F-30, F-31) | `go test ./internal/providers/linuxssh -run 'FirstContact\|ChangedHostKey\|PinnedAlgorithm\|HostKeyStore\|NoCodeAcceptsAnyHostKey\|Repin\|WithoutTheClientKey' -count=1` | ok |
| 2 | Confirmation and re-pin rules, one email per change, history kept, dismissal, stale candidates never pinned, background jobs never pin (F-30..F-33) | `go test -tags integration ./internal/inventory -run 'F30\|Confirm\|Changed\|Repin\|Observed\|Dismiss\|Stale' -count=1` and `go test -tags integration ./internal/api -run 'TestAddServerJourney\|TestChangedHostKeyJourney\|TestDismissedHostKeyChange' -count=1` | ok |
| 3 | Command surface: only helper constructors and `cat /etc/os-release`; one quoting function; no session call outside `dial.go`; no `InsecureIgnoreHostKey`, no `StrictHostKeyChecking=no`; sudoers matches every built command; the setup script never writes through `alice-svc` paths and checks the helper checksum (A-12, SEC-063) | `go test ./internal/providers/linuxssh/... -run 'Command\|Quote\|OnlyDial\|Hostile\|Sudoers\|SetupScript\|HelperCheck' -count=1` and `make lint` | ok |
| 4 | Helper argument and path validation, candidate-only paths, symlinks out of the home refused, hard links and foreign owners refused, swap races, atomic compare-and-swap writes, lock file, backups and their 30-day sweep (A-12, A-13, F-38) | `go test ./cmd/alice-helper -count=1` (as a normal user the three root-only tests `TestWriteAsRoot`, `TestStaleRootInodeInUserDirIsRefused` and `TestAttackSSHDirSwappedForARootDirectory` skip; run it as root on a disposable machine to include them) | ok |
| 5 | Helper is a static binary that links only the allowed modules | `go test ./cmd/alice-helper -run TestHelperIsStatic -count=1` and `make helper` | ok |
| 6 | Parsers fuzzed (§25.6) | `make fuzz-ssh` | no crasher |
| 7 | Key operations: own key refused by fingerprint, last root key, keys managed elsewhere, `cert-authority` lines, CRLF and foreign lines preserved, three compare-and-swap attempts; removal requests refused before queueing; database trigger protects Alice's key location (F-35..F-38) | `go test ./internal/providers/linuxssh -run 'Remove\|Add\|KeyOperations\|ConcurrentChange\|Write' -count=1` and `go test -tags integration ./internal/inventory -run 'Removal\|Protect\|Trigger\|PlatformKey' -count=1` | ok |
| 8 | Real OpenSSH on Ubuntu 22.04, Debian 12, Rocky 9: setup script, sudoers profile, discovery, F-31 with a rotated host key, F-35, F-37, F-38 | `make test-ssh` (`go test -count=1 -tags integration -run TestRealOpenSSH ./internal/providers/linuxssh/`) | ok |
| 9 | Job queue: exactly once with 20 workers and 1000 jobs, per-target exclusivity, retries, MAC tamper, crash recovery kill test, fenced writes, leader lock, alerts (F-66, F-69, J-1) | `go test -tags integration ./internal/jobs/... -count=1` | ok |
| 10 | License: target limit and lock with real targets, blocked removals wait for an administrator (L-04, L-26, L-29, L-70..L-79, L-81) | `go test -tags integration ./internal/inventory -run 'L0\|L7\|AddInLock' -count=1`, `go test -tags integration ./internal/api -run 'TestLockRefusesInfrastructureChanges\|TestBlockedRemovalNeedsConfirmation\|TestEvaluationLimitViaAPI' -count=1`, `go test -tags integration ./internal/jobs -run Lock -count=1` and `go test ./internal/archtest -count=1` | ok |
| 11 | Authorization matrix incl. the five new permissions; lock-group rules; test and discover are read-only class and refused in lock | `go test ./internal/api -run 'Authz\|RouteRule\|Lock\|Sensitive\|Gated\|InfrastructureRoutes' -count=1` and `make authz-doc && git diff --exit-code docs/authz-matrix.md` | ok, no diff |
| 12 | Secret leak with the platform SSH key (seed, OpenSSH PEM) through journeys and error paths; S-04 ciphertext | `go test -tags integration ./internal/api -run 'TestSecretsNeverLeak\|TestPlatformKeyNeverLeaks' -count=1` | ok |
| 13 | Grants: `credentials` append-only, inventory never deleted, own-key protection trigger cannot be bypassed; `00004` Down safe | `go test -tags integration ./migrations -count=1` | ok |
| 14 | Coverage floors | `make coverage` | every package ok |
| 15 | E2E EN/TR incl. axe at 375/640/1280/1920 px on the new screens and banners, on the separate compose project `alice-e2e` | `make e2e-up && make e2e-hardening-check && make e2e`, then `make e2e-down` | all passed |

L-81's browser "Run now" is covered by Vitest (`make web-test`) and the Go integration test of row 10, not by
Playwright: the e2e build has no deterministic way to queue a job before the lock begins.

## Review checklist

- [ ] `HostKeyCallback` decides from the pinned key only; an unpinned or different key aborts before
      authentication; `Observed` is the only write and never pins.
- [ ] `HostKeyAlgorithms` is the pinned type only; key exchange, ciphers and MACs are the SEC-080 lists.
- [ ] The only command lines are `cat /etc/os-release`, `/usr/local/libexec/alice-helper version` and
      `sudo -n /usr/local/libexec/alice-helper <subcommand> '<arg>'…` with arguments from `[A-Za-z0-9._/@:+-]`.
- [ ] The helper refuses every path it did not compute itself from `/etc/passwd` and `sshd -T`, resolves symlinks
      and keeps them inside the user's home (also for an absolute pattern that points into the home) or inside a
      root-controlled directory of an absolute pattern, reads or writes a file reached through a symlink only in a
      directory of its user, opens a candidate the scan reached without a symlink with `RESOLVE_NO_SYMLINKS` (a
      symlink that appeared after the scan is refused) and one reached through a symlink still beneath its allowed
      directory (`RESOLVE_BENEATH`) and only in a directory of its user, requires root-controlled directories above
      every home (and, for a symlinked home, a resolved home of the account itself), never prints private key
      material, and
      writes with a root-private lock file, hash check of the current file, hash check of the received content
      (`--content-sha256`, protocol 3: a connection dropped mid-transfer never leaves a truncated file), backup,
      temporary file, `fsync`, rename and directory `fsync`.
- [ ] sudoers allows only `alice-helper` subcommands of the chosen profile with the narrowed argument patterns
      (R37 item 3); `!requiretty`, `!lecture`, `env_reset`, `secure_path`, `log_output`.
- [ ] The setup script never writes, chowns or chmods through a path `alice-svc` controls, leaves no file in
      `alice-svc`'s home that `alice-svc` owns (no `/etc/skel` files; everything but `.ssh` is removed on every run),
      and installs only a helper whose SHA-256 matches the checksum built into Alice: it copies `./alice-helper`
      into a fresh root-only directory first and checks and installs that copy, so the file cannot be swapped
      between the check and the install.
- [ ] The platform key seed is only decrypted inside one dial and zeroed afterwards; it never reaches a log,
      error, audit row, job row or response (leak suite).
- [ ] Remote output is size-capped, decoded as one JSON value, and never logged; stderr is discarded.
- [ ] Job payloads are MAC'd; a changed payload is never executed (`job.tampered`).
- [ ] Every target insert calls `CheckCanAddTarget` in its transaction (L-79 static test).

## Findings

| ID | Severity | Description | Decision |
|---|---|---|---|
| P3-01 | High (residual, spec SC-6) | Whoever controls Alice (or its database plus the master key) can sign in to every managed server as `alice-svc` and use the helper's subcommands there. Whoever can run as `alice-svc` on a server is effectively root on it: `authkeys-write` accepts new content for every listed account's file, `root`'s included (only Alice applies the last-root-key guard, not the helper). | Accepted residual risk of the product (decisions "Threat model"); mitigations: restricted sudoers, the helper's own validation, optional `from=` in the `authorized_keys` line, audit forwarding. Recorded in `SECURITY-REPORT.md` (Phase 8). |
| P3-02 | Medium (spec SC-1) | Trust on first use: an attacker between Alice and a new server at the moment it is added can present their own key; the administrator must compare the fingerprint out of band. | Accepted; the UI shows the exact command to run on the server and never pins without an administrator's click. |
| P3-03 | Medium (spec J-1) | The job payload MAC is derived from the master key; an attacker with the database and the master key can insert a valid job. | Accepted (same trust boundary as every secret). |
| P3-04 | Medium | An explicit **Test connection** within 60 s of the previous use reused an idle pooled connection, so it could report success for a server whose host key had just changed. | Fixed before the Phase 3 merge (controller ruling): the test job dials a fresh connection (`providers.Env.FreshConnection`), and a dial that finds a changed key closes the target's idle connections. Scans and removals within 60 s may still reuse a connection opened with the old key (see "Known limitations"). |
| P3-05 | Low | Accounts known only to LDAP/SSSD are not listed, so their keys are not inventoried. | Accepted for v1 (R37 item 4); a warning names the gap on each such server. |
| P3-06 | Low | The `nginx` sudoers profile keeps `*` wildcards that accept any arguments; the helper is the enforcement point. The `linux` profile lines are narrowed (R37 item 3). | Accepted (spec §12.3); helper validation is tested on three distributions; the Nginx lines are narrowed with their command builders in Phase 4. |
| P3-07 | Low | Helper backups of `authorized_keys` (public data) stay on the server for up to 30 days; Alice does not call `cleanup` in Phase 3. | Accepted; they are root-only (0700/0600). |
| P3-08 | Info | The `nginx` sudoers profile already allows subcommands that protocol 3 answers with `UNKNOWN_SUBCOMMAND`. | Intended (R37 item 3). |

No High finding is open except the documented product residual P3-01.

## Known limitations

- **Audit chain is unkeyed.** The audit log is a plain SHA-256 hash chain. It detects changed and deleted entries,
  but `alice_app` (or anyone with its database password) can append new rows that verify as valid. External
  anchors (syslog forwarding, signed checkpoints) arrive in Phase 7. The daily check (`audit.verified` by
  `scheduler`) only re-checks the chain.
- **Directory-service accounts.** The static helper reads `/etc/passwd` only; users that exist only in LDAP or
  SSSD are not listed (warning `directory_users_not_listed` per server). At most 200 accounts are listed per server
  (warning `too_many_users`).
- **Helper base directory.** The helper opens the base directory of a key file (the user's home, or the directory
  an absolute `AuthorizedKeysFile` names) by its path and resolves everything below it through that descriptor.
  This is safe only while every directory above it (for example `/home` and `/`) is controlled by root, so the
  helper checks it at the scan: every existing directory above the home must be root's and not group or other
  writable. A symlink among those directories is accepted only when root owns it and the path it leads to passes
  the same check (at most 40 links, so a loop is refused) and its target has no `..` component (the check must
  look at the same path the kernel opens, and the path it checked must equal the resolved path); this covers
  `/home -> /data/home` and Fedora's `/home -> var/home`. A symlink owned by another user, one whose target contains `..`, or one that leads into a
  directory another user owns or can write, makes the account unsupported. A home that is itself a symlink must lead to a directory owned by the
  account (root excepted) below such directories. The directory of an absolute pattern outside the home must not
  be reached through any symlink. Otherwise the account's key files are reported as unsupported and never read
  or written. Standard layouts (`/home/<u>`, `/root`, `/var/lib/<x>`) pass; a home below a directory other users
  can write (for example a group-writable `/srv/homes`) does not. The check and the open are separate steps: a root-controlled layout
  cannot change in between, which is why the check is required.
- **Last-key guard for uid-0 accounts.** Alice's linuxssh provider asks for an administrator's confirmation before
  it removes the last key of the account named `root`, and of any account that an account listing made earlier in
  the same session reported with uid 0. The helper lists no uid-0 account other than `root` today, so in practice
  the guard covers `root` only. Inventory's own
  pre-check before queueing a removal still looks at the name `root` only, so for another uid-0 account the refusal
  arrives when the job runs rather than when the removal is requested.
- **`.ssh` created with root's supplementary groups.** The helper creates a missing `.ssh` with the user's
  filesystem uid and gid but keeps root's supplementary groups. Ownership is the user's either way; a directory
  that ended up group-writable would be refused by the StrictModes check of the next write, never used.
- **Platform-key rotation and pooled connections.** A connection opened before the platform key was replaced keeps
  authenticating with the old key's session for up to 60 s (the pool idle time).
- **`Match Address` and `Match Host`.** The helper evaluates per-user settings with
  `sshd -T -C user=<u>,host=localhost,addr=127.0.0.1`. Blocks that match on the client address or host name of
  real clients cannot be evaluated; their `AuthorizedKeysFile` and `AuthorizedKeysCommand` are not seen.
- **Internal test and error details.** The fake provider's configuration copy is shallow (tests only), and a
  credential failure of the platform key is reported without its cause (deliberately: the cause can name key
  material).
- **Stale host-key candidates.** A key a server presented and no longer presents stays as a candidate until an
  Administrator acts. If a blocked server presents its pinned key again, the block stays, the page still offers the
  old candidate (accepting it fails with `ALC-TGT-0003`), and the block can only be ended through the API by
  re-pinning the pinned key (`hostkey.change_dismissed`); the UI has no button for this yet.
- **Servers without readable sshd settings.** Alice refuses key removal on a server (or for a user) when the last
  scan could not run `sshd -T`, because it cannot know which file sshd honours. A server whose `sshd -T` fails
  permanently cannot have keys removed through Alice.
- **Pooled connections (P3-04).** **Test connection** always dials a new connection, so it sees the host key the
  server presents now. Scans and key removals within 60 s of Alice's last work on a server may reuse an idle
  connection (after a liveness probe) that was opened with the previous key; a server that was reinstalled drops
  those connections, and a changed key is detected on the next new connection. The e2e test still moves the demo
  clock past the idle time before it tests a rotated key (it is not needed any more, but harmless).
- **Missing keys per path.** A key location is marked "no longer found" only when its file was read in the scan,
  matching on the file path and not the user, so an absolute `AuthorizedKeysFile` shared by several users is
  tracked per path (R37 item 23).
- **No automatic restore.** When reading a key file back after a write does not show the expected content, the job
  stops for a person (`ALC-KEY-0005`) and names the backup; restoring is manual until Phase 4.
- **No certificates yet (Phase 4).** Nginx servers can be added only as Linux servers; `nginx-*` subcommands and
  the deploy job arrive with the next helper protocol. L-80 and L-82 need the deploy job.
- **No key generation or rotation (Phase 6).** Keys can be removed, not generated or deployed through the UI;
  L-83..L-86 and L-88 need the rotation runner.
- **Alerts (Phase 7).** Host-key, sign-in, dead-job, tampered-job and audit-chain emails are sent directly; the
  alert list, dashboard and email settings arrive in Phase 7. SSH limits are constants until Settings exist.
- **Target edits.** Only the name and the scan interval can be changed (API; the UI has no edit form yet).
- **Address checks.** SEC-065's "unless explicitly allowed" switch is not built: link-local and metadata,
  unspecified, multicast and broadcast addresses are always refused, loopback is allowed.
- **Packaging (Phase 8).** The helper is built with `make helper`; the release bundle and its signature arrive in
  Phase 8. Master-key rotation (which must re-seal the installation record and the time record, and re-encrypt the
  platform key) is not built. Replacing the platform SSH key is a manual procedure (`docs/operator-guide.md`).
- **Coverage of root-only helper paths.** `make coverage` runs as a normal user, so the helper's root-only tests
  are skipped there; the real-OpenSSH suite (row 8) exercises the helper as root inside the test containers.
- The Phase 1 and Phase 2 findings still open stay as recorded in their review notes.

## Owner verification

Spec §26.5 "Owner verifies". You need:

- A **disposable** test Linux server (a virtual machine with Ubuntu 22.04, Debian 12 or Rocky Linux 9, x86_64 or
  aarch64) that the Alice machine can reach over SSH, where you can become root. Steps 1 and 5 change it; never
  use a production server.
- A development stack on the Alice machine: `make up` (keeps your data) or `make reset` for a fresh installation
  (**this deletes the development database, keys and license state**), then `make setup-token` and the setup
  wizard (`docs/first-run.md`) with **Start 30-day evaluation (up to 5 targets)**.
- An administrator with an email address (to see the email of step 5) and a second user with the role
  **Operator** (create one on **Users**).

If `deploy/.env` sets `ALICE_PORT`, open `https://localhost:<port>` instead of `https://localhost`.

1. **Prepare the server.** On the Alice machine run `make helper`. Copy `bin/alice-helper-linux-amd64` (or
   `-arm64` for an aarch64 server) to the test server as `alice-helper` in a new directory that only you can write
   (not a shared directory such as `/tmp`), for example with `ssh you@server mkdir -m 700 alice-setup` and
   `scp bin/alice-helper-linux-amd64 you@server:alice-setup/alice-helper`. In Alice open **Servers**: **Prepare a
   server for Alice** shows Alice's public key, its fingerprint and the commands. Choose **Server type** **Linux
   server** and **Copy commands**. On the server save them as `~/alice-setup/prepare-alice.sh` and run
   `cd ~/alice-setup && sudo sh ./prepare-alice.sh`.
   Expected: the last line is "This server is ready for Alice."; `sudo -l -U alice-svc` on the server lists only
   `/usr/local/libexec/alice-helper` subcommands; `ls -ld /var/lib/alice-svc /var/lib/alice-svc/.ssh` shows root as
   owner. If the script says "./alice-helper is not the alice-helper of this Alice version", the file was built
   from another commit or Go version than the running Alice image: rebuild both from the same checkout
   (`make helper` and `make up`).
2. **Add the server.** Choose **Add server**, enter a name, the server's address and the user name `alice-svc`
   (already filled in), choose **Connect**. Alice shows **Is this your server?** with a fingerprint and a command.
   Run the command on the server and compare. Choose **Yes, this is my server**.
   Expected: the server shows **Connected** within a few seconds.
3. **Inventory.** Wait a few seconds (or choose **Scan for SSH keys** on the server's page).
   Expected: **SSH keys on this server** lists the keys of `root`, of normal users and of `alice-svc` (marked
   **Alice's key**) with their user names. On **SSH keys**, open one key: **Where this key is used** lists the
   server, user, file and line.
4. **Own key.** On the server's page, choose **Remove key** in the row of `alice-svc` (Alice's key) and confirm
   with **Remove key**.
   Expected: "Alice needs this key to connect to this server and will not remove it." Nothing changes on the server
   (`sudo sha256sum /var/lib/alice-svc/.ssh/authorized_keys` prints the same value before and after), and the
   **Audit log** shows "SSH key removal refused".
5. **Changed host key.** On the test
   server run `sudo rm /etc/ssh/ssh_host_*` and `sudo ssh-keygen -A`, then restart the SSH service
   (`sudo systemctl restart ssh` on Ubuntu and Debian, `sudo systemctl restart sshd` on Rocky). In Alice choose
   **Test connection**.
   Expected: a red message "The server's identity has changed, so Alice stopped all work on it. …"; the status is
   **Server identity changed**; **Scan for SSH keys** and key removal are refused; administrators with an email
   address get one email (without `ALICE_SMTP_*` settings no email is sent; the **Audit log** shows "Server
   identity changed" either way). Sign in as the operator in a private window: there is no
   **Review the new fingerprint** button. As the administrator choose **Review the new fingerprint**, compare the
   new fingerprint on the server, enter a reason of at least 10 characters, choose **Accept new fingerprint** and
   enter your authenticator code if Alice asks for it.
   Expected: the server returns to **Connected**; the **Audit log** shows "New server fingerprint accepted".
6. **License limit.** The evaluation allows 5 servers. Add servers until there are 5 (the addresses may be other
   test machines or unused addresses in your network; a server that cannot be reached still counts; choose
   **No, cancel** at the fingerprint question if one appears), then try one more.
   Expected: "Your license allows 5 targets." and no new server; administrators see the banner "You are using all
   5 licensed targets. …". Remove the extra servers afterwards with **Remove server**.

Clean-up on the test server: see "Removing Alice from a server" in `docs/nginx-host-preparation.md`.

| Step | Result (pass, or what differed) | Date and tester |
|---|---|---|
| 1 | | |
| 2 | | |
| 3 | | |
| 4 | | |
| 5 | | |
| 6 | | |

## Sign-off

Reviewer, date and commit are filled in when the review is completed.
