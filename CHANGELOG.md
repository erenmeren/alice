# Changelog

## Unreleased — Phase 5: Azure Key Vault

**Upgrade notes**
- Migrations `00008` (Key Vault tables, connections, imports) and `00009` (a version's chain flag) run at start.
  Once a vault exists, `00008` refuses to go down.
- Alice now connects to Azure (`login.microsoftonline.com` and each vault's `<name>.vault.azure.net`, TCP 443)
  when a vault is added; allow both outbound. Do not set `AZURE_REGIONAL_AUTHORITY_NAME`, `MSAL_FORCE_REGION` or
  `AZURE_SDK_GO_LOGGING` for the Alice container: with any of them Alice refuses to sign in to Azure
  (`ALC-AKV-0011`). Proxy variables are ignored for Azure.
- API clients that deploy a vault version Alice knows to have an incomplete chain must send
  `confirm_incomplete_chain` (Administrator); otherwise the request is refused with 409 `ALC-CRT-0011`.

### Added
- **Key Vaults**: add an Azure Key Vault (administrators, with a fresh authenticator code) by name or address, signing
  in with a certificate (recommended), a client secret or the managed identity of the Azure virtual machine Alice
  runs on. Alice checks the sign-in and the certificate list before it stores anything; the **Access check** shows,
  per feature (monitor, deploy, import), what the identity may do and the Azure role that is missing, with the
  `az` commands to grant it. Each vault counts as one license target.
- The vault's certificates (versions, expiry, thumbprints, exportable key or **Monitor only**), keys (type, size)
  and secrets (metadata only; values are never read), checked every 15 minutes by default (5 to 1440 minutes) and
  with **Check now**; statuses **Connected**, **Partly working**, **Credentials refused**, **Cannot reach Azure**.
- **Connect websites**: a vault certificate follows up to 200 Nginx websites. **Automatic deployment** (off by
  default; administrators) deploys a new current version found after it was switched on, through the Phase 4
  deployment engine with a first step **Read the certificate from Key Vault** (the exact version, before anything
  is sent to the server): five at a time per connection, one hour between attempts on a website, stopped after
  three failures with one email. **Deploy now** deploys any version Alice has read.
- Versions that appear while the license is locked, or with an incomplete chain, are **Held** for an administrator,
  who deploys or releases them.
- **Import into Key Vault** (administrators): copies a certificate Alice holds with its key into a vault, sent once
  and never again by itself; an import whose answer was lost reads **Not confirmed yet** until a check settles it.
- Emails to administrators for repeated sign-in failures, removed certificates, versions not deployed
  automatically, stopped automatic deployments and failed or unknown imports (at most 20 of a kind per vault and
  run, then a summary).
- Error codes `ALC-AKV-0001..0041`; audit actions `vault.*`, `kv.*` and `binding.*`; every read of a certificate's
  secret is audited (`kv.secret_read`). Jobs name their deployment or import (`deployment_id`, `import_id`).
- `GET /api/v1/certificate-locations` lists websites across servers.
- Guides: `docs/azure-setup.md` for Azure administrators (identity, roles, access policies, network), the Key
  Vaults chapter of `docs/operator-guide.md`, Key Vaults in `docs/admin-guide.md`, `docs/licensing.md` and
  `docs/troubleshooting.md`.
- Developer targets: `make test-azure` and `make record-azure` (optional, against a real vault, never in `make ci`);
  the e2e stack runs a fake Azure service (`fakeazure`). `make coverage` enforces floors for
  `internal/platform/azureid` (100), `internal/providers/azurekv` (98) and `internal/jobs/kvjobs` (100), and raised
  ones for `internal/api` (94), `internal/certs` (98) and `internal/inventory` (89).

### Changed
- A new permission, `credentials.manage` (Administrator with a fresh authenticator code, never an API token), gates
  adding a vault, replacing its credentials, automatic deployment, releasing a held version and importing.
- Lock mode also stops vault checks, adding vaults, connecting websites, **Deploy now** of vault versions and
  imports; switching automatic deployment off and deleting a connection stay possible.
- The scrolling part of every table is a keyboard stop (a named group) with a visible focus ring, and field errors
  are drawn with a higher contrast.
- "Busy reading other PFX files" (`ALC-CRT-0015`) now says to try again, since a Key Vault deployment can meet it
  too.

### Known issues
- Nothing was tested against real Azure: the fake service follows the public REST reference. Whether `Key Vault
  Reader` alone is enough to monitor a vault is expected but not confirmed.
- Public Azure cloud only; no HTTPS proxy or custom CA for Azure; managed identity only on Azure virtual machines;
  no deployment windows; no reminder email before a client secret or sign-in certificate expires.
- The full list is in `docs/security/reviews/phase-5.md` ("Known limitations" and "Not verified against Azure").

## Unreleased — Audit remediation

Fixes for the independent audit of 2026-10-04; the full record is `docs/security/reviews/audit-remediation.md`.

**Upgrade notes**
- **Update `alice-helper` on every managed server first, then Alice.** This release needs helper protocol 6
  (`alice-helper` 1.5.0); the new helper also works with the previous Alice. Copy the `alice-helper` of this release
  next to the setup commands from **Servers** and run them again on each server (the sudoers file does not change).
  A server whose helper is older shows "The alice-helper on this server is outdated." (`ALC-SSH-0005`) and Alice does
  nothing on it, deployment recovery included, until it is updated.
- **Set a new password** and **Sign out everywhere** now also revoke the person's API tokens: scripts of a person
  whose password an administrator resets need new tokens.
- **The 30-minute idle timeout now works:** a page left open is signed out 30 minutes after the last click, key,
  wheel or touch, although it keeps refreshing.
- Migration `00007` (applied at start) makes the installation record's protection read-only for the application
  role. A development database that was never started since before Phase 2 reads as tampered: `make reset`.
- The CSV audit export has a new first line; readers that expect the column names on line 1 must skip it.
- Behind a reverse proxy, set `ALICE_TRUSTED_PROXIES` (now passed to the container) to the proxy's address only;
  otherwise every client shares the proxy's address for the request limits.
- A new installation needs an empty state volume: a time record left by an earlier installation ends the new
  installation's evaluation.

### Security
- Idle timeout: only a person's activity extends a session (a change, or a page request the web marks after real
  input); background refreshes no longer keep an unattended browser signed in.
- License gate: Alice counts the time between its license checks itself, stops changes at the lock time without
  waiting for the next check, and pauses changes ("Alice could not check its license since …", `ALC-LIC-0009`) when
  no check has succeeded for 3 hours; the check runs in every Alice process and is retried within minutes. Queued
  work waits and resumes by itself; deployment recovery and rollback keep running.
- SSH key inventory: accounts with dots, capitals or a final `$` in their names (`john.doe`, `Deploy2`, `host$`) and
  homes with a trailing `/` are listed; every `/etc/passwd` entry Alice cannot list is shown as a server warning
  with its user ID, and the server's account list then counts as incomplete (also for a NUL byte in `/etc/passwd`,
  any non-local account source, systemd user records and an unreadable `nsswitch.conf`). The last-root-key guard
  covers every account with user ID 0.
- API tokens are revoked by an administrator's **Set a new password**, **Sign out everywhere** and **Disable**, one
  audit entry per token; a token or recovery codes can no longer be created by a session that is being signed out.
- Server addresses are checked again each time Alice connects (SSH and its own website check): a name that
  resolves to a link-local (cloud metadata), multicast, unspecified or reserved address is refused
  (`ALC-SSH-0012`).
- Requests with credentials Alice does not accept are limited per client address before the database is asked;
  stale session cookies are deleted; the public `/healthz` is limited.
- Text PostgreSQL cannot store (NUL, invalid UTF-8 in queries, `\u0000` in JSON) is refused before any handler
  (`ALC-SYS-0004`); list cursors are bounded; certificates dated outside the years 1 to 9999 are refused; an answer
  that cannot be encoded is a complete 500, never a cut-off 200.
- Parallel sign-in attempts for an existing and for an unknown user name now queue and do the same work, so their
  timing no longer tells the names apart; a small residual (a millisecond-scale database write for a real account,
  weaker legacy password hashes) is recorded in R39 item 12.
- Resetting the setup code wins against an administrator creation in progress; the master key file's directory is
  synced when the key is created.
- An installation record without its protection is never trusted, and more traces show that an installation
  existed; refusal entries are written even when the client has gone.

### Changed
- `alice-helper` 1.5.0 (protocol 6) is required; a discovery reads the key files in one pass.
- Repeated refusals of the same person, permission and request are recorded once per 10 minutes, with a later
  entry that counts the rest (`suppressed_count`; all sessions of a person together, all their tokens together).
- One audit log check or export runs at a time (`ALC-AUD-0001`, try again later); an export may take up to 10
  minutes; the CSV export starts with `# alice audit export: intact=… checked=… head_seq=… head_hash=…`.
- The public `/healthz` answers at most 60 requests a minute per address; the internal health listener and `/livez`
  are not limited.
- A signed license in a newer format asks to update Alice (`ALC-LIC-0006`) also when it has new fields; an unsigned
  or edited one is "not a valid license".
- Discarding a waiting job is possible in every license state.
- `make up` and the other development-stack targets read `deploy/docker-compose.override.yml`; `ALICE_TRUSTED_PROXIES`
  and `ALICE_LOG_LEVEL` reach Alice.
- The web interface: an error page instead of a blank screen, English when the Turkish texts cannot load, all
  waiting jobs (**Show more**), the step-up dialog closes when the session ends, and the audit log shows each entry's
  object and details.

### Added
- Error codes `ALC-LIC-0009` (license could not be checked), `ALC-SSH-0012` (address not allowed) and
  `ALC-AUD-0001` (audit check or export already running).
- Server warnings for accounts Alice could not list (by name, user or group ID, or home directory, each naming the
  user ID) and for a NUL byte in `/etc/passwd`.
- `make image-check` (the release image and its binary checked without network), build-tag checks in
  `release-symcheck` and `internal/archtest`, `tools/pincheck` (actions by commit, images by digest), Dependabot,
  `npm ci --ignore-scripts`, `go mod verify`, Vitest coverage thresholds and coverage floors for more Go packages;
  CI runs on every branch and pull request.

### Known issues
- Accounts with user IDs 1–999, `nologin` shells or no home are not inventoried; some servers keep an incomplete
  account list for good (directory services, systemd-homed, unsupported names).
- Clients behind one address (NAT, a reverse proxy without `ALICE_TRUSTED_PROXIES`, rootless Docker) share the
  limit for unaccepted credentials.
- A server name that later resolves to 127.0.0.1 is still connected to.
- The lockout of an account also blocks its step-up and password change; the CI workflow has never run on GitHub;
  the npm lockfile is not scanned for secrets.
- The full list is in `docs/security/reviews/audit-remediation.md` ("Known limitations").

## Unreleased — Phase 4: Nginx certificates

### Added
- **Nginx servers**: add a server as **Nginx server** (prepared with the `nginx` setup commands). **Discover** reads
  its SSH keys and its websites together: every `ssl_certificate`/`ssl_certificate_key` pair Nginx uses, with the
  certificate, its expiry, the file's owner and mode, and a plain reason for each place Alice cannot manage.
- **Certificates**: one list of the certificates found on servers and the ones you added, with filters, details,
  chain check and where each is used.
- Certificate upload as PEM text or PFX file (administrators and operators), checked before anything is stored;
  private keys are stored encrypted and never shown again.
- Signing requests: Alice creates the key (ECDSA P-256, RSA 3072 or RSA 4096) and the request; you add the signed
  certificate when it arrives.
- **Deploy certificate**: to one website from the server's page, or to up to 20 websites that use a certificate from
  its page. The helper backs up the current files, writes the new key and certificate, runs `nginx -t`, reloads Nginx
  and puts everything back when a step fails; Alice checks the website before and after, from its own network or
  from the server itself.
- **Deployment history** with every step, the result, the verification, and the backup folder on the server.
- Interrupted deployments are finished or undone automatically from the helper's journal on the server, also while
  the license is expired; administrators get emails for failed deployments, deployments that need manual action and
  deployments Alice cannot finish.
- **Verification settings** per website (administrators): the port and name Alice checks, or no check.
- Helper protocol 5 (`alice-helper` 1.4.0): `nginx-dump`, `nginx-test`, `nginx-deploy`, `nginx-restore`,
  `nginx-status`, `nginx-fence` (sudo, with narrow sudoers lines) and `tls-probe` (no sudo). `nginx-fence` lets
  Alice prove that an interrupted deployment it has no journal for can never be applied later.
- Error codes `ALC-NGX-0001..0010`, `ALC-CRT-0001..0017`, `ALC-DEP-0001..0024` and the audit actions
  `certificate.*`, `csr.*`, `location.*` and `deployment.*`.
- Uploading a certificate Alice already holds with an incomplete chain, now with its complete chain, completes the
  stored chain (`certificate.chain_completed`); any other repeated upload is still refused (`ALC-CRT-0008`).
- Developer targets: `make fuzz-nginx`, `make fuzz-certs`; `make test-ssh` also runs a real-Nginx matrix on Ubuntu
  22.04, Debian 12 and Rocky 9 and is part of `make ci` and of a new CI job; `go run ./tools/testcerts` writes a test
  certificate pack.
- Guides: certificates and deployments in `docs/operator-guide.md`, verification settings and deployment emails in
  `docs/admin-guide.md`, the Nginx profile, backups and manual restore in `docs/nginx-host-preparation.md`.

### Changed
- Every server needs the new helper (protocol 5): copy the `alice-helper` of this release next to the setup commands
  and run them again on each server (Alice reports older helpers with `ALC-SSH-0005` and does nothing on them until
  then; see "Updating the helper" in `docs/nginx-host-preparation.md`). The `nginx` sudoers lines changed with it
  (new `nginx-fence` line).
- The helper refuses a deployment while the website's previous change is still being finished, when Nginx is not
  running (`ALC-NGX-0010`), and for a certificate or key file whose real name (after links) has characters it does
  not accept (shown as **Not supported**). When the unfinished change is one Alice no longer follows (for example
  after a deployment whose outcome was not confirmed), a new deployment of that website undoes it once and deploys
  again (`ALC-DEP-0024` with its own email when only the undo succeeded, `ALC-DEP-0023` when it cannot undo it).
- Too many authentication failures on a server count as a refused sign-in (`ALC-SSH-0002`).
- A connection lost while signing in to a server is now "cannot be reached" (`ALC-SSH-0001`, retried), not "sign-in
  refused"; an SSH-key scan is bounded (users, files, keys, warnings, 10 minutes of reading; a cut scan says so) and
  a discovery job stops after 20 minutes.
- SSH keys: keys of accounts deleted from a server are now marked **No longer found** when the server's account list
  is complete (no LDAP or SSSD accounts, not more accounts than Alice lists); every uid-0 account and accounts with an empty shell field are
  scanned; the root last-key guard covers every uid-0 account; the **SSH keys** list marks keys that are no longer
  found.
- Lock mode also refuses certificate uploads, signing requests, deployments and verification settings; deployments
  waiting in the queue are held for an administrator. A held deployment an administrator discards ends
  **cancelled** (`ALC-DEP-0022`) without a failure email.
- A scan never changes the chain of a certificate you uploaded or whose key Alice holds; uploading the key of a
  certificate found on a server stores your chain (the certificate is then listed as uploaded); a certificate found
  only on servers keeps the leaf and its ordered chain, without other certificates of the file.
- Alice creates at most two signing-request keys at once (`ALC-CRT-0016`, try again) and keeps at most 1000 open
  signing requests for the whole installation (`ALC-CRT-0017`).
- `make coverage` enforces floors for `internal/api`, `internal/certs`, `internal/providers/nginx` and its parser;
  several existing floors were raised.

### Known issues
- A website whose `listen` names a host name resolving to another address of the server cannot be verified;
  deployments to it are refused unless an administrator turns the check off.
- Configuration files that users other than root can change make their websites (or the whole server) unmanaged.
- No private-key download, and no retry or undo button on a deployment (deploy again, or deploy the earlier
  certificate).
- Real systemd is not part of the automated tests yet.
- The full list is in `docs/security/reviews/phase-4.md` ("Known limitations").

## Unreleased — Phase 3: Servers and SSH key inventory

### Added
- **Servers**: add a Linux server over SSH, confirm its host-key fingerprint before Alice trusts it, test the
  connection, scan it, remove it. Servers count toward the license; the limit and lock mode are enforced when a
  server is added.
- `alice-helper`, a small static program installed root-owned on each server (`make helper`), and a generated
  setup script with two restricted sudoers profiles (`linux`, `nginx`) that checks the helper's SHA-256 checksum
  before installing it. Alice runs nothing else as root.
- Host-key pinning: a changed host key stops all work on that server, emails administrators once and needs an
  administrator with a recent authenticator code and a reason to accept the new key.
- **SSH keys**: inventory of every `authorized_keys` entry (users, files, options, comments) with filters and
  findings (weak keys, root keys without `from=`, forced commands, duplicates, certificate authorities, hardware
  security keys); servers that use `AuthorizedKeysCommand` are detected and not changed.
- Removing a key from one place (administrators and operators); Alice's own key is always refused, and root's last
  key needs an administrator's confirmation.
- Alice's own Ed25519 SSH key, created at first start and stored encrypted in the database; shown with the setup
  commands on **Servers** and in the wizard's new **Connect your servers** step.
- A durable job queue in PostgreSQL with leases, retries, crash recovery and one job per server at a time; work
  paused by an expired license waits for an administrator after renewal.
- Daily audit chain verification and hourly clean-up of expired sessions and old jobs; emails to administrators for
  a broken audit chain, a job that stopped after its last attempt and a job changed in the database.
- Developer targets: `make helper`, `make fuzz-ssh`, `make test-ssh` (real OpenSSH on Ubuntu 22.04, Debian 12,
  Rocky 9); the e2e stack runs as the separate compose project `alice-e2e` with an SSH test server.
- The re-pin dialog offers **The server still shows the previous fingerprint**: an administrator can end a host-key
  block from the UI when the previous fingerprint is still right (audited `hostkey.change_dismissed`).
- A server that cannot be reached is tested again once per discovery interval and scanned as soon as the test
  succeeds; a successful scan or key removal also brings it back to **Connected** (`target.status_changed` reasons
  `discovery_ok`, `removal_ok`).
- Audit action `job.cancelled_license` for a read-only job the license lock cancelled; `job.dead` carries
  `shutdown=true`, and sends no email, when Alice's own shutdown cut off the last attempt.
- `ALC-SSH-0011`: a versioned build without the helper checksums answers this code on **Prepare a server for Alice**
  instead of a generic error, and logs a warning at startup.

### Changed
- Every state-changing API route belongs to exactly one license lock group; `GET /api/v1/license/status` answers
  `ALC-SYS-0002` until the first license evaluation has finished.
- A changed installation record is audited once per occurrence (`license.installation_tampered`), and restoring it
  is audited too (`license.installation_restored`).
- On a new installation the audit log now starts with `platform_key.created`.
- Builds other than development builds (version `dev`) need the helper checksums: `make build` and the image build
  embed them, and a build without them offers no setup commands.
- Helper protocol 3 (helper 1.2.0): `authkeys-write` takes `--content-sha256` and refuses incomplete content
  (`CONTENT_MISMATCH`), so a dropped connection never leaves a truncated `authorized_keys`. The sudoers line changed
  with it: run the setup commands again with the new `alice-helper` on servers prepared with an earlier build
  (Alice reports them with `ALC-SSH-0005`, helper outdated).
- The setup commands check and install a root-private copy of `./alice-helper`, create `alice-svc` without
  `/etc/skel` files and empty its home on every run; keep the helper in a directory only you can write.
- The helper lists key files as unsupported when another user could redirect them: an absolute `AuthorizedKeysFile`
  directory that is reached through a symlink or not controlled by root (for example a user-owned `/srv/keys/%u`),
  and every file of an account with a directory above its home that is not root's or is writable by others
  (root-owned symlinks such as `/home -> /data/home` work; a `..` in such a link does not). It answers
  `HOME_NOT_WRITABLE` when a user's `.ssh` cannot be created, removes lock files unused for 30 days, and reading or
  writing a key file may take up to 60 seconds.
- **Test connection** always opens a new SSH connection; removing a server closes the connections Alice kept open to
  it.
- Scheduled work runs at most once per discovery interval per server, whatever its outcome; a failed scheduled
  re-test ends without a dead-job email (becoming unreachable sends no email of its own; a scan, or a test a person started, that fails on its last attempt still sends the `job.dead` email); a confirmed server
  left at **Checking…** by a restart or the license lock is tested again by the scheduler.
- A new server that cannot be reached before its fingerprint is confirmed stays "Waiting for fingerprint
  confirmation"; confirm, re-pin and dismissal always start a new connection test.
- A job whose lease cannot be renewed is stopped and handed back before the lease runs out; a key removal applied
  while its server was deleted is still recorded, and a removal retry that finds its server deleted is recorded as
  failed and stops for a person.
- The database checks server addresses, ports and fingerprint formats; local-use NAT64 addresses
  (`64:ff9b:1::/48`) that translate to link-local, multicast or broadcast addresses are refused.
- Web: progress waits through network errors, a stopped task says so, the setup wizard no longer reports success
  after a failed first check, and several Turkish texts were corrected.
- Development: `make image` builds `alice:ci` (never the `alice:dev` tag of the `make up` stack); the e2e stack
  publishes `ALICE_E2E_PORT` (default 9443) so it runs beside the `make up` stack; `make ci` removes it at the end.

### Known issues
- Accounts that exist only in LDAP or SSSD are not inventoried.
- Keys of an account deleted from a server (or switched to a `nologin` shell) stay listed as found and cannot be
  removed through Alice; see `docs/operator-guide.md`.
- Replacing Alice's own SSH key needs the vendor; there is no command for it.
- The full list is in `docs/security/reviews/phase-3.md` ("Known limitations").

## Unreleased — Phase 2: Licensing

### Added
- Signed licenses per installation (Ed25519 over RFC 8785 canonical JSON), limited by managed targets; the
  Installation ID (`ALICE-XXXX-XXXX-XXXX-XXXX`, with a check character) is created at first start and kept by
  restores.
- 30-day evaluation (5 targets) from the installation date; the setup wizard's new license step (upload a license or
  start the evaluation).
- **License** page: Installation ID with Copy, state, "Valid until <date>, N targets", target usage, uploaded
  licenses, history; upload with a server check, a confirmation dialog and step-up.
- License banners on every page (evaluation, warnings 60/30/14/7/1 days, grace, lock, clock problems, damaged
  license data, pending license, target limit) and warning emails to administrators, each sent once (SMTP from
  `ALICE_SMTP_*`, TLS only).
- Lock mode after the 7-day grace period (directly after the evaluation): automatic work that changes servers
  pauses; changes to servers are refused (`ALC-LIC-0001`); sign-in, license upload, backups, audit, exports, user
  administration and tokens keep working. Nothing is deleted.
- Clock protection: a server clock set back never extends a license; a forward jump of more than 48 hours waits
  24 hours before it can start the grace period or the lock.
- The installation record (Installation ID and evaluation start) is protected by a key derived from the master key:
  a changed or deleted record never starts a new evaluation (audited as `license.installation_tampered`).
- `licensectl` (vendor only, never shipped): `keygen`, `issue`, `inspect`, `verify`, `keyset`, `ledger-verify`,
  with an encrypted key file and a signed issuance ledger.
- CLI: `alice license status`, `alice license keys`.
- Coverage floors enforced by `make coverage` (`coverage-floors.json`).
- Guides: `docs/licensing.md`; vendor guide `docs/vendor/licensing-vendor.md` (not shipped).

### Changed
- Finishing setup now needs a license choice (`ALC-SET-0009`).
- New volume `alice-state` at `/opt/alice/state` (back it up with the others).
- The permission `setup.finish` was removed (unused).
- `make ci` runs `make coverage` instead of `make test-integration`.

### Known issues
- Until the vendor's public key is built in, release builds accept no license (evaluation only), and
  `make release-keycheck` fails.
- Nothing in this release changes servers yet, so lock mode only shows its banners; the refusal of changes becomes
  visible with targets in the next release.
- Certificate expiry emails with the "license expired" note arrive with alerts in a later release.
- The full list is in `docs/security/reviews/phase-2.md` ("Known limitations").

## Unreleased — Phase 1: Core

### Added
- Setup wizard: one-time setup code, language, administrator account with mandatory authenticator app and
  10 recovery codes, recovery passphrase (generates the backup key pair).
- Local sign-in with Argon2id passwords (12–128 characters, 100,000-entry leaked-password list), mandatory TOTP,
  recovery codes, progressive delay and 15-minute lockout, step-up confirmation for sensitive changes.
- Sessions (`__Host-alice_session`, 30 minutes idle, 12 hours absolute) with CSRF protection and rate limits.
- Roles Administrator, Operator and Auditor enforced on every API route from one permission table
  (`docs/authz-matrix.md`).
- User management, personal API tokens (read or operate scope, at most 365 days).
- Tamper-evident audit log with viewer, CSV/JSON export and integrity verification (`alice audit verify`).
- Envelope encryption (AES-256-GCM, per-secret key) with a master key file; the application database role cannot
  change or delete audit entries.
- CLI: `alice setup-token --reset`, `alice audit verify`, `alice admin reset-mfa <username>`,
  `alice admin unlock <username>` (ends a sign-in block; `make unlock ACCOUNT=<username>`).
- Guides: `docs/first-run.md`, `docs/admin-guide.md`, `docs/operator-guide.md`.

### Changed
- `/api/v1/version` now requires sign-in.
- Database errors for a wrong password or a missing database stop startup immediately with a clear message.
- Development stack: separate `alice_app` database role; run `make reset` once after upgrading from Phase 0.

### Known issues
- The setup code comes from `alice setup-token --reset` (`make setup-token`); the installer prints it from a later
  release.
- The wizard ends after the recovery passphrase; HTTPS certificate upload, email, license and first target steps
  are added later. (Phase 2 adds the license step.)
- Account blocks and audit-integrity problems are recorded in the audit log but not emailed or sent to syslog, and
  there is no automatic daily integrity check yet.
- People created by an administrator are not forced to change their initial password.
- API tokens with "read and operate" access can do nothing more than read-only tokens until targets exist.
- In the development stack the database owner used for migrations is the PostgreSQL superuser, and its password is
  in the `alice` container (see `docs/operator-guide.md`).
- The full list, with the security review, is in `docs/security/reviews/phase-1.md` ("Known limitations").
