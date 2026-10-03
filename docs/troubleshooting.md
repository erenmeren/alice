# Troubleshooting

Every error returned by the Alice API carries a stable code in the form `ALC-<AREA>-<NNNN>`. Quote the code and the `request_id` when asking for help.

## Cannot sign in

- **"Incorrect username or password." although the password is right.** After 5 wrong attempts Alice makes the
  account wait a few seconds; after 10 it blocks the account for 15 minutes. Wait and try again with care: until a
  complete sign-in, one more wrong attempt starts a new 15-minute block. An administrator can see `auth.lockout`
  in the audit log, and **Set a new password** on **Users** lifts the block at once. If you are the only
  administrator, the server operator runs `alice admin unlock <username>` ([operator-guide.md](operator-guide.md));
  `alice admin reset-mfa` does not end a block.
- **Lost the phone with the authenticator app.** Choose **Use a recovery code** on the sign-in page. Without
  recovery codes, ask an administrator to reset your MFA (**Users**). If you are the only administrator, the
  server operator runs `alice admin reset-mfa <username>` ([operator-guide.md](operator-guide.md)).
- **"Your session ended. Please sign in again."** Sessions end after 30 minutes without activity and always after
  12 hours. Sign in again.
- **The setup wizard says the setup code is wrong or the session expired.** Create a new code with
  `alice setup-token --reset` (development: `make setup-token`). After five wrong codes the wizard waits
  15 minutes (`ALC-SET-0002`). Once an administrator exists the wizard no longer accepts codes: sign in instead.
- **Alice does not start: "the master key file is missing" / "does not match this database".** See
  [operator-guide.md](operator-guide.md#master-key).
- **Alice does not start: "the database server … rejected the user name or password".** The database password in
  the configuration is wrong, or (development) a Phase 0 database volume lacks the new `alice_app` role: run
  `make reset`.

## Servers and SSH keys

- **"Connecting to the server…" ends with "Cannot be reached".** Check the address and port, that the server's SSH
  service runs, and that a firewall lets the Alice server through (`ALC-SSH-0001`, `ALC-SSH-0003`). Then choose
  **Test connection** on the server's page. Alice also tests a server that cannot be reached once per discovery
  interval on its own and scans it as soon as the test succeeds; becoming unreachable and a failed scheduled re-test
  send no email of their own (the server is shown on **Servers** and in the audit log), but a scan or a **Test
  connection** you started that fails on its last attempt sends the usual email about a stopped task. A new server whose fingerprint
  is not confirmed yet is not tested on its own.
- **"Sign-in refused" (`ALC-SSH-0002`).** The server does not accept Alice's key for the user you entered. Run the
  setup commands again (they put the key in `/var/lib/alice-svc/.ssh/authorized_keys`), check that the user
  name is `alice-svc`, then choose **Test connection**. Alice does not try a server with a refused key again on its
  own, so the server never locks the account because of Alice.
- **"The Alice account on this server is not allowed to run the helper" (`ALC-SSH-0004`) or "The alice-helper on
  this server is outdated" (`ALC-SSH-0005`).** Copy the `alice-helper` file of this Alice version next to the
  commands from **Servers → Prepare a server for Alice** and run them again as root; they install the helper and the
  sudoers file.
- **The setup commands stop with "./alice-helper is not the alice-helper of this Alice version".** The file's
  checksum differs from the one built into Alice. Copy `alice-helper-linux-amd64` (x86_64) or
  `alice-helper-linux-arm64` (aarch64) built by `make helper` from the same Alice version, renamed to
  `alice-helper`.
- **Server identity changed (`ALC-TGT-0004`).** See [nginx-host-preparation.md](nginx-host-preparation.md#when-the-server-is-rebuilt).
  Never accept a new fingerprint you have not compared on the server itself. If the server shows its previous
  fingerprint again, choose **Review the new fingerprint** and **The server still shows the previous fingerprint**.
- **A key of a deleted account is still listed as found.** Alice does not learn that an account was deleted (or got a
  `nologin` shell); see [operator-guide.md](operator-guide.md#keys-of-accounts-alice-no-longer-lists).
- **"This server gets its SSH keys from a program" (`ALC-SSH-0008`).** The server uses `AuthorizedKeysCommand`;
  Alice lists keys but does not change them there.
- **A key removal says "The file changed while Alice was working" (`ALC-SSH-0007`).** Someone or something edited
  the file at the same moment; Alice changed nothing. Try again.
- **A key removal says "Alice could not read the SSH server settings" (`ALC-KEY-0004`).** Run `sshd -T` as root on
  the server, fix what it reports, choose **Scan for SSH keys**, then try again.
- **"Alice needs this key to connect to this server and will not remove it." (`ALC-KEY-0001`).** This is Alice's
  own key; it is protected on purpose.

## License messages

- **"The server clock changed unexpectedly …"** The server's clock is behind the latest time Alice has seen. Alice
  keeps using the later time (and keeps counting while the clock is behind), so nothing is extended or locked
  because of it. Correct the server time (NTP). The warning is recorded in the audit log once a day
  (`clock.rollback_detected`).
- **"The server clock jumped forward by N days"** Alice keeps the previous time for 24 hours. If the new time is
  wrong, correct it (the warning then ends); otherwise wait, or ask the vendor for a correction license, which
  accepts the new time at once.
- **"License data was changed outside Alice"** A stored license file no longer matches its signature (the database
  was edited or damaged). Alice ignores it. Upload the license file from the vendor again.
- **Everyone sees "The evaluation period has ended" or "License expired"** An administrator uploads a license on
  the **License** page; everything works again at once.
- **"The evaluation period has ended" right after a database change, and the Audit log lists "Installation record
  changed outside Alice" (`license.installation_tampered`).** The Installation ID or the evaluation start in the
  database no longer matches its protection (problem `seal_mismatch` or `seal_missing`), or the record was deleted
  (`installation_missing`). Alice does not trust a changed record and ignores every license until the original
  record is restored, for example from a backup. After a deleted record, Alice created a new Installation ID: send
  it to your vendor for a license.
- **Alice logs "this build has no build time".** The image was built without `ALICE_BUILD_TIME` (for example with a
  plain `docker compose build`). Rebuild with `make up`; see `docs/dev/getting-started.md`.
- **Every upload says "This license was issued with a key this version of Alice does not know."** If this happens
  with every file from your vendor, the build has no vendor key (`alice license keys` says so): install the
  vendor's release build.
- **No warning emails arrive.** Check `ALICE_SMTP_*` ([operator-guide.md](operator-guide.md#email)) and that the
  administrators have an email address on **Users**. The container log shows a reason code for each failed attempt.
- **Alice logs "this build embeds no license verification key".** A development or pre-release build: only the
  evaluation works. See `alice license keys`.

## ALC-SYS-0001: Not found

**Meaning.** The requested API path does not exist (HTTP 404).

**Likely cause.** A typo in the URL, an outdated client calling a removed endpoint, or a wrong HTTP method on an API route.

**What to do.** Check the path against the API documentation and make sure the client matches the server version (`GET /api/v1/version`).

## ALC-SYS-0002: Alice is temporarily unavailable

**Meaning.** A dependency is not ready, so Alice cannot serve the request (HTTP 503, retryable). `/healthz` returns this code.

**Likely cause.** The database is unreachable (for example still starting after a host reboot) or its migrations have not been applied yet.

**What to do.** Wait a minute and retry. If it persists, check that the database container is running and healthy, then read the Alice logs (`docker compose logs alice`) for the `database_unreachable` or `migrations_pending` reason.

## ALC-SYS-0003: Unexpected error

**Meaning.** Alice hit an unexpected internal problem while handling the request (HTTP 500).

**Likely cause.** A bug or an unforeseen condition. Details are deliberately not shown in the response.

**What to do.** Retry once. If it repeats, look up the `request_id` from the response in the Alice logs and report it together with the steps that led to the error.

## ALC-SYS-0004: Request could not be read

**Meaning.** The request body is not valid JSON, contains fields the endpoint does not accept, or has data after the JSON value (HTTP 400).

**Likely cause.** An outdated browser tab after an upgrade, or an API client sending extra or misspelled fields.

**What to do.** Reload the page. API users: compare the request with the schemas in `api/openapi.yaml`; unknown fields are always rejected.

## ALC-SYS-0005: Too many requests

**Meaning.** A rate limit was reached (HTTP 429, retryable). The `Retry-After` header says how many seconds to wait.

**Likely cause.** More than 300 requests per minute for one session or token, more than 60 per minute from one address without signing in, more than 10 sign-in attempts or 5 verification codes per minute from one address.

**What to do.** Wait for the time in `Retry-After`. If many people share one address through a proxy, ask the administrator to set `ALICE_TRUSTED_PROXIES` so Alice sees real client addresses.

## ALC-SYS-0006: Some fields need attention

**Meaning.** One or more fields failed validation (HTTP 422). `details` lists each field with a `validation.*` code.

**Likely cause.** A required field is empty, a value is too long, or a value does not have the expected format (for example a username with spaces).

**What to do.** Correct the fields named in `details` and send the request again.

## ALC-SYS-0007: Request too large

**Meaning.** The request body is larger than 1 MiB (HTTP 413).

**Likely cause.** A very large paste or file was sent to an endpoint that accepts small JSON documents.

**What to do.** Send less data. Certificate and license uploads (later versions) have their own, larger limit.

## ALC-AUTH-0001: Session ended

**Meaning.** The request has no valid session or API token (HTTP 401).

**Likely cause.** The user signed out, was idle for 30 minutes, reached the 12-hour session limit, was disabled, or an administrator ended their sessions; or an API token expired or was revoked.

**What to do.** Sign in again. API users: create a new token.

## ALC-AUTH-0002: Permission denied

**Meaning.** The signed-in user or token is not allowed to perform this action (HTTP 403). The attempt is recorded in the audit log as `authz.denied`.

**Likely cause.** The user's role (Administrator, Operator, Auditor) does not include the action, or an API token is used for an action that needs a browser session.

**What to do.** Ask an administrator for the right role. See `docs/authz-matrix.md` for who may do what.

## ALC-AUTH-0003: Confirmation required

**Meaning.** A sensitive action needs a fresh verification code (HTTP 403). The confirmation lasts 5 minutes.

**Likely cause.** More than 5 minutes passed since the last sign-in or confirmation, and the action changes users, tokens, recovery codes or backup settings.

**What to do.** Enter the 6-digit code from the authenticator app when Alice asks (`POST /api/v1/auth/stepup`), then repeat the action.

## ALC-AUTH-0004: Request blocked (CSRF)

**Meaning.** A state-changing request did not carry the page's security token, or came from another site (HTTP 403).

**Likely cause.** An old browser tab, a browser extension changing requests, or a malicious page trying to act on the user's behalf.

**What to do.** Reload the page. API clients should use an API token (`Authorization: Bearer alice_...`), which needs no CSRF token.

## ALC-AUTH-0005: Incorrect username or password

**Meaning.** Sign-in failed (HTTP 401). The message is the same whether the user exists, the password is wrong, or the account is temporarily blocked, so attackers learn nothing.

**Likely cause.** A typo, a wrong password, a disabled account, or too many failed attempts: after 5 failures Alice waits 1, 2, 4, ... seconds between attempts, after 10 it blocks the account for 15 minutes.

**What to do.** Wait 15 minutes and try again carefully. An administrator can reset the password in Users. Failed attempts are listed in the audit log (`auth.login`, `auth.lockout`).

## ALC-AUTH-0006: Wrong verification code

**Meaning.** The 6-digit code or the recovery code was not accepted (HTTP 401).

**Likely cause.** A typo, a code that was already used (each code works once), or a phone or server clock that is more than 30 seconds off.

**What to do.** Wait for the next code and try again, or use a recovery code. Check that the server and phone clocks are correct (NTP).

## ALC-AUTH-0007: Authenticator already set up

**Meaning.** The account already has an authenticator app enrolled (HTTP 409).

**Likely cause.** The enrollment page was opened twice.

**What to do.** Enter a code from the app. If the device is lost, an administrator can reset it (**Users**, **Manage**, **Reset two-factor sign-in**), or the host administrator can run `alice admin reset-mfa <username>`.

## ALC-AUTH-0008: Password too short

**Meaning.** The new password has fewer than 12 characters (HTTP 422, `params.min`).

**Likely cause.** A short password was chosen.

**What to do.** Use at least 12 characters; a short sentence works well.

## ALC-AUTH-0009: Password too long

**Meaning.** The new password has more than 128 characters (HTTP 422, `params.max`).

**Likely cause.** A very long value was pasted.

**What to do.** Use at most 128 characters.

## ALC-AUTH-0010: Password too common

**Meaning.** The password is on Alice's built-in list of 100,000 commonly used passwords (HTTP 422). The check is offline.

**Likely cause.** A well-known password such as `qwerty123456` was chosen.

**What to do.** Choose a different password that is not used anywhere else.

## ALC-AUTH-0011: Current password incorrect

**Meaning.** When changing a password, the current password did not match (HTTP 422).

**Likely cause.** A typo in the current password field.

**What to do.** Enter the current password again. If it is forgotten, ask an administrator to reset it.

## ALC-AUTH-0012: Account busy, try again

**Meaning.** Alice could not check the password or verification code in time because another check for the same account was still running (HTTP 503, retryable, `Retry-After: 1`). Nothing was verified and the attempt was not counted as a failure.

**Likely cause.** Many sign-in or verification attempts for one account at the same moment, for example a script retrying in parallel or someone guessing the password while the owner signs in.

**What to do.** Wait a second and try again. If it happens often, look in the audit log for many `auth.login` failures on that account and find where they come from.

## ALC-USR-0001: Username already in use

**Meaning.** Another user already has this username (HTTP 409). Usernames ignore case, so `Admin` and `admin` are the same.

**Likely cause.** The person already has an account, or the name is taken.

**What to do.** Choose a different username, or edit the existing user.

## ALC-USR-0002: Last administrator

**Meaning.** The change would leave no enabled local administrator (HTTP 409). Alice always keeps one as a break-glass account.

**Likely cause.** Disabling or demoting the only remaining administrator, including yourself.

**What to do.** Give the Administrator role to another person first, then repeat the change.

## ALC-TOK-0001: Token access not allowed

**Meaning.** The requested token access exceeds what the owner's role allows (HTTP 422).

**Likely cause.** An Auditor asked for a token with "operate" access.

**What to do.** Create a read-only token.

## ALC-SET-0001: Wrong setup code

**Meaning.** The one-time setup code entered in the setup wizard is not correct (HTTP 401).

**Likely cause.** A typo, or the code was replaced by running `setup-token --reset` again.

**What to do.** Type the code exactly as printed (dashes and case do not matter). To get a new code, run `alice setup-token --reset` on the server (in development: `make setup-token`).

## ALC-SET-0002: Setup temporarily blocked

**Meaning.** Five wrong setup codes were entered from this address; setup is blocked for 15 minutes from it (HTTP 429, `Retry-After`).

**Likely cause.** Repeated typos, or someone guessing the code.

**What to do.** Wait 15 minutes. If you did not make these attempts, check who can reach the server.

## ALC-SET-0003: Setup session ended

**Meaning.** The wizard session is missing or expired (HTTP 401).

**Likely cause.** The wizard was idle for 60 minutes, cookies were cleared, or setup was completed in another browser.

**What to do.** Enter the setup code again. If an administrator already exists, sign in instead.

## ALC-SET-0004: Administrator details missing

**Meaning.** The verification-code step of the wizard was sent before the administrator form (HTTP 409).

**Likely cause.** The page was reloaded between the two steps after the wizard session was renewed.

**What to do.** Reload the page and enter the setup code again; the wizard then asks for the administrator
details once more. (The wizard has no "Back" button yet.)

## ALC-SET-0005: Recovery passphrase too short

**Meaning.** The recovery passphrase has fewer than 16 characters (HTTP 422, `params.min`).

**Likely cause.** A short passphrase was chosen.

**What to do.** Choose at least 16 characters, for example several unrelated words.

## ALC-SET-0006: Passphrases do not match

**Meaning.** The passphrase and its repetition differ (HTTP 422).

**Likely cause.** A typo in one of the two fields.

**What to do.** Type the same passphrase in both fields.

## ALC-SET-0007: Recovery passphrase already set

**Meaning.** A recovery passphrase was already chosen for this installation (HTTP 409).

**Likely cause.** The step was submitted twice.

**What to do.** Continue with the next step. The passphrase cannot be changed in this version.

## ALC-SET-0008: Setup not finished

**Meaning.** Setup cannot be completed yet (HTTP 409).

**Likely cause.** The recovery passphrase has not been chosen.

**What to do.** Choose the recovery passphrase in the wizard, then finish setup.

## ALC-SET-0009: License step not done

**Meaning.** Setup cannot be finished because the license step is open (HTTP 409).

**Likely cause.** Neither a license file was uploaded nor **Start 30-day evaluation** was chosen.

**What to do.** On the wizard's license step, upload the license file from your vendor or start the evaluation, then
choose **Go to the dashboard**. The evaluation has been running since Alice was first started either way.

## ALC-LIC-0001: Not available while the license is expired

**Meaning.** The action changes a managed server, key or certificate, and the license or the 30-day evaluation has
ended (HTTP 403). Alice is in lock mode: automatic tasks are paused and such changes are refused. Signing in,
uploading a license, backups, the audit log, exports and user administration keep working. Nothing was changed.

**Likely cause.** The license expired more than 7 days ago (168 hours), or the evaluation ended.

**What to do.** Ask your vendor for a renewed license (send the Installation ID shown on the **License** page) and
upload it there. Everything works again immediately; work that was paused waits for an administrator's confirmation.

## ALC-LIC-0002: Not a valid license file

**Meaning.** The uploaded file is not a license Alice can accept (HTTP 422): it is not a license file, it is
damaged, or a value in it was changed after the vendor signed it. Nothing was changed; the installed license stays.

**Likely cause.** The file was opened and saved by an editor that changed it, only part of it was copied, or the
wrong attachment was chosen.

**What to do.** Save the attachment from the vendor's email again, without opening it, and upload that file.

## ALC-LIC-0003: License for another installation

**Meaning.** The license names a different Installation ID (HTTP 422). The message shows the last six characters of
both IDs.

**Likely cause.** The license was made for another Alice server, or the ID was mistyped when it was requested.

**What to do.** Copy the Installation ID from the **License** page, send it to your vendor and upload the new file.
Restoring a backup keeps the Installation ID, so a license keeps working after moving to new hardware.

## ALC-LIC-0004: Unknown signing key

**Meaning.** The license was signed with a key this Alice version does not contain (HTTP 422).

**Likely cause.** The license is for a newer Alice release, or it was not issued by your vendor. A development build
without the vendor's key refuses every license.

**What to do.** Contact your vendor's support, quoting the request ID.

## ALC-LIC-0005: Signing key no longer trusted

**Meaning.** The license was signed with a vendor key that this Alice version marks as revoked (HTTP 422).

**Likely cause.** The vendor replaced its signing key.

**What to do.** Ask your vendor for a new license file; it is free of charge.

## ALC-LIC-0006: Newer license format

**Meaning.** The license uses a newer file format than this Alice version reads (HTTP 422). The current license
stays in use.

**Likely cause.** The vendor issued the license for a newer Alice release.

**What to do.** Update Alice (see `docs/upgrade.md` when available), then upload the file again.

## ALC-LIC-0007: A newer license is already installed

**Meaning.** The file is older than the license in use and does not last longer (HTTP 409). Nothing was changed.

**Likely cause.** An old license file was uploaded by mistake.

**What to do.** Nothing, if the current license is right. If your vendor sent the older file on purpose, ask them
for a correction license (it names the license it replaces and is always accepted).

## ALC-LIC-0008: License target limit reached

**Meaning.** Adding a target would exceed the number of targets the license allows (HTTP 409, `params.used`,
`params.max`). Existing targets keep working; nothing is locked.

**Likely cause.** All licensed targets are in use, or a renewal lowered the limit below the targets in use.

**What to do.** Remove a target that is no longer needed, or ask your vendor to increase the license.

## ALC-SYS-0008: Changed while you were editing

**Meaning.** The item was changed by someone else after you opened it (HTTP 412). Your change was not saved.

**Likely cause.** Two people edited the same server at the same time, or the page was open for a long time.

**What to do.** Reload the page, check the current values and make your change again.

## ALC-TGT-0001: Server already exists

**Meaning.** Another server already has this name, or the same address and SSH port (HTTP 409). Names are compared
without regard to upper and lower case.

**Likely cause.** The server was added before, perhaps under another name.

**What to do.** Choose another name, or open the existing server on the **Servers** page.

## ALC-TGT-0002: Fingerprint not confirmed yet

**Meaning.** Alice does nothing on a server until an administrator confirms its SSH host-key fingerprint (HTTP 409).

**Likely cause.** The server was just added and nobody has clicked **Yes, this is my server** yet.

**What to do.** Open the server, run the shown `ssh-keygen -lf …` command on the server, compare the fingerprints and
confirm.

## ALC-TGT-0003: Not the fingerprint the server presented

**Meaning.** The fingerprint you confirmed is not the one the server presented (HTTP 409). Nothing was pinned.

**Likely cause.** The page was open while the server presented another key, or the fingerprint was edited.

**What to do.** Reload the page and compare again. If the server keeps presenting different keys, stop and ask your
security team: something may be intercepting the connection.

## ALC-TGT-0004: Server identity changed

**Meaning.** The server presented another host key than the confirmed one. Alice stopped every operation on it
(HTTP 409) and emailed the administrators.

**Likely cause.** The server was reinstalled or its SSH host keys were regenerated, or someone is impersonating it.

**What to do.** Ask your security team to confirm the change on the server itself. Then an administrator opens the
server, chooses **Review the new fingerprint**, gives a reason and chooses **Accept new fingerprint** (the previous
fingerprint stays in the history) or, when the previous fingerprint is still the right one, **The server still shows
the previous fingerprint** (Alice tests the connection again and blocks the server again if it presents another
key). Alice asks for an authenticator code if the last one is more than five minutes old.

## ALC-TGT-0005: Fingerprint cannot be accepted now

**Meaning.** The confirmation does not fit the server's state (HTTP 409): a first fingerprint can be confirmed only
while the server waits for it, a new one only after the identity changed.

**Likely cause.** Another administrator already confirmed it, or the page is outdated.

**What to do.** Reload the server's page.

## ALC-TGT-0006: Server disabled

**Meaning.** The server is disabled, so Alice runs no task on it (shown on the task, HTTP 409 when returned directly).

**Likely cause.** The server was disabled while the task waited in the queue.

**What to do.** Open the server to see why it is disabled, then click **Test connection**.

## ALC-SSH-0001: Server cannot be reached

**Meaning.** Alice could not open an SSH connection (HTTP 502 when returned directly; usually shown on the server and its
tasks).

**Likely cause.** The server is off, the address or port is wrong, or a firewall blocks the Alice host.

**What to do.** Check the server and the network path to its SSH port, then click **Test connection**.

## ALC-SSH-0002: Server refused Alice's key

**Meaning.** The server rejected the sign-in of the `alice-svc` account with Alice's key. The server is marked "Sign-in
refused" and administrators get an email. Alice never tries a refused key again on its own (no scheduled scan or
test), so the server never locks the account because of Alice; only **Test connection** tries again.

**Likely cause.** The preparation commands were not run, the key line was removed from
`/var/lib/alice-svc/.ssh/authorized_keys`, or the account is locked.

**What to do.** Run the preparation commands from the **Servers** page again as root on the server, then test the
connection.

## ALC-SSH-0003: Server answered too slowly

**Meaning.** A connection or a command took longer than its time limit (10 s to connect, 30–60 s per command).

**Likely cause.** A very slow network or an overloaded server.

**What to do.** Try again later; check the server's load.

## ALC-SSH-0004: Helper not allowed or not installed

**Meaning.** `sudo -n /usr/local/libexec/alice-helper …` failed on the server.

**Likely cause.** `alice-helper` is missing, or `/etc/sudoers.d/alice` is missing or was changed.

**What to do.** Copy `alice-helper` from the Alice bundle to the server and run the preparation commands again as root.

## ALC-SSH-0005: Helper outdated

**Meaning.** The helper on the server speaks an older protocol than this Alice version needs (this release needs
protocol 3, `alice-helper` 1.2.0).

**Likely cause.** Alice was updated but the helper on the server was not.

**What to do.** Copy the helper from the current Alice bundle and run the preparation commands again.

## ALC-SSH-0006: Helper refused the request

**Meaning.** The helper checked the request and refused it (`params.helper_code` names the rule, for example
`PATH_NOT_ALLOWED`).

**Likely cause.** A key file is outside the places the helper may read or change (for example a symbolic link that
leaves the user's home), or the file is not a regular file.

`CONTENT_MISMATCH` means the new file content reached the server incomplete (the connection dropped while Alice
sent it); the helper wrote nothing. `HOME_NOT_WRITABLE` means the user has no `.ssh` directory yet and may not create
one in their home directory (for example a home owned by root); the helper wrote nothing. `params.reason`
`too_many_users` means the server has more accounts than the helper lists (200) and the requested user is not among
them, so Alice cannot check that a new key file belongs to that user.

**What to do.** Scan the server again. If the refusal stays, check the named file on the server; contact support with
the request ID if needed. After `CONTENT_MISMATCH`, check the network path to the server and run the action again.

## ALC-SSH-0007: File changed during the operation

**Meaning.** The `authorized_keys` file changed between Alice's read and write, three times in a row (HTTP 409). Alice
wrote nothing.

**Likely cause.** Another tool or person edited the file at the same time.

**What to do.** Try again.

## ALC-SSH-0008: Keys managed elsewhere

**Meaning.** The server's SSH daemon uses `AuthorizedKeysCommand`, so Alice lists the file keys but does not change keys
there (HTTP 409).

**Likely cause.** Keys come from a directory service or another program.

**What to do.** Manage those keys in the system that provides them.

## ALC-SSH-0009: Answer too large

**Meaning.** The server sent more than Alice accepts (8 MiB per command, 1 MiB per key file).

**Likely cause.** An unusually large key file or SSH configuration.

**What to do.** Inspect the server's `authorized_keys` files and `sshd -T` output.

## ALC-SSH-0010: Unexpected answer from the server

**Meaning.** The helper's answer could not be read.

**Likely cause.** The file at `/usr/local/libexec/alice-helper` is not Alice's helper, or it is damaged.

**What to do.** Install the helper again from the Alice bundle and compare its checksum with `alice-helper.sha256`.

## ALC-SSH-0011: This build cannot show the setup commands

**Meaning.** Alice cannot show **Prepare a server for Alice** (`GET /api/v1/ssh-keys/platform-key`, HTTP 500). Its
setup commands check `alice-helper` against the checksums built into Alice before they install it as root, and this
build has none. Alice also logs "this build has no alice-helper checksums" at every start.

**Likely cause.** Alice was built by hand with `go build` and a version number, not with `make build` or the image
build, which embed the checksums. (A development build, version `dev`, shows the commands with a warning that they
cannot check the helper.)

**What to do.** Install an official Alice release, or rebuild with `make build` or the image build. Servers that are
already prepared keep working.

## ALC-KEY-0001: Alice's own key is protected

**Meaning.** Alice refuses to remove its own connection key (HTTP 409), in any file and whatever its comment says. The
refusal is recorded in the audit log.

**Likely cause.** The key that Alice uses to sign in was chosen for removal.

**What to do.** Keep the key. To stop managing a server, remove the server from Alice instead.

## ALC-KEY-0002: Last key of root

**Meaning.** Removing this key would leave the root account without any key (HTTP 409).

**Likely cause.** The key is the only line in root's `authorized_keys`.

**What to do.** Add another key for root first, or let an administrator confirm the removal on purpose.

## ALC-KEY-0003: Key cannot be changed in this file

**Meaning.** Alice cannot remove (or add) this key in this file (HTTP 409 when returned directly; on a task,
`params.reason` names the cause: `cert_authority` or `file_too_large`).

**Likely cause.** The key location no longer exists or was already removed, the line is a `cert-authority` line that
Alice only lists, or the `authorized_keys` file is larger than 1 MiB.

**What to do.** Click **Scan for SSH keys** on the server and try again; check the size of the file on the server.

## ALC-KEY-0004: SSH server settings could not be read

**Meaning.** The last scan could not read the SSH server's effective settings (`sshd -T`) for the server or for the
key's user, so Alice refuses to change keys there (HTTP 409). The refusal is recorded in the audit log.

**Likely cause.** `sshd -T` fails on the server, for example because of a broken `sshd_config` or a `Match` block it
cannot evaluate for that user.

**What to do.** Run `sshd -T` as root on the server and fix the reported problem, scan the server again, then retry.

## ALC-KEY-0005: Change could not be verified

**Meaning.** Alice wrote the `authorized_keys` file but reading it back did not show the expected result. The task
stops for a person ("needs attention"); Alice did not record the key as removed. The task's result names the backup of
the previous file.

**Likely cause.** Another program changed the file right after Alice's write, or the file system did not keep the write.

**What to do.** Compare the file on the server with the backup named on the task, restore it if needed, then scan the
server again.

## ALC-JOB-0001: Task is not waiting

**Meaning.** Only tasks paused by an expired license ("Waiting for an administrator") can be run, and only those and
tasks that have not started yet can be discarded (HTTP 409).

**Likely cause.** The task already ran or was discarded by someone else.

**What to do.** Reload the page.

## ALC-JOB-0002: Task interrupted

**Meaning.** A task's lease ran out because Alice stopped while running it; Alice queued it again (shown on the task).

**Likely cause.** A restart, an update or a lost database connection.

**What to do.** Nothing; if it happens often, find out why Alice restarts.

## ALC-JOB-0003: Task changed outside Alice

**Meaning.** A stored task failed its integrity check (HMAC), so Alice did not run it and recorded `job.tampered`.

**Likely cause.** Someone wrote to the `jobs` table directly.

**What to do.** Review database access; start the work again from its page.

## ALC-JOB-0004: Unknown task type

**Meaning.** A stored task has a type this Alice version does not know; it was not run.

**Likely cause.** Two Alice versions use the same database.

**What to do.** Run only one Alice version per database.

## ALC-JOB-0005: Same task already queued with other options

**Meaning.** A task of this kind is already queued for the same item with different options, so the new request was not
queued (HTTP 409).

**Likely cause.** Two people asked for the same work at almost the same time, for example removing the same key with
and without the confirmation for root's last key.

**What to do.** Wait until the queued task has finished, then try again.
