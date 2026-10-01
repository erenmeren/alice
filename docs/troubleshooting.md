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
  plain `docker compose build`). Rebuild with `make up` or `make image`; see `docs/dev/getting-started.md`.
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
