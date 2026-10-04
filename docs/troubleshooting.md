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
- **A key of a deleted account is still listed as found.** Alice marks the keys of a deleted account **No longer
  found** only when the server's account list is complete (no LDAP or SSSD accounts, not more accounts than Alice
  lists), and keeps the keys of an account that got a `nologin` shell or lost its home as last seen; see
  [operator-guide.md](operator-guide.md#keys-of-accounts-alice-no-longer-lists).
- **"This server gets its SSH keys from a program" (`ALC-SSH-0008`).** The server uses `AuthorizedKeysCommand`;
  Alice lists keys but does not change them there.
- **A key removal says "The file changed while Alice was working" (`ALC-SSH-0007`).** Someone or something edited
  the file at the same moment; Alice changed nothing. Try again.
- **A key removal says "Alice could not read the SSH server settings" (`ALC-KEY-0004`).** Run `sshd -T` as root on
  the server, fix what it reports, choose **Scan for SSH keys**, then try again.
- **"Alice needs this key to connect to this server and will not remove it." (`ALC-KEY-0001`).** This is Alice's
  own key; it is protected on purpose.

## Certificates

- **An upload is refused.** The message says why and nothing is stored; the codes are listed below
  (`ALC-CRT-0001`…`ALC-CRT-0015`). Common cases: the key belongs to another certificate (`ALC-CRT-0002`; use the key
  created with this certificate), the key has a password (`ALC-CRT-0004`; remove it with
  `openssl pkey -in protected.key -out plain.key`, or upload a PFX file with its password), the certificate has
  expired (`ALC-CRT-0003`), or a weak key or SHA-1 signature (`ALC-CRT-0006`).
- **"Alice already has this certificate with its key" (`ALC-CRT-0008`) right after an upload that seemed to fail.**
  The first upload reached Alice but its answer was lost. The certificate is in the list; deploy it from there.
- **"Alice is busy reading other PFX files" (`ALC-CRT-0015`).** Alice reads at most two PFX files at a time. Wait a
  moment and upload again. If it keeps happening, someone may be uploading PFX files that take very long to open;
  check the audit log for `certificate.upload_rejected` and `certificate.uploaded`, and restart Alice if needed.
- **"The chain is incomplete" after an upload.** Add the intermediate certificates your certificate authority sent
  (in any order) and upload again, or let an administrator deploy it with a confirmation
  ([admin-guide.md](admin-guide.md#incomplete-chains)).
- **The certificate list says "Not in Alice" in the Private key column.** Alice found this certificate on a server and
  never reads private keys from servers. Upload the certificate with its key to deploy it elsewhere.
- **A signing request's certificate is refused (`ALC-CRT-0013`).** It was not issued for this request's key: paste the
  certificate your certificate authority returned for exactly this request.

## Deployments

- **"Deploying is unavailable for now." on a server's websites.** The reason is shown under it: the server is not
  connected (see its status), the Nginx permissions are not installed (`ALC-NGX-0004`: run the setup commands with
  **Server type** **Nginx server** again), Nginx was not found (`ALC-NGX-0001`), Nginx's configuration has an error
  (`ALC-NGX-0002`: run `nginx -t` on the server), or the last scan failed. Fix it, then choose **Discover**.
- **A website is "Not supported".** The row says why. The cases and what to change are in
  [nginx-host-preparation.md](nginx-host-preparation.md#configurations-alice-cannot-manage). After a change on the
  server, choose **Discover**.
- **"Alice cannot trust Nginx's output for this configuration" or "Alice cannot read this configuration safely".**
  Alice refuses the whole server and names the reason and, where it can, the file with the problem. Usual causes: a
  configuration file or folder that users other than root can change (`chmod go-w` on it, owner root), an `include`
  written with `..` (write the path without `..`), a configuration file name with a space, or a comment in a real
  configuration file that starts with `# configuration file`. Then choose **Discover**.
- **"A configuration file of this website can be changed by users other than root."** The website is not supported
  until the file and its folders belong to root and are not writable by group or others. This is on purpose: whoever
  can edit that file could otherwise make Alice write a key to a file of their choosing.
- **The check before the deployment fails with "Alice could not reach the website on port N" (`ALC-DEP-0005`).**
  Nothing was changed. Check that the website answers on that port from the Alice server or, failing that, on the
  server itself (`curl -kv https://127.0.0.1:<port>/`). If the website's `listen` names a host name (for example
  `listen www.example.com:443 ssl;`) that resolves to an address other than 127.0.0.1, Alice cannot check it from
  either side, although the message suggests a firewall: change the `listen` to an IP address or to `listen 443 ssl;`,
  or ask an administrator to turn off the check for that website (**Verification settings**, not recommended).
- **The check before the deployment fails with "Alice could not confirm which certificate the website serves"
  (`ALC-DEP-0004`).** Nothing was changed. The website served a certificate Alice did not expect: a load balancer or
  proxy in front of it (an administrator can set the port and name to check in **Verification settings**), the
  certificate changed since the last scan (choose **Discover**), or another `server` block listens on the server's
  own address and port and answers for this name (Nginx prefers a `listen` with an explicit address; give both blocks
  the same kind of `listen`).
- **"The website serves the expected certificate with a different chain (port N)." (`ALC-DEP-0012`).** The number of certificates
  the website sends differs from the uploaded chain. Check that the website's `ssl_certificate` file is the one Alice
  replaced and that no proxy changes the chain.
- **A deployment shows "Confirming the outcome" or "Needs attention".** Alice did not get a clear answer from the
  server and is finding out how the change ended (see
  [operator-guide.md](operator-guide.md#interrupted-deployments)). The server is usually unreachable: check its
  status and its network. The deployment then shows `ALC-DEP-0010` while the latest recovery attempt shows the
  connection error (`ALC-SSH-0001` or `ALC-SSH-0003`); the same lost connection can appear under either code.
  Nothing needs to be done once the server is back.
- **A deployment ended "Outcome not confirmed".** Alice cannot vouch for what the website serves now. Check it:
  `openssl s_client -connect <server>:443 -servername <website> </dev/null | openssl x509 -noout -fingerprint -sha256`
  shows the served certificate's fingerprint; compare it with **Previous certificate** and **New certificate** on the
  deployment's page. On the server, compare the files with the backup in
  `/var/lib/alice-helper/backups/<deployment ID>` (`sha256sum`), restore by hand if needed
  ([nginx-host-preparation.md](nginx-host-preparation.md#restoring-a-previous-certificate-by-hand)), run `nginx -t` and
  `systemctl reload nginx`, then choose **Discover**. The error code tells which case it is (`ALC-DEP-0008`, `0014`,
  `0017`, `0018`, `0019`, `0020`).

  Do **not** restore the backup after `ALC-DEP-0014` (a later deployment replaced the files: restoring would put
  back a key that the later deployment replaced) or after `ALC-DEP-0020` (another program, for example certbot,
  changed the certificate or key file while Alice was deploying or putting the previous files back: Alice put back
  at most the files it had written itself and left the other program's file, so restoring would overwrite that
  file). After `ALC-DEP-0020` the certificate and key on the server may not belong together: run `nginx -t` on the
  server at once; if it fails, let the other program write a matching pair again (for certbot, renew the
  certificate) or deploy the intended certificate from Alice. In both cases find out which certificate is meant to
  be there and deploy it, or leave the files to the other program. Restore by hand only when the files on the server
  still hold what this deployment wrote (`sha256sum` of the certificate file equals `new_cert_sha256` in the
  folder's `journal.json`) and the website is broken.
- **"The previous files are back, but the website was not confirmed." (`ALC-DEP-0019`) although the website looks right.** This
  happens when another `server` block answers on the server's own address and port: Alice's check reaches that
  block instead. Check the website in a browser and see the previous point.
- **"Alice is still finishing an earlier deployment on this server" (`ALC-DEP-0002`).** Wait until that deployment
  shows a result in **Deployment history**; at most about a day when the server stays unreachable.
- **"The certificate file changed since Alice last looked" (`ALC-NGX-0006`).** Another tool (for example certbot)
  replaced the file. Decide which tool manages this website; choose **Discover** before deploying again.
- **"The server does not have enough free disk space." (`ALC-NGX-0005`).** The server needs room for the new files, their backups and 10 MiB
  more. The same answer comes when the helper already keeps 1000 deployment backups: old ones are removed
  automatically after 7 days.
- **"Another certificate change is running on this server" (`ALC-NGX-0008`).** The helper changes one website at a
  time on a server. Wait a minute and try again.
- **"The certificate file contains a block that is not a certificate. Alice ignored it."** A certificate file holds a
  block that Alice cannot read as a certificate. The note does not name the file: check the files of the server's
  websites with `openssl crl2pkcs7 -nocrl -certfile <file> | openssl pkcs7 -print_certs -noout`. If it was the first
  block of a file, Alice shows the next certificate of that file.
- **"These websites may be out of date".** The last scan could not read the websites (the reason is shown); the list
  is the one Alice read at the time shown. Fix the reason and choose **Discover**.
- **A website shows "The certificate changed outside Alice."** Its file holds a certificate Alice did not deploy (for
  example renewed by certbot, or restored by hand). Expected after a manual change; otherwise find out which program
  changed it.
- **A website's warning says Alice could not order the certificates of its file** (warning code `chain_unresolved`).
  The certificate file holds many certificates with the same name that could each have issued the others; Alice
  stops after 100 signature checks per file, keeps only the website's own certificate and counts its chain as
  incomplete. The website still works as before. Put only the certificate and its real chain in the file (for
  example certbot's `fullchain.pem`) and choose **Discover**.
- **The website list or the certificate files are incomplete on a very large server** ("This server has more
  websites than Alice lists", "This server uses more certificate files than Alice lists", or `ALC-SSH-0009`). Alice
  reads at most 1000 certificate files and 16 MiB of website summary per server; such servers are not fully managed
  in this release.

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

## ALC-LIC-0009: The license could not be checked

**Meaning.** Alice checks its license at start, after every upload and every hour, in every Alice process; a failed
check is tried again after 1, 2, 4 and 8 minutes, then every 10 minutes. No check has succeeded for more than 3 hours (`license.unverified`, HTTP 503, retryable), so the action, which changes a
managed server, key or certificate, was refused. Nothing was changed. Everyone sees a red banner with the time of
the last successful check. Signing in, uploading a license, the audit log, exports, user administration and the
recovery and rollback of deployments keep working. Queued jobs that change servers are not cancelled and need no
confirmation: they wait and start by themselves after the next successful check if the license is still valid.

**Likely cause.** The database was unreachable or overloaded for hours, or another database session keeps the
`license` row locked (a check waits at most 30 seconds for it and gives up after 2 minutes). Alice logs "the
license could not be checked for more than 3h0m0s" once, and "scheduled task failed" with `job_type=license.evaluate`
for each failed check.

**What to do.** Check that the database is reachable and healthy. As the database owner, look for a session that
holds the license row: `SELECT pid, state, xact_start, query FROM pg_stat_activity WHERE pid = ANY
(pg_blocking_pids(<pid of a waiting Alice session>))`, or list long transactions with `SELECT pid, usename,
xact_start, query FROM pg_stat_activity WHERE xact_start < now() - interval '5 minutes'`; end such a session with
`SELECT pg_terminate_backend(<pid>)`. If the license is still valid, changes resume after the next successful check,
which is retried at least every 10 minutes (or restart Alice to check at once). If the license itself has expired, the answer
then becomes ALC-LIC-0001.

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

**Likely cause.** The server is off, the address or port is wrong, or a firewall blocks the Alice host. A connection
that is closed or reset while Alice signs in also counts as unreachable (it is retried), not as a refused sign-in;
only the server's explicit refusal of every sign-in method (or "too many authentication failures") is
`ALC-SSH-0002`.

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
protocol 5, `alice-helper` 1.4.0).

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

**Likely cause.** An unusually large key file, SSH configuration or Nginx configuration (`nginx -T`).

**What to do.** Inspect the server's `authorized_keys` files, `sshd -T` output and `nginx -T` output.

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

## ALC-SSH-0012: Alice does not connect to this server's address

**Meaning.** When Alice connected, the server's name resolved to an address Alice never connects to, so Alice opened
no connection (nothing was sent). These are the addresses that are refused when a server is added by address: link-local
addresses, including the cloud metadata address `169.254.169.254` and its IPv6 forms, multicast addresses, unspecified
addresses (`0.0.0.0`, `::`, which reach services of Alice's own host), `0.0.0.0/8`, `240.0.0.0/4` (with
`255.255.255.255`), and the IPv6 forms that never name a server (IPv4-compatible `::a.b.c.d`, IPv4-translated
`::ffff:0:a.b.c.d`, Teredo `2001::/32`). Loopback and private addresses are allowed. Alice checks every address the
name resolves to, at every connection (SSH and its own TLS check of a website), on the address it actually connects
to; a refused address is never connected, another address of the same name may be. The reason is also shown when the
name has a refused address and its other addresses failed to connect (one address down, one refused): the refused
record is what needs fixing. The server's status becomes **Cannot be reached** with this reason (a server still waiting
for its fingerprint confirmation keeps that status); the job is not retried, and the next scheduled test or a **Test
connection** tries again. When only Alice's own TLS check of a website is refused, the check on the server decides and
Alice logs a warning with this reason.

**Likely cause.** The server's DNS record changed (by mistake, or a wildcard DNS name such as `*.nip.io` that encodes an
address), or someone is trying to make Alice reach a service of its own host or the cloud metadata service through a
name that resolves differently over time (DNS rebinding).

**What to do.** Check the server's DNS record (`dig +short <name>` from Alice's host). If the name is wrong, edit the
server and enter its real address or a name that resolves to it, then **Test connection**. If you did not change the
record, treat it as a possible attack on Alice's network position.

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

## ALC-NGX-0001: Nginx not found

**Meaning.** Nginx was not found on this server. (HTTP 502, reason `nginx.not_found`.)

**Likely cause.** Alice looked for `/usr/sbin/nginx`, where the standard packages install it.

**What to do.** Install Nginx from your distribution or nginx.org, or add this server as a Linux server.

## ALC-NGX-0002: Nginx configuration has a problem

**Meaning.** Nginx's configuration has a problem, so Alice will not deploy to this server until it is fixed. (HTTP 409, reason `nginx.config_invalid`.)

**Likely cause.** Nginx's configuration has an error, or it uses files or settings Alice cannot safely read. Nothing was changed.

**What to do.** Run `nginx -t` on the server and fix any error. If it passes, check the file named on the server's page, then choose Discover again.

## ALC-NGX-0003: Nginx configuration changed

**Meaning.** The Nginx configuration changed since Alice last looked. (HTTP 409, reason `nginx.config_changed`.)

**Likely cause.** This website no longer uses the certificate and key files Alice found. Nothing was changed.

**What to do.** Choose Discover on the server's page, then deploy again.

## ALC-NGX-0004: Server not prepared for Nginx

**Meaning.** This server is not prepared for Nginx work. (HTTP 502, reason `nginx.profile_missing`.)

**Likely cause.** The Alice account may run `alice-helper` for SSH keys only (Linux profile), not for certificates.

**What to do.** On the Servers page choose Server type Nginx server, copy the commands and run them on the server again.

When the Nginx lines disappear from `/etc/sudoers.d/alice` after the last scan, a deployment cannot tell sudo's refusal
from a change that started (sudo may already have read the new key): it is not ended as this failure but goes to
**Confirming the outcome**, whose checks fail with this code until the commands are run again (after about a day it
ends **Outcome not confirmed**, `ALC-DEP-0018`). After any change to the sudoers file, choose **Test connection** and
**Discover** on the server's page before deploying.

## ALC-NGX-0005: Not enough free disk space

**Meaning.** The server does not have enough free disk space. (HTTP 502, reason `nginx.no_space`.)

**Likely cause.** Alice needs room for the new files and a backup of the old ones. Nothing was changed.

**What to do.** Free some space on the server, then deploy again.

## ALC-NGX-0006: Certificate file changed

**Meaning.** The certificate file changed since Alice last looked. (HTTP 409, reason `nginx.file_changed`.)

**Likely cause.** Someone or another tool replaced the file after the last discovery. Nothing was changed.

**What to do.** Choose Discover on the server's page, check the website, then deploy again.

## ALC-NGX-0007: Certificates cannot be changed here

**Meaning.** Alice cannot change certificates at this place. (HTTP 409, reason `nginx.location_unsupported`.)

**Likely cause.** The website's certificate setup is one Alice does not support, its files no longer meet Alice's safety rules (for example a folder that users other than root can change), or the website no longer uses this file. Nothing was changed.

**What to do.** Choose Discover on the server's page to see the reason next to the website, and change the setup on the server if you want Alice to manage it.

## ALC-NGX-0008: Another certificate change is running

**Meaning.** Another certificate change is running on this server. (HTTP 409, reason `nginx.busy`.)

**Likely cause.** `alice-helper` changes one website at a time on a server.

**What to do.** Wait a minute and try again.

## ALC-NGX-0009: Server could not complete the file work

**Meaning.** The server could not complete the file work. Nothing was changed. (HTTP 502, reason `nginx.io_error`.)

**Likely cause.** `alice-helper` reported an input or output error before it replaced any file, for example a folder it cannot write, a read-only file system, or Nginx stopping while it was checked.

**What to do.** Check the server's disks and certificate folders, then deploy again.

## ALC-NGX-0010: Nginx not running

**Meaning.** Nginx is not running on the server. Nothing was changed. (HTTP 502, reason `nginx.not_running`.)

**Likely cause.** `alice-helper` checks before it changes any file that `/usr/bin/systemctl` exists and that `systemctl is-active nginx` succeeds; otherwise a reload could not apply the new certificate. Nginx was stopped or failed, or the server does not use systemd.

**What to do.** Run `systemctl status nginx` on the server, start Nginx (`systemctl start nginx`), then deploy again.
A server that runs Nginx under another systemd unit name, or without systemd, cannot be deployed to (a known
limitation).

## ALC-CRT-0001: Not a readable certificate

**Meaning.** This is not a certificate Alice can read. (HTTP 422, reason `certificate.invalid`.)

**Likely cause.** Alice expects PEM text with `BEGIN CERTIFICATE` blocks, or a PFX file. During a deployment, the stored certificate could not be sent to the server in that form.

**What to do.** When uploading, check that you chose the certificate file, not a request or another file. After a deployment, look at the deployment's steps: if the certificate file itself is at fault, upload a corrected certificate and deploy that one. If it happens again, report the request ID.

## ALC-CRT-0002: Certificate and key do not match

**Meaning.** The certificate does not match its private key. (HTTP 422, reason `certificate.key_mismatch`.)

**Likely cause.** When uploading: the private key belongs to another certificate. During a deployment: after the new files were written, `nginx -t` reported that a certificate and its key file on the server do not belong together.

**What to do.** When uploading, use the key that was created together with this certificate. After a deployment, check which certificate and key files the websites on this server use; the deployment's status shows whether the previous files are back.

## ALC-CRT-0003: Certificate expired

**Meaning.** This certificate has already expired. (HTTP 422, reason `certificate.expired`.)

**Likely cause.** Its validity period has ended, so browsers would refuse it.

**What to do.** Get a renewed certificate from your certificate authority and upload that one.

## ALC-CRT-0004: Private key protected with a password

**Meaning.** The private key is protected with a password. (HTTP 422, reason `certificate.key_encrypted`.)

**Likely cause.** Alice cannot store a key it cannot read.

**What to do.** Remove the password from the key, or upload a PFX file and enter its password.

## ALC-CRT-0005: Wrong PFX password

**Meaning.** The PFX password is wrong or the file is damaged. (HTTP 422, reason `certificate.pfx_password`.)

**Likely cause.** Alice could not open the PFX file with this password.

**What to do.** Check the password, or export the PFX file again.

## ALC-CRT-0006: Weak key or signature

**Meaning.** This certificate or one in its chain uses a weak key or signature. (HTTP 422, reason `certificate.weak`.)

**Likely cause.** RSA keys shorter than 2048 bits and MD5 or SHA-1 signatures are no longer safe.

**What to do.** Ask your certificate authority for a certificate with a stronger key and a SHA-256 signature.

## ALC-CRT-0007: Key type not supported

**Meaning.** Alice supports RSA and ECDSA certificates only. (HTTP 422, reason `certificate.unsupported_key`.)

**Likely cause.** This certificate uses another key type (for example Ed25519), another curve, or an RSA key larger than 16384 bits.

**What to do.** Use a certificate with an RSA key of 2048 to 16384 bits, or an ECDSA P-256 or P-384 key.

## ALC-CRT-0008: Certificate already stored

**Meaning.** Alice already has this certificate with its key. (HTTP 409, reason `certificate.duplicate`.)

**Likely cause.** This certificate and its key are already stored, from an earlier upload or a signing request.
One upload of a stored certificate is accepted: when the chain Alice holds is incomplete and the upload brings the
certificate with its complete chain (and its key), Alice completes the stored chain instead (answer "chain
completed", audit `certificate.chain_completed`). A certificate from a signing request cannot be uploaded (its key
never leaves Alice), so its chain cannot be completed this way.

**What to do.** Open the certificate in the list and deploy it from there.

## ALC-CRT-0009: Private key not held

**Meaning.** Alice does not have the private key of this certificate. (HTTP 409, reason `certificate.no_private_key`.)

**Likely cause.** Alice found this certificate on a server, and private keys are never read from servers.

**What to do.** Upload the certificate together with its key, then deploy it.

## ALC-CRT-0010: Key type does not fit this place

**Meaning.** This certificate's key type does not fit this place. (HTTP 409, reason `certificate.key_type_mismatch`.)

**Likely cause.** Key type the website uses here: `<expected>`. Key type of this certificate: `<actual>`.

**What to do.** Choose a certificate with the same key type, or the website's other certificate place.

## ALC-CRT-0011: Incomplete chain needs an administrator

**Meaning.** An administrator must confirm the incomplete chain of this certificate. (HTTP 409, reason `certificate.chain_unconfirmed`.)

**Likely cause.** The certificate chain does not reach a trusted root, so some browsers may not trust it.

**What to do.** Ask an administrator to deploy it and confirm the chain.

## ALC-CRT-0012: Signing request no longer open

**Meaning.** This signing request is no longer open. (HTTP 409, reason `csr.not_pending`.)

**Likely cause.** It was completed or cancelled.

**What to do.** Create a new signing request if you need one.

## ALC-CRT-0013: Certificate not issued for this request

**Meaning.** This certificate was not issued for this signing request. (HTTP 422, reason `csr.certificate_mismatch`.)

**Likely cause.** Its public key is not the one Alice created for the request.

**What to do.** Paste the certificate your certificate authority returned for this request.

## ALC-CRT-0014: Certificate not valid yet

**Meaning.** This certificate is not valid yet. (HTTP 409, reason `certificate.not_yet_valid`.)

**Likely cause.** Its validity period has not started, so browsers would refuse it.

**What to do.** Deploy it once its validity period has started, or check the clock of the Alice host.

## ALC-CRT-0015: Busy reading other PFX files

**Meaning.** Alice is busy reading other PFX files. (HTTP 503, reason `certificate.pfx_busy`.)

**Likely cause.** Alice reads at most two PFX files at a time, and that limit was reached. Nothing was stored.

**What to do.** Wait a moment and upload the file again.

## ALC-CRT-0016: Busy creating other signing requests

**Meaning.** Alice is busy creating other signing requests. (HTTP 503, reason `csr.busy`.)

**Likely cause.** Alice creates the keys of at most two signing requests at a time (an RSA 4096 key takes about a second of one processor core), and that limit was reached. Nothing was stored.

**What to do.** Wait a moment and create the signing request again.

## ALC-CRT-0017: Too many open signing requests

**Meaning.** There are too many open signing requests. (HTTP 409, reason `csr.too_many_pending`.)

**Likely cause.** Alice keeps at most 1000 open signing requests for the whole installation, all users together (each holds a private key that waits for its certificate), and that limit was reached. Nothing was created.

**What to do.** Complete or cancel the signing requests you no longer need (under **Open signing requests** on the Certificates page), then create this one again.

## ALC-DEP-0001: Deployment already in progress

**Meaning.** Another deployment to this website is in progress. (HTTP 409, reason `deployment.in_progress`.)

**Likely cause.** Alice runs one deployment per certificate file at a time.

**What to do.** Wait until it finishes; its progress is in the deployment history.

## ALC-DEP-0002: Earlier deployment still being finished

**Meaning.** Alice is still finishing an earlier deployment on this server. (HTTP 409, reason `deployment.recovery_pending`.)

**Likely cause.** An earlier deployment on this server did not end normally, and Alice must first find out how it ended and finish it. The server's helper gives the same answer when an earlier change of the same files that Alice is still finishing blocks them.

**What to do.** Wait until that deployment shows its result in the deployment history, then deploy again. (When the blocking change is one Alice no longer follows, the deployment ends with `ALC-DEP-0023` or `ALC-DEP-0024` instead.)

## ALC-DEP-0003: Website still serves the previous certificate

**Meaning.** The website still serves the previous certificate. (HTTP 502, reason `deployment.verify_failed`.)

**Likely cause.** After the change the website kept serving the previous certificate, for example because the website's configuration sends this name to another website, or Nginx was not reloaded. The deployment's status shows whether the previous files are back.

**What to do.** Check which part of the Nginx configuration answers for this website's name, then deploy again.

## ALC-DEP-0004: Served certificate could not be confirmed

**Meaning.** Alice could not confirm which certificate the website serves. (HTTP 502, reason `deployment.verify_other`.)

**Likely cause.** The website served a certificate that is neither the previous nor the new one (for example from a load balancer in front of it), or Alice has not read the website's current certificate yet. The deployment's status shows whether anything was changed.

**What to do.** Choose Discover on the server's page. If the website is behind another server, an administrator can set the port and name to check in its verification settings.

## ALC-DEP-0005: Website could not be reached for the check

**Meaning.** Alice could not reach the website on port `<port>`. (HTTP 502, reason `deployment.verify_unreachable`.)

**Likely cause.** Neither Alice nor the server itself could connect to the website, or the website has no HTTPS address Alice can check. The certificate it serves could not be checked. The deployment's status shows whether anything was changed.

**What to do.** Allow Alice to reach this port, or ask an administrator to change the website's verification settings.

When the website's `listen` names a host name that resolves to an address other than 127.0.0.1, no firewall change
helps: Alice cannot check such a website. Change the `listen` to an IP address or to a plain port, or turn the check
off in its verification settings (see [Deployments](#deployments)).

## ALC-DEP-0006: Nginx did not reload

**Meaning.** Nginx did not reload. (HTTP 502, reason `deployment.reload_failed`.)

**Likely cause.** `systemctl reload nginx` failed after the new files were written. The deployment's status shows whether the previous files are back.

**What to do.** Run `systemctl status nginx` on the server to see why, then deploy again.

## ALC-DEP-0007: Nginx rejected the new files

**Meaning.** Nginx rejected the new files. (HTTP 502, reason `deployment.config_test_failed`.)

**Likely cause.** `nginx -t` failed after the new certificate and key were written. The deployment's status shows whether the previous files are back.

**What to do.** Check the certificate file format and the chain, then deploy again.

## ALC-DEP-0008: Previous certificate not confirmed back

**Meaning.** Alice could not confirm that the previous certificate is back. Manual action is needed. (HTTP 502, reason `deployment.rollback_failed`.)

**Likely cause.** The deployment failed, and putting the previous certificate and key back did not finish or could not be confirmed. A backup of the previous files is on the server in `/var/lib/alice-helper/backups`, in the folder named with this deployment's ID.

A deployment may show `ALC-DEP-0019` (the files are back but the website was not confirmed) or `ALC-DEP-0020` (another program changed the files) instead; a task (job) record always shows this code.

**What to do.** Check the website now. Compare the files with the backup on the server, then run `nginx -t` and `systemctl reload nginx`.

## ALC-DEP-0009: Files restored but Nginx did not reload

**Meaning.** Files are back in place but Nginx did not reload. (HTTP 502, reason `deployment.rollback_reload_failed`.)

**Likely cause.** Alice restored the previous certificate and key, but `systemctl reload nginx` failed afterwards.

**What to do.** Run `systemctl status nginx` on the server, fix the cause, then reload Nginx.

## ALC-DEP-0010: Deployment did not finish normally

**Meaning.** The deployment did not finish normally. (HTTP 502, reason `deployment.interrupted`.)

**Likely cause.** While the deployment ran, the connection to the server was lost, Alice restarted, or the server could not finish writing the files. The deployment's status shows which certificate the server has; if Alice does not know yet, it keeps checking.

**What to do.** Check the deployment history. Once it shows a result, deploy again if needed.

## ALC-DEP-0011: Server not ready for a deployment

**Meaning.** Alice cannot deploy to this server now. (HTTP 409, reason `deployment.target_not_ready`.)

**Likely cause.** The server is not connected: its host key fingerprint is not confirmed or has changed, Alice cannot sign in, or the server is disabled.

**What to do.** Open the server's page, solve the problem shown there, then deploy again.

## ALC-DEP-0012: Website serves a different chain

**Meaning.** The website serves the expected certificate with a different chain (port `<port>`). (HTTP 502, reason `deployment.verify_chain`.)

**Likely cause.** The number of certificates the website sends differs from the chain Alice expected, for example because another file or a proxy adds or drops intermediate certificates. The deployment's status shows whether anything was changed.

**What to do.** Check which certificate files this website's configuration uses, then deploy again.

## ALC-DEP-0013: Nothing to restore

**Meaning.** There was nothing to restore. (HTTP 502, reason `deployment.nothing_to_restore`.)

**Likely cause.** `alice-helper` found that this deployment had not changed any file, so there was nothing to put back.

**What to do.** Check the deployment's result in the deployment history, then deploy again if needed.

## ALC-DEP-0014: A later change replaced the files

**Meaning.** A later change replaced the files, so Alice did not restore them. (HTTP 502, reason `deployment.superseded`.)

**Likely cause.** While Alice was finishing this deployment, a later operation on the server replaced the certificate files. Alice cannot tell what they hold now.

**What to do.** Check which certificate the website serves now, then choose Discover on the server's page.

## ALC-DEP-0015: Server has no record of the deployment

**Meaning.** The server has no record of this deployment. (HTTP 502, reason `deployment.unknown_operation`.)

**Likely cause.** `alice-helper` has no record of this deployment, for example because it never received it or because it removed the record after 7 days or more.

**What to do.** Check which certificate the website serves now, then choose Discover on the server's page.

## ALC-DEP-0016: Server deleted during the deployment

**Meaning.** The server was deleted before the deployment finished. (HTTP 409, reason `deployment.target_deleted`.)

**Likely cause.** The server was removed from Alice while this deployment was waiting or running. If a change had already reached the server, Alice cannot check it any more.

**What to do.** If the server still exists, check its website and the certificate files on it.

## ALC-DEP-0017: Alice stopped trying to finish the deployment

**Meaning.** Alice stopped trying to finish this deployment. Manual action is needed. (HTTP 502, reason `deployment.recovery_exhausted`.)

**Likely cause.** For about a day Alice could not find out how the deployment ended, usually because it could not reach the server. If the change reached the server, a backup of the previous files is there in `/var/lib/alice-helper/backups`, in the folder named with this deployment's ID.

**What to do.** Check the website and the server's connection now, then choose Discover on the server's page.

## ALC-DEP-0018: Outcome of the deployment unknown

**Meaning.** Alice cannot tell how this deployment ended. Manual action is needed. (HTTP 502, reason `deployment.outcome_unknown`.)

**Likely cause.** Alice no longer has the records it needs to check or undo this deployment. If the change reached the server, a backup of the previous files is there in `/var/lib/alice-helper/backups`, in the folder named with this deployment's ID.

**What to do.** Check the website now, then choose Discover on the server's page.

## ALC-DEP-0019: Files restored but the website was not confirmed

**Meaning.** The previous files are back, but the website was not confirmed. (HTTP 502, reason `deployment.restored_unverified`.)

**Likely cause.** Alice put the previous certificate and key back, but then could not confirm that the website serves the previous certificate again.

**What to do.** Check the website now. If it is wrong, run `nginx -t` and `systemctl reload nginx` on the server.

## ALC-DEP-0020: Files changed by another program during the deployment

**Meaning.** Another program changed the certificate files during the deployment. Manual action is needed. (HTTP 502, reason `deployment.rollback_file_changed`.)

**Likely cause.** While Alice was deploying or putting the previous files back, another program changed the certificate or key file. Alice never overwrites that program's file: it put back at most the files it had written itself, so the certificate and key on the server may not belong together now. A backup of the previous files is on the server in `/var/lib/alice-helper/backups`, in the folder named with this deployment's ID.

**What to do.** Run `nginx -t` on the server now: if it fails, the certificate and key do not belong together. Find out which program changed the files (for example certbot), put a matching pair back from that program or from the backup, check the website, then choose Discover on the server's page. Do not restore the backup over the other program's file without checking which certificate is meant to be there (see the deployment points above).

## ALC-DEP-0021: Files must be read again first

**Meaning.** Alice must read this website's files again before deploying. (HTTP 409, reason `deployment.rescan_needed`.)

**Likely cause.** Alice does not know the current content of the certificate file, which it needs to make sure nobody changed the file in the meantime.

**What to do.** Choose Discover on the server's page, then deploy again.

## ALC-DEP-0022: Deployment cancelled by an administrator

**Meaning.** An administrator cancelled this deployment before anything was sent to the server. (HTTP 409, reason `deployment.cancelled`.)

**Likely cause.** An administrator chose **Discard** for the deployment's waiting job (for example a job held while the license was expired), so Alice sent nothing to the server. The website keeps its previous certificate, and no failure email is sent.

**What to do.** Deploy the certificate again if it is still needed.

## ALC-DEP-0023: An unfinished change of the files on the server stops new changes

**Meaning.** An unfinished change of these certificate files on the server stops new changes. The server refused the deployment because an earlier change of the same certificate and key files did not finish there; this deployment's certificate was not written. (HTTP 409, reason `deployment.server_operation_pending`; the parameter `operation_id` names the unfinished change.)

**Likely cause.** An earlier change was interrupted on the server (for example the helper was killed between writing the key and the certificate) and Alice no longer follows it, and `alice-helper` refuses new changes of those files until that change is undone. Alice undoes such a change by itself, once, only when it does not know the change at all (the server was deleted and added again, or Alice's database was restored from a backup) or knows it as a deployment of this same website whose outcome was not confirmed; it then deploys again. This message means one of:

- Alice does not undo that change because it knows it otherwise: from another website, or as a change that ended normally.
- Alice tried and the undo did not finish (the step **recover_pending** in the deployment's history shows it failed). It may have put back one of the two files.
- The change's record on the server cannot be read (see below).

**Where to find the operation id.** Open the deployment in **Deployment history**: the error's details show `operation_id`, and so does the step **recover_pending** if Alice tried the undo. It is a deployment ID; if Alice still has a deployment with that ID, the history shows it.

**What to do.** On the server, as root:

1. Run `/usr/local/libexec/alice-helper nginx-restore --op <operation_id>` and read its answer. A `restored` phase means the files from before that change are back.
2. Run `nginx -t` and, if it passes, `systemctl reload nginx`.
3. In Alice choose **Discover** on the server's page, then deploy again.

If `nginx-restore` answers `IO_ERROR`, the change's record (`/var/lib/alice-helper/backups/<operation_id>/journal.json`) usually cannot be read, typically one written by an older helper for a file name the helper no longer accepts. The helper keeps such a record, and keeps refusing changes of those files, for 30 days; `cleanup --op` refuses to remove it. `IO_ERROR` is also the helper's answer to a disk or permission problem, so first check that `journal.json` exists in that folder and is either not valid JSON or names a file the helper refuses; if the file reads normally, look for a full disk or changed permissions under `/var/lib/alice-helper` instead and do not continue with the steps below. To unblock the files before the 30 days pass, by hand:

1. **Warning: this folder holds the previous private key.** Copy the whole folder somewhere only root can read first, for example `cp -a /var/lib/alice-helper/backups/<operation_id> /root/alice-backup-<operation_id>`.
2. Find the certificate and key files of the website (from the Nginx configuration, or `cat journal.json` if it can still be read as text). Check that they belong together: `openssl x509 -in <certificate file> -noout -pubkey` and `openssl pkey -in <key file> -pubout` must print the same key. If they do not, put back both previous files from `cert.bak` and `key.bak` in that folder with the owner, group and mode the current files have (`install -o … -g … -m … key.bak <key file>`, the key first; see [nginx-host-preparation.md](nginx-host-preparation.md#restoring-a-previous-certificate-by-hand)), and check again.
3. Run `nginx -t` and `systemctl reload nginx`.
4. Remove the change's folder: `rm -r /var/lib/alice-helper/backups/<operation_id>`. Only this removal unblocks the files (the helper then no longer finds an unfinished change for them). Do not remove any other folder.
5. In Alice choose **Discover**, then deploy again.

## ALC-DEP-0024: Alice undid an unfinished earlier change; the certificate was not deployed

**Meaning.** An earlier change of the same certificate and key files on the server did not finish, and Alice no longer followed it. Alice put back the files that change had replaced, so the website now serves the certificate from before that change; the certificate of this deployment was not written. (HTTP 409, reason `deployment.pending_change_restored`, status rolled back; the parameter `operation_id` names the earlier change, and the deployment's history shows the step `recover_pending`.)

**Likely cause.** The earlier change was interrupted on the server (for example the helper was killed after replacing the files), and Alice had stopped following it: its outcome was recorded as unknown, the server was deleted and added again, or Alice's database was restored. The new deployment found the files blocked, restored them, and then could not write its own certificate, typically because the files no longer held what Alice had last read (it had read the earlier change's files).

**What to do.** Choose **Discover** on the server's page so that Alice reads the files again, then deploy the certificate again.
