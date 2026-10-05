# Administrator Guide

This guide covers day-to-day administration. Sections for alerts and SSO are added in later releases. First-time setup is described in [first-run.md](first-run.md); server commands are in
[operator-guide.md](operator-guide.md).

## Users and roles

Alice has three roles:

| Role | Can do | Cannot do |
|---|---|---|
| Administrator | Everything: users, settings, audit log, API tokens of other people, a website's verification settings, deploying a certificate with an incomplete chain; Key Vaults: adding a vault, its credentials and check interval, automatic deployment, held versions, imports into a vault | — |
| Operator | View inventory; test servers, run discovery and remove SSH keys; upload certificates, create signing requests and deploy certificates; check a Key Vault, connect its certificates to websites and deploy a version that is not held; own API tokens | Manage users, see the audit log, change settings or verification settings, deploy an incomplete chain, manage Key Vaults beyond that |
| Auditor | View inventory read-only, view and export the audit log, verify its integrity; own read-only API tokens | Change anything, manage users |

The full list of which role may call which API operation is in [authz-matrix.md](authz-matrix.md).

### Add a person

1. Open **Users** and choose **Add user**.
2. Enter the username, full name, optional email, **Role** and an **Initial password** (at least 12 characters).
3. Choose **Create user**. If you have not confirmed your identity in the last five minutes, Alice asks for a
   6-digit code (**Confirm it's you**).
4. Give the person their username and initial password through a separate channel. At their first sign-in they
   scan a QR code with their authenticator app and save their own recovery codes. Alice does not force them to
   change the initial password; ask them to do so on **My account** (**Change password**).

Expected: the person appears in the list; the **Two-factor sign-in** column shows "Not set up yet" until their
first sign-in.

Usernames use the letters A–Z, digits, dot, underscore and dash (2 to 64 characters) and must start with a letter
or digit. They are compared without
regard to case ("Admin" and "admin" are the same account). Letters such as "İ" or "ş" are refused so nobody can
create a lookalike account; full names may use any letters.

### Change a role, disable a person, reset their MFA or password

Open **Users**, choose **Manage** on the person's row and choose the action: **Edit** (name, email, role),
**Reset two-factor sign-in**, **Set a new password**, **Sign out everywhere**, **Disable** or **Enable**. Every
one of these asks for a fresh 6-digit code if you have not confirmed your identity in the last five minutes.

Changing a role, disabling a person, resetting their MFA or password, and **Sign out everywhere** end all their
current sessions immediately. **Set a new password**, **Sign out everywhere** and **Disable** also revoke all their
API tokens (the dialogs say so); enabling the account again does not bring the tokens back. A token is refused from
its next request on; a task a token or session already queued still runs. A role change and **Reset two-factor
sign-in** keep the tokens (they follow the new role), and so does a person's own password change on **My account**.
The audit log records one "API token revoked" entry per token (with the reason) and the number of revoked tokens
on the reset, sign-out or disable entry.

Alice never lets you remove the last enabled local administrator (disable or change role). This keeps a
break-glass account available.

### If an account may be compromised

First decide what may be known to someone else:

- **The password, the authenticator or the recovery codes may be known** (or you do not know): choose **Set a new
  password** and then **Reset two-factor sign-in**. **Set a new password** ends every session and revokes every API
  token of the person; **Reset two-factor sign-in** removes their authenticator and recovery codes, so they set up a
  new one at the next sign-in. Give the new password to the person through a separate channel. If the person should
  not sign in at all for now, choose **Disable** (it also ends the sessions and revokes the tokens; **Enable**
  later, after the two steps above).
- **Only a signed-in device was lost or stolen, and the password and authenticator are believed safe:** choose
  **Sign out everywhere**. It ends every session and revokes every API token; the person signs in again with their
  password and code. Do not use it when the credentials may be known: whoever knows them signs in again just as
  easily.

Then open **Audit log** and check the entries that show the person in the **User** column (use **Load more** for
older entries, or **Export JSON** and search the file); **Details** of an entry shows what it changed.

**Reset two-factor sign-in** and a role change on their own end the sessions but do **not** revoke API tokens: a
token keeps working with the person's current role. Only **Set a new password**, **Sign out everywhere** and
**Disable** revoke them; the person's scripts then need new tokens.

## Multi-factor authentication and recovery codes

Every local account must use an authenticator app. Each code works once. If a person loses their phone they sign
in with one of their recovery codes (each works once) and then create new recovery codes on **My account**
(**Create new recovery codes**; the old codes stop working).
If they have no recovery codes left, an administrator resets their MFA on **Users**; if the only administrator has
lost both the authenticator and the recovery codes, the server operator runs `alice admin reset-mfa <username>`
(see [operator-guide.md](operator-guide.md)). Resetting MFA does not end a sign-in block; see below.

## Sign-in protection

After 5 wrong attempts (password or code) in a row, Alice makes the account wait a little longer before each new
attempt (1, 2, 4, 8 and 16 seconds). After 10, the account is blocked for 15 minutes. During the wait the
message stays "Incorrect username or password." even for the right password, so an attacker learns nothing.
The count starts again only after a complete sign-in (password and code); a correct password on its own does not
reset it. Because the count is still 10 or more when a block ends, one more wrong attempt starts a new 15-minute
block. **Set a new password** on **Users** clears the block at once. If the blocked account is the only
administrator (so nobody can open **Users**), the server operator runs `alice admin unlock <username>` (see
[operator-guide.md](operator-guide.md)): it sets the count back to zero and ends the block, and is recorded in the
audit log (`user.unlocked`, actor `cli`).
Every sign-in, failure and block is in the audit log (`auth.lockout`). Email notification of blocks arrives in a
later release.

The same failure count also covers **Confirm it's you** codes and the current password on **Change password**: while
an account is blocked, its owner cannot confirm their identity for administrator actions either, even in a session
that is still open, and someone who keeps guessing an administrator's password can keep it that way. `alice admin
unlock` ends one block, but the next wrong attempts start a new one; check the audit log for where they come from.

## Staying signed in

A session ends after 30 minutes without activity, and always 12 hours after sign-in. Activity means clicking,
typing, scrolling with the wheel or touching the page, or saving a change. Pages that refresh themselves (the
license status, a server or deployment you are watching, a running task) do not count, so a page left open is
signed out 30 minutes after the last input although it keeps refreshing. Moving the mouse alone does not count
either: someone who only reads one page for 30 minutes is signed out. Input reaches Alice within about a minute;
when you switch to another tab or close it, Alice sends any input it has not reported yet. After a timeout the
sign-in page says "Your session ended. Please sign in again."; what was typed into an open dialog is lost.

Tools that drive the browser's real input (remote desktop, browser automation) count as activity; a script or
browser extension that fakes events does not. For automation use API tokens, which have no idle timeout.

## API tokens

**API tokens** lets each person create tokens for scripts. Choose a **Name**, the **Access** (**Read only** or
**Read and operate**; auditors can only create read-only tokens) and how many days the token is valid (at most
365). Creating a token asks for a fresh 6-digit code if you have not confirmed your identity in the last five
minutes. The token is shown once; copy it immediately. Scripts send it as `Authorization: Bearer alice_…`.
A token never has more rights than its owner's current role, and tokens cannot manage users, settings or tokens.
Revoking a token stops it at once.

Administrators can list and revoke anyone's tokens through the API: `GET /api/v1/tokens?user_id=<id>` and
`DELETE /api/v1/tokens/<token id>`, from a signed-in browser session. The **API tokens** page shows your own
tokens.

The API is described in `api/openapi.yaml` in the Alice source (every operation, its request and response
fields and the permission it needs).

## Audit log

**Audit log** (administrators and auditors) lists every sign-in, failure, denied request and change, newest
first. Each entry is linked to the previous one with a SHA-256 hash, so changing or deleting an entry breaks the
chain.

- **Verify integrity** checks the whole chain. Expected: "The audit log is intact." If it reports "Audit log
  integrity problem at entry N", keep a copy of the database and of an export, and contact your security team.
- **Export CSV** / **Export JSON** download the whole log with its verification result. Exports are recorded in
  the audit log. The CSV file's first line carries the result (`# alice audit export: intact=true …`); the column
  names are on line 2. Use the JSON export to re-check the chain outside Alice: the CSV export protects spreadsheet
  users by prefixing cells that start with `=`, `+`, `-` or `@` with an apostrophe, so its cells are not always
  the original values (see [operator-guide.md](operator-guide.md#checking-an-audit-export-outside-alice)).
- Alice runs one check or export of the audit log at a time. If someone else's is running, **Verify integrity**
  answers "Alice is already checking or exporting the audit log." and an export download fails: wait until the other
  one has finished and try again. Such refusals are recorded too ("Audit log export refused: another check or export
  was running").
- The **Object** column names what an entry is about, and **Details** opens its recorded values.
- Repeated refusals are recorded once per 10 minutes. When the same person is refused the same thing on the same
  page or API operation again within 10 minutes (permission denied, or blocked by the license), Alice writes no new
  entry; when the 10 minutes end it adds one entry whose details say how many more refusals like it there were and
  between which times, and from how many addresses (and, where it applies, for how many objects or API tokens).
  All sessions of a person count together, and all API tokens of a person count together.
- After verification Alice shows the **Fingerprint of the latest entry**. Record it somewhere outside Alice (for
  example in a ticket) from time to time: a later fingerprint that does not continue from it shows that entries
  were removed. Syslog forwarding arrives in a later release.
- Alice also checks the whole chain once a day on its own (recorded as `audit.verified` by `scheduler`). If the
  check finds a problem, administrators with an email address get one email about it.

## Servers

**Servers** lists every server Alice manages with its status: **Connected**, **Waiting for fingerprint
confirmation**, **Checking…**, **Cannot be reached**, **Sign-in refused**, **Server identity changed** or
**Disabled**. Everyone can see the list and each server's details; nobody ever sees a password or private key there.

- **Add server** (administrators): see [nginx-host-preparation.md](nginx-host-preparation.md). Each server counts
  toward the license; when the license is full, Alice says "Your license allows N targets." and adds nothing. A
  server's address, SSH port and user cannot be changed later: remove the server and add it again.
- **Test connection** and **Scan for SSH keys** (administrators and operators) run in the background; the page
  updates when they finish. Test connection always opens a new connection to the server. On an **Nginx server** the
  scan is called **Discover** (in **Websites on this server**) and reads the SSH keys and the websites together.
- A server's **Server type** (**Linux server** or **Nginx server**) is chosen when it is added and cannot be
  changed; see [nginx-host-preparation.md](nginx-host-preparation.md#changing-a-linux-server-into-an-nginx-server).
- Alice scans every **Connected** server on its own once per discovery interval (one day unless it was changed
  through the API; at least one hour), and starts at most one scheduled job per server per interval whatever its
  outcome. A server that **Cannot be reached** is tested again at that interval; when the test succeeds it is
  **Connected** again and Alice scans it at once. Becoming unreachable sends no email of its own, and neither does a
  failed scheduled re-test; a scan, or a **Test connection** you started, that fails on its last attempt still sends
  the usual email about a stopped task. A
  successful scan or key removal also brings it back to **Connected**. A server left at **Checking…** after its
  fingerprint was confirmed (for example because Alice restarted) is tested again on its own. A server with **Sign-in refused** or **Server identity changed** is never tried again
  automatically: fix the cause, then choose **Test connection** (Sign-in refused) or review the fingerprint (Server
  identity changed).
- A new server that cannot be reached before you confirmed its fingerprint stays **Waiting for fingerprint
  confirmation** (its last error says why), so a fingerprint Alice already recorded can still be confirmed. Alice does
  not try it again on its own: choose **Test connection** when it can be reached.
- **Server identity changed**: Alice stopped all work on the server because its host key is different from the
  one you confirmed. Only an administrator can end this, with **Review the new fingerprint**, a reason and a recent
  authenticator code: **Accept new fingerprint** after checking it on the server, or **The server still shows the
  previous fingerprint** when the previous one is still right (Alice then tests the connection again and blocks the
  server again if it still presents another key). See
  [nginx-host-preparation.md](nginx-host-preparation.md#when-the-server-is-rebuilt). Everything is recorded in the
  audit log, and administrators with an email address get one email each time a server becomes blocked. The same
  email goes out once when a server refuses Alice's key.
- **Remove server** (administrators) makes Alice forget the server, closes the SSH connections Alice kept open to it
  and frees its license slot. Nothing is changed on the server.
- **Waiting for an administrator** lists work that was paused while the license had expired (for example a key
  removal), 50 at a time (**Show more** for the rest). After a new license is installed, an administrator chooses
  **Run now** or **Discard** for each item; nothing starts on its own. **Discard** is possible at any time, also
  while the license is expired. Work requested while Alice could not check its license (see [License](#license)) is
  not listed here: it waits and starts by itself after the next successful check.

## SSH keys

**SSH keys** lists every public key Alice found, once per key, with the number of servers and places where it is
used. Filter by **Search** (fingerprint, comment or key type), **Server**, **User** or **Finding** (weak key, runs a
fixed command, root key without a source address limit, listed more than once, certificate authority, hardware
security key). **Show keys that are no longer found** also lists keys that disappeared since the last scan; Alice
never deletes them from its records.

Open a key to see **Where this key is used**: server, user, file, line, options, last seen and state.
Administrators and operators can remove a key from one place with **Remove key** (on the server's page and on the
key's page). Alice removes only that key's lines from that file. It refuses to remove its own key ("Alice needs this
key to connect to this server and will not remove it."), refuses the last key of `root` (or of another account with user ID 0) in a file unless an
administrator ticks "This is the last key of the root account. Remove it anyway.", and refuses changes on servers
that get their keys from a program (`AuthorizedKeysCommand`) or whose SSH settings the last scan could not read.
Every refusal that protects access is recorded in the audit log. Generating, deploying and rotating keys arrive in a
later release.

The **SSH keys** list marks a key **No longer found** when every place it was used is gone; open a key to see the
state of each place. The keys of an account deleted from a server are marked **No longer found** when the server's
account list is complete; otherwise, and for an account that got a `nologin` shell or lost its home, the keys stay
listed as they were last seen and cannot be removed through Alice (see
[operator-guide.md](operator-guide.md#keys-of-accounts-alice-no-longer-lists)). A server's page warns when Alice could
not list an account (for example a name with characters Alice does not support): the warning names its user ID, and
`getent passwd <user ID>` on the server shows the account. While such a warning is shown, Alice does not mark keys of
deleted accounts **No longer found** on that server. Key options such as `command=` or
`environment=` are shown exactly as they are in the file, to everyone who can see the key, auditors included.

## Certificates

How to upload certificates, create signing requests, deploy and read the deployment history is described in
[operator-guide.md](operator-guide.md#certificates); administrators and operators work the same way there. Three
things are for administrators only.

### Verification settings

After every deployment Alice checks that the website serves the new certificate, and before it, that it serves the
current one. By default it connects to the server's address on each HTTPS port that Nginx's configuration names for
the website, with the website's first server name (for a wildcard name `*.example.com` it uses
`alice-check.example.com`; for a default server, the certificate's first name). When Alice cannot reach the port from
its own network, it checks from the server itself. A `listen` on a specific address other than the server's own is
always checked from the server itself.

Choose **Verification settings** in a website's row (on the server's page) when this does not fit, for example behind
a load balancer or a port mapping:

- **Port to check**: the port Alice connects to instead of the configured one (empty: the port from the
  configuration).
- **Name to check**: the domain name Alice asks for (empty: from the configuration). A domain name, not an IP
  address, without `*`.
- **Skip the check for this website**: Alice no longer checks before or after a deployment. Not recommended: a
  wrong certificate is then neither noticed nor restored automatically, and the deployment shows
  **Verification** **Skipped**. Use it only when nothing else works, for example for a `listen` on a host name that
  resolves to another address of the server (see [troubleshooting.md](troubleshooting.md#deployments)).

Choose **Save**. Every change is recorded in the audit log (`location.updated`). If someone else changed the website
in the meantime, Alice shows the current values and asks you to save again. Operators and auditors see the settings
read-only.

### Incomplete chains

A certificate whose chain does not lead to a trusted root is marked "The certificate chain is incomplete: some
browsers may not trust this certificate." (an expired certificate on the way counts as a gap). Operators cannot
deploy it. An administrator can, after ticking **I confirm that this incomplete chain is intended** in the deploy
dialog; the confirmation is recorded with the deployment. Prefer uploading the certificate again with its full
chain from your certificate authority: when Alice already holds the certificate with its key, that upload completes
the stored chain (`certificate.chain_completed`; not possible for a certificate from a signing request, whose key
never leaves Alice). A chain found on a server never completes it: the chain Alice deploys with a key it holds is the
chain uploaded (or pasted at a signing request's completion) with that key, also when the key was added to a
certificate first found on a server.

Signing requests: at most 1000 may be open for the whole installation, all users together (`ALC-CRT-0017`); cancel
the ones nobody needs.

### Emails about deployments

Every administrator with an email address gets these emails (when email is set up,
[operator-guide.md](operator-guide.md#email)):

| Email | Sent when |
|---|---|
| "Certificate deployment failed on <server>" | A deployment failed and nothing changed, or the previous certificate was put back. |
| "Manual action needed: certificate restore failed on <server>" | The previous files could not be put back, or another program changed them during the deployment (Alice then put back at most what it had written: run `nginx -t`, the pair may not match). It names the backup on the server. |
| "The previous certificate is back on <server> but Alice could not confirm the website serves it" | The files are back, but the check of the previous certificate did not succeed. Check the website. |
| "Alice put back older certificate files on <server>; your certificate was not deployed" | A deployment found an unfinished earlier change of the same files that Alice no longer followed and undid it (`ALC-DEP-0024`): the website now serves the certificate from before that change, which may be older or even expired. Check the website, choose **Discover** and deploy again. |
| "A later operation overwrote the files of a deployment on <server>" | Alice could not finish or undo a deployment because a later change replaced the files. |
| "Alice cannot finish a deployment on <server>" or "Alice cannot confirm a deployment on <server> yet" | Once per deployment, after four failed attempts to find out how an interrupted deployment ended. Alice keeps trying every 15 minutes. |
| "Alice could not confirm a certificate deployment on <server>" | Alice stopped trying after about a day, or the server was removed after the change was sent. Check the website and the backup on the server. |

A successful deployment, and one an administrator cancelled by discarding its waiting job (`ALC-DEP-0022`), sends no
email. Every deployment, refusal and outcome is in the audit log
(`deployment.*`, `certificate.*`, `csr.*`, `location.*`).

## Key Vaults

Day-to-day use of a vault (statuses, inventory, connections, automatic deployment, held versions, imports) is in
[operator-guide.md](operator-guide.md#key-vaults); giving Alice access in Azure is in
[azure-setup.md](azure-setup.md). What is for administrators:

| Action | Who |
|---|---|
| **Add Key Vault**, **Replace credentials** | Administrator with a fresh authenticator code; never an API token |
| Switching **Automatic deployment** on or off, **Release** of a held version, **Import into Key Vault** | Administrator with a fresh authenticator code; never an API token |
| **Deploy now** of a held version, adding websites to a connection that deploys automatically, removing a vault together with its connections | Administrator with a fresh authenticator code; never an API token |
| The check interval, **Remove Key Vault** (without connections) | Administrator |
| **Check now**, the access check, connecting websites, **Deploy now** of a version that is not held | Administrator or operator |
| Reading vaults, their inventory, connections and imports | Everyone |

The full list per API route is in [authz-matrix.md](authz-matrix.md).

**Sign-in credentials.** A vault signs in with a certificate (recommended), a client secret or the managed identity
of the Azure virtual machine Alice runs on. Alice stores a certificate's private key or a client secret only
encrypted with its master key, never shows it again and never returns it through the API; the secret fields of the
forms are emptied when the request is sent (they ask the browser not to remember them, which a browser may ignore).
**Replace credentials** checks the new ones as when adding a vault and keeps the old ones if the check fails; the
replaced credentials stay in the database, encrypted, because Alice never deletes stored credentials. Replace a
client secret or certificate before it expires: the vault's page warns from 30 days before the date (for a secret,
the date typed when it was added). This release sends no reminder email; after the date the vault shows
**Credentials expired** (`ALC-AKV-0002`). When Alice cannot decrypt a vault's stored credentials (it runs with
another master key than the one they were sealed with), a deployment from that vault fails with `ALC-AKV-0041`:
choose **Replace credentials** (a check of the vault or an import shows the generic `ALC-SYS-0003` in that case).

**What Alice stores of a vault.** The address, the sign-in method, the tenant and client IDs, the sealed credential,
the object ID Alice signs in as, and the metadata of certificates, versions, keys and secrets (names, versions,
thumbprints, dates, key types, content types, policies). Alice never stores the value of a secret or a certificate's
private key read from a vault: a deployment reads it right before it changes the server, keeps it in memory and
clears it afterwards. Every read of a certificate's secret is in the audit log (`kv.secret_read`, with its purpose).

**Check interval.** Each vault is checked every 15 minutes unless an administrator changes **Check every
(minutes)** on its page (5 to 1440). **Check now** checks at once.

**Emails.** Administrators with an email address get, per vault: a sign-in that failed three times in a row; a
certificate that disappeared from the vault; a new version of a connected certificate that automatic deployment
will not deploy (switched off, held for the license or its chain, disabled, expired, not yet valid, older than the
website's certificate, created before automatic deployment was switched on, replaced by a newer version before it
was deployed); automatic deployment of a version stopped after three failures; an import that failed or whose
outcome stays unknown. One check or planner run sends at most 20 emails of one kind per vault, then one summary;
there is no limit across vaults. No email is sent when the vault firewall refuses Alice. Everything a
vault does is in the audit log (`vault.*`, `kv.*`, `binding.*`).

## License

**License** (administrators and auditors) shows the Installation ID with **Copy**, the state ("Evaluation",
"Evaluation ended", "Active", "Expired, grace period" or "Expired, locked"), "Valid until <date>, N targets", how many targets
are in use, a license that starts later, the uploaded licenses and the history. Administrators upload a license
under **Upload a license**: **Check the file**, read **Confirm the license**, then **Install license** (a new
6-digit code may be asked first). Every upload, refused or accepted, is recorded in the audit log. The full guide,
including what lock mode does and how clock changes are handled, is [licensing.md](licensing.md).

License banners appear at the top of every page: the evaluation, the grace period, lock mode and "Alice could not
check its license since …" for everyone;
warnings 60/30/14/7/1 days before the end, clock problems, damaged license data, a license that starts later and
the target limit for administrators only. Administrators with an email address also get the warnings by email when
the server operator has set up email ([operator-guide.md](operator-guide.md#email)).

## For auditors

Auditors sign in like everyone else (password and authenticator app). They see **Home**, **Servers**, **SSH keys**, **Certificates**, **Deployment history**, **Key Vaults**, **Audit log**,
**License** (read only), **API tokens** and **My account**, and no button that changes anything except their own password, recovery codes,
language and read-only API tokens. On **Audit log** they can filter, **Verify integrity** and export. A read-only
API token lets a script fetch `GET /api/v1/audit` or `GET /api/v1/audit/export?format=json` for regular
collection.
