# Administrator Guide

This guide covers day-to-day administration. Sections for targets, certificates, SSH keys, alerts and SSO are
added in later releases. First-time setup is described in [first-run.md](first-run.md); server commands are in
[operator-guide.md](operator-guide.md).

## Users and roles

Alice has three roles:

| Role | Can do | Cannot do |
|---|---|---|
| Administrator | Everything: users, settings, audit log, API tokens of other people | — |
| Operator | View inventory; run discovery, deploy certificates and add or remove SSH keys (from later releases); own API tokens | Manage users, see the audit log, change settings |
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
current sessions immediately. Disabling a person also revokes all their API tokens; enabling the account again
does not bring the tokens back.

Alice never lets you remove the last enabled local administrator (disable or change role). This keeps a
break-glass account available.

### If an account may be compromised

1. **Disable** the account. This ends its sessions and revokes its API tokens at once.
2. Open **Audit log** and check the entries that show the person in the **User** column (use **Load more** for
   older entries, or **Export JSON** and search the file).
3. Before enabling it again, **Set a new password** and **Reset two-factor sign-in**, and give the new password
   to the person through a separate channel.

A role change, a password reset or an MFA reset on its own ends the sessions but does **not** revoke API tokens:
a token keeps working with the person's current role. Disable the account (or revoke the tokens) whenever the
person or their scripts should lose access.

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
  the audit log. Use the JSON export to re-check the chain outside Alice: the CSV export protects spreadsheet
  users by prefixing cells that start with `=`, `+`, `-` or `@` with an apostrophe, so its cells are not always
  the original values (see [operator-guide.md](operator-guide.md#checking-an-audit-export-outside-alice)).
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
  updates when they finish. Alice also scans every connected server once a day on its own. A server that cannot be
  reached or refused Alice's key is not tried again automatically: fix the cause, then choose **Test connection**.
- **Server identity changed**: Alice stopped all work on the server because its host key is different from the
  one you confirmed. Only an administrator can accept the new fingerprint, after checking it on the server, with a
  reason and a recent authenticator code. Everything is recorded in the audit log, and administrators with an email
  address get one email when it happens. The same email goes out once when a server refuses Alice's key.
- **Remove server** (administrators) makes Alice forget the server and frees its license slot. Nothing is changed on
  the server.
- **Waiting for an administrator** lists work that was paused while the license had expired (for example a key
  removal). After a new license is installed, an administrator chooses **Run now** or **Discard** for each item;
  nothing starts on its own (R29).

## SSH keys

**SSH keys** lists every public key Alice found, once per key, with the number of servers and places where it is
used. Filter by **Search** (fingerprint, comment or key type), **Server**, **User** or **Finding** (weak key, runs a
fixed command, root key without a source address limit, listed more than once, certificate authority, hardware
security key). **Show keys that are no longer found** also lists keys that disappeared since the last scan; Alice
never deletes them from its records.

Open a key to see **Where this key is used**: server, user, file, line, options, last seen and state.
Administrators and operators can remove a key from one place with **Remove key** (on the server's page and on the
key's page). Alice removes only that key's lines from that file. It refuses to remove its own key ("Alice needs this
key to connect to this server and will not remove it."), refuses the last key of `root` in a file unless an
administrator ticks "This is the last key of the root account. Remove it anyway.", and refuses changes on servers
that get their keys from a program (`AuthorizedKeysCommand`) or whose SSH settings the last scan could not read.
Every refusal that protects access is recorded in the audit log. Generating, deploying and rotating keys arrive in a
later release.

## License

**License** (administrators and auditors) shows the Installation ID with **Copy**, the state ("Evaluation",
"Evaluation ended", "Active", "Expired, grace period" or "Expired, locked"), "Valid until <date>, N targets", how many targets
are in use, a license that starts later, the uploaded licenses and the history. Administrators upload a license
under **Upload a license**: **Check the file**, read **Confirm the license**, then **Install license** (a new
6-digit code may be asked first). Every upload, refused or accepted, is recorded in the audit log. The full guide,
including what lock mode does and how clock changes are handled, is [licensing.md](licensing.md).

License banners appear at the top of every page: the evaluation, the grace period and lock mode for everyone;
warnings 60/30/14/7/1 days before the end, clock problems, damaged license data, a license that starts later and
the target limit for administrators only. Administrators with an email address also get the warnings by email when
the server operator has set up email ([operator-guide.md](operator-guide.md#email)).

## For auditors

Auditors sign in like everyone else (password and authenticator app). They see **Home**, **Servers**, **SSH keys**, **Audit log**,
**License** (read only), **API tokens** and **My account**, and no button that changes anything except their own password, recovery codes,
language and read-only API tokens. On **Audit log** they can filter, **Verify integrity** and export. A read-only
API token lets a script fetch `GET /api/v1/audit` or `GET /api/v1/audit/export?format=json` for regular
collection.
