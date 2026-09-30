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
If they have no recovery codes left, an administrator resets their MFA on **Users**; if the only administrator is
locked out, the server operator runs `alice admin reset-mfa <username>` (see
[operator-guide.md](operator-guide.md)).

## Sign-in protection

After 5 wrong attempts (password or code) in a row, Alice makes the account wait a little longer before each new
attempt (1, 2, 4, 8 and 16 seconds). After 10, the account is blocked for 15 minutes. During the wait the
message stays "Incorrect username or password." even for the right password, so an attacker learns nothing.
The count starts again only after a complete sign-in (password and code); a correct password on its own does not
reset it. **Set a new password** clears the block at once.
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
  were removed. Syslog forwarding and a daily automatic check arrive in a later release.

## For auditors

Auditors sign in like everyone else (password and authenticator app). They see **Home**, **Audit log**,
**API tokens** and **My account**, and no button that changes anything except their own password, recovery codes,
language and read-only API tokens. On **Audit log** they can filter, **Verify integrity** and export. A read-only
API token lets a script fetch `GET /api/v1/audit` or `GET /api/v1/audit/export?format=json` for regular
collection.
