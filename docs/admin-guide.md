# Administrator Guide

This guide covers day-to-day administration. First-time setup is described in [first-run.md](first-run.md); server
commands are in [operator-guide.md](operator-guide.md).

## Users and roles

Alice has three roles:

| Role | Can do | Cannot do |
|---|---|---|
| Administrator | Everything: users, **Settings** (mail server, recipients, alerts, general, single sign-on), audit log, API tokens of other people, a website's verification settings, deploying a certificate with an incomplete chain; Key Vaults: adding a vault, its credentials and check interval, automatic deployment, held versions, imports into a vault; SSH keys: downloading a private key, rotation policies and runs; certificate authorities: adding them, their accounts and DNS hooks, choosing which certificates Alice gets (**Get a certificate**), switching automatic renewal and automatic deployment on, **Renew now**, **Release** | — |
| Operator | View inventory; test servers, run discovery and remove SSH keys; generate SSH keys and deploy them; upload certificates, create signing requests and deploy certificates; check a Key Vault, connect its certificates to websites and deploy a version that is not held; for certificates from a certificate authority: **Test run**, **Order now**, **Deploy now**, connecting and removing websites, switching automatic deployment off; own API tokens | Manage users, see the audit log, change settings or verification settings, deploy an incomplete chain, manage Key Vaults beyond that, download a private key, manage rotations, add certificate authorities or names to be certified, switch automatic deployment on |
| Auditor | View inventory read-only, view and export the audit log, verify its integrity; own read-only API tokens | Change anything, manage users |

The full list of which role may call which API operation is in [authz-matrix.md](authz-matrix.md).

### Add a person

1. Open **People & access** and choose **Add user**.
2. Enter the username, full name, optional email, **Role** and an **Initial password** (at least 12 characters).
3. Choose **Create user**. If you have not confirmed your identity in the last five minutes, Alice asks for a
   6-digit code (**Confirm it's you**).
4. Give the person their username and initial password through a separate channel. At their first sign-in they
   scan a QR code with their authenticator app and save their own recovery codes. Alice does not force them to
   change the initial password; ask them to do so on **Your account** (**Change password**).

Expected: the person appears in the **People** table; its **Sign-in method** column shows **Local account** with
"Authenticator app not set up yet" until their first sign-in.

Usernames use the letters A–Z, digits, dot, underscore and dash (2 to 64 characters) and must start with a letter
or digit. They are compared without
regard to case ("Admin" and "admin" are the same account). Letters such as "İ" or "ş" are refused so nobody can
create a lookalike account; full names may use any letters.

### Change a role, disable a person, reset their MFA or password

Open **People & access**, choose **Manage** on the person's row and choose the action: **Edit** (name, email, role),
**Reset two-factor sign-in**, **Set a new password**, **Sign out everywhere**, **Disable** or **Enable**. Every
one of these asks for a fresh 6-digit code if you have not confirmed your identity in the last five minutes.

Changing a role, disabling a person, resetting their MFA or password, and **Sign out everywhere** end all their
current sessions immediately. **Set a new password**, **Sign out everywhere** and **Disable** also revoke all their
API tokens (the dialogs say so); enabling the account again does not bring the tokens back. A token is refused from
its next request on; a task a token or session already queued still runs. A role change and **Reset two-factor
sign-in** keep the tokens (they follow the new role), and so does a person's own password change on **Your account**.
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

Then open **Audit trail** and check the entries that show the person in the **User** column (use **Load more** for
older entries, or **Export JSON** and search the file); **Details** of an entry shows what it changed.

**Reset two-factor sign-in** and a role change on their own end the sessions but do **not** revoke API tokens: a
token keeps working with the person's current role. Only **Set a new password**, **Sign out everywhere** and
**Disable** revoke them; the person's scripts then need new tokens.

## Multi-factor authentication and recovery codes

Every local account must use an authenticator app. Each code works once. If a person loses their phone they sign
in with one of their recovery codes (each works once) and then create new recovery codes on **Your account**
(**Create new recovery codes**; the old codes stop working).
If they have no recovery codes left, an administrator resets their MFA on **People & access**; if the only administrator has
lost both the authenticator and the recovery codes, the server operator runs `alice admin reset-mfa <username>`
(see [operator-guide.md](operator-guide.md)). Resetting MFA does not end a sign-in block; see below.

## Sign-in protection

After 5 wrong attempts (password or code) in a row, Alice makes the account wait a little longer before each new
attempt (1, 2, 4, 8 and 16 seconds). After 10, the account is blocked for 15 minutes. During the wait the
message stays "Incorrect username or password." even for the right password, so an attacker learns nothing.
The count starts again only after a complete sign-in (password and code); a correct password on its own does not
reset it. Because the count is still 10 or more when a block ends, one more wrong attempt starts a new 15-minute
block. **Set a new password** on **People & access** clears the block at once (not for single sign-on users, who sign in at their
identity provider and are never blocked by Alice). If the blocked account is the only
administrator (so nobody can open **People & access**), the server operator runs `alice admin unlock <username>` (see
[operator-guide.md](operator-guide.md)): it sets the count back to zero and ends the block, and is recorded in the
audit log (`user.unlocked`, actor `cli`).
Every sign-in, failure and block is in the audit log (`auth.lockout`). Each block also sends one e-mail, "Sign-in
blocked: <username>", to the alert recipients ([Recipients](#recipients)).

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

## Appearance

Each person chooses how Alice looks on **Your account**, in the appearance panel (**A workspace that feels right**):
the **Color mode** **Light**, **Dark** or **System** (follows the computer's setting; the default) and **Compact
tables** (shorter table rows, to see more at once). The
moon/sun button in the top bar switches between light and dark directly. Both choices stay on that computer and
browser (in its local storage), not in the account: another computer starts with the system setting. The language
is different: it belongs to the account and follows the person to every browser. Choose it in the same panel
(**Language**) or with the **TR**/**EN** button in the top bar.

## API tokens

**API tokens** lets each person create tokens for scripts. Choose a **Name**, the **Access** (**Read only** or
**Read and operate**; auditors can only create read-only tokens) and how many days the token is valid (at most
365). Creating a token asks for a fresh 6-digit code if you have not confirmed your identity in the last five
minutes. The token is shown once; copy it immediately. Scripts send it as `Authorization: Bearer alice_…`.
A token never has more rights than its owner's current role, and tokens cannot manage users, settings or tokens.
Revoking a token stops it at once. People who sign in through single sign-on cannot create tokens
([Single sign-on](#roles-sso-users-may-be-admin-and-sso-users)).

Administrators can list and revoke anyone's tokens through the API: `GET /api/v1/tokens?user_id=<id>` and
`DELETE /api/v1/tokens/<token id>`, from a signed-in browser session. The **API tokens** page shows your own
tokens.

The API is described in `api/openapi.yaml` in the Alice source (every operation, its request and response
fields and the permission it needs); [api.md](api.md) explains tokens, errors, paging and gives `curl` examples.
Tokens never reach backups or any action that asks for **Confirm it's you**.

## Audit trail

**Audit trail** (administrators and auditors) lists every sign-in, failure, denied request and change, newest
first. Each entry is linked to the previous one with a SHA-256 hash, so changing or deleting an entry breaks the
chain.

- **Verify integrity** checks the whole chain. Expected: "The audit log is intact." with "Hash chain verified through
  entry #N.". If it reports "Audit log integrity problem at entry N", keep a copy of the database and of an export,
  and contact your security team. The result also says what the check proves: the chain is continuous, which is not
  independent proof against someone who controls the server; forwarding adds that ([Audit forwarding](#audit-forwarding)).
- **Export CSV** / **Export JSON** download the whole log with its verification result, never only the entries the
  filters show. Exports are recorded in
  the audit log. The CSV file's first line carries the result (`# alice audit export: intact=true …`); the column
  names are on line 2. Use the JSON export to re-check the chain outside Alice: the CSV export protects spreadsheet
  users by prefixing cells that start with `=`, `+`, `-` or `@` with an apostrophe, so its cells are not always
  the original values (see [operator-guide.md](operator-guide.md#checking-an-audit-export-outside-alice)).
- Alice runs one check or export of the audit log at a time. If someone else's is running, **Verify integrity**
  answers "Alice is already checking or exporting the audit log." and an export download fails: wait until the other
  one has finished and try again. Such refusals are recorded too ("Audit log export refused: another check or export
  was running").
- **Action starts with** and **Result**, then **Apply filters**, narrow the list. The **User** column shows the
  person (and the address they came from); the **Object** column names what an entry is about, and **Details** opens
  its recorded values. The page loads the newest entries first; **Load more** adds older ones.
- Repeated refusals are recorded once per 10 minutes. When the same person is refused the same thing on the same
  page or API operation again within 10 minutes (permission denied, or blocked by the license), Alice writes no new
  entry; when the 10 minutes end it adds one entry whose details say how many more refusals like it there were and
  between which times, and from how many addresses (and, where it applies, for how many objects or API tokens).
  All sessions of a person count together, and all API tokens of a person count together.
- After verification Alice shows the **Fingerprint of the latest entry**. Record it somewhere outside Alice (for
  example in a ticket) from time to time: a later fingerprint that does not continue from it shows that entries
  were removed. The **Overview** shows the latest verified entry's hash too (**Assurance → Audit integrity**,
  **Head hash**). To keep a copy
  outside Alice as it is written, forward the log to your syslog server or SIEM ([Audit forwarding](#audit-forwarding)).
- Alice also checks the whole chain once a day on its own (recorded as `audit.verified` by `scheduler`). If the
  check finds a problem, the alert recipients get one email about it and the **Overview** shows it under **Needs
  attention**.

## Overview

**Overview** is the first page after sign-in (it was called **Dashboard** before). Everyone sees it; what each part
shows depends on the role. It reads its numbers again every minute; **Refresh** reads them at once. The line beside
the tabs says which Alice version answered and when the numbers were made (**Updated …**). Every count that is a
link opens the list it counts, and that list shows exactly that many rows.

Four numbers sit at the top: **Monitored certificates** (the certificates in use, with how many expire within 30 days,
expired included; opens **Certificates** with that filter), **Managed targets** (servers and Key Vaults, with how many
need review: **Server identity changed**, **Sign-in refused**, **Cannot be reached**, **Partly working** or **Waiting
for fingerprint confirmation**; opens **Servers**), **Key rotations** (rotations in progress; opens **Key rotations**)
and **Needs attention** (the number of entries in the list of that name below).

The page has two tabs. **Operations** is for everyone:

- **Expiration horizon**: four bars, **Expired**, **1–7 days**, **8–30 days** and **31–60 days**; each certificate is
  in exactly one bar. **7d**, **30d** and **60d** choose the window of the large number ("expiring within 30 days,
  expired included"), with **N already expired** beside it. Below the bars are the links **Expired**, **Within 7
  days**, **Within 30 days** and **Within 60 days**. These windows include each other and the expired ones, as the
  **Expiry** filter of **Certificates** does ("Within 30 days" also counts the expired certificates and those within
  7 days). They count every certificate in the inventory, also uploaded ones that are on no server. **Certificates in
  use: N** counts the certificates found on at least one server Alice manages: only those get expiry e-mails (see
  [Alerts and e-mail](#alerts-and-e-mail)). **Key Vault keys and secrets expiring within 30 days: N** counts the keys
  of your vaults and the client secrets Alice signs in to vaults with, expired ones included; Key Vault certificates
  are counted with the certificates.
- **Needs attention**: servers with **Server identity changed** or **Sign-in refused**, failed deployments, for
  administrators and auditors a broken audit chain, and for administrators failing e-mail delivery. Each entry links
  to the page where you deal with it; **N open** is the number of entries.
- **Upcoming renewals**: the 10 soonest of everything in use that expires within 30 days (certificates on servers,
  Key Vault certificates, keys and client secrets), with the server or vault; expired ones come first and are marked
  **Expired**. **View all** opens **Certificates** with the 30-day filter.
- **Target connectivity**: how many servers and vaults are **Connected** out of all of them, a bar with one part per
  state, and a link per state.
- **Failed deployments (last 7 days)**: deployments that failed, were rolled back or could not be rolled back in the
  last 7 days, and every deployment that still needs attention, however old.
- **Key rotation**: policies whose next run is due within 14 days, and how many runs are running or need attention;
  **View rotations** opens **Key rotations**.

**Assurance** is for administrators and auditors (operators do not see this tab):

- **Audit integrity**: **Chain intact** or **Integrity problem**, the entry number the daily integrity check verified
  up to, when it ran (**Last verified**) and the **Head hash**. Write the hash down outside Alice from time to time
  (for example in a ticket): a later head that does not continue from it shows that entries were removed. When the
  last check found a problem, this part says so; open **Audit trail** and choose **Verify integrity**. Administrators
  also see **Forwarding**, a link to **Settings → Audit forwarding**; the Overview does not read the forwarding state.
- **Recovery readiness** (backups): the age of the last successful backup ("3 hours ago"), or **No backup has been
  made yet.**; **The last backup failed. Alice e-mailed the administrators.** when the last one failed; **No
  successful backup for 48 hours** in red after 48 hours without a successful backup. **Restore drill** says "Not
  established by a backup checksum": a backup that checks out is not yet a restore that worked; run the
  [disaster-recovery drill](backup-restore.md#disaster-recovery-drill). **Open the backups** (administrators) leads to **Settings → Backups**
  ([Backups](#backups)).
- **License**: its state and **Valid until**. Operators see the license only through the banners at the top of every
  page.
- **Evidence trail**: the 5 newest audit entries; **Open audit trail** opens the whole list.

- **Finish setting up** (administrators, until every item is done): **Set the recovery passphrase** and **Install
  your HTTPS certificate** (both marked **Required**), **Set up the mail server**, **Add a license** and **Add your
  first server**. These are the steps the setup wizard lets you skip or postpone; each turns **Done** when it is
  finished (the HTTPS item when the certificate in use is no longer Alice's temporary one, the mail item when mail
  settings are saved, the license item when a license is installed), and the list disappears when all are done.

Administrators also see the banner **E-mails could not be sent** at the top of every page while e-mail delivery is
failing (see [Alerts and e-mail](#alerts-and-e-mail)), and the red banner **No successful backup for 48 hours**
while no backup has succeeded for 48 hours (it links to **Settings → Backups**).

## Alerts and e-mail

### What Alice alerts about

Every 15 minutes (the background task `alerts.scan`, which also runs while the license is expired) Alice checks what
expires and e-mails the recipients:

| Kind | Monitored while |
|---|---|
| Certificate in use | It is found at a place that still exists on a server Alice manages |
| Key Vault certificate | It is enabled and still in the vault, unless its current version is a certificate in use on a server (the certificate e-mail covers it then) |
| Key Vault key | It is enabled, still in the vault and has an expiry date |
| Client secret of a vault | Alice signs in to the vault with a client secret; the date is the one typed when the vault was added or its credentials replaced |

By default Alice e-mails 60, 30, 14, 7 and 1 days before the expiry, and once more when it has expired. **Settings →
Alerts** changes the days (**Send an e-mail this many days before an expiry**): 1 to 10 different whole numbers from
1 to 365, with **Add threshold** and **Remove threshold N**; **Save alert thresholds** is disabled while a row is
empty. A change applies from the next check and never sends an e-mail again.

Each threshold is e-mailed once per expiry date, also across restarts and with two Alice processes. When Alice was
not running while several thresholds passed, the next check sends only the most urgent one (for example only the
7-day notice after being down from 31 to 13 days before the expiry), and never a less urgent one after a more urgent
one; a notice skipped that way is never sent later. A renewed certificate (a new expiry date) starts again from the
first threshold; a certificate replaced on its server is no longer in use and gets no further e-mails.

**Not monitored** by this check: certificates you uploaded or completed from a signing request that are on no server
(listed, counted on the Overview, but not e-mailed until deployed), which includes a certificate from a certificate
authority until it is on a server (its renewal e-mails cover it, see
[Certificate authorities (ACME)](#certificate-authorities-acme)); certificates whose places all disappeared or
whose servers were removed; disabled Key Vault certificates and keys, keys without an expiry date, and vaults removed
from Alice. Other conditions keep their own e-mails, each sent once when the condition starts: license warnings (60,
30, 14, 7 and 1 days before the end, see [License](#license)), a changed server identity, a server that refuses
Alice's key, failed deployments, a broken audit chain, stopped tasks and rotation events. The Overview lists them
under **Needs attention**.

**The first check after the upgrade** e-mails every monitored item that has already reached a threshold (only its
most urgent one). In one check Alice sends at most 20 e-mails of each kind; the rest are recorded the same way and
summed up in one e-mail "More expiry notices: N" per kind. Every notice is in the audit log (**Expiry notice
recorded**, `alert.sent`; the summary `alert.summarized`).

**What an expiry e-mail says**: the certificate's name, its expiry time in UTC (for example `2026-10-17 09:00 UTC`;
e-mails do not use the person's time zone), the days left, the websites and servers that use it (up to 10 each) and
its SHA-256 fingerprint; for Key Vault items the vault's name. It never carries a private key, a secret's value or
a password. While the license is expired, every expiry e-mail ends with "Note: Alice's license has expired. Renew it
to resume automatic deployment. License page: …" (Key Vault e-mails also say that Key Vault data may be outdated);
the link is Alice's address from **Settings → General** followed by `/license` (without the address, only
`/license`).

### Recipients

**Settings → Recipients** decides who gets every e-mail Alice sends to administrators: the expiry e-mails above, the
license warnings, the sign-in block e-mail, and the e-mails about deployments, Key Vaults, servers, stopped tasks,
the audit chain, SSH key rotations and certificates from certificate authorities (renewal and automatic deployment).

- **Send alerts to every administrator with an e-mail address** (on by default): every enabled administrator with an
  e-mail address on **People & access**, each in their own language.
- **More addresses** (**Add address**, up to 20): any address, for example a team mailbox, each with a language
  (English or Turkish). Type the plain address (`ops@example.com`), without a name or angle brackets. An address that
  is also an administrator's gets one e-mail.

At least one of the two is needed. **Save recipients** records the change with the addresses in the audit log
("Alert recipients changed"). When a check records notices but nobody would get them (no extra address, and no
enabled administrator with an address), Alice still records them and writes a warning to its log
(`alerts.no_recipients`).

**Sign-in block e-mail**: when a local account is blocked for 15 minutes after 10 wrong attempts, the recipients get
"Sign-in blocked: <username>" with the number of attempts and the minutes (see [Sign-in protection](#sign-in-protection)).

### Delivery and "E-mails could not be sent"

Alice sends queued e-mails every minute, one per recipient. A failed send is tried again after 30 seconds, doubling up
to one hour, until 24 hours after the e-mail was queued; then it is marked failed and Alice logs `notify.gave_up`.
Each recipient is sent to once: when the mail server refuses one address, the others still get their e-mail. Without
mail settings every e-mail is recorded as skipped and never sent later.

After three failed send attempts in a row (any e-mail, any recipient), administrators see **E-mails could not be
sent** on every page, with the last error code (for example `smtp.connect`) and **Open the mail settings**; the
Overview lists it under **Needs attention**. The next successful send ends it. One address the mail server refuses
(`smtp.rejected`) can raise the banner while everyone else gets their e-mails: check **Settings → Recipients**. The
codes are explained under `ALC-NTF-0003` to `ALC-NTF-0009` in [troubleshooting.md](troubleshooting.md).

## Mail server

Open **Settings** (administrators only; Alice asks for the authenticator code when you open it, or sends single
sign-on administrators to their identity provider, see [Single sign-on](#single-sign-on)) → **Email**:

| Field | Meaning |
|---|---|
| **Mail server**, **Port** | The SMTP server's name or address and port; an IPv6 address without brackets (`2001:db8::25`) |
| **Encryption** | **STARTTLS (upgrades an open connection)**, usually port 587, or **TLS (encrypted from the start)**, usually port 465. Alice always encrypts, with TLS 1.2 or newer; there is no unencrypted option |
| **Sender address** | For example `alice@example.com` |
| **User name (optional)**, **Password** | The mail server account. A user name needs a password; without a user name Alice does not sign in to the server |
| **Certificate authority (optional, PEM)** | Your organisation's certificate authority, if the mail server's certificate comes from one (up to 20 certificates, 64 KiB) |

Choose **Save mail settings**. The password is stored only encrypted with the master key, never shown again and
never returned by the API; afterwards the field is empty and says "A password is stored. Leave the field empty to keep
it; a new host or port needs the password again." Changing **Mail server** or **Port** without typing the password
again is refused on the password field: Alice never sends a stored password to a new destination. Every change is in the audit log (**Mail settings changed**; the password never).

**Send test e-mail** sends a test to the address in **Send the test to** (yours by default) through the **saved**
settings, so save first. Expected: "The test e-mail was sent to <address>." and the e-mail "Alice test e-mail"
arrives. Each test is in the audit log (**Test e-mail sent**, with the result); each person can send 5 a minute.

**Trusting a certificate.** When the mail server's certificate is not signed by an authority Alice trusts (the system's
or the one you entered), the test stops before anything is sent and shows **The mail server's certificate is not
trusted** with its **Fingerprint (SHA-256)**, **Certificate subject** and **Valid until**. Ask the mail server's
administrator for the fingerprint, or read it yourself, for example with `openssl s_client -connect <server>:587
-starttls smtp </dev/null | openssl x509 -noout -fingerprint -sha256`, and compare every character. Then choose
**Trust this certificate**: Alice pins exactly that certificate for this server and port and accepts it from then on
("Trusted certificate: <fingerprint>"). Only a certificate a test showed in the last hour can be trusted, and only
once. Changing the server name or port removes the pin. When the server gets a new certificate (also a renewed
self-signed one), the e-mails fail with `smtp.untrusted` until you send a test and trust the new one; entering the
certificate authority instead avoids that. **Stop trusting this certificate** removes the pin. Both are in the audit
log (**Mail server certificate trusted**, **… no longer trusted**).

Alice connects to the mail server's address only when it is not a link-local or cloud metadata address
(`ALC-NTF-0009`); loopback and private addresses are allowed. There is no button to remove the mail settings: an
administrator can call `DELETE /api/v1/settings/smtp` (with a fresh authenticator code), which removes them and the
stored password (**Mail settings removed**); the `ALICE_SMTP_*` variables are then not imported again. How the
settings of earlier versions (`ALICE_SMTP_*`) were taken over is in [operator-guide.md](operator-guide.md#email).

## Backups

**Settings → Backups** (administrators only). Alice makes an encrypted backup of everything every day; this page
shows the backups on the server, makes one at once and sets the schedule. How backups work, how to copy them off the
server and how to restore is in [backup-restore.md](backup-restore.md).

At the top:

- **Last successful backup: <time>**, or **No backup has been made yet.**
- **Free disk space for backups: <size>**. Alice starts a backup only when the free space is at least twice the size
  of the newest backup plus 1 GiB; otherwise the backup fails with `ALC-BAK-0004` (`disk_full`). Copy older manual and
  pre-update backups off the server and delete them there to make room.
- In red, **No successful backup for 48 hours** with "Check the free disk space and the Audit log, then choose Back
  up now.", and **The last backup failed. Alice e-mailed the administrators.** after a failed backup.
- Before the recovery passphrase is set: **Backups start after the recovery passphrase is set.**
- **Backups are stored on this server only. Copy them to another machine regularly.** and **Restoring is done on
  the server with alicectl restore.** There is no restore button, by design: a restore replaces all data and the
  encryption key, so it is a deliberate action of the operator on the server.

**Backup files on this server** lists every file, newest first: **File**, **Kind** (**Daily**, **Manual**,
**Before a restore**, **Before the update to <version>**), **Size**, **Made at** and **Check**:

| Check | Meaning |
|---|---|
| **Checked** | The header, the size and the checksum file agree. |
| **Checksum file missing** | The `.sha256` file is not there (for example a file copied in by hand without it). The operator can still check it with the passphrase (`alicectl backup verify --deep`). |
| **Damaged: the checksum does not match** | The file changed after it was written. Do not rely on it. |
| **Not a readable backup file** | The file is not an Alice backup, or its header is damaged. |
| **Alice cannot read this file: permission denied** / **…: read error** | The file's owner or mode on the server, or a disk error. |

**Back up now** makes a manual backup at once ("Backup made: <name>"); manual backups are never deleted
automatically. Alice makes one backup at a time: while another one runs, the button is refused with `ALC-BAK-0001`.
**Download** saves one file to your computer. It is recorded in the audit log (**Backup downloaded**) before the
first byte is sent. Each person can start 5 downloads a minute (backup and SSH private-key downloads count
together); **Back up now** is limited to 5 a minute per person too. The file is encrypted: it is useless without the recovery
passphrase, but treat it as confidential.

**Confirming your identity.** Opening **Settings**, **Back up now** and **Download** need a confirmation from the last
5 minutes: a fresh 6-digit code (**Confirm it's you**), or for a single sign-on administrator a fresh sign-in at the
identity provider. API tokens can never list, make or download backups.

**Daily backup** sets the schedule:

| Field | Meaning |
|---|---|
| **Daily backup time** | 24-hour clock, for example 02:30 (the default). |
| **Time zone** | The zone of that time; by default the server's time zone at installation. |
| **Automatic backups to keep** | From 7 to 60 (default 14). Older daily backups are deleted after each new one (**Old backup deleted** in the audit log). Manual backups and backups made before an update or a restore are never deleted. |

The page shows **Next backup: <time>**. Choose **Save backup schedule**; the change is recorded as **Backup schedule
changed**. If someone else saved the schedule meanwhile, Alice refuses the save (`ALC-SYS-0008`): reload and try
again. A backup missed while the server was off is made as soon as Alice runs again.

When a daily backup fails, the administrators get the e-mail "Alice could not make its daily backup" with the error
code; after 48 hours without a successful backup they get "Alice has had no successful backup for 48 hours" (the mail
server must be set up, [Mail server](#mail-server)).

## HTTPS certificate

**Settings → HTTPS certificate** (administrators only) shows the **Certificate in use**: its **Subject**, **Names**,
**Valid until** and **Fingerprint (SHA-256)**, and either **Alice is using your own certificate.** or **Alice is using
a temporary certificate. Browsers will warn until you upload your own.**

The installer created the temporary certificate. Alice renews it by itself when it is within 7 days of its end
(**Temporary HTTPS certificate renewed** in the audit log). Alice never renews your own certificate: upload the new
one before the old one expires.

To install or replace your certificate:

1. Under **Upload certificate** choose the **File format**:
   - **PEM: a certificate file and a key file**: the **Certificate file (PEM)** with the certificate followed by the
     intermediate certificates, and the **Private key file (PEM)**, unencrypted;
   - **PFX (PKCS#12): one file with a password**: the **PFX file** and its **PFX password**.
2. Choose **Upload certificate**.

Expected: **The new certificate is in use.** Alice uses it at once, without a restart; open connections keep the
old one until they close. The private key never leaves the server and is never shown again. The replacement is
recorded as **HTTPS certificate replaced**.

Alice refuses a certificate whose key does not match (`ALC-TLS-0001`), that is not valid now or for less than one
more day (`ALC-TLS-0002`), whose key is not RSA of at least 2,048 bits or ECDSA P-256/P-384 (`ALC-TLS-0003`), a PFX
with a wrong password (`ALC-TLS-0004`), or a file it cannot read (`ALC-TLS-0005`). The certificate in use then stays.
An accepted certificate may come with **The certificate is in use. Check these points:**

- **None of the names in the certificate matches the address of this Alice server, so browsers will warn.**
- **The chain to a trusted authority is incomplete. Add the intermediate certificates to the certificate file.**
- **The certificate expires within 30 days.**

Fix these with a new upload. The certificate is part of every backup.

## Audit forwarding

**Settings → Audit forwarding** (administrators only) sends every audit log entry, in order, to your syslog server or
SIEM, so a copy of the log exists outside Alice as soon as it is written.

| Field | Meaning |
|---|---|
| **Forward the audit log** | Switches forwarding on or off. |
| **Syslog server**, **Port** | The receiver's name or address and port (default 6514, the syslog-over-TLS port). |
| **Protocol** | **TLS (encrypted, recommended)**; **TCP (not encrypted)**; **UDP (not encrypted; messages can be lost)**. |
| **Certificate authority of the syslog server (PEM, optional)** | The authority that issued the receiver's certificate, when it is not one the system trusts. It is stored and never shown again (**A CA certificate is set**); leave the field empty to keep it, paste another one to replace it, or tick **Remove the stored CA certificate** and save to remove it. |

Choose **Save forwarding settings** (recorded as **Audit forwarding settings changed**), then **Send test message**.
Expected: **The test message was sent.** With TLS, the receiver's certificate must verify against the system's
authorities plus the CA entered, and must name the host you entered. Alice never connects to link-local or metadata
addresses (`ALC-AUD-0002`). An unreachable receiver is `ALC-AUD-0003`, an untrusted certificate `ALC-AUD-0004`
([troubleshooting.md](troubleshooting.md#alc-aud-0003-alice-could-not-reach-the-syslog-receiver)).

**Delivery** shows **Last entry sent: <time>**, **Number of the last entry sent: <seq>**, **Entries waiting to be sent:
<count>** (the backlog) and the **Last problem** with its time. Alice sends up to 500 entries every 15 seconds. When
the receiver cannot be reached, nothing is lost locally: the entries stay in Alice's audit log, the backlog grows, and
forwarding continues from the same entry once the receiver answers. Forwarding never slows down or blocks Alice's own
recording. Watch the backlog: a backlog that keeps growing means the receiver has not been getting entries.

**Message format.** One RFC 5424 message per entry (octet-counted framing over TCP and TLS, one datagram over UDP, at
most 8 KiB; long details are cut to fit), facility `auth`, severity `notice` for a success, `warning` for a failure or
a refusal, and `critical` for a failed integrity check:

```
<PRI>1 <time> <host> alice - <action> [alice@32473 seq="<seq>" hash="<hex>" prev_hash="<hex>" actor="<actor>" result="<result>"] <JSON of the object and details>
```

The daily integrity check's checkpoint is sent too, once per new checkpoint, as action `audit.checkpoint` with its
sequence number and hash.

**Delivery is at most once.** Alice moves on when a message was handed to the network; a connection that breaks
afterwards can lose messages that the receiver never saw. Each message carries its sequence number (`seq`) and the
previous entry's hash (`prev_hash`), so the receiver can see a gap: `seq` must grow by exactly one, and each
`prev_hash` must equal the `hash` of the message before. Set up an alert on a gap in `seq` at the receiver, and fetch
the missing entries from Alice's JSON export ([api.md](api.md#examples)). After a restore from a backup the receiver
gets entries again, then `system.restored` under a sequence number it already holds: a second, visible branch
([backup-restore.md](backup-restore.md#restore-on-the-same-server)).

**What the receiver can check.** The forwarded stream lets the receiver check that the entries link up (`seq` and
`prev_hash`) and keep the hashes outside Alice. It cannot recompute an entry's `hash` from the message: the hash also
covers fields the message does not carry (the actor's ID and type, the client address and the request ID), and long
details or actor names are cut to fit the message. To prove that an entry's
content matches its hash, compare the forwarded `hash` with Alice's JSON export of that entry, which carries every
field, and run **Verify integrity** (`alicectl audit verify`).

**Example receiver: rsyslog with TLS.** On the syslog server (rsyslog 8 with the GnuTLS driver, package
`rsyslog-gnutls`), with a certificate for the name you enter as **Syslog server**, for example in
`/etc/rsyslog.d/alice.conf`:

```
global(
  DefaultNetstreamDriver="gtls"
  DefaultNetstreamDriverCAFile="/etc/rsyslog-tls/ca.pem"
  DefaultNetstreamDriverCertFile="/etc/rsyslog-tls/syslog.example.com.pem"
  DefaultNetstreamDriverKeyFile="/etc/rsyslog-tls/syslog.example.com-key.pem"
)
module(load="imtcp" StreamDriver.Name="gtls" StreamDriver.Mode="1" StreamDriver.AuthMode="anon")
template(name="aliceRaw" type="string" string="%rawmsg%\n")
ruleset(name="aliceAudit") {
  action(type="omfile" file="/var/log/alice-audit.log" template="aliceRaw")
}
input(type="imtcp" port="6514" ruleset="aliceAudit")
```

Restart rsyslog, open TCP 6514 on the syslog server for the Alice server's address only (Alice does not present a
client certificate, hence `AuthMode="anon"`), then choose **Send test message** in Alice. This example is a starting
point; the vendor's tests use their own test receiver, not rsyslog.

## Single sign-on

Alice supports single sign-on (SSO) with OpenID Connect identity providers, for example Microsoft Entra ID, AD FS and
Keycloak. People choose **Sign in with <name>** on the sign-in page; the local sign-in form (password and
authenticator code) stays on the same page.

### Setting up a provider

1. **Settings → General**: enter **Alice's address**, the `https://` address people use to open Alice (for example
   `https://alice.example.com`, no path), and choose **Save general settings**. The identity provider sends people
   back to it; a provider cannot be switched on without it (`ALC-SSO-0004`).
2. Register Alice at the identity provider (see the sections below). You need the issuer address, a client ID and a
   client secret.
3. **Settings → Single sign-on → Add identity provider**: **Name shown on the sign-in page**, **Issuer address**,
   **Client ID**, **Client secret**, **Groups claim** (the claim that carries the groups, `groups` by default),
   **Certificate authority (optional, PEM)** when the provider's certificate comes from your own authority, and
   **Allow sign-in with this provider** (off by default). Choose **Save identity provider**. Alice reads the
   provider's discovery document and keys at once: the issuer must be an `https://` address and the document must
   name exactly that issuer; otherwise nothing is saved (`ALC-SSO-0001`, with the cause).
4. The dialog shows "Redirect address to register at the provider: …" with **Copy**, for example
   `https://alice.example.com/api/v1/auth/oidc/<id>/callback`. Register exactly this address at the provider, then
   choose **Continue**.
5. **Map group**: enter a **Group** value exactly as the provider sends it (upper and lower case count), choose its
   **Role in Alice**, and add it. Without a mapping nobody can sign in through the provider.
6. Switch **Allow sign-in with this provider** on (**Edit <name>**). Sign in through it in a private browser window
   to check.

Alice keeps the provider's addresses from the time it read them. When the provider moves its endpoints or keys
address, choose **Read the provider's settings again**. The client secret is stored only encrypted with the master
key; edit the provider to replace it (an empty field keeps it; a new **Issuer address** needs the client secret
again, so a stored secret is never sent to another provider). Alice sends the secret in the `Authorization` header
(`client_secret_basic`), asks for the scopes `openid profile email`, follows no redirects and accepts tokens signed
with RS256, ES256 or PS256 only. At most 5 providers, and at most 200 mappings per provider. A provider through which
people have signed in cannot be deleted (`ALC-SSO-0005`) and its issuer cannot be changed: switch it off instead.
Every change is in the audit log (**Identity provider added**, **changed**, **settings read again**, **deleted**,
**Group mapping added**, **removed**, **refused**).

### Microsoft Entra ID

- **Issuer address**: `https://login.microsoftonline.com/<tenant ID>/v2.0`.
- In the Microsoft Entra admin center, **App registrations → New registration**, platform **Web**, redirect URI =
  Alice's redirect address. Under **Certificates & secrets** create a client secret (note its expiry: renew it and
  edit the provider in Alice before it expires). The **Application (client) ID** is the client ID.
- **Token configuration → Add groups claim**: Entra ID sends the groups as **object IDs** (for example
  `5b2f…-…`) in the claim `groups`. Map the object IDs, not the display names.
- **Too many groups**: Entra ID leaves the groups out of the token when a person is in more than 200 groups and sends
  only a marker. Alice does not ask Microsoft Graph for them: such a person is refused with "Your identity provider
  did not send your groups" (`ALC-SSO-0007`). Choose **Groups assigned to the application** in the groups claim and
  assign the groups that should use Alice to the application (**Enterprise applications → Users and groups**), so the
  token carries only those.

### AD FS

- **Issuer address**: `https://<AD FS host>/adfs`.
- Add an application group with a server application (confidential, with a generated shared secret: the client
  secret) whose redirect URI is Alice's redirect address, and allow the scopes `openid`, `profile` and `email`.
- Send the groups with an issuance transform rule (for example "Send Group Membership as a Claim" or LDAP attribute
  "Token-Groups"). AD FS names the claim `group` or `http://schemas.xmlsoap.org/claims/Group`: enter the name your
  rule produces as **Groups claim** in Alice, and map the values it sends.
- AD FS certificates often come from your own authority: paste it into **Certificate authority (optional, PEM)**.
  Alice refuses provider endpoints whose address carries a query (`?…`); AD FS's standard endpoints have none.

### Keycloak

- **Issuer address**: `https://<Keycloak host>/realms/<realm>`.
- Create an OpenID Connect client with **Client authentication** on and the standard flow, and set **Valid redirect
  URIs** to Alice's redirect address. The client secret is on its **Credentials** tab.
- Add a **Group Membership** mapper with the token claim name `groups` to the client (or a client scope it uses).
  With **Full group path** on, the values are paths such as `/alice-operators`: map them that way.

### Roles, "SSO users may be Admin" and SSO users

A person gets the highest role any of their groups is mapped to. Nobody gets a role by default: a person in no mapped
group is refused ("Your account has no access to Alice, contact your administrator", `ALC-SSO-0006`).

**SSO users may be Admin** is off by default. While it is off, mapping a group to Administrator is refused ("A group
cannot be mapped to Administrator.", `ALC-SSO-0002`) and nobody becomes an Administrator through single sign-on.
Switching it on needs nothing else. Switching it off is refused while a group is mapped to Administrator
(`ALC-SSO-0003`); otherwise it asks **Switch off SSO users may be Admin?** and then every SSO user who is an
Administrator loses the role at once and is signed out. They become **Auditors** (the confirmation says so);
at their next single sign-on they get the role their groups map to. Switching the setting on again
gives no role back.

An **SSO user** is created at their first single sign-on ("User created by single sign-on"). Their user name comes
from the provider (`preferred_username`, `upn` or e-mail, letters folded to lower case; a taken name gets `-2`,
`-3`, …); without one it is `sso-` and 12 characters. Alice recognises them by the provider and the provider's subject
identifier, never by e-mail, and never joins them to a local account: a first single sign-on whose e-mail belongs to
a local user is refused (`ALC-SSO-0008`), and so is a later one whose e-mail changed to a local user's.

On **People & access**, SSO users carry the badge **Single sign-on** in the **Sign-in method** column, with their
provider's name and **At the identity provider**, and there is no **Set a new password**, **Reset two-factor sign-in** or role choice: their role comes from their
groups at every single sign-on ("Role updated from the identity provider"), and a change by hand is refused
(`ALC-USR-0003`). **Disable** and **Enable** work as for everyone. SSO users have no password, no authenticator and no
recovery codes in Alice and cannot be the break-glass account; their **Your account** page shows no password form
and no **Create new recovery codes**, and says that their identity provider manages both. **SSO users cannot create API tokens**
(`ALC-USR-0003`): **API tokens** shows them a note instead of **Create token** (they can still revoke tokens), so no
credential Alice issued outlives the person's removal at the identity provider. A script that needs a token uses one
of a local account.

**Group changes at the identity provider** take effect at the person's next single sign-on or confirmation. A person
removed from every mapped group is refused there, and Alice then ends all their sessions. Until then an open session keeps working (at most 30 minutes idle, 12 hours in all; Alice keeps no refresh
tokens). To stop someone at once, choose **Disable** on **People & access**.

### MFA and confirming your identity

A single sign-on opens the 5-minute window for actions that ask **Confirm it's you** only when the provider reports
(`auth_time` in the ID token) that it authenticated the person within the last 5 minutes; the window then ends 5
minutes after that time. A silent sign-in (the person still had a session at the provider), or a provider that sends
no `auth_time`, leaves it closed: the first such action asks to confirm at the identity provider.

Alice does not ask SSO users for an authenticator code: **multi-factor authentication is the identity provider's
job, and requiring it there is the customer's responsibility** (for example Conditional Access in Entra ID, an MFA
policy in AD FS, OTP in Keycloak). Alice does not check that it happened.

Actions that ask a local user for a fresh code (**Confirm it's you**) ask an SSO user to **Confirm at your identity
provider**: **Continue to <name>** sends the browser to the provider with a request for a fresh sign-in
(`prompt=login`, `max_age=0`). Alice accepts the answer only for the same person and a sign-in at most 5 minutes old,
then returns to the page (**Identity confirmed again** in the audit log). A provider that ignores the request and
reports an older sign-in makes the confirmation fail (`ALC-SSO-0010`). The confirmation also reads the groups again:
the role may change, and a person no longer in a mapped group is refused and signed out.

Starting a single sign-on counts against the sign-in limit of 10 a minute per address: behind one company address
(NAT), the 11th person starting a single sign-on within a minute waits ("Too many requests").

### Break-glass

The local administrator created in the setup wizard always signs in with password and authenticator code, also when
every identity provider is down or wrongly configured: keep its password and recovery codes safe and try it from time
to time. Alice never lets you disable or demote the last enabled local administrator, and an SSO user can never take
that place.

### Refused sign-ins

A refused single sign-on brings the person back to the sign-in page with a message, and writes one audit entry
**Single sign-on refused** (`auth.oidc.denied`) with the reason (`no_access`, `groups_overage`, `email_in_use`,
`idp_unreachable`, `login_invalid`, `login_expired`, `user_disabled`, `provider_disabled`, `stepup_other_user`,
`idp_error`); no account is created and no session is opened. A return to Alice that names no sign-in Alice started
(no state, an unknown one, or one already used) is recorded at most once a minute per client address, so a stream
of forged returns cannot fill the audit log. A sign-in must be finished within 10 minutes in the
browser that started it. See "SSO sign-in refused" in [troubleshooting.md](troubleshooting.md#alerts-e-mail-and-single-sign-on).

## Saved views and export

**Certificates** and **SSH keys** keep their filters in the page's address: a bookmark or a link reproduces the list
exactly. **Clear filters** removes them. On **Certificates**, **Expiry** offers **Any date**, **Expired** and
**Within 7**, **14**, **30**, **60** or **90 days** (each including the expired ones), and **Source** also **Key
Vault**.

**Save view** stores the current filters under a **Name of the view** (1 to 60 characters; one name per page, upper
and lower case counting as the same); **Saved views** applies one or deletes it (**Delete view <name>**). Each person
keeps up to 50 views on the two pages together (`ALC-RPT-0002`). Views are private: nobody else sees them, not even
an administrator, and they are not in the audit log.

**Export** downloads exactly the rows the list shows with the current filters (all pages, in the same order) as a
CSV file: `alice-certificates-<date>.csv` or `alice-ssh-keys-<date>.csv`, UTF-8 with a byte order mark, English
column names (certificates: `id`, `subject_cn`, `label`, `sans`, `issuer`, `serial`, `not_before`, `not_after`,
`days_left`, `source`, `key_algorithm`, `key_bits`, `self_signed`, `chain_complete`, `fingerprint`,
`location_count`; SSH keys: `id`, `fingerprint`, `key_type`, `bits`, `comment`, `managed`, `platform_key`, `weak`,
`location_count`, `target_count`, `missing`, `retired`, `first_seen_at`), times in UTC. A cell that starts with `=`,
`+`, `-`, `@`, a tab, a carriage return or a line feed gets a leading apostrophe, so a spreadsheet never runs it as
a formula.

Everyone who can see a list can export it, also read-only API tokens and during a license lock. Each export is
recorded in the audit log (**Inventory exported**, with the filters and the row count) before the first byte is
sent. Limits: at most 50,000 rows (`ALC-RPT-0001`: narrow the filter), one export at a time per person
(`ALC-RPT-0004`) and 10 a minute per person or API token. Scripts call `GET /api/v1/certificates/export` or
`GET /api/v1/ssh-keys/export` with the list's filter parameters (without `cursor` and `limit`).

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
  audit log, and the alert recipients get one email each time a server becomes blocked. The same
  email goes out once when a server refuses Alice's key.
- **Remove server** (administrators) makes Alice forget the server, closes the SSH connections Alice kept open to it
  and frees its license slot. Nothing is changed on the server.
- **Waiting for an administrator** lists work that was paused while the license had expired (for example a key
  removal), and work that changes servers or Key Vaults which a restore brought back from the backup's queue
  ([backup-restore.md](backup-restore.md#restore-on-the-same-server)), 50 at a time (**Show more** for the rest). After a new license is installed, an administrator chooses
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
Every refusal that protects access is recorded in the audit log. Keys Alice generated are marked **Generated by
Alice** and are listed even before they are used anywhere; generating, deploying, downloading and rotating them is
described in [operator-guide.md](operator-guide.md#ssh-keys-and-rotation), and what is for administrators below.

The **SSH keys** list marks a key **No longer found** when every place it was used is gone; open a key to see the
state of each place. The keys of an account deleted from a server are marked **No longer found** when the server's
account list is complete; otherwise, and for an account that got a `nologin` shell or lost its home, the keys stay
listed as they were last seen and cannot be removed through Alice (see
[operator-guide.md](operator-guide.md#keys-of-accounts-alice-no-longer-lists)). A server's page warns when Alice could
not list an account (for example a name with characters Alice does not support): the warning names its user ID, and
`getent passwd <user ID>` on the server shows the account. While such a warning is shown, Alice does not mark keys of
deleted accounts **No longer found** on that server. Key options such as `command=` or
`environment=` are shown exactly as they are in the file, to everyone who can see the key, auditors included.

### Generated keys and rotation

How to generate, deploy, download and rotate keys is in
[operator-guide.md](operator-guide.md#ssh-keys-and-rotation). Who may do what:

| Action | Who |
|---|---|
| **Generate key**, **Deploy to a server** | Administrator or operator, also with an API token with operate access |
| **Download private key** | Administrator in a signed-in browser with a fresh authenticator code; never an API token; at most 5 per minute per person |
| Create, edit, delete and switch off a rotation policy, **Preview next run**, **Stop and undo** | Administrator, also with the administrator's API token with operate access; no authenticator code |
| Switch a policy on, **Run now**, **Continue**, **Finish now**, **Keep the old key on these servers** | Administrator in a signed-in browser with a fresh authenticator code; never an API token |
| Reading keys, policies, runs and a server's key files | Everyone |

While the license does not allow changes, everything above is refused except reading, **Download private key** and
**Stop and undo**. The full list per API route is in [authz-matrix.md](authz-matrix.md). A run's page offers each
person only the decisions that person may make.

**What Alice stores.** For a generated key: the public key, its fingerprint, type and size, the name, the comment
written into `authorized_keys` lines, who generated it, the key it replaced, the download count and time, and the
private key only encrypted with the master key (AES-256-GCM, bound to its row). Alice never stores or logs the private
key in clear, a download passphrase or the downloaded file; the private key is in no API answer other than the
download, in no job, audit entry, rotation record or email. For policies and runs Alice stores the settings, the
previewed plan (public lines only), the state of each place and every step. Every action is in the audit log
(`sshkey.*`, `rotation.*`; for example `sshkey.generated`, `sshkey.deploy_requested`, `sshkey.added`,
`sshkey.add_failed`, `sshkey.private_key_downloaded` with the reason, `sshkey.retired`,
`sshkey.private_key_destroyed`, `rotation.policy_enabled`, `rotation.created`, `rotation.continued`,
`rotation.stop_requested`). A deploy also writes `sshkey.add_sent` right before it sends the key to the server, which
is how Alice later knows whether a line is its own.

**Retired keys.** After a completed rotation the old key is retired once no place uses it. Its private key is
destroyed 30 days after retirement; **Settings → General** changes the days (**Keep the private key of a retired SSH
key for this many days**, 1 to 3650). Until then an administrator can still download it. The
destruction removes the encrypted key from the database, but database backups taken before it still contain it,
encrypted with the master key: keep backups as protected as the master key, and expire them.

**Background tasks.**

| Task | Every | In lock |
|---|---|---|
| `rotation.plan`: creates the planned run of each policy that is on when its notice time is reached, and emails its preview | minute | does not run |
| `rotation.sweep`: starts planned runs whose preview email was delivered, advances every run, pauses runs in lock, emails the renewal notice, queues each place's work again (at most five times) | minute | runs |
| `sshkey.destroy_retired`: destroys private keys retired longer ago than the retention of **Settings → General** (30 days by default; up to 500 per run), retires old keys nothing uses, records the outcome of key deploys whose task ended without one and scans their servers | hour | does not run |

**Emails.** The alert recipients ([Recipients](#recipients); by default every enabled administrator with an email
address) get: the preview of each planned run (and of an
on-demand preview, at most once per key in 10 minutes); "nothing to rotate" once per interval when every place is
skipped; the start of the overlap, one day before its end (overlaps longer than two days) and after **Finish now**;
a decision needed about places Alice cannot test; completed (or completed with places kept); undone; needs
attention; paused for the license; the renewal notice after a pause; a late answer from a server. **Scheduled
rotation needs working email delivery**: a scheduled run starts only after its preview email was accepted by the mail
server for at least one recipient before the planned start, otherwise it is cancelled (`ALC-ROT-0017`). Without
email (see [Mail server](#mail-server)), only **Run now** rotates. Emails name the reason code (for
example `rotation.notice_undelivered`), which [troubleshooting.md](troubleshooting.md) explains.

**After the upgrade** to this version every server refuses key deploys and is skipped by rotations until it has been
scanned again (Alice needs the list of key files of the account it connects with). Each connected server is scanned
once per discovery interval (one day unless it was changed); choose **Scan for SSH keys** on a server (on an Nginx
server, **Discover**) to do it at once.

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

The alert recipients ([Recipients](#recipients)) get these emails when the mail server is set up
([Mail server](#mail-server)):

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
the date typed when it was added), and a client secret's date is also e-mailed at the alert thresholds
([Alerts and e-mail](#alerts-and-e-mail)); after the date the vault shows **Credentials expired** (`ALC-AKV-0002`). When Alice cannot decrypt a vault's stored credentials (it runs with
another master key than the one they were sealed with), a deployment from that vault fails with `ALC-AKV-0041`:
choose **Replace credentials** (a check of the vault or an import shows the generic `ALC-SYS-0003` in that case).

**What Alice stores of a vault.** The address, the sign-in method, the tenant and client IDs, the sealed credential,
the object ID Alice signs in as, and the metadata of certificates, versions, keys and secrets (names, versions,
thumbprints, dates, key types, content types, policies). Alice never stores the value of a secret or a certificate's
private key read from a vault: a deployment reads it right before it changes the server, keeps it in memory and
clears it afterwards. Every read of a certificate's secret is in the audit log (`kv.secret_read`, with its purpose, and for an access
check the person who asked).

**Check interval.** Each vault is checked every 15 minutes unless an administrator changes **Check every
(minutes)** on its page (5 to 1440). **Check now** checks at once.

**Emails.** The alert recipients get, per vault: a sign-in that failed three times in a row; a
certificate that disappeared from the vault; a new version of a connected certificate that automatic deployment
will not deploy (switched off, held for the license or its chain, disabled, expired, not yet valid, older than the
website's certificate, created before automatic deployment was switched on, replaced by a newer version before it
was deployed); automatic deployment of a version stopped after three failures; an import that failed or whose
outcome stays unknown. One check or planner run sends at most 20 emails of one kind per vault, then one summary;
there is no limit across vaults. No email is sent when the vault firewall refuses Alice. Key Vault certificates, keys
and client secrets that are about to expire are e-mailed by the expiry check ([Alerts and e-mail](#alerts-and-e-mail)).
Everything a vault does is in the audit log (`vault.*`, `kv.*`, `binding.*`).

## Certificate authorities (ACME)

Alice can get certificates from a certificate authority that speaks ACME (the protocol of Let's Encrypt, RFC 8555):
a public one such as Let's Encrypt or ZeroSSL, or your company's own (for example step-ca, EJBCA or an ACME
gateway). Alice proves to the authority that you control each name, receives the certificate, renews it before it
expires and, if you want, puts it on your Nginx websites. Putting it on a website is an ordinary deployment, with
the same checks and the same automatic undo as when a person deploys a certificate. Day-to-day use (**Issued
certificates**, Test run, ordering, deploying) is in [operator-guide.md](operator-guide.md#issued-certificates-acme).
This section is the setup, which is for administrators.

| Action | Who |
|---|---|
| Adding, changing and removing certificate authorities and DNS hooks; registering, rotating and deactivating an account | Administrator with a fresh authenticator code; never an API token |
| **Get a certificate** (which names, which authority, how the names are proved), deleting it, its **Automatic renewal**, **Renew now**, **Release** of a held certificate | Administrator with a fresh authenticator code; never an API token |
| Switching **Automatic deployment** on, for the certificate or for a website | Administrator with a fresh authenticator code; never an API token |
| Reading the authority's terms before registering (done by the **Register account** dialog) | Administrator, no new code |
| **Test run**, **Get certificate now** / **Order now**, **Deploy now**, connecting websites (with automatic deployment off), removing websites, switching automatic deployment off | Administrator or operator, also with a **Read and operate** API token |
| Reading authorities, accounts (including their contact e-mail), hooks, certificates, orders and websites | Everyone |

The full list per API route is in [authz-matrix.md](authz-matrix.md). Together, every person and token may start at
most 10 of these actions a minute (orders, Test runs, Deploy now, **Renew now**, changes of a certificate, account
operations, reading the terms); more are refused with `ALC-SYS-0005`.

### What Alice connects to

**Nothing is contacted until you act.** Adding a certificate authority or a DNS hook only stores settings. Alice has
no list of authorities it contacts by itself, no telemetry and no update check. These connections exist only once an
administrator has set up an authority, and they all start from the Alice server:

| Connection | To | When |
|---|---|---|
| HTTPS | The authority's directory address, and the addresses its answers name (orders, proofs, the certificate, renewal information) | Reading the terms (**Register account**), registering, key change and deactivation of the account, every Test run and order, renewal checks |
| HTTPS | The DNS hook's address | Each DNS proof: adding the record, then removing it |
| HTTP, port 80 | `http://<name>/.well-known/acme-challenge/<token>` for each name proved by the web proof | Alice checks the proof file itself before it asks the authority to look |
| SSH, port 22 | The Nginx server chosen for the web proof | Writing and removing the proof file through `alice-helper` |

The authority itself connects to port 80 of each name (web proof) or reads your DNS (DNS proof); that is between the
authority and your network. Every connection Alice makes uses the address rule of the rest of Alice (no link-local,
cloud metadata, multicast or reserved address; private and loopback addresses are allowed) and is checked when it is
opened. HTTPS is required for the authority and the hook, also for the addresses an authority's answer names; Alice
never follows a redirect, reads at most 1 MiB of an answer and waits at most 30 seconds for one exchange. Proxy
settings of the environment (`HTTPS_PROXY` and similar) are ignored: Alice needs a direct route to the authority and
the hook, so a public authority behind a forward proxy cannot be used in this version. The authority's or the hook's
answer text never reaches an error message, the log or the audit log; Alice keeps only its own `ALC-ACM` code.

### Adding a certificate authority

Open **Settings → Certificate authorities** and choose **Add certificate authority**:

- **Certificate authority**: **Let's Encrypt**, **Let's Encrypt (staging, for tests)** (certificates browsers do not
  trust, but much higher request limits), **ZeroSSL** or **My own CA**. The choice only fills in the directory
  address.
- **Name shown in Alice**.
- **Directory address**: the authority's ACME directory, `https://…`, without a user name, password, query or `#`
  part (at most 2048 characters). Let's Encrypt: `https://acme-v02.api.letsencrypt.org/directory`; ZeroSSL:
  `https://acme.zerossl.com/v2/DV90`. Your own CA's documentation names its address.
- **Root certificate of your CA (optional)**: one to ten certificates in PEM form (`-----BEGIN CERTIFICATE-----`),
  at most 64 KiB, nothing else. Alice uses them for two things: it trusts the authority's HTTPS connection when it
  is signed by one of them (besides the system's authorities), and it uses them to decide whether an issued
  certificate's chain is complete. For a company CA paste its root certificate here (and the one that signed the
  ACME server's own HTTPS certificate, if that is another). Without the root, every certificate from that CA counts as
  having an incomplete chain: **Deploy now** then needs an administrator's confirmation and automatic deployment holds
  it. Public authorities need nothing here.
- **External account binding (optional)**: **Key ID** and **Secret key (HMAC)**, exactly as your authority gives them
  (base64url text). ZeroSSL and many commercial or company authorities require one. The secret key is write-only: Alice
  shows "A secret key is stored" afterwards and never shows it again; leave the field empty to keep it, or tick
  **Remove the stored external account binding**.
- **Allowed names (domain endings)**: the names this authority may issue for. `example.com` allows `example.com` and
  every name below it; `.example.com` only the names below it. Each entry needs at least two parts. **An empty list
  allows nothing.** List only domains your organisation owns: this list (and the hook's list, below) is what limits
  operators, who can renew certificates but cannot add names.

**Save certificate authority** contacts nothing ("Nothing was contacted"). Changing the directory address of an
authority that has an account asks you to tick **Retire the current account**: the account is then no longer used by
Alice (it is not deactivated at the authority) and you register a new one. **Remove** is refused while the
authority has an account or certificates use it (`ALC-ACM-0012`): delete those certificates and deactivate the
account first.

### The account

Alice keeps one account per certificate authority. Choose **Register account** on the authority:

1. Alice reads the authority's directory ("Contacting <host> to read its terms of service…") and shows the address of
   its terms of service as a link. Read them, then tick **I have read and accept the terms at this address**. An
   authority without terms needs no tick. If the address is not a safe `https` address, Alice does not offer the
   registration.
2. **Contact e-mail (optional)**: the authority may write to it (for example about expiring certificates or policy
   changes). It is stored with the account and visible to everyone who can read the certificate authorities (also
   auditors and read-only API tokens); it is not written to the audit log.
3. **Register account**. Alice creates the account key itself (ECDSA P-256), stores it encrypted and never shows it.
   If the authority published other terms in the meantime, the registration is refused (`ALC-ACM-0003`), the dialog
   shows the new terms and you tick again.

The account panel shows the state, the contact, the terms' address and when they were accepted. The audit log
records who registered the account, the terms' address and whether an external account binding was used.

- **Rotate account key** replaces the account key at the authority (the authority must support key changes,
  otherwise `ALC-ACM-0014`). If the authority's answer is lost, the authority shows **Key change not settled**:
  certificates of that authority are not ordered until it is settled. Choose **Check key change** a few minutes later
  (Alice keeps the new key at least 5 minutes before it may give it up); Alice asks the authority which key it knows
  and settles the account.
- **Deactivate account** ends the account at the authority for good. The dialog says how many certificates use the
  authority: they are not renewed until you register a new account (each failed renewal counts, so the renewal
  e-mails below follow). Register a new account afterwards; the certificates use it from their next order.
- Only one account operation per authority runs at a time; a second one answers `ALC-ACM-0024` ("try again in a
  moment").

### DNS hooks (DNS proof)

With the DNS proof (DNS-01) the authority looks up a TXT record `_acme-challenge.<name>` in your DNS. Alice does not
talk to DNS servers or DNS providers itself: you run a small HTTPS service, the **DNS hook**, that adds and removes
that record in your DNS, and Alice calls it. A hook can be a few lines in front of your DNS provider's API, your
internal DNS automation or a dynamic-update (RFC 2136) script. The DNS proof is the only proof for wildcard names
(`*.example.com`) and needs nothing on your web servers.

Choose **Add DNS hook** under **Settings → Certificate authorities**:

- **Name shown in Alice**; **Address of the hook**: `https://…`, without a user name, password, query or `#` part.
- **Secret**: 16 to 256 printable characters, write-only like the external account key. Alice sends it as a bearer
  token and uses it as the key of a signature over each request (below).
- **Root certificate of the hook's CA (optional)**, as for an authority.
- **Wait after adding the record (seconds)**: 0 to 120, default 5. **Time to wait for the record (seconds)**: 1 to
  100, default 60. Together at most 120 seconds.
- **Allowed names**, as for an authority. Alice calls the hook only for a name that both the authority's and the
  hook's lists allow.

What the hook receives (the same text is under **How does the hook work?** in Alice):

```
POST <address of the hook>
Authorization: Bearer <secret>
X-Alice-Signature: <lowercase hex of HMAC-SHA256(secret, the exact request body)>
Content-Type: application/json
User-Agent: alice-acme/1

{"action":"present","fqdn":"_acme-challenge.www.example.com","value":"<TXT value>","ttl":60}
```

- `action` is `present` (add the TXT record with this value) or `cleanup` (remove the record with exactly this value,
  never the other records of the name). Both must be safe to repeat.
- A wildcard and its base name (`*.example.com` and `example.com`) use the same `fqdn`: keep both values side by side.
- Answer 200 or 204 when done; anything else (a redirect too) is a refusal (`ALC-ACM-0008`). An optional answer body
  `{"ready":true}` tells Alice the record is visible to the authority now; `{"ready":false}` makes Alice send the same
  `present` again every 2 seconds until `true` or until **Time to wait for the record** has passed. Without such an
  answer Alice waits **Wait after adding the record** and then asks the authority to look.
- Alice reads at most 4 KiB of the answer and never stores or logs it.

**Remove** is refused while certificates use the hook (`ALC-ACM-0019`). Records that a failed or interrupted order
left behind are removed by a clean-up task, also while the license is locked; it tries again every hour for up to
seven days.

### The web proof (HTTP-01)

With the web proof the authority fetches `http://<name>/.well-known/acme-challenge/<token>` on port 80. It is
optional; use it when you cannot run a DNS hook. It needs:

- An Nginx server in Alice (**Server type** **Nginx server**) that answers for every name of the certificate on port
  80, reachable from the authority and from Alice. One server per certificate; wildcard names cannot use it.
- `alice-helper` 1.6.0 (protocol 7) with the current sudoers lines on that server. Servers with an older helper keep
  working for everything else; a web proof on them fails with `ALC-SSH-0013` until you reinstall the helper ("Updating
  the helper" in [nginx-host-preparation.md](nginx-host-preparation.md)).
- A one-time preparation by the server's administrator: a root-owned directory `/var/www/alice-acme/.well-known/acme-challenge`
  and these three lines in the `server` block that listens on port 80, added and reloaded by you:

  ```nginx
  location ^~ /.well-known/acme-challenge/ {
      root /var/www/alice-acme;
  }
  ```

  The exact steps, the ownership rules and what to do with an existing redirect to HTTPS are in "Publishing HTTP-01
  challenges" in [nginx-host-preparation.md](nginx-host-preparation.md). **Alice never edits the Nginx
  configuration**: the helper only writes one small file in that directory while a certificate is ordered and
  removes it afterwards.

### Automatic renewal

Automatic renewal is on for a new certificate. The first certificate is always ordered by a person (**Get certificate
now**); after that Alice plans every minute:

- A certificate is renewed when the time left falls below **Renew how many days before it expires** (1 to 60, default
  30) or below a third of its lifetime, whichever is shorter, so a 90-day certificate renews 30 days before it expires
  and a 6-day certificate 2 days before. When the authority publishes renewal information (ARI, RFC 9773) suggesting
  an earlier time, Alice renews then; a later suggestion is ignored.
- Each renewal gets a new private key, which Alice creates and stores encrypted; the certificate is added to
  **Certificates** ("Issued by ACME") and becomes the current one.
- After a failure Alice waits 1, 2, 4, 8, 16 and then 24 hours, or as long as the authority asks (at most 24 hours),
  and never orders the same certificate twice within 15 minutes. While the authority limits the requests of one
  certificate, the other certificates of that authority wait too (at most 24 hours, and never past the middle of
  their renewal time). At most 5 renewals start per minute.
- After **3** failed renewals in a row the alert recipients get "Alice could not renew the certificate for …"; after
  **5** Alice stops renewing it (**Renewal stopped**, e-mail "Automatic renewal stopped: …"). The certificate in use
  keeps working until it expires. Remove the cause; then **Renew now** (administrators, with a fresh code) switches
  automatic renewal on again, and Alice renews at the next planned time. To renew at once, use **Order now**; a
  successful order also ends the stop. These e-mails are only about renewals: when the first order fails, the page
  says so and nobody is e-mailed.

### Automatic deployment

A certificate is put on a website automatically only when both switches are on: the certificate's **Automatic
deployment of new certificates** and the website's own switch (its page says "Will deploy automatically to N of M
websites"). **Only an administrator, with a fresh code and never with an API token, can switch either on.** Operators
can connect websites with the switch off, switch it off, remove websites and use **Deploy now**. Alice then works
like Key Vault's automatic deployment:

- Only the certificate's current (newest) certificate, never one whose chain is incomplete (it is held: "needs a
  check before it is deployed", e-mail; an administrator uses **Deploy now** with the chain confirmation).
- At most 5 unfinished automatic deployments per certificate; one hour between attempts on a website after a failed
  one; after **3** failed deployments of a certificate Alice stops deploying it automatically ("Automatic deployment
  stopped", e-mail): remove the cause and use **Deploy now**; the next certificate Alice receives is deployed
  automatically again.
- A certificate Alice received before the license last started to allow changes again, deployed nowhere yet, is
  held for an administrator ("waiting for an administrator", e-mail) when one of its websites was connected before
  that moment: check it, then **Deploy now** or **Release** (Alice then deploys it by itself).
- Unlike a Key Vault connection, a connected website gets the new certificate even when it serves a certificate that
  ends later: connecting the website says that it follows this certificate.
- A deployment that was waiting is checked again just before it runs: when the website was removed, automatic
  deployment switched off, a newer certificate arrived, the round stopped or the certificate is held, nothing is sent
  (`ALC-ACM-0030` to `ALC-ACM-0034`).
- A failed deployment is undone like any deployment: the website keeps its previous certificate, and the recipients
  get the usual "Certificate deployment failed on <server>". The website shows **Needs attention** from the planner's
  next run, about a minute later.

Each kind of e-mail is sent once per certificate Alice received; there is no limit per minute across certificates.

### While the license is locked

No authority, hook or server is contacted for certificates: orders, Test runs, registrations, reading the terms,
**Deploy now**, adding authorities, hooks and certificates, connecting websites and switching automatic deployment
(also off) are refused with `ALC-LIC-0001`, and renewal and automatic deployment plan nothing. **Remove** of a
website and **Delete** of a certificate keep working; removing a website is how you stop its automatic deployment
in lock. An order that is running when the lock starts publishes no further proof and does not send the request
for the certificate; proof records already published are cleaned up. Certificate authorities, accounts, hooks and
certificates do not count as targets of the license.

### After a restore

A restore switches automatic renewal off for every certificate from a certificate authority (the restore prints
"Automatic renewal of N certificates ordered from certificate authorities is switched off…"), so that a copy of
an installation never orders certificates behind the original's back. When the restored installation replaces the
original, switch **Automatic renewal** on again on each certificate's page. Orders that were waiting in the backup are
held like other changes ([backup-restore.md](backup-restore.md)). A restored copy uses the same accounts at the same
authorities as the original: do not rotate or deactivate an account on a test copy, it would change the original's
account too.

### What Alice keeps, and the audit log

The account keys, the external account keys and the hook secrets are stored encrypted with the master key, each
bound to its own row, and are never returned by the API, written to a log, an audit entry, a task or an error
message (a test plants them and searches every answer, log line, table, e-mail and the backup's manifest for them).
The private key of each issued certificate is stored like an uploaded certificate's key. Everything is in the audit
log: `acme.provider.*`, `acme.account.*`, `acme.hook.*`, `acme.certificate.*`, `acme.order.*`, `acme.binding.*`,
`acme.auto_renew.*` and `acme.auto_deploy.*`; deployments keep their `deployment.*` entries, with the trigger
`acme_renewal` for automatic ones.

**Not in this version**: revoking a certificate (do it at the authority), an HTTPS proxy, built-in DNS providers
(the hook is the adapter), the TLS-ALPN-01 proof, more than one account per authority, and ACME profiles. Renewals
are not marked as replacements of the previous certificate (ARI's `replaces`), so Let's Encrypt counts them against
its usual limits; use **Let's Encrypt (staging, for tests)** for trials.

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
the target limit for administrators only. The alert recipients also get the warnings by email when the mail server is
set up ([Mail server](#mail-server)).

## For auditors

Auditors sign in like everyone else (password and authenticator app, or single sign-on). They see **Overview** (with its **Assurance** tab), **Certificates**, **Issued certificates**, **SSH keys**, **Servers**, **Key Vaults**,
**Deployments**, **Key rotations**, **Audit trail**, **License** (read only), **API tokens** and **Your account**, and
no button that changes anything except their own password, recovery codes,
language, read-only API tokens and their own saved views; they can export the certificate and SSH key lists. On
**Audit trail** they can filter, **Verify integrity** and export. A read-only
API token lets a script fetch `GET /api/v1/audit` or `GET /api/v1/audit/export?format=json` for regular
collection.
