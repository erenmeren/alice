# Vendor console: operations runbook

This runbook is for the people who run the vendor console: the owner, the IT manager and the
signers. It covers roles, keys, people joining and leaving, backups and the restore drill, tamper
checks, monitoring and incidents. How each command works is in
[vendor-console.md](vendor-console.md). The signing key itself (creation, backups, rotation,
compromise, the release key) is in [vendor/licensing-vendor.md](vendor/licensing-vendor.md); this
runbook links to it and does not repeat it.

**Signing option in force until Phase 2:** option <1 or 2> (section 2), decided by the owner on
<YYYY-MM-DD>.

Rules for every step below:

- No password, connection string, enrollment code or private key goes into a document, a ticket, a
  chat or this repository. Commands show placeholders such as `<login>` and `<password>`.
- Each person uses their own database login in `VENDOR_DATABASE_URL`. Never share a login.
- The connection string has `sslmode=verify-full` (for example `...?sslmode=verify-full`, or
  `...?sslmode=verify-full&sslrootcert=system` when libpq needs to be told to use the system's root
  certificates) unless the database is on the same computer.
- Passwords are set with `psql`'s `\password "<login>"`, which asks for the password and sends it
  only in hashed form. A password typed inside an SQL statement (`ALTER ROLE ... PASSWORD '...'`)
  lands in `~/.psql_history` and in the server log if statements are logged, so do not do that.

**The ledger.** The hash-chained `audit` table and the `licenses` table together are the issuance
ledger of the console. No CSV ledger is exported from the database: such a file would have to be
signed with the license key, and that key signs nothing but licenses. `licensectl ledger-verify`
stays for the `issued.csv` files of licenses issued with `licensectl`.

## 1. Roles and who does what

| Person | Database login | Other credentials | Where they live |
|---|---|---|---|
| Owner (UK) | one login in `vendor_owner` | the migration login; the Neon account; the mailbox that gets `owner_email` | the owner's own computer and password manager |
| IT manager (Istanbul), signer | one login in `vendor_signer` | the `vendor-web` service login and TLS certificate; the server that runs `notify run` | the servers' environment files, readable by root only |
| Sales people | none needed | a web user name and a passkey for the sales page | the passkey on their security key or device |
| `notify run` timer | one login in `vendor_notifier` | the SMTP login | `/etc/vendor-console/notify.env` (mode 0600, root) |
| Sales web service | one login in `vendor_web` (for example `vendor_web_svc`) | none | `VENDOR_WEB_DATABASE_URL` on the web server |

Group roles and what they may do (created by `vendor-console migrate`):

- `vendor_sales`: read customers and licenses, add customers and requests, cancel own open requests.
- `vendor_signer`: everything `vendor_sales` can, plus insert licenses (`issue`), change customers,
  and update any request, not only their own (the `requests_update_signer` policy: a signer can
  change or cancel anyone's request).
- `vendor_owner`: everything `vendor_signer` can, plus read the audit log (`audit show`,
  `audit-verify`, `audit-head`), revoke licenses, manage web users, change settings, and read the
  mail outbox and reminder records.
- `vendor_notifier`: only what `notify run` needs. It may also run `audit-head`, `notify failed`
  and `notify retry`.
- `vendor_web`: only the sales web service. It cannot sign or read the audit log.

The migration login owns the tables and is not held back by the grants. Use it only for
`vendor-console migrate`, for creating and dropping logins, for backups (`pg_dump`) and for the
fixes this runbook names. The owner keeps it.

Signing keys: until Phase 2 (YubiKey signing) is built, licenses are signed with the passphrase key
file (section 2). After Phase 2, the owner and the IT manager each have their own YubiKey, and a
third YubiKey is the spare.

## 2. Key ceremony

**The YubiKey signer (Phase 2) is not built yet.** This release signs only with the passphrase key
file. Until Phase 2 lands:

- The key file, its passphrase, its backups and its yearly recovery test follow
  [licensing-vendor.md](vendor/licensing-vendor.md) sections 1, 2 and 6 exactly (two
  hardware-encrypted USB drives, a printout, the passphrase paper stored apart).
- `internal/license/keys/production.json` lists no key today. Until it does, release builds accept
  no license. Embedding the first key is section 2 of licensing-vendor.md.

`vendor-console issue --key FILE` needs the database, so the computer that runs it is online, while
licensing-vendor.md says the signing key is never on a computer connected to the internet. Until the
YubiKey signer lands, two ways are supported. The owner decides which one is in force and records
the decision and its date at the top of this runbook.

**Option 1: `licensectl` offline, as today.** Sign on the offline machine exactly as
licensing-vendor.md section 3 says. These licenses are not in the console's database: no issuance
mail, no reminders, no line in the weekly summary, nothing for `verify-licenses` to check. Their
record is the `issued.csv` ledger next to the key and the paper log, which the owner keeps
(licensing-vendor.md section 5). The owner may add the customer to the console by hand
(`vendor-console customer add --name "<customer>"`) so sales see it; the license itself is not
entered.

**Option 2: the file key on an online signer computer.** `vendor-console issue --key FILE` signs
and records the license in the database (issuance mail, reminders, summary, audit). The passphrase
is typed on a computer that is online, so malware on it (a keylogger) could take the passphrase and
the key file together. The computer must therefore be a dedicated signer computer: used for nothing
else, fully patched, the key on a hardware-encrypted USB drive plugged in only while signing.
licensing-vendor.md records this exception in its "Rules that never change". If the signer computer
may have been compromised, follow section 9 ("Signer machine compromise") and treat the key as
leaked.

### YubiKey checklist (to follow once Phase 2 lands)

This is the checklist spec section 4.4 asks for. The exact commands (PIV or OpenPGP) come with
Phase 2, which depends on open items O1 (firmware) and O3 (library). Do it once per YubiKey, the
owner's keys in the UK.

1. Run `ykman info`. Record the serial number, the firmware version and the enabled applications.
   PIV Ed25519 needs firmware 5.7 or later; OpenPGP Ed25519 needs 5.2.3 or later.
2. Change the default PIN and PUK (and the management key for PIV) to new values. Write the PUK on
   paper and store it like a passphrase (apart from the key).
3. Generate the Ed25519 key pair **on the device**, so the private key never exists outside it.
   Require the PIN for every signature and require touch.
4. Export the public key. Record the key ID (`vk-YYYY-NN`, a new ID for every key) and the
   fingerprint on paper.
5. Build the key set entry with `licensectl keyset --pub <public key file>` (or the Phase 2
   equivalent) and compare the printed fingerprint with the paper.
6. Add the entry to `internal/license/keys/production.json`: the owner's key, the IT manager's key
   and the spare, all `"active"`, one entry per key ID (licensing-vendor.md section 7 shows how to
   merge entries). Run `make release-keycheck`.
7. Ship the release that embeds the keys. Sign with a new key only from the release after that, so
   customers who update late already trust it. In the built image, run `alice license keys` and
   compare every fingerprint with the paper.
8. Store the spare YubiKey and the PUK papers in separate safe places, apart from the daily keys.
9. Record the date, the serial numbers and the key IDs in the paper log.

## 3. Onboarding and offboarding

### A new sales person

A sales person needs no database login. As the owner login:

    vendor-console web-user add <name>
    vendor-console web-user set-email <name> <address>     # for reminders of their requests

`add` prints a one-time enrollment code (24 hours, shown once). Give it to the person over a
channel you trust. They open `/enroll` on the sales page and register a passkey.

- Lost or new device: `vendor-console web-user invite <name>` prints a new code. The old passkeys
  stay.
- Check who exists: `vendor-console web-user list`.

### A new signer (or owner) login

As the migration login (a role that may create roles), in `psql`:

    CREATE ROLE "<login>" LOGIN IN ROLE vendor_signer;
    \password "<login>"

Use `vendor_sales`, `vendor_signer`, `vendor_owner` or `vendor_notifier` as needed; the web
service's login is `IN ROLE vendor_web` and nothing else. One group role per login. Best is that
the person types the password themselves: set a temporary one with `\password "<login>"`, then the
person connects with it and runs `\password` in their own `psql` session to choose their own.

A signer also needs a signing key: the key file today (section 2), a YubiKey after Phase 2.

To see every login and its group role:

    SELECT m.rolname AS login, g.rolname AS group_role
    FROM pg_auth_members a JOIN pg_roles m ON m.oid = a.member JOIN pg_roles g ON g.oid = a.roleid
    WHERE m.rolcanlogin AND g.rolname LIKE 'vendor\_%' AND (a.inherit_option OR a.set_option)
    ORDER BY 2, 1;

(On PostgreSQL 16 the login that created the group roles holds them with the admin option only;
the last condition leaves it out.)

### A leaver

1. Web user: `vendor-console web-user disable <name>` (owner login). Sign-in stops and their
   sessions end at once. Do not `enable` the name again if a passkey may be in someone else's hands;
   make a new name instead.
2. Database login, as the migration login:

       DROP ROLE "<login>";

   The login normally owns nothing, so this is enough. The audit rows and the `created_by` and
   `requested_by` columns keep the name as text. If `DROP ROLE` says objects depend on the role, run
   (PostgreSQL 16 lets you reassign only the objects of a role whose privileges you hold, so grant
   it to yourself first):

       GRANT "<login>" TO CURRENT_USER;
       REASSIGN OWNED BY "<login>" TO CURRENT_USER;
       DROP OWNED BY "<login>";
       DROP ROLE "<login>";

   `REASSIGN OWNED` and `DROP OWNED` act on the current database only; the vendor console uses one.
   `DROP ROLE` and `GRANT "<login>" TO CURRENT_USER` work this way because the migration login
   created the login and so holds it with the admin option; a login created another way (for
   example in the Neon console) may need the role that created it, or the Neon console.
   Do not give the same login name to another person later.
3. If the person held a signing key, or knew a key's passphrase or PIN: treat the key as
   compromised (section 4), unless you are certain they never had the passphrase or the device.
4. If the person knew a shared credential (the web service login, the notifier login, the SMTP
   login, the migration login): rotate it (section 9, "Database credential leak").

## 4. A lost or compromised signing key

The procedure is [licensing-vendor.md](vendor/licensing-vendor.md) section 8 (compromise) and
section 7 (rotation). In short:

- **Compromised** (the key or its passphrase may have leaked, or a YubiKey is lost with its PIN):
  new key, then an emergency release whose `production.json` adds the new key and marks the old one
  `"status": "revoked"` **with no `revoked_from`**. Every license signed with that key stops counting
  in a customer's Alice once they run that release. Every customer needs a new license file before,
  or with, that release.
- **Lost but not leaked** (a YubiKey destroyed, a key file lost while its backups are safe): sign
  with another embedded key (the IT manager's or the spare). Licenses signed with the lost key stay
  valid. Retire the key later with `"revoked"` and a `"revoked_from"` cutoff only after all its
  licenses have expired or been reissued (section 7 step 4).

Revoking a signing key is always a product release; nothing in the console revokes a key.

Find the licenses signed with a key (any vendor login can read this):

    SELECT l.license_id, c.name, l.issued_at, l.valid_until, l.revoked_at
    FROM licenses l JOIN customers c ON c.id = l.customer_id
    WHERE l.key_id = '<key-id>' ORDER BY l.valid_until;

The ones with a `valid_until` in the future and no `revoked_at` need a new license. Make one request
per license with the same customer, installation and targets, and sign it with the new key.

After the new `production.json` is committed, check the database against it:

    vendor-console verify-licenses --keyset internal/license/keys/production.json

Every license signed with the compromised key is then listed as "the file is signed by a key that is
revoked for its issue date". Everything else must show no problem.

What to tell customers (licensing-vendor.md section 8, step 4, "Notify customers"): that a new
license file is coming and why, and that they must upload it before or together with the update.
Publish the new key's fingerprint so they can compare it (licensing-vendor.md section 2, "Put the
public key into Alice builds", step 4).

## 5. Revoking a license

    vendor-console license revoke --id <LICENSE-ID> --reason "<why>"

Owner login only. The reason is one line, at most 200 characters, and goes into the audit row
`license.revoke`.

What it does:

- Sets `revoked_at` on the license in the vendor database.
- Reminders stop for it, and it no longer counts in the summary's "Ending in the next 90 days".
- The audit records who revoked it, when and why.

What it does **not** do:

- It does not touch the customer's installation. Alice checks license files offline, against the
  keys built into it, and never asks the vendor. A revoked license keeps working there until it
  ends or is replaced by a later license.
- It does not revoke a signing key. That is a product release (section 4).

An unknown or already revoked license is refused and nothing changes.

## 6. Backups and the restore drill

The vendor database is backed up separately from the product: [backup-restore.md](backup-restore.md)
is about a customer's Alice installation and has nothing to do with this database.

### What the database holds

- Customers, license requests, issued licenses with their signed files.
- The audit chain (every change, with who and when).
- Web users, their passkeys (`web_credentials`, public keys only) and enrollment code hashes.
- Settings (`owner_email`, `timezone`), the mail outbox and the reminder records.
- Web sessions. They are disposable; after a restore people simply sign in again.

### What is not in it

- **The signing keys.** Key files, passphrases and YubiKeys are backed up as licensing-vendor.md
  says, never in the database.
- The database logins and their passwords (they belong to the PostgreSQL server, not to the
  database; `pg_dump` of one database does not include them).
- `notify.env`, the web service environment, its TLS certificate.
- The weekly summary mails. They stay in the owner's mailbox, which is the point (section 7).

### How to back up

1. **Neon point-in-time restore.** Check that the project's history window covers at least the
   time between two checks of the weekly mail (a week or more).
2. **An encrypted dump kept apart from Neon**, at least monthly and before every migration. Run it
   as the migration login: it owns the tables, and `pg_dump` with another login stops at the
   row-level security on `license_requests`. Use a `pg_dump` of at least the server's major
   version (run `SELECT version();` to see it).

   Never type the migration login's connection string on the command line, where it stays in the
   shell history and is visible in the process list. Either export it for this one shell from the
   password manager (`read -rs VENDOR_DATABASE_URL && export VENDOR_DATABASE_URL`, paste, Enter;
   close the shell afterwards) or put the password in `~/.pgpass` with mode 0600.

   Immediately before the dump, record two values for the drill record (as the owner login, or with
   `psql` as the migration login for the count):

       vendor-console audit-head                  # prints <seq>:<hash>
       SELECT count(*) FROM licenses;

   Then, with the migration login in `VENDOR_DATABASE_URL`:

       pg_dump -Fc -d "$VENDOR_DATABASE_URL" -f vendor-<YYYYMMDD>.dump

   Write the head, the count and the time next to the file name in the operations log. Encrypt the
   dump with the tool you already use, for example
   `gpg --symmetric --cipher-algo AES256 vendor-<YYYYMMDD>.dump` or
   `age -p -o vendor-<YYYYMMDD>.dump.age vendor-<YYYYMMDD>.dump`, then delete the plain file. Store
   the encrypted file away from Neon (an encrypted drive, a second cloud account). Keep its
   passphrase as you keep the other vendor passphrases.

   About TLS: the console accepts a remote connection string only with `sslmode=verify-full`. If
   libpq (here `pg_dump`) cannot find the root certificates, add `sslrootcert=system` (libpq 16 or
   later), for example `...?sslmode=verify-full&sslrootcert=system`.

### The restore drill (quarterly)

Do it on a computer you trust, into a scratch database, never into production. You need the dump's
record from the operations log: the head and the license count taken just before it.

1. **Pick the checkpoints.** The first is the head recorded before the dump. The second is the
   witness outside the database: in the owner's mailbox, find the newest weekly summary sent
   **before** the dump was taken and copy its last line, `Audit head: <seq>:<hash>`. (A summary
   sent after the dump names rows the dump does not have, and step 6 then reports a mismatch.)
2. **Decrypt the dump** on the drill computer: `gpg -o vendor.dump -d vendor-<YYYYMMDD>.dump.gpg`
   or `age -d -o vendor.dump vendor-<YYYYMMDD>.dump.age`.
3. **Start a scratch PostgreSQL** of the production server's major version on this computer. It
   listens on 127.0.0.1 only and needs no passwords (`trust`), because it holds nothing but this
   drill:

       docker run -d --rm --name vendor-drill -e POSTGRES_HOST_AUTH_METHOD=trust \
           -p 127.0.0.1:55432:5432 postgres:<major version>
       docker cp vendor.dump vendor-drill:/tmp/vendor.dump

   Then create a restoring login, the database and the group roles (the dump holds grants to them,
   but not the roles themselves):

       docker exec -i vendor-drill psql -U postgres <<'EOF'
       CREATE ROLE restorer LOGIN CREATEROLE;
       CREATE DATABASE vendor_drill OWNER restorer;
       EOF
       docker exec -i vendor-drill psql -U restorer -d postgres <<'EOF'
       CREATE ROLE vendor_sales NOLOGIN;
       CREATE ROLE vendor_signer NOLOGIN IN ROLE vendor_sales;
       CREATE ROLE vendor_owner NOLOGIN IN ROLE vendor_signer;
       CREATE ROLE vendor_web NOLOGIN IN ROLE vendor_sales;
       CREATE ROLE vendor_notifier NOLOGIN;
       EOF

4. **Restore:**

       docker exec vendor-drill pg_restore -U restorer -d vendor_drill --no-owner --exit-on-error /tmp/vendor.dump

   Expected: no output, exit code 0. Then create a drill owner login:

       docker exec vendor-drill psql -U restorer -d vendor_drill -c "CREATE ROLE drill_owner LOGIN IN ROLE vendor_owner;"

5. **Migrations find nothing to do.** A database on this computer needs no TLS:

       export VENDOR_DATABASE_URL='postgres://restorer@127.0.0.1:55432/vendor_drill?sslmode=disable'
       docker exec vendor-drill psql -U restorer -d vendor_drill -tc "SELECT max(version_id) FROM goose_db_version WHERE is_applied"
       vendor-console migrate
       docker exec vendor-drill psql -U restorer -d vendor_drill -tc "SELECT max(version_id) FROM goose_db_version WHERE is_applied"

   Expected: `migrations applied`, and the same version before and after (the number of the newest
   file in `internal/vconsole/migrations`, `4` today). A higher number after means the dump was
   older than the code; note it.
6. **The audit chain and both checkpoints:**

       export VENDOR_DATABASE_URL='postgres://drill_owner@127.0.0.1:55432/vendor_drill?sslmode=disable'
       vendor-console audit-verify --head <head recorded before the dump>
       vendor-console audit-verify --head <seq>:<hash from the weekly summary>

   Expected, both times: `audit chain OK; checkpoint <seq> found`.
7. **Every license file:**

       vendor-console verify-licenses --keyset internal/license/keys/production.json

   Expected: `checked N, problems 0`, where N is at least the license count recorded before the dump
   (equal, unless someone issued a license between the count and the dump). `WARNING: no licenses
   found` on a database that should have licenses is a failed drill. While `production.json` lists
   no key, the command refuses with `the key set has no keys`; then use the public key file
   instead: `vendor-console verify-licenses --pub alice-license-public.pem` (repeat `--pub` for each
   key).
8. **Spot-check one license file:**

       vendor-console license export --id <LICENSE-ID> --out drill-check.json
       sha256sum drill-check.json
       docker exec vendor-drill psql -U restorer -d vendor_drill -tc "SELECT file_sha256 FROM licenses WHERE license_id = '<LICENSE-ID>'"
       licensectl verify --pub alice-license-public.pem drill-check.json

   Expected: the two hashes are equal, and `OK`.
9. **Clean up:** `docker stop vendor-drill` (the `--rm` container is removed with its data), and
   delete `vendor.dump` and `drill-check.json`.

**Drilling the Neon side** (point-in-time restore) instead of the dump: create a branch from a
point in time in the Neon console. The branch has the roles and logins already, so skip steps 2 to
4. Connect with your own owner login to the branch's host, with `sslmode=verify-full` as for
production, and run steps 6, 7 and 8 against it. For step 5 run `vendor-console migrate` with the
migration login on the branch, and read `goose_db_version` with `psql` on the branch instead of
`docker exec`. Use the head of the newest weekly summary sent before the chosen point in time. Delete
the branch afterwards.

**Success** means: the restore finished without errors, `migrate` changed nothing, both checkpoints
were found, every license verified, and the count matches the record. Anything else: find out why
before the next issue, and record it.

**Record** each drill in the operations log (paper or a document outside the database):

    Restore drill <YYYY-MM-DD>, done by <name>
    Dump: vendor-<YYYYMMDD>.dump.<gpg|age>, taken <YYYY-MM-DD HH:MM UTC>, stored at <place>
    Recorded before the dump: audit head <seq>:<first 12 hex of hash>, licenses <N>
    Weekly summary checkpoint: <seq>:<first 12 hex of hash> from the summary of <YYYY-MM-DD>
    pg_restore: OK / errors: <...>
    Schema version before/after migrate: <n>/<n>
    audit-verify --head (recorded head): OK / <output>
    audit-verify --head (summary head): OK / <output>
    verify-licenses: checked <N>, problems <M>
    Spot check: <LICENSE-ID>, hash equal yes/no, licensectl verify OK yes/no
    Neon history window checked: <days>
    Follow-up: <none / what and who>

## 7. Tamper evidence

`audit-verify` shows that no audit row was edited or removed from the middle of the chain. It
cannot see newest rows that were cut from the end. The weekly summary closes that gap: its last line
is

    Audit head: <seq>:<hash>

the newest audit row at the time the summary was written. The owner's mailbox is the witness outside
the database. Keep every summary mail; do not delete them.

To check now, as the owner login:

    vendor-console audit-verify --head <seq>:<hash>

- `audit chain OK; checkpoint <seq> found`: the chain is intact and the rows up to the checkpoint are
  still there.
- `audit chain BROKEN at sequence <n>`: a row was edited or removed in the middle.
- `audit checkpoint MISMATCH: row <seq> is missing or is not the row of checkpoint ...`: rows up to
  the checkpoint were removed or replaced after the summary was written. On a production database
  this means tampering, or that someone restored an older backup without telling you.

`vendor-console audit-head` prints the current head (owner or notifier login), for a checkpoint
between two summaries, for example before and after a migration.

The owner reads the audit with `audit show` (owner login only):

    vendor-console audit show                                # newest 50 rows
    vendor-console audit show --since 2026-10-01 --action license. --limit 200
    vendor-console audit show --actor web:<name> --details

Rows come newest first: sequence, time (UTC), actor, action, subject. `--limit` is at most 1000.
`--details` adds each row's details. Installation IDs never appear: they are shown as `inst#` and
8 hex digits (a fingerprint of the ID, the same for the same ID).

### When a check fails

1. **Stop issuing.** Tell every signer not to sign until you say so. If the web service may be
   involved, stop it.
2. **Keep the evidence.** Change nothing in the database. Take an encrypted dump now (section 6).
   Save the `audit-verify` output, the time, and the summary mails.
3. **Compare with a Neon restore point.** Create a branch from a time before the suspected change
   (at or just after the checkpoint's summary). On the branch, run `audit-verify --head` with the
   same checkpoint and `audit show` for the rows from that time. Compare with production to see
   which rows are missing or changed. Compare the `licenses` table with the issuance mails in the
   owner's mailbox (there is one mail for every license inserted).
4. Find out which login could have done it (section 9, "Database credential leak"). Only the
   migration login, or a superuser, can remove audit rows.
5. Decide with what you found whether to restore from the branch. Record what happened.

## 8. Monitoring

`notify run` runs from a timer (hourly in the example of vendor-console.md). Each run sends due
mails and, when more than 7 days passed since the last one, the weekly summary.

- **A dead timer.** No weekly summary for 8 days means the timer, the server, the database
  connection or the mail is down. The owner notices because the summary stops arriving: put a
  weekly reminder in the owner's calendar ("summary arrived?"). On the timer server:
  `systemctl list-timers vendor-notify.timer` and `journalctl -u vendor-notify.service`. A run that
  had errors exits with 1, so `systemctl --failed` shows it.
- **Failed mail.** The summary's "Failed e-mails" section lists mails given up on in the last 28
  days. To list them now (owner or notifier login):

      vendor-console notify failed

  Fix the cause (an address, the SMTP login), then, **with the notifier login**:

      vendor-console notify retry <ID>

  The next `notify run` sends it, with a fresh attempt count. Only a failed, unsent mail is touched.
  The owner login is refused: a retry is the notifier's job. Each retry writes a `mail.retry` audit
  row. That row is a trail, not a control: the notifier login may add mail to the outbox, so it
  could also queue a new mail without a retry row. The owner can read the outbox directly:

      SELECT id, kind, to_addrs, created_at, attempts, last_error FROM mail_outbox
      WHERE failed_at IS NOT NULL ORDER BY id DESC;

- **Unusual.** Read the summary's "Unusual" section every week: licenses issued at night, a signer
  with more than 5 licenses in a day, and licenses without an issue audit row. The last one means
  triggers were turned off or audit rows are gone: follow section 7, "When a check fails".
- **Issued licenses.** Every license sends the owner a mail. A license you did not expect is an
  incident (section 9).

## 9. Incident checklists

### Break-in of the web service

Follow [vendor-console.md, "After a break-in of the web service"](vendor-console.md#after-a-break-in-of-the-web-service):
review `webuser.passkey_add` rows (`vendor-console audit show --action webuser.passkey_add
--details`) and `web_credentials`, disable affected web users, rotate the service login's password.
The service cannot sign, so no license can be forged through it. Then:

- [ ] Rebuild the server from a clean image; new TLS certificate.
- [ ] `audit-verify --head` with the newest summary's line.
- [ ] Check the requests and customers added in the period with `audit show --since <date>`.

### Signer machine compromise

- [ ] Stop signing from that machine.
- [ ] The key file was on it or plugged into it, or its passphrase was typed on it: treat the key as
      compromised (section 4). With a YubiKey (after Phase 2), PIN and touch stop silent signing,
      but remove the key from that machine and change the PIN.
- [ ] Rotate the signer's database password (below).
- [ ] Check the licenses issued by that login: `audit show --actor <login> --action license.`, and
      compare with the issuance mails.
- [ ] `audit-verify --head` with the newest summary's line.

### Database credential leak

- [ ] Change the password, as the migration login, in `psql`:

      \password "<login>"

- [ ] A new password does not end open sessions. End them (PostgreSQL 16 needs the privileges of the
      role, so grant it to yourself for the moment):

      GRANT "<login>" TO CURRENT_USER;
      SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = '<login>';
      REVOKE "<login>" FROM CURRENT_USER;

- [ ] Put the new password where the login is used (`notify.env`, `VENDOR_WEB_DATABASE_URL`, the
      person's own environment).
- [ ] Review what the login could do (section 1) and check it with `audit show --actor <login>`.
- [ ] The migration login leaked: change it in the Neon console, then run `audit-verify --head` and
      `verify-licenses`: that login can change any table.
- [ ] The Neon account leaked: secure the account first (password, second factor), then rotate
      every login.

### Lost owner login

- [ ] Lost database password: reset it with the migration login in `psql`
      (`\password "<owner login>"`).
- [ ] Lost migration login: reset it in the Neon console with the Neon account.
- [ ] Lost access to the `owner_email` mailbox: the summaries (checkpoints) and issuance mails are
      there. Set a new address with `vendor-console settings set owner_email <address>` and note in
      the operations log from which date the checkpoints are in the new mailbox.
- [ ] The owner leaves the company: the next owner gets a new login in `vendor_owner` and the
      migration login; then offboard the old owner (section 3) and rotate every shared credential.

## 10. Quarterly and yearly checklists

### Every quarter

- [ ] Restore drill (section 6), recorded.
- [ ] `vendor-console audit-verify --head <newest summary's line>` on production.
- [ ] `vendor-console verify-licenses --keyset internal/license/keys/production.json` on production.
- [ ] `vendor-console notify failed`: nothing old left.
- [ ] `vendor-console web-user list`: disable people who left.
- [ ] The login list (section 3): drop logins of people who left.
- [ ] `vendor-console audit show --action webuser.passkey_add --since <date of last check>`: every
      new passkey belongs to an enrollment you know about.
- [ ] The encrypted dumps exist where they should, and the newest is less than a month old.
- [ ] Every weekly summary of the quarter arrived (no gap of more than 8 days).

### Every year

- [ ] The yearly recovery test of each signing key ([licensing-vendor.md](vendor/licensing-vendor.md)
      section 6); after Phase 2, check each YubiKey's PIN works and the spare is where the log says.
- [ ] Decrypt the oldest dump you keep, to prove its passphrase still works.
- [ ] Rotate the passwords of the web service login, the notifier login, the SMTP login and the
      migration login.
- [ ] Plan key rotation: a new key is added at least one release before it is used
      (licensing-vendor.md section 7).
- [ ] Renew the web service's TLS certificate if it is not renewed automatically.
- [ ] Review this runbook against the current commands (`vendor-console` with no arguments prints
      them).
