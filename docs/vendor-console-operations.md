# Vendor console: operations runbook

This runbook is for the people who run the vendor console: the owner, the IT manager and the
signers. It covers roles, keys, people joining and leaving, backups and the restore drill, tamper
checks, monitoring, incidents, the YubiKey key ceremony (section 2) and the YubiKey hardware smoke
test (section 11). How each command works is in [vendor-console.md](vendor-console.md). The
passphrase key file (creation, backups, rotation, compromise, the release key) is in
[vendor/licensing-vendor.md](vendor/licensing-vendor.md); this runbook links to it and does not
repeat it.

**Signing option in force:** option <1, 2 or 3> (section 2), decided by the owner on
<YYYY-MM-DD>. Option 3 (the YubiKey) only after the hardware smoke test (section 11) has passed on
every platform a signer uses.

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

Signing keys: until the hardware smoke test (section 11) has passed, licenses are signed with the
passphrase key file (section 2, options 1 and 2). With the YubiKey signer (option 3), the owner and
the IT manager each have their own YubiKey with its own key ID, and a third YubiKey is the spare.

## 2. Key ceremony

Licenses can be signed in three ways (below). The YubiKey signer (option 3,
`vendor-console issue --signer openpgp`) is built and tested against a software card, but it has
**not yet run against a real YubiKey**. Until the owner has run the hardware smoke test
(section 11) on every operating system a signer uses, option 3 is not in force.

The passphrase key file, its backups and its yearly recovery test follow
[licensing-vendor.md](vendor/licensing-vendor.md) sections 1, 2 and 6 exactly (two
hardware-encrypted USB drives, a printout, the passphrase paper stored apart).
`internal/license/keys/production.json` lists no key today. Until it does, release builds accept no
license. Embedding a key is section 2 of licensing-vendor.md.

### Signing options

`vendor-console issue --key FILE` needs the database, so the computer that runs it is online, while
licensing-vendor.md says the signing key file is never on a computer connected to the internet. The
owner decides which option is in force and records the decision and its date at the top of this
runbook.

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

**Option 3: the YubiKey (preferred, once the owner has run the hardware smoke test of section 11 on
every platform a signer uses).** `vendor-console issue --signer openpgp` signs with an Ed25519 key
that was generated on the YubiKey and never leaves it, and records the license like option 2. Before
the PIN prompt the console prints every field of the license and the SHA-256 of the exact bytes the
card signs, and asks `Sign this license? [y/N]`. The card asks for the PIN for every signature and
waits for a touch. Malware on the signer computer cannot copy the key; at worst it can get one
signature per PIN entry and touch, and every license still sends the owner a mail (section 8). Each
signer has their own YubiKey and key ID, and a third YubiKey is the spare.

### The YubiKey key ceremony

Do this once per YubiKey: the owner's key and the spare in the UK, the IT manager's in Istanbul.

**Not run by the author.** The `ykman` and `gpg` commands below come from the tools'
documentation; nobody has run them against a YubiKey for this runbook. On first use, check each one
against your installed versions (`ykman --version`, `gpg --version`, and the command's `--help`),
and write any difference into the paper log so that the next ceremony uses what worked.

**Prerequisites**

- One YubiKey per signer, plus the spare. Each one gets **its own key ID** of the form
  `vk-YYYY-NN` (for example `vk-2026-02`, `vk-2026-03`, `vk-2026-04`). Never reuse a key ID,
  including one a file key already has.
- `ykman info` shows firmware **5.2.3 or later** (Ed25519 on the OpenPGP application needs it) and
  **OpenPGP enabled** over USB. Use `ykman config usb --enable OPENPGP` if it is not.
- YubiKey Manager (`ykman`), GnuPG 2.2 or later, and the YubiKey build of the console,
  `bin/vendor-console-yubikey` (section 11, "Get the binary"). On Linux, `pcscd` must be running.
- A computer you trust and that is patched. It need not be offline: the private key is made on
  the YubiKey and never exists outside it.

**Step 1. Look at the YubiKey.** *(Not run by the author; check against your installed ykman/gpg
versions on first use.)*

    ykman info
    ykman openpgp info

Write down the serial number, the firmware version, the OpenPGP version and the PIN tries. If
`ykman openpgp info` shows that the card already holds OpenPGP keys and nothing on it is needed,
`ykman openpgp reset` erases every OpenPGP key and sets the PINs back to the factory defaults.

**Step 2. Change the PINs from the factory defaults.** *(Not run by the author; check against your
installed ykman/gpg versions on first use.)* The OpenPGP application's factory defaults are User PIN
`123456` and Admin PIN `12345678`.

    ykman openpgp access change-pin
    ykman openpgp access change-admin-pin

- User PIN: at least 6 characters (the console refuses shorter ones). Use digits or plain ASCII
  letters only: the PIN is sent byte for byte, so an accented letter typed on another keyboard or
  operating system can produce other bytes.
- Admin PIN: at least 8 characters. It changes the card's settings and unblocks the User PIN. Write
  it on paper and store it like a passphrase, apart from the YubiKey.
- **Reset Code decision.** A Reset Code unblocks the User PIN without the Admin PIN. Recommended:
  set none, so only the Admin PIN can unblock. If the owner wants one (for a signer who should not
  hold the Admin PIN), set it with `ykman openpgp access change-reset-code` and store it like the
  Admin PIN. Record the decision in the paper log.
- Do **not** set up a PIN key derivation function (`kdf-setup` in `gpg --card-edit`). The console
  refuses such a card ("the card uses a PIN key derivation function (KDF-DO), which is not
  supported").
- The card allows 3 User PIN tries by default. The console never retries a wrong PIN by itself and
  refuses to ask for the PIN when only one try is left unless `--last-pin-try` is given.

**Step 3. Generate the Ed25519 signing key on the card.** *(Not run by the author; check against
your installed ykman/gpg versions on first use.)*

    gpg --card-edit
    gpg/card> admin
    gpg/card> key-attr

`key-attr` asks about the signature key, the encryption key and the authentication key in turn.
For the **signature key** choose `ECC` and then `Curve 25519`; give the others the same (the console
uses only the signature key). It asks for the Admin PIN. Then:

    gpg/card> generate

- `Make off-card backup of encryption key?` Answer **no**. Nothing of this ceremony may exist
  outside the card.
- Expiry: `0` (does not expire) is fine; the console does not use the OpenPGP certificate gpg makes.
- Name: something you will recognise, for example `Alice license key vk-2026-02`.
- gpg asks for the PIN and signs its own certificate with the new key, so the signature counter
  starts at a small number rather than 0.

Then `quit`. The key on the card is the license key; the certificate gpg put into the local keyring
is not used by the console.

Alternative: if `ykman openpgp keys --help` on your installed version lists a command that generates
a key on the card, it may be used instead, provided it makes an Ed25519 **signature** key on the
card. The rest of the ceremony is the same.

**Step 4. Ask for the PIN for every signature.** *(Not run by the author; check against your
installed ykman/gpg versions on first use.)* The console refuses a card that keeps the PIN valid for
several signatures (PIN policy `NOT forced` in `signer info`).

    gpg --card-edit
    gpg/card> admin
    gpg/card> forcesig
    gpg/card> quit
    gpg --card-status

`forcesig` **toggles** the setting. Run it again until `gpg --card-status` shows
`Signature PIN ....: forced`.

**Step 5. Require a touch for signatures.** *(Not run by the author; check against your installed
ykman/gpg versions on first use.)*

    ykman openpgp keys set-touch sig on

It asks for the Admin PIN. Check with `ykman openpgp info` (touch policy of the signature key). The
choices:

- `on`: a touch for every signature. Recommended.
- `fixed`: like `on`, but it **cannot be changed back**: only resetting the OpenPGP application,
  which deletes the key, turns it off. It protects against someone who has the Admin PIN turning
  touch off.
- `cached`: one touch covers further signatures for about 15 seconds. The console signs one license
  per run, so it gains nothing and weakens the protection; not recommended. (`cached-fixed` is
  `cached` that cannot be changed back.)
- `off`: the console refuses to sign unless `--allow-no-touch` is given. Do not use it.

Record the choice in the paper log.

**Step 6. Free the card for the console.** gpg's `scdaemon` keeps the card open, and the console
needs it for itself:

    gpgconf --kill scdaemon

**Step 7. Record the public key.** No PIN is needed:

    bin/vendor-console-yubikey signer info --key-id vk-2026-02 --out vk-2026-02-public.pem

It prints the card (section 11 shows a good output) and `wrote vk-2026-02-public.pem`. The file is
in the same format `licensectl keygen` writes for a file key (a PEM public key with the `Key-Id`
header), so every command that takes `--pub` reads it. `in this build's key set: no` is expected
until a release embeds the key. Write the card serial, the key ID and the fingerprint on paper. Then
build the key set entry:

    bin/licensectl keyset --pub vk-2026-02-public.pem

It prints the JSON entry and `Fingerprint: SHA256:...`, which must equal the paper.

**Step 8. Test the key before it is embedded.**

    bin/vendor-console-yubikey signer test --key-id vk-2026-02 --pub vk-2026-02-public.pem
    bin/vendor-console-yubikey signer test --key-id vk-2026-02 --pub vk-2026-02-public.pem --max-size

Each prints the not-in-key-set warning (expected), the text it signs, asks for the PIN and a touch,
and ends with `smoke test OK (signature verified with key ID vk-2026-02, SHA256:...)`. The license
key signs nothing but licenses; the smoke-test text is the one documented exception and can never
verify as a license. If `--max-size` fails, **stop** and follow section 11: do not embed the key.

**Step 9. Embed the keys and ship a release.** Add the entries of the owner's key, the IT manager's
key and the spare to `internal/license/keys/production.json`, all `"active"`, one entry per key ID
(licensing-vendor.md section 7 shows how to merge entries), and run `make release-keycheck`. Then
follow licensing-vendor.md section 2, steps 2 to 4 (commit, release, `alice license keys` in the
built image, compare every fingerprint with the paper). Sign customer licenses with a new key only
once a release that embeds it has shipped, so customers who update late already trust it. Rebuild
the console's YubiKey build from that release commit: it then knows the keys, and `issue` no longer
needs `--not-in-key-set`.

**Step 10. Check against the embedded key set.**

    bin/vendor-console-yubikey signer info --key-id vk-2026-02 --keyset internal/license/keys/production.json
    bin/vendor-console-yubikey signer test --key-id vk-2026-02 --keyset internal/license/keys/production.json

Expected: `matches key set      yes`, `in this build's key set: yes`, and `smoke test OK (...)`.

**Step 11. Store and record.** Store the spare YubiKey and the Admin PIN papers in separate safe
places, apart from the daily keys. Record in the paper log the date, each serial number, firmware
version, key ID and fingerprint, the touch policy chosen, the Reset Code decision, and where each
paper is.

### Signing with the YubiKey

    vendor-console request show <ID>        # note the hash on the last line
    bin/vendor-console-yubikey issue --request <ID> --hash <hash> --out <customer>.json \
        --signer openpgp --key-id vk-2026-02 --keyset internal/license/keys/production.json

Before any PIN prompt, the console checks that the card holds an Ed25519 signature key equal to the
key set's key for `--key-id`, that this build's key set lists that key as active (a key ID it does
not list yet needs `--not-in-key-set`; one listed with another key, or revoked, is refused), that the
PIN is not blocked and has more than one try left (unless `--last-pin-try`), that a touch is required
(unless `--allow-no-touch`) and that the PIN is asked for every signature. Then it prints the license
and `SHA-256 of the signed bytes: <hex>`, asks `Sign this license? [y/N]` (`--yes` skips only the
question), asks `PIN of the YubiKey <serial> (<n> tries left): `, prints `Touch the YubiKey
now...`, checks the card's signature with the public key and with the product's own license check,
records the license and writes the file: `issued <LICENSE-ID> valid until <YYYY-MM-DD>`.

- **Time limit.** From the display to the card's answer the operator has **2 minutes** (question,
  PIN and touch together). After that nothing is signed and the command says so; run it again.
  Ctrl-C at any point cancels, closes the card and records nothing.
- **The request row is locked** during those 2 minutes: a sales change to that one request waits.
  For the database: do not set `idle_in_transaction_session_timeout` below about **3 minutes** for
  a signer (PostgreSQL's default is off, and nothing in the console sets it). If you want it as a
  safety net, set it per signer login, for example `ALTER ROLE "<login>" SET
  idle_in_transaction_session_timeout = '5min';` (a setting on the group role `vendor_signer` does
  not apply to its members).
- **Card busy.** `pcsc: another program holds the card (often gpg's scdaemon: run gpgconf --kill
  scdaemon)`: run `gpgconf --kill scdaemon` and try again. The console holds the card exclusively
  while it signs, so gpg cannot use it meanwhile. When the console closes the card it resets it, so
  the verified PIN is gone for every program.
- **Linux** needs `pcscd` running: `pcsc: the smart card service is not running (Linux: start
  pcscd)` means it is not (for example `sudo systemctl enable --now pcscd.socket`).
- **Wrong PIN**: `wrong PIN (<n> tries left). Nothing was signed; the PIN is never asked again
  automatically: run the command again to retry`. A blocked PIN is unblocked with the Admin PIN (or
  the Reset Code), with `gpg --card-edit`, `admin`, `passwd`, or `ykman openpgp access unblock-pin`
  where your ykman has it (not run by the author).
- **Not touched in time** (the YubiKey gives up after about 15 seconds): `the YubiKey was not touched
  in time: nothing was signed; run the command again`.

**The signature counter is not the number of licenses.** The card counts every signature it makes
(`signature counter` in `signer info`). It also counts the smoke tests and gpg's own signature at
key generation, and a signature the card made after which no license was recorded: the operator
cancelled or the time ran out just after the touch, the signature failed its check, or the database
did not take the license. The console then says so:

    the card made a signature (its signature counter went up) but no license was recorded by this
    command (...). Check: vendor-console request show <ID>; if the request shows as signed, use:
    vendor-console license export --id <LICENSE-ID> --out FILE. The card's signature counter and the
    number of licenses will differ by one

A license is never recorded without a signature, so for each card the counter is always at least the
number of licenses signed with it. If the database did not confirm the commit, the console says the
outcome is unknown and names the same two commands; run them before signing again.

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

A signer also needs a signing key: the key file (section 2, options 1 and 2) or their own YubiKey
(option 3, after the smoke test of section 11).

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

   For a dump taken from Neon, also create `neon_superuser` and the migration login's role name
   (the login the dump was taken with, for example `vendor_migrator`) as `NOLOGIN` roles in the
   same way (`CREATE ROLE neon_superuser NOLOGIN;`, `CREATE ROLE <migration login> NOLOGIN;`). The
   dump holds grants to them. If `pg_restore` stops with `role "X" does not exist`, create `X`
   `NOLOGIN` on a fresh scratch database (drop the container and start again from this step) and
   run it again. Keep `--exit-on-error` and the grants: do not switch to `--no-acl`, because it
   drops the `vendor_*` grants and breaks steps 6 to 8.

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

   Paste the `<seq>:<hash>` part of the mailed line, or the whole `Audit head: <seq>:<hash>` line
   in quotes: both are accepted.

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
      compromised (section 4). With a YubiKey (option 3), PIN and touch stop silent signing,
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
      section 6); with YubiKeys, run `signer test` with each one (its PIN works) and check the spare is
      where the log says.
- [ ] Decrypt the oldest dump you keep, to prove its passphrase still works.
- [ ] Rotate the passwords of the web service login, the notifier login, the SMTP login and the
      migration login.
- [ ] Plan key rotation: a new key is added at least one release before it is used
      (licensing-vendor.md section 7).
- [ ] Renew the web service's TLS certificate if it is not renewed automatically.
- [ ] Review this runbook against the current commands (`vendor-console` with no arguments prints
      them).

## 11. Smoke test on real hardware (owner-pending)

The YubiKey signer was written against the OpenPGP card specification and tested against a software
card. No real YubiKey has been used yet. The owner runs this test once per operating system a signer
will sign from (Linux, Windows, macOS), with a YubiKey prepared by the ceremony in section 2 (steps
1 to 8; the key need not be embedded yet). Option 3 of section 2 comes into force only after the
platforms in use have passed. Repeat it after a YubiKey firmware change or a new operating system
version on a signer computer.

### What is not proven yet

These assumptions can only be checked on real hardware; the steps below are built to show each one:

1. **Long chained input.** The console sends the license's signed bytes (a few hundred bytes) to the
   card in 255-byte chained parts and assumes the YubiKey signs the whole input as the Ed25519
   message. GnuPG never sends more than 64 bytes, so common tools do not exercise this. Step 4
   (`signer test --max-size`, 600 bytes) is the decisive test.
2. **The card's capability values.** What a YubiKey reports as its maximum command length (DO 7F66)
   and its command chaining bit. If reading 7F66 fails with a card status, `signer info` stops with
   an error naming `get data 7F66`.
3. **The touch timeout status word.** A touch that never comes is assumed to end with status 6982 or
   6985, shown as "the YubiKey was not touched in time". Any other text is a finding.
4. **Reset on close versus scdaemon.** The console holds the card exclusively and resets it when it
   closes it. Whether gpg and scdaemon cope with that afterwards (step 8).
5. **The Windows and macOS builds.** The YubiKey build has been compiled only on Linux. On Windows
   the console builds without cgo (see "Get the binary") but has not been run there.

### Get the binary

The YubiKey build cannot be cross-compiled. Build it on each operating system from a checkout of the
repository with Go installed:

| OS | Needs | Build |
|---|---|---|
| Linux | a C compiler, `pkg-config`, `libpcsclite-dev` (Debian and Ubuntu; `pcsc-lite` on Fedora and Arch) and `pcscd` running (`sudo systemctl enable --now pcscd.socket`) | `make vendor-console-yubikey` |
| macOS | the Xcode command line tools (`xcode-select --install`) for cgo; the system's PC/SC, nothing else | `make vendor-console-yubikey` |
| Windows | the Smart Card service (`SCardSvr`) running (it starts when a reader is plugged in); no C compiler: the PC/SC library loads the system's `winscard.dll` | `go build -trimpath -tags yubikey -o bin\vendor-console-yubikey.exe ./cmd/vendor-console` in PowerShell (no cgo needed, `CGO_ENABLED=0` works) |

The result is `bin/vendor-console-yubikey`. `make vendor-console` builds the normal console, which
has no YubiKey support and refuses every card command with `pcsc: this build has no YubiKey support
(build with -tags yubikey)` (exit code 2).

**Windows.** `go build -tags yubikey ./cmd/vendor-console` builds on Windows (and cross-compiles from
Linux with `GOOS=windows CGO_ENABLED=0`); no C compiler is needed, but the Smart Card service must be
running. It has not been run on a Windows machine yet: the owner's smoke test fills the Windows row.

### The steps

Run them in a terminal (the PIN is read with no echo and is refused from a pipe). Use the YubiKey's
key ID and the public key file from section 2 step 7. Below, `vc` stands for
`bin/vendor-console-yubikey`, `KEY` for `--key-id vk-2026-02 --pub vk-2026-02-public.pem`. Before
starting, run `gpgconf --kill scdaemon`.

**Step 1. No card.** Unplug the YubiKey and run `vc signer info`. Expected: an error naming the
missing reader or card, such as `pcsc: no smart card reader is connected`, or `pcsc: reader not
found: no YubiKey reader; readers present: ...`; exit code 1. On Linux with `pcscd` stopped:
`pcsc: the smart card service is not running (Linux: start pcscd) (during establish context)`.

**Step 2. `vc signer info KEY`** (no PIN). A good output looks like this:

    reader               (the one YubiKey connected)
    card serial          <8 digits>
    signature algorithm  ed25519
    PIN tries left       3
    PIN policy           forced (the PIN is asked for every signature)
    touch policy         on
    signature counter    <a small number>
    max command length   <a number, or unknown>
    command chaining     yes
    public key           <base64>
    fingerprint          SHA256:<64 hex digits>
    matches key set      yes
    in this build's key set: no

Check: `signature algorithm` is `ed25519`; `PIN policy` is `forced`; `touch policy` is `on`,
`fixed`, `cached` or `cached-fixed` (whatever section 2 step 5 chose); `card serial` equals the
`Serial number` of `gpg --card-status` (and should equal the serial of `ykman info`); the fingerprint
equals the paper; `matches key set yes`. Write down the `max command length`, `command chaining` and
`signature counter` values for the report. `in this build's key set: no` is expected before the
release that embeds the key (`yes` after it). Exit code 0; with `matches key set NO` it is 1.

**Step 3. `vc signer test KEY`.** It prints the not-in-key-set warning, the text
`alice-vendor-console smoke test: not a license` and that it is not a license, then
`PIN of the YubiKey <serial> (3 tries left): `. Type the PIN; it prints `Touch the YubiKey now...`
and the YubiKey blinks; touch it. Expected: `smoke test OK (signature verified with key ID
vk-2026-02, SHA256:...)`, exit code 0. `signer info` afterwards shows the counter one higher.

**Step 4. `vc signer test KEY --max-size`. This is the decisive test.** It signs a 600-byte text,
longer than any license. Expected: `smoke test OK (...)` as in step 3.

If it fails with a length refusal (`the card refused the signing input of 600 bytes at the ... part
... status 6700`, `6A80` or `6884`, or `the message has 600 bytes and the card, which has no command
chaining, accepts at most 255`), or with `the card's signature does not verify with the expected
key`, or with any other card status: **STOP.** Do not sign licenses with the YubiKey, and do not try
to work around it by changing the license format or the console. Report the output of `signer info`
and the full error text (below). Option 1 or 2 of section 2 stays in force.

**Step 5. One real license against a throwaway database.** Never against production. A scratch
PostgreSQL on this computer (Docker; on Windows and macOS Docker Desktop):

    docker run -d --rm --name vendor-smoke -e POSTGRES_HOST_AUTH_METHOD=trust \
        -p 127.0.0.1:55433:5432 postgres:<major version>
    export VENDOR_DATABASE_URL='postgres://postgres@127.0.0.1:55433/postgres?sslmode=disable'
    vc migrate
    docker exec -i vendor-smoke psql -U postgres -c 'CREATE ROLE smoke_signer LOGIN IN ROLE vendor_signer;'
    export VENDOR_DATABASE_URL='postgres://smoke_signer@127.0.0.1:55433/postgres?sslmode=disable'
    vc customer add --name "Smoke test"
    vc request add --customer <ID> --installation ALICE-J9N1-MQN8-N17Z-E7FS --targets 5 --features alpha,beta
    vc request show <request ID>            # the hash is the last line
    vc issue --request <request ID> --hash <hash> --out smoke-license.json \
        --signer openpgp KEY --not-in-key-set
    vc verify-licenses --pub vk-2026-02-public.pem

(`ALICE-J9N1-MQN8-N17Z-E7FS` is a made-up but well-formed installation ID. `--not-in-key-set` is
needed until the key is embedded.) Expected: the display lists every field (customer, installation
ID, targets, valid from, valid until, months, features, replaces, license ID, issued at, format, key
ID, card serial) and `SHA-256 of the signed bytes: <64 hex digits>`; `Sign this license? [y/N]`,
answer `y`; the PIN; the touch; `issued <LICENSE-ID> valid until <date>`, exit code 0. Then
`verify-licenses` prints `checked 1, problems 0`. Optionally `licensectl verify --pub
vk-2026-02-public.pem smoke-license.json` prints `OK`. Clean up with `docker stop vendor-smoke` and
delete `smoke-license.json`.

**Step 6. Wrong PIN.** Run `vc signer test KEY` and type a wrong PIN. Expected: `wrong PIN (2 tries
left). Nothing was signed; the PIN is never asked again automatically: run the command again to
retry`, exit code 1, and no second PIN prompt. Then run step 3 again with the right PIN: it succeeds,
and `signer info` shows `PIN tries left 3` again. Never do this step with fewer than 3 tries left.

**Step 7. Touch timeout.** Run `vc signer test KEY`, type the PIN and do **not** touch. Expected
after about 15 seconds: `the YubiKey was not touched in time: nothing was signed; run the command
again`, exit code 1. Write down the exact text if it differs (assumption 3).

**Step 8. Cancel while the card waits for a touch.** Run `vc signer test KEY`, type the PIN, and
press Ctrl-C at `Touch the YubiKey now...` (do not touch). Expected: `signing cancelled: nothing was
signed or recorded and the card connection is closed` at once; the command may take up to about 15
seconds more to exit (the card connection is released only when the card stops waiting for the
touch; at most 20 seconds). Within about 20 seconds after that, `vc signer info KEY` and
`gpg --card-status` both work again (then `gpgconf --kill scdaemon` before the next console
command). Do the same with Ctrl-C at the `Sign this license? [y/N]` question of an `issue` in the
throwaway database: `signing cancelled: ...`, the request stays open, `verify-licenses` still says
`checked 1, problems 0`.

### Results

Fill in one row per run and keep the table in the paper log (or here, in a commit of your own):

| Date | OS and version | YubiKey serial | Firmware | Touch policy | Steps passed | Result | Notes (max command length, chaining, any message that differed) |
|---|---|---|---|---|---|---|---|
| | Linux | | | | | not run | |
| | Windows | | | | | not run | |
| | macOS | | | | | not run | |

### Reporting a problem

Send the output of `vc signer info KEY`, the exact command line, the full error text, the OS and
version, and the `ykman --version` and `gpg --version` output. **Never** include the PIN, the Admin
PIN or the Reset Code, and no database connection string. The public key and fingerprint are not
secret.
