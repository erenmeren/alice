# Vendor console

The vendor console keeps the vendor's customers, license requests and issued licenses in a
PostgreSQL database and issues licenses from requests. It is for the vendor only and is never
part of a customer build. Design: `docs/superpowers/specs/2026-10-15-vendor-console-design.md`.

Operations (roles, key ceremony, onboarding and offboarding, a lost signing key, backups and the
restore drill, tamper checks, monitoring, incidents, quarterly and yearly checks):
[vendor-console-operations.md](vendor-console-operations.md).

## Set up the database

1. Create the database (for example on Neon, EU region) and a migration login that may create
   roles. The connection string must end in `?sslmode=verify-full`: the console refuses any other
   TLS mode unless the database is on the same computer. Never put the string in a file in this
   repository.
2. With the migration login in `VENDOR_DATABASE_URL`, run `vendor-console migrate`. Use that login
   for nothing else: it owns the tables and is not held back by the grants or the row rules. In
   particular it must not be used as the web service login (below).
3. Create one login per person and add it to one group role, in `psql`:
   `CREATE ROLE "<login>" LOGIN IN ROLE vendor_sales;` (sales people), `vendor_signer` (the people
   who sign) or `vendor_owner` (the owner), then `\password "<login>"` to set its password (psql asks
   for it and sends it hashed; a password typed inside an SQL statement lands in `~/.psql_history`).
   The person can choose their own later with `\password` in their own session. Each person puts
   their own login in `VENDOR_DATABASE_URL`. The audit log records the login (`session_user`), also
   when someone runs `SET ROLE` to their group.

## Daily use

    vendor-console customer add --name "Acme Ltd"
    vendor-console request add --customer 1 --installation ALICE-... --targets 5
    vendor-console request show 1          # note the hash on the last line
    vendor-console issue --request 1 --hash <hash> --key alice-license-private.pem --out acme.json
    vendor-console license export --id LIC-... --out acme-again.json   # the same file again
    vendor-console request cancel 1
    vendor-console audit-verify

`issue` refuses when the request changed after you looked at it (the hash no longer matches),
when the request is no longer open, and when a correction would end earlier than the license it
replaces. The key passphrase is asked on the terminal (signing with a YubiKey instead: "Signing
with a YubiKey" below). The output file is created before anything
is signed and an existing file is never overwritten; if nothing was issued it is removed again.
A request with a start date more than a day old can no longer be signed: cancel it and make a new
one. If the file cannot be written after signing, `license export` writes it again.

Every change to customers, requests and licenses writes its own audit row in the database, whatever
tool made the change.

## What the audit check proves

`audit-verify` proves that no audit row was edited or removed from the middle of the log. On its
own it does not prove that the newest rows were not removed. The weekly summary mail closes that
gap: its last line is `Audit head: <seq>:<hash>`, the newest audit row when it was written, and the
owner's mailbox keeps it outside the database. As the owner login:

    vendor-console audit-verify --head <seq>:<hash>   # chain intact and rows up to the checkpoint still there
    vendor-console audit-head                         # the current head, to keep elsewhere (owner or notifier login)

A mismatch means rows up to the checkpoint were removed or replaced after it was taken; see the
runbook, section 7, for what to do.

## Owner commands

As the owner login:

    vendor-console audit show [--since YYYY-MM-DD] [--actor NAME] [--action PREFIX] [--limit 50] [--details]
    vendor-console license revoke --id LIC-... --reason "customer cancelled"
    vendor-console verify-licenses --keyset internal/license/keys/production.json   # or --pub FILE (repeatable)

- `audit show` prints audit rows newest first (sequence, UTC time, actor, action, subject), at most
  1000 (`--limit`, default 50). `--action` matches a prefix (`license.`). `--details` adds each
  row's details. Installation IDs are never printed; they appear as `inst#` and 8 hex digits (a
  fingerprint, the same for the same ID). Only the owner login can run `audit show` and
  `audit-verify`. The web service cannot read the audit log at all, so there is no audit page on the
  sales web page. The notifier login has a narrow read: the time, actor, action and subject columns
  (no details), for the weekly summary, and the head through `audit-head`.
- `license revoke` marks the license revoked in the vendor records: reminders stop and the reason
  goes into the `license.revoke` audit row. The customer's installation is **not** affected:
  license files are checked offline. Revoking a signing key is a product release (runbook,
  section 4).
- `verify-licenses` re-checks every stored license (after a restore, or any time): the file hash,
  the signature against the given keys (a revoked key judged at the license's own issue date) and
  that the row's license ID, installation, key ID, dates, targets and replaced license agree with
  the signed file. It does not compare the customer name (names may be corrected after issue) or
  the features. It prints `checked N, problems M`, one line per problem, and exits 1 when there are
  problems; on an empty database it also prints `WARNING: no licenses found`. Any login that can
  read the license files may run it (owner, signer, sales).

## Signing with a YubiKey

`issue --signer openpgp` signs with the Ed25519 key on a YubiKey's OpenPGP application instead of a
key file. It is built and tested against a software card, but has not yet run against a real
YubiKey: until the owner's hardware smoke test (runbook, section 11) has passed, the passphrase key
file stays in use. The key ceremony (PINs, `forcesig`, touch policy, generating the key on the card,
embedding the public key) is in the runbook, section 2.

**Build.** The normal build (`make vendor-console`, no cgo) has no YubiKey support: `issue --signer
openpgp`, `signer info` and `signer test` stop with `pcsc: this build has no YubiKey support (build
with -tags yubikey)` and exit code 2. The YubiKey build uses the build tag `yubikey`. On Linux and
macOS it needs cgo and is built natively with `make vendor-console-yubikey` (output
`bin/vendor-console-yubikey`): Linux needs `libpcsclite-dev` and a running `pcscd`; macOS uses the
system's PC/SC. On Windows it needs no cgo: `go build -trimpath -tags yubikey -o
bin\vendor-console-yubikey.exe ./cmd/vendor-console` on Windows, or `make
vendor-console-yubikey-windows` from Linux or macOS (output `bin/vendor-console-yubikey.exe`); the
Smart Card service must be running. The customer-facing `alice` binary never contains this code.

    vendor-console issue --request 1 --hash <hash> --out acme.json \
        --signer openpgp --key-id vk-2026-02 --keyset internal/license/keys/production.json

- `--key-id ID` and either `--pub FILE` (a public key file with that key ID) or `--keyset FILE`
  (the active entry for that ID) name the key the card must hold. `--key` belongs to `--signer
  file` and is refused here; the card flags are refused with `--signer file`.
- Before any PIN prompt it refuses a card whose signature key is missing, not Ed25519 or not the
  named key; a key ID that this build's key set lists with another key or as revoked; a blocked PIN;
  a PIN with one try left (unless `--last-pin-try`); a card whose touch policy is not `on` or
  `fixed` (unless `--allow-no-touch`: `off` signs without a touch, and `cached` or `cached-fixed`
  let a second signature through without a touch for about 15 seconds); and a card that does not
  ask for the PIN for every signature (GnuPG's `forcesig`). A key ID this build's key set does not
  list yet is refused unless `--not-in-key-set` is given (customers' builds will not accept such a
  license until a release with the key ships).
- `--reader NAME` picks the reader when more than one YubiKey is connected (default: the one reader
  whose name contains "yubi").
- It prints every field of the license, `signed bytes: <N> bytes` and `SHA-256 of the signed bytes:
  <hex>`, the bytes the card receives, then asks `Sign this license? [y/N]` (`--yes` skips only the
  question; the license is still shown), then `PIN of the YubiKey <serial> (<n> tries left): ` and
  `Touch the YubiKey now...`. A wrong PIN is never asked again: the command ends and says how many
  tries are left.
- It sends at most 1024 signed bytes to the card, the size `signer test --max-size` proves. A
  longer license (possible with a long customer name and many long feature names; the largest is
  about 3.3 KB) is refused after the display and before the PIN prompt, until the owner raises the
  limit (`sign.MaxSignedBytes`) after a smoke test with the larger size.
- The signature is checked with the public key and with the product's own license check, and the
  signed license must be the one whose SHA-256 was shown, before anything is recorded. The
  question, the PIN and the touch together have 2 minutes; Ctrl-C cancels. The request row stays
  locked meanwhile (runbook, section 2, for the database setting this needs).
- The display and the SHA-256 protect against a request changed in the database and against
  mistakes; they do not protect against malware on the signer computer, which can show the real
  license and send its own to the card. Such a license is never recorded; the card's signature
  counter is the check (runbook, section 2, "Counter reconciliation").
- If the card signed but no license was recorded (a cancel just after the touch, for example), the
  command says so: the card's signature counter and the number of licenses then differ by one. A
  Ctrl-C after `Touch the YubiKey now...` says `signing cancelled: no license was recorded; if the
  key was touched its signature counter may have gone up`.
- The PIN buffers of the console are cleared after use. Only the console's own buffers: the terminal
  library, pcscd or WinSCard may keep copies it cannot clear.

Two more commands, YubiKey build only:

    vendor-console signer info [--reader NAME] [--key-id ID [--pub FILE | --keyset FILE]] [--out FILE]
    vendor-console signer test --key-id ID (--pub FILE | --keyset FILE) [--reader NAME] [--max-size]
        [--last-pin-try] [--allow-no-touch]

- `signer info` needs no PIN. It prints the card serial, signature algorithm, PIN tries left, PIN
  policy, touch policy, signature counter, maximum command length, command chaining, the public key
  and its fingerprint; with `--key-id` and `--pub`/`--keyset` whether the card holds that key (exit
  code 1 when it does not), and with `--key-id` whether this build's key set lists it. `--out FILE`
  (needs `--key-id`) writes the card's public key as a public key file in the format `licensectl
  keygen` writes, which `licensectl keyset --pub` and every `--pub` flag read; it never overwrites a
  file.
- `signer test` makes the card checks `issue` makes (the named key, PIN tries, touch policy, PIN
  forced), asks for the PIN and a touch, signs the fixed text `alice-vendor-console smoke test: not
  a license` (with `--max-size` a 1024-byte text starting with it, the longest signed bytes `issue`
  sends) and verifies the signature. For a key ID this build's key set does not list yet it only
  warns (no `--not-in-key-set` needed); a key ID listed with another key or as revoked is refused.
  The vendor console signs nothing but licenses with the license key, except these smoke-test texts;
  gpg also certifies the key once when it is generated on the card with gpg (runbook, section 2).
  None of them is a license or can verify as one.

## Sales web service

`vendor-web` is the web page for sales people: sign in with a passkey, add customers, make and
cancel license requests, list licenses with their end dates, download signed license files. It has
no signing key and its database login cannot write signed licenses, so a break-in cannot create a
valid license. It is for the vendor only and never ships to customers.

### Who does what

The IT manager runs the service. The owner (login in `vendor_owner`) creates the sales people. A
sales person is a row in the database, not a database login. The service is the one database login,
and it acts for the signed-in person inside each transaction. The audit log shows `web:<name>`.

### Database login for the service

Run once, as a role that may create roles:

    CREATE ROLE vendor_web_svc LOGIN IN ROLE vendor_web;
    \password vendor_web_svc

Give it no other membership. In particular it must never be a member of `vendor_signer` or
`vendor_owner`. The role `vendor_web` is created by `vendor-console migrate`. It is a member of
`vendor_sales` only. It cannot insert licenses, read the audit log or call the audit functions,
except `web_audit_login`, which records a sign-in for an enabled user. The service reads the
person's name from the session, so only logins that inherit `vendor_web` can act under a `web:`
name; any other login (including a superuser and the migration login) still appears under its own
name. Do not use the migration login as the service login.

### Start

Environment:

- `VENDOR_WEB_DATABASE_URL`: connection string of the service login. It must end in
  `?sslmode=verify-full` unless the database is on the same computer.
- `VENDOR_WEB_ORIGIN`: the public address, for example `https://licenses.example.com`. Plain http
  is accepted for localhost only.
- `VENDOR_WEB_RPID`: the passkey domain. Default: the host of the origin. Passkeys are bound to
  it; changing it later makes every enrolled passkey useless.

Flags: `--listen :8443` (default), `--tls-cert FILE --tls-key FILE` (both or neither),
`--trusted-proxy CIDR` (repeatable, see below).

    vendor-web --listen :8443 --tls-cert cert.pem --tls-key key.pem

Nothing is logged that contains the connection string, a code or a session cookie.

### TLS and proxy

Serve with your own certificate (`--tls-cert`, `--tls-key`) or put a reverse proxy that ends TLS in
front and let `vendor-web` listen on a private address. The proxy must pass `Origin` and `Host`
unchanged. A form post from another site is refused with 403, and the check compares `Origin` with
`VENDOR_WEB_ORIGIN`.

The sign-in rate limit is 10 attempts a minute for each client address (for IPv6, for each /64
network). Behind a reverse proxy, name the proxy with `--trusted-proxy`:

    vendor-web --listen 127.0.0.1:8443 --trusted-proxy 127.0.0.1/32
    vendor-web --listen 10.0.0.5:8443 --trusted-proxy 10.0.0.0/24 --trusted-proxy fd00::/64

A value is a CIDR range or a single address; a range that covers every address (`0.0.0.0/0`,
`::/0`) is refused. Only when the connection comes from a trusted range is `X-Forwarded-For` read,
and then the client is the right-most address in it that is not itself in a trusted range (entries
further left are written by the client and never chosen over it). An entry that cannot be read ends
the walk and the request counts against the proxy's own address. The proxy must append the
client's address to `X-Forwarded-For`. The header is used for the rate limit only.

Without `--trusted-proxy`, `X-Forwarded-For` is ignored. Behind a proxy the limiter then sees only
the proxy's address, so all clients share one counter: anyone can block every sign-in by sending 11
requests a minute. Either set `--trusted-proxy`, or run with `--tls-cert`/`--tls-key` and a
firewall in front instead of a proxy. Setting a rate limit on the proxy too does no harm.

### Cookies and sessions

The session cookie is `__Host-vsession` over https, `vsession` for the localhost http origin. It is
`HttpOnly`, `Secure` (not on http localhost), `SameSite=Strict`. A session ends after 8 hours, or
after 30 minutes without a request. The passkey ceremony uses a short cookie (`__Host-vceremony`
over https, `vceremony` for the localhost http origin; `Path=/`, 5 minutes). Every page carries a Content-Security-Policy that allows only files from the service
itself: no inline script or style.

### Pages

`/login` and `/enroll` need no session. After sign-in: `/` (home), `/customers`, `/requests/new`,
`/requests/ID`, `/licenses`, `/licenses/ID/download`. Any other path shows nothing to a signed-out
visitor except the sign-in page. A person can cancel only their own open requests; everyone can read
all requests.

### Sales people

As the owner login (`VENDOR_DATABASE_URL`):

    vendor-console web-user add NAME       # prints a one-time enrollment code
    vendor-console web-user invite NAME    # a new code, for a lost key
    vendor-console web-user disable NAME   # leaves: no new sign-in, sessions end
    vendor-console web-user enable NAME
    vendor-console web-user list

`NAME` has letters, digits, `.`, `_` and `-`, up to 64 characters. The code is valid for 24 hours,
works once, and is shown once; only a hash is stored. Give it to the person over a channel you
trust. The person opens `/enroll`, types the code and registers a passkey (a security key or the
phone or computer's own). The authenticator must verify the person with a PIN or biometrics. Adding
a passkey never removes the others, so a lost key is handled with `invite`. There is no command to
remove one passkey in this phase. Keep a person who must lose all access `disabled` (this ends
their sessions at once); a stolen key stays on the person's record, so do not `enable` that person
again. Create a new name instead.

### Development on one computer

Use `VENDOR_WEB_ORIGIN=http://localhost:8443` and a database on the same computer. Passkeys work on
`localhost` over http; use the name `localhost`, not `127.0.0.1`.

### Operation notes

- Run one instance. The passkey ceremony state is kept in memory, so a second instance behind a
  load balancer would fail some sign-ins. Restarting loses only ceremonies in progress.
- Backup of the database includes the `web_users`, `web_credentials`, `web_enrollments` and
  `web_sessions` tables. A restore keeps passkeys working if `VENDOR_WEB_RPID` is unchanged.
  Sessions are not worth restoring. Backups and the restore drill: runbook, section 6.

### After a break-in of the web service

The service login cannot sign licenses, but it can add a passkey to any web user and then sign in
as that person. After a suspected break-in of the server that runs `vendor-web`:

1. Review the audit rows with action `webuser.passkey_add`
   (`vendor-console audit show --action webuser.passkey_add --details`) and the `web_credentials`
   table for passkeys that nobody registered.
2. `vendor-console web-user disable NAME` for every affected person (create a new name for them
   later; see above).
3. Rotate the service login's password (in `psql` as the migration login: `\password vendor_web_svc`)
   and update `VENDOR_WEB_DATABASE_URL`.

## Mail and reminders

`vendor-console notify run` sends the owner an e-mail for every issued license, a weekly summary,
and expiry reminders. It is meant for cron or a systemd timer and does one pass, then exits.

### What you need

The SMTP server is any provider (a transactional service or your own mail server). Environment of
the run:

- `VENDOR_SMTP_ADDR`: `host:port`. Port 465 means TLS from the first byte; any other port must
  offer STARTTLS. The certificate is verified against the system roots, also on a local relay: a
  relay on the same computer that offers STARTTLS with a self-signed certificate fails that check
  and every mail is retried and finally marked failed. Give such a relay a certificate from a trusted CA, or turn its
  STARTTLS off (see below).
- `VENDOR_SMTP_FROM`: the sender address, for example `licenses@example.com`. It is the envelope
  sender and the `From:` header; the provider usually has to allow it.
- `VENDOR_SMTP_USER` and `VENDOR_SMTP_PASSWORD`: the login, both or neither. A login is sent only
  over an encrypted connection.
- `VENDOR_DATABASE_URL`: the notifier login (below), with `?sslmode=verify-full`. Also needed
  for `--dry-run`, which connects with the same notifier login.

If the server offers no STARTTLS the message is not sent, except to a server on the same computer
(a local relay), where no login is sent either. The program announces itself with `EHLO localhost`;
a strict provider that insists on a real host name in EHLO may refuse it, and this cannot be
changed today. Nothing in logs, errors or mails contains the SMTP password or the database URL.

Create the notifier login once, as a role that may create roles:

    CREATE ROLE "<login>" LOGIN IN ROLE vendor_notifier;
    \password "<login>"

`vendor_notifier` is created by `vendor-console migrate`. It reads only the columns it needs:
licenses without the license file, the ID and name of customers (no contact, no notes), the
number, customer, status, requester and time of requests (not their contents), the name, address
and disabled time of web users, the settings, and the time, actor, action and subject of audit
rows (not their details). It adds mail to the outbox and may change only its delivery columns
(recipients, sent, attempts, last error, failed, next attempt), never a subject or body; it adds
reminder records and stores the time of the last summary. It cannot sign or change a license.
`notify run` refuses a login that is not a member of it. Do not use the owner or migration login.

Then, as the owner login:

    vendor-console settings set owner_email owner@example.com
    vendor-console settings set timezone Europe/Istanbul     # default when not set
    vendor-console settings show
    vendor-console web-user set-email NAME sales.person@example.com   # "" removes the address

`timezone` is an IANA name; it decides what counts as night and as a day in the summary. `owner_email`
and `timezone` are audited (`settings.set`), the web user's address too (`webuser.email`). Until
`owner_email` is set, mails for the owner wait in the outbox with no recipient and go out on the
first run after it is set. Nothing is lost, but nothing is merged either: a weekly summary is still
created every week while no address is set, and all the waiting summaries go out together on that
first run.

### Run it

    vendor-console notify run --base-url https://licenses.example.com
    vendor-console notify run --dry-run

One run does these steps in order, and a failing step does not stop the next ones (the errors are
printed at the end and the exit code is 1; it is also 1 when a message was marked failed):

1. Fill the recipient of waiting mails from `owner_email`.
2. Create expiry reminders (below).
3. Create the weekly summary when one is due (below).
4. Send every due mail in the outbox, oldest first.

It prints one line for each step with counts. `--base-url` is the public address of `vendor-web`;
it is used for the Renew link in reminders and without it reminders have no link. `--dry-run`
prints how many recipients, reminders and mails there would be, whether a summary is due, and
changes nothing and sends nothing; it needs no SMTP settings, but it does need
`VENDOR_DATABASE_URL` with a notifier login. A SIGTERM stops the run between mails; a mail the
server already accepted is still recorded as sent.

A mail is due when its next-attempt time, set by the database clock when the mail is created, is
not after the run's own time, taken from the host clock. If the host clock is behind the database
clock, a mail created during a run (an issuance mail, a reminder, the summary) may wait until the
next run. Keep both clocks synchronised (NTP).

Example systemd units that run it every hour (`/etc/systemd/system/vendor-notify.service` and
`.timer`). Run it as an unprivileged system user, not root (`useradd --system vendor-notify`):

    [Unit]
    Description=Vendor console mail and reminders

    [Service]
    Type=oneshot
    User=vendor-notify
    EnvironmentFile=/etc/vendor-console/notify.env
    ExecStart=/usr/local/bin/vendor-console notify run --base-url https://licenses.example.com

    [Timer]
    OnCalendar=hourly
    Persistent=true

    [Install]
    WantedBy=timers.target

`notify.env` holds `VENDOR_DATABASE_URL`, `VENDOR_SMTP_ADDR`, `VENDOR_SMTP_FROM`,
`VENDOR_SMTP_USER` and `VENDOR_SMTP_PASSWORD`, one `NAME=value` per line. systemd reads it before
switching to `User=`, so it can stay readable by root only:

    chown root:root /etc/vendor-console/notify.env
    chmod 0600 /etc/vendor-console/notify.env

systemd does not read the file like a shell: a backslash is an escape character even outside
quotes, and a value that starts with a quote is a quoted value. So write every value that contains
a backslash, a quote, a space or `$` (common in passwords and in a `From` with a display name) in
double quotes, and inside them put a backslash before each `"` and `\`, for example
`VENDOR_SMTP_FROM="Licenses <licenses@example.com>"`. A line that starts with `#` is a comment.
Enable it with `systemctl enable --now vendor-notify.timer`.
Two runs at the same time are safe: each mail is claimed by one of them. The schedule is the timer's
job: the program sends the weekly summary when more than 7 days passed since the last one, so an hourly
timer gives a summary about every 7 days, a few hours late at most when the timer was off.

### What each mail contains

- **Issued license** (written by the database in the same statement that inserts the license, so
  it exists even when someone issues with plain SQL): customer, license ID, targets, valid from and
  until, who signed, key ID and request number. Sent to the owner. "Signed by" is the login that
  inserted the license (the same name the audit log records), not the `signed_by` column, which
  the inserting client can fill in itself. When that column holds a different name the mail adds a
  line `Recorded signer: NAME (differs from the login)`.
- **Reminder** (subject `License ending in N days: CUSTOMER`): customer, license ID, valid until,
  days left, targets, who requested it, and the Renew link when `--base-url` is given.
- **Weekly summary**: see below.

No mail contains the installation ID, the license file or its content, a customer contact or a
customer e-mail address. Names and license IDs are cut to a bounded length, and control characters
(line breaks, escape sequences) and invisible formatting characters (such as bidi overrides) are
removed or turned into a space, in the subject and the body, so a customer name with a line break
inside is shown on one line and cannot add a line of its own.

### Weekly summary

Sent to `owner_email`, subject `Weekly summary: N issued, N open requests, N unusual`. It goes out
even on a quiet week, which shows the system is alive. The first one covers the 7 days before the
run; later ones start where the last one ended. All times are in the configured time zone. Sections
(at most 20 lines each, then `... and N more`):

- **Issued since ...**: license, customer, targets, signer, time. Signer and time are the login and
  time of the license's audit row (`license.issue`), written by the database when the license was
  inserted, not the `signed_by` and `issued_at` columns the inserting client can set: a back-dated
  license is listed in the week it was really issued.
- **Open requests**: number, customer, age in days, who requested.
- **Ending in the next 90 days**: licenses that are not revoked, not replaced and not renewed (the
  same rule as the reminders, below).
- **Failed e-mails**: every mail that was given up on in the last 28 days (kind, created, subject,
  error). A failure stays listed in four summaries in a row.
- **Unusual**: a license issued from 22:00 up to 06:00 local time, or a signer who issued more than 5
  licenses on one local day, both judged by the audit time and login. If the `timezone` setting is
  not a known zone, times are shown in UTC and the section says so.
  The section also counts every license, whatever its dates, that has no `license.issue` audit row,
  which means it was inserted with the database triggers turned off or its audit row is gone
  (`N license(s) have no issue audit row (possible tampering or disabled triggers)`).

If `last_summary_at` (kept by the program in the settings) is missing, unreadable or more than an
hour in the future, a summary is sent at the next run. Storing it writes a `settings.set` audit row
for `last_summary_at` with the notifier login as the actor, one per summary.

### Reminders

A license that is not revoked, not replaced and not renewed gets a reminder when it ends within
90, 60 and 30 days, each threshold once. Renewed means a later license, not revoked, for the same
customer and installation that ends after it, whether or not it names the old one as replaced; so
issuing the renewal stops the reminders for the old license, and the new one gets its own in time.
Recipients: the owner, and the person who requested the license when that is a web user with an
e-mail address who is not disabled (a database login has no address, so only the owner is told).
Each recipient gets a separate mail, so a requester's mailbox that refuses mail does not stop the
owner's copy; the owner's copy waits for `owner_email` like other owner mail. Catch-up: if a
license is found already inside a threshold that was never sent (the timer was off, or the license was issued 20 days before its
end), only the most urgent unsent threshold is mailed and the less urgent ones are recorded as sent,
so nothing arrives late. A license revoked, replaced or renewed before its reminder gets none; one
revoked at the same moment as a run can still produce one reminder.

The **Renew** link in a reminder (and the Renew link on the license list) opens
`/requests/new?renew=<license-id>`: a new request prefilled with the customer, installation,
targets and features of the old license, starting on its end date, for the person to check and
submit. Nothing is stored before that.

### Failed mails

A mail that cannot be sent is tried again with a growing delay of 2^n minutes (2, 4, 8, ... up to 6
hours) after the n-th failure, and is marked failed after 10 failures (about 14 hours of trying). A
message the sender refuses before connecting (a malformed address) is marked failed at once, since a
retry cannot help. Failed mails are listed in the weekly summary, and at any time with

    vendor-console notify failed      # owner or notifier login

The owner login can also read the outbox (and the reminder records) with SQL, but not change them:

    select id, kind, to_addrs, created_at, attempts, last_error from mail_outbox where failed_at is not null order by id desc;

A failed mail is not sent again by itself. Fix the cause (an address, the SMTP login) and either let
the next event create a new mail or put the mail back in the queue, with the notifier login:

    vendor-console notify retry ID

The next `notify run` sends it with a fresh attempt count. Only a failed, unsent mail is changed;
the owner login is refused. Each retry writes a `mail.retry` audit row. That row is an audit trail,
not a tamper-proof control: the notifier login may add mail to the outbox, so it can also queue a
mail without a retry row.

### Address rules

`settings set owner_email` and `web-user set-email` accept only a plain ASCII address
`local@domain` (no display name, no quotes, no internationalized characters) whose domain has at
least one dot, at most 254 characters; the database enforces the same rule, so a stored address is
always one the sender can mail. An address that breaks the rule is refused when you set it.

`VENDOR_SMTP_FROM` must be a plain ASCII `local@domain` too, but it may carry a display name
(`Licenses <licenses@example.com>`), which goes into the header only. The dot and length rules
above are for the stored addresses; they do not apply to `VENDOR_SMTP_FROM`. The sender does not
speak SMTPUTF8.

### Delivery guarantees

Mail is delivered at least once. If the server accepts a message and the program dies before it can
write that down (a power cut, a lost database connection), the next run sends it again. A message is
never dropped silently: it is sent, waiting, retrying, or marked failed.
