# Vendor console (Phases 1, 3 and 4)

The vendor console keeps the vendor's customers, license requests and issued licenses in a
PostgreSQL database and issues licenses from requests. It is for the vendor only and is never
part of a customer build. Design: `docs/superpowers/specs/2026-10-15-vendor-console-design.md`.

## Set up the database

1. Create the database (for example on Neon, EU region) and a migration login that may create
   roles. The connection string must end in `?sslmode=verify-full`: the console refuses any other
   TLS mode unless the database is on the same computer. Never put the string in a file in this
   repository.
2. With the migration login in `VENDOR_DATABASE_URL`, run `vendor-console migrate`. Use that login
   for nothing else: it owns the tables and is not held back by the grants or the row rules. In
   particular it must not be used as the web service login (below).
3. Create one login per person and add it to one group role:
   `CREATE ROLE "<login>" LOGIN PASSWORD '<password>' IN ROLE vendor_sales;` (sales people),
   `vendor_signer` (the people who sign) or `vendor_owner` (the owner). Each person puts their
   own login in `VENDOR_DATABASE_URL`. The audit log records the login (`session_user`), also
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
replaces. The key passphrase is asked on the terminal. The output file is created before anything
is signed and an existing file is never overwritten; if nothing was issued it is removed again.
A request with a start date more than a day old can no longer be signed: cancel it and make a new
one. If the file cannot be written after signing, `license export` writes it again.

Every change to customers, requests and licenses writes its own audit row in the database, whatever
tool made the change.

## What the audit check proves

`audit-verify` proves that no audit row was edited or removed from the middle of the log. It does
not prove that the newest rows were not removed. A signed checkpoint that closes this gap is
planned for Phase 5.

## Not yet there

YubiKey signing (Phase 2). The owner's audit view on the web page was not built in Phase 4 and
is planned for Phase 5; until then read the `audit` table with SQL and run `audit-verify`.

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

    CREATE ROLE vendor_web_svc LOGIN PASSWORD '<password>' IN ROLE vendor_web;

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

Flags: `--listen :8443` (default), `--tls-cert FILE --tls-key FILE` (both or neither).

    vendor-web --listen :8443 --tls-cert cert.pem --tls-key key.pem

Nothing is logged that contains the connection string, a code or a session cookie.

### TLS and proxy

Serve with your own certificate (`--tls-cert`, `--tls-key`) or put a reverse proxy that ends TLS in
front and let `vendor-web` listen on a private address. The proxy must pass `Origin` and `Host`
unchanged. A form post from another site is refused with 403, and the check compares `Origin` with
`VENDOR_WEB_ORIGIN`.

`X-Forwarded-For` is ignored in this phase. The sign-in rate limit is 10 attempts a minute for each
address (for IPv6, for each /64 network). Behind a reverse proxy it sees only the proxy's address,
so all clients share one counter: anyone can block every sign-in by sending 11 requests a minute.
Until a trusted-proxy option exists, prefer running with `--tls-cert`/`--tls-key` and a firewall in
front instead of a proxy. If you do use a proxy, set a rate limit there too.

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
  Sessions are not worth restoring.

### After a break-in of the web service

The service login cannot sign licenses, but it can add a passkey to any web user and then sign in
as that person. After a suspected break-in of the server that runs `vendor-web`:

1. Review the audit rows with action `webuser.passkey_add` and the `web_credentials` table for
   passkeys that nobody registered.
2. `vendor-console web-user disable NAME` for every affected person (create a new name for them
   later; see above).
3. Rotate the service login's password (`ALTER ROLE vendor_web_svc PASSWORD '...'`) and update
   `VENDOR_WEB_DATABASE_URL`.

## Mail and reminders

`vendor-console notify run` sends the owner an e-mail for every issued license, a weekly summary,
and expiry reminders. It is meant for cron or a systemd timer and does one pass, then exits.

### What you need

The SMTP server is any provider (a transactional service or your own mail server). Environment of
the run:

- `VENDOR_SMTP_ADDR`: `host:port`. Port 465 means TLS from the first byte; any other port must
  offer STARTTLS. The certificate is verified against the system roots.
- `VENDOR_SMTP_FROM`: the sender address, for example `licenses@example.com`. It is the envelope
  sender and the `From:` header; the provider usually has to allow it.
- `VENDOR_SMTP_USER` and `VENDOR_SMTP_PASSWORD`: the login, both or neither. A login is sent only
  over an encrypted connection.
- `VENDOR_DATABASE_URL`: the notifier login (below), with `?sslmode=verify-full`.

If the server offers no STARTTLS the message is not sent, except to a server on the same computer
(a local relay), where no login is sent either. The program announces itself with `EHLO localhost`;
a strict provider that insists on a real host name in EHLO may refuse it, and this cannot be
changed today. Nothing in logs, errors or mails contains the SMTP password or the database URL.

Create the notifier login once, as a role that may create roles:

    CREATE ROLE "<login>" LOGIN PASSWORD '<password>' IN ROLE vendor_notifier;

`vendor_notifier` is created by `vendor-console migrate`. It can read licenses (not the license
file), customers, requests, web users, settings and the audit log, and write only the mail outbox,
the reminder records and the time of the last summary. It cannot sign or change a license.
`notify run` refuses a login that is not a member of it. Do not use the owner or migration login.

Then, as the owner login:

    vendor-console settings set owner_email owner@example.com
    vendor-console settings set timezone Europe/Istanbul     # default when not set
    vendor-console settings show
    vendor-console web-user set-email NAME sales.person@example.com   # "" removes the address

`timezone` is an IANA name; it decides what counts as night and as a day in the summary. `owner_email`
and `timezone` are audited (`settings.set`), the web user's address too (`webuser.email`). Until
`owner_email` is set, mails for the owner wait in the outbox with no recipient and go out on the
first run after it is set. Nothing is lost.

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
changes nothing and sends nothing; it needs no SMTP settings. A SIGTERM stops the run between
mails; a mail the server already accepted is still recorded as sent.

Example systemd units that run it every hour (`/etc/systemd/system/vendor-notify.service` and
`.timer`; keep the environment file readable by root only):

    [Unit]
    Description=Vendor console mail and reminders

    [Service]
    Type=oneshot
    EnvironmentFile=/etc/vendor-console/notify.env
    ExecStart=/usr/local/bin/vendor-console notify run --base-url https://licenses.example.com

    [Timer]
    OnCalendar=hourly
    Persistent=true

    [Install]
    WantedBy=timers.target

`notify.env` holds `VENDOR_DATABASE_URL`, `VENDOR_SMTP_ADDR`, `VENDOR_SMTP_FROM`,
`VENDOR_SMTP_USER` and `VENDOR_SMTP_PASSWORD`. Enable it with `systemctl enable --now vendor-notify.timer`.
Two runs at the same time are safe: each mail is claimed by one of them. The schedule is the timer's
job: the program sends the weekly summary when more than 7 days passed since the last one, so an hourly
timer gives a summary about every 7 days, a few hours late at most when the timer was off.

### What each mail contains

- **Issued license** (written by the database in the same statement that inserts the license, so
  it exists even when someone issues with plain SQL): customer, license ID, targets, valid from and
  until, who signed (the login), key ID and request number. Sent to the owner.
- **Reminder** (subject `License ending in N days: CUSTOMER`): customer, license ID, valid until,
  days left, targets, who requested it, and the Renew link when `--base-url` is given.
- **Weekly summary**: see below.

No mail contains the installation ID, the license file or its content, a customer contact or a
customer e-mail address. Names and license IDs are cut to a bounded length and line breaks are
removed; a customer name with a line break inside is shown on one line in the subject (the body of the
issuance mail keeps the name as stored).

### Weekly summary

Sent to `owner_email`, subject `Weekly summary: N issued, N open requests, N unusual`. It goes out
even on a quiet week, which shows the system is alive. The first one covers the 7 days before the
run; later ones start where the last one ended. All times are in the configured time zone. Sections
(at most 20 lines each, then `... and N more`):

- **Issued since ...**: license, customer, targets, signer, time.
- **Open requests**: number, customer, age in days, who requested.
- **Ending in the next 90 days**: licenses that are not revoked and not replaced by a later one.
- **Failed e-mails**: every mail that was given up on in the last 28 days (kind, created, subject,
  error). A failure stays listed in four summaries in a row.
- **Unusual**: a license issued from 22:00 up to 06:00 local time, or a signer who issued more than 5
  licenses on one local day. If the `timezone` setting is not a known zone, times are shown in UTC
  and the section says so.

If `last_summary_at` (kept by the program in the settings) is missing, unreadable or more than an
hour in the future, a summary is sent at the next run.

### Reminders

A license that is not revoked and not replaced by a later license gets a reminder when it ends
within 90, 60 and 30 days, each threshold once. Recipients: the owner, and the person who requested
the license when that is a web user with an e-mail address who is not disabled (a database login
has no address, so only the owner is told). Catch-up: if a license is found already inside a
threshold that was never sent (the timer was off, or the license was issued 20 days before its
end), only the most urgent unsent threshold is mailed and the less urgent ones are recorded as sent,
so nothing arrives late. A license revoked or replaced before its reminder gets none; one revoked
at the same moment as a run can still produce one reminder.

The **Renew** link in a reminder (and the Renew link on the license list) opens
`/requests/new?renew=<license-id>`: a new request prefilled with the customer, installation,
targets and features of the old license, starting on its end date, for the person to check and
submit. Nothing is stored before that.

### Failed mails

A mail that cannot be sent is tried again with a growing delay of 2^n minutes (2, 4, 8, ... up to 6
hours) after the n-th failure, and is marked failed after 10 failures (about 14 hours of trying). A
message the sender refuses before connecting (a malformed address) is marked failed at once, since a
retry cannot help. Failed mails are listed in the weekly summary. The owner login has no read access
to the outbox; look with the migration login or the notifier login:

    select id, kind, created_at, attempts, last_error from mail_outbox where failed_at is not null order by id desc;

A failed mail is not sent again by itself. Fix the cause (an address, the SMTP login) and let the
next event create a new mail, or ask a developer to reset `failed_at` of that row.

### Address rules

Only plain ASCII addresses `local@domain` are accepted by `settings set owner_email` and
`web-user set-email` (no display names, no quotes), and the address inside `VENDOR_SMTP_FROM` must
follow the same character rules (a display name there is allowed and goes into the header only). No
internationalized (non-ASCII) names, a domain with at least one dot, at most 254 characters. The
sender does not speak SMTPUTF8, and one rule for the program and the database keeps a stored
address from being one that can never be mailed. An address that breaks the rule is refused when you
set it.

### Delivery guarantees

Mail is delivered at least once. If the server accepts a message and the program dies before it can
write that down (a power cut, a lost database connection), the next run sends it again. A message is
never dropped silently: it is sent, waiting, retrying, or marked failed.
