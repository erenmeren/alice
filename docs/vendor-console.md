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
own it does not prove that the newest rows were not removed. A checkpoint kept outside the database
closes that gap: the head `<seq>:<hash>`, the newest audit row at some moment. The weekly summary
notification ends with `Audit head: <seq>:<hash>`, and `vendor-console audit-head` prints the
current one. The notification lives in the same database as the audit log, so it is **not** an
outside witness: someone who can remove audit rows could change it too. The owner copies the head
into the paper log every week (runbook, section 7), and the checks use the head from the paper log:

    vendor-console audit-verify --head <seq>:<hash>   # chain intact and rows up to the checkpoint still there (owner login)
    vendor-console audit-head                         # the current head, for the paper log (owner or notifier login)

`audit-head` always prints the full hash, and the full 64 hex digits are the best check. Because the
head is copied by hand, `--head` also accepts the sequence with only the first 16 or more hex digits
(never fewer); it then checks that the row's hash starts with them and says so: `audit chain OK;
checkpoint <seq> found (first N hex digits only; the full hash is a stronger check)`.

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

`vendor-web` is the web page for sales people and the owner: sign in with a passkey, add customers,
make and cancel license requests, list licenses with their end dates, download signed license files,
read notifications ("Notifications" below). It has
no signing key and its database login cannot write signed licenses, so a break-in cannot create a
valid license. It is for the vendor only and never ships to customers.

### Who does what

The IT manager runs the service. The owner (login in `vendor_owner`) creates the web users: the
sales people (role `sales`) and the owner's own web user (role `owner`, which also sees the owner
notifications). A web user is a row in the database, not a database login. The service is the one database login,
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
`/requests/emergency`, `/requests/ID`, `/licenses`, `/licenses/ID/download`, `/notifications`. The pages are the same for
both roles; the role only decides which notifications a person sees. Any other path shows nothing to a signed-out
visitor except the sign-in page. A person can cancel only their own open requests; everyone can read
all requests.

### Emergency extensions

When a customer's license has lapsed (or is about to) and the renewal is not ready, anyone signed in
can ask for an **emergency extension** from the licenses page: the button appears on an
installation's latest license (not revoked) that ends before an extension signed today could end.
The form shows what is carried over from that license (customer, installation, targets, features)
and takes only the number of days (default 14, at most 30) and a reason, which is required. The
signed license is an ordinary license valid from 00:00 UTC of the signing day for that many days;
the label lives only on the vendor side: in the request (`vendor-console request show` and `request
list` say EMERGENCY EXTENSION), on the YubiKey confirmation, in the audit log (`request.add` and
`license.issue` with `"kind": "emergency"`, the days, the reason and the carried-over license), in
the owner's notification ("Emergency extension issued") and on the license list.

It is signed like any request (`vendor-console issue`, same PIN, touch and confirmation rules). At
signing time it is refused when the carried-over license was revoked meanwhile, or when a license
valid on the start day already runs at least as long (for example the real renewal was signed
first): cancel the request then.

The real renewal: use **Renew** on the extension's row (or on its reminder). It starts where the
extension ends and takes over in Alice at that moment without a gap. A renewal that should start
earlier (backdated to the original lapse) must name the extension in **Replaces license**;
otherwise the console refuses it, because Alice would keep the extension, the later start, in force
with its end warnings until it ends. A renewal starting on the day it is signed needs nothing
special. Rulings: `docs/superpowers/rulings/vendor-emergency-extension.md`.

### Sales people

As the owner login (`VENDOR_DATABASE_URL`):

    vendor-console web-user add NAME           # role sales; prints a one-time enrollment code
    vendor-console web-user add NAME --owner   # role owner (the owner's own web user)
    vendor-console web-user invite NAME        # a new code, for a lost key
    vendor-console web-user disable NAME       # leaves: no new sign-in, sessions end
    vendor-console web-user enable NAME
    vendor-console web-user list               # NAME  ROLE, and "disabled" when disabled

`NAME` has letters, digits, `.`, `_` and `-`, up to 64 characters. The role is set when the person
is added (`add` prints `enrollment code for NAME (role R) ...`) and is recorded in the
`webuser.add` audit row. It cannot be changed afterwards, not from the web page and not with a
command: disable the person and add a new name. The code is valid for 24 hours,
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
- Backup of the database includes the `web_users`, `web_credentials`, `web_enrollments`,
  `web_sessions`, `notifications` and `notification_reads` tables. A restore keeps passkeys working if `VENDOR_WEB_RPID` is unchanged.
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
4. Review the owner notifications of the period, read or not: the intruder could mark them read so
   the bell showed nothing (runbook, section 9, "Break-in of the web service", has the queries).

## Notifications

The owner and the sales people see their notifications inside the sales web page: a bell with the
number of unread notifications and a notifications page. Nothing is sent anywhere: there is no
e-mail, no browser push and no desktop notification. The commands print their own results on the
terminal as usual.

### What creates a notification

- **Issued license** (kind `license.issued`, for the owner). A database trigger writes it in the
  same statement that inserts the license, so it exists even when someone issues with plain SQL,
  and a hostile customer name cannot make the insert fail. Title `License issued: CUSTOMER
  (LICENSE)`; body: customer, license ID, targets, valid from and until, who signed, key ID and
  request number. "Signed by" is the login that inserted the license (the same name the audit log
  records), not the `signed_by` column, which the inserting client can fill in itself; when that
  column holds a different name the body adds `Recorded signer: NAME (differs from the login)`.
  The notifier login cannot write a notification of this kind (row-level security), so it cannot
  pre-empt the real one.
- **Expiry reminder** (kind `license.ending`), created by `notify run` (below) when a license ends
  within 90, 60 and 30 days. Title `License ending in N days: CUSTOMER`; body: customer, license
  ID, valid until, days left, targets, who requested it and `Renew: /requests/new?renew=<license-id>`.
  Severity `warning` at 30 days, `info` before.
- **Weekly summary** (kind `summary.weekly`, for the owner), created by `notify run` once every 7
  days (below).
- **Unusual activity** (kind `activity.unusual`, severity `alert`, for the owner), created together
  with a weekly summary whose Unusual section is not empty. It repeats that section, so it stands out
  in the list instead of hiding inside a routine summary.

No notification contains the installation ID, the license file or its content, or a customer
contact. Names and license IDs are cut to a bounded length, and control characters (line breaks,
escape sequences) and invisible formatting characters (such as bidi overrides) become a space, in
the title and the body, so a customer name with a line break inside is shown on one line and cannot
add a line of its own. The page shows every text escaped.

### Who sees what

Each notification has an audience: `owner`, `sales` or one named web user.

- A web user with the role **owner** sees the owner notifications, the sales notifications and the
  ones addressed to them.
- A web user with the role **sales** sees the sales notifications and the ones addressed to them;
  never an owner notification or another person's.
- A **disabled** web user sees nothing (and cannot sign in).

Issuance, the weekly summary and unusual activity go to the owner. A reminder goes to the owner
and, when the license was requested on the web page by a web user who is enabled and is not an
owner, also to that person. A request made with a database login gets the owner's copy only. No
notification uses the audience `sales` today.

Read state is kept per person: marking a notification read does not mark it for anybody else, and
two owners each have their own unread count. The web service reads and marks notifications only
through four database functions (`web_notifications`, `web_unread_count`, `web_mark_read`,
`web_mark_all_read`); it cannot read the tables directly or write a notification, and the
functions show nothing unless the transaction acts for that same person.

That check protects against bugs in the web service's Go code, not against a break-in: the service
itself sets the acting person (`vendor.actor`) and passes the user id, so whoever controls the
server that runs `vendor-web` (or holds its database login) can act as any enabled web user. They
can read anyone's notifications, the owner's included, and mark them read, so the owner's bell can
stay empty while new notifications arrive; and through the owner notifications they see data that
comes from the audit log (signer logins, issue times, the audit head in the weekly summary). They
still cannot create, change or delete a notification, read the audit table or write a license. See
"After a break-in of the web service" below for what to check.

### The bell and the page

Every signed-in page shows `Notifications (N)` at the top, N being the unread count (no number when
there is nothing unread); it links to `/notifications`. The home page lists the 3 newest unread
notifications. `/notifications` lists the newest 100 (all, or unread only with the filter), each
with its severity (`info`, `warning`, `alert`), its time in UTC, a link to the request or the
license list when it is about one, and the body behind a "details" toggle. "Mark as read" marks one
and "Mark all as read" marks every notification the person can see. Notifications are never deleted
from the web page.

### The owner on the web page

The owner reads the owner notifications as a web user with the role `owner`. Create it once, as the
owner login (`VENDOR_DATABASE_URL`):

    vendor-console web-user add NAME --owner

and enroll a passkey at `/enroll` with the printed code, like every sales person (see "Sales
people"). The owner web user can also use every sales page. The owner keeps the `vendor_owner`
database login for the command line work (`audit show`, `license revoke`, the `web-user` and
`settings` commands); the web role gives no database rights. A role cannot be changed: disable the
person and add a new name. As the owner login, the notifications can also be read with SQL (the
owner may read `notifications`, `notification_reads` and `reminders`, but not change them):

    select id, created_at, kind, audience, title from notifications order by id desc limit 20;

### The periodic job: notify run

`vendor-console notify run` creates the due expiry reminders and the weekly summary, and prunes old
read notifications. It does one pass and exits; run it from a systemd timer (or cron) every hour.

Create the notifier login once, as a role that may create roles:

    CREATE ROLE "<login>" LOGIN IN ROLE vendor_notifier;
    \password "<login>"

`vendor_notifier` is created by `vendor-console migrate`. It reads only the columns it needs:
licenses without the license file, the ID and name of customers (no contact, no notes), the
number, customer, status, requester and time of requests (not their contents), the name, role and
disabled time of web users, the settings, and the time, actor, action and subject of audit rows
(not their details). It adds notifications (never one of kind `license.issued` or with an `issued`
key) and reminder records, stores the time of the last summary and prunes through one database
function. It cannot change or delete a notification otherwise, sign or change a license. `notify
run` refuses a login that is not a member of it. Do not use the owner or migration login.

If the notifier login is stolen, its holder can add notifications that look real (the page does not
show the kind, so a title such as `License issued: ...` looks like an issuance notice), take the next
weekly summary's or unusual-activity alert's key first so the real one is silently skipped, read every
notification body and flood the list. They cannot write an issuance notification, read audit
details, or change or delete notifications. The issuance notices, the audit log and the paper log
stay trustworthy; see the runbook, section 9, "Database credential leak".

    vendor-console notify run
    vendor-console notify run --dry-run

One run does these steps in order, and a failing step does not stop the next ones (the errors are
printed at the end and the exit code is 1):

1. Create expiry reminders (below). Prints `reminders: N created`.
2. Create the weekly summary when one is due (below). Prints `weekly summary: created`,
   `weekly summary: not due`, or `weekly summary: failed` when the step ended with an error (then
   nothing of it was kept: no summary and no new `last_summary_at`, so the next run tries again).
3. Prune old notifications (below). Prints `pruned: N`.

Before the steps it warns on standard error when no enabled web user has the role owner
(`warning: no enabled owner web user exists; owner notifications will wait until one is created`);
the notifications are still created and the owner sees them once an owner web user exists. The
warning never fails the run.

`--dry-run` makes the same selection in a read-only transaction and changes nothing. It prints
`dry run, nothing changed`, `reminders: N to create`, `weekly summary: due` or `not due`, and
`pruned: not run (dry run)`. It needs `VENDOR_DATABASE_URL` with the notifier login too. A SIGTERM
stops a run between licenses; what was committed stays.

Two runs at the same time are safe: every notification has a unique key, so each reminder and each
weekly summary is created once. The schedule is the timer's job: the program creates the weekly
summary when 7 days or more passed since the last one, so an hourly timer gives a summary about every
7 days, a few hours late at most when the timer was off.

Example systemd units that run it every hour (`/etc/systemd/system/vendor-notify.service` and
`/etc/systemd/system/vendor-notify.timer`). Run it as an unprivileged system user, not root
(`useradd --system vendor-notify`):

    # vendor-notify.service
    [Unit]
    Description=Vendor console reminders and weekly summary

    [Service]
    Type=oneshot
    User=vendor-notify
    EnvironmentFile=/etc/vendor-console/notify.env
    ExecStart=/usr/local/bin/vendor-console notify run

    # vendor-notify.timer
    [Unit]
    Description=Run vendor-notify.service every hour

    [Timer]
    OnCalendar=hourly
    Persistent=true

    [Install]
    WantedBy=timers.target

`notify.env` holds one line, `VENDOR_DATABASE_URL=...`, the connection string of the notifier login
with `?sslmode=verify-full`. systemd reads it before switching to `User=`, so it can stay readable
by root only:

    chown root:root /etc/vendor-console/notify.env
    chmod 0600 /etc/vendor-console/notify.env

systemd does not read the file like a shell: a backslash is an escape character even outside
quotes, and a value that starts with a quote is a quoted value. If the password contains a
backslash, a quote, a space or `$`, write the value in double quotes and put a backslash before
each `"` and `\` inside them. Enable it with `systemctl enable --now vendor-notify.timer`. Nothing in
logs or errors contains the database URL.

### Weekly summary

Title `Weekly summary: N issued, N open requests, N unusual`, for the owner. It is created even on a
quiet week, which shows the system is alive. The first one covers the 7 days before the run; later
ones start where the last one ended. All times are in the configured time zone. Sections (at most
20 lines each, then `... and N more`; fewer when the body would pass 4000 characters, the long lists
giving up lines first):

- **Issued since ...**: license, customer, targets, signer, time. Signer and time are the login and
  time of the license's audit row (`license.issue`), written by the database when the license was
  inserted, not the `signed_by` and `issued_at` columns the inserting client can set: a back-dated
  license is listed in the week it was really issued.
- **Open requests**: number, customer, age in days, who requested.
- **Ending in the next 90 days**: licenses that are not revoked, not replaced and not renewed (the
  same rule as the reminders, below).
- **Unusual**, in this order: every license, whatever its dates, that has no `license.issue` audit
  row, which means it was inserted with the database triggers turned off or its audit row is gone
  (`N license(s) have no issue audit row (possible tampering or disabled triggers)`); a signer who
  issued more than 5 licenses on one local day; a license issued from 22:00 up to 06:00 local time.
  Both of the last two are judged by the audit time and login. When lines must be dropped to fit,
  the night lines go first and the tampering line last. If the `timezone` setting is not a known
  zone, times are shown in UTC and the section says so.

The last line is `Audit head: <seq>:<hash>`, the newest audit row when the summary was made (see
"What the audit check proves"; it is missing only while the audit log is empty).

The time zone is a setting, as the owner login:

    vendor-console settings set timezone Europe/Istanbul     # default when not set
    vendor-console settings show

`timezone` is an IANA name; it decides what counts as night and as a day in the summary, and its
changes are audited (`settings.set`). It is the only setting; when it is not set, `settings show`
prints `timezone (not set; Europe/Istanbul is used)`. `settings show` also prints
`last_summary_at`, which the program keeps: if it is missing, unreadable or more than an hour in the
future, a summary is created at the next run. Storing it writes a `settings.set` audit row for
`last_summary_at` with the notifier login as the actor, one per summary.

### Reminders

A license that is not revoked, not replaced and not renewed gets a reminder when it ends within
90, 60 and 30 days, each threshold once. Renewed means a later license, not revoked, for the same
customer and installation that ends after it, whether or not it names the old one as replaced; so
issuing the renewal stops the reminders for the old license, and the new one gets its own in time.
Catch-up: if a license is found already inside a threshold that never fired (the timer was off, or
the license was issued 20 days before its end), only the most urgent threshold creates a
notification and the less urgent ones are recorded as done, so nothing arrives late. A license
revoked, replaced or renewed before its reminder gets none; one revoked at the same moment as a run
can still produce one reminder.

The **Renew** path in a reminder (and the Renew link on the license list) opens
`/requests/new?renew=<license-id>`: a new request prefilled with the customer, installation,
targets and features of the old license, starting on its end date, for the person to check and
submit. Nothing is stored before that.

### Pruning

Each run removes notifications older than 180 days that at least one web user has read (their read
marks go with them). An unread notification stays whatever its age, so nothing disappears unseen.
With two owners, one owner's read is enough. The 180 days are enforced by the database: no caller
can prune younger ones. The reminder records are not pruned.
