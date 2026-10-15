# Vendor console: design (draft)

Status: all five phases are built in code. Phase 2 (YubiKey signing) has not yet run on a real
YubiKey: the hardware smoke test is owner-pending (`docs/vendor-console-operations.md` section 11).
O1 and O3 are resolved by the Phase 2 plan's rulings. See the status table in section 10.
Date: 2026-10-15.

## 1. Purpose

Today the vendor side of licensing is `cmd/licensectl`, an offline command line tool with a
passphrase-protected key file and a signed CSV ledger (`internal/license/issuer`). It works for
one person. It does not fit the real setup:

- the owner lives in the UK; sales and the IT manager (the second signer) are in Istanbul;
- sales people need to record customers, ask for licenses and see when licenses end;
- the owner must be able to see who issued what, without approving each license;
- signing keys should live on YubiKeys, not in files.

The vendor console adds a shared record (customers, license requests, issued licenses, audit), a
signing application that uses YubiKeys, and a small web page for sales. It does not change the
license file format or what the customer's Alice verifies, except for adding public keys to the
embedded key set (section 8).

## 2. Decisions already made

| Decision | Choice |
|---|---|
| Signing | Only with a YubiKey (OpenPGP application, Ed25519; PIV is not built, Phase 2 ruling 1). No online key, no KMS. The passphrase key file stays until the hardware smoke test passes. |
| Signers | The owner and the IT manager, each with their own YubiKey. A third key is a spare. |
| Approval | No owner approval step. Every issuance notifies the owner. |
| Sales | Separate people. They create requests and download signed licenses. They cannot sign. |
| Database | PostgreSQL on Neon (EU region). SQLite is not used. |
| Signing app | One Go command line program for Linux, Windows and macOS. No local browser UI: the confirmation is shown on the terminal (Phase 2 ruling 3). |
| Sales UI | A small web page, WebAuthn login. It holds no signing key. |
| Code location | This repository, under `cmd/` and `internal/vconsole/`, never shipped to customers. |

## 3. Components

```
 Sales (Istanbul)           Signers (owner UK, IT manager Istanbul)
      |                                   |
  web page  ----------- Neon (Postgres) ----------  signing app (local, YubiKey)
  (request, download,       customers, requests,     shows the full license,
   expiry list)             issued licenses,         PIN + touch, writes the
                            hash-chained audit       signed file back
```

- **Signing app** (`cmd/vendor-console`, new). Local command line program. Reads open requests
  from Neon, shows the exact license content on the terminal, signs on the YubiKey, writes the
  signed license and an audit entry back. Also usable by a signer to create a license directly.
  The YubiKey support is compiled only with the build tag `yubikey` (cgo and PC/SC on Linux and
  macOS); the default build has none.
- **Sales web service** (`cmd/vendor-web`, new). Small server. Customer and request forms, list
  of licenses with end dates, download of signed license files. It connects to Neon with a role
  that cannot write signed licenses. It has no signing key, so a break-in cannot create a valid
  license. Built in Phase 3. Sales people are rows in `web_users`, not database logins. The service
  is one login (member of `vendor_web`, which is a member of `vendor_sales` only) and sets
  `vendor.actor` for each transaction. The database function `vendor_actor()` honors that setting
  only for logins that inherit `vendor_web` (not superusers or admin-only grantors), so audit rows and row-level security name the real person
  (`web:<name>`) and no other login can impersonate one. Enrollment: the owner runs
  `vendor-console web-user add NAME` and gets a one-time code (24 hours, stored hashed); the person
  opens `/enroll`, enters the code and registers a passkey. A lost key is handled with
  `web-user invite`, a leaver with `web-user disable`. Sessions last 8 hours, 30 minutes idle.
- **Shared code**. `internal/vconsole/...` for the data model, the audit chain and the signer
  interface. It reuses `internal/license` and `internal/license/issuer` for the license payload
  and the canonical signing bytes, so the console and the product cannot drift apart.

The `alice` binary must never link `internal/vconsole` or `issuer`. The existing test in `cmd/alice`
that checks this is extended to cover the new packages.

## 4. Signing

### 4.1 Signer interface

```go
type Signer interface {
    KeyID() string
    Public() ed25519.PublicKey
    Issue(ctx context.Context, p license.Payload) ([]byte, error) // PIN and touch happen here
}
```

Implementations:

1. **OpenPGP Ed25519** (`sign.OpenPGPSigner`, YubiKey firmware 5.2.3 or later): the OpenPGP card
   protocol is implemented in this repository (`internal/vconsole/sign/openpgp`) over a PC/SC
   transport built on `github.com/ebfe/scard` (`internal/vconsole/sign/pcsc`, build tag `yubikey`
   only). Before any PIN prompt it requires an Ed25519 signature key equal to the key set's key, a
   PIN that is not blocked and has more than one try left, a touch policy of `on` or `fixed`
   (`cached` lets a second signature through untouched for about 15 seconds and, like `off`, needs
   `--allow-no-touch`), the PIN forced for every signature, and signed bytes no longer than the size
   the hardware smoke test proves (`sign.MaxSignedBytes`, 1024 bytes); it verifies the card's
   signature before returning.
2. **File key** (the existing passphrase key file), kept for tests and as the path in use until the
   hardware smoke test passes.

PIV is not built (Phase 2 ruling 1): OpenPGP Ed25519 works from firmware 5.2.3, PIV Ed25519 only
from 5.7, so the OpenPGP implementation covers every key PIV would and more. The rulings are in
`docs/superpowers/plans/2026-10-15-vendor-console-phase-2.md`.

### 4.2 What is signed

The same bytes the product already verifies: `license.SignedBytes(payload)`. The console builds the
payload, shows it, and signs it. The license key signs nothing else, with two documented exceptions:
the smoke-test texts of `signer test` (and its `--max-size` form), which are not JSON and do not
start with the signing prefix, and gpg's certification of the key when it is generated on the card
with gpg. Neither can verify as a license. The key is never used for git or mail signing, and the
gpg keyring entry is removed after the ceremony (runbook section 2).

### 4.3 What you see is what you sign

The app builds the payload locally from the request fields, prints every field on the terminal
(customer, installation ID, targets, validity, months, features, replaces, license ID, issue time,
format, key ID, card serial) and the SHA-256 of the exact bytes the card receives, asks `Sign this
license? [y/N]`, then asks for PIN and touch. There is no local browser UI (Phase 2 ruling 3): a
local web server would add attack surface and show nothing more. A request row in Neon that changed after a signer opened it is detected by
comparing a content hash taken at display time with the one at signing time, and the signed file is
recorded only if the SHA-256 of its signed bytes equals the one shown.

This protects against a changed database request and against operator mistakes. It does not protect
against malware on the signer computer, which draws the display itself and can show the real license
while it sends its own payload to the card (section 9).

### 4.4 YubiKey setup (done once per key, in the UK for the owner's keys)

1. `ykman info`: firmware 5.2.3 or later and OpenPGP enabled; record the serial. One key ID
   (`vk-YYYY-NN`) per YubiKey.
2. Change the User PIN and Admin PIN from the factory defaults; decide on the Reset Code.
3. Generate the Ed25519 signature key on the card (`gpg --card-edit`, `key-attr`, `generate`, no
   off-card backup). Force the PIN for every signature (`forcesig`, or `ykman openpgp access
   set-signature-policy always`) and require touch (`ykman openpgp keys set-touch sig on`, or
   `fixed`). Remove the gpg keyring entry afterwards and never use the key for anything else.
4. Record the public key with `vendor-console signer info --out FILE` and its fingerprint; build the
   key set entry (`licensectl keyset --pub FILE`); `signer test` and `signer test --max-size`.
5. Embed the owner's, the IT manager's and the spare key in `production.json` and ship a release.
6. Store spare keys in separate safe places. Write each key's signature counter into the paper log
   (the counter reconciliation in section 9 starts from it).

The full ceremony, with commands marked as not yet run on hardware, is in
`docs/vendor-console-operations.md` section 2; the owner's hardware smoke test is section 11.

## 5. Data model (PostgreSQL)

- `customers(id, name, contact, notes, created_by, created_at)`
- `license_requests(id, customer_id, installation_id, targets, valid_from, months, features,
  replaces, status, requested_by, requested_at)`. There is no stored hash: the request hash is recomputed from the row at signing time (section 4.3). Status: `open`, `signed`,
  `rejected`, `cancelled`.
- `licenses(license_id, request_id, customer_id, installation_id, key_id, issued_at, valid_from,
  valid_until, targets, file, file_sha256, signed_by, replaces, revoked_at)`
- `audit(seq, at, actor, action, subject, details, prev_hash, hash)`: hash chain, same idea as the
  product's audit log. Written by triggers in the same statement as the change, with
  `vendor_actor()` as actor: the login (`session_user`), or `web:<name>` for the web service acting
  for a signed-in person; no login may write it by hand.
- `reminders(license_id, days_before, sent_at)`

Licenses are never updated after signing, except for `revoked_at`. A correction is a new license
that `replaces` the old one, as `licensectl` does today.

Roles in Postgres (one login per person, no shared password):

| Role | May do |
|---|---|
| `sales` | read customers and licenses; insert customers and requests; update only their own open requests |
| `signer` | everything `sales` can, plus insert into `licenses`, update request status |
| `owner` | everything; manage logins and web users; read (not change) the reminder records, `notifications` and `notification_reads` (writing them is the notifier's and the issuance trigger's). The owner is also a web user with the role `owner` (`web_users.role`; `web-user add NAME --owner`), which sees the owner notifications in the web page; the role is set at creation and cannot be changed through the web or a command |
| `vendor_web` | the sales web service login: everything `sales` can (acting as `web:<name>`), plus its own web tables (sessions, adding passkeys and updating their sign counters, consuming enrollment codes) and `web_audit_login`; EXECUTE on four notification functions only (`web_notifications`, `web_unread_count`, `web_mark_read`, `web_mark_all_read`), which show and mark only the notifications of the person named by the transaction's actor (they must be called inside the actor transaction); the service sets that actor itself, so this guards against bugs in its Go code, not against a compromised service (section 9); no direct access to `notifications` or `notification_reads`, no INSERT of notifications; no signing, no audit read |
| `vendor_notifier` | the `notify run` login (Phase 4): read only the columns it needs: licenses (not the file), customers (`id`, `name`), requests (`id`, `customer_id`, `status`, `requested_by`, `requested_at`), web users (`name`, `disabled_at`, `role`), settings, audit (`at`, `actor`, `action`, `subject`; no details); insert notifications (content columns only; row-level security refuses the kind `license.issued` and `issued*` dedupe keys, which only the issuance trigger writes); insert reminder records; record the time of the last weekly summary and prune old read notifications through one function each; no updates or deletes, no signing |

Row-level security enforces this in the database, so a bug in a client cannot widen it.
Connections require TLS with certificate verification. Credentials come from the environment or
the OS keychain, never from the repository.

## 6. Existing ledger

`licensectl` keeps a signed CSV ledger (`issued.csv`) that detects tampering and rejects duplicate
IDs and conflicting corrections. The console must keep these rules (duplicate license ID, replace
cycle, shortened term only with explicit confirmation, same installation). O2 is resolved (Phase 5):
the hash-chained `audit` table plus the `licenses` table are the ledger. No CSV ledger is exported:
it would have to be signed with the license key, which signs nothing but licenses (section 4.2 lists
the two exceptions, neither of which is a ledger).
`licensectl ledger-verify` stays for the `issued.csv` files of licenses issued with `licensectl`.

The chain alone cannot show that the newest audit rows were cut from the end. Instead of a signed
head, the weekly summary notification ends with `Audit head: <seq>:<hash>` (the newest row when the
summary was made). The notification lives in the same database, so it is not a witness outside it:
the owner copies the head into the paper log every week (`vendor-console audit-head` prints it on
demand), and the paper log is the witness. (E-mail, which used to carry the head outside the
database, was dropped before deployment; this is a loss of an external channel, accepted.)
`vendor-console audit-verify --head SEQ:HASH` checks that the chain is intact and that row `SEQ`
still exists with that hash; `vendor-console audit-head` prints the current head (always the full
hash). Because the head is copied by hand, `--head` also accepts `SEQ` with only the first 16 to 63
hex digits and then checks that the row's hash starts with them (about 2^64 work for an insider to
forge with 16 digits; fewer are refused); the full hash is preferred and the output says when only a
prefix was checked. After a restore,
`vendor-console verify-licenses` re-checks every stored license file against the key set (file
hash, signature, and that the row agrees with the signed payload).

## 7. Owner visibility (built in Phases 4 and 5)

Notifications are in-app only: they appear in the vendor web page (a bell with the unread count on
every signed-in page, the newest unread on the home page, and `/notifications` with mark read and
mark all read). There is no e-mail, no browser push and no desktop notification. Each notification
(`notifications` table) has a kind, a severity (`info`, `warning`, `alert`), a one-line title, a
body of at most 4000 characters, an audience (`owner`, `sales` or one named web user) and a unique
dedupe key, so concurrent writers create it once. A web user with the role `owner` sees owner and
sales notifications and their own; a sales user sees sales notifications and their own; a disabled
user sees nothing. Read state is per person (`notification_reads`). The web service reads and marks
only through four database functions (section 5); the database enforces who sees what.

- Issuance: a database trigger on `licenses` writes an owner notification (kind `license.issued`,
  key `issued:<license-id>`, hashed for very long IDs) in the same statement that inserts the
  license, so no client can issue without the owner being notified, and hostile text cannot make
  the insert fail. Body: customer,
  license, targets, term, signer (the inserting login; a differing `signed_by` value is shown as
  "Recorded signer"), key ID, request number. The notifier cannot pre-empt it (row-level security).
- `vendor-console notify run` (hourly timer, notifier login) creates the reminders and the weekly
  summary and prunes, then exits; `--dry-run` reports what it would create and changes nothing. It
  warns when no enabled owner web user exists.
- Weekly summary (kind `summary.weekly`, owner), created when the last one is 7 days old or older
  (the first covers the 7 days before the run): licenses issued in the period, open requests,
  licenses ending in the next 90 days and unusual activity, then the `Audit head` line (section 6).
  Unusual, in this order of weight: licenses with no issue audit row (possible tampering), more than
  5 licenses by one signer in one local day, a license issued between 22:00 and 06:00 in the
  configured time zone (default `Europe/Istanbul`); when the body must shrink, night lines go first.
  Issue time and signer come from the license's audit row, not from the client-writable `issued_at`
  and `signed_by`. A quiet week still produces a summary. When Unusual is not empty, a separate
  alert notification (kind `activity.unusual`) repeats it.
- Expiry reminders at 90, 60 and 30 days (kind `license.ending`) to the owner and to the person who
  made the request, when that is an enabled web user who is not an owner (the owner copy already
  reaches an owner). Catch-up rule: a license found already inside a threshold that never fired gets
  only the most urgent reminder, and the less urgent ones are recorded as done. Revoked, replaced or
  renewed licenses get none (renewed: a later, unrevoked license for the same customer and
  installation ending after it).
- Renewal is not a stored draft. The license list has a "Renew" link and every reminder carries the
  path (`/requests/new?renew=<license-id>`): it prefills a new request from the old license
  (customer, installation, targets, features, start date = old end date) for the person to review
  and submit.
- Pruning: each `notify run` deletes notifications older than 180 days that at least one person has
  read; unread ones stay. The database enforces the 180-day floor.
- No notification contains an installation ID, a license file or a customer contact; free text is
  cleaned of control and bidi characters in SQL and Go and rendered escaped.
- The owner reads the audit log on the command line, not on a web page: `vendor-console audit show`
  (owner login only; newest first, filters by date, actor and action prefix, at most 1000 rows;
  installation IDs shown only as `inst#<8 hex>` fingerprints). The web service must not be able to
  read the audit log, and a web page would need that (Phase 5 ruling).
- `vendor-console license revoke --id ID --reason TEXT` (owner login) marks a license revoked in the
  vendor records: reminders stop and the reason is audited. The customer's installation is not
  affected, because license files are checked offline. Revoking a signing key stays a product release
  (section 8).

## 8. Product-side changes

Small, and listed so nothing is a surprise:

1. `internal/license/keys/production.json` is empty today. It will list the public keys: owner key,
   IT manager key, spare key. Key IDs follow the existing pattern (`vk-...`).
2. The key set is embedded in the binary, so adding or revoking a key needs a new release. The
   spare key is therefore embedded from the first release.
3. Revoking a key sets `status: revoked` and `revoked_from` (existing mechanism). Licenses signed
   before that date stay valid.

No change to the license format, the verifier or the license tests is planned.

## 9. Security notes

- No private key on any server. Neon holds no secret that can create a license.
- Neon breach: records can be read or damaged, licenses cannot be forged. The audit chain and the
  signed license files let damage be detected. Neon point-in-time restore plus an encrypted dump
  to a separate place are the recovery path.
- Compromised signer machine (YubiKey signer): the key cannot be copied, and without the PIN and a
  touch nothing is signed. The "what you see" screen, the content hash and the check of the signed
  bytes against the confirmed SHA-256 stop a swapped database request and catch operator mistakes;
  they do **not** stop malware on the signer computer, which can show the real license and send its
  own payload to the card, getting one signature per PIN entry and touch. That license is never
  recorded (no issuance notification, no audit row, `verify-licenses` never sees it). The control is the
  counter reconciliation: each key's signature counter is written into the paper log after every
  ceremony, smoke test and signing session, and each quarter it must equal the licenses issued with
  that key ID plus the logged tests and failed signings plus gpg's certifications at key
  generation; any unexplained increase is treated as a compromise of the signer machine and of the
  key (runbook sections 2 and 9). The counter is per key and starts again with a new key. Revoke the
  key and ship a release if a key is lost or compromised.
- A malicious virtual PC/SC reader whose name contains "Yubi" could be picked by default and capture
  the PIN at VERIFY. It cannot forge a signature (every signature is verified against the expected
  key before anything is recorded), and a second matching reader makes `--reader` mandatory. The
  touch on the real key is the control that matters.
- Interim note: the YubiKey signer is built, but is used only once the owner's hardware smoke test
  (runbook section 11) has passed on the platforms in use. Until then "the key cannot be copied" and
  "no private key on any server" do not hold under signing option 2 (the file key on a dedicated
  online signer machine). See the operations runbook, section 2.
- A signer can sign any license. Limits (targets, term) are advice in the app, not enforced by the
  key. The owner's notification and the audit are the control. This is accepted.
- Compromised web service (the `vendor-web` server or its database login): it sets
  `vendor.actor` and passes the user id itself, so it can act as any enabled web user. It can read
  and mark as read anyone's notifications, the owner's included (so the owner's bell can stay
  empty), and through them it sees data derived from the audit log (signer logins, issue times, the
  audit head in the weekly summary). It still cannot create, change or delete notifications, read
  the audit table, sign or write licenses. The database's actor check on the notification functions
  only protects against bugs in the Go code. After a break-in the owner reviews all owner
  notifications since then, read or not, and the owner's `notification_reads.read_at` in that window
  (runbook section 9).
- Stolen notifier login: it can create look-alike notifications of other kinds (the page does not
  show the kind, so a title `License issued: ...` looks real), take the next `summary:<date>` or
  `unusual:<date>` dedupe key first so the real summary or alert is silently skipped (the
  `last_summary_at` mark is still written), read every notification body and flood the list. It
  cannot forge `license.issued` rows (row-level security), read audit details, or update or delete
  notifications. The issuance notices (kind `license.issued`), the audit and the paper log remain
  trustworthy (runbook section 9, "Database credential leak").
- Sales login: WebAuthn (the owner's existing keys work), short sessions, rate limits.
- Customer data in Neon is personal data: EU region, access only through the roles above.

## 10. Phases

1. **Foundation.** Module layout, schema and migrations, roles with row-level security, audit
   chain, `Signer` interface with the file key implementation, tests. The signing app can issue a
   license from a request using the file key.
2. **YubiKey signing (built in code; hardware verification owner-pending).** OpenPGP
   implementation (rulings 1 and 2), PIN and touch flow, confirmation display on the command line,
   `signer info` and `signer test`, the `yubikey` build tag and `make vendor-console-yubikey`. Tested
   against a software card only; the smoke tests on Linux, Windows and macOS are the owner's
   checklist (runbook section 11). `vendor-console` builds for Windows and macOS (cross-compile tested
   without cgo, the Windows YubiKey build included; the YubiKey build for Linux and macOS needs cgo
   and is built natively).
3. **Sales web page (built).** Login, customers, requests, license list with end dates, download. The owner's audit view is a command line view (`audit show`, Phase 5), not a page.
4. **Reminders and owner reports (built).** In-app notifications in the web page (bell and
   notifications page; the owner is a web user with the role `owner`) on issuance, the weekly
   summary with unusual activity, expiry reminders, renewal as a prefilled request (no stored
   draft). First built with e-mail; the e-mail sending was replaced by in-app notifications before
   any deployment.
5. **Operations (built, except the YubiKey-dependent ceremony steps).** Audit head checkpoint in the
   weekly summary (copied into the paper log) and `audit-verify --head`, `verify-licenses`,
   `license revoke`, `audit show` (a command line view instead of a web page), `vendor-web --trusted-proxy`,
   and the operations runbook `docs/vendor-console-operations.md` (backup and restore drill, key
   revocation procedure, onboarding and offboarding, incidents). The YubiKey ceremony (runbook
   section 2) is written for the OpenPGP signer; it is carried out with the hardware smoke test.

| Phase | Status |
|---|---|
| 1. Foundation | built |
| 2. YubiKey signing | built in code; hardware smoke test owner-pending (runbook section 11) |
| 3. Sales web page | built |
| 4. Reminders and owner reports | built (in-app notifications; no e-mail) |
| 5. Operations | built; the YubiKey ceremony is carried out with the hardware smoke test |

## 11. Open items

| ID | Item | Needed before |
|---|---|---|
| O1 | Firmware and enabled applications of the owner's three YubiKey 5C NFC (`ykman info`). Resolved by Phase 2 ruling 1: OpenPGP only (Ed25519 from firmware 5.2.3), no PIV, so the firmware need not be 5.7; the ceremony checks 5.2.3 or later | Phase 2 (done) |
| O2 | CSV ledger versus audit table (section 6). Resolved: the `audit` and `licenses` tables are the ledger; no CSV export; `licensectl ledger-verify` stays for old file ledgers | Phase 5 (done) |
| O3 | Which Go library reads PIV/OpenPGP Ed25519 on all three platforms (PC/SC). Resolved by Phase 2 ruling 2: `github.com/ebfe/scard` for the PC/SC transport only, with the OpenPGP card protocol implemented in this repository; `piv-go` rejected (PIV only, firmware 5.7 and later). Working on real hardware is the owner's smoke test | Phase 2 (done) |
| O4 | Where the sales web service runs and who operates it. Resolved: one static binary `vendor-web` behind any TLS-ending reverse proxy, or with its own certificate; operated by the IT manager (Istanbul); the owner holds the `vendor_owner` login that creates web users; single instance (ceremony state is in memory) | Phase 3 (done) |
| O5 | E-mail sending (provider, sender address). Closed: not needed; in-app notifications replace e-mail | Phase 4 (closed) |
| O6 | Whether the installation ID flow (customer gives it, vendor binds the license to it) stays as is | Phase 1 |
| O7 | What if the card cannot sign the full message (smoke test step 4 fails). Options, in order: find out whether the card or the console's chaining fails (yubikit test); extended-length commands in the console; a smaller `sign.MaxSignedBytes` the card meets; another OpenPGP card with Ed25519; PIV Ed25519 (firmware 5.7+); keep the file key. Prehashing or another algorithm is not an option (new verifier). Details: runbook section 11, "If the YubiKey cannot sign the full license message" | Option 3 coming into force |

## 12. Not in scope

Payments and invoicing (only an invoice reference field), calls from customer installations to the
vendor, usage reports from customers, multi-tenant vendor accounts.
