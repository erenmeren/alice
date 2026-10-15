# Vendor console: design (draft)

Status: draft. Phase 1 (foundation) is built on the branch vendor-console; later phases are not.
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
| Signing | Only with a YubiKey (PIV or OpenPGP, Ed25519). No online key, no KMS. |
| Signers | The owner and the IT manager, each with their own YubiKey. A third key is a spare. |
| Approval | No owner approval step. Every issuance notifies the owner. |
| Sales | Separate people. They create requests and download signed licenses. They cannot sign. |
| Database | PostgreSQL on Neon (EU region). SQLite is not used. |
| Signing app | One Go program for Linux, Windows and macOS, serving a local browser UI on localhost. |
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

- **Signing app** (`cmd/vendor-console`, new). Local program, opens `http://127.0.0.1:<port>`.
  Reads open requests from Neon, shows the exact license content, signs on the YubiKey, writes
  the signed license and an audit entry back. Also usable by a signer to create a license directly.
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
    PublicKey() ed25519.PublicKey
    Issue(ctx context.Context, p license.Payload) ([]byte, error) // PIN and touch happen here
}
```

Implementations:

1. **PIV Ed25519** (YubiKey firmware 5.7 or later).
2. **OpenPGP Ed25519** (firmware 5.2.3 or later).
3. **File key** (the existing passphrase key file), kept for tests and as an emergency path.

Which of 1 and 2 ships first depends on the firmware of the owner's three keys. That is not known
yet (open item O1). The rest of the design does not depend on the answer.

### 4.2 What is signed

The same bytes the product already verifies: `license.SignedBytes(payload)`. The console builds the
payload, shows it, and signs it. Nothing else is signed by the license key.

### 4.3 What you see is what you sign

The app builds the payload locally from the request fields, displays every field (customer,
installation ID, targets, validity, features, replaces) and the SHA-256 of the signed bytes, then
asks for PIN and touch. A request row in Neon that changed after a signer opened it is detected by
comparing a content hash taken at display time with the one at signing time.

### 4.4 YubiKey setup (done once per key, in the UK for the owner's keys)

1. `ykman info`: record firmware and enabled applications.
2. Generate the key pair on the device (non-exportable). Set PIN and PUK. Require touch.
3. Record the public key and its fingerprint. Build the key set entry.
4. Store spare keys in separate safe places.

A checklist for this goes into the operator documentation of the console.

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
| `owner` | everything; manage logins |
| `vendor_web` | the sales web service login: everything `sales` can (acting as `web:<name>`), plus its own web tables (sessions, adding passkeys and updating their sign counters, consuming enrollment codes) and `web_audit_login`; no signing, no audit read |

Row-level security enforces this in the database, so a bug in a client cannot widen it.
Connections require TLS with certificate verification. Credentials come from the environment or
the OS keychain, never from the repository.

## 6. Existing ledger

`licensectl` keeps a signed CSV ledger (`issued.csv`) that detects tampering and rejects duplicate
IDs and conflicting corrections. The console must keep these rules (duplicate license ID, replace
cycle, shortened term only with explicit confirmation, same installation). Open item O2: whether
the CSV ledger stays as an offline copy that is exported from Neon, or is replaced by the hash-chained
`audit` table. Proposed: export a signed ledger file from the database on demand, so offline
verification with `licensectl ledger-verify` keeps working.

## 7. Owner visibility

- E-mail to the owner on every signed license: customer, targets, term, signer, key ID.
- Weekly summary: new licenses, open requests, licenses ending in the next 90 days, odd activity
  (outside usual hours, many licenses in a day).
- Expiry reminders at 90, 60 and 30 days to the customer's sales owner and the owner. A renewal
  draft is created from the old license.
- The web page shows the audit trail to the owner role.

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
- Compromised signer machine: PIN and touch stop silent signing. The "what you see" screen and the
  content hash stop a swapped request. Revoke the key and ship a release if a key is lost.
- A signer can sign any license. Limits (targets, term) are advice in the app, not enforced by the
  key. The owner's notification and the audit are the control. This is accepted.
- Sales login: WebAuthn (the owner's existing keys work), short sessions, rate limits.
- Customer data in Neon is personal data: EU region, access only through the roles above.

## 10. Phases

1. **Foundation.** Module layout, schema and migrations, roles with row-level security, audit
   chain, `Signer` interface with the file key implementation, tests. The signing app can issue a
   license from a request using the file key.
2. **YubiKey signing.** PIV or OpenPGP implementation (decided by O1), PIN and touch flow,
   cross-platform builds and smoke tests on Linux, Windows and macOS.
3. **Sales web page (built).** Login, customers, requests, license list with end dates, download. The owner's audit view stays in Phase 4.
4. **Reminders and owner reports.** E-mail on issuance, weekly summary, expiry reminders, renewal
   drafts.
5. **Operations.** Backup and restore drill, key ceremony checklist, key revocation procedure, docs.

## 11. Open items

| ID | Item | Needed before |
|---|---|---|
| O1 | Firmware and enabled applications of the owner's three YubiKey 5C NFC (`ykman info`); new key for the IT manager must be firmware 5.7 or later for PIV | Phase 2 |
| O2 | CSV ledger versus audit table (section 6) | Phase 1 |
| O3 | Which Go library reads PIV/OpenPGP Ed25519 on all three platforms (PC/SC). To be checked with a spike, not assumed | Phase 2 |
| O4 | Where the sales web service runs and who operates it. Resolved: one static binary `vendor-web` behind any TLS-ending reverse proxy, or with its own certificate; operated by the IT manager (Istanbul); the owner holds the `vendor_owner` login that creates web users; single instance (ceremony state is in memory) | Phase 3 (done) |
| O5 | E-mail sending (provider, sender address) | Phase 4 |
| O6 | Whether the installation ID flow (customer gives it, vendor binds the license to it) stays as is | Phase 1 |

## 12. Not in scope

Payments and invoicing (only an invoice reference field), calls from customer installations to the
vendor, usage reports from customers, multi-tenant vendor accounts.
