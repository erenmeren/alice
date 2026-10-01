# Operator Guide

This guide is for the person who runs the Alice server. Commands run inside the `alice` container. On a
development machine use the `make` targets; on a server use
`sudo docker compose exec alice /usr/local/bin/alice <command>` in the Alice directory.

## Commands

| Command | What it does |
|---|---|
| `alice setup-token --reset` | Prints a new one-time setup code to the terminal (never to a file). Any earlier code stops working. Works only while no administrator exists. Development: `make setup-token`. |
| `alice audit verify` | Verifies the audit hash chain. Exit code 0 and "The audit log is intact: … head hash …" when the chain is complete; exit code 1 and "Audit log integrity problem at entry N" otherwise. The check is itself recorded in the audit log (actor `cli`). |
| `alice admin reset-mfa <username>` | Removes the person's authenticator and recovery codes and ends their sessions; they enrol again at the next sign-in. Use it when the only administrator lost both phone and recovery codes. Recorded in the audit log as done by `cli`. It does not end a sign-in block. |
| `alice admin unlock <username>` | Ends the person's sign-in delay or 15-minute block and sets their failed sign-in count back to zero; nothing else changes. Use it when the only administrator is blocked after too many wrong attempts. Recorded in the audit log as `user.unlocked`, done by `cli`. Development: `make unlock ACCOUNT=<username>`. |
| `alice license status` | Prints the Installation ID, the license state (`evaluation`, `evaluation_expired`, `active`, `grace`, `locked`) and the license in force or the end of the evaluation, and warns when the server clock is behind. Changes nothing. |
| `alice license keys` | Lists the vendor license keys built into this binary with their status and SHA-256 fingerprints; compare them with the fingerprint your vendor publishes. A build without the vendor key says so and accepts no license (evaluation only). |
| `alice migrate` | Applies database migrations and exits. `alice serve` also applies them at startup. |

`alice audit verify` does not need the master key, so it works even when Alice refuses to start because of a
key problem.

## Database roles

Alice uses two PostgreSQL roles:

- The **owner** role (`ALICE_MIGRATE_DATABASE_URL`) creates and changes tables at startup.
- The **application** role `alice_app` (`ALICE_DATABASE_URL`) serves requests and runs the commands above. It can
  only add and read audit log entries, never change or delete them. A database trigger blocks changes even for
  the owner.

If `ALICE_MIGRATE_DATABASE_URL` is empty, Alice uses the application URL for both and logs a warning, because the
audit log is then protected by the triggers only.

In this release the owner role of the Docker Compose stack is the PostgreSQL superuser `alice`, and its URL is in
the `alice` container's environment. A superuser can switch the triggers off, so anyone who takes over the
`alice` container could rewrite the audit log. A dedicated non-superuser owner and a separate one-shot migration
container arrive with the installer packaging.

## Master key

Alice encrypts secrets (for example authenticator secrets) with a 256-bit master key in `master.key` inside the
keys directory (`/opt/alice/keys`). On the very first start Alice creates it (mode 0400). Afterwards:

- If the file is missing, Alice refuses to start ("the master key file is missing but this database already holds
  encrypted data"). Restore the file from your backup; Alice never creates a new key over existing data.
- If the file is different from the one the database was created with, Alice refuses to start ("the master key
  does not match this database").
- If the file permissions are wider than 0400, the file belongs to another user, or it is a symbolic link, Alice
  refuses to start and prints the command that fixes it (for example `chmod 0400 master.key`).

The server disk must use full-disk encryption: anyone who can read both the database and this file can decrypt the
secrets. The `alice` container has core dumps disabled so a crash never writes key material to disk.

## Checking an audit export outside Alice

The JSON export (`GET /api/v1/audit/export?format=json`, or **Export JSON** on the **Audit log** page) holds a
`verification` object (the result Alice computed, with `head_seq` and `head_hash`) and all `entries` in order.
Entries appended while the export was being written are not covered by `verification`. The response header
`X-Alice-Audit-Intact` carries the same result. Very large logs may not finish within the server's 60-second
response limit; use `alice audit verify` on the server in that case.

To recompute the chain yourself, for each entry in `seq` order:

1. Build the JSON object with exactly these keys in this order: `seq`, `at`, `actor_type`, `actor_id`,
   `actor_name`, `ip`, `action`, `object_type`, `object_id`, `result`, `details`, `request_id`. Write `null`
   `actor_id` and `ip` as `""`, write `at` in UTC with exactly six fractional digits
   (`2026-09-30T08:15:02.120000Z`), sort the `details` keys, use no spaces, and escape `<`, `>`, `&`, U+2028 and U+2029
   as `\u003c`, `\u003e`, `\u0026`, `\u2028` and `\u2029` (Go `encoding/json` rules); other non-ASCII characters stay
   as UTF-8.
2. `hash = SHA-256(previous hash || that JSON)`, where the previous hash of the first entry is 32 zero bytes.
3. Compare with the entry's `hash` (hex).

The CSV export is meant for spreadsheets: cells that start with `=`, `+`, `-`, `@`, a tab or a carriage return
get a leading apostrophe, so use the JSON export for this check.

## State volume

Alice keeps its license time record (the latest time it has seen, encrypted and protected with a MAC derived from
the master key) in `ALICE_STATE_DIR` (default `/opt/alice/state`, the `alice-state` volume, owned by user 10001)
in addition to the database. Back it up with the other volumes. If the file is lost or damaged, Alice uses the copy
in the database and records "time record damaged" (`clock.hwm_damaged`) in the audit log; if both are lost on an
existing installation, Alice starts from the later of the system clock and the release's build time and records
"time reference reset" (`clock.time_reference_reset`). Neither ever extends a license.

## Email

In this release email is configured with environment variables in `deploy/.env`; a Settings page follows in a later
release. Alice sends license warnings to every enabled administrator with an email address, in their language.

| Variable | Meaning |
|---|---|
| `ALICE_SMTP_HOST` | Mail server. Empty = no email: warnings are then shown only as banners, and each email is recorded as skipped. |
| `ALICE_SMTP_PORT` | Default 587 with `starttls`, 465 with `tls` |
| `ALICE_SMTP_FROM` | Sender, for example `Alice <alice@example.com>`; required when `ALICE_SMTP_HOST` is set |
| `ALICE_SMTP_USERNAME` | Optional user name; needs `ALICE_SMTP_PASSWORD_FILE` (both or neither) |
| `ALICE_SMTP_PASSWORD_FILE` | Path, inside the container, of a file holding the password (never the password itself) |
| `ALICE_SMTP_TLS` | `starttls` (default) or `tls`. Alice never sends email unencrypted, needs TLS 1.2 or newer and checks the server certificate. |
| `ALICE_SMTP_CA_FILE` | Path, inside the container, of a PEM file with a private certificate authority, if the mail server's certificate comes from one |

The password and CA files must be mounted into the container. Add a `docker-compose.override.yml` next to
`docker-compose.yml`:

    services:
      alice:
        volumes:
          - ./secrets/smtp_password:/run/secrets/smtp_password:ro
          - ./secrets/smtp_ca.pem:/run/secrets/smtp_ca.pem:ro

and set `ALICE_SMTP_PASSWORD_FILE=/run/secrets/smtp_password` (and `ALICE_SMTP_CA_FILE=/run/secrets/smtp_ca.pem`)
in `deploy/.env`. Alice refuses to start with a clear message when the settings are inconsistent or a file cannot
be read; the recovery commands (`alice admin …`, `alice audit verify`) do not read the email settings and keep
working. A failed send is retried for about 2 hours (10 attempts, 30 seconds doubling up to 30 minutes); every
failed attempt is logged with a reason code (never the password), and the email is then marked `failed`.

## Development stack reset

`make reset` **deletes the development database, keys and state volumes** (everything: users, audit log, license
files, Installation ID, master key, time record) and starts a fresh installation with a new Installation ID and a
new 30-day evaluation. Use it after pulling a phase that needs a fresh database (for example Phase 1 onto a Phase 0
stack: the `alice_app` role is created only on a fresh database). A license issued for the old Installation ID does
not work on the new one.

`make e2e-up` starts the **test build** on the same development database, and every Playwright run empties all its
tables (`POST /test/reset`). Do not run it on a stack whose data you want to keep, and never on a server.
