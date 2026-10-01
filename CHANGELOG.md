# Changelog

## Unreleased — Phase 2: Licensing

### Added
- Signed licenses per installation (Ed25519 over RFC 8785 canonical JSON), limited by managed targets; the
  Installation ID (`ALICE-XXXX-XXXX-XXXX-XXXX`, with a check character) is created at first start and kept by
  restores.
- 30-day evaluation (5 targets) from the installation date; the setup wizard's new license step (upload a license or
  start the evaluation).
- **License** page: Installation ID with Copy, state, "Valid until <date>, N targets", target usage, uploaded
  licenses, history; upload with a server check, a confirmation dialog and step-up.
- License banners on every page (evaluation, warnings 60/30/14/7/1 days, grace, lock, clock problems, damaged
  license data, pending license, target limit) and warning emails to administrators, each sent once (SMTP from
  `ALICE_SMTP_*`, TLS only).
- Lock mode after the 7-day grace period (directly after the evaluation): automatic work that changes servers
  pauses; changes to servers are refused (`ALC-LIC-0001`); sign-in, license upload, backups, audit, exports, user
  administration and tokens keep working. Nothing is deleted.
- Clock protection: a server clock set back never extends a license; a forward jump of more than 48 hours waits
  24 hours before it can start the grace period or the lock.
- `licensectl` (vendor only, never shipped): `keygen`, `issue`, `inspect`, `verify`, `keyset`, `ledger-verify`,
  with an encrypted key file and a signed issuance ledger.
- CLI: `alice license status`, `alice license keys`.
- Coverage floors enforced by `make coverage` (`coverage-floors.json`).
- Guides: `docs/licensing.md`; vendor guide `docs/vendor/licensing-vendor.md` (not shipped).

### Changed
- Finishing setup now needs a license choice (`ALC-SET-0009`).
- New volume `alice-state` at `/opt/alice/state` (back it up with the others).
- The permission `setup.finish` was removed (unused).
- `make ci` runs `make coverage` instead of `make test-integration`.

### Known issues
- Until the vendor's public key is built in, release builds accept no license (evaluation only), and
  `make release-keycheck` fails.
- Nothing in this release changes servers yet, so lock mode only shows its banners; the refusal of changes becomes
  visible with targets in the next release.
- Certificate expiry emails with the "license expired" note arrive with alerts in a later release.
- The full list is in `docs/security/reviews/phase-2.md` ("Known limitations").

## Unreleased — Phase 1: Core

### Added
- Setup wizard: one-time setup code, language, administrator account with mandatory authenticator app and
  10 recovery codes, recovery passphrase (generates the backup key pair).
- Local sign-in with Argon2id passwords (12–128 characters, 100,000-entry leaked-password list), mandatory TOTP,
  recovery codes, progressive delay and 15-minute lockout, step-up confirmation for sensitive changes.
- Sessions (`__Host-alice_session`, 30 minutes idle, 12 hours absolute) with CSRF protection and rate limits.
- Roles Administrator, Operator and Auditor enforced on every API route from one permission table
  (`docs/authz-matrix.md`).
- User management, personal API tokens (read or operate scope, at most 365 days).
- Tamper-evident audit log with viewer, CSV/JSON export and integrity verification (`alice audit verify`).
- Envelope encryption (AES-256-GCM, per-secret key) with a master key file; the application database role cannot
  change or delete audit entries.
- CLI: `alice setup-token --reset`, `alice audit verify`, `alice admin reset-mfa <username>`,
  `alice admin unlock <username>` (ends a sign-in block; `make unlock ACCOUNT=<username>`).
- Guides: `docs/first-run.md`, `docs/admin-guide.md`, `docs/operator-guide.md`.

### Changed
- `/api/v1/version` now requires sign-in.
- Database errors for a wrong password or a missing database stop startup immediately with a clear message.
- Development stack: separate `alice_app` database role; run `make reset` once after upgrading from Phase 0.

### Known issues
- The setup code comes from `alice setup-token --reset` (`make setup-token`); the installer prints it from a later
  release.
- The wizard ends after the recovery passphrase; HTTPS certificate upload, email, license and first target steps
  are added later. (Phase 2 adds the license step.)
- Account blocks and audit-integrity problems are recorded in the audit log but not emailed or sent to syslog, and
  there is no automatic daily integrity check yet.
- People created by an administrator are not forced to change their initial password.
- API tokens with "read and operate" access can do nothing more than read-only tokens until targets exist.
- In the development stack the database owner used for migrations is the PostgreSQL superuser, and its password is
  in the `alice` container (see `docs/operator-guide.md`).
- The full list, with the security review, is in `docs/security/reviews/phase-1.md` ("Known limitations").
