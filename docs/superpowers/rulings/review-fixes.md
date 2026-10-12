# Review fixes — rulings

Decisions taken while fixing the external code review of 2026-10-12 on branch `review-fixes` (ledger
`.superpowers/sdd/2026-10-12-review-fixes/external-report.md`). Each entry: item — decision — why — cost if wrong.

- M-1 (backup sender key; narrows Phase 8 S-2 and R43 row 41) — the format is not redesigned; every claim now says
  what the sender key gives: a file cannot be forged by someone who does not know the recovery passphrase, and it is
  not authentication against a passphrase holder (X25519 symmetry: S_priv·R_pub = R_priv·S_pub, R_priv unwraps with
  the passphrase, S_pub is in the clear header). Pinned by `internal/backup/format:TestPassphraseHolderCanForge`;
  wording changed in the format and backup-key comments, `docs/security-overview.md`, `docs/backup-restore.md`,
  `CHANGELOG.md`, `SECURITY-REPORT.md` (KI-14 and the keys paragraph) and R43 row 41 — why: KI-14 already accepted
  the residual, the defect was the overclaim; real authentication against a passphrase holder needs a signature
  checked against a trust root kept outside the installation and its backups (for example a verification key the
  operator records separately and enters at restore), which is a format, restore-UI and key-ceremony change for a
  later version — cost if wrong: an operator who treats the passphrase as less sensitive than the master key can be
  handed a forged backup; the docs now say to keep it as secret as the master key.

- L-3 (backup scheduler) — a scheduled backup that fails with `not_configured` is recorded once per episode: later
  ticks only re-check the keys (no audit row, no state write) and back up at the first tick after they work; any
  other failure is retried after 5 minutes doubling to 1 hour (24-30 attempts a day instead of 288). A scheduled
  backup whose file was made but whose success could not be recorded is still pruned after, remembered in memory and
  recorded at the next tick before anything else; no other backup is made while that record fails; `recordSuccess`
  is idempotent per file name — why: audit-chain growth and a filling backup volume were the two failure modes; the
  48-hour alarm still runs on every tick — cost if wrong: after a fix, the next automatic backup can wait up to an
  hour (Back up now is immediate); a restart while a success is unrecorded forgets it, so that process makes one more
  backup.
