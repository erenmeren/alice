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
