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

- L-10 (Key Vault certificate details) — all-or-nothing was not intended: inventory already stores a certificate listed
  without details (`details_pending`, `DetailsPending`). A failed detail read (GET or the version list) now keeps the
  listing: the certificate stays without details, counts as pending and as unreadable (`kv_item_unreadable`
  warning), like a key whose details failed. Kept as a failure of the whole certificate listing: the caller's
  context, a whole-vault code, `azure.forbidden` (it names the missing role, F-40; RBAC for certificate reads is
  vault-wide in practice) and three detail failures in a row (the vault, not one certificate, is failing; this also
  bounds the retries a broken vault costs one poll) — cost if wrong: a vault whose certificates fail one by one, with
  successes between them, shows as healthy with unreadable items instead of degraded.

- L-11 (removal after a compare-and-set refusal) — not intentional: fixed (`targetjobs.removeFailed` now applies
  `sshkeyjobs.definiteNoChange`'s rule, so `ssh.file_changed` after the write step is retried). Other definite helper
  refusals after the write step started stay uncertain in both packages, as `definiteNoChange` documents — why: only
  `ssh.file_changed` is produced by the provider itself after it saw every attempt refused; trusting every refusal
  code there is the L-12 question — cost if wrong: a removal the helper refused for another definite reason waits for
  a person instead of being retried.
- L-12 (helper `IO_ERROR` before the write and after the rename) — confirmed (`cmd/alice-helper/write.go`: lock
  timeout, backup, staging file and directory errors before the rename, and the directory fsync after it, all answer
  `IO_ERROR`); kept as the intentional conservative choice and carried to v1.x with the other helper protocol
  changes: Alice treats `IO_ERROR` as uncertain, which only sends a deploy, rotation add or removal to its proving or
  attention path; it never loses a change or reports one that did not happen. Splitting the code needs a new helper
  release that every managed server must install, and Alice must keep `IO_ERROR` uncertain for older helpers anyway
  — cost if wrong: extra manual steps on a full disk or a lock held for more than 30 s.
- L-13 `UpdatePolicy` without a license gate — intentional: an edit of an enabled policy switches it off and cancels
  its previewed run, an edit of a disabled policy changes nothing Alice does, and switching a policy on is gated
  (`SetPolicyEnabled`); disable and delete are not gated either (L-26 lists creating a policy, not editing one) — cost
  if wrong: none known. The other L-13 items are fixed (attentionParams error, `GetSSHKey` missing/retired,
  `chain_certificate_expired` over the stored path).

- L-4 (bracketed IPv6 SMTP host) — refused at validation (422 `validation.pattern` on host), like the syslog
  forwarder's host, instead of stripping the brackets: one spelling per address, and nothing was released, so no
  stored value needs a migration — cost if wrong: an Administrator who types `[2001:db8::25]` is told to drop the
  brackets (the admin guide and the schema say so).
- L-6 (mail sent inside a transaction) — no `sending` status and no migration: the claim counts the attempt and
  leases the row by moving `next_attempt_at` 2 minutes ahead (send timeout 60 s + 1 minute), the send runs with no
  transaction or connection held, and the outcome is stored in a second transaction fenced on the attempt count (a
  send that outlived its lease leaves the later drain's outcome alone) — why: the smallest correct change; delivery
  stays at least once only for a crash or an unreachable database between send and record, now with a 2-minute gap
  instead of an immediate resend — cost if wrong: such a message is sent twice, as before.
- L-8 (unauthenticated OIDC callback audit growth) — coalesced, not skipped: a callback that names no stored state
  (none, unknown or already used) writes at most one `auth.oidc.denied` row per client address (IPv6 /64) per
  minute; every refusal of a stored state is still audited — why: the first replay of a callback (O-04) stays in the
  audit log; a stream of forged callbacks costs one row a minute per address instead of up to 60 — cost if wrong: the
  second and later replays of one minute from one address are only in the application log.
- L-14 (unique violation of a named constraint) — not reproducible as a misreport today (`users` has no other unique
  constraint a local user can violate: the primary key is a fresh UUIDv7 and the SSO identity index is partial on
  `oidc_provider_id`); fixed anyway as asked: `db.IsUniqueViolationOn` names the constraint in `CreateUser`,
  SSO provisioning (M-2) and group mappings; `internal/inventory/targets.go` keeps the any-constraint check on purpose
  (a duplicate name and a duplicate address both mean `ErrDuplicateTarget`). A schema test pins the two names.
- L-17 (rate limiter eviction) — batches instead of an LRU list: a full limiter or lockout drops idle keys, then the
  least recently used down to 90 % of `maxKeys`, in one O(n log n) pass, so a stream of new keys costs amortised
  O(log n) under the mutex. Idle buckets are swept only when the limiter is full (before, at every new key once
  full). The old pass refilled every bucket before comparing last use, which made the LRU order meaningless; fixed —
  cost if wrong: under a flood of new keys, up to 1,000 tracked addresses at once get a fresh bucket.
- I-7 (malformed stored hash) — also applied to the current password of a password change and to stored recovery
  codes: a hash that does not parse runs the dummy Argon2 work, counts as a wrong secret (`bad_password`,
  `current_password_invalid`, `bad_recovery_code`) and logs `stored … hash is malformed` with the user ID
  (`auth.Config.Log`, wired in `cmd/alice`).
