# Vendor Console Phase 5 (Operations) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the vendor console operable and recoverable: tamper checkpoints for the audit chain, a license integrity check usable after a restore, a license revoke command, owner tools to read the audit and handle failed mail, a trusted-proxy option for the web service, and one operations runbook (key ceremony, onboarding and offboarding, key loss, backup and restore drill, incident response).

**Architecture:** Small additions to the existing packages. Database changes go into migration `00004_ops.sql` (not deployed yet, edit in place during this phase). Commands go into `cmd/vendor-console`. The runbook is a document, `docs/vendor-console-operations.md`, linked from `docs/vendor-console.md`. No new dependency.

**Tech Stack:** Go 1.27, `pgx/v5`, testcontainers PostgreSQL 16 via `vpgtest`, `internal/license` for verification.

**Spec:** `docs/superpowers/specs/2026-10-15-vendor-console-design.md` (sections 6, 7, 9, 10 phase 5, 11 O2)

## Global Constraints

- Branch `vendor-console-ops`, cut from `master`. Merged into `master` locally (fast-forward) at the end; never pushed.
- `alice` must not link `alice/internal/vconsole/...` or `alice/cmd/vendor-*` (existing release-binary test; extend for any new package).
- `internal/vconsole/...` imports only the platform and `alice/internal/license/...` from the product.
- No secret, database URL or private key in output, logs, errors or documents. Examples in documents use placeholders.
- Every new state change is audited by the database (trigger) or by an explicit `audit_append` in the same transaction.
- Go style: errors lower-case and wrapped with `%w`, no `panic` in library code, comments say why; `now` is a parameter, no `time.Now()` in library code.
- Commits end with `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`; commit with `git -c user.name="Eren Altan" -c user.email="erenaltan@gmail.com" commit ...`.

## Rulings

1. **O2 (CSV ledger versus audit table):** the hash-chained `audit` table plus the `licenses` table are the ledger. No CSV export is built (it would have to be signed with the license key, which signs nothing but licenses). `licensectl ledger-verify` stays for old file ledgers. The operations document says so.
2. **Audit head checkpoint instead of a signed head:** the newest audit rows can be deleted without breaking the chain (known Phase 1 limit). The weekly summary mail already goes to the owner: it gets a line `Audit head: <seq>:<hash>`. The owner's mailbox is the external witness. `vendor-console audit-verify --head SEQ:HASH` checks that the chain is intact AND that row `SEQ` exists with that hash (so a later deletion of rows up to that point is noticed).
3. **Owner audit view:** a command line view (`audit show`) for the owner login, not a web page. The web service must not be able to read the audit log, and a web page would need that. Spec section 7 is changed accordingly.
4. **Backup and restore:** the database backup is the operator's job with standard tools (Neon point-in-time restore, plus an encrypted `pg_dump` kept elsewhere). The code adds what only this system can do: `verify-licenses` re-checks every stored license file after a restore. The runbook has the drill.
5. **Revocation of a license:** `license revoke` sets `licenses.revoked_at` (the vendor record: reminders and lists stop; the customer's installation is not affected, because license files are checked offline). Revoking a SIGNING key is a product release and is in the runbook (existing mechanism `status: revoked`, `revoked_from`).
6. **Trusted proxy:** `vendor-web --trusted-proxy CIDR` (repeatable). Only when the TCP peer is inside one of these ranges is `X-Forwarded-For` used, and then the right-most address that is NOT inside a trusted range is the client. Used for the rate limiter only.

## Review Focus

- The head check must fail when the newest rows were deleted, when a row was edited, and when the head string is malformed; it must pass on a healthy chain with later rows added. Pinned in Task 1.
- `verify-licenses` must catch: a file whose bytes changed (sha mismatch), a file that does not verify against the key set, a row whose columns disagree with the signed payload (customer, installation, targets, valid_until, license ID), a missing file. Pinned in Task 2.
- `license revoke` of an unknown, already revoked, or other-customer license: distinct errors, nothing changed; non-owner refused. Pinned in Task 3.
- `X-Forwarded-For` from an untrusted peer must be ignored; spoofed left entries behind a trusted proxy must not choose the client; IPv6 and malformed values. Pinned in Task 5.
- `audit show` must not print more than the audit table holds and must cap output; `notify retry` must only touch failed rows. Pinned in Task 4.

---

## File Structure

| Path | Responsibility |
|---|---|
| `internal/vconsole/migrations/00004_ops.sql` | `audit_head()`, revoke guard changes if needed, grants |
| `internal/vconsole/audit/audit.go` | `Head`, `VerifyHead` |
| `internal/vconsole/store/verify.go` | `VerifyLicenses` |
| `internal/vconsole/store/licenses.go` | `RevokeLicense` |
| `internal/vconsole/notify/summary.go` | head line in the weekly summary |
| `cmd/vendor-console/ops.go` | `audit-head`, `audit-verify --head`, `audit show`, `verify-licenses`, `license revoke`, `notify failed`, `notify retry` |
| `internal/vconsole/web/clientip.go`, `server.go`, `cmd/vendor-web/main.go` | trusted proxy |
| `docs/vendor-console-operations.md`, `docs/vendor-console.md`, spec | runbook and updates |

---

### Task 1: Audit head and head verification

**Files:**
- Create: `internal/vconsole/migrations/00004_ops.sql`
- Modify: `internal/vconsole/audit/audit.go`, `internal/vconsole/notify/summary.go`
- Test: `internal/vconsole/audit/audit_integration_test.go` (append), `internal/vconsole/notify/summary_integration_test.go` (append)

**Interfaces:**
- SQL: `audit_head() RETURNS TABLE(seq bigint, hash text)` (SECURITY DEFINER, fixed search_path; empty set when the chain is empty); EXECUTE for `vendor_owner` and `vendor_notifier`, revoked from PUBLIC.
- Go:

```go
type Head struct {
	Seq  int64
	Hash string
}
func (h Head) String() string                 // "<seq>:<hash>"
func ParseHead(s string) (Head, error)        // refuses anything but digits ':' 64 hex
func CurrentHead(ctx context.Context, q Q) (Head, bool, error) // false when the chain is empty
// VerifyHead checks the whole chain (as Check does) and then that row h.Seq exists with hash h.Hash.
// ErrHeadMismatch when the row is missing or differs (rows were removed or replaced).
var ErrHeadMismatch = errors.New("audit: the checkpoint does not match the chain")
func VerifyHead(ctx context.Context, q Q, h Head) error
```

- Weekly summary: a last line `Audit head: <seq>:<hash>` (omitted when the chain is empty), read with `audit_head()` in the same transaction.

- [ ] **Step 1: Write the failing tests** (`integration` tag): `TestCurrentHeadMatchesTheLastRow`; `TestEmptyChainHasNoHead`; `TestVerifyHeadPassesWhenRowsWereAddedLater`; `TestVerifyHeadFailsWhenTheNewestRowsWereDeleted` (delete the last rows as the owner/superuser pool with triggers disabled via `SET session_replication_role = replica`, then `VerifyHead` with the old head → `ErrHeadMismatch`); `TestVerifyHeadFailsWhenARowWasEdited` (chain break reported as `ErrBroken`); `TestVerifyHeadFailsWhenTheHashDiffers`; `TestParseHeadRefusesJunk` (empty, `5`, `5:zz`, `-1:<64hex>`, `5:<63hex>`, uppercase hex is accepted and normalised to lower case, spaces, `5:<hash>\n`); `TestNotifierAndOwnerCanReadHeadButSalesCannot` (42501 for `vendor_sales`, `vendor_web`, `vendor_signer`); summary test `TestSummaryEndsWithTheAuditHead` and `TestSummaryHasNoHeadLineOnAnEmptyChain`.
- [ ] **Step 2: Run to verify failure:** `go test -tags integration ./internal/vconsole/audit/ ./internal/vconsole/notify/ -count=1` → FAIL.
- [ ] **Step 3: Implement** (`audit_head()` is `SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1`; `VerifyHead` runs `Check` then `SELECT hash FROM audit WHERE seq = $1`). Keep all earlier migrations untouched; 00004 has its own `Down`.
- [ ] **Step 4: Run to verify it passes:** `go test -tags integration ./internal/vconsole/... -count=1`.
- [ ] **Step 5: Commit** (`feat(vconsole): audit head, head verification and the head line in the weekly summary`).

---

### Task 2: License integrity check

**Files:**
- Create: `internal/vconsole/store/verify.go`
- Test: `internal/vconsole/store/verify_integration_test.go`

**Interfaces:**
- Produces:

```go
type LicenseProblem struct {
	LicenseID string
	Problem   string // short, no file bytes, no installation ID
}
// VerifyLicenses re-checks every stored license against the given key set and its own row:
// 1. sha256(file) equals file_sha256; 2. the file verifies (signature, key ID known in ks, not
// revoked for the signing date) with license.Verify against ks at the file's own issued time;
// 3. the signed payload agrees with the row: license ID, installation, targets, valid_until, valid_from
// (and customer name equals the customer's name at issue time is NOT checked: names may be corrected).
// It returns problems in license order and the number checked. It never stops at the first problem.
func VerifyLicenses(ctx context.Context, q audit.Q, ks license.KeySet, now time.Time) (checked int, problems []LicenseProblem, err error)
```

  Read how `internal/license` verifies a file (`license.Verify...`, `license.ParseKeySet`/`KeySet` types, `license.DecodeFile`) and use the product's own functions; do not re-implement signature checking. The owner and signer logins may call it (they can read `licenses.file`); the notifier cannot (column grant), which is intended.
- [ ] **Step 1: Write the failing tests** (seed licenses by the real `issue.Issue` with the file signer, as Phase 1 tests do): `TestHealthyLicensesPass`; `TestChangedFileBytesAreFound` (owner pool updates `file` with triggers disabled via `session_replication_role = replica`); `TestFileSignedByAnUnknownKeyIsFound`; `TestFileForADifferentInstallationThanTheRowIsFound`; `TestRowColumnsThatDisagreeWithThePayloadAreFound` (targets, valid_until); `TestAllProblemsAreReportedNotOnlyTheFirst`; `TestEmptyTableChecksZero`; `TestRevokedKeyForTheIssueDateIsReported` (key set with `status: revoked`, `revoked_from` before the license date → problem; after → ok); `TestProblemTextHasNoFileBytesOrInstallationID`.
- [ ] **Steps 2-5:** fail → implement → pass (`go test -tags integration ./internal/vconsole/store/ -count=1`) → commit (`feat(vconsole): re-verify every stored license against the key set`).

---

### Task 3: `license revoke`

**Files:**
- Modify: `internal/vconsole/store/licenses.go`, `internal/vconsole/migrations/00004_ops.sql` (only if a privilege or audit detail is missing)
- Test: `internal/vconsole/store/revoke_integration_test.go`

**Interfaces:**
- `func RevokeLicense(ctx context.Context, q audit.Q, licenseID, reason string, now time.Time) error` — sets `revoked_at = now` where `revoked_at IS NULL`; `ErrNotFound` for unknown; `ErrAlreadyRevoked` if already set; the reason (1..200 characters, one line) goes into the audit row: extend the `license.revoke` audit in a new migration step by passing the reason through a transaction-local setting `vendor.reason` read by the existing trigger function (replace `vendor_audit_licenses()` in 00004; keep the old behavior when the setting is empty). Only `vendor_owner` may revoke (existing `UPDATE (revoked_at)` grant).
- [ ] **Step 1: Write the failing tests:** `TestRevokeSetsTimeAndAuditsTheReason`; `TestRevokeTwiceIsRefused`; `TestRevokeUnknownIsNotFound`; `TestSignerAndSalesCannotRevoke` (42501); `TestRevokedLicenseDisappearsFromEndingList` (uses `ListLicenses` and reminders: no reminder is created after a revoke); `TestReasonRules` (empty, 201 chars, CR/LF refused; control characters refused); `TestRevokeKeepsTheFileAndOtherColumns` (the update guard still forbids other columns); old `license.revoke` audit tests still pass.
- [ ] **Steps 2-5:** fail → implement → pass → commit (`feat(vconsole): revoke a license with a reason`).

---

### Task 4: Owner commands

**Files:**
- Create: `cmd/vendor-console/ops.go`
- Modify: `cmd/vendor-console/run.go` (usage and dispatch), `internal/vconsole/notify/outbox.go` (add `ListFailed`, `RetryFailed`)
- Test: `cmd/vendor-console/ops_test.go`, `cmd/vendor-console/ops_integration_test.go`, `internal/vconsole/notify/failed_integration_test.go`

**Interfaces:**
- Commands: `audit-head` (prints `<seq>:<hash>` or `empty`); `audit-verify [--head SEQ:HASH]`; `audit show [--since YYYY-MM-DD] [--actor NAME] [--action PREFIX] [--limit N]` (default limit 50, maximum 1000; newest first; one line per row: seq, time (UTC), actor, action, subject; `--details` adds the details JSON with installation IDs shortened to 8 characters); `verify-licenses --pub FILE [--pub FILE ...]` (reads public key files the way `licensectl` does, or `--keyset FILE` for a `production.json`; exit 0 when no problems, 1 when problems or checked == 0 with licenses present, 2 usage); `license revoke --id ID --reason TEXT`; `notify failed` (lists failed outbox rows: id, kind, created, attempts, first 80 characters of subject and of last_error); `notify retry ID` (notifier login: sets `failed_at = NULL, attempts = 0, last_error = '', next_attempt_at = now` for that failed row only; refuses a row that is not failed).
- Notify package: `ListFailed(ctx, q, limit int) ([]FailedRow, error)`, `RetryFailed(ctx, q, id int64, now time.Time) error` (`ErrNotFailed`).
- [ ] **Step 1: Write the failing tests:** unit: usage lists every new command; `audit-verify --head bad` exits 2; `audit show --limit 0` and `--limit 1001` exit 2; `verify-licenses` without `--pub`/`--keyset` exits 2; `license revoke` without `--reason` exits 2. Integration: `audit-head` then add a license then `audit-verify --head <old>` exits 0, delete newest rows (replica role) then exits 1 with a message that does not print hashes beyond the head given; `audit show --actor` filters; `audit show` as a sales login exits 1 (permission); `--limit` honored; `verify-licenses` over a healthy database exits 0 and prints `checked N, problems 0`, with a tampered row exits 1 and prints license ID and problem only; `license revoke` flow and audit; `notify failed` lists a failed row and `notify retry` makes it due again, refuses a pending row, and a sales login is refused; no command prints a database URL or password.
- [ ] **Steps 2-5:** fail → implement → pass (`go test ./cmd/vendor-console/ && go test -tags integration ./cmd/vendor-console/ ./internal/vconsole/notify/ -count=1`) → commit (`feat(vconsole): owner commands for the audit, license checks, revoke and failed mail`).

---

### Task 5: Trusted proxy for the web service

**Files:**
- Create: `internal/vconsole/web/clientip.go`
- Modify: `internal/vconsole/web/server.go` (limiter uses the resolved client), `cmd/vendor-web/main.go` (flag), `docs` later in Task 6
- Test: `internal/vconsole/web/clientip_test.go`, `cmd/vendor-web/main_test.go`

**Interfaces:**
- `func ParseTrustedProxies(cidrs []string) ([]netip.Prefix, error)` (refuses empty strings, bare IPs are accepted as /32 or /128, `0.0.0.0/0` and `::/0` are refused: trusting everyone defeats the purpose).
- `Config.TrustedProxies []netip.Prefix`; `func clientAddr(remote string, xff []string, trusted []netip.Prefix) netip.Addr`: peer address after `Unmap`; if the peer is not in `trusted` return it (header ignored); otherwise walk the `X-Forwarded-For` values (all header lines, comma-split, trimmed) from right to left and return the first address that parses and is not in `trusted`; if every entry is trusted or none parse, return the peer. IPv6 keyed by /64 as the limiter already does.
- Flag `--trusted-proxy CIDR` (repeatable), config errors exit 2.
- [ ] **Step 1: Write the failing tests:** table test for `clientAddr`: no header, untrusted peer with spoofed header (ignored), trusted peer one hop, trusted peer chain `client, proxy2` with both proxies trusted, spoofed left entry `1.2.3.4, real` (right-most untrusted wins → `real`), garbage entries skipped, IPv6 peer and IPv6 client, IPv4-mapped IPv6 normalised, all-trusted chain falls back to peer; `ParseTrustedProxies` rules; limiter integration test: two clients behind one trusted proxy have separate buckets; a spoofed header from an untrusted peer does not escape the limit; `main_test.go`: `--trusted-proxy 0.0.0.0/0` exits 2, `--trusted-proxy bad` exits 2.
- [ ] **Steps 2-5:** fail → implement → pass (`go test ./internal/vconsole/web/ ./cmd/vendor-web/`) → commit (`feat(vconsole): trusted proxy option for the web service rate limiter`).

---

### Task 6: Runbook, documents, architecture rules, final checks

**Files:**
- Create: `docs/vendor-console-operations.md`
- Modify: `docs/vendor-console.md`, `docs/vendor/licensing-vendor.md` (pointer only), `docs/superpowers/specs/2026-10-15-vendor-console-design.md`, `internal/archtest/arch_test.go` (only if a new package was added)

- [ ] **Step 1: Write `docs/vendor-console-operations.md`**, verifying every command and statement against the code (run `vendor-console` usage text, read `docs/vendor/licensing-vendor.md` sections 7-8 and 9). Sections:
  1. **Roles and who does what:** owner (UK), IT manager (Istanbul, signer), sales; where each credential lives; one login per person.
  2. **Key ceremony** (YubiKey, once per key; Phase 2 delivers the signer, so this is the checklist the spec section 4.4 calls for): the steps from `ykman info` through generating the key on the device, PIN/PUK/touch policy, recording the public key, `licensectl keyset --pub`, adding it to `internal/license/keys/production.json` (owner key, IT manager key, spare), the release that embeds it, storing spares apart. State clearly that the YubiKey signer is not part of this release if Phase 2 is not built yet, and what is used until then (the file key with its backup rules from `licensing-vendor.md`).
  3. **Onboarding and offboarding:** sales person (database login not needed: `web-user add`, enrollment code, `invite` for a lost key, `disable`), signer (database login creation SQL, key ceremony), leaver checklist (disable web user, drop database login, `REASSIGN OWNED`/`DROP ROLE` snippet, revoke signing key when the person held one).
  4. **A lost or compromised signing key:** the exact existing mechanism (`status: revoked`, `revoked_from`), the release, which licenses stay valid, how to find licenses signed with that key (`select license_id, issued_at from licenses where key_id = '...'`), `verify-licenses` with the new key set, what to tell customers; reference `licensing-vendor.md` section 8 instead of duplicating it.
  5. **Revoking a license** (`license revoke`) and what it does and does not do.
  6. **Backups and the restore drill:** what to back up (database via Neon point-in-time restore and an encrypted `pg_dump -Fc` stored apart; the key files are NOT in the database), a quarterly drill with exact commands: restore into a scratch database, `vendor-console migrate` finds nothing to do, `audit-verify --head <latest from the weekly mail>`, `verify-licenses --keyset production.json`, spot-check one `license export`; what success looks like; how to record the drill.
  7. **Tamper evidence:** the weekly mail's `Audit head`, keeping it, `audit-verify --head`, what a mismatch means and the steps (stop issuing, compare with the Neon restore point, preserve evidence).
  8. **Monitoring:** `notify run` timer, `notify failed`, `notify retry`, the summary's Failed and Unusual sections, a dead timer (no summary for 8 days) and how the owner notices.
  9. **Incident checklist:** web service break-in (link the recovery note in `vendor-console.md`), signer machine compromise, database credential leak (rotate: `ALTER ROLE ... PASSWORD`, sessions), lost owner login.
  10. **Quarterly and yearly checklist.**
  Keep the style of the existing documents: plain, short sentences, copy-paste commands with placeholders, no secrets.
- [ ] **Step 2:** `docs/vendor-console.md` gets a link to the runbook and the trusted-proxy flag (replace the earlier "prefer own TLS" warning with the flag, keeping the warning about shared counters when the flag is not used) and the new commands. `docs/vendor/licensing-vendor.md` gets one line pointing to the runbook. Spec: O2 resolved (ruling 1), section 6 and 7 updated (head checkpoint, `audit show` instead of a web page), Phase 5 marked built except the YubiKey-dependent ceremony items, phase list status table current (1, 3, 4, 5 built; 2 depends on hardware).
- [ ] **Step 3: Architecture rules/tests** for any new package (none planned; confirm with `go list`), release-binary test unchanged.
- [ ] **Step 4: Final verification:** `gofmt -l cmd internal` (empty); `go vet ./...`; `golangci-lint run ./cmd/... ./internal/vconsole/... ./internal/archtest/...` (0 issues); `go test ./... -count=1`; `go test -tags integration ./internal/vconsole/... ./cmd/vendor-console/... -count=1`.
- [ ] **Step 5: Commit** (`docs(vconsole): operations runbook, phase 5 notes and spec update`), then the final whole-branch review and fast-forward `master`.

---

## Self-Review

- **Spec coverage:** backup and restore drill (Task 6 runbook, Task 2 check), key ceremony checklist (Task 6; the device part waits for Phase 2), key revocation procedure (Task 6 and Task 3), docs (Task 6); carried items: signed head checkpoint (Task 1, as a witnessed head), owner audit view (Task 4 command, ruling 3), `notify failed/retry` (Task 4), `--trusted-proxy` (Task 5).
- **Placeholders:** none; the test lists name inputs and expected outcomes.
- **Types:** `audit.Head`, `ParseHead`, `CurrentHead`, `VerifyHead`, `store.VerifyLicenses`, `store.RevokeLicense`, `notify.ListFailed`, `notify.RetryFailed`, `web.ParseTrustedProxies` are defined before use.
- **Review Focus** lines each map to a named test.
