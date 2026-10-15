# Vendor Console: In-App Notifications Instead of E-mail Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The owner and the sales people see their notifications inside the vendor web application (a bell with an unread count and a notifications page). No e-mail is sent: the SMTP sender, the mail outbox and everything that serves them are removed.

**Architecture:** The notification rules of Phase 4 (issuance, expiry reminders at 90/60/30 days, weekly summary with unusual activity) stay. Their sink changes: instead of `mail_outbox` rows they write `notifications` rows with an audience (`owner`, `sales` or one `user`). The web service reads them through its own narrow grants and records per-user read state in `notification_reads`. The owner becomes a web user with the role `owner`. `vendor-console notify run` stays as the periodic job that creates reminders and the weekly summary (no sending step).

**Tech Stack:** Go 1.27, `pgx/v5`, `html/template`, testcontainers PostgreSQL 16 via `vpgtest`.

**Spec:** `docs/superpowers/specs/2026-10-15-vendor-console-design.md` (section 7 "Owner visibility", open item O5 which this plan retires)

## Global Constraints

- Branch `vendor-console-notifications`, cut from `master`. Merged into `master` locally (fast-forward) at the end; never pushed.
- Nothing from the earlier phases is deployed anywhere, so migrations `00003_notify.sql` and `00004_ops.sql` are edited in place (mail objects removed, notification objects added). Down sections stay correct for what each file creates.
- All earlier security properties stay: `vendor_web` is a member of `vendor_sales` only; it must not gain INSERT on `notifications`, any access to `audit`, `licenses.file` writes, or `EXECUTE` on `audit_*`; the notifier login stays column-limited; every state change is audited by the database where it was before.
- `alice` (the product binary) must not link anything under `alice/internal/vconsole/...` or `alice/cmd/vendor-*`.
- Notification texts contain no license file content and no installation ID beyond what the earlier mail rules allowed (none). Free text from customers and users is cleaned of control and bidi characters in SQL and Go as before, and rendered by `html/template` only.
- Go style: errors lower-case and wrapped with `%w`, no `panic` in library code, comments say why; time is a parameter.
- Commits end with `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`; commit with `git -c user.name="Eren Altan" -c user.email="erenaltan@gmail.com" commit ...`; stage by explicit path only (never `git add -A`; the working tree has untracked files that are not ours).

## Rulings

1. **Where notifications appear:** only in the vendor web application. No browser push, no desktop notification, no terminal notification. The `vendor-console` command line keeps printing results as before.
2. **Who gets what:** issuance and the weekly summary and unusual-activity notices go to the audience `owner`. A reminder goes to `owner` and, when the requester is an enabled web user, to that user (audience `user`). Sales people see their own reminders and any notification with the audience `sales`.
3. **The owner is a web user:** `web_users.role` is `sales` (default) or `owner`; `vendor-console web-user add NAME --owner` creates an owner. The role is read from the database for every request; nobody can set it through the web.
4. **Read state is per user** (`notification_reads`), so two owners each have their own unread count. Notifications are never deleted by the web; the notifier login prunes read-by-everyone ones older than 180 days in `notify run`.
5. **Witness for the audit head:** the weekly e-mail was the external witness of the audit chain head. In-app notifications live in the same database, so they are NOT an external witness. The summary notification still shows `Audit head: <seq>:<hash>`; the runbook now tells the owner to copy it into the paper log every week (`audit-head` prints it on demand). This is a loss of an external channel and is stated honestly in the documents.
6. **No delivery failures to handle:** the retry, backoff, failed list and `notify failed` / `notify retry` commands disappear with the outbox.
7. **Idempotence:** every notification has a `dedupe_key`; inserting the same key twice does nothing (reminders and the weekly summary use it so two concurrent `notify run` processes create each notification once).

## Review Focus

- A sales user must never see an `owner` notification, another user's `user` notification, or mark someone else's as read. Pinned in Task 1 and Task 3.
- `vendor_web` can only SELECT `notifications` and INSERT into `notification_reads` for the signed-in user's id; it cannot insert, update or delete notifications. Pinned in Task 1.
- The issuance notification cannot be skipped by a signer inserting a license with raw SQL (trigger), and cannot make the license insert fail with hostile customer names. Pinned in Task 1.
- Two `notify run` processes create each reminder and each weekly summary once. Pinned in Task 2.
- Disabled web users receive nothing new and cannot read anything (sessions already stop). The owner role cannot be gained by a role-name trick in the session. Pinned in Task 3.
- No leftover mail code, environment variables, grants, tables or documentation. Pinned in Task 4 and Task 5.

---

## File Structure

| Path | Responsibility |
|---|---|
| `internal/vconsole/migrations/00003_notify.sql`, `00004_ops.sql` | `notifications`, `notification_reads`, `web_users.role`, issuance trigger, grants; mail objects removed |
| `internal/vconsole/notify/notify.go` | `Notify` (insert with dedupe), prune |
| `internal/vconsole/notify/reminders.go`, `summary.go`, `preview.go` | reminders, weekly summary, dry run on the new sink |
| `internal/vconsole/webuser/webuser.go` | `Role`, role in `User` |
| `internal/vconsole/web/notifications.go`, templates | bell, list, mark read |
| `cmd/vendor-console/notify.go`, `run.go`, `ops.go` | `notify run` without sending, `web-user add --owner`, removed mail commands |
| `docs/vendor-console.md`, `docs/vendor-console-operations.md`, spec | updated |

---

### Task 1: Schema: notifications, roles, grants (edit migrations 00003 and 00004 in place)

**Files:**
- Modify: `internal/vconsole/migrations/00003_notify.sql`, `internal/vconsole/migrations/00004_ops.sql`, `internal/vconsole/migrations/notify_integration_test.go`, `internal/vconsole/migrations/web_integration_test.go` (only where tests mention the removed objects)
- Test: `internal/vconsole/migrations/notifications_integration_test.go`

**Interfaces:**
- Produces (SQL): table `notifications(id bigint identity PK, kind text, severity text CHECK in ('info','warning','alert'), title text (1..200, one line), body text (<= 4000), audience text CHECK in ('owner','sales','user'), target_user text (web user name; NOT NULL iff audience = 'user'), subject text (e.g. license id, <= 64, may be empty), created_at timestamptz DEFAULT now(), dedupe_key text NOT NULL UNIQUE)`; table `notification_reads(notification_id bigint REFERENCES notifications ON DELETE CASCADE, user_id bigint REFERENCES web_users, read_at timestamptz DEFAULT now(), PRIMARY KEY (notification_id, user_id))`; column `web_users.role text NOT NULL DEFAULT 'sales' CHECK (role IN ('sales','owner'))`; function `web_notifications(p_user_id bigint, p_limit int, p_unread_only boolean)` and `web_unread_count(p_user_id bigint)` (SECURITY DEFINER, fixed search_path; they apply the audience rule using the user's role and name read from `web_users` by id, so the visibility rule lives in one place in the database); `web_mark_read(p_user_id bigint, p_notification_id bigint)` and `web_mark_all_read(p_user_id bigint)` (SECURITY DEFINER; insert only visible notifications into `notification_reads`); EXECUTE for these four granted to `vendor_web` only (and revoked from PUBLIC); the issuance trigger now inserts one `notifications` row (kind `license.issued`, audience `owner`, subject = license id, `dedupe_key = 'issued:' || license_id`, title and body built from the same cleaned values as the old mail: customer, targets, valid_from/valid_until, the real actor (`vendor_actor()`) and the `Recorded signer` line when `signed_by` differs, key ID, request id; no installation ID, no file); `vendor_notifier` gets `SELECT, INSERT` on `notifications` and `DELETE` for pruning only through a SECURITY DEFINER function `notify_prune(p_before timestamptz) RETURNS bigint` that removes notifications older than the cutoff that every web user who could see them has read (or that nobody could see because no such user exists... keep simple: older than cutoff AND (read by at least one user) — document the rule in a comment); the owner gets `SELECT` on `notifications` and `notification_reads`; `web_users.email`, `vendor_settings` key `owner_email`, `mail_outbox`, its audit trigger/function (`mail.retry`), `web_audit_*` mail-related grants, and all mail grants are REMOVED from 00003/00004 (keep `vendor_settings` for `timezone` and `last_summary_at`; keep `notify_mark_summary`). Tighten the `vendor_settings` key CHECK accordingly. The audit trigger for `webuser.email` is removed; role changes of web users are audited (`webuser.add` details include the role).
- [ ] **Step 1: Write the failing tests** (`integration` tag, package `migrations_test`, no new `TestMain`): `TestIssuingALicenseCreatesAnOwnerNotification` (raw SQL insert as signer; one row, audience owner, subject = license id, body has the actor and key id, no installation ID, no file bytes); `TestForgedSignedByNamesTheRealActor` (the `Recorded signer` line); `TestHostileCustomerNameCannotBreakOrForgeLines` (newlines/bidi/300-char name: insert succeeds, one-line title, no extra `Signed by:` line); `TestWebSeesOnlyItsOwnAudience` (owner user sees owner + sales notifications; sales user `ayse` sees sales + her own user notifications, not owner's, not `mehmet`'s); `TestUnreadCountAndMarkRead` (mark read changes only that user's count; marking an invisible notification inserts nothing and returns no error leak; mark-all-read affects only visible ones); `TestWebServiceCannotWriteNotifications` (`vendor_web` INSERT/UPDATE/DELETE on notifications -> 42501; direct INSERT on notification_reads -> 42501 too: reads are written only through the functions); `TestSalesAndSignerCannotCallTheWebFunctions` (42501); `TestNotifierWritesNotificationsAndPrunes` (insert ok, update/delete 42501, `notify_prune` removes only old read ones); `TestDedupeKeyIsUnique`; `TestOwnerRoleOnlyThroughTheDatabase` (role column CHECK; `vendor_web` has no UPDATE on web_users); `TestNoMailObjectsRemain` (no table `mail_outbox`, no function with `mail` in its name, no `owner_email` key accepted, `web_users` has no `email` column); Up/Down/Up sanity for 00003 and 00004 if the old tests had one.
- [ ] **Step 2: Run to verify failure:** `go test -tags integration ./internal/vconsole/migrations/ -count=1` → FAIL.
- [ ] **Step 3: Edit the migrations** following the existing patterns (SECURITY DEFINER with `SET search_path = public, pg_temp`, `REVOKE ALL ... FROM PUBLIC`, explicit grants, `-- +goose StatementBegin/End`). Keep column-level grants narrow. Update the old migration tests that referenced removed objects (delete or rewrite them for the new objects; do not leave skipped tests).
- [ ] **Step 4: Run to verify it passes:** `go test -tags integration ./internal/vconsole/migrations/ -race -count=1` (other packages will fail to compile or test until Tasks 2-4: that is expected on this branch; run only the migrations package here and say so).
- [ ] **Step 5: Commit** (`feat(vconsole): notifications and owner role in the schema, mail objects removed`).

---

### Task 2: The notification sink for reminders, the weekly summary and the dry run

**Files:**
- Create: `internal/vconsole/notify/notify.go`
- Modify: `internal/vconsole/notify/reminders.go`, `summary.go`, `preview.go` and their tests; delete `outbox.go`, `failed.go` and their tests
- Test: `internal/vconsole/notify/notify_integration_test.go` (+ updated existing tests)

**Interfaces:**
- Produces:

```go
type Audience string
const (AudienceOwner Audience = "owner"; AudienceSales Audience = "sales"; AudienceUser Audience = "user")
type Notice struct {
	Kind      string   // e.g. "license.ending", "summary.weekly", "activity.unusual"
	Severity  string   // info | warning | alert
	Title     string
	Body      string
	Audience  Audience
	Target    string   // web user name when Audience is user
	Subject   string
	DedupeKey string
}
// Notify inserts the notice unless its DedupeKey exists; it reports whether a row was created.
func Notify(ctx context.Context, q audit.Q, n Notice) (created bool, err error)
// Prune removes read notifications older than 180 days through notify_prune.
func Prune(ctx context.Context, q audit.Q, now time.Time) (int64, error)
```

- Behavior: `CreateReminders` writes, per license and threshold, an owner notice (`DedupeKey = "ending:<license>:<T>"`, severity warning at 30, info otherwise) and, when the requester is an enabled web user, a user notice (`"ending:<license>:<T>:<user>"`) in the same transaction as the reminder rows; catch-up, revoked/replaced/superseded and ended rules unchanged; the Renew link becomes a path `/requests/new?renew=<id>` in the body (no base URL needed any more: remove the `baseURL` parameter and flag). `WeeklySummary` writes one owner notice (`"summary:<period end date>"`, kind `summary.weekly`) with the same sections as before minus "Failed e-mails" (removed), plus the `Audit head` line; unusual activity additionally creates a separate owner notice with severity `alert` (`"unusual:<period end date>"`) only when the Unusual section is non-empty. `last_summary_at` handling, the 1-hour skew rule and `notify_mark_summary` stay, in the same transaction. The dry run prints what it would create. All "waiting" logic for missing owner addresses disappears.
- [ ] **Step 1: Write the failing tests** (as `vendor_notifier`, seed through the owner pool): move/rewrite the existing reminder and summary tests onto the new sink (every earlier behavior that still applies keeps its test: thresholds, catch-up, boundaries, revoked/replaced/superseded, requester dedupe and disabled users, one bad license does not stop the run, concurrent runs create each notice once (assert row counts), summary period arithmetic, night/6th-license rules and DST, audit-based issued list and the no-audit-row anomaly, 28-day failed mails REMOVED, future-mark skew, dry-run parity with the real run via the shared `summaryDue`), plus: `TestNotifyIsIdempotentOnTheDedupeKey`; `TestUnusualActivityGetsAnAlertNotice` and `TestQuietWeekHasNoAlertNotice`; `TestReminderBodyHasTheRenewPathAndNoInstallationID`; `TestPruneKeepsUnreadAndRecent`.
- [ ] **Step 2: Run to verify failure:** `go test -tags integration ./internal/vconsole/notify/ -count=1` → FAIL (does not compile).
- [ ] **Step 3: Implement** and delete the outbox code. Keep one shared one-line/cleaning helper for titles and names.
- [ ] **Step 4: Run to verify it passes:** `go test -tags integration ./internal/vconsole/notify/ -race -count=1`; `golangci-lint run ./internal/vconsole/notify/...`.
- [ ] **Step 5: Commit** (`feat(vconsole): reminders and the weekly summary write in-app notifications`).

---

### Task 3: Roles and the notifications UI in the web service

**Files:**
- Create: `internal/vconsole/web/notifications.go`, `templates/notifications.html`
- Modify: `internal/vconsole/webuser/webuser.go` (+ tests), `internal/vconsole/web/server.go`, `pages.go`, `templates/layout.html`, `templates/home.html`, `static/app.css`
- Test: `internal/vconsole/webuser/webuser_integration_test.go` (append), `internal/vconsole/web/notifications_integration_test.go`

**Interfaces:**
- `webuser.User` gains `Role string` (`"sales"` or `"owner"`), loaded by every session lookup and by `GetUserByName/ID/ListUsers`; `AddUser(ctx, q, name string, role string)` (role validated; default `sales`); the `list` output and audit details show the role.
- Web: layout shows a bell link `Notifications (N)` with the unread count for every signed-in user (count obtained per request through `web_unread_count`; failure to read it must not break the page: show no count); `GET /notifications?unread=1` lists up to 100 notifications (title, severity badge, time in UTC, subject link: a license ID links to `/licenses` filtered or the request page when the subject is `request:<id>`; the body in a `<details>` element; unread ones marked); `POST /notifications/{id}/read` and `POST /notifications/read-all` (same-origin protected like every POST, redirect back to `/notifications`); the home page shows the three newest unread. The audience rule is NOT re-implemented in Go: only the database functions decide visibility. Severity is shown with a text label, not colour alone.
- [ ] **Step 1: Write the failing tests:** webuser: role round trip, invalid role refused, role present on the `User` returned by `Session`; web (passkey login helper from the existing tests): `TestOwnerSeesOwnerNotificationsSalesDoesNot`; `TestBellShowsTheUnreadCountAndItDropsAfterMarkRead`; `TestMarkReadOfAnInvisibleNotificationIs404OrNoOp` (no information about its existence: same response as an unknown id); `TestReadAllOnlyAffectsOwnState`; `TestNotificationTextIsEscaped` (title and body with `<script>` and bidi characters); `TestNotificationsPageRequiresLogin`; `TestCrossSitePostToReadIsRefused`; `TestNoCountDoesNotBreakThePage` (simulate the count function failing through a revoked EXECUTE in the test database); `TestOwnerNeedsNoSpecialRouteForTheSalesPages` (owner can also use customers/requests/licenses).
- [ ] **Steps 2-5:** fail → implement → pass (`go test -tags integration ./internal/vconsole/webuser/ ./internal/vconsole/web/ -race -count=1`) → commit (`feat(vconsole): notification bell and page in the web service, owner role`).

---

### Task 4: Remove the e-mail machinery; commands

**Files:**
- Delete: `internal/vconsole/mail/` (including `mailtest/`)
- Modify: `cmd/vendor-console/notify.go`, `run.go`, `ops.go`, their tests; `internal/archtest/arch_test.go`; `cmd/alice/license_release_test.go`; `internal/archtest/buildtags_test.go`; `Makefile` (if it names mail); `.github`/CI files if they reference the mail packages
- Test: updated tests in `cmd/vendor-console`

**Interfaces / behavior:**
- `vendor-console notify run [--dry-run]`: steps: `CreateReminders`, `WeeklySummary`, `Prune`; prints one line per step with counts (`reminders: N created`, `weekly summary: created|not due`, `pruned: N`); exit 1 when a step errors (and the other steps still run), else 0. No SMTP variables, no `--base-url`. It needs a `vendor_notifier` login (same membership check as before); `--dry-run` writes nothing (read-only transaction, shared `summaryDue`).
- Removed: `settings set owner_email` (the key no longer exists; `settings set timezone` stays), `web-user set-email`, `notify failed`, `notify retry`, every `VENDOR_SMTP_*` reference, `mail.ValidateAddress` users, the `mailtest` architecture rows and test-only registrations, the mail package rules, all stale tests.
- `web-user add NAME [--owner]` creates the role; `web-user list` shows the role; `web-user` has no role-change command in this plan (an owner is created as an owner; changing a role needs `disable` + a new user: documented), keeping the surface small.
- Usage text updated; `docs` later in Task 5.
- [ ] **Step 1: Write/adjust the failing tests:** usage lists no mail command and does list `web-user add NAME [--owner]`; `notify run --dry-run` writes nothing (row counts and settings snapshot unchanged) and agrees with the real run on `summary due`; a real run creates notifications and a second run creates none; exit code 1 when one step fails (inject through a revoked privilege) while the others still ran; `web-user add --owner` creates an owner and `list` shows it; `settings set owner_email` is refused as an unknown key; no output contains a database URL or password; architecture tests no longer mention `mail`/`mailtest`; `go list -deps ./cmd/vendor-console` contains no `net/smtp`.
- [ ] **Step 2: Run to verify failure:** `go test ./cmd/vendor-console/ ./internal/archtest/ ./cmd/alice/` and the integration run → FAIL.
- [ ] **Step 3: Implement the removal** (`git rm -r internal/vconsole/mail`), fix compile errors everywhere, `grep -rIn -i "smtp\|mail_outbox\|owner_email\|mailtest\|ErrInvalidMessage\|vendor_notifier.*mail" --include=*.go --include=*.sql --include=Makefile --include=*.yml .` must show nothing relevant (docs are Task 5).
- [ ] **Step 4: Run to verify it passes:** `go build ./... && go vet ./cmd/... ./internal/vconsole/... && go test ./cmd/... ./internal/archtest/ ./internal/vconsole/... && go test -tags integration ./internal/vconsole/... ./cmd/vendor-console/... -race -count=1`; `golangci-lint run ./cmd/... ./internal/vconsole/... ./internal/archtest/...` (0 issues).
- [ ] **Step 5: Commit** (`refactor(vconsole): remove the e-mail machinery; notify run only creates notifications`).

---

### Task 5: Documents, spec, final checks

**Files:**
- Modify: `docs/vendor-console.md`, `docs/vendor-console-operations.md`, `docs/vendor/licensing-vendor.md` (only if it mentions mail), the design spec

- [ ] **Step 1: Documents** (verify every statement against the code): remove the "Mail and reminders" section and every mention of SMTP, `VENDOR_SMTP_*`, the outbox, failed mail, `notify failed/retry`, owner e-mail, sender address, STARTTLS and EHLO notes; add "Notifications": what creates a notification (issuance, reminders at 90/60/30, weekly summary, unusual activity alert), who sees what (owner / sales / own), the bell and the page, `web-user add NAME --owner` for the owner (the owner needs a passkey like everybody), the periodic job (`notify run` with a systemd timer example hourly: unit file with `User=`, `EnvironmentFile` holding only the database URL of the notifier login, 0600), `notify run --dry-run`, pruning after 180 days. Runbook: the weekly summary notification carries the audit head: the owner copies it into the paper log every week (also `audit-head`); STATE PLAINLY that in-app notifications are not an external witness (they live in the same database) and that the paper log is the witness; update the audit-head drill, monitoring section (a dead timer means no weekly summary notification for 8 days: the owner must look at the bell weekly; there is no mail to notice absence: add a calendar reminder to the checklist), incident checklists (no mail trail: the audit and the notifications table), quarterly checklist (counter reconciliation stays), roles section (owner is a web user with role owner; the owner also keeps the `vendor_owner` database login for CLI work). Spec: section 7 rewritten to what exists (in-app notifications, no e-mail), O5 closed as 'not needed: in-app notifications', phase 4 text updated, roles table: the notifier row no longer mentions mail, the owner row mentions the web role.
- [ ] **Step 2: Final verification:** `gofmt -l cmd internal` (empty); `go build ./... && go build -tags yubikey ./...`; `CGO_ENABLED=0 go build ./cmd/alice ./cmd/vendor-console ./cmd/vendor-web`; `go vet ./...`; `golangci-lint run ./cmd/... ./internal/vconsole/... ./internal/archtest/...` (0 issues); `go test ./... -count=1`; `go test -tags integration ./internal/vconsole/... ./cmd/vendor-console/... -count=1`; `grep -rIni "smtp\|e-mail\|email\|mail_outbox" docs/vendor-console*.md docs/vendor/ docs/superpowers/specs/2026-10-15-vendor-console-design.md` shows only deliberate historical mentions (the spec may keep a short note that e-mail was dropped).
- [ ] **Step 3: Commit** (`docs(vconsole): in-app notifications replace e-mail`), then the final whole-branch review and fast-forward `master`.

---

## Self-Review

- **Spec coverage:** owner visibility (spec section 7): issuance notification (Task 1), weekly summary with unusual activity (Task 2), expiry reminders to the sales owner and the owner (Task 2), the web page shows it (Task 3); e-mail removed (Task 4); documents (Task 5). The audit-head witness loss is stated (ruling 5).
- **Placeholders:** none; test lists name inputs and outcomes.
- **Types:** `Notice`, `Notify`, `Prune`, `Audience`, `webuser.User.Role`, the four SQL functions are defined before use.
- **Review Focus** lines each map to a named test.
