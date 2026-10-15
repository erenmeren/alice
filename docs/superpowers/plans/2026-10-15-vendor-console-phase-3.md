# Vendor Console Phase 3 (Sales Web Page) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A small web service for sales people (login with a passkey, customers, license requests, license list with end dates, download of signed files) that holds no signing key and cannot sign.

**Architecture:** New command `cmd/vendor-web` and packages `internal/vconsole/webuser` (users, enrollment, passkeys, sessions in PostgreSQL) and `internal/vconsole/web` (HTTP handlers, server-rendered `html/template`, one small static JS file for the WebAuthn ceremony). The service connects to PostgreSQL as one service login (`vendor_web`, member of `vendor_sales` only, never `vendor_signer`). It acts for the signed-in person inside each transaction by setting `vendor.actor`; a database function `vendor_actor()` honors that setting only for logins that are members of `vendor_web`, so audit rows and row-level security name the real person (`web:<name>`), and no other login can use the setting to impersonate.

**Tech Stack:** Go 1.27, `net/http` (`ServeMux` patterns, `http.CrossOriginProtection`), `html/template`, `pgx/v5`, `github.com/go-webauthn/webauthn` (new dependency, added in Task 3), testcontainers PostgreSQL 16 via `vpgtest`.

**Spec:** `docs/superpowers/specs/2026-10-15-vendor-console-design.md` (sections 2, 3 "Sales web service", 5, 9 "Sales login", 10 phase 3)

## Global Constraints

- Branch `vendor-console-web`, cut from `master`. Merged into `master` locally (fast-forward) at the end; never pushed.
- `alice` (the product binary) must not link `alice/internal/vconsole/...`, `alice/cmd/vendor-console` or `alice/cmd/vendor-web` (extend `TestReleaseBinaryLinksNoTestOrVendorCode`).
- The web service has no signing key, never imports `internal/vconsole/sign` or `internal/vconsole/issue` and never logs a database URL, token or session cookie.
- `vendor_web` is a member of `vendor_sales` and of nothing else; it has no `INSERT` on `licenses`, no `SELECT` on `audit`, no `EXECUTE` on `audit_append` or `audit_verify`.
- Connections to PostgreSQL: `sslmode=verify-full` unless the host is loopback (same rule as `vendor-console`).
- Cookies: `__Host-` prefix when served over HTTPS, `HttpOnly`, `Secure`, `SameSite=Strict`; session lifetime 8 hours absolute, 30 minutes idle.
- Content-Security-Policy `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`. No inline script or style.
- No change to `internal/license`, `internal/license/issuer`, the license format or the Phase 1 tables except the `DEFAULT`/policy replacements listed in Task 1.
- Go style: errors lower-case and wrapped with `%w`, no `panic` in library code, comments say why.
- Commits end with `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`. Git has no identity in this environment: `git -c user.name="Eren Altan" -c user.email="erenaltan@gmail.com" commit ...`.

## Rulings (open item O4 and friends, decided here, recorded in the spec at the end)

1. **Where it runs / who operates it (O4):** one static binary `vendor-web` behind any TLS-terminating reverse proxy, or with its own `--tls-cert/--tls-key`. Operated by the IT manager (Istanbul); the owner holds the `vendor_owner` login that creates web users. Single instance (the WebAuthn ceremony state is kept in memory with a 5 minute lifetime).
2. **Web users are not database logins.** Sales people exist as rows in `web_users`; the service is the one database login. The audit actor is `web:<name>`.
3. **Enrollment:** the owner runs `vendor-console web-user add NAME`, which prints a one-time enrollment code (valid 24 hours, stored hashed). The person opens `/enroll`, enters the code, and registers a passkey. A lost key: `vendor-console web-user invite NAME` issues a new code; adding a passkey never removes others; `web-user disable NAME` ends access and sessions.
4. **Audit view for the owner** (spec section 7) and e-mail are Phase 4, not here.

## Review Focus

- A login that is not a member of `vendor_web` sets `vendor.actor` to someone else's name: audit and RLS must still show its own login. Pinned in Task 1.
- Two web users: one cancels or reads the other's request. Cancel must fail for the other's; read is allowed. Pinned in Task 1 and Task 4.
- Enrollment code used twice, expired, or for a disabled user: refused. A disabled user's existing session stops working. Pinned in Task 2.
- A session cookie that is expired, idle too long, forged, or from before the user was disabled: treated as signed out. Pinned in Task 2 and Task 3.
- A cross-site POST (wrong `Origin` / `Sec-Fetch-Site: cross-site`) to any state-changing route: refused with 403. Pinned in Task 3.
- A license file download for a license that does not exist or an ID with path characters: 404, never a path or SQL error text. Pinned in Task 4.
- Customer names and notes containing `<script>`: rendered escaped. Pinned in Task 4.

---

## File Structure

| Path | Responsibility |
|---|---|
| `internal/vconsole/migrations/00002_web.sql` | `vendor_web` role, `vendor_actor()`, web tables, grants, audit triggers |
| `internal/vconsole/webuser/webuser.go` | users, enrollment codes, stored passkeys, sessions |
| `internal/vconsole/store/licenses.go` | `ListLicenses` (end dates, filter) |
| `internal/vconsole/web/server.go` | `Server`, routing, middleware (headers, limiter, CSRF, session), `inActorTx` |
| `internal/vconsole/web/passkey.go` | WebAuthn begin/finish handlers for enroll and login |
| `internal/vconsole/web/pages.go` | customers, requests, licenses, download handlers |
| `internal/vconsole/web/templates/*.html`, `static/passkey.js`, `static/app.css` | embedded UI |
| `cmd/vendor-web/main.go` | config from environment and flags, TLS, graceful shutdown |
| `cmd/vendor-console/run.go` | new `web-user add|invite|disable|list` commands |
| `docs/vendor-console.md` | operator notes for the web service |

Dependency direction: `cmd/vendor-web` -> `web` -> `webuser`, `store`, `audit`; `web` never -> `sign`, `issue`.

---

### Task 1: Migration 00002: actor function, `vendor_web` role, web tables

**Files:**
- Create: `internal/vconsole/migrations/00002_web.sql`
- Test: `internal/vconsole/migrations/web_integration_test.go`

**Interfaces:**
- Produces (SQL): role `vendor_web` (NOLOGIN, member of `vendor_sales`); function `vendor_actor() text`; tables `web_users(id, name, created_by, created_at, disabled_at)`, `web_credentials(credential_id bytea PK, user_id, credential jsonb, created_at, last_used_at)`, `web_enrollments(token_hash text PK, user_id, expires_at, used_at)`, `web_sessions(token_hash text PK, user_id, created_at, expires_at, last_seen)`; function `web_audit_login(p_user text)` (SECURITY DEFINER, writes action `web.login`).
- Consumes: Phase 1 tables, `audit_append`, `vpgtest.New`, `d.As(t, group, login)`.

- [ ] **Step 1: Write the failing test** `web_integration_test.go` (build tag `integration`, package `migrations_test`, `TestMain` already exists in this package's other test files, do not add another):

```go
func TestActorSettingIsHonoredOnlyForTheWebServiceLogin(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	web := d.As(t, "vendor_web", "t_web_svc")
	sales := d.As(t, "vendor_sales", "t_sales_impostor")

	actor := func(p *pgxpool.Pool) string {
		tx, err := p.Begin(ctx)
		require.NoError(t, err)
		defer func() { _ = tx.Rollback(ctx) }()
		_, err = tx.Exec(ctx, `SELECT set_config('vendor.actor', 'ayse', true)`)
		require.NoError(t, err)
		var a string
		require.NoError(t, tx.QueryRow(ctx, `SELECT vendor_actor()`).Scan(&a))
		return a
	}
	assert.Equal(t, "web:ayse", actor(web))
	assert.Equal(t, "t_sales_impostor", actor(sales))
}

func TestWebServiceActsAsThePersonInRowsAndAudit(t *testing.T) {
	d := vpgtest.New(t)
	ctx := context.Background()
	web := d.As(t, "vendor_web", "t_web_svc2")

	var cid int64
	tx, _ := web.Begin(ctx)
	_, err := tx.Exec(ctx, `SELECT set_config('vendor.actor', 'ayse', true)`)
	require.NoError(t, err)
	require.NoError(t, tx.QueryRow(ctx, `INSERT INTO customers (name) VALUES ('Acme') RETURNING id`).Scan(&cid))
	var by string
	require.NoError(t, tx.QueryRow(ctx, `SELECT created_by FROM customers WHERE id = $1`, cid).Scan(&by))
	require.NoError(t, tx.Commit(ctx))
	assert.Equal(t, "web:ayse", by)

	var actor string
	require.NoError(t, d.Owner.QueryRow(ctx, `SELECT actor FROM audit WHERE action = 'customer.add'`).Scan(&actor))
	assert.Equal(t, "web:ayse", actor)
}

func TestWebUserCannotCancelAnotherWebUsersRequest(t *testing.T) {
	// Insert a request as web:ayse, then try UPDATE ... status='cancelled' as web:mehmet
	// in a transaction with set_config('vendor.actor','mehmet'); RowsAffected must be 0.
	// Then cancel as web:ayse; RowsAffected must be 1.
}

func TestWebServiceHasNoSigningOrAuditPrivileges(t *testing.T) {
	// As vendor_web: INSERT INTO licenses ..., SELECT FROM audit, SELECT audit_append(...),
	// SELECT audit_verify() each fail with SQLSTATE 42501 (insufficient_privilege).
}

func TestWebLoginAuditRowNamesThePerson(t *testing.T) {
	// As vendor_web: SELECT web_audit_login('ayse'); owner reads audit: action 'web.login',
	// subject 'ayse', actor is the service login (the function records who asked and for whom).
}
```

Write the two commented tests out in full (same helper style as the first two); they are not placeholders for the implementer to skip: each must contain the SQL and assertions stated in its comment.

- [ ] **Step 2: Run to verify failure**

Run: `go test -tags integration ./internal/vconsole/migrations/ -run 'Actor|WebService|WebUser|WebLogin' -v`
Expected: FAIL (role `vendor_web` does not exist).

- [ ] **Step 3: Write `00002_web.sql`**

```sql
-- +goose Up
-- +goose StatementBegin
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vendor_web') THEN
        CREATE ROLE vendor_web NOLOGIN IN ROLE vendor_sales;
    END IF;
END
$$;
-- +goose StatementEnd

-- Who is acting. The web service is one login that acts for a signed-in person by setting
-- vendor.actor for the transaction. The setting counts only for members of vendor_web, so any
-- other login that sets it still appears under its own name.
-- +goose StatementBegin
CREATE FUNCTION vendor_actor() RETURNS text LANGUAGE sql STABLE AS $$
    SELECT CASE
        WHEN pg_has_role(session_user, 'vendor_web', 'member')
             AND coalesce(current_setting('vendor.actor', true), '') ~ '^[A-Za-z0-9._-]{1,64}$'
        THEN 'web:' || current_setting('vendor.actor', true)
        ELSE session_user::text
    END
$$;
-- +goose StatementEnd
GRANT EXECUTE ON FUNCTION vendor_actor() TO vendor_sales;

CREATE OR REPLACE FUNCTION audit_actor() RETURNS text LANGUAGE sql STABLE AS $$ SELECT vendor_actor() $$;

ALTER TABLE customers        ALTER COLUMN created_by   SET DEFAULT vendor_actor();
ALTER TABLE license_requests ALTER COLUMN requested_by SET DEFAULT vendor_actor();
ALTER TABLE licenses         ALTER COLUMN signed_by    SET DEFAULT vendor_actor();

DROP POLICY requests_insert ON license_requests;
DROP POLICY requests_update_own ON license_requests;
CREATE POLICY requests_insert ON license_requests FOR INSERT TO vendor_sales
    WITH CHECK (requested_by = vendor_actor() AND status = 'open');
CREATE POLICY requests_update_own ON license_requests FOR UPDATE TO vendor_sales
    USING (requested_by = vendor_actor() AND status = 'open')
    WITH CHECK (requested_by = vendor_actor() AND status IN ('open', 'cancelled'));

CREATE TABLE web_users (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name        text NOT NULL CHECK (name ~ '^[A-Za-z0-9._-]{1,64}$'),
    created_by  text NOT NULL DEFAULT session_user,
    created_at  timestamptz NOT NULL DEFAULT now(),
    disabled_at timestamptz
);
CREATE UNIQUE INDEX web_users_name_key ON web_users (lower(name));

CREATE TABLE web_credentials (
    credential_id bytea PRIMARY KEY,
    user_id       bigint NOT NULL REFERENCES web_users (id),
    credential    jsonb NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_used_at  timestamptz
);
CREATE INDEX web_credentials_user_idx ON web_credentials (user_id);

CREATE TABLE web_enrollments (
    token_hash text PRIMARY KEY,
    user_id    bigint NOT NULL REFERENCES web_users (id),
    expires_at timestamptz NOT NULL,
    used_at    timestamptz
);

CREATE TABLE web_sessions (
    token_hash text PRIMARY KEY,
    user_id    bigint NOT NULL REFERENCES web_users (id),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    last_seen  timestamptz NOT NULL
);

REVOKE ALL ON web_users, web_credentials, web_enrollments, web_sessions FROM PUBLIC;
GRANT SELECT ON web_users TO vendor_web;
GRANT SELECT, INSERT, UPDATE ON web_credentials TO vendor_web;
GRANT SELECT, UPDATE ON web_enrollments TO vendor_web;
GRANT SELECT, INSERT, UPDATE, DELETE ON web_sessions TO vendor_web;
-- The owner creates and disables web users and issues enrollment codes.
GRANT SELECT, INSERT, UPDATE ON web_users TO vendor_owner;
GRANT SELECT, INSERT ON web_enrollments TO vendor_owner;
GRANT SELECT ON web_credentials TO vendor_owner;
GRANT DELETE ON web_sessions TO vendor_owner;
GRANT SELECT ON web_sessions TO vendor_owner;

-- +goose StatementBegin
CREATE FUNCTION vendor_audit_web() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
    IF TG_TABLE_NAME = 'web_users' THEN
        IF TG_OP = 'INSERT' THEN
            PERFORM audit_append('webuser.add', NEW.name, '{}'::jsonb);
        ELSIF NEW.disabled_at IS DISTINCT FROM OLD.disabled_at THEN
            PERFORM audit_append(CASE WHEN NEW.disabled_at IS NULL THEN 'webuser.enable' ELSE 'webuser.disable' END, NEW.name, '{}'::jsonb);
        END IF;
    ELSIF TG_TABLE_NAME = 'web_credentials' AND TG_OP = 'INSERT' THEN
        PERFORM audit_append('webuser.passkey_add', NEW.user_id::text, '{}'::jsonb);
    ELSIF TG_TABLE_NAME = 'web_enrollments' AND TG_OP = 'INSERT' THEN
        PERFORM audit_append('webuser.invite', NEW.user_id::text, jsonb_build_object('expires_at', NEW.expires_at));
    END IF;
    RETURN NULL;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER web_users_audit AFTER INSERT OR UPDATE ON web_users FOR EACH ROW EXECUTE FUNCTION vendor_audit_web();
CREATE TRIGGER web_credentials_audit AFTER INSERT ON web_credentials FOR EACH ROW EXECUTE FUNCTION vendor_audit_web();
CREATE TRIGGER web_enrollments_audit AFTER INSERT ON web_enrollments FOR EACH ROW EXECUTE FUNCTION vendor_audit_web();

-- The web service may record one kind of audit row: a successful sign-in.
-- +goose StatementBegin
CREATE FUNCTION web_audit_login(p_user text) RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp AS $$
    SELECT audit_append('web.login', p_user, '{}'::jsonb) WHERE EXISTS (SELECT 1 FROM web_users WHERE name = p_user AND disabled_at IS NULL)
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION web_audit_login(text), vendor_audit_web() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION web_audit_login(text) TO vendor_web;

-- +goose Down
DROP FUNCTION web_audit_login(text);
DROP TABLE web_sessions, web_enrollments, web_credentials, web_users;
DROP FUNCTION vendor_audit_web();
```

(The `Down` section keeps the Phase 1 pattern of dropping only what this migration created; the `DEFAULT`/policy replacements are not reverted because Phase 1 `Down` drops the tables anyway.)

- [ ] **Step 4: Run to verify it passes**

Run: `go test -tags integration ./internal/vconsole/... -count=1`
Expected: PASS, including all Phase 1 tests (policies were replaced, behavior for plain logins is unchanged because `vendor_actor()` returns `session_user` for them).

- [ ] **Step 5: Commit**

```bash
git add internal/vconsole/migrations
git -c user.name="Eren Altan" -c user.email="erenaltan@gmail.com" commit -m "feat(vconsole): web service role, actor function and web tables

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 2: `webuser` package: users, enrollment codes, passkeys, sessions

**Files:**
- Create: `internal/vconsole/webuser/webuser.go`
- Test: `internal/vconsole/webuser/webuser_integration_test.go` (tag `integration`, `TestMain` with `vpgtest.Main`)

**Interfaces:**
- Consumes: `audit.Q` (`alice/internal/vconsole/audit`).
- Produces:

```go
var (
	ErrNotFound  = errors.New("webuser: not found")
	ErrBadCode   = errors.New("webuser: the enrollment code is wrong, used or expired")
	ErrNoSession = errors.New("webuser: no valid session")
)

type User struct {
	ID       int64
	Name     string
	Disabled bool
}

func AddUser(ctx context.Context, q audit.Q, name string) (int64, error)               // owner
func SetDisabled(ctx context.Context, q audit.Q, name string, disabled bool, now time.Time) error // owner; also deletes the user's sessions
func ListUsers(ctx context.Context, q audit.Q) ([]User, error)
func GetUserByName(ctx context.Context, q audit.Q, name string) (User, error)
func GetUserByID(ctx context.Context, q audit.Q, id int64) (User, error)

func NewEnrollment(ctx context.Context, q audit.Q, userID int64, now time.Time, ttl time.Duration) (code string, err error) // owner
// LookupEnrollment returns the user for a valid, unused code without consuming it.
func LookupEnrollment(ctx context.Context, q audit.Q, code string, now time.Time) (User, error)
// ConsumeEnrollment marks the code used (UPDATE ... WHERE used_at IS NULL AND expires_at > now); ErrBadCode if no row changed.
func ConsumeEnrollment(ctx context.Context, q audit.Q, code string, now time.Time) error

type StoredCredential struct {
	ID   []byte
	JSON []byte // the library's credential, as JSON
}
func AddCredential(ctx context.Context, q audit.Q, userID int64, id, credentialJSON []byte) error
func Credentials(ctx context.Context, q audit.Q, userID int64) ([]StoredCredential, error)
func UpdateCredential(ctx context.Context, q audit.Q, id, credentialJSON []byte, now time.Time) error
func UserByCredential(ctx context.Context, q audit.Q, id []byte) (User, error)

const (
	SessionAbsolute = 8 * time.Hour
	SessionIdle     = 30 * time.Minute
)
func NewSession(ctx context.Context, q audit.Q, userID int64, now time.Time) (token string, err error)
// Session returns the user of a valid token and extends last_seen; ErrNoSession for unknown, expired,
// idle-expired tokens and disabled users.
func Session(ctx context.Context, q audit.Q, token string, now time.Time) (User, error)
func EndSession(ctx context.Context, q audit.Q, token string) error
```

Tokens and codes are 32 random bytes, base64url without padding; only `hex(sha256(token))` is stored. Codes are shown to humans, so `NewEnrollment` returns the same encoding (43 characters); the `/enroll` page accepts it with surrounding spaces trimmed.

- [ ] **Step 1: Write failing tests** (each uses `vpgtest.New`, an owner-group login `d.As(t,"vendor_owner","t_wu_owner")` and a web login `d.As(t,"vendor_web","t_wu_web")`):
  - `TestEnrollmentCodeWorksOnce`: owner adds user and code; web `LookupEnrollment` returns the user; `ConsumeEnrollment` succeeds; second `ConsumeEnrollment` and `LookupEnrollment` return `ErrBadCode`.
  - `TestEnrollmentCodeExpires`: ttl 1 minute, `now+2min` → `ErrBadCode`.
  - `TestWrongCodeIsRefused`: random string → `ErrBadCode` (no error text containing SQL).
  - `TestDisabledUserCannotEnrollOrKeepASession`: user with a session and an unused code; `SetDisabled(true)` → `Session` returns `ErrNoSession`, `LookupEnrollment` returns `ErrBadCode`.
  - `TestSessionIdleAndAbsoluteLimits`: `Session` at `now+29m` ok (and moves `last_seen`), at `+29m+31m` after that fails (idle), a session touched every 20 minutes still dies at `SessionAbsolute`.
  - `TestForgedAndUnknownSessionTokens`: `""`, random, and a valid token with one character changed → `ErrNoSession`.
  - `TestEndSession`: after `EndSession`, `Session` fails.
  - `TestCredentialsRoundTrip`: `AddCredential` then `Credentials` returns the bytes; `UpdateCredential` replaces JSON and sets `last_used_at`; `UserByCredential` finds the user; duplicate credential id → error.
  - `TestAddUserNameRules`: names `"a b"`, `""`, 65 chars refused; `Ayse` and `ayse` are the same user (`ErrDuplicateUser`).
  - `TestSalesLoginCannotCreateUsers`: `vendor_sales` login → permission error.

- [ ] **Step 2: Run to verify failure**

Run: `go test -tags integration ./internal/vconsole/webuser/ -count=1`
Expected: FAIL (package does not compile).

- [ ] **Step 3: Implement** `webuser.go` following the interface above. Key statements:

```go
func hashToken(t string) string { s := sha256.Sum256([]byte(t)); return hex.EncodeToString(s[:]) }

func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil { return "", fmt.Errorf("webuser: random: %w", err) }
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ConsumeEnrollment
tag, err := q.Exec(ctx, `UPDATE web_enrollments e SET used_at = $2
	FROM web_users u WHERE e.token_hash = $1 AND e.used_at IS NULL AND e.expires_at > $2
	AND u.id = e.user_id AND u.disabled_at IS NULL`, hashToken(code), now)

// Session
err := q.QueryRow(ctx, `UPDATE web_sessions s SET last_seen = $2
	FROM web_users u WHERE s.token_hash = $1 AND u.id = s.user_id AND u.disabled_at IS NULL
	AND s.expires_at > $2 AND s.last_seen > $2 - $3::interval
	RETURNING u.id, u.name`, hashToken(token), now, fmt.Sprintf("%d seconds", int(SessionIdle.Seconds()))).Scan(&u.ID, &u.Name)
```

`SetDisabled` runs `UPDATE web_users SET disabled_at = $2 / NULL` and `DELETE FROM web_sessions WHERE user_id = ...` (the owner has both rights). `AddUser` maps the unique violation on `web_users_name_key` to `ErrDuplicateUser` with `db.IsUniqueViolationOn`.

- [ ] **Step 4: Run to verify it passes**

Run: `go test -tags integration ./internal/vconsole/webuser/ -count=1`
Expected: PASS.

- [ ] **Step 5: Commit** (`feat(vconsole): web users, enrollment codes, passkeys and sessions`).

---

### Task 3: Web server skeleton, passkey enrollment and login

**Files:**
- Create: `internal/vconsole/web/server.go`, `internal/vconsole/web/passkey.go`, `internal/vconsole/web/templates/{layout,login,enroll}.html`, `internal/vconsole/web/static/passkey.js`, `internal/vconsole/web/static/app.css`, `internal/vconsole/web/embed.go`
- Modify: `go.mod`, `go.sum`
- Test: `internal/vconsole/web/server_test.go` (unit, no database), `internal/vconsole/web/passkey_integration_test.go`

**Interfaces:**
- Consumes: Task 2 `webuser`; `audit.Q`.
- Produces:

```go
type Config struct {
	Pool        *pgxpool.Pool
	RPID        string // e.g. "licenses.example.com"
	Origin      string // e.g. "https://licenses.example.com"; http only for localhost
	Clock       clock.Clock
	CookieName  string // set by New: "__Host-vsession" for https origins, "vsession" otherwise
}
func New(cfg Config) (*Server, error)
func (s *Server) Handler() http.Handler
// inActorTx runs fn in a transaction in which vendor.actor is the signed-in user's name.
func (s *Server) inActorTx(ctx context.Context, u webuser.User, fn func(tx pgx.Tx) error) error
```

- [ ] **Step 1: Spike the dependency**

Run: `go get github.com/go-webauthn/webauthn@latest && go build ./...`
Expected: success. If the module needs a Go version above 1.27.2 or pulls a conflicting `golang.org/x/*`, stop and record it; fall back to the next older minor version of the library.

- [ ] **Step 2: Write failing unit tests** `server_test.go` using `httptest` and a `Server` built with a nil pool where the route does not touch the database:
  - `TestSecurityHeadersOnEveryResponse`: GET `/login` has the exact CSP from Global Constraints, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`; static files get the CSP too.
  - `TestCrossSitePostIsRefused`: POST `/logout` and POST `/webauthn/login/begin` with `Sec-Fetch-Site: cross-site`, and with `Origin: https://evil.example` → 403.
  - `TestUnauthenticatedPagesRedirectToLogin`: GET `/`, `/customers`, `/requests/new`, `/licenses` → 303 to `/login`; `/licenses/x/download` → 303 as well (never the file).
  - `TestBeginEndpointsAreRateLimited`: 11th POST to `/webauthn/login/begin` within a minute from one address → 429; a different `RemoteAddr` is unaffected. Limiter: fixed window, 10 per minute per IP (`netip.Addr` from `RemoteAddr`; behind a proxy only `X-Forwarded-For` of a trusted proxy would count, which this phase does not support: documented).
  - `TestInsecureOriginIsRefusedExceptLocalhost`: `New` with `Origin: http://example.com` errors; `http://localhost:8443` and `https://x.example` are accepted; `RPID` must equal the origin's host without port.

- [ ] **Step 3: Write failing integration tests** `passkey_integration_test.go` driving the ceremony with a software authenticator. The library ships none; use `github.com/descope/virtualwebauthn` (add with `go get`, test-only) to produce attestation and assertion for the options JSON the server returns:
  - `TestEnrollThenLogin`: owner adds `ayse` and a code; GET `/enroll` shows the form; POST `/webauthn/register/begin` with the code returns options; the virtual authenticator's attestation posted to `/webauthn/register/finish` returns 200 and stores one credential; `/webauthn/login/begin` (discoverable) then `/webauthn/login/finish` returns 200 with a `Set-Cookie` for the session (`HttpOnly`, `Secure` when https, `SameSite=Strict`); GET `/` with that cookie is 200; audit has `web.login` for `ayse`.
  - `TestEnrollmentCodeCannotBeReused`: second `register/begin` with the same code after a successful finish → 400.
  - `TestRegisterFinishWithoutBeginIsRefused` and `TestLoginFinishWithUnknownCredential` → 400, body contains no internal error text.
  - `TestDisabledUserCannotLogIn`.
  - `TestLogoutEndsTheSession`: POST `/logout` (same-origin headers) → cookie cleared and the old token no longer works.
  - `TestSessionCookieAttributes`.

- [ ] **Step 4: Run to verify failure**

Run: `go test ./internal/vconsole/web/ && go test -tags integration ./internal/vconsole/web/ -count=1`
Expected: FAIL (package does not compile).

- [ ] **Step 5: Implement**

`server.go` routing (Go 1.22+ patterns):

```go
mux := http.NewServeMux()
mux.Handle("GET /static/", http.FileServerFS(staticFS))
mux.HandleFunc("GET /login", s.loginPage)
mux.HandleFunc("GET /enroll", s.enrollPage)
mux.HandleFunc("POST /webauthn/register/begin", s.limited(s.registerBegin))
mux.HandleFunc("POST /webauthn/register/finish", s.registerFinish)
mux.HandleFunc("POST /webauthn/login/begin", s.limited(s.loginBegin))
mux.HandleFunc("POST /webauthn/login/finish", s.loginFinish)
mux.HandleFunc("POST /logout", s.authed(s.logout))
// pages (Task 4) are registered by s.pages(mux)
cop := http.NewCrossOriginProtection() // refuses cross-origin unsafe methods
return headers(cop.Handler(mux))
```

Ceremony state: `map[string]ceremony` guarded by a mutex, keyed by a random id sent back in an `HttpOnly` cookie `vceremony` (5 minute lifetime, one use, pruned on each insert). Registration ceremony carries the enrollment code's user id; `registerFinish` runs `LookupEnrollment`, `webauthn.FinishRegistration`, then in one `inActorTx`-less transaction (the service is not acting for a person yet): `ConsumeEnrollment` + `AddCredential`; any failure rolls both back so the code is not burned by a failed ceremony.

Login uses `BeginDiscoverableLogin`/`FinishDiscoverableLogin` with a handler that resolves the user by `userHandle` (the user's id encoded as 8 big-endian bytes) and loads that user's credentials; after success: `UpdateCredential` (new sign count), `NewSession`, `SELECT web_audit_login($1)`, set cookie, respond `{"redirect":"/"}`. A user that is disabled or unknown yields the same 400 `{"error":"login failed"}` as a bad assertion.

`webAuthnUser` adapter implements the library's `webauthn.User` (`WebAuthnID`, `WebAuthnName`, `WebAuthnDisplayName`, `WebAuthnCredentials`), unmarshalling each `StoredCredential.JSON` into `webauthn.Credential`.

`authed(next func(w, r, u webuser.User))` reads the cookie, calls `webuser.Session`, redirects to `/login` (303) on `ErrNoSession` for page requests and returns 401 JSON for `POST /webauthn/...`/fetch requests.

`passkey.js` (no inline script; loaded by `<script src="/static/passkey.js">`): converts base64url fields to `ArrayBuffer`, calls `navigator.credentials.create/get`, posts the JSON to the finish endpoint with `fetch` (`credentials: 'same-origin'`), and follows `redirect` from the response. Buttons have `id="enroll-button"` and `id="login-button"`; errors are written into an element with `role="alert"`.

- [ ] **Step 6: Run to verify it passes**

Run: `go test ./internal/vconsole/web/ && go test -tags integration ./internal/vconsole/web/ -count=1`
Expected: PASS.

- [ ] **Step 7: Commit** (`feat(vconsole): web server with passkey enrollment and login`).

---

### Task 4: Customers, requests, license list and download

**Files:**
- Create: `internal/vconsole/store/licenses.go`, `internal/vconsole/web/pages.go`, `internal/vconsole/web/templates/{home,customers,request_new,request,licenses}.html`
- Test: `internal/vconsole/store/licenses_integration_test.go`, `internal/vconsole/web/pages_integration_test.go`

**Interfaces:**
- Produces (store):

```go
type LicenseRow struct {
	LicenseID, Customer, Installation, KeyID, SignedBy, Replaces string
	IssuedAt, ValidFrom, ValidUntil                              time.Time
	Targets                                                      int
	RevokedAt                                                    *time.Time
}
// ListLicenses returns licenses ordered by valid_until ascending. endingWithinDays 0 means all;
// otherwise only licenses that are not revoked and end between now and now+days (already ended ones
// are included when days > 0 and includeEnded is true).
func ListLicenses(ctx context.Context, q audit.Q, now time.Time, endingWithinDays int, includeEnded bool) ([]LicenseRow, error)
func ListCustomers(ctx context.Context, q audit.Q) ([]Customer, error)
```

- Routes (all through `authed`, state-changing ones also protected by the cross-origin check): `GET /` (open requests and licenses ending in 90 days), `GET /customers`, `POST /customers`, `GET /requests/new`, `POST /requests`, `GET /requests/{id}`, `POST /requests/{id}/cancel`, `GET /licenses?ending=90|60|30|all`, `GET /licenses/{id}/download`.
- Every database call goes through `inActorTx`, so rows and audit name `web:<user>`.

- [ ] **Step 1: Write failing tests.**
  - store: `TestListLicensesOrdersByEndDateAndFilters` (three licenses ending in 10, 50, 200 days plus one revoked and one already ended; `ending=90` returns the first two, `all` returns all five in end-date order, revoked ones carry `RevokedAt`); `TestListCustomersSorted`.
  - web (use the enrollment/login helper from Task 3's tests to get a cookie for `ayse` and for `mehmet`):
    - `TestAddCustomerAndRequestThenSeeItListed`: form POST creates a customer and a request (valid installation ID from `license.NewInstallationID()`); `/requests/{id}` shows customer name, installation, targets, status `open`, and requested-by `web:ayse`; audit chain verifies.
    - `TestRequestFormRejectsWhatCouldNeverBeSigned`: bad installation ID, targets 0, months 61 → 422 with the form re-rendered and a message; nothing stored.
    - `TestSecondUserSeesButCannotCancelTheFirstUsersRequest`: `mehmet` GET `/requests/{id}` 200; POST `/requests/{id}/cancel` as `mehmet` → 404; as `ayse` → 303 and status `cancelled`.
    - `TestLicenseListShowsEndDatesAndExpiryFilter`: seed licenses through the owner pool (use `issue.Issue` with the file signer as Phase 1 tests do, or direct INSERT as owner); `/licenses?ending=90` lists only those ending within 90 days, in end-date order, with the end date as `2006-01-02`.
    - `TestDownloadReturnsTheExactIssuedBytes`: body equals the stored bytes, `Content-Type: application/octet-stream`, `Content-Disposition: attachment; filename="<license-id>.alicelic"` with the ID restricted to `[A-Za-z0-9._-]` (anything else → 404), `X-Content-Type-Options: nosniff`.
    - `TestDownloadOfUnknownOrOddIDsIs404`: `nope`, `..%2f..%2fetc%2fpasswd`, `a'b`, 300-character ID → 404 and the body has no SQL or path text.
    - `TestMarkupInCustomerFieldsIsEscaped`: customer name `<script>alert(1)</script>` appears as `&lt;script&gt;` in `/customers` and `/requests/{id}`.
    - `TestSalesWebCannotSign`: through the web pool, attempting `INSERT INTO licenses` fails (guards the role grant; complements Task 1).
  - Decide the extension from the product: check `cmd/licensectl` and `cmd/vendor-console license export` default file names first (`grep -n "\.json\|\.lic" cmd/licensectl/*.go cmd/vendor-console/run.go`) and use the same extension in `filename=`; adjust the test string to match.

- [ ] **Step 2: Run to verify failure**

Run: `go test -tags integration ./internal/vconsole/store/ ./internal/vconsole/web/ -count=1`
Expected: FAIL.

- [ ] **Step 3: Implement** `licenses.go` (a single `SELECT ... FROM licenses l JOIN customers c ... ORDER BY valid_until, license_id` with the filter in SQL, parameters never concatenated), the handlers (parse with `r.ParseForm`, `http.MaxBytesReader` 64 KiB, map `store.ErrNotFound` → 404, validation errors from `store.AddRequest` → 422 with the message from the error, everything else → 500 with a generic page and the error logged without request bodies), and the templates (`html/template`, auto-escaping only; no `template.HTML` anywhere).

- [ ] **Step 4: Run to verify it passes**

Run: `go test -tags integration ./internal/vconsole/... -count=1`
Expected: PASS.

- [ ] **Step 5: Commit** (`feat(vconsole): sales pages for customers, requests, licenses and download`).

---

### Task 5: `vendor-web` command and `web-user` owner commands

**Files:**
- Create: `cmd/vendor-web/main.go`, `cmd/vendor-web/main_test.go`
- Modify: `cmd/vendor-console/run.go`, `cmd/vendor-console/run_test.go`, `cmd/vendor-console/run_integration_test.go`

**Interfaces:**
- `vendor-web` environment: `VENDOR_WEB_DATABASE_URL` (required; same TLS rule as `vendor-console`, reuse the check function by moving it into `internal/vconsole/store` or duplicating the 15 lines: prefer a small exported `store.RequireTLSVerification(url string) error` moved from `cmd/vendor-console/run.go` with its test, so both commands share it), `VENDOR_WEB_ORIGIN`, `VENDOR_WEB_RPID`, flags `--listen :8443`, `--tls-cert`, `--tls-key` (both or neither).
- `vendor-console`: `web-user add NAME` (prints the code once, with the expiry), `web-user invite NAME`, `web-user disable NAME`, `web-user enable NAME`, `web-user list`.

- [ ] **Step 1: Write failing tests.**
  - `main_test.go`: missing database URL, missing origin, `http://` non-localhost origin, only one of `--tls-cert/--tls-key`, and a database URL with `sslmode=disable` on a non-loopback host each exit 2 with a message that does not contain the URL's password.
  - `run_test.go`: usage lists `web-user`; `web-user add` without a name exits 2.
  - `run_integration_test.go`: `web-user add ayse` prints a code and exit 0; `list` shows `ayse`; `invite ayse` prints a different code; `disable ayse` then `list` shows disabled; as a sales login every `web-user` command exits 1 with a permission message.

- [ ] **Step 2: Run to verify failure** (`go test ./cmd/vendor-web/ ./cmd/vendor-console/ && go test -tags integration ./cmd/vendor-console/ -count=1`). Expected: FAIL.

- [ ] **Step 3: Implement.** `main.go`: parse flags and env, `db.Open` with the pool, `web.New`, `http.Server` with `ReadHeaderTimeout: 10s`, `ReadTimeout: 30s`, `WriteTimeout: 30s`, `IdleTimeout: 120s`, `MaxHeaderBytes: 16 << 10`, graceful shutdown on SIGINT/SIGTERM (10 s). It prints the listen address and the origin only, never the database URL. The `web-user` commands call `webuser.AddUser` + `NewEnrollment` in one transaction so a failed code issue leaves no user.

- [ ] **Step 4: Run to verify it passes** (same commands). Expected: PASS.

- [ ] **Step 5: Commit** (`feat(vconsole): vendor-web command and web-user commands`).

---

### Task 6: Architecture rules, docs, spec update, final checks

**Files:**
- Modify: `internal/archtest/arch_test.go`, `cmd/alice/license_release_test.go`, `docs/vendor-console.md`, `docs/superpowers/specs/2026-10-15-vendor-console-design.md`

- [ ] **Step 1: Write failing architecture tests.** In `arch_test.go` add rows to the table near line 288: `web` -> `store` allowed; `web` -> `webuser` allowed; `web` -> `sign` denied; `web` -> `issue` denied; `webuser` -> `store` denied (the only shared dependency is `audit`). Extend `denied` for `alice/internal/vconsole/web/...` with `alice/internal/vconsole/sign` and `alice/internal/vconsole/issue`. Extend `TestReleaseBinaryLinksNoTestOrVendorCode` with `alice/cmd/vendor-web` and the new packages.

- [ ] **Step 2: Run to verify failure, then make them pass.** `go test ./internal/archtest/ ./cmd/alice/ -count=1`.

- [ ] **Step 3: Docs.** `docs/vendor-console.md`: a "Sales web service" section: environment variables; the database login for the service (`CREATE ROLE vendor_web_svc LOGIN PASSWORD '...' IN ROLE vendor_web;`, no other membership); TLS (own certificate or reverse proxy; the proxy must not rewrite `Origin`/`Host`; `X-Forwarded-For` is ignored in this phase so the rate limit sees the proxy address: put the limit at the proxy as well); creating a sales person (`web-user add`), losing a key (`invite`), leaving (`disable`); backup of the database includes `web_*` tables; single-instance note.

- [ ] **Step 4: Spec update.** In the design spec: O4 resolved with ruling 1; section 3 "Sales web service" gets the `vendor_actor()` identity model and passkey enrollment; Phase 3 marked built; the audit view for the owner stays in Phase 4.

- [ ] **Step 5: Full verification.**

Run: `gofmt -l cmd internal` (empty), `go vet ./...`, `golangci-lint run ./cmd/... ./internal/vconsole/... ./internal/archtest/...` (0 issues), `go test ./... -count=1`, `go test -tags integration ./internal/vconsole/... ./cmd/vendor-console/... -count=1`.
Expected: all pass.

- [ ] **Step 6: Commit** (`docs(vconsole): phase 3 notes, architecture rules and spec update`), then run the final whole-branch review and fast-forward `master`.

---

## Self-Review

- **Spec coverage:** login (WebAuthn) Task 2-3; customers and requests Task 4; license list with end dates and download Task 4; role that cannot write signed licenses Task 1; short sessions and rate limits Task 3; "holds no signing key" guarded by Task 6 architecture rules and Task 4 `TestSalesWebCannotSign`; O4 Task 6. Owner audit view and e-mail are Phase 4 by the spec.
- **Placeholders:** the two commented tests in Task 1 and the test lists in Tasks 2-5 state exact inputs and expected results; the implementer writes the bodies in the style of the first tests of the same file.
- **Types:** `webuser.User`, `StoredCredential`, `Session`, `ListLicenses`, `inActorTx` are defined before use. The session cookie name is set only by `web.New`.
- **Review Focus** lines each map to a named test above.
