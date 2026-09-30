//go:build integration

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/auth"
)

// Session, CSRF and rate-limit suite (spec §25.3 R-01..R-10, §25.4 A-01..A-09).
// R-04's 200-sample timing test is deferred (Known Limitation); R-07 (bounded
// Argon2 work) is unit-tested in internal/auth with the credential slots.

// countWhere counts rows of table matching a constant SQL condition.
func (s *stack) countWhere(table, cond string) int {
	s.t.Helper()
	var n int
	require.NoError(s.t, s.db.Owner.QueryRow(context.Background(), "SELECT count(*) FROM "+table+" WHERE "+cond).Scan(&n))
	return n
}

func withHeader(name, value string) reqOpt {
	return func(r *http.Request) { r.Header.Set(name, value) }
}

func withoutHeader(name string) reqOpt {
	return func(r *http.Request) { r.Header.Del(name) }
}

const (
	adminPassword    = "correct horse battery staple"
	operatorPassword = "operator password 2026"
	backupPassphrase = "a long recovery passphrase for backups"
	wrongPassword    = "not the password at all"
)

// installed returns a stack with a finished wizard and the admin's browser.
func installed(t *testing.T, trusted ...netip.Prefix) (*stack, *client, *account) {
	t.Helper()
	s := newStack(t, trusted...)
	admin := &account{username: "ada", password: adminPassword}
	c := s.setupAdmin(admin, backupPassphrase, nil)
	return s, c, admin
}

// errorWithoutRequestID decodes an error body and drops the per-request ID.
func errorWithoutRequestID(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	delete(body["error"], "request_id")
	return body["error"]
}

func loginBody(username, password string) map[string]string {
	return map[string]string{"username": username, "password": password}
}

func TestA01CookieAttributes(t *testing.T) {
	s, _, admin := installed(t)
	s.signIn(s.client("198.51.100.20"), admin)

	seen := map[string]bool{}
	var values []string
	for _, e := range s.recorded() {
		for _, line := range e.header.Values("Set-Cookie") {
			ck, err := http.ParseSetCookie(line)
			require.NoError(t, err)
			if ck.Value == "" || ck.MaxAge < 0 {
				continue // clearing cookies
			}
			seen[ck.Name] = true
			values = append(values, ck.Value)
			assert.True(t, strings.HasPrefix(ck.Name, "__Host-"), line)
			assert.True(t, ck.Secure, line)
			assert.True(t, ck.HttpOnly, line)
			assert.Equal(t, http.SameSiteStrictMode, ck.SameSite, line)
			assert.Equal(t, "/", ck.Path, line)
			assert.Empty(t, ck.Domain, line)
		}
	}
	assert.True(t, seen[sessionCookie], "session cookie observed")
	assert.True(t, seen[setupCookie], "setup cookie observed")
	require.NotEmpty(t, values)
	for _, e := range s.recorded() {
		for _, v := range values {
			assert.NotContains(t, string(e.body), v, "a session ID appeared in the body of %s", e.key())
		}
	}
}

func TestA02IdleTimeout(t *testing.T) {
	s, c, _ := installed(t)
	s.clock.Advance(29 * time.Minute)
	requireStatus(t, c.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusOK)
	s.clock.Advance(29 * time.Minute) // activity above reset the idle timer
	requireStatus(t, c.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusOK)
	s.clock.Advance(31 * time.Minute)
	requireError(t, c.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusUnauthorized, "ALC-AUTH-0001")
}

func TestA03AbsoluteTimeout(t *testing.T) {
	s, c, _ := installed(t)
	for i := 0; i < 28; i++ { // 28 x 25 min = 11 h 40 min, always active
		s.clock.Advance(25 * time.Minute)
		requireStatus(t, c.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusOK)
	}
	s.clock.Advance(25 * time.Minute) // 12 h 05 min after sign-in
	requireError(t, c.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusUnauthorized, "ALC-AUTH-0001")
}

func TestA04SessionIDChangesAtLoginMFAAndStepUp(t *testing.T) {
	s, _, admin := installed(t)
	c := s.client("198.51.100.21")
	s.clock.Advance(31 * time.Second)
	requireStatus(t, c.do(http.MethodPost, "/api/v1/auth/login", loginBody("ada", adminPassword)), http.StatusOK)
	pending, pendingCSRF := c.cookies[sessionCookie], c.csrf
	require.NotEmpty(t, pending)
	requireStatus(t, c.do(http.MethodPost, "/api/v1/auth/mfa/verify", map[string]string{"code": s.totpNow(admin.secret)}), http.StatusOK)
	full := c.cookies[sessionCookie]
	assert.NotEqual(t, pending, full, "MFA completion issues a new session ID")

	// The pending ID is dead: with its own valid CSRF token and a fresh code it
	// can neither complete MFA again nor act as a session.
	old := s.client("198.51.100.22")
	old.cookies[sessionCookie], old.csrf = pending, pendingCSRF
	s.clock.Advance(31 * time.Second)
	requireError(t, old.do(http.MethodPost, "/api/v1/auth/mfa/verify", map[string]string{"code": s.totpNow(admin.secret)}), http.StatusUnauthorized, "ALC-AUTH-0001")
	requireError(t, old.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusUnauthorized, "ALC-AUTH-0001")

	s.stepUp(c, admin)
	stepped := c.cookies[sessionCookie]
	assert.NotEqual(t, full, stepped, "step-up issues a new session ID")
	old.cookies[sessionCookie] = full
	requireError(t, old.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusUnauthorized, "ALC-AUTH-0001")
	requireStatus(t, c.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusOK)
}

func TestA05LogoutRevocationRoleChangeAndPasswordChange(t *testing.T) {
	s, adminBrowser, admin := installed(t)

	t.Run("logout invalidates the cookie server-side", func(t *testing.T) {
		c := s.client("198.51.100.30")
		s.signIn(c, admin)
		cookie := c.cookies[sessionCookie]
		requireStatus(t, c.do(http.MethodPost, "/api/v1/auth/logout", nil), http.StatusNoContent)
		replay := s.client("198.51.100.31")
		replay.cookies[sessionCookie] = cookie
		requireError(t, replay.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusUnauthorized, "ALC-AUTH-0001")
	})

	operator := s.createUser(adminBrowser, admin, "otto", "operator", operatorPassword)
	op := s.client("198.51.100.32")
	s.firstSignIn(op, operator)

	t.Run("admin signs the user out everywhere", func(t *testing.T) {
		s.stepUp(adminBrowser, admin)
		requireStatus(t, adminBrowser.do(http.MethodPost, "/api/v1/users/"+operator.id+"/actions/revoke-sessions", nil), http.StatusNoContent)
		requireError(t, op.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusUnauthorized, "ALC-AUTH-0001")
	})

	t.Run("a role change ends the user's sessions", func(t *testing.T) {
		s.signIn(op, operator)
		s.stepUp(adminBrowser, admin)
		requireStatus(t, adminBrowser.do(http.MethodPatch, "/api/v1/users/"+operator.id, map[string]string{"role": "auditor"}), http.StatusOK)
		requireError(t, op.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusUnauthorized, "ALC-AUTH-0001")
	})

	t.Run("disabling ends the sessions, revokes the tokens and blocks sign-in", func(t *testing.T) {
		s.signIn(op, operator)
		token, _ := createToken(t, s, op, operator, "read", 1)
		api := s.client("198.51.100.35")
		api.bearer = token
		requireStatus(t, api.do(http.MethodGet, "/api/v1/version", nil), http.StatusOK)

		s.stepUp(adminBrowser, admin)
		requireStatus(t, adminBrowser.do(http.MethodPatch, "/api/v1/users/"+operator.id, map[string]bool{"disabled": true}), http.StatusOK)
		requireError(t, op.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusUnauthorized, "ALC-AUTH-0001")
		requireError(t, api.do(http.MethodGet, "/api/v1/version", nil), http.StatusUnauthorized, "ALC-AUTH-0001")
		requireError(t, s.login("otto", operatorPassword), http.StatusUnauthorized, "ALC-AUTH-0005")

		// The tokens were revoked, not just suspended: re-enabling does not revive them.
		s.stepUp(adminBrowser, admin)
		requireStatus(t, adminBrowser.do(http.MethodPatch, "/api/v1/users/"+operator.id, map[string]bool{"disabled": false}), http.StatusOK)
		requireError(t, api.do(http.MethodGet, "/api/v1/version", nil), http.StatusUnauthorized, "ALC-AUTH-0001")
		s.signIn(op, operator)
	})

	t.Run("a password change ends the other sessions", func(t *testing.T) {
		first, second := s.client("198.51.100.33"), s.client("198.51.100.34")
		s.signIn(first, admin)
		s.signIn(second, admin)
		before := first.cookies[sessionCookie]
		requireStatus(t, first.do(http.MethodPost, "/api/v1/auth/password", map[string]string{
			"current_password": adminPassword, "new_password": "a brand new admin password",
		}), http.StatusOK)
		assert.NotEqual(t, before, first.cookies[sessionCookie], "the current session gets a new ID")
		requireStatus(t, first.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusOK)
		requireError(t, second.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusUnauthorized, "ALC-AUTH-0001")
		requireError(t, adminBrowser.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusUnauthorized, "ALC-AUTH-0001")
		old := s.client("198.51.100.36")
		old.cookies[sessionCookie] = before
		requireError(t, old.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusUnauthorized, "ALC-AUTH-0001")
	})
}

func TestA06CSRFAndOriginChecks(t *testing.T) {
	s, c, _ := installed(t)
	sessions := s.count("sessions")

	requireError(t, c.do(http.MethodPost, "/api/v1/auth/logout", nil, withoutHeader("X-CSRF-Token")), http.StatusForbidden, "ALC-AUTH-0004")
	requireError(t, c.do(http.MethodPost, "/api/v1/auth/logout", nil, withHeader("X-CSRF-Token", "forged")), http.StatusForbidden, "ALC-AUTH-0004")
	requireError(t, c.do(http.MethodPost, "/api/v1/auth/logout", nil, withHeader("Origin", "https://evil.example")), http.StatusForbidden, "ALC-AUTH-0004")
	requireError(t, c.do(http.MethodPost, "/api/v1/auth/logout", nil, withHeader("Sec-Fetch-Site", "cross-site")), http.StatusForbidden, "ALC-AUTH-0004")
	assert.Equal(t, sessions, s.count("sessions"), "no refused logout reached the handler")
	requireStatus(t, c.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusOK)

	// Login CSRF: a cross-site form cannot sign the victim in either.
	for name, opt := range map[string]reqOpt{
		"foreign Origin":        withHeader("Origin", "https://evil.example"),
		"cross-site fetch mode": withHeader("Sec-Fetch-Site", "cross-site"),
	} {
		rec := s.freshClient().do(http.MethodPost, "/api/v1/auth/login", loginBody("ada", adminPassword), opt)
		requireError(t, rec, http.StatusForbidden, "ALC-AUTH-0004")
		assert.Empty(t, rec.Header().Values("Set-Cookie"), name)
	}
	assert.Equal(t, sessions, s.count("sessions"), "no pending session was opened cross-site")
}

// rowsChecksum is an order-independent digest of every row of table. The
// sliding idle timeout of sessions (last_seen_at, idle_expires_at) is the one
// write an authenticated GET is allowed to make, so it is left out.
func (s *stack) rowsChecksum(table, where string) string {
	s.t.Helper()
	var sum string
	require.NoError(s.t, s.db.Owner.QueryRow(context.Background(), `SELECT md5(coalesce(string_agg(r, E'\n' ORDER BY r), ''))
FROM (SELECT (to_jsonb(t) - 'last_seen_at' - 'idle_expires_at')::text AS r FROM `+pgx.Identifier{table}.Sanitize()+` t WHERE `+where+`) x`).Scan(&sum))
	return sum
}

func (s *stack) maxAuditSeq() int64 {
	s.t.Helper()
	var seq int64
	require.NoError(s.t, s.db.Owner.QueryRow(context.Background(), "SELECT coalesce(max(seq), 0) FROM audit_log").Scan(&seq))
	return seq
}

func TestA06GETRoutesNeverChangeState(t *testing.T) {
	s, c, admin := installed(t)
	// Store an audit checkpoint first, so a GET that moved it would be caught.
	requireStatus(t, c.do(http.MethodPost, "/api/v1/audit/verify", nil), http.StatusOK)
	require.Equal(t, 1, s.countWhere("settings", "key = 'audit.checkpoint'"))

	var tables []string
	for _, table := range s.dumpTables() {
		if table != "audit_log" {
			tables = append(tables, table)
		}
	}
	snapshot := func() map[string]string {
		m := map[string]string{}
		for _, table := range tables {
			m[table] = s.rowsChecksum(table, "true")
		}
		return m
	}
	before, seq := snapshot(), s.maxAuditSeq()
	history := s.rowsChecksum("audit_log", "true")
	var gets int
	for _, op := range specOps() {
		if op.method != "get" {
			continue
		}
		gets++
		path := strings.ReplaceAll(op.path, "{id}", admin.id)
		// The export is audited (SEC-075): exactly one audit.exported row is its only write.
		wantAudit := 0
		if op.path == "/api/v1/audit/export" {
			path, wantAudit = path+"?format=json", 1
		}
		rec := c.do(http.MethodGet, path, nil)
		assert.Equal(t, http.StatusOK, rec.Code, "%s: %s", op.key(), rec.Body.String())
		assert.Equal(t, before, snapshot(), "GET %s changed stored state", path)

		assert.Equal(t, history, s.rowsChecksum("audit_log", "seq <= "+strconv.FormatInt(seq, 10)), "GET %s changed existing audit rows", path)
		assert.Equal(t, int64(wantAudit), s.maxAuditSeq()-seq, "GET %s appended audit rows", path)
		if wantAudit == 1 {
			assert.Equal(t, 1, s.countWhere("audit_log", "seq = "+strconv.FormatInt(seq+1, 10)+" AND action = 'audit.exported'"))
		}
		seq = s.maxAuditSeq()
		history = s.rowsChecksum("audit_log", "true")
	}
	assert.GreaterOrEqual(t, gets, 10)
}

func TestA07NoCrossOriginResourceSharing(t *testing.T) {
	s, c, _ := installed(t)
	pre := s.freshClient().do(http.MethodOptions, "/api/v1/auth/session", nil,
		withHeader("Origin", "https://evil.example"), withHeader("Access-Control-Request-Method", "POST"))
	assert.Empty(t, pre.Header().Get("Access-Control-Allow-Origin"))
	assert.Empty(t, pre.Header().Get("Access-Control-Allow-Credentials"))
	assert.Empty(t, pre.Header().Get("Access-Control-Allow-Methods"))
	assert.GreaterOrEqual(t, pre.Code, 400, "preflight is not answered")

	rec := c.do(http.MethodGet, "/api/v1/auth/session", nil, withHeader("Origin", "https://evil.example"))
	assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
	assert.Empty(t, rec.Header().Get("Access-Control-Allow-Credentials"))
}

func TestA08SecurityHeadersOnAPIResponses(t *testing.T) {
	s, c, _ := installed(t)
	for name, rec := range map[string]*httptest.ResponseRecorder{
		"authenticated": c.do(http.MethodGet, "/api/v1/auth/session", nil),
		"unauthorized":  s.freshClient().do(http.MethodGet, "/api/v1/auth/session", nil),
		"bad request":   s.freshClient().do(http.MethodPost, "/api/v1/auth/login", `{"username":`),
	} {
		h := rec.Header()
		assert.Equal(t, "max-age=31536000; includeSubDomains", h.Get("Strict-Transport-Security"), name)
		assert.Equal(t, "default-src 'none'; frame-ancestors 'none'", h.Get("Content-Security-Policy"), name)
		assert.Equal(t, "nosniff", h.Get("X-Content-Type-Options"), name)
		assert.Equal(t, "DENY", h.Get("X-Frame-Options"), name)
		assert.Equal(t, "no-referrer", h.Get("Referrer-Policy"), name)
		assert.Equal(t, "no-store", h.Get("Cache-Control"), name)
		assert.Equal(t, "application/json; charset=utf-8", h.Get("Content-Type"), name)
	}
}

// createToken steps c up and creates an API token, returning its secret and ID.
func createToken(t *testing.T, s *stack, c *client, a *account, scope string, days int) (string, string) {
	t.Helper()
	s.stepUp(c, a)
	rec := c.do(http.MethodPost, "/api/v1/tokens", map[string]any{"name": "ci-" + scope, "scope": scope, "expires_in_days": days})
	requireStatus(t, rec, http.StatusCreated)
	var body struct {
		Token string `json:"token"`
		Item  struct {
			ID string `json:"id"`
		} `json:"item"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	return body.Token, body.Item.ID
}

func TestA09APITokenRules(t *testing.T) {
	s, adminBrowser, admin := installed(t)
	token, tokenID := createToken(t, s, adminBrowser, admin, "read", 1)

	api := s.client("198.51.100.40")
	api.bearer = token
	requireStatus(t, api.do(http.MethodGet, "/api/v1/version", nil), http.StatusOK)
	// Bearer requests carry no ambient credentials, so no CSRF token or Origin is needed.
	requireStatus(t, api.do(http.MethodPost, "/api/v1/audit/verify", nil, withoutHeader("Origin"), withoutHeader("Sec-Fetch-Site")), http.StatusOK)
	// Session-only and step-up operations are never available to tokens.
	requireError(t, api.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusForbidden, "ALC-AUTH-0002")
	requireError(t, api.do(http.MethodPost, "/api/v1/users", map[string]string{"username": "x"}), http.StatusForbidden, "ALC-AUTH-0002")
	requireError(t, api.do(http.MethodPost, "/api/v1/tokens", map[string]any{"name": "x", "scope": "read", "expires_in_days": 1}), http.StatusForbidden, "ALC-AUTH-0002")

	// A token is never accepted as a cookie.
	viaCookie := s.client("198.51.100.41")
	viaCookie.cookies[sessionCookie] = token
	requireError(t, viaCookie.do(http.MethodGet, "/api/v1/version", nil), http.StatusUnauthorized, "ALC-AUTH-0001")

	// An auditor cannot mint an operate token, nor revoke someone else's token.
	auditor := s.createUser(adminBrowser, admin, "audrey", "auditor", operatorPassword)
	aud := s.client("198.51.100.42")
	s.firstSignIn(aud, auditor)
	s.stepUp(aud, auditor)
	requireError(t, aud.do(http.MethodPost, "/api/v1/tokens", map[string]any{"name": "x", "scope": "operate", "expires_in_days": 1}),
		http.StatusUnprocessableEntity, "ALC-TOK-0001")
	requireError(t, aud.do(http.MethodDelete, "/api/v1/tokens/"+tokenID, nil), http.StatusNotFound, "ALC-SYS-0001")
	requireStatus(t, api.do(http.MethodGet, "/api/v1/version", nil), http.StatusOK)

	// Revocation takes effect immediately.
	requireStatus(t, adminBrowser.do(http.MethodDelete, "/api/v1/tokens/"+tokenID, nil), http.StatusNoContent)
	requireError(t, api.do(http.MethodGet, "/api/v1/version", nil), http.StatusUnauthorized, "ALC-AUTH-0001")

	// Expired tokens are rejected.
	second, _ := createToken(t, s, adminBrowser, admin, "read", 1)
	api.bearer = second
	requireStatus(t, api.do(http.MethodGet, "/api/v1/version", nil), http.StatusOK)
	s.clock.Advance(24*time.Hour + time.Minute)
	requireError(t, api.do(http.MethodGet, "/api/v1/version", nil), http.StatusUnauthorized, "ALC-AUTH-0001")
}

// installedWithOperator adds an enrolled operator "olga".
func installedWithOperator(t *testing.T) (*stack, *account) {
	t.Helper()
	s, adminBrowser, admin := installed(t)
	olga := s.createUser(adminBrowser, admin, "olga", "operator", operatorPassword)
	s.firstSignIn(s.client("198.51.100.50"), olga)
	return s, olga
}

// lockOut fails username's password auth.LockThreshold times, each from a new
// IP and each as soon as the progressive delay allows (1+2+4+8+16 s in total).
func lockOut(t *testing.T, s *stack, username string) {
	t.Helper()
	wait := time.Duration(0)
	for n := 1; n <= auth.LockThreshold; n++ {
		s.clock.Advance(wait)
		requireError(t, s.login(username, wrongPassword), http.StatusUnauthorized, "ALC-AUTH-0005")
		if n >= auth.DelayThreshold {
			wait = time.Duration(1<<(n-auth.DelayThreshold)) * time.Second
		}
	}
}

func TestR01R02ProgressiveDelayAndLockout(t *testing.T) {
	s, olga := installedWithOperator(t)
	wrong := func() *httptest.ResponseRecorder {
		rec := s.login("olga", wrongPassword)
		requireError(t, rec, http.StatusUnauthorized, "ALC-AUTH-0005")
		return rec
	}
	right := func() *httptest.ResponseRecorder { return s.login("olga", olga.password) }

	normal := errorWithoutRequestID(t, wrong())
	for i := 2; i <= auth.DelayThreshold; i++ {
		wrong()
	}
	// Five consecutive failures: the next attempt within 1 s fails even with
	// the right password, and looks exactly like a normal failure.
	delayed := right()
	requireError(t, delayed, http.StatusUnauthorized, "ALC-AUTH-0005")
	assert.Equal(t, normal, errorWithoutRequestID(t, delayed))
	s.clock.Advance(time.Second)
	requireStatus(t, right(), http.StatusOK) // the password step alone does not reset the counter

	// Failures 6..9 double the delay (2, 4, 8, 16 s); failure 10 locks for 15 minutes.
	for n, wait := 6, time.Second; n <= auth.LockThreshold; n++ {
		if n > 6 {
			// Inside the delay of the previous failure even the right password fails.
			s.clock.Advance(wait - time.Second)
			requireError(t, right(), http.StatusUnauthorized, "ALC-AUTH-0005")
			s.clock.Advance(time.Second)
		}
		wrong()
		wait = time.Duration(1<<(n-auth.DelayThreshold)) * time.Second
	}
	locked := right()
	requireError(t, locked, http.StatusUnauthorized, "ALC-AUTH-0005")
	assert.Equal(t, normal, errorWithoutRequestID(t, locked))
	s.clock.Advance(14 * time.Minute)
	requireError(t, right(), http.StatusUnauthorized, "ALC-AUTH-0005")
	s.clock.Advance(61 * time.Second)
	requireStatus(t, right(), http.StatusOK)

	assert.Equal(t, 1, s.countWhere("audit_log", "action = 'auth.lockout'"))
}

func TestR03CredentialStuffingHitsThePerIPLimit(t *testing.T) {
	s, olga := installedWithOperator(t)
	attacker := s.client("203.0.113.50")
	failures := s.countWhere("audit_log", "action = 'auth.login' AND result = 'failure'")

	// 50 distinct usernames from one address; two real accounts are among them.
	var codes []int
	for i := 0; i < 50; i++ {
		name := fmt.Sprintf("user%02d", i)
		switch i {
		case 3:
			name = "olga"
		case 30:
			name = "ada"
		}
		rec := attacker.do(http.MethodPost, "/api/v1/auth/login", loginBody(name, wrongPassword))
		codes = append(codes, rec.Code)
		if rec.Code == http.StatusTooManyRequests {
			requireError(t, rec, http.StatusTooManyRequests, "ALC-SYS-0005")
			assert.NotEmpty(t, rec.Header().Get("Retry-After"))
		}
	}
	for i, code := range codes {
		want := http.StatusUnauthorized
		if i >= 10 {
			want = http.StatusTooManyRequests
		}
		assert.Equal(t, want, code, "attempt %d", i+1)
	}
	assert.Equal(t, failures+10, s.countWhere("audit_log", "action = 'auth.login' AND result = 'failure'"), "only 10 attempts were evaluated")

	// No account was locked or delayed: olga has one failure, ada (after the limit) none.
	assert.Equal(t, 1, s.countWhere("users", "username = 'olga' AND failed_logins = 1 AND locked_until IS NULL"))
	assert.Equal(t, 1, s.countWhere("users", "username = 'ada' AND failed_logins = 0 AND locked_until IS NULL"))
	assert.Zero(t, s.countWhere("audit_log", "action = 'auth.lockout'"))
	requireStatus(t, s.login("olga", olga.password), http.StatusOK)
	requireStatus(t, s.login("ada", adminPassword), http.StatusOK)
}

func TestR04UnknownAndExistingUsersFailAlike(t *testing.T) {
	// Only the shape is compared here: timing equality rests on the Argon2id dummy
	// verification (unit-tested in internal/auth); the 200-sample statistical test
	// of §25.3 is deferred (Known Limitation).
	s, _ := installedWithOperator(t)
	existing := s.login("olga", wrongPassword)
	unknown := s.login("nobody", wrongPassword)
	requireError(t, existing, http.StatusUnauthorized, "ALC-AUTH-0005")
	assert.Equal(t, existing.Code, unknown.Code)
	assert.Equal(t, errorWithoutRequestID(t, existing), errorWithoutRequestID(t, unknown))
	assert.Equal(t, existing.Header().Get("Content-Type"), unknown.Header().Get("Content-Type"))
	assert.Equal(t, existing.Header().Values("Set-Cookie"), unknown.Header().Values("Set-Cookie"))
}

func TestR05TOTPReplayBruteForceAndRecoveryCodes(t *testing.T) {
	t.Run("codes are single use, also right after enrollment", func(t *testing.T) {
		s, _, admin := installed(t)
		c := s.client("198.51.100.60")
		requireStatus(t, c.do(http.MethodPost, "/api/v1/auth/login", loginBody("ada", adminPassword)), http.StatusOK)
		// Same 30 s step as the enrollment code used by the wizard.
		requireError(t, c.do(http.MethodPost, "/api/v1/auth/mfa/verify", map[string]string{"code": s.totpNow(admin.secret)}), http.StatusUnauthorized, "ALC-AUTH-0006")
		s.clock.Advance(30 * time.Second)
		code := s.totpNow(admin.secret)
		requireStatus(t, c.do(http.MethodPost, "/api/v1/auth/mfa/verify", map[string]string{"code": code}), http.StatusOK)
		requireStatus(t, c.do(http.MethodPost, "/api/v1/auth/logout", nil), http.StatusNoContent)

		requireStatus(t, c.do(http.MethodPost, "/api/v1/auth/login", loginBody("ada", adminPassword)), http.StatusOK)
		requireError(t, c.do(http.MethodPost, "/api/v1/auth/mfa/verify", map[string]string{"code": code}), http.StatusUnauthorized, "ALC-AUTH-0006")
	})

	t.Run("recovery codes are single use", func(t *testing.T) {
		s, _, admin := installed(t)
		c := s.client("198.51.100.61")
		requireStatus(t, c.do(http.MethodPost, "/api/v1/auth/login", loginBody("ada", adminPassword)), http.StatusOK)
		requireStatus(t, c.do(http.MethodPost, "/api/v1/auth/mfa/verify", map[string]string{"recovery_code": admin.recovery[0]}), http.StatusOK)
		requireStatus(t, c.do(http.MethodPost, "/api/v1/auth/logout", nil), http.StatusNoContent)
		requireStatus(t, c.do(http.MethodPost, "/api/v1/auth/login", loginBody("ada", adminPassword)), http.StatusOK)
		requireError(t, c.do(http.MethodPost, "/api/v1/auth/mfa/verify", map[string]string{"recovery_code": admin.recovery[0]}), http.StatusUnauthorized, "ALC-AUTH-0006")
		requireStatus(t, c.do(http.MethodPost, "/api/v1/auth/mfa/verify", map[string]string{"recovery_code": admin.recovery[1]}), http.StatusOK)
	})

	t.Run("guessing codes is rate limited per IP", func(t *testing.T) {
		s, _, admin := installed(t)
		c := s.client("198.51.100.62")
		s.clock.Advance(31 * time.Second)
		requireStatus(t, c.do(http.MethodPost, "/api/v1/auth/login", loginBody("ada", adminPassword)), http.StatusOK)
		for i := 0; i < 5; i++ {
			requireError(t, c.do(http.MethodPost, "/api/v1/auth/mfa/verify", map[string]string{"code": fmt.Sprintf("%06d", i)}), http.StatusUnauthorized, "ALC-AUTH-0006")
		}
		// The 6th request is refused before any check, even with the right code.
		rec := c.do(http.MethodPost, "/api/v1/auth/mfa/verify", map[string]string{"code": s.totpNow(admin.secret)})
		requireError(t, rec, http.StatusTooManyRequests, "ALC-SYS-0005")
		assert.NotEmpty(t, rec.Header().Get("Retry-After"))
		assert.Equal(t, 5, s.countWhere("audit_log", "action = 'auth.mfa_verify' AND result = 'failure'"), "the 6th guess was never evaluated")
	})
}

func TestR06GeneralRateLimitPerIdentity(t *testing.T) {
	s, other, admin := installed(t)
	c := s.client("198.51.100.70")
	s.signIn(c, admin)

	for i := 0; i < 300; i++ {
		requireStatus(t, c.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusOK)
	}
	rec := c.do(http.MethodGet, "/api/v1/auth/session", nil)
	requireError(t, rec, http.StatusTooManyRequests, "ALC-SYS-0005")
	retry, err := strconv.Atoi(rec.Header().Get("Retry-After"))
	require.NoError(t, err)
	assert.GreaterOrEqual(t, retry, 1)

	requireStatus(t, other.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusOK) // a different session is unaffected
	probe := s.client("198.51.100.70")                                                     // same IP as the limited session
	for i := 0; i < 400; i++ {
		requireStatus(t, probe.do(http.MethodGet, "/livez", nil), http.StatusOK)
	}
	s.clock.Advance(time.Minute)
	requireStatus(t, c.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusOK)
}

func TestR08ForwardedForIsIgnoredUnlessProxyIsTrusted(t *testing.T) {
	attempts := func(s *stack) []int {
		var codes []int
		c := s.client("203.0.113.9")
		for i := 0; i < 15; i++ {
			rec := c.do(http.MethodPost, "/api/v1/auth/login", loginBody("nobody", wrongPassword),
				withHeader("X-Forwarded-For", fmt.Sprintf("10.0.0.%d", i+1)))
			codes = append(codes, rec.Code)
		}
		return codes
	}

	untrusted := attempts(newStack(t))
	assert.Equal(t, http.StatusUnauthorized, untrusted[9], "the 10th attempt is still evaluated")
	assert.Equal(t, http.StatusTooManyRequests, untrusted[10], "rotating X-Forwarded-For does not evade the per-IP limit")

	trusted := attempts(newStack(t, netip.MustParsePrefix("203.0.113.9/32")))
	for i, code := range trusted {
		assert.Equal(t, http.StatusUnauthorized, code, "attempt %d from a distinct client behind the trusted proxy", i+1)
	}
}

func TestR09LockoutSurvivesRestart(t *testing.T) {
	s, olga := installedWithOperator(t)
	for n := 1; n <= auth.LockThreshold; n++ {
		if n > auth.DelayThreshold {
			s.clock.Advance(auth.MaxDelay)
		}
		requireError(t, s.login("olga", wrongPassword), http.StatusUnauthorized, "ALC-AUTH-0005")
	}
	s.start() // new services and handler: in-memory limiters are gone, the lockout is in the database
	requireError(t, s.login("olga", olga.password), http.StatusUnauthorized, "ALC-AUTH-0005")
	s.clock.Advance(auth.LockDuration + time.Second)
	requireStatus(t, s.login("olga", olga.password), http.StatusOK)
}

func TestR10RecoveryCodeSignInIsLimitedToo(t *testing.T) {
	t.Run("recovery-code guesses share the per-IP MFA limit", func(t *testing.T) {
		s, _, admin := installed(t)
		c := s.client("198.51.100.80")
		requireStatus(t, c.do(http.MethodPost, "/api/v1/auth/login", loginBody("ada", adminPassword)), http.StatusOK)
		for i := 0; i < 5; i++ {
			requireError(t, c.do(http.MethodPost, "/api/v1/auth/mfa/verify", map[string]string{"recovery_code": fmt.Sprintf("AAAA-BBBB-CCCC-%04d", i)}),
				http.StatusUnauthorized, "ALC-AUTH-0006")
		}
		rec := c.do(http.MethodPost, "/api/v1/auth/mfa/verify", map[string]string{"recovery_code": admin.recovery[0]})
		requireError(t, rec, http.StatusTooManyRequests, "ALC-SYS-0005")
		assert.NotEmpty(t, rec.Header().Get("Retry-After"))
		assert.Zero(t, s.countWhere("recovery_codes", "used_at IS NOT NULL"), "the limited request consumed no recovery code")
	})

	t.Run("a locked account cannot sign in with a recovery code", func(t *testing.T) {
		s, _, admin := installed(t)
		c := s.client("198.51.100.81")
		requireStatus(t, c.do(http.MethodPost, "/api/v1/auth/login", loginBody("ada", adminPassword)), http.StatusOK)
		lockOut(t, s, "ada") // 31 s: the pending session above is still valid
		requireError(t, c.do(http.MethodPost, "/api/v1/auth/mfa/verify", map[string]string{"recovery_code": admin.recovery[0]}),
			http.StatusUnauthorized, "ALC-AUTH-0006")
		assert.Zero(t, s.countWhere("recovery_codes", "used_at IS NOT NULL"), "a refused attempt consumed no recovery code")

		s.clock.Advance(auth.LockDuration)
		requireStatus(t, c.do(http.MethodPost, "/api/v1/auth/login", loginBody("ada", adminPassword)), http.StatusOK)
		requireStatus(t, c.do(http.MethodPost, "/api/v1/auth/mfa/verify", map[string]string{"recovery_code": admin.recovery[0]}), http.StatusOK)
	})
}
