//go:build integration

package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"alice/internal/auth"
	"alice/internal/inventory"
	"alice/internal/providers"
	"alice/internal/testutil/pki"
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

// poll is a background read of the web UI: no X-Alice-Activity marker.
func poll(c *client, path string, opts ...reqOpt) *httptest.ResponseRecorder {
	return c.do(http.MethodGet, path, nil, append([]reqOpt{withoutHeader(activityHeader)}, opts...)...)
}

// idleDeadline reads idle_expires_at from GET /auth/session without sliding it.
func idleDeadline(t *testing.T, c *client) time.Time {
	t.Helper()
	rec := poll(c, "/api/v1/auth/session")
	requireStatus(t, rec, http.StatusOK)
	return decodeBody[struct {
		IdleExpiresAt time.Time `json:"idle_expires_at"`
	}](t, rec).IdleExpiresAt
}

// AUD-01 (A-02, from the audit's TestZZAuditBackgroundPollDefeatsIdleTimeout): the web UI's
// minute-by-minute license poll alone does not keep a session open, and the session endpoint
// reports the deadline it does not move.
func TestA02BackgroundPollsDoNotKeepASessionAlive(t *testing.T) {
	s, c, _ := installed(t)
	requireStatus(t, c.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusOK) // the last action: the reference point
	deadline := s.clock.Now().Add(auth.SessionIdle)
	for i := 1; i <= 29; i++ {
		s.clock.Advance(time.Minute)
		requireStatus(t, poll(c, "/api/v1/license/status"), http.StatusOK)
	}
	assert.True(t, deadline.Equal(idleDeadline(t, c)), "polls leave idle_expires_at where the last action put it")
	s.clock.Advance(time.Minute) // 30 minutes after the last action
	requireError(t, poll(c, "/api/v1/license/status"), http.StatusUnauthorized, "ALC-AUTH-0001")
	requireError(t, c.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusUnauthorized, "ALC-AUTH-0001")
}

// A person's read among polls slides the timer again (A-02 "activity resets the idle timer"), and
// the session endpoint reports the new deadline.
func TestA02ActivityAmongPollsSlides(t *testing.T) {
	s, c, _ := installed(t)
	s.clock.Advance(20 * time.Minute)
	requireStatus(t, c.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusOK) // marked
	assert.True(t, s.clock.Now().Add(auth.SessionIdle).Equal(idleDeadline(t, c)))
	for i := 0; i < 29; i++ {
		s.clock.Advance(time.Minute)
		requireStatus(t, poll(c, "/api/v1/license/status"), http.StatusOK)
	}
	s.clock.Advance(time.Minute)
	requireError(t, poll(c, "/api/v1/license/status"), http.StatusUnauthorized, "ALC-AUTH-0001")
}

// AUD-01: a state-changing request this origin's page sent slides the session even when it is
// then refused by validation; requests another page could make the browser send (cross-site,
// a sibling subdomain, without this session's CSRF token, a marked read from another site)
// never slide it, so no third-party page can keep an unattended session alive.
func TestA02OnlyAcceptedRequestsSlide(t *testing.T) {
	s, c, _ := installed(t)
	requireStatus(t, c.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusOK)
	s.clock.Advance(20 * time.Minute)
	for name, opt := range map[string]reqOpt{
		"missing CSRF token": withoutHeader("X-CSRF-Token"),
		"wrong CSRF token":   withHeader("X-CSRF-Token", "forged"),
		"foreign Origin":     withHeader("Origin", "https://evil.example"),
		"sibling subdomain":  withHeader("Sec-Fetch-Site", "same-site"),
		"cross-site":         withHeader("Sec-Fetch-Site", "cross-site"),
	} {
		rec := c.do(http.MethodPut, "/api/v1/auth/locale", map[string]string{"locale": "en"}, opt)
		assert.Equal(t, http.StatusForbidden, rec.Code, name)
		assert.Contains(t, rec.Body.String(), `"ALC-AUTH-0004"`, name)
	}
	requireStatus(t, poll(c, "/api/v1/license/status", withHeader(activityHeader, "1"), withHeader("Sec-Fetch-Site", "same-site")), http.StatusOK)
	requireStatus(t, poll(c, "/api/v1/license/status", withHeader(activityHeader, "1"), withHeader("Sec-Fetch-Site", "cross-site")), http.StatusOK)
	s.clock.Advance(10 * time.Minute)
	requireError(t, poll(c, "/api/v1/license/status"), http.StatusUnauthorized, "ALC-AUTH-0001")

	s, c, _ = installed(t)
	s.clock.Advance(20 * time.Minute)
	requireStatus(t, c.do(http.MethodPut, "/api/v1/auth/locale", map[string]string{"locale": "de"}, withoutHeader(activityHeader)), http.StatusUnprocessableEntity)
	s.clock.Advance(29 * time.Minute) // 49 minutes after the wizard: the refused change was the person's action
	requireStatus(t, poll(c, "/api/v1/license/status"), http.StatusOK)
	requireStatus(t, c.do(http.MethodPut, "/api/v1/auth/locale", map[string]string{"locale": "en"}, withoutHeader(activityHeader)), http.StatusNoContent)
	s.clock.Advance(29 * time.Minute)
	requireStatus(t, poll(c, "/api/v1/license/status"), http.StatusOK)
	s.clock.Advance(time.Minute)
	requireError(t, poll(c, "/api/v1/license/status"), http.StatusUnauthorized, "ALC-AUTH-0001")
}

// The marker cannot revive an ended session, and API tokens have no idle timeout at all.
func TestA02MarkerOnAnEndedSessionAndTokens(t *testing.T) {
	s, c, admin := installed(t)
	token, _ := createToken(t, s, c, admin, "read", 1)
	api := s.client("198.51.100.43")
	api.bearer = token
	requireStatus(t, api.do(http.MethodGet, "/api/v1/version", nil, withoutHeader(activityHeader)), http.StatusOK)

	s.clock.Advance(auth.SessionIdle)
	requireError(t, c.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusUnauthorized, "ALC-AUTH-0001")
	requireError(t, c.do(http.MethodPost, "/api/v1/auth/logout", nil), http.StatusUnauthorized, "ALC-AUTH-0001")
	requireError(t, poll(c, "/api/v1/license/status"), http.StatusUnauthorized, "ALC-AUTH-0001")

	s.clock.Advance(2 * time.Hour)
	requireStatus(t, api.do(http.MethodGet, "/api/v1/version", nil, withoutHeader(activityHeader)), http.StatusOK)
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
	s, c, admin := installed(t)
	other := s.client("198.51.100.23") // a second, valid session of the same user
	s.signIn(other, admin)
	require.NotEmpty(t, other.csrf)
	require.NotEqual(t, c.csrf, other.csrf)

	// Every cookie-authenticated state change is refused without this
	// session's own token: missing, forged, or valid for another session.
	forged := func() map[string]reqOpt {
		return map[string]reqOpt{
			"missing token":         withoutHeader("X-CSRF-Token"),
			"wrong token":           withHeader("X-CSRF-Token", "forged"),
			"other session's token": withHeader("X-CSRF-Token", other.csrf),
		}
	}
	refused := func(t *testing.T, cl *client, method, path string, body any) {
		t.Helper()
		for name, opt := range forged() {
			rec := cl.do(method, path, body, opt)
			assert.Equal(t, http.StatusForbidden, rec.Code, "%s %s with %s: %s", method, path, name, rec.Body.String())
			assert.Contains(t, rec.Body.String(), `"ALC-AUTH-0004"`, "%s %s with %s", method, path, name)
		}
	}

	t.Run("POST logout", func(t *testing.T) {
		sessions := s.count("sessions")
		refused(t, c, http.MethodPost, "/api/v1/auth/logout", nil)
		requireError(t, c.do(http.MethodPost, "/api/v1/auth/logout", nil, withHeader("Origin", "https://evil.example")), http.StatusForbidden, "ALC-AUTH-0004")
		requireError(t, c.do(http.MethodPost, "/api/v1/auth/logout", nil, withHeader("Sec-Fetch-Site", "cross-site")), http.StatusForbidden, "ALC-AUTH-0004")
		assert.Equal(t, sessions, s.count("sessions"), "no refused logout reached the handler")
		requireStatus(t, c.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusOK)
	})

	t.Run("PATCH user", func(t *testing.T) {
		s.stepUp(c, admin) // so that only the CSRF token stands between the request and the change
		refused(t, c, http.MethodPatch, "/api/v1/users/"+admin.id, map[string]string{"display_name": "Forged Name"})
		assert.Zero(t, s.countWhere("users", "display_name = 'Forged Name'"))
		requireStatus(t, c.do(http.MethodPatch, "/api/v1/users/"+admin.id, map[string]string{"display_name": "Ada Lovelace"}), http.StatusOK)
	})

	t.Run("DELETE token", func(t *testing.T) {
		_, tokenID := createToken(t, s, c, admin, "read", 1)
		refused(t, c, http.MethodDelete, "/api/v1/tokens/"+tokenID, nil)
		assert.Zero(t, s.countWhere("api_tokens", "revoked_at IS NOT NULL"))
		requireStatus(t, c.do(http.MethodDelete, "/api/v1/tokens/"+tokenID, nil), http.StatusNoContent)
	})

	t.Run("POST MFA verify with a pending session", func(t *testing.T) {
		p := s.client("198.51.100.24")
		s.clock.Advance(31 * time.Second)
		requireStatus(t, p.do(http.MethodPost, "/api/v1/auth/login", loginBody("ada", adminPassword)), http.StatusOK)
		require.NotEmpty(t, p.csrf)
		code := s.totpNow(admin.secret)
		refused(t, p, http.MethodPost, "/api/v1/auth/mfa/verify", map[string]string{"code": code})
		requireStatus(t, p.do(http.MethodPost, "/api/v1/auth/mfa/verify", map[string]string{"code": code}), http.StatusOK)
	})

	t.Run("login from a cross-site form", func(t *testing.T) {
		sessions := s.count("sessions")
		for name, opt := range map[string]reqOpt{
			"foreign Origin":        withHeader("Origin", "https://evil.example"),
			"cross-site fetch mode": withHeader("Sec-Fetch-Site", "cross-site"),
		} {
			rec := s.freshClient().do(http.MethodPost, "/api/v1/auth/login", loginBody("ada", adminPassword), opt)
			requireError(t, rec, http.StatusForbidden, "ALC-AUTH-0004")
			assert.Empty(t, rec.Header().Values("Set-Cookie"), name)
		}
		assert.Equal(t, sessions, s.count("sessions"), "no pending session was opened cross-site")
	})
}

// rowsChecksum is an order-independent digest of the rows of table matching
// where. The sliding idle timeout of sessions (last_seen_at, idle_expires_at)
// is the one write an authenticated GET is allowed to make, so those two
// session columns are left out; every column of every other table counts.
func (s *stack) rowsChecksum(table, where string) string {
	s.t.Helper()
	row := "to_jsonb(t)"
	if table == "sessions" {
		row = "(to_jsonb(t) - 'last_seen_at' - 'idle_expires_at')"
	}
	var sum string
	require.NoError(s.t, s.db.Owner.QueryRow(context.Background(), `SELECT md5(coalesce(string_agg(r, E'\n' ORDER BY r), ''))
FROM (SELECT `+row+`::text AS r FROM `+pgx.Identifier{table}.Sanitize()+` t WHERE `+where+`) x`).Scan(&sum))
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
	// One server (with its first job) and one discovered SSH key, so every GET of an item answers
	// 200 with a real record (Phase 3, preflight D8).
	ids := phase3Records(t, s, c)
	for k, v := range phase4Records(t, s, c, ids["/api/v1/targets/"]) {
		ids[k] = v
	}
	ids["/api/v1/users/"] = admin.id
	p5 := phase5Records(t, s, ids["/api/v1/certificates/"])
	ids["/api/v1/bindings/"] = p5["binding"]
	for k, v := range phase6Records(t, s, c) {
		ids[k] = v
	}
	ids["/api/v1/sso/providers/"] = ssoProviderRecord(t, s)
	ids["/api/v1/auth/oidc/"] = ids["/api/v1/sso/providers/"]
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
		path := op.path
		if strings.HasPrefix(path, "/api/v1/targets/{id}/kv/") {
			// The inventory of a vault is addressed through the vault.
			path = strings.NewReplacer("{id}", p5["vault"], "{certificate_id}", p5["kv_certificate"], "{import_id}", p5["import"]).Replace(path)
		} else if strings.Contains(path, "{id}") {
			id, longest := "", 0
			for prefix, v := range ids {
				if strings.HasPrefix(path, prefix) && len(prefix) > longest {
					id, longest = v, len(prefix) // /certificates/csr/{id} is not /certificates/{id}
				}
			}
			require.NotEmpty(t, id, "no record for %s", op.path)
			path = strings.ReplaceAll(path, "{id}", id)
		}
		// The exports are audited (SEC-075): exactly one audit.exported or inventory.exported row is their only write.
		wantAudit, wantAction := 0, ""
		switch op.path {
		case "/api/v1/audit/export":
			path, wantAudit, wantAction = path+"?format=json", 1, "audit.exported"
		case "/api/v1/certificates/export", "/api/v1/ssh-keys/export":
			// Phase 7 (R42 row 16): an inventory export is audited before its first byte; that row is its only write.
			wantAudit, wantAction = 1, "inventory.exported"
		case "/api/v1/views":
			path += "?page=certificates"
		case "/api/v1/sso/group-mappings":
			path += "?provider_id=" + ids["/api/v1/sso/providers/"]
		case "/api/v1/auth/oidc/{id}/callback":
			// The A-06 exception (R42 row 18, B13): the identity provider's redirect back is the one GET that changes state
			// (it consumes the sign-in state and audits a refusal); it is always answered with a redirect.
			rec := c.do(http.MethodGet, path, nil)
			assert.Equal(t, http.StatusSeeOther, rec.Code, op.key())
			assert.Equal(t, "/login?sso_error=sso.login_expired", rec.Header().Get("Location"))
			// Its only write here (no state row to consume) is the one audited refusal (review M-8).
			assert.Equal(t, before, snapshot(), "the callback changed stored state")
			assert.Equal(t, history, s.rowsChecksum("audit_log", "seq <= "+strconv.FormatInt(seq, 10)), "the callback changed existing audit rows")
			assert.Equal(t, int64(1), s.maxAuditSeq()-seq, "the callback appends exactly one audit row")
			assert.Equal(t, 1, s.countWhere("audit_log", "seq = "+strconv.FormatInt(seq+1, 10)+" AND action = 'auth.oidc.denied'"))
			before, seq = snapshot(), s.maxAuditSeq()
			history = s.rowsChecksum("audit_log", "true")
			continue
		}
		rec := c.do(http.MethodGet, path, nil)
		assert.Equal(t, http.StatusOK, rec.Code, "%s: %s", op.key(), rec.Body.String())
		assert.Equal(t, before, snapshot(), "GET %s changed stored state", path)

		assert.Equal(t, history, s.rowsChecksum("audit_log", "seq <= "+strconv.FormatInt(seq, 10)), "GET %s changed existing audit rows", path)
		assert.Equal(t, int64(wantAudit), s.maxAuditSeq()-seq, "GET %s appended audit rows", path)
		if wantAudit == 1 {
			assert.Equal(t, 1, s.countWhere("audit_log", "seq = "+strconv.FormatInt(seq+1, 10)+" AND action = '"+wantAction+"'"), path)
		}
		seq = s.maxAuditSeq()
		history = s.rowsChecksum("audit_log", "true")
	}
	assert.GreaterOrEqual(t, gets, 10)
}

// phase3Records adds one server through the API (which queues its connection test) and stores one
// discovered SSH key for it, and returns the IDs to substitute per path prefix.
func phase3Records(t *testing.T, s *stack, c *client) map[string]string {
	t.Helper()
	rec := c.do(http.MethodPost, "/api/v1/targets", map[string]any{"name": "web-01", "host": "127.0.0.1", "port": 2222})
	requireStatus(t, rec, http.StatusCreated)
	var created struct {
		Target struct {
			ID string `json:"id"`
		} `json:"target"`
		JobID string `json:"job_id"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &created))
	targetID := uuid.MustParse(created.Target.ID)

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sshPub, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)
	fp := ssh.FingerprintSHA256(sshPub)
	_, err = s.inv.Reconcile(context.Background(), targetID, providers.DiscoveryResult{
		SSHKeys: []providers.DiscoveredSSHKey{{OSUser: "deploy", FilePath: "/home/deploy/.ssh/authorized_keys", LineNo: 1,
			PublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))), Fingerprint: fp, KeyType: sshPub.Type(), Bits: 256,
			Comment: "deploy@laptop"}},
		SSHD:      providers.SSHDSummary{Read: true, AuthorizedKeysCommand: "none"},
		ReadFiles: []string{"/home/deploy/.ssh/authorized_keys"},
	})
	require.NoError(t, err)
	page, err := s.inv.ListSSHKeys(context.Background(), inventory.KeyFilter{TargetID: targetID})
	require.NoError(t, err)
	require.Len(t, page.Items, 1)
	return map[string]string{
		"/api/v1/targets/":  created.Target.ID,
		"/api/v1/jobs/":     created.JobID,
		"/api/v1/ssh-keys/": page.Items[0].ID.String(),
	}
}

// phase4Records adds a certificate (uploaded), a signing request, a certificate location on the
// server and a deployment, so every Phase 4 GET of an item answers 200 with a real record. The
// location and the deployment are inserted as the owner: the stack registers no Nginx provider
// (the Nginx journeys are the next task's integration suite).
func phase4Records(t *testing.T, s *stack, c *client, targetID string) map[string]string {
	t.Helper()
	ca := pki.NewCA("API Test CA", pki.ECDSA256, s.clock.Now())
	leaf := ca.Issue(pki.Opts{CommonName: "www.example.com", SANs: []string{"www.example.com"}}, s.clock.Now())
	rec := c.do(http.MethodPost, "/api/v1/certificates/upload", map[string]any{"label": "Web",
		"certificate_pem": string(leaf.FullchainPEM), "private_key_pem": string(leaf.KeyPEM)})
	requireStatus(t, rec, http.StatusCreated)
	var stored struct {
		Certificate struct {
			ID          string `json:"id"`
			Fingerprint string `json:"fingerprint"`
		} `json:"certificate"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &stored))
	rec = c.do(http.MethodPost, "/api/v1/certificates/csr", map[string]any{"common_name": "shop.example.com", "key_type": "ecdsa-p256"})
	requireStatus(t, rec, http.StatusCreated)
	var csr struct {
		ID string `json:"id"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &csr))

	ctx := context.Background()
	loc, dep := uuid.New(), uuid.Must(uuid.NewV7())
	_, err := s.db.Owner.Exec(ctx, `INSERT INTO certificate_locations (id, target_id, kind, cert_path, key_path, certificate_id, supported,
servers, first_seen_at, last_seen_at) VALUES ($1, $2, 'nginx_file', '/etc/nginx/ssl/www.crt', '/etc/nginx/ssl/www.key', $3, true,
'[{"names":["www.example.com"],"listens":[{"addr":"*","port":443,"default_server":false}],"file":"/etc/nginx/conf.d/www.conf","line":3}]',
$4, $4)`, loc, targetID, stored.Certificate.ID, s.clock.Now())
	require.NoError(t, err)
	_, err = s.db.Owner.Exec(ctx, `INSERT INTO deployments (id, certificate_id, location_id, target_id, trigger, state, status,
new_fingerprint, cert_path, key_path, created_at) VALUES ($1, $2, $3, $4, 'manual', 'queued', 'pending', $5, '/etc/nginx/ssl/www.crt',
'/etc/nginx/ssl/www.key', $6)`, dep, stored.Certificate.ID, loc, targetID, stored.Certificate.Fingerprint, s.clock.Now())
	require.NoError(t, err)
	return map[string]string{
		"/api/v1/certificates/":     stored.Certificate.ID,
		"/api/v1/certificates/csr/": csr.ID,
		"/api/v1/deployments/":      dep.String(),
	}
}

// phase5Records stores one Key Vault with a certificate (one version), a connection and a failed import of the
// uploaded certificate, as the owner role (the vault's credential row holds placeholder bytes: nothing opens it).
func phase5Records(t *testing.T, s *stack, certificateID string) map[string]string {
	t.Helper()
	ctx := context.Background()
	now := s.clock.Now()
	vault, cred, kvc, ver, binding, imp := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()),
		uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	tx, err := s.db.Owner.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `INSERT INTO credentials (id, purpose, kind, public_info, ciphertext, nonce, wrapped_dek, key_version, created_at, target_id)
VALUES ($1, 'azure_vault', 'azure_sp_secret', '{"auth":"client_secret"}', '\x01', decode(repeat('00', 12), 'hex'), '\x02', 1, $2, $3)`, cred, now, vault)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `INSERT INTO targets (id, name, type, config, credential_id, status, discovery_interval_seconds, created_at, updated_at)
VALUES ($1, 'prod-vault', 'azure_key_vault', jsonb_build_object('vault_url', 'https://contoso.vault.azure.net', 'host', 'contoso.vault.azure.net', 'port', 443), $2, 'ok', 900, $3, $3)`,
		vault, cred, now)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `INSERT INTO kv_certificates (id, target_id, name, current_version, current_thumbprint, listed_thumbprint, enabled, key_type, content_type, first_seen_at, last_seen_at)
VALUES ($1, $2, 'web-cert', repeat('a', 32), repeat('b', 40), repeat('b', 40), true, 'rsa', 'pkcs12', $3, $3)`, kvc, vault, now)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `INSERT INTO kv_certificate_versions (id, kv_certificate_id, version, thumbprint, enabled, key_type, content_type, detected_at)
VALUES ($1, $2, repeat('a', 32), repeat('b', 40), true, 'rsa', 'pkcs12', $3)`, ver, kvc, now)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `INSERT INTO bindings (id, kv_certificate_id, kv_target_id, created_at) VALUES ($1, $2, $3, $4)`, binding, kvc, vault, now)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `INSERT INTO kv_imports (id, certificate_id, target_id, name, new_version, state, thumbprint, error_code, created_at, finished_at)
VALUES ($1, $2, $3, 'web-cert', false, 'failed', repeat('b', 40), 'kv.import_rejected', $4, $4)`, imp, certificateID, vault, now)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	return map[string]string{"vault": vault.String(), "kv_certificate": kvc.String(), "binding": binding.String(), "import": imp.String()}
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
	// The limits of SEC-020 / R33, pinned as literals.
	require.Equal(t, 5, auth.DelayThreshold)
	require.Equal(t, 10, auth.LockThreshold)
	require.Equal(t, 15*time.Minute, auth.LockDuration)
	require.Equal(t, 60*time.Second, auth.MaxDelay)
	delayAfter := map[int]time.Duration{ // failure number -> progressive delay
		5: 1 * time.Second, 6: 2 * time.Second, 7: 4 * time.Second, 8: 8 * time.Second, 9: 16 * time.Second,
	}

	s, olga := installedWithOperator(t)
	wrong := func(n int) {
		t.Helper()
		requireError(t, s.login("olga", wrongPassword), http.StatusUnauthorized, "ALC-AUTH-0005")
		require.Equal(t, 1, s.countWhere("users", "username = 'olga' AND failed_logins = "+strconv.Itoa(n)), "failure %d was counted", n)
	}
	right := func() *httptest.ResponseRecorder { return s.login("olga", olga.password) }
	// The correct password passes the password step (a pending session). It
	// does not reset the failure counter: only a completed MFA sign-in does, so
	// one account can walk the whole sequence and nothing needs signing out.
	accepted := func(msg string, args ...any) {
		t.Helper()
		rec := right()
		require.Equal(t, http.StatusOK, rec.Code, append([]any{msg + ": %s"}, append(args, rec.Body.String())...)...)
		require.Equal(t, "mfa_required", decodeBody[map[string]string](t, rec)["status"])
	}

	first := s.login("olga", wrongPassword)
	requireError(t, first, http.StatusUnauthorized, "ALC-AUTH-0005")
	normal := errorWithoutRequestID(t, first)
	for n := 2; n <= 4; n++ {
		wrong(n)
	}
	// Up to four failures: no delay at all.
	accepted("after failure 4, no delay")

	// Failures 5..9: blocked for exactly 1, 2, 4, 8, 16 s. Refused (looking like
	// any other failure) up to the last second of the window, accepted at its end.
	for n := auth.DelayThreshold; n < auth.LockThreshold; n++ {
		wrong(n)
		d := delayAfter[n]
		refused := right()
		requireError(t, refused, http.StatusUnauthorized, "ALC-AUTH-0005")
		assert.Equal(t, normal, errorWithoutRequestID(t, refused))
		if d > time.Second {
			s.clock.Advance(d - time.Second) // the window's last second
			requireError(t, right(), http.StatusUnauthorized, "ALC-AUTH-0005")
		}
		s.clock.Advance(time.Second) // exactly d after failure n
		accepted("after failure %d, once its %s delay is over", n, d)
		require.Equal(t, 1, s.countWhere("users", "username = 'olga' AND failed_logins = "+strconv.Itoa(n)), "the password step reset nothing")
	}
	assert.Zero(t, s.countWhere("audit_log", "action = 'auth.lockout'"), "no lockout before failure 10")

	// Failure 10 locks for exactly 15 minutes.
	wrong(auth.LockThreshold)
	locked := right()
	requireError(t, locked, http.StatusUnauthorized, "ALC-AUTH-0005")
	assert.Equal(t, normal, errorWithoutRequestID(t, locked))
	s.clock.Advance(15*time.Minute - time.Second)
	requireError(t, right(), http.StatusUnauthorized, "ALC-AUTH-0005")
	s.clock.Advance(time.Second)
	accepted("15 minutes after the lockout")

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

// ssoProviderRecord stores one identity provider row directly (creating one through the API reads a discovery
// document) and returns its ID.
func ssoProviderRecord(t *testing.T, s *stack) string {
	t.Helper()
	id := uuid.New()
	_, err := s.db.Owner.Exec(context.Background(), `INSERT INTO oidc_providers (id, name, issuer_url, client_id, scopes, groups_claim,
authorization_endpoint, token_endpoint, jwks_uri, enabled, created_at, updated_at)
VALUES ($1, 'Corp', 'https://idp.example.com', 'alice', '{openid}', 'groups', 'https://idp.example.com/a', 'https://idp.example.com/t',
'https://idp.example.com/k', true, $2, $2)`, id, s.clock.Now())
	require.NoError(t, err)
	return id.String()
}
