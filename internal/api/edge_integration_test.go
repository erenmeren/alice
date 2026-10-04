//go:build integration

package api

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func edgeCursor(sep, micros string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(micros + sep + "018f0000-0000-7000-8000-000000000000"))
}

// AUD-13 (the audit's reproductions): no text parameter and no cursor answers 5xx; NUL and invalid
// UTF-8 in a query and NUL in a JSON body are 400 ALC-SYS-0004 at the edge, naming the parameter or
// the body; such a sign-in is not audited (Decision 10).
func TestUnstorableTextIsRefusedAtTheEdge(t *testing.T) {
	s, admin, acct := installed(t)
	for _, c := range []struct{ path, field string }{
		{"/api/v1/audit?actor=" + url.QueryEscape("a\x00b"), "actor"}, {"/api/v1/audit?action=a%00b", "action"}, {"/api/v1/audit?actor=%ff", "actor"},
		{"/api/v1/ssh-keys?os_user=a%00b", "os_user"}, {"/api/v1/ssh-keys?os_user=%ff", "os_user"}, {"/api/v1/ssh-keys?q=a%00b", "q"},
		{"/api/v1/certificates?q=a%00b", "q"}, {"/api/v1/certificates?q=%ff", "q"}, {"/api/v1/audit?%ff=1", "query"},
		{"/api/v1/jobs?status=%00", "status"}, {"/api/v1/deployments?cursor=%ff", "cursor"},
	} {
		rec := admin.do(http.MethodGet, c.path, nil)
		assert.True(t, unstorableRefusal(t, rec.Code, rec.Body.Bytes(), c.field), "%s: %d %s", c.path, rec.Code, rec.Body)
	}
	// Legitimate query text still reaches the lists.
	for _, p := range []string{"/api/v1/audit?actor=" + url.QueryEscape("Ayşe 🔑 é"), "/api/v1/ssh-keys?q=a%2Fb+c", "/api/v1/certificates?q=%C4%B0zmir"} {
		requireStatus(t, admin.do(http.MethodGet, p, nil), http.StatusOK)
	}

	// Cursors at and beyond the extremes: a 4xx, never a 5xx; the bounds themselves are valid cursors.
	minMicros := strconv.FormatInt(time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC).UnixMicro(), 10)
	maxMicros := strconv.FormatInt(time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC).UnixMicro()-1, 10)
	for _, p := range []string{
		"/api/v1/ssh-keys?cursor=" + edgeCursor(".", "-9223372036854775808"),
		"/api/v1/ssh-keys?cursor=" + edgeCursor(".", "9223372036854775807"),
		"/api/v1/certificates?cursor=" + edgeCursor(".", "-9223372036854775808"),
		"/api/v1/certificates?cursor=" + edgeCursor(".", "9223372036854775807"),
		"/api/v1/deployments?cursor=" + edgeCursor(".", "-9223372036854775808"),
		"/api/v1/jobs?cursor=" + edgeCursor("|", "-9223372036854775808"),
		"/api/v1/jobs?cursor=" + edgeCursor("|", "9223372036854775807"),
		"/api/v1/audit?cursor=-1",
	} {
		rec := admin.do(http.MethodGet, p, nil)
		assert.GreaterOrEqual(t, rec.Code, 400, p)
		assert.Less(t, rec.Code, 500, p)
	}
	requireStatus(t, admin.do(http.MethodGet, "/api/v1/audit?cursor=9223372036854775807", nil), http.StatusOK) // a valid bigint sequence
	for _, micros := range []string{minMicros, maxMicros, "-631152000000000"} {                                // year 0, the end of 9999, 1950
		for _, p := range []string{"/api/v1/ssh-keys", "/api/v1/certificates", "/api/v1/deployments"} {
			requireStatus(t, admin.do(http.MethodGet, p+"?cursor="+edgeCursor(".", micros), nil), http.StatusOK)
		}
		requireStatus(t, admin.do(http.MethodGet, "/api/v1/jobs?cursor="+edgeCursor("|", micros), nil), http.StatusOK)
	}

	// Sign-in with a name PostgreSQL cannot store: refused at the edge, not a sign-in attempt.
	anon := s.freshClient()
	attempts := s.countWhere("audit_log", "action LIKE 'auth.login%'")
	rec := anon.do(http.MethodPost, "/api/v1/auth/login", map[string]string{"username": "a\x00b", "password": "whatever-password"})
	assert.True(t, unstorableRefusal(t, rec.Code, rec.Body.Bytes(), "body"), "%d %s", rec.Code, rec.Body)
	assert.Equal(t, attempts, s.countWhere("audit_log", "action LIKE 'auth.login%'"), "a malformed body is not a sign-in attempt (Decision 10)")
	// Invalid UTF-8 in a JSON string reads as U+FFFD: an ordinary unknown name, audited as such.
	requireError(t, anon.do(http.MethodPost, "/api/v1/auth/login", "{\"username\":\"adm\xffin\",\"password\":\"whatever-password\"}"),
		http.StatusUnauthorized, "ALC-AUTH-0005")
	assert.Equal(t, attempts+1, s.countWhere("audit_log", "action = 'auth.login' AND details->>'reason' = 'unknown_user'"))

	s.stepUp(admin, acct)
	for _, c := range []struct {
		method, path string
		body         map[string]any // D18: the same body without the NUL passes the decode
	}{
		{http.MethodPost, "/api/v1/users", map[string]any{"username": "nulx", "display_name": "a\x00b", "email": "", "role": "auditor", "password": "a long enough password 1"}},
		{http.MethodPost, "/api/v1/tokens", map[string]any{"name": "a\x00b", "scope": "read", "expires_in_days": 1}},
		{http.MethodPost, "/api/v1/targets", map[string]any{"name": "a\x00b", "type": "linux", "host": "192.0.2.10", "port": 22, "username": "alice-svc"}},
		{http.MethodPost, "/api/v1/certificates/csr", map[string]any{"common_name": "a\x00b.example.com", "key_type": "ecdsa-p256"}},
		{http.MethodPost, "/api/v1/license/preview", map[string]any{"license": "a\x00b"}},
		{http.MethodPost, "/api/v1/auth/password", map[string]any{"current_password": "a\x00b", "new_password": "a\x00b long enough password"}},
	} {
		rec := admin.do(c.method, c.path, c.body)
		assert.True(t, unstorableRefusal(t, rec.Code, rec.Body.Bytes(), "body"), "%s: %d %s", c.path, rec.Code, rec.Body)
		clean := map[string]any{}
		for k, v := range c.body {
			if str, ok := v.(string); ok {
				v = stripNUL(str)
			}
			clean[k] = v
		}
		rec = admin.do(c.method, c.path, clean)
		assert.False(t, rec.Code == http.StatusBadRequest && edgeErr(t, rec.Body.Bytes()).Error.Code == "ALC-SYS-0004",
			"%s without the NUL must pass the decode: %d %s", c.path, rec.Code, rec.Body)
	}

	// S9: an upload refused at the edge still writes license.upload.invalid.
	const notJSONRows = "action = 'license.upload.invalid' AND result = 'failure' AND details->>'problem' = 'not_json'"
	invalid := s.countWhere("audit_log", notJSONRows)
	rec = admin.do(http.MethodPost, "/api/v1/license", map[string]any{"license": "{\"format\":1\x00}"})
	assert.True(t, unstorableRefusal(t, rec.Code, rec.Body.Bytes(), "body"), "%d %s", rec.Code, rec.Body)
	assert.Equal(t, invalid+1, s.countWhere("audit_log", notJSONRows))

	assert.NotContains(t, s.logs.String(), "request failed")
	require.NotContains(t, s.logs.String(), "22021")
}

func stripNUL(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r != 0 {
			out = append(out, r)
		}
	}
	return string(out)
}
