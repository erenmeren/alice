//go:build integration

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/testutil/fakeidp"
)

// The O-suite and X-05 over the wire (Task 16): the real oidc.Service behind the HTTP stack, the stack's fake
// identity provider, and the browser's round trip (start, the provider's authorize step, the callback) through the
// API. Every refusal is a 303 to the sign-in page (or, for a step-up, the asking page) with the closed reason, no
// session cookie, the binding cookie cleared and exactly one auth.oidc.denied row.

// ssoReady configures the stack's identity provider through the API: Alice's address, one enabled provider with the
// fake's CA, and the mapping alice-operators -> operator. It returns the provider's ID.
func (s *stack) ssoReady(t *testing.T, admin *client, adminAcct *account) string {
	t.Helper()
	s.stepUp(admin, adminAcct)
	rec := admin.do(http.MethodGet, "/api/v1/settings/general", nil)
	requireStatus(t, rec, http.StatusOK)
	requireStatus(t, admin.do(http.MethodPut, "/api/v1/settings/general",
		map[string]any{"public_url": "https://alice.test", "retired_key_retention_days": 30}, ifMatchOf(etagVersion(t, rec))), http.StatusOK)
	rec = admin.do(http.MethodPost, "/api/v1/sso/providers", map[string]any{"name": "Corp IdP", "issuer_url": s.idp.Issuer(),
		"client_id": s.idp.ClientID(), "client_secret": s.idp.ClientSecret(), "ca_pem": string(s.idp.CAPEM()), "enabled": true})
	requireStatus(t, rec, http.StatusCreated)
	p := decodeBody[struct {
		ID          string `json:"id"`
		RedirectURI string `json:"redirect_uri"`
	}](t, rec)
	require.Equal(t, "https://alice.test/api/v1/auth/oidc/"+p.ID+"/callback", p.RedirectURI)
	s.idp.RegisterRedirect(p.RedirectURI)
	s.mapGroup(t, admin, p.ID, "alice-operators", "operator")
	return p.ID
}

// mapGroup maps an identity provider group to a role through the API (the admin is stepped up).
func (s *stack) mapGroup(t *testing.T, admin *client, provider, group, role string) {
	t.Helper()
	requireStatus(t, admin.do(http.MethodPost, "/api/v1/sso/group-mappings",
		map[string]string{"provider_id": provider, "group": group, "role": role}), http.StatusCreated)
}

// ssoStart starts a sign-in on c and returns the authorize URL; the binding cookie is in c's cookie jar.
func (s *stack) ssoStart(t *testing.T, c *client, provider string) string {
	t.Helper()
	rec := c.do(http.MethodPost, "/api/v1/auth/oidc/"+provider+"/start", map[string]string{"next": "/certificates"})
	requireStatus(t, rec, http.StatusOK)
	require.NotEmpty(t, c.cookies[oidcCookie], "the start sets the binding cookie")
	return decodeBody[struct {
		AuthorizeURL string `json:"authorize_url"`
	}](t, rec).AuthorizeURL
}

// authorizeAt is the browser's step at the identity provider: it returns the callback path and query.
func (s *stack) authorizeAt(t *testing.T, authorizeURL string) string {
	t.Helper()
	cb, err := s.idp.Authorize(authorizeURL)
	require.NoError(t, err)
	u, err := url.Parse(cb)
	require.NoError(t, err)
	require.Equal(t, "alice.test", u.Host)
	return u.RequestURI()
}

// browserSSO runs the browser's round trip through the API: start (keeps the binding cookie), the IdP, the callback.
func (s *stack) browserSSO(t *testing.T, c *client, provider string) *httptest.ResponseRecorder {
	t.Helper()
	return c.do(http.MethodGet, s.authorizeAt(t, s.ssoStart(t, c, provider)), nil)
}

// setCookies parses the Set-Cookie lines of an answer by name.
func setCookies(t *testing.T, rec *httptest.ResponseRecorder) map[string]*http.Cookie {
	t.Helper()
	out := map[string]*http.Cookie{}
	for _, line := range rec.Header().Values("Set-Cookie") {
		ck, err := http.ParseSetCookie(line)
		require.NoError(t, err)
		out[ck.Name] = ck
	}
	return out
}

// requireRefused asserts a refused callback: a 303 to want, no session cookie, the binding cookie cleared, and
// exactly one new auth.oidc.denied row with the reason (without "sso.").
func (s *stack) requireRefused(t *testing.T, rec *httptest.ResponseRecorder, want, reason string, deniedBefore int, name string) {
	t.Helper()
	require.Equal(t, http.StatusSeeOther, rec.Code, "%s: %s", name, rec.Body.String())
	assert.Equal(t, want, rec.Header().Get("Location"), name)
	cookies := setCookies(t, rec)
	if ck, ok := cookies[sessionCookie]; ok {
		assert.True(t, ck.Value == "" || ck.MaxAge < 0, "%s: a refusal sets no session", name)
	}
	if ck := cookies[oidcCookie]; assert.NotNil(t, ck, "%s: the binding cookie is cleared", name) {
		assert.Negative(t, ck.MaxAge, name)
		assert.Empty(t, ck.Value, name)
	}
	assert.NotContains(t, rec.Header().Get("Content-Type"), "json", name)
	assert.Equal(t, deniedBefore+1, s.countWhere("audit_log", "action = 'auth.oidc.denied'"), "%s: one denial row", name)
	assert.Equal(t, 1, s.countWhere("audit_log", "action = 'auth.oidc.denied' AND seq = (SELECT max(seq) FROM audit_log "+
		"WHERE action = 'auth.oidc.denied') AND details->>'reason' = '"+reason+"'"), name)
}

func TestSSOLoginOverTheWire(t *testing.T) {
	s, admin, adminAcct := installedWithFakes(t)
	p := s.ssoReady(t, admin, adminAcct)

	// The sign-in page lists the enabled provider (ID and name only).
	rec := s.freshClient().do(http.MethodGet, "/api/v1/auth/oidc/providers", nil)
	requireStatus(t, rec, http.StatusOK)
	assert.JSONEq(t, `{"items":[{"id":"`+p+`","name":"Corp IdP"}]}`, rec.Body.String())

	s.idp.NextLogin(fakeidp.Login{Subject: "u1", Username: "omer", Name: "Ömer", Email: "omer@example.com", Groups: []string{"alice-operators"}})
	browser := s.freshClient()
	rec = browser.do(http.MethodPost, "/api/v1/auth/oidc/"+p+"/start", map[string]string{"next": "/certificates"})
	requireStatus(t, rec, http.StatusOK)
	// The binding cookie (SEC-011): __Host-, Secure, HttpOnly, SameSite=Lax (the provider's redirect back is a
	// cross-site top-level navigation), Path=/, 10 minutes, a 256-bit value that is not in the body.
	bind := setCookies(t, rec)[oidcCookie]
	require.NotNil(t, bind)
	assert.True(t, bind.Secure)
	assert.True(t, bind.HttpOnly)
	assert.Equal(t, http.SameSiteLaxMode, bind.SameSite)
	assert.Equal(t, "/", bind.Path)
	assert.Empty(t, bind.Domain)
	assert.Equal(t, 600, bind.MaxAge)
	assert.GreaterOrEqual(t, len(bind.Value), 43)
	assert.NotContains(t, rec.Body.String(), bind.Value)
	assert.Empty(t, setCookies(t, rec)[sessionCookie], "starting is not signing in")
	authz := decodeBody[struct {
		AuthorizeURL string `json:"authorize_url"`
	}](t, rec).AuthorizeURL
	au, err := url.Parse(authz)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(authz, s.idp.Issuer()+"/authorize?"), authz)
	assert.Equal(t, "S256", au.Query().Get("code_challenge_method"), "PKCE (SEC-011)")
	assert.NotEmpty(t, au.Query().Get("nonce"))
	assert.NotEmpty(t, au.Query().Get("state"))
	assert.Empty(t, au.Query().Get("prompt"), "a sign-in does not force a new sign-in at the provider")
	assert.Equal(t, 1, s.count("oidc_login_states"))

	rec = browser.do(http.MethodGet, s.authorizeAt(t, authz), nil)
	require.Equal(t, http.StatusSeeOther, rec.Code, rec.Body.String())
	assert.Equal(t, "/certificates", rec.Header().Get("Location"))
	cookies := setCookies(t, rec)
	if ck := cookies[oidcCookie]; assert.NotNil(t, ck) {
		assert.Negative(t, ck.MaxAge, "the binding cookie is cleared")
	}
	sess := cookies[sessionCookie]
	require.NotNil(t, sess)
	assert.True(t, sess.Secure)
	assert.True(t, sess.HttpOnly)
	assert.Equal(t, http.SameSiteStrictMode, sess.SameSite)
	assert.Equal(t, 0, s.count("oidc_login_states"), "the state is used once and deleted")
	// The token request carried the PKCE verifier and the exact redirect URI.
	form := s.idp.LastTokenForm()
	assert.NotEmpty(t, form.Get("code_verifier"))
	assert.Equal(t, "https://alice.test/api/v1/auth/oidc/"+p+"/callback", form.Get("redirect_uri"))
	assert.Empty(t, form.Get("client_secret"), "client_secret_basic only (C11)")

	rec = browser.do(http.MethodGet, "/api/v1/auth/session", nil)
	requireStatus(t, rec, http.StatusOK)
	assert.Contains(t, rec.Body.String(), `"role":"operator"`)
	assert.Contains(t, rec.Body.String(), `"auth_source":"oidc"`)
	assert.Contains(t, rec.Body.String(), `"sso_provider_id":"`+p+`"`)
	assert.Contains(t, rec.Body.String(), `"username":"omer"`)
	requireStatus(t, browser.do(http.MethodGet, "/api/v1/certificates", nil), http.StatusOK)
	requireError(t, browser.do(http.MethodGet, "/api/v1/users", nil), http.StatusForbidden, "ALC-AUTH-0002")
	assert.Equal(t, 1, s.countWhere("audit_log", "action = 'user.provisioned' AND details->>'role' = 'operator'"))
	assert.Equal(t, 1, s.countWhere("audit_log", "action = 'auth.login' AND details->>'method' = 'oidc' AND details->>'provider_id' = '"+p+"'"))

	// The same identity signs in again as the same user; a new group sets the new role (role sync).
	s.stepUp(admin, adminAcct)
	s.mapGroup(t, admin, p, "alice-auditors", "auditor")
	s.idp.NextLogin(fakeidp.Login{Subject: "u1", Username: "omer", Email: "omer@example.com", Groups: []string{"alice-auditors"}})
	second := s.freshClient()
	rec = s.browserSSO(t, second, p)
	require.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Contains(t, second.do(http.MethodGet, "/api/v1/auth/session", nil).Body.String(), `"role":"auditor"`)
	assert.Equal(t, 1, s.countWhere("users", "auth_source = 'oidc'"))
	assert.Equal(t, 1, s.countWhere("audit_log", "action = 'user.role_synced' AND details->>'to_role' = 'auditor'"))

	// An SSO user has no password: the password sign-in refuses it like any wrong password.
	rec = s.login("omer", "anything at all")
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	// The user list shows the source.
	s.stepUp(admin, adminAcct)
	assert.Contains(t, admin.do(http.MethodGet, "/api/v1/users/"+s.userID("omer"), nil).Body.String(), `"auth_source":"oidc"`)
}

// A provider is created switched off unless the body says otherwise (Task 15 fix M-1): the sign-in page does not list
// it and a start is refused with ALC-SSO-0013. Without Alice's address it has no redirect URI yet and a start is refused
// with ALC-SSO-0004. O-12: an issuer that is not https is refused before any request.
func TestSSOProviderStartsSwitchedOffOverTheWire(t *testing.T) {
	s, admin, adminAcct := installedWithFakes(t)
	s.stepUp(admin, adminAcct)
	assert.Contains(t, fieldErrors(t, admin.do(http.MethodPost, "/api/v1/sso/providers", map[string]any{"name": "Plain",
		"issuer_url": "http://idp.example.test", "client_id": "alice", "client_secret": "x"})), "issuer_url")
	rec := admin.do(http.MethodPost, "/api/v1/sso/providers", map[string]any{"name": "Corp IdP", "issuer_url": s.idp.Issuer(),
		"client_id": s.idp.ClientID(), "client_secret": s.idp.ClientSecret(), "ca_pem": string(s.idp.CAPEM())})
	requireStatus(t, rec, http.StatusCreated)
	p := decodeBody[map[string]any](t, rec)
	id := p["id"].(string)
	assert.Equal(t, false, p["enabled"])
	assert.Equal(t, true, p["has_client_secret"])
	assert.Equal(t, "", p["redirect_uri"], "no redirect URI while Alice's address is not set")
	assert.NotContains(t, rec.Body.String(), s.idp.ClientSecret())
	assert.JSONEq(t, `{"items":[]}`, s.freshClient().do(http.MethodGet, "/api/v1/auth/oidc/providers", nil).Body.String())
	requireError(t, s.freshClient().do(http.MethodPost, "/api/v1/auth/oidc/"+id+"/start", nil), http.StatusForbidden, "ALC-SSO-0013")

	version := etagVersion(t, rec)
	requireError(t, admin.do(http.MethodPatch, "/api/v1/sso/providers/"+id, map[string]any{"enabled": true}, ifMatchOf(version)),
		http.StatusConflict, "ALC-SSO-0004")

	requireStatus(t, admin.do(http.MethodPut, "/api/v1/settings/general",
		map[string]any{"public_url": "https://alice.test", "retired_key_retention_days": 30}, ifMatchOf("0")), http.StatusOK)
	rec = admin.do(http.MethodGet, "/api/v1/sso/providers/"+id, nil)
	assert.Equal(t, "https://alice.test/api/v1/auth/oidc/"+id+"/callback", decodeBody[map[string]any](t, rec)["redirect_uri"])
	requireStatus(t, admin.do(http.MethodPatch, "/api/v1/sso/providers/"+id, map[string]any{"enabled": true}, ifMatchOf(version)), http.StatusOK)
	requireStatus(t, s.freshClient().do(http.MethodPost, "/api/v1/auth/oidc/"+id+"/start", nil), http.StatusOK)
	// Alice's address can be removed later (Task 16 report, concern): the start is then refused cleanly, never sent to
	// the provider with an empty return address.
	rec = admin.do(http.MethodGet, "/api/v1/settings/general", nil)
	requireStatus(t, admin.do(http.MethodPut, "/api/v1/settings/general", map[string]any{"public_url": "", "retired_key_retention_days": 30},
		ifMatchOf(etagVersion(t, rec))), http.StatusOK)
	states := s.count("oidc_login_states")
	requireError(t, s.freshClient().do(http.MethodPost, "/api/v1/auth/oidc/"+id+"/start", nil), http.StatusConflict, "ALC-SSO-0004")
	assert.Equal(t, states, s.count("oidc_login_states"))
}

// O-01..O-14 over the wire: each refusal is a redirect to the sign-in page with the reason, no session cookie, the
// binding cookie cleared and one auth.oidc.denied row.
func TestOIDCNegativeSuiteOverTheWire(t *testing.T) {
	s, admin, adminAcct := installedWithFakes(t)
	p := s.ssoReady(t, admin, adminAcct)
	wrong := "wrong"
	ops := []string{"alice-operators"}
	cases := []struct {
		name   string
		login  fakeidp.Login
		fault  fakeidp.Fault
		reason string
	}{
		{"O-01 alg none", fakeidp.Login{Subject: "u", Groups: ops}, fakeidp.Fault{Alg: "none"}, "login_invalid"},
		{"O-01 HS256 keyed with the public key", fakeidp.Login{Subject: "u", Groups: ops}, fakeidp.Fault{Alg: "HS256"}, "login_invalid"},
		{"O-01 HS256 keyed with the PEM", fakeidp.Login{Subject: "u", Groups: ops}, fakeidp.Fault{Alg: "HS256", HMACKeyPEM: true}, "login_invalid"},
		{"O-01 other key", fakeidp.Login{Subject: "u", Groups: ops}, fakeidp.Fault{OtherKey: true}, "login_invalid"},
		{"O-01 unknown kid", fakeidp.Login{Subject: "u", Groups: ops}, fakeidp.Fault{UnknownKid: true}, "login_invalid"},
		{"O-02 issuer", fakeidp.Login{Subject: "u", Groups: ops}, fakeidp.Fault{Issuer: "https://evil"}, "login_invalid"},
		{"O-02 audience", fakeidp.Login{Subject: "u", Groups: ops}, fakeidp.Fault{Audience: []string{"x"}}, "login_invalid"},
		{"O-02 azp", fakeidp.Login{Subject: "u", Groups: ops}, fakeidp.Fault{Audience: []string{"alice", "x"}, Azp: "x"}, "login_invalid"},
		{"O-02 expired", fakeidp.Login{Subject: "u", Groups: ops}, fakeidp.Fault{ExpIn: -5 * time.Minute}, "login_invalid"},
		{"O-02 not yet valid", fakeidp.Login{Subject: "u", Groups: ops}, fakeidp.Fault{NbfOffset: time.Hour}, "login_invalid"},
		{"O-02 issued in the future", fakeidp.Login{Subject: "u", Groups: ops}, fakeidp.Fault{IatOffset: time.Hour}, "login_invalid"},
		{"O-03 nonce", fakeidp.Login{Subject: "u", Groups: ops}, fakeidp.Fault{Nonce: &wrong}, "login_invalid"},
		{"O-03 no nonce", fakeidp.Login{Subject: "u", Groups: ops}, fakeidp.Fault{OmitNonce: true}, "login_invalid"},
		{"O-05 IdP error", fakeidp.Login{Subject: "u", Groups: ops}, fakeidp.Fault{AuthorizeError: "access_denied"}, "idp_error"},
		{"O-06 no group", fakeidp.Login{Subject: "u", Groups: []string{"nobody"}}, fakeidp.Fault{}, "no_access"},
		{"O-06 no groups claim", fakeidp.Login{Subject: "u"}, fakeidp.Fault{}, "no_access"},
		{"O-07 overage", fakeidp.Login{Subject: "u"}, fakeidp.Fault{Overage: true}, "groups_overage"},
		{"O-07 hasgroups", fakeidp.Login{Subject: "u"}, fakeidp.Fault{HasGroups: true}, "groups_overage"},
		{"O-10 local e-mail", fakeidp.Login{Subject: "u", Email: "ada@example.com", Groups: ops}, fakeidp.Fault{}, "email_in_use"},
	}
	requireStatus(t, admin.do(http.MethodPatch, "/api/v1/users/"+s.userID("ada"), map[string]string{"email": "ada@example.com"}), http.StatusOK)
	for _, c := range cases {
		s.idp.NextLogin(c.login)
		s.idp.SetFault(c.fault)
		before := s.countWhere("audit_log", "action = 'auth.oidc.denied'")
		browser := s.freshClient()
		rec := s.browserSSO(t, browser, p)
		s.requireRefused(t, rec, "/login?sso_error=sso."+c.reason, c.reason, before, c.name)
		requireError(t, browser.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusUnauthorized, "ALC-AUTH-0001")
		assert.Equal(t, 0, s.countWhere("users", "auth_source = 'oidc'"), "%s: nobody is provisioned", c.name)
	}
	s.idp.SetFault(fakeidp.Fault{})
	assert.Equal(t, 0, s.countWhere("sessions", "user_id <> '"+adminAcct.id+"'"))

	refusedFlow := func(name, reason string, run func() *httptest.ResponseRecorder) {
		t.Helper()
		before := s.countWhere("audit_log", "action = 'auth.oidc.denied'")
		s.requireRefused(t, run(), "/login?sso_error=sso."+reason, reason, before, name)
	}
	s.idp.NextLogin(fakeidp.Login{Subject: "u", Groups: ops})

	// O-03: the callback without the browser's binding cookie (another browser, or a forged link) is refused, and so is
	// one with another sign-in's cookie.
	refusedFlow("O-03 no binding cookie", "login_expired", func() *httptest.ResponseRecorder {
		cb := s.authorizeAt(t, s.ssoStart(t, s.freshClient(), p))
		return s.freshClient().do(http.MethodGet, cb, nil)
	})
	refusedFlow("O-03 another sign-in's cookie", "login_expired", func() *httptest.ResponseRecorder {
		a, b := s.freshClient(), s.freshClient()
		cbA := s.authorizeAt(t, s.ssoStart(t, a, p))
		s.ssoStart(t, b, p)
		return b.do(http.MethodGet, cbA, nil)
	})
	// O-04: a callback is used once: replaying it (same browser, same cookie value) is refused and signs nobody in.
	browser := s.freshClient()
	cb := s.authorizeAt(t, s.ssoStart(t, browser, p))
	binding := browser.cookies[oidcCookie]
	rec := browser.do(http.MethodGet, cb, nil)
	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Equal(t, "/certificates", rec.Header().Get("Location"))
	refusedFlow("O-04 replayed callback", "login_expired", func() *httptest.ResponseRecorder {
		replay := s.freshClient()
		replay.cookies[oidcCookie] = binding
		return replay.do(http.MethodGet, cb, nil)
	})
	// O-13: a sign-in must end within 10 minutes.
	refusedFlow("O-13 state expired", "login_expired", func() *httptest.ResponseRecorder {
		c := s.freshClient()
		cb := s.authorizeAt(t, s.ssoStart(t, c, p))
		s.clock.Advance(10*time.Minute + time.Second)
		return c.do(http.MethodGet, cb, nil)
	})
	// O-14: the state belongs to its provider: another provider's callback path consumes and refuses it.
	refusedFlow("O-14 another provider's path", "login_expired", func() *httptest.ResponseRecorder {
		c := s.freshClient()
		cb := s.authorizeAt(t, s.ssoStart(t, c, p))
		return c.do(http.MethodGet, strings.Replace(cb, p, "00000000-0000-4000-8000-000000000001", 1), nil)
	})
	// A path that is no provider ID at all is refused without a state lookup.
	before := s.countWhere("audit_log", "action = 'auth.oidc.denied'")
	rec = s.freshClient().do(http.MethodGet, "/api/v1/auth/oidc/not-a-uuid/callback?state=x&code=y", nil)
	require.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "/login?sso_error=sso.login_invalid", rec.Header().Get("Location"))
	assert.Equal(t, before, s.countWhere("audit_log", "action = 'auth.oidc.denied'"))
	// O-11: the provider cannot be reached for the token exchange.
	refusedFlow("O-11 IdP unreachable", "idp_unreachable", func() *httptest.ResponseRecorder {
		c := s.freshClient()
		cb := s.authorizeAt(t, s.ssoStart(t, c, p))
		s.idp.Down()
		defer s.idp.Up()
		return c.do(http.MethodGet, cb, nil)
	})
	// O-09: the provider is switched off between the start and the callback.
	s.stepUp(admin, adminAcct)
	cur := admin.do(http.MethodGet, "/api/v1/sso/providers/"+p, nil)
	requireStatus(t, cur, http.StatusOK)
	c := s.freshClient()
	cb = s.authorizeAt(t, s.ssoStart(t, c, p))
	rec = admin.do(http.MethodPatch, "/api/v1/sso/providers/"+p, map[string]any{"enabled": false}, ifMatchOf(etagVersion(t, cur)))
	requireStatus(t, rec, http.StatusOK)
	refusedFlow("O-09 provider switched off", "provider_disabled", func() *httptest.ResponseRecorder { return c.do(http.MethodGet, cb, nil) })
	requireError(t, s.freshClient().do(http.MethodPost, "/api/v1/auth/oidc/"+p+"/start", nil), http.StatusForbidden, "ALC-SSO-0013")
	requireStatus(t, admin.do(http.MethodPatch, "/api/v1/sso/providers/"+p, map[string]any{"enabled": true}, ifMatchOf(etagVersion(t, rec))),
		http.StatusOK)
	// O-08: a disabled SSO user is refused (the user "u" exists since O-04).
	var u string
	require.NoError(t, s.db.Owner.QueryRow(context.Background(), `SELECT id::text FROM users WHERE oidc_subject = 'u'`).Scan(&u))
	requireStatus(t, admin.do(http.MethodPatch, "/api/v1/users/"+u, map[string]any{"disabled": true}), http.StatusOK)
	refusedFlow("O-08 user disabled", "user_disabled", func() *httptest.ResponseRecorder { return s.browserSSO(t, s.freshClient(), p) })

	// No refusal left a sign-in state behind except the one of O-03's second browser.
	assert.LessOrEqual(t, s.count("oidc_login_states"), 1)
	assert.Equal(t, 1, s.countWhere("users", "auth_source = 'oidc'"))
}

// stepUpSSO runs an SSO user's step-up on c: POST /auth/oidc/stepup with next, the IdP, the callback.
func (s *stack) stepUpSSO(t *testing.T, c *client, next string) *httptest.ResponseRecorder {
	t.Helper()
	// The page loads the session first (its CSRF token: a sign-in or step-up callback is a redirect, not JSON).
	requireStatus(t, c.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusOK)
	rec := c.do(http.MethodPost, "/api/v1/auth/oidc/stepup", map[string]string{"next": next})
	requireStatus(t, rec, http.StatusOK)
	authz := decodeBody[struct {
		AuthorizeURL string `json:"authorize_url"`
	}](t, rec).AuthorizeURL
	u, err := url.Parse(authz)
	require.NoError(t, err)
	assert.Equal(t, "login", u.Query().Get("prompt"), "a step-up asks for a fresh sign-in")
	assert.Equal(t, "0", u.Query().Get("max_age"))
	return c.do(http.MethodGet, s.authorizeAt(t, authz), nil)
}

// S-1 over the wire: an SSO user's step-up re-evaluates groups -> role as a sign-in does; a step-up as another identity is
// refused; losing every mapped group ends the session; a session that ended meanwhile is never resurrected.
func TestOIDCStepUpReevaluatesOverTheWire(t *testing.T) {
	s, admin, adminAcct := installedWithFakes(t)
	p := s.ssoReady(t, admin, adminAcct)
	s.mapGroup(t, admin, p, "alice-auditors", "auditor")
	omer := fakeidp.Login{Subject: "u1", Username: "omer", Groups: []string{"alice-operators"}}
	s.idp.NextLogin(omer)
	browser := s.freshClient()
	require.Equal(t, "/certificates", s.browserSSO(t, browser, p).Header().Get("Location"))

	// A local user confirms with the authenticator code instead.
	requireError(t, admin.do(http.MethodPost, "/api/v1/auth/oidc/stepup", map[string]string{"next": "/settings"}),
		http.StatusConflict, "ALC-SSO-0016")

	// The step-up with a new group: the role is the new group's, the window opens, the session cookie is rotated.
	omer.Groups = []string{"alice-auditors"}
	s.idp.NextLogin(omer)
	oldSession := browser.cookies[sessionCookie]
	rec := s.stepUpSSO(t, browser, "/settings")
	require.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "/settings", rec.Header().Get("Location"))
	assert.NotEqual(t, oldSession, browser.cookies[sessionCookie], "A-04: the step-up rotates the session")
	sess := decodeBody[struct {
		User struct {
			Role string `json:"role"`
		} `json:"user"`
		StepUpUntil *time.Time `json:"stepup_until"`
	}](t, browser.do(http.MethodGet, "/api/v1/auth/session", nil))
	assert.Equal(t, "auditor", sess.User.Role)
	require.NotNil(t, sess.StepUpUntil)
	assert.True(t, sess.StepUpUntil.After(s.clock.Now()))
	assert.Equal(t, 1, s.countWhere("audit_log", "action = 'auth.stepup' AND details->>'method' = 'oidc'"))
	assert.Equal(t, 1, s.countWhere("audit_log", "action = 'user.role_synced' AND details->>'from_role' = 'operator' AND details->>'to_role' = 'auditor'"))

	// Another identity at the provider: refused back to the asking page; the session stays.
	s.idp.NextLogin(fakeidp.Login{Subject: "someone-else", Groups: []string{"alice-auditors"}})
	before := s.countWhere("audit_log", "action = 'auth.oidc.denied'")
	s.requireRefused(t, s.stepUpSSO(t, browser, "/settings?tab=mail#smtp"), "/settings?tab=mail&sso_error=sso.stepup_other_user#smtp",
		"stepup_other_user", before, "step-up as another user")
	requireStatus(t, browser.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusOK)

	// No mapped group any more: the step-up is refused and every session of the user ends (S-1).
	second := s.freshClient()
	s.idp.NextLogin(omer)
	require.Equal(t, http.StatusSeeOther, s.browserSSO(t, second, p).Code)
	omer.Groups = []string{"nobody"}
	s.idp.NextLogin(omer)
	before = s.countWhere("audit_log", "action = 'auth.oidc.denied'")
	s.requireRefused(t, s.stepUpSSO(t, browser, "/settings"), "/settings?sso_error=sso.no_access", "no_access", before, "step-up without access")
	requireError(t, browser.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusUnauthorized, "ALC-AUTH-0001")
	requireError(t, second.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusUnauthorized, "ALC-AUTH-0001")
	assert.Equal(t, 1, s.countWhere("audit_log", "action = 'user.sessions_ended' AND details->>'reason' = 'no_access' AND details->>'ended_count' = '2'"))

	// A session that ended between the step-up's start and its callback is not resurrected by a valid callback.
	omer.Groups = []string{"alice-operators"}
	s.idp.NextLogin(omer)
	third := s.freshClient()
	require.Equal(t, http.StatusSeeOther, s.browserSSO(t, third, p).Code)
	requireStatus(t, third.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusOK)
	rec = third.do(http.MethodPost, "/api/v1/auth/oidc/stepup", map[string]string{"next": "/settings"})
	requireStatus(t, rec, http.StatusOK)
	cb := s.authorizeAt(t, decodeBody[struct {
		AuthorizeURL string `json:"authorize_url"`
	}](t, rec).AuthorizeURL)
	s.stepUp(admin, adminAcct)
	requireStatus(t, admin.do(http.MethodPost, "/api/v1/users/"+s.userID("omer")+"/actions/revoke-sessions", nil), http.StatusNoContent)
	before = s.countWhere("audit_log", "action = 'auth.oidc.denied'")
	s.requireRefused(t, third.do(http.MethodGet, cb, nil), "/settings?sso_error=sso.login_expired", "login_expired", before,
		"step-up of an ended session")
	requireError(t, third.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusUnauthorized, "ALC-AUTH-0001")
	assert.Equal(t, 0, s.countWhere("sessions", "revoked_at IS NULL AND user_id = '"+s.userID("omer")+"'"))
}

// The limits over the wire (S-11 as amended by the Task 15 review): the start keeps the sign-in form's 10 a minute per
// address; the callback is limited to 10 a minute per binding cookie inside the anonymous 60 a minute per address.
func TestOIDCLimitsOverTheWire(t *testing.T) {
	s, admin, adminAcct := installedWithFakes(t)
	p := s.ssoReady(t, admin, adminAcct)
	s.api.ResetLimits()

	one := s.client("203.0.113.10")
	for i := 0; i < 10; i++ {
		requireStatus(t, one.do(http.MethodPost, "/api/v1/auth/oidc/"+p+"/start", nil), http.StatusOK)
	}
	requireError(t, one.do(http.MethodPost, "/api/v1/auth/oidc/"+p+"/start", nil), http.StatusTooManyRequests, "ALC-SYS-0005")
	assert.Equal(t, 10, s.count("oidc_login_states"), "a refused start stores nothing")
	requireStatus(t, s.client("203.0.113.11").do(http.MethodPost, "/api/v1/auth/oidc/"+p+"/start", nil), http.StatusOK)

	s.api.ResetLimits()
	cb := "/api/v1/auth/oidc/" + p + "/callback?state=guess&code=guess"
	browser := s.client("203.0.113.20")
	browser.cookies[oidcCookie] = "one-binding-value"
	for i := 0; i < 10; i++ {
		browser.cookies[oidcCookie] = "one-binding-value" // every callback clears it; a retrying browser sends it again
		rec := browser.do(http.MethodGet, cb, nil)
		require.Equal(t, http.StatusSeeOther, rec.Code)
	}
	browser.cookies[oidcCookie] = "one-binding-value"
	requireError(t, browser.do(http.MethodGet, cb, nil), http.StatusTooManyRequests, "ALC-SYS-0005")
	// Other browsers behind the same address still finish their sign-ins...
	for i := 0; i < 5; i++ {
		other := s.client("203.0.113.20")
		other.cookies[oidcCookie] = "other-binding-" + string(rune('a'+i))
		assert.Equal(t, http.StatusSeeOther, other.do(http.MethodGet, cb, nil).Code)
	}
	// ...but fresh cookies do not buy unlimited callbacks: the address is bounded at 60 a minute.
	s.api.ResetLimits()
	var last int
	for i := 0; i < 61; i++ {
		c := s.client("203.0.113.30")
		c.cookies[oidcCookie] = "fresh-" + strings.Repeat("x", i+1)
		last = c.do(http.MethodGet, cb, nil).Code
		if i < 60 {
			require.Equal(t, http.StatusSeeOther, last, "callback %d", i+1)
		}
	}
	assert.Equal(t, http.StatusTooManyRequests, last)
	// HEAD on the callback runs nothing.
	before := s.countWhere("audit_log", "action = 'auth.oidc.denied'")
	rec := s.freshClient().do(http.MethodHead, cb, nil)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	assert.Equal(t, "GET", rec.Header().Get("Allow"))
	assert.Equal(t, before, s.countWhere("audit_log", "action = 'auth.oidc.denied'"))
}

// X-05, R-03: with the identity provider down, single sign-on fails cleanly and the local Administrator with the
// authenticator code signs in, steps up and can switch the provider off.
func TestX05BreakGlassWhileIdPDown(t *testing.T) {
	s, admin, adminAcct := installedWithFakes(t)
	p := s.ssoReady(t, admin, adminAcct)
	s.idp.NextLogin(fakeidp.Login{Subject: "u1", Groups: []string{"alice-operators"}})
	browser := s.freshClient()
	cb := s.authorizeAt(t, s.ssoStart(t, browser, p))
	s.idp.Down()

	// The sign-in page still lists the provider and a start needs no call to it (the endpoints are stored).
	assert.Contains(t, s.freshClient().do(http.MethodGet, "/api/v1/auth/oidc/providers", nil).Body.String(), p)
	requireStatus(t, s.freshClient().do(http.MethodPost, "/api/v1/auth/oidc/"+p+"/start", map[string]string{}), http.StatusOK)
	before := s.countWhere("audit_log", "action = 'auth.oidc.denied'")
	s.requireRefused(t, browser.do(http.MethodGet, cb, nil), "/login?sso_error=sso.idp_unreachable", "idp_unreachable", before, "X-05")

	local := s.freshClient()
	s.signIn(local, adminAcct)
	requireStatus(t, local.do(http.MethodGet, "/api/v1/users", nil), http.StatusOK)
	s.stepUp(local, adminAcct)
	cur := local.do(http.MethodGet, "/api/v1/sso/providers/"+p, nil)
	requireStatus(t, cur, http.StatusOK)
	requireStatus(t, local.do(http.MethodPatch, "/api/v1/sso/providers/"+p, map[string]any{"enabled": false}, ifMatchOf(etagVersion(t, cur))),
		http.StatusOK)
	assert.JSONEq(t, `{"items":[]}`, s.freshClient().do(http.MethodGet, "/api/v1/auth/oidc/providers", nil).Body.String())
	// Reading the provider's settings again while it is down is a clean 502 (ALC-SSO-0001), not a 500.
	cur = local.do(http.MethodGet, "/api/v1/sso/providers/"+p, nil)
	requireError(t, local.do(http.MethodPost, "/api/v1/sso/providers/"+p+"/actions/refresh", nil, ifMatchOf(etagVersion(t, cur))),
		http.StatusBadGateway, "ALC-SSO-0001")
}
