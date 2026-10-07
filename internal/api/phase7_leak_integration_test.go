//go:build integration

package api

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/secrets"
	"alice/internal/testutil/fakeidp"
	"alice/internal/testutil/seed"
)

// The Phase 7 secret-leak suite (Review Focus 3, §25.2, S-01..S-05, the global secret rule): the SMTP password, every
// OIDC client secret, the keyring material behind their envelopes, the browser binding cookie, the OIDC state, nonce,
// authorization code and PKCE verifier are planted or captured as canaries while every Phase 7 flow runs over the
// wire — including the failures — and then looked for, in every spelling, in every answer body and header, every log
// line (DEBUG), every row of every table (audit details, settings, the outbox, the sign-in states) and every e-mail.

// leakCanary is one secret and the answers that may carry it: in their body (bodyOK) or in a header (headerOK),
// keyed by "METHOD /path".
type leakCanary struct {
	secretValue
	bodyOK, headerOK func(key string) bool
}

func never(string) bool { return false }

func TestPhase7SecretsNeverLeak(t *testing.T) {
	s, admin, adminAcct := installedWithFakes(t)
	ctx := context.Background()
	s.stepUp(admin, adminAcct)
	requireStatus(t, admin.do(http.MethodPatch, "/api/v1/users/"+adminAcct.id, map[string]string{"email": "ada@example.com"}), http.StatusOK)

	// The mail settings: a refused change, a wrong password, the untrusted certificate, trust, the server refusing
	// the credentials, the right password, a test e-mail, then alerts delivered during and after an outage.
	refusedPW, wrongPW := canary("smtp-refused"), canary("smtp-wrong")
	bad := s.mailBody(refusedPW)
	bad["host"] = "bad host"
	fieldErrors(t, admin.do(http.MethodPut, "/api/v1/settings/smtp", bad, ifMatchOf("0")))
	rec := admin.do(http.MethodPut, "/api/v1/settings/smtp", s.mailBody(wrongPW), ifMatchOf("0"))
	requireStatus(t, rec, http.StatusOK)
	rec = admin.do(http.MethodPost, "/api/v1/settings/smtp/actions/test", map[string]string{"to": "ops@example.com"})
	requireError(t, rec, http.StatusBadGateway, "ALC-NTF-0005")
	rec = admin.do(http.MethodPost, "/api/v1/settings/smtp/actions/trust",
		map[string]string{"fingerprint": decodeBody[apiError](t, rec).Error.Params["fingerprint"]}, ifMatchOf("1"))
	requireStatus(t, rec, http.StatusOK)
	requireError(t, admin.do(http.MethodPost, "/api/v1/settings/smtp/actions/test", map[string]string{"to": "ops@example.com"}),
		http.StatusBadGateway, "ALC-NTF-0006")
	requireStatus(t, admin.do(http.MethodPut, "/api/v1/settings/smtp", s.mailBody(stackSMTPPassword), ifMatchOf(etagVersion(t, rec))),
		http.StatusOK)
	requireStatus(t, admin.do(http.MethodPost, "/api/v1/settings/smtp/actions/test", map[string]string{"to": "ops@example.com"}), http.StatusOK)
	requireStatus(t, admin.do(http.MethodGet, "/api/v1/settings/smtp", nil), http.StatusOK)
	_, err := seed.Dashboard(ctx, s.db.Owner, s.clock.Now())
	require.NoError(t, err)
	_, err = s.alerts.Scan(ctx)
	require.NoError(t, err)
	s.smtp.Down()
	s.drainMail()
	require.NoError(t, s.smtp.Up())
	s.clock.Advance(time.Minute)
	s.drainMail()
	require.NotEmpty(t, s.smtp.Messages())
	s.signIn(admin, adminAcct)
	requireStatus(t, admin.do(http.MethodGet, "/api/v1/notifications/status", nil), http.StatusOK)
	requireStatus(t, admin.do(http.MethodGet, "/api/v1/dashboard/summary", nil), http.StatusOK)

	// Single sign-on: a refused provider (its secret must not be echoed), the provider, a replaced secret that the
	// provider refuses, the real one again, a sign-in, a refused sign-in and a step-up.
	refusedSecret, otherSecret := canary("client-secret-refused"), canary("client-secret-other")
	s.stepUp(admin, adminAcct)
	fieldErrors(t, admin.do(http.MethodPost, "/api/v1/sso/providers", map[string]any{"name": "", "issuer_url": s.idp.Issuer(),
		"client_id": "alice", "client_secret": refusedSecret}))
	p := s.ssoReady(t, admin, adminAcct)
	cur := admin.do(http.MethodGet, "/api/v1/sso/providers/"+p, nil)
	rec = admin.do(http.MethodPatch, "/api/v1/sso/providers/"+p, map[string]any{"client_secret": otherSecret}, ifMatchOf(etagVersion(t, cur)))
	requireStatus(t, rec, http.StatusOK)

	var bindings, states, nonces, codes, verifiers []string
	// login runs one browser round trip and captures what the browser and the provider saw.
	login := func(c *client, path string, body map[string]string) *http.Cookie {
		t.Helper()
		if path == "/api/v1/auth/oidc/stepup" {
			requireStatus(t, c.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusOK)
		}
		rec := c.do(http.MethodPost, path, body)
		requireStatus(t, rec, http.StatusOK)
		bindings = append(bindings, c.cookies[oidcCookie])
		authz, err := url.Parse(decodeBody[struct {
			AuthorizeURL string `json:"authorize_url"`
		}](t, rec).AuthorizeURL)
		require.NoError(t, err)
		states = append(states, authz.Query().Get("state"))
		nonces = append(nonces, authz.Query().Get("nonce"))
		cb := s.authorizeAt(t, authz.String())
		cbURL, err := url.Parse(cb)
		require.NoError(t, err)
		if code := cbURL.Query().Get("code"); code != "" {
			codes = append(codes, code)
		}
		res := c.do(http.MethodGet, cb, nil)
		require.Equal(t, http.StatusSeeOther, res.Code)
		if v := s.idp.LastTokenForm().Get("code_verifier"); v != "" && !containsString(verifiers, v) {
			verifiers = append(verifiers, v)
		}
		return setCookies(t, res)[sessionCookie]
	}
	start := "/api/v1/auth/oidc/" + p + "/start"
	s.idp.NextLogin(fakeidp.Login{Subject: "u1", Username: "omer", Email: "omer@example.com", Groups: []string{"alice-operators"}})
	assert.Nil(t, login(s.freshClient(), start, map[string]string{"next": "/"}), "the provider refuses the replaced client secret")
	cur = admin.do(http.MethodGet, "/api/v1/sso/providers/"+p, nil)
	requireStatus(t, admin.do(http.MethodPatch, "/api/v1/sso/providers/"+p, map[string]any{"client_secret": s.idp.ClientSecret()},
		ifMatchOf(etagVersion(t, cur))), http.StatusOK)
	browser := s.freshClient()
	require.NotNil(t, login(browser, start, map[string]string{"next": "/certificates"}))
	s.idp.SetFault(fakeidp.Fault{Alg: "none"})
	assert.Nil(t, login(s.freshClient(), start, map[string]string{}))
	s.idp.SetFault(fakeidp.Fault{})
	require.NotNil(t, login(browser, "/api/v1/auth/oidc/stepup", map[string]string{"next": "/settings"}))
	requireStatus(t, browser.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusOK)
	s.stepUp(admin, adminAcct)
	requireStatus(t, admin.do(http.MethodGet, "/api/v1/sso/providers", nil), http.StatusOK)
	requireStatus(t, admin.do(http.MethodGet, "/api/v1/users", nil), http.StatusOK)
	require.Len(t, bindings, 4)
	require.Len(t, codes, 4)
	require.NotEmpty(t, verifiers)
	assert.Equal(t, 0, s.count("oidc_login_states"), "no sign-in is pending")

	// The canaries.
	isStart := func(key string) bool {
		return key == "POST "+start || key == "POST /api/v1/auth/oidc/stepup"
	}
	var canaries []leakCanary
	plain := func(name, value string) {
		canaries = append(canaries, leakCanary{secretValue: secretValue{name: name, value: value}, bodyOK: never, headerOK: never})
	}
	plain("SMTP password (stack)", stackSMTPPassword)
	plain("SMTP password (wrong)", wrongPW)
	plain("SMTP password (refused)", refusedPW)
	plain("client secret", s.idp.ClientSecret())
	plain("client secret (replaced)", otherSecret)
	plain("client secret (refused)", refusedSecret)
	for _, v := range codes {
		plain("authorization code", v)
	}
	for _, v := range verifiers {
		plain("PKCE verifier", v)
	}
	for _, v := range bindings {
		// The binding value is the start's Set-Cookie and nowhere else; the database holds only its SHA-256.
		canaries = append(canaries, leakCanary{secretValue: secretValue{name: "binding cookie", value: v}, bodyOK: never, headerOK: isStart})
	}
	for _, v := range append(append([]string(nil), states...), nonces...) {
		// The state and the nonce travel in the authorize URL the start answers with; they are never logged and the
		// state is stored only hashed.
		canaries = append(canaries, leakCanary{secretValue: secretValue{name: "state or nonce", value: v}, bodyOK: isStart, headerOK: never})
	}
	canaries = append(canaries, leakCanary{secretValue: s.masterKeySecret(), bodyOK: never, headerOK: never})
	rows, err := s.db.Owner.Query(ctx, `SELECT key, wrapped_dek, key_version FROM setting_secrets ORDER BY key`)
	require.NoError(t, err)
	type env struct {
		key string
		e   secrets.Envelope
	}
	envs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (env, error) {
		var x env
		return x, r.Scan(&x.key, &x.e.WrappedDEK, &x.e.KeyVersion)
	})
	require.NoError(t, err)
	require.Len(t, envs, 2, "the SMTP password and the one client secret are stored as envelopes")
	for _, x := range envs {
		dek := unwrapDEK(t, s.masterKey(), secrets.Location{Table: "setting_secrets", RowID: x.key, Column: "ciphertext"}, x.e)
		canaries = append(canaries, leakCanary{secretValue: secretValue{name: "data key of " + x.key, forms: binaryForms(dek)[1:]},
			bodyOK: never, headerOK: never})
	}

	// Where they must not be.
	exchanges := s.recorded()
	require.NotEmpty(t, exchanges)
	logs := s.logs.String()
	dump := s.dump()
	var mails strings.Builder
	for _, m := range s.smtp.Messages() {
		mails.WriteString(m.Raw + "\n" + m.Subject + "\n" + m.Body + "\n")
	}
	for _, c := range canaries {
		for _, x := range exchanges {
			if !c.bodyOK(x.key()) {
				if i, found := c.leakedIn(string(x.body)); found {
					t.Errorf("%s leaked in the body of %s (spelling #%d)", c.name, x.key(), i)
				}
			}
			if !c.headerOK(x.key()) {
				for k, v := range x.header {
					if i, found := c.leakedIn(strings.Join(v, "\n")); found {
						t.Errorf("%s leaked in header %s of %s (spelling #%d)", c.name, k, x.key(), i)
					}
				}
			}
		}
		assertNoSecret(t, "the logs (DEBUG)", logs, []secretValue{c.secretValue})
		assertNoSecret(t, "the database", dump, []secretValue{c.secretValue})
		assertNoSecret(t, "the e-mails", mails.String(), []secretValue{c.secretValue})
	}
	// Positive controls: the scan sees what it scans.
	assert.Contains(t, dump, "settings.smtp_tested")
	assert.Contains(t, dump, "auth.oidc.denied")
	assert.Contains(t, logs, "single sign-on refused")
	var sawBinding bool
	for _, x := range exchanges {
		if isStart(x.key()) && strings.Contains(strings.Join(x.header.Values("Set-Cookie"), " "), bindings[0]) {
			sawBinding = true
		}
	}
	assert.True(t, sawBinding, "the binding cookie was observed where it belongs")
	// The answers carry only the flags.
	smtp := admin.do(http.MethodGet, "/api/v1/settings/smtp", nil).Body.String()
	assert.Contains(t, smtp, `"has_password":true`)
	assert.NotContains(t, smtp, `"password"`)
	prov := admin.do(http.MethodGet, "/api/v1/sso/providers/"+p, nil).Body.String()
	assert.Contains(t, prov, `"has_client_secret":true`)
	assert.NotContains(t, prov, `"client_secret"`)
}
