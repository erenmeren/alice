//go:build integration

package oidc_test

import (
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/auth"
	"alice/internal/auth/oidc"
	"alice/internal/rbac"
	"alice/internal/testutil/fakeidp"
)

// refused: a failed sign-in (§25.5): the reason, one more auth.oidc.denied row carrying that reason, and no session.
func (x *harness) refused(t *testing.T, want string, run func() error) {
	t.Helper()
	sessions := x.count(t, `SELECT count(*) FROM sessions`)
	denied := x.count(t, `SELECT count(*) FROM audit_log WHERE action = 'auth.oidc.denied'`)
	err := run()
	assert.Equal(t, want, reasonOf(err), "%v", err)
	assert.Equal(t, sessions, x.count(t, `SELECT count(*) FROM sessions`), "no session (a revocation is an update, never a new row)")
	assert.Equal(t, denied+1, x.count(t, `SELECT count(*) FROM audit_log WHERE action = 'auth.oidc.denied'`))
	var got string
	require.NoError(t, x.d.Owner.QueryRow(x.ctx, `SELECT details->>'reason' FROM audit_log WHERE action = 'auth.oidc.denied' ORDER BY seq DESC LIMIT 1`).Scan(&got))
	assert.Equal(t, want, got)
}

func (x *harness) ready(t *testing.T) {
	t.Helper()
	x.mapGroup(t, "ops", rbac.Operator)
	x.idp.NextLogin(fakeidp.Login{Subject: "u1", Username: "ada", Email: "ada@example.com", Groups: []string{"ops"}})
}

func TestGoodLoginGivesTheMappedRole(t *testing.T) {
	x := newHarness(t)
	x.ready(t)
	c, err := x.login(t, "/certificates?expiry=30")
	require.NoError(t, err)
	assert.Equal(t, "/certificates?expiry=30", c.Next)
	assert.False(t, c.StepUp)
	pr, err := x.auth.Authenticate(x.ctx, c.Session.Token)
	require.NoError(t, err)
	assert.Equal(t, rbac.Operator, pr.Role)
	assert.Contains(t, x.idp.LastTokenForm(), "code_verifier", "O-04: the verifier is always sent")
	assert.Equal(t, "openid profile email", x.idp.LastAuthorizeQuery().Get("scope"))
	assert.Zero(t, x.count(t, `SELECT count(*) FROM oidc_login_states`), "the state is single use")
}

func TestO01Signatures(t *testing.T) {
	x := newHarness(t)
	x.ready(t)
	for _, f := range []fakeidp.Fault{{Alg: "none"}, {Alg: "HS256"}, {Alg: "HS256", HMACKeyPEM: true}, {OtherKey: true}, {UnknownKid: true}} {
		x.idp.SetFault(f)
		x.refused(t, "login_invalid", func() error { _, err := x.login(t, "/"); return err })
	}
}

func TestO02TimesIssuerAudience(t *testing.T) {
	x := newHarness(t)
	x.ready(t)
	for _, f := range []fakeidp.Fault{{Issuer: "https://evil.example"}, {Audience: []string{"someone-else"}},
		{Audience: []string{x.idp.ClientID(), "other"}}, {ExpIn: -2 * time.Minute}, {IatOffset: 2 * time.Minute},
		{NbfOffset: 2 * time.Minute}} {
		x.idp.SetFault(f)
		x.refused(t, "login_invalid", func() error { _, err := x.login(t, "/"); return err })
	}
}

func TestO03StateNonceAndCodeReplay(t *testing.T) {
	x := newHarness(t)
	x.ready(t)
	wrong := "n-wrong"
	for _, f := range []fakeidp.Fault{{Nonce: &wrong}, {OmitNonce: true}} {
		x.idp.SetFault(f)
		x.refused(t, "login_invalid", func() error { _, err := x.login(t, "/"); return err })
	}
	x.idp.SetFault(fakeidp.Fault{})
	b, err := x.svc.Begin(x.ctx, oidc.BeginInput{ProviderID: x.prov.ID, Next: "/"})
	require.NoError(t, err)
	cb, err := x.idp.Authorize(b.AuthorizeURL)
	require.NoError(t, err)
	u, _ := url.Parse(cb)
	q := u.Query()
	x.refused(t, "login_expired", func() error { _, err := x.svc.Complete(x.ctx, x.prov.ID, q, "other-browser", meta); return err })
	x.refused(t, "login_expired", func() error { _, err := x.svc.Complete(x.ctx, x.prov.ID, q, b.Binding, meta); return err })
	missing := url.Values{"code": q["code"]}
	x.clk.Advance(time.Minute) // a callback without a stored state is audited once a minute per address (review L-8)
	x.refused(t, "login_expired", func() error { _, err := x.svc.Complete(x.ctx, x.prov.ID, missing, b.Binding, meta); return err })
	// An authorization code that was used once is refused when replayed under a fresh state.
	b1, err := x.svc.Begin(x.ctx, oidc.BeginInput{ProviderID: x.prov.ID, Next: "/"})
	require.NoError(t, err)
	cb1, err := x.idp.Authorize(b1.AuthorizeURL)
	require.NoError(t, err)
	u1, _ := url.Parse(cb1)
	_, err = x.svc.Complete(x.ctx, x.prov.ID, u1.Query(), b1.Binding, meta)
	require.NoError(t, err)
	b2, err := x.svc.Begin(x.ctx, oidc.BeginInput{ProviderID: x.prov.ID, Next: "/"})
	require.NoError(t, err)
	replay := url.Values{"code": u1.Query()["code"], "state": {mustQuery(t, b2.AuthorizeURL, "state")}}
	x.refused(t, "login_invalid", func() error { _, err := x.svc.Complete(x.ctx, x.prov.ID, replay, b2.Binding, meta); return err })
	// A state older than 10 minutes is refused.
	b3, err := x.svc.Begin(x.ctx, oidc.BeginInput{ProviderID: x.prov.ID, Next: "/"})
	require.NoError(t, err)
	cb3, err := x.idp.Authorize(b3.AuthorizeURL)
	require.NoError(t, err)
	x.clk.Advance(oidc.StateLifetime + time.Second)
	u3, _ := url.Parse(cb3)
	x.refused(t, "login_expired", func() error { _, err := x.svc.Complete(x.ctx, x.prov.ID, u3.Query(), b3.Binding, meta); return err })
	// O-03 (scan): a wrong state value with the right binding cookie.
	b4, err := x.svc.Begin(x.ctx, oidc.BeginInput{ProviderID: x.prov.ID, Next: "/"})
	require.NoError(t, err)
	cb4, err := x.idp.Authorize(b4.AuthorizeURL)
	require.NoError(t, err)
	u4, _ := url.Parse(cb4)
	q4 := u4.Query()
	q4.Set("state", "AAAA"+q4.Get("state")[4:])
	x.refused(t, "login_expired", func() error { _, err := x.svc.Complete(x.ctx, x.prov.ID, q4, b4.Binding, meta); return err })
	// O-03 (scan): the nonce of an earlier completed sign-in, replayed in a fresh one.
	oldNonce := mustQuery(t, b1.AuthorizeURL, "nonce")
	x.idp.SetFault(fakeidp.Fault{Nonce: &oldNonce})
	x.refused(t, "login_invalid", func() error { _, err := x.login(t, "/"); return err })
	// A state of another provider is refused and consumed.
	x.idp.SetFault(fakeidp.Fault{})
	b5, err := x.svc.Begin(x.ctx, oidc.BeginInput{ProviderID: x.prov.ID, Next: "/"})
	require.NoError(t, err)
	q5 := url.Values{"code": {"x"}, "state": {mustQuery(t, b5.AuthorizeURL, "state")}}
	x.refused(t, "login_expired", func() error { _, err := x.svc.Complete(x.ctx, [16]byte{4}, q5, b5.Binding, meta); return err })
}

func mustQuery(t *testing.T, authorizeURL, key string) string {
	t.Helper()
	u, err := url.Parse(authorizeURL)
	require.NoError(t, err)
	return u.Query().Get(key)
}

func TestO04PKCE(t *testing.T) {
	x := newHarness(t)
	x.ready(t)
	b, err := x.svc.Begin(x.ctx, oidc.BeginInput{ProviderID: x.prov.ID, Next: "/"})
	require.NoError(t, err)
	au, _ := url.Parse(b.AuthorizeURL)
	assert.Equal(t, "S256", au.Query().Get("code_challenge_method"))
	assert.NotEmpty(t, au.Query().Get("code_challenge"))
	cb, err := x.idp.Authorize(b.AuthorizeURL)
	require.NoError(t, err)
	_, err = x.d.Owner.Exec(x.ctx, `UPDATE oidc_login_states SET code_verifier = repeat('w', 43)`) // a wrong verifier
	require.NoError(t, err)
	u, _ := url.Parse(cb)
	x.refused(t, "login_invalid", func() error { _, err := x.svc.Complete(x.ctx, x.prov.ID, u.Query(), b.Binding, meta); return err })
}

func TestO05RedirectAndNext(t *testing.T) {
	x := newHarness(t)
	x.ready(t)
	c, err := x.login(t, "https://evil.example/steal")
	require.NoError(t, err)
	assert.Equal(t, "/", c.Next, "next never leaves Alice")
	x.idp.SetFault(fakeidp.Fault{AuthorizeError: "invalid_request"})
	x.refused(t, "idp_error", func() error { _, err := x.login(t, "/"); return err })
	x.idp.SetFault(fakeidp.Fault{})
	other, err := x.svc.Begin(x.ctx, oidc.BeginInput{ProviderID: x.prov.ID, Next: "/"})
	require.NoError(t, err)
	_, err = x.idp.Authorize(strings.Replace(other.AuthorizeURL, url.QueryEscape(publicURL), url.QueryEscape("https://evil.example"), 1))
	assert.Error(t, err, "the provider refuses a redirect URI it does not know")
}

func TestO06NoMappedGroup(t *testing.T) {
	x := newHarness(t)
	x.mapGroup(t, "ops", rbac.Operator)
	x.idp.NextLogin(fakeidp.Login{Subject: "u1", Username: "ada", Groups: []string{"everyone"}})
	x.refused(t, "no_access", func() error { _, err := x.login(t, "/"); return err })
	assert.Zero(t, x.count(t, `SELECT count(*) FROM users WHERE auth_source = 'oidc'`), "no user is created with any role")
}

func TestO07Overage(t *testing.T) {
	x := newHarness(t)
	x.ready(t)
	x.idp.SetFault(fakeidp.Fault{Overage: true})
	x.refused(t, "groups_overage", func() error { _, err := x.login(t, "/"); return err })
	x.idp.SetFault(fakeidp.Fault{HasGroups: true})
	x.refused(t, "groups_overage", func() error { _, err := x.login(t, "/"); return err })
	// A-s1-01: a malformed groups claim is login_invalid.
	x.idp.SetFault(fakeidp.Fault{})
	x.idp.NextLogin(fakeidp.Login{Subject: "u1", Username: "ada", Extra: map[string]any{"groups": 42}})
	x.refused(t, "login_invalid", func() error { _, err := x.login(t, "/"); return err })
}

func TestO08GroupRemovedEndsSessions(t *testing.T) {
	x := newHarness(t)
	x.ready(t)
	c, err := x.login(t, "/")
	require.NoError(t, err)
	x.idp.NextLogin(fakeidp.Login{Subject: "u1", Username: "ada", Groups: []string{"none"}})
	x.refused(t, "no_access", func() error { _, err := x.login(t, "/"); return err })
	_, err = x.auth.Authenticate(x.ctx, c.Session.Token)
	assert.Error(t, err, "the earlier session ended")
}

func TestO09MatchBySubjectNotEmail(t *testing.T) {
	x := newHarness(t)
	x.ready(t)
	c1, err := x.login(t, "/")
	require.NoError(t, err)
	x.idp.NextLogin(fakeidp.Login{Subject: "u1", Username: "ada", Email: "changed@example.com", Groups: []string{"ops"}})
	c2, err := x.login(t, "/")
	require.NoError(t, err)
	p1, _ := x.auth.Authenticate(x.ctx, c1.Session.Token)
	p2, _ := x.auth.Authenticate(x.ctx, c2.Session.Token)
	assert.Equal(t, p1.UserID, p2.UserID)
	x.idp.NextLogin(fakeidp.Login{Subject: "u2", Username: "mallory", Email: "changed@example.com", Groups: []string{"ops"}})
	c3, err := x.login(t, "/")
	require.NoError(t, err)
	p3, _ := x.auth.Authenticate(x.ctx, c3.Session.Token)
	assert.NotEqual(t, p1.UserID, p3.UserID, "the same e-mail under another subject is another user")
}

func TestO10NoLinkToLocalAccounts(t *testing.T) {
	x := newHarness(t)
	x.mapGroup(t, "ops", rbac.Operator)
	_, err := x.d.Owner.Exec(x.ctx, `INSERT INTO users (id, username, display_name, email, password_hash, role, created_at, updated_at)
VALUES (gen_random_uuid(), 'ada', 'Ada', 'ada@example.com', '$argon2id$x', 'admin', now(), now())`)
	require.NoError(t, err)
	x.idp.NextLogin(fakeidp.Login{Subject: "u1", Username: "ada", Email: "ada@example.com", Groups: []string{"ops"}})
	x.refused(t, "email_in_use", func() error { _, err := x.login(t, "/"); return err })
}

func TestDisabledUserAndProvider(t *testing.T) {
	x := newHarness(t)
	x.ready(t)
	_, err := x.login(t, "/")
	require.NoError(t, err)
	_, err = x.d.Owner.Exec(x.ctx, `UPDATE users SET disabled_at = now() WHERE auth_source = 'oidc'`)
	require.NoError(t, err)
	x.refused(t, "user_disabled", func() error { _, err := x.login(t, "/"); return err })

	b, err := x.svc.Begin(x.ctx, oidc.BeginInput{ProviderID: x.prov.ID, Next: "/"})
	require.NoError(t, err)
	cb, err := x.idp.Authorize(b.AuthorizeURL)
	require.NoError(t, err)
	_, err = x.svc.UpdateProvider(x.ctx, x.admin, x.prov.ID, x.prov.Version, oidc.ProviderPatch{Enabled: ptrBool(false)})
	require.NoError(t, err)
	u, _ := url.Parse(cb)
	x.refused(t, "provider_disabled", func() error { _, err := x.svc.Complete(x.ctx, x.prov.ID, u.Query(), b.Binding, meta); return err })
	_, err = x.svc.Begin(x.ctx, oidc.BeginInput{ProviderID: x.prov.ID, Next: "/"})
	assert.Equal(t, "provider_disabled", reasonOf(err))
	_, err = x.svc.Begin(x.ctx, oidc.BeginInput{ProviderID: [16]byte{5}, Next: "/"})
	assert.ErrorIs(t, err, oidc.ErrNotFound)
}

func TestO11IdPDownAndKeyRotation(t *testing.T) {
	x := newHarness(t)
	x.ready(t)
	_, err := x.login(t, "/")
	require.NoError(t, err)
	x.idp.RotateKey()
	x.clk.Advance(oidc.JWKSRefetchEvery)
	_, err = x.login(t, "/")
	require.NoError(t, err, "an unknown kid after the rotation is fetched once")
	b, err := x.svc.Begin(x.ctx, oidc.BeginInput{ProviderID: x.prov.ID, Next: "/"})
	require.NoError(t, err)
	cb, err := x.idp.Authorize(b.AuthorizeURL)
	require.NoError(t, err)
	x.idp.Down()
	u, _ := url.Parse(cb)
	x.refused(t, "idp_unreachable", func() error { _, err := x.svc.Complete(x.ctx, x.prov.ID, u.Query(), b.Binding, meta); return err })
}

// S-2 at service level: the key set of a provider follows the JWKS answer's max-age.
func TestJWKSCacheFollowsTheProvidersHeaders(t *testing.T) {
	x := newHarness(t)
	x.ready(t)
	x.idp.SetJWKSMaxAge(10 * time.Minute)
	_, err := x.login(t, "/")
	require.NoError(t, err)
	fetched := x.idp.Stats().JWKS
	x.clk.Advance(9 * time.Minute)
	_, err = x.login(t, "/")
	require.NoError(t, err)
	assert.Equal(t, fetched, x.idp.Stats().JWKS, "cached within max-age")
	x.clk.Advance(2 * time.Minute)
	_, err = x.login(t, "/")
	require.NoError(t, err)
	assert.Equal(t, fetched+1, x.idp.Stats().JWKS, "read again after max-age")
}

// O-14: SSO users need no local MFA; nothing of the callback reaches a local account.
func TestO14LocalMFANotBypassed(t *testing.T) {
	x := newHarness(t)
	x.ready(t)
	_, err := x.d.Owner.Exec(x.ctx, `INSERT INTO users (id, username, display_name, email, password_hash, role, created_at, updated_at)
VALUES (gen_random_uuid(), 'root-admin', 'Root', '', '$argon2id$x', 'admin', now(), now())`)
	require.NoError(t, err)
	x.idp.NextLogin(fakeidp.Login{Subject: "root-admin", Username: "root-admin", Groups: []string{"ops"}})
	c, err := x.login(t, "/")
	require.NoError(t, err)
	pr, err := x.auth.Authenticate(x.ctx, c.Session.Token)
	require.NoError(t, err)
	assert.Equal(t, "oidc", pr.AuthSource)
	assert.Equal(t, rbac.Operator, pr.Role, "a new SSO user, never the local Administrator")
	assert.Zero(t, x.count(t, `SELECT count(*) FROM sessions s JOIN users u ON u.id = s.user_id WHERE u.auth_source = 'local'`),
		"no session of a local account exists")
}

func (x *harness) stepUp(t *testing.T, sessionHash []byte, userID [16]byte) (oidc.Completion, error) {
	t.Helper()
	b, err := x.svc.Begin(x.ctx, oidc.BeginInput{StepUp: true, SessionHash: sessionHash, UserID: userID, Next: "/settings"})
	require.NoError(t, err)
	au, _ := url.Parse(b.AuthorizeURL)
	assert.Equal(t, "login", au.Query().Get("prompt"))
	assert.Equal(t, "0", au.Query().Get("max_age"))
	cb, err := x.idp.Authorize(b.AuthorizeURL)
	require.NoError(t, err)
	u, _ := url.Parse(cb)
	return x.svc.Complete(x.ctx, x.prov.ID, u.Query(), b.Binding, meta)
}

func TestStepUpViaIdP(t *testing.T) {
	x := newHarness(t)
	x.ready(t)
	c, err := x.login(t, "/")
	require.NoError(t, err)
	pr, err := x.auth.Authenticate(x.ctx, c.Session.Token)
	require.NoError(t, err)
	x.idp.SetFault(fakeidp.Fault{AuthTimeAgo: 10 * time.Minute})
	x.refused(t, "login_invalid", func() error { _, err := x.stepUp(t, pr.SessionHash, pr.UserID); return err })
	var le *oidc.LoginError
	_, err = x.stepUp(t, pr.SessionHash, pr.UserID)
	require.ErrorAs(t, err, &le)
	assert.True(t, le.StepUp, "a refused step-up returns to the page it came from")
	assert.Equal(t, "/settings", le.Next)
	x.idp.SetFault(fakeidp.Fault{})
	x.idp.NextLogin(fakeidp.Login{Subject: "u1", Username: "ada", Groups: []string{"ops"}})
	done, err := x.stepUp(t, pr.SessionHash, pr.UserID)
	require.NoError(t, err)
	assert.True(t, done.StepUp)
	assert.Equal(t, "/settings", done.Next)
	up, err := x.auth.Authenticate(x.ctx, done.Session.Token)
	require.NoError(t, err)
	assert.True(t, up.Subject(x.clk.Now()).StepUp)

	// Another identity answers the step-up.
	x.idp.NextLogin(fakeidp.Login{Subject: "u2", Username: "bob", Groups: []string{"ops"}})
	x.refused(t, "stepup_other_user", func() error { _, err := x.stepUp(t, up.SessionHash, up.UserID); return err })

	// A local user has no IdP step-up.
	var localID [16]byte
	require.NoError(t, x.d.Owner.QueryRow(x.ctx, `SELECT id FROM users WHERE username = 'ada-admin'`).Scan(&localID))
	_, err = x.svc.Begin(x.ctx, oidc.BeginInput{StepUp: true, SessionHash: up.SessionHash, UserID: localID, Next: "/"})
	assert.Error(t, err)
}

// I-1: a sign-in opens the step-up window only when the ID token's auth_time is within the 5-minute window of Alice's
// clock. A silent sign-in at the provider (an old or absent auth_time) leaves it closed, and the provider's step-up
// (prompt=login, max_age=0) then opens it.
func TestSignInOpensStepUpOnlyForAFreshAuthTime(t *testing.T) {
	x := newHarness(t)
	x.mapGroup(t, "ops", rbac.Operator)
	signIn := func(name string, l fakeidp.Login, f fakeidp.Fault) auth.Principal {
		t.Helper()
		l.Subject, l.Username, l.Groups = "u1", "ada", []string{"ops"}
		x.idp.SetFault(f)
		x.idp.NextLogin(l)
		c, err := x.login(t, "/")
		require.NoError(t, err, name)
		pr, err := x.auth.Authenticate(x.ctx, c.Session.Token)
		require.NoError(t, err, name)
		return pr
	}
	now := x.clk.Now()
	fresh := signIn("fresh", fakeidp.Login{}, fakeidp.Fault{})
	assert.True(t, fresh.Subject(now).StepUp, "the provider authenticated the user just now")
	recent := signIn("recent", fakeidp.Login{Extra: map[string]any{"auth_time": now.Add(-4 * time.Minute).Unix()}}, fakeidp.Fault{})
	assert.True(t, recent.Subject(now).StepUp)
	assert.Equal(t, now.Add(time.Minute), recent.StepUpUntil, "the window ends 5 minutes after the provider's sign-in")

	stale := signIn("stale", fakeidp.Login{Extra: map[string]any{"auth_time": now.Add(-time.Hour).Unix()}}, fakeidp.Fault{})
	assert.False(t, stale.Subject(now).StepUp, "a silent sign-in with an old auth_time")
	absent := signIn("absent", fakeidp.Login{}, fakeidp.Fault{OmitAuthTime: true})
	assert.False(t, absent.Subject(now).StepUp, "no auth_time")
	var open int
	require.NoError(t, x.d.Owner.QueryRow(x.ctx, `SELECT count(*) FROM sessions WHERE id_hash = ANY($1) AND stepup_until IS NOT NULL`,
		[][]byte{stale.SessionHash, absent.SessionHash}).Scan(&open))
	assert.Zero(t, open, "stepup_until is NULL")

	// The provider's step-up still opens the window of the closed session.
	x.idp.SetFault(fakeidp.Fault{})
	x.idp.NextLogin(fakeidp.Login{Subject: "u1", Username: "ada", Groups: []string{"ops"}})
	done, err := x.stepUp(t, stale.SessionHash, stale.UserID)
	require.NoError(t, err)
	up, err := x.auth.Authenticate(x.ctx, done.Session.Token)
	require.NoError(t, err)
	assert.True(t, up.Subject(x.clk.Now()).StepUp)
}

// S-1: the step-up re-evaluates groups → role; a user who lost every mapped group is refused and loses the session,
// and a session ended meanwhile is never resurrected by the step-up callback.
func TestS1StepUpReevaluatesGroupsAndNeedsALiveSession(t *testing.T) {
	x := newHarness(t)
	x.ready(t)
	x.mapGroup(t, "audit", rbac.Auditor)
	c, err := x.login(t, "/")
	require.NoError(t, err)
	pr, err := x.auth.Authenticate(x.ctx, c.Session.Token)
	require.NoError(t, err)

	// The groups changed at the IdP: the step-up gives the new role.
	x.idp.NextLogin(fakeidp.Login{Subject: "u1", Username: "ada", Groups: []string{"audit"}})
	done, err := x.stepUp(t, pr.SessionHash, pr.UserID)
	require.NoError(t, err)
	up, err := x.auth.Authenticate(x.ctx, done.Session.Token)
	require.NoError(t, err)
	assert.Equal(t, rbac.Auditor, up.Role)

	// No mapped group any more: refused no_access and the session ended.
	x.idp.NextLogin(fakeidp.Login{Subject: "u1", Username: "ada", Groups: []string{"none"}})
	x.refused(t, "no_access", func() error { _, err := x.stepUp(t, up.SessionHash, up.UserID); return err })
	_, err = x.auth.Authenticate(x.ctx, done.Session.Token)
	assert.Error(t, err)

	// A step-up started on that (now ended) session cannot bring it back.
	x.idp.NextLogin(fakeidp.Login{Subject: "u1", Username: "ada", Groups: []string{"ops"}})
	x.refused(t, "login_expired", func() error { _, err := x.stepUp(t, up.SessionHash, up.UserID); return err })
	assert.Zero(t, x.count(t, `SELECT count(*) FROM sessions WHERE user_id = $1 AND revoked_at IS NULL`, up.UserID))
}

func TestPruneStates(t *testing.T) {
	x := newHarness(t)
	_, err := x.svc.Begin(x.ctx, oidc.BeginInput{ProviderID: x.prov.ID, Next: "/"})
	require.NoError(t, err)
	n, err := x.svc.PruneStates(x.ctx)
	require.NoError(t, err)
	assert.Zero(t, n, "a live state stays")
	x.clk.Advance(oidc.StateLifetime)
	n, err = x.svc.PruneStates(x.ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
}

// M-1 (O-11): the token endpoint answers but the key set cannot be read: a clear idp_unreachable, not login_invalid.
func TestJWKSUnreachableIsIdPUnreachable(t *testing.T) {
	x := newHarness(t)
	x.ready(t)
	_, err := x.d.Owner.Exec(x.ctx, `UPDATE oidc_providers SET jwks_uri = 'https://127.0.0.1:1/jwks' WHERE id = $1`, x.prov.ID)
	require.NoError(t, err)
	x.refused(t, "idp_unreachable", func() error { _, err := x.login(t, "/"); return err })
	x.idp.NextLogin(fakeidp.Login{Subject: "u1", Username: "ada", Groups: []string{"ops"}})
	x.refused(t, "idp_unreachable", func() error { _, err := x.login(t, "/"); return err }) // within the refetch minute
}

// Review L-8: the callback is public. A callback that names no stored state (none at all, a random or a replayed one)
// identifies no sign-in, so its refusals are audited at most once a minute per client address; any other refusal,
// and the first of a minute, still writes its row.
func TestUnknownStateRefusalsAreCoalescedPerAddress(t *testing.T) {
	x := newHarness(t)
	x.ready(t)
	denied := func() int {
		return x.count(t, `SELECT count(*) FROM audit_log WHERE action = 'auth.oidc.denied'`)
	}
	bogus := func(m auth.Meta, q url.Values) {
		t.Helper()
		_, err := x.svc.Complete(x.ctx, uuid.New(), q, "cookie", m)
		assert.Equal(t, "login_expired", reasonOf(err))
	}
	before := denied()
	bogus(meta, url.Values{"state": {"x"}})
	assert.Equal(t, before+1, denied(), "the first one of a minute is audited")
	for range 20 {
		bogus(meta, url.Values{"state": {uuid.NewString()}})
		bogus(meta, url.Values{})
	}
	assert.Equal(t, before+1, denied(), "the rest of the minute is not")
	other := meta
	other.IP = netip.MustParseAddr("198.51.100.7")
	bogus(other, url.Values{"state": {"x"}})
	assert.Equal(t, before+2, denied(), "another address has its own minute")
	x.clk.Advance(time.Minute)
	bogus(meta, url.Values{"state": {"x"}})
	assert.Equal(t, before+3, denied(), "the next minute is audited again")

	// A refusal of a real (stored) state is always audited.
	b, err := x.svc.Begin(x.ctx, oidc.BeginInput{ProviderID: x.prov.ID, Next: "/"})
	require.NoError(t, err)
	cb, err := x.idp.Authorize(b.AuthorizeURL)
	require.NoError(t, err)
	u, _ := url.Parse(cb)
	x.refused(t, "login_expired", func() error { _, err := x.svc.Complete(x.ctx, x.prov.ID, u.Query(), "other-browser", meta); return err })
}
