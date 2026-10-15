//go:build integration

package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/clock"
	"alice/internal/vconsole/vpgtest"
	"alice/internal/vconsole/webuser"
)

func TestMain(m *testing.M) { os.Exit(vpgtest.Main(m)) }

var loginSeq atomic.Int64

// uniqueLogin returns a database login name that no other test of this run uses (roles are cluster-wide).
func uniqueLogin(prefix string) string {
	return fmt.Sprintf("t_web_%s_%d", prefix, loginSeq.Add(1))
}

// testEnv is one web service over a fresh database, driven in-process.
type testEnv struct {
	t      *testing.T
	d      *vpgtest.DB
	owner  *pgxpool.Pool // a vendor_owner login: creates web users and codes
	web    *pgxpool.Pool // the vendor_web login the service uses
	srv    *Server
	h      http.Handler
	clk    *clock.Fake
	origin string
	host   string
	rp     virtualwebauthn.RelyingParty
}

func newEnv(t *testing.T, origin string) *testEnv {
	t.Helper()
	d := vpgtest.New(t)
	u, err := url.Parse(origin)
	require.NoError(t, err)
	e := &testEnv{
		t: t, d: d,
		owner:  d.As(t, "vendor_owner", uniqueLogin("owner")),
		web:    d.As(t, "vendor_web", uniqueLogin("web")),
		clk:    clock.NewFake(time.Now().UTC()),
		origin: origin, host: u.Host,
		rp: virtualwebauthn.RelyingParty{Name: "Alice licenses", ID: u.Hostname(), Origin: origin},
	}
	e.srv, err = New(Config{Pool: e.web, RPID: u.Hostname(), Origin: origin, Clock: e.clk})
	require.NoError(t, err)
	e.h = e.srv.Handler()
	return e
}

// do sends a same-origin request as a browser on the page would.
func (e *testEnv) do(method, path, body string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, e.origin+path, rd)
	r.Host = e.host
	if method != http.MethodGet {
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		r.Header.Set("Origin", e.origin)
		r.Header.Set("Content-Type", "application/json")
	}
	for _, c := range cookies {
		if c != nil {
			r.AddCookie(c)
		}
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	return w
}

func cookieNamed(w *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// addUser creates a sales web user through the owner login and returns a fresh enrollment code.
func (e *testEnv) addUser(name string) (int64, string) {
	e.t.Helper()
	return e.addUserRole(name, webuser.RoleSales)
}

// addUserRole is addUser with a role (webuser.RoleSales or webuser.RoleOwner).
func (e *testEnv) addUserRole(name, role string) (int64, string) {
	e.t.Helper()
	ctx := context.Background()
	id, err := webuser.AddUser(ctx, e.owner, name, role)
	require.NoError(e.t, err)
	code, err := webuser.NewEnrollment(ctx, e.owner, id, e.clk.Now(), 24*time.Hour)
	require.NoError(e.t, err)
	return id, code
}

// passkey is a software authenticator holding one credential.
type passkey struct {
	auth virtualwebauthn.Authenticator
	cred virtualwebauthn.Credential
}

// enroll runs the registration ceremony with code and returns the new passkey.
func (e *testEnv) enroll(code string) *passkey {
	e.t.Helper()
	w := e.do(http.MethodPost, "/webauthn/register/begin", `{"code":"`+code+`"}`)
	require.Equal(e.t, http.StatusOK, w.Code, w.Body.String())
	cer := cookieNamed(w, e.srv.ceremonyCookie)
	require.NotNil(e.t, cer)
	opts, err := virtualwebauthn.ParseAttestationOptions(w.Body.String())
	require.NoError(e.t, err)
	pk := &passkey{
		auth: virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{UserHandle: []byte(opts.UserID)}),
		cred: virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2),
	}
	att := virtualwebauthn.CreateAttestationResponse(e.rp, pk.auth, pk.cred, *opts)
	w = e.do(http.MethodPost, "/webauthn/register/finish", att, cer)
	require.Equal(e.t, http.StatusOK, w.Code, w.Body.String())
	pk.auth.AddCredential(pk.cred)
	return pk
}

// login runs the discoverable login ceremony and returns the finish response.
func (e *testEnv) login(pk *passkey) *httptest.ResponseRecorder {
	e.t.Helper()
	w := e.do(http.MethodPost, "/webauthn/login/begin", "")
	require.Equal(e.t, http.StatusOK, w.Code, w.Body.String())
	cer := cookieNamed(w, e.srv.ceremonyCookie)
	require.NotNil(e.t, cer)
	opts, err := virtualwebauthn.ParseAssertionOptions(w.Body.String())
	require.NoError(e.t, err)
	pk.cred.Counter++
	asr := virtualwebauthn.CreateAssertionResponse(e.rp, pk.auth, pk.cred, *opts)
	return e.do(http.MethodPost, "/webauthn/login/finish", asr, cer)
}

// signIn enrolls a new sales web user called name and returns its session cookie. The page tests use it.
func (e *testEnv) signIn(name string) *http.Cookie {
	e.t.Helper()
	return e.signInRole(name, webuser.RoleSales)
}

// signInRole is signIn with a role.
func (e *testEnv) signInRole(name, role string) *http.Cookie {
	e.t.Helper()
	_, code := e.addUserRole(name, role)
	w := e.login(e.enroll(code))
	require.Equal(e.t, http.StatusOK, w.Code, w.Body.String())
	c := cookieNamed(w, e.srv.cfg.CookieName)
	require.NotNil(e.t, c)
	return c
}

func TestEnrollThenLogin(t *testing.T) {
	e := newEnv(t, "https://licenses.example.test")
	ctx := context.Background()
	id, code := e.addUser("ayse")

	w := e.do(http.MethodGet, "/enroll", "")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `id="enroll-button"`)

	pk := e.enroll(code)
	creds, err := webuser.Credentials(ctx, e.owner, id)
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Equal(t, pk.cred.ID, creds[0].ID)

	w = e.login(pk)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.JSONEq(t, `{"redirect":"/"}`, w.Body.String())
	sess := cookieNamed(w, "__Host-vsession")
	require.NotNil(t, sess)
	assert.True(t, sess.HttpOnly)
	assert.True(t, sess.Secure)
	assert.Equal(t, http.SameSiteStrictMode, sess.SameSite)

	w = e.do(http.MethodGet, "/", "", sess)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "ayse")

	// The sign-in is audited, as the person (inActorTx), with the user as subject.
	var actor string
	require.NoError(t, e.d.Owner.QueryRow(ctx,
		`SELECT actor FROM audit WHERE action = 'web.login' AND subject = 'ayse'`).Scan(&actor))
	assert.Equal(t, "web:ayse", actor)

	// The sign counter was stored.
	creds, err = webuser.Credentials(ctx, e.owner, id)
	require.NoError(t, err)
	var stored struct {
		Authenticator struct {
			SignCount uint32 `json:"signCount"`
		} `json:"authenticator"`
	}
	require.NoError(t, json.Unmarshal(creds[0].JSON, &stored))
	assert.Equal(t, uint32(1), stored.Authenticator.SignCount)

	// A second login with the same passkey works and moves the counter on.
	w = e.login(pk)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

func TestEnrollmentCodeCannotBeReused(t *testing.T) {
	e := newEnv(t, "https://licenses.example.test")
	_, code := e.addUser("ayse")
	e.enroll(code)
	w := e.do(http.MethodPost, "/webauthn/register/begin", `{"code":"`+code+`"}`)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"error":"enrollment failed"}`, w.Body.String())
}

func TestFailedRegistrationDoesNotBurnTheCode(t *testing.T) {
	e := newEnv(t, "https://licenses.example.test")
	ctx := context.Background()
	id, code := e.addUser("ayse")

	w := e.do(http.MethodPost, "/webauthn/register/begin", `{"code":"`+code+`"}`)
	require.Equal(t, http.StatusOK, w.Code)
	cer := cookieNamed(w, e.srv.ceremonyCookie)
	opts, err := virtualwebauthn.ParseAttestationOptions(w.Body.String())
	require.NoError(t, err)
	// An attestation for the wrong origin fails verification.
	bad := virtualwebauthn.RelyingParty{Name: e.rp.Name, ID: e.rp.ID, Origin: "https://evil.example"}
	att := virtualwebauthn.CreateAttestationResponse(bad, virtualwebauthn.NewAuthenticator(), virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2), *opts)
	w = e.do(http.MethodPost, "/webauthn/register/finish", att, cer)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"error":"enrollment failed"}`, w.Body.String())

	creds, err := webuser.Credentials(ctx, e.owner, id)
	require.NoError(t, err)
	assert.Empty(t, creds)
	e.enroll(code) // the code still works
}

func TestRegisterFinishWithoutBeginIsRefused(t *testing.T) {
	e := newEnv(t, "https://licenses.example.test")
	_, code := e.addUser("ayse")
	// Use a real begin only to have valid-looking options; then finish without the ceremony cookie.
	w := e.do(http.MethodPost, "/webauthn/register/begin", `{"code":"`+code+`"}`)
	require.Equal(t, http.StatusOK, w.Code)
	opts, err := virtualwebauthn.ParseAttestationOptions(w.Body.String())
	require.NoError(t, err)
	att := virtualwebauthn.CreateAttestationResponse(e.rp, virtualwebauthn.NewAuthenticator(), virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2), *opts)
	for _, cer := range []*http.Cookie{nil, {Name: e.srv.ceremonyCookie, Value: "forged"}} {
		w = e.do(http.MethodPost, "/webauthn/register/finish", att, cer)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.JSONEq(t, `{"error":"enrollment failed"}`, w.Body.String())
	}
	// Garbage with a real ceremony.
	w = e.do(http.MethodPost, "/webauthn/register/begin", `{"code":"`+code+`"}`)
	cer := cookieNamed(w, e.srv.ceremonyCookie)
	w = e.do(http.MethodPost, "/webauthn/register/finish", `{"id":"x"}`, cer)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"error":"enrollment failed"}`, w.Body.String())
	// Bad JSON to begin.
	w = e.do(http.MethodPost, "/webauthn/register/begin", `not json`)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"error":"enrollment failed"}`, w.Body.String())
}

func TestLoginFinishWithUnknownCredential(t *testing.T) {
	e := newEnv(t, "https://licenses.example.test")
	id, _ := e.addUser("ayse")
	// A passkey the server never registered, claiming to be ayse.
	pk := &passkey{
		auth: virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{UserHandle: userHandle(id)}),
		cred: virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2),
	}
	w := e.login(pk)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"error":"login failed"}`, w.Body.String())
	assert.Nil(t, cookieNamed(w, e.srv.cfg.CookieName))

	// Finish without begin.
	w = e.do(http.MethodPost, "/webauthn/login/finish", `{"id":"x"}`)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"error":"login failed"}`, w.Body.String())
}

func TestLoginWithAnotherUsersHandleFails(t *testing.T) {
	e := newEnv(t, "https://licenses.example.test")
	_, code := e.addUser("ayse")
	mehmetID, _ := e.addUser("mehmet")
	pk := e.enroll(code)
	pk.auth.Options.UserHandle = userHandle(mehmetID) // ayse's key, mehmet's handle
	w := e.login(pk)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"error":"login failed"}`, w.Body.String())
}

func TestCeremonyIsSingleUse(t *testing.T) {
	e := newEnv(t, "https://licenses.example.test")
	_, code := e.addUser("ayse")
	pk := e.enroll(code)
	w := e.do(http.MethodPost, "/webauthn/login/begin", "")
	cer := cookieNamed(w, e.srv.ceremonyCookie)
	opts, err := virtualwebauthn.ParseAssertionOptions(w.Body.String())
	require.NoError(t, err)
	pk.cred.Counter++
	asr := virtualwebauthn.CreateAssertionResponse(e.rp, pk.auth, pk.cred, *opts)
	require.Equal(t, http.StatusOK, e.do(http.MethodPost, "/webauthn/login/finish", asr, cer).Code)
	w = e.do(http.MethodPost, "/webauthn/login/finish", asr, cer)
	assert.Equal(t, http.StatusBadRequest, w.Code, "replayed assertion")
}

func TestCeremonyExpiresAfterFiveMinutes(t *testing.T) {
	e := newEnv(t, "https://licenses.example.test")
	_, code := e.addUser("ayse")
	pk := e.enroll(code)
	w := e.do(http.MethodPost, "/webauthn/login/begin", "")
	cer := cookieNamed(w, e.srv.ceremonyCookie)
	opts, err := virtualwebauthn.ParseAssertionOptions(w.Body.String())
	require.NoError(t, err)
	e.clk.Advance(5*time.Minute + time.Second)
	pk.cred.Counter++
	asr := virtualwebauthn.CreateAssertionResponse(e.rp, pk.auth, pk.cred, *opts)
	assert.Equal(t, http.StatusBadRequest, e.do(http.MethodPost, "/webauthn/login/finish", asr, cer).Code)
}

func TestDisabledUserCannotLogIn(t *testing.T) {
	e := newEnv(t, "https://licenses.example.test")
	ctx := context.Background()
	_, code := e.addUser("ayse")
	pk := e.enroll(code)
	w := e.login(pk)
	require.Equal(t, http.StatusOK, w.Code)
	sess := cookieNamed(w, e.srv.cfg.CookieName)

	require.NoError(t, webuser.SetDisabled(ctx, e.owner, "ayse", true, e.clk.Now()))
	w = e.login(pk)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"error":"login failed"}`, w.Body.String())
	assert.Nil(t, cookieNamed(w, e.srv.cfg.CookieName))
	var n int
	require.NoError(t, e.d.Owner.QueryRow(ctx, `SELECT count(*) FROM web_sessions`).Scan(&n))
	assert.Zero(t, n, "no session was created for the disabled user")

	// The session from before the disable no longer works.
	w = e.do(http.MethodGet, "/", "", sess)
	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/login", w.Header().Get("Location"))
}

func TestLogoutEndsTheSession(t *testing.T) {
	e := newEnv(t, "https://licenses.example.test")
	sess := e.signIn("ayse")
	require.Equal(t, http.StatusOK, e.do(http.MethodGet, "/", "", sess).Code)

	w := e.do(http.MethodPost, "/logout", "", sess)
	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/login", w.Header().Get("Location"))
	cleared := cookieNamed(w, e.srv.cfg.CookieName)
	require.NotNil(t, cleared)
	assert.Empty(t, cleared.Value)
	assert.Less(t, cleared.MaxAge, 0)

	w = e.do(http.MethodGet, "/", "", sess)
	assert.Equal(t, http.StatusSeeOther, w.Code, "the old token no longer works")
}

func TestSessionCookieAttributes(t *testing.T) {
	e := newEnv(t, "https://licenses.example.test")
	_, code := e.addUser("ayse")
	w := e.login(e.enroll(code))
	require.Equal(t, http.StatusOK, w.Code)
	var raw string
	for _, v := range w.Result().Header.Values("Set-Cookie") {
		if strings.HasPrefix(v, "__Host-vsession=") {
			raw = v
		}
	}
	require.NotEmpty(t, raw)
	assert.Contains(t, raw, "Path=/")
	assert.NotContains(t, raw, "Domain=")
	assert.Contains(t, raw, "HttpOnly")
	assert.Contains(t, raw, "Secure")
	assert.Contains(t, raw, "SameSite=Strict")
	assert.Contains(t, raw, fmt.Sprintf("Max-Age=%d", int(webuser.SessionAbsolute.Seconds())))

	// Over plain http on localhost: no __Host- prefix and no Secure (browsers would drop it on http).
	l := newEnv(t, "http://localhost:8443")
	_, code = l.addUser("ayse")
	w = l.login(l.enroll(code))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	c := cookieNamed(w, "vsession")
	require.NotNil(t, c)
	assert.True(t, c.HttpOnly)
	assert.False(t, c.Secure)
	assert.Equal(t, http.SameSiteStrictMode, c.SameSite)

	// The ceremony cookie is HttpOnly, Strict, Secure over https.
	w = e.do(http.MethodPost, "/webauthn/login/begin", "")
	cer := cookieNamed(w, e.srv.ceremonyCookie)
	require.NotNil(t, cer)
	assert.True(t, cer.HttpOnly)
	assert.True(t, cer.Secure)
	assert.Equal(t, http.SameSiteStrictMode, cer.SameSite)
}

func TestSessionIdleAndAbsoluteExpiry(t *testing.T) {
	e := newEnv(t, "https://licenses.example.test")
	sess := e.signIn("ayse")
	e.clk.Advance(webuser.SessionIdle + time.Second)
	assert.Equal(t, http.StatusSeeOther, e.do(http.MethodGet, "/", "", sess).Code, "idle")

	sess = e.signIn("mehmet")
	for range 17 { // 17 x 29 min > 8 h, never idle for 30 minutes
		e.clk.Advance(29 * time.Minute)
		if e.do(http.MethodGet, "/", "", sess).Code != http.StatusOK {
			break
		}
	}
	assert.Equal(t, http.StatusSeeOther, e.do(http.MethodGet, "/", "", sess).Code, "absolute")
	// A forged cookie is treated as signed out.
	assert.Equal(t, http.StatusSeeOther, e.do(http.MethodGet, "/", "", &http.Cookie{Name: e.srv.cfg.CookieName, Value: "forged"}).Code)
}

func TestInActorTxActsAsTheSignedInPerson(t *testing.T) {
	e := newEnv(t, "https://licenses.example.test")
	ctx := context.Background()
	id, _ := e.addUser("ayse")
	u := webuser.User{ID: id, Name: "ayse"}
	require.NoError(t, e.srv.inActorTx(ctx, u, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO customers (name) VALUES ('Acme')`)
		return err
	}))
	var createdBy string
	require.NoError(t, e.d.Owner.QueryRow(ctx, `SELECT created_by FROM customers WHERE name = 'Acme'`).Scan(&createdBy))
	assert.Equal(t, "web:ayse", createdBy)
	var actor string
	require.NoError(t, e.d.Owner.QueryRow(ctx,
		`SELECT actor FROM audit WHERE action LIKE 'customer%' ORDER BY seq DESC LIMIT 1`).Scan(&actor))
	assert.Equal(t, "web:ayse", actor)

	// The setting is local to the transaction: outside it the service is itself.
	var self string
	require.NoError(t, e.web.QueryRow(ctx, `SELECT vendor_actor()`).Scan(&self))
	assert.NotEqual(t, "web:ayse", self)

	// An error from fn rolls back.
	err := e.srv.inActorTx(ctx, u, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO customers (name) VALUES ('Rolled')`); err != nil {
			return err
		}
		return fmt.Errorf("stop")
	})
	require.Error(t, err)
	var n int
	require.NoError(t, e.d.Owner.QueryRow(ctx, `SELECT count(*) FROM customers WHERE name = 'Rolled'`).Scan(&n))
	assert.Zero(t, n)
}
