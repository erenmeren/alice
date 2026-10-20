package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/auth"
	"alice/internal/auth/ldap"
	"alice/internal/auth/ratelimit"
	"alice/internal/i18n"
	"alice/internal/platform/clock"
	"alice/internal/rbac"
	"alice/internal/secrets"
	"alice/locales"
)

var testDirectoryID = uuid.MustParse("0190f5a0-0000-7000-8000-0000000000d1")

// ldapDeps are testDeps with a fakeLDAP whose directory signs in "deniz" (MFA on), and an extra identity "ldap-user":
// a directory user's session of testDirectoryID.
func ldapDeps(t *testing.T) (Deps, *fakeLDAP, *fakeAuth) {
	t.Helper()
	d := testDeps(t, nil)
	fa := d.Auth.(*fakeAuth)
	base := fa.AuthenticateFn
	fa.AuthenticateFn = func(ctx context.Context, tok string) (auth.Principal, error) {
		if tok == "ldap-user" {
			return auth.Principal{Kind: rbac.UserSession, UserID: operatorID, Username: "deniz", Role: rbac.Operator, Locale: "en",
				SessionHash: []byte("ldap-user"), AuthSource: auth.AuthLDAP, LDAPDirectoryID: testDirectoryID, LDAPUniqueID: "0a0b",
				LDAPLogin: "deniz"}, nil
		}
		return base(ctx, tok)
	}
	fl := newFakeLDAP()
	dir := ldap.Directory{ID: testDirectoryID, Name: "Corp", MFARequired: true, Enabled: true, Version: 1}
	fl.VerifyFn = func(_ context.Context, id uuid.UUID, login string, password secrets.Plaintext) (ldap.Identity, ldap.Directory, error) {
		defer password.Zero()
		if login != "deniz" {
			return ldap.Identity{}, dir, &ldap.LoginError{Reason: ldap.ReasonBadCredentials, Detail: ldap.DetailNotFound}
		}
		if string(password.Bytes()) != "pw-1" {
			return ldap.Identity{UniqueID: "0a0b", Login: "deniz"}, dir, &ldap.LoginError{Reason: ldap.ReasonBadCredentials, Detail: ldap.DetailUserBind}
		}
		return ldap.Identity{UniqueID: "0a0b", Login: "deniz", Groups: []string{"ops"}}, dir, nil
	}
	fl.DirectoryFn = func(_ context.Context, id uuid.UUID) (ldap.Directory, error) {
		if id != testDirectoryID {
			return ldap.Directory{}, ldap.ErrNotFound
		}
		return dir, nil
	}
	fl.ResolveRoleFn = func(context.Context, uuid.UUID, []string) (rbac.Role, bool, error) { return rbac.Operator, true, nil }
	fl.TestSignInFn = func(_ context.Context, _ audit.Actor, _ uuid.UUID, _ string, password secrets.Plaintext) (ldap.TestResult, error) {
		defer password.Zero()
		return ldap.TestResult{Identity: ldap.Identity{Login: "deniz", Groups: []string{"ops"}}, Role: rbac.Operator}, nil
	}
	fl.CreateDirectoryFn = func(context.Context, audit.Actor, ldap.DirectoryInput) (ldap.Directory, error) { return dir, nil }
	fl.UpdateDirectoryFn = func(context.Context, audit.Actor, uuid.UUID, int, ldap.DirectoryPatch) (ldap.Directory, error) {
		return ldap.Directory{}, ldap.ErrVersion
	}
	fa.SignInLDAPFn = func(context.Context, auth.LDAPIdentity, rbac.Role, bool, auth.Meta) (auth.LoginResult, error) {
		return auth.LoginResult{Status: auth.StatusMFARequired, SessionToken: "pending-tok"}, nil
	}
	fa.StepUpLDAPFn = func(context.Context, auth.Principal, auth.LDAPIdentity, rbac.Role, string, bool, auth.Meta) (auth.SessionResult, error) {
		return auth.SessionResult{Token: "new-tok"}, nil
	}
	d.LDAP = fl
	return d, fl, fa
}

// Every path of the routes with a directory password or the service account password leaves the handler's copies and
// the body buffer zeroed: success, a refusal, a validation error, an unknown key.
func TestDirectoryPasswordsAreZeroedOnEveryPath(t *testing.T) {
	d, _, _ := ldapDeps(t)
	s := newServer(d)
	s.ldapRefusalFloor = 0 // the fake clock never moves here
	h := s.handler(s.apiRoutes())
	w := watchSecrets(t)
	login := "/api/v1/auth/ldap/" + testDirectoryID.String() + "/login"
	dirs := "/api/v1/ldap/directories"
	one := dirs + "/" + testDirectoryID.String()
	ifm := map[string]string{"If-Match": `"1"`}
	cases := []struct {
		name, method, path, id, body string
		hdr                          map[string]string
		status, slices               int
	}{
		{"sign-in ok", http.MethodPost, login, "", `{"username":"deniz","password":"pw-1"}`, nil, http.StatusOK, 1},
		{"sign-in wrong password", http.MethodPost, login, "", `{"username":"deniz","password":"pw-2"}`, nil, http.StatusUnauthorized, 1},
		{"sign-in unknown user", http.MethodPost, login, "", `{"username":"ghost","password":"pw-1"}`, nil, http.StatusUnauthorized, 1},
		{"sign-in name too long", http.MethodPost, login, "", `{"username":"` + strings.Repeat("a", 65) + `","password":"pw-1"}`, nil,
			http.StatusUnprocessableEntity, 1},
		{"sign-in unknown key", http.MethodPost, login, "", `{"username":"deniz","password":"pw-1","x":1}`, nil, http.StatusBadRequest, 0},
		{"step-up ok", http.MethodPost, "/api/v1/auth/ldap/stepup", "ldap-user", `{"password":"pw-1","code":"123456"}`, nil, http.StatusOK, 1},
		{"step-up wrong password", http.MethodPost, "/api/v1/auth/ldap/stepup", "ldap-user", `{"password":"pw-2"}`, nil, http.StatusUnauthorized, 1},
		{"step-up of a local user", http.MethodPost, "/api/v1/auth/ldap/stepup", "admin", `{"password":"pw-1"}`, nil, http.StatusConflict, 1},
		{"test sign-in", http.MethodPost, one + "/actions/test-signin", "admin-stepup", `{"username":"deniz","password":"pw-1"}`, nil, http.StatusOK, 1},
		{"create", http.MethodPost, dirs, "admin-stepup", `{"name":"Corp","bind_password":"bind-1"}`, nil, http.StatusCreated, 1},
		{"create, null name", http.MethodPost, dirs, "admin-stepup", `{"bind_password":"bind-1","name":null}`, nil, http.StatusBadRequest, 1},
		{"change refused", http.MethodPatch, one, "admin-stepup", `{"bind_password":"bind-1"}`, ifm, http.StatusPreconditionFailed, 1},
	}
	for _, c := range cases {
		s.ldapLockout.Reset()
		s.login.Reset()
		rec, body := callObserved(h, c.method, c.path, c.id, c.body, c.hdr)
		assert.Equal(t, c.status, rec.Code, "%s: %s", c.name, rec.Body.String())
		w.requireZeroed(t, c.name, c.slices)
		body.requireZeroed(t, c.name)
		assert.NotContains(t, rec.Body.String(), "pw-1", c.name)
		assert.NotContains(t, rec.Body.String(), "bind-1", c.name)
	}
}

// A refused sign-in waits on the server's clock until ldapRefusalFloor has passed, and no longer than the request.
func TestDirectoryRefusalIsHeldToTheFloor(t *testing.T) {
	d, _, _ := ldapDeps(t)
	clk := d.Clock.(*clock.Fake)
	h := New(d).Handler()
	login := "/api/v1/auth/ldap/" + testDirectoryID.String() + "/login"
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- call(h, http.MethodPost, login, "", `{"username":"ghost","password":"pw-1"}`) }()
	waitForTimer(t, clk, done)
	clk.Advance(ldapRefusalFloor - time.Millisecond)
	select {
	case <-done:
		t.Fatal("answered before the floor")
	case <-time.After(20 * time.Millisecond):
	}
	clk.Advance(time.Millisecond)
	var rec *httptest.ResponseRecorder
	select {
	case rec = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("not answered once the floor passed")
	}
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, "ALC-LDAP-0001", decodeErr(t, rec).Error.Code)

	// The wait ends with the request.
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, login, strings.NewReader(`{"username":"ghost","password":"pw-1"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://"+req.Host)
	go func() {
		r := httptest.NewRecorder()
		h.ServeHTTP(r, req)
		done <- r
	}()
	waitForTimer(t, clk, done) // the first wait's timer fired and is no longer pending
	cancel()
	select {
	case rec := <-done:
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	case <-time.After(5 * time.Second):
		t.Fatal("the wait did not end with the request")
	}
}

// waitForTimer waits (bounded) until the handler waits on clk; a handler that answers without waiting fails the test
// instead of hanging it.
func waitForTimer(t *testing.T, clk *clock.Fake, done <-chan *httptest.ResponseRecorder) {
	t.Helper()
	blocked := make(chan struct{})
	go func() { clk.BlockUntil(1, 0); close(blocked) }()
	select {
	case <-blocked:
	case rec := <-done:
		t.Fatalf("answered %d without waiting for the floor", rec.Code)
	case <-time.After(5 * time.Second):
		t.Fatal("the handler never waited on the clock")
	}
}

// A full lockout table is logged once per 10 minutes, without the key.
func TestDirectoryLockoutFullIsLoggedRarely(t *testing.T) {
	d := testDeps(t, nil)
	var logs syncLog
	d.Log = slog.New(slog.NewTextHandler(&logs, nil))
	s := newServer(d)
	s.ldapLockout = ratelimit.NewBoundedLockout(d.Clock, ldapLockoutFailures, ldapLockoutWindow, ldapLockoutFor, 1)
	s.ldapLockout.OnFull = func() { s.logLockoutFull("name") }
	r, ok, _ := s.ldapLockout.Reserve("held")
	require.True(t, ok)
	for range 3 {
		_, ok, _ = s.ldapLockout.Reserve("secret-name")
		assert.False(t, ok)
	}
	assert.Equal(t, 1, strings.Count(logs.String(), "lockout table is full"))
	assert.NotContains(t, logs.String(), "secret-name")
	d.Clock.(*clock.Fake).Advance(ldapFullLogEvery)
	_, _, _ = s.ldapLockout.Reserve("other")
	assert.Equal(t, 2, strings.Count(logs.String(), "lockout table is full"))
	r.Release()
	s.logLockoutFull("name") // within the interval again: not logged
	assert.Equal(t, 2, strings.Count(logs.String(), "lockout table is full"))
	s.logLockoutFull("account") // the other table has its own interval
	s.logLockoutFull("account")
	assert.Equal(t, 3, strings.Count(logs.String(), "lockout table is full"))
	assert.Equal(t, 1, strings.Count(logs.String(), "table=account"))
}

// syncLog is a log buffer safe for the handler's goroutines.
type syncLog struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *syncLog) Write(p []byte) (int, error) { l.mu.Lock(); defer l.mu.Unlock(); return l.b.Write(p) }
func (l *syncLog) String() string              { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

func TestDirectoryLoginKeyFoldsTheName(t *testing.T) {
	other := uuid.New()
	assert.Equal(t, ldapLoginKey(testDirectoryID, "deniz"), ldapLoginKey(testDirectoryID, "DENIZ"))
	assert.Equal(t, ldapLoginKey(testDirectoryID, "çağla"), ldapLoginKey(testDirectoryID, "ÇAĞLA"))
	assert.Equal(t, ldapLoginKey(testDirectoryID, "\u00e7a\u011fla"), ldapLoginKey(testDirectoryID, "c\u0327ag\u0306la"), "NFC and NFD share one budget")
	assert.Len(t, []rune(ldapLoginKey(testDirectoryID, strings.Repeat("ß", 256))), 36+1+256, "cut to 256 runes after folding")
	assert.Equal(t, ldapLoginKey(testDirectoryID, "deniz"), ldapLoginKey(testDirectoryID, "ｄｅｎｉｚ"), "full-width letters (NFKC)")
	assert.Equal(t, ldapLoginKey(testDirectoryID, "John Smith"), ldapLoginKey(testDirectoryID, "john \u00a0 smith"), "white space runs collapsed")
	assert.Equal(t, ldapLoginKey(testDirectoryID, "ﬁle"), ldapLoginKey(testDirectoryID, "FILE"), "a ligature folds and normalises")
	assert.Equal(t, ldapAccountKey(testDirectoryID, "0a0b"), testDirectoryID.String()+"\x00"+"0a0b")
	assert.NotEqual(t, ldapLoginKey(testDirectoryID, "deniz"), ldapLoginKey(other, "deniz"), "each directory has its own budget")
	assert.NotEqual(t, ldapLoginKey(testDirectoryID, "deniz"), ldapLoginKey(testDirectoryID, "deniz2"))
}

// Test sign-in goes through the sign-in's lockout with the same key: three failed tests lock the name (for the test and
// for the sign-in, answered 429 without contacting the directory); a test that gives a role clears the count, one
// that gives none does not.
func TestDirectoryTestSignInSharesTheLockout(t *testing.T) {
	d, fl, _ := ldapDeps(t)
	s := newServer(d)
	s.ldapRefusalFloor = 0
	h := s.handler(s.apiRoutes())
	test := "/api/v1/ldap/directories/" + testDirectoryID.String() + "/actions/test-signin"
	login := "/api/v1/auth/ldap/" + testDirectoryID.String() + "/login"
	calls, role := 0, rbac.Operator
	fl.TestSignInFn = func(_ context.Context, _ audit.Actor, _ uuid.UUID, _ string, password secrets.Plaintext) (ldap.TestResult, error) {
		defer password.Zero()
		calls++
		if string(password.Bytes()) != "pw-1" {
			return ldap.TestResult{}, &ldap.LoginError{Reason: ldap.ReasonBadCredentials, Detail: ldap.DetailUserBind}
		}
		return ldap.TestResult{Identity: ldap.Identity{UniqueID: "0a0b", Login: "deniz"}, Role: role}, nil
	}
	run := func(password string) int {
		s.actions[limitDirectoryTest].Reset() // the 5-a-minute test limit is not what this test is about
		return call(h, http.MethodPost, test, "admin-stepup", `{"username":"DENIZ","password":"`+password+`"}`).Code
	}
	for range 3 {
		assert.Equal(t, http.StatusUnprocessableEntity, run("pw-2"))
	}
	assert.Equal(t, 3, calls)
	assert.Equal(t, http.StatusTooManyRequests, run("pw-1"), "locked: the right password is not tested")
	assert.Equal(t, 3, calls, "the directory was not contacted")
	rec := call(h, http.MethodPost, login, "", `{"username":"deniz","password":"pw-1"}`)
	assert.Equal(t, http.StatusTooManyRequests, rec.Code, "the sign-in shares the key")

	s.ldapLockout.Reset()
	assert.Equal(t, http.StatusUnprocessableEntity, run("pw-2"))
	assert.Equal(t, http.StatusUnprocessableEntity, run("pw-2"))
	assert.Equal(t, http.StatusOK, run("pw-1"), "a test that gives a role clears the count")
	assert.Equal(t, http.StatusUnprocessableEntity, run("pw-2"))
	assert.Equal(t, http.StatusUnprocessableEntity, run("pw-2"))
	assert.Equal(t, http.StatusUnprocessableEntity, run("pw-2"), "the count started again after the success")
	assert.Equal(t, http.StatusTooManyRequests, run("pw-2"))

	s.ldapLockout.Reset()
	role = ""
	assert.Equal(t, http.StatusUnprocessableEntity, run("pw-2"))
	assert.Equal(t, http.StatusUnprocessableEntity, run("pw-2"))
	assert.Equal(t, http.StatusOK, run("pw-1"), "a test without a role")
	assert.Equal(t, http.StatusUnprocessableEntity, run("pw-2"), "did not clear the count: this is the third failure")
	assert.Equal(t, http.StatusTooManyRequests, run("pw-1"))
}

// The service and auth sentinels of the directory routes have their documented answers; none is a 500.
func TestDirectoryErrorsAreMapped(t *testing.T) {
	s := newServer(testDeps(t, nil))
	cases := []struct {
		err    error
		status int
		code   string
	}{
		{auth.ErrDirectoryUser, http.StatusConflict, "ALC-USR-0003"},
		{auth.ErrLDAPEnrolmentRequired, http.StatusConflict, "ALC-LDAP-0007"},
		{auth.ErrNotDirectoryUser, http.StatusConflict, "ALC-LDAP-0009"},
		{auth.ErrLDAPEmailInUse, http.StatusUnauthorized, "ALC-LDAP-0001"},
		{auth.ErrLDAPUserDisabled, http.StatusUnauthorized, "ALC-LDAP-0001"},
		{auth.ErrLDAPUserLocked, http.StatusUnauthorized, "ALC-LDAP-0001"},
		{auth.ErrLDAPOtherUser, http.StatusUnauthorized, "ALC-LDAP-0001"},
		{auth.ErrLDAPIdentityInvalid, http.StatusUnauthorized, "ALC-LDAP-0001"},
		{ldap.ErrAdminMappingDisabled, http.StatusConflict, "ALC-SSO-0002"},
		{ldap.ErrDirectoryInUse, http.StatusConflict, "ALC-LDAP-0003"},
		{ldap.ErrTooMany, http.StatusConflict, "ALC-LDAP-0005"},
		{ldap.ErrNotFound, http.StatusNotFound, "ALC-SYS-0001"},
		{ldap.ErrVersion, http.StatusPreconditionFailed, "ALC-SYS-0008"},
		{&ldap.LoginError{Reason: ldap.ReasonBadCredentials}, http.StatusUnauthorized, "ALC-LDAP-0001"},
		{&ldap.LoginError{Reason: ldap.ReasonAmbiguousUser}, http.StatusUnauthorized, "ALC-LDAP-0001"},
		{&ldap.LoginError{Reason: ldap.ReasonLoginInvalid}, http.StatusUnauthorized, "ALC-LDAP-0001"},
		{&ldap.LoginError{Reason: ldap.ReasonUnreachable}, http.StatusServiceUnavailable, "ALC-LDAP-0002"},
		{&ldap.LoginError{Reason: ldap.ReasonMisconfigured}, http.StatusServiceUnavailable, "ALC-LDAP-0002"},
		{&ldap.LoginError{Reason: ldap.ReasonDisabled}, http.StatusServiceUnavailable, "ALC-LDAP-0002"},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		s.fail(rec, httptest.NewRequest(http.MethodPost, "/api/v1/auth/ldap/stepup", nil), errors.Join(c.err))
		assert.Equal(t, c.status, rec.Code, "%v", c.err)
		assert.Equal(t, c.code, decodeErr(t, rec).Error.Code, "%v", c.err)
	}
	rec := httptest.NewRecorder()
	s.fail(rec, httptest.NewRequest(http.MethodPost, "/api/v1/ldap/directories", nil), ldap.ErrTooMany)
	assert.Contains(t, rec.Body.String(), `"params":{"max":"3"}`)
}

// The directory refusals that could tell something about a person are one answer; only a directory that says nothing
// about users has its own.
func TestDirectoryRefusalReasons(t *testing.T) {
	for _, c := range []struct {
		err    error
		reason string
		code   ErrorCode
	}{
		{errNoAccess, "no_access", ErrLDAPSignInRefused},
		{auth.ErrLDAPEmailInUse, "email_in_use", ErrLDAPSignInRefused},
		{auth.ErrLDAPUserDisabled, "user_disabled", ErrLDAPSignInRefused},
		{auth.ErrLDAPUserLocked, "locked", ErrLDAPSignInRefused},
		{auth.ErrLDAPIdentityInvalid, "identity_invalid", ErrLDAPSignInRefused},
		{auth.ErrLDAPOtherUser, "stepup_other_user", ErrLDAPSignInRefused},
		{auth.ErrLDAPDirectoryDisabled, "provider_disabled", ErrLDAPDirectoryUnavailable},
		{&ldap.LoginError{Reason: ldap.ReasonBadCredentials}, "bad_credentials", ErrLDAPSignInRefused},
		{&ldap.LoginError{Reason: ldap.ReasonUnreachable}, "directory_unreachable", ErrLDAPDirectoryUnavailable},
	} {
		reason, ec, ok := directoryRefusal(c.err)
		assert.True(t, ok, c.reason)
		assert.Equal(t, c.reason, reason)
		assert.Equal(t, c.code, ec, c.reason)
	}
	_, _, ok := directoryRefusal(errors.New("database down"))
	assert.False(t, ok, "not a refusal: fail answers it")
}

// ldapParams are the params the directory codes are answered with.
var ldapParams = map[string]map[string]string{
	"ALC-LDAP-0004": {"reason": "directory_unreachable", "detail": "timeout"},
	"ALC-LDAP-0005": {"max": "3"},
	"ALC-LDAP-0006": {"reason": "bad_credentials", "detail": "user_bind"},
}

// Every directory code has a section headed by its English title, with its HTTP status and reason, a cause and a
// remedy (the Phase 7 format); its texts render with the params it is answered with.
func TestLDAPCodesHaveTroubleshootingSections(t *testing.T) {
	doc, err := os.ReadFile("../../docs/troubleshooting.md")
	require.NoError(t, err)
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	var n int
	for _, ec := range AllErrorCodes() {
		if !strings.HasPrefix(ec.Code, "ALC-LDAP-") {
			continue
		}
		n++
		title := cat.T("en", "errors."+ec.Reason+".title", nil)
		assert.Contains(t, string(doc), "\n## "+ec.Code+": "+strings.TrimSuffix(title, ".")+"\n", ec.Code)
		assert.Regexp(t, regexp.MustCompile(`(?m)^## `+ec.Code+`: .+\n\n\*\*Meaning\.\*\* .*\(HTTP `+strconv.Itoa(ec.Status)+`, reason `+"`"+
			regexp.QuoteMeta(ec.Reason)+"`"), string(doc), ec.Code)
		section := troubleshootingSection(string(doc), ec.Code)
		assert.Regexp(t, `(?m)^\*\*Likely cause\.\*\* \S`, section, ec.Code)
		assert.Regexp(t, `(?m)^\*\*What to do\.\*\* \S`, section, ec.Code)
		for _, lang := range []string{"en", "tr"} {
			for _, part := range []string{"title", "cause", "action"} {
				assert.NotContains(t, cat.T(lang, "errors."+ec.Reason+"."+part, ldapParams[ec.Code]), "{{", "%s %s.%s", lang, ec.Reason, part)
			}
		}
	}
	assert.Equal(t, 9, n)
	// The reused codes name directory users too.
	for _, reason := range []string{"user.sso_user", "sso.admin_mapping_disabled", "sso.admin_mappings_exist"} {
		text := cat.T("en", "errors."+reason+".title", nil) + cat.T("en", "errors."+reason+".cause", nil)
		assert.Contains(t, text, "director", reason)
	}
}
