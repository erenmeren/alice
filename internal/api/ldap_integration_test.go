//go:build integration

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/auth/ldap"
	"alice/internal/auth/ratelimit"
	"alice/internal/platform/clock"
	"alice/internal/secrets"
)

// Directory sign-in over the wire (Task 5): the real ldap.Service and auth.Service behind the HTTP stack, with a fake
// directory as the service's client (ldap.Config.NewClient), so no network is used. The fake answers like a directory:
// an unknown name, a wrong password (with the entry), several entries, an unreachable directory.

// Canaries: the people's directory password and the service account password must never appear in an answer, a
// header, an audit row or a log line.
const (
	dirUserPassword = "CANARY-ldap-user-pass-7d1f2c"
	dirBindPassword = "CANARY-ldap-bind-pass-3a9c51"
	dirOperators    = "alice-operators"
)

type fakeDirUser struct {
	login, password, uid, name, email string
	alias                             string // a second sign-in name of the same entry (a UPN beside the sAMAccountName)
	groups                            []string
}

// fakeDirectory is an ldap.Client (and ldap.ConnectionChecker) over a table of people.
type fakeDirectory struct {
	clk *clock.Fake

	mu        sync.Mutex
	users     []fakeDirUser
	down      bool          // every connection fails as unreachable
	slow      time.Duration // each Authenticate moves the clock this much (a slow directory)
	authCalls int           // Authenticate calls: traffic to the directory
	userBinds int           // binds with a user's password to an entry the search found
	binds     []string      // the service account passwords the client was handed
	hold      chan struct{} // when set, Authenticate waits for it to close (or the request to end) before answering
	panicNext bool          // the next Authenticate panics
}

var (
	_ ldap.Client            = (*fakeDirectory)(nil)
	_ ldap.ConnectionChecker = (*fakeDirectory)(nil)
)

func newFakeDirectory(clk *clock.Fake) *fakeDirectory { return &fakeDirectory{clk: clk} }

func (f *fakeDirectory) add(u fakeDirUser) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.users = append(f.users, u)
}

func (f *fakeDirectory) set(fn func(f *fakeDirectory)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

func (f *fakeDirectory) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.authCalls
}

func (f *fakeDirectory) userBindCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.userBinds
}

// find matches the sign-in name as a directory does: case-insensitively. The caller holds f.mu.
func (f *fakeDirectory) find(login string) []fakeDirUser {
	var out []fakeDirUser
	for _, u := range f.users {
		if strings.EqualFold(u.login, login) || (u.alias != "" && strings.EqualFold(u.alias, login)) {
			out = append(out, u)
		}
	}
	return out
}

func dirEntry(d ldap.Directory, u fakeDirUser) ldap.Entry {
	attrs := map[string][][]byte{d.UniqueIDAttribute: {[]byte(u.uid)}, d.LoginAttribute: {[]byte(u.login)}}
	if d.DisplayNameAttribute != "" && u.name != "" {
		attrs[d.DisplayNameAttribute] = [][]byte{[]byte(u.name)}
	}
	if d.EmailAttribute != "" && u.email != "" {
		attrs[d.EmailAttribute] = [][]byte{[]byte(u.email)}
	}
	return ldap.Entry{DN: "uid=" + u.login + "," + d.UserBaseDN, Attrs: attrs}
}

func (f *fakeDirectory) Authenticate(ctx context.Context, d ldap.Directory, bind secrets.Plaintext, login string, password secrets.Plaintext) (ldap.Entry, error) {
	f.mu.Lock()
	f.authCalls++
	hold, boom := f.hold, f.panicNext
	f.panicNext = false
	f.mu.Unlock()
	if boom {
		panic("fake directory: panic in Authenticate")
	}
	if hold != nil {
		select {
		case <-hold:
		case <-ctx.Done():
			return ldap.Entry{}, &ldap.LoginError{Reason: ldap.ReasonUnreachable, Detail: ldap.DetailTimeout}
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.binds = append(f.binds, string(bind.Bytes()))
	if f.slow > 0 {
		f.clk.Advance(f.slow)
	}
	if f.down {
		return ldap.Entry{}, &ldap.LoginError{Reason: ldap.ReasonUnreachable, Detail: ldap.DetailConnect}
	}
	found := f.find(login)
	switch {
	case len(found) == 0:
		return ldap.Entry{}, &ldap.LoginError{Reason: ldap.ReasonBadCredentials, Detail: ldap.DetailNotFound}
	case len(found) > 1:
		return ldap.Entry{}, &ldap.LoginError{Reason: ldap.ReasonAmbiguousUser, Detail: ldap.DetailUserSearch}
	}
	e := dirEntry(d, found[0])
	if err := ldap.RunGate(ctx, e); err != nil {
		return e, err
	}
	f.userBinds++
	if string(password.Bytes()) != found[0].password {
		return e, &ldap.LoginError{Reason: ldap.ReasonBadCredentials, Detail: ldap.DetailUserBind}
	}
	return e, nil
}

func (f *fakeDirectory) Groups(_ context.Context, _ ldap.Directory, _ secrets.Plaintext, _ ldap.Entry, login string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if found := f.find(login); len(found) == 1 {
		return append([]string{}, found[0].groups...), nil
	}
	return nil, &ldap.LoginError{Reason: ldap.ReasonMisconfigured, Detail: ldap.DetailGroupSearch}
}

func (f *fakeDirectory) CheckConnection(_ context.Context, _ ldap.Directory, bind secrets.Plaintext) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.binds = append(f.binds, string(bind.Bytes()))
	if f.down {
		return &ldap.LoginError{Reason: ldap.ReasonUnreachable, Detail: ldap.DetailTimeout}
	}
	return nil
}

// directoryBodyFor is a valid directory for the fake (OpenLDAP-style attribute names).
func directoryBodyFor(name string, mfa, enabled bool) map[string]any {
	return map[string]any{"name": name, "addresses": []string{"ldaps://ldap.corp.example:636"},
		"user_base_dn": "ou=people,dc=corp,dc=example", "user_filter": "(uid={login})", "login_attribute": "uid",
		"unique_id_attribute": "entryUUID", "display_name_attribute": "cn", "email_attribute": "mail",
		"bind_dn": "cn=alice,ou=services,dc=corp,dc=example", "bind_password": dirBindPassword,
		"group_base_dn": "ou=groups,dc=corp,dc=example", "group_name_attribute": "cn", "mfa_required": mfa, "enabled": enabled}
}

// directoryReady adds an enabled directory through the API, maps alice-operators to Operator and fills the fake
// directory with its people. It returns the directory's ID.
func (s *stack) directoryReady(t *testing.T, admin *client, adminAcct *account, mfa bool) string {
	t.Helper()
	s.stepUp(admin, adminAcct)
	rec := admin.do(http.MethodPost, "/api/v1/ldap/directories", directoryBodyFor("Corp LDAP", mfa, true))
	requireStatus(t, rec, http.StatusCreated)
	id := decodeBody[directoryDTO](t, rec).ID.String()
	requireStatus(t, admin.do(http.MethodPost, "/api/v1/ldap/group-mappings",
		map[string]string{"directory_id": id, "group": dirOperators, "role": "operator"}), http.StatusCreated)
	for _, u := range []fakeDirUser{
		{login: "deniz", alias: "deniz@corp.example", uid: "6f1c5b7e-0d3a-4c1e-9a55-000000000001", name: "Deniz Yılmaz", email: "deniz@corp.example",
			groups: []string{dirOperators}},
		{login: "John Smith", uid: "6f1c5b7e-0d3a-4c1e-9a55-000000000009", name: "John Smith", groups: []string{dirOperators}},
		{login: "berk", uid: "6f1c5b7e-0d3a-4c1e-9a55-000000000002", name: "Berk Kaya", email: "berk@corp.example", groups: []string{dirOperators}},
		{login: "selin", uid: "6f1c5b7e-0d3a-4c1e-9a55-000000000003", name: "Selin", groups: []string{dirOperators}},
		{login: "ayse", uid: "6f1c5b7e-0d3a-4c1e-9a55-000000000004", name: "Ayşe", email: "ayse@corp.example", groups: []string{dirOperators}},
		{login: "nogroup", uid: "6f1c5b7e-0d3a-4c1e-9a55-000000000005", name: "No Group", groups: []string{"cn=other"}},
		{login: "Çağla", uid: "6f1c5b7e-0d3a-4c1e-9a55-000000000008", name: "Çağla Demir", groups: []string{dirOperators}},
		{login: "dup", uid: "6f1c5b7e-0d3a-4c1e-9a55-000000000006"},
		{login: "dup", uid: "6f1c5b7e-0d3a-4c1e-9a55-000000000007"},
	} {
		u.password = dirUserPassword
		s.dir.add(u)
	}
	return id
}

// timedDo sends a request that may wait on the stack's clock (a refused directory sign-in is held to ldapRefusalFloor):
// while it has not answered, the clock moves to the next timer. It returns the answer and how far the clock moved.
func (s *stack) timedDo(c *client, method, path string, body any) (*httptest.ResponseRecorder, time.Duration) {
	start := s.clock.Now()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- c.do(method, path, body) }()
	for {
		select {
		case rec := <-done:
			return rec, s.clock.Now().Sub(start)
		case <-time.After(2 * time.Millisecond):
			s.clock.AdvanceToNextTimer()
		}
	}
}

func (s *stack) dirLogin(c *client, dir, username, password string) (*httptest.ResponseRecorder, time.Duration) {
	return s.timedDo(c, http.MethodPost, "/api/v1/auth/ldap/"+dir+"/login", map[string]string{"username": username, "password": password})
}

// lastDenial is the reason and the recorded sign-in name of the newest auth.ldap.denied row.
func (s *stack) lastDenial(t *testing.T) (reason, login, actorType string) {
	t.Helper()
	require.NoError(t, s.db.Owner.QueryRow(context.Background(), `SELECT details->>'reason', coalesce(details->>'login_name', ''), actor_type
FROM audit_log WHERE action = 'auth.ldap.denied' ORDER BY seq DESC LIMIT 1`).Scan(&reason, &login, &actorType))
	return reason, login, actorType
}

// normalized is an answer without its per-request ID: the body with the ID replaced and the headers without it.
func normalized(rec *httptest.ResponseRecorder) (int, string, http.Header) {
	id := rec.Header().Get("X-Request-Id")
	h := rec.Header().Clone()
	h.Del("X-Request-Id")
	return rec.Code, strings.ReplaceAll(rec.Body.String(), id, "RID"), h
}

// enrolDirectoryUser finishes a first sign-in that asked for enrolment and returns the account (TOTP secret set).
func (s *stack) enrolDirectoryUser(t *testing.T, c *client, username string) *account {
	t.Helper()
	rec := c.do(http.MethodPost, "/api/v1/auth/mfa/enroll", nil)
	requireStatus(t, rec, http.StatusOK)
	a := &account{username: username, password: dirUserPassword, secret: decodeBody[enrollmentBody](t, rec).Secret}
	rec = c.do(http.MethodPost, "/api/v1/auth/mfa/verify", map[string]string{"code": s.totpNow(a.secret)})
	requireStatus(t, rec, http.StatusOK)
	a.id = decodeBody[sessionBody](t, rec).User.ID
	return a
}

type sessionUserBody struct {
	User struct {
		Username        string  `json:"username"`
		Role            string  `json:"role"`
		AuthSource      string  `json:"auth_source"`
		LDAPDirectoryID *string `json:"ldap_directory_id"`
		SSOProviderID   *string `json:"sso_provider_id"`
	} `json:"user"`
	StepUpUntil *time.Time `json:"stepup_until"`
}

func TestDirectorySignInOverTheWire(t *testing.T) {
	s, admin, adminAcct := installed(t)
	dir := s.directoryReady(t, admin, adminAcct, true)

	// The admin answers never carry the service account password; a switched-off directory is not on the sign-in page.
	rec := admin.do(http.MethodGet, "/api/v1/ldap/directories/"+dir, nil)
	requireStatus(t, rec, http.StatusOK)
	assert.Equal(t, `"1"`, rec.Header().Get("ETag"))
	got := decodeBody[directoryDTO](t, rec)
	assert.True(t, got.BindPasswordSet)
	assert.True(t, got.MFARequired)
	requireStatus(t, admin.do(http.MethodPost, "/api/v1/ldap/directories", directoryBodyFor("Branch LDAP", true, false)), http.StatusCreated)
	rec = s.freshClient().do(http.MethodGet, "/api/v1/auth/ldap/directories", nil)
	requireStatus(t, rec, http.StatusOK)
	assert.JSONEq(t, `{"items":[{"id":"`+dir+`","name":"Corp LDAP"}]}`, rec.Body.String(), "enabled directories only, no address")

	// MFA on: the first sign-in asks for enrolment with a pending session; enroll and verify finish it.
	browser := s.freshClient()
	before := s.dir.calls()
	rec, took := s.dirLogin(browser, dir, "deniz", dirUserPassword)
	requireStatus(t, rec, http.StatusOK)
	assert.Zero(t, took, "a successful sign-in is never held")
	assert.Equal(t, before+1, s.dir.calls())
	body := decodeBody[map[string]string](t, rec)
	assert.Equal(t, "mfa_enrollment_required", body["status"])
	assert.NotEmpty(t, body["csrf_token"])
	assert.NotEmpty(t, setCookies(t, rec)[sessionCookie].Value, "the pending session cookie")
	deniz := s.enrolDirectoryUser(t, browser, "deniz")
	rec = browser.do(http.MethodGet, "/api/v1/auth/session", nil)
	requireStatus(t, rec, http.StatusOK)
	sess := decodeBody[sessionUserBody](t, rec)
	assert.Equal(t, "deniz", sess.User.Username)
	assert.Equal(t, "operator", sess.User.Role)
	assert.Equal(t, "ldap", sess.User.AuthSource)
	require.NotNil(t, sess.User.LDAPDirectoryID)
	assert.Equal(t, dir, *sess.User.LDAPDirectoryID)
	assert.Nil(t, sess.User.SSOProviderID)

	// The second sign-in asks for the code.
	s.clock.Advance(31 * time.Second)
	browser = s.freshClient()
	rec, _ = s.dirLogin(browser, dir, "DENIZ", dirUserPassword)
	requireStatus(t, rec, http.StatusOK)
	assert.Equal(t, "mfa_required", decodeBody[map[string]string](t, rec)["status"])
	requireStatus(t, browser.do(http.MethodPost, "/api/v1/auth/mfa/verify", map[string]string{"code": s.totpNow(deniz.secret)}), http.StatusOK)

	// People & access shows the source and the directory.
	s.stepUp(admin, adminAcct)
	rec = admin.do(http.MethodGet, "/api/v1/users/"+deniz.id, nil)
	requireStatus(t, rec, http.StatusOK)
	assert.Contains(t, rec.Body.String(), `"auth_source":"ldap"`)
	assert.Contains(t, rec.Body.String(), `"ldap_directory_id":"`+dir+`"`)

	// MFA off (If-Match): a full session at once, and the step-up needs the password only.
	rec = admin.do(http.MethodGet, "/api/v1/ldap/directories/"+dir, nil)
	requireStatus(t, admin.do(http.MethodPatch, "/api/v1/ldap/directories/"+dir, map[string]any{"mfa_required": false},
		ifMatchOf(etagVersion(t, rec))), http.StatusOK)
	browser = s.freshClient()
	rec, _ = s.dirLogin(browser, dir, "berk", dirUserPassword)
	requireStatus(t, rec, http.StatusOK)
	assert.Equal(t, "signed_in", decodeBody[map[string]string](t, rec)["status"])
	rec = browser.do(http.MethodGet, "/api/v1/auth/session", nil)
	requireStatus(t, rec, http.StatusOK)
	assert.Equal(t, "berk", decodeBody[sessionUserBody](t, rec).User.Username)
	assert.Equal(t, 1, s.countWhere("audit_log", "action = 'auth.login' AND details->>'method' = 'ldap'"))
	rec = browser.do(http.MethodPost, "/api/v1/auth/ldap/stepup", map[string]string{"password": dirUserPassword})
	requireStatus(t, rec, http.StatusOK)
	assert.NotNil(t, decodeBody[sessionUserBody](t, rec).StepUpUntil)

	s.requireNoDirectoryCanary(t)
}

func TestDirectorySignInRefusalsLookTheSame(t *testing.T) {
	s, admin, adminAcct := installed(t)
	dir := s.directoryReady(t, admin, adminAcct, true)

	// Setup for two refusals: selin exists and is then disabled; a local user holds ayşe's e-mail address.
	rec, _ := s.dirLogin(s.freshClient(), dir, "selin", dirUserPassword)
	requireStatus(t, rec, http.StatusOK)
	s.stepUp(admin, adminAcct)
	requireStatus(t, admin.do(http.MethodPatch, "/api/v1/users/"+s.userID("selin"), map[string]any{"disabled": true}), http.StatusOK)
	requireStatus(t, admin.do(http.MethodPost, "/api/v1/users", map[string]string{"username": "lale", "display_name": "Lale",
		"email": "ayse@corp.example", "role": "auditor", "password": operatorPassword}), http.StatusCreated)

	type tc struct{ name, user, password, reason, login, actor string }
	cases := []tc{
		{"unknown user", "ghost", dirUserPassword, "bad_credentials", "", "system"},
		{"wrong password", "deniz", "not-her-password", "bad_credentials", "deniz", "system"},
		{"no mapped group", "nogroup", dirUserPassword, "no_access", "nogroup", "system"},
		{"disabled user", "selin", dirUserPassword, "user_disabled", "selin", "user"},
		{"e-mail of a local user", "ayse", dirUserPassword, "email_in_use", "ayse", "system"},
		{"several entries", "dup", dirUserPassword, "ambiguous_user", "dup", "system"},
		{"name that cannot be sent", "bad\tname", dirUserPassword, "login_invalid", "", "system"},
		{"empty password", "deniz", "", "bad_credentials", "", "system"},
	}
	var first *httptest.ResponseRecorder
	for _, c := range cases {
		rec, took := s.dirLogin(s.freshClient(), dir, c.user, c.password)
		requireError(t, rec, http.StatusUnauthorized, "ALC-LDAP-0001")
		assert.Equal(t, ldapRefusalFloor, took, "%s: held to the floor", c.name)
		assert.Empty(t, setCookies(t, rec)[sessionCookie], "%s: no session", c.name)
		if first == nil {
			first = rec
		} else {
			code1, body1, h1 := normalized(first)
			code2, body2, h2 := normalized(rec)
			assert.Equal(t, code1, code2, c.name)
			assert.Equal(t, body1, body2, "%s: the same body", c.name)
			assert.Equal(t, h1, h2, "%s: the same headers", c.name)
		}
		reason, login, actor := s.lastDenial(t)
		assert.Equal(t, c.reason, reason, c.name)
		assert.Equal(t, c.login, login, "%s: the name is recorded only for a resolved entry", c.name)
		assert.Equal(t, c.actor, actor, c.name)
	}
	assert.Equal(t, len(cases), s.countWhere("audit_log", "action = 'auth.ldap.denied'"))

	// A slow directory is not held further than it took.
	s.dir.set(func(f *fakeDirectory) { f.slow = 2 * time.Second })
	rec, took := s.dirLogin(s.freshClient(), dir, "ghost", dirUserPassword)
	requireError(t, rec, http.StatusUnauthorized, "ALC-LDAP-0001")
	assert.Equal(t, 2*time.Second, took)
	s.dir.set(func(f *fakeDirectory) { f.slow = 0 })

	// What says nothing about users has its own answer: an unreachable, switched-off or unknown directory (503).
	s.dir.set(func(f *fakeDirectory) { f.down = true })
	rec, took = s.dirLogin(s.freshClient(), dir, "deniz", dirUserPassword)
	requireError(t, rec, http.StatusServiceUnavailable, "ALC-LDAP-0002")
	assert.Equal(t, ldapRefusalFloor, took)
	assert.NotContains(t, rec.Body.String(), "deniz")
	reason, login, _ := s.lastDenial(t)
	assert.Equal(t, [2]string{"directory_unreachable", ""}, [2]string{reason, login})
	s.dir.set(func(f *fakeDirectory) { f.down = false })
	s.stepUp(admin, adminAcct)
	rec = admin.do(http.MethodGet, "/api/v1/ldap/directories/"+dir, nil)
	requireStatus(t, admin.do(http.MethodPatch, "/api/v1/ldap/directories/"+dir, map[string]any{"enabled": false},
		ifMatchOf(etagVersion(t, rec))), http.StatusOK)
	calls := s.dir.calls()
	rec, _ = s.dirLogin(s.freshClient(), dir, "deniz", dirUserPassword)
	requireError(t, rec, http.StatusServiceUnavailable, "ALC-LDAP-0002")
	assert.Equal(t, calls, s.dir.calls(), "a switched-off directory is never contacted")
	reason, _, _ = s.lastDenial(t)
	assert.Equal(t, "provider_disabled", reason)
	denials := s.countWhere("audit_log", "action = 'auth.ldap.denied'")
	rec, _ = s.dirLogin(s.freshClient(), "3f2b8c1e-5d4a-4b7e-9a10-0c1d2e3f4a5b", "deniz", dirUserPassword)
	requireError(t, rec, http.StatusServiceUnavailable, "ALC-LDAP-0002")
	assert.Equal(t, denials, s.countWhere("audit_log", "action = 'auth.ldap.denied'"), "an unknown directory is not recorded")

	// A malformed body is answered at once.
	rec, took = s.timedDo(s.freshClient(), http.MethodPost, "/api/v1/auth/ldap/"+dir+"/login", `{"username":"deniz"`)
	requireStatus(t, rec, http.StatusBadRequest)
	assert.Zero(t, took)
	rec, took = s.timedDo(s.freshClient(), http.MethodPost, "/api/v1/auth/ldap/"+dir+"/login",
		map[string]string{"username": strings.Repeat("a", 65), "password": "x"})
	requireError(t, rec, http.StatusUnprocessableEntity, "ALC-SYS-0006")
	assert.Zero(t, took)

	s.requireNoDirectoryCanary(t)
}

func TestDirectorySignInLockout(t *testing.T) {
	s, admin, adminAcct := installed(t)
	dir := s.directoryReady(t, admin, adminAcct, true)
	path := "/api/v1/auth/ldap/" + dir + "/login"
	lockout := func() int { return s.api.s.ldapLockout.Len() }

	// The sign-in form's limit per address: the 11th request in a minute is refused, whatever its body.
	c := s.freshClient()
	long := map[string]string{"username": "deniz", "password": strings.Repeat("p", maxLoginPassword+1)}
	for range 10 {
		requireError(t, c.do(http.MethodPost, path, long), http.StatusUnprocessableEntity, "ALC-SYS-0006")
	}
	rec, took := s.timedDo(c, http.MethodPost, path, long)
	requireError(t, rec, http.StatusTooManyRequests, "ALC-SYS-0005")
	assert.NotEmpty(t, rec.Header().Get("Retry-After"))
	assert.Zero(t, took, "a rate limit is answered at once")

	// 3 failed passwords lock the name for 45 minutes, from any address, before any directory traffic: the right
	// password is refused too, in any case, and an unknown name is counted exactly the same.
	for _, name := range [][2]string{{"deniz", "DENIZ"}, {"ghost", "Ghost"}} {
		for range 3 {
			rec, _ := s.dirLogin(s.freshClient(), dir, name[0], "wrong-password")
			requireError(t, rec, http.StatusUnauthorized, "ALC-LDAP-0001")
		}
		calls := s.dir.calls()
		rec, took := s.dirLogin(s.freshClient(), dir, name[0], dirUserPassword)
		requireError(t, rec, http.StatusTooManyRequests, "ALC-SYS-0005")
		assert.Zero(t, took, "a locked name is answered at once")
		retry, err := strconv.Atoi(rec.Header().Get("Retry-After"))
		require.NoError(t, err)
		assert.InDelta(t, ldapLockoutFor.Seconds(), retry, 10)
		rec, _ = s.dirLogin(s.freshClient(), dir, name[1], dirUserPassword)
		requireError(t, rec, http.StatusTooManyRequests, "ALC-SYS-0005")
		assert.Equal(t, calls, s.dir.calls(), "%s: a locked name never reaches the directory", name[0])
	}
	// NFC and NFD spellings of one name share one budget.
	for _, spelling := range []string{"çağla", "çağla", "ÇAĞLA"} {
		rec, _ := s.dirLogin(s.freshClient(), dir, spelling, "wrong-password")
		requireError(t, rec, http.StatusUnauthorized, "ALC-LDAP-0001")
	}
	rec, _ = s.dirLogin(s.freshClient(), dir, "çağla", dirUserPassword)
	requireError(t, rec, http.StatusTooManyRequests, "ALC-SYS-0005")
	// The lock ends after 45 minutes, not before.
	s.clock.Advance(ldapLockoutFor - time.Minute)
	rec, _ = s.dirLogin(s.freshClient(), dir, "deniz", dirUserPassword)
	requireError(t, rec, http.StatusTooManyRequests, "ALC-SYS-0005")
	s.clock.Advance(time.Minute)
	rec, _ = s.dirLogin(s.freshClient(), dir, "deniz", dirUserPassword)
	requireStatus(t, rec, http.StatusOK)

	// A successful sign-in clears the failures.
	for range 2 {
		rec, _ := s.dirLogin(s.freshClient(), dir, "berk", "wrong-password")
		requireError(t, rec, http.StatusUnauthorized, "ALC-LDAP-0001")
	}
	rec, _ = s.dirLogin(s.freshClient(), dir, "berk", dirUserPassword)
	requireStatus(t, rec, http.StatusOK)
	for range 2 {
		rec, _ := s.dirLogin(s.freshClient(), dir, "berk", "wrong-password")
		requireError(t, rec, http.StatusUnauthorized, "ALC-LDAP-0001")
	}
	rec, _ = s.dirLogin(s.freshClient(), dir, "berk", dirUserPassword)
	requireStatus(t, rec, http.StatusOK)

	// Made-up directories and unusable names make no key.
	keys := lockout()
	for range 20 {
		rec, _ := s.dirLogin(s.freshClient(), dir[:24]+uuidSuffix(), "deniz", "wrong-password")
		requireError(t, rec, http.StatusServiceUnavailable, "ALC-LDAP-0002")
	}
	rec, _ = s.dirLogin(s.freshClient(), dir, "bad\tname", "wrong-password")
	requireError(t, rec, http.StatusUnauthorized, "ALC-LDAP-0001")
	assert.Equal(t, keys, lockout())

	// ResetLimits clears the lockout (and the per-address limit).
	s.api.ResetLimits()
	assert.Zero(t, lockout())
	rec, _ = s.dirLogin(c, dir, "çağla", dirUserPassword)
	requireStatus(t, rec, http.StatusOK)
}

// uuidSuffix is the last 12 hex digits of a fresh UUID (a made-up directory ID with a real one's prefix).
func uuidSuffix() string { u := uuid.NewString(); return u[24:] }

// A full lockout table never drops a locked name; it refuses new names until one expires (fail closed).
func TestDirectoryLockoutTableFailsClosed(t *testing.T) {
	s, admin, adminAcct := installed(t)
	dir := s.directoryReady(t, admin, adminAcct, true)
	s.api.s.ldapLockout = ratelimit.NewBoundedLockout(s.clock, ldapLockoutFailures, ldapLockoutWindow, ldapLockoutFor, 2)
	for range 3 {
		rec, _ := s.dirLogin(s.freshClient(), dir, "deniz", "wrong-password")
		requireError(t, rec, http.StatusUnauthorized, "ALC-LDAP-0001")
	}
	rec, _ := s.dirLogin(s.freshClient(), dir, "ghost", "wrong-password")
	requireError(t, rec, http.StatusUnauthorized, "ALC-LDAP-0001")
	calls := s.dir.calls()
	rec, _ = s.dirLogin(s.freshClient(), dir, "berk", dirUserPassword)
	requireError(t, rec, http.StatusTooManyRequests, "ALC-SYS-0005")
	for _, name := range []string{"x1", "x2", "x3"} {
		rec, _ = s.dirLogin(s.freshClient(), dir, name, "wrong-password")
		requireError(t, rec, http.StatusTooManyRequests, "ALC-SYS-0005")
	}
	rec, _ = s.dirLogin(s.freshClient(), dir, "deniz", dirUserPassword)
	requireError(t, rec, http.StatusTooManyRequests, "ALC-SYS-0005")
	assert.Equal(t, calls, s.dir.calls())
	// Once ghost's window is over it makes room; deniz stays locked until its 45 minutes end.
	s.clock.Advance(ldapLockoutWindow + time.Minute)
	rec, _ = s.dirLogin(s.freshClient(), dir, "berk", dirUserPassword)
	requireStatus(t, rec, http.StatusOK)
	rec, _ = s.dirLogin(s.freshClient(), dir, "deniz", dirUserPassword)
	requireError(t, rec, http.StatusTooManyRequests, "ALC-SYS-0005")
}

func TestDirectoryStepUp(t *testing.T) {
	s, admin, adminAcct := installed(t)
	dir := s.directoryReady(t, admin, adminAcct, true)
	browser := s.freshClient()
	rec, _ := s.dirLogin(browser, dir, "deniz", dirUserPassword)
	requireStatus(t, rec, http.StatusOK)
	deniz := s.enrolDirectoryUser(t, browser, "deniz")

	stepup := "/api/v1/auth/ldap/stepup"
	// The password and the code (MFA on), for the sign-in name Alice stored.
	s.clock.Advance(31 * time.Second)
	rec, took := s.timedDo(browser, http.MethodPost, stepup, map[string]string{"password": dirUserPassword, "code": s.totpNow(deniz.secret)})
	requireStatus(t, rec, http.StatusOK)
	assert.Zero(t, took)
	assert.NotNil(t, decodeBody[sessionUserBody](t, rec).StepUpUntil)
	assert.Equal(t, 1, s.countWhere("audit_log", "action = 'auth.stepup' AND details->>'method' = 'ldap'"))

	// The caller cannot name another sign-in name.
	requireStatus(t, browser.do(http.MethodPost, stepup, map[string]string{"username": "berk", "password": dirUserPassword}), http.StatusBadRequest)

	// A wrong password: the generic answer, held to the floor, recorded with the session user as the actor.
	rec, took = s.timedDo(browser, http.MethodPost, stepup, map[string]string{"password": "wrong", "code": s.totpNow(deniz.secret)})
	requireError(t, rec, http.StatusUnauthorized, "ALC-LDAP-0001")
	assert.Equal(t, ldapRefusalFloor, took)
	reason, login, actor := s.lastDenial(t)
	assert.Equal(t, [3]string{"bad_credentials", "deniz", "user"}, [3]string{reason, login, actor})
	var actorID string
	require.NoError(t, s.db.Owner.QueryRow(context.Background(), `SELECT actor_id::text FROM audit_log WHERE action = 'auth.ldap.denied'
ORDER BY seq DESC LIMIT 1`).Scan(&actorID))
	assert.Equal(t, deniz.id, actorID)
	s.clock.Advance(31 * time.Second)
	requireError(t, browser.do(http.MethodPost, stepup, map[string]string{"password": dirUserPassword, "code": "000000"}),
		http.StatusUnauthorized, "ALC-AUTH-0006")

	// The stored name now finds another entry: not this person; recorded with the session user, never the other entry.
	s.dir.set(func(f *fakeDirectory) {
		for i := range f.users {
			if f.users[i].login == "deniz" {
				f.users[i].uid = "6f1c5b7e-0d3a-4c1e-9a55-0000000000ff"
			}
		}
	})
	s.clock.Advance(31 * time.Second)
	rec, took = s.timedDo(browser, http.MethodPost, stepup, map[string]string{"password": dirUserPassword, "code": s.totpNow(deniz.secret)})
	requireError(t, rec, http.StatusUnauthorized, "ALC-LDAP-0001")
	assert.Equal(t, ldapRefusalFloor, took)
	reason, login, actor = s.lastDenial(t)
	assert.Equal(t, [3]string{"stepup_other_user", "deniz", "user"}, [3]string{reason, login, actor})
	assert.Zero(t, s.countWhere("users", "ldap_unique_id = encode('6f1c5b7e-0d3a-4c1e-9a55-0000000000ff', 'hex')"), "no user for the other entry")

	// A user whose Alice name was transliterated and suffixed (çağla -> cagla-2) steps up with the stored name.
	s.stepUp(admin, adminAcct)
	requireStatus(t, admin.do(http.MethodPost, "/api/v1/users", map[string]string{"username": "cagla", "display_name": "Local Cagla",
		"email": "", "role": "auditor", "password": operatorPassword}), http.StatusCreated)
	cb := s.freshClient()
	rec, _ = s.dirLogin(cb, dir, "Çağla", dirUserPassword)
	requireStatus(t, rec, http.StatusOK)
	cagla := s.enrolDirectoryUser(t, cb, "cagla-2")
	rec = cb.do(http.MethodGet, "/api/v1/auth/session", nil)
	assert.Equal(t, "cagla-2", decodeBody[sessionUserBody](t, rec).User.Username)
	s.clock.Advance(31 * time.Second)
	rec = cb.do(http.MethodPost, stepup, map[string]string{"password": dirUserPassword, "code": s.totpNow(cagla.secret)})
	requireStatus(t, rec, http.StatusOK)

	// A local user confirms with the authenticator code; a directory user cannot use that route.
	s.clock.Advance(31 * time.Second)
	requireError(t, admin.do(http.MethodPost, stepup, map[string]string{"password": adminPassword}), http.StatusConflict, "ALC-LDAP-0008")
	requireError(t, cb.do(http.MethodPost, "/api/v1/auth/stepup", map[string]string{"code": s.totpNow(cagla.secret)}),
		http.StatusConflict, "ALC-USR-0003")
	requireError(t, s.freshClient().do(http.MethodPost, stepup, map[string]string{"password": dirUserPassword}),
		http.StatusUnauthorized, "ALC-AUTH-0001")

	// The step-up shares the sign-in's lockout: 3 wrong passwords lock the stored name for the sign-in too.
	for range 3 {
		rec, _ := s.timedDo(cb, http.MethodPost, stepup, map[string]string{"password": "wrong"})
		requireError(t, rec, http.StatusUnauthorized, "ALC-LDAP-0001")
	}
	requireError(t, cb.do(http.MethodPost, stepup, map[string]string{"password": dirUserPassword}), http.StatusTooManyRequests, "ALC-SYS-0005")
	rec, _ = s.dirLogin(s.freshClient(), dir, "çağla", dirUserPassword)
	requireError(t, rec, http.StatusTooManyRequests, "ALC-SYS-0005")
	s.api.ResetLimits()

	// No authenticator while the directory asks for MFA (an Administrator reset it while MFA was off): the person signs
	// in again to enrol (409 ALC-LDAP-0007, nothing counted).
	s.stepUp(admin, adminAcct)
	requireStatus(t, admin.do(http.MethodPost, "/api/v1/users/"+cagla.id+"/actions/reset-mfa", nil), http.StatusNoContent)
	setMFA := func(on bool) {
		rec := admin.do(http.MethodGet, "/api/v1/ldap/directories/"+dir, nil)
		requireStatus(t, admin.do(http.MethodPatch, "/api/v1/ldap/directories/"+dir, map[string]any{"mfa_required": on},
			ifMatchOf(etagVersion(t, rec))), http.StatusOK)
	}
	setMFA(false)
	fresh := s.freshClient()
	rec, _ = s.dirLogin(fresh, dir, "Çağla", dirUserPassword)
	requireStatus(t, rec, http.StatusOK)
	require.Equal(t, "signed_in", decodeBody[map[string]string](t, rec)["status"])
	setMFA(true)
	requireError(t, fresh.do(http.MethodPost, stepup, map[string]string{"password": dirUserPassword}), http.StatusConflict, "ALC-LDAP-0007")

	s.requireNoDirectoryCanary(t)
}

// A refused step-up ends the session user's sessions when the refusal says they have no access any more: removed from
// every mapped group (no_access), or the directory switched off (provider_disabled, answered ALC-LDAP-0002). MFA is
// off here, so the sign-in opens a full session at once and the step-up needs the password only.
func TestDirectoryStepUpRefusalEndsTheSessions(t *testing.T) {
	s, admin, adminAcct := installed(t)
	dir := s.directoryReady(t, admin, adminAcct, false)
	stepup := "/api/v1/auth/ldap/stepup"
	signedIn := func(login string) *client {
		c := s.freshClient()
		rec, _ := s.dirLogin(c, dir, login, dirUserPassword)
		requireStatus(t, rec, http.StatusOK)
		require.Equal(t, "signed_in", decodeBody[map[string]string](t, rec)["status"])
		requireStatus(t, c.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusOK)
		return c
	}
	selin, ayse := signedIn("selin"), signedIn("ayse")
	other := signedIn("selin") // a second session of the same person

	// Selin leaves every mapped group: her confirmation is refused and every session of hers ends.
	s.dir.set(func(f *fakeDirectory) {
		for i := range f.users {
			if f.users[i].login == "selin" {
				f.users[i].groups = []string{"cn=other"}
			}
		}
	})
	rec, took := s.timedDo(selin, http.MethodPost, stepup, map[string]string{"password": dirUserPassword})
	requireError(t, rec, http.StatusUnauthorized, "ALC-LDAP-0001")
	assert.Equal(t, ldapRefusalFloor, took)
	reason, login, actor := s.lastDenial(t)
	assert.Equal(t, [3]string{"no_access", "selin", "user"}, [3]string{reason, login, actor})
	requireError(t, selin.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusUnauthorized, "ALC-AUTH-0001")
	requireError(t, other.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusUnauthorized, "ALC-AUTH-0001")
	requireStatus(t, ayse.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusOK)

	// The directory is switched off: Ayşe's confirmation is refused and her session ends.
	s.stepUp(admin, adminAcct)
	rec = admin.do(http.MethodGet, "/api/v1/ldap/directories/"+dir, nil)
	requireStatus(t, admin.do(http.MethodPatch, "/api/v1/ldap/directories/"+dir, map[string]any{"enabled": false},
		ifMatchOf(etagVersion(t, rec))), http.StatusOK)
	requireStatus(t, ayse.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusOK) // switching off ends nothing by itself
	rec, _ = s.timedDo(ayse, http.MethodPost, stepup, map[string]string{"password": dirUserPassword})
	requireError(t, rec, http.StatusServiceUnavailable, "ALC-LDAP-0002")
	reason, _, actor = s.lastDenial(t)
	assert.Equal(t, [2]string{"provider_disabled", "user"}, [2]string{reason, actor})
	requireError(t, ayse.do(http.MethodGet, "/api/v1/auth/session", nil), http.StatusUnauthorized, "ALC-AUTH-0001")
	assert.Equal(t, 2, s.countWhere("audit_log", "action = 'user.sessions_ended'"))

	s.requireNoDirectoryCanary(t)
}

func TestDirectoryAdministration(t *testing.T) {
	s, admin, adminAcct := installed(t)
	dir := s.directoryReady(t, admin, adminAcct, true)
	base := "/api/v1/ldap/directories/" + dir

	// Permissions: anonymous 401, an Administrator without step-up 403 stepup_required, an Operator 403; with step-up
	// allowed (TestAuthzMatrix covers every route and identity against the table).
	rec, _ := s.dirLogin(s.freshClient(), dir, "deniz", dirUserPassword)
	requireStatus(t, rec, http.StatusOK)
	operator := s.freshClient()
	rec, _ = s.dirLogin(operator, dir, "berk", dirUserPassword)
	requireStatus(t, rec, http.StatusOK)
	s.enrolDirectoryUser(t, operator, "berk")
	for _, rt := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/ldap/directories"}, {http.MethodGet, base}, {http.MethodPost, base + "/actions/test-connection"},
		{http.MethodGet, "/api/v1/ldap/group-mappings?directory_id=" + dir},
	} {
		requireError(t, s.freshClient().do(rt.method, rt.path, nil), http.StatusUnauthorized, "ALC-AUTH-0001")
		requireError(t, operator.do(rt.method, rt.path, nil), http.StatusForbidden, "ALC-AUTH-0002")
	}
	s.clock.Advance(6 * time.Minute) // the step-up window has passed
	requireError(t, admin.do(http.MethodGet, "/api/v1/ldap/directories", nil), http.StatusForbidden, "ALC-AUTH-0003")
	s.stepUp(admin, adminAcct)
	rec = admin.do(http.MethodGet, "/api/v1/ldap/directories", nil)
	requireStatus(t, rec, http.StatusOK)
	assert.NotContains(t, rec.Body.String(), "bind_password\"")

	// ETag / If-Match: required, and a stale version is refused.
	requireError(t, admin.do(http.MethodPatch, base, map[string]any{"name": "Corp"}), http.StatusPreconditionFailed, "ALC-SYS-0008")
	requireError(t, admin.do(http.MethodPatch, base, map[string]any{"name": "Corp"}, ifMatchOf("9")), http.StatusPreconditionFailed, "ALC-SYS-0008")
	rec = admin.do(http.MethodPatch, base, map[string]any{"name": "Corp"}, ifMatchOf("1"))
	requireStatus(t, rec, http.StatusOK)
	assert.Equal(t, `"2"`, rec.Header().Get("ETag"))
	requireStatus(t, admin.do(http.MethodPatch, base, map[string]any{"name": nil}, ifMatchOf("2")), http.StatusBadRequest)
	requireStatus(t, admin.do(http.MethodPatch, base, map[string]any{"extra": 1}, ifMatchOf("2")), http.StatusBadRequest)
	// A new address needs the password again; with users, addresses still change, the unique id attribute does not.
	requireError(t, admin.do(http.MethodPatch, base, map[string]any{"addresses": []string{"ldaps://ldap.corp.example:636", "ldaps://other.corp.example"}},
		ifMatchOf("2")), http.StatusUnprocessableEntity, "ALC-SYS-0006")
	requireStatus(t, admin.do(http.MethodPatch, base, map[string]any{"addresses": []string{"ldaps://ldap.corp.example:636", "ldaps://other.corp.example"},
		"bind_password": dirBindPassword}, ifMatchOf("2")), http.StatusOK)
	requireStatus(t, admin.do(http.MethodPatch, base, map[string]any{"addresses": []string{"ldaps://other.corp.example"}}, ifMatchOf("3")), http.StatusOK)
	requireError(t, admin.do(http.MethodPatch, base, map[string]any{"unique_id_attribute": "uid", "bind_password": dirBindPassword},
		ifMatchOf("4")), http.StatusConflict, "ALC-LDAP-0003")
	requireError(t, admin.do(http.MethodDelete, base, nil), http.StatusPreconditionFailed, "ALC-SYS-0008")
	requireError(t, admin.do(http.MethodDelete, base, nil, ifMatchOf("4")), http.StatusConflict, "ALC-LDAP-0003")

	// At most 3 directories; an unused one is deleted.
	rec = admin.do(http.MethodPost, "/api/v1/ldap/directories", directoryBodyFor("Second", true, false))
	requireStatus(t, rec, http.StatusCreated)
	second := decodeBody[directoryDTO](t, rec).ID.String()
	requireStatus(t, admin.do(http.MethodPost, "/api/v1/ldap/directories", directoryBodyFor("Third", true, false)), http.StatusCreated)
	requireError(t, admin.do(http.MethodPost, "/api/v1/ldap/directories", directoryBodyFor("Fourth", true, false)),
		http.StatusConflict, "ALC-LDAP-0005")
	requireError(t, admin.do(http.MethodPost, "/api/v1/ldap/directories", map[string]any{"name": "No password"}),
		http.StatusUnprocessableEntity, "ALC-SYS-0006")
	requireStatus(t, admin.do(http.MethodDelete, "/api/v1/ldap/directories/"+second, nil, ifMatchOf("1")), http.StatusNoContent)
	requireError(t, admin.do(http.MethodGet, "/api/v1/ldap/directories/"+second, nil), http.StatusNotFound, "ALC-SYS-0001")

	// Group mappings: Administrator needs the switch (ALC-SSO-0002); another directory's mapping is not found.
	requireError(t, admin.do(http.MethodPost, "/api/v1/ldap/group-mappings", map[string]string{"directory_id": dir, "group": "admins",
		"role": "admin"}), http.StatusConflict, "ALC-SSO-0002")
	rec = admin.do(http.MethodPost, "/api/v1/ldap/group-mappings", map[string]string{"directory_id": dir, "group": "cn=Auditors,ou=groups",
		"role": "auditor"})
	requireStatus(t, rec, http.StatusCreated)
	mapping := decodeBody[directoryMappingDTO](t, rec)
	assert.Equal(t, "cn=Auditors,ou=groups", mapping.Group)
	rec = admin.do(http.MethodGet, "/api/v1/ldap/group-mappings?directory_id="+dir, nil)
	requireStatus(t, rec, http.StatusOK)
	assert.Len(t, decodeBody[struct {
		Items []directoryMappingDTO `json:"items"`
	}](t, rec).Items, 2)
	requireError(t, admin.do(http.MethodGet, "/api/v1/ldap/group-mappings", nil), http.StatusUnprocessableEntity, "ALC-SYS-0006")
	requireError(t, admin.do(http.MethodDelete, "/api/v1/ldap/group-mappings/"+mapping.ID.String()+"?directory_id=3f2b8c1e-5d4a-4b7e-9a10-0c1d2e3f4a5b", nil),
		http.StatusNotFound, "ALC-SYS-0001")
	requireStatus(t, admin.do(http.MethodDelete, "/api/v1/ldap/group-mappings/"+mapping.ID.String()+"?directory_id="+dir, nil), http.StatusNoContent)

	// Test connection and Test sign-in: results, failures with their reason, the stored bind password used, and a
	// shared limit of 5 a minute per user.
	rec = admin.do(http.MethodPost, base+"/actions/test-connection", nil)
	requireStatus(t, rec, http.StatusOK)
	assert.JSONEq(t, `{"result":"ok"}`, rec.Body.String())
	s.dir.set(func(f *fakeDirectory) { f.down = true })
	rec = admin.do(http.MethodPost, base+"/actions/test-connection", map[string]any{})
	requireError(t, rec, http.StatusUnprocessableEntity, "ALC-LDAP-0004")
	assert.Equal(t, map[string]string{"reason": "directory_unreachable", "detail": "timeout"}, decodeBody[apiError](t, rec).Error.Params)
	s.dir.set(func(f *fakeDirectory) { f.down = false })
	rec = admin.do(http.MethodPost, base+"/actions/test-signin", map[string]string{"username": "nogroup", "password": dirUserPassword})
	requireStatus(t, rec, http.StatusOK)
	res := decodeBody[directoryTestDTO](t, rec)
	assert.Equal(t, []string{"cn=other"}, res.Groups)
	assert.Nil(t, res.Role)
	rec = admin.do(http.MethodPost, base+"/actions/test-signin", map[string]string{"username": "deniz", "password": "wrong"})
	requireError(t, rec, http.StatusUnprocessableEntity, "ALC-LDAP-0006")
	assert.Equal(t, map[string]string{"reason": "bad_credentials", "detail": "user_bind"}, decodeBody[apiError](t, rec).Error.Params)
	rec = admin.do(http.MethodPost, base+"/actions/test-signin", map[string]string{"username": "deniz", "password": dirUserPassword})
	requireStatus(t, rec, http.StatusOK)
	res = decodeBody[directoryTestDTO](t, rec)
	require.NotNil(t, res.Role)
	assert.Equal(t, "operator", *res.Role)
	assert.Equal(t, "deniz", res.Login)
	requireError(t, admin.do(http.MethodPost, base+"/actions/test-signin", map[string]string{"username": "deniz", "password": dirUserPassword}),
		http.StatusTooManyRequests, "ALC-SYS-0005")
	s.dir.mu.Lock()
	for _, b := range s.dir.binds {
		assert.Equal(t, dirBindPassword, b, "the stored service account password reaches the client")
	}
	s.dir.mu.Unlock()
	assert.Equal(t, 2, s.countWhere("audit_log", "action = 'ldap.directory_tested'"))
	assert.Equal(t, 3, s.countWhere("audit_log", "action = 'ldap.signin_tested'"))

	s.requireNoDirectoryCanary(t)
}

// requireNoDirectoryCanary: neither password ever appears in an answer, a header, an audit row or a log line.
func (s *stack) requireNoDirectoryCanary(t *testing.T) {
	t.Helper()
	for _, e := range s.recorded() {
		raw, err := json.Marshal(e.header)
		require.NoError(t, err)
		for _, canary := range []string{dirUserPassword, dirBindPassword} {
			assert.NotContains(t, string(e.body), canary, e.key())
			assert.NotContains(t, string(raw), canary, e.key())
		}
	}
	for _, canary := range []string{dirUserPassword, dirBindPassword} {
		assert.Zero(t, s.countWhere("audit_log a", "to_jsonb(a)::text LIKE '%"+canary+"%'"), "audit")
		assert.NotContains(t, s.logs.String(), canary)
		assert.NotContains(t, s.rawLogs.String(), canary)
	}
}

// Parallel attempts reserve their slots: with the directory holding every answer, at most 3 attempts for one name reach
// it; every slot is released on every outcome (an unreachable directory, a cancelled request, a panic).
func TestDirectoryLockoutReservesParallelAttempts(t *testing.T) {
	s, admin, adminAcct := installed(t)
	dir := s.directoryReady(t, admin, adminAcct, true)
	path := "/api/v1/auth/ldap/" + dir + "/login"
	hold := make(chan struct{})
	s.dir.set(func(f *fakeDirectory) { f.hold = hold })
	const n = 10
	codes := make(chan int, n)
	for range n {
		c := s.freshClient()
		go func() {
			codes <- c.do(http.MethodPost, path, map[string]string{"username": "deniz", "password": "wrong-password"}).Code
		}()
	}
	// The 7 refused attempts answer at once (429); 3 are inside the directory.
	var refused int
	for refused < n-3 {
		select {
		case code := <-codes:
			require.Equal(t, http.StatusTooManyRequests, code)
			refused++
		case <-time.After(10 * time.Second):
			t.Fatalf("only %d attempts were refused", refused)
		}
	}
	assert.Equal(t, 3, s.dir.calls(), "at most 3 attempts reached the directory")
	close(hold)
	// The held attempts now fail and wait for the refusal floor on the stack clock.
	deadline := time.After(20 * time.Second)
	for got := 0; got < 3; {
		select {
		case code := <-codes:
			assert.Equal(t, http.StatusUnauthorized, code)
			got++
		case <-time.After(2 * time.Millisecond):
			s.clock.AdvanceToNextTimer()
		case <-deadline:
			t.Fatal("the held attempts did not answer")
		}
	}
	assert.True(t, s.api.s.ldapLockout.Locked(ldapLoginKey(uuid.MustParse(dir), "deniz")), "the 3 failures locked the name")
	s.dir.set(func(f *fakeDirectory) { f.hold = nil })

	// Neutral outcomes release their slots: an unreachable directory, a cancelled request, a panic.
	s.api.ResetLimits()
	s.dir.set(func(f *fakeDirectory) { f.down = true })
	for range 5 {
		rec, _ := s.dirLogin(s.freshClient(), dir, "berk", dirUserPassword)
		requireError(t, rec, http.StatusServiceUnavailable, "ALC-LDAP-0002")
	}
	s.dir.set(func(f *fakeDirectory) { f.down = false })
	ctx, cancel := context.WithCancel(context.Background())
	s.dir.set(func(f *fakeDirectory) { f.hold = make(chan struct{}) })
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.freshClient().do(http.MethodPost, path, map[string]string{"username": "berk", "password": dirUserPassword},
			func(r *http.Request) { *r = *r.WithContext(ctx) })
	}()
	require.Eventually(t, func() bool { return s.dir.calls() > 0 && s.api.s.ldapLockout.Len() == 1 }, 5*time.Second, time.Millisecond)
	cancel()
	<-done
	s.dir.set(func(f *fakeDirectory) { f.hold = nil; f.panicNext = true })
	rec := s.freshClient().do(http.MethodPost, path, map[string]string{"username": "berk", "password": dirUserPassword})
	assert.Equal(t, http.StatusInternalServerError, rec.Code, "the fake panicked")
	assert.Zero(t, s.api.s.ldapLockout.Len(), "every slot was released")
	assert.Zero(t, s.api.s.ldapAccountLockout.Len())
	rec, _ = s.dirLogin(s.freshClient(), dir, "berk", dirUserPassword)
	requireStatus(t, rec, http.StatusOK)
}

// Spellings a directory treats alike share the name key; aliases of one account share the account key, whose lock
// stops the bind itself.
func TestDirectoryLockoutSpellingsAndAccounts(t *testing.T) {
	s, admin, adminAcct := installed(t)
	dir := s.directoryReady(t, admin, adminAcct, true)
	dirID := uuid.MustParse(dir)

	// Full-width, upper-case and double-space spellings of "John Smith" share one name key.
	for _, spelling := range []string{"John Smith", "ＪＯＨＮ ＳＭＩＴＨ", "john  smith"} {
		rec, _ := s.dirLogin(s.freshClient(), dir, spelling, "wrong-password")
		requireError(t, rec, http.StatusUnauthorized, "ALC-LDAP-0001")
	}
	assert.True(t, s.api.s.ldapLockout.Locked(ldapLoginKey(dirID, "John Smith")))
	// A variation selector makes no new spelling: it is refused before any traffic and makes no key.
	calls, keys := s.dir.calls(), s.api.s.ldapLockout.Len()
	rec, _ := s.dirLogin(s.freshClient(), dir, "deniz\ufe0f", dirUserPassword)
	requireError(t, rec, http.StatusUnauthorized, "ALC-LDAP-0001")
	assert.Equal(t, calls, s.dir.calls())
	assert.Equal(t, keys, s.api.s.ldapLockout.Len())

	// Three failures through two names of one account lock the account: the 4th attempt, through either name and even
	// with the right password, is never bound to.
	for _, name := range []string{"deniz", "deniz@corp.example", "deniz"} {
		rec, _ := s.dirLogin(s.freshClient(), dir, name, "wrong-password")
		requireError(t, rec, http.StatusUnauthorized, "ALC-LDAP-0001")
	}
	assert.False(t, s.api.s.ldapLockout.Locked(ldapLoginKey(dirID, "deniz")), "neither name reached 3 failures")
	binds := s.dir.userBindCount()
	rec, took := s.dirLogin(s.freshClient(), dir, "deniz@corp.example", dirUserPassword)
	requireError(t, rec, http.StatusUnauthorized, "ALC-LDAP-0001")
	assert.Equal(t, ldapRefusalFloor, took, "the generic answer, held to the floor")
	assert.Equal(t, binds, s.dir.userBindCount(), "a locked account is never bound to")
	reason, login, actor := s.lastDenial(t)
	assert.Equal(t, [3]string{"bad_credentials", "deniz", "system"}, [3]string{reason, login, actor})
	rec, _ = s.dirLogin(s.freshClient(), dir, "DENIZ", dirUserPassword)
	requireError(t, rec, http.StatusUnauthorized, "ALC-LDAP-0001")
	assert.Equal(t, binds, s.dir.userBindCount())
	s.clock.Advance(ldapLockoutFor)
	rec, _ = s.dirLogin(s.freshClient(), dir, "deniz@corp.example", dirUserPassword)
	requireStatus(t, rec, http.StatusOK)

	// A success clears both keys.
	for _, name := range []string{"berk", "berk"} {
		rec, _ := s.dirLogin(s.freshClient(), dir, name, "wrong-password")
		requireError(t, rec, http.StatusUnauthorized, "ALC-LDAP-0001")
	}
	rec, _ = s.dirLogin(s.freshClient(), dir, "berk", dirUserPassword)
	requireStatus(t, rec, http.StatusOK)
	for range 2 {
		rec, _ := s.dirLogin(s.freshClient(), dir, "berk", "wrong-password")
		requireError(t, rec, http.StatusUnauthorized, "ALC-LDAP-0001")
	}
	rec, _ = s.dirLogin(s.freshClient(), dir, "berk", dirUserPassword)
	requireStatus(t, rec, http.StatusOK) // two failures after the success: neither key is locked
}
