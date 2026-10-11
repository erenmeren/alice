package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeAlice is a hand fake of the API routes zapsession calls, with Alice's rules where they matter
// to the tool: the setup code, same-origin and CSRF checks on every state-changing request after
// the setup session, TOTP codes checked against the enrolment secret and never accepted twice (or
// for an earlier step), step-up before user administration, and __Host- cookies. Its clock is the
// test's fake clock, which a wait of zapsession moves forward.
type fakeAlice struct {
	t        *testing.T
	mu       sync.Mutex
	clk      *fakeClock
	code     string
	users    map[string]*fakeUser // by username
	sessions map[string]*fakeSession
	calls    []string
	n        int
	https    []byte // the certificate installed through PUT /api/v1/settings/https
}

type fakeUser struct {
	role, password, secret string
	last                   int64
}

type fakeSession struct {
	user      string
	full      bool
	steppedUp bool
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }

func (c *fakeClock) Sleep(d time.Duration) { c.mu.Lock(); defer c.mu.Unlock(); c.now = c.now.Add(d) }

func (f *fakeAlice) token() string { f.n++; return "tok" + strings.Repeat("x", f.n) }

func csrfOf(tok string) string { return "csrf-" + tok }

func (f *fakeAlice) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	var body map[string]string
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	fail := func(status int, code string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "reason": "fake"}})
	}
	ok := func(v any) {
		w.Header().Set("Content-Type", "application/json")
		if v == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_ = json.NewEncoder(w).Encode(v)
	}
	setCookie := func(name, tok string) {
		http.SetCookie(w, &http.Cookie{Name: name, Value: tok, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	}
	if r.Header.Get("Sec-Fetch-Site") != "same-origin" || r.Header.Get("X-Alice-Activity") != "1" {
		fail(http.StatusForbidden, "ALC-AUTH-SAMEORIGIN")
		return
	}
	// The session of this request (setup or full) and its CSRF check.
	var tok string
	for _, name := range []string{"__Host-alice_session", "__Host-alice_setup"} {
		if c, err := r.Cookie(name); err == nil {
			tok = c.Value
			break
		}
	}
	sess := f.sessions[tok]
	if sess != nil && r.Header.Get("X-CSRF-Token") != csrfOf(tok) {
		fail(http.StatusForbidden, "ALC-AUTH-CSRF")
		return
	}
	checkCode := func(u *fakeUser, code string) bool {
		now := f.clk.Now().Unix() / 30
		for step := now - 1; step <= now+1; step++ {
			want, err := totp.GenerateCodeCustom(u.secret, time.Unix(step*30, 0), totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
			require.NoError(f.t, err)
			if want == code && step > u.last {
				u.last = step
				return true
			}
		}
		return false
	}
	newSecret := func(name string) string {
		k, err := totp.Generate(totp.GenerateOpts{Issuer: "Alice", AccountName: name})
		require.NoError(f.t, err)
		return k.Secret()
	}
	switch r.Method + " " + r.URL.Path {
	case "POST /api/v1/setup/session":
		if body["code"] != f.code {
			fail(http.StatusUnauthorized, "ALC-SET-0001")
			return
		}
		t := f.token()
		f.sessions[t] = &fakeSession{}
		setCookie("__Host-alice_setup", t)
		ok(map[string]string{"csrf_token": csrfOf(t)})
	case "PUT /api/v1/setup/language":
		ok(nil)
	case "POST /api/v1/setup/admin/enrollment":
		f.users[body["username"]] = &fakeUser{role: "admin", password: body["password"], secret: newSecret(body["username"])}
		ok(map[string]string{"secret": f.users[body["username"]].secret})
	case "POST /api/v1/setup/admin":
		for name, u := range f.users {
			if u.role == "admin" && checkCode(u, body["code"]) {
				t := f.token()
				f.sessions[t] = &fakeSession{user: name, full: true}
				setCookie("__Host-alice_session", t)
				http.SetCookie(w, &http.Cookie{Name: "__Host-alice_setup", Value: "", Path: "/", MaxAge: -1, Secure: true})
				ok(map[string]any{"csrf_token": csrfOf(t)})
				return
			}
		}
		fail(http.StatusUnauthorized, "ALC-AUTH-TOTP")
	case "POST /api/v1/auth/login":
		u := f.users[body["username"]]
		if u == nil || u.password != body["password"] {
			fail(http.StatusUnauthorized, "ALC-AUTH-0001")
			return
		}
		t := f.token()
		f.sessions[t] = &fakeSession{user: body["username"]}
		setCookie("__Host-alice_session", t)
		status := "mfa_required"
		if u.secret == "" {
			status = "mfa_enrollment_required"
		}
		ok(map[string]string{"status": status, "csrf_token": csrfOf(t)})
	case "POST /api/v1/auth/mfa/enroll":
		if sess == nil {
			fail(http.StatusUnauthorized, "ALC-AUTH-0002")
			return
		}
		f.users[sess.user].secret = newSecret(sess.user)
		ok(map[string]string{"secret": f.users[sess.user].secret})
	case "POST /api/v1/auth/mfa/verify":
		if sess == nil || !checkCode(f.users[sess.user], body["code"]) {
			fail(http.StatusUnauthorized, "ALC-AUTH-TOTP")
			return
		}
		// A verified sign-in gets a new session token (and so a new CSRF token).
		delete(f.sessions, tok)
		t := f.token()
		f.sessions[t] = &fakeSession{user: sess.user, full: true}
		setCookie("__Host-alice_session", t)
		ok(map[string]any{"csrf_token": csrfOf(t)})
	case "POST /api/v1/auth/stepup":
		if sess == nil || !sess.full || !checkCode(f.users[sess.user], body["code"]) {
			fail(http.StatusUnauthorized, "ALC-AUTH-TOTP")
			return
		}
		sess.steppedUp = true
		ok(map[string]any{"csrf_token": csrfOf(tok)})
	case "PUT /api/v1/settings/https":
		if sess == nil || !sess.full || f.users[sess.user].role != "admin" {
			fail(http.StatusForbidden, "ALC-AUTH-0003")
			return
		}
		if _, err := tls.X509KeyPair([]byte(body["cert_pem"]), []byte(body["key_pem"])); err != nil {
			fail(http.StatusBadRequest, "ALC-TLS-0001")
			return
		}
		f.https = []byte(body["cert_pem"])
		ok(map[string]any{"temporary": false})
	case "POST /api/v1/setup/recovery-passphrase", "POST /api/v1/setup/https/keep-temporary", "POST /api/v1/setup/mail/skip",
		"POST /api/v1/setup/evaluation", "POST /api/v1/setup/complete":
		if sess == nil || !sess.full {
			fail(http.StatusUnauthorized, "ALC-AUTH-0002")
			return
		}
		if strings.HasSuffix(r.URL.Path, "recovery-passphrase") && (len(body["passphrase"]) < 16 || body["passphrase"] != body["passphrase_confirm"]) {
			fail(http.StatusBadRequest, "ALC-SET-0010")
			return
		}
		ok(map[string]any{})
	case "POST /api/v1/users":
		if sess == nil || !sess.steppedUp || f.users[sess.user].role != "admin" {
			fail(http.StatusForbidden, "ALC-AUTH-STEPUP")
			return
		}
		f.users[body["username"]] = &fakeUser{role: body["role"], password: body["password"]}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"x"}`))
	default:
		fail(http.StatusNotFound, "ALC-SYS-0404")
	}
}

func startFake(t *testing.T) (*fakeAlice, *httptest.Server, string) {
	t.Helper()
	f := &fakeAlice{t: t, clk: &fakeClock{now: time.Date(2026, 10, 11, 9, 0, 10, 0, time.UTC)}, code: "ABCD-EFGH",
		users: map[string]*fakeUser{}, sessions: map[string]*fakeSession{}}
	srv := httptest.NewTLSServer(f)
	t.Cleanup(srv.Close)
	ca := filepath.Join(t.TempDir(), "tls.crt")
	require.NoError(t, os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600))
	return f, srv, ca
}

func TestWritesOneSessionPerRole(t *testing.T) {
	f, srv, ca := startFake(t)
	out := filepath.Join(t.TempDir(), "zap")
	var stdout, stderr bytes.Buffer
	code := run([]string{"-base", srv.URL, "-ca", ca, "-setup-code", f.code, "-out", out}, clock{now: f.clk.Now, sleep: f.clk.Sleep}, &stdout, &stderr)
	require.Equal(t, 0, code, stderr.String())

	f.mu.Lock()
	defer f.mu.Unlock()
	for _, role := range []string{"admin", "operator", "auditor"} {
		p := filepath.Join(out, role+".env")
		st, err := os.Stat(p)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), st.Mode().Perm(), role)
		raw, err := os.ReadFile(p)
		require.NoError(t, err)
		lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
		require.Len(t, lines, 2, role)
		tok, isCookie := strings.CutPrefix(lines[0], "COOKIE=__Host-alice_session=")
		require.True(t, isCookie, lines[0])
		csrf, isCSRF := strings.CutPrefix(lines[1], "CSRF=")
		require.True(t, isCSRF, lines[1])
		assert.Equal(t, csrfOf(tok), csrf, "%s: the CSRF token of that session", role)
		sess := f.sessions[tok]
		require.NotNil(t, sess, "%s: a live session", role)
		assert.True(t, sess.full, role)
		assert.Equal(t, role, f.users[sess.user].role)
		assert.Equal(t, role == "admin", sess.steppedUp, "only the Administrator is stepped up")
		assert.Contains(t, stdout.String(), "zapsession: "+role+" signed in as zap-"+role)
	}
	// The wizard installed a certificate for 127.0.0.1 issued by the CA in test-ca.crt.
	caPEM, err := os.ReadFile(filepath.Join(out, "test-ca.crt"))
	require.NoError(t, err)
	assert.NotContains(t, string(caPEM), "PRIVATE KEY", "only the CA certificate is written")
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(caPEM))
	block, _ := pem.Decode(f.https)
	require.NotNil(t, block, "a certificate was installed")
	leaf, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "127.0.0.1", CurrentTime: f.clk.Now()})
	require.NoError(t, err, "a complete chain of trust for 127.0.0.1")
	_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "localhost", CurrentTime: f.clk.Now()})
	require.NoError(t, err)
	assert.NotContains(t, f.calls, "POST /api/v1/setup/https/keep-temporary")

	// No secret of the run reaches its output.
	for name, u := range f.users {
		assert.NotContains(t, stdout.String()+stderr.String(), u.password, name)
		assert.NotContains(t, stdout.String()+stderr.String(), u.secret, name)
	}
	// The wizard ran first, then the users, then the sign-ins.
	assert.Equal(t, "POST /api/v1/setup/session", f.calls[0])
	assert.Contains(t, f.calls, "POST /api/v1/setup/complete")
	assert.Equal(t, "POST /api/v1/auth/stepup", f.calls[len(f.calls)-1], "the Administrator steps up last")
}

func TestRefusesAWrongSetupCodeAndBadArguments(t *testing.T) {
	f, srv, ca := startFake(t)
	var stdout, stderr bytes.Buffer
	clk := clock{now: f.clk.Now, sleep: f.clk.Sleep}
	assert.Equal(t, 1, run([]string{"-base", srv.URL, "-ca", ca, "-setup-code", "WRONG", "-out", t.TempDir()}, clk, &stdout, &stderr))
	assert.Contains(t, stderr.String(), "POST /api/v1/setup/session: HTTP 401 ALC-SET-0001")
	assert.NotContains(t, stderr.String(), "WRONG", "the setup code is never printed")

	assert.Equal(t, 2, run([]string{"-base", srv.URL}, clk, &stdout, &stderr))
	stderr.Reset()
	assert.Equal(t, 1, run([]string{"-base", "http://x", "-ca", ca, "-setup-code", "c", "-out", t.TempDir()}, clk, &stdout, &stderr))
	assert.Contains(t, stderr.String(), "is not an https URL")
	stderr.Reset()
	notPEM := filepath.Join(t.TempDir(), "x")
	require.NoError(t, os.WriteFile(notPEM, []byte("x"), 0o600))
	assert.Equal(t, 1, run([]string{"-ca", notPEM, "-setup-code", "c", "-out", t.TempDir()}, clk, &stdout, &stderr))
	assert.Contains(t, stderr.String(), "holds no PEM certificate")
}

func TestCodeWaitsForTheNextStep(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 10, 11, 9, 0, 10, 0, time.UTC)}
	c := &client{clk: clock{now: clk.Now, sleep: clk.Sleep}}
	a := &account{secret: "JBSWY3DPEHPK3PXP"}
	seen := map[string]bool{}
	start := clk.Now()
	for range 5 {
		code := c.code(a)
		assert.False(t, seen[code], "a code is never handed out twice")
		seen[code] = true
	}
	// Steps now-1, now, now+1 are free at once; the next two need a wait of one step each.
	assert.GreaterOrEqual(t, clk.Now().Sub(start), 30*time.Second)
	assert.Less(t, clk.Now().Sub(start), 2*time.Minute)
}
