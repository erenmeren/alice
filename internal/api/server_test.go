package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/i18n"
	"alice/internal/platform/clock"
	"alice/internal/version"
	"alice/locales"
)

type fakeHealth struct{ err error }

func (f fakeHealth) Check(context.Context) error { return f.err }

const indexHTML = `<!doctype html><html><head><meta name="csp-nonce" content="__CSP_NONCE__"></head><body><div id="root"></div></body></html>`

// testNow is the fake clock's start time in handler tests.
var testNow = time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

// testDeps returns dependencies backed by fakes: identityAuth (see
// fakes_test.go), a fakeSetup, a fakeAudit and a fake clock at testNow.
func testDeps(t *testing.T, health error) Deps {
	t.Helper()
	cat, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	return Deps{
		Health:  fakeHealth{err: health},
		Catalog: cat,
		Version: version.Info{Version: "1.2.3", Commit: "abc", BuildTime: "t"},
		UI: fstest.MapFS{
			"index.html":         {Data: []byte(indexHTML)},
			"assets/app-1a2b.js": {Data: []byte("console.log(1)")},
			"favicon.svg":        {Data: []byte("<svg/>")},
		},
		Log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock: clock.NewFake(testNow),
		Auth:  identityAuth(testNow),
		Setup: &fakeSetup{},
		Audit: &fakeAudit{},
	}
}

// as makes req come from a test identity: "" is anonymous, "setup" uses the
// wizard cookie, "alice_*" is an API token, anything else is a session cookie
// value understood by identityAuth. Cookie identities also send the matching
// CSRF token and a same-origin Origin header.
func as(req *http.Request, id string) *http.Request {
	req.Header.Set("Origin", "https://"+req.Host)
	switch {
	case id == "":
	case id == "setup":
		req.AddCookie(&http.Cookie{Name: setupCookie, Value: "setup-ok"})
		req.Header.Set("X-CSRF-Token", "csrf-setup-ok")
	case strings.HasPrefix(id, "alice_"):
		req.Header.Set("Authorization", "Bearer "+id)
	default:
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: id})
		req.Header.Set("X-CSRF-Token", "csrf-"+id)
	}
	return req
}

// call sends a request with an optional JSON body as the given identity.
func call(h http.Handler, method, target, id, body string) *httptest.ResponseRecorder {
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := as(httptest.NewRequest(method, target, rdr), id)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func do(h http.Handler, method, target string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

type errBody struct {
	Error struct {
		Code, Reason, MessageKey, Message, RequestID string
		Retryable                                    bool
	} `json:"error"`
}

func decodeErr(t *testing.T, rec *httptest.ResponseRecorder) errBody {
	t.Helper()
	var raw map[string]map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &raw))
	e := raw["error"]
	var b errBody
	b.Error.Code, _ = e["code"].(string)
	b.Error.Reason, _ = e["reason"].(string)
	b.Error.MessageKey, _ = e["message_key"].(string)
	b.Error.Message, _ = e["message"].(string)
	b.Error.RequestID, _ = e["request_id"].(string)
	b.Error.Retryable, _ = e["retryable"].(bool)
	return b
}

func TestLivez(t *testing.T) {
	rec := do(NewHandler(testDeps(t, nil)), http.MethodGet, "/livez", nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"status":"ok"}`, rec.Body.String())
}

func TestHealthzOK(t *testing.T) {
	rec := do(NewHandler(testDeps(t, nil)), http.MethodGet, "/healthz", nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"status":"ok"}`, rec.Body.String())
}

func TestHealthzUnavailableHidesCause(t *testing.T) {
	rec := do(NewHandler(testDeps(t, errors.New("dial tcp postgres: password s3cret-pw rejected"))), http.MethodGet, "/healthz", nil)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.NotContains(t, rec.Body.String(), "s3cret-pw")
	b := decodeErr(t, rec)
	assert.Equal(t, "ALC-SYS-0002", b.Error.Code)
	assert.True(t, b.Error.Retryable)
}

func TestVersionAndLocales(t *testing.T) {
	h := NewHandler(testDeps(t, nil))
	rec := do(h, http.MethodGet, "/api/v1/version", nil)
	assert.Equal(t, http.StatusUnauthorized, rec.Code, "version needs a signed-in user or token")

	rec = call(h, http.MethodGet, "/api/v1/version", "operator", "")
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"version":"1.2.3","commit":"abc","build_time":"t"}`, rec.Body.String())
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	assert.Equal(t, "application/json; charset=utf-8", rec.Header().Get("Content-Type"))

	rec = do(h, http.MethodGet, "/api/v1/i18n/locales", nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"default":"en","locales":[{"code":"en","name":"English","direction":"ltr"},{"code":"tr","name":"Türkçe","direction":"ltr"}]}`, rec.Body.String())
}

func TestUnknownAPIPathIsJSON404InRequestLanguage(t *testing.T) {
	rec := do(NewHandler(testDeps(t, nil)), http.MethodGet, "/api/v1/nope", map[string]string{"Accept-Language": "tr-TR"})
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Equal(t, "application/json; charset=utf-8", rec.Header().Get("Content-Type"))
	b := decodeErr(t, rec)
	assert.Equal(t, "ALC-SYS-0001", b.Error.Code)
	assert.Equal(t, "system.not_found", b.Error.Reason)
	assert.Equal(t, "errors.system.not_found", b.Error.MessageKey)
	assert.Contains(t, b.Error.Message, "bulunamadı")
	assert.Equal(t, rec.Header().Get("X-Request-Id"), b.Error.RequestID)
	assert.NotEmpty(t, b.Error.RequestID)
}

func TestWrongMethodOnAPIRouteIsJSONNotSPA(t *testing.T) {
	// "/api/" is more specific than "/", so a POST to a GET-only API route gets the JSON 404.
	rec := do(NewHandler(testDeps(t, nil)), http.MethodPost, "/api/v1/version", nil)
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Equal(t, "ALC-SYS-0001", decodeErr(t, rec).Error.Code)
}

func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	h := NewHandler(testDeps(t, nil))
	for _, p := range []string{"/livez", "/", "/api/v1/nope", "/assets/app-1a2b.js"} {
		rec := do(h, http.MethodGet, p, nil)
		hdr := rec.Header()
		assert.Equal(t, "max-age=31536000; includeSubDomains", hdr.Get("Strict-Transport-Security"), p)
		assert.Equal(t, "nosniff", hdr.Get("X-Content-Type-Options"), p)
		assert.Equal(t, "DENY", hdr.Get("X-Frame-Options"), p)
		assert.Equal(t, "no-referrer", hdr.Get("Referrer-Policy"), p)
		assert.Equal(t, "same-origin", hdr.Get("Cross-Origin-Opener-Policy"), p)
		assert.Equal(t, "same-origin", hdr.Get("Cross-Origin-Resource-Policy"), p)
		assert.Equal(t, "camera=(), microphone=(), geolocation=()", hdr.Get("Permissions-Policy"), p)
		assert.NotEmpty(t, hdr.Get("Content-Security-Policy"), p)
		assert.NotEmpty(t, hdr.Get("X-Request-Id"), p)
	}
}

var nonceRE = regexp.MustCompile(`content="([A-Za-z0-9+/=]{20,})"`)

func TestIndexGetsFreshNonceMatchingCSP(t *testing.T) {
	h := NewHandler(testDeps(t, nil))
	var nonces []string
	for range 2 {
		rec := do(h, http.MethodGet, "/", nil)
		require.Equal(t, http.StatusOK, rec.Code)
		assert.NotContains(t, rec.Body.String(), "__CSP_NONCE__")
		m := nonceRE.FindStringSubmatch(rec.Body.String())
		require.Len(t, m, 2)
		csp := rec.Header().Get("Content-Security-Policy")
		assert.Equal(t, "default-src 'none'; script-src 'self'; style-src 'self' 'nonce-"+m[1]+"'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'", csp)
		assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
		assert.Equal(t, "text/html; charset=utf-8", rec.Header().Get("Content-Type"))
		nonces = append(nonces, m[1])
	}
	assert.NotEqual(t, nonces[0], nonces[1])
}

func TestClientSideRoutesServeIndex(t *testing.T) {
	rec := do(NewHandler(testDeps(t, nil)), http.MethodGet, "/users/5", nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), `<div id="root">`)
}

func TestAssetsAreCachedAndMissingAssetsAre404(t *testing.T) {
	h := NewHandler(testDeps(t, nil))
	rec := do(h, http.MethodGet, "/assets/app-1a2b.js", nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "public, max-age=31536000, immutable", rec.Header().Get("Cache-Control"))
	assert.Equal(t, "console.log(1)", rec.Body.String())

	rec = do(h, http.MethodGet, "/favicon.svg", nil)
	assert.Equal(t, "no-cache", rec.Header().Get("Cache-Control"))

	rec = do(h, http.MethodGet, "/assets/missing.js", nil)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestPathTraversalNeverEscapesUI(t *testing.T) {
	ui, err := fs.Sub(fstest.MapFS{
		"app/index.html": {Data: []byte(indexHTML)},
		"secret.txt":     {Data: []byte("TOP-SECRET")},
	}, "app")
	require.NoError(t, err)
	d := testDeps(t, nil)
	d.UI = ui
	h := NewHandler(d)
	for _, p := range []string{"/../secret.txt", "/..%2fsecret.txt", "/assets/../../secret.txt"} {
		rec := do(h, http.MethodGet, p, nil)
		assert.NotContains(t, rec.Body.String(), "TOP-SECRET", p)
	}
}

func TestTestPrefixIsJSON404ForAnyMethod(t *testing.T) {
	h := NewHandler(testDeps(t, nil))
	for _, m := range []string{http.MethodGet, http.MethodPost} {
		rec := do(h, m, "/test/clock", nil)
		assert.Equal(t, http.StatusNotFound, rec.Code, m)
		assert.Equal(t, "ALC-SYS-0001", decodeErr(t, rec).Error.Code, m)
	}
}

func TestUINotBuiltShowsHelpfulPage(t *testing.T) {
	d := testDeps(t, nil)
	d.UI = fstest.MapFS{}
	rec := do(NewHandler(d), http.MethodGet, "/", nil)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Contains(t, rec.Body.String(), "make web")
}

func TestPanicBecomesUnexpectedError(t *testing.T) {
	s := &server{deps: testDeps(t, nil)}
	h := s.requestID(securityHeaders(s.recoverer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom s3cret-pw") }))))
	rec := do(h, http.MethodGet, "/x", nil)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.NotContains(t, rec.Body.String(), "s3cret-pw")
	assert.Equal(t, "ALC-SYS-0003", decodeErr(t, rec).Error.Code)
	assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "max-age=31536000; includeSubDomains", rec.Header().Get("Strict-Transport-Security"))
	assert.NotEmpty(t, rec.Header().Get("Content-Security-Policy"))
}

func TestPanicAfterPartialResponseDoesNotAppendJSON(t *testing.T) {
	s := &server{deps: testDeps(t, nil)}
	h := s.requestID(securityHeaders(s.recoverer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<partial>"))
		panic("boom")
	}))))
	srv := httptest.NewServer(h)
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err == nil {
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		assert.NotContains(t, string(body), "ALC-SYS-0003")
	}
}

func TestHealthHandlerExposesOnlyProbes(t *testing.T) {
	h := NewHealthHandler(testDeps(t, nil))
	assert.Equal(t, http.StatusOK, do(h, http.MethodGet, "/healthz", nil).Code)
	assert.Equal(t, http.StatusOK, do(h, http.MethodGet, "/livez", nil).Code)
	assert.Equal(t, http.StatusNotFound, do(h, http.MethodGet, "/api/v1/version", nil).Code)
	assert.False(t, strings.Contains(do(h, http.MethodGet, "/", nil).Body.String(), "root"))
}

func TestDeepLinksWithDotsServeIndex(t *testing.T) {
	h := NewHandler(testDeps(t, nil))
	for _, p := range []string{"/users/a.b", "/users/ali.veli", "/audit/2026.09.30"} {
		rec := do(h, http.MethodGet, p, nil)
		assert.Equal(t, http.StatusOK, rec.Code, p)
		assert.Contains(t, rec.Body.String(), `<div id="root">`, p)
	}
}

func TestMissingAssetsAndRootFilesAre404(t *testing.T) {
	h := NewHandler(testDeps(t, nil))
	for _, p := range []string{"/assets/x.js", "/assets/deep/y.css", "/favicon.ico", "/robots.txt", "/manifest.webmanifest"} {
		rec := do(h, http.MethodGet, p, nil)
		assert.Equal(t, http.StatusNotFound, rec.Code, p)
		assert.NotContains(t, rec.Body.String(), `<div id="root">`, p)
	}
}
