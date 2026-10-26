//go:build integration

package web

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
	"alice/internal/vconsole/audit"
)

// form posts url-encoded values the way a browser form does.
func (e *testEnv) form(path string, v url.Values, cookie *http.Cookie) *httptest.ResponseRecorder {
	e.t.Helper()
	r := httptest.NewRequest(http.MethodPost, e.origin+path, strings.NewReader(v.Encode()))
	r.Host = e.host
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.Header.Set("Origin", e.origin)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	return w
}

var requestPath = regexp.MustCompile(`^/requests/(\d+)$`)

// addCustomer posts the customer form and returns the customer's ID.
func (e *testEnv) addCustomer(c *http.Cookie, name string) int64 {
	e.t.Helper()
	w := e.form("/customers", url.Values{"name": {name}, "contact": {"x@example.test"}, "notes": {"n"}}, c)
	require.Equal(e.t, http.StatusSeeOther, w.Code, w.Body.String())
	var id int64
	require.NoError(e.t, e.d.Owner.QueryRow(context.Background(), `SELECT id FROM customers WHERE lower(name) = lower($1)`, strings.TrimSpace(name)).Scan(&id))
	return id
}

// addRequest posts the request form and returns the new request's path.
func (e *testEnv) addRequest(c *http.Cookie, cid int64, inst string) string {
	e.t.Helper()
	w := e.form("/requests", url.Values{"customer_id": {fmt.Sprint(cid)}, "installation": {inst}, "targets": {"7"}, "months": {"12"}}, c)
	require.Equal(e.t, http.StatusSeeOther, w.Code, w.Body.String())
	loc := w.Header().Get("Location")
	require.Regexp(e.t, requestPath, loc)
	return loc
}

func (e *testEnv) countRows(table string) int {
	var n int
	require.NoError(e.t, e.d.Owner.QueryRow(context.Background(), `SELECT count(*) FROM `+table).Scan(&n))
	return n
}

// seedLicense inserts a request and an issued license through the owner pool; the web service never
// signs, so the tests do not need a signer either.
func (e *testEnv) seedLicense(cid int64, id string, until time.Time, file []byte) {
	e.t.Helper()
	ctx := context.Background()
	var reqID int64
	require.NoError(e.t, e.d.Owner.QueryRow(ctx, `INSERT INTO license_requests (customer_id, installation, targets)
		VALUES ($1, $2, 5) RETURNING id`, cid, license.NewInstallationID()).Scan(&reqID))
	_, err := e.d.Owner.Exec(ctx, `INSERT INTO licenses (license_id, request_id, customer_id, installation, key_id, issued_at,
		valid_from, valid_until, targets, file, file_sha256)
		VALUES ($1, $2, $3, 'inst', 'key1', now() - interval '1 day', now() - interval '1 day', $4, 5, $5, 'sha')`,
		id, reqID, cid, until, file)
	require.NoError(e.t, err)
}

func TestAddCustomerAndRequestThenSeeItListed(t *testing.T) {
	e := newEnv(t, "https://licenses.example.test")
	ayse := e.signIn("ayse")
	cid := e.addCustomer(ayse, "Acme Ltd")
	list := e.do(http.MethodGet, "/customers", "", ayse)
	assert.Equal(t, http.StatusOK, list.Code)
	assert.Contains(t, list.Body.String(), "Acme Ltd")

	inst := license.NewInstallationID()
	loc := e.addRequest(ayse, cid, inst)
	w := e.do(http.MethodGet, loc, "", ayse)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	body := w.Body.String()
	for _, want := range []string{"Acme Ltd", inst, ">7<", "open", "web:ayse"} {
		assert.Contains(t, body, want)
	}
	home := e.do(http.MethodGet, "/", "", ayse)
	assert.Equal(t, http.StatusOK, home.Code)
	assert.Contains(t, home.Body.String(), "Acme Ltd")
	assert.Contains(t, home.Body.String(), loc)

	require.NoError(t, audit.Check(context.Background(), e.owner))
}

func TestRequestFormRejectsWhatCouldNeverBeSigned(t *testing.T) {
	e := newEnv(t, "https://licenses.example.test")
	ayse := e.signIn("ayse")
	cid := e.addCustomer(ayse, "Beta Ltd")
	valid := license.NewInstallationID()
	cases := map[string]url.Values{
		"bad installation": {"installation": {"ALICE-AAAAA-AAAAA"}, "targets": {"5"}, "months": {"12"}},
		"zero targets":     {"installation": {valid}, "targets": {"0"}, "months": {"12"}},
		"61 months":        {"installation": {valid}, "targets": {"5"}, "months": {"61"}},
		"targets not num":  {"installation": {valid}, "targets": {"lots"}, "months": {"12"}},
		"unknown customer": {"installation": {valid}, "targets": {"5"}, "months": {"12"}, "customer_id": {"99999"}},
	}
	for name, v := range cases {
		if v.Get("customer_id") == "" {
			v.Set("customer_id", fmt.Sprint(cid))
		}
		w := e.form("/requests", v, ayse)
		assert.Equal(t, http.StatusUnprocessableEntity, w.Code, name)
		assert.Contains(t, w.Body.String(), `class="alert"`, name)
		assert.Contains(t, w.Body.String(), `<form`, name)
	}
	assert.Zero(t, e.countRows("license_requests"))
}

func TestSecondUserSeesButCannotCancelTheFirstUsersRequest(t *testing.T) {
	e := newEnv(t, "https://licenses.example.test")
	ayse := e.signIn("ayse")
	mehmet := e.signIn("mehmet")
	loc := e.addRequest(ayse, e.addCustomer(ayse, "Gamma Ltd"), license.NewInstallationID())

	assert.Equal(t, http.StatusOK, e.do(http.MethodGet, loc, "", mehmet).Code)
	assert.Equal(t, http.StatusNotFound, e.form(loc+"/cancel", url.Values{}, mehmet).Code)
	assert.Contains(t, e.do(http.MethodGet, loc, "", ayse).Body.String(), "open")

	w := e.form(loc+"/cancel", url.Values{}, ayse)
	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.Contains(t, e.do(http.MethodGet, loc, "", ayse).Body.String(), "cancelled")
}

// TestLicenseListShowsEndDatesAndExpiryFilter: the 30/90-day filters and the order by end date,
// and the end dates printed as UTC dates whatever the machine's zone. The licenses end at 23:30
// UTC, so a zone east of UTC would move them to the next date if a page printed the process's local
// time: the test sets the process's zone to Asia/Tokyo (pgx returns times in time.Local), so it
// discriminates on a UTC CI runner too (R67 Ruling 6; no test in this package runs in parallel).
func TestLicenseListShowsEndDatesAndExpiryFilter(t *testing.T) {
	tokyo, err := time.LoadLocation("Asia/Tokyo")
	require.NoError(t, err)
	old := time.Local
	time.Local = tokyo
	t.Cleanup(func() { time.Local = old })
	e := newEnv(t, "https://licenses.example.test")
	ayse := e.signIn("ayse")
	cid := e.addCustomer(ayse, "Delta Ltd")
	now := time.Now().UTC()
	day := 24 * time.Hour
	late := func(t time.Time) time.Time { return time.Date(t.Year(), t.Month(), t.Day(), 23, 30, 0, 0, time.UTC) }
	near, mid, far := late(now.Add(10*day)), late(now.Add(50*day)), late(now.Add(200*day))
	e.seedLicense(cid, "LIC-FAR", far, []byte("f"))
	e.seedLicense(cid, "LIC-NEAR", near, []byte("n"))
	e.seedLicense(cid, "LIC-MID", mid, []byte("m"))

	body := e.do(http.MethodGet, "/licenses?ending=90", "", ayse).Body.String()
	assert.Contains(t, body, near.Format("2006-01-02"))
	assert.NotContains(t, body, near.AddDate(0, 0, 1).Format("2006-01-02"), "the UTC date, not the machine's")
	assert.Contains(t, body, mid.Format("2006-01-02"))
	assert.NotContains(t, body, far.Format("2006-01-02"))
	assert.NotContains(t, body, "LIC-FAR")
	assert.Less(t, strings.Index(body, "LIC-NEAR"), strings.Index(body, "LIC-MID"))

	all := e.do(http.MethodGet, "/licenses?ending=all", "", ayse).Body.String()
	assert.Contains(t, all, "LIC-FAR")
	assert.Contains(t, all, far.Format("2006-01-02"))
	assert.Less(t, strings.Index(all, "LIC-MID"), strings.Index(all, "LIC-FAR"))

	s30 := e.do(http.MethodGet, "/licenses?ending=30", "", ayse).Body.String()
	assert.Contains(t, s30, "LIC-NEAR")
	assert.NotContains(t, s30, "LIC-MID")

	// The home page shows the ones ending within 90 days.
	home := e.do(http.MethodGet, "/", "", ayse).Body.String()
	assert.Contains(t, home, "LIC-NEAR")
	assert.NotContains(t, home, "LIC-FAR")
}

func TestDownloadReturnsTheExactIssuedBytes(t *testing.T) {
	e := newEnv(t, "https://licenses.example.test")
	ayse := e.signIn("ayse")
	cid := e.addCustomer(ayse, "Eps Ltd")
	file := []byte("{\"payload\":\"x\"}\n\x00\xff exact bytes")
	e.seedLicense(cid, "LIC-2026-123456", time.Now().Add(30*24*time.Hour), file)

	w := e.do(http.MethodGet, "/licenses/LIC-2026-123456/download", "", ayse)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, file, w.Body.Bytes())
	assert.Equal(t, "application/octet-stream", w.Header().Get("Content-Type"))
	assert.Equal(t, `attachment; filename="LIC-2026-123456.alicelic"`, w.Header().Get("Content-Disposition"))
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))

	// Signed out: sent to the login page, no file.
	out := e.do(http.MethodGet, "/licenses/LIC-2026-123456/download", "")
	assert.Equal(t, http.StatusSeeOther, out.Code)
	assert.NotContains(t, out.Body.String(), "exact bytes")
}

func TestDownloadOfUnknownOrOddIDsIs404(t *testing.T) {
	e := newEnv(t, "https://licenses.example.test")
	ayse := e.signIn("ayse")
	for _, id := range []string{"nope", "..%2f..%2fetc%2fpasswd", "a%27b", strings.Repeat("a", 300), "a%20b", "%00"} {
		w := e.do(http.MethodGet, "/licenses/"+id+"/download", "", ayse)
		assert.Equal(t, http.StatusNotFound, w.Code, id)
		b := strings.ToLower(w.Body.String()) //nolint:forbidigo // ASCII needles in a test body
		for _, bad := range []string{"select", "sql", "/etc", "pgx", "licenses"} {
			assert.NotContains(t, b, bad, id)
		}
	}
}

func TestMarkupInCustomerFieldsIsEscaped(t *testing.T) {
	e := newEnv(t, "https://licenses.example.test")
	ayse := e.signIn("ayse")
	xss := "<script>alert(1)</script>"
	cid := e.addCustomer(ayse, xss)
	for _, p := range []string{"/customers", e.addRequest(ayse, cid, license.NewInstallationID())} {
		body := e.do(http.MethodGet, p, "", ayse).Body.String()
		assert.Contains(t, body, "&lt;script&gt;", p)
		assert.NotContains(t, body, "<script>alert", p)
	}
}

func TestSalesWebCannotSign(t *testing.T) {
	e := newEnv(t, "https://licenses.example.test")
	ayse := e.signIn("ayse")
	cid := e.addCustomer(ayse, "Zeta Ltd")
	var reqID int64
	ctx := context.Background()
	require.NoError(t, e.d.Owner.QueryRow(ctx, `INSERT INTO license_requests (customer_id, installation, targets)
		VALUES ($1, $2, 5) RETURNING id`, cid, license.NewInstallationID()).Scan(&reqID))
	_, err := e.web.Exec(ctx, `INSERT INTO licenses (license_id, request_id, customer_id, installation, key_id, issued_at,
		valid_from, valid_until, targets, file, file_sha256)
		VALUES ('LIC-X', $1, $2, 'i', 'k', now(), now(), now(), 1, 'x', 's')`, reqID, cid)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "permission denied")
}

func TestPagesNeedASessionAndUnknownPathsStay404(t *testing.T) {
	e := newEnv(t, "https://licenses.example.test")
	ayse := e.signIn("ayse")
	for _, p := range []string{"/", "/customers", "/requests/new", "/requests/1", "/licenses", "/licenses/x/download"} {
		w := e.do(http.MethodGet, p, "")
		assert.Equal(t, http.StatusSeeOther, w.Code, p)
		assert.Equal(t, "/login", w.Header().Get("Location"), p)
	}
	assert.Equal(t, http.StatusNotFound, e.do(http.MethodGet, "/nowhere", "", ayse).Code)
	assert.Equal(t, http.StatusNotFound, e.do(http.MethodGet, "/requests/abc", "", ayse).Code)
	assert.Equal(t, http.StatusNotFound, e.do(http.MethodGet, "/requests/999", "", ayse).Code)
}

func TestFormBodiesAreCapped(t *testing.T) {
	e := newEnv(t, "https://licenses.example.test")
	ayse := e.signIn("ayse")
	w := e.form("/customers", url.Values{"name": {"x"}, "notes": {strings.Repeat("a", 70<<10)}}, ayse)
	assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
	assert.Zero(t, e.countRows("customers"))
}

func TestDuplicateCustomerIsRefusedWithAMessage(t *testing.T) {
	e := newEnv(t, "https://licenses.example.test")
	ayse := e.signIn("ayse")
	e.addCustomer(ayse, "Dup Ltd")
	w := e.form("/customers", url.Values{"name": {"dup ltd"}}, ayse)
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
	assert.Contains(t, w.Body.String(), "already exists")
	assert.Equal(t, 1, e.countRows("customers"))
}
