package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/alerts"
	"alice/internal/audit"
	"alice/internal/inventory"
	"alice/internal/license"
	"alice/internal/notify"
	"alice/internal/platform/settings"
	"alice/internal/platform/validate"
	"alice/internal/rbac"
	"alice/internal/reports"
)

func phase7Deps(t *testing.T) (Deps, *fakeMail, *fakeAlerts, *fakeReports) {
	t.Helper()
	d := testDeps(t, nil)
	fm, fa, fr := &fakeMail{}, &fakeAlerts{}, &fakeReports{}
	d.Mail, d.Alerts, d.Reports = fm, fa, fr
	return d, fm, fa, fr
}

// phase7Calls are the routes of this task with a body and headers the handler accepts.
func phase7Calls() map[string]routeCall {
	v := map[string]string{"If-Match": `"1"`}
	return map[string]routeCall{
		"GET /api/v1/dashboard/summary":              {},
		"GET /api/v1/dashboard/expiring":             {},
		"GET /api/v1/alerts":                         {},
		"GET /api/v1/notifications/status":           {},
		"GET /api/v1/certificates/export":            {},
		"GET /api/v1/ssh-keys/export":                {},
		"GET /api/v1/views":                          {},
		"POST /api/v1/views":                         {body: `{"page":"certificates","name":"x","query":{}}`},
		"DELETE /api/v1/views/{id}":                  {},
		"GET /api/v1/settings/smtp":                  {},
		"PUT /api/v1/settings/smtp":                  {body: `{"host":"smtp.example.com","port":587,"tls_mode":"starttls","from":"a@example.com","username":"","ca_pem":""}`, hdr: v},
		"DELETE /api/v1/settings/smtp":               {hdr: v},
		"POST /api/v1/settings/smtp/actions/test":    {body: `{"to":"ops@example.com"}`},
		"POST /api/v1/settings/smtp/actions/trust":   {body: `{"fingerprint":"` + strings.Repeat("ab", 32) + `"}`, hdr: v},
		"POST /api/v1/settings/smtp/actions/untrust": {hdr: v},
		"GET /api/v1/settings/notifications":         {},
		"PUT /api/v1/settings/notifications":         {body: `{"administrators":true,"addresses":[]}`, hdr: v},
		"GET /api/v1/settings/alerts":                {},
		"PUT /api/v1/settings/alerts":                {body: `{"thresholds_days":[30,7]}`, hdr: v},
		"GET /api/v1/settings/general":               {},
		"PUT /api/v1/settings/general":               {body: `{"public_url":"","retired_key_retention_days":30}`, hdr: v},
	}
}

// phase7Queries are the query strings a route needs to be accepted.
var phase7Queries = map[string]string{"GET /api/v1/views": "?page=certificates"}

// Review Focus 5: every Phase 7 route of this task, as every identity, in and out of lock: a refused request never
// reaches a service; an allowed one does; settings need an Administrator with step-up; exports and the dashboard work
// in lock.
func TestPhase7RoutesAuthz(t *testing.T) {
	calls := phase7Calls()
	for _, locked := range []bool{false, true} {
		d, fm, fa, fr := phase7Deps(t)
		fm.succeed()
		fa.succeed()
		fr.succeed()
		if locked {
			d.License.(*fakeLicense).set(license.ErrLocked)
		}
		s := newServer(d)
		h := s.handler(s.apiRoutes())
		seen := 0
		for _, rt := range s.apiRoutes() {
			key := rt.method + " " + rt.pattern
			c, ok := calls[key]
			if !ok {
				continue
			}
			seen++
			target := pathParamRE.ReplaceAllString(rt.pattern, uuid.NewString()) + phase7Queries[key]
			for _, id := range identities {
				(&Server{s: s}).ResetLimits()
				fm.reset()
				fa.reset()
				fr.reset()
				rec := callWith(h, rt.method, target, id, c.body, c.hdr)
				want := expectedMatrix[rt.perm][id]
				name := key + " as " + id
				switch want {
				case allw:
					assert.Less(t, rec.Code, 300, "%s (locked %v): %s", name, locked, rec.Body.String())
					if key != "GET /api/v1/notifications/status" || strings.Contains(id, "admin") {
						assert.Positive(t, fm.calls()+fa.calls()+fr.calls(), "an allowed request reaches its service: %s", name)
					}
				case step:
					assert.Equal(t, "ALC-AUTH-0003", decodeErr(t, rec).Error.Code, name)
				default:
					assert.Equal(t, want, rec.Code, name)
				}
				if want != allw {
					assert.Zero(t, fm.calls()+fa.calls()+fr.calls(), "a refused request has no side effect: %s", name)
				}
			}
		}
		assert.Equal(t, len(calls), seen, "every Phase 7 route of this task is in the table")
	}
}

func TestDashboardIsRoleFiltered(t *testing.T) {
	d, _, _, fr := phase7Deps(t)
	fr.succeed()
	s := newServer(d)
	h := s.handler(s.apiRoutes())
	rec := callWith(h, http.MethodGet, "/api/v1/dashboard/summary", "operator", "", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, rbac.Operator, fr.lastViewer.Role, "the viewer is the caller")
	assert.Equal(t, operatorID, fr.lastViewer.UserID)
	rec = callWith(h, http.MethodGet, "/api/v1/notifications/status", "operator", "", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"failing":false}`, rec.Body.String(), "only Administrators see the delivery state")
	rec = callWith(h, http.MethodGet, "/api/v1/dashboard/expiring?days=0", "admin", "", nil)
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
}

// F-62 over HTTP: an untrusted certificate is a 502 with the certificate's facts and nothing of the server's text.
func TestTestMailAnswers(t *testing.T) {
	d, fm, _, _ := phase7Deps(t)
	s := newServer(d)
	h := s.handler(s.apiRoutes())
	fm.TestMailFn = func(context.Context, audit.Actor, string, string) error {
		return &notify.CertError{Cert: notify.CertInfo{Fingerprint: strings.Repeat("cd", 32), Subject: "CN=mail.example.com",
			NotAfter: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)}}
	}
	rec := callWith(h, http.MethodPost, "/api/v1/settings/smtp/actions/test", "admin-stepup", `{"to":"ops@example.com"}`, nil)
	require.Equal(t, http.StatusBadGateway, rec.Code)
	e := decodeErr(t, rec).Error
	assert.Equal(t, "ALC-NTF-0005", e.Code)
	params := decodeMap(t, rec.Body.Bytes())["error"].(map[string]any)["params"].(map[string]any)
	assert.Equal(t, strings.Repeat("cd", 32), params["fingerprint"])
	assert.Equal(t, "CN=mail.example.com", params["subject"])
	assert.Equal(t, "2027-01-01T00:00:00Z", params["not_after"])
	fm.TestMailFn = func(context.Context, audit.Actor, string, string) error { return notify.ErrSMTPAuth }
	rec = callWith(h, http.MethodPost, "/api/v1/settings/smtp/actions/test", "admin-stepup", `{"to":"ops@example.com"}`, nil)
	assert.Equal(t, "ALC-NTF-0006", decodeErr(t, rec).Error.Code)
	for i := 0; i < 5; i++ {
		callWith(h, http.MethodPost, "/api/v1/settings/smtp/actions/test", "admin-stepup", `{"to":"ops@example.com"}`, nil)
	}
	rec = callWith(h, http.MethodPost, "/api/v1/settings/smtp/actions/test", "admin-stepup", `{"to":"ops@example.com"}`, nil)
	assert.Equal(t, http.StatusTooManyRequests, rec.Code, "5 per minute per user")
	rec = callWith(h, http.MethodPost, "/api/v1/settings/smtp/actions/test", "admin2-stepup", `{"to":"ops@example.com"}`, nil)
	assert.Equal(t, http.StatusBadGateway, rec.Code, "another Administrator has a limit of their own")
}

// Review Focus 3: the SMTP password is write-only and zeroed on every path; the answer says only has_password.
func TestSMTPPasswordIsWriteOnly(t *testing.T) {
	d, fm, _, _ := phase7Deps(t)
	s := newServer(d)
	h := s.handler(s.apiRoutes())
	var seen []byte
	onSecretBytes = func(b []byte) { seen = b }
	t.Cleanup(func() { onSecretBytes = nil })
	fm.SaveSMTPFn = func(_ context.Context, _ audit.Actor, version int, in notify.SMTPInput) (notify.SMTPSettings, error) {
		assert.Equal(t, 0, version)
		require.NotNil(t, in.Password)
		assert.Equal(t, "CANARY-pw", string(in.Password.Bytes()))
		return notify.SMTPSettings{Host: "smtp.example.com", Port: 587, TLSMode: "starttls", From: "a@example.com", HasPassword: true, Version: 1}, nil
	}
	rec := callWith(h, http.MethodPut, "/api/v1/settings/smtp", "admin-stepup",
		`{"host":"smtp.example.com","port":587,"tls_mode":"starttls","from":"a@example.com","username":"u","password":"CANARY-pw","ca_pem":""}`,
		map[string]string{"If-Match": `"0"`})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, `"1"`, rec.Header().Get("ETag"))
	assert.NotContains(t, rec.Body.String(), "CANARY")
	assert.Contains(t, rec.Body.String(), `"has_password":true`)
	assert.Equal(t, make([]byte, len("CANARY-pw")), seen, "the password bytes were zeroed")
	rec = callWith(h, http.MethodPut, "/api/v1/settings/smtp", "admin-stepup", `{"host":"x","port":1,"tls_mode":"tls","from":"a@example.com","username":"","ca_pem":""}`, nil)
	assert.Equal(t, http.StatusPreconditionFailed, rec.Code, "a change needs If-Match")
	assert.Equal(t, "ALC-SYS-0008", decodeErr(t, rec).Error.Code)

	// The service's refusal is zeroed too, and its field errors reach the answer (Task 6: a user name needs a password).
	seen = nil
	fm.SaveSMTPFn = func(context.Context, audit.Actor, int, notify.SMTPInput) (notify.SMTPSettings, error) {
		return notify.SMTPSettings{}, validate.Errors{{Field: "password", Code: validate.Required}}
	}
	rec = callWith(h, http.MethodPut, "/api/v1/settings/smtp", "admin-stepup",
		`{"host":"smtp.example.com","port":587,"tls_mode":"starttls","from":"a@example.com","username":"u","password":"CANARY-2","ca_pem":""}`,
		map[string]string{"If-Match": `"3"`})
	require.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	assert.Contains(t, rec.Body.String(), `"field":"password"`)
	assert.NotContains(t, rec.Body.String(), "CANARY")
	assert.Equal(t, make([]byte, len("CANARY-2")), seen)

	// Absent keeps (nil), "" removes (an empty plaintext).
	var got []*[]byte
	fm.SaveSMTPFn = func(_ context.Context, _ audit.Actor, _ int, in notify.SMTPInput) (notify.SMTPSettings, error) {
		if in.Password == nil {
			got = append(got, nil)
		} else {
			b := in.Password.Bytes()
			got = append(got, &b)
		}
		return notify.SMTPSettings{Version: 4}, nil
	}
	for _, body := range []string{
		`{"host":"h","port":25,"tls_mode":"tls","from":"a@example.com","username":"","ca_pem":""}`,
		`{"host":"h","port":25,"tls_mode":"tls","from":"a@example.com","username":"","password":"","ca_pem":""}`,
		`{"host":"h","port":25,"tls_mode":"tls","from":"a@example.com","username":"","password":null,"ca_pem":""}`,
	} {
		rec = callWith(h, http.MethodPut, "/api/v1/settings/smtp", "admin-stepup", body, map[string]string{"If-Match": `"3"`})
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	}
	require.Len(t, got, 3)
	assert.Nil(t, got[0], "no password key keeps the stored one")
	require.NotNil(t, got[1])
	assert.Empty(t, *got[1], `"" removes the password`)
	assert.Nil(t, got[2], "null keeps the stored one")
	rec = callWith(h, http.MethodPut, "/api/v1/settings/smtp", "admin-stepup", `{"host":"h","Password":"x"}`, map[string]string{"If-Match": `"3"`})
	assert.Equal(t, http.StatusBadRequest, rec.Code, "keys are exact")
}

func TestExportHandlerHeadersAndRefusal(t *testing.T) {
	d, _, _, fr := phase7Deps(t)
	s := newServer(d)
	h := s.handler(s.apiRoutes())
	fr.ExportCertificatesFn = func(_ context.Context, a audit.Actor, f inventory.CertificateFilter, w io.Writer) (int, error) {
		assert.Equal(t, "30", f.Expiry)
		assert.Equal(t, auditorID, a.ID)
		assert.Empty(t, f.Cursor)
		assert.Zero(t, f.Limit)
		_, err := w.Write([]byte("\xEF\xBB\xBFid\n"))
		return 0, err
	}
	rec := callWith(h, http.MethodGet, "/api/v1/certificates/export?expiry=30", "auditor", "", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "text/csv; charset=utf-8", rec.Header().Get("Content-Type"))
	assert.Regexp(t, `^attachment; filename="alice-certificates-\d{4}-\d{2}-\d{2}\.csv"$`, rec.Header().Get("Content-Disposition"))
	assert.Equal(t, `attachment; filename="alice-certificates-2026-09-30.csv"`, rec.Header().Get("Content-Disposition"))
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "\xEF\xBB\xBFid\n", rec.Body.String())
	fr.ExportCertificatesFn = func(context.Context, audit.Actor, inventory.CertificateFilter, io.Writer) (int, error) {
		return 0, reports.ErrTooLarge
	}
	rec = callWith(h, http.MethodGet, "/api/v1/certificates/export", "alice_read_auditor", "", nil)
	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.Equal(t, "ALC-RPT-0001", decodeErr(t, rec).Error.Code)
	assert.Equal(t, "application/json; charset=utf-8", rec.Header().Get("Content-Type"))
	assert.Empty(t, rec.Header().Get("Content-Disposition"))
	rec = callWith(h, http.MethodGet, "/api/v1/certificates/export?cursor=abc", "admin", "", nil)
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code, "an export is never a page")
	rec = callWith(h, http.MethodGet, "/api/v1/certificates/export?limit=10", "admin", "", nil)
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code, "an export is never a page")
	rec = callWith(h, http.MethodGet, "/api/v1/certificates/export?expiry=45", "admin", "", nil)
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	fr.ExportCertificatesFn = func(context.Context, audit.Actor, inventory.CertificateFilter, io.Writer) (int, error) {
		return 0, reports.ErrExportBusy
	}
	rec = callWith(h, http.MethodGet, "/api/v1/certificates/export", "admin", "", nil)
	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.Equal(t, "ALC-RPT-0004", decodeErr(t, rec).Error.Code)
	assert.True(t, decodeErr(t, rec).Error.Retryable)
	assert.Equal(t, "5", rec.Header().Get("Retry-After"))
}

// B5 (Task 10's values): the API accepts the new windows and the Key Vault source on the list and on the export.
func TestCertificateFiltersAcceptTheNewWindowsAndKeyVault(t *testing.T) {
	d, _, _, fr := phase7Deps(t)
	inv := &fakeInventory{}
	d.Inventory = inv
	var listed []inventory.CertificateFilter
	inv.ListCertificatesFn = func(_ context.Context, f inventory.CertificateFilter) (inventory.CertificatePage, error) {
		listed = append(listed, f)
		return inventory.CertificatePage{}, nil
	}
	var exported []inventory.CertificateFilter
	fr.ExportCertificatesFn = func(_ context.Context, _ audit.Actor, f inventory.CertificateFilter, w io.Writer) (int, error) {
		exported = append(exported, f)
		_, err := w.Write([]byte("x"))
		return 1, err
	}
	s := newServer(d)
	h := s.handler(s.apiRoutes())
	for _, e := range []string{"expired", "7", "14", "30", "60", "90"} {
		for _, path := range []string{"/api/v1/certificates", "/api/v1/certificates/export"} {
			rec := callWith(h, http.MethodGet, path+"?source=azure_kv&expiry="+e, "operator", "", nil)
			assert.Equal(t, http.StatusOK, rec.Code, path+" "+e+": "+rec.Body.String())
		}
	}
	require.Len(t, listed, 6)
	require.Len(t, exported, 6)
	assert.Equal(t, "azure_kv", exported[1].Source)
	assert.Equal(t, "7", exported[1].Expiry)
	for _, q := range []string{"expiry=45", "source=vault", "target_id=x", "q=" + strings.Repeat("a", 201)} {
		rec := callWith(h, http.MethodGet, "/api/v1/certificates?"+q, "operator", "", nil)
		assert.Equal(t, http.StatusUnprocessableEntity, rec.Code, q)
	}
}

func TestExportSSHKeys(t *testing.T) {
	d, _, _, fr := phase7Deps(t)
	s := newServer(d)
	h := s.handler(s.apiRoutes())
	target := uuid.New()
	fr.ExportSSHKeysFn = func(_ context.Context, _ audit.Actor, f inventory.KeyFilter, w io.Writer) (int, error) {
		assert.Equal(t, inventory.KeyFilter{TargetID: target, OSUser: "root", Query: "ci", Flag: "weak", IncludeMissing: true}, f)
		_, err := w.Write([]byte("\xEF\xBB\xBFid\n"))
		return 0, err
	}
	rec := callWith(h, http.MethodGet, "/api/v1/ssh-keys/export?target_id="+target.String()+"&os_user=root&q=ci&flag=weak&missing=true",
		"alice_read_admin", "", nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, `attachment; filename="alice-ssh-keys-2026-09-30.csv"`, rec.Header().Get("Content-Disposition"))
	for _, q := range []string{"cursor=a", "limit=5", "flag=nope", "missing=maybe", "os_user=" + strings.Repeat("u", 33)} {
		rec = callWith(h, http.MethodGet, "/api/v1/ssh-keys/export?"+q, "admin", "", nil)
		assert.Equal(t, http.StatusUnprocessableEntity, rec.Code, q)
	}
	// 10 exports per minute per identity.
	(&Server{s: s}).ResetLimits()
	for i := 0; i < 10; i++ {
		rec = callWith(h, http.MethodGet, "/api/v1/ssh-keys/export?target_id="+target.String()+"&os_user=root&q=ci&flag=weak&missing=true",
			"alice_read_admin", "", nil)
		require.Equal(t, http.StatusOK, rec.Code)
	}
	rec = callWith(h, http.MethodGet, "/api/v1/ssh-keys/export", "alice_read_admin", "", nil)
	assert.Equal(t, http.StatusTooManyRequests, rec.Code)
}

// A failure after the first byte never ends the file as if it were complete: the connection is aborted.
func TestExportFailureAfterTheFirstByteAborts(t *testing.T) {
	d, _, _, fr := phase7Deps(t)
	s := newServer(d)
	h := s.handler(s.apiRoutes())
	fr.ExportCertificatesFn = func(_ context.Context, _ audit.Actor, _ inventory.CertificateFilter, w io.Writer) (int, error) {
		_, _ = w.Write([]byte("\xEF\xBB\xBFid\n"))
		return 1, context.Canceled
	}
	assert.PanicsWithValue(t, http.ErrAbortHandler, func() {
		callWith(h, http.MethodGet, "/api/v1/certificates/export", "admin", "", nil)
	})
}

func TestViewsHandlers(t *testing.T) {
	d, _, _, fr := phase7Deps(t)
	s := newServer(d)
	h := s.handler(s.apiRoutes())
	at := time.Date(2026, 9, 1, 8, 0, 0, 0, time.FixedZone("x", 3600))
	viewID := uuid.New()
	fr.ViewsFn = func(_ context.Context, userID uuid.UUID, page string) ([]reports.View, error) {
		assert.Equal(t, operatorID, userID)
		assert.Equal(t, reports.PageSSHKeys, page)
		return []reports.View{{ID: viewID, Page: page, Name: "root keys", Query: map[string]string{"os_user": "root"}, CreatedAt: at},
			{ID: viewID, Page: page, Name: "all", CreatedAt: at}}, nil
	}
	rec := callWith(h, http.MethodGet, "/api/v1/views?page=ssh_keys", "operator", "", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"items":[{"id":"`+viewID.String()+`","page":"ssh_keys","name":"root keys","query":{"os_user":"root"},"created_at":"2026-09-01T07:00:00Z"},
		{"id":"`+viewID.String()+`","page":"ssh_keys","name":"all","query":{},"created_at":"2026-09-01T07:00:00Z"}]}`, rec.Body.String())
	for _, q := range []string{"", "?page=targets"} {
		rec = callWith(h, http.MethodGet, "/api/v1/views"+q, "operator", "", nil)
		assert.Equal(t, http.StatusUnprocessableEntity, rec.Code, q)
		assert.Contains(t, rec.Body.String(), `"field":"page"`)
	}

	fr.CreateViewFn = func(_ context.Context, userID uuid.UUID, page, name string, query map[string]string) (reports.View, error) {
		assert.Equal(t, auditorID, userID)
		assert.Equal(t, map[string]string{"expiry": "7"}, query)
		return reports.View{ID: viewID, Page: page, Name: name, Query: query, CreatedAt: at}, nil
	}
	rec = callWith(h, http.MethodPost, "/api/v1/views", "auditor", `{"page":"certificates","name":"soon","query":{"expiry":"7"}}`, nil)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), `"name":"soon"`)
	for _, c := range []struct {
		err  error
		code string
	}{{reports.ErrViewLimit, "ALC-RPT-0002"}, {reports.ErrViewName, "ALC-RPT-0003"}} {
		fr.CreateViewFn = func(context.Context, uuid.UUID, string, string, map[string]string) (reports.View, error) {
			return reports.View{}, c.err
		}
		rec = callWith(h, http.MethodPost, "/api/v1/views", "auditor", `{"page":"certificates","name":"soon","query":{}}`, nil)
		assert.Equal(t, http.StatusConflict, rec.Code)
		assert.Equal(t, c.code, decodeErr(t, rec).Error.Code)
	}
	fr.CreateViewFn = func(context.Context, uuid.UUID, string, string, map[string]string) (reports.View, error) {
		return reports.View{}, reports.ErrViewLimit
	}
	rec = callWith(h, http.MethodPost, "/api/v1/views", "auditor", `{"page":"certificates","name":"a","query":{}}`, nil)
	assert.Equal(t, map[string]any{"max": "50"}, decodeMap(t, rec.Body.Bytes())["error"].(map[string]any)["params"])
	rec = callWith(h, http.MethodPost, "/api/v1/views", "auditor", `{"page":"certificates","name":"a","query":{"expiry":7}}`, nil)
	assert.Equal(t, http.StatusBadRequest, rec.Code, "query values are strings")
	rec = callWith(h, http.MethodPost, "/api/v1/views", "auditor", `{"page":"certificates","name":"a","filters":{}}`, nil)
	assert.Equal(t, http.StatusBadRequest, rec.Code, "keys are exact")

	fr.DeleteViewFn = func(_ context.Context, userID, id uuid.UUID) error {
		assert.Equal(t, adminID, userID)
		if id == viewID {
			return nil
		}
		return reports.ErrNotFound
	}
	rec = callWith(h, http.MethodDelete, "/api/v1/views/"+viewID.String(), "admin", "", nil)
	assert.Equal(t, http.StatusNoContent, rec.Code)
	rec = callWith(h, http.MethodDelete, "/api/v1/views/"+uuid.NewString(), "admin", "", nil)
	assert.Equal(t, http.StatusNotFound, rec.Code, "another user's view is not found")
	rec = callWith(h, http.MethodDelete, "/api/v1/views/not-a-uuid", "admin", "", nil)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// C13's DashboardSummary for an Administrator, field by field (web/src/api/phase7.ts compiles against it).
func TestDashboardSummaryJSON(t *testing.T) {
	d, _, _, fr := phase7Deps(t)
	s := newServer(d)
	h := s.handler(s.apiRoutes())
	at := time.Date(2026, 9, 29, 10, 30, 0, 0, time.FixedZone("x", 7200))
	days := 12
	depID, tgtID, polID, keyID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	fr.SummaryFn = func(context.Context, reports.Viewer) (reports.Summary, error) {
		return reports.Summary{
			GeneratedAt:  at,
			Certificates: alertsCounts(),
			Deployments: reports.DeploymentSummary{Failed7d: 2, Recent: []reports.FailedDeployment{{ID: depID, CertificateName: "www",
				TargetID: tgtID, TargetName: "web-01", Status: "failed", ErrorCode: "ALC-DEP-0003", At: at}}},
			Targets:       reports.TargetSummary{Total: 3, ByStatus: map[string]int{"ok": 2, "unreachable": 1}},
			License:       reports.LicenseSummary{Phase: "valid", EndsAt: &at, DaysLeft: &days},
			Rotation:      reports.RotationSummary{Upcoming: []reports.UpcomingRotation{{PolicyID: polID, SSHKeyID: keyID, KeyLabel: "ci", NextRunAt: at}}, Running: 1, NeedsAttention: 1},
			Notifications: &notify.Delivery{ConsecutiveFailures: 3, LastFailureAt: &at, LastFailureCode: "smtp.connect", Pending: 4, Failed24h: 2},
			Audit:         &reports.AuditHead{HeadSeq: 42, HeadHash: "ab12", CheckedAt: at, Intact: true},
			Attention:     5,
		}, nil
	}
	rec := callWith(h, http.MethodGet, "/api/v1/dashboard/summary", "admin", "", nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.JSONEq(t, `{"generated_at":"2026-09-29T08:30:00Z",
		"certificates":{"monitored":10,"expired":1,"within_7":2,"within_30":3,"within_60":4,"kv_expired":5,"kv_within_30":6},
		"deployments":{"failed_7d":2,"recent":[{"id":"`+depID.String()+`","certificate_name":"www","target_id":"`+tgtID.String()+`",
			"target_name":"web-01","status":"failed","error_code":"ALC-DEP-0003","at":"2026-09-29T08:30:00Z"}]},
		"targets":{"total":3,"by_status":{"ok":2,"unreachable":1}},
		"license":{"expired":false,"phase":"valid","ends_at":"2026-09-29T08:30:00Z","days_left":12},
		"rotation":{"upcoming":[{"policy_id":"`+polID.String()+`","ssh_key_id":"`+keyID.String()+`","key_label":"ci","next_run_at":"2026-09-29T08:30:00Z"}],
			"running":1,"needs_attention":1},
		"notifications":{"failing":true,"consecutive_failures":3,"last_failure_at":"2026-09-29T08:30:00Z","last_failure_code":"smtp.connect",
			"last_success_at":null,"pending":4,"failed_24h":2},
		"audit":{"head_seq":42,"head_hash":"ab12","checked_at":"2026-09-29T08:30:00Z","intact":true},
		"attention":5}`, rec.Body.String())

	// An Operator's summary: the role-filtered parts are null, every list is a list.
	fr.SummaryFn = func(context.Context, reports.Viewer) (reports.Summary, error) {
		return reports.Summary{GeneratedAt: at, License: reports.LicenseSummary{Expired: true}}, nil
	}
	rec = callWith(h, http.MethodGet, "/api/v1/dashboard/summary", "operator", "", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"generated_at":"2026-09-29T08:30:00Z",
		"certificates":{"monitored":0,"expired":0,"within_7":0,"within_30":0,"within_60":0,"kv_expired":0,"kv_within_30":0},
		"deployments":{"failed_7d":0,"recent":[]},"targets":{"total":0,"by_status":{}},
		"license":{"expired":true,"phase":"","ends_at":null,"days_left":null},
		"rotation":{"upcoming":[],"running":0,"needs_attention":0},"notifications":null,"audit":null,"attention":0}`, rec.Body.String())

	fr.SummaryFn = func(context.Context, reports.Viewer) (reports.Summary, error) {
		return reports.Summary{}, errNotConfigured
	}
	rec = callWith(h, http.MethodGet, "/api/v1/dashboard/summary", "operator", "", nil)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestExpiringAndAlertsJSON(t *testing.T) {
	d, _, _, fr := phase7Deps(t)
	s := newServer(d)
	h := s.handler(s.apiRoutes())
	certID, vaultID, kvID, tgt := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	fr.ExpiringFn = func(_ context.Context, days, limit int) ([]alerts.Item, error) {
		assert.Equal(t, 7, days)
		assert.Equal(t, 20, limit)
		return []alerts.Item{
			{Kind: alerts.KindCertificate, ObjectID: certID, Name: "www.example.com", ExpiresAt: testNow.Add(-time.Hour), Fingerprint: "ff",
				Websites: []string{"www.example.com"}, Servers: []string{"web-01"}, TargetIDs: []uuid.UUID{tgt}},
			{Kind: alerts.KindKVKey, ObjectID: kvID, Name: "signing", ExpiresAt: testNow.Add(50 * time.Hour), Vault: "prod", VaultID: vaultID},
		}, nil
	}
	rec := callWith(h, http.MethodGet, "/api/v1/dashboard/expiring?days=7&limit=20", "auditor", "", nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.JSONEq(t, `{"items":[
		{"kind":"certificate_expiry","object_id":"`+certID.String()+`","name":"www.example.com","expires_at":"2026-09-30T11:00:00Z",
		 "days_left":0,"expired":true,"fingerprint":"ff","websites":["www.example.com"],"servers":["web-01"],"target_ids":["`+tgt.String()+`"],
		 "vault":"","vault_id":null},
		{"kind":"kv_key_expiry","object_id":"`+kvID.String()+`","name":"signing","expires_at":"2026-10-02T14:00:00Z",
		 "days_left":3,"expired":false,"fingerprint":"","websites":[],"servers":[],"target_ids":[],"vault":"prod","vault_id":"`+vaultID.String()+`"}]}`,
		rec.Body.String())
	fr.ExpiringFn = func(_ context.Context, days, limit int) ([]alerts.Item, error) {
		assert.Equal(t, 30, days, "the default window")
		assert.Equal(t, 50, limit, "the default limit")
		return nil, nil
	}
	rec = callWith(h, http.MethodGet, "/api/v1/dashboard/expiring", "auditor", "", nil)
	assert.JSONEq(t, `{"items":[]}`, rec.Body.String())
	for _, q := range []string{"days=366", "days=x", "limit=0", "limit=201"} {
		rec = callWith(h, http.MethodGet, "/api/v1/dashboard/expiring?"+q, "auditor", "", nil)
		assert.Equal(t, http.StatusUnprocessableEntity, rec.Code, q)
	}

	since := time.Date(2026, 9, 28, 1, 2, 3, 0, time.UTC)
	fr.AttentionFn = func(_ context.Context, v reports.Viewer) ([]reports.Condition, error) {
		assert.Equal(t, rbac.Auditor, v.Role)
		return []reports.Condition{{Kind: reports.CondAuditBroken, Since: since}, {Kind: reports.CondAuthFailed, ObjectID: tgt.String(), Name: "web-01",
			Since: since, ErrorCode: "ALC-SSH-0002"}}, nil
	}
	rec = callWith(h, http.MethodGet, "/api/v1/alerts", "alice_read_auditor", "", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"items":[{"kind":"audit_broken","object_id":"","name":"","since":"2026-09-28T01:02:03Z","error_code":""},
		{"kind":"auth_failed","object_id":"`+tgt.String()+`","name":"web-01","since":"2026-09-28T01:02:03Z","error_code":"ALC-SSH-0002"}]}`, rec.Body.String())
	fr.AttentionFn = func(context.Context, reports.Viewer) ([]reports.Condition, error) { return nil, nil }
	rec = callWith(h, http.MethodGet, "/api/v1/alerts", "operator", "", nil)
	assert.JSONEq(t, `{"items":[]}`, rec.Body.String())
}

// The failing banner's source: an Administrator gets the delivery state with the last error code (Task 7 review).
func TestNotificationStatusForAdministrators(t *testing.T) {
	d, fm, _, _ := phase7Deps(t)
	s := newServer(d)
	h := s.handler(s.apiRoutes())
	ok := time.Date(2026, 9, 30, 9, 0, 0, 0, time.UTC)
	fm.DeliveryFn = func(context.Context) (notify.Delivery, error) {
		return notify.Delivery{ConsecutiveFailures: 1, LastFailureCode: "smtp.auth", LastSuccessAt: &ok}, nil
	}
	rec := callWith(h, http.MethodGet, "/api/v1/notifications/status", "alice_read_admin", "", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"failing":false,"consecutive_failures":1,"last_failure_at":null,"last_failure_code":"smtp.auth",
		"last_success_at":"2026-09-30T09:00:00Z","pending":0,"failed_24h":0}`, rec.Body.String())
	fm.DeliveryFn = func(context.Context) (notify.Delivery, error) { return notify.Delivery{}, errNotConfigured }
	rec = callWith(h, http.MethodGet, "/api/v1/notifications/status", "admin", "", nil)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestSMTPSettingsHandlers(t *testing.T) {
	d, fm, _, _ := phase7Deps(t)
	s := newServer(d)
	h := s.handler(s.apiRoutes())
	fm.SMTPFn = func(context.Context) (notify.SMTPSettings, bool, error) { return notify.SMTPSettings{}, false, nil }
	rec := callWith(h, http.MethodGet, "/api/v1/settings/smtp", "admin-stepup", "", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, `"0"`, rec.Header().Get("ETag"))
	assert.JSONEq(t, `{"configured":false,"host":"","port":0,"tls_mode":"","from":"","username":"","has_password":false,"ca_pem":"",
		"trusted_certificate":null,"version":0,"updated_at":null}`, rec.Body.String())

	at := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	stored := notify.SMTPSettings{Host: "smtp.example.com", Port: 465, TLSMode: "tls", From: "alice@example.com", Username: "alice",
		HasPassword: true, CAPEM: "-----BEGIN CERTIFICATE-----", Version: 7, UpdatedAt: at,
		Trusted: &notify.TrustedCert{CertInfo: notify.CertInfo{Fingerprint: strings.Repeat("ab", 32), Subject: "CN=smtp", NotAfter: at},
			TrustedBy: "admin", TrustedAt: at}}
	fm.SMTPFn = func(context.Context) (notify.SMTPSettings, bool, error) { return stored, true, nil }
	rec = callWith(h, http.MethodGet, "/api/v1/settings/smtp", "admin-stepup", "", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, `"7"`, rec.Header().Get("ETag"))
	assert.JSONEq(t, `{"configured":true,"host":"smtp.example.com","port":465,"tls_mode":"tls","from":"alice@example.com","username":"alice",
		"has_password":true,"ca_pem":"-----BEGIN CERTIFICATE-----","trusted_certificate":{"fingerprint":"`+strings.Repeat("ab", 32)+`",
		"subject":"CN=smtp","not_after":"2026-09-01T00:00:00Z","trusted_by":"admin","trusted_at":"2026-09-01T00:00:00Z"},
		"version":7,"updated_at":"2026-09-01T00:00:00Z"}`, rec.Body.String())
	fm.SMTPFn = func(context.Context) (notify.SMTPSettings, bool, error) {
		return notify.SMTPSettings{}, false, errNotConfigured
	}
	assert.Equal(t, http.StatusInternalServerError, callWith(h, http.MethodGet, "/api/v1/settings/smtp", "admin-stepup", "", nil).Code)

	fm.TrustFn = func(_ context.Context, a audit.Actor, version int, fp string) (notify.SMTPSettings, error) {
		assert.Equal(t, adminID, a.ID)
		assert.Equal(t, 7, version)
		assert.Equal(t, strings.Repeat("ab", 32), fp)
		return stored, nil
	}
	rec = callWith(h, http.MethodPost, "/api/v1/settings/smtp/actions/trust", "admin-stepup", `{"fingerprint":"`+strings.Repeat("ab", 32)+`"}`,
		map[string]string{"If-Match": `"7"`})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, `"7"`, rec.Header().Get("ETag"))
	fm.TrustFn = func(context.Context, audit.Actor, int, string) (notify.SMTPSettings, error) {
		return notify.SMTPSettings{}, notify.ErrCertNotSeen
	}
	rec = callWith(h, http.MethodPost, "/api/v1/settings/smtp/actions/trust", "admin-stepup", `{"fingerprint":"00"}`, map[string]string{"If-Match": `"7"`})
	assert.Equal(t, "ALC-NTF-0008", decodeErr(t, rec).Error.Code)
	rec = callWith(h, http.MethodPost, "/api/v1/settings/smtp/actions/trust", "admin-stepup", `{"fingerprint":"00"}`, map[string]string{"If-Match": `W/"7"`})
	assert.Equal(t, http.StatusPreconditionFailed, rec.Code, "a weak validator is refused")
	rec = callWith(h, http.MethodPost, "/api/v1/settings/smtp/actions/trust", "admin-stepup", `{"pin":"00"}`, map[string]string{"If-Match": `"7"`})
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	fm.UntrustFn = func(_ context.Context, _ audit.Actor, version int) (notify.SMTPSettings, error) {
		stored.Trusted, stored.Version = nil, version+1
		return stored, nil
	}
	rec = callWith(h, http.MethodPost, "/api/v1/settings/smtp/actions/untrust", "admin-stepup", `{}`, map[string]string{"If-Match": `"7"`})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, `"8"`, rec.Header().Get("ETag"))
	assert.Contains(t, rec.Body.String(), `"trusted_certificate":null`)
	fm.UntrustFn = func(context.Context, audit.Actor, int) (notify.SMTPSettings, error) {
		return notify.SMTPSettings{}, notify.ErrVersion
	}
	rec = callWith(h, http.MethodPost, "/api/v1/settings/smtp/actions/untrust", "admin-stepup", "", map[string]string{"If-Match": `"1"`})
	assert.Equal(t, http.StatusPreconditionFailed, rec.Code, "a stale version")
	assert.Equal(t, http.StatusPreconditionFailed, callWith(h, http.MethodPost, "/api/v1/settings/smtp/actions/untrust", "admin-stepup", "", nil).Code)
	rec = callWith(h, http.MethodPost, "/api/v1/settings/smtp/actions/untrust", "admin-stepup", `{"x":1}`, map[string]string{"If-Match": `"1"`})
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	fm.DeleteSMTPFn = func(_ context.Context, _ audit.Actor, version int) error {
		assert.Equal(t, 8, version)
		return notify.ErrNotConfigured
	}
	rec = callWith(h, http.MethodDelete, "/api/v1/settings/smtp", "admin-stepup", "", map[string]string{"If-Match": `"8"`})
	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.Equal(t, "ALC-NTF-0002", decodeErr(t, rec).Error.Code)
	assert.Equal(t, http.StatusPreconditionFailed, callWith(h, http.MethodDelete, "/api/v1/settings/smtp", "admin-stepup", "", nil).Code)

	rec = callWith(h, http.MethodPost, "/api/v1/settings/smtp/actions/test", "admin-stepup", `{"to":"ops@example.com","cc":"x"}`, nil)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var gotLocale string
	fm.TestMailFn = func(_ context.Context, _ audit.Actor, to, locale string) error {
		gotLocale = locale
		assert.Equal(t, "ops@example.com", to)
		return nil
	}
	rec = callWith(h, http.MethodPost, "/api/v1/settings/smtp/actions/test", "admin-stepup", `{"to":"ops@example.com"}`, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"sent":true}`, rec.Body.String())
	assert.Equal(t, "en", gotLocale, "the test e-mail is in the Administrator's language")
	assert.Equal(t, http.StatusPreconditionFailed, callWith(h, http.MethodPut, "/api/v1/settings/smtp", "admin-stepup", `{}`,
		map[string]string{"If-Match": `"01"`}).Code)
}

func TestRecipientsAlertsAndGeneralSettings(t *testing.T) {
	d, fm, fa, _ := phase7Deps(t)
	s := newServer(d)
	h := s.handler(s.apiRoutes())
	fm.RecipientsFn = func(context.Context) (notify.Recipients, error) { return notify.Recipients{Administrators: true}, nil }
	rec := callWith(h, http.MethodGet, "/api/v1/settings/notifications", "admin-stepup", "", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, `"0"`, rec.Header().Get("ETag"))
	assert.JSONEq(t, `{"administrators":true,"addresses":[],"version":0}`, rec.Body.String())
	fm.SaveRecipientsFn = func(_ context.Context, _ audit.Actor, version int, r notify.Recipients) (notify.Recipients, error) {
		assert.Equal(t, 0, version)
		assert.Equal(t, notify.Recipients{Addresses: []notify.Address{{Email: "ops@example.com", Locale: "tr"}}}, r)
		r.Version = 1
		return r, nil
	}
	rec = callWith(h, http.MethodPut, "/api/v1/settings/notifications", "admin-stepup",
		`{"administrators":false,"addresses":[{"email":"ops@example.com","locale":"tr"}]}`, map[string]string{"If-Match": `"0"`})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, `"1"`, rec.Header().Get("ETag"))
	assert.JSONEq(t, `{"administrators":false,"addresses":[{"email":"ops@example.com","locale":"tr"}],"version":1}`, rec.Body.String())
	for _, body := range []string{`{"administrators":false,"addresses":[{"email":"ops@example.com","Locale":"tr"}]}`,
		`{"administrators":false,"addresses":[{"email":"ops@example.com","locale":"tr","name":"x"}]}`,
		`{"administrators":false,"addresses":[{"email":1}]}`, `{"administrators":false,"addresses":["x"]}`} {
		rec = callWith(h, http.MethodPut, "/api/v1/settings/notifications", "admin-stepup", body, map[string]string{"If-Match": `"0"`})
		assert.Equal(t, http.StatusBadRequest, rec.Code, body)
	}
	fm.SaveRecipientsFn = func(context.Context, audit.Actor, int, notify.Recipients) (notify.Recipients, error) {
		return notify.Recipients{}, validate.Errors{{Field: "addresses", Code: validate.Required}}
	}
	rec = callWith(h, http.MethodPut, "/api/v1/settings/notifications", "admin-stepup", `{"administrators":false,"addresses":[]}`,
		map[string]string{"If-Match": `"0"`})
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	assert.Equal(t, http.StatusPreconditionFailed, callWith(h, http.MethodPut, "/api/v1/settings/notifications", "admin-stepup", `{}`, nil).Code)
	fm.RecipientsFn = func(context.Context) (notify.Recipients, error) { return notify.Recipients{}, errNotConfigured }
	assert.Equal(t, http.StatusInternalServerError, callWith(h, http.MethodGet, "/api/v1/settings/notifications", "admin-stepup", "", nil).Code)

	fa.ThresholdsFn = func(context.Context) (alerts.ThresholdSettings, error) {
		return alerts.ThresholdSettings{Days: []int{60, 30, 14, 7, 1}, Version: 3}, nil
	}
	rec = callWith(h, http.MethodGet, "/api/v1/settings/alerts", "admin-stepup", "", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, `"3"`, rec.Header().Get("ETag"))
	assert.JSONEq(t, `{"thresholds_days":[60,30,14,7,1],"version":3}`, rec.Body.String())
	fa.SaveThresholdsFn = func(_ context.Context, _ audit.Actor, version int, days []int) (alerts.ThresholdSettings, error) {
		assert.Equal(t, 3, version)
		assert.Equal(t, []int{7, 90}, days)
		return alerts.ThresholdSettings{Days: []int{90, 7}, Version: 4}, nil
	}
	rec = callWith(h, http.MethodPut, "/api/v1/settings/alerts", "admin-stepup", `{"thresholds_days":[7,90]}`, map[string]string{"If-Match": `"3"`})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, `"4"`, rec.Header().Get("ETag"))
	assert.JSONEq(t, `{"thresholds_days":[90,7],"version":4}`, rec.Body.String())
	fa.SaveThresholdsFn = func(context.Context, audit.Actor, int, []int) (alerts.ThresholdSettings, error) {
		return alerts.ThresholdSettings{}, validate.Errors{{Field: "thresholds_days", Code: validate.Duplicate}}
	}
	rec = callWith(h, http.MethodPut, "/api/v1/settings/alerts", "admin-stepup", `{"thresholds_days":[7,7]}`, map[string]string{"If-Match": `"3"`})
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code, "SaveThresholds refuses with field errors (Task 8)")
	fa.SaveThresholdsFn = func(context.Context, audit.Actor, int, []int) (alerts.ThresholdSettings, error) {
		return alerts.ThresholdSettings{}, notify.ErrVersion
	}
	rec = callWith(h, http.MethodPut, "/api/v1/settings/alerts", "admin-stepup", `{"thresholds_days":[7]}`, map[string]string{"If-Match": `"2"`})
	assert.Equal(t, http.StatusPreconditionFailed, rec.Code)
	rec = callWith(h, http.MethodPut, "/api/v1/settings/alerts", "admin-stepup", `{"thresholds_days":"7"}`, map[string]string{"If-Match": `"2"`})
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, http.StatusPreconditionFailed, callWith(h, http.MethodPut, "/api/v1/settings/alerts", "admin-stepup", `{}`, nil).Code)
	fa.ThresholdsFn = func(context.Context) (alerts.ThresholdSettings, error) {
		return alerts.ThresholdSettings{}, errNotConfigured
	}
	assert.Equal(t, http.StatusInternalServerError, callWith(h, http.MethodGet, "/api/v1/settings/alerts", "admin-stepup", "", nil).Code)

	fm.GeneralFn = func(context.Context) (settings.General, error) {
		return settings.General{PublicURL: "https://alice.example.com", RetiredKeyRetentionDays: 30, Version: 2}, nil
	}
	rec = callWith(h, http.MethodGet, "/api/v1/settings/general", "admin-stepup", "", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, `"2"`, rec.Header().Get("ETag"))
	assert.JSONEq(t, `{"public_url":"https://alice.example.com","retired_key_retention_days":30,"version":2}`, rec.Body.String())
	fm.SaveGeneralFn = func(_ context.Context, _ audit.Actor, version int, g settings.General) (settings.General, error) {
		assert.Equal(t, 2, version)
		assert.Equal(t, settings.General{PublicURL: "https://a.example.com", RetiredKeyRetentionDays: 90}, g)
		g.Version = 3
		return g, nil
	}
	rec = callWith(h, http.MethodPut, "/api/v1/settings/general", "admin-stepup", `{"public_url":"https://a.example.com","retired_key_retention_days":90}`,
		map[string]string{"If-Match": `"2"`})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, `"3"`, rec.Header().Get("ETag"))
	assert.JSONEq(t, `{"public_url":"https://a.example.com","retired_key_retention_days":90,"version":3}`, rec.Body.String())
	rec = callWith(h, http.MethodPut, "/api/v1/settings/general", "admin-stepup", `{"public_url":"x","version":3}`, map[string]string{"If-Match": `"2"`})
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, http.StatusPreconditionFailed, callWith(h, http.MethodPut, "/api/v1/settings/general", "admin-stepup", `{}`, nil).Code)
	fm.GeneralFn = func(context.Context) (settings.General, error) { return settings.General{}, errNotConfigured }
	assert.Equal(t, http.StatusInternalServerError, callWith(h, http.MethodGet, "/api/v1/settings/general", "admin-stepup", "", nil).Code)
}

// settingsVersion accepts "0" (never saved) besides the versions ifMatch accepts; nothing else.
func TestSettingsVersion(t *testing.T) {
	for raw, want := range map[string]int{`"0"`: 0, `"1"`: 1, `"9999999999"`: 9999999999} {
		r, _ := http.NewRequest(http.MethodPut, "/", nil)
		r.Header.Set("If-Match", raw)
		n, ok := settingsVersion(r)
		assert.True(t, ok, raw)
		assert.Equal(t, want, n, raw)
	}
	for _, raw := range []string{"", `0`, `"00"`, `"01"`, `W/"1"`, `"1", "2"`, `*`, `"-1"`, `"12345678901"`} {
		r, _ := http.NewRequest(http.MethodPut, "/", nil)
		r.Header.Set("If-Match", raw)
		_, ok := settingsVersion(r)
		assert.False(t, ok, raw)
	}
}

func alertsCounts() alerts.Counts {
	return alerts.Counts{Monitored: 10, Expired: 1, Within7: 2, Within30: 3, Within60: 4, KVExpired: 5, KVWithin30: 6}
}

// A service failure is the generic 500 on every Phase 7 read and change that has no other refusal test.
func TestPhase7ServiceFailures(t *testing.T) {
	d, fm, _, fr := phase7Deps(t)
	s := newServer(d)
	h := s.handler(s.apiRoutes())
	fr.ExpiringFn = func(context.Context, int, int) ([]alerts.Item, error) { return nil, errNotConfigured }
	fr.AttentionFn = func(context.Context, reports.Viewer) ([]reports.Condition, error) { return nil, errNotConfigured }
	fr.ViewsFn = func(context.Context, uuid.UUID, string) ([]reports.View, error) { return nil, errNotConfigured }
	fm.SaveGeneralFn = func(context.Context, audit.Actor, int, settings.General) (settings.General, error) {
		return settings.General{}, validate.Errors{{Field: "public_url", Code: validate.Pattern}}
	}
	for _, c := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/v1/dashboard/expiring", ""}, {http.MethodGet, "/api/v1/alerts", ""},
		{http.MethodGet, "/api/v1/views?page=certificates", ""},
	} {
		assert.Equal(t, http.StatusInternalServerError, callWith(h, c.method, c.path, "admin", c.body, nil).Code, c.path)
	}
	rec := callWith(h, http.MethodPut, "/api/v1/settings/general", "admin-stepup", `{"public_url":"http://x","retired_key_retention_days":1}`,
		map[string]string{"If-Match": `"0"`})
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	rec = callWith(h, http.MethodGet, "/api/v1/ssh-keys?cursor="+strings.Repeat("c", 513), "admin", "", nil)
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
}

// Task 14 review I1: 10 exports a minute per browser user and per API token, each identity on its own.
func TestExportLimitIsPerUserAndPerToken(t *testing.T) {
	d, _, _, fr := phase7Deps(t)
	fr.succeed()
	s := newServer(d)
	h := s.handler(s.apiRoutes())
	for i := 0; i < 10; i++ {
		require.Equal(t, http.StatusOK, callWith(h, http.MethodGet, "/api/v1/certificates/export", "auditor", "", nil).Code, i)
	}
	rec := callWith(h, http.MethodGet, "/api/v1/certificates/export", "auditor", "", nil)
	assert.Equal(t, http.StatusTooManyRequests, rec.Code, "the 11th export of the Auditor's session")
	assert.Equal(t, http.StatusTooManyRequests, callWith(h, http.MethodGet, "/api/v1/ssh-keys/export", "auditor-stepup", "", nil).Code,
		"another session of the same user shares the user's limit")
	assert.Equal(t, http.StatusOK, callWith(h, http.MethodGet, "/api/v1/certificates/export", "admin", "", nil).Code,
		"another user's session has its own limit")
	assert.Equal(t, http.StatusOK, callWith(h, http.MethodGet, "/api/v1/certificates/export", "alice_read_auditor", "", nil).Code,
		"the user's API token has its own limit")
}

// Task 14 review M6 (ruling): HEAD on an audited export is 405 and never runs the export nor writes an audit row.
func TestHeadOnAuditedExportsIsRefused(t *testing.T) {
	d, _, _, fr := phase7Deps(t)
	fr.succeed()
	fa := d.Audit.(*fakeAudit)
	verified := false
	fa.VerifyReadOnlyFn = func(context.Context) (audit.Report, error) {
		verified = true
		return audit.Report{}, nil
	}
	s := newServer(d)
	h := s.handler(s.apiRoutes())
	for _, path := range []string{"/api/v1/certificates/export", "/api/v1/ssh-keys/export", "/api/v1/audit/export?format=csv"} {
		fr.reset()
		rec := callWith(h, http.MethodHead, path, "admin", "", nil)
		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code, path)
		assert.Equal(t, "GET", rec.Header().Get("Allow"), path)
		assert.Zero(t, fr.calls(), path)
	}
	assert.False(t, verified, "the audit export did not start")
	assert.Zero(t, fa.Count("audit.exported"))
	assert.Equal(t, http.StatusOK, callWith(h, http.MethodHead, "/api/v1/dashboard/summary", "admin", "", nil).Code,
		"other reads still answer HEAD")
}

// Review L-7: every key the schema marks required must be present. An omitted one is a 422 "required" on that field and
// nothing is saved, instead of a zero value that switches mail authentication off, clears the pinned CA bundle, stops
// the Administrators' e-mails or blanks public_url. null is no value of these fields (400).
func TestSettingsPutsRequireTheirKeys(t *testing.T) {
	d, fm, _, _ := phase7Deps(t)
	s := newServer(d)
	h := s.handler(s.apiRoutes())
	saved := 0
	fm.SaveSMTPFn = func(context.Context, audit.Actor, int, notify.SMTPInput) (notify.SMTPSettings, error) {
		saved++
		return notify.SMTPSettings{}, nil
	}
	fm.SaveRecipientsFn = func(context.Context, audit.Actor, int, notify.Recipients) (notify.Recipients, error) {
		saved++
		return notify.Recipients{}, nil
	}
	fm.SaveGeneralFn = func(context.Context, audit.Actor, int, settings.General) (settings.General, error) {
		saved++
		return settings.General{}, nil
	}
	v := map[string]string{"If-Match": `"1"`}
	missing := func(rec *httptest.ResponseRecorder) map[string]string {
		t.Helper()
		require.Equal(t, http.StatusUnprocessableEntity, rec.Code, rec.Body.String())
		var body struct {
			Error struct {
				Details []struct{ Field, Code string } `json:"details"`
			} `json:"error"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		out := map[string]string{}
		for _, f := range body.Error.Details {
			out[f.Field] = f.Code
		}
		return out
	}
	req := validate.Required
	assert.Equal(t, map[string]string{"username": req, "ca_pem": req},
		missing(callWith(h, http.MethodPut, "/api/v1/settings/smtp", "admin-stepup", `{"host":"smtp.x","port":587,"tls_mode":"starttls","from":"a@b.c"}`, v)))
	assert.Equal(t, map[string]string{"host": req, "port": req, "tls_mode": req, "from": req, "username": req, "ca_pem": req},
		missing(callWith(h, http.MethodPut, "/api/v1/settings/smtp", "admin-stepup", `{"password":"x"}`, v)))
	assert.Equal(t, map[string]string{"administrators": req},
		missing(callWith(h, http.MethodPut, "/api/v1/settings/notifications", "admin-stepup", `{"addresses":[]}`, v)))
	assert.Equal(t, map[string]string{"addresses": req},
		missing(callWith(h, http.MethodPut, "/api/v1/settings/notifications", "admin-stepup", `{"administrators":true}`, v)))
	assert.Equal(t, map[string]string{"public_url": req},
		missing(callWith(h, http.MethodPut, "/api/v1/settings/general", "admin-stepup", `{"retired_key_retention_days":30}`, v)))
	assert.Equal(t, map[string]string{"public_url": req, "retired_key_retention_days": req},
		missing(callWith(h, http.MethodPut, "/api/v1/settings/general", "admin-stepup", `{}`, v)))
	for path, body := range map[string]string{
		"/api/v1/settings/smtp":          `{"host":"smtp.x","port":587,"tls_mode":"starttls","from":"a@b.c","username":null,"ca_pem":""}`,
		"/api/v1/settings/notifications": `{"administrators":null,"addresses":[]}`,
		"/api/v1/settings/general":       `{"public_url":"https://a.example.com","retired_key_retention_days":null}`,
	} {
		assert.Equal(t, http.StatusBadRequest, callWith(h, http.MethodPut, path, "admin-stepup", body, v).Code, path)
	}
	assert.Zero(t, saved, "nothing was saved")

	// Every key present: saved, and the password stays optional.
	assert.Equal(t, http.StatusOK, callWith(h, http.MethodPut, "/api/v1/settings/smtp", "admin-stepup",
		`{"host":"smtp.x","port":587,"tls_mode":"starttls","from":"a@b.c","username":"","ca_pem":""}`, v).Code)
	assert.Equal(t, http.StatusOK, callWith(h, http.MethodPut, "/api/v1/settings/notifications", "admin-stepup",
		`{"administrators":false,"addresses":[]}`, v).Code)
	assert.Equal(t, http.StatusOK, callWith(h, http.MethodPut, "/api/v1/settings/general", "admin-stepup",
		`{"public_url":"","retired_key_retention_days":30}`, v).Code)
	assert.Equal(t, 3, saved)
}
