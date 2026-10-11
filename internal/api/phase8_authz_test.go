package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/audit/forward"
	"alice/internal/auth"
	"alice/internal/backup"
	"alice/internal/license"
	"alice/internal/platform/tlscert"
	"alice/internal/rbac"
	"alice/internal/setup"
)

// fakeBackup implements BackupService over a directory of its own; every call is counted.
type fakeBackup struct {
	phase7Fake
	dir      string
	opened   []string
	CreateFn func(ctx context.Context, in backup.CreateInput) (backup.Info, error)
	saved    backup.Schedule
}

func newFakeBackup(t *testing.T) *fakeBackup {
	t.Helper()
	f := &fakeBackup{dir: t.TempDir()}
	require.NoError(t, os.WriteFile(filepath.Join(f.dir, "alice-backup-7F3K92QD-20261010T023000Z-manual.alicebak"), []byte("backup bytes"), 0o600))
	return f
}

func (f *fakeBackup) Create(ctx context.Context, in backup.CreateInput) (backup.Info, error) {
	f.record()
	if f.CreateFn != nil {
		return f.CreateFn(ctx, in)
	}
	return backup.Info{Name: "alice-backup-7F3K92QD-20261010T023000Z-manual.alicebak", Kind: in.Kind, Size: 12, Check: backup.CheckOK}, nil
}

func (f *fakeBackup) List(context.Context) ([]backup.Info, error) {
	f.record()
	return []backup.Info{{Name: "alice-backup-7F3K92QD-20261010T023000Z-manual.alicebak", Kind: backup.KindManual, Size: 12,
		CreatedAt: testNow, AliceVersion: "1.0.0", Check: backup.CheckOK}}, nil
}

func (f *fakeBackup) Open(_ context.Context, name string) (*os.File, backup.Info, error) {
	f.record()
	f.opened = append(f.opened, name)
	if !backup.ValidName(name) {
		return nil, backup.Info{}, backup.ErrNotFound
	}
	file, err := os.Open(filepath.Join(f.dir, name)) //nolint:gosec // G304: a name ValidName accepted, in the test's directory
	if err != nil {
		return nil, backup.Info{}, backup.ErrNotFound
	}
	return file, backup.Info{Name: name, Check: backup.CheckOK}, nil
}

func (f *fakeBackup) FreeBytes() (uint64, error) { f.record(); return 1 << 30, nil }

func (f *fakeBackup) Schedule(context.Context) (backup.Schedule, error) {
	f.record()
	return backup.Schedule{Time: "02:30", Zone: "UTC", Retention: 14, Version: 1}, nil
}

func (f *fakeBackup) SaveSchedule(_ context.Context, _ audit.Actor, version int, in backup.Schedule) (backup.Schedule, error) {
	f.record()
	in.Version = version + 1
	f.saved = in
	return in, nil
}

func (f *fakeBackup) State(context.Context) (backup.State, error) {
	f.record()
	return backup.State{LastSuccessAt: testNow.Add(-3 * time.Hour), LastSuccessName: "x.alicebak"}, nil
}

// fakeForward implements ForwardService.
type fakeForward struct {
	phase7Fake
	saved, tested forward.Settings
	TestFn        func(ctx context.Context, in forward.Settings) error
}

func (f *fakeForward) Settings(context.Context) (forward.Settings, forward.State, error) {
	f.record()
	return forward.Settings{Host: "siem.example.com", Port: 6514, Transport: forward.TransportTLS, CASet: true, Version: 2},
		forward.State{Backlog: 3}, nil
}

func (f *fakeForward) Save(_ context.Context, in forward.Settings, version int, _ audit.Actor) (forward.Settings, error) {
	f.record()
	f.saved = in
	in.Version = version + 1
	return in, nil
}

func (f *fakeForward) Test(ctx context.Context, in forward.Settings) error {
	f.record()
	f.tested = in
	if f.TestFn != nil {
		return f.TestFn(ctx, in)
	}
	return nil
}

// fakeHTTPS implements HTTPSService.
type fakeHTTPS struct {
	phase7Fake
	info      tlscert.Info
	uploaded  tlscert.Upload
	InstallFn func(u tlscert.Upload) (tlscert.Info, error)
}

func (f *fakeHTTPS) Info() tlscert.Info { f.record(); return f.info }

func (f *fakeHTTPS) Install(_ context.Context, _ auth.Principal, _ auth.Meta, u tlscert.Upload) (tlscert.Info, error) {
	f.record()
	f.uploaded = tlscert.Upload{CertPEM: append([]byte(nil), u.CertPEM...), Hosts: u.Hosts}
	if f.InstallFn != nil {
		return f.InstallFn(u)
	}
	return tlscert.Info{Subject: "CN=alice.example.com", Warnings: []string{"name_mismatch"}}, nil
}

// phase8Fakes counts the calls of every Phase 8 service, the setup steps included.
type phase8Fakes struct {
	backup  *fakeBackup
	forward *fakeForward
	https   *fakeHTTPS
	setup   phase7Fake
}

func (p *phase8Fakes) calls() int {
	return p.backup.calls() + p.forward.calls() + p.https.calls() + p.setup.calls()
}

func (p *phase8Fakes) reset() {
	p.backup.reset()
	p.forward.reset()
	p.https.reset()
	p.setup.reset()
}

func phase8Deps(t *testing.T) (Deps, *phase8Fakes) {
	t.Helper()
	d := testDeps(t, nil)
	f := &phase8Fakes{backup: newFakeBackup(t), forward: &fakeForward{}, https: &fakeHTTPS{info: tlscert.Info{Temporary: true}}}
	fs := d.Setup.(*fakeSetup)
	step := func(context.Context, auth.Principal, auth.Meta) (setup.Status, error) {
		f.setup.record()
		return setup.Status{NextStep: "license"}, nil
	}
	fs.KeepTemporaryFn, fs.SkipMailFn = step, step
	status := fs.StatusFn
	fs.StatusFn = func(ctx context.Context) (setup.Status, error) { f.setup.record(); return status(ctx) }
	d.Backup, d.Forward, d.TLSStore = f.backup, f.forward, f.https
	return d, f
}

// phase8Calls are C12's new routes with a body and headers the handler accepts.
func phase8Calls() map[string]routeCall {
	v := map[string]string{"If-Match": `"1"`}
	fwd := `{"enabled":true,"host":"siem.example.com","port":6514,"transport":"tls"}`
	return map[string]routeCall{
		"GET /api/v1/backups":                         {},
		"POST /api/v1/backups":                        {},
		"GET /api/v1/backups/{name}/download":         {},
		"GET /api/v1/settings/backups":                {},
		"PUT /api/v1/settings/backups":                {body: `{"time":"03:15","zone":"Europe/Istanbul","retention":20}`, hdr: v},
		"GET /api/v1/settings/https":                  {},
		"PUT /api/v1/settings/https":                  {body: `{"cert_pem":"x","key_pem":"y"}`},
		"POST /api/v1/setup/https/keep-temporary":     {},
		"POST /api/v1/setup/mail/skip":                {},
		"GET /api/v1/settings/audit-forwarding":       {},
		"PUT /api/v1/settings/audit-forwarding":       {body: fwd, hdr: v},
		"POST /api/v1/settings/audit-forwarding/test": {body: fwd},
	}
}

// unlimited calls h with the rate limits of s reset first (the download and upload routes allow 5 a minute).
func unlimited(s *server, h http.Handler) func(method, target, id, body string, hdr map[string]string) *httptest.ResponseRecorder {
	return func(method, target, id, body string, hdr map[string]string) *httptest.ResponseRecorder {
		(&Server{s: s}).ResetLimits()
		return callWith(h, method, target, id, body, hdr)
	}
}

const downloadName = "alice-backup-7F3K92QD-20261010T023000Z-manual.alicebak"

// TestPhase8RoutesAuthz: every C12 route, as every identity, in and out of lock: only an Administrator with step-up
// reaches a Phase 8 service, and everything works in lock (platform administration).
func TestPhase8RoutesAuthz(t *testing.T) {
	calls := phase8Calls()
	for _, locked := range []bool{false, true} {
		d, f := phase8Deps(t)
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
			assert.Contains(t, []rbac.Permission{rbac.BackupManage, rbac.SettingsManage}, rt.perm, key)
			if strings.HasPrefix(rt.pattern, "/api/v1/backups") {
				assert.Equal(t, rbac.BackupManage, rt.perm, key)
			}
			target := strings.ReplaceAll(pathParamRE.ReplaceAllString(rt.pattern, uuid.NewString()), "{name}", downloadName)
			target = strings.Replace(target, "/backups/"+downloadName, "/backups/"+downloadName, 1)
			if strings.Contains(rt.pattern, "{name}") {
				target = "/api/v1/backups/" + downloadName + "/download"
			}
			for _, id := range identities {
				(&Server{s: s}).ResetLimits()
				f.reset()
				rec := callWith(h, rt.method, target, id, c.body, c.hdr)
				want := expectedMatrix[rt.perm][id]
				name := key + " as " + id
				switch want {
				case allw:
					assert.Less(t, rec.Code, 300, "%s (locked %v): %s", name, locked, rec.Body.String())
					assert.Positive(t, f.calls(), "an allowed request reaches its service: %s", name)
				case step:
					assert.Equal(t, "ALC-AUTH-0003", decodeErr(t, rec).Error.Code, name)
				default:
					assert.Equal(t, want, rec.Code, name)
				}
				if want != allw {
					assert.Zero(t, f.calls(), "a refused request has no side effect: %s", name)
				}
			}
		}
		assert.Equal(t, len(calls), seen, "every C12 route is in the route table")
	}
}

// The two changed GET routes keep their rules: the summary is read, the setup status public.
func TestPhase8ChangedRoutesKeepTheirRules(t *testing.T) {
	s := newServer(testDeps(t, nil))
	perms := map[string]rbac.Permission{}
	for _, rt := range s.apiRoutes() {
		perms[rt.method+" "+rt.pattern] = rt.perm
	}
	assert.Equal(t, rbac.Read, perms["GET /api/v1/dashboard/summary"])
	assert.Equal(t, rbac.Public, perms["GET /api/v1/setup/status"])
}

// A download name that is not C7's is ALC-BAK-0003 before the service opens anything.
func TestBackupDownloadNameIsCheckedFirst(t *testing.T) {
	d, f := phase8Deps(t)
	s := newServer(d)
	call := unlimited(s, s.handler(s.apiRoutes()))
	for _, name := range []string{"..%2f..%2fetc%2fpasswd", "%2e%2e", ".alice-backup-x.alicebak.partial", "x%00.alicebak", "notes.txt",
		"a%5cb.alicebak"} {
		f.reset()
		f.backup.opened = nil
		rec := call(http.MethodGet, "/api/v1/backups/"+name+"/download", "admin-stepup", "", nil)
		assert.Equal(t, http.StatusNotFound, rec.Code, name)
		assert.Equal(t, "ALC-BAK-0003", decodeErr(t, rec).Error.Code, name)
		assert.Empty(t, f.backup.opened, "nothing is opened for %s", name)
	}
	rec := call(http.MethodGet, "/api/v1/backups/"+downloadName+"/download", "admin-stepup", "", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "backup bytes", rec.Body.String())
	assert.Equal(t, `attachment; filename="`+downloadName+`"`, rec.Header().Get("Content-Disposition"))
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	assert.Equal(t, "none", rec.Header().Get("Accept-Ranges"))
	assert.Equal(t, "application/octet-stream", rec.Header().Get("Content-Type"))
	fa := d.Audit.(*fakeAudit)
	assert.Equal(t, 1, fa.Count("backup.downloaded"))
	rec = call(http.MethodHead, "/api/v1/backups/"+downloadName+"/download", "admin-stepup", "", nil)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code, "HEAD would audit a download that sends nothing")
	assert.Equal(t, 1, fa.Count("backup.downloaded"))
}

func TestAttachmentHeader(t *testing.T) {
	assert.Equal(t, `attachment; filename="a.alicebak"`, attachment("a.alicebak"))
	assert.Equal(t, `attachment; filename*=utf-8''%C3%A7%22.alicebak`, attachment(`ç".alicebak`))
}

// The download is refused, unaudited, when the audit row cannot be written.
func TestBackupDownloadNeedsItsAuditRow(t *testing.T) {
	d, _ := phase8Deps(t)
	d.Audit = &fakeAudit{WriteFn: func(context.Context, audit.Event) error { return errors.New("database down") }}
	s := newServer(d)
	h := s.handler(s.apiRoutes())
	rec := callWith(h, http.MethodGet, "/api/v1/backups/"+downloadName+"/download", "admin-stepup", "", nil)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.NotContains(t, rec.Body.String(), "backup bytes")
}

// Forwarding: ca_pem absent keeps the stored bundle, "" removes it, a PEM replaces it; answers never carry it.
func TestForwardingBodyAndAnswer(t *testing.T) {
	d, f := phase8Deps(t)
	s := newServer(d)
	call := unlimited(s, s.handler(s.apiRoutes()))
	v := map[string]string{"If-Match": `"2"`}
	rec := call(http.MethodPut, "/api/v1/settings/audit-forwarding", "admin-stepup",
		`{"enabled":true,"host":"siem.example.com","port":6514,"transport":"tls"}`, v)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.True(t, f.forward.saved.CASet, "absent: keep")
	assert.Empty(t, f.forward.saved.CAPEM)
	rec = call(http.MethodPut, "/api/v1/settings/audit-forwarding", "admin-stepup",
		`{"enabled":true,"host":"siem.example.com","port":6514,"transport":"tls","ca_pem":""}`, v)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.False(t, f.forward.saved.CASet, `"": remove`)
	rec = call(http.MethodPut, "/api/v1/settings/audit-forwarding", "admin-stepup",
		`{"enabled":true,"host":"siem.example.com","port":6514,"transport":"tls","ca_pem":"PEM"}`, v)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "PEM", f.forward.saved.CAPEM)
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.NotContains(t, body, "ca_pem")
	assert.Equal(t, true, body["ca_set"])
	assert.Equal(t, `"2"`, rec.Header().Get("ETag"))
	rec = call(http.MethodPut, "/api/v1/settings/audit-forwarding", "admin-stepup", `{"enabled":true}`, nil)
	assert.Equal(t, http.StatusPreconditionFailed, rec.Code, "If-Match is required")

	for err, code := range map[error]string{forward.ErrUnreachable: "ALC-AUD-0003", forward.ErrUntrusted: "ALC-AUD-0004",
		forward.ErrAddressRefused: "ALC-AUD-0002"} {
		f.forward.TestFn = func(context.Context, forward.Settings) error { return err }
		rec = call(http.MethodPost, "/api/v1/settings/audit-forwarding/test", "admin-stepup",
			`{"enabled":true,"host":"siem.example.com","port":6514,"transport":"tls"}`, nil)
		assert.Equal(t, code, decodeErr(t, rec).Error.Code)
	}
}

// S-18: after completion an anonymous caller learns only completed and default_locale.
func TestSetupStatusHidesTheStepsAfterCompletion(t *testing.T) {
	d := testDeps(t, nil)
	done := true
	d.Setup.(*fakeSetup).StatusFn = func(context.Context) (setup.Status, error) {
		return setup.Status{AdminExists: true, RecoveryPassphraseSet: true, LicenseChosen: true, Completed: done, DefaultLocale: "tr",
			HTTPSChosen: true, MailChosen: true, NextStep: "done"}, nil
	}
	s := newServer(d)
	h := s.handler(s.apiRoutes())
	keys := func(id string) []string {
		rec := callWith(h, http.MethodGet, "/api/v1/setup/status", id, "", nil)
		require.Equal(t, http.StatusOK, rec.Code)
		var m map[string]any
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &m))
		var out []string
		for k := range m {
			out = append(out, k)
		}
		return out
	}
	assert.ElementsMatch(t, []string{"completed", "default_locale"}, keys(""))
	assert.ElementsMatch(t, []string{"completed", "default_locale"}, keys("alice_read_admin"), "a token is not a signed-in browser")
	all := []string{"admin_exists", "recovery_passphrase_set", "license_chosen", "completed", "default_locale", "https_chosen",
		"mail_chosen", "next_step"}
	assert.ElementsMatch(t, all, keys("admin"))
	assert.ElementsMatch(t, all, keys("operator"))
	done = false
	assert.ElementsMatch(t, all, keys(""))
}

func TestPassphraseTooWeakAnswersItsCode(t *testing.T) {
	d := testDeps(t, nil)
	d.Setup.(*fakeSetup).SetRecoveryPassphraseFn = func(context.Context, auth.Principal, auth.Meta, string, string) error {
		return setup.ErrPassphraseTooWeak
	}
	s := newServer(d)
	h := s.handler(s.apiRoutes())
	rec := callWith(h, http.MethodPost, "/api/v1/setup/recovery-passphrase", "admin-stepup",
		`{"passphrase":"aaaaaaaaaaaaaaaaaa","passphrase_confirm":"aaaaaaaaaaaaaaaaaa"}`, nil)
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	assert.Equal(t, "ALC-SET-0010", decodeErr(t, rec).Error.Code)
}

// The TLS refusals answer their codes; the request host is a name the certificate should cover.
func TestHTTPSUploadAnswers(t *testing.T) {
	d, f := phase8Deps(t)
	s := newServer(d)
	call := unlimited(s, s.handler(s.apiRoutes()))
	rec := call(http.MethodPut, "/api/v1/settings/https", "admin-stepup", `{"cert_pem":"c","key_pem":"k"}`, nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, []string{"example.com"}, f.https.uploaded.Hosts)
	assert.Contains(t, rec.Body.String(), `"warnings":["name_mismatch"]`)
	for err, code := range map[error]string{tlscert.ErrKeyMismatch: "ALC-TLS-0001", tlscert.ErrNotValidNow: "ALC-TLS-0002",
		tlscert.ErrWeakKey: "ALC-TLS-0003", tlscert.ErrPFXPassword: "ALC-TLS-0004", tlscert.ErrUnreadable: "ALC-TLS-0005"} {
		f.https.InstallFn = func(tlscert.Upload) (tlscert.Info, error) { return tlscert.Info{}, err }
		rec = call(http.MethodPut, "/api/v1/settings/https", "admin-stepup", `{"cert_pem":"c","key_pem":"k"}`, nil)
		assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
		assert.Equal(t, code, decodeErr(t, rec).Error.Code)
	}
	rec = call(http.MethodPut, "/api/v1/settings/https", "admin-stepup", `{"pfx_base64":"!!","pfx_password":"p"}`, nil)
	assert.Equal(t, "ALC-TLS-0005", decodeErr(t, rec).Error.Code)
	rec = call(http.MethodGet, "/api/v1/settings/https", "admin-stepup", "", nil)
	assert.Contains(t, rec.Body.String(), `"temporary":true`)
	assert.Contains(t, rec.Body.String(), `"warnings":[]`)
}

// R43 row 18: Administrators get the backup state and the checklist, Auditors the backup state, Operators neither.
func TestDashboardPhase8SectionsAreRoleFiltered(t *testing.T) {
	d, _ := phase8Deps(t)
	fr := &fakeReports{}
	fr.succeed()
	d.Reports = fr
	fm := &fakeMail{}
	fm.succeed()
	d.Mail = fm
	s := newServer(d)
	h := s.handler(s.apiRoutes())
	get := func(id string) map[string]any {
		rec := callWith(h, http.MethodGet, "/api/v1/dashboard/summary", id, "", nil)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var m map[string]any
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &m))
		return m
	}
	admin := get("admin")
	require.Contains(t, admin, "backup")
	assert.EqualValues(t, 3, admin["backup"].(map[string]any)["age_hours"])
	require.Contains(t, admin, "setup_checklist")
	items := map[string]map[string]any{}
	for _, it := range admin["setup_checklist"].([]any) {
		m := it.(map[string]any)
		items[m["item"].(string)] = m
	}
	assert.Equal(t, false, items["https"]["done"], "the temporary certificate is in use")
	assert.Equal(t, true, items["https"]["required"])
	assert.Equal(t, true, items["passphrase"]["required"])
	assert.Equal(t, true, items["mail"]["done"], "mail settings exist")
	assert.Equal(t, false, items["mail"]["required"])
	assert.Len(t, items, 5)
	auditor := get("auditor")
	assert.Contains(t, auditor, "backup")
	assert.NotContains(t, auditor, "setup_checklist")
	operator := get("operator")
	assert.NotContains(t, operator, "backup")
	assert.NotContains(t, operator, "setup_checklist")
}

// The next scheduled backup is the next wall-clock time in the schedule's zone, across daylight saving too.
func TestNextScheduled(t *testing.T) {
	now := time.Date(2026, 10, 24, 23, 0, 0, 0, time.UTC) // 02:00 in Istanbul (UTC+3)
	next, ok := nextScheduled(now, backup.Schedule{Time: "02:30", Zone: "Europe/Istanbul"})
	require.True(t, ok)
	assert.Equal(t, time.Date(2026, 10, 24, 23, 30, 0, 0, time.UTC), next)
	next, ok = nextScheduled(now, backup.Schedule{Time: "01:00", Zone: "Europe/Istanbul"})
	require.True(t, ok)
	assert.Equal(t, time.Date(2026, 10, 25, 22, 0, 0, 0, time.UTC), next)
	_, ok = nextScheduled(now, backup.Schedule{Time: "25:00", Zone: "UTC"})
	assert.False(t, ok)
	_, ok = nextScheduled(now, backup.Schedule{Time: "02:30", Zone: "Mars/Olympus"})
	assert.False(t, ok)
}
