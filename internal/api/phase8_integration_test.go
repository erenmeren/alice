//go:build integration

package api

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/backup"
	"alice/internal/platform/tlscert"
	"alice/internal/testutil/fakesyslog"
	"alice/internal/testutil/pki"
)

// setupUntilPassphrase runs the wizard up to and including the recovery passphrase and returns the admin's browser:
// the HTTPS, mail and license steps are still open.
func (s *stack) setupUntilPassphrase(a *account) *client {
	t := s.t
	t.Helper()
	code, err := s.setup.ResetToken(context.Background())
	require.NoError(t, err)
	c := s.client("198.51.100.10")
	requireStatus(t, c.do(http.MethodPost, "/api/v1/setup/session", map[string]string{"code": code}), http.StatusOK)
	requireStatus(t, c.do(http.MethodPut, "/api/v1/setup/language", map[string]string{"language": "en"}), http.StatusNoContent)
	rec := c.do(http.MethodPost, "/api/v1/setup/admin/enrollment", map[string]string{
		"username": a.username, "display_name": "Ada Admin", "email": "", "password": a.password,
	})
	requireStatus(t, rec, http.StatusOK)
	a.secret = decodeBody[enrollmentBody](t, rec).Secret
	rec = c.do(http.MethodPost, "/api/v1/setup/admin", map[string]string{"code": s.totpNow(a.secret)})
	requireStatus(t, rec, http.StatusOK)
	a.id = decodeBody[sessionBody](t, rec).User.ID
	requireStatus(t, c.do(http.MethodPost, "/api/v1/setup/recovery-passphrase", map[string]string{
		"passphrase": backupPassphrase, "passphrase_confirm": backupPassphrase,
	}), http.StatusNoContent)
	return c
}

func statusKeys(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	requireStatus(t, rec, http.StatusOK)
	var m map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &m))
	return m
}

// S-18: once setup is complete, an anonymous caller learns only that and the default language.
func TestSetupStatusAfterCompletionRevealsNothing(t *testing.T) {
	s := newStack(t)
	before := statusKeys(t, s.freshClient().do(http.MethodGet, "/api/v1/setup/status", nil))
	for _, k := range []string{"https_chosen", "mail_chosen", "next_step", "admin_exists"} {
		assert.Contains(t, before, k, "while setup is open")
	}
	admin := &account{username: "ada", password: adminPassword}
	c := s.setupAdmin(admin, backupPassphrase, nil)
	anon := statusKeys(t, s.freshClient().do(http.MethodGet, "/api/v1/setup/status", nil))
	assert.Equal(t, map[string]any{"completed": true, "default_locale": "en"}, anon)
	signedIn := statusKeys(t, c.do(http.MethodGet, "/api/v1/setup/status", nil))
	assert.Equal(t, "done", signedIn["next_step"])
	assert.Contains(t, signedIn, "https_chosen")
	assert.Contains(t, signedIn, "mail_chosen")
}

func TestBackupRoutes(t *testing.T) {
	s, c, admin := installed(t)
	s.stepUp(c, admin)
	rec := c.do(http.MethodPost, "/api/v1/backups", nil)
	requireStatus(t, rec, http.StatusCreated)
	made := decodeBody[map[string]any](t, rec)
	assert.Equal(t, "manual", made["kind"])
	assert.Equal(t, "ok", made["check"])
	name := made["name"].(string)

	rec = c.do(http.MethodGet, "/api/v1/backups", nil)
	requireStatus(t, rec, http.StatusOK)
	list := decodeBody[struct {
		Items []map[string]any `json:"items"`
		State map[string]any   `json:"state"`
		Sch   map[string]any   `json:"schedule"`
	}](t, rec)
	require.Len(t, list.Items, 1)
	assert.Equal(t, name, list.Items[0]["name"])
	assert.Equal(t, true, list.State["configured"])
	assert.Greater(t, list.State["free_bytes"].(float64), float64(0))
	assert.Equal(t, name, list.State["last_success_name"])
	assert.Equal(t, "02:30", list.Sch["time"])
	assert.NotNil(t, list.Sch["next_at"])
	assert.Equal(t, 1, s.countWhere("audit_log", "action = 'backup.created' AND actor_type = 'user'"))

	// A second backup while the first is held.
	conn, err := s.db.Owner.Acquire(context.Background())
	require.NoError(t, err)
	_, err = conn.Exec(context.Background(), "SELECT pg_advisory_lock(hashtext('alice.backup'))")
	require.NoError(t, err)
	requireError(t, c.do(http.MethodPost, "/api/v1/backups", nil), http.StatusConflict, "ALC-BAK-0001")
	_, err = conn.Exec(context.Background(), "SELECT pg_advisory_unlock(hashtext('alice.backup'))")
	require.NoError(t, err)
	conn.Release()

	// Without a recovery passphrase.
	_, err = s.db.Owner.Exec(context.Background(), "DELETE FROM settings WHERE key = 'backup.key'")
	require.NoError(t, err)
	requireError(t, c.do(http.MethodPost, "/api/v1/backups", nil), http.StatusConflict, "ALC-BAK-0002")
}

// request is the browser's GET as client.do builds it, for a test that serves it with its own writer.
func (c *client) request(path string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "https://alice.test"+path, nil)
	req.RemoteAddr = c.ip + ":40000"
	for name, value := range c.cookies {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	req.Header.Set(activityHeader, "1")
	return req
}

// firstWriteWriter calls onFirst before the first body byte is written.
type firstWriteWriter struct {
	*httptest.ResponseRecorder
	onFirst func()
	written bool
}

func (w *firstWriteWriter) Write(p []byte) (int, error) {
	if !w.written {
		w.written = true
		w.onFirst()
	}
	return w.ResponseRecorder.Write(p)
}

func TestBackupDownloadIsAuditedFirst(t *testing.T) {
	s, c, admin := installed(t)
	s.stepUp(c, admin)
	rec := c.do(http.MethodPost, "/api/v1/backups", nil)
	requireStatus(t, rec, http.StatusCreated)
	name := decodeBody[map[string]any](t, rec)["name"].(string)
	file, err := os.ReadFile(filepath.Join(s.backupsDir, name))
	require.NoError(t, err)

	auditedAtFirstByte := -1
	w := &firstWriteWriter{ResponseRecorder: httptest.NewRecorder(), onFirst: func() {
		auditedAtFirstByte = s.countWhere("audit_log", "action = 'backup.downloaded' AND details->>'name' = '"+name+"'")
	}}
	s.handler.ServeHTTP(w, c.request("/api/v1/backups/"+name+"/download"))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, 1, auditedAtFirstByte, "the audit row is committed before the first byte")
	assert.Equal(t, file, w.Body.Bytes())
	assert.Equal(t, `attachment; filename="`+name+`"`, w.Header().Get("Content-Disposition"))
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	assert.Equal(t, "none", w.Header().Get("Accept-Ranges"))
	assert.Equal(t, strconv.Itoa(len(file)), w.Header().Get("Content-Length"))
}

func TestBackupDownloadRefusesPathTricks(t *testing.T) {
	s, c, admin := installed(t)
	s.stepUp(c, admin)
	elsewhere := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(elsewhere, "other.alicebak"), []byte("not ours"), 0o600))
	var opened []string
	s.backupHook = func(name string) { opened = append(opened, name) }
	for _, path := range []string{"..%2f..%2fetc%2fpasswd", "%2e%2e", ".alice-backup-x.alicebak.partial", "other.alicebak",
		"x%00.alicebak", "..%2f" + escapeDir(elsewhere) + "%2fother.alicebak", "a%5c..%5cb.alicebak"} {
		s.api.ResetLimits()
		rec := c.do(http.MethodGet, "/api/v1/backups/"+path+"/download", nil)
		requireError(t, rec, http.StatusNotFound, "ALC-BAK-0003")
	}
	assert.Equal(t, []string{"other.alicebak"}, opened, "only a valid name reaches the service, which opens inside its directory")
	s.api.ResetLimits()
	rec := c.do(http.MethodGet, "/api/v1/backups/x/../../y.alicebak/download", nil)
	assert.GreaterOrEqual(t, rec.Code, 300, "a path with dot segments never reaches a download: %d", rec.Code)
	assert.Equal(t, []string{"other.alicebak"}, opened)
	assert.Zero(t, s.countWhere("audit_log", "action = 'backup.downloaded'"))
}

// escapeDir escapes the slashes of a directory for one path segment.
func escapeDir(dir string) string { return strings.ReplaceAll(dir, "/", "%2f") }

func TestBackupDownloadRateLimit(t *testing.T) {
	s, c, admin := installed(t)
	s.stepUp(c, admin)
	rec := c.do(http.MethodPost, "/api/v1/backups", nil)
	requireStatus(t, rec, http.StatusCreated)
	name := decodeBody[map[string]any](t, rec)["name"].(string)
	s.api.ResetLimits()
	for i := range 5 {
		requireStatus(t, c.do(http.MethodGet, "/api/v1/backups/"+name+"/download", nil), http.StatusOK)
		_ = i
	}
	requireStatus(t, c.do(http.MethodGet, "/api/v1/backups/"+name+"/download", nil), http.StatusTooManyRequests)
}

func TestBackupScheduleSettings(t *testing.T) {
	s, c, admin := installed(t)
	s.stepUp(c, admin)
	rec := c.do(http.MethodGet, "/api/v1/settings/backups", nil)
	requireStatus(t, rec, http.StatusOK)
	assert.Equal(t, `"0"`, rec.Header().Get("ETag"))
	body := map[string]any{"time": "03:15", "zone": "Europe/Istanbul", "retention": 20}
	requireError(t, c.do(http.MethodPut, "/api/v1/settings/backups", body), http.StatusPreconditionFailed, "ALC-SYS-0008")
	ifm := func(v string) reqOpt { return func(r *http.Request) { r.Header.Set("If-Match", `"`+v+`"`) } }
	for field, bad := range map[string]map[string]any{
		"time":      {"time": "25:00", "zone": "UTC", "retention": 14},
		"zone":      {"time": "02:30", "zone": "Mars/Olympus", "retention": 14},
		"retention": {"time": "02:30", "zone": "UTC", "retention": 6},
	} {
		rec := c.do(http.MethodPut, "/api/v1/settings/backups", bad, ifm("0"))
		requireError(t, rec, http.StatusUnprocessableEntity, "ALC-SYS-0006")
		assert.Contains(t, rec.Body.String(), `"field":"`+field+`"`)
	}
	rec = c.do(http.MethodPut, "/api/v1/settings/backups", map[string]any{"time": "02:30", "zone": "UTC", "retention": 61}, ifm("0"))
	requireError(t, rec, http.StatusUnprocessableEntity, "ALC-SYS-0006")
	rec = c.do(http.MethodPut, "/api/v1/settings/backups", body, ifm("0"))
	requireStatus(t, rec, http.StatusOK)
	assert.Equal(t, `"1"`, rec.Header().Get("ETag"))
	got := decodeBody[map[string]any](t, rec)
	assert.Equal(t, "Europe/Istanbul", got["zone"])
	requireError(t, c.do(http.MethodPut, "/api/v1/settings/backups", body, ifm("0")), http.StatusPreconditionFailed, "ALC-SYS-0008")
	assert.Equal(t, 1, s.countWhere("audit_log", "action = 'backup.settings_changed'"))
}

func TestHTTPSRoutes(t *testing.T) {
	s, c, admin := installed(t)
	s.stepUp(c, admin)
	rec := c.do(http.MethodGet, "/api/v1/settings/https", nil)
	requireStatus(t, rec, http.StatusOK)
	assert.Equal(t, true, decodeBody[map[string]any](t, rec)["temporary"])

	now := s.clock.Now()
	leaf := s.ca.Issue(pki.Opts{CommonName: "www.example.org", SANs: []string{"www.example.org"}}, now)
	other := s.ca.Issue(pki.Opts{CommonName: "other.example.org", SANs: []string{"other.example.org"}}, now)
	put := func(body map[string]any) *httptest.ResponseRecorder {
		s.api.ResetLimits()
		return c.do(http.MethodPut, "/api/v1/settings/https", body)
	}
	expired := s.ca.Issue(pki.Opts{CommonName: "old.example.org", NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(-time.Hour)}, now)
	weak := s.ca.Issue(pki.Opts{CommonName: "weak.example.org", KeyType: pki.RSA1024}, now)
	pfx := pki.PFX(leaf, s.ca, "right password")
	for code, body := range map[string]map[string]any{
		"ALC-TLS-0001": {"cert_pem": string(leaf.FullchainPEM), "key_pem": string(other.KeyPEM)},
		"ALC-TLS-0002": {"cert_pem": string(expired.FullchainPEM), "key_pem": string(expired.KeyPEM)},
		"ALC-TLS-0003": {"cert_pem": string(weak.FullchainPEM), "key_pem": string(weak.KeyPEM)},
		"ALC-TLS-0004": {"pfx_base64": base64.StdEncoding.EncodeToString(pfx), "pfx_password": "wrong password"},
		"ALC-TLS-0005": {"cert_pem": "not a certificate", "key_pem": "nor a key"},
	} {
		requireError(t, put(body), http.StatusUnprocessableEntity, code)
	}
	assert.True(t, s.tlsStore.Info().Temporary, "no refusal changed the certificate")

	rec = put(map[string]any{"cert_pem": string(leaf.FullchainPEM), "key_pem": string(leaf.KeyPEM)})
	requireStatus(t, rec, http.StatusOK)
	info := decodeBody[map[string]any](t, rec)
	assert.Equal(t, false, info["temporary"])
	assert.Contains(t, info["warnings"], "name_mismatch", "alice.test and localhost are not in the certificate")
	assert.Equal(t, 1, s.countWhere("audit_log", "action = 'https.certificate_replaced'"))
	assert.Equal(t, 1, s.countWhere("settings", "key = 'setup.https_choice' AND value = '\"uploaded\"'"))

	// The next handshake presents the new certificate, without a restart.
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlscert.ServerConfigFor(s.tlsStore))
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	go func() {
		if sc, err := ln.Accept(); err == nil {
			_ = sc.(*tls.Conn).Handshake()
			_ = sc.Close()
		}
	}()
	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // G402: the test compares the leaf
	require.NoError(t, err)
	assert.Equal(t, leaf.Cert.Raw, conn.ConnectionState().PeerCertificates[0].Raw)
	require.NoError(t, conn.Close())

	// A PFX with the right password.
	rec = put(map[string]any{"pfx_base64": base64.StdEncoding.EncodeToString(pfx), "pfx_password": "right password"})
	requireStatus(t, rec, http.StatusOK)

	// The key never leaves: no answer and no audit row holds it.
	keyBody := strings.Split(string(leaf.KeyPEM), "\n")[1]
	for _, e := range s.recorded() {
		assert.NotContains(t, string(e.body), keyBody, e.key())
	}
	assert.Zero(t, s.countWhere("audit_log", "details::text LIKE '%"+keyBody[:20]+"%'"))
}

func TestWizardHTTPSAndMailRoutes(t *testing.T) {
	s := newStack(t)
	admin := &account{username: "ada", password: adminPassword}
	c := s.setupUntilPassphrase(admin)
	st := statusKeys(t, c.do(http.MethodGet, "/api/v1/setup/status", nil))
	assert.Equal(t, "https", st["next_step"])
	st = statusKeys(t, c.do(http.MethodPost, "/api/v1/setup/https/keep-temporary", nil))
	assert.Equal(t, "mail", st["next_step"])
	assert.Equal(t, true, st["https_chosen"])
	st = statusKeys(t, c.do(http.MethodPost, "/api/v1/setup/mail/skip", nil))
	assert.Equal(t, "license", st["next_step"])
	assert.Equal(t, 1, s.countWhere("audit_log", "action = 'setup.https_kept_temporary'"))
	assert.Equal(t, 1, s.countWhere("audit_log", "action = 'setup.mail_skipped'"))
	requireStatus(t, c.do(http.MethodPost, "/api/v1/setup/evaluation", nil), http.StatusOK)
	requireStatus(t, c.do(http.MethodPost, "/api/v1/setup/complete", nil), http.StatusOK)

	rows := s.count("audit_log")
	st = statusKeys(t, c.do(http.MethodPost, "/api/v1/setup/https/keep-temporary", nil))
	assert.Equal(t, true, st["completed"])
	statusKeys(t, c.do(http.MethodPost, "/api/v1/setup/mail/skip", nil))
	assert.Equal(t, rows, s.count("audit_log"), "after completion both steps change nothing (S-39)")
}

func TestForwardingRoutes(t *testing.T) {
	s, c, admin := installed(t)
	s.stepUp(c, admin)
	fake := fakesyslog.Start(t, fakesyslog.Options{TLS: true})
	host, portText, ok := strings.Cut(fake.Addr(), ":")
	require.True(t, ok)
	port, err := strconv.Atoi(portText)
	require.NoError(t, err)
	body := map[string]any{"enabled": true, "host": host, "port": port, "transport": "tls", "ca_pem": string(fake.CAPEM())}
	rec := c.do(http.MethodGet, "/api/v1/settings/audit-forwarding", nil)
	requireStatus(t, rec, http.StatusOK)
	rec = c.do(http.MethodPut, "/api/v1/settings/audit-forwarding", body, func(r *http.Request) { r.Header.Set("If-Match", `"0"`) })
	requireStatus(t, rec, http.StatusOK)
	rec = c.do(http.MethodGet, "/api/v1/settings/audit-forwarding", nil)
	requireStatus(t, rec, http.StatusOK)
	got := decodeBody[map[string]any](t, rec)
	assert.Equal(t, true, got["ca_set"])
	assert.NotContains(t, got, "ca_pem")
	assert.NotContains(t, rec.Body.String(), "BEGIN CERTIFICATE")
	assert.Equal(t, `"1"`, rec.Header().Get("ETag"))

	test := func(b map[string]any) *httptest.ResponseRecorder {
		s.api.ResetLimits()
		return c.do(http.MethodPost, "/api/v1/settings/audit-forwarding/test", b)
	}
	stored := map[string]any{"enabled": true, "host": host, "port": port, "transport": "tls"} // ca_pem absent: the stored CA
	requireStatus(t, test(stored), http.StatusNoContent)
	require.Eventually(t, func() bool { return len(fake.Messages()) > 0 }, 5*time.Second, 20*time.Millisecond)
	noCA := map[string]any{"enabled": true, "host": host, "port": port, "transport": "tls", "ca_pem": ""}
	requireError(t, test(noCA), http.StatusBadGateway, "ALC-AUD-0004")
	requireError(t, test(map[string]any{"enabled": true, "host": "169.254.169.254", "port": port, "transport": "tls"}),
		http.StatusUnprocessableEntity, "ALC-AUD-0002")
	fake.Down()
	requireError(t, test(stored), http.StatusBadGateway, "ALC-AUD-0003")
}

func TestDashboardBackupAndChecklist(t *testing.T) {
	s := newStack(t)
	admin := &account{username: "ada", password: adminPassword}
	c := s.setupUntilPassphrase(admin)
	statusKeys(t, c.do(http.MethodPost, "/api/v1/setup/https/keep-temporary", nil))
	statusKeys(t, c.do(http.MethodPost, "/api/v1/setup/mail/skip", nil))
	requireStatus(t, c.do(http.MethodPost, "/api/v1/setup/evaluation", nil), http.StatusOK)
	requireStatus(t, c.do(http.MethodPost, "/api/v1/setup/complete", nil), http.StatusOK)
	s.stepUp(c, admin)
	requireStatus(t, c.do(http.MethodPost, "/api/v1/backups", nil), http.StatusCreated)

	summary := func(cl *client) map[string]any {
		rec := cl.do(http.MethodGet, "/api/v1/dashboard/summary", nil)
		requireStatus(t, rec, http.StatusOK)
		return decodeBody[map[string]any](t, rec)
	}
	sum := summary(c)
	require.Contains(t, sum, "backup")
	assert.Equal(t, false, sum["backup"].(map[string]any)["alarm"])
	items := map[string]bool{}
	for _, it := range sum["setup_checklist"].([]any) {
		m := it.(map[string]any)
		items[m["item"].(string)] = m["done"].(bool)
	}
	assert.Equal(t, map[string]bool{"passphrase": true, "https": false, "mail": false, "license": false, "target": false}, items)

	auditor := s.createUser(c, admin, "audrey", "auditor", "auditor password long enough")
	ac := s.freshClient()
	s.firstSignIn(ac, auditor)
	operator := s.createUser(c, admin, "otto", "operator", "operator password long enough")
	oc := s.freshClient()
	s.firstSignIn(oc, operator)
	as := summary(ac)
	assert.Contains(t, as, "backup")
	assert.NotContains(t, as, "setup_checklist")
	opSum := summary(oc)
	assert.NotContains(t, opSum, "backup")
	assert.NotContains(t, opSum, "setup_checklist")

	s.clock.Advance(49 * time.Hour)
	s.signIn(c, admin)
	assert.Equal(t, true, summary(c)["backup"].(map[string]any)["alarm"])
	_ = backup.AlarmAfter
}
