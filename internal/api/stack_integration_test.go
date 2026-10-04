//go:build integration

package api

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/auth"
	"alice/internal/i18n"
	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/jobs/deployjobs"
	"alice/internal/jobs/targetjobs"
	"alice/internal/license"
	"alice/internal/license/licensetest"
	"alice/internal/notify"
	"alice/internal/platform/clock"
	"alice/internal/platform/db"
	"alice/internal/platform/logging"
	"alice/internal/providers"
	"alice/internal/providers/linuxssh"
	"alice/internal/providers/nginx"
	"alice/internal/secrets"
	"alice/internal/setup"
	"alice/internal/testutil/pgtest"
	"alice/internal/testutil/pki"
	"alice/internal/version"
	"alice/locales"
	"alice/migrations"
)

// Integration suites for the whole HTTP stack: real services, real PostgreSQL
// (one fresh database per test), a fake clock and cheap Argon2id parameters.
// Production Argon2id parameters are asserted in internal/auth and internal/secrets.

func TestMain(m *testing.M) {
	os.Exit(pgtest.Main(m))
}

var stackStart = time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)

var fastArgon = auth.Argon2Params{MemoryKiB: 64, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}

const stackIndexHTML = `<!doctype html><html><head><meta name="csp-nonce" content="__CSP_NONCE__"></head><body><div id="root"></div></body></html>`

// syncBuffer collects log output from concurrent handlers.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// exchange is one recorded request/response pair, scanned by the leak tests.
type exchange struct {
	method, path string
	status       int
	header       http.Header
	body         []byte
}

func (e exchange) key() string { return e.method + " " + e.path }

type stack struct {
	t         *testing.T
	db        *pgtest.DB
	clock     *clock.Fake
	keysDir   string
	logs      *syncBuffer
	trusted   []netip.Prefix
	keyring   *secrets.Keyring
	auth      *auth.Service
	setup     *setup.Service
	auditSvc  *audit.Service
	license   *license.Service
	inv       *inventory.Service
	queue     *jobs.Queue
	runner    *jobs.Runner
	registry  *providers.Registry
	ca        *pki.CA // issues every certificate of the Nginx journeys; its root is the inventory's trust anchor
	stateDir  string
	handler   http.Handler
	setupCode string

	mu        sync.Mutex
	nginxSrvs []*nginxFixture // the emulated Nginx hosts Alice's own TLS probe can reach
	wrap      func(providers.TargetRef, providers.Session) providers.Session
	exchanges []exchange
	totpCodes []string // every code totpNow handed out (leak canaries)
	ips       atomic.Int64
}

func newStack(t *testing.T, trusted ...netip.Prefix) *stack {
	t.Helper()
	s := &stack{
		t:        t,
		db:       pgtest.New(t),
		clock:    clock.NewFake(stackStart),
		keysDir:  t.TempDir(),
		stateDir: t.TempDir(),
		logs:     &syncBuffer{},
		trusted:  trusted,
	}
	s.ca = pki.NewCA("API Test CA", pki.ECDSA256, s.clock.Now())
	s.start()
	return s
}

// start builds every service and the HTTP handler on the stack's database,
// key directory and clock. Calling it again simulates a process restart:
// in-memory state (rate limiters, lockout counters of the setup code) is lost.
func (s *stack) start() {
	t := s.t
	t.Helper()
	ctx := context.Background()
	keyring, err := secrets.LoadOrCreateMasterKey(ctx, s.db.App, s.keysDir, s.clock.Now())
	require.NoError(t, err)
	auditLog := audit.New(s.clock)
	hasher := auth.NewHasher(fastArgon, 4)
	s.keyring = keyring
	s.license = license.New(license.Config{
		Pool: s.db.App, Keyring: keyring, Audit: auditLog, Clock: s.clock, Uptime: s.clock,
		Keys: licensetest.KeySet(), StateDir: s.stateDir, Notifier: notify.AdminNotifier{Clock: s.clock},
		Log: logging.New(s.logs, slog.LevelDebug), Targets: inventory.Counter{},
	})
	require.NoError(t, s.license.Start(ctx))
	s.auth = auth.NewService(auth.Config{
		Pool: s.db.App, Keyring: keyring, Audit: auditLog, Clock: s.clock, Hasher: hasher, RecoveryHasher: hasher,
	})
	s.setup = setup.New(setup.Config{
		Pool: s.db.App, Auth: s.auth, Keyring: keyring, Audit: auditLog, Clock: s.clock, Hasher: hasher,
		BackupKDF: secrets.KDFParams{MemoryKiB: 64, Time: 1, Threads: 1}, License: s.license,
	})
	s.auditSvc = audit.NewService(auditLog, s.db.App)
	s.startInventory(keyring, auditLog)
	s.handler = New(s.deps()).Handler()
}

// startInventory builds the Phase 3 services the way cmd/alice does: the job queue, the inventory
// with the platform key, the linuxssh provider over a real dialer (pinned against the inventory's
// host-key store) and a job runner with the target handlers. Tests drive the runner with RunOnce.
// The dialer uses the real clock: it only measures network timeouts.
func (s *stack) startInventory(keyring *secrets.Keyring, auditLog *audit.Log) {
	t := s.t
	t.Helper()
	log := logging.New(s.logs, slog.LevelDebug)
	s.queue = jobs.NewQueue(jobs.QueueConfig{Pool: s.db.App, Keyring: keyring, Audit: auditLog, Clock: s.clock, Gate: s.license})
	s.registry = providers.NewRegistry()
	roots := x509.NewCertPool()
	roots.AddCert(s.ca.Root)
	s.inv = inventory.New(inventory.Config{
		Pool: s.db.App, Keyring: keyring, Audit: auditLog, Clock: s.clock, License: s.license, Registry: s.registry,
		Jobs: s.queue, Notifier: notify.AdminNotifier{Clock: s.clock}, Log: log, Roots: roots,
	})
	pool := linuxssh.NewPool(&linuxssh.Dialer{Clock: clock.Real{}, HostKeys: s.inv.HostKeyStore()},
		linuxssh.MaxConnections, linuxssh.MaxConnectionsPerTarget, linuxssh.IdleTimeout)
	t.Cleanup(pool.Close)
	ssh := linuxssh.New(linuxssh.Options{Pool: pool, AllowUnverifiedHelper: true})
	s.registry.Register(ssh)
	// One verification attempt per endpoint: the provider's waits run on the session clock, which is
	// the fake clock here.
	s.registry.Register(stackNginx{Provider: nginx.New(nginx.Options{SSH: ssh, Prober: stackProber{s}, Attempts: 1}), s: s})
	s.registry.Freeze()
	_, err := s.inv.EnsurePlatformKey(context.Background())
	require.NoError(t, err)
	s.runner = jobs.NewRunner(jobs.RunnerConfig{
		Pool: s.db.App, Queue: s.queue, Gate: s.license, Audit: auditLog, Clock: s.clock, Log: log,
		Jitter: func() float64 { return 0 },
	})
	targetjobs.Register(s.runner, targetjobs.Deps{Inventory: s.inv, Registry: s.registry, Clock: s.clock, Log: log})
	deployjobs.Register(s.runner, deployjobs.Deps{Inventory: s.inv, Registry: s.registry, Clock: s.clock, Log: log})
}

// deps are the handler dependencies of the current services. Tests that need
// a modified service replace one field and rebuild s.handler from them.
func (s *stack) deps() Deps {
	t := s.t
	t.Helper()
	catalog, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	health, err := db.NewHealthChecker(s.db.App, migrations.FS)
	require.NoError(t, err)
	return Deps{
		Health:         health,
		Catalog:        catalog,
		Version:        version.Info{Version: "test", Commit: "test", BuildTime: "test"},
		UI:             fstest.MapFS{"index.html": {Data: []byte(stackIndexHTML)}},
		Log:            logging.New(s.logs, slog.LevelDebug),
		Clock:          s.clock,
		Auth:           s.auth,
		Setup:          s.setup,
		Audit:          s.auditSvc,
		License:        s.license,
		Inventory:      s.inv,
		Jobs:           s.queue,
		Providers:      s.registry,
		TrustedProxies: s.trusted,
	}
}

func (s *stack) record(method, path string, rec *httptest.ResponseRecorder) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.exchanges = append(s.exchanges, exchange{
		method: method, path: strings.SplitN(path, "?", 2)[0], status: rec.Code,
		header: rec.Header().Clone(), body: append([]byte(nil), rec.Body.Bytes()...),
	})
}

func (s *stack) recorded() []exchange {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]exchange(nil), s.exchanges...)
}

// client is one browser (or API client) with its own cookies, CSRF token and IP.
type client struct {
	s       *stack
	ip      string
	cookies map[string]string
	csrf    string
	bearer  string
}

func (s *stack) client(ip string) *client {
	return &client{s: s, ip: ip, cookies: map[string]string{}}
}

// freshClient returns a client with a new, unique source IP (so per-IP login limits never interfere).
func (s *stack) freshClient() *client {
	n := s.ips.Add(1)
	return s.client(fmt.Sprintf("10.9.%d.%d", n/250, n%250+1))
}

type reqOpt func(*http.Request)

// do sends one request the way the SPA does: same-origin headers, the CSRF
// token on state-changing requests, and the cookies the server set earlier.
func (c *client) do(method, path string, body any, opts ...reqOpt) *httptest.ResponseRecorder {
	c.s.t.Helper()
	var rdr io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rdr = strings.NewReader(b)
	case []byte:
		rdr = bytes.NewReader(b)
	default:
		j, err := json.Marshal(b)
		require.NoError(c.s.t, err)
		rdr = bytes.NewReader(j)
	}
	req := httptest.NewRequest(method, "https://alice.test"+path, rdr)
	req.RemoteAddr = c.ip + ":40000"
	req.Header.Set("Accept", "application/json")
	if rdr != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet && method != http.MethodHead {
		req.Header.Set("Origin", "https://alice.test")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		if c.csrf != "" {
			req.Header.Set("X-CSRF-Token", c.csrf)
		}
	}
	for name, value := range c.cookies {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	if c.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearer)
	}
	for _, o := range opts {
		o(req)
	}
	rec := httptest.NewRecorder()
	c.s.handler.ServeHTTP(rec, req)
	c.s.record(method, path, rec)

	for _, ck := range responseCookies(rec) {
		if ck.MaxAge < 0 || ck.Value == "" {
			delete(c.cookies, ck.Name)
		} else {
			c.cookies[ck.Name] = ck.Value
		}
	}
	var probe struct {
		CSRFToken string `json:"csrf_token"`
	}
	if json.Unmarshal(rec.Body.Bytes(), &probe) == nil && probe.CSRFToken != "" {
		c.csrf = probe.CSRFToken
	}
	return rec
}

func responseCookies(rec *httptest.ResponseRecorder) []*http.Cookie {
	res := rec.Result()
	defer func() { _ = res.Body.Close() }()
	return res.Cookies()
}

func requireStatus(t *testing.T, rec *httptest.ResponseRecorder, want int) {
	t.Helper()
	require.Equal(t, want, rec.Code, "body: %s", rec.Body.String())
}

type apiError struct {
	Error struct {
		Code       string `json:"code"`
		Reason     string `json:"reason"`
		MessageKey string `json:"message_key"`
		Message    string `json:"message"`
		RequestID  string `json:"request_id"`
	} `json:"error"`
}

// requireError asserts the status and the stable ALC code of an error response.
func requireError(t *testing.T, rec *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	requireStatus(t, rec, status)
	var e apiError
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &e), rec.Body.String())
	require.Equal(t, code, e.Error.Code, rec.Body.String())
}

func decodeBody[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &v), rec.Body.String())
	return v
}

// totpNow is the code an authenticator app shows at the stack's current time.
func (s *stack) totpNow(secret string) string {
	s.t.Helper()
	code, err := totp.GenerateCodeCustom(secret, s.clock.Now(), totp.ValidateOpts{
		Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	require.NoError(s.t, err)
	s.mu.Lock()
	s.totpCodes = append(s.totpCodes, code)
	s.mu.Unlock()
	return code
}

// account is a user as the tests know it.
type account struct {
	id       string
	username string
	password string
	secret   string   // TOTP secret base32
	recovery []string // current recovery codes
}

type enrollmentBody struct {
	Secret     string `json:"secret"`
	OtpauthURI string `json:"otpauth_uri"`
	QRPNG      string `json:"qr_png"`
}

type sessionBody struct {
	User struct {
		ID       string `json:"id"`
		Username string `json:"username"`
		Role     string `json:"role"`
	} `json:"user"`
	CSRFToken     string   `json:"csrf_token"`
	RecoveryCodes []string `json:"recovery_codes"`
}

// setupAdmin runs the Phase 1 wizard on a fresh install and returns the
// signed-in administrator's browser. afterEnroll (optional) runs while the
// pending administrator is stored in setup_sessions.
func (s *stack) setupAdmin(a *account, passphrase string, afterEnroll func()) *client {
	t := s.t
	t.Helper()
	code, err := s.setup.ResetToken(context.Background())
	require.NoError(t, err)
	s.setupCode = code

	c := s.client("198.51.100.10")
	requireStatus(t, c.do(http.MethodPost, "/api/v1/setup/session", map[string]string{"code": code}), http.StatusOK)
	requireStatus(t, c.do(http.MethodPut, "/api/v1/setup/language", map[string]string{"language": "en"}), http.StatusNoContent)
	rec := c.do(http.MethodPost, "/api/v1/setup/admin/enrollment", map[string]string{
		"username": a.username, "display_name": "Ada Admin", "email": "", "password": a.password,
	})
	requireStatus(t, rec, http.StatusOK)
	a.secret = decodeBody[enrollmentBody](t, rec).Secret
	require.NotEmpty(t, a.secret)
	if afterEnroll != nil {
		afterEnroll()
	}
	rec = c.do(http.MethodPost, "/api/v1/setup/admin", map[string]string{"code": s.totpNow(a.secret)})
	requireStatus(t, rec, http.StatusOK)
	sess := decodeBody[sessionBody](t, rec)
	a.id, a.recovery = sess.User.ID, sess.RecoveryCodes
	require.Len(t, a.recovery, 10)
	require.NotEmpty(t, c.cookies[sessionCookie])
	require.Empty(t, c.cookies[setupCookie], "the wizard cookie is cleared once the admin exists")

	requireError(t, c.do(http.MethodPost, "/api/v1/setup/recovery-passphrase", map[string]string{
		"passphrase": passphrase, "passphrase_confirm": passphrase + "-mismatch",
	}), http.StatusUnprocessableEntity, "ALC-SET-0006")
	requireStatus(t, c.do(http.MethodPost, "/api/v1/setup/recovery-passphrase", map[string]string{
		"passphrase": passphrase, "passphrase_confirm": passphrase,
	}), http.StatusNoContent)
	requireError(t, c.do(http.MethodPost, "/api/v1/setup/complete", nil), http.StatusConflict, "ALC-SET-0009")
	requireStatus(t, c.do(http.MethodPost, "/api/v1/setup/evaluation", nil), http.StatusOK)
	requireStatus(t, c.do(http.MethodPost, "/api/v1/setup/complete", nil), http.StatusOK)
	return c
}

// signIn logs an enrolled account in on c. The clock moves 31 s first so the
// TOTP code is never one that was already used.
func (s *stack) signIn(c *client, a *account) {
	t := s.t
	t.Helper()
	s.clock.Advance(31 * time.Second)
	rec := c.do(http.MethodPost, "/api/v1/auth/login", map[string]string{"username": a.username, "password": a.password})
	requireStatus(t, rec, http.StatusOK)
	require.Equal(t, "mfa_required", decodeBody[map[string]string](t, rec)["status"])
	requireStatus(t, c.do(http.MethodPost, "/api/v1/auth/mfa/verify", map[string]string{"code": s.totpNow(a.secret)}), http.StatusOK)
}

// firstSignIn logs a new user in for the first time, enrolling TOTP.
func (s *stack) firstSignIn(c *client, a *account) {
	t := s.t
	t.Helper()
	s.clock.Advance(31 * time.Second)
	rec := c.do(http.MethodPost, "/api/v1/auth/login", map[string]string{"username": a.username, "password": a.password})
	requireStatus(t, rec, http.StatusOK)
	require.Equal(t, "mfa_enrollment_required", decodeBody[map[string]string](t, rec)["status"])
	rec = c.do(http.MethodPost, "/api/v1/auth/mfa/enroll", nil)
	requireStatus(t, rec, http.StatusOK)
	a.secret = decodeBody[enrollmentBody](t, rec).Secret
	rec = c.do(http.MethodPost, "/api/v1/auth/mfa/verify", map[string]string{"code": s.totpNow(a.secret)})
	requireStatus(t, rec, http.StatusOK)
	a.recovery = decodeBody[sessionBody](t, rec).RecoveryCodes
	require.Len(t, a.recovery, 10)
}

// stepUp re-confirms the TOTP code so admin-only changes are allowed for 5 minutes.
func (s *stack) stepUp(c *client, a *account) {
	s.t.Helper()
	s.clock.Advance(31 * time.Second)
	requireStatus(s.t, c.do(http.MethodPost, "/api/v1/auth/stepup", map[string]string{"code": s.totpNow(a.secret)}), http.StatusOK)
}

// createUser creates a user as the (stepped-up) admin and returns the account.
func (s *stack) createUser(admin *client, adminAcct *account, username, role, password string) *account {
	t := s.t
	t.Helper()
	s.stepUp(admin, adminAcct)
	rec := admin.do(http.MethodPost, "/api/v1/users", map[string]string{
		"username": username, "display_name": "User " + username, "email": "", "role": role, "password": password,
	})
	requireStatus(t, rec, http.StatusCreated)
	return &account{id: decodeBody[map[string]any](t, rec)["id"].(string), username: username, password: password}
}

// login attempts the password step from a fresh IP address.
func (s *stack) login(username, password string) *httptest.ResponseRecorder {
	return s.freshClient().do(http.MethodPost, "/api/v1/auth/login", map[string]string{"username": username, "password": password})
}

// count returns the number of rows in table (read as the owner role).
func (s *stack) count(table string) int {
	s.t.Helper()
	var n int
	require.NoError(s.t, s.db.Owner.QueryRow(context.Background(), "SELECT count(*) FROM "+table).Scan(&n))
	return n
}
