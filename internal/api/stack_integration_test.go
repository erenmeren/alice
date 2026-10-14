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
	"net"
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

	"alice/internal/alerts"
	"alice/internal/audit"
	"alice/internal/audit/forward"
	"alice/internal/auth"
	"alice/internal/auth/oidc"
	"alice/internal/backup"
	"alice/internal/discovery/discoverysvc"
	"alice/internal/i18n"
	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/jobs/acmejobs"
	"alice/internal/jobs/deployjobs"
	"alice/internal/jobs/kvjobs"
	"alice/internal/jobs/netdiscojobs"
	"alice/internal/jobs/sshkeyjobs"
	"alice/internal/jobs/targetjobs"
	"alice/internal/license"
	"alice/internal/license/licensetest"
	"alice/internal/notify"
	"alice/internal/platform/clock"
	"alice/internal/platform/db"
	"alice/internal/platform/logging"
	"alice/internal/platform/netaddr"
	"alice/internal/platform/tlscert"
	"alice/internal/providers"
	"alice/internal/providers/linuxssh"
	"alice/internal/providers/linuxssh/helperproto"
	"alice/internal/providers/nginx"
	"alice/internal/reports"
	"alice/internal/secrets"
	"alice/internal/setup"
	"alice/internal/sshkeys"
	"alice/internal/testutil/fakeidp"
	"alice/internal/testutil/fakekv"
	"alice/internal/testutil/fakesmtp"
	"alice/internal/testutil/pgtest"
	"alice/internal/testutil/pki"
	"alice/internal/testutil/scanpolicy"
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
	t        testing.TB // a *testing.T, or the *testing.F of a fuzz target (installed(f))
	db       *pgtest.DB
	clock    *clock.Fake
	keysDir  string
	logs     *syncBuffer
	rawLogs  *syncBuffer // every record also BEFORE redaction (the ACME leak suite scans it: no secret is even handed to a logger)
	trusted  []netip.Prefix
	keyring  *secrets.Keyring
	auth     *auth.Service
	setup    *setup.Service
	auditSvc *audit.Service
	license  *license.Service
	inv      *inventory.Service
	sshKeys  *sshkeys.Service // Phase 6: generated keys and rotation; its job handlers are on every runner (sshkeyjobs)
	// Phase 7: mail settings, expiry thresholds, the dashboard, exports and saved views, wired as cmd/alice does (release:
	// no dialer override and no fallback mailbox).
	mail        *notify.Settings
	alerts      *alerts.Service
	reports     *reports.Service
	sso         *oidc.Service    // Phase 7: identity providers and the OIDC sign-in
	smtp        *fakesmtp.Server // Phase 7: the fake mail server (user "mailer", stackSMTPPassword); nil until startFakes
	idp         *fakeidp.Server  // Phase 7: the fake identity provider (token clock: s.clock); nil until startFakes
	tick        *tickClock       // the Phase 6 services' clock: s.clock, moving 1 ms on every read while switched on
	mailbox     *mailbox         // what deliverMail handed to the "SMTP server"
	auditLog    *audit.Log
	queue       *jobs.Queue
	runner      *jobs.Runner
	registry    *providers.Registry
	ca          *pki.CA // issues every certificate of the Nginx journeys; its root is the inventory's trust anchor
	stateDir    string
	handler     http.Handler
	api         *Server // the server behind handler as start built it (denial summaries, AUD-06)
	setupCode   string
	tokMu       sync.Mutex // guards toks and sentPFX (keyvault_harness_integration_test.go)
	toks        map[string]bool
	sentPFX     [][]byte
	closePanics atomic.Bool    // the Key Vault provider's sessions panic when closed (keyvault_harness_integration_test.go)
	kv          *fakekv.Server // the fake Azure service behind the real azurekv provider (nil: no Key Vault in this stack)
	// Phase 8: backups (into backupsDir), audit forwarding and the HTTPS certificate store, wired as cmd/alice does.
	backup     *backup.Service
	backupsDir string
	forward    *forward.Forwarder
	tlsStore   *tlscert.Store
	backupHook func(name string) // tests: sees every name the backup service is asked to open
	// Network discovery (Task 9): the service as cmd/alice builds it, with the stack's name resolver (names maps a host
	// name to its addresses; any other name does not resolve, so no test ever asks a real name server).
	discovery *discoverysvc.Service
	names     map[string][]netip.Addr

	mu        sync.Mutex
	nginxSrvs []*nginxFixture // the emulated Nginx hosts Alice's own TLS probe can reach
	wrap      func(providers.TargetRef, providers.Session) providers.Session
	down      bool // Nginx servers are unreachable
	exchanges []exchange
	totpCodes []string // every code totpNow handed out (leak canaries)
	ips       atomic.Int64
}

func newStack(t testing.TB, trusted ...netip.Prefix) *stack {
	t.Helper()
	return newStackWith(t, stackStart, nil, trusted...)
}

// newStackWith is newStack with a start time and, optionally, a fake Azure service: the stack then
// registers the REAL azurekv provider (its connections mapped to the fake by the integration-only
// seam, trusting only the fake's CA), the Key Vault job handlers, and trusts the fake's CA as a
// certificate root of the inventory.
func newStackWith(t testing.TB, start time.Time, kv func(now func() time.Time) *fakekv.Server, trusted ...netip.Prefix) *stack {
	t.Helper()
	s := &stack{
		t:        t,
		db:       pgtest.New(t),
		clock:    clock.NewFake(start),
		keysDir:  t.TempDir(),
		stateDir: t.TempDir(),
		logs:     &syncBuffer{},
		rawLogs:  &syncBuffer{},
		trusted:  trusted,
		mailbox:  &mailbox{},
	}
	s.tick = &tickClock{Fake: s.clock}
	s.ca = pki.NewCA("API Test CA", pki.ECDSA256, s.clock.Now())
	if kv != nil {
		s.kv = kv(s.clock.Now)
	}
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
		Log: s.logger(), Targets: inventory.Counter{},
		RowLockTimeout: 200 * time.Millisecond, // tests that hold the license row (AUD-02) do not wait 30 s
	})
	require.NoError(t, s.license.Start(ctx))
	s.auth = auth.NewService(auth.Config{
		Pool: s.db.App, Keyring: keyring, Audit: auditLog, Clock: s.clock, Hasher: hasher, RecoveryHasher: hasher,
	})
	s.auditSvc = audit.NewService(auditLog, s.db.App)
	s.startInventory(keyring, auditLog)
	s.setup = setup.New(setup.Config{
		Pool: s.db.App, Auth: s.auth, Keyring: keyring, Audit: auditLog, Clock: s.clock, Hasher: hasher,
		// The lowest cost the backup header accepts (C7: 8,192 KiB), so the stack's backups open.
		BackupKDF: secrets.KDFParams{MemoryKiB: 8192, Time: 1, Threads: 1}, License: s.license, Mail: s.mail,
	})
	s.startPhase8(keyring, auditLog)
	s.api = New(s.deps())
	s.handler = s.api.Handler()
}

// startInventory builds the Phase 3 services the way cmd/alice does: the job queue, the inventory
// with the platform key, the linuxssh provider over a real dialer (pinned against the inventory's
// host-key store) and a job runner with the target handlers. Tests drive the runner with RunOnce.
// The dialer uses the real clock: it only measures network timeouts.
func (s *stack) startInventory(keyring *secrets.Keyring, auditLog *audit.Log) {
	t := s.t
	t.Helper()
	log := s.logger()
	s.queue = jobs.NewQueue(jobs.QueueConfig{Pool: s.db.App, Keyring: keyring, Audit: auditLog, Clock: s.clock, Gate: s.license})
	s.registry = providers.NewRegistry()
	roots := x509.NewCertPool()
	roots.AddCert(s.ca.Root)
	if s.kv != nil {
		require.True(t, roots.AppendCertsFromPEM(s.kv.CAPEM()))
	}
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
	if s.kv != nil {
		s.registry.Register(s.azureProvider())
	}
	s.registry.Register(stackNginx{Provider: nginx.New(nginx.Options{SSH: ssh, Prober: stackProber{s}, Attempts: 1}), s: s})
	s.registry.Freeze()
	_, err := s.inv.EnsurePlatformKey(context.Background())
	require.NoError(t, err)
	s.sshKeys = sshkeys.New(sshkeys.Config{
		Pool: s.db.App, Keyring: keyring, Audit: auditLog, Clock: s.tick, License: s.license, Inventory: s.inv, Jobs: s.queue,
		Notifier: notify.AdminNotifier{Clock: s.tick}, Log: log, HelperBudget: helperproto.HelperBudget,
	})
	s.auditLog = auditLog
	catalog, err := i18n.Load(locales.FS)
	require.NoError(t, err)
	s.mail = notify.NewSettings(notify.SettingsConfig{Pool: s.db.App, Keyring: keyring, Audit: auditLog, Clock: s.clock, Catalog: catalog, Log: log})
	s.alerts = alerts.New(alerts.Config{Pool: s.db.App, Audit: auditLog, Clock: s.clock, License: s.license,
		Notifier: notify.AdminNotifier{Clock: s.clock}, Log: log})
	s.reports = reports.New(reports.Config{Pool: s.db.App, Clock: s.clock, Audit: auditLog, License: s.license, Alerts: s.alerts,
		Delivery: s.mail, Inventory: s.inv})
	s.sso = oidc.New(oidc.Config{Pool: s.db.App, Keyring: keyring, Audit: auditLog, Clock: s.clock, Auth: s.auth, Log: log})
	s.discovery = discoverysvc.New(discoverysvc.Config{Pool: s.db.App, Audit: auditLog, Queue: s.queue, Clock: s.clock, Resolver: stackResolver{s}})
	s.runner = s.newRunner("", 0)
}

// startPhase8 builds the backup service, the audit forwarder and the certificate store as cmd/alice does (the
// backup KDF is the fast test one of setup; the forwarder dials through netaddr).
func (s *stack) startPhase8(keyring *secrets.Keyring, auditLog *audit.Log) {
	t := s.t
	t.Helper()
	log := s.logger()
	if s.backupsDir == "" {
		s.backupsDir = t.TempDir()
	}
	s.backup = backup.New(backup.Config{Pool: s.db.App, Audit: auditLog, Notifier: notify.AdminNotifier{Clock: s.clock}, Clock: s.clock,
		Dir: s.backupsDir, KeysDir: s.keysDir, StateDir: s.stateDir, Version: "1.0.0", Log: log, Keyring: keyring})
	s.forward = forward.New(forward.Config{Pool: s.db.App, Audit: auditLog, Clock: s.clock, Log: log, Hostname: "alice.test"})
	store, err := tlscert.NewStore(s.keysDir, []string{"localhost"}, s.clock.Now)
	require.NoError(t, err)
	s.tlsStore = store
}

// stackBackup is the stack's backup service with a hook on Open (the path-trick test records every name).
type stackBackup struct {
	BackupService
	s *stack
}

func (b stackBackup) Open(ctx context.Context, name string) (*os.File, backup.Info, error) {
	if b.s.backupHook != nil {
		b.s.backupHook(name)
	}
	return b.BackupService.Open(ctx, name)
}

// newRunner builds a job runner with the target and deployment handlers, the way cmd/alice does
// (the sweep of unfinished deployments is driven by the tests). A second runner with its own worker
// name and a heartbeat that never beats on the fake clock stands for a process that dies.
func (s *stack) newRunner(worker string, heartbeat time.Duration) *jobs.Runner {
	log := s.logger()
	r := jobs.NewRunner(jobs.RunnerConfig{
		Pool: s.db.App, Queue: s.queue, Gate: s.license, Audit: s.auditLog, Clock: s.clock, Log: log,
		Jitter: func() float64 { return 0 }, WorkerID: worker, Heartbeat: heartbeat, Notifier: notify.AdminNotifier{Clock: s.clock},
	})
	targetjobs.Register(r, targetjobs.Deps{Inventory: s.inv, Registry: s.registry, Clock: s.clock, Log: log})
	deployjobs.Register(r, deployjobs.Deps{Inventory: s.inv, Registry: s.registry, Clock: s.clock, Log: log})
	if s.kv != nil {
		kvjobs.Register(r, kvjobs.Deps{Inventory: s.inv, Registry: s.registry, Clock: s.clock, Log: log})
	}
	// Phase 6: sshkey.add and rotation.location, as cmd/alice wires them (the services' clock).
	sshkeyjobs.Register(r, sshkeyjobs.Deps{Keys: s.sshKeys, Targets: s.inv, Registry: s.registry, Clock: s.tick, Gate: s.license, Log: log})
	// ACME: acme.issue and acme.cleanup, as cmd/alice wires them.
	acmejobs.Register(r, acmejobs.Deps{Inventory: s.inv, Registry: s.registry, Gate: s.license, Clock: s.clock, Log: log})
	// Network discovery: netdisco.scan as cmd/alice wires it, except the scan policy (the test one: Alice's own interface
	// addresses may be dialed, so the fleet can listen on one of them; every other rule of the scan still applies) and
	// the resolver. A scan paces its connections on the real clock.
	netdiscojobs.Register(r, netdiscojobs.Deps{Pool: s.db.App, Queue: s.queue, License: s.license, Clock: clock.Real{}, Log: log,
		DatabaseURL: s.db.AppURL, Audit: s.auditLog, Resolver: stackResolver{s},
		NewPolicy: func(context.Context, netaddr.ScanPolicyInputs) (netaddr.ScanPolicy, error) {
			return scanpolicy.Permissive(), nil
		}})
	return r
}

// stackResolver answers the stack's names map.
type stackResolver struct{ s *stack }

func (r stackResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if a, ok := r.s.names[host]; ok {
		return a, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
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
		Log:            s.logger(),
		Clock:          s.clock,
		Auth:           s.auth,
		Setup:          s.setup,
		Audit:          s.auditSvc,
		License:        s.license,
		Inventory:      s.inv,
		ACME:           s.inv,
		Discovery:      s.discovery,
		Jobs:           s.queue,
		Providers:      s.registry,
		SSHKeys:        s.sshKeys,
		Mail:           s.mail,
		Alerts:         s.alerts,
		Reports:        s.reports,
		SSO:            s.sso,
		Backup:         stackBackup{BackupService: s.backup, s: s},
		Forward:        s.forward,
		TLSStore:       setup.CertificateInstaller{Store: s.tlsStore, Setup: s.setup, Log: s.logger()},
		TrustedProxies: s.trusted,
	}
}

// logger is the services' logger: the redacting JSON logger of cmd/alice (logging.New) writing to s.logs, and the same
// records unredacted to s.rawLogs.
func (s *stack) logger() *slog.Logger {
	opts := &slog.HandlerOptions{Level: slog.LevelDebug}
	return slog.New(slog.NewMultiHandler(logging.NewRedactingHandler(slog.NewJSONHandler(s.logs, opts)), slog.NewJSONHandler(s.rawLogs, opts)))
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
	req.Header.Set(activityHeader, "1") // the integration clients act like a person; tests of background work remove it
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

func requireStatus(t testing.TB, rec *httptest.ResponseRecorder, want int) {
	t.Helper()
	require.Equal(t, want, rec.Code, "body: %s", rec.Body.String())
}

type apiError struct {
	Error struct {
		Code       string            `json:"code"`
		Reason     string            `json:"reason"`
		MessageKey string            `json:"message_key"`
		Message    string            `json:"message"`
		RequestID  string            `json:"request_id"`
		Params     map[string]string `json:"params"`
	} `json:"error"`
}

// requireError asserts the status and the stable ALC code of an error response.
func requireError(t testing.TB, rec *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	requireStatus(t, rec, status)
	var e apiError
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &e), rec.Body.String())
	require.Equal(t, code, e.Error.Code, rec.Body.String())
}

func decodeBody[T any](t testing.TB, rec *httptest.ResponseRecorder) T {
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

// stackSMTPPassword is the password the stack's fake mail server requires of user "mailer" (a canary: the leak suite
// looks for it everywhere).
const stackSMTPPassword = "CANARY-stack-smtp-password-5c2e"

// startFakes starts the stack's fake mail server and fake identity provider (Phase 7), once per stack: a restart
// (start) keeps them, as a restart of Alice keeps the outside world. They are closed by t.Cleanup. Only the Phase 7
// suites start them, so the other suites do not pay for their keys.
func (s *stack) startFakes() {
	s.t.Helper()
	if s.smtp == nil {
		s.smtp = fakesmtp.Start(s.t, fakesmtp.Options{Username: "mailer", Password: stackSMTPPassword})
	}
	if s.idp == nil {
		s.idp = fakeidp.Start(s.t, fakeidp.Options{Now: s.clock.Now})
	}
}

// installedWithFakes is installed with the Phase 7 fakes started.
func installedWithFakes(t *testing.T) (*stack, *client, *account) {
	t.Helper()
	s, c, a := installed(t)
	s.startFakes()
	return s, c, a
}

// etagVersion is the version of a strong ETag ("3" -> 3 as text).
func etagVersion(t testing.TB, rec *httptest.ResponseRecorder) string {
	t.Helper()
	tag := rec.Header().Get("ETag")
	require.Regexp(t, `^"[0-9]+"$`, tag)
	return strings.Trim(tag, `"`)
}

// mailBody is a mail settings change for the stack's fake mail server.
func (s *stack) mailBody(password any) map[string]any {
	host, port := s.smtp.Addr()
	b := map[string]any{"host": host, "port": port, "tls_mode": "starttls", "from": "alice@example.com", "username": "mailer", "ca_pem": ""}
	if password != nil {
		b["password"] = password
	}
	return b
}

// configureMail stores working mail settings through the API and trusts the fake server's certificate the way an
// Administrator does (F-62): a test e-mail shows the certificate, Trust pins it, the next test e-mail is sent. The
// admin must be stepped up. The fake's mailbox is emptied afterwards.
func (s *stack) configureMail(admin *client) {
	t := s.t
	t.Helper()
	cur := admin.do(http.MethodGet, "/api/v1/settings/smtp", nil)
	requireStatus(t, cur, http.StatusOK)
	rec := admin.do(http.MethodPut, "/api/v1/settings/smtp", s.mailBody(stackSMTPPassword), ifMatchOf(etagVersion(t, cur)))
	requireStatus(t, rec, http.StatusOK)
	version := etagVersion(t, rec)
	rec = admin.do(http.MethodPost, "/api/v1/settings/smtp/actions/test", map[string]string{"to": "ops@example.com"})
	requireError(t, rec, http.StatusBadGateway, "ALC-NTF-0005")
	fp := decodeBody[apiError](t, rec).Error.Params["fingerprint"]
	require.Equal(t, s.smtp.Fingerprint(), fp)
	requireStatus(t, admin.do(http.MethodPost, "/api/v1/settings/smtp/actions/trust", map[string]string{"fingerprint": fp},
		ifMatchOf(version)), http.StatusOK)
	requireStatus(t, admin.do(http.MethodPost, "/api/v1/settings/smtp/actions/test", map[string]string{"to": "ops@example.com"}),
		http.StatusOK)
	require.Len(t, s.smtp.Messages(), 1)
	s.smtp.Clear()
}

// drainMail drains the outbox the way the notify.send job does in production: notify.Sender with the mail settings
// as its mailer source (the stack's fake mail server once configureMail ran). It returns how many e-mails it handled.
func (s *stack) drainMail() int {
	s.t.Helper()
	catalog, err := i18n.Load(locales.FS)
	require.NoError(s.t, err)
	sender := notify.Sender{Pool: s.db.App, Source: s.mail, Catalog: catalog, Clock: s.clock, Log: s.logger()}
	n, err := sender.Drain(context.Background())
	require.NoError(s.t, err)
	return n
}

// userID reads a user's ID by user name (owner pool).
func (s *stack) userID(username string) string {
	s.t.Helper()
	var id string
	require.NoError(s.t, s.db.Owner.QueryRow(context.Background(), `SELECT id::text FROM users WHERE username = $1`, username).Scan(&id))
	return id
}
