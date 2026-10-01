// Package api is Alice's HTTP layer. It holds no business logic and no SQL.
package api

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"github.com/google/uuid"

	"alice/internal/audit"
	"alice/internal/auth"
	"alice/internal/auth/ratelimit"
	"alice/internal/i18n"
	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/license"
	"alice/internal/platform/clock"
	"alice/internal/platform/db"
	"alice/internal/providers"
	"alice/internal/rbac"
	"alice/internal/setup"
	"alice/internal/version"
)

// HealthChecker reports whether dependencies (the database) are ready.
type HealthChecker interface {
	Check(ctx context.Context) error
}

// AuthService is the part of auth.Service the HTTP layer uses.
type AuthService interface {
	Authenticate(ctx context.Context, sessionToken string) (auth.Principal, error)
	AuthenticateToken(ctx context.Context, bearer string) (auth.Principal, error)
	CSRFToken(sessionToken string) string
	CheckCSRF(sessionToken, header string) bool
	Login(ctx context.Context, username, password string, m auth.Meta) (auth.LoginResult, error)
	EnrollMFA(ctx context.Context, p auth.Principal, m auth.Meta) (auth.TOTPEnrollment, error)
	VerifyMFA(ctx context.Context, p auth.Principal, in auth.MFAInput, m auth.Meta) (auth.SessionResult, error)
	SessionInfo(ctx context.Context, p auth.Principal, sessionToken string) (auth.SessionInfo, error)
	StepUp(ctx context.Context, p auth.Principal, code string, m auth.Meta) (auth.SessionResult, error)
	Logout(ctx context.Context, p auth.Principal, m auth.Meta) error
	ChangePassword(ctx context.Context, p auth.Principal, current, next string, m auth.Meta) (auth.SessionResult, error)
	RegenerateRecoveryCodes(ctx context.Context, p auth.Principal, m auth.Meta) ([]string, error)
	SetLocale(ctx context.Context, p auth.Principal, locale string) error
	ListUsers(ctx context.Context) ([]auth.User, error)
	GetUser(ctx context.Context, id uuid.UUID) (auth.User, error)
	CreateUser(ctx context.Context, p auth.Principal, m auth.Meta, in auth.NewUser) (auth.User, error)
	UpdateUser(ctx context.Context, p auth.Principal, m auth.Meta, id uuid.UUID, in auth.UserUpdate) (auth.User, error)
	ResetMFA(ctx context.Context, p auth.Principal, m auth.Meta, id uuid.UUID) error
	ResetPassword(ctx context.Context, p auth.Principal, m auth.Meta, id uuid.UUID, password string) error
	RevokeSessions(ctx context.Context, p auth.Principal, m auth.Meta, id uuid.UUID) error
	CreateToken(ctx context.Context, p auth.Principal, m auth.Meta, in auth.NewToken) (string, auth.Token, error)
	ListTokens(ctx context.Context, p auth.Principal, m auth.Meta, userID uuid.UUID) ([]auth.Token, error)
	RevokeToken(ctx context.Context, p auth.Principal, m auth.Meta, id uuid.UUID) error
}

// SetupService is the part of setup.Service the HTTP layer uses.
type SetupService interface {
	Status(ctx context.Context) (setup.Status, error)
	StartSession(ctx context.Context, code string, m auth.Meta) (string, error)
	Authenticate(ctx context.Context, token string) error
	SetLanguage(ctx context.Context, token, language string) error
	BeginAdminEnrollment(ctx context.Context, token string, in setup.AdminInput) (auth.TOTPEnrollment, error)
	CreateAdmin(ctx context.Context, token, code string, m auth.Meta) (auth.SessionResult, error)
	SetRecoveryPassphrase(ctx context.Context, p auth.Principal, m auth.Meta, passphrase, confirm string) error
	ChooseEvaluation(ctx context.Context, p auth.Principal, m auth.Meta) (setup.Status, error)
	Complete(ctx context.Context, p auth.Principal, m auth.Meta) (setup.Status, error)
}

// AuditService is the part of audit.Service the HTTP layer uses.
type AuditService interface {
	Write(ctx context.Context, e audit.Event) error
	List(ctx context.Context, f audit.Filter) ([]audit.Entry, int64, error)
	Iterate(ctx context.Context, fn func(audit.Entry) error) error
	Verify(ctx context.Context, actor audit.Actor) (audit.Report, error)
	// VerifyReadOnly checks the chain without writing a checkpoint or an audit row (used by the export).
	VerifyReadOnly(ctx context.Context) (audit.Report, error)
}

// LicenseService is the part of license.Service the HTTP layer uses.
type LicenseService interface {
	// Allow is the single lock-mode gate (spec §8.6, R9).
	Allow(c license.Class) error
	Snapshot() license.Snapshot
	Detail(ctx context.Context) (license.Detail, error)
	Preview(ctx context.Context, raw []byte) (license.UploadResult, error)
	Install(ctx context.Context, raw []byte, actor audit.Actor, by uuid.UUID) (license.UploadResult, error)
}

// InventoryService is the part of inventory.Service the HTTP layer uses.
type InventoryService interface {
	ListTargets(ctx context.Context) ([]inventory.Target, error)
	GetTarget(ctx context.Context, id uuid.UUID) (inventory.Target, error)
	CreateTarget(ctx context.Context, a inventory.Actor, in inventory.NewTarget) (inventory.Target, uuid.UUID, error)
	UpdateTarget(ctx context.Context, a inventory.Actor, id uuid.UUID, ifVersion int, p inventory.TargetPatch) (inventory.Target, error)
	DeleteTarget(ctx context.Context, a inventory.Actor, id uuid.UUID) error
	RequestTest(ctx context.Context, a inventory.Actor, id uuid.UUID) (uuid.UUID, error)
	RequestDiscovery(ctx context.Context, a inventory.Actor, id uuid.UUID) (uuid.UUID, error)
	ListHostKeys(ctx context.Context, targetID uuid.UUID) ([]inventory.HostKeyRecord, error)
	ConfirmHostKey(ctx context.Context, a inventory.Actor, targetID, keyID uuid.UUID, fingerprint string) (uuid.UUID, error)
	RepinHostKey(ctx context.Context, a inventory.Actor, targetID, keyID uuid.UUID, fingerprint, reason string) (uuid.UUID, error)
	ListTargetKeys(ctx context.Context, targetID uuid.UUID, includeMissing bool) ([]inventory.KeyLocation, error)
	ListSSHKeys(ctx context.Context, f inventory.KeyFilter) (inventory.KeyPage, error)
	GetSSHKey(ctx context.Context, id uuid.UUID) (inventory.SSHKey, error)
	SetupGuide(ctx context.Context, from string) (inventory.Guide, error)
	RequestKeyRemoval(ctx context.Context, a inventory.Actor, locationID uuid.UUID, confirmLastRootKey bool) (uuid.UUID, error)
}

// JobsService is the part of jobs.Queue the HTTP layer uses.
type JobsService interface {
	Get(ctx context.Context, id uuid.UUID) (jobs.View, error)
	List(ctx context.Context, f jobs.ListFilter) ([]jobs.View, string, error)
	Confirm(ctx context.Context, actor audit.Actor, by uuid.UUID, id uuid.UUID) error
	Discard(ctx context.Context, actor audit.Actor, by uuid.UUID, id uuid.UUID) error
}

// ProviderCatalog lists the compiled-in providers (providers.Registry).
type ProviderCatalog interface {
	List() []providers.Descriptor
}

// Deps are the handler's dependencies, wired in cmd/alice.
type Deps struct {
	Health         HealthChecker
	Catalog        *i18n.Catalog
	Version        version.Info
	UI             fs.FS
	Log            *slog.Logger
	Clock          clock.Clock
	Auth           AuthService
	Setup          SetupService
	Audit          AuditService
	License        LicenseService
	Inventory      InventoryService
	Jobs           JobsService
	Providers      ProviderCatalog
	TrustedProxies []netip.Prefix
	TestHandler    http.Handler // nil in release builds; mounted at "/test/" by the e2e build
}

// limitClass selects the rate limits applied to a route in addition to the general limit.
type limitClass int

const (
	limitDefault limitClass = iota // general limit only
	limitNone                      // no limit (health probes)
	limitLogin                     // 10 per minute per IP (password and setup-code guessing)
	limitMFA                       // 5 per minute per IP (verification codes)
)

// route is one documented operation. The route table is the single source of
// truth for what the muxes serve and which permission each operation needs;
// openapi.yaml must list exactly these operations with the same x-permission.
type route struct {
	method  string
	pattern string
	perm    rbac.Permission
	limit   limitClass
	// lic is how lock mode treats this operation. Every non-GET route declares it: ClassAlways
	// for platform administration, ClassChange for changes to managed systems or inventory
	// (refused while the license is expired, R9). GET routes leave it unset (reads stay available).
	lic     license.Class
	handler http.HandlerFunc
}

type server struct {
	deps    Deps
	general *ratelimit.Limiter // authenticated subjects, per session or token: 300/min
	anon    *ratelimit.Limiter // anonymous and setup subjects, per IP: 60/min
	login   *ratelimit.Limiter // per IP: 10/min
	mfa     *ratelimit.Limiter // per IP: 5/min
}

func newServer(d Deps) *server {
	if d.Clock == nil {
		d.Clock = clock.Real{}
	}
	return &server{
		deps:    d,
		general: ratelimit.New(d.Clock, 300, time.Minute),
		anon:    ratelimit.New(d.Clock, 60, time.Minute),
		login:   ratelimit.New(d.Clock, 10, time.Minute),
		mfa:     ratelimit.New(d.Clock, 5, time.Minute),
	}
}

// Server is the public HTTPS handler plus the controls the e2e build needs.
type Server struct {
	s *server
	h http.Handler
}

// New builds the public HTTPS handler. It panics if a route declares an
// unknown permission or a state-changing route declares no license class, so a
// misconfigured route table never starts (SEC-016, R9).
func New(d Deps) *Server {
	s := newServer(d)
	return &Server{s: s, h: s.handler(s.apiRoutes())}
}

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler { return s.h }

// ResetLimits clears all in-memory rate limiters (used by the e2e reset endpoint).
func (s *Server) ResetLimits() {
	s.s.general.Reset()
	s.s.anon.Reset()
	s.s.login.Reset()
	s.s.mfa.Reset()
}

// NewHandler returns the public HTTPS handler.
func NewHandler(d Deps) http.Handler { return New(d).Handler() }

// NewHealthHandler returns the handler for the internal, container-local health listener.
func NewHealthHandler(d Deps) http.Handler {
	s := newServer(d)
	mux := http.NewServeMux()
	s.register(mux, s.probeRoutes())
	return s.requestID(securityHeaders(s.recoverer(mux)))
}

func (s *server) handler(routes []route) http.Handler {
	mux := http.NewServeMux()
	s.register(mux, routes)
	notFound := func(w http.ResponseWriter, r *http.Request) { s.writeError(w, r, ErrNotFound) }
	mux.HandleFunc("/api/", notFound)
	if s.deps.TestHandler != nil {
		mux.Handle("/test/", s.deps.TestHandler)
	} else {
		mux.HandleFunc("/test/", notFound) // reserved for test-only routes; never the SPA
	}
	mux.Handle("/", s.spa())
	return s.requestID(securityHeaders(s.recoverer(mux)))
}

// register is the only place routes reach a mux; every route passes through guard.
func (s *server) register(mux *http.ServeMux, routes []route) {
	for _, r := range routes {
		if _, ok := rbac.PolicyFor(r.perm); !ok {
			panic(fmt.Sprintf("api: route %s %s has unknown permission %q", r.method, r.pattern, r.perm))
		}
		if !safeMethod(r.method) && !r.lic.Valid() {
			panic(fmt.Sprintf("api: state-changing route %s %s declares no license class", r.method, r.pattern))
		}
		mux.HandleFunc(r.method+" "+r.pattern, s.guard(r))
	}
}

// probeRoutes are served on both the public and the internal health listener.
func (s *server) probeRoutes() []route {
	return []route{
		{method: http.MethodGet, pattern: "/livez", perm: rbac.Public, limit: limitNone, handler: func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		}},
		{method: http.MethodGet, pattern: "/healthz", perm: rbac.Public, limit: limitNone, handler: func(w http.ResponseWriter, r *http.Request) {
			if err := s.deps.Health.Check(r.Context()); err != nil {
				s.deps.Log.Warn("health check failed", "request_id", RequestID(r.Context()), "reason", healthReason(err))
				s.writeError(w, r, ErrUnavailable)
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		}},
	}
}

// systemRoutes are small informational endpoints.
func (s *server) systemRoutes() []route {
	return []route{
		{method: http.MethodGet, pattern: "/api/v1/version", perm: rbac.Read, handler: func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, s.deps.Version)
		}},
		{method: http.MethodGet, pattern: "/api/v1/i18n/locales", perm: rbac.Public, handler: func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, map[string]any{"default": s.deps.Catalog.Default(), "locales": s.deps.Catalog.Locales()})
		}},
	}
}

// apiRoutes are the documented operations on the public listener.
// Undocumented catch-alls (the /api/ and /test/ JSON 404s and the SPA
// fallback) are registered separately in handler and are not operations.
func (s *server) apiRoutes() []route {
	var routes []route
	routes = append(routes, s.probeRoutes()...)
	routes = append(routes, s.systemRoutes()...)
	routes = append(routes, s.setupRoutes()...)
	routes = append(routes, s.authRoutes()...)
	routes = append(routes, s.userRoutes()...)
	routes = append(routes, s.tokenRoutes()...)
	routes = append(routes, s.auditRoutes()...)
	routes = append(routes, s.licenseRoutes()...)
	routes = append(routes, s.providerRoutes()...)
	routes = append(routes, s.targetRoutes()...)
	routes = append(routes, s.sshKeyRoutes()...)
	routes = append(routes, s.jobRoutes()...)
	return routes
}

// healthReason maps an error to a fixed label so no driver text (which could
// include connection details) ever reaches the logs.
func healthReason(err error) string {
	switch {
	case errors.Is(err, db.ErrUnreachable):
		return "database_unreachable"
	case errors.Is(err, db.ErrMigrationsPending):
		return "migrations_pending"
	default:
		return "unknown"
	}
}
