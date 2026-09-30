// Package api is Alice's HTTP layer. It holds no business logic and no SQL.
package api

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"

	"alice/internal/i18n"
	"alice/internal/platform/db"
	"alice/internal/version"
)

// HealthChecker reports whether dependencies (the database) are ready.
type HealthChecker interface {
	Check(ctx context.Context) error
}

// Deps are the handler's dependencies, wired in cmd/alice.
type Deps struct {
	Health  HealthChecker
	Catalog *i18n.Catalog
	Version version.Info
	UI      fs.FS
	Log     *slog.Logger
}

type server struct{ deps Deps }

// route is one documented operation. The route tables are the single source
// of truth for what the muxes serve; openapi.yaml must list exactly these.
type route struct {
	method  string
	pattern string
	handler http.HandlerFunc
}

func register(mux *http.ServeMux, routes []route) {
	for _, r := range routes {
		mux.HandleFunc(r.method+" "+r.pattern, r.handler)
	}
}

// probeRoutes are served on both the public and the internal health listener.
func (s *server) probeRoutes() []route {
	return []route{
		{http.MethodGet, "/livez", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		}},
		{http.MethodGet, "/healthz", func(w http.ResponseWriter, r *http.Request) {
			if err := s.deps.Health.Check(r.Context()); err != nil {
				s.deps.Log.Warn("health check failed", "request_id", RequestID(r.Context()), "reason", healthReason(err))
				s.writeError(w, r, ErrUnavailable)
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		}},
	}
}

// apiRoutes are the documented operations on the public listener.
// Undocumented catch-alls (the /api/ and /test/ JSON 404s and the SPA
// fallback) are registered separately in NewHandler and are not operations.
func (s *server) apiRoutes() []route {
	return append(s.probeRoutes(),
		route{http.MethodGet, "/api/v1/version", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, s.deps.Version)
		}},
		route{http.MethodGet, "/api/v1/i18n/locales", func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, map[string]any{"default": s.deps.Catalog.Default(), "locales": s.deps.Catalog.Locales()})
		}},
	)
}

// NewHandler returns the public HTTPS handler.
func NewHandler(d Deps) http.Handler {
	s := &server{deps: d}
	mux := http.NewServeMux()
	register(mux, s.apiRoutes())
	notFound := func(w http.ResponseWriter, r *http.Request) { s.writeError(w, r, ErrNotFound) }
	mux.HandleFunc("/api/", notFound)
	mux.HandleFunc("/test/", notFound) // reserved for test-only routes; never the SPA
	mux.Handle("/", s.spa())
	return s.requestID(securityHeaders(s.recoverer(mux)))
}

// NewHealthHandler returns the handler for the internal, container-local health listener.
func NewHealthHandler(d Deps) http.Handler {
	s := &server{deps: d}
	mux := http.NewServeMux()
	register(mux, s.probeRoutes())
	return s.requestID(securityHeaders(s.recoverer(mux)))
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
