// Package web is the sales web page of the vendor console: passkey sign-in and the customer,
// request and license pages. It holds no signing key and connects to PostgreSQL as the
// vendor_web login; it acts for the signed-in person by setting vendor.actor inside each
// transaction (inActorTx), which the database honors only for vendor_web members.
package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"alice/internal/platform/clock"
	"alice/internal/vconsole/webuser"
)

// Config configures a Server.
type Config struct {
	Pool       *pgxpool.Pool
	RPID       string // e.g. "licenses.example.com"
	Origin     string // e.g. "https://licenses.example.com"; http only for localhost
	Clock      clock.Clock
	CookieName string       // set by New: "__Host-vsession" for https origins, "vsession" otherwise
	Logger     *slog.Logger // optional; slog.Default() when nil

	// TrustedProxies are the ranges whose X-Forwarded-For is believed, for the rate limiter only.
	// Empty: the header is ignored.
	TrustedProxies []netip.Prefix

	// Rate limit of the begin endpoints per client address; tests shorten them. Zero means the
	// defaults (10 per minute).
	limitN      int
	limitWindow time.Duration
}

// csp is sent on every response: only our own scripts, styles and images; no inline code, no
// framing, forms post only to us.
const csp = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"

const (
	defaultLimitN      = 10
	defaultLimitWindow = time.Minute
	maxCeremonies      = 10000
	maxJSONBody        = 64 << 10
)

// Server is the web service.
type Server struct {
	cfg            Config
	secure         bool   // the origin is https: cookies get Secure
	ceremonyCookie string // "__Host-vceremony" for https origins, "vceremony" otherwise
	log            *slog.Logger
	wa             *webauthn.WebAuthn
	ceremonies     *ceremonies
	limiter        *limiter
	tmpl           map[string]*template.Template
	handler        http.Handler
}

// New validates cfg and builds the server. The pool may be nil for routes that do not reach the
// database (unit tests).
func New(cfg Config) (*Server, error) {
	secure, err := checkOrigin(cfg.RPID, cfg.Origin)
	if err != nil {
		return nil, err
	}
	for _, p := range cfg.TrustedProxies {
		if !p.IsValid() || p.Bits() == 0 {
			return nil, errors.New("web: a trusted proxy range must not cover every address")
		}
	}
	if cfg.Clock == nil {
		cfg.Clock = clock.Real{}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.limitN <= 0 {
		cfg.limitN = defaultLimitN
	}
	if cfg.limitWindow <= 0 {
		cfg.limitWindow = defaultLimitWindow
	}
	// The __Host- prefix makes the browser refuse the cookie unless it is Secure, host-only and
	// Path=/, so a sibling subdomain cannot plant or overwrite it. It needs https.
	cfg.CookieName = "vsession"
	if secure {
		cfg.CookieName = "__Host-vsession"
	}
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          cfg.RPID,
		RPDisplayName: "Alice licenses",
		RPOrigins:     []string{cfg.Origin},
		// Passkeys: the credential is discoverable (sign-in without a user name) and the
		// authenticator must verify the person (PIN or biometrics), so a stolen key alone is not enough.
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: protocol.ResidentKeyRequired(),
			UserVerification:   protocol.VerificationRequired,
		},
		AttestationPreference: protocol.PreferNoAttestation,
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Timeout: ceremonyTTL, TimeoutUVD: ceremonyTTL},
			Registration: webauthn.TimeoutConfig{Timeout: ceremonyTTL, TimeoutUVD: ceremonyTTL},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("web: webauthn config: %w", err)
	}
	pages, err := parsePages()
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg: cfg, secure: secure, ceremonyCookie: ceremonyCookieName(secure), log: cfg.Logger, wa: wa,
		ceremonies: newCeremonies(cfg.Clock, maxCeremonies),
		limiter:    newLimiter(cfg.Clock, cfg.limitN, cfg.limitWindow),
		tmpl:       pages,
	}
	if s.handler, err = s.routes(); err != nil {
		return nil, err
	}
	return s, nil
}

// ceremonyCookieName is the name of the passkey ceremony cookie. Like the session cookie it uses
// the __Host- prefix when the origin is https.
func ceremonyCookieName(secure bool) string {
	if secure {
		return "__Host-vceremony"
	}
	return "vceremony"
}

// checkOrigin requires an https origin (http only for localhost, where browsers allow WebAuthn)
// that is a bare scheme://host[:port] and whose host is the RP ID. It reports whether it is https.
func checkOrigin(rpid, origin string) (bool, error) {
	u, err := url.Parse(origin)
	if err != nil || origin == "" {
		return false, fmt.Errorf("web: origin %q does not parse", origin)
	}
	if u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return false, fmt.Errorf("web: origin %q must be scheme://host[:port] only", origin)
	}
	host := u.Hostname()
	if host == "" || rpid != host {
		return false, fmt.Errorf("web: the RP ID %q must equal the origin's host %q", rpid, host)
	}
	// WebAuthn RP IDs are domains; an IP address origin cannot use passkeys.
	if _, err := netip.ParseAddr(host); err == nil {
		return false, fmt.Errorf("web: origin %q: the host must be a domain name, not an address", origin)
	}
	switch u.Scheme {
	case "https":
		return true, nil
	case "http":
		if host == "localhost" {
			return false, nil
		}
		return false, fmt.Errorf("web: origin %q: plain http is allowed only for localhost", origin)
	default:
		return false, fmt.Errorf("web: origin %q: scheme must be https", origin)
	}
}

// Handler returns the HTTP handler of the service.
func (s *Server) Handler() http.Handler { return s.handler }

func (s *Server) routes() (http.Handler, error) {
	static, err := staticFS()
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.StripPrefix("/static/", staticOnly(static, http.FileServerFS(static))))
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("GET /enroll", s.enrollPage)
	mux.HandleFunc("POST /webauthn/register/begin", s.limited(s.registerBegin))
	mux.HandleFunc("POST /webauthn/register/finish", s.registerFinish)
	mux.HandleFunc("POST /webauthn/login/begin", s.limited(s.loginBegin))
	mux.HandleFunc("POST /webauthn/login/finish", s.loginFinish)
	mux.HandleFunc("POST /logout", s.authed(s.logout))
	// Everything else needs a session first, so an unknown path tells a signed-out visitor nothing:
	// signed out it redirects to /login, signed in it is 404. The pages (including "GET /{$}") are
	// more specific and win.
	mux.HandleFunc("/", s.authed(s.fallback))
	s.pages(mux)

	cop := http.NewCrossOriginProtection()
	// Behind a reverse proxy the Host header may differ from the public origin; a request whose
	// Origin is exactly ours is same-origin whatever Host says.
	if err := cop.AddTrustedOrigin(s.cfg.Origin); err != nil {
		return nil, fmt.Errorf("web: trusted origin: %w", err)
	}
	cop.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "cross-origin request refused", http.StatusForbidden)
	}))
	return headers(cop.Handler(mux)), nil
}

// headers sets the security headers on every response, including static files and errors.
func headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

// staticOnly serves existing regular files only: a directory is never listed, and a missing file
// gets our own 404 (the file server's error path drops Cache-Control, which every response keeps).
func staticOnly(root fs.FS, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Path
		st, err := fs.Stat(root, name)
		if name == "" || !fs.ValidPath(name) || err != nil || !st.Mode().IsRegular() {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// pageData is what every page template receives: the signed-in user and the page's own data.
type pageData struct {
	User webuser.User
	Data any
}

// render executes a page into a buffer first so a template error never leaves half a page.
func (s *Server) render(w http.ResponseWriter, status int, page string, data pageData) {
	t, ok := s.tmpl[page]
	if !ok {
		s.log.Error("web: unknown page", "page", page)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	var b strings.Builder
	if err := t.Execute(&b, data); err != nil {
		s.log.Error("web: render", "page", page, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(b.String()))
}

func (s *Server) loginPage(w http.ResponseWriter, _ *http.Request) {
	s.render(w, http.StatusOK, "login", pageData{})
}

func (s *Server) enrollPage(w http.ResponseWriter, _ *http.Request) {
	s.render(w, http.StatusOK, "enroll", pageData{})
}

func (s *Server) fallback(w http.ResponseWriter, r *http.Request, _ webuser.User) {
	http.NotFound(w, r)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// authed runs next with the signed-in user. Without a valid session a page request is sent to
// /login (303); a request to the JSON API gets 401. The database is reached only when a cookie is
// present.
func (s *Server) authed(next func(http.ResponseWriter, *http.Request, webuser.User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, err := s.sessionUser(r)
		if errors.Is(err, webuser.ErrNoSession) {
			if strings.HasPrefix(r.URL.Path, "/webauthn/") || strings.Contains(r.Header.Get("Accept"), "application/json") {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not signed in"})
				return
			}
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if err != nil {
			s.log.Error("web: session lookup", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		next(w, r, u)
	}
}

// sessionUser resolves the session cookie. It never logs the token.
func (s *Server) sessionUser(r *http.Request) (webuser.User, error) {
	c, err := r.Cookie(s.cfg.CookieName)
	if err != nil || c.Value == "" || len(c.Value) > 128 {
		return webuser.User{}, webuser.ErrNoSession
	}
	if s.cfg.Pool == nil {
		return webuser.User{}, errors.New("web: no database")
	}
	return webuser.Session(r.Context(), s.cfg.Pool, c.Value, s.cfg.Clock.Now())
}

func (s *Server) sessionCookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{ //nolint:gosec // G124: Secure is false only for the http://localhost origin, where browsers would drop it
		Name: s.cfg.CookieName, Value: value, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: s.secure, SameSite: http.SameSiteStrictMode,
	}
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request, _ webuser.User) {
	if c, err := r.Cookie(s.cfg.CookieName); err == nil {
		if err := webuser.EndSession(r.Context(), s.cfg.Pool, c.Value); err != nil {
			s.log.Error("web: end session", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}
	http.SetCookie(w, s.sessionCookie("", -1))
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// inActorTx runs fn in a transaction in which vendor.actor is the signed-in user's name, so
// defaults, row-level security and audit rows name "web:<name>". The setting is transaction-local
// (set_config's third argument), so it cannot leak to the next use of the pooled connection.
func (s *Server) inActorTx(ctx context.Context, u webuser.User, fn func(tx pgx.Tx) error) error {
	if s.cfg.Pool == nil {
		return errors.New("web: no database")
	}
	tx, err := s.cfg.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("web: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT set_config($1, $2, true)`, "vendor.actor", u.Name); err != nil {
		return fmt.Errorf("web: set actor: %w", err)
	}
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("web: commit: %w", err)
	}
	return nil
}

// limiter is a fixed-window request counter per client address. It keys on the connection's
// address, unless the peer is a configured trusted proxy (Config.TrustedProxies): then the
// client from X-Forwarded-For is used. Nothing else in the service reads that header.
type limiter struct {
	mu        sync.Mutex
	clk       clock.Clock
	n         int
	window    time.Duration
	m         map[netip.Addr]*bucket
	lastPrune time.Time
}

type bucket struct {
	start time.Time
	count int
}

func newLimiter(clk clock.Clock, n int, window time.Duration) *limiter {
	return &limiter{clk: clk, n: n, window: window, m: map[netip.Addr]*bucket{}}
}

func (l *limiter) allow(a netip.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clk.Now()
	if now.Sub(l.lastPrune) >= l.window {
		for k, b := range l.m {
			if now.Sub(b.start) >= l.window {
				delete(l.m, k)
			}
		}
		l.lastPrune = now
	}
	b, ok := l.m[a]
	if !ok || now.Sub(b.start) >= l.window {
		b = &bucket{start: now}
		l.m[a] = b
	}
	b.count++
	return b.count <= l.n
}

func (s *Server) limited(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.limiter.allow(s.limiterKey(r)) {
			w.Header().Set("Retry-After", fmt.Sprint(int(s.cfg.limitWindow.Seconds())))
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many attempts, try again in a minute"})
			return
		}
		next(w, r)
	}
}
