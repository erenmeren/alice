// Package fakekv is an in-process fake of what Alice's Azure SDK clients talk to: the Key Vault data
// plane of one vault, the Microsoft Entra ID token endpoint, and the managed-identity (IMDS) endpoint.
//
// It is test-support code: production code never imports it (archtest keeps it out of every release
// binary). It is an http.Handler plus a small constructor and holds no global state, so the e2e
// service (cmd/alice-fakeazure) wraps the same Handler.
//
// Fidelity rule: every answer follows the public REST reference of Key Vault api-version 2025-07-01 and
// the Microsoft identity platform; the reference answer shapes are committed in
// test/testdata/kv-recordings (placeholders only) and shapes_test.go compares every answer with them.
// Where the reference is silent, the behaviour is a GUESS and is marked "GUESS" in a comment: the
// security review lists those as unverified against Azure.
package fakekv

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"alice/internal/platform/clock"
	"alice/internal/testutil/pki"
)

const (
	// APIVersion is the only Key Vault api-version the fake serves (R40 row 2).
	APIVersion = "2025-07-01"
	loginHost  = "login.microsoftonline.com"
	imdsAddr   = "169.254.169.254:80"
	// vaultResource is the audience of every Key Vault access token.
	vaultResource = "https://vault.azure.net"
)

// Options configures the fake. The zero value is a working configuration.
type Options struct {
	// Now is the time source for token lifetimes and the created/updated times of vault objects.
	// Default clock.Real{}.Now. Tests pass a clock.Fake's Now. The TLS certificates of the fake
	// always use the real clock, because the TLS client under test does.
	Now        func() time.Time
	TenantID   string            // default a generated GUID
	ClientID   string            // the registered application; default a generated GUID
	Secret     string            // its client secret; default NewClientSecret()
	ClientCert *x509.Certificate // a registered certificate credential (RSA; PS256 assertions are verified with it)
	VaultName  string            // default "alice-test"
	// ManagedIdentity makes the IMDS endpoint answer for the machine's identity.
	ManagedIdentity bool
	MIClientID      string // a user-assigned identity's client ID ("" = system-assigned)
	// Model is "rbac" (default) or "access_policy": it picks the inner code of a 403.
	Model string
	// ExtraHosts are further host names the fake's TLS certificate names and DialAddr maps to it
	// (a wrong-host nextLink or challenge that actually reaches the fake, so a test can prove nothing
	// was sent there). Requests for them are logged and answered 404 with no body.
	ExtraHosts []string
	// VersionsOldestFirst lists certificate versions oldest first (default newest first: the order of
	// the REST listing is unspecified, GUESS; a test can flip it to prove the product does not depend on it).
	VersionsOldestFirst bool
	// TokenLifetime is the lifetime of issued tokens (default 1 hour).
	TokenLifetime time.Duration
}

// Request is one logged request: method, host, path and the sorted query KEYS. Never bodies, headers or
// query values (a $skiptoken, a client_id, a token never enter the log).
type Request struct {
	Method, Host, Path string
	Query              []string
	// Status is the status the fake answered (0 while the request is in flight or when the
	// connection was dropped).
	Status int
	// HadAuth reports that the request carried an Authorization header (never its value): the proof
	// that a bearer token did or did not travel to a host.
	HadAuth bool
}

// Server is the fake. Create it with NewServer or Start.
type Server struct {
	o       Options
	ca      *pki.CA
	srv     *httptest.Server // TLS: login host and vault host
	imds    *httptest.Server // plain HTTP on its own port: 169.254.169.254:80
	tlsConf *tls.Config

	mu sync.Mutex
	// vault state
	certs   map[string]*certEntry
	keys    map[string]*keyEntry
	secrets map[string]*secretEntry
	keyPool map[string]any // generated public-key pairs shared by AddKey, per type
	// identity state
	tokens     map[string]issuedToken
	lastToken  string
	oid, tid   string // claims of the tokens it issues
	extraCerts []*x509.Certificate
	// controls
	revoked    map[string]bool
	firewall   string
	challenge  string // "" = the standard challenge
	latency    time.Duration
	faults     []*scriptedFault
	holds      []*hold
	heldNow    int
	expiredSec bool
	log        []Request
	tokenLife  time.Duration
	testToken  string
	vaultHostN string
}

// NewClientSecret returns "fake-" + 40 random hex characters.
func NewClientSecret() string {
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	return "fake-" + hex.EncodeToString(b)
}

// NewServer starts the fake on 127.0.0.1 (TLS for the login and vault hosts, plain HTTP for IMDS).
func NewServer(o Options) (*Server, error) {
	if o.Now == nil {
		o.Now = clock.Real{}.Now
	}
	if o.TenantID == "" {
		o.TenantID = uuid.NewString()
	}
	if o.ClientID == "" {
		o.ClientID = uuid.NewString()
	}
	if o.Secret == "" {
		o.Secret = NewClientSecret()
	}
	if o.VaultName == "" {
		o.VaultName = "alice-test"
	}
	if o.Model == "" {
		o.Model = "rbac"
	}
	if o.TokenLifetime <= 0 {
		o.TokenLifetime = time.Hour
	}
	real := clock.Real{}.Now()
	s := &Server{
		o: o, ca: pki.NewCA("Alice fake Azure", pki.ECDSA256, real),
		certs: map[string]*certEntry{}, keys: map[string]*keyEntry{}, secrets: map[string]*secretEntry{},
		keyPool: map[string]any{}, tokens: map[string]issuedToken{}, revoked: map[string]bool{},
		oid: uuid.NewString(), tid: o.TenantID, tokenLife: o.TokenLifetime,
		vaultHostN: o.VaultName + ".vault.azure.net",
	}
	if o.ClientCert != nil {
		s.extraCerts = append(s.extraCerts, o.ClientCert)
	}
	sans := append([]string{loginHost, s.vaultHostN, "127.0.0.1"}, o.ExtraHosts...)
	leaf := s.ca.Issue(pki.Opts{CommonName: "fake azure", SANs: sans}, real)
	s.tlsConf = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.Cert.Raw, s.ca.Intermediate.Raw}, PrivateKey: leaf.Key}},
		MinVersion:   tls.VersionTLS12,
	}
	s.srv = httptest.NewUnstartedServer(s.Handler())
	s.srv.TLS = s.tlsConf.Clone()
	s.srv.Config.ErrorLog = log.New(io.Discard, "", 0) // dropped connections are the fake's business
	s.srv.StartTLS()
	s.imds = httptest.NewServer(s.IMDSHandler())
	return s, nil
}

// Start is NewServer with cleanup; it fails the test on error.
func Start(t testing.TB, o Options) *Server {
	t.Helper()
	s, err := NewServer(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

// Close stops the listeners. A held request is released first.
func (s *Server) Close() {
	s.mu.Lock()
	for _, h := range s.holds {
		h.releaseLocked()
	}
	s.mu.Unlock()
	s.srv.CloseClientConnections()
	s.srv.Close()
	s.imds.CloseClientConnections()
	s.imds.Close()
}

// Handler serves the Entra ID and Key Vault routes, told apart by the Host header (for
// cmd/alice-fakeazure, which listens itself).
func (s *Server) Handler() http.Handler { return http.HandlerFunc(s.serve) }

// IMDSHandler serves the managed-identity endpoint (any host).
func (s *Server) IMDSHandler() http.Handler { return http.HandlerFunc(s.serveIMDS) }

// TLSConfig is the fake's server TLS configuration: its certificate names the login host, the vault
// host, 127.0.0.1 and ExtraHosts.
func (s *Server) TLSConfig() *tls.Config { return s.tlsConf.Clone() }

// CAPool returns a pool holding only the fake's root.
func (s *Server) CAPool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(s.ca.Root)
	return p
}

// CAPEM returns the fake's root certificate as PEM.
func (s *Server) CAPEM() []byte { return s.ca.RootPEM }

// DialAddr maps the fake's host names (login host, vault host, ExtraHosts on :443; IMDS on :80) to its
// listeners and returns every other address unchanged.
func (s *Server) DialAddr(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	host = foldASCII(host)
	if port == "80" && host == "169.254.169.254" {
		return s.imds.Listener.Addr().String()
	}
	if port != "443" {
		return addr
	}
	if host == loginHost || host == s.vaultHostN {
		return s.srv.Listener.Addr().String()
	}
	for _, h := range s.o.ExtraHosts {
		if foldASCII(h) == host {
			return s.srv.Listener.Addr().String()
		}
	}
	return addr
}

// VaultURL returns the vault's URL ("https://<name>.vault.azure.net").
func (s *Server) VaultURL() string { return "https://" + s.vaultHostN }

// TenantID returns the tenant.
func (s *Server) TenantID() string { return s.o.TenantID }

// ClientID returns the registered application's client ID.
func (s *Server) ClientID() string { return s.o.ClientID }

// Secret returns the registered application's client secret.
func (s *Server) Secret() string { return s.o.Secret }

// ObjectID returns the oid claim of the tokens it issues.
func (s *Server) ObjectID() string { s.mu.Lock(); defer s.mu.Unlock(); return s.oid }

// LastAccessToken returns the last token it issued ("" before any) - a leak-test needle.
func (s *Server) LastAccessToken() string { s.mu.Lock(); defer s.mu.Unlock(); return s.lastToken }

// Requests returns a copy of the request log.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Request, len(s.log))
	copy(out, s.log)
	for i := range out {
		out[i].Query = append([]string(nil), out[i].Query...)
	}
	return out
}

// ClearRequests empties the request log.
func (s *Server) ClearRequests() { s.mu.Lock(); s.log = nil; s.mu.Unlock() }

// record logs a request and returns its index.
func (s *Server) record(r *http.Request) int {
	keys := make([]string, 0, len(r.URL.Query()))
	for k := range r.URL.Query() {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.log = append(s.log, Request{Method: r.Method, Host: r.Host, Path: r.URL.Path, Query: keys, HadAuth: r.Header.Get("Authorization") != ""})
	return len(s.log) - 1
}

func (s *Server) setStatus(i, status int) {
	s.mu.Lock()
	if i < len(s.log) {
		s.log[i].Status = status
	}
	s.mu.Unlock()
}

// serve routes by host.
func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	i := s.record(r)
	sw := &statusWriter{ResponseWriter: w}
	defer func() { s.setStatus(i, sw.status) }()
	switch hostOnly(r.Host) {
	case loginHost:
		s.serveWithFaults(sw, r, s.serveLogin)
	case s.vaultHostN:
		s.serveVault(sw, r)
	default:
		// The fake never answers a name it does not own.
		sw.WriteHeader(http.StatusNotFound)
	}
}

// statusWriter records the status written. It unwraps for http.ResponseController (hijacking).
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func hostOnly(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return foldASCII(h)
}

// foldASCII lower-cases ASCII letters only (host names).
func foldASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

// TestClient returns an HTTP client for tests: it dials through DialAddr, trusts only the fake's CA,
// uses no proxy and never follows a redirect. GetJSON and Get send a valid bearer token.
func (s *Server) TestClient() *TestClient {
	d := &net.Dialer{Timeout: 5 * time.Second}
	return &TestClient{s: s, c: &http.Client{
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return d.DialContext(ctx, network, s.DialAddr(addr))
			},
			TLSClientConfig: &tls.Config{RootCAs: s.CAPool(), MinVersion: tls.VersionTLS12},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}
