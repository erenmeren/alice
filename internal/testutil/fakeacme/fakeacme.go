// Package fakeacme is an in-process fake of an ACME certificate authority (RFC 8555) for Alice's
// tests: directory, nonces, accounts (external account binding, terms of service, key rollover,
// deactivation), orders, authorizations, revocation (RFC 8555 section 7.6) with real HTTP-01 and DNS-01 validation, finalize with CSR
// checks, certificate download with alternates, and ACME Renewal Information (RFC 9773). It speaks
// the wire format golang.org/x/crypto/acme expects, over TLS with a CA of its own, and issues
// leaves from an issuing CA of its own (root, intermediate and, for alternates, further
// intermediates). The e2e service cmd/alice-fakeacme wraps the same handler.
//
// It is test-support code: production code never imports it (archtest keeps it out of every release
// binary). It holds no global state.
//
// # Validation is real
//
// DNS-01 looks the TXT value up in the fake's own DNS table, which is fed by the control API
// (Server.DNSSet, admin POST /dns) and by the DNS hook endpoint below. HTTP-01 fetches
// http://<name>/.well-known/acme-challenge/<token> and compares the body; a name can be mapped to a
// host:port (Server.SetHTTPTarget, admin POST /http-target) so tests point it at a stub or at the
// nginx of a container. Validation is synchronous: the challenge POST answers with the final status
// (unless the order is configured to stay pending).
//
// # The DNS hook contract (what Alice's DNS-01 webhook solver calls)
//
//	POST <base>/hook
//	Authorization: Bearer <secret>
//	X-Alice-Signature: <lowercase hex of HMAC-SHA256(secret, raw request body)>
//	Content-Type: application/json
//
//	{"action":"present"|"cleanup","fqdn":"_acme-challenge.example.test","value":"<TXT value>","ttl":60}
//
// The secret is the HookSecret of Credentials (one value for the bearer token and the HMAC key; the
// signature may carry a "sha256=" prefix). Answers: 200 {"ok":true}; 400 for an unknown action, an
// empty fqdn or a missing value; 401 for a missing or wrong bearer token or signature; 405 for a
// method other than POST; 413 for a body over 4 KiB. present adds the TXT value to the fqdn
// (several values may coexist, as for a wildcard and its base name); cleanup removes that value
// (all values of the fqdn when value is empty). The trailing dot of an fqdn and its case are ignored.
//
// # Fidelity
//
// Every answer follows RFC 8555 and RFC 9773. Where those are silent the behaviour is a GUESS and
// is marked so. The fake never logs or returns request bodies; its request log has method, path,
// status and time only.
package fakeacme

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"alice/internal/platform/clock"
)

// Challenge types the fake can offer.
const (
	HTTP01 = "http-01"
	DNS01  = "dns-01"
)

// DefaultBaseURL is the base URL of the e2e service (compose network alias).
const DefaultBaseURL = "https://acme.test.alice"

// Options configures the fake. The zero value is a working configuration.
type Options struct {
	// Now is the time source for issued certificates, order and authorization expiry and ARI.
	// Default time.Now. The fake's own TLS certificate always uses the real clock.
	Now func() time.Time
	// BaseURL is the public base URL ("https://acme.test.alice"). Start sets it to the listener's
	// address when it is empty; a service that serves Handler itself must give it.
	BaseURL string
	// Hosts are further names and IP addresses the TLS certificate holds (localhost, 127.0.0.1 and
	// the host of BaseURL are always included).
	Hosts []string
	// Challenges are the challenge types offered for a non-wildcard name (default both; a wildcard
	// is always dns-01 only).
	Challenges []string
	// RequireEAB sets meta.externalAccountRequired and refuses registration without a binding.
	RequireEAB bool
	// EABKID and EABKey are the external account binding credentials (defaults: generated).
	EABKID string
	EABKey []byte
	// HookSecret is the DNS hook's bearer token and HMAC key (default: generated).
	HookSecret string
	// LeafLifetime is the validity of issued leaves (default 90 days).
	LeafLifetime time.Duration
	// Alternates is the number of alternate chains offered besides the default one.
	Alternates int
	// NoTerms leaves termsOfService out of the directory (registration then needs no agreement).
	NoTerms bool
	// NoARI leaves renewalInfo out of the directory; NoKeyChange leaves keyChange out.
	NoARI       bool
	NoKeyChange bool
}

// Server is the fake. Create it with New; serve Handler or call Start.
type Server struct {
	opts Options
	now  func() time.Time
	pki  *pki

	mu   sync.Mutex
	base string
	st   *state
	cfg  config

	skew atomic.Int64 // nanoseconds the fake's clock runs from Options.Now

	httpClient *http.Client
	ts         *http.Server
	ln         net.Listener
}

// New builds the fake: its CAs and TLS certificate are generated here.
func New(opts Options) (*Server, error) {
	if opts.Now == nil {
		opts.Now = clock.Real{}.Now
	}
	if len(opts.Challenges) == 0 {
		opts.Challenges = []string{HTTP01, DNS01}
	}
	if opts.EABKID == "" {
		opts.EABKID = "kid-" + randHex(8)
	}
	if len(opts.EABKey) == 0 {
		opts.EABKey = randBytes(32)
	}
	if opts.HookSecret == "" {
		opts.HookSecret = randHex(24)
	}
	if opts.LeafLifetime <= 0 {
		opts.LeafLifetime = 90 * 24 * time.Hour
	}
	s := &Server{opts: opts, base: strings.TrimRight(opts.BaseURL, "/")}
	s.now = func() time.Time {
		return opts.Now().Add(time.Duration(s.skew.Load()))
	}
	p, err := newPKI(s.now(), opts.Alternates, tlsNames(opts))
	if err != nil {
		return nil, err
	}
	s.pki = p
	s.httpClient = s.newHTTPClient()
	s.resetLocked()
	return s, nil
}

func tlsNames(o Options) []string {
	names := []string{"localhost", "127.0.0.1", "::1", "acme.test.alice"}
	if h := hostOf(o.BaseURL); h != "" {
		names = append(names, h)
	}
	return append(names, o.Hosts...)
}

func hostOf(u string) string {
	u = strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
	if i := strings.IndexAny(u, "/"); i >= 0 {
		u = u[:i]
	}
	if h, _, err := net.SplitHostPort(u); err == nil {
		return h
	}
	return u
}

// BaseURL is the public base URL ("" before Start when none was given).
func (s *Server) BaseURL() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.base
}

// DirectoryURL is the ACME directory URL.
func (s *Server) DirectoryURL() string { return s.BaseURL() + "/directory" }

// CAPEM is the PEM of the CA that signs the fake's TLS certificate (what Alice must trust).
func (s *Server) CAPEM() []byte { return s.pki.tlsCAPEM() }

// IssuerRootPEM is the PEM of the root of the chain the fake issues leaves under.
func (s *Server) IssuerRootPEM() []byte { return s.pki.rootPEM() }

// TLSConfig is the server TLS configuration.
func (s *Server) TLSConfig() *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{s.pki.tlsCert}, MinVersion: tls.VersionTLS12}
}

// HTTPClient is a client that trusts only the fake's TLS CA.
func (s *Server) HTTPClient() *http.Client {
	return &http.Client{Transport: &http.Transport{Proxy: nil, TLSClientConfig: s.pki.clientTLS()}, Timeout: 30 * time.Second}
}

// Start serves the fake over TLS on 127.0.0.1 on a free port and sets the base URL when none was
// given. Close stops it.
func (s *Server) Start() error {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("fakeacme: listen: %w", err)
	}
	s.mu.Lock()
	if s.base == "" {
		s.base = "https://" + ln.Addr().String()
	}
	s.ln = ln
	s.ts = &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second}
	srv := s.ts
	s.mu.Unlock()
	go func() { _ = srv.Serve(tls.NewListener(ln, s.TLSConfig())) }()
	return nil
}

// Close stops a server started with Start.
func (s *Server) Close() {
	s.mu.Lock()
	srv := s.ts
	s.ts = nil
	s.mu.Unlock()
	if srv != nil {
		_ = srv.Close()
	}
	s.httpClient.CloseIdleConnections()
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("fakeacme: no randomness: " + err.Error())
	}
	return b
}

func randHex(n int) string { return hex.EncodeToString(randBytes(n)) }

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// asciiLower lowercases a DNS name (ASCII only, so the Turkish dotted/dotless i never matters).
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}
