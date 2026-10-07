// Package fakeidp is an OpenID Connect identity provider for tests (spec §25.5: "generates keys, discovery document
// and signed ID tokens, supports fault injection"): discovery, JWKS, the authorization endpoint (it signs in the
// identity set by NextLogin without a form) and the token endpoint with PKCE S256, single-use codes and client
// authentication. It is the Go suites' fake and the engine of cmd/alice-fakeidp (the e2e container).
package fakeidp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"alice/internal/platform/clock"
)

// Options configure the provider.
type Options struct {
	Plain bool
	Host  string
	Now   func() time.Time
}

// Login is the identity the next authorization signs in.
type Login struct {
	Subject, Username, Name, Email string
	Groups                         []string
	Extra                          map[string]any
}

// Fault shapes the next tokens and answers (C6).
type Fault struct {
	Alg            string
	OtherKey       bool
	UnknownKid     bool
	Issuer         string
	Audience       []string
	Azp            string
	ExpIn          time.Duration
	IatOffset      time.Duration
	NbfOffset      time.Duration
	Nonce          *string
	OmitNonce      bool
	Overage        bool
	AuthTimeAgo    time.Duration
	OmitAuthTime   bool
	AuthorizeError string
	ReplayCode     bool
	Kid            string // overrides the kid in the header of an RS256 token
	HMACKeyPEM     bool   // with Alg "HS256": key the MAC with the PEM text of the public key instead of its DER
	HasGroups      bool   // the Entra "hasgroups" overage marker, without groups
}

// Stats counts requests per endpoint.
type Stats struct{ Discovery, JWKS, Authorize, Token int }

type signingKey struct {
	kid string
	key *rsa.PrivateKey
}

type grant struct {
	login     Login
	nonce     string
	challenge string
	redirect  string
	authTime  time.Time
	used      bool
}

// Server is the provider.
type Server struct {
	opts     Options
	clientID string
	secret   string
	caPEM    []byte
	tlsCfg   *tls.Config
	client   *http.Client

	mu        sync.Mutex
	ln        net.Listener
	issuer    string
	keys      []signingKey
	nextKid   int
	jwksAge   time.Duration
	redirects map[string]bool
	prefixes  []string
	next      Login
	fault     Fault
	grants    map[string]*grant
	down      bool
	stats     Stats
	lastForm  url.Values
	lastQuery url.Values
}

func random(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// New makes the keys, the client secret and (unless Plain) a CA and the TLS certificate for Host.
func New(o Options) (*Server, error) {
	if o.Host == "" {
		o.Host = "127.0.0.1"
	}
	if o.Now == nil {
		o.Now = clock.Real{}.Now
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	s := &Server{opts: o, clientID: "alice", secret: random(32), keys: []signingKey{{kid: "k1", key: key}}, nextKid: 2,
		redirects: map[string]bool{}, grants: map[string]*grant{}, next: Login{Subject: "user-1", Username: "user1"}}
	s.client = &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if o.Plain {
		return s, nil
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := clock.Real{}.Now()
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Alice e2e fake IdP CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	ca, _ := x509.ParseCertificate(caDER)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: o.Host},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if ip := net.ParseIP(o.Host); ip != nil {
		leafTmpl.IPAddresses = []net.IP{ip}
	} else {
		leafTmpl.DNSNames = []string{o.Host}
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	s.caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	s.tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}}}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	s.client.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	return s, nil
}

// Start is New and Listen on a free loopback port; t.Cleanup closes it.
func Start(t testing.TB, o Options) *Server {
	t.Helper()
	s, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

// Listen serves on addr; the issuer is scheme://Host:port.
func (s *Server) Listen(addr string) error {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", addr)
	if err != nil {
		return err
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	scheme := "https"
	if s.opts.Plain {
		scheme = "http"
	} else {
		ln = tls.NewListener(ln, s.tlsCfg)
	}
	s.mu.Lock()
	s.ln, s.issuer = ln, scheme+"://"+net.JoinHostPort(s.opts.Host, port)
	s.mu.Unlock()
	srv := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	return nil
}

// Close stops listening.
func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln != nil {
		_ = s.ln.Close()
	}
}

func (s *Server) Issuer() string       { s.mu.Lock(); defer s.mu.Unlock(); return s.issuer }
func (s *Server) ClientID() string     { return s.clientID }
func (s *Server) ClientSecret() string { return s.secret }
func (s *Server) CAPEM() []byte        { return s.caPEM }
func (s *Server) Client() *http.Client { return s.client }

func (s *Server) RegisterRedirect(uri string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.redirects[uri] = true
}
func (s *Server) RegisterRedirectPrefix(prefix string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prefixes = append(s.prefixes, prefix)
}
func (s *Server) NextLogin(l Login) { s.mu.Lock(); defer s.mu.Unlock(); s.next = l }
func (s *Server) SetFault(f Fault)  { s.mu.Lock(); defer s.mu.Unlock(); s.fault = f }
func (s *Server) Down()             { s.mu.Lock(); defer s.mu.Unlock(); s.down = true }
func (s *Server) Up()               { s.mu.Lock(); defer s.mu.Unlock(); s.down = false }
func (s *Server) Stats() Stats      { s.mu.Lock(); defer s.mu.Unlock(); return s.stats }

// LastTokenForm is a copy of the last token request's form.
func (s *Server) LastTokenForm() url.Values {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := url.Values{}
	for k, v := range s.lastForm {
		out[k] = append([]string(nil), v...)
	}
	return out
}

// LastAuthorizeQuery is a copy of the last authorization request's query (scope, nonce, prompt, max_age, acr_values…).
func (s *Server) LastAuthorizeQuery() url.Values {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := url.Values{}
	for k, v := range s.lastQuery {
		out[k] = append([]string(nil), v...)
	}
	return out
}

// RotateKey adds a signing key with a new kid; the old ones stay in the JWKS until DropOldKeys.
func (s *Server) RotateKey() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys = append(s.keys, signingKey{kid: "k" + strconv.Itoa(s.nextKid), key: key})
	s.nextKid++
}

// DropOldKeys keeps only the newest signing key.
func (s *Server) DropOldKeys() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.keys) > 1 {
		s.keys = s.keys[len(s.keys)-1:]
	}
}

// SetJWKSMaxAge sets the max-age of the Cache-Control header of the JWKS answer (default 300 s); a negative value
// omits the header (S-2: a verifier's key-set cache expiry is tested against it).
func (s *Server) SetJWKSMaxAge(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jwksAge = d
}

// WithdrawKey removes the key with kid from the JWKS and from signing (S-2: a withdrawn key stops verifying once the
// verifier's cache expires). It reports whether the kid existed.
func (s *Server) WithdrawKey(kid string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, k := range s.keys {
		if k.kid == kid {
			s.keys = append(s.keys[:i:i], s.keys[i+1:]...)
			return true
		}
	}
	return false
}

// Kids lists the kids in the JWKS, oldest first; the last one signs.
func (s *Server) Kids() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.keys))
	for _, k := range s.keys {
		out = append(out, k.kid)
	}
	return out
}

// Authorize performs the browser's visit of authorizeURL and returns where the provider redirects it.
func (s *Server) Authorize(authorizeURL string) (string, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, authorizeURL, nil)
	if err != nil {
		return "", err
	}
	res, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusFound {
		return "", fmt.Errorf("fakeidp: authorize answered %d", res.StatusCode)
	}
	return res.Header.Get("Location"), nil
}

func (s *Server) redirectAllowed(uri string) bool {
	if s.redirects[uri] {
		return true
	}
	for _, p := range s.prefixes {
		if strings.HasPrefix(uri, p) {
			return true
		}
	}
	return false
}

// Handler serves the provider's endpoints.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", s.discovery)
	mux.HandleFunc("GET /jwks", s.jwks)
	mux.HandleFunc("GET /authorize", s.authorize)
	mux.HandleFunc("POST /token", s.token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		down := s.down
		s.mu.Unlock()
		if down {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) discovery(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	s.stats.Discovery++
	iss := s.issuer
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"issuer": iss, "authorization_endpoint": iss + "/authorize",
		"token_endpoint": iss + "/token", "jwks_uri": iss + "/jwks", "response_types_supported": []string{"code"},
		"subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"RS256"},
		"code_challenge_methods_supported": []string{"S256"}, "scopes_supported": []string{"openid", "profile", "email"}})
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (s *Server) jwks(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	s.stats.JWKS++
	age := s.jwksAge
	keys := make([]map[string]string, 0, len(s.keys))
	for _, k := range s.keys {
		keys = append(keys, map[string]string{"kty": "RSA", "kid": k.kid, "use": "sig", "alg": "RS256",
			"n": b64(k.key.N.Bytes()), "e": b64(big.NewInt(int64(k.key.E)).Bytes())})
	}
	s.mu.Unlock()
	if age >= 0 {
		if age == 0 {
			age = 300 * time.Second
		}
		w.Header().Set("Cache-Control", "max-age="+strconv.Itoa(int(age/time.Second)))
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": keys})
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.Authorize++
	s.lastQuery = q
	redirect := q.Get("redirect_uri")
	if q.Get("client_id") != s.clientID || !s.redirectAllowed(redirect) {
		http.Error(w, "unknown client or redirect_uri", http.StatusBadRequest)
		return
	}
	target, err := url.Parse(redirect)
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	vals := target.Query()
	if q.Has("state") {
		vals.Set("state", q.Get("state"))
	}
	switch {
	case s.fault.AuthorizeError != "":
		vals.Set("error", s.fault.AuthorizeError)
	case q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" ||
		!strings.Contains(" "+q.Get("scope")+" ", " openid "):
		vals.Set("error", "invalid_request")
	default:
		code := random(24)
		s.grants[code] = &grant{login: s.next, nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), redirect: redirect,
			authTime: s.opts.Now()}
		vals.Set("code", code)
	}
	target.RawQuery = vals.Encode()
	// The target is a registered redirect URI (checked above), so this is no open redirect.
	w.Header().Set("Location", target.String())
	w.WriteHeader(http.StatusFound)
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	s.mu.Lock()
	needSpare := s.fault.OtherKey
	s.mu.Unlock()
	var spare *rsa.PrivateKey // generated outside the lock: a 2048-bit key takes a while
	if needSpare {
		var err error
		if spare, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
			return
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.Token++
	s.lastForm = r.PostForm
	id, secret, ok := r.BasicAuth()
	if ok {
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
	} else {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	if id != s.clientID || secret != s.secret {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	g := s.grants[r.PostForm.Get("code")]
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if g == nil || (g.used && !s.fault.ReplayCode) || r.PostForm.Get("redirect_uri") != g.redirect || b64(sum[:]) != g.challenge ||
		r.PostForm.Get("grant_type") != "authorization_code" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}
	g.used = true
	tok, err := s.idToken(g, spare)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"access_token": random(24), "token_type": "Bearer", "expires_in": 300, "id_token": tok})
}

var errNoKey = errors.New("fakeidp: no signing key")
