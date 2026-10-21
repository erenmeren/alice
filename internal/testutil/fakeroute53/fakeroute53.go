// Package fakeroute53 is an in-process fake of what Alice's Route 53 DNS provider (internal/acme/solver/dnsapi/route53)
// talks to: the Route 53 API 2013-04-01 (ListHostedZonesByName, ListResourceRecordSets, ChangeResourceRecordSets and
// GetChange, TXT records only) and STS AssumeRole, both behind AWS Signature Version 4.
//
// It is test-support code: production code never imports it (archtest keeps it out of every release binary). It is
// an http.Handler routed by host name plus a small constructor, and holds no global state, so another binary can
// mount Handler behind its own listener with TLSConfig.
//
// The fake verifies every signature with its own implementation (sigv4.go here, written apart from the provider's):
// a request signed with the wrong secret, for the wrong service or region, with a stale X-Amz-Date (more than five
// minutes off) or with a session token that does not belong to its key is refused 403 the way AWS refuses it.
//
// Fidelity: the routes, parameters, XML shapes and error codes follow the public API reference of Route 53 2013-04-01
// and STS 2011-06-15. Where the reference is silent the behaviour is a GUESS, marked so in a comment.
package fakeroute53

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"alice/internal/platform/clock"
	"alice/internal/testutil/pki"
)

// Host names the fake answers.
const (
	Route53Host = "route53.amazonaws.com"
	STSHost     = "sts.amazonaws.com"
	// Region is the only region the fake accepts in a credential scope (Route 53 and the global STS endpoint).
	Region = "us-east-1"
	// MaxClockSkew is how far X-Amz-Date may be from the fake's clock.
	MaxClockSkew = 5 * time.Minute
)

// Operations, the names FailNext, FailAll and Counters use.
const (
	OpZones      = "zones"      // ListHostedZonesByName
	OpList       = "list"       // ListResourceRecordSets
	OpChange     = "change"     // ChangeResourceRecordSets
	OpGetChange  = "getchange"  // GetChange
	OpAssumeRole = "assumerole" // STS AssumeRole
)

// Zone is a hosted zone of the fake's account.
type Zone struct {
	Name    string // "example.com" (a trailing dot and upper case are accepted)
	Private bool
}

// Sink receives the TXT values the fake holds, unquoted (internal/testutil/fakeacme's Server is one: its DNS table
// then answers the CA's DNS-01 validation).
type Sink interface {
	DNSSet(fqdn, value string)
	DNSClear(fqdn, value string)
}

// Options configures the fake. The zero value is a working configuration with no zone.
type Options struct {
	// AccessKeyID and SecretAccessKey are the account's long-term key; both are generated when empty.
	AccessKeyID     string
	SecretAccessKey string
	// RoleARN is a role the long-term key may assume (with ExternalID, when set, required). With a role, Route 53
	// accepts the role's temporary credentials only: the long-term key is refused AccessDenied, so a test proves
	// the provider used the role.
	RoleARN    string
	ExternalID string
	Zones      []Zone
	// InsyncAfter is how many GetChange polls of a change answer PENDING before INSYNC.
	InsyncAfter int
	// Sink, when set, mirrors every TXT value added or removed.
	Sink Sink
	// Now is the clock of signatures and session expiry (default clock.Real{}.Now). The TLS certificate always uses
	// the real clock.
	Now func() time.Time
}

// Request is one logged request: method, host, path, the operation and the status answered. Never a query, a
// header, a signature, a key or a body.
type Request struct {
	Method, Host, Path, Op string
	Status                 int
}

// Credentials are temporary credentials the fake issued (leak-test needles).
type Credentials struct {
	AccessKeyID, SecretAccessKey, SessionToken string
	Expiration                                 time.Time
}

// Session is one AssumeRole the fake granted.
type Session struct {
	RoleSessionName string
	DurationSeconds int
	ExternalID      string
}

// Server is the fake. Create it with New or Start.
type Server struct {
	o       Options
	now     func() time.Time
	ca      *pki.CA
	tlsConf *tls.Config
	srv     *httptest.Server

	mu       sync.Mutex
	zones    []*zone
	changes  map[string]int // change ID -> PENDING polls left
	temps    map[string]Credentials
	sessions []Session
	faults   []*scripted
	log      []Request
	counters map[string]int
	lastSig  string
}

type zone struct {
	id, name string
	private  bool
	sets     map[string]*rrset // record name (lower case, no trailing dot) -> TXT set
}

type rrset struct {
	ttl    int
	values []string // Route 53's quoted form
}

// New starts the fake on 127.0.0.1 with TLS for both host names.
func New(o Options) (*Server, error) {
	if o.Now == nil {
		o.Now = clock.Real{}.Now
	}
	if o.AccessKeyID == "" {
		o.AccessKeyID = "FAKE" + randomUpper(16)
	}
	if o.SecretAccessKey == "" {
		o.SecretAccessKey = randomSecret(30)
	}
	s := &Server{o: o, now: o.Now, changes: map[string]int{}, temps: map[string]Credentials{}, counters: map[string]int{}}
	for _, z := range o.Zones {
		s.addZoneLocked(z)
	}
	real := clock.Real{}.Now()
	s.ca = pki.NewCA("Alice fake AWS", pki.ECDSA256, real)
	leaf := s.ca.Issue(pki.Opts{CommonName: "fake aws", SANs: []string{Route53Host, STSHost, "127.0.0.1"}}, real)
	s.tlsConf = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.Cert.Raw, s.ca.Intermediate.Raw}, PrivateKey: leaf.Key}},
		MinVersion:   tls.VersionTLS12,
	}
	s.srv = httptest.NewUnstartedServer(s.Handler())
	s.srv.TLS = s.tlsConf.Clone()
	s.srv.Config.ErrorLog = log.New(io.Discard, "", 0) // reset connections are the fake's business
	s.srv.StartTLS()
	return s, nil
}

// Start is New with cleanup; it fails the test on error.
func Start(t testing.TB, o Options) *Server {
	t.Helper()
	s, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

// Close stops the listener.
func (s *Server) Close() {
	s.srv.CloseClientConnections()
	s.srv.Close()
}

// Handler serves both hosts, told apart by the Host header.
func (s *Server) Handler() http.Handler { return http.HandlerFunc(s.serve) }

// TLSConfig is the fake's server TLS configuration (its certificate names both hosts and 127.0.0.1).
func (s *Server) TLSConfig() *tls.Config { return s.tlsConf.Clone() }

// CAPool returns a pool holding only the fake's root.
func (s *Server) CAPool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(s.ca.Root)
	return p
}

// CAPEM returns the fake's root certificate as PEM.
func (s *Server) CAPEM() []byte { return s.ca.RootPEM }

// MapAddr maps both host names on port 443 to the fake's listener and returns every other address unchanged.
func (s *Server) MapAddr(hostport string) string {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil || port != "443" {
		return hostport
	}
	switch foldASCII(host) {
	case Route53Host, STSHost:
		return s.srv.Listener.Addr().String()
	}
	return hostport
}

// AccessKeyID returns the long-term access key ID.
func (s *Server) AccessKeyID() string { return s.o.AccessKeyID }

// SecretAccessKey returns the long-term secret (a leak-test needle).
func (s *Server) SecretAccessKey() string { return s.o.SecretAccessKey }

// AddZone adds a hosted zone and returns its ID.
func (s *Server) AddZone(z Zone) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addZoneLocked(z).id
}

func (s *Server) addZoneLocked(z Zone) *zone {
	nz := &zone{id: "Z" + randomUpper(13), name: normName(z.Name), private: z.Private, sets: map[string]*rrset{}}
	s.zones = append(s.zones, nz)
	return nz
}

// ZoneID returns the ID of the first zone named name with that visibility ("" when there is none).
func (s *Server) ZoneID(name string, private bool) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := normName(name)
	for _, z := range s.zones {
		if z.name == n && z.private == private {
			return z.id
		}
	}
	return ""
}

// SetRecord replaces the TXT set at fqdn (unquoted values) in the longest public zone that holds it, as another tool
// would have written it; no values removes the set. It reports false when no public zone holds fqdn.
func (s *Server) SetRecord(fqdn string, ttl int, values ...string) bool {
	n := normName(fqdn)
	s.mu.Lock()
	z := s.longestLocked(n)
	if z == nil {
		s.mu.Unlock()
		return false
	}
	var old []string
	if cur := z.sets[n]; cur != nil {
		old = cur.values
	}
	var quoted []string
	for _, v := range values {
		quoted = append(quoted, quote(v))
	}
	if len(quoted) == 0 {
		delete(z.sets, n)
	} else {
		z.sets[n] = &rrset{ttl: ttl, values: quoted}
	}
	s.mu.Unlock()
	s.mirror(n, old, quoted)
	return true
}

func (s *Server) longestLocked(n string) *zone {
	var best *zone
	for _, z := range s.zones {
		if z.private || (n != z.name && !strings.HasSuffix(n, "."+z.name)) {
			continue
		}
		if best == nil || len(z.name) > len(best.name) {
			best = z
		}
	}
	return best
}

// RecordSet returns the TTL and the unquoted values of the TXT set at fqdn in a public zone.
func (s *Server) RecordSet(fqdn string) (ttl int, values []string, ok bool) {
	n := normName(fqdn)
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, z := range s.zones {
		if set := z.sets[n]; set != nil && !z.private {
			for _, v := range set.values {
				values = append(values, unquote(v))
			}
			return set.ttl, values, true
		}
	}
	return 0, nil, false
}

// Records returns every TXT set of every zone: record name -> unquoted values.
func (s *Server) Records() map[string][]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string][]string{}
	for _, z := range s.zones {
		for n, set := range z.sets {
			for _, v := range set.values {
				out[n] = append(out[n], unquote(v))
			}
		}
	}
	return out
}

// Requests returns a copy of the request log.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.log...)
}

// Counters returns a copy of the counters: one per operation answered with success, "auth-failed" for every refused
// signature or identity, "fault" for every scripted fault answered.
func (s *Server) Counters() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]int, len(s.counters))
	for k, v := range s.counters {
		out[k] = v
	}
	return out
}

// IssuedCredentials returns the temporary credentials the fake issued (leak-test needles).
func (s *Server) IssuedCredentials() []Credentials {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Credentials, 0, len(s.temps))
	for _, c := range s.temps {
		out = append(out, c)
	}
	return out
}

// Sessions returns the AssumeRole calls the fake granted, in order.
func (s *Server) Sessions() []Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Session(nil), s.sessions...)
}

// LastSignature returns the signature of the last request that verified ("" before any): a leak-test needle.
func (s *Server) LastSignature() string { s.mu.Lock(); defer s.mu.Unlock(); return s.lastSig }

func (s *Server) count(name string) { s.mu.Lock(); s.counters[name]++; s.mu.Unlock() }

// serve logs the request, checks its signature and routes it by host.
func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	host := hostOnly(r.Host)
	op := operation(host, r.Method, r.URL.Path)
	s.mu.Lock()
	s.log = append(s.log, Request{Method: r.Method, Host: host, Path: r.URL.Path, Op: op})
	i := len(s.log) - 1
	s.mu.Unlock()
	sw := &statusWriter{ResponseWriter: w}
	defer func() {
		s.mu.Lock()
		s.log[i].Status = sw.status
		s.mu.Unlock()
	}()
	switch host {
	case Route53Host:
		s.serveRoute53(sw, r, op, body)
	case STSHost:
		s.serveSTS(sw, r, op, body)
	default:
		// The fake never answers a name it does not own.
		sw.WriteHeader(http.StatusNotFound)
	}
}

// operation names a request's operation ("" for a route the fake does not serve).
func operation(host, method, path string) string {
	if host == STSHost {
		if method == http.MethodPost && path == "/" {
			return OpAssumeRole
		}
		return ""
	}
	rest, ok := strings.CutPrefix(path, "/2013-04-01/")
	if !ok {
		return ""
	}
	parts := strings.Split(strings.TrimSuffix(rest, "/"), "/")
	switch {
	case method == http.MethodGet && len(parts) == 1 && parts[0] == "hostedzonesbyname":
		return OpZones
	case len(parts) == 3 && parts[0] == "hostedzone" && parts[2] == "rrset" && method == http.MethodGet:
		return OpList
	case len(parts) == 3 && parts[0] == "hostedzone" && parts[2] == "rrset" && method == http.MethodPost:
		return OpChange
	case method == http.MethodGet && len(parts) == 2 && parts[0] == "change":
		return OpGetChange
	}
	return ""
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

// foldASCII lower-cases ASCII letters only.
func foldASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

// normName is a DNS name in the fake's form: lower case, no trailing dot.
func normName(n string) string { return strings.TrimSuffix(foldASCII(n), ".") }

const upperAlnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// randomUpper returns n random characters of A-Z and 0-9 (IDs and access key IDs, made at run time).
func randomUpper(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = upperAlnum[int(b[i])%len(upperAlnum)]
	}
	return string(b)
}

// randomSecret returns the base64 text of n random bytes (secret keys and session tokens hold "/" and "+" too).
func randomSecret(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}
