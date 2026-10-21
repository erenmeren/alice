// Package fakecloudflare is an in-process fake of the part of the Cloudflare API v4 Alice's DNS-01 provider uses:
// zone lookup by name and TXT record create, list and delete, behind a bearer API token.
//
// It is test-support code: production code never imports it. It is an http.Handler plus a small constructor and
// holds no global state, so another binary can mount Handler behind its own listener (with host routing); New
// also starts an httptest TLS listener whose certificate, signed by the fake's own test CA, names
// api.cloudflare.com, and MapAddr sends a client's connections for that host there.
//
// Fidelity: the routes, the answer envelope ({"result","success","errors","messages","result_info"}), the error
// codes (10000 authentication error, 6003/6111 a malformed Authorization header, 7003 an unknown zone route, 81044
// a record that does not exist, 81058 an identical record, 9021 a TTL out of range) and the TTL rules (1 or
// 60..86400) follow Cloudflare's public API documentation. Where it is silent, the behaviour is a GUESS and marked
// so: duplicates are compared on the unquoted content, and a token limited to some zones gets a 403 with code 10000
// for any other zone's records.
package fakecloudflare

import (
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"alice/internal/platform/clock"
	"alice/internal/testutil/pki"
)

// Host is the host name the fake's certificate names.
const Host = "api.cloudflare.com"

// Sink receives the TXT values the fake holds, unquoted (fakeacme.Server satisfies it: its DNS-01 validation then
// sees the records).
type Sink interface {
	DNSSet(fqdn, value string)
	DNSClear(fqdn, value string)
}

// Options configures the fake. The zero value is a working configuration with no zones.
type Options struct {
	// Token is the one API token the fake accepts (default NewToken()).
	Token string
	// Zones are the zone names of the account (lower case, no trailing dot); their IDs are generated.
	Zones []string
	// TokenZones limits the token to these zones (nil: every zone of the account). A zone outside them is missing
	// from the zone listing and its records answer 403, as with a token whose permissions name some zones only.
	TokenZones []string
	// Sink, when set, mirrors every TXT value created and deleted.
	Sink Sink
	// Now stamps created_on and modified_on (default the real clock).
	Now func() time.Time
}

// Record is one DNS record the fake holds.
type Record struct {
	ID, ZoneID, ZoneName string
	Type, Name, Content  string
	TTL                  int
}

// Request is one logged request: the method, the path and the endpoint's op name ("" for an unknown route), and
// the status answered (0 for a dropped connection). Never a header, a query, a token or a body.
type Request struct {
	Method, Path, Op string
	Status           int
}

// Ops of the endpoints, for FailNext, FailAll and Counters.
const (
	OpZones  = "zones"
	OpCreate = "create"
	OpList   = "list"
	OpDelete = "delete"
)

type zone struct {
	id, name string
	allowed  bool
}

// Server is the fake. Create it with New or Start.
type Server struct {
	o    Options
	ca   *pki.CA
	srv  *httptest.Server
	pool *x509.CertPool
	now  func() time.Time

	mu       sync.Mutex
	zones    []*zone
	records  []Record
	log      []Request
	counters map[string]int
	faults   []*scriptedFault
}

// NewToken returns "fake-cf-" + 40 random hex characters.
func NewToken() string { return "fake-cf-" + randHex(20) }

// NewID returns a Cloudflare-shaped ID: 32 lower-case hex characters.
func NewID() string { return randHex(16) }

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// New starts the fake's TLS listener on 127.0.0.1.
func New(o Options) (*Server, error) {
	if o.Token == "" {
		o.Token = NewToken()
	}
	if o.Now == nil {
		o.Now = clock.Real{}.Now
	}
	s := &Server{o: o, now: o.Now, counters: map[string]int{}}
	limit := map[string]bool{}
	for _, z := range o.TokenZones {
		limit[normName(z)] = true
	}
	for _, n := range o.Zones {
		n = normName(n)
		s.zones = append(s.zones, &zone{id: NewID(), name: n, allowed: o.TokenZones == nil || limit[n]})
	}
	real := clock.Real{}.Now()
	s.ca = pki.NewCA("Alice fake Cloudflare", pki.ECDSA256, real)
	leaf := s.ca.Issue(pki.Opts{CommonName: Host, SANs: []string{Host}}, real)
	s.pool = x509.NewCertPool()
	s.pool.AddCert(s.ca.Root)
	s.srv = httptest.NewUnstartedServer(s.Handler())
	s.srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.Cert.Raw, s.ca.Intermediate.Raw}, PrivateKey: leaf.Key}},
		MinVersion:   tls.VersionTLS12,
	}
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

// Handler serves the API (any host, any listener).
func (s *Server) Handler() http.Handler { return http.HandlerFunc(s.serve) }

// TLSConfig is the fake's server TLS configuration (its certificate for api.cloudflare.com), for a harness that serves
// Handler on a listener of its own (the e2e fake ACME container).
func (s *Server) TLSConfig() *tls.Config { return s.srv.TLS.Clone() }

// CAPool returns a pool holding only the fake's root.
func (s *Server) CAPool() *x509.CertPool { return s.pool.Clone() }

// CAPEM returns the fake's root certificate as PEM.
func (s *Server) CAPEM() []byte { return append([]byte(nil), s.ca.RootPEM...) }

// Addr is the listener's "host:port".
func (s *Server) Addr() string { return s.srv.Listener.Addr().String() }

// MapAddr maps api.cloudflare.com:443 to the listener and returns every other address unchanged.
func (s *Server) MapAddr(hostport string) string {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil || port != "443" || normName(host) != Host {
		return hostport
	}
	return s.Addr()
}

// Token is the accepted API token.
func (s *Server) Token() string { return s.o.Token }

// ZoneID is the ID of a zone of the account, "" when there is none by that name.
func (s *Server) ZoneID(name string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if z := s.zoneByName(normName(name)); z != nil {
		return z.id
	}
	return ""
}

// AddRecord adds a record directly (another tool's record at a name); the content is stored as given and mirrored
// to the Sink when it is a TXT record. It returns the record's ID, "" when the zone does not exist.
func (s *Server) AddRecord(zoneName, typ, name, content string, ttl int) string {
	s.mu.Lock()
	z := s.zoneByName(normName(zoneName))
	if z == nil {
		s.mu.Unlock()
		return ""
	}
	r := Record{ID: NewID(), ZoneID: z.id, ZoneName: z.name, Type: typ, Name: normName(name), Content: content, TTL: ttl}
	s.records = append(s.records, r)
	s.mu.Unlock()
	s.mirror(r, true)
	return r.ID
}

// Records returns the records held now, in creation order.
func (s *Server) Records() []Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Record(nil), s.records...)
}

// TXT returns the unquoted TXT values at name, sorted.
func (s *Server) TXT(name string) []string {
	n := normName(name)
	var out []string
	for _, r := range s.Records() {
		if r.Type == "TXT" && r.Name == n {
			out = append(out, Unquote(r.Content))
		}
	}
	sort.Strings(out)
	return out
}

// Requests returns the request log.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.log...)
}

// Counters returns the number of requests per op (unknown routes under ""), faults included.
func (s *Server) Counters() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]int, len(s.counters))
	for k, v := range s.counters {
		out[k] = v
	}
	return out
}

func (s *Server) zoneByName(n string) *zone {
	for _, z := range s.zones {
		if z.name == n {
			return z
		}
	}
	return nil
}

func (s *Server) zoneByID(id string) *zone {
	for _, z := range s.zones {
		if z.id == id {
			return z
		}
	}
	return nil
}

func (s *Server) mirror(r Record, set bool) {
	if s.o.Sink == nil || r.Type != "TXT" {
		return
	}
	if set {
		s.o.Sink.DNSSet(r.Name, Unquote(r.Content))
	} else {
		s.o.Sink.DNSClear(r.Name, Unquote(r.Content))
	}
}

// authorized checks the bearer token: missing or malformed is Cloudflare's 400 6003 (error_chain 6111), a token
// it does not know its 401 10000.
func (s *Server) authorized(w http.ResponseWriter, r *http.Request) bool {
	h := r.Header.Get("Authorization")
	tok, ok := strings.CutPrefix(h, "Bearer ")
	if !ok || tok == "" || strings.ContainsAny(tok, " \t") {
		writeJSON(w, http.StatusBadRequest, envelope{Errors: []apiError{{Code: 6003, Message: "Invalid request headers",
			ErrorChain: []apiError{{Code: 6111, Message: "Invalid format for Authorization header"}}}}})
		return false
	}
	if subtle.ConstantTimeCompare([]byte(tok), []byte(s.o.Token)) != 1 {
		writeError(w, http.StatusUnauthorized, 10000, "Authentication error")
		return false
	}
	return true
}

// normName is a name in lower ASCII without a trailing dot.
func normName(n string) string {
	b := []byte(strings.TrimSuffix(n, "."))
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// Unquote is a TXT content without one pair of surrounding quotes.
func Unquote(c string) string {
	if len(c) >= 2 && c[0] == '"' && c[len(c)-1] == '"' {
		return c[1 : len(c)-1]
	}
	return c
}
