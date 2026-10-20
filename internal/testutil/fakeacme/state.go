package fakeacme

import (
	"crypto"
	"time"
)

// maxLog bounds the request log.
const maxLog = 2000

type identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type account struct {
	id      string
	key     crypto.PublicKey
	thumb   string
	contact []string
	status  string
}

type challenge struct {
	typ, token, status string
	problem            *problem
	validated          time.Time
}

type authz struct {
	id, account string
	ident       identifier // wildcard names carry the base name here
	wildcard    bool
	status      string
	expires     time.Time
	challenges  []*challenge
}

type order struct {
	id, account string
	idents      []identifier // as ordered (wildcards keep "*.")
	authzs      []string
	status      string
	expires     time.Time
	certID      string
	polls       int // further polls answered "processing" after finalize
	problem     *problem
	// replaces is the RFC 9773 identifier of the certificate the order replaces ("" none).
	replaces string
}

// state is everything a Reset clears.
type state struct {
	accounts map[string]*account
	byThumb  map[string]string
	nonces   map[string]struct{}
	orders   map[string]*order
	authzs   map[string]*authz
	certs    map[string]*issued
	byARI    map[string]*issued
	dns      map[string][]string
	targets  map[string]string
	faults   []*Fault
	counters map[string]int
	log      []LogEntry

	// ariWindows are windows set for one certificate (by its RFC 9773 identifier); replaced lists the orders that
	// carried replaces, in order.
	ariWindows map[string]ariWindow
	replaced   []Replacement
}

// config is the behaviour toggles a Reset returns to the Options.
type config struct {
	requireEAB      bool
	challenges      []string
	lifetime        time.Duration
	stuck           bool
	failValidation  map[string]bool
	rejected        []string
	overrides       map[string]string
	ariStart        time.Time
	ariEnd          time.Time
	ariBefore       time.Duration
	ariLength       time.Duration
	processingPolls int
}

// LogEntry is one request the fake served: never a body, a header or a query.
type LogEntry struct {
	Time   time.Time `json:"time"`
	Method string    `json:"method"`
	Path   string    `json:"path"`
	Status int       `json:"status"`
}

func newState() *state {
	return &state{
		accounts: map[string]*account{}, byThumb: map[string]string{}, nonces: map[string]struct{}{},
		orders: map[string]*order{}, authzs: map[string]*authz{}, certs: map[string]*issued{}, byARI: map[string]*issued{},
		ariWindows: map[string]ariWindow{}, dns: map[string][]string{}, targets: map[string]string{}, counters: map[string]int{},
	}
}

// resetLocked returns state and configuration to the Options. The CAs, the TLS certificate, the
// EAB credentials and the hook secret stay (the CA file Alice trusts stays right). The caller holds
// no lock or holds mu.
func (s *Server) resetLocked() {
	s.st = newState()
	s.skew.Store(0)
	s.cfg = config{
		requireEAB: s.opts.RequireEAB, challenges: append([]string(nil), s.opts.Challenges...), lifetime: s.opts.LeafLifetime,
		failValidation: map[string]bool{}, overrides: map[string]string{},
	}
}

func (s *Server) count(name string) {
	s.mu.Lock()
	s.st.counters[name]++
	s.mu.Unlock()
}

func (s *Server) logRequest(method, path string, status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.st.log) >= maxLog {
		s.st.log = s.st.log[1:]
	}
	s.st.log = append(s.st.log, LogEntry{Time: s.now(), Method: method, Path: path, Status: status})
}
