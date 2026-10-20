package fakeacme

import (
	"encoding/json"
	"io"
	"net/http"
	"time"
)

func jsonEncode(w io.Writer, v any) error { return json.NewEncoder(w).Encode(v) }

// statusRecorder remembers the status a handler wrote, for the request log.
type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (r *statusRecorder) WriteHeader(code int) {
	if !r.wrote {
		r.status, r.wrote = code, true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if !r.wrote {
		r.status, r.wrote = http.StatusOK, true
	}
	return r.ResponseWriter.Write(b)
}

type routeFn func(w http.ResponseWriter, r *http.Request, req *jwsReq)

// route wraps a handler: request counting and log, a fresh Replay-Nonce on every answer, the armed
// faults, and (for auth routes) JWS verification.
func (s *Server) route(endpoint string, auth bool, mode jwsMode, fn routeFn) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		defer func() { s.logRequest(r.Method, r.URL.Path, rec.status) }()
		s.count("requests")
		s.count(endpoint)
		rec.Header().Set("Replay-Nonce", s.newNonce())
		rec.Header().Set("Cache-Control", "no-store")
		eff := s.takeFaults(endpoint, auth)
		if eff.delay > 0 {
			t := time.NewTimer(eff.delay)
			select {
			case <-r.Context().Done():
				// The client gave up. Returning normally would make net/http send an implicit empty 200,
				// and a client whose own deadline raced that answer could read it as a (broken) answer of
				// the CA. Abort instead: the connection closes with no answer at all.
				t.Stop()
				rec.status = 0 // logged as "no answer"
				panic(http.ErrAbortHandler)
			case <-t.C:
			}
		}
		if eff.terminal != nil {
			s.applyTerminal(rec, eff.terminal)
			return
		}
		var req *jwsReq
		if auth {
			var prob *problem
			if req, prob = s.authenticate(rec, r, mode); prob != nil {
				s.writeProblem(rec, prob)
				return
			}
		}
		fn(rec, r, req)
	}
}

// Handler is the fake's ACME and hook handler. Serve it over TLS (Start, or TLSConfig).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /directory", s.route("directory", false, modeKID, s.handleDirectory))
	nonce := s.route("new-nonce", false, modeKID, s.handleNonce)
	mux.HandleFunc("HEAD /acme/new-nonce", nonce)
	mux.HandleFunc("GET /acme/new-nonce", nonce)
	mux.HandleFunc("GET /terms", s.route("terms", false, modeKID, func(w http.ResponseWriter, _ *http.Request, _ *jwsReq) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "Terms of service of the Alice fake ACME CA: none, it is a test double.\n")
	}))
	mux.HandleFunc("POST /acme/new-acct", s.route("new-account", true, modeJWK, s.handleNewAccount))
	mux.HandleFunc("POST /acme/acct/{id}", s.route("account", true, modeKID, s.handleAccount))
	mux.HandleFunc("POST /acme/key-change", s.route("key-change", true, modeKID, s.handleKeyChange))
	mux.HandleFunc("POST /acme/revoke-cert", s.route("revoke-cert", true, modeEither, s.handleRevoke))
	mux.HandleFunc("POST /acme/new-order", s.route("new-order", true, modeKID, s.handleNewOrder))
	mux.HandleFunc("POST /acme/order/{id}", s.route("order", true, modeKID, s.handleOrder))
	mux.HandleFunc("POST /acme/finalize/{id}", s.route("finalize", true, modeKID, s.handleFinalize))
	mux.HandleFunc("POST /acme/authz/{id}", s.route("authz", true, modeKID, s.handleAuthz))
	mux.HandleFunc("POST /acme/chall/{id}/{n}", s.route("challenge", true, modeKID, s.handleChallenge))
	mux.HandleFunc("POST /acme/cert/{id}", s.route("certificate", true, modeKID, s.handleCertificate))
	mux.HandleFunc("POST /acme/cert/{id}/alt/{n}", s.route("certificate", true, modeKID, s.handleCertificate))
	mux.HandleFunc("GET /acme/renewal-info/{certid}", s.route("ari", false, modeKID, s.handleARI))
	mux.HandleFunc("/hook", s.route("hook", false, modeKID, s.handleHook))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		defer func() { s.logRequest(r.Method, r.URL.Path, rec.status) }()
		s.count("requests")
		s.writeProblem(rec, malformed(http.StatusNotFound, "no such resource"))
	})
	return mux
}

func (s *Server) handleNonce(w http.ResponseWriter, r *http.Request, _ *jwsReq) {
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// override returns the URL a test forced for field, or def. "off" (the empty-string sentinel of the
// control API) is handled by the caller.
func (s *Server) override(field, def string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if v, ok := s.cfg.overrides[field]; ok {
		return v
	}
	return def
}

func (s *Server) handleDirectory(w http.ResponseWriter, _ *http.Request, _ *jwsReq) {
	base := s.BaseURL()
	s.mu.Lock()
	requireEAB := s.cfg.requireEAB
	s.mu.Unlock()
	d := map[string]any{
		"newNonce":   s.override("newNonce", base+"/acme/new-nonce"),
		"newAccount": s.override("newAccount", base+"/acme/new-acct"),
		"newOrder":   s.override("newOrder", base+"/acme/new-order"),
		"revokeCert": s.override("revokeCert", base+"/acme/revoke-cert"),
	}
	if !s.opts.NoKeyChange {
		d["keyChange"] = s.override("keyChange", base+"/acme/key-change")
	}
	if !s.opts.NoARI {
		d["renewalInfo"] = s.override("renewalInfo", base+"/acme/renewal-info")
	}
	meta := map[string]any{"externalAccountRequired": requireEAB, "website": base}
	if terms := s.override("termsOfService", base+"/terms"); !s.opts.NoTerms && terms != "" {
		meta["termsOfService"] = terms // a test may advertise other terms (changed terms, an unsafe URL) or none ("off")
	}
	d["meta"] = meta
	for k, v := range d {
		if v == "" {
			delete(d, k) // an override of "" removes the field
		}
	}
	writeJSON(w, http.StatusOK, d)
}
