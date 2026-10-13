package fakeacme

import (
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// Fault kinds.
const (
	FaultBadNonce       = "badNonce"       // 400 urn:ietf:params:acme:error:badNonce (POST routes only)
	FaultRateLimited    = "rateLimited"    // 429 urn:ietf:params:acme:error:rateLimited with Retry-After
	FaultServerInternal = "serverInternal" // 500 urn:ietf:params:acme:error:serverInternal
	FaultSlow           = "slow"           // the answer is delayed by Delay
	FaultGiant          = "giant"          // a 200 answer of 2 MiB (over any sane cap)
)

// Endpoints a Fault can name (also the keys of Counters); "*" matches every endpoint.
var Endpoints = []string{"directory", "new-nonce", "new-account", "account", "key-change", "revoke-cert", "new-order", "order",
	"finalize", "authz", "challenge", "certificate", "ari", "terms", "hook"}

// Fault is one injected misbehaviour. It applies to the next Times requests of Endpoint (every
// request until ClearFaults when Times is 0).
type Fault struct {
	Endpoint   string        `json:"endpoint"`
	Kind       string        `json:"kind"`
	Times      int           `json:"times"`
	RetryAfter time.Duration `json:"retry_after"` // rateLimited
	Delay      time.Duration `json:"delay"`       // slow
}

const giantSize = 2 << 20

// AddFault arms a fault.
func (s *Server) AddFault(f Fault) error {
	if f.Endpoint != "*" && !contains(Endpoints, f.Endpoint) {
		return fmt.Errorf("fakeacme: unknown endpoint %q (known: %v)", f.Endpoint, Endpoints)
	}
	switch f.Kind {
	case FaultBadNonce, FaultRateLimited, FaultServerInternal, FaultGiant:
	case FaultSlow:
		if f.Delay <= 0 || f.Delay > time.Minute {
			return fmt.Errorf("fakeacme: a slow fault needs a delay up to one minute")
		}
	default:
		return fmt.Errorf("fakeacme: unknown fault kind %q", f.Kind)
	}
	if f.Times < 0 || f.Times > 1000 || f.RetryAfter < 0 || f.RetryAfter > 24*time.Hour {
		return fmt.Errorf("fakeacme: fault times or retry-after out of range")
	}
	c := f
	s.mu.Lock()
	s.st.faults = append(s.st.faults, &c)
	s.mu.Unlock()
	return nil
}

// ClearFaults removes every armed fault.
func (s *Server) ClearFaults() {
	s.mu.Lock()
	s.st.faults = nil
	s.mu.Unlock()
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

type effect struct {
	delay    time.Duration
	terminal *Fault
}

// takeFaults returns what applies to one request and consumes it.
func (s *Server) takeFaults(endpoint string, post bool) effect {
	s.mu.Lock()
	defer s.mu.Unlock()
	var e effect
	keep := s.st.faults[:0]
	for _, f := range s.st.faults {
		hit := f.Endpoint == endpoint || f.Endpoint == "*"
		switch {
		case !hit:
		case f.Kind == FaultBadNonce && !post:
			hit = false
		case f.Kind == FaultSlow:
			e.delay += f.Delay
		case e.terminal != nil:
			hit = false // one terminal fault per request; the next one waits for the next request
		default:
			c := *f
			e.terminal = &c
		}
		if hit && f.Times > 0 {
			f.Times--
			if f.Times == 0 {
				continue
			}
		}
		keep = append(keep, f)
	}
	s.st.faults = keep
	return e
}

// applyTerminal answers a request with its terminal fault.
func (s *Server) applyTerminal(w http.ResponseWriter, f *Fault) {
	switch f.Kind {
	case FaultBadNonce:
		s.writeProblem(w, newProblem(http.StatusBadRequest, "badNonce", "the nonce is stale (injected by the fake)"))
	case FaultRateLimited:
		p := newProblem(http.StatusTooManyRequests, "rateLimited", "too many requests (injected by the fake)")
		p.retryAfter = f.RetryAfter
		s.writeProblem(w, p)
	case FaultServerInternal:
		s.writeProblem(w, newProblem(http.StatusInternalServerError, "serverInternal", "the fake failed on purpose"))
	case FaultGiant:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		chunk := make([]byte, 32<<10)
		for i := range chunk {
			chunk[i] = 'A'
		}
		_, _ = w.Write([]byte(`{"pad":"`))
		for n := 0; n < giantSize; n += len(chunk) {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
		_, _ = w.Write([]byte(`"}`))
	}
}

// problem is an RFC 7807 / RFC 8555 section 6.7 problem document.
type problem struct {
	status     int
	typ        string
	detail     string
	retryAfter time.Duration
}

func newProblem(status int, short, detail string) *problem {
	return &problem{status: status, typ: "urn:ietf:params:acme:error:" + short, detail: detail}
}

func malformed(status int, detail string) *problem { return newProblem(status, "malformed", detail) }

func (p *problem) doc() map[string]any {
	return map[string]any{"type": p.typ, "detail": p.detail, "status": p.status}
}

func (s *Server) writeProblem(w http.ResponseWriter, p *problem) {
	if p.retryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(p.retryAfter.Seconds())))
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(p.status)
	_ = jsonEncode(w, p.doc())
}
