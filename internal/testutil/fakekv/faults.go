package fakekv

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Fault is a scripted answer for a request.
//
//	Status      the status to answer. 0 with no Body: the real answer, modified by NextLink/Truncate/Drop.
//	Body        the raw body ("" = the real shape for Status). With Status 0 the status is 200: a body
//	            of "{not json" is a malformed answer.
//	RetryAfter  the Retry-After header, verbatim: "7" (seconds) or an HTTP-date.
//	Truncate    cut the body in half with the HTTP framing intact (malformed JSON, F-52).
//	Drop        cut the body in half and close the connection (a dropped connection: the client sees an
//	            unexpected EOF, the declared Content-Length is not met). The log keeps the status it started to send.
//	Reset       close the connection before any response byte (the client's Do fails; with Apply the
//	            state change happens first, as with an import whose answer never arrives). Logged with Status 0.
//	Location    a redirect target (use with Status 301/302/307/308).
//	NextLink    replace the nextLink of a listing (a wrong-host nextLink, A-14).
//	Apply       process the request first (an import happens), then answer the fault.
//	Delay       wait before answering, honouring the request's context (wall time).
type Fault struct {
	Status     int
	Body       string
	RetryAfter string
	Truncate   bool
	Drop       bool
	Reset      bool
	Location   string
	NextLink   string
	Apply      bool
	Delay      time.Duration
}

type scriptedFault struct {
	prefix  string
	f       Fault
	forever bool
}

type hold struct {
	prefix string
	gate   chan struct{}
	once   sync.Once
	taken  bool // a request waits on it (or waited): it matches no further request
}

func (h *hold) releaseLocked() { h.once.Do(func() { close(h.gate) }) }

// FailNext scripts the next AUTHENTICATED request whose path starts with path. The prefix matches EVERY
// route under it ("/certificates" also matches "/certificates/x/import" and "/certificates/x/versions"):
// use the most specific path. It applies to any host (the token
// endpoint, IMDS and the vault share the mechanism): it answers f. Several calls queue in order. An
// unauthenticated vault request (the SDK's challenge probe) never consumes a fault.
func (s *Server) FailNext(path string, f Fault) {
	s.mu.Lock()
	s.faults = append(s.faults, &scriptedFault{prefix: path, f: f})
	s.mu.Unlock()
}

// FailAll answers f to every matching request until the returned function is called.
func (s *Server) FailAll(path string, f Fault) (stop func()) {
	sf := &scriptedFault{prefix: path, f: f, forever: true}
	s.mu.Lock()
	s.faults = append(s.faults, sf)
	s.mu.Unlock()
	return func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		for i, x := range s.faults {
			if x == sf {
				s.faults = append(s.faults[:i], s.faults[i+1:]...)
				return
			}
		}
	}
}

// SetLatency delays every answer (except the challenge) by d of wall time, honouring request contexts.
func (s *Server) SetLatency(d time.Duration) { s.mu.Lock(); s.latency = d; s.mu.Unlock() }

// Hold makes the next request whose path starts with path wait until release is called or its context
// ends (L-87: a poll in flight). Held reports how many requests wait now.
func (s *Server) Hold(path string) (release func()) {
	h := &hold{prefix: path, gate: make(chan struct{})}
	s.mu.Lock()
	s.holds = append(s.holds, h)
	s.mu.Unlock()
	return func() { s.mu.Lock(); h.releaseLocked(); s.mu.Unlock() }
}

// Held returns the number of requests waiting in a Hold now.
func (s *Server) Held() int { s.mu.Lock(); defer s.mu.Unlock(); return s.heldNow }

// ExpireSecret makes the client secret read as expired: a right secret answers AADSTS7000222.
func (s *Server) ExpireSecret() { s.mu.Lock(); s.expiredSec = true; s.mu.Unlock() }

// RestoreSecret undoes ExpireSecret.
func (s *Server) RestoreSecret() { s.mu.Lock(); s.expiredSec = false; s.mu.Unlock() }

// SetChallenge replaces the WWW-Authenticate value of the vault's 401 ("" = the standard challenge):
// a challenge naming another authority or resource (A-14).
func (s *Server) SetChallenge(value string) { s.mu.Lock(); s.challenge = value; s.mu.Unlock() }

// sleepCtx waits d of wall time; false when ctx ended first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// serveWithFaults runs latency, hold and the scripted faults, then route.
func (s *Server) serveWithFaults(w http.ResponseWriter, r *http.Request, route http.HandlerFunc) {
	s.mu.Lock()
	lat := s.latency
	s.mu.Unlock()
	if !sleepCtx(r.Context(), lat) {
		return
	}
	if !s.waitHold(r) {
		return
	}
	f := s.takeFault(r.URL.Path)
	if f == nil {
		route(w, r)
		return
	}
	s.applyFault(w, r, f, route)
}

func (s *Server) waitHold(r *http.Request) bool {
	s.mu.Lock()
	var h *hold
	for _, x := range s.holds {
		if !x.taken && strings.HasPrefix(r.URL.Path, x.prefix) {
			h = x
			h.taken = true // kept in the list so Close can release it
			break
		}
	}
	if h == nil {
		s.mu.Unlock()
		return true
	}
	s.heldNow++
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.heldNow--; s.mu.Unlock() }()
	select {
	case <-h.gate:
		return true
	case <-r.Context().Done():
		return false
	}
}

func (s *Server) takeFault(path string) *Fault {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, x := range s.faults {
		if !strings.HasPrefix(path, x.prefix) {
			continue
		}
		f := x.f
		if !x.forever {
			s.faults = append(s.faults[:i], s.faults[i+1:]...)
		}
		return &f
	}
	return nil
}

func (s *Server) applyFault(w http.ResponseWriter, r *http.Request, f *Fault, route http.HandlerFunc) {
	if f.Reset {
		if f.Apply {
			route(httptest.NewRecorder(), r)
		}
		resetConn(w)
		return
	}
	status, body := f.Status, []byte(f.Body)
	hdr := http.Header{}
	if f.Status == 0 || f.Apply {
		rec := httptest.NewRecorder()
		route(rec, r) // the real answer (and its side effects)
		if f.Status == 0 {
			status, body = rec.Code, rec.Body.Bytes()
			if f.Body != "" {
				body = []byte(f.Body)
			}
			for k, v := range rec.Header() {
				hdr[k] = v
			}
			if f.NextLink != "" {
				body = withNextLink(body, f.NextLink)
			}
		}
	}
	if f.Status != 0 {
		if f.Body == "" && f.Status >= 400 {
			body = defaultFaultBody(r, f.Status)
		}
		hdr.Set("Content-Type", "application/json; charset=utf-8")
		hdr.Set("x-ms-request-id", uuid.NewString())
	}
	if f.RetryAfter != "" {
		hdr.Set("Retry-After", f.RetryAfter)
	}
	if f.Location != "" {
		hdr.Set("Location", f.Location)
	}
	if !sleepCtx(r.Context(), f.Delay) {
		return
	}
	full := len(body)
	if (f.Truncate || f.Drop) && len(body) > 1 {
		body = body[:len(body)/2]
	}
	if f.Drop {
		hdr.Set("Content-Length", strconv.Itoa(full)) // promise more than is sent
	} else {
		hdr.Set("Content-Length", strconv.Itoa(len(body)))
	}
	for k, v := range hdr {
		w.Header()[k] = v
	}
	w.WriteHeader(status)
	_, _ = w.Write(body)
	if f.Drop {
		_ = http.NewResponseController(w).Flush()
		panic(http.ErrAbortHandler) // closes the connection before the declared length is met
	}
}

// withNextLink rewrites the nextLink of a listing body (adds one when absent).
func withNextLink(body []byte, link string) []byte {
	var m map[string]any
	if json.Unmarshal(body, &m) != nil {
		return body
	}
	m["nextLink"] = link
	out, err := json.Marshal(m)
	if err != nil {
		return body
	}
	return out
}

// defaultFaultBody is the error body of a scripted failure, in the shape of the host that answers:
// Entra for the login host, the Key Vault error otherwise. The codes are GUESSES (S10): the REST
// reference does not list the body of a throttle or an outage.
func defaultFaultBody(r *http.Request, status int) []byte {
	if hostOnly(r.Host) == loginHost {
		code, desc := "temporarily_unavailable", "AADSTS90033: A transient error has occurred. Please try again."
		if status == http.StatusTooManyRequests {
			code, desc = "temporarily_unavailable", "AADSTS50196: The server terminated an operation because it encountered a client request loop."
		}
		b, _ := json.Marshal(map[string]any{"error": code, "error_description": desc})
		return b
	}
	if strings.HasPrefix(r.URL.Path, "/metadata/") {
		b, _ := json.Marshal(map[string]any{"error": "temporarily_unavailable", "error_description": "The service is temporarily unavailable."})
		return b
	}
	code, msg := "InternalServerError", "Internal server error."
	switch status {
	case http.StatusTooManyRequests:
		code, msg = "Throttled", "Request was throttled. Please retry later."
	case http.StatusBadGateway:
		code, msg = "BadGateway", "Bad gateway."
	case http.StatusServiceUnavailable:
		code, msg = "ServiceUnavailable", "The service is temporarily unavailable."
	case http.StatusGatewayTimeout:
		code, msg = "GatewayTimeout", "The gateway timed out."
	case http.StatusForbidden:
		code, msg = "Forbidden", "Forbidden."
	case http.StatusNotFound:
		code, msg = "NotFound", "Not found."
	case http.StatusUnauthorized:
		code, msg = "Unauthorized", "Unauthorized."
	}
	b, _ := json.Marshal(kvErrorBody{Error: kvError{Code: code, Message: msg}})
	return b
}

// resetConn closes the connection without writing a byte (a TCP RST where the transport allows it).
func resetConn(w http.ResponseWriter) {
	conn, _, err := http.NewResponseController(w).Hijack()
	if err != nil {
		panic(http.ErrAbortHandler)
	}
	raw := conn
	if tc, ok := conn.(*tls.Conn); ok {
		raw = tc.NetConn()
	}
	if t, ok := raw.(*net.TCPConn); ok {
		_ = t.SetLinger(0)
	}
	_ = raw.Close()
}
