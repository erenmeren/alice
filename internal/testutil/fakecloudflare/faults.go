package fakecloudflare

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

// Fault is a scripted answer for a request of one op.
//
//	Delay   wait first (wall time, honouring the request's context); with nothing else set, the real answer follows.
//	Reset   close the connection without an answer (the client's request fails). Logged with status 0.
//	Status  the status to answer (default 200 when Body is set).
//	Code    the Cloudflare error code of the generated error body (default 1000 + Status); ignored with Body.
//	Body    the raw body, verbatim (a canary text, malformed JSON, an answer with a bad ID, a huge body).
//	Location  a Location header (a redirect with Status 301/302/307/308).
//
// A fault applies before the token is checked: it models the network and the API's failures, not the account.
type Fault struct {
	Status   int
	Code     int
	Body     string
	Location string
	Reset    bool
	Delay    time.Duration
}

type scriptedFault struct {
	op      string
	f       Fault
	forever bool
}

// FailNext scripts the next request of op (OpZones, OpCreate, OpList, OpDelete). Several calls queue in order.
func (s *Server) FailNext(op string, f Fault) {
	s.mu.Lock()
	s.faults = append(s.faults, &scriptedFault{op: op, f: f})
	s.mu.Unlock()
}

// FailAll answers f to every request of op until stop is called.
func (s *Server) FailAll(op string, f Fault) (stop func()) {
	sf := &scriptedFault{op: op, f: f, forever: true}
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

func (s *Server) takeFault(op string) *Fault {
	if op == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, x := range s.faults {
		if x.op != op {
			continue
		}
		if !x.forever {
			s.faults = append(s.faults[:i], s.faults[i+1:]...)
		}
		f := x.f
		return &f
	}
	return nil
}

// applyFault answers f; false means the real answer follows (a Delay alone).
func (s *Server) applyFault(w http.ResponseWriter, r *http.Request, f *Fault) bool {
	if f.Delay > 0 {
		t := time.NewTimer(f.Delay)
		defer t.Stop()
		select {
		case <-t.C:
		case <-r.Context().Done():
			return true
		}
	}
	switch {
	case f.Reset:
		resetConn(w)
		return true
	case f.Status == 0 && f.Body == "":
		return false
	}
	if f.Location != "" {
		w.Header().Set("Location", f.Location)
	}
	if f.Body != "" {
		status := f.Status
		if status == 0 {
			status = http.StatusOK
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(f.Body))
		return true
	}
	code := f.Code
	if code == 0 {
		code = 1000 + f.Status
	}
	writeError(w, f.Status, code, http.StatusText(f.Status))
	return true
}

// resetConn closes the connection without writing a byte (a TCP RST where the transport allows it). Over HTTP/2
// (a mounting binary's listener) the stream is aborted instead.
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

// statusWriter records the status answered, for the request log.
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

func (s *Server) record(r *http.Request, op string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.log = append(s.log, Request{Method: r.Method, Path: r.URL.Path, Op: op})
	s.counters[op]++
	return len(s.log) - 1
}

func (s *Server) setStatus(i, status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if i < len(s.log) {
		s.log[i].Status = status
	}
}
