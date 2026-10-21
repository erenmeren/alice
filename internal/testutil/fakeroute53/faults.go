package fakeroute53

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strconv"
	"time"
)

// Fault is a scripted answer to one operation, given after the request's signature verified.
//
//	Status  the status to answer: 0 with a Code is 400 (AWS's status for most coded errors), 0 with a Body is 200.
//	Code    the AWS error code of the error document ("Throttling", "PriorRequestNotComplete", "InvalidChangeBatch"...);
//	        "" with a Status of 400 or more picks the code AWS gives that status.
//	Body    the raw body, verbatim (a canary, a malformed answer, an answer with an invalid ID); "" = the error
//	        document of Status and Code. The fake never echoes a request into an error document.
//	Reset   close the connection before any response byte.
//	Delay   wait before answering (honouring the request's context); alone, it delays the real answer.
type Fault struct {
	Status int
	Code   string
	Body   string
	Reset  bool
	Delay  time.Duration
}

type scripted struct {
	op      string
	f       Fault
	forever bool
}

// FailNext answers f to the next request of op. Several calls queue in order.
func (s *Server) FailNext(op string, f Fault) {
	s.mu.Lock()
	s.faults = append(s.faults, &scripted{op: op, f: f})
	s.mu.Unlock()
}

// FailAll answers f to every request of op until stop is called.
func (s *Server) FailAll(op string, f Fault) (stop func()) {
	sf := &scripted{op: op, f: f, forever: true}
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

// withFault answers op's scripted fault, or runs real when there is none (or the fault is a delay only).
func (s *Server) withFault(w http.ResponseWriter, r *http.Request, op string, ns string, real func()) {
	f := s.takeFault(op)
	if f == nil {
		real()
		return
	}
	if !sleepCtx(r.Context(), f.Delay) {
		return
	}
	if f.Reset {
		s.count("fault")
		resetConn(w)
		return
	}
	if f.Status == 0 && f.Code == "" && f.Body == "" {
		real()
		return
	}
	s.count("fault")
	status := f.Status
	if status == 0 {
		status = http.StatusBadRequest
		if f.Code == "" {
			status = http.StatusOK
		}
	}
	if f.Body != "" {
		w.Header().Set("Content-Type", "text/xml")
		w.Header().Set("Content-Length", strconv.Itoa(len(f.Body)))
		w.WriteHeader(status)
		_, _ = w.Write([]byte(f.Body))
		return
	}
	code := f.Code
	if code == "" {
		code = defaultCode(status)
	}
	if code == codeInvalidChangeBatch {
		writeInvalidChangeBatch(w, "fake: scripted refusal")
		return
	}
	writeError(w, ns, status, code)
}

// defaultCode is the code AWS gives a status without a more specific one (GUESS for the server errors: the
// reference lists the codes, not which status carries which).
func defaultCode(status int) string {
	switch status {
	case http.StatusForbidden:
		return "AccessDenied"
	case http.StatusNotFound:
		return "NoSuchHostedZone"
	case http.StatusTooManyRequests:
		return "Throttling"
	case http.StatusServiceUnavailable:
		return "ServiceUnavailable"
	}
	if status >= 500 {
		return "InternalFailure"
	}
	return "InvalidInput"
}

// sleepCtx waits d of wall time; false when ctx ended first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return true
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

// resetConn closes the connection without writing a byte.
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
