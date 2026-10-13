package fakeacme

import (
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

const maxAdminBody = 1 << 16

type adminError struct {
	status int
	msg    string
}

func bad(msg string) *adminError { return &adminError{status: http.StatusBadRequest, msg: msg} }

func boolArg(v string) (bool, *adminError) {
	switch v {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, bad("expected true or false, got \"" + v + "\"")
}

func durArg(v string) (time.Duration, *adminError) {
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, bad("\"" + v + "\" is not a duration (e.g. 90m, 720h)")
	}
	return d, nil
}

// AdminHandler is the control API of the e2e service: every route answers one JSON object and takes
// its arguments in the query string. It answers loopback callers only (the listener is loopback
// already: defence in depth). Routes: GET /ping, GET /credentials, GET /ca, POST /reset, GET /counters,
// GET /requests, POST /requests/clear, POST /fault, POST /unfault, GET /dns, POST /dns,
// POST /dns/clear, POST /http-target, POST /eab, POST /lifetime, POST /ari, POST /stuck,
// POST /reject, POST /reject/clear, POST /validation-fail, POST /advertise, POST /challenges,
// POST /processing-polls, POST /clock.
func (s *Server) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	ok := map[string]bool{"ok": true}
	route := func(pattern string, fn func(q func(string) string) (any, *adminError)) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			qv := r.URL.Query()
			out, aerr := fn(qv.Get)
			if aerr != nil {
				writeJSON(w, aerr.status, map[string]string{"error": aerr.msg})
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			writeJSON(w, http.StatusOK, out)
		})
	}
	route("GET /ping", func(func(string) string) (any, *adminError) { return ok, nil })
	route("GET /credentials", func(func(string) string) (any, *adminError) { return s.Credentials(), nil })
	// The public CA certificates, for a form that takes a CA bundle: the TLS CA (the PEM the serve command writes to
	// --ca-out) and the root the issued certificates chain to (the chains it hands out omit it, as public CAs do).
	route("GET /ca", func(func(string) string) (any, *adminError) {
		return map[string]string{"ca_pem": string(s.CAPEM()), "issuer_root_pem": string(s.IssuerRootPEM())}, nil
	})
	route("POST /reset", func(func(string) string) (any, *adminError) { s.Reset(); return s.Credentials(), nil })
	route("GET /counters", func(func(string) string) (any, *adminError) { return s.Counters(), nil })
	route("GET /requests", func(func(string) string) (any, *adminError) { return map[string]any{"requests": s.Requests()}, nil })
	route("POST /requests/clear", func(func(string) string) (any, *adminError) { s.ClearRequests(); return ok, nil })

	route("POST /fault", func(q func(string) string) (any, *adminError) {
		f := Fault{Endpoint: q("endpoint"), Kind: q("kind")}
		var err error
		if v := q("times"); v != "" {
			if f.Times, err = strconv.Atoi(v); err != nil {
				return nil, bad("times must be a number")
			}
		}
		if v := q("retry_after"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil {
				return nil, bad("retry-after must be a number of seconds")
			}
			f.RetryAfter = time.Duration(n) * time.Second
		}
		if v := q("delay"); v != "" {
			var aerr *adminError
			if f.Delay, aerr = durArg(v); aerr != nil {
				return nil, aerr
			}
		}
		if err := s.AddFault(f); err != nil {
			return nil, bad(err.Error())
		}
		return ok, nil
	})
	route("POST /unfault", func(func(string) string) (any, *adminError) { s.ClearFaults(); return ok, nil })

	route("GET /dns", func(func(string) string) (any, *adminError) { return s.DNSRecords(), nil })
	route("POST /dns", func(q func(string) string) (any, *adminError) {
		if normFQDN(q("name")) == "" || q("value") == "" {
			return nil, bad("name and value are required")
		}
		s.DNSSet(q("name"), q("value"))
		return ok, nil
	})
	route("POST /dns/clear", func(q func(string) string) (any, *adminError) { s.DNSClear(q("name"), q("value")); return ok, nil })
	route("POST /http-target", func(q func(string) string) (any, *adminError) {
		if q("name") == "" {
			return nil, bad("name is required")
		}
		addr := q("addr")
		if addr == "off" {
			addr = ""
		}
		s.SetHTTPTarget(q("name"), addr)
		return ok, nil
	})
	route("POST /eab", func(q func(string) string) (any, *adminError) {
		on, aerr := boolArg(q("required"))
		if aerr != nil {
			return nil, aerr
		}
		s.SetExternalAccountRequired(on)
		return ok, nil
	})
	route("POST /lifetime", func(q func(string) string) (any, *adminError) {
		d, aerr := durArg(q("duration"))
		if aerr != nil {
			return nil, aerr
		}
		if err := s.SetLeafLifetime(d); err != nil {
			return nil, bad(err.Error())
		}
		return ok, nil
	})
	route("POST /ari", func(q func(string) string) (any, *adminError) { return s.adminARI(q, ok) })
	route("POST /stuck", func(q func(string) string) (any, *adminError) {
		on, aerr := boolArg(q("on"))
		if aerr != nil {
			return nil, aerr
		}
		s.SetStuckPending(on)
		return ok, nil
	})
	route("POST /reject", func(q func(string) string) (any, *adminError) {
		if q("identifier") == "" {
			return nil, bad("identifier is required")
		}
		s.RejectIdentifier(q("identifier"))
		return ok, nil
	})
	route("POST /reject/clear", func(func(string) string) (any, *adminError) { s.ClearRejected(); return ok, nil })
	route("POST /validation-fail", func(q func(string) string) (any, *adminError) {
		on, aerr := boolArg(q("on"))
		if aerr != nil {
			return nil, aerr
		}
		if err := s.FailValidation(q("type"), on); err != nil {
			return nil, bad(err.Error())
		}
		return ok, nil
	})
	route("POST /advertise", func(q func(string) string) (any, *adminError) {
		if err := s.Advertise(q("field"), q("url")); err != nil {
			return nil, bad(err.Error())
		}
		return ok, nil
	})
	route("POST /challenges", func(q func(string) string) (any, *adminError) {
		if err := s.SetChallenges(strings.Split(q("types"), ",")...); err != nil {
			return nil, bad(err.Error())
		}
		return ok, nil
	})
	route("POST /processing-polls", func(q func(string) string) (any, *adminError) {
		n, err := strconv.Atoi(q("n"))
		if err != nil || n < 0 || n > 100 {
			return nil, bad("n must be a number from 0 to 100")
		}
		s.SetProcessingPolls(n)
		return ok, nil
	})
	route("POST /clock", func(q func(string) string) (any, *adminError) {
		if q("time") == "real" {
			s.SetClock(time.Time{})
		} else {
			at, err := time.Parse(time.RFC3339, q("time"))
			if err != nil || at.Year() < 2000 || at.Year() > 2100 {
				return nil, bad("time must be \"real\" or an RFC 3339 time between the years 2000 and 2100")
			}
			s.SetClock(at)
		}
		return map[string]string{"now": s.Now().UTC().Format(time.RFC3339)}, nil
	})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ap, err := netip.ParseAddrPort(r.RemoteAddr)
		if err != nil || !ap.Addr().Unmap().IsLoopback() {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "the admin API answers loopback callers only"})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxAdminBody)
		mux.ServeHTTP(w, r)
	})
}

// adminARI: "default=true", or "start"+"end" (RFC 3339), or "before"+"length" (durations).
func (s *Server) adminARI(q func(string) string, ok map[string]bool) (any, *adminError) {
	switch {
	case q("default") == "true":
		s.SetARIRelative(0, 0)
	case q("start") != "":
		start, err1 := time.Parse(time.RFC3339, q("start"))
		end, err2 := time.Parse(time.RFC3339, q("end"))
		if err1 != nil || err2 != nil {
			return nil, bad("start and end must be RFC 3339 times")
		}
		if err := s.SetARIWindow(start, end); err != nil {
			return nil, bad(err.Error())
		}
	case q("before") != "":
		before, aerr := durArg(q("before"))
		if aerr != nil {
			return nil, aerr
		}
		length := time.Duration(0)
		if q("length") != "" {
			if length, aerr = durArg(q("length")); aerr != nil {
				return nil, aerr
			}
		}
		if before < 0 || length < 0 {
			return nil, bad("durations must not be negative")
		}
		s.SetARIRelative(before, length)
	default:
		return nil, bad("give default=true, start and end, or before (and length)")
	}
	return ok, nil
}
