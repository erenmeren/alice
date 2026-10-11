package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/google/uuid"
)

type ctxKey int

const requestIDKey ctxKey = iota

// RequestID returns the request ID assigned by the middleware, or "".
func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey).(string)
	return id
}

// requestID assigns a server-generated ID. Client-supplied IDs are ignored so
// they cannot be used to forge audit correlations.
func (s *server) requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := uuid.Must(uuid.NewV7()).String()
		w.Header().Set("X-Request-Id", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey, id)))
	})
}

// apiCSP is the policy of every response but index.html (SEC-033). base-uri and form-action do not
// fall back to default-src, so they are named too: an API answer rendered as a document (the OIDC
// callback's error page, a mistyped Content-Type) can neither set a base URL nor submit a form
// (ZAP rule 10055, found by make zap-baseline, Phase 8 Task 15).
const apiCSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		h.Set("Content-Security-Policy", apiCSP) // the SPA handler replaces this for index.html
		next.ServeHTTP(w, r)
	})
}

// startedWriter records whether the response has begun. Unwrap keeps
// http.ResponseController (Flush, deadlines) working through the wrapper.
type startedWriter struct {
	http.ResponseWriter
	started bool
}

func (w *startedWriter) WriteHeader(code int) {
	w.started = true
	w.ResponseWriter.WriteHeader(code)
}

func (w *startedWriter) Write(b []byte) (int, error) {
	w.started = true
	return w.ResponseWriter.Write(b)
}

func (w *startedWriter) Flush() {
	w.started = true
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}

func (w *startedWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (s *server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &startedWriter{ResponseWriter: w}
		defer func() {
			if v := recover(); v != nil {
				if err, ok := v.(error); ok && errors.Is(err, http.ErrAbortHandler) {
					panic(v)
				}
				if f, ok := v.(encodeFailure); ok {
					// writeJSON could not encode an answer (nothing was written): only the Go type.
					s.deps.Log.Error("response encoding failed", "request_id", RequestID(r.Context()), "path", r.URL.Path, "value_type", f.valueType)
				} else {
					// The panic value is not logged: it may contain request data or secrets.
					s.deps.Log.Error("request handler panicked", "request_id", RequestID(r.Context()), "path", r.URL.Path)
				}
				if sw.started {
					// Headers are gone; appending a JSON error would corrupt the body.
					// Abort so net/http drops the connection and the client sees a truncated response.
					panic(http.ErrAbortHandler)
				}
				s.writeError(w, r, ErrUnexpected)
			}
		}()
		next.ServeHTTP(sw, r)
	})
}
