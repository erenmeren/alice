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

const apiCSP = "default-src 'none'; frame-ancestors 'none'"

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

func (s *server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if err, ok := v.(error); ok && errors.Is(err, http.ErrAbortHandler) {
					panic(v)
				}
				// The panic value is not logged: it may contain request data or secrets.
				s.deps.Log.Error("request handler panicked", "request_id", RequestID(r.Context()), "path", r.URL.Path)
				s.writeError(w, r, ErrUnexpected)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
