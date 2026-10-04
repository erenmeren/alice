package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"

	"github.com/google/uuid"

	"alice/internal/auth"
)

const (
	sessionCookie = "__Host-alice_session"
	setupCookie   = "__Host-alice_setup"

	// maxBody caps JSON request bodies (SEC-023).
	maxBody = 1 << 20
	// maxUserAgent bounds the stored User-Agent header in runes (as auth.truncateUA does).
	maxUserAgent = 256
)

// decode reads a JSON request body into dst. Unknown fields, malformed JSON,
// trailing data and bodies over 1 MiB are rejected (SEC-061, SEC-023). On
// failure it writes the error response and returns false.
func (s *server) decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	return s.decodeLimit(w, r, dst, maxBody)
}

// decodeLimit is decode with a smaller body cap than maxBody.
func (s *server) decodeLimit(w http.ResponseWriter, r *http.Request, dst any, limit int64) bool {
	return s.decodeBody(w, r, dst, limit, false)
}

// decodeOptional is decode for an optional body: an empty body (with or without a
// Content-Length, e.g. an empty chunked body) leaves dst unchanged.
func (s *server) decodeOptional(w http.ResponseWriter, r *http.Request, dst any) bool {
	return s.decodeBody(w, r, dst, maxBody, true)
}

// decodeOptionalLimit is decodeOptional with a smaller body cap than maxBody.
func (s *server) decodeOptionalLimit(w http.ResponseWriter, r *http.Request, dst any, limit int64) bool {
	return s.decodeBody(w, r, dst, limit, true)
}

func (s *server) decodeBody(w http.ResponseWriter, r *http.Request, dst any, limit int64, optional bool) bool {
	if r.ContentLength > limit {
		s.writeError(w, r, ErrBodyTooLarge) // declared too large: refused unread
		return false
	}
	body := http.MaxBytesReader(w, r.Body, limit)
	dec := json.NewDecoder(body)
	dec.DisallowUnknownFields()
	err := dec.Decode(dst)
	if optional && errors.Is(err, io.EOF) {
		return true // no JSON value at all
	}
	if err == nil {
		if _, tail := dec.Token(); !errors.Is(tail, io.EOF) {
			err = errors.New("trailing data after JSON value")
		}
	}
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			s.writeError(w, r, ErrBodyTooLarge)
		} else {
			s.writeError(w, r, ErrBadRequest)
		}
		return false
	}
	return true
}

// sessionTokenFrom returns the raw session cookie value, or "".
func sessionTokenFrom(r *http.Request) string { return cookieValue(r, sessionCookie) }

// setupTokenFrom returns the raw setup (wizard) cookie value, or "".
func setupTokenFrom(r *http.Request) string { return cookieValue(r, setupCookie) }

func cookieValue(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}

// meta collects the request facts the services record in sessions and audit events.
func (s *server) meta(r *http.Request) auth.Meta {
	ua := strings.ToValidUTF8(r.Header.Get("User-Agent"), "")
	if runes := []rune(ua); len(runes) > maxUserAgent {
		ua = string(runes[:maxUserAgent])
	}
	return auth.Meta{IP: clientIP(r, s.deps.TrustedProxies), UserAgent: ua, RequestID: RequestID(r.Context())}
}

func setCookie(w http.ResponseWriter, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

// setSessionCookie sets the browser-session cookie (SEC-018). It has no
// Max-Age: the server enforces the idle and absolute limits.
func setSessionCookie(w http.ResponseWriter, token string) { setCookie(w, sessionCookie, token, 0) }
func clearSessionCookie(w http.ResponseWriter)             { setCookie(w, sessionCookie, "", -1) }
func setSetupCookie(w http.ResponseWriter, token string)   { setCookie(w, setupCookie, token, 0) }
func clearSetupCookie(w http.ResponseWriter)               { setCookie(w, setupCookie, "", -1) }

// pathUUID parses a UUID path parameter.
func pathUUID(r *http.Request, name string) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue(name))
	return id, err == nil
}

// clientIP returns the caller's address. X-Forwarded-For is honoured only when
// the direct peer is a configured trusted proxy; then the right-most address
// that is not itself a trusted proxy wins (SEC-021).
func clientIP(r *http.Request, trusted []netip.Prefix) netip.Addr {
	peer := parseHostAddr(r.RemoteAddr)
	if !peer.IsValid() || !isTrusted(peer, trusted) {
		return peer
	}
	// Every header line counts: a proxy may add its own line instead of
	// appending, and a client-supplied first line must not win.
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for _, hop := range slices.Backward(hops) {
		a, err := netip.ParseAddr(strings.TrimSpace(hop))
		if err != nil {
			return peer
		}
		a = a.Unmap()
		if !isTrusted(a, trusted) {
			return a
		}
	}
	return peer
}

func parseHostAddr(remote string) netip.Addr {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap()
}

func isTrusted(a netip.Addr, trusted []netip.Prefix) bool {
	for _, p := range trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// decodeExact is decodeLimit for the bodies that carry key material (uploads, signing request
// completions): the body is read into a buffer the handler owns and clears, its top level must be
// one object whose keys are exactly the documented names, each at most once (encoding/json alone
// matches keys in any case and lets a repeated key win), and it is then decoded strictly.
func (s *server) decodeExact(w http.ResponseWriter, r *http.Request, dst any, limit int64, keys ...string) bool {
	if r.ContentLength > limit {
		s.writeError(w, r, ErrBodyTooLarge)
		return false
	}
	buf, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	defer clear(buf)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			s.writeError(w, r, ErrBodyTooLarge)
		} else {
			s.writeError(w, r, ErrBadRequest)
		}
		return false
	}
	if !exactTopLevelKeys(buf, keys) {
		s.writeError(w, r, ErrBadRequest)
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(buf))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		s.writeError(w, r, ErrBadRequest)
		return false
	}
	if _, tail := dec.Token(); !errors.Is(tail, io.EOF) {
		s.writeError(w, r, ErrBadRequest)
		return false
	}
	return true
}

// exactTopLevelKeys reports whether buf is one JSON object whose keys are among allowed, matched
// exactly, none twice. Values are skipped token by token (never copied into a value Alice keeps).
func exactTopLevelKeys(buf []byte, allowed []string) bool {
	dec := json.NewDecoder(bytes.NewReader(buf))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return false
	}
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		key, ok := tok.(string)
		if err != nil || !ok || seen[key] || !slices.Contains(allowed, key) {
			return false
		}
		seen[key] = true
		if !skipValue(dec) {
			return false
		}
	}
	tok, err := dec.Token()
	return err == nil && tok == json.Delim('}')
}

// skipValue reads one JSON value from dec.
func skipValue(dec *json.Decoder) bool {
	depth := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			return false
		}
		switch tok {
		case json.Delim('{'), json.Delim('['):
			depth++
		case json.Delim('}'), json.Delim(']'):
			depth--
		}
		if depth == 0 {
			return true
		}
	}
}
