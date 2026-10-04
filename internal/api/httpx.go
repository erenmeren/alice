package api

import (
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
// completions) and for the Phase 4 changes whose fields decide what happens (deploy requests,
// signing request creation, location settings): a repeated or case-variant key is refused instead of
// letting one of the values win silently. The body is read into one buffer (readBounded: a single allocation when the length
// is declared; otherwise every outgrown array is cleared before it is dropped), its top level must
// be one object whose keys are exactly the documented names, each at most once (encoding/json alone
// matches keys in any case and lets a repeated key win), checked by topLevelKeys, which allocates
// the keys only; json.Unmarshal then decodes in place. The buffer is cleared on every path. What
// cannot be cleared: the strings of dst (Go strings are immutable), the bytes net/http and TLS
// buffered on the way in, and the copies the service makes.
func (s *server) decodeExact(w http.ResponseWriter, r *http.Request, dst any, limit int64, keys ...string) bool {
	if r.ContentLength > limit {
		s.writeError(w, r, ErrBodyTooLarge)
		return false
	}
	buf, err := readBounded(r.Body, r.ContentLength, limit)
	defer clear(buf)
	switch {
	case errors.Is(err, errTooLarge):
		s.writeError(w, r, ErrBodyTooLarge)
		return false
	case err != nil:
		s.writeError(w, r, ErrBadRequest)
		return false
	}
	got, ok := topLevelKeys(buf)
	if !ok || !exactKeys(got, keys) || json.Unmarshal(buf, dst) != nil {
		s.writeError(w, r, ErrBadRequest)
		return false
	}
	return true
}

// exactKeys reports whether every key is allowed (exactly) and none repeats.
func exactKeys(got, allowed []string) bool {
	for i, k := range got {
		if !slices.Contains(allowed, k) || slices.Contains(got[:i], k) {
			return false
		}
	}
	return true
}

// errTooLarge: a body is larger than its route allows.
var errTooLarge = errors.New("api: body too large")

// readBounded reads body into a single buffer of at most limit bytes. contentLength >= 0 is the
// declared length (one allocation of that size plus one byte, to see a longer body); -1 grows the
// buffer, clearing each array it outgrows.
func readBounded(body io.Reader, contentLength, limit int64) ([]byte, error) {
	return readBoundedObserved(body, contentLength, limit, nil)
}

// readBoundedObserved is readBounded with a hook that sees each outgrown array after it was cleared
// (tests).
func readBoundedObserved(body io.Reader, contentLength, limit int64, dropped func([]byte)) ([]byte, error) {
	size := int64(4 << 10)
	if contentLength >= 0 {
		size = contentLength + 1
	}
	buf := make([]byte, 0, min(size, limit+1))
	fail := func(err error) ([]byte, error) {
		clear(buf[:cap(buf)])
		return nil, err
	}
	for {
		if len(buf) == cap(buf) {
			if int64(cap(buf)) > limit {
				return fail(errTooLarge)
			}
			grown := make([]byte, len(buf), min(2*int64(cap(buf)), limit+1))
			copy(grown, buf)
			old := buf[:cap(buf)]
			clear(old)
			if dropped != nil {
				dropped(old)
			}
			buf = grown
		}
		n, err := body.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]
		switch {
		case int64(len(buf)) > limit:
			return fail(errTooLarge)
		case contentLength >= 0 && int64(len(buf)) > contentLength:
			return fail(errors.New("api: body longer than declared"))
		case errors.Is(err, io.EOF):
			return buf, nil
		case err != nil:
			return fail(err)
		}
	}
}

// maxJSONDepth bounds the nesting topLevelKeys accepts in a value (the documented bodies hold
// strings only).
const maxJSONDepth = 32

// topLevelKeys returns the keys of the one JSON object in b, in order and repeats included, or
// ok=false when b is not exactly one object (whitespace around it allowed). Values are skipped in
// place without being copied; only the keys are unescaped (json.Unmarshal of the key's bytes, so
// escapes and invalid UTF-8 read as encoding/json reads them). json.Unmarshal validates the rest.
func topLevelKeys(b []byte) ([]string, bool) {
	i := skipSpace(b, 0)
	if i >= len(b) || b[i] != '{' {
		return nil, false
	}
	keys := []string{}
	i = skipSpace(b, i+1)
	if i < len(b) && b[i] == '}' {
		return keys, skipSpace(b, i+1) == len(b)
	}
	for {
		end := skipJSONString(b, i)
		if end < 0 {
			return nil, false
		}
		var k string
		if json.Unmarshal(b[i:end], &k) != nil {
			return nil, false
		}
		keys = append(keys, k)
		i = skipSpace(b, end)
		if i >= len(b) || b[i] != ':' {
			return nil, false
		}
		if i = skipJSONValue(b, skipSpace(b, i+1), 1); i < 0 {
			return nil, false
		}
		i = skipSpace(b, i)
		switch {
		case i < len(b) && b[i] == ',':
			i = skipSpace(b, i+1)
		case i < len(b) && b[i] == '}':
			return keys, skipSpace(b, i+1) == len(b)
		default:
			return nil, false
		}
	}
}

func skipSpace(b []byte, i int) int {
	for i < len(b) && (b[i] == ' ' || b[i] == '\t' || b[i] == '\n' || b[i] == '\r') {
		i++
	}
	return i
}

// skipJSONString returns the index after the string starting at b[i], or -1.
func skipJSONString(b []byte, i int) int {
	if i >= len(b) || b[i] != '"' {
		return -1
	}
	for i++; i < len(b); i++ {
		switch c := b[i]; {
		case c == '\\':
			i++ // the escaped byte (json.Unmarshal checks the escape itself)
		case c == '"':
			return i + 1
		case c < 0x20:
			return -1
		}
	}
	return -1
}

// skipJSONValue returns the index after the value starting at b[i], or -1; depth counts the
// containers around it.
func skipJSONValue(b []byte, i, depth int) int {
	if i >= len(b) || depth > maxJSONDepth {
		return -1
	}
	switch b[i] {
	case '"':
		return skipJSONString(b, i)
	case '{', '[':
		closing := byte('}')
		if b[i] == '[' {
			closing = ']'
		}
		i = skipSpace(b, i+1)
		if i < len(b) && b[i] == closing {
			return i + 1
		}
		for {
			if closing == '}' {
				if i = skipJSONString(b, i); i < 0 {
					return -1
				}
				if i = skipSpace(b, i); i >= len(b) || b[i] != ':' {
					return -1
				}
				i = skipSpace(b, i+1)
			}
			if i = skipJSONValue(b, i, depth+1); i < 0 {
				return -1
			}
			i = skipSpace(b, i)
			switch {
			case i < len(b) && b[i] == ',':
				i = skipSpace(b, i+1)
			case i < len(b) && b[i] == closing:
				return i + 1
			default:
				return -1
			}
		}
	default:
		start := i
		for i < len(b) && strings.IndexByte("-+.0123456789eEtrufalsn", b[i]) >= 0 {
			i++
		}
		if i == start {
			return -1
		}
		return i
	}
}
