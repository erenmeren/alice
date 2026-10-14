package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
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
	if err := readJSON(w, r, dst, limit, optional); err != nil {
		s.refuseBody(w, r, err)
		return false
	}
	return true
}

// readJSON is decodeBody without the answer: errTooLarge, errUnstorableText (AUD-13) or another
// error for a malformed body. The size cap wins: a declared length over limit is refused unread,
// nothing past limit is ever read, and a body over the cap is errTooLarge even when it holds the NUL
// escape; then the text check on the bytes as they are read; then the DTO. A body within the cap
// holding the NUL escape is refused as such even when it is malformed otherwise.
func readJSON(w http.ResponseWriter, r *http.Request, dst any, limit int64, optional bool) error {
	if r.ContentLength > limit {
		return errTooLarge // declared too large: refused unread
	}
	text := &textCheck{r: http.MaxBytesReader(w, r.Body, limit)}
	dec := json.NewDecoder(text)
	dec.DisallowUnknownFields()
	err := dec.Decode(dst)
	if optional && errors.Is(err, io.EOF) {
		return nil // no JSON value at all
	}
	if err == nil {
		if _, tail := dec.Token(); !errors.Is(tail, io.EOF) {
			err = errors.New("trailing data after JSON value")
		}
	}
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge):
		return errTooLarge
	case text.refusal() != nil:
		return text.refusal() // errTooLarge when the body is also over the cap
	case err != nil:
		return fmt.Errorf("api: malformed body: %w", err)
	}
	return nil
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
	// Stored in sessions and audit rows: only text PostgreSQL can store (AUD-13; net/http already
	// refuses control characters in header values, NUL included).
	ua := strings.ReplaceAll(strings.ToValidUTF8(r.Header.Get("User-Agent"), ""), "\x00", "")
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

// issueSessionCookie sets a session cookie this server just created and remembers it as valid,
// so its holder passes the failed-credential limit at once (AUD-16).
func (s *server) issueSessionCookie(w http.ResponseWriter, token string) {
	setSessionCookie(w, token)
	s.recent.Add(token)
}

// issueSetupCookie is issueSessionCookie for the setup wizard's cookie.
func (s *server) issueSetupCookie(w http.ResponseWriter, token string) {
	setSetupCookie(w, token)
	s.recent.Add(token)
}

// pathFingerprint reads a certificate's SHA-256 fingerprint path parameter: 64 lower-case hex digits.
func pathFingerprint(r *http.Request, name string) (string, bool) {
	fp := r.PathValue(name)
	return fp, fingerprintRE.MatchString(fp)
}

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
// matches keys in any case and lets a repeated key win), checked while the keys are scanned
// (scanKeys stops at the first key that is not allowed or repeats, and allocates only a key that
// has an escape in it); json.Unmarshal then decodes in place. The buffer is cleared on every path.
// What cannot be cleared: the strings of dst (Go strings are immutable), the temporary slice
// encoding/json makes to unescape each string value with an escape in it (a PEM's \n line breaks
// included), the bytes net/http and TLS buffered on the way in, and the copies the service makes.
func (s *server) decodeExact(w http.ResponseWriter, r *http.Request, dst any, limit int64, keys ...string) bool {
	return s.decodeExactBody(w, r, dst, limit, false, keys...)
}

// decodeExactOptional is decodeExact for a body that may be absent: an empty body leaves dst unchanged; any
// other body must meet decodeExact's rules (keys exactly as documented, each once).
func (s *server) decodeExactOptional(w http.ResponseWriter, r *http.Request, dst any, limit int64, keys ...string) bool {
	return s.decodeExactBody(w, r, dst, limit, true, keys...)
}

func (s *server) decodeExactBody(w http.ResponseWriter, r *http.Request, dst any, limit int64, optional bool, keys ...string) bool {
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
	if optional && len(bytes.TrimSpace(buf)) == 0 {
		return true
	}
	if hasNULEscape(buf) {
		s.refuseBody(w, r, errUnstorableText) // AUD-13: after the size cap, before the keys and the DTO
		return false
	}
	_, ok := scanKeys(buf, func(k []byte, earlier []string) (string, bool) { return exactKey(k, keys, earlier) })
	if !ok || json.Unmarshal(buf, dst) != nil {
		s.writeError(w, r, ErrBadRequest)
		return false
	}
	return true
}

// exactKey reads one raw key (its JSON string, quotes included) and reports it when it is one of
// allowed, exactly, and not among earlier. A key without an escape is compared as it stands (the
// allowed keys are plain ASCII), so a junk key is refused without being unescaped or copied.
func exactKey(raw []byte, allowed, earlier []string) (string, bool) {
	inner := raw[1 : len(raw)-1]
	k, found := "", false
	if bytes.IndexByte(inner, '\\') < 0 {
		for _, a := range allowed {
			if a == string(inner) { // compared without a copy
				k, found = a, true
				break
			}
		}
	} else {
		k, found = unescapedKey(raw, allowed)
	}
	return k, found && !slices.Contains(earlier, k)
}

// unescapedKey reads a raw key with an escape as encoding/json does and reports it when allowed.
func unescapedKey(raw []byte, allowed []string) (string, bool) {
	var k string
	if json.Unmarshal(raw, &k) != nil || !slices.Contains(allowed, k) {
		return "", false
	}
	return k, true
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
	return scanKeys(b, func(raw []byte, _ []string) (string, bool) {
		var k string
		return k, json.Unmarshal(raw, &k) == nil
	})
}

// scanKeys is topLevelKeys with key reads the caller decides: key gets each raw key (its JSON
// string, quotes included) and the keys before it, and returns the key or false to stop the scan
// (ok=false).
func scanKeys(b []byte, key func(raw []byte, earlier []string) (string, bool)) ([]string, bool) {
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
		k, ok := key(b[i:end], keys)
		if !ok {
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

// oidcCookie binds a single sign-on to the browser that started it (SEC-011).
const oidcCookie = "__Host-alice_oidc"

// setBindingCookie stores the sign-in's binding value for 10 minutes. SameSite=Lax (not Strict): the identity
// provider's redirect back to Alice is a cross-site top-level navigation, on which only Lax cookies are sent; the
// value alone is useless — the state row holds only its SHA-256 and is single use (SEC-011).
func setBindingCookie(w http.ResponseWriter, value string) {
	http.SetCookie(w, &http.Cookie{Name: oidcCookie, Value: value, Path: "/", MaxAge: 600, Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode})
}

// clearBindingCookie deletes the binding cookie (every callback, whatever its outcome).
func clearBindingCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: oidcCookie, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode})
}

// withQuery adds key=value to the query of a path that claims.SafeNext already made safe, before a fragment (S-13).
func withQuery(path, key, value string) string {
	frag := ""
	if i := strings.IndexByte(path, '#'); i >= 0 {
		path, frag = path[:i], path[i:]
	}
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	return path + sep + url.QueryEscape(key) + "=" + url.QueryEscape(value) + frag
}
