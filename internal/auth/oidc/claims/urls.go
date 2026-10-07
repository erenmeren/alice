package claims

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"strings"
	"unicode"
)

// ErrIssuer refuses an issuer (or endpoint) address.
var ErrIssuer = errors.New("claims: the issuer must be an https:// address without user name, query or fragment")

const maxNext = 2048

// SafeNext returns raw when it is a path inside Alice's web application, else "/". It refuses absolute and
// scheme-relative addresses, backslashes, white space and control characters, dot segments and API paths, in the
// raw and in the percent-decoded path (O-05).
func SafeNext(raw string) string {
	if raw == "" || len(raw) > maxNext || raw[0] != '/' || strings.HasPrefix(raw, "//") || strings.HasPrefix(raw, "/\\") ||
		raw == "/api" || strings.HasPrefix(raw, "/api/") || strings.ContainsRune(raw, '\\') ||
		strings.IndexFunc(raw, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }) >= 0 {
		return "/"
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || u.Opaque != "" {
		return "/"
	}
	dec, err := url.PathUnescape(u.EscapedPath())
	if err != nil || !safeDecodedPath(dec) {
		return "/"
	}
	return raw
}

// safeDecodedPath checks the percent-decoded path: no backslash or control character (%00, %09,
// …), not scheme-relative, no "." or ".." segment (a browser resolves "/..//evil.example" to
// "//evil.example"), and not an API path ("/%61pi/…").
func safeDecodedPath(dec string) bool {
	if strings.ContainsRune(dec, '\\') || strings.IndexFunc(dec, unicode.IsControl) >= 0 || strings.HasPrefix(dec, "//") ||
		dec == "/api" || strings.HasPrefix(dec, "/api/") {
		return false
	}
	for seg := range strings.SplitSeq(dec, "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// ValidateIssuer accepts https://host[:port][/path] of at most 500 bytes without user info, query or fragment
// (SEC-013, O-12). Endpoints from discovery are checked with it too.
func ValidateIssuer(raw string) error {
	if raw == "" || len(raw) > 500 || strings.IndexFunc(raw, unicode.IsSpace) >= 0 {
		return ErrIssuer
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		u.Opaque != "" || strings.HasSuffix(raw, "?") || strings.HasSuffix(raw, "#") {
		return ErrIssuer
	}
	return nil
}

const maxUsername = 64

// Username derives an Alice user name from the claims: preferred_username, upn or email (folded to lower-case
// ASCII; other characters dropped), else "sso-" and 12 hex digits of SHA-256(iss "\n" sub).
func Username(c Claims) string {
	for _, v := range []string{c.PreferredUsername, c.UPN, c.Email} {
		if u := cleanName(v); u != "" {
			return u
		}
	}
	sum := sha256.Sum256([]byte(c.Issuer + "\n" + c.Subject))
	return "sso-" + hex.EncodeToString(sum[:6])
}

func cleanName(v string) string {
	var b strings.Builder
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '_', r == '-', r == '@':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + ('a' - 'A'))
		}
	}
	s := strings.Trim(b.String(), ".-_@")
	if len(s) > maxUsername {
		s = strings.TrimRight(s[:maxUsername], ".-_@")
	}
	return s
}
