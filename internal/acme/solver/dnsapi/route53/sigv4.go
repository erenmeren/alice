package route53

// AWS Signature Version 4, the part of it Route 53 and STS need: a request signed in the Authorization header with
// an access key (and a session token for temporary credentials). There is no SDK in Alice's module, so this is the
// whole implementation; sigv4_test.go checks it against the vectors of the AWS SigV4 test suite and the fake
// (internal/testutil/fakeroute53) verifies every request with an independent implementation.
//
// The canonical request is
//
//	method \n canonical URI \n canonical query \n canonical headers \n signed headers \n hex(SHA-256(payload))
//
// Canonical URI: every segment of the request's escaped path is URI-encoded once more (RFC 3986: A-Z a-z 0-9 - _
// . ~ stay, every other byte becomes %XX in upper-case hex). That is AWS's rule for every service except S3 (the
// "double encoding" the AWS SDKs and botocore apply); the paths this package builds hold unreserved characters and
// "/" only, so the second encoding never changes them. The path is not normalised ("." and ".." segments are never
// built). An empty path is "/".
//
// Canonical query: every name and value decoded, then URI-encoded as above, sorted by name and then by value, joined
// as name=value with "&".
//
// Canonical headers: the signed header names in lower case, sorted, each "name:value\n" with the value's leading and
// trailing spaces removed and inner runs of spaces collapsed to one; several values of one header are joined with
// ",". Host is the request's host. This package signs host, x-amz-date, content-type when the request has a body and
// x-amz-security-token when the credentials carry one: the minimum AWS accepts plus everything that changes what the
// request means.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"alice/internal/acme/solver"
	"alice/internal/secrets"
)

const (
	sigAlgorithm  = "AWS4-HMAC-SHA256"
	amzDateLayout = "20060102T150405Z"
	scopeLayout   = "20060102"
	scopeTerm     = "aws4_request"
)

// credentials is one signing identity: the long-term access key, or the temporary credentials of an assumed role
// (which carry a session token). The secret and the token are the provider's own copies.
type credentials struct {
	keyID  string
	secret secrets.Plaintext
	token  secrets.Plaintext // empty for the long-term key
}

// sign stamps req with X-Amz-Date (now, UTC) and, for temporary credentials, X-Amz-Security-Token, then adds the
// Authorization header. body is the exact payload req sends.
func sign(req *http.Request, body []byte, c credentials, region, service string, now time.Time) {
	req.Header.Set("X-Amz-Date", now.UTC().Format(amzDateLayout))
	names := []string{"host", "x-amz-date"}
	if req.Header.Get("Content-Type") != "" {
		names = append(names, "content-type")
	}
	if tok := c.token.Bytes(); len(tok) > 0 {
		req.Header.Set("X-Amz-Security-Token", string(tok))
		names = append(names, "x-amz-security-token")
	}
	req.Header.Set("Authorization", authorization(req, body, c.keyID, c.secret.Bytes(), region, service, names))
}

// authorization computes the Authorization header of req for the headers named (lower case), from the X-Amz-Date
// header req already carries. It is the test vectors' entry point.
func authorization(req *http.Request, body []byte, keyID string, secret []byte, region, service string, names []string) string {
	amzDate := req.Header.Get("X-Amz-Date")
	day := amzDate
	if len(day) > len(scopeLayout) {
		day = day[:len(scopeLayout)]
	}
	scope := day + "/" + region + "/" + service + "/" + scopeTerm
	signed, canonHeaders := canonicalHeaders(req, names)
	payload := sha256.Sum256(body)
	canon := req.Method + "\n" + canonicalURI(req.URL.EscapedPath()) + "\n" + canonicalQuery(req.URL.RawQuery) + "\n" +
		canonHeaders + "\n" + signed + "\n" + hex.EncodeToString(payload[:])
	creq := sha256.Sum256([]byte(canon))
	toSign := sigAlgorithm + "\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(creq[:])

	key := signingKey(secret, day, region, service)
	sig := hmacSHA256(key, []byte(toSign))
	clear(key)
	return sigAlgorithm + " Credential=" + keyID + "/" + scope + ", SignedHeaders=" + signed + ", Signature=" + hex.EncodeToString(sig)
}

// signingKey is the derived key chain: HMAC("AWS4"+secret, day) -> region -> service -> "aws4_request". The
// intermediate keys are cleared; the caller clears the result.
func signingKey(secret []byte, day, region, service string) []byte {
	seed := make([]byte, 0, 4+len(secret))
	seed = append(append(seed, "AWS4"...), secret...)
	k := hmacSHA256(seed, []byte(day))
	clear(seed)
	for _, part := range []string{region, service, scopeTerm} {
		next := hmacSHA256(k, []byte(part))
		clear(k)
		k = next
	}
	return k
}

func hmacSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

// canonicalURI encodes every segment of the escaped path once more (the package comment).
func canonicalURI(escapedPath string) string {
	if escapedPath == "" {
		return "/"
	}
	segs := strings.Split(escapedPath, "/")
	for i, s := range segs {
		segs[i] = uriEncode(s)
	}
	return strings.Join(segs, "/")
}

// canonicalQuery is the sorted, re-encoded query (the package comment). A pair that does not decode is used as
// it stands: the provider never builds one, and the server would then see the same bytes.
func canonicalQuery(raw string) string {
	if raw == "" {
		return ""
	}
	type pair struct{ k, v string }
	var pairs []pair
	for _, part := range strings.Split(raw, "&") {
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		pairs = append(pairs, pair{uriEncode(unescape(k)), uriEncode(unescape(v))})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].k != pairs[j].k {
			return pairs[i].k < pairs[j].k
		}
		return pairs[i].v < pairs[j].v
	})
	out := make([]string, len(pairs))
	for i, p := range pairs {
		out[i] = p.k + "=" + p.v
	}
	return strings.Join(out, "&")
}

func unescape(s string) string {
	if u, err := url.QueryUnescape(s); err == nil {
		return u
	}
	return s
}

// canonicalHeaders returns the signed-headers list and the canonical header block of names.
func canonicalHeaders(req *http.Request, names []string) (signed, block string) {
	lower := make([]string, 0, len(names))
	for _, n := range names {
		lower = append(lower, solver.ASCIILower(n))
	}
	sort.Strings(lower)
	var b strings.Builder
	for _, n := range lower {
		var vals []string
		if n == "host" {
			h := req.Host
			if h == "" {
				h = req.URL.Host
			}
			vals = []string{h}
		} else {
			vals = req.Header.Values(n)
		}
		for i, v := range vals {
			vals[i] = collapseSpaces(v)
		}
		b.WriteString(n)
		b.WriteByte(':')
		b.WriteString(strings.Join(vals, ","))
		b.WriteByte('\n')
	}
	return strings.Join(lower, ";"), b.String()
}

// collapseSpaces trims a header value and folds every inner run of spaces into one.
func collapseSpaces(v string) string {
	return strings.Join(strings.Fields(v), " ")
}

const upperHex = "0123456789ABCDEF"

// uriEncode is AWS's UriEncode: unreserved characters stay, every other byte is %XX in upper-case hex.
func uriEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if unreserved(c) {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(upperHex[c>>4])
		b.WriteByte(upperHex[c&15])
	}
	return b.String()
}

func unreserved(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~'
}
