package fakeroute53

// The fake's own SigV4 verifier. It is written apart from the provider's signer on purpose (different structure,
// url.Values and bytes.Buffer, its own encoder): a mistake shared by both would make every test pass against a fake
// that AWS would refuse. The rules are AWS's for every service but S3: each segment of the escaped path is
// URI-encoded once more, the query is decoded, re-encoded and sorted, header values are trimmed with inner spaces
// collapsed.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// signer is who signed a verified request.
type signer struct {
	keyID string
	temp  bool // temporary credentials of the role
}

// authError is a refusal with AWS's status and code.
type authError struct {
	status int
	code   string
}

// verify checks the Authorization header of r against the credentials the fake knows, for service.
func (s *Server) verify(r *http.Request, body []byte, service string) (signer, *authError) {
	deny := func(code string) (signer, *authError) {
		return signer{}, &authError{status: http.StatusForbidden, code: code}
	}
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return deny("MissingAuthenticationToken")
	}
	rest, ok := strings.CutPrefix(auth, "AWS4-HMAC-SHA256 ")
	if !ok {
		return deny("IncompleteSignature")
	}
	fields := map[string]string{}
	for _, part := range strings.Split(rest, ",") {
		k, v, found := strings.Cut(strings.TrimSpace(part), "=")
		if !found {
			return deny("IncompleteSignature")
		}
		fields[k] = v
	}
	cred, signedList, sig := fields["Credential"], fields["SignedHeaders"], fields["Signature"]
	scope := strings.Split(cred, "/")
	if len(scope) != 5 || signedList == "" || sig == "" {
		return deny("IncompleteSignature")
	}
	keyID, day, region, svc, term := scope[0], scope[1], scope[2], scope[3], scope[4]

	secret, who, refused := s.secretFor(keyID, r.Header.Get("X-Amz-Security-Token"))
	if refused != "" {
		return deny(refused)
	}
	amzDate := r.Header.Get("X-Amz-Date")
	t, err := time.Parse("20060102T150405Z", amzDate)
	if err != nil {
		return deny("IncompleteSignature")
	}
	if d := s.now().Sub(t); d > MaxClockSkew || d < -MaxClockSkew {
		return deny("SignatureDoesNotMatch") // AWS: "Signature expired"
	}
	if day != amzDate[:8] || region != Region || svc != service || term != "aws4_request" {
		return deny("SignatureDoesNotMatch")
	}
	signed := strings.Split(signedList, ";")
	if !sort.StringsAreSorted(signed) || !contains(signed, "host") || !contains(signed, "x-amz-date") ||
		(who.temp && !contains(signed, "x-amz-security-token")) {
		return deny("SignatureDoesNotMatch")
	}

	want := expectedSignature(r, body, signed, amzDate, scope[1:], secret)
	if !hmac.Equal([]byte(want), []byte(sig)) {
		return deny("SignatureDoesNotMatch")
	}
	s.mu.Lock()
	s.lastSig = sig
	s.mu.Unlock()
	return who, nil
}

// expectedSignature recomputes the hex signature of r for the signed header names (sorted, lower case), the
// X-Amz-Date value and the scope [day, region, service, "aws4_request"].
func expectedSignature(r *http.Request, body []byte, signed []string, amzDate string, scope []string, secret string) string {
	var creq bytes.Buffer
	creq.WriteString(r.Method + "\n")
	creq.WriteString(fakeCanonicalPath(r.URL.EscapedPath()) + "\n")
	creq.WriteString(fakeCanonicalQuery(r.URL.Query()) + "\n")
	for _, h := range signed {
		var vals []string
		if h == "host" {
			vals = []string{r.Host}
		} else {
			for _, v := range r.Header.Values(h) { // a copy: Values is the header's own slice
				vals = append(vals, strings.Join(strings.Fields(v), " "))
			}
		}
		fmt.Fprintf(&creq, "%s:%s\n", h, strings.Join(vals, ","))
	}
	creq.WriteString("\n" + strings.Join(signed, ";") + "\n")
	ph := sha256.Sum256(body)
	creq.WriteString(hex.EncodeToString(ph[:]))

	ch := sha256.Sum256(creq.Bytes())
	sts := strings.Join([]string{"AWS4-HMAC-SHA256", amzDate, strings.Join(scope, "/"), hex.EncodeToString(ch[:])}, "\n")
	k := []byte("AWS4" + secret)
	for _, part := range scope {
		k = mac(k, part)
	}
	return hex.EncodeToString(mac(k, sts))
}

// secretFor finds the secret of keyID: the long-term key, or issued temporary credentials whose session token
// matches and has not expired. It returns AWS's refusal code otherwise.
func (s *Server) secretFor(keyID, token string) (string, signer, string) {
	if keyID == s.o.AccessKeyID {
		if token != "" {
			return "", signer{}, "InvalidClientTokenId" // a long-term key carries no session token
		}
		return s.o.SecretAccessKey, signer{keyID: keyID}, ""
	}
	s.mu.Lock()
	c, ok := s.temps[keyID]
	s.mu.Unlock()
	switch {
	case !ok || !hmac.Equal([]byte(token), []byte(c.SessionToken)):
		return "", signer{}, "InvalidClientTokenId"
	case !s.now().Before(c.Expiration):
		return "", signer{}, "ExpiredToken"
	}
	return c.SecretAccessKey, signer{keyID: keyID, temp: true}, ""
}

func mac(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

func fakeCanonicalPath(escaped string) string {
	if escaped == "" {
		return "/"
	}
	var out []string
	for _, seg := range strings.Split(escaped, "/") {
		out = append(out, awsEscape(seg))
	}
	return strings.Join(out, "/")
}

func fakeCanonicalQuery(q url.Values) string {
	var pairs []string
	for k, vs := range q {
		for _, v := range vs {
			pairs = append(pairs, awsEscape(k)+"="+awsEscape(v))
		}
	}
	// By name, then by value (not by the joined "k=v" text: "a-b=1" and "a=1" would sort the other way).
	sort.Slice(pairs, func(i, j int) bool {
		ki, vi, _ := strings.Cut(pairs[i], "=")
		kj, vj, _ := strings.Cut(pairs[j], "=")
		if ki != kj {
			return ki < kj
		}
		return vi < vj
	})
	return strings.Join(pairs, "&")
}

// awsEscape is url.PathEscape tightened to RFC 3986's unreserved set.
func awsEscape(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9', c == '-', c == '.', c == '_', c == '~':
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
