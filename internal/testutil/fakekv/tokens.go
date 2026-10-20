package fakekv

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

var b64url = base64.RawURLEncoding

// tokenSkew is the clock skew the vault tolerates before a token's nbf, as Entra-protected services do
// (GUESS: five minutes, the usual JWT validation default). Without it a wall clock stepped back by a
// fraction of a second (a CI runner's time sync) made a token issued a moment earlier "not yet valid",
// and a request that should have waited in a latency or hold was answered 401 at once.
const tokenSkew = 5 * time.Minute

type issuedToken struct {
	aud       string
	nbf, exp  time.Time
	fromTests bool
}

// issueToken builds an access token at run time: a JWT-shaped string (header.claims.random-signature)
// with the claims of an Entra v1 access token for a service principal. The signature is random: the
// fake vault accepts only tokens it issued, and nothing in Alice may verify or rely on the signature
// (GUESS: real tokens are RS256-signed; Alice decodes only the oid and tid claims).
func (s *Server) issueToken(aud string, test bool) (token string, nbf, exp time.Time) {
	now := s.o.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	exp = now.Add(s.tokenLife)
	claims, _ := json.Marshal(map[string]any{
		"aud": aud, "iss": "https://sts.windows.net/" + s.tid + "/", "iat": now.Unix(), "nbf": now.Unix(),
		"exp": exp.Unix(), "appid": s.o.ClientID, "appidacr": "1", "idp": "https://sts.windows.net/" + s.tid + "/",
		"oid": s.oid, "sub": s.oid, "tid": s.tid, "ver": "1.0",
	})
	sig := make([]byte, 32)
	_, _ = rand.Read(sig)
	token = b64url.EncodeToString([]byte(`{"typ":"JWT","alg":"RS256"}`)) + "." + b64url.EncodeToString(claims) + "." + b64url.EncodeToString(sig)
	s.tokens[token] = issuedToken{aud: aud, nbf: now, exp: exp, fromTests: test}
	if !test {
		s.lastToken = token
	}
	return token, now, exp
}

// SetTokenClaims sets the oid and tid claims of the tokens issued from now on; the values need not
// be GUIDs (ruling S13: Alice must store them only when they are).
func (s *Server) SetTokenClaims(oid, tid string) {
	s.mu.Lock()
	s.oid, s.tid = oid, tid
	s.mu.Unlock()
}

// SetTokenLifetime changes the lifetime of the tokens issued from now on.
func (s *Server) SetTokenLifetime(d time.Duration) { s.mu.Lock(); s.tokenLife = d; s.mu.Unlock() }

// testBearer returns a valid token for TestClient (not reported by LastAccessToken). A cached one is
// replaced when it expired on the test clock.
func (s *Server) testBearer() string {
	s.mu.Lock()
	tok := s.testToken
	t, ok := s.tokens[tok]
	s.mu.Unlock()
	if ok && s.o.Now().Before(t.exp) {
		return tok
	}
	tok, _, _ = s.issueToken(vaultResource, true)
	s.mu.Lock()
	s.testToken = tok
	s.mu.Unlock()
	return tok
}

// tokenState classifies the bearer token of a request.
type tokenState int

const (
	tokenMissing tokenState = iota
	tokenUnknown
	tokenExpired
	tokenWrongAudience
	tokenOK
)

func (s *Server) checkToken(r *http.Request) tokenState {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || tok == "" {
		return tokenMissing
	}
	s.mu.Lock()
	t, known := s.tokens[tok]
	s.mu.Unlock()
	now := s.o.Now()
	switch {
	case !known:
		return tokenUnknown
	case !now.Before(t.exp) || now.Add(tokenSkew).Before(t.nbf):
		return tokenExpired
	case t.aud != vaultResource:
		return tokenWrongAudience
	}
	return tokenOK
}
