package fakeidp

import (
	"crypto"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const redirect = "https://alice.example.test/api/v1/auth/oidc/p1/callback"

func authorizeURL(s *Server, challenge string) string {
	q := url.Values{"response_type": {"code"}, "client_id": {s.ClientID()}, "redirect_uri": {redirect}, "scope": {"openid email"},
		"state": {"st"}, "nonce": {"no"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}
	return s.Issuer() + "/authorize?" + q.Encode()
}

func challengeOf(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func exchange(t *testing.T, s *Server, code, verifier string) (int, map[string]any) {
	t.Helper()
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect}, "code_verifier": {verifier}}
	req, err := http.NewRequest(http.MethodPost, s.Issuer()+"/token", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(s.ClientID()), url.QueryEscape(s.ClientSecret()))
	res, err := s.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = res.Body.Close() }()
	var body map[string]any
	b, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(b, &body))
	return res.StatusCode, body
}

func login(t *testing.T, s *Server, verifier string) (int, map[string]any) {
	t.Helper()
	cb, err := s.Authorize(authorizeURL(s, challengeOf(verifier)))
	require.NoError(t, err)
	u, err := url.Parse(cb)
	require.NoError(t, err)
	require.Equal(t, "st", u.Query().Get("state"))
	return exchange(t, s, u.Query().Get("code"), verifier)
}

func decode(t *testing.T, part string, dst any) {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(part)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(b, dst))
}

func verifyRS256(t *testing.T, s *Server, token string) map[string]any {
	t.Helper()
	claims, err := verifyRS256Err(t, s, token)
	require.NoError(t, err)
	return claims
}

func signatureErr(t *testing.T, s *Server, token string) error {
	t.Helper()
	_, err := verifyRS256Err(t, s, token)
	return err
}

func verifyRS256Err(t *testing.T, s *Server, token string) (map[string]any, error) {
	t.Helper()
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)
	var hdr struct{ Alg, Kid string }
	decode(t, parts[0], &hdr)
	require.Equal(t, "RS256", hdr.Alg)
	res, err := s.Client().Get(s.Issuer() + "/jwks")
	require.NoError(t, err)
	defer func() { _ = res.Body.Close() }()
	var set struct{ Keys []struct{ Kid, N, E string } }
	require.NoError(t, json.NewDecoder(res.Body).Decode(&set))
	for _, k := range set.Keys {
		if k.Kid != hdr.Kid {
			continue
		}
		n, _ := base64.RawURLEncoding.DecodeString(k.N)
		e, _ := base64.RawURLEncoding.DecodeString(k.E)
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
		sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
			return nil, err
		}
		var claims map[string]any
		decode(t, parts[1], &claims)
		return claims, nil
	}
	return nil, fmt.Errorf("kid %s not in the JWKS", hdr.Kid)
}

func start(t *testing.T) (*Server, *time.Time) {
	now := time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)
	s := Start(t, Options{Now: func() time.Time { return now }})
	s.RegisterRedirect(redirect)
	return s, &now
}

func TestDiscoveryAndAGoodLogin(t *testing.T) {
	s, now := start(t)
	res, err := s.Client().Get(s.Issuer() + "/.well-known/openid-configuration")
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, json.NewDecoder(res.Body).Decode(&doc))
	_ = res.Body.Close()
	assert.Equal(t, s.Issuer(), doc["issuer"])
	assert.Equal(t, s.Issuer()+"/jwks", doc["jwks_uri"])
	assert.True(t, strings.HasPrefix(s.Issuer(), "https://127.0.0.1:"))

	s.NextLogin(Login{Subject: "u-1", Username: "ada", Email: "ada@example.com", Groups: []string{"ops"}})
	status, body := login(t, s, strings.Repeat("v", 43))
	require.Equal(t, http.StatusOK, status, body)
	claims := verifyRS256(t, s, body["id_token"].(string))
	assert.Equal(t, s.Issuer(), claims["iss"])
	assert.Equal(t, s.ClientID(), claims["aud"])
	assert.Equal(t, "u-1", claims["sub"])
	assert.Equal(t, "no", claims["nonce"])
	assert.Equal(t, []any{"ops"}, claims["groups"])
	assert.Equal(t, float64(now.Add(5*time.Minute).Unix()), claims["exp"])
	assert.Equal(t, "code_verifier", firstKey(s.LastTokenForm(), "code_verifier"))
	st := s.Stats()
	assert.Equal(t, 1, st.Authorize)
	assert.Equal(t, 1, st.Token)
}

func firstKey(v url.Values, k string) string {
	if _, ok := v[k]; ok {
		return k
	}
	return ""
}

func TestPKCEAndSingleUseCodes(t *testing.T) {
	s, _ := start(t)
	cb, err := s.Authorize(authorizeURL(s, challengeOf(strings.Repeat("v", 43))))
	require.NoError(t, err)
	u, _ := url.Parse(cb)
	code := u.Query().Get("code")
	status, _ := exchange(t, s, code, strings.Repeat("w", 43))
	assert.Equal(t, http.StatusBadRequest, status, "wrong verifier")
	status, _ = exchange(t, s, code, strings.Repeat("v", 43))
	assert.Equal(t, http.StatusOK, status)
	status, _ = exchange(t, s, code, strings.Repeat("v", 43))
	assert.Equal(t, http.StatusBadRequest, status, "a code is used once")
	s.SetFault(Fault{ReplayCode: true})
	status, _ = exchange(t, s, code, strings.Repeat("v", 43))
	assert.Equal(t, http.StatusOK, status, "the replay fault accepts a used code")
}

func TestAuthorizeRefusesUnknownRedirectsAndMissingPKCE(t *testing.T) {
	s, _ := start(t)
	bad := strings.Replace(authorizeURL(s, challengeOf("v")), url.QueryEscape(redirect), url.QueryEscape("https://evil.example/cb"), 1)
	_, err := s.Authorize(bad)
	assert.Error(t, err, "an unregistered redirect gets an error page, never a redirect")
	noPKCE := strings.Replace(authorizeURL(s, challengeOf("v")), "code_challenge_method=S256", "code_challenge_method=plain", 1)
	cb, err := s.Authorize(noPKCE)
	require.NoError(t, err)
	assert.Contains(t, cb, "error=invalid_request")
	s.SetFault(Fault{AuthorizeError: "access_denied"})
	cb, err = s.Authorize(authorizeURL(s, challengeOf("v")))
	require.NoError(t, err)
	assert.Contains(t, cb, "error=access_denied")
	assert.Contains(t, cb, "state=st")
}

func TestFaultsShapeTheToken(t *testing.T) {
	s, now := start(t)
	other := "other-nonce"
	s.SetFault(Fault{Issuer: "https://wrong", Audience: []string{"alice", "x"}, ExpIn: -time.Minute, IatOffset: 2 * time.Minute,
		NbfOffset: 3 * time.Minute, Nonce: &other, Overage: true, AuthTimeAgo: time.Hour, Azp: "x"})
	_, body := login(t, s, strings.Repeat("v", 43))
	claims := verifyRS256(t, s, body["id_token"].(string))
	assert.Equal(t, "https://wrong", claims["iss"])
	assert.Equal(t, []any{"alice", "x"}, claims["aud"])
	assert.Equal(t, float64(now.Add(-time.Minute).Unix()), claims["exp"])
	assert.Equal(t, float64(now.Add(2*time.Minute).Unix()), claims["iat"])
	assert.Equal(t, float64(now.Add(3*time.Minute).Unix()), claims["nbf"])
	assert.Equal(t, "other-nonce", claims["nonce"])
	assert.Equal(t, float64(now.Add(-time.Hour).Unix()), claims["auth_time"])
	assert.Equal(t, "x", claims["azp"])
	assert.Nil(t, claims["groups"])
	assert.NotNil(t, claims["_claim_names"])

	for _, f := range []Fault{{Alg: "none"}, {Alg: "HS256"}, {UnknownKid: true}, {OtherKey: true}} {
		s.SetFault(f)
		_, body := login(t, s, strings.Repeat("v", 43))
		parts := strings.Split(body["id_token"].(string), ".")
		var hdr struct{ Alg, Kid string }
		decode(t, parts[0], &hdr)
		switch {
		case f.Alg == "none":
			assert.Equal(t, "none", hdr.Alg)
			assert.Empty(t, parts[2])
		case f.Alg == "HS256":
			assert.Equal(t, "HS256", hdr.Alg)
		case f.UnknownKid:
			assert.Equal(t, "unknown", hdr.Kid)
		case f.OtherKey:
			assert.Equal(t, "RS256", hdr.Alg)
			assert.Equal(t, "k1", hdr.Kid)
			assert.Error(t, signatureErr(t, s, body["id_token"].(string)), "the signature does not verify")
		}
	}
}

func TestKeyRotationAndDown(t *testing.T) {
	s, _ := start(t)
	s.RotateKey()
	_, body := login(t, s, strings.Repeat("v", 43))
	verifyRS256(t, s, body["id_token"].(string)) // signed by the new key, found in the JWKS
	s.DropOldKeys()
	s.Down()
	res, err := s.Client().Get(s.Issuer() + "/jwks")
	require.NoError(t, err)
	_ = res.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, res.StatusCode)
	s.Up()
	res, err = s.Client().Get(s.Issuer() + "/jwks")
	require.NoError(t, err)
	_ = res.Body.Close()
	assert.Equal(t, http.StatusOK, res.StatusCode)
}

func TestPlainModeServesHTTP(t *testing.T) {
	s := Start(t, Options{Plain: true})
	assert.True(t, strings.HasPrefix(s.Issuer(), "http://127.0.0.1:"))
	assert.Nil(t, s.CAPEM())
}

func jwksResponse(t *testing.T, s *Server) (cache string, kids []string) {
	t.Helper()
	res, err := s.Client().Get(s.Issuer() + "/jwks")
	require.NoError(t, err)
	defer func() { _ = res.Body.Close() }()
	var set struct{ Keys []struct{ Kid string } }
	require.NoError(t, json.NewDecoder(res.Body).Decode(&set))
	for _, k := range set.Keys {
		kids = append(kids, k.Kid)
	}
	return res.Header.Get("Cache-Control"), kids
}

// S-2: the JWKS carries a Cache-Control max-age the test can set, and a key can be withdrawn or rotated.
func TestJWKSCacheHeaderAndWithdrawal(t *testing.T) {
	s, _ := start(t)
	cache, kids := jwksResponse(t, s)
	assert.Equal(t, "max-age=300", cache)
	assert.Equal(t, []string{"k1"}, kids)
	s.SetJWKSMaxAge(10 * time.Minute)
	cache, _ = jwksResponse(t, s)
	assert.Equal(t, "max-age=600", cache)
	s.SetJWKSMaxAge(-1)
	cache, _ = jwksResponse(t, s)
	assert.Empty(t, cache)

	s.RotateKey()
	s.DropOldKeys()
	s.RotateKey()
	assert.Equal(t, []string{"k2", "k3"}, s.Kids(), "a kid is never reused after DropOldKeys")
	assert.False(t, s.WithdrawKey("nope"))
	assert.True(t, s.WithdrawKey("k2"))
	_, kids = jwksResponse(t, s)
	assert.Equal(t, []string{"k3"}, kids)
	_, body := login(t, s, strings.Repeat("v", 43))
	verifyRS256(t, s, body["id_token"].(string))
	s.WithdrawKey("k3")
	status, body := login(t, s, strings.Repeat("v", 43))
	assert.Equal(t, http.StatusInternalServerError, status, "no signing key left: %v", body)
}

// S-1, S-7, S-11 and the O-suite: chosen auth_time, e-mail, subject, kid, extra claims and the hasgroups marker.
func TestChosenClaimsKidAndHasGroups(t *testing.T) {
	s, now := start(t)
	s.NextLogin(Login{Subject: "u-9", Email: "x@example.com", Groups: []string{"g"},
		Extra: map[string]any{"upn": "x@corp.example.com", "auth_time": now.Add(-90 * time.Second).Unix()}})
	_, body := login(t, s, strings.Repeat("v", 43))
	c := verifyRS256(t, s, body["id_token"].(string))
	assert.Equal(t, "x@corp.example.com", c["upn"])
	assert.Equal(t, "x@example.com", c["email"])
	assert.Equal(t, float64(now.Add(-90*time.Second).Unix()), c["auth_time"])

	s.SetFault(Fault{HasGroups: true, Kid: "k9"})
	_, body = login(t, s, strings.Repeat("v", 43))
	parts := strings.Split(body["id_token"].(string), ".")
	var hdr struct{ Alg, Kid string }
	decode(t, parts[0], &hdr)
	assert.Equal(t, "k9", hdr.Kid)
	var claims map[string]any
	decode(t, parts[1], &claims)
	assert.Equal(t, true, claims["hasgroups"])
	assert.Nil(t, claims["groups"])
	assert.Nil(t, claims["_claim_names"])
	s.SetFault(Fault{OmitNonce: true, OmitAuthTime: true})
	_, body = login(t, s, strings.Repeat("v", 43))
	c = verifyRS256(t, s, body["id_token"].(string))
	assert.NotContains(t, c, "nonce")
	assert.NotContains(t, c, "auth_time")
}

// rawToken posts form to /token with the client authentication chosen by auth.
func rawToken(t *testing.T, s *Server, form url.Values, auth func(r *http.Request)) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, s.Issuer()+"/token", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	auth(req)
	res, err := s.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = res.Body.Close() }()
	var body map[string]any
	b, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(b, &body))
	return res.StatusCode, body
}

func freshCode(t *testing.T, s *Server, verifier string) string {
	t.Helper()
	cb, err := s.Authorize(authorizeURL(s, challengeOf(verifier)))
	require.NoError(t, err)
	u, err := url.Parse(cb)
	require.NoError(t, err)
	return u.Query().Get("code")
}

func tokenForm(code, verifier string) url.Values {
	return url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect}, "code_verifier": {verifier}}
}

// Review Important 1: the algorithm-confusion token is really keyed with the public key (DER by default, the PEM
// text with Fault.HMACKeyPEM), so a verifier that is vulnerable to either form fails the negative test for a reason.
func TestHS256ConfusionTokenIsKeyedWithThePublicKey(t *testing.T) {
	for _, pemForm := range []bool{false, true} {
		s, _ := start(t)
		s.SetFault(Fault{Alg: "HS256", HMACKeyPEM: pemForm})
		_, body := login(t, s, strings.Repeat("v", 43))
		parts := strings.Split(body["id_token"].(string), ".")
		require.Len(t, parts, 3)
		der, err := x509.MarshalPKIXPublicKey(&s.keys[len(s.keys)-1].key.PublicKey)
		require.NoError(t, err)
		secret := der
		if pemForm {
			secret = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
		}
		mac := hmac.New(sha256.New, secret)
		mac.Write([]byte(parts[0] + "." + parts[1]))
		assert.Equal(t, b64(mac.Sum(nil)), parts[2], "pem=%v", pemForm)
		other := hmac.New(sha256.New, []byte("another secret"))
		other.Write([]byte(parts[0] + "." + parts[1]))
		assert.NotEqual(t, b64(other.Sum(nil)), parts[2])
	}
}

func TestTokenEndpointNegativePaths(t *testing.T) {
	s, _ := start(t)
	v := strings.Repeat("v", 43)
	basic := func(r *http.Request) {
		r.SetBasicAuth(url.QueryEscape(s.ClientID()), url.QueryEscape(s.ClientSecret()))
	}

	status, body := rawToken(t, s, tokenForm(freshCode(t, s, v), v), func(r *http.Request) {
		r.SetBasicAuth(url.QueryEscape(s.ClientID()), "wrong")
	})
	assert.Equal(t, http.StatusUnauthorized, status)
	assert.Equal(t, "invalid_client", body["error"])

	form := tokenForm(freshCode(t, s, v), v)
	form.Set("client_id", s.ClientID())
	form.Set("client_secret", s.ClientSecret())
	status, body = rawToken(t, s, form, func(*http.Request) {})
	assert.Equal(t, http.StatusOK, status, "client_secret_post is accepted: %v", body)

	form = tokenForm(freshCode(t, s, v), v)
	form.Set("redirect_uri", "https://alice.example.test/other")
	status, body = rawToken(t, s, form, basic)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_grant", body["error"], "redirect_uri must equal the authorize request's")

	form = tokenForm(freshCode(t, s, v), v)
	form.Set("grant_type", "client_credentials")
	status, body = rawToken(t, s, form, basic)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_grant", body["error"])

	status, body = rawToken(t, s, url.Values{"grant_type": {"authorization_code"}, "code": {"nope"}, "code_verifier": {v}}, basic)
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_grant", body["error"], "an unknown code")
}

func TestRedirectPrefixAndDown(t *testing.T) {
	s := Start(t, Options{})
	s.RegisterRedirectPrefix("https://localhost:")
	withRedirect := func(uri string) string {
		q := url.Values{"response_type": {"code"}, "client_id": {s.ClientID()}, "redirect_uri": {uri}, "scope": {"openid"},
			"state": {"st"}, "nonce": {"no"}, "code_challenge": {challengeOf("v")}, "code_challenge_method": {"S256"}}
		return s.Issuer() + "/authorize?" + q.Encode()
	}
	cb, err := s.Authorize(withRedirect("https://localhost:8443/api/v1/auth/oidc/p1/callback"))
	require.NoError(t, err)
	assert.Contains(t, cb, "code=")
	_, err = s.Authorize(withRedirect("https://localhost.evil.example/cb"))
	assert.Error(t, err, "the prefix includes the colon")
	_, err = s.Authorize(withRedirect("http://localhost:8443/cb"))
	assert.Error(t, err)

	s.Down()
	_, err = s.Authorize(withRedirect("https://localhost:8443/cb"))
	assert.ErrorContains(t, err, "503")
}

// Review Important 3: a real IdP omits a nonce the request did not carry and echoes state only when sent; the
// authorize query is recorded so step-up tests can assert prompt=login and max_age=0.
func TestNonceStateAndAuthorizeQuery(t *testing.T) {
	s, _ := start(t)
	q := url.Values{"response_type": {"code"}, "client_id": {s.ClientID()}, "redirect_uri": {redirect}, "scope": {"openid email"},
		"code_challenge": {challengeOf(strings.Repeat("v", 43))}, "code_challenge_method": {"S256"},
		"prompt": {"login"}, "max_age": {"0"}, "acr_values": {"mfa"}}
	cb, err := s.Authorize(s.Issuer() + "/authorize?" + q.Encode())
	require.NoError(t, err)
	u, err := url.Parse(cb)
	require.NoError(t, err)
	assert.False(t, u.Query().Has("state"), "no state sent, none echoed")
	got := s.LastAuthorizeQuery()
	assert.Equal(t, "login", got.Get("prompt"))
	assert.Equal(t, "0", got.Get("max_age"))
	assert.Equal(t, "mfa", got.Get("acr_values"))
	assert.Equal(t, "openid email", got.Get("scope"))
	got.Set("prompt", "none")
	assert.Equal(t, "login", s.LastAuthorizeQuery().Get("prompt"), "a copy")

	status, body := exchange(t, s, u.Query().Get("code"), strings.Repeat("v", 43))
	require.Equal(t, http.StatusOK, status)
	claims := verifyRS256(t, s, body["id_token"].(string))
	assert.NotContains(t, claims, "nonce", "never nonce: \"\"")
}

func TestDropOldKeysAfterEveryKeyWasWithdrawn(t *testing.T) {
	s, _ := start(t)
	require.True(t, s.WithdrawKey("k1"))
	assert.NotPanics(t, s.DropOldKeys)
	assert.Empty(t, s.Kids())
	s.RotateKey()
	assert.Equal(t, []string{"k2"}, s.Kids())
}
