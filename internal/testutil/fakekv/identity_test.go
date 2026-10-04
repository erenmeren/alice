package fakekv_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/clock"
	"alice/internal/testutil/fakekv"
	"alice/internal/testutil/pki"
)

var b64 = base64.RawURLEncoding

const (
	tokenURL   = "https://login.microsoftonline.com/%s/oauth2/v2.0/token"
	vaultScope = "https://vault.azure.net/.default"
	imdsURL    = "http://169.254.169.254/metadata/identity/oauth2/token"
)

var formHeader = http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}

func postToken(t *testing.T, c *fakekv.TestClient, tenant string, form url.Values) fakekv.Response {
	t.Helper()
	return c.Raw(t, http.MethodPost, strings.Replace(tokenURL, "%s", tenant, 1), formHeader, form.Encode())
}

func secretForm(s *fakekv.Server, secret string) url.Values {
	return url.Values{"grant_type": {"client_credentials"}, "client_id": {s.ClientID()}, "client_secret": {secret}, "scope": {vaultScope}}
}

func errCode(t *testing.T, r fakekv.Response) (string, float64) {
	t.Helper()
	m := r.JSON(t).(obj)
	codes := m["error_codes"].([]any)
	require.Len(t, codes, 1)
	return m["error"].(string), codes[0].(float64)
}

type assertionOpts struct {
	nbf, exp  time.Time
	aud, iss  string
	sub       string
	urlX5t    bool
	badSig    bool
	headerAlg string
}

func buildAssertion(t *testing.T, s *fakekv.Server, leaf pki.Leaf, o assertionOpts) string {
	t.Helper()
	now := time.Now()
	if o.nbf.IsZero() {
		o.nbf = now
	}
	if o.exp.IsZero() {
		o.exp = now.Add(10 * time.Minute)
	}
	if o.aud == "" {
		o.aud = "https://login.microsoftonline.com/" + s.TenantID() + "/oauth2/v2.0/token"
	}
	if o.iss == "" {
		o.iss = s.ClientID()
	}
	if o.sub == "" {
		o.sub = o.iss
	}
	if o.headerAlg == "" {
		o.headerAlg = "PS256"
	}
	sum := sha256.Sum256(leaf.Cert.Raw)
	x5t := base64.StdEncoding.EncodeToString(sum[:]) // MSAL v1.9.0 sends standard base64 (scan D10)
	if o.urlX5t {
		x5t = b64.EncodeToString(sum[:])
	}
	hb, _ := json.Marshal(obj{"alg": o.headerAlg, "typ": "JWT", "x5t#S256": x5t})
	cb, _ := json.Marshal(obj{"aud": o.aud, "iss": o.iss, "sub": o.sub, "jti": "j", "nbf": o.nbf.Unix(), "exp": o.exp.Unix()})
	signing := b64.EncodeToString(hb) + "." + b64.EncodeToString(cb)
	h := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPSS(rand.Reader, leaf.Key.(*rsa.PrivateKey), crypto.SHA256, h[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	require.NoError(t, err)
	if o.badSig {
		sig[0] ^= 0xff
	}
	return signing + "." + b64.EncodeToString(sig)
}

func assertionForm(s *fakekv.Server, a string) url.Values {
	return url.Values{"grant_type": {"client_credentials"}, "client_id": {s.ClientID()}, "scope": {vaultScope},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}, "client_assertion": {a}}
}

func claimsOf(t *testing.T, token string) obj {
	t.Helper()
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)
	b, err := b64.DecodeString(parts[1])
	require.NoError(t, err)
	var m obj
	require.NoError(t, json.Unmarshal(b, &m))
	return m
}

func TestTokenEndpoint(t *testing.T) {
	clk := clock.NewFake(time.Now())
	spCA := pki.NewCA("SP", pki.RSA2048, time.Now())
	sp := spCA.Issue(pki.Opts{CommonName: "alice-sp", KeyType: pki.RSA2048}, time.Now())
	s := fakekv.Start(t, fakekv.Options{Now: clk.Now, ClientCert: sp.Cert})
	s.AddCertificate("web-cert", fakekv.CertOptions{CommonName: "w.example.test", Exportable: true})
	c := s.TestClient()

	// OpenID configuration.
	oc := c.Raw(t, http.MethodGet, "https://login.microsoftonline.com/"+s.TenantID()+"/v2.0/.well-known/openid-configuration", nil, "")
	require.Equal(t, 200, oc.Status)
	m := oc.JSON(t).(obj)
	assert.Equal(t, "https://login.microsoftonline.com/"+s.TenantID()+"/oauth2/v2.0/token", m["token_endpoint"])
	assert.Equal(t, "https://login.microsoftonline.com/"+s.TenantID()+"/v2.0", m["issuer"])
	assert.Equal(t, "https://login.microsoftonline.com/"+s.TenantID()+"/oauth2/v2.0/authorize", m["authorization_endpoint"])
	bad := c.Raw(t, http.MethodGet, "https://login.microsoftonline.com/"+s.ClientID()+"/v2.0/.well-known/openid-configuration", nil, "")
	assert.Equal(t, 400, bad.Status)
	e, code := errCode(t, bad)
	assert.Equal(t, "invalid_tenant", e)
	assert.EqualValues(t, 90002, code)

	// Client secret.
	ok := postToken(t, c, s.TenantID(), secretForm(s, s.Secret()))
	require.Equal(t, 200, ok.Status, string(ok.Body))
	body := ok.JSON(t).(obj)
	assert.Equal(t, "Bearer", body["token_type"])
	assert.EqualValues(t, 3600, body["expires_in"])
	assert.EqualValues(t, 3600, body["ext_expires_in"])
	tok := body["access_token"].(string)
	assert.Equal(t, tok, s.LastAccessToken())
	cl := claimsOf(t, tok)
	assert.Equal(t, "https://vault.azure.net", cl["aud"])
	assert.Equal(t, s.TenantID(), cl["tid"])
	assert.Equal(t, s.ObjectID(), cl["oid"])
	assert.Equal(t, s.ClientID(), cl["appid"])
	assert.Equal(t, "https://sts.windows.net/"+s.TenantID()+"/", cl["iss"])
	assert.EqualValues(t, clk.Now().Unix(), cl["nbf"])
	assert.EqualValues(t, clk.Now().Add(time.Hour).Unix(), cl["exp"])
	assert.NotContains(t, string(ok.Body), s.Secret())

	for name, tc := range map[string]struct {
		tenant     string
		form       url.Values
		status     int
		err        string
		aadsts     float64
		wantInDesc string
	}{
		"wrong secret":   {s.TenantID(), secretForm(s, "wrong-secret"), 401, "invalid_client", 7000215, "AADSTS7000215"},
		"unknown app":    {s.TenantID(), url.Values{"grant_type": {"client_credentials"}, "client_id": {"nope"}, "client_secret": {"x"}, "scope": {vaultScope}}, 400, "unauthorized_client", 700016, "AADSTS700016"},
		"unknown tenant": {s.ClientID(), secretForm(s, s.Secret()), 400, "invalid_request", 90002, "AADSTS90002"},
		"bad grant":      {s.TenantID(), url.Values{"grant_type": {"password"}, "client_id": {s.ClientID()}}, 400, "unsupported_grant_type", 70003, "AADSTS70003"},
		"no credential":  {s.TenantID(), url.Values{"grant_type": {"client_credentials"}, "client_id": {s.ClientID()}, "scope": {vaultScope}}, 401, "invalid_client", 7000216, "AADSTS7000216"},
		"no scope":       {s.TenantID(), url.Values{"grant_type": {"client_credentials"}, "client_id": {s.ClientID()}, "client_secret": {s.Secret()}}, 400, "invalid_scope", 70011, "AADSTS70011"},
	} {
		r := postToken(t, c, tc.tenant, tc.form)
		assert.Equal(t, tc.status, r.Status, name)
		e, code := errCode(t, r)
		assert.Equal(t, tc.err, e, name)
		assert.Equal(t, tc.aadsts, code, name)
		assert.Contains(t, r.JSON(t).(obj)["error_description"], tc.wantInDesc, name)
		assert.NotContains(t, string(r.Body), s.Secret(), name)
	}

	// An expired secret: the right secret is refused with 7000222; restoring brings it back.
	s.ExpireSecret()
	r := postToken(t, c, s.TenantID(), secretForm(s, s.Secret()))
	assert.Equal(t, 401, r.Status)
	e, code = errCode(t, r)
	assert.Equal(t, "invalid_client", e)
	assert.EqualValues(t, 7000222, code)
	wrongStill := postToken(t, c, s.TenantID(), secretForm(s, "wrong-secret"))
	_, code = errCode(t, wrongStill)
	assert.EqualValues(t, 7000215, code, "a wrong secret is still a wrong secret")
	s.RestoreSecret()
	assert.Equal(t, 200, postToken(t, c, s.TenantID(), secretForm(s, s.Secret())).Status)

	// Client assertion.
	good := postToken(t, c, s.TenantID(), assertionForm(s, buildAssertion(t, s, sp, assertionOpts{})))
	assert.Equal(t, 200, good.Status, string(good.Body))
	assert.Equal(t, 200, postToken(t, c, s.TenantID(), assertionForm(s, buildAssertion(t, s, sp, assertionOpts{urlX5t: true}))).Status, "x5t#S256 in base64url is accepted too")
	other := spCA.Issue(pki.Opts{CommonName: "other", KeyType: pki.RSA2048}, time.Now())
	for name, tc := range map[string]struct {
		a      string
		aadsts float64
	}{
		"bad signature":  {buildAssertion(t, s, sp, assertionOpts{badSig: true}), 700027},
		"unregistered":   {buildAssertion(t, s, other, assertionOpts{}), 700027},
		"garbage":        {"a.b.c", 700027},
		"not a jwt":      {"x", 700027},
		"wrong alg":      {buildAssertion(t, s, sp, assertionOpts{headerAlg: "RS256"}), 700027},
		"expired":        {buildAssertion(t, s, sp, assertionOpts{nbf: time.Now().Add(-2 * time.Hour), exp: time.Now().Add(-time.Hour)}), 700024},
		"not yet valid":  {buildAssertion(t, s, sp, assertionOpts{nbf: time.Now().Add(time.Hour), exp: time.Now().Add(2 * time.Hour)}), 700024},
		"wrong audience": {buildAssertion(t, s, sp, assertionOpts{aud: "https://login.microsoftonline.com/x/oauth2/v2.0/token"}), 700023},
		"wrong issuer":   {buildAssertion(t, s, sp, assertionOpts{iss: "someone-else"}), 700021},
	} {
		r := postToken(t, c, s.TenantID(), assertionForm(s, tc.a))
		assert.Equal(t, 401, r.Status, name)
		_, code := errCode(t, r)
		assert.Equal(t, tc.aadsts, code, name)
		assert.NotContains(t, string(r.Body), tc.a, name)
	}
	f := assertionForm(s, buildAssertion(t, s, sp, assertionOpts{}))
	f.Set("client_assertion_type", "other")
	_, code = errCode(t, postToken(t, c, s.TenantID(), f))
	assert.EqualValues(t, 700027, code)
	reg := spCA.Issue(pki.Opts{CommonName: "second", KeyType: pki.RSA2048}, time.Now())
	s.RegisterCertificate(reg.Cert)
	assert.Equal(t, 200, postToken(t, c, s.TenantID(), assertionForm(s, buildAssertion(t, s, reg, assertionOpts{}))).Status)

	// A GET on the token endpoint is not served.
	assert.Equal(t, 405, c.Raw(t, http.MethodGet, strings.Replace(tokenURL, "%s", s.TenantID(), 1), nil, "").Status)
	assert.Equal(t, 404, c.Raw(t, http.MethodGet, "https://login.microsoftonline.com/nothing", nil, "").Status)
}

func TestIssuedTokensAreCheckedByTheVault(t *testing.T) {
	clk := clock.NewFake(time.Now())
	s := fakekv.Start(t, fakekv.Options{Now: clk.Now})
	s.AddCertificate("web-cert", fakekv.CertOptions{CommonName: "w.example.test"})
	c := s.TestClient()
	vault := s.VaultURL() + "/certificates?api-version=" + fakekv.APIVersion
	tok := func() string {
		r := postToken(t, c, s.TenantID(), secretForm(s, s.Secret()))
		require.Equal(t, 200, r.Status)
		return r.JSON(t).(obj)["access_token"].(string)
	}
	call := func(token string) fakekv.Response {
		h := http.Header{}
		if token != "" {
			h.Set("Authorization", "Bearer "+token)
		}
		return c.Raw(t, http.MethodGet, vault, h, "")
	}
	good := tok()
	assert.Equal(t, 200, call(good).Status)
	for name, token := range map[string]string{"none": "", "unknown": "abc.def.ghi", "foreign": "x"} {
		r := call(token)
		assert.Equal(t, 401, r.Status, name)
		assert.Equal(t, "Unauthorized", get(r.JSON(t), "error", "code"), name)
	}
	// Expiry follows the test clock.
	clk.Advance(59 * time.Minute)
	assert.Equal(t, 200, call(good).Status)
	clk.Advance(2 * time.Minute)
	r := call(good)
	assert.Equal(t, 401, r.Status)
	assert.NotEmpty(t, r.Header.Get("WWW-Authenticate"))
	assert.Equal(t, 200, call(tok()).Status)
	s.SetTokenLifetime(time.Minute)
	short := tok()
	assert.EqualValues(t, clk.Now().Add(time.Minute).Unix(), claimsOf(t, short)["exp"])
	// A token for another resource is refused by the vault.
	imds := fakekv.Start(t, fakekv.Options{ManagedIdentity: true})
	graph := imds.TestClient().Raw(t, http.MethodGet, imdsURL+"?api-version=2018-02-01&resource=https://graph.microsoft.com", http.Header{"Metadata": {"true"}}, "")
	require.Equal(t, 200, graph.Status)
	gtok := graph.JSON(t).(obj)["access_token"].(string)
	r = imds.TestClient().Raw(t, http.MethodGet, imds.VaultURL()+"/certificates?api-version="+fakekv.APIVersion, http.Header{"Authorization": {"Bearer " + gtok}}, "")
	assert.Equal(t, 401, r.Status)
}

func TestTokensCarryChosenClaims(t *testing.T) {
	s := fakekv.Start(t, fakekv.Options{})
	c := s.TestClient()
	s.SetTokenClaims("not-a-guid", "also not a guid")
	cl := claimsOf(t, postToken(t, c, s.TenantID(), secretForm(s, s.Secret())).JSON(t).(obj)["access_token"].(string))
	assert.Equal(t, "not-a-guid", cl["oid"])
	assert.Equal(t, "also not a guid", cl["tid"])
	s.SetTokenClaims(strings.Repeat("x", 300), "")
	cl = claimsOf(t, postToken(t, c, s.TenantID(), secretForm(s, s.Secret())).JSON(t).(obj)["access_token"].(string))
	assert.Len(t, cl["oid"], 300)
	assert.Equal(t, "", cl["tid"])
	assert.Equal(t, s.ObjectID(), strings.Repeat("x", 300))
}

func TestManagedIdentityEndpoint(t *testing.T) {
	meta := http.Header{"Metadata": {"true"}}
	q := "?api-version=2018-02-01&resource=https://vault.azure.net"
	get := func(s *fakekv.Server, query string, h http.Header) fakekv.Response {
		return s.TestClient().Raw(t, http.MethodGet, imdsURL+query, h, "")
	}
	clk := clock.NewFake(time.Now())
	s := fakekv.Start(t, fakekv.Options{ManagedIdentity: true, Now: clk.Now})
	r := get(s, q, meta)
	require.Equal(t, 200, r.Status, string(r.Body))
	m := r.JSON(t).(obj)
	for _, k := range []string{"access_token", "client_id", "expires_in", "expires_on", "ext_expires_in", "not_before", "resource", "token_type"} {
		assert.Contains(t, m, k)
	}
	assert.Equal(t, "Bearer", m["token_type"])
	assert.Equal(t, "https://vault.azure.net", m["resource"])
	assert.Equal(t, "3600", m["expires_in"], "IMDS sends numbers as strings")
	assert.Equal(t, strconv.FormatInt(clk.Now().Add(time.Hour).Unix(), 10), m["expires_on"])
	assert.Equal(t, strconv.FormatInt(clk.Now().Unix(), 10), m["not_before"])
	assert.Equal(t, "https://vault.azure.net", claimsOf(t, m["access_token"].(string))["aud"])
	vault := s.TestClient().Raw(t, http.MethodGet, s.VaultURL()+"/certificates?api-version="+fakekv.APIVersion,
		http.Header{"Authorization": {"Bearer " + m["access_token"].(string)}}, "")
	assert.Equal(t, 200, vault.Status, "the vault accepts the managed identity's token")

	assert.Equal(t, 400, get(s, q, nil).Status, "no Metadata header")
	assert.Equal(t, 400, get(s, "?resource=x", meta).Status, "no api-version")
	assert.Equal(t, 400, get(s, "?api-version=2018-02-01", meta).Status, "no resource")
	nf := get(s, q+"&client_id=00000000-0000-0000-0000-000000000001", meta)
	assert.Equal(t, 400, nf.Status)
	assert.Equal(t, "Identity not found", nf.JSON(t).(obj)["error_description"])
	assert.Equal(t, 404, s.TestClient().Raw(t, http.MethodGet, "http://169.254.169.254/metadata/instance"+q, meta, "").Status)
	assert.Equal(t, 405, s.TestClient().Raw(t, http.MethodPost, imdsURL+q, meta, "").Status)

	// A user-assigned identity.
	ua := fakekv.Start(t, fakekv.Options{ManagedIdentity: true, MIClientID: "11111111-2222-3333-4444-555555555555"})
	assert.Equal(t, 200, get(ua, q+"&client_id=11111111-2222-3333-4444-555555555555", meta).Status)
	assert.Equal(t, 400, get(ua, q, meta).Status, "the system-assigned identity does not exist")

	// No managed identity at all.
	none := fakekv.Start(t, fakekv.Options{})
	r = get(none, q, meta)
	assert.Equal(t, 400, r.Status)
	assert.Equal(t, "Identity not found", r.JSON(t).(obj)["error_description"])
}

func TestVaultChallengeAndRoles(t *testing.T) {
	s := fakekv.Start(t, fakekv.Options{})
	v := s.AddCertificate("web-cert", fakekv.CertOptions{CommonName: "w.example.test", Exportable: true})
	s.AddKey("signing", fakekv.KeyOptions{KeyType: "RSA", Size: 2048, Enabled: true})
	c := s.TestClient()
	api := "?api-version=" + fakekv.APIVersion
	r := c.Raw(t, http.MethodGet, s.VaultURL()+"/certificates"+api, nil, "")
	assert.Equal(t, 401, r.Status)
	assert.Equal(t, `Bearer authorization="https://login.microsoftonline.com/`+s.TenantID()+`", resource="https://vault.azure.net"`, r.Header.Get("WWW-Authenticate"))
	assert.Equal(t, "Unauthorized", get(r.JSON(t), "error", "code"))
	assert.Contains(t, get(r.JSON(t), "error", "message"), "AKV10000")
	assert.Regexp(t, `^[0-9a-f-]{36}$`, r.Header.Get("x-ms-request-id"))
	s.SetChallenge(`Bearer authorization="https://evil.test/x", resource="https://vault.azure.net"`)
	assert.Contains(t, c.Raw(t, http.MethodGet, s.VaultURL()+"/certificates"+api, nil, "").Header.Get("WWW-Authenticate"), "evil.test")
	s.SetChallenge("")

	routes := map[string]string{
		"certificates/list": "/certificates", "certificates/get": "/certificates/web-cert/", "keys/list": "/keys", "keys/get": "/keys/signing/",
		"secrets/list": "/secrets", "secrets/get": "/secrets/web-cert/" + v,
	}
	for action, path := range routes {
		s.RevokeRole(action)
		for name, other := range routes {
			want := 200
			if name == action {
				want = 403
			}
			assert.Equal(t, want, c.Get(t, other).Status, "revoked %s, calling %s", action, name)
		}
		denied := c.Get(t, path)
		assert.Equal(t, "Forbidden", get(denied.JSON(t), "error", "code"))
		assert.Equal(t, "ForbiddenByRbac", get(denied.JSON(t), "error", "innererror", "code"))
		assert.Contains(t, get(denied.JSON(t), "error", "message"), "Caller: appid="+s.ClientID())
		s.GrantRole(action)
		assert.Equal(t, 200, c.Get(t, path).Status)
	}
	// The list role also covers a certificate's versions; import has its own.
	s.RevokeRole("certificates/list")
	assert.Equal(t, 403, c.Get(t, "/certificates/web-cert/versions").Status)
	s.GrantRole("certificates/list")
	s.RevokeRole("certificates/import")
	assert.Equal(t, 403, c.Do(t, http.MethodPost, "/certificates/x/import", `{}`).Status, "the role is checked before the body")
	s.GrantRole("certificates/import")
	assert.Equal(t, 400, c.Do(t, http.MethodPost, "/certificates/x/import", `{}`).Status)

	ap := fakekv.Start(t, fakekv.Options{Model: "access_policy"})
	ap.RevokeRole("secrets/get")
	d := ap.TestClient().Get(t, "/secrets/x/"+strings.Repeat("a", 32))
	assert.Equal(t, 403, d.Status)
	assert.Equal(t, "ForbiddenByPolicy", get(d.JSON(t), "error", "innererror", "code"))

	// The firewall refuses everything, before the role and the route.
	s.Firewall("203.0.113.7")
	for _, p := range []string{"/certificates", "/keys", "/nothing"} {
		fw := c.Get(t, p)
		assert.Equal(t, 403, fw.Status, p)
		assert.Equal(t, "ForbiddenByFirewall", get(fw.JSON(t), "error", "innererror", "code"))
		assert.Contains(t, get(fw.JSON(t), "error", "message"), "Client address: 203.0.113.7")
	}
	assert.Equal(t, 401, c.Raw(t, http.MethodGet, s.VaultURL()+"/certificates"+api, nil, "").Status, "the challenge still comes first")
	s.Firewall("")
	assert.Equal(t, 200, c.Get(t, "/certificates").Status)
}

func TestFaults(t *testing.T) {
	s := fakekv.Start(t, fakekv.Options{})
	s.AddBulkCertificates("bulk", 30)
	c := s.TestClient()

	// One 429 with Retry-After (seconds), then normal; the next one with an HTTP-date.
	s.FailNext("/certificates", fakekv.Fault{Status: 429, RetryAfter: "7"})
	r := c.Get(t, "/certificates")
	assert.Equal(t, 429, r.Status)
	assert.Equal(t, "7", r.Header.Get("Retry-After"))
	assert.NotEmpty(t, get(r.JSON(t), "error", "code"))
	assert.Equal(t, 200, c.Get(t, "/certificates").Status)
	date := time.Now().Add(30 * time.Second).UTC().Format(http.TimeFormat)
	s.FailNext("/certificates", fakekv.Fault{Status: 429, RetryAfter: date})
	assert.Equal(t, date, c.Get(t, "/certificates").Header.Get("Retry-After"))
	s.FailNext("/certificates", fakekv.Fault{Status: 429})
	assert.Empty(t, c.Get(t, "/certificates").Header.Get("Retry-After"), "a 429 without Retry-After")

	// Queue order; 5xx; a custom body.
	s.FailNext("/certificates", fakekv.Fault{Status: 503})
	s.FailNext("/certificates", fakekv.Fault{Status: 500, Body: `{"error":{"code":"Custom","message":"m"}}`})
	assert.Equal(t, 503, c.Get(t, "/certificates").Status)
	r = c.Get(t, "/certificates")
	assert.Equal(t, 500, r.Status)
	assert.Equal(t, "Custom", get(r.JSON(t), "error", "code"))

	// Path prefix matching: a fault for /keys does not touch /certificates.
	s.FailNext("/keys", fakekv.Fault{Status: 503})
	assert.Equal(t, 200, c.Get(t, "/certificates").Status)
	assert.Equal(t, 503, c.Get(t, "/keys").Status)

	// Malformed and truncated bodies.
	s.FailNext("/certificates", fakekv.Fault{Body: "{not json"})
	r = c.Get(t, "/certificates")
	assert.Equal(t, 200, r.Status)
	assert.False(t, json.Valid(r.Body))
	s.FailNext("/certificates", fakekv.Fault{Truncate: true})
	r = c.Get(t, "/certificates")
	assert.Equal(t, 200, r.Status)
	assert.False(t, json.Valid(r.Body))
	assert.Contains(t, string(r.Body), `"value"`)

	// A dropped connection: the body ends before its declared length.
	s.FailNext("/certificates", fakekv.Fault{Drop: true})
	req, _ := http.NewRequest(http.MethodGet, s.VaultURL()+"/certificates?api-version="+fakekv.APIVersion, http.NoBody)
	req.Header.Set("Authorization", "Bearer "+s.TestClientToken())
	assert.Error(t, drain(c, req), "unexpected EOF")

	// A redirect (not followed by the test client) and a wrong-host nextLink.
	s.FailNext("/certificates", fakekv.Fault{Status: 302, Location: "https://169.254.169.254/"})
	r = c.Get(t, "/certificates")
	assert.Equal(t, 302, r.Status)
	assert.Equal(t, "https://169.254.169.254/", r.Header.Get("Location"))
	s.FailNext("/certificates", fakekv.Fault{NextLink: "https://evil.test/certificates"})
	r = c.Get(t, "/certificates")
	assert.Equal(t, 200, r.Status)
	assert.Equal(t, "https://evil.test/certificates", get(r.JSON(t), "nextLink"))
	assert.Len(t, get(r.JSON(t), "value"), 25, "the rest of the page is real")
	s.FailNext("/keys", fakekv.Fault{NextLink: "https://evil.test/keys"})
	assert.Equal(t, "https://evil.test/keys", get(c.GetJSON(t, "/keys"), "nextLink"), "added to a last page too")

	// FailAll until stopped.
	stop := s.FailAll("/secrets", fakekv.Fault{Status: 429, RetryAfter: "1"})
	assert.Equal(t, 429, c.Get(t, "/secrets").Status)
	assert.Equal(t, 429, c.Get(t, "/secrets").Status)
	stop()
	stop()
	assert.Equal(t, 200, c.Get(t, "/secrets").Status)

	// Apply: an import happens although the answer failed.
	ca := pki.NewCA("I", pki.ECDSA256, time.Now())
	leaf := ca.Issue(pki.Opts{CommonName: "i.example.test"}, time.Now())
	body := importBody(t, leaf)
	s.FailNext("/certificates/new-cert/import", fakekv.Fault{Status: 503, Apply: true})
	assert.Equal(t, 503, c.Do(t, http.MethodPost, "/certificates/new-cert/import", body).Status)
	assert.Len(t, s.Versions("new-cert"), 1)
	s.FailNext("/certificates/other/import", fakekv.Fault{Status: 503})
	assert.Equal(t, 503, c.Do(t, http.MethodPost, "/certificates/other/import", body).Status)
	assert.Nil(t, s.Versions("other"), "without Apply nothing happened")

	// An unauthenticated request (the SDK's challenge probe) never consumes a fault.
	s.FailNext("/certificates", fakekv.Fault{Status: 503})
	assert.Equal(t, 401, c.Raw(t, http.MethodGet, s.VaultURL()+"/certificates?api-version="+fakekv.APIVersion, nil, "").Status)
	assert.Equal(t, 503, c.Get(t, "/certificates").Status)

	// Faults reach the token endpoint and IMDS too.
	s.FailNext("/"+s.TenantID()+"/oauth2/v2.0/token", fakekv.Fault{Status: 503})
	assert.Equal(t, 503, postToken(t, c, s.TenantID(), secretForm(s, s.Secret())).Status)
	assert.Equal(t, 200, postToken(t, c, s.TenantID(), secretForm(s, s.Secret())).Status)
}

func TestLatencyAndHold(t *testing.T) {
	s := fakekv.Start(t, fakekv.Options{})
	s.AddCertificate("web-cert", fakekv.CertOptions{CommonName: "w.example.test"})
	c := s.TestClient()

	s.SetLatency(150 * time.Millisecond)
	start := time.Now()
	assert.Equal(t, 200, c.Get(t, "/certificates").Status)
	assert.GreaterOrEqual(t, time.Since(start), 150*time.Millisecond)
	s.SetLatency(0)

	// A latency honours the request context.
	s.SetLatency(time.Minute)
	ctx, cancel := ctxTimeout(50 * time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, s.VaultURL()+"/certificates?api-version="+fakekv.APIVersion, http.NoBody)
	req.Header.Set("Authorization", "Bearer "+s.TestClientToken())
	require.Error(t, drain(c, req))
	s.SetLatency(0)

	// Hold: the next matching request waits for release; a context ends the wait.
	release := s.Hold("/certificates")
	done := make(chan fakekv.Response, 1)
	go func() { done <- c.Get(t, "/certificates") }()
	require.Eventually(t, func() bool { return s.Held() == 1 }, 3*time.Second, 5*time.Millisecond)
	select {
	case <-done:
		t.Fatal("the request was not held")
	case <-time.After(100 * time.Millisecond):
	}
	release()
	release()
	assert.Equal(t, 200, (<-done).Status)
	assert.Equal(t, 0, s.Held())
	assert.Equal(t, 200, c.Get(t, "/certificates").Status, "only the next request is held")

	s.Hold("/keys")
	ctx2, cancel2 := ctxTimeout(80 * time.Millisecond)
	defer cancel2()
	req, _ = http.NewRequestWithContext(ctx2, http.MethodGet, s.VaultURL()+"/keys?api-version="+fakekv.APIVersion, http.NoBody)
	req.Header.Set("Authorization", "Bearer "+s.TestClientToken())
	require.Error(t, drain(c, req))
	require.Eventually(t, func() bool { return s.Held() == 0 }, 3*time.Second, 5*time.Millisecond)

	// Close releases a held request.
	s2 := fakekv.Start(t, fakekv.Options{})
	s2.Hold("/certificates")
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		req, _ := http.NewRequest(http.MethodGet, s2.VaultURL()+"/certificates?api-version="+fakekv.APIVersion, http.NoBody)
		req.Header.Set("Authorization", "Bearer "+s2.TestClientToken())
		if resp, err := s2.TestClient().HTTPClient().Do(req); err == nil {
			_ = resp.Body.Close()
		}
	}()
	require.Eventually(t, func() bool { return s2.Held() == 1 }, 3*time.Second, 5*time.Millisecond)
	s2.Close()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not release the held request")
	}
}

func TestFaultDelay(t *testing.T) {
	s := fakekv.Start(t, fakekv.Options{})
	c := s.TestClient()
	s.FailNext("/certificates", fakekv.Fault{Status: 503, Delay: 120 * time.Millisecond})
	start := time.Now()
	assert.Equal(t, 503, c.Get(t, "/certificates").Status)
	assert.GreaterOrEqual(t, time.Since(start), 120*time.Millisecond)
}

func TestRequestLogHoldsNoSecrets(t *testing.T) {
	spCA := pki.NewCA("SP", pki.RSA2048, time.Now())
	sp := spCA.Issue(pki.Opts{CommonName: "alice-sp", KeyType: pki.RSA2048}, time.Now())
	s := fakekv.Start(t, fakekv.Options{ClientCert: sp.Cert, ManagedIdentity: true})
	v := s.AddCertificate("web-cert", fakekv.CertOptions{CommonName: "w.example.test", Exportable: true})
	c := s.TestClient()
	secretTok := postToken(t, c, s.TenantID(), secretForm(s, s.Secret()))
	assertion := buildAssertion(t, s, sp, assertionOpts{})
	assertTok := postToken(t, c, s.TenantID(), assertionForm(s, assertion))
	tok := assertTok.JSON(t).(obj)["access_token"].(string)
	c.Raw(t, http.MethodGet, s.VaultURL()+"/secrets/web-cert/"+v+"?api-version="+fakekv.APIVersion, http.Header{"Authorization": {"Bearer " + tok}}, "")
	c.Get(t, "/certificates")
	c.Raw(t, http.MethodGet, imdsURL+"?api-version=2018-02-01&resource=https://vault.azure.net", http.Header{"Metadata": {"true"}}, "")
	reqs := s.Requests()
	require.GreaterOrEqual(t, len(reqs), 5)
	dump, _ := json.Marshal(reqs)
	needles := []string{s.Secret(), assertion, tok, secretTok.JSON(t).(obj)["access_token"].(string), string(s.SecretValue("web-cert", v)), s.LastAccessToken(), s.ClientID()}
	for _, n := range needles {
		assert.NotContains(t, string(dump), n)
	}
	var tokenReq fakekv.Request
	for _, r := range reqs {
		if strings.HasSuffix(r.Path, "/oauth2/v2.0/token") {
			tokenReq = r
		}
	}
	assert.Equal(t, "POST", tokenReq.Method)
	assert.Equal(t, "login.microsoftonline.com", tokenReq.Host)
	assert.Empty(t, tokenReq.Query, "form values are in the body, never in the log")
	hosts := map[string]bool{}
	for _, r := range reqs {
		hosts[r.Host] = true
	}
	assert.True(t, hosts["169.254.169.254"], "IMDS requests are logged")
}

func TestExtraHostsAreLoggedAndRefused(t *testing.T) {
	s := fakekv.Start(t, fakekv.Options{ExtraHosts: []string{"evil.test"}})
	r := s.TestClient().Raw(t, http.MethodGet, "https://evil.test/certificates", http.Header{"Authorization": {"Bearer x"}}, "")
	assert.Equal(t, 404, r.Status)
	assert.Empty(t, r.Body)
	last := s.Requests()[len(s.Requests())-1]
	assert.Equal(t, "evil.test", last.Host)
	assert.Equal(t, 404, last.Status)
}
