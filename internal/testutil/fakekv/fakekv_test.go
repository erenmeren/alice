package fakekv_test

import (
	"crypto/sha1" //nolint:gosec // the x5t thumbprint is SHA-1 by definition
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"software.sslmate.com/src/go-pkcs12"

	"alice/internal/platform/clock"
	"alice/internal/testutil/fakekv"
	"alice/internal/testutil/pki"
)

type obj = map[string]any

func get(v any, path ...string) any {
	for _, p := range path {
		if a, ok := v.([]any); ok {
			i, _ := strconv.Atoi(p)
			v = a[i]
			continue
		}
		v = v.(obj)[p]
	}
	return v
}

func thumb(der []byte) string {
	sum := sha1.Sum(der) //nolint:gosec // x5t
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func TestListingsArePagedAndUnversioned(t *testing.T) {
	s := fakekv.Start(t, fakekv.Options{})
	for i := 0; i < 60; i++ {
		s.AddCertificate(fmt.Sprintf("cert-%02d", i), fakekv.CertOptions{CommonName: "x.example.test"})
	}
	c := s.TestClient()
	var names []string
	var sizes []int
	next := "/certificates"
	for next != "" {
		page := c.GetJSON(t, next)
		items := get(page, "value").([]any)
		sizes = append(sizes, len(items))
		for _, it := range items {
			id := get(it, "id").(string)
			assert.True(t, strings.HasPrefix(id, "https://alice-test.vault.azure.net/certificates/cert-"), id)
			assert.NotContains(t, strings.TrimPrefix(id, "https://alice-test.vault.azure.net/certificates/"), "/", "no version in a listing")
			names = append(names, id)
			der := s.Leaf(strings.TrimPrefix(id, "https://alice-test.vault.azure.net/certificates/"), "").Raw
			assert.Equal(t, thumb(der), get(it, "x5t"))
		}
		nl, _ := get(page, "nextLink").(string)
		if nl == "" {
			next = ""
			continue
		}
		u, err := url.Parse(nl)
		require.NoError(t, err)
		assert.Equal(t, "alice-test.vault.azure.net:443", u.Host, "the nextLink is on the vault host, with the port as Azure writes it")
		assert.Equal(t, fakekv.APIVersion, u.Query().Get("api-version"))
		assert.Equal(t, "25", u.Query().Get("maxresults"))
		assert.NotEmpty(t, u.Query().Get("$skiptoken"))
		next = nl
	}
	assert.Equal(t, []int{25, 25, 10}, sizes)
	assert.Len(t, names, 60)
	assert.True(t, sortedStrings(names))
}

func sortedStrings(s []string) bool {
	for i := 1; i < len(s); i++ {
		if s[i-1] >= s[i] {
			return false
		}
	}
	return true
}

func TestMaxResultsAndBadTokens(t *testing.T) {
	s := fakekv.Start(t, fakekv.Options{})
	s.AddBulkCertificates("b", 5)
	c := s.TestClient()
	page := c.GetJSON(t, "/certificates?maxresults=2")
	assert.Len(t, get(page, "value"), 2)
	assert.Contains(t, get(page, "nextLink"), "maxresults=2")
	for _, bad := range []string{"0", "26", "x"} {
		r := c.Get(t, "/certificates?maxresults="+bad)
		assert.Equal(t, 400, r.Status, bad)
		assert.Equal(t, "BadParameter", get(r.JSON(t), "error", "code"))
	}
	assert.Equal(t, 400, c.Get(t, "/certificates?$skiptoken=!!!").Status)
}

func TestGetLatestAndVersions(t *testing.T) {
	clk := clock.NewFake(time.Now())
	s := fakekv.Start(t, fakekv.Options{Now: clk.Now})
	v1 := s.AddCertificate("web-cert", fakekv.CertOptions{CommonName: "www.example.test", Exportable: true})
	c := s.TestClient()
	got := c.GetJSON(t, "/certificates/web-cert/")
	base := "https://alice-test.vault.azure.net"
	assert.Equal(t, base+"/certificates/web-cert/"+v1, get(got, "id"))
	assert.Equal(t, base+"/keys/web-cert/"+v1, get(got, "kid"))
	assert.Equal(t, base+"/secrets/web-cert/"+v1, get(got, "sid"))
	der, err := base64.StdEncoding.DecodeString(get(got, "cer").(string))
	require.NoError(t, err)
	assert.Equal(t, s.Leaf("web-cert", v1).Raw, der)
	assert.Equal(t, thumb(der), get(got, "x5t"))
	kp := get(got, "policy", "key_props")
	assert.Equal(t, obj{"exportable": true, "kty": "EC", "key_size": float64(256), "crv": "P-256", "reuse_key": false}, kp)
	assert.Equal(t, "application/x-pkcs12", get(got, "policy", "secret_props", "contentType"))
	assert.Equal(t, "Self", get(got, "policy", "issuer", "name"))
	la := get(got, "policy", "lifetime_actions").([]any)
	require.Len(t, la, 1)
	assert.Equal(t, "AutoRenew", get(la[0], "action", "action_type"))
	assert.Equal(t, float64(clk.Now().Unix()), get(got, "attributes", "created"))

	clk.Advance(48 * time.Hour)
	v2 := s.Renew("web-cert")
	assert.NotEqual(t, v1, v2)
	assert.Regexp(t, `^[0-9a-f]{32}$`, v2)
	latest := c.GetJSON(t, "/certificates/web-cert/")
	assert.Equal(t, base+"/certificates/web-cert/"+v2, get(latest, "id"))
	assert.NotEqual(t, get(got, "x5t"), get(latest, "x5t"))
	assert.Greater(t, get(latest, "attributes", "updated"), get(got, "attributes", "updated"))
	list := c.GetJSON(t, "/certificates")
	assert.Equal(t, get(latest, "x5t"), get(list, "value", "0", "x5t"), "the listing shows the current version")
}

func TestVersionsListOrder(t *testing.T) {
	for _, oldest := range []bool{false, true} {
		s := fakekv.Start(t, fakekv.Options{VersionsOldestFirst: oldest})
		s.AddCertificate("web-cert", fakekv.CertOptions{CommonName: "w.example.test"})
		for i := 0; i < 29; i++ {
			s.Renew("web-cert")
		}
		ids := s.Versions("web-cert") // oldest first
		c := s.TestClient()
		var listed []string
		next := "/certificates/web-cert/versions"
		for next != "" {
			page := c.GetJSON(t, next)
			for _, it := range get(page, "value").([]any) {
				id := get(it, "id").(string)
				listed = append(listed, id[strings.LastIndex(id, "/")+1:])
			}
			next, _ = get(page, "nextLink").(string)
		}
		require.Len(t, listed, 30)
		want := append([]string(nil), ids...)
		if !oldest {
			for i, j := 0, len(want)-1; i < j; i, j = i+1, j-1 {
				want[i], want[j] = want[j], want[i]
			}
		}
		assert.Equal(t, want, listed)
		// The old version still answers.
		r := c.Get(t, "/certificates/web-cert/"+ids[0])
		assert.Equal(t, 200, r.Status)
		assert.Equal(t, 404, c.Get(t, "/certificates/web-cert/"+strings.Repeat("0", 32)).Status)
	}
}

func TestSecretOfAVersion(t *testing.T) {
	s := fakekv.Start(t, fakekv.Options{})
	ver := s.AddCertificate("web-cert", fakekv.CertOptions{CommonName: "www.example.test", Exportable: true})
	rootVer := s.AddCertificate("root-cert", fakekv.CertOptions{CommonName: "r.example.test", Exportable: true, IncludeRoot: true})
	pemVer := s.AddCertificate("pem-cert", fakekv.CertOptions{CommonName: "p.example.test", Exportable: true, ContentType: "application/x-pem-file"})
	lastVer := s.AddCertificate("pem-last", fakekv.CertOptions{CommonName: "p.example.test", Exportable: true, ContentType: "application/x-pem-file", PEMKeyLast: true})
	s.AddCertificate("locked", fakekv.CertOptions{CommonName: "l.example.test"})
	c := s.TestClient()

	sec := c.GetJSON(t, "/secrets/web-cert/"+ver)
	assert.Equal(t, "application/x-pkcs12", get(sec, "contentType"))
	assert.Equal(t, true, get(sec, "managed"))
	raw, err := base64.StdEncoding.DecodeString(get(sec, "value").(string))
	require.NoError(t, err)
	key, leaf, chain, err := pkcs12.DecodeChain(raw, "")
	require.NoError(t, err)
	assert.NotNil(t, key)
	assert.Equal(t, s.Leaf("web-cert", ver).Raw, leaf.Raw)
	assert.Len(t, chain, 1, "leaf + fake intermediate")
	assert.Equal(t, string(s.SecretValue("web-cert", ver)), get(sec, "value"), "SecretValue is the served value")
	assert.Equal(t, get(sec, "value"), get(c.GetJSON(t, "/secrets/web-cert/"+ver), "value"), "a re-read serves the same bytes")

	rs := c.GetJSON(t, "/secrets/root-cert/"+rootVer)
	raw, _ = base64.StdEncoding.DecodeString(get(rs, "value").(string))
	_, _, chain, err = pkcs12.DecodeChain(raw, "")
	require.NoError(t, err)
	assert.Len(t, chain, 2, "intermediate and root")

	ps := c.GetJSON(t, "/secrets/pem-cert/"+pemVer)
	assert.Equal(t, "application/x-pem-file", get(ps, "contentType"))
	text := get(ps, "value").(string)
	marker := "-----BEGIN " + "PRIVATE KEY-----"
	assert.True(t, strings.HasPrefix(text, marker), "key block first by default")
	blk, rest := pem.Decode([]byte(text))
	assert.Equal(t, "PRIVATE KEY", blk.Type)
	blk, _ = pem.Decode(rest)
	assert.Equal(t, "CERTIFICATE", blk.Type)
	_, err = x509.ParseCertificate(blk.Bytes)
	require.NoError(t, err)
	last := get(c.GetJSON(t, "/secrets/pem-last/"+lastVer), "value").(string)
	assert.True(t, strings.HasSuffix(strings.TrimSpace(last), "-----END "+"PRIVATE KEY-----"))

	// Not exportable: 403 Forbidden with the inner code of the vault's model.
	locked := c.Get(t, "/secrets/locked/"+s.Versions("locked")[0])
	assert.Equal(t, 403, locked.Status)
	assert.Equal(t, "Forbidden", get(locked.JSON(t), "error", "code"))
	assert.Equal(t, "ForbiddenByRbac", get(locked.JSON(t), "error", "innererror", "code"))
	s.SetExportable("locked", true)
	assert.Equal(t, 200, c.Get(t, "/secrets/locked/"+s.Versions("locked")[0]).Status)
	s.SetExportable("locked", false)

	// Never "latest".
	for _, p := range []string{"/secrets/web-cert/", "/secrets/web-cert"} {
		r := c.Get(t, p)
		assert.Equal(t, 400, r.Status, p)
		assert.Equal(t, "BadParameter", get(r.JSON(t), "error", "code"))
	}
	assert.Equal(t, 404, c.Get(t, "/secrets/absent/"+ver).Status)
	assert.Equal(t, 404, c.Get(t, "/secrets/web-cert/"+strings.Repeat("a", 32)).Status)
}

func TestDisabledDeletedAndExpired(t *testing.T) {
	s := fakekv.Start(t, fakekv.Options{})
	v := s.AddCertificate("web-cert", fakekv.CertOptions{CommonName: "w.example.test", Exportable: true})
	old := s.AddCertificate("old-cert", fakekv.CertOptions{CommonName: "o.example.test", Exportable: true,
		NotBefore: time.Now().Add(-72 * time.Hour), NotAfter: time.Now().Add(-time.Hour)})
	c := s.TestClient()
	s.DisableVersion("web-cert", v)
	cert := c.GetJSON(t, "/certificates/web-cert/"+v)
	assert.Equal(t, false, get(cert, "attributes", "enabled"))
	sec := c.Get(t, "/secrets/web-cert/"+v)
	assert.Equal(t, 403, sec.Status)
	assert.Equal(t, "SecretDisabled", get(sec.JSON(t), "error", "innererror", "code"))
	s.EnableVersion("web-cert", v)
	assert.Equal(t, 200, c.Get(t, "/secrets/web-cert/"+v).Status)

	// An expired certificate is still listed and readable; exp tells.
	exp := get(c.GetJSON(t, "/certificates/old-cert/"+old), "attributes", "exp").(float64)
	assert.Less(t, exp, float64(time.Now().Unix()))
	assert.Equal(t, 200, c.Get(t, "/secrets/old-cert/"+old).Status)

	// Soft-deleted: absent from listings, 404 everywhere, name cannot be imported into.
	s.DeleteCertificate("web-cert")
	assert.Equal(t, 404, c.Get(t, "/certificates/web-cert/").Status)
	assert.Equal(t, 404, c.Get(t, "/certificates/web-cert/versions").Status)
	assert.Equal(t, 404, c.Get(t, "/secrets/web-cert/"+v).Status)
	assert.Equal(t, 404, c.Get(t, "/keys/web-cert/").Status)
	for _, l := range []string{"/certificates", "/secrets", "/keys"} {
		assert.NotContains(t, string(c.Get(t, l).Body), "web-cert", l)
	}
	nf := c.Get(t, "/certificates/web-cert/")
	assert.Equal(t, "CertificateNotFound", get(nf.JSON(t), "error", "code"))
	s.RecoverCertificate("web-cert")
	assert.Equal(t, 200, c.Get(t, "/certificates/web-cert/").Status)
}

func TestBackingKeyAndSecretAreListedAsManaged(t *testing.T) {
	s := fakekv.Start(t, fakekv.Options{})
	s.AddCertificate("web-cert", fakekv.CertOptions{CommonName: "w.example.test", Exportable: true})
	s.AddKey("signing", fakekv.KeyOptions{KeyType: "RSA", Size: 2048, Enabled: true})
	s.AddSecret("db-password", "text/plain")
	c := s.TestClient()
	keys := get(c.GetJSON(t, "/keys"), "value").([]any)
	require.Len(t, keys, 2)
	assert.Equal(t, "https://alice-test.vault.azure.net/keys/signing", get(keys[0], "kid"))
	assert.Equal(t, false, get(keys[0], "managed"))
	assert.Equal(t, true, get(keys[1], "managed"))
	secrets := get(c.GetJSON(t, "/secrets"), "value").([]any)
	require.Len(t, secrets, 2)
	assert.Equal(t, "https://alice-test.vault.azure.net/secrets/db-password", get(secrets[0], "id"))
	assert.Equal(t, "text/plain", get(secrets[0], "contentType"))
	assert.Equal(t, true, get(secrets[1], "managed"))
	assert.Equal(t, "application/x-pkcs12", get(secrets[1], "contentType"))
}

func TestImportCreatesAVersion(t *testing.T) {
	clk := clock.NewFake(time.Now())
	s := fakekv.Start(t, fakekv.Options{Now: clk.Now})
	c := s.TestClient()
	ca := pki.NewCA("Import CA", pki.ECDSA256, time.Now())
	leaf := ca.Issue(pki.Opts{CommonName: "imp.example.test", SANs: []string{"imp.example.test"}}, time.Now())
	pfx, err := pkcs12.LegacyDES.Encode(leaf.Key, leaf.Cert, []*x509.Certificate{ca.Intermediate}, "")
	require.NoError(t, err)
	body := func(v []byte, pwd string) string {
		b, _ := json.Marshal(obj{"value": base64.StdEncoding.EncodeToString(v), "pwd": pwd,
			"policy": obj{"key_props": obj{"exportable": true, "kty": "EC", "reuse_key": false}, "secret_props": obj{"contentType": "application/x-pkcs12"}}})
		return string(b)
	}
	sent := clk.Now()
	clk.Advance(3 * time.Second)
	r := c.Do(t, http.MethodPost, "/certificates/new-cert/import", body(pfx, ""))
	require.Equal(t, 200, r.Status, string(r.Body))
	b := r.JSON(t)
	id := get(b, "id").(string)
	ver := id[strings.LastIndex(id, "/")+1:]
	assert.Regexp(t, `^[0-9a-f]{32}$`, ver)
	assert.Equal(t, thumb(leaf.Cert.Raw), get(b, "x5t"))
	assert.Greater(t, get(b, "attributes", "created"), float64(sent.Unix()), "created is after the request was sent (ruling S14)")
	assert.Equal(t, "Unknown", get(b, "policy", "issuer", "name"))
	assert.Equal(t, []string{ver}, s.Versions("new-cert"))
	assert.Equal(t, leaf.Cert.Raw, s.Leaf("new-cert", "").Raw)
	// The imported PFX is read back through the secret.
	sec := c.GetJSON(t, "/secrets/new-cert/"+ver)
	raw, _ := base64.StdEncoding.DecodeString(get(sec, "value").(string))
	_, got, _, err := pkcs12.DecodeChain(raw, "")
	require.NoError(t, err)
	assert.Equal(t, leaf.Cert.Raw, got.Raw)

	// The same name again: a new version that becomes current.
	clk.Advance(time.Minute)
	leaf2 := ca.Issue(pki.Opts{CommonName: "imp.example.test"}, time.Now())
	pfx2, err := pkcs12.Modern.Encode(leaf2.Key, leaf2.Cert, nil, "")
	require.NoError(t, err)
	r2 := c.Do(t, http.MethodPost, "/certificates/new-cert/import", body(pfx2, ""))
	require.Equal(t, 200, r2.Status, string(r2.Body))
	assert.Len(t, s.Versions("new-cert"), 2)
	assert.Equal(t, leaf2.Cert.Raw, s.Leaf("new-cert", "").Raw)
	assert.Equal(t, thumb(leaf2.Cert.Raw), get(c.GetJSON(t, "/certificates/new-cert/"), "x5t"))

	// Refusals: not a PFX, wrong password, PEM, bad name, no value, a deleted name.
	for name, tc := range map[string]struct{ path, body string }{
		"garbage":  {"/certificates/x/import", body([]byte("not a pfx"), "")},
		"password": {"/certificates/x/import", body(pfx, "wrong")},
		"pem":      {"/certificates/x/import", body(leaf.FullchainPEM, "")},
		"name":     {"/certificates/bad_name/import", body(pfx, "")},
		"empty":    {"/certificates/x/import", `{}`},
		"json":     {"/certificates/x/import", `{`},
	} {
		r := c.Do(t, http.MethodPost, tc.path, tc.body)
		assert.Equal(t, 400, r.Status, name)
		assert.Equal(t, "BadParameter", get(r.JSON(t), "error", "code"), name)
	}
	assert.Equal(t, 404, c.Get(t, "/certificates/x/").Status, "a refused import creates nothing")
	s.DeleteCertificate("new-cert")
	assert.Equal(t, 409, c.Do(t, http.MethodPost, "/certificates/new-cert/import", body(pfx, "")).Status)
}

func TestImportWithoutPolicyKeepsTheExistingPolicy(t *testing.T) {
	s := fakekv.Start(t, fakekv.Options{})
	s.AddCertificate("web-cert", fakekv.CertOptions{CommonName: "w.example.test", Exportable: false})
	c := s.TestClient()
	ca := pki.NewCA("Import CA", pki.ECDSA256, time.Now())
	leaf := ca.Issue(pki.Opts{CommonName: "w.example.test"}, time.Now())
	pfx, _ := pkcs12.Modern.Encode(leaf.Key, leaf.Cert, nil, "")
	b, _ := json.Marshal(obj{"value": base64.StdEncoding.EncodeToString(pfx)})
	r := c.Do(t, http.MethodPost, "/certificates/web-cert/import", string(b))
	require.Equal(t, 200, r.Status, string(r.Body))
	assert.Equal(t, false, get(r.JSON(t), "policy", "key_props", "exportable"))
	assert.Equal(t, "Self", get(r.JSON(t), "policy", "issuer", "name"))
	// Without a policy for a new name: defaults of an import.
	r = c.Do(t, http.MethodPost, "/certificates/fresh/import", string(b))
	require.Equal(t, 200, r.Status)
	assert.Equal(t, true, get(r.JSON(t), "policy", "key_props", "exportable"))
	assert.Equal(t, "application/x-pkcs12", get(r.JSON(t), "policy", "secret_props", "contentType"))
}

func TestOtherAPIVersionsAreRefused(t *testing.T) {
	s := fakekv.Start(t, fakekv.Options{})
	c := s.TestClient()
	for _, v := range []string{"7.5", "2025-06-01", "2026-02-01"} {
		r := c.Get(t, "/certificates?api-version="+v)
		assert.Equal(t, 400, r.Status, v)
		assert.Equal(t, "BadParameter", get(r.JSON(t), "error", "code"))
	}
	r := c.Get(t, "/certificates?api-version=")
	assert.Equal(t, 400, r.Status, "an empty api-version is refused too")
}

func TestUnauthenticatedAndUnknownRoutes(t *testing.T) {
	s := fakekv.Start(t, fakekv.Options{})
	c := s.TestClient()
	r := c.Get(t, "/nothing")
	assert.Equal(t, 404, r.Status)
	assert.Equal(t, 405, c.Do(t, http.MethodDelete, "/certificates/x/", "").Status)
	assert.Equal(t, 405, c.Do(t, http.MethodGet, "/certificates/x/import", "").Status)
	// A request for another host is answered 404 with no body, and logged.
	req, _ := http.NewRequest(http.MethodGet, "https://127.0.0.1:"+portOf(t, s.DialAddr("alice-test.vault.azure.net:443"))+"/certificates", http.NoBody)
	resp, err := s.TestClient().HTTPClient().Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, 404, resp.StatusCode)
	reqs := s.Requests()
	assert.Equal(t, "127.0.0.1", strings.Split(reqs[len(reqs)-1].Host, ":")[0])
}

func portOf(t *testing.T, addr string) string {
	t.Helper()
	return addr[strings.LastIndex(addr, ":")+1:]
}

func TestDialAddr(t *testing.T) {
	s := fakekv.Start(t, fakekv.Options{ExtraHosts: []string{"Evil.Test"}})
	l := s.DialAddr("login.microsoftonline.com:443")
	assert.Equal(t, l, s.DialAddr("alice-test.vault.azure.net:443"))
	assert.Equal(t, l, s.DialAddr("evil.test:443"))
	assert.Equal(t, l, s.DialAddr("ALICE-TEST.vault.azure.net:443"))
	assert.NotEqual(t, l, s.DialAddr("169.254.169.254:80"))
	assert.Equal(t, "other.example.test:443", s.DialAddr("other.example.test:443"))
	assert.Equal(t, "alice-test.vault.azure.net:8443", s.DialAddr("alice-test.vault.azure.net:8443"))
	assert.Equal(t, "garbage", s.DialAddr("garbage"))
}

func TestBulkCertificatesAreCheap(t *testing.T) {
	s := fakekv.Start(t, fakekv.Options{})
	s.AddBulkCertificates("bulk", 5000)
	c := s.TestClient()
	n, pages := 0, 0
	next := "/certificates"
	for next != "" {
		page := c.GetJSON(t, next)
		n += len(get(page, "value").([]any))
		pages++
		next, _ = get(page, "nextLink").(string)
	}
	assert.Equal(t, 5000, n)
	assert.Equal(t, 200, pages)
	v := s.Versions("bulk-04999")[0]
	assert.Equal(t, 200, c.Get(t, "/secrets/bulk-04999/"+v).Status)
}

func TestSecretValueOfUnknownIsNil(t *testing.T) {
	s := fakekv.Start(t, fakekv.Options{})
	assert.Nil(t, s.SecretValue("nope", ""))
	assert.Nil(t, s.Leaf("nope", ""))
	assert.Nil(t, s.Versions("nope"))
	s.AddSecret("plain", "text/plain")
	assert.Contains(t, string(s.SecretValue("plain", "")), "fake-secret-value-")
}

func TestConcurrentUse(t *testing.T) {
	s := fakekv.Start(t, fakekv.Options{})
	s.AddCertificate("web-cert", fakekv.CertOptions{CommonName: "w.example.test", Exportable: true})
	c := s.TestClient()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				if i%2 == 0 {
					s.Renew("web-cert")
				} else {
					_ = c.Get(t, "/certificates/web-cert/versions")
					_ = s.Requests()
				}
			}
		}(i)
	}
	wg.Wait()
	assert.Len(t, s.Versions("web-cert"), 21)
}

func TestRequestLogHoldsNoValues(t *testing.T) {
	s := fakekv.Start(t, fakekv.Options{})
	s.AddBulkCertificates("b", 30)
	c := s.TestClient()
	page := c.GetJSON(t, "/certificates")
	c.GetJSON(t, get(page, "nextLink").(string))
	reqs := s.Requests()
	require.Len(t, reqs, 2)
	assert.Equal(t, []string{"$skiptoken", "api-version", "maxresults"}, reqs[1].Query)
	assert.Equal(t, "/certificates", reqs[1].Path)
	assert.Equal(t, 200, reqs[1].Status)
	s.ClearRequests()
	assert.Empty(t, s.Requests())
}

func TestPanicsOnProgrammerErrors(t *testing.T) {
	s := fakekv.Start(t, fakekv.Options{})
	assert.Panics(t, func() { s.AddCertificate("bad name", fakekv.CertOptions{}) })
	assert.Panics(t, func() { s.Renew("absent") })
	s.AddCertificate("c", fakekv.CertOptions{CommonName: "x"})
	assert.Panics(t, func() { s.AddSecret("c", "text/plain") })
}
