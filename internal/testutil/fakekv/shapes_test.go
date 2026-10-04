package fakekv_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/testutil/fakekv"
)

// optionalKeys are keys the reference marks optional (or that depend on the object): they are
// ignored, with everything beneath them, on both sides.
var optionalKeys = map[string]bool{"nextLink": true, "crv": true, "sans": true, "nbf": true, "exp": true}

// attrKeys are optional where a listing's first item may be a plain secret or key without expiry.
var attrKeys = map[string]bool{"nbf": true, "exp": true}

func readShape(t *testing.T, file string) any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "test", "testdata", "kv-recordings", file))
	require.NoError(t, err)
	var v any
	require.NoError(t, json.Unmarshal(b, &v), file)
	return v
}

// keyPaths returns the sorted set of "path:type" of a JSON value: object keys recursively, array
// elements by their first item (an empty array is just "path:array").
func keyPaths(v any, optional map[string]bool) []string {
	var out []string
	var walk func(path string, v any)
	walk = func(path string, v any) {
		switch x := v.(type) {
		case map[string]any:
			out = append(out, path+":object")
			for k, c := range x {
				if optional[k] {
					continue
				}
				walk(path+"."+k, c)
			}
		case []any:
			out = append(out, path+":array")
			if len(x) > 0 {
				walk(path+"[]", x[0])
			}
		case string:
			out = append(out, path+":string")
		case float64:
			out = append(out, path+":number")
		case bool:
			out = append(out, path+":boolean")
		case nil:
			out = append(out, path+":null")
		}
	}
	walk("", v)
	sort.Strings(out)
	return out
}

func TestKeyPathsHelper(t *testing.T) {
	var v any
	require.NoError(t, json.Unmarshal([]byte(`{"a":[{"b":1,"c":null}],"d":{},"nextLink":"x"}`), &v))
	assert.Equal(t, []string{".a:array", ".a[].b:number", ".a[].c:null", ".a[]:object", ".d:object", ":object"}, keyPaths(v, optionalKeys))
}

// TestAnswersMatchTheReferenceShapes compares the key structure of every fake answer with its
// reference file: the fake may add nothing and omit nothing the reference shows, except optionalKeys.
func TestAnswersMatchTheReferenceShapes(t *testing.T) {
	s := fakekv.Start(t, fakekv.Options{})
	s.AddCertificate("web-cert", fakekv.CertOptions{CommonName: "www.example.test", SANs: []string{"www.example.test"}, Exportable: true})
	s.AddCertificate("pem-cert", fakekv.CertOptions{CommonName: "pem.example.test", Exportable: true, ContentType: "application/x-pem-file"})
	s.AddKey("ec-key", fakekv.KeyOptions{KeyType: "EC", Curve: "P-256", Enabled: true})
	s.AddKey("signing", fakekv.KeyOptions{KeyType: "RSA", Size: 2048, Enabled: true})
	s.AddSecret("db-password", "text/plain")
	c := s.TestClient()
	ver := s.Versions("web-cert")[0]
	pemVer := s.Versions("pem-cert")[0]
	cases := []struct{ file, path string }{
		{"list_certificates.json", "/certificates"},
		{"get_certificate.json", "/certificates/web-cert/"},
		{"get_certificate.json", "/certificates/web-cert/" + ver},
		{"list_certificate_versions.json", "/certificates/web-cert/versions"},
		{"list_keys.json", "/keys"},
		{"get_key_rsa.json", "/keys/signing/"},
		{"get_key_ec.json", "/keys/ec-key/"},
		{"get_key_rsa.json", "/keys/signing/"},
		{"list_secrets.json", "/secrets"},
		{"get_secret_pkcs12.json", "/secrets/web-cert/" + ver},
		{"get_secret_pem.json", "/secrets/pem-cert/" + pemVer},
	}
	for _, tc := range cases {
		got := c.GetJSON(t, tc.path)
		assert.Equal(t, keyPaths(readShape(t, tc.file), optionalKeys), keyPaths(got, optionalKeys), tc.file+" "+tc.path)
	}
	// An RSA certificate: the same bundle shape, no crv.
	s.AddCertificate("rsa-cert", fakekv.CertOptions{CommonName: "rsa.example.test", KeyType: "rsa2048", Exportable: true})
	got := c.GetJSON(t, "/certificates/rsa-cert/")
	assert.Equal(t, keyPaths(readShape(t, "get_certificate.json"), optionalKeys), keyPaths(got, optionalKeys))
}

// TestPagedListingsKeepTheNextLinkShape compares full first pages, nextLink included.
func TestPagedListingsKeepTheNextLinkShape(t *testing.T) {
	s := fakekv.Start(t, fakekv.Options{})
	s.AddBulkCertificates("bulk", 30)
	for i := 0; i < 30; i++ {
		s.AddSecret(fmt.Sprintf("plain-%02d", i), "text/plain")
		s.AddKey(fmt.Sprintf("key-%02d", i), fakekv.KeyOptions{KeyType: "EC", Curve: "P-256", Enabled: true})
	}
	c := s.TestClient()
	for file, path := range map[string]string{
		"list_certificates.json": "/certificates", "list_keys.json": "/keys", "list_secrets.json": "/secrets",
		"list_certificate_versions.json": "/certificates/bulk-00000/versions?maxresults=1",
	} {
		if file == "list_certificate_versions.json" {
			s.Renew("bulk-00000")
		}
		got := c.GetJSON(t, path)
		assert.Equal(t, keyPaths(readShape(t, file), attrKeys), keyPaths(got, attrKeys), file)
	}
}

func TestErrorAnswersMatchTheReferenceShapes(t *testing.T) {
	s := fakekv.Start(t, fakekv.Options{})
	s.AddCertificate("web-cert", fakekv.CertOptions{CommonName: "www.example.test", Exportable: true})
	c := s.TestClient()
	check := func(file string, r fakekv.Response, status int) {
		t.Helper()
		assert.Equal(t, status, r.Status, file)
		assert.Equal(t, keyPaths(readShape(t, file), nil), keyPaths(r.JSON(t), nil), file)
	}
	check("error_not_found.json", c.Get(t, "/certificates/absent/"), 404)
	s.RevokeRole("certificates/list")
	check("error_forbidden_rbac.json", c.Get(t, "/certificates"), 403)
	s.GrantRole("certificates/list")
	s2 := fakekv.Start(t, fakekv.Options{Model: "access_policy"})
	s2.RevokeRole("certificates/list")
	check("error_forbidden_policy.json", s2.TestClient().Get(t, "/certificates"), 403)
	s.Firewall("203.0.113.7")
	r := c.Get(t, "/certificates")
	check("error_forbidden_firewall.json", r, 403)
	assert.Contains(t, string(r.Body), "Client address: 203.0.113.7")
}

var (
	guidRE   = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)
	base64RE = regexp.MustCompile(`^[A-Za-z0-9+/_-]{32,}={0,2}$`)
)

// TestReferenceFilesHoldPlaceholders: the recorded shapes never hold a real or generated value.
func TestReferenceFilesHoldPlaceholders(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "..", "test", "testdata", "kv-recordings", "*.json"))
	require.NoError(t, err)
	require.NotEmpty(t, files)
	for _, f := range files {
		b, err := os.ReadFile(f)
		require.NoError(t, err)
		var v any
		require.NoError(t, json.Unmarshal(b, &v), f)
		var walk func(v any)
		walk = func(v any) {
			switch x := v.(type) {
			case map[string]any:
				for _, c := range x {
					walk(c)
				}
			case []any:
				for _, c := range x {
					walk(c)
				}
			case string:
				assert.Less(t, len(x), 200, f)
				assert.False(t, guidRE.MatchString(x), "%s: a GUID %q", f, x)
				assert.False(t, base64RE.MatchString(x), "%s: a base64-looking value %q", f, x)
				assert.False(t, strings.Contains(x, "eyJ"), "%s: a JWT-looking value %q", f, x)
			}
		}
		walk(v)
	}
}
