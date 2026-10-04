package azurekv

import (
	"bytes"
	"encoding/json"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The recorder of the optional real-Azure suite (record_test.go, tag azure) writes what shapeOf
// returns. It lives here, without the tag, so that its redaction is tested on every run.

var idRE = regexp.MustCompile(`^https://[^/]+/(certificates|keys|secrets)/([^/?]+)(/[^/?]+)?$`)

// encodeShape writes a shape the way the recordings are written: indented, no HTML escaping, so
// the placeholders read <cer>, not \u003ccer\u003e.
func encodeShape(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	err := enc.Encode(v)
	return b.Bytes(), err
}

// placeholders by key name: key material and identifiers that must never be recorded.
var placeholders = map[string]string{"cer": "<cer>", "x5t": "<x5t>", "x5t#S256": "<x5t>", "value": "<value>", "n": "<n>", "e": "<e>", "x": "<x>", "y": "<y>",
	"subject": "CN=<subject>"}

// literal keeps the strings that are values of a closed set, never customer text.
var literal = map[string]bool{"recoveryLevel": true, "contentType": true, "kty": true, "crv": true, "action_type": true}

// shapeOf keeps the keys and types of a document and replaces its strings with placeholders.
func shapeOf(key string, v any) any {
	switch x := v.(type) {
	case map[string]any:
		if key == "tags" {
			return map[string]any{} // the keys are the customer's
		}
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = shapeOf(k, e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = shapeOf(key, e)
		}
		return out
	case string:
		if p, ok := placeholders[key]; ok {
			return p
		}
		if literal[key] && (key != "contentType" || x == contentTypePKCS12 || x == contentTypePEM) {
			return x // a plain secret's content type is the customer's free text
		}
		if key == "dns_names" {
			return "<dns>"
		}
		if key == "nextLink" {
			return "https://<vault>.vault.azure.net:443/<kind>?api-version=2025-07-01&$skiptoken=<token>&maxresults=25"
		}
		if m := idRE.FindStringSubmatch(x); m != nil {
			if m[3] != "" {
				return "https://<vault>.vault.azure.net/" + m[1] + "/<name>/<version>"
			}
			return "https://<vault>.vault.azure.net/" + m[1] + "/<name>"
		}
		return "<string>"
	}
	return v
}

func TestShapeOfKeepsNoCustomerOrKeyMaterial(t *testing.T) {
	const doc = `{"id":"https://acme.vault.azure.net/certificates/payroll/0123456789abcdef0123456789abcdef","x5t":"c2VjcmV0","cer":"TUlJ",
	  "value":"c2VjcmV0cGZ4","attributes":{"enabled":true,"nbf":1700000000,"recoveryLevel":"Recoverable"},
	  "tags":{"owner-jane-doe":"finance","cost-centre":"1234"},
	  "contentType":"my payroll export, do not share",
	  "policy":{"x509_props":{"subject":"CN=payroll.acme.example","sans":{"dns_names":["payroll.acme.example"]}},
	            "issuer":{"name":"AcmePrivateCA"},"key_props":{"kty":"RSA","key_size":2048}},
	  "key":{"n":"AQAB","e":"AQAB","kid":"https://acme.vault.azure.net/keys/payroll/0123456789abcdef0123456789abcdef"},
	  "nextLink":"https://acme.vault.azure.net:443/certificates?api-version=2025-07-01&$skiptoken=abc&maxresults=25",
	  "list":[{"id":"https://acme.vault.azure.net/secrets/db-password"}]}`
	var in any
	require.NoError(t, json.Unmarshal([]byte(doc), &in))
	out, err := encodeShape(shapeOf("", in))
	require.NoError(t, err)
	got := string(out)
	for _, leak := range []string{"acme", "payroll", "owner-jane-doe", "cost-centre", "finance", "c2VjcmV0", "TUlJ", "0123456789abcdef", "AcmePrivateCA", "payroll export", "db-password", "skiptoken=abc", "AQAB"} {
		assert.NotContains(t, got, leak)
	}
	for _, kept := range []string{`"enabled": true`, `"nbf": 1700000000`, `"contentType": "<string>"`, `"recoveryLevel": "Recoverable"`, `"kty": "RSA"`, `"key_size": 2048`, `"tags": {}`,
		"https://<vault>.vault.azure.net/certificates/<name>/<version>", "https://<vault>.vault.azure.net/secrets/<name>", `"cer": "<cer>"`} {
		assert.Contains(t, got, kept)
	}
}
