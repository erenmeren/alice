package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --dns-providers: the fake Cloudflare and Route 53 answer on the CA's listener for their own host names, with
// certificates the CA file serve wrote makes trusted, and a TXT value created at Cloudflare reaches the CA's DNS.
func TestDNSProvidersThroughTheTool(t *testing.T) {
	st := startStack(t, func(c *serveConfig) { c.DNSProviders = true })
	creds := st.ctlJSON("dns-providers")
	assert.Equal(t, "example.test", creds["zone"])
	token := creds["cloudflare"].(map[string]any)["token"].(string)
	require.NotEmpty(t, token)
	assert.NotEmpty(t, creds["route53"].(map[string]any)["secret_access_key"])
	c := st.client()
	do := func(method, url, body string) map[string]any {
		t.Helper()
		req, err := http.NewRequestWithContext(context.Background(), method, url, strings.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.Do(req)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		var m map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&m))
		return m
	}
	zones := do(http.MethodGet, "https://api.cloudflare.com/client/v4/zones?name=example.test", "")["result"].([]any)
	require.Len(t, zones, 1)
	id := zones[0].(map[string]any)["id"].(string)
	created := do(http.MethodPost, "https://api.cloudflare.com/client/v4/zones/"+id+"/dns_records",
		`{"type":"TXT","name":"_acme-challenge.www.example.test","content":"\"tool-value\"","ttl":60}`)
	assert.Equal(t, true, created["success"])
	assert.Equal(t, []any{"tool-value"}, st.ctlJSON("dns", "list")["_acme-challenge.www.example.test"])
	records := st.ctlJSON("dns-providers")["cloudflare"].(map[string]any)["records"].(map[string]any)
	assert.Equal(t, []any{"tool-value"}, records["_acme-challenge.www.example.test"])

	// Route 53 and STS answer for their names (an unsigned request is refused as AWS refuses it).
	for _, u := range []string{"https://route53.amazonaws.com/2013-04-01/hostedzonesbyname?dnsname=example.test", "https://sts.amazonaws.com/"} {
		resp, err := c.Get(u) //nolint:noctx // test
		require.NoError(t, err, u)
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode, u)
	}
	// The CA still answers for its own name.
	resp, err := c.Get("https://acme.test.alice/directory") //nolint:noctx // test
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	// The admin route is a GET.
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://"+st.admin+"/dns-providers", nil)
	require.NoError(t, err)
	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
}

func TestHostOnly(t *testing.T) {
	assert.Equal(t, "api.cloudflare.com", hostOnly("API.Cloudflare.com:443"))
	assert.Equal(t, "sts.amazonaws.com", hostOnly("sts.amazonaws.com."))
}
