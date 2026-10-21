//go:build integration

package api

import (
	"crypto/x509"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/acme/solver/dnsapi"
	"alice/internal/testutil/fakecloudflare"
	"alice/internal/testutil/fakekv"
	"alice/internal/testutil/fakeroute53"
	"alice/internal/testutil/pki"
)

// Secret-leak suite of the built-in DNS providers (R57). Each provider is added through the API with canary
// credentials (a Cloudflare token, an AWS secret access key, an Azure client secret, and an Azure sign-in certificate's
// private key), its credentials replaced once, and a Test run goes through each of the three fakes, which accept the
// canaries (so every credential really travels, to the fakes only) and mirror their records into the fake CA. Then
// the API's answers (every list and detail of the publishers, the audit log, the jobs), every row of every table,
// the captured logs and the rendered e-mails are scanned for every canary.
func TestDNSProviderCredentialsNeverLeak(t *testing.T) {
	pool := x509.NewCertPool()
	stackACMERoots = func() (*x509.CertPool, error) { return pool, nil }
	defer func() { stackACMERoots = nil }()
	w := newACMELeakWorld(t)
	providerID, _ := w.setUp()

	cfToken, awsSecret, azSecret := canary("cloudflare-token"), canary("aws-secret-key"), canary("azure-client-secret")
	cf := fakecloudflare.Start(t, fakecloudflare.Options{Token: cfToken, Zones: []string{"example.test"}, Sink: w.fake})
	r53 := fakeroute53.Start(t, fakeroute53.Options{AccessKeyID: "TESTACCESSKEYID0001", SecretAccessKey: awsSecret,
		Zones: []fakeroute53.Zone{{Name: "example.test"}}, InsyncAfter: 1, Sink: w.fake})
	az := fakekv.Start(t, fakekv.Options{Secret: azSecret, DNSZones: []string{"example.test"}, DNSSink: w.fake})
	for _, pem := range [][]byte{cf.CAPEM(), r53.CAPEM(), az.CAPEM()} {
		require.True(t, pool.AppendCertsFromPEM(pem))
	}
	defer dnsapi.MapAddressesForTest(func(hp string) string {
		for _, m := range []func(string) string{cf.MapAddr, r53.MapAddr, az.DialAddr} {
			if a := m(hp); a != hp {
				return a
			}
		}
		return hp
	})()

	add := func(body map[string]any) string {
		t.Helper()
		body["allowed_suffixes"] = []string{"example.test"}
		body["propagation_wait_seconds"] = 0
		rec := w.admin.do(http.MethodPost, "/api/v1/acme/hooks", body)
		requireStatus(t, rec, http.StatusCreated)
		return decodeBody[map[string]any](t, rec)["id"].(string)
	}
	cfID := add(map[string]any{"kind": "cloudflare", "name": "Cloudflare", "api_token": cfToken})
	r53ID := add(map[string]any{"kind": "route53", "name": "Route 53", "access_key_id": "TESTACCESSKEYID0001", "secret_access_key": awsSecret})
	azID := add(map[string]any{"kind": "azure_dns", "name": "Azure DNS", "auth": "client_secret", "tenant_id": az.TenantID(),
		"client_id": az.ClientID(), "subscription_id": az.DNSSubscriptionID(), "resource_group": az.DNSResourceGroup(), "client_secret": azSecret})
	leaf := pki.SelfSigned("sp.example.test", pki.RSA2048, w.clock.Now())
	certID := add(map[string]any{"kind": "azure_dns", "name": "Azure DNS (certificate)", "auth": "certificate", "tenant_id": az.TenantID(),
		"client_id": az.ClientID(), "subscription_id": az.DNSSubscriptionID(), "resource_group": az.DNSResourceGroup(),
		"certificate_pem": string(leaf.CertPEM), "private_key_pem": string(leaf.KeyPEM)})
	// Replacing credentials: the new ones are canaries too (and the old ones must be gone from the answers as well).
	cfNext := canary("cloudflare-token-next")
	requireStatus(t, w.admin.do(http.MethodPatch, "/api/v1/acme/hooks/"+cfID, map[string]any{"api_token": cfNext}), http.StatusOK)

	// A Test run through each provider (Cloudflare after the fake learns the new token).
	cf2 := fakecloudflare.Start(t, fakecloudflare.Options{Token: cfNext, Zones: []string{"example.test"}, Sink: w.fake})
	require.True(t, pool.AppendCertsFromPEM(cf2.CAPEM()))
	cf.Close()
	defer dnsapi.MapAddressesForTest(func(hp string) string {
		for _, m := range []func(string) string{cf2.MapAddr, r53.MapAddr, az.DialAddr} {
			if a := m(hp); a != hp {
				return a
			}
		}
		return hp
	})()
	for _, hook := range []string{cfID, r53ID, azID} {
		rec := w.defineCert(providerID, hook, "www.example.test")
		requireStatus(t, rec, http.StatusCreated)
		id := decodeBody[map[string]any](t, rec)["id"].(string)
		requireStatus(t, w.op.do(http.MethodPost, "/api/v1/acme/certificates/"+id+"/test", nil), http.StatusAccepted)
		w.runJobs()
		rec = w.admin.do(http.MethodGet, "/api/v1/acme/certificates/"+id+"/orders", nil)
		requireStatus(t, rec, http.StatusOK)
		orders := decodeBody[struct {
			Items []map[string]any `json:"items"`
		}](t, rec).Items
		require.NotEmpty(t, orders)
		assert.Equal(t, "succeeded", orders[0]["state"], "the Test run through %s: %v", hook, orders[0])
	}
	assert.Positive(t, cf2.Counters()["create"], "the Cloudflare token travelled to the fake")
	assert.Positive(t, r53.Counters()["change"], "the AWS key signed requests to the fake")
	assert.NotEmpty(t, az.LastAccessToken(), "the Azure client secret signed in at the fake")

	// Every answer of the API that names a publisher.
	for _, p := range []string{"/api/v1/acme/hooks", "/api/v1/acme/hooks/" + cfID, "/api/v1/acme/hooks/" + r53ID, "/api/v1/acme/hooks/" + azID,
		"/api/v1/acme/hooks/" + certID, "/api/v1/audit?limit=200", "/api/v1/jobs", "/api/v1/acme/certificates"} {
		requireStatus(t, w.admin.do(http.MethodGet, p, nil), http.StatusOK)
	}

	secs := []secretValue{textCanary("Cloudflare token", cfToken), textCanary("Cloudflare token (replaced)", cfNext),
		textCanary("AWS secret access key", awsSecret), textCanary("Azure client secret", azSecret)}
	secs = append(secs, keyCanaries("Azure sign-in key", leaf.Key, leaf.Cert)...)
	assert.Empty(t, w.acmeLeaks(secs, map[string]string{}))
}
