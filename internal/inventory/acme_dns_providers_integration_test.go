//go:build integration

package inventory_test

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/acme/solver/dnssolver"
	"alice/internal/certs"
	"alice/internal/inventory"
	"alice/internal/platform/azureid"
	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/secrets"
	"alice/internal/testutil/fakeacme"
	"alice/internal/testutil/pki"
)

// runtimeSecret is a credential made for one test (no secret-looking literal in the source).
func runtimeSecret(t *testing.T, prefix string) string {
	t.Helper()
	b := make([]byte, 20)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return prefix + hex.EncodeToString(b)
}

func dnsFieldsOf(t *testing.T, err error) []string {
	t.Helper()
	var errs validate.Errors
	require.ErrorAs(t, err, &errs)
	out := make([]string, 0, len(errs))
	for _, fe := range errs {
		out = append(out, fe.Field)
	}
	return out
}

const (
	dnsTenant = "11111111-2222-3333-4444-555555555555"
	dnsClient = "66666666-7777-8888-9999-000000000000"
	dnsSub    = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
)

// A Cloudflare provider: created without a network call, its token sealed and never shown, stored or audited in the
// clear; its solver configuration builds a working solver; a hook's fields and other kinds' fields are refused.
func TestACMEDNSProviderCloudflareLifecycle(t *testing.T) {
	w := newRegistryWorld(t, fakeacme.Options{})
	token := runtimeSecret(t, "cf-")
	before := w.requests()
	h, err := w.svc.CreateACMEHook(w.ctx, w.admin, inventory.ACMEHookInput{Kind: inventory.ACMEHookKindCloudflare, Name: "Cloudflare",
		Credentials: inventory.ACMEDNSCredentials{APIToken: secrets.NewPlaintext([]byte(token))}, AllowedSuffixes: []string{"example.test"}})
	require.NoError(t, err)
	assert.Equal(t, before, w.requests(), "creating a provider contacts nobody")
	assert.Equal(t, inventory.ACMEHookKindCloudflare, h.Kind)
	assert.Equal(t, inventory.ACMEDNSSettings{}, h.Settings)
	assert.True(t, h.SecretConfigured)
	assert.Empty(t, h.URL)
	assert.Equal(t, inventory.DefaultACMEPropagationWaitSeconds, h.PropagationWaitSeconds)
	d := w.auditDetails("acme.hook.created")
	require.Len(t, d, 1)
	assert.Equal(t, []string{"allowed_suffixes", "kind", "name", "poll_timeout_seconds", "propagation_wait_seconds"}, detailKeys(d[0]))
	assert.Equal(t, "cloudflare", d[0]["kind"])

	cfg, err := w.svc.ACMEHookSolverConfig(w.ctx, h.ID)
	require.NoError(t, err)
	assert.Equal(t, dnssolver.KindCloudflare, cfg.Kind)
	assert.Equal(t, token, string(cfg.Cloudflare.APIToken.Bytes()))
	assert.Equal(t, []string{"example.test"}, cfg.AllowedSuffixes)
	assert.NotContains(t, fmt.Sprintf("%v %+v %#v", cfg, cfg, cfg), token)
	s, err := dnssolver.New(cfg)
	require.NoError(t, err)
	dnssolver.Close(s)
	cfg.Zero()
	assert.NotContains(t, w.allRows(), token)

	// A new token replaces the stored one; a hook's fields and another kind's are refused.
	next := runtimeSecret(t, "cf-")
	_, err = w.svc.UpdateACMEHook(w.ctx, w.admin, h.ID, inventory.ACMEHookPatch{Credentials: inventory.ACMEDNSCredentials{APIToken: secrets.NewPlaintext([]byte(next))}})
	require.NoError(t, err)
	assert.Equal(t, "credentials", w.auditDetails("acme.hook.updated")[0]["fields"])
	cfg, err = w.svc.ACMEHookSolverConfig(w.ctx, h.ID)
	require.NoError(t, err)
	assert.Equal(t, next, string(cfg.Cloudflare.APIToken.Bytes()))
	cfg.Zero()
	url, bundle := "https://dns.example/hook", "-----BEGIN CERTIFICATE-----"
	_, err = w.svc.UpdateACMEHook(w.ctx, w.admin, h.ID, inventory.ACMEHookPatch{URL: &url, CABundlePEM: &bundle,
		Secret: secrets.NewPlaintext([]byte("0123456789abcdef")), Settings: &inventory.ACMEDNSSettings{TenantID: dnsTenant},
		Credentials: inventory.ACMEDNSCredentials{SecretAccessKey: secrets.NewPlaintext([]byte("abcdefghijklmnopqrstuvwxyz"))}})
	assert.ElementsMatch(t, []string{"ca_bundle_pem", "secret", "url", "tenant_id", "secret_access_key"}, dnsFieldsOf(t, err))
	_, err = w.svc.CreateACMEHook(w.ctx, w.admin, inventory.ACMEHookInput{Kind: inventory.ACMEHookKindCloudflare, Name: "short",
		Credentials: inventory.ACMEDNSCredentials{APIToken: secrets.NewPlaintext([]byte("short"))}})
	assert.Equal(t, []string{"api_token"}, dnsFieldsOf(t, err))
	_, err = w.svc.CreateACMEHook(w.ctx, w.admin, inventory.ACMEHookInput{Kind: inventory.ACMEHookKindCloudflare, Name: "spaced",
		Credentials: inventory.ACMEDNSCredentials{APIToken: secrets.NewPlaintext([]byte("with a space in the middle of it"))}})
	assert.Equal(t, []string{"api_token"}, dnsFieldsOf(t, err))
	_, err = w.svc.CreateACMEHook(w.ctx, w.admin, inventory.ACMEHookInput{Kind: inventory.ACMEHookKindCloudflare, Name: "none"})
	assert.Equal(t, []string{"api_token"}, dnsFieldsOf(t, err))
	_, err = w.svc.CreateACMEHook(w.ctx, w.admin, inventory.ACMEHookInput{Kind: "bind9", Name: "bind"})
	assert.Equal(t, []string{"kind"}, dnsFieldsOf(t, err))
	_, err = w.svc.CreateACMEHook(w.ctx, w.admin, inventory.ACMEHookInput{Name: "hook with settings", URL: "https://dns.example/hook",
		Secret: secrets.NewPlaintext([]byte("0123456789abcdef")), Settings: inventory.ACMEDNSSettings{AccessKeyID: "X"},
		Credentials: inventory.ACMEDNSCredentials{APIToken: secrets.NewPlaintext([]byte(next))}})
	assert.Equal(t, []string{"settings", "credentials"}, dnsFieldsOf(t, err))

	require.NoError(t, w.svc.DeleteACMEHook(w.ctx, w.admin, h.ID))
	assert.Equal(t, []map[string]string{{"name": "Cloudflare", "kind": "cloudflare"}}, w.auditDetails("acme.hook.deleted"))
	cfg, err = w.svc.ACMEHookCleanupConfig(w.ctx, h.ID)
	require.NoError(t, err, "a deleted provider still cleans up what it published")
	assert.Equal(t, next, string(cfg.Cloudflare.APIToken.Bytes()))
	cfg.Zero()
}

// Azure DNS: the Key Vault credential's sign-in rules (client secret, certificate, managed identity), the subscription
// and resource group, credentials kept while the sign-in method stays and required again when it changes.
func TestACMEDNSProviderAzureLifecycle(t *testing.T) {
	w := newRegistryWorld(t, fakeacme.Options{})
	secret := runtimeSecret(t, "az-")
	h, err := w.svc.CreateACMEHook(w.ctx, w.admin, inventory.ACMEHookInput{Kind: inventory.ACMEHookKindAzureDNS, Name: "Azure DNS",
		Settings: inventory.ACMEDNSSettings{Auth: providers.AzureAuthClientSecret, TenantID: "11111111-2222-3333-4444-555555555555 ",
			ClientID: dnsClient, SubscriptionID: "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE", ResourceGroup: "dns-rg"},
		Credentials: inventory.ACMEDNSCredentials{ClientSecret: secrets.NewPlaintext([]byte(secret))}, AllowedSuffixes: []string{"example.test"}})
	require.NoError(t, err)
	assert.Equal(t, inventory.ACMEDNSSettings{Auth: providers.AzureAuthClientSecret, TenantID: dnsTenant, ClientID: dnsClient,
		SubscriptionID: dnsSub, ResourceGroup: "dns-rg"}, h.Settings)
	d := w.auditDetails("acme.hook.created")[0]
	assert.Equal(t, map[string]string{"kind": "azure_dns", "auth": "client_secret", "tenant_id": dnsTenant, "client_id": dnsClient,
		"subscription_id": dnsSub, "resource_group": "dns-rg", "name": "Azure DNS", "allowed_suffixes": "example.test",
		"propagation_wait_seconds": "5", "poll_timeout_seconds": "60"}, d)
	cfg, err := w.svc.ACMEHookSolverConfig(w.ctx, h.ID)
	require.NoError(t, err)
	assert.Equal(t, secret, string(cfg.AzureDNS.ClientSecret.Bytes()))
	assert.Equal(t, dnsSub, cfg.AzureDNS.SubscriptionID)
	assert.Equal(t, "dns-rg", cfg.AzureDNS.ResourceGroup)
	assert.Equal(t, providers.AzureAuthClientSecret, cfg.AzureDNS.Auth)
	cfg.Zero()

	// Another resource group keeps the secret; another method needs its credential.
	_, err = w.svc.UpdateACMEHook(w.ctx, w.admin, h.ID, inventory.ACMEHookPatch{Settings: &inventory.ACMEDNSSettings{
		Auth: providers.AzureAuthClientSecret, TenantID: dnsTenant, ClientID: dnsClient, SubscriptionID: dnsSub, ResourceGroup: "other-rg"}})
	require.NoError(t, err)
	assert.Equal(t, "settings", w.auditDetails("acme.hook.updated")[0]["fields"])
	cfg, err = w.svc.ACMEHookSolverConfig(w.ctx, h.ID)
	require.NoError(t, err)
	assert.Equal(t, secret, string(cfg.AzureDNS.ClientSecret.Bytes()), "the stored secret stays")
	cfg.Zero()
	_, err = w.svc.UpdateACMEHook(w.ctx, w.admin, h.ID, inventory.ACMEHookPatch{Settings: &inventory.ACMEDNSSettings{
		Auth: providers.AzureAuthCertificate, TenantID: dnsTenant, ClientID: dnsClient, SubscriptionID: dnsSub, ResourceGroup: "other-rg"}})
	assert.Equal(t, []string{"certificate"}, dnsFieldsOf(t, err))

	// A certificate: its thumbprint and expiry are shown, its key sealed.
	leaf := pki.SelfSigned("sp.example.test", pki.RSA2048, w.clock.Now())
	up, err := w.svc.UpdateACMEHook(w.ctx, w.admin, h.ID, inventory.ACMEHookPatch{Settings: &inventory.ACMEDNSSettings{
		Auth: providers.AzureAuthCertificate, TenantID: dnsTenant, ClientID: dnsClient, SubscriptionID: dnsSub, ResourceGroup: "other-rg"},
		Credentials: inventory.ACMEDNSCredentials{Certificate: certs.Upload{CertificatePEM: leaf.CertPEM, PrivateKeyPEM: leaf.KeyPEM}}})
	require.NoError(t, err)
	assert.Equal(t, azureid.ThumbprintOf(leaf.Cert.Raw), up.Settings.CertThumbprint)
	assert.Equal(t, leaf.Cert.NotAfter.UTC(), *up.Settings.CertNotAfter)
	assert.Equal(t, "settings,credentials", w.auditDetails("acme.hook.updated")[1]["fields"])
	cfg, err = w.svc.ACMEHookSolverConfig(w.ctx, h.ID)
	require.NoError(t, err)
	assert.Equal(t, leaf.Cert.Raw, cfg.AzureDNS.CertificateDER)
	assert.NotEmpty(t, cfg.AzureDNS.PrivateKeyDER.Bytes())
	assert.Empty(t, cfg.AzureDNS.ClientSecret.Bytes(), "the old secret is gone")
	cfg.Zero()
	for _, m := range secretMarkers(t, leaf.Key) {
		assert.NotContains(t, w.allRows(), m)
	}

	// A managed identity has no secret; it keeps its thumbprint-less settings.
	up, err = w.svc.UpdateACMEHook(w.ctx, w.admin, h.ID, inventory.ACMEHookPatch{Settings: &inventory.ACMEDNSSettings{
		Auth: providers.AzureAuthManagedIdentity, SubscriptionID: dnsSub, ResourceGroup: "other-rg"}})
	require.NoError(t, err)
	assert.Empty(t, up.Settings.CertThumbprint)
	cfg, err = w.svc.ACMEHookSolverConfig(w.ctx, h.ID)
	require.NoError(t, err)
	assert.Empty(t, cfg.AzureDNS.PrivateKeyDER.Bytes())
	assert.Empty(t, cfg.AzureDNS.CertificateDER)
	assert.Equal(t, providers.AzureAuthManagedIdentity, cfg.AzureDNS.Auth)
	cfg.Zero()

	// Refusals.
	_, err = w.svc.CreateACMEHook(w.ctx, w.admin, inventory.ACMEHookInput{Kind: inventory.ACMEHookKindAzureDNS, Name: "bad",
		Settings: inventory.ACMEDNSSettings{Auth: "password", SubscriptionID: "not-a-guid", ResourceGroup: "bad/rg", AccessKeyID: "X"}})
	assert.ElementsMatch(t, []string{"access_key_id", "auth", "subscription_id", "resource_group"}, dnsFieldsOf(t, err))
	_, err = w.svc.CreateACMEHook(w.ctx, w.admin, inventory.ACMEHookInput{Kind: inventory.ACMEHookKindAzureDNS, Name: "bad",
		Settings:    inventory.ACMEDNSSettings{Auth: providers.AzureAuthClientSecret, ResourceGroup: "rg."},
		Credentials: inventory.ACMEDNSCredentials{APIToken: secrets.NewPlaintext([]byte(secret))}})
	assert.ElementsMatch(t, []string{"api_token", "tenant_id", "client_id", "client_secret", "subscription_id", "resource_group"}, dnsFieldsOf(t, err))
}

// Route 53: the access key ID shown and audited, the secret sealed; an optional role with an external ID; a new key ID
// needs its secret.
func TestACMEDNSProviderRoute53Lifecycle(t *testing.T) {
	w := newRegistryWorld(t, fakeacme.Options{})
	secret := runtimeSecret(t, "r53/")
	role := "arn:aws:iam::123456789012:role/alice-dns"
	h, err := w.svc.CreateACMEHook(w.ctx, w.admin, inventory.ACMEHookInput{Kind: inventory.ACMEHookKindRoute53, Name: "Route 53",
		Settings:    inventory.ACMEDNSSettings{AccessKeyID: "TESTACCESSKEYID0001", RoleARN: role, ExternalID: "alice-external"},
		Credentials: inventory.ACMEDNSCredentials{SecretAccessKey: secrets.NewPlaintext([]byte(secret))}, AllowedSuffixes: []string{"example.test"}})
	require.NoError(t, err)
	assert.Equal(t, inventory.ACMEDNSSettings{AccessKeyID: "TESTACCESSKEYID0001", RoleARN: role, ExternalID: "alice-external"}, h.Settings)
	d := w.auditDetails("acme.hook.created")[0]
	assert.Equal(t, "TESTACCESSKEYID0001", d["access_key_id"])
	assert.Equal(t, role, d["role_arn"])
	assert.Equal(t, "true", d["external_id_set"])
	assert.NotContains(t, fmt.Sprint(d), "alice-external")
	cfg, err := w.svc.ACMEHookSolverConfig(w.ctx, h.ID)
	require.NoError(t, err)
	assert.Equal(t, secret, string(cfg.Route53.SecretAccessKey.Bytes()))
	assert.Equal(t, role, cfg.Route53.RoleARN)
	assert.Equal(t, "alice-external", cfg.Route53.ExternalID)
	cfg.Zero()
	assert.NotContains(t, w.allRows(), secret)

	// The role goes, the secret stays; a new key ID needs its secret.
	_, err = w.svc.UpdateACMEHook(w.ctx, w.admin, h.ID, inventory.ACMEHookPatch{Settings: &inventory.ACMEDNSSettings{AccessKeyID: "TESTACCESSKEYID0001"}})
	require.NoError(t, err)
	cfg, err = w.svc.ACMEHookSolverConfig(w.ctx, h.ID)
	require.NoError(t, err)
	assert.Equal(t, secret, string(cfg.Route53.SecretAccessKey.Bytes()))
	assert.Empty(t, cfg.Route53.RoleARN)
	cfg.Zero()
	_, err = w.svc.UpdateACMEHook(w.ctx, w.admin, h.ID, inventory.ACMEHookPatch{Settings: &inventory.ACMEDNSSettings{AccessKeyID: "TESTACCESSKEYID0002"}})
	assert.Equal(t, []string{"secret_access_key"}, dnsFieldsOf(t, err))
	// A patch that changes nothing writes nothing.
	n := w.audits("acme.hook.updated")
	_, err = w.svc.UpdateACMEHook(w.ctx, w.admin, h.ID, inventory.ACMEHookPatch{Settings: &inventory.ACMEDNSSettings{AccessKeyID: "TESTACCESSKEYID0001"}})
	require.NoError(t, err)
	assert.Equal(t, n, w.audits("acme.hook.updated"))

	_, err = w.svc.CreateACMEHook(w.ctx, w.admin, inventory.ACMEHookInput{Kind: inventory.ACMEHookKindRoute53, Name: "bad",
		Settings:    inventory.ACMEDNSSettings{AccessKeyID: "lower-case", RoleARN: "arn:aws:iam::1:user/x", ExternalID: "x", TenantID: dnsTenant},
		Credentials: inventory.ACMEDNSCredentials{SecretAccessKey: secrets.NewPlaintext([]byte("short"))}})
	assert.ElementsMatch(t, []string{"tenant_id", "access_key_id", "role_arn", "external_id", "secret_access_key"}, dnsFieldsOf(t, err))
	_, err = w.svc.CreateACMEHook(w.ctx, w.admin, inventory.ACMEHookInput{Kind: inventory.ACMEHookKindRoute53, Name: "bad",
		Settings:    inventory.ACMEDNSSettings{AccessKeyID: "TESTACCESSKEYID0001", ExternalID: "without-a-role"},
		Credentials: inventory.ACMEDNSCredentials{SecretAccessKey: secrets.NewPlaintext([]byte(secret))}})
	assert.Equal(t, []string{"external_id"}, dnsFieldsOf(t, err))
}
