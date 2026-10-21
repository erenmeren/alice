//go:build integration

package acmejobs

import (
	"crypto/x509"
	"encoding/base64"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/acme"
	"alice/internal/acme/solver/dnsapi"
	"alice/internal/inventory"
	"alice/internal/providers"
	"alice/internal/secrets"
	"alice/internal/testutil/fakecloudflare"
	"alice/internal/testutil/fakekv"
	"alice/internal/testutil/fakeroute53"
)

// dnsWorld is the job world with the three fake DNS providers, each mirroring its TXT values into the fake CA's DNS
// (so the CA validates what the provider published), every provider host mapped to its fake, and the fakes' CAs as
// the inventory's trust (ACMERoots, as the e2e build's).
type dnsWorld struct {
	*world
	cf  *fakecloudflare.Server
	r53 *fakeroute53.Server
	az  *fakekv.Server
}

func newDNSWorld(t *testing.T) *dnsWorld {
	t.Helper()
	pool := x509.NewCertPool()
	w := &dnsWorld{}
	w.world = newWorldWith(t, func() (*x509.CertPool, error) { return pool, nil })
	w.cf = fakecloudflare.Start(t, fakecloudflare.Options{Zones: []string{"example.test"}, Sink: w.fake})
	w.r53 = fakeroute53.Start(t, fakeroute53.Options{Zones: []fakeroute53.Zone{{Name: "example.test"}}, InsyncAfter: 1, Sink: w.fake})
	w.az = fakekv.Start(t, fakekv.Options{DNSZones: []string{"example.test"}, DNSSink: w.fake})
	for _, pem := range [][]byte{w.cf.CAPEM(), w.r53.CAPEM(), w.az.CAPEM()} {
		require.True(t, pool.AppendCertsFromPEM(pem))
	}
	restore := dnsapi.MapAddressesForTest(func(hp string) string {
		for _, m := range []func(string) string{w.cf.MapAddr, w.r53.MapAddr, w.az.DialAddr} {
			if a := m(hp); a != hp {
				return a
			}
		}
		return hp
	})
	t.Cleanup(restore)
	return w
}

// provider adds a DNS provider of kind with in's settings and credentials (allowed for example.test, no wait).
func (w *dnsWorld) dnsProvider(kind string, in inventory.ACMEHookInput) inventory.ACMEHook {
	w.t.Helper()
	none := 0
	in.Kind, in.Name, in.AllowedSuffixes, in.PropagationWaitSeconds, in.PollTimeoutSeconds = kind, in.Name+kind+" dns", []string{"example.test"}, &none, 30
	h, err := w.inv.CreateACMEHook(w.ctx, w.admin, in)
	require.NoError(w.t, err)
	return h
}

func (w *dnsWorld) certVia(hook uuid.UUID, names ...string) inventory.ACMECertificate {
	w.t.Helper()
	c, err := w.inv.CreateACMECertificate(w.ctx, w.admin, inventory.ACMECertificateInput{ProviderID: w.provider.ID, Names: names,
		Challenge: inventory.ACMEChallengeDNS01, HookID: &hook})
	require.NoError(w.t, err)
	return c
}

// issued orders a certificate through the hook, runs the jobs and checks the whole result: issued, nothing left
// published at the provider or seen by the CA, no secret in the jobs, the audit log or the logs.
func (w *dnsWorld) issued(hook inventory.ACMEHook, left func() int, secret string) {
	w.t.Helper()
	c := w.certVia(hook.ID, "www.example.test", "*.example.test")
	o := w.order(c, inventory.ACMEOrderIssue)
	w.drain()
	o = w.getOrder(o.ID)
	require.Equal(w.t, inventory.ACMEOrderSucceeded, o.State, o.ErrorCode)
	assert.Zero(w.t, o.Presented)
	assert.Equal(w.t, inventory.ACMEStateActive, w.getCert(c.ID).State)
	assert.Zero(w.t, w.dnsLeft(), "the CA's view of the zone is empty again")
	assert.Zero(w.t, left(), "the provider holds no challenge value")
	assert.Zero(w.t, w.count("SELECT count(*) FROM jobs WHERE type = 'acme.cleanup'"), "nothing was left to clean up")
	w.noSecrets()
	w.noDNSSecret(secret)
}

func (w *dnsWorld) noDNSSecret(secret string) {
	w.t.Helper()
	var text string
	require.NoError(w.t, w.db.Owner.QueryRow(w.ctx, `SELECT coalesce(string_agg(payload::text || coalesce(result::text, ''), ''), '') FROM jobs`).Scan(&text))
	var audit string
	require.NoError(w.t, w.db.Owner.QueryRow(w.ctx, `SELECT coalesce(string_agg(details::text, ''), '') FROM audit_log`).Scan(&audit))
	all := text + audit + w.logs.String()
	assert.NotContains(w.t, all, secret)
	assert.NotContains(w.t, all, base64.StdEncoding.EncodeToString([]byte(secret)))
}

func TestIssueThroughCloudflare(t *testing.T) {
	w := newDNSWorld(t)
	h := w.dnsProvider(inventory.ACMEHookKindCloudflare, inventory.ACMEHookInput{Credentials: inventory.ACMEDNSCredentials{
		APIToken: secrets.NewPlaintext([]byte(w.cf.Token()))}})
	w.issued(h, func() int { return len(w.cf.Records()) }, w.cf.Token())
	assert.Positive(t, w.cf.Counters()["create"])
	assert.Positive(t, w.cf.Counters()["delete"])
}

func TestIssueThroughRoute53WithARole(t *testing.T) {
	w := newDNSWorld(t)
	h := w.dnsProvider(inventory.ACMEHookKindRoute53, inventory.ACMEHookInput{
		Settings:    inventory.ACMEDNSSettings{AccessKeyID: w.r53.AccessKeyID()},
		Credentials: inventory.ACMEDNSCredentials{SecretAccessKey: secrets.NewPlaintext([]byte(w.r53.SecretAccessKey()))}})
	w.issued(h, func() int { return len(w.r53.Records()) }, w.r53.SecretAccessKey())
	assert.Positive(t, w.r53.Counters()["getchange"], "the order waited for INSYNC")
}

func TestIssueThroughAzureDNS(t *testing.T) {
	w := newDNSWorld(t)
	h := w.dnsProvider(inventory.ACMEHookKindAzureDNS, inventory.ACMEHookInput{
		Settings: inventory.ACMEDNSSettings{Auth: providers.AzureAuthClientSecret, TenantID: w.az.TenantID(), ClientID: w.az.ClientID(),
			SubscriptionID: w.az.DNSSubscriptionID(), ResourceGroup: w.az.DNSResourceGroup()},
		Credentials: inventory.ACMEDNSCredentials{ClientSecret: secrets.NewPlaintext([]byte(w.az.Secret()))}})
	w.issued(h, func() int { return len(w.az.DNSRecords()) }, w.az.Secret())
}

// A refused credential is a permanent failure (dns_auth_failed) and publishes nothing; a provider outage is
// transient (dns_provider_error) and what was published is cleaned up.
func TestDNSProviderFailuresAreClassified(t *testing.T) {
	w := newDNSWorld(t)
	wrong := w.dnsProvider(inventory.ACMEHookKindCloudflare, inventory.ACMEHookInput{Credentials: inventory.ACMEDNSCredentials{
		APIToken: secrets.NewPlaintext([]byte(fakecloudflare.NewToken()))}})
	c := w.certVia(wrong.ID, "www.example.test")
	o := w.order(c, inventory.ACMEOrderIssue)
	w.drain()
	o = w.getOrder(o.ID)
	assert.Equal(t, inventory.ACMEOrderFailed, o.State)
	assert.Equal(t, acme.ReasonDNSAuthFailed, o.ErrorCode)
	assert.Equal(t, acme.ClassPermanent, w.getCert(c.ID).LastFailureClass)
	assert.Zero(t, w.dnsLeft())

	good := w.dnsProvider(inventory.ACMEHookKindCloudflare, inventory.ACMEHookInput{Name: "x", Credentials: inventory.ACMEDNSCredentials{
		APIToken: secrets.NewPlaintext([]byte(w.cf.Token()))}})
	stop := w.cf.FailAll(fakecloudflare.OpCreate, fakecloudflare.Fault{Status: 503, Body: "canary-cloudflare-outage"})
	c2 := w.certVia(good.ID, "api.example.test")
	o = w.order(c2, inventory.ACMEOrderIssue)
	w.drain()
	stop()
	o = w.getOrder(o.ID)
	assert.Equal(t, inventory.ACMEOrderFailed, o.State)
	assert.Equal(t, acme.ReasonDNSProviderError, o.ErrorCode)
	assert.Equal(t, acme.ClassTransient, w.getCert(c2.ID).LastFailureClass)
	assert.Empty(t, w.cf.Records(), "nothing stayed published")
	assert.NotContains(t, w.logs.String(), "canary-cloudflare-outage")
}

// A deleted provider still removes what it published: the cleanup job uses its row and sealed credentials.
func TestCleanupThroughADeletedProvider(t *testing.T) {
	w := newDNSWorld(t)
	h := w.dnsProvider(inventory.ACMEHookKindCloudflare, inventory.ACMEHookInput{Credentials: inventory.ACMEDNSCredentials{
		APIToken: secrets.NewPlaintext([]byte(w.cf.Token()))}})
	c := w.certVia(h.ID, "www.example.test")
	o := w.order(c, inventory.ACMEOrderIssue)
	// The delete fails while the record is published: the cleanup is queued and retried.
	stop := w.cf.FailAll(fakecloudflare.OpDelete, fakecloudflare.Fault{Status: 500})
	w.drain()
	stop()
	require.Len(t, w.cf.Records(), 1, "the record is still published")
	require.NoError(t, w.inv.DeleteACMECertificate(w.ctx, w.admin, c.ID))
	require.NoError(t, w.inv.DeleteACMEHook(w.ctx, w.admin, h.ID))
	w.clock.Advance(2 * time.Hour) // past the queue's back-off
	w.drain()
	assert.Empty(t, w.cf.Records(), "the deleted provider's credentials removed it")
	assert.Zero(t, w.getOrder(o.ID).Presented)
}
