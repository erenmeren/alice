package azurekv

import (
	"context"
	"crypto/sha1" //nolint:gosec // G505: x5t is the SHA-1 thumbprint by definition
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/platform/azureid"
	"alice/internal/providers"
	"alice/internal/testutil/fakekv"
	"alice/internal/testutil/pki"
)

// lowerBounds lowers the package bounds for one test and restores them afterwards.
func lowerBounds(t *testing.T, certs, details, versions, keys, keyDetails, secrets int) {
	t.Helper()
	oc, od, ov, ok, okd, os := maxKVCertificates, maxKVDetails, maxKVVersions, maxKVKeys, maxKVKeyDetails, maxKVSecrets
	maxKVCertificates, maxKVDetails, maxKVVersions, maxKVKeys, maxKVKeyDetails, maxKVSecrets = certs, details, versions, keys, keyDetails, secrets
	t.Cleanup(func() {
		maxKVCertificates, maxKVDetails, maxKVVersions, maxKVKeys, maxKVKeyDetails, maxKVSecrets = oc, od, ov, ok, okd, os
	})
}

func byName(c []providers.KVCertificate) map[string]providers.KVCertificate {
	m := map[string]providers.KVCertificate{}
	for _, x := range c {
		m[x.Name] = x
	}
	return m
}

func knownOf(certs []providers.KVCertificate) map[string]providers.KVKnown {
	known := map[string]providers.KVKnown{}
	for _, c := range certs {
		if c.Details != nil {
			known[c.Name] = providers.KVKnown{Version: c.Details.Version, Thumbprint: c.Details.Thumbprint, Updated: *c.Details.Updated}
		}
	}
	return known
}

func TestDiscoverFetchesDetailsOnlyForChanges(t *testing.T) {
	w := newWorld(t, fakekv.Options{})
	v1 := w.s.AddCertificate("web-cert", fakekv.CertOptions{CommonName: "www.example.test", Exportable: true})
	w.s.AddCertificate("monitor-only", fakekv.CertOptions{CommonName: "m.example.test"})
	res, err := w.discover(providers.DiscoverRequest{Certificates: true})
	require.NoError(t, err)
	require.NotNil(t, res.KV)
	got := byName(res.KV.Certificates)
	require.Len(t, got, 2)
	web := got["web-cert"]
	require.NotNil(t, web.Details)
	assert.Equal(t, v1, web.Details.Version)
	assert.True(t, *web.Details.Exportable)
	assert.False(t, *got["monitor-only"].Details.Exportable)
	assert.Len(t, web.Versions, 1)
	assert.Equal(t, v1, web.Versions[0].Version)
	assert.Equal(t, azureid.ThumbprintOf(web.Details.CER), web.Details.Thumbprint, "the thumbprint is the leaf's SHA-1")
	assert.Equal(t, web.Details.Thumbprint, web.Thumbprint, "the listing's x5t agrees")
	assert.Equal(t, "ecdsa", web.Details.KeyType)
	assert.Equal(t, "pkcs12", web.Details.ContentType)
	assert.Equal(t, "Self", web.Details.IssuerName)
	assert.True(t, web.Details.AutoRenew)
	assert.True(t, web.Enabled)
	assert.Empty(t, res.KV.Truncated)
	assert.Zero(t, res.KV.DetailsPending)
	assert.Empty(t, res.KV.Failures)
	assert.Empty(t, res.Warnings)

	known := knownOf(res.KV.Certificates)
	w.s.ClearRequests()
	res, err = w.discover(providers.DiscoverRequest{Certificates: true, KVKnown: known})
	require.NoError(t, err)
	for _, c := range res.KV.Certificates {
		assert.Nil(t, c.Details, "unchanged (x5t, updated): no details read")
		assert.Empty(t, c.Versions)
	}
	assert.Equal(t, 1, w.authed(), "one listing page, no per-certificate call (§11.6: large vaults cost pages)")

	w.clk.Advance(10 * time.Minute)
	v2 := w.s.Renew("web-cert")
	res, err = w.discover(providers.DiscoverRequest{Certificates: true, KVKnown: known})
	require.NoError(t, err)
	got = byName(res.KV.Certificates)
	require.NotNil(t, got["web-cert"].Details)
	assert.Equal(t, v2, got["web-cert"].Details.Version)
	require.Len(t, got["web-cert"].Versions, 2)
	assert.Equal(t, []string{v2, v1}, []string{got["web-cert"].Versions[0].Version, got["web-cert"].Versions[1].Version}, "newest first")
	assert.Nil(t, got["monitor-only"].Details, "the unchanged certificate costs nothing")

	// A known name that differs only in case still counts as known (names are case-insensitive).
	upper := map[string]providers.KVKnown{}
	for n, k := range known {
		upper[upperASCII(n)] = k
	}
	for n, k := range knownOf(res.KV.Certificates) {
		upper[upperASCII(n)] = k
	}
	w.s.ClearRequests()
	res, err = w.discover(providers.DiscoverRequest{Certificates: true, KVKnown: upper})
	require.NoError(t, err)
	assert.Equal(t, 1, w.authed())
	assert.Nil(t, byName(res.KV.Certificates)["web-cert"].Details)
}

func TestDiscoverSameVersionsListedOnlyWhenTheCurrentVersionChanges(t *testing.T) {
	w := newWorld(t, fakekv.Options{})
	w.s.AddCertificate("web-cert", fakekv.CertOptions{CommonName: "www.example.test", Exportable: true})
	res, err := w.discover(providers.DiscoverRequest{Certificates: true})
	require.NoError(t, err)
	known := knownOf(res.KV.Certificates)
	// A policy change moves updated but not the version: details are read, the versions are not.
	w.clk.Advance(10 * time.Minute)
	w.s.DisableVersion("web-cert", w.s.Versions("web-cert")[0])
	w.s.ClearRequests()
	res, err = w.discover(providers.DiscoverRequest{Certificates: true, KVKnown: known})
	require.NoError(t, err)
	c := byName(res.KV.Certificates)["web-cert"]
	require.NotNil(t, c.Details)
	assert.False(t, c.Enabled)
	assert.Empty(t, c.Versions)
	for _, r := range w.vaultRequests() {
		assert.NotContains(t, r.Path, "/versions")
	}
}

func TestDiscoverBounds(t *testing.T) {
	t.Run("certificates and details", func(t *testing.T) {
		lowerBounds(t, 30, 10, 3, 3, 2, 3)
		w := newWorld(t, fakekv.Options{})
		w.s.AddBulkCertificates("bulk", 40)
		res, err := w.discover(providers.DiscoverRequest{Certificates: true})
		require.NoError(t, err)
		assert.Len(t, res.KV.Certificates, 30)
		assert.Equal(t, []string{"certificates"}, res.KV.Truncated)
		withDetails := 0
		for _, c := range res.KV.Certificates {
			if c.Details != nil {
				withDetails++
			}
		}
		assert.Equal(t, 10, withDetails)
		assert.Equal(t, 20, res.KV.DetailsPending)
	})
	t.Run("exactly the bound is not a truncation", func(t *testing.T) {
		lowerBounds(t, 30, 100, 3, 3, 2, 3)
		w := newWorld(t, fakekv.Options{})
		w.s.AddBulkCertificates("bulk", 30)
		res, err := w.discover(providers.DiscoverRequest{Certificates: true})
		require.NoError(t, err)
		assert.Len(t, res.KV.Certificates, 30)
		assert.Empty(t, res.KV.Truncated)
	})
	t.Run("versions", func(t *testing.T) {
		lowerBounds(t, 30, 10, 3, 3, 2, 3)
		w := newWorld(t, fakekv.Options{})
		w.s.AddCertificate("web-cert", fakekv.CertOptions{CommonName: "www.example.test", Exportable: true})
		for range 4 {
			w.clk.Advance(time.Minute)
			w.s.Renew("web-cert")
		}
		all := w.s.Versions("web-cert")
		require.Len(t, all, 5)
		res, err := w.discover(providers.DiscoverRequest{Certificates: true})
		require.NoError(t, err)
		c := byName(res.KV.Certificates)["web-cert"]
		require.Len(t, c.Versions, 3)
		assert.Contains(t, res.KV.Truncated, "versions")
		assert.Equal(t, all[4], c.Details.Version)
		assert.Equal(t, all[4], c.Versions[0].Version, "the current version is always kept, newest first")
	})
	t.Run("keys and secrets", func(t *testing.T) {
		lowerBounds(t, 30, 10, 3, 3, 2, 3)
		w := newWorld(t, fakekv.Options{})
		for i := range 5 {
			w.s.AddKey(fmt.Sprintf("key-%d", i), fakekv.KeyOptions{KeyType: "RSA", Size: 2048, Enabled: true})
			w.s.AddSecret(fmt.Sprintf("secret-%d", i), "text/plain")
		}
		res, err := w.discover(providers.DiscoverRequest{KVKeys: true, KVSecrets: true})
		require.NoError(t, err)
		assert.Len(t, res.KV.Keys, 3)
		assert.Len(t, res.KV.Secrets, 3)
		assert.ElementsMatch(t, []string{"keys", "secrets"}, res.KV.Truncated)
		assert.False(t, res.KV.KeysListed, "a cut list is not a complete list")
		assert.False(t, res.KV.SecretsListed)
		withDetails := 0
		for _, k := range res.KV.Keys {
			if k.Details != nil {
				withDetails++
			}
		}
		assert.Equal(t, 2, withDetails)
	})
}

// A poll that passes its budget ends with what it read, says so, and does not read the rest.
func TestDiscoverEndsAtThePollBudget(t *testing.T) {
	oldBudget := pollBudget
	pollBudget = 10 * time.Minute
	t.Cleanup(func() { pollBudget = oldBudget })
	api := &stubAPI{}
	sess, clk := stubSession(api)
	good := func(n string) *azcertificates.CertificateProperties {
		return certProps(n, make([]byte, 20), time.Unix(1_700_000_000, 0))
	}
	api.certs = func(page func([]*azcertificates.CertificateProperties) error) error {
		if err := page([]*azcertificates.CertificateProperties{good("a-1"), good("a-2")}); err != nil {
			return err
		}
		clk.Advance(11 * time.Minute) // the first page took the whole budget
		return page([]*azcertificates.CertificateProperties{good("b-1")})
	}
	api.get = func(name, _ string) (azcertificates.Certificate, error) {
		t.Fatalf("details of %s asked after the budget", name)
		return azcertificates.Certificate{}, nil
	}
	res, err := sess.Discover(context.Background(), providers.DiscoverRequest{Certificates: true, KVKeys: true, KVSecrets: true})
	require.NoError(t, err)
	names := []string{}
	for _, c := range res.KV.Certificates {
		names = append(names, c.Name)
	}
	assert.Equal(t, []string{"a-1", "a-2"}, names, "what was read before the budget ended")
	assert.ElementsMatch(t, []string{"certificates", "keys", "secrets"}, res.KV.Truncated)
	assert.False(t, res.KV.KeysListed)
	assert.False(t, res.KV.SecretsListed)
	assert.Equal(t, []string{"list_certificates"}, api.calls, "the remaining lists are not read")
}

func TestDiscoverEmptyRequestSendsNothing(t *testing.T) {
	w := newWorld(t, fakekv.Options{})
	res, err := w.sess.Discover(context.Background(), providers.DiscoverRequest{SSHKeys: true})
	require.NoError(t, err)
	assert.Nil(t, res.KV)
	assert.Empty(t, w.s.Requests())
}

func TestDiscoverKeysAndSecretsOnlyWhenAsked(t *testing.T) {
	w := newWorld(t, fakekv.Options{})
	w.s.AddCertificate("web-cert", fakekv.CertOptions{CommonName: "www.example.test", Exportable: true})
	w.s.AddKey("signing", fakekv.KeyOptions{KeyType: "RSA", Size: 2048, Enabled: true})
	w.s.AddKey("ec-key", fakekv.KeyOptions{KeyType: "EC", Curve: "P-384", Enabled: true})
	w.s.AddSecret("db-password", "text/plain")

	res, err := w.discover(providers.DiscoverRequest{Certificates: true})
	require.NoError(t, err)
	for _, r := range w.vaultRequests() {
		assert.NotContains(t, r.Path, "/keys", "KVKeys false: no /keys request")
		assert.NotContains(t, r.Path, "/secrets")
	}
	assert.Empty(t, res.KV.Keys)
	assert.Empty(t, res.KV.Secrets)
	assert.False(t, res.KV.KeysListed)
	assert.False(t, res.KV.SecretsListed)

	w.s.ClearRequests()
	res, err = w.discover(providers.DiscoverRequest{KVKeys: true})
	require.NoError(t, err)
	assert.Empty(t, res.KV.Certificates, "no certificate was asked for")
	assert.True(t, res.KV.KeysListed)
	keys := map[string]providers.KVKey{}
	for _, k := range res.KV.Keys {
		keys[k.Name] = k
	}
	require.Len(t, keys, 3, "web-cert's backing key is listed, flagged managed")
	assert.True(t, keys["web-cert"].Managed, "a certificate's backing key is not a standalone key")
	assert.Nil(t, keys["web-cert"].Details, "no GetKey for a managed key")
	assert.False(t, keys["signing"].Managed)
	require.NotNil(t, keys["signing"].Details)
	assert.Equal(t, providers.KVKeyDetails{Version: keys["signing"].Details.Version, KeyType: "rsa", Size: 2048}, *keys["signing"].Details)
	assert.True(t, azureid.ValidVersion(keys["signing"].Details.Version))
	require.NotNil(t, keys["ec-key"].Details)
	assert.Equal(t, "ec", keys["ec-key"].Details.KeyType)
	assert.Equal(t, "P-384", keys["ec-key"].Details.Curve)
	assert.Empty(t, keys["signing"].DetailsProblem)

	// Keys Alice already read are not read again; a changed one is.
	known := map[string]time.Time{}
	for n, k := range keys {
		if k.Updated != nil {
			known[n] = *k.Updated
		}
	}
	w.s.ClearRequests()
	res, err = w.discover(providers.DiscoverRequest{KVKeys: true, KVKnownKeys: known})
	require.NoError(t, err)
	for _, k := range res.KV.Keys {
		assert.Nil(t, k.Details, k.Name)
	}
	assert.Equal(t, 1, w.authed(), "the listing only")

	// GetKey refused: the key is still listed and says why.
	w.s.RevokeRole("keys/get")
	res, err = w.discover(providers.DiscoverRequest{KVKeys: true})
	require.NoError(t, err)
	for _, k := range res.KV.Keys {
		if !k.Managed {
			assert.Equal(t, "forbidden", k.DetailsProblem, k.Name)
			assert.Nil(t, k.Details)
		}
	}
	assert.True(t, res.KV.KeysListed)
	w.s.GrantAllRoles()
	w.s.FailAll("/keys/signing", fakekv.Fault{Status: 500})
	res, err = w.discover(providers.DiscoverRequest{KVKeys: true})
	require.NoError(t, err)
	for _, k := range res.KV.Keys {
		if k.Name == "signing" {
			assert.Equal(t, "failed", k.DetailsProblem)
		}
	}

	// Secrets: metadata only. Never a read of a secret's value.
	w.s.ClearRequests()
	res, err = w.discover(providers.DiscoverRequest{KVSecrets: true})
	require.NoError(t, err)
	assert.True(t, res.KV.SecretsListed)
	secrets := map[string]providers.KVSecret{}
	for _, s := range res.KV.Secrets {
		secrets[s.Name] = s
	}
	require.Len(t, secrets, 2)
	assert.True(t, secrets["web-cert"].Managed)
	assert.False(t, secrets["db-password"].Managed)
	assert.Equal(t, "text/plain", secrets["db-password"].ContentType)
	assert.True(t, secrets["db-password"].Enabled)
	for _, r := range w.vaultRequests() {
		assert.Equal(t, "/secrets", r.Path, "never GET /secrets/<name>/...: a vault secret's value is never read by a poll")
	}
}

func TestDiscoverReportsListFailuresAndKeepsTheRest(t *testing.T) {
	t.Run("F-40: certificates forbidden, keys still read", func(t *testing.T) {
		w := newWorld(t, fakekv.Options{})
		w.s.AddCertificate("web-cert", fakekv.CertOptions{CommonName: "www.example.test", Exportable: true})
		w.s.AddKey("signing", fakekv.KeyOptions{KeyType: "RSA", Size: 2048, Enabled: true})
		w.s.RevokeRole("certificates/list")
		res, err := w.discover(providers.DiscoverRequest{Certificates: true, KVKeys: true})
		require.NoError(t, err)
		require.Len(t, res.KV.Failures, 1)
		f := res.KV.Failures[0]
		assert.Equal(t, "certificates", f.Object)
		assert.Equal(t, codeForbidden, f.Err.Code)
		assert.Equal(t, providers.RoleKeyVaultReader, f.Err.Params["role"])
		assert.Empty(t, res.KV.Certificates)
		assert.NotEmpty(t, res.KV.Keys)
		assert.True(t, res.KV.KeysListed)
	})
	t.Run("a sign-in failure ends the poll", func(t *testing.T) {
		s := fakekv.Start(t, fakekv.Options{})
		id := secretIdentity(s)
		id.ClientSecret = providers.NewSecret([]byte(fakekv.NewClientSecret()))
		clk := nearNow()
		sess := openSession(t, testProvider(s), &idSource{id: id}, clk)
		var res providers.DiscoveryResult
		err := drive(clk, func() (e error) {
			res, e = sess.Discover(context.Background(), providers.DiscoverRequest{Certificates: true, KVKeys: true})
			return e
		})
		assert.Equal(t, codeAuthFailed, asProviderError(t, err).Code)
		assert.Nil(t, res.KV)
	})
	t.Run("an unknown vault ends the poll", func(t *testing.T) {
		nx := &netDNS
		w := newWorld(t, fakekv.Options{}, dialFailingTune(testVaultHost, nx))
		_, err := w.discover(providers.DiscoverRequest{Certificates: true, KVKeys: true})
		assert.Equal(t, codeVaultNotFound, asProviderError(t, err).Code)
	})
	t.Run("F-52: a truncated page fails that list, never a partial list as complete", func(t *testing.T) {
		w := newWorld(t, fakekv.Options{})
		w.s.AddCertificate("web-cert", fakekv.CertOptions{CommonName: "www.example.test", Exportable: true})
		w.s.AddKey("signing", fakekv.KeyOptions{KeyType: "RSA", Size: 2048, Enabled: true})
		w.s.FailAll("/certificates", fakekv.Fault{Truncate: true})
		res, err := w.discover(providers.DiscoverRequest{Certificates: true, KVKeys: true})
		require.NoError(t, err)
		require.Len(t, res.KV.Failures, 1)
		assert.Equal(t, codeUnexpected, res.KV.Failures[0].Err.Code)
		assert.Empty(t, res.KV.Certificates)
		assert.True(t, res.KV.KeysListed)
	})
	t.Run("page two failing for good fails the whole list", func(t *testing.T) {
		w := newWorld(t, fakekv.Options{})
		w.s.AddBulkCertificates("bulk", 60)
		w.s.FailNext("/certificates", fakekv.Fault{}) // page one passes
		w.s.FailAll("/certificates", fakekv.Fault{Status: 500})
		res, err := w.discover(providers.DiscoverRequest{Certificates: true})
		require.NoError(t, err)
		require.Len(t, res.KV.Failures, 1)
		assert.Equal(t, codeUnreachable, res.KV.Failures[0].Err.Code)
		assert.Empty(t, res.KV.Certificates, "page one's 25 certificates are not a listing")
	})
	t.Run("a failed details call fails the certificate list", func(t *testing.T) {
		w := newWorld(t, fakekv.Options{})
		w.s.AddCertificate("web-cert", fakekv.CertOptions{CommonName: "www.example.test", Exportable: true})
		w.s.RevokeRole("certificates/get")
		res, err := w.discover(providers.DiscoverRequest{Certificates: true})
		require.NoError(t, err)
		require.Len(t, res.KV.Failures, 1)
		assert.Equal(t, codeForbidden, res.KV.Failures[0].Err.Code)
		assert.Empty(t, res.KV.Certificates)
	})
	t.Run("a cancelled context is an error, not a failure row", func(t *testing.T) {
		w := newWorld(t, fakekv.Options{})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := w.sess.Discover(ctx, providers.DiscoverRequest{Certificates: true})
		assert.ErrorIs(t, err, context.Canceled)
		assert.Empty(t, w.s.Requests())
	})
}

// Short and empty pages that still carry a nextLink are followed.
func TestDiscoverFollowsShortAndEmptyPages(t *testing.T) {
	for _, empty := range []bool{false, true} {
		t.Run(fmt.Sprintf("empty pages %v", empty), func(t *testing.T) {
			w := newWorld(t, fakekv.Options{})
			for i := range 10 {
				w.s.AddCertificate(fmt.Sprintf("cert-%02d", i), fakekv.CertOptions{CommonName: "x.example.test"})
			}
			w.s.AddKey("signing", fakekv.KeyOptions{KeyType: "RSA", Size: 2048, Enabled: true})
			w.s.SetPageFill(3)
			w.s.SetEmptyPages(empty)
			res, err := w.discover(providers.DiscoverRequest{Certificates: true, KVKeys: true, KVSecrets: true})
			require.NoError(t, err)
			assert.Len(t, res.KV.Certificates, 10)
			assert.Len(t, res.KV.Keys, 11, "ten backing keys and one key")
			assert.Len(t, res.KV.Secrets, 10, "ten backing secrets")
			assert.Empty(t, res.KV.Failures)
			assert.True(t, res.KV.KeysListed)
			assert.True(t, res.KV.SecretsListed)
		})
	}
}

// Names are case-insensitive in Azure: two spellings of one name in a list are an inconsistent
// answer, and that list fails as a whole (inventory keys names on lower(name COLLATE "C")).
func TestDiscoverRefusesNamesThatFoldTogether(t *testing.T) {
	good := func(n string) *azcertificates.CertificateProperties {
		return certProps(n, make([]byte, 20), time.Unix(1_700_000_000, 0))
	}
	api := &stubAPI{
		certs: func(page func([]*azcertificates.CertificateProperties) error) error {
			return page([]*azcertificates.CertificateProperties{good("Web-Cert"), good("other"), good("web-cert")})
		},
		keys: func(page func([]*azkeys.KeyProperties) error) error {
			return page([]*azkeys.KeyProperties{keyProps("Signing", false), keyProps("signing", false)})
		},
		secrets: func(page func([]*azsecrets.SecretProperties) error) error {
			return page([]*azsecrets.SecretProperties{secretProps("db", "text/plain", false), secretProps("DB", "text/plain", false)})
		},
	}
	sess, _ := stubSession(api)
	res, err := sess.Discover(context.Background(), providers.DiscoverRequest{Certificates: true, KVKeys: true, KVSecrets: true})
	require.NoError(t, err)
	require.Len(t, res.KV.Failures, 3)
	for i, obj := range []string{"certificates", "keys", "secrets"} {
		assert.Equal(t, obj, res.KV.Failures[i].Object)
		assert.Equal(t, codeUnexpected, res.KV.Failures[i].Err.Code)
		require.ErrorIs(t, res.KV.Failures[i].Err, providers.ErrUnexpectedAnswer)
	}
	assert.Empty(t, res.KV.Certificates)
	assert.Empty(t, res.KV.Keys)
	assert.Empty(t, res.KV.Secrets)
	assert.False(t, res.KV.KeysListed)
	assert.False(t, res.KV.SecretsListed)
}

func TestDiscoverSkipsUnusableItems(t *testing.T) {
	when := time.Unix(1_700_000_000, 0)
	x5t := make([]byte, 20)
	api := &stubAPI{}
	api.certs = func(page func([]*azcertificates.CertificateProperties) error) error {
		bad := certProps("bad name", x5t, when) // outside ValidObjectName
		short := certProps("short-x5t", x5t[:19], when)
		pending := certProps("pending", nil, when) // a certificate being created has no x5t
		noID := certProps("no-id", x5t, when)
		noID.ID = nil
		return page([]*azcertificates.CertificateProperties{bad, certProps("good", x5t, when), short, pending, noID, certProps("good-two", x5t, when)})
	}
	leaf := pki.NewCA("t", pki.ECDSA256, time.Now()).Issue(pki.Opts{CommonName: "x.example.test", KeyType: pki.ECDSA256}, time.Now())
	api.get = func(name, _ string) (azcertificates.Certificate, error) {
		c := azcertificates.Certificate{ID: certID(name, strings.Repeat("a", 32)), CER: leaf.Cert.Raw, X509Thumbprint: sha1sum(leaf.Cert.Raw),
			Attributes: &azcertificates.CertificateAttributes{Updated: &when}}
		if name == "good" {
			c.ID = certID(name, "NOTHEX") // a version that is not 32 hex
		}
		return c, nil
	}
	api.versions = func(_ string, page func([]*azcertificates.CertificateProperties) error) error {
		okv := certProps("good-two", sha1sum(leaf.Cert.Raw), when)
		okv.ID = certID("good-two", strings.Repeat("a", 32))
		badv := certProps("good-two", sha1sum(leaf.Cert.Raw), when)
		badv.ID = certID("good-two", "XYZ")
		shortv := certProps("good-two", x5t[:3], when)
		shortv.ID = certID("good-two", strings.Repeat("b", 32))
		return page([]*azcertificates.CertificateProperties{okv, badv, shortv})
	}
	api.keys = func(page func([]*azkeys.KeyProperties) error) error {
		return page([]*azkeys.KeyProperties{keyProps("bad name", false), keyProps("fine", true)})
	}
	api.secrets = func(page func([]*azsecrets.SecretProperties) error) error {
		return page([]*azsecrets.SecretProperties{secretProps("bad name", "", false), secretProps("fine", "", false)})
	}
	sess, _ := stubSession(api)
	res, err := sess.Discover(context.Background(), providers.DiscoverRequest{Certificates: true, KVKeys: true, KVSecrets: true})
	require.NoError(t, err)

	names := []string{}
	for _, c := range res.KV.Certificates {
		names = append(names, c.Name)
	}
	assert.Equal(t, []string{"good", "good-two"}, names, "unusable items are never stored")
	got := byName(res.KV.Certificates)
	assert.Nil(t, got["good"].Details, "details with a version that is not 32 hex are dropped, the listed certificate stays")
	assert.Equal(t, 1, res.KV.DetailsPending, "unusable details are counted as waiting")
	require.NotNil(t, got["good-two"].Details)
	require.Len(t, got["good-two"].Versions, 1, "only the usable version")
	assert.Len(t, res.KV.Keys, 1)
	assert.Len(t, res.KV.Secrets, 1)
	assert.ElementsMatch(t, []string{"certificates", "versions", "keys", "secrets"}, res.KV.Truncated,
		"a list with a skipped item is incomplete: nothing of that kind may be marked missing")
	assert.False(t, res.KV.KeysListed)
	assert.False(t, res.KV.SecretsListed)

	warn := map[string]string{}
	for _, w := range res.Warnings {
		assert.Equal(t, providers.WarnKVItemUnreadable, w.Code)
		_, dup := warn[w.Params["object"]]
		assert.False(t, dup, "one warning per kind")
		warn[w.Params["object"]] = w.Params["count"]
	}
	assert.Equal(t, map[string]string{"certificates": "5", "versions": "2", "keys": "1", "secrets": "1"}, warn)
}

// Provider values the database would refuse are dropped item by item, never failing the listing.
func TestDiscoverClampsValuesTheDatabaseRefuses(t *testing.T) {
	when := time.Unix(1_700_000_000, 0)
	farFuture := time.Date(20000, 1, 1, 0, 0, 0, 0, time.UTC)
	leaf := pki.NewCA("t", pki.ECDSA256, time.Now()).Issue(pki.Opts{CommonName: "x.example.test", KeyType: pki.ECDSA256}, time.Now())
	thumb := sha1sum(leaf.Cert.Raw)
	api := &stubAPI{}
	api.certs = func(page func([]*azcertificates.CertificateProperties) error) error {
		a := certProps("clamped", thumb, when)
		a.Attributes.Expires = &farFuture
		a.Attributes.NotBefore = to.Ptr(time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC).Add(-time.Hour))
		return page([]*azcertificates.CertificateProperties{a, certProps("mismatch", thumb, when), certProps("nocer", thumb, when)})
	}
	api.get = func(name, _ string) (azcertificates.Certificate, error) {
		c := azcertificates.Certificate{ID: certID(name, strings.Repeat("c", 32)), CER: leaf.Cert.Raw, X509Thumbprint: thumb,
			Attributes: &azcertificates.CertificateAttributes{Updated: &when},
			Policy: &azcertificates.CertificatePolicy{
				KeyProperties:    &azcertificates.KeyProperties{KeySize: to.Ptr(int32(99999)), KeyType: to.Ptr(azcertificates.KeyType("quantum"))},
				SecretProperties: &azcertificates.SecretProperties{ContentType: to.Ptr("text/plain")},
				IssuerParameters: &azcertificates.IssuerParameters{Name: to.Ptr(strings.Repeat("i", 200))},
			}}
		switch name {
		case "mismatch":
			c.X509Thumbprint = sha1sum([]byte("another certificate"))
		case "nocer":
			c.CER = nil
		}
		return c, nil
	}
	api.keys = func(page func([]*azkeys.KeyProperties) error) error {
		return page([]*azkeys.KeyProperties{keyProps("k", false)})
	}
	api.getKey = func(string) (azkeys.KeyBundle, error) {
		kty, crv := azkeys.KeyType("RSA-HSM"), azkeys.CurveName("P-999")
		return azkeys.KeyBundle{Key: &azkeys.JSONWebKey{KID: keyID("k", strings.Repeat("d", 32)), Kty: &kty, N: make([]byte, 5000), Crv: &crv}}, nil
	}
	api.secrets = func(page func([]*azsecrets.SecretProperties) error) error {
		return page([]*azsecrets.SecretProperties{secretProps("s", strings.Repeat("t", 300), false), secretProps("s2", "bad\x00type", false)})
	}
	sess, _ := stubSession(api)
	res, err := sess.Discover(context.Background(), providers.DiscoverRequest{Certificates: true, KVKeys: true, KVSecrets: true})
	require.NoError(t, err)
	got := byName(res.KV.Certificates)
	require.Len(t, got, 3, "no certificate is lost to a bad detail value")

	c := got["clamped"]
	assert.Nil(t, c.Expires, "year 20000 does not fit the database")
	assert.Nil(t, c.NotBefore)
	require.NotNil(t, c.Details)
	assert.Equal(t, 0, c.Details.KeySize)
	assert.Equal(t, "other", c.Details.KeyType)
	assert.Equal(t, "other", c.Details.ContentType)
	assert.Equal(t, "", c.Details.IssuerName, "an issuer name above 127 characters is dropped")
	assert.Nil(t, got["mismatch"].Details, "a leaf that is not the one x5t names")
	assert.Nil(t, got["nocer"].Details, "details without the leaf are unusable")

	require.Len(t, res.KV.Keys, 1)
	kd := res.KV.Keys[0].Details
	require.NotNil(t, kd)
	assert.Equal(t, providers.KVKeyDetails{Version: strings.Repeat("d", 32), KeyType: "rsa", HSM: true, Size: 0, Curve: "other"}, *kd)

	require.Len(t, res.KV.Secrets, 2)
	assert.Equal(t, "", res.KV.Secrets[0].ContentType, "above 255 characters")
	assert.Equal(t, "", res.KV.Secrets[1].ContentType, "a NUL byte")
}

func TestDiscoverVersionsOfADeletedCertificateAreSkipped(t *testing.T) {
	when := time.Unix(1_700_000_000, 0)
	api := &stubAPI{}
	api.certs = func(page func([]*azcertificates.CertificateProperties) error) error {
		return page([]*azcertificates.CertificateProperties{certProps("gone", make([]byte, 20), when), certProps("kept", make([]byte, 20), when)})
	}
	api.get = func(name, _ string) (azcertificates.Certificate, error) {
		if name == "gone" {
			return azcertificates.Certificate{}, providers.NewError(codeCertificateNotFound, false, nil, nil)
		}
		return azcertificates.Certificate{}, providers.NewError(codeForbidden, false, nil, map[string]string{"role": providers.RoleKeyVaultReader})
	}
	sess, _ := stubSession(api)
	res, err := sess.Discover(context.Background(), providers.DiscoverRequest{Certificates: true})
	require.NoError(t, err)
	require.Len(t, res.KV.Failures, 1, "the forbidden call fails the list")

	api.get = func(name, _ string) (azcertificates.Certificate, error) {
		return azcertificates.Certificate{}, providers.NewError(codeCertificateNotFound, false, nil, nil)
	}
	res, err = sess.Discover(context.Background(), providers.DiscoverRequest{Certificates: true})
	require.NoError(t, err)
	assert.Empty(t, res.KV.Failures)
	assert.Empty(t, res.KV.Certificates, "deleted since the listing: not part of the vault any more")
}

// ---- builders for the stub tests ----

func certID(name, version string) *azcertificates.ID {
	id := azcertificates.ID("https://" + testVaultHost + "/certificates/" + name)
	if version != "" {
		id += azcertificates.ID("/" + version)
	}
	return &id
}

func keyID(name, version string) *azkeys.ID {
	id := azkeys.ID("https://" + testVaultHost + "/keys/" + name)
	if version != "" {
		id += azkeys.ID("/" + version)
	}
	return &id
}

func sha1sum(b []byte) []byte {
	h := sha1.Sum(b) //nolint:gosec // G401: x5t is SHA-1 by definition
	return h[:]
}

func certProps(name string, x5t []byte, updated time.Time) *azcertificates.CertificateProperties {
	return &azcertificates.CertificateProperties{
		ID: certID(name, ""), X509Thumbprint: x5t,
		Attributes: &azcertificates.CertificateAttributes{Enabled: to.Ptr(true), Updated: &updated, Created: &updated},
	}
}

func keyProps(name string, managed bool) *azkeys.KeyProperties {
	now := time.Unix(1_700_000_000, 0)
	return &azkeys.KeyProperties{KID: keyID(name, ""), Managed: &managed, Attributes: &azkeys.KeyAttributes{Enabled: to.Ptr(true), Updated: &now}}
}

func secretProps(name, contentType string, managed bool) *azsecrets.SecretProperties {
	id := azsecrets.ID("https://" + testVaultHost + "/secrets/" + name)
	now := time.Unix(1_700_000_000, 0)
	return &azsecrets.SecretProperties{ID: &id, ContentType: &contentType, Managed: &managed, Attributes: &azsecrets.SecretAttributes{Enabled: to.Ptr(true), Updated: &now}}
}

// I1: a 200 page without a "value" array is not "end of list": `{}`, `{"value":null}` and `null` fail
// that list on page one and on page two, whatever the kind; a real empty array is a complete, empty list.
func TestDiscoverRefusesAPageWithoutValue(t *testing.T) {
	kinds := []struct {
		name, path string
		req        providers.DiscoverRequest
	}{
		{"certificates", "/certificates", providers.DiscoverRequest{Certificates: true}},
		{"keys", "/keys", providers.DiscoverRequest{KVKeys: true}},
		{"secrets", "/secrets", providers.DiscoverRequest{KVSecrets: true}},
	}
	for _, k := range kinds {
		for _, body := range []string{`{}`, `{"value":null}`, `null`} {
			for _, page := range []int{1, 2} {
				t.Run(fmt.Sprintf("%s %s page %d", k.name, body, page), func(t *testing.T) {
					w := newWorld(t, fakekv.Options{})
					w.s.AddBulkCertificates("bulk", 60) // two or three pages of each kind
					if page == 2 {
						w.s.FailNext(k.path, fakekv.Fault{}) // page one passes
					}
					w.s.FailNext(k.path, fakekv.Fault{Body: body})
					res, err := w.discover(k.req)
					require.NoError(t, err)
					require.Len(t, res.KV.Failures, 1)
					assert.Equal(t, k.name, res.KV.Failures[0].Object)
					assert.Equal(t, codeUnexpected, res.KV.Failures[0].Err.Code)
					assert.ErrorIs(t, res.KV.Failures[0].Err, providers.ErrUnexpectedAnswer)
					assert.Empty(t, res.KV.Certificates)
					assert.Empty(t, res.KV.Keys)
					assert.Empty(t, res.KV.Secrets)
					assert.False(t, res.KV.KeysListed)
					assert.False(t, res.KV.SecretsListed)
				})
			}
		}
	}
	t.Run("an empty vault answers value [] and is complete and empty", func(t *testing.T) {
		w := newWorld(t, fakekv.Options{})
		res, err := w.discover(providers.DiscoverRequest{Certificates: true, KVKeys: true, KVSecrets: true})
		require.NoError(t, err)
		assert.Empty(t, res.KV.Failures)
		assert.Empty(t, res.KV.Truncated)
		assert.True(t, res.KV.KeysListed)
		assert.True(t, res.KV.SecretsListed)
		assert.Empty(t, res.KV.Certificates)
	})
	t.Run("a scripted value [] is the same", func(t *testing.T) {
		w := newWorld(t, fakekv.Options{})
		w.s.AddBulkCertificates("bulk", 3)
		w.s.FailAll("/certificates", fakekv.Fault{Body: `{"value":[]}`})
		res, err := w.discover(providers.DiscoverRequest{Certificates: true})
		require.NoError(t, err)
		assert.Empty(t, res.KV.Failures)
		assert.Empty(t, res.KV.Certificates)
	})
	t.Run("versions without a value", func(t *testing.T) {
		w := newWorld(t, fakekv.Options{})
		w.s.AddCertificate("web-cert", fakekv.CertOptions{CommonName: "www.example.test", Exportable: true})
		w.s.FailAll("/certificates/web-cert/versions", fakekv.Fault{Body: `{}`})
		res, err := w.discover(providers.DiscoverRequest{Certificates: true})
		require.NoError(t, err)
		// One certificate's version list is that certificate's details: it stays listed without them (L-10).
		assert.Empty(t, res.KV.Failures)
		require.Len(t, res.KV.Certificates, 1)
		assert.Nil(t, res.KV.Certificates[0].Details)
		assert.Equal(t, 1, res.KV.DetailsPending)
	})
}

// One certificate whose details cannot be read stays listed without them (review-fixes L-10): the rest of the
// listing and the other details are kept, like keys(). Several failures in a row are a vault problem, and the
// listing fails as before.
func TestDiscoverKeepsTheListingWhenOneCertificateDetailFails(t *testing.T) {
	for name, f := range map[string]fakekv.Fault{
		"5xx":       {Status: 500},
		"no value":  {Body: `{}`},
		"throttled": {Status: 429},
	} {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t, fakekv.Options{})
			w.s.AddCertificate("web-cert", fakekv.CertOptions{CommonName: "www.example.test", Exportable: true})
			w.s.AddCertificate("bad-cert", fakekv.CertOptions{CommonName: "bad.example.test", Exportable: true})
			w.s.AddCertificate("zzz-cert", fakekv.CertOptions{CommonName: "z.example.test", Exportable: true})
			w.s.FailAll("/certificates/bad-cert", f)
			res, err := w.discover(providers.DiscoverRequest{Certificates: true})
			require.NoError(t, err)
			assert.Empty(t, res.KV.Failures)
			require.Len(t, res.KV.Certificates, 3)
			got := map[string]bool{}
			for _, c := range res.KV.Certificates {
				got[c.Name] = c.Details != nil
			}
			assert.Equal(t, map[string]bool{"web-cert": true, "bad-cert": false, "zzz-cert": true}, got)
			assert.Equal(t, 1, res.KV.DetailsPending)
			assert.Contains(t, res.Warnings, providers.Warning{Code: providers.WarnKVItemUnreadable,
				Params: map[string]string{"object": kindCertificates, "count": "1"}})
		})
	}
	t.Run("every detail read fails", func(t *testing.T) {
		w := newWorld(t, fakekv.Options{})
		for _, n := range []string{"a-cert", "b-cert", "c-cert", "d-cert"} {
			w.s.AddCertificate(n, fakekv.CertOptions{CommonName: n + ".example.test", Exportable: true})
		}
		w.s.FailAll("/certificates/", fakekv.Fault{Status: 500})
		res, err := w.discover(providers.DiscoverRequest{Certificates: true})
		require.NoError(t, err)
		require.Len(t, res.KV.Failures, 1)
		assert.Equal(t, codeUnreachable, res.KV.Failures[0].Err.Code)
		assert.Empty(t, res.KV.Certificates)
	})
}
