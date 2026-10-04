package azurekv

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/certs"
	"alice/internal/platform/azureid"
	"alice/internal/platform/clock"
	"alice/internal/providers"
	"alice/internal/testutil/fakekv"
)

// contractEnv is a vault the contract runs against: the fake (always) or a real vault (tag azure).
type contractEnv struct {
	open     func(t *testing.T) providers.Session
	certName string             // an exportable certificate with at least one version
	renew    func(t *testing.T) // creates a new version (the fake renews; a real vault only when its policy renews daily)
}

// runContract is the one set of assertions both the fake and a real vault must pass (R40 row 30).
func runContract(t *testing.T, env contractEnv) {
	t.Helper()
	ctx := context.Background()
	sess := env.open(t)

	// 1. The access check: signed in; every list ok, or forbidden with the role that would allow it.
	rep, err := sess.TestConnection(ctx)
	require.NoError(t, err)
	require.NotNil(t, rep.Azure)
	assert.Equal(t, providers.AzureCheckSignIn, rep.Azure.Checks[0].Name)
	assert.Equal(t, providers.AzureResultOK, rep.Azure.Checks[0].Result)
	for _, c := range rep.Azure.Checks[1:4] {
		switch c.Result {
		case providers.AzureResultOK:
		case providers.AzureResultForbidden:
			assert.Equal(t, providers.RoleKeyVaultReader, c.Role, c.Name)
		default:
			assert.Fail(t, "a list neither ok nor forbidden", "%s: %s %s", c.Name, c.Result, c.Reason)
		}
	}

	// 2. Discovery: the certificate is listed and its details have the shapes inventory stores.
	res, err := sess.Discover(ctx, providers.DiscoverRequest{Certificates: true})
	require.NoError(t, err)
	require.NotNil(t, res.KV)
	require.Empty(t, res.KV.Failures)
	var found *providers.KVCertificate
	for i := range res.KV.Certificates {
		if res.KV.Certificates[i].Name == env.certName {
			found = &res.KV.Certificates[i]
		}
	}
	require.NotNil(t, found, "the certificate %s is listed", env.certName)
	d := found.Details
	require.NotNil(t, d, "the first poll reads its details")
	assert.True(t, azureid.ValidVersion(d.Version))
	assert.True(t, azureid.ValidThumbprint(d.Thumbprint))
	assert.Equal(t, azureid.ThumbprintOf(d.CER), d.Thumbprint)
	require.NotNil(t, d.Exportable)
	assert.True(t, *d.Exportable)
	assert.Contains(t, []string{"pkcs12", "pem"}, d.ContentType)
	assert.NotEmpty(t, found.Versions)

	// 3. The secret of that version decodes to the leaf the details name.
	sec, err := sess.ReadCertificateSecret(ctx, providers.SecretRequest{Name: env.certName, Version: d.Version})
	require.NoError(t, err)
	defer sec.Value.Zero()
	v, err := certs.ParseKVSecret(sec.ContentType, sec.Value.Bytes(), time.Now(), nil)
	require.NoError(t, err)
	defer v.PrivateKeyDER.Zero()
	assert.Equal(t, d.Thumbprint, azureid.ThumbprintOf(v.Leaf.Raw), "the leaf of the secret is the leaf of the version")

	// 4. A second poll that knows the first reads no details.
	known := map[string]providers.KVKnown{}
	for _, c := range res.KV.Certificates {
		if c.Details != nil && c.Details.Updated != nil {
			known[c.Name] = providers.KVKnown{Version: c.Details.Version, Thumbprint: c.Details.Thumbprint, Updated: *c.Details.Updated}
		}
	}
	res2, err := sess.Discover(ctx, providers.DiscoverRequest{Certificates: true, KVKnown: known})
	require.NoError(t, err)
	for _, c := range res2.KV.Certificates {
		if _, ok := known[c.Name]; ok {
			assert.Nil(t, c.Details, "%s: unchanged, no details read", c.Name)
		}
	}

	// 5. After a renewal the new version is detected (when the environment can renew).
	if env.renew != nil {
		env.renew(t)
		res3, err := sess.Discover(ctx, providers.DiscoverRequest{Certificates: true, KVKnown: known})
		require.NoError(t, err)
		for _, c := range res3.KV.Certificates {
			if c.Name == env.certName {
				require.NotNil(t, c.Details)
				assert.NotEqual(t, d.Version, c.Details.Version)
				require.NotEmpty(t, c.Versions)
				assert.Equal(t, c.Details.Version, c.Versions[0].Version, "newest first")
			}
		}
	}
}

func fakeContractEnv(t *testing.T) contractEnv {
	t.Helper()
	s := fakekv.Start(t, fakekv.Options{})
	s.AddCertificate("web-cert", fakekv.CertOptions{CommonName: "www.example.test", Exportable: true})
	s.AddCertificate("monitor-only", fakekv.CertOptions{CommonName: "m.example.test"})
	p := testProvider(s)
	return contractEnv{
		certName: "web-cert",
		open: func(t *testing.T) providers.Session {
			t.Helper()
			sess, err := p.Open(context.Background(), target(), &idSource{id: secretIdentity(s)}, providers.Env{Clock: clock.Real{}})
			require.NoError(t, err)
			t.Cleanup(func() { _ = sess.Close() })
			return sess
		},
		renew: func(t *testing.T) { t.Helper(); time.Sleep(1100 * time.Millisecond); s.Renew("web-cert") },
	}
}

func TestContractAgainstTheFake(t *testing.T) { runContract(t, fakeContractEnv(t)) }
