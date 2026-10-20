//go:build integration

package deployjobs

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/providers"
	"alice/internal/providers/nginx"
	"alice/internal/testutil/pki"
)

// stepParams is the params of the last step logged as name:status.
func stepParams(d inventory.Deployment, name, status string) map[string]string {
	var out map[string]string
	for _, s := range d.Steps {
		if s.Name == name && s.Status == status {
			out = s.Params
		}
	}
	return out
}

// R51: a deployment records the level its verification proved. The uploaded chain leads to a root Alice trusts, so
// the anchor is known and the served chain verified against it: trusted.
func TestDeploymentRecordsTheTrustedLevel(t *testing.T) {
	e := newEnv(t)
	s := e.addServer("web-01", wwwSite())
	id := e.request(s.locs[wwwCert])[0]
	e.drain()
	d := e.deployment(id)
	require.Equal(t, inventory.DeployStatusSucceeded, d.Status, "%s %v", d.ErrorCode, d.ErrorParams)
	assert.Equal(t, providers.LevelTrusted, d.Level)
	assert.Equal(t, providers.Trust{Status: providers.TrustTrusted, Store: providers.TrustStoreSystem, Enforced: true}, d.Trust)
	assert.Equal(t, map[string]string{"mode": "remote", "trust": providers.TrustTrusted}, stepParams(d, "verify", "ok"))
}

// R51: a private CA Alice has no root of (the upload's chain was confirmed incomplete): the anchor is unknown, so an
// untrusted chain is a warning: the deployment succeeds at level served and records why the chain did not verify.
func TestUnknownAnchorIsAWarning(t *testing.T) {
	e := newEnv(t)
	s := e.addServer("web-01", wwwSite())
	other := pki.NewCA("Private", pki.ECDSA256, e.clock.Now()).Issue(pki.Opts{CommonName: wwwName, SANs: []string{wwwName}}, e.clock.Now())
	c, _, err := e.inv.UploadCertificate(e.ctx, e.admin, inventory.UploadInput{CertificatePEM: string(other.FullchainPEM),
		PrivateKeyPEM: string(other.KeyPEM)})
	require.NoError(t, err)
	got, err := e.inv.RequestDeployment(e.ctx, e.admin, inventory.DeployRequestInput{CertificateID: c.ID, LocationIDs: []uuid.UUID{s.locs[wwwCert]},
		ConfirmIncompleteChain: true})
	require.NoError(t, err)
	e.drain()
	d := e.deployment(got[0].ID)
	require.Equal(t, inventory.DeployStatusSucceeded, d.Status, "%s %v", d.ErrorCode, d.ErrorParams)
	assert.Equal(t, providers.LevelServed, d.Level)
	assert.Equal(t, providers.Trust{Status: providers.TrustUntrusted, Error: providers.TrustErrUnknownAuthority, Port: 443,
		Store: providers.TrustStoreSystem}, d.Trust)

	// The same private CA with its root uploaded along: the root is the anchor.
	e = newEnv(t)
	s = e.addServer("web-01", wwwSite())
	ca := pki.NewCA("Private", pki.ECDSA256, e.clock.Now())
	leaf := ca.Issue(pki.Opts{CommonName: wwwName, SANs: []string{wwwName}}, e.clock.Now())
	c, _, err = e.inv.UploadCertificate(e.ctx, e.admin, inventory.UploadInput{CertificatePEM: string(leaf.FullchainPEM) + string(ca.RootPEM),
		PrivateKeyPEM: string(leaf.KeyPEM)})
	require.NoError(t, err)
	require.True(t, c.ChainComplete)
	got, err = e.inv.RequestDeployment(e.ctx, e.admin, inventory.DeployRequestInput{CertificateID: c.ID, LocationIDs: []uuid.UUID{s.locs[wwwCert]}})
	require.NoError(t, err)
	e.drain()
	d = e.deployment(got[0].ID)
	require.Equal(t, inventory.DeployStatusSucceeded, d.Status, "%s %v", d.ErrorCode, d.ErrorParams)
	assert.Equal(t, providers.LevelTrusted, d.Level)
	assert.Equal(t, providers.TrustStoreUploadedRoot, d.Trust.Store)
}

// R51: with a known anchor, the right leaf with the right chain length but a wrong intermediate fails the deployment:
// it is rolled back (the R48 guard applies as to any rollback), the record names the precise fault, the
// Administrators get the failure email, and nothing claims a level.
func TestUntrustedChainWithAKnownAnchorIsRolledBack(t *testing.T) {
	e := newEnv(t)
	s := e.addServer("web-01", wwwSite())
	wrong := pki.NewCA("Wrong", pki.ECDSA256, e.clock.Now()).Intermediate.Raw
	nwFP := pki.Fingerprint(e.nw.Cert)
	e.setProbe(func(p nginx.Probe) (nginx.Probe, error) {
		if p.LeafSHA256 == nwFP && len(p.Chain) == 2 {
			p.Chain = [][]byte{p.Chain[0], wrong}
		}
		return p, nil
	})
	id := e.request(s.locs[wwwCert])[0]
	e.drain()
	d := e.deployment(id)
	require.Equal(t, inventory.DeployStatusRolledBack, d.Status, "%s %v", d.ErrorCode, d.ErrorParams)
	assert.Equal(t, "deployment.verify_untrusted", d.ErrorCode)
	assert.Equal(t, providers.TrustErrWrongIntermediate, d.ErrorParams["trust_error"])
	assert.Equal(t, "verify", d.FailedStep)
	assert.Equal(t, providers.LevelNone, d.Level)
	assert.Equal(t, providers.Trust{Status: providers.TrustUntrusted, Error: providers.TrustErrWrongIntermediate, Port: 443,
		Store: providers.TrustStoreSystem, Enforced: true}, d.Trust)
	assert.Equal(t, map[string]string{"port": "443", "reason": "deployment.verify_untrusted", "trust_error": providers.TrustErrWrongIntermediate},
		stepParams(d, "verify", "failed"))
	assert.Equal(t, pki.Fingerprint(e.old.Cert), s.emu.Served(443, wwwName), "the previous certificate is served again")
	assert.Equal(t, 1, e.count("SELECT count(*) FROM notifications_outbox WHERE template_key = 'deployment.failed'"))
}

// R51: the in-target check of an older helper answers without the chain: the trust is unchecked, never a failure, and
// the level is served. A connection that times out once is measured again (not a bad certificate).
func TestAnOlderHelperLeavesTheTrustUnchecked(t *testing.T) {
	e := newEnv(t)
	s := e.addServer("web-01", wwwSite())
	s.emu.SetProtocol(10)
	e.setProbe(func(nginx.Probe) (nginx.Probe, error) { return nginx.Probe{}, nginx.ErrProbeUnreachable })
	id := e.request(s.locs[wwwCert])[0]
	e.drain()
	d := e.deployment(id)
	require.Equal(t, inventory.DeployStatusSucceeded, d.Status, "%s %v", d.ErrorCode, d.ErrorParams)
	assert.Equal(t, "local", d.Verified)
	assert.Equal(t, providers.LevelServed, d.Level)
	assert.Equal(t, providers.TrustUnchecked, d.Trust.Status)
}
