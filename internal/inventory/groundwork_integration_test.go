//go:build integration

package inventory_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/rbac"
	"alice/internal/testutil/pki"
)

// R59 G1-G5 groundwork through the inventory. The kind of a location is independent of its target's type in this
// phase (the target phases add their types to the discovery and deployment paths), so a non-file location is reported
// here by an Nginx server next to its files.

func secretLocation(name string, leaf pki.Leaf, details map[string]any) providers.DiscoveredCertificate {
	return providers.DiscoveredCertificate{Location: providers.CertLocation{Kind: providers.LocationK8sTLSSecret,
		Locator: providers.Locator{"namespace": "shop", "name": name}, Details: details, CertPath: "shop/" + name, Supported: true,
		KeyPath: "/must/not/be/kept", KeyMode: "0600", KeyOwner: "root", Symlinked: true, ResolvedCertPath: "/x",
		Servers: []providers.CertServer{{Names: []string{"www.example.test"}, Section: "Ingress/shop/web",
			Listens: []providers.CertListen{{Addr: "10.20.0.5", Port: 443}}}}},
		PEMChain: leaf.FullchainPEM, FileSHA256: sha(leaf.FullchainPEM)}
}

// reconcileWithSecret reports target1's two files and the Secret.
func reconcileWithSecret(t *testing.T, f *deployFixture, secret providers.DiscoveredCertificate) {
	t.Helper()
	_, err := f.h.svc.Reconcile(f.h.ctx, f.target1, providers.DiscoveryResult{WebServer: nginxOK, Certificates: []providers.DiscoveredCertificate{
		dc(cl("/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key", "www.example.test"), f.old),
		dc(cl("/etc/nginx/ssl/b.crt", "/etc/nginx/ssl/b.key", "www.example.test"), f.old), secret}})
	require.NoError(t, err)
}

func TestLocationOfAnotherKindIsStoredByItsLocator(t *testing.T) {
	f := newDeployFixture(t)
	h := f.h
	before := locationRows(t, h, f.target1, "last_seen_at", "file_observed_at")
	reconcileWithSecret(t, f, secretLocation("shop-tls", f.old, map[string]any{"resource_version": "12"}))
	locs := byPath(t, h, f.target1, false)
	require.Len(t, locs, 3)
	s := locs["shop/shop-tls"]
	assert.Equal(t, providers.LocationK8sTLSSecret, s.Kind)
	assert.True(t, s.Locator.Equal(providers.Locator{"namespace": "shop", "name": "shop-tls"}))
	assert.Equal(t, map[string]any{"resource_version": "12"}, s.Details)
	assert.Empty(t, s.KeyPath, "no key path, no Unix key facts for a Secret")
	assert.Empty(t, s.KeyMode)
	assert.Empty(t, s.KeyOwner)
	assert.Empty(t, s.ResolvedCertPath)
	assert.False(t, s.Symlinked)
	assert.True(t, s.Supported)
	assert.Equal(t, pki.Fingerprint(f.old.Cert), s.Certificate.Fingerprint, "linked to inventory by fingerprint")
	assert.Equal(t, sha(f.old.FullchainPEM), s.CertFileSHA256, "the compare-and-swap token")
	www := locs["/etc/nginx/ssl/www.crt"]
	assert.Equal(t, providers.LocationServerFile, www.Kind)
	assert.Nil(t, www.Locator)
	assert.Nil(t, www.Details)
	assert.Equal(t, before, locationRows(t, h, f.target1, "last_seen_at", "file_observed_at")[:2], "the files' rows are unchanged")

	// The same report changes nothing (the version stays); new details are stored with a new version.
	reconcileWithSecret(t, f, secretLocation("shop-tls", f.old, map[string]any{"resource_version": "12"}))
	assert.Equal(t, s.Version, byPath(t, h, f.target1, false)["shop/shop-tls"].Version)
	reconcileWithSecret(t, f, secretLocation("shop-tls", f.old, map[string]any{"resource_version": "13"}))
	again := byPath(t, h, f.target1, false)["shop/shop-tls"]
	assert.Equal(t, s.Version+1, again.Version)
	assert.Equal(t, map[string]any{"resource_version": "13"}, again.Details)

	// Details too large are dropped with list_truncated; an invalid locator, an unknown kind or a missing path are not
	// stored at all.
	huge := map[string]any{"blob": string(make([]byte, providers.MaxDetailsBytes))}
	reconcileWithSecret(t, f, secretLocation("shop-tls", f.old, huge))
	again = byPath(t, h, f.target1, false)["shop/shop-tls"]
	assert.Nil(t, again.Details)
	assert.Contains(t, again.Warnings, providers.WarnListTruncated)
	for name, d := range map[string]providers.DiscoveredCertificate{
		"bad locator": func() providers.DiscoveredCertificate {
			x := secretLocation("x1", f.old, nil)
			x.Location.Locator = providers.Locator{}
			return x
		}(),
		"unknown kind": func() providers.DiscoveredCertificate {
			x := secretLocation("x2", f.old, nil)
			x.Location.Kind = "ssh_file"
			return x
		}(),
		"no text": func() providers.DiscoveredCertificate {
			x := secretLocation("x3", f.old, nil)
			x.Location.CertPath = ""
			return x
		}(),
	} {
		reconcileWithSecret(t, f, d)
		assert.Len(t, byPath(t, h, f.target1, false), 2, "%s: not stored, and the Secret it replaced is missing now", name)
		reconcileWithSecret(t, f, secretLocation("shop-tls", f.old, nil))
	}

	// A provider that reports another locator under the same text is not stored and does not make the stored one
	// missing; another text with the same locator neither.
	moved := secretLocation("shop-tls", f.old, nil)
	moved.Location.Locator = providers.Locator{"namespace": "shop", "name": "renamed"}
	reconcileWithSecret(t, f, moved)
	locs = byPath(t, h, f.target1, false)
	require.Contains(t, locs, "shop/shop-tls", "kept, not missing")
	assert.True(t, locs["shop/shop-tls"].Locator.Equal(providers.Locator{"namespace": "shop", "name": "shop-tls"}))
	renamed := secretLocation("shop-tls", f.old, nil)
	renamed.Location.CertPath = "shop/other-text"
	reconcileWithSecret(t, f, renamed)
	assert.NotContains(t, byPath(t, h, f.target1, false), "shop/other-text")

	// A complete scan without it marks it missing, as a file.
	_, err := h.svc.Reconcile(h.ctx, f.target1, providers.DiscoveryResult{WebServer: nginxOK, Certificates: []providers.DiscoveredCertificate{
		dc(cl("/etc/nginx/ssl/www.crt", "/etc/nginx/ssl/www.key", "www.example.test"), f.old),
		dc(cl("/etc/nginx/ssl/b.crt", "/etc/nginx/ssl/b.key", "www.example.test"), f.old)}})
	require.NoError(t, err)
	assert.NotNil(t, byPath(t, h, f.target1, true)["shop/shop-tls"].MissingSince)
}

func TestProbeAddressOfALocation(t *testing.T) {
	f := newDeployFixture(t)
	h := f.h
	reconcileWithSecret(t, f, secretLocation("shop-tls", f.old, nil))
	s := byPath(t, h, f.target1, false)["shop/shop-tls"]
	addr := " 2001:DB8::0:7 "
	got, err := h.svc.UpdateLocation(h.ctx, f.admin, s.ID, s.Version, inventory.LocationPatch{VerifyAddress: &addr})
	require.NoError(t, err)
	assert.Equal(t, "2001:db8::7", got.VerifyAddress, "one form per address")
	assert.Equal(t, s.Version+1, got.Version)
	host := "LB.internal.example.test"
	got, err = h.svc.UpdateLocation(h.ctx, f.admin, s.ID, got.Version, inventory.LocationPatch{VerifyAddress: &host})
	require.NoError(t, err)
	assert.Equal(t, "lb.internal.example.test", got.VerifyAddress)
	assert.Equal(t, 1, h.count(`SELECT count(*) FROM audit_log WHERE action = 'location.updated' AND details->>'verify_address' = 'lb.internal.example.test'`))
	for _, bad := range []string{"10.0.0.5%2", "fe80::1%eth0", "lb internal", "*.example.test", "a_b.example.test"} {
		_, err = h.svc.UpdateLocation(h.ctx, f.admin, s.ID, got.Version, inventory.LocationPatch{VerifyAddress: &bad})
		var ve validate.Errors
		require.ErrorAs(t, err, &ve, bad)
		assert.Equal(t, "verify_address", ve[0].Field)
	}
	empty := ""
	got, err = h.svc.UpdateLocation(h.ctx, f.admin, s.ID, got.Version, inventory.LocationPatch{VerifyAddress: &empty})
	require.NoError(t, err)
	assert.Empty(t, got.VerifyAddress, "cleared")

	// A certificate file takes none: refused, nothing changed.
	www := byPath(t, h, f.target1, false)["/etc/nginx/ssl/www.crt"]
	ip := "10.0.0.9"
	_, err = h.svc.UpdateLocation(h.ctx, f.admin, www.ID, www.Version, inventory.LocationPatch{VerifyAddress: &ip})
	var ve validate.Errors
	require.ErrorAs(t, err, &ve)
	assert.Equal(t, validate.FieldError{Field: "verify_address", Code: validate.Pattern}, ve[0])
	assert.Equal(t, www.Version, byPath(t, h, f.target1, false)["/etc/nginx/ssl/www.crt"].Version)
	_, err = h.svc.UpdateLocation(h.ctx, f.admin, www.ID, www.Version, inventory.LocationPatch{VerifyAddress: &empty})
	require.NoError(t, err, "clearing is always allowed")
	assert.Zero(t, h.count(`SELECT count(*) FROM audit_log WHERE action = 'location.updated' AND details ? 'verify_address'
AND details->>'location_id' = $1`, www.ID.String()), "a file's audit row is unchanged")
}

func TestDeploymentToAnotherKind(t *testing.T) {
	f := newDeployFixture(t)
	h := f.h
	reconcileWithSecret(t, f, secretLocation("shop-tls", f.old, map[string]any{"resource_version": "12"}))
	s := byPath(t, h, f.target1, false)["shop/shop-tls"]
	addr := "10.20.0.5"
	_, err := h.svc.UpdateLocation(h.ctx, f.admin, s.ID, s.Version, inventory.LocationPatch{VerifyAddress: &addr})
	require.NoError(t, err)
	f.setConfigValid(f.target1, false) // the web server's configuration gates its files only

	id := f.request(f.admin, f.cert.ID, s.ID)
	var kind, certPath, keyPath string
	require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT location_kind, cert_path, key_path FROM deployments WHERE id = $1", id).
		Scan(&kind, &certPath, &keyPath))
	assert.Equal(t, []string{"k8s_tls_secret", "shop/shop-tls", ""}, []string{kind, certPath, keyPath})
	_, err = h.svc.RequestDeployment(h.ctx, f.admin, inventory.DeployRequestInput{CertificateID: f.cert.ID, LocationIDs: []uuid.UUID{f.loc1}})
	assert.ErrorIs(t, err, inventory.ErrNginxConfigInvalid, "a file of the same server still needs a valid configuration")

	m, err := h.svc.DeploymentMaterial(h.ctx, id, true)
	require.NoError(t, err)
	defer m.PrivateKeyPEM.Zero()
	assert.Equal(t, providers.LocationK8sTLSSecret, m.Location.Kind)
	assert.True(t, m.Location.Locator.Equal(providers.Locator{"namespace": "shop", "name": "shop-tls"}))
	assert.Equal(t, map[string]any{"resource_version": "12"}, m.Location.Details)
	assert.Equal(t, "10.20.0.5", m.Verify.Address)
	assert.True(t, m.ConfigValid)
	req := m.DeployRequest(m.SendValues("", 0))
	assert.NotNil(t, req.Backups, "every request carries the deployment's held backup store")
	assert.NotNil(t, m.RollbackRequest(m.Guard).Backups)
	assert.Equal(t, "10.20.0.5", m.PrecheckRequest().Verify.Address)

	// A file's request is exactly as before: no kind, no locator, no probe address.
	fileID := f.request(f.admin, f.cert.ID, f.loc2)
	fm, err := h.svc.DeploymentMaterial(h.ctx, fileID, false)
	require.NoError(t, err)
	assert.Equal(t, providers.LocationKind(""), fm.Location.Kind)
	assert.Nil(t, fm.Location.Locator)
	assert.Nil(t, fm.Location.Details)
	assert.Empty(t, fm.Verify.Address)
}

func TestHeldBackups(t *testing.T) {
	f := newDeployFixture(t)
	h := f.h
	reconcileWithSecret(t, f, secretLocation("shop-tls", f.old, nil))
	s := byPath(t, h, f.target1, false)["shop/shop-tls"]
	id := f.request(f.admin, f.cert.ID, s.ID)
	store := h.svc.HeldBackups(id)

	_, err := store.Load(h.ctx)
	assert.ErrorIs(t, err, providers.ErrNoHeldBackup)
	other := f.ca.Issue(pki.Opts{CommonName: "other.example.test", SANs: []string{"other.example.test"}}, h.clock.Now())
	assert.Error(t, store.Hold(h.ctx, providers.HeldBackup{CertificatePEM: f.old.FullchainPEM, PrivateKeyPEM: providers.NewSecret(other.KeyPEM)}),
		"a key that is not the leaf's is never held")
	assert.Error(t, store.Hold(h.ctx, providers.HeldBackup{CertificatePEM: []byte("junk"), PrivateKeyPEM: providers.NewSecret(f.old.KeyPEM)}))
	assert.Zero(t, h.count("SELECT count(*) FROM deployment_backups"))

	require.NoError(t, store.Hold(h.ctx, providers.HeldBackup{CertificatePEM: f.old.FullchainPEM, PrivateKeyPEM: providers.NewSecret(f.old.KeyPEM)}))
	require.NoError(t, store.Hold(h.ctx, providers.HeldBackup{CertificatePEM: other.FullchainPEM, PrivateKeyPEM: providers.NewSecret(other.KeyPEM)}),
		"a second hold keeps the first")
	b, err := store.Load(h.ctx)
	require.NoError(t, err)
	assert.Equal(t, f.old.FullchainPEM, b.CertificatePEM)
	assert.Equal(t, f.old.KeyPEM, b.PrivateKeyPEM.Bytes())
	b.Zero()
	var leaf, spki string
	var ct []byte
	require.NoError(t, h.db.Owner.QueryRow(h.ctx, "SELECT leaf_sha256, spki_sha256, ciphertext FROM deployment_backups WHERE deployment_id = $1", id).
		Scan(&leaf, &spki, &ct))
	assert.Equal(t, pki.Fingerprint(f.old.Cert), leaf)
	assert.NotContains(t, string(ct), "PRIVATE KEY", "sealed")

	// Another deployment's store cannot open it (the AAD names the row).
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE deployments SET location_id = location_id WHERE id = $1", id)
	require.NoError(t, err)
	fileID := f.request(f.admin, f.cert.ID, f.loc2)
	_, err = h.db.Owner.Exec(h.ctx, `INSERT INTO deployment_backups (deployment_id, location_id, leaf_sha256, spki_sha256, ciphertext, nonce,
    wrapped_dek, key_version, created_at) SELECT $2, $3, leaf_sha256, spki_sha256, ciphertext, nonce, wrapped_dek, key_version, created_at
FROM deployment_backups WHERE deployment_id = $1`, id, fileID, f.loc2)
	require.NoError(t, err)
	_, err = h.svc.HeldBackups(fileID).Load(h.ctx)
	require.Error(t, err)
	assert.NotErrorIs(t, err, providers.ErrNoHeldBackup)

	// Fenced to the job's claim; refused for an unknown or a final deployment.
	lost := inventory.WithClaim(h.ctx, inventory.Claim{JobID: uuid.New(), Attempt: 1})
	assert.ErrorIs(t, h.svc.HeldBackups(id).Hold(lost, providers.HeldBackup{CertificatePEM: f.old.FullchainPEM,
		PrivateKeyPEM: providers.NewSecret(f.old.KeyPEM)}), inventory.ErrClaimLost)
	assert.ErrorIs(t, h.svc.HeldBackups(uuid.New()).Hold(h.ctx, providers.HeldBackup{CertificatePEM: f.old.FullchainPEM,
		PrivateKeyPEM: providers.NewSecret(f.old.KeyPEM)}), inventory.ErrNotFound)

	// The retention: never while unfinished, 7 days after final.
	n, err := h.svc.PurgeHeldBackups(h.ctx)
	require.NoError(t, err)
	assert.Zero(t, n)
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE deployments SET state = 'done', status = 'succeeded', finished_at = $2 WHERE id = $1", id, h.clock.Now())
	require.NoError(t, err)
	assert.ErrorIs(t, h.svc.HeldBackups(id).Hold(h.ctx, providers.HeldBackup{CertificatePEM: f.old.FullchainPEM,
		PrivateKeyPEM: providers.NewSecret(f.old.KeyPEM)}), inventory.ErrDeploymentState)
	h.clock.Advance(inventory.HeldBackupRetention - time.Minute)
	n, err = h.svc.PurgeHeldBackups(h.ctx)
	require.NoError(t, err)
	assert.Zero(t, n)
	h.clock.Advance(time.Minute)
	n, err = h.svc.PurgeHeldBackups(h.ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	_, err = h.svc.HeldBackups(id).Load(h.ctx)
	assert.ErrorIs(t, err, providers.ErrNoHeldBackup)
	assert.Equal(t, 1, h.count("SELECT count(*) FROM deployment_backups"), "the other deployment's copy is unfinished")
}

func TestTargetCredentialsOfAPITargets(t *testing.T) {
	h := newHarness(t)
	password, token := "pw-"+uuid.NewString(), "tok-"+uuid.NewString()
	leaf := pki.NewCA("Client", pki.ECDSA256, start).Issue(pki.Opts{CommonName: "alice"}, start)
	bigip, err := h.svc.AddAPITarget(h.ctx, h.db.Owner, providers.TargetTypeF5BigIP, "bigip-1", "bigip.example.test",
		providers.TargetSecret{Kind: providers.TargetSecretPassword, Username: "alice-svc", Password: providers.NewSecret([]byte(password))})
	require.NoError(t, err)
	tokenCluster, err := h.svc.AddAPITarget(h.ctx, h.db.Owner, providers.TargetTypeKubernetes, "cluster-1", "k8s-1.example.test",
		providers.TargetSecret{Kind: providers.TargetSecretToken, Token: providers.NewSecret([]byte(token))})
	require.NoError(t, err)
	certCluster, err := h.svc.AddAPITarget(h.ctx, h.db.Owner, providers.TargetTypeKubernetes, "cluster-2", "k8s-2.example.test",
		providers.TargetSecret{Kind: providers.TargetSecretClientCertificate, ClientCertificatePEM: leaf.CertPEM,
			ClientKeyPEM: providers.NewSecret(leaf.KeyPEM)})
	require.NoError(t, err)

	sec, release, err := h.svc.TargetCredentials(bigip).TargetSecret(h.ctx)
	require.NoError(t, err)
	assert.Equal(t, "alice-svc", sec.Username)
	assert.Equal(t, password, string(sec.Password.Bytes()))
	release()
	assert.NotEqual(t, password, string(sec.Password.Bytes()), "release zeroes it")

	sec, release, err = h.svc.TargetCredentials(tokenCluster).TargetSecret(h.ctx)
	require.NoError(t, err)
	assert.Equal(t, providers.TargetSecretToken, sec.Kind)
	assert.Equal(t, token, string(sec.Token.Bytes()))
	release()

	sec, release, err = h.svc.TargetCredentials(certCluster).TargetSecret(h.ctx)
	require.NoError(t, err)
	assert.Equal(t, leaf.CertPEM, sec.ClientCertificatePEM)
	assert.Equal(t, leaf.KeyPEM, sec.ClientKeyPEM.Bytes())
	release()

	_, _, err = h.svc.TargetCredentials(bigip).SSHSigner(h.ctx)
	assert.Error(t, err, "an API target has no SSH key")
	_, _, err = h.svc.TargetCredentials(uuid.New()).TargetSecret(h.ctx)
	assert.ErrorIs(t, err, inventory.ErrNotFound)

	for name, c := range map[string]struct {
		typ string
		sec providers.TargetSecret
	}{
		"a token for a BIG-IP":        {providers.TargetTypeF5BigIP, providers.TargetSecret{Kind: providers.TargetSecretToken, Token: providers.NewSecret([]byte("t"))}},
		"a password for a cluster":    {providers.TargetTypeKubernetes, providers.TargetSecret{Kind: providers.TargetSecretPassword, Username: "u", Password: providers.NewSecret([]byte("p"))}},
		"a password without a user":   {providers.TargetTypeF5BigIP, providers.TargetSecret{Kind: providers.TargetSecretPassword, Password: providers.NewSecret([]byte("p"))}},
		"an empty token":              {providers.TargetTypeKubernetes, providers.TargetSecret{Kind: providers.TargetSecretToken}},
		"a certificate without a key": {providers.TargetTypeKubernetes, providers.TargetSecret{Kind: providers.TargetSecretClientCertificate, ClientCertificatePEM: leaf.CertPEM}},
		"a Windows server":            {providers.TargetTypeWindows, providers.TargetSecret{Kind: providers.TargetSecretToken, Token: providers.NewSecret([]byte("t"))}},
	} {
		_, err := h.svc.AddAPITarget(h.ctx, h.db.Owner, c.typ, "x-"+uuid.NewString()[:8], uuid.NewString()[:8]+".example.test", c.sec)
		assert.Error(t, err, name)
	}

	// A credential whose row no longer suits the target is never used.
	_, err = h.db.Owner.Exec(h.ctx, `UPDATE credentials SET public_info = '{"secret":"token"}' WHERE target_id = $1`, bigip)
	require.NoError(t, err)
	_, _, err = h.svc.TargetCredentials(bigip).TargetSecret(h.ctx)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), password)
}

func TestTLSIdentityInTheHostKeyFlow(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	tg := okTarget(t, h, admin, "bigip")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	id := providers.TLSIdentity(spki)
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE targets SET status = 'pending_host_key' WHERE id = $1", tg.ID)
	require.NoError(t, err)
	require.NoError(t, h.svc.HostKeyStore().Observed(h.ctx, tg.ID, id, false))
	_, err = h.svc.ConfirmHostKey(h.ctx, admin, tg.ID, keyID(t, h, tg.ID, id.Fingerprint), id.Fingerprint)
	require.NoError(t, err)
	pinned, err := h.svc.HostKeyStore().Pinned(h.ctx, tg.ID)
	require.NoError(t, err)
	assert.Equal(t, id, pinned, "a TLS identity is pinned as an SSH host key is")
	assert.Contains(t, inventory.VerifyCommand(providers.HostKeyTypeTLSSPKI), "openssl s_client")

	bad := id
	bad.Fingerprint = providers.TLSIdentity([]byte("x")).Fingerprint
	err = h.svc.HostKeyStore().Observed(h.ctx, tg.ID, bad, true)
	require.Error(t, err)
	assert.False(t, errors.Is(err, context.Canceled))
	assert.Equal(t, inventory.StatusChecking, statusOf(t, h, tg.ID), "an inconsistent sighting changes nothing")
}
