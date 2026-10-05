//go:build integration

package inventory_test

import (
	"crypto/x509"
	"encoding/base64"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"software.sslmate.com/src/go-pkcs12"

	"alice/internal/certs"
	"alice/internal/inventory"
	"alice/internal/license"
	"alice/internal/platform/azureid"
	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/testutil/pki"
)

// finishQueued ends the queued deployments so that their locations are free again.
func (b *bindFixture) finishQueued(reqs ...inventory.RequestedDeployment) {
	b.h.t.Helper()
	for _, r := range reqs {
		require.NoError(b.h.t, b.h.svc.FinishDeployment(b.h.ctx, r.ID, inventory.DeploymentFinish{Status: inventory.DeployStatusFailed,
			ErrorCode: "deployment.interrupted"}))
	}
}

func (b *bindFixture) exec(sql string, args ...any) {
	b.h.t.Helper()
	_, err := b.h.db.Owner.Exec(b.h.ctx, sql, args...)
	require.NoError(b.h.t, err)
}

func TestRequestKVDeployment(t *testing.T) {
	b := newBindFixture(t)
	h, ctx := b.h, b.h.ctx
	bind := b.create(b.admin, b.web, b.loc1, b.loc2)
	v1 := b.versionID(b.web, ver(1))
	deployJobs := func() int {
		n := 0
		for _, r := range h.jobs.requests() {
			if r.Type == inventory.JobCertificateDeploy {
				n++
			}
		}
		return n
	}
	request := func(a inventory.Actor, version uuid.UUID, locs ...uuid.UUID) ([]inventory.RequestedDeployment, error) {
		return h.svc.RequestKVDeployment(ctx, a, inventory.KVDeployInput{StrictSession: true, BindingID: bind.ID, VersionID: version, LocationIDs: locs})
	}
	lastDenial := func() map[string]string { d := h.auditDetails("deployment.denied"); return d[len(d)-1] }
	var created int
	refused := func(what string, want error, reason string, a inventory.Actor, version uuid.UUID, locs ...uuid.UUID) {
		t.Helper()
		before := h.audits("deployment.denied")
		_, err := request(a, version, locs...)
		assert.ErrorIs(t, err, want, what)
		assert.Equal(t, before+1, h.audits("deployment.denied"), what)
		assert.Equal(t, reason, lastDenial()["reason"], what)
		assert.Equal(t, created, h.count("SELECT count(*) FROM deployments"), "%s: nothing is created", what)
	}

	// Deploy now of the current version to every location of the binding (an incomplete chain needs no
	// confirmation here: the chain is judged when the secret is read, KVDeployMaterial).
	assert.False(t, b.certRowChainComplete(pki.Fingerprint(b.webLeaf.Cert)), "the listing knows the leaf only")
	reqs, err := request(b.admin, v1)
	require.NoError(t, err)
	require.Len(t, reqs, 2)
	created = 2
	assert.Equal(t, 2, deployJobs())
	byLoc := map[uuid.UUID]inventory.RequestedDeployment{}
	for _, r := range reqs {
		byLoc[r.LocationID] = r
	}
	require.Contains(t, byLoc, b.loc1)
	require.Contains(t, byLoc, b.loc2)
	for loc, r := range byLoc {
		d := b.get(r.ID)
		assert.Equal(t, "manual", d.Trigger)
		assert.Equal(t, loc, d.LocationID)
		require.NotNil(t, d.BindingID)
		assert.Equal(t, bind.ID, *d.BindingID)
		assert.Equal(t, ver(1), d.KVVersion)
		assert.Equal(t, "prod", d.VaultName)
		assert.Equal(t, "key_vault", d.Source)
		assert.Equal(t, pki.Fingerprint(b.webLeaf.Cert), d.NewFingerprint)
		assert.False(t, d.ConfirmIncompleteChain)
		assert.Equal(t, inventory.DeployStateQueued, d.State)
		var kvVersion uuid.UUID
		require.NoError(t, h.db.Owner.QueryRow(ctx, "SELECT kv_version_id FROM deployments WHERE id = $1", r.ID).Scan(&kvVersion))
		assert.Equal(t, v1, kvVersion)
		require.NotNil(t, d.JobID)
	}
	ev := h.auditDetails("deployment.requested")
	require.Len(t, ev, 2)
	for _, e := range ev {
		assert.Equal(t, bind.ID.String(), e["binding_id"])
		assert.Equal(t, ver(1), e["version"])
		assert.NotEmpty(t, e["deployment_id"])
	}
	// Phase 4's own deployments keep their shape.
	assert.Equal(t, "upload", func() string {
		id := b.request(b.admin, b.cert.ID, b.loc5)
		return b.get(id).Source
	}())
	created++

	// F-15: an unfinished deployment of a location refuses the request, naming it.
	_, err = request(b.admin, v1, b.loc1)
	var lr *inventory.LocationRefusalError
	require.ErrorAs(t, err, &lr)
	assert.ErrorIs(t, err, inventory.ErrDeploymentInProgress)
	assert.Equal(t, b.loc1, lr.LocationID)
	assert.Equal(t, "in_progress", lastDenial()["reason"])
	b.finishQueued(reqs...)

	// A location outside the binding.
	_, err = request(b.admin, v1, b.loc5)
	require.ErrorAs(t, err, &lr)
	assert.ErrorIs(t, err, inventory.ErrNotFound)
	assert.Equal(t, b.loc5, lr.LocationID)
	assert.Equal(t, "location_not_in_binding", lastDenial()["reason"])
	_, err = request(b.admin, v1, uuid.New())
	assert.ErrorIs(t, err, inventory.ErrNotFound)

	// A subset of the binding's locations.
	sub, err := request(b.operator, v1, b.loc2)
	require.NoError(t, err, "an Operator deploys a version that is not held (S6)")
	require.Len(t, sub, 1)
	assert.Equal(t, b.loc2, sub[0].LocationID)
	created++
	b.finishQueued(sub...)

	// Version refusals.
	v2, other := b.versionID(b.second, ver(2)), uuid.New()
	refused("another certificate's version", inventory.ErrVersionNotDeployable, "version_not_deployable", b.admin, v2, b.loc1)
	refused("an unknown version", inventory.ErrNotFound, "version_not_found", b.admin, other, b.loc1)

	// A listed older version Alice never read the details of has no certificate row.
	h.clock.Advance(time.Minute)
	l2 := b.issue("web.example.test", pki.ECDSA256)
	h.reconcile(b.vault, kvResult(h.kvc("web-cert", l2, ver(11), h.clock.Now(), true, ver(5))))
	refused("a version without details", inventory.ErrVersionNotDeployable, "version_not_deployable", b.admin, b.versionID(b.web, ver(5)), b.loc1)

	tweak := func(set, restore string, want error, reason string) {
		t.Helper()
		b.exec("UPDATE kv_certificate_versions SET "+set+" WHERE id = $1", v1)
		refused(set, want, reason, b.admin, v1, b.loc1)
		b.exec("UPDATE kv_certificate_versions SET "+restore+" WHERE id = $1", v1)
	}
	tweak("enabled = false", "enabled = true", inventory.ErrVersionDisabled, "version_disabled")
	tweak("exportable = false", "exportable = true", inventory.ErrNotExportable, "not_exportable")
	var leafRow uuid.UUID
	require.NoError(t, h.db.Owner.QueryRow(ctx, "SELECT certificate_id FROM kv_certificate_versions WHERE id = $1", v1).Scan(&leafRow))
	var nb, na time.Time
	require.NoError(t, h.db.Owner.QueryRow(ctx, "SELECT not_before, not_after FROM certificates WHERE id = $1", leafRow).Scan(&nb, &na))
	b.exec("UPDATE certificates SET not_after = $2 WHERE id = $1", leafRow, h.clock.Now().Add(-time.Hour))
	refused("expired", inventory.ErrCertificateExpired, "expired", b.admin, v1, b.loc1)
	b.exec("UPDATE certificates SET not_after = $2, not_before = $3 WHERE id = $1", leafRow, na, h.clock.Now().Add(time.Hour))
	refused("not yet valid", inventory.ErrCertificateNotYetValid, "not_yet_valid", b.admin, v1, b.loc1)
	b.exec("UPDATE certificates SET not_before = $2 WHERE id = $1", leafRow, nb)
	b.exec("UPDATE kv_certificates SET missing_since = $2 WHERE id = $1", b.web, h.clock.Now())
	refused("removed from the vault", inventory.ErrKVCertificateMissing, "certificate_missing", b.admin, v1, b.loc1)
	b.exec("UPDATE kv_certificates SET missing_since = NULL WHERE id = $1", b.web)

	// Held: an Operator is refused, an Administrator is accepted; the hold stays.
	b.exec("UPDATE kv_certificate_versions SET held = true, held_reason = 'license' WHERE id = $1", v1)
	refused("held, by an Operator", inventory.ErrHeldNeedsAdmin, "held_needs_admin", b.operator, v1, b.loc1)
	held, err := request(b.admin, v1, b.loc1)
	require.NoError(t, err, "an Administrator may deploy a held version")
	created++
	assert.Equal(t, 1, h.count("SELECT count(*) FROM kv_certificate_versions WHERE id = $1 AND held", v1), "deploying does not release")
	b.finishQueued(held...)
	b.exec("UPDATE kv_certificate_versions SET held = false, held_reason = '' WHERE id = $1", v1)

	// Location refusals are Phase 4's (target not ready, key type).
	b.setTargetStatus(b.target1, "auth_failed")
	refused("a server that is not connected", inventory.ErrTargetNotReady, "target_not_ready", b.admin, v1, b.loc1)
	b.setTargetStatus(b.target1, "ok")
	b.exec("UPDATE certificate_locations SET key_type = 'rsa' WHERE id = $1", b.loc1)
	_, err = request(b.admin, v1, b.loc1)
	var km *inventory.KeyTypeMismatchError
	require.ErrorAs(t, err, &km)
	assert.Equal(t, "rsa", km.Expected)
	assert.Equal(t, "ecdsa", km.Actual)
	b.exec("UPDATE certificate_locations SET key_type = 'ecdsa' WHERE id = $1", b.loc1)

	// Malformed requests, an unknown or removed binding.
	var ve validate.Errors
	_, err = request(b.admin, v1, b.loc1, b.loc1)
	assert.ErrorAs(t, err, &ve, "a duplicate id")
	_, err = h.svc.RequestKVDeployment(ctx, b.admin, inventory.KVDeployInput{StrictSession: true, BindingID: uuid.New(), VersionID: v1})
	assert.ErrorIs(t, err, inventory.ErrNotFound)
	_, err = h.svc.RequestKVDeployment(ctx, b.admin, inventory.KVDeployInput{StrictSession: true, BindingID: bind.ID})
	assert.ErrorAs(t, err, &validate.Errors{}, "a version is named: never 'latest'")

	// Lock: refused with the license error and audited.
	h.clock.Advance(40 * 24 * time.Hour)
	require.NoError(t, h.lic.Tick(ctx))
	require.ErrorIs(t, h.lic.Allow(license.ClassChange), license.ErrLocked)
	_, err = request(b.admin, v1, b.loc1)
	assert.ErrorIs(t, err, license.ErrLocked)
	assert.Equal(t, "locked", lastDenial()["reason"])
}

func (b *bindFixture) certRowChainComplete(fp string) bool {
	b.h.t.Helper()
	var ok bool
	require.NoError(b.h.t, b.h.db.Owner.QueryRow(b.h.ctx, "SELECT chain_complete FROM certificates WHERE fingerprint_sha256 = $1", fp).Scan(&ok))
	return ok
}

func (b *bindFixture) certPEM(fp string) (string, string) {
	b.h.t.Helper()
	var pem, source string
	require.NoError(b.h.t, b.h.db.Owner.QueryRow(b.h.ctx, "SELECT pem_chain, source FROM certificates WHERE fingerprint_sha256 = $1", fp).Scan(&pem, &source))
	return pem, source
}

func pfxSecret(l pki.Leaf, ca *pki.CA) ([]byte, providers.CertificateSecret) {
	raw := []byte(base64.StdEncoding.EncodeToString(pki.PFX(l, ca, "")))
	return raw, providers.CertificateSecret{ContentType: certs.ContentTypePKCS12, Value: providers.NewSecret(raw)}
}

func pemSecret(text string) ([]byte, providers.CertificateSecret) {
	raw := []byte(text)
	return raw, providers.CertificateSecret{ContentType: certs.ContentTypePEM, Value: providers.NewSecret(raw)}
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func TestKVDeployMaterial(t *testing.T) {
	b := newBindFixture(t)
	h, ctx := b.h, b.h.ctx
	bind := b.create(b.admin, b.web, b.loc1, b.loc2, b.loc3)
	v1 := b.versionID(b.web, ver(1))
	fp := pki.Fingerprint(b.webLeaf.Cert)
	reqs, err := h.svc.RequestKVDeployment(ctx, b.admin, inventory.KVDeployInput{StrictSession: true, BindingID: bind.ID, VersionID: v1,
		LocationIDs: []uuid.UUID{b.loc1, b.loc2, b.loc3}})
	require.NoError(t, err)
	dep := map[uuid.UUID]uuid.UUID{}
	for _, r := range reqs {
		dep[r.LocationID] = r.ID
		_, err := h.svc.BeginDeployment(ctx, r.ID)
		require.NoError(t, err)
	}
	pemBefore, source := b.certPEM(fp)
	require.Equal(t, "azure_kv", source)
	assert.Equal(t, 1, chainCount(pemBefore), "the poll stored the leaf only")

	// DeploymentMaterial of a Key Vault deployment: the vault source, never a key (the engine reads the vault).
	m, err := h.svc.DeploymentMaterial(ctx, dep[b.loc1], true)
	require.NoError(t, err)
	require.NotNil(t, m.KV)
	assert.Empty(t, m.PrivateKeyPEM.Bytes())
	assert.Equal(t, inventory.KVSource{VaultID: b.vault, KVCertificateID: b.web, VersionID: v1, Name: "web-cert", Version: ver(1),
		Thumbprint: azureid.ThumbprintOf(b.webLeaf.Cert.Raw)}, *m.KV)
	assert.Equal(t, 1, m.NewChainLength)
	ordinaryID := b.request(b.admin, b.cert.ID, b.loc5)
	ordinary, err := h.svc.DeploymentMaterial(ctx, ordinaryID, true)
	require.NoError(t, err)
	assert.Nil(t, ordinary.KV, "an uploaded certificate's deployment has no vault source")
	assert.NotEmpty(t, ordinary.PrivateKeyPEM.Bytes())
	ordinary.PrivateKeyPEM.Zero()

	// The material of the first send: the chain as the vault delivered it minus the self-signed root, the key as PEM.
	raw, secret := pemSecret(string(b.webLeaf.KeyPEM) + string(b.webLeaf.FullchainPEM) + string(b.ca.RootPEM))
	m, err = h.svc.KVDeployMaterial(ctx, dep[b.loc1], secret)
	require.NoError(t, err)
	assert.True(t, allZero(raw), "the secret's value is zeroed")
	assert.Equal(t, string(b.webLeaf.FullchainPEM), string(m.CertificatePEM), "leaf + intermediate, the root dropped")
	assert.True(t, string(b.webLeaf.KeyPEM) == string(m.PrivateKeyPEM.Bytes()))
	assert.Equal(t, 2, m.NewChainLength)
	assert.Equal(t, sha(m.CertificatePEM), m.NewCertSHA256)
	assert.Equal(t, fp, m.Fingerprint)
	assert.Equal(t, "ecdsa", m.KeyType)
	require.NotNil(t, m.KV)
	assert.Equal(t, "web-cert", m.KV.Name)
	assert.Empty(t, m.Warnings, "the chain is complete")
	m.PrivateKeyPEM.Zero()
	pemAfter, _ := b.certPEM(fp)
	assert.Equal(t, string(b.webLeaf.FullchainPEM), pemAfter, "the certificate row keeps what is sent")
	assert.True(t, b.certRowChainComplete(fp))
	ev := h.auditDetails("kv.secret_read")
	require.Len(t, ev, 1)
	assert.Equal(t, map[string]string{"purpose": "deploy", "deployment_id": dep[b.loc1].String(), "kv_certificate_id": b.web.String(),
		"certificate_name": "web-cert", "version": ver(1)}, ev[0])
	// What a recovery job reads later is the same hash.
	again, err := h.svc.DeploymentMaterial(ctx, dep[b.loc1], false)
	require.NoError(t, err)
	assert.Equal(t, sha(m.CertificatePEM), again.NewCertSHA256)

	// A PFX works the same way (leaf + intermediate).
	raw, secret = pfxSecret(b.webLeaf, b.ca)
	m, err = h.svc.KVDeployMaterial(ctx, dep[b.loc2], secret)
	require.NoError(t, err)
	assert.True(t, allZero(raw))
	assert.Equal(t, 2, m.NewChainLength)
	m.PrivateKeyPEM.Zero()

	// Refusals; each zeroes the secret and writes nothing.
	reads := h.audits("kv.secret_read")
	check := func(what string, want error, reason string, id uuid.UUID, ct string, text string) {
		t.Helper()
		raw := []byte(text)
		_, err := h.svc.KVDeployMaterial(ctx, id, providers.CertificateSecret{ContentType: ct, Value: providers.NewSecret(raw)})
		assert.ErrorIs(t, err, want, what)
		assert.True(t, allZero(raw), "%s: zeroed", what)
		// The secret reached Alice's memory: the read is audited as a failure with the closed reason (R40 row 34).
		reads++
		assert.Equal(t, reads, h.audits("kv.secret_read"), "%s: an audit row", what)
		last := h.auditDetails("kv.secret_read")
		assert.Equal(t, reason, last[len(last)-1]["reason"], what)
		assert.Equal(t, "deploy", last[len(last)-1]["purpose"], what)
	}
	otherLeaf := b.issue("web.example.test", pki.ECDSA256)
	check("another leaf", inventory.ErrSecretMismatch, "secret_mismatch", dep[b.loc3], certs.ContentTypePEM, string(otherLeaf.KeyPEM)+string(otherLeaf.FullchainPEM))
	check("a key that does not match", inventory.ErrSecretUnreadable, "secret_unreadable", dep[b.loc3], certs.ContentTypePEM,
		string(otherLeaf.KeyPEM)+string(b.webLeaf.FullchainPEM))
	check("plain text", inventory.ErrSecretUnreadable, "secret_unreadable", dep[b.loc3], "text/plain", "hello")
	check("a certificate without its key", inventory.ErrSecretUnreadable, "not_exportable", dep[b.loc3], certs.ContentTypePEM, string(b.webLeaf.FullchainPEM))
	check("garbage PFX", inventory.ErrSecretUnreadable, "secret_unreadable", dep[b.loc3], certs.ContentTypePKCS12, "!!!")
	rsaLeaf := b.issue("web.example.test", pki.RSA2048)
	check("another key type, another leaf", inventory.ErrSecretMismatch, "secret_mismatch", dep[b.loc3], certs.ContentTypePEM, string(rsaLeaf.KeyPEM)+string(rsaLeaf.FullchainPEM))

	release, ok := inventory.HoldPFXSlots(inventory.MaxPFXDecodes())
	require.True(t, ok)
	check("both PFX slots taken", inventory.ErrPFXBusy, "pfx_busy", dep[b.loc3], certs.ContentTypePKCS12, string(base64.StdEncoding.EncodeToString(pki.PFX(b.webLeaf, b.ca, ""))))
	release()

	claimed := inventory.WithClaim(ctx, inventory.Claim{JobID: uuid.New(), Attempt: 1})
	raw, secret = pemSecret(string(b.webLeaf.KeyPEM) + string(b.webLeaf.FullchainPEM))
	b.exec("UPDATE certificates SET pem_chain = $2 WHERE fingerprint_sha256 = $1", fp, pemBefore)
	_, err = h.svc.KVDeployMaterial(claimed, dep[b.loc3], secret)
	assert.ErrorIs(t, err, inventory.ErrClaimLost, "a lost claim writes nothing")
	assert.True(t, allZero(raw))
	pemNow, _ := b.certPEM(fp)
	assert.Equal(t, pemBefore, pemNow)
	assert.Equal(t, reads, h.audits("kv.secret_read"))

	// A started deployment (a send may have happened) and a deployment that is not from a vault.
	m0, err := h.svc.DeploymentMaterial(ctx, dep[b.loc3], false)
	require.NoError(t, err)
	require.NoError(t, h.svc.StartDeployment(ctx, dep[b.loc3], m0.SendValues("", 0)))
	_, secret = pemSecret(string(b.webLeaf.KeyPEM) + string(b.webLeaf.FullchainPEM))
	_, err = h.svc.KVDeployMaterial(ctx, dep[b.loc3], secret)
	assert.ErrorIs(t, err, inventory.ErrDeploymentState, "the first send was recorded: never re-read")
	_, secret = pemSecret(string(b.webLeaf.KeyPEM) + string(b.webLeaf.FullchainPEM))
	_, err = h.svc.KVDeployMaterial(ctx, ordinaryID, secret)
	assert.ErrorIs(t, err, inventory.ErrDeploymentState, "not a Key Vault deployment")
	_, secret = pemSecret("x")
	_, err = h.svc.KVDeployMaterial(ctx, uuid.New(), secret)
	assert.ErrorIs(t, err, inventory.ErrNotFound)
}

func chainCount(pem string) int {
	n := 0
	for i := 0; i+len("BEGIN CERTIFICATE") <= len(pem); i++ {
		if pem[i:i+len("BEGIN CERTIFICATE")] == "BEGIN CERTIFICATE" {
			n++
		}
	}
	return n
}

// An uploaded certificate row with the same leaf is never changed by a vault read.
func TestKVDeployMaterialNeverChangesAnUploadedRow(t *testing.T) {
	b := newBindFixture(t)
	h, ctx := b.h, b.h.ctx
	leaf := b.issue("up.example.test", pki.ECDSA256)
	_, _, err := h.svc.UploadCertificate(ctx, b.admin, inventory.UploadInput{CertificatePEM: string(leaf.CertPEM), PrivateKeyPEM: string(leaf.KeyPEM)})
	require.NoError(t, err)
	h.reconcile(b.vault, kvResult(h.kvc("uploaded-too", leaf, ver(40), h.clock.Now(), true)))
	cert := h.certRow(b.vault, "uploaded-too").ID
	bind := b.create(b.admin, cert, b.loc1)
	reqs, err := h.svc.RequestKVDeployment(ctx, b.admin, inventory.KVDeployInput{StrictSession: true, BindingID: bind.ID, VersionID: b.versionID(cert, ver(40))})
	require.NoError(t, err)
	_, err = h.svc.BeginDeployment(ctx, reqs[0].ID)
	require.NoError(t, err)
	fp := pki.Fingerprint(leaf.Cert)
	before, source := b.certPEM(fp)
	require.Equal(t, "uploaded", source)
	require.False(t, b.certRowChainComplete(fp), "the uploaded row holds the leaf only")
	_, secret := pemSecret(string(leaf.KeyPEM) + string(leaf.FullchainPEM) + string(b.ca.RootPEM)) // the vault delivers the whole chain
	m, err := h.svc.KVDeployMaterial(ctx, reqs[0].ID, secret)
	require.NoError(t, err, "the vault's chain is judged on its own")
	m.PrivateKeyPEM.Zero()
	after, _ := b.certPEM(fp)
	assert.Equal(t, before, after, "an uploaded row is never changed")
	assert.False(t, b.certRowChainComplete(fp))
	assert.Equal(t, 2, m.NewChainLength, "what is sent is what the vault delivered")
}

// S7: F-17 is not relaxed for a Key Vault deployment; automatic deployment holds the version.
func TestKVDeployMaterialIncompleteChain(t *testing.T) {
	b := newBindFixture(t)
	h, ctx := b.h, b.h.ctx
	bind := b.create(b.admin, b.web, b.loc1, b.loc2, b.loc3)
	v1 := b.versionID(b.web, ver(1))
	fp := pki.Fingerprint(b.webLeaf.Cert)
	leafOnly := string(b.webLeaf.KeyPEM) + string(b.webLeaf.CertPEM) // the intermediate is missing: incomplete
	begin := func(a inventory.Actor, confirm bool, loc uuid.UUID) uuid.UUID {
		t.Helper()
		reqs, err := h.svc.RequestKVDeployment(ctx, a, inventory.KVDeployInput{StrictSession: true, BindingID: bind.ID, VersionID: v1, LocationIDs: []uuid.UUID{loc},
			ConfirmIncompleteChain: confirm})
		require.NoError(t, err)
		_, err = h.svc.BeginDeployment(ctx, reqs[0].ID)
		require.NoError(t, err)
		return reqs[0].ID
	}
	pemBefore, _ := b.certPEM(fp)

	// Unconfirmed: refused, nothing written, the version is not held (a person asked).
	id := begin(b.admin, false, b.loc1)
	raw, secret := pemSecret(leafOnly)
	_, err := h.svc.KVDeployMaterial(ctx, id, secret)
	assert.ErrorIs(t, err, inventory.ErrChainUnconfirmed)
	assert.True(t, allZero(raw))
	now, _ := b.certPEM(fp)
	assert.Equal(t, pemBefore, now)
	assert.Equal(t, 1, h.secretReads("failure"), "the refused read is audited")
	assert.Zero(t, h.secretReads("success"))
	assert.Zero(t, h.count("SELECT count(*) FROM kv_certificate_versions WHERE held"))
	// What the read found is kept on the version: every later manual request needs the confirmation up front.
	assert.True(t, b.chainIncomplete(v1), "the read found the chain incomplete")
	b.finishQueued(inventory.RequestedDeployment{ID: id})
	request := func(a inventory.Actor, confirm bool, loc uuid.UUID) error {
		_, err := h.svc.RequestKVDeployment(ctx, a, inventory.KVDeployInput{StrictSession: true, BindingID: bind.ID, VersionID: v1,
			LocationIDs: []uuid.UUID{loc}, ConfirmIncompleteChain: confirm})
		return err
	}
	assert.ErrorIs(t, request(b.admin, false, b.loc1), inventory.ErrChainUnconfirmed, "refused before anything is queued or read")
	// An Operator's confirmation counts for nothing (the request records it only for an Administrator).
	assert.ErrorIs(t, request(b.operator, true, b.loc2), inventory.ErrChainUnconfirmed)
	assert.Zero(t, h.count("SELECT count(*) FROM deployments WHERE state = 'queued'"), "nothing was queued")
	// A manual deployment that started before Alice knew (requested earlier) still meets the refusal at the read.
	b.exec("UPDATE kv_certificate_versions SET chain_incomplete = false WHERE id = $1", v1)
	id2 := begin(b.operator, true, b.loc2)
	assert.False(t, b.get(id2).ConfirmIncompleteChain)
	_, secret = pemSecret(leafOnly)
	_, err = h.svc.KVDeployMaterial(ctx, id2, secret)
	assert.ErrorIs(t, err, inventory.ErrChainUnconfirmed)
	assert.True(t, b.chainIncomplete(v1))

	// Confirmed by an Administrator: proceeds with a warning.
	id3 := begin(b.admin, true, b.loc3)
	assert.True(t, b.get(id3).ConfirmIncompleteChain)
	_, secret = pemSecret(leafOnly)
	m, err := h.svc.KVDeployMaterial(ctx, id3, secret)
	require.NoError(t, err)
	assert.Equal(t, []string{"chain_incomplete"}, m.Warnings)
	assert.Equal(t, 1, m.NewChainLength)
	m.PrivateKeyPEM.Zero()
	assert.False(t, b.certRowChainComplete(fp))
	assert.Equal(t, 1, h.secretReads("success"))
	assert.True(t, b.chainIncomplete(v1), "a confirmed deployment of an incomplete chain does not make it complete")
	got, err := h.svc.KVCertificate(ctx, b.vault, b.web)
	require.NoError(t, err)
	for _, v := range got.Versions {
		assert.Equal(t, v.ID == v1, v.ChainIncomplete, "the version detail says so")
	}

	// An automatic deployment (the planner's trigger) never proceeds: the version is held until an
	// Administrator deploys or releases it; a hold of another reason is kept (the first reason wins).
	b.finishQueued(inventory.RequestedDeployment{ID: id}, inventory.RequestedDeployment{ID: id2}, inventory.RequestedDeployment{ID: id3})
	auto := func() uuid.UUID {
		t.Helper()
		// The planner queues its deployment without the manual request's check (it is judged at the read).
		b.exec("UPDATE kv_certificate_versions SET chain_incomplete = false WHERE id = $1", v1)
		reqs, err := h.svc.RequestKVDeployment(ctx, b.admin, inventory.KVDeployInput{StrictSession: true, BindingID: bind.ID, VersionID: v1, LocationIDs: []uuid.UUID{b.loc1}})
		require.NoError(t, err)
		b.exec("UPDATE deployments SET trigger = 'kv_renewal' WHERE id = $1", reqs[0].ID)
		_, err = h.svc.BeginDeployment(ctx, reqs[0].ID)
		require.NoError(t, err)
		return reqs[0].ID
	}
	cur, err := h.svc.Binding(ctx, bind.ID)
	require.NoError(t, err)
	_, err = h.svc.SetAutoDeploy(ctx, b.admin, bind.ID, cur.Version, true)
	require.NoError(t, err)
	autoID := auto()
	_, secret = pemSecret(leafOnly)
	_, err = h.svc.KVDeployMaterial(ctx, autoID, secret)
	assert.ErrorIs(t, err, inventory.ErrChainUnconfirmed)
	var held bool
	var reason string
	require.NoError(t, h.db.Owner.QueryRow(ctx, "SELECT held, held_reason FROM kv_certificate_versions WHERE id = $1", v1).Scan(&held, &reason))
	assert.True(t, held)
	assert.Equal(t, "incomplete_chain", reason)
	ev := h.auditDetails("kv.version.held")
	require.Len(t, ev, 1)
	assert.Equal(t, map[string]string{"kv_certificate_id": b.web.String(), "certificate_name": "web-cert", "version": ver(1),
		"reason": "incomplete_chain", "held": "true", "deployment_id": autoID.String()}, ev[0])
	b.finishQueued(inventory.RequestedDeployment{ID: autoID})
	// A version that is held already is refused before anything is used.
	autoID = auto()
	reads := h.audits("kv.secret_read")
	_, secret = pemSecret(leafOnly)
	_, err = h.svc.KVDeployMaterial(ctx, autoID, secret)
	assert.ErrorIs(t, err, inventory.ErrVersionHeld)
	assert.Equal(t, reads+1, h.audits("kv.secret_read"), "a caller that skipped the engine's check is audited")
	last := h.auditDetails("kv.secret_read")
	assert.Equal(t, "version_held", last[len(last)-1]["reason"])
	b.finishQueued(inventory.RequestedDeployment{ID: autoID})
	// A hold of another reason that appears while the secret is being judged is kept: the first reason wins.
	b.exec("UPDATE kv_certificate_versions SET held = false, held_reason = '' WHERE id = $1", v1)
	autoID = auto()
	restore := inventory.SetKVMaterialHook(func(stage string, _ []byte) {
		if stage == "der" {
			b.exec("UPDATE kv_certificate_versions SET held = true, held_reason = 'license' WHERE id = $1", v1)
		}
	})
	defer restore()
	_, secret = pemSecret(leafOnly)
	_, err = h.svc.KVDeployMaterial(ctx, autoID, secret)
	assert.ErrorIs(t, err, inventory.ErrChainUnconfirmed)
	require.NoError(t, h.db.Owner.QueryRow(ctx, "SELECT held_reason FROM kv_certificate_versions WHERE id = $1", v1).Scan(&reason))
	assert.Equal(t, "license", reason, "the first reason wins")
	assert.Len(t, h.auditDetails("kv.version.held"), 1)
}

// chainIncomplete reads what the last read of the version's secret found about its chain.
func (b *bindFixture) chainIncomplete(version uuid.UUID) bool {
	b.h.t.Helper()
	var v bool
	require.NoError(b.h.t, b.h.db.Owner.QueryRow(b.h.ctx, "SELECT chain_incomplete FROM kv_certificate_versions WHERE id = $1", version).Scan(&v))
	return v
}

// A read that finds the chain complete clears what an earlier read found (the vault's secret was fixed).
func TestKVDeployMaterialCompleteChainClearsTheMark(t *testing.T) {
	b := newBindFixture(t)
	h, ctx := b.h, b.h.ctx
	bind := b.create(b.admin, b.web, b.loc1)
	v1 := b.versionID(b.web, ver(1))
	b.exec("UPDATE kv_certificate_versions SET chain_incomplete = true WHERE id = $1", v1)
	reqs, err := h.svc.RequestKVDeployment(ctx, b.admin, inventory.KVDeployInput{StrictSession: true, BindingID: bind.ID, VersionID: v1,
		LocationIDs: []uuid.UUID{b.loc1}, ConfirmIncompleteChain: true})
	require.NoError(t, err)
	_, err = h.svc.BeginDeployment(ctx, reqs[0].ID)
	require.NoError(t, err)
	_, secret := b.fullSecret()
	m, err := h.svc.KVDeployMaterial(ctx, reqs[0].ID, secret)
	require.NoError(t, err)
	m.PrivateKeyPEM.Zero()
	assert.Empty(t, m.Warnings)
	assert.False(t, b.chainIncomplete(v1))
}

// exportable reads the stored exportable flag of the certificate and of one of its versions.
func (b *bindFixture) exportable(cert, version uuid.UUID) (onCert, onVersion *bool) {
	b.h.t.Helper()
	require.NoError(b.h.t, b.h.db.Owner.QueryRow(b.h.ctx, "SELECT exportable FROM kv_certificates WHERE id = $1", cert).Scan(&onCert))
	require.NoError(b.h.t, b.h.db.Owner.QueryRow(b.h.ctx, "SELECT exportable FROM kv_certificate_versions WHERE id = $1", version).Scan(&onVersion))
	return onCert, onVersion
}

// A certificate whose policy became non-exportable without a new version: the poll does not notice, the
// deployment's secret read gets the certificates without the key. That read is refused as before
// (kv.secret_unreadable), and the certificate and the version are stored as not exportable, so the next
// request answers kv.not_exportable and the page shows Monitor only. A secret that is wrong otherwise marks
// nothing.
func TestKVDeployMaterialWithoutAKeyMarksTheCertificateNotExportable(t *testing.T) {
	for name, secret := range map[string]func(b *bindFixture) ([]byte, providers.CertificateSecret){
		"pem": func(b *bindFixture) ([]byte, providers.CertificateSecret) {
			return pemSecret(string(b.webLeaf.FullchainPEM))
		},
		"pfx (openssl -nokeys shape)": func(b *bindFixture) ([]byte, providers.CertificateSecret) {
			raw := []byte(base64.StdEncoding.EncodeToString(pki.CertificatesOnlyPFX("", b.webLeaf.Cert, b.ca.Intermediate)))
			return raw, providers.CertificateSecret{ContentType: certs.ContentTypePKCS12, Value: providers.NewSecret(raw)}
		},
		"pfx (Java trust store)": func(b *bindFixture) ([]byte, providers.CertificateSecret) {
			store, err := pkcs12.Modern.EncodeTrustStore([]*x509.Certificate{b.webLeaf.Cert, b.ca.Intermediate}, "")
			require.NoError(b.h.t, err)
			raw := []byte(base64.StdEncoding.EncodeToString(store))
			return raw, providers.CertificateSecret{ContentType: certs.ContentTypePKCS12, Value: providers.NewSecret(raw)}
		},
	} {
		t.Run(name, func(t *testing.T) {
			b := newBindFixture(t)
			h, ctx := b.h, b.h.ctx
			bind := b.create(b.admin, b.web, b.loc1, b.loc2, b.loc3)
			v1 := b.versionID(b.web, ver(1))
			ids := b.beginKV(b.admin, bind.ID, v1, false, b.loc1, b.loc2)

			// A key that does not fit marks nothing.
			other := b.issue("web.example.test", pki.ECDSA256)
			_, wrong := pemSecret(string(other.KeyPEM) + string(b.webLeaf.FullchainPEM))
			_, err := h.svc.KVDeployMaterial(ctx, ids[1], wrong)
			require.ErrorIs(t, err, inventory.ErrSecretUnreadable)
			onCert, onVersion := b.exportable(b.web, v1)
			require.NotNil(t, onCert)
			assert.True(t, *onCert)
			assert.True(t, onVersion == nil || *onVersion)

			raw, sec := secret(b)
			_, err = h.svc.KVDeployMaterial(ctx, ids[0], sec)
			require.ErrorIs(t, err, inventory.ErrSecretUnreadable, "this attempt ends as before")
			assert.True(t, allZero(raw))
			onCert, onVersion = b.exportable(b.web, v1)
			require.NotNil(t, onCert)
			require.NotNil(t, onVersion)
			assert.False(t, *onCert, "the certificate is Monitor only now")
			assert.False(t, *onVersion)
			last := h.auditDetails("kv.secret_read")
			assert.Equal(t, "not_exportable", last[len(last)-1]["reason"])

			// The next attempt is refused before anything is read.
			_, err = h.svc.RequestKVDeployment(ctx, b.admin, inventory.KVDeployInput{StrictSession: true, BindingID: bind.ID, VersionID: v1,
				LocationIDs: []uuid.UUID{b.loc3}})
			require.ErrorIs(t, err, inventory.ErrNotExportable)

			// A later poll that reads the certificate's policy again (Azure moved its updated time) and finds the key
			// exportable clears the mark on both rows, and Deploy now is accepted again.
			h.clock.Advance(time.Minute)
			h.reconcile(b.vault, kvResult(h.kvc("web-cert", b.webLeaf, ver(1), h.clock.Now(), true)))
			onCert, onVersion = b.exportable(b.web, v1)
			require.NotNil(t, onCert)
			require.NotNil(t, onVersion)
			assert.True(t, *onCert, "the poll's policy wins")
			assert.True(t, *onVersion)
			_, err = h.svc.RequestKVDeployment(ctx, b.admin, inventory.KVDeployInput{StrictSession: true, BindingID: bind.ID, VersionID: v1,
				LocationIDs: []uuid.UUID{b.loc3}})
			require.NoError(t, err)
		})
	}
}
