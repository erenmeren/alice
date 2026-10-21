//go:build integration

package inventory_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/acme"
	"alice/internal/authz"
	"alice/internal/inventory"
	"alice/internal/testutil/fakeacme"
	"alice/internal/testutil/pki"
)

// incidentLocation is one location of the incident as GetIncident reports it.
func incidentLocation(t *testing.T, i inventory.Incident, loc uuid.UUID) inventory.IncidentLocation {
	t.Helper()
	for _, l := range i.Locations {
		if l.LocationID == loc {
			return l
		}
	}
	require.Failf(t, "no such location", "%s", loc)
	return inventory.IncidentLocation{}
}

// endDeployment ends a deployment as the owner: done with status, verification mode and code as given.
func (w *acmeDeployWorld) endDeployment(id uuid.UUID, status, verified, code string) {
	w.h.t.Helper()
	_, err := w.h.db.Owner.Exec(w.h.ctx, `UPDATE deployments SET state = 'done', status = $2, verified = $3, error_code = $4, finished_at = $5
WHERE id = $1`, id, status, verified, code, w.h.clock.Now())
	require.NoError(w.h.t, err)
}

// The places of an incident of another source, each as its server allows: a deployment of the replacement already
// running there is followed, a place busy with another certificate's deployment waits a few runs and then fails busy,
// a place that needs another key type fails with its code; a deployment that ended without verifying leaves the place
// unverified, one that failed without a code fails it as deployment.failed. A retry of an incident without a replacement
// waits for a person again; the replacement can be chosen anew while it needs attention.
func TestIncidentPlacesAreRequestedFollowedAndSettled(t *testing.T) {
	f := newDeployFixture(t)
	h := f.h
	h.installLicense("LIC-INCIDENT-PLACES", 5, 365)
	require.NoError(t, h.lic.Tick(h.ctx))
	w := &acmeDeployWorld{deployFixture: f}
	_, _, err := h.svc.UploadCertificate(h.ctx, f.admin, pemUpload(f.old))
	require.NoError(t, err)
	old := f.certByFingerprint(t, pki.Fingerprint(f.old.Cert))

	// web-01 www.crt already gets the replacement; web-02 www.crt is busy with another certificate; spare.crt needs RSA.
	pre, err := h.svc.RequestDeployment(h.ctx, f.admin, inventory.DeployRequestInput{CertificateID: f.cert.ID, LocationIDs: []uuid.UUID{f.loc1}})
	require.NoError(t, err)
	busy := uuid.Must(uuid.NewV7())
	_, err = h.db.Owner.Exec(h.ctx, `INSERT INTO deployments (id, certificate_id, location_id, target_id, trigger, state, status, new_fingerprint,
cert_path, key_path, created_at) VALUES ($1, $2, $3, $4, 'manual', 'queued', 'pending', $5, '/etc/nginx/ssl/www.crt', '/etc/nginx/ssl/www.key', $6)`,
		busy, f.rsaCert.ID, f.loc2, f.target2, f.rsaCert.Fingerprint, h.clock.Now())
	require.NoError(t, err)
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE certificate_locations SET key_type = 'rsa' WHERE id = $1", f.loc4)
	require.NoError(t, err)

	i, err := h.svc.StartIncident(h.ctx, f.admin, old.ID, inventory.IncidentInput{})
	require.NoError(t, err)
	require.Equal(t, inventory.IncidentAwaitingReplacement, i.State)

	// A retry while nothing replaces the certificate yet goes back to waiting for a person.
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE certificate_incidents SET state = 'needs_attention', attention_code = $2 WHERE id = $1", i.ID,
		inventory.IncidentCodeReplacementGone)
	require.NoError(t, err)
	i, err = h.svc.RetryIncident(h.ctx, f.admin, i.ID)
	require.NoError(t, err)
	assert.Equal(t, inventory.IncidentAwaitingReplacement, i.State)
	assert.Empty(t, i.AttentionCode)

	// Visible from the certificate's service only.
	in, err := h.svc.ListIncidentsIn(h.ctx, &old.ID, true, 0, authz.Only(h.defaultService()))
	require.NoError(t, err)
	require.Len(t, in, 1)
	assert.Equal(t, i.ID, in[0].ID)
	assert.Equal(t, i.Counts, in[0].Counts)
	out, err := h.svc.ListIncidentsIn(h.ctx, nil, false, 0, authz.Only(h.newService("Payments")))
	require.NoError(t, err)
	assert.Empty(t, out)

	i, err = h.svc.ChooseIncidentReplacement(h.ctx, f.admin, i.ID, f.cert.ID)
	require.NoError(t, err)
	w.advance()
	i = w.incident(i.ID)
	assert.Equal(t, map[uuid.UUID]string{f.loc1: "deploying", f.loc5: "deploying", f.loc2: "pending", f.loc3onTarget2: "deploying",
		f.loc4: "failed:" + inventory.IncidentCodeNotDeployable}, locationStatus(i))
	first := incidentLocation(t, i, f.loc1)
	require.NotNil(t, first.DeploymentID)
	assert.Equal(t, pre[0].ID, *first.DeploymentID, "the running deployment of the replacement is followed, not requested again")
	assert.Positive(t, incidentLocation(t, i, f.loc2).Attempts, "the busy place counts its attempts")
	assert.Nil(t, incidentLocation(t, i, f.loc2).DeploymentID)

	// The busy place gives up after its last attempt.
	_, err = h.db.Owner.Exec(h.ctx, "UPDATE certificate_incident_locations SET attempts = 29 WHERE incident_id = $1 AND location_id = $2", i.ID, f.loc2)
	require.NoError(t, err)
	w.advance()
	i = w.incident(i.ID)
	assert.Equal(t, "failed:"+inventory.IncidentCodeLocationBusy, locationStatus(i)[f.loc2])
	assert.Equal(t, 30, incidentLocation(t, i, f.loc2).Attempts)

	w.finish(pre[0].ID, inventory.DeployStatusSucceeded, "")
	w.endDeployment(*incidentLocation(t, i, f.loc3onTarget2).DeploymentID, inventory.DeployStatusSucceeded, "skipped", "")
	w.endDeployment(*incidentLocation(t, i, f.loc5).DeploymentID, inventory.DeployStatusFailed, "", "")
	w.advance()
	i = w.incident(i.ID)
	assert.Equal(t, map[uuid.UUID]string{f.loc1: "verified", f.loc5: "failed:deployment.failed", f.loc2: "failed:" + inventory.IncidentCodeLocationBusy,
		f.loc3onTarget2: "unverified", f.loc4: "failed:" + inventory.IncidentCodeNotDeployable}, locationStatus(i))
	assert.Equal(t, inventory.IncidentNeedsAttention, i.State)
	assert.Equal(t, inventory.IncidentCodeDeploymentsFailed, i.AttentionCode)

	// Another replacement while it needs attention: the failed places are requested again.
	i, err = h.svc.ChooseIncidentReplacement(h.ctx, f.admin, i.ID, f.rsaCert.ID)
	require.NoError(t, err)
	assert.Equal(t, inventory.IncidentDeploying, i.State)
	assert.Equal(t, map[uuid.UUID]string{f.loc1: "verified", f.loc5: "pending", f.loc2: "pending", f.loc3onTarget2: "unverified",
		f.loc4: "pending"}, locationStatus(i))
	assert.Equal(t, 2, h.audits("incident.replacement_chosen"))

	i, err = h.svc.CloseIncident(h.ctx, f.admin, i.ID)
	require.NoError(t, err)
	_, err = h.svc.RevokeIncidentNow(h.ctx, f.admin, i.ID)
	require.ErrorIs(t, err, inventory.ErrIncidentState, "a finished incident")
	_, err = h.svc.ChooseIncidentReplacement(h.ctx, f.admin, i.ID, f.cert.ID)
	require.ErrorIs(t, err, inventory.ErrIncidentState)
}

// An ACME incident whose deployments could not be verified waits for a person, who accepts them with "revoke now"; a
// CA that cannot revoke is not retried: the incident needs attention with the CA's reason, and a retry tries again. A
// replacement is never chosen by hand for an ACME certificate, and a revocation done already cannot be asked again.
func TestACMEIncidentUnverifiedPlacesAndARevocationTheCARefuses(t *testing.T) {
	w := newACMEDeployWorld(t)
	require.NoError(t, w.h.lic.Tick(w.h.ctx))
	_, cur := w.issued("www.example.test")
	w.serves(w.loc1, cur)
	i, err := w.h.svc.StartIncident(w.h.ctx, w.admin, cur, inventory.IncidentInput{})
	require.NoError(t, err)
	_, err = w.h.svc.ChooseIncidentReplacement(w.h.ctx, w.admin, i.ID, w.cert.ID)
	require.ErrorIs(t, err, inventory.ErrIncidentState, "an ACME incident orders its own replacement")
	replacement := w.complete(*i.OrderID)
	w.advance()
	for _, d := range w.deps(replacement) {
		w.endDeployment(d.ID, inventory.DeployStatusSucceeded, "skipped", "")
	}
	w.advance()
	i = w.incident(i.ID)
	assert.Equal(t, inventory.IncidentNeedsAttention, i.State)
	assert.Equal(t, inventory.IncidentCodeUnverified, i.AttentionCode)
	assert.Equal(t, map[uuid.UUID]string{w.loc1: "unverified"}, locationStatus(i))
	assert.Equal(t, "valid", revocationStatus(t, w.fake, w.certOf(cur)).Status, "nothing revoked before a person accepts")

	// The person accepts the unverified place; the CA no longer revokes: the incident needs attention at once.
	require.NoError(t, w.fake.Advertise("revokeCert", "off"))
	i, err = w.h.svc.RevokeIncidentNow(w.h.ctx, w.admin, i.ID)
	require.NoError(t, err)
	assert.Equal(t, inventory.IncidentRevoking, i.State)
	assert.Empty(t, i.AttentionCode)
	w.advance()
	i = w.incident(i.ID)
	assert.Equal(t, inventory.IncidentNeedsAttention, i.State)
	assert.Equal(t, inventory.IncidentRevocationFailed, i.Revocation)
	assert.Equal(t, acme.ReasonRevokeUnsupported, i.AttentionCode)
	assert.Equal(t, 1, i.RevokeAttempts)
	assert.Nil(t, i.NextAttemptAt, "a refusal is not retried by itself")
	assert.Equal(t, 1, w.h.audits("incident.revoke_failed"))

	// A retry asks again; the CA revokes now.
	require.NoError(t, w.fake.Advertise("revokeCert", ""))
	i, err = w.h.svc.RetryIncident(w.h.ctx, w.admin, i.ID)
	require.NoError(t, err)
	assert.Equal(t, inventory.IncidentRevocationPending, i.Revocation)
	assert.Equal(t, inventory.IncidentDeploying, i.State)
	assert.Zero(t, i.RevokeAttempts)
	assert.Equal(t, inventory.IncidentRevokeNow, i.RevokeMode, "the person's revoke now holds")
	w.advance()
	i = w.incident(i.ID)
	assert.Equal(t, inventory.IncidentCompleted, i.State, "revoked, and the accepted unverified place settles it")
	assert.Equal(t, inventory.IncidentRevocationRevoked, i.Revocation)
	assert.Equal(t, "revoked", revocationStatus(t, w.fake, w.certOf(cur)).Status)
	_, err = w.h.svc.RevokeIncidentNow(w.h.ctx, w.admin, i.ID)
	require.ErrorIs(t, err, inventory.ErrIncidentState)
}

// A CA that asks to wait (rateLimited with Retry-After) is tried again no sooner than it asked, at most an hour later.
func TestACMEIncidentRevocationHonoursTheCAsWait(t *testing.T) {
	w := newACMEDeployWorld(t)
	require.NoError(t, w.h.lic.Tick(w.h.ctx))
	_, cur := w.issued("www.example.test")
	require.NoError(t, w.fake.AddFault(fakeacme.Fault{Endpoint: "revoke-cert", Kind: fakeacme.FaultRateLimited, Times: 1,
		RetryAfter: 20 * time.Minute}))
	i, err := w.h.svc.StartIncident(w.h.ctx, w.admin, cur, inventory.IncidentInput{RevokeMode: inventory.IncidentRevokeNow})
	require.NoError(t, err)
	w.advance()
	i = w.incident(i.ID)
	assert.Equal(t, inventory.IncidentRevocationPending, i.Revocation)
	assert.Equal(t, 1, i.RevokeAttempts)
	require.NotNil(t, i.NextAttemptAt)
	assert.Equal(t, w.h.clock.Now().UTC().Add(20*time.Minute), i.NextAttemptAt.UTC(), "the CA's wait, longer than the first back-off")
}

// The provider of an ACME incident lost its account: the order cannot start and the revocation cannot be signed, each
// a closed reason a person can act on.
func TestACMEIncidentWithoutAUsableAccount(t *testing.T) {
	t.Run("the order", func(t *testing.T) {
		w := newACMEDeployWorld(t)
		require.NoError(t, w.h.lic.Tick(w.h.ctx))
		_, cur := w.issued("www.example.test")
		i, err := w.h.svc.StartIncident(w.h.ctx, w.admin, cur, inventory.IncidentInput{})
		require.NoError(t, err)
		require.NoError(t, w.h.svc.FailACMEOrder(w.h.ctx, *i.OrderID, acme.ReasonValidationFailedDNS, 0))
		_, err = w.h.db.Owner.Exec(w.h.ctx, "UPDATE jobs SET status = 'failed', finished_at = now() WHERE type = 'acme.issue' AND status = 'queued'")
		require.NoError(t, err)
		w.advance()
		_, err = w.h.svc.RetryIncident(w.h.ctx, w.admin, i.ID)
		require.NoError(t, err)
		_, err = w.h.db.Owner.Exec(w.h.ctx, "UPDATE acme_accounts SET state = 'retired' WHERE provider_id = $1", w.provider.ID)
		require.NoError(t, err)
		w.advance()
		i = w.incident(i.ID)
		assert.Equal(t, inventory.IncidentNeedsAttention, i.State)
		assert.Equal(t, "acme.account_state", i.AttentionCode)
		assert.Nil(t, i.OrderID)
		_, err = w.h.svc.RevokeACMECertificate(w.h.ctx, w.admin, *i.ACMECertificateID, inventory.ACMERevokeInput{Reason: "keyCompromise"})
		require.ErrorIs(t, err, inventory.ErrACMEAccountState, "no account signs the revocation")
	})
	t.Run("the revocation", func(t *testing.T) {
		w := newACMEDeployWorld(t)
		require.NoError(t, w.h.lic.Tick(w.h.ctx))
		_, cur := w.issued("www.example.test")
		i, err := w.h.svc.StartIncident(w.h.ctx, w.admin, cur, inventory.IncidentInput{RevokeMode: inventory.IncidentRevokeNow})
		require.NoError(t, err)
		// A key change of the account is under way (its new key is pending).
		_, err = w.h.db.Owner.Exec(w.h.ctx, `INSERT INTO acme_accounts (id, provider_id, contact_email, account_url, key_ct, key_nonce, key_wrapped_dek,
    key_version, state, pending_since, created_at, updated_at)
SELECT $2, provider_id, contact_email, account_url, key_ct, key_nonce, key_wrapped_dek, key_version, 'pending_rollover', now(), now(), now()
FROM acme_accounts WHERE provider_id = $1 AND state = 'active'`, w.provider.ID, uuid.Must(uuid.NewV7()))
		require.NoError(t, err)
		w.advance()
		i = w.incident(i.ID)
		assert.Equal(t, inventory.IncidentNeedsAttention, i.State)
		assert.Equal(t, inventory.IncidentRevocationFailed, i.Revocation)
		assert.Equal(t, "acme.rollover_pending", i.AttentionCode)
		_, err = w.h.svc.RevokeACMECertificate(w.h.ctx, w.admin, *i.ACMECertificateID, inventory.ACMERevokeInput{Reason: "keyCompromise"})
		require.ErrorIs(t, err, inventory.ErrACMERolloverPending)
		assert.Equal(t, 1, w.h.count(`SELECT count(*) FROM audit_log WHERE action = 'acme.certificate.revoke_failed'
AND details->>'error' = 'acme.rollover_pending'`))
	})
}

// failRunningOrder fails a running order as the acme.issue job does.
func (w *acmeDeployWorld) failRunningOrder(order uuid.UUID, code string) {
	w.h.t.Helper()
	require.NoError(w.h.t, w.h.svc.FailACMEOrder(w.h.ctx, order, code, 0))
	_, err := w.h.db.Owner.Exec(w.h.ctx, "UPDATE jobs SET status = 'failed', finished_at = now() WHERE type = 'acme.issue' AND status = 'queued'")
	require.NoError(w.h.t, err)
}

// An order of the ACME certificate already running when the incident starts is waited for: the incident orders its
// own replacement (with a new key) once it ended.
func TestACMEIncidentWaitsForARunningOrder(t *testing.T) {
	w := newACMEDeployWorld(t)
	require.NoError(t, w.h.lic.Tick(w.h.ctx))
	c, cur := w.issued("www.example.test")
	running, err := w.h.svc.RequestOrder(w.h.ctx, w.operator, c.ID, inventory.ACMEOrderIssue)
	require.NoError(t, err)
	i, err := w.h.svc.StartIncident(w.h.ctx, w.admin, cur, inventory.IncidentInput{})
	require.NoError(t, err)
	assert.Equal(t, inventory.IncidentOrdering, i.State)
	assert.Nil(t, i.OrderID, "the running order is not the incident's")
	assert.Zero(t, w.advance(), "still running")
	assert.Nil(t, w.incident(i.ID).OrderID)

	w.failRunningOrder(running.ID, acme.ReasonValidationFailedDNS)
	w.advance()
	i = w.incident(i.ID)
	require.NotNil(t, i.OrderID)
	assert.NotEqual(t, running.ID, *i.OrderID)
	assert.Equal(t, inventory.ACMEOrderRunning, i.OrderState)
	assert.Equal(t, inventory.IncidentOrdering, i.State)
}

// The certificate the incident's order issued is no longer usable when the incident takes it (revoked meanwhile): the
// incident needs a person instead of deploying it.
func TestACMEIncidentReplacementTheOrderIssuedIsUnusable(t *testing.T) {
	w := newACMEDeployWorld(t)
	require.NoError(t, w.h.lic.Tick(w.h.ctx))
	_, cur := w.issued("www.example.test")
	w.serves(w.loc1, cur)
	i, err := w.h.svc.StartIncident(w.h.ctx, w.admin, cur, inventory.IncidentInput{})
	require.NoError(t, err)
	replacement := w.complete(*i.OrderID)
	_, err = w.h.db.Owner.Exec(w.h.ctx, "UPDATE certificates SET revoked_at = now(), revocation_reason = 'superseded' WHERE id = $1", replacement)
	require.NoError(t, err)
	w.advance()
	i = w.incident(i.ID)
	assert.Equal(t, inventory.IncidentNeedsAttention, i.State)
	assert.Equal(t, inventory.IncidentCodeReplacementGone, i.AttentionCode)
	assert.Nil(t, i.ReplacementCertificateID)
	assert.Empty(t, w.deps(replacement), "nothing deployed")
}

// With "revoke now" the certificate is revoked whatever its order does; once revoked, a second "revoke now" does not
// apply.
func TestACMEIncidentRevokeNowOnceRevoked(t *testing.T) {
	w := newACMEDeployWorld(t)
	require.NoError(t, w.h.lic.Tick(w.h.ctx))
	_, cur := w.issued("www.example.test")
	i, err := w.h.svc.StartIncident(w.h.ctx, w.admin, cur, inventory.IncidentInput{RevokeMode: inventory.IncidentRevokeNow})
	require.NoError(t, err)
	w.failRunningOrder(*i.OrderID, acme.ReasonValidationFailedDNS)
	w.advance()
	i = w.incident(i.ID)
	assert.Equal(t, inventory.IncidentRevocationRevoked, i.Revocation)
	assert.Equal(t, inventory.IncidentNeedsAttention, i.State)
	assert.Equal(t, acme.ReasonValidationFailedDNS, i.AttentionCode)
	_, err = w.h.svc.RevokeIncidentNow(w.h.ctx, w.admin, i.ID)
	require.ErrorIs(t, err, inventory.ErrIncidentState, "nothing is left to revoke")
}

// A key-compromise incident of an ACME certificate whose only version with the key is revoked already starts with
// nothing to revoke; its places follow their own sources: one bound to another ACME certificate and one Alice cannot
// deploy to are skipped with their reasons.
func TestACMEIncidentOfARevokedVersionAndItsPlaces(t *testing.T) {
	w := newACMEDeployWorld(t)
	require.NoError(t, w.h.lic.Tick(w.h.ctx))
	c, cur := w.issued("www.example.test")
	other, _ := w.issued("api.example.test")
	for _, l := range []uuid.UUID{w.loc1, w.loc2, w.loc5} {
		w.serves(l, cur)
	}
	w.bind(w.get(other.ID), false, w.loc2)
	_, err := w.h.db.Owner.Exec(w.h.ctx, "UPDATE certificate_locations SET supported = false, unsupported_reason = 'variable' WHERE id = $1", w.loc5)
	require.NoError(t, err)
	_, err = w.h.svc.RevokeACMECertificate(w.h.ctx, w.admin, c.ID, inventory.ACMERevokeInput{Reason: "superseded"})
	require.NoError(t, err)

	i, err := w.h.svc.StartIncident(w.h.ctx, w.admin, cur, inventory.IncidentInput{})
	require.NoError(t, err)
	assert.Equal(t, inventory.IncidentRevocationRevoked, i.Revocation)
	require.NotNil(t, i.RevokedAt)
	assert.Equal(t, inventory.IncidentOrdering, i.State)
	status := locationStatus(i)
	assert.Equal(t, "pending", status[w.loc1])
	assert.Equal(t, "skipped:"+inventory.IncidentCodeFollowsOtherACME, status[w.loc2])
	assert.Equal(t, "skipped:"+inventory.IncidentCodeNotDeployable, status[w.loc5])
	d := w.h.auditDetails("incident.started")[0]
	assert.Equal(t, inventory.IncidentRevocationRevoked, d["revocation"])
}
