//go:build integration

package deployjobs

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/authz"
	"alice/internal/inventory"
)

// Scoped access (R49, design §5.6 (c)) through the whole stack: a certificate of one service is deployed to a server of
// another only with a trust from the server's service to the certificate's; a trust removed after the request stops
// the deployment at its first send, before anything reaches the server.

// newService adds a service and returns its id.
func (e *env) newService(name string) uuid.UUID {
	e.t.Helper()
	id := uuid.Must(uuid.NewV7())
	_, err := e.db.Owner.Exec(e.ctx, "INSERT INTO services (id, name, created_at, updated_at) VALUES ($1, $2, now(), now())", id, name)
	require.NoError(e.t, err)
	return id
}

// moveTarget puts a server in a service (what POST /services/{id}/actions/assign does).
func (e *env) moveTarget(target, service uuid.UUID) {
	e.t.Helper()
	_, err := e.db.Owner.Exec(e.ctx, "UPDATE targets SET service_id = $2 WHERE id = $1", target, service)
	require.NoError(e.t, err)
}

func (e *env) defaultService() uuid.UUID {
	e.t.Helper()
	var id uuid.UUID
	require.NoError(e.t, e.db.Owner.QueryRow(e.ctx, "SELECT id FROM services WHERE is_default").Scan(&id))
	return id
}

func (e *env) trust(source, target uuid.UUID) uuid.UUID {
	e.t.Helper()
	id := uuid.Must(uuid.NewV7())
	_, err := e.db.Owner.Exec(e.ctx, `INSERT INTO service_trusts (id, source_service_id, target_service_id, created_at) VALUES ($1, $2, $3, now())`,
		id, source, target)
	require.NoError(e.t, err)
	return id
}

func TestDeploymentAcrossServicesNeedsATrust(t *testing.T) {
	e := newEnv(t)
	s := e.addServer("web-01", wwwSite())
	def, pay := e.defaultService(), e.newService("Payments")
	e.moveTarget(s.target, pay)
	c := e.upload()
	require.Equal(t, def, c.ServiceID, "an upload without a service goes to the Default service")

	// No trust: refused before anything is queued or sent.
	e.evaluate()
	_, err := e.inv.RequestDeployment(e.ctx, e.admin, inventory.DeployRequestInput{CertificateID: c.ID, LocationIDs: []uuid.UUID{s.locs[wwwCert]}})
	var refused *inventory.LocationRefusalError
	require.ErrorAs(t, err, &refused)
	assert.Equal(t, s.locs[wwwCert], refused.LocationID)
	var untrusted *authz.UntrustedError
	require.ErrorAs(t, err, &untrusted)
	assert.Equal(t, authz.UntrustedError{Source: def, Target: pay}, *untrusted)
	assert.Zero(t, e.count("SELECT count(*) FROM deployments"))
	assert.Equal(t, 1, e.count("SELECT count(*) FROM audit_log WHERE action = 'deployment.denied' AND details->>'reason' = $1",
		inventory.ReasonServiceUntrusted))

	// A trust from the server's service to the certificate's: deployed.
	tr := e.trust(def, pay)
	id := e.request(s.locs[wwwCert])[0]
	e.drain()
	assert.Equal(t, inventory.DeployStatusSucceeded, e.deployment(id).Status)
	assert.Equal(t, 1, s.emu.DeployCount())

	// The trust removed after the request: the first send refuses it, the server is never contacted for it.
	_, err = e.db.Owner.Exec(e.ctx, "DELETE FROM service_trusts WHERE id = $1", tr)
	require.NoError(t, err)
	e.trust(def, pay) // again, for the request only
	_, err = e.db.Owner.Exec(e.ctx, "UPDATE certificate_locations SET deployed_fingerprint = '' WHERE id = $1", s.locs[wwwCert])
	require.NoError(t, err)
	got, err := e.inv.RequestDeployment(e.ctx, e.admin, inventory.DeployRequestInput{CertificateID: c.ID, LocationIDs: []uuid.UUID{s.locs[wwwCert]}})
	require.NoError(t, err)
	_, err = e.db.Owner.Exec(e.ctx, "DELETE FROM service_trusts")
	require.NoError(t, err)
	e.drain()
	d := e.deployment(got[0].ID)
	assert.Equal(t, inventory.DeployStateDone, d.State)
	assert.Equal(t, inventory.DeployStatusFailed, d.Status)
	assert.Equal(t, inventory.ReasonServiceUntrusted, d.ErrorCode)
	assert.Equal(t, 1, s.emu.DeployCount(), "nothing more was sent to the server")
}

// The ACME planner (design §5.6): a bound server moved to a service without a trust gets no automatic deployment; the
// binding is marked service.untrusted and one e-mail goes out; a trust lets the next run deploy and clears the mark.
func TestACMEAutoDeployAcrossServicesHoldsUntilATrust(t *testing.T) {
	w := newACMEWorld(t)
	c, _ := w.issueFirst()
	def, pay := w.defaultService(), w.newService("Payments")
	require.Equal(t, def, c.ServiceID)
	w.moveTarget(w.s.target, pay)
	cur, _ := w.renew(c)
	untrustedMails := func() int {
		return w.count("SELECT count(*) FROM notifications_outbox WHERE template_key = $1", inventory.TemplateACMEAutoDeployUntrusted)
	}

	assert.Empty(t, w.planDeploy(cur), "no trust: nothing is deployed")
	b := w.bindingState(c.ID)
	assert.Equal(t, inventory.ReasonServiceUntrusted, b.AttentionCode)
	assert.Equal(t, 1, untrustedMails())
	assert.Equal(t, 1, w.count("SELECT count(*) FROM audit_log WHERE action = 'acme.auto_deploy.untrusted'"))
	assert.Empty(t, w.planDeploy(cur))
	assert.Equal(t, 1, untrustedMails(), "the mark is the once-only flag")

	w.trust(def, pay)
	ids := w.planDeploy(cur)
	require.Len(t, ids, 1, "with a trust the next run deploys")
	w.drain()
	assert.Equal(t, inventory.DeployStatusSucceeded, w.deployment(ids[0]).Status)
	assert.Empty(t, w.bindingState(c.ID).AttentionCode, "the mark is cleared")
}
