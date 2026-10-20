//go:build integration

package sshkeys_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/authz"
	"alice/internal/inventory"
	"alice/internal/platform/validate"
	"alice/internal/sshkeys"
)

// Scoped access (R49, design §4.4, §5.6 (c)): a generated key goes to the service named (the Default service when none
// is), a rotation's new key to the old key's; a key of one service is deployed to a server of another only with a trust,
// at the request and again when the job runs.
func TestGeneratedKeysAndDeploysAcrossServices(t *testing.T) {
	e := newEnv(t)
	var def uuid.UUID
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT id FROM services WHERE is_default").Scan(&def))
	pay := uuid.Must(uuid.NewV7())
	_, err := e.db.Owner.Exec(e.ctx, "INSERT INTO services (id, name, created_at, updated_at) VALUES ($1, 'Payments', now(), now())", pay)
	require.NoError(t, err)

	k := e.generate("ci")
	assert.Equal(t, def, k.ServiceID)
	_, err = e.svc.Generate(e.ctx, e.admin, sshkeys.GenerateInput{Label: "nowhere", ServiceID: uuid.New()})
	var v validate.Errors
	require.ErrorAs(t, err, &v)
	assert.Equal(t, "service_id", v[0].Field)
	inPay, err := e.svc.Generate(e.ctx, e.admin, sshkeys.GenerateInput{Label: "pay", ServiceID: pay})
	require.NoError(t, err)
	assert.Equal(t, pay, inPay.ServiceID)

	srv := e.server("web-01")
	_, err = e.db.Owner.Exec(e.ctx, "UPDATE targets SET service_id = $2 WHERE id = $1", srv, pay)
	require.NoError(t, err)
	in := sshkeys.DeployInput{KeyID: k.ID, TargetID: srv, OSUser: "deploy", FilePath: "/home/deploy/.ssh/authorized_keys"}
	_, err = e.svc.RequestDeploy(e.ctx, e.operator, in)
	var ue *authz.UntrustedError
	require.ErrorAs(t, err, &ue)
	assert.Equal(t, authz.UntrustedError{Source: def, Target: pay}, *ue)
	assert.Equal(t, sshkeys.DenyServiceUntrusted, e.lastAuditDetail("sshkey.deploy.denied", "reason"))
	_, err = e.svc.RequestDeploy(e.ctx, e.operator, sshkeys.DeployInput{KeyID: inPay.ID, TargetID: srv, OSUser: "deploy",
		FilePath: "/home/deploy/.ssh/authorized_keys"})
	require.NoError(t, err, "a key of the server's own service needs no trust")

	_, err = e.db.Owner.Exec(e.ctx, `INSERT INTO service_trusts (id, source_service_id, target_service_id, created_at) VALUES ($1, $2, $3, now())`,
		uuid.Must(uuid.NewV7()), def, pay)
	require.NoError(t, err)
	in.FilePath = "/root/.ssh/authorized_keys"
	in.OSUser = "root"
	id, err := e.svc.RequestDeploy(e.ctx, e.operator, in)
	require.NoError(t, err)
	_, err = e.db.Owner.Exec(e.ctx, "DELETE FROM service_trusts")
	require.NoError(t, err)
	_, err = e.svc.DeployJob(e.ctx, id, srv, e.job(id).Payload)
	assert.ErrorIs(t, err, inventory.ErrServiceUntrusted, "the job checks the trust again")
}
