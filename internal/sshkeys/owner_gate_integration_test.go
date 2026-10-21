//go:build integration

package sshkeys_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// SR-27 (R56, design §7.2 ruling): the rotation notice gate counts a delivered copy to any recipient of the notice,
// owners included. With no Administrator address, the run's notice goes only to the owner of the key's service; its
// delivery in time lets the scheduled run start.
func TestRotationNoticeDeliveredOnlyToAnOwnerOpensTheGate(t *testing.T) {
	e := newEnv(t)
	e.tick.on.Store(true)
	_, err := e.db.Owner.Exec(e.ctx, "UPDATE users SET email = '' WHERE role = 'admin'")
	require.NoError(t, err)
	owner := e.user("olga", "operator")
	_, err = e.db.Owner.Exec(e.ctx, `INSERT INTO service_owners (id, service_id, user_id, created_at)
VALUES ($1, (SELECT id FROM services WHERE is_default), $2, now())`, uuid.Must(uuid.NewV7()), owner.UserID)
	require.NoError(t, err)

	k := e.deployed("ci", e.server("web-01"), "deploy")
	p := e.enabledPolicy(k.ID, 90, 7, 24)
	e.clock.Advance(89 * 24 * time.Hour)
	_, err = e.svc.PlanDue(e.ctx)
	require.NoError(t, err)
	r := e.onlyRun(p.ID)
	var to string
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, `SELECT string_agg(to_address, ',') FROM notifications_outbox
WHERE template_key = 'rotation.preview' AND params->>'rotation_id' = $1`, r.ID.String()).Scan(&to))
	assert.Equal(t, "olga@example.com", to, "the notice goes to the owner only")

	at := r.PlannedFor
	_, err = e.db.Owner.Exec(e.ctx, `UPDATE notifications_outbox SET status = 'sent', sent_at = $2 WHERE params->>'rotation_id' = $1`,
		r.ID.String(), at)
	require.NoError(t, err)
	e.clock.Set(r.PlannedFor)
	require.NoError(t, e.svc.Advance(e.ctx, r.ID))
	assert.Equal(t, "adding_new", e.run(r.ID).Status, "the owner's delivered copy opens the gate")
}
