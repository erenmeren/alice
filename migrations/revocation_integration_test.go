//go:build integration

package migrations_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/testutil/pgtest"
	"alice/migrations"
)

const (
	revocationFinal = "Z1022" // a revoked or compromised certificate stays so
	incidentFrozen  = "Z1023" // a finished incident is history
)

// 00021: a certificate's revocation and compromise marks are final once set; the incident tables keep one open incident
// per certificate and freeze a finished one; discovery certificates take a public key hash.
func TestMigration00021Revocation(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	w := seedAcme(t, d)
	user := seedUser(t, d, "Ada", "ada@example.test")

	// The marks: a reason only with a time, then never changed or cleared.
	assert.Equal(t, checkViolation, sqlState(exec(t, d.App, "UPDATE certificates SET revocation_reason = 'keyCompromise' WHERE id = $1", w.cert)))
	assert.Equal(t, checkViolation, sqlState(exec(t, d.App, "UPDATE certificates SET revoked_at = now(), revocation_reason = 'cACompromise' WHERE id = $1", w.cert)))
	assert.Equal(t, checkViolation, sqlState(exec(t, d.App, "UPDATE certificates SET compromised_by = $2 WHERE id = $1", w.cert, user)))
	require.NoError(t, exec(t, d.App, "UPDATE certificates SET revoked_at = now(), revocation_reason = 'keyCompromise', revoked_by = $2 WHERE id = $1",
		w.cert, user))
	assert.Equal(t, revocationFinal, sqlState(exec(t, d.App, "UPDATE certificates SET revocation_reason = 'superseded' WHERE id = $1", w.cert)))
	assert.Equal(t, revocationFinal, sqlState(exec(t, d.App, "UPDATE certificates SET revoked_at = NULL, revocation_reason = '', revoked_by = NULL WHERE id = $1", w.cert)))
	require.NoError(t, exec(t, d.App, "UPDATE certificates SET compromised_at = now(), compromised_by = $2 WHERE id = $1", w.cert, user))
	assert.Equal(t, revocationFinal, sqlState(exec(t, d.App, "UPDATE certificates SET compromised_at = NULL, compromised_by = NULL WHERE id = $1", w.cert)))
	require.NoError(t, exec(t, d.App, "UPDATE certificates SET label = 'still editable' WHERE id = $1", w.cert))

	// One open incident per certificate; a finished one is frozen with its locations.
	incident := func(id uuid.UUID, acme bool) error {
		if acme {
			return exec(t, d.App, `INSERT INTO certificate_incidents (id, certificate_id, public_key_sha256, acme_certificate_id, state, revocation,
started_by, created_at, updated_at) VALUES ($1, $2, $3, $4, 'ordering', 'pending', $5, now(), now())`, id, w.cert, hex64("b"), w.acmeCert, user)
		}
		return exec(t, d.App, `INSERT INTO certificate_incidents (id, certificate_id, public_key_sha256, state, revocation, created_at, updated_at)
VALUES ($1, $2, $3, 'awaiting_replacement', 'not_possible', now(), now())`, id, w.cert, hex64("b"))
	}
	first := uuid.New()
	require.NoError(t, incident(first, true))
	assert.Equal(t, uniqueViolation, sqlState(incident(uuid.New(), false)))
	assert.Equal(t, checkViolation, sqlState(exec(t, d.App, `INSERT INTO certificate_incidents (id, certificate_id, public_key_sha256, state, revocation,
created_at, updated_at) VALUES ($1, $2, $3, 'ordering', 'pending', now(), now())`, uuid.New(), w.cert, hex64("b"))), "pending revocation needs an ACME certificate")
	assert.Equal(t, checkViolation, sqlState(exec(t, d.App, "UPDATE certificate_incidents SET state = 'needs_attention' WHERE id = $1", first)))
	assert.Equal(t, checkViolation, sqlState(exec(t, d.App, "UPDATE certificate_incidents SET replacement_certificate_id = certificate_id WHERE id = $1", first)))
	require.NoError(t, exec(t, d.App, `INSERT INTO certificate_incident_locations (incident_id, location_id, status, updated_at)
VALUES ($1, $2, 'pending', now())`, first, w.loc))
	assert.Equal(t, checkViolation, sqlState(exec(t, d.App, "UPDATE certificate_incident_locations SET status = 'failed' WHERE incident_id = $1", first)))
	assert.Equal(t, checkViolation, sqlState(exec(t, d.App, "UPDATE certificate_incident_locations SET status = 'verified' WHERE incident_id = $1", first)))
	require.NoError(t, exec(t, d.App, "UPDATE certificate_incident_locations SET status = 'skipped', error_code = 'incident.other_certificate' WHERE incident_id = $1", first))
	require.NoError(t, exec(t, d.App, "UPDATE certificate_incidents SET state = 'closed', closed_by = $2, finished_at = now() WHERE id = $1", first, user))
	assert.Equal(t, incidentFrozen, sqlState(exec(t, d.App, "UPDATE certificate_incidents SET updated_at = now() WHERE id = $1", first)))
	assert.Equal(t, incidentFrozen, sqlState(exec(t, d.App, "UPDATE certificate_incident_locations SET attempts = 1 WHERE incident_id = $1", first)))
	require.NoError(t, incident(uuid.New(), false), "a closed incident does not block a new one")
	assert.Equal(t, insufficientPrivilege, sqlState(exec(t, d.App, "DELETE FROM certificate_incidents WHERE id = $1", first)))

	// Discovery certificates: a public key hash or ''.
	dw := seedDiscovery(t, d)
	require.NoError(t, exec(t, d.App, "UPDATE discovery_certificates SET public_key_sha256 = $2 WHERE fingerprint_sha256 = $1", dw.leaf, hex64("b")))
	assert.Equal(t, checkViolation, sqlState(exec(t, d.App, "UPDATE discovery_certificates SET public_key_sha256 = 'x' WHERE fingerprint_sha256 = $1", dw.leaf)))
	assert.Empty(t, grantProblems(t, d))

	// Down and up again.
	p, err := goose.NewProvider(goose.DialectPostgres, stdlib.OpenDBFromPool(d.Owner), migrations.FS)
	require.NoError(t, err)
	_, err = p.DownTo(ctx, 20)
	require.NoError(t, err)
	assert.False(t, tableExists(t, d, "certificate_incidents"))
	assert.False(t, hasColumn(t, d, "certificates", "revoked_at"))
	assert.Empty(t, grantProblems(t, d))
	_, err = p.Up(ctx)
	require.NoError(t, err)
	assert.True(t, tableExists(t, d, "certificate_incident_locations"))
}
