//go:build integration

package migrations_test

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/testutil/pgtest"
	"alice/migrations"
)

// 00033 (R64 Ruling 12): the store notices the outbox still holds are recorded on the way up, so an update does not send
// them again; a notice of an incident that does not exist, or with a malformed thumbprint, is left out; Down drops the
// table. The application inserts and reads notices, never changes or deletes one.
func TestMigration00033BackfillsTheStoreNotices(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	p, err := goose.NewProvider(goose.DialectPostgres, stdlib.OpenDBFromPool(d.Owner), migrations.FS)
	require.NoError(t, err)
	_, err = p.DownTo(ctx, 32)
	require.NoError(t, err)

	_, cert, _ := seedCertWorld(t, d)
	incident := uuid.New()
	require.NoError(t, exec(t, d.Owner, `INSERT INTO certificate_incidents (id, certificate_id, public_key_sha256, state, revocation, created_at, updated_at)
VALUES ($1, $2, $3, 'deploying', 'not_possible', now(), now())`, incident, cert, hex64("b")))
	thumb := "0123456789abcdef0123456789abcdef01234567"
	outbox := func(incidentID, thumbprint string) {
		require.NoError(t, exec(t, d.Owner, `INSERT INTO notifications_outbox (id, kind, to_address, template_key, params, locale, status, next_attempt_at, created_at)
VALUES ($1, 'email', 'ada@example.com', 'windows.compromised_in_store', jsonb_build_object('incident_id', $2::text, 'thumbprint', $3::text), 'en',
'sent', now(), now())`, uuid.New(), incidentID, thumbprint))
	}
	outbox(incident.String(), thumb)
	outbox(incident.String(), strings.ToUpper(thumb)) //nolint:forbidigo // the same notice, its thumbprint in upper case (final review M5)
	outbox(uuid.New().String(), thumb)
	outbox(incident.String(), "not-a-thumbprint")

	_, err = p.UpTo(ctx, 33)
	require.NoError(t, err)
	var notices []string
	rows, err := d.Owner.Query(ctx, "SELECT incident_id::text || ' ' || notice FROM incident_notices ORDER BY 1")
	require.NoError(t, err)
	for rows.Next() {
		var n string
		require.NoError(t, rows.Scan(&n))
		notices = append(notices, n)
	}
	require.NoError(t, rows.Err())
	assert.Equal(t, []string{incident.String() + " windows.compromised_in_store:" + thumb}, notices)

	assert.Equal(t, uniqueViolation, sqlState(exec(t, d.App, "INSERT INTO incident_notices (incident_id, notice, created_at) VALUES ($1, $2, now())",
		incident, "windows.compromised_in_store:"+thumb)), "once per incident and notice")
	require.NoError(t, exec(t, d.App, "INSERT INTO incident_notices (incident_id, notice, created_at) VALUES ($1, $2, now()) ON CONFLICT DO NOTHING",
		incident, "windows.compromised_in_store:"+thumb))
	assert.Equal(t, checkViolation, sqlState(exec(t, d.App, "INSERT INTO incident_notices (incident_id, notice, created_at) VALUES ($1, 'x', now())", incident)))
	assert.Equal(t, privilegeDenied, sqlState(exec(t, d.App, "DELETE FROM incident_notices")))
	assert.Equal(t, privilegeDenied, sqlState(exec(t, d.App, "UPDATE incident_notices SET created_at = now()")))

	_, err = p.DownTo(ctx, 32)
	require.NoError(t, err)
	var exists bool
	require.NoError(t, d.Owner.QueryRow(ctx, "SELECT to_regclass('incident_notices') IS NOT NULL").Scan(&exists))
	assert.False(t, exists)
	_, err = p.Up(ctx)
	require.NoError(t, err)
}
