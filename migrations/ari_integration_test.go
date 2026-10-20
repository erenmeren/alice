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

// 00024 completes ARI (R50): the application writes the chosen renewal time of an ACME certificate and, while an order
// runs, its replaces identifier, outcome and account; the identifier has the RFC 9773 form and comes with an outcome; a
// finished order stays frozen (00013); the Down removes the columns.
func TestMigration00024ARI(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	w := seedAcme(t, d)
	require.NoError(t, exec(t, d.App, "UPDATE acme_certificates SET ari_renew_at = now() + interval '3 days' WHERE id = $1", w.acmeCert))

	running := uuid.New()
	require.NoError(t, exec(t, d.App, `INSERT INTO acme_orders (id, acme_certificate_id, kind, state, started_at) VALUES ($1, $2, 'issue', 'running', now())`,
		running, w.acmeCert))
	require.NoError(t, exec(t, d.App, `UPDATE acme_orders SET replaces = 'aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE', replaces_outcome = 'sent',
    account_url = 'https://ca.corp.example/acct/1' WHERE id = $1`, running))
	for _, bad := range []string{
		"UPDATE acme_orders SET replaces = 'no dot', replaces_outcome = 'sent' WHERE id = $1",
		"UPDATE acme_orders SET replaces = 'a.b.c', replaces_outcome = 'sent' WHERE id = $1",
		"UPDATE acme_orders SET replaces = 'a.b', replaces_outcome = 'lost' WHERE id = $1",
		"UPDATE acme_orders SET replaces = 'a.b', replaces_outcome = '' WHERE id = $1",
		"UPDATE acme_orders SET replaces = '', replaces_outcome = 'sent' WHERE id = $1",
	} {
		assert.Equal(t, checkViolation, sqlState(exec(t, d.App, bad, running)), bad)
	}
	assert.Equal(t, "Z1017", sqlState(exec(t, d.App, "UPDATE acme_orders SET replaces = 'a.b', replaces_outcome = 'sent' WHERE id = $1", w.order)),
		"a finished order is frozen")

	p, err := goose.NewProvider(goose.DialectPostgres, stdlib.OpenDBFromPool(d.Owner), migrations.FS)
	require.NoError(t, err)
	_, err = p.DownTo(ctx, 22)
	require.NoError(t, err)
	assert.False(t, hasColumn(t, d, "acme_certificates", "ari_renew_at"))
	assert.False(t, hasColumn(t, d, "acme_orders", "replaces"))
	assert.Empty(t, grantProblems(t, d))
	_, err = p.Up(ctx)
	require.NoError(t, err)
	assert.Empty(t, grantProblems(t, d))
}
