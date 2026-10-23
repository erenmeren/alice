//go:build integration

package migrations_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/testutil/pgtest"
)

// 00032 (R62 Ruling 13): the cleanup switch is a column that every existing target has on, that the application may change,
// and that is the only target setting it may change besides the ones it already could (the connection stays read-only).
func TestMigration00032CertificateCleanupSwitch(t *testing.T) {
	d := pgtest.New(t)
	w := seedWorld(t, d)
	var on bool
	require.NoError(t, d.App.QueryRow(context.Background(), "SELECT certificate_cleanup FROM targets WHERE id = $1", w.target).Scan(&on))
	assert.True(t, on, "a target inserted before the column existed (or without it) has the switch on")

	require.NoError(t, exec(t, d.App, "UPDATE targets SET certificate_cleanup = false WHERE id = $1", w.target))
	require.NoError(t, d.App.QueryRow(context.Background(), "SELECT certificate_cleanup FROM targets WHERE id = $1", w.target).Scan(&on))
	assert.False(t, on)
	assert.Equal(t, privilegeDenied, sqlState(exec(t, d.App, `UPDATE targets SET config = config || '{"x":1}' WHERE id = $1`, w.target)),
		"the connection settings are still never written by the application")
	assert.NotEmpty(t, sqlState(exec(t, d.App, "UPDATE targets SET certificate_cleanup = NULL WHERE id = $1", w.target)), "never null")
}
