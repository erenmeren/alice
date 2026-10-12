//go:build integration

package sshkeys_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/sshkeys"
)

// A failed query of the needs_attention mail's parameters is an error of the transition (review-fixes L-13): the
// transaction is aborted by then, and going on would fail later with a confusing "current transaction is aborted".
func TestAttentionParamsReturnsItsQueryError(t *testing.T) {
	e := newEnv(t)
	tx, err := e.db.App.Begin(e.ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(e.ctx) }()
	p, err := sshkeys.AttentionParams(e.ctx, e.svc, tx, uuid.New())
	require.NoError(t, err)
	assert.Equal(t, "0", p["undo_failed_count"])
	assert.Equal(t, "—", p["remove_failed_servers"])

	_, err = tx.Exec(e.ctx, "SELECT 1/0") // aborts the transaction: the next statement fails
	require.Error(t, err)
	_, err = sshkeys.AttentionParams(e.ctx, e.svc, tx, uuid.New())
	require.Error(t, err)
}
