//go:build integration

package auth_test

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/rbac"
)

func TestPruneExpiredRemovesDeadSessionsOnly(t *testing.T) {
	e := newEnv(t)
	user := e.insertUser(t, "prune-me", rbac.Operator, "a long enough password")
	now := e.clk.Now()
	session := func(expires, idle time.Time, revoked *time.Time) []byte {
		id := make([]byte, 32)
		_, _ = rand.Read(id)
		_, err := e.db.Owner.Exec(e.ctx, `INSERT INTO sessions (id_hash, user_id, kind, created_at, last_seen_at, expires_at,
    idle_expires_at, revoked_at) VALUES ($1, $2, 'full', $3, $3, $4, $5, $6)`, id, user, now.Add(-time.Hour), expires, idle, revoked)
		require.NoError(t, err)
		return id
	}
	recentRevoke, oldRevoke := now.Add(-time.Hour), now.Add(-25*time.Hour)
	live := session(now.Add(time.Hour), now.Add(10*time.Minute), nil)
	session(now.Add(-time.Second), now.Add(10*time.Minute), nil) // absolute lifetime over
	session(now.Add(time.Hour), now.Add(-time.Second), nil)      // idle too long
	session(now.Add(time.Hour), now.Add(10*time.Minute), &oldRevoke)
	revokedRecently := session(now.Add(time.Hour), now.Add(10*time.Minute), &recentRevoke)
	for _, idle := range []time.Time{now.Add(-time.Minute), now.Add(time.Minute)} {
		id := make([]byte, 32)
		_, _ = rand.Read(id)
		_, err := e.db.Owner.Exec(e.ctx, `INSERT INTO setup_sessions (id_hash, created_at, idle_expires_at) VALUES ($1, $2, $3)`,
			id, now.Add(-time.Hour), idle)
		require.NoError(t, err)
	}

	n, err := e.svc.PruneExpired(e.ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(4), n, "three dead sessions and one expired setup session")
	var kept [][]byte
	rows, err := e.db.Owner.Query(e.ctx, `SELECT id_hash FROM sessions ORDER BY id_hash`)
	require.NoError(t, err)
	for rows.Next() {
		var id []byte
		require.NoError(t, rows.Scan(&id))
		kept = append(kept, id)
	}
	rows.Close()
	assert.ElementsMatch(t, [][]byte{live, revokedRecently}, kept)
	var setups int
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, `SELECT count(*) FROM setup_sessions`).Scan(&setups))
	assert.Equal(t, 1, setups)

	n, err = e.svc.PruneExpired(e.ctx)
	require.NoError(t, err)
	assert.Zero(t, n)
}
