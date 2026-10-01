//go:build integration

package jobs

import (
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/platform/db"
)

// A request that hits a live job's dedupe key with other options (a removal now confirmed for
// root's last key) is refused instead of silently answering with the old job.
func TestEnqueueTxRefusesADedupeHitWithOtherOptions(t *testing.T) {
	e := newQEnv(t)
	enqueue := func(payload map[string]string) (id [16]byte, err error) {
		err = db.InTx(e.ctx, e.d.App, func(tx pgx.Tx) error {
			var err error
			id, err = e.q.EnqueueTx(e.ctx, tx, inventory.JobRequest{Type: testQueueJob.Name, Payload: payload, Kind: "system",
				DedupeKey: "sshkey.remove:loc-1"})
			return err
		})
		return id, err
	}
	first, err := enqueue(map[string]string{"location_id": "loc-1", "confirm_last_root_key": "false"})
	require.NoError(t, err)
	same, err := enqueue(map[string]string{"confirm_last_root_key": "false", "location_id": "loc-1"})
	require.NoError(t, err)
	assert.Equal(t, first, same, "the same request answers the live job")
	_, err = enqueue(map[string]string{"location_id": "loc-1", "confirm_last_root_key": "true"})
	require.ErrorIs(t, err, inventory.ErrJobConflict)
	assert.Equal(t, 1, e.count(t, "SELECT count(*) FROM jobs"))
}
