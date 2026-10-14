//go:build integration

package jobs

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/platform/db"
	"alice/internal/testutil/pgtest"
)

func TestMaxRunningFor(t *testing.T) {
	n, ok := MaxRunningFor(KVPoll)
	assert.True(t, ok)
	assert.Equal(t, inventory.MaxConcurrentKVPolls, n)
	n, ok = MaxRunningFor(NetdiscoScan)
	assert.True(t, ok)
	assert.Equal(t, MaxConcurrentNetdiscoScans, n, "at most two network discovery scans run at once")
	for _, typ := range []Type{KVTestConnection, KVImport, CertificateDeploy, CertificateDeployRecover, TargetDiscover, TargetTestConnection, SSHKeyRemove,
		LicenseEvaluate, NotifySend, NetdiscoSchedule, NetdiscoRetention, DiscoverySchedule} {
		_, ok := MaxRunningFor(typ)
		assert.False(t, ok, "%s has no cap: only the poll's behaviour changed", typ.Name)
	}
}

// capFull counts the running jobs of the type and says whether the cap is reached.
func TestCapFullCountsRunningJobsOfTheType(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	full := func(typ string, limit int) bool {
		var got bool
		require.NoError(t, db.InTx(ctx, d.App, func(tx pgx.Tx) error {
			var err error
			got, err = capFull(ctx, tx, typ, limit)
			return err
		}))
		return got
	}
	assert.False(t, full("kv.poll", 2))
	for range 2 {
		_, err := d.Owner.Exec(ctx, `INSERT INTO jobs (id, type, class, kind, payload_mac, status, run_at, max_attempts, attempts, created_at)
VALUES (gen_random_uuid(), 'kv.poll', 'read_only', 'scheduled', decode(repeat('00', 32), 'hex'), 'running', now(), 1, 1, now())`)
		require.NoError(t, err)
	}
	_, err := d.Owner.Exec(ctx, `INSERT INTO jobs (id, type, class, kind, payload_mac, status, run_at, max_attempts, created_at)
VALUES (gen_random_uuid(), 'kv.poll', 'read_only', 'scheduled', decode(repeat('00', 32), 'hex'), 'queued', now(), 1, now())`)
	require.NoError(t, err)
	assert.True(t, full("kv.poll", 2), "two are running; the queued one does not count")
	assert.False(t, full("kv.poll", 3))
	assert.False(t, full("kv.import", 2), "another type is counted on its own")
}
