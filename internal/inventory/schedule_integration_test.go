//go:build integration

package inventory_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/rbac"
)

func TestScheduleDiscoveryEnqueuesDueTargetsOnly(t *testing.T) {
	h := newHarness(t)
	admin := h.user("ada", rbac.Admin, "")
	due := okTarget(t, h, admin, "web-01")
	h.add(admin, "pending", "pending.example.com") // never confirmed: not scheduled
	gone := okTarget(t, h, admin, "gone")
	require.NoError(t, h.svc.DeleteTarget(h.ctx, admin, gone.ID))
	recent := okTarget(t, h, admin, "recent")
	_, err := h.db.Owner.Exec(h.ctx, "UPDATE targets SET last_discovery_at = $2 WHERE id = $1", recent.ID, h.clock.Now())
	require.NoError(t, err)

	before := len(h.jobs.requests())
	n, err := h.svc.ScheduleDiscovery(h.ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	req := h.jobs.requests()[before]
	slot := h.clock.Now().Unix() / int64((24 * time.Hour).Seconds())
	assert.Equal(t, inventory.JobRequest{Type: inventory.JobDiscover, TargetID: due.ID, Payload: map[string]string{},
		Kind: "scheduled", DedupeKey: fmt.Sprintf("target.discover:%s:%d", due.ID, slot)}, req)
	assert.Equal(t, 1, h.count("SELECT count(*) FROM targets WHERE last_scheduled_at = $1", h.clock.Now()))

	// Whatever became of that job, the target is not queued again within its interval (R37 #13).
	h.clock.Advance(time.Minute)
	n, err = h.svc.ScheduleDiscovery(h.ctx)
	require.NoError(t, err)
	assert.Zero(t, n)

	h.clock.Advance(24 * time.Hour)
	n, err = h.svc.ScheduleDiscovery(h.ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, n, "both connected targets are due a day later")
}
