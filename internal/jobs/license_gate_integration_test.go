//go:build integration

package jobs

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/license"
	"alice/internal/license/licensetest"
)

// AUD-02 with the real license service: while no evaluation can succeed (a session holds the
// license row) the gate answers "unverified" after 3 hours; a deployment recovery (always class)
// is still claimed and run at once, while a queued change waits queued, neither held nor audited,
// and runs by itself after the next successful evaluation.
func TestRecoveryRunsWhileTheLicenseIsUnverified(t *testing.T) {
	e := newQEnv(t)
	// serve starts the license before any user exists, and a user row shows an earlier
	// installation (AUD-18): the harness's administrator is added after the first start.
	_, err := e.d.Owner.Exec(e.ctx, "DELETE FROM users")
	require.NoError(t, err)
	lic := license.New(license.Config{Pool: e.d.App, Keyring: testKeyring(t), Audit: e.audit, Clock: e.fake, Uptime: e.fake,
		Keys: licensetest.KeySet(), StateDir: t.TempDir(), RowLockTimeout: 200 * time.Millisecond, Log: quiet})
	require.NoError(t, lic.Start(e.ctx))
	t.Cleanup(lic.Close)
	_, err = e.d.Owner.Exec(e.ctx, `INSERT INTO users (id, username, display_name, password_hash, role, created_at, updated_at)
VALUES ($1, 'admin', 'Admin', 'x', 'admin', $2, $2)`, admin.ID, queueStart)
	require.NoError(t, err)

	tx, err := e.d.App.Begin(e.ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(context.Background()) }()
	_, err = tx.Exec(e.ctx, "SELECT 1 FROM license WHERE id = 1 FOR UPDATE")
	require.NoError(t, err)
	e.fake.Advance(license.MaxEvaluationAge + time.Minute)
	require.Error(t, lic.Tick(e.ctx))
	require.ErrorIs(t, lic.Allow(license.ClassChange), license.ErrUnverified)

	recovery := e.enqueue(t, Spec{Type: CertificateDeployRecover, TargetID: insertTarget(t, e.d)})
	change := e.enqueue(t, Spec{Type: SSHKeyRemove, Kind: KindUser, TargetID: insertTarget(t, e.d)})
	var recovered, changed atomic.Int32
	r := e.runner(t, "w1", func(c *RunnerConfig) { c.Gate = lic })
	r.Handle(CertificateDeployRecover, func(context.Context, Job, StepRecorder) (map[string]any, error) { recovered.Add(1); return nil, nil })
	r.Handle(SSHKeyRemove, func(context.Context, Job, StepRecorder) (map[string]any, error) { changed.Add(1); return nil, nil })
	drain := func() {
		for {
			ran, err := r.RunOnce(e.ctx)
			require.NoError(t, err)
			if !ran {
				return
			}
		}
	}
	drain()
	assert.Equal(t, int32(1), recovered.Load(), "recovery is never paused by the license")
	assert.Equal(t, "succeeded", e.row(t, recovery).status)
	assert.Zero(t, changed.Load())
	assert.Equal(t, "queued", e.row(t, change).status)
	assert.Zero(t, e.audits(t, "job.blocked_license"))
	assert.Zero(t, e.audits(t, "job.cancelled_license"))

	require.NoError(t, tx.Rollback(e.ctx))
	require.NoError(t, lic.Tick(e.ctx))
	drain()
	assert.Equal(t, int32(1), changed.Load(), "the change resumes by itself")
	assert.Equal(t, "succeeded", e.row(t, change).status)
}
