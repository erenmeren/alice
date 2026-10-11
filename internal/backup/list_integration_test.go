//go:build integration

package backup_test

import (
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/audit"
	"alice/internal/backup"
)

// countHashes counts the whole-file hashes of e.svc from now on.
func countHashes(e *env) *atomic.Int64 {
	var n atomic.Int64
	backup.SetHashed(e.svc, func(string) { n.Add(1) })
	return &n
}

func TestListHashesEachFileOnceUntilItChanges(t *testing.T) {
	e := newEnv(t, true)
	a := e.create(backup.KindManual)
	e.clk.Advance(time.Minute)
	b := e.create(backup.KindManual)
	hashes := countHashes(e)

	for range 3 {
		list, err := e.svc.List(e.ctx)
		require.NoError(t, err)
		require.Len(t, list, 2)
		assert.Equal(t, backup.CheckOK, list[0].Check)
		assert.Equal(t, backup.CheckOK, list[1].Check)
	}
	assert.EqualValues(t, 2, hashes.Load(), "the first List hashes each file, the next ones use the cache")
	_, err := e.svc.Prune(e.ctx, 1, audit.SystemActor("test"))
	require.NoError(t, err)
	assert.EqualValues(t, 2, hashes.Load(), "Prune uses the cache too")

	// A byte changed in place, same size, new mtime: hashed again and found damaged.
	raw, err := os.ReadFile(a.Path)
	require.NoError(t, err)
	raw[len(raw)-100] ^= 1
	require.NoError(t, os.WriteFile(a.Path, raw, 0o600))
	later := time.Now().Add(time.Hour)
	require.NoError(t, os.Chtimes(a.Path, later, later))
	list, err := e.svc.List(e.ctx)
	require.NoError(t, err)
	assert.EqualValues(t, 3, hashes.Load())
	assert.Equal(t, backup.CheckChecksumMismatch, find(t, list, a.Name).Check)

	// A changed checksum file alone also invalidates the cached result.
	sum, err := os.ReadFile(b.Path + ".sha256")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(b.Path+".sha256", []byte(strings.Repeat("0", 64)+"  "+b.Name+"\n"), 0o600))
	list, err = e.svc.List(e.ctx)
	require.NoError(t, err)
	assert.Equal(t, backup.CheckChecksumMismatch, find(t, list, b.Name).Check)
	require.NoError(t, os.WriteFile(b.Path+".sha256", sum, 0o600))
	list, err = e.svc.List(e.ctx)
	require.NoError(t, err)
	assert.Equal(t, backup.CheckOK, find(t, list, b.Name).Check)
	n := hashes.Load()

	// The explicit check and the download always hash.
	_, err = e.svc.Verify(e.ctx, b.Path)
	require.NoError(t, err)
	f, info, err := e.svc.Open(e.ctx, b.Name)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	assert.Equal(t, backup.CheckOK, info.Check)
	assert.Equal(t, n+2, hashes.Load())
}

func find(t *testing.T, list []backup.Info, name string) backup.Info {
	t.Helper()
	for _, i := range list {
		if i.Name == name {
			return i
		}
	}
	require.Failf(t, "not listed", "%s", name)
	return backup.Info{}
}

func TestListAndPruneCarryOnPastAnUnreadableFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a file of mode 000")
	}
	e := newEnv(t, true)
	var autos []backup.Info
	for range 4 {
		autos = append(autos, e.create(backup.KindAuto))
		e.clk.Advance(time.Hour)
	}
	newest := autos[3]
	require.NoError(t, os.Chmod(newest.Path, 0))
	t.Cleanup(func() { _ = os.Chmod(newest.Path, 0o600) })

	list, err := e.svc.List(e.ctx)
	require.NoError(t, err, "one unreadable file does not fail the list")
	require.Len(t, list, 4)
	bad := find(t, list, newest.Name)
	assert.Equal(t, backup.CheckUnreadable, bad.Check)
	assert.Equal(t, "permission_denied", bad.Code)
	assert.Equal(t, newest.Size, bad.Size)
	for _, a := range autos[:3] {
		got := find(t, list, a.Name)
		assert.Equal(t, backup.CheckOK, got.Check)
		assert.Empty(t, got.Code)
	}

	// The unreadable file is neither deleted nor counted among the 2 kept.
	n, err := e.svc.Prune(e.ctx, 2, audit.SystemActor("test"))
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	for i, a := range autos {
		_, err := os.Lstat(a.Path)
		if i == 0 {
			assert.ErrorIs(t, err, os.ErrNotExist)
		} else {
			assert.NoError(t, err, a.Name)
		}
	}
}

func TestScheduledRunSweepsOldPartialFiles(t *testing.T) {
	e := newEnv(t, true)
	now := e.clk.Now()
	write := func(name string, age time.Duration) string {
		p := filepath.Join(e.dir, name)
		require.NoError(t, os.WriteFile(p, []byte("x"), 0o600))
		require.NoError(t, os.Chtimes(p, now.Add(-age), now.Add(-age)))
		return p
	}
	oldBak := write(".alice-backup-ABCD1234-20260901T023000Z-auto.alicebak.partial", 25*time.Hour)
	oldSum := write(".mine.alicebak.sha256.partial", 48*time.Hour)
	fresh := write(".alice-backup-ABCD1234-20260930T023000Z-auto.alicebak.partial", time.Hour)
	other := write(".notes.partial", 72*time.Hour)

	require.NoError(t, e.svc.RunScheduled(e.ctx))
	for _, p := range []string{oldBak, oldSum} {
		_, err := os.Lstat(p)
		assert.ErrorIs(t, err, os.ErrNotExist, filepath.Base(p))
	}
	for _, p := range []string{fresh, other} {
		_, err := os.Lstat(p)
		assert.NoError(t, err, filepath.Base(p))
	}
	list, err := e.svc.List(e.ctx)
	require.NoError(t, err)
	assert.Len(t, list, 1, "the scheduled backup was made")
}

func TestPruneKeepsTheNewBackupWhenTheClockWentBack(t *testing.T) {
	e := newEnv(t, true)
	_, err := e.svc.SaveSchedule(e.ctx, audit.SystemActor("test"), 0, backup.Schedule{Time: "02:30", Zone: "UTC", Retention: backup.MinRetention})
	require.NoError(t, err)
	// backup.MinRetention automatic backups stamped a day ahead, then the clock is corrected backwards.
	e.clk.Advance(24 * time.Hour)
	var future []backup.Info
	for range backup.MinRetention {
		future = append(future, e.create(backup.KindAuto))
		e.clk.Advance(time.Minute)
	}
	e.clk.Set(e.clk.Now().Add(-48 * time.Hour))
	made := e.create(backup.KindAuto)

	_, err = os.Lstat(made.Path)
	require.NoError(t, err, "the backup just made is never pruned")
	_, err = os.Lstat(future[len(future)-1].Path)
	require.NoError(t, err, "nor the newest verified one")
	_, err = os.Lstat(future[0].Path)
	require.ErrorIs(t, err, os.ErrNotExist, "the oldest goes")
	list, err := e.svc.List(e.ctx)
	require.NoError(t, err)
	assert.Len(t, list, backup.MinRetention)
}

func TestAlarmIsRaisedOnTheTickWhenNoAttemptIsRecorded(t *testing.T) {
	e := newEnv(t, true)
	e.completeSetup()
	start := e.clk.Now()
	// A hung backup holds the lock: every scheduled run finds it running and records nothing.
	conn, err := e.db.App.Acquire(e.ctx)
	require.NoError(t, err)
	defer conn.Release()
	_, err = conn.Exec(e.ctx, "SELECT pg_advisory_lock(hashtext('alice.backup'))")
	require.NoError(t, err)
	for e.clk.Now().Before(start.Add(backup.AlarmAfter + time.Hour)) {
		require.NoError(t, e.svc.RunScheduled(e.ctx))
		if e.clk.Now().Before(start.Add(backup.AlarmAfter)) {
			assert.Zero(t, e.outbox("backup.alarm_never"))
		}
		e.clk.Advance(30 * time.Minute)
	}
	_, err = conn.Exec(e.ctx, "SELECT pg_advisory_unlock(hashtext('alice.backup'))")
	require.NoError(t, err)
	assert.Empty(t, e.auditRows("backup.failed"))
	assert.Zero(t, e.outbox("backup.failed"))
	assert.Zero(t, e.outbox("backup.alarm"))
	assert.Equal(t, 1, e.outbox("backup.alarm_never"), "once, from the tick")
	var params map[string]string
	require.NoError(t, e.db.Owner.QueryRow(e.ctx, "SELECT params FROM notifications_outbox WHERE template_key = 'backup.alarm_never'").Scan(&params))
	assert.Equal(t, map[string]string{"dashboard_url": "/"}, params)
	assert.True(t, e.state().AlarmNotified)
}
