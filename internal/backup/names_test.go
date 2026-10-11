package backup_test

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/backup"
)

func TestNameFromParts(t *testing.T) {
	at := time.Date(2026, 10, 1, 2, 30, 0, 0, time.UTC)
	for kind, want := range map[backup.Kind]string{
		"auto":              "alice-backup-7F3K92QD-20261001T023000Z-auto.alicebak",
		"manual":            "alice-backup-7F3K92QD-20261001T023000Z-manual.alicebak",
		"pre-upgrade-1.0.0": "alice-backup-7F3K92QD-20261001T023000Z-pre-upgrade-1.0.0.alicebak",
		"pre-restore":       "alice-backup-7F3K92QD-20261001T023000Z-pre-restore.alicebak",
	} {
		got, err := backup.FileName("ALICE-7F3K-92QD-M4XT-A81P", at, kind)
		require.NoError(t, err)
		assert.Equal(t, want, got)
		assert.True(t, backup.ValidName(got))
	}
	local := time.Date(2026, 10, 1, 5, 30, 0, 0, time.FixedZone("TRT", 3*3600))
	got, err := backup.FileName("ALICE-7F3K-92QD-M4XT-A81P", local, "auto")
	require.NoError(t, err)
	assert.Equal(t, "alice-backup-7F3K92QD-20261001T023000Z-auto.alicebak", got, "the time is UTC")

	for _, id := range []string{"", "ALICE-7F3K", "7F3K-92QD-M4XT-A81P", "ALICE-7f3k-92qd-m4xt-a81p"} {
		_, err := backup.FileName(id, at, "auto")
		assert.Error(t, err, id)
	}
	for _, kind := range []backup.Kind{"", "weekly", "pre-upgrade-", "pre-upgrade-1.0", "auto/../x"} {
		_, err := backup.FileName("ALICE-7F3K-92QD-M4XT-A81P", at, kind)
		assert.Error(t, err, kind)
	}
}

func TestNameRules(t *testing.T) {
	for _, ok := range []string{
		"alice-backup-7F3K92QD-20261001T023000Z-auto.alicebak",
		"alice-backup-7F3K92QD-20261001T023000Z-pre-upgrade-1.0.0-rc.1.alicebak",
		"before-firewall-change.alicebak",
		strings.Repeat("a", 255-len(".alicebak")) + ".alicebak",
	} {
		assert.True(t, backup.ValidName(ok), ok)
	}
	for _, bad := range []string{
		"../x.alicebak", "a/b.alicebak", ".hidden.alicebak", "x.alicebak\x00", "x.tar", "x.alicebak.sha256",
		".alicebak", "a\\b.alicebak", "", strings.Repeat("a", 256-len(".alicebak")) + ".alicebak", "x\n.alicebak",
		".alice-backup-7F3K92QD-20261001T023000Z-auto.alicebak.partial", "x.ALICEBAK", "\xff.alicebak",
	} {
		assert.False(t, backup.ValidName(bad), "%q", bad)
	}
}
