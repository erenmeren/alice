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

// winrmDownRefused is the SQLSTATE of 00038's Down while a WinRM password exists.
const winrmDownRefused = "Z1036"

// seedWinRMWorld is a Windows server whose transport is WinRM (the platform key stays its credential_id, R71 Ruling 5).
func seedWinRMWorld(t *testing.T, d *pgtest.DB) uuid.UUID {
	t.Helper()
	w, win := seedWorld(t, d), uuid.New()
	require.NoError(t, exec(t, d.Owner, `INSERT INTO targets (id, name, type, config, credential_id, status, created_at, updated_at)
VALUES ($1, 'iis-01', 'windows', '{"host":"10.0.0.7","port":5986,"transport":"winrm"}', $2, 'ok', now(), now())`, win, platformCredential(t, d, w)))
	return win
}

// 00038 (R71, W7 Ruling 5): the WinRM password of a Windows server (purpose win_winrm, kind winrm_password, bound to its
// target).
func TestMigration00038WindowsWinRM(t *testing.T) {
	d := pgtest.New(t)
	win := seedWinRMWorld(t, d)
	require.NoError(t, ccsCredential(t, d, "win_winrm", "winrm_password", win))
	require.NoError(t, ccsCredential(t, d, "win_winrm", "winrm_password", win), "rows are append-only: a replacement is a new row")
	assert.Equal(t, checkViolation, sqlState(ccsCredential(t, d, "win_winrm", "winrm_password", nil)), "the password belongs to its server")
	assert.Equal(t, checkViolation, sqlState(ccsCredential(t, d, "win_ccs", "winrm_password", win)), "the kind goes with its purpose")
	assert.Equal(t, checkViolation, sqlState(ccsCredential(t, d, "f5_device", "winrm_password", win)), "the kind goes with its purpose")
	assert.Equal(t, checkViolation, sqlState(ccsCredential(t, d, "win_winrm", "win_ccs_password", win)), "the purpose takes its kind only")
	assert.Equal(t, checkViolation, sqlState(ccsCredential(t, d, "win_winrms", "winrm_password", win)), "the purpose list stays closed")
	require.NoError(t, ccsCredential(t, d, "win_ccs", "win_ccs_password", win), "00036's CCS password is unchanged")
}

// 00038's Down refuses while a win_winrm credential exists, and otherwise restores the lists of 00037 (00036's).
func TestMigration00038Down(t *testing.T) {
	ctx := context.Background()
	d := pgtest.New(t)
	p, err := goose.NewProvider(goose.DialectPostgres, stdlib.OpenDBFromPool(d.Owner), migrations.FS)
	require.NoError(t, err)
	win := seedWinRMWorld(t, d)
	require.NoError(t, ccsCredential(t, d, "win_winrm", "winrm_password", win))

	_, err = p.DownTo(ctx, 37)
	assert.Equal(t, winrmDownRefused, sqlState(err), "a WinRM password exists: %v", err)
	require.NoError(t, exec(t, d.Owner, "DELETE FROM credentials WHERE purpose = 'win_winrm'"))
	_, err = p.DownTo(ctx, 37)
	require.NoError(t, err)
	assert.Equal(t, checkViolation, sqlState(ccsCredential(t, d, "win_winrm", "winrm_password", win)), "00037's purposes are back")
	require.NoError(t, ccsCredential(t, d, "win_ccs", "win_ccs_password", win), "00036's CCS password is kept")
	assert.Empty(t, grantProblems(t, d))

	_, err = p.Up(ctx)
	require.NoError(t, err)
	require.NoError(t, ccsCredential(t, d, "win_winrm", "winrm_password", win))
}
