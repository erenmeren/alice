//go:build integration

package migrations_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/testutil/pgtest"
	"alice/migrations"
)

func putSettingSecret(t *testing.T, d *pgtest.DB, key string) error {
	t.Helper()
	return exec(t, d.App, `INSERT INTO setting_secrets (key, ciphertext, nonce, wrapped_dek, key_version, updated_at)
VALUES ($1, '\x01', decode(repeat('00', 12), 'hex'), '\x02', 1, now())`, key)
}

// R43 row 41: the installation's backup sender key is a setting secret (00012); the list stays closed.
func TestSettingSecretsHoldTheBackupSenderKey(t *testing.T) {
	d := pgtest.New(t)
	require.NoError(t, putSettingSecret(t, d, "backup.sender"))
	require.NoError(t, putSettingSecret(t, d, "notify.smtp.password"))
	for _, bad := range []string{"backup.key", "backup.senderx", "backup_sender", "BACKUP.SENDER", "backup.sender.x"} {
		assert.Equal(t, "23514", sqlState(putSettingSecret(t, d, bad)), bad)
	}
}

func TestMigration00012DownRefusesASenderKeyAndIsCleanWithout(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	p, err := goose.NewProvider(goose.DialectPostgres, stdlib.OpenDBFromPool(d.Owner), migrations.FS)
	require.NoError(t, err)
	require.NoError(t, putSettingSecret(t, d, "notify.smtp.password"))
	_, err = p.DownTo(ctx, 11)
	require.NoError(t, err, "no sender key: the Down runs")
	assert.Equal(t, "23514", sqlState(putSettingSecret(t, d, "backup.sender")), "the Phase 7 list again")
	assert.Empty(t, grantProblems(t, d))

	_, err = p.Up(ctx)
	require.NoError(t, err)
	require.NoError(t, putSettingSecret(t, d, "backup.sender"))
	_, err = p.DownTo(ctx, 11)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Z1016")
	version, err := p.GetDBVersion(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(12), version, "nothing changed")
}
