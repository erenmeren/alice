//go:build integration

package secrets_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/secrets"
	"alice/internal/testutil/pgtest"
)

func TestSettingSecretsRoundTripBoundToTheirKey(t *testing.T) {
	d := pgtest.New(t)
	ctx := context.Background()
	k, err := secrets.NewKeyring(1, bytes.Repeat([]byte{7}, 32))
	require.NoError(t, err)
	now := time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)
	require.NoError(t, k.PutSetting(ctx, d.App, "notify.smtp.password", secrets.NewPlaintext([]byte("CANARY-smtp-1")), now))
	got, ok, err := k.GetSetting(ctx, d.App, "notify.smtp.password")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "CANARY-smtp-1", string(got.Bytes()))
	got.Zero()

	var raw []byte
	require.NoError(t, d.Owner.QueryRow(ctx, "SELECT ciphertext FROM setting_secrets WHERE key = 'notify.smtp.password'").Scan(&raw))
	assert.NotContains(t, string(raw), "CANARY", "S-04: only ciphertext is stored")

	// Copied under another key, the envelope does not open (AAD setting_secrets/<key>/ciphertext).
	other := "sso.provider.0192e000-0000-7000-8000-000000000001.client_secret"
	_, err = d.Owner.Exec(ctx, `INSERT INTO setting_secrets (key, ciphertext, nonce, wrapped_dek, key_version, updated_at)
SELECT $1, ciphertext, nonce, wrapped_dek, key_version, updated_at FROM setting_secrets WHERE key = 'notify.smtp.password'`, other)
	require.NoError(t, err)
	_, _, err = k.GetSetting(ctx, d.App, other)
	assert.ErrorIs(t, err, secrets.ErrDecrypt)

	require.NoError(t, k.PutSetting(ctx, d.App, "notify.smtp.password", secrets.NewPlaintext([]byte("CANARY-smtp-2")), now))
	got, _, err = k.GetSetting(ctx, d.App, "notify.smtp.password")
	require.NoError(t, err)
	assert.Equal(t, "CANARY-smtp-2", string(got.Bytes()), "a put replaces")
	require.NoError(t, secrets.DeleteSetting(ctx, d.App, "notify.smtp.password"))
	_, ok, err = k.GetSetting(ctx, d.App, "notify.smtp.password")
	require.NoError(t, err)
	assert.False(t, ok)
}
