package secrets

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"alice/internal/platform/db"
)

// The secrets of settings (the SMTP password, OIDC client secrets) live in setting_secrets, one envelope per key,
// bound to the key by the AAD setting_secrets/<key>/ciphertext (spec §7.6; R42 rows 9 and 19).
func settingLocation(key string) Location {
	return Location{Table: "setting_secrets", RowID: key, Column: "ciphertext"}
}

// PutSetting seals p under key, replacing any earlier value. The caller zeroes p.
func (k *Keyring) PutSetting(ctx context.Context, q db.Querier, key string, p Plaintext, now time.Time) error {
	env, err := k.Seal(settingLocation(key), p.Bytes())
	if err != nil {
		return err
	}
	_, err = q.Exec(ctx, `INSERT INTO setting_secrets (key, ciphertext, nonce, wrapped_dek, key_version, updated_at)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (key) DO UPDATE SET ciphertext = EXCLUDED.ciphertext, nonce = EXCLUDED.nonce, wrapped_dek = EXCLUDED.wrapped_dek,
key_version = EXCLUDED.key_version, updated_at = EXCLUDED.updated_at`,
		key, env.Ciphertext, env.Nonce, env.WrappedDEK, env.KeyVersion, now.UTC())
	if err != nil {
		return fmt.Errorf("secrets: store setting secret: %w", err)
	}
	return nil
}

// GetSetting opens the secret of key; ok is false when there is none. The caller zeroes the plaintext.
func (k *Keyring) GetSetting(ctx context.Context, q db.Querier, key string) (Plaintext, bool, error) {
	var env Envelope
	err := q.QueryRow(ctx, `SELECT ciphertext, nonce, wrapped_dek, key_version FROM setting_secrets WHERE key = $1`, key).
		Scan(&env.Ciphertext, &env.Nonce, &env.WrappedDEK, &env.KeyVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return Plaintext{}, false, nil
	}
	if err != nil {
		return Plaintext{}, false, fmt.Errorf("secrets: read setting secret: %w", err)
	}
	p, err := k.Open(settingLocation(key), env)
	if err != nil {
		return Plaintext{}, false, err
	}
	return p, true, nil
}

// DeleteSetting removes the secret of key; a missing key is not an error.
func DeleteSetting(ctx context.Context, q db.Querier, key string) error {
	if _, err := q.Exec(ctx, `DELETE FROM setting_secrets WHERE key = $1`, key); err != nil {
		return fmt.Errorf("secrets: delete setting secret: %w", err)
	}
	return nil
}
