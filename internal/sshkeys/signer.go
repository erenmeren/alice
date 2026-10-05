package sshkeys

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/ssh"

	"alice/internal/inventory"
	"alice/internal/platform/db"
	"alice/internal/providers"
	"alice/internal/secrets"
	"alice/internal/sshkeys/keymat"
)

// keyRow is what the deploy, the signer and the download read of a key before they act on it.
type keyRow struct {
	id, privateKeyID   uuid.UUID // privateKeyID uuid.Nil: Alice holds no private key
	fingerprint        string
	publicKey          string
	label, comment     string
	isPlatform         bool
	retired, destroyed bool
	algorithm          string
	bits               int
}

// readKeyRow reads one ssh_keys row with its private key's state; ErrNotFound.
func readKeyRow(ctx context.Context, q db.Querier, id uuid.UUID) (keyRow, error) {
	var (
		r    keyRow
		pkID *uuid.UUID
	)
	err := q.QueryRow(ctx, `SELECT k.id, k.private_key_id, k.fingerprint_sha256, k.public_key, k.label, k.key_comment, k.is_platform_key,
    k.retired_at IS NOT NULL, coalesce(p.destroyed_at IS NOT NULL, false), coalesce(p.algorithm, ''), coalesce(p.bits, 0)
FROM ssh_keys k LEFT JOIN managed_private_keys p ON p.id = k.private_key_id WHERE k.id = $1`, id).Scan(&r.id, &pkID, &r.fingerprint,
		&r.publicKey, &r.label, &r.comment, &r.isPlatform, &r.retired, &r.destroyed, &r.algorithm, &r.bits)
	if errors.Is(err, pgx.ErrNoRows) {
		return keyRow{}, ErrNotFound
	}
	if err != nil {
		return keyRow{}, fmt.Errorf("sshkeys: read the key: %w", err)
	}
	if pkID != nil {
		r.privateKeyID = *pkID
	}
	return r, nil
}

// openKey opens a stored private key: the only place this module unseals one. The caller zeroes
// the result as soon as it has used it. A destroyed key is ErrDestroyed; an envelope this master
// key does not open is errUndecryptable. It never logs; its errors carry no key material.
func (s *Service) openKey(ctx context.Context, q db.Querier, privateKeyID uuid.UUID) (secrets.Plaintext, error) {
	var (
		env       secrets.Envelope
		version   *int
		destroyed bool
	)
	err := q.QueryRow(ctx, `SELECT ciphertext, nonce, wrapped_dek, key_version, destroyed_at IS NOT NULL FROM managed_private_keys
WHERE id = $1 AND owner_type = 'ssh_key'`, privateKeyID).Scan(&env.Ciphertext, &env.Nonce, &env.WrappedDEK, &version, &destroyed)
	if errors.Is(err, pgx.ErrNoRows) {
		return secrets.Plaintext{}, ErrNotManaged
	}
	if err != nil {
		return secrets.Plaintext{}, fmt.Errorf("sshkeys: read the private key: %w", err)
	}
	if destroyed || version == nil {
		return secrets.Plaintext{}, ErrDestroyed
	}
	env.KeyVersion = *version
	pt, err := s.keyring.Open(keyLocation(privateKeyID), env)
	if err != nil {
		return secrets.Plaintext{}, errUndecryptable
	}
	hold(holdOpened, pt.Bytes())
	return pt, nil
}

// keySigner is the credential source of a test login with a generated key.
type keySigner struct {
	s     *Service
	keyID uuid.UUID
}

// KeySigner returns the credential source of a test login with the key (spec §13.4): each
// SSHSigner call opens the key's envelope, builds a signer and zeroes the opened PKCS #8 at once;
// release clears the signer's own copy. A destroyed key is ErrDestroyed, a key Alice did not
// generate ErrNotManaged.
func (s *Service) KeySigner(keyID uuid.UUID) providers.CredentialSource {
	return keySigner{s: s, keyID: keyID}
}

// SSHSigner implements providers.CredentialSource.
func (c keySigner) SSHSigner(ctx context.Context) (ssh.Signer, func(), error) {
	row, err := readKeyRow(ctx, c.s.pool, c.keyID)
	if err != nil {
		return nil, nil, err
	}
	if row.privateKeyID == uuid.Nil || row.isPlatform {
		return nil, nil, ErrNotManaged
	}
	pt, err := c.s.openKey(ctx, c.s.pool, row.privateKeyID)
	if err != nil {
		return nil, nil, err
	}
	// The signer keeps its own parsed key, which release clears; the PKCS #8 is not needed past
	// this function.
	defer pt.Zero()
	signer, release, err := keymat.Signer(pt)
	if err != nil {
		return nil, nil, err
	}
	return signer, release, nil
}

// ProtectedFingerprints returns the fingerprints of Alice's own keys (inventory's rule, F-36):
// no deploy, removal or rotation ever touches a line of one of them.
func (s *Service) ProtectedFingerprints(ctx context.Context) ([]string, error) {
	var out []string
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		out, err = inventory.ProtectedFingerprintsTx(ctx, tx)
		return err
	})
	return out, err
}
