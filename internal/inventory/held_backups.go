package inventory

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/platform/db"
	"alice/internal/providers"
	"alice/internal/secrets"
)

// Alice-held backups (R59 G5, migration 00031): a provider whose target keeps nothing of what it replaces (a Kubernetes
// Secret) hands the previous certificate chain and key to the engine before it changes the location; they are sealed
// like every key Alice holds (the Phase 3 envelope, AAD deployment_backups/<deployment id>/ciphertext) and read back for
// a rollback. The retention deletes a backup once its deployment has been final for HeldBackupRetention; the database
// refuses deleting the backup of an unfinished deployment (Z1032).

// HeldBackupRetention is how long a backup stays after its deployment is final (the design's 7 days, Q5 of the
// Kubernetes design): a rollback of a final deployment never happens, so this is only a margin for an Administrator.
const HeldBackupRetention = 7 * 24 * time.Hour

// maxHeldBackupBytes bounds the sealed payload (the column's CHECK is 256 KiB of ciphertext; GCM adds 16 bytes).
const maxHeldBackupBytes = 256<<10 - 64

var (
	// errHeldBackupInvalid: the backup's chain does not start with a certificate, its key is not a private key Alice
	// reads (PKCS #8, PKCS #1, SEC 1) or is not the leaf's, or the whole is larger than a backup may be.
	errHeldBackupInvalid = errors.New("inventory: the backup is not a certificate chain with its key")
	// errHeldBackupUnreadable: a stored backup did not decrypt or decode (secrets.ErrDecrypt says nothing about why).
	errHeldBackupUnreadable = errors.New("inventory: the held backup cannot be read")
)

func heldBackupLocation(deployment uuid.UUID) secrets.Location {
	return secrets.Location{Table: "deployment_backups", RowID: deployment.String(), Column: "ciphertext"}
}

// HeldBackups returns the store of deployment's held backup (providers.HeldBackups). Every deployment request and
// rollback request the engine builds carries one (Material sets it); providers that keep their backups on the target
// never call it.
func (s *Service) HeldBackups(deployment uuid.UUID) providers.HeldBackups {
	return heldBackups{s: s, deployment: deployment}
}

type heldBackups struct {
	s          *Service
	deployment uuid.UUID
}

// Hold seals and stores the backup of an unfinished deployment, fenced to the job's claim like every engine write
// (ErrClaimLost); a deployment that is final is ErrDeploymentState, an unknown one ErrNotFound. A backup already held for
// the deployment is kept (the content before any change of this deployment): Hold then stores nothing and returns nil.
// The chain must start with the certificate the key belongs to (errHeldBackupInvalid otherwise): what Alice may put back
// is checked before anything changes.
func (h heldBackups) Hold(ctx context.Context, b providers.HeldBackup) error {
	leaf, spki, err := checkHeldBackup(b)
	if err != nil {
		return err
	}
	payload := packHeldBackup(b)
	defer clear(payload)
	env, err := h.s.keyring.Seal(heldBackupLocation(h.deployment), payload)
	if err != nil {
		return fmt.Errorf("inventory: seal the held backup: %w", err)
	}
	return db.InTx(ctx, h.s.pool, func(tx pgx.Tx) error {
		if err := checkClaim(ctx, tx); err != nil {
			return err
		}
		var (
			location uuid.UUID
			state    string
		)
		err := tx.QueryRow(ctx, "SELECT location_id, state FROM deployments WHERE id = $1 FOR SHARE", h.deployment).Scan(&location, &state)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			return ErrNotFound
		case err != nil:
			return fmt.Errorf("inventory: read the deployment: %w", err)
		case state == DeployStateDone:
			return ErrDeploymentState
		}
		_, err = tx.Exec(ctx, `INSERT INTO deployment_backups (deployment_id, location_id, leaf_sha256, spki_sha256, ciphertext, nonce,
    wrapped_dek, key_version, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT (deployment_id) DO NOTHING`,
			h.deployment, location, leaf, spki, env.Ciphertext, env.Nonce, env.WrappedDEK, env.KeyVersion, h.s.clock.Now().UTC())
		if err != nil {
			return fmt.Errorf("inventory: store the held backup: %w", err)
		}
		return nil
	})
}

// Load opens the deployment's held backup; the caller zeroes it. providers.ErrNoHeldBackup when none is held (never
// taken, or deleted by the retention).
func (h heldBackups) Load(ctx context.Context) (providers.HeldBackup, error) {
	var env secrets.Envelope
	err := h.s.pool.QueryRow(ctx, "SELECT ciphertext, nonce, wrapped_dek, key_version FROM deployment_backups WHERE deployment_id = $1",
		h.deployment).Scan(&env.Ciphertext, &env.Nonce, &env.WrappedDEK, &env.KeyVersion)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return providers.HeldBackup{}, providers.ErrNoHeldBackup
	case err != nil:
		return providers.HeldBackup{}, fmt.Errorf("inventory: read the held backup: %w", err)
	}
	pt, err := h.s.keyring.Open(heldBackupLocation(h.deployment), env)
	if err != nil {
		return providers.HeldBackup{}, fmt.Errorf("%w (%w)", errHeldBackupUnreadable, err)
	}
	defer pt.Zero()
	b, ok := unpackHeldBackup(pt.Bytes())
	if !ok {
		return providers.HeldBackup{}, errHeldBackupUnreadable
	}
	return b, nil
}

// PurgeHeldBackups deletes the held backups of deployments final for more than HeldBackupRetention (maintenance.cleanup,
// every license state) and returns how many.
func (s *Service) PurgeHeldBackups(ctx context.Context) (int, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM deployment_backups b USING deployments d
WHERE d.id = b.deployment_id AND d.state = $1 AND d.finished_at <= $2`, DeployStateDone, s.clock.Now().UTC().Add(-HeldBackupRetention))
	if err != nil {
		return 0, fmt.Errorf("inventory: purge held backups: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// checkHeldBackup returns the hex SHA-256 of the leaf's DER and of its SubjectPublicKeyInfo after checking that the
// chain starts with a certificate whose public key is the key's.
func checkHeldBackup(b providers.HeldBackup) (leaf, spki string, err error) {
	if len(b.CertificatePEM)+len(b.PrivateKeyPEM.Bytes()) > maxHeldBackupBytes {
		return "", "", errHeldBackupInvalid
	}
	block, _ := pem.Decode(b.CertificatePEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", "", errHeldBackupInvalid
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", "", errHeldBackupInvalid
	}
	pub, ok := heldKeyPublic(b.PrivateKeyPEM.Bytes())
	if !ok || !pub.Equal(cert.PublicKey) {
		return "", "", errHeldBackupInvalid
	}
	l, s := sha256.Sum256(cert.Raw), sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(l[:]), hex.EncodeToString(s[:]), nil
}

// heldKeyPublic parses the single PEM private key and returns its public half.
func heldKeyPublic(keyPEM []byte) (interface{ Equal(crypto.PublicKey) bool }, bool) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, false
	}
	defer clear(block.Bytes)
	var (
		key any
		err error
	)
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, false
	}
	if err != nil {
		return nil, false
	}
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey, true
	case *ecdsa.PrivateKey:
		return &k.PublicKey, true
	case ed25519.PrivateKey:
		return k.Public().(ed25519.PublicKey), true
	}
	return nil, false
}

// packHeldBackup is the sealed payload: the chain's length (4 bytes, big-endian), the chain, the key.
func packHeldBackup(b providers.HeldBackup) []byte {
	key := b.PrivateKeyPEM.Bytes()
	out := make([]byte, 4, 4+len(b.CertificatePEM)+len(key))
	binary.BigEndian.PutUint32(out, uint32(len(b.CertificatePEM))) //nolint:gosec // G115: bounded by maxHeldBackupBytes
	out = append(out, b.CertificatePEM...)
	return append(out, key...)
}

// unpackHeldBackup reverses packHeldBackup into copies (the caller zeroes the payload).
func unpackHeldBackup(p []byte) (providers.HeldBackup, bool) {
	if len(p) < 4 {
		return providers.HeldBackup{}, false
	}
	n := int(binary.BigEndian.Uint32(p))
	if n > len(p)-4 {
		return providers.HeldBackup{}, false
	}
	chain := append([]byte(nil), p[4:4+n]...)
	key := append([]byte(nil), p[4+n:]...)
	return providers.HeldBackup{CertificatePEM: chain, PrivateKeyPEM: secrets.NewPlaintext(key)}, true
}
