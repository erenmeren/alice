package inventory

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"alice/internal/audit"
	"alice/internal/license"
	"alice/internal/platform/db"
	"alice/internal/providers"
	"alice/internal/secrets"
)

// The CCS password of a Windows server (R68, W5 Rulings 9-11). IIS's Centralized Certificate Store opens every PFX file
// of the store with one private-key password, so Alice keeps one per server: a credentials row of purpose win_ccs and
// kind win_ccs_password whose target_id is the server, sealed like every credential (AAD credentials/<id>/ciphertext;
// public_info is empty). Rows are append-only and the newest row of a server is its password; W5 has no delete. The
// password reaches the Windows provider only through the platform credential source (CCSPassword) and leaves Alice only
// inside the helper's standard input.

const (
	purposeWinCCS = "win_ccs"
	kindWinCCS    = "win_ccs_password"
	// minCCSPassword and maxCCSPassword are winproto.MinCCSPassword and MaxCCSPassword (Ruling 10).
	minCCSPassword = 12
	maxCCSPassword = 128
)

var (
	// ErrCCSPasswordInvalid: the password is not 12 to 128 characters of printable ASCII without a space (Ruling 10).
	ErrCCSPasswordInvalid = errors.New("inventory: the CCS password does not follow the rule")
	// ErrNotWindowsTarget: a CCS password was set on a target that is not a Windows server.
	ErrNotWindowsTarget = errors.New("inventory: the target is not a Windows server")
)

// validCCSPassword is winproto.ValidCCSPassword: the inventory may not import the Windows protocol (archtest), so it
// mirrors the rule (TestCCSPasswordRuleEqualsTheHelpers keeps the two equal). The alphabet is BuildPFX's: its
// BMPString and PBKDF2 bytes are then the same text.
func validCCSPassword(pw []byte) bool {
	if len(pw) < minCCSPassword || len(pw) > maxCCSPassword {
		return false
	}
	for _, c := range pw {
		if c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}

// SetCCSPassword stores pw as the CCS password of Windows server target, whose version must be ifVersion, and returns
// the target with its new version and CCSPasswordSetAt. pw is zeroed on every path. The API admits an Administrator
// with a fresh step-up only (rbac.CredentialsManage); the change is ClassChange. Audited as target.ccs_password_set,
// without the secret.
func (s *Service) SetCCSPassword(ctx context.Context, a Actor, target uuid.UUID, ifVersion int, pw secrets.Plaintext) (Target, error) {
	defer pw.Zero()
	if !validCCSPassword(pw.Bytes()) {
		return Target{}, ErrCCSPasswordInvalid
	}
	if err := s.license.Allow(license.ClassChange); err != nil {
		return Target{}, err
	}
	id := uuid.Must(uuid.NewV7())
	env, err := s.keyring.Seal(credentialLocation(id), pw.Bytes())
	if err != nil {
		return Target{}, fmt.Errorf("inventory: seal the CCS password: %w", err)
	}
	var updated Target
	err = db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		cur, err := getTarget(ctx, tx, target, true)
		if err != nil {
			return err
		}
		if cur.Type != TypeWindows {
			return ErrNotWindowsTarget
		}
		if cur.Version != ifVersion {
			return ErrVersionMismatch
		}
		now := s.clock.Now().UTC()
		if _, err := tx.Exec(ctx, `INSERT INTO credentials (id, purpose, kind, ciphertext, nonce, wrapped_dek, key_version, created_at, target_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			id, purposeWinCCS, kindWinCCS, env.Ciphertext, env.Nonce, env.WrappedDEK, env.KeyVersion, now, target); err != nil {
			return fmt.Errorf("inventory: store the CCS password: %w", err)
		}
		if _, err := tx.Exec(ctx, "UPDATE targets SET version = version + 1, updated_at = $2 WHERE id = $1", target, now); err != nil {
			return fmt.Errorf("inventory: update target: %w", err)
		}
		if updated, err = getTarget(ctx, tx, target, false); err != nil {
			return err
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "target.ccs_password_set", ObjectType: "target",
			ObjectID: target.String(), Result: audit.Success, Details: map[string]string{"name": cur.Name, "credential_id": id.String()}})
		return err
	})
	if err != nil {
		return Target{}, err
	}
	return updated, nil
}

// CCSPassword implements providers.CCSPasswordSource: it decrypts the newest CCS password of live Windows server target
// for one helper call. ErrNotFound wrapping providers.ErrNoCCSPassword when the server has none (or is not a live
// target); a row that does not suit the target (another type, another kind) is refused (errForeignCredential), never
// opened. release zeroes the password.
// Errors carry no secret.
func (c platformCredentials) CCSPassword(ctx context.Context, target uuid.UUID) (secrets.Plaintext, func(), error) {
	var (
		id         uuid.UUID
		kind, typ  string
		env        secrets.Envelope
		emptyValue secrets.Plaintext
	)
	err := c.s.pool.QueryRow(ctx, `SELECT c.id, c.kind, c.ciphertext, c.nonce, c.wrapped_dek, c.key_version, t.type
FROM targets t JOIN credentials c ON c.target_id = t.id AND c.purpose = $2
WHERE t.id = $1 AND t.deleted_at IS NULL
ORDER BY c.created_at DESC, c.id DESC LIMIT 1`, target, purposeWinCCS).
		Scan(&id, &kind, &env.Ciphertext, &env.Nonce, &env.WrappedDEK, &env.KeyVersion, &typ)
	if errors.Is(err, pgx.ErrNoRows) {
		return emptyValue, nil, fmt.Errorf("%w: %w", ErrNotFound, providers.ErrNoCCSPassword)
	}
	if err != nil {
		return emptyValue, nil, fmt.Errorf("inventory: read the CCS password: %w", err)
	}
	if typ != TypeWindows || kind != kindWinCCS {
		return emptyValue, nil, fmt.Errorf("%w: %w", errForeignCredential, providers.ErrCCSPasswordUnusable)
	}
	pt, err := c.s.keyring.Open(credentialLocation(id), env)
	if err != nil { // secrets.ErrDecrypt, which says nothing about why
		return emptyValue, nil, fmt.Errorf("inventory: the CCS password cannot be decrypted with this master key: %w", providers.ErrCCSPasswordUnusable)
	}
	return pt, pt.Zero, nil
}
