package inventory

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

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
// public_info is empty). Rows are never deleted: a set or a removal ends the live row (rotated_at, R72 Ruling 7), so a
// server has at most one live row, its password. The
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

// targetPasswordSpec is one password credential of a Windows server (the CCS password, W5 Rulings 9-11; the WinRM
// password, R71 Rulings 7-8): its credentials purpose and kind, its name in error texts, the targets that take it, its
// rule and the error for a password outside it, its audit actions (set, removed) and the provider sentinels of its source.
type targetPasswordSpec struct {
	purpose, kind, name string
	check               func(Target) error
	valid               func([]byte) bool
	invalid             error
	action, removed     string
	none, unusable      error
}

var ccsPasswordSpec = targetPasswordSpec{purpose: purposeWinCCS, kind: kindWinCCS, name: "CCS",
	check: func(t Target) error {
		if t.Type != TypeWindows {
			return ErrNotWindowsTarget
		}
		return nil
	},
	valid: validCCSPassword, invalid: ErrCCSPasswordInvalid, action: "target.ccs_password_set", removed: "target.ccs_password_removed",
	none: providers.ErrNoCCSPassword, unusable: providers.ErrCCSPasswordUnusable}

// SetCCSPassword stores pw as the CCS password of Windows server target, whose version must be ifVersion, and returns
// the target with its new version and CCSPasswordSetAt. pw is zeroed on every path. The API admits an Administrator
// with a fresh step-up only (rbac.CredentialsManage); the change is ClassChange. Audited as target.ccs_password_set,
// without the secret.
func (s *Service) SetCCSPassword(ctx context.Context, a Actor, target uuid.UUID, ifVersion int, pw secrets.Plaintext) (Target, error) {
	return s.setTargetPassword(ctx, a, target, ifVersion, pw, ccsPasswordSpec)
}

// setTargetPassword stores pw as the spec's password of target, whose version must be ifVersion: the live row ended,
// one new sealed row, the target's version moved, and the spec's audit action without the secret. pw is zeroed on every
// path. The seal happens before the transaction; inside it the target is checked first, then the rule (so the seal of
// an invalid password is discarded with the transaction, W5-5), then the version.
func (s *Service) setTargetPassword(ctx context.Context, a Actor, target uuid.UUID, ifVersion int, pw secrets.Plaintext,
	spec targetPasswordSpec) (Target, error) {
	defer pw.Zero()
	if err := s.license.Allow(license.ClassChange); err != nil {
		return Target{}, err
	}
	id := uuid.Must(uuid.NewV7())
	env, err := s.keyring.Seal(credentialLocation(id), pw.Bytes())
	if err != nil {
		return Target{}, fmt.Errorf("inventory: seal the %s password: %w", spec.name, err)
	}
	var updated Target
	err = db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		cur, err := getTarget(ctx, tx, target, true)
		if err != nil {
			return err
		}
		if err := spec.check(cur); err != nil {
			return err
		}
		if !spec.valid(pw.Bytes()) {
			return spec.invalid
		}
		if cur.Version != ifVersion {
			return ErrVersionMismatch
		}
		now := s.clock.Now().UTC()
		if _, err := endPasswords(ctx, tx, target, spec, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO credentials (id, purpose, kind, ciphertext, nonce, wrapped_dek, key_version, created_at, target_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			id, spec.purpose, spec.kind, env.Ciphertext, env.Nonce, env.WrappedDEK, env.KeyVersion, now, target); err != nil {
			return fmt.Errorf("inventory: store the %s password: %w", spec.name, err)
		}
		if _, err := tx.Exec(ctx, "UPDATE targets SET version = version + 1, updated_at = $2 WHERE id = $1", target, now); err != nil {
			return fmt.Errorf("inventory: update target: %w", err)
		}
		if updated, err = getTarget(ctx, tx, target, false); err != nil {
			return err
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: spec.action, ObjectType: "target",
			ObjectID: target.String(), Result: audit.Success, Details: map[string]string{"name": cur.Name, "credential_id": id.String()}})
		return err
	})
	if err != nil {
		return Target{}, err
	}
	return updated, nil
}

// endPasswords ends the live rows of the spec's purpose of target at now and returns their ids (R72 Ruling 7).
func endPasswords(ctx context.Context, tx pgx.Tx, target uuid.UUID, spec targetPasswordSpec, now time.Time) ([]string, error) {
	rows, _ := tx.Query(ctx, `UPDATE credentials SET rotated_at = $3 WHERE target_id = $1 AND purpose = $2 AND rotated_at IS NULL
RETURNING id::text`, target, spec.purpose, now)
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("inventory: end the %s password: %w", spec.name, err)
	}
	return ids, nil
}

// ClearCCSPassword removes the CCS password of Windows server target, whose version must be ifVersion
// (clearTargetPassword). The API admits an Administrator with a fresh step-up only; the change is ClassChange.
func (s *Service) ClearCCSPassword(ctx context.Context, a Actor, target uuid.UUID, ifVersion int) (Target, error) {
	return s.clearTargetPassword(ctx, a, target, ifVersion, ccsPasswordSpec)
}

// clearTargetPassword ends the live rows of the spec's purpose of target, whose version must be ifVersion (R72 Rulings
// 7-8): nothing is deleted, the ended ciphertext stays sealed. When a row ended the target's version moves and the
// spec's removed action is audited with the name and the ended credential ids (credential_id, comma-separated: the
// audit refuses any other key naming a credential), never a secret; with nothing to remove
// the target is answered unchanged, nothing audited.
func (s *Service) clearTargetPassword(ctx context.Context, a Actor, target uuid.UUID, ifVersion int, spec targetPasswordSpec) (Target, error) {
	if err := s.license.Allow(license.ClassChange); err != nil {
		return Target{}, err
	}
	var updated Target
	err := db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		cur, err := getTarget(ctx, tx, target, true)
		if err != nil {
			return err
		}
		if err := spec.check(cur); err != nil {
			return err
		}
		if cur.Version != ifVersion {
			return ErrVersionMismatch
		}
		now := s.clock.Now().UTC()
		ended, err := endPasswords(ctx, tx, target, spec, now)
		if err != nil {
			return err
		}
		if len(ended) == 0 {
			updated = cur
			return nil
		}
		if _, err := tx.Exec(ctx, "UPDATE targets SET version = version + 1, updated_at = $2 WHERE id = $1", target, now); err != nil {
			return fmt.Errorf("inventory: update target: %w", err)
		}
		if updated, err = getTarget(ctx, tx, target, false); err != nil {
			return err
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: spec.removed, ObjectType: "target",
			ObjectID: target.String(), Result: audit.Success,
			Details: map[string]string{"name": cur.Name, "credential_id": strings.Join(ended, ",")}})
		return err
	})
	if err != nil {
		return Target{}, err
	}
	return updated, nil
}

// CCSPassword implements providers.CCSPasswordSource: it decrypts the live CCS password of live Windows server target
// for one helper call. ErrNotFound wrapping providers.ErrNoCCSPassword when the server has none (or is not a live
// target); a row that does not suit the target (another type, another kind) is refused (errForeignCredential), never
// opened. release zeroes the password.
// Errors carry no secret.
func (c platformCredentials) CCSPassword(ctx context.Context, target uuid.UUID) (secrets.Plaintext, func(), error) {
	return c.targetPassword(ctx, target, ccsPasswordSpec)
}

// targetPassword decrypts the newest live row (rotated_at IS NULL) of the spec's purpose of live Windows server target: ErrNotFound wrapping
// spec.none when there is none, errForeignCredential wrapping spec.unusable for a row of another target type or kind
// (never opened), spec.unusable for a row this master key cannot open. release zeroes the password.
func (c platformCredentials) targetPassword(ctx context.Context, target uuid.UUID, spec targetPasswordSpec) (secrets.Plaintext, func(), error) {
	var (
		id         uuid.UUID
		kind, typ  string
		env        secrets.Envelope
		emptyValue secrets.Plaintext
	)
	err := c.s.pool.QueryRow(ctx, `SELECT c.id, c.kind, c.ciphertext, c.nonce, c.wrapped_dek, c.key_version, t.type
FROM targets t JOIN credentials c ON c.target_id = t.id AND c.purpose = $2 AND c.rotated_at IS NULL
WHERE t.id = $1 AND t.deleted_at IS NULL
ORDER BY c.created_at DESC, c.id DESC LIMIT 1`, target, spec.purpose).
		Scan(&id, &kind, &env.Ciphertext, &env.Nonce, &env.WrappedDEK, &env.KeyVersion, &typ)
	if errors.Is(err, pgx.ErrNoRows) {
		return emptyValue, nil, fmt.Errorf("%w: %w", ErrNotFound, spec.none)
	}
	if err != nil {
		return emptyValue, nil, fmt.Errorf("inventory: read the %s password: %w", spec.name, err)
	}
	if typ != TypeWindows || kind != spec.kind {
		return emptyValue, nil, fmt.Errorf("%w: %w", errForeignCredential, spec.unusable)
	}
	pt, err := c.s.keyring.Open(credentialLocation(id), env)
	if err != nil { // secrets.ErrDecrypt, which says nothing about why
		return emptyValue, nil, fmt.Errorf("inventory: the %s password cannot be decrypted with this master key: %w", spec.name, spec.unusable)
	}
	return pt, pt.Zero, nil
}
