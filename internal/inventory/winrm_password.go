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

// The WinRM password of a Windows server whose transport is winrm (R71 Rulings 5, 7 and 8), W5's CCS password pattern
// exactly: a credentials row of purpose win_winrm and kind winrm_password whose target_id is the server, sealed like
// every credential (AAD credentials/<id>/ciphertext; public_info is empty). Rows are append-only and the newest row of a
// server is its password; W7 has no delete. The password reaches the Windows provider only through the platform
// credential source (WinRMPassword), for one call at a time.

const (
	purposeWinWinRM   = "win_winrm"
	kindWinRMPassword = "winrm_password"
)

var (
	// ErrWinRMPasswordInvalid: the password is not 12 to 128 characters of printable ASCII without a space (Ruling 7).
	ErrWinRMPasswordInvalid = errors.New("inventory: the WinRM password does not follow the rule")
	// ErrTransportImmutable: a change named another transport than the target's (Ruling 3: fixed at creation).
	ErrTransportImmutable = errors.New("inventory: the transport of a target cannot be changed")
)

// validWinRMPassword is the CCS rule (Ruling 7): Windows' own password policy is the server's.
func validWinRMPassword(pw []byte) bool { return validCCSPassword(pw) }

// WinRMSetup is the WinRM setup of a target (Ruling 19): its account, as typed, and the provider's script for it ("" for
// a build that cannot verify the helper).
type WinRMSetup struct {
	User   string
	Script string
}

// WinRMSetup answers the WinRM setup script of live Windows server target, through the Windows provider's
// providers.WinRMSetupGuide (the inventory may not import the provider). Any other target, an SSH Windows server among
// them, is ErrNotWindowsTarget.
func (s *Service) WinRMSetup(ctx context.Context, target uuid.UUID) (WinRMSetup, error) {
	t, err := s.GetTarget(ctx, target)
	if err != nil {
		return WinRMSetup{}, err
	}
	if err := requireWinRM(t); err != nil {
		return WinRMSetup{}, err
	}
	out := WinRMSetup{User: t.Username}
	if p, ok := s.providerFor(t.Type); ok {
		if g, ok := p.(providers.WinRMSetupGuide); ok {
			out.Script = g.WinRMSetupScript(t.Username)
		}
	}
	return out, nil
}

// requireWinRM refuses a target that is not a Windows server whose transport is winrm.
func requireWinRM(t Target) error {
	if t.Type != TypeWindows {
		return ErrNotWindowsTarget
	}
	if t.Transport != TransportWinRM {
		return fmt.Errorf("%w: its transport is not winrm", ErrNotWindowsTarget)
	}
	return nil
}

// SetWinRMPassword stores pw as the WinRM password of Windows server target, whose transport must be winrm and whose
// version must be ifVersion, and returns the target with its new version and WinRMPasswordSetAt. pw is zeroed on every
// path. The API admits an Administrator with a fresh step-up only (rbac.CredentialsManage); the change is ClassChange.
// Audited as target.winrm_password_set, without the secret.
func (s *Service) SetWinRMPassword(ctx context.Context, a Actor, target uuid.UUID, ifVersion int, pw secrets.Plaintext) (Target, error) {
	defer pw.Zero()
	if err := s.license.Allow(license.ClassChange); err != nil {
		return Target{}, err
	}
	id := uuid.Must(uuid.NewV7())
	env, err := s.keyring.Seal(credentialLocation(id), pw.Bytes())
	if err != nil {
		return Target{}, fmt.Errorf("inventory: seal the WinRM password: %w", err)
	}
	var updated Target
	err = db.InTx(ctx, s.pool, func(tx pgx.Tx) error {
		cur, err := getTarget(ctx, tx, target, true)
		if err != nil {
			return err
		}
		if err := requireWinRM(cur); err != nil {
			return err
		}
		if !validWinRMPassword(pw.Bytes()) { // after the target (W5-5): the seal of an invalid password is discarded with the transaction
			return ErrWinRMPasswordInvalid
		}
		if cur.Version != ifVersion {
			return ErrVersionMismatch
		}
		now := s.clock.Now().UTC()
		if _, err := tx.Exec(ctx, `INSERT INTO credentials (id, purpose, kind, ciphertext, nonce, wrapped_dek, key_version, created_at, target_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			id, purposeWinWinRM, kindWinRMPassword, env.Ciphertext, env.Nonce, env.WrappedDEK, env.KeyVersion, now, target); err != nil {
			return fmt.Errorf("inventory: store the WinRM password: %w", err)
		}
		if _, err := tx.Exec(ctx, "UPDATE targets SET version = version + 1, updated_at = $2 WHERE id = $1", target, now); err != nil {
			return fmt.Errorf("inventory: update target: %w", err)
		}
		if updated, err = getTarget(ctx, tx, target, false); err != nil {
			return err
		}
		_, err = s.audit.Append(ctx, tx, audit.Event{Actor: a.Audit, Action: "target.winrm_password_set", ObjectType: "target",
			ObjectID: target.String(), Result: audit.Success, Details: map[string]string{"name": cur.Name, "credential_id": id.String()}})
		return err
	})
	if err != nil {
		return Target{}, err
	}
	return updated, nil
}

// WinRMPassword implements providers.WinRMPasswordSource: it decrypts the newest WinRM password of live Windows server
// target for one helper call. ErrNotFound wrapping providers.ErrNoWinRMPassword when the server has none (or is not a
// live target); a row that does not suit the target (another type, another kind) is refused (errForeignCredential),
// never opened. release zeroes the password.
// Errors carry no secret.
func (c platformCredentials) WinRMPassword(ctx context.Context, target uuid.UUID) (secrets.Plaintext, func(), error) {
	var (
		id         uuid.UUID
		kind, typ  string
		env        secrets.Envelope
		emptyValue secrets.Plaintext
	)
	err := c.s.pool.QueryRow(ctx, `SELECT c.id, c.kind, c.ciphertext, c.nonce, c.wrapped_dek, c.key_version, t.type
FROM targets t JOIN credentials c ON c.target_id = t.id AND c.purpose = $2
WHERE t.id = $1 AND t.deleted_at IS NULL
ORDER BY c.created_at DESC, c.id DESC LIMIT 1`, target, purposeWinWinRM).
		Scan(&id, &kind, &env.Ciphertext, &env.Nonce, &env.WrappedDEK, &env.KeyVersion, &typ)
	if errors.Is(err, pgx.ErrNoRows) {
		return emptyValue, nil, fmt.Errorf("%w: %w", ErrNotFound, providers.ErrNoWinRMPassword)
	}
	if err != nil {
		return emptyValue, nil, fmt.Errorf("inventory: read the WinRM password: %w", err)
	}
	if typ != TypeWindows || kind != kindWinRMPassword {
		return emptyValue, nil, fmt.Errorf("%w: %w", errForeignCredential, providers.ErrWinRMPasswordUnusable)
	}
	pt, err := c.s.keyring.Open(credentialLocation(id), env)
	if err != nil { // secrets.ErrDecrypt, which says nothing about why
		return emptyValue, nil, fmt.Errorf("inventory: the WinRM password cannot be decrypted with this master key: %w", providers.ErrWinRMPasswordUnusable)
	}
	return pt, pt.Zero, nil
}
