package inventory

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"alice/internal/providers"
	"alice/internal/secrets"
)

// The WinRM password of a Windows server whose transport is winrm (R71 Rulings 5, 7 and 8), stored and read by the CCS
// password's code (setTargetPassword, targetPassword) with its own spec: a credentials row of purpose win_winrm and kind winrm_password whose target_id is the server, sealed like
// every credential (AAD credentials/<id>/ciphertext; public_info is empty). A set or a removal ends the live row
// (rotated_at, R72 Ruling 7); the live row is the password. The password reaches the Windows provider only through the platform
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
//
// from is the optional address the script's firewall rule accepts, validated and made canonical as SetupGuide's.
func (s *Service) WinRMSetup(ctx context.Context, target uuid.UUID, from string) (WinRMSetup, error) {
	from, err := setupFrom(from)
	if err != nil {
		return WinRMSetup{}, err
	}
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
			out.Script = g.WinRMSetupScript(t.Username, from)
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

// winrmPasswordSpec is the WinRM password's targetPasswordSpec: a Windows server whose transport is winrm.
var winrmPasswordSpec = targetPasswordSpec{purpose: purposeWinWinRM, kind: kindWinRMPassword, name: "WinRM", check: requireWinRM,
	valid: validWinRMPassword, invalid: ErrWinRMPasswordInvalid, action: "target.winrm_password_set",
	removed: "target.winrm_password_removed", none: providers.ErrNoWinRMPassword, unusable: providers.ErrWinRMPasswordUnusable}

// SetWinRMPassword stores pw as the WinRM password of Windows server target, whose transport must be winrm and whose
// version must be ifVersion, and returns the target with its new version and WinRMPasswordSetAt (setTargetPassword).
// pw is zeroed on every path. The API admits an Administrator with a fresh step-up only (rbac.CredentialsManage); the
// change is ClassChange. Audited as target.winrm_password_set, without the secret.
func (s *Service) SetWinRMPassword(ctx context.Context, a Actor, target uuid.UUID, ifVersion int, pw secrets.Plaintext) (Target, error) {
	return s.setTargetPassword(ctx, a, target, ifVersion, pw, winrmPasswordSpec)
}

// ClearWinRMPassword removes the WinRM password of Windows server target, whose transport must be winrm and whose
// version must be ifVersion (clearTargetPassword). Afterwards every helper call is refused windows.winrm_password_missing
// before any dial, until a new password is set (R72 Ruling 9).
func (s *Service) ClearWinRMPassword(ctx context.Context, a Actor, target uuid.UUID, ifVersion int) (Target, error) {
	return s.clearTargetPassword(ctx, a, target, ifVersion, winrmPasswordSpec)
}

// WinRMPassword implements providers.WinRMPasswordSource: it decrypts the newest WinRM password of live Windows server
// target for one helper call (targetPassword). ErrNotFound wrapping providers.ErrNoWinRMPassword when the server has
// none; a row that does not suit the target is refused (errForeignCredential), never opened. release zeroes the
// password. Errors carry no secret.
func (c platformCredentials) WinRMPassword(ctx context.Context, target uuid.UUID) (secrets.Plaintext, func(), error) {
	return c.targetPassword(ctx, target, winrmPasswordSpec)
}
