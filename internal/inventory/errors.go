package inventory

import (
	"errors"

	"github.com/google/uuid"

	"alice/internal/certs"
)

// Errors of the inventory service. The API maps each to a stable ALC code (Task 16). None of
// them carries a value from the request or the database.
var (
	ErrNotFound             = errors.New("inventory: not found")
	ErrDuplicateTarget      = errors.New("inventory: a server with this name or address exists")
	ErrVersionMismatch      = errors.New("inventory: the target changed since it was read")
	ErrHostKeyUnconfirmed   = errors.New("inventory: the server's fingerprint is not confirmed")
	ErrHostKeyChanged       = errors.New("inventory: the server's identity changed")
	ErrHostKeyStale         = errors.New("inventory: the fingerprint is not the one the server presented")
	ErrHostKeyState         = errors.New("inventory: the host key cannot be confirmed in this state")
	ErrOwnKeyProtected      = errors.New("inventory: Alice's own key cannot be removed")
	ErrLastRootKey          = errors.New("inventory: this is the last key of root")
	ErrKeysManagedElsewhere = errors.New("inventory: keys on this server are managed by AuthorizedKeysCommand")
	ErrNotRemovable         = errors.New("inventory: this key location cannot be removed")
	// ErrSSHDUnreadable: the last scan could not read sshd's settings (for the server or the
	// key's user), so the files Alice sees may not be the ones sshd uses.
	ErrSSHDUnreadable = errors.New("inventory: the server's sshd settings could not be read")
	// ErrJobConflict: the same job is already queued with other options (EnqueueTx).
	ErrJobConflict = errors.New("inventory: the same job is already queued with other options")
	// ErrNoSetupScript: the provider offers no setup script, because this build has no
	// alice-helper checksums and is not a development build (R37 item 2).
	ErrNoSetupScript = errors.New("inventory: this build of Alice cannot offer a setup script")
	// ErrNoPlatformKey means EnsurePlatformKey has not run on this database yet.
	ErrNoPlatformKey = errors.New("inventory: the platform SSH key does not exist yet")
)

// Errors of certificate uploads, signing requests and locations (Task 14). The upload and signing
// request refusals are the certs package's sentinels re-exported (api may not import certs); like
// those, none carries input, and never key material or a password.
var (
	ErrCertificateDuplicate = errors.New("inventory: Alice already holds this certificate with its key")
	ErrCSRNotPending        = errors.New("inventory: the signing request is no longer open")
	ErrLocationUnsupported  = errors.New("inventory: certificates cannot be deployed to this location")
	// ErrPFXBusy: the process already decodes as many PFX files as it allows at once
	// (maxPFXDecodes); retryable.
	ErrPFXBusy             = errors.New("inventory: too many PFX files are being read; try again shortly")
	ErrCertificateInvalid  = certs.ErrInvalid
	ErrKeyMismatch         = certs.ErrKeyMismatch
	ErrCertificateExpired  = certs.ErrExpired // also returned by RequestDeployment (Task 15)
	ErrKeyEncrypted        = certs.ErrKeyEncrypted
	ErrPFXPassword         = certs.ErrPFXPassword
	ErrWeakCertificate     = certs.ErrWeak
	ErrUnsupportedKey      = certs.ErrUnsupportedKey
	ErrCSRMismatch         = certs.ErrCSRMismatch
	ErrCertificateTooLarge = certs.ErrTooLarge
)

// Errors of deployments (Task 15). RequestDeployment refuses with the first that applies; the
// API maps each to its code (Task 17).
var (
	// ErrDeploymentInProgress: the location already has an unfinished deployment (F-15;
	// deployments_one_active is the backstop for concurrent requests).
	ErrDeploymentInProgress = errors.New("inventory: another deployment to this location is in progress")
	// ErrRecoveryPending: a deployment on the same server is being recovered; nothing new starts
	// there until it ends (R38 item 8, F-09).
	ErrRecoveryPending  = errors.New("inventory: an earlier deployment on this server is being recovered")
	ErrNoPrivateKey     = errors.New("inventory: Alice does not hold this certificate's private key")
	ErrKeyTypeMismatch  = errors.New("inventory: the certificate's key type does not fit the location")
	ErrChainUnconfirmed = errors.New("inventory: an Administrator must confirm the incomplete chain")
	// ErrNginxConfigInvalid: the server's last test or scan found nginx -t failing.
	ErrNginxConfigInvalid = errors.New("inventory: the server's Nginx configuration has an error")
	// ErrTargetNotReady: the server is not connected (pending or changed host key, failed sign-in,
	// disabled).
	ErrTargetNotReady = errors.New("inventory: the server is not connected")
	// ErrDeploymentState: the deployment is not in a state that allows the step (a second start,
	// a success that was never sent, the key asked for after the first send, a step of a finished
	// deployment). The engine reads the deployment again and follows its state.
	ErrDeploymentState = errors.New("inventory: the deployment is not in a state that allows this")
	// ErrCertificateNotYetValid: the certificate's validity has not begun; browsers would refuse
	// it (a probe comparing fingerprints would still pass).
	ErrCertificateNotYetValid = errors.New("inventory: the certificate is not valid yet")
	// ErrLocationNeedsDiscovery: Alice does not know the hash of the location's certificate file
	// (never read, or a deployment ended without the new file's hash); the compare-and-swap needs
	// it, so the server must be discovered again first.
	ErrLocationNeedsDiscovery = errors.New("inventory: the location must be discovered again before a deployment")
)

// KeyTypeMismatchError is ErrKeyTypeMismatch with the two key types ("rsa", "ecdsa"): the type
// the location's current certificate has and the type of the certificate asked for.
type KeyTypeMismatchError struct{ Expected, Actual string }

func (e *KeyTypeMismatchError) Error() string { return ErrKeyTypeMismatch.Error() }

// Is makes errors.Is(err, ErrKeyTypeMismatch) hold.
func (e *KeyTypeMismatchError) Is(target error) bool { return target == ErrKeyTypeMismatch }

// LocationRefusalError names the location a RequestDeployment refusal is about (an unknown
// location, or a refusal decided for one location). Err is the refusal; errors.Is and errors.As
// see through it. A refusal of the certificate itself (no key, expired, an unconfirmed chain) is
// returned bare: it applies to every location of the request.
type LocationRefusalError struct {
	LocationID uuid.UUID
	Err        error
}

func (e *LocationRefusalError) Error() string { return e.Err.Error() }

// Unwrap returns the refusal.
func (e *LocationRefusalError) Unwrap() error { return e.Err }
