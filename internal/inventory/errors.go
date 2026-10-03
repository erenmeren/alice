package inventory

import (
	"errors"

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
	ErrCertificateInvalid   = certs.ErrInvalid
	ErrKeyMismatch          = certs.ErrKeyMismatch
	ErrCertificateExpired   = certs.ErrExpired // also returned by RequestDeployment (Task 15)
	ErrKeyEncrypted         = certs.ErrKeyEncrypted
	ErrPFXPassword          = certs.ErrPFXPassword
	ErrWeakCertificate      = certs.ErrWeak
	ErrUnsupportedKey       = certs.ErrUnsupportedKey
	ErrCSRMismatch          = certs.ErrCSRMismatch
	ErrCertificateTooLarge  = certs.ErrTooLarge
)
