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
	ErrPFXBusy = errors.New("inventory: too many PFX files are being read; try again shortly")
	// ErrCSRBusy: the process already generates as many signing-request keys as it allows at once
	// (maxCSRKeygens); retryable.
	ErrCSRBusy = errors.New("inventory: too many signing-request keys are being generated; try again shortly")
	// ErrTooManyPendingCSRs: maxPendingCSRs signing requests are open; one must be completed or
	// cancelled first.
	ErrTooManyPendingCSRs  = errors.New("inventory: too many signing requests are open")
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

// Errors of Key Vault targets (Task 10). The API maps each to its code (Task 17).
var (
	// ErrVaultHasBindings: the vault still has connected websites; delete them first or ask for
	// them to be removed with the vault.
	ErrVaultHasBindings = errors.New("inventory: the vault still has connected websites")
	// ErrNotAVault: the target is not a Key Vault (a vault-only operation named a server).
	ErrNotAVault = errors.New("inventory: the target is not a Key Vault")
	// ErrNotAServer: the target is a Key Vault (a server-only operation named a vault).
	ErrNotAServer = errors.New("inventory: the target is not a server")
	// ErrClientCertificateInvalid: the sign-in certificate's key is not an RSA key of 2048 bits or
	// more (certs.ErrClientCertKey).
	ErrClientCertificateInvalid = certs.ErrClientCertKey
	// ErrNotExportable: the vault certificate's private key cannot be read from the vault.
	ErrNotExportable = errors.New("inventory: the vault certificate is not exportable")
	// ErrVersionNotDeployable: Alice has not read a current version of the vault certificate yet.
	ErrVersionNotDeployable = errors.New("inventory: the vault certificate has no known current version")
	// ErrCredentialNotTheTargets: the database refused a credential that does not belong to the
	// target it was set on (SQLSTATE Z1006). Correct code never gets it.
	ErrCredentialNotTheTargets = errors.New("inventory: the credential does not belong to this target")
	// errForeignCredential: a vault's credential row names another vault; it is never used.
	errForeignCredential = errors.New("inventory: the vault's credential belongs to another target")
	// errNotAnSSHTarget: a vault's credential source offers no SSH key.
	errNotAnSSHTarget = errors.New("inventory: a Key Vault has no SSH credential")
)

// Errors of bindings and Key Vault deployments (Task 12). The API maps each to its code (Task 17).
var (
	// ErrLocationBound: the website (certificate location) is already connected to a vault certificate.
	// A *LocationRefusalError names the location.
	ErrLocationBound = errors.New("inventory: the website is already connected to a vault certificate")
	// ErrBindingExists: the vault certificate already has connected websites; change that binding.
	ErrBindingExists = errors.New("inventory: the vault certificate already has connected websites")
	// ErrVersionDisabled: the version is disabled in the vault.
	ErrVersionDisabled = errors.New("inventory: the vault certificate version is disabled")
	// ErrKVCertificateMissing: the vault certificate is unknown, or no longer listed by its vault.
	ErrKVCertificateMissing = errors.New("inventory: the vault certificate is not in the vault")
	// ErrHeldNeedsAdmin: a held version is deployed or released by an Administrator only (rulings S6, S8).
	ErrHeldNeedsAdmin = errors.New("inventory: only an Administrator can deploy or release a held version")
	// ErrAdminRequired: only an Administrator may switch automatic deployment or add websites to a
	// binding that deploys automatically (ruling S6).
	ErrAdminRequired = errors.New("inventory: only an Administrator can do this")
	// ErrVersionNotHeld: the version is not held, so there is nothing to release.
	ErrVersionNotHeld = errors.New("inventory: the version is not held")
	// ErrSecretUnreadable: the vault secret behind a version cannot be used (not a certificate with
	// its key, an unsupported container or a key that does not fit the certificate).
	ErrSecretUnreadable = errors.New("inventory: the vault secret cannot be read as a certificate with its key")
	// ErrSecretMismatch: the vault secret is not the certificate version Alice recorded (another
	// leaf, thumbprint or key type).
	ErrSecretMismatch = errors.New("inventory: the vault secret is not the recorded version")
)

// Errors of the material step of a Key Vault deployment (Task 12 review fixes): the state the
// deployment was requested in no longer holds, so no secret is read and no key is handed out. None
// writes anything; the engine ends the deployment with the matching closed reason.
var (
	// ErrBindingGone: the deployment's binding was removed, or its website no longer belongs to it.
	ErrBindingGone = errors.New("inventory: the website is no longer connected to the deployment's binding")
	// ErrAutoDeployOff: an automatic deployment of a binding whose automatic deployment was switched off.
	ErrAutoDeployOff = errors.New("inventory: automatic deployment of the binding is switched off")
	// ErrVersionHeld: the version is held (an automatic deployment never deploys it; a manual one only
	// when an Administrator asked for it).
	ErrVersionHeld = errors.New("inventory: the version is held")
	// ErrVaultUnavailable: the vault is disabled or deleted.
	ErrVaultUnavailable = errors.New("inventory: the vault is disabled or deleted")
)

// Errors of imports into a vault (Task 14). The API maps each to its code (Task 17).
var (
	// ErrImportConfirmNeeded: the certificate name already exists in the vault and the request did not
	// confirm that a new version may be added (ruling S9). The error is an *ImportConfirmError naming it.
	ErrImportConfirmNeeded = errors.New("inventory: the vault already has a certificate with this name; confirm to add a version")
	// ErrImportInProgress: an import of this name into this vault is queued, running or not confirmed yet.
	ErrImportInProgress = errors.New("inventory: an import of this certificate name into this vault is still open")
	// ErrImportState: the import is not in a state that allows the step (a second send, a result for an
	// import that was never sent, anything for a finished import).
	ErrImportState = errors.New("inventory: the import is not in a state that allows this")
	// ErrImportChanged: the certificate Alice holds is no longer the one the import was requested for.
	ErrImportChanged = errors.New("inventory: the certificate changed since the import was requested")
)

// ImportConfirmError is ErrImportConfirmNeeded with the certificate name the vault already has.
type ImportConfirmError struct{ CertificateName string }

func (e *ImportConfirmError) Error() string { return ErrImportConfirmNeeded.Error() }

// Is makes errors.Is(err, ErrImportConfirmNeeded) hold.
func (e *ImportConfirmError) Is(target error) bool { return target == ErrImportConfirmNeeded }

// Errors of the pre-read check for AUTOMATIC deployments (fix round 1, m2): the planner created the
// deployment for a version that is no longer the right one. Manual deployments are never refused for
// these reasons (the spec allows deploying an older version by hand).
var (
	// ErrVersionSuperseded: the version is no longer the certificate's current version.
	ErrVersionSuperseded = errors.New("inventory: a newer version of the certificate replaced this one")
	// ErrWaveStopped: the binding's automatic wave of this version was stopped (stopped_version).
	ErrWaveStopped = errors.New("inventory: the automatic deployment of this version was stopped")
)
