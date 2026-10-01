package inventory

import "errors"

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
	// ErrNoPlatformKey means EnsurePlatformKey has not run on this database yet.
	ErrNoPlatformKey = errors.New("inventory: the platform SSH key does not exist yet")
)
