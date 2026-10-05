package sshkeys

import (
	"errors"

	"alice/internal/inventory"
)

// Errors of the module (C7). The API maps each to its code (C11). None carries a value from the
// request or the database, and never key material.
var (
	ErrNotFound          = inventory.ErrNotFound
	ErrNotManaged        = errors.New("sshkeys: Alice holds no private key for this key")
	ErrRetired           = errors.New("sshkeys: the key is retired")
	ErrDestroyed         = errors.New("sshkeys: the private key was destroyed")
	ErrConnectionAccount = errors.New("sshkeys: Alice does not change its connection account's keys")
	ErrNotAKeyFile       = errors.New("sshkeys: the file is not one of the user's key files")
	ErrGenerateBusy      = errors.New("sshkeys: too many keys are being generated")
	ErrVersionMismatch   = inventory.ErrVersionMismatch
	ErrOwnKeyProtected   = inventory.ErrOwnKeyProtected
)

// errUndecryptable: the envelope does not open with this master key (another key, a damaged row).
// It wraps nothing: the keyring's error says nothing either, but the text here is fixed.
var errUndecryptable = errors.New("sshkeys: the private key cannot be decrypted with this master key")
