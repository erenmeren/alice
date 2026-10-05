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
	// ErrInRotation: the key is the new key of an unfinished rotation run; it is deployed only after the
	// run finished (reason sshkey.in_rotation; re-review N-m11).
	ErrInRotation = errors.New("sshkeys: the key is the new key of a rotation that has not finished")
	// ErrConnectionFilesUnknown: the last scan of the server has no complete, single list of the
	// connection account's key files, so Alice cannot rule out that a file is one its connection
	// account reads; scan the server again (reason sshkey.connection_files_unknown; review N1).
	ErrConnectionFilesUnknown = errors.New("sshkeys: the connection account's key files on this server are not known completely")
	// ErrClockBehind: the clock is behind a time Alice already recorded (a stepped-back clock, G14);
	// nothing was done; retryable (reason sshkey.clock_behind).
	ErrClockBehind        = errors.New("sshkeys: the clock is behind an earlier record; try again later")
	ErrPolicyExists       = errors.New("sshkeys: the key already has a rotation policy")
	ErrRotationInProgress = errors.New("sshkeys: a rotation of this key is running")
	ErrPlanChanged        = errors.New("sshkeys: the plan changed since the preview")
	ErrNothingToRotate    = errors.New("sshkeys: no location can change")
	ErrNotWaiting         = errors.New("sshkeys: the rotation is not waiting for this action")
	// ErrNoticePending: Continue before the renewal notice of this pause was queued (the next sweep
	// queues it; reason rotation.notice_pending; Task 9 review I2).
	ErrNoticePending = errors.New("sshkeys: the renewal notice has not been sent yet; try again in a minute")
	// ErrPlanTooLarge: the plan has more locations than a run can hold (reason rotation.plan_too_large).
	ErrPlanTooLarge    = errors.New("sshkeys: the plan has too many locations for one run")
	ErrVersionMismatch = inventory.ErrVersionMismatch
	ErrOwnKeyProtected = inventory.ErrOwnKeyProtected
)

// errUndecryptable: the envelope does not open with this master key (another key, a damaged row).
// It wraps nothing: the keyring's error says nothing either, but the text here is fixed.
var errUndecryptable = errors.New("sshkeys: the private key cannot be decrypted with this master key")
