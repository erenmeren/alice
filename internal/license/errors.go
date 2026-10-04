package license

import (
	"errors"
	"fmt"
	"strings"
)

// Errors returned by the license module. The API maps each to a stable ALC-LIC code.
var (
	ErrInvalid               = errors.New("license: not a valid license file")
	ErrUnsupportedFormat     = errors.New("license: the file uses a newer format than this version of Alice supports")
	ErrUnknownKey            = errors.New("license: signed by a key this version of Alice does not know")
	ErrRevokedKey            = errors.New("license: signed by a key that is no longer trusted")
	ErrWrongInstallation     = errors.New("license: issued for another installation")
	ErrOlderThanInstalled    = errors.New("license: a newer license is already installed")
	ErrLocked                = errors.New("license: the license has expired; changes are paused")
	ErrTargetLimit           = errors.New("license: the licensed number of targets is reached")
	ErrUnclassified          = errors.New("license: work without a license class")
	ErrInvalidInstallationID = errors.New("license: installation ID is not valid")
	// ErrUnverified: no evaluation has succeeded for MaxEvaluationAge, or none has run yet
	// (AUD-02). Gated work is refused until one succeeds; errors.Is(ErrUnverified, ErrLocked) is
	// true, so every path that refuses locked work refuses it too. It is not a lock decision:
	// the job runner pauses queued work instead of holding or cancelling it.
	ErrUnverified error = unverifiedError{}
	// ErrLockDue: the gate's own clock (the last evaluation's time advanced by uptime) reached
	// LocksAt, but no evaluation has confirmed the lock yet (AUD-02). Gated work is refused as in
	// lock (errors.Is(ErrLockDue, ErrLocked) is true, the API answers ALC-LIC-0001), but nothing
	// lasting is decided from it: the next evaluation, started at once, confirms or refutes it.
	ErrLockDue error = lockDueError{}
)

// ConfirmedLock reports whether a refusal of the gate is a lock an evaluation decided, on which
// lasting decisions may be taken (holding queued changes for a confirmation, cancelling queued
// read-only work). ErrUnverified and ErrLockDue are refusals without such a decision: the work
// waits and starts by itself once an evaluation allows it.
func ConfirmedLock(err error) bool {
	return errors.Is(err, ErrLocked) && !errors.Is(err, ErrUnverified) && !errors.Is(err, ErrLockDue)
}

// DenialReason is the audit label of a refusal of the gate: "unverified", "lock_due", "locked",
// or "" for an error that is not a refusal of the gate.
func DenialReason(err error) string {
	switch {
	case errors.Is(err, ErrUnverified):
		return "unverified"
	case errors.Is(err, ErrLockDue):
		return "lock_due"
	case errors.Is(err, ErrLocked):
		return "locked"
	}
	return ""
}

// lockDueError is ErrLockDue: it matches ErrLocked, with its own message.
type lockDueError struct{}

func (lockDueError) Error() string {
	return "license: the license reached its lock time; changes are paused until the next check confirms it"
}

// Is makes ErrLockDue match ErrLocked.
func (lockDueError) Is(target error) bool { return target == ErrLocked }

// unverifiedError is ErrUnverified: it matches ErrLocked, with its own message.
type unverifiedError struct{}

func (unverifiedError) Error() string {
	return "license: the license could not be checked recently; changes are paused"
}

// Is makes ErrUnverified match ErrLocked.
func (unverifiedError) Is(target error) bool { return target == ErrLocked }

// InvalidError says why a file is not a valid license. Problem is a fixed label
// for logs and the audit trail; it never contains file content.
type InvalidError struct{ Problem string }

func (e *InvalidError) Error() string { return "license: not a valid license file (" + e.Problem + ")" }

// Is makes every InvalidError match ErrInvalid.
func (e *InvalidError) Is(target error) bool { return target == ErrInvalid }

func invalid(problem string) error { return &InvalidError{Problem: problem} }

// WrongInstallationError is returned for a license made for another installation.
// Expected and Got are the last six characters of the two IDs (L-43).
type WrongInstallationError struct{ Expected, Got string }

func (e *WrongInstallationError) Error() string {
	return fmt.Sprintf("license: issued for installation …%s, this is …%s", e.Got, e.Expected)
}

// Is makes every WrongInstallationError match ErrWrongInstallation.
func (e *WrongInstallationError) Is(target error) bool { return target == ErrWrongInstallation }

// TargetLimitError is returned when adding a target would exceed the license (L-71).
type TargetLimitError struct{ Max, Used int }

func (e *TargetLimitError) Error() string {
	return fmt.Sprintf("license: %d of %d licensed targets are in use", e.Used, e.Max)
}

// Is makes every TargetLimitError match ErrTargetLimit.
func (e *TargetLimitError) Is(target error) bool { return target == ErrTargetLimit }

// IDSuffix returns the last six characters of an installation ID, not counting the group
// separators (shown in messages so an administrator can compare IDs without reading the
// whole value aloud, L-43).
func IDSuffix(id string) string {
	id = strings.ReplaceAll(id, "-", "")
	if len(id) <= 6 {
		return id
	}
	return id[len(id)-6:]
}

// RejectReason is the audit label of a refused upload: the audit action is
// "license.upload." + RejectReason(err) (spec L-40: license.upload.invalid_signature).
func RejectReason(err error) string {
	var inv *InvalidError
	switch {
	case errors.As(err, &inv) && inv.Problem == "signature":
		return "invalid_signature"
	case errors.Is(err, ErrInvalid):
		return "invalid"
	case errors.Is(err, ErrUnsupportedFormat):
		return "unsupported_format"
	case errors.Is(err, ErrUnknownKey):
		return "unknown_key"
	case errors.Is(err, ErrRevokedKey):
		return "revoked_key"
	case errors.Is(err, ErrWrongInstallation):
		return "wrong_installation"
	case errors.Is(err, ErrOlderThanInstalled):
		return "older_than_installed"
	default:
		return "error"
	}
}
