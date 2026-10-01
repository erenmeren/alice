package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"alice/internal/auth"
	"alice/internal/inventory"
	"alice/internal/jobs"
	"alice/internal/license"
	"alice/internal/platform/validate"
	"alice/internal/providers"
	"alice/internal/setup"
)

// ErrorCode is a stable, documented API error. Codes are never reused.
type ErrorCode struct {
	Code      string
	Reason    string
	Status    int
	Retryable bool
}

var (
	ErrNotFound           = ErrorCode{Code: "ALC-SYS-0001", Reason: "system.not_found", Status: http.StatusNotFound}
	ErrUnavailable        = ErrorCode{Code: "ALC-SYS-0002", Reason: "system.unavailable", Status: http.StatusServiceUnavailable, Retryable: true}
	ErrUnexpected         = ErrorCode{Code: "ALC-SYS-0003", Reason: "internal.unexpected", Status: http.StatusInternalServerError}
	ErrBadRequest         = ErrorCode{Code: "ALC-SYS-0004", Reason: "system.bad_request", Status: http.StatusBadRequest}
	ErrRateLimited        = ErrorCode{Code: "ALC-SYS-0005", Reason: "rate.limited", Status: http.StatusTooManyRequests, Retryable: true}
	ErrValidation         = ErrorCode{Code: "ALC-SYS-0006", Reason: "validation.failed", Status: http.StatusUnprocessableEntity}
	ErrBodyTooLarge       = ErrorCode{Code: "ALC-SYS-0007", Reason: "system.body_too_large", Status: http.StatusRequestEntityTooLarge}
	ErrPreconditionFailed = ErrorCode{Code: "ALC-SYS-0008", Reason: "system.precondition_failed", Status: http.StatusPreconditionFailed}

	ErrUnauthenticated        = ErrorCode{Code: "ALC-AUTH-0001", Reason: "auth.unauthenticated", Status: http.StatusUnauthorized}
	ErrForbidden              = ErrorCode{Code: "ALC-AUTH-0002", Reason: "auth.forbidden", Status: http.StatusForbidden}
	ErrStepUpRequired         = ErrorCode{Code: "ALC-AUTH-0003", Reason: "auth.stepup_required", Status: http.StatusForbidden}
	ErrCSRF                   = ErrorCode{Code: "ALC-AUTH-0004", Reason: "auth.csrf_failed", Status: http.StatusForbidden}
	ErrInvalidCredentials     = ErrorCode{Code: "ALC-AUTH-0005", Reason: "auth.invalid_credentials", Status: http.StatusUnauthorized}
	ErrMFAInvalid             = ErrorCode{Code: "ALC-AUTH-0006", Reason: "auth.mfa_invalid", Status: http.StatusUnauthorized}
	ErrMFAAlreadyEnrolled     = ErrorCode{Code: "ALC-AUTH-0007", Reason: "auth.mfa_already_enrolled", Status: http.StatusConflict}
	ErrPasswordTooShort       = ErrorCode{Code: "ALC-AUTH-0008", Reason: "auth.password_too_short", Status: http.StatusUnprocessableEntity}
	ErrPasswordTooLong        = ErrorCode{Code: "ALC-AUTH-0009", Reason: "auth.password_too_long", Status: http.StatusUnprocessableEntity}
	ErrPasswordBreached       = ErrorCode{Code: "ALC-AUTH-0010", Reason: "auth.password_breached", Status: http.StatusUnprocessableEntity}
	ErrCurrentPasswordInvalid = ErrorCode{Code: "ALC-AUTH-0011", Reason: "auth.current_password_invalid", Status: http.StatusUnprocessableEntity}
	ErrTryAgain               = ErrorCode{Code: "ALC-AUTH-0012", Reason: "auth.try_again", Status: http.StatusServiceUnavailable, Retryable: true}

	ErrUsernameTaken        = ErrorCode{Code: "ALC-USR-0001", Reason: "user.username_taken", Status: http.StatusConflict}
	ErrLastAdmin            = ErrorCode{Code: "ALC-USR-0002", Reason: "user.last_admin", Status: http.StatusConflict}
	ErrTokenScopeNotAllowed = ErrorCode{Code: "ALC-TOK-0001", Reason: "token.scope_not_allowed", Status: http.StatusUnprocessableEntity}

	ErrSetupCodeInvalid          = ErrorCode{Code: "ALC-SET-0001", Reason: "setup.code_invalid", Status: http.StatusUnauthorized}
	ErrSetupLocked               = ErrorCode{Code: "ALC-SET-0002", Reason: "setup.locked", Status: http.StatusTooManyRequests, Retryable: true}
	ErrSetupSessionExpired       = ErrorCode{Code: "ALC-SET-0003", Reason: "setup.session_expired", Status: http.StatusUnauthorized}
	ErrSetupEnrollmentMissing    = ErrorCode{Code: "ALC-SET-0004", Reason: "setup.enrollment_missing", Status: http.StatusConflict}
	ErrPassphraseTooShort        = ErrorCode{Code: "ALC-SET-0005", Reason: "setup.passphrase_too_short", Status: http.StatusUnprocessableEntity}
	ErrPassphraseMismatch        = ErrorCode{Code: "ALC-SET-0006", Reason: "setup.passphrase_mismatch", Status: http.StatusUnprocessableEntity}
	ErrPassphraseAlreadySet      = ErrorCode{Code: "ALC-SET-0007", Reason: "setup.passphrase_already_set", Status: http.StatusConflict}
	ErrSetupIncomplete           = ErrorCode{Code: "ALC-SET-0008", Reason: "setup.incomplete", Status: http.StatusConflict}
	ErrSetupLicenseChoiceMissing = ErrorCode{Code: "ALC-SET-0009", Reason: "setup.license_choice_missing", Status: http.StatusConflict}

	ErrLicenseLocked             = ErrorCode{Code: "ALC-LIC-0001", Reason: "license.locked", Status: http.StatusForbidden}
	ErrLicenseInvalid            = ErrorCode{Code: "ALC-LIC-0002", Reason: "license.invalid", Status: http.StatusUnprocessableEntity}
	ErrLicenseWrongInstallation  = ErrorCode{Code: "ALC-LIC-0003", Reason: "license.wrong_installation", Status: http.StatusUnprocessableEntity}
	ErrLicenseUnknownKey         = ErrorCode{Code: "ALC-LIC-0004", Reason: "license.unknown_key", Status: http.StatusUnprocessableEntity}
	ErrLicenseRevokedKey         = ErrorCode{Code: "ALC-LIC-0005", Reason: "license.revoked_key", Status: http.StatusUnprocessableEntity}
	ErrLicenseUnsupportedFormat  = ErrorCode{Code: "ALC-LIC-0006", Reason: "license.unsupported_format", Status: http.StatusUnprocessableEntity}
	ErrLicenseOlderThanInstalled = ErrorCode{Code: "ALC-LIC-0007", Reason: "license.older_than_installed", Status: http.StatusConflict}
	ErrLicenseTargetLimit        = ErrorCode{Code: "ALC-LIC-0008", Reason: "license.target_limit_reached", Status: http.StatusConflict}

	// Phase 3: servers, SSH, keys and jobs (R37). The SSH and job reasons are mostly carried by job
	// records and target statuses; the API answers with them when a request fails for that reason.
	ErrTargetDuplicate    = ErrorCode{Code: "ALC-TGT-0001", Reason: "target.duplicate", Status: http.StatusConflict}
	ErrHostKeyUnconfirmed = ErrorCode{Code: "ALC-TGT-0002", Reason: "target.host_key_unconfirmed", Status: http.StatusConflict}
	ErrHostKeyStale       = ErrorCode{Code: "ALC-TGT-0003", Reason: "target.host_key_stale", Status: http.StatusConflict}
	ErrHostKeyChanged     = ErrorCode{Code: "ALC-TGT-0004", Reason: "target.host_key_changed", Status: http.StatusConflict}
	ErrHostKeyState       = ErrorCode{Code: "ALC-TGT-0005", Reason: "target.host_key_state", Status: http.StatusConflict}
	ErrTargetDisabled     = ErrorCode{Code: "ALC-TGT-0006", Reason: "target.disabled", Status: http.StatusConflict}

	ErrSSHUnreachable       = ErrorCode{Code: "ALC-SSH-0001", Reason: "ssh.unreachable", Status: http.StatusBadGateway, Retryable: true}
	ErrSSHAuthFailed        = ErrorCode{Code: "ALC-SSH-0002", Reason: "ssh.auth_failed", Status: http.StatusBadGateway}
	ErrSSHTimeout           = ErrorCode{Code: "ALC-SSH-0003", Reason: "ssh.timeout", Status: http.StatusGatewayTimeout, Retryable: true}
	ErrHelperMissing        = ErrorCode{Code: "ALC-SSH-0004", Reason: "ssh.helper_missing", Status: http.StatusBadGateway}
	ErrHelperOutdated       = ErrorCode{Code: "ALC-SSH-0005", Reason: "ssh.helper_outdated", Status: http.StatusBadGateway}
	ErrHelperRefused        = ErrorCode{Code: "ALC-SSH-0006", Reason: "ssh.helper_refused", Status: http.StatusBadGateway}
	ErrFileChanged          = ErrorCode{Code: "ALC-SSH-0007", Reason: "ssh.file_changed", Status: http.StatusConflict, Retryable: true}
	ErrKeysManagedElsewhere = ErrorCode{Code: "ALC-SSH-0008", Reason: "ssh.keys_managed_elsewhere", Status: http.StatusConflict}
	ErrOutputTooLarge       = ErrorCode{Code: "ALC-SSH-0009", Reason: "ssh.output_too_large", Status: http.StatusBadGateway}
	ErrSSHProtocol          = ErrorCode{Code: "ALC-SSH-0010", Reason: "ssh.protocol_error", Status: http.StatusBadGateway}

	ErrOwnKeyProtected = ErrorCode{Code: "ALC-KEY-0001", Reason: "sshkey.own_key_protected", Status: http.StatusConflict}
	ErrLastRootKey     = ErrorCode{Code: "ALC-KEY-0002", Reason: "sshkey.last_root_key", Status: http.StatusConflict}
	ErrKeyNotRemovable = ErrorCode{Code: "ALC-KEY-0003", Reason: "sshkey.not_removable", Status: http.StatusConflict}
	ErrSSHDUnreadable  = ErrorCode{Code: "ALC-KEY-0004", Reason: "sshkey.sshd_unreadable", Status: http.StatusConflict}
	ErrKeyVerifyFailed = ErrorCode{Code: "ALC-KEY-0005", Reason: "sshkey.verify_failed", Status: http.StatusBadGateway}

	ErrJobNotWaiting   = ErrorCode{Code: "ALC-JOB-0001", Reason: "job.not_waiting", Status: http.StatusConflict}
	ErrJobLeaseExpired = ErrorCode{Code: "ALC-JOB-0002", Reason: "job.lease_expired", Status: http.StatusInternalServerError, Retryable: true}
	ErrJobTampered     = ErrorCode{Code: "ALC-JOB-0003", Reason: "job.tampered", Status: http.StatusInternalServerError}
	ErrJobUnknownType  = ErrorCode{Code: "ALC-JOB-0004", Reason: "job.unknown_type", Status: http.StatusInternalServerError}
	ErrJobConflict     = ErrorCode{Code: "ALC-JOB-0005", Reason: "job.conflict", Status: http.StatusConflict}
)

// AllErrorCodes lists every registered code; tests check format, uniqueness, translations and docs.
func AllErrorCodes() []ErrorCode {
	return []ErrorCode{
		ErrNotFound, ErrUnavailable, ErrUnexpected, ErrBadRequest, ErrRateLimited, ErrValidation, ErrBodyTooLarge, ErrPreconditionFailed,
		ErrUnauthenticated, ErrForbidden, ErrStepUpRequired, ErrCSRF, ErrInvalidCredentials, ErrMFAInvalid,
		ErrMFAAlreadyEnrolled, ErrPasswordTooShort, ErrPasswordTooLong, ErrPasswordBreached, ErrCurrentPasswordInvalid, ErrTryAgain,
		ErrUsernameTaken, ErrLastAdmin, ErrTokenScopeNotAllowed,
		ErrSetupCodeInvalid, ErrSetupLocked, ErrSetupSessionExpired, ErrSetupEnrollmentMissing,
		ErrPassphraseTooShort, ErrPassphraseMismatch, ErrPassphraseAlreadySet, ErrSetupIncomplete, ErrSetupLicenseChoiceMissing,
		ErrLicenseLocked,
		ErrLicenseInvalid, ErrLicenseWrongInstallation, ErrLicenseUnknownKey, ErrLicenseRevokedKey,
		ErrLicenseUnsupportedFormat, ErrLicenseOlderThanInstalled, ErrLicenseTargetLimit,
		ErrTargetDuplicate, ErrHostKeyUnconfirmed, ErrHostKeyStale, ErrHostKeyChanged, ErrHostKeyState, ErrTargetDisabled,
		ErrSSHUnreachable, ErrSSHAuthFailed, ErrSSHTimeout, ErrHelperMissing, ErrHelperOutdated, ErrHelperRefused,
		ErrFileChanged, ErrKeysManagedElsewhere, ErrOutputTooLarge, ErrSSHProtocol,
		ErrOwnKeyProtected, ErrLastRootKey, ErrKeyNotRemovable, ErrSSHDUnreadable, ErrKeyVerifyFailed,
		ErrJobNotWaiting, ErrJobLeaseExpired, ErrJobTampered, ErrJobUnknownType, ErrJobConflict,
	}
}

// codeForReason returns the registered code of a stable reason (job records and target statuses
// store reasons). An unknown reason is ErrUnexpected, so a client always gets a documented code.
func codeForReason(reason string) ErrorCode {
	for _, ec := range AllErrorCodes() {
		if ec.Reason == reason {
			return ec
		}
	}
	return ErrUnexpected
}

// errorMap translates domain errors into API codes. Order matters only for
// errors that wrap each other; none of these do.
var errorMap = []struct {
	err    error
	code   ErrorCode
	params map[string]string
}{
	{auth.ErrNotFound, ErrNotFound, nil},
	{auth.ErrUnauthenticated, ErrUnauthenticated, nil},
	{auth.ErrInvalidCredentials, ErrInvalidCredentials, nil},
	{auth.ErrMFAInvalid, ErrMFAInvalid, nil},
	{auth.ErrMFAAlreadyEnrolled, ErrMFAAlreadyEnrolled, nil},
	{auth.ErrPasswordTooShort, ErrPasswordTooShort, map[string]string{"min": strconv.Itoa(auth.MinPasswordLength)}},
	{auth.ErrPasswordTooLong, ErrPasswordTooLong, map[string]string{"max": strconv.Itoa(auth.MaxPasswordLength)}},
	{auth.ErrPasswordBreached, ErrPasswordBreached, nil},
	{auth.ErrCurrentPasswordInvalid, ErrCurrentPasswordInvalid, nil},
	{auth.ErrUsernameTaken, ErrUsernameTaken, nil},
	{auth.ErrLastAdmin, ErrLastAdmin, nil},
	{auth.ErrTokenScopeNotAllowed, ErrTokenScopeNotAllowed, nil},
	{setup.ErrAlreadySetUp, ErrNotFound, nil},
	{setup.ErrCodeInvalid, ErrSetupCodeInvalid, nil},
	{setup.ErrSessionInvalid, ErrSetupSessionExpired, nil},
	{setup.ErrEnrollmentMissing, ErrSetupEnrollmentMissing, nil},
	{setup.ErrPassphraseTooShort, ErrPassphraseTooShort, map[string]string{"min": strconv.Itoa(setup.MinPassphraseLength)}},
	{setup.ErrPassphraseMismatch, ErrPassphraseMismatch, nil},
	{setup.ErrPassphraseAlreadySet, ErrPassphraseAlreadySet, nil},
	{setup.ErrIncomplete, ErrSetupIncomplete, nil},
	{setup.ErrLicenseChoiceMissing, ErrSetupLicenseChoiceMissing, nil},
	{setup.ErrForbidden, ErrForbidden, nil},
	{license.ErrInvalid, ErrLicenseInvalid, nil},
	{license.ErrUnknownKey, ErrLicenseUnknownKey, nil},
	{license.ErrRevokedKey, ErrLicenseRevokedKey, nil},
	{license.ErrUnsupportedFormat, ErrLicenseUnsupportedFormat, nil},
	{license.ErrOlderThanInstalled, ErrLicenseOlderThanInstalled, nil},
	{license.ErrLocked, ErrLicenseLocked, nil},
	// The typed errors (*TargetLimitError, *WrongInstallationError) are matched above with their
	// params; a bare sentinel still gets its own code instead of a 500.
	{license.ErrTargetLimit, ErrLicenseTargetLimit, nil},
	{license.ErrWrongInstallation, ErrLicenseWrongInstallation, nil},
	{license.ErrNoInstallation, ErrUnavailable, nil},
	{inventory.ErrNotFound, ErrNotFound, nil},
	{inventory.ErrNoPlatformKey, ErrUnavailable, nil}, // EnsurePlatformKey runs before serving; only a broken start reaches this
	{inventory.ErrDuplicateTarget, ErrTargetDuplicate, nil},
	{inventory.ErrVersionMismatch, ErrPreconditionFailed, nil},
	{inventory.ErrHostKeyUnconfirmed, ErrHostKeyUnconfirmed, nil},
	{inventory.ErrHostKeyStale, ErrHostKeyStale, nil},
	{inventory.ErrHostKeyChanged, ErrHostKeyChanged, nil},
	{inventory.ErrHostKeyState, ErrHostKeyState, nil},
	{inventory.ErrOwnKeyProtected, ErrOwnKeyProtected, nil},
	{inventory.ErrLastRootKey, ErrLastRootKey, nil},
	{inventory.ErrNotRemovable, ErrKeyNotRemovable, nil},
	{inventory.ErrKeysManagedElsewhere, ErrKeysManagedElsewhere, nil},
	{inventory.ErrSSHDUnreadable, ErrSSHDUnreadable, nil},
	{inventory.ErrJobConflict, ErrJobConflict, nil},
	{jobs.ErrNotFound, ErrNotFound, nil},
	{jobs.ErrNotWaiting, ErrJobNotWaiting, nil},
	{jobs.ErrBadCursor, ErrBadRequest, nil}, // a cursor that does not decode
	{jobs.ErrUnknownType, ErrJobUnknownType, nil},
}

type errorPayload struct {
	Code       string                `json:"code"`
	Reason     string                `json:"reason"`
	MessageKey string                `json:"message_key"`
	Message    string                `json:"message"`
	RequestID  string                `json:"request_id"`
	Retryable  bool                  `json:"retryable"`
	Params     map[string]string     `json:"params,omitempty"`
	Details    []validate.FieldError `json:"details,omitempty"`
}

func (s *server) writeError(w http.ResponseWriter, r *http.Request, ec ErrorCode) {
	s.writeErrorWith(w, r, ec, nil, nil)
}

// writeErrorWith writes the error body of spec §9.3. message is the fallback
// text in the request language; clients render message_key with params.
func (s *server) writeErrorWith(w http.ResponseWriter, r *http.Request, ec ErrorCode, params map[string]string, details []validate.FieldError) {
	lang := s.deps.Catalog.Negotiate(r.Header.Get("Accept-Language"))
	key := "errors." + ec.Reason
	msg := s.deps.Catalog.T(lang, key+".title", params) + " " + s.deps.Catalog.T(lang, key+".action", params)
	writeJSON(w, ec.Status, map[string]errorPayload{"error": {
		Code:       ec.Code,
		Reason:     ec.Reason,
		MessageKey: key,
		Message:    msg,
		RequestID:  RequestID(r.Context()),
		Retryable:  ec.Retryable,
		Params:     params,
		Details:    details,
	}})
}

// fail maps a service error to its API error. Unknown errors are logged with
// the request ID and answered with a generic 500 (SEC-052).
func (s *server) fail(w http.ResponseWriter, r *http.Request, err error) {
	var verrs validate.Errors
	if errors.As(err, &verrs) {
		s.writeErrorWith(w, r, ErrValidation, nil, verrs)
		return
	}
	var locked *setup.LockedError
	if errors.As(err, &locked) {
		secs := int(locked.RetryAfter.Round(time.Second) / time.Second)
		w.Header().Set("Retry-After", strconv.Itoa(max(1, secs)))
		s.writeError(w, r, ErrSetupLocked)
		return
	}
	if errors.Is(err, auth.ErrTryAgain) {
		// The account lock was busy; nothing was verified or counted (auth.ErrTryAgain).
		w.Header().Set("Retry-After", "1")
		s.writeError(w, r, ErrTryAgain)
		return
	}
	var wrong *license.WrongInstallationError
	if errors.As(err, &wrong) {
		// Only the six-character ID suffixes, never file content (L-43).
		s.writeErrorWith(w, r, ErrLicenseWrongInstallation, map[string]string{"expected": wrong.Expected, "got": wrong.Got}, nil)
		return
	}
	var limit *license.TargetLimitError
	if errors.As(err, &limit) {
		s.writeErrorWith(w, r, ErrLicenseTargetLimit, map[string]string{"used": strconv.Itoa(limit.Used), "max": strconv.Itoa(limit.Max)}, nil)
		return
	}
	var perr *providers.Error
	if errors.As(err, &perr) {
		// Only the stable reason and its allowlisted primitive params reach the client; the
		// provider's cause (remote output, driver text) is never shown nor logged as text.
		if ec := codeForReason(perr.Code); ec != ErrUnexpected {
			s.writeErrorWith(w, r, ec, providerParams(perr.Params), nil)
			return
		}
	}
	for _, m := range errorMap {
		if errors.Is(err, m.err) {
			s.writeErrorWith(w, r, m.code, m.params, nil)
			return
		}
	}
	s.deps.Log.Error("request failed", append([]any{"request_id", RequestID(r.Context()), "path", r.URL.Path}, errorAttrs(err)...)...)
	s.writeError(w, r, ErrUnexpected)
}

// providerParamKeys are the provider error params a client may see: fixed labels, numbers and
// fingerprints (which are not secret). Any other key is dropped, so a provider that ever puts
// remote text or a key line into its params cannot leak it through the API.
var providerParamKeys = map[string]bool{
	"helper_code": true, "subcommand": true, "exit_code": true, "reason": true, "field": true, "attempts": true,
	"wait": true, "fingerprint": true, "old_fingerprint": true, "new_fingerprint": true,
}

// providerParams returns the allowlisted params of a provider error (nil when none remain).
func providerParams(in map[string]string) map[string]string {
	var out map[string]string
	for k, v := range in {
		if providerParamKeys[k] {
			if out == nil {
				out = map[string]string{}
			}
			out[k] = v
		}
	}
	return out
}

// errorAttrs describes err for the logs with fixed labels only: the type of
// the innermost error and, for database errors, the SQLSTATE. The error text
// is never logged, because driver messages and wrapped errors can carry column
// values such as password or token hashes (SEC-052).
func errorAttrs(err error) []any {
	inner := err
	for {
		next := errors.Unwrap(inner)
		if next == nil {
			break
		}
		inner = next
	}
	attrs := []any{"error_type", fmt.Sprintf("%T", inner)}
	var db interface{ SQLState() string }
	if errors.As(err, &db) {
		attrs = append(attrs, "sqlstate", db.SQLState())
	}
	switch {
	case errors.Is(err, context.Canceled):
		attrs = append(attrs, "cause", "canceled")
	case errors.Is(err, context.DeadlineExceeded):
		attrs = append(attrs, "cause", "deadline_exceeded")
	}
	return attrs
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
