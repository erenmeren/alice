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
	"alice/internal/license"
	"alice/internal/platform/validate"
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
	ErrNotFound     = ErrorCode{Code: "ALC-SYS-0001", Reason: "system.not_found", Status: http.StatusNotFound}
	ErrUnavailable  = ErrorCode{Code: "ALC-SYS-0002", Reason: "system.unavailable", Status: http.StatusServiceUnavailable, Retryable: true}
	ErrUnexpected   = ErrorCode{Code: "ALC-SYS-0003", Reason: "internal.unexpected", Status: http.StatusInternalServerError}
	ErrBadRequest   = ErrorCode{Code: "ALC-SYS-0004", Reason: "system.bad_request", Status: http.StatusBadRequest}
	ErrRateLimited  = ErrorCode{Code: "ALC-SYS-0005", Reason: "rate.limited", Status: http.StatusTooManyRequests, Retryable: true}
	ErrValidation   = ErrorCode{Code: "ALC-SYS-0006", Reason: "validation.failed", Status: http.StatusUnprocessableEntity}
	ErrBodyTooLarge = ErrorCode{Code: "ALC-SYS-0007", Reason: "system.body_too_large", Status: http.StatusRequestEntityTooLarge}

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
)

// AllErrorCodes lists every registered code; tests check format, uniqueness, translations and docs.
func AllErrorCodes() []ErrorCode {
	return []ErrorCode{
		ErrNotFound, ErrUnavailable, ErrUnexpected, ErrBadRequest, ErrRateLimited, ErrValidation, ErrBodyTooLarge,
		ErrUnauthenticated, ErrForbidden, ErrStepUpRequired, ErrCSRF, ErrInvalidCredentials, ErrMFAInvalid,
		ErrMFAAlreadyEnrolled, ErrPasswordTooShort, ErrPasswordTooLong, ErrPasswordBreached, ErrCurrentPasswordInvalid, ErrTryAgain,
		ErrUsernameTaken, ErrLastAdmin, ErrTokenScopeNotAllowed,
		ErrSetupCodeInvalid, ErrSetupLocked, ErrSetupSessionExpired, ErrSetupEnrollmentMissing,
		ErrPassphraseTooShort, ErrPassphraseMismatch, ErrPassphraseAlreadySet, ErrSetupIncomplete, ErrSetupLicenseChoiceMissing,
		ErrLicenseLocked,
		ErrLicenseInvalid, ErrLicenseWrongInstallation, ErrLicenseUnknownKey, ErrLicenseRevokedKey,
		ErrLicenseUnsupportedFormat, ErrLicenseOlderThanInstalled, ErrLicenseTargetLimit,
	}
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
	for _, m := range errorMap {
		if errors.Is(err, m.err) {
			s.writeErrorWith(w, r, m.code, m.params, nil)
			return
		}
	}
	s.deps.Log.Error("request failed", append([]any{"request_id", RequestID(r.Context()), "path", r.URL.Path}, errorAttrs(err)...)...)
	s.writeError(w, r, ErrUnexpected)
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
