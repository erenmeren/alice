package providers

import "errors"

// ErrUnsupported is returned by sessions for capabilities the provider does not have.
var ErrUnsupported = errors.New("providers: operation not supported by this provider")

// Error is the only error type providers return (spec §6.3 item 5). Code is a stable reason
// ("ssh.auth_failed"); the API maps it to an ALC code. Cause is kept for errors.Is and for logs
// (its type only) and is never part of the message, because SDK and SSH errors can echo
// remote output or secrets.
type Error struct {
	Code      string
	Params    map[string]string
	Retryable bool
	Cause     error
}

// Error returns "providers: <code>", never the cause's text.
func (e *Error) Error() string { return "providers: " + e.Code }

// Unwrap returns the cause.
func (e *Error) Unwrap() error { return e.Cause }

// NewError builds an Error; params are never nil.
func NewError(code string, retryable bool, cause error, params map[string]string) *Error {
	if params == nil {
		params = map[string]string{}
	}
	return &Error{Code: code, Params: params, Retryable: retryable, Cause: cause}
}
