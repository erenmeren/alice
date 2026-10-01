package jobs

import (
	"errors"

	"alice/internal/providers"
)

// FailureClass says what the runner does with a failed job (spec §8.4).
type FailureClass int

// Failure classes.
const (
	// Retryable failures run again after Backoff until MaxAttempts, then the job is dead.
	Retryable FailureClass = iota
	// Permanent failures (authentication failed, host key changed) never retry.
	Permanent
	// NeedsAttention failures stop and are flagged for a person.
	NeedsAttention
)

// Failure is a classified job error. Reason is a stable reason ("ssh.auth_failed") that the
// API maps to an ALC code; Params are shown with it. Cause is kept for errors.Is/As and its
// type for the logs; its text is never stored, logged or shown.
type Failure struct {
	Class  FailureClass
	Reason string
	Params map[string]string
	Cause  error
}

// Error names the reason only: the cause's text may carry remote output or values.
func (f *Failure) Error() string { return "jobs: " + f.Reason }

// Unwrap returns the cause.
func (f *Failure) Unwrap() error { return f.Cause }

// Retry is a failure that may succeed later.
func Retry(reason string, params map[string]string, cause error) error {
	return &Failure{Class: Retryable, Reason: reason, Params: params, Cause: cause}
}

// Fail is a failure that never succeeds by trying again.
func Fail(reason string, params map[string]string, cause error) error {
	return &Failure{Class: Permanent, Reason: reason, Params: params, Cause: cause}
}

// Attention is a failure a person must look at.
func Attention(reason string, params map[string]string, cause error) error {
	return &Failure{Class: NeedsAttention, Reason: reason, Params: params, Cause: cause}
}

// FromProvider classifies err: a *Failure passes through, a *providers.Error keeps its code
// and params (retryable or permanent as the provider says), anything else is an unexpected,
// retryable failure.
func FromProvider(err error) error {
	if err == nil {
		return nil
	}
	var f *Failure
	if errors.As(err, &f) {
		return f
	}
	var pe *providers.Error
	if errors.As(err, &pe) {
		if pe.Retryable {
			return Retry(pe.Code, pe.Params, err)
		}
		return Fail(pe.Code, pe.Params, err)
	}
	return Retry("internal.unexpected", nil, err)
}

// classify turns any handler error into a *Failure.
func classify(err error) *Failure {
	var f *Failure
	if errors.As(FromProvider(err), &f) {
		return f
	}
	return &Failure{Class: Retryable, Reason: "internal.unexpected", Cause: err}
}
