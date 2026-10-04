package providers

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"

	"alice/internal/platform/azureid"
)

// ImportCertificate returns an ImportResult together with an error as follows (CheckImportReturn):
//
//	created    the vault answered with the new version: Version, Thumbprint and CER set; nil error
//	refused    nothing was created: no Version, Thumbprint or CER; a *Error that is a well-formed
//	           refusal (refused before anything was sent, or a complete answer of the vault that
//	           says no), never a transport failure
//	uncertain  the request may have reached the vault (a timeout, a lost connection, a cancelled
//	           request, an unparsable or truncated answer, an unexpected status): no Version,
//	           Thumbprint or CER; a non-nil error saying why
//
// Any other Outcome, including "", and ErrUnsupported are invalid. "refused" is the only word for
// "nothing changed": the vault has no idempotency key, so an import whose answer was lost is
// never re-sent and never reported as refused (R40 row 25). The transport-error check in
// CheckImportReturn is a floor, not a proof: a provider classifies by positive evidence, and only
// a refusal before anything was sent or a complete, parsed 4xx answer that carries an Azure error
// code is "refused"; everything else is "uncertain"; a caller treats any violation of these
// rules as uncertain and reads the truth from a later listing.

// Validate checks ImportResult's invariants: created carries a valid version, a valid thumbprint
// that is the SHA-1 of the leaf, and the leaf; refused and uncertain carry none of them; any other outcome is invalid.
func (r ImportResult) Validate() error {
	switch r.Outcome {
	case ImportCreated:
		if !azureid.ValidVersion(r.Version) || !azureid.ValidThumbprint(r.Thumbprint) || len(r.CER) == 0 {
			return errors.New("providers: import result: created needs a version, a thumbprint and the leaf")
		}
		if azureid.ThumbprintOf(r.CER) != r.Thumbprint {
			return errors.New("providers: import result: created: the thumbprint is not the leaf's")
		}
	case ImportRefused, ImportUncertain:
		if r.Version != "" || r.Thumbprint != "" || len(r.CER) > 0 {
			return fmt.Errorf("providers: import result: %s carries no version, thumbprint or leaf", r.Outcome)
		}
	default:
		return fmt.Errorf("providers: import result: blank or unknown outcome %q", orBlank(r.Outcome))
	}
	return nil
}

// transportFailure reports an error chain that says the request may have been sent: a context
// that ended, a network error or a connection that closed in the middle of an answer. An import
// that failed this way is uncertain, whatever code the provider put on it.
func transportFailure(err error) bool {
	var ne net.Error
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.As(err, &ne)
}

// CheckImportReturn checks what ImportCertificate returned: Validate, then created with a nil
// error, refused with a *Error that is no transport failure (nothing was created), uncertain with
// a non-nil error. A caller treats any violation as uncertain: the request may have reached the
// vault (R40 row 25).
func CheckImportReturn(r ImportResult, err error) error {
	if errors.Is(err, ErrUnsupported) {
		return errors.New("providers: import: ErrUnsupported is not an outcome")
	}
	if verr := r.Validate(); verr != nil {
		return verr
	}
	switch {
	case r.Outcome == ImportCreated && err != nil:
		return errors.New("providers: import: created with an error")
	case r.Outcome == ImportRefused && !isProviderError(err):
		return errors.New("providers: import: refused needs a *providers.Error")
	case r.Outcome == ImportRefused && transportFailure(err):
		return errors.New("providers: import: refused by a transport failure: the request may have reached the vault, so it is uncertain")
	case r.Outcome == ImportUncertain && err == nil:
		return errors.New("providers: import: uncertain without an error")
	}
	return nil
}
