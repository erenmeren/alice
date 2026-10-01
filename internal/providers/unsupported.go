package providers

import "context"

// UnsupportedSession answers ErrUnsupported for every operation; providers embed it and
// implement only what they advertise.
type UnsupportedSession struct{}

// Close does nothing.
func (UnsupportedSession) Close() error { return nil }

// TestConnection is not supported.
func (UnsupportedSession) TestConnection(context.Context) (ConnectionReport, error) {
	return ConnectionReport{}, ErrUnsupported
}

// Discover is not supported.
func (UnsupportedSession) Discover(context.Context, DiscoverRequest) (DiscoveryResult, error) {
	return DiscoveryResult{}, ErrUnsupported
}

// ListAuthorizedKeys is not supported.
func (UnsupportedSession) ListAuthorizedKeys(context.Context) ([]DiscoveredSSHKey, error) {
	return nil, ErrUnsupported
}

// AddAuthorizedKey is not supported.
func (UnsupportedSession) AddAuthorizedKey(context.Context, AuthKeyChange, StepLogger) (AuthKeyResult, error) {
	return AuthKeyResult{}, ErrUnsupported
}

// RemoveAuthorizedKey is not supported.
func (UnsupportedSession) RemoveAuthorizedKey(context.Context, AuthKeyChange, StepLogger) (AuthKeyResult, error) {
	return AuthKeyResult{}, ErrUnsupported
}

var _ Session = UnsupportedSession{}
