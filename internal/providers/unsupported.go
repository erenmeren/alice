package providers

import (
	"context"

	"github.com/google/uuid"
)

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

// DeployCertificate is not supported.
func (UnsupportedSession) DeployCertificate(context.Context, DeployRequest, StepLogger) (DeployOutcome, error) {
	return DeployOutcome{}, ErrUnsupported
}

// RollbackDeployment is not supported.
func (UnsupportedSession) RollbackDeployment(context.Context, RollbackRequest, StepLogger) (RollbackOutcome, error) {
	return RollbackOutcome{}, ErrUnsupported
}

// VerifyDeployment is not supported.
func (UnsupportedSession) VerifyDeployment(context.Context, VerifyRequest) (VerifyResult, error) {
	return VerifyResult{}, ErrUnsupported
}

// DeploymentStatus is not supported.
func (UnsupportedSession) DeploymentStatus(context.Context, uuid.UUID) (DeploymentState, error) {
	return DeploymentState{}, ErrUnsupported
}

var _ Session = UnsupportedSession{}
