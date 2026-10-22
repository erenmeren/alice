package windows

import (
	"context"
	"slices"

	"github.com/google/uuid"

	"alice/internal/providers"
	"alice/internal/providers/windows/winproto"
)

// DeploymentStatus reads an operation's journal on the server (iis-status, on a connection of its
// own). The answer is checked against the helper's vocabulary and DeploymentState.Validate; one that
// breaks them is an ssh.protocol_error, never a state. A Windows state names no backup directory (the
// previous certificate stays in its store, W2 Ruling 17). Any refusal (a W1 helper's UNKNOWN_SUBCOMMAND
// among them: windows.helper_outdated, W2 Ruling 3) is an error that proves nothing about the
// operation; the engine's recovery waits.
func (s *session) DeploymentStatus(ctx context.Context, op uuid.UUID) (providers.DeploymentState, error) {
	return s.stateCall(ctx, winproto.SubIISStatus, op)
}

// FenceDeployment fences an operation on the server (iis-fence, AUD-05): under the helper's lock an
// operation without a journal, or with a prepared one, gets a tombstone, after which iis-deploy of it
// refuses (FENCED) without writing. The answer is checked like iis-status's. Only PhaseFenced with a
// nil error proves that the operation wrote nothing and never will; any error (transport, BUSY, a W1
// helper, a protocol error) proves nothing.
func (s *session) FenceDeployment(ctx context.Context, op uuid.UUID) (providers.DeploymentState, error) {
	st, err := s.stateCall(ctx, winproto.SubIISFence, op)
	if err == nil && st.Active && st.Phase == providers.PhaseFenced {
		return providers.DeploymentState{}, protocolError(winproto.SubIISFence, "a fence answered while another helper held the lock")
	}
	return st, err
}

// stateCall runs iis-status or iis-fence and checks the answer (see DeploymentStatus).
func (s *session) stateCall(ctx context.Context, sub string, op uuid.UUID) (providers.DeploymentState, error) {
	if !s.caps.Has(providers.CapDeployCertificate) {
		return providers.DeploymentState{}, providers.ErrUnsupported
	}
	if err := s.open(); err != nil {
		return providers.DeploymentState{}, err
	}
	if err := s.writeReady(); err != nil {
		return providers.DeploymentState{}, err
	}
	r, _, err := call[winproto.StatusResponse](ctx, s, sub, winproto.ArgOp, op.String())
	if err != nil {
		return providers.DeploymentState{}, err
	}
	fields := []string{r.FailedStep, r.CauseStep, r.Error, r.NewCertSHA256, r.CurrentCertSHA256}
	switch {
	case !slices.Contains(helperPhases, r.Phase):
		return providers.DeploymentState{}, protocolError(sub, "an unknown phase")
	case r.Phase == winproto.PhaseNone || r.Phase == winproto.PhaseFenced:
		if slices.ContainsFunc(fields, func(v string) bool { return v != "" }) {
			return providers.DeploymentState{}, protocolError(sub, "no journal, or a tombstone, with a journal's fields")
		}
		return providers.DeploymentState{Phase: r.Phase, Active: r.Active}, nil
	case (r.FailedStep != "" && !slices.Contains(helperSteps, r.FailedStep)) || !knownCause(r.CauseStep) || !knownClass(r.Error) ||
		!isHexSHA256(r.NewCertSHA256) || (r.CurrentCertSHA256 != "" && !isHexSHA256(r.CurrentCertSHA256)):
		return providers.DeploymentState{}, protocolError(sub, "a journal outside the helper's vocabulary")
	}
	st := providers.DeploymentState{Phase: r.Phase, Active: r.Active, FailedStep: r.FailedStep, CauseStep: r.CauseStep, Error: r.Error,
		NewCertSHA256: r.NewCertSHA256, CurrentCertSHA256: r.CurrentCertSHA256}
	if err := st.Validate(); err != nil {
		return providers.DeploymentState{}, protocolError(sub, "a journal state that breaks the invariants")
	}
	return st, nil
}

// isHexSHA256: 64 lower-case hex digits.
func isHexSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range []byte(s) {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
