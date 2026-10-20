package linuxssh

import (
	"context"
	"errors"
	"strconv"

	"alice/internal/providers"
	"alice/internal/providers/linuxssh/helperproto"
)

// ReasonRollbackGuardOutdated is the reason of a deployment (or a restore) that needs the rollback
// guard on the server (R48: an incident replacement, or a backup holding a revoked or compromised
// certificate or key) while the server's helper is older than helperproto.RollbackGuardMinProtocol:
// such a helper would put the backup back by itself after a failed change, without checking it, so
// nothing is sent. Every other deployment to the server keeps working; the administrator runs the
// setup commands again (the new helper) and retries. Params: helper_protocol, required_protocol.
// Registered as ALC-SSH-0014.
const ReasonRollbackGuardOutdated = "ssh.helper_outdated_rollback_guard"

// ErrRollbackGuardOutdated is the cause of a ReasonRollbackGuardOutdated error (errors.Is).
var ErrRollbackGuardOutdated = errors.New("linuxssh: reinstall the helper on this server: it cannot refuse to restore a compromised key")

// RollbackGuardOutdated is the refusal of a helper of protocol p that cannot check the rollback guard.
func RollbackGuardOutdated(p int) *providers.Error {
	return providers.NewError(ReasonRollbackGuardOutdated, false, ErrRollbackGuardOutdated, map[string]string{
		"helper_protocol": strconv.Itoa(p), "required_protocol": strconv.Itoa(helperproto.RollbackGuardMinProtocol)})
}

// GuardsRollback reports whether the server's helper checks the rollback guard itself (protocol 10).
func (c *Conn) GuardsRollback(ctx context.Context) (bool, int, error) {
	p, err := c.HelperProtocol(ctx)
	if err != nil {
		return false, 0, err
	}
	return p >= helperproto.RollbackGuardMinProtocol, p, nil
}
