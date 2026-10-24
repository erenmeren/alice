package api

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/jobs/sshkeyjobs"
)

// incidentRefusals are the refusals of RequestDeployment the incident engine keeps on a place (IsIncidentRefusal).
var incidentRefusals = map[string]error{
	"ErrNotFound":               inventory.ErrNotFound,
	"ErrLocationUnsupported":    inventory.ErrLocationUnsupported,
	"ErrNginxConfigInvalid":     inventory.ErrNginxConfigInvalid,
	"ErrLocationNeedsDiscovery": inventory.ErrLocationNeedsDiscovery,
	"ErrChainUnconfirmed":       inventory.ErrChainUnconfirmed,
	"ErrCertificateExpired":     inventory.ErrCertificateExpired,
	"ErrCertificateNotYetValid": inventory.ErrCertificateNotYetValid,
	"ErrNoPrivateKey":           inventory.ErrNoPrivateKey,
	"ErrUnsupportedKey":         inventory.ErrUnsupportedKey,
	"ErrCertificateRevoked":     inventory.ErrCertificateRevoked,
	"ErrCertificateCompromised": inventory.ErrCertificateCompromised,
	"ErrTargetDisabled":         inventory.ErrTargetDisabled,
}

// TestIncidentRefusalCodesMatchTheCatalogue (HB-01): the code the incident engine stores on a refused place is the API's
// reason of the same error, so the page shows that error's text; the key-type mismatch is the one documented exception
// (a stored code carries no params). Every code the engine can store is registered.
func TestIncidentRefusalCodesMatchTheCatalogue(t *testing.T) {
	for name, err := range incidentRefusals {
		require.True(t, inventory.IsIncidentRefusal(err), name)
		ec, _, ok := classify(err)
		require.True(t, ok, name)
		assert.Equal(t, ec.Reason, inventory.IncidentRefusalCode(err), name)
	}
	km := &inventory.KeyTypeMismatchError{Expected: "rsa", Actual: "ecdsa"}
	require.True(t, inventory.IsIncidentRefusal(km))
	assert.Equal(t, "incident.not_deployable", inventory.IncidentRefusalCode(km))
	lr := &inventory.LocationRefusalError{Err: inventory.ErrLocationUnsupported}
	assert.True(t, inventory.IsIncidentRefusal(lr))

	all := []error{km, inventory.ErrTargetNotReady, inventory.ErrACMEAccountState, inventory.ErrACMERolloverPending}
	for _, err := range incidentRefusals {
		all = append(all, err)
	}
	for _, err := range all {
		code := inventory.IncidentRefusalCode(err)
		assert.NotEqual(t, ErrUnexpected, codeForReason(code), "%v: %q has no registered code", err, code)
	}
	assert.Equal(t, ErrUnexpected.Reason, inventory.IncidentRefusalCode(errors.New("the database")))
	assert.False(t, inventory.IsIncidentRefusal(errors.New("the database")))
}

// TestSSHKeyDeployRefusalsMatchTheCatalogue (HB-01): the reason the key deploy job records for a refusal is the API's
// reason of the same error. ErrNotAServer is recorded as system.not_found, the reason of ErrNotFound.
func TestSSHKeyDeployRefusalsMatchTheCatalogue(t *testing.T) {
	refusals := sshkeyjobs.DeployRefusalReasons()
	require.NotEmpty(t, refusals)
	for err, reason := range refusals {
		if errors.Is(err, inventory.ErrNotAServer) {
			nf, _, ok := classify(inventory.ErrNotFound)
			require.True(t, ok)
			assert.Equal(t, nf.Reason, reason)
			continue
		}
		ec, _, ok := classify(err)
		require.True(t, ok, "%v", err)
		assert.Equal(t, ec.Reason, reason, "%v", err)
	}
}
