package api

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/providers"
	"alice/internal/providers/linuxssh"
)

// R48: the two reasons of the rollback guard are registered with their params.
func TestRollbackGuardReasonsClassify(t *testing.T) {
	got, params, ok := classify(linuxssh.RollbackGuardOutdated(9))
	assert.True(t, ok)
	assert.Equal(t, ErrHelperOutdatedRollbackGuard, got)
	assert.Equal(t, map[string]string{"helper_protocol": "9", "required_protocol": "10"}, params)

	got, _, ok = classify(providers.NewError(providers.ReasonRollbackForbidden, false, nil, nil))
	assert.True(t, ok)
	assert.Equal(t, ErrDeployRollbackForbidden, got)
	assert.Equal(t, "ALC-DEP-0025", got.Code)
}

// R48: a place whose replacement was sent but not confirmed says so, with the deployment's reason; it is never shown
// as replaced.
func TestIncidentLocationOutcomeUncertain(t *testing.T) {
	i := sampleIncident()
	i.Locations = append(i.Locations, inventory.IncidentLocation{LocationID: uuid.New(), TargetID: uuid.New(), TargetName: "web-02",
		CertPath: "/etc/ssl/api.pem", Status: inventory.IncidentLocationDeploying, OutcomeUncertain: true, UncertainCode: "ssh.unreachable"})
	d := incidentJSON(i, true)
	require.NotNil(t, d.Locations)
	locs := *d.Locations
	require.Len(t, locs, 2)
	assert.False(t, locs[0].OutcomeUncertain)
	assert.Equal(t, "ALC-DEP-0006", locs[0].Error.Code)
	assert.True(t, locs[1].OutcomeUncertain)
	assert.Equal(t, "deploying", locs[1].Status)
	require.NotNil(t, locs[1].Error)
	assert.Equal(t, "ALC-SSH-0001", locs[1].Error.Code)
}
