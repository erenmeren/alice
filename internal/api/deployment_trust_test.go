package api

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"alice/internal/inventory"
	"alice/internal/providers"
)

// R51: deployment.verify_untrusted is registered (the next free deployment code) and keeps its trust_error param.
func TestVerifyUntrustedClassifies(t *testing.T) {
	got, params, ok := classify(providers.NewError("deployment.verify_untrusted", false, nil,
		map[string]string{"port": "443", "trust_error": "wrong_intermediate", "stderr": "remote text"}))
	assert.True(t, ok)
	assert.Equal(t, ErrDeployVerifyUntrusted, got)
	assert.Equal(t, "ALC-DEP-0026", got.Code)
	assert.Equal(t, map[string]string{"port": "443", "trust_error": "wrong_intermediate"}, params)
	assert.Nil(t, providerParams(map[string]string{"trust_error": "Not A Code"}), "a value outside the closed list is dropped")
	for _, code := range providers.TrustErrors {
		assert.Equal(t, map[string]string{"trust_error": code}, providerParams(map[string]string{"trust_error": code}), "the API's list is providers'")
	}
}

// R51: a deployment shows the level its verification proved and what it found about the served chains; a failed
// verification says whether the network, the certificate or the trust failed.
func TestDeploymentVerificationJSON(t *testing.T) {
	d := inventory.Deployment{ID: uuid.New(), Status: inventory.DeployStatusSucceeded, Verified: "remote", Level: providers.LevelTrusted,
		Trust: providers.Trust{Status: providers.TrustTrusted, Store: providers.TrustStoreACME, Enforced: true}}
	b, err := json.Marshal(deploymentJSON(d))
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(b, &m))
	assert.Equal(t, map[string]any{"level": 3.0, "failure": "",
		"trust": map[string]any{"status": "trusted", "error": "", "port": nil, "store": "acme_bundle", "enforced": true}}, m["verification"])

	warn := inventory.Deployment{ID: uuid.New(), Status: inventory.DeployStatusSucceeded, Verified: "local", Level: providers.LevelServed,
		Trust: providers.Trust{Status: providers.TrustUntrusted, Error: providers.TrustErrUnknownAuthority, Port: 8443, Store: providers.TrustStoreSystem}}
	v := deploymentJSON(warn).Verification
	assert.Equal(t, providers.LevelServed, v.Level)
	require.NotNil(t, v.Trust)
	require.NotNil(t, v.Trust.Port)
	assert.Equal(t, 8443, *v.Trust.Port)
	assert.Equal(t, "unknown_authority", v.Trust.Error)

	old := inventory.Deployment{ID: uuid.New(), Status: inventory.DeployStatusSucceeded, Verified: "remote", Level: providers.LevelServed}
	assert.Nil(t, deploymentJSON(old).Verification.Trust, "not measured (before R51, or skipped)")

	for code, want := range map[string]string{
		"deployment.verify_unreachable": providers.VerifyFailureNetwork, "deployment.verify_failed": providers.VerifyFailureCertificate,
		"deployment.verify_other": providers.VerifyFailureCertificate, "deployment.verify_chain": providers.VerifyFailureCertificate,
		"deployment.verify_untrusted": providers.VerifyFailureTrust, "deployment.reload_failed": "",
	} {
		f := inventory.Deployment{ID: uuid.New(), Status: inventory.DeployStatusRolledBack, ErrorCode: code, ErrorParams: map[string]string{}}
		assert.Equal(t, want, deploymentJSON(f).Verification.Failure, code)
	}
	unc := inventory.Deployment{ID: uuid.New(), Status: inventory.DeployStatusNeedsAttention, VerifyFailedReason: "deployment.verify_untrusted"}
	assert.Equal(t, providers.VerifyFailureTrust, deploymentJSON(unc).Verification.Failure, "the recorded verification failure counts")

	// The verify step's trust params reach the UI; unknown values do not.
	assert.Equal(t, map[string]string{"trust": "untrusted", "trust_error": "name_mismatch"},
		stepParams(map[string]string{"trust": "untrusted", "trust_error": "name_mismatch"}))
	assert.Empty(t, stepParams(map[string]string{"trust": "maybe", "trust_error": "bad"}))
}
