package inventory

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"alice/internal/acme/keygen"
	"alice/internal/authz"
)

// The service policy (R55) names the ACME key types, challenges, revocation modes and renewal window as this package
// does (authz knows the platform only, so it keeps its own lists).
func TestPolicyValuesMatchTheInventorys(t *testing.T) {
	var keyTypes []string
	for _, p := range keygen.Policies() {
		keyTypes = append(keyTypes, string(p))
	}
	assert.ElementsMatch(t, keyTypes, authz.PolicyKeyTypes)
	for _, c := range []string{ACMEChallengeDNS01, ACMEChallengeHTTP01} {
		assert.NoError(t, authz.EmptyPolicy().CheckACME([16]byte{}, c, string(keygen.Default)))
	}
	assert.Equal(t, IncidentRevokeAfterVerified, authz.RevokeAfterVerified)
	assert.Equal(t, IncidentRevokeNow, authz.RevokeNow)
	assert.Equal(t, minACMERenewBeforeDays, authz.MinPolicyRenewDays)
	assert.Equal(t, maxACMERenewBeforeDays, authz.MaxPolicyRenewDays)
	_, err := authz.ParsePolicy([]byte(`{"schema":1,"acme":{"challenges":["`+ACMEChallengeDNS01+`","`+ACMEChallengeHTTP01+`"]}}`), "")
	assert.NoError(t, err, "both challenges are policy values")
}
