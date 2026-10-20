package inventory

import (
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// The capability matrix (ruling: docs/superpowers/rulings/certificate-revocation.md). Only an ACME certificate is
// obtained, renewed, revoked and recovered by Alice; every source is discovered; deploy and verify need a key.
func TestSourceCapabilityMatrix(t *testing.T) {
	assert.Equal(t, []SourceCapability{"discover", "obtain", "renew", "deploy", "verify", "revoke", "recovery"}, SourceCapabilities())
	m := SourceCapabilityMatrix()
	assert.Equal(t, SourceCapabilities(), m["acme"])
	assert.Equal(t, []SourceCapability{SourceCapDiscover}, m["discovered"])
	for _, src := range []string{"uploaded", "csr", "azure_kv"} {
		assert.Equal(t, []SourceCapability{SourceCapDiscover, SourceCapDeploy, SourceCapVerify}, m[src], src)
	}
	for src, caps := range m {
		assert.True(t, slices.Contains(caps, SourceCapDiscover), src)
		if src != "acme" {
			for _, c := range []SourceCapability{SourceCapObtain, SourceCapRenew, SourceCapRevoke, SourceCapRecovery} {
				assert.NotContains(t, caps, c, src)
			}
		}
	}
	assert.ElementsMatch(t, certificateSources, keys(m), "every source has a row")
	assert.Nil(t, CapabilitiesOf("nonsense"))
	m["acme"][0] = "changed"
	assert.Equal(t, SourceCapDiscover, CapabilitiesOf("acme")[0], "a copy")
}

func keys(m map[string][]SourceCapability) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestCertificateCapabilities(t *testing.T) {
	now := time.Now()
	acme := Certificate{Source: "acme", HasPrivateKey: true}
	assert.Equal(t, SourceCapabilities(), CertificateCapabilities(acme))
	revoked := acme
	revoked.RevokedAt = &now
	assert.Equal(t, []SourceCapability{"discover", "obtain", "renew", "recovery"}, CertificateCapabilities(revoked))
	compromised := acme
	compromised.CompromisedAt = &now
	assert.Equal(t, []SourceCapability{"discover", "obtain", "renew", "revoke", "recovery"}, CertificateCapabilities(compromised))
	assert.Equal(t, []SourceCapability{"discover"}, CertificateCapabilities(Certificate{Source: "uploaded"}), "no key: nothing to deploy")
	assert.Equal(t, []SourceCapability{"discover", "deploy", "verify"}, CertificateCapabilities(Certificate{Source: "azure_kv"}),
		"the vault holds the key")
	assert.Equal(t, []SourceCapability{"discover"}, CertificateCapabilities(Certificate{Source: "discovered"}))
}
