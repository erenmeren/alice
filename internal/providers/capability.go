package providers

import (
	"maps"
	"sort"
)

// Capability is one thing a provider can do (spec §6.1).
type Capability string

// Capabilities of v1 providers.
const (
	CapTestConnection    Capability = "test_connection"
	CapDiscoverCerts     Capability = "discover_certificates"
	CapDiscoverSSHKeys   Capability = "discover_ssh_keys"
	CapDiscoverKVKeys    Capability = "discover_kv_keys"
	CapDiscoverKVSecrets Capability = "discover_kv_secret_metadata" //nolint:gosec // G101 false positive: a capability name, not a credential
	CapDeployCertificate Capability = "deploy_certificate"
	CapImportCertificate Capability = "import_certificate"
	CapAuthorizedKeys    Capability = "authorized_keys"
	CapVerifyDeployment  Capability = "verify_deployment"
	// CapReadCertificateSecret: read the secret that backs a vault certificate version (the private
	// key, for a deployment to Nginx; spec §11.5; R40 row 18).
	CapReadCertificateSecret Capability = "read_certificate_secret" //nolint:gosec // G101 false positive: a capability name, not a credential
	// CapKeyLogin: VerifyKeyLogin, one test login with one SSH key (spec §13.4).
	CapKeyLogin Capability = "key_login"
	// CapHTTP01: publish and remove an ACME HTTP-01 token on the server (http01.Publisher; spec 2026-10-17 §3.4).
	CapHTTP01 Capability = "http01_challenge"
	// CapCleanupCertificates: plan and remove certificates Alice put on the target and no longer uses
	// (CertificateCleaner; R62 W3, the Windows provider's iis-cleanup).
	CapCleanupCertificates Capability = "cleanup_certificates"
)

// CapabilitySet is the static set a provider advertises.
type CapabilitySet map[Capability]struct{}

// NewCapabilitySet builds a set; duplicates are ignored.
func NewCapabilitySet(caps ...Capability) CapabilitySet {
	c := make(CapabilitySet, len(caps))
	for _, x := range caps {
		c[x] = struct{}{}
	}
	return c
}

// Has reports whether x is in the set (false for a nil set).
func (c CapabilitySet) Has(x Capability) bool {
	_, ok := c[x]
	return ok
}

// Sorted returns the capabilities in lexical order (stable API output).
func (c CapabilitySet) Sorted() []Capability {
	out := make([]Capability, 0, len(c))
	for x := range c {
		out = append(out, x)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Clone returns an independent copy of the set.
func (c CapabilitySet) Clone() CapabilitySet { return maps.Clone(c) }

var knownCapabilities = NewCapabilitySet(
	CapTestConnection, CapDiscoverCerts, CapDiscoverSSHKeys, CapDiscoverKVKeys, CapDiscoverKVSecrets,
	CapDeployCertificate, CapImportCertificate, CapAuthorizedKeys, CapVerifyDeployment, CapReadCertificateSecret,
	CapKeyLogin, CapHTTP01, CapCleanupCertificates,
)
