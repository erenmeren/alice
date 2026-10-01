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
	CapDeployCertificate, CapImportCertificate, CapAuthorizedKeys, CapVerifyDeployment,
)
