package inventory

import "slices"

// SourceCapability is one thing Alice can do with a certificate of a source (owner decision 2026-10-20,
// docs/superpowers/rulings/certificate-revocation.md): the per-source matrix the API shows with every certificate and the
// web uses to disable what a source cannot do. It is the certificate-side counterpart of the providers' capability sets
// (internal/providers/capability.go): a deployment needs both the certificate's deploy and the server's
// deploy_certificate.
type SourceCapability string

// The capabilities of a certificate source.
const (
	// SourceCapDiscover: Alice finds where the certificate is used (on managed servers, by network discovery).
	SourceCapDiscover SourceCapability = "discover"
	// SourceCapObtain: Alice obtains the certificate from its CA herself.
	SourceCapObtain SourceCapability = "obtain"
	// SourceCapRenew: Alice renews it herself before it expires.
	SourceCapRenew SourceCapability = "renew"
	// SourceCapDeploy: Alice deploys it to servers (she holds or can read its private key).
	SourceCapDeploy SourceCapability = "deploy"
	// SourceCapVerify: Alice checks after her deployment that the server serves it (it goes with deploy).
	SourceCapVerify SourceCapability = "verify"
	// SourceCapRevoke: Alice asks its CA to revoke it (RFC 8555 section 7.6).
	SourceCapRevoke SourceCapability = "revoke"
	// SourceCapRecovery: Alice recovers its renewal by herself after an outage of the CA, DNS or hook.
	SourceCapRecovery SourceCapability = "recovery"
)

// SourceCapabilities lists every capability, in the order the matrix shows them.
func SourceCapabilities() []SourceCapability {
	return []SourceCapability{SourceCapDiscover, SourceCapObtain, SourceCapRenew, SourceCapDeploy, SourceCapVerify, SourceCapRevoke,
		SourceCapRecovery}
}

// sourceCapabilities is the matrix. discovered: found on a server or by a scan, its key is not in Alice (nothing but
// finding it). uploaded and csr: a person brought it (with its key, or for a signing request Alice made); its CA is
// outside Alice. azure_kv: Azure Key Vault issues and renews it; Alice follows new versions and deploys them (the key is
// read from the vault). acme: Alice orders, renews, deploys, verifies and revokes it, and recovers its renewal.
var sourceCapabilities = map[string][]SourceCapability{
	"discovered": {SourceCapDiscover},
	"uploaded":   {SourceCapDiscover, SourceCapDeploy, SourceCapVerify},
	"csr":        {SourceCapDiscover, SourceCapDeploy, SourceCapVerify},
	"azure_kv":   {SourceCapDiscover, SourceCapDeploy, SourceCapVerify},
	"acme":       SourceCapabilities(),
}

// CapabilitiesOf is the capability list of a certificate source (nil for an unknown source), in matrix order.
func CapabilitiesOf(source string) []SourceCapability {
	return slices.Clone(sourceCapabilities[source])
}

// CertificateCapabilities is the capability list of one certificate: its source's, less deploy when Alice holds no key
// for it (a Key Vault leaf excepted: the key is read from the vault), less revoke when it is revoked already, and less
// deploy once it is revoked or compromised (neither is ever deployed again); verify goes with deploy.
func CertificateCapabilities(c Certificate) []SourceCapability {
	out := CapabilitiesOf(c.Source)
	return slices.DeleteFunc(out, func(x SourceCapability) bool {
		switch x {
		case SourceCapDeploy, SourceCapVerify:
			return (!c.HasPrivateKey && c.Source != "azure_kv") || c.RevokedAt != nil || c.CompromisedAt != nil
		case SourceCapRevoke:
			return c.RevokedAt != nil
		}
		return false
	})
}

// SourceCapabilityMatrix is the whole matrix (source -> capabilities), for the API and the documentation.
func SourceCapabilityMatrix() map[string][]SourceCapability {
	out := make(map[string][]SourceCapability, len(sourceCapabilities))
	for k, v := range sourceCapabilities {
		out[k] = slices.Clone(v)
	}
	return out
}
