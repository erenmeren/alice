package authz

import "strings"

// The reach conditions of the lists (design §4.5, §5.8), shared by every module that lists rows, so that a row is
// visible from exactly the same services in a list, its count, its export and the resolver of its by-id route
// (authz/services). Each takes the alias of the listed table and the placeholder of the reach (Reach.SQL: NULL for
// every service, otherwise the array of services) and is a complete condition: true for every row when the reach is
// every service. The filter applies inside the query, before the cursor and the limit, so pages, totals and facet
// counts are computed over the visible rows only.

// OwnedVisible: a row of a table with its own service_id column (servers, Key Vaults, signing requests, ACME
// certificates by their owning service, scan scopes, jobs, alerts).
func OwnedVisible(alias, reach string) string {
	return expand(`({r}::uuid[] IS NULL OR {a}.service_id = ANY({r}))`, alias, reach)
}

// TargetVisible: a row derived from a server or a Key Vault through its target_id column (locations, host keys, Key
// Vault objects, deployments by their server).
func TargetVisible(alias, reach string) string {
	return expand(`({r}::uuid[] IS NULL OR EXISTS (SELECT 1 FROM targets vt WHERE vt.id = {a}.target_id AND vt.service_id = ANY({r})))`, alias, reach)
}

// CertificateVisible: a certificate is visible from its owning service, the services of the servers holding a live
// location of it, the vault's service of a Key Vault version that is it, and the service of an ACME certificate whose
// current or an earlier certificate it is.
func CertificateVisible(alias, reach string) string {
	return expand(`({r}::uuid[] IS NULL OR {a}.service_id = ANY({r})
    OR EXISTS (SELECT 1 FROM certificate_locations vl JOIN targets vt ON vt.id = vl.target_id
        WHERE vl.certificate_id = {a}.id AND vl.missing_since IS NULL AND vt.deleted_at IS NULL AND vt.service_id = ANY({r}))
    OR EXISTS (SELECT 1 FROM kv_certificate_versions vk JOIN kv_certificates vkc ON vkc.id = vk.kv_certificate_id
        JOIN targets vv ON vv.id = vkc.target_id WHERE vk.certificate_id = {a}.id AND vv.deleted_at IS NULL AND vv.service_id = ANY({r}))
    OR EXISTS (SELECT 1 FROM acme_certificates va WHERE va.current_certificate_id = {a}.id AND va.service_id = ANY({r}))
    OR EXISTS (SELECT 1 FROM acme_orders vo JOIN acme_certificates vao ON vao.id = vo.acme_certificate_id
        WHERE vo.certificate_id = {a}.id AND vao.service_id = ANY({r})))`, alias, reach)
}

// SSHKeyVisible: an SSH key is visible from its owning service and the services of the servers holding a live
// location of it.
func SSHKeyVisible(alias, reach string) string {
	return expand(`({r}::uuid[] IS NULL OR {a}.service_id = ANY({r})
    OR EXISTS (SELECT 1 FROM ssh_key_locations vl JOIN targets vt ON vt.id = vl.target_id
        WHERE vl.ssh_key_id = {a}.id AND vl.missing_since IS NULL AND vt.deleted_at IS NULL AND vt.service_id = ANY({r})))`, alias, reach)
}

// ACMECertificateVisible: an ACME certificate is visible from its owning service and the services of its bound
// locations' servers.
func ACMECertificateVisible(alias, reach string) string {
	return expand(`({r}::uuid[] IS NULL OR {a}.service_id = ANY({r})
    OR EXISTS (SELECT 1 FROM acme_bindings vb JOIN certificate_locations vl ON vl.id = vb.location_id JOIN targets vt ON vt.id = vl.target_id
        WHERE vb.acme_certificate_id = {a}.id AND vt.deleted_at IS NULL AND vt.service_id = ANY({r})))`, alias, reach)
}

// DeploymentVisible: a deployment is visible from its server's service and its certificate's owning service.
func DeploymentVisible(alias, reach string) string {
	return expand(`({r}::uuid[] IS NULL
    OR EXISTS (SELECT 1 FROM targets vt WHERE vt.id = {a}.target_id AND vt.service_id = ANY({r}))
    OR EXISTS (SELECT 1 FROM certificates vc WHERE vc.id = {a}.certificate_id AND vc.service_id = ANY({r})))`, alias, reach)
}

// ScopeVisible: a row of network discovery is visible from its scope's service (the scope_id column).
func ScopeVisible(alias, reach string) string {
	return expand(`({r}::uuid[] IS NULL OR EXISTS (SELECT 1 FROM discovery_scopes vs WHERE vs.id = {a}.scope_id AND vs.service_id = ANY({r})))`, alias, reach)
}

// DiscoveredCertificateVisible: a discovered certificate is visible from the services of the scopes with an endpoint
// presenting it, as the leaf or in the chain (the fingerprint_sha256 column of the alias).
func DiscoveredCertificateVisible(alias, reach string) string {
	return expand(`({r}::uuid[] IS NULL OR EXISTS (SELECT 1 FROM discovery_endpoints ve JOIN discovery_scopes vs ON vs.id = ve.scope_id
    WHERE (ve.fingerprint_sha256 = {a}.fingerprint_sha256 OR {a}.fingerprint_sha256 = ANY (ve.chain_fingerprints)) AND vs.service_id = ANY({r})))`, alias, reach)
}

// RotationPolicyVisible: a rotation policy is visible from its key's service and the services that approved it.
func RotationPolicyVisible(alias, reach string) string {
	return expand(`({r}::uuid[] IS NULL OR {a}.approved_service_ids && {r}
    OR EXISTS (SELECT 1 FROM ssh_keys vk WHERE vk.id = {a}.ssh_key_id AND vk.service_id = ANY({r})))`, alias, reach)
}

// IncidentVisible: an incident is visible from its certificate's service and every service in its service_ids.
func IncidentVisible(alias, reach string) string {
	return expand(`({r}::uuid[] IS NULL OR {a}.service_ids && {r}
    OR EXISTS (SELECT 1 FROM certificates vc WHERE vc.id = {a}.certificate_id AND vc.service_id = ANY({r})))`, alias, reach)
}

func expand(tpl, alias, reach string) string {
	return strings.NewReplacer("{a}", alias, "{r}", reach).Replace(tpl)
}
