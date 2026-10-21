// Query keys shared by the Phase 3 screens. Invalidating TARGETS_KEY refreshes every server
// query (list, detail, host keys, keys on a server), because TanStack Query matches by prefix.
export const TARGETS_KEY = ['targets'] as const;
export const targetKey = (id: string) => ['targets', id] as const;
export const SSH_KEYS_KEY = ['ssh-keys'] as const;
export const PLATFORM_KEY_KEY = ['platform-key'] as const;
export const BLOCKED_JOBS_KEY = ['jobs', 'blocked'] as const;

// Phase 4. Invalidating CERTIFICATES_KEY refreshes the list, every detail and every filter,
// because TanStack Query matches by prefix.
export const CERTIFICATES_KEY = ['certificates'] as const;
export const certificateKey = (id: string) => ['certificates', id] as const;
export const CSRS_KEY = ['csrs'] as const;
export const DEPLOYMENTS_KEY = ['deployments'] as const;
export const deploymentKey = (id: string) => ['deployments', id] as const;
export const locationsKey = (targetId: string) => ['locations', targetId] as const;

// The license status: polled every minute while someone is signed in (auth/SessionActivity.tsx)
// and shown by the license banners.
export const LICENSE_STATUS_KEY = ['license', 'status'] as const;

// Phase 5 (Key Vault). A vault is a target, so invalidating TARGETS_KEY refreshes these too; the
// KV_* keys are prefixes (the vault id, then the object) so one invalidation refreshes a vault's inventory.
// Three segments, so no target id (one segment) can ever address the same cache entry (/key-vaults/vaults).
export const VAULTS_KEY = ['targets', 'list', 'azure_key_vault'] as const;
export const KV_CERTIFICATES_KEY = ['kv', 'certificates'] as const;
export const kvCertificateKey = (vaultId: string, id: string) => ['kv', 'certificates', vaultId, id] as const;
export const kvListKey = (vaultId: string, kind: 'certificates' | 'keys' | 'secrets') => ['kv', kind, vaultId, 'list'] as const;
export const BINDINGS_KEY = ['bindings'] as const;
export const bindingKey = (id: string) => ['bindings', id] as const;
export const KV_IMPORTS_KEY = ['kv', 'imports'] as const;

// Phase 6 (SSH key lifecycle). sshKey(id) is the key's detail query (under SSH_KEYS_KEY, so one invalidation of the list
// refreshes it too); keyFiles(targetId) sits under the target's own key, so TARGETS_KEY refreshes it.
export const sshKey = (id: string) => ['ssh-keys', id] as const;
export const keyFiles = (targetId: string) => ['targets', targetId, 'key-files'] as const;

// Phase 6 rotation. A policy and a run are read by id; ROTATION_RUNS_KEY is a prefix so one invalidation refreshes every
// list and every run.
export const ROTATION_POLICIES_KEY = ['rotation', 'policies'] as const;
export const policyKey = (id: string) => ['rotation', 'policies', id] as const;
export const ROTATION_RUNS_KEY = ['rotation', 'runs'] as const;
export const runKey = (id: string) => ['rotation', 'runs', id] as const;

// Phase 7 (alerts, dashboard, saved views). EXPIRING_KEY sits under DASHBOARD_KEY, so one invalidation refreshes both.
export const DASHBOARD_KEY = ['dashboard'] as const;
export const EXPIRING_KEY = ['dashboard', 'expiring'] as const;
export const ALERTS_KEY = ['alerts'] as const;
export const NOTIFICATIONS_KEY = ['notifications', 'status'] as const;
export const viewsKey = (page: string) => ['views', page] as const;

// Phase 7 settings and single sign-on (admin pages). SETTINGS_KEY is a prefix: one invalidation reads every form again.
export const SETTINGS_KEY = ['settings'] as const;
export const settingsKey = (name: 'smtp' | 'recipients' | 'alerts' | 'general' | 'backups' | 'https' | 'forwarding') => ['settings', name] as const;
export const SSO_KEY = ['sso'] as const;
export const SSO_PROVIDERS_KEY = ['sso', 'providers'] as const;
export const SSO_SETTINGS_KEY = ['sso', 'settings'] as const;
export const ssoMappingsKey = (providerId: string) => ['sso', 'mappings', providerId] as const;
export const PUBLIC_PROVIDERS_KEY = ['auth', 'oidc', 'providers'] as const;

// Directories (LDAP or Active Directory). No key holds a password: the service account, sign-in and test passwords are
// mutation inputs only.
export const LDAP_KEY = ['ldap'] as const;
export const LDAP_DIRECTORIES_KEY = ['ldap', 'directories'] as const;
export const ldapMappingsKey = (directoryId: string) => ['ldap', 'mappings', directoryId] as const;
export const PUBLIC_DIRECTORIES_KEY = ['auth', 'ldap', 'directories'] as const;

// Phase 8. The backup list (with its state and schedule); the backup schedule, the HTTPS certificate's information and
// the audit forwarding are settings (settingsKey). No key holds a secret: uploads and the CA PEM are mutation inputs only.
export const BACKUPS_KEY = ['backups'] as const;

// ACME issuance. ACME_KEY is the prefix of everything; the lists sit under 'list' segments, so no id (a UUID) can
// address the same entry. No key holds a secret: the EAB HMAC key and the DNS hook secret are mutation inputs only.
export const ACME_KEY = ['acme'] as const;
export const ACME_PROVIDERS_KEY = ['acme', 'providers'] as const;
export const ACME_PROVIDER_LIST_KEY = ['acme', 'providers', 'list'] as const;
export const acmeProviderKey = (id: string) => ['acme', 'providers', id] as const;
// The registration form's directory preview: it contacts the CA, so it is read when the form opens and is never
// refreshed by an invalidation of the providers (notACMEPreview).
export const acmePreviewKey = (id: string) => ['acme', 'providers', id, 'preview'] as const;
export const notACMEPreview = (q: { queryKey: readonly unknown[] }) => !(q.queryKey[0] === 'acme' && q.queryKey[3] === 'preview');
export const ACME_HOOKS_KEY = ['acme', 'hooks'] as const;
export const ACME_HOOK_LIST_KEY = ['acme', 'hooks', 'list'] as const;
export const ACME_CERTIFICATES_KEY = ['acme', 'certificates'] as const;
export const acmeCertificateListKey = (filters: { state?: string; provider_id?: string; q?: string; cursor?: string; limit?: number }) =>
  ['acme', 'certificates', 'list', filters] as const;
export const acmeCertificateKey = (id: string) => ['acme', 'certificates', id] as const;
export const acmeOrdersKey = (id: string) => ['acme', 'certificates', id, 'orders'] as const;
export const acmeBindingsKey = (id: string) => ['acme', 'certificates', id, 'bindings'] as const;

// Revocation and key-compromise incidents (2026-10-20). The impact of a certificate sits under its certificate key, so
// invalidating CERTIFICATES_KEY refreshes it too; the incidents have a prefix of their own, lists under 'list'.
export const certificateImpactKey = (id: string) => ['certificates', id, 'impact'] as const;
export const CERTIFICATE_CAPABILITIES_KEY = ['certificate-capabilities'] as const;
export const INCIDENTS_KEY = ['incidents'] as const;
export const incidentKey = (id: string) => ['incidents', id] as const;
export const incidentListKey = (filters: { open?: boolean; certificate_id?: string }) => ['incidents', 'list', filters] as const;

// Network discovery. DISCOVERY_KEY is the prefix of everything; the lists sit under 'list' segments, so no id or
// fingerprint can address the same entry. The scope preview is never cached (it is read with the form's own abort).
export const DISCOVERY_KEY = ['discovery'] as const;
export const DISCOVERY_SUMMARY_KEY = ['discovery', 'summary'] as const;
export const DISCOVERY_SETTINGS_KEY = ['discovery', 'settings'] as const;
export const DISCOVERY_SCOPES_KEY = ['discovery', 'scopes'] as const;
export const DISCOVERY_SCOPE_LIST_KEY = ['discovery', 'scopes', 'list'] as const;
export const DISCOVERY_SCANS_KEY = ['discovery', 'scans'] as const;
export const discoveryScanListKey = (filters: { scope_id?: string; state?: string }) => ['discovery', 'scans', 'list', filters] as const;
export const DISCOVERY_CERTIFICATES_KEY = ['discovery', 'certificates'] as const;
export const discoveredCertificateListKey = (filters: Record<string, unknown>) => ['discovery', 'certificates', 'list', filters] as const;
export const discoveredCertificateKey = (fingerprint: string) => ['discovery', 'certificates', fingerprint] as const;

// Services and environments (R49). SERVICES_KEY is the prefix of every service query (the list, each service, its policy,
// its resources and the trusts), so one invalidation after a change or a move reads them all again; a move also changes
// the rows of the inventory lists, which their own keys refresh.
export const SERVICES_KEY = ['services'] as const;
export const SERVICE_LIST_KEY = ['services', 'list'] as const;
export const serviceKey = (id: string) => ['services', id] as const;
export const servicePolicyKey = (id: string) => ['services', id, 'policy'] as const;
export const servicePolicyVersionsKey = (id: string) => ['services', id, 'policy', 'versions'] as const;
export const serviceResourcesKey = (id: string, kind: string) => ['services', id, 'resources', kind] as const;
export const SERVICE_TRUSTS_KEY = ['services', 'trusts'] as const;
export const ENVIRONMENTS_KEY = ['environments'] as const;

// Role bindings of people (R49 Phase 2). ACCESS_KEY is the prefix of the binding lists and each person's access, so one
// invalidation after an added or removed binding reads them all again.
export const ACCESS_KEY = ['access'] as const;
export const roleBindingsKey = (filter: Record<string, string>) => ['access', 'bindings', filter] as const;
export const userAccessKey = (userId: string) => ['access', 'user', userId] as const;
