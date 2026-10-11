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

// Phase 8. The backup list (with its state and schedule); the backup schedule, the HTTPS certificate's information and
// the audit forwarding are settings (settingsKey). No key holds a secret: uploads and the CA PEM are mutation inputs only.
export const BACKUPS_KEY = ['backups'] as const;
