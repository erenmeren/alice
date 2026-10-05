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
