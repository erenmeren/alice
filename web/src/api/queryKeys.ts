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
