// Query keys shared by the Phase 3 screens. Invalidating TARGETS_KEY refreshes every server
// query (list, detail, host keys, keys on a server), because TanStack Query matches by prefix.
export const TARGETS_KEY = ['targets'] as const;
export const targetKey = (id: string) => ['targets', id] as const;
export const SSH_KEYS_KEY = ['ssh-keys'] as const;
export const PLATFORM_KEY_KEY = ['platform-key'] as const;
export const BLOCKED_JOBS_KEY = ['jobs', 'blocked'] as const;
