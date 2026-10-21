import type { Permission, Role, SessionAccess, SessionInfo } from '../api/types';

// The permissions of each global role (internal/rbac/rbac.go policies, docs/authz-matrix.md). The server sends what a
// person holds in the session's access (R49 Phase 2); a session answer without it (an older server) is read as the global
// role's rights everywhere. The UI is not an authorization boundary: the server decides every request.
const OPERATOR: Permission[] = ['read', 'inventory.operate', 'certificates.operate', 'acme.view', 'acme.operate', 'discovery.view', 'discovery.operate'];
const AUDITOR: Permission[] = ['read', 'audit.read', 'license.read', 'acme.view', 'discovery.view'];
const ADMIN: Permission[] = [
  'read',
  'audit.read',
  'users.read',
  'users.manage',
  'settings.manage',
  'license.read',
  'license.manage',
  'targets.manage',
  'hostkeys.confirm',
  'hostkeys.repin',
  'inventory.operate',
  'jobs.confirm',
  'certificates.operate',
  'credentials.manage',
  'sshkeys.download',
  'rotation.manage',
  'rotation.operate',
  'sso.manage',
  'backup.manage',
  'acme.view',
  'acme.operate',
  'acme.manage',
  'acme.preview',
  'discovery.view',
  'discovery.operate',
  'discovery.manage',
  'certificates.incident',
  'services.manage',
  'services.assign',
  'services.trust',
  'access.manage',
];

export const ROLE_PERMISSIONS: Record<Role, readonly Permission[]> = { admin: ADMIN, operator: OPERATOR, auditor: AUDITOR };

// sessionAccess is the access of the signed-in person: the server's answer, or (without one) the global role's rights.
export function sessionAccess(session: SessionInfo | null | undefined): SessionAccess {
  if (session?.access) return session.access;
  const role = session?.user.role ?? null;
  const perms = role ? [...ROLE_PERMISSIONS[role]] : [];
  return { global_role: role, services: [], permissions_anywhere: perms, platform_permissions: [...perms] };
}

// can: the person holds the permission on at least one service (or globally): lists, create buttons, navigation.
export function can(session: SessionInfo | null | undefined, perm: Permission): boolean {
  return sessionAccess(session).permissions_anywhere.includes(perm);
}

// canPlatform: the person holds the permission with a global grant: the platform pages and actions (people, settings,
// audit, license, SSO, backups, ACME providers, discovery settings, services and their access).
export function canPlatform(session: SessionInfo | null | undefined, perm: Permission): boolean {
  return sessionAccess(session).platform_permissions.includes(perm);
}

// canOn: the person holds the permission on the row's owning service (its allowed_actions). A row without the field (an
// older answer) falls back to can.
export function canOn(session: SessionInfo | null | undefined, row: { allowed_actions?: string[] } | null | undefined, perm: Permission): boolean {
  if (row && Array.isArray(row.allowed_actions)) return row.allowed_actions.includes(perm);
  // The server omits an empty allowed_actions: a row of a server that sends access in the session shows no action.
  if (row && session?.access) return false;
  return can(session, perm);
}

// rowAllows narrows a decision already made for the page (can) by the row's allowed_actions, when the row has them.
export function rowAllows(row: { allowed_actions?: string[] }, perm: Permission): boolean {
  return !Array.isArray(row.allowed_actions) || row.allowed_actions.includes(perm);
}

// adminOn: the person is an Administrator of the row's service (some changes inside a route are an Administrator's: the
// confirmation of an incomplete chain, of a held version, of root's last key). targets.manage is held by Administrators
// only, so it stands for the role.
export function adminOn(session: SessionInfo | null | undefined, row: { allowed_actions?: string[] } | null | undefined): boolean {
  return canOn(session, row, 'targets.manage');
}

// canIn: the person holds the permission on one service (by its id): globally, or through a role on that service.
export function canIn(session: SessionInfo | null | undefined, serviceId: string, perm: Permission): boolean {
  if (!session?.access) return can(session, perm);
  const a = session.access;
  if (a.platform_permissions.includes(perm)) return true;
  const held = a.services.find((s) => s.id === serviceId);
  return !!held && held.roles.some((r) => ROLE_PERMISSIONS[r]?.includes(perm));
}

// hasNoAccess: a signed-in person with no global role and no role on any service: there is nothing they may open.
export function hasNoAccess(session: SessionInfo | null | undefined): boolean {
  if (!session) return false;
  const a = sessionAccess(session);
  return a.global_role === null && a.services.length === 0 && a.permissions_anywhere.length === 0;
}
