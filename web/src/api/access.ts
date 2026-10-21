import { apiFetch } from './client';
import type { ApiToken, CreatedToken, EnvironmentRef, Role, ServiceRef, TokenCreateRequest } from './types';

// Role bindings of people (R49 Phase 2, api/openapi.yaml /api/v1/role-bindings, /api/v1/users/{id}/access): a role a
// person holds on one service or on every service of one environment, beside their global role ("All services").
// Reading them is a global Administrator's (users.read); adding and removing them is access.manage, a global
// Administrator's browser session with a fresh step-up, never an API token.

export interface RoleBinding {
  id: string;
  user_id: string | null;
  username?: string;
  display_name?: string;
  // The user is an automation account (R54).
  automation?: boolean;
  directory_group_id: string | null;
  // The directory group of a group binding (R54).
  group?: BindingGroup;
  role: Role;
  // Exactly one of service and environment is set.
  service: ServiceRef | null;
  environment: EnvironmentRef | null;
  // The services the binding covers now (an environment binding: every service that carries the environment).
  services: ServiceRef[];
  created_by: string | null;
  created_by_name: string;
  created_at: string;
}

export interface RoleBindingFilter {
  user_id?: string;
  service_id?: string;
  environment_id?: string;
  directory_group_id?: string;
}

// A binding's subject is a person or an automation account (user_id) or a directory group (directory_group_id, R54).
export type RoleBindingCreate = ({ user_id: string } | { directory_group_id: string }) & { role: Role } & ({ service_id: string } | { environment_id: string });

export interface BindingGroup {
  source: DirectorySource;
  source_name: string;
  value: string;
  label: string;
}

// AccessGrant is one role as the authorization check sees it: the services it covers now.
export interface AccessGrant {
  role: Role;
  services: ServiceRef[];
}

// UserAccess explains a person's effective access ("Explain"): the global role (null: none), every binding, the grants
// they add up to, and whether the "SSO users may be Admin" setting lowers an Administrator binding to Operator.
export interface UserAccess {
  global_role: Role | null;
  bindings: RoleBinding[];
  // The bindings of the directory groups the person was in at their last sign-in (R54).
  group_bindings?: RoleBinding[];
  grants: AccessGrant[];
  admin_capped: boolean;
}

const v1 = '/api/v1';
const enc = encodeURIComponent;

// bindingQuery is the filter as a plain record (the query key) and a query string.
export function bindingFilterRecord(f: RoleBindingFilter): Record<string, string> {
  const out: Record<string, string> = {};
  for (const k of ['user_id', 'service_id', 'environment_id', 'directory_group_id'] as const) if (f[k]) out[k] = f[k] as string;
  return out;
}

export const listRoleBindings = (f: RoleBindingFilter, signal?: AbortSignal) => {
  const qs = new URLSearchParams(bindingFilterRecord(f)).toString();
  return apiFetch<{ items: RoleBinding[] }>(`${v1}/role-bindings${qs ? `?${qs}` : ''}`, { signal });
};
export const createRoleBinding = (body: RoleBindingCreate) => apiFetch<RoleBinding>(`${v1}/role-bindings`, { method: 'POST', body });
export const deleteRoleBinding = (id: string) => apiFetch<void>(`${v1}/role-bindings/${enc(id)}`, { method: 'DELETE' });
export const getUserAccess = (userId: string, signal?: AbortSignal) => apiFetch<UserAccess>(`${v1}/users/${enc(userId)}/access`, { signal });

// Directory groups (R54, /api/v1/directory-groups): a group of an SSO provider or a directory that role bindings name.
// The value is exactly what the provider's groups claim or the directory's group search returns (case-sensitive).
export type DirectorySource = 'oidc' | 'ldap';

export interface DirectoryGroup {
  id: string;
  source: DirectorySource;
  provider_id: string | null;
  directory_id: string | null;
  source_name: string;
  value: string;
  label: string;
  members: number;
  bindings: number;
  created_by: string | null;
  created_by_name: string;
  created_at: string;
}

// SeenGroup is a group value seen at sign-ins, with how many people had it and its declared group, if any.
export interface SeenGroup {
  source: DirectorySource;
  provider_id: string | null;
  directory_id: string | null;
  source_name: string;
  value: string;
  users: number;
  directory_group_id: string | null;
}

export interface DirectoryGroupCreate {
  source: DirectorySource;
  provider_id?: string;
  directory_id?: string;
  value: string;
  label?: string;
}

export const listDirectoryGroups = (signal?: AbortSignal) => apiFetch<{ items: DirectoryGroup[]; seen: SeenGroup[] }>(`${v1}/directory-groups`, { signal });
export const createDirectoryGroup = (body: DirectoryGroupCreate) => apiFetch<DirectoryGroup>(`${v1}/directory-groups`, { method: 'POST', body });
export const deleteDirectoryGroup = (id: string) =>
  apiFetch<{ bindings_removed: number; owners_removed: number }>(`${v1}/directory-groups/${enc(id)}`, { method: 'DELETE' });

// Automation accounts (R54, /api/v1/automation-accounts): a non-person that never signs in and only holds API tokens,
// which a global Administrator makes. Its global role is none, Operator or Auditor, never Administrator.
export type AutomationRole = Exclude<Role, 'admin'>;

export interface AutomationAccount {
  id: string;
  username: string;
  display_name: string;
  description: string;
  role: AutomationRole | null;
  disabled: boolean;
  tokens: number;
  last_used_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface AutomationCreate {
  username: string;
  display_name: string;
  description: string;
  role: AutomationRole | null;
}

export type AutomationUpdate = Partial<Pick<AutomationCreate, 'display_name' | 'description' | 'role'>> & { disabled?: boolean };

const automation = `${v1}/automation-accounts`;
export const listAutomationAccounts = (signal?: AbortSignal) => apiFetch<{ items: AutomationAccount[] }>(automation, { signal });
export const createAutomationAccount = (body: AutomationCreate) => apiFetch<AutomationAccount>(automation, { method: 'POST', body });
export const updateAutomationAccount = (id: string, body: AutomationUpdate) => apiFetch<AutomationAccount>(`${automation}/${enc(id)}`, { method: 'PATCH', body });
export const listAutomationTokens = (id: string, signal?: AbortSignal) => apiFetch<{ items: ApiToken[] }>(`${automation}/${enc(id)}/tokens`, { signal });
export const createAutomationToken = (id: string, body: TokenCreateRequest) => apiFetch<CreatedToken>(`${automation}/${enc(id)}/tokens`, { method: 'POST', body });
export const revokeAutomationToken = (id: string, tokenId: string) => apiFetch<void>(`${automation}/${enc(id)}/tokens/${enc(tokenId)}`, { method: 'DELETE' });
