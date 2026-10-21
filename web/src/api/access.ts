import { apiFetch } from './client';
import type { EnvironmentRef, Role, ServiceRef } from './types';

// Role bindings of people (R49 Phase 2, api/openapi.yaml /api/v1/role-bindings, /api/v1/users/{id}/access): a role a
// person holds on one service or on every service of one environment, beside their global role ("All services").
// Reading them is a global Administrator's (users.read); adding and removing them is access.manage, a global
// Administrator's browser session with a fresh step-up, never an API token.

export interface RoleBinding {
  id: string;
  user_id: string | null;
  username?: string;
  display_name?: string;
  directory_group_id: string | null;
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

export type RoleBindingCreate = { user_id: string; role: Role } & ({ service_id: string } | { environment_id: string });

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
