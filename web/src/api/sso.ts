import { apiFetch } from './client';
import { ifMatch } from './settings';
import type { Role } from './types';

// Single sign-on (contract C13 and Task 15's shipped API).

export interface Provider {
  id: string;
  name: string;
  issuer_url: string;
  client_id: string;
  has_client_secret: boolean;
  scopes: string[];
  groups_claim: string;
  ca_pem: string;
  endpoints: { authorization: string; token: string; jwks: string };
  enabled: boolean;
  redirect_uri: string;
  version: number;
  created_at: string;
  updated_at: string;
}

// client_secret is write-only: absent keeps the stored one.
export interface ProviderInput {
  name: string;
  issuer_url: string;
  client_id: string;
  client_secret?: string;
  groups_claim: string;
  ca_pem: string;
  enabled: boolean;
}

export interface Mapping {
  id: string;
  provider_id: string;
  group: string;
  role: Role;
  created_at: string;
}

export interface SSOSettings {
  allow_admin_role: boolean;
  version: number;
}

export interface PublicProvider {
  id: string;
  name: string;
}

// The reasons the callback puts into /login?sso_error= (sso.<reason>), a closed set: any other value is ignored.
export const SSO_ERROR_REASONS = [
  'sso.no_access',
  'sso.groups_overage',
  'sso.email_in_use',
  'sso.idp_unreachable',
  'sso.login_invalid',
  'sso.login_expired',
  'sso.user_disabled',
  'sso.provider_disabled',
  'sso.stepup_other_user',
  'sso.idp_error',
] as const;

export function ssoErrorReason(value: string | null | undefined): string | null {
  return (SSO_ERROR_REASONS as readonly string[]).includes(value ?? '') ? (value as string) : null;
}

const v1 = '/api/v1';
const enc = encodeURIComponent;

// Public: the sign-in page lists the providers before anybody is signed in.
export const listPublicProviders = () => apiFetch<{ items: PublicProvider[] }>(`${v1}/auth/oidc/providers`, { publicRoute: true });
export const startSSO = (id: string, next: string) =>
  apiFetch<{ authorize_url: string }>(`${v1}/auth/oidc/${enc(id)}/start`, { method: 'POST', body: { next }, publicRoute: true });
export const startSSOStepUp = (next: string) => apiFetch<{ authorize_url: string }>(`${v1}/auth/oidc/stepup`, { method: 'POST', body: { next } });

export const listProviders = () => apiFetch<{ items: Provider[] }>(`${v1}/sso/providers`);
export const createProvider = (body: ProviderInput) => apiFetch<Provider>(`${v1}/sso/providers`, { method: 'POST', body });
export const updateProvider = (id: string, version: number, body: Partial<ProviderInput>) =>
  apiFetch<Provider>(`${v1}/sso/providers/${enc(id)}`, { method: 'PATCH', body, headers: ifMatch(version) });
export const deleteProvider = (id: string, version: number) => apiFetch<void>(`${v1}/sso/providers/${enc(id)}`, { method: 'DELETE', headers: ifMatch(version) });
export const refreshProvider = (id: string, version: number) =>
  apiFetch<Provider>(`${v1}/sso/providers/${enc(id)}/actions/refresh`, { method: 'POST', headers: ifMatch(version) });

export const listMappings = (providerId: string) => apiFetch<{ items: Mapping[] }>(`${v1}/sso/group-mappings?provider_id=${enc(providerId)}`);
export const createMapping = (body: { provider_id: string; group: string; role: Role }) => apiFetch<Mapping>(`${v1}/sso/group-mappings`, { method: 'POST', body });
// The server checks that the provider owns the mapping, so the provider is part of the request.
export const deleteMapping = (id: string, providerId: string) =>
  apiFetch<void>(`${v1}/sso/group-mappings/${enc(id)}?provider_id=${enc(providerId)}`, { method: 'DELETE' });

export const getSSOSettings = () => apiFetch<SSOSettings>(`${v1}/sso/settings`);
export const saveSSOSettings = (version: number, allow: boolean) =>
  apiFetch<SSOSettings>(`${v1}/sso/settings`, { method: 'PUT', body: { allow_admin_role: allow }, headers: ifMatch(version) });
