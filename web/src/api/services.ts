import { apiFetch } from './client';
import type { EnvironmentRef, ServiceRef } from './types';

export type { EnvironmentRef, ServiceRef };

// Services and environments (R49, api/openapi.yaml /api/v1/services, /api/v1/environments, /api/v1/service-trusts). A
// service groups servers, Key Vaults, certificates, signing requests, ACME certificates, SSH keys and scan scopes; every
// resource belongs to one, the Default service when nobody chose another. Reading is every role's; creating, changing,
// moving resources and trusts are an Administrator's with a fresh step-up (services.manage, services.assign,
// services.trust), never an API token.

export interface Environment {
  id: string;
  key: string;
  name: string;
  sort: number;
  version: number;
  // How many services carry the environment (one in use cannot be deleted).
  services: number;
  created_at: string;
  updated_at: string;
}

export interface ServiceCounts {
  servers: number;
  key_vaults: number;
  certificates: number;
  signing_requests: number;
  acme_certificates: number;
  ssh_keys: number;
  discovery_scopes: number;
}

export interface Service {
  id: string;
  name: string;
  description: string;
  environment: EnvironmentRef | null;
  is_default: boolean;
  policy_version: number;
  version: number;
  counts: ServiceCounts;
  created_at: string;
  updated_at: string;
}

export interface ServiceCreate {
  name: string;
  description?: string;
  environment_id?: string | null;
}

// environment_id null removes the environment; absent keeps it.
export interface ServicePatch {
  name?: string;
  description?: string;
  environment_id?: string | null;
}

export interface ServicePolicy {
  version: number;
  body: Record<string, unknown>;
  created_by: string | null;
  created_by_name: string;
  created_at: string;
}

export interface ServiceTrust {
  id: string;
  // target accepts certificates and SSH keys owned by source.
  source: ServiceRef;
  target: ServiceRef;
  created_by_name: string;
  created_at: string;
}

export type AssignType = 'target' | 'certificate' | 'csr' | 'ssh_key' | 'acme_certificate' | 'discovery_scope';

export interface AssignResource {
  type: AssignType;
  id: string;
}

export interface AssignMove {
  type: AssignType;
  id: string;
  name: string;
  from: ServiceRef;
  // false: the resource is in the destination already.
  changed: boolean;
}

// A binding location that crosses services without a trust after the move: its automatic deployments stop there.
export interface UntrustedBinding {
  kind: 'key_vault' | 'acme';
  source_id: string;
  source_name: string;
  location_id: string;
  target_id: string;
  target_name: string;
  source_service: ServiceRef;
  target_service: ServiceRef;
}

export interface AssignResult {
  dry_run: boolean;
  destination: ServiceRef;
  moves: AssignMove[];
  untrusted: UntrustedBinding[];
}

export const ASSIGN_TYPES: readonly AssignType[] = ['target', 'certificate', 'csr', 'ssh_key', 'acme_certificate', 'discovery_scope'];
// The keys of the seeded environments: the UI names them in the reader's language until an Administrator renames one.
export const SEEDED_ENVIRONMENTS: Record<string, string> = { production: 'Production', staging: 'Staging', test: 'Test', development: 'Development' };
export const MAX_SERVICE_NAME = 100;
export const MAX_SERVICE_DESCRIPTION = 500;
export const MAX_ENVIRONMENT_NAME = 60;
export const ENVIRONMENT_KEY_RE = /^[a-z][a-z0-9-]{0,31}$/;

const v1 = '/api/v1';
const enc = encodeURIComponent;
const ifMatch = (version: number) => ({ 'If-Match': `"${version}"` });

// The filters of a list page (design §5.8): rows of one service or of the services of one environment.
export interface ServiceFilter {
  service_id?: string;
  environment_id?: string;
}

// addServiceFilter adds the filters to a query string.
export function addServiceFilter(params: URLSearchParams, f: ServiceFilter): void {
  if (f.service_id) params.set('service_id', f.service_id);
  if (f.environment_id) params.set('environment_id', f.environment_id);
}

// inServiceFilter reports whether a row passes the filters (lists read completely filter in the browser).
export function inServiceFilter(service: ServiceRef | undefined | null, f: ServiceFilter): boolean {
  if (f.service_id && service?.id !== f.service_id) return false;
  if (f.environment_id && service?.environment?.id !== f.environment_id) return false;
  return true;
}

export const listEnvironments = (signal?: AbortSignal) => apiFetch<{ items: Environment[] }>(`${v1}/environments`, { signal });
export const createEnvironment = (body: { key: string; name: string; sort?: number }) =>
  apiFetch<Environment>(`${v1}/environments`, { method: 'POST', body });
export const updateEnvironment = (id: string, version: number, body: { name?: string; sort?: number }) =>
  apiFetch<Environment>(`${v1}/environments/${enc(id)}`, { method: 'PATCH', body, headers: ifMatch(version) });
export const deleteEnvironment = (id: string, version: number) =>
  apiFetch<void>(`${v1}/environments/${enc(id)}`, { method: 'DELETE', headers: ifMatch(version) });

export const listServices = (signal?: AbortSignal) => apiFetch<{ items: Service[] }>(`${v1}/services`, { signal });
export const getService = (id: string, signal?: AbortSignal) => apiFetch<Service>(`${v1}/services/${enc(id)}`, { signal });
export const createService = (body: ServiceCreate) => apiFetch<Service>(`${v1}/services`, { method: 'POST', body });
export const updateService = (id: string, version: number, body: ServicePatch) =>
  apiFetch<Service>(`${v1}/services/${enc(id)}`, { method: 'PATCH', body, headers: ifMatch(version) });
export const deleteService = (id: string, version: number) => apiFetch<void>(`${v1}/services/${enc(id)}`, { method: 'DELETE', headers: ifMatch(version) });
export const getServicePolicy = (id: string, signal?: AbortSignal) => apiFetch<ServicePolicy>(`${v1}/services/${enc(id)}/policy`, { signal });

// assignToService moves resources to the service (dryRun: only what the move would do; nothing changes).
export const assignToService = (id: string, resources: AssignResource[], dryRun: boolean) =>
  apiFetch<AssignResult>(`${v1}/services/${enc(id)}/actions/assign${dryRun ? '?dry_run=true' : ''}`, { method: 'POST', body: { resources } });

export const listTrusts = (serviceId?: string, signal?: AbortSignal) =>
  apiFetch<{ items: ServiceTrust[] }>(`${v1}/service-trusts${serviceId ? `?service_id=${enc(serviceId)}` : ''}`, { signal });
export const createTrust = (sourceServiceId: string, targetServiceId: string) =>
  apiFetch<ServiceTrust>(`${v1}/service-trusts`, { method: 'POST', body: { source_service_id: sourceServiceId, target_service_id: targetServiceId } });
export const deleteTrust = (id: string) => apiFetch<void>(`${v1}/service-trusts/${enc(id)}`, { method: 'DELETE' });
