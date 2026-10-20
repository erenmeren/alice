import { apiFetch } from './client';
import type { ErrorRef, JobAccepted } from './types';

// Azure Key Vault (Phase 5): the wire types and calls of the vault routes (api/openapi.yaml). A
// vault is a Target of type azure_key_vault; its inventory lives under /targets/{id}/kv/….
// Secrets (client secret, private key, PFX and its password) appear in requests only; the caller
// keeps them in component state for the length of the form and clears them afterwards.

const v1 = '/api/v1';
const enc = encodeURIComponent;

export type VaultAuth = 'certificate' | 'client_secret' | 'managed_identity';
export const VAULT_AUTHS: readonly VaultAuth[] = ['certificate', 'client_secret', 'managed_identity'];

export type AccessResult = 'ok' | 'forbidden' | 'failed' | 'not_checked';
export type AccessCheckName = 'sign_in' | 'list_certificates' | 'list_keys' | 'list_secrets' | 'read_secret' | 'import';
export type AzureRole = '' | 'Key Vault Reader' | 'Key Vault Secrets User' | 'Key Vault Certificates Officer';

export interface AccessCheckRow {
  name: AccessCheckName;
  result: AccessResult;
  // role is the Azure role that would allow the call (never translated).
  role: AzureRole;
  error: ErrorRef | null;
}

export interface VaultAccess {
  object_id: string;
  tenant_id: string;
  permission_model: '' | 'rbac' | 'access_policy' | 'unknown';
  checks: AccessCheckRow[];
  checked_at: string;
}

export interface Vault {
  url: string;
  name: string;
  auth: VaultAuth;
  tenant_id: string;
  client_id: string;
  poll_interval_minutes: number;
  secret_expires_on: string | null;
  cert_thumbprint: string;
  cert_not_after: string | null;
  access: VaultAccess | null;
}

// VaultSignIn is the sign-in part shared by adding a vault and replacing its credentials.
export interface VaultSignIn {
  auth: VaultAuth;
  tenant_id?: string;
  client_id?: string;
  client_secret?: string;
  secret_expires_on?: string;
  certificate_pem?: string;
  private_key_pem?: string;
  pfx_base64?: string;
  pfx_password?: string;
}

export interface VaultCreateRequest extends VaultSignIn {
  name: string;
  vault_url: string;
  poll_interval_minutes?: number;
}

export interface VaultWithAccess {
  target: import('./types').Target;
  access: VaultAccess | null;
  job_id: string | null;
}

export interface VaultCreated extends VaultWithAccess {
  job_id: string;
  status_url: string;
}

export interface KVCertificate {
  id: string;
  target_id: string;
  name: string;
  current_version: string;
  current_thumbprint: string;
  enabled: boolean;
  not_before: string | null;
  expires: string | null;
  kv_created_at: string | null;
  kv_updated_at: string | null;
  exportable: boolean | null;
  key_type: string;
  key_size: number;
  content_type: string;
  issuer_name: string;
  auto_renew: boolean;
  details_pending: boolean;
  first_seen_at: string;
  last_seen_at: string;
  missing_since: string | null;
  bound: boolean;
  current_held: boolean;
  current_held_reason: '' | 'license' | 'incomplete_chain';
}

export interface KVVersion {
  id: string;
  version: string;
  thumbprint: string;
  certificate_id: string | null;
  enabled: boolean;
  not_before: string | null;
  expires: string | null;
  kv_created_at: string | null;
  exportable: boolean | null;
  key_type: string;
  content_type: string;
  detected_at: string;
  held: boolean;
  held_reason: '' | 'license' | 'incomplete_chain';
  // The last read of the version's secret found its chain incomplete: every manual deployment needs an
  // Administrator's confirmation, held or released alike.
  chain_incomplete: boolean;
}

export interface BindingSummary {
  id: string;
  auto_deploy: boolean;
  auto_since: string | null;
  stopped_version: string;
  location_count: number;
  version: number;
  created_at: string;
}

export type DeployAccess = 'ok' | 'forbidden' | 'not_checked';

export interface KVCertificateDetail extends KVCertificate {
  versions: KVVersion[];
  binding: BindingSummary | null;
  deploy_access: DeployAccess;
}

export interface KVKey {
  id: string;
  target_id: string;
  name: string;
  version: string;
  key_type: string;
  curve: string;
  key_size: number;
  hsm: boolean;
  managed: boolean;
  enabled: boolean;
  details_updated_at: string | null;
  details_problem: '' | 'forbidden' | 'failed';
  not_before: string | null;
  expires: string | null;
  kv_created_at: string | null;
  kv_updated_at: string | null;
  first_seen_at: string;
  last_seen_at: string;
  missing_since: string | null;
}

export interface KVSecret {
  id: string;
  target_id: string;
  name: string;
  content_type: string;
  managed: boolean;
  enabled: boolean;
  not_before: string | null;
  expires: string | null;
  kv_created_at: string | null;
  kv_updated_at: string | null;
  first_seen_at: string;
  last_seen_at: string;
  missing_since: string | null;
}

export interface Page<T> {
  items: T[];
  next_cursor: string | null;
}

export type BindingLocationState = 'not_deployed' | 'pending' | 'deployed' | 'failed' | 'stopped';

export interface BindingLocation {
  location_id: string;
  target_id: string;
  target_name: string;
  cert_path: string;
  state: BindingLocationState;
  version: string;
  deployment_id: string | null;
  // "service.untrusted": the website's server is in a service that does not accept the vault's keys (R49); automatic
  // deployment holds there until a trust allows it. "" otherwise (absent from an older answer).
  attention_code?: string;
}

export interface Binding {
  id: string;
  kv_certificate_id: string;
  vault_id: string;
  certificate_name: string;
  vault_name: string;
  auto_deploy: boolean;
  auto_since: string | null;
  stopped_version: string;
  location_count: number;
  version: number;
  created_at: string;
  created_by: string | null;
  locations: BindingLocation[];
}

export interface DeployableLocation {
  id: string;
  target_id: string;
  target_name: string;
  cert_path: string;
  key_path: string;
  key_type: '' | 'rsa' | 'ecdsa';
  server_names: string[];
  binding_id: string | null;
}

export interface BindingDeployResult {
  deployments: { id: string; job_id: string; location_id: string; status_url: string; deployment_url: string; warnings: string[] }[];
}

// '' is a state this version does not know (the API sends it instead of inventing one).
export type ImportState = '' | 'queued' | 'running' | 'succeeded' | 'failed' | 'uncertain';

export interface KVImport {
  id: string;
  certificate_id: string;
  target_id: string;
  name: string;
  new_version: boolean;
  state: ImportState;
  version: string;
  thumbprint: string;
  error: ErrorRef | null;
  can_retry: boolean;
  job_id: string | null;
  requested_by: string | null;
  created_at: string;
  sent_at: string | null;
  finished_at: string | null;
}

export interface ImportAccepted extends JobAccepted {
  import: KVImport;
}

export interface ListQuery {
  q?: string;
  expires_before?: string;
  missing?: 'include' | 'only';
  cursor?: string | null;
  limit?: number;
}

function qs(params: Record<string, string | number | boolean | null | undefined>): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== '' && v !== false) p.set(k, String(v));
  const s = p.toString();
  return s ? `?${s}` : '';
}

const etag = (version: number) => ({ 'If-Match': `"${version}"` });

// Vaults. Adding and replacing credentials need an Administrator with a fresh step-up (wrap in useStepUp().run).
export const createVault = (req: VaultCreateRequest) => apiFetch<VaultCreated>(`${v1}/key-vaults`, { method: 'POST', body: req });

export const replaceVaultCredentials = (id: string, version: number, req: VaultSignIn) =>
  apiFetch<VaultWithAccess>(`${v1}/targets/${enc(id)}/vault-credentials`, { method: 'PUT', body: req, headers: etag(version) });

export const updateVaultInterval = (id: string, version: number, minutes: number) =>
  apiFetch<import('./types').Target>(`${v1}/targets/${enc(id)}`, { method: 'PATCH', body: { poll_interval_minutes: minutes }, headers: etag(version) });

export const deleteVault = (id: string, removeBindings = false) =>
  apiFetch<void>(`${v1}/targets/${enc(id)}${removeBindings ? '?remove_bindings=true' : ''}`, { method: 'DELETE' });

export const runAccessCheck = (id: string, readSecretOf?: string) =>
  apiFetch<JobAccepted>(`${v1}/targets/${enc(id)}/actions/test`, readSecretOf ? { method: 'POST', body: { read_secret_of: readSecretOf } } : { method: 'POST' });

export const checkVaultNow = (id: string) => apiFetch<JobAccepted>(`${v1}/targets/${enc(id)}/actions/discover`, { method: 'POST' });

// Inventory.
const list = <T>(kind: 'certificates' | 'keys' | 'secrets', vaultId: string, q: ListQuery) =>
  apiFetch<Page<T>>(`${v1}/targets/${enc(vaultId)}/kv/${kind}${qs({ ...q })}`);
export const listKVCertificates = (vaultId: string, q: ListQuery = {}) => list<KVCertificate>('certificates', vaultId, q);
export const listKVKeys = (vaultId: string, q: ListQuery = {}) => list<KVKey>('keys', vaultId, q);
export const listKVSecrets = (vaultId: string, q: ListQuery = {}) => list<KVSecret>('secrets', vaultId, q);

export const getKVCertificate = (vaultId: string, id: string) =>
  apiFetch<KVCertificateDetail>(`${v1}/targets/${enc(vaultId)}/kv/certificates/${enc(id)}`);

export const releaseKVVersion = (vaultId: string, certificateId: string, versionId: string, confirmIncompleteChain: boolean) =>
  apiFetch<KVVersion>(`${v1}/targets/${enc(vaultId)}/kv/certificates/${enc(certificateId)}/versions/${enc(versionId)}/actions/release`, {
    method: 'POST',
    body: confirmIncompleteChain ? { confirm_incomplete_chain: true } : {},
  });

// Bindings (Connected websites).
export const listDeployableLocations = (q: { key_type?: string; unbound?: boolean; q?: string; cursor?: string | null; limit?: number }) =>
  apiFetch<Page<DeployableLocation>>(`${v1}/certificate-locations${qs({ ...q })}`);

export const createBinding = (kvCertificateId: string, locationIds: string[]) =>
  apiFetch<Binding>(`${v1}/bindings`, { method: 'POST', body: { kv_certificate_id: kvCertificateId, location_ids: locationIds } });

export const getBinding = (id: string) => apiFetch<Binding>(`${v1}/bindings/${enc(id)}`);

export const updateBindingLocations = (id: string, version: number, locationIds: string[]) =>
  apiFetch<Binding>(`${v1}/bindings/${enc(id)}`, { method: 'PATCH', body: { location_ids: locationIds }, headers: etag(version) });

export const setAutoDeploy = (id: string, version: number, enabled: boolean) =>
  apiFetch<Binding>(`${v1}/bindings/${enc(id)}/auto-deploy`, { method: 'PUT', body: { enabled }, headers: etag(version) });

export const deleteBinding = (id: string) => apiFetch<void>(`${v1}/bindings/${enc(id)}`, { method: 'DELETE' });

export const deployBinding = (id: string, versionId: string, locationIds: string[], confirmIncompleteChain: boolean) =>
  apiFetch<BindingDeployResult>(`${v1}/bindings/${enc(id)}/actions/deploy`, {
    method: 'POST',
    body: { version_id: versionId, location_ids: locationIds, ...(confirmIncompleteChain ? { confirm_incomplete_chain: true } : {}) },
  });

// Imports.
export const importToKeyVault = (certificateId: string, vaultId: string, name: string, confirmNewVersion: boolean) =>
  apiFetch<ImportAccepted>(`${v1}/certificates/${enc(certificateId)}/actions/import-to-key-vault`, {
    method: 'POST',
    body: { target_id: vaultId, name, ...(confirmNewVersion ? { confirm_new_version: true } : {}) },
  });

export const listKVImports = (vaultId: string, certificateId?: string, limit = 50, cursor?: string | null) =>
  apiFetch<Page<KVImport>>(`${v1}/targets/${enc(vaultId)}/kv/imports${qs({ certificate_id: certificateId, limit, cursor })}`);

export const getKVImport = (vaultId: string, id: string) => apiFetch<KVImport>(`${v1}/targets/${enc(vaultId)}/kv/imports/${enc(id)}`);
