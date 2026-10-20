import { apiFetch } from './client';
import type { Certificate, DeployResult, ErrorRef, RevocationReason, RevocationReasonOrEmpty, ServiceRef } from './types';

// ACME certificate issuance (api/openapi.yaml, /api/v1/acme). The names follow the API's snake_case schemas. No type
// here carries a secret the server keeps: the EAB HMAC key and the DNS hook secret are write-only request fields
// (eab_configured, secret_configured say whether one is stored), and none of them is ever part of a query key.

export type ACMEPreset = '' | 'letsencrypt' | 'letsencrypt_staging' | 'zerossl' | 'custom';
export type ACMEAccountState = 'active' | 'pending_rollover' | 'retired' | 'deactivated';
export type ACMECertificateState = 'pending' | 'issuing' | 'active' | 'failing' | 'stopped';
export type ACMEChallenge = 'dns01' | 'http01';
export type ACMEKeyType = 'ecdsa_p256' | 'ecdsa_p384' | 'rsa_2048' | 'rsa_3072' | 'rsa_4096';
export type ACMEOrderKind = 'issue' | 'test';
export type ACMEOrderState = 'running' | 'succeeded' | 'failed';
export type ACMEOrderTrigger = 'manual' | 'renewal';
export type ACMEBindingState = 'current' | 'pending' | 'attention';
export type ACMEHeldReason = '' | 'license' | 'chain_incomplete';

export interface ACMEAccount {
  id: string;
  provider_id: string;
  contact_email: string;
  account_url: string;
  tos_url: string;
  tos_accepted_at: string | null;
  state: ACMEAccountState;
  created_at: string;
  updated_at: string;
}

export interface ACMEProvider {
  id: string;
  name: string;
  directory_url: string;
  preset: string;
  ca_bundle_pem: string;
  eab_kid: string;
  eab_configured: boolean;
  allowed_suffixes: string[];
  active_account_id: string | null;
  pending_rollover: boolean;
  created_at: string;
  updated_at: string;
  // GET of one provider only, newest first.
  accounts?: ACMEAccount[];
}

// eab_hmac is write-only (with eab_kid); absent keeps the stored one.
export interface ACMEProviderCreate {
  name: string;
  directory_url: string;
  preset?: ACMEPreset;
  ca_bundle_pem?: string;
  eab_kid?: string;
  eab_hmac?: string;
  allowed_suffixes?: string[];
}

export interface ACMEProviderPatch extends Partial<ACMEProviderCreate> {
  remove_eab?: boolean;
  confirm_directory_change?: boolean;
}

export interface ACMEAccountRegister {
  contact_email?: string;
  tos_accepted?: boolean;
  // The terms address the preview showed: the CA's terms changed when it differs now (422 ALC-ACM-0003).
  accepted_terms_url?: string;
}

// What the CA's directory says, read before the registration (POST .../preview). Both addresses are safe https links
// or "": terms_url_unsafe says the CA publishes terms at an address that is not one, and then no registration is offered.
export interface ACMEProviderPreview {
  terms_of_service_url: string;
  terms_url_unsafe: boolean;
  external_account_required: boolean;
  key_change_supported: boolean;
  renewal_info_supported: boolean;
  website: string;
}

export interface ACMEHook {
  id: string;
  name: string;
  url: string;
  ca_bundle_pem: string;
  secret_configured: boolean;
  allowed_suffixes: string[];
  propagation_wait_seconds: number;
  poll_timeout_seconds: number;
  created_at: string;
  updated_at: string;
}

// secret is write-only: required to create, absent on a change keeps the stored one.
export interface ACMEHookCreate {
  name: string;
  url: string;
  secret: string;
  ca_bundle_pem?: string;
  allowed_suffixes?: string[];
  propagation_wait_seconds?: number;
  poll_timeout_seconds?: number;
}

export type ACMEHookPatch = Partial<ACMEHookCreate>;

export interface ACMECurrentCertificate {
  id: string;
  fingerprint_sha256: string;
  not_before: string;
  not_after: string;
  chain_complete: boolean;
  revoked_at: string | null;
  revocation_reason: RevocationReasonOrEmpty;
  compromised: boolean;
}

export interface ACMEBinding {
  acme_certificate_id: string;
  location_id: string;
  target_id: string;
  target_name: string;
  cert_path: string;
  auto_deploy: boolean;
  state: ACMEBindingState;
  attention_at: string | null;
  attention: ErrorRef | null;
  served_certificate_id: string | null;
  created_at: string;
}

export interface ACMECertificate {
  service?: ServiceRef;
  id: string;
  provider_id: string;
  account_id: string;
  names: string[];
  key_type: string;
  challenge: ACMEChallenge;
  hook_id: string | null;
  http_target_id: string | null;
  renew_before_days: number;
  auto_renew: boolean;
  auto_deploy: boolean;
  state: ACMECertificateState;
  stopped_reason: '' | 'renewal_failures';
  failures: number;
  // The class of the last failure: an outage that clears by itself, or a cause that needs a person ('' without one).
  last_failure_class: ACMEFailureClass;
  // The permanent failures among them: 5 stop automatic renewal; outages never do while the certificate is valid.
  permanent_failures: number;
  // Stopped, but the last failure was an outage: Alice still orders it again by itself, slowly, until it expires.
  recovering: boolean;
  // When Alice may try again: the later of its own backoff and the CA's wait.
  next_attempt_at: string | null;
  // The CA asked Alice not to order again before this time (a rate limit's Retry-After; null when no such wait runs);
  // ca_wait_critical: the wait leaves less than half of the renewal window (the administrators were e-mailed).
  ca_not_before: string | null;
  ca_wait_critical: boolean;
  last_attempt_at: string | null;
  last_error: ErrorRef | null;
  running_order_id: string | null;
  current: ACMECurrentCertificate | null;
  ari_window: { start: string; end: string } | null;
  deploy_held_reason: ACMEHeldReason;
  deploy_stopped: boolean;
  bindings_count: number;
  // GET of one certificate only.
  bindings?: ACMEBinding[];
  // GET of one certificate only, absent before its first renewal e-mail: how the newest one was delivered.
  last_notice?: ACMENoticeDelivery;
  created_at: string;
  updated_at: string;
}

export type ACMEFailureClass = '' | 'transient' | 'permanent';

// The delivery of the newest renewal e-mail of a certificate: one copy per recipient, by outcome.
export interface ACMENoticeDelivery {
  template: string;
  queued_at: string;
  recipients: number;
  sent: number;
  pending: number;
  failed: number;
  skipped: number;
  sent_at: string | null;
  last_failure_code: string;
}

export interface ACMECertificateCreate {
  provider_id: string;
  names: string[];
  key_type?: ACMEKeyType;
  challenge: ACMEChallenge;
  hook_id?: string | null;
  http_target_id?: string | null;
  renew_before_days?: number;
  auto_renew?: boolean;
  auto_deploy?: boolean;
}

export type ACMECertificatePatch = Partial<ACMECertificateCreate>;

export interface ACMECertificatePage {
  items: ACMECertificate[];
  next_cursor: string | null;
}

export interface ACMECertificateQuery {
  state?: ACMECertificateState;
  provider_id?: string;
  q?: string;
  service_id?: string;
  environment_id?: string;
  cursor?: string;
  limit?: number;
}

export interface ACMEOrder {
  id: string;
  acme_certificate_id: string;
  kind: ACMEOrderKind;
  state: ACMEOrderState;
  trigger: ACMEOrderTrigger;
  started_at: string;
  finished_at: string | null;
  error: ErrorRef | null;
  certificate_id: string | null;
  requested_by: string | null;
  presented: number;
  cleanup_at: string | null;
  cleanup_error: ErrorRef | null;
  revoked_at: string | null;
  revocation_reason: RevocationReasonOrEmpty;
  compromised: boolean;
}

export interface ACMEDeploy {
  location_ids?: string[];
  confirm_incomplete_chain?: boolean;
}

// The enums of the schemas above, checked against api/openapi.yaml by acme.test.ts; each has a label in both languages.
export const ACME_PRESETS: readonly Exclude<ACMEPreset, ''>[] = ['letsencrypt', 'letsencrypt_staging', 'zerossl', 'custom'];
export const ACME_ACCOUNT_STATES: readonly ACMEAccountState[] = ['active', 'pending_rollover', 'retired', 'deactivated'];
export const ACME_CERTIFICATE_STATES: readonly ACMECertificateState[] = ['pending', 'issuing', 'active', 'failing', 'stopped'];
export const ACME_CHALLENGES: readonly ACMEChallenge[] = ['dns01', 'http01'];
export const ACME_KEY_TYPES: readonly ACMEKeyType[] = ['ecdsa_p256', 'ecdsa_p384', 'rsa_2048', 'rsa_3072', 'rsa_4096'];
export const ACME_ORDER_STATES: readonly ACMEOrderState[] = ['running', 'succeeded', 'failed'];
export const ACME_BINDING_STATES: readonly ACMEBindingState[] = ['current', 'pending', 'attention'];

// The directory addresses a preset fills in (the CAs' documented ACME v2 directories). A preset only pre-fills the
// form: nothing is contacted until the account is registered. "custom" (My own CA) leaves the address to the person.
export const PRESET_DIRECTORIES: Readonly<Record<Exclude<ACMEPreset, '' | 'custom'>, string>> = {
  letsencrypt: 'https://acme-v02.api.letsencrypt.org/directory',
  letsencrypt_staging: 'https://acme-staging-v02.api.letsencrypt.org/directory',
  zerossl: 'https://acme.zerossl.com/v2/DV90',
};

// The bounds of a DNS hook's waits (ACMEHookCreate): the propagation wait 0..120 s, the poll timeout 1..100 s, and
// both together at most 120 s.
export const HOOK_WAIT_MAX = 120;
export const HOOK_POLL_MIN = 1;
export const HOOK_POLL_MAX = 100;
export const HOOK_TOTAL_MAX = 120;
export const HOOK_SECRET_MIN = 16;
export const HOOK_SECRET_MAX = 256;

// A label key per enum value; a value from a newer server gets the neutral text.
const labelOf = (group: string, values: readonly string[]) => (v: string) => (values.includes(v) ? `acme.enum.${group}.${v}` : 'enum.unknown');
export const presetKey = labelOf('preset', ACME_PRESETS);
export const accountStateKey = labelOf('accountState', ACME_ACCOUNT_STATES);
export const certificateStateKey = labelOf('certificateState', ACME_CERTIFICATE_STATES);
export const challengeKey = labelOf('challenge', ACME_CHALLENGES);
export const keyTypeKey = labelOf('keyType', ACME_KEY_TYPES);
export const orderStateKey = labelOf('orderState', ACME_ORDER_STATES);
export const bindingStateKey = labelOf('bindingState', ACME_BINDING_STATES);

// directoryHost is the host of a directory or hook address, for the list (the full address is in the form).
export function directoryHost(url: string): string {
  try {
    return new URL(url).host || url;
  } catch {
    return url;
  }
}

// suffixProblem checks one allowed-name entry as the server does (inventory normDNSSuffix): an optional leading dot,
// then at least two DNS labels of letters, digits and hyphens (no hyphen at either end, at most 63 characters each), at
// most 253 characters. It answers the label key of the problem, or '' when the entry is fine. The server stays the
// judge; this only tells the person early.
export function suffixProblem(raw: string, existing: readonly string[] = []): string {
  const s = raw.trim();
  const body = s.startsWith('.') ? s.slice(1) : s;
  if (body === '') return 'acme.suffix.empty';
  if (body.length > 253) return 'acme.suffix.tooLong';
  const labels = body.split('.');
  if (labels.length < 2) return 'acme.suffix.twoLabels';
  for (const l of labels) if (!/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(l)) return 'acme.suffix.invalid';
  // Names are ASCII; the comparison ignores letter case as the server does.
  if (existing.some((e) => e.trim().localeCompare(s, 'en', { sensitivity: 'accent' }) === 0)) return 'acme.suffix.duplicate';
  return '';
}

const v1 = '/api/v1/acme';
const enc = encodeURIComponent;

// Providers (certificate authorities) and their accounts.
export const listACMEProviders = (signal?: AbortSignal) => apiFetch<{ items: ACMEProvider[] }>(`${v1}/providers`, { signal });
export const getACMEProvider = (id: string, signal?: AbortSignal) => apiFetch<ACMEProvider>(`${v1}/providers/${enc(id)}`, { signal });
export const createACMEProvider = (body: ACMEProviderCreate) => apiFetch<ACMEProvider>(`${v1}/providers`, { method: 'POST', body });
export const updateACMEProvider = (id: string, body: ACMEProviderPatch) => apiFetch<ACMEProvider>(`${v1}/providers/${enc(id)}`, { method: 'PATCH', body });
export const deleteACMEProvider = (id: string) => apiFetch<void>(`${v1}/providers/${enc(id)}`, { method: 'DELETE' });
// previewACMEProvider contacts the CA (its directory only) for the registration form: an Administrator, no step-up.
export const previewACMEProvider = (id: string, signal?: AbortSignal) =>
  apiFetch<ACMEProviderPreview>(`${v1}/providers/${enc(id)}/preview`, { method: 'POST', signal });
export const registerACMEAccount = (providerId: string, body: ACMEAccountRegister) =>
  apiFetch<ACMEAccount>(`${v1}/providers/${enc(providerId)}/account`, { method: 'POST', body });
export const rolloverACMEAccount = (id: string) => apiFetch<ACMEAccount>(`${v1}/accounts/${enc(id)}/rollover`, { method: 'POST' });
export const recoverACMERollover = (id: string) => apiFetch<ACMEAccount>(`${v1}/accounts/${enc(id)}/rollover/recover`, { method: 'POST' });
export const deactivateACMEAccount = (id: string) => apiFetch<ACMEAccount>(`${v1}/accounts/${enc(id)}/deactivate`, { method: 'POST' });

// DNS hooks.
export const listACMEHooks = (signal?: AbortSignal) => apiFetch<{ items: ACMEHook[] }>(`${v1}/hooks`, { signal });
export const getACMEHook = (id: string, signal?: AbortSignal) => apiFetch<ACMEHook>(`${v1}/hooks/${enc(id)}`, { signal });
export const createACMEHook = (body: ACMEHookCreate) => apiFetch<ACMEHook>(`${v1}/hooks`, { method: 'POST', body });
export const updateACMEHook = (id: string, body: ACMEHookPatch) => apiFetch<ACMEHook>(`${v1}/hooks/${enc(id)}`, { method: 'PATCH', body });
export const deleteACMEHook = (id: string) => apiFetch<void>(`${v1}/hooks/${enc(id)}`, { method: 'DELETE' });

// ACME certificates (Issued certificates), their orders, bindings and deployments.
export function listACMECertificates(query: ACMECertificateQuery = {}, signal?: AbortSignal) {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) if (v !== undefined && v !== '') p.set(k, String(v));
  const qs = p.toString();
  return apiFetch<ACMECertificatePage>(`${v1}/certificates${qs ? `?${qs}` : ''}`, { signal });
}
export const getACMECertificate = (id: string, signal?: AbortSignal) => apiFetch<ACMECertificate>(`${v1}/certificates/${enc(id)}`, { signal });
export const createACMECertificate = (body: ACMECertificateCreate) => apiFetch<ACMECertificate>(`${v1}/certificates`, { method: 'POST', body });
export const updateACMECertificate = (id: string, body: ACMECertificatePatch) =>
  apiFetch<ACMECertificate>(`${v1}/certificates/${enc(id)}`, { method: 'PATCH', body });
export const deleteACMECertificate = (id: string) => apiFetch<void>(`${v1}/certificates/${enc(id)}`, { method: 'DELETE' });
export const orderACMECertificate = (id: string) => apiFetch<ACMEOrder>(`${v1}/certificates/${enc(id)}/order`, { method: 'POST' });
export const testACMECertificate = (id: string) => apiFetch<ACMEOrder>(`${v1}/certificates/${enc(id)}/test`, { method: 'POST' });
export const listACMEOrders = (id: string, limit?: number, signal?: AbortSignal) =>
  apiFetch<{ items: ACMEOrder[] }>(`${v1}/certificates/${enc(id)}/orders${limit ? `?limit=${limit}` : ''}`, { signal });
export const rearmACMECertificate = (id: string) => apiFetch<ACMECertificate>(`${v1}/certificates/${enc(id)}/rearm`, { method: 'POST' });
export const releaseACMEHold = (id: string) => apiFetch<ACMECertificate>(`${v1}/certificates/${enc(id)}/release-hold`, { method: 'POST' });
export const listACMEBindings = (id: string, signal?: AbortSignal) => apiFetch<{ items: ACMEBinding[] }>(`${v1}/certificates/${enc(id)}/bindings`, { signal });
export const putACMEBinding = (id: string, locationId: string, autoDeploy: boolean) =>
  apiFetch<ACMEBinding>(`${v1}/certificates/${enc(id)}/bindings/${enc(locationId)}`, { method: 'PUT', body: { auto_deploy: autoDeploy } });
export const deleteACMEBinding = (id: string, locationId: string) =>
  apiFetch<void>(`${v1}/certificates/${enc(id)}/bindings/${enc(locationId)}`, { method: 'DELETE' });
// revokeACMECertificate revokes a version (none named: the current certificate) at the CA; it cannot be undone.
export const revokeACMECertificate = (id: string, reason: RevocationReason, certificateId?: string) =>
  apiFetch<Certificate>(`${v1}/certificates/${enc(id)}/revoke`, {
    method: 'POST',
    body: certificateId ? { reason, certificate_id: certificateId } : { reason },
  });
export const deployACMECertificate = (id: string, body: ACMEDeploy = {}) =>
  apiFetch<DeployResult>(`${v1}/certificates/${enc(id)}/deploy`, { method: 'POST', body });
