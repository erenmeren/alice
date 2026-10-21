import { apiFetch } from './client';
import type { Certificate, ErrorRef, SourceCapability } from './types';

// The impact of a certificate, the per-source capability matrix and key-compromise incidents (api/openapi.yaml;
// docs/superpowers/rulings/certificate-revocation.md). Public data only: no key ever reaches the browser.

export type ImpactMatch = 'certificate' | 'key';
export type IncidentState = 'awaiting_replacement' | 'ordering' | 'deploying' | 'revoking' | 'needs_attention' | 'completed' | 'closed';
export type IncidentRevocation = 'pending' | 'revoked' | 'failed' | 'not_possible';
export type IncidentRevokeMode = 'after_verified' | 'now';
export type IncidentLocationStatus = 'pending' | 'deploying' | 'verified' | 'unverified' | 'failed' | 'skipped';

// The enums above, checked against api/openapi.yaml by incidents.test.ts; each has a label in both languages.
export const INCIDENT_STATES: readonly IncidentState[] = ['awaiting_replacement', 'ordering', 'deploying', 'revoking', 'needs_attention', 'completed', 'closed'];
export const INCIDENT_REVOCATIONS: readonly IncidentRevocation[] = ['pending', 'revoked', 'failed', 'not_possible'];
export const INCIDENT_LOCATION_STATUSES: readonly IncidentLocationStatus[] = ['pending', 'deploying', 'verified', 'unverified', 'failed', 'skipped'];

export interface ImpactCertificate {
  id: string;
  fingerprint: string;
  subject_cn: string;
  label: string;
  source: string;
  not_after: string;
  revoked_at: string | null;
  compromised_at: string | null;
  match: ImpactMatch;
}

export interface ImpactLocation {
  location_id: string;
  target_id: string;
  target_name: string;
  target_type: string;
  cert_path: string;
  certificate_id: string | null;
  fingerprint: string;
  match: ImpactMatch;
  deployable: boolean;
  acme_certificate_id: string | null;
  kv_bound: boolean;
}

export interface ImpactVault {
  vault_id: string;
  vault_name: string;
  kv_certificate_id: string;
  name: string;
  version: string;
  certificate_id: string;
  current: boolean;
  match: ImpactMatch;
}

export interface ImpactEndpoint {
  endpoint_id: string;
  scope_id: string;
  scope_name: string;
  address: string;
  port: number;
  sni: string;
  host: string;
  fingerprint: string;
  state: 'present' | 'unreachable';
  last_seen: string | null;
  match: ImpactMatch;
}

export interface CertificateImpact {
  certificate: Certificate;
  certificates: ImpactCertificate[];
  locations: ImpactLocation[];
  vaults: ImpactVault[];
  endpoints: ImpactEndpoint[];
  endpoints_hidden: boolean;
  truncated: boolean;
  open_incident_id: string | null;
  // Certificates, locations and Key Vault versions with the key outside the reader's services, left out (R49 Phase 2).
  hidden_count?: number;
}

export interface SourceCapabilities {
  capabilities: SourceCapability[];
  sources: { source: string; capabilities: SourceCapability[] }[];
}

export interface IncidentLocation {
  location_id: string;
  target_id: string;
  target_name: string;
  cert_path: string;
  status: IncidentLocationStatus;
  deployment_id: string | null;
  error: ErrorRef | null;
  attempts: number;
  updated_at: string;
  // Sent but not confirmed (R48): never counted as replaced.
  outcome_uncertain: boolean;
}

export interface Incident {
  id: string;
  certificate_id: string;
  certificate_name: string;
  fingerprint: string;
  source: string;
  public_key_sha256: string;
  acme_certificate_id: string | null;
  state: IncidentState;
  revoke_mode: IncidentRevokeMode;
  revocation: IncidentRevocation;
  order_id: string | null;
  order_state: '' | 'running' | 'succeeded' | 'failed';
  replacement_certificate_id: string | null;
  replacement_fingerprint: string;
  attention: ErrorRef | null;
  revoke_attempts: number;
  next_attempt_at: string | null;
  revoked_at: string | null;
  started_by: string | null;
  started_by_name: string;
  closed_by: string | null;
  created_at: string;
  updated_at: string;
  finished_at: string | null;
  counts: Partial<Record<IncidentLocationStatus, number>>;
  locations?: IncidentLocation[];
  // With locations: those on servers outside the reader's services, left out (R49 Phase 2).
  hidden_count?: number;
}

// An incident is open until completed or closed.
export const incidentOpen = (i: Pick<Incident, 'finished_at'>) => i.finished_at === null;

const v1 = '/api/v1';
const enc = encodeURIComponent;

export const getCertificateImpact = (id: string, signal?: AbortSignal) => apiFetch<CertificateImpact>(`${v1}/certificate-impact/${enc(id)}`, { signal });
export const getCertificateCapabilities = (signal?: AbortSignal) => apiFetch<SourceCapabilities>(`${v1}/certificates/capabilities`, { signal });
export const startIncident = (certificateId: string, revokeMode: IncidentRevokeMode) =>
  apiFetch<Incident>(`${v1}/certificates/${enc(certificateId)}/incidents`, { method: 'POST', body: { revoke_mode: revokeMode } });
export function listIncidents(q: { open?: boolean; certificate_id?: string } = {}, signal?: AbortSignal) {
  const p = new URLSearchParams();
  if (q.open) p.set('open', 'true');
  if (q.certificate_id) p.set('certificate_id', q.certificate_id);
  const qs = p.toString();
  return apiFetch<{ items: Incident[] }>(`${v1}/incidents${qs ? `?${qs}` : ''}`, { signal });
}
export const getIncident = (id: string, signal?: AbortSignal) => apiFetch<Incident>(`${v1}/incidents/${enc(id)}`, { signal });
export const retryIncident = (id: string) => apiFetch<Incident>(`${v1}/incidents/${enc(id)}/retry`, { method: 'POST' });
export const revokeIncidentNow = (id: string) => apiFetch<Incident>(`${v1}/incidents/${enc(id)}/revoke-now`, { method: 'POST' });
export const closeIncident = (id: string) => apiFetch<Incident>(`${v1}/incidents/${enc(id)}/close`, { method: 'POST' });
export const chooseIncidentReplacement = (id: string, certificateId: string) =>
  apiFetch<Incident>(`${v1}/incidents/${enc(id)}/replacement`, { method: 'POST', body: { certificate_id: certificateId } });

// The incident page polls while Alice works on the incident (ordering, deploying, revoking).
export const INCIDENT_POLL_MS = 5000;
export const incidentBusy = (i: Pick<Incident, 'state' | 'finished_at'>) => i.finished_at === null && ['ordering', 'deploying', 'revoking'].includes(i.state);
