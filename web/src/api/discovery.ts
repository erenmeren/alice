import { ApiError, apiFetch } from './client';
import type { OwnerService, RevocationCheck } from './types';

// Network certificate discovery (api/openapi.yaml, /api/v1/discovery). The names follow the API's snake_case schemas.
// Nothing here is secret: scopes, scans and the certificates found are public facts of the network. The map of the
// network is sensitive all the same, so every route needs discovery.view (all three roles in a browser; an API token
// needs the operate scope: decision D7). Defining scopes and the settings is discovery.manage (an Administrator with a
// fresh step-up); starting and cancelling scans is discovery.operate (Operators and Administrators).

export type DiscoveryScanState = 'queued' | 'running' | 'done' | 'cancelled' | 'timed_out' | 'failed';
export type DiscoveryScanTrigger = 'manual' | 'schedule';
// managed: Alice has this exact certificate on a live location of a live server; known: Alice has it, on no live
// location; unmanaged: Alice has no record of it (the ledger's ruling of Task 7).
export type DiscoveredStatus = 'unmanaged' | 'managed' | 'known';
export type DiscoveredStatusFilter = 'all' | DiscoveredStatus;
export type DiscoveredEndpointState = 'present' | 'unreachable' | 'gone' | 'no_tls' | 'excluded' | 'malformed';
export type DiscoveredEndpointError = '' | 'refused' | 'timeout' | 'no_tls' | 'reset' | 'chain_too_large' | 'policy' | 'malformed';
export type DiscoveredKeyAlgorithm = 'rsa' | 'ecdsa' | 'ed25519' | 'other';

export interface DiscoveryScan {
  id: string;
  scope_id: string;
  scope_name: string;
  trigger: DiscoveryScanTrigger;
  state: DiscoveryScanState;
  cancel_requested: boolean;
  endpoints_total: number;
  endpoints_answered: number;
  endpoints_failed: number;
  endpoints_excluded: number;
  certificates_new: number;
  cert_churn: number;
  requested_by: string | null;
  queued_at: string;
  started_at: string | null;
  finished_at: string | null;
  // The ALC code and the stable reason (discovery.* or license.*) of a scan that ended without finishing.
  error_code: string | null;
  error_reason: string | null;
}

export interface DiscoveryScope {
  service?: OwnerService;
  // What the caller may do with the row: the permissions held on its owning service (omitted when none).
  allowed_actions?: string[];
  id: string;
  name: string;
  entries: string[];
  ports: number[];
  sni_names: string[];
  exclusions: string[];
  enabled: boolean;
  // 0: no schedule. window_start/window_end are "HH:MM" or "" (no window), never null; window_tz is UTC when none was given.
  schedule_hours: number;
  window_start: string;
  window_end: string;
  window_tz: string;
  alert_on_expiry: boolean;
  rate_per_sec: number;
  concurrency: number;
  version: number;
  created_by: string | null;
  created_at: string;
  updated_at: string;
  last_scheduled_at: string | null;
  active_scan_id: string | null;
  last_scan: DiscoveryScan | null;
}

export interface DiscoveryScopeCreate {
  name: string;
  entries: string[];
  ports: number[];
  sni_names?: string[];
  exclusions?: string[];
  enabled?: boolean;
  schedule_hours?: number;
  window_start?: string;
  window_end?: string;
  window_tz?: string;
  alert_on_expiry?: boolean;
  rate_per_sec?: number;
  concurrency?: number;
}

// The four schedule fields are one group: sending any of them replaces the whole schedule (an absent one is 0 or "").
export type DiscoveryScopePatch = Partial<DiscoveryScopeCreate>;

export interface DiscoveryPreview {
  addresses: number;
  excluded_addresses: number;
  hostnames: number;
  ports: number;
  sni_names: number;
  endpoints: number;
  builtin_exclusions: string[];
}

export interface DiscoveredEndpoint {
  id: string;
  scope_id: string;
  address: string;
  port: number;
  sni: string;
  host: string;
  fingerprint_sha256: string | null;
  // The leaves it presented before its current one, newest first (its rotations).
  previous_fingerprints: string[];
  chain_length: number;
  tls_version: string;
  cipher: string;
  state: DiscoveredEndpointState;
  last_error_code: DiscoveredEndpointError;
  missed_scans: number;
  first_seen: string;
  last_seen: string | null;
  last_scanned_at: string;
  gone_since: string | null;
  target: { id: string; name: string } | null;
}

export interface DiscoveredCertificate {
  fingerprint_sha256: string;
  subject_cn: string;
  sans: string[];
  issuer_cn: string;
  not_before: string;
  not_after: string;
  days_left: number;
  expired: boolean;
  key_algorithm: DiscoveredKeyAlgorithm;
  self_signed: boolean;
  status: DiscoveredStatus;
  managed_certificate_id: string | null;
  // Endpoints presenting it now.
  endpoint_count: number;
  seen_on_count: number;
  first_seen: string;
  last_seen: string;
  // The detail only (at most 200).
  endpoints?: DiscoveredEndpoint[];
  more_endpoints?: boolean;
  // The detail only: the last revocation check, null before the first (R66).
  revocation_check?: RevocationCheck | null;
}

export interface DiscoverySettings {
  allowed_networks: string[];
  global_exclusions: string[];
  retention_days: number;
  // False while no allowed scan network is set: nothing may be scanned then.
  scanning_enabled: boolean;
  builtin_exclusions: string[];
}

export interface DiscoverySettingsInput {
  allowed_networks: string[];
  global_exclusions: string[];
  retention_days: number;
}

export interface DiscoverySummary {
  unmanaged_total: number;
  unmanaged_expiring_30d: number;
  scopes: number;
  last_scan_at: string | null;
}

// Page is one keyset page of a list: next_cursor is null on the last page.
export interface Page<T> {
  items: T[];
  next_cursor: string | null;
}

export interface CertificateQuery {
  status?: DiscoveredStatusFilter;
  expiring_within_days?: number;
  expired?: boolean;
  self_signed?: boolean;
  // current: only certificates still found (an endpoint that is not gone presents or last presented it), the summary's
  // definition; without it a certificate stays listed until retention removes it.
  current?: boolean;
  q?: string;
  scope_id?: string;
}

export interface ScanQuery {
  scope_id?: string;
  state?: DiscoveryScanState;
}

export interface EndpointQuery {
  scope_id?: string;
  fingerprint?: string;
}

interface Paging {
  cursor?: string | null;
  limit?: number;
}

// The enums of the schemas above, checked against api/openapi.yaml by discovery.test.ts; each has a label in both languages.
export const SCAN_STATES: readonly DiscoveryScanState[] = ['queued', 'running', 'done', 'cancelled', 'timed_out', 'failed'];
export const SCAN_TRIGGERS: readonly DiscoveryScanTrigger[] = ['manual', 'schedule'];
export const DISCOVERED_STATUSES: readonly DiscoveredStatus[] = ['unmanaged', 'managed', 'known'];
export const STATUS_FILTERS: readonly DiscoveredStatusFilter[] = ['all', 'unmanaged', 'managed', 'known'];
export const ENDPOINT_STATES: readonly DiscoveredEndpointState[] = ['present', 'unreachable', 'gone', 'no_tls', 'excluded', 'malformed'];
export const ENDPOINT_ERRORS: readonly Exclude<DiscoveredEndpointError, ''>[] = ['refused', 'timeout', 'no_tls', 'reset', 'chain_too_large', 'policy', 'malformed'];

// The limits of a scope and of the settings (internal/discovery/scope.go, checked against the OpenAPI document). The UI
// tells them before a save; the server stays the judge.
export const MAX_ENTRIES = 256;
export const MAX_PORTS = 16;
export const MAX_SNI_NAMES = 256;
export const MAX_EXCLUSIONS = 256;
export const MAX_SCOPE_NAME = 100;
export const MAX_RATE = 100;
export const MAX_CONCURRENCY = 64;
export const DEFAULT_RATE = 20;
export const DEFAULT_CONCURRENCY = 32;
export const MAX_SCHEDULE_HOURS = 168;
export const MIN_RETENTION_DAYS = 7;
export const MAX_RETENTION_DAYS = 730;
export const DEFAULT_RETENTION_DAYS = 90;
export const MAX_ADDRESSES = 4096;
export const MAX_ENDPOINTS = 20000;
// At most this many scans are queued or running at once (a third start is refused with ALC-DSC-0007).
export const MAX_ACTIVE_SCANS = 2;

// A label key per enum value; a value from a newer server gets the neutral text.
const labelOf = (group: string, values: readonly string[]) => (v: string) => (values.includes(v) ? `discovery.enum.${group}.${v}` : 'enum.unknown');
export const scanStateKey = labelOf('scanState', SCAN_STATES);
export const scanTriggerKey = labelOf('trigger', SCAN_TRIGGERS);
export const statusKey = labelOf('status', DISCOVERED_STATUSES);
export const endpointStateKey = labelOf('endpointState', ENDPOINT_STATES);
export const endpointErrorKey = labelOf('endpointError', ENDPOINT_ERRORS);

// isActiveScan: the scan is queued or running (it may still change, so the screens read it again).
export const isActiveScan = (state: string) => state === 'queued' || state === 'running';

// endpointAddress is "address:port", with an IPv6 address in brackets.
export function endpointAddress(e: Pick<DiscoveredEndpoint, 'address' | 'port'>): string {
  return e.address.includes(':') ? `[${e.address}]:${e.port}` : `${e.address}:${e.port}`;
}

// lines splits a text box into its entries: one per line, trimmed, empty lines dropped. A comma also separates, so a
// pasted "10.0.0.0/24, 10.0.1.0/24" is two entries.
export function lines(text: string): string[] {
  return text
    .split(/[\n,]/)
    .map((l) => l.trim())
    .filter((l) => l !== '');
}

// parsePorts reads "443, 8443" (commas, spaces or new lines). problem is the label key of the first problem, or ''.
export function parsePorts(text: string): { ports: number[]; problem: string } {
  const parts = text.split(/[\s,]+/).filter((p) => p !== '');
  if (parts.length === 0) return { ports: [], problem: 'discovery.scope.portsRequired' };
  const ports: number[] = [];
  for (const p of parts) {
    if (!/^\d{1,5}$/.test(p) || Number(p) < 1 || Number(p) > 65535) return { ports: [], problem: 'discovery.scope.portInvalid' };
    if (!ports.includes(Number(p))) ports.push(Number(p));
  }
  if (ports.length > MAX_PORTS) return { ports: [], problem: 'discovery.scope.portsTooMany' };
  return { ports, problem: '' };
}

// The refusals that name one element of a list (params field and index): ALC-DSC-0001/0002/0003/0009/0010.
const ELEMENT_REASONS = new Set(['discovery.scope_too_large', 'discovery.entry_not_allowed', 'discovery.entry_invalid', 'discovery.schedule_invalid', 'discovery.name_unresolved']);

// elementProblem says which list element (field and 0-based index) a discovery refusal names, or null. The value
// itself is never in the answer: the screen shows the line the person typed.
export function elementProblem(error: unknown): { field: string; index: number | null; reason: string } | null {
  if (!(error instanceof ApiError) || !ELEMENT_REASONS.has(error.reason)) return null;
  const field = error.params.field ?? '';
  const raw = error.params.index;
  const index = raw !== undefined && /^\d+$/.test(raw) ? Number(raw) : null;
  return { field, index, reason: error.reason };
}

const v1 = '/api/v1/discovery';
const enc = encodeURIComponent;

function query(params: Record<string, string | number | boolean | null | undefined>): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== '') p.set(k, String(v));
  const qs = p.toString();
  return qs ? `?${qs}` : '';
}

// certificateParams is the list's filters as the API reads them: status "all" is the default and is left out.
function certificateParams(q: CertificateQuery): Record<string, string | number | boolean | undefined> {
  return {
    status: q.status && q.status !== 'all' ? q.status : undefined,
    expiring_within_days: q.expiring_within_days,
    expired: q.expired,
    self_signed: q.self_signed,
    current: q.current ? true : undefined,
    q: q.q?.trim() || undefined,
    scope_id: q.scope_id,
  };
}

// nextCursor is the keyset paging rule of every discovery list (TanStack getNextPageParam).
export const nextCursor = <T>(last: Page<T>) => last.next_cursor;

// allPages follows next_cursor to the end (at most 100 pages; a cursor seen twice ends it).
export async function allPages<T>(page: (cursor: string | null) => Promise<Page<T>>): Promise<Page<T>> {
  const items: T[] = [];
  const seen = new Set<string>();
  let cursor: string | null = null;
  for (let i = 0; i < 100; i++) {
    const res: Page<T> = await page(cursor);
    items.push(...res.items);
    cursor = res.next_cursor;
    if (!cursor || seen.has(cursor)) break;
    seen.add(cursor);
  }
  return { items, next_cursor: null };
}

const ifMatch = (version?: number) => (version === undefined ? undefined : { 'If-Match': `"${version}"` });

export const getDiscoverySummary = (signal?: AbortSignal) => apiFetch<DiscoverySummary>(`${v1}/summary`, { signal });

// Scopes.
export const listDiscoveryScopes = (p: Paging = {}, signal?: AbortSignal) =>
  apiFetch<Page<DiscoveryScope>>(`${v1}/scopes${query({ cursor: p.cursor, limit: p.limit })}`, { signal });
export const listAllDiscoveryScopes = (signal?: AbortSignal) => allPages((cursor) => listDiscoveryScopes({ cursor, limit: 200 }, signal));
export const getDiscoveryScope = (id: string, signal?: AbortSignal) => apiFetch<DiscoveryScope>(`${v1}/scopes/${enc(id)}`, { signal });
export const createDiscoveryScope = (body: DiscoveryScopeCreate) => apiFetch<DiscoveryScope>(`${v1}/scopes`, { method: 'POST', body });
export const updateDiscoveryScope = (id: string, body: DiscoveryScopePatch, version?: number) =>
  apiFetch<DiscoveryScope>(`${v1}/scopes/${enc(id)}`, { method: 'PATCH', body, headers: ifMatch(version) });
export const deleteDiscoveryScope = (id: string, version?: number) => apiFetch<void>(`${v1}/scopes/${enc(id)}`, { method: 'DELETE', headers: ifMatch(version) });
// previewDiscoveryScope sizes a scope as typed: no name is looked up, nothing is dialed, nothing is stored.
export const previewDiscoveryScope = (body: DiscoveryScopePatch, signal?: AbortSignal) =>
  apiFetch<DiscoveryPreview>(`${v1}/scopes/preview`, { method: 'POST', body, signal });

// Scans: a scan is only ever of a scope, never of addresses given here.
export const startDiscoveryScan = (scopeId: string) => apiFetch<DiscoveryScan>(`${v1}/scopes/${enc(scopeId)}/scans`, { method: 'POST' });
export const listDiscoveryScans = (q: ScanQuery & Paging = {}, signal?: AbortSignal) =>
  apiFetch<Page<DiscoveryScan>>(`${v1}/scans${query({ scope_id: q.scope_id, state: q.state, cursor: q.cursor, limit: q.limit })}`, { signal });
export const getDiscoveryScan = (id: string, signal?: AbortSignal) => apiFetch<DiscoveryScan>(`${v1}/scans/${enc(id)}`, { signal });
export const cancelDiscoveryScan = (id: string) => apiFetch<DiscoveryScan>(`${v1}/scans/${enc(id)}/cancel`, { method: 'POST' });

// Results.
export const listDiscoveredCertificates = (q: CertificateQuery & Paging = {}, signal?: AbortSignal) =>
  apiFetch<Page<DiscoveredCertificate>>(`${v1}/certificates${query({ ...certificateParams(q), cursor: q.cursor, limit: q.limit })}`, { signal });
export const getDiscoveredCertificate = (fingerprint: string, signal?: AbortSignal) =>
  apiFetch<DiscoveredCertificate>(`${v1}/certificates/${enc(fingerprint)}`, { signal });
export const listDiscoveredEndpoints = (q: EndpointQuery & Paging = {}, signal?: AbortSignal) =>
  apiFetch<Page<DiscoveredEndpoint>>(`${v1}/endpoints${query({ scope_id: q.scope_id, fingerprint: q.fingerprint, cursor: q.cursor, limit: q.limit })}`, { signal });
// The export takes the list's filters exactly (no cursor, no limit).
export const discoveredCertificatesExportPath = (q: CertificateQuery = {}) => `${v1}/certificates/export${query(certificateParams(q))}`;
// exportDiscoveredCertificates fetches the CSV as a Blob, or an ApiError for a refusal (409 too large or busy, 429).
export const exportDiscoveredCertificates = (q: CertificateQuery = {}) => apiFetch<Blob>(discoveredCertificatesExportPath(q), { responseType: 'csv' });

// Settings.
export const getDiscoverySettings = (signal?: AbortSignal) => apiFetch<DiscoverySettings>(`${v1}/settings`, { signal });
export const putDiscoverySettings = (body: DiscoverySettingsInput) => apiFetch<DiscoverySettings>(`${v1}/settings`, { method: 'PUT', body });
