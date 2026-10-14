import { apiFetch } from './client';
import type { BackupSummary, ChecklistItem } from './types';

// Phase 7 (alerts, dashboard, saved views, CSV export). The shapes are contract C13; times are UTC RFC 3339 strings.

export type ViewPage = 'certificates' | 'ssh_keys';

export interface Delivery {
  failing: boolean;
  consecutive_failures: number;
  last_failure_at: string | null;
  last_failure_code: string;
  last_success_at: string | null;
  pending: number;
  failed_24h: number;
}

export interface RecentDeployment {
  id: string;
  certificate_name: string;
  target_id: string;
  target_name: string;
  status: string;
  error_code: string;
  at: string;
}

export interface UpcomingRotation {
  policy_id: string;
  ssh_key_id: string;
  key_label: string;
  next_run_at: string;
}

export interface DashboardSummary {
  generated_at: string;
  certificates: { monitored: number; expired: number; within_7: number; within_30: number; within_60: number; kv_expired: number; kv_within_30: number };
  deployments: { failed_7d: number; recent: RecentDeployment[] };
  targets: { total: number; by_status: Record<string, number> };
  // For Operators phase is "" and ends_at / days_left are null.
  license: { expired: boolean; phase: string; ends_at: string | null; days_left: number | null };
  rotation: { upcoming: UpcomingRotation[]; running: number; needs_attention: number };
  // null for everyone but Administrators.
  notifications: Delivery | null;
  // null for Operators.
  audit: { head_seq: number; head_hash: string; checked_at: string | null; intact: boolean } | null;
  attention: number;
  // Phase 8: absent or null for the roles that do not get them (R43 row 18).
  backup?: BackupSummary | null;
  setup_checklist?: ChecklistItem[] | null;
  // Network discovery (decision D2): unmanaged certificates found on the network that expire within 30 days, never part
  // of certificates. Absent while no scan scope exists and for a caller without discovery.view (a read-scope token).
  discovery?: { unmanaged_expiring_30d: number } | null;
}

export interface ExpiringItem {
  kind: string;
  object_id: string;
  name: string;
  expires_at: string;
  days_left: number;
  expired: boolean;
  fingerprint: string;
  websites: string[];
  servers: string[];
  target_ids: string[];
  vault: string;
  vault_id: string | null;
}

export interface Condition {
  kind: string;
  object_id: string;
  name: string;
  since: string;
  error_code: string;
}

export interface SavedView {
  id: string;
  page: ViewPage;
  name: string;
  query: Record<string, string>;
  created_at: string;
}

const v1 = '/api/v1';

export const getDashboardSummary = () => apiFetch<DashboardSummary>(`${v1}/dashboard/summary`);
export const getExpiring = (days = 30, limit = 10) => apiFetch<{ items: ExpiringItem[] }>(`${v1}/dashboard/expiring?days=${days}&limit=${limit}`);
export const getAlerts = () => apiFetch<{ items: Condition[] }>(`${v1}/alerts`);
// Administrators get the Delivery; everyone else gets only { failing: false }.
export const getNotificationStatus = () => apiFetch<Partial<Delivery> & { failing: boolean }>(`${v1}/notifications/status`);
export const listViews = (page: ViewPage) => apiFetch<{ items: SavedView[] }>(`${v1}/views?page=${page}`);
export const createView = (body: { page: ViewPage; name: string; query: Record<string, string> }) => apiFetch<SavedView>(`${v1}/views`, { method: 'POST', body });
export const deleteView = (id: string) => apiFetch<void>(`${v1}/views/${encodeURIComponent(id)}`, { method: 'DELETE' });

// exportPath is the address of the CSV export of a list with the same filters (no cursor, no limit; empty values are dropped).
export function exportPath(kind: 'certificates' | 'ssh-keys', filters: Record<string, string>): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(filters)) if (v) p.set(k, v);
  const qs = p.toString();
  return `${v1}/${kind}/export${qs ? `?${qs}` : ''}`;
}

// exportCsv fetches the export: the CSV as a Blob, or an ApiError for a refusal (409 too large or busy, 422, 429, 405).
export const exportCsv = (kind: 'certificates' | 'ssh-keys', filters: Record<string, string>) => apiFetch<Blob>(exportPath(kind, filters), { responseType: 'csv' });
