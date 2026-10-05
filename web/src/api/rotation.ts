import { ApiError, apiFetch } from './client';
import type { KeyType } from './sshkeys';
import type { ErrorRef } from './types';

const v1 = '/api/v1/rotation';
const enc = encodeURIComponent;
const etag = (version: number) => ({ 'If-Match': `"${version}"` });

export type NewKeyType = 'same' | KeyType;

// Policy is a rotation policy as the API answers it. last_run_* is the latest finished run, so a policy that silently
// skips (for example an undelivered notice) shows why.
export interface Policy {
  id: string;
  ssh_key_id: string;
  name: string;
  enabled: boolean;
  interval_days: number;
  overlap_days: number;
  overlap_minutes: number;
  notify_before_hours: number;
  new_key_type: NewKeyType;
  next_run_at: string | null;
  open_rotation_id: string | null;
  last_run_id: string | null;
  last_run_status: string | null;
  last_run_result: ErrorRef | null;
  version: number;
  created_at: string;
  updated_at: string;
}

export interface PolicyInput {
  ssh_key_id: string;
  name: string;
  interval_days: number;
  overlap_days: number;
  notify_before_hours: number;
  new_key_type: NewKeyType;
}

export type PolicyPatch = Partial<Omit<PolicyInput, 'ssh_key_id'>>;

export interface PreviewAction {
  n: number;
  location_id: string;
  target_id: string;
  target_name: string;
  os_user: string;
  file_path: string;
  options: string;
  skip_reason: string;
  verify: boolean;
  verify_note: string;
  remove_line: string;
  add_line: string;
}

export interface Preview {
  policy_id: string;
  ssh_key_id: string;
  fingerprint: string;
  plan_digest: string;
  planned_for: string;
  new_key_type: string;
  overlap_minutes: number;
  change_count: number;
  skip_count: number;
  emailed: boolean;
  actions: PreviewAction[];
}

export type RunAction = 'continue' | 'finish_now' | 'keep_old' | 'abort';

export interface RunLocation {
  id: string;
  n: number;
  target_id: string;
  target_name: string;
  os_user: string;
  file_path: string;
  options: string;
  state: string;
  skip_reason: string;
  verify_note: string;
  error: ErrorRef | null;
  backup: string;
  verified_at: string | null;
  reverified_at: string | null;
  removed_at: string | null;
  new_location_id: string | null;
  // How often the add was sent again after its answer was lost.
  add_resend_count: number;
  add_resent_at: string | null;
}

export interface RunStep {
  n: number;
  location_id: string | null;
  name: string;
  status: string;
  at: string;
  params: Record<string, string>;
}

export interface Run {
  id: string;
  policy_id: string;
  old_ssh_key_id: string;
  new_ssh_key_id: string | null;
  old_fingerprint: string;
  new_fingerprint: string;
  trigger: string;
  status: string;
  paused_license: boolean;
  awaiting_decision: boolean;
  decision_due_at: string | null;
  planned_for: string;
  notified_at: string;
  started_at: string | null;
  verified_at: string | null;
  overlap_until: string | null;
  finished_at: string | null;
  result: ErrorRef | null;
  plan_digest: string;
  new_key_type: string;
  overlap_minutes: number;
  change_count: number;
  skip_count: number;
  kept_count: number;
  // actions_allowed is what the page may offer now; the page never works it out itself.
  actions_allowed: RunAction[];
  // Place counts are on every run; the places and the steps only on the detail (a list item has neither).
  // The buckets add up to total (verified: the new key works and the old key is not removed yet; removed; kept by an
  // administrator; failed; skipped; undone; cancelled: never sent or refused at send time; in_flight). The server may add
  // more, so any key can arrive.
  location_counts: Record<string, number>;
  locations?: RunLocation[];
  steps?: RunStep[];
  // Why Continue is not offered yet, when the server says (the renewal notice); absent on older servers.
  // notice_state (reason rotation.notice_pending) says the renewal email is still being prepared; notice_error (reason
  // notify.queue_failed) that it could not be queued. Both are error references or null; the page never infers them.
  notice_state?: ErrorRef | null;
  notice_error?: ErrorRef | null;
  version: number;
}

export interface RunQuery {
  policy_id?: string;
  ssh_key_id?: string;
  cursor?: string | null;
  limit?: number;
}

export const getPolicy = (id: string) => apiFetch<Policy>(`${v1}/policies/${enc(id)}`);
export const createPolicy = (body: PolicyInput) => apiFetch<Policy>(`${v1}/policies`, { method: 'POST', body });
export const updatePolicy = (id: string, version: number, body: PolicyPatch) =>
  apiFetch<Policy>(`${v1}/policies/${enc(id)}`, { method: 'PATCH', body, headers: etag(version) });
export const deletePolicy = (id: string, version: number) => apiFetch<void>(`${v1}/policies/${enc(id)}`, { method: 'DELETE', headers: etag(version) });
export const enablePolicy = (id: string, version: number) =>
  apiFetch<Policy>(`${v1}/policies/${enc(id)}/actions/enable`, { method: 'POST', headers: etag(version) });
export const disablePolicy = (id: string, version: number) =>
  apiFetch<Policy>(`${v1}/policies/${enc(id)}/actions/disable`, { method: 'POST', headers: etag(version) });
export const previewPolicy = (id: string) => apiFetch<Preview>(`${v1}/policies/${enc(id)}/actions/preview`, { method: 'POST' });
export const runPolicy = (id: string, planDigest: string) =>
  apiFetch<{ rotation_id: string; status_url: string }>(`${v1}/policies/${enc(id)}/actions/run`, { method: 'POST', body: { plan_digest: planDigest } });

// listRuns: the query string order is fixed (policy_id, ssh_key_id, cursor, limit; empty values omitted).
export function listRuns(q: RunQuery = {}) {
  const params = new URLSearchParams();
  if (q.policy_id) params.set('policy_id', q.policy_id);
  if (q.ssh_key_id) params.set('ssh_key_id', q.ssh_key_id);
  if (q.cursor) params.set('cursor', q.cursor);
  if (q.limit) params.set('limit', String(q.limit));
  const qs = params.toString();
  return apiFetch<{ items: Run[]; next_cursor: string | null }>(`${v1}/runs${qs ? `?${qs}` : ''}`);
}
export const getRun = (id: string) => apiFetch<Run>(`${v1}/runs/${enc(id)}`);
export const continueRun = (id: string) => apiFetch<void>(`${v1}/runs/${enc(id)}/actions/continue`, { method: 'POST' });
export const finishRunNow = (id: string) => apiFetch<void>(`${v1}/runs/${enc(id)}/actions/finish-now`, { method: 'POST' });
export const keepOldKey = (id: string, locationIds: string[]) =>
  apiFetch<void>(`${v1}/runs/${enc(id)}/actions/keep-old`, { method: 'POST', body: { location_ids: locationIds } });
export const abortRun = (id: string) => apiFetch<void>(`${v1}/runs/${enc(id)}/actions/abort`, { method: 'POST' });

const TERMINAL_RUN: ReadonlySet<string> = new Set(['completed', 'aborted', 'needs_attention', 'cancelled']);
export const RUN_POLL_MS = 3000;

// runPollInterval is how long a page waits before reading a run again: never once the run is final or cannot be read at all,
// three seconds while it moves, as long as the server's Retry-After asks when it is busy, and ten seconds after any other
// failed refresh (the page keeps what it has).
export function runPollInterval(run: Run | undefined, error: unknown): number | false {
  if (run && TERMINAL_RUN.has(run.status)) return false;
  if (error instanceof ApiError && error.retryAfter !== null) return Math.max(RUN_POLL_MS, error.retryAfter * 1000);
  if (error && !run) return false;
  return error ? 10000 : RUN_POLL_MS;
}
