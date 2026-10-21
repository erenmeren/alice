import { apiFetch } from './client';
import type { DeployResult, ErrorRef } from './types';

// What a bound location should have, what Alice last deployed there and what is observed today (R52,
// docs/superpowers/rulings/certificate-drift.md; api/openapi.yaml LocationObservation), its repair mode and the
// one-action repair.

export type LocationHealth = 'in_sync' | 'drifted' | 'pending' | 'unreachable' | 'stale' | 'unmanaged';
export type DriftMode = 'observe' | 'approve' | 'auto';
export type DriftModeSetting = DriftMode | 'default';
export type DriftProbe = 'alice' | 'helper';
export type DriftBackoff = '' | 'flapping' | 'repair_failing';

// The enums above, checked against api/openapi.yaml and the Go sources by drift.test.ts; each has a label in both
// languages.
export const LOCATION_HEALTHS: readonly LocationHealth[] = ['in_sync', 'drifted', 'pending', 'unreachable', 'stale', 'unmanaged'];
export const DRIFT_MODES: readonly DriftMode[] = ['observe', 'approve', 'auto'];
export const DRIFT_MODE_SETTINGS: readonly DriftModeSetting[] = ['observe', 'approve', 'auto', 'default'];

export interface ObservedCertificate {
  certificate_id: string | null;
  // The leaf's SHA-256 (hex); "" when the file holds no certificate.
  fingerprint: string;
  not_after: string | null;
}

export interface LocationObservation {
  health: LocationHealth;
  source: '' | 'acme' | 'key_vault';
  source_id: string | null;
  desired: ObservedCertificate | null;
  last_deployment: { deployment_id: string; fingerprint: string; finished_at: string | null; level: number } | null;
  // observed_at: when a scan last read the file (never the time of a scan that could not read it).
  file: (ObservedCertificate & { observed_at: string; changed_outside_at: string | null }) | null;
  // observed_at: the last probe that completed a handshake; probe: from Alice or from the server itself.
  tls: (ObservedCertificate & { observed_at: string; probe: DriftProbe; level: number; trust: '' | 'trusted' | 'untrusted' | 'unchecked'; trust_error: string }) | null;
  tls_attempted_at: string | null;
  tls_error: ErrorRef | null;
  mode: DriftMode;
  mode_setting: DriftModeSetting;
  default_mode: 'observe' | 'auto';
  drift_since: string | null;
  drift_fingerprint: string;
  drift_source: '' | 'tls' | 'file';
  backoff_reason: DriftBackoff;
  backed_off_at: string | null;
  active_deployment_id: string | null;
  next_observe_at: string | null;
  repair_available: boolean;
}

const v1 = '/api/v1';
const enc = encodeURIComponent;

// setDriftMode chooses how Alice treats a drift of the location; automatic repair needs an Administrator's fresh
// step-up (the caller runs it through useStepUp).
export const setDriftMode = (locationId: string, mode: DriftModeSetting) =>
  apiFetch<LocationObservation>(`${v1}/locations/${enc(locationId)}/drift-mode`, { method: 'PUT', body: { mode } });

// repairDrift deploys the certificate the location should have again (a person's deployment, with every check).
export const repairDrift = (locationId: string) => apiFetch<DeployResult>(`${v1}/locations/${enc(locationId)}/actions/repair`, { method: 'POST' });

export const healthKey = (h: string) => ((LOCATION_HEALTHS as readonly string[]).includes(h) ? `drift.health.${h}` : 'enum.unknown');
export const modeKey = (m: string) => ((DRIFT_MODE_SETTINGS as readonly string[]).includes(m) ? `drift.mode.${m}` : 'enum.unknown');

// DriftSummary counts the observed places for the summary line ("Live and verified on 17 of 20 places; 2 not
// reachable; 1 serves the old certificate (expires in 18 h)"): in sync, unreachable, drifted, the rest (pending or
// stale), and the soonest end of a certificate a drifted place serves instead (null when not known).
export interface DriftSummary {
  total: number;
  inSync: number;
  unreachable: number;
  drifted: number;
  other: number;
  driftedExpires: string | null;
}

export function driftSummary(observations: (LocationObservation | null | undefined)[]): DriftSummary {
  const out: DriftSummary = { total: 0, inSync: 0, unreachable: 0, drifted: 0, other: 0, driftedExpires: null };
  for (const o of observations) {
    if (!o || o.health === 'unmanaged') continue;
    out.total++;
    if (o.health === 'in_sync') out.inSync++;
    else if (o.health === 'unreachable') out.unreachable++;
    else if (o.health === 'drifted') {
      out.drifted++;
      const end = observedInstead(o)?.not_after ?? null;
      if (end && (out.driftedExpires === null || end < out.driftedExpires)) out.driftedExpires = end;
    } else out.other++;
  }
  return out;
}

// observedInstead is the certificate a drifted place serves (or holds) instead of the desired one: the website's when
// it disagrees, else the file's.
export function observedInstead(o: LocationObservation): ObservedCertificate | null {
  const want = o.desired?.fingerprint ?? '';
  if (o.tls && o.tls.fingerprint !== want) return o.tls;
  if (o.file && o.file.fingerprint !== want) return o.file;
  return null;
}
