import { Text } from '@mantine/core';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import type { ACMECertificate, ACMECertificateState, ACMEProvider, ACMEHook } from '../../api/acme';
import { listACMEHooks, listACMEProviders } from '../../api/acme';
import { getLicenseStatus, listAllServers } from '../../api/endpoints';
import { isWebServer } from '../../api/webServer';
import { ACME_HOOK_LIST_KEY, ACME_PROVIDER_LIST_KEY, LICENSE_STATUS_KEY } from '../../api/queryKeys';
import type { ErrorRef } from '../../api/types';
import type { IconName } from '../../design/Icon';
import type { Tone } from '../ui';
import { reasonTitle } from '../JobErrorAlert';
import { withRoleCode } from '../CodeText';

// Shared pieces of the Issued certificates screens (the ACME certificates): state colors and icons, the renewal date,
// the client-side name checks (early feedback only: the server decides) and the reads every screen needs.

const DAY_MS = 86_400_000;

// DNS names are ASCII and compared without letter case in the English (ASCII) rules, never the Turkish dotless i.
export const dnsLower = (s: string) => s.toLocaleLowerCase('en-US');

export const STATE_TONE: Record<ACMECertificateState, Tone> = { pending: 'neutral', issuing: 'info', active: 'success', failing: 'warning', stopped: 'danger' };
export const STATE_ICON: Record<ACMECertificateState, IconName> = { pending: 'Clock3', issuing: 'RefreshCw', active: 'CircleCheck', failing: 'CircleAlert', stopped: 'CircleOff' };
export const stateTone = (s: string): Tone => STATE_TONE[s as ACMECertificateState] ?? 'neutral';
export const stateIcon = (s: string): IconName => STATE_ICON[s as ACMECertificateState] ?? 'CircleDot';

// The query key of the web servers (an HTTP-01 proof runs on one), apart from every other target list.
export const WEB_SERVERS_KEY = ['targets', 'list', 'web-servers'] as const;

// The ACME key type of a certificate as the key family a website's file has (rsa, ecdsa), for the website list.
export const keyFamily = (keyType: string): 'rsa' | 'ecdsa' | '' => (keyType.startsWith('rsa') ? 'rsa' : keyType.startsWith('ecdsa') ? 'ecdsa' : '');

// The most websites one Deploy now names (api/openapi.yaml ACMEDeploy.location_ids maxItems).
export const MAX_DEPLOY = 20;
// How often a screen reads a running order again.
export const ORDER_POLL_MS = 3000;

export type Renewal =
  | { kind: 'off' }
  | { kind: 'stopped' }
  | { kind: 'none' }
  | { kind: 'attempt'; at: string }
  | { kind: 'planned'; at: string; ari: boolean };

// renewal says when Alice renews next, from what the API sends: a scheduled attempt (next_attempt_at) first; otherwise,
// for an issued certificate, renew_at (the time Alice chose in the authority's suggested window, or its own rule); from
// an older server without it, the rule renew_before_days before expiry (at most a third of the lifetime), or the start
// of the authority's window when that is earlier. Before the first issuance there is none.
export function renewal(c: ACMECertificate): Renewal {
  // A certificate stopped after an outage is still retried by itself (recovering): its next attempt is shown.
  if (c.state === 'stopped' && !(c.recovering && c.next_attempt_at)) return { kind: 'stopped' };
  if (!c.auto_renew) return { kind: 'off' };
  if (c.next_attempt_at) return { kind: 'attempt', at: c.next_attempt_at };
  if (!c.current) return { kind: 'none' };
  // The server's own answer (R50): a time chosen once at random in the authority's window, or the local rule.
  if (c.renew_at && !Number.isNaN(Date.parse(c.renew_at))) return { kind: 'planned', at: c.renew_at, ari: c.renew_at_source === 'ca_window' };
  const end = Date.parse(c.current.not_after);
  const start = Date.parse(c.current.not_before);
  if (Number.isNaN(end)) return { kind: 'none' };
  const lifetime = Number.isNaN(start) ? Infinity : end - start;
  const at = end - Math.min(c.renew_before_days * DAY_MS, lifetime / 3);
  const ari = c.ari_window ? Date.parse(c.ari_window.start) : NaN;
  if (!Number.isNaN(ari) && ari < at) return { kind: 'planned', at: new Date(ari).toISOString(), ari: true };
  return { kind: 'planned', at: new Date(at).toISOString(), ari: false };
}

// The DNS name rule of the server (inventory CheckACMENames), told early: letters, digits and hyphens in parts of at
// most 63 characters, at least two parts, at most 253 characters, a wildcard only as the whole first part, no IP
// address. The answer is a label key, or '' when the name is fine.
export function nameProblem(raw: string, existing: readonly string[] = []): string {
  const n = dnsLower(raw.trim());
  if (n === '') return 'acme.issued.names.empty';
  if (n.length > 253) return 'acme.issued.names.tooLong';
  const body = n.startsWith('*.') ? n.slice(2) : n;
  const labels = body.split('.');
  if (labels.length < 2) return 'acme.issued.names.twoLabels';
  for (const l of labels) if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(l)) return body.includes('*') ? 'acme.issued.names.wildcardPlace' : 'acme.issued.names.invalid';
  if (/^\d+$/.test(labels[labels.length - 1])) return 'acme.issued.names.address';
  if (existing.some((e) => dnsLower(e) === n)) return 'acme.issued.names.duplicate';
  return '';
}

export const isWildcard = (name: string) => name.startsWith('*.');

// nameAllowed mirrors inventory.ACMENameAllowed: "example.com" admits that name and every name below it, ".example.com"
// only the names below it, a wildcard is judged by its base name, an empty list admits nothing.
export function nameAllowed(suffixes: readonly string[], raw: string): boolean {
  const n = dnsLower(raw.trim()).replace(/^\*\./, '');
  return suffixes.some((s0) => {
    const s = dnsLower(s0.trim());
    if (s === '' || s === '.') return false;
    if (s.startsWith('.')) return n.endsWith(s);
    return n === s || n.endsWith(`.${s}`);
  });
}

// usableProvider says why a certificate cannot be ordered from an authority, or '' when it can.
export function providerProblem(p: ACMEProvider): string {
  if (!p.active_account_id) return 'acme.issued.wizard.noAccount';
  if (p.pending_rollover) return 'acme.issued.wizard.rolloverPending';
  if (p.allowed_suffixes.length === 0) return 'acme.issued.wizard.noNames';
  return '';
}

// The reads several screens share. Providers and hooks come from the typed client's own keys (Task 14), not from the
// Settings components.
export const useProviders = () => useQuery({ queryKey: ACME_PROVIDER_LIST_KEY, queryFn: () => listACMEProviders() });
export const useHooks = () => useQuery({ queryKey: ACME_HOOK_LIST_KEY, queryFn: () => listACMEHooks() });
export const useWebServers = (enabled = true) =>
  useQuery({ queryKey: WEB_SERVERS_KEY, queryFn: async () => ({ items: (await listAllServers()).items.filter((s) => isWebServer(s.type)) }), enabled });

export const providerName = (list: ACMEProvider[] | undefined, id: string) => list?.find((p) => p.id === id)?.name ?? '';
export const hookName = (list: ACMEHook[] | undefined, id: string | null) => (id ? (list?.find((h) => h.id === id)?.name ?? '') : '');

// useChangesLocked says whether the license refuses changes now (lock, an ended evaluation, an unverified license):
// the buttons that contact an authority or a server are then disabled with an explanation. The server stays the judge.
export function useChangesLocked(): boolean {
  const status = useQuery({ queryKey: LICENSE_STATUS_KEY, queryFn: () => getLicenseStatus() });
  const s = status.data;
  if (!s) return false;
  return s.phase === 'locked' || s.phase === 'evaluation_expired' || s.banners.some((b) => b.kind === 'locked' || b.kind === 'evaluation_ended' || b.kind === 'unverified');
}

// Problem is a stable error of an order, a renewal or a website in plain words: what happened, what to do, and its code.
export function Problem({ error, testId }: { error: ErrorRef; testId?: string }) {
  const { t, i18n } = useTranslation();
  const params = error.params ?? {};
  const actionKey = `errors.${error.reason}.action`;
  return (
    <div data-testid={testId}>
      <Text size="sm" fw={600}>
        {withRoleCode(reasonTitle(t, i18n, error.reason, params), params.role)}
      </Text>
      {i18n.exists(actionKey) && (
        <Text size="sm">
          {t('acme.issued.whatToDo')} {withRoleCode(t(actionKey, params), params.role)}
        </Text>
      )}
      {error.code && (
        <Text size="xs" c="dimmed" translate="no">
          {t('jobs.errorCode', { code: error.code })}
        </Text>
      )}
    </div>
  );
}
