import { Text } from '@mantine/core';
import type { TFunction } from 'i18next';
import { useTranslation } from 'react-i18next';
import { MAX_ACTIVE_SCANS, scanStateKey, statusKey, type DiscoveredStatus, type DiscoveryScan, type DiscoveryScanState, type DiscoveryScope, type DiscoveredEndpointState } from '../../api/discovery';
import { useAuth } from '../../auth/AuthProvider';
import { can, canPlatform } from '../../auth/permissions';
import type { IconName } from '../../design/Icon';
import { reasonTitle } from '../JobErrorAlert';
import { StatusBadge, type Tone } from '../ui';

// Shared pieces of the Network discovery screens: who may do what, the state colors and icons (always with a text: a
// status never relies on color alone), the schedule in words and the reasons a scan cannot start.

// How often a screen reads a queued or running scan again.
export const SCAN_POLL_MS = 3000;

// useDiscoveryRole: every role reads discovery (discovery.view); Operators and Administrators start and cancel scans
// (discovery.operate, on the scope's service); only a global Administrator defines scopes and the settings
// (discovery.manage, a platform permission, with a step-up). The server stays the judge; the screens only follow its rules.
export function useDiscoveryRole() {
  const { session } = useAuth();
  const canOperate = can(session, 'discovery.operate');
  return { admin: canPlatform(session, 'discovery.manage'), canOperate, auditor: !canOperate };
}

export const formatNumber = (n: number, lang: string) => new Intl.NumberFormat(lang).format(n);

const STATUS_TONE: Record<DiscoveredStatus, Tone> = { unmanaged: 'warning', managed: 'success', known: 'info' };
const STATUS_ICON: Record<DiscoveredStatus, IconName> = { unmanaged: 'CircleHelp', managed: 'ShieldCheck', known: 'Eye' };

export function StatusChip({ status }: { status: DiscoveredStatus }) {
  const { t } = useTranslation();
  return (
    <StatusBadge tone={STATUS_TONE[status] ?? 'neutral'} icon={STATUS_ICON[status] ?? 'CircleDot'} size="sm" data-status={status}>
      {t(statusKey(status))}
    </StatusBadge>
  );
}

// GoneChip: no endpoint that is not gone presents the certificate any more (it stays listed until retention).
export function GoneChip() {
  const { t } = useTranslation();
  return (
    <StatusBadge tone="neutral" icon="CircleOff" size="sm" data-status="gone">
      {t('discovery.chips.gone')}
    </StatusBadge>
  );
}

const SCAN_TONE: Record<DiscoveryScanState, Tone> = { queued: 'neutral', running: 'info', done: 'success', cancelled: 'neutral', timed_out: 'warning', failed: 'danger' };
const SCAN_ICON: Record<DiscoveryScanState, IconName> = { queued: 'Clock3', running: 'RefreshCw', done: 'CircleCheck', cancelled: 'CircleOff', timed_out: 'CircleAlert', failed: 'CircleX' };

export function ScanStateBadge({ state }: { state: DiscoveryScanState }) {
  const { t } = useTranslation();
  return (
    <StatusBadge tone={SCAN_TONE[state] ?? 'neutral'} icon={SCAN_ICON[state] ?? 'CircleDot'} size="sm" data-state={state}>
      {t(scanStateKey(state))}
    </StatusBadge>
  );
}

const ENDPOINT_TONE: Record<DiscoveredEndpointState, Tone> = { present: 'success', unreachable: 'warning', gone: 'neutral', no_tls: 'warning', excluded: 'neutral', malformed: 'danger' };
const ENDPOINT_ICON: Record<DiscoveredEndpointState, IconName> = { present: 'CircleCheck', unreachable: 'Unplug', gone: 'CircleOff', no_tls: 'CircleAlert', excluded: 'CircleOff', malformed: 'CircleX' };
export const endpointTone = (s: string): Tone => ENDPOINT_TONE[s as DiscoveredEndpointState] ?? 'neutral';
export const endpointIcon = (s: string): IconName => ENDPOINT_ICON[s as DiscoveredEndpointState] ?? 'CircleDot';

// scheduleText is a scope's schedule in words. With a daily window an interval of 24 hours or more counts whole local
// days, rounded up (netdiscojobs.Due): the second line says so when the hours are not a whole number of days.
export function scheduleText(t: TFunction, s: Pick<DiscoveryScope, 'schedule_hours' | 'window_start' | 'window_end' | 'window_tz'>): { text: string; note: string } {
  const h = s.schedule_hours;
  if (!h || h <= 0) return { text: t('discovery.schedule.manual'), note: '' };
  const windowed = s.window_start !== '' && s.window_end !== '';
  if (!windowed) return { text: t('discovery.schedule.every', { count: h }), note: '' };
  const days = Math.ceil(h / 24);
  const every = h >= 24 ? t('discovery.schedule.days', { count: days }) : t('discovery.schedule.every', { count: h });
  const text = t('discovery.schedule.window', { every, start: s.window_start, end: s.window_end, tz: s.window_tz || 'UTC' });
  const note = h >= 24 && h % 24 !== 0 ? t('discovery.schedule.rounded', { count: days, hours: h }) : '';
  return { text, note };
}

// durationText is how long a scan ran, "–" while it has not started.
export function durationText(t: TFunction, start: string | null, end: string | null, now = Date.now()): string {
  if (!start) return '–';
  const from = Date.parse(start);
  const to = end ? Date.parse(end) : now;
  if (Number.isNaN(from) || Number.isNaN(to)) return '–';
  const secs = Math.max(0, Math.round((to - from) / 1000));
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const sec = secs % 60;
  if (h > 0) return t('discovery.duration.hours', { h, m });
  if (m > 0) return t('discovery.duration.minutes', { m, s: sec });
  return t('discovery.duration.seconds', { s: sec });
}

export type StartBlock = '' | 'locked' | 'noNetworks' | 'disabled' | 'running' | 'tooMany';

// startBlock is why a scan of the scope cannot start now, or '' when it can. activeCount is the scans queued or running
// anywhere (the scopes with a scan in flight). The server decides again (ALC-LIC-0001, 0013, 0004, 0007).
export function startBlock(scope: Pick<DiscoveryScope, 'enabled' | 'active_scan_id'>, ctx: { locked: boolean; scanningEnabled: boolean; activeCount: number }): StartBlock {
  if (ctx.locked) return 'locked';
  if (!ctx.scanningEnabled) return 'noNetworks';
  if (!scope.enabled) return 'disabled';
  if (scope.active_scan_id) return 'running';
  if (ctx.activeCount >= MAX_ACTIVE_SCANS) return 'tooMany';
  return '';
}

// ScanProblem is why a scan ended without finishing, in plain words (errors.<reason> in locales/common): what happened,
// what to do and the stable code.
export function ScanProblem({ scan }: { scan: Pick<DiscoveryScan, 'error_code' | 'error_reason'> }) {
  const { t, i18n } = useTranslation();
  if (!scan.error_reason && !scan.error_code) return null;
  const reason = scan.error_reason ?? '';
  const actionKey = `errors.${reason}.action`;
  return (
    <div data-testid="scan-problem">
      <Text size="sm" fw={600}>
        {reasonTitle(t, i18n, reason)}
      </Text>
      {reason !== '' && i18n.exists(actionKey) && (
        <Text size="sm">
          {t('discovery.whatToDo')} {t(actionKey)}
        </Text>
      )}
      {scan.error_code && (
        <Text size="xs" c="dimmed" translate="no">
          {t('jobs.errorCode', { code: scan.error_code })}
        </Text>
      )}
    </div>
  );
}
