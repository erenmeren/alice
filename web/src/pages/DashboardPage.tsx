import { Anchor, Code, Stack, Table, Tabs, Text } from '@mantine/core';
import { useQuery } from '@tanstack/react-query';
import type { TFunction } from 'i18next';
import { useTranslation } from 'react-i18next';
import { Link, useSearchParams } from 'react-router';
import { ApiError } from '../api/client';
import { getVersion, listAudit } from '../api/endpoints';
import { getAlerts, getDashboardSummary, getExpiring, type DashboardSummary } from '../api/phase7';
import { ALERTS_KEY, DASHBOARD_KEY, EXPIRING_KEY } from '../api/queryKeys';
import type { AuditEntry, AuditResult } from '../api/types';
import { useAuth } from '../auth/AuthProvider';
import { AttentionList } from '../components/dashboard/AttentionList';
import { AuditHead } from '../components/dashboard/AuditHead';
import { BackupCard } from '../components/dashboard/BackupCard';
import { ExpiringList } from '../components/dashboard/ExpiringList';
import { ExpiryHorizon } from '../components/dashboard/ExpiryHorizon';
import { FailedDeployments } from '../components/dashboard/FailedDeployments';
import { LicenseCard } from '../components/dashboard/LicenseCard';
import { RotationUpcoming } from '../components/dashboard/RotationUpcoming';
import { SetupChecklist } from '../components/dashboard/SetupChecklist';
import { TargetsByStatus } from '../components/dashboard/TargetsByStatus';
import { Widget } from '../components/dashboard/Widget';
import { ErrorAlert } from '../components/ErrorAlert';
import { useNow } from '../components/Expiry';
import { LoadingIndicator } from '../components/LoadingIndicator';
import { EmptyState, MetricStrip, PageHeader, StatusBadge, type Metric, type Tone } from '../components/ui';
import { formatDateTime } from '../datetime';
import classes from './DashboardPage.module.css';

// Background reads: they are polling, so they do not carry the activity mark (R39 item 1).
const REFRESH_MS = 60_000;
// The target states that need someone to look (the "need review" footnote of Managed targets).
const REVIEW = ['host_key_changed', 'auth_failed', 'unreachable', 'degraded', 'pending_host_key'];

// metrics are the design's four numbers, each from the role-filtered summary (never from a paged list, R20).
function metrics(s: DashboardSummary, t: TFunction): Metric[] {
  const within30 = s.certificates.within_30;
  const review = REVIEW.reduce((n, k) => n + (s.targets.by_status[k] ?? 0), 0);
  return [
    { label: t('dashboard.metrics.monitored'), value: s.certificates.monitored, foot: t('dashboard.metrics.within30', { count: within30 }), tone: within30 > 0 ? 'warning' : undefined, icon: 'FileKey2', to: '/certificates?expiry=30' },
    { label: t('dashboard.metrics.targets'), value: s.targets.total, foot: t('dashboard.metrics.review', { count: review }), tone: review > 0 ? 'warning' : undefined, icon: 'Server', to: '/servers' },
    { label: t('dashboard.metrics.rotations'), value: s.rotation.running, foot: t('dashboard.metrics.rotationsRunning', { count: s.rotation.running }), icon: 'RotateCw', to: '/rotations' },
    { label: t('dashboard.metrics.attention'), value: s.attention, foot: t('dashboard.metrics.attentionFoot'), tone: s.attention > 0 ? 'warning' : undefined, icon: 'ShieldAlert' },
  ];
}

const RESULT_TONE: Record<AuditResult, Tone> = { success: 'success', failure: 'warning', denied: 'danger' };

// ownText says whether the catalog has a text at key as its own property (an action read from the server, say
// "constructor", must not find an inherited property).
function ownText(bundle: unknown, key: string): boolean {
  let node = bundle;
  for (const part of key.split('.')) {
    if (!node || typeof node !== 'object' || !Object.prototype.hasOwnProperty.call(node, part)) return false;
    node = (node as Record<string, unknown>)[part];
  }
  return typeof node === 'string';
}

// EvidenceTrail is the design's "Evidence trail": the five newest audit entries and the way to the full audit trail.
// It reads the audit log only while the Assurance tab is open, and draws nothing for a role that may not read it.
function EvidenceTrail() {
  const { t, i18n } = useTranslation();
  const audit = useQuery({ queryKey: [...DASHBOARD_KEY, 'evidence'], queryFn: () => listAudit({ limit: 5 }), refetchInterval: REFRESH_MS });
  if (audit.error instanceof ApiError && audit.error.status === 403) return null;
  const known = (action: string) => {
    const key = `audit.actions.${action.replace(/\./g, '_')}`;
    return ownText(i18n.getResourceBundle(i18n.language, 'web'), key) || ownText(i18n.getResourceBundle('en', 'web'), key) ? t(key) : null;
  };
  const actor = (e: AuditEntry) => (e.actor_type === 'system' ? t('audit.systemActor', { name: e.actor_name }) : e.actor_name);
  const items = audit.data?.items ?? [];
  return (
    <Widget
      title={t('dashboard.assurance.evidence')}
      description={t('dashboard.assurance.evidenceSub')}
      testId="evidence-trail"
      padded={false}
      className={classes.wide}
      footer={
        <Anchor component={Link} to="/audit" size="xs">
          {t('dashboard.assurance.openTrail')}
        </Anchor>
      }
    >
      {audit.isError && <ErrorAlert error={audit.error} />}
      {audit.isPending && <LoadingIndicator />}
      {audit.isSuccess && items.length === 0 && <EmptyState icon="ScrollText" title={t('dashboard.assurance.noEvidence')} />}
      {items.length > 0 && (
        <Table.ScrollContainer minWidth={560}>
          <Table aria-label={t('dashboard.assurance.evidenceLabel')} highlightOnHover>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>{t('audit.columns.time')}</Table.Th>
                <Table.Th>{t('audit.columns.user')}</Table.Th>
                <Table.Th>{t('audit.columns.action')}</Table.Th>
                <Table.Th>{t('audit.columns.result')}</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {items.map((e) => (
                <Table.Tr key={e.seq}>
                  <Table.Td>{formatDateTime(e.at, i18n.language)}</Table.Td>
                  <Table.Td>{actor(e)}</Table.Td>
                  <Table.Td>{known(e.action) ?? <Code translate="no">{e.action}</Code>}</Table.Td>
                  <Table.Td>
                    <StatusBadge tone={RESULT_TONE[e.result] ?? 'neutral'}>{t(`audit.result.${e.result}`)}</StatusBadge>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      )}
    </Widget>
  );
}

// DashboardPage is the design's Overview (R10): what expires, what failed, what needs attention on the Operations tab;
// audit integrity, recovery readiness and the license on the Assurance tab (?view=assurance), which exists only when the
// role-filtered summary carries audit or backup data (never for an Operator). The parts the server leaves out for a role
// are null in the summary and not drawn.
export function DashboardPage() {
  const { t, i18n } = useTranslation();
  const { session } = useAuth();
  const role = session?.user.role;
  const now = useNow();
  const [params, setParams] = useSearchParams();
  const version = useQuery({ queryKey: ['version'], queryFn: getVersion });
  const summary = useQuery({ queryKey: DASHBOARD_KEY, queryFn: getDashboardSummary, refetchInterval: REFRESH_MS });
  const expiring = useQuery({ queryKey: EXPIRING_KEY, queryFn: () => getExpiring(30, 10), refetchInterval: REFRESH_MS });
  const alerts = useQuery({ queryKey: ALERTS_KEY, queryFn: getAlerts, refetchInterval: REFRESH_MS });

  let status = t('home.serverChecking');
  if (version.isSuccess) status = t('home.serverVersion', { version: version.data.version });
  if (version.isError) status = t('home.serverUnreachable');

  const s = summary.data;
  const loading = summary.isPending || expiring.isPending || alerts.isPending;
  // Each failing query shows its own error, so a partial dashboard says which part is missing.
  const failed = [summary, expiring, alerts].filter((q) => q.isError);
  const assuranceAllowed = !!(s?.audit || s?.backup);
  const view = params.get('view') === 'assurance' && assuranceAllowed ? 'assurance' : 'operations';
  return (
    <>
      <PageHeader
        eyebrow={new Intl.DateTimeFormat(i18n.language, { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' }).format(now)}
        title={t('dashboard.title')}
        description={t('dashboard.description')}
      />
      {failed.length > 0 && (
        <Stack gap="xs" mb="md">
          <Text fw={600}>{t('dashboard.loadFailed')}</Text>
          {failed.map((q, i) => (
            <ErrorAlert key={i} error={q.error} />
          ))}
        </Stack>
      )}
      {s?.setup_checklist && <SetupChecklist items={s.setup_checklist} />}
      <Tabs keepMounted={false} value={view} onChange={(v) => setParams(v === 'assurance' ? { view: 'assurance' } : {}, { replace: true })}>
        <div className={classes.tabsRow}>
          <Tabs.List aria-label={t('dashboard.tabs.label')} className={classes.tabsList}>
            <Tabs.Tab value="operations" className={classes.tabsTab}>
              {t('dashboard.tabs.operations')}
            </Tabs.Tab>
            {assuranceAllowed && (
              <Tabs.Tab value="assurance" className={classes.tabsTab}>
                {t('dashboard.tabs.assurance')}
              </Tabs.Tab>
            )}
          </Tabs.List>
          {/* " · " separates two complete translated strings; it is not sentence assembly. */}
          <span className={classes.updated} data-testid="server-status" aria-live="polite">
            {status}
            {s && ` · ${t('dashboard.updated', { time: formatDateTime(s.generated_at, i18n.language) })}`}
          </span>
        </div>
        {loading && <LoadingIndicator />}
        {s && <MetricStrip label={t('dashboard.metrics.label')} items={metrics(s, t)} />}
        <Tabs.Panel value="operations">
          <div className={classes.grid} aria-busy={loading}>
            {s && <ExpiryHorizon counts={s.certificates} />}
            {alerts.data && <AttentionList items={alerts.data.items} />}
            {expiring.data && <ExpiringList items={expiring.data.items} />}
            {s && <TargetsByStatus targets={s.targets} />}
            {s && <FailedDeployments deployments={s.deployments} />}
            {s && <RotationUpcoming rotation={s.rotation} />}
          </div>
        </Tabs.Panel>
        {assuranceAllowed && s && (
          <Tabs.Panel value="assurance">
            <div className={classes.assurance}>
              {s.audit && <AuditHead audit={s.audit} />}
              {s.backup && <BackupCard backup={s.backup} admin={role === 'admin'} />}
              <LicenseCard license={s.license} detailed={role === 'admin' || role === 'auditor'} />
              {view === 'assurance' && <EvidenceTrail />}
            </div>
          </Tabs.Panel>
        )}
      </Tabs>
    </>
  );
}
