import { Anchor, Code, Stack, Table } from '@mantine/core';
import { useInfiniteQuery, useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';
import { ROTATION_POLICIES_KEY, ROTATION_RUNS_KEY } from '../api/queryKeys';
import { listPolicies, listRuns, TERMINAL_RUN, type Policy, type RunSummary } from '../api/rotation';
import { PageLoader } from '../auth/guards';
import { ErrorAlert } from '../components/ErrorAlert';
import { RotationPath } from '../components/rotation/RotationPath';
import { durationText, labelOf, runTone } from '../components/rotationText';
import { CursorFooter, EmptyState, LinkTabs, PageHeader, Panel, ResourceTable, StatusBadge } from '../components/ui';
import { WRAP } from '../components/wrap';
import { formatDateTime } from '../datetime';
import { Icon } from '../design/Icon';
import { SSH_KEY_TABS } from './SSHKeysPage';
import classes from './Rotations.module.css';

// The page's own reads: every live policy (one answer, no cursor) and the runs, page by page.
const POLICIES_KEY = [...ROTATION_POLICIES_KEY, 'all'] as const;
const RUNS_KEY = [...ROTATION_RUNS_KEY, 'all'] as const;

function ActiveRun({ run, policy }: { run: RunSummary; policy: Policy | undefined }) {
  const { t, i18n } = useTranslation();
  const lang = i18n.language;
  // A license pause stops the clock: no end time is shown, only that the overlap is on hold (as on the run page).
  const time = run.paused_license
    ? run.status === 'overlap'
      ? t('rotation.overlapOnHold')
      : null
    : run.status === 'overlap' && run.overlap_until
      ? t('rotation.overlapUntil', { date: formatDateTime(run.overlap_until, lang) })
      : t('rotation.plannedFor', { date: formatDateTime(run.planned_for, lang) });
  return (
    <li className={classes.run} data-testid="active-rotation">
      <div className={classes.runHead}>
        <div className={classes.runTitle}>
          <span className={classes.runIcon}>
            <Icon name="RotateCw" size={16} />
          </span>
          <div>
            <h3 className={classes.runName}>
              {policy ? (
                <span translate="no">{policy.name}</span>
              ) : (
                // The policy is gone (deleted after the run started): the run is named by the key it replaces.
                <Code translate="no" style={WRAP}>
                  {run.old_fingerprint}
                </Code>
              )}
            </h3>
            {time && <p className={classes.runTime}>{time}</p>}
          </div>
        </div>
        <div className={classes.badges}>
          <StatusBadge tone={runTone(run.status)}>{labelOf(t, i18n, 'rotation.status', run.status)}</StatusBadge>
          {run.paused_license && (
            <StatusBadge tone="danger" icon="Pause">
              {t('rotation.step.paused')}
            </StatusBadge>
          )}
        </div>
      </div>
      <RotationPath status={run.status} />
      <Anchor component={Link} to={`/rotation/runs/${encodeURIComponent(run.id)}`} size="sm">
        {t('rotation.page.inspectRun')}
      </Anchor>
    </li>
  );
}

function PolicyRow({ p }: { p: Policy }) {
  const { t, i18n } = useTranslation();
  return (
    <Table.Tr>
      <Table.Td>
        <Anchor component={Link} to={`/ssh-keys/${encodeURIComponent(p.ssh_key_id)}`} className={classes.name} translate="no">
          {p.name}
        </Anchor>
      </Table.Td>
      <Table.Td>{p.interval_days === 1 ? t('rotation.everyDay') : t('rotation.every', { count: p.interval_days })}</Table.Td>
      <Table.Td>{durationText(t, p.overlap_minutes)}</Table.Td>
      <Table.Td>
        {p.open_rotation_id ? t('rotation.page.phaseCurrent') : p.next_run_at ? formatDateTime(p.next_run_at, i18n.language) : t('rotation.page.noNextRun')}
      </Table.Td>
      <Table.Td>
        <StatusBadge tone={p.enabled ? 'success' : 'neutral'}>{p.enabled ? t('rotation.on') : t('rotation.off')}</StatusBadge>
        {p.last_run_status && <p className={classes.secondary}>{t('rotation.lastRun', { status: labelOf(t, i18n, 'rotation.status', p.last_run_status) })}</p>}
      </Table.Td>
      <Table.Td>
        <div className={classes.links}>
          {p.open_rotation_id && (
            <Anchor component={Link} to={`/rotation/runs/${encodeURIComponent(p.open_rotation_id)}`} size="sm">
              {t('rotation.openRun')}
            </Anchor>
          )}
          {p.last_run_id && (
            <Anchor component={Link} to={`/rotation/runs/${encodeURIComponent(p.last_run_id)}`} size="sm">
              {t('rotation.openLastRun')}
            </Anchor>
          )}
        </div>
      </Table.Td>
    </Table.Tr>
  );
}

// RotationsPage is the design's Key rotations page (R19): the rotations that are running and every rotation policy. It
// only reads: a policy is created, previewed and run on its key's page (it needs the key, a step-up and the preview), and
// a run's decisions are on the run's page. Every role may read it (GET /rotation/policies and /rotation/runs are `read`).
export function RotationsPage() {
  const { t } = useTranslation();
  const policies = useQuery({ queryKey: POLICIES_KEY, queryFn: listPolicies });
  const runs = useInfiniteQuery({
    queryKey: RUNS_KEY,
    queryFn: ({ pageParam }) => listRuns({ cursor: pageParam }),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
  });
  const byId = new Map((policies.data?.items ?? []).map((p) => [p.id, p]));
  // Only the runs loaded so far: the page never claims there is no running rotation while older pages remain.
  const active = (runs.data?.pages.flatMap((p) => p.items) ?? []).filter((r) => !TERMINAL_RUN.has(r.status));
  const items = policies.data?.items ?? [];
  // The page appears once both first reads answered (each section then shows its own error), so the active runs are never
  // drawn without the names of their policies.
  if (policies.isPending || runs.isPending) return <PageLoader />;

  return (
    <Stack gap="md">
      <PageHeader title={t('nav.rotations')} description={t('rotation.page.description')} />
      <LinkTabs items={SSH_KEY_TABS(t)} label={t('sshKeys.page.sections')} />
      <Panel
        title={t('rotation.page.active')}
        aria-label={t('rotation.page.active')}
        footer={
          runs.data && runs.hasNextPage ? (
            <CursorFooter shown={active.length} hasMore={runs.hasNextPage} loading={runs.isFetchingNextPage} onMore={() => void runs.fetchNextPage()} moreLabel={t('sshKeys.loadMore')} />
          ) : undefined
        }
      >
        {runs.isError && !runs.data ? (
          <ErrorAlert error={runs.error} />
        ) : active.length > 0 ? (
          <>
            <ul className={classes.runs}>
              {active.map((r) => (
                <ActiveRun key={r.id} run={r} policy={byId.get(r.policy_id)} />
              ))}
            </ul>
            {!runs.hasNextPage && <p className={classes.secondary}>{t('ui.table.shown', { count: active.length })}</p>}
          </>
        ) : (
          <EmptyState icon="RotateCw" title={runs.hasNextPage ? t('rotation.page.noActiveLoaded') : t('rotation.page.noActive')} />
        )}
        {runs.isFetchNextPageError && <ErrorAlert error={runs.error} />}
      </Panel>
      {policies.isError ? (
        <ErrorAlert error={policies.error} />
      ) : items.length === 0 ? (
        <Panel title={t('rotation.page.policies')}>
          <EmptyState icon="KeyRound" title={t('rotation.page.noPolicies')} />
        </Panel>
      ) : (
        <ResourceTable label={t('rotation.page.policies')} minWidth={820}>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>{t('rotation.page.policyKey')}</Table.Th>
              <Table.Th>{t('rotation.page.interval')}</Table.Th>
              <Table.Th>{t('rotation.page.overlap')}</Table.Th>
              <Table.Th>{t('rotation.page.nextRun')}</Table.Th>
              <Table.Th>{t('rotation.page.state')}</Table.Th>
              <Table.Th>{t('rotation.page.runs')}</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {items.map((p) => (
              <PolicyRow key={p.id} p={p} />
            ))}
          </Table.Tbody>
        </ResourceTable>
      )}
    </Stack>
  );
}
