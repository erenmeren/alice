import { ActionIcon, Anchor, Button, Stack, Table, VisuallyHidden } from '@mantine/core';
import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, useNavigate } from 'react-router';
import { listAllServers } from '../api/endpoints';
import { isServerType } from '../api/webServer';
import { TARGETS_KEY } from '../api/queryKeys';
import { inServiceFilter } from '../api/services';
import type { Target } from '../api/types';
import { useAuth } from '../auth/AuthProvider';
import { can } from '../auth/permissions';
import { AddServerModal } from '../components/AddServerModal';
import { BlockedJobsPanel } from '../components/BlockedJobsPanel';
import { ErrorAlert } from '../components/ErrorAlert';
import { reasonTitle } from '../components/JobErrorAlert';
import { PlatformKeyPanel } from '../components/PlatformKeyPanel';
import { ServiceBadge, ServiceFilters, useServiceFilters } from '../components/services/shared';
import { TargetStatusBadge } from '../components/TargetStatusBadge';
import { EmptyState, PageHeader, Panel, ResourceTable, StatusBadge } from '../components/ui';
import { formatDateTime } from '../datetime';
import { Icon } from '../design/Icon';
import classes from './TargetsPage.module.css';

// TargetsPage lists the managed servers for every role (metadata only, never credentials, R3).
// Administrators also get "Add server", the paused changes and the preparation commands.
export function TargetsPage() {
  const { t } = useTranslation();
  const { session } = useAuth();
  const navigate = useNavigate();
  // Adding needs targets.manage on some service; the paused changes are confirmed with jobs.confirm.
  const canAdd = can(session, 'targets.manage');
  const canConfirmJobs = can(session, 'jobs.confirm');
  const targets = useQuery({ queryKey: TARGETS_KEY, queryFn: listAllServers });
  const [adding, setAdding] = useState(false);
  const items = targets.data?.items ?? [];

  return (
    <Stack gap={0}>
      <PageHeader
        title={t('targets.title')}
        description={t('targets.page.description')}
        actions={
          canAdd && (
            <Button leftSection={<Icon name="Plus" size={15} />} onClick={() => setAdding(true)}>
              {t('targets.add')}
            </Button>
          )
        }
      />
      <Stack gap="lg">
        <ErrorAlert error={targets.error} />
        {targets.isSuccess && <MiniStats items={items} />}
        {canConfirmJobs && <BlockedJobsPanel />}
        {targets.isSuccess && items.length === 0 && (
          <Panel>
            <EmptyState icon="Server" title={t('targets.empty')} />
          </Panel>
        )}
        {items.length > 0 && <ServersTable items={items} />}
        {/* Below the list: the empty state's text points to "the command below". */}
        {canAdd && <PlatformKeyPanel />}
      </Stack>
      {adding && (
        <AddServerModal
          onClose={() => setAdding(false)}
          onAdded={(tg) => {
            setAdding(false);
            navigate(`/servers/${tg.id}`, { state: { added: true } });
          }}
        />
      )}
    </Stack>
  );
}

// MiniStats is the design's connection summary. The servers list is read completely (listAllServers), so these
// counts are true totals (R20), never counts of a loaded page. Every server is in one bucket: the design's three
// (connected, identity changed, unreachable) always; a refused sign-in and a server waiting for its fingerprint on their
// own when there are any; the remaining states (checking, partly working, disabled) as a labelled remainder.
function MiniStats({ items }: { items: Target[] }) {
  const { t } = useTranslation();
  const count = (status: Target['status']) => items.filter((s) => s.status === status).length;
  const known = ['ok', 'host_key_changed', 'unreachable', 'auth_failed', 'pending_host_key'];
  const other = items.filter((s) => !known.includes(s.status)).length;
  const stats: { key: string; n: number; label: string; tone?: string; always?: boolean }[] = [
    { key: 'total', n: items.length, label: t('targets.page.servers', { count: items.length }), always: true },
    { key: 'ok', n: count('ok'), label: t('targets.page.connected'), tone: 'success', always: true },
    { key: 'changed', n: count('host_key_changed'), label: t('targets.page.identityChanged'), tone: 'danger', always: true },
    { key: 'unreachable', n: count('unreachable'), label: t('targets.page.unreachable'), tone: 'warning', always: true },
    { key: 'authFailed', n: count('auth_failed'), label: t('targets.page.signInRefused'), tone: 'danger' },
    { key: 'pending', n: count('pending_host_key'), label: t('targets.page.awaiting'), tone: 'warning' },
    { key: 'other', n: other, label: t('targets.page.otherStates', { count: other }) },
  ];
  return (
    <ul role="list" aria-label={t('targets.page.summary')} className={classes.miniStats}>
      {stats.filter((s) => s.always || s.n > 0).map((s) => (
        <li key={s.key} className={classes.miniStat} data-tone={s.tone}>
          {s.tone && <span className={classes.dot} aria-hidden="true" />}
          <b>{s.n}</b> {s.label}
        </li>
      ))}
    </ul>
  );
}

// ServersTable filters by service and environment in the browser: the list is read completely.
function ServersTable({ items: all }: { items: Target[] }) {
  const { t, i18n } = useTranslation();
  const [serviceFilter, setServiceFilter] = useServiceFilters();
  const items = all.filter((tg) => inServiceFilter(tg.service, serviceFilter));
  return (
    <ResourceTable
      label={t('targets.title')}
      testId="targets-table"
      minWidth={760}
      toolbar={<ServiceFilters value={serviceFilter} onChange={setServiceFilter} />}
      footer={<span>{t('targets.page.vaultsElsewhere')}</span>}
    >
      <Table.Thead>
        <Table.Tr>
          <Table.Th>{t('targets.page.columns.server')}</Table.Th>
          <Table.Th>{t('targets.columns.address')}</Table.Th>
          <Table.Th>{t('targets.page.columns.platform')}</Table.Th>
          <Table.Th>{t('targets.page.columns.connection')}</Table.Th>
          <Table.Th>{t('targets.page.columns.lastConnected')}</Table.Th>
          <Table.Th>{t('services.column')}</Table.Th>
          <Table.Th>
            <VisuallyHidden>{t('targets.page.columns.open')}</VisuallyHidden>
          </Table.Th>
        </Table.Tr>
      </Table.Thead>
      <Table.Tbody>
        {items.length === 0 && (
          <Table.Tr>
            <Table.Td colSpan={7}>{t('services.filter.noMatch')}</Table.Td>
          </Table.Tr>
        )}
        {items.map((tg) => (
          <Table.Tr key={tg.id}>
            <Table.Td>
              <div className={classes.resourceName}>
                <span className={classes.resourceIcon}>
                  <Icon name="Server" size={16} />
                </span>
                <div>
                  <Anchor component={Link} to={`/servers/${tg.id}`} className={classes.name} translate="no">
                    {tg.name}
                  </Anchor>
                  {tg.facts.os.pretty_name && <p className={classes.secondary}>{tg.facts.os.pretty_name}</p>}
                </div>
              </div>
            </Table.Td>
            <Table.Td>
              <span className={classes.mono} translate="no">{`${tg.host}:${tg.port}`}</span>
            </Table.Td>
            <Table.Td>
              {isServerType(tg.type) && (
                <StatusBadge tone="neutral" icon="Server" size="sm">
                  {t(`targets.typeLabel.${tg.type}`)}
                </StatusBadge>
              )}
            </Table.Td>
            <Table.Td>
              <TargetStatusBadge status={tg.status} />
              {tg.last_error && <p className={classes.secondary}>{reasonTitle(t, i18n, tg.last_error.reason)}</p>}
            </Table.Td>
            <Table.Td>
              <span className={classes.mono}>{tg.last_success_at ? formatDateTime(tg.last_success_at, i18n.language) : t('targets.page.never')}</span>
            </Table.Td>
            <Table.Td>
              <ServiceBadge service={tg.service} />
            </Table.Td>
            <Table.Td>
              <ActionIcon component={Link} to={`/servers/${tg.id}`} variant="subtle" color="gray" className={classes.openLink} aria-label={t('targets.page.openNamed', { name: tg.name })}>
                <Icon name="ChevronRight" size={16} />
              </ActionIcon>
            </Table.Td>
          </Table.Tr>
        ))}
      </Table.Tbody>
    </ResourceTable>
  );
}
