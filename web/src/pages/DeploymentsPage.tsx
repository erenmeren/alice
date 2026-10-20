import { ActionIcon, Anchor, Code, Stack, Table, VisuallyHidden } from '@mantine/core';
import { useInfiniteQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';
import { deploymentView, untrustedSuccess } from '../api/deployments';
import { deploymentStateKey, verifiedKey } from '../api/enums';
import { listDeployments } from '../api/endpoints';
import { DEPLOYMENTS_KEY } from '../api/queryKeys';
import type { Deployment } from '../api/types';
import { CodeText } from '../components/CodeText';
import { DeploymentStatusBadge } from '../components/DeploymentView';
import { ErrorAlert } from '../components/ErrorAlert';
import { CursorFooter, EmptyState, PageHeader, Panel, ResourceTable } from '../components/ui';
import { formatDateTime } from '../datetime';
import { Icon } from '../design/Icon';
import classes from './Deployments.module.css';

// DeploymentsPage is the history of every certificate deployment, newest first, with its status.
// The status is the deployment's own (a deployment being recovered shows that, not its job's). The
// history is cursor-paged, so it never states totals per outcome (R20).
export function DeploymentsPage() {
  const { t, i18n } = useTranslation();
  const list = useInfiniteQuery({
    queryKey: [...DEPLOYMENTS_KEY, 'history'],
    queryFn: ({ pageParam }) => listDeployments({ cursor: pageParam, limit: 50 }),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
  });
  const items = list.data?.pages.flatMap((p) => p.items) ?? [];

  return (
    <Stack gap="md">
      <PageHeader title={t('deployments.title')} description={t('deployments.page.description')} />
      <ErrorAlert error={list.error} />
      {list.isSuccess && items.length === 0 && (
        <Panel>
          <EmptyState icon="Rocket" title={t('deployments.empty')} description={t('deployments.intro')} />
        </Panel>
      )}
      {items.length > 0 && (
        <ResourceTable
          label={t('deployments.tableLabel')}
          minWidth={820}
          footer={
            <CursorFooter
              shown={items.length}
              hasMore={list.hasNextPage}
              loading={list.isFetchingNextPage}
              onMore={() => void list.fetchNextPage()}
              moreLabel={t('deployments.loadMore')}
            />
          }
        >
          <Table.Thead>
            <Table.Tr>
              <Table.Th>{t('deployments.columns.certificate')}</Table.Th>
              <Table.Th>{t('deployments.columns.server')}</Table.Th>
              <Table.Th>{t('deployments.page.triggeredBy')}</Table.Th>
              <Table.Th>{t('deployments.columns.result')}</Table.Th>
              <Table.Th>{t('deployments.columns.when')}</Table.Th>
              <Table.Th>
                <VisuallyHidden>{t('deployments.open')}</VisuallyHidden>
              </Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {items.map((d) => (
              <Row key={d.id} d={d} when={formatDateTime(d.created_at, i18n.language)} />
            ))}
          </Table.Tbody>
        </ResourceTable>
      )}
    </Stack>
  );
}

function Row({ d, when }: { d: Deployment; when: string }) {
  const { t } = useTranslation();
  const view = deploymentView(d);
  const unverified = view === 'final' && d.status === 'succeeded' && d.verified !== 'remote' && d.verified !== 'local';
  const untrusted = view === 'final' && !unverified && untrustedSuccess(d);
  const labelId = `open-${d.id}`;
  return (
    <Table.Tr data-testid="deployment-row">
      <Table.Td>
        <div className={classes.resourceName}>
          <span className={classes.resourceIcon}>
            <Icon name="Rocket" size={16} />
          </span>
          <div>
            <Anchor component={Link} to={`/certificates/${d.certificate_id}`} className={classes.name} translate="no">
              {d.certificate_name}
            </Anchor>
            <p className={classes.secondaryMono} translate="no">
              {d.id}
            </p>
          </div>
        </div>
      </Table.Td>
      <Table.Td>
        <Anchor component={Link} to={`/servers/${d.target_id}`} className={classes.name} translate="no">
          {d.target_name}
        </Anchor>
        <p className={classes.secondary}>
          <Code translate="no">{d.cert_path}</Code>
        </p>
      </Table.Td>
      <Table.Td>
        <span className={classes.small} translate={d.requested_by_name ? 'no' : undefined}>
          {d.requested_by_name || t('deployments.page.system')}
        </span>
        {d.source === 'key_vault' && (
          <p className={classes.secondary} data-testid="deployment-source">
            <CodeText i18nKey="deployments.source.key_vault_named" param="name" value={d.vault_name} />
            {d.kv_version && (
              <>
                {' '}
                <Code translate="no">{d.kv_version.slice(0, 8)}</Code>
              </>
            )}
          </p>
        )}
      </Table.Td>
      <Table.Td>
        {/* A success Alice did not verify (skipped, or no verification) is not a plain green Succeeded: the word stays,
            the tone is the detail page's warning and a line says what happened to the verification. */}
        <DeploymentStatusBadge d={d} tone={unverified || untrusted ? 'warning' : undefined} />
        {unverified && <p className={classes.secondary}>{t('deployments.page.verification', { state: t(verifiedKey(d.verified)) })}</p>}
        {/* R51: served, but the chain is not trusted: the same warning tone, and a line that says so. */}
        {untrusted && (
          <p className={classes.secondary}>
            {t(d.verification.trust?.error === 'name_mismatch' ? 'deployments.page.nameMismatch' : 'deployments.page.untrusted')}
          </p>
        )}
        {view === 'recovering' && <p className={classes.secondary}>{t(deploymentStateKey(d.state))}</p>}
        {view === 'held' && <p className={classes.secondary}>{t('deployments.held')}</p>}
      </Table.Td>
      <Table.Td>
        <span className={classes.mono}>{when}</span>
      </Table.Td>
      <Table.Td>
        <span id={labelId} hidden translate="no">
          {t('deployments.openNamed', { name: `${d.certificate_name}, ${when}` })}
        </span>
        <ActionIcon component={Link} to={`/deployments/${d.id}`} variant="subtle" color="gray" className={classes.openLink} aria-labelledby={labelId}>
          <Icon name="ChevronRight" size={16} />
        </ActionIcon>
      </Table.Td>
    </Table.Tr>
  );
}
