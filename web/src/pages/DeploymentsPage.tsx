import { Anchor, Button, Code, Group, Stack, Table, Text, Title } from '@mantine/core';
import { useInfiniteQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';
import { deploymentView } from '../api/deployments';
import { listDeployments } from '../api/endpoints';
import { DEPLOYMENTS_KEY } from '../api/queryKeys';
import type { Deployment } from '../api/types';
import { DeploymentStatusBadge } from '../components/DeploymentView';
import { ErrorAlert } from '../components/ErrorAlert';
import { WRAP } from '../components/wrap';
import { formatDateTime } from '../datetime';
import { deploymentStateKey } from '../api/enums';

// DeploymentsPage is the history of every certificate deployment, newest first, with its status.
// The status is the deployment's own (a deployment being recovered shows that, not its job's).
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
      <Title order={1}>{t('deployments.title')}</Title>
      <Text size="sm">{t('deployments.intro')}</Text>
      <ErrorAlert error={list.error} />
      {list.isSuccess && items.length === 0 && <Text c="gray.7">{t('deployments.empty')}</Text>}
      {items.length > 0 && (
        <Table.ScrollContainer minWidth={820}>
          <Table striped aria-label={t('deployments.tableLabel')}>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>{t('deployments.columns.when')}</Table.Th>
                <Table.Th>{t('deployments.columns.server')}</Table.Th>
                <Table.Th>{t('deployments.columns.file')}</Table.Th>
                <Table.Th>{t('deployments.columns.certificate')}</Table.Th>
                <Table.Th>{t('deployments.columns.result')}</Table.Th>
                <Table.Th />
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {items.map((d) => (
                <Row key={d.id} d={d} when={formatDateTime(d.created_at, i18n.language)} />
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      )}
      {list.hasNextPage && (
        <Group>
          <Button variant="default" loading={list.isFetchingNextPage} onClick={() => void list.fetchNextPage()}>
            {t('deployments.loadMore')}
          </Button>
        </Group>
      )}
    </Stack>
  );
}

function Row({ d, when }: { d: Deployment; when: string }) {
  const { t } = useTranslation();
  const view = deploymentView(d);
  const labelId = `open-${d.id}`;
  return (
    <Table.Tr data-testid="deployment-row">
      <Table.Td>{when}</Table.Td>
      <Table.Td style={WRAP}>
        <Anchor component={Link} to={`/servers/${d.target_id}`} translate="no">
          {d.target_name}
        </Anchor>
      </Table.Td>
      <Table.Td>
        <Code translate="no" style={WRAP}>
          {d.cert_path}
        </Code>
      </Table.Td>
      <Table.Td style={WRAP}>
        <Anchor component={Link} to={`/certificates/${d.certificate_id}`} translate="no">
          {d.certificate_name}
        </Anchor>
        {d.source === 'key_vault' && (
          <Text size="xs" data-testid="deployment-source" style={WRAP}>
            {t('deployments.source.key_vault')} <span translate="no">{d.vault_name}</span>
            {d.kv_version && (
              <>
                {' '}
                <Code translate="no">{d.kv_version.slice(0, 8)}</Code>
              </>
            )}
          </Text>
        )}
      </Table.Td>
      <Table.Td>
        <Stack gap={2}>
          <DeploymentStatusBadge d={d} />
          {view === 'recovering' && <Text size="xs">{t(deploymentStateKey(d.state))}</Text>}
          {view === 'held' && <Text size="xs">{t('deployments.held')}</Text>}
        </Stack>
      </Table.Td>
      <Table.Td>
        <span id={labelId} hidden translate="no">
          {t('deployments.openNamed', { name: `${d.certificate_name}, ${when}` })}
        </span>
        <Anchor component={Link} to={`/deployments/${d.id}`} aria-labelledby={labelId}>
          {t('deployments.open')}
        </Anchor>
      </Table.Td>
    </Table.Tr>
  );
}
