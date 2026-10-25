import { Anchor, SegmentedControl, Stack, Table, Text } from '@mantine/core';
import { useInfiniteQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';
import { listIncidents, type Incident, type IncidentListQuery } from '../api/incidents';
import { incidentListKey } from '../api/queryKeys';
import { PageLoader } from '../auth/guards';
import { ErrorAlert } from '../components/ErrorAlert';
import { CursorFooter, EmptyState, PageHeader, Panel, ResourceTable, StatusBadge } from '../components/ui';
import { formatDateTime } from '../datetime';
import { STATE_ICON, STATE_TONE } from './incidentStates';

// The filters of the list: every incident, the open ones, or one of three states.
const FILTERS = ['all', 'open', 'needs_attention', 'completed', 'closed'] as const;
type Filter = (typeof FILTERS)[number];

const PAGE_SIZE = 50;

function queryOf(f: Filter): IncidentListQuery {
  switch (f) {
    case 'all':
      return {};
    case 'open':
      return { open: true };
    default:
      return { state: f };
  }
}

// places is the incident's replaced places of those Alice replaces: verified of every place not skipped.
function places(i: Incident): { verified: number; total: number } {
  const c = i.counts;
  const total = Object.entries(c).reduce((n, [status, count]) => (status === 'skipped' ? n : n + (count ?? 0)), 0);
  return { verified: c.verified ?? 0, total };
}

function IncidentRow({ i }: { i: Incident }) {
  const { t, i18n } = useTranslation();
  const lang = i18n.language;
  return (
    <Table.Tr>
      <Table.Td>
        <Anchor component={Link} to={`/incidents/${encodeURIComponent(i.id)}`} state={{ from: 'incidents' }} translate="no">
          {i.certificate_name}
        </Anchor>
      </Table.Td>
      <Table.Td>
        <StatusBadge tone={STATE_TONE[i.state]} icon={STATE_ICON[i.state]}>
          {t(`incidents.states.${i.state}`)}
        </StatusBadge>
      </Table.Td>
      <Table.Td>{t(`incidents.revocation.${i.revocation}`)}</Table.Td>
      <Table.Td>{t('incidents.list.places', places(i))}</Table.Td>
      <Table.Td>
        {formatDateTime(i.created_at, lang)}
        {i.started_by_name && (
          <Text size="xs" c="dimmed">
            {i.started_by_name}
          </Text>
        )}
      </Table.Td>
      <Table.Td>{i.finished_at ? formatDateTime(i.finished_at, lang) : '—'}</Table.Td>
    </Table.Tr>
  );
}

// IncidentsPage lists every key compromise incident the reader may see (its services only, as the server decides),
// newest first, with a filter and paging (D2, R64). Reading incidents is `read` for every role; the actions are on each
// incident's page.
export function IncidentsPage() {
  const { t } = useTranslation();
  const [filter, setFilter] = useState<Filter>('all');
  const q = queryOf(filter);
  const list = useInfiniteQuery({
    queryKey: incidentListKey(q),
    queryFn: ({ pageParam, signal }) => listIncidents({ ...q, cursor: pageParam, limit: PAGE_SIZE }, signal),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
  });
  const items = list.data?.pages.flatMap((p) => p.items) ?? [];

  return (
    <Stack gap="md">
      <PageHeader icon="ShieldAlert" title={t('incidents.list.title')} description={t('incidents.list.description')} />
      <SegmentedControl
        size="xs"
        style={{ alignSelf: 'flex-start' }}
        aria-label={t('incidents.list.filterLabel')}
        value={filter}
        onChange={(v) => setFilter(v as Filter)}
        data={FILTERS.map((f) => ({ value: f, label: t(`incidents.list.filter.${f}`) }))}
      />
      {list.isPending && <PageLoader />}
      <ErrorAlert error={list.error} />
      {list.isSuccess && items.length === 0 && (
        <Panel>
          <EmptyState icon="ShieldAlert" title={filter === 'all' ? t('incidents.list.empty') : t('incidents.list.emptyFiltered')} />
        </Panel>
      )}
      {items.length > 0 && (
        <ResourceTable
          label={t('incidents.list.tableLabel')}
          minWidth={820}
          footer={
            <CursorFooter
              shown={items.length}
              hasMore={list.hasNextPage}
              loading={list.isFetchingNextPage}
              onMore={() => void list.fetchNextPage()}
              moreLabel={t('incidents.list.loadMore')}
            />
          }
        >
          <Table.Thead>
            <Table.Tr>
              <Table.Th>{t('incidents.list.columns.certificate')}</Table.Th>
              <Table.Th>{t('incidents.list.columns.state')}</Table.Th>
              <Table.Th>{t('incidents.list.columns.revocation')}</Table.Th>
              <Table.Th>{t('incidents.list.columns.places')}</Table.Th>
              <Table.Th>{t('incidents.list.columns.started')}</Table.Th>
              <Table.Th>{t('incidents.list.columns.finished')}</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {items.map((i) => (
              <IncidentRow key={i.id} i={i} />
            ))}
          </Table.Tbody>
        </ResourceTable>
      )}
    </Stack>
  );
}
