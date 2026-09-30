import { useState, type FormEvent } from 'react';
import { Alert, Badge, Button, Code, Group, NativeSelect, Stack, Table, Text, TextInput, Title } from '@mantine/core';
import { useInfiniteQuery, useMutation } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { auditExportUrl, listAudit, verifyAudit } from '../api/endpoints';
import type { AuditEntry, AuditResult } from '../api/types';
import { ErrorAlert } from '../components/ErrorAlert';
import { formatDateTime } from '../datetime';

const PAGE_SIZE = 50;
const RESULT_COLORS: Record<AuditResult, string> = { success: 'green', failure: 'orange', denied: 'red' };

interface Filters {
  action: string;
  result: '' | AuditResult;
}

// actionKey maps a stored action ("auth.login") to its label key ("audit.actions.auth_login").
export function actionKey(action: string): string {
  return `audit.actions.${action.replace(/\./g, '_')}`;
}

export function AuditPage() {
  const { t, i18n } = useTranslation();
  const [draft, setDraft] = useState<Filters>({ action: '', result: '' });
  const [filters, setFilters] = useState<Filters>({ action: '', result: '' });

  const entries = useInfiniteQuery({
    queryKey: ['audit', filters],
    queryFn: ({ pageParam }) =>
      listAudit({ limit: PAGE_SIZE, cursor: pageParam, action: filters.action || undefined, result: filters.result || undefined }),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
  });
  const verify = useMutation({ mutationFn: verifyAudit });

  const label = (e: AuditEntry) => (i18n.exists(actionKey(e.action)) ? t(actionKey(e.action)) : e.action);
  const actor = (e: AuditEntry) => (e.actor_type === 'system' ? t('audit.systemActor', { name: e.actor_name }) : e.actor_name);
  const apply = (ev: FormEvent) => {
    ev.preventDefault();
    setFilters({ action: draft.action.trim(), result: draft.result });
  };
  const items = entries.data?.pages.flatMap((p) => p.items) ?? [];

  return (
    <Stack gap="md">
      <Group justify="space-between">
        <Title order={1}>{t('audit.title')}</Title>
        <Group gap="xs">
          <Button onClick={() => verify.mutate()} loading={verify.isPending}>
            {t('audit.verify')}
          </Button>
          <Button component="a" href={auditExportUrl('csv')} download variant="default">
            {t('audit.exportCsv')}
          </Button>
          <Button component="a" href={auditExportUrl('json')} download variant="default">
            {t('audit.exportJson')}
          </Button>
        </Group>
      </Group>

      {verify.isError && <ErrorAlert error={verify.error} />}
      {verify.isSuccess && (
        <Alert
          color={verify.data.intact ? 'green' : 'red'}
          role="status"
          title={verify.data.intact ? t('audit.intact') : t('audit.broken', { seq: verify.data.first_bad_seq ?? 0 })}
        >
          <Stack gap={4}>
            <Text size="sm">
              {t('audit.checked', { count: verify.data.checked, formatted: new Intl.NumberFormat(i18n.language).format(verify.data.checked) })}
            </Text>
            {verify.data.intact && (
              <Text size="sm">
                {t('audit.headHash')} <Code>{verify.data.head_hash}</Code>
              </Text>
            )}
            {!verify.data.intact && <Text size="sm">{t('audit.brokenHelp')}</Text>}
          </Stack>
        </Alert>
      )}

      <form onSubmit={apply}>
        <Group align="flex-end" gap="sm">
          <TextInput
            label={t('audit.filters.action')}
            value={draft.action}
            onChange={(e) => setDraft({ ...draft, action: e.currentTarget.value })}
          />
          <NativeSelect
            label={t('audit.filters.result')}
            value={draft.result}
            onChange={(e) => setDraft({ ...draft, result: e.currentTarget.value as Filters['result'] })}
            data={[
              { value: '', label: t('audit.filters.anyResult') },
              { value: 'success', label: t('audit.result.success') },
              { value: 'failure', label: t('audit.result.failure') },
              { value: 'denied', label: t('audit.result.denied') },
            ]}
          />
          <Button type="submit" variant="light">
            {t('audit.filters.apply')}
          </Button>
        </Group>
      </form>

      {entries.isError && <ErrorAlert error={entries.error} />}
      {entries.isSuccess && items.length === 0 && <Text c="gray.7">{t('audit.empty')}</Text>}
      {items.length > 0 && (
        <Table striped>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>{t('audit.columns.time')}</Table.Th>
              <Table.Th>{t('audit.columns.user')}</Table.Th>
              <Table.Th>{t('audit.columns.action')}</Table.Th>
              <Table.Th>{t('audit.columns.result')}</Table.Th>
              <Table.Th>{t('audit.columns.ip')}</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {items.map((e) => (
              <Table.Tr key={e.seq}>
                <Table.Td>{formatDateTime(e.at, i18n.language)}</Table.Td>
                <Table.Td>{actor(e)}</Table.Td>
                <Table.Td>{label(e)}</Table.Td>
                <Table.Td>
                  <Badge color={RESULT_COLORS[e.result]} variant="light">
                    {t(`audit.result.${e.result}`)}
                  </Badge>
                </Table.Td>
                <Table.Td>
                  <Text ff="monospace" size="sm">
                    {e.ip ?? ''}
                  </Text>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      )}
      {entries.hasNextPage && (
        <Button variant="default" onClick={() => void entries.fetchNextPage()} loading={entries.isFetchingNextPage}>
          {t('audit.loadMore')}
        </Button>
      )}
    </Stack>
  );
}
