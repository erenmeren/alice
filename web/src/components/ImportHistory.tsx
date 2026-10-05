import { Anchor, Button, Code, Stack, Table, Text, Title } from '@mantine/core';
import { useInfiniteQuery, useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';
import { listAllTargets } from '../api/endpoints';
import { listKVImports, type KVImport } from '../api/keyvault';
import { KV_IMPORTS_KEY, VAULTS_KEY } from '../api/queryKeys';
import { formatDateTime } from '../datetime';
import { ErrorAlert } from './ErrorAlert';
import { reasonTitle } from './JobErrorAlert';
import { shortVersion } from './vaultText';
import { WRAP } from './wrap';

function stateText(i: KVImport): string {
  if (i.state === 'failed' && i.error?.reason === 'kv.import_outcome_unknown') return 'imports.state.unknown';
  return i.state === '' ? 'enum.unknown' : `imports.state.${i.state}`;
}

// ImportHistory lists the imports of one certificate into any vault, newest first. The API lists a
// vault's imports (filtered by certificate), so each vault is asked, and "Show more" follows the cursors.
export function ImportHistory({ certificateId }: { certificateId: string }) {
  const { t, i18n } = useTranslation();
  const vaults = useQuery({ queryKey: [...VAULTS_KEY, 'import-history'], queryFn: () => listAllTargets('azure_key_vault') });
  const ids = (vaults.data?.items ?? []).map((v) => v.id);
  // One page of every vault that still has pages; the cursors travel as one map. A vault whose answer
  // has no next_cursor is done and is left out of the next request.
  const imports = useInfiniteQuery({
    queryKey: [...KV_IMPORTS_KEY, 'certificate', certificateId, ids.join(',')],
    enabled: vaults.isSuccess && ids.length > 0,
    initialPageParam: Object.fromEntries(ids.map((id) => [id, null])) as Record<string, string | null>,
    queryFn: async ({ pageParam }) => {
      const open = Object.entries(pageParam);
      const pages = await Promise.all(open.map(async ([id, cursor]) => ({ id, page: await listKVImports(id, certificateId, 50, cursor) })));
      return { items: pages.flatMap((p) => p.page.items), next: Object.fromEntries(pages.filter((p) => p.page.next_cursor).map((p) => [p.id, p.page.next_cursor])) as Record<string, string | null> };
    },
    getNextPageParam: (last) => (Object.keys(last.next).length > 0 ? last.next : undefined),
    // Follow what is not finished (the existing polling pattern): a running import often, an uncertain one
    // (a later check of the vault settles it) slowly; nothing once every import shown is final.
    refetchInterval: (q) => {
      const states = (q.state.data?.pages ?? []).flatMap((p) => p.items.map((i) => i.state));
      if (states.some((s) => s === 'queued' || s === 'running')) return 3_000;
      return states.includes('uncertain') ? 30_000 : false;
    },
  });
  const names = new Map((vaults.data?.items ?? []).map((v) => [v.id, v.name]));
  const items = (imports.data?.pages.flatMap((p) => p.items) ?? []).sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at));
  const error = vaults.error ?? imports.error ?? null;
  if (vaults.isSuccess && ids.length === 0) return null;
  return (
    <Stack gap="sm" data-testid="import-history">
      <Title order={2} size="h3">
        {t('imports.history.title')}
      </Title>
      <ErrorAlert error={error} />
      {imports.isSuccess && items.length === 0 && <Text size="sm">{t('imports.history.empty')}</Text>}
      {items.length > 0 && (
        <Table.ScrollContainer minWidth={640}>
          <Table striped aria-label={t('imports.history.tableLabel')}>
            <Table.Thead>
              <Table.Tr>
                {(['when', 'vault', 'name', 'state', 'version'] as const).map((c) => (
                  <Table.Th key={c}>{t(`imports.history.columns.${c}`)}</Table.Th>
                ))}
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {items.map((i) => (
                <Table.Tr key={i.id} data-testid="import-row">
                  <Table.Td>{formatDateTime(i.created_at, i18n.language)}</Table.Td>
                  <Table.Td style={WRAP}>
                    <Anchor component={Link} to={`/key-vaults/${i.target_id}`} translate="no">
                      {names.get(i.target_id) ?? ''}
                    </Anchor>
                  </Table.Td>
                  <Table.Td>
                    <Code translate="no" style={WRAP}>
                      {i.name}
                    </Code>
                  </Table.Td>
                  <Table.Td>
                    <Stack gap={2}>
                      <Text size="sm">{t(stateText(i))}</Text>
                      {i.state === 'failed' && i.error && (
                        <Text size="xs" style={WRAP}>
                          {reasonTitle(t, i18n, i.error.reason, i.error.params ?? {})}
                        </Text>
                      )}
                    </Stack>
                  </Table.Td>
                  <Table.Td>{i.version ? <Code translate="no">{shortVersion(i.version)}</Code> : ''}</Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      )}
      {imports.hasNextPage && (
        <Button variant="default" w="fit-content" loading={imports.isFetchingNextPage} onClick={() => void imports.fetchNextPage()}>
          {t('vaults.showMore')}
        </Button>
      )}
    </Stack>
  );
}
