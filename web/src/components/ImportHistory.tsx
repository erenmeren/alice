import { Anchor, Button, Code, Stack, Table, Text, Title } from '@mantine/core';
import { useInfiniteQuery, useQuery } from '@tanstack/react-query';
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';
import { ApiError } from '../api/client';
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
    // One vault that fails does not hide the others: what answered is shown. A vault that is gone (404: deleted between
    // the two requests) is left out silently; any other failure is reported for that vault, with a way to try again.
    queryFn: async ({ pageParam }) => {
      const open = Object.entries(pageParam);
      const settled = await Promise.allSettled(open.map(async ([id, cursor]) => ({ id, page: await listKVImports(id, certificateId, 50, cursor) })));
      const pages = settled.flatMap((r) => (r.status === 'fulfilled' ? [r.value] : []));
      const failed = settled.flatMap((r, i) => (r.status === 'rejected' && !(r.reason instanceof ApiError && r.reason.status === 404) ? [{ id: open[i][0], error: r.reason as unknown }] : []));
      return { failed, items: pages.flatMap((p) => p.page.items), next: Object.fromEntries(pages.filter((p) => p.page.next_cursor).map((p) => [p.id, p.page.next_cursor])) as Record<string, string | null> };
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
  // A vault whose read failed is retried alone; what it answers is kept here and merged in.
  const [recovered, setRecovered] = useState<Record<string, KVImport[]>>({});
  const [retryErrors, setRetryErrors] = useState<Record<string, { error: unknown; at: number }>>({});
  const [retrying, setRetrying] = useState<string | null>(null);
  const names = new Map((vaults.data?.items ?? []).map((v) => [v.id, v.name]));
  const seen = new Set<string>();
  const items = [...(imports.data?.pages.flatMap((p) => p.items) ?? []), ...Object.values(recovered).flat()]
    .filter((i) => !seen.has(i.id) && !!seen.add(i.id))
    .sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at));
  const failures = new Map<string, unknown>();
  // A retry's error stands only until the main read has answered again after it.
  for (const page of imports.data?.pages ?? []) for (const f of page.failed) failures.set(f.id, retryErrors[f.id] && retryErrors[f.id].at > imports.dataUpdatedAt ? retryErrors[f.id].error : f.error);
  for (const id of Object.keys(recovered)) failures.delete(id);
  const error = vaults.error ?? imports.error ?? null;
  // A retried vault is followed like the others: while one of its imports is still moving, it is read again.
  const moving = Object.entries(recovered)
    .filter(([, rows]) => rows.some((i) => i.state === 'queued' || i.state === 'running'))
    .map(([id]) => id)
    .join(',');
  useEffect(() => {
    if (moving === '') return;
    const timer = setTimeout(() => {
      for (const id of moving.split(',')) {
        listKVImports(id, certificateId, 50, null)
          .then((page) => setRecovered((r) => ({ ...r, [id]: page.items })))
          .catch(() => undefined);
      }
    }, 3_000);
    return () => clearTimeout(timer);
  }, [moving, recovered, certificateId]);
  const tryAgain = async (vaultId: string) => {
    setRetrying(vaultId);
    try {
      const page = await listKVImports(vaultId, certificateId, 50, null);
      setRecovered((r) => ({ ...r, [vaultId]: page.items }));
      setRetryErrors((r) => Object.fromEntries(Object.entries(r).filter(([k]) => k !== vaultId)));
    } catch (e) {
      // A vault that is gone by now is dropped without a word, as in the first read.
      if (e instanceof ApiError && e.status === 404) setRecovered((r) => ({ ...r, [vaultId]: [] }));
      else setRetryErrors((r) => ({ ...r, [vaultId]: { error: e, at: Date.now() } }));
    }
    setRetrying(null);
  };
  if (vaults.isSuccess && ids.length === 0) return null;
  return (
    <Stack gap="sm" data-testid="import-history">
      <Title order={2} size="h3">
        {t('imports.history.title')}
      </Title>
      <ErrorAlert error={error} />
      {[...failures].map(([id, e]) => (
        <Stack gap={6} key={id} data-testid="import-history-failed">
          <Text size="sm" style={WRAP}>
            {t('imports.history.loadFailed', { vault: names.get(id) || t('imports.history.unnamedVault') })}
          </Text>
          <ErrorAlert error={e} />
          <Button size="xs" variant="default" w="fit-content" loading={retrying === id} onClick={() => void tryAgain(id)}>
            {t('imports.history.tryAgain')}
          </Button>
        </Stack>
      ))}
      {imports.isSuccess && items.length === 0 && failures.size === 0 && <Text size="sm">{t('imports.history.empty')}</Text>}
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
