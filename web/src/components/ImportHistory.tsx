import { Anchor, Code, Stack, Table, Text, Title } from '@mantine/core';
import { useQueries, useQuery } from '@tanstack/react-query';
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
// vault's imports (filtered by certificate), so one request goes to each vault.
export function ImportHistory({ certificateId }: { certificateId: string }) {
  const { t, i18n } = useTranslation();
  const vaults = useQuery({ queryKey: [...VAULTS_KEY, 'import-history'], queryFn: () => listAllTargets('azure_key_vault') });
  const lists = useQueries({
    queries: (vaults.data?.items ?? []).map((v) => ({
      queryKey: [...KV_IMPORTS_KEY, v.id, certificateId],
      queryFn: () => listKVImports(v.id, certificateId),
    })),
  });
  const names = new Map((vaults.data?.items ?? []).map((v) => [v.id, v.name]));
  const items = lists.flatMap((q) => q.data?.items ?? []).sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at));
  const error = vaults.error ?? lists.find((q) => q.error)?.error ?? null;
  const loaded = vaults.isSuccess && lists.every((q) => q.isSuccess);
  if (vaults.isSuccess && (vaults.data?.items.length ?? 0) === 0) return null;
  if (loaded && items.length === 0) return null;
  return (
    <Stack gap="sm" data-testid="import-history">
      <Title order={2} size="h3">
        {t('imports.history.title')}
      </Title>
      <ErrorAlert error={error} />
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
    </Stack>
  );
}
