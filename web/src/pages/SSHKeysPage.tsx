import { Anchor, Badge, Button, Code, Group, NativeSelect, SimpleGrid, Stack, Switch, Table, Text, TextInput, Title } from '@mantine/core';
import { useInfiniteQuery, useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, useNavigate } from 'react-router';
import { listAllServers, listSSHKeys } from '../api/endpoints';
import { SSH_KEYS_KEY, TARGETS_KEY } from '../api/queryKeys';
import type { KeyFlag, SSHKeyQuery } from '../api/types';
import { useAuth } from '../auth/AuthProvider';
import { ErrorAlert } from '../components/ErrorAlert';
import { ExportButton } from '../components/ExportButton';
import { GenerateKeyDialog } from '../components/GenerateKeyDialog';
import { SavedViews } from '../components/SavedViews';
import { WRAP } from '../components/wrap';
import { useDebouncedParam, useUrlFilters } from '../hooks/useUrlFilters';

// The filters live in the address (useSearchParams), so a link, a saved view and the export reproduce the list.
const SSH_FILTER_KEYS = ['target_id', 'os_user', 'q', 'flag', 'missing'] as const;
const FLAGS: KeyFlag[] = ['weak', 'command', 'root_without_from', 'duplicate', 'cert_authority', 'security_key'];

// SSHKeysPage is the SSH key inventory (spec §13.3, §26.5): one row per key, filtered on the
// server so the page stays fast with thousands of keys; the free-text fields are debounced.
// The filter is part of the query key, so a change starts again from the first page and a
// response for an older filter never replaces the current one.
export function SSHKeysPage() {
  const { t } = useTranslation();
  const { session } = useAuth();
  const navigate = useNavigate();
  const canGenerate = session?.user.role === 'admin' || session?.user.role === 'operator';
  const [generating, setGenerating] = useState(false);
  const [filters, setFilters, clearFilters] = useUrlFilters(SSH_FILTER_KEYS);
  const [search, onSearch, resetSearch] = useDebouncedParam(filters.q, (q) => setFilters({ q }));
  const [user, onUser, resetUser] = useDebouncedParam(filters.os_user, (os_user) => setFilters({ os_user }));

  const targets = useQuery({ queryKey: TARGETS_KEY, queryFn: listAllServers });
  const filter: SSHKeyQuery = { q: filters.q, os_user: filters.os_user, target_id: filters.target_id, flag: filters.flag as KeyFlag | '', missing: filters.missing === 'true' };
  const keys = useInfiniteQuery({
    queryKey: [...SSH_KEYS_KEY, filter],
    queryFn: ({ pageParam }) => listSSHKeys({ ...filter, cursor: pageParam }),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
  });
  const items = keys.data?.pages.flatMap((p) => p.items) ?? [];

  return (
    <Stack gap="md">
      <Group justify="space-between" align="flex-start" wrap="wrap">
        <Title order={1}>{t('sshKeys.title')}</Title>
        {canGenerate && <Button onClick={() => setGenerating(true)}>{t('sshKeys.generate')}</Button>}
      </Group>
      <Text size="sm">{t('sshKeys.intro')}</Text>
      <SimpleGrid cols={{ base: 1, sm: 2, lg: 4 }}>
        <TextInput label={t('sshKeys.search')} description={t('sshKeys.searchHelp')} value={search} onChange={(e) => onSearch(e.currentTarget.value)} maxLength={200} />
        <NativeSelect
          label={t('sshKeys.server')}
          value={filters.target_id}
          onChange={(e) => setFilters({ target_id: e.currentTarget.value })}
          data={[{ value: '', label: t('sshKeys.allServers') }, ...(targets.data?.items ?? []).map((tg) => ({ value: tg.id, label: tg.name }))]}
        />
        <TextInput label={t('sshKeys.user')} value={user} onChange={(e) => onUser(e.currentTarget.value)} maxLength={32} />
        <NativeSelect
          label={t('sshKeys.flag')}
          value={filters.flag}
          onChange={(e) => setFilters({ flag: e.currentTarget.value })}
          data={[{ value: '', label: t('sshKeys.allFlags') }, ...FLAGS.map((f) => ({ value: f, label: t(`sshKeys.flags.${f}`) }))]}
        />
      </SimpleGrid>
      <Switch label={t('sshKeys.showMissing')} checked={filters.missing === 'true'} onChange={(e) => setFilters({ missing: e.currentTarget.checked ? 'true' : '' })} />
      <Group align="flex-start" gap="sm">
        <SavedViews
          page="ssh_keys"
          keys={SSH_FILTER_KEYS}
          values={filters}
          set={(next) => {
            resetSearch(next.q ?? '');
            resetUser(next.os_user ?? '');
            setFilters(next);
          }}
        />
        <ExportButton kind="ssh-keys" filters={filters} />
        <Button
          variant="subtle"
          onClick={() => {
            resetSearch('');
            resetUser('');
            clearFilters();
          }}
        >
          {t('filters.clear')}
        </Button>
      </Group>
      <ErrorAlert error={keys.error} />
      {keys.isSuccess && items.length === 0 && <Text c="gray.7">{t('sshKeys.empty')}</Text>}
      {items.length > 0 && (
        <Table.ScrollContainer minWidth={720}>
          <Table striped data-testid="ssh-keys-table">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>{t('sshKeys.key')}</Table.Th>
                <Table.Th>{t('sshKeys.comment')}</Table.Th>
                <Table.Th>{t('sshKeys.locationCount')}</Table.Th>
                <Table.Th>{t('sshKeys.targetCount')}</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {items.map((k) => (
                <Table.Tr key={k.id}>
                  <Table.Td>
                    <Stack gap={2}>
                      <Anchor component={Link} to={`/ssh-keys/${k.id}`}>
                        <Code style={WRAP}>{k.fingerprint}</Code>
                      </Anchor>
                      <Text size="xs">{t('sshKeys.keyType', { type: k.key_type, bits: k.bits })}</Text>
                      <Group gap={4}>
                        {k.managed && (
                          <Badge variant="light" color="teal" tt="none">
                            {t('sshKeys.managedBadge')}
                          </Badge>
                        )}
                        {k.is_platform_key && (
                          <Badge variant="light" color="indigo" tt="none">
                            {t('sshKeys.aliceKey')}
                          </Badge>
                        )}
                        {k.weak && (
                          <Badge variant="light" color="orange" tt="none">
                            {t('sshKeys.flags.weak')}
                          </Badge>
                        )}
                        {k.missing && (
                          <Badge variant="light" color="gray" tt="none">
                            {t('sshKeys.missingBadge')}
                          </Badge>
                        )}
                      </Group>
                    </Stack>
                  </Table.Td>
                  <Table.Td style={WRAP}>{k.comment}</Table.Td>
                  <Table.Td>{k.location_count}</Table.Td>
                  <Table.Td>{k.target_count}</Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      )}
      {keys.hasNextPage && (
        <Button variant="default" w="fit-content" loading={keys.isFetchingNextPage} onClick={() => void keys.fetchNextPage()}>
          {t('sshKeys.loadMore')}
        </Button>
      )}
      <GenerateKeyDialog
        opened={generating}
        onClose={() => setGenerating(false)}
        onGenerated={(id) => {
          setGenerating(false);
          void navigate(`/ssh-keys/${encodeURIComponent(id)}`);
        }}
      />
    </Stack>
  );
}
