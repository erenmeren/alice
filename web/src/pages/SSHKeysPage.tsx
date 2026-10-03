import { Anchor, Badge, Button, Code, Group, NativeSelect, SimpleGrid, Stack, Switch, Table, Text, TextInput, Title } from '@mantine/core';
import { useDebouncedValue } from '@mantine/hooks';
import { useInfiniteQuery, useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';
import { listAllTargets, listSSHKeys } from '../api/endpoints';
import { SSH_KEYS_KEY, TARGETS_KEY } from '../api/queryKeys';
import type { KeyFlag, SSHKeyQuery } from '../api/types';
import { ErrorAlert } from '../components/ErrorAlert';
import { WRAP } from '../components/wrap';

const FLAGS: KeyFlag[] = ['weak', 'command', 'root_without_from', 'duplicate', 'cert_authority', 'security_key'];

// SSHKeysPage is the SSH key inventory (spec §13.3, §26.5): one row per key, filtered on the
// server so the page stays fast with thousands of keys; the free-text fields are debounced.
// The filter is part of the query key, so a change starts again from the first page and a
// response for an older filter never replaces the current one.
export function SSHKeysPage() {
  const { t } = useTranslation();
  const [search, setSearch] = useState('');
  const [user, setUser] = useState('');
  const [targetId, setTargetId] = useState('');
  const [flag, setFlag] = useState<KeyFlag | ''>('');
  const [missing, setMissing] = useState(false);
  const [q] = useDebouncedValue(search.trim(), 300);
  const [osUser] = useDebouncedValue(user.trim(), 300);

  const targets = useQuery({ queryKey: TARGETS_KEY, queryFn: listAllTargets });
  const filter: SSHKeyQuery = { q, os_user: osUser, target_id: targetId, flag, missing };
  const keys = useInfiniteQuery({
    queryKey: [...SSH_KEYS_KEY, filter],
    queryFn: ({ pageParam }) => listSSHKeys({ ...filter, cursor: pageParam }),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
  });
  const items = keys.data?.pages.flatMap((p) => p.items) ?? [];

  return (
    <Stack gap="md">
      <Title order={1}>{t('sshKeys.title')}</Title>
      <Text size="sm">{t('sshKeys.intro')}</Text>
      <SimpleGrid cols={{ base: 1, sm: 2, lg: 4 }}>
        <TextInput label={t('sshKeys.search')} description={t('sshKeys.searchHelp')} value={search} onChange={(e) => setSearch(e.currentTarget.value)} maxLength={200} />
        <NativeSelect
          label={t('sshKeys.server')}
          value={targetId}
          onChange={(e) => setTargetId(e.currentTarget.value)}
          data={[{ value: '', label: t('sshKeys.allServers') }, ...(targets.data?.items ?? []).map((tg) => ({ value: tg.id, label: tg.name }))]}
        />
        <TextInput label={t('sshKeys.user')} value={user} onChange={(e) => setUser(e.currentTarget.value)} maxLength={32} />
        <NativeSelect
          label={t('sshKeys.flag')}
          value={flag}
          onChange={(e) => setFlag(e.currentTarget.value as KeyFlag | '')}
          data={[{ value: '', label: t('sshKeys.allFlags') }, ...FLAGS.map((f) => ({ value: f, label: t(`sshKeys.flags.${f}`) }))]}
        />
      </SimpleGrid>
      <Switch label={t('sshKeys.showMissing')} checked={missing} onChange={(e) => setMissing(e.currentTarget.checked)} />
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
    </Stack>
  );
}
