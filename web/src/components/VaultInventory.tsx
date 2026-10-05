import { Anchor, Badge, Button, Group, Stack, Table, Tabs, Text } from '@mantine/core';
import { useInfiniteQuery } from '@tanstack/react-query';
import { useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';
import { listKVCertificates, listKVKeys, listKVSecrets, type KVCertificate, type KVKey, type KVSecret, type Page } from '../api/keyvault';
import { kvListKey } from '../api/queryKeys';
import { ErrorAlert } from './ErrorAlert';
import { Expiry, useNow } from './Expiry';
import { isRecentNewVersion, shortVersion } from './vaultText';
import { WRAP } from './wrap';

type Kind = 'certificates' | 'keys' | 'secrets';

// Everything below comes from Azure or from whoever owns the vault (names, content types, curves).
// It is rendered as text only, wraps inside its cell and never becomes a link or markup.
const Name = ({ children }: { children: ReactNode }) => (
  <span translate="no" style={WRAP}>
    {children}
  </span>
);

function Chip({ children, color = 'gray', testId }: { children: ReactNode; color?: string; testId?: string }) {
  return (
    <Badge variant="light" color={color} tt="none" data-testid={testId} style={{ maxWidth: '100%' }}>
      {children}
    </Badge>
  );
}

function useList<T>(vaultId: string, kind: Kind, load: (cursor: string | null) => Promise<Page<T>>) {
  return useInfiniteQuery({
    queryKey: [...kvListKey(vaultId, kind)],
    queryFn: ({ pageParam }) => load(pageParam),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor ?? undefined,
  });
}

function Listing<T>({ query, empty, children }: { query: ReturnType<typeof useList<T>>; empty: string; children: (items: T[]) => ReactNode }) {
  const { t } = useTranslation();
  const items = query.data?.pages.flatMap((p) => p.items) ?? [];
  return (
    <Stack gap="sm">
      <ErrorAlert error={query.error} />
      {query.isSuccess && items.length === 0 && <Text size="sm">{empty}</Text>}
      {items.length > 0 && children(items)}
      {query.hasNextPage && (
        <Group>
          <Button variant="default" loading={query.isFetchingNextPage} onClick={() => void query.fetchNextPage()}>
            {t('vaults.showMore')}
          </Button>
        </Group>
      )}
    </Stack>
  );
}

function CertificatesTab({ vaultId }: { vaultId: string }) {
  const { t } = useTranslation();
  const now = useNow();
  const query = useList<KVCertificate>(vaultId, 'certificates', (cursor) => listKVCertificates(vaultId, { cursor, limit: 50, missing: 'include' }));
  return (
    <Listing query={query} empty={t('vaults.cert.empty')}>
      {(items) => (
        <Table.ScrollContainer minWidth={720}>
          <Table striped aria-label={t('vaults.tabs.certificates')}>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>{t('vaults.cert.columns.name')}</Table.Th>
                <Table.Th>{t('vaults.cert.columns.version')}</Table.Th>
                <Table.Th>{t('vaults.cert.columns.expires')}</Table.Th>
                <Table.Th>{t('vaults.cert.columns.state')}</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {items.map((c) => (
                <Table.Tr key={c.id} data-testid="kv-certificate-row">
                  <Table.Td>
                    <Anchor component={Link} to={`/key-vaults/${vaultId}/certificates/${c.id}`} translate="no" style={WRAP}>
                      {c.name}
                    </Anchor>
                  </Table.Td>
                  <Table.Td>{c.current_version ? <code translate="no">{shortVersion(c.current_version)}</code> : ''}</Table.Td>
                  <Table.Td>{c.expires ? <Expiry notAfter={c.expires} /> : t('vaults.noExpiry')}</Table.Td>
                  <Table.Td>
                    <Group gap={4}>
                      {c.exportable === false && <Chip>{t('vaults.monitorOnly')}</Chip>}
                      {c.missing_since !== null && <Chip color="orange">{t('vaults.removed')}</Chip>}
                      {isRecentNewVersion(c.kv_created_at, c.first_seen_at, now) && <Chip color="blue">{t('vaults.newVersion')}</Chip>}
                      {c.current_held && <Chip color="yellow">{t('vaults.heldChip')}</Chip>}
                      {!c.enabled && <Chip>{t('vaults.disabledChip')}</Chip>}
                      {c.details_pending && <Chip>{t('vaults.detailsPending')}</Chip>}
                      {c.bound && <Chip color="green">{t('vaults.connectedChip')}</Chip>}
                    </Group>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      )}
    </Listing>
  );
}

const yesNo = (t: (k: string) => string, v: boolean) => t(v ? 'vaults.yes' : 'vaults.no');

function KeysTab({ vaultId }: { vaultId: string }) {
  const { t } = useTranslation();
  const query = useList<KVKey>(vaultId, 'keys', (cursor) => listKVKeys(vaultId, { cursor, limit: 50, missing: 'include' }));
  return (
    <Listing query={query} empty={t('vaults.keys.empty')}>
      {(items) => (
        <Table.ScrollContainer minWidth={720}>
          <Table striped aria-label={t('vaults.tabs.keys')}>
            <Table.Thead>
              <Table.Tr>
                {(['name', 'type', 'size', 'expires', 'enabled', 'managed'] as const).map((c) => (
                  <Table.Th key={c}>{t(`vaults.keys.columns.${c}`)}</Table.Th>
                ))}
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {items.map((k) => (
                <Table.Tr key={k.id}>
                  <Table.Td>
                    <Stack gap={2}>
                      <Name>{k.name}</Name>
                      <Group gap={4}>
                        {k.missing_since !== null && <Chip color="orange">{t('vaults.removed')}</Chip>}
                        {k.hsm && <Chip>{t('vaults.keys.hsm')}</Chip>}
                        {k.details_problem !== '' && <Chip color="yellow">{t('vaults.keys.problem')}</Chip>}
                      </Group>
                    </Stack>
                  </Table.Td>
                  <Table.Td>
                    <Name>{k.key_type}</Name>
                  </Table.Td>
                  <Table.Td>{k.key_size > 0 ? t('vaults.keys.bits', { bits: k.key_size }) : <Name>{k.curve}</Name>}</Table.Td>
                  <Table.Td>{k.expires ? <Expiry notAfter={k.expires} /> : t('vaults.noExpiry')}</Table.Td>
                  <Table.Td>{yesNo(t, k.enabled)}</Table.Td>
                  <Table.Td>{yesNo(t, k.managed)}</Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      )}
    </Listing>
  );
}

function SecretsTab({ vaultId }: { vaultId: string }) {
  const { t } = useTranslation();
  const query = useList<KVSecret>(vaultId, 'secrets', (cursor) => listKVSecrets(vaultId, { cursor, limit: 50, missing: 'include' }));
  return (
    <Listing query={query} empty={t('vaults.secrets.empty')}>
      {(items) => (
        <Table.ScrollContainer minWidth={640}>
          <Table striped aria-label={t('vaults.tabs.secrets')}>
            <Table.Thead>
              <Table.Tr>
                {(['name', 'contentType', 'expires', 'enabled', 'managed'] as const).map((c) => (
                  <Table.Th key={c}>{t(`vaults.secrets.columns.${c}`)}</Table.Th>
                ))}
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {items.map((s) => (
                <Table.Tr key={s.id}>
                  <Table.Td>
                    <Stack gap={2}>
                      <Name>{s.name}</Name>
                      {s.missing_since !== null && <Chip color="orange">{t('vaults.removed')}</Chip>}
                    </Stack>
                  </Table.Td>
                  <Table.Td>
                    <Name>{s.content_type}</Name>
                  </Table.Td>
                  <Table.Td>{s.expires ? <Expiry notAfter={s.expires} /> : t('vaults.noExpiry')}</Table.Td>
                  <Table.Td>{yesNo(t, s.enabled)}</Table.Td>
                  <Table.Td>{yesNo(t, s.managed)}</Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      )}
    </Listing>
  );
}

// VaultInventory is the three tabs of a vault: certificates, keys and secrets (metadata only; a key
// is never shown, a secret never has a value). Only the open tab is read.
export function VaultInventory({ vaultId }: { vaultId: string }) {
  const { t } = useTranslation();
  const [tab, setTab] = useState<string | null>('certificates');
  return (
    <Tabs value={tab} onChange={setTab} keepMounted={false}>
      <Tabs.List>
        <Tabs.Tab value="certificates">{t('vaults.tabs.certificates')}</Tabs.Tab>
        <Tabs.Tab value="keys">{t('vaults.tabs.keys')}</Tabs.Tab>
        <Tabs.Tab value="secrets">{t('vaults.tabs.secrets')}</Tabs.Tab>
      </Tabs.List>
      <Tabs.Panel value="certificates" pt="md">
        <CertificatesTab vaultId={vaultId} />
      </Tabs.Panel>
      <Tabs.Panel value="keys" pt="md">
        <KeysTab vaultId={vaultId} />
      </Tabs.Panel>
      <Tabs.Panel value="secrets" pt="md">
        <SecretsTab vaultId={vaultId} />
      </Tabs.Panel>
    </Tabs>
  );
}
