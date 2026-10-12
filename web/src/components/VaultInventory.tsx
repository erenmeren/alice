import { Anchor, Box, Group, Stack, Table, Tabs } from '@mantine/core';
import { useInfiniteQuery } from '@tanstack/react-query';
import { useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';
import { listKVCertificates, listKVKeys, listKVSecrets, type KVCertificate, type KVKey, type KVSecret, type Page } from '../api/keyvault';
import { kvListKey } from '../api/queryKeys';
import type { IconName } from '../design/Icon';
import { ErrorAlert } from './ErrorAlert';
import { Expiry, useNow } from './Expiry';
import { CursorFooter, EmptyState, Notice, Panel, ResourceTable, StatusBadge, type Tone } from './ui';
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

// Chip is a state of an inventory row as the design's status badge (text plus a dot plus tone).
function Chip({ children, tone = 'neutral', testId }: { children: ReactNode; tone?: Tone; testId?: string }) {
  return (
    <StatusBadge tone={tone} size="sm" testId={testId} style={{ maxWidth: '100%' }}>
      {children}
    </StatusBadge>
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

// Listing is one tab's table in the design's ResourceTable (named like its tab, in the theme's scroll region) with
// "N shown" and Show more for the cursor, or the tab's empty state.
function Listing<T>({ query, label, empty, emptyIcon, minWidth, head, children }: { query: ReturnType<typeof useList<T>>; label: string; empty: string; emptyIcon: IconName; minWidth: number; head: ReactNode; children: (items: T[]) => ReactNode }) {
  const { t } = useTranslation();
  const items = query.data?.pages.flatMap((p) => p.items) ?? [];
  return (
    <Stack gap="sm">
      <ErrorAlert error={query.error} />
      {query.isSuccess && items.length === 0 && (
        <Panel>
          <EmptyState icon={emptyIcon} title={empty} />
        </Panel>
      )}
      {items.length > 0 && (
        <ResourceTable
          label={label}
          minWidth={minWidth}
          footer={<CursorFooter shown={items.length} hasMore={query.hasNextPage} loading={query.isFetchingNextPage} onMore={() => void query.fetchNextPage()} moreLabel={t('vaults.showMore')} />}
        >
          <Table.Thead>{head}</Table.Thead>
          <Table.Tbody>{children(items)}</Table.Tbody>
        </ResourceTable>
      )}
    </Stack>
  );
}

function CertificatesTab({ vaultId }: { vaultId: string }) {
  const { t } = useTranslation();
  const now = useNow();
  const query = useList<KVCertificate>(vaultId, 'certificates', (cursor) => listKVCertificates(vaultId, { cursor, limit: 50, missing: 'include' }));
  const head = (
    <Table.Tr>
      <Table.Th>{t('vaults.cert.columns.name')}</Table.Th>
      <Table.Th>{t('vaults.cert.columns.version')}</Table.Th>
      <Table.Th>{t('vaults.cert.columns.expires')}</Table.Th>
      <Table.Th>{t('vaults.cert.columns.state')}</Table.Th>
    </Table.Tr>
  );
  return (
    <Listing query={query} label={t('vaults.tabs.certificates')} empty={t('vaults.cert.empty')} emptyIcon="FileKey2" minWidth={720} head={head}>
      {(items) =>
        items.map((c) => (
          <Table.Tr key={c.id} data-testid="kv-certificate-row">
            <Table.Td>
              <Anchor component={Link} to={`/key-vaults/${vaultId}/certificates/${c.id}`} translate="no" fw={550} style={WRAP}>
                {c.name}
              </Anchor>
            </Table.Td>
            <Table.Td>{c.current_version ? <code translate="no">{shortVersion(c.current_version)}</code> : ''}</Table.Td>
            <Table.Td>{c.expires ? <Expiry notAfter={c.expires} /> : t('vaults.noExpiry')}</Table.Td>
            <Table.Td>
              <Group gap={4}>
                {c.exportable === false && <Chip>{t('vaults.monitorOnly')}</Chip>}
                {c.missing_since !== null && <Chip tone="warning">{t('vaults.removed')}</Chip>}
                {isRecentNewVersion(c.kv_created_at, c.first_seen_at, now) && <Chip tone="info">{t('vaults.newVersion')}</Chip>}
                {c.current_held && <Chip tone="warning">{t('vaults.heldChip')}</Chip>}
                {!c.enabled && <Chip>{t('vaults.disabledChip')}</Chip>}
                {c.details_pending && <Chip>{t('vaults.detailsPending')}</Chip>}
                {c.bound && <Chip tone="success">{t('vaults.connectedChip')}</Chip>}
              </Group>
            </Table.Td>
          </Table.Tr>
        ))
      }
    </Listing>
  );
}

const yesNo = (t: (k: string) => string, v: boolean) => t(v ? 'vaults.yes' : 'vaults.no');

function KeysTab({ vaultId }: { vaultId: string }) {
  const { t } = useTranslation();
  const query = useList<KVKey>(vaultId, 'keys', (cursor) => listKVKeys(vaultId, { cursor, limit: 50, missing: 'include' }));
  const head = (
    <Table.Tr>
      {(['name', 'type', 'size', 'expires', 'enabled', 'managed'] as const).map((c) => (
        <Table.Th key={c}>{t(`vaults.keys.columns.${c}`)}</Table.Th>
      ))}
    </Table.Tr>
  );
  return (
    <Listing query={query} label={t('vaults.tabs.keys')} empty={t('vaults.keys.empty')} emptyIcon="KeyRound" minWidth={720} head={head}>
      {(items) =>
        items.map((k) => (
          <Table.Tr key={k.id}>
            <Table.Td>
              <Stack gap={4}>
                <Name>{k.name}</Name>
                <Group gap={4}>
                  {k.missing_since !== null && <Chip tone="warning">{t('vaults.removed')}</Chip>}
                  {k.hsm && <Chip>{t('vaults.keys.hsm')}</Chip>}
                  {k.details_problem !== '' && <Chip tone="warning">{t('vaults.keys.problem')}</Chip>}
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
        ))
      }
    </Listing>
  );
}

function SecretsTab({ vaultId }: { vaultId: string }) {
  const { t } = useTranslation();
  const query = useList<KVSecret>(vaultId, 'secrets', (cursor) => listKVSecrets(vaultId, { cursor, limit: 50, missing: 'include' }));
  const head = (
    <Table.Tr>
      {(['name', 'contentType', 'expires', 'enabled', 'managed'] as const).map((c) => (
        <Table.Th key={c}>{t(`vaults.secrets.columns.${c}`)}</Table.Th>
      ))}
    </Table.Tr>
  );
  return (
    <Listing query={query} label={t('vaults.tabs.secrets')} empty={t('vaults.secrets.empty')} emptyIcon="LockKeyhole" minWidth={640} head={head}>
      {(items) =>
        items.map((s) => (
          <Table.Tr key={s.id}>
            <Table.Td>
              <Stack gap={4}>
                <Name>{s.name}</Name>
                {s.missing_since !== null && (
                  <Group gap={4}>
                    <Chip tone="warning">{t('vaults.removed')}</Chip>
                  </Group>
                )}
              </Stack>
            </Table.Td>
            <Table.Td>
              <Name>{s.content_type}</Name>
            </Table.Td>
            <Table.Td>{s.expires ? <Expiry notAfter={s.expires} /> : t('vaults.noExpiry')}</Table.Td>
            <Table.Td>{yesNo(t, s.enabled)}</Table.Td>
            <Table.Td>{yesNo(t, s.managed)}</Table.Td>
          </Table.Tr>
        ))
      }
    </Listing>
  );
}

// VaultInventory is the three tabs of a vault: certificates, keys and secrets (metadata only; a key
// is never shown, a secret never has a value). Only the open tab is read. The Keys tab says that keys are inventory
// only (no Azure Key Vault key rotation in v1) and the Secrets tab that only metadata is shown, as the design does.
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
      <Tabs.Panel value="certificates" pt="lg">
        <CertificatesTab vaultId={vaultId} />
      </Tabs.Panel>
      <Tabs.Panel value="keys" pt="lg">
        <Box mb="md">
          <Notice tone="brand" title={t('vaults.page.keysOnlyTitle')}>
            {t('vaults.page.keysOnlyText')}
          </Notice>
        </Box>
        <KeysTab vaultId={vaultId} />
      </Tabs.Panel>
      <Tabs.Panel value="secrets" pt="lg">
        <Box mb="md">
          <Notice tone="brand" title={t('vaults.page.metadataTitle')}>
            {t('vaults.page.metadataText')}
          </Notice>
        </Box>
        <SecretsTab vaultId={vaultId} />
      </Tabs.Panel>
    </Tabs>
  );
}
