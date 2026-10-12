import { Anchor, Button, Code, NativeSelect, Stack, Switch, Table, TextInput } from '@mantine/core';
import { useInfiniteQuery, useQuery } from '@tanstack/react-query';
import type { TFunction } from 'i18next';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, useNavigate } from 'react-router';
import { listAllServers, listSSHKeys } from '../api/endpoints';
import { SSH_KEYS_KEY, TARGETS_KEY } from '../api/queryKeys';
import type { KeyFlag, SSHKey, SSHKeyQuery } from '../api/types';
import { useAuth } from '../auth/AuthProvider';
import { ErrorAlert } from '../components/ErrorAlert';
import { ExportButton } from '../components/ExportButton';
import { GenerateKeyDialog } from '../components/GenerateKeyDialog';
import { SavedViews } from '../components/SavedViews';
import { CursorFooter, EmptyState, LinkTabs, Notice, PageHeader, StatusBadge, type LinkTab } from '../components/ui';
import ui from '../components/ui/ui.module.css';
import { WRAP } from '../components/wrap';
import { Icon } from '../design/Icon';
import { useDebouncedParam, useUrlFilters } from '../hooks/useUrlFilters';
import classes from './SSHKeysPage.module.css';

// The filters live in the address (useSearchParams), so a link, a saved view and the export reproduce the list.
const SSH_FILTER_KEYS = ['target_id', 'os_user', 'q', 'flag', 'missing'] as const;
const FLAGS: KeyFlag[] = ['weak', 'command', 'root_without_from', 'duplicate', 'cert_authority', 'security_key'];

// SSH_KEY_TABS are the design's two SSH key sections (R19): the inventory and the key rotations, plain links with
// aria-current (not a tablist). The rotations page (Task 10) shows the same tabs; a run page counts as Key rotations.
export function SSH_KEY_TABS(t: TFunction | ((key: string) => string)): LinkTab[] {
  return [
    { to: '/ssh-keys', label: t('sshKeys.page.inventory') },
    { to: '/rotations', label: t('nav.rotations'), match: ['/rotation/'] },
  ];
}

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
  const filtered = Object.values(filters).some((v) => v !== '');
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

  const toolbar = (
    <>
      <TextInput
        className={classes.search}
        label={t('sshKeys.search')}
        placeholder={t('sshKeys.searchHelp')}
        leftSection={<Icon name="Search" size={15} />}
        value={search}
        onChange={(e) => onSearch(e.currentTarget.value)}
        maxLength={200}
      />
      <NativeSelect
        className={classes.select}
        label={t('sshKeys.server')}
        value={filters.target_id}
        onChange={(e) => setFilters({ target_id: e.currentTarget.value })}
        data={[{ value: '', label: t('sshKeys.allServers') }, ...(targets.data?.items ?? []).map((tg) => ({ value: tg.id, label: tg.name }))]}
      />
      <TextInput className={classes.user} label={t('sshKeys.user')} value={user} onChange={(e) => onUser(e.currentTarget.value)} maxLength={32} />
      <NativeSelect
        className={classes.select}
        label={t('sshKeys.flag')}
        value={filters.flag}
        onChange={(e) => setFilters({ flag: e.currentTarget.value })}
        data={[{ value: '', label: t('sshKeys.allFlags') }, ...FLAGS.map((f) => ({ value: f, label: t(`sshKeys.flags.${f}`) }))]}
      />
      <Switch
        className={classes.switch}
        label={t('sshKeys.showMissing')}
        checked={filters.missing === 'true'}
        onChange={(e) => setFilters({ missing: e.currentTarget.checked ? 'true' : '' })}
      />
      <div className={classes.grow} />
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
      <Button
        variant="subtle"
        leftSection={<Icon name="X" size={15} />}
        onClick={() => {
          resetSearch('');
          resetUser('');
          clearFilters();
        }}
      >
        {t('filters.clear')}
      </Button>
    </>
  );

  return (
    <Stack gap="md">
      <PageHeader
        title={t('sshKeys.title')}
        description={t('sshKeys.page.description')}
        actions={
          <>
            <ExportButton kind="ssh-keys" filters={filters} />
            {canGenerate && (
              <Button leftSection={<Icon name="Plus" size={15} />} onClick={() => setGenerating(true)}>
                {t('sshKeys.generate')}
              </Button>
            )}
          </>
        }
      />
      <LinkTabs items={SSH_KEY_TABS(t)} label={t('sshKeys.page.sections')} />
      {/* No count: the list is cursor-paged, so the number of weak keys is unknown here (R20). */}
      <Notice
        tone="warning"
        title={t('sshKeys.page.weakTitle')}
        action={
          <Anchor component={Link} to="/ssh-keys?flag=weak" c="inherit" underline="always" size="sm">
            {t('sshKeys.page.showWeak')}
          </Anchor>
        }
      >
        {t('sshKeys.page.weakText')}
      </Notice>
      <ErrorAlert error={keys.error} />
      {/* The design's table panel (ResourceTable look); the toolbar stays mounted whether rows or an empty state follow,
          so the search box keeps its focus while a person types a search without matches. */}
      <div className={ui.tablePanel}>
        <div className={ui.toolbar}>{toolbar}</div>
        {keys.isSuccess && items.length === 0 && !filtered && <EmptyState icon="KeyRound" title={t('sshKeys.page.emptyTitle')} description={t('sshKeys.page.emptyText')} />}
        {/* No second Clear filters here: the toolbar's is just above (one button per name for the e2e). */}
        {keys.isSuccess && items.length === 0 && filtered && <EmptyState title={t('sshKeys.page.noMatchTitle')} description={t('sshKeys.empty')} />}
        {items.length > 0 && <KeysTable items={items} t={t} />}
        {items.length > 0 && (
          <div className={ui.tableBottom}>
            <CursorFooter shown={items.length} hasMore={keys.hasNextPage} loading={keys.isFetchingNextPage} onMore={() => void keys.fetchNextPage()} moreLabel={t('sshKeys.loadMore')} />
          </div>
        )}
      </div>
      <p className={classes.note}>{t('sshKeys.intro')}</p>
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

// KeysTable follows the design's rows: the key (tile, fingerprint link — the row's only link — and the comment), the
// algorithm with its weakness, where it is used, and who manages it. The list carries no rotation state (gap).
function KeysTable({ items, t }: { items: SSHKey[]; t: TFunction }) {
  return (
    <Table.ScrollContainer minWidth={720}>
      <Table data-testid="ssh-keys-table" aria-label={t('sshKeys.title')} highlightOnHover>
        <Table.Thead>
          <Table.Tr>
            <Table.Th>{t('sshKeys.key')}</Table.Th>
            <Table.Th>{t('sshKeys.page.columns.algorithm')}</Table.Th>
            <Table.Th>{t('sshKeys.page.columns.locations')}</Table.Th>
            <Table.Th>{t('sshKeys.page.columns.managed')}</Table.Th>
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {items.map((k) => (
            <Table.Tr key={k.id}>
              <Table.Td>
                <div className={classes.resourceName}>
                  <span className={classes.resourceIcon} data-platform={k.is_platform_key || undefined}>
                    <Icon name="KeyRound" size={16} />
                  </span>
                  <div className={classes.resourceText}>
                    <Anchor component={Link} to={`/ssh-keys/${k.id}`} className={classes.name}>
                      <Code translate="no" style={WRAP}>
                        {k.fingerprint}
                      </Code>
                    </Anchor>
                    {k.comment && (
                      <p className={classes.secondary} translate="no">
                        {k.comment}
                      </p>
                    )}
                    {(k.is_platform_key || k.missing) && (
                      <div className={classes.badges}>
                        {k.is_platform_key && (
                          <StatusBadge tone="brand" icon="KeyRound" size="sm">
                            {t('sshKeys.aliceKey')}
                          </StatusBadge>
                        )}
                        {k.missing && (
                          <StatusBadge tone="neutral" icon="CircleOff" size="sm">
                            {t('sshKeys.missingBadge')}
                          </StatusBadge>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              </Table.Td>
              <Table.Td>
                <span className={classes.mono}>{t('sshKeys.keyType', { type: k.key_type, bits: k.bits })}</span>
                {k.weak && (
                  <div className={classes.badges}>
                    <StatusBadge tone="warning" icon="CircleAlert" size="sm">
                      {t('sshKeys.flags.weak')}
                    </StatusBadge>
                  </div>
                )}
              </Table.Td>
              <Table.Td>
                {t('sshKeys.page.places', { count: k.location_count })}
                <p className={classes.secondary}>{t('sshKeys.page.onServers', { count: k.target_count })}</p>
              </Table.Td>
              <Table.Td>
                <StatusBadge tone={k.managed ? 'success' : 'neutral'} icon={k.managed ? 'ShieldCheck' : 'Search'}>
                  {k.managed ? t('sshKeys.managedBadge') : t('sshKeys.page.discovered')}
                </StatusBadge>
              </Table.Td>
            </Table.Tr>
          ))}
        </Table.Tbody>
      </Table>
    </Table.ScrollContainer>
  );
}
