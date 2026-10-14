import { Button, Code, NativeSelect, Stack, Table, TextInput } from '@mantine/core';
import { useInfiniteQuery, useMutation } from '@tanstack/react-query';
import { useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router';
import {
  STATUS_FILTERS,
  exportDiscoveredCertificates,
  listDiscoveredCertificates,
  nextCursor,
  type CertificateQuery,
  type DiscoveredCertificate,
  type DiscoveredEndpoint,
  type DiscoveredStatusFilter,
  type DiscoveryScope,
} from '../../api/discovery';
import { discoveredCertificateListKey } from '../../api/queryKeys';
import { Icon } from '../../design/Icon';
import { useDebouncedParam, useUrlFilters } from '../../hooks/useUrlFilters';
import { AddServerModal } from '../AddServerModal';
import { ErrorAlert } from '../ErrorAlert';
import { Expiry } from '../Expiry';
import { LoadingIndicator } from '../LoadingIndicator';
import { saveBlob } from '../saveBlob';
import { CursorFooter, EmptyState, Notice, StatusBadge } from '../ui';
import ui from '../ui/ui.module.css';
import { WRAP } from '../wrap';
import { CertificateDrawer, hostOf } from './CertificateDrawer';
import classes from './discovery.module.css';
import { StatusChip, useDiscoveryRole } from './shared';

// The Results filters live in the address, so a link (the Overview's, an alert e-mail's) and the export reproduce the
// list. view=unmanaged is the link the Overview and the e-mails use: the status filter starts at Unmanaged.
export const RESULT_FILTER_KEYS = ['status', 'expiry', 'self_signed', 'scope_id', 'q', 'view'] as const;
const EXPIRY_DAYS = ['7', '14', '30', '60', '90'] as const;

// resultQuery is what the address asks for, with values that are not options ignored (the selects never say "all"
// over a filtered list).
export function resultQuery(f: Record<(typeof RESULT_FILTER_KEYS)[number], string>): { status: DiscoveredStatusFilter; query: CertificateQuery; filtered: boolean } {
  const status: DiscoveredStatusFilter = (STATUS_FILTERS as readonly string[]).includes(f.status) ? (f.status as DiscoveredStatusFilter) : f.view === 'unmanaged' ? 'unmanaged' : 'all';
  const expiry = f.expiry === 'expired' || (EXPIRY_DAYS as readonly string[]).includes(f.expiry) ? f.expiry : '';
  const selfSigned = f.self_signed === 'true' || f.self_signed === 'false' ? f.self_signed : '';
  const query: CertificateQuery = {
    status,
    expired: expiry === 'expired' ? true : undefined,
    expiring_within_days: expiry && expiry !== 'expired' ? Number(expiry) : undefined,
    self_signed: selfSigned === '' ? undefined : selfSigned === 'true',
    scope_id: f.scope_id || undefined,
    q: f.q.trim() || undefined,
  };
  const filtered = status !== 'all' || expiry !== '' || selfSigned !== '' || !!query.scope_id || !!query.q;
  return { status, query, filtered };
}

// ResultsTab is every certificate found on the network, soonest expiry first, with filters, the export and the detail
// drawer.
export function ResultsTab({ scopes, onAddScope }: { scopes: DiscoveryScope[] | undefined; onAddScope: () => void }) {
  const { t } = useTranslation();
  const { admin, canOperate } = useDiscoveryRole();
  const navigate = useNavigate();
  const [filters, setFilters, clearFilters] = useUrlFilters(RESULT_FILTER_KEYS);
  const [search, onSearch, resetSearch] = useDebouncedParam(filters.q, (q) => setFilters({ q }));
  const { status, query, filtered } = resultQuery(filters);
  const list = useInfiniteQuery({
    queryKey: discoveredCertificateListKey({ ...query }),
    queryFn: ({ pageParam, signal }) => listDiscoveredCertificates({ ...query, cursor: pageParam }, signal),
    initialPageParam: null as string | null,
    getNextPageParam: nextCursor,
  });
  const items = list.data?.pages.flatMap((p) => p.items) ?? [];
  const [selected, setSelected] = useState<string | null>(null);
  const [adding, setAdding] = useState<DiscoveredEndpoint | null>(null);
  // The row's name opened the drawer; it gets the focus back after the Add server dialog the drawer handed over to.
  const opener = useRef<HTMLButtonElement | null>(null);
  const noScopes = scopes !== undefined && scopes.length === 0;

  const exporting = useMutation({
    mutationFn: () => exportDiscoveredCertificates(query),
    onSuccess: (blob) => saveBlob(blob, `alice-discovered-certificates-${new Date().toISOString().slice(0, 10)}.csv`),
  });

  if (noScopes) {
    return (
      <div className={ui.tablePanel}>
        <EmptyState
          icon="Network"
          title={t('discovery.empty.title')}
          description={
            <>
              <span>{t('discovery.empty.text')}</span> <span>{t('discovery.empty.who')}</span>
            </>
          }
          action={
            admin && (
              <Button leftSection={<Icon name="Plus" size={15} />} onClick={onAddScope}>
                {t('discovery.empty.add')}
              </Button>
            )
          }
          testId="discovery-empty"
        />
      </div>
    );
  }

  const toolbar = (
    <>
      <TextInput
        className={classes.search}
        label={t('discovery.results.search')}
        placeholder={t('discovery.results.searchHelp')}
        leftSection={<Icon name="Search" size={15} />}
        value={search}
        onChange={(e) => onSearch(e.currentTarget.value)}
        maxLength={200}
      />
      <NativeSelect
        className={classes.select}
        label={t('discovery.results.status')}
        value={status}
        // An explicit choice replaces the link's view, so "All statuses" really shows all.
        onChange={(e) => setFilters({ status: e.currentTarget.value, view: '' })}
        data={STATUS_FILTERS.map((s) => ({ value: s, label: s === 'all' ? t('discovery.results.statusAll') : t(`discovery.enum.status.${s}`) }))}
      />
      <NativeSelect
        className={classes.select}
        label={t('discovery.results.expiry')}
        value={query.expired ? 'expired' : query.expiring_within_days ? String(query.expiring_within_days) : ''}
        onChange={(e) => setFilters({ expiry: e.currentTarget.value })}
        data={[
          { value: '', label: t('discovery.results.expiryAll') },
          { value: 'expired', label: t('discovery.results.expiryExpired') },
          ...EXPIRY_DAYS.map((d) => ({ value: d, label: t('discovery.results.expiryWithin', { count: Number(d) }) })),
        ]}
      />
      <NativeSelect
        className={classes.select}
        label={t('discovery.results.selfSigned')}
        value={query.self_signed === undefined ? '' : String(query.self_signed)}
        onChange={(e) => setFilters({ self_signed: e.currentTarget.value })}
        data={[
          { value: '', label: t('discovery.results.selfSignedAll') },
          { value: 'true', label: t('discovery.results.selfSignedYes') },
          { value: 'false', label: t('discovery.results.selfSignedNo') },
        ]}
      />
      <NativeSelect
        className={classes.select}
        label={t('discovery.results.scope')}
        value={(scopes ?? []).some((s) => s.id === filters.scope_id) ? filters.scope_id : ''}
        onChange={(e) => setFilters({ scope_id: e.currentTarget.value })}
        data={[{ value: '', label: t('discovery.results.scopeAll') }, ...(scopes ?? []).map((s) => ({ value: s.id, label: s.name }))]}
      />
      <div className={classes.grow} />
      <Button
        variant="subtle"
        leftSection={<Icon name="X" size={15} />}
        onClick={() => {
          resetSearch('');
          clearFilters();
        }}
      >
        {t('filters.clear')}
      </Button>
      <Button variant="default" leftSection={<Icon name="Download" size={15} />} loading={exporting.isPending} onClick={() => exporting.mutate()}>
        {t('filters.export')}
      </Button>
    </>
  );

  return (
    <Stack gap="md">
      <Notice tone="neutral" title={t('discovery.unmanagedHelp.title')} testId="discovery-unmanaged-help">
        {t('discovery.unmanagedHelp.text')}
      </Notice>
      <ErrorAlert error={exporting.error} />
      <ErrorAlert error={list.error} />
      <div className={ui.tablePanel}>
        <div className={ui.toolbar}>{toolbar}</div>
        {list.isPending && <LoadingIndicator />}
        {list.isSuccess && items.length === 0 && !filtered && (
          <EmptyState icon="ScanLine" title={t('discovery.results.noResults')} description={canOperate ? t('discovery.results.noResultsText') : t('discovery.results.noResultsRead')} />
        )}
        {list.isSuccess && items.length === 0 && filtered && <EmptyState title={t('discovery.results.noMatch')} description={t('discovery.results.noMatchText')} />}
        {items.length > 0 && (
          <Table.ScrollContainer minWidth={860}>
            <Table aria-label={t('discovery.results.label')} data-testid="discovery-results-table" highlightOnHover>
              <Table.Thead>
                <Table.Tr>
                  {(['certificate', 'issuer', 'expires', 'foundOn', 'status'] as const).map((k) => (
                    <Table.Th key={k}>{t(`discovery.results.columns.${k}`)}</Table.Th>
                  ))}
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {items.map((c) => (
                  <ResultRow
                    key={c.fingerprint_sha256}
                    c={c}
                    onOpen={(button) => {
                      opener.current = button;
                      setSelected(c.fingerprint_sha256);
                    }}
                  />
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        )}
        {items.length > 0 && (
          <div className={ui.tableBottom}>
            <CursorFooter shown={items.length} hasMore={list.hasNextPage} loading={list.isFetchingNextPage} onMore={() => void list.fetchNextPage()} moreLabel={t('discovery.results.more')} />
          </div>
        )}
      </div>
      <CertificateDrawer
        fingerprint={selected}
        onClose={() => setSelected(null)}
        onAddServer={(e) => {
          setSelected(null);
          setAdding(e);
        }}
      />
      {adding && admin && (
        <AddServerModal
          initial={{ host: hostOf(adding), name: hostOf(adding) }}
          onClose={() => {
            setAdding(null);
            window.setTimeout(() => opener.current?.focus(), 0);
          }}
          onAdded={(tg) => {
            setAdding(null);
            void navigate(`/servers/${tg.id}`, { state: { added: true } });
          }}
        />
      )}
    </Stack>
  );
}

function ResultRow({ c, onOpen }: { c: DiscoveredCertificate; onOpen: (button: HTMLButtonElement) => void }) {
  const { t } = useTranslation();
  const name = c.subject_cn || c.sans[0] || '';
  const others = c.sans.filter((s) => s !== name);
  return (
    // The whole row opens the detail for a pointer; the name is the keyboard's (and the screen reader's) way in.
    <Table.Tr data-testid="discovery-result-row" onClick={(e) => onOpen((e.currentTarget.querySelector('button') as HTMLButtonElement | null) ?? (e.target as HTMLButtonElement))} style={{ cursor: 'pointer' }}>
      <Table.Td>
        <button
          type="button"
          className={classes.nameButton}
          aria-haspopup="dialog"
          onClick={(e) => {
            e.stopPropagation();
            onOpen(e.currentTarget);
          }}
        >
          {name ? (
            <Code translate="no" style={WRAP}>
              {name}
            </Code>
          ) : (
            t('discovery.results.noName')
          )}
        </button>
        {others.length > 0 && (
          <p className={classes.secondary} translate="no">
            {others.slice(0, 3).join(', ')}
            {others.length > 3 && ' …'}
          </p>
        )}
      </Table.Td>
      <Table.Td className={classes.small}>
        <span translate="no">{c.issuer_cn || '–'}</span>
      </Table.Td>
      <Table.Td>
        <Stack gap={4} align="flex-start">
          <Expiry notAfter={c.not_after} part="badge" />
          <span className={classes.secondary}>
            <Expiry notAfter={c.not_after} part="date" />
          </span>
        </Stack>
      </Table.Td>
      <Table.Td className={classes.small}>{t('discovery.results.foundOn', { count: c.endpoint_count })}</Table.Td>
      <Table.Td>
        <div className={classes.chips}>
          <StatusChip status={c.status} />
          {c.expired && (
            <StatusBadge tone="danger" icon="CircleX" size="sm">
              {t('discovery.chips.expired')}
            </StatusBadge>
          )}
          {c.self_signed && (
            <StatusBadge tone="neutral" icon="Fingerprint" size="sm">
              {t('discovery.chips.selfSigned')}
            </StatusBadge>
          )}
        </div>
      </Table.Td>
    </Table.Tr>
  );
}
