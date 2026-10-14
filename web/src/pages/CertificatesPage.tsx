import { Anchor, Button, Code, NativeSelect, Stack, Table, TextInput } from '@mantine/core';
import { useInfiniteQuery, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, useNavigate } from 'react-router';
import { keyAlgorithmKey } from '../api/enums';
import { listAllServers, listCertificates } from '../api/endpoints';
import { getDiscoverySummary } from '../api/discovery';
import { getDashboardSummary } from '../api/phase7';
import { CERTIFICATES_KEY, CSRS_KEY, DASHBOARD_KEY, DISCOVERY_SUMMARY_KEY, TARGETS_KEY } from '../api/queryKeys';
import type { Certificate, CertificateQuery, CertificateSourceFilter, ExpiryFilter } from '../api/types';
import { useAuth } from '../auth/AuthProvider';
import { sourceIcon } from '../components/certificates/UsageTopology';
import { CreateCSRDialog } from '../components/CreateCSRDialog';
import { ErrorAlert } from '../components/ErrorAlert';
import { Expiry } from '../components/Expiry';
import { ExportButton } from '../components/ExportButton';
import { PendingCSRs } from '../components/PendingCSRs';
import { SavedViews } from '../components/SavedViews';
import { CursorFooter, EmptyState, PageHeader, StatusBadge } from '../components/ui';
import ui from '../components/ui/ui.module.css';
import { UploadCertificateDialog } from '../components/UploadCertificateDialog';
import { WRAP } from '../components/wrap';
import { Icon } from '../design/Icon';
import { useDebouncedParam, useUrlFilters } from '../hooks/useUrlFilters';
import classes from './CertificatesPage.module.css';

// The sources the list can be filtered by (openapi: listCertificates source).
const SOURCES: { value: CertificateSourceFilter; key: string }[] = [
  { value: 'discovered', key: 'sourceDiscovered' },
  { value: 'uploaded', key: 'sourceUploaded' },
  { value: 'csr', key: 'sourceCsr' },
  { value: 'azure_kv', key: 'sourceAzureKv' },
  { value: 'acme', key: 'sourceAcme' },
];
const EXPIRIES: { value: Exclude<ExpiryFilter, ''>; key: string }[] = [
  { value: 'expired', key: 'expiryExpired' },
  { value: '7', key: 'expiry7' },
  { value: '14', key: 'expiry14' },
  { value: '30', key: 'expiry30' },
  { value: '60', key: 'expiry60' },
  { value: '90', key: 'expiry90' },
];
// The filters live in the address (useSearchParams), so a link, a saved view and the export reproduce the list.
const CERT_FILTER_KEYS = ['target_id', 'source', 'q', 'expiry'] as const;

// The design's expiry shortcuts. Each sets the same `expiry` address filter as the native select (cumulative, as the
// server counts: "Next 30 days" includes the expired ones). The counts come from the dashboard summary, which counts the
// whole inventory; "All" has none, because the paged list has no total (R20).
const CHIPS: { value: '' | 'expired' | '7' | '30'; key: string; count?: 'expired' | 'within_7' | 'within_30' }[] = [
  { value: '', key: 'certificates.page.all' },
  { value: 'expired', key: 'certificates.expiryExpired', count: 'expired' },
  { value: '7', key: 'certificates.page.next7', count: 'within_7' },
  { value: '30', key: 'certificates.page.next30', count: 'within_30' },
];

// InventoryPanel is the design's table panel (the ResourceTable look): the toolbar stays mounted whether rows, an empty
// state or a no-match state follow it, so the search box keeps its focus while a person types into a search without
// matches. The table is rendered only when there are rows.
function InventoryPanel({ toolbar, footer, children }: { toolbar: ReactNode; footer?: ReactNode; children: ReactNode }) {
  return (
    <div className={ui.tablePanel}>
      <div className={ui.toolbar}>{toolbar}</div>
      {children}
      {footer && <div className={ui.tableBottom}>{footer}</div>}
    </div>
  );
}

// CertificatesPage is the certificate inventory: one row per certificate however many servers use
// it, soonest expiry first, filtered on the server. The filter is part of the query key, so a
// change starts again from the first page.
export function CertificatesPage() {
  const { t, i18n } = useTranslation();
  const { session } = useAuth();
  const client = useQueryClient();
  const navigate = useNavigate();
  const canOperate = session?.user.role === 'admin' || session?.user.role === 'operator';
  const [urlFilters, setFilters, clearFilters] = useUrlFilters(CERT_FILTER_KEYS);
  // A value in the address that is not one of the options (a typed link) is ignored: the list, the select, the export and a
  // saved view then agree, and the select never says "all" over a filtered list.
  const filters = {
    ...urlFilters,
    source: SOURCES.some((s) => s.value === urlFilters.source) ? urlFilters.source : '',
    expiry: EXPIRIES.some((x) => x.value === urlFilters.expiry) ? urlFilters.expiry : '',
  };
  const filtered = Object.values(filters).some((v) => v !== '');
  // Any filter other than the expiry window. The chips' counts come from the dashboard summary and count the whole
  // inventory (each equals the rows of ?expiry=N alone), so they are shown only while nothing else narrows the list.
  const narrowed = Object.entries(filters).some(([k, v]) => k !== 'expiry' && v !== '');
  const [search, onSearch, resetSearch] = useDebouncedParam(filters.q, (q) => setFilters({ q }));
  const [uploading, setUploading] = useState(false);
  const [creating, setCreating] = useState(false);
  // The certificate stored by the last upload: closing the dialog then opens it.
  const [uploadedId, setUploadedId] = useState<string | null>(null);

  const targets = useQuery({ queryKey: TARGETS_KEY, queryFn: listAllServers });
  const summary = useQuery({ queryKey: DASHBOARD_KEY, queryFn: getDashboardSummary });
  // Network discovery's unmanaged certificates are not part of this inventory (decision D2): a link says how many were
  // found, once a scan scope exists. A role or token that may not read the network map gets an error and no link.
  const discovery = useQuery({ queryKey: DISCOVERY_SUMMARY_KEY, queryFn: ({ signal }) => getDiscoverySummary(signal), retry: false });
  const filter: CertificateQuery = {
    target_id: filters.target_id,
    source: filters.source as CertificateSourceFilter | '',
    q: filters.q,
    expiry: filters.expiry as ExpiryFilter,
  };
  const certs = useInfiniteQuery({
    queryKey: [...CERTIFICATES_KEY, filter],
    queryFn: ({ pageParam }) => listCertificates({ ...filter, cursor: pageParam }),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
  });
  const items = certs.data?.pages.flatMap((p) => p.items) ?? [];

  const closeUpload = () => {
    setUploading(false);
    if (uploadedId) navigate(`/certificates/${uploadedId}`);
    setUploadedId(null);
  };
  const clearAll = () => {
    resetSearch('');
    clearFilters();
  };
  const sourceText = (c: Certificate) => {
    const key = `enum.certificateSource.${c.source}`;
    return i18n.exists(key) ? t(key) : c.source;
  };

  const toolbar = (
    <>
      <TextInput
        className={classes.search}
        label={t('certificates.search')}
        placeholder={t('certificates.searchHelp')}
        leftSection={<Icon name="Search" size={15} />}
        value={search}
        onChange={(e) => onSearch(e.currentTarget.value)}
        maxLength={200}
      />
      <NativeSelect
        className={classes.select}
        label={t('certificates.source')}
        value={filters.source}
        onChange={(e) => setFilters({ source: e.currentTarget.value })}
        data={[{ value: '', label: t('certificates.sourceAll') }, ...SOURCES.map((s) => ({ value: s.value, label: t(`certificates.${s.key}`) }))]}
      />
      <NativeSelect
        className={classes.select}
        label={t('certificates.server')}
        value={filters.target_id}
        onChange={(e) => setFilters({ target_id: e.currentTarget.value })}
        data={[{ value: '', label: t('certificates.allServers') }, ...(targets.data?.items ?? []).map((tg) => ({ value: tg.id, label: tg.name }))]}
      />
      <NativeSelect
        className={classes.select}
        label={t('certificates.expiry')}
        value={filters.expiry}
        onChange={(e) => setFilters({ expiry: e.currentTarget.value })}
        data={[{ value: '', label: t('certificates.expiryAll') }, ...EXPIRIES.map((x) => ({ value: x.value, label: t(`certificates.${x.key}`) }))]}
      />
      <div className={classes.grow} />
      <SavedViews
        page="certificates"
        keys={CERT_FILTER_KEYS}
        values={filters}
        set={(next) => {
          resetSearch(next.q ?? '');
          setFilters(next);
        }}
      />
      <Button variant="subtle" leftSection={<Icon name="X" size={15} />} onClick={clearAll}>
        {t('filters.clear')}
      </Button>
    </>
  );

  const counts = summary.data?.certificates;
  return (
    <Stack gap="md">
      <PageHeader
        title={t('certificates.title')}
        description={t('certificates.page.description')}
        actions={
          <>
            <ExportButton kind="certificates" filters={filters} />
            {canOperate && (
              <>
                <Button variant="default" leftSection={<Icon name="FileKey2" size={15} />} onClick={() => setCreating(true)}>
                  {t('certificates.createRequest')}
                </Button>
                <Button
                  leftSection={<Icon name="Plus" size={15} />}
                  onClick={() => {
                    setUploadedId(null);
                    setUploading(true);
                  }}
                >
                  {t('certificates.uploadButton')}
                </Button>
              </>
            )}
          </>
        }
      />
      <div className={classes.chipRow}>
        <div className={classes.chips} role="group" aria-label={t('certificates.page.chips')}>
          {CHIPS.map((c) => {
            // "All certificates" is pressed only when nothing at all is filtered: never "all" over a filtered list.
            const pressed = c.value === '' ? !filtered : filters.expiry === c.value;
            const n = c.count && counts && !narrowed ? counts[c.count] : undefined;
            return (
              <Button
                key={c.value || 'all'}
                size="xs"
                variant={pressed ? 'light' : 'default'}
                className={classes.chip}
                aria-pressed={pressed}
                onClick={() => setFilters({ expiry: c.value })}
              >
                {t(c.key)}
                {/* The space keeps the label and the count two words in the accessible name ("Next 7 days 4"). */}
                {n !== undefined && (
                  <>
                    {' '}
                    <b className={classes.chipCount}>{n}</b>
                  </>
                )}
              </Button>
            );
          })}
        </div>
        {discovery.data && discovery.data.scopes > 0 && (
          <Button component={Link} to="/discovery?view=unmanaged" size="xs" variant="default" className={classes.chip} leftSection={<Icon name="Network" size={14} />} data-testid="discovery-chip">
            {t('certificates.page.discovered', { count: discovery.data.unmanaged_total })}
          </Button>
        )}
      </div>
      <PendingCSRs canOperate={canOperate} onCompleted={(id) => navigate(`/certificates/${id}`)} />
      <ErrorAlert error={certs.error} />
      <InventoryPanel
        toolbar={toolbar}
        footer={items.length > 0 ? <CursorFooter shown={items.length} hasMore={certs.hasNextPage} loading={certs.isFetchingNextPage} onMore={() => void certs.fetchNextPage()} moreLabel={t('certificates.loadMore')} /> : undefined}
      >
        {certs.isSuccess && items.length === 0 && !filtered && (
          <EmptyState icon="FileKey2" title={t('certificates.page.emptyTitle')} description={t('certificates.intro')} />
        )}
        {/* No second Clear filters button here: the toolbar's is just above, and one control per name keeps the page's
            button names unique (the e2e clicks Clear filters by its name). */}
        {certs.isSuccess && items.length === 0 && filtered && (
          <EmptyState
            title={t('certificates.page.noMatchTitle')}
            description={
              <>
                <span>{t('certificates.empty')}</span> <span>{t('certificates.page.noMatchText')}</span>
              </>
            }
          />
        )}
        {items.length > 0 && (
          <Table.ScrollContainer minWidth={720}>
            <Table data-testid="certificates-table" aria-label={t('certificates.title')} highlightOnHover>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>{t('certificates.columns.name')}</Table.Th>
                  <Table.Th>{t('certificates.columns.expires')}</Table.Th>
                  <Table.Th>{t('certificates.columns.usedOn')}</Table.Th>
                  <Table.Th>{t('certificates.page.algorithm')}</Table.Th>
                  <Table.Th>{t('certificates.columns.key')}</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {items.map((c) => (
                  <Table.Tr key={c.id}>
                    <Table.Td>
                      <div className={classes.resourceName}>
                        <span className={classes.resourceIcon} data-source={c.source}>
                          <Icon name={sourceIcon(c.source)} size={16} />
                        </span>
                        <div className={classes.resourceText}>
                          {/* The link is the name alone (the e2e finds a row by it); the first <code> of a row is the name. */}
                          <Anchor component={Link} to={`/certificates/${c.id}`} className={classes.name}>
                            {c.label || c.subject_cn ? (
                              <Code translate="no" style={WRAP}>
                                {c.label || c.subject_cn}
                              </Code>
                            ) : (
                              t('certificates.noName')
                            )}
                          </Anchor>
                          <p className={classes.secondary} style={WRAP}>
                            {sourceText(c)} · <span translate="no">{c.issuer}</span>
                          </p>
                        </div>
                      </div>
                    </Table.Td>
                    <Table.Td>
                      <Stack gap={4} align="flex-start">
                        <Expiry notAfter={c.not_after} part="badge" />
                        <span className={classes.secondary}>
                          <Expiry notAfter={c.not_after} part="date" />
                        </span>
                      </Stack>
                    </Table.Td>
                    <Table.Td>{t('certificates.usedOn', { count: c.location_count })}</Table.Td>
                    <Table.Td className={classes.mono}>{t('certificates.detail.keyValue', { algorithm: t(keyAlgorithmKey(c.key_algorithm)), bits: c.key_bits })}</Table.Td>
                    <Table.Td>
                      <StatusBadge tone={c.has_private_key ? 'success' : 'neutral'} icon={c.has_private_key ? 'LockKeyhole' : 'Eye'}>
                        {c.has_private_key ? t('certificates.keyHeld') : t('certificates.keyNotHeld')}
                      </StatusBadge>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        )}
      </InventoryPanel>
      <p className={classes.note}>{t('certificates.page.cumulative')}</p>
      {canOperate && (
        <>
          <UploadCertificateDialog
            opened={uploading}
            onClose={closeUpload}
            onUploaded={(id) => {
              setUploadedId(id);
              void client.invalidateQueries({ queryKey: CERTIFICATES_KEY });
            }}
          />
          <CreateCSRDialog opened={creating} onClose={() => setCreating(false)} onCreated={() => void client.invalidateQueries({ queryKey: CSRS_KEY })} />
        </>
      )}
    </Stack>
  );
}
