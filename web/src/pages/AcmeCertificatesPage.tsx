import { Anchor, Button, Code, NativeSelect, Stack, Table } from '@mantine/core';
import { useInfiniteQuery } from '@tanstack/react-query';
import { useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, useNavigate } from 'react-router';
import { ACME_CERTIFICATE_STATES, certificateStateKey, challengeKey, listACMECertificates, type ACMECertificate, type ACMECertificateState } from '../api/acme';
import { acmeCertificateListKey } from '../api/queryKeys';
import { useAuth } from '../auth/AuthProvider';
import { GetCertificateDialog } from '../components/acme/GetCertificateDialog';
import { providerName, renewal, stateIcon, stateTone, useChangesLocked, useProviders } from '../components/acme/issued';
import { ErrorAlert } from '../components/ErrorAlert';
import { Expiry } from '../components/Expiry';
import { InternalLink } from '../components/InternalLink';
import { LoadingIndicator } from '../components/LoadingIndicator';
import { CursorFooter, EmptyState, Notice, PageHeader, StatusBadge } from '../components/ui';
import ui from '../components/ui/ui.module.css';
import { WRAP } from '../components/wrap';
import { formatDate, formatDateTime } from '../datetime';
import { Icon } from '../design/Icon';
import { useUrlFilters } from '../hooks/useUrlFilters';
import classes from './KeyVaults.module.css';

const FILTER_KEYS = ['state', 'provider_id'] as const;

// AcmeCertificatesPage is "Issued certificates": the certificates Alice gets and renews from a certificate authority
// (ACME). Everybody who may read them sees the list; an Administrator also defines new ones ("Get a certificate").
export function AcmeCertificatesPage() {
  const { t, i18n } = useTranslation();
  const { session } = useAuth();
  const navigate = useNavigate();
  const role = session?.user.role;
  const admin = role === 'admin';
  const locked = useChangesLocked();
  const [urlFilters, setFilters, clearFilters] = useUrlFilters(FILTER_KEYS);
  // A value in the address that is not an option is ignored, so the select never says "all" over a filtered list.
  const filters = { ...urlFilters, state: (ACME_CERTIFICATE_STATES as readonly string[]).includes(urlFilters.state) ? urlFilters.state : '' };
  const filtered = filters.state !== '' || filters.provider_id !== '';
  const providers = useProviders();
  const query = { state: (filters.state || undefined) as ACMECertificateState | undefined, provider_id: filters.provider_id || undefined };
  const list = useInfiniteQuery({
    queryKey: acmeCertificateListKey(query),
    queryFn: ({ pageParam }) => listACMECertificates({ ...query, cursor: pageParam ?? undefined }),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
  });
  const items = list.data?.pages.flatMap((p) => p.items) ?? [];
  const [creating, setCreating] = useState(false);
  // The empty state carries the button itself: one control per name on the page.
  const emptyInstall = list.isSuccess && items.length === 0 && !filtered;

  const toolbar = (
    <>
      <NativeSelect
        label={t('acme.issued.list.state')}
        value={filters.state}
        onChange={(e) => setFilters({ state: e.currentTarget.value })}
        data={[{ value: '', label: t('acme.issued.list.stateAll') }, ...ACME_CERTIFICATE_STATES.map((s) => ({ value: s, label: t(certificateStateKey(s)) }))]}
      />
      <NativeSelect
        label={t('acme.issued.list.authority')}
        value={filters.provider_id}
        onChange={(e) => setFilters({ provider_id: e.currentTarget.value })}
        data={[{ value: '', label: t('acme.issued.list.authorityAll') }, ...(providers.data?.items ?? []).map((p) => ({ value: p.id, label: p.name }))]}
      />
      <div style={{ flex: '1 1 auto' }} />
      <Button variant="subtle" leftSection={<Icon name="X" size={15} />} onClick={clearFilters}>
        {t('filters.clear')}
      </Button>
    </>
  );

  return (
    <Stack gap="md">
      <PageHeader
        title={t('acme.issued.title')}
        description={t('acme.issued.description')}
        actions={
          admin &&
          list.isSuccess &&
          !emptyInstall && (
            <Button leftSection={<Icon name="Plus" size={15} />} disabled={locked} onClick={() => setCreating(true)}>
              {t('acme.issued.getCertificate')}
            </Button>
          )
        }
      />
      {locked && <Notice tone="warning" title={t('acme.issued.lockedTitle')}>{t('acme.issued.lockedText')}</Notice>}
      {role === 'auditor' && <Notice tone="neutral" title={t('acme.issued.readOnly')} />}
      <ErrorAlert error={list.error} />
      <div className={ui.tablePanel}>
        <div className={ui.toolbar}>{toolbar}</div>
        {list.isPending && <LoadingIndicator />}
        {emptyInstall && (
          <EmptyState
            icon="ShieldCheck"
            title={t('acme.issued.empty')}
            description={
              <>
                <span>{t('acme.issued.emptyText')}</span>{' '}
                {admin && (providers.data?.items ?? []).length === 0 && (
                  <span>
                    {t('acme.issued.emptyNoAuthority')}{' '}
                    <InternalLink to="/settings?tab=acme">{t('acme.issued.settingsLink')}</InternalLink>
                  </span>
                )}
                {!admin && <span>{t('acme.issued.emptyAdminOnly')}</span>}
              </>
            }
            action={
              admin && (
                <Button leftSection={<Icon name="Plus" size={15} />} disabled={locked} onClick={() => setCreating(true)}>
                  {t('acme.issued.getCertificate')}
                </Button>
              )
            }
          />
        )}
        {list.isSuccess && items.length === 0 && filtered && <EmptyState title={t('acme.issued.noMatch')} description={t('acme.issued.noMatchText')} />}
        {items.length > 0 && (
          <Table.ScrollContainer minWidth={900}>
            <Table aria-label={t('acme.issued.title')} data-testid="acme-certificates-table" highlightOnHover>
              <Table.Thead>
                <Table.Tr>
                  {(['names', 'authority', 'state', 'proof', 'expires', 'renewal', 'automation'] as const).map((k) => (
                    <Table.Th key={k}>{t(`acme.issued.columns.${k}`)}</Table.Th>
                  ))}
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {items.map((c) => (
                  <Row key={c.id} c={c} authority={providerName(providers.data?.items, c.provider_id)} lang={i18n.language} />
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        )}
        {items.length > 0 && (
          <div className={ui.tableBottom}>
            <CursorFooter shown={items.length} hasMore={list.hasNextPage} loading={list.isFetchingNextPage} onMore={() => void list.fetchNextPage()} moreLabel={t('acme.issued.list.more')} />
          </div>
        )}
      </div>
      {creating && (
        <GetCertificateDialog
          onClose={() => setCreating(false)}
          onOpen={(id, testOrderId) => {
            setCreating(false);
            void navigate(`/acme/${id}`, testOrderId ? { state: { testOrderId } } : undefined);
          }}
        />
      )}
    </Stack>
  );
}

function Row({ c, authority, lang }: { c: ACMECertificate; authority: string; lang: string }) {
  const { t } = useTranslation();
  const r = renewal(c);
  let next: ReactNode;
  switch (r.kind) {
    case 'attempt':
      next = t('acme.issued.renewal.attemptAt', { time: formatDateTime(r.at, lang) });
      break;
    case 'planned':
      next = (
        <>
          <span>{formatDate(r.at, lang)}</span>
          <p className={classes.secondary}>{r.ari ? t('acme.issued.renewal.ariShort') : t('acme.issued.renewal.beforeExpiry', { count: c.renew_before_days })}</p>
        </>
      );
      break;
    case 'none':
      next = t('acme.issued.renewal.afterFirst');
      break;
    case 'stopped':
      next = t('acme.issued.renewal.stoppedShort');
      break;
    default:
      next = t('acme.issued.renewal.offShort');
  }
  const more = c.names.length - 1;
  return (
    <Table.Tr data-testid="acme-certificate-row">
      <Table.Td>
        <Anchor component={Link} to={`/acme/${c.id}`} className={classes.name}>
          <Code translate="no" style={WRAP}>
            {c.names[0] ?? ''}
          </Code>
        </Anchor>
        {more > 0 && <p className={classes.secondary}>{t('acme.issued.moreNames', { count: more })}</p>}
      </Table.Td>
      <Table.Td>
        <span translate="no">{authority}</span>
      </Table.Td>
      <Table.Td>
        <StatusBadge tone={stateTone(c.state)} icon={stateIcon(c.state)} data-state={c.state}>
          {t(certificateStateKey(c.state))}
        </StatusBadge>
      </Table.Td>
      <Table.Td className={classes.small}>{t(challengeKey(c.challenge))}</Table.Td>
      <Table.Td>
        {c.current ? (
          <Stack gap={4} align="flex-start">
            <Expiry notAfter={c.current.not_after} part="badge" />
            <span className={classes.secondary}>
              <Expiry notAfter={c.current.not_after} part="date" />
            </span>
          </Stack>
        ) : (
          <span className={classes.small}>{t('acme.issued.notIssued')}</span>
        )}
      </Table.Td>
      <Table.Td className={classes.small}>{next}</Table.Td>
      <Table.Td>
        <div className={classes.chips}>
          <StatusBadge tone={c.auto_renew ? 'success' : 'neutral'} icon={c.auto_renew ? 'RotateCw' : 'Pause'} size="sm">
            {t(c.auto_renew ? 'acme.issued.autoRenewOn' : 'acme.issued.autoRenewOff')}
          </StatusBadge>
          <StatusBadge tone={c.auto_deploy ? 'success' : 'neutral'} icon={c.auto_deploy ? 'Rocket' : 'Pause'} size="sm">
            {t(c.auto_deploy ? 'acme.issued.autoDeployOn' : 'acme.issued.autoDeployOff')}
          </StatusBadge>
        </div>
      </Table.Td>
    </Table.Tr>
  );
}
