import { Anchor, Badge, Button, Code, Group, NativeSelect, SimpleGrid, Stack, Table, Text, TextInput, Title } from '@mantine/core';
import { useDebouncedValue } from '@mantine/hooks';
import { useInfiniteQuery, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, useNavigate } from 'react-router';
import { listAllServers, listCertificates } from '../api/endpoints';
import { CERTIFICATES_KEY, CSRS_KEY, TARGETS_KEY } from '../api/queryKeys';
import type { CertificateQuery, CertificateSourceFilter, ExpiryFilter } from '../api/types';
import { useAuth } from '../auth/AuthProvider';
import { CreateCSRDialog } from '../components/CreateCSRDialog';
import { ErrorAlert } from '../components/ErrorAlert';
import { Expiry } from '../components/Expiry';
import { PendingCSRs } from '../components/PendingCSRs';
import { UploadCertificateDialog } from '../components/UploadCertificateDialog';
import { WRAP } from '../components/wrap';

// The sources the list can be filtered by (openapi: listCertificates source).
const SOURCES: { value: CertificateSourceFilter; key: string }[] = [
  { value: 'discovered', key: 'sourceDiscovered' },
  { value: 'uploaded', key: 'sourceUploaded' },
  { value: 'csr', key: 'sourceCsr' },
];
const EXPIRIES: { value: Exclude<ExpiryFilter, ''>; key: string }[] = [
  { value: 'expired', key: 'expiryExpired' },
  { value: '30', key: 'expiry30' },
  { value: '60', key: 'expiry60' },
];

// CertificatesPage is the certificate inventory: one row per certificate however many servers use
// it, soonest expiry first, filtered on the server. The filter is part of the query key, so a
// change starts again from the first page.
export function CertificatesPage() {
  const { t } = useTranslation();
  const { session } = useAuth();
  const client = useQueryClient();
  const navigate = useNavigate();
  const canOperate = session?.user.role === 'admin' || session?.user.role === 'operator';
  const [search, setSearch] = useState('');
  const [targetId, setTargetId] = useState('');
  const [source, setSource] = useState<CertificateSourceFilter | ''>('');
  const [expiry, setExpiry] = useState<ExpiryFilter>('');
  const [q] = useDebouncedValue(search.trim(), 300);
  const [uploading, setUploading] = useState(false);
  const [creating, setCreating] = useState(false);
  // The certificate stored by the last upload: closing the dialog then opens it.
  const [uploadedId, setUploadedId] = useState<string | null>(null);

  const targets = useQuery({ queryKey: TARGETS_KEY, queryFn: listAllServers });
  const filter: CertificateQuery = { target_id: targetId, source, q, expiry };
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

  return (
    <Stack gap="md">
      <Title order={1}>{t('certificates.title')}</Title>
      <Text size="sm">{t('certificates.intro')}</Text>
      {canOperate && (
        <Group>
          <Button
            onClick={() => {
              setUploadedId(null);
              setUploading(true);
            }}
          >{t('certificates.uploadButton')}</Button>
          <Button variant="default" onClick={() => setCreating(true)}>
            {t('certificates.createRequest')}
          </Button>
        </Group>
      )}
      <PendingCSRs canOperate={canOperate} onCompleted={(id) => navigate(`/certificates/${id}`)} />
      <SimpleGrid cols={{ base: 1, sm: 2, lg: 4 }}>
        <TextInput label={t('certificates.search')} description={t('certificates.searchHelp')} value={search} onChange={(e) => setSearch(e.currentTarget.value)} maxLength={200} />
        <NativeSelect
          label={t('certificates.server')}
          value={targetId}
          onChange={(e) => setTargetId(e.currentTarget.value)}
          data={[{ value: '', label: t('certificates.allServers') }, ...(targets.data?.items ?? []).map((tg) => ({ value: tg.id, label: tg.name }))]}
        />
        <NativeSelect
          label={t('certificates.source')}
          value={source}
          onChange={(e) => setSource(e.currentTarget.value as CertificateSourceFilter | '')}
          data={[{ value: '', label: t('certificates.sourceAll') }, ...SOURCES.map((s) => ({ value: s.value, label: t(`certificates.${s.key}`) }))]}
        />
        <NativeSelect
          label={t('certificates.expiry')}
          value={expiry}
          onChange={(e) => setExpiry(e.currentTarget.value as ExpiryFilter)}
          data={[{ value: '', label: t('certificates.expiryAll') }, ...EXPIRIES.map((x) => ({ value: x.value, label: t(`certificates.${x.key}`) }))]}
        />
      </SimpleGrid>
      <ErrorAlert error={certs.error} />
      {certs.isSuccess && items.length === 0 && <Text c="gray.7">{t('certificates.empty')}</Text>}
      {items.length > 0 && (
        <Table.ScrollContainer minWidth={720}>
          <Table striped data-testid="certificates-table" aria-label={t('certificates.title')}>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>{t('certificates.columns.name')}</Table.Th>
                <Table.Th>{t('certificates.columns.expires')}</Table.Th>
                <Table.Th>{t('certificates.columns.daysLeft')}</Table.Th>
                <Table.Th>{t('certificates.columns.usedOn')}</Table.Th>
                <Table.Th>{t('certificates.columns.key')}</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {items.map((c) => (
                <Table.Tr key={c.id}>
                  <Table.Td style={WRAP}>
                    <Anchor component={Link} to={`/certificates/${c.id}`}>
                      {c.label || c.subject_cn ? <Code translate="no" style={WRAP}>{c.label || c.subject_cn}</Code> : t('certificates.noName')}
                    </Anchor>
                  </Table.Td>
                  <Table.Td>
                    <Expiry notAfter={c.not_after} part="date" />
                  </Table.Td>
                  <Table.Td>
                    <Expiry notAfter={c.not_after} part="badge" />
                  </Table.Td>
                  <Table.Td>{t('certificates.usedOn', { count: c.location_count })}</Table.Td>
                  <Table.Td>
                    <Badge variant="light" color={c.has_private_key ? 'green' : 'gray'} tt="none">
                      {c.has_private_key ? t('certificates.keyHeld') : t('certificates.keyNotHeld')}
                    </Badge>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      )}
      {certs.hasNextPage && (
        <Button variant="default" w="fit-content" loading={certs.isFetchingNextPage} onClick={() => void certs.fetchNextPage()}>
          {t('certificates.loadMore')}
        </Button>
      )}
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
