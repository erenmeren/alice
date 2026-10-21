import { Anchor, Code, Group, Loader, Stack, Table, Text } from '@mantine/core';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';
import { getCertificateImpact, type CertificateImpact, type ImpactMatch } from '../../api/incidents';
import { certificateImpactKey } from '../../api/queryKeys';
import { formatDateTime } from '../../datetime';
import { ErrorAlert } from '../ErrorAlert';
import { HiddenCount } from '../services/shared';
import { EmptyState, Panel, StatusBadge } from '../ui';
import { WRAP } from '../wrap';

// MatchBadge says how a place is affected: it holds this very certificate, or another certificate made with the same
// private key (a key leak affects both).
export function MatchBadge({ match }: { match: ImpactMatch }) {
  const { t } = useTranslation();
  return (
    <StatusBadge tone={match === 'certificate' ? 'danger' : 'warning'} icon={match === 'certificate' ? 'FileKey2' : 'KeyRound'} size="sm">
      {t(`certificates.impact.match.${match}`)}
    </StatusBadge>
  );
}

// ImpactPanel answers "where is this certificate, or its private key, in use?": certificate files on managed servers,
// Key Vault versions and endpoints network discovery found. It is the first thing to read when a key leaked.
export function ImpactPanel({ certificateId }: { certificateId: string }) {
  const { t, i18n } = useTranslation();
  const q = useQuery({ queryKey: certificateImpactKey(certificateId), queryFn: ({ signal }) => getCertificateImpact(certificateId, signal) });
  const m: CertificateImpact | undefined = q.data;
  const others = m ? m.certificates.filter((c) => c.match === 'key') : [];
  const total = m ? m.locations.length + m.vaults.length + m.endpoints.length : 0;
  return (
    <Panel title={t('certificates.impact.title')} description={t('certificates.impact.description')} testId="impact-panel">
      <Stack gap="sm">
        <ErrorAlert error={q.error} />
        {q.isPending && (
          <Group>
            <Loader size="sm" aria-label={t('ui.loading')} />
          </Group>
        )}
        {m && (
          <Text size="sm" data-testid="impact-summary">
            {t('certificates.impact.summary', { servers: m.locations.length, vaults: m.vaults.length, endpoints: m.endpoints.length })}
          </Text>
        )}
        {m && others.length > 0 && (
          <Text size="sm" data-testid="impact-same-key">
            {t('certificates.impact.sameKey', { count: others.length })}{' '}
            {others.map((c, i) => (
              <span key={c.id}>
                {i > 0 && ', '}
                <Anchor component={Link} to={`/certificates/${c.id}`} translate="no">
                  {c.label || c.subject_cn || c.fingerprint.slice(0, 16)}
                </Anchor>
              </span>
            ))}
          </Text>
        )}
        {m && total === 0 && <EmptyState icon="CircleCheck" title={t('certificates.impact.none')} description={t('certificates.impact.noneText')} />}
        {m && m.locations.length > 0 && (
          <Table.ScrollContainer minWidth={560}>
            <Table aria-label={t('certificates.impact.servers')} highlightOnHover>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>{t('certificates.detail.columns.server')}</Table.Th>
                  <Table.Th>{t('certificates.detail.columns.file')}</Table.Th>
                  <Table.Th>{t('certificates.impact.columns.match')}</Table.Th>
                  <Table.Th>{t('certificates.impact.columns.replace')}</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {m.locations.map((l) => (
                  <Table.Tr key={l.location_id} data-testid="impact-location">
                    <Table.Td>
                      <Anchor component={Link} to={`/servers/${l.target_id}`} translate="no">
                        {l.target_name}
                      </Anchor>
                    </Table.Td>
                    <Table.Td>
                      <Code translate="no" style={WRAP}>
                        {l.cert_path}
                      </Code>
                    </Table.Td>
                    <Table.Td>
                      <MatchBadge match={l.match} />
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm">
                        {t(l.kv_bound ? 'certificates.impact.replace.vault' : l.deployable ? 'certificates.impact.replace.alice' : 'certificates.impact.replace.manual')}
                      </Text>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        )}
        {m && m.vaults.length > 0 && (
          <Table.ScrollContainer minWidth={480}>
            <Table aria-label={t('certificates.impact.vaults')}>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>{t('certificates.impact.columns.vault')}</Table.Th>
                  <Table.Th>{t('certificates.impact.columns.name')}</Table.Th>
                  <Table.Th>{t('certificates.impact.columns.match')}</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {m.vaults.map((v) => (
                  <Table.Tr key={`${v.kv_certificate_id}-${v.version}`} data-testid="impact-vault">
                    <Table.Td translate="no">{v.vault_name}</Table.Td>
                    <Table.Td>
                      <Anchor component={Link} to={`/key-vaults/${v.vault_id}/certificates/${v.kv_certificate_id}`} translate="no">
                        {v.name}
                      </Anchor>{' '}
                      {v.current && <Text span size="xs">{t('certificates.impact.currentVersion')}</Text>}
                    </Table.Td>
                    <Table.Td>
                      <MatchBadge match={v.match} />
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        )}
        {m && m.endpoints.length > 0 && (
          <Table.ScrollContainer minWidth={480}>
            <Table aria-label={t('certificates.impact.endpoints')}>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>{t('certificates.impact.columns.endpoint')}</Table.Th>
                  <Table.Th>{t('certificates.impact.columns.scope')}</Table.Th>
                  <Table.Th>{t('certificates.impact.columns.lastSeen')}</Table.Th>
                  <Table.Th>{t('certificates.impact.columns.match')}</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {m.endpoints.map((e) => (
                  <Table.Tr key={e.endpoint_id} data-testid="impact-endpoint">
                    <Table.Td>
                      <Code translate="no">{`${e.host || e.address}:${e.port}${e.sni ? ` (${e.sni})` : ''}`}</Code>
                    </Table.Td>
                    <Table.Td translate="no">{e.scope_name}</Table.Td>
                    <Table.Td>{e.last_seen ? formatDateTime(e.last_seen, i18n.language) : ''}</Table.Td>
                    <Table.Td>
                      <MatchBadge match={e.match} />
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        )}
        {m?.endpoints_hidden && (
          <Text size="xs" c="dimmed" data-testid="endpoints-hidden">
            {t('certificates.impact.endpointsHidden')}
          </Text>
        )}
        {m?.truncated && <Text size="xs">{t('certificates.impact.truncated')}</Text>}
        <HiddenCount count={m?.hidden_count} />
      </Stack>
    </Panel>
  );
}
