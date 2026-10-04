import { Alert, Anchor, Badge, Box, Button, Code, Group, Stack, Table, Text, Title } from '@mantine/core';
import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, useParams } from 'react-router';
import { deploymentStatusKey, keyAlgorithmKey } from '../api/enums';
import { getCertificate, listDeployments } from '../api/endpoints';
import { certificateKey, DEPLOYMENTS_KEY } from '../api/queryKeys';
import type { CertificateDetail } from '../api/types';
import { useAuth } from '../auth/AuthProvider';
import { PageLoader } from '../auth/guards';
import { DeployDialog } from '../components/DeployDialog';
import { ErrorAlert } from '../components/ErrorAlert';
import { Expiry, useNow } from '../components/Expiry';
import { WRAP } from '../components/wrap';
import { formatDateTime } from '../datetime';

function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <Box component="li" style={{ listStyle: 'none' }}>
      <Text size="sm" fw={600} component="span" display="block">
        {label}
      </Text>
      <Box component="div">{children}</Box>
    </Box>
  );
}

// CertificateDetailPage is one certificate (public data only: the private key never reaches the
// browser) with the websites that use it and its latest deployments. Deploy opens the dialog for
// the websites that already use the certificate; a new certificate is deployed from a server's page.
export function CertificateDetailPage() {
  const { t, i18n } = useTranslation();
  const { id = '' } = useParams();
  const { session } = useAuth();
  const canOperate = session?.user.role === 'admin' || session?.user.role === 'operator';
  const now = useNow();
  const [deploying, setDeploying] = useState(false);
  const cert = useQuery({ queryKey: certificateKey(id), queryFn: () => getCertificate(id) });
  const deployments = useQuery({
    queryKey: [...DEPLOYMENTS_KEY, { certificate_id: id, limit: 5 }],
    queryFn: () => listDeployments({ certificate_id: id, limit: 5 }),
  });

  if (cert.isPending) return <PageLoader />;
  if (cert.isError || !cert.data)
    return (
      <Stack gap="md">
        <ErrorAlert error={cert.error} />
        <Anchor component={Link} to="/certificates" w="fit-content">
          {t('certificates.detail.backToList')}
        </Anchor>
      </Stack>
    );
  const c: CertificateDetail = cert.data;
  const expired = Date.parse(c.not_after) <= now;
  const first = c.locations[0];
  const canDeploy = canOperate && c.has_private_key && !expired && first !== undefined;
  const sourceKey = `enum.certificateSource.${c.source}`;
  const upcoming = deployments.data?.items ?? [];

  return (
    <Stack gap="md">
      <Anchor component={Link} to="/certificates" w="fit-content" size="sm">
        {t('certificates.detail.backToList')}
      </Anchor>
      <Title order={1} style={WRAP}>
        {c.label || c.subject_cn ? <Code translate="no" fz="inherit" fw="inherit" style={WRAP}>{c.label || c.subject_cn}</Code> : t('certificates.noName')}
      </Title>
      {c.self_signed && (
        <Group>
          <Badge variant="light" color="gray" tt="none">
            {t('certificates.detail.selfSigned')}
          </Badge>
        </Group>
      )}
      {c.chain_complete ? (
        <Text size="sm">{t('certificates.detail.chainComplete')}</Text>
      ) : (
        <Alert color="yellow" role="status">
          {t('certificates.detail.chainIncomplete')}
        </Alert>
      )}
      {!c.has_private_key && (
        <Alert color="gray" role="status">
          {t('certificates.detail.noKey')}
        </Alert>
      )}
      {expired && (
        <Alert color="red" role="status">
          {t('certificates.detail.expiredNoDeploy')}
        </Alert>
      )}
      <Box component="ul" p={0} m={0} aria-label={t('certificates.detail.facts')} style={{ display: 'grid', gap: 'var(--mantine-spacing-sm)' }}>
        <Fact label={t('certificates.detail.subject')}>
          <Code translate="no" style={WRAP}>{c.subject}</Code>
        </Fact>
        <Fact label={t('certificates.detail.issuer')}>
          <Code translate="no" style={WRAP}>{c.issuer}</Code>
        </Fact>
        <Fact label={t('certificates.detail.names')}>
          {c.sans.length === 0 ? (
            <Text size="sm">{t('certificates.detail.noNames')}</Text>
          ) : (
            <Group gap={4}>
              {c.sans.map((n) => (
                <Code translate="no" key={n} style={WRAP}>
                  {n}
                </Code>
              ))}
            </Group>
          )}
        </Fact>
        <Fact label={t('certificates.detail.serial')}>
          <Code translate="no" style={WRAP}>{c.serial}</Code>
        </Fact>
        <Fact label={t('certificates.detail.validFrom')}>
          <Text size="sm">{formatDateTime(c.not_before, i18n.language)}</Text>
        </Fact>
        <Fact label={t('certificates.detail.validUntil')}>
          <Expiry notAfter={c.not_after} />
        </Fact>
        <Fact label={t('certificates.detail.key')}>
          <Text size="sm">{t('certificates.detail.keyValue', { algorithm: t(keyAlgorithmKey(c.key_algorithm)), bits: c.key_bits })}</Text>
        </Fact>
        <Fact label={t('certificates.columns.key')}>
          <Text size="sm">{c.has_private_key ? t('certificates.keyHeld') : t('certificates.keyNotHeld')}</Text>
        </Fact>
        <Fact label={t('certificates.detail.fingerprint')}>
          <Code translate="no" style={WRAP}>{c.fingerprint}</Code>
        </Fact>
        <Fact label={t('certificates.detail.source')}>
          <Text size="sm">{i18n.exists(sourceKey) ? t(sourceKey) : c.source}</Text>
        </Fact>
      </Box>
      {canDeploy && (
        <Stack gap={4}>
          <Button w="fit-content" onClick={() => setDeploying(true)}>
            {t('certificates.detail.deploy')}
          </Button>
          <Text size="sm">{t('certificates.detail.deployHelp')}</Text>
        </Stack>
      )}
      {canOperate && c.has_private_key && !expired && first === undefined && (
        <Alert color="blue" role="note" data-testid="deploy-hint">
          <Stack gap={4} align="flex-start">
            <Text size="sm">{t('certificates.detail.deployHint')}</Text>
            {/* Black and underlined like the license banner links: the primary color on the blue
                tint is below 4.5:1 (axe, e2e). */}
            {/* Black and underlined like the license banner links: the primary color on the blue
                tint is below 4.5:1 (axe, e2e). */}
            <Anchor component={Link} to="/servers" size="sm" c="black" underline="always">
              {t('certificates.detail.openServers')}
            </Anchor>
          </Stack>
        </Alert>
      )}

      <Title order={2} size="h3">
        {t('certificates.detail.usedWhere')}
      </Title>
      {c.locations.length === 0 ? (
        <Text size="sm">{t('certificates.detail.notUsed')}</Text>
      ) : (
        <Table.ScrollContainer minWidth={560}>
          <Table striped aria-label={t('certificates.detail.usedWhere')}>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>{t('certificates.detail.columns.server')}</Table.Th>
                <Table.Th>{t('certificates.detail.columns.website')}</Table.Th>
                <Table.Th>{t('certificates.detail.columns.file')}</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {c.locations.map((l) => {
                const name = l.servers[0]?.names[0];
                return (
                  <Table.Tr key={l.id}>
                    <Table.Td>
                      <Anchor component={Link} to={`/servers/${l.target_id}`}>
                        {l.target_name}
                      </Anchor>
                    </Table.Td>
                    <Table.Td>{name ? <Code translate="no" style={WRAP}>{name}</Code> : t('certificates.detail.noNames')}</Table.Td>
                    <Table.Td>
                      <Code translate="no" style={WRAP}>{l.cert_path}</Code>
                    </Table.Td>
                  </Table.Tr>
                );
              })}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      )}
      {c.locations_truncated && <Text size="sm">{t('certificates.detail.moreLocations')}</Text>}

      <Title order={2} size="h3">
        {t('certificates.detail.deployments')}
      </Title>
      <ErrorAlert error={deployments.error} />
      {deployments.isSuccess && upcoming.length === 0 && <Text size="sm">{t('certificates.detail.noDeployments')}</Text>}
      {upcoming.length > 0 && (
        <Table.ScrollContainer minWidth={560}>
          <Table striped aria-label={t('certificates.detail.deployments')}>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>{t('certificates.detail.columns.when')}</Table.Th>
                <Table.Th>{t('certificates.detail.columns.server')}</Table.Th>
                <Table.Th>{t('certificates.detail.columns.file')}</Table.Th>
                <Table.Th>{t('certificates.detail.columns.result')}</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {upcoming.map((d) => (
                <Table.Tr key={d.id}>
                  <Table.Td>{formatDateTime(d.created_at, i18n.language)}</Table.Td>
                  <Table.Td>{d.target_name}</Table.Td>
                  <Table.Td>
                    <Code translate="no" style={WRAP}>{d.cert_path}</Code>
                  </Table.Td>
                  <Table.Td>
                    <Anchor component={Link} to={`/deployments/${d.id}`}>
                      {t(deploymentStatusKey(d.status))}
                    </Anchor>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      )}
      {canDeploy && <DeployDialog opened={deploying} onClose={() => setDeploying(false)} certificate={c} />}
    </Stack>
  );
}
