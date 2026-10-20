import { Anchor, Button, Code, CopyButton, Group, Progress, Stack, Table, Text, Title } from '@mantine/core';
import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, useParams } from 'react-router';
import { deploymentStatusText } from '../api/deployments';
import { keyAlgorithmKey } from '../api/enums';
import { getCertificate, listDeployments } from '../api/endpoints';
import { getCertificateImpact } from '../api/incidents';
import { certificateImpactKey, certificateKey, DEPLOYMENTS_KEY } from '../api/queryKeys';
import type { CertificateDetail } from '../api/types';
import { useAuth } from '../auth/AuthProvider';
import { PageLoader } from '../auth/guards';
import { CapabilitiesPanel } from '../components/certificates/CapabilitiesPanel';
import { ImpactPanel } from '../components/certificates/ImpactPanel';
import { StartIncidentDialog } from '../components/certificates/StartIncidentDialog';
import { UsageTopology } from '../components/certificates/UsageTopology';
import { DeployDialog } from '../components/DeployDialog';
import { ErrorAlert } from '../components/ErrorAlert';
import { daysLeft, expiryState, useNow } from '../components/Expiry';
import { ImportHistory } from '../components/ImportHistory';
import { ImportToKeyVaultDialog } from '../components/ImportToKeyVaultDialog';
import { MoveDialog } from '../components/services/MoveDialog';
import { ServiceBadge } from '../components/services/shared';
import { expiryTone, FactList, Notice, PageHeader, Panel, StatusBadge, type Fact } from '../components/ui';
import { WRAP } from '../components/wrap';
import { formatDate, formatDateTime } from '../datetime';
import { Icon } from '../design/Icon';
import classes from './CertificateDetailPage.module.css';

const DAY_MS = 86_400_000;

// lifeLeft is the share of the certificate's validity period still ahead, 0 to 100 (the validity bar).
function lifeLeft(c: CertificateDetail, now: number): number {
  const start = Date.parse(c.not_before);
  const end = Date.parse(c.not_after);
  if (!(end > start)) return 0;
  return Math.max(0, Math.min(100, ((end - now) / (end - start)) * 100));
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
  const admin = session?.user.role === 'admin';
  const [deploying, setDeploying] = useState(false);
  const [importing, setImporting] = useState(false);
  const [incident, setIncident] = useState(false);
  const [moving, setMoving] = useState(false);
  const cert = useQuery({ queryKey: certificateKey(id), queryFn: () => getCertificate(id) });
  // The impact (read by the panel too, one request) names the open key compromise incident, if any.
  const impact = useQuery({ queryKey: certificateImpactKey(id), queryFn: ({ signal }) => getCertificateImpact(id, signal) });
  const openIncident = impact.data?.open_incident_id ?? null;
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
  const state = expiryState(c.not_after, now);
  const days = daysLeft(c.not_after, now);
  const soon = !expired && Date.parse(c.not_after) - now < 7 * DAY_MS;
  // Only places whose server's software deploys certificates count: a certificate found only on
  // discovery-only servers (Apache) has nothing to deploy to from here.
  const first = c.locations.find((l) => l.deployable);
  // A revoked or compromised certificate is never deployed again: the capability list says so.
  const canDeploy = canOperate && c.has_private_key && !expired && first !== undefined && c.capabilities.includes('deploy');
  const sourceKey = `enum.certificateSource.${c.source}`;
  const sourceText = i18n.exists(sourceKey) ? t(sourceKey) : c.source;
  const upcoming = deployments.data?.items ?? [];
  const name = c.label || c.subject_cn;

  const facts: Fact[] = [
    { key: 'subject', label: t('certificates.detail.subject'), value: <Code translate="no" style={WRAP}>{c.subject}</Code> },
    { key: 'issuer', label: t('certificates.detail.issuer'), value: <Code translate="no" style={WRAP}>{c.issuer}</Code> },
    {
      key: 'names',
      label: t('certificates.detail.names'),
      value:
        c.sans.length === 0 ? (
          t('certificates.detail.noNames')
        ) : (
          <Group gap={4}>
            {c.sans.map((n) => (
              <Code translate="no" key={n} style={WRAP}>
                {n}
              </Code>
            ))}
          </Group>
        ),
    },
    { key: 'serial', label: t('certificates.detail.serial'), value: <Code translate="no" style={WRAP}>{c.serial}</Code> },
    { key: 'key', label: t('certificates.detail.key'), value: t('certificates.detail.keyValue', { algorithm: t(keyAlgorithmKey(c.key_algorithm)), bits: c.key_bits }) },
    {
      key: 'chain',
      label: t('certificates.page.chain'),
      value: (
        <Stack gap={6} align="flex-start">
          <StatusBadge tone={c.chain_complete ? 'success' : 'warning'} icon={c.chain_complete ? 'CircleCheck' : 'CircleAlert'}>
            {c.chain_complete ? t('certificates.page.chainComplete') : t('certificates.page.chainIncomplete')}
          </StatusBadge>
          <span>{c.chain_complete ? t('certificates.detail.chainComplete') : t('certificates.detail.chainIncomplete')}</span>
          {/* Alice completes a stored chain when the same certificate is uploaded again with the full
              chain; a certificate from a signing request cannot be completed that way. */}
          {!c.chain_complete && canOperate && (c.source === 'uploaded' || c.source === 'discovered') && (
            <span data-testid="chain-hint">{t('certificates.detail.chainCompleteByUpload')}</span>
          )}
        </Stack>
      ),
    },
    {
      key: 'privateKey',
      label: t('certificates.columns.key'),
      value: (
        <StatusBadge tone={c.has_private_key ? 'success' : 'neutral'} icon={c.has_private_key ? 'LockKeyhole' : 'Eye'}>
          {c.has_private_key ? t('certificates.keyHeld') : t('certificates.keyNotHeld')}
        </StatusBadge>
      ),
    },
    { key: 'fingerprint', label: t('certificates.detail.fingerprint'), value: <Code translate="no" style={WRAP}>{c.fingerprint}</Code> },
    { key: 'source', label: t('certificates.detail.source'), value: sourceText },
  ];

  return (
    <Stack gap="md">
      <PageHeader
        back={{ to: '/certificates', label: t('certificates.detail.backToList') }}
        icon="FileKey2"
        title={
          name ? (
            <Code translate="no" fz="inherit" fw="inherit" className={classes.titleCode} style={WRAP}>
              {name}
            </Code>
          ) : (
            t('certificates.noName')
          )
        }
        description={`${sourceText} · ${t('certificates.page.firstSeen', { date: formatDate(c.first_seen_at, i18n.language) })}`}
        status={
          <Group gap="xs">
            {c.self_signed && (
              <StatusBadge tone="neutral" icon="CircleDot">
                {t('certificates.detail.selfSigned')}
              </StatusBadge>
            )}
            <ServiceBadge service={c.service} link />
          </Group>
        }
        actions={
          <>
            <CopyButton value={c.fingerprint}>
              {({ copied, copy }) => (
                <Button variant="default" leftSection={<Icon name={copied ? 'Check' : 'Copy'} size={15} />} onClick={copy}>
                  {copied ? t('certificates.page.fingerprintCopied') : t('certificates.page.copyFingerprint')}
                </Button>
              )}
            </CopyButton>
            {canDeploy && (
              <Button leftSection={<Icon name="Rocket" size={15} />} onClick={() => setDeploying(true)}>
                {t('certificates.detail.deploy')}
              </Button>
            )}
            {openIncident && (
              <Button component={Link} to={`/incidents/${openIncident}`} variant="light" color="red" leftSection={<Icon name="ShieldAlert" size={15} />}>
                {t('incidents.openIncident')}
              </Button>
            )}
            {admin && (
              <Button variant="default" leftSection={<Icon name="Layers" size={15} />} onClick={() => setMoving(true)}>
                {t('services.moveTo')}
              </Button>
            )}
            {admin && !openIncident && impact.isSuccess && (
              <Button variant="light" color="red" leftSection={<Icon name="ShieldAlert" size={15} />} onClick={() => setIncident(true)}>
                {t('incidents.start.action')}
              </Button>
            )}
          </>
        }
      />
      {c.revoked_at && (
        <Notice tone="danger" title={t('certificates.revocation.revokedTitle')} testId="revoked-notice">
          {t('certificates.revocation.revokedText', {
            date: formatDateTime(c.revoked_at, i18n.language),
            reason: t(`acme.issued.revoke.reasons.${c.revocation_reason || 'unspecified'}`),
          })}
          {c.revoked_by_name ? ` ${t('certificates.revocation.revokedBy', { name: c.revoked_by_name })}` : ''}
        </Notice>
      )}
      {c.compromised_at && (
        <Notice tone="danger" title={t('certificates.revocation.compromisedTitle')} testId="compromised-notice">
          {t(c.source === 'acme' ? 'certificates.revocation.compromisedTextAcme' : 'certificates.revocation.compromisedText', {
            date: formatDateTime(c.compromised_at, i18n.language),
          })}
        </Notice>
      )}
      {expired ? (
        <Notice tone="danger" title={t('certificates.detail.expiredNoDeploy')}>
          {t('certificates.page.expiredText')}
        </Notice>
      ) : soon ? (
        <Notice tone="warning" title={days > 0 ? t('certificates.page.renewalDue', { count: days }) : t('certificates.page.renewalDueToday')}>
          {t('certificates.page.renewalText')}
        </Notice>
      ) : (
        <Notice tone="brand" title={t('certificates.page.validTitle')}>
          {t('certificates.page.validityNote')}
        </Notice>
      )}

      <div className={classes.grid}>
        <div className={classes.column}>
          <UsageTopology certificate={c} />
          <ImpactPanel certificateId={c.id} />
          <Panel title={t('certificates.page.details')}>
            <FactList label={t('certificates.detail.facts')} facts={facts} />
          </Panel>
          {c.locations.length > 0 && (
            <Panel title={t('certificates.page.locations')} padded={false} footer={c.locations_truncated ? <span>{t('certificates.detail.moreLocations')}</span> : undefined}>
              <Table.ScrollContainer minWidth={560}>
                <Table aria-label={t('certificates.detail.usedWhere')} highlightOnHover>
                  <Table.Thead>
                    <Table.Tr>
                      <Table.Th>{t('certificates.detail.columns.server')}</Table.Th>
                      <Table.Th>{t('certificates.detail.columns.website')}</Table.Th>
                      <Table.Th>{t('certificates.detail.columns.file')}</Table.Th>
                    </Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {c.locations.map((l) => {
                      const site = l.servers[0]?.names[0];
                      return (
                        <Table.Tr key={l.id}>
                          <Table.Td>
                            <Anchor component={Link} to={`/servers/${l.target_id}`} translate="no">
                              {l.target_name}
                            </Anchor>
                          </Table.Td>
                          <Table.Td>{site ? <Code translate="no" style={WRAP}>{site}</Code> : t('certificates.detail.noNames')}</Table.Td>
                          <Table.Td>
                            <Code translate="no" style={WRAP}>
                              {l.cert_path}
                            </Code>
                          </Table.Td>
                        </Table.Tr>
                      );
                    })}
                  </Table.Tbody>
                </Table>
              </Table.ScrollContainer>
            </Panel>
          )}
          <Panel title={t('certificates.detail.deployments')} padded={upcoming.length === 0}>
            <ErrorAlert error={deployments.error} />
            {deployments.isSuccess && upcoming.length === 0 && <Text size="sm">{t('certificates.detail.noDeployments')}</Text>}
            {upcoming.length > 0 && (
              <Table.ScrollContainer minWidth={560}>
                <Table aria-label={t('certificates.detail.deployments')} highlightOnHover>
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
                        <Table.Td translate="no">{d.target_name}</Table.Td>
                        <Table.Td>
                          <Code translate="no" style={WRAP}>
                            {d.cert_path}
                          </Code>
                        </Table.Td>
                        <Table.Td>
                          <Anchor component={Link} to={`/deployments/${d.id}`}>
                            {t(deploymentStatusText(d))}
                          </Anchor>
                        </Table.Td>
                      </Table.Tr>
                    ))}
                  </Table.Tbody>
                </Table>
              </Table.ScrollContainer>
            )}
          </Panel>
          {c.has_private_key && <ImportHistory certificateId={c.id} />}
        </div>

        <div className={classes.side}>
          <Panel title={t('certificates.page.validity')}>
            <div className={classes.validity}>
              <div>
                <div className={classes.eyebrow}>{t('certificates.page.remaining')}</div>
                <div className={classes.largeValue} data-tone={expiryTone(state)}>
                  {expired ? t('certificates.expired') : t('certificates.daysLeft', { count: days })}
                </div>
              </div>
              <Icon name="CalendarDays" size={20} className={classes.validityIcon} />
            </div>
            <Progress
              value={expired ? 0 : Math.round(lifeLeft(c, now))}
              size={5}
              radius={5}
              aria-label={t('certificates.page.remaining')}
              className={classes.progress}
              classNames={{ section: classes.progressSection }}
              data-soon={days <= 30 ? true : undefined}
            />
            <div className={classes.validityFacts}>
              <FactList
                facts={[
                  { key: 'from', label: t('certificates.detail.validFrom'), value: formatDateTime(c.not_before, i18n.language) },
                  { key: 'until', label: t('certificates.detail.validUntil'), value: formatDateTime(c.not_after, i18n.language) },
                ]}
              />
            </div>
          </Panel>

          <Panel title={t('certificates.page.nextAction')}>
            <Stack gap="sm" align="flex-start">
              {/* The deployment steps only where a deployment is possible: the reader's role, an expired certificate and
                  a missing key each get their own next action. */}
              {!canOperate && <Text size="sm">{t('certificates.page.nextActionReadOnly')}</Text>}
              {canOperate && expired && <Text size="sm">{t('certificates.page.nextActionExpired')}</Text>}
              {canOperate && !expired && c.has_private_key && <Text size="sm">{t('certificates.page.nextActionText')}</Text>}
              {!canOperate && (
                <StatusBadge tone="neutral" icon="Eye">
                  {t('certificates.page.readOnly')}
                </StatusBadge>
              )}
              {canDeploy && <Text size="sm">{t('certificates.detail.deployHelp')}</Text>}
              {!c.has_private_key && <Notice tone="neutral" title={t('certificates.detail.noKey')} />}
              {canOperate && c.has_private_key && !expired && first === undefined && (
                <Notice
                  tone="info"
                  testId="deploy-hint"
                  title={t('certificates.detail.deployHint')}
                  action={
                    // Underlined in the notice's own (info) color: readable on the tint in both color schemes.
                    <Anchor component={Link} to="/servers" size="sm" c="inherit" underline="always">
                      {t('certificates.detail.openServers')}
                    </Anchor>
                  }
                />
              )}
              {canOperate && c.has_private_key && !expired && (
                <Stack gap={4} align="flex-start">
                  <Button variant="default" leftSection={<Icon name="Cloud" size={15} />} disabled={!admin} onClick={() => setImporting(true)}>
                    {t('imports.action')}
                  </Button>
                  <Text size="sm">{t(admin ? 'certificates.detail.importHelp' : 'imports.adminOnly')}</Text>
                </Stack>
              )}
            </Stack>
          </Panel>

          <CapabilitiesPanel certificate={c} />

          <Panel title={t('certificates.page.dataHandling')}>
            <div className={classes.dataHandling}>
              <Icon name="LockKeyhole" size={18} className={classes.lock} />
              <div>
                <Title order={3} className={classes.h3}>
                  {t('certificates.page.keysPrivate')}
                </Title>
                <Text size="sm" mt={8}>
                  {t('certificates.page.keysPrivateText')}
                </Text>
              </div>
            </div>
          </Panel>
        </div>
      </div>
      {importing && admin && <ImportToKeyVaultDialog certificate={c} onClose={() => setImporting(false)} />}
      {canDeploy && <DeployDialog opened={deploying} onClose={() => setDeploying(false)} certificate={c} />}
      {moving && admin && <MoveDialog resource={{ type: 'certificate', id: c.id, name: name || c.fingerprint.slice(0, 16), service: c.service }} onClose={() => setMoving(false)} />}
      {incident && admin && <StartIncidentDialog certificate={c} onClose={() => setIncident(false)} />}
    </Stack>
  );
}
