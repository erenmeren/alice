import { Alert, Anchor, Badge, Box, Button, Checkbox, Code, Group, Stack, Table, Text, Title } from '@mantine/core';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, useParams } from 'react-router';
import { getBinding, getKVCertificate, releaseKVVersion, type KVCertificateDetail, type KVVersion } from '../api/keyvault';
import { bindingKey, KV_CERTIFICATES_KEY, kvCertificateKey } from '../api/queryKeys';
import { useAuth } from '../auth/AuthProvider';
import { PageLoader } from '../auth/guards';
import { AppModal } from '../components/AppModal';
import { BindingPanel } from '../components/BindingPanel';
import { CodeText } from '../components/CodeText';
import { ErrorAlert } from '../components/ErrorAlert';
import { Expiry, useNow } from '../components/Expiry';
import { KVDeployDialog } from '../components/KVDeployDialog';
import { ROLE_SECRETS_USER } from '../components/roleCommands';
import { useStepUp } from '../components/StepUpProvider';
import { isRecentNewVersion, shortVersion, versionBlock } from '../components/vaultText';
import { WRAP } from '../components/wrap';
import { formatDate, formatDateTime } from '../datetime';

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <Group gap="xs" align="baseline" wrap="wrap">
      <Text size="sm" fw={600}>
        {label}
      </Text>
      {children}
    </Group>
  );
}

const Chip = ({ children, color = 'gray' }: { children: ReactNode; color?: string }) => (
  <Badge variant="light" color={color} tt="none">
    {children}
  </Badge>
);

// What releasing a held version leads to, from what the page knows. Automatic deployment never
// carries the chain confirmation, so a version held for its incomplete chain is refused and held again;
// it only ever considers the certificate's CURRENT version; and even then nothing is guaranteed (the
// vault may be unreachable, a wave may have stopped), so the text says "may". Everything else is manual; a
// chain hold released without automatic deployment also says that Deploy now asks for the chain again (a
// release never confirms it).
type ReleaseKind = 'chain' | 'may' | 'manual' | 'chainManual';
const RELEASE_HELP: Record<ReleaseKind, string> = {
  chain: 'vaults.cert.releaseHelpChain',
  may: 'vaults.cert.releaseHelpAuto',
  manual: 'vaults.cert.releaseHelpManual',
  chainManual: 'vaults.cert.releaseHelpChainManual',
};
const RELEASED: Record<ReleaseKind, string> = {
  chain: 'vaults.cert.releasedChain',
  may: 'vaults.cert.releasedAuto',
  manual: 'vaults.cert.releasedManual',
  chainManual: 'vaults.cert.releasedChainManual',
};
function releaseKind(v: KVVersion, c: KVCertificateDetail): ReleaseKind {
  if (c.binding?.auto_deploy !== true) return v.held_reason === 'incomplete_chain' ? 'chainManual' : 'manual';
  if (v.held_reason === 'incomplete_chain') return 'chain';
  return v.held_reason === 'license' && v.version === c.current_version ? 'may' : 'manual';
}

// KVCertificatePage is one certificate of a vault: its policy, every version Alice has seen (newest
// first, with held versions and Deploy now) and the websites connected to it.
export function KVCertificatePage() {
  const { t, i18n } = useTranslation();
  const { vaultId = '', id = '' } = useParams();
  const { session } = useAuth();
  const now = useNow();
  const role = session?.user.role;
  const admin = role === 'admin';
  const canOperate = admin || role === 'operator';
  const cert = useQuery({ queryKey: kvCertificateKey(vaultId, id), queryFn: () => getKVCertificate(vaultId, id) });
  const [deploy, setDeploy] = useState<string | null>(null);
  const [releasing, setReleasing] = useState<KVVersion | null>(null);
  const [released, setReleased] = useState<ReleaseKind | null>(null);

  const back = (
    <Anchor component={Link} to={`/key-vaults/${vaultId}`} w="fit-content" size="sm">
      {t('vaults.cert.backToVault')}
    </Anchor>
  );
  if (cert.isPending) return <PageLoader />;
  if (cert.isError || !cert.data)
    return (
      <Stack gap="md">
        <ErrorAlert error={cert.error} />
        {back}
      </Stack>
    );
  const c: KVCertificateDetail = cert.data;
  const monitorOnly = c.exportable === false;
  // The versions arrive newest first.
  const versions = c.versions;

  return (
    <Stack gap="md">
      {back}
      <Title order={1} style={WRAP}>
        <span translate="no">{c.name}</span>
      </Title>
      <Group gap={4}>
        {monitorOnly && <Chip>{t('vaults.monitorOnly')}</Chip>}
        {c.missing_since !== null && <Chip color="orange">{t('vaults.removed')}</Chip>}
        {!c.enabled && <Chip>{t('vaults.disabledChip')}</Chip>}
        {c.bound && <Chip color="green">{t('vaults.connected', { count: c.binding?.location_count ?? 0 })}</Chip>}
      </Group>
      {monitorOnly && (
        <Alert color="gray" role="status">
          {t('vaults.cert.notExportable')}
        </Alert>
      )}
      {c.details_pending && (
        <Alert color="gray" role="status">
          {t('vaults.cert.detailsPending')}
        </Alert>
      )}
      {!monitorOnly && c.deploy_access === 'forbidden' && (
        <Alert color="yellow" role="status">
          <CodeText i18nKey="vaults.cert.secretsRole" param="role" value={ROLE_SECRETS_USER} />
        </Alert>
      )}
      {released && (
        <Alert color="green" role="status">
          {t(RELEASED[released])}
        </Alert>
      )}

      <Title order={2} size="h3">
        {t('vaults.cert.policyTitle')}
      </Title>
      <Stack gap={4} role="group" aria-label={t('vaults.cert.policyTitle')}>
        <Fact label={t('vaults.cert.exportable')}>
          <Text size="sm">{c.exportable === null ? t('vaults.cert.exportableUnknown') : t(c.exportable ? 'vaults.yes' : 'vaults.no')}</Text>
        </Fact>
        {c.key_type !== '' && (
          <Text size="sm" style={WRAP}>
            <CodeText i18nKey={c.key_size > 0 ? 'vaults.cert.keyValue' : 'vaults.cert.keyValueNoSize'} param="type" value={c.key_type} params={{ bits: c.key_size }} />
          </Text>
        )}
        {c.issuer_name !== '' && (
          <Fact label={t('vaults.cert.issuer')}>
            <Text size="sm" translate="no" style={WRAP}>
              {c.issuer_name}
            </Text>
          </Fact>
        )}
        {c.content_type !== '' && (
          <Fact label={t('vaults.cert.contentType')}>
            <Text size="sm" translate="no" style={WRAP}>
              {c.content_type}
            </Text>
          </Fact>
        )}
        <Text size="sm">{t(c.auto_renew ? 'vaults.cert.renews' : 'vaults.cert.noRenew')}</Text>
        {c.expires && (
          <Fact label={t('vaults.cert.expires')}>
            <Expiry notAfter={c.expires} />
          </Fact>
        )}
      </Stack>

      <Title order={2} size="h3">
        {t('vaults.cert.versionsTitle')}
      </Title>
      {versions.length === 0 && <Text size="sm">{t('vaults.cert.noVersions')}</Text>}
      {versions.length > 0 && (
        <Table.ScrollContainer minWidth={900}>
          <Table striped aria-label={t('vaults.cert.versionsTitle')}>
            <Table.Thead>
              <Table.Tr>
                {(['version', 'thumbprint', 'validFrom', 'validTo', 'enabled', 'found', 'state', 'actions'] as const).map((k) => (
                  <Table.Th key={k}>{t(`vaults.cert.vcolumns.${k}`)}</Table.Th>
                ))}
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {versions.map((v, i) => {
                const block = versionBlock(v, now);
                const current = v.version === c.current_version;
                const heldText = v.held ? t(v.held_reason === 'incomplete_chain' ? 'vaults.heldChain' : 'vaults.heldVersion') : '';
                const newer = i === 0 && isRecentNewVersion(v.kv_created_at, c.first_seen_at, now);
                // An Operator cannot confirm a chain Alice knows is incomplete: the row says so up front.
                const reason = !c.binding ? null : v.held && !admin ? 'heldAdmin' : (block ?? (!admin && v.chain_incomplete ? 'chainAdmin' : null));
                return (
                  <Table.Tr key={v.id} data-testid="kv-version-row" data-held={v.held ? 'true' : undefined}>
                    <Table.Td>
                      <Stack gap={2}>
                        <Code translate="no">{shortVersion(v.version)}</Code>
                        {current && <Chip color="blue">{t('vaults.cert.current')}</Chip>}
                      </Stack>
                    </Table.Td>
                    <Table.Td>
                      <Code translate="no" style={WRAP}>
                        {v.thumbprint}
                      </Code>
                    </Table.Td>
                    <Table.Td>{v.not_before ? formatDate(v.not_before, i18n.language) : ''}</Table.Td>
                    <Table.Td>{v.expires ? <Expiry notAfter={v.expires} /> : t('vaults.noExpiry')}</Table.Td>
                    <Table.Td>{t(v.enabled ? 'vaults.yes' : 'vaults.no')}</Table.Td>
                    <Table.Td>{formatDateTime(v.detected_at, i18n.language)}</Table.Td>
                    <Table.Td>
                      <Stack gap={4}>
                        <Group gap={4}>
                          {newer && <Chip color="blue">{t('vaults.newVersion')}</Chip>}
                          {v.held && <Chip color="yellow">{t('vaults.heldChip')}</Chip>}
                          {v.exportable === false && <Chip>{t('vaults.monitorOnly')}</Chip>}
                        </Group>
                        {v.held && (
                          <Text size="xs" data-testid="held-text">
                            {heldText}
                          </Text>
                        )}
                      </Stack>
                    </Table.Td>
                    <Table.Td>
                      <Stack gap={4}>
                        {canOperate && c.binding && (
                          <Button size="xs" disabled={reason !== null} aria-label={t('vaults.cert.deployNamed', { version: shortVersion(v.version) })} onClick={() => setDeploy(v.id)}>
                            {t('bindings.deployNow')}
                          </Button>
                        )}
                        {canOperate && c.binding && reason !== null && <Text size="xs">{t(`bindings.cannot.${reason}`)}</Text>}
                        {v.held && admin && (
                          <Button size="xs" variant="default" aria-label={t('vaults.cert.releaseNamed', { version: shortVersion(v.version) })} onClick={() => setReleasing(v)}>
                            {t('vaults.cert.release')}
                          </Button>
                        )}
                        {v.held && !admin && <Text size="xs">{t('vaults.cert.releaseAdminOnly')}</Text>}
                      </Stack>
                    </Table.Td>
                  </Table.Tr>
                );
              })}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      )}

      <BindingPanel vaultId={vaultId} certificate={c} canOperate={canOperate} admin={admin} />

      {deploy !== null && <KVDeploy certificateId={id} vaultId={vaultId} versionId={deploy} onClose={() => setDeploy(null)} />}
      {releasing && (
        <ReleaseDialog
          vaultId={vaultId}
          certificateId={id}
          version={releasing}
          onClose={() => setReleasing(null)}
          kind={releaseKind(releasing, c)}
          onReleased={() => {
            setReleased(releaseKind(releasing, c));
            setReleasing(null);
          }}
        />
      )}
    </Stack>
  );
}

// KVDeploy opens Deploy now with the connection read fresh (its websites and version).
function KVDeploy({ certificateId, vaultId, versionId, onClose }: { certificateId: string; vaultId: string; versionId: string; onClose: () => void }) {
  const cert = useQuery({ queryKey: kvCertificateKey(vaultId, certificateId), queryFn: () => getKVCertificate(vaultId, certificateId) });
  return <DeployWithBinding certificate={cert.data} versionId={versionId} onClose={onClose} />;
}

function DeployWithBinding({ certificate, versionId, onClose }: { certificate: KVCertificateDetail | undefined; versionId: string; onClose: () => void }) {
  const { t } = useTranslation();
  const summaryId = certificate?.binding?.id ?? '';
  const binding = useQuery({ queryKey: bindingKey(summaryId), queryFn: () => getBinding(summaryId), enabled: summaryId !== '' });
  if (binding.isError)
    return (
      <AppModal opened onClose={onClose} title={t('bindings.deployTitle')}>
        <Stack gap="sm">
          <ErrorAlert error={binding.error} />
          <Group justify="flex-end">
            <Button onClick={onClose}>{t('ui.close')}</Button>
          </Group>
        </Stack>
      </AppModal>
    );
  if (!certificate || !binding.data) return null;
  return <KVDeployDialog binding={binding.data} certificate={certificate} versionId={versionId} onClose={onClose} />;
}

// ReleaseDialog releases a held version: automatic deployment may then consider it. Nothing is
// deployed. A version held for its incomplete chain also needs the Administrator's confirmation.
// Administrators only, with a fresh step-up (asked for when the server wants it).
function ReleaseDialog({ vaultId, certificateId, version, kind, onClose, onReleased }: { vaultId: string; certificateId: string; version: KVVersion; kind: ReleaseKind; onClose: () => void; onReleased: () => void }) {
  const { t } = useTranslation();
  const { run } = useStepUp();
  const client = useQueryClient();
  const chain = version.held_reason === 'incomplete_chain';
  const [confirm, setConfirm] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const go = async () => {
    setBusy(true);
    setError(null);
    try {
      await run(() => releaseKVVersion(vaultId, certificateId, version.id, chain && confirm));
      void client.invalidateQueries({ queryKey: KV_CERTIFICATES_KEY });
      onReleased();
    } catch (e) {
      setError(e);
      setBusy(false);
    }
  };
  return (
    <AppModal opened onClose={onClose} title={t('vaults.cert.releaseTitle')}>
      <Stack gap="sm">
        <Text size="sm">{t(chain ? 'vaults.heldChain' : 'vaults.heldVersion')}</Text>
        <Text size="sm">{t(RELEASE_HELP[kind])}</Text>
        {chain && <Box><Checkbox label={t('deploy.confirmChain')} checked={confirm} onChange={(e) => setConfirm(e.currentTarget.checked)} /></Box>}
        <ErrorAlert error={error} />
        <Group justify="flex-end">
          <Button variant="default" onClick={onClose}>
            {t('ui.cancel')}
          </Button>
          <Button loading={busy} disabled={chain && !confirm} onClick={() => void go()}>
            {t('vaults.cert.release')}
          </Button>
        </Group>
      </Stack>
    </AppModal>
  );
}
