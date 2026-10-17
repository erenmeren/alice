import { Alert, Box, Button, Code, Group, Stack, Switch, Table, Text } from '@mantine/core';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { fileProblemKey, configErrorKey, configReasonKey, unsupportedReasonKey } from '../api/enums';
import { canDeployTo, firstServerName, listenAddrs, webServerState, serverNames, type DeployBlock } from '../api/webServer';
import type { CertificateLocation, Target } from '../api/types';
import { useAuth } from '../auth/AuthProvider';
import { formatDateTime } from '../datetime';
import { DeployDialog } from './DeployDialog';
import { ErrorAlert } from './ErrorAlert';
import { Expiry } from './Expiry';
import { InternalLink } from './InternalLink';
import { LabelledCode } from './LabelledCode';
import { LocationWarning } from './LocationWarning';
import { LocationSettingsDialog } from './LocationSettingsDialog';
import { reasonTitle } from './JobErrorAlert';
import { siteIsData } from './SiteName';
import { useLocations, websitesAsOf } from './useLocations';
import { useSiteLabel } from './useSiteLabel';
import { softwareName } from './software';
import { EmptyState, Panel, StatusBadge } from './ui';
import { WRAP } from './wrap';

const BLOCK_KEYS: Record<DeployBlock, string> = {
  status: 'locations.unavailable.status',
  profile_missing: 'locations.unavailable.profile_missing',
  server_not_found: 'locations.unavailable.server_not_found',
  config_invalid: 'locations.unavailable.config_invalid',
  last_error: 'locations.unavailable.last_error',
  discovery_failed: 'locations.unavailable.last_error',
};

// RowButton is a button whose accessible name carries the website ("Deploy certificate: name").
// The name text is data, so it sits in a hidden translate="no" element the button points at.
function RowButton({ id, label, data, children, ...rest }: { id: string; label: string; data: boolean; children: string; onClick: () => void; disabled?: boolean; variant?: string }) {
  return (
    <>
      <span id={id} hidden translate={data ? 'no' : undefined}>
        {label}
      </span>
      <Button size="xs" variant="light" aria-labelledby={id} {...rest}>
        {children}
      </Button>
    </>
  );
}

// WebsitesPanel lists the certificate files an Nginx server uses ("websites"), from the last
// successful scan. Discover (on the server's page, next to Test connection) refreshes them. When
// the facts are stale (the server is not reachable, the Nginx permissions are missing, Nginx is not
// found, its configuration is invalid, or the last scan failed) the list says so with the time of
// the last good scan and Deploy is disabled with the reason.
export function WebsitesPanel({ target, discoveryFailed = false }: { target: Target; discoveryFailed?: boolean }) {
  const { t, i18n } = useTranslation();
  const { session } = useAuth();
  const role = session?.user.role;
  const canDeploy = role === 'admin' || role === 'operator';
  const admin = role === 'admin';
  const siteLabel = useSiteLabel();
  const [showMissing, setShowMissing] = useState(false);
  const [deploying, setDeploying] = useState<CertificateLocation | null>(null);
  const [settingsId, setSettingsId] = useState<string | null>(null);

  const locs = useLocations(target.id, showMissing);
  const state = webServerState(target, discoveryFailed);
  const software = softwareName(t, target.type);
  const webServer = target.facts.web_server;
  const items = locs.data?.items ?? [];
  const settingsFor = items.find((l) => l.id === settingsId) ?? null;
  const asOf = websitesAsOf(items);
  const lastScan = asOf ? formatDateTime(asOf, i18n.language) : '';

  return (
    <Panel title={t('locations.title')} description={t('locations.intro', { software })} aria-label={t('locations.title')} padded={false}>
      <Stack gap="sm" px={22} py="md">
        {state.configInvalid && (
          <Alert color="red" role="alert" data-testid="config-invalid">
            <Stack gap={2}>
              <Text size="sm" fw={500}>
                {t('locations.configInvalid', { software })}
              </Text>
              {webServer && webServer.config_error !== '' && <Text size="sm">{t(configErrorKey(webServer.config_error))}</Text>}
              {webServer && webServer.config_error_reason !== '' && <Text size="sm">{t(configReasonKey(webServer.config_error_reason))}</Text>}
              {webServer && webServer.config_error_file !== '' && (
                <LabelledCode text={t('locations.configFile', { file: '' })} value={webServer.config_error_file} />
              )}
            </Stack>
          </Alert>
        )}
        {state.stale && (
          <Alert color="yellow" role="status" title={t('locations.stale.title')} data-testid="stale-websites">
            <Stack gap={2}>
              <Text size="sm">{lastScan ? t('locations.stale.help', { time: lastScan }) : t('locations.stale.neverScanned')}</Text>
              <Text size="sm" fw={500}>
                {t('locations.deployUnavailable')}
              </Text>
              {state.block && (
                <Text size="sm">
                  {state.block === 'last_error' && target.last_error ? reasonTitle(t, i18n, target.last_error.reason) : t(BLOCK_KEYS[state.block], { software })}
                </Text>
              )}
            </Stack>
          </Alert>
        )}

        <Switch label={t('locations.showMissing')} checked={showMissing} onChange={(e) => setShowMissing(e.currentTarget.checked)} />
        <ErrorAlert error={locs.error} />
        {locs.data?.truncated && (
          <Alert color="yellow" role="status">
            {t('locations.truncated')}
          </Alert>
        )}
      </Stack>
      {locs.isSuccess && items.length === 0 && <EmptyState icon="Globe" title={t('locations.empty')} />}
      {items.length > 0 && (
        <Table.ScrollContainer minWidth={960}>
          <Table aria-label={t('locations.tableLabel')} highlightOnHover>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>{t('locations.columns.website')}</Table.Th>
                <Table.Th>{t('locations.columns.port')}</Table.Th>
                <Table.Th>{t('locations.columns.file')}</Table.Th>
                <Table.Th>{t('locations.columns.certificate')}</Table.Th>
                <Table.Th>{t('locations.columns.expires')}</Table.Th>
                <Table.Th>{t('locations.columns.state')}</Table.Th>
                <Table.Th>{t('locations.columns.actions')}</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {items.map((l) => (
                <LocationRow
                  key={l.id}
                  l={l}
                  site={siteLabel(l)}
                  blocked={state.block !== null}
                  canDeploy={canDeploy}
                  onDeploy={() => setDeploying(l)}
                  onSettings={() => setSettingsId(l.id)}
                />
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      )}

      {deploying && <DeployDialog opened onClose={() => setDeploying(null)} location={deploying} />}
      {settingsFor && <LocationSettingsDialog location={settingsFor} canEdit={admin} onClose={() => setSettingsId(null)} />}
    </Panel>
  );
}

function LocationRow({
  l,
  site,
  blocked,
  canDeploy,
  onDeploy,
  onSettings,
}: {
  l: CertificateLocation;
  site: string;
  blocked: boolean;
  canDeploy: boolean;
  onDeploy: () => void;
  onSettings: () => void;
}) {
  const { t, i18n } = useTranslation();
  const missing = l.missing_since !== null;
  const names = serverNames(l);
  const first = l.servers[0];
  const cert = l.certificate;
  const problems = l.unsupported_reason === 'file_problem' ? [l.problem, l.key_problem].filter((p) => p !== '') : [];
  return (
    <Table.Tr data-testid="location-row" data-location={l.id}>
      <Table.Td style={WRAP}>
        <Stack gap={2}>
          {names.length === 0 ? (
            <Text size="sm">{t('locations.noWebsite')}</Text>
          ) : (
            <Group gap={4}>
              {names.map((n) =>
                n === '_' ? (
                  <Text key={n} size="sm" span>
                    {t('locations.defaultServer')}
                  </Text>
                ) : (
                  <Code key={n} translate="no">
                    {n}
                  </Code>
                ),
              )}
            </Group>
          )}
          {first && (
            <Stack gap={0}>
              <LabelledCode size="xs" text={t('locations.definedIn', { file: '' })} value={first.file} />
              <Text size="xs" c="dimmed">
                {t('locations.definedLine', { line: first.line })}
              </Text>
            </Stack>
          )}
          {l.inherited && <Text size="xs">{t('locations.inherited')}</Text>}
        </Stack>
      </Table.Td>
      <Table.Td>
        <Stack gap={2}>
          {listenAddrs(l).map((a) => (
            <Code key={a} translate="no">
              {a}
            </Code>
          ))}
        </Stack>
      </Table.Td>
      <Table.Td>
        <Code translate="no" style={WRAP}>
          {l.cert_path}
        </Code>
      </Table.Td>
      <Table.Td style={WRAP}>
        {cert ? (
          <InternalLink to={`/certificates/${cert.id}`} translate="no">
            {cert.label || cert.subject_cn}
          </InternalLink>
        ) : (
          <Text size="sm">{t('locations.noCertificate')}</Text>
        )}
      </Table.Td>
      <Table.Td>{cert ? <Expiry notAfter={cert.not_after} /> : null}</Table.Td>
      <Table.Td>
        <Stack gap={4}>
          <Group gap={4}>
            {missing ? (
              <StatusBadge tone="neutral" size="sm">
                {t('locations.missing')}
              </StatusBadge>
            ) : l.supported ? (
              <StatusBadge tone="success" icon="CircleCheck" size="sm">
                {t('locations.ready')}
              </StatusBadge>
            ) : (
              <StatusBadge tone="neutral" size="sm">
                {t('locations.notSupported')}
              </StatusBadge>
            )}
            {l.active_deployment_id !== null && (
              <StatusBadge tone="info" icon="RefreshCw" size="sm">
                {t('locations.deploying')}
              </StatusBadge>
            )}
          </Group>
          {missing && <Text size="xs">{t('locations.missingSince', { time: formatDateTime(l.missing_since, i18n.language) })}</Text>}
          {!l.supported && <Text size="xs">{t(unsupportedReasonKey(l.unsupported_reason))}</Text>}
          {problems.map((p, i) => (
            <Text size="xs" key={`${p}-${i}`}>
              {t(i === 0 ? 'locations.problemCertificate' : 'locations.problemKey', { problem: t(fileProblemKey(p)) })}
            </Text>
          ))}
          {l.changed_outside_at && (
            <Box>
              <Text size="xs" fw={500}>
                {t('locations.changedOutside')}
              </Text>
              <Text size="xs">{t('locations.changedOutsideAt', { time: formatDateTime(l.changed_outside_at, i18n.language) })}</Text>
            </Box>
          )}
          {l.warnings.map((w) => (
            <LocationWarning key={w} code={w} mode={l.key_mode} site={firstServerName(l) || site} />
          ))}
        </Stack>
      </Table.Td>
      <Table.Td>
        <Group gap="xs">
          {canDeploy && canDeployTo(l) && (
            <RowButton id={`deploy-${l.id}`} data={siteIsData(l)} label={t('locations.deployNamed', { site })} onClick={onDeploy} disabled={blocked}>
              {t('locations.deploy')}
            </RowButton>
          )}
          <RowButton id={`settings-${l.id}`} data={siteIsData(l)} label={t('locations.settingsNamed', { site })} variant="default" onClick={onSettings}>
            {t('locations.settings')}
          </RowButton>
        </Group>
      </Table.Td>
    </Table.Tr>
  );
}
