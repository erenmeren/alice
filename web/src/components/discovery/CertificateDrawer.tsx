import { Anchor, Button, Code, Drawer, Stack, Text } from '@mantine/core';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';
import { endpointAddress, endpointErrorKey, endpointStateKey, getDiscoveredCertificate, statusKey, type DiscoveredCertificate, type DiscoveredEndpoint } from '../../api/discovery';
import { keyAlgorithmKey } from '../../api/enums';
import { discoveredCertificateKey } from '../../api/queryKeys';
import { formatDateTime } from '../../datetime';
import { Icon } from '../../design/Icon';
import { CodeText } from '../CodeText';
import { ErrorAlert } from '../ErrorAlert';
import { Expiry } from '../Expiry';
import { LoadingIndicator } from '../LoadingIndicator';
import { FactList, StatusBadge } from '../ui';
import { WRAP } from '../wrap';
import classes from './discovery.module.css';
import { endpointIcon, endpointTone, GoneChip, StatusChip, useDiscoveryRole } from './shared';

// The host a server would be added with: the name the scope listed, else the address.
export const hostOf = (e: Pick<DiscoveredEndpoint, 'host' | 'address'>) => e.host || e.address;

// CertificateDrawer is one certificate found on the network: what it is, what Alice knows of it, and every place
// (address, port and server name) that presents it, with the server in Alice it belongs to. An Administrator can add a
// place that is not a server in Alice yet through the usual Add server dialog (the license decides there).
export function CertificateDrawer({ fingerprint, name, onClose, onAddServer }: { fingerprint: string | null; name: string; onClose: () => void; onAddServer: (e: DiscoveredEndpoint) => void }) {
  const { t } = useTranslation();
  const detail = useQuery({
    queryKey: discoveredCertificateKey(fingerprint ?? ''),
    queryFn: ({ signal }) => getDiscoveredCertificate(fingerprint ?? '', signal),
    enabled: fingerprint !== null,
  });
  return (
    <Drawer
      opened={fingerprint !== null}
      onClose={onClose}
      position="right"
      size="lg"
      title={name ? <CodeText i18nKey="discovery.drawer.titleNamed" param="name" value={name} /> : t('discovery.drawer.title')}
      closeButtonProps={{ 'aria-label': t('ui.close') }}
      data-testid="discovery-drawer"
    >
      <ErrorAlert error={detail.error} />
      {detail.isPending && fingerprint !== null && <LoadingIndicator />}
      {detail.data && <Detail c={detail.data} onAddServer={onAddServer} />}
    </Drawer>
  );
}

function Detail({ c, onAddServer }: { c: DiscoveredCertificate; onAddServer: (e: DiscoveredEndpoint) => void }) {
  const { t, i18n } = useTranslation();
  const lang = i18n.language;
  const endpoints = c.endpoints ?? [];
  return (
    <Stack gap="lg">
      <Stack gap="xs">
        <div className={classes.chips}>
          <StatusChip status={c.status} />
          {c.expired && (
            <StatusBadge tone="danger" icon="CircleX" size="sm">
              {t('discovery.chips.expired')}
            </StatusBadge>
          )}
          {c.seen_on_count === 0 && <GoneChip />}
          {c.self_signed && (
            <StatusBadge tone="neutral" icon="Fingerprint" size="sm">
              {t('discovery.chips.selfSigned')}
            </StatusBadge>
          )}
        </div>
        <Text size="sm">{t(`discovery.statusText.${c.status}`, { defaultValue: t(statusKey(c.status)) })}</Text>
        {c.status === 'unmanaged' && <Text size="xs" c="dimmed">{t('discovery.unmanagedHelp.text')}</Text>}
        {c.managed_certificate_id && (
          <Anchor component={Link} to={`/certificates/${c.managed_certificate_id}`} size="sm">
            {t('discovery.drawer.openManaged')}
          </Anchor>
        )}
      </Stack>
      <FactList
        label={t('discovery.drawer.facts')}
        facts={[
          { label: t('discovery.drawer.subject'), value: c.subject_cn ? <Code translate="no" style={WRAP}>{c.subject_cn}</Code> : t('discovery.results.noName') },
          {
            label: t('discovery.drawer.names'),
            value:
              c.sans.length > 0 ? (
                <ul className={classes.codeList}>
                  {c.sans.map((n) => (
                    <li key={n}>
                      <Code translate="no">{n}</Code>
                    </li>
                  ))}
                </ul>
              ) : (
                t('discovery.settings.none')
              ),
          },
          { label: t('discovery.drawer.issuer'), value: <span translate="no">{c.issuer_cn || '–'}</span> },
          { label: t('discovery.drawer.validFrom'), value: formatDateTime(c.not_before, lang) },
          { label: t('discovery.drawer.expires'), value: <Expiry notAfter={c.not_after} /> },
          { label: t('discovery.drawer.algorithm'), value: t(keyAlgorithmKey(c.key_algorithm)) },
          { label: t('discovery.drawer.fingerprint'), value: <Code translate="no" style={WRAP}>{c.fingerprint_sha256}</Code> },
          { label: t('discovery.drawer.firstSeen'), value: formatDateTime(c.first_seen, lang) },
          { label: t('discovery.drawer.lastSeen'), value: formatDateTime(c.last_seen, lang) },
        ]}
      />
      <Stack gap="xs">
        <h3 className={classes.section}>{t('discovery.drawer.endpoints')}</h3>
        <p className={classes.help}>{t('discovery.drawer.endpointsHelp')}</p>
        {endpoints.length === 0 && <Text size="sm">{t('discovery.drawer.noEndpoints')}</Text>}
        <ul className={classes.endpointList} aria-label={t('discovery.drawer.endpoints')}>
          {endpoints.map((e) => (
            <EndpointItem key={e.id} e={e} onAddServer={onAddServer} />
          ))}
        </ul>
        {c.more_endpoints && <Text size="xs" c="dimmed">{t('discovery.drawer.moreEndpoints')}</Text>}
      </Stack>
    </Stack>
  );
}

function EndpointItem({ e, onAddServer }: { e: DiscoveredEndpoint; onAddServer: (e: DiscoveredEndpoint) => void }) {
  const { t, i18n } = useTranslation();
  const { admin } = useDiscoveryRole();
  const lang = i18n.language;
  return (
    <li className={classes.endpoint} data-testid="discovery-endpoint">
      <div className={classes.endpointHead}>
        <Code translate="no">{endpointAddress(e)}</Code>
        <StatusBadge tone={endpointTone(e.state)} icon={endpointIcon(e.state)} size="sm" data-state={e.state}>
          {t(endpointStateKey(e.state))}
        </StatusBadge>
      </div>
      <FactList
        facts={[
          ...(e.host ? [{ label: t('discovery.drawer.host'), value: <Code translate="no">{e.host}</Code> }] : []),
          { label: t('discovery.drawer.sni'), value: e.sni ? <Code translate="no">{e.sni}</Code> : t('discovery.drawer.sniNone') },
          ...(e.last_error_code ? [{ label: t('discovery.drawer.lastProblem'), value: t(endpointErrorKey(e.last_error_code)) }] : []),
          { label: t('discovery.drawer.tls'), value: e.tls_version ? <span translate="no">{`${e.tls_version} · ${e.cipher}`}</span> : '–' },
          { label: t('discovery.drawer.firstSeen'), value: formatDateTime(e.first_seen, lang) },
          { label: t('discovery.drawer.lastSeen'), value: e.last_seen ? formatDateTime(e.last_seen, lang) : '–' },
          {
            label: t('discovery.drawer.rotations'),
            value:
              e.previous_fingerprints.length > 0 ? (
                <ul className={classes.codeList}>
                  {e.previous_fingerprints.map((f) => (
                    <li key={f}>
                      <Code translate="no" title={f}>
                        {f.slice(0, 16)}…
                      </Code>
                    </li>
                  ))}
                </ul>
              ) : (
                t('discovery.drawer.rotationsNone')
              ),
          },
          {
            label: t('discovery.drawer.server'),
            value: e.target ? (
              <Anchor component={Link} to={`/servers/${e.target.id}`} translate="no">
                {e.target.name}
              </Anchor>
            ) : (
              t('discovery.drawer.serverNone')
            ),
          },
        ]}
      />
      {!e.target && admin && (
        <Stack gap={4} align="flex-start">
          <Button size="xs" variant="default" leftSection={<Icon name="Plus" size={14} />} aria-label={t('discovery.drawer.addServerLabel', { address: endpointAddress(e) })} onClick={() => onAddServer(e)}>
            {t('discovery.drawer.addServer')}
          </Button>
          <p className={classes.secondary}>{t('discovery.drawer.addServerHelp')}</p>
        </Stack>
      )}
      {!e.target && !admin && <p className={classes.secondary}>{t('discovery.drawer.adminAdds')}</p>}
    </li>
  );
}
