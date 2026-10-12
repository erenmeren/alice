import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';
import type { CertificateDetail, CertificateLocation } from '../../api/types';
import { Icon, type IconName } from '../../design/Icon';
import { Panel } from '../ui';
import classes from './UsageTopology.module.css';

// The source tile of a certificate: a vault, a server where Alice found it, or a file (upload or signing request).
export function sourceIcon(source: string): IconName {
  if (source === 'azure_kv') return 'Cloud';
  if (source === 'discovered') return 'Server';
  return 'FileKey2';
}

// siteNames are the website names of one location with the port Nginx listens on ("www.example.test:443"), as Alice
// read them from the server's configuration.
function siteNames(loc: CertificateLocation): string[] {
  return loc.servers.flatMap((s) => s.names.map((n) => (s.listens[0] ? `${n}:${s.listens[0].port}` : n)));
}

interface TargetNode {
  id: string;
  name: string;
  sites: string[];
}

// byTarget groups the certificate's locations by server id (never by name), in the order the API lists them.
function byTarget(locations: CertificateLocation[]): TargetNode[] {
  const nodes = new Map<string, TargetNode>();
  for (const loc of locations) {
    const node = nodes.get(loc.target_id) ?? { id: loc.target_id, name: loc.target_name, sites: [] };
    const sites = siteNames(loc);
    for (const site of sites.length > 0 ? sites : [loc.cert_path]) if (!node.sites.includes(site)) node.sites.push(site);
    nodes.set(loc.target_id, node);
  }
  return [...nodes.values()];
}

// UsageTopology is the design's "Where this certificate is used" view: the source on the left, one node per server on
// the right, each a link to that server. The connections are CertificateDetail.locations (what Alice discovered or
// deployed to); nothing is inferred from names.
export function UsageTopology({ certificate }: { certificate: Pick<CertificateDetail, 'source' | 'label' | 'subject_cn' | 'locations' | 'locations_truncated'> }) {
  const { t, i18n } = useTranslation();
  const sourceKey = `enum.certificateSource.${certificate.source}`;
  const name = certificate.label || certificate.subject_cn || t('certificates.noName');
  const targets = byTarget(certificate.locations);
  const listLabel = t('certificates.page.locations');
  return (
    <Panel
      title={t('certificates.page.usedTitle')}
      description={t('certificates.page.usedSub')}
      padded={false}
      footer={
        <>
          <span>{t('certificates.page.topologyNote')}</span>
          {certificate.locations_truncated && <span>{t('certificates.page.truncated')}</span>}
        </>
      }
    >
      <div className={classes.topology}>
        <div className={classes.flow}>
          <div>
            <p className={classes.label}>{t('certificates.page.source')}</p>
            <div className={`${classes.node} ${classes.center}`} data-testid="usage-source">
              <span className={classes.icon} data-icon={sourceIcon(certificate.source)}>
                <Icon name={sourceIcon(certificate.source)} size={16} />
              </span>
              <div className={classes.text}>
                <strong>{i18n.exists(sourceKey) ? t(sourceKey) : certificate.source}</strong>
                <p translate="no">{name}</p>
              </div>
            </div>
          </div>
          <div className={classes.connector} aria-hidden="true" />
          <div>
            <p className={classes.label} aria-hidden="true">
              {listLabel}
            </p>
            {targets.length === 0 ? (
              <p className={classes.none}>{t('certificates.detail.notUsed')}</p>
            ) : (
              <ul className={classes.targets} role="list" aria-label={listLabel}>
                {targets.map((n) => (
                  <li key={n.id}>
                    <Link to={`/servers/${n.id}`} className={classes.node} data-node="usage">
                      <span className={classes.icon}>
                        <Icon name="Server" size={16} />
                      </span>
                      <span className={classes.text}>
                        <strong translate="no">{n.name}</strong>
                        <span className={classes.sites} translate="no">
                          {n.sites.join(', ')}
                        </span>
                      </span>
                      <Icon name="ArrowUpRight" size={14} className={classes.arrow} />
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      </div>
    </Panel>
  );
}
