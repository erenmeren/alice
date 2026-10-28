import { useTranslation } from 'react-i18next';
import { firstServerName } from '../api/webServer';
import type { CertificateLocation } from '../api/types';

// siteIsData: the website's name is a server name from the configuration (data), not one of the
// translated stand-ins "(default server)" and "(no server name)".
export const siteIsData = (loc: CertificateLocation): boolean => {
  const n = firstServerName(loc);
  return n !== '' && n !== '_';
};

// SiteName shows a website's name: a server name in a no-translate element, the stand-ins as
// ordinary translated text; the Remote Desktop listener (R69) its translated name.
export function SiteName({ loc }: { loc: CertificateLocation }) {
  const { t } = useTranslation();
  if (loc.kind === 'win_rdp') return <span>{t('locations.rdp.name')}</span>;
  if (siteIsData(loc)) return <span translate="no">{firstServerName(loc)}</span>;
  return <span>{t(firstServerName(loc) === '_' ? 'locations.defaultServer' : 'locations.noWebsite')}</span>;
}
