import { useTranslation } from 'react-i18next';
import { firstServerName } from '../api/nginx';
import type { CertificateLocation } from '../api/types';

// siteIsData: the website's name is a server name from the configuration (data), not one of the
// translated stand-ins "(default server)" and "(no server name)".
export const siteIsData = (loc: CertificateLocation): boolean => {
  const n = firstServerName(loc);
  return n !== '' && n !== '_';
};

// SiteName shows a website's name: a server name in a no-translate element, the stand-ins as
// ordinary translated text.
export function SiteName({ loc }: { loc: CertificateLocation }) {
  const { t } = useTranslation();
  if (siteIsData(loc)) return <span translate="no">{firstServerName(loc)}</span>;
  return <span>{t(firstServerName(loc) === '_' ? 'locations.defaultServer' : 'locations.noWebsite')}</span>;
}
