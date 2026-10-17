import { useTranslation } from 'react-i18next';
import { firstServerName } from '../api/webServer';
import type { CertificateLocation } from '../api/types';

// useSiteLabel returns a function that names a website: its first server name, "(default server)"
// for the catch-all "_" and the name of its first frontend (HAProxy) or "(no server name)" when it has none.
export function useSiteLabel() {
  const { t } = useTranslation();
  return (loc: CertificateLocation): string => {
    const name = firstServerName(loc);
    if (name === '') return loc.servers.find((s) => s.section)?.section || t('locations.noWebsite');
    return name === '_' ? t('locations.defaultServer') : name;
  };
}
