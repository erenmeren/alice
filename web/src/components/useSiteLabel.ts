import { useTranslation } from 'react-i18next';
import { firstServerName } from '../api/webServer';
import type { CertificateLocation } from '../api/types';

// useSiteLabel returns a function that names a website: its first server name, "(default server)"
// for the catch-all "_" and "(no server name)" when it has none.
export function useSiteLabel() {
  const { t } = useTranslation();
  return (loc: CertificateLocation): string => {
    const name = firstServerName(loc);
    return name === '' ? t('locations.noWebsite') : name === '_' ? t('locations.defaultServer') : name;
  };
}
