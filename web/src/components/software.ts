import type { TFunction } from 'i18next';
import { isWebServer } from '../api/webServer';

// softwareName is the display name of the software a web server type runs (the {{software}} of shared
// texts); '' for a type that is not a web server (a Linux server has no such software).
export function softwareName(t: TFunction, type: string): string {
  return isWebServer(type) ? t(`webServer.software.${type}`) : '';
}

// siteColumnLabel is the heading of the column that names a website: the software's own word for it
// (HAProxy: "Frontend"), "Website" for any software without one.
export function siteColumnLabel(t: TFunction, type: string): string {
  return t(`webServer.siteColumn.${type}`, { defaultValue: t('locations.columns.website') });
}
