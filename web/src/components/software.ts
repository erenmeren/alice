import type { TFunction } from 'i18next';
import { isWebServer } from '../api/webServer';

// softwareName is the display name of the software a web server type runs (the {{software}} of shared
// texts); '' for a type that is not a web server (a Linux server has no such software).
export function softwareName(t: TFunction, type: string): string {
  return isWebServer(type) ? t(`webServer.software.${type}`) : '';
}
