import type { TFunction } from 'i18next';

// softwareName is the display name of the software a server type runs (the {{software}} of shared texts).
export function softwareName(t: TFunction, type: string): string {
  return t(`webServer.software.${type}`);
}
