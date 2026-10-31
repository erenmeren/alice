import type { TFunction } from 'i18next';
import type { CertificateLocation } from '../api/types';

// APPLICATION_NAMES are the proper names of the applications the helper's table knows (details.application); they
// are names, not words, so they are the same in every language.
const APPLICATION_NAMES: Record<string, string> = { iis: 'IIS', iisexpress: 'IIS Express', winrm: 'WinRM', sstp: 'SSTP' };

// foreignAppText words a Windows binding that belongs to another application: it names the application
// (details.application from the helper's table: iis, iisexpress, winrm, sstp), or shows the raw application id when
// Alice does not know it (AD FS, for one); iis_unused is an IIS binding no site uses. null for any other reason. The
// deploy dialog's picker shows the same sentence (C4, R70).
export function foreignAppText(t: TFunction, l: CertificateLocation): string | null {
  if (l.unsupported_reason !== 'win_foreign_app') return null;
  const application = typeof l.details?.application === 'string' ? l.details.application : '';
  const appId = typeof l.details?.app_id === 'string' ? l.details.app_id : '';
  if (application === 'iis_unused') return t('locations.unsupported.win_foreign_app_iis_unused');
  return application !== ''
    ? t('locations.unsupported.win_foreign_app', { application: APPLICATION_NAMES[application] ?? application })
    : t('locations.unsupported.win_foreign_app_unknown', { app_id: appId });
}
