import type { i18n as I18n, TFunction } from 'i18next';
import type { RevocationCheck } from '../api/types';
import { formatDateTime } from '../datetime';
import { reasonTitle } from './JobErrorAlert';

// methodName is how the revocation check's answer is named (OCSP or CRL; "OCSP" when an older answer names none).
export function methodName(method: string | undefined): string {
  return method === 'crl' ? 'CRL' : 'OCSP';
}

// revocationCheckText is the last revocation check of a certificate in words (R64, D5), for an inventory certificate's
// page and a found certificate's drawer (R66); undefined counts as never checked.
export function revocationCheckText(t: TFunction, i18n: I18n, rc: RevocationCheck | null | undefined): string {
  if (!rc) return t('certificates.revocationCheck.status.none');
  const lang = i18n.language;
  const reason = rc.error ? reasonTitle(t, i18n, rc.error.reason, rc.error.params ?? {}) : '';
  return t(`certificates.revocationCheck.status.${rc.status}`, {
    date: formatDateTime(rc.status === 'on_hold' ? rc.revoked_at : rc.checked_at, lang),
    method: methodName(rc.method),
    reason,
    next: formatDateTime(rc.next_check_at, lang),
  });
}
