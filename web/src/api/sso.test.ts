import { createI18n } from '../i18n';
import { SSO_ERROR_REASONS, ssoErrorReason } from './sso';

describe('SSO error reasons', () => {
  it.each(['en-US', 'tr-TR'])('every reason has a title and an action text (%s)', async (lang) => {
    const i18n = await createI18n([lang]);
    for (const r of SSO_ERROR_REASONS) {
      expect(i18n.exists(`errors.${r}.title`), r).toBe(true);
      expect(i18n.exists(`errors.${r}.action`), r).toBe(true);
    }
  });

  it('accepts only the closed set', () => {
    expect(ssoErrorReason('sso.no_access')).toBe('sso.no_access');
    expect(ssoErrorReason('sso.nope')).toBeNull();
    expect(ssoErrorReason(null)).toBeNull();
  });
});
