import { createI18n } from '../i18n';
import { DIRECTORY_PRESETS, directorySignInReason } from './ldap';
import { LDAP_DIRECTORIES_KEY, ldapMappingsKey, PUBLIC_DIRECTORIES_KEY } from './queryKeys';

describe('directory sign-in texts', () => {
  it('turns every 401 into the one generic refusal and a 503 into "cannot be used"; anything else is shown as it is', () => {
    expect(directorySignInReason(401)).toBe('ldap.signin_refused');
    expect(directorySignInReason(503)).toBe('ldap.directory_unavailable');
    for (const status of [400, 403, 422, 429, 500]) expect(directorySignInReason(status)).toBeNull();
  });

  it.each(['en-US', 'tr-TR'])('has a title and an action for both sign-in reasons and the step-up enrolment (%s)', async (lang) => {
    const i18n = await createI18n([lang]);
    for (const r of ['ldap.signin_refused', 'ldap.directory_unavailable', 'ldap.enrolment_required']) {
      expect(i18n.exists(`errors.${r}.title`), r).toBe(true);
      expect(i18n.exists(`errors.${r}.action`), r).toBe(true);
    }
  });
});

describe('directory presets', () => {
  it('fill the attribute and filter fields only, with the placeholders the server accepts', () => {
    for (const p of Object.values(DIRECTORY_PRESETS)) {
      expect(Object.keys(p).sort()).toEqual(['display_name_attribute', 'email_attribute', 'group_filter', 'group_name_attribute', 'login_attribute', 'unique_id_attribute', 'user_filter']);
      expect(p.user_filter.split('{login}')).toHaveLength(2);
      expect(p.group_filter).toContain('{dn}');
    }
    expect(DIRECTORY_PRESETS.ad.group_filter).toContain('1.2.840.113556.1.4.1941');
  });
});

describe('directory query keys', () => {
  it('keep the admin list, the public list and each directory\'s mappings apart', () => {
    expect(LDAP_DIRECTORIES_KEY).not.toEqual(PUBLIC_DIRECTORIES_KEY);
    expect(ldapMappingsKey('a')).not.toEqual(ldapMappingsKey('b'));
  });
});
