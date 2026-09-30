import { createI18n, pickLanguage, setLanguage } from './i18n';

describe('pickLanguage', () => {
  beforeEach(() => localStorage.clear());

  it('uses a stored supported language first', () => {
    expect(pickLanguage('tr', ['en-US'])).toBe('tr');
  });
  it('ignores an unsupported stored value', () => {
    expect(pickLanguage('xx', ['tr-TR'])).toBe('tr');
  });
  it('matches the browser language by its base code', () => {
    expect(pickLanguage(null, ['de-DE', 'tr-TR'])).toBe('tr');
    expect(pickLanguage(null, ['TR'])).toBe('tr');
  });
  it('falls back to English', () => {
    expect(pickLanguage(null, ['de-DE'])).toBe('en');
    expect(pickLanguage(null, [])).toBe('en');
  });
});

describe('lazy locale loading', () => {
  beforeEach(() => localStorage.clear());

  it('loads Turkish only when it is selected', async () => {
    const i18n = await createI18n(['en-US']);
    expect(i18n.hasResourceBundle('en', 'web')).toBe(true);
    expect(i18n.hasResourceBundle('tr', 'web')).toBe(false);

    await setLanguage(i18n, 'tr');
    expect(i18n.hasResourceBundle('tr', 'web')).toBe(true);
    expect(i18n.hasResourceBundle('tr', 'common')).toBe(true);
    expect(i18n.t('nav.home')).toBe('Ana sayfa');
    expect(document.documentElement.lang).toBe('tr');
  });

  it('loads the browser language at start and keeps English as fallback', async () => {
    const i18n = await createI18n(['tr-TR']);
    expect(i18n.language).toBe('tr');
    expect(i18n.hasResourceBundle('tr', 'web')).toBe(true);
    expect(i18n.hasResourceBundle('en', 'web')).toBe(true);
  });
});
