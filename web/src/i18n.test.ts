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

describe('locale fallback (AUD-25 d)', () => {
  beforeEach(() => localStorage.clear());

  const failing = () => Promise.reject(new Error('chunk failed to load'));

  it('falls back to English when the Turkish texts cannot be loaded at start', async () => {
    localStorage.setItem('alice.lang', 'tr');
    const i18n = await createI18n(['tr-TR'], { load: failing });
    expect(i18n.language).toBe('en');
    expect(i18n.t('nav.home')).toBe('Home');
    expect(document.documentElement.lang).toBe('en');
  });

  it('ignores unknown, empty and malformed stored and browser languages', async () => {
    for (const stored of ['xx', '', 'tr-TR', '../tr', 'TR ']) {
      localStorage.setItem('alice.lang', stored);
      const i18n = await createI18n(['*', '', 'zz-ZZ', 'de']);
      expect(i18n.language, JSON.stringify(stored)).toBe('en');
    }
  });

  it('keeps the current language when a language switch cannot load its texts', async () => {
    const i18n = await createI18n(['en-US']);
    await expect(setLanguage(i18n, 'tr', { load: failing })).rejects.toThrow('chunk failed to load');
    expect(i18n.language).toBe('en');
    expect(localStorage.getItem('alice.lang')).toBeNull();
  });

  it('falls back to English for a key missing in Turkish', async () => {
    const i18n = await createI18n(['tr-TR'], {
      load: async () => ({ web: { nav: { home: 'Ana sayfa' } }, common: {} }),
    });
    expect(i18n.language).toBe('tr');
    expect(i18n.t('nav.home')).toBe('Ana sayfa');
    expect(i18n.t('nav.servers')).toBe('Servers');
  });

  it('never renders the raw key of a text missing everywhere in a production build', async () => {
    const i18n = await createI18n(['en-US'], { hideMissingKeys: true });
    expect(i18n.t('nav.noSuchText')).toBe('');
    expect(i18n.t('nav.home')).toBe('Home');
    expect(i18n.exists('nav.noSuchText')).toBe(false);
  });

  it('keeps raw keys visible in development and tests, so the raw-key checks stay strict', async () => {
    const i18n = await createI18n(['en-US']);
    expect(i18n.t('nav.noSuchText')).toBe('nav.noSuchText');
  });
});
