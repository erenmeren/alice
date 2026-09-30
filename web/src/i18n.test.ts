import { pickLanguage } from './i18n';

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
