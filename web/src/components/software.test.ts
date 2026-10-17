import { createInstance } from 'i18next';
import en from '../locales/en.json';
import { softwareName } from './software';

describe('softwareName', () => {
  it('names the software of a web server type', async () => {
    const i18n = createInstance();
    await i18n.init({ lng: 'en', resources: { en: { translation: { webServer: { software: { nginx: 'Nginx' } } } } } });
    expect(softwareName(i18n.t, 'nginx')).toBe('Nginx');
  });

  it('names Apache from the real locale', async () => {
    const i18n = createInstance();
    await i18n.init({ lng: 'en', resources: { en: { translation: en } } });
    expect(softwareName(i18n.t, 'apache')).toBe('Apache');
  });

  it('is empty for a type that is not a web server, without a translation lookup', () => {
    const t = vi.fn();
    expect(softwareName(t as never, 'linux')).toBe('');
    expect(t).not.toHaveBeenCalled();
  });
});
