import { renderHook } from '@testing-library/react';
import { I18nextProvider } from 'react-i18next';
import { createInstance } from 'i18next';
import type { ReactNode } from 'react';
import en from '../locales/en.json';
import { locationFixture } from '../test/fixtures';
import { useSiteLabel } from './useSiteLabel';

async function label(servers: Array<{ names: string[]; section?: string }>) {
  const i18n = createInstance();
  await i18n.init({ lng: 'en', resources: { en: { translation: en } } });
  const wrapper = ({ children }: { children: ReactNode }) => <I18nextProvider i18n={i18n}>{children}</I18nextProvider>;
  const { result } = renderHook(() => useSiteLabel(), { wrapper });
  return result.current(locationFixture({ servers: servers.map((s) => ({ ...s, listens: [], file: 'f', line: 1 })) }));
}

describe('useSiteLabel', () => {
  it('names a website by its first server name, then by its frontend, then "(no server name)"', async () => {
    expect(await label([{ names: ['a.example.test'], section: 'fe' }])).toBe('a.example.test');
    expect(await label([{ names: ['_'] }])).toBe('(default server)');
    expect(await label([{ names: [] }, { names: [], section: 'fe_https' }])).toBe('fe_https');
    expect(await label([{ names: [] }])).toBe('(no server name)');
  });
});
