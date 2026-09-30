import { screen, waitFor } from '@testing-library/react';
import type { SessionInfo, SetupStatus } from './api/types';
import { freshStatus, installedStatus, sessionFor, sessionHandlers } from './test/fixtures';
import { expectNoRawKeys } from './test/i18nAssert';
import { renderRoute } from './test/render';
import { server } from './test/server';

interface Screen {
  path: string;
  session: SessionInfo | null;
  status: SetupStatus;
  // text proves the screen finished loading; a function of the language
  ready: { en: string; tr: string };
}

// SCREENS lists every routed screen. Later tasks append their pages here.
export const SCREENS: Screen[] = [
  { path: '/', session: sessionFor('admin'), status: installedStatus, ready: { en: 'Home', tr: 'Ana sayfa' } },
  { path: '/login', session: null, status: installedStatus, ready: { en: 'Sign in to Alice', tr: "Alice'e giriş yapın" } },
  { path: '/setup', session: null, status: freshStatus, ready: { en: 'Set up Alice', tr: 'Alice kurulumu' } },
  { path: '/missing', session: null, status: installedStatus, ready: { en: 'Page not found', tr: 'Sayfa bulunamadı' } },
];

describe.each(['en', 'tr'] as const)('every screen in %s', (lang) => {
  it.each(SCREENS.map((s) => [s.path, s] as const))('%s has no untranslated keys', async (_path, s) => {
    const session = s.session ? { ...s.session, user: { ...s.session.user, locale: lang } } : null;
    server.use(...sessionHandlers(session, s.status));
    await renderRoute(s.path, { languages: [lang] });
    await waitFor(() => expect(screen.getAllByText(s.ready[lang]).length).toBeGreaterThan(0));
    expectNoRawKeys();
  });
});
