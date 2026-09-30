import { screen, waitFor } from '@testing-library/react';
import { sessionHandlers } from './test/fixtures';
import { expectNoRawKeys } from './test/i18nAssert';
import { renderRoute } from './test/render';
import { SCREENS } from './test/screens';
import { server } from './test/server';

describe.each(['en', 'tr'] as const)('every screen in %s', (lang) => {
  it.each(SCREENS.map((s) => [s.path, s] as const))('%s has no untranslated keys', async (_path, s) => {
    const session = s.session ? { ...s.session, user: { ...s.session.user, locale: lang } } : null;
    server.use(...sessionHandlers(session, s.status));
    await renderRoute(s.path, { languages: [lang] });
    await waitFor(() => expect(screen.getAllByText(s.ready[lang]).length).toBeGreaterThan(0));
    expectNoRawKeys();
  });
});
