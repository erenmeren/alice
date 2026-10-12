import { screen, within } from '@testing-library/react';
import { sessionFor, sessionHandlers } from '../test/fixtures';
import { expectNoRawKeys } from '../test/i18nAssert';
import { renderRoute } from '../test/render';
import { server } from '../test/server';

describe('NotFoundPage', () => {
  it('has one h1, the text and the way home, in the form side of the sign-in layout without the brand', async () => {
    server.use(...sessionHandlers(sessionFor('admin')));
    await renderRoute('/no-such-page');
    const main = await screen.findByRole('main');
    expect(within(main).getByRole('heading', { level: 1, name: 'Page not found' })).toBeInTheDocument();
    expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
    expect(screen.getByText('The address may be mistyped, or the page was moved.')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Go to the home page' })).toHaveAttribute('href', '/');
    expect(screen.queryByRole('complementary')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Switch color mode' })).toBeInTheDocument();
    expect(screen.getAllByRole('main')).toHaveLength(1);
    expectNoRawKeys();
  });

  it('is shown in Turkish', async () => {
    await renderRoute('/no-such-page', { languages: ['tr-TR'] });
    expect(await screen.findByRole('heading', { level: 1, name: 'Sayfa bulunamadı' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Ana sayfaya dön' })).toBeInTheDocument();
  });
});
