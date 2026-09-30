import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { errorResponse, freshStatus, sessionFor, sessionHandlers } from './test/fixtures';
import { renderRoute } from './test/render';
import { server } from './test/server';

function navLabels(): string[] {
  const nav = screen.getByRole('navigation');
  return within(nav)
    .getAllByRole('link')
    .map((a) => a.textContent ?? '');
}

describe('application shell', () => {
  it('sends a fresh install to the setup wizard', async () => {
    server.use(...sessionHandlers(null, freshStatus));
    const { router } = await renderRoute('/');
    await waitFor(() => expect(router.state.location.pathname).toBe('/setup'));
    expect(await screen.findByRole('heading', { name: 'Set up Alice' })).toBeInTheDocument();
  });

  it('sends a signed-out visitor to the sign-in page', async () => {
    const { router } = await renderRoute('/');
    await waitFor(() => expect(router.state.location.pathname).toBe('/login'));
    expect(await screen.findByRole('heading', { name: 'Sign in to Alice' })).toBeInTheDocument();
  });

  it('shows the admin home page with the server version and the full navigation', async () => {
    server.use(...sessionHandlers(sessionFor('admin')));
    await renderRoute('/');
    expect(await screen.findByRole('heading', { name: 'Welcome, Ayşe Yılmaz' })).toBeInTheDocument();
    await waitFor(() => expect(screen.getByTestId('server-status')).toHaveTextContent('Server version: 1.2.3'));
    expect(navLabels()).toEqual(['Home', 'Users', 'Audit log', 'API tokens', 'My account']);
  });

  it('hides Users and Audit log from operators', async () => {
    server.use(...sessionHandlers(sessionFor('operator')));
    await renderRoute('/');
    await screen.findByRole('heading', { name: 'Welcome, Olcay Öztürk' });
    expect(navLabels()).toEqual(['Home', 'API tokens', 'My account']);
  });

  it('shows the audit log but not Users to auditors, in Turkish', async () => {
    server.use(...sessionHandlers(sessionFor('auditor', 'tr')));
    await renderRoute('/', { languages: ['tr-TR'] });
    expect(await screen.findByRole('heading', { name: 'Hoş geldiniz, Ilgın Işık' })).toBeInTheDocument();
    expect(navLabels()).toEqual(['Ana sayfa', 'Denetim kaydı', 'API anahtarları', 'Hesabım']);
    expect(document.documentElement.lang).toBe('tr');
  });

  it('switches to the language saved on the account after sign-in', async () => {
    server.use(...sessionHandlers(sessionFor('admin', 'tr')));
    await renderRoute('/');
    expect(await screen.findByRole('heading', { name: 'Hoş geldiniz, Ayşe Yılmaz' })).toBeInTheDocument();
  });

  it('saves a language change on the account when signed in', async () => {
    let saved = '';
    server.use(
      ...sessionHandlers(sessionFor('admin')),
      http.put('/api/v1/auth/locale', async ({ request }) => {
        saved = ((await request.json()) as { locale: string }).locale;
        return new HttpResponse(null, { status: 204 });
      }),
    );
    await renderRoute('/');
    await screen.findByRole('heading', { name: 'Welcome, Ayşe Yılmaz' });
    await userEvent.click(screen.getByText('Türkçe'));
    expect(await screen.findByRole('heading', { name: 'Hoş geldiniz, Ayşe Yılmaz' })).toBeInTheDocument();
    await waitFor(() => expect(saved).toBe('tr'));
    expect(localStorage.getItem('alice.lang')).toBe('tr');
  });

  it('shows the setup banner to an admin until the recovery passphrase is set', async () => {
    server.use(
      ...sessionHandlers(sessionFor('admin'), {
        admin_exists: true,
        recovery_passphrase_set: false,
        completed: false,
        default_locale: 'en',
      }),
    );
    await renderRoute('/');
    expect(await screen.findByTestId('setup-banner')).toHaveTextContent(
      'Finish setting up: choose a recovery passphrase.',
    );
  });

  it('does not show the setup banner to operators', async () => {
    server.use(
      ...sessionHandlers(sessionFor('operator'), {
        admin_exists: true,
        recovery_passphrase_set: false,
        completed: false,
        default_locale: 'en',
      }),
    );
    await renderRoute('/');
    await screen.findByRole('heading', { name: 'Welcome, Olcay Öztürk' });
    expect(screen.queryByTestId('setup-banner')).not.toBeInTheDocument();
  });

  it('returns to the sign-in page with a notice when the session ends', async () => {
    server.use(
      ...sessionHandlers(sessionFor('admin')),
      http.get('/api/v1/version', () => errorResponse(401, 'ALC-AUTH-0001', 'auth.unauthenticated')),
    );
    const { router } = await renderRoute('/');
    await waitFor(() => expect(router.state.location.pathname).toBe('/login'));
    expect(router.state.location.search).toBe('?ended=1');
    expect(await screen.findByText('Your session ended. Please sign in again.')).toBeInTheDocument();
  });

  it('signs out', async () => {
    let loggedOut = false;
    server.use(
      ...sessionHandlers(sessionFor('admin')),
      http.post('/api/v1/auth/logout', () => {
        loggedOut = true;
        return new HttpResponse(null, { status: 204 });
      }),
    );
    const { router } = await renderRoute('/');
    await userEvent.click(await screen.findByRole('button', { name: 'Sign out' }));
    await waitFor(() => expect(router.state.location.pathname).toBe('/login'));
    expect(loggedOut).toBe(true);
  });

  it('shows a not-found page for unknown addresses, including ones with a dot', async () => {
    await renderRoute('/no/such.page');
    expect(await screen.findByRole('heading', { name: 'Page not found' })).toBeInTheDocument();
  });
});
