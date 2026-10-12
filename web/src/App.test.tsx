import { act, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { errorResponse, freshStatus, sessionFor, sessionHandlers } from './test/fixtures';
import { renderRoute } from './test/render';
import { server } from './test/server';

function navLabels(): string[] {
  const nav = screen.getByRole('navigation');
  return within(nav)
    .getAllByRole('link')
    .map((a) => a.textContent ?? '')
    .filter((n) => !n.startsWith('Alice')); // the brand link is not a destination
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
    expect(await screen.findByRole('heading', { level: 1, name: 'Overview' })).toBeInTheDocument();
    expect(screen.getByTestId('current-user')).toHaveTextContent(/^Ayşe Yılmaz$/);
    await waitFor(() => expect(screen.getByTestId('server-status')).toHaveTextContent('Server version: 1.2.3'));
    expect(navLabels()).toEqual(['Overview', 'Certificates', 'SSH keys', 'Servers', 'Key Vaults', 'Deployments', 'Key rotations', 'Audit trail', 'People & access', 'Settings', 'License', 'Your account', 'API tokens']);
  });

  it('hides People & access and Audit trail from operators', async () => {
    server.use(...sessionHandlers(sessionFor('operator')));
    await renderRoute('/');
    await screen.findByRole('heading', { level: 1, name: 'Overview' });
    expect(navLabels()).toEqual(['Overview', 'Certificates', 'SSH keys', 'Servers', 'Key Vaults', 'Deployments', 'Key rotations', 'Your account', 'API tokens']);
  });

  it('shows the audit trail but not People & access to auditors, in Turkish', async () => {
    server.use(...sessionHandlers(sessionFor('auditor', 'tr')));
    await renderRoute('/', { languages: ['tr-TR'] });
    expect(await screen.findByRole('heading', { level: 1, name: 'Genel bakış' })).toBeInTheDocument();
    expect(screen.getByTestId('current-user')).toHaveTextContent(/^Ilgın Işık$/);
    expect(navLabels()).toEqual(['Genel bakış', 'Sertifikalar', 'SSH anahtarları', 'Sunucular', 'Key Vault kasaları', 'Dağıtımlar', 'Anahtar rotasyonları', 'Denetim kaydı', 'Lisans', 'Hesabınız', 'API anahtarları']);
    expect(document.documentElement.lang).toBe('tr');
  });

  it('switches to the language saved on the account after sign-in', async () => {
    server.use(...sessionHandlers(sessionFor('admin', 'tr')));
    await renderRoute('/');
    expect(await screen.findByRole('heading', { level: 1, name: 'Genel bakış' })).toBeInTheDocument();
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
    await screen.findByRole('heading', { level: 1, name: 'Overview' });
    await userEvent.click(screen.getByRole('button', { name: 'Türkçe' }));
    expect(await screen.findByRole('heading', { level: 1, name: 'Genel bakış' })).toBeInTheDocument();
    await waitFor(() => expect(saved).toBe('tr'));
    expect(localStorage.getItem('alice.lang')).toBe('tr');
  });

  it('opens and closes the navigation with the menu button and closes it after navigating', async () => {
    server.use(...sessionHandlers(sessionFor('admin')));
    const { router } = await renderRoute('/');
    await screen.findByRole('heading', { level: 1, name: 'Overview' });
    const menu = screen.getByRole('button', { name: 'Open navigation' });
    expect(menu).toHaveAttribute('aria-expanded', 'false');
    await userEvent.click(menu);
    expect(screen.getByRole('button', { name: 'Close navigation' })).toHaveAttribute('aria-expanded', 'true');
    await userEvent.click(within(screen.getByRole('navigation')).getByRole('link', { name: 'People & access' }));
    await waitFor(() => expect(router.state.location.pathname).toBe('/users'));
    expect(screen.getByRole('button', { name: 'Open navigation' })).toHaveAttribute('aria-expanded', 'false');
  });

  it('closes the navigation after any navigation, not only a menu link', async () => {
    server.use(...sessionHandlers(sessionFor('admin')));
    const { router } = await renderRoute('/');
    await screen.findByRole('heading', { level: 1, name: 'Overview' });
    await userEvent.click(screen.getByRole('button', { name: 'Open navigation' }));
    expect(screen.getByRole('button', { name: 'Close navigation' })).toHaveAttribute('aria-expanded', 'true');
    await act(() => router.navigate('/account'));
    expect(await screen.findByRole('heading', { level: 1, name: 'Your account' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Open navigation' })).toHaveAttribute('aria-expanded', 'false');
  });

  it('shows the user name in the sidebar, which phones open with the menu button', async () => {
    server.use(...sessionHandlers(sessionFor('admin')));
    await renderRoute('/');
    expect(within(await screen.findByRole('complementary')).getByTestId('current-user')).toHaveTextContent(/^Ayşe Yılmaz$/);
  });

  it('shows the setup banner to an admin until the recovery passphrase is set', async () => {
    server.use(
      ...sessionHandlers(sessionFor('admin'), {
        admin_exists: true,
        recovery_passphrase_set: false,
        license_chosen: false,
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
        license_chosen: false,
        completed: false,
        default_locale: 'en',
      }),
    );
    await renderRoute('/');
    await screen.findByRole('heading', { level: 1, name: 'Overview' });
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

  it('keeps the intended location when redirecting to sign-in', async () => {
    const { router } = await renderRoute('/');
    await waitFor(() => expect(router.state.location.pathname).toBe('/login'));
    expect((router.state.location.state as { from: { pathname: string } }).from.pathname).toBe('/');
  });

  it('drops cached data on sign-out', async () => {
    server.use(...sessionHandlers(sessionFor('admin')));
    const { router, client } = await renderRoute('/');
    await waitFor(() => expect(screen.getByTestId('server-status')).toHaveTextContent('Server version: 1.2.3'));
    expect(client.getQueryData(['version'])).toBeDefined();
    await userEvent.click(screen.getByRole('button', { name: 'Sign out' }));
    await waitFor(() => expect(router.state.location.pathname).toBe('/login'));
    expect(client.getQueryData(['version'])).toBeUndefined();
    // Only the public provider list of the sign-in page the person landed on is cached now.
    expect(client.getQueryCache().getAll().map((q) => q.queryKey)).toEqual([['auth', 'oidc', 'providers']]);
  });

  it('drops cached data when the session ends', async () => {
    let calls = 0;
    server.use(
      ...sessionHandlers(sessionFor('admin')),
      http.get('/api/v1/version', () => {
        calls++;
        return calls === 1
          ? HttpResponse.json({ version: '1.2.3', commit: 'abc', build_time: 't' })
          : errorResponse(401, 'ALC-AUTH-0001', 'auth.unauthenticated');
      }),
    );
    const { router, client } = await renderRoute('/');
    await waitFor(() => expect(screen.getByTestId('server-status')).toHaveTextContent('Server version: 1.2.3'));
    await client.fetchQuery({ queryKey: ['other'], queryFn: () => Promise.resolve(1) });
    await client.invalidateQueries({ queryKey: ['version'] });
    await waitFor(() => expect(router.state.location.pathname).toBe('/login'));
    expect(client.getQueryData(['other'])).toBeUndefined();
    expect(client.getQueryData(['version'])).toBeUndefined();
  });

  it('signs out locally when the session is already gone (401 on logout)', async () => {
    server.use(
      ...sessionHandlers(sessionFor('admin')),
      http.post('/api/v1/auth/logout', () => errorResponse(401, 'ALC-AUTH-0001', 'auth.unauthenticated')),
    );
    const { router } = await renderRoute('/');
    await userEvent.click(await screen.findByRole('button', { name: 'Sign out' }));
    await waitFor(() => expect(router.state.location.pathname).toBe('/login'));
  });

  it('stays signed in and says so when logout fails for another reason', async () => {
    server.use(
      ...sessionHandlers(sessionFor('admin')),
      http.post('/api/v1/auth/logout', () => errorResponse(500, 'ALC-SYS-0003', 'internal.unexpected')),
    );
    const { router } = await renderRoute('/');
    await userEvent.click(await screen.findByRole('button', { name: 'Sign out' }));
    expect(await screen.findByTestId('signout-error')).toHaveTextContent('Could not sign you out. Try again.');
    expect(router.state.location.pathname).toBe('/');
    expect(screen.getByTestId('current-user')).toHaveTextContent('Ayşe Yılmaz');
  });

  it('reminds the admin of the license step', async () => {
    server.use(
      ...sessionHandlers(sessionFor('admin'), {
        admin_exists: true,
        recovery_passphrase_set: true,
        license_chosen: false,
        completed: false,
        default_locale: 'en',
      }),
    );
    await renderRoute('/');
    expect(await screen.findByTestId('setup-banner')).toHaveTextContent('Finish setting up: add a license or start the evaluation.');
  });
});

describe('a tab that resumes during a rate limit (AUD-16)', () => {
  it('stays signed in when its reads are refused with 429 rate.limited, and shows no alerts for them', async () => {
    const { focusManager } = await import('@tanstack/react-query');
    server.use(...sessionHandlers(sessionFor('admin')));
    const { router } = await renderRoute('/');
    await waitFor(() => expect(screen.getByTestId('server-status')).toHaveTextContent('Server version: 1.2.3'));
    let refused = 0;
    const limited = () => {
      refused += 1;
      return errorResponse(429, 'ALC-SYS-0005', 'rate.limited', { retryable: true });
    };
    server.use(http.get('/api/v1/version', limited), http.get('/api/v1/license/status', limited), http.get('/api/v1/auth/session', limited));
    act(() => {
      focusManager.setFocused(false);
      focusManager.setFocused(true); // the tab comes back: every stale query reads again
    });
    await waitFor(() => expect(refused).toBeGreaterThan(0));
    await waitFor(() => expect(screen.getByTestId('server-status')).toHaveTextContent('The server cannot be reached right now.'));
    expect(router.state.location.pathname).toBe('/');
    expect(screen.getByRole('heading', { level: 1, name: 'Overview' })).toBeInTheDocument();
    expect(screen.queryAllByRole('alert')).toHaveLength(0);
    act(() => focusManager.setFocused(undefined));
  });
});
