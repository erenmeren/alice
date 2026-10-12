import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import type { SessionInfo } from '../api/types';
import * as navigation from '../navigation';
import { completedAnonymousStatus, errorResponse, freshStatus, installedStatus, sessionFor, sessionHandlers } from '../test/fixtures';
import { expectNoRawKeys } from '../test/i18nAssert';
import { renderRoute } from '../test/render';
import { server } from '../test/server';

const enrollment = { secret: 'JBSWY3DPEHPK3PXP', otpauth_uri: 'otpauth://totp/Alice:olcay', qr_png: 'iVBORw0KGgo=' };

// signedInAfter makes GET /auth/session answer 401 until verify succeeded.
function loginHandlers(status: 'mfa_required' | 'mfa_enrollment_required', verify: Parameters<typeof http.post>[1]) {
  let session: SessionInfo | null = null;
  return [
    http.get('/api/v1/setup/status', () => HttpResponse.json(installedStatus)),
    http.get('/api/v1/auth/session', () =>
      session ? HttpResponse.json(session) : errorResponse(401, 'ALC-AUTH-0001', 'auth.unauthenticated'),
    ),
    http.post('/api/v1/auth/login', () => HttpResponse.json({ status, csrf_token: 'pending-csrf' })),
    http.post('/api/v1/auth/mfa/enroll', () => HttpResponse.json(enrollment)),
    http.post('/api/v1/auth/mfa/verify', async (info) => {
      const res = await verify(info);
      if (res instanceof Response && res.ok) session = (await res.clone().json()) as SessionInfo;
      return res;
    }),
  ];
}

async function signIn(username = 'olcay', password = 'correct horse battery') {
  await userEvent.type(await screen.findByLabelText('Username'), username);
  await userEvent.type(screen.getByLabelText('Password'), password);
  await userEvent.click(screen.getByRole('button', { name: 'Sign in' }));
}

describe('sign-in page', () => {
  it('signs in with password and authenticator code', async () => {
    let csrf: string | null = null;
    let body: unknown = null;
    server.use(
      ...loginHandlers('mfa_required', async ({ request }) => {
        csrf = request.headers.get('X-CSRF-Token');
        body = await request.json();
        return HttpResponse.json(sessionFor('operator'));
      }),
    );
    const { router } = await renderRoute('/login');
    expect(await screen.findByRole('heading', { name: 'Sign in to Alice' })).toBeInTheDocument();
    await signIn();
    expect(await screen.findByRole('heading', { name: 'Enter your verification code' })).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText('6-digit code'), '123456');
    await userEvent.click(screen.getByRole('button', { name: 'Verify' }));
    await waitFor(() => expect(router.state.location.pathname).toBe('/'));
    expect(await screen.findByTestId('current-user')).toHaveTextContent(/^Olcay Öztürk$/);
    expect(body).toEqual({ code: '123456' });
    expect(csrf).toBe('pending-csrf');
  });

  it('shows the generic message for a wrong username or password', async () => {
    server.use(http.post('/api/v1/auth/login', () => errorResponse(401, 'ALC-AUTH-0005', 'auth.invalid_credentials')));
    const { router } = await renderRoute('/login');
    await signIn('nobody', 'wrong password!');
    expect(await screen.findByRole('alert')).toHaveTextContent('Incorrect username or password.');
    expect(router.state.location.pathname).toBe('/login');
  });

  it('keeps the code step after a wrong code and accepts the next one', async () => {
    let tries = 0;
    server.use(
      ...loginHandlers('mfa_required', () => {
        tries += 1;
        return tries === 1
          ? errorResponse(401, 'ALC-AUTH-0006', 'auth.mfa_invalid')
          : HttpResponse.json(sessionFor('operator'));
      }),
    );
    const { router } = await renderRoute('/login');
    await signIn();
    await userEvent.type(await screen.findByLabelText('6-digit code'), '000000');
    await userEvent.click(screen.getByRole('button', { name: 'Verify' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('The verification code is not correct.');
    await userEvent.clear(screen.getByLabelText('6-digit code'));
    await userEvent.type(screen.getByLabelText('6-digit code'), '123456');
    await userEvent.click(screen.getByRole('button', { name: 'Verify' }));
    await waitFor(() => expect(router.state.location.pathname).toBe('/'));
  });

  it('accepts a recovery code instead of an authenticator code', async () => {
    let body: unknown = null;
    server.use(
      ...loginHandlers('mfa_required', async ({ request }) => {
        body = await request.json();
        return HttpResponse.json(sessionFor('operator'));
      }),
    );
    const { router } = await renderRoute('/login');
    await signIn();
    await userEvent.click(await screen.findByRole('button', { name: 'Use a recovery code' }));
    await userEvent.type(screen.getByLabelText('Recovery code'), 'AAAA-BBBB-CCCC-DDDD');
    await userEvent.click(screen.getByRole('button', { name: 'Verify' }));
    await waitFor(() => expect(router.state.location.pathname).toBe('/'));
    expect(body).toEqual({ recovery_code: 'AAAA-BBBB-CCCC-DDDD' });
  });

  it('enrolls the authenticator app on the first sign-in and shows recovery codes', async () => {
    server.use(
      ...loginHandlers('mfa_enrollment_required', () =>
        HttpResponse.json({ ...sessionFor('operator'), recovery_codes: ['AAAA-BBBB-CCCC-DDDD'] }),
      ),
    );
    const { router } = await renderRoute('/login');
    await signIn();
    expect(await screen.findByRole('heading', { name: 'Set up your authenticator app' })).toBeInTheDocument();
    expect(screen.getByTestId('totp-secret')).toHaveTextContent('JBSWY3DPEHPK3PXP');
    await userEvent.type(screen.getByLabelText('6-digit code'), '123456');
    await userEvent.click(screen.getByRole('button', { name: 'Verify' }));
    expect(await screen.findByRole('heading', { name: 'Save your recovery codes' })).toBeInTheDocument();
    expect(router.state.location.pathname).toBe('/login');
    await userEvent.click(screen.getByLabelText('I saved these codes in a safe place'));
    await userEvent.click(screen.getByRole('button', { name: 'Continue' }));
    await waitFor(() => expect(router.state.location.pathname).toBe('/'));
  });

  it('starts again when the pending sign-in expired', async () => {
    server.use(...loginHandlers('mfa_required', () => errorResponse(401, 'ALC-AUTH-0001', 'auth.unauthenticated')));
    await renderRoute('/login');
    await signIn();
    await userEvent.type(await screen.findByLabelText('6-digit code'), '123456');
    await userEvent.click(screen.getByRole('button', { name: 'Verify' }));
    expect(await screen.findByLabelText('Username')).toBeInTheDocument();
    expect(screen.getByRole('alert')).toHaveTextContent('Your session ended. Please sign in again.');
  });

  it('tells the user when the session ended', async () => {
    await renderRoute('/login?ended=1');
    expect(await screen.findByText('Your session ended. Please sign in again.')).toBeInTheDocument();
  });

  it('is shown in Turkish', async () => {
    await renderRoute('/login', { languages: ['tr-TR'] });
    expect(await screen.findByRole('heading', { name: "Alice'e giriş yapın" })).toBeInTheDocument();
    expect(screen.getByLabelText('Kullanıcı adı')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Giriş yap' })).toBeInTheDocument();
    expectNoRawKeys();
  });

  it('shows the sign-in form when setup is complete and the status says nothing more (S-18)', async () => {
    server.use(...sessionHandlers(null, completedAnonymousStatus));
    const { router } = await renderRoute('/login');
    expect(await screen.findByRole('heading', { name: 'Sign in to Alice' })).toBeInTheDocument();
    expect(router.state.location.pathname).toBe('/login');
  });

  it('sends an anonymous visitor of a completed installation to the sign-in page, never to setup (S-18)', async () => {
    server.use(...sessionHandlers(null, completedAnonymousStatus));
    const { router } = await renderRoute('/');
    await waitFor(() => expect(router.state.location.pathname).toBe('/login'));
    expect(await screen.findByRole('heading', { name: 'Sign in to Alice' })).toBeInTheDocument();
  });

  it('sends signed-in users home and a fresh install to setup', async () => {
    server.use(...sessionHandlers(sessionFor('admin')));
    const first = await renderRoute('/login');
    await waitFor(() => expect(first.router.state.location.pathname).toBe('/'));
    first.unmount();

    server.use(...sessionHandlers(null, freshStatus));
    const second = await renderRoute('/login');
    await waitFor(() => expect(second.router.state.location.pathname).toBe('/setup'));
  });
});

describe('sign-in page safety', () => {
  it('returns to the page the user came from after sign-in', async () => {
    server.use(...loginHandlers('mfa_required', () => HttpResponse.json(sessionFor('operator'))));
    const { router } = await renderRoute('/account');
    await signIn();
    await userEvent.type(await screen.findByLabelText('6-digit code'), '123456');
    await userEvent.click(screen.getByRole('button', { name: 'Verify' }));
    await waitFor(() => expect(router.state.location.pathname).toBe('/account'));
  });

  it('never loops back to the sign-in page after sign-in', async () => {
    server.use(...loginHandlers('mfa_required', () => HttpResponse.json(sessionFor('operator'))));
    const { router } = await renderRoute({ pathname: '/login', state: { from: { pathname: '/login', search: '?ended=1' } } });
    await signIn();
    await userEvent.type(await screen.findByLabelText('6-digit code'), '123456');
    await userEvent.click(screen.getByRole('button', { name: 'Verify' }));
    await waitFor(() => expect(router.state.location.pathname).toBe('/'));
  });

  it('clears the password after a failed attempt and keeps secrets out of storage and the URL', async () => {
    server.use(http.post('/api/v1/auth/login', () => errorResponse(401, 'ALC-AUTH-0005', 'auth.invalid_credentials')));
    const { router } = await renderRoute('/login');
    await signIn('nobody', 'wrong password!');
    await screen.findByRole('alert');
    expect(screen.getByLabelText('Password')).toHaveValue('');
    expect(router.state.location.search).toBe('');
    expect(router.state.location.state).toBeNull();
    expect(JSON.stringify({ ...localStorage, ...sessionStorage })).not.toContain('wrong password!');
  });

  it('clears the code field after a wrong code', async () => {
    server.use(...loginHandlers('mfa_required', () => errorResponse(401, 'ALC-AUTH-0006', 'auth.mfa_invalid')));
    await renderRoute('/login');
    await signIn();
    await userEvent.type(await screen.findByLabelText('6-digit code'), '000000');
    await userEvent.click(screen.getByRole('button', { name: 'Verify' }));
    await screen.findByRole('alert');
    expect(screen.getByLabelText('6-digit code')).toHaveValue('');
  });

  it('shows the retry message when the server is busy with the account', async () => {
    server.use(http.post('/api/v1/auth/login', () => errorResponse(503, 'ALC-AUTH-0012', 'auth.try_again')));
    await renderRoute('/login');
    await signIn();
    expect(await screen.findByRole('alert')).toHaveTextContent('Alice is busy with this account. Please try again.');
    expect(screen.getByRole('button', { name: 'Sign in' })).toBeEnabled();
  });

  it('starts again when the pending sign-in expires during authenticator setup', async () => {
    server.use(...loginHandlers('mfa_enrollment_required', () => errorResponse(401, 'ALC-AUTH-0001', 'auth.unauthenticated')));
    await renderRoute('/login');
    await signIn();
    await userEvent.type(await screen.findByLabelText('6-digit code'), '123456');
    await userEvent.click(screen.getByRole('button', { name: 'Verify' }));
    expect(await screen.findByLabelText('Username')).toBeInTheDocument();
    expect(screen.getByRole('alert')).toHaveTextContent('Your session ended. Please sign in again.');
    expect(screen.getByLabelText('Password')).toHaveValue('');
  });

  it('has the language toggle, which switches the page to Turkish without a session', async () => {
    let saved = false;
    server.use(http.put('/api/v1/auth/locale', () => {
      saved = true;
      return new HttpResponse(null, { status: 204 });
    }));
    await renderRoute('/login');
    await userEvent.click(await screen.findByRole('button', { name: 'Türkçe' }));
    expect(await screen.findByRole('heading', { level: 1, name: "Alice'e giriş yapın" })).toBeInTheDocument();
    expect(screen.getByText('Alice hesabınızla giriş yapın.')).toBeInTheDocument();
    expect(saved).toBe(false);
  });

  describe('single sign-on', () => {
    afterEach(() => vi.restoreAllMocks());

    it('offers single sign-on and goes to the identity provider', async () => {
      const go = vi.spyOn(navigation, 'goTo').mockImplementation(() => {});
      server.use(
        ...sessionHandlers(null),
        http.get('/api/v1/auth/oidc/providers', () => HttpResponse.json({ items: [{ id: 'p1', name: 'Corp IdP' }] })),
        http.post('/api/v1/auth/oidc/p1/start', async ({ request }) => {
          expect(await request.json()).toEqual({ next: '/' });
          return HttpResponse.json({ authorize_url: 'https://idp.example.com/authorize?state=s' });
        }),
      );
      await renderRoute('/login');
      await userEvent.click(await screen.findByRole('button', { name: 'Sign in with Corp IdP' }));
      await waitFor(() => expect(go).toHaveBeenCalledWith('https://idp.example.com/authorize?state=s'));
      expect(screen.getByText('or')).toBeInTheDocument();
      // The local sign-in stays available (break-glass, X-05).
      expect(screen.getByLabelText('Username')).toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Sign in' })).toBeInTheDocument();
    });

    it('starts the sign-in with the page the person wanted', async () => {
      const go = vi.spyOn(navigation, 'goTo').mockImplementation(() => {});
      let next: unknown;
      server.use(
        ...sessionHandlers(null),
        http.get('/api/v1/auth/oidc/providers', () => HttpResponse.json({ items: [{ id: 'p1', name: 'Corp IdP' }] })),
        http.post('/api/v1/auth/oidc/p1/start', async ({ request }) => {
          next = ((await request.json()) as { next: string }).next;
          return HttpResponse.json({ authorize_url: 'https://idp.example.com/a' });
        }),
      );
      await renderRoute({ pathname: '/login', state: { from: '/certificates?expiry=7' } });
      await userEvent.click(await screen.findByRole('button', { name: 'Sign in with Corp IdP' }));
      await waitFor(() => expect(go).toHaveBeenCalled());
      expect(next).toBe('/certificates?expiry=7');
    });

    it('shows the error when the sign-in cannot be started', async () => {
      const go = vi.spyOn(navigation, 'goTo').mockImplementation(() => {});
      server.use(
        ...sessionHandlers(null),
        http.get('/api/v1/auth/oidc/providers', () => HttpResponse.json({ items: [{ id: 'p1', name: 'Corp IdP' }] })),
        http.post('/api/v1/auth/oidc/p1/start', () => errorResponse(403, 'ALC-SSO-0013', 'sso.provider_disabled')),
      );
      await renderRoute('/login');
      await userEvent.click(await screen.findByRole('button', { name: 'Sign in with Corp IdP' }));
      expect(await screen.findByRole('alert')).toBeInTheDocument();
      expect(go).not.toHaveBeenCalled();
    });

    it('explains a refused single sign-on (O-06)', async () => {
      server.use(...sessionHandlers(null));
      await renderRoute('/login?sso_error=sso.no_access');
      expect(await screen.findByText('Your account has no access to Alice, contact your administrator.')).toBeInTheDocument();
      expect(screen.getByText(/Ask your administrator to add your group/)).toBeInTheDocument();
    });

    it('explains it in Turkish', async () => {
      server.use(...sessionHandlers(null));
      await renderRoute('/login?sso_error=sso.idp_unreachable', { languages: ['tr-TR'] });
      expect(await screen.findByRole('alert')).toHaveTextContent('Alice kimlik sağlayıcıya ulaşamadı.');
    });

    it('ignores an unknown sso_error value', async () => {
      server.use(...sessionHandlers(null));
      await renderRoute('/login?sso_error=<script>');
      await screen.findByRole('heading', { level: 1 });
      expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    });

    it('shows no single sign-on part when the provider list cannot be read', async () => {
      server.use(...sessionHandlers(null), http.get('/api/v1/auth/oidc/providers', () => errorResponse(500, 'ALC-SYS-0003', 'internal.unexpected')));
      await renderRoute('/login');
      await screen.findByRole('button', { name: 'Sign in' });
      expect(screen.queryByText('or')).not.toBeInTheDocument();
    });
  });
});

describe('sign-in page design', () => {
  it('has the split layout: one h1 in the form side, the subtitle, one "Sign in" button, SSO under the divider and the MFA note', async () => {
    server.use(
      ...sessionHandlers(null),
      http.get('/api/v1/auth/oidc/providers', () => HttpResponse.json({ items: [{ id: 'p1', name: 'Corp IdP' }] })),
    );
    await renderRoute('/login');
    await screen.findByRole('button', { name: 'Sign in with Corp IdP' });
    const main = screen.getByRole('main');
    expect(screen.getAllByRole('main')).toHaveLength(1);
    expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
    expect(within(main).getByRole('heading', { level: 1, name: 'Sign in to Alice' })).toBeInTheDocument();
    expect(within(main).getByText('Sign in with your Alice account.')).toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: 'Sign in' })).toHaveLength(1);
    expect(within(main).getByText('Protected with multi-factor authentication')).toBeInTheDocument();
    expect(within(main).getByRole('button', { name: 'Switch color mode' })).toBeInTheDocument();
    expect(screen.getByRole('complementary', { name: 'Alice' })).toBeInTheDocument();
    expectNoRawKeys();
  });

  it('keeps one h1 in the code step and widens the form for the enrollment', async () => {
    server.use(...loginHandlers('mfa_required', () => HttpResponse.json(sessionFor('operator'))));
    await renderRoute('/login');
    await signIn();
    expect(await screen.findByRole('heading', { level: 2, name: 'Enter your verification code' })).toBeInTheDocument();
    expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
    expect(screen.queryByText('Sign in with your Alice account.')).not.toBeInTheDocument();
    expect(screen.getByLabelText('6-digit code')).toHaveFocus();
  });

  it('shows the enrollment in the wide form, keeps it after a wrong code and finishes without codes to show', async () => {
    let tries = 0;
    server.use(
      ...loginHandlers('mfa_enrollment_required', () =>
        ++tries === 1 ? errorResponse(401, 'ALC-AUTH-0006', 'auth.mfa_invalid') : HttpResponse.json(sessionFor('operator')),
      ),
    );
    const { router } = await renderRoute('/login');
    await signIn();
    const heading = await screen.findByRole('heading', { name: 'Set up your authenticator app' });
    expect(heading.closest('[data-wide]')).not.toBeNull();
    expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
    await userEvent.type(screen.getByLabelText('6-digit code'), '000000');
    await userEvent.click(screen.getByRole('button', { name: 'Verify' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('The verification code is not correct.');
    await userEvent.clear(screen.getByLabelText('6-digit code'));
    await userEvent.type(screen.getByLabelText('6-digit code'), '123456');
    await userEvent.click(screen.getByRole('button', { name: 'Verify' }));
    await waitFor(() => expect(router.state.location.pathname).toBe('/'));
  });
});
