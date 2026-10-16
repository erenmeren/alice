import { readFileSync } from 'node:fs';
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
    const enrollHeading = await screen.findByRole('heading', { name: 'Set up your authenticator app' });
    // The sign-in form has gone: focus moves to the new phase's title.
    await waitFor(() => expect(enrollHeading).toHaveFocus());
    expect(screen.getByTestId('totp-secret')).toHaveTextContent('JBSWY3DPEHPK3PXP');
    await userEvent.type(screen.getByLabelText('6-digit code'), '123456');
    await userEvent.click(screen.getByRole('button', { name: 'Verify' }));
    const codesHeading = await screen.findByRole('heading', { name: 'Save your recovery codes' });
    await waitFor(() => expect(codesHeading).toHaveFocus());
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
    // The MFA note belongs to the password form only: single sign-on is not protected by Alice's MFA (owner ruling).
    const note = within(main).getByText('Protected with multi-factor authentication');
    expect(note.compareDocumentPosition(screen.getByText('or')) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(note.compareDocumentPosition(screen.getByRole('button', { name: 'Sign in with Corp IdP' })) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
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
    expect(screen.queryByText('Protected with multi-factor authentication')).not.toBeInTheDocument();
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

describe('sign-in buttons on phones', () => {
  it('are 42 px tall and grow to the design’s 44 px touch target below 768 px', async () => {
    const css = readFileSync('src/components/auth/auth.module.css', 'utf8');
    expect(css).toMatch(/^\.authButton \{ min-height: 42px; \}/m);
    const phone = css.slice(css.indexOf('@media (max-width: 767px)'));
    expect(phone.slice(0, phone.indexOf('\n}') + 2)).toMatch(/\.authButton \{ min-height: 44px; \}/);
    server.use(
      ...sessionHandlers(null),
      http.get('/api/v1/auth/oidc/providers', () => HttpResponse.json({ items: [{ id: 'p1', name: 'Corp IdP' }] })),
    );
    await renderRoute('/login');
    await screen.findByRole('button', { name: 'Sign in with Corp IdP' });
    for (const name of ['Sign in', 'Sign in with Corp IdP']) {
      expect(screen.getByRole('button', { name }).className).toMatch(/authButton/);
    }
  });
});

describe('directory sign-in', () => {
  const DIR = '0192f100-0000-7000-8000-0000000000d1';
  const directories = (items = [{ id: DIR, name: 'Corp AD' }]) => http.get('/api/v1/auth/ldap/directories', () => HttpResponse.json({ items }));

  // dirHandlers answers the directory sign-in with status and makes GET /auth/session answer once a session exists.
  function dirHandlers(status: 'mfa_required' | 'mfa_enrollment_required' | 'signed_in', onLogin: (body: unknown) => void = () => {}) {
    let session: SessionInfo | null = null;
    const signedIn = { ...sessionFor('operator'), user: { ...sessionFor('operator').user, username: 'deniz', auth_source: 'ldap' as const, ldap_directory_id: DIR } };
    return [
      directories(),
      http.get('/api/v1/setup/status', () => HttpResponse.json(installedStatus)),
      http.get('/api/v1/auth/session', () => (session ? HttpResponse.json(session) : errorResponse(401, 'ALC-AUTH-0001', 'auth.unauthenticated'))),
      http.post(`/api/v1/auth/ldap/${DIR}/login`, async ({ request }) => {
        onLogin(await request.json());
        if (status === 'signed_in') session = signedIn;
        return HttpResponse.json({ status, csrf_token: 'dir-csrf' });
      }),
      http.post('/api/v1/auth/mfa/enroll', () => HttpResponse.json(enrollment)),
      http.post('/api/v1/auth/mfa/verify', () => {
        session = signedIn;
        return HttpResponse.json({ ...signedIn, recovery_codes: [] });
      }),
    ];
  }

  async function chooseDirectory(name = 'Corp AD') {
    await userEvent.selectOptions(await screen.findByRole('combobox', { name: 'Sign in to' }), name);
  }

  it('offers no "Sign in to" choice while no directory is switched on', async () => {
    server.use(...sessionHandlers(null));
    await renderRoute('/login');
    expect(await screen.findByLabelText('Username')).toBeInTheDocument();
    expect(screen.queryByRole('combobox', { name: 'Sign in to' })).not.toBeInTheDocument();
  });

  it('offers Local first (chosen) and each switched-on directory by name', async () => {
    server.use(...sessionHandlers(null), directories([{ id: DIR, name: 'Corp AD' }, { id: 'd2', name: 'Lab LDAP' }]));
    await renderRoute('/login');
    const select = await screen.findByRole('combobox', { name: 'Sign in to' });
    expect(select).toHaveValue('local');
    expect(within(select).getAllByRole('option').map((o) => o.textContent)).toEqual(['Local account', 'Corp AD', 'Lab LDAP']);
  });

  it('keeps the local form on /auth/login while Local is chosen', async () => {
    let local = 0;
    server.use(
      ...sessionHandlers(null),
      directories(),
      http.post('/api/v1/auth/login', () => {
        local++;
        return errorResponse(401, 'ALC-AUTH-0005', 'auth.invalid_credentials');
      }),
    );
    await renderRoute('/login');
    await screen.findByRole('combobox', { name: 'Sign in to' });
    await signIn('ada', 'wrong password!');
    expect(await screen.findByRole('alert')).toHaveTextContent('Incorrect username or password.');
    expect(local).toBe(1);
  });

  it('posts to the chosen directory and goes through the code step', async () => {
    let body: unknown;
    server.use(...dirHandlers('mfa_required', (b) => (body = b)));
    const { router } = await renderRoute('/login');
    await chooseDirectory();
    await signIn('deniz', 'directory secret 1');
    expect(await screen.findByRole('heading', { name: 'Enter your verification code' })).toBeInTheDocument();
    expect(body).toEqual({ username: 'deniz', password: 'directory secret 1' });
    expect(document.body.innerHTML).not.toContain('directory secret 1');
    await userEvent.type(screen.getByLabelText('6-digit code'), '123456');
    await userEvent.click(screen.getByRole('button', { name: 'Verify' }));
    await waitFor(() => expect(router.state.location.pathname).toBe('/'));
  });

  it('sets up the authenticator on a first directory sign-in', async () => {
    server.use(...dirHandlers('mfa_enrollment_required'));
    const { router } = await renderRoute('/login');
    await chooseDirectory();
    await signIn('deniz', 'directory secret 1');
    expect(await screen.findByRole('heading', { name: 'Set up your authenticator app' })).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText('6-digit code'), '123456');
    await userEvent.click(screen.getByRole('button', { name: 'Verify' }));
    await waitFor(() => expect(router.state.location.pathname).toBe('/'));
  });

  it('goes straight into the app when the directory does not ask for a code (signed_in)', async () => {
    server.use(...dirHandlers('signed_in'));
    const { router } = await renderRoute('/login');
    await chooseDirectory();
    await signIn('deniz', 'directory secret 1');
    await waitFor(() => expect(router.state.location.pathname).toBe('/'));
    expect(await screen.findByTestId('current-user')).toHaveTextContent(/^Olcay Öztürk$/);
  });

  it('shows one generic text for every refused directory sign-in, whatever the 401 says', async () => {
    const answers = [
      errorResponse(401, 'ALC-LDAP-0001', 'ldap.signin_refused'),
      errorResponse(401, 'ALC-AUTH-0005', 'auth.invalid_credentials'),
      HttpResponse.json({ error: { code: 'X', reason: 'ldap.no_access', message_key: 'errors.ldap.no_access', message: 'no group', request_id: 'r9', retryable: false } }, { status: 401 }),
    ];
    let i = 0;
    server.use(...sessionHandlers(null), directories(), http.post(`/api/v1/auth/ldap/${DIR}/login`, () => answers[i++]));
    await renderRoute('/login');
    await chooseDirectory();
    const texts: string[] = [];
    for (let n = 0; n < answers.length; n++) {
      await signIn('deniz', 'wrong');
      const alert = await screen.findByRole('alert');
      texts.push(alert.textContent ?? '');
      await userEvent.clear(screen.getByLabelText('Username'));
    }
    expect(texts[0]).toContain('The user name or password is wrong, or you have no access.');
    expect(texts[0]).toContain('Check the user name and password and try again.');
    expect(new Set(texts).size).toBe(1);
    expect(texts[0]).not.toMatch(/req-1|r9|ALC-/);
  });

  it('says when the directory cannot be used (503) and shows the rate limit as it is (429)', async () => {
    let i = 0;
    server.use(
      ...sessionHandlers(null),
      directories(),
      http.post(`/api/v1/auth/ldap/${DIR}/login`, () =>
        i++ === 0 ? errorResponse(503, 'ALC-LDAP-0002', 'ldap.directory_unavailable', { retryable: true }) : errorResponse(429, 'ALC-SYS-0005', 'rate.limited'),
      ),
    );
    await renderRoute('/login');
    await chooseDirectory();
    await signIn('deniz', 'pw');
    expect(await screen.findByRole('alert')).toHaveTextContent('The directory cannot be used for sign-in right now.');
    await userEvent.clear(screen.getByLabelText('Username'));
    await signIn('deniz', 'pw');
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('Too many requests in a short time.'));
  });

  it('is translated in Turkish', async () => {
    server.use(...sessionHandlers(null), directories());
    await renderRoute('/login', { languages: ['tr-TR'] });
    const select = await screen.findByRole('combobox', { name: 'Oturum açılacak yer' });
    expect(within(select).getByRole('option', { name: 'Yerel hesap' })).toBeInTheDocument();
    expectNoRawKeys();
  });

  it('says signing in could not be finished, not refused, when the session cannot be read after signed_in', async () => {
    server.use(
      ...sessionHandlers(null),
      directories(),
      http.post(`/api/v1/auth/ldap/${DIR}/login`, () => HttpResponse.json({ status: 'signed_in', csrf_token: 'c' })),
    );
    const { router } = await renderRoute('/login');
    await chooseDirectory();
    await signIn('deniz', 'pw');
    expect(await screen.findByRole('alert')).toHaveTextContent('Alice could not finish signing you in. Try again.');
    expect(screen.queryByText(/The user name or password is wrong/)).not.toBeInTheDocument();
    expect(router.state.location.pathname).toBe('/login');
  });

  it('does not show the session-ended notice together with a directory refusal', async () => {
    server.use(...sessionHandlers(null), directories(), http.post(`/api/v1/auth/ldap/${DIR}/login`, () => errorResponse(401, 'ALC-LDAP-0001', 'ldap.signin_refused')));
    await renderRoute('/login?ended=1');
    expect(await screen.findByText('Your session ended. Please sign in again.')).toBeInTheDocument();
    await chooseDirectory();
    await signIn('deniz', 'pw');
    expect(await screen.findByText('The user name or password is wrong, or you have no access.')).toBeInTheDocument();
    expect(screen.queryByText('Your session ended. Please sign in again.')).not.toBeInTheDocument();
  });

  it('hides the choice when the directory list cannot be read, and Local sign-in still works', async () => {
    let local = 0;
    server.use(
      http.get('/api/v1/auth/ldap/directories', () => errorResponse(503, 'ALC-SYS-0002', 'system.unavailable')),
      http.post('/api/v1/auth/login', () => {
        local++;
        return HttpResponse.json({ status: 'mfa_required', csrf_token: 'p' });
      }),
      ...loginHandlers('mfa_required', () => HttpResponse.json(sessionFor('operator'))),
    );
    await renderRoute('/login');
    await signIn();
    expect(await screen.findByRole('heading', { name: 'Enter your verification code' })).toBeInTheDocument();
    expect(screen.queryByRole('combobox', { name: 'Sign in to' })).not.toBeInTheDocument();
    expect(local).toBe(1);
  });

  it('falls back to Local when the chosen directory is no longer offered', async () => {
    let offered = [{ id: DIR, name: 'Corp AD' }];
    let local = 0;
    server.use(
      ...sessionHandlers(null),
      http.get('/api/v1/auth/ldap/directories', () => HttpResponse.json({ items: offered })),
      http.post('/api/v1/auth/login', () => {
        local++;
        return errorResponse(401, 'ALC-AUTH-0005', 'auth.invalid_credentials');
      }),
    );
    const { client } = await renderRoute('/login');
    await chooseDirectory();
    offered = [{ id: 'd2', name: 'Lab LDAP' }];
    await client.invalidateQueries({ queryKey: ['auth', 'ldap', 'directories'] });
    const select = screen.getByRole('combobox', { name: 'Sign in to' });
    await waitFor(() => expect(within(select).queryByRole('option', { name: 'Corp AD' })).not.toBeInTheDocument());
    expect(select).toHaveValue('local');
    await signIn('ada', 'pw');
    expect(await screen.findByRole('alert')).toHaveTextContent('Incorrect username or password.');
    expect(local).toBe(1);
  });
});

