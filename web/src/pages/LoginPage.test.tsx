import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import type { SessionInfo } from '../api/types';
import { errorResponse, freshStatus, installedStatus, sessionFor, sessionHandlers } from '../test/fixtures';
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
    expect(await screen.findByRole('heading', { name: 'Welcome, Olcay Öztürk' })).toBeInTheDocument();
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

  it('has a language switcher', async () => {
    await renderRoute('/login');
    expect(await screen.findByRole('radio', { name: 'Türkçe' })).toBeInTheDocument();
  });
});
