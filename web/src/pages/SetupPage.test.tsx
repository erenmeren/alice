import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import type { SetupStatus } from '../api/types';
import { errorResponse, freshStatus, installedStatus, sessionFor, sessionHandlers } from '../test/fixtures';
import { expectNoRawKeys } from '../test/i18nAssert';
import { renderRoute } from '../test/render';
import { server } from '../test/server';
import { startOf } from './SetupPage';

const enrollment = { secret: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP', otpauth_uri: 'otpauth://totp/Alice:admin', qr_png: 'iVBORw0KGgo=' };
const codes = ['AAAA-BBBB-CCCC-DDDD', 'EEEE-FFFF-GGGG-HHHH'];

async function enterCode(code = 'K7QX2M-9TPD4R-WB5H8N-3VZC6A') {
  await userEvent.type(await screen.findByLabelText('Setup code'), code);
  await userEvent.click(screen.getByRole('button', { name: 'Continue' }));
}

describe('setup wizard', () => {
  it('walks a fresh install from the setup code to the dashboard', async () => {
    let status: SetupStatus = { ...freshStatus };
    const csrfSeen: (string | null)[] = [];
    const bodies: Record<string, unknown> = {};
    server.use(
      http.get('/api/v1/setup/status', () => HttpResponse.json(status)),
      http.post('/api/v1/setup/session', async ({ request }) => {
        bodies.session = await request.json();
        return HttpResponse.json({ csrf_token: 'setup-csrf' });
      }),
      http.put('/api/v1/setup/language', async ({ request }) => {
        csrfSeen.push(request.headers.get('X-CSRF-Token'));
        bodies.language = await request.json();
        return new HttpResponse(null, { status: 204 });
      }),
      http.post('/api/v1/setup/admin/enrollment', async ({ request }) => {
        bodies.enrollment = await request.json();
        return HttpResponse.json(enrollment);
      }),
      http.post('/api/v1/setup/admin', async ({ request }) => {
        bodies.admin = await request.json();
        status = { ...status, admin_exists: true };
        return HttpResponse.json({ ...sessionFor('admin'), recovery_codes: codes });
      }),
      http.post('/api/v1/setup/recovery-passphrase', async ({ request }) => {
        csrfSeen.push(request.headers.get('X-CSRF-Token'));
        bodies.passphrase = await request.json();
        status = { ...status, recovery_passphrase_set: true };
        return new HttpResponse(null, { status: 204 });
      }),
      http.post('/api/v1/setup/complete', () => {
        status = { ...installedStatus };
        return HttpResponse.json(status);
      }),
    );
    const { router } = await renderRoute('/setup');

    expect(await screen.findByRole('heading', { name: 'Set up Alice' })).toBeInTheDocument();
    await enterCode();
    expect(bodies.session).toEqual({ code: 'K7QX2M-9TPD4R-WB5H8N-3VZC6A' });

    expect(await screen.findByRole('heading', { name: 'Choose your language' })).toBeInTheDocument();
    await userEvent.click(screen.getByLabelText('English'));
    await userEvent.click(screen.getByRole('button', { name: 'Continue' }));
    expect(bodies.language).toEqual({ language: 'en' });

    expect(await screen.findByRole('heading', { name: 'Create the administrator account' })).toBeInTheDocument();
    await userEvent.clear(screen.getByLabelText('Username'));
    await userEvent.type(screen.getByLabelText('Username'), 'ayse');
    await userEvent.type(screen.getByLabelText('Full name'), 'Ayşe Yılmaz');
    await userEvent.type(screen.getByLabelText('Password'), 'correct horse battery');
    await userEvent.type(screen.getByLabelText('Repeat password'), 'correct horse battery');
    await userEvent.click(screen.getByRole('button', { name: 'Continue' }));
    expect(bodies.enrollment).toEqual({
      username: 'ayse',
      display_name: 'Ayşe Yılmaz',
      email: '',
      password: 'correct horse battery',
    });

    expect(await screen.findByRole('heading', { name: 'Set up your authenticator app' })).toBeInTheDocument();
    expect(screen.getByTestId('totp-secret')).toHaveTextContent(enrollment.secret);
    expect(screen.getByRole('img', { name: 'QR code for your authenticator app' })).toHaveAttribute(
      'src',
      `data:image/png;base64,${enrollment.qr_png}`,
    );
    await userEvent.type(screen.getByLabelText('6-digit code'), '123456');
    await userEvent.click(screen.getByRole('button', { name: 'Verify' }));
    expect(bodies.admin).toEqual({ code: '123456' });

    expect(await screen.findByRole('heading', { name: 'Save your recovery codes' })).toBeInTheDocument();
    expect(screen.getByTestId('recovery-codes')).toHaveTextContent('AAAA-BBBB-CCCC-DDDD');
    const next = screen.getByRole('button', { name: 'Continue' });
    expect(next).toBeDisabled();
    await userEvent.click(screen.getByLabelText('I saved these codes in a safe place'));
    await userEvent.click(next);

    expect(await screen.findByRole('heading', { name: 'Choose a recovery passphrase' })).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText('Recovery passphrase'), 'correct horse battery staple');
    expect(screen.getByTestId('passphrase-strength')).toHaveTextContent('Strong');
    await userEvent.type(screen.getByLabelText('Repeat the passphrase'), 'correct horse battery staple');
    const save = screen.getByRole('button', { name: 'Save passphrase' });
    expect(save).toBeDisabled();
    await userEvent.click(screen.getByLabelText('I stored the passphrase safely'));
    await userEvent.click(save);
    expect(bodies.passphrase).toEqual({
      passphrase: 'correct horse battery staple',
      passphrase_confirm: 'correct horse battery staple',
    });

    expect(await screen.findByRole('heading', { name: 'Alice is ready' })).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Go to the dashboard' }));
    await waitFor(() => expect(router.state.location.pathname).toBe('/'));
    expect(await screen.findByRole('heading', { name: 'Welcome, Ayşe Yılmaz' })).toBeInTheDocument();
    // The setup session CSRF token is used before the admin exists, the admin session token after.
    expect(csrfSeen).toEqual(['setup-csrf', 'csrf-admin']);
  });

  it('explains a wrong setup code', async () => {
    server.use(
      ...sessionHandlers(null, freshStatus),
      http.post('/api/v1/setup/session', () => errorResponse(401, 'ALC-SET-0001', 'setup.code_invalid')),
    );
    const { i18n } = await renderRoute('/setup');
    await enterCode('WRONG');
    expect(await screen.findByRole('alert')).toHaveTextContent(i18n.t('errors.setup.code_invalid.title'));
    expect(screen.getByLabelText('Setup code')).toBeInTheDocument();
  });

  it('explains that the wizard is locked after too many wrong codes', async () => {
    server.use(
      ...sessionHandlers(null, freshStatus),
      http.post('/api/v1/setup/session', () => errorResponse(429, 'ALC-SET-0002', 'setup.locked')),
    );
    const { i18n } = await renderRoute('/setup');
    await enterCode('WRONG');
    expect(await screen.findByRole('alert')).toHaveTextContent(i18n.t('errors.setup.locked.title'));
  });

  it('shows the password policy problem from the server', async () => {
    server.use(
      ...sessionHandlers(null, freshStatus),
      http.post('/api/v1/setup/session', () => HttpResponse.json({ csrf_token: 'setup-csrf' })),
      http.put('/api/v1/setup/language', () => new HttpResponse(null, { status: 204 })),
      http.post('/api/v1/setup/admin/enrollment', () =>
        errorResponse(422, 'ALC-AUTH-0008', 'auth.password_too_short', { params: { min: '12' } }),
      ),
    );
    const { i18n } = await renderRoute('/setup');
    await enterCode();
    await userEvent.click(await screen.findByRole('button', { name: 'Continue' }));
    await screen.findByRole('heading', { name: 'Create the administrator account' });
    await userEvent.type(screen.getByLabelText('Full name'), 'Ayşe');
    await userEvent.type(screen.getByLabelText('Password'), 'short');
    await userEvent.type(screen.getByLabelText('Repeat password'), 'short');
    await userEvent.click(screen.getByRole('button', { name: 'Continue' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(
      i18n.t('errors.auth.password_too_short.title', { min: '12' }),
    );
  });

  it('catches different passwords before sending them', async () => {
    let called = false;
    server.use(
      ...sessionHandlers(null, freshStatus),
      http.post('/api/v1/setup/session', () => HttpResponse.json({ csrf_token: 'setup-csrf' })),
      http.put('/api/v1/setup/language', () => new HttpResponse(null, { status: 204 })),
      http.post('/api/v1/setup/admin/enrollment', () => {
        called = true;
        return HttpResponse.json(enrollment);
      }),
    );
    await renderRoute('/setup');
    await enterCode();
    await userEvent.click(await screen.findByRole('button', { name: 'Continue' }));
    await screen.findByRole('heading', { name: 'Create the administrator account' });
    await userEvent.type(screen.getByLabelText('Password'), 'correct horse battery');
    await userEvent.type(screen.getByLabelText('Repeat password'), 'correct horse batterx');
    await userEvent.click(screen.getByRole('button', { name: 'Continue' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('The two passwords are different.');
    expect(called).toBe(false);
  });

  it('asks the returning admin to confirm with a code before saving the passphrase', async () => {
    let attempts = 0;
    server.use(
      ...sessionHandlers(sessionFor('admin'), {
        admin_exists: true,
        recovery_passphrase_set: false,
        completed: false,
        default_locale: 'en',
      }),
      http.post('/api/v1/setup/recovery-passphrase', () => {
        attempts += 1;
        return attempts === 1
          ? errorResponse(403, 'ALC-AUTH-0003', 'auth.stepup_required')
          : new HttpResponse(null, { status: 204 });
      }),
      http.post('/api/v1/auth/stepup', () => HttpResponse.json(sessionFor('admin'))),
    );
    await renderRoute('/setup');
    await screen.findByRole('heading', { name: 'Choose a recovery passphrase' });
    await userEvent.type(screen.getByLabelText('Recovery passphrase'), 'correct horse battery staple');
    await userEvent.type(screen.getByLabelText('Repeat the passphrase'), 'correct horse battery staple');
    await userEvent.click(screen.getByLabelText('I stored the passphrase safely'));
    await userEvent.click(screen.getByRole('button', { name: 'Save passphrase' }));

    expect(await screen.findByRole('dialog', { name: "Confirm it's you" })).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText('6-digit code'), '654321');
    await userEvent.click(screen.getByRole('button', { name: 'Confirm' }));
    expect(await screen.findByRole('heading', { name: 'Alice is ready' })).toBeInTheDocument();
    expect(attempts).toBe(2);
  });

  it('is shown in Turkish for a Turkish browser', async () => {
    server.use(...sessionHandlers(null, freshStatus));
    await renderRoute('/setup', { languages: ['tr-TR'] });
    expect(await screen.findByRole('heading', { name: 'Alice kurulumu' })).toBeInTheDocument();
    expect(screen.getByLabelText('Kurulum kodu')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Devam' })).toBeInTheDocument();
    expectNoRawKeys();
  });

  it('sends visitors of a finished installation to the right page', async () => {
    const { router } = await renderRoute('/setup');
    await waitFor(() => expect(router.state.location.pathname).toBe('/login'));
  });
});

describe('setup wizard edge cases', () => {
  it('sends the user to sign-in when the server says setup is over (404)', async () => {
    server.use(
      ...sessionHandlers(null, freshStatus),
      http.post('/api/v1/setup/session', () => errorResponse(404, 'ALC-GEN-0404', 'not_found')),
    );
    const { router } = await renderRoute('/setup');
    await enterCode();
    await waitFor(() => expect(router.state.location.pathname).toBe('/login'));
  });

  it('never keeps the setup code or passphrase in browser storage', async () => {
    server.use(
      ...sessionHandlers(sessionFor('admin'), { admin_exists: true, recovery_passphrase_set: false, completed: false, default_locale: 'en' }),
      http.post('/api/v1/setup/recovery-passphrase', () => new HttpResponse(null, { status: 204 })),
    );
    await renderRoute('/setup');
    await screen.findByRole('heading', { name: 'Choose a recovery passphrase' });
    await userEvent.type(screen.getByLabelText('Recovery passphrase'), 'correct horse battery staple');
    await userEvent.type(screen.getByLabelText('Repeat the passphrase'), 'correct horse battery staple');
    await userEvent.click(screen.getByLabelText('I stored the passphrase safely'));
    await userEvent.click(screen.getByRole('button', { name: 'Save passphrase' }));
    await screen.findByRole('heading', { name: 'Alice is ready' });
    const stored = JSON.stringify({ ...localStorage }) + JSON.stringify({ ...sessionStorage });
    expect(stored).not.toContain('correct horse');
  });

  it('asks for a code again when finishing needs a fresh step-up', async () => {
    let attempts = 0;
    server.use(
      ...sessionHandlers(sessionFor('admin'), { admin_exists: true, recovery_passphrase_set: true, completed: false, default_locale: 'en' }),
      http.post('/api/v1/setup/complete', () => {
        attempts += 1;
        return attempts === 1 ? errorResponse(403, 'ALC-AUTH-0003', 'auth.stepup_required') : HttpResponse.json(installedStatus);
      }),
      http.post('/api/v1/auth/stepup', () => HttpResponse.json(sessionFor('admin'))),
    );
    const { router } = await renderRoute('/setup');
    await userEvent.click(await screen.findByRole('button', { name: 'Go to the dashboard' }));
    await screen.findByRole('dialog', { name: "Confirm it's you" });
    await userEvent.type(screen.getByLabelText('6-digit code'), '654321');
    await userEvent.click(screen.getByRole('button', { name: 'Confirm' }));
    await waitFor(() => expect(router.state.location.pathname).toBe('/'));
    expect(attempts).toBe(2);
  });
});

describe('startOf', () => {
  const admin = sessionFor('admin');
  it('chooses the first step from the setup status', () => {
    expect(startOf(null, null)).toBe('code');
    expect(startOf(freshStatus, null)).toBe('code');
    expect(startOf(installedStatus, null)).toBe('login');
    expect(startOf(installedStatus, admin)).toBe('home');
    expect(startOf({ ...installedStatus, completed: false, recovery_passphrase_set: false }, admin)).toBe('passphrase');
    expect(startOf({ ...installedStatus, completed: false }, admin)).toBe('done');
    expect(startOf({ ...installedStatus, completed: false }, sessionFor('operator'))).toBe('home');
  });
});
