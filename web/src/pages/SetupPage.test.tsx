import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import type { SetupStatus } from '../api/types';
import {
  completedAnonymousStatus,
  errorResponse,
  freshStatus,
  installedStatus,
  jobFixture,
  licenseInfoFixture,
  sessionFor,
  sessionHandlers,
  smtpFixture,
  httpsInfoFixture,
  targetFixture,
} from '../test/fixtures';
import { expectNoRawKeys } from '../test/i18nAssert';
import { renderRoute } from '../test/render';
import { server } from '../test/server';
import { startOf } from './SetupPage';

const enrollment = { secret: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP', otpauth_uri: 'otpauth://totp/Alice:admin', qr_png: 'iVBORw0KGgo=' };
const codes = ['AAAA-BBBB-CCCC-DDDD', 'EEEE-FFFF-GGGG-HHHH'];

// The handlers of a fresh installation (nobody signed in, no administrator yet).
function freshSetupHandlers() {
  return sessionHandlers(null, freshStatus);
}

// The handlers of an administrator who stopped the wizard after the passphrase; overrides set the resume point.
function adminSetupHandlers(overrides: Partial<SetupStatus> = {}) {
  const status: SetupStatus = {
    admin_exists: true,
    recovery_passphrase_set: true,
    license_chosen: false,
    completed: false,
    default_locale: 'en',
    https_chosen: true,
    mail_chosen: false,
    next_step: 'mail',
    ...overrides,
  };
  return [
    ...sessionHandlers(sessionFor('admin'), status),
    http.get('/api/v1/settings/smtp', () => HttpResponse.json(smtpFixture)),
    http.get('/api/v1/settings/https', () => HttpResponse.json(httpsInfoFixture({ temporary: true }))),
  ];
}

const rail = () => screen.getByRole('list', { name: 'Setup progress' });

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
      http.post('/api/v1/setup/https/keep-temporary', () => {
        csrfSeen.push('keep-temporary');
        status = { ...status, https_chosen: true, next_step: 'mail' };
        return HttpResponse.json(status);
      }),
      http.get('/api/v1/settings/smtp', () => HttpResponse.json(smtpFixture)),
      http.post('/api/v1/setup/mail/skip', () => {
        csrfSeen.push('mail-skip');
        status = { ...status, mail_chosen: true, next_step: 'license' };
        return HttpResponse.json(status);
      }),
      http.post('/api/v1/setup/evaluation', () => {
        csrfSeen.push('evaluation');
        status = { ...status, license_chosen: true };
        return HttpResponse.json(status);
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

    // R43 row 16: the HTTPS certificate and the mail server come after the recovery passphrase.
    expect(await screen.findByRole('heading', { name: 'HTTPS certificate' })).toBeInTheDocument();
    await userEvent.click(await screen.findByTestId('https-keep-temporary'));
    expect(await screen.findByRole('heading', { name: 'Mail server (optional)' })).toBeInTheDocument();
    await userEvent.click(await screen.findByTestId('setup-skip'));

    expect(await screen.findByRole('heading', { name: 'Add a license' })).toBeInTheDocument();
    expect(screen.getByTestId('installation-id')).toHaveTextContent('ALICE-7F3K-9Q2M-XD41-B8TC');
    await userEvent.click(screen.getByRole('button', { name: 'Start 30-day evaluation (up to 5 targets)' }));

    // Step 7 (spec §18.5): Alice's public key and the preparation commands; adding a server is optional.
    expect(await screen.findByRole('heading', { name: 'Connect your servers' })).toBeInTheDocument();
    expect(await screen.findByTestId('platform-public-key')).toHaveTextContent('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5');
    expect(screen.getByRole('button', { name: 'Add a server now' })).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Continue' }));

    expect(await screen.findByRole('heading', { name: 'Alice is ready' })).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Go to the dashboard' }));
    await waitFor(() => expect(router.state.location.pathname).toBe('/'));
    expect(await screen.findByTestId('current-user')).toHaveTextContent(/^Ayşe Yılmaz$/);
    // The setup session CSRF token is used before the admin exists, the admin session token after.
    expect(csrfSeen).toEqual(['setup-csrf', 'csrf-admin', 'keep-temporary', 'mail-skip', 'evaluation']);
    // Eleven screens and the dashboard's shell at the end: under a loaded test run this takes longer than 5 s.
  }, 20_000);

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
    expect(screen.getByLabelText('Username')).toHaveAccessibleDescription(
      '2 to 64 characters: English letters (A–Z), digits, dot, underscore or hyphen. Start with a letter or digit.',
    );
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
        license_chosen: false,
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
    expect(await screen.findByRole('heading', { name: 'HTTPS certificate' })).toBeInTheDocument();
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
    // Once the server answers 404 setup is over, so the status the page re-reads says installed.
    let over = false;
    server.use(
      http.get('/api/v1/setup/status', () => HttpResponse.json(over ? installedStatus : freshStatus)),
      http.get('/api/v1/auth/session', () => errorResponse(401, 'ALC-AUTH-0001', 'auth.unauthenticated')),
      http.post('/api/v1/setup/session', () => {
        over = true;
        return errorResponse(404, 'ALC-SYS-0001', 'system.not_found');
      }),
    );
    const { router } = await renderRoute('/setup');
    await enterCode();
    await waitFor(() => expect(router.state.location.pathname).toBe('/login'));
  });

  it('never keeps the setup code or passphrase in browser storage', async () => {
    server.use(
      ...sessionHandlers(sessionFor('admin'), { admin_exists: true, recovery_passphrase_set: false, license_chosen: false, completed: false, default_locale: 'en' }),
      http.post('/api/v1/setup/recovery-passphrase', () => new HttpResponse(null, { status: 204 })),
    );
    await renderRoute('/setup');
    await screen.findByRole('heading', { name: 'Choose a recovery passphrase' });
    await userEvent.type(screen.getByLabelText('Recovery passphrase'), 'correct horse battery staple');
    await userEvent.type(screen.getByLabelText('Repeat the passphrase'), 'correct horse battery staple');
    await userEvent.click(screen.getByLabelText('I stored the passphrase safely'));
    await userEvent.click(screen.getByRole('button', { name: 'Save passphrase' }));
    await screen.findByRole('heading', { name: 'HTTPS certificate' });
    const stored = JSON.stringify({ ...localStorage }) + JSON.stringify({ ...sessionStorage });
    expect(stored).not.toContain('correct horse');
  });

  it('asks for a code again when finishing needs a fresh step-up', async () => {
    let attempts = 0;
    server.use(
      ...sessionHandlers(sessionFor('admin'), { admin_exists: true, recovery_passphrase_set: true, license_chosen: true, completed: false, default_locale: 'en' }),
      http.post('/api/v1/setup/complete', () => {
        attempts += 1;
        return attempts === 1 ? errorResponse(403, 'ALC-AUTH-0003', 'auth.stepup_required') : HttpResponse.json(installedStatus);
      }),
      http.post('/api/v1/auth/stepup', () => HttpResponse.json(sessionFor('admin'))),
    );
    const { router } = await renderRoute('/setup');
    await screen.findByRole('heading', { name: 'Connect your servers' });
    await userEvent.click(screen.getByRole('button', { name: 'Continue' }));
    await userEvent.click(await screen.findByRole('button', { name: 'Go to the dashboard' }));
    await screen.findByRole('dialog', { name: "Confirm it's you" });
    await userEvent.type(screen.getByLabelText('6-digit code'), '654321');
    await userEvent.click(screen.getByRole('button', { name: 'Confirm' }));
    await waitFor(() => expect(router.state.location.pathname).toBe('/'));
    expect(attempts).toBe(2);
  });

  it('uploads a license in the wizard instead of starting the evaluation', async () => {
    let status = { admin_exists: true, recovery_passphrase_set: true, license_chosen: false, completed: false, default_locale: 'en' };
    const upload = {
      license: { ...licenseInfoFixture, customer: 'Test Company' },
      pending: false,
      already_expired: false,
      correction: false,
      duplicate: false,
      phase: 'active',
    };
    server.use(
      http.get('/api/v1/setup/status', () => HttpResponse.json(status)),
      http.get('/api/v1/auth/session', () => HttpResponse.json(sessionFor('admin'))),
      http.post('/api/v1/license/preview', () => HttpResponse.json(upload)),
      http.post('/api/v1/license', () => {
        status = { ...status, license_chosen: true };
        return HttpResponse.json(upload);
      }),
    );
    await renderRoute('/setup');
    await screen.findByRole('heading', { name: 'Add a license' });
    await userEvent.upload(screen.getByLabelText('License file'), new File(['{}'], 'l.alicelic', { type: 'application/json' }));
    await userEvent.click(screen.getByRole('button', { name: 'Check the file' }));
    await userEvent.click(within(await screen.findByRole('dialog', { name: 'Confirm the license' })).getByRole('button', { name: 'Install license' }));
    expect(await screen.findByRole('heading', { name: 'Connect your servers' })).toBeInTheDocument();
  });

  it('asks for a code before starting the evaluation when the step-up expired', async () => {
    let attempts = 0;
    server.use(
      ...sessionHandlers(sessionFor('admin'), { admin_exists: true, recovery_passphrase_set: true, license_chosen: false, completed: false, default_locale: 'en' }),
      http.post('/api/v1/setup/evaluation', () => {
        attempts += 1;
        return attempts === 1
          ? errorResponse(403, 'ALC-AUTH-0003', 'auth.stepup_required')
          : HttpResponse.json({ ...installedStatus, completed: false });
      }),
      http.post('/api/v1/auth/stepup', () => HttpResponse.json(sessionFor('admin'))),
    );
    await renderRoute('/setup');
    await userEvent.click(await screen.findByRole('button', { name: 'Start 30-day evaluation (up to 5 targets)' }));
    await screen.findByRole('dialog', { name: "Confirm it's you" });
    await userEvent.type(screen.getByLabelText('6-digit code'), '654321');
    await userEvent.click(screen.getByRole('button', { name: 'Confirm' }));
    expect(await screen.findByRole('heading', { name: 'Connect your servers' })).toBeInTheDocument();
    expect(attempts).toBe(2);
  });

  it('adds a server from the wizard and then continues to Finish', async () => {
    server.use(
      ...sessionHandlers(sessionFor('admin'), { admin_exists: true, recovery_passphrase_set: true, license_chosen: true, completed: false, default_locale: 'en' }),
      http.post('/api/v1/targets', () =>
        HttpResponse.json({ target: targetFixture, job_id: 'job-1', status_url: '/api/v1/jobs/job-1' }, { status: 201 }),
      ),
      http.get('/api/v1/jobs/:id', () => HttpResponse.json(jobFixture({ id: 'job-1' }))),
    );
    await renderRoute('/setup');
    expect(await screen.findByRole('heading', { name: 'Connect your servers' })).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Add a server now' }));
    const dialog = await screen.findByRole('dialog', { name: 'Add server' });
    await userEvent.type(within(dialog).getByLabelText(/^Name/), 'web-01');
    await userEvent.type(within(dialog).getByLabelText(/^Address/), 'web-01.example.com');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Connect' }));
    expect(await screen.findByText('Server added. Alice is reading its SSH keys.')).toBeInTheDocument();
    expect(screen.queryByRole('dialog', { name: 'Add server' })).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Continue' }));
    expect(await screen.findByRole('heading', { name: 'Alice is ready' })).toBeInTheDocument();
  });

  it('does not report success in the wizard when the first check of a new server failed', async () => {
    server.use(
      ...sessionHandlers(sessionFor('admin'), { admin_exists: true, recovery_passphrase_set: true, license_chosen: true, completed: false, default_locale: 'en' }),
      http.post('/api/v1/targets', () =>
        HttpResponse.json({ target: targetFixture, job_id: 'job-1', status_url: '/api/v1/jobs/job-1' }, { status: 201 }),
      ),
      http.get('/api/v1/jobs/:id', () =>
        HttpResponse.json(jobFixture({ id: 'job-1', status: 'failed', error: { code: 'ALC-SSH-0001', reason: 'ssh.unreachable' } })),
      ),
    );
    await renderRoute('/setup');
    await userEvent.click(await screen.findByRole('button', { name: 'Add a server now' }));
    const dialog = await screen.findByRole('dialog', { name: 'Add server' });
    await userEvent.type(within(dialog).getByLabelText(/^Name/), 'web-01');
    await userEvent.type(within(dialog).getByLabelText(/^Address/), 'web-01.example.com');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Connect' }));
    expect(await within(dialog).findByText('Alice cannot reach the server.')).toBeInTheDocument();
    expect(within(dialog).queryByRole('button', { name: 'Open the server' })).not.toBeInTheDocument();
    // The dialog also has a corner close icon with the same name; the labelled button is the one with text.
    await userEvent.click(within(dialog).getByText('Close', { selector: 'button *' }));
    expect(await screen.findByText(/could not finish the first check/)).toBeInTheDocument();
    expect(screen.queryByText('Server added. Alice is reading its SSH keys.')).not.toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Connect your servers' })).toBeInTheDocument();
  });

  it('adds a server from the wizard under React StrictMode and stays in the wizard', async () => {
    server.use(
      ...sessionHandlers(sessionFor('admin'), { admin_exists: true, recovery_passphrase_set: true, license_chosen: true, completed: false, default_locale: 'en' }),
      http.post('/api/v1/targets', () =>
        HttpResponse.json({ target: targetFixture, job_id: 'job-1', status_url: '/api/v1/jobs/job-1' }, { status: 201 }),
      ),
      http.get('/api/v1/jobs/:id', () => HttpResponse.json(jobFixture({ id: 'job-1' }))),
    );
    const { router } = await renderRoute('/setup', { strict: true });
    await userEvent.click(await screen.findByRole('button', { name: 'Add a server now' }));
    const dialog = await screen.findByRole('dialog', { name: 'Add server' });
    await userEvent.type(within(dialog).getByLabelText(/^Name/), 'web-01');
    await userEvent.type(within(dialog).getByLabelText(/^Address/), 'web-01.example.com');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Connect' }));
    expect(await screen.findByText('Server added. Alice is reading its SSH keys.')).toBeInTheDocument();
    expect(router.state.location.pathname).toBe('/setup');
    expect(screen.getByRole('heading', { name: 'Connect your servers' })).toBeInTheDocument();
  });
});

describe('startOf', () => {
  const admin = sessionFor('admin');
  it('chooses the first step from the setup status', () => {
    expect(startOf(null, null)).toBe('code');
    expect(startOf(freshStatus, null)).toBe('code');
    expect(startOf(installedStatus, null)).toBe('login');
    // An anonymous caller of a completed installation gets only {completed, default_locale} (S-18).
    expect(startOf(completedAnonymousStatus, null)).toBe('login');
    expect(startOf(installedStatus, admin)).toBe('home');
    expect(startOf({ ...installedStatus, completed: false, recovery_passphrase_set: false, license_chosen: false }, admin)).toBe('passphrase');
    expect(startOf({ ...installedStatus, completed: false, license_chosen: false }, admin)).toBe('license');
    expect(startOf({ ...installedStatus, completed: false }, admin)).toBe('platform');
    expect(startOf({ ...installedStatus, completed: false }, sessionFor('operator'))).toBe('home');
  });

  it('resumes at the step the server names (R43 row 16)', () => {
    const open = { ...installedStatus, completed: false, license_chosen: false, https_chosen: false, mail_chosen: false };
    expect(startOf({ ...open, next_step: 'https' }, admin)).toBe('https');
    expect(startOf({ ...open, https_chosen: true, next_step: 'mail' }, admin)).toBe('mail');
    expect(startOf({ ...open, https_chosen: true, mail_chosen: true, next_step: 'license' }, admin)).toBe('license');
    expect(startOf({ ...open, license_chosen: true, https_chosen: true, mail_chosen: true, next_step: 'platform' }, admin)).toBe('platform');
    expect(startOf({ ...open, recovery_passphrase_set: false, next_step: 'passphrase' }, admin)).toBe('passphrase');
    // A server without next_step: the choices it reports still decide.
    expect(startOf(open, admin)).toBe('https');
    expect(startOf({ ...open, https_chosen: true }, admin)).toBe('mail');
    // An unknown step from a newer server falls back to the reported choices.
    expect(startOf({ ...open, https_chosen: true, mail_chosen: true, next_step: 'later' as never }, admin)).toBe('license');
  });
});

describe('setup wizard steps of Phase 8', () => {
  const open: SetupStatus = {
    admin_exists: true,
    recovery_passphrase_set: true,
    license_chosen: false,
    completed: false,
    default_locale: 'en',
    https_chosen: false,
    mail_chosen: false,
    next_step: 'https',
  };

  it('opens the mail step directly when the server says the wizard stopped there (resume)', async () => {
    server.use(...sessionHandlers(sessionFor('admin'), { ...open, https_chosen: true, next_step: 'mail' }), http.get('/api/v1/settings/smtp', () => HttpResponse.json(smtpFixture)));
    await renderRoute('/setup');
    expect(await screen.findByRole('heading', { name: 'Mail server (optional)' })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Choose a recovery passphrase' })).not.toBeInTheDocument();
  });

  it('goes back from the mail step to the HTTPS step in its done state, and from there to the passphrase that cannot change', async () => {
    server.use(
      ...sessionHandlers(sessionFor('admin'), { ...open, https_chosen: true, next_step: 'mail' }),
      http.get('/api/v1/settings/smtp', () => HttpResponse.json(smtpFixture)),
      http.get('/api/v1/settings/https', () => HttpResponse.json(httpsInfoFixture({ temporary: true }))),
    );
    await renderRoute('/setup');
    await screen.findByRole('heading', { name: 'Mail server (optional)' });
    await userEvent.click(screen.getByTestId('setup-back'));
    expect(await screen.findByRole('heading', { name: 'HTTPS certificate' })).toBeInTheDocument();
    expect(await screen.findByText(/You chose to keep the temporary certificate/)).toBeInTheDocument();
    expect(screen.queryByTestId('https-keep-temporary')).not.toBeInTheDocument();

    await userEvent.click(screen.getByTestId('setup-back'));
    expect(await screen.findByRole('heading', { name: 'Choose a recovery passphrase' })).toBeInTheDocument();
    expect(screen.getByText('The recovery passphrase is set. It cannot be changed here.')).toBeInTheDocument();
    expect(screen.queryByLabelText('Recovery passphrase')).not.toBeInTheDocument();
    // Nothing before the passphrase can be shown again (the recovery codes are shown once).
    expect(screen.queryByTestId('setup-back')).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Continue' }));
    expect(await screen.findByRole('heading', { name: 'HTTPS certificate' })).toBeInTheDocument();
  });

  it('shows an uploaded certificate as the done state of the HTTPS step', async () => {
    server.use(
      ...sessionHandlers(sessionFor('admin'), { ...open, https_chosen: true, next_step: 'mail' }),
      http.get('/api/v1/settings/smtp', () => HttpResponse.json(smtpFixture)),
      http.get('/api/v1/settings/https', () => HttpResponse.json(httpsInfoFixture({ temporary: false }))),
    );
    await renderRoute('/setup');
    await screen.findByRole('heading', { name: 'Mail server (optional)' });
    await userEvent.click(screen.getByTestId('setup-back'));
    expect(await screen.findByText(/Your own certificate is in use/)).toBeInTheDocument();
  });

  it('keeps the typed mail fields (not the password) and the HTTPS format when going Back and forward', async () => {
    server.use(
      ...sessionHandlers(sessionFor('admin'), { ...open, https_chosen: true, next_step: 'mail' }),
      http.get('/api/v1/settings/smtp', () => HttpResponse.json(smtpFixture)),
      http.get('/api/v1/settings/https', () => HttpResponse.json(httpsInfoFixture({ temporary: true }))),
    );
    await renderRoute('/setup');
    await screen.findByRole('heading', { name: 'Mail server (optional)' });
    await userEvent.type(await screen.findByLabelText('Mail server'), 'mail.example.test');
    await userEvent.type(screen.getByLabelText('Sender address'), 'alice@example.test');
    await userEvent.type(screen.getByLabelText('Password'), 'hunter2');
    await userEvent.click(screen.getByTestId('setup-back'));
    await screen.findByRole('heading', { name: 'HTTPS certificate' });
    await userEvent.click(screen.getByLabelText(/PKCS/i));
    await userEvent.click(screen.getByRole('button', { name: 'Continue' }));
    await screen.findByRole('heading', { name: 'Mail server (optional)' });
    expect(await screen.findByLabelText('Mail server')).toHaveValue('mail.example.test');
    expect(screen.getByLabelText('Sender address')).toHaveValue('alice@example.test');
    expect(screen.getByLabelText('Password')).toHaveValue('');
    await userEvent.click(screen.getByTestId('setup-back'));
    await screen.findByRole('heading', { name: 'HTTPS certificate' });
    expect(screen.getByLabelText(/PKCS/i)).toBeChecked();
  });

  it('goes back through Finish, the servers, the license and the mail step, and forward again', async () => {
    server.use(
      ...sessionHandlers(sessionFor('admin'), { ...open, https_chosen: true, mail_chosen: true, license_chosen: true, next_step: 'platform' }),
      http.get('/api/v1/settings/smtp', () => HttpResponse.json(smtpFixture)),
    );
    await renderRoute('/setup');
    await screen.findByRole('heading', { name: 'Connect your servers' });
    await userEvent.click(screen.getByRole('button', { name: 'Continue' }));
    await screen.findByRole('heading', { name: 'Alice is ready' });
    await userEvent.click(screen.getByTestId('setup-back'));
    await screen.findByRole('heading', { name: 'Connect your servers' });
    await userEvent.click(screen.getByTestId('setup-back'));
    expect(await screen.findByRole('heading', { name: 'Add a license' })).toBeInTheDocument();
    expect(screen.getByText('A license is chosen. You can change it here or later on the License page.')).toBeInTheDocument();
    await userEvent.click(screen.getByTestId('setup-back'));
    expect(await screen.findByRole('heading', { name: 'Mail server (optional)' })).toBeInTheDocument();
    await userEvent.click(await screen.findByRole('button', { name: 'Continue' }));
    expect(await screen.findByRole('heading', { name: 'Add a license' })).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Continue' }));
    expect(await screen.findByRole('heading', { name: 'Connect your servers' })).toBeInTheDocument();
  });

  it('keeps the passphrase submit disabled for a fair passphrase and says why', async () => {
    server.use(...sessionHandlers(sessionFor('admin'), { ...open, recovery_passphrase_set: false, next_step: 'passphrase' }));
    await renderRoute('/setup');
    await screen.findByRole('heading', { name: 'Choose a recovery passphrase' });
    await userEvent.type(screen.getByLabelText('Recovery passphrase'), 'abcdefghijklmnop');
    await userEvent.type(screen.getByLabelText('Repeat the passphrase'), 'abcdefghijklmnop');
    await userEvent.click(screen.getByLabelText('I stored the passphrase safely'));
    expect(screen.getByTestId('passphrase-strength')).toHaveTextContent('Fair');
    expect(screen.getByText(/This passphrase is too easy to guess/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Save passphrase' })).toBeDisabled();

    await userEvent.clear(screen.getByLabelText('Recovery passphrase'));
    await userEvent.type(screen.getByLabelText('Recovery passphrase'), 'short');
    expect(screen.getByRole('button', { name: 'Save passphrase' })).toBeDisabled();

    await userEvent.clear(screen.getByLabelText('Recovery passphrase'));
    await userEvent.type(screen.getByLabelText('Recovery passphrase'), 'abcdefghijklmnopqrst');
    expect(screen.getByTestId('passphrase-strength')).toHaveTextContent('Good');
    expect(screen.queryByText(/This passphrase is too easy to guess/)).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Save passphrase' })).toBeEnabled();
  });

  it('shows the server refusal of a weak passphrase (ALC-SET-0010)', async () => {
    server.use(
      ...sessionHandlers(sessionFor('admin'), { ...open, recovery_passphrase_set: false, next_step: 'passphrase' }),
      http.post('/api/v1/setup/recovery-passphrase', () => errorResponse(422, 'ALC-SET-0010', 'setup.passphrase_too_weak')),
    );
    const { i18n } = await renderRoute('/setup');
    await screen.findByRole('heading', { name: 'Choose a recovery passphrase' });
    await userEvent.type(screen.getByLabelText('Recovery passphrase'), 'correct horse battery staple');
    await userEvent.type(screen.getByLabelText('Repeat the passphrase'), 'correct horse battery staple');
    await userEvent.click(screen.getByLabelText('I stored the passphrase safely'));
    await userEvent.click(screen.getByRole('button', { name: 'Save passphrase' }));
    expect(i18n.exists('errors.setup.passphrase_too_weak.title')).toBe(true);
    // The page's passphrase warning is an alert too; the refusal is the one with the catalogue title.
    await waitFor(() =>
      expect(screen.getAllByRole('alert').some((a) => a.textContent?.includes(i18n.t('errors.setup.passphrase_too_weak.title')))).toBe(true),
    );
  });

  it.each([
    ['en', 'en-US', ['HTTPS certificate', 'Mail server (optional)', 'Choose a recovery passphrase', 'Add a license'], 'Back'],
    ['tr', 'tr-TR', ['HTTPS sertifikası', 'E-posta sunucusu (isteğe bağlı)', 'Kurtarma parolası belirleyin', 'Lisans ekleyin'], 'Geri'],
  ])('renders every new step and its done state in %s without a raw key', async (lang, language, [https, mail, passphrase, license], back) => {
    server.use(
      ...sessionHandlers(sessionFor('admin', lang), { ...open, https_chosen: true, mail_chosen: true, license_chosen: true, next_step: 'platform' }),
      http.get('/api/v1/settings/smtp', () => HttpResponse.json(smtpFixture)),
    );
    await renderRoute('/setup', { languages: [language] });
    for (const heading of [license, mail, https, passphrase]) {
      await screen.findAllByRole('heading', { level: 2 });
      await userEvent.click(screen.getByRole('button', { name: back }));
      expect(await screen.findByRole('heading', { name: heading })).toBeInTheDocument();
      // The HTTPS step reads the certificate first.
      if (heading === https) await screen.findByTestId('https-done');
      expectNoRawKeys();
    }
  });
});

describe('setup wizard in the design\'s setup shell', () => {
  it('keeps "Set up Alice" as the only h1 and each step title as an h2 inside the setup shell', async () => {
    server.use(...freshSetupHandlers());
    await renderRoute('/setup');
    expect(await screen.findByRole('heading', { level: 1, name: 'Set up Alice' })).toBeVisible();
    expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
    expect(screen.getByRole('heading', { level: 2, name: 'Enter the setup code' })).toBeVisible();
    expect(rail()).toBeVisible();
    expect(screen.getByRole('main')).toContainElement(rail());
    expect(screen.getByText('Setup', { selector: '.mantine-Badge-label' })).toBeInTheDocument();
  });

  it('rail marks the step resumed from next_step and Back sits in the step’s actions row', async () => {
    server.use(...adminSetupHandlers({ next_step: 'mail' }));
    await renderRoute('/setup');
    await screen.findByRole('heading', { level: 2, name: 'Mail server (optional)' });
    expect(within(rail()).getByText('Mail server').closest('li')).toHaveAttribute('aria-current', 'step');
    const back = screen.getByTestId('setup-back');
    const skip = screen.getByTestId('setup-skip');
    expect(back.compareDocumentPosition(skip) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(back.parentElement).toBe(skip.parentElement);
  });

  it('offers the language toggle only on the setup code step; the theme toggle stays', async () => {
    server.use(
      ...freshSetupHandlers(),
      http.post('/api/v1/setup/session', () => HttpResponse.json({ csrf_token: 'setup-csrf' })),
    );
    await renderRoute('/setup');
    await screen.findByRole('heading', { level: 2, name: 'Enter the setup code' });
    expect(screen.getByRole('button', { name: 'Switch color mode' })).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Türkçe' }));
    expect(await screen.findByRole('heading', { level: 1, name: 'Alice kurulumu' })).toBeInTheDocument();
    expect(within(screen.getByRole('list', { name: 'Kurulum adımları' })).getByText('Kurulum kodu ve dil')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'English' }));
    await enterCode();
    await screen.findByRole('heading', { level: 2, name: 'Choose your language' });
    expect(screen.queryByRole('button', { name: 'Türkçe' })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Switch color mode' })).toBeInTheDocument();
    // The language step is still the first rail item, and nothing is done yet.
    expect(within(rail()).getByText('Setup code & language').closest('li')).toHaveAttribute('aria-current', 'step');
    expect(within(rail()).queryAllByText('Done')).toHaveLength(0);
  });

  it('has no Back before the HTTPS step and moves the rail only with the wizard’s own buttons', async () => {
    server.use(...adminSetupHandlers({ recovery_passphrase_set: false, https_chosen: false, next_step: 'passphrase' }));
    await renderRoute('/setup');
    await screen.findByRole('heading', { level: 2, name: 'Choose a recovery passphrase' });
    expect(screen.queryByTestId('setup-back')).not.toBeInTheDocument();
    const current = within(rail()).getByText('Recovery passphrase').closest('li');
    expect(current).toHaveAttribute('aria-current', 'step');
    // Clicking a later rail item goes nowhere: the passphrase is still required.
    await userEvent.click(within(rail()).getByText('License'));
    expect(screen.getByRole('heading', { level: 2, name: 'Choose a recovery passphrase' })).toBeInTheDocument();
    expect(current).toHaveAttribute('aria-current', 'step');
    expect(screen.getByRole('button', { name: 'Save passphrase' })).toBeDisabled();
  });

  it.each([
    ['https', 'HTTPS certificate', 'HTTPS certificate', { https_chosen: false, next_step: 'https' }],
    ['license', 'Add a license', 'License', { mail_chosen: true, next_step: 'license' }],
    ['platform', 'Connect your servers', 'First server', { mail_chosen: true, license_chosen: true, next_step: 'platform' }],
  ] as const)('puts Back first in the actions row of the %s step', async (_step, heading, item, overrides) => {
    server.use(...adminSetupHandlers(overrides as Partial<SetupStatus>));
    await renderRoute('/setup');
    await screen.findByRole('heading', { level: 2, name: heading });
    expect(within(rail()).getByText(item).closest('li')).toHaveAttribute('aria-current', 'step');
    const back = screen.getByTestId('setup-back');
    expect(back).toHaveTextContent('Back');
    expect(back.parentElement!.firstElementChild).toBe(back);
  });

  it('puts Back first in the actions row of the last step and marks every rail item done', async () => {
    server.use(...adminSetupHandlers({ mail_chosen: true, license_chosen: true, next_step: 'platform' }));
    await renderRoute('/setup');
    await screen.findByRole('heading', { level: 2, name: 'Connect your servers' });
    await userEvent.click(screen.getByRole('button', { name: 'Continue' }));
    await screen.findByRole('heading', { level: 2, name: 'Alice is ready' });
    const back = screen.getByTestId('setup-back');
    expect(back.parentElement!.firstElementChild).toBe(back);
    expect(within(back.parentElement!).getByRole('button', { name: 'Go to the dashboard' })).toBeInTheDocument();
    for (const li of within(rail()).getAllByRole('listitem')) expect(li).toHaveTextContent('Done');
  });
});
