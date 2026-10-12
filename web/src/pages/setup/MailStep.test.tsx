import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import type { SetupStatus } from '../../api/types';
import { errorResponse, httpsInfoFixture, licenseDetailFixture, sessionFor, sessionHandlers, smtpFixture } from '../../test/fixtures';
import { expectNoRawKeys } from '../../test/i18nAssert';
import { renderRoute } from '../../test/render';
import { server } from '../../test/server';
import settings from '../../components/settings/settings.module.css';

const atMail: SetupStatus = {
  admin_exists: true,
  recovery_passphrase_set: true,
  license_chosen: false,
  completed: false,
  default_locale: 'en',
  https_chosen: true,
  mail_chosen: false,
  next_step: 'mail',
};

describe('wizard mail step', () => {
  it('reuses the mail settings form: a saved mail server lets the wizard continue', async () => {
    let status = { ...atMail };
    let saved: unknown;
    server.use(
      http.get('/api/v1/setup/status', () => HttpResponse.json(status)),
      http.get('/api/v1/auth/session', () => HttpResponse.json(sessionFor('admin'))),
      http.get('/api/v1/settings/smtp', () => HttpResponse.json(smtpFixture)),
      http.put('/api/v1/settings/smtp', async ({ request }) => {
        saved = await request.json();
        status = { ...status, mail_chosen: true, next_step: 'license' };
        return HttpResponse.json({ ...smtpFixture, configured: true, host: 'mail.example.test', from: 'alice@example.test', version: 1 });
      }),
    );
    await renderRoute('/setup');
    expect(await screen.findByRole('heading', { name: 'Mail server (optional)' })).toBeInTheDocument();
    // Nothing saved yet: Continue explains what is missing.
    await userEvent.click(await screen.findByRole('button', { name: 'Continue' }));
    expect(await screen.findByText('Save the mail settings first, or choose Skip.')).toBeInTheDocument();
    // One separator row only: the wizard's actions row has the rule, the form's save row does not.
    expect(screen.getByRole('button', { name: 'Save mail settings' }).parentElement).toHaveClass(settings.formActions, settings.formActionsPlain);

    await userEvent.type(screen.getByLabelText('Mail server'), 'mail.example.test');
    await userEvent.type(screen.getByLabelText('Sender address'), 'alice@example.test');
    await userEvent.click(screen.getByRole('button', { name: 'Save mail settings' }));
    await waitFor(() => expect(saved).toMatchObject({ host: 'mail.example.test', from: 'alice@example.test' }));
    await userEvent.click(screen.getByRole('button', { name: 'Continue' }));
    expect(await screen.findByRole('heading', { name: 'Add a license' })).toBeInTheDocument();
    expect(screen.queryByText('Save the mail settings first, or choose Skip.')).not.toBeInTheDocument();
  });

  it('skips the mail server and goes to the license step', async () => {
    let skipped = 0;
    let status = { ...atMail };
    server.use(
      http.get('/api/v1/setup/status', () => HttpResponse.json(status)),
      http.get('/api/v1/auth/session', () => HttpResponse.json(sessionFor('admin'))),
      http.get('/api/v1/settings/smtp', () => HttpResponse.json(smtpFixture)),
      http.post('/api/v1/setup/mail/skip', () => {
        skipped += 1;
        status = { ...status, mail_chosen: true, next_step: 'license' };
        return HttpResponse.json(status);
      }),
      http.get('/api/v1/license', () => HttpResponse.json(licenseDetailFixture)),
    );
    await renderRoute('/setup');
    await userEvent.click(await screen.findByTestId('setup-skip'));
    expect(await screen.findByRole('heading', { name: 'Add a license' })).toBeInTheDocument();
    expect(skipped).toBe(1);
  });

  it('explains a refused skip and stays', async () => {
    server.use(
      ...sessionHandlers(sessionFor('admin'), atMail),
      http.get('/api/v1/settings/smtp', () => HttpResponse.json(smtpFixture)),
      http.post('/api/v1/setup/mail/skip', () => errorResponse(403, 'ALC-AUTH-0002', 'auth.forbidden')),
    );
    await renderRoute('/setup');
    await userEvent.click(await screen.findByTestId('setup-skip'));
    expect(await screen.findByRole('alert')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Mail server (optional)' })).toBeInTheDocument();
  });

  it('goes back to the HTTPS step in its done state', async () => {
    server.use(
      ...sessionHandlers(sessionFor('admin'), atMail),
      http.get('/api/v1/settings/smtp', () => HttpResponse.json(smtpFixture)),
      http.get('/api/v1/settings/https', () => HttpResponse.json(httpsInfoFixture({ temporary: true }))),
    );
    await renderRoute('/setup');
    await screen.findByRole('heading', { name: 'Mail server (optional)' });
    await userEvent.click(screen.getByTestId('setup-back'));
    expect(await screen.findByRole('heading', { name: 'HTTPS certificate' })).toBeInTheDocument();
    expect(await screen.findByText(/You chose to keep the temporary certificate/)).toBeInTheDocument();
    // From the done state the wizard goes on to the mail step again.
    await userEvent.click(screen.getByRole('button', { name: 'Continue' }));
    expect(await screen.findByRole('heading', { name: 'Mail server (optional)' })).toBeInTheDocument();
  });

  it('is shown in Turkish without a raw key', async () => {
    server.use(...sessionHandlers(sessionFor('admin', 'tr'), atMail), http.get('/api/v1/settings/smtp', () => HttpResponse.json(smtpFixture)));
    await renderRoute('/setup', { languages: ['tr-TR'] });
    expect(await screen.findByRole('heading', { name: 'E-posta sunucusu (isteğe bağlı)' })).toBeInTheDocument();
    expect(await screen.findByRole('button', { name: 'Atla' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Geri' })).toBeInTheDocument();
    expectNoRawKeys();
  });
});
