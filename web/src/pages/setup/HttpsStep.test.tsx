import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import type { SetupStatus } from '../../api/types';
import { errorResponse, httpsInfoFixture, sessionFor, sessionHandlers, smtpFixture } from '../../test/fixtures';
import { expectNoRawKeys } from '../../test/i18nAssert';
import { renderRoute } from '../../test/render';
import { server } from '../../test/server';

const atHttps: SetupStatus = {
  admin_exists: true,
  recovery_passphrase_set: true,
  license_chosen: false,
  completed: false,
  default_locale: 'en',
  https_chosen: false,
  mail_chosen: false,
  next_step: 'https',
};

const pem = (text: string, name: string) => new File([text], name, { type: 'application/x-pem-file' });

async function choosePfx(password: string) {
  await userEvent.click(screen.getByRole('radio', { name: 'PFX (PKCS#12): one file with a password' }));
  await userEvent.upload(screen.getByLabelText('PFX file'), new File([new Uint8Array([1, 2, 3])], 'site.pfx', { type: 'application/x-pkcs12' }));
  await userEvent.type(screen.getByLabelText('PFX password'), password);
}

describe('wizard HTTPS step', () => {
  it('uploads a PEM pair, shows the new certificate is in use and its warnings, then continues', async () => {
    let body: unknown;
    let status = { ...atHttps };
    server.use(
      http.get('/api/v1/setup/status', () => HttpResponse.json(status)),
      http.get('/api/v1/auth/session', () => HttpResponse.json(sessionFor('admin'))),
      http.put('/api/v1/settings/https', async ({ request }) => {
        body = await request.json();
        status = { ...status, https_chosen: true, next_step: 'mail' };
        return HttpResponse.json(httpsInfoFixture({ temporary: false, warnings: ['name_mismatch', 'chain_incomplete', 'expires_soon', 'new_warning'] }));
      }),
      http.get('/api/v1/settings/smtp', () => HttpResponse.json(smtpFixture)),
    );
    await renderRoute('/setup');
    expect(await screen.findByRole('heading', { name: 'HTTPS certificate' })).toBeInTheDocument();
    expect(await screen.findByText(/Alice is using a temporary certificate/)).toBeInTheDocument();
    expect(screen.getByTestId('https-keep-temporary')).toHaveTextContent('Keep the temporary certificate');
    expectNoRawKeys();

    await userEvent.upload(screen.getByLabelText('Certificate file (PEM)'), pem('certificate file text', 'site.crt'));
    await userEvent.upload(screen.getByLabelText('Private key file (PEM)'), pem('key file text', 'site.key'));
    await userEvent.click(screen.getByRole('button', { name: 'Upload certificate' }));
    expect(await screen.findByText('The new certificate is in use.')).toBeInTheDocument();
    expect(body).toEqual({ cert_pem: 'certificate file text', key_pem: 'key file text' });
    expect(screen.getByText(/None of the names in the certificate matches/)).toBeInTheDocument();
    expect(screen.getByText(/The chain to a trusted authority is incomplete/)).toBeInTheDocument();
    expect(screen.getByText('The certificate expires within 30 days.')).toBeInTheDocument();
    expect(screen.getByText(/a problem with the certificate that this page cannot describe/)).toBeInTheDocument();
    // The chosen files are dropped once the server answered.
    expect((screen.getByLabelText('Private key file (PEM)') as HTMLInputElement).files).toHaveLength(0);

    await userEvent.click(screen.getByRole('button', { name: 'Continue' }));
    expect(await screen.findByRole('heading', { name: 'Mail server (optional)' })).toBeInTheDocument();
  });

  it('uploads a PFX with its password and clears the password after the request', async () => {
    let body: unknown;
    server.use(
      ...sessionHandlers(sessionFor('admin'), atHttps),
      http.put('/api/v1/settings/https', async ({ request }) => {
        body = await request.json();
        return HttpResponse.json(httpsInfoFixture({ temporary: false, warnings: [] }));
      }),
    );
    await renderRoute('/setup');
    await screen.findByRole('heading', { name: 'HTTPS certificate' });
    await choosePfx('pfx-secret');
    await userEvent.click(screen.getByRole('button', { name: 'Upload certificate' }));
    expect(await screen.findByText('The new certificate is in use.')).toBeInTheDocument();
    expect(body).toEqual({ pfx_base64: 'AQID', pfx_password: 'pfx-secret' });
    expect(screen.getByLabelText('PFX password')).toHaveValue('');
    const stored = JSON.stringify({ ...localStorage }) + JSON.stringify({ ...sessionStorage });
    expect(stored).not.toContain('pfx-secret');
  });

  it('shows the catalogue title of a refused certificate and clears the password', async () => {
    server.use(
      ...sessionHandlers(sessionFor('admin'), atHttps),
      http.put('/api/v1/settings/https', () => errorResponse(422, 'ALC-TLS-0001', 'tls.key_mismatch')),
    );
    const { i18n } = await renderRoute('/setup');
    await screen.findByRole('heading', { name: 'HTTPS certificate' });
    await choosePfx('pfx-secret');
    await userEvent.click(screen.getByRole('button', { name: 'Upload certificate' }));
    expect(i18n.exists('errors.tls.key_mismatch.title')).toBe(true);
    expect(await screen.findByRole('alert')).toHaveTextContent(i18n.t('errors.tls.key_mismatch.title'));
    expect(screen.getByLabelText('PFX password')).toHaveValue('');
    expect(screen.queryByText('The new certificate is in use.')).not.toBeInTheDocument();
  });

  it('asks for the files before sending anything', async () => {
    let called = false;
    server.use(
      ...sessionHandlers(sessionFor('admin'), atHttps),
      http.put('/api/v1/settings/https', () => {
        called = true;
        return HttpResponse.json(httpsInfoFixture());
      }),
    );
    await renderRoute('/setup');
    await screen.findByRole('heading', { name: 'HTTPS certificate' });
    await userEvent.click(screen.getByRole('button', { name: 'Upload certificate' }));
    expect(await screen.findByText('Choose the certificate file and the key file.')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('radio', { name: 'PFX (PKCS#12): one file with a password' }));
    await userEvent.click(screen.getByRole('button', { name: 'Upload certificate' }));
    expect(await screen.findByText('Choose the PFX file.')).toBeInTheDocument();
    expect(called).toBe(false);
  });

  it('keeps the temporary certificate and goes on to the mail step', async () => {
    let status = { ...atHttps };
    let kept = 0;
    server.use(
      http.get('/api/v1/setup/status', () => HttpResponse.json(status)),
      http.get('/api/v1/auth/session', () => HttpResponse.json(sessionFor('admin'))),
      http.post('/api/v1/setup/https/keep-temporary', () => {
        kept += 1;
        status = { ...status, https_chosen: true, next_step: 'mail' };
        return HttpResponse.json(status);
      }),
      http.get('/api/v1/settings/smtp', () => HttpResponse.json(smtpFixture)),
    );
    await renderRoute('/setup');
    await userEvent.click(await screen.findByTestId('https-keep-temporary'));
    expect(await screen.findByRole('heading', { name: 'Mail server (optional)' })).toBeInTheDocument();
    expect(kept).toBe(1);
  });

  it('asks for a code when keeping the temporary certificate needs a fresh step-up', async () => {
    let attempts = 0;
    server.use(
      ...sessionHandlers(sessionFor('admin'), atHttps),
      http.post('/api/v1/setup/https/keep-temporary', () => {
        attempts += 1;
        return attempts === 1 ? errorResponse(403, 'ALC-AUTH-0003', 'auth.stepup_required') : HttpResponse.json({ ...atHttps, https_chosen: true, next_step: 'mail' });
      }),
      http.post('/api/v1/auth/stepup', () => HttpResponse.json(sessionFor('admin'))),
      http.get('/api/v1/settings/smtp', () => HttpResponse.json(smtpFixture)),
    );
    await renderRoute('/setup');
    await userEvent.click(await screen.findByTestId('https-keep-temporary'));
    await screen.findByRole('dialog', { name: "Confirm it's you" });
    await userEvent.type(screen.getByLabelText('6-digit code'), '654321');
    await userEvent.click(screen.getByRole('button', { name: 'Confirm' }));
    expect(await screen.findByRole('heading', { name: 'Mail server (optional)' })).toBeInTheDocument();
    await waitFor(() => expect(attempts).toBe(2));
  });

  it('explains a refused keep-temporary answer and stays', async () => {
    server.use(
      ...sessionHandlers(sessionFor('admin'), atHttps),
      http.post('/api/v1/setup/https/keep-temporary', () => errorResponse(403, 'ALC-AUTH-0002', 'auth.forbidden')),
    );
    await renderRoute('/setup');
    await userEvent.click(await screen.findByTestId('https-keep-temporary'));
    expect(await screen.findByRole('alert')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'HTTPS certificate' })).toBeInTheDocument();
  });

  it('is shown in Turkish without a raw key', async () => {
    server.use(...sessionHandlers(sessionFor('admin', 'tr'), atHttps));
    await renderRoute('/setup', { languages: ['tr-TR'] });
    expect(await screen.findByRole('heading', { name: 'HTTPS sertifikası' })).toBeInTheDocument();
    expect(await screen.findByText(/Alice geçici bir sertifika kullanıyor/)).toBeInTheDocument();
    expect(screen.getByTestId('https-keep-temporary')).toHaveTextContent('Geçici sertifikayı kullanmaya devam et');
    expectNoRawKeys();
  });
});
