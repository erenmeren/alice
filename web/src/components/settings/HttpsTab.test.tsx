import { readFileSync } from 'node:fs';
import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { formatDateTime } from '../../datetime';
import { adminSession, errorResponse, httpsInfoFixture, sessionFor, sessionHandlers } from '../../test/fixtures';
import { expectNoRawKeys } from '../../test/i18nAssert';
import { renderRoute } from '../../test/render';
import { server } from '../../test/server';
import classes from './settings.module.css';

const steppedUp = { ...adminSession, stepup_until: '2099-01-01T00:00:00Z' };
const steppedUpTr = { ...sessionFor('admin', 'tr'), stepup_until: '2099-01-01T00:00:00Z' };
const pem = (text: string, name: string) => new File([text], name, { type: 'application/x-pem-file' });

describe('HttpsTab', () => {
  it('shows the certificate in use with its data never translated', async () => {
    server.use(...sessionHandlers(steppedUp));
    await renderRoute('/settings?tab=https');
    expect(await screen.findByText('Alice is using a temporary certificate. Browsers will warn until you upload your own.')).toBeInTheDocument();
    const subject = screen.getByText('CN=alice.example.test');
    expect(subject.tagName).toBe('CODE');
    expect(screen.getByText('alice.example.test, 10.0.0.5').tagName).toBe('CODE');
    expect(screen.getByText('ab'.repeat(32))).toHaveAttribute('translate', 'no');
    // The certificate in use is the design's fact list: a term and its value, the data in <code>.
    const facts = screen.getByLabelText('Certificate in use');
    expect(facts.tagName).toBe('DL');
    const until = within(facts).getByText('Valid until');
    expect(until.tagName).toBe('DT');
    expect(until.nextElementSibling).toHaveTextContent(formatDateTime('2027-10-01T00:00:00Z', 'en'));
    expect(within(facts).getByText('Fingerprint (SHA-256)').nextElementSibling).toHaveTextContent('ab'.repeat(32));
    expect(within(facts).getByText('Subject').nextElementSibling?.querySelector('code')).toHaveTextContent('CN=alice.example.test');
    expect(screen.getByTestId('https-temporary')).toHaveAttribute('role', 'note');
    // The two formats are the design's bordered choice rows; the upload sits in the form's actions row.
    for (const name of ['PEM: a certificate file and a key file', 'PFX (PKCS#12): one file with a password']) {
      expect(screen.getByRole('radio', { name }).closest(`.${classes.checkOption}`)).not.toBeNull();
    }
    expect(screen.getByRole('button', { name: 'Upload certificate' }).closest(`.${classes.formActions}`)).not.toBeNull();
    expect(screen.getByRole('button', { name: 'Upload certificate' }).parentElement).not.toHaveClass(classes.formActionsPlain);
    expect(screen.getByTestId('https-upload-form')).toBeInTheDocument();
    expectNoRawKeys();
  });

  it('makes the whole bordered choice row toggle its input (like the design\'s <label class="check-option">) and has a plain actions row for the wizard', () => {
    // jsdom cannot click the padding; the rule is pinned: the row is the containing block and the label's ::after
    // covers it, so a click anywhere in the row is a click on the label.
    const css = readFileSync('src/components/settings/settings.module.css', 'utf8').replace(/\/\*[\s\S]*?\*\//g, '');
    const rule = (selector: string) => {
      for (const m of css.matchAll(/([^{}]+)\{([^{}]*)\}/g)) if (m[1].split(',').map((x) => x.trim()).includes(selector)) return m[2];
      return '';
    };
    // The wizard's plain actions row (the wizard draws the one rule).
    expect(rule('.formActionsPlain')).toMatch(/border-top:\s*0/);
    expect(rule('.formActionsPlain')).toMatch(/padding-top:\s*0/);
    expect(css.indexOf('.formActionsPlain {')).toBeGreaterThan(css.indexOf('.formActions {'));
    expect(rule('.checkOption')).toMatch(/position:\s*relative/);
    expect(rule('.checkOption')).toMatch(/cursor:\s*pointer/);
    for (const label of ['.mantine-Checkbox-label', '.mantine-Radio-label']) {
      const after = rule(`.checkOption :global(${label})::after`);
      expect(after).toMatch(/content:\s*''/);
      expect(after).toMatch(/position:\s*absolute/);
      expect(after).toMatch(/inset:\s*0/);
    }
  });

  it('uploads a certificate and shows the new one without a reload', async () => {
    let body: unknown;
    server.use(
      ...sessionHandlers(steppedUp),
      http.put('/api/v1/settings/https', async ({ request }) => {
        body = await request.json();
        return HttpResponse.json(httpsInfoFixture({ temporary: false, subject: 'CN=alice.corp.example', warnings: [] }));
      }),
    );
    await renderRoute('/settings?tab=https');
    const form = await screen.findByTestId('https-upload-form');
    await userEvent.upload(within(form).getByLabelText('Certificate file (PEM)'), pem('CERT', 'a.crt'));
    await userEvent.upload(within(form).getByLabelText('Private key file (PEM)'), pem('KEY', 'a.key'));
    await userEvent.click(within(form).getByRole('button', { name: 'Upload certificate' }));
    expect(await screen.findByText('The new certificate is in use.')).toBeInTheDocument();
    // No warnings: the notice is green (success).
    expect(screen.getByText('The new certificate is in use.').closest('[role="status"]')?.getAttribute('style')).toContain('--alert-bg: var(--alice-success-soft)');
    expect(body).toEqual({ cert_pem: 'CERT', key_pem: 'KEY' });
    expect(await screen.findByText('Alice is using your own certificate.')).toBeInTheDocument();
    expect(screen.getByText('CN=alice.corp.example')).toBeInTheDocument();
    expect(screen.queryByText(/Alice is using a temporary certificate/)).not.toBeInTheDocument();
  });

  it('shows the catalogue title of a wrong PFX password', async () => {
    server.use(...sessionHandlers(steppedUp), http.put('/api/v1/settings/https', () => errorResponse(422, 'ALC-TLS-0004', 'tls.pfx_password')));
    const { i18n } = await renderRoute('/settings?tab=https');
    const form = await screen.findByTestId('https-upload-form');
    await userEvent.click(within(form).getByRole('radio', { name: 'PFX (PKCS#12): one file with a password' }));
    await userEvent.upload(within(form).getByLabelText('PFX file'), new File([new Uint8Array([9])], 'a.pfx'));
    await userEvent.type(within(form).getByLabelText('PFX password'), 'wrong');
    await userEvent.click(within(form).getByRole('button', { name: 'Upload certificate' }));
    expect(i18n.exists('errors.tls.pfx_password.title')).toBe(true);
    expect(await screen.findByRole('alert')).toHaveTextContent(i18n.t('errors.tls.pfx_password.title'));
    expect(within(form).getByLabelText('PFX password')).toHaveValue('');
  });

  it('keeps the chosen files after a dropped connection, so the upload can be sent again', async () => {
    let calls = 0;
    server.use(
      ...sessionHandlers(steppedUp),
      http.put('/api/v1/settings/https', () => {
        calls += 1;
        return calls === 1 ? HttpResponse.error() : HttpResponse.json(httpsInfoFixture({ temporary: false, warnings: [] }));
      }),
    );
    await renderRoute('/settings?tab=https');
    const form = await screen.findByTestId('https-upload-form');
    await userEvent.upload(within(form).getByLabelText('Certificate file (PEM)'), pem('CERT', 'a.crt'));
    await userEvent.upload(within(form).getByLabelText('Private key file (PEM)'), pem('KEY', 'a.key'));
    await userEvent.click(within(form).getByRole('button', { name: 'Upload certificate' }));
    expect(await screen.findByText('Alice cannot be reached.', {}, { timeout: 5000 })).toBeInTheDocument();
    await userEvent.click(within(form).getByRole('button', { name: 'Upload certificate' }));
    expect(await screen.findByText('The new certificate is in use.', {}, { timeout: 5000 })).toBeInTheDocument();
    expect(calls).toBe(2);
  });

  it('says when the browser cannot read a chosen file, and sends nothing', async () => {
    let called = false;
    server.use(
      ...sessionHandlers(steppedUp),
      http.put('/api/v1/settings/https', () => {
        called = true;
        return HttpResponse.json(httpsInfoFixture());
      }),
    );
    await renderRoute('/settings?tab=https');
    const form = await screen.findByTestId('https-upload-form');
    const broken = pem('KEY', 'a.key');
    broken.text = () => Promise.reject(new Error('gone'));
    await userEvent.upload(within(form).getByLabelText('Certificate file (PEM)'), pem('CERT', 'a.crt'));
    await userEvent.upload(within(form).getByLabelText('Private key file (PEM)'), broken);
    await userEvent.click(within(form).getByRole('button', { name: 'Upload certificate' }));
    expect(await screen.findByText('The file could not be read in the browser. Choose it again.')).toBeInTheDocument();
    expect(called).toBe(false);
  });

  it('shows why the certificate information cannot be read', async () => {
    server.use(...sessionHandlers(steppedUp), http.get('/api/v1/settings/https', () => errorResponse(403, 'ALC-AUTH-0002', 'auth.forbidden')));
    await renderRoute('/settings?tab=https');
    expect(await screen.findByRole('alert')).toBeInTheDocument();
  });

  it('is shown in Turkish without a raw key', async () => {
    server.use(...sessionHandlers(steppedUpTr));
    await renderRoute('/settings?tab=https', { languages: ['tr-TR'] });
    expect(await screen.findByText(/Alice geçici bir sertifika kullanıyor/)).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'HTTPS sertifikası' })).toBeInTheDocument();
    expectNoRawKeys();
  });
});
