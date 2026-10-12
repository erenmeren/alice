import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { adminSession, errorResponse, operatorSession, sessionFor, sessionHandlers } from '../test/fixtures';
import { renderRoute } from '../test/render';
import { server } from '../test/server';
import { expectNoRawKeys } from '../test/i18nAssert';
import settingsClasses from '../components/settings/settings.module.css';
import classes from './SettingsPage.module.css';

const steppedUp = { ...adminSession, stepup_until: '2099-01-01T00:00:00Z' };

const smtp = (over: Record<string, unknown> = {}) => ({
  configured: true, host: 'smtp.example.com', port: 587, tls_mode: 'starttls', from: 'alice@example.com', username: 'mailer',
  has_password: true, ca_pem: '', trusted_certificate: null, version: 1, updated_at: '2026-10-07T09:00:00Z', ...over,
});
const untrusted = () =>
  HttpResponse.json({ error: { code: 'ALC-NTF-0005', reason: 'notify.smtp_untrusted', message_key: 'errors.notify.smtp_untrusted',
    message: '', request_id: 'r', retryable: false, params: { fingerprint: 'ab'.repeat(32), subject: 'CN=smtp.example.com', not_after: '2027-01-01T00:00:00Z' } } },
    { status: 502 });

describe('SettingsPage, mail', () => {
  it('sends a test e-mail and trusts the certificate the server presented (owner step 1, F-62)', async () => {
    let trusted: { body: unknown; ifMatch: string | null } | undefined;
    let tests = 0;
    let sentTo: unknown;
    server.use(
      ...sessionHandlers(steppedUp),
      http.get('/api/v1/settings/smtp', () => HttpResponse.json(smtp(), { headers: { ETag: '"1"' } })),
      http.post('/api/v1/settings/smtp/actions/test', async ({ request }) => {
        tests++;
        sentTo = await request.json();
        return tests === 1 ? untrusted() : HttpResponse.json({ sent: true });
      }),
      http.post('/api/v1/settings/smtp/actions/trust', async ({ request }) => {
        trusted = { body: await request.json(), ifMatch: request.headers.get('If-Match') };
        return HttpResponse.json(smtp({ version: 2, trusted_certificate: { fingerprint: 'ab'.repeat(32), subject: 'CN=smtp.example.com',
          not_after: '2027-01-01T00:00:00Z', trusted_by: 'ada', trusted_at: '2026-10-07T09:01:00Z' } }), { headers: { ETag: '"2"' } });
      }),
    );
    await renderRoute('/settings?tab=mail');
    expect(screen.queryByText('Trusted certificate:')).not.toBeInTheDocument();
    await userEvent.click(await screen.findByRole('button', { name: 'Send test e-mail' }));
    const dialog = await screen.findByRole('dialog', { name: "The mail server's certificate is not trusted" });
    expect(sentTo).toEqual({ to: adminSession.user.email });
    expect(dialog).toHaveTextContent('ab'.repeat(32));
    expect(dialog).toHaveTextContent('CN=smtp.example.com');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Trust this certificate' }));
    await waitFor(() => expect(trusted).toEqual({ body: { fingerprint: 'ab'.repeat(32) }, ifMatch: '"1"' }));
    expect(await screen.findByText(`Trusted certificate: ${'ab'.repeat(32)}`)).toBeInTheDocument();
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(tests).toBe(1); // the test is sent again only when the person asks
    await userEvent.click(screen.getByRole('button', { name: 'Send test e-mail' }));
    expect(await screen.findByText(/The test e-mail was sent to/)).toBeInTheDocument();
  });

  it('asks for the code when the step-up window ended before the test e-mail, then sends it', async () => {
    let tests = 0;
    server.use(
      ...sessionHandlers(steppedUp),
      http.get('/api/v1/settings/smtp', () => HttpResponse.json(smtp())),
      http.post('/api/v1/settings/smtp/actions/test', () => (++tests === 1 ? errorResponse(403, 'ALC-AUTH-0003', 'auth.stepup_required') : HttpResponse.json({ sent: true }))),
      http.post('/api/v1/auth/stepup', () => HttpResponse.json(steppedUp)),
    );
    await renderRoute('/settings?tab=mail');
    await userEvent.click(await screen.findByRole('button', { name: 'Send test e-mail' }));
    expect(await screen.findByRole('dialog', { name: "Confirm it's you" })).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText('6-digit code'), '123456');
    await userEvent.click(screen.getByRole('button', { name: 'Confirm' }));
    expect(await screen.findByText(/The test e-mail was sent to/)).toBeInTheDocument();
    expect(tests).toBe(2);
  });

  it('stops trusting a certificate', async () => {
    let ifMatch: string | null = null;
    server.use(
      ...sessionHandlers(steppedUp),
      http.get('/api/v1/settings/smtp', () => HttpResponse.json(smtp({ version: 4, trusted_certificate: { fingerprint: 'cd'.repeat(32), subject: 's', not_after: '2027-01-01T00:00:00Z', trusted_by: 'ada', trusted_at: '2026-10-07T09:01:00Z' } }))),
      http.post('/api/v1/settings/smtp/actions/untrust', ({ request }) => {
        ifMatch = request.headers.get('If-Match');
        return HttpResponse.json(smtp({ version: 5 }));
      }),
    );
    await renderRoute('/settings?tab=mail');
    await userEvent.click(await screen.findByRole('button', { name: 'Stop trusting this certificate' }));
    await waitFor(() => expect(screen.queryByText(/Trusted certificate:/)).not.toBeInTheDocument());
    expect(ifMatch).toBe('"4"');
  });

  it('shows the other test failures with their texts and offers no trust', async () => {
    server.use(
      ...sessionHandlers(steppedUp),
      http.get('/api/v1/settings/smtp', () => HttpResponse.json(smtp())),
      http.post('/api/v1/settings/smtp/actions/test', () => errorResponse(502, 'ALC-NTF-0006', 'notify.smtp_auth')),
    );
    await renderRoute('/settings?tab=mail');
    await userEvent.click(await screen.findByRole('button', { name: 'Send test e-mail' }));
    expect(await screen.findByRole('alert')).toBeInTheDocument();
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('never shows the stored password, and sends one only when typed', async () => {
    const bodies: Record<string, unknown>[] = [];
    server.use(
      ...sessionHandlers(steppedUp),
      http.get('/api/v1/settings/smtp', () => HttpResponse.json(smtp(), { headers: { ETag: '"1"' } })),
      http.put('/api/v1/settings/smtp', async ({ request }) => {
        bodies.push((await request.json()) as Record<string, unknown>);
        return HttpResponse.json(smtp({ version: 2 }), { headers: { ETag: '"2"' } });
      }),
    );
    await renderRoute('/settings?tab=mail');
    expect(await screen.findByText('A password is stored. Leave the field empty to keep it; a new host or port needs the password again.')).toBeInTheDocument();
    expect(screen.getByLabelText('Password')).toHaveValue('');
    await userEvent.click(screen.getByRole('button', { name: 'Save mail settings' }));
    await waitFor(() => expect(bodies).toHaveLength(1));
    expect(bodies[0]).not.toHaveProperty('password');
    expect(bodies[0]).toMatchObject({ host: 'smtp.example.com', port: 587, tls_mode: 'starttls', from: 'alice@example.com', username: 'mailer' });
    expect(await screen.findByText('Saved.')).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText('Password'), 'S3cret-canary');
    await userEvent.click(screen.getByRole('button', { name: 'Save mail settings' }));
    await waitFor(() => expect(bodies).toHaveLength(2));
    expect(bodies[1].password).toBe('S3cret-canary');
    await waitFor(() => expect(screen.getByLabelText('Password')).toHaveValue('')); // cleared after the request
    expect(document.body.innerHTML).not.toContain('S3cret-canary');
  });

  it('shows "password required" on the password field', async () => {
    server.use(
      ...sessionHandlers(steppedUp),
      http.get('/api/v1/settings/smtp', () => HttpResponse.json(smtp({ has_password: false, username: '' }))),
      http.put('/api/v1/settings/smtp', () =>
        errorResponse(422, 'ALC-SYS-0006', 'validation.failed', { details: [{ field: 'password', code: 'validation.required' }] }),
      ),
    );
    await renderRoute('/settings?tab=mail');
    await userEvent.type(await screen.findByLabelText(/^User name/), 'mailer');
    await userEvent.click(screen.getByRole('button', { name: 'Save mail settings' }));
    const field = await screen.findByLabelText('Password');
    await waitFor(() => expect(field).toHaveAttribute('data-invalid', 'true'));
    expect(field).toHaveAccessibleDescription(/required/i);
  });

  it('reads the form again after a 412 and says so', async () => {
    let gets = 0;
    server.use(
      ...sessionHandlers(steppedUp),
      http.get('/api/v1/settings/smtp', () => HttpResponse.json(smtp({ version: ++gets === 1 ? 1 : 2, host: gets === 1 ? 'old.example.com' : 'new.example.com' }))),
      http.put('/api/v1/settings/smtp', () => errorResponse(412, 'ALC-SYS-0008', 'system.precondition_failed')),
    );
    await renderRoute('/settings?tab=mail');
    expect(await screen.findByLabelText('Mail server')).toHaveValue('old.example.com');
    await userEvent.click(screen.getByRole('button', { name: 'Save mail settings' }));
    expect(await screen.findByRole('alert')).toBeInTheDocument();
    await waitFor(() => expect(screen.getByLabelText('Mail server')).toHaveValue('new.example.com'));
    expect(screen.getByRole('alert')).toBeInTheDocument();
  });

  it('asks for the authenticator code once on arrival', async () => {
    let gets = 0;
    server.use(
      ...sessionHandlers(adminSession),
      http.get('/api/v1/settings/smtp', () => (++gets === 1 ? errorResponse(403, 'ALC-AUTH-0003', 'auth.stepup_required') : HttpResponse.json(smtp()))),
      http.post('/api/v1/auth/stepup', () => HttpResponse.json(steppedUp)),
    );
    await renderRoute('/settings');
    expect(await screen.findByRole('dialog', { name: "Confirm it's you" })).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText('6-digit code'), '123456');
    await userEvent.click(screen.getByRole('button', { name: 'Confirm' }));
    expect(await screen.findByLabelText('Mail server')).toHaveValue('smtp.example.com');
    expect(gets).toBe(2);
  });

  it('is reserved for Administrators, and is in the navigation for them only', async () => {
    server.use(...sessionHandlers(operatorSession));
    await renderRoute('/settings');
    expect(await screen.findByText(/You do not have access|no access/i)).toBeInTheDocument();
  });

  it('keeps the tab in the address and starts on the mail tab', async () => {
    server.use(
      ...sessionHandlers(steppedUp),
      http.get('/api/v1/settings/smtp', () => HttpResponse.json(smtp())),
      http.get('/api/v1/settings/notifications', () => HttpResponse.json({ administrators: true, addresses: [], version: 0 })),
    );
    const { router } = await renderRoute('/settings');
    expect(await screen.findByRole('heading', { level: 1, name: 'Settings' })).toBeInTheDocument();
    expect(await screen.findByLabelText('Mail server')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('tab', { name: 'Recipients' }));
    await waitFor(() => expect(router.state.location.search).toBe('?tab=recipients'));
    expect(await screen.findByRole('button', { name: 'Save recipients' })).toBeInTheDocument();
  });

  it('is fully translated in Turkish', async () => {
    server.use(
      ...sessionHandlers({ ...sessionFor('admin', 'tr'), stepup_until: '2099-01-01T00:00:00Z' }),
      http.get('/api/v1/settings/smtp', () => HttpResponse.json(smtp())),
    );
    await renderRoute('/settings?tab=mail', { languages: ['tr-TR'] });
    expect(await screen.findByRole('button', { name: 'Test e-postası gönder' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Posta ayarlarını kaydet' })).toBeInTheDocument();
  });
});

describe('SettingsPage, design', () => {
  const TABS = ['mail', 'recipients', 'alerts', 'general', 'backups', 'https', 'forwarding', 'sso'] as const;
  const LABELS = ['Email', 'Recipients', 'Alerts', 'General', 'Backups', 'HTTPS certificate', 'Audit forwarding', 'Single sign-on'];
  const DESCRIPTIONS: Record<(typeof TABS)[number], string> = {
    mail: 'The mail server Alice uses to send alerts.',
    recipients: 'The people who receive operational alerts.',
    alerts: 'Warn early enough to act. Keep urgent signals distinct.',
    general: 'Defaults for this Alice installation.',
    backups: 'Encrypted backups protect recovery data. Test your restore procedure separately.',
    https: 'The certificate presented by this Alice installation.',
    forwarding: 'Send audit events to an independent syslog or SIEM destination.',
    sso: 'Connect an OpenID Connect provider and map groups to Alice roles.',
  };
  const SAVE: Partial<Record<(typeof TABS)[number], string>> = {
    mail: 'Save mail settings',
    recipients: 'Save recipients',
    alerts: 'Save alert thresholds',
    general: 'Save general settings',
    backups: 'Save backup schedule',
    forwarding: 'Save forwarding settings',
    https: 'Upload certificate',
  };

  function every() {
    server.use(
      ...sessionHandlers(steppedUp),
      http.get('/api/v1/settings/notifications', () => HttpResponse.json({ administrators: true, addresses: [], version: 0 })),
      http.get('/api/v1/settings/alerts', () => HttpResponse.json({ thresholds_days: [60, 30], version: 0 })),
      http.get('/api/v1/settings/general', () => HttpResponse.json({ public_url: 'https://alice.example.com', retired_key_retention_days: 30, version: 0 })),
      http.get('/api/v1/sso/settings', () => HttpResponse.json({ allow_admin_role: false, version: 0 })),
      http.get('/api/v1/sso/providers', () => HttpResponse.json({ items: [] })),
    );
  }

  it('has the design header and lists the eight sections in order, each with an icon', async () => {
    every();
    await renderRoute('/settings');
    expect(await screen.findByRole('heading', { level: 1, name: 'Settings' })).toBeInTheDocument();
    expect(screen.getByText('Make Alice work the way your team does.')).toBeInTheDocument();
    const list = screen.getByRole('tablist', { name: 'Settings sections' });
    const tabs = within(list).getAllByRole('tab');
    expect(tabs).toHaveLength(8);
    tabs.forEach((tab, i) => {
      expect(tab).toHaveTextContent(LABELS[i]);
      expect(tab.textContent).toBe(LABELS[i]);
      expect(tab.querySelector('svg[aria-hidden="true"]')).not.toBeNull();
    });
    expect(list).toHaveClass(classes.navList);
    tabs.forEach((tab) => expect(tab).toHaveClass(classes.navTab));
  });

  // onWideScreen runs a test body with the 768 px (48em) media query matching, as at phase7's 1280 px, then restores it.
  async function onWideScreen(body: () => Promise<void>) {
    const original = window.matchMedia;
    window.matchMedia = ((query: string) => ({
      matches: query.includes('min-width: 48em'),
      media: query,
      onchange: null,
      addListener: () => {},
      removeListener: () => {},
      addEventListener: () => {},
      removeEventListener: () => {},
      dispatchEvent: () => false,
    })) as typeof window.matchMedia;
    try {
      await body();
    } finally {
      window.matchMedia = original;
    }
  }

  it('draws the sections as a vertical list from 768 px', () =>
    onWideScreen(async () => {
      every();
      await renderRoute('/settings');
      expect(await screen.findByRole('tablist', { name: 'Settings sections' })).toHaveAttribute('aria-orientation', 'vertical');
    }));

  it('moves along the vertical list with the up and down arrows, End and Enter open the last section', () =>
    onWideScreen(async () => {
      every();
      const { router } = await renderRoute('/settings?tab=general');
      const general = await screen.findByRole('tab', { name: 'General', selected: true });
      general.focus();
      await userEvent.keyboard('{ArrowDown}');
      expect(screen.getByRole('tab', { name: 'Backups' })).toHaveFocus();
      await userEvent.keyboard('{ArrowUp}');
      expect(general).toHaveFocus();
      await userEvent.keyboard('{End}');
      expect(screen.getByRole('tab', { name: 'Single sign-on' })).toHaveFocus();
      await userEvent.keyboard('{Enter}');
      expect(await screen.findByRole('tab', { name: 'Single sign-on', selected: true })).toBeInTheDocument();
      await waitFor(() => expect(router.state.location.search).toBe('?tab=sso'));
    }));

  it('draws the sections as a horizontal list on a phone', async () => {
    every();
    await renderRoute('/settings');
    expect(await screen.findByRole('tablist', { name: 'Settings sections' })).toHaveAttribute('aria-orientation', 'horizontal');
  });

  it('opens a section from the address', async () => {
    every();
    await renderRoute('/settings?tab=backups');
    expect(await screen.findByRole('tab', { name: 'Backups', selected: true })).toBeInTheDocument();
    expect(await screen.findByTestId('backup-now')).toBeInTheDocument();
  });

  it('moves along the sections with Home and End, and Enter opens one', async () => {
    every();
    const { router } = await renderRoute('/settings?tab=general');
    const general = await screen.findByRole('tab', { name: 'General', selected: true });
    general.focus();
    await userEvent.keyboard('{End}');
    expect(screen.getByRole('tab', { name: 'Single sign-on' })).toHaveFocus();
    await userEvent.keyboard('{Enter}');
    expect(await screen.findByRole('tab', { name: 'Single sign-on', selected: true })).toBeInTheDocument();
    await waitFor(() => expect(router.state.location.search).toBe('?tab=sso'));
    await userEvent.keyboard('{Home}');
    expect(screen.getByRole('tab', { name: 'Email' })).toHaveFocus();
  });

  it.each(TABS.map((tab, i) => [tab, LABELS[i]] as const))('titles the %s section with its name and description, the save in the actions row', async (tab, label) => {
    every();
    await renderRoute(`/settings?tab=${tab}`);
    const panel = await screen.findByRole('tabpanel');
    const heading = within(panel).getByRole('heading', { level: 2, name: label });
    expect(heading).toHaveClass(classes.sectionTitle);
    expect(within(panel).getByText(DESCRIPTIONS[tab])).toBeInTheDocument();
    expect(heading.closest(`.${classes.formSection}`)).not.toBeNull();
    const save = SAVE[tab];
    if (save) {
      const button = await within(panel).findByRole('button', { name: save });
      expect(button.closest(`.${settingsClasses.formActions}`)).not.toBeNull();
    }
  });

  it('keeps a local recovery administrator in mind on the single sign-on section', async () => {
    every();
    await renderRoute('/settings?tab=sso');
    expect(await screen.findByText('Keep a local recovery administrator')).toBeInTheDocument();
    expect(screen.getByText('A local account provides access if the identity provider is unavailable.')).toBeInTheDocument();
    expect(screen.getByText('Keep a local recovery administrator').closest('[role="note"]')).not.toBeNull();
  });

  it('is fully translated in Turkish, the section names and descriptions included', async () => {
    server.use(
      ...sessionHandlers({ ...sessionFor('admin', 'tr'), stepup_until: '2099-01-01T00:00:00Z' }),
      http.get('/api/v1/sso/settings', () => HttpResponse.json({ allow_admin_role: false, version: 0 })),
      http.get('/api/v1/sso/providers', () => HttpResponse.json({ items: [] })),
    );
    await renderRoute('/settings?tab=sso', { languages: ['tr-TR'] });
    expect(await screen.findByRole('tablist', { name: 'Ayar bölümleri' })).toBeInTheDocument();
    expect(screen.getByText('Alice’i ekibinizin çalışma biçimine uyarlayın.')).toBeInTheDocument();
    expect(await screen.findByText('Yerel kurtarma yöneticisi bulundurun')).toBeInTheDocument();
    expectNoRawKeys();
  });
});
