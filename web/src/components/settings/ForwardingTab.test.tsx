import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { formatDateTime } from '../../datetime';
import { adminSession, errorResponse, forwardingFixture, sessionFor, sessionHandlers } from '../../test/fixtures';
import { expectNoRawKeys } from '../../test/i18nAssert';
import { renderRoute } from '../../test/render';
import { server } from '../../test/server';
import classes from './settings.module.css';

const steppedUp = { ...adminSession, stepup_until: '2099-01-01T00:00:00Z' };
const steppedUpTr = { ...sessionFor('admin', 'tr'), stepup_until: '2099-01-01T00:00:00Z' };
const CA = '-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n';

describe('ForwardingTab', () => {
  it('saves the forwarding with If-Match and never shows the CA certificate again', async () => {
    let sent: { body: unknown; ifMatch: string | null } | undefined;
    server.use(
      ...sessionHandlers(steppedUp),
      http.put('/api/v1/settings/audit-forwarding', async ({ request }) => {
        sent = { body: await request.json(), ifMatch: request.headers.get('If-Match') };
        return HttpResponse.json(forwardingFixture({ enabled: true, host: 'syslog.example.test', port: 6514, ca_set: true, version: 1 }));
      }),
    );
    await renderRoute('/settings?tab=forwarding');
    const form = await screen.findByTestId('forwarding-form');
    await userEvent.click(within(form).getByLabelText('Forward the audit log'));
    await userEvent.type(within(form).getByLabelText('Syslog server'), 'syslog.example.test');
    await userEvent.type(within(form).getByLabelText('Certificate authority of the syslog server (PEM, optional)'), CA);
    await userEvent.click(within(form).getByRole('button', { name: 'Save forwarding settings' }));
    await waitFor(() =>
      expect(sent).toEqual({ ifMatch: '"0"', body: { enabled: true, host: 'syslog.example.test', port: 6514, transport: 'tls', ca_pem: CA } }),
    );
    expect(await screen.findByText('A CA certificate is set')).toBeInTheDocument();
    expect(screen.getByLabelText('Certificate authority of the syslog server (PEM, optional)')).toHaveValue('');
    expect(screen.getByText('Saved.')).toBeInTheDocument();
  });

  it('ends the form with its actions row until a test result exists (no empty spaced block)', async () => {
    server.use(...sessionHandlers(steppedUp));
    await renderRoute('/settings?tab=forwarding');
    const form = await screen.findByTestId('forwarding-form');
    expect(form.lastElementChild).toHaveClass(classes.formActions);
  });

  it('keeps the stored CA certificate when the field stays empty', async () => {
    let sent: unknown;
    server.use(
      ...sessionHandlers(steppedUp),
      http.get('/api/v1/settings/audit-forwarding', () => HttpResponse.json(forwardingFixture({ enabled: true, host: 'syslog.example.test', ca_set: true, version: 5 }))),
      http.put('/api/v1/settings/audit-forwarding', async ({ request }) => {
        sent = await request.json();
        return HttpResponse.json(forwardingFixture({ enabled: true, host: 'syslog.example.test', transport: 'tcp', port: 601, ca_set: true, version: 6 }));
      }),
    );
    await renderRoute('/settings?tab=forwarding');
    const form = await screen.findByTestId('forwarding-form');
    expect(screen.getByText('A CA certificate is set')).toBeInTheDocument();
    await userEvent.selectOptions(within(form).getByLabelText('Protocol'), 'tcp');
    const port = within(form).getByLabelText('Port');
    await userEvent.clear(port);
    await userEvent.type(port, '601');
    await userEvent.click(within(form).getByRole('button', { name: 'Save forwarding settings' }));
    await waitFor(() => expect(sent).toEqual({ enabled: true, host: 'syslog.example.test', port: 601, transport: 'tcp' }));
  });

  it('removes the stored CA certificate when asked, and offers that only while one is set', async () => {
    let sent: unknown;
    server.use(
      ...sessionHandlers(steppedUp),
      http.get('/api/v1/settings/audit-forwarding', () => HttpResponse.json(forwardingFixture({ enabled: true, host: 'syslog.example.test', ca_set: true, version: 5 }))),
      http.put('/api/v1/settings/audit-forwarding', async ({ request }) => {
        sent = await request.json();
        return HttpResponse.json(forwardingFixture({ enabled: true, host: 'syslog.example.test', ca_set: false, version: 6 }));
      }),
    );
    await renderRoute('/settings?tab=forwarding');
    const form = await screen.findByTestId('forwarding-form');
    const caField = within(form).getByLabelText('Certificate authority of the syslog server (PEM, optional)');
    await userEvent.click(within(form).getByLabelText('Remove the stored CA certificate'));
    // The field cannot hold a replacement at the same time.
    expect(caField).toBeDisabled();
    await userEvent.click(within(form).getByRole('button', { name: 'Save forwarding settings' }));
    await waitFor(() => expect(sent).toEqual({ enabled: true, host: 'syslog.example.test', port: 6514, transport: 'tls', ca_pem: '' }));
    expect(await screen.findByText('Saved.')).toBeInTheDocument();
    expect(screen.queryByText('A CA certificate is set')).not.toBeInTheDocument();
    expect(screen.queryByLabelText('Remove the stored CA certificate')).not.toBeInTheDocument();
    expect(screen.getByLabelText('Certificate authority of the syslog server (PEM, optional)')).toBeEnabled();
  });

  it('tests without the stored CA certificate while its removal is chosen', async () => {
    let sent: unknown;
    server.use(
      ...sessionHandlers(steppedUp),
      http.get('/api/v1/settings/audit-forwarding', () => HttpResponse.json(forwardingFixture({ enabled: true, host: 'syslog.example.test', ca_set: true, version: 5 }))),
      http.post('/api/v1/settings/audit-forwarding/test', async ({ request }) => {
        sent = await request.json();
        return new HttpResponse(null, { status: 204 });
      }),
    );
    await renderRoute('/settings?tab=forwarding');
    const form = await screen.findByTestId('forwarding-form');
    await userEvent.click(within(form).getByLabelText('Remove the stored CA certificate'));
    await userEvent.click(within(form).getByRole('button', { name: 'Send test message' }));
    expect(await screen.findByText('The test message was sent.')).toBeInTheDocument();
    // A test without a CA uses the system's trusted authorities, as the saved setting would after the removal.
    expect(sent).toEqual({ enabled: true, host: 'syslog.example.test', port: 6514, transport: 'tls', ca_pem: '' });
  });

  it('sends a test message with the form as it is', async () => {
    let sent: unknown;
    server.use(
      ...sessionHandlers(steppedUp),
      http.get('/api/v1/settings/audit-forwarding', () => HttpResponse.json(forwardingFixture({ enabled: true, host: 'syslog.example.test', transport: 'udp', port: 514 }))),
      http.post('/api/v1/settings/audit-forwarding/test', async ({ request }) => {
        sent = await request.json();
        return new HttpResponse(null, { status: 204 });
      }),
    );
    await renderRoute('/settings?tab=forwarding');
    await userEvent.click(await screen.findByRole('button', { name: 'Send test message' }));
    expect(await screen.findByText('The test message was sent.')).toBeInTheDocument();
    expect(sent).toEqual({ enabled: true, host: 'syslog.example.test', port: 514, transport: 'udp' });
  });

  it.each([
    [502, 'ALC-AUD-0003', 'audit.forwarding_unreachable'],
    [502, 'ALC-AUD-0004', 'audit.forwarding_untrusted'],
    [422, 'ALC-AUD-0002', 'audit.forwarding_address_refused'],
  ])('shows the text of a refused test message (%s %s)', async (status, code, reason) => {
    server.use(
      ...sessionHandlers(steppedUp),
      http.get('/api/v1/settings/audit-forwarding', () => HttpResponse.json(forwardingFixture({ enabled: true, host: 'syslog.example.test' }))),
      http.post('/api/v1/settings/audit-forwarding/test', () => errorResponse(status, code, reason)),
    );
    const { i18n } = await renderRoute('/settings?tab=forwarding');
    await userEvent.click(await screen.findByRole('button', { name: 'Send test message' }));
    expect(i18n.exists(`errors.${reason}.title`)).toBe(true);
    expect(await screen.findByRole('alert')).toHaveTextContent(i18n.t(`errors.${reason}.title`));
    expect(screen.queryByText('The test message was sent.')).not.toBeInTheDocument();
  });

  it('shows the backlog, the last entry sent and the last problem', async () => {
    server.use(
      ...sessionHandlers(steppedUp),
      http.get('/api/v1/settings/audit-forwarding', () =>
        HttpResponse.json(
          forwardingFixture({
            enabled: true,
            host: 'syslog.example.test',
            backlog: 42,
            cursor_seq: 1234,
            last_sent_at: '2026-10-10T08:00:00Z',
            last_error_code: 'ALC-AUD-0003',
            last_error_at: '2026-10-10T09:00:00Z',
          }),
        ),
      ),
    );
    const { i18n } = await renderRoute('/settings?tab=forwarding');
    expect(await screen.findByText('Entries waiting to be sent: 42')).toBeInTheDocument();
    expect(screen.getByText('Number of the last entry sent: 1234')).toBeInTheDocument();
    expect(screen.getByText(`Last entry sent: ${formatDateTime('2026-10-10T08:00:00Z', 'en')}`)).toBeInTheDocument();
    expect(i18n.exists('errors.audit.forwarding_unreachable.title')).toBe(true);
    expect(
      screen.getByText(`Last problem (${formatDateTime('2026-10-10T09:00:00Z', 'en')}): ${i18n.t('errors.audit.forwarding_unreachable.title')}`),
    ).toBeInTheDocument();
  });

  it('names an unknown last problem by its code and says when nothing was sent', async () => {
    server.use(
      ...sessionHandlers(steppedUp),
      http.get('/api/v1/settings/audit-forwarding', () =>
        HttpResponse.json(forwardingFixture({ last_error_code: 'ALC-AUD-0099', last_error_at: '2026-10-10T09:00:00Z' })),
      ),
    );
    await renderRoute('/settings?tab=forwarding');
    expect(await screen.findByText('No entry has been sent yet.')).toBeInTheDocument();
    expect(screen.getByText(/error code ALC-AUD-0099/)).toBeInTheDocument();
  });

  it('is shown in Turkish without a raw key', async () => {
    server.use(...sessionHandlers(steppedUpTr));
    await renderRoute('/settings?tab=forwarding', { languages: ['tr-TR'] });
    expect(await screen.findByTestId('forwarding-form')).toBeInTheDocument();
    expect(screen.getByText('Gönderilmeyi bekleyen kayıtlar: 0')).toBeInTheDocument();
    expectNoRawKeys();
  });
});
