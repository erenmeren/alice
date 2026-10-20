import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import type { Incident } from '../api/incidents';
import {
  acmeCertificateFixture,
  acmeCurrentFixture,
  acmeHookFixture,
  acmeOrderFixture,
  acmeProviderFixture,
  ACME_CERT_ID,
  ACME_CURRENT_ID,
  certificateDetailFixture,
  certificateFixture,
  certificateImpactFixture,
  incidentFixture,
  INCIDENT_ID,
  sessionFor,
  sessionHandlers,
} from '../test/fixtures';
import { expectNoRawKeys } from '../test/i18nAssert';
import { renderRoute } from '../test/render';
import { server } from '../test/server';

const CERT = '0192c000-0000-7000-8000-0000000000c1';
const steppedUp = (role: 'admin' | 'operator' | 'auditor' = 'admin') => ({ ...sessionFor(role), stepup_until: '2099-01-01T00:00:00Z' });

function certificatePage(opts: { role?: 'admin' | 'operator' | 'auditor'; detail?: Parameters<typeof certificateDetailFixture>[0]; impact?: Parameters<typeof certificateImpactFixture>[0] } = {}) {
  const started: unknown[] = [];
  server.use(
    ...sessionHandlers(steppedUp(opts.role ?? 'admin')),
    http.get('/api/v1/targets', () => HttpResponse.json({ items: [], next_cursor: null })),
    http.get(`/api/v1/certificates/${CERT}`, () => HttpResponse.json(certificateDetailFixture({ id: CERT, ...opts.detail }))),
    http.get('/api/v1/deployments', () => HttpResponse.json({ items: [], next_cursor: null })),
    http.get(`/api/v1/certificate-impact/${CERT}`, () => HttpResponse.json(certificateImpactFixture(opts.impact))),
    http.post(`/api/v1/certificates/${CERT}/incidents`, async ({ request }) => {
      started.push(await request.json());
      return HttpResponse.json(incidentFixture(), { status: 201 });
    }),
    http.get(`/api/v1/incidents/${INCIDENT_ID}`, () => HttpResponse.json(incidentFixture())),
  );
  return started;
}

describe('the certificate page: capabilities, impact and the incident', () => {
  it('shows what Alice can do with an uploaded certificate, and that only its issuer revokes it', async () => {
    certificatePage();
    await renderRoute(`/certificates/${CERT}`);
    const panel = await screen.findByTestId('capabilities-panel');
    const items = within(panel).getAllByRole('listitem');
    expect(items.map((li) => [li.getAttribute('data-capability'), li.getAttribute('data-enabled')])).toEqual([
      ['discover', 'true'],
      ['obtain', 'false'],
      ['renew', 'false'],
      ['deploy', 'true'],
      ['verify', 'true'],
      ['revoke', 'false'],
      ['recovery', 'false'],
    ]);
    expect(within(panel).getByText(/only its issuing authority can revoke it/)).toBeInTheDocument();
    expect(within(panel).getByTestId('no-revoke')).toBeInTheDocument();
    expectNoRawKeys();
  });

  it('lists every place that holds the certificate or its key', async () => {
    certificatePage();
    await renderRoute(`/certificates/${CERT}`);
    const panel = await screen.findByTestId('impact-panel');
    expect(await within(panel).findByTestId('impact-summary')).toHaveTextContent('Servers: 2 · Key vault versions: 0 · Network endpoints: 1');
    expect(within(panel).getByTestId('impact-same-key')).toHaveTextContent('1 other certificate was made with the same private key: other.example.test');
    const rows = within(panel).getAllByTestId('impact-location');
    expect(rows).toHaveLength(2);
    expect(within(rows[0]).getByText('This certificate')).toBeInTheDocument();
    expect(within(rows[1]).getByText('Same key')).toBeInTheDocument();
    expect(within(panel).getByTestId('impact-endpoint')).toHaveTextContent('10.0.0.9:443');
  });

  it('starts an incident after the Administrator confirms, and opens it', async () => {
    const started = certificatePage();
    await renderRoute(`/certificates/${CERT}`);
    await userEvent.click(await screen.findByRole('button', { name: 'Key compromised…' }));
    const dialog = await screen.findByRole('dialog', { name: 'Start a key compromise incident?' });
    expect(within(dialog).getByTestId('not-revocable')).toBeInTheDocument();
    expect(within(dialog).queryByLabelText(/Revoke at once/)).not.toBeInTheDocument();
    const go = within(dialog).getByRole('button', { name: 'Start the incident' });
    expect(go).toBeDisabled();
    await userEvent.click(within(dialog).getByLabelText('I understand that this cannot be undone.'));
    await userEvent.click(go);
    expect(await screen.findByTestId('incident-state')).toHaveTextContent('Needs attention');
    expect(started).toEqual([{ revoke_mode: 'after_verified' }]);
  });

  it('offers revoke-now for a certificate Alice ordered, and links an open incident instead of starting another', async () => {
    const started = certificatePage({ detail: { source: 'acme', capabilities: ['discover', 'obtain', 'renew', 'deploy', 'verify', 'revoke', 'recovery'] } });
    await renderRoute(`/certificates/${CERT}`);
    await userEvent.click(await screen.findByRole('button', { name: 'Key compromised…' }));
    const dialog = await screen.findByRole('dialog', { name: 'Start a key compromise incident?' });
    expect(within(dialog).queryByTestId('not-revocable')).not.toBeInTheDocument();
    await userEvent.click(within(dialog).getByLabelText(/Revoke at once/));
    await userEvent.click(within(dialog).getByLabelText('I understand that this cannot be undone.'));
    await userEvent.click(within(dialog).getByRole('button', { name: 'Start the incident' }));
    await waitFor(() => expect(started).toEqual([{ revoke_mode: 'now' }]));
  });

  it('shows a revoked and compromised certificate, without Deploy, and the open incident', async () => {
    certificatePage({
      detail: { source: 'acme', revoked_at: '2026-10-02T08:00:00Z', revocation_reason: 'keyCompromise', revoked_by_name: 'Ada', compromised_at: '2026-10-02T07:00:00Z', capabilities: ['discover', 'obtain', 'renew', 'recovery'] },
      impact: { open_incident_id: INCIDENT_ID },
    });
    await renderRoute(`/certificates/${CERT}`);
    expect(await screen.findByTestId('revoked-notice')).toHaveTextContent('reason: Key compromise');
    expect(screen.getByTestId('revoked-notice')).toHaveTextContent('Revoked by Ada.');
    expect(screen.getByTestId('compromised-notice')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Deploy' })).not.toBeInTheDocument();
    expect(await screen.findByRole('link', { name: 'Open the incident' })).toHaveAttribute('href', `/incidents/${INCIDENT_ID}`);
    expect(screen.queryByRole('button', { name: 'Key compromised…' })).not.toBeInTheDocument();
    const panel = screen.getByTestId('capabilities-panel');
    expect(within(panel).getByText(/It is revoked already/)).toBeInTheDocument();
  });

  it('does not offer the incident to an Operator', async () => {
    certificatePage({ role: 'operator' });
    await renderRoute(`/certificates/${CERT}`);
    await screen.findByTestId('impact-panel');
    expect(screen.queryByRole('button', { name: 'Key compromised…' })).not.toBeInTheDocument();
  });
});

function incidentPage(incident: Incident | (() => Incident), role: 'admin' | 'auditor' = 'admin') {
  const calls: string[] = [];
  const get = () => (typeof incident === 'function' ? incident() : incident);
  server.use(
    ...sessionHandlers(steppedUp(role)),
    http.get(`/api/v1/incidents/${INCIDENT_ID}`, () => HttpResponse.json(get())),
    http.post(`/api/v1/incidents/${INCIDENT_ID}/:action`, async ({ params, request }) => {
      const text = await request.text();
      calls.push(`${String(params.action)}${text ? ` ${text}` : ''}`);
      return HttpResponse.json(get());
    }),
    http.get('/api/v1/certificates', () =>
      HttpResponse.json({
        items: [
          certificateFixture({ id: 'c-new', label: 'new www', public_key_sha256: 'ff00'.repeat(16) }),
          certificateFixture({ id: 'c-same', label: 'same key' }),
          certificateFixture({ id: 'c-nokey', label: 'no key', has_private_key: false, public_key_sha256: 'aa00'.repeat(16) }),
        ],
        next_cursor: null,
      }),
    ),
  );
  return calls;
}

describe('IncidentPage', () => {
  it('shows what needs attention, every place and the actions', async () => {
    const calls = incidentPage(incidentFixture());
    await renderRoute(`/incidents/${INCIDENT_ID}`);
    expect(await screen.findByTestId('incident-state')).toHaveTextContent('Needs attention');
    expect(screen.getByTestId('incident-attention')).toHaveTextContent('The replacement could not be deployed everywhere.');
    const rows = screen.getAllByTestId('incident-location');
    expect(rows.map((r) => r.getAttribute('data-status'))).toEqual(['verified', 'failed']);
    expect(within(rows[1]).getByText(/reload/i)).toBeInTheDocument();
    expect(screen.getByTestId('revocation')).toHaveTextContent('Not yet');
    await userEvent.click(screen.getByRole('button', { name: 'Retry' }));
    await waitFor(() => expect(calls).toEqual(['retry']));
    await userEvent.click(screen.getByRole('button', { name: 'Revoke now regardless' }));
    const dialog = await screen.findByRole('dialog', { name: 'Revoke now regardless?' });
    await userEvent.click(within(dialog).getByRole('button', { name: 'Revoke now' }));
    await waitFor(() => expect(calls).toEqual(['retry', 'revoke-now']));
    await userEvent.click(screen.getByRole('button', { name: 'Close the incident' }));
    const close = await screen.findByRole('dialog', { name: 'Close the incident?' });
    await userEvent.click(within(close).getByRole('button', { name: 'Close the incident' }));
    await waitFor(() => expect(calls).toEqual(['retry', 'revoke-now', 'close']));
    expectNoRawKeys();
  });

  it('shows a place whose server cannot be reached as not confirmed, and a refused undo with its reason (R48)', async () => {
    const base = incidentFixture();
    const [first, second] = base.locations ?? [];
    incidentPage(
      incidentFixture({
        state: 'deploying',
        attention: null,
        locations: [
          { ...first, status: 'deploying', outcome_uncertain: true, error: { code: 'ALC-SSH-0001', reason: 'ssh.unreachable' } },
          { ...second, status: 'failed', error: { code: 'ALC-DEP-0025', reason: 'deployment.rollback_forbidden' } },
        ],
      }),
    );
    await renderRoute(`/incidents/${INCIDENT_ID}`);
    const rows = await screen.findAllByTestId('incident-location');
    expect(within(rows[0]).getByTestId('location-uncertain')).toHaveTextContent('Not confirmed: server not reached');
    expect(within(rows[0]).queryByText('Replaced and checked')).not.toBeInTheDocument();
    expect(within(rows[1]).getByText(/did not put the previous certificate back because it is revoked or compromised/)).toBeInTheDocument();
    expectNoRawKeys();
  });

  it('lets the Administrator choose the replacement of an uploaded certificate', async () => {
    const calls = incidentPage(
      incidentFixture({ source: 'uploaded', acme_certificate_id: null, state: 'awaiting_replacement', revocation: 'not_possible', attention: null, replacement_certificate_id: null, replacement_fingerprint: '', order_id: null, order_state: '', locations: [] }),
    );
    await renderRoute(`/incidents/${INCIDENT_ID}`);
    expect(await screen.findByTestId('not-revocable')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Revoke now regardless' })).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Choose the replacement' }));
    const dialog = await screen.findByRole('dialog', { name: 'Choose the replacement' });
    // Only a certificate with a key in Alice and another key is offered.
    const select = within(dialog).getByRole('combobox', { name: 'Replacement certificate' });
    expect(await within(dialog).findByRole('option', { name: /new www/ })).toBeInTheDocument();
    expect(within(dialog).queryByRole('option', { name: /same key/ })).not.toBeInTheDocument();
    expect(within(dialog).queryByRole('option', { name: /no key/ })).not.toBeInTheDocument();
    await userEvent.selectOptions(select, 'c-new');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Use this certificate' }));
    await waitFor(() => expect(calls).toEqual(['replacement {"certificate_id":"c-new"}']));
  });

  it('is read-only for an Auditor and quiet once completed', async () => {
    incidentPage(incidentFixture({ state: 'completed', revocation: 'revoked', revoked_at: '2026-10-20T09:00:00Z', finished_at: '2026-10-20T09:00:00Z', attention: null }), 'auditor');
    await renderRoute(`/incidents/${INCIDENT_ID}`);
    expect(await screen.findByTestId('incident-state')).toHaveTextContent('Completed');
    expect(screen.getByTestId('incident-notice')).toHaveTextContent('The incident is completed');
    expect(screen.queryByRole('button', { name: 'Close the incident' })).not.toBeInTheDocument();
    expect(screen.queryByTestId('incident-busy')).not.toBeInTheDocument();
  });
});

describe('Revoking an issued certificate', () => {
  function acmePage(revoked: unknown[]) {
    const cert = acmeCertificateFixture({ current: acmeCurrentFixture() });
    server.use(
      ...sessionHandlers(steppedUp()),
      http.get(`/api/v1/acme/certificates/${ACME_CERT_ID}`, () => HttpResponse.json(cert)),
      http.get(`/api/v1/acme/certificates/${ACME_CERT_ID}/orders`, () =>
        HttpResponse.json({ items: [acmeOrderFixture(), acmeOrderFixture({ id: 'o-old', certificate_id: 'v-old', finished_at: '2026-07-13T09:01:00Z' }), acmeOrderFixture({ id: 'o-rev', certificate_id: 'v-rev', revoked_at: '2026-08-01T00:00:00Z', revocation_reason: 'superseded' })] }),
      ),
      http.get(`/api/v1/acme/certificates/${ACME_CERT_ID}/bindings`, () => HttpResponse.json({ items: [] })),
      http.get('/api/v1/acme/certificates', () => HttpResponse.json({ items: [cert], next_cursor: null })),
      http.get('/api/v1/acme/providers', () => HttpResponse.json({ items: [acmeProviderFixture()] })),
      http.get('/api/v1/acme/hooks', () => HttpResponse.json({ items: [acmeHookFixture()] })),
      http.get('/api/v1/certificates/:id', () => HttpResponse.json(certificateDetailFixture({ id: ACME_CURRENT_ID }))),
      http.post(`/api/v1/acme/certificates/${ACME_CERT_ID}/revoke`, async ({ request }) => {
        revoked.push(await request.json());
        return HttpResponse.json(certificateFixture({ id: ACME_CURRENT_ID, revoked_at: '2026-10-20T10:00:00Z', revocation_reason: 'superseded' }));
      }),
    );
  }

  it('asks for the version, the reason and the understanding that it cannot be undone', async () => {
    const revoked: unknown[] = [];
    acmePage(revoked);
    await renderRoute(`/acme/${ACME_CERT_ID}`);
    expect(await screen.findByTestId('order-revoked')).toHaveTextContent('Revoked');
    await userEvent.click(await screen.findByRole('button', { name: 'Revoke' }));
    const dialog = await screen.findByRole('dialog', { name: 'Revoke the certificate?' });
    expect(within(dialog).getByText('Did the private key leak?')).toBeInTheDocument();
    // The current certificate and the earlier one not revoked yet; the revoked one is not offered.
    const versions = within(within(dialog).getByRole('combobox', { name: 'Certificate' })).getAllByRole('option');
    expect(versions.map((o) => o.getAttribute('value'))).toEqual([ACME_CURRENT_ID, 'v-old']);
    await userEvent.selectOptions(within(dialog).getByRole('combobox', { name: 'Reason' }), 'cessationOfOperation');
    await userEvent.selectOptions(within(dialog).getByRole('combobox', { name: 'Reason' }), 'superseded');
    const go = within(dialog).getByRole('button', { name: 'Revoke the certificate' });
    expect(go).toBeDisabled();
    await userEvent.click(within(dialog).getByLabelText('I understand that a revocation cannot be undone.'));
    await userEvent.click(go);
    expect(await within(dialog).findByTestId('revoked')).toHaveTextContent('The certificate is revoked.');
    expect(revoked).toEqual([{ reason: 'superseded' }]);
    expectNoRawKeys();
  });
});
