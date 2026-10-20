import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import {
  assignResultFixture,
  certificateFixture,
  DEFAULT_SERVICE_ID,
  defaultServiceFixture,
  defaultServiceRef,
  environmentFixture,
  PRODUCTION_ID,
  SERVICE_ID,
  serviceFixture,
  servicePolicyFixture,
  serviceRef,
  serviceTrustFixture,
  sessionFor,
  sessionHandlers,
  targetFixture,
} from '../test/fixtures';
import { expectNoRawKeys } from '../test/i18nAssert';
import { renderRoute } from '../test/render';
import { server } from '../test/server';

const steppedUp = (role: 'admin' | 'operator' | 'auditor', locale: string) => ({ ...sessionFor(role, locale), stepup_until: '2099-01-01T00:00:00Z' });

function services(role: 'admin' | 'operator' | 'auditor' = 'admin', locale = 'en') {
  const seen: { method: string; path: string; body: unknown; ifMatch: string | null }[] = [];
  const record = async (request: Request) => {
    const url = new URL(request.url);
    seen.push({ method: request.method, path: url.pathname + url.search, body: request.method === 'DELETE' ? null : await request.json(), ifMatch: request.headers.get('If-Match') });
  };
  server.use(
    ...sessionHandlers(steppedUp(role, locale)),
    http.get('/api/v1/services', () => HttpResponse.json({ items: [defaultServiceFixture, serviceFixture()] })),
    http.get('/api/v1/environments', () => HttpResponse.json({ items: [environmentFixture(), environmentFixture({ id: 'e2', key: 'staging', name: 'Staging', sort: 20, services: 0 })] })),
    http.get(`/api/v1/services/${SERVICE_ID}`, () => HttpResponse.json(serviceFixture())),
    http.get(`/api/v1/services/${DEFAULT_SERVICE_ID}`, () => HttpResponse.json(defaultServiceFixture)),
    http.get('/api/v1/services/:id/policy', () => HttpResponse.json(servicePolicyFixture())),
    http.get('/api/v1/service-trusts', () => HttpResponse.json({ items: [serviceTrustFixture()] })),
    http.get('/api/v1/targets', () => HttpResponse.json({ items: [{ ...targetFixture, service: serviceRef }, { ...targetFixture, id: 't-other', name: 'other-web', service: defaultServiceRef }], next_cursor: null })),
    http.get('/api/v1/certificates', () => HttpResponse.json({ items: [{ ...certificateFixture(), service: serviceRef }], next_cursor: null })),
    http.get('/api/v1/acme/certificates', () => HttpResponse.json({ items: [], next_cursor: null })),
    http.get('/api/v1/ssh-keys', () => HttpResponse.json({ items: [], next_cursor: null })),
    http.get('/api/v1/discovery/scopes', () => HttpResponse.json({ items: [], next_cursor: null })),
    http.post('/api/v1/services', async ({ request }) => {
      await record(request);
      return HttpResponse.json(serviceFixture(), { status: 201 });
    }),
    http.post('/api/v1/services/:id/actions/assign', async ({ request }) => {
      await record(request);
      const dry = new URL(request.url).searchParams.get('dry_run') === 'true';
      return HttpResponse.json(assignResultFixture({ dry_run: dry }));
    }),
    http.post('/api/v1/service-trusts', async ({ request }) => {
      await record(request);
      return HttpResponse.json(serviceTrustFixture(), { status: 201 });
    }),
    http.delete('/api/v1/service-trusts/:id', async ({ request }) => {
      await record(request);
      return new HttpResponse(null, { status: 204 });
    }),
  );
  return seen;
}

describe('ServicesPage', () => {
  it('lists the services with their environment, what they own and their policy version', async () => {
    services();
    await renderRoute('/services');
    const table = await screen.findByTestId('services-table');
    const rows = within(table).getAllByTestId('service-row');
    expect(rows).toHaveLength(2);
    expect(within(rows[0]).getByRole('link', { name: 'Default' })).toHaveAttribute('href', `/services/${DEFAULT_SERVICE_ID}`);
    expect(within(rows[0]).getByText('Default service')).toBeInTheDocument();
    expect(within(rows[0]).getByText('No environment')).toBeInTheDocument();
    expect(within(rows[0]).getByText('2 servers, 1 Key Vault, 3 certificates, 1 ACME certificate, 2 SSH keys, 1 scan scope')).toBeInTheDocument();
    expect(within(rows[1]).getByText('Production').closest('[data-environment]')).toHaveAttribute('data-environment', 'production');
    expect(within(rows[1]).getByText('1 server, 1 certificate')).toBeInTheDocument();
    expect(within(rows[1]).getByText('Version 1')).toBeInTheDocument();
  });

  it('lets an Administrator add a service in an environment and opens it', async () => {
    const seen = services();
    const { router } = await renderRoute('/services');
    await userEvent.click(await screen.findByRole('button', { name: 'Add service' }));
    const dialog = await screen.findByRole('dialog', { name: 'Add a service' });
    await userEvent.type(within(dialog).getByLabelText(/Name/), 'Payments');
    await waitFor(() => expect(within(dialog).getByRole('option', { name: 'Production' })).toBeInTheDocument());
    await userEvent.selectOptions(within(dialog).getByLabelText('Environment'), PRODUCTION_ID);
    await userEvent.click(within(dialog).getByRole('button', { name: 'Add service' }));
    await waitFor(() => expect(router.state.location.pathname).toBe(`/services/${SERVICE_ID}`));
    expect(seen).toEqual([{ method: 'POST', path: '/api/v1/services', body: { name: 'Payments', description: '', environment_id: PRODUCTION_ID }, ifMatch: null }]);
  });

  it('shows no add button to an Auditor, and translates the page', async () => {
    services('auditor', 'tr');
    await renderRoute('/services', { languages: ['tr-TR'] });
    await screen.findByTestId('services-table');
    expect(screen.queryByRole('button', { name: 'Hizmet ekle' })).not.toBeInTheDocument();
    expect(screen.getByText('Üretim')).toBeInTheDocument();
    expectNoRawKeys(document.body);
  });
});

describe('ServicePage', () => {
  it('shows the overview with the environment, description and the read-only policy', async () => {
    services();
    await renderRoute(`/services/${SERVICE_ID}`);
    expect(await screen.findByRole('heading', { level: 1, name: 'Payments' })).toBeInTheDocument();
    expect(screen.getByText('Card payments and the checkout website.')).toBeInTheDocument();
    expect(await screen.findByTestId('policy-version')).toHaveTextContent('Version 1');
    expect(screen.getByText('No rules yet')).toBeInTheDocument();
    // The service owns a server and a certificate: it cannot be deleted.
    expect(screen.getByRole('button', { name: 'Delete service' })).toBeDisabled();
  });

  it('lists what the service owns, linked to their pages and to the filtered lists', async () => {
    services();
    await renderRoute(`/services/${SERVICE_ID}?tab=resources`);
    const servers = await screen.findByRole('link', { name: targetFixture.name });
    expect(servers).toHaveAttribute('href', `/servers/${targetFixture.id}`);
    expect(screen.queryByRole('link', { name: 'other-web' })).not.toBeInTheDocument();
    const all = screen.getAllByRole('link', { name: 'Show all' }).map((a) => a.getAttribute('href'));
    expect(all).toContain(`/servers?service_id=${SERVICE_ID}`);
    expect(all).toContain(`/certificates?service_id=${SERVICE_ID}`);
  });

  it('moves a server here: the dry run first shows the bindings that would stop deploying, then the move', async () => {
    const seen = services();
    await renderRoute(`/services/${SERVICE_ID}?tab=resources`);
    await userEvent.click(await screen.findByRole('button', { name: 'Move here' }));
    const dialog = await screen.findByRole('dialog', { name: 'Move something to Payments' });
    await waitFor(() => expect(within(dialog).getByRole('option', { name: 'other-web (Default)' })).toBeInTheDocument());
    // The server already in Payments is not offered.
    expect(within(dialog).queryByRole('option', { name: new RegExp(`^${targetFixture.name}`) })).not.toBeInTheDocument();
    await userEvent.selectOptions(within(dialog).getByLabelText('Resource'), 't-other');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Check the move' }));
    const warning = await within(dialog).findByTestId('move-untrusted');
    expect(warning).toHaveTextContent('1 binding would no longer deploy automatically');
    expect(warning).toHaveTextContent(`www-cert on ${targetFixture.name} (Default → Payments)`);
    expect(within(dialog).getByTestId('move-preview')).toHaveTextContent(`${targetFixture.name}: Default → Payments`);
    await userEvent.click(within(dialog).getByRole('button', { name: 'Move' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(seen).toEqual([
      { method: 'POST', path: `/api/v1/services/${SERVICE_ID}/actions/assign?dry_run=true`, body: { resources: [{ type: 'target', id: 't-other' }] }, ifMatch: null },
      { method: 'POST', path: `/api/v1/services/${SERVICE_ID}/actions/assign`, body: { resources: [{ type: 'target', id: 't-other' }] }, ifMatch: null },
    ]);
  });

  it('shows the trusts both ways and lets an Administrator add and remove one', async () => {
    const seen = services();
    await renderRoute(`/services/${SERVICE_ID}?tab=trusts`);
    const accepts = await screen.findByTestId('trusts-accepts');
    expect(within(accepts).getByRole('link', { name: 'Default' })).toHaveAttribute('href', `/services/${DEFAULT_SERVICE_ID}`);
    expect(screen.getByTestId('trusts-sends')).toHaveTextContent('None');
    await userEvent.selectOptions(screen.getByLabelText('Direction'), 'sends');
    await waitFor(() => expect(screen.getByRole('option', { name: 'Default' })).toBeInTheDocument());
    await userEvent.selectOptions(screen.getByLabelText('Service'), DEFAULT_SERVICE_ID);
    await userEvent.click(screen.getByRole('button', { name: 'Add trust' }));
    await userEvent.click(within(accepts).getByRole('button', { name: 'Remove' }));
    await waitFor(() => expect(seen).toHaveLength(2));
    expect(seen[0]).toEqual({ method: 'POST', path: '/api/v1/service-trusts', body: { source_service_id: SERVICE_ID, target_service_id: DEFAULT_SERVICE_ID }, ifMatch: null });
    expect(seen[1]).toMatchObject({ method: 'DELETE', path: `/api/v1/service-trusts/${serviceTrustFixture().id}` });
  });

  it('gives an Operator no changes', async () => {
    services('operator');
    await renderRoute(`/services/${SERVICE_ID}?tab=trusts`);
    await screen.findByTestId('trusts-accepts');
    expect(screen.queryByRole('button', { name: 'Remove' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Edit' })).not.toBeInTheDocument();
    expect(screen.queryByText('Add a trust')).not.toBeInTheDocument();
  });
});
