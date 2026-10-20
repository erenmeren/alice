import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import {
  assignResultFixture,
  certificateDetailFixture,
  certificateFixture,
  certificateImpactFixture,
  DEFAULT_SERVICE_ID,
  defaultServiceFixture,
  defaultServiceRef,
  environmentFixture,
  PRODUCTION_ID,
  SERVICE_ID,
  serviceFixture,
  serviceRef,
  sessionFor,
  sessionHandlers,
  targetFixture,
} from '../../test/fixtures';
import { renderRoute } from '../../test/render';
import { server } from '../../test/server';

const CERT = '0192c000-0000-7000-8000-0000000000c1';
const steppedUp = (role: 'admin' | 'operator') => ({ ...sessionFor(role), stepup_until: '2099-01-01T00:00:00Z' });

function lists(role: 'admin' | 'operator' = 'admin') {
  const queries: string[] = [];
  const assigned: { path: string; body: unknown }[] = [];
  server.use(
    ...sessionHandlers(steppedUp(role)),
    http.get('/api/v1/services', () => HttpResponse.json({ items: [defaultServiceFixture, serviceFixture()] })),
    http.get('/api/v1/environments', () => HttpResponse.json({ items: [environmentFixture()] })),
    http.get('/api/v1/targets', () =>
      HttpResponse.json({ items: [{ ...targetFixture, service: serviceRef }, { ...targetFixture, id: 't-other', name: 'other-web', service: defaultServiceRef }], next_cursor: null }),
    ),
    http.get('/api/v1/certificates', ({ request }) => {
      queries.push(new URL(request.url).search);
      return HttpResponse.json({ items: [{ ...certificateFixture(), service: serviceRef }], next_cursor: null });
    }),
    http.get(`/api/v1/certificates/${CERT}`, () => HttpResponse.json(certificateDetailFixture({ id: CERT, service: defaultServiceRef }))),
    http.get(`/api/v1/certificate-impact/${CERT}`, () => HttpResponse.json(certificateImpactFixture())),
    http.get('/api/v1/deployments', () => HttpResponse.json({ items: [], next_cursor: null })),
    http.post('/api/v1/services/:id/actions/assign', async ({ request }) => {
      const url = new URL(request.url);
      assigned.push({ path: url.pathname + url.search, body: await request.json() });
      return HttpResponse.json(assignResultFixture({ moves: [{ type: 'certificate', id: CERT, name: 'www.example.test', from: defaultServiceRef, changed: true }], untrusted: [] }));
    }),
  );
  return { queries, assigned };
}

describe('the service column and filters of the lists', () => {
  it('shows the owning service of a certificate and asks the server for one service', async () => {
    const { queries } = lists();
    const { router } = await renderRoute('/certificates');
    const table = await screen.findByRole('table', { name: 'Certificates' });
    const badge = within(table).getByTestId('service-badge');
    expect(within(badge).getByText('Payments')).toBeInTheDocument();
    expect(within(badge).queryByRole('link')).not.toBeInTheDocument(); // the row keeps its one link
    expect(within(badge).getByText('Production')).toBeInTheDocument();
    await waitFor(() => expect(screen.getByRole('option', { name: 'Payments' })).toBeInTheDocument());
    await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Service' }), SERVICE_ID);
    await waitFor(() => expect(queries.at(-1)).toContain(`service_id=${SERVICE_ID}`));
    expect(router.state.location.search).toContain(`service_id=${SERVICE_ID}`);
    await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Environment' }), PRODUCTION_ID);
    await waitFor(() => expect(queries.at(-1)).toContain(`environment_id=${PRODUCTION_ID}`));
  });

  it('filters the servers in the browser by service', async () => {
    lists();
    await renderRoute(`/servers?service_id=${DEFAULT_SERVICE_ID}`);
    const table = await screen.findByTestId('targets-table');
    expect(within(table).getByRole('link', { name: 'other-web' })).toBeInTheDocument();
    expect(within(table).queryByRole('link', { name: targetFixture.name })).not.toBeInTheDocument();
  });
});

describe('Move to service on a detail page', () => {
  it('lets an Administrator move a certificate after the dry run', async () => {
    const { assigned } = lists();
    await renderRoute(`/certificates/${CERT}`);
    const badge = await screen.findByTestId('service-badge');
    expect(badge).toHaveTextContent('Default');
    expect(within(badge).getByRole('link', { name: 'Default' })).toHaveAttribute('href', expect.stringMatching(/^\/services\//));
    await userEvent.click(screen.getByRole('button', { name: 'Move to service' }));
    const dialog = await screen.findByRole('dialog');
    await waitFor(() => expect(within(dialog).getByRole('option', { name: 'Payments' })).toBeInTheDocument());
    // The service it is in already is not offered.
    expect(within(dialog).queryByRole('option', { name: 'Default' })).not.toBeInTheDocument();
    await userEvent.selectOptions(within(dialog).getByRole('combobox', { name: 'Service' }), SERVICE_ID);
    await userEvent.click(within(dialog).getByRole('button', { name: 'Check the move' }));
    expect(await within(dialog).findByTestId('move-preview')).toHaveTextContent('www.example.test: Default → Payments');
    expect(within(dialog).queryByTestId('move-untrusted')).not.toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Move' }));
    await waitFor(() => expect(assigned).toHaveLength(2));
    expect(assigned.map((a) => a.path)).toEqual([`/api/v1/services/${SERVICE_ID}/actions/assign?dry_run=true`, `/api/v1/services/${SERVICE_ID}/actions/assign`]);
    expect(assigned[1].body).toEqual({ resources: [{ type: 'certificate', id: CERT }] });
  });

  it('gives an Operator the badge but no move', async () => {
    lists('operator');
    await renderRoute(`/certificates/${CERT}`);
    await screen.findByTestId('service-badge');
    expect(screen.queryByRole('button', { name: 'Move to service' })).not.toBeInTheDocument();
  });
});
