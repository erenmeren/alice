import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import {
  auditorSession,
  certificateDetailFixture,
  certificateFixture,
  csrFixture,
  errorResponse,
  operatorSession,
  sessionHandlers,
  sessionFor,
  targetFixture,
} from '../test/fixtures';
import { renderRoute } from '../test/render';
import { server } from '../test/server';

const targets = http.get('/api/v1/targets', () => HttpResponse.json({ items: [targetFixture], next_cursor: null }));
const noCsrs = http.get('/api/v1/certificates/csr', () => HttpResponse.json({ items: [] }));

describe('CertificatesPage', () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2026-10-03T12:00:00Z'));
  });
  afterEach(() => vi.useRealTimers());

  it('lists certificates with days left, expired ones marked', async () => {
    server.use(
      ...sessionHandlers(operatorSession),
      targets,
      noCsrs,
      http.get('/api/v1/certificates', () =>
        HttpResponse.json({
          items: [
            certificateFixture({ id: 'c1', subject_cn: 'www.example.test', not_after: '2026-10-15T12:00:00Z', location_count: 2, has_private_key: true }),
            certificateFixture({ id: 'c2', subject_cn: 'old.example.test', not_after: '2026-09-01T00:00:00Z', location_count: 1, has_private_key: false }),
          ],
          next_cursor: null,
        }),
      ),
    );
    await renderRoute('/certificates');
    const rows = await screen.findAllByRole('row');
    expect(within(rows[1]).getByRole('link', { name: 'www.example.test' })).toHaveAttribute('href', '/certificates/c1');
    expect(within(rows[1]).getByText('12 days')).toBeInTheDocument();
    expect(within(rows[1]).getByText('2 websites')).toBeInTheDocument();
    expect(within(rows[1]).getByText('In Alice')).toBeInTheDocument();
    expect(within(rows[2]).getByText('Expired')).toBeInTheDocument();
    expect(within(rows[2]).getByText('1 website')).toBeInTheDocument();
    expect(within(rows[2]).getByText('Not in Alice')).toBeInTheDocument();
  });

  it('names a certificate by its label, else its subject, else "(no name)"', async () => {
    server.use(
      ...sessionHandlers(operatorSession),
      targets,
      noCsrs,
      http.get('/api/v1/certificates', () =>
        HttpResponse.json({
          items: [
            certificateFixture({ id: 'c1', label: 'Shop', subject_cn: 'shop.example.test' }),
            certificateFixture({ id: 'c2', label: '', subject_cn: '' }),
          ],
          next_cursor: null,
        }),
      ),
    );
    await renderRoute('/certificates');
    expect(await screen.findByRole('link', { name: 'Shop' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: '(no name)' })).toHaveAttribute('href', '/certificates/c2');
  });

  it('sends the filters to the server in a fixed order', async () => {
    const seen: string[] = [];
    server.use(
      ...sessionHandlers(operatorSession),
      targets,
      noCsrs,
      http.get('/api/v1/certificates', ({ request }) => {
        seen.push(new URL(request.url).search);
        return HttpResponse.json({ items: [], next_cursor: null });
      }),
    );
    await renderRoute('/certificates');
    await userEvent.selectOptions(await screen.findByLabelText('Expiry'), '30');
    await userEvent.selectOptions(screen.getByLabelText('Source'), 'uploaded');
    await userEvent.selectOptions(screen.getByLabelText('Server'), targetFixture.id);
    await waitFor(() => expect(seen.at(-1)).toBe(`?target_id=${targetFixture.id}&source=uploaded&expiry=30`));
    expect(await screen.findByText('No certificates match these filters.')).toBeInTheDocument();
    expect(seen[0]).toBe('');
  });

  it('searches after a pause and shows more with the cursor', async () => {
    vi.useRealTimers();
    const seen: string[] = [];
    server.use(
      ...sessionHandlers(operatorSession),
      targets,
      noCsrs,
      http.get('/api/v1/certificates', ({ request }) => {
        const params = new URL(request.url).searchParams;
        seen.push(params.toString());
        if (params.get('cursor') === 'p2') return HttpResponse.json({ items: [certificateFixture({ id: 'c3', subject_cn: 'second.example.test' })], next_cursor: null });
        return HttpResponse.json({ items: [certificateFixture({ id: 'c1' })], next_cursor: 'p2' });
      }),
    );
    await renderRoute('/certificates');
    await userEvent.click(await screen.findByRole('button', { name: 'Show more' }));
    expect(await screen.findByRole('link', { name: 'second.example.test' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Show more' })).not.toBeInTheDocument();
    await userEvent.type(screen.getByLabelText('Search'), 'shop');
    await waitFor(() => expect(seen.at(-1)).toBe('q=shop'));
  });

  it('keeps the page and shows an error alert when the list cannot be loaded', async () => {
    server.use(
      ...sessionHandlers(operatorSession),
      targets,
      noCsrs,
      http.get('/api/v1/certificates', () => errorResponse(422, 'ALC-SYS-0006', 'validation.failed')),
    );
    await renderRoute('/certificates');
    expect(await screen.findByRole('alert')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Certificates', level: 1 })).toBeInTheDocument();
  });

  it('shows Upload and Create signing request to Operators and Administrators', async () => {
    for (const role of ['operator', 'admin'] as const) {
      server.use(...sessionHandlers(sessionFor(role)), targets, noCsrs, http.get('/api/v1/certificates', () => HttpResponse.json({ items: [], next_cursor: null })));
      const { unmount } = await renderRoute('/certificates');
      expect(await screen.findByRole('button', { name: 'Upload certificate' })).toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Create signing request' })).toBeInTheDocument();
      unmount();
    }
  });

  it('shows neither button to Auditors and lists open requests without actions', async () => {
    let csrAsked = false;
    server.use(
      ...sessionHandlers(auditorSession),
      targets,
      http.get('/api/v1/certificates/csr', () => {
        csrAsked = true;
        return HttpResponse.json({ items: [csrFixture()] });
      }),
      http.get('/api/v1/certificates', () => HttpResponse.json({ items: [certificateFixture()], next_cursor: null })),
    );
    await renderRoute('/certificates');
    await screen.findByRole('link', { name: 'www.example.test' });
    expect(screen.queryByRole('button', { name: 'Upload certificate' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Create signing request' })).not.toBeInTheDocument();
    // Auditors read: the open requests are listed, without actions.
    expect(await screen.findByText('Open signing requests')).toBeInTheDocument();
    expect(csrAsked).toBe(true);
    expect(screen.queryByRole('button', { name: /Add signed certificate/ })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Cancel request/ })).not.toBeInTheDocument();
  });

  it('is in the navigation for every role', async () => {
    server.use(...sessionHandlers(auditorSession), targets, noCsrs, http.get('/api/v1/certificates', () => HttpResponse.json({ items: [], next_cursor: null })));
    await renderRoute('/certificates');
    const nav = await screen.findByRole('navigation', { name: 'Main navigation' });
    expect(within(nav).getByRole('link', { name: 'Certificates' })).toHaveAttribute('href', '/certificates');
  });

  it('opens the upload dialog and refreshes the list after an upload', async () => {
    let listCalls = 0;
    server.use(
      ...sessionHandlers(operatorSession),
      targets,
      noCsrs,
      http.get('/api/v1/certificates', () => {
        listCalls += 1;
        return HttpResponse.json({ items: [], next_cursor: null });
      }),
      http.post('/api/v1/certificates/upload', () =>
        HttpResponse.json({ certificate: { ...certificateFixture({ id: 'c9' }), pem_chain: '', locations: [], locations_truncated: false }, warnings: [] }, { status: 201 }),
      ),
      http.get('/api/v1/certificates/c9', () => HttpResponse.json({ ...certificateFixture({ id: 'c9' }), pem_chain: '', locations: [], locations_truncated: false })),
    );
    vi.useRealTimers();
    const { router } = await renderRoute('/certificates');
    await userEvent.click(await screen.findByRole('button', { name: 'Upload certificate' }));
    const dialog = await screen.findByRole('dialog', { name: 'Upload a certificate' });
    await userEvent.type(within(dialog).getByLabelText('Certificate and chain (PEM)'), 'CERT');
    await userEvent.type(within(dialog).getByLabelText('Private key (PEM)'), 'KEY');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Upload' }));
    expect(await within(dialog).findByText('Certificate uploaded.')).toBeInTheDocument();
    await waitFor(() => expect(listCalls).toBe(2));
    // Closing after a successful upload opens the new certificate.
    await userEvent.click(within(dialog).getAllByRole('button', { name: 'Close' })[0]);
    await waitFor(() => expect(router.state.location.pathname).toBe('/certificates/c9'));
  });

  it('shows the result of adding a signed certificate and opens the certificate only when it is closed', async () => {
    vi.useRealTimers();
    server.use(
      ...sessionHandlers(operatorSession),
      targets,
      http.get('/api/v1/certificates/csr', () => HttpResponse.json({ items: [csrFixture()] })),
      http.get('/api/v1/certificates', () => HttpResponse.json({ items: [], next_cursor: null })),
      http.post('/api/v1/certificates/csr/:id/actions/complete', () =>
        HttpResponse.json({ certificate: certificateDetailFixture({ id: 'c7' }), warnings: ['csr_name_mismatch', 'chain_incomplete'] }, { status: 201 }),
      ),
      http.get('/api/v1/certificates/c7', () => HttpResponse.json(certificateDetailFixture({ id: 'c7' }))),
      http.get('/api/v1/deployments', () => HttpResponse.json({ items: [], next_cursor: null })),
    );
    const { router } = await renderRoute('/certificates');
    await userEvent.click(await screen.findByRole('button', { name: /Add signed certificate/ }));
    const dialog = await screen.findByRole('dialog', { name: 'Add the signed certificate' });
    await userEvent.type(within(dialog).getByLabelText('Signed certificate and chain (PEM)'), 'SIGNED');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Add certificate' }));
    expect(await within(dialog).findByText('Certificate added.')).toBeInTheDocument();
    expect(within(dialog).getByText(/domain names in the certificate differ/)).toBeInTheDocument();
    expect(within(dialog).getByText(/The chain is incomplete/)).toBeInTheDocument();
    expect(router.state.location.pathname).toBe('/certificates');
    await userEvent.click(within(dialog).getAllByRole('button', { name: 'Close' })[0]);
    await waitFor(() => expect(router.state.location.pathname).toBe('/certificates/c7'));
  });
});
