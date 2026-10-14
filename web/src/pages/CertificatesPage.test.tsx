import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import {
  adminSession,
  auditorSession,
  certificateDetailFixture,
  certificateFixture,
  csrFixture,
  emptyDashboardSummary,
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
const oneCertificate = http.get('/api/v1/certificates', () => HttpResponse.json({ items: [certificateFixture()], next_cursor: null }));

describe('CertificatesPage', () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2026-10-03T12:00:00Z'));
  });
  afterEach(() => vi.useRealTimers());

  it('shows the design header, chips with the summary’s cumulative counts and none on All', async () => {
    server.use(
      ...sessionHandlers(adminSession),
      targets,
      noCsrs,
      oneCertificate,
      http.get('/api/v1/dashboard/summary', () =>
        HttpResponse.json({ ...emptyDashboardSummary, certificates: { ...emptyDashboardSummary.certificates, expired: 1, within_7: 4, within_30: 7 } }),
      ),
    );
    await renderRoute('/certificates');
    expect(await screen.findByRole('heading', { level: 1, name: 'Certificates' })).toBeVisible();
    expect(screen.getByText('Every certificate. Every location. One inventory.')).toBeVisible();
    const chips = screen.getByRole('group', { name: 'Expiry shortcuts' });
    expect(within(chips).getByRole('button', { name: 'All certificates' })).toHaveTextContent(/^All certificates$/);
    expect(within(chips).getByRole('button', { name: 'All certificates' })).toHaveAttribute('aria-pressed', 'true');
    await waitFor(() => expect(within(chips).getByRole('button', { name: /Next 7 days/ })).toHaveTextContent('4'));
    expect(within(chips).getByRole('button', { name: /Next 30 days/ })).toHaveTextContent('7');
    expect(within(chips).getByRole('button', { name: /Expired/ })).toHaveTextContent('1');
    // The label and the count are two words of the accessible name.
    expect(within(chips).getByRole('button', { name: 'Next 7 days 4' })).toBeVisible();
    expect(screen.getByText('Expiry filters are cumulative: “Next 30 days” includes expired certificates.')).toBeVisible();
  });

  it.each([
    ['a scope exists', { unmanaged_total: 7, unmanaged_expiring_30d: 1, scopes: 2, last_scan_at: null }, 'Found on the network, not managed (7)'],
    ['no scope exists', { unmanaged_total: 0, unmanaged_expiring_30d: 0, scopes: 0, last_scan_at: null }, null],
  ])('links to the unmanaged certificates of Network discovery when %s', async (_case, summary, text) => {
    server.use(...sessionHandlers(auditorSession), targets, noCsrs, oneCertificate, http.get('/api/v1/discovery/summary', () => HttpResponse.json(summary)));
    await renderRoute('/certificates');
    await screen.findByRole('heading', { level: 1, name: 'Certificates' });
    if (text) {
      const link = await screen.findByRole('link', { name: text });
      expect(link).toHaveAttribute('href', '/discovery?view=unmanaged');
      // A link, not one of the expiry filters.
      expect(within(screen.getByRole('group', { name: 'Expiry shortcuts' })).queryByRole('link')).not.toBeInTheDocument();
    } else {
      await waitFor(() => expect(screen.queryByTestId('discovery-chip')).not.toBeInTheDocument());
    }
  });

  it('shows no discovery link to someone who may not read the network map', async () => {
    let asked = false;
    server.use(
      ...sessionHandlers(operatorSession),
      targets,
      noCsrs,
      oneCertificate,
      http.get('/api/v1/discovery/summary', () => {
        asked = true;
        return errorResponse(403, 'ALC-AUTH-0002', 'auth.forbidden');
      }),
    );
    await renderRoute('/certificates');
    await waitFor(() => expect(asked).toBe(true));
    expect(screen.queryByTestId('discovery-chip')).not.toBeInTheDocument();
    expect(screen.queryByText('ALC-AUTH-0002')).not.toBeInTheDocument();
  });

  it('shows the whole-inventory counts only while no other filter narrows the list, and All pressed only when nothing is filtered', async () => {
    server.use(
      ...sessionHandlers(adminSession),
      targets,
      noCsrs,
      oneCertificate,
      http.get('/api/v1/dashboard/summary', () =>
        HttpResponse.json({ ...emptyDashboardSummary, certificates: { ...emptyDashboardSummary.certificates, expired: 1, within_7: 4, within_30: 7 } }),
      ),
    );
    const { unmount } = await renderRoute(`/certificates?target_id=${targetFixture.id}`);
    const chips = await screen.findByRole('group', { name: 'Expiry shortcuts' });
    await screen.findByTestId('certificates-table');
    // The summary counts all certificates; beside a list narrowed to one server they would not match its rows.
    expect(within(chips).getByRole('button', { name: 'Next 7 days' })).toHaveTextContent(/^Next 7 days$/);
    expect(within(chips).getByRole('button', { name: 'Expired' })).toHaveTextContent(/^Expired$/);
    expect(within(chips).getByRole('button', { name: 'All certificates' })).toHaveAttribute('aria-pressed', 'false');
    unmount();
    await renderRoute('/certificates?q=shop&expiry=30');
    const again = await screen.findByRole('group', { name: 'Expiry shortcuts' });
    expect(within(again).getByRole('button', { name: 'Next 30 days' })).toHaveAttribute('aria-pressed', 'true');
    expect(within(again).getByRole('button', { name: 'Next 30 days' })).toHaveTextContent(/^Next 30 days$/);
    expect(within(again).getByRole('button', { name: 'All certificates' })).toHaveAttribute('aria-pressed', 'false');
  });

  it('sets the same URL filter as the native expiry select from a chip', async () => {
    server.use(...sessionHandlers(adminSession), targets, noCsrs, oneCertificate);
    const { router } = await renderRoute('/certificates');
    await userEvent.click(within(await screen.findByRole('group', { name: 'Expiry shortcuts' })).getByRole('button', { name: /Next 30 days/ }));
    expect(router.state.location.search).toBe('?expiry=30');
    expect(screen.getByRole('combobox', { name: 'Expiry' })).toHaveValue('30');
    expect(within(screen.getByRole('group', { name: 'Expiry shortcuts' })).getByRole('button', { name: /Next 30 days/ })).toHaveAttribute('aria-pressed', 'true');
    // All clears the expiry filter only.
    await userEvent.click(within(screen.getByRole('group', { name: 'Expiry shortcuts' })).getByRole('button', { name: 'All certificates' }));
    expect(router.state.location.search).toBe('');
  });

  it.each([
    ['/certificates', 'Your inventory starts here'],
    ['/certificates?q=nothing', 'No matching certificates'],
  ])('tells an empty inventory from a filter without matches (%s)', async (path, text) => {
    server.use(...sessionHandlers(adminSession), targets, noCsrs, http.get('/api/v1/certificates', () => HttpResponse.json({ items: [], next_cursor: null })));
    await renderRoute(path);
    expect(await screen.findByText(text)).toBeVisible();
    expect(screen.queryByTestId('certificates-table')).not.toBeInTheDocument();
  });

  it('clears the filters from the no-match state', async () => {
    server.use(...sessionHandlers(operatorSession), targets, noCsrs, http.get('/api/v1/certificates', () => HttpResponse.json({ items: [], next_cursor: null })));
    const { router } = await renderRoute('/certificates?expiry=7');
    expect(await screen.findByText('No certificates match these filters.')).toBeVisible();
    expect(screen.getByText('Try a different search or clear your filters.')).toBeVisible();
    await userEvent.click(screen.getByRole('button', { name: 'Clear filters' }));
    await waitFor(() => expect(router.state.location.search).toBe(''));
    expect(await screen.findByText('Your inventory starts here')).toBeVisible();
  });

  it('pages with the cursor and states only how many rows are shown', async () => {
    server.use(
      ...sessionHandlers(operatorSession),
      targets,
      noCsrs,
      http.get('/api/v1/certificates', ({ request }) => {
        const cursor = new URL(request.url).searchParams.get('cursor');
        if (cursor === 'p2') return HttpResponse.json({ items: [certificateFixture({ id: 'c3', subject_cn: 'second.example.test' })], next_cursor: null });
        return HttpResponse.json({ items: [certificateFixture({ id: 'c1' })], next_cursor: 'p2' });
      }),
    );
    await renderRoute('/certificates');
    expect(await screen.findByText('1 shown')).toBeVisible();
    await userEvent.click(screen.getByRole('button', { name: 'Show more' }));
    expect(await screen.findByText('2 shown')).toBeVisible();
    expect(screen.queryByRole('button', { name: 'Show more' })).not.toBeInTheDocument();
    expect(screen.queryByText(/ of \d+/)).not.toBeInTheDocument();
  });

  it('shows each row as the design’s resource: source tile, name in code, source and issuer, algorithm and key badge', async () => {
    server.use(
      ...sessionHandlers(operatorSession),
      targets,
      noCsrs,
      http.get('/api/v1/certificates', () =>
        HttpResponse.json({
          items: [
            certificateFixture({ id: 'c1', source: 'azure_kv', has_private_key: true }),
            certificateFixture({ id: 'c2', subject_cn: 'found.example.test', source: 'discovered', has_private_key: false, key_algorithm: 'rsa', key_bits: 2048 }),
          ],
          next_cursor: null,
        }),
      ),
    );
    await renderRoute('/certificates');
    const table = await screen.findByTestId('certificates-table');
    const rows = within(table).getAllByRole('row');
    expect(rows[1].querySelector('code')).toHaveTextContent('www.example.test');
    expect(rows[1].querySelector('p')).toHaveTextContent('Azure Key Vault · CN=Example Test CA');
    expect(rows[1].querySelector('[data-source="azure_kv"]')).not.toBeNull();
    expect(within(rows[1]).getByText('ECDSA, 256 bit')).toBeInTheDocument();
    expect(within(rows[1]).getByText('In Alice').closest('.mantine-Badge-root')).toHaveAttribute('data-tone', 'success');
    expect(rows[2].querySelector('p')).toHaveTextContent('Found on servers · CN=Example Test CA');
    expect(within(rows[2]).getByText('Not in Alice').closest('.mantine-Badge-root')).toHaveAttribute('data-tone', 'neutral');
    // The link is the name alone: e2e finds rows by the link name.
    expect(within(rows[2]).getByRole('link', { name: 'found.example.test' })).toHaveAttribute('href', '/certificates/c2');
  });

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
  it('ignores an expiry or source in the address that is not an option, so the select and the list agree', async () => {
    const seen: string[] = [];
    server.use(
      ...sessionHandlers(operatorSession),
      targets,
      noCsrs,
      http.get('/api/v1/views', () => HttpResponse.json({ items: [] })),
      http.get('/api/v1/certificates', ({ request }) => {
        seen.push(new URL(request.url).search);
        return HttpResponse.json({ items: [], next_cursor: null });
      }),
    );
    await renderRoute('/certificates?expiry=5&source=nope');
    await waitFor(() => expect(seen.length).toBeGreaterThan(0));
    expect(seen.every((q) => q === '')).toBe(true);
    expect(screen.getByLabelText('Expiry')).toHaveValue('');
    expect(screen.getByLabelText('Source')).toHaveValue('');
  });
  it('reads its filters from the address and writes them back (owner step 3)', async () => {
    const seen: string[] = [];
    const exported: string[] = [];
    server.use(
      ...sessionHandlers(operatorSession),
      targets,
      noCsrs,
      http.get('/api/v1/views', () => HttpResponse.json({ items: [] })),
      http.get('/api/v1/certificates', ({ request }) => {
        seen.push(new URL(request.url).search);
        return HttpResponse.json({ items: [], next_cursor: null });
      }),
      http.get('/api/v1/certificates/export', ({ request }) => {
        exported.push(new URL(request.url).search);
        return new HttpResponse('a\r\n', { headers: { 'Content-Type': 'text/csv' } });
      }),
    );
    const { router } = await renderRoute('/certificates?expiry=30&target_id=' + targetFixture.id);
    await waitFor(() => expect(seen).toContain(`?target_id=${targetFixture.id}&expiry=30`));
    expect(screen.getByLabelText('Expiry')).toHaveValue('30');
    await userEvent.click(screen.getByRole('button', { name: 'Export' }));
    await waitFor(() => expect(exported).toEqual([`?target_id=${targetFixture.id}&expiry=30`]));
    await userEvent.selectOptions(screen.getByLabelText('Expiry'), '7');
    await waitFor(() => expect(router.state.location.search).toContain('expiry=7'));
    await waitFor(() => expect(seen.at(-1)).toContain('expiry=7'));
    await userEvent.click(screen.getByRole('button', { name: 'Clear filters' }));
    await waitFor(() => expect(router.state.location.search).toBe(''));
  });

  it('offers the new expiry and source options and writes a typed search after the debounce', async () => {
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
    const { router } = await renderRoute('/certificates?source=azure_kv');
    await waitFor(() => expect(seen).toContain('?source=azure_kv'));
    expect(within(screen.getByLabelText('Expiry')).getAllByRole('option').map((o) => o.getAttribute('value'))).toEqual(['', 'expired', '7', '14', '30', '60', '90']);
    expect(within(screen.getByLabelText('Source')).getByRole('option', { name: 'Key Vault' })).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText('Search'), 'abc');
    await waitFor(() => expect(router.state.location.search).toContain('q=abc'));
  });
});
