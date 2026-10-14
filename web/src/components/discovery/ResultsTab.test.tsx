import { act, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { discoveredCertificateFixture, discoveredEndpointFixture, errorResponse, platformKeyFixture, sessionFor } from '../../test/fixtures';
import { discoveryWorld, requests } from '../../test/discovery';
import { expectNoRawKeys } from '../../test/i18nAssert';
import { renderRoute } from '../../test/render';
import { server } from '../../test/server';
import { resultQuery } from './ResultsTab';

const blank = { status: '', expiry: '', self_signed: '', scope_id: '', found: '', q: '', view: '' };

describe('resultQuery', () => {
  it('reads the address, ignoring values that are not options', () => {
    expect(resultQuery(blank)).toEqual({ status: 'all', query: { status: 'all', current: true, expired: undefined, expiring_within_days: undefined, self_signed: undefined, scope_id: undefined, q: undefined }, filtered: false });
    expect(resultQuery({ ...blank, found: 'all' })).toMatchObject({ query: { current: false }, filtered: true });
    expect(resultQuery({ ...blank, found: 'bogus' }).query.current).toBe(true);
    expect(resultQuery({ ...blank, view: 'unmanaged' }).status).toBe('unmanaged');
    expect(resultQuery({ ...blank, view: 'unmanaged', status: 'all' }).status).toBe('all');
    expect(resultQuery({ ...blank, status: 'bogus', expiry: '13', self_signed: 'maybe' }).filtered).toBe(false);
    expect(resultQuery({ ...blank, expiry: 'expired' }).query.expired).toBe(true);
    const q = resultQuery({ ...blank, expiry: '30', self_signed: 'false', scope_id: 's1', q: ' web ' });
    expect(q.query).toMatchObject({ expiring_within_days: 30, self_signed: false, scope_id: 's1', q: 'web' });
    expect(q.filtered).toBe(true);
  });
});

describe('Network discovery results', () => {
  const certificates = [
    discoveredCertificateFixture(),
    discoveredCertificateFixture({ fingerprint_sha256: 'b2'.repeat(32), subject_cn: '', sans: ['san-only.example.test', 'a.test', 'b.test', 'c.test', 'd.test'], status: 'managed', managed_certificate_id: 'mc1', endpoint_count: 1, seen_on_count: 1, expired: true, not_after: '2020-01-01T00:00:00Z', self_signed: true }),
    discoveredCertificateFixture({ fingerprint_sha256: 'c3'.repeat(32), subject_cn: '', sans: [], status: 'known', issuer_cn: '', endpoint_count: 0, seen_on_count: 0 }),
  ];

  it('lists each certificate with its names, issuer, expiry, places and status chips with text', async () => {
    discoveryWorld({ certificates });
    await renderRoute('/discovery');
    const table = await screen.findByRole('table', { name: 'Certificates found on the network' });
    const rows = within(table).getAllByTestId('discovery-result-row');
    expect(rows).toHaveLength(3);
    const [first, second, third] = rows;
    expect(within(first).getByRole('button', { name: 'legacy.example.test' })).toHaveAttribute('aria-haspopup', 'dialog');
    expect(within(first).getByText('old.example.test')).toBeInTheDocument();
    expect(within(first).getByText('Example Issuing CA')).toBeInTheDocument();
    expect(within(first).getByText('2 endpoints')).toBeInTheDocument();
    expect(within(first).getByText('Unmanaged')).toBeInTheDocument();
    expect(within(second).getByRole('button', { name: 'san-only.example.test' })).toBeInTheDocument();
    expect(within(second).getByText('a.test, b.test, c.test …')).toBeInTheDocument();
    expect(within(second).getByText('1 endpoint')).toBeInTheDocument();
    expect(within(second).getByText('Managed')).toBeInTheDocument();
    // The expiry badge says Expired; the status column has no second Expired chip.
    expect(within(second).getAllByText('Expired')).toHaveLength(1);
    expect(within(second).getByText('Self-signed')).toBeInTheDocument();
    expect(within(third).getByRole('button', { name: '(no name)' })).toBeInTheDocument();
    expect(within(third).getByText('Known')).toBeInTheDocument();
    expect(within(third).getByText('No longer found')).toBeInTheDocument();
    expect(within(third).queryByText(/endpoint/)).not.toBeInTheDocument();
    expect(within(first).queryByText('No longer found')).not.toBeInTheDocument();
    // The A10 explanation of "unmanaged".
    expect(screen.getByText(/Alice has no record of this exact certificate/)).toBeInTheDocument();
    expect(screen.getByText(/on a proxy or a load balancer, is still unmanaged/)).toBeInTheDocument();
    expectNoRawKeys();
  });

  it('starts at the unmanaged certificates for ?view=unmanaged, and All statuses really shows all', async () => {
    const seen = discoveryWorld({ certificates });
    const { router } = await renderRoute('/discovery?view=unmanaged&expiry=30');
    await screen.findByRole('table', { name: 'Certificates found on the network' });
    const last = () => requests(seen, 'GET', '/api/v1/discovery/certificates').at(-1)!.search;
    expect(last().get('status')).toBe('unmanaged');
    expect(last().get('expiring_within_days')).toBe('30');
    expect(last().get('current')).toBe('true');
    expect(screen.getByRole('combobox', { name: 'Status' })).toHaveValue('unmanaged');
    await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Status' }), 'all');
    await waitFor(() => expect(last().get('status')).toBeNull());
    expect(router.state.location.search).toBe('?expiry=30&status=all');
  });

  it('sends each filter to the server, the search after a pause, and clears them all', async () => {
    const seen = discoveryWorld({ certificates });
    const { router } = await renderRoute('/discovery');
    await screen.findByRole('table', { name: 'Certificates found on the network' });
    await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Expiry' }), 'expired');
    await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Signed by' }), 'true');
    await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Scope' }), 'Data centre');
    expect(requests(seen, 'GET', '/api/v1/discovery/certificates').at(-1)!.search.get('current')).toBe('true');
    await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Found' }), 'all');
    await userEvent.type(screen.getByRole('textbox', { name: 'Search' }), 'legacy');
    await waitFor(() => expect(router.state.location.search).toContain('q=legacy'), { timeout: 5000 });
    await waitFor(() => expect(requests(seen, 'GET', '/api/v1/discovery/certificates').at(-1)!.search.get('q')).toBe('legacy'), { timeout: 5000 });
    const last = requests(seen, 'GET', '/api/v1/discovery/certificates').at(-1)!.search;
    expect(last.get('expired')).toBe('true');
    expect(last.get('self_signed')).toBe('true');
    expect(last.get('scope_id')).toBeTruthy();
    expect(last.get('q')).toBe('legacy');
    expect(last.get('current')).toBeNull();
    await userEvent.click(screen.getByRole('button', { name: 'Clear filters' }));
    expect(router.state.location.search).toBe('');
    expect(screen.getByRole('textbox', { name: 'Search' })).toHaveValue('');
  });

  it('says when nothing matches, and when nothing was found yet', async () => {
    discoveryWorld({ certificates: [] });
    const { router } = await renderRoute('/discovery');
    expect(await screen.findByText('No certificates found yet')).toBeInTheDocument();
    expect(screen.getByText(/Start a scan of a scope on the Scans tab/)).toBeInTheDocument();
    await act(() => router.navigate('/discovery?status=managed'));
    expect(await screen.findByText('No certificate matches these filters')).toBeInTheDocument();
  });

  it('tells an Auditor where results come from without asking for a scan', async () => {
    discoveryWorld({ session: sessionFor('auditor'), certificates: [] });
    await renderRoute('/discovery');
    expect(await screen.findByText('The certificates found by the scans of a scope appear here.')).toBeInTheDocument();
  });

  it('exports with the filters in the address, and says when another export is running', async () => {
    const seen = discoveryWorld({ certificates });
    const created = vi.fn(() => 'blob:x');
    const revoked = vi.fn();
    Object.assign(URL, { createObjectURL: created, revokeObjectURL: revoked });
    await renderRoute('/discovery?view=unmanaged&self_signed=false');
    await screen.findByRole('table', { name: 'Certificates found on the network' });
    await userEvent.click(screen.getByRole('button', { name: 'Export' }));
    await waitFor(() => expect(created).toHaveBeenCalled());
    const exp = requests(seen, 'GET', '/api/v1/discovery/certificates/export')[0].search;
    expect(exp.get('status')).toBe('unmanaged');
    expect(exp.get('self_signed')).toBe('false');
    expect(exp.get('cursor')).toBeNull();
    server.use(http.get('/api/v1/discovery/certificates/export', () => errorResponse(409, 'ALC-RPT-0004', 'export.busy', { retryable: true })));
    await userEvent.click(screen.getByRole('button', { name: 'Export' }));
    expect(await screen.findByText('ALC-RPT-0004')).toBeInTheDocument();
  });

  it('opens the detail of a certificate with every place it was found, in plain words', async () => {
    const endpoints = [
      discoveredEndpointFixture({ host: 'legacy.example.test', sni: 'legacy.example.test', previous_fingerprints: ['ff'.repeat(32)], target: { id: 't1', name: 'web-01' } }),
      discoveredEndpointFixture({ id: 'e2', address: '2001:db8::5', port: 8443, state: 'no_tls', last_error_code: 'no_tls', tls_version: '', last_seen: null }),
    ];
    discoveryWorld({ certificates: [discoveredCertificateFixture({ endpoints, more_endpoints: true })] });
    await renderRoute('/discovery');
    await userEvent.click(await screen.findByRole('button', { name: 'legacy.example.test' }));
    const drawer = await screen.findByRole('dialog', { name: 'Found on the network: legacy.example.test' });
    const items = await within(drawer).findAllByTestId('discovery-endpoint');
    expect(items).toHaveLength(2);
    expect(within(items[0]).getByText('10.0.1.20:443')).toBeInTheDocument();
    expect(within(items[0]).getByText('Answering')).toBeInTheDocument();
    expect(within(items[0]).getByText('TLS 1.3 · TLS_AES_128_GCM_SHA256')).toBeInTheDocument();
    expect(within(items[0]).getByRole('link', { name: 'web-01' })).toHaveAttribute('href', '/servers/t1');
    expect(within(items[0]).getByText(`${'ff'.repeat(8)}…`)).toBeInTheDocument();
    expect(within(items[0]).queryByRole('button', { name: /Add as server/ })).not.toBeInTheDocument();
    expect(within(items[1]).getByText('[2001:db8::5]:8443')).toBeInTheDocument();
    expect(within(items[1]).getByText('The server did not complete a TLS handshake.')).toBeInTheDocument();
    expect(within(items[1]).getByText('Not a server in Alice')).toBeInTheDocument();
    expect(within(drawer).getByText('Only the first 200 places are shown.')).toBeInTheDocument();
    expect(within(drawer).getByText(`${'a1'.repeat(32)}`)).toBeInTheDocument();
    expectNoRawKeys();
    await userEvent.click(within(drawer).getByRole('button', { name: 'Close' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  });

  it('says "Unknown" for a status this version does not know, never a raw key', async () => {
    discoveryWorld({ certificates: [discoveredCertificateFixture({ status: 'future' as never, endpoints: [] })] });
    await renderRoute('/discovery');
    await userEvent.click(await screen.findByRole('button', { name: 'legacy.example.test' }));
    const drawer = await screen.findByRole('dialog', { name: /^Found on the network: / });
    expect(await within(drawer).findAllByText('Unknown')).not.toHaveLength(0);
    expect(within(drawer).queryByText(/statusText/)).not.toBeInTheDocument();
    expectNoRawKeys();
  });

  it('links a managed certificate to its page in Alice', async () => {
    discoveryWorld({ certificates: [discoveredCertificateFixture({ status: 'managed', managed_certificate_id: 'mc1', endpoints: [] })] });
    await renderRoute('/discovery');
    await userEvent.click(await screen.findByRole('button', { name: 'legacy.example.test' }));
    const drawer = await screen.findByRole('dialog', { name: /^Found on the network: / });
    expect(await within(drawer).findByRole('link', { name: 'Open this certificate in Alice' })).toHaveAttribute('href', '/certificates/mc1');
    expect(within(drawer).getByText('No endpoint presents this certificate now.')).toBeInTheDocument();
  });

  it('opens the existing Add server dialog for an Administrator, filled in with the host found', async () => {
    discoveryWorld({ certificates: [discoveredCertificateFixture({ endpoints: [discoveredEndpointFixture({ host: 'legacy.example.test' })] })] });
    server.use(http.get('/api/v1/ssh-keys/platform-key', () => HttpResponse.json(platformKeyFixture)));
    await renderRoute('/discovery');
    const name = await screen.findByRole('button', { name: 'legacy.example.test' });
    await userEvent.click(name);
    const drawer = await screen.findByRole('dialog', { name: /^Found on the network: / });
    await userEvent.click(await within(drawer).findByRole('button', { name: 'Add as server: 10.0.1.20:443' }));
    const dialog = await screen.findByRole('dialog', { name: 'Add server' });
    expect(within(dialog).getByRole('textbox', { name: /Address/ })).toHaveValue('legacy.example.test');
    expect(within(dialog).getByRole('textbox', { name: /^Name/ })).toHaveValue('legacy.example.test');
    // The SSH port, not the port the certificate was found on.
    expect(within(dialog).getByRole('textbox', { name: /SSH port/ })).toHaveValue('22');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Close' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    await waitFor(() => expect(name).toHaveFocus());
  });

  it.each(['operator', 'auditor'] as const)('offers an %s no Add as server, and says who can', async (role) => {
    discoveryWorld({ session: sessionFor(role) });
    await renderRoute('/discovery');
    await userEvent.click(await screen.findByRole('button', { name: 'legacy.example.test' }));
    const drawer = await screen.findByRole('dialog', { name: /^Found on the network: / });
    expect(await within(drawer).findByText('An administrator can add this server to Alice.')).toBeInTheDocument();
    expect(within(drawer).queryByRole('button', { name: /Add as server/ })).not.toBeInTheDocument();
  });

  it('moves the focus to the name when a row is clicked, so the drawer gives it back there', async () => {
    discoveryWorld({ certificates: [discoveredCertificateFixture({ seen_on_count: 0, endpoint_count: 0 })] });
    await renderRoute('/discovery');
    const name = await screen.findByRole('button', { name: 'legacy.example.test' });
    await userEvent.click(within(screen.getByTestId('discovery-result-row')).getByText('Example Issuing CA'));
    const drawer = await screen.findByRole('dialog', { name: 'Found on the network: legacy.example.test' });
    expect(await within(drawer).findByText('No longer found')).toBeInTheDocument();
    await userEvent.keyboard('{Escape}');
    await waitFor(() => expect(name).toHaveFocus());
  });

  it('closes the detail when the person moves to another tab and back', async () => {
    discoveryWorld();
    await renderRoute('/discovery');
    await userEvent.click(await screen.findByRole('button', { name: 'legacy.example.test' }));
    await screen.findByRole('dialog', { name: /^Found on the network: / });
    await userEvent.keyboard('{Escape}');
    await userEvent.click(screen.getByRole('tab', { name: 'Scans' }));
    await userEvent.click(screen.getByRole('tab', { name: 'Results' }));
    await screen.findByRole('table', { name: 'Certificates found on the network' });
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('shows a failing list as an error', async () => {
    discoveryWorld();
    server.use(http.get('/api/v1/discovery/certificates', () => errorResponse(403, 'ALC-AUTH-0002', 'auth.forbidden')));
    await renderRoute('/discovery');
    expect(await screen.findByText('ALC-AUTH-0002')).toBeInTheDocument();
  });
});
