import { act, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import type { DiscoveryScope } from '../../api/discovery';
import { discoveryScanFixture, discoveryScopeFixture, discoverySettingsFixture, errorResponse, sessionFor } from '../../test/fixtures';
import { discoveryWorld, requests, track } from '../../test/discovery';
import { expectNoRawKeys } from '../../test/i18nAssert';
import { renderRoute } from '../../test/render';
import { STARTED_MESSAGE_MS } from './StartScan';
import { server } from '../../test/server';

describe('Network discovery scopes', () => {
  it('lists each scope with its size, ports, schedule, switch, e-mails and last scan', async () => {
    discoveryWorld({
      scopes: [
        discoveryScopeFixture({ sni_names: ['a.test'], exclusions: ['10.0.1.9'], schedule_hours: 36, window_start: '01:00', window_end: '05:00', window_tz: 'Europe/Istanbul', alert_on_expiry: true }),
        discoveryScopeFixture({ id: 's2', name: 'Lab', entries: ['10.0.2.5'], ports: [636], enabled: false, last_scan: null, schedule_hours: 6 }),
        discoveryScopeFixture({ id: 's3', name: 'Busy', active_scan_id: 'n9', last_scan: discoveryScanFixture({ state: 'failed', error_code: 'ALC-DSC-0012', error_reason: 'discovery.scan_interrupted' }) }),
      ],
    });
    await renderRoute('/discovery?tab=scopes');
    const table = await screen.findByRole('table', { name: 'Scan scopes' });
    const [dc, lab, busy] = within(table).getAllByTestId('discovery-scope-row');
    expect(within(dc).getByText('2 addresses, ranges and host names · 1 server name · 1 left out')).toBeInTheDocument();
    expect(within(dc).getByText('443, 8443')).toBeInTheDocument();
    expect(within(dc).getByText('Every 2 days, between 01:00 and 05:00 (Europe/Istanbul)')).toBeInTheDocument();
    expect(within(dc).getByText('With a daily time window, 36 hours count as whole days: every 2 days.')).toBeInTheDocument();
    // The switch is named by its scope alone; On/Off is the visible state beside it.
    expect(within(dc).getByRole('switch', { name: 'Data centre' })).toBeChecked();
    expect(within(dc).getByRole('switch', { name: 'Data centre' }).closest('td')).toHaveTextContent('On');
    expect(within(dc).getByText('Sends e-mails')).toBeInTheDocument();
    expect(within(dc).getByText('Finished')).toBeInTheDocument();
    expect(within(lab).getByText('Every 6 hours')).toBeInTheDocument();
    expect(within(lab).getByText('Never scanned')).toBeInTheDocument();
    expect(within(lab).getByRole('switch', { name: 'Lab' })).not.toBeChecked();
    expect(within(lab).getByRole('switch', { name: 'Lab' }).closest('td')).toHaveTextContent('Off');
    expect(within(lab).getByRole('button', { name: 'Scan now: Lab' })).toBeDisabled();
    expect(within(lab).getByText('This scope is switched off.')).toBeInTheDocument();
    expect(within(busy).getByText('Running')).toBeInTheDocument();
    expect(within(busy).getByRole('button', { name: 'Scan now: Busy' })).toHaveAccessibleDescription('A scan of this scope is already running.');
    expectNoRawKeys();
  });

  it('shows the settings: allowed networks, exclusions, retention and the built-in exclusions', async () => {
    discoveryWorld();
    await renderRoute('/discovery?tab=scopes');
    const panel = await screen.findByTestId('discovery-settings');
    expect(await within(panel).findByText('10.0.0.0/16')).toBeInTheDocument();
    expect(within(panel).getByText('10.0.9.0/24')).toBeInTheDocument();
    expect(within(panel).getByText('90 days')).toBeInTheDocument();
    expect(within(panel).getByText('169.254.0.0/16')).toBeInTheDocument();
    expect(screen.queryByTestId('discovery-no-networks')).not.toBeInTheDocument();
  });

  it('starts a scan of a scope, and shows a refusal from the server', async () => {
    const seen = discoveryWorld();
    await renderRoute('/discovery?tab=scopes');
    await userEvent.click(await screen.findByRole('button', { name: 'Scan now: Data centre' }));
    expect(await screen.findByText('The scan of Data centre has started.')).toBeInTheDocument();
    expect(requests(seen, 'POST', /\/scopes\/.+\/scans$/)).toHaveLength(1);
    server.use(http.post('/api/v1/discovery/scopes/:id/scans', () => errorResponse(409, 'ALC-DSC-0007', 'discovery.too_many_scans', { retryable: true })));
    await userEvent.click(screen.getByRole('button', { name: 'Scan now: Data centre' }));
    expect(await screen.findByText('Too many scans are running.')).toBeInTheDocument();
  });

  it('clears the "scan started" line after a few seconds, or when the scan is over', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      let active: string | null = null;
      discoveryWorld({ scopes: () => [discoveryScopeFixture({ active_scan_id: active })] });
      server.use(
        http.post('/api/v1/discovery/scopes/:id/scans', () => {
          active = 'n1';
          return HttpResponse.json(discoveryScanFixture({ id: 'n1', state: 'queued', started_at: null, finished_at: null }), { status: 202 });
        }),
      );
      await renderRoute('/discovery?tab=scopes');
      await userEvent.click(await screen.findByRole('button', { name: 'Scan now: Data centre' }));
      expect(await screen.findByText('The scan of Data centre has started.')).toBeInTheDocument();
      await waitFor(() => expect(screen.getByRole('button', { name: 'Scan now: Data centre' })).toBeDisabled());
      active = null;
      await act(() => vi.advanceTimersByTimeAsync(3100));
      await waitFor(() => expect(screen.queryByText('The scan of Data centre has started.')).not.toBeInTheDocument());
      // A second start whose scan the list has not shown yet: the line goes after a few seconds.
      server.use(http.post('/api/v1/discovery/scopes/:id/scans', () => HttpResponse.json(discoveryScanFixture({ state: 'queued', started_at: null, finished_at: null }), { status: 202 })));
      await userEvent.click(screen.getByRole('button', { name: 'Scan now: Data centre' }));
      expect(await screen.findByText('The scan of Data centre has started.')).toBeInTheDocument();
      await act(() => vi.advanceTimersByTimeAsync(STARTED_MESSAGE_MS + 100));
      await waitFor(() => expect(screen.queryByText('The scan of Data centre has started.')).not.toBeInTheDocument());
    } finally {
      vi.useRealTimers();
    }
  });

  it('switches a scope off with its version', async () => {
    const seen = discoveryWorld();
    server.use(http.patch('/api/v1/discovery/scopes/:id', () => HttpResponse.json(discoveryScopeFixture({ enabled: false }))));
    track(seen);
    await renderRoute('/discovery?tab=scopes');
    await userEvent.click(await screen.findByRole('switch', { name: 'Data centre' }));
    await waitFor(() => expect(requests(seen, 'PATCH', /\/scopes\//)).toHaveLength(1));
    const [patch] = requests(seen, 'PATCH', /\/scopes\//);
    expect(patch.body).toEqual({ enabled: false });
    expect(patch.ifMatch).toBe('"3"');
  });

  it('asks before deleting a scope, says what happens to its results, and the row leaves at once', async () => {
    let scopes: DiscoveryScope[] = [discoveryScopeFixture(), discoveryScopeFixture({ id: 's2', name: 'Lab' })];
    const seen = discoveryWorld({ scopes: () => scopes });
    let release: () => void = () => {};
    const gate = new Promise<void>((r) => (release = r));
    server.use(
      http.delete('/api/v1/discovery/scopes/:id', () => {
        scopes = [discoveryScopeFixture()];
        return new HttpResponse(null, { status: 204 });
      }),
      // The list read after the delete is slow: the deleted row must not come back meanwhile.
      http.get('/api/v1/discovery/scopes', async () => {
        if (requests(seen, 'DELETE', /scopes/).length > 0) await gate;
        return HttpResponse.json({ items: scopes, next_cursor: null });
      }),
    );
    track(seen);
    await renderRoute('/discovery?tab=scopes');
    await userEvent.click(await screen.findByRole('button', { name: 'Delete Lab' }));
    const dialog = await screen.findByRole('dialog', { name: 'Delete Lab?' });
    expect(within(dialog).getByText(/removed by the regular cleanup/)).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Delete scope' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(screen.queryByRole('button', { name: 'Delete Lab' })).not.toBeInTheDocument();
    expect(requests(seen, 'DELETE', /scopes/)[0].ifMatch).toBe('"3"');
    await waitFor(() => expect(screen.getByRole('button', { name: 'Add a scope' })).toHaveFocus());
    release();
  });

  it('keeps the dialog open with the error when the delete is refused', async () => {
    discoveryWorld();
    server.use(http.delete('/api/v1/discovery/scopes/:id', () => errorResponse(404, 'ALC-DSC-0008', 'discovery.scope_not_found')));
    await renderRoute('/discovery?tab=scopes');
    await userEvent.click(await screen.findByRole('button', { name: 'Delete Data centre' }));
    const dialog = await screen.findByRole('dialog');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Delete scope' }));
    expect(await within(dialog).findByText('This scan scope was not found.')).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
  });

  it('shows a scopes list that cannot be read, and an empty list for each role', async () => {
    discoveryWorld({ scopes: [] });
    await renderRoute('/discovery?tab=scopes');
    expect(await screen.findByText('No scan scopes yet')).toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: 'Add a scope' })).toHaveLength(1);
  });

  it('says an Operator cannot add scopes in the empty list', async () => {
    discoveryWorld({ session: sessionFor('operator'), scopes: [] });
    await renderRoute('/discovery?tab=scopes');
    expect(await screen.findByText('An administrator adds scopes. Nothing is scanned until then.')).toBeInTheDocument();
  });

  it('shows the errors of the scope and settings reads', async () => {
    discoveryWorld();
    server.use(
      http.get('/api/v1/discovery/scopes', () => errorResponse(500, 'ALC-SYS-0003', 'internal.unexpected')),
      http.get('/api/v1/discovery/settings', () => errorResponse(500, 'ALC-SYS-0003', 'internal.unexpected')),
    );
    await renderRoute('/discovery?tab=scopes');
    await waitFor(() => expect(screen.getAllByText('ALC-SYS-0003')).toHaveLength(2));
  });
});

describe('Network discovery settings dialog', () => {
  it('saves the lists line by line and the retention', async () => {
    const seen = discoveryWorld({ settings: discoverySettingsFixture({ allowed_networks: [], scanning_enabled: false, global_exclusions: [] }) });
    server.use(http.put('/api/v1/discovery/settings', () => HttpResponse.json(discoverySettingsFixture())));
    track(seen);
    await renderRoute('/discovery?tab=scopes');
    await userEvent.click(await screen.findByRole('button', { name: 'Change settings' }));
    const dialog = await screen.findByRole('dialog', { name: 'Discovery settings' });
    await userEvent.type(within(dialog).getByRole('textbox', { name: 'Allowed scan networks' }), '10.0.0.0/16{enter}{enter} 10.1.0.0/16 ');
    await userEvent.type(within(dialog).getByRole('textbox', { name: 'Never scan these' }), '10.0.9.0/24');
    const retention = within(dialog).getByRole('textbox', { name: 'Keep results for (days)' });
    await userEvent.clear(retention);
    await userEvent.type(retention, '30');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save settings' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(requests(seen, 'PUT', '/api/v1/discovery/settings')[0].body).toEqual({ allowed_networks: ['10.0.0.0/16', '10.1.0.0/16'], global_exclusions: ['10.0.9.0/24'], retention_days: 30 });
  });

  it('checks the retention before sending and marks the line the server refuses', async () => {
    const seen = discoveryWorld();
    server.use(http.put('/api/v1/discovery/settings', () => errorResponse(422, 'ALC-DSC-0003', 'discovery.entry_invalid', { params: { field: 'allowed_networks', index: '1' } })));
    track(seen);
    await renderRoute('/discovery?tab=scopes');
    await userEvent.click(await screen.findByRole('button', { name: 'Change settings' }));
    const dialog = await screen.findByRole('dialog', { name: 'Discovery settings' });
    const retention = within(dialog).getByRole('textbox', { name: 'Keep results for (days)' });
    await userEvent.clear(retention);
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save settings' }));
    expect(await within(dialog).findByText('Enter a whole number of days from 7 to 730.')).toBeInTheDocument();
    expect(requests(seen, 'PUT', '/api/v1/discovery/settings')).toHaveLength(0);
    await userEvent.type(retention, '30');
    await userEvent.type(within(dialog).getByRole('textbox', { name: 'Allowed scan networks' }), '{enter}not-a-network');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save settings' }));
    expect(await within(dialog).findByText('Line 2: An entry of this scope is not valid.')).toBeInTheDocument();
    expectNoRawKeys();
  });
});
