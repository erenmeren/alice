import { act, fireEvent, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { discoveryPreviewFixture, discoveryScopeFixture, discoverySettingsFixture, errorResponse, sessionFor } from '../../test/fixtures';
import { discoveryWorld, requests, track } from '../../test/discovery';
import { expectNoRawKeys } from '../../test/i18nAssert';
import { renderRoute } from '../../test/render';
import { server } from '../../test/server';
import { browserTimeZone, PREVIEW_DEBOUNCE_MS, timeZones } from './ScopeDialog';

async function openAdd() {
  await renderRoute('/discovery?tab=scopes');
  await userEvent.click(await screen.findByRole('button', { name: 'Add a scope' }));
  return screen.findByRole('dialog', { name: 'Add a scan scope' });
}

const field = (dialog: HTMLElement, name: string | RegExp) => within(dialog).getByRole('textbox', { name });

describe('the time zones', () => {
  it('include UTC and the scope zone, sorted', () => {
    const zones = timeZones('Mars/Olympus');
    expect(zones).toContain('UTC');
    expect(zones).toContain('Mars/Olympus');
    expect([...zones].sort()).toEqual(zones);
    expect(browserTimeZone()).toBeTruthy();
  });

  it('fall back to UTC when the browser lists none', () => {
    const original = (Intl as unknown as { supportedValuesOf?: unknown }).supportedValuesOf;
    Object.assign(Intl, {
      supportedValuesOf: () => {
        throw new Error('no');
      },
    });
    try {
      expect(timeZones('')).toEqual(['UTC']);
    } finally {
      Object.assign(Intl, { supportedValuesOf: original });
    }
  });
});

describe('the scope dialog', () => {
  it('asks for the size once the person stops typing, and cancels the request it replaces', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      const seen = discoveryWorld({ scopes: [] });
      server.use(
        http.post('/api/v1/discovery/scopes/preview', () =>
          HttpResponse.json(discoveryPreviewFixture({ addresses: 1024, ports: 2, endpoints: 2048, excluded_addresses: 3, builtin_exclusions: ['10.0.0.0/32'] })),
        ),
      );
      track(seen);
      const dialog = await openAdd();
      expect(within(dialog).getByText('Enter the addresses and ports to see the size.')).toBeInTheDocument();
      fireEvent.change(field(dialog, /Addresses, ranges and host names/), { target: { value: '10.0.0.0/22' } });
      fireEvent.change(field(dialog, /Addresses, ranges and host names/), { target: { value: '10.0.0.0/2' } });
      fireEvent.change(field(dialog, /Addresses, ranges and host names/), { target: { value: '10.0.0.0/22' } });
      expect(within(dialog).getByText('Checking the size…')).toBeInTheDocument();
      await act(() => vi.advanceTimersByTimeAsync(PREVIEW_DEBOUNCE_MS - 50));
      expect(requests(seen, 'POST', '/api/v1/discovery/scopes/preview')).toHaveLength(0);
      await act(() => vi.advanceTimersByTimeAsync(100));
      expect(await within(dialog).findByText('This scope covers 1,024 addresses × 2 ports.')).toBeInTheDocument();
      const previews = requests(seen, 'POST', '/api/v1/discovery/scopes/preview');
      expect(previews).toHaveLength(1);
      expect(previews[0].body).toEqual({ entries: ['10.0.0.0/22'], ports: [443], sni_names: [], exclusions: [] });
      expect(within(dialog).getByText('One scan tries 2,048 combinations of address, port and server name (at most 20,000).')).toBeInTheDocument();
      expect(within(dialog).getByText('3 addresses are left out by the exclusions.')).toBeInTheDocument();
      expect(within(dialog).getByText('10.0.0.0/32')).toBeInTheDocument();
      // Ports that do not parse ask for nothing.
      fireEvent.change(field(dialog, 'Ports'), { target: { value: '443, https' } });
      await act(() => vi.advanceTimersByTimeAsync(PREVIEW_DEBOUNCE_MS * 2));
      expect(requests(seen, 'POST', '/api/v1/discovery/scopes/preview')).toHaveLength(1);
      expect(within(dialog).getByText('Enter the addresses and ports to see the size.')).toBeInTheDocument();
    } finally {
      vi.useRealTimers();
    }
  });

  it('counts host names apart and names one address and one port in the singular', async () => {
    discoveryWorld({ scopes: [] });
    server.use(http.post('/api/v1/discovery/scopes/preview', () => HttpResponse.json(discoveryPreviewFixture({ addresses: 1, hostnames: 2, ports: 1, endpoints: 3 }))));
    const dialog = await openAdd();
    await userEvent.type(field(dialog, /Addresses, ranges and host names/), '10.0.0.1');
    expect(await within(dialog).findByText('This scope covers 1 address and 2 host names × 1 port.')).toBeInTheDocument();
  });

  it('marks the line the size check refuses', async () => {
    discoveryWorld({ scopes: [] });
    server.use(http.post('/api/v1/discovery/scopes/preview', () => errorResponse(422, 'ALC-DSC-0002', 'discovery.entry_not_allowed', { params: { field: 'entries', index: '1' } })));
    const dialog = await openAdd();
    await userEvent.type(field(dialog, /Addresses, ranges and host names/), '10.0.0.1{enter}169.254.169.254');
    expect(await within(dialog).findByText('Line 2: This address may not be scanned.')).toBeInTheDocument();
    expect(within(dialog).getAllByText('This address may not be scanned.').length).toBeGreaterThan(0);
    expectNoRawKeys();
  });

  it('waits for a click before asking for a step-up for the size', async () => {
    let fresh = false;
    discoveryWorld({ scopes: [] });
    server.use(
      http.post('/api/v1/discovery/scopes/preview', () => (fresh ? HttpResponse.json(discoveryPreviewFixture()) : errorResponse(403, 'ALC-AUTH-0003', 'auth.stepup_required'))),
      http.post('/api/v1/auth/stepup', () => {
        fresh = true;
        return HttpResponse.json({ ...sessionFor('admin'), stepup_until: '2099-01-01T00:00:00Z' });
      }),
    );
    const dialog = await openAdd();
    await userEvent.type(field(dialog, /Addresses, ranges and host names/), '10.0.0.0/22');
    expect(await within(dialog).findByText('Confirm it is you to see the size.')).toBeInTheDocument();
    expect(screen.queryByRole('dialog', { name: /Confirm/ })).not.toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Show the size' }));
    const code = await screen.findByLabelText('6-digit code');
    await userEvent.type(code, '123456{enter}');
    expect(await within(dialog).findByText('This scope covers 1,024 addresses × 2 ports.')).toBeInTheDocument();
  });

  it('checks the form before sending', async () => {
    const seen = discoveryWorld({ scopes: [] });
    const dialog = await openAdd();
    fireEvent.change(field(dialog, 'Ports'), { target: { value: '70000' } });
    fireEvent.change(field(dialog, 'New connections per second'), { target: { value: '500' } });
    await userEvent.click(within(dialog).getByRole('checkbox', { name: 'Only scan during a daily time window' }));
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save scope' }));
    expect(await within(dialog).findByText('Enter a name.')).toBeInTheDocument();
    expect(within(dialog).getByText('Enter at least one address, range or host name.')).toBeInTheDocument();
    expect(within(dialog).getByText('A port is a number from 1 to 65535.')).toBeInTheDocument();
    expect(within(dialog).getByText('A time window needs a schedule: enter the hours between scans.')).toBeInTheDocument();
    expect(requests(seen, 'POST', '/api/v1/discovery/scopes')).toHaveLength(0);
  });

  it('creates a scope with every field, the window in the chosen zone', async () => {
    const seen = discoveryWorld({ scopes: [], settings: discoverySettingsFixture() });
    server.use(
      http.post('/api/v1/discovery/scopes/preview', () => HttpResponse.json(discoveryPreviewFixture())),
      http.post('/api/v1/discovery/scopes', () => HttpResponse.json(discoveryScopeFixture(), { status: 201 })),
    );
    track(seen);
    const dialog = await openAdd();
    await userEvent.type(field(dialog, 'Name'), 'Data centre');
    await userEvent.type(field(dialog, /Addresses, ranges and host names/), '10.0.1.0/24{enter}intranet.example.test');
    fireEvent.change(field(dialog, 'Ports'), { target: { value: '443, 8443' } });
    await userEvent.type(field(dialog, /Server names to ask for/), 'a.example.test');
    await userEvent.type(field(dialog, /Leave out/), '10.0.1.9');
    fireEvent.change(field(dialog, 'New connections per second'), { target: { value: '50' } });
    fireEvent.change(field(dialog, 'Connections at the same time'), { target: { value: '16' } });
    fireEvent.change(field(dialog, 'Scan every (hours)'), { target: { value: '24' } });
    await userEvent.click(within(dialog).getByRole('checkbox', { name: 'Only scan during a daily time window' }));
    expect(within(dialog).getByText(/the window still closes at its local end time/)).toBeInTheDocument();
    await userEvent.selectOptions(within(dialog).getByRole('combobox', { name: 'Time zone' }), 'UTC');
    await userEvent.click(within(dialog).getByRole('switch', { name: /E-mail before certificates/ }));
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save scope' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(requests(seen, 'POST', '/api/v1/discovery/scopes')[0].body).toEqual({
      name: 'Data centre',
      entries: ['10.0.1.0/24', 'intranet.example.test'],
      ports: [443, 8443],
      sni_names: ['a.example.test'],
      exclusions: ['10.0.1.9'],
      enabled: true,
      alert_on_expiry: true,
      rate_per_sec: 50,
      concurrency: 16,
      schedule_hours: 24,
      window_start: '01:00',
      window_end: '05:00',
      window_tz: 'UTC',
    });
  });

  it('marks the line a save refuses and shows the full reason with its code', async () => {
    discoveryWorld({ scopes: [] });
    server.use(
      http.post('/api/v1/discovery/scopes/preview', () => HttpResponse.json(discoveryPreviewFixture())),
      http.post('/api/v1/discovery/scopes', () => errorResponse(422, 'ALC-DSC-0010', 'discovery.name_unresolved', { params: { field: 'entries', index: '0' } })),
    );
    const dialog = await openAdd();
    await userEvent.type(field(dialog, 'Name'), 'Lab');
    await userEvent.type(field(dialog, /Addresses, ranges and host names/), 'nowhere.example.test');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save scope' }));
    expect(await within(dialog).findByText('Line 1: A host name in this scope could not be found.')).toBeInTheDocument();
    expect(within(dialog).getByText('ALC-DSC-0010')).toBeInTheDocument();
  });

  it('says a scope cannot be saved before the allowed networks are set', async () => {
    discoveryWorld({ scopes: [], settings: discoverySettingsFixture({ allowed_networks: [], scanning_enabled: false }) });
    const dialog = await openAdd();
    expect(within(dialog).getByText(/so this scope cannot be saved/)).toBeInTheDocument();
  });

  it('changes only what was changed, with the version, and the schedule as one group', async () => {
    const scope = discoveryScopeFixture({ schedule_hours: 6, active_scan_id: 'n1' });
    const seen = discoveryWorld({ scopes: [scope] });
    server.use(
      http.post('/api/v1/discovery/scopes/preview', () => HttpResponse.json(discoveryPreviewFixture())),
      http.patch('/api/v1/discovery/scopes/:id', () => HttpResponse.json(scope)),
    );
    track(seen);
    await renderRoute('/discovery?tab=scopes');
    await userEvent.click(await screen.findByRole('button', { name: 'Edit Data centre' }));
    const dialog = await screen.findByRole('dialog', { name: 'Change Data centre' });
    expect(within(dialog).getByText('A scan of this scope is running')).toBeInTheDocument();
    expect(field(dialog, /Addresses, ranges and host names/)).toHaveValue('10.0.1.0/24\nintranet.example.test');
    // Nothing changed: nothing to save.
    expect(within(dialog).getByRole('button', { name: 'Save scope' })).toBeDisabled();
    expect(within(dialog).getByText('Nothing has changed yet.')).toBeInTheDocument();
    fireEvent.change(field(dialog, 'Scan every (hours)'), { target: { value: '12' } });
    await userEvent.click(within(dialog).getByRole('switch', { name: /^Switched on/ }));
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save scope' }));
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Change Data centre' })).not.toBeInTheDocument());
    const [patch] = requests(seen, 'PATCH', /\/scopes\//);
    expect(patch.ifMatch).toBe('"3"');
    expect(patch.body).toEqual({ enabled: false, schedule_hours: 12, window_start: '', window_end: '', window_tz: '' });
  });

  it('sends every changed list and the pace when they change', async () => {
    const scope = discoveryScopeFixture({ schedule_hours: 24, window_start: '22:00', window_end: '02:00', window_tz: 'Europe/Istanbul', rate_per_sec: 10 });
    const seen = discoveryWorld({ scopes: [scope] });
    server.use(
      http.post('/api/v1/discovery/scopes/preview', () => HttpResponse.json(discoveryPreviewFixture())),
      http.patch('/api/v1/discovery/scopes/:id', () => HttpResponse.json(scope)),
    );
    track(seen);
    await renderRoute('/discovery?tab=scopes');
    await userEvent.click(await screen.findByRole('button', { name: 'Edit Data centre' }));
    const dialog = await screen.findByRole('dialog', { name: 'Change Data centre' });
    expect(within(dialog).getByRole('combobox', { name: 'Time zone' })).toHaveValue('Europe/Istanbul');
    fireEvent.change(field(dialog, 'Name'), { target: { value: 'DC' } });
    fireEvent.change(field(dialog, /Addresses, ranges and host names/), { target: { value: '10.0.1.0/24' } });
    fireEvent.change(field(dialog, 'Ports'), { target: { value: '443' } });
    fireEvent.change(field(dialog, /Server names to ask for/), { target: { value: 'x.example.test' } });
    fireEvent.change(field(dialog, /Leave out/), { target: { value: '10.0.1.1' } });
    fireEvent.change(field(dialog, 'New connections per second'), { target: { value: '' } });
    fireEvent.change(field(dialog, 'Connections at the same time'), { target: { value: '8' } });
    await userEvent.click(within(dialog).getByRole('switch', { name: /E-mail before certificates/ }));
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save scope' }));
    await waitFor(() => expect(requests(seen, 'PATCH', /\/scopes\//)).toHaveLength(1));
    expect(requests(seen, 'PATCH', /\/scopes\//)[0].body).toEqual({
      name: 'DC',
      entries: ['10.0.1.0/24'],
      ports: [443],
      sni_names: ['x.example.test'],
      exclusions: ['10.0.1.1'],
      alert_on_expiry: true,
      rate_per_sec: 0,
      concurrency: 8,
    });
  });

  it('shows a slow name server as a refusal to try again', async () => {
    discoveryWorld({ scopes: [] });
    server.use(
      http.post('/api/v1/discovery/scopes/preview', () => errorResponse(500, 'ALC-SYS-0003', 'internal.unexpected')),
      http.post('/api/v1/discovery/scopes', () => errorResponse(503, 'ALC-SYS-0002', 'system.unavailable', { retryable: true })),
    );
    const dialog = await openAdd();
    await userEvent.type(field(dialog, 'Name'), 'Lab');
    await userEvent.type(field(dialog, /Addresses, ranges and host names/), 'a.example.test');
    expect(await within(dialog).findByText('Something went wrong on our side.')).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save scope' }));
    expect(await within(dialog).findByText('ALC-SYS-0002')).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  });
});
