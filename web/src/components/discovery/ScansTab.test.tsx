import { act, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { discoveryScanFixture, discoveryScopeFixture, discoverySettingsFixture, errorResponse, SCAN_ID, sessionFor } from '../../test/fixtures';
import { STARTED_MESSAGE_MS } from './StartScan';
import { discoveryWorld, requests, track } from '../../test/discovery';
import { expectNoRawKeys } from '../../test/i18nAssert';
import { renderRoute } from '../../test/render';
import { server } from '../../test/server';

describe('Network discovery scans', () => {
  it('lists the scans with scope, trigger, state, counts, times, duration and why one ended early', async () => {
    discoveryWorld({
      scans: [
        discoveryScanFixture({ id: 'n1', state: 'running', finished_at: null, certificates_new: 0 }),
        discoveryScanFixture({ id: 'n2', trigger: 'schedule' }),
        discoveryScanFixture({ id: 'n3', state: 'failed', error_code: 'ALC-DSC-0012', error_reason: 'discovery.scan_interrupted' }),
        discoveryScanFixture({ id: 'n4', state: 'queued', started_at: null, finished_at: null, cancel_requested: true }),
        discoveryScanFixture({ id: 'n5', state: 'cancelled', error_code: 'ALC-DSC-0005', error_reason: 'discovery.scan_cancelled', started_at: '2026-10-13T08:00:00Z', finished_at: '2026-10-13T09:30:00Z' }),
        discoveryScanFixture({ id: 'n6', state: 'timed_out', error_code: 'ALC-DSC-0006', error_reason: null, finished_at: '2026-10-13T09:00:30Z' }),
      ],
    });
    await renderRoute('/discovery?tab=scans');
    const table = await screen.findByRole('table', { name: 'Scans' });
    const [running, scheduled, failed, queued, cancelled, timedOut] = within(table).getAllByTestId('discovery-scan-row');
    expect(within(running).getByText('Running')).toBeInTheDocument();
    expect(within(running).getByText('Still running')).toBeInTheDocument();
    expect(within(running).getByRole('button', { name: 'Cancel scan: Data centre' })).toBeInTheDocument();
    expect(within(scheduled).getByText('Schedule')).toBeInTheDocument();
    expect(within(scheduled).getByText('40 answered · 472 not answering · 512 in total')).toBeInTheDocument();
    expect(within(scheduled).getByText('3 new certificates')).toBeInTheDocument();
    expect(within(scheduled).getByText('3 min 12 s')).toBeInTheDocument();
    expect(within(failed).getByText('Failed')).toBeInTheDocument();
    expect(within(failed).getByText('The scan was interrupted.')).toBeInTheDocument();
    expect(within(failed).getByText(/Start the scan again/)).toBeInTheDocument();
    expect(within(failed).getByText('Error code: ALC-DSC-0012')).toBeInTheDocument();
    expect(within(queued).getByText('Waiting to start')).toBeInTheDocument();
    expect(within(queued).getByText('Stopping…')).toBeInTheDocument();
    expect(within(queued).getByText('Not started yet')).toBeInTheDocument();
    expect(within(queued).queryByRole('button', { name: /Cancel scan/ })).not.toBeInTheDocument();
    expect(within(cancelled).getByText('1 h 30 min')).toBeInTheDocument();
    expect(within(cancelled).getByText('The scan was cancelled.')).toBeInTheDocument();
    expect(within(timedOut).getByText('Took too long')).toBeInTheDocument();
    expect(within(timedOut).getByText('29 s')).toBeInTheDocument();
    expect(screen.getByText(/This list updates by itself while a scan runs/)).toBeInTheDocument();
    expectNoRawKeys();
  });

  it('cancels a running scan', async () => {
    const seen = discoveryWorld({ scans: [discoveryScanFixture({ id: 'n1', state: 'running', finished_at: null })] });
    await renderRoute('/discovery?tab=scans');
    await userEvent.click(await screen.findByRole('button', { name: 'Cancel scan: Data centre' }));
    await waitFor(() => expect(requests(seen, 'POST', '/api/v1/discovery/scans/n1/cancel')).toHaveLength(1));
  });

  it('shows a refused cancel', async () => {
    const seen = discoveryWorld({ scans: [discoveryScanFixture({ id: 'n1', state: 'running', finished_at: null })] });
    server.use(http.post('/api/v1/discovery/scans/:id/cancel', () => errorResponse(429, 'ALC-SYS-0005', 'rate.limited', { retryable: true })));
    track(seen);
    await renderRoute('/discovery?tab=scans');
    await userEvent.click(await screen.findByRole('button', { name: 'Cancel scan: Data centre' }));
    expect(await screen.findByText('ALC-SYS-0005')).toBeInTheDocument();
  });

  it('starts a scan of the scope chosen in the dialog, scopes that cannot start listed with their reason', async () => {
    const seen = discoveryWorld({
      scopes: [discoveryScopeFixture({ id: 's1', name: 'Off', enabled: false }), discoveryScopeFixture({ id: 's2', name: 'Lab' }), discoveryScopeFixture({ id: 's3', name: 'Busy', active_scan_id: 'n9' })],
      scans: [],
    });
    await renderRoute('/discovery?tab=scans');
    expect(await screen.findByText('No scans yet')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Start a scan' }));
    const dialog = await screen.findByRole('dialog', { name: 'Start a scan' });
    const select = within(dialog).getByRole('combobox', { name: 'Scope' });
    expect(select).toHaveValue('s2');
    expect(within(select).getByRole('option', { name: 'Off (This scope is switched off.)' })).toBeDisabled();
    expect(within(select).getByRole('option', { name: 'Busy (A scan of this scope is already running.)' })).toBeDisabled();
    expect(within(dialog).getByText(/It changes nothing on the scanned servers/)).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Start scan' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(await screen.findByText('The scan of Data centre has started.')).toBeInTheDocument();
    expect(requests(seen, 'POST', '/api/v1/discovery/scopes/s2/scans')).toHaveLength(1);
  });

  it('keeps a refused start in the dialog', async () => {
    const seen = discoveryWorld({ scans: [] });
    server.use(http.post('/api/v1/discovery/scopes/:id/scans', () => errorResponse(409, 'ALC-DSC-0013', 'discovery.scope_disabled')));
    track(seen);
    await renderRoute('/discovery?tab=scans');
    await userEvent.click(await screen.findByRole('button', { name: 'Start a scan' }));
    const dialog = await screen.findByRole('dialog', { name: 'Start a scan' });
    await userEvent.click(within(dialog).getByRole('button', { name: 'Start scan' }));
    expect(await within(dialog).findByText('This scan scope is switched off.')).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
  });

  it.each([
    ['two scans run', { scopes: [discoveryScopeFixture({ id: 'a', active_scan_id: 'x' }), discoveryScopeFixture({ id: 'b', name: 'B', active_scan_id: 'y' }), discoveryScopeFixture({ id: 'c', name: 'C' })] }, 'Two scans are already running. Wait until one has finished.'],
    ['no allowed network is set', { settings: discoverySettingsFixture({ allowed_networks: [], scanning_enabled: false }) }, 'No allowed scan networks are set, so nothing can be scanned.'],
    ['the license is locked', { locked: true }, 'The license does not allow scans now.'],
    ['every scope is off', { scopes: [discoveryScopeFixture({ enabled: false })] }, 'No scope can be scanned now: each one is switched off or already being scanned.'],
    ['there is no scope', { scopes: [] }, 'Add a scope on the Scopes tab first.'],
  ])('disables Start a scan when %s, with the reason', async (_case, world, reason) => {
    discoveryWorld({ scans: [], ...world });
    await renderRoute('/discovery?tab=scans');
    const button = await screen.findByRole('button', { name: 'Start a scan' });
    await waitFor(() => expect(button).toBeDisabled());
    expect(button).toHaveAccessibleDescription(reason);
  });

  it('tells an Operator without scopes that an Administrator adds them', async () => {
    discoveryWorld({ session: sessionFor('operator'), scans: [], scopes: [] });
    await renderRoute('/discovery?tab=scans');
    expect(await screen.findByText('An administrator adds scopes first.')).toBeInTheDocument();
  });

  it('shows a dash, not an empty cell, for a cancelled scan that carries no problem', async () => {
    discoveryWorld({ scans: [discoveryScanFixture({ id: 'n1', state: 'cancelled', error_code: null, error_reason: null })] });
    await renderRoute('/discovery?tab=scans');
    const row = await screen.findByTestId('discovery-scan-row');
    expect(within(row).queryByTestId('scan-problem')).not.toBeInTheDocument();
    expect(within(row).getAllByRole('cell')[7]).toHaveTextContent('–');
  });

  it('does not say there are no scopes while the scopes are not loaded', async () => {
    discoveryWorld({ scans: [] });
    server.use(http.get('/api/v1/discovery/scopes', () => errorResponse(500, 'ALC-SYS-0003', 'internal.unexpected')));
    await renderRoute('/discovery?tab=scans');
    const button = await screen.findByRole('button', { name: 'Start a scan' });
    await waitFor(() => expect(button).toHaveAccessibleDescription('Scopes are not loaded yet.'));
    expect(screen.queryByText('Add a scope on the Scopes tab first.')).not.toBeInTheDocument();
  });

  it('polls only while a scan is queued or running, and stops when it is over', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      let state: 'running' | 'done' = 'running';
      const seen = discoveryWorld({ scans: () => [discoveryScanFixture({ state, finished_at: state === 'done' ? '2026-10-13T09:05:00Z' : null })] });
      await renderRoute('/discovery?tab=scans');
      await screen.findByRole('table', { name: 'Scans' });
      const reads = () => requests(seen, 'GET', '/api/v1/discovery/scans').length;
      const before = reads();
      await act(() => vi.advanceTimersByTimeAsync(3100));
      await waitFor(() => expect(reads()).toBeGreaterThan(before));
      state = 'done';
      await act(() => vi.advanceTimersByTimeAsync(3100));
      await waitFor(() => expect(screen.getByTestId('discovery-scan-row')).toHaveAttribute('data-state', 'done'));
      const settled = reads();
      await act(() => vi.advanceTimersByTimeAsync(10_000));
      expect(reads()).toBe(settled);
    } finally {
      vi.useRealTimers();
    }
  });

  it('shows a list that cannot be read', async () => {
    const seen = discoveryWorld();
    server.use(http.get('/api/v1/discovery/scans', () => errorResponse(500, 'ALC-SYS-0003', 'internal.unexpected')));
    track(seen);
    await renderRoute('/discovery?tab=scans');
    expect(await screen.findByText('ALC-SYS-0003')).toBeInTheDocument();
  });
});

describe('Network discovery scans (review round)', () => {
  it('polls only the first page, and loads older pages once', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      const seen = discoveryWorld();
      server.use(
        http.get('/api/v1/discovery/scans', ({ request }) =>
          new URL(request.url).searchParams.get('cursor')
            ? HttpResponse.json({ items: [discoveryScanFixture({ id: 'old', scope_name: 'Old scope' }), discoveryScanFixture({ id: 'n1', state: 'running', finished_at: null })], next_cursor: null })
            : HttpResponse.json({ items: [discoveryScanFixture({ id: 'n1', state: 'running', finished_at: null })], next_cursor: 'p2' }),
        ),
      );
      track(seen);
      await renderRoute('/discovery?tab=scans');
      await screen.findByRole('table', { name: 'Scans' });
      await userEvent.click(screen.getByRole('button', { name: 'Load more scans' }));
      expect(await screen.findByText('Old scope')).toBeInTheDocument();
      // n1 is on both pages: shown once.
      expect(screen.getAllByTestId('discovery-scan-row')).toHaveLength(2);
      expect(screen.queryByRole('button', { name: 'Load more scans' })).not.toBeInTheDocument();
      const cursorReads = () => requests(seen, 'GET', '/api/v1/discovery/scans').filter((r) => r.search.get('cursor')).length;
      const firstReads = () => requests(seen, 'GET', '/api/v1/discovery/scans').filter((r) => !r.search.get('cursor')).length;
      const before = firstReads();
      await act(() => vi.advanceTimersByTimeAsync(3100 * 3));
      await waitFor(() => expect(firstReads()).toBeGreaterThan(before));
      expect(cursorReads()).toBe(1);
    } finally {
      vi.useRealTimers();
    }
  });

  it('drops the older pages when the first page moves on, so no scans are skipped', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      let firstCursor = 'p2';
      discoveryWorld();
      server.use(
        http.get('/api/v1/discovery/scans', ({ request }) =>
          new URL(request.url).searchParams.get('cursor')
            ? HttpResponse.json({ items: [discoveryScanFixture({ id: 'old', scope_name: 'Old scope' })], next_cursor: null })
            : HttpResponse.json({ items: [discoveryScanFixture({ id: 'n1', state: 'running', finished_at: null })], next_cursor: firstCursor }),
        ),
      );
      await renderRoute('/discovery?tab=scans');
      await screen.findByRole('table', { name: 'Scans' });
      await userEvent.click(screen.getByRole('button', { name: 'Load more scans' }));
      expect(await screen.findByText('Old scope')).toBeInTheDocument();
      firstCursor = 'p3'; // a scan was queued: the first page now ends elsewhere
      await act(() => vi.advanceTimersByTimeAsync(3100));
      await waitFor(() => expect(screen.queryByText('Old scope')).not.toBeInTheDocument());
      expect(screen.getByRole('button', { name: 'Load more scans' })).toBeInTheDocument();
    } finally {
      vi.useRealTimers();
    }
  });

  it('shows an older page that cannot be read', async () => {
    const seen = discoveryWorld();
    server.use(
      http.get('/api/v1/discovery/scans', ({ request }) =>
        new URL(request.url).searchParams.get('cursor') ? errorResponse(500, 'ALC-SYS-0003', 'internal.unexpected') : HttpResponse.json({ items: [discoveryScanFixture()], next_cursor: 'p2' }),
      ),
    );
    track(seen);
    await renderRoute('/discovery?tab=scans');
    await userEvent.click(await screen.findByRole('button', { name: 'Load more scans' }));
    expect(await screen.findByText('ALC-SYS-0003')).toBeInTheDocument();
  });

  it('stops polling when the page is left', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      const seen = discoveryWorld({
        scopes: [discoveryScopeFixture({ active_scan_id: 'n1' })],
        scans: [discoveryScanFixture({ id: 'n1', state: 'running', finished_at: null })],
      });
      const { router } = await renderRoute('/discovery?tab=scans');
      await screen.findByRole('table', { name: 'Scans' });
      await act(() => router.navigate('/'));
      await screen.findByRole('heading', { level: 1, name: 'Overview' });
      const reads = () => requests(seen, 'GET', /\/discovery\/(scans|scopes)$/).length;
      const left = reads();
      await act(() => vi.advanceTimersByTimeAsync(15_000));
      expect(reads()).toBe(left);
    } finally {
      vi.useRealTimers();
    }
  });

  it('clears "the scan has started" once that scan is over, and after a few seconds anyway', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      let state: 'queued' | 'done' = 'queued';
      discoveryWorld({ scans: () => [discoveryScanFixture({ id: SCAN_ID, state, started_at: null, finished_at: state === 'done' ? '2026-10-13T09:05:00Z' : null })] });
      await renderRoute('/discovery?tab=scans');
      await userEvent.click(await screen.findByRole('button', { name: 'Start a scan' }));
      await userEvent.click(within(await screen.findByRole('dialog', { name: 'Start a scan' })).getByRole('button', { name: 'Start scan' }));
      expect(await screen.findByText('The scan of Data centre has started.')).toBeInTheDocument();
      state = 'done';
      await act(() => vi.advanceTimersByTimeAsync(3100));
      await waitFor(() => expect(screen.queryByText('The scan of Data centre has started.')).not.toBeInTheDocument());
      // Again, and the scan stays queued: the message goes after a few seconds.
      state = 'queued';
      await userEvent.click(screen.getByRole('button', { name: 'Start a scan' }));
      await userEvent.click(within(await screen.findByRole('dialog', { name: 'Start a scan' })).getByRole('button', { name: 'Start scan' }));
      expect(await screen.findByText('The scan of Data centre has started.')).toBeInTheDocument();
      await act(() => vi.advanceTimersByTimeAsync(STARTED_MESSAGE_MS + 100));
      await waitFor(() => expect(screen.queryByText('The scan of Data centre has started.')).not.toBeInTheDocument());
    } finally {
      vi.useRealTimers();
    }
  });
});
