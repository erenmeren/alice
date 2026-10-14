import { act, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { discoveryScanFixture, discoveryScopeFixture, discoverySettingsFixture, sessionFor } from '../test/fixtures';
import { discoveryWorld, requests } from '../test/discovery';
import { expectNoRawKeys } from '../test/i18nAssert';
import { renderRoute } from '../test/render';

describe('Network discovery page', () => {
  it('explains an installation without scopes and who can do what, with one Add a scope button for an Administrator', async () => {
    discoveryWorld({ scopes: [], scans: [] });
    await renderRoute('/discovery');
    expect(await screen.findByText('Nothing is scanned until you add a scope')).toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 1, name: 'Network discovery' })).toBeInTheDocument();
    expect(screen.getByText(/never changes the scanned servers/)).toBeInTheDocument();
    expect(screen.getByText(/Administrators define scopes and the discovery settings/)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Network discovery' })).toHaveAttribute('aria-current', 'page');
    expect(screen.getAllByRole('button', { name: 'Add a scope' })).toHaveLength(1);
    expectNoRawKeys();
    // The empty state's button opens the scope dialog on the Scopes tab.
    await userEvent.click(screen.getByRole('button', { name: 'Add a scope' }));
    expect(await screen.findByRole('dialog', { name: 'Add a scan scope' })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'Scopes' })).toHaveAttribute('aria-selected', 'true');
  });

  it.each(['operator', 'auditor'] as const)('gives an %s no way to define scopes in the empty state', async (role) => {
    discoveryWorld({ session: sessionFor(role), scopes: [], scans: [] });
    await renderRoute('/discovery');
    expect(await screen.findByText('Nothing is scanned until you add a scope')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Add a scope' })).not.toBeInTheDocument();
  });

  it('opens the tab the address names, and the Results for an unknown one', async () => {
    discoveryWorld();
    const { router } = await renderRoute('/discovery?tab=scans');
    expect(await screen.findByRole('table', { name: 'Scans' })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'Scans' })).toHaveAttribute('aria-selected', 'true');
    await userEvent.click(screen.getByRole('tab', { name: 'Results' }));
    expect(router.state.location.search).toBe('');
    await act(() => router.navigate('/discovery?tab=nonsense'));
    expect(screen.getByRole('tab', { name: 'Results' })).toHaveAttribute('aria-selected', 'true');
  });

  it('lets an Auditor read every tab with no control that changes anything', async () => {
    discoveryWorld({ session: sessionFor('auditor'), scans: [discoveryScanFixture({ state: 'running', finished_at: null })] });
    const { router } = await renderRoute('/discovery?tab=scopes');
    expect(await screen.findByRole('table', { name: 'Scan scopes' })).toBeInTheDocument();
    expect(screen.getAllByText(/You can look, not change/).length).toBeGreaterThan(0);
    for (const name of ['Add a scope', 'Change settings', /^Scan now/, /^Edit/, /^Delete/]) expect(screen.queryByRole('button', { name })).not.toBeInTheDocument();
    expect(screen.queryByRole('switch')).not.toBeInTheDocument();
    expect(screen.getAllByText('On').length).toBeGreaterThan(0);
    await act(() => router.navigate('/discovery?tab=scans'));
    expect(await screen.findByRole('table', { name: 'Scans' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Start a scan' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /^Cancel scan/ })).not.toBeInTheDocument();
    expectNoRawKeys();
  });

  it('lets an Operator start and cancel scans and says who defines scopes', async () => {
    discoveryWorld({ session: sessionFor('operator'), scans: [discoveryScanFixture({ state: 'running', finished_at: null })] });
    const { router } = await renderRoute('/discovery?tab=scopes');
    expect(await screen.findByRole('table', { name: 'Scan scopes' })).toBeInTheDocument();
    expect(screen.getByText('Only an administrator defines scopes and the discovery settings. You can start and cancel scans.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Scan now: Data centre' })).toBeEnabled();
    for (const name of ['Add a scope', 'Change settings', /^Edit/, /^Delete/]) expect(screen.queryByRole('button', { name })).not.toBeInTheDocument();
    await act(() => router.navigate('/discovery?tab=scans'));
    expect(await screen.findByRole('button', { name: 'Cancel scan: Data centre' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Start a scan' })).toBeInTheDocument();
  });

  it('says the license stops scans and disables starting them, with the reason as text', async () => {
    discoveryWorld({ locked: true });
    await renderRoute('/discovery?tab=scopes');
    expect(await screen.findByText('The license does not allow scans now')).toBeInTheDocument();
    const scan = await screen.findByRole('button', { name: 'Scan now: Data centre' });
    await waitFor(() => expect(scan).toBeDisabled());
    expect(scan).toHaveAccessibleDescription('The license does not allow scans now.');
  });

  it('polls the scopes while a scan runs, then reads the results and the scans again when it ends', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      let running = true;
      const seen = discoveryWorld({
        scopes: () => [discoveryScopeFixture({ active_scan_id: running ? 'n1' : null })],
        scans: () => [discoveryScanFixture({ id: 'n1', state: running ? 'running' : 'done', finished_at: running ? null : '2026-10-13T09:05:00Z' })],
      });
      await renderRoute('/discovery');
      await screen.findByRole('table', { name: 'Certificates found on the network' });
      const scopeReads = () => requests(seen, 'GET', '/api/v1/discovery/scopes').length;
      const certReads = () => requests(seen, 'GET', '/api/v1/discovery/certificates').length;
      const before = scopeReads();
      const certsBefore = certReads();
      await act(() => vi.advanceTimersByTimeAsync(3100));
      await waitFor(() => expect(scopeReads()).toBeGreaterThan(before));
      expect(certReads()).toBe(certsBefore);
      running = false;
      await act(() => vi.advanceTimersByTimeAsync(3100));
      await waitFor(() => expect(certReads()).toBeGreaterThan(certsBefore));
      // Nothing runs any more: the polling stops.
      const settled = scopeReads();
      await act(() => vi.advanceTimersByTimeAsync(10_000));
      expect(scopeReads()).toBe(settled);
    } finally {
      vi.useRealTimers();
    }
  });

  it('shows the settings banner on the Scopes tab when no allowed network is set', async () => {
    discoveryWorld({ settings: discoverySettingsFixture({ allowed_networks: [], scanning_enabled: false }) });
    await renderRoute('/discovery?tab=scopes');
    const banner = await screen.findByTestId('discovery-no-networks');
    expect(within(banner).getByText('Nothing is scanned until you list the networks Alice may scan')).toBeInTheDocument();
    await userEvent.click(within(banner).getByRole('button', { name: 'Set the allowed networks' }));
    expect(await screen.findByRole('dialog', { name: 'Discovery settings' })).toBeInTheDocument();
  });

  it('renders in Turkish with no untranslated keys', async () => {
    discoveryWorld({ session: sessionFor('admin', 'tr') });
    await renderRoute('/discovery?tab=scopes', { languages: ['tr'] });
    expect(await screen.findByRole('table', { name: 'Tarama kapsamları' })).toBeInTheDocument();
    expectNoRawKeys();
  });
});
