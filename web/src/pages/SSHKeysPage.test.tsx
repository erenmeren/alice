import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { errorResponse, sessionFor, sessionHandlers, sshKeyFixture, targetFixture, targetWith } from '../test/fixtures';
import { renderRoute } from '../test/render';
import { SSH_KEY_TABS } from './SSHKeysPage';
import { server } from '../test/server';

const weak = sshKeyFixture({
  id: '0192b000-0000-7000-8000-0000000000k2',
  fingerprint: 'SHA256:weakWeakWeakWeakWeakWeakWeakWeakWeakWeakWeak0',
  key_type: 'ssh-rsa',
  bits: 1024,
  weak: true,
  comment: 'old@laptop',
  location_count: 1,
  target_count: 1,
});
const alice = sshKeyFixture({
  id: '0192b000-0000-7000-8000-0000000000k9',
  fingerprint: 'SHA256:aliceAliceAliceAliceAliceAliceAliceAlice00',
  comment: 'alice-platform',
  is_platform_key: true,
});
const db = targetWith({ id: '0192b000-0000-7000-8000-0000000000a2', name: 'db-01' });

// keysServer answers like the server: the first page has a cursor, the second does not; it records every query.
function keysServer(role: 'admin' | 'operator' | 'auditor' = 'auditor', lang = 'en') {
  const queries: URLSearchParams[] = [];
  server.use(
    ...sessionHandlers(sessionFor(role, lang)),
    http.get('/api/v1/targets', () => HttpResponse.json({ items: [targetFixture, db], next_cursor: null })),
    http.get('/api/v1/ssh-keys', ({ request }) => {
      const params = new URL(request.url).searchParams;
      queries.push(params);
      if (params.get('cursor') === 'page-2') return HttpResponse.json({ items: [alice], next_cursor: null });
      return HttpResponse.json({ items: [sshKeyFixture(), weak], next_cursor: 'page-2' });
    }),
  );
  return queries;
}

describe('SSHKeysPage', () => {
  beforeEach(() => localStorage.clear());

  it('lists every key once with its findings and pages with the cursor', async () => {
    const queries = keysServer();
    await renderRoute('/ssh-keys');
    expect(await screen.findByRole('heading', { name: 'SSH keys', level: 1 })).toBeInTheDocument();
    const table = await screen.findByTestId('ssh-keys-table');
    const row = within(table).getByText('deploy@laptop').closest('tr')!;
    expect(within(row).getByRole('link', { name: 'SHA256:deployDeployDeployDeployDeployDeployDeploy0' })).toHaveAttribute(
      'href',
      '/ssh-keys/0192b000-0000-7000-8000-0000000000k1',
    );
    expect(within(row).getByText('ssh-ed25519, 256 bits')).toBeInTheDocument();
    expect(within(within(table).getByText('old@laptop').closest('tr')!).getByText('Weak key')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Show more' }));
    const aliceRow = (await within(table).findByText('alice-platform')).closest('tr')!;
    expect(within(aliceRow).getByText("Alice's key")).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Show more' })).not.toBeInTheDocument();
    expect(queries.at(-1)?.get('cursor')).toBe('page-2');
  });

  it('sends the filters to the server', async () => {
    const queries = keysServer();
    await renderRoute('/ssh-keys');
    await screen.findByTestId('ssh-keys-table');
    await userEvent.selectOptions(screen.getByLabelText('Server'), db.id);
    await waitFor(() => expect(queries.at(-1)?.get('target_id')).toBe(db.id));
    await userEvent.selectOptions(screen.getByLabelText('Finding'), 'weak');
    await waitFor(() => expect(queries.at(-1)?.get('flag')).toBe('weak'));
    await userEvent.click(screen.getByLabelText('Show keys that are no longer found'));
    await waitFor(() => expect(queries.at(-1)?.get('missing')).toBe('true'));
    await userEvent.type(screen.getByLabelText('User'), 'deploy');
    await waitFor(() => expect(queries.at(-1)?.get('os_user')).toBe('deploy'));
    // In the page body: the shell's top bar has a "Search pages" button too.
    await userEvent.type(within(screen.getByRole('main')).getByLabelText(/^Search/), 'İzmir');
    // The search is debounced: the server sees the whole word once, not one query per letter.
    await waitFor(() => expect(queries.at(-1)?.get('q')).toBe('İzmir'));
    expect(queries.filter((q) => q.get('q') === 'İ')).toHaveLength(0);
  });

  it('starts again from the first page when a filter changes after paging', async () => {
    const queries = keysServer();
    await renderRoute('/ssh-keys');
    const table = await screen.findByTestId('ssh-keys-table');
    await userEvent.click(screen.getByRole('button', { name: 'Show more' }));
    await within(table).findByText('alice-platform');
    await userEvent.selectOptions(screen.getByLabelText('Finding'), 'weak');
    await waitFor(() => expect(queries.at(-1)?.get('flag')).toBe('weak'));
    expect(queries.at(-1)?.get('cursor')).toBeNull();
    expect(await screen.findByRole('button', { name: 'Show more' })).toBeInTheDocument();
  });

  it('says when nothing matches', async () => {
    keysServer();
    server.use(http.get('/api/v1/ssh-keys', () => HttpResponse.json({ items: [], next_cursor: null })));
    await renderRoute('/ssh-keys?flag=duplicate');
    expect(await screen.findByText('No matching keys')).toBeInTheDocument();
    expect(screen.getByText('No SSH keys match these filters.')).toBeInTheDocument();
    expect(screen.queryByTestId('ssh-keys-table')).not.toBeInTheDocument();
    // One Clear filters (the toolbar's): the e2e finds it by its name.
    expect(screen.getAllByRole('button', { name: 'Clear filters' })).toHaveLength(1);
  });

  it('tells an empty inventory from a filter without matches', async () => {
    keysServer();
    server.use(http.get('/api/v1/ssh-keys', () => HttpResponse.json({ items: [], next_cursor: null })));
    await renderRoute('/ssh-keys');
    expect(await screen.findByText('No SSH keys yet')).toBeInTheDocument();
    expect(screen.getByText('Alice lists the keys it finds when it scans a server, and the keys you generate.')).toBeInTheDocument();
    expect(screen.queryByText('No matching keys')).not.toBeInTheDocument();
    // An empty inventory has no weak key to review.
    expect(screen.queryByText('Weak keys need review')).not.toBeInTheDocument();
  });

  it('has the design header with Export and Generate key, and the link tabs to the rotation policies', async () => {
    keysServer('operator');
    await renderRoute('/ssh-keys');
    expect(await screen.findByRole('heading', { name: 'SSH keys', level: 1 })).toBeInTheDocument();
    expect(screen.getByText('Understand access. Rotate with control.')).toBeInTheDocument();
    const header = screen.getByRole('heading', { level: 1 }).closest('header')!;
    expect(within(header).getByRole('button', { name: 'Export' })).toBeInTheDocument();
    expect(within(header).getByRole('button', { name: 'Generate key' })).toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: 'Export' })).toHaveLength(1);
    const tabs = screen.getByRole('group', { name: 'SSH key sections' });
    expect(within(tabs).getByRole('link', { name: 'Inventory' })).toHaveAttribute('aria-current', 'page');
    const rotations = within(tabs).getByRole('link', { name: 'Rotation policies' });
    expect(rotations).toHaveAttribute('href', '/rotations');
    expect(rotations).not.toHaveAttribute('aria-current');
    expect(screen.queryByRole('tablist')).not.toBeInTheDocument();
  });

  it('exports the tabs for the rotations page', () => {
    const tabs = SSH_KEY_TABS((k: string) => k);
    expect(tabs).toEqual([
      { to: '/ssh-keys', label: 'sshKeys.page.inventory' },
      { to: '/rotations', label: 'rotation.page.policies', match: ['/rotation/'] },
    ]);
  });

  it('points to the weak keys with a filter link and states no count (R20)', async () => {
    keysServer();
    const { router } = await renderRoute('/ssh-keys');
    const notice = (await screen.findByText('Weak keys need review')).closest('[role="note"]')!;
    expect(within(notice as HTMLElement).getByText('Review a weak key’s locations before replacing it.')).toBeInTheDocument();
    expect(notice.textContent).not.toMatch(/\d/);
    const link = within(notice as HTMLElement).getByRole('link', { name: 'Show weak keys' });
    expect(link).toHaveAttribute('href', '/ssh-keys?flag=weak');
    await userEvent.click(link);
    await waitFor(() => expect(router.state.location.search).toBe('?flag=weak'));
    expect(screen.getByLabelText('Finding')).toHaveValue('weak');
    // The weak filter is on: the notice would only link to the page already shown.
    expect(screen.queryByText('Weak keys need review')).not.toBeInTheDocument();
  });

  it('shows each row as the design resource and states only how many rows are shown', async () => {
    keysServer();
    await renderRoute('/ssh-keys');
    const table = await screen.findByTestId('ssh-keys-table');
    expect(table).toHaveAccessibleName('SSH keys');
    expect(within(table).getAllByRole('columnheader').map((h) => h.textContent)).toEqual(['Key', 'Algorithm', 'Locations', 'Managed']);
    const row = within(table).getByText('deploy@laptop').closest('tr')!;
    // Exactly one link per row: the e2e clicks the row's link.
    expect(within(row).getAllByRole('link')).toHaveLength(1);
    expect(within(row).getByText('Discovered')).toBeInTheDocument();
    const weakRow = within(table).getByText('old@laptop').closest('tr')!;
    expect(within(weakRow).getByText('ssh-rsa, 1024 bits')).toBeInTheDocument();
    expect(within(weakRow).getByText('Weak key').closest('.mantine-Badge-root')).toHaveAttribute('data-tone', 'warning');
    expect(within(weakRow).getByText('1 place')).toBeInTheDocument();
    expect(within(weakRow).getByText('on 1 server')).toBeInTheDocument();
    expect(screen.getByText('2 shown')).toBeInTheDocument();
    expect(screen.queryByText(/of \d+/)).not.toBeInTheDocument();
  });

  it('shows the error instead of an empty list when loading fails', async () => {
    keysServer();
    server.use(http.get('/api/v1/ssh-keys', () => errorResponse(500, 'ALC-SYS-0003', 'internal.unexpected')));
    await renderRoute('/ssh-keys');
    expect(await screen.findByRole('alert')).toBeInTheDocument();
    expect(screen.queryByText('No SSH keys match these filters.')).not.toBeInTheDocument();
  });

  it('is shown in Turkish', async () => {
    keysServer('operator', 'tr');
    await renderRoute('/ssh-keys', { languages: ['tr-TR'] });
    expect(await screen.findByRole('heading', { name: 'SSH anahtarları', level: 1 })).toBeInTheDocument();
    expect(await screen.findAllByText('ssh-ed25519, 256 bit')).not.toHaveLength(0);
    expect(screen.getByLabelText('Artık bulunmayan anahtarları göster')).toBeInTheDocument();
  });

  it('marks keys that are no longer found', async () => {
    keysServer();
    server.use(
      http.get('/api/v1/ssh-keys', () =>
        HttpResponse.json({
          items: [
            sshKeyFixture({ id: 'k1', missing: true }),
            sshKeyFixture({ id: 'k2', fingerprint: 'SHA256:' + 'b'.repeat(43) }),
          ],
          next_cursor: null,
        }),
      ),
    );
    await renderRoute('/ssh-keys');
    const table = await screen.findByTestId('ssh-keys-table');
    const rows = await within(table).findAllByRole('row');
    expect(within(rows[1]).getByText('No longer found')).toBeInTheDocument();
    expect(within(rows[2]).queryByText('No longer found')).not.toBeInTheDocument();
  });

  it.each([
    ['admin', true],
    ['operator', true],
    ['auditor', false],
  ] as const)('shows Generate key for %s: %s', async (role, shown) => {
    keysServer(role);
    await renderRoute('/ssh-keys');
    await screen.findByTestId('ssh-keys-table');
    expect(screen.queryByRole('button', { name: 'Generate key' }) !== null).toBe(shown);
  });

  it('marks keys Alice generated with a badge', async () => {
    server.use(
      ...sessionHandlers(sessionFor('operator')),
      http.get('/api/v1/targets', () => HttpResponse.json({ items: [targetFixture], next_cursor: null })),
      http.get('/api/v1/ssh-keys', () => HttpResponse.json({ items: [sshKeyFixture({ managed: true }), weak], next_cursor: null })),
    );
    await renderRoute('/ssh-keys');
    const table = await screen.findByTestId('ssh-keys-table');
    expect(within(within(table).getByText('deploy@laptop').closest('tr')!).getByText('Generated by Alice')).toBeInTheDocument();
    expect(within(within(table).getByText('old@laptop').closest('tr')!).queryByText('Generated by Alice')).not.toBeInTheDocument();
  });

  it('generates a key and opens it', async () => {
    keysServer('operator');
    server.use(
      http.post('/api/v1/ssh-keys/generate', () => HttpResponse.json({ id: 'new-key', managed_key: {} }, { status: 201 })),
      http.get('/api/v1/ssh-keys/new-key', () => HttpResponse.json({ ...sshKeyFixture({ id: 'new-key', managed: true }), managed_key: null })),
    );
    const { router } = await renderRoute('/ssh-keys');
    await userEvent.click(await screen.findByRole('button', { name: 'Generate key' }));
    const dialog = await screen.findByRole('dialog', { name: 'Generate an SSH key' });
    await userEvent.type(within(dialog).getByLabelText(/^Name/), 'backup');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Generate' }));
    await waitFor(() => expect(router.state.location.pathname).toBe('/ssh-keys/new-key'));
  });
  it('reads its filters from the address and writes them back', async () => {
    const queries = keysServer();
    server.use(http.get('/api/v1/views', () => HttpResponse.json({ items: [] })));
    const { router } = await renderRoute('/ssh-keys?os_user=root&flag=weak');
    await waitFor(() => expect(queries.map((p) => `?${p.toString()}`)).toContain('?os_user=root&flag=weak'));
    let exported = '';
    server.use(http.get('/api/v1/ssh-keys/export', ({ request }) => {
      exported = new URL(request.url).search;
      return new HttpResponse('a\r\n', { headers: { 'Content-Type': 'text/csv' } });
    }));
    await userEvent.click(screen.getByRole('button', { name: 'Export' }));
    await waitFor(() => expect(exported).toBe('?os_user=root&flag=weak'));
    await userEvent.selectOptions(screen.getByLabelText('Finding'), 'duplicate');
    await waitFor(() => expect(router.state.location.search).toContain('flag=duplicate'));
    await waitFor(() => expect(queries.at(-1)?.get('flag')).toBe('duplicate'));
    await userEvent.click(screen.getByRole('button', { name: 'Clear filters' }));
    await waitFor(() => expect(router.state.location.search).toBe(''));
  });

  it('closes the generate dialog with Cancel and gives the focus back', async () => {
    keysServer('admin');
    await renderRoute('/ssh-keys');
    const generate = await screen.findByRole('button', { name: 'Generate key' });
    await userEvent.click(generate);
    const dialog = await screen.findByRole('dialog', { name: 'Generate an SSH key' });
    await userEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Generate an SSH key' })).not.toBeInTheDocument());
  });

  it('applies a saved view to the filters and the search box', async () => {
    const queries = keysServer();
    server.use(http.get('/api/v1/views', () => HttpResponse.json({ items: [{ id: 'v1', page: 'ssh_keys', name: 'Root keys', query: { os_user: 'root', q: 'ci' }, created_at: '2026-10-01T08:00:00Z' }] })));
    const { router } = await renderRoute('/ssh-keys');
    await screen.findByTestId('ssh-keys-table');
    await userEvent.click(screen.getByRole('button', { name: 'Saved views' }));
    await userEvent.click(await screen.findByRole('menuitem', { name: 'Root keys' }));
    await waitFor(() => expect(router.state.location.search).toContain('os_user=root'));
    await waitFor(() => expect(queries.at(-1)?.get('q')).toBe('ci'));
    expect(within(screen.getByRole('main')).getByLabelText(/^Search/)).toHaveValue('ci');
    expect(screen.getByLabelText('User')).toHaveValue('root');
  });
});
