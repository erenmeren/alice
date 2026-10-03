import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { errorResponse, sessionFor, sessionHandlers, sshKeyFixture, targetFixture, targetWith } from '../test/fixtures';
import { renderRoute } from '../test/render';
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
    await userEvent.type(screen.getByLabelText(/^Search/), 'İzmir');
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
    await renderRoute('/ssh-keys');
    expect(await screen.findByText('No SSH keys match these filters.')).toBeInTheDocument();
    expect(screen.queryByTestId('ssh-keys-table')).not.toBeInTheDocument();
  });

  it('shows the error instead of an empty list when loading fails', async () => {
    keysServer();
    server.use(http.get('/api/v1/ssh-keys', () => errorResponse(500, 'ALC-SYS-0001', 'internal')));
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
});
