import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import type { SSHKey } from '../api/types';
import {
  aliceKeyLocation,
  errorResponse,
  jobFixture,
  keyLocationFixture,
  managedKeyFixture,
  sessionFor,
  sessionHandlers,
  sshKeyFixture,
} from '../test/fixtures';
import { renderRoute } from '../test/render';
import { server } from '../test/server';

const onDb = keyLocationFixture({
  id: '0192b000-0000-7000-8000-0000000000l5',
  target_id: '0192b000-0000-7000-8000-0000000000a2',
  target_name: 'db-01',
  line_no: 4,
  missing_since: '2026-10-02T08:00:00Z',
});
const key: SSHKey = { ...sshKeyFixture(), locations: [keyLocationFixture(), onDb] };

function onKey(role: 'admin' | 'operator' | 'auditor', k: SSHKey = key) {
  server.use(...sessionHandlers(sessionFor(role)), http.get('/api/v1/ssh-keys/:id', () => HttpResponse.json(k)));
}

// rootRemoval serves a key whose only place is the root account; the server insists on the confirmation first.
function rootRemoval() {
  const rootLoc = keyLocationFixture({ os_user: 'root', file_path: '/root/.ssh/authorized_keys' });
  onKey('admin', { ...key, locations: [rootLoc] });
  const bodies: unknown[] = [];
  server.use(
    http.post('/api/v1/ssh-keys/locations/:id/actions/remove', async ({ request }) => {
      const body = (await request.json()) as { confirm_last_root_key: boolean };
      bodies.push(body);
      return body.confirm_last_root_key
        ? HttpResponse.json({ job_id: 'job-r', status_url: '/api/v1/jobs/job-r' }, { status: 202 })
        : errorResponse(409, 'ALC-KEY-0002', 'sshkey.last_root_key');
    }),
    http.get('/api/v1/jobs/:id', () => HttpResponse.json(jobFixture({ id: 'job-r', type: 'sshkey.remove' }))),
  );
  return bodies;
}

describe('SSHKeyDetailPage', () => {
  beforeEach(() => localStorage.clear());

  it('shows the key and every place it is used', async () => {
    onKey('auditor');
    await renderRoute(`/ssh-keys/${key.id}`);
    expect(await screen.findByRole('heading', { name: 'SSH key', level: 1 })).toBeInTheDocument();
    expect(screen.getByText(key.public_key)).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Where this key is used' })).toBeInTheDocument();
    const table = screen.getByTestId('key-locations');
    const web = within(table).getByRole('link', { name: 'web-01' });
    expect(web).toHaveAttribute('href', `/servers/${keyLocationFixture().target_id}`);
    const dbRow = within(table).getByRole('link', { name: 'db-01' }).closest('tr')!;
    expect(within(dbRow).getByText('No longer found')).toBeInTheDocument();
    expect(within(dbRow).getByText('4')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /^Remove key from/ })).not.toBeInTheDocument();
  });

  it('has the design header, the locations panel and the public identity facts', async () => {
    onKey('operator');
    await renderRoute(`/ssh-keys/${key.id}`);
    const h1 = await screen.findByRole('heading', { name: 'SSH key', level: 1 });
    const header = h1.closest('header')!;
    expect(within(header).getByText(/ssh-ed25519, 256 bits/)).toBeInTheDocument();
    expect(within(header).getByText(/Discovered on a server/)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Back to SSH keys' })).toHaveAttribute('href', '/ssh-keys');
    const locations = screen.getByTestId('key-locations');
    expect(locations).toHaveAccessibleName('Where this key is used');
    expect(screen.getByText('The exact account and file on each server.')).toBeInTheDocument();
    // The first cell of a location row is the server; the user follows.
    const firstRow = within(locations).getAllByRole('row')[1];
    expect(within(firstRow).getAllByRole('cell')[0]).toHaveTextContent('web-01');
    const facts = screen.getByLabelText('Public identity');
    expect(within(facts).getByText(key.fingerprint).tagName).toBe('CODE');
    expect(within(facts).getByText('Not held by Alice')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Public identity', level: 2 })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Copy public key' })).toBeInTheDocument();
    const note = screen.getByText('Review before removing').closest('[role="note"]')!;
    expect(note).toHaveTextContent('Removal applies to one selected location. A shared key can still exist on other servers.');
  });

  it('warns about a weak key and keeps the removal note from an Auditor', async () => {
    onKey('auditor', { ...key, weak: true, key_type: 'ssh-rsa', bits: 1024 });
    await renderRoute(`/ssh-keys/${key.id}`);
    expect(await screen.findByText('Weak algorithm detected')).toBeInTheDocument();
    expect(screen.queryByText('Review before removing')).not.toBeInTheDocument();
  });

  it('shows the error when the key cannot be loaded', async () => {
    server.use(...sessionHandlers(sessionFor('admin')), http.get('/api/v1/ssh-keys/:id', () => errorResponse(404, 'ALC-SYS-0001', 'system.not_found')));
    await renderRoute(`/ssh-keys/${key.id}`);
    expect(await screen.findByRole('alert')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Back to SSH keys' })).toHaveAttribute('href', '/ssh-keys');
  });

  it('refuses to remove Alice’s own key', async () => {
    onKey('admin', { ...sshKeyFixture({ is_platform_key: true, comment: 'alice-platform' }), locations: [aliceKeyLocation] });
    server.use(http.post('/api/v1/ssh-keys/locations/:id/actions/remove', () => errorResponse(409, 'ALC-KEY-0001', 'sshkey.own_key_protected')));
    await renderRoute(`/ssh-keys/${key.id}`);
    await userEvent.click(await screen.findByRole('button', { name: 'Remove key from alice-svc' }));
    const dialog = await screen.findByRole('dialog', { name: 'Remove this key from the server?' });
    await userEvent.click(within(dialog).getByRole('button', { name: 'Remove key' }));
    expect(await within(dialog).findByText('Alice needs this key to connect to this server and will not remove it.')).toBeInTheDocument();
  });

  it('asks an administrator before removing the last key of root', async () => {
    const bodies = rootRemoval();
    await renderRoute(`/ssh-keys/${key.id}`);
    await userEvent.click(await screen.findByRole('button', { name: 'Remove key from root' }));
    const dialog = await screen.findByRole('dialog', { name: 'Remove this key from the server?' });
    await userEvent.click(within(dialog).getByRole('button', { name: 'Remove key' }));
    const confirm = await within(dialog).findByLabelText('This is the last key of the root account. Remove it anyway.');
    expect(within(dialog).getByRole('button', { name: 'Remove key' })).toBeDisabled();
    await userEvent.click(confirm);
    await userEvent.click(within(dialog).getByRole('button', { name: 'Remove key' }));
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Remove this key from the server?' })).not.toBeInTheDocument());
    expect(bodies).toEqual([{ confirm_last_root_key: false }, { confirm_last_root_key: true }]);
  });

  it('finishes the removal job under React StrictMode', async () => {
    const bodies = rootRemoval();
    await renderRoute(`/ssh-keys/${key.id}`, { strict: true });
    await userEvent.click(await screen.findByRole('button', { name: 'Remove key from root' }));
    const dialog = await screen.findByRole('dialog', { name: 'Remove this key from the server?' });
    await userEvent.click(within(dialog).getByRole('button', { name: 'Remove key' }));
    await userEvent.click(await within(dialog).findByLabelText('This is the last key of the root account. Remove it anyway.'));
    await userEvent.click(within(dialog).getByRole('button', { name: 'Remove key' }));
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Remove this key from the server?' })).not.toBeInTheDocument());
    expect(bodies).toHaveLength(2);
  });

  describe('a key generated by Alice', () => {
    const managed = (o = {}, k: Partial<SSHKey> = {}): SSHKey => ({ ...key, managed: true, managed_key: managedKeyFixture(o), ...k }) as SSHKey;

    it('shows the badge, the comment as text and the download count, with both buttons for an Administrator', async () => {
      onKey('admin', managed({ download_count: 2, last_downloaded_at: '2026-10-06T08:00:00Z', comment: '<b>evil</b>' }));
      await renderRoute(`/ssh-keys/${key.id}`);
      expect(await screen.findByText('Generated by Alice')).toBeInTheDocument();
      expect(screen.getByText('Downloaded 2 times')).toBeInTheDocument();
      expect(screen.getByText('<b>evil</b>')).toHaveAttribute('translate', 'no');
      expect(screen.getByRole('heading', { name: 'Managed by Alice', level: 2 })).toBeInTheDocument();
      expect(screen.getByText('Generated by Alice').closest('.mantine-Badge-root')!.getAttribute('style')).toContain('var(--alice-success-soft)'); // teal = success
      expect(document.querySelector('b')).toBeNull();
      expect(screen.getByRole('button', { name: 'Deploy to a server' })).toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Download private key' })).toBeInTheDocument();
      expect(screen.queryByText('Retired')).not.toBeInTheDocument();
      // Both are the page's actions (design header), Deploy first: the keyboard goes from Deploy to Download with Tab.
      const header = screen.getByRole('heading', { name: 'SSH key', level: 1 }).closest('header')!;
      expect(within(header).getAllByRole('button').map((b) => b.textContent)).toEqual(['Deploy to a server', 'Download private key']);
      expect(within(header).getByText(/Managed by Alice/)).toBeInTheDocument();
      expect(within(screen.getByLabelText('Public identity')).getByText('Held by Alice. It is never displayed on this page.')).toBeInTheDocument();
    });

    it('says "Downloaded 1 time" in the singular', async () => {
      onKey('admin', managed({ download_count: 1 }));
      await renderRoute(`/ssh-keys/${key.id}`);
      expect(await screen.findByText('Downloaded 1 time')).toBeInTheDocument();
    });

    it('gives an Operator Deploy but not the download', async () => {
      onKey('operator', managed());
      await renderRoute(`/ssh-keys/${key.id}`);
      expect(await screen.findByRole('button', { name: 'Deploy to a server' })).toBeInTheDocument();
      expect(screen.queryByRole('button', { name: 'Download private key' })).not.toBeInTheDocument();
    });

    it('gives an Auditor neither button', async () => {
      onKey('auditor', managed());
      await renderRoute(`/ssh-keys/${key.id}`);
      expect(await screen.findByText('Generated by Alice')).toBeInTheDocument();
      expect(screen.queryByRole('button', { name: 'Deploy to a server' })).not.toBeInTheDocument();
      expect(screen.queryByRole('button', { name: 'Download private key' })).not.toBeInTheDocument();
    });

    it('shows a retired key as retired with no Deploy', async () => {
      onKey('admin', managed({ retired_at: '2026-10-07T08:00:00Z', rotated_from: null }));
      await renderRoute(`/ssh-keys/${key.id}`);
      expect(await screen.findByText('Retired')).toBeInTheDocument();
      expect(screen.queryByRole('button', { name: 'Deploy to a server' })).not.toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Download private key' })).toBeInTheDocument();
    });

    it('shows a destroyed key with no download', async () => {
      onKey('admin', managed({ retired_at: '2026-10-07T08:00:00Z', destroyed_at: '2026-11-07T08:00:00Z' }));
      await renderRoute(`/ssh-keys/${key.id}`);
      expect(await screen.findByText('Private key destroyed')).toBeInTheDocument();
      expect(screen.queryByRole('button', { name: 'Download private key' })).not.toBeInTheDocument();
      expect(screen.queryByRole('button', { name: 'Deploy to a server' })).not.toBeInTheDocument();
    });

    it('links to the key it replaces', async () => {
      onKey('admin', managed({ rotated_from: 'old-key-1' }));
      await renderRoute(`/ssh-keys/${key.id}`);
      expect(await screen.findByRole('link', { name: 'Replaces an earlier key' })).toHaveAttribute('href', '/ssh-keys/old-key-1');
    });

    it('shows the rotation panel on a live key and not on a retired one', async () => {
      server.use(http.get('/api/v1/rotation/runs', () => HttpResponse.json({ items: [], next_cursor: null })));
      onKey('operator', managed());
      const view = await renderRoute(`/ssh-keys/${key.id}`);
      expect(await screen.findByText('Automatic rotation')).toBeInTheDocument();
      expect(screen.getByText('No rotation policy. Alice changes this key only when you ask.')).toBeInTheDocument();
      expect(screen.queryByRole('button', { name: 'Create rotation policy' })).not.toBeInTheDocument();
      view.unmount();
      onKey('admin', managed({ retired_at: '2026-10-07T08:00:00Z' }));
      await renderRoute(`/ssh-keys/${key.id}`);
      await screen.findByText('Retired');
      expect(screen.queryByText('Automatic rotation')).not.toBeInTheDocument();
    });

    it('opens the deploy and download dialogs', async () => {
      onKey('admin', managed());
      server.use(
        http.get('/api/v1/targets', () => HttpResponse.json({ items: [], next_cursor: null })),
      );
      await renderRoute(`/ssh-keys/${key.id}`);
      await userEvent.click(await screen.findByRole('button', { name: 'Deploy to a server' }));
      expect(await screen.findByRole('dialog', { name: 'Deploy this key' })).toBeInTheDocument();
      await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Cancel' }));
      await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Deploy this key' })).not.toBeInTheDocument());
      await userEvent.click(screen.getByRole('button', { name: 'Download private key' }));
      expect(await screen.findByRole('dialog', { name: 'Download the private key' })).toBeInTheDocument();
    });
  });

  it('says that the platform key cannot be downloaded and offers no buttons', async () => {
    onKey('admin', { ...key, is_platform_key: true, managed: false, managed_key: null } as SSHKey);
    await renderRoute(`/ssh-keys/${key.id}`);
    expect(await screen.findByText("This is Alice's own connection key. It cannot be downloaded.")).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Download private key' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Deploy to a server' })).not.toBeInTheDocument();
    // Alice holds the private half of its own connection key, although the key is never "managed".
    const facts = screen.getByLabelText('Public identity');
    expect(within(facts).getByText('Held by Alice for its own connections. It cannot be downloaded.')).toBeInTheDocument();
    expect(within(facts).queryByText('Not held by Alice')).not.toBeInTheDocument();
  });

  it('shows a key found on a server without the managed section', async () => {
    onKey('admin');
    await renderRoute(`/ssh-keys/${key.id}`);
    await screen.findByRole('heading', { name: 'SSH key', level: 1 });
    expect(screen.queryByText('Generated by Alice')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Download private key' })).not.toBeInTheDocument();
  });
});
