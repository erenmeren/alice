import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import type { SSHKey } from '../api/types';
import {
  aliceKeyLocation,
  errorResponse,
  jobFixture,
  keyLocationFixture,
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
});
