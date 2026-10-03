import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import commonEn from '@locales/common/en.json';
import {
  errorResponse,
  hostKeyFixture,
  jobFixture,
  keyLocationFixture,
  platformKeyFixture,
  sessionFor,
  sessionHandlers,
  targetFixture,
  targetWith,
} from '../test/fixtures';
import { renderRoute } from '../test/render';
import { server } from '../test/server';

const pending = targetWith({ id: '0192b000-0000-7000-8000-0000000000a2', name: 'db-01', host: 'db-01.example.com', status: 'pending_host_key', last_discovery_at: null });

function withTargets(role: 'admin' | 'operator' | 'auditor', items = [targetFixture], lang = 'en') {
  server.use(...sessionHandlers(sessionFor(role, lang)), http.get('/api/v1/targets', () => HttpResponse.json({ items, next_cursor: null })));
}

describe('TargetsPage', () => {
  beforeEach(() => localStorage.clear());

  it('lists servers with their status and shows the preparation commands to administrators', async () => {
    withTargets('admin', [targetFixture, targetWith({ ...pending, last_error: { code: 'ALC-SSH-0001', reason: 'ssh.unreachable' } })]);
    await renderRoute('/servers');
    expect(await screen.findByRole('heading', { name: 'Servers', level: 1 })).toBeInTheDocument();
    const table = await screen.findByTestId('targets-table');
    const row = within(table).getByText('web-01').closest('tr')!;
    expect(within(row).getByText('web-01.example.com:22')).toBeInTheDocument();
    expect(within(row).getByText('Connected')).toBeInTheDocument();
    const pendingRow = within(table).getByText('db-01').closest('tr')!;
    expect(within(pendingRow).getByText('Waiting for fingerprint confirmation')).toBeInTheDocument();
    expect(within(pendingRow).getByText(commonEn.errors.ssh.unreachable.title)).toBeInTheDocument();
    expect(within(row).getByRole('link', { name: 'web-01' })).toHaveAttribute('href', `/servers/${targetFixture.id}`);

    expect(screen.getByRole('button', { name: 'Add server' })).toBeInTheDocument();
    expect(await screen.findByRole('heading', { name: 'Prepare a server for Alice' })).toBeInTheDocument();
    expect(screen.getByTestId('platform-public-key')).toHaveTextContent(platformKeyFixture.public_key);
    expect(screen.getByTestId('platform-fingerprint')).toHaveTextContent(platformKeyFixture.fingerprint);
    expect(screen.getByTestId('setup-script')).toHaveTextContent('# linux setup script');
    await userEvent.selectOptions(screen.getByLabelText('Server type'), 'nginx');
    expect(screen.getByTestId('setup-script')).toHaveTextContent('# nginx setup script');
  });

  it('shows operators the list without the administrator tools', async () => {
    let platformAsked = false;
    withTargets('operator');
    server.use(
      http.get('/api/v1/ssh-keys/platform-key', () => {
        platformAsked = true;
        return errorResponse(403, 'ALC-AUTH-0002', 'auth.forbidden');
      }),
    );
    await renderRoute('/servers');
    expect(await screen.findByText('web-01')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Add server' })).not.toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Prepare a server for Alice' })).not.toBeInTheDocument();
    expect(platformAsked).toBe(false);
  });

  it('says that there are no servers yet', async () => {
    withTargets('admin', []);
    await renderRoute('/servers');
    expect(await screen.findByText('No servers yet. Prepare a server with the command below, then add it.')).toBeInTheDocument();
  });

  it('adds a server, shows the fingerprint and pins it after the administrator confirms', async () => {
    withTargets('admin', []);
    const observed = hostKeyFixture({ id: 'hk-observed', status: 'observed', fingerprint: 'SHA256:newServerNewServerNewServerNewServerNew0', confirmed_at: null, confirmed_by_name: '' });
    const bodies: Record<string, unknown> = {};
    server.use(
      http.post('/api/v1/targets', async ({ request }) => {
        bodies.create = await request.json();
        return HttpResponse.json({ target: pending, job_id: 'job-1', status_url: '/api/v1/jobs/job-1' }, { status: 201 });
      }),
      http.get('/api/v1/jobs/:id', ({ params }) =>
        HttpResponse.json(
          params.id === 'job-1'
            ? jobFixture({ id: 'job-1', status: 'failed', error: { code: 'ALC-TGT-0002', reason: 'target.host_key_unconfirmed', params: { fingerprint: observed.fingerprint } } })
            : jobFixture({ id: 'job-2', status: 'succeeded' }),
        ),
      ),
      http.get('/api/v1/targets/:id/host-keys', () => HttpResponse.json({ items: [observed] })),
      http.post('/api/v1/targets/:id/host-keys/:keyId/actions/confirm', async ({ request, params }) => {
        bodies.confirm = { body: await request.json(), keyId: params.keyId };
        return HttpResponse.json({ job_id: 'job-2', status_url: '/api/v1/jobs/job-2' }, { status: 202 });
      }),
      http.get('/api/v1/targets/:id', () => HttpResponse.json(targetWith({ ...pending, status: 'ok' }))),
      http.get('/api/v1/targets/:id/ssh-keys', () => HttpResponse.json({ items: [keyLocationFixture({ target_id: pending.id })] })),
    );
    const { router } = await renderRoute('/servers');
    await userEvent.click(await screen.findByRole('button', { name: 'Add server' }));
    const dialog = await screen.findByRole('dialog', { name: 'Add server' });
    await userEvent.type(within(dialog).getByLabelText(/^Name/), 'db-01');
    await userEvent.type(within(dialog).getByLabelText(/^Address/), ' db-01.example.com ');
    expect(within(dialog).getByLabelText(/^User name on the server/)).toHaveValue('alice-svc');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Connect' }));

    const confirm = await screen.findByRole('dialog', { name: 'Is this your server?' });
    expect(within(confirm).getByText(/Alice received this fingerprint from db-01\.example\.com\./)).toBeInTheDocument();
    expect(within(confirm).getByTestId('host-key-fingerprint')).toHaveTextContent(observed.fingerprint);
    expect(within(confirm).getByTestId('host-key-command')).toHaveTextContent('ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub');
    await userEvent.click(within(confirm).getByRole('button', { name: 'Yes, this is my server' }));

    await waitFor(() => expect(router.state.location.pathname).toBe(`/servers/${pending.id}`));
    expect(await screen.findByText('Server added. Alice is reading its SSH keys.')).toBeInTheDocument();
    expect(bodies.create).toEqual({ name: 'db-01', type: 'linux', host: 'db-01.example.com', port: 22, username: 'alice-svc' });
    expect(bodies.confirm).toEqual({ body: { fingerprint: observed.fingerprint }, keyId: 'hk-observed' });
  });

  it('shows the license limit in plain words and keeps the form open', async () => {
    withTargets('admin');
    server.use(
      http.post('/api/v1/targets', () =>
        errorResponse(409, 'ALC-LIC-0008', 'license.target_limit_reached', { params: { used: '5', max: '5' } }),
      ),
    );
    await renderRoute('/servers');
    await userEvent.click(await screen.findByRole('button', { name: 'Add server' }));
    const dialog = await screen.findByRole('dialog', { name: 'Add server' });
    await userEvent.type(within(dialog).getByLabelText(/^Name/), 'web-06');
    await userEvent.type(within(dialog).getByLabelText(/^Address/), 'web-06.example.com');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Connect' }));
    expect(await within(dialog).findByText('Your license allows 5 targets.')).toBeInTheDocument();
    expect(within(dialog).getByRole('button', { name: 'Connect' })).toBeInTheDocument();
  });

  it('explains a failed connection test', async () => {
    withTargets('admin', []);
    server.use(
      http.post('/api/v1/targets', () => HttpResponse.json({ target: pending, job_id: 'job-1', status_url: '/api/v1/jobs/job-1' }, { status: 201 })),
      http.get('/api/v1/jobs/:id', () =>
        HttpResponse.json(jobFixture({ id: 'job-1', status: 'failed', error: { code: 'ALC-SSH-0002', reason: 'ssh.auth_failed' } })),
      ),
    );
    await renderRoute('/servers');
    await userEvent.click(await screen.findByRole('button', { name: 'Add server' }));
    const dialog = await screen.findByRole('dialog', { name: 'Add server' });
    await userEvent.type(within(dialog).getByLabelText(/^Name/), 'db-01');
    await userEvent.type(within(dialog).getByLabelText(/^Address/), 'db-01.example.com');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Connect' }));
    expect(await within(dialog).findByText(commonEn.errors.ssh.auth_failed.title)).toBeInTheDocument();
    expect(within(dialog).getByText('Error code: ALC-SSH-0002')).toBeInTheDocument();
  });

  it('lets an administrator run or discard a change paused by the license', async () => {
    withTargets('admin');
    const blocked = jobFixture({ id: 'job-b', type: 'sshkey.remove', status: 'blocked_license', finished_at: null });
    const calls: string[] = [];
    let items = [blocked];
    server.use(
      http.get('/api/v1/jobs', ({ request }) => {
        expect(new URL(request.url).searchParams.get('status')).toBe('blocked_license');
        return HttpResponse.json({ items, next_cursor: null });
      }),
      http.post('/api/v1/jobs/:id/actions/confirm', ({ params }) => {
        calls.push(`confirm ${String(params.id)}`);
        items = [];
        return HttpResponse.json({ ...blocked, status: 'queued' });
      }),
    );
    await renderRoute('/servers');
    const panel = await screen.findByTestId('blocked-jobs');
    expect(within(panel).getByRole('heading', { name: 'Waiting for an administrator' })).toBeInTheDocument();
    expect(within(panel).getByRole('button', { name: 'Discard: SSH key removal' })).toBeInTheDocument();
    await userEvent.click(within(panel).getByRole('button', { name: 'Run now: SSH key removal' }));
    await waitFor(() => expect(calls).toEqual(['confirm job-b']));
    await waitFor(() => expect(screen.queryByTestId('blocked-jobs')).not.toBeInTheDocument());
  });

  it('is shown in Turkish', async () => {
    withTargets('admin', [targetFixture], 'tr');
    await renderRoute('/servers', { languages: ['tr-TR'] });
    expect(await screen.findByRole('heading', { name: 'Sunucular', level: 1 })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Sunucu ekle' })).toBeInTheDocument();
    expect(await screen.findByText('Bağlı')).toBeInTheDocument();
    expect(await screen.findByRole('heading', { name: 'Sunucuyu Alice için hazırlayın' })).toBeInTheDocument();
  });

  const addForm = async (host = 'db-01.example.com') => {
    await userEvent.click(await screen.findByRole('button', { name: 'Add server' }));
    const dialog = await screen.findByRole('dialog', { name: 'Add server' });
    await userEvent.type(within(dialog).getByLabelText(/^Name/), 'db-01');
    await userEvent.type(within(dialog).getByLabelText(/^Address/), host);
    await userEvent.click(within(dialog).getByRole('button', { name: 'Connect' }));
    return dialog;
  };
  const created = http.post('/api/v1/targets', () => HttpResponse.json({ target: pending, job_id: 'job-1', status_url: '/api/v1/jobs/job-1' }, { status: 201 }));

  it('does not go back to the form when something fails after the server was created', async () => {
    withTargets('admin', []);
    let creates = 0;
    server.use(
      http.post('/api/v1/targets', () => {
        creates += 1;
        return HttpResponse.json({ target: pending, job_id: 'job-1', status_url: '/api/v1/jobs/job-1' }, { status: 201 });
      }),
      http.get('/api/v1/jobs/:id', () => errorResponse(500, 'ALC-INT-0001', 'internal.unexpected')),
      http.get('/api/v1/targets/:id', () => HttpResponse.json(pending)),
      http.get('/api/v1/targets/:id/host-keys', () => HttpResponse.json({ items: [] })),
      http.get('/api/v1/targets/:id/ssh-keys', () => HttpResponse.json({ items: [] })),
    );
    const { router } = await renderRoute('/servers');
    const dialog = await addForm();
    const open = await within(dialog).findByRole('button', { name: 'Open the server' });
    expect(within(dialog).queryByRole('button', { name: 'Connect' })).not.toBeInTheDocument();
    expect(within(dialog).queryByLabelText(/^Address/)).not.toBeInTheDocument();
    await userEvent.click(open);
    await waitFor(() => expect(router.state.location.pathname).toBe(`/servers/${pending.id}`));
    expect(creates).toBe(1);
  });

  it('does not navigate when the dialog was closed while the connection test was still running', async () => {
    withTargets('admin', []);
    let calls = 0;
    server.use(
      created,
      http.get('/api/v1/jobs/:id', () => {
        calls += 1;
        return HttpResponse.json(jobFixture({ id: 'job-1', status: calls < 2 ? 'running' : 'succeeded' }));
      }),
    );
    const { router } = await renderRoute('/servers');
    const dialog = await addForm();
    await within(dialog).findByText('Connecting to the server…');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Close' }));
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Add server' })).not.toBeInTheDocument());
    await new Promise((r) => setTimeout(r, 1400));
    expect(router.state.location.pathname).toBe('/servers');
    expect(calls).toBe(1);
  });

  it('says that the first check is waiting for an administrator when the license paused it', async () => {
    withTargets('admin', []);
    server.use(created, http.get('/api/v1/jobs/:id', () => HttpResponse.json(jobFixture({ id: 'job-1', status: 'blocked_license', error: null }))));
    await renderRoute('/servers');
    const dialog = await addForm();
    expect(await within(dialog).findByText('Waiting for an administrator')).toBeInTheDocument();
    expect(within(dialog).getByText('This task is paused and waits for an administrator to run it.')).toBeInTheDocument();
    expect(within(dialog).getByRole('button', { name: 'Open the server' })).toBeInTheDocument();
  });

  it('loads every page of servers', async () => {
    const second = targetWith({ id: '0192b000-0000-7000-8000-0000000000a3', name: 'app-02', host: 'app-02.example.com' });
    server.use(
      ...sessionHandlers(sessionFor('operator')),
      http.get('/api/v1/targets', ({ request }) => {
        const cursor = new URL(request.url).searchParams.get('cursor');
        return cursor ? HttpResponse.json({ items: [second], next_cursor: null }) : HttpResponse.json({ items: [targetFixture], next_cursor: 'c2' });
      }),
    );
    await renderRoute('/servers');
    const table = await screen.findByTestId('targets-table');
    await waitFor(() => expect(within(table).getByText('app-02')).toBeInTheDocument());
    expect(within(table).getByText('web-01')).toBeInTheDocument();
  });

  it('works in React StrictMode, which mounts, cleans up and mounts again', async () => {
    withTargets('admin', []);
    server.use(
      created,
      http.get('/api/v1/jobs/:id', () => HttpResponse.json(jobFixture({ id: 'job-1', status: 'succeeded' }))),
      http.get('/api/v1/targets/:id', () => HttpResponse.json(targetWith({ ...pending, status: 'ok' }))),
      http.get('/api/v1/targets/:id/host-keys', () => HttpResponse.json({ items: [] })),
      http.get('/api/v1/targets/:id/ssh-keys', () => HttpResponse.json({ items: [] })),
    );
    const { router } = await renderRoute('/servers', { strict: true });
    await addForm();
    await waitFor(() => expect(router.state.location.pathname).toBe(`/servers/${pending.id}`));
  });

  it('after the confirmation call fails, offers to open the server instead of the confirmation again', async () => {
    withTargets('admin', []);
    const observed = hostKeyFixture({ id: 'hk-observed', status: 'observed', fingerprint: 'SHA256:newServerNewServerNewServerNewServerNew0', confirmed_at: null, confirmed_by_name: '' });
    server.use(
      created,
      http.get('/api/v1/jobs/:id', () =>
        HttpResponse.json(jobFixture({ id: 'job-1', status: 'failed', error: { code: 'ALC-TGT-0002', reason: 'target.host_key_unconfirmed' } })),
      ),
      http.get('/api/v1/targets/:id/host-keys', () => HttpResponse.json({ items: [observed] })),
      http.post('/api/v1/targets/:id/host-keys/:keyId/actions/confirm', () => errorResponse(500, 'ALC-INT-0001', 'internal.unexpected')),
    );
    await renderRoute('/servers');
    await addForm();
    const confirm = await screen.findByRole('dialog', { name: 'Is this your server?' });
    await userEvent.click(within(confirm).getByRole('button', { name: 'Yes, this is my server' }));
    const dialog = await screen.findByRole('dialog', { name: 'Add server' });
    expect(await within(dialog).findByRole('button', { name: 'Open the server' })).toBeInTheDocument();
    expect(within(dialog).queryByRole('button', { name: 'Yes, this is my server' })).not.toBeInTheDocument();
  });
});
