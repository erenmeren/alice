import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import commonEn from '@locales/common/en.json';
import {
  deploymentFixture,
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
    await userEvent.selectOptions(screen.getByLabelText('Server type'), 'apache');
    expect(screen.getByTestId('setup-script')).toHaveTextContent('# apache setup script');
    await userEvent.selectOptions(screen.getByLabelText('Server type'), 'haproxy');
    expect(screen.getByTestId('setup-script')).toHaveTextContent('# haproxy setup script');
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

  it('names a server whose address Alice refuses to connect to (ALC-SSH-0012)', async () => {
    withTargets('admin', [targetWith({ ...pending, status: 'unreachable', last_error: { code: 'ALC-SSH-0012', reason: 'ssh.address_not_allowed' } })]);
    server.use(
      http.post('/api/v1/targets', () => HttpResponse.json({ target: pending, job_id: 'job-1', status_url: '/api/v1/jobs/job-1' }, { status: 201 })),
      http.get('/api/v1/jobs/:id', () =>
        HttpResponse.json(jobFixture({ id: 'job-1', status: 'failed', error: { code: 'ALC-SSH-0012', reason: 'ssh.address_not_allowed' } })),
      ),
    );
    await renderRoute('/servers');
    const row = (await screen.findByText('db-01')).closest('tr')!;
    expect(within(row).getByText(commonEn.errors.ssh.address_not_allowed.title)).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: 'Add server' }));
    const dialog = await screen.findByRole('dialog', { name: 'Add server' });
    await userEvent.type(within(dialog).getByLabelText(/^Name/), 'meta');
    await userEvent.type(within(dialog).getByLabelText(/^Address/), 'metadata.example.test');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Connect' }));
    expect(await within(dialog).findByText(commonEn.errors.ssh.address_not_allowed.title)).toBeInTheDocument();
    expect(within(dialog).getByText(commonEn.errors.ssh.address_not_allowed.action)).toBeInTheDocument();
    expect(within(dialog).getByText('Error code: ALC-SSH-0012')).toBeInTheDocument();
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

  it('says whether a held deployment job was already sent, so Discard is not taken for "nothing ran" (C-I1)', async () => {
    withTargets('admin');
    const sent = jobFixture({ id: 'job-sent', type: 'certificate.deploy', target_id: targetFixture.id, status: 'blocked_license', finished_at: null });
    const held = jobFixture({ id: 'job-held', type: 'certificate.deploy', target_id: targetFixture.id, status: 'blocked_license', finished_at: null });
    let deploymentQuery = '';
    server.use(
      http.get('/api/v1/jobs', () => HttpResponse.json({ items: [sent, held], next_cursor: null })),
      http.get('/api/v1/deployments', ({ request }) => {
        deploymentQuery = new URL(request.url).search;
        return HttpResponse.json({
          items: [
            deploymentFixture({ id: 'dep-sent', job_id: 'job-sent', job_status: 'blocked_license', status: 'running', state: 'recovering', finished_at: null }),
            deploymentFixture({ id: 'dep-held', job_id: 'job-held', job_status: 'blocked_license', status: 'pending', state: 'queued', finished_at: null }),
          ],
          next_cursor: null,
        });
      }),
    );
    await renderRoute('/servers');
    const rows = await screen.findAllByTestId('blocked-job');
    expect(await within(rows[0]).findByText(/Alice already sent this deployment to the server .* Discarding this job does not undo it\./)).toBeInTheDocument();
    expect(within(rows[0]).getByRole('link', { name: 'Open this deployment' })).toHaveAttribute('href', '/deployments/dep-sent');
    expect(within(rows[1]).getByText('Nothing has been sent to the server yet. Discarding this job cancels the deployment.')).toBeInTheDocument();
    expect(deploymentQuery).toContain(`target_id=${targetFixture.id}`);
  });

  it('shows every held job: "Show more" reads the next page and appends it, then goes away (AUD-25 d)', async () => {
    withTargets('admin');
    const first = Array.from({ length: 50 }, (_, i) => jobFixture({ id: `job-${i}`, type: 'sshkey.remove', status: 'blocked_license', finished_at: null }));
    const second = [jobFixture({ id: 'job-last', type: 'target.discover', status: 'blocked_license', finished_at: null })];
    const cursors: (string | null)[] = [];
    server.use(
      http.get('/api/v1/jobs', ({ request }) => {
        const q = new URL(request.url).searchParams;
        expect(q.get('status')).toBe('blocked_license');
        cursors.push(q.get('cursor'));
        return q.get('cursor') === 'page-2'
          ? HttpResponse.json({ items: second, next_cursor: null })
          : HttpResponse.json({ items: first, next_cursor: 'page-2' });
      }),
    );
    await renderRoute('/servers');
    const panel = await screen.findByTestId('blocked-jobs');
    expect(within(panel).getAllByTestId('blocked-job')).toHaveLength(50);
    expect(within(panel).queryByRole('button', { name: 'Run now: Server scan' })).not.toBeInTheDocument();
    await userEvent.click(within(panel).getByRole('button', { name: 'Show more' }));
    expect(await within(panel).findByRole('button', { name: 'Run now: Server scan' })).toBeInTheDocument();
    expect(within(panel).getAllByTestId('blocked-job')).toHaveLength(51);
    expect(within(panel).queryByRole('button', { name: 'Show more' })).not.toBeInTheDocument();
    expect(cursors).toEqual([null, 'page-2']);
  });

  it('offers no "Show more" when all held jobs fit on one page', async () => {
    withTargets('admin');
    const blocked = jobFixture({ id: 'job-b', type: 'sshkey.remove', status: 'blocked_license', finished_at: null });
    server.use(http.get('/api/v1/jobs', () => HttpResponse.json({ items: [blocked], next_cursor: null })));
    await renderRoute('/servers');
    const panel = await screen.findByTestId('blocked-jobs');
    expect(within(panel).getAllByTestId('blocked-job')).toHaveLength(1);
    expect(within(panel).queryByRole('button', { name: 'Show more' })).not.toBeInTheDocument();
  });

  it('refreshes the server list after a paused change is run', async () => {
    withTargets('admin');
    const blocked = jobFixture({ id: 'job-b', type: 'sshkey.remove', status: 'blocked_license', finished_at: null });
    let listCalls = 0;
    server.use(
      http.get('/api/v1/targets', () => {
        listCalls += 1;
        return HttpResponse.json({ items: [targetFixture], next_cursor: null });
      }),
      http.get('/api/v1/jobs', () => HttpResponse.json({ items: [blocked], next_cursor: null })),
      http.post('/api/v1/jobs/:id/actions/confirm', () => HttpResponse.json({ ...blocked, status: 'queued' })),
    );
    await renderRoute('/servers');
    const panel = await screen.findByTestId('blocked-jobs');
    await screen.findByTestId('targets-table');
    const before = listCalls;
    await userEvent.click(within(panel).getByRole('button', { name: 'Run now: SSH key removal' }));
    await waitFor(() => expect(listCalls).toBeGreaterThan(before));
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
      http.get('/api/v1/jobs/:id', () => errorResponse(500, 'ALC-SYS-0003', 'internal.unexpected')),
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
      http.post('/api/v1/targets/:id/host-keys/:keyId/actions/confirm', () => errorResponse(500, 'ALC-SYS-0003', 'internal.unexpected')),
    );
    await renderRoute('/servers');
    await addForm();
    const confirm = await screen.findByRole('dialog', { name: 'Is this your server?' });
    await userEvent.click(within(confirm).getByRole('button', { name: 'Yes, this is my server' }));
    const dialog = await screen.findByRole('dialog', { name: 'Add server' });
    expect(await within(dialog).findByRole('button', { name: 'Open the server' })).toBeInTheDocument();
    expect(within(dialog).queryByRole('button', { name: 'Yes, this is my server' })).not.toBeInTheDocument();
  });

  describe('the server type of a new server', () => {
    it('offers Linux server and Nginx server, shows the commands of the chosen type and sends it', async () => {
      withTargets('admin', []);
      let body: unknown = null;
      server.use(
        http.post('/api/v1/targets', async ({ request }) => {
          body = await request.json();
          return HttpResponse.json({ target: { ...pending, type: 'nginx' }, job_id: 'job-1', status_url: '/api/v1/jobs/job-1' }, { status: 201 });
        }),
        http.get('/api/v1/jobs/:id', () => HttpResponse.json(jobFixture({ id: 'job-1', status: 'succeeded' }))),
        http.get('/api/v1/targets/:id', () => HttpResponse.json(targetWith({ ...pending, type: 'nginx', status: 'ok' }))),
        http.get('/api/v1/targets/:id/host-keys', () => HttpResponse.json({ items: [] })),
        http.get('/api/v1/targets/:id/ssh-keys', () => HttpResponse.json({ items: [] })),
        http.get('/api/v1/targets/:id/certificate-locations', () => HttpResponse.json({ items: [], truncated: false })),
      );
      const { router } = await renderRoute('/servers');
      await userEvent.click(await screen.findByRole('button', { name: 'Add server' }));
      const dialog = await screen.findByRole('dialog', { name: 'Add server' });
      const type = within(dialog).getByLabelText('Server type');
      expect(type).toHaveValue('linux');
      expect(within(dialog).getAllByRole('option').map((o) => o.textContent)).toEqual(['Linux server', 'Nginx server', 'Apache server', 'HAProxy server', 'Windows server']);
      expect(within(dialog).getByText(/^Choose the web server software this server runs/)).toBeInTheDocument();
      expect(await within(dialog).findByTestId('add-server-script')).toHaveTextContent('# linux setup script');
      await userEvent.selectOptions(type, 'nginx');
      expect(within(dialog).getByTestId('add-server-script')).toHaveTextContent('# nginx setup script');
      await userEvent.type(within(dialog).getByLabelText(/^Name/), 'db-01');
      await userEvent.type(within(dialog).getByLabelText(/^Address/), 'db-01.example.com');
      await userEvent.click(within(dialog).getByRole('button', { name: 'Connect' }));
      await waitFor(() => expect(router.state.location.pathname).toBe(`/servers/${pending.id}`));
      expect(body).toEqual({ name: 'db-01', type: 'nginx', host: 'db-01.example.com', port: 22, username: 'alice-svc' });
    });

    it('shows the Apache commands and sends the type apache', async () => {
      withTargets('admin', []);
      let body: unknown = null;
      server.use(
        http.post('/api/v1/targets', async ({ request }) => {
          body = await request.json();
          return HttpResponse.json({ target: { ...pending, type: 'apache' }, job_id: 'job-1', status_url: '/api/v1/jobs/job-1' }, { status: 201 });
        }),
        http.get('/api/v1/jobs/:id', () => HttpResponse.json(jobFixture({ id: 'job-1', status: 'succeeded' }))),
        http.get('/api/v1/targets/:id', () => HttpResponse.json(targetWith({ ...pending, type: 'apache', status: 'ok' }))),
        http.get('/api/v1/targets/:id/host-keys', () => HttpResponse.json({ items: [] })),
        http.get('/api/v1/targets/:id/ssh-keys', () => HttpResponse.json({ items: [] })),
        http.get('/api/v1/targets/:id/certificate-locations', () => HttpResponse.json({ items: [], truncated: false })),
      );
      const { router } = await renderRoute('/servers');
      await userEvent.click(await screen.findByRole('button', { name: 'Add server' }));
      const dialog = await screen.findByRole('dialog', { name: 'Add server' });
      await userEvent.selectOptions(within(dialog).getByLabelText('Server type'), 'apache');
      expect(within(dialog).getByTestId('add-server-script')).toHaveTextContent('# apache setup script');
      await userEvent.type(within(dialog).getByLabelText(/^Name/), 'db-01');
      await userEvent.type(within(dialog).getByLabelText(/^Address/), 'db-01.example.com');
      await userEvent.click(within(dialog).getByRole('button', { name: 'Connect' }));
      await waitFor(() => expect(router.state.location.pathname).toBe(`/servers/${pending.id}`));
      expect(body).toEqual({ name: 'db-01', type: 'apache', host: 'db-01.example.com', port: 22, username: 'alice-svc' });
    });

    it('shows the HAProxy commands and sends the type haproxy', async () => {
      withTargets('admin', []);
      let body: unknown = null;
      server.use(
        http.post('/api/v1/targets', async ({ request }) => {
          body = await request.json();
          return HttpResponse.json({ target: { ...pending, type: 'haproxy' }, job_id: 'job-1', status_url: '/api/v1/jobs/job-1' }, { status: 201 });
        }),
        http.get('/api/v1/jobs/:id', () => HttpResponse.json(jobFixture({ id: 'job-1', status: 'succeeded' }))),
        http.get('/api/v1/targets/:id', () => HttpResponse.json(targetWith({ ...pending, type: 'haproxy', status: 'ok' }))),
        http.get('/api/v1/targets/:id/host-keys', () => HttpResponse.json({ items: [] })),
        http.get('/api/v1/targets/:id/ssh-keys', () => HttpResponse.json({ items: [] })),
        http.get('/api/v1/targets/:id/certificate-locations', () => HttpResponse.json({ items: [], truncated: false })),
      );
      const { router } = await renderRoute('/servers');
      await userEvent.click(await screen.findByRole('button', { name: 'Add server' }));
      const dialog = await screen.findByRole('dialog', { name: 'Add server' });
      await userEvent.selectOptions(within(dialog).getByLabelText('Server type'), 'haproxy');
      expect(within(dialog).getByTestId('add-server-script')).toHaveTextContent('# haproxy setup script');
      await userEvent.type(within(dialog).getByLabelText(/^Name/), 'db-01');
      await userEvent.type(within(dialog).getByLabelText(/^Address/), 'db-01.example.com');
      await userEvent.click(within(dialog).getByRole('button', { name: 'Connect' }));
      await waitFor(() => expect(router.state.location.pathname).toBe(`/servers/${pending.id}`));
      expect(body).toEqual({ name: 'db-01', type: 'haproxy', host: 'db-01.example.com', port: 22, username: 'alice-svc' });
    });

    describe('windows type', () => {
      it('shows the PowerShell script, defaults the account to alice and sends a domain account verbatim', async () => {
        withTargets('admin', []);
        let body: unknown = null;
        server.use(
          http.post('/api/v1/targets', async ({ request }) => {
            body = await request.json();
            return HttpResponse.json({ target: { ...pending, type: 'windows' }, job_id: 'job-1', status_url: '/api/v1/jobs/job-1' }, { status: 201 });
          }),
          http.get('/api/v1/jobs/:id', () => HttpResponse.json(jobFixture({ id: 'job-1', status: 'succeeded' }))),
          http.get('/api/v1/targets/:id', () => HttpResponse.json(targetWith({ ...pending, type: 'windows', status: 'ok' }))),
          http.get('/api/v1/targets/:id/host-keys', () => HttpResponse.json({ items: [] })),
          http.get('/api/v1/targets/:id/ssh-keys', () => HttpResponse.json({ items: [] })),
          http.get('/api/v1/targets/:id/certificate-locations', () => HttpResponse.json({ items: [], truncated: false })),
        );
        const { router } = await renderRoute('/servers');
        await userEvent.click(await screen.findByRole('button', { name: 'Add server' }));
        const dialog = await screen.findByRole('dialog', { name: 'Add server' });
        const user = within(dialog).getByLabelText(/^User name on the server/);
        expect(user).toHaveValue('alice-svc');
        await userEvent.selectOptions(within(dialog).getByLabelText('Server type'), 'windows');
        expect(await within(dialog).findByTestId('add-server-script')).toHaveTextContent('# windows setup script');
        expect(within(dialog).getByText('PowerShell setup script')).toBeInTheDocument();
        expect(within(dialog).getByText('Run it once in an elevated PowerShell on the server, in the folder that holds alice-helper.exe. It uses the Windows account you enter above.')).toBeInTheDocument();
        expect(within(dialog).getByLabelText(/^Windows account/)).toHaveValue('alice');
        expect(within(dialog).getByLabelText(/^Windows account/)).toHaveAttribute('maxlength', '36');
        await userEvent.type(within(dialog).getByLabelText(/^Name/), 'iis-01');
        await userEvent.type(within(dialog).getByLabelText(/^Address/), 'iis-01.example.com');
        const account = within(dialog).getByLabelText(/^Windows account/);
        await userEvent.clear(account);
        await userEvent.type(account, 'CORP\\alice-svc');
        await userEvent.click(within(dialog).getByRole('button', { name: 'Connect' }));
        await waitFor(() => expect(router.state.location.pathname).toBe(`/servers/${pending.id}`));
        expect(body).toEqual({ name: 'iis-01', type: 'windows', host: 'iis-01.example.com', port: 22, username: 'CORP\\alice-svc' });
      });

      // The script names the account typed above (final review I1); a name outside the Windows rule keeps alice.
      it('puts the typed account into the shown and copied script', async () => {
        withTargets('admin', []);
        const user = userEvent.setup(); // provides the clipboard Mantine's CopyButton writes to
        await renderRoute('/servers');
        await user.click(await screen.findByRole('button', { name: 'Add server' }));
        const dialog = await screen.findByRole('dialog', { name: 'Add server' });
        await user.selectOptions(within(dialog).getByLabelText('Server type'), 'windows');
        const script = await within(dialog).findByTestId('add-server-script');
        expect(script).toHaveTextContent("$AliceUser = 'alice'");
        expect(within(dialog).getByText(/uses the Windows account you enter above/)).toBeInTheDocument();
        const account = within(dialog).getByLabelText(/^Windows account/);
        await user.clear(account);
        await user.type(account, 'CORP\\alice-svc');
        expect(script).toHaveTextContent("$AliceUser = 'CORP\\alice-svc'");
        expect(script).not.toHaveTextContent("$AliceUser = 'alice'");
        await user.click(within(dialog).getByRole('button', { name: 'Copy commands' }));
        expect(await navigator.clipboard.readText()).toContain("$AliceUser = 'CORP\\alice-svc'\n");
        await user.clear(account);
        await user.type(account, "bad'name");
        expect(script).toHaveTextContent("$AliceUser = 'alice'");
        expect(script).not.toHaveTextContent('bad');
      });

      it('restores the Linux default when switching back, but keeps a name the person typed', async () => {
        withTargets('admin', []);
        await renderRoute('/servers');
        await userEvent.click(await screen.findByRole('button', { name: 'Add server' }));
        const dialog = await screen.findByRole('dialog', { name: 'Add server' });
        const type = within(dialog).getByLabelText('Server type');
        await userEvent.selectOptions(type, 'windows');
        await userEvent.selectOptions(type, 'linux');
        expect(within(dialog).getByLabelText(/^User name on the server/)).toHaveValue('alice-svc');
        await userEvent.selectOptions(type, 'windows');
        const account = within(dialog).getByLabelText(/^Windows account/);
        await userEvent.clear(account);
        await userEvent.type(account, 'svc-iis');
        await userEvent.selectOptions(type, 'nginx');
        expect(within(dialog).getByLabelText(/^User name on the server/)).toHaveValue('svc-iis');
      });

      it('words the type in Turkish', async () => {
        withTargets('admin', [], 'tr');
        await renderRoute('/servers', { languages: ['tr-TR'] });
        await userEvent.click(await screen.findByRole('button', { name: 'Sunucu ekle' }));
        const dialog = await screen.findByRole('dialog', { name: 'Sunucu ekle' });
        await userEvent.selectOptions(within(dialog).getByLabelText('Sunucu türü'), 'windows');
        expect(await within(dialog).findByTestId('add-server-script')).toHaveTextContent('# windows setup script');
        expect(within(dialog).getByText('PowerShell kurulum betiği')).toBeInTheDocument();
        expect(within(dialog).getByLabelText(/^Windows hesabı/)).toHaveValue('alice');
      });

      it('lists the Windows profile in the preparation panel', async () => {
        withTargets('admin', [targetFixture]);
        await renderRoute('/servers');
        await screen.findByTestId('platform-public-key');
        await userEvent.selectOptions(screen.getByLabelText('Server type'), 'windows');
        expect(screen.getByTestId('setup-script')).toHaveTextContent('# windows setup script');
      });
    });

    it('shows the choice in Turkish', async () => {
      withTargets('admin', [], 'tr');
      await renderRoute('/servers', { languages: ['tr-TR'] });
      await userEvent.click(await screen.findByRole('button', { name: 'Sunucu ekle' }));
      const dialog = await screen.findByRole('dialog', { name: 'Sunucu ekle' });
      expect(within(dialog).getByLabelText('Sunucu türü')).toBeInTheDocument();
      expect(within(dialog).getAllByRole('option').map((o) => o.textContent)).toEqual(['Linux sunucusu', 'Nginx sunucusu', 'Apache sunucusu', 'HAProxy sunucusu', 'Windows sunucusu']);
    });
  });
});

describe('TargetsPage and Key Vaults', () => {
  it('does not list a vault under Servers', async () => {
    withTargets('admin', [targetFixture, targetWith({ id: 'v1', name: 'Prod vault', type: 'azure_key_vault', host: 'contoso-prod.vault.azure.net', port: 443 })]);
    await renderRoute('/servers');
    const table = await screen.findByTestId('targets-table');
    expect(within(table).getByText('web-01')).toBeInTheDocument();
    expect(within(table).queryByText('Prod vault')).not.toBeInTheDocument();
  });
});

describe('TargetsPage in the design', () => {
  beforeEach(() => localStorage.clear());

  it('has the design header: the h1, the description, and Add server for administrators only', async () => {
    withTargets('admin');
    const view = await renderRoute('/servers');
    expect(await screen.findByRole('heading', { name: 'Servers', level: 1 })).toBeInTheDocument();
    expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
    expect(screen.getByText('Know what is connected, what changed, and what needs a closer look.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Add server' })).toBeInTheDocument();
    view.unmount();
    withTargets('auditor');
    await renderRoute('/servers');
    await screen.findByTestId('targets-table');
    expect(screen.queryByRole('button', { name: 'Add server' })).not.toBeInTheDocument();
  });

  it('counts the connection states over the complete list, every page of it', async () => {
    const page1 = [
      targetFixture,
      targetWith({ id: 's2', name: 'web-02', status: 'host_key_changed' }),
      targetWith({ id: 's3', name: 'web-03', status: 'unreachable' }),
    ];
    const page2 = [targetWith({ id: 's4', name: 'web-04', status: 'ok' }), targetWith({ id: 's5', name: 'web-05', status: 'pending_host_key' })];
    server.use(
      ...sessionHandlers(sessionFor('operator')),
      http.get('/api/v1/targets', ({ request }) =>
        new URL(request.url).searchParams.get('cursor') ? HttpResponse.json({ items: page2, next_cursor: null }) : HttpResponse.json({ items: page1, next_cursor: 'c2' }),
      ),
    );
    await renderRoute('/servers');
    const stats = await screen.findByRole('list', { name: 'Connection summary' });
    const items = within(stats).getAllByRole('listitem');
    // Every server is in a bucket: the one waiting for its fingerprint is counted on its own.
    expect(items.map((i) => i.textContent)).toEqual(['5 servers', '2 connected', '1 identity changed', '1 unreachable', '1 awaiting fingerprint confirmation']);
    expect(items.map((i) => i.getAttribute('data-tone'))).toEqual([null, 'success', 'danger', 'warning', 'warning']);
  });

  it('counts refused sign-ins on their own and the remaining states as a labelled remainder, so the buckets add up', async () => {
    withTargets('operator', [
      targetFixture,
      targetWith({ id: 's2', name: 'web-02', status: 'auth_failed' }),
      targetWith({ id: 's3', name: 'web-03', status: 'checking' }),
      targetWith({ id: 's4', name: 'web-04', status: 'disabled' }),
    ]);
    await renderRoute('/servers');
    const items = within(await screen.findByRole('list', { name: 'Connection summary' })).getAllByRole('listitem');
    // Empty buckets of the less common states are not drawn.
    expect(items.map((i) => i.textContent)).toEqual(['4 servers', '1 connected', '0 identity changed', '0 unreachable', '1 sign-in refused', '2 in other states']);
    expect(items.map((i) => i.getAttribute('data-tone'))).toEqual([null, 'success', 'danger', 'warning', 'danger', null]);
  });

  it('says "1 server" in the singular', async () => {
    withTargets('operator', [targetFixture]);
    await renderRoute('/servers');
    const items = within(await screen.findByRole('list', { name: 'Connection summary' })).getAllByRole('listitem');
    expect(items[0]).toHaveTextContent('1 server');
    expect(items).toHaveLength(4);
  });

  it('shows the inventory table: one header row, one row per server, status badges with text and icon, an open link and the footer', async () => {
    withTargets('operator', [targetFixture, targetWith({ id: 's2', name: 'web-02', type: 'nginx', status: 'host_key_changed', last_success_at: null })]);
    await renderRoute('/servers');
    const table = await screen.findByTestId('targets-table');
    expect(within(table).getAllByRole('row')).toHaveLength(3);
    expect(within(table).getAllByRole('columnheader').map((h) => h.textContent)).toEqual(['Server', 'Address', 'Platform', 'Connection', 'Last connected', 'Service', 'Open']);
    const row = within(table).getByRole('link', { name: 'web-01' }).closest('tr')!;
    expect(within(row).getByText('Ubuntu 22.04.4 LTS')).toBeInTheDocument();
    expect(within(row).getByText('Linux server')).toBeInTheDocument();
    const badge = within(row).getByText('Connected').closest('.mantine-Badge-root')!;
    expect(badge).toHaveAttribute('data-tone', 'success');
    expect(badge.querySelector('svg')).not.toBeNull();
    expect(within(row).getByRole('link', { name: 'Open web-01' })).toHaveAttribute('href', `/servers/${targetFixture.id}`);
    const changed = within(table).getByRole('link', { name: 'web-02' }).closest('tr')!;
    expect(within(changed).getByText('Server identity changed').closest('.mantine-Badge-root')).toHaveAttribute('data-tone', 'danger');
    expect(within(changed).getByText('Nginx server')).toBeInTheDocument();
    expect(within(changed).getByText('Never')).toBeInTheDocument();
    expect(screen.getByText('Azure Key Vaults are listed separately.')).toBeInTheDocument();
  });

  it('replaces the table with the empty state when there are no servers', async () => {
    withTargets('admin', []);
    await renderRoute('/servers');
    expect(await screen.findByText('No servers yet. Prepare a server with the command below, then add it.')).toBeInTheDocument();
    expect(screen.queryByTestId('targets-table')).not.toBeInTheDocument();
  });

  it('shows the held jobs and the platform key as panels for administrators', async () => {
    withTargets('admin');
    const blocked = jobFixture({ id: 'job-b', type: 'sshkey.remove', status: 'blocked_license', finished_at: null });
    server.use(http.get('/api/v1/jobs', () => HttpResponse.json({ items: [blocked], next_cursor: null })));
    await renderRoute('/servers');
    const held = await screen.findByTestId('blocked-jobs');
    expect(held.tagName).toBe('SECTION');
    expect(within(held).getByRole('heading', { name: 'Waiting for an administrator', level: 2 })).toBeInTheDocument();
    const prepare = (await screen.findByRole('heading', { name: 'Prepare a server for Alice', level: 2 })).closest('section')!;
    expect(within(prepare).getByTestId('platform-public-key')).toBeInTheDocument();
  });
});
