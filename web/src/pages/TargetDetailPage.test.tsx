import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import commonEn from '@locales/common/en.json';
import type { KeyLocation, Target, Warning } from '../api/types';
import {
  aliceKeyLocation,
  errorResponse,
  hostKeyFixture,
  jobFixture,
  locationFixture,
  nginxFacts,
  nginxTargetFixture,
  nginxTargetWith,
  keyLocationFixture,
  sessionFor,
  sessionHandlers,
  targetFixture,
  targetWith,
} from '../test/fixtures';
import { renderRoute } from '../test/render';
import { server } from '../test/server';

const ci = keyLocationFixture({
  id: '0192b000-0000-7000-8000-0000000000l2',
  ssh_key_id: '0192b000-0000-7000-8000-0000000000k2',
  fingerprint: 'SHA256:ciCiCiCiCiCiCiCiCiCiCiCiCiCiCiCiCiCiCiCiCi00',
  key_type: 'ssh-rsa',
  comment: 'ci@build',
  line_no: 2,
});
const root = keyLocationFixture({
  id: '0192b000-0000-7000-8000-0000000000l3',
  ssh_key_id: '0192b000-0000-7000-8000-0000000000k3',
  fingerprint: 'SHA256:rootRootRootRootRootRootRootRootRootRoot0000',
  os_user: 'root',
  file_path: '/root/.ssh/authorized_keys',
  options: 'from="10.0.0.0/8"',
  comment: 'root@bastion',
});
const pinned = hostKeyFixture();
const observed = hostKeyFixture({
  id: '0192b000-0000-7000-8000-0000000000h2',
  status: 'observed',
  fingerprint: 'SHA256:changedChangedChangedChangedChangedChanged0',
  confirmed_at: null,
  confirmed_by_name: '',
});

function onServer(role: 'admin' | 'operator' | 'auditor', target: Target = targetFixture, keys: KeyLocation[] = [keyLocationFixture(), ci, root, aliceKeyLocation], lang = 'en') {
  server.use(
    ...sessionHandlers(sessionFor(role, lang)),
    http.get('/api/v1/targets/:id', () => HttpResponse.json(target)),
    http.get('/api/v1/targets/:id/host-keys', () => HttpResponse.json({ items: target.status === 'host_key_changed' ? [pinned, observed] : [pinned] })),
    http.get('/api/v1/targets/:id/ssh-keys', () => HttpResponse.json({ items: keys })),
  );
}

const path = `/servers/${targetFixture.id}`;

describe('TargetDetailPage', () => {
  beforeEach(() => localStorage.clear());

  it('shows the server, its facts and the keys found with their users', async () => {
    onServer('operator', targetWith({ facts: { ...targetFixture.facts, warnings: [{ code: 'strict_modes', params: { user: 'old', path: '/home/old/.ssh/authorized_keys' } }] } }));
    await renderRoute(path);
    expect(await screen.findByRole('heading', { name: 'web-01', level: 1 })).toBeInTheDocument();
    expect(screen.getByTestId('target-status')).toHaveTextContent('Connected');
    expect(screen.getByText('Operating system: Ubuntu 22.04.4 LTS')).toBeInTheDocument();
    expect(screen.getByText('alice-helper version: 1.0.0')).toBeInTheDocument();
    expect(screen.getByText('The SSH server ignores this key file because its permissions are too open: /home/old/.ssh/authorized_keys')).toBeInTheDocument();
    const table = await screen.findByTestId('target-keys');
    expect(within(table).getByText('ci@build').closest('tr')).toHaveTextContent('deploy');
    expect(within(table).getByText('root@bastion').closest('tr')).toHaveTextContent('root');
    expect(within(table).getByText('alice-platform').closest('tr')).toHaveTextContent("Alice's key");
    expect(screen.getByRole('button', { name: 'Test connection' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Scan for SSH keys' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Remove server' })).not.toBeInTheDocument();
    expect(within(table).getAllByRole('button', { name: 'Remove key from deploy' })).toHaveLength(2);
  });

  it('gives auditors a read-only page', async () => {
    onServer('auditor');
    await renderRoute(path);
    await screen.findByTestId('target-keys');
    expect(screen.queryByRole('button', { name: 'Test connection' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Scan for SSH keys' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /^Remove key from/ })).not.toBeInTheDocument();
  });

  it('blocks the server visibly when its identity changed; only administrators can review it', async () => {
    onServer('operator', targetWith({ status: 'host_key_changed' }));
    await renderRoute(path);
    const alert = await screen.findByTestId('host-key-changed');
    expect(alert).toHaveTextContent(
      "The server's identity has changed, so Alice stopped all work on it. Ask your security team to confirm the change before you accept it.",
    );
    expect(screen.getByTestId('target-status')).toHaveTextContent('Server identity changed');
    expect(screen.queryByRole('button', { name: 'Review the new fingerprint' })).not.toBeInTheDocument();
  });

  it('accepts the new fingerprint after a step-up, with a reason', async () => {
    let target = targetWith({ status: 'host_key_changed' });
    onServer('admin', target);
    let attempts = 0;
    let body: unknown = null;
    server.use(
      http.get('/api/v1/targets/:id', () => HttpResponse.json(target)),
      http.post('/api/v1/targets/:id/host-keys/:keyId/actions/repin', async ({ request }) => {
        attempts += 1;
        if (attempts === 1) return errorResponse(403, 'ALC-AUTH-0003', 'auth.stepup_required');
        body = await request.json();
        target = targetWith({ status: 'ok' });
        return HttpResponse.json({ job_id: 'job-r', status_url: '/api/v1/jobs/job-r' }, { status: 202 });
      }),
      http.post('/api/v1/auth/stepup', () => HttpResponse.json(sessionFor('admin'))),
      http.get('/api/v1/jobs/:id', () => HttpResponse.json(jobFixture({ id: 'job-r' }))),
    );
    await renderRoute(path);
    await userEvent.click(await screen.findByRole('button', { name: 'Review the new fingerprint' }));
    const dialog = await screen.findByRole('dialog', { name: 'Accept the new server fingerprint' });
    expect(within(dialog).getByText(pinned.fingerprint)).toBeInTheDocument();
    expect(within(dialog).getByTestId('repin-new-fingerprint')).toHaveTextContent(observed.fingerprint);
    await userEvent.type(within(dialog).getByLabelText(/^Reason/), 'CHG-2026-0412 reinstall');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Accept new fingerprint' }));
    const stepUp = await screen.findByRole('dialog', { name: "Confirm it's you" });
    await userEvent.type(within(stepUp).getByLabelText('6-digit code'), '123456');
    await userEvent.click(within(stepUp).getByRole('button', { name: 'Confirm' }));
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Accept the new server fingerprint' })).not.toBeInTheDocument());
    expect(body).toEqual({ fingerprint: observed.fingerprint, reason: 'CHG-2026-0412 reinstall' });
    expect(await screen.findByText('Connected')).toBeInTheDocument();
    expect(screen.queryByTestId('host-key-changed')).not.toBeInTheDocument();
  });

  it('sends the re-pin reason on one line even when it was typed over several lines', async () => {
    const target = targetWith({ status: 'host_key_changed' });
    onServer('admin', target);
    let body: unknown = null;
    server.use(
      http.post('/api/v1/targets/:id/host-keys/:keyId/actions/repin', async ({ request }) => {
        body = await request.json();
        return HttpResponse.json({ job_id: 'job-r', status_url: '/api/v1/jobs/job-r' }, { status: 202 });
      }),
      http.get('/api/v1/jobs/:id', () => HttpResponse.json(jobFixture({ id: 'job-r' }))),
    );
    await renderRoute(path);
    await userEvent.click(await screen.findByRole('button', { name: 'Review the new fingerprint' }));
    const dialog = await screen.findByRole('dialog', { name: 'Accept the new server fingerprint' });
    await userEvent.type(within(dialog).getByLabelText(/^Reason/), 'CHG-2026-0412{Enter}  server   reinstalled{Enter}');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Accept new fingerprint' }));
    await waitFor(() => expect(body).toEqual({ fingerprint: observed.fingerprint, reason: 'CHG-2026-0412 server reinstalled' }));
  });

  it('lets an administrator keep the previous fingerprint when the server still shows it', async () => {
    let target = targetWith({ status: 'host_key_changed' });
    onServer('admin', target);
    let body: unknown = null;
    let repinned = '';
    server.use(
      http.get('/api/v1/targets/:id', () => HttpResponse.json(target)),
      http.post('/api/v1/targets/:id/host-keys/:keyId/actions/repin', async ({ request, params }) => {
        body = await request.json();
        repinned = String(params.keyId);
        target = targetWith({ status: 'ok' });
        return HttpResponse.json({ job_id: 'job-d', status_url: '/api/v1/jobs/job-d' }, { status: 202 });
      }),
      http.get('/api/v1/jobs/:id', () => HttpResponse.json(jobFixture({ id: 'job-d' }))),
    );
    await renderRoute(path);
    await userEvent.click(await screen.findByRole('button', { name: 'Review the new fingerprint' }));
    const dialog = await screen.findByRole('dialog', { name: 'Accept the new server fingerprint' });
    const keep = within(dialog).getByRole('button', { name: 'The server still shows the previous fingerprint' });
    expect(keep).toBeDisabled();
    await userEvent.type(within(dialog).getByLabelText(/^Reason/), 'Traffic was misrouted for an hour');
    await userEvent.click(keep);
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Accept the new server fingerprint' })).not.toBeInTheDocument());
    expect(repinned).toBe(pinned.id);
    expect(body).toEqual({ fingerprint: pinned.fingerprint, reason: 'Traffic was misrouted for an hour' });
    expect(await screen.findByText('Connected')).toBeInTheDocument();
    expect(screen.queryByTestId('host-key-changed')).not.toBeInTheDocument();
  });

  it('offers to keep the previous fingerprint when no new one was recorded, and asks for a step-up', async () => {
    const target = targetWith({ status: 'host_key_changed' });
    onServer('admin', target);
    server.use(http.get('/api/v1/targets/:id/host-keys', () => HttpResponse.json({ items: [pinned] })));
    let attempts = 0;
    server.use(
      http.post('/api/v1/targets/:id/host-keys/:keyId/actions/repin', () => {
        attempts += 1;
        if (attempts === 1) return errorResponse(403, 'ALC-AUTH-0003', 'auth.stepup_required');
        return HttpResponse.json({ job_id: 'job-d', status_url: '/api/v1/jobs/job-d' }, { status: 202 });
      }),
      http.post('/api/v1/auth/stepup', () => HttpResponse.json(sessionFor('admin'))),
      http.get('/api/v1/jobs/:id', () => HttpResponse.json(jobFixture({ id: 'job-d' }))),
    );
    await renderRoute(path);
    await userEvent.click(await screen.findByRole('button', { name: 'Review the new fingerprint' }));
    const dialog = await screen.findByRole('dialog', { name: 'Accept the new server fingerprint' });
    expect(within(dialog).getByText('Alice has not recorded a new fingerprint for this server.')).toBeInTheDocument();
    expect(within(dialog).queryByRole('button', { name: 'Accept new fingerprint' })).not.toBeInTheDocument();
    await userEvent.type(within(dialog).getByLabelText(/^Reason/), 'Traffic was misrouted for an hour');
    await userEvent.click(within(dialog).getByRole('button', { name: 'The server still shows the previous fingerprint' }));
    const stepUp = await screen.findByRole('dialog', { name: "Confirm it's you" });
    await userEvent.type(within(stepUp).getByLabelText('6-digit code'), '123456');
    await userEvent.click(within(stepUp).getByRole('button', { name: 'Confirm' }));
    await waitFor(() => expect(attempts).toBe(2));
  });

  it('refreshes the server after a refused re-pin so a stale candidate disappears', async () => {
    const target = targetWith({ status: 'host_key_changed' });
    let hostKeyCalls = 0;
    onServer('admin', target);
    server.use(
      http.get('/api/v1/targets/:id/host-keys', () => {
        hostKeyCalls += 1;
        return HttpResponse.json({ items: [pinned, observed] });
      }),
      http.post('/api/v1/targets/:id/host-keys/:keyId/actions/repin', () => errorResponse(409, 'ALC-TGT-0003', 'target.host_key_stale')),
    );
    await renderRoute(path);
    await userEvent.click(await screen.findByRole('button', { name: 'Review the new fingerprint' }));
    const dialog = await screen.findByRole('dialog', { name: 'Accept the new server fingerprint' });
    const before = hostKeyCalls;
    await userEvent.type(within(dialog).getByLabelText(/^Reason/), 'CHG-2026-0412 reinstall');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Accept new fingerprint' }));
    await waitFor(() => expect(hostKeyCalls).toBeGreaterThan(before));
  });

  it('shows the confirmation card once a server that was being checked starts waiting for confirmation', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      let target = targetWith({ status: 'checking' });
      onServer('admin', target);
      server.use(
        http.get('/api/v1/targets/:id', () => HttpResponse.json(target)),
        http.get('/api/v1/targets/:id/host-keys', () =>
          HttpResponse.json({ items: target.status === 'pending_host_key' ? [hostKeyFixture({ status: 'observed', confirmed_at: null, confirmed_by_name: '' })] : [] }),
        ),
      );
      await renderRoute(path);
      await screen.findByTestId('target-status');
      expect(screen.queryByRole('heading', { name: 'Is this your server?' })).not.toBeInTheDocument();
      target = targetWith({ status: 'pending_host_key' });
      await vi.advanceTimersByTimeAsync(3_100);
      expect(await screen.findByRole('heading', { name: 'Is this your server?' })).toBeInTheDocument();
    } finally {
      vi.useRealTimers();
    }
  });

  it('keeps the new fingerprint on screen while the host keys are read again after the server moved on', async () => {
    let target = targetWith({ status: 'host_key_changed' });
    onServer('admin', target);
    let slow = false;
    server.use(
      http.get('/api/v1/targets/:id', () => HttpResponse.json(target)),
      http.get('/api/v1/targets/:id/host-keys', async () => {
        if (slow) await new Promise((r) => setTimeout(r, 400));
        return HttpResponse.json({ items: [pinned, observed] });
      }),
      http.post('/api/v1/targets/:id/host-keys/:keyId/actions/repin', () => {
        // The refusal comes with a server that is no longer in the changed state.
        target = targetWith({ status: 'checking' });
        slow = true;
        return errorResponse(409, 'ALC-TGT-0003', 'target.host_key_stale');
      }),
    );
    await renderRoute(path);
    await userEvent.click(await screen.findByRole('button', { name: 'Review the new fingerprint' }));
    const dialog = await screen.findByRole('dialog', { name: 'Accept the new server fingerprint' });
    await userEvent.type(within(dialog).getByLabelText(/^Reason/), 'CHG-2026-0412 reinstall');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Accept new fingerprint' }));
    await waitFor(() => expect(screen.getByTestId('target-status')).toHaveTextContent('Checking'));
    // While the host keys are being read for the new status the candidate stays and "no candidate" never shows.
    expect(within(dialog).getByTestId('repin-new-fingerprint')).toBeInTheDocument();
    expect(within(dialog).queryByText('Alice has not recorded a new fingerprint for this server.')).not.toBeInTheDocument();
  });

  it('refuses to remove Alice’s own key and says why', async () => {
    onServer('admin');
    server.use(http.post('/api/v1/ssh-keys/locations/:id/actions/remove', () => errorResponse(409, 'ALC-KEY-0001', 'sshkey.own_key_protected')));
    await renderRoute(path);
    const table = await screen.findByTestId('target-keys');
    await userEvent.click(within(table).getByRole('button', { name: 'Remove key from alice-svc' }));
    const dialog = await screen.findByRole('dialog', { name: 'Remove this key from the server?' });
    expect(within(dialog).getByText('Alice removes only this key from /var/lib/alice-svc/.ssh/authorized_keys. Other lines in the file stay as they are.')).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Remove key' }));
    expect(await within(dialog).findByText('Alice needs this key to connect to this server and will not remove it.')).toBeInTheDocument();
  });

  it('removes another key and refreshes the list', async () => {
    let keys = [keyLocationFixture(), ci, aliceKeyLocation];
    onServer('operator');
    let removed = '';
    server.use(
      http.get('/api/v1/targets/:id/ssh-keys', () => HttpResponse.json({ items: keys })),
      http.post('/api/v1/ssh-keys/locations/:id/actions/remove', async ({ params, request }) => {
        removed = String(params.id);
        expect(await request.json()).toEqual({ confirm_last_root_key: false });
        keys = keys.filter((k) => k.id !== removed);
        return HttpResponse.json({ job_id: 'job-x', status_url: '/api/v1/jobs/job-x' }, { status: 202 });
      }),
      http.get('/api/v1/jobs/:id', () => HttpResponse.json(jobFixture({ id: 'job-x', type: 'sshkey.remove' }))),
    );
    await renderRoute(path);
    const table = await screen.findByTestId('target-keys');
    const row = within(table).getByText('ci@build').closest('tr')!;
    await userEvent.click(within(row).getByRole('button', { name: 'Remove key from deploy' }));
    const dialog = await screen.findByRole('dialog', { name: 'Remove this key from the server?' });
    await userEvent.click(within(dialog).getByRole('button', { name: 'Remove key' }));
    await waitFor(() => expect(screen.queryByText('ci@build')).not.toBeInTheDocument());
    expect(removed).toBe(ci.id);
    expect(screen.getByText('deploy@laptop')).toBeInTheDocument();
  });

  it('shows why a connection test failed', async () => {
    onServer('operator');
    server.use(
      http.post('/api/v1/targets/:id/actions/test', () => HttpResponse.json({ job_id: 'job-t', status_url: '/api/v1/jobs/job-t' }, { status: 202 })),
      http.get('/api/v1/jobs/:id', () =>
        HttpResponse.json(jobFixture({ id: 'job-t', status: 'failed', error: { code: 'ALC-SSH-0001', reason: 'ssh.unreachable' } })),
      ),
    );
    await renderRoute(path);
    await userEvent.click(await screen.findByRole('button', { name: 'Test connection' }));
    expect(await screen.findByText(commonEn.errors.ssh.unreachable.title)).toBeInTheDocument();
  });

  it('removes the server after confirmation and returns to the list', async () => {
    onServer('admin');
    let deleted = '';
    server.use(
      http.delete('/api/v1/targets/:id', ({ params }) => {
        deleted = String(params.id);
        return new HttpResponse(null, { status: 204 });
      }),
      http.get('/api/v1/targets', () => HttpResponse.json({ items: [], next_cursor: null })),
    );
    const { router } = await renderRoute(path);
    await userEvent.click(await screen.findByRole('button', { name: 'Remove server' }));
    const dialog = await screen.findByRole('dialog', { name: 'Remove this server from Alice?' });
    expect(within(dialog).getByText('Alice forgets the server and its keys. Nothing is changed on the server.')).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Remove server' }));
    await waitFor(() => expect(router.state.location.pathname).toBe('/servers'));
    expect(deleted).toBe(targetFixture.id);
  });

  it('confirms the fingerprint of a server that is still waiting for it', async () => {
    onServer('admin', targetWith({ status: 'pending_host_key', last_discovery_at: null }), []);
    let body: unknown = null;
    server.use(
      http.get('/api/v1/targets/:id/host-keys', () => HttpResponse.json({ items: [observed] })),
      http.post('/api/v1/targets/:id/host-keys/:keyId/actions/confirm', async ({ request }) => {
        body = await request.json();
        return HttpResponse.json({ job_id: 'job-c', status_url: '/api/v1/jobs/job-c' }, { status: 202 });
      }),
      http.get('/api/v1/jobs/:id', () => HttpResponse.json(jobFixture({ id: 'job-c' }))),
    );
    await renderRoute(path);
    expect(await screen.findByRole('heading', { name: 'Is this your server?' })).toBeInTheDocument();
    expect(screen.getByTestId('host-key-fingerprint')).toHaveTextContent(observed.fingerprint);
    await userEvent.click(screen.getByRole('button', { name: 'Yes, this is my server' }));
    await waitFor(() => expect(body).toEqual({ fingerprint: observed.fingerprint }));
  });

  it('words the helper warnings with and without their parameters and never shows a raw placeholder', async () => {
    const warnings: Warning[] = [
      { code: 'unsupported_path', params: { user: 'old', path: '/data/keys' } },
      { code: 'unsupported_path', params: {} },
      { code: 'sshd_unreadable', params: {} },
      { code: 'sshd_unreadable', params: { user: 'deploy' } },
      { code: 'keys_managed_elsewhere', params: { user: 'ldapuser' } },
      { code: 'too_many_users', params: {} },
      { code: 'made_up_by_a_newer_helper', params: {} },
    ];
    onServer('operator', targetWith({ facts: { ...targetFixture.facts, warnings } }));
    await renderRoute(path);
    expect(await screen.findByText('Alice cannot read a key file at this path: /data/keys')).toBeInTheDocument();
    expect(screen.getByText('Alice cannot read a key file at one of the paths that the SSH server uses.')).toBeInTheDocument();
    expect(screen.getByText('Could not read the SSH server settings; only the default key files were checked.')).toBeInTheDocument();
    expect(screen.getByText('Could not read the SSH server settings for deploy; only the default key files were checked.')).toBeInTheDocument();
    expect(screen.getByText(/keys of ldapuser/)).toBeInTheDocument();
    expect(screen.getByText(/more user accounts than Alice lists/)).toBeInTheDocument();
    expect(screen.queryByText(/\{\{/)).not.toBeInTheDocument();
  });

  it('words the server-wide keys-managed-elsewhere warning without a user', async () => {
    onServer('operator', targetWith({ facts: { ...targetFixture.facts, warnings: [{ code: 'keys_managed_elsewhere', params: {} }] } }));
    await renderRoute(path);
    expect(
      await screen.findByText(
        'The SSH server also asks a program (AuthorizedKeysCommand) for keys, so the key files may not be the whole picture. Alice will not change keys here.',
      ),
    ).toBeInTheDocument();
    expect(screen.queryByText(/without its details/)).not.toBeInTheDocument();
    expect(screen.queryByText(/\{\{/)).not.toBeInTheDocument();
  });

  it('finishes a started task in React StrictMode', async () => {
    onServer('operator');
    server.use(
      http.post('/api/v1/targets/:id/actions/test', () => HttpResponse.json({ job_id: 'job-t', status_url: '/api/v1/jobs/job-t' }, { status: 202 })),
      http.get('/api/v1/jobs/:id', () => HttpResponse.json(jobFixture({ id: 'job-t' }))),
    );
    await renderRoute(path, { strict: true });
    await userEvent.click(await screen.findByRole('button', { name: 'Test connection' }));
    expect(await screen.findByText('Finished.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Test connection' })).toBeEnabled();
  });

  it('says when a started task is waiting for an administrator', async () => {
    onServer('operator');
    server.use(
      http.post('/api/v1/targets/:id/actions/test', () => HttpResponse.json({ job_id: 'job-t', status_url: '/api/v1/jobs/job-t' }, { status: 202 })),
      http.get('/api/v1/jobs/:id', () => HttpResponse.json(jobFixture({ id: 'job-t', status: 'blocked_license', error: null }))),
    );
    await renderRoute(path);
    await userEvent.click(await screen.findByRole('button', { name: 'Test connection' }));
    expect(await screen.findByText('This task is paused and waits for an administrator to run it.')).toBeInTheDocument();
    expect(screen.queryByText('Finished.')).not.toBeInTheDocument();
  });

  it('says when a started task was stopped without an error', async () => {
    onServer('operator');
    server.use(
      http.post('/api/v1/targets/:id/actions/test', () => HttpResponse.json({ job_id: 'job-t', status_url: '/api/v1/jobs/job-t' }, { status: 202 })),
      http.get('/api/v1/jobs/:id', () => HttpResponse.json(jobFixture({ id: 'job-t', status: 'dead', error: null }))),
    );
    await renderRoute(path);
    await userEvent.click(await screen.findByRole('button', { name: 'Test connection' }));
    expect(await screen.findByText('This task was stopped before it finished.')).toBeInTheDocument();
    expect(screen.queryByText('Finished.')).not.toBeInTheDocument();
  });

  it('shows a generic note with the code for warnings it cannot describe or that lack their details', async () => {
    const warnings: Warning[] = [
      { code: 'made_up_by_a_newer_helper', params: {} },
      { code: 'strict_modes', params: {} },
    ];
    onServer('operator', targetWith({ facts: { ...targetFixture.facts, warnings } }));
    await renderRoute(path);
    await screen.findByTestId('target-keys');
    expect(screen.getAllByText('Alice reported a note about this server that this version cannot describe.')).toHaveLength(1);
    expect(screen.getAllByText('Alice reported a note about this server without its details.')).toHaveLength(1);
    expect(screen.getByText('made_up_by_a_newer_helper')).toBeInTheDocument();
    expect(screen.getByText('strict_modes')).toBeInTheDocument();
    expect(screen.queryByText(/\{\{/)).not.toBeInTheDocument();
  });

  it('is shown in Turkish', async () => {
    onServer('admin', targetWith({ status: 'host_key_changed' }), undefined, 'tr');
    await renderRoute(path, { languages: ['tr-TR'] });
    expect(await screen.findByTestId('host-key-changed')).toHaveTextContent('Sunucunun kimliği değişti, bu yüzden Alice bu sunucudaki tüm işleri durdurdu.');
    expect(screen.getByRole('button', { name: 'Yeni parmak izini incele' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Bu sunucudaki SSH anahtarları' })).toBeInTheDocument();
  });

  describe('the scan action and facts of each server type', () => {
    function nginxServer(role: 'admin' | 'operator' | 'auditor', target: Target = nginxTargetFixture, lang = 'en') {
      onServer(role, target, [], lang);
      server.use(http.get('/api/v1/targets/:id/certificate-locations', () => HttpResponse.json({ items: [locationFixture()], truncated: false })));
    }

    it('labels the scan action Discover on an Nginx server and keeps "Scan for SSH keys" on a Linux server', async () => {
      nginxServer('operator');
      const view = await renderRoute(`/servers/${nginxTargetFixture.id}`);
      expect(await screen.findByRole('button', { name: 'Discover' })).toBeInTheDocument();
      expect(screen.queryByRole('button', { name: 'Scan for SSH keys' })).not.toBeInTheDocument();
      expect(screen.getByText('Nginx server')).toBeInTheDocument();
      view.unmount();
      onServer('operator');
      await renderRoute(path);
      expect(await screen.findByRole('button', { name: 'Scan for SSH keys' })).toBeInTheDocument();
      expect(screen.queryByRole('button', { name: 'Discover' })).not.toBeInTheDocument();
      expect(screen.queryByRole('heading', { name: 'Websites on this server' })).not.toBeInTheDocument();
    });

    it('labels them "Keşfet" and "SSH anahtarlarını tara" in Turkish', async () => {
      nginxServer('admin', nginxTargetFixture, 'tr');
      const view = await renderRoute(`/servers/${nginxTargetFixture.id}`, { languages: ['tr-TR'] });
      expect(await screen.findByRole('button', { name: 'Keşfet' })).toBeInTheDocument();
      view.unmount();
      onServer('admin', targetFixture, [], 'tr');
      await renderRoute(path, { languages: ['tr-TR'] });
      expect(await screen.findByRole('button', { name: 'SSH anahtarlarını tara' })).toBeInTheDocument();
    });

    it('shows the Nginx version and the websites above the SSH keys', async () => {
      nginxServer('operator');
      await renderRoute(`/servers/${nginxTargetFixture.id}`);
      expect(await screen.findByText('Nginx version: 1.24.0')).toBeInTheDocument();
      const websites = screen.getByRole('heading', { name: 'Websites on this server' });
      const keys = screen.getByRole('heading', { name: 'SSH keys on this server' });
      expect(websites.compareDocumentPosition(keys) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    });

    it('shows no Nginx facts that the server never reported', async () => {
      nginxServer('operator', nginxTargetWith({}, { nginx: undefined }));
      await renderRoute(`/servers/${nginxTargetFixture.id}`);
      await screen.findByRole('button', { name: 'Discover' });
      expect(screen.queryByText(/Nginx version/)).not.toBeInTheDocument();
    });

    it('marks the websites stale after a failed Discover', async () => {
      nginxServer('operator');
      server.use(
        http.post('/api/v1/targets/:id/actions/discover', () => HttpResponse.json({ job_id: 'job-d', status_url: '/api/v1/jobs/job-d' }, { status: 202 })),
        http.get('/api/v1/jobs/:id', () =>
          HttpResponse.json(jobFixture({ id: 'job-d', status: 'failed', error: { code: 'ALC-NGX-0002', reason: 'nginx.config_invalid' } })),
        ),
      );
      await renderRoute(`/servers/${nginxTargetFixture.id}`);
      await userEvent.click(await screen.findByRole('button', { name: 'Discover' }));
      const stale = await screen.findByTestId('stale-websites');
      expect(stale).toHaveTextContent('The last scan failed.');
      expect(screen.getByRole('button', { name: 'Deploy certificate: www.example.test' })).toBeDisabled();
    });

    it('lists the Nginx scan warnings in words', async () => {
      const warnings: Warning[] = [
        { code: 'stream_tls', params: {} },
        { code: 'config_file_writable', params: { path: '/etc/nginx/conf.d/w.conf' } },
        { code: 'locations_dropped', params: {} },
      ];
      nginxServer('operator', nginxTargetWith({}, { warnings, nginx: nginxFacts() }));
      await renderRoute(`/servers/${nginxTargetFixture.id}`);
      expect(await screen.findByText(/TLS in stream blocks is not supported in this version/)).toBeInTheDocument();
      expect(screen.getByText('An Nginx configuration file can be changed by users other than root: /etc/nginx/conf.d/w.conf')).toBeInTheDocument();
      expect(screen.getByText(/more websites than Alice lists/)).toBeInTheDocument();
    });
  });
});
