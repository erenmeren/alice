import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import type { KeyFiles } from '../api/sshkeys';
import { errorResponse, jobFixture, nginxTargetFixture, operatorSession, sessionHandlers, targetFixture, vaultFixture } from '../test/fixtures';
import { expectNoRawKeys } from '../test/i18nAssert';
import { renderApp } from '../test/render';
import { server } from '../test/server';
import { DeployKeyDialog } from './DeployKeyDialog';

const pending = { ...targetFixture, id: 'p-1', name: 'pending-01', status: 'pending_host_key' as const };
const FILES: KeyFiles = {
  items: [
    { os_user: 'deploy', files: ['/home/deploy/.ssh/authorized_keys', '/home/deploy/.ssh/authorized_keys2'], default_file: '/home/deploy/.ssh/authorized_keys' },
    { os_user: 'alice-svc', files: ['/var/lib/alice-svc/.ssh/authorized_keys'], default_file: '/var/lib/alice-svc/.ssh/authorized_keys' },
    { os_user: 'ops', files: ['/home/ops/.ssh/authorized_keys', '/var/lib/alice-svc/.ssh/authorized_keys'], default_file: '/home/ops/.ssh/authorized_keys' },
  ],
  scanned_at: '2026-10-01T08:00:00Z',
};

function world(files: KeyFiles = FILES) {
  server.use(
    ...sessionHandlers(operatorSession),
    http.get('/api/v1/targets', () => HttpResponse.json({ items: [pending, vaultFixture, targetFixture, nginxTargetFixture], next_cursor: null })),
    http.get('/api/v1/targets/:id/key-files', () => HttpResponse.json(files)),
  );
}

function deployReturns(job: Parameters<typeof jobFixture>[0]) {
  const bodies: unknown[] = [];
  server.use(
    http.post('/api/v1/ssh-keys/:id/actions/deploy', async ({ request }) => {
      bodies.push(await request.json());
      return HttpResponse.json({ job_id: 'job-d', status_url: '/api/v1/jobs/job-d' }, { status: 202 });
    }),
    http.get('/api/v1/jobs/:id', () => HttpResponse.json(jobFixture({ id: 'job-d', type: 'sshkey.add', ...job }))),
  );
  return bodies;
}

const open = () => renderApp(<DeployKeyDialog keyId="k1" opened onClose={() => {}} />);

describe('DeployKeyDialog', () => {
  it('offers only servers that are ready, and the users and files from the key-files answer', async () => {
    world();
    await open();
    const server_ = await screen.findByLabelText('Server');
    await waitFor(() => expect(within(server_).getAllByRole('option').map((o) => o.textContent)).toEqual(['web-01', 'web-nginx']));
    const user = await screen.findByLabelText('User on the server');
    expect(within(user).getAllByRole('option').map((o) => o.textContent)).toEqual(['deploy', 'ops']);
    expect(screen.queryByRole('option', { name: 'alice-svc' })).not.toBeInTheDocument();
    const file = screen.getByLabelText('File');
    expect(within(file).getAllByRole('option').map((o) => o.textContent)).toEqual(['/home/deploy/.ssh/authorized_keys', '/home/deploy/.ssh/authorized_keys2']);
    expect(file).toHaveValue('/home/deploy/.ssh/authorized_keys');
    expectNoRawKeys();
  });

  it('never offers a file of the connection account, not even under another user', async () => {
    world();
    await open();
    const user = await screen.findByLabelText('User on the server');
    await waitFor(() => expect(within(user).getAllByRole('option')).toHaveLength(2));
    await userEvent.selectOptions(user, 'ops');
    const file = screen.getByLabelText('File');
    expect(within(file).getAllByRole('option').map((o) => o.textContent)).toEqual(['/home/ops/.ssh/authorized_keys']);
  });

  it('says so and disables Deploy when there is no key file to offer', async () => {
    world({ items: [], scanned_at: null });
    await open();
    expect(await screen.findByText("Alice has not found this user's key files yet. Scan the server, then try again.")).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Deploy' })).toBeDisabled();
  });

  it('says so when no server is ready', async () => {
    server.use(...sessionHandlers(operatorSession), http.get('/api/v1/targets', () => HttpResponse.json({ items: [pending, vaultFixture], next_cursor: null })));
    await open();
    expect(await screen.findByText(/Alice has no server it can deploy to yet/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Deploy' })).toBeDisabled();
  });

  it('sends the options as typed and reports a verified login', async () => {
    world();
    const bodies = deployReturns({ result: { result: 'verified', note: '' } });
    await open();
    await userEvent.type(await screen.findByLabelText('Allowed source addresses (optional)'), '10.0.0.0/8, 192.168.1.5');
    await userEvent.click(screen.getByRole('checkbox', { name: 'Allow sign-in only (no forwarding)' }));
    await waitFor(() => expect(screen.getByLabelText('File')).toHaveValue('/home/deploy/.ssh/authorized_keys'));
    await userEvent.click(screen.getByRole('button', { name: 'Deploy' }));
    expect(await screen.findByText('Alice added the key and verified a login with it.')).toBeInTheDocument();
    expect(bodies).toEqual([
      { target_id: targetFixture.id, os_user: 'deploy', file_path: '/home/deploy/.ssh/authorized_keys', from: '10.0.0.0/8, 192.168.1.5', restrict: true },
    ]);
  });

  it('sends neither option when they are left alone', async () => {
    world();
    const bodies = deployReturns({ result: { result: 'already_present' } });
    await open();
    await userEvent.click(await screen.findByRole('button', { name: 'Deploy' }));
    expect(await screen.findByText('The key was already on the server.')).toBeInTheDocument();
    expect(bodies).toEqual([{ target_id: targetFixture.id, os_user: 'deploy', file_path: '/home/deploy/.ssh/authorized_keys' }]);
  });

  it('shows the title of the error of a failed job', async () => {
    world();
    deployReturns({ status: 'failed', error: { code: 'ALC-KEY-0005', reason: 'sshkey.verify_failed' } });
    await open();
    await userEvent.click(await screen.findByRole('button', { name: 'Deploy' }));
    expect(await screen.findByText('Alice changed the key file but could not confirm the result.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Deploy' })).toBeEnabled();
  });

  it('shows what the server refused for the request itself', async () => {
    world();
    server.use(http.post('/api/v1/ssh-keys/:id/actions/deploy', () => errorResponse(422, 'ALC-SYS-0006', 'validation.failed', { details: [{ field: 'from', code: 'validation.required' }] })));
    await open();
    await userEvent.click(await screen.findByRole('button', { name: 'Deploy' }));
    expect(await screen.findByText('This field is required.')).toBeInTheDocument();
  });

  it('renders hostile user and file names as text', async () => {
    const evil = '<img src=x onerror=alert(1)>';
    world({ items: [{ os_user: evil, files: ['/tmp/<b>x</b>'], default_file: '/tmp/<b>x</b>' }], scanned_at: null });
    await open();
    const user = await screen.findByLabelText('User on the server');
    expect(await within(user).findByRole('option', { name: evil })).toBeInTheDocument();
    expect(document.querySelector('img[src="x"]')).toBeNull();
  });
});
