import { screen, waitFor, within } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import type { DeploymentDetail } from '../api/types';
import { deploymentDetailFixture, errorResponse, sessionFor, sessionHandlers, stepFixture } from '../test/fixtures';
import { expectNoRawKeys } from '../test/i18nAssert';
import { renderRoute } from '../test/render';
import { server } from '../test/server';

const ID = '0192c000-0000-7000-8000-0000000000d1';

const okSteps = [stepFixture(1, 'verify_current'), stepFixture(2, 'backup'), stepFixture(3, 'write_key'), stepFixture(4, 'write_cert'), stepFixture(5, 'config_test'), stepFixture(6, 'reload'), stepFixture(7, 'verify', 'ok', { mode: 'remote' })];

function show(d: DeploymentDetail, role: 'admin' | 'operator' | 'auditor' = 'auditor', lang = 'en') {
  server.use(...sessionHandlers(sessionFor(role, lang)), http.get(`/api/v1/deployments/${ID}`, () => HttpResponse.json(d)));
}

const headline = () => screen.getByTestId('deployment-headline');

describe('DeploymentDetailPage', () => {
  it('shows a successful deployment: status and state first, the steps with the pre-check, who, files and fingerprints', async () => {
    show(deploymentDetailFixture({ id: ID, steps: okSteps }));
    await renderRoute(`/deployments/${ID}`);
    expect(await screen.findByRole('heading', { name: 'Deployment', level: 1 })).toBeInTheDocument();
    expect(within(headline()).getByText('Succeeded')).toBeInTheDocument();
    expect(within(headline()).getByText('Finished')).toBeInTheDocument();
    expect(screen.getByText('The new certificate is live and verified.')).toBeInTheDocument();
    const list = screen.getByRole('list', { name: 'Steps' });
    const items = within(list).getAllByRole('listitem');
    expect(items[0]).toHaveTextContent('Check the current certificate');
    expect(items).toHaveLength(6);
    expect(within(list).getByText('Verify').closest('li')).toHaveTextContent('Done');
    expect(screen.getByText(/Requested by: Olcay Öztürk/)).toBeInTheDocument();
    expect(screen.getByText('Previous certificate:', { exact: false })).toHaveTextContent('cd34'.repeat(16));
    expect(screen.getByText('New certificate:', { exact: false })).toHaveTextContent('ab12'.repeat(16));
    expect(screen.getByText('/etc/nginx/ssl/www.crt')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'www.example.test' })).toHaveAttribute('href', expect.stringContaining('/certificates/'));
    expect(screen.queryByText(/Backup on the server/)).not.toBeInTheDocument();
    expectNoRawKeys();
  });

  it('shows a rollback with the failed step, the cause and the verification failure', async () => {
    show(
      deploymentDetailFixture({
        id: ID,
        status: 'rolled_back',
        result: 'rolled_back',
        verified: '',
        error: { code: 'ALC-DEP-0004', reason: 'deployment.verify_unreachable', params: { port: '443' } },
        verify_failed: { code: 'ALC-DEP-0004', reason: 'deployment.verify_unreachable', params: { port: '443' } },
        failed_step: 'verify',
        steps: [...okSteps.slice(0, 6), stepFixture(7, 'verify', 'failed', { port: '443', reason: 'deployment.verify_unreachable' }), stepFixture(8, 'restore'), stepFixture(9, 'rollback_config_test'), stepFixture(10, 'rollback_reload'), stepFixture(11, 'verify_old')],
      }),
    );
    await renderRoute(`/deployments/${ID}`);
    expect(await screen.findByText('Your server was restored to its previous certificate.')).toBeInTheDocument();
    expect(within(headline()).getByText('Failed, restored')).toBeInTheDocument();
    const alerts = screen.getAllByRole('alert');
    expect(alerts[0]).toHaveTextContent(/443/);
    expect(alerts[0]).toHaveTextContent('ALC-DEP-0004');
    expect(screen.getByText('Why the new certificate was rolled back')).toBeInTheDocument();
    expect(screen.getByText('Failed at: Verify')).toBeInTheDocument();
    const list = screen.getByRole('list', { name: 'Steps' });
    expect(within(list).getByText('Verify the previous certificate').closest('li')).toHaveTextContent('Done');
    expect(screen.queryByText(/\{\{/)).not.toBeInTheDocument();
  });

  it.each([
    ['deployment.rollback_failed', 'ALC-DEP-0008', /backup of the previous files is on the server/],
    ['deployment.restored_unverified', 'ALC-DEP-0019', /could not confirm that the website serves the previous certificate/],
    ['deployment.rollback_file_changed', 'ALC-DEP-0020', /./],
  ])('shows the cause-specific text of %s and the backup folder', async (reason, code, cause) => {
    show(
      deploymentDetailFixture({
        id: ID,
        status: 'rollback_failed',
        result: 'rollback_failed',
        backup_dir: '/var/lib/alice-helper/backups/0192c000',
        helper_error: reason === 'deployment.rollback_file_changed' ? 'file_changed' : '',
        error: { code, reason },
        steps: [stepFixture(1, 'backup'), stepFixture(2, 'write_key'), stepFixture(3, 'write_cert'), stepFixture(4, 'config_test', 'failed', { error: 'key_mismatch' })],
        failed_step: 'config_test',
      }),
    );
    await renderRoute(`/deployments/${ID}`);
    expect(await screen.findByText('Automatic restore failed. Manual action is needed.')).toBeInTheDocument();
    expect(within(headline()).getByText('Restore failed')).toBeInTheDocument();
    expect(screen.getByText('/var/lib/alice-helper/backups/0192c000')).toBeInTheDocument();
    expect(screen.getByText(/Backup on the server:/)).toBeInTheDocument();
    expect(screen.getByRole('alert')).toHaveTextContent(cause);
    expect(screen.getByRole('alert')).toHaveTextContent(code);
    expect(screen.getByText('Failed at: Check')).toBeInTheDocument();
  });

  it('shows the key mismatch class and the file-changed cause as technical detail', async () => {
    show(
      deploymentDetailFixture({
        id: ID,
        status: 'failed',
        error: { code: 'ALC-DEP-0005', reason: 'deployment.config_test_failed' },
        failed_step: 'config_test',
        helper_error: 'key_mismatch',
        steps: [stepFixture(1, 'backup'), stepFixture(2, 'config_test', 'failed', { error: 'key_mismatch' })],
      }),
    );
    await renderRoute(`/deployments/${ID}`);
    expect(await screen.findByText('Technical details')).toBeInTheDocument();
    expect(screen.getAllByText('Reason: The certificate and the private key do not belong together.').length).toBeGreaterThan(0);
  });

  it('shows a deployment that Alice is finishing after a lost connection with attempts, next attempt and the code as detail', async () => {
    show(
      deploymentDetailFixture({
        id: ID,
        status: 'needs_attention',
        state: 'recovering',
        recovery_attempts: 4,
        recover_after: '2026-10-04T13:15:00Z',
        error: { code: 'ALC-SSH-0003', reason: 'ssh.connection_lost' },
        finished_at: null,
        steps: [stepFixture(1, 'backup'), stepFixture(2, 'write_key')],
      }),
    );
    await renderRoute(`/deployments/${ID}`);
    expect(await screen.findByText('The connection to the server was lost. Alice will check the server and finish or undo the change.')).toBeInTheDocument();
    expect(within(headline()).getByText('Needs attention')).toBeInTheDocument();
    expect(within(headline()).getByText('Being finished after a lost connection')).toBeInTheDocument();
    const recovery = screen.getByTestId('recovery');
    expect(recovery).toHaveTextContent('Recovery attempts: 4');
    expect(recovery).toHaveTextContent(/Next attempt after: .*Oct 4, 2026/);
    expect(recovery).toHaveTextContent('Alice cannot reach the server and keeps trying.');
    expect(screen.getByRole('alert')).toHaveTextContent('ALC-SSH-0003');
    // Steps not reached yet are waiting, not "not run": the deployment is not over.
    expect(within(screen.getByRole('list', { name: 'Steps' })).getByText('Reload').closest('li')).toHaveTextContent('Waiting');
  });

  it('shows the recovery of a deployment whose code is ALC-DEP-0010 the same way', async () => {
    show(
      deploymentDetailFixture({ id: ID, status: 'running', state: 'recovering', recovery_attempts: 1, error: { code: 'ALC-DEP-0010', reason: 'deployment.outcome_unknown' }, finished_at: null }),
    );
    await renderRoute(`/deployments/${ID}`);
    expect(await screen.findByText('The connection to the server was lost. Alice will check the server and finish or undo the change.')).toBeInTheDocument();
    expect(screen.getByTestId('recovery')).toHaveTextContent('Alice is checking the server to finish or undo the change.');
    expect(screen.getByRole('alert')).toHaveTextContent('ALC-DEP-0010');
  });

  it('shows a deployment held by the license', async () => {
    show(deploymentDetailFixture({ id: ID, status: 'pending', state: 'queued', job_status: 'blocked_license', finished_at: null, started_at: null }));
    await renderRoute(`/deployments/${ID}`);
    expect(await screen.findByText(/The license has expired, so this deployment is on hold/)).toBeInTheDocument();
    expect(within(headline()).getByText('Waiting')).toBeInTheDocument();
    expect(within(headline()).getByText('On hold for the license')).toBeInTheDocument();
  });

  it('shows Unknown for a status, a state and a step status this version does not know', async () => {
    show(deploymentDetailFixture({ id: ID, status: '', state: '', steps: [{ ...stepFixture(1, 'backup'), status: '' }, stepFixture(2, 'made_up_step')], finished_at: null }));
    await renderRoute(`/deployments/${ID}`);
    await screen.findByTestId('deployment-status');
    expect(screen.getByTestId('deployment-status')).toHaveTextContent('Unknown');
    expect(screen.getByTestId('deployment-state')).toHaveTextContent('Unknown');
    const list = screen.getByRole('list', { name: 'Steps' });
    expect(within(list).getByText('Backup').closest('li')).toHaveTextContent('Unknown');
    expect(within(list).getByText('Other step').closest('li')).toHaveTextContent('made_up_step');
    expect(screen.getByText(/Alice cannot tell the state of this deployment/)).toBeInTheDocument();
    expectNoRawKeys();
  });

  it('shows a generic message with the code for a reason it has no text for, and never a raw placeholder', async () => {
    show(deploymentDetailFixture({ id: ID, status: 'failed', error: { code: 'ALC-DEP-0999', reason: 'deployment.from_the_future' } }));
    const view = await renderRoute(`/deployments/${ID}`);
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('Something went wrong.');
    expect(alert).toHaveTextContent('ALC-DEP-0999');
    view.unmount();
    // verify_unreachable needs params.port: without it the text would show {{port}}.
    show(deploymentDetailFixture({ id: ID, status: 'rolled_back', error: { code: 'ALC-DEP-0004', reason: 'deployment.verify_unreachable' } }));
    await renderRoute(`/deployments/${ID}`);
    expect((await screen.findAllByRole('alert'))[0]).not.toHaveTextContent(/\{\{/);
  });

  describe('following a deployment that can still change', () => {
    beforeEach(() => vi.useFakeTimers({ shouldAdvanceTime: true }));
    afterEach(() => vi.useRealTimers());

    it('polls a running deployment, shows the steps as they arrive and stops when it is settled', async () => {
      let polls = 0;
      let current = deploymentDetailFixture({ id: ID, status: 'running', state: 'deploying', finished_at: null, steps: [stepFixture(1, 'backup')] });
      server.use(...sessionHandlers(sessionFor('operator')), http.get(`/api/v1/deployments/${ID}`, () => ((polls += 1), HttpResponse.json(current))));
      await renderRoute(`/deployments/${ID}`);
      expect(await screen.findByText('Alice is deploying the certificate…')).toBeInTheDocument();
      expect(within(headline()).getByText('Running')).toBeInTheDocument();
      expect(within(headline()).getByText('Deploying')).toBeInTheDocument();
      current = deploymentDetailFixture({ id: ID, status: 'succeeded', state: 'done', steps: okSteps });
      await vi.advanceTimersByTimeAsync(2_100);
      expect(await screen.findByText('The new certificate is live and verified.')).toBeInTheDocument();
      const seen = polls;
      await vi.advanceTimersByTimeAsync(60_000);
      expect(polls).toBe(seen);
    });

    it('polls a deployment that is being recovered slowly and shows its end', async () => {
      let polls = 0;
      let current = deploymentDetailFixture({ id: ID, status: 'needs_attention', state: 'recovering', finished_at: null, recovery_attempts: 1 });
      server.use(...sessionHandlers(sessionFor('operator')), http.get(`/api/v1/deployments/${ID}`, () => ((polls += 1), HttpResponse.json(current))));
      await renderRoute(`/deployments/${ID}`);
      await screen.findByTestId('recovery');
      const first = polls;
      await vi.advanceTimersByTimeAsync(5_000);
      expect(polls).toBe(first);
      current = deploymentDetailFixture({ id: ID, status: 'rolled_back', state: 'done', error: { code: 'ALC-DEP-0006', reason: 'deployment.reload_failed' } });
      await vi.advanceTimersByTimeAsync(10_100);
      expect(await screen.findByText('Your server was restored to its previous certificate.')).toBeInTheDocument();
      expect(screen.queryByTestId('recovery')).not.toBeInTheDocument();
    });

    it('keeps the last state while a read fails and carries on', async () => {
      let polls = 0;
      server.use(
        ...sessionHandlers(sessionFor('operator')),
        http.get(`/api/v1/deployments/${ID}`, () => {
          polls += 1;
          if (polls === 2) return HttpResponse.error();
          return HttpResponse.json(deploymentDetailFixture({ id: ID, status: polls < 3 ? 'running' : 'succeeded', state: polls < 3 ? 'deploying' : 'done', finished_at: null }));
        }),
      );
      await renderRoute(`/deployments/${ID}`);
      await screen.findByText('Alice is deploying the certificate…');
      await vi.advanceTimersByTimeAsync(2_100);
      expect(screen.getByText('Alice is deploying the certificate…')).toBeInTheDocument();
      await vi.advanceTimersByTimeAsync(2_100);
      expect(await screen.findByText('The new certificate is live and verified.')).toBeInTheDocument();
    });
  });

  it('shows the server text and a way back for a deployment that does not exist', async () => {
    server.use(...sessionHandlers(sessionFor('operator')), http.get(`/api/v1/deployments/${ID}`, () => errorResponse(404, 'ALC-SYS-0002', 'system.not_found')));
    await renderRoute(`/deployments/${ID}`);
    expect(await screen.findByRole('alert')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Back to deployment history' })).toHaveAttribute('href', '/deployments');
  });

  it('is shown in Turkish', async () => {
    show(deploymentDetailFixture({ id: ID, status: 'rolled_back', error: { code: 'ALC-DEP-0006', reason: 'deployment.reload_failed' }, steps: okSteps.slice(0, 5) }), 'operator', 'tr');
    await renderRoute(`/deployments/${ID}`, { languages: ['tr-TR'] });
    expect(await screen.findByRole('heading', { name: 'Dağıtım', level: 1 })).toBeInTheDocument();
    expect(await screen.findByText('Sunucunuz önceki sertifikasına geri döndürüldü.')).toBeInTheDocument();
    await waitFor(() => expectNoRawKeys());
  });
});
