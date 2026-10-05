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
        error: { code: 'ALC-DEP-0005', reason: 'deployment.verify_unreachable', params: { port: '443' } },
        verify_failed: { code: 'ALC-DEP-0005', reason: 'deployment.verify_unreachable', params: { port: '443' } },
        failed_step: 'verify',
        steps: [...okSteps.slice(0, 6), stepFixture(7, 'verify', 'failed', { port: '443', reason: 'deployment.verify_unreachable' }), stepFixture(8, 'restore'), stepFixture(9, 'rollback_config_test'), stepFixture(10, 'rollback_reload'), stepFixture(11, 'verify_old')],
      }),
    );
    await renderRoute(`/deployments/${ID}`);
    expect(await screen.findByText('Your server was restored to its previous certificate.')).toBeInTheDocument();
    expect(within(headline()).getByText('Failed, restored')).toBeInTheDocument();
    const alerts = screen.getAllByRole('alert');
    expect(alerts[0]).toHaveTextContent(/443/);
    expect(alerts[0]).toHaveTextContent('ALC-DEP-0005');
    expect(screen.getByText('Verification result')).toBeInTheDocument();
    expect(screen.getByText('Failed at: Verify')).toBeInTheDocument();
    const list = screen.getByRole('list', { name: 'Steps' });
    expect(within(list).getByText('Verify the previous certificate').closest('li')).toHaveTextContent('Done');
    expect(screen.queryByText(/\{\{/)).not.toBeInTheDocument();
  });

  it.each([
    ['deployment.rollback_failed', 'ALC-DEP-0008', 'restore_failed', /backup of the previous files is on the server/, 'Alice cannot confirm which certificate the website serves. Manual action is needed.'],
    ['deployment.restored_unverified', 'ALC-DEP-0019', 'restored', /could not confirm that the website serves the previous certificate/, /The previous files are back, but Alice could not confirm/],
    ['deployment.rollback_file_changed', 'ALC-DEP-0020', 'restore_failed', /./, 'Alice cannot confirm which certificate the website serves. Manual action is needed.'],
  ])('shows the cause-specific text of %s, a headline that agrees with it, and the backup folder', async (reason, code, phase, cause, headlineText) => {
    show(
      deploymentDetailFixture({
        id: ID,
        status: 'rollback_failed',
        result: 'rollback_failed',
        phase: phase as DeploymentDetail['phase'],
        backup_dir: '/var/lib/alice-helper/backups/0192c000',
        helper_error: reason === 'deployment.rollback_file_changed' ? 'file_changed' : '',
        error: { code, reason },
        steps: [stepFixture(1, 'backup'), stepFixture(2, 'write_key'), stepFixture(3, 'write_cert'), stepFixture(4, 'config_test', 'failed', { error: 'key_mismatch' })],
        failed_step: 'config_test',
      }),
    );
    await renderRoute(`/deployments/${ID}`);
    expect(await screen.findByText(headlineText)).toBeInTheDocument();
    expect(within(headline()).getByText('Outcome not confirmed')).toBeInTheDocument();
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
        error: { code: 'ALC-DEP-0007', reason: 'deployment.config_test_failed' },
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
        error: { code: 'ALC-SSH-0001', reason: 'ssh.unreachable' },
        finished_at: null,
        steps: [stepFixture(1, 'backup'), stepFixture(2, 'write_key')],
      }),
    );
    await renderRoute(`/deployments/${ID}`);
    expect(await screen.findByText('Alice has not yet confirmed how this deployment ended. It is checking the server and will finish or undo the change.')).toBeInTheDocument();
    expect(within(headline()).getByText('Needs attention')).toBeInTheDocument();
    expect(within(headline()).getByText('Confirming the outcome')).toBeInTheDocument();
    const recovery = screen.getByTestId('recovery');
    expect(recovery).toHaveTextContent('Recovery attempts: 4');
    expect(recovery).toHaveTextContent(/Next attempt after: .*Oct 4, 2026/);
    expect(recovery).toHaveTextContent('Alice still cannot confirm the outcome after several attempts and keeps trying.');
    expect(screen.getByRole('alert')).toHaveTextContent('ALC-SSH-0001');
    // Steps not reached yet are waiting, not "not run": the deployment is not over.
    expect(within(screen.getByRole('list', { name: 'Steps' })).getByText('Reload').closest('li')).toHaveTextContent('Waiting');
  });

  it('shows the recovery of a deployment whose code is ALC-DEP-0010 the same way', async () => {
    show(
      deploymentDetailFixture({ id: ID, status: 'running', state: 'recovering', job_status: 'succeeded', recovery_attempts: 1, error: { code: 'ALC-DEP-0010', reason: 'deployment.interrupted' }, finished_at: null }),
    );
    await renderRoute(`/deployments/${ID}`);
    expect(await screen.findByText('Alice has not yet confirmed how this deployment ended. It is checking the server and will finish or undo the change.')).toBeInTheDocument();
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

  it('shows a sent deployment that is being recovered as recovering, not on hold, although its original job is held (C-I1)', async () => {
    show(deploymentDetailFixture({ id: ID, status: 'running', state: 'recovering', job_status: 'blocked_license', recovery_attempts: 1, recover_after: '2026-10-02T10:15:00Z', finished_at: null }));
    await renderRoute(`/deployments/${ID}`);
    expect(await screen.findByText(/Alice has not yet confirmed how this deployment ended/)).toBeInTheDocument();
    expect(screen.queryByText(/The license has expired, so this deployment is on hold/)).not.toBeInTheDocument();
    expect(within(headline()).queryByText('On hold for the license')).not.toBeInTheDocument();
    expect(screen.getByTestId('recovery')).toBeInTheDocument();
  });

  it('shows a deployment an administrator cancelled as Cancelled, with the reason as information', async () => {
    show(deploymentDetailFixture({ id: ID, status: 'failed', error: { code: 'ALC-DEP-0022', reason: 'deployment.cancelled' }, steps: [] }));
    await renderRoute(`/deployments/${ID}`);
    expect(await screen.findByTestId('deployment-status')).toHaveTextContent('Cancelled');
    expect(screen.getByText('An administrator cancelled this deployment before anything was sent to the server.')).toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expectNoRawKeys();
  });

  it('shows the step that undid an unfinished earlier change, with its end and the change it names', async () => {
    const op = '0192c000-0000-7000-8000-00000000abcd';
    show(
      deploymentDetailFixture({
        id: ID,
        status: 'failed',
        backup_dir: '/var/lib/alice-helper/backups/own',
        failed_step: 'recover_pending',
        error: { code: 'ALC-DEP-0023', reason: 'deployment.server_operation_pending', params: { operation_id: op } },
        steps: [stepFixture(1, 'verify_current'), stepFixture(2, 'recover_pending', 'started', { operation_id: op }), stepFixture(3, 'recover_pending', 'failed', { operation_id: op })],
      }),
    );
    await renderRoute(`/deployments/${ID}`);
    const list = await screen.findByRole('list', { name: 'Steps' });
    // Not "nothing was changed": an unfinished restore attempt may have put back one of the files.
    expect(screen.getByText('The new certificate was not written. An unfinished earlier change on the server blocks these files; see below.')).toBeInTheDocument();
    expect(screen.queryByText('Nothing was changed on the server.')).not.toBeInTheDocument();
    const row = within(list).getByText('Undo an unfinished earlier change').closest('li') as HTMLElement;
    expect(row).toHaveAttribute('data-status', 'failed');
    expect(row).toHaveTextContent('The unfinished earlier change still blocks these files.');
    expect(within(row).getByText(op)).toHaveAttribute('translate', 'no');
    // The change on the server is named apart from this deployment's own backup folder.
    expect(within(screen.getByRole('alert')).getByText(op)).toBeInTheDocument();
    expect(screen.getByText(/Backup on the server/)).toHaveTextContent('/var/lib/alice-helper/backups/own');
    expect(screen.getByText(/Backup on the server/)).not.toHaveTextContent(op);
    expect(screen.getByText("Failed at: Undo an unfinished earlier change")).toBeInTheDocument();
    expectNoRawKeys();
  });

  it.each([
    ['ok', 'Alice put back the files from before the unfinished earlier change.'],
    ['skipped', 'There was nothing to put back.'],
  ] as const)('says how the undo step ended: %s', async (status, text) => {
    show(deploymentDetailFixture({ id: ID, steps: [stepFixture(1, 'recover_pending', 'started'), stepFixture(2, 'recover_pending', status, { operation_id: '0192c000-0000-7000-8000-00000000abcd' }), ...okSteps.slice(1).map((s, i) => ({ ...s, n: i + 3 }))] }));
    await renderRoute(`/deployments/${ID}`);
    expect(await screen.findByText(text)).toBeInTheDocument();
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
    show(deploymentDetailFixture({ id: ID, status: 'failed', error: { code: 'ALC-DEP-0999', reason: 'deployment.from_the_future' } })); // not in the error table, on purpose
    const view = await renderRoute(`/deployments/${ID}`);
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('Something went wrong.');
    expect(alert).toHaveTextContent('ALC-DEP-0999');
    view.unmount();
    // verify_unreachable needs params.port: without it the text would show {{port}}.
    show(deploymentDetailFixture({ id: ID, status: 'rolled_back', error: { code: 'ALC-DEP-0005', reason: 'deployment.verify_unreachable' } }));
    await renderRoute(`/deployments/${ID}`);
    expect((await screen.findAllByRole('alert'))[0]).not.toHaveTextContent(/\{\{/);
  });

  it('says a finished deployment that went through recovery was confirmed after N attempts, and not that recovery goes on', async () => {
    show(deploymentDetailFixture({ id: ID, status: 'succeeded', state: 'done', recovery_attempts: 3, recover_after: '2026-10-04T13:15:00Z' }));
    await renderRoute(`/deployments/${ID}`);
    const card = await screen.findByTestId('recovery');
    expect(card).toHaveTextContent('Alice confirmed the outcome after 3 recovery attempts.');
    expect(card).not.toHaveTextContent('Next attempt');
    expect(card).not.toHaveTextContent('keeps trying');
    expect(card).not.toHaveTextContent('Alice is checking the server');
  });

  it('says recovery ended, not that the outcome was confirmed, when a deployment gave up', async () => {
    show(deploymentDetailFixture({ id: ID, status: 'rollback_failed', phase: 'restore_failed', recovery_attempts: 5, error: { code: 'ALC-DEP-0017', reason: 'deployment.recovery_exhausted' } }));
    await renderRoute(`/deployments/${ID}`);
    const card = await screen.findByTestId('recovery');
    expect(card).toHaveTextContent('Recovery ended after 5 attempts.');
    expect(card).not.toHaveTextContent('confirmed');
  });

  it('shows no recovery card for a finished deployment that never needed one', async () => {
    show(deploymentDetailFixture({ id: ID, recovery_attempts: 0 }));
    await renderRoute(`/deployments/${ID}`);
    await screen.findByTestId('deployment-status');
    expect(screen.queryByTestId('recovery')).not.toBeInTheDocument();
  });

  it('says "no change needed" for an unchanged deployment and "nothing was changed" for a failed one', async () => {
    show(deploymentDetailFixture({ id: ID, status: 'unchanged', result: 'unchanged' }));
    const view = await renderRoute(`/deployments/${ID}`);
    expect(await screen.findByText('This certificate was already in place. Nothing was changed.')).toBeInTheDocument();
    expect(within(headline()).getByText('No change needed')).toBeInTheDocument();
    view.unmount();
    show(deploymentDetailFixture({ id: ID, status: 'failed', error: { code: 'ALC-DEP-0007', reason: 'deployment.config_test_failed' } }));
    await renderRoute(`/deployments/${ID}`);
    expect(await screen.findByText('Nothing was changed on the server.')).toBeInTheDocument();
    expect(within(headline()).getByText('Failed, nothing changed')).toBeInTheDocument();
  });

  it('shows a deployment whose job ended while the record is not final as stopped, and a finished job with a running record as being finished', async () => {
    show(deploymentDetailFixture({ id: ID, status: 'running', state: 'deploying', job_status: 'dead', finished_at: null }));
    const view = await renderRoute(`/deployments/${ID}`);
    expect(await screen.findByText(/The background job ended before the deployment did/)).toBeInTheDocument();
    view.unmount();
    show(deploymentDetailFixture({ id: ID, status: 'running', state: 'deploying', job_status: 'succeeded', finished_at: null }));
    await renderRoute(`/deployments/${ID}`);
    expect(await screen.findByText('The background job has finished. Alice is recording the result.')).toBeInTheDocument();
    expect(screen.queryByText('Alice is deploying the certificate…')).not.toBeInTheDocument();
  });

  describe('following a deployment that can still change', () => {
    beforeEach(() => vi.useFakeTimers({ shouldAdvanceTime: true }));
    afterEach(() => vi.useRealTimers());

    it('polls a running deployment, shows the steps as they arrive and stops when it is settled', async () => {
      let polls = 0;
      let current = deploymentDetailFixture({ id: ID, status: 'running', state: 'deploying', job_status: 'running', finished_at: null, steps: [stepFixture(1, 'backup')] });
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

    it('keeps reading a stopped deployment slowly and gives up after a while', async () => {
      let polls = 0;
      server.use(
        ...sessionHandlers(sessionFor('operator')),
        http.get(`/api/v1/deployments/${ID}`, () => ((polls += 1), HttpResponse.json(deploymentDetailFixture({ id: ID, status: 'running', state: 'deploying', job_status: 'dead', finished_at: null })))),
      );
      await renderRoute(`/deployments/${ID}`);
      await screen.findByText(/The background job ended before the deployment did/);
      await vi.advanceTimersByTimeAsync(60_000);
      expect(polls).toBeGreaterThanOrEqual(4);
      expect(polls).toBeLessThanOrEqual(6);
      await vi.advanceTimersByTimeAsync(600_000);
      const seen = polls;
      await vi.advanceTimersByTimeAsync(120_000);
      expect(polls).toBe(seen);
      expect(seen).toBeLessThanOrEqual(25);
    });

    it('keeps the last state while a read fails and carries on', async () => {
      let polls = 0;
      server.use(
        ...sessionHandlers(sessionFor('operator')),
        http.get(`/api/v1/deployments/${ID}`, () => {
          polls += 1;
          if (polls === 2) return HttpResponse.error();
          return HttpResponse.json(deploymentDetailFixture({ id: ID, status: polls < 3 ? 'running' : 'succeeded', state: polls < 3 ? 'deploying' : 'done', job_status: polls < 3 ? 'running' : 'succeeded', finished_at: null }));
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
    server.use(...sessionHandlers(sessionFor('operator')), http.get(`/api/v1/deployments/${ID}`, () => errorResponse(404, 'ALC-SYS-0001', 'system.not_found')));
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

describe('DeploymentDetailPage from Key Vault', () => {
  it('shows the kv_secret step first, the vault and the version; an upload shows neither', async () => {
    server.use(
      ...sessionHandlers(sessionFor('auditor')),
      http.get('/api/v1/deployments/dv', () =>
        HttpResponse.json(
          deploymentDetailFixture({
            id: 'dv',
            source: 'key_vault',
            vault_name: 'Prod vault',
            kv_version: '0123456789abcdef0123456789abcdef',
            steps: [stepFixture(1, 'verify_current'), stepFixture(2, 'kv_secret'), stepFixture(3, 'backup')],
          }),
        ),
      ),
      http.get('/api/v1/deployments/du', () => HttpResponse.json(deploymentDetailFixture({ id: 'du', steps: [stepFixture(1, 'backup')] }))),
    );
    const view = await renderRoute('/deployments/dv');
    const list = await screen.findByRole('list', { name: 'Steps' });
    const names = within(list).getAllByRole('listitem').map((li) => li.getAttribute('data-step'));
    expect(names.slice(0, 2)).toEqual(['verify_current', 'kv_secret']);
    expect(within(list).getByText('Read the certificate from Key Vault')).toBeInTheDocument();
    expect(screen.getByText('Prod vault')).toBeInTheDocument();
    expect(screen.getByText('0123456789abcdef0123456789abcdef').tagName).toBe('CODE');
    expect(screen.getByText('From Key Vault')).toBeInTheDocument();
    view.unmount();
    await renderRoute('/deployments/du');
    const plain = await screen.findByRole('list', { name: 'Steps' });
    expect(within(plain).queryByText('Read the certificate from Key Vault')).not.toBeInTheDocument();
  });

  it('names the failed kv_secret step with the missing role in the error', async () => {
    server.use(
      ...sessionHandlers(sessionFor('auditor')),
      http.get('/api/v1/deployments/dk', () =>
        HttpResponse.json(
          deploymentDetailFixture({
            id: 'dk',
            source: 'key_vault',
            vault_name: 'Prod vault',
            status: 'failed',
            result: '',
            failed_step: 'kv_secret',
            error: { code: 'ALC-AKV-0003', reason: 'azure.forbidden', params: { role: 'Key Vault Secrets User' } },
            steps: [stepFixture(1, 'kv_secret', 'failed')],
          }),
        ),
      ),
    );
    await renderRoute('/deployments/dk');
    expect(await screen.findByText('Missing permission in the vault')).toBeInTheDocument();
    expect(screen.getByText('Read the certificate from Key Vault', { selector: 'span, p' })).toBeInTheDocument();
  });
});
