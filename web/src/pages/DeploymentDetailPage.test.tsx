import { screen, waitFor, within } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import type { DeploymentDetail } from '../api/types';
import { deploymentDetailFixture, errorResponse, rdpDeploymentFixture, sessionFor, sessionHandlers, stepFixture, WIN_PREVIOUS_SHA1, windowsDeploymentFixture } from '../test/fixtures';
import commonEn from '@locales/common/en.json';
import commonTr from '@locales/common/tr.json';
import enWeb from '../locales/en.json';
import trWeb from '../locales/tr.json';
import { goFiles, readRepoFile } from '../test/goSources';
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

  // R51: the operation details show the level the verification proved and what it found about the served chain.
  it('shows the evidence level and the trust of the served chain', async () => {
    show(
      deploymentDetailFixture({
        id: ID,
        steps: [...okSteps.slice(0, 6), stepFixture(7, 'verify', 'ok', { mode: 'remote', trust: 'trusted' })],
        verification: { level: 3, failure: '', trust: { status: 'trusted', error: '', port: null, store: 'acme_bundle', enforced: true } },
      }),
    );
    await renderRoute(`/deployments/${ID}`);
    expect(await screen.findByTestId('deployment-level')).toHaveTextContent('Trusted: the served chain verifies against a trusted root');
    expect(screen.getByTestId('deployment-trust')).toHaveTextContent("Trusted, checked against the certificate authority's CA bundle");
    expect(within(screen.getByRole('list', { name: 'Steps' })).getByText('Chain: Trusted')).toBeInTheDocument();
    expectNoRawKeys();
  });

  it('shows a deployment rolled back for an untrusted chain with the precise fault and the kind of failure', async () => {
    show(
      deploymentDetailFixture({
        id: ID,
        status: 'rolled_back',
        result: 'rolled_back',
        phase: 'restored',
        failed_step: 'verify',
        cause_step: 'verify',
        error: { code: 'ALC-DEP-0026', reason: 'deployment.verify_untrusted', params: { port: '443', trust_error: 'wrong_intermediate' } },
        steps: [...okSteps.slice(0, 6), stepFixture(7, 'verify', 'failed', { port: '443', reason: 'deployment.verify_untrusted', trust_error: 'wrong_intermediate' })],
        verification: { level: 0, failure: 'trust', trust: { status: 'untrusted', error: 'wrong_intermediate', port: 443, store: 'system', enforced: true } },
      }),
    );
    await renderRoute(`/deployments/${ID}`);
    expect(await screen.findByText('The website serves the new certificate, but its chain is not trusted (port 443).')).toBeInTheDocument();
    expect(screen.getByTestId('deployment-level')).toHaveTextContent('None');
    expect(screen.getByTestId('deployment-trust')).toHaveTextContent('Not trusted. No certificate the website sends after its own certificate issued it (a wrong intermediate certificate) (port 443)');
    expect(screen.getByTestId('deployment-failure')).toHaveTextContent("The website's certificate chain is not trusted.");
    expect(within(screen.getByRole('list', { name: 'Steps' })).getByText(/Chain fault: No certificate the website sends/)).toBeInTheDocument();
    expectNoRawKeys();
  });

  it('tells a network failure from a wrong certificate', async () => {
    show(
      deploymentDetailFixture({
        id: ID,
        status: 'rolled_back',
        error: { code: 'ALC-DEP-0005', reason: 'deployment.verify_unreachable', params: { port: '443' } },
        verification: { level: 0, failure: 'network', trust: null },
      }),
    );
    await renderRoute(`/deployments/${ID}`);
    expect(await screen.findByTestId('deployment-failure')).toHaveTextContent('Alice could not reach the website (a network problem, not a wrong certificate).');
    expect(screen.queryByTestId('deployment-trust')).not.toBeInTheDocument();
  });

  it('has the design layout: header with the way back and the status, the outcome notice, the sequence, operation details and evidence', async () => {
    show(
      deploymentDetailFixture({
        id: ID,
        backup_dir: '/var/lib/alice-helper/backups/0192c000',
        steps: [...okSteps.slice(0, 6), stepFixture(7, 'verify', 'ok', { mode: 'remote', served: 'ef56'.repeat(16) })],
      }),
    );
    await renderRoute(`/deployments/${ID}`);
    const h1 = await screen.findByRole('heading', { name: 'Deployment', level: 1 });
    const header = h1.closest('header') as HTMLElement;
    expect(within(header).getByTestId('deployment-status')).toHaveTextContent('Succeeded');
    expect(within(header).getByTestId('deployment-headline')).toHaveAttribute('aria-live', 'polite');
    expect(within(header).getByTestId('deployment-state')).toHaveTextContent('Finished');
    expect(screen.getByRole('link', { name: 'Back to deployment history' })).toHaveAttribute('href', '/deployments');
    // The outcome notice comes before the sequence.
    const notice = screen.getByText('The new certificate is live and verified.').closest('.mantine-Alert-root') as HTMLElement;
    const sequence = screen.getByRole('heading', { level: 2, name: 'Deployment sequence' });
    expect(notice.compareDocumentPosition(sequence) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    const seqPanel = sequence.closest('section') as HTMLElement;
    // The subtitle is true of every deployment, including one whose verification was skipped.
    expect(seqPanel).toHaveTextContent('Each step shows its own result. A step that did not run is never shown as done.');
    expect(within(seqPanel).getByRole('list', { name: 'Steps' })).toBeInTheDocument();
    // Operation details.
    const details = screen.getByRole('heading', { level: 2, name: 'Operation details' }).closest('section') as HTMLElement;
    const facts = within(details).getByLabelText('Operation details');
    expect(facts.tagName).toBe('DL');
    expect(within(facts).getByRole('link', { name: 'www.example.test' })).toHaveAttribute('href', `/certificates/${deploymentDetailFixture().certificate_id}`);
    expect(within(facts).getByRole('link', { name: 'web-01' })).toHaveAttribute('href', `/servers/${deploymentDetailFixture().target_id}`);
    expect(facts).toHaveTextContent('Requested by: Olcay Öztürk');
    expect(facts).toHaveTextContent('Uploaded');
    expect(facts).toHaveTextContent(/Started.*Oct 2, 2026/);
    expect(facts).toHaveTextContent('Checked from Alice');
    // Evidence: the fingerprints, what the website served and the backup folder, as data.
    const evidence = screen.getByRole('heading', { level: 2, name: 'Evidence' }).closest('section') as HTMLElement;
    expect(within(evidence).getByText('ab12'.repeat(16)).tagName).toBe('CODE');
    expect(within(evidence).getByText('cd34'.repeat(16)).tagName).toBe('CODE');
    expect(within(evidence).getByText('ef56'.repeat(16))).toHaveAttribute('translate', 'no');
    expect(within(evidence).getByText('/var/lib/alice-helper/backups/0192c000').tagName).toBe('CODE');
    expect(evidence).toHaveTextContent('Served certificate:');
    expectNoRawKeys();
  });

  it('does not claim a served certificate the verification did not report', async () => {
    show(deploymentDetailFixture({ id: ID, verified: 'skipped', steps: [...okSteps.slice(0, 6), stepFixture(7, 'verify', 'skipped', { mode: 'skipped' })] }));
    await renderRoute(`/deployments/${ID}`);
    const evidence = (await screen.findByRole('heading', { level: 2, name: 'Evidence' })).closest('section') as HTMLElement;
    expect(evidence).not.toHaveTextContent('Served certificate');
    expect(within(screen.getByLabelText('Operation details')).getByText('Skipped')).toBeInTheDocument();
    expect(screen.getByText('The new certificate was deployed and Nginx was reloaded.')).toBeInTheDocument();
    expect(screen.queryByText('The new certificate is live and verified.')).not.toBeInTheDocument();
    // Nothing on the page promises a verification that did not happen.
    expect(document.body).not.toHaveTextContent(/verified before/i);
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
    expect(await screen.findByRole('heading', { level: 2, name: 'Technical details' })).toBeInTheDocument();
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
    expect(within(recovery).getByRole('heading', { level: 2, name: 'Recovery' })).toBeInTheDocument();
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

  it('warns never to restore the backup of a deployment whose undo the rollback guard refused (R48)', async () => {
    show(
      deploymentDetailFixture({
        id: ID,
        status: 'rollback_failed',
        phase: 'restore_forbidden',
        failed_step: 'restore',
        backup_dir: '/var/lib/alice-helper/backups/own',
        error: { code: 'ALC-DEP-0025', reason: 'deployment.rollback_forbidden' },
      }),
    );
    await renderRoute(`/deployments/${ID}`);
    expect(await screen.findByText(/it holds the compromised key: never restore it/)).toBeInTheDocument();
    expect(screen.getByText(/Alice did not undo the failed change/)).toBeInTheDocument();
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

describe('DeploymentDetailPage of a canary deployment (R65)', () => {
  it('shows the observation, the round summary and the rollout panel', async () => {
    show(
      deploymentDetailFixture({
        id: ID,
        status: 'running',
        state: 'holding',
        finished_at: null,
        rollout: { id: 'r1', wave: 1, state: 'hold' },
        canary: { rounds: 3, passes: 3, consecutive_failures: 0, last_at: '2026-10-04T12:00:00Z', last_result: 'pass', last_reason: '', last_tls: 'pass', last_http_status: 200, last_latency_ms: 9, next_check_at: '2026-10-04T12:00:30Z' },
      }),
      'operator',
    );
    server.use(
      http.get('/api/v1/deployment-rollouts/r1', () =>
        HttpResponse.json({
          id: 'r1', state: 'hold', reason: '', reason_params: {}, origin: 'manual', certificate: null, service: null, policy_version: 1,
          settings: { count: 1, percent: 0, hold: '10m', interval: '30s', failures: 2, check: null, override_allowed: true },
          hold_started_at: '2026-10-04T12:00:00Z', hold_until: '2026-10-04T12:10:00Z', now: '2026-10-04T12:01:00Z',
          waves: [], skipped: [], allowed_actions: ['continue', 'abort'], hidden_count: 0, created_at: '2026-10-04T11:59:00Z', finished_at: null,
        }),
      ),
    );
    await renderRoute(`/deployments/${ID}`);
    expect(await screen.findByText('The new certificate is in place and verified; it is under observation before the other websites follow.')).toBeInTheDocument();
    expect(await screen.findByTestId('rollout-panel')).toBeInTheDocument();
    expect(screen.getByTestId('rollout-state')).toHaveTextContent('Observing the first wave');
    expect(screen.getByTestId('rollout-continue')).toBeInTheDocument();
    expectNoRawKeys();
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

  it('names a certificate ordered from a certificate authority as its source, not an upload', async () => {
    server.use(
      ...sessionHandlers(sessionFor('auditor')),
      http.get('/api/v1/deployments/da', () => HttpResponse.json(deploymentDetailFixture({ id: 'da', source: 'acme', steps: [stepFixture(1, 'backup')] }))),
    );
    await renderRoute('/deployments/da');
    expect(await screen.findByText('From a certificate authority (ACME)')).toBeInTheDocument();
    expect(screen.queryByText('Uploaded')).not.toBeInTheDocument();
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

// R61: a deployment to an http.sys binding of a Windows server.
describe('DeploymentDetailPage of a Windows binding', () => {
  const winSteps = (verify: Record<string, string> = { mode: 'remote' }) => [
    stepFixture(1, 'verify_current'),
    stepFixture(2, 'import_chain'),
    stepFixture(3, 'import_certificate'),
    stepFixture(4, 'bind'),
    stepFixture(5, 'verify', 'ok', verify),
  ];
  const stepIds = () =>
    Array.from(within(screen.getByRole('list', { name: /Steps|Adımlar/ })).getAllByRole('listitem')).map((i) => (i.closest('[data-step]') ?? i.querySelector('[data-step]'))?.getAttribute('data-step'));

  it('shows the Windows steps in their order, the binding, no key file and the previous certificate by store and thumbprint', async () => {
    show(windowsDeploymentFixture({ id: ID, steps: winSteps() }));
    await renderRoute(`/deployments/${ID}`);
    expect(await screen.findByText('The new certificate is live and verified.')).toBeInTheDocument();
    expect(stepIds()).toEqual(['verify_current', 'import_chain', 'import_certificate', 'bind', 'verify']);
    const items = within(screen.getByRole('list', { name: 'Steps' })).getAllByRole('listitem');
    expect(items[1]).toHaveTextContent('Import the chain');
    expect(items[2]).toHaveTextContent('Import the certificate');
    expect(items[3]).toHaveTextContent('Bind');
    expect(items[4]).toHaveTextContent('Verify');
    for (const i of items) expect(i).toHaveTextContent('Done');
    expect(screen.queryByText('Backup')).not.toBeInTheDocument();
    expect(screen.queryByText('Reload')).not.toBeInTheDocument();
    expect(screen.getByText('Binding', { selector: 'dt' }).nextElementSibling).toHaveTextContent('http.sys/hostnameport/www.example.test:443');
    expect(screen.queryByText('Key file', { selector: 'dt' })).not.toBeInTheDocument();
    expect(screen.queryByText('Certificate file', { selector: 'dt' })).not.toBeInTheDocument();
    expect(screen.getByText(`Previous certificate: My \\ ${WIN_PREVIOUS_SHA1}`)).toBeInTheDocument();
    expect(screen.queryByText(/Backup on the server/)).not.toBeInTheDocument();
    expect(screen.queryByTestId('win-chain-differs')).not.toBeInTheDocument();
    expectNoRawKeys();
  });

  it('notes a chain Windows serves with another length than Alice deployed, with both numbers', async () => {
    show(windowsDeploymentFixture({ id: ID, steps: winSteps({ mode: 'remote', chain_differs: 'true', deployed_chain: '3', built_chain: '2' }) }));
    await renderRoute(`/deployments/${ID}`);
    expect(await screen.findByTestId('win-chain-differs')).toHaveTextContent('Windows serves a chain of 2 certificates; Alice deployed 3.');
  });

  it('words a failed bind by its Windows error class', async () => {
    show(
      windowsDeploymentFixture({
        id: ID,
        status: 'rolled_back',
        result: 'rolled_back',
        phase: 'restored',
        verified: '',
        failed_step: 'bind',
        helper_error: 'key_unusable',
        error: { code: 'ALC-WIN-0009', reason: 'windows.key_unusable' },
        steps: [stepFixture(1, 'verify_current'), stepFixture(2, 'import_chain'), stepFixture(3, 'import_certificate'), stepFixture(4, 'bind', 'failed', { error: 'key_unusable' })],
      }),
    );
    await renderRoute(`/deployments/${ID}`);
    expect(await screen.findByText('Failed at: Bind')).toBeInTheDocument();
    expect(screen.getAllByText('Reason: Windows cannot use the private key of the certificate.')).toHaveLength(2);
    // The error's text names http.sys (a product name, not a key): the steps are checked.
    expectNoRawKeys(screen.getByRole('list', { name: 'Steps' }));
  });

  it('shows a failed rollback with the previous certificate by store and thumbprint, never the Linux backup folder', async () => {
    show(
      windowsDeploymentFixture({
        id: ID,
        status: 'rollback_failed',
        result: 'rollback_failed',
        phase: 'restore_failed',
        backup_store: 'WebHosting',
        failed_step: 'verify',
        error: { code: 'ALC-DEP-0008', reason: 'deployment.rollback_failed', params: { store: 'WebHosting', previous_sha1: WIN_PREVIOUS_SHA1 } },
        steps: [...winSteps().slice(0, 4), stepFixture(5, 'verify', 'failed'), stepFixture(6, 'restore', 'failed', { error: 'backup_missing' })],
      }),
    );
    await renderRoute(`/deployments/${ID}`);
    expect(await screen.findByText('Alice cannot confirm which certificate the website serves. Manual action is needed.')).toBeInTheDocument();
    const alert = screen.getByRole('alert');
    expect(alert).toHaveTextContent('pointing the binding back to the previous certificate');
    expect(alert).toHaveTextContent('ALC-DEP-0008');
    expect(alert).not.toHaveTextContent('/var/lib/alice-helper');
    expect(alert).not.toHaveTextContent(/nginx/i);
    expect(alert).not.toHaveTextContent(/files/);
    expect(screen.getByText(`Previous certificate: WebHosting \\ ${WIN_PREVIOUS_SHA1}`)).toBeInTheDocument();
    expect(screen.queryByText(/Backup on the server/)).not.toBeInTheDocument();
    expect(screen.getByText('Reason: The previous certificate or its private key is no longer in the certificate store.')).toBeInTheDocument();
    expectNoRawKeys();
  });

  it('names the previous certificate from the error when the deployment does not carry it', async () => {
    show(
      windowsDeploymentFixture({
        id: ID,
        status: 'rollback_failed',
        phase: 'restore_failed',
        backup_store: undefined,
        backup_sha1: undefined,
        error: { code: 'ALC-DEP-0008', reason: 'deployment.rollback_failed', params: { store: 'My', previous_sha1: WIN_PREVIOUS_SHA1 } },
      }),
    );
    await renderRoute(`/deployments/${ID}`);
    expect(await screen.findByText(`Previous certificate: My \\ ${WIN_PREVIOUS_SHA1}`)).toBeInTheDocument();
  });

  it('words the other rollback outcomes for a binding, not for files', async () => {
    show(
      windowsDeploymentFixture({
        id: ID,
        status: 'rollback_failed',
        phase: 'restored',
        error: { code: 'ALC-DEP-0019', reason: 'deployment.restored_unverified' },
      }),
    );
    const view = await renderRoute(`/deployments/${ID}`);
    expect(await screen.findByText(/The binding names the previous certificate again/)).toBeInTheDocument();
    expect(screen.getByRole('alert')).not.toHaveTextContent(/nginx|files/i);
    view.unmount();
    show(
      windowsDeploymentFixture({
        id: ID,
        status: 'rollback_failed',
        phase: 'restore_failed',
        helper_error: 'file_changed',
        error: { code: 'ALC-DEP-0020', reason: 'deployment.rollback_file_changed' },
      }),
    );
    await renderRoute(`/deployments/${ID}`);
    expect(await screen.findByRole('alert')).toHaveTextContent('another program changed the binding');
    expect(screen.getByRole('alert')).not.toHaveTextContent(/nginx|files|\/var\/lib/i);
    expect(screen.getByText('Reason: Another program changed the binding: it names a certificate Alice did not deploy.')).toBeInTheDocument();
  });

  it('keeps the rollback guard text of a refused undo (R48) and marks the previous certificate', async () => {
    show(
      windowsDeploymentFixture({
        id: ID,
        status: 'rollback_failed',
        phase: 'restore_forbidden',
        failed_step: 'restore',
        error: { code: 'ALC-DEP-0025', reason: 'deployment.rollback_forbidden', params: { store: 'My', previous_sha1: WIN_PREVIOUS_SHA1 } },
      }),
    );
    await renderRoute(`/deployments/${ID}`);
    expect(await screen.findByText(/Alice did not undo the failed change/)).toBeInTheDocument();
    expect(screen.getByRole('alert')).toHaveTextContent('The change failed, and Alice did not put the previous certificate back because it is revoked or compromised.');
    expect(screen.getByText(`Previous certificate (revoked or compromised: never bind it again): My \\ ${WIN_PREVIOUS_SHA1}`)).toBeInTheDocument();
  });

  it('is shown in Turkish', async () => {
    show(windowsDeploymentFixture({ id: ID, steps: winSteps({ mode: 'remote', chain_differs: 'true', deployed_chain: '3', built_chain: '2' }) }), 'operator', 'tr');
    await renderRoute(`/deployments/${ID}`, { languages: ['tr-TR'] });
    await screen.findByTestId('win-chain-differs');
    expect(stepIds()).toEqual(['verify_current', 'import_chain', 'import_certificate', 'bind', 'verify']);
    const items = within(screen.getByRole('list', { name: 'Adımlar' })).getAllByRole('listitem');
    expect(items[1]).toHaveTextContent('Zinciri içe aktarma');
    expect(items[2]).toHaveTextContent('Sertifikayı içe aktarma');
    expect(items[3]).toHaveTextContent('Bağlamayı güncelleme');
    expect(items[4]).toHaveTextContent('Doğrulama');
    expect(screen.getByText(`Önceki sertifika: My \\ ${WIN_PREVIOUS_SHA1}`)).toBeInTheDocument();
    expect(screen.getByTestId('win-chain-differs')).toHaveTextContent('Windows 2 sertifikalık bir zincir sunuyor; Alice 3 sertifika dağıttı.');
    await waitFor(() => expectNoRawKeys());
  });
});

describe('DeploymentDetailPage recognises a Windows deployment by its location kind', () => {
  it('words the binding and the previous certificate when location_kind is win_sslbinding', async () => {
    show(windowsDeploymentFixture({ id: ID }));
    await renderRoute(`/deployments/${ID}`);
    expect(await screen.findByText(`Previous certificate: My \\ ${WIN_PREVIOUS_SHA1}`)).toBeInTheDocument();
    expect(screen.getByText('Binding', { selector: 'dt' })).toBeInTheDocument();
  });

  it('does not take a backup_store without the kind, or an http.sys text, for Windows', async () => {
    show(windowsDeploymentFixture({ id: ID, location_kind: 'server_file' }));
    await renderRoute(`/deployments/${ID}`);
    await screen.findByRole('heading', { level: 1 });
    expect(screen.queryByText(/Previous certificate: My/)).not.toBeInTheDocument();
    expect(screen.queryByText('Binding', { selector: 'dt' })).not.toBeInTheDocument();
  });
});

// R61, Task 13 review I1: no text a Windows deployment can show speaks of Nginx, its files, a reload or the Linux
// backup folder. The reasons are read from the Windows provider, the shared verification judgement and the deployment
// engine; a reason only the Linux helper or the Nginx provider produces is left out by name, with the reason why.
describe('Windows deployment texts', () => {
  const LINUX_ONLY: Record<string, string> = {
    // The Windows provider maps these transport answers to windows.helper_refused, windows.binding_changed,
    // windows.helper_missing and windows.helper_outdated (W2 Ruling 6).
    'ssh.helper_refused': 'mapped',
    'ssh.file_changed': 'mapped',
    'ssh.helper_missing': 'mapped',
    'ssh.helper_outdated': 'mapped',
    // The engine's names for a configuration test or reload of the Linux helper (causeReason), and its pre-check of a
    // web server whose configuration is invalid (a Windows server has no configuration test).
    'deployment.config_test_failed': 'nginx helper steps',
    'deployment.reload_failed': 'nginx helper steps',
    'deployment.rollback_reload_failed': 'nginx helper steps',
    'deployment.rollback_config_invalid': 'nginx helper steps',
    'nginx.config_invalid': 'nginx configuration',
    'nginx.file_changed': 'nginx provider',
    'nginx.no_space': 'nginx provider',
    'nginx.profile_missing': 'nginx profile',
  };
  const quoted = (rel: string) => [...readRepoFile(rel).matchAll(/"((?:deployment|ssh|nginx|windows)\.[a-z_]+)"/g)].map((m) => m[1]);
  const sources = [...goFiles('internal/providers/windows').filter((f) => !f.includes('/winhelper/') && !f.includes('/wintest/')), ...goFiles('internal/providers/tlsverify'), ...goFiles('internal/jobs/deployjobs')];
  // The deployment records' own reasons (the sweep's recovery_exhausted, a deleted server, a rescan) and the API's
  // in_progress apply to every deployment; only their deployment.* reasons are taken.
  const recordSources = ['internal/inventory/deployment_records.go', 'internal/inventory/sweep.go', 'internal/inventory/deployment_outcome.go', 'internal/api/errors.go'];
  const catalogue = (lang: 'en' | 'tr') => (lang === 'en' ? commonEn : commonTr).errors as Record<string, Record<string, Record<string, string> | undefined>>;
  const shared = (lang: 'en' | 'tr', reason: string) => {
    const [ns, name] = reason.split('.');
    return catalogue(lang)[ns]?.[name];
  };
  // The reasons a Windows deployment can end with that have texts (an audit event such as deployment.started has none).
  // R68: the windows.ccs_* reasons end only a deployment to a CCS file, which is a file, so their texts speak of files.
  const reasons = [...new Set([...sources.flatMap(quoted), ...recordSources.flatMap(quoted).filter((r) => r.startsWith('deployment.'))])]
    .filter((r) => !(r in LINUX_ONLY) && !r.startsWith('windows.ccs_') && shared('en', r) !== undefined)
    .sort();
  const own = (lang: 'en' | 'tr', reason: string) => {
    const [ns, name] = reason.split('.');
    const w = ((lang === 'en' ? enWeb : trWeb).deployments as unknown as { windowsErrors: Record<string, Record<string, Record<string, string>>> }).windowsErrors;
    return w[ns]?.[name] ?? {};
  };
  // "files" in lower case: "C:\\Program Files" is a Windows path.
  const WRONG_EN = /nginx|certificate file|key file|\/var\/lib|\/usr\/local|systemctl|reload|as root/i;
  const WRONG_TR = /nginx|dosyalar|sertifika dosya|anahtar dosya|\/var\/lib|\/usr\/local|systemctl|yeniden yükle|root olarak/i;
  const wrong = (lang: 'en' | 'tr', text: string) => (lang === 'en' ? WRONG_EN.test(text) || /\bfiles\b/.test(text) : WRONG_TR.test(text));

  // R68: the reasons a CCS file deployment ends with speak of its file and of the Centralized Certificate Store (in
  // capitals), never of a binding, netsh or the Windows certificate stores (in lower case).
  const ccsReasons = [...new Set(sources.flatMap(quoted))].filter((r) => r.startsWith('windows.ccs_') && shared('en', r) !== undefined).sort();
  const WRONG_CCS_EN = /netsh|binding|certificate store|WebHosting/;
  const WRONG_CCS_TR = /netsh|bağlama|sertifika deposu|WebHosting/;

  it.each(['en', 'tr'] as const)('words every CCS reason for a file, not for a binding or a store (%s)', (lang) => {
    expect(ccsReasons).toEqual(expect.arrayContaining(['windows.ccs_disabled', 'windows.ccs_path_changed', 'windows.ccs_password_mismatch', 'windows.ccs_password_missing', 'windows.ccs_file_not_found']));
    const bad: string[] = [];
    for (const r of ccsReasons) {
      for (const part of ['title', 'cause', 'action']) {
        const text = shared(lang, r)?.[part] ?? '';
        if ((lang === 'en' ? WRONG_CCS_EN : WRONG_CCS_TR).test(text)) bad.push(`${r}.${part}: ${text}`);
      }
    }
    expect(bad).toEqual([]);
  });

  it('finds the reasons of the Windows provider and the engine', () => {
    expect(reasons).toEqual(expect.arrayContaining(['deployment.verify_failed', 'deployment.interrupted', 'deployment.verify_chain', 'deployment.recovery_exhausted', 'deployment.outcome_unknown', 'windows.key_unusable']));
  });

  it.each(['en', 'tr'] as const)('words every such reason for a binding (%s)', (lang) => {
    const bad: string[] = [];
    for (const r of reasons) {
      for (const part of ['title', 'cause', 'action']) {
        const text = own(lang, r)[part] ?? shared(lang, r)?.[part] ?? '';
        if (wrong(lang, text)) bad.push(`${r}.${part}: ${text}`);
      }
    }
    expect(bad).toEqual([]);
  });

  it.each([
    ['ALC-DEP-0003', 'deployment.verify_failed', 'rolled_back', 'restored'],
    ['ALC-DEP-0010', 'deployment.interrupted', 'rollback_failed', 'writing'],
    ['ALC-DEP-0012', 'deployment.verify_chain', 'rolled_back', 'restored'],
    ['ALC-DEP-0017', 'deployment.recovery_exhausted', 'rollback_failed', 'writing'],
    ['ALC-DEP-0018', 'deployment.outcome_unknown', 'rollback_failed', 'writing'],
    ['ALC-DEP-0023', 'deployment.server_operation_pending', 'failed', 'none'],
    ['ALC-DEP-0024', 'deployment.pending_change_restored', 'rolled_back', 'restored'],
  ])('shows %s %s on a Windows deployment page without Nginx, files or the backup folder', async (code, reason, status, phase) => {
    show(windowsDeploymentFixture({ id: ID, status: status as DeploymentDetail['status'], phase: phase as DeploymentDetail['phase'], verified: '', error: { code, reason, params: { port: '443' } } }));
    await renderRoute(`/deployments/${ID}`);
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveAttribute('data-reason', reason);
    expect(wrong('en', alert.textContent ?? ''), alert.textContent ?? '').toBe(false);
    expect(alert.textContent ?? '').not.toMatch(/\{\{/);
    // The headline above it too.
    for (const s of screen.getAllByRole('status')) expect(wrong('en', s.textContent ?? ''), s.textContent ?? '').toBe(false);
    const ownText = own('en', reason);
    for (const part of Object.values(ownText)) expect(alert).toHaveTextContent(part.replace(/\{\{port\}\}/g, '443'));
  });

  // R69: the Remote Desktop listener's own texts (deployments.rdpErrors), else the Windows ones, else the shared ones:
  // none speaks of a binding, netsh, IIS Manager, files or Nginx.
  const rdpOwn = (lang: 'en' | 'tr', reason: string) => {
    const [ns, name] = reason.split('.');
    const r = ((lang === 'en' ? enWeb : trWeb).deployments as unknown as { rdpErrors: Record<string, Record<string, Record<string, string>>> }).rdpErrors;
    return r[ns]?.[name] ?? {};
  };
  const WRONG_RDP_EN = /binding|netsh|IIS Manager/i;
  // "Binding" here is Alice's binding of a location to an issued certificate or a vault, not an http.sys binding; the
  // cleanup's reason never ends a deployment.
  const RDP_EXEMPT = ['deployment.drift_not_bound', 'deployment.drift_repair_superseded', 'windows.cleanup_outcome_unknown'];
  const WRONG_RDP_TR = /bağlama|netsh|IIS Yöneticisi/i;

  it.each(['en', 'tr'] as const)('words every such reason for the Remote Desktop listener (%s)', (lang) => {
    const bad: string[] = [];
    for (const r of reasons.filter((x) => !RDP_EXEMPT.includes(x))) {
      for (const part of ['title', 'cause', 'action']) {
        const text = rdpOwn(lang, r)[part] ?? own(lang, r)[part] ?? shared(lang, r)?.[part] ?? '';
        if (wrong(lang, text) || (lang === 'en' ? WRONG_RDP_EN : WRONG_RDP_TR).test(text)) bad.push(`${r}.${part}: ${text}`);
      }
    }
    expect(bad).toEqual([]);
  });

  it('keeps the shared texts for a Linux deployment', async () => {
    show(deploymentDetailFixture({ id: ID, status: 'rolled_back', error: { code: 'ALC-DEP-0003', reason: 'deployment.verify_failed' } }));
    await renderRoute(`/deployments/${ID}`);
    expect(await screen.findByRole('alert')).toHaveTextContent('Check which part of the Nginx configuration answers for this website');
  });
});

// R69: a deployment to the Remote Desktop listener of a Windows server.
describe('DeploymentDetailPage of the Remote Desktop listener', () => {
  it.each([
    ['en', 'Listener', 'Remote Desktop (RDP-Tcp)', 'Previous certificate: Remote Desktop'],
    ['tr', 'Dinleyici', 'Uzak Masaüstü (RDP-Tcp)', 'Önceki sertifika: Remote Desktop'],
  ])('shows its steps, the listener and the previous certificate by store and thumbprint (%s)', async (lang, label, name, previous) => {
    show(rdpDeploymentFixture({ id: ID }), 'auditor', lang);
    await renderRoute(`/deployments/${ID}`, { languages: [lang] });
    const list = await screen.findByRole('list', { name: /Steps|Adımlar/ });
    expect(Array.from(list.querySelectorAll('[data-step]')).map((e) => e.getAttribute('data-step'))).toEqual([
      'verify_current',
      'import_chain',
      'import_certificate',
      'grant_key_read',
      'set_listener',
      'verify',
      'journal',
    ]);
    expect(screen.getByText(label, { selector: 'dt' }).nextElementSibling).toHaveTextContent(name);
    expect(screen.queryByText('Key file', { selector: 'dt' })).not.toBeInTheDocument();
    expect(screen.getByTestId('windows-previous')).toHaveTextContent(`${previous} \\ ${WIN_PREVIOUS_SHA1}`);
    expectNoRawKeys();
  });
});

// R69 (Ruling 20): a failed rollback of the Remote Desktop listener, or one it could not confirm, names the listener,
// where to check it on the server and that the console or SSH is the way in, never a binding or files.
describe('DeploymentDetailPage of a failed Remote Desktop rollback', () => {
  it.each([
    ['en', 'Alice cannot confirm which certificate the Remote Desktop listener serves', 'Win32_TSGeneralSetting', "the server's console or SSH"],
    ['tr', 'Alice, Uzak Masaüstü dinleyicisinin hangi sertifikayı sunduğunu doğrulayamıyor', 'Win32_TSGeneralSetting', 'sunucunun konsolunu ya da SSH'],
  ])('rollback_failed (%s)', async (lang, headline, where, wayIn) => {
    show(
      rdpDeploymentFixture({ id: ID, status: 'rollback_failed', result: 'rollback_failed', phase: 'writing', verified: '', error: { code: 'ALC-DEP-0008', reason: 'deployment.rollback_failed' } }),
      'auditor',
      lang,
    );
    await renderRoute(`/deployments/${ID}`, { languages: [lang] });
    const alert = await screen.findByRole('alert');
    expect(screen.getByText(new RegExp(headline))).toBeInTheDocument();
    expect(alert).toHaveTextContent(where);
    expect(alert).toHaveTextContent(wayIn);
    expect(alert.textContent ?? '').not.toMatch(lang === 'en' ? /binding|netsh|files/i : /bağlama|netsh|dosyalar/i);
    expectNoRawKeys();
  });

  it.each([
    ['en', 'The Remote Desktop listener names the previous certificate again', 'Remote Desktop settings'],
    ['tr', 'Uzak Masaüstü dinleyicisi yeniden önceki sertifikayı gösteriyor', 'Uzak Masaüstü ayarları'],
  ])('restored_unverified (%s)', async (lang, headline, where) => {
    show(
      rdpDeploymentFixture({ id: ID, status: 'rollback_failed', result: 'rollback_failed', phase: 'restored', verified: '', error: { code: 'ALC-DEP-0019', reason: 'deployment.restored_unverified' } }),
      'auditor',
      lang,
    );
    await renderRoute(`/deployments/${ID}`, { languages: [lang] });
    const alert = await screen.findByRole('alert');
    expect(screen.getAllByText(new RegExp(headline)).length).toBeGreaterThan(0);
    expect(alert).toHaveTextContent(where);
    expect(alert).toHaveTextContent('Win32_TSGeneralSetting');
    expect(alert.textContent ?? '').not.toMatch(lang === 'en' ? /binding|netsh|files/i : /bağlama|netsh|dosyalar/i);
    expectNoRawKeys();
  });
});
