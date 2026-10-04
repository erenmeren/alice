import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import type { Certificate, CertificateLocation, DeploymentDetail, DeploymentStep } from '../api/types';
import {
  certificateDetailFixture,
  certificateFixture,
  deploymentDetailFixture,
  errorResponse,
  locationFixture,
  sessionFor,
  sessionHandlers,
  stepFixture,
} from '../test/fixtures';
import { renderWithAuth } from '../test/render';
import { server } from '../test/server';
import { DeployDialog } from './DeployDialog';

const NEW_ID = '0192c000-0000-7000-8000-0000000000c9';
const L1 = '0192c000-0000-7000-8000-0000000000e1';
const L2 = '0192c000-0000-7000-8000-0000000000e2';
const D1 = '0192c000-0000-7000-8000-0000000000d1';
const D2 = '0192c000-0000-7000-8000-0000000000d2';

const NEW_CERT = certificateFixture({ id: NEW_ID, subject_cn: 'new.example.test', has_private_key: true, key_algorithm: 'ecdsa' });

function accepted(...ids: [string, string][]) {
  return {
    deployments: ids.map(([id, loc]) => ({ id, job_id: `j-${id}`, location_id: loc, status_url: `/api/v1/jobs/j-${id}`, deployment_url: `/api/v1/deployments/${id}`, warnings: [] as string[] })),
  };
}

function asRole(role: 'admin' | 'operator' | 'auditor') {
  server.use(...sessionHandlers(sessionFor(role)));
}

function certificates(items: Certificate[]) {
  server.use(http.get('/api/v1/certificates', () => HttpResponse.json({ items, next_cursor: null })));
}

function showDialog(props: { certificate?: Certificate; location?: CertificateLocation }) {
  return renderWithAuth(<DeployDialog opened onClose={() => {}} {...props} />);
}

beforeEach(() => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
  vi.setSystemTime(new Date('2026-10-04T12:00:00Z'));
});
afterEach(() => vi.useRealTimers());

describe('DeployDialog from a website', () => {
  it('deploys to a website and shows the steps turn done, then says the certificate is live', async () => {
    asRole('operator');
    certificates([NEW_CERT]);
    const steps: DeploymentStep[] = [];
    let status: DeploymentDetail['status'] = 'running';
    let body: unknown = null;
    server.use(
      http.post(`/api/v1/certificates/${NEW_ID}/deploy`, async ({ request }) => {
        body = await request.json();
        return HttpResponse.json(accepted([D1, L1]), { status: 202 });
      }),
      http.get(`/api/v1/deployments/${D1}`, () => HttpResponse.json(deploymentDetailFixture({ id: D1, status, state: 'deploying', steps: [...steps], finished_at: null }))),
    );
    await showDialog({ location: locationFixture({ id: L1, key_type: 'ecdsa' }) });
    await userEvent.selectOptions(await screen.findByLabelText('Certificate'), NEW_ID);
    await userEvent.click(screen.getByRole('button', { name: 'Deploy' }));
    expect(body).toEqual({ location_ids: [L1], confirm_incomplete_chain: false });
    const list = await screen.findByRole('list', { name: 'Steps' });
    for (const name of ['Backup', 'Write', 'Check', 'Reload', 'Verify']) expect(within(list).getByText(name)).toBeInTheDocument();
    expect(within(list).getAllByText('Waiting')).toHaveLength(5);
    expect(screen.getByText('Alice is deploying the certificate…')).toBeInTheDocument();
    steps.push(...['backup', 'write_key', 'write_cert', 'config_test', 'reload'].map((n, i) => stepFixture(i + 1, n, 'ok')));
    await vi.advanceTimersByTimeAsync(1_000);
    expect(await within(list).findAllByText('Done')).toHaveLength(4);
    // Never "live" before the deployment says succeeded.
    expect(screen.queryByText('The new certificate is live and verified.')).not.toBeInTheDocument();
    expect(screen.getByText('Current step: Reload')).toBeInTheDocument();
    steps.push(stepFixture(6, 'verify', 'ok'));
    status = 'succeeded';
    await vi.advanceTimersByTimeAsync(1_000);
    expect(await screen.findByText('The new certificate is live and verified.')).toBeInTheDocument();
    expect(within(list).getAllByText('Done')).toHaveLength(5);
    expect(screen.queryByText('Alice is deploying the certificate…')).not.toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Open this deployment' })).toHaveAttribute('href', `/deployments/${D1}`);
  });

  it('says so when the check was done from the server itself or skipped, and does not call a skipped check verified', async () => {
    asRole('operator');
    certificates([NEW_CERT]);
    let verified: DeploymentDetail['verified'] = 'local';
    server.use(
      http.post(`/api/v1/certificates/${NEW_ID}/deploy`, () => HttpResponse.json(accepted([D1, L1]), { status: 202 })),
      http.get(`/api/v1/deployments/${D1}`, () => HttpResponse.json(deploymentDetailFixture({ id: D1, verified }))),
    );
    const first = await showDialog({ location: locationFixture({ id: L1 }) });
    await userEvent.selectOptions(await screen.findByLabelText('Certificate'), NEW_ID);
    await userEvent.click(screen.getByRole('button', { name: 'Deploy' }));
    expect(await screen.findByText('The new certificate is live and verified.')).toBeInTheDocument();
    expect(screen.getByText('Alice checked it from the server itself because it cannot reach the website directly.')).toBeInTheDocument();
    first.unmount();
    verified = 'skipped';
    await showDialog({ location: locationFixture({ id: L1 }) });
    await userEvent.selectOptions(await screen.findByLabelText('Certificate'), NEW_ID);
    await userEvent.click(screen.getByRole('button', { name: 'Deploy' }));
    expect(await screen.findByText('The new certificate was deployed and Nginx was reloaded.')).toBeInTheDocument();
    expect(screen.getByText(/the check was skipped for this website/i)).toBeInTheDocument();
    expect(screen.queryByText('The new certificate is live and verified.')).not.toBeInTheDocument();
  });

  it('reports a rollback with the reason, the restore steps and the failed Reload', async () => {
    asRole('operator');
    certificates([NEW_CERT]);
    server.use(
      http.post(`/api/v1/certificates/${NEW_ID}/deploy`, () => HttpResponse.json(accepted([D1, L1]), { status: 202 })),
      http.get(`/api/v1/deployments/${D1}`, () =>
        HttpResponse.json(
          deploymentDetailFixture({
            id: D1,
            status: 'rolled_back',
            state: 'done',
            error: { code: 'ALC-DEP-0006', reason: 'deployment.reload_failed' },
            steps: [
              stepFixture(1, 'backup'),
              stepFixture(2, 'write_key'),
              stepFixture(3, 'write_cert'),
              stepFixture(4, 'config_test'),
              stepFixture(5, 'reload', 'failed'),
              stepFixture(6, 'restore'),
              stepFixture(7, 'rollback_config_test'),
              stepFixture(8, 'rollback_reload'),
              stepFixture(9, 'verify_old'),
            ],
          }),
        ),
      ),
    );
    await showDialog({ location: locationFixture({ id: L1 }) });
    await userEvent.selectOptions(await screen.findByLabelText('Certificate'), NEW_ID);
    await userEvent.click(screen.getByRole('button', { name: 'Deploy' }));
    expect(await screen.findByText('Your server was restored to its previous certificate.')).toBeInTheDocument();
    expect(screen.getByRole('alert')).toHaveTextContent('Nginx did not reload');
    expect(screen.getByRole('alert')).toHaveTextContent('ALC-DEP-0006');
    const list = screen.getByRole('list', { name: 'Steps' });
    expect(within(within(list).getByText('Reload').closest('li')!).getByText('Failed')).toBeInTheDocument();
    for (const name of ['Restore', 'Check again', 'Reload again', 'Verify the previous certificate']) expect(within(list).getByText(name)).toBeInTheDocument();
    // Verify was never reached.
    expect(within(within(list).getByText('Verify').closest('li')!).getByText('Not run')).toBeInTheDocument();
  });

  it('offers only certificates with a key, valid now and of the same key type', async () => {
    asRole('operator');
    certificates([
      NEW_CERT,
      certificateFixture({ id: 'rsa', subject_cn: 'rsa.example.test', key_algorithm: 'rsa' }),
      certificateFixture({ id: 'nokey', subject_cn: 'nokey.example.test', has_private_key: false }),
      certificateFixture({ id: 'expired', subject_cn: 'old.example.test', not_after: '2026-09-30T00:00:00Z' }),
      certificateFixture({ id: 'future', subject_cn: 'future.example.test', not_before: '2026-11-01T00:00:00Z' }),
    ]);
    await showDialog({ location: locationFixture({ id: L1, key_type: 'ecdsa' }) });
    const select = await screen.findByLabelText('Certificate');
    const options = within(select).getAllByRole('option').map((o) => o.getAttribute('value'));
    expect(options).toEqual(['', NEW_ID]);
  });

  it('offers any key type for a website that does not report one, and says when nothing fits', async () => {
    asRole('operator');
    certificates([certificateFixture({ id: 'rsa', key_algorithm: 'rsa' })]);
    const first = await showDialog({ location: locationFixture({ id: L1, key_type: '' }) });
    expect(within(await screen.findByLabelText('Certificate')).getAllByRole('option')).toHaveLength(2);
    first.unmount();
    certificates([certificateFixture({ id: 'nokey', has_private_key: false })]);
    await showDialog({ location: locationFixture({ id: L1, key_type: 'ecdsa' }) });
    expect(await screen.findByText('Alice holds no certificate with a private key that fits this website. Upload one first.')).toBeInTheDocument();
    expect(screen.queryByLabelText('Certificate')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Deploy' })).toBeDisabled();
  });

  it('needs an Administrator for an incomplete chain', async () => {
    certificates([certificateFixture({ id: NEW_ID, chain_complete: false })]);
    let body: unknown = null;
    server.use(
      http.post(`/api/v1/certificates/${NEW_ID}/deploy`, async ({ request }) => {
        body = await request.json();
        return HttpResponse.json(accepted([D1, L1]), { status: 202 });
      }),
      http.get(`/api/v1/deployments/${D1}`, () => HttpResponse.json(deploymentDetailFixture({ id: D1 }))),
    );
    asRole('operator');
    const op = await showDialog({ location: locationFixture({ id: L1 }) });
    await userEvent.selectOptions(await screen.findByLabelText('Certificate'), NEW_ID);
    expect(await screen.findByText('The chain of this certificate is incomplete. An administrator must deploy it.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Deploy' })).toBeDisabled();
    expect(screen.queryByLabelText('I confirm that this incomplete chain is intended')).not.toBeInTheDocument();
    op.unmount();

    asRole('admin');
    await showDialog({ location: locationFixture({ id: L1 }) });
    await userEvent.selectOptions(await screen.findByLabelText('Certificate'), NEW_ID);
    const confirm = await screen.findByLabelText('I confirm that this incomplete chain is intended');
    expect(screen.getByRole('button', { name: 'Deploy' })).toBeDisabled();
    await userEvent.click(confirm);
    await userEvent.click(screen.getByRole('button', { name: 'Deploy' }));
    await waitFor(() => expect(body).toEqual({ location_ids: [L1], confirm_incomplete_chain: true }));
  });

  it('keeps the dialog and the chosen certificate and highlights the website the server refused', async () => {
    asRole('operator');
    certificates([NEW_CERT]);
    server.use(http.post(`/api/v1/certificates/${NEW_ID}/deploy`, () => errorResponse(409, 'ALC-DEP-0011', 'deployment.target_not_ready', { params: { location_id: L1 } })));
    await showDialog({ location: locationFixture({ id: L1 }) });
    await userEvent.selectOptions(await screen.findByLabelText('Certificate'), NEW_ID);
    await userEvent.click(screen.getByRole('button', { name: 'Deploy' }));
    const row = await waitFor(() => {
      const el = document.querySelector('[data-refused="true"]');
      expect(el).not.toBeNull();
      return el as HTMLElement;
    });
    expect(within(row).getByText(/Alice stopped here/)).toBeInTheDocument();
    expect(screen.getByLabelText('Certificate')).toHaveValue(NEW_ID);
    expect(screen.getByRole('button', { name: 'Deploy' })).toBeEnabled();
    expect(screen.queryByRole('list', { name: 'Steps' })).not.toBeInTheDocument();
  });

  it('shows the san_mismatch warning of the answer without blocking', async () => {
    asRole('operator');
    certificates([NEW_CERT]);
    server.use(
      http.post(`/api/v1/certificates/${NEW_ID}/deploy`, () => HttpResponse.json({ deployments: [{ ...accepted([D1, L1]).deployments[0], warnings: ['san_mismatch'] }] }, { status: 202 })),
      http.get(`/api/v1/deployments/${D1}`, () => HttpResponse.json(deploymentDetailFixture({ id: D1 }))),
    );
    await showDialog({ location: locationFixture({ id: L1 }) });
    await userEvent.selectOptions(await screen.findByLabelText('Certificate'), NEW_ID);
    await userEvent.click(screen.getByRole('button', { name: 'Deploy' }));
    expect(await screen.findByText(/The certificate does not name this website:/)).toHaveTextContent('The certificate does not name this website: www.example.test');
  });
});

describe('DeployDialog from a certificate', () => {
  const l1 = locationFixture({ id: L1 });
  const l2 = locationFixture({ id: L2, cert_path: '/etc/nginx/ssl/api.crt', servers: [{ names: ['api.example.test'], listens: [{ addr: '*', port: 443, default_server: false }], file: '/etc/nginx/conf.d/api.conf', line: 2 }] });
  const detail = (locations: CertificateLocation[], o: Partial<Certificate> = {}) => certificateDetailFixture({ id: NEW_ID, ...o, locations });

  function certServer(locations: CertificateLocation[], o: Partial<Certificate> = {}) {
    server.use(http.get(`/api/v1/certificates/${NEW_ID}`, () => HttpResponse.json(detail(locations, o))));
  }

  it('deploys one certificate to several websites and summarizes', async () => {
    asRole('operator');
    certServer([l1, l2]);
    let body: unknown = null;
    server.use(
      http.post(`/api/v1/certificates/${NEW_ID}/deploy`, async ({ request }) => {
        body = await request.json();
        return HttpResponse.json(accepted([D1, L1], [D2, L2]), { status: 202 });
      }),
      http.get(`/api/v1/deployments/${D1}`, () => HttpResponse.json(deploymentDetailFixture({ id: D1, location_id: L1 }))),
      http.get(`/api/v1/deployments/${D2}`, () =>
        HttpResponse.json(deploymentDetailFixture({ id: D2, location_id: L2, status: 'rolled_back', error: { code: 'ALC-DEP-0006', reason: 'deployment.reload_failed' } })),
      ),
    );
    await showDialog({ certificate: NEW_CERT });
    await userEvent.click(await screen.findByRole('checkbox', { name: /www\.example\.test/ }));
    await userEvent.click(screen.getByRole('checkbox', { name: /api\.example\.test/ }));
    await userEvent.click(screen.getByRole('button', { name: 'Deploy' }));
    expect(body).toEqual({ location_ids: [L1, L2], confirm_incomplete_chain: false });
    expect(await screen.findByText('Updated websites: 1 of 2')).toBeInTheDocument();
    expect(screen.getAllByRole('list', { name: 'Steps' })).toHaveLength(2);
    expect(screen.getByText('The new certificate is live and verified.')).toBeInTheDocument();
    expect(screen.getByText('Your server was restored to its previous certificate.')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Open deployment history' })).toHaveAttribute('href', '/deployments');
  });

  it('shows websites Alice cannot deploy to as unselectable, with the reason', async () => {
    asRole('operator');
    certServer([
      l1,
      locationFixture({ id: L2, supported: false, unsupported_reason: 'variable' }),
      locationFixture({ id: 'l3', supported: false, unsupported_reason: 'file_problem', problem: 'hard_linked' }),
      locationFixture({ id: 'l4', missing_since: '2026-10-01T00:00:00Z' }),
      locationFixture({ id: 'l5', active_deployment_id: D1 }),
    ]);
    await showDialog({ certificate: NEW_CERT });
    const boxes = await screen.findAllByRole('checkbox');
    expect(boxes.map((b) => (b as HTMLInputElement).disabled)).toEqual([false, true, true, true, true]);
    expect(screen.getByText('The path uses a variable, so Alice cannot know which file is used.')).toBeInTheDocument();
    expect(screen.getByText('Alice cannot use the files at this place.')).toBeInTheDocument();
    expect(screen.getByText('The file has more than one name (hard link).')).toBeInTheDocument();
    expect(screen.getByText('This website is no longer found.')).toBeInTheDocument();
    expect(screen.getByText('A deployment to this place is in progress.')).toBeInTheDocument();
  });

  it('refuses more than 20 websites with the limit and sends nothing', async () => {
    asRole('operator');
    const many = Array.from({ length: 21 }, (_, i) => locationFixture({ id: `l${i}`, cert_path: `/etc/nginx/ssl/${i}.crt` }));
    certServer(many);
    let posted = false;
    server.use(http.post(`/api/v1/certificates/${NEW_ID}/deploy`, () => ((posted = true), HttpResponse.json(accepted(), { status: 202 }))));
    await showDialog({ certificate: NEW_CERT });
    const boxes = await screen.findAllByRole('checkbox');
    for (const b of boxes.slice(0, 20)) await userEvent.click(b);
    expect(screen.queryByText(/at most 20 websites/)).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Deploy' })).toBeEnabled();
    await userEvent.click(boxes[20]);
    expect(screen.getByText('You can deploy to at most 20 websites at once. Untick some websites.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Deploy' })).toBeDisabled();
    expect(posted).toBe(false);
  });

  it('cannot deploy a certificate without a key, an expired one or one that is not valid yet', async () => {
    asRole('operator');
    certServer([l1]);
    const cases: [Certificate, string][] = [
      [certificateFixture({ id: NEW_ID, has_private_key: false }), 'Alice does not have the private key of this certificate, so it cannot deploy it.'],
      [certificateFixture({ id: NEW_ID, not_after: '2026-09-30T00:00:00Z' }), 'This certificate has expired and cannot be deployed.'],
      [certificateFixture({ id: NEW_ID, not_before: '2026-11-01T00:00:00Z' }), 'This certificate is not valid yet and cannot be deployed.'],
    ];
    for (const [cert, text] of cases) {
      const view = await showDialog({ certificate: cert });
      expect(await screen.findByText(text)).toBeInTheDocument();
      await userEvent.click(await screen.findByRole('checkbox'));
      expect(screen.getByRole('button', { name: 'Deploy' })).toBeDisabled();
      view.unmount();
    }
  });

  it('highlights the refused website, keeps the selection and tells that only the first refusal is named', async () => {
    asRole('operator');
    certServer([l1, l2]);
    server.use(http.post(`/api/v1/certificates/${NEW_ID}/deploy`, () => errorResponse(409, 'ALC-NGX-0007', 'nginx.location_unsupported', { params: { location_id: L2 } })));
    await showDialog({ certificate: NEW_CERT });
    await userEvent.click(await screen.findByRole('checkbox', { name: /www\.example\.test/ }));
    await userEvent.click(screen.getByRole('checkbox', { name: /api\.example\.test/ }));
    await userEvent.click(screen.getByRole('button', { name: 'Deploy' }));
    await waitFor(() => expect(document.querySelectorAll('[data-refused="true"]')).toHaveLength(1));
    const refused = document.querySelector('[data-refused="true"]') as HTMLElement;
    expect(within(refused).getByRole('checkbox')).toBeChecked();
    expect(within(refused).getByText(/names only the first website/)).toBeInTheDocument();
    expect(screen.getByRole('checkbox', { name: /www\.example\.test/ })).toBeChecked();
    expect(screen.getByRole('button', { name: 'Deploy' })).toBeEnabled();
  });

  it('shows a server refusal of the whole request and stays open', async () => {
    asRole('operator');
    certServer([l1]);
    server.use(http.post(`/api/v1/certificates/${NEW_ID}/deploy`, () => errorResponse(403, 'ALC-AUTH-0004', 'auth.forbidden')));
    await showDialog({ certificate: NEW_CERT });
    await userEvent.click(await screen.findByRole('checkbox'));
    await userEvent.click(screen.getByRole('button', { name: 'Deploy' }));
    expect(await screen.findByRole('alert')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Deploy' })).toBeEnabled();
  });

  it('says when the certificate is not used on any website', async () => {
    asRole('operator');
    certServer([]);
    await showDialog({ certificate: NEW_CERT });
    expect(await screen.findByText(/not used on any website that Alice can deploy to/)).toBeInTheDocument();
  });
});

describe('DeployDialog polling', () => {
  async function start() {
    asRole('operator');
    certificates([NEW_CERT]);
    server.use(http.post(`/api/v1/certificates/${NEW_ID}/deploy`, () => HttpResponse.json(accepted([D1, L1]), { status: 202 })));
    await showDialog({ location: locationFixture({ id: L1 }) });
    await userEvent.selectOptions(await screen.findByLabelText('Certificate'), NEW_ID);
    await userEvent.click(screen.getByRole('button', { name: 'Deploy' }));
  }

  it('stops after the deadline with "still working" and a link to the history', async () => {
    let polls = 0;
    server.use(http.get(`/api/v1/deployments/${D1}`, () => ((polls += 1), HttpResponse.json(deploymentDetailFixture({ id: D1, status: 'running', state: 'deploying', finished_at: null })))));
    await start();
    await screen.findByRole('list', { name: 'Steps' });
    await vi.advanceTimersByTimeAsync(125_000);
    expect(await screen.findByText('Alice is still working on this. Open the deployment history in a minute to see the result.')).toBeInTheDocument();
    expect(screen.queryByText('The new certificate is live and verified.')).not.toBeInTheDocument();
    const seen = polls;
    await vi.advanceTimersByTimeAsync(30_000);
    expect(polls).toBe(seen);
    expect(seen).toBeGreaterThan(50);
    expect(seen).toBeLessThan(140);
  });

  it('waits out a dropped connection and carries on', async () => {
    let polls = 0;
    server.use(
      http.get(`/api/v1/deployments/${D1}`, () => {
        polls += 1;
        if (polls <= 2) return HttpResponse.error();
        return HttpResponse.json(deploymentDetailFixture({ id: D1 }));
      }),
    );
    await start();
    await vi.advanceTimersByTimeAsync(3_000);
    expect(await screen.findByText('The new certificate is live and verified.')).toBeInTheDocument();
    expect(polls).toBeGreaterThanOrEqual(3);
  });

  it('says the connection is lost when it never comes back before the deadline', async () => {
    server.use(http.get(`/api/v1/deployments/${D1}`, () => HttpResponse.error()));
    await start();
    await vi.advanceTimersByTimeAsync(125_000);
    expect(await screen.findByText(/Alice cannot reach itself right now/)).toBeInTheDocument();
  });

  it('shows a deployment that Alice is finishing after a lost connection, and stops polling', async () => {
    let polls = 0;
    server.use(
      http.get(`/api/v1/deployments/${D1}`, () => {
        polls += 1;
        return HttpResponse.json(
          deploymentDetailFixture({
            id: D1,
            status: 'needs_attention',
            state: 'recovering',
            recovery_attempts: 3,
            recover_after: '2026-10-04T12:05:00Z',
            error: { code: 'ALC-SSH-0001', reason: 'ssh.unreachable' },
            finished_at: null,
          }),
        );
      }),
    );
    await start();
    expect(await screen.findByText('The connection to the server was lost. Alice will check the server and finish or undo the change.')).toBeInTheDocument();
    const seen = polls;
    await vi.advanceTimersByTimeAsync(5_000);
    expect(polls).toBe(seen);
    expect(screen.queryByText('The new certificate is live and verified.')).not.toBeInTheDocument();
  });

  it('says a deployment is on hold for the license', async () => {
    server.use(http.get(`/api/v1/deployments/${D1}`, () => HttpResponse.json(deploymentDetailFixture({ id: D1, status: 'pending', state: 'queued', job_status: 'blocked_license', finished_at: null }))));
    await start();
    expect(await screen.findByText(/The license has expired, so this deployment is on hold/)).toBeInTheDocument();
  });

  it('stops following when the dialog closes', async () => {
    let polls = 0;
    server.use(http.get(`/api/v1/deployments/${D1}`, () => ((polls += 1), HttpResponse.json(deploymentDetailFixture({ id: D1, status: 'running', state: 'deploying', finished_at: null })))));
    await start();
    await screen.findByRole('list', { name: 'Steps' });
    await userEvent.click(screen.getAllByRole('button', { name: 'Close' })[1]);
    const seen = polls;
    await vi.advanceTimersByTimeAsync(10_000);
    expect(polls).toBe(seen);
  });
});
