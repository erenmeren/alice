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
  SERVICE_ID,
  serviceRef,
  servicePolicyFixture,
  sessionFor,
  sessionHandlers,
  stepFixture,
  windowsBindingFixture,
  windowsCCSFileFixture,
  windowsDeploymentFixture,
  windowsRDPFixture,
  ccsDeploymentFixture,
  rdpDeploymentFixture,
} from '../test/fixtures';
import { renderWithAuth } from '../test/render';
import { server } from '../test/server';
import { DeployDialog } from './DeployDialog';
import type { CanaryPolicy } from '../api/services';
import deploy from './deploy.module.css';

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

function showDialog(props: { certificate?: Certificate; location?: CertificateLocation; siblings?: CertificateLocation[] }) {
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
      http.get(`/api/v1/deployments/${D1}`, () => HttpResponse.json(deploymentDetailFixture({ id: D1, status, state: 'deploying', job_status: 'running', steps: [...steps], finished_at: null }))),
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
    expect(row).toHaveClass(deploy.refused);
    expect(row?.getAttribute('style') ?? '').not.toMatch(/border/);
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
    // Several runs are separated by a rule in the border token (a class, not an inline color).
    for (const run of screen.getAllByTestId('deployment-run')) {
      expect(run).toHaveClass(deploy.separated);
      expect(run.getAttribute('style') ?? '').not.toMatch(/border/);
    }
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

  it('lists a place on a server whose software cannot deploy disabled with the note, never as a choice', async () => {
    asRole('operator');
    certServer([l1, locationFixture({ id: L2, target_name: 'apache-01', target_type: 'apache', deployable: false, cert_path: '/etc/apache2/ssl/www.crt' })]);
    let body: unknown = null;
    server.use(http.post(`/api/v1/certificates/${NEW_ID}/deploy`, async ({ request }) => ((body = await request.json()), HttpResponse.json(accepted([D1, L1]), { status: 202 }))));
    await showDialog({ certificate: NEW_CERT });
    const boxes = await screen.findAllByRole('checkbox');
    expect(boxes.map((b) => (b as HTMLInputElement).disabled)).toEqual([false, true]);
    expect(screen.getByText('Not available for Apache servers yet')).toBeInTheDocument();
    expect(screen.getByText('apache-01')).toBeInTheDocument();
    expect(screen.queryByText('Not supported')).not.toBeInTheDocument();
    await userEvent.click(boxes[1]);
    expect(screen.getByRole('button', { name: 'Deploy' })).toBeDisabled();
    await userEvent.click(boxes[0]);
    await userEvent.click(screen.getByRole('button', { name: 'Deploy' }));
    await waitFor(() => expect(body).not.toBeNull());
    expect(JSON.stringify(body)).not.toContain(L2);
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
    expect(refused).toHaveClass(deploy.refused);
    expect(refused?.getAttribute('style') ?? '').not.toMatch(/border/);
    expect(within(refused).getByText(/names only the first website/)).toBeInTheDocument();
    expect(screen.getByRole('checkbox', { name: /www\.example\.test/ })).toBeChecked();
    expect(screen.getByRole('button', { name: 'Deploy' })).toBeEnabled();
  });

  it('shows a server refusal of the whole request and stays open', async () => {
    asRole('operator');
    certServer([l1]);
    server.use(http.post(`/api/v1/certificates/${NEW_ID}/deploy`, () => errorResponse(403, 'ALC-AUTH-0002', 'auth.forbidden')));
    await showDialog({ certificate: NEW_CERT });
    await userEvent.click(await screen.findByRole('checkbox'));
    await userEvent.click(screen.getByRole('button', { name: 'Deploy' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('You do not have permission to do this.');
    expect(screen.getByRole('button', { name: 'Deploy' })).toBeEnabled();
  });

  it('says when the certificate is not used on any website', async () => {
    asRole('operator');
    certServer([]);
    await showDialog({ certificate: NEW_CERT });
    expect(await screen.findByText(/not used on any website that Alice can deploy to/)).toBeInTheDocument();
  });

  it('opened from a certificate, a Windows place shows the Windows summary', async () => {
    asRole('operator');
    certServer([l1, windowsBindingFixture({ id: 'w9', cert_path: 'http.sys/ipport/0.0.0.0:9443' })]);
    await showDialog({ certificate: NEW_CERT });
    await userEvent.click(await screen.findByRole('checkbox', { name: /0\.0\.0\.0:9443/ }));
    const texts = screen.getAllByText(/^Alice (imports|backs up)/).map((e) => e.textContent ?? '');
    expect(texts).toEqual([expect.stringContaining('into the certificate store of the binding')]);
  });
});

describe('DeployDialog canary (R65)', () => {
  const l1 = locationFixture({ id: L1 });
  const l2 = locationFixture({ id: L2, cert_path: '/etc/nginx/ssl/api.crt', servers: [{ names: ['api.example.test'], listens: [{ addr: '*', port: 443, default_server: false }], file: '/etc/nginx/conf.d/api.conf', line: 2 }] });
  const OWNED = { ...NEW_CERT, service: serviceRef };

  function canaryWorld(canary: CanaryPolicy, answer: object = accepted([D1, L1])) {
    const bodies: unknown[] = [];
    server.use(
      http.get(`/api/v1/certificates/${NEW_ID}`, () => HttpResponse.json(certificateDetailFixture({ id: NEW_ID, service: serviceRef, locations: [l1, l2] }))),
      http.get(`/api/v1/services/${SERVICE_ID}/policy`, () => HttpResponse.json(servicePolicyFixture({ body: { schema: 1, canary } }))),
      http.post(`/api/v1/certificates/${NEW_ID}/deploy`, async ({ request }) => {
        bodies.push(await request.json());
        return HttpResponse.json(answer, { status: 202 });
      }),
      http.get(`/api/v1/deployments/${D1}`, () => HttpResponse.json(deploymentDetailFixture({ id: D1, location_id: L1, status: 'running', state: 'holding', job_status: 'running', finished_at: null }))),
    );
    return bodies;
  }

  async function pickBoth() {
    await showDialog({ certificate: OWNED });
    await userEvent.click(await screen.findByRole('checkbox', { name: /www\.example\.test/ }));
    await userEvent.click(screen.getByRole('checkbox', { name: /api\.example\.test/ }));
  }

  it('says how many go first and how long Alice waits, and tells the canary started', async () => {
    asRole('operator');
    const bodies = canaryWorld(
      { enabled: true, hold: '15m' },
      { ...accepted([D1, L1]), rollout: { id: 'r1', state: 'hold', wave1: [L1], wave2: [L2], settings: { count: 1, percent: 0, hold: '15m', interval: '30s', failures: 2, check: null, override_allowed: true } } },
    );
    await pickBoth();
    expect(await screen.findByTestId('canary-note')).toHaveTextContent('Deploys to 1 website(s) first, then waits 15m before the rest.');
    await userEvent.click(screen.getByRole('button', { name: 'Deploy' }));
    expect(bodies).toEqual([{ location_ids: [L1, L2], confirm_incomplete_chain: false }]);
    expect(await screen.findByTestId('canary-started')).toHaveTextContent('Canary deployment started: 1 website(s) follow once the first wave passed its observation.');
    expect(await screen.findByText('The new certificate is in place and verified; it is under observation before the other websites follow.')).toBeInTheDocument();
  });

  it('sends the override when "Deploy to all at once" is chosen', async () => {
    asRole('operator');
    const bodies = canaryWorld({ enabled: true }, accepted([D1, L1], [D2, L2]));
    server.use(http.get(`/api/v1/deployments/${D2}`, () => HttpResponse.json(deploymentDetailFixture({ id: D2, location_id: L2 }))));
    await pickBoth();
    await userEvent.click(await screen.findByRole('checkbox', { name: /Deploy to all at once/ }));
    expect(screen.queryByTestId('canary-note')).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Deploy' }));
    await waitFor(() => expect(bodies).toEqual([{ location_ids: [L1, L2], confirm_incomplete_chain: false, canary_override: true }]));
  });

  it('offers no override when the policy forbids it, and says nothing for one website or no canary', async () => {
    asRole('operator');
    canaryWorld({ enabled: true, override: 'forbidden' });
    const view = await showDialog({ certificate: OWNED });
    await userEvent.click(await screen.findByRole('checkbox', { name: /www\.example\.test/ }));
    expect(screen.queryByTestId('canary-choice')).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('checkbox', { name: /api\.example\.test/ }));
    expect(await screen.findByTestId('canary-note')).toBeInTheDocument();
    expect(screen.queryByTestId('canary-override')).not.toBeInTheDocument();
    view.unmount();
    canaryWorld({ enabled: false });
    await pickBoth();
    await screen.findByRole('button', { name: 'Deploy' });
    expect(screen.queryByTestId('canary-choice')).not.toBeInTheDocument();
  });
});

describe('DeployDialog request budget with settling runs', () => {
  it('keeps ALL requests of a 20-website batch, settles included, below 150 a minute', async () => {
    asRole('operator');
    const places = Array.from({ length: 20 }, (_, i) => locationFixture({ id: `q${i}`, cert_path: `/etc/nginx/ssl/q${i}.crt` }));
    let all = 0;
    const settledAt: Record<string, number> = {};
    const reads: Record<string, number> = {};
    server.use(
      http.get(`/api/v1/certificates/${NEW_ID}`, () => HttpResponse.json(certificateDetailFixture({ id: NEW_ID, locations: places }))),
      http.post(`/api/v1/certificates/${NEW_ID}/deploy`, () => HttpResponse.json(accepted(...places.map((p, i): [string, string] => [`e${i}`, p.id])), { status: 202 })),
      http.get('/api/v1/deployments/:id', ({ params }) => {
        const id = String(params.id);
        reads[id] = (reads[id] ?? 0) + 1;
        const done = reads[id] >= 2;
        if (done) settledAt[id] = settledAt[id] ?? Date.now();
        return HttpResponse.json(deploymentDetailFixture({ id, status: done ? 'succeeded' : 'running', state: done ? 'done' : 'deploying', job_status: done ? 'succeeded' : 'running', finished_at: null }));
      }),
    );
    server.events.on('request:start', () => {
      all += 1;
    });
    await showDialog({ certificate: NEW_CERT });
    for (const b of await screen.findAllByRole('checkbox')) await userEvent.click(b);
    await userEvent.click(screen.getByRole('button', { name: 'Deploy' }));
    await screen.findAllByRole('list', { name: 'Steps' });
    all = 0;
    await vi.advanceTimersByTimeAsync(60_000);
    server.events.removeAllListeners();
    expect(Object.keys(settledAt).length).toBeGreaterThan(5);
    expect(all).toBeLessThanOrEqual(150);
  }, 30_000);
});

describe('DeployDialog states', () => {
  async function runWith(d: Partial<DeploymentDetail>) {
    asRole('operator');
    certificates([NEW_CERT]);
    server.use(
      http.post(`/api/v1/certificates/${NEW_ID}/deploy`, () => HttpResponse.json(accepted([D1, L1]), { status: 202 })),
      http.get(`/api/v1/deployments/${D1}`, () => HttpResponse.json(deploymentDetailFixture({ id: D1, ...d }))),
    );
    await showDialog({ location: locationFixture({ id: L1 }) });
    await userEvent.selectOptions(await screen.findByLabelText('Certificate'), NEW_ID);
    await userEvent.click(screen.getByRole('button', { name: 'Deploy' }));
  }

  it('says "no change needed" for an unchanged deployment', async () => {
    await runWith({ status: 'unchanged', result: 'unchanged', verified: 'skipped' });
    expect(await screen.findByText('This certificate was already in place. Nothing was changed.')).toBeInTheDocument();
    expect(screen.queryByText('The new certificate is live and verified.')).not.toBeInTheDocument();
  });

  it('says nothing was changed for a failed deployment and shows the error', async () => {
    await runWith({ status: 'failed', error: { code: 'ALC-DEP-0007', reason: 'deployment.config_test_failed' }, steps: [stepFixture(1, 'backup'), stepFixture(2, 'config_test', 'failed')] });
    expect(await screen.findByText('Nothing was changed on the server.')).toBeInTheDocument();
    expect(screen.getByRole('alert')).toHaveTextContent('ALC-DEP-0007');
  });

  it('words rollback_failed by what is known: the files are back but the website is unconfirmed', async () => {
    await runWith({ status: 'rollback_failed', phase: 'restored', backup_dir: '/var/lib/alice-helper/backups/x', error: { code: 'ALC-DEP-0019', reason: 'deployment.restored_unverified' } });
    expect(await screen.findByText(/The previous files are back, but Alice could not confirm that the website serves the previous certificate/)).toBeInTheDocument();
    expect(screen.queryByText(/Automatic restore failed/)).not.toBeInTheDocument();
    expect(screen.getByRole('alert')).toHaveTextContent('ALC-DEP-0019');
  });

  it('words rollback_failed without a restored phase as: Alice cannot confirm which certificate the website serves', async () => {
    await runWith({ status: 'rollback_failed', phase: 'restore_failed', error: { code: 'ALC-DEP-0008', reason: 'deployment.rollback_failed' } });
    expect(await screen.findByText('Alice cannot confirm which certificate the website serves. Manual action is needed.')).toBeInTheDocument();
    expect(screen.queryByText(/The previous files are back/)).not.toBeInTheDocument();
  });

  it('says a job that ended while the record is not final is stopped, and stops polling', async () => {
    await runWith({ status: 'running', state: 'deploying', job_status: 'dead', finished_at: null });
    expect(await screen.findByText(/The background job ended before the deployment did/)).toBeInTheDocument();
  });

  it('says a job that succeeded while the record still runs is being finished, and keeps following', async () => {
    let polls = 0;
    server.use(
      http.get(`/api/v1/deployments/${D1}`, () => {
        polls += 1;
        return HttpResponse.json(deploymentDetailFixture({ id: D1, status: polls < 3 ? 'running' : 'succeeded', state: 'deploying', job_status: 'succeeded', finished_at: null }));
      }),
    );
    asRole('operator');
    certificates([NEW_CERT]);
    server.use(http.post(`/api/v1/certificates/${NEW_ID}/deploy`, () => HttpResponse.json(accepted([D1, L1]), { status: 202 })));
    await showDialog({ location: locationFixture({ id: L1 }) });
    await userEvent.selectOptions(await screen.findByLabelText('Certificate'), NEW_ID);
    await userEvent.click(screen.getByRole('button', { name: 'Deploy' }));
    expect(await screen.findByText('The background job has finished. Alice is recording the result.')).toBeInTheDocument();
    await vi.advanceTimersByTimeAsync(3_000);
    expect(await screen.findByText('The new certificate is live and verified.')).toBeInTheDocument();
  });

  it('moves focus to the progress view when the deployments start', async () => {
    await runWith({ status: 'running', state: 'deploying', job_status: 'running', finished_at: null });
    await screen.findByRole('list', { name: 'Steps' });
    const view = screen.getByRole('list', { name: 'Steps' }).closest('[tabindex="-1"]') as HTMLElement;
    expect(view).toHaveFocus();
  });

  it('forgets the incomplete-chain confirmation when another certificate is chosen', async () => {
    asRole('admin');
    certificates([certificateFixture({ id: NEW_ID, chain_complete: false }), certificateFixture({ id: 'other', chain_complete: false })]);
    await showDialog({ location: locationFixture({ id: L1 }) });
    const select = await screen.findByLabelText('Certificate');
    await userEvent.selectOptions(select, NEW_ID);
    await userEvent.click(await screen.findByLabelText('I confirm that this incomplete chain is intended'));
    expect(screen.getByRole('button', { name: 'Deploy' })).toBeEnabled();
    await userEvent.selectOptions(select, 'other');
    expect(screen.getByLabelText('I confirm that this incomplete chain is intended')).not.toBeChecked();
    expect(screen.getByRole('button', { name: 'Deploy' })).toBeDisabled();
  });

  it('cannot be cancelled or closed while the request is on its way', async () => {
    asRole('operator');
    certificates([NEW_CERT]);
    let release: () => void = () => {};
    const gate = new Promise<void>((r) => (release = r));
    server.use(
      http.post(`/api/v1/certificates/${NEW_ID}/deploy`, async () => {
        await gate;
        return HttpResponse.json(accepted([D1, L1]), { status: 202 });
      }),
      http.get(`/api/v1/deployments/${D1}`, () => HttpResponse.json(deploymentDetailFixture({ id: D1 }))),
    );
    await showDialog({ location: locationFixture({ id: L1 }) });
    await userEvent.selectOptions(await screen.findByLabelText('Certificate'), NEW_ID);
    await userEvent.click(screen.getByRole('button', { name: 'Deploy' }));
    await waitFor(() => expect(screen.getByRole('button', { name: 'Cancel' })).toBeDisabled());
    expect(screen.queryByRole('button', { name: 'Close' })).not.toBeInTheDocument();
    release();
    expect(await screen.findByText('The new certificate is live and verified.')).toBeInTheDocument();
  });

  it('does not offer a key type the server does not deploy when the website does not report one', async () => {
    asRole('operator');
    certificates([certificateFixture({ id: 'ed', key_algorithm: 'ed25519' }), certificateFixture({ id: 'ok', key_algorithm: 'rsa' })]);
    await showDialog({ location: locationFixture({ id: L1, key_type: '' }) });
    const options = within(await screen.findByLabelText('Certificate')).getAllByRole('option').map((o) => o.getAttribute('value'));
    expect(options).toEqual(['', 'ok']);
  });

  it('says when the list of certificates was cut', async () => {
    asRole('operator');
    let page = 0;
    server.use(http.get('/api/v1/certificates', () => HttpResponse.json({ items: [NEW_CERT], next_cursor: String((page += 1)) })));
    await showDialog({ location: locationFixture({ id: L1 }) });
    expect(await screen.findByText(/The list of certificates was cut after 10000 entries/)).toBeInTheDocument();
  });

  it('counts only succeeded deployments as updated, and says which are still open', async () => {
    asRole('operator');
    const l2 = locationFixture({ id: L2, cert_path: '/etc/nginx/ssl/api.crt' });
    server.use(
      http.get(`/api/v1/certificates/${NEW_ID}`, () => HttpResponse.json(certificateDetailFixture({ id: NEW_ID, locations: [locationFixture({ id: L1 }), l2] }))),
      http.post(`/api/v1/certificates/${NEW_ID}/deploy`, () => HttpResponse.json(accepted([D1, L1], [D2, L2]), { status: 202 })),
      http.get(`/api/v1/deployments/${D1}`, () => HttpResponse.json(deploymentDetailFixture({ id: D1, location_id: L1 }))),
      http.get(`/api/v1/deployments/${D2}`, () => HttpResponse.json(deploymentDetailFixture({ id: D2, location_id: L2, status: 'needs_attention', state: 'recovering', finished_at: null }))),
    );
    await showDialog({ certificate: NEW_CERT });
    await userEvent.click(await screen.findAllByRole('checkbox').then((b) => b[0]));
    await userEvent.click(screen.getAllByRole('checkbox')[1]);
    await userEvent.click(screen.getByRole('button', { name: 'Deploy' }));
    expect(await screen.findByText('Updated websites: 1 of 2')).toBeInTheDocument();
    expect(screen.getByText('Websites not finished yet: 1. Follow them in the deployment history.')).toBeInTheDocument();
    expect(screen.queryByText(/Websites that already had this certificate/)).not.toBeInTheDocument();
  });

  it('counts the websites that already had the certificate apart from the updated ones', async () => {
    asRole('operator');
    const ids = [1, 2, 3, 4, 5].map((n) => [`0192c000-0000-7000-8000-0000000000d${n}`, `0192c000-0000-7000-8000-0000000000e${n}`] as [string, string]);
    const locations = ids.map(([, loc], i) => locationFixture({ id: loc, cert_path: `/etc/nginx/ssl/s${i + 1}.crt` }));
    server.use(
      http.get(`/api/v1/certificates/${NEW_ID}`, () => HttpResponse.json(certificateDetailFixture({ id: NEW_ID, locations }))),
      http.post(`/api/v1/certificates/${NEW_ID}/deploy`, () => HttpResponse.json(accepted(...ids), { status: 202 })),
      ...ids.map(([id, loc]) =>
        http.get(`/api/v1/deployments/${id}`, () => HttpResponse.json(deploymentDetailFixture({ id, location_id: loc, status: 'unchanged', result: 'unchanged' }))),
      ),
    );
    await showDialog({ certificate: NEW_CERT });
    for (const box of await screen.findAllByRole('checkbox')) await userEvent.click(box);
    await userEvent.click(screen.getByRole('button', { name: 'Deploy' }));
    expect(await screen.findByText('Updated websites: 0 of 5', {}, { timeout: 10_000 })).toBeInTheDocument();
    expect(screen.getByText('Websites that already had this certificate: 5')).toBeInTheDocument();
    expect(screen.getAllByText('This certificate was already in place. Nothing was changed.')).toHaveLength(5);
  });

  it('does not call an undone earlier change "restored to its previous certificate", and names that change', async () => {
    const op = '0192c000-0000-7000-8000-00000000abcd';
    await runWith({
      status: 'rolled_back',
      phase: 'restored',
      failed_step: 'recover_pending',
      error: { code: 'ALC-DEP-0024', reason: 'deployment.pending_change_restored', params: { operation_id: op } },
      steps: [stepFixture(1, 'recover_pending', 'started', { operation_id: op }), stepFixture(2, 'recover_pending', 'ok', { operation_id: op })],
    });
    expect(await screen.findByText(/The new certificate was not written\. Alice put back the files from before an unfinished earlier change/)).toBeInTheDocument();
    expect(screen.queryByText('Your server was restored to its previous certificate.')).not.toBeInTheDocument();
    const alert = screen.getByRole('alert');
    expect(alert).toHaveTextContent('ALC-DEP-0024');
    expect(within(alert).getByText(op).tagName).toBe('CODE');
    expect(within(alert).getByText(op)).toHaveAttribute('translate', 'no');
    expect(alert).toHaveTextContent('Unfinished earlier change on the server (operation ID):');
  });

  it('does not say "nothing was changed" when an unfinished earlier change blocks the files (ALC-DEP-0023)', async () => {
    const op = '0192c000-0000-7000-8000-00000000abcd';
    await runWith({ status: 'failed', failed_step: 'recover_pending', error: { code: 'ALC-DEP-0023', reason: 'deployment.server_operation_pending', params: { operation_id: op } } });
    expect(await screen.findByText('The new certificate was not written. An unfinished earlier change on the server blocks these files; see below.')).toBeInTheDocument();
    expect(screen.queryByText('Nothing was changed on the server.')).not.toBeInTheDocument();
    expect(within(screen.getByRole('alert')).getByText(op)).toBeInTheDocument();
  });

  it('shows a deployment an administrator cancelled as cancelled, without a failure alert', async () => {
    await runWith({ status: 'failed', error: { code: 'ALC-DEP-0022', reason: 'deployment.cancelled' } });
    expect(await screen.findByText('Nothing was changed on the server.')).toBeInTheDocument();
    expect(screen.getByText('An administrator cancelled this deployment before anything was sent to the server.')).toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('follows 20 websites with one loop, far below the session request limit', async () => {
    asRole('operator');
    const places = Array.from({ length: 20 }, (_, i) => locationFixture({ id: `p${i}`, cert_path: `/etc/nginx/ssl/${i}.crt` }));
    let reads = 0;
    server.use(
      http.get(`/api/v1/certificates/${NEW_ID}`, () => HttpResponse.json(certificateDetailFixture({ id: NEW_ID, locations: places }))),
      http.post(`/api/v1/certificates/${NEW_ID}/deploy`, () => HttpResponse.json(accepted(...places.map((p, i): [string, string] => [`d${i}`, p.id])), { status: 202 })),
      http.get('/api/v1/deployments/:id', ({ params }) => {
        reads += 1;
        return HttpResponse.json(deploymentDetailFixture({ id: String(params.id), status: 'running', state: 'deploying', job_status: 'running', finished_at: null }));
      }),
    );
    await showDialog({ certificate: NEW_CERT });
    for (const b of await screen.findAllByRole('checkbox')) await userEvent.click(b);
    await userEvent.click(screen.getByRole('button', { name: 'Deploy' }));
    await screen.findAllByRole('list', { name: 'Steps' });
    reads = 0;
    await vi.advanceTimersByTimeAsync(60_000);
    expect(reads).toBeLessThanOrEqual(125);
    expect(reads).toBeGreaterThan(40);
  }, 30_000);
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
    server.use(http.get(`/api/v1/deployments/${D1}`, () => ((polls += 1), HttpResponse.json(deploymentDetailFixture({ id: D1, status: 'running', state: 'deploying', job_status: 'running', finished_at: null })))));
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
    expect(await screen.findByText(/Your browser cannot reach Alice right now/)).toBeInTheDocument();
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
            job_status: 'failed',
            finished_at: null,
          }),
        );
      }),
    );
    await start();
    expect(await screen.findByText('Alice has not yet confirmed how this deployment ended. It is checking the server and will finish or undo the change.')).toBeInTheDocument();
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
    server.use(http.get(`/api/v1/deployments/${D1}`, () => ((polls += 1), HttpResponse.json(deploymentDetailFixture({ id: D1, status: 'running', state: 'deploying', job_status: 'running', finished_at: null })))));
    await start();
    await screen.findByRole('list', { name: 'Steps' });
    await userEvent.click(screen.getAllByRole('button', { name: 'Close' })[1]);
    const seen = polls;
    await vi.advanceTimersByTimeAsync(10_000);
    expect(polls).toBe(seen);
  });
});

// R61, design §15 Q5 (W2 Ruling 21): from a binding of a Windows server the dialog picks among the server's bindings,
// grouped by the certificate they serve, and selects all bindings of one certificate at once.
describe('DeployDialog on a Windows server', () => {
  const SERVED = { id: '0192c000-0000-7000-8000-0000000000c1', subject_cn: 'www.example.test', label: '', fingerprint: 'ab12'.repeat(16), not_after: '2027-09-01T00:00:00Z' };
  const OTHER = { ...SERVED, id: '0192c000-0000-7000-8000-0000000000c2', subject_cn: 'api.example.test', fingerprint: 'ef56'.repeat(16) };
  const W1 = windowsBindingFixture({ id: L1, cert_path: 'http.sys/ipport/0.0.0.0:8443', certificate: SERVED });
  const W2 = windowsBindingFixture({ id: L2, cert_path: 'http.sys/hostnameport/www.example.test:443', certificate: SERVED });
  const W3 = windowsBindingFixture({ id: 'w3', cert_path: 'http.sys/hostnameport/api.example.test:443', certificate: OTHER });
  const W4 = windowsBindingFixture({ id: 'w4', cert_path: 'http.sys/hostnameport/old.example.test:443', certificate: null });
  const busy = windowsBindingFixture({ id: 'w5', cert_path: 'http.sys/ipport/0.0.0.0:9443', certificate: SERVED, active_deployment_id: D2 });
  const siblings = [W3, W4, W1, busy, W2];

  it('shows the bindings grouped by certificate and "Select all bindings of this certificate" selects exactly that group', async () => {
    asRole('operator');
    certificates([NEW_CERT]);
    let body: unknown = null;
    server.use(
      http.post(`/api/v1/certificates/${NEW_ID}/deploy`, async ({ request }) => {
        body = await request.json();
        return HttpResponse.json(accepted([D1, L2], [D2, L1]), { status: 202 });
      }),
      http.get('/api/v1/deployments/:id', ({ params }) => HttpResponse.json(windowsDeploymentFixture({ id: String(params.id), location_id: params.id === D1 ? L2 : L1 }))),
    );
    await showDialog({ location: W3, siblings });
    expect(await screen.findByText(/Alice imports the certificate into the certificate store of the binding/)).toBeInTheDocument();
    const groups = screen.getAllByTestId('deploy-certificate-group');
    expect(groups.map((g) => within(g).getByRole('heading').textContent)).toEqual(['api.example.test', 'www.example.test', 'No certificate']);
    const box = (path: string) => screen.getByRole('checkbox', { name: new RegExp(path.replace(/[./]/g, '\\$&')) });
    expect(box(W3.cert_path)).toBeChecked();
    expect(box(busy.cert_path)).toBeDisabled();
    expect(screen.queryByRole('button', { name: /Select all bindings of this certificate: No certificate/ })).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Select all bindings of this certificate: www.example.test' }));
    expect(box(W1.cert_path)).toBeChecked();
    expect(box(W2.cert_path)).toBeChecked();
    expect(box(W3.cert_path)).not.toBeChecked();
    expect(box(W4.cert_path)).not.toBeChecked();
    expect(box(busy.cert_path)).not.toBeChecked();
    await userEvent.selectOptions(await screen.findByLabelText('Certificate'), NEW_ID);
    await userEvent.click(screen.getByRole('button', { name: 'Deploy' }));
    expect(body).toEqual({ location_ids: [L2, L1], confirm_incomplete_chain: false });
    const lists = await screen.findAllByRole('list', { name: 'Steps' });
    expect(lists).toHaveLength(2);
    for (const name of ['Import the chain', 'Import the certificate', 'Bind', 'Verify']) expect(within(lists[0]).getByText(name)).toBeInTheDocument();
    expect(within(lists[0]).queryByText('Backup')).not.toBeInTheDocument();
  });

  it('describes a CCS file deployment as a file written with a backup, not as a binding change (R68)', async () => {
    asRole('operator');
    certificates([NEW_CERT]);
    const file = windowsCCSFileFixture({ id: 'c1', certificate: OTHER });
    server.use(
      http.post(`/api/v1/certificates/${NEW_ID}/deploy`, () => HttpResponse.json(accepted([D1, 'c1']), { status: 202 })),
      http.get('/api/v1/deployments/:id', ({ params }) => HttpResponse.json(ccsDeploymentFixture({ id: String(params.id), location_id: 'c1' }))),
    );
    await showDialog({ location: file, siblings: [W1, file] });
    expect(await screen.findByText(/keeping a backup of the previous file beside it in the Centralized Certificate Store folder/)).toBeInTheDocument();
    expect(screen.queryByText(/points the binding/)).not.toBeInTheDocument();
    expect(screen.getByRole('group', { name: 'Bindings and files' })).toBeInTheDocument();
    expect(screen.getByRole('checkbox', { name: /C:\\CCS\\ccs\.example\.test\.pfx/ })).toBeChecked();
    await userEvent.selectOptions(await screen.findByLabelText('Certificate'), NEW_ID);
    await userEvent.click(screen.getByRole('button', { name: 'Deploy' }));
    const list = await screen.findByRole('list', { name: 'Steps' });
    for (const name of ['Import the chain', 'Write the file', 'Verify']) expect(within(list).getByText(name)).toBeInTheDocument();
    expect(within(list).queryByText('Bind')).not.toBeInTheDocument();
  });

  it('offers the Remote Desktop listener like a binding and names the listener in the summary (R69)', async () => {
    asRole('operator');
    certificates([NEW_CERT]);
    const rdp = windowsRDPFixture({ id: 'r1', certificate: OTHER });
    server.use(
      http.post(`/api/v1/certificates/${NEW_ID}/deploy`, () => HttpResponse.json(accepted([D1, 'r1']), { status: 202 })),
      http.get('/api/v1/deployments/:id', ({ params }) => HttpResponse.json(rdpDeploymentFixture({ id: String(params.id), location_id: 'r1' }))),
    );
    await showDialog({ location: rdp, siblings: [W1, rdp] });
    expect(await screen.findByText(/points the Remote Desktop listener \(RDP-Tcp\) to the new certificate/)).toBeInTheDocument();
    expect(screen.getByText(/gives NETWORK SERVICE, the account Remote Desktop runs as, read access to the new private key/)).toBeInTheDocument();
    expect(screen.getByText(/points the listener back to the previous certificate/)).toBeInTheDocument();
    expect(screen.queryByText(/points the binding/)).not.toBeInTheDocument();
    expect(screen.getByRole('group', { name: 'Where to deploy' })).toBeInTheDocument();
    expect(screen.getByRole('checkbox', { name: /Remote Desktop \(RDP-Tcp\).*rdp\/RDP-Tcp/ })).toBeChecked();
    expect(screen.getByRole('checkbox', { name: /0\.0\.0\.0:8443/ })).not.toBeChecked();
    await userEvent.selectOptions(await screen.findByLabelText('Certificate'), NEW_ID);
    await userEvent.click(screen.getByRole('button', { name: 'Deploy' }));
    const list = await screen.findByRole('list', { name: 'Steps' });
    for (const name of ['Import the chain', 'Import the certificate', 'Allow NETWORK SERVICE to read the key', 'Point the listener to the certificate', 'Verify'])
      expect(within(list).getByText(name)).toBeInTheDocument();
    expect(within(list).queryByText('Bind')).not.toBeInTheDocument();
  });

  it('adds the listener summary when the listener is ticked beside the binding the dialog was opened from (R69)', async () => {
    asRole('operator');
    certificates([NEW_CERT]);
    const rdp = windowsRDPFixture({ id: 'r1', certificate: OTHER });
    await showDialog({ location: W1, siblings: [W1, rdp] });
    expect(await screen.findByText(/points the binding to the new certificate/)).toBeInTheDocument();
    expect(screen.queryByText(/gives NETWORK SERVICE/)).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('checkbox', { name: /rdp\/RDP-Tcp/ }));
    expect(screen.getByText(/gives NETWORK SERVICE, the account Remote Desktop runs as, read access to the new private key/)).toBeInTheDocument();
    expect(screen.getByText(/points the binding to the new certificate/)).toBeInTheDocument();
  });

  it('names the application of a foreign binding (C4, R70)', async () => {
    asRole('operator');
    certificates([NEW_CERT]);
    const winrm = windowsBindingFixture({ id: 'wf1', cert_path: 'http.sys/ipport/0.0.0.0:5986', certificate: SERVED, supported: false, unsupported_reason: 'win_foreign_app', details: { application: 'winrm', app_id: '{4dc3e181-e14b-4a21-b022-59fc669b0914}' } });
    const unknown = windowsBindingFixture({ id: 'wf2', cert_path: 'http.sys/ipport/0.0.0.0:49443', certificate: SERVED, supported: false, unsupported_reason: 'win_foreign_app', details: { app_id: '{5d89a20c-beab-4389-9447-324788eb944a}' } });
    await showDialog({ location: W1, siblings: [W1, winrm, unknown] });
    expect(await screen.findByText('This binding belongs to another application (WinRM). Alice does not change it.')).toBeInTheDocument();
    expect(screen.getByText('This binding belongs to another application with the id {5d89a20c-beab-4389-9447-324788eb944a}. Alice does not change it.')).toBeInTheDocument();
    expect(screen.queryByText(/\{\{/)).not.toBeInTheDocument();
    expect(screen.getByRole('checkbox', { name: /0\.0\.0\.0:5986/ })).toBeDisabled();
  });

  it('shows one summary per kind of place, the opening kind first (W5-12c, R70)', async () => {
    asRole('operator');
    certificates([NEW_CERT]);
    const file = windowsCCSFileFixture({ id: 'c1', certificate: SERVED });
    const rdp = windowsRDPFixture({ id: 'r1', certificate: SERVED });
    const summaries = () => screen.getAllByText(/^Alice imports/).map((e) => e.textContent ?? '');
    await showDialog({ location: W1, siblings: [W1, file, rdp] });
    await screen.findByText(/points the binding to the new certificate/);
    expect(summaries()).toEqual([expect.stringContaining('into the certificate store of the binding')]);
    await userEvent.click(screen.getByRole('button', { name: 'Select all places of this certificate: www.example.test' }));
    expect(summaries()).toEqual([
      expect.stringContaining('into the certificate store of the binding'),
      expect.stringContaining('intermediate certificates into the server'),
      expect.stringContaining("into the server's Personal (My) store"),
    ]);
    screen.getByText(/keeping a backup of the previous file/);
    screen.getByText(/gives NETWORK SERVICE/);
  });

  it('puts the listener summary first when opened from the listener with a binding ticked (W5-12c, R70)', async () => {
    asRole('operator');
    certificates([NEW_CERT]);
    const rdp = windowsRDPFixture({ id: 'r1', certificate: OTHER });
    await showDialog({ location: rdp, siblings: [W1, rdp] });
    await screen.findByText(/gives NETWORK SERVICE/);
    await userEvent.click(screen.getByRole('checkbox', { name: /0\.0\.0\.0:8443/ }));
    const texts = screen.getAllByText(/^Alice imports/).map((e) => e.textContent ?? '');
    expect(texts).toHaveLength(2);
    expect(texts[0]).toContain("into the server's Personal (My) store");
    expect(texts[1]).toContain('into the certificate store of the binding');
  });

  it('an unticked opening binding leaves no summary of its kind', async () => {
    asRole('operator');
    certificates([NEW_CERT]);
    const file = windowsCCSFileFixture({ id: 'c1', certificate: SERVED });
    await showDialog({ location: W1, siblings: [W1, file] });
    await screen.findByText(/points the binding to the new certificate/);
    await userEvent.click(screen.getByRole('checkbox', { name: /0\.0\.0\.0:8443/ }));
    await userEvent.click(screen.getByRole('checkbox', { name: /ccs\.example\.test\.pfx/ }));
    const texts = screen.getAllByText(/^Alice imports/).map((e) => e.textContent ?? '');
    expect(texts).toEqual([expect.stringContaining('intermediate certificates into the server')]);
    expect(screen.queryByText(/points the binding to the new certificate/)).not.toBeInTheDocument();
  });

  it('says "places" for the select-all of a group that holds a CCS file, "bindings" for one of bindings only (W5-12d, R70)', async () => {
    asRole('operator');
    certificates([NEW_CERT]);
    const file = windowsCCSFileFixture({ id: 'c1', certificate: SERVED });
    await showDialog({ location: W1, siblings: [W3, W1, file] });
    await screen.findByText(/points the binding to the new certificate/);
    expect(screen.getByRole('button', { name: 'Select all places of this certificate: www.example.test' })).toHaveTextContent('Select all places of this certificate');
    expect(screen.getByRole('button', { name: 'Select all bindings of this certificate: api.example.test' })).toHaveTextContent('Select all bindings of this certificate');
    await userEvent.click(screen.getByRole('button', { name: 'Select all places of this certificate: www.example.test' }));
    expect(screen.getByRole('checkbox', { name: /ccs\.example\.test\.pfx/ })).toBeChecked();
  });

  it('keeps the binding wording when no CCS file is among the siblings', async () => {
    asRole('operator');
    certificates([NEW_CERT]);
    await showDialog({ location: W1, siblings });
    expect(await screen.findByText(/points the binding to the new certificate/)).toBeInTheDocument();
    expect(screen.getByRole('group', { name: 'Bindings' })).toBeInTheDocument();
  });

  it('cannot deploy when every binding is unticked', async () => {
    asRole('operator');
    certificates([NEW_CERT]);
    await showDialog({ location: W1, siblings });
    await userEvent.selectOptions(await screen.findByLabelText('Certificate'), NEW_ID);
    expect(screen.getByRole('button', { name: 'Deploy' })).toBeEnabled();
    await userEvent.click(screen.getByRole('checkbox', { name: /0\.0\.0\.0:8443/ }));
    expect(screen.getByRole('button', { name: 'Deploy' })).toBeDisabled();
  });

  it('names each certificate group as a group with a level-3 heading below the dialog title', async () => {
    asRole('operator');
    certificates([NEW_CERT]);
    await showDialog({ location: W1, siblings });
    const group = await screen.findByRole('group', { name: 'www.example.test' });
    expect(within(group).getByRole('heading', { level: 3, name: 'www.example.test' })).toBeInTheDocument();
    expect(screen.getByRole('group', { name: 'No certificate' })).toBeInTheDocument();
  });

  it('says why a chosen certificate no longer fits when a binding of another key type is ticked', async () => {
    asRole('operator');
    certificates([NEW_CERT]);
    const rsa = windowsBindingFixture({ id: 'w-rsa', cert_path: 'http.sys/ipport/0.0.0.0:7443', certificate: SERVED, key_type: 'rsa' });
    await showDialog({ location: W1, siblings: [...siblings, rsa] });
    await userEvent.selectOptions(await screen.findByLabelText('Certificate'), NEW_ID);
    expect(screen.getByRole('button', { name: 'Deploy' })).toBeEnabled();
    await userEvent.click(screen.getByRole('checkbox', { name: /0\.0\.0\.0:7443/ }));
    expect(screen.getByText('The chosen certificate does not fit every ticked binding (another key type). Choose another certificate or untick that binding.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Deploy' })).toBeDisabled();
    await userEvent.click(screen.getByRole('checkbox', { name: /0\.0\.0\.0:7443/ }));
    expect(screen.queryByText(/does not fit every ticked binding/)).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Deploy' })).toBeEnabled();
  });

  it('keeps a Linux website a single place without the picker', async () => {
    asRole('operator');
    certificates([NEW_CERT]);
    await showDialog({ location: locationFixture({ id: L1, key_type: 'ecdsa' }), siblings: [locationFixture({ id: L1, key_type: 'ecdsa' }), locationFixture({ id: L2, key_type: 'ecdsa' })] });
    await screen.findByLabelText('Certificate');
    expect(screen.queryByTestId('deploy-certificate-group')).not.toBeInTheDocument();
    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
  });
});
