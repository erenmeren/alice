import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import {
  bindingFixture,
  bindingLocationFixture,
  BINDING_ID,
  deploymentDetailFixture,
  errorResponse,
  kvCertificateDetailFixture,
  kvVersionFixture,
  SERVICE_ID,
  serviceRef,
  servicePolicyFixture,
  targetFixture,
  VAULT_ID,
  sessionFor,
  sessionHandlers,
  stepFixture,
  windowsDeploymentFixture,
} from '../test/fixtures';
import { expectNoRawKeys } from '../test/i18nAssert';
import { renderWithStepUp } from '../test/render';
import { server } from '../test/server';
import { KVDeployDialog } from './KVDeployDialog';
import { targetKey } from '../api/queryKeys';
import deploy from './deploy.module.css';

const V_NEW = kvVersionFixture({ id: 'v-new', version: 'aaaaaaaa11111111aaaaaaaa11111111', detected_at: '2026-10-05T00:00:00Z' });
const V_OLD = kvVersionFixture({ id: 'v-old', version: 'bbbbbbbb22222222bbbbbbbb22222222', detected_at: '2026-09-01T00:00:00Z' });
const L2 = bindingLocationFixture({ location_id: 'loc-2', target_name: 'web-02', cert_path: '/etc/nginx/ssl/two.crt' });
const BINDING = bindingFixture({ locations: [bindingLocationFixture(), L2], location_count: 2 });

function cert(versions = [V_NEW, V_OLD], current = V_NEW.version) {
  return kvCertificateDetailFixture({ versions, current_version: current, binding: { id: BINDING_ID, auto_deploy: false, auto_since: null, stopped_version: '', location_count: 2, version: 2, created_at: '' } });
}

function asRole(role: 'admin' | 'operator', lang = 'en') {
  server.use(...sessionHandlers(sessionFor(role, lang)));
}

function accepted(...ids: [string, string][]) {
  return { deployments: ids.map(([id, loc]) => ({ id, job_id: `j-${id}`, location_id: loc, status_url: '', deployment_url: `/api/v1/deployments/${id}`, warnings: [] as string[] })) };
}

describe('KVDeployDialog', () => {
  it('defaults to the current version and all the websites, and posts version_id and location_ids', async () => {
    asRole('operator');
    let body: unknown = null;
    server.use(
      http.post(`/api/v1/bindings/${BINDING_ID}/actions/deploy`, async ({ request }) => {
        body = await request.json();
        return HttpResponse.json(accepted(['d1', bindingLocationFixture().location_id], ['d2', 'loc-2']), { status: 202 });
      }),
      http.get('/api/v1/deployments/:id', ({ params }) =>
        HttpResponse.json(deploymentDetailFixture({ id: String(params.id), source: 'key_vault', vault_name: 'Prod vault', steps: [stepFixture(1, 'kv_secret'), stepFixture(2, 'backup')] })),
      ),
    );
    await renderWithStepUp(<KVDeployDialog binding={BINDING} certificate={cert()} onClose={vi.fn()} />);
    const select = screen.getByLabelText('Version') as HTMLSelectElement;
    expect(select.value).toBe('v-new');
    expect(within(select).getAllByRole('option')).toHaveLength(2);
    expect(screen.getAllByRole('checkbox').every((c) => (c as HTMLInputElement).checked)).toBe(true);
    await userEvent.click(screen.getByRole('button', { name: 'Deploy now' }));
    expect(body).toEqual({ version_id: 'v-new', location_ids: [bindingLocationFixture().location_id, 'loc-2'] });
    const runs = await screen.findAllByTestId('deployment-run');
    expect(runs).toHaveLength(2);
    for (const run of runs) expect(run).toHaveClass(deploy.separated);
    expect(within(runs[0]).getByText('Read the certificate from Key Vault')).toBeInTheDocument();
    expect(within(runs[0]).getByRole('link', { name: 'Open this deployment' })).toHaveAttribute('href', '/deployments/d1');
  });

  // R61, R62 Ruling 18: the steps are listed once the deployment is read; its location_kind decides, not the text of the location.
  it('shows the Windows steps for a deployment whose location_kind is win_sslbinding', async () => {
    asRole('operator');
    const win = bindingLocationFixture({ location_id: 'loc-w', target_name: 'web-iis', cert_path: 'http.sys/hostnameport/www.example.test:443' });
    server.use(
      http.post(`/api/v1/bindings/${BINDING_ID}/actions/deploy`, () => HttpResponse.json(accepted(['dw', 'loc-w']), { status: 202 })),
      http.get('/api/v1/deployments/:id', () => HttpResponse.json(windowsDeploymentFixture({ id: 'dw', status: 'running', state: 'deploying', finished_at: null }))),
    );
    await renderWithStepUp(<KVDeployDialog binding={bindingFixture({ locations: [win], location_count: 1 })} certificate={cert()} onClose={vi.fn()} />);
    await userEvent.click(screen.getByRole('button', { name: 'Deploy now' }));
    const run = await screen.findByTestId('deployment-run');
    for (const name of ['Import the chain', 'Import the certificate', 'Bind', 'Verify']) expect(await within(run).findByText(name)).toBeInTheDocument();
    expect(within(run).queryByText('Backup')).not.toBeInTheDocument();
  });

  it('does not take a location whose text starts with http.sys/ for Windows when the deployment is a file one', async () => {
    asRole('operator');
    const odd = bindingLocationFixture({ location_id: 'loc-o', cert_path: 'http.sys/hostnameport/www.example.test:443' });
    server.use(
      http.post(`/api/v1/bindings/${BINDING_ID}/actions/deploy`, () => HttpResponse.json(accepted(['do', 'loc-o']), { status: 202 })),
      http.get('/api/v1/deployments/:id', () => HttpResponse.json(deploymentDetailFixture({ id: 'do', status: 'running', state: 'deploying', finished_at: null }))),
    );
    await renderWithStepUp(<KVDeployDialog binding={bindingFixture({ locations: [odd], location_count: 1 })} certificate={cert()} onClose={vi.fn()} />);
    await userEvent.click(screen.getByRole('button', { name: 'Deploy now' }));
    const run = await screen.findByTestId('deployment-run');
    expect(await within(run).findByText('Backup')).toBeInTheDocument();
    expect(within(run).queryByText('Import the chain')).not.toBeInTheDocument();
  });

  it('defaults to the CURRENT version even when it is not the first in the list', async () => {
    asRole('operator');
    await renderWithStepUp(<KVDeployDialog binding={BINDING} certificate={cert([V_NEW, V_OLD], V_OLD.version)} onClose={vi.fn()} />);
    expect((screen.getByLabelText('Version') as HTMLSelectElement).value).toBe('v-old');
  });

  it('deploys an older version to some websites only', async () => {
    asRole('operator');
    let body: unknown = null;
    server.use(
      http.post(`/api/v1/bindings/${BINDING_ID}/actions/deploy`, async ({ request }) => { body = await request.json(); return HttpResponse.json(accepted(['d1', 'loc-2']), { status: 202 }); }),
      http.get('/api/v1/deployments/d1', () => HttpResponse.json(deploymentDetailFixture({ id: 'd1' }))),
    );
    const user = userEvent.setup();
    await renderWithStepUp(<KVDeployDialog binding={BINDING} certificate={cert()} versionId="v-old" onClose={vi.fn()} />);
    expect((screen.getByLabelText('Version') as HTMLSelectElement).value).toBe('v-old');
    await user.click(screen.getByRole('checkbox', { name: /web-01/ }));
    await user.click(screen.getByRole('button', { name: 'Deploy now' }));
    expect(await screen.findByTestId('deployment-run')).not.toHaveClass(deploy.separated);
    expect(body).toEqual({ version_id: 'v-old', location_ids: ['loc-2'] });
  });

  it.each([
    ['no details', { certificate_id: null }, 'Alice has not read the details of this version yet.'],
    ['disabled', { enabled: false }, 'This version is disabled in Key Vault.'],
    ['expired', { expires: '2020-01-01T00:00:00Z' }, 'This version has expired.'],
    ['not yet valid', { not_before: '2099-01-01T00:00:00Z' }, 'This version is not valid yet.'],
    ['not exportable', { exportable: false }, 'The private key of this version is not exportable.'],
  ] as const)('refuses a version with %s and says why', async (_n, patch, text) => {
    asRole('admin');
    await renderWithStepUp(<KVDeployDialog binding={BINDING} certificate={cert([{ ...V_NEW, ...patch }], V_NEW.version)} onClose={vi.fn()} />);
    expect(screen.getByRole('alert')).toHaveTextContent(text);
    expect(screen.getByRole('button', { name: 'Deploy now' })).toBeDisabled();
  });

  it('lets only an Administrator deploy a held version, with a step-up, and says holding stays', async () => {
    const held = { ...V_NEW, held: true, held_reason: 'license' as const };
    asRole('operator');
    const view = await renderWithStepUp(<KVDeployDialog binding={BINDING} certificate={cert([held])} onClose={vi.fn()} />);
    expect(screen.getByText('This version is held. Only an administrator can deploy it.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Deploy now' })).toBeDisabled();
    view.unmount();

    asRole('admin');
    let calls = 0;
    server.use(
      http.post(`/api/v1/bindings/${BINDING_ID}/actions/deploy`, () => (++calls === 1 ? errorResponse(403, 'ALC-AUTH-0003', 'auth.stepup_required') : HttpResponse.json(accepted(['d1', 'loc-2']), { status: 202 }))),
      http.post('/api/v1/auth/stepup', () => HttpResponse.json(sessionFor('admin'))),
      http.get('/api/v1/deployments/d1', () => HttpResponse.json(deploymentDetailFixture({ id: 'd1' }))),
    );
    const user = userEvent.setup();
    await renderWithStepUp(<KVDeployDialog binding={BINDING} certificate={cert([held])} onClose={vi.fn()} />);
    expect(await screen.findByText('This version is held. Deploying it does not release it; use Release for that.')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Deploy now' }));
    await user.type(await screen.findByLabelText('6-digit code'), '123456');
    await user.click(screen.getByRole('button', { name: 'Confirm' }));
    await screen.findByTestId('deployment-run');
    expect(calls).toBe(2);
  });

  it('offers the incomplete-chain confirmation for a version held for it, to an Administrator only', async () => {
    const held = { ...V_NEW, held: true, held_reason: 'incomplete_chain' as const };
    asRole('admin');
    let body: unknown = null;
    server.use(
      http.post(`/api/v1/bindings/${BINDING_ID}/actions/deploy`, async ({ request }) => { body = await request.json(); return HttpResponse.json(accepted(['d1', 'loc-2']), { status: 202 }); }),
      http.get('/api/v1/deployments/d1', () => HttpResponse.json(deploymentDetailFixture({ id: 'd1' }))),
    );
    const user = userEvent.setup();
    await renderWithStepUp(<KVDeployDialog binding={BINDING} certificate={cert([held])} onClose={vi.fn()} />);
    const confirm = await screen.findByLabelText('I confirm that this incomplete chain is intended');
    expect(screen.getByRole('button', { name: 'Deploy now' })).toBeDisabled();
    await user.click(confirm);
    await user.click(screen.getByRole('button', { name: 'Deploy now' }));
    await screen.findByTestId('deployment-run');
    expect(body).toEqual({ version_id: 'v-new', location_ids: [bindingLocationFixture().location_id, 'loc-2'], confirm_incomplete_chain: true });
  });

  it.each([
    ['released (not held)', { held: false, held_reason: '' as const }],
    ['held for the license', { held: true, held_reason: 'license' as const }],
  ])('offers the chain confirmation up front for a version whose chain a read found incomplete, %s', async (_, hold) => {
    const v = { ...V_NEW, ...hold, chain_incomplete: true };
    asRole('admin');
    let body: unknown = null;
    server.use(
      http.post(`/api/v1/bindings/${BINDING_ID}/actions/deploy`, async ({ request }) => { body = await request.json(); return HttpResponse.json(accepted(['d1', 'loc-2']), { status: 202 }); }),
      http.get('/api/v1/deployments/d1', () => HttpResponse.json(deploymentDetailFixture({ id: 'd1' }))),
    );
    const user = userEvent.setup();
    await renderWithStepUp(<KVDeployDialog binding={BINDING} certificate={cert([v])} onClose={vi.fn()} />);
    const confirm = await screen.findByLabelText('I confirm that this incomplete chain is intended');
    expect(screen.getByRole('button', { name: 'Deploy now' })).toBeDisabled();
    await user.click(confirm);
    await user.click(screen.getByRole('button', { name: 'Deploy now' }));
    await screen.findByTestId('deployment-run');
    expect(body).toEqual({ version_id: 'v-new', location_ids: [bindingLocationFixture().location_id, 'loc-2'], confirm_incomplete_chain: true });
  });

  it('tells an Operator up front that a version with an incomplete chain needs an administrator, and sends nothing', async () => {
    asRole('operator');
    let calls = 0;
    server.use(http.post(`/api/v1/bindings/${BINDING_ID}/actions/deploy`, () => { calls++; return HttpResponse.json(accepted(), { status: 202 }); }));
    await renderWithStepUp(<KVDeployDialog binding={BINDING} certificate={cert([{ ...V_NEW, chain_incomplete: true }])} onClose={vi.fn()} />);
    expect(await screen.findByText(/An administrator can deploy it after confirming the chain/)).toBeInTheDocument();
    expect(screen.queryByLabelText('I confirm that this incomplete chain is intended')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Deploy now' })).toBeDisabled();
    expect(calls).toBe(0);
  });

  it('offers no chain confirmation until the server asks for it, and only to an Administrator', async () => {
    server.use(http.post(`/api/v1/bindings/${BINDING_ID}/actions/deploy`, () => errorResponse(409, 'ALC-CRT-0011', 'certificate.chain_unconfirmed')));
    asRole('admin');
    const user = userEvent.setup();
    const view = await renderWithStepUp(<KVDeployDialog binding={BINDING} certificate={cert()} onClose={vi.fn()} />);
    expect(screen.queryByLabelText('I confirm that this incomplete chain is intended')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Deploy now' }));
    expect(await screen.findByLabelText('I confirm that this incomplete chain is intended')).toBeInTheDocument();
    // The server asked about THAT version: another version picked does not inherit the request.
    await user.selectOptions(screen.getByLabelText('Version'), 'v-old');
    expect(screen.queryByLabelText('I confirm that this incomplete chain is intended')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Deploy now' })).toBeEnabled();
    view.unmount();

    asRole('operator');
    await renderWithStepUp(<KVDeployDialog binding={BINDING} certificate={cert()} onClose={vi.fn()} />);
    await user.click(screen.getByRole('button', { name: 'Deploy now' }));
    expect(await screen.findByText(/An administrator can deploy it after confirming the chain/)).toBeInTheDocument();
    expect(screen.queryByLabelText('I confirm that this incomplete chain is intended')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Deploy now' }), 'the same request would be refused again').toBeDisabled();
  });

  it('highlights the website a refusal names', async () => {
    asRole('operator');
    server.use(http.post(`/api/v1/bindings/${BINDING_ID}/actions/deploy`, () => errorResponse(409, 'ALC-DEP-0001', 'deployment.in_progress', { params: { location_id: 'loc-2' } })));
    await renderWithStepUp(<KVDeployDialog binding={BINDING} certificate={cert()} onClose={vi.fn()} />);
    await userEvent.click(screen.getByRole('button', { name: 'Deploy now' }));
    await waitFor(() => expect(document.querySelector('[data-refused="true"]')).toHaveTextContent('web-02'));
    expect(document.querySelector('[data-refused="true"]')).toHaveClass(deploy.refused);
    expect(document.querySelector('[data-refused="true"]')?.getAttribute('style') ?? '').not.toMatch(/border/);
  });

  it('says a canary goes first for the vault service and sends the override when chosen (R65)', async () => {
    asRole('operator');
    const bodies: unknown[] = [];
    server.use(
      http.get(`/api/v1/services/${SERVICE_ID}/policy`, () => HttpResponse.json(servicePolicyFixture({ body: { schema: 1, canary: { enabled: true, hold: '20m' } } }))),
      http.post(`/api/v1/bindings/${BINDING_ID}/actions/deploy`, async ({ request }) => {
        bodies.push(await request.json());
        return HttpResponse.json(accepted(['d1', bindingLocationFixture().location_id], ['d2', 'loc-2']), { status: 202 });
      }),
      http.get('/api/v1/deployments/:id', ({ params }) => HttpResponse.json(deploymentDetailFixture({ id: String(params.id), source: 'key_vault' }))),
    );
    const { client } = await renderWithStepUp(<KVDeployDialog binding={BINDING} certificate={cert()} onClose={vi.fn()} />);
    client.setQueryData(targetKey(VAULT_ID), { ...targetFixture, id: VAULT_ID, service: serviceRef });
    // The vault as last read gives the service; a change of the choice renders the dialog again.
    const second = screen.getAllByRole('checkbox')[1];
    await userEvent.click(second);
    await userEvent.click(second);
    expect(await screen.findByTestId('canary-note')).toHaveTextContent('Deploys to 1 website(s) first, then waits 20m before the rest.');
    await userEvent.click(screen.getByRole('checkbox', { name: /Deploy to all at once/ }));
    await userEvent.click(screen.getByRole('button', { name: 'Deploy now' }));
    await waitFor(() => expect(bodies).toEqual([{ version_id: 'v-new', location_ids: [bindingLocationFixture().location_id, 'loc-2'], canary_override: true }]));
  });

  it('is complete in Turkish', async () => {
    asRole('operator', 'tr');
    await renderWithStepUp(<KVDeployDialog binding={BINDING} certificate={cert()} onClose={vi.fn()} />, ['tr-TR']);
    expect(screen.getByRole('button', { name: 'Şimdi dağıt' })).toBeInTheDocument();
    expect(screen.getByLabelText('Sürüm')).toBeInTheDocument();
    expectNoRawKeys(screen.getByRole('dialog'));
  });
});
