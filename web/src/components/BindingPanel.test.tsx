import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import {
  bindingFixture,
  bindingLocationFixture,
  BINDING_ID,
  errorResponse,
  jobFixture,
  kvCertificateDetailFixture,
  KV_CERT_ID,
  sessionFor,
  sessionHandlers,
  VAULT_ID,
} from '../test/fixtures';
import { expectNoRawKeys } from '../test/i18nAssert';
import { renderWithStepUp } from '../test/render';
import { server } from '../test/server';
import { BindingPanel } from './BindingPanel';

type Role = 'admin' | 'operator' | 'auditor';
const SUMMARY = { id: BINDING_ID, auto_deploy: false, auto_since: null, stopped_version: '', location_count: 1, version: 2, created_at: '' };

function setup(role: Role, binding = bindingFixture(), lang = 'en') {
  server.use(...sessionHandlers(sessionFor(role, lang)), http.get(`/api/v1/bindings/${BINDING_ID}`, () => HttpResponse.json(binding)));
}

async function show(role: Role, o: Parameters<typeof kvCertificateDetailFixture>[0] = {}, binding = bindingFixture(), languages: string[] = ['en-US']) {
  setup(role, binding, languages[0] === 'tr-TR' ? 'tr' : 'en');
  const cert = kvCertificateDetailFixture({ binding: SUMMARY, bound: true, ...o });
  const view = await renderWithStepUp(<BindingPanel vaultId={VAULT_ID} certificate={cert} canOperate={role !== 'auditor'} admin={role === 'admin'} />, languages);
  return { ...view, cert };
}

describe('BindingPanel without a connection', () => {
  it('offers Connect websites to an Operator and an Administrator', async () => {
    for (const role of ['admin', 'operator'] as const) {
      server.use(...sessionHandlers(sessionFor(role)));
      const v = await renderWithStepUp(<BindingPanel vaultId={VAULT_ID} certificate={kvCertificateDetailFixture()} canOperate admin={role === 'admin'} />);
      expect(screen.getByText('No website is connected to this certificate yet.')).toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Connect websites' })).toBeEnabled();
      v.unmount();
    }
  });
  it('offers nothing to an Auditor and explains a certificate that cannot be deployed', async () => {
    server.use(...sessionHandlers(sessionFor('auditor')));
    const v = await renderWithStepUp(<BindingPanel vaultId={VAULT_ID} certificate={kvCertificateDetailFixture()} canOperate={false} admin={false} />);
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
    v.unmount();
    server.use(...sessionHandlers(sessionFor('operator')));
    await renderWithStepUp(<BindingPanel vaultId={VAULT_ID} certificate={kvCertificateDetailFixture({ exportable: false })} canOperate admin={false} />);
    expect(screen.getByRole('button', { name: 'Connect websites' })).toBeDisabled();
    expect(screen.getByText('Alice cannot deploy this certificate because its private key is not exportable.')).toBeInTheDocument();
  });
});

describe('BindingPanel with a connection', () => {
  it('lists the websites with their state; a deployed one names its version in <code>', async () => {
    await show(
      'operator',
      {},
      bindingFixture({
        locations: [
          bindingLocationFixture({ state: 'deployed', version: '0123456789abcdef0123456789abcdef', deployment_id: 'd1' }),
          bindingLocationFixture({ location_id: 'l2', target_name: 'web-02', state: 'pending' }),
          bindingLocationFixture({ location_id: 'l3', target_name: 'web-03', state: 'failed' }),
          bindingLocationFixture({ location_id: 'l4', target_name: 'web-04', state: 'stopped' }),
          bindingLocationFixture({ location_id: 'l5', target_name: 'web-05', state: 'not_deployed' }),
        ],
      }),
    );
    const rows = await screen.findAllByTestId('binding-location');
    expect(rows).toHaveLength(5);
    expect(rows[0]).toHaveTextContent('Deployed: version 01234567');
    expect(within(rows[0]).getByText('01234567').tagName).toBe('CODE');
    expect(within(rows[0]).getByRole('link', { name: 'Open this deployment' })).toHaveAttribute('href', '/deployments/d1');
    expect(rows[1]).toHaveTextContent('Waiting to deploy');
    expect(rows[2]).toHaveTextContent('Failed');
    expect(rows[3]).toHaveTextContent('Stopped after 3 failures');
    expect(rows[4]).toHaveTextContent('Not deployed yet');
    expect(within(rows[0]).getByText('/etc/nginx/ssl/www.crt').tagName).toBe('CODE');
  });

  it('points a stopped automatic deployment to Deploy now, never to switching it off and on', async () => {
    await show('admin', {}, bindingFixture({ auto_deploy: true, stopped_version: 'abcdef0123456789abcdef0123456789', locations: [bindingLocationFixture({ state: 'stopped' })] }));
    const help = await screen.findByTestId('stopped-help');
    expect(help).toHaveTextContent('Automatic deployment of version abcdef01 stopped after 3 failures. Fix the cause, then use Deploy now.');
    expect(help.textContent).not.toMatch(/switch (it )?off|off and on/i);
    expect(screen.getByRole('button', { name: 'Deploy now' })).toBeInTheDocument();
  });

  it('shows the automatic deployment switch to an Administrator and the state only to an Operator', async () => {
    const v = await show('admin');
    expect(await screen.findByRole('switch', { name: /Automatic deployment/ })).toBeInTheDocument();
    v.unmount();
    await show('operator', {}, bindingFixture({ auto_deploy: true }));
    expect(await screen.findByTestId('auto-deploy-state')).toHaveTextContent('On');
    expect(screen.queryByRole('switch')).not.toBeInTheDocument();
  });

  it('says "Deploy access not checked" and its button runs the access check with this certificate', async () => {
    let body: unknown = null;
    server.use(
      http.post(`/api/v1/targets/${VAULT_ID}/actions/test`, async ({ request }) => { body = await request.json(); return HttpResponse.json({ job_id: 'j1', status_url: '' }, { status: 202 }); }),
      http.get('/api/v1/jobs/j1', () => HttpResponse.json(jobFixture({ id: 'j1' }))),
    );
    await show('operator');
    expect(await screen.findByText('Deploy access not checked')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Check deploy access' }));
    await waitFor(() => expect(body).toEqual({ read_secret_of: KV_CERT_ID }));
  });

  it('shows the missing role in <code> when deploy access is refused, and a confirmation when it works', async () => {
    const v = await show('operator', { deploy_access: 'forbidden' });
    const access = await screen.findByTestId('deploy-access');
    expect(access).toHaveTextContent('Not allowed: needs Key Vault Secrets User');
    expect(within(access).getByText('Key Vault Secrets User').tagName).toBe('CODE');
    v.unmount();
    await show('operator', { deploy_access: 'ok' });
    expect(await screen.findByText('Deploy access confirmed')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Check deploy access' })).not.toBeInTheDocument();
  });

  it('opens Deploy now with the connection\'s websites', async () => {
    await show('operator', { versions: kvCertificateDetailFixture().versions });
    await userEvent.click(await screen.findByRole('button', { name: 'Deploy now' }));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByLabelText('Version')).toBeInTheDocument();
    expect(within(dialog).getByRole('checkbox', { name: /web-01/ })).toBeChecked();
  });

  it('removes a website with the connection\'s version, and keeps the last one', async () => {
    const two = bindingFixture({ locations: [bindingLocationFixture(), bindingLocationFixture({ location_id: 'l2', target_name: 'web-02' })] });
    let body: unknown = null;
    let ifMatch: string | null = null;
    server.use(http.patch(`/api/v1/bindings/${BINDING_ID}`, async ({ request }) => { body = await request.json(); ifMatch = request.headers.get('If-Match'); return HttpResponse.json(bindingFixture()); }));
    const v = await show('operator', {}, two);
    await userEvent.click(await screen.findByRole('button', { name: 'Remove website: web-02' }));
    await waitFor(() => expect(body).toEqual({ location_ids: [bindingLocationFixture().location_id] }));
    expect(ifMatch).toBe('"2"');
    v.unmount();
    await show('operator');
    expect(await screen.findByRole('button', { name: 'Remove website: web-01' })).toBeDisabled();
    expect(screen.getByText(/needs at least one website/)).toBeInTheDocument();
  });

  it('deletes the connection after a confirmation', async () => {
    let deleted = false;
    server.use(http.delete(`/api/v1/bindings/${BINDING_ID}`, () => { deleted = true; return new HttpResponse(null, { status: 204 }); }));
    await show('operator');
    await userEvent.click(await screen.findByRole('button', { name: 'Delete connection' }));
    const dialog = await screen.findByRole('dialog');
    expect(dialog).toHaveTextContent('The websites are released and nothing changes on them.');
    expect(deleted).toBe(false);
    await userEvent.click(within(dialog).getByRole('button', { name: 'Delete connection' }));
    await waitFor(() => expect(deleted).toBe(true));
  });

  it('lets an Operator add websites only to a connection that does not deploy automatically', async () => {
    const v = await show('operator', {}, bindingFixture({ auto_deploy: true }));
    expect(await screen.findByRole('button', { name: 'Add websites' })).toBeDisabled();
    expect(screen.getByText('Only an administrator can change this.')).toBeInTheDocument();
    v.unmount();
    await show('operator');
    expect(await screen.findByRole('button', { name: 'Add websites' })).toBeEnabled();
  });

  it('shows an Auditor the connection without any button', async () => {
    await show('auditor');
    await screen.findAllByTestId('binding-location');
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
  });

  it('shows the error of a failed read', async () => {
    server.use(...sessionHandlers(sessionFor('operator')), http.get(`/api/v1/bindings/${BINDING_ID}`, () => errorResponse(404, 'ALC-SYS-0001', 'system.not_found')));
    await renderWithStepUp(<BindingPanel vaultId={VAULT_ID} certificate={kvCertificateDetailFixture({ binding: SUMMARY })} canOperate admin={false} />);
    expect(await screen.findByRole('alert')).toBeInTheDocument();
  });

  it('is complete in Turkish', async () => {
    await show('admin', { deploy_access: 'forbidden' }, bindingFixture({ locations: [bindingLocationFixture({ state: 'deployed', version: '0123456789abcdef0123456789abcdef' })] }), ['tr-TR']);
    expect(await screen.findByText('Bağlı web siteleri')).toBeInTheDocument();
    expect(screen.getByTestId('binding-location')).toHaveTextContent('Dağıtıldı: sürüm 01234567');
    expect(screen.getByTestId('deploy-access')).toHaveTextContent('İzin yok: Key Vault Secrets User gerekiyor');
    expect(screen.getByRole('button', { name: 'Şimdi dağıt' })).toBeInTheDocument();
    expect(screen.getByRole('switch', { name: /Otomatik dağıtım/ })).toBeInTheDocument();
    expectNoRawKeys(screen.getByTestId('binding-panel'));
  });
});

describe('BindingPanel fix round', () => {
  it('re-reads the connection after a 412 on Remove website, and the next click sends the new ETag', async () => {
    const two = (version: number) => bindingFixture({ version, locations: [bindingLocationFixture(), bindingLocationFixture({ location_id: 'l2', target_name: 'web-02' })] });
    let current = two(2);
    const matches: (string | null)[] = [];
    server.use(
      ...sessionHandlers(sessionFor('operator')),
      http.get(`/api/v1/bindings/${BINDING_ID}`, () => HttpResponse.json(current)),
      http.patch(`/api/v1/bindings/${BINDING_ID}`, ({ request }) => {
        matches.push(request.headers.get('If-Match'));
        if (matches.length === 1) {
          current = two(3);
          return errorResponse(412, 'ALC-SYS-0008', 'system.precondition_failed');
        }
        return HttpResponse.json(bindingFixture());
      }),
    );
    const cert = kvCertificateDetailFixture({ binding: SUMMARY, bound: true });
    await renderWithStepUp(<BindingPanel vaultId={VAULT_ID} certificate={cert} canOperate admin={false} />);
    const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'Remove website: web-02' }));
    await waitFor(() => expect(matches).toEqual(['"2"']));
    await waitFor(() => expect(screen.getAllByRole('alert').length).toBeGreaterThan(0));
    await waitFor(async () => {
      await user.click(screen.getByRole('button', { name: 'Remove website: web-02' }));
      expect(matches.length).toBeGreaterThan(1);
    });
    expect(matches[1]).toBe('"3"');
  });

  it('says why an Operator cannot add websites to a connection that deploys automatically', async () => {
    await show('operator', {}, bindingFixture({ auto_deploy: true }));
    expect(await screen.findByRole('button', { name: 'Add websites' })).toBeDisabled();
    expect(screen.getByText('Adding websites to a connection that deploys automatically needs an administrator.')).toBeInTheDocument();
  });

  it('says in the delete dialog that deployments in the queue stop and a running one finishes', async () => {
    await show('operator');
    await userEvent.click(await screen.findByRole('button', { name: 'Delete connection' }));
    expect(await screen.findByRole('dialog')).toHaveTextContent('deployments still waiting in the queue stop, and one that is already running finishes');
  });

  it('has a visually hidden header for the actions column and a labelled loading state with a role', async () => {
    await show('operator');
    expect(await screen.findByRole('columnheader', { name: 'Actions' })).toBeInTheDocument();
    expect(screen.queryByRole('columnheader', { name: '' })).not.toBeInTheDocument();
  });

  it('gives the loading indicator a status role instead of a bare label', async () => {
    server.use(...sessionHandlers(sessionFor('operator')), http.get(`/api/v1/bindings/${BINDING_ID}`, async () => { await new Promise((r) => setTimeout(r, 200)); return HttpResponse.json(bindingFixture()); }));
    await renderWithStepUp(<BindingPanel vaultId={VAULT_ID} certificate={kvCertificateDetailFixture({ binding: SUMMARY, bound: true })} canOperate admin={false} />);
    const busy = await screen.findByRole('status', { name: 'Loading…' });
    expect(busy.querySelector('[aria-label]')).toBeNull();
  });

  it('points a deploy access check that outlives the wait to this Key Vault\'s page', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      server.use(
        http.post(`/api/v1/targets/${VAULT_ID}/actions/test`, () => HttpResponse.json({ job_id: 'jr', status_url: '' }, { status: 202 })),
        http.get('/api/v1/jobs/jr', () => HttpResponse.json(jobFixture({ id: 'jr', status: 'running' }))),
      );
      await show('operator');
      await userEvent.setup({ advanceTimers: vi.advanceTimersByTime }).click(await screen.findByRole('button', { name: 'Check deploy access' }));
      vi.setSystemTime(Date.now() + 200_000);
      expect(await screen.findByText(/Open this Key Vault's page in a minute/, {}, { timeout: 8000 })).toBeInTheDocument();
      expect(document.body.textContent).not.toMatch(/server's page/);
    } finally {
      vi.useRealTimers();
    }
  }, 20_000);
});

