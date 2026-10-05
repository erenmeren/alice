import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import {
  accessFixture,
  accessRow,
  errorResponse,
  jobFixture,
  OBJECT_ID,
  sessionFor,
  sessionHandlers,
  TENANT_ID,
  CLIENT_ID,
  targetFixture,
  VAULT_ID,
  vaultFixture,
  vaultWith,
} from '../test/fixtures';
import { expectNoRawKeys } from '../test/i18nAssert';
import { renderRoute } from '../test/render';
import { server } from '../test/server';

type Role = 'admin' | 'operator' | 'auditor';

function asRole(role: Role, vault = vaultFixture, lang = 'en') {
  server.use(
    ...sessionHandlers(sessionFor(role, lang)),
    http.get(`/api/v1/targets/${VAULT_ID}`, () => HttpResponse.json(vault)),
    http.get('/api/v1/targets', () => HttpResponse.json({ items: [vault], next_cursor: null })),
  );
}

const PATH = `/key-vaults/${VAULT_ID}`;

describe('KeyVaultDetailPage header', () => {
  it('shows the status, how Alice signs in, the object ID in <code>, when it was last checked and the interval', async () => {
    asRole('operator');
    await renderRoute(PATH);
    expect(await screen.findByRole('heading', { name: 'Prod vault', level: 1 })).toBeInTheDocument();
    expect(screen.getByTestId('vault-status')).toHaveTextContent('Connected');
    expect(screen.getByText('https://contoso-prod.vault.azure.net').tagName).toBe('CODE');
    const signs = screen.getByText(/^Alice signs in to Azure as/);
    expect(signs).toHaveTextContent(`Alice signs in to Azure as ${OBJECT_ID}`);
    expect(within(signs).getByText(OBJECT_ID).tagName).toBe('CODE');
    expect(screen.getByText(TENANT_ID).tagName).toBe('CODE');
    expect(screen.getByText(CLIENT_ID).tagName).toBe('CODE');
    expect(screen.getByText(/^Last checked:/)).toBeInTheDocument();
    expect(screen.getByText('Alice checks this vault every 15 minutes.')).toBeInTheDocument();
    expect(screen.getByRole('table', { name: 'Access check' })).toBeInTheDocument();
    expect(screen.getByText('Roles Alice needs', { selector: 'h3' })).toBeInTheDocument();
  });

  it('redirects a server id to the server page', async () => {
    server.use(...sessionHandlers(sessionFor('admin')), http.get(`/api/v1/targets/${targetFixture.id}`, () => HttpResponse.json(targetFixture)));
    const view = await renderRoute(`/key-vaults/${targetFixture.id}`);
    await waitFor(() => expect(view.router.state.location.pathname).toBe(`/servers/${targetFixture.id}`));
  });

  it('redirects /servers/<vault id> to the vault page', async () => {
    asRole('admin');
    const view = await renderRoute(`/servers/${VAULT_ID}`);
    await waitFor(() => expect(view.router.state.location.pathname).toBe(PATH));
    expect(await screen.findByRole('heading', { name: 'Prod vault', level: 1 })).toBeInTheDocument();
  });

  it('shows the 404 of an unknown vault with a way back', async () => {
    server.use(...sessionHandlers(sessionFor('admin')), http.get(`/api/v1/targets/${VAULT_ID}`, () => errorResponse(404, 'ALC-SYS-0001', 'system.not_found')));
    await renderRoute(PATH);
    expect(await screen.findByRole('alert')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Back to Key Vaults' })).toHaveAttribute('href', '/key-vaults');
  });

  describe('states', () => {
    it.each([
      ['degraded', 'azure.forbidden', 'Partly working', 'a permission is missing'],
      ['auth_failed', 'azure.credentials_expired', 'Credentials expired', 'refused Alice'],
      ['unreachable', 'azure.unreachable', 'Cannot reach Azure', 'cannot reach Azure or this vault'],
    ] as const)('says what is wrong with a %s vault', async (status, reason, label, help) => {
      asRole('operator', vaultWith({ status, last_error: { code: 'ALC-AKV-0003', reason, params: { role: 'Key Vault Reader' } } }, { access: accessFixture({ checks: [accessRow('list_certificates', 'ok')] }) }));
      await renderRoute(PATH);
      await screen.findByRole('heading', { name: 'Prod vault', level: 1 });
      expect(screen.getByTestId('vault-status')).toHaveTextContent(label === 'Partly working' ? 'Partly working' : label);
      expect(screen.getByTestId('vault-status-help')).toHaveTextContent(help);
      expect(screen.getAllByRole('alert').length).toBeGreaterThan(0);
    });

    it('names the missing role in <code> for a vault without the permission', async () => {
      asRole(
        'operator',
        vaultWith({ status: 'degraded', last_error: { code: 'ALC-AKV-0003', reason: 'azure.forbidden', params: { role: 'Key Vault Reader' } } }, { access: accessFixture({ checks: [accessRow('list_certificates', 'forbidden', 'Key Vault Reader')] }) }),
      );
      await renderRoute(PATH);
      expect(await screen.findByTestId('vault-status')).toHaveTextContent('No permission to read certificates');
      const table = screen.getByRole('table', { name: 'Access check' });
      expect(within(table).getByRole('row', { name: /Monitor certificates/ })).toHaveTextContent('Not allowed: needs Key Vault Reader');
    });

    it('warns when the sign-in secret expires within 30 days, and when it has expired', async () => {
      const soon = new Date(Date.now() + 10 * 86_400_000).toISOString();
      asRole('admin', vaultWith({}, { auth: 'client_secret', secret_expires_on: soon }));
      const view = await renderRoute(PATH);
      expect(await screen.findByTestId('credentials-expiry')).toHaveTextContent('expire within 30 days');
      view.unmount();
      asRole('admin', vaultWith({}, { auth: 'client_secret', secret_expires_on: '2020-01-01T00:00:00Z' }));
      await renderRoute(PATH);
      expect(await screen.findByTestId('credentials-expiry')).toHaveTextContent('have expired');
    });

    it('does not warn for a secret that lasts long', async () => {
      asRole('admin', vaultWith({}, { auth: 'client_secret', secret_expires_on: new Date(Date.now() + 200 * 86_400_000).toISOString() }));
      await renderRoute(PATH);
      await screen.findByRole('heading', { name: 'Prod vault', level: 1 });
      expect(screen.queryByTestId('credentials-expiry')).not.toBeInTheDocument();
    });

    it('shows the sign-in certificate with its thumbprint and expiry for certificate sign-in', async () => {
      asRole('operator', vaultWith({}, { auth: 'certificate', cert_thumbprint: 'ab'.repeat(20), cert_not_after: '2030-01-01T00:00:00Z' }));
      await renderRoute(PATH);
      expect((await screen.findByText('ab'.repeat(20))).tagName).toBe('CODE');
      expect(screen.getByText('Sign-in certificate expires')).toBeInTheDocument();
    });
  });

  describe('actions', () => {
    it('Check now posts actions/discover and waits for the job (Administrator and Operator)', async () => {
      for (const role of ['admin', 'operator'] as const) {
        asRole(role);
        let calls = 0;
        server.use(
          http.post(`/api/v1/targets/${VAULT_ID}/actions/discover`, () => {
            calls++;
            return HttpResponse.json({ job_id: 'j1', status_url: '' }, { status: 202 });
          }),
          http.get('/api/v1/jobs/j1', () => HttpResponse.json(jobFixture({ id: 'j1', type: 'kv.poll', target_id: VAULT_ID }))),
        );
        const view = await renderRoute(PATH);
        await userEvent.click(await screen.findByRole('button', { name: 'Check now' }));
        expect(await screen.findByText('Finished.')).toBeInTheDocument();
        expect(calls).toBe(1);
        view.unmount();
      }
    });

    it('shows a held Check now as waiting for an administrator', async () => {
      asRole('admin');
      server.use(
        http.post(`/api/v1/targets/${VAULT_ID}/actions/discover`, () => HttpResponse.json({ job_id: 'j1', status_url: '' }, { status: 202 })),
        http.get('/api/v1/jobs/j1', () => HttpResponse.json(jobFixture({ id: 'j1', status: 'blocked_license' }))),
      );
      await renderRoute(PATH);
      await userEvent.click(await screen.findByRole('button', { name: 'Check now' }));
      expect(await screen.findByText('This task is paused and waits for an administrator to run it.')).toBeInTheDocument();
    });

    it('gives an Operator Check now and nothing that changes the vault; an Auditor no buttons', async () => {
      asRole('operator');
      const view = await renderRoute(PATH);
      await screen.findByRole('button', { name: 'Check now' });
      for (const name of ['Replace credentials', 'Remove Key Vault', 'Save interval']) expect(screen.queryByRole('button', { name })).not.toBeInTheDocument();
      expect(screen.queryByLabelText('Check every (minutes)')).not.toBeInTheDocument();
      view.unmount();
      asRole('auditor');
      await renderRoute(PATH);
      await screen.findByRole('heading', { name: 'Prod vault', level: 1 });
      expect(screen.queryByRole('button', { name: 'Check now' })).not.toBeInTheDocument();
      expect(screen.queryByRole('button', { name: 'Check again' })).not.toBeInTheDocument();
    });

    it('an Administrator changes the interval with If-Match and sees it saved', async () => {
      asRole('admin');
      let body: unknown = null;
      let ifMatch: string | null = null;
      server.use(
        http.patch(`/api/v1/targets/${VAULT_ID}`, async ({ request }) => {
          body = await request.json();
          ifMatch = request.headers.get('If-Match');
          return HttpResponse.json(vaultWith({ version: 5 }, { poll_interval_minutes: 30 }));
        }),
      );
      const user = userEvent.setup();
      await renderRoute(PATH);
      const field = await screen.findByLabelText('Check every (minutes)');
      expect(screen.getByRole('button', { name: 'Save interval' })).toBeDisabled();
      await user.clear(field);
      await user.type(field, '30');
      await user.click(screen.getByRole('button', { name: 'Save interval' }));
      expect(await screen.findByText('Interval saved.')).toBeInTheDocument();
      expect(body).toEqual({ poll_interval_minutes: 30 });
      expect(ifMatch).toBe('"4"');
    });

    it('does not accept an interval outside 5 to 1440 minutes', async () => {
      asRole('admin');
      const user = userEvent.setup();
      await renderRoute(PATH);
      const field = await screen.findByLabelText('Check every (minutes)');
      await user.clear(field);
      await user.type(field, '2');
      expect(screen.getByRole('button', { name: 'Save interval' })).toBeDisabled();
    });

    it('replaces the credentials and says so', async () => {
      asRole('admin', vaultWith({}, { auth: 'client_secret' }));
      server.use(
        http.put(`/api/v1/targets/${VAULT_ID}/vault-credentials`, () => HttpResponse.json({ target: vaultFixture, access: accessFixture(), job_id: null })),
      );
      const user = userEvent.setup();
      await renderRoute(PATH);
      await user.click(await screen.findByRole('button', { name: 'Replace credentials' }));
      const dialog = await screen.findByRole('dialog');
      await user.type(within(dialog).getByLabelText(/^Secret value/), 'fake-new-secret');
      await user.click(within(dialog).getByRole('button', { name: 'Replace credentials' }));
      expect(await screen.findByText('Credentials replaced.')).toBeInTheDocument();
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    });

    it('removes a vault and returns to the list', async () => {
      asRole('admin');
      let url = '';
      server.use(http.delete(`/api/v1/targets/${VAULT_ID}`, ({ request }) => { url = request.url; return new HttpResponse(null, { status: 204 }); }));
      const user = userEvent.setup();
      const view = await renderRoute(PATH);
      await user.click(await screen.findByRole('button', { name: 'Remove Key Vault' }));
      const dialog = await screen.findByRole('dialog');
      expect(within(dialog).getByText('Remove this Key Vault from Alice?')).toBeInTheDocument();
      await user.click(within(dialog).getByRole('button', { name: 'Remove Key Vault' }));
      await waitFor(() => expect(view.router.state.location.pathname).toBe('/key-vaults'));
      expect(new URL(url).search).toBe('');
    });

    it('asks to remove the connections of a vault with connected websites and sends remove_bindings=true', async () => {
      asRole('admin');
      const urls: string[] = [];
      server.use(
        http.delete(`/api/v1/targets/${VAULT_ID}`, ({ request }) => {
          urls.push(new URL(request.url).search);
          return urls.length === 1 ? errorResponse(409, 'ALC-AKV-0020', 'kv.vault_has_bindings') : new HttpResponse(null, { status: 204 });
        }),
      );
      const user = userEvent.setup();
      const view = await renderRoute(PATH);
      await user.click(await screen.findByRole('button', { name: 'Remove Key Vault' }));
      const dialog = await screen.findByRole('dialog');
      await user.click(within(dialog).getByRole('button', { name: 'Remove Key Vault' }));
      expect(await within(dialog).findByText('Websites are still connected to certificates of this vault. Remove those connections too?')).toBeInTheDocument();
      await user.click(within(dialog).getByRole('button', { name: 'Remove the connections and the vault' }));
      await waitFor(() => expect(view.router.state.location.pathname).toBe('/key-vaults'));
      expect(urls).toEqual(['', '?remove_bindings=true']);
    });

    it('asks for step-up when removing with the connections needs a fresh code, then sends the same request', async () => {
      asRole('admin');
      const urls: string[] = [];
      server.use(
        http.delete(`/api/v1/targets/${VAULT_ID}`, ({ request }) => {
          const q = new URL(request.url).search;
          urls.push(q);
          if (q === '') return errorResponse(409, 'ALC-AKV-0020', 'kv.vault_has_bindings');
          return urls.filter((u) => u !== '').length === 1 ? errorResponse(403, 'ALC-AUTH-0003', 'auth.stepup_required') : new HttpResponse(null, { status: 204 });
        }),
        http.post('/api/v1/auth/stepup', () => HttpResponse.json(sessionFor('admin'))),
      );
      const user = userEvent.setup();
      const view = await renderRoute(PATH);
      await user.click(await screen.findByRole('button', { name: 'Remove Key Vault' }));
      const dialog = await screen.findByRole('dialog');
      await user.click(within(dialog).getByRole('button', { name: 'Remove Key Vault' }));
      await user.click(await within(dialog).findByRole('button', { name: 'Remove the connections and the vault' }));
      await user.type(await screen.findByLabelText('6-digit code'), '123456');
      await user.click(screen.getByRole('button', { name: 'Confirm' }));
      await waitFor(() => expect(view.router.state.location.pathname).toBe('/key-vaults'));
      expect(urls).toEqual(['', '?remove_bindings=true', '?remove_bindings=true']);
    });
  });

  it('is complete in Turkish', async () => {
    asRole('admin', vaultWith({ status: 'degraded', last_error: { code: 'ALC-AKV-0003', reason: 'azure.forbidden', params: { role: 'Key Vault Reader' } } }, { access: accessFixture({ checks: [accessRow('list_certificates', 'forbidden', 'Key Vault Reader')] }) }), 'tr');
    await renderRoute(PATH, { languages: ['tr-TR'] });
    expect(await screen.findByRole('heading', { name: 'Prod vault', level: 1 })).toBeInTheDocument();
    expect(screen.getByTestId('vault-status')).toHaveTextContent('Sertifikaları okuma izni yok');
    expect(screen.getByRole('button', { name: 'Şimdi denetle' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Kimlik bilgilerini değiştir' })).toBeInTheDocument();
    expect(screen.getByText(/^Alice, Azure'da/)).toHaveTextContent(`Alice, Azure'da ${OBJECT_ID} olarak oturum açar`);
    expect(screen.getByRole('table', { name: 'Erişim denetimi' })).toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/errors\.azure/);
    expectNoRawKeys(screen.getByRole('heading', { name: 'Prod vault', level: 1 }).parentElement as HTMLElement);
  });
});
