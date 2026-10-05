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
import { kvCertificateFixture, kvKeyFixture, kvSecretFixture } from '../test/fixtures';
import { renderRoute } from '../test/render';
import { server } from '../test/server';

type Role = 'admin' | 'operator' | 'auditor';

function asRole(role: Role, vault = vaultFixture, lang = 'en') {
  server.use(
    ...sessionHandlers(sessionFor(role, lang)),
    http.get(`/api/v1/targets/${VAULT_ID}`, () => HttpResponse.json(vault)),
    http.get('/api/v1/targets', () => HttpResponse.json({ items: [vault], next_cursor: null })),
    http.get(`/api/v1/targets/${VAULT_ID}/kv/certificates`, () => HttpResponse.json({ items: [], next_cursor: null })),
  );
}

const PATH = `/key-vaults/${VAULT_ID}`;

const HOSTILE = [
  '<img src=x onerror=alert(1)>',
  'javascript:alert(1)',
  `${'long-'.repeat(60)}end`,
  '\u202Eevil-rtl\u202C',
];

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
    expect(screen.getByText(/^Last successful check:/)).toBeInTheDocument();
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
      ['degraded', 'azure.forbidden', 'Partly working', 'only in part'],
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

    it.each(['203.0.113.7', '2001:db8::7', ...HOSTILE])('shows the address the vault firewall saw as text in <code>: %s', async (address) => {
      asRole('operator', vaultWith({ status: 'degraded', last_error: { code: 'ALC-AKV-0004', reason: 'azure.firewall', params: { client_address: address } } }));
      await renderRoute(PATH);
      await screen.findByRole('heading', { name: 'Prod vault', level: 1 });
      const fact = screen.getByTestId('vault-firewall-address');
      expect(fact).toHaveTextContent("Alice's address as the vault saw it");
      const code = within(fact).getByText(address);
      expect(code.tagName).toBe('CODE');
      expect(code.textContent).toBe(address);
      expect(fact.querySelector('img, a, script')).toBeNull();
    });

    it('shows no firewall address for another failure, or without one', async () => {
      asRole('operator', vaultWith({ status: 'degraded', last_error: { code: 'ALC-AKV-0004', reason: 'azure.firewall' } }));
      await renderRoute(PATH);
      await screen.findByRole('heading', { name: 'Prod vault', level: 1 });
      expect(screen.queryByTestId('vault-firewall-address')).toBeNull();
    });

    it('shows the firewall address in Turkish', async () => {
      asRole('operator', vaultWith({ status: 'degraded', last_error: { code: 'ALC-AKV-0004', reason: 'azure.firewall', params: { client_address: '203.0.113.7' } } }), 'tr');
      await renderRoute(PATH, { languages: ['tr-TR'] });
      await screen.findByRole('heading', { name: 'Prod vault', level: 1 });
      expect(screen.getByTestId('vault-firewall-address')).toHaveTextContent('Kasanın gördüğü Alice adresi');
      expectNoRawKeys(screen.getByTestId('vault-firewall-address'));
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
      expect(await within(dialog).findByText(/^Websites are still connected to certificates of this vault\. Remove those connections too\?/)).toBeInTheDocument();
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

describe('KeyVaultDetailPage inventory', () => {
  const certs = [
    kvCertificateFixture({ id: 'c1', name: 'web-cert', bound: true, current_version: '0123456789abcdef0123456789abcdef' }),
    kvCertificateFixture({ id: 'c2', name: 'monitor-only', exportable: false, current_version: 'aaaaaaaabbbbbbbbccccccccdddddddd', expires: '2020-01-01T00:00:00Z' }),
    kvCertificateFixture({ id: 'c3', name: 'old-cert', missing_since: '2026-10-01T00:00:00Z' }),
    kvCertificateFixture({ id: 'c4', name: 'fresh-cert', first_seen_at: '2026-09-01T00:00:00Z', kv_created_at: new Date(Date.now() - 86_400_000).toISOString() }),
    kvCertificateFixture({ id: 'c5', name: 'held-cert', current_held: true, current_held_reason: 'license' }),
  ];

  it('lists certificates with the first 8 hex digits in <code>, expiry and the chips', async () => {
    asRole('operator');
    let query = '';
    server.use(
      http.get(`/api/v1/targets/${VAULT_ID}/kv/certificates`, ({ request }) => {
        query = new URL(request.url).search;
        return HttpResponse.json({ items: certs, next_cursor: null });
      }),
    );
    await renderRoute(PATH);
    const table = await screen.findByRole('table', { name: 'Certificates' });
    const row = (n: string) => within(table).getByText(n).closest('tr')!;
    expect(query).toContain('missing=include');
    expect(within(row('web-cert')).getByText('01234567').tagName).toBe('CODE');
    expect(within(row('web-cert')).getByRole('link', { name: 'web-cert' })).toHaveAttribute('href', `/key-vaults/${VAULT_ID}/certificates/c1`);
    expect(row('web-cert')).toHaveTextContent('Connected websites');
    expect(row('monitor-only')).toHaveTextContent('Monitor only');
    expect(row('monitor-only')).toHaveTextContent('Expired');
    expect(row('old-cert')).toHaveTextContent('Removed from Key Vault');
    expect(row('fresh-cert')).toHaveTextContent('New version found');
    expect(row('web-cert')).not.toHaveTextContent('New version found');
    expect(row('held-cert')).toHaveTextContent('Held');
  });

  it('shows the Keys tab: name, type, size or curve, expiry, enabled, managed', async () => {
    asRole('auditor');
    server.use(
      http.get(`/api/v1/targets/${VAULT_ID}/kv/keys`, () =>
        HttpResponse.json({ items: [kvKeyFixture(), kvKeyFixture({ id: 'k2', name: 'ec-key', key_type: 'EC', key_size: 0, curve: 'P-256', managed: true, enabled: false, hsm: true, expires: null })], next_cursor: null }),
      ),
    );
    await renderRoute(PATH);
    await userEvent.click(await screen.findByRole('tab', { name: 'Keys' }));
    const table = await screen.findByRole('table', { name: 'Keys' });
    const rsa = within(table).getByText('signing-key').closest('tr')!;
    expect(rsa).toHaveTextContent('RSA');
    expect(rsa).toHaveTextContent('2048 bits');
    const ec = within(table).getByText('ec-key').closest('tr')!;
    expect(ec).toHaveTextContent('P-256');
    expect(ec).toHaveTextContent('No expiry');
    expect(ec).toHaveTextContent('HSM');
    expect(within(table).getByRole('columnheader', { name: 'Size or curve' })).toBeInTheDocument();
  });

  it('shows the Secrets tab: name, content type, expiry, enabled, managed (never a value)', async () => {
    asRole('auditor');
    server.use(http.get(`/api/v1/targets/${VAULT_ID}/kv/secrets`, () => HttpResponse.json({ items: [kvSecretFixture()], next_cursor: null })));
    await renderRoute(PATH);
    await userEvent.click(await screen.findByRole('tab', { name: 'Secrets' }));
    const table = await screen.findByRole('table', { name: 'Secrets' });
    const row = within(table).getByText('db-password').closest('tr')!;
    expect(row).toHaveTextContent('text/plain');
    expect(within(table).queryByText(/value/i)).not.toBeInTheDocument();
  });

  it('pages with Show more using the cursor', async () => {
    asRole('operator');
    const cursors: (string | null)[] = [];
    server.use(
      http.get(`/api/v1/targets/${VAULT_ID}/kv/certificates`, ({ request }) => {
        const c = new URL(request.url).searchParams.get('cursor');
        cursors.push(c);
        return c ? HttpResponse.json({ items: [kvCertificateFixture({ id: 'c9', name: 'second-page' })], next_cursor: null }) : HttpResponse.json({ items: [kvCertificateFixture({ id: 'c8', name: 'first-page' })], next_cursor: 'cur-2' });
      }),
    );
    await renderRoute(PATH);
    await screen.findByText('first-page');
    await userEvent.click(screen.getByRole('button', { name: 'Show more' }));
    expect(await screen.findByText('second-page')).toBeInTheDocument();
    expect(screen.getByText('first-page')).toBeInTheDocument();
    expect(cursors).toEqual([null, 'cur-2']);
    expect(screen.queryByRole('button', { name: 'Show more' })).not.toBeInTheDocument();
  });

  it('shows the empty state of a tab', async () => {
    asRole('operator');
    await renderRoute(PATH);
    expect(await screen.findByText('No certificates in this vault.')).toBeInTheDocument();
  });

  it('shows what Azure or the vault owner wrote as text only: no element, no link, wrapped inside its table', async () => {
    asRole('operator');
    const names = HOSTILE.map((h, i) => kvCertificateFixture({ id: `h${i}`, name: h }));
    server.use(
      http.get(`/api/v1/targets/${VAULT_ID}/kv/certificates`, () => HttpResponse.json({ items: names, next_cursor: null })),
      http.get(`/api/v1/targets/${VAULT_ID}/kv/secrets`, () => HttpResponse.json({ items: HOSTILE.map((h, i) => kvSecretFixture({ id: `s${i}`, name: h, content_type: h })), next_cursor: null })),
      http.get(`/api/v1/targets/${VAULT_ID}/kv/keys`, () => HttpResponse.json({ items: HOSTILE.map((h, i) => kvKeyFixture({ id: `k${i}`, name: h, key_type: h, curve: h, key_size: 0 })), next_cursor: null })),
    );
    await renderRoute(PATH);
    for (const tab of ['Certificates', 'Keys', 'Secrets']) {
      await userEvent.click(await screen.findByRole('tab', { name: tab }));
      const table = await screen.findByRole('table', { name: tab });
      expect(table.querySelector('img')).toBeNull();
      expect(table.querySelector('a[href^="javascript"]')).toBeNull();
      expect(table.textContent).toContain('<img src=x onerror=alert(1)>');
      expect(table.textContent).toContain('javascript:alert(1)');
      expect(table.textContent).toContain('\u202Eevil-rtl\u202C');
      expect(table.closest('[class*="ScrollArea"], [class*="ScrollContainer"]')).not.toBeNull();
      for (const cell of Array.from(table.querySelectorAll<HTMLElement>('td span[translate="no"], td a'))) {
        if (cell.textContent?.includes('long-long')) expect(cell.style.overflowWrap).toBe('anywhere');
      }
    }
    expect(document.querySelector('img[src="x"]')).toBeNull();
  });

  it('shows the truncated-listing warnings of the last check', async () => {
    asRole('operator', vaultWith({ facts: { ...vaultFixture.facts, warnings: [{ code: 'kv_item_unreadable', params: { object: 'certificates', count: '3' } }, { code: 'kv_listing_empty', params: {} }, { code: 'kv_version_conflict', params: { object: 'certificates', count: '1' } }] } }));
    await renderRoute(PATH);
    const warnings = await screen.findAllByTestId('vault-warning');
    expect(warnings).toHaveLength(3);
    expect(warnings[0]).toHaveTextContent('could not be read and were left out');
    expect(warnings[1]).toHaveTextContent('found no certificates in this vault, although Alice knows some');
    expect(warnings[2]).toHaveTextContent('different thumbprint');
  });

  it('is complete in Turkish', async () => {
    asRole('operator', vaultFixture, 'tr');
    server.use(http.get(`/api/v1/targets/${VAULT_ID}/kv/certificates`, () => HttpResponse.json({ items: certs, next_cursor: null })));
    await renderRoute(PATH, { languages: ['tr-TR'] });
    expect(await screen.findByRole('tab', { name: 'Sertifikalar' })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'Anahtarlar' })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'Gizli anahtarlar' })).toBeInTheDocument();
    const table = await screen.findByRole('table', { name: 'Sertifikalar' });
    expect(within(table).getAllByText('Yalnızca izleme').length).toBeGreaterThan(0);
    expect(within(table).getByText("Key Vault'tan kaldırıldı")).toBeInTheDocument();
    expect(within(table).getAllByText('Yeni sürüm bulundu').length).toBeGreaterThan(0);
    expectNoRawKeys(table);
  });
});

describe('KeyVaultDetailPage fix round', () => {
  it('says "No successful check yet" for a vault degraded from birth and never "Last checked"', async () => {
    asRole('operator', vaultWith({ status: 'degraded', last_success_at: null, last_error: { code: 'ALC-AKV-0003', reason: 'azure.forbidden', params: { role: 'Key Vault Reader' } } }));
    await renderRoute(PATH);
    await screen.findByRole('heading', { name: 'Prod vault', level: 1 });
    expect(screen.getByText('No successful check yet')).toBeInTheDocument();
    expect(screen.queryByText(/Last checked/)).not.toBeInTheDocument();
    expect(screen.queryByText('Not checked yet')).not.toBeInTheDocument();
  });

  it('says only that a degraded vault is reached in part when it is throttled, and points to the reason', async () => {
    asRole('operator', vaultWith({ status: 'degraded', last_error: { code: 'ALC-AKV-0007', reason: 'azure.throttled' } }, { access: accessFixture({ checks: [accessRow('list_certificates', 'ok')] }) }));
    await renderRoute(PATH);
    const help = await screen.findByTestId('vault-status-help');
    expect(help).toHaveTextContent('Alice reaches this vault only in part. The reason is shown below.');
    expect(help.textContent).not.toMatch(/permission|firewall/);
    expect(screen.getByText('Azure asked Alice to slow down')).toBeInTheDocument();
  });

  it('does not read the vault again on an interval while it is ok and no job runs', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      let reads = 0;
      asRole('operator');
      server.use(http.get(`/api/v1/targets/${VAULT_ID}`, () => { reads++; return HttpResponse.json(vaultFixture); }));
      await renderRoute(PATH);
      await screen.findByRole('heading', { name: 'Prod vault', level: 1 });
      const before = reads;
      await vi.advanceTimersByTimeAsync(20_000);
      expect(reads).toBe(before);
    } finally {
      vi.useRealTimers();
    }
  });

  it('shows the not-found state for /key-vaults/vaults, which is not the list cache, and never goes to /servers/undefined', async () => {
    asRole('admin');
    server.use(http.get('/api/v1/targets/vaults', () => errorResponse(404, 'ALC-SYS-0001', 'system.not_found')));
    const view = await renderRoute('/key-vaults');
    await screen.findByTestId('vaults-table');
    await view.router.navigate('/key-vaults/vaults');
    expect(await screen.findByRole('alert')).toBeInTheDocument();
    expect(view.router.state.location.pathname).toBe('/key-vaults/vaults');
    expect(screen.getByRole('link', { name: 'Back to Key Vaults' })).toBeInTheDocument();
  });

  it('says that deployments waiting in the queue stop and a running one finishes when removing connections', async () => {
    asRole('admin');
    server.use(http.delete(`/api/v1/targets/${VAULT_ID}`, () => errorResponse(409, 'ALC-AKV-0020', 'kv.vault_has_bindings')));
    const user = userEvent.setup();
    await renderRoute(PATH);
    await user.click(await screen.findByRole('button', { name: 'Remove Key Vault' }));
    const dialog = await screen.findByRole('dialog');
    await user.click(within(dialog).getByRole('button', { name: 'Remove Key Vault' }));
    const alert = await within(dialog).findByRole('alert');
    expect(alert).toHaveTextContent('Automatic deployments still waiting in the queue stop; one that is already running finishes.');
  });

  it('shows the role of a catalogue alert in <code> as text', async () => {
    asRole('operator', vaultWith({ status: 'degraded', last_error: { code: 'ALC-AKV-0003', reason: 'azure.forbidden', params: { role: 'Key Vault Reader' } } }));
    await renderRoute(PATH);
    const alert = (await screen.findAllByRole('alert'))[0];
    const roles = within(alert).getAllByText('Key Vault Reader');
    expect(roles.length).toBeGreaterThan(0);
    for (const r of roles) expect(r.tagName).toBe('CODE');
  });

  it('translates the kind in the warnings of the last check', async () => {
    asRole('operator', vaultWith({ facts: { ...vaultFixture.facts, warnings: [{ code: 'kv_item_unreadable', params: { object: 'certificates', count: '3' } }, { code: 'kv_version_conflict', params: { object: 'versions', count: '1' } }] } }), 'tr');
    await renderRoute(PATH, { languages: ['tr-TR'] });
    const warnings = await screen.findAllByTestId('vault-warning');
    expect(warnings[0]).toHaveTextContent('sertifikalar');
    expect(warnings[0].textContent).not.toMatch(/certificates/);
    expect(warnings[1]).toHaveTextContent('sürümler');
  });

  it('points a Check now that outlives the wait to this Key Vault\'s page, not to a server', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      asRole('admin');
      server.use(
        http.post(`/api/v1/targets/${VAULT_ID}/actions/discover`, () => HttpResponse.json({ job_id: 'jr', status_url: '' }, { status: 202 })),
        http.get('/api/v1/jobs/jr', () => HttpResponse.json(jobFixture({ id: 'jr', status: 'running' }))),
      );
      await renderRoute(PATH);
      await userEvent.setup({ advanceTimers: vi.advanceTimersByTime }).click(await screen.findByRole('button', { name: 'Check now' }));
      vi.setSystemTime(Date.now() + 200_000);
      expect(await screen.findByText(/Open this Key Vault's page in a minute/, {}, { timeout: 8000 })).toBeInTheDocument();
      expect(document.body.textContent).not.toMatch(/server's page/);
    } finally {
      vi.useRealTimers();
    }
  }, 20_000);

  it('does not show the certificates of one vault in another (the list keys carry the vault id)', async () => {
    const B = '0192d000-0000-7000-8000-0000000000b2';
    server.use(
      ...sessionHandlers(sessionFor('operator')),
      http.get('/api/v1/targets/:id', ({ params }) => HttpResponse.json(vaultWith({ id: String(params.id), name: params.id === B ? 'Vault B' : 'Prod vault' }))),
      http.get('/api/v1/targets/:id/kv/certificates', ({ params }) =>
        HttpResponse.json({ items: [kvCertificateFixture({ id: `c-${String(params.id)}`, name: params.id === B ? 'cert-of-b' : 'cert-of-a' })], next_cursor: null }),
      ),
    );
    const view = await renderRoute(PATH);
    await screen.findByText('cert-of-a');
    await view.router.navigate(`/key-vaults/${B}`);
    await screen.findByRole('heading', { name: 'Vault B', level: 1 });
    expect(await screen.findByText('cert-of-b')).toBeInTheDocument();
    expect(screen.queryByText('cert-of-a')).not.toBeInTheDocument();
  });
});

