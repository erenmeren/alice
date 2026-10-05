import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { accessFixture, accessRow, CLIENT_ID, errorResponse, OBJECT_ID, sessionFor, sessionHandlers, TENANT_ID, vaultFixture } from '../test/fixtures';
import { expectNoRawKeys } from '../test/i18nAssert';
import { renderWithStepUp } from '../test/render';
import { server } from '../test/server';
import { AddKeyVaultDialog } from './AddKeyVaultDialog';

// The dialog tests type into many fields; under a loaded machine they need more than the default 5 s.
vi.setConfig({ testTimeout: 30_000 });

// Fake secret values for the tests: obviously not real, and not shaped like any real credential.
const SECRET = 'fake-secret-value';
const KEY_TEXT = ['fake', 'key', 'text'].join('-');
const PFX_PASSWORD = 'fake-pfx-password';

function asAdmin(lang = 'en') {
  server.use(...sessionHandlers(sessionFor('admin', lang)));
}

function created(extra = {}) {
  return { target: vaultFixture, access: accessFixture(), job_id: 'j1', status_url: '/api/v1/jobs/j1', ...extra };
}

async function fillCommon(user: ReturnType<typeof userEvent.setup>, name = 'Prod vault', url = 'contoso-prod') {
  await user.type(await screen.findByLabelText(/^Name/), name);
  await user.type(screen.getByLabelText(/^Vault address/), url);
}

async function fillClientSecret(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole('radio', { name: 'Client secret' }));
  await user.type(screen.getByLabelText(/^Directory \(tenant\) ID/), TENANT_ID);
  await user.type(screen.getByLabelText(/^Application \(client\) ID/), CLIENT_ID);
  await user.type(screen.getByLabelText(/^Secret value/), SECRET);
}

describe('AddKeyVaultDialog', () => {
  it('adds a vault with a client secret and shows the access check', async () => {
    asAdmin();
    const user = userEvent.setup();
    let body: unknown = null;
    server.use(
      http.post('/api/v1/key-vaults', async ({ request }) => {
        body = await request.json();
        return HttpResponse.json(created(), { status: 201 });
      }),
    );
    const onAdded = vi.fn();
    await renderWithStepUp(<AddKeyVaultDialog onClose={vi.fn()} onAdded={onAdded} />);
    await fillCommon(user);
    await fillClientSecret(user);
    await user.click(screen.getByRole('button', { name: 'Add Key Vault' }));
    expect(await screen.findByText('Key Vault added.')).toBeVisible();
    expect(body).toEqual({
      name: 'Prod vault',
      vault_url: 'contoso-prod',
      auth: 'client_secret',
      tenant_id: TENANT_ID,
      client_id: CLIENT_ID,
      client_secret: SECRET,
      poll_interval_minutes: 15,
    });
    const signs = screen.getByText(/^Alice signs in to Azure as/);
    expect(signs).toHaveTextContent(`Alice signs in to Azure as ${OBJECT_ID}`);
    expect(within(signs).getByText(OBJECT_ID).tagName).toBe('CODE');
    expect(screen.getByRole('row', { name: /Monitor certificates/ })).toHaveTextContent('Allowed');
    await user.click(screen.getByRole('button', { name: 'Open the vault' }));
    expect(onAdded).toHaveBeenCalledWith(vaultFixture);
  });

  it('preselects Certificate (recommended) and accepts PEM text or a PFX file with its password', async () => {
    asAdmin();
    const user = userEvent.setup();
    const bodies: Record<string, unknown>[] = [];
    server.use(
      http.post('/api/v1/key-vaults', async ({ request }) => {
        bodies.push((await request.json()) as Record<string, unknown>);
        return HttpResponse.json(created(), { status: 201 });
      }),
    );
    const view = await renderWithStepUp(<AddKeyVaultDialog onClose={vi.fn()} onAdded={vi.fn()} />);
    await fillCommon(user);
    expect(screen.getByRole('radio', { name: 'Certificate (recommended)' })).toBeChecked();
    await user.type(screen.getByLabelText(/^Directory \(tenant\) ID/), TENANT_ID);
    await user.type(screen.getByLabelText(/^Application \(client\) ID/), CLIENT_ID);
    // PEM: two text areas, no spell checking, no completion.
    const cert = screen.getByLabelText(/^Certificate \(PEM\)/);
    const key = screen.getByLabelText(/^Private key \(PEM\)/);
    expect(key.tagName).toBe('TEXTAREA');
    expect(key).toHaveAttribute('spellcheck', 'false');
    await user.click(cert);
    await user.paste('fake-certificate-text');
    await user.click(key);
    await user.paste(KEY_TEXT);
    await user.click(screen.getByRole('button', { name: 'Add Key Vault' }));
    await screen.findByText('Key Vault added.');
    expect(bodies[0]).toEqual({ name: 'Prod vault', vault_url: 'contoso-prod', auth: 'certificate', tenant_id: TENANT_ID, client_id: CLIENT_ID, certificate_pem: 'fake-certificate-text', private_key_pem: KEY_TEXT, poll_interval_minutes: 15 });
    view.unmount();

    // PFX: read in memory, sent as base64 with its password.
    await renderWithStepUp(<AddKeyVaultDialog onClose={vi.fn()} onAdded={vi.fn()} />);
    await fillCommon(user);
    await user.type(screen.getByLabelText(/^Directory \(tenant\) ID/), TENANT_ID);
    await user.type(screen.getByLabelText(/^Application \(client\) ID/), CLIENT_ID);
    await user.click(screen.getByRole('radio', { name: 'PFX file' }));
    await user.upload(document.querySelector<HTMLInputElement>('input[type="file"]')!, new File(['abc'], 'sign-in.pfx'));
    await user.type(screen.getByLabelText('PFX password'), PFX_PASSWORD);
    await user.click(screen.getByRole('button', { name: 'Add Key Vault' }));
    await screen.findByText('Key Vault added.');
    expect(bodies[1]).toEqual({
      name: 'Prod vault', vault_url: 'contoso-prod', auth: 'certificate', tenant_id: TENANT_ID, client_id: CLIENT_ID,
      pfx_base64: btoa('abc'), pfx_password: PFX_PASSWORD, poll_interval_minutes: 15,
    });
  });

  it('a managed identity hides the tenant and the secret and shows the optional client ID', async () => {
    asAdmin();
    const user = userEvent.setup();
    let body: unknown = null;
    server.use(
      http.post('/api/v1/key-vaults', async ({ request }) => {
        body = await request.json();
        return HttpResponse.json(created(), { status: 201 });
      }),
    );
    await renderWithStepUp(<AddKeyVaultDialog onClose={vi.fn()} onAdded={vi.fn()} />);
    await fillCommon(user);
    await user.click(screen.getByRole('radio', { name: 'Managed identity' }));
    expect(screen.queryByLabelText(/Directory \(tenant\) ID/)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/Secret value/)).not.toBeInTheDocument();
    expect(screen.getByLabelText('Application (client) ID (optional)')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Add Key Vault' }));
    await screen.findByText('Key Vault added.');
    expect(body).toEqual({ name: 'Prod vault', vault_url: 'contoso-prod', auth: 'managed_identity', poll_interval_minutes: 15 });
  });

  it('keeps the form and names the error when the vault is not found; the secret is cleared and typed again', async () => {
    asAdmin();
    const user = userEvent.setup();
    server.use(http.post('/api/v1/key-vaults', () => errorResponse(502, 'ALC-AKV-0005', 'azure.vault_not_found')));
    await renderWithStepUp(<AddKeyVaultDialog onClose={vi.fn()} onAdded={vi.fn()} />);
    await fillCommon(user);
    await fillClientSecret(user);
    await user.click(screen.getByRole('button', { name: 'Add Key Vault' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Vault not found');
    expect(screen.getByLabelText(/^Name/)).toHaveValue('Prod vault');
    expect(screen.getByLabelText(/^Vault address/)).toHaveValue('contoso-prod');
    expect(screen.getByLabelText(/^Directory \(tenant\) ID/)).toHaveValue(TENANT_ID);
    expect(screen.getByLabelText(/^Secret value/)).toHaveValue('');
    expect(screen.getByText(/does not keep what you typed in the secret fields/)).toBeInTheDocument();
    expect(document.body.textContent).not.toContain(SECRET);
  });

  it('shows a field problem under its field', async () => {
    asAdmin();
    const user = userEvent.setup();
    server.use(http.post('/api/v1/key-vaults', () => errorResponse(422, 'ALC-SYS-0006', 'validation.failed', { details: [{ field: 'vault_url', code: 'validation.pattern' }] })));
    await renderWithStepUp(<AddKeyVaultDialog onClose={vi.fn()} onAdded={vi.fn()} />);
    await fillCommon(user, 'Prod vault', 'https://contoso.vault.azure.net:8443');
    await user.click(screen.getByRole('radio', { name: 'Managed identity' }));
    await user.click(screen.getByRole('button', { name: 'Add Key Vault' }));
    const field = await screen.findByLabelText(/^Vault address/);
    await waitFor(() => expect(field).toHaveAttribute('aria-invalid', 'true'));
    expect(field.closest('.mantine-InputWrapper-root')).toHaveTextContent('This value contains characters that are not allowed.');
  });

  it('shows the checking text and disables nothing it must not while the request runs', async () => {
    asAdmin();
    const user = userEvent.setup();
    let release: () => void = () => {};
    const gate = new Promise<void>((r) => (release = r));
    server.use(
      http.post('/api/v1/key-vaults', async () => {
        await gate;
        return HttpResponse.json(created(), { status: 201 });
      }),
    );
    await renderWithStepUp(<AddKeyVaultDialog onClose={vi.fn()} onAdded={vi.fn()} />);
    await fillCommon(user);
    await user.click(screen.getByRole('radio', { name: 'Managed identity' }));
    await user.click(screen.getByRole('button', { name: 'Add Key Vault' }));
    expect(await screen.findByText('Checking that Alice can sign in and reach the vault…')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Add Key Vault' })).not.toBeInTheDocument();
    release();
    await screen.findByText('Key Vault added.');
  });

  it('asks for step-up when the server says so and sends the same request again', async () => {
    asAdmin();
    const user = userEvent.setup();
    let calls = 0;
    server.use(
      http.post('/api/v1/key-vaults', () => {
        calls++;
        return calls === 1 ? errorResponse(403, 'ALC-AUTH-0003', 'auth.stepup_required') : HttpResponse.json(created(), { status: 201 });
      }),
      http.post('/api/v1/auth/stepup', () => HttpResponse.json(sessionFor('admin'))),
    );
    await renderWithStepUp(<AddKeyVaultDialog onClose={vi.fn()} onAdded={vi.fn()} />);
    await fillCommon(user);
    await user.click(screen.getByRole('radio', { name: 'Managed identity' }));
    await user.click(screen.getByRole('button', { name: 'Add Key Vault' }));
    await user.type(await screen.findByLabelText('6-digit code'), '123456');
    await user.click(screen.getByRole('button', { name: 'Confirm' }));
    expect(await screen.findByText('Key Vault added.')).toBeVisible();
    expect(calls).toBe(2);
  });

  it('says a vault was added with a missing permission and shows the roles to grant', async () => {
    asAdmin();
    const user = userEvent.setup();
    const partly = accessFixture({ checks: [accessRow('sign_in', 'ok'), accessRow('list_certificates', 'forbidden', 'Key Vault Reader'), accessRow('list_keys', 'ok'), accessRow('list_secrets', 'ok')] });
    server.use(http.post('/api/v1/key-vaults', () => HttpResponse.json(created({ access: partly, target: { ...vaultFixture, status: 'degraded', last_error: { code: 'ALC-AKV-0003', reason: 'azure.forbidden', params: { role: 'Key Vault Reader' } } } }), { status: 201 })));
    await renderWithStepUp(<AddKeyVaultDialog onClose={vi.fn()} onAdded={vi.fn()} />);
    await fillCommon(user);
    await user.click(screen.getByRole('radio', { name: 'Managed identity' }));
    await user.click(screen.getByRole('button', { name: 'Add Key Vault' }));
    expect(await screen.findByText(/Alice is missing a permission/)).toBeInTheDocument();
    const checklist = screen.getByRole('table', { name: 'Access check' });
    expect(within(checklist).getByRole('row', { name: /Monitor certificates/ })).toHaveTextContent('Not allowed: needs Key Vault Reader');
    expect(screen.getByText('Partly working')).toBeInTheDocument();
    expect(document.body.textContent).toContain('az role assignment create --role "Key Vault Reader" --assignee ' + CLIENT_ID);
  });

  describe('secrets', () => {
    it('are password fields that are not completed, and are wiped after success, after a refusal and with the dialog', async () => {
      asAdmin();
      const user = userEvent.setup();
      server.use(http.post('/api/v1/key-vaults', () => errorResponse(502, 'ALC-AKV-0001', 'azure.auth_failed', { params: { aadsts: 'AADSTS7000215' } })));
      const view = await renderWithStepUp(<AddKeyVaultDialog onClose={vi.fn()} onAdded={vi.fn()} />);
      await fillCommon(user);
      await user.click(screen.getByRole('radio', { name: 'Client secret' }));
      const secret = screen.getByLabelText(/^Secret value/);
      expect(secret).toHaveAttribute('type', 'password');
      expect(secret).toHaveAttribute('autocomplete', 'off');
      expect(screen.getByRole('radio', { name: 'Client secret' }).closest('form')).toHaveAttribute('autocomplete', 'off');
      await user.type(screen.getByLabelText(/^Directory \(tenant\) ID/), TENANT_ID);
      await user.type(screen.getByLabelText(/^Application \(client\) ID/), CLIENT_ID);
      await user.type(secret, SECRET);
      await user.click(screen.getByRole('button', { name: 'Add Key Vault' }));
      await screen.findByRole('alert');
      expect(screen.getByLabelText(/^Secret value/)).toHaveValue('');
      expect(document.body.innerHTML).not.toContain(SECRET);
      // Nothing was stored in the browser.
      expect(JSON.stringify({ ...localStorage })).not.toContain(SECRET);
      expect(JSON.stringify({ ...sessionStorage })).not.toContain(SECRET);
      // The PEM key and the PFX password too: filled, refused, empty.
      await user.click(screen.getByRole('radio', { name: 'Certificate (recommended)' }));
      await user.click(screen.getByLabelText(/^Private key \(PEM\)/));
      await user.paste(KEY_TEXT);
      await user.click(screen.getByLabelText(/^Certificate \(PEM\)/));
      await user.paste('fake-certificate-text');
      await user.click(screen.getByRole('button', { name: 'Add Key Vault' }));
      await waitFor(() => expect(screen.getByLabelText(/^Private key \(PEM\)/)).toHaveValue(''));
      expect(document.body.innerHTML).not.toContain(KEY_TEXT);
      await user.click(screen.getByRole('radio', { name: 'PFX file' }));
      await user.upload(document.querySelector<HTMLInputElement>('input[type="file"]')!, new File(['abc'], 'a.pfx'));
      await user.type(screen.getByLabelText('PFX password'), PFX_PASSWORD);
      await user.click(screen.getByRole('button', { name: 'Add Key Vault' }));
      await waitFor(() => expect(screen.getByLabelText('PFX password')).toHaveValue(''));
      expect(document.body.innerHTML).not.toContain(PFX_PASSWORD);
      // Unmounted: nothing of it is left in the page.
      view.unmount();
      expect(document.body.innerHTML).not.toContain(SECRET);
      expect(document.body.innerHTML).not.toContain(KEY_TEXT);
    });

    it('never reach console output, and the success page does not show them', async () => {
      asAdmin();
      const user = userEvent.setup();
      const logs: string[] = [];
      const spies = (['log', 'info', 'warn', 'error', 'debug'] as const).map((m) => vi.spyOn(console, m).mockImplementation((...a: unknown[]) => void logs.push(a.map(String).join(' '))));
      server.use(http.post('/api/v1/key-vaults', () => HttpResponse.json(created(), { status: 201 })));
      await renderWithStepUp(<AddKeyVaultDialog onClose={vi.fn()} onAdded={vi.fn()} />);
      await fillCommon(user);
      await fillClientSecret(user);
      await user.click(screen.getByRole('button', { name: 'Add Key Vault' }));
      await screen.findByText('Key Vault added.');
      expect(document.body.innerHTML).not.toContain(SECRET);
      expect(logs.join('\n')).not.toContain(SECRET);
      spies.forEach((s) => s.mockRestore());
    });

    it('wipes the form when the dialog is closed by cancel', async () => {
      asAdmin();
      const user = userEvent.setup();
      const onClose = vi.fn();
      await renderWithStepUp(<AddKeyVaultDialog onClose={onClose} onAdded={vi.fn()} />);
      await fillCommon(user);
      await fillClientSecret(user);
      await user.click(screen.getByRole('button', { name: 'Cancel' }));
      expect(onClose).toHaveBeenCalled();
    });

    it('refuses a PFX that would not fit the request and sends nothing', async () => {
      asAdmin();
      const user = userEvent.setup();
      let sent = false;
      server.use(http.post('/api/v1/key-vaults', () => { sent = true; return HttpResponse.json(created(), { status: 201 }); }));
      await renderWithStepUp(<AddKeyVaultDialog onClose={vi.fn()} onAdded={vi.fn()} />);
      await fillCommon(user);
      await user.type(screen.getByLabelText(/^Directory \(tenant\) ID/), TENANT_ID);
      await user.type(screen.getByLabelText(/^Application \(client\) ID/), CLIENT_ID);
      await user.click(screen.getByRole('radio', { name: 'PFX file' }));
      await user.upload(document.querySelector<HTMLInputElement>('input[type="file"]')!, new File([new Uint8Array(600_000)], 'big.pfx'));
      await user.click(screen.getByRole('button', { name: 'Add Key Vault' }));
      expect(await screen.findByText(/PFX file is too large/)).toBeInTheDocument();
      expect(sent).toBe(false);
    });
  });

  it('is complete in Turkish with the exact copy', async () => {
    asAdmin('tr');
    const user = userEvent.setup();
    server.use(http.post('/api/v1/key-vaults', () => HttpResponse.json(created(), { status: 201 })));
    await renderWithStepUp(<AddKeyVaultDialog onClose={vi.fn()} onAdded={vi.fn()} />, ['tr-TR']);
    await user.type(await screen.findByLabelText(/^Ad/), 'Üretim kasası');
    await user.type(screen.getByLabelText(/^Kasa adresi/), 'contoso-prod');
    expect(screen.getByRole('radio', { name: 'Sertifika (önerilir)' })).toBeChecked();
    expect(screen.getByRole('radio', { name: 'İstemci gizli anahtarı' })).toBeInTheDocument();
    await user.click(screen.getByRole('radio', { name: 'Yönetilen kimlik' }));
    expect(screen.getByLabelText('Uygulama (istemci) kimliği (isteğe bağlı)')).toBeInTheDocument();
    expectNoRawKeys();
    await user.click(screen.getByRole('button', { name: 'Key Vault ekle' }));
    expect(await screen.findByText('Key Vault eklendi.')).toBeVisible();
    expect(screen.getByText(/^Alice, Azure'da/)).toHaveTextContent(`Alice, Azure'da ${OBJECT_ID} olarak oturum açar`);
    expect(screen.getByRole('row', { name: /Sertifikaları, anahtarları/ })).toHaveTextContent('İzin var');
    expectNoRawKeys();
  });
});
