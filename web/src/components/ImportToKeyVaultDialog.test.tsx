import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { importName, ImportToKeyVaultDialog } from './ImportToKeyVaultDialog';
import { certificateFixture, errorResponse, jobFixture, kvImportFixture, sessionFor, sessionHandlers, vaultFixture, vaultWith, VAULT_ID } from '../test/fixtures';
import { expectNoRawKeys } from '../test/i18nAssert';
import { renderWithStepUp } from '../test/render';
import { server } from '../test/server';

const CERT = certificateFixture({ id: 'cert-1', subject_cn: 'www.example.test', has_private_key: true });
const IMPORT_URL = '/api/v1/certificates/cert-1/actions/import-to-key-vault';

function asAdmin(lang = 'en', vaults = [vaultFixture]) {
  server.use(...sessionHandlers(sessionFor('admin', lang)), http.get('/api/v1/targets', () => HttpResponse.json({ items: vaults, next_cursor: null })));
}

function accepted(i = kvImportFixture({ state: 'queued' })) {
  return HttpResponse.json({ import: i, job_id: 'j-imp', status_url: '/api/v1/jobs/j-imp' }, { status: 202 });
}

function job(status: 'succeeded' | 'failed' | 'blocked_license' = 'succeeded') {
  server.use(http.get('/api/v1/jobs/j-imp', () => HttpResponse.json(jobFixture({ id: 'j-imp', type: 'kv.import', status }))));
}

function imp(i: Parameters<typeof kvImportFixture>[0]) {
  server.use(http.get(`/api/v1/targets/${VAULT_ID}/kv/imports/${kvImportFixture().id}`, () => HttpResponse.json(kvImportFixture(i))));
}

describe('importName', () => {
  it('replaces every character outside letters, digits and hyphen and trims to 127', () => {
    expect(importName('www.example.test')).toBe('www-example-test');
    expect(importName('*.example.test')).toBe('--example-test');
    expect(importName('ünï cödé_1')).toBe('-n--c-d--1');
    expect(importName('a'.repeat(200))).toHaveLength(127);
    expect(importName('')).toBe('');
  });
});

describe('ImportToKeyVaultDialog', () => {
  it('offers the vaults only, prefills the name from the common name and shows the note', async () => {
    asAdmin('en', [vaultFixture, vaultWith({ id: 'v2', name: 'Other vault' }), vaultWith({ id: 'v3', name: 'Off vault', status: 'disabled' })]);
    await renderWithStepUp(<ImportToKeyVaultDialog certificate={CERT} onClose={vi.fn()} />);
    const select = (await screen.findByLabelText('Vault')) as HTMLSelectElement;
    await waitFor(() => expect(within(select).getAllByRole('option').map((o) => o.textContent)).toEqual(['Prod vault', 'Other vault']));
    expect(screen.getByLabelText(/^Certificate name in the vault/)).toHaveValue('www-example-test');
    expect(screen.getByText('An imported certificate does not renew itself in Key Vault.')).toBeInTheDocument();
  });

  it('validates the name as typed', async () => {
    asAdmin();
    const user = userEvent.setup();
    await renderWithStepUp(<ImportToKeyVaultDialog certificate={CERT} onClose={vi.fn()} />);
    const name = await screen.findByLabelText(/^Certificate name in the vault/);
    await user.clear(name);
    await user.type(name, 'bad name!');
    expect(screen.getByText('Use letters, digits and hyphens only, 1 to 127 characters.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Import into Key Vault' })).toBeDisabled();
    await user.clear(name);
    await user.type(name, 'good-name');
    expect(screen.getByRole('button', { name: 'Import into Key Vault' })).toBeEnabled();
  });

  it('says so when there is no vault', async () => {
    asAdmin('en', []);
    await renderWithStepUp(<ImportToKeyVaultDialog certificate={CERT} onClose={vi.fn()} />);
    expect(await screen.findByText('There is no Key Vault yet. Add one first.')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Open Key Vaults' })).toHaveAttribute('href', '/key-vaults');
    expect(screen.getByRole('button', { name: 'Import into Key Vault' })).toBeDisabled();
  });

  it('posts the import and shows Imported with the vault version in <code>', async () => {
    asAdmin();
    let body: unknown = null;
    server.use(http.post(IMPORT_URL, async ({ request }) => { body = await request.json(); return accepted(); }));
    job();
    imp({ state: 'succeeded' });
    const user = userEvent.setup();
    await renderWithStepUp(<ImportToKeyVaultDialog certificate={CERT} onClose={vi.fn()} />);
    await screen.findByRole('option', { name: 'Prod vault' });
    await user.click(screen.getByRole('button', { name: 'Import into Key Vault' }));
    const outcome = await screen.findByTestId('import-outcome');
    expect(outcome).toHaveAttribute('data-state', 'succeeded');
    expect(outcome).toHaveTextContent('Imported');
    expect(within(outcome).getByText('0123456789abcdef0123456789abcdef').tagName).toBe('CODE');
    expect(body).toEqual({ target_id: VAULT_ID, name: 'www-example-test' });
  });

  it('shows Not confirmed yet with the explanation that the next check confirms it, including a swept import without an error', async () => {
    asAdmin();
    server.use(http.post(IMPORT_URL, () => accepted()));
    job('failed');
    imp({ state: 'uncertain', error: null, version: '', finished_at: null });
    await renderWithStepUp(<ImportToKeyVaultDialog certificate={CERT} onClose={vi.fn()} />);
    await screen.findByRole('option', { name: 'Prod vault' });
    await userEvent.click(screen.getByRole('button', { name: 'Import into Key Vault' }));
    const outcome = await screen.findByTestId('import-outcome');
    expect(outcome).toHaveAttribute('data-state', 'uncertain');
    expect(outcome).toHaveTextContent('Not confirmed yet');
    expect(outcome).toHaveTextContent('Alice sent the certificate but could not confirm that Key Vault stored it. Alice keeps checking the vault and shows the result here. Do not import it again while this is shown.');
    expect(screen.queryByText('Failed')).not.toBeInTheDocument();
  });

  it('shows Outcome unknown with its own explanation and the catalogue text, not a plain failure', async () => {
    asAdmin();
    server.use(http.post(IMPORT_URL, () => accepted()));
    job();
    imp({ state: 'failed', error: { code: 'ALC-AKV-0026', reason: 'kv.import_outcome_unknown' }, version: '' });
    await renderWithStepUp(<ImportToKeyVaultDialog certificate={CERT} onClose={vi.fn()} />);
    await screen.findByRole('option', { name: 'Prod vault' });
    await userEvent.click(screen.getByRole('button', { name: 'Import into Key Vault' }));
    const outcome = await screen.findByTestId('import-outcome');
    expect(outcome).toHaveAttribute('data-state', 'unknown');
    expect(within(outcome).getAllByText('Outcome unknown').length).toBeGreaterThan(0);
    expect(outcome).toHaveTextContent('Look for the certificate in the vault.');
    expect(outcome).toHaveTextContent('Import outcome unknown');
  });

  it('shows the error of a failed import by its title and offers a retry when nothing reached the vault', async () => {
    asAdmin();
    server.use(http.post(IMPORT_URL, () => accepted()));
    job('failed');
    imp({ state: 'failed', can_retry: true, error: { code: 'ALC-AKV-0003', reason: 'azure.forbidden', params: { role: 'Key Vault Certificates Officer' } }, version: '' });
    await renderWithStepUp(<ImportToKeyVaultDialog certificate={CERT} onClose={vi.fn()} />);
    await screen.findByRole('option', { name: 'Prod vault' });
    await userEvent.click(screen.getByRole('button', { name: 'Import into Key Vault' }));
    const outcome = await screen.findByTestId('import-outcome');
    expect(outcome).toHaveTextContent('Failed');
    expect(outcome).toHaveTextContent('Missing permission in the vault');
    expect(outcome).toHaveTextContent('Nothing reached the vault, so you can try again.');
    await userEvent.click(screen.getByRole('button', { name: 'Try again' }));
    expect(await screen.findByLabelText(/^Certificate name in the vault/)).toBeInTheDocument();
  });

  it('shows a held import as waiting for an administrator', async () => {
    asAdmin();
    server.use(http.post(IMPORT_URL, () => accepted()));
    job('blocked_license');
    await renderWithStepUp(<ImportToKeyVaultDialog certificate={CERT} onClose={vi.fn()} />);
    await screen.findByRole('option', { name: 'Prod vault' });
    await userEvent.click(screen.getByRole('button', { name: 'Import into Key Vault' }));
    expect(await screen.findByText('This task is paused and waits for an administrator to run it.')).toBeInTheDocument();
  });

  describe('a name the vault already has', () => {
    function refuse(params: Record<string, string>) {
      const bodies: unknown[] = [];
      server.use(
        http.post(IMPORT_URL, async ({ request }) => {
          const b = (await request.json()) as { confirm_new_version?: boolean };
          bodies.push(b);
          return b.confirm_new_version ? accepted(kvImportFixture({ state: 'queued', new_version: true })) : errorResponse(409, 'ALC-AKV-0023', 'kv.import_confirm_needed', { params });
        }),
      );
      return bodies;
    }

    it('shows the warning with the name in <code> and a required confirmation, then resends with confirm_new_version', async () => {
      asAdmin();
      const bodies = refuse({ certificate_name: 'www-example-test', bound: 'false', auto_deploy_follows: 'false' });
      job();
      imp({ state: 'succeeded', new_version: true });
      const user = userEvent.setup();
      await renderWithStepUp(<ImportToKeyVaultDialog certificate={CERT} onClose={vi.fn()} />);
      await screen.findByRole('option', { name: 'Prod vault' });
      await user.click(screen.getByRole('button', { name: 'Import into Key Vault' }));
      const warning = await screen.findByTestId('import-confirm');
      expect(warning).toHaveTextContent('This will add a new version to the existing certificate www-example-test.');
      expect(within(warning).getByText('www-example-test').tagName).toBe('CODE');
      expect(warning).toHaveTextContent("replaces the certificate's settings in the vault");
      expect(warning).not.toHaveTextContent('Websites are connected');
      const submit = screen.getByRole('button', { name: 'Import into Key Vault' });
      expect(submit).toBeDisabled();
      await user.click(screen.getByLabelText('I understand and want to add a new version'));
      await user.click(submit);
      expect(await screen.findByTestId('import-outcome')).toHaveAttribute('data-state', 'succeeded');
      expect(bodies).toEqual([{ target_id: VAULT_ID, name: 'www-example-test' }, { target_id: VAULT_ID, name: 'www-example-test', confirm_new_version: true }]);
    });

    it('says that automatic deployment follows when a connection with it names the certificate', async () => {
      asAdmin();
      refuse({ certificate_name: 'www-example-test', bound: 'true', auto_deploy_follows: 'true' });
      await renderWithStepUp(<ImportToKeyVaultDialog certificate={CERT} onClose={vi.fn()} />);
      await screen.findByRole('option', { name: 'Prod vault' });
      await userEvent.click(screen.getByRole('button', { name: 'Import into Key Vault' }));
      const warning = await screen.findByTestId('import-confirm');
      expect(warning).toHaveTextContent('Websites are connected to this vault certificate.');
      expect(warning).toHaveTextContent('Automatic deployment is on for it, so Alice may deploy the new version to those websites by itself.');
    });

    it('says nothing is deployed by itself when a connection exists with automatic deployment off', async () => {
      asAdmin();
      refuse({ certificate_name: 'www-example-test', bound: 'true', auto_deploy_follows: 'false' });
      await renderWithStepUp(<ImportToKeyVaultDialog certificate={CERT} onClose={vi.fn()} />);
      await screen.findByRole('option', { name: 'Prod vault' });
      await userEvent.click(screen.getByRole('button', { name: 'Import into Key Vault' }));
      const warning = await screen.findByTestId('import-confirm');
      expect(warning).toHaveTextContent('Automatic deployment is off for it, so nothing is deployed by itself.');
    });

    it('drops the confirmation when the name is changed', async () => {
      asAdmin();
      refuse({ certificate_name: 'www-example-test', bound: 'false', auto_deploy_follows: 'false' });
      const user = userEvent.setup();
      await renderWithStepUp(<ImportToKeyVaultDialog certificate={CERT} onClose={vi.fn()} />);
      await screen.findByRole('option', { name: 'Prod vault' });
      await user.click(screen.getByRole('button', { name: 'Import into Key Vault' }));
      await screen.findByTestId('import-confirm');
      await user.type(screen.getByLabelText(/^Certificate name in the vault/), 'x');
      expect(screen.queryByTestId('import-confirm')).not.toBeInTheDocument();
    });
  });

  it('asks for step-up and sends the same request again', async () => {
    asAdmin();
    let calls = 0;
    server.use(
      http.post(IMPORT_URL, () => (++calls === 1 ? errorResponse(403, 'ALC-AUTH-0003', 'auth.stepup_required') : accepted())),
      http.post('/api/v1/auth/stepup', () => HttpResponse.json(sessionFor('admin'))),
    );
    job();
    imp({ state: 'succeeded' });
    const user = userEvent.setup();
    await renderWithStepUp(<ImportToKeyVaultDialog certificate={CERT} onClose={vi.fn()} />);
    await screen.findByRole('option', { name: 'Prod vault' });
    await user.click(screen.getByRole('button', { name: 'Import into Key Vault' }));
    await user.type(await screen.findByLabelText('6-digit code'), '123456');
    await user.click(screen.getByRole('button', { name: 'Confirm' }));
    await screen.findByTestId('import-outcome');
    expect(calls).toBe(2);
  });

  it('shows the refusal of a name whose import is still open', async () => {
    asAdmin();
    server.use(http.post(IMPORT_URL, () => errorResponse(409, 'ALC-AKV-0024', 'kv.import_in_progress')));
    await renderWithStepUp(<ImportToKeyVaultDialog certificate={CERT} onClose={vi.fn()} />);
    await screen.findByRole('option', { name: 'Prod vault' });
    await userEvent.click(screen.getByRole('button', { name: 'Import into Key Vault' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Import already running');
  });

  it('is complete in Turkish', async () => {
    asAdmin('tr');
    server.use(http.post(IMPORT_URL, () => errorResponse(409, 'ALC-AKV-0023', 'kv.import_confirm_needed', { params: { certificate_name: 'www-example-test', bound: 'true', auto_deploy_follows: 'true' } })));
    await renderWithStepUp(<ImportToKeyVaultDialog certificate={CERT} onClose={vi.fn()} />, ['tr-TR']);
    await screen.findByRole('option', { name: 'Prod vault' });
    expect(screen.getByText("İçe aktarılan sertifika Key Vault'ta kendini yenilemez.")).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: "Key Vault'a aktar" }));
    const warning = await screen.findByTestId('import-confirm');
    expect(warning).toHaveTextContent('Bu, mevcut www-example-test sertifikasına yeni bir sürüm ekler.');
    expectNoRawKeys(warning);
  });
});

describe('ImportToKeyVaultDialog outcome in Turkish', () => {
  it.each([
    ['uncertain', { state: 'uncertain', error: null }, 'Henüz doğrulanmadı'],
    ['unknown', { state: 'failed', error: { code: 'ALC-AKV-0026', reason: 'kv.import_outcome_unknown' } }, 'Sonuç bilinmiyor'],
    ['succeeded', { state: 'succeeded' }, 'İçe aktarıldı'],
  ] as const)('%s', async (_n, patch, label) => {
    asAdmin('tr');
    server.use(http.post(IMPORT_URL, () => accepted()));
    job();
    imp(patch);
    await renderWithStepUp(<ImportToKeyVaultDialog certificate={CERT} onClose={vi.fn()} />, ['tr-TR']);
    await screen.findByRole('option', { name: 'Prod vault' });
    await userEvent.click(screen.getByRole('button', { name: "Key Vault'a aktar" }));
    const outcome = await screen.findByTestId('import-outcome');
    expect(within(outcome).getAllByText(label).length).toBeGreaterThan(0);
  });
});

describe('ImportToKeyVaultDialog fix round', () => {
  async function start() {
    await screen.findByRole('option', { name: 'Prod vault' });
    await userEvent.click(screen.getByRole('button', { name: 'Import into Key Vault' }));
  }

  it('shows the import text and no Import button when the wait ends while the job still runs (a second send is refused)', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      asAdmin();
      server.use(http.post(IMPORT_URL, () => accepted()), http.get('/api/v1/jobs/j-imp', () => HttpResponse.json(jobFixture({ id: 'j-imp', type: 'kv.import', status: 'running' }))));
      await renderWithStepUp(<ImportToKeyVaultDialog certificate={CERT} onClose={vi.fn()} />);
      await screen.findByRole('option', { name: 'Prod vault' });
      await userEvent.setup({ advanceTimers: vi.advanceTimersByTime }).click(screen.getByRole('button', { name: 'Import into Key Vault' }));
      vi.setSystemTime(Date.now() + 200_000);
      expect(await screen.findByText('The import is still running. Its result appears in the import history of the certificate.', {}, { timeout: 8000 })).toBeInTheDocument();
      expect(screen.queryByRole('button', { name: 'Import into Key Vault' })).not.toBeInTheDocument();
      expect(screen.getAllByRole('button', { name: 'Close' }).length).toBeGreaterThan(0);
      expect(document.body.textContent).not.toMatch(/server's page/);
    } finally {
      vi.useRealTimers();
    }
  }, 20_000);

  it('shows the import text and no Import button for an import that is running when the job ended', async () => {
    asAdmin();
    server.use(http.post(IMPORT_URL, () => accepted()));
    job();
    imp({ state: 'running', version: '', finished_at: null });
    await renderWithStepUp(<ImportToKeyVaultDialog certificate={CERT} onClose={vi.fn()} />);
    await start();
    expect(await screen.findByText('The import is still running. Its result appears in the import history of the certificate.')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Import into Key Vault' })).not.toBeInTheDocument();
  });

  it.each([
    ['an uncertain import, even when the record says it can be retried', { state: 'uncertain', can_retry: true, error: null, version: '' }],
    ['a failed import that cannot be retried', { state: 'failed', can_retry: false, error: { code: 'ALC-AKV-0025', reason: 'kv.import_rejected' }, version: '' }],
    ['a succeeded import', { state: 'succeeded', can_retry: true }],
  ] as const)('offers no Try again for %s', async (_n, patch) => {
    asAdmin();
    server.use(http.post(IMPORT_URL, () => accepted()));
    job();
    imp(patch);
    await renderWithStepUp(<ImportToKeyVaultDialog certificate={CERT} onClose={vi.fn()} />);
    await start();
    await screen.findByTestId('import-outcome');
    expect(screen.queryByRole('button', { name: 'Try again' })).not.toBeInTheDocument();
  });

  it('drops the confirmation when another vault is chosen', async () => {
    asAdmin('en', [vaultFixture, vaultWith({ id: 'v2', name: 'Other vault' })]);
    server.use(http.post(IMPORT_URL, () => errorResponse(409, 'ALC-AKV-0023', 'kv.import_confirm_needed', { params: { certificate_name: 'www-example-test', bound: 'false', auto_deploy_follows: 'false' } })));
    await renderWithStepUp(<ImportToKeyVaultDialog certificate={CERT} onClose={vi.fn()} />);
    await screen.findByRole('option', { name: 'Other vault' });
    await userEvent.click(screen.getByRole('button', { name: 'Import into Key Vault' }));
    await screen.findByTestId('import-confirm');
    await userEvent.selectOptions(screen.getByLabelText('Vault'), 'v2');
    expect(screen.queryByTestId('import-confirm')).not.toBeInTheDocument();
  });
});

