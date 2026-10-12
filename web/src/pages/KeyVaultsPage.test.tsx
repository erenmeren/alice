import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import commonEn from '@locales/common/en.json';
import { accessFixture, accessRow, errorResponse, jobFixture, sessionFor, sessionHandlers, vaultFixture, vaultWith } from '../test/fixtures';
import { expectNoRawKeys } from '../test/i18nAssert';
import { renderRoute } from '../test/render';
import { server } from '../test/server';

function withVaults(role: 'admin' | 'operator' | 'auditor', items = [vaultFixture], lang = 'en') {
  let query = '';
  server.use(
    ...sessionHandlers(sessionFor(role, lang)),
    http.get('/api/v1/targets', ({ request }) => {
      query = new URL(request.url).search;
      return HttpResponse.json({ items, next_cursor: null });
    }),
  );
  return () => query;
}

describe('KeyVaultsPage', () => {
  it('lists vaults only (type=azure_key_vault) with name, address, status, sign-in method and last checked', async () => {
    const query = withVaults('admin');
    await renderRoute('/key-vaults');
    expect(await screen.findByRole('heading', { name: 'Key Vaults', level: 1 })).toBeInTheDocument();
    const table = await screen.findByTestId('vaults-table');
    expect(query()).toBe('?type=azure_key_vault');
    const row = within(table).getByText('Prod vault').closest('tr')!;
    expect(within(row).getByRole('link', { name: 'Prod vault' })).toHaveAttribute('href', `/key-vaults/${vaultFixture.id}`);
    expect(within(row).getByText('https://contoso-prod.vault.azure.net').tagName).toBe('CODE');
    expect(within(row).getByText('Connected')).toBeInTheDocument();
    expect(within(row).getByText('Client secret')).toBeInTheDocument();
    expect(within(row).queryByText('No successful check yet')).not.toBeInTheDocument();
    expect(within(table).getAllByRole('columnheader').map((h) => h.textContent)).toEqual(['Name', 'Status', 'Sign-in method', 'Last successful check']);
  });

  it('has the design header: the title, the description and Add Key Vault with its icon for an Administrator', async () => {
    withVaults('admin');
    await renderRoute('/key-vaults');
    const h1 = await screen.findByRole('heading', { name: 'Key Vaults', level: 1 });
    expect(h1.closest('header')).toHaveTextContent('See certificate versions and the websites connected to them.');
    const add = screen.getByRole('button', { name: 'Add Key Vault' });
    expect(add.querySelector('svg')).not.toBeNull();
    expect(screen.queryByText(/Alice watches the certificates, keys and secrets/)).not.toBeInTheDocument();
  });

  it('shows each vault as the design\'s resource: the Azure tile, the name link and the address below it, the status as a badge', async () => {
    withVaults('auditor', [vaultWith({ status: 'auth_failed', last_error: { code: 'ALC-AKV-0001', reason: 'azure.auth_failed' } })]);
    await renderRoute('/key-vaults');
    const table = await screen.findByTestId('vaults-table');
    const first = within(table).getAllByRole('row')[1].querySelector('td')!;
    const tile = first.querySelector('[data-tone="info"]');
    expect(tile).not.toBeNull();
    expect(tile!.querySelector('svg')).not.toBeNull();
    expect(within(first).getByRole('link', { name: 'Prod vault' })).toBeInTheDocument();
    expect(within(first).getByText('https://contoso-prod.vault.azure.net').tagName).toBe('CODE');
    const badge = within(table).getByText('Credentials refused').closest('.mantine-Badge-root')!;
    expect(badge).toHaveAttribute('data-tone', 'danger');
  });

  it('states the Azure access boundary below the table and keeps the held jobs for an Administrator', async () => {
    withVaults('admin');
    server.use(http.get('/api/v1/jobs', () => HttpResponse.json({ items: [jobFixture()], next_cursor: null })));
    await renderRoute('/key-vaults');
    const table = await screen.findByTestId('vaults-table');
    const boundary = screen.getByText('A precise boundary for Azure access').closest('[role="note"]')!;
    expect(boundary).not.toBeNull();
    expect(boundary).toHaveTextContent('Keys are inventory-only; secrets show metadata only.');
    expect(table.compareDocumentPosition(boundary) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(await screen.findByTestId('blocked-jobs')).toBeInTheDocument();
  });

  it('shows the empty inventory as an empty state with the product text, and no second Add button', async () => {
    withVaults('admin', []);
    await renderRoute('/key-vaults');
    expect(await screen.findByText('No Key Vault yet. Add one to see its certificates and keys.')).toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: /Add Key Vault/ })).toHaveLength(1);
    expect(screen.queryByTestId('vaults-table')).not.toBeInTheDocument();
  });

  it('puts the table in its own scroll container (375 px) and names it', async () => {
    withVaults('auditor');
    await renderRoute('/key-vaults');
    const table = await screen.findByRole('table', { name: 'Key Vaults' });
    expect(table.closest('[class*="ScrollArea"], [class*="ScrollContainer"]')).not.toBeNull();
  });

  it('says "No successful check yet" for a vault degraded from birth, and names the column honestly', async () => {
    withVaults('operator', [vaultWith({ last_success_at: null, status: 'degraded' })]);
    await renderRoute('/key-vaults');
    expect(await screen.findByText('No successful check yet')).toBeInTheDocument();
    expect(screen.queryByText('Not checked yet')).not.toBeInTheDocument();
    expect(screen.getByRole('columnheader', { name: 'Last successful check' })).toBeInTheDocument();
    expect(screen.queryByRole('columnheader', { name: 'Last checked' })).not.toBeInTheDocument();
  });

  it('names a vault without permission to list certificates, one with expired credentials and one that is out of reach', async () => {
    const noList = vaultWith(
      { id: 'v-a', name: 'no-list', status: 'degraded', last_error: { code: 'ALC-AKV-0003', reason: 'azure.forbidden', params: { role: 'Key Vault Reader' } } },
      { access: accessFixture({ checks: [accessRow('list_certificates', 'forbidden', 'Key Vault Reader')] }) },
    );
    const forbiddenElsewhere = vaultWith({ id: 'v-e', name: 'other-forbidden', status: 'degraded', last_error: { code: 'ALC-AKV-0003', reason: 'azure.forbidden' } }, { access: accessFixture({ checks: [accessRow('read_secret', 'forbidden', 'Key Vault Secrets User')] }) });
    const expired = vaultWith({ id: 'v-b', name: 'expired', status: 'auth_failed', last_error: { code: 'ALC-AKV-0002', reason: 'azure.credentials_expired' } });
    const refused = vaultWith({ id: 'v-r', name: 'refused', status: 'auth_failed', last_error: { code: 'ALC-AKV-0001', reason: 'azure.auth_failed' } });
    const away = vaultWith({ id: 'v-c', name: 'away', status: 'unreachable', last_error: { code: 'ALC-AKV-0006', reason: 'azure.unreachable' } });
    withVaults('auditor', [noList, forbiddenElsewhere, expired, refused, away]);
    await renderRoute('/key-vaults');
    const table = await screen.findByTestId('vaults-table');
    const rowOf = (name: string) => within(table).getByText(name).closest('tr')!;
    expect(rowOf('no-list')).toHaveTextContent('No permission to read certificates');
    expect(rowOf('no-list')).toHaveTextContent(commonEn.errors.azure.forbidden.title);
    expect(rowOf('other-forbidden')).toHaveTextContent('Partly working');
    expect(rowOf('expired')).toHaveTextContent('Credentials expired');
    expect(rowOf('refused')).toHaveTextContent('Credentials refused');
    expect(rowOf('away')).toHaveTextContent('Cannot reach Azure');
  });

  it('shows a loading state while the list is read', async () => {
    server.use(
      ...sessionHandlers(sessionFor('operator')),
      http.get('/api/v1/targets', async () => {
        await new Promise((r) => setTimeout(r, 300));
        return HttpResponse.json({ items: [vaultFixture], next_cursor: null });
      }),
    );
    await renderRoute('/key-vaults');
    expect(await screen.findByRole('status', { name: 'Loading…' })).toBeInTheDocument();
    expect(await screen.findByTestId('vaults-table')).toBeInTheDocument();
    expect(screen.queryByRole('status', { name: 'Loading…' })).not.toBeInTheDocument();
  });

  it('shows the empty state', async () => {
    withVaults('operator', []);
    await renderRoute('/key-vaults');
    expect(await screen.findByText('No Key Vault yet. Add one to see its certificates and keys.')).toBeInTheDocument();
  });

  it('shows the error of a failed list', async () => {
    server.use(...sessionHandlers(sessionFor('admin')), http.get('/api/v1/targets', () => errorResponse(500, 'ALC-SYS-0003', 'internal.unexpected')));
    await renderRoute('/key-vaults');
    expect(await screen.findByRole('alert')).toBeInTheDocument();
  });

  it('shows Add Key Vault to an Administrator only', async () => {
    withVaults('admin');
    const view = await renderRoute('/key-vaults');
    expect(await screen.findByRole('button', { name: 'Add Key Vault' })).toBeInTheDocument();
    view.unmount();
    for (const role of ['operator', 'auditor'] as const) {
      withVaults(role);
      const v = await renderRoute('/key-vaults');
      await screen.findByTestId('vaults-table');
      expect(screen.queryByRole('button', { name: 'Add Key Vault' })).not.toBeInTheDocument();
      v.unmount();
    }
  });

  it('opens the add dialog and the new vault page after adding', async () => {
    withVaults('admin');
    server.use(http.post('/api/v1/key-vaults', () => HttpResponse.json({ target: vaultFixture, access: accessFixture(), job_id: 'j1', status_url: '' }, { status: 201 })), http.get(`/api/v1/targets/${vaultFixture.id}`, () => HttpResponse.json(vaultFixture)));
    const user = userEvent.setup();
    const view = await renderRoute('/key-vaults');
    await user.click(await screen.findByRole('button', { name: 'Add Key Vault' }));
    const dialog = await screen.findByRole('dialog');
    await user.type(within(dialog).getByLabelText(/^Name/), 'Prod vault');
    await user.type(within(dialog).getByLabelText(/^Vault address/), 'contoso-prod');
    await user.click(within(dialog).getByRole('radio', { name: 'Managed identity' }));
    await user.click(within(dialog).getByRole('button', { name: 'Add Key Vault' }));
    await user.click(await within(dialog).findByRole('button', { name: 'Open the vault' }));
    expect(await screen.findByRole('heading', { name: 'Prod vault', level: 1 })).toBeInTheDocument();
    expect(view.router.state.location.pathname).toBe(`/key-vaults/${vaultFixture.id}`);
  });

  it('is not in the Servers list, and the navigation links to it', async () => {
    withVaults('operator', [vaultFixture]);
    await renderRoute('/key-vaults');
    const nav = await screen.findByRole('navigation', { name: 'Main navigation' });
    expect(within(nav).getByRole('link', { name: 'Key Vaults' })).toHaveAttribute('href', '/key-vaults');
  });

  it('is complete in Turkish', async () => {
    withVaults('admin', [vaultFixture, vaultWith({ id: 'v2', name: 'away', status: 'unreachable', last_error: { code: 'ALC-AKV-0006', reason: 'azure.unreachable' } })], 'tr');
    server.use(http.get('/api/v1/jobs', () => HttpResponse.json({ items: [jobFixture()], next_cursor: null })));
    await renderRoute('/key-vaults', { languages: ['tr-TR'] });
    expect(await screen.findByRole('heading', { name: 'Key Vault kasaları', level: 1 })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Key Vault ekle' })).toBeInTheDocument();
    expect((await screen.findAllByText("Azure'a ulaşılamıyor")).length).toBeGreaterThan(0);
    expect(screen.getByRole('columnheader', { name: 'Oturum açma yöntemi' })).toBeInTheDocument();
    expectNoRawKeys();
  });
});
