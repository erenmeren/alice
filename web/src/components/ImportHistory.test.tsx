import { screen, within } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import { errorResponse, kvImportFixture, sessionFor, sessionHandlers, VAULT_ID, vaultFixture, vaultWith } from '../test/fixtures';
import { expectNoRawKeys } from '../test/i18nAssert';
import { renderWithAuth } from '../test/render';
import { server } from '../test/server';
import { ImportHistory } from './ImportHistory';

function setup(vaults = [vaultFixture], imports: Record<string, ReturnType<typeof kvImportFixture>[]> = {}, lang = 'en') {
  const queries: string[] = [];
  server.use(
    ...sessionHandlers(sessionFor('operator', lang)),
    http.get('/api/v1/targets', () => HttpResponse.json({ items: vaults, next_cursor: null })),
    http.get('/api/v1/targets/:id/kv/imports', ({ params, request }) => {
      queries.push(`${String(params.id)}${new URL(request.url).search}`);
      return HttpResponse.json({ items: imports[String(params.id)] ?? [], next_cursor: null });
    }),
  );
  return queries;
}

describe('ImportHistory', () => {
  it('lists the imports of the certificate newest first with vault, name, state, version and the error title', async () => {
    const queries = setup([vaultFixture, vaultWith({ id: 'v2', name: 'Other vault' })], {
      [VAULT_ID]: [
        kvImportFixture({ id: 'i1', created_at: '2026-10-05T09:00:00Z', name: 'first-name' }),
        kvImportFixture({ id: 'i3', created_at: '2026-10-03T09:00:00Z', name: 'failed-name', state: 'failed', version: '', error: { code: 'ALC-AKV-0025', reason: 'kv.import_rejected' } }),
      ],
      v2: [kvImportFixture({ id: 'i2', target_id: 'v2', created_at: '2026-10-04T09:00:00Z', name: 'second-name', state: 'uncertain', version: '', error: null })],
    });
    await renderWithAuth(<ImportHistory certificateId="cert-1" />);
    const rows = await screen.findAllByTestId('import-row');
    expect(rows.map((r) => within(r).getByText(/-name$/).textContent)).toEqual(['first-name', 'second-name', 'failed-name']);
    expect(rows[0]).toHaveTextContent('Prod vault');
    expect(rows[0]).toHaveTextContent('Imported');
    expect(within(rows[0]).getByText('01234567').tagName).toBe('CODE');
    expect(within(rows[0]).getByText('first-name').tagName).toBe('CODE');
    expect(rows[1]).toHaveTextContent('Other vault');
    expect(rows[1]).toHaveTextContent('Not confirmed yet');
    expect(rows[2]).toHaveTextContent('Failed');
    expect(rows[2]).toHaveTextContent('Key Vault refused the import');
    expect(queries.sort()).toEqual([`${VAULT_ID}?certificate_id=cert-1&limit=50`, 'v2?certificate_id=cert-1&limit=50']);
  });

  it('shows Outcome unknown for an import that ended without an answer', async () => {
    setup([vaultFixture], { [VAULT_ID]: [kvImportFixture({ state: 'failed', version: '', error: { code: 'ALC-AKV-0026', reason: 'kv.import_outcome_unknown' } })] });
    await renderWithAuth(<ImportHistory certificateId="cert-1" />);
    expect(await screen.findByTestId('import-row')).toHaveTextContent('Outcome unknown');
  });

  it('shows nothing for a certificate that was never imported, or when there is no vault', async () => {
    setup([vaultFixture], {});
    const v = await renderWithAuth(<ImportHistory certificateId="cert-1" />);
    await new Promise((r) => setTimeout(r, 100));
    expect(screen.queryByTestId('import-history')).not.toBeInTheDocument();
    v.unmount();
    setup([], {});
    await renderWithAuth(<ImportHistory certificateId="cert-1" />);
    await new Promise((r) => setTimeout(r, 100));
    expect(screen.queryByTestId('import-history')).not.toBeInTheDocument();
  });

  it('shows the error of a failed read', async () => {
    server.use(...sessionHandlers(sessionFor('operator')), http.get('/api/v1/targets', () => HttpResponse.json({ items: [vaultFixture], next_cursor: null })), http.get('/api/v1/targets/:id/kv/imports', () => errorResponse(500, 'ALC-SYS-0003', 'internal.unexpected')));
    await renderWithAuth(<ImportHistory certificateId="cert-1" />);
    expect(await screen.findByRole('alert')).toBeInTheDocument();
  });

  it('shows hostile names as text', async () => {
    const evil = '<img src=x onerror=alert(1)>';
    setup([vaultWith({ name: evil })], { [VAULT_ID]: [kvImportFixture({ name: 'javascript:alert(1)' })] });
    await renderWithAuth(<ImportHistory certificateId="cert-1" />);
    const row = await screen.findByTestId('import-row');
    expect(row).toHaveTextContent(evil);
    expect(row.querySelector('img')).toBeNull();
    expect(row.querySelector('a[href^="javascript"]')).toBeNull();
    expect(row.closest('[class*="ScrollArea"], [class*="ScrollContainer"]')).not.toBeNull();
  });

  it('is complete in Turkish', async () => {
    setup([vaultFixture], { [VAULT_ID]: [kvImportFixture({ state: 'uncertain', version: '', error: null })] }, 'tr');
    await renderWithAuth(<ImportHistory certificateId="cert-1" />, ['tr-TR']);
    const row = await screen.findByTestId('import-row');
    expect(row).toHaveTextContent('Henüz doğrulanmadı');
    expect(screen.getByText("Key Vault'a içe aktarmalar", { selector: 'h2' })).toBeInTheDocument();
    expectNoRawKeys(screen.getByTestId('import-history'));
  });
});
