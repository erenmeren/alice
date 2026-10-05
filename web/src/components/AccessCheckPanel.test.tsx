import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { accessFixture, accessRow, errorResponse, jobFixture, kvCertificateFixture, sessionFor, sessionHandlers, VAULT_ID } from '../test/fixtures';
import { expectNoRawKeys } from '../test/i18nAssert';
import { renderWithAuth } from '../test/render';
import { server } from '../test/server';
import { accessRows, AccessCheckPanel } from './AccessCheckPanel';

function asRole(role: 'admin' | 'operator' | 'auditor', lang = 'en') {
  server.use(...sessionHandlers(sessionFor(role, lang)));
}

const forbidden = accessFixture({
  checks: [
    accessRow('sign_in', 'ok'),
    accessRow('list_certificates', 'forbidden', 'Key Vault Reader', { code: 'ALC-AKV-0003', reason: 'azure.forbidden', params: { role: 'Key Vault Reader' } }),
    accessRow('list_keys', 'ok'),
    accessRow('list_secrets', 'ok'),
    accessRow('read_secret', 'forbidden', 'Key Vault Secrets User'),
    accessRow('import', 'not_checked'),
  ],
});

describe('AccessCheckPanel', () => {
  it('renders ok as Allowed, forbidden as the missing role in <code>, not_checked as Not checked, and import as checked at import', async () => {
    asRole('operator');
    await renderWithAuth(
      <AccessCheckPanel
        vaultId={VAULT_ID}
        canOperate
        access={accessFixture({ checks: [accessRow('list_certificates', 'ok'), accessRow('list_keys', 'ok'), accessRow('list_secrets', 'ok'), accessRow('read_secret', 'forbidden', 'Key Vault Secrets User'), accessRow('import', 'not_checked')] })}
      />,
    );
    const monitor = screen.getByRole('row', { name: /Monitor certificates/ });
    expect(monitor).toHaveTextContent('Allowed');
    const deploy = screen.getByRole('row', { name: /Deploy certificates to Nginx/ });
    expect(deploy).toHaveTextContent('Not allowed: needs Key Vault Secrets User');
    expect(within(deploy).getByText('Key Vault Secrets User').tagName).toBe('CODE');
    expect(screen.getByRole('row', { name: /Import certificates into the vault/ })).toHaveTextContent('Checked when you import');
  });

  it('shows Not checked for a question nobody asked yet, and Check failed with its reason', async () => {
    asRole('auditor');
    await renderWithAuth(
      <AccessCheckPanel vaultId={VAULT_ID} canOperate={false} access={accessFixture({ checks: [accessRow('list_certificates', 'failed', '', { code: 'ALC-AKV-0006', reason: 'azure.unreachable' })] })} />,
    );
    expect(screen.getByRole('row', { name: /Monitor certificates/ })).toHaveTextContent('Check failed');
    expect(screen.getByRole('row', { name: /Monitor certificates/ })).toHaveTextContent('Cannot reach Azure');
    expect(screen.getByRole('row', { name: /Deploy certificates to Nginx/ })).toHaveTextContent('Not checked');
  });

  it('says so when no check ran yet', async () => {
    asRole('admin');
    await renderWithAuth(<AccessCheckPanel vaultId={VAULT_ID} canOperate access={null} />);
    expect(screen.getByText("Alice has not checked this vault's access yet.")).toBeInTheDocument();
    expect(screen.getByRole('row', { name: /Monitor certificates/ })).toHaveTextContent('Not checked');
  });

  it('folds the three listings: the worst answer counts, and a missing answer keeps "Not checked"', () => {
    expect(accessRows(forbidden).map((r) => [r.id, r.result, r.role])).toEqual([
      ['monitor', 'forbidden', 'Key Vault Reader'],
      ['deploy', 'forbidden', 'Key Vault Secrets User'],
      ['import', 'not_checked', ''],
    ]);
    expect(accessRows(accessFixture({ checks: [accessRow('list_certificates', 'ok')] }))[0].result).toBe('ok');
    expect(accessRows(accessFixture({ checks: [accessRow('list_certificates', 'ok'), accessRow('list_keys', 'not_checked')] }))[0].result).toBe('not_checked');
    expect(accessRows(null).map((r) => r.result)).toEqual(['not_checked', 'not_checked', 'not_checked']);
  });

  it('Check again posts actions/test without a body and waits for the job (Administrator and Operator)', async () => {
    for (const role of ['admin', 'operator'] as const) {
      asRole(role);
      let body: string | null = null;
      server.use(
        http.post(`/api/v1/targets/${VAULT_ID}/actions/test`, async ({ request }) => {
          body = await request.text();
          return HttpResponse.json({ job_id: 'j1', status_url: '/api/v1/jobs/j1' }, { status: 202 });
        }),
        http.get('/api/v1/jobs/j1', () => HttpResponse.json(jobFixture({ id: 'j1', type: 'kv.test_connection', target_id: VAULT_ID }))),
      );
      const view = await renderWithAuth(<AccessCheckPanel vaultId={VAULT_ID} canOperate access={accessFixture()} />);
      await userEvent.click(screen.getByRole('button', { name: 'Check again' }));
      expect(await screen.findByText('Finished.')).toBeInTheDocument();
      expect(body).toBe('');
      view.unmount();
    }
  });

  it('"Also test deployment access" needs a certificate and posts read_secret_of', async () => {
    asRole('admin');
    let body: unknown = null;
    server.use(
      http.get(`/api/v1/targets/${VAULT_ID}/kv/certificates`, () =>
        HttpResponse.json({
          items: [
            kvCertificateFixture({ id: 'c-ok', name: 'web-cert' }),
            kvCertificateFixture({ id: 'c-monitor', name: 'monitor-only', exportable: false }),
            kvCertificateFixture({ id: 'c-gone', name: 'old-cert', missing_since: '2026-10-01T00:00:00Z' }),
          ],
          next_cursor: null,
        }),
      ),
      http.post(`/api/v1/targets/${VAULT_ID}/actions/test`, async ({ request }) => {
        body = await request.json();
        return HttpResponse.json({ job_id: 'j2', status_url: '/api/v1/jobs/j2' }, { status: 202 });
      }),
      http.get('/api/v1/jobs/j2', () => HttpResponse.json(jobFixture({ id: 'j2' }))),
    );
    await renderWithAuth(<AccessCheckPanel vaultId={VAULT_ID} canOperate access={accessFixture()} />);
    await userEvent.click(screen.getByLabelText('Also test deployment access'));
    const select = await screen.findByLabelText('Certificate whose secret Alice reads once');
    expect(within(select).getAllByRole('option').map((o) => o.textContent)).toEqual(['Choose a certificate', 'web-cert']);
    expect(screen.getByRole('button', { name: 'Check again' })).toBeDisabled();
    await userEvent.selectOptions(select, 'c-ok');
    await userEvent.click(screen.getByRole('button', { name: 'Check again' }));
    await screen.findByText('Finished.');
    expect(body).toEqual({ read_secret_of: 'c-ok' });
  });

  it('offers no buttons to an Auditor', async () => {
    asRole('auditor');
    await renderWithAuth(<AccessCheckPanel vaultId={VAULT_ID} canOperate={false} access={accessFixture()} />);
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
    expect(screen.queryByLabelText('Also test deployment access')).not.toBeInTheDocument();
  });

  it('shows the error of a refused check and of a failed job, never a raw reason', async () => {
    asRole('admin');
    server.use(http.post(`/api/v1/targets/${VAULT_ID}/actions/test`, () => errorResponse(409, 'ALC-AKV-0013', 'kv.not_exportable')));
    await renderWithAuth(<AccessCheckPanel vaultId={VAULT_ID} canOperate access={accessFixture()} />);
    await userEvent.click(screen.getByRole('button', { name: 'Check again' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Private key not exportable');
    server.use(
      http.post(`/api/v1/targets/${VAULT_ID}/actions/test`, () => HttpResponse.json({ job_id: 'j3', status_url: '' }, { status: 202 })),
      http.get('/api/v1/jobs/j3', () => HttpResponse.json(jobFixture({ id: 'j3', status: 'failed', error: { code: 'ALC-AKV-0006', reason: 'azure.unreachable' } }))),
    );
    await userEvent.click(screen.getByRole('button', { name: 'Check again' }));
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('Cannot reach Azure'));
    // The catalogue text names login.microsoftonline.com, which the raw-key scan cannot tell from a key: assert the reason is not shown instead.
    expect(document.body.textContent).not.toMatch(/azure\.unreachable|errors\.azure/);
  });

  it('is complete in Turkish', async () => {
    asRole('admin', 'tr');
    await renderWithAuth(<AccessCheckPanel vaultId={VAULT_ID} canOperate access={forbidden} />, ['tr-TR']);
    expect(await screen.findByText('Erişim denetimi')).toBeInTheDocument();
    expect(screen.getByRole('row', { name: /Sertifikaları, anahtarları/ })).toHaveTextContent('İzin yok: Key Vault Reader gerekiyor');
    expect(screen.getByRole('row', { name: /Aktarma|Sertifikaları kasaya aktarma/ })).toHaveTextContent('Aktarma sırasında denetlenir');
    expect(screen.getByRole('button', { name: 'Yeniden denetle' })).toBeInTheDocument();
    expectNoRawKeys();
  });
});
