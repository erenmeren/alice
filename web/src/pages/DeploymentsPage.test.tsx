import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { deploymentFixture, errorResponse, sessionFor, sessionHandlers } from '../test/fixtures';
import { expectNoRawKeys } from '../test/i18nAssert';
import { renderRoute } from '../test/render';
import { server } from '../test/server';

const first = deploymentFixture({ id: 'd-1', created_at: '2026-10-02T10:00:00Z', certificate_name: 'www.example.test' });
const second = deploymentFixture({ id: 'd-2', created_at: '2026-10-02T09:00:00Z', certificate_name: 'api.example.test', status: 'rolled_back', cert_path: '/etc/nginx/ssl/api.crt', target_name: 'web-02' });

describe('DeploymentsPage', () => {
  it('lists deployments with the time, server, file, certificate and the status in words', async () => {
    server.use(...sessionHandlers(sessionFor('auditor')), http.get('/api/v1/deployments', () => HttpResponse.json({ items: [first, second], next_cursor: null })));
    await renderRoute('/deployments');
    const table = await screen.findByRole('table', { name: 'Deployments' });
    const rows = within(table).getAllByTestId('deployment-row');
    expect(rows).toHaveLength(2);
    expect(rows[0]).toHaveTextContent('Oct 2, 2026');
    expect(within(rows[0]).getByRole('link', { name: 'web-01' })).toHaveAttribute('href', `/servers/${first.target_id}`);
    expect(within(rows[0]).getByText('/etc/nginx/ssl/www.crt')).toBeInTheDocument();
    expect(within(rows[0]).getByRole('link', { name: 'www.example.test' })).toHaveAttribute('href', `/certificates/${first.certificate_id}`);
    expect(within(rows[0]).getByText('Succeeded')).toBeInTheDocument();
    expect(within(rows[1]).getByText('Failed, restored')).toBeInTheDocument();
    expect(within(rows[1]).getByRole('link', { name: /^Open deployment: api\.example\.test, / })).toHaveAttribute('href', '/deployments/d-2');
    expectNoRawKeys();
  });

  it('has the design header and table: tile, certificate with its id, server with the file, who triggered it, the outcome, the time and an open link', async () => {
    server.use(...sessionHandlers(sessionFor('auditor')), http.get('/api/v1/deployments', () => HttpResponse.json({ items: [first, deploymentFixture({ id: 'd-3', requested_by: null, requested_by_name: '' })], next_cursor: null })));
    await renderRoute('/deployments');
    expect(await screen.findByRole('heading', { level: 1, name: 'Deployments' })).toBeInTheDocument();
    expect(screen.getByText('Every change has a sequence. Every outcome has evidence.')).toBeInTheDocument();
    const table = await screen.findByRole('table', { name: 'Deployments' });
    expect(within(table).getAllByRole('columnheader').map((th) => th.textContent)).toEqual(['Certificate', 'Server', 'Triggered by', 'Result', 'When', 'Open']);
    const [row, auto] = within(table).getAllByTestId('deployment-row');
    expect(row.querySelector('td:first-child svg')).not.toBeNull();
    expect(within(row).getByText('d-1')).toHaveAttribute('translate', 'no');
    expect(within(row).getByText('Olcay Öztürk')).toBeInTheDocument();
    expect(within(auto).getByText('Alice (automatic)')).toBeInTheDocument();
    // The outcome is the status badge of the design.
    expect(within(row).getByText('Succeeded').closest('.mantine-Badge-root')).toHaveAttribute('data-status', 'succeeded');
    // Exactly one link opens the deployment by name; the others are the certificate and the server.
    expect(within(row).getAllByRole('link').map((a) => a.getAttribute('href'))).toEqual([`/certificates/${first.certificate_id}`, `/servers/${first.target_id}`, '/deployments/d-1']);
    expect(screen.getByText('2 shown')).toBeInTheDocument();
  });

  it('shows no outcome totals: the history is paged, so no count of verified or rolled back deployments (R20)', async () => {
    server.use(...sessionHandlers(sessionFor('auditor')), http.get('/api/v1/deployments', () => HttpResponse.json({ items: [first, second], next_cursor: 'c2' })));
    await renderRoute('/deployments');
    const table = await screen.findByRole('table', { name: 'Deployments' });
    const main = screen.getByRole('main');
    const outside = (main.textContent ?? '').replace(table.textContent ?? '', '');
    expect(outside).not.toMatch(/\d+\s*(verified|rolled back|recovering|unchanged|succeeded|failed)/i);
    expect(within(main).queryByRole('list', { name: /summary/i })).not.toBeInTheDocument();
  });

  it('shows state and hold for deployments that are being recovered or held, and Unknown for an unknown status', async () => {
    server.use(
      ...sessionHandlers(sessionFor('operator')),
      http.get('/api/v1/deployments', () =>
        HttpResponse.json({
          items: [
            deploymentFixture({ id: 'r', status: 'needs_attention', state: 'recovering' }),
            deploymentFixture({ id: 'h', status: 'pending', state: 'queued', job_status: 'blocked_license' }),
            deploymentFixture({ id: 'u', status: '', state: '' }),
            // Sent, being recovered, its original job held by the license (C-I1): recovering, never held.
            deploymentFixture({ id: 's', status: 'running', state: 'recovering', job_status: 'blocked_license', finished_at: null }),
            deploymentFixture({ id: 'c', status: 'failed', error: { code: 'ALC-DEP-0022', reason: 'deployment.cancelled' } }),
          ],
          next_cursor: null,
        }),
      ),
    );
    await renderRoute('/deployments');
    const rows = await screen.findAllByTestId('deployment-row');
    expect(within(rows[0]).getByText('Needs attention')).toBeInTheDocument();
    expect(within(rows[0]).getByText('Confirming the outcome')).toBeInTheDocument();
    expect(within(rows[1]).getByText('On hold for the license')).toBeInTheDocument();
    expect(within(rows[2]).getByText('Unknown')).toBeInTheDocument();
    expect(within(rows[3]).getByText('Confirming the outcome')).toBeInTheDocument();
    expect(within(rows[3]).queryByText('On hold for the license')).not.toBeInTheDocument();
    expect(within(rows[4]).getByText('Cancelled')).toBeInTheDocument();
    expect(within(rows[4]).queryByText('Failed, nothing changed')).not.toBeInTheDocument();
  });

  it('tells a verified success from one whose verification was skipped or not done: never a plain green Succeeded', async () => {
    server.use(
      ...sessionHandlers(sessionFor('operator')),
      http.get('/api/v1/deployments', () =>
        HttpResponse.json({
          items: [
            deploymentFixture({ id: 'v-remote', verified: 'remote' }),
            deploymentFixture({ id: 'v-local', verified: 'local' }),
            deploymentFixture({ id: 'v-skipped', verified: 'skipped' }),
            deploymentFixture({ id: 'v-none', verified: '' }),
            deploymentFixture({ id: 'v-failed', status: 'failed', verified: '' }),
          ],
          next_cursor: null,
        }),
      ),
    );
    await renderRoute('/deployments');
    const rows = await screen.findAllByTestId('deployment-row');
    const badge = (row: HTMLElement) => within(row).getByText(/Succeeded|Failed/).closest('.mantine-Badge-root');
    // Verified from Alice or from the server: the success badge and no qualifier.
    for (const row of rows.slice(0, 2)) {
      expect(badge(row)).toHaveAttribute('data-tone', 'success');
      expect(row).not.toHaveTextContent('Verification:');
    }
    // Deployed but not verified: the status word stays (filters and specs read it), the tone is a warning and the line says why.
    expect(badge(rows[2])).toHaveAttribute('data-tone', 'warning');
    expect(badge(rows[2])).toHaveAttribute('data-status', 'succeeded');
    expect(rows[2]).toHaveTextContent('Verification: Skipped');
    expect(badge(rows[3])).toHaveAttribute('data-tone', 'warning');
    expect(rows[3]).toHaveTextContent('Verification: Not done');
    // A deployment that did not succeed keeps its own tone and has no verification line.
    expect(badge(rows[4])).toHaveAttribute('data-tone', 'danger');
    expect(rows[4]).not.toHaveTextContent('Verification:');
    expectNoRawKeys();
  });

  it('pages with Show more using next_cursor', async () => {
    const queries: string[] = [];
    server.use(
      ...sessionHandlers(sessionFor('operator')),
      http.get('/api/v1/deployments', ({ request }) => {
        const q = new URL(request.url).search;
        queries.push(q);
        return q.includes('cursor=c2') ? HttpResponse.json({ items: [second], next_cursor: null }) : HttpResponse.json({ items: [first], next_cursor: 'c2' });
      }),
    );
    await renderRoute('/deployments');
    await screen.findAllByTestId('deployment-row');
    await userEvent.click(screen.getByRole('button', { name: 'Show more' }));
    await waitFor(() => expect(screen.getAllByTestId('deployment-row')).toHaveLength(2));
    expect(queries[1]).toContain('cursor=c2');
    expect(screen.getByText('2 shown')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Show more' })).not.toBeInTheDocument();
  });

  it('says when there are none and shows a server refusal', async () => {
    server.use(...sessionHandlers(sessionFor('operator')), http.get('/api/v1/deployments', () => HttpResponse.json({ items: [], next_cursor: null })));
    const view = await renderRoute('/deployments');
    expect(await screen.findByText('No deployments yet.')).toBeInTheDocument();
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
    view.unmount();
    server.use(http.get('/api/v1/deployments', () => errorResponse(403, 'ALC-AUTH-0002', 'auth.forbidden')));
    await renderRoute('/deployments');
    expect(await screen.findByRole('alert')).toHaveTextContent('You do not have permission to do this.');
  });

  it('is in the navigation for every role', async () => {
    server.use(...sessionHandlers(sessionFor('auditor')), http.get('/api/v1/deployments', () => HttpResponse.json({ items: [], next_cursor: null })));
    await renderRoute('/');
    expect(await screen.findByRole('link', { name: 'Deployments' })).toHaveAttribute('href', '/deployments');
  });

  it('is shown in Turkish', async () => {
    server.use(...sessionHandlers(sessionFor('operator', 'tr')), http.get('/api/v1/deployments', () => HttpResponse.json({ items: [first], next_cursor: null })));
    await renderRoute('/deployments', { languages: ['tr-TR'] });
    expect(await screen.findByRole('heading', { name: 'Dağıtımlar' })).toBeInTheDocument();
    expect(await screen.findByText('Başarılı')).toBeInTheDocument();
    expectNoRawKeys();
  });
});

describe('DeploymentsPage from Key Vault', () => {
  it('shows "From Key Vault", the vault name and the version for a vault deployment, and nothing for an upload', async () => {
    server.use(
      ...sessionHandlers(sessionFor('auditor')),
      http.get('/api/v1/deployments', () =>
        HttpResponse.json({
          items: [
            deploymentFixture({ id: 'dv', source: 'key_vault', binding_id: 'b1', vault_name: 'Prod vault', kv_version: '0123456789abcdef0123456789abcdef' }),
            deploymentFixture({ id: 'du', certificate_name: 'upload.example.test' }),
          ],
          next_cursor: null,
        }),
      ),
    );
    await renderRoute('/deployments');
    const sources = await screen.findAllByTestId('deployment-source');
    expect(sources).toHaveLength(1);
    expect(sources[0]).toHaveTextContent('From Key Vault: Prod vault 01234567');
    expect(within(sources[0]).getByText('01234567').tagName).toBe('CODE');
  });
});
