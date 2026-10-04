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
    expect(within(rows[1]).getByRole('link', { name: /Open deployment: api\.example\.test/ })).toHaveAttribute('href', '/deployments/d-2');
    expect(within(rows[1]).getByText('Open')).toBeInTheDocument();
    expectNoRawKeys();
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
    expect(screen.queryByRole('button', { name: 'Show more' })).not.toBeInTheDocument();
  });

  it('says when there are none and shows a server refusal', async () => {
    server.use(...sessionHandlers(sessionFor('operator')), http.get('/api/v1/deployments', () => HttpResponse.json({ items: [], next_cursor: null })));
    const view = await renderRoute('/deployments');
    expect(await screen.findByText('No deployments yet.')).toBeInTheDocument();
    view.unmount();
    server.use(http.get('/api/v1/deployments', () => errorResponse(403, 'ALC-AUTH-0002', 'auth.forbidden')));
    await renderRoute('/deployments');
    expect(await screen.findByRole('alert')).toHaveTextContent('You do not have permission to do this.');
  });

  it('is in the navigation for every role', async () => {
    server.use(...sessionHandlers(sessionFor('auditor')), http.get('/api/v1/deployments', () => HttpResponse.json({ items: [], next_cursor: null })));
    await renderRoute('/');
    expect(await screen.findByRole('link', { name: 'Deployment history' })).toHaveAttribute('href', '/deployments');
  });

  it('is shown in Turkish', async () => {
    server.use(...sessionHandlers(sessionFor('operator', 'tr')), http.get('/api/v1/deployments', () => HttpResponse.json({ items: [first], next_cursor: null })));
    await renderRoute('/deployments', { languages: ['tr-TR'] });
    expect(await screen.findByRole('heading', { name: 'Dağıtım geçmişi' })).toBeInTheDocument();
    expect(await screen.findByText('Başarılı')).toBeInTheDocument();
    expectNoRawKeys();
  });
});
