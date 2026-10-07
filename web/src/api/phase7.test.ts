import { http, HttpResponse } from 'msw';
import { server } from '../test/server';
import { createView, deleteView, exportUrl, getAlerts, getDashboardSummary, getExpiring, getNotificationStatus, listViews } from './phase7';

describe('phase7 calls', () => {
  it('hit the C13 paths', async () => {
    const seen: string[] = [];
    let body: unknown;
    server.use(
      http.get('/api/v1/dashboard/summary', ({ request }) => (seen.push(new URL(request.url).pathname), HttpResponse.json({ attention: 0 }))),
      http.get('/api/v1/dashboard/expiring', ({ request }) => (seen.push(new URL(request.url).pathname + new URL(request.url).search), HttpResponse.json({ items: [] }))),
      http.get('/api/v1/alerts', ({ request }) => (seen.push(new URL(request.url).pathname), HttpResponse.json({ items: [] }))),
      http.get('/api/v1/notifications/status', ({ request }) => (seen.push(new URL(request.url).pathname), HttpResponse.json({ failing: false }))),
      http.get('/api/v1/views', ({ request }) => (seen.push(new URL(request.url).pathname + new URL(request.url).search), HttpResponse.json({ items: [] }))),
      http.post('/api/v1/views', async ({ request }) => {
        body = await request.json();
        return HttpResponse.json({ id: 'v' }, { status: 201 });
      }),
      http.delete('/api/v1/views/:id', ({ request }) => (seen.push('DELETE ' + new URL(request.url).pathname), new HttpResponse(null, { status: 204 }))),
    );
    await getDashboardSummary();
    await getExpiring();
    await getExpiring(7, 3);
    await getAlerts();
    await getNotificationStatus();
    await listViews('ssh_keys');
    await createView({ page: 'certificates', name: 'n', query: { expiry: '7' } });
    await deleteView('a/b');
    expect(seen).toEqual([
      '/api/v1/dashboard/summary',
      '/api/v1/dashboard/expiring?days=30&limit=10',
      '/api/v1/dashboard/expiring?days=7&limit=3',
      '/api/v1/alerts',
      '/api/v1/notifications/status',
      '/api/v1/views?page=ssh_keys',
      'DELETE /api/v1/views/a%2Fb',
    ]);
    expect(body).toEqual({ page: 'certificates', name: 'n', query: { expiry: '7' } });
  });

  it('exportUrl builds the query without empty values', () => {
    expect(exportUrl('certificates', { target_id: 't', q: '', expiry: '30' })).toBe('/api/v1/certificates/export?target_id=t&expiry=30');
    expect(exportUrl('ssh-keys', {})).toBe('/api/v1/ssh-keys/export');
    expect(exportUrl('ssh-keys', { q: 'a b&c' })).toBe('/api/v1/ssh-keys/export?q=a+b%26c');
  });
});
