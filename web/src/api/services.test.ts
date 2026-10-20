import { http, HttpResponse } from 'msw';
import { server } from '../test/server';
import * as s from './services';
import { listCertificates, listSSHKeys } from './endpoints';

describe('the services client', () => {
  function capture() {
    const seen: { method: string; path: string; ifMatch: string | null; body: unknown }[] = [];
    server.use(
      http.all('/api/v1/*', async ({ request }) => {
        const u = new URL(request.url);
        const text = request.method === 'GET' || request.method === 'DELETE' ? '' : await request.text();
        seen.push({ method: request.method, path: u.pathname + u.search, ifMatch: request.headers.get('If-Match'), body: text ? JSON.parse(text) : undefined });
        if (request.method === 'DELETE') return new HttpResponse(null, { status: 204 });
        return HttpResponse.json({ items: [], next_cursor: null });
      }),
    );
    return seen;
  }

  it('reads and writes services, environments and trusts at their addresses', async () => {
    const seen = capture();
    await s.listEnvironments();
    await s.createEnvironment({ key: 'qa', name: 'QA', sort: 25 });
    await s.updateEnvironment('e/1', 2, { name: 'Quality' });
    await s.deleteEnvironment('e1', 3);
    await s.listServices();
    await s.getService('s/1');
    await s.createService({ name: 'Payments', environment_id: 'e1' });
    await s.updateService('s1', 4, { environment_id: null });
    await s.deleteService('s1', 5);
    await s.getServicePolicy('s1');
    await s.assignToService('s1', [{ type: 'target', id: 't1' }], true);
    await s.assignToService('s1', [{ type: 'certificate', id: 'c1' }], false);
    await s.listTrusts('s1');
    await s.createTrust('a', 'b');
    await s.deleteTrust('t1');
    expect(seen.map((x) => `${x.method} ${x.path} ${x.ifMatch ?? ''}`.trim())).toEqual([
      'GET /api/v1/environments',
      'POST /api/v1/environments',
      'PATCH /api/v1/environments/e%2F1 "2"',
      'DELETE /api/v1/environments/e1 "3"',
      'GET /api/v1/services',
      'GET /api/v1/services/s%2F1',
      'POST /api/v1/services',
      'PATCH /api/v1/services/s1 "4"',
      'DELETE /api/v1/services/s1 "5"',
      'GET /api/v1/services/s1/policy',
      'POST /api/v1/services/s1/actions/assign?dry_run=true',
      'POST /api/v1/services/s1/actions/assign',
      'GET /api/v1/service-trusts?service_id=s1',
      'POST /api/v1/service-trusts',
      'DELETE /api/v1/service-trusts/t1',
    ]);
    expect(seen[7].body).toEqual({ environment_id: null });
    expect(seen[10].body).toEqual({ resources: [{ type: 'target', id: 't1' }] });
    expect(seen[13].body).toEqual({ source_service_id: 'a', target_service_id: 'b' });
  });

  it('sends the list filters of the certificate and SSH key lists', async () => {
    const seen = capture();
    await listCertificates({ service_id: 's1', environment_id: 'e1' });
    await listSSHKeys({ environment_id: 'e1' });
    expect(seen.map((x) => x.path)).toEqual(['/api/v1/certificates?service_id=s1&environment_id=e1', '/api/v1/ssh-keys?environment_id=e1']);
  });

  it('filters rows read completely in the browser', () => {
    const pay = { id: 's2', name: 'Payments', environment: { id: 'e1', key: 'production', name: 'Production' } };
    expect(s.inServiceFilter(pay, {})).toBe(true);
    expect(s.inServiceFilter(pay, { service_id: 's2' })).toBe(true);
    expect(s.inServiceFilter(pay, { service_id: 's1' })).toBe(false);
    expect(s.inServiceFilter(pay, { environment_id: 'e1' })).toBe(true);
    expect(s.inServiceFilter({ ...pay, environment: null }, { environment_id: 'e1' })).toBe(false);
    expect(s.inServiceFilter(undefined, { service_id: 's2' })).toBe(false);
  });
});
