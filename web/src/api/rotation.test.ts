import { http, HttpResponse } from 'msw';
import { server } from '../test/server';
import { ApiError, setCsrfToken } from './client';
import {
  abortRun,
  continueRun,
  createPolicy,
  deletePolicy,
  disablePolicy,
  enablePolicy,
  finishRunNow,
  getPolicy,
  getRun,
  keepOldKey,
  listRuns,
  previewPolicy,
  runPolicy,
  runPollInterval,
  updatePolicy,
} from './rotation';

interface Seen {
  method: string;
  path: string;
  search: string;
  ifMatch: string | null;
  body: unknown;
}

function record() {
  const seen: Seen[] = [];
  server.use(
    http.all('/api/v1/rotation/*', async ({ request }) => {
      const url = new URL(request.url);
      const text = await request.text();
      seen.push({ method: request.method, path: url.pathname, search: url.search, ifMatch: request.headers.get('If-Match'), body: text === '' ? null : JSON.parse(text) });
      return request.method === 'DELETE' || request.url.includes('/actions/') && !/preview|run$/.test(url.pathname) ? new HttpResponse(null, { status: 204 }) : HttpResponse.json({});
    }),
  );
  return seen;
}

describe('rotation api', () => {
  beforeEach(() => setCsrfToken('tok'));

  it('reads and writes policies with the version as a strong If-Match', async () => {
    const seen = record();
    await getPolicy('p 1');
    await createPolicy({ ssh_key_id: 'k1', name: 'n', interval_days: 90, overlap_days: 7, notify_before_hours: 24, new_key_type: 'same' });
    await updatePolicy('p1', 3, { interval_days: 30 });
    await deletePolicy('p1', 4);
    await enablePolicy('p1', 5);
    await disablePolicy('p1', 6);
    expect(seen).toEqual([
      { method: 'GET', path: '/api/v1/rotation/policies/p%201', search: '', ifMatch: null, body: null },
      { method: 'POST', path: '/api/v1/rotation/policies', search: '', ifMatch: null, body: { ssh_key_id: 'k1', name: 'n', interval_days: 90, overlap_days: 7, notify_before_hours: 24, new_key_type: 'same' } },
      { method: 'PATCH', path: '/api/v1/rotation/policies/p1', search: '', ifMatch: '"3"', body: { interval_days: 30 } },
      { method: 'DELETE', path: '/api/v1/rotation/policies/p1', search: '', ifMatch: '"4"', body: null },
      { method: 'POST', path: '/api/v1/rotation/policies/p1/actions/enable', search: '', ifMatch: '"5"', body: null },
      { method: 'POST', path: '/api/v1/rotation/policies/p1/actions/disable', search: '', ifMatch: '"6"', body: null },
    ]);
  });

  it('previews, runs with the digest, and lists and reads runs', async () => {
    const seen = record();
    await previewPolicy('p1');
    await runPolicy('p1', 'a'.repeat(64));
    await listRuns({ ssh_key_id: 'k1', policy_id: 'p1', cursor: 'c', limit: 5 });
    await listRuns({});
    await getRun('r1');
    expect(seen.map((s) => [s.method, s.path + s.search, s.body])).toEqual([
      ['POST', '/api/v1/rotation/policies/p1/actions/preview', null],
      ['POST', '/api/v1/rotation/policies/p1/actions/run', { plan_digest: 'a'.repeat(64) }],
      ['GET', '/api/v1/rotation/runs?policy_id=p1&ssh_key_id=k1&cursor=c&limit=5', null],
      ['GET', '/api/v1/rotation/runs', null],
      ['GET', '/api/v1/rotation/runs/r1', null],
    ]);
  });

  it('sends the decisions to their own paths', async () => {
    const seen = record();
    await continueRun('r1');
    await finishRunNow('r1');
    await keepOldKey('r1', ['l1', 'l2']);
    await abortRun('r1');
    expect(seen.map((s) => [s.method, s.path, s.body])).toEqual([
      ['POST', '/api/v1/rotation/runs/r1/actions/continue', null],
      ['POST', '/api/v1/rotation/runs/r1/actions/finish-now', null],
      ['POST', '/api/v1/rotation/runs/r1/actions/keep-old', { location_ids: ['l1', 'l2'] }],
      ['POST', '/api/v1/rotation/runs/r1/actions/abort', null],
    ]);
  });
});

describe('runPollInterval', () => {
  const run = (status: string) => ({ status }) as never;
  it('stops for a final run and polls every three seconds for a moving one', () => {
    for (const s of ['completed', 'aborted', 'needs_attention', 'cancelled']) expect(runPollInterval(run(s), null)).toBe(false);
    for (const s of ['dry_run_notified', 'adding_new', 'verifying_new', 'overlap', 'removing_old', 'rolling_back']) expect(runPollInterval(run(s), null)).toBe(3000);
    expect(runPollInterval(undefined, null)).toBe(3000);
  });
  it('waits as long as Retry-After asks, never less than three seconds', () => {
    const busy = (secs: number) => new ApiError(503, null, secs);
    expect(runPollInterval(run('overlap'), busy(30))).toBe(30000);
    expect(runPollInterval(run('overlap'), busy(1))).toBe(3000);
    expect(runPollInterval(run('overlap'), new ApiError(500, null))).toBe(3000);
  });
});
