import { http, HttpResponse } from 'msw';
import { deploymentDetailFixture } from '../test/fixtures';
import { server } from '../test/server';
import { CANCELLED_REASON, deploymentView, isCancelled, wasSent, watchDeployments } from './deployments';

const ids = (n: number) => Array.from({ length: n }, (_, i) => `0192c000-0000-7000-8000-${String(i).padStart(12, '0')}`);

beforeEach(() => vi.useFakeTimers({ shouldAdvanceTime: true }));
afterEach(() => vi.useRealTimers());

// Requests made in one simulated minute by a batch that never settles.
async function requestsPerMinute(n: number): Promise<{ total: number; perId: Record<string, number> }> {
  const perId: Record<string, number> = {};
  server.use(
    http.get('/api/v1/deployments/:id', ({ params }) => {
      const id = String(params.id);
      perId[id] = (perId[id] ?? 0) + 1;
      return HttpResponse.json(deploymentDetailFixture({ id, status: 'running', state: 'deploying', job_status: 'running', finished_at: null }));
    }),
  );
  const ctrl = new AbortController();
  const done = watchDeployments(ids(n), { signal: ctrl.signal, timeoutMs: 10 * 60_000 }).catch(() => undefined);
  await vi.advanceTimersByTimeAsync(60_000);
  ctrl.abort();
  await vi.advanceTimersByTimeAsync(1_000);
  await done;
  return { total: Object.values(perId).reduce((a, b) => a + b, 0), perId };
}

describe('watchDeployments request budget', () => {
  it.each([1, 5, 20])('stays far below the 300 requests a minute of a session for %i deployments, and reads every deployment', async (n) => {
    const { total, perId } = await requestsPerMinute(n);
    expect(total).toBeLessThanOrEqual(125);
    expect(total).toBeGreaterThanOrEqual(55);
    // Round-robin: each deployment is read, about evenly.
    expect(Object.keys(perId)).toHaveLength(n);
    const counts = Object.values(perId);
    expect(Math.max(...counts) - Math.min(...counts)).toBeLessThanOrEqual(2);
  });

  it('waits at least Retry-After after a 429 before the next request', async () => {
    const times: number[] = [];
    let calls = 0;
    const start = Date.now();
    server.use(
      http.get('/api/v1/deployments/:id', ({ params }) => {
        times.push(Date.now() - start);
        calls += 1;
        if (calls === 1) {
          return HttpResponse.json(
            { error: { code: 'ALC-SYS-0005', reason: 'rate.limited', message_key: 'errors.rate.limited', message: 'x', request_id: 'r', retryable: true } },
            { status: 429, headers: { 'Retry-After': '7' } },
          );
        }
        return HttpResponse.json(deploymentDetailFixture({ id: String(params.id) }));
      }),
    );
    const done = watchDeployments(ids(1));
    await vi.advanceTimersByTimeAsync(20_000);
    const res = await done;
    expect(times).toHaveLength(2);
    expect(times[1] - times[0]).toBeGreaterThanOrEqual(7_000);
    expect(Object.values(res)[0].deployment?.status).toBe('succeeded');
  });

  it('reports each deployment when it settles and stops at the deadline for the others', async () => {
    const [a, b] = ids(2);
    server.use(
      http.get('/api/v1/deployments/:id', ({ params }) =>
        HttpResponse.json(params.id === a ? deploymentDetailFixture({ id: a }) : deploymentDetailFixture({ id: b, status: 'running', state: 'deploying', job_status: 'running', finished_at: null })),
      ),
    );
    const done: string[] = [];
    const res = watchDeployments([a, b], { timeoutMs: 5_000, onDone: (id) => done.push(id) });
    await vi.advanceTimersByTimeAsync(8_000);
    const out = await res;
    expect(done).toEqual([a, b]);
    expect(out[a].timedOut).toBe(false);
    expect(out[b].timedOut).toBe(true);
  });
});

describe('watchDeployments with one unreadable deployment', () => {
  it('marks that deployment with its error and keeps following the others', async () => {
    const [a, b] = ids(2);
    server.use(
      http.get('/api/v1/deployments/:id', ({ params }) =>
        params.id === a
          ? HttpResponse.json({ error: { code: 'ALC-SYS-0001', reason: 'system.not_found', message_key: 'errors.system.not_found', message: 'x', request_id: 'r', retryable: false } }, { status: 404 })
          : HttpResponse.json(deploymentDetailFixture({ id: b })),
      ),
    );
    const res = watchDeployments([a, b]);
    await vi.advanceTimersByTimeAsync(5_000);
    const out = await res;
    expect(out[a].error).toBeDefined();
    expect(out[b].error).toBeUndefined();
    expect(out[b].deployment?.status).toBe('succeeded');
  });
});

describe('deploymentView', () => {
  it('tells a job that succeeded while the record still runs from a running one', () => {
    expect(deploymentView({ status: 'running', state: 'deploying', job_status: 'succeeded' })).toBe('finishing');
    expect(deploymentView({ status: 'running', state: 'deploying', job_status: 'running' })).toBe('working');
    expect(deploymentView({ status: 'running', state: 'deploying', job_status: 'dead' })).toBe('stopped');
    expect(deploymentView({ status: 'needs_attention', state: 'recovering', job_status: 'succeeded' })).toBe('recovering');
    expect(deploymentView({ status: '', state: '', job_status: '' })).toBe('unknown');
  });

  // The API reports the status of a deployment's ORIGINAL job: it can be blocked_license while the
  // deployment, already sent, is followed by a recovery job of its own (final review C-I1). Such a
  // deployment is never "on hold for the license"; held is only for one that has not been sent.
  it.each([
    // status, state, job_status, view
    ['pending', 'queued', 'blocked_license', 'held'],
    ['running', 'precheck', 'blocked_license', 'held'],
    ['running', 'recovering', 'blocked_license', 'recovering'],
    ['needs_attention', 'recovering', 'blocked_license', 'recovering'],
    ['needs_attention', 'deploying', 'blocked_license', 'recovering'],
    ['running', 'deploying', 'blocked_license', 'working'],
    ['pending', 'queued', 'queued', 'working'],
    ['running', 'recovering', 'running', 'recovering'],
    ['rolled_back', 'done', 'blocked_license', 'final'],
    ['failed', 'done', 'cancelled', 'final'],
  ] as const)('status %s in state %s with job %s is %s', (status, state, job_status, view) => {
    expect(deploymentView({ status, state, job_status })).toBe(view);
  });

  it('tells a deployment an administrator cancelled from a failed one, and a sent one from one that was not', () => {
    const cancelled = { status: 'failed' as const, error: { code: 'ALC-DEP-0022', reason: CANCELLED_REASON } };
    expect(isCancelled(cancelled)).toBe(true);
    expect(isCancelled({ status: 'failed', error: { code: 'ALC-DEP-0010', reason: 'deployment.interrupted' } })).toBe(false);
    expect(isCancelled({ status: 'rolled_back', error: { code: 'ALC-DEP-0022', reason: CANCELLED_REASON } })).toBe(false);
    expect(isCancelled({ status: 'failed', error: null })).toBe(false);
    expect(['queued', 'precheck', ''].map((state) => wasSent({ state: state as never }))).toEqual([false, false, false]);
    expect(['deploying', 'recovering', 'done'].map((state) => wasSent({ state: state as never }))).toEqual([true, true, true]);
  });
});
