import { http, HttpResponse } from 'msw';
import { jobFixture } from '../test/fixtures';
import { server } from '../test/server';
import { isTerminal, JobTimeoutError, waitForJob } from './jobs';

describe('waitForJob', () => {
  it('polls until the job has finished', async () => {
    let calls = 0;
    server.use(
      http.get('/api/v1/jobs/:id', ({ params }) => {
        calls += 1;
        const status = calls < 3 ? 'running' : 'succeeded';
        return HttpResponse.json(jobFixture({ id: String(params.id), status }));
      }),
    );
    const job = await waitForJob('job-1', { intervalMs: 1 });
    expect(job.status).toBe('succeeded');
    expect(job.id).toBe('job-1');
    expect(calls).toBe(3);
  });

  it('treats a job waiting for an administrator as finished for the caller', () => {
    expect(isTerminal('blocked_license')).toBe(true);
    expect(isTerminal('failed')).toBe(true);
    expect(isTerminal('queued')).toBe(false);
    expect(isTerminal('running')).toBe(false);
  });

  it('gives up after the timeout and returns the last state', async () => {
    server.use(http.get('/api/v1/jobs/:id', () => HttpResponse.json(jobFixture({ status: 'running' }))));
    const err = await waitForJob('job-2', { intervalMs: 1, timeoutMs: 5 }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(JobTimeoutError);
    expect((err as JobTimeoutError).job.status).toBe('running');
  });

  it('stops polling when the caller cancels', async () => {
    let calls = 0;
    server.use(
      http.get('/api/v1/jobs/:id', () => {
        calls += 1;
        return HttpResponse.json(jobFixture({ status: 'running' }));
      }),
    );
    const ctrl = new AbortController();
    const pending = waitForJob('job-3', { intervalMs: 20, signal: ctrl.signal }).catch((e: unknown) => e);
    await new Promise((r) => setTimeout(r, 50));
    ctrl.abort();
    const err = await pending;
    expect((err as Error).name).toBe('AbortError');
    const seen = calls;
    await new Promise((r) => setTimeout(r, 80));
    expect(calls).toBe(seen);
  });
});
