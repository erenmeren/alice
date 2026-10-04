import { http, HttpResponse } from 'msw';
import { errorResponse, jobFixture } from '../test/fixtures';
import { server } from '../test/server';
import type { ApiErrorBody } from './types';
import { ApiError, NetworkError } from './client';
import { isTerminal, isTransient, JobTimeoutError, waitForJob } from './jobs';

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

  it('keeps waiting through a retryable server error and a dropped connection', async () => {
    let calls = 0;
    server.use(
      http.get('/api/v1/jobs/:id', () => {
        calls += 1;
        if (calls === 1) return errorResponse(503, 'ALC-SYS-0002', 'system.unavailable', { retryable: true });
        if (calls === 2) return HttpResponse.error();
        return HttpResponse.json(jobFixture({ status: 'succeeded' }));
      }),
    );
    const job = await waitForJob('job-4', { intervalMs: 1 });
    expect(job.status).toBe('succeeded');
    expect(calls).toBe(3);
  });

  it('rejects at once on an error that retrying cannot fix', async () => {
    let calls = 0;
    server.use(
      http.get('/api/v1/jobs/:id', () => {
        calls += 1;
        return errorResponse(404, 'ALC-SYS-0001', 'system.not_found');
      }),
    );
    await expect(waitForJob('job-5', { intervalMs: 1 })).rejects.toMatchObject({ status: 404 });
    expect(calls).toBe(1);
  });

  it('gives up on a failing server when the deadline has passed', async () => {
    server.use(http.get('/api/v1/jobs/:id', () => HttpResponse.error()));
    await expect(waitForJob('job-6', { intervalMs: 1, timeoutMs: 20 })).rejects.toBeInstanceOf(NetworkError);
  });

  it('treats only network failures and retryable API errors as transient', () => {
    expect(isTransient(new NetworkError('offline', { cause: new TypeError('Failed to fetch') }))).toBe(true);
    expect(isTransient(new TypeError("Cannot read properties of undefined (reading 'status')"))).toBe(false);
    expect(isTransient(new ApiError(503, { code: 'ALC-SYS-0002', reason: 'system.unavailable', retryable: true } as ApiErrorBody['error']))).toBe(true);
    expect(isTransient(new ApiError(404, { code: 'ALC-SYS-0001', reason: 'system.not_found', retryable: false } as ApiErrorBody['error']))).toBe(false);
  });

  it('retries a network failure until the job ends', async () => {
    let calls = 0;
    server.use(http.get('/api/v1/jobs/j2', () => (++calls < 3 ? HttpResponse.error() : HttpResponse.json(jobFixture({ id: 'j2', status: 'succeeded' })))));
    await expect(waitForJob('j2', { intervalMs: 1 })).resolves.toMatchObject({ status: 'succeeded' });
    expect(calls).toBe(3);
  });
});
