import { http, HttpResponse } from 'msw';
import { QueryClient } from '@tanstack/react-query';
import { errorResponse } from '../test/fixtures';
import { server } from '../test/server';
import { apiFetch, ApiError } from './client';
import { queryDefaults, retryDelay, shouldRetry } from './retry';

function apiError(status: number, retryable: boolean, retryAfter: number | null = null) {
  return new ApiError(
    status,
    { code: 'ALC-X-1', reason: 'x.y', message_key: 'errors.x.y', message: 'm', request_id: 'r', retryable },
    retryAfter,
  );
}

describe('retry policy', () => {
  it('retries retryable API errors and network failures, at most twice', () => {
    expect(shouldRetry(0, apiError(503, true))).toBe(true);
    expect(shouldRetry(1, apiError(503, true))).toBe(true);
    expect(shouldRetry(2, apiError(503, true))).toBe(false);
    expect(shouldRetry(0, new TypeError('Failed to fetch'))).toBe(true);
    expect(shouldRetry(0, new Error('boom'))).toBe(false);
  });

  it('never retries 401 or 403', () => {
    expect(shouldRetry(0, apiError(401, false))).toBe(false);
    expect(shouldRetry(0, apiError(403, false))).toBe(false);
  });

  it('honours Retry-After, caps it, and otherwise backs off exponentially', () => {
    expect(retryDelay(0, apiError(503, true, 5))).toBe(5000);
    expect(retryDelay(0, apiError(503, true, 0))).toBe(0);
    expect(retryDelay(0, apiError(503, true, 600))).toBe(30000);
    expect(retryDelay(0, apiError(503, true))).toBe(1000);
    expect(retryDelay(1, new TypeError('x'))).toBe(2000);
    expect(retryDelay(10, new TypeError('x'))).toBe(30000);
  });

  it('never retries mutations', () => {
    expect(queryDefaults.mutations?.retry).toBe(false);
  });

  it('retries a retryable 503 through a real query and stops on a 401', async () => {
    let calls = 0;
    server.use(
      http.get('/api/v1/flaky', () => {
        calls++;
        if (calls < 3) {
          return HttpResponse.json(
            { error: { code: 'ALC-SYS-0002', reason: 'system.unavailable', message_key: 'errors.system.unavailable', message: 'm', request_id: 'r', retryable: true } },
            { status: 503, headers: { 'Retry-After': '0' } },
          );
        }
        return HttpResponse.json({ ok: true });
      }),
      http.get('/api/v1/denied', () => {
        calls++;
        return errorResponse(401, 'ALC-AUTH-0006', 'auth.mfa_invalid');
      }),
    );
    const client = new QueryClient({ defaultOptions: queryDefaults });
    await expect(client.fetchQuery({ queryKey: ['a'], queryFn: () => apiFetch('/api/v1/flaky') })).resolves.toEqual({ ok: true });
    expect(calls).toBe(3);

    calls = 0;
    await expect(client.fetchQuery({ queryKey: ['b'], queryFn: () => apiFetch('/api/v1/denied') })).rejects.toBeInstanceOf(ApiError);
    expect(calls).toBe(1);
  });

  it('parses Retry-After seconds into ApiError.retryAfter', async () => {
    server.use(
      http.get('/api/v1/slow', () =>
        HttpResponse.json(
          { error: { code: 'C', reason: 'r', message_key: 'k', message: 'm', request_id: 'x', retryable: true } },
          { status: 503, headers: { 'Retry-After': '7' } },
        ),
      ),
    );
    const e = (await apiFetch('/api/v1/slow').catch((x: unknown) => x)) as ApiError;
    expect(e.retryAfter).toBe(7);
  });
});
