import { http, HttpResponse } from 'msw';
import { server } from '../test/server';
import { errorResponse } from '../test/fixtures';
import { apiFetch, ApiError, onUnauthorized, setCsrfToken } from './client';

describe('apiFetch', () => {
  it('sends JSON with the CSRF token on state-changing requests only', async () => {
    const seen: { method: string; csrf: string | null; type: string | null }[] = [];
    server.use(
      http.all('/api/v1/echo', async ({ request }) => {
        seen.push({
          method: request.method,
          csrf: request.headers.get('X-CSRF-Token'),
          type: request.headers.get('Content-Type'),
        });
        return HttpResponse.json({ ok: true });
      }),
    );
    setCsrfToken('tok-1');
    await apiFetch('/api/v1/echo');
    await apiFetch('/api/v1/echo', { method: 'POST', body: { a: 1 } });
    expect(seen).toEqual([
      { method: 'GET', csrf: null, type: null },
      { method: 'POST', csrf: 'tok-1', type: 'application/json' },
    ]);
  });

  it('returns undefined for 204', async () => {
    server.use(http.delete('/api/v1/echo', () => new HttpResponse(null, { status: 204 })));
    await expect(apiFetch('/api/v1/echo', { method: 'DELETE' })).resolves.toBeUndefined();
  });

  it('turns an error body into ApiError', async () => {
    server.use(
      http.post('/api/v1/echo', () =>
        errorResponse(422, 'ALC-SYS-0006', 'validation.failed', {
          details: [{ field: 'username', code: 'validation.required' }],
        }),
      ),
    );
    const err = await apiFetch('/api/v1/echo', { method: 'POST', body: {} }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    const e = err as ApiError;
    expect([e.status, e.code, e.reason, e.messageKey, e.requestId]).toEqual([
      422,
      'ALC-SYS-0006',
      'validation.failed',
      'errors.validation.failed',
      'req-1',
    ]);
    expect(e.details).toEqual([{ field: 'username', code: 'validation.required' }]);
  });

  it('keeps a non-JSON error body usable', async () => {
    server.use(http.get('/api/v1/echo', () => new HttpResponse('<html>bad gateway</html>', { status: 502 })));
    const e = (await apiFetch('/api/v1/echo').catch((x: unknown) => x)) as ApiError;
    expect(e.status).toBe(502);
    expect(e.reason).toBe('');
  });

  it('announces an ended session, but not wrong codes or quiet probes', async () => {
    const calls: string[] = [];
    const off = onUnauthorized(() => calls.push('ended'));
    server.use(
      http.get('/api/v1/ended', () => errorResponse(401, 'ALC-AUTH-0001', 'auth.unauthenticated')),
      http.post('/api/v1/wrong', () => errorResponse(401, 'ALC-AUTH-0006', 'auth.mfa_invalid')),
    );
    await apiFetch('/api/v1/ended').catch(() => undefined);
    await apiFetch('/api/v1/wrong', { method: 'POST' }).catch(() => undefined);
    await apiFetch('/api/v1/ended', { quietUnauthorized: true }).catch(() => undefined);
    off();
    await apiFetch('/api/v1/ended').catch(() => undefined);
    expect(calls).toEqual(['ended']);
  });
});
