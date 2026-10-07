import { http, HttpResponse } from 'msw';
import { server } from '../test/server';
import { errorResponse } from '../test/fixtures';
import { noteInput, resetActivity, takeActivity } from './activity';
import { apiFetch, ApiError, NetworkError, onUnauthorized, setCsrfToken } from './client';

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

  it('ignores a session-ended answer to a request sent before the session was replaced (AUD-16 rotation race)', async () => {
    const calls: string[] = [];
    const off = onUnauthorized(() => calls.push('ended'));
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    server.use(
      http.get('/api/v1/slow-old-cookie', async () => {
        await gate; // answered after the step-up rotated the cookie: the old cookie is refused
        return errorResponse(401, 'ALC-AUTH-0001', 'auth.unauthenticated');
      }),
      http.get('/api/v1/ended', () => errorResponse(401, 'ALC-AUTH-0001', 'auth.unauthenticated')),
    );
    setCsrfToken('csrf-old');
    const stale = apiFetch('/api/v1/slow-old-cookie').catch((e: unknown) => e);
    setCsrfToken('csrf-new'); // a step-up or a password change set the new session
    release();
    const err = (await stale) as ApiError;
    expect(err.reason).toBe('auth.unauthenticated');
    expect(err.staleSession).toBe(true);
    expect(calls).toEqual([]);

    // A request sent with the new session that is refused does end it.
    const fresh = (await apiFetch('/api/v1/ended').catch((e: unknown) => e)) as ApiError;
    expect(fresh.staleSession).toBe(false);
    expect(calls).toEqual(['ended']);
    off();
  });

  it('wraps a rejected fetch in NetworkError and sends extra headers', async () => {
    server.use(http.get('/api/v1/down', () => HttpResponse.error()));
    await expect(apiFetch('/api/v1/down')).rejects.toBeInstanceOf(NetworkError);
    let ifMatch: string | null = null;
    server.use(http.patch('/api/v1/etag', ({ request }) => { ifMatch = request.headers.get('If-Match'); return HttpResponse.json({}); }));
    await apiFetch('/api/v1/etag', { method: 'PATCH', body: {}, headers: { 'If-Match': '"3"' } });
    expect(ifMatch).toBe('"3"');
  });

  it('wraps a connection that drops while the body is read in NetworkError too', async () => {
    server.use(
      http.get('/api/v1/cut', () => {
        const body = new ReadableStream({
          start(c) {
            c.error(new TypeError('terminated'));
          },
        });
        return new HttpResponse(body, { status: 200, headers: { 'Content-Type': 'application/json' } });
      }),
    );
    await expect(apiFetch('/api/v1/cut')).rejects.toBeInstanceOf(NetworkError);
  });
});

describe('activity mark (AUD-01)', () => {
  const keydown = { isTrusted: true, type: 'keydown' } as unknown as Event;
  let seen: (string | null)[];

  beforeEach(() => {
    resetActivity(false);
    seen = [];
    server.use(
      http.all('/api/v1/echo', ({ request }) => {
        seen.push(request.headers.get('X-Alice-Activity'));
        return HttpResponse.json({});
      }),
    );
  });

  it('marks a read only after input, once, and every state-changing request', async () => {
    await apiFetch('/api/v1/echo');
    noteInput(keydown);
    await apiFetch('/api/v1/echo');
    await apiFetch('/api/v1/echo');
    await apiFetch('/api/v1/echo', { method: 'POST', body: {} });
    await apiFetch('/api/v1/echo', { method: 'DELETE' });
    await apiFetch('/api/v1/echo');
    expect(seen).toEqual([null, '1', null, '1', '1', null]);
  });

  it('never marks polls without input, however many', async () => {
    for (let i = 0; i < 10; i++) await apiFetch('/api/v1/echo');
    expect(seen).toEqual(Array(10).fill(null));
  });

  it('a state-changing request also uses up the input mark, since it slides the session itself', async () => {
    noteInput(keydown);
    await apiFetch('/api/v1/echo', { method: 'POST', body: {} });
    await apiFetch('/api/v1/echo');
    expect(seen).toEqual(['1', null]);
  });

  it('a public route neither carries nor uses up the mark', async () => {
    let publicMark: string | null = 'unset';
    server.use(http.get('/api/v1/setup/status', ({ request }) => { publicMark = request.headers.get('X-Alice-Activity'); return HttpResponse.json({}); }));
    noteInput(keydown);
    await apiFetch('/api/v1/setup/status', { publicRoute: true });
    await apiFetch('/api/v1/echo');
    expect(publicMark).toBeNull();
    expect(seen).toEqual(['1']);
  });

  it('gives the mark back when its request fails, so the next one carries it', async () => {
    server.use(http.get('/api/v1/down', () => HttpResponse.error()));
    noteInput(keydown);
    await expect(apiFetch('/api/v1/down')).rejects.toBeInstanceOf(NetworkError);
    await apiFetch('/api/v1/echo');
    await apiFetch('/api/v1/echo');
    expect(seen).toEqual(['1', null]);
  });

  it('gives the mark back when the request is cancelled', async () => {
    const abort = new AbortController();
    abort.abort();
    noteInput(keydown);
    await expect(apiFetch('/api/v1/echo', { signal: abort.signal })).rejects.toMatchObject({ name: 'AbortError' });
    expect(takeActivity()).toBe(true);
  });

  it.each([429, 503, 500])('gives the mark back on %i (the activity may not have been recorded)', async (status) => {
    server.use(http.get('/api/v1/busy', () => errorResponse(status, 'ALC-SYS-0002', 'system.unavailable')));
    noteInput(keydown);
    await expect(apiFetch('/api/v1/busy')).rejects.toBeInstanceOf(ApiError);
    expect(takeActivity()).toBe(true);
  });

  it.each([401, 403, 404, 409, 422])('keeps the mark used on %i (the server recorded it, or there is no session)', async (status) => {
    server.use(http.get('/api/v1/refused', () => errorResponse(status, 'ALC-SYS-0006', 'validation.failed')));
    noteInput(keydown);
    await expect(apiFetch('/api/v1/refused', { quietUnauthorized: true })).rejects.toBeInstanceOf(ApiError);
    expect(takeActivity()).toBe(false);
  });

  it('never sends the mark to another origin and keeps it for Alice', async () => {
    const elsewhere: (string | null)[] = [];
    server.use(http.get('https://elsewhere.example/x', ({ request }) => { elsewhere.push(request.headers.get('X-Alice-Activity')); return HttpResponse.json({}); }));
    noteInput(keydown);
    await apiFetch('https://elsewhere.example/x', { method: 'GET' });
    await apiFetch('/api/v1/echo');
    expect(elsewhere).toEqual([null]);
    expect(seen).toEqual(['1']);
  });

  it('returns a Blob for a successful answer with responseType blob', async () => {
    server.use(http.post('/api/v1/echo', () => new HttpResponse('raw-bytes', { headers: { 'Content-Type': 'application/octet-stream' } })));
    const blob = await apiFetch<Blob>('/api/v1/echo', { method: 'POST', body: {}, responseType: 'blob' });
    expect(blob).toBeInstanceOf(Blob);
    expect(await blob.text()).toBe('raw-bytes');
  });

  it('still throws ApiError with the parsed body for a failed blob request', async () => {
    server.use(http.post('/api/v1/echo', () => errorResponse(409, 'ALC-KEY-0001', 'sshkey.own_key_protected')));
    await expect(apiFetch<Blob>('/api/v1/echo', { method: 'POST', body: {}, responseType: 'blob' })).rejects.toMatchObject({
      name: 'ApiError',
      status: 409,
      reason: 'sshkey.own_key_protected',
    });
  });

  it('accepts the file content type in any letter case', async () => {
    server.use(http.post('/api/v1/echo', () => new HttpResponse('x', { headers: { 'Content-Type': 'Application/Octet-Stream; charset=binary' } })));
    await expect(apiFetch<Blob>('/api/v1/echo', { method: 'POST', body: {}, responseType: 'blob' })).resolves.toBeInstanceOf(Blob);
  });

  it('refuses a successful blob answer that is not the file', async () => {
    server.use(http.post('/api/v1/echo', () => HttpResponse.json({ spa: true })));
    await expect(apiFetch<Blob>('/api/v1/echo', { method: 'POST', body: {}, responseType: 'blob' })).rejects.toBeInstanceOf(ApiError);
    server.use(http.post('/api/v1/echo', () => new HttpResponse('<html>', { headers: { 'Content-Type': 'text/html' } })));
    await expect(apiFetch<Blob>('/api/v1/echo', { method: 'POST', body: {}, responseType: 'blob' })).rejects.toMatchObject({ status: 200 });
  });

  it('returns a Blob for a text/csv answer with responseType csv, and asks for csv', async () => {
    let accept = '';
    server.use(http.get('/api/v1/echo', ({ request }) => {
      accept = request.headers.get('Accept') ?? '';
      return new HttpResponse('a,b\n1,2\n', { headers: { 'Content-Type': 'text/csv; charset=utf-8' } });
    }));
    const blob = await apiFetch<Blob>('/api/v1/echo', { responseType: 'csv' });
    expect(await blob.text()).toBe('a,b\n1,2\n');
    expect(accept).toBe('text/csv, application/json');
  });

  it('never takes a JSON or an octet-stream answer for the csv file, and throws the error body', async () => {
    server.use(http.get('/api/v1/echo', () => HttpResponse.json({ spa: true })));
    await expect(apiFetch<Blob>('/api/v1/echo', { responseType: 'csv' })).rejects.toBeInstanceOf(ApiError);
    server.use(http.get('/api/v1/echo', () => errorResponse(409, 'ALC-RPT-0001', 'export.too_large', { params: { max: '50000' } })));
    await expect(apiFetch<Blob>('/api/v1/echo', { responseType: 'csv' })).rejects.toMatchObject({ status: 409, reason: 'export.too_large' });
  });
});
