import type { ApiErrorBody, FieldError } from './types';

// ApiError carries the stable error fields from the server (spec §9.3).
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly reason: string;
  readonly messageKey: string;
  readonly params: Record<string, string>;
  readonly details: FieldError[];
  readonly requestId: string;
  readonly retryable: boolean;
  // retryAfter is the Retry-After header in seconds, or null when absent.
  readonly retryAfter: number | null;

  constructor(status: number, body: ApiErrorBody['error'] | null, retryAfter: number | null = null) {
    // No body means no localized text; the UI then shows its own generic message.
    super(body?.message ?? '');
    this.name = 'ApiError';
    this.status = status;
    this.code = body?.code ?? '';
    this.reason = body?.reason ?? '';
    this.messageKey = body?.message_key ?? '';
    this.params = body?.params ?? {};
    this.details = body?.details ?? [];
    this.requestId = body?.request_id ?? '';
    this.retryable = body?.retryable ?? false;
    this.retryAfter = retryAfter;
  }
}

// NetworkError is a fetch() that rejected: the network or the server was unreachable. It is the
// only non-API failure the screens treat as transient (a TypeError from our own code is a bug).
export class NetworkError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'NetworkError';
  }
}

export function isApiError(e: unknown, reason?: string): e is ApiError {
  return e instanceof ApiError && (reason === undefined || e.reason === reason);
}

let csrfToken: string | null = null;

// setCsrfToken stores the token sent as X-CSRF-Token on state-changing requests.
// It lives in memory only; a page reload fetches it again from /auth/session.
export function setCsrfToken(token: string | null): void {
  csrfToken = token;
}

export function getCsrfToken(): string | null {
  return csrfToken;
}

type Listener = () => void;
const unauthorizedListeners = new Set<Listener>();

// onUnauthorized registers a callback for "your session ended" (reason auth.unauthenticated).
export function onUnauthorized(cb: Listener): () => void {
  unauthorizedListeners.add(cb);
  return () => {
    unauthorizedListeners.delete(cb);
  };
}

export interface FetchOptions {
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  body?: unknown;
  signal?: AbortSignal;
  // quietUnauthorized suppresses the session-ended event (used by the initial session probe).
  quietUnauthorized?: boolean;
  // headers are extra request headers (for example If-Match); they never replace the fixed ones.
  headers?: Record<string, string>;
}

function parseRetryAfter(value: string | null): number | null {
  if (value === null || !/^\d+$/.test(value.trim())) return null;
  return Number(value.trim());
}

function parseErrorBody(text: string): ApiErrorBody['error'] | null {
  try {
    const parsed = JSON.parse(text) as Partial<ApiErrorBody>;
    return parsed.error ?? null;
  } catch {
    return null;
  }
}

export async function apiFetch<T>(path: string, opts: FetchOptions = {}): Promise<T> {
  const method = opts.method ?? 'GET';
  const headers: Record<string, string> = { ...opts.headers, Accept: 'application/json' };
  if (opts.body !== undefined) headers['Content-Type'] = 'application/json';
  if (method !== 'GET' && csrfToken) headers['X-CSRF-Token'] = csrfToken;

  let res: Response;
  try {
    res = await fetch(new URL(path, window.location.origin), {
      method,
      headers,
      body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
      credentials: 'same-origin',
      signal: opts.signal,
    });
  } catch (e) {
    // An aborted request stays an AbortError: the caller cancelled it, nothing failed.
    if (e instanceof Error && e.name === 'AbortError') throw e;
    throw new NetworkError('network failure', { cause: e });
  }
  if (res.status === 204) return undefined as T;
  let text: string;
  try {
    text = await res.text();
  } catch (e) {
    // The connection can drop after the headers; that is the same transient failure.
    if (e instanceof Error && e.name === 'AbortError') throw e;
    throw new NetworkError('network failure', { cause: e });
  }
  if (!res.ok) {
    const err = new ApiError(res.status, parseErrorBody(text), parseRetryAfter(res.headers.get('Retry-After')));
    if (err.status === 401 && err.reason === 'auth.unauthenticated' && !opts.quietUnauthorized) {
      unauthorizedListeners.forEach((l) => l());
    }
    throw err;
  }
  return (text === '' ? undefined : JSON.parse(text)) as T;
}
