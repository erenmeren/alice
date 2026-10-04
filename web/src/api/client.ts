import { ACTIVITY_HEADER, returnActivity, takeActivity } from './activity';
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
  // staleSession: a 401 auth.unauthenticated to a request sent before the session was replaced (a
  // step-up or a password change rotates the cookie); it did not end the current session.
  staleSession = false;

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
// sessionGeneration counts the sessions this page has been given (every setCsrfToken). A request
// remembers the generation it was sent in.
let sessionGeneration = 0;

// setCsrfToken stores the token sent as X-CSRF-Token on state-changing requests, and starts a new
// session generation: the session was set, replaced (a step-up or a password change rotates the
// cookie) or ended. It lives in memory only; a page reload fetches it again from /auth/session.
export function setCsrfToken(token: string | null): void {
  csrfToken = token;
  sessionGeneration += 1;
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
  // publicRoute marks a route the server answers without resolving the session (rbac.Public). It
  // neither carries nor consumes the activity mark, which would slide nothing there (AUD-01).
  publicRoute?: boolean;
  // keepalive lets the request finish after the page is closed (the activity flush on pagehide).
  keepalive?: boolean;
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
  const url = new URL(path, window.location.origin);
  // AUD-01 (activity.ts): the first request after a person's input carries the activity mark, and
  // so does every state-changing request. Polls without input since the last mark do not, so they
  // never keep a session alive. Only Alice's own origin ever sees the header.
  const marks = url.origin === window.location.origin && !opts.publicRoute;
  const tookMark = marks && takeActivity();
  const sentIn = sessionGeneration;
  if (marks && (tookMark || method !== 'GET')) headers[ACTIVITY_HEADER] = '1';

  let res: Response;
  try {
    res = await fetch(url, {
      method,
      headers,
      body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
      credentials: 'same-origin',
      signal: opts.signal,
      keepalive: opts.keepalive,
    });
  } catch (e) {
    // The request may never have reached Alice: the next one carries the mark instead.
    if (tookMark) returnActivity();
    // An aborted request stays an AbortError: the caller cancelled it, nothing failed.
    if (e instanceof Error && e.name === 'AbortError') throw e;
    throw new NetworkError('network failure', { cause: e });
  }
  // A rate-limited or failed answer may not have recorded the activity either.
  if (tookMark && (res.status === 429 || res.status >= 500)) returnActivity();
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
    if (err.status === 401 && err.reason === 'auth.unauthenticated') {
      // A request sent with a session that has since been replaced carried the old cookie: its
      // refusal says nothing about the current session, so it does not sign the person out (the
      // rotation race of a step-up or a password change). A query reads again (retry.ts).
      if (sentIn !== sessionGeneration) err.staleSession = true;
      else if (!opts.quietUnauthorized) unauthorizedListeners.forEach((l) => l());
    }
    throw err;
  }
  return (text === '' ? undefined : JSON.parse(text)) as T;
}
