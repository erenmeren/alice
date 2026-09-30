import type { DefaultOptions } from '@tanstack/react-query';
import { isApiError } from './client';

const MAX_RETRIES = 2;
const MAX_DELAY_MS = 30_000;

// shouldRetry retries what the server marked retryable (503 and similar) and network
// failures (fetch throws TypeError). 401, 403 and validation errors are never retried.
export function shouldRetry(failureCount: number, error: unknown): boolean {
  const retryable = isApiError(error) ? error.retryable : error instanceof TypeError;
  return retryable && failureCount < MAX_RETRIES;
}

// retryDelay honours Retry-After (capped) and otherwise backs off exponentially.
export function retryDelay(failureCount: number, error: unknown): number {
  if (isApiError(error) && error.retryAfter !== null) return Math.min(error.retryAfter * 1000, MAX_DELAY_MS);
  return Math.min(1000 * 2 ** failureCount, MAX_DELAY_MS);
}

export const queryDefaults: DefaultOptions = {
  queries: { retry: shouldRetry, retryDelay },
  mutations: { retry: false },
};
