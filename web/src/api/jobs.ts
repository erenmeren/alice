import { isApiError } from './client';
import { getJob } from './endpoints';
import type { Job, JobStatus } from './types';

// A job in one of these states will not change on its own any more. blocked_license waits for an
// Administrator (R29), so a screen that started it stops waiting and shows that state instead.
const TERMINAL: ReadonlySet<JobStatus> = new Set<JobStatus>(['succeeded', 'failed', 'cancelled', 'dead', 'blocked_license']);

export function isTerminal(status: JobStatus): boolean {
  return TERMINAL.has(status);
}

// JobTimeoutError means the job did not finish while the screen waited; job is its last state.
export class JobTimeoutError extends Error {
  readonly job: Job;

  constructor(job: Job) {
    super('job did not finish in time');
    this.name = 'JobTimeoutError';
    this.job = job;
  }
}

function abortError(): Error {
  const err = new Error('cancelled');
  err.name = 'AbortError';
  return err;
}

// isAbort tells a cancelled wait from a real failure.
export function isAbort(e: unknown): boolean {
  return e instanceof Error && e.name === 'AbortError';
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(abortError());
      return;
    }
    const onAbort = () => {
      clearTimeout(timer);
      reject(abortError());
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

// waitForJob polls GET /jobs/{id} until the job has finished. Long operations answer 202 with a
// job ID (spec §9.1); the screens wait here and then refresh what the job changed. A screen that
// goes away passes a signal; a network error or a retryable error while polling is retried until
// the deadline; the wait then rejects with an AbortError (see isAbort).
export async function waitForJob(
  id: string,
  opts: { intervalMs?: number; timeoutMs?: number; signal?: AbortSignal } = {},
): Promise<Job> {
  const interval = opts.intervalMs ?? 1000;
  const deadline = Date.now() + (opts.timeoutMs ?? 120_000);
  for (;;) {
    if (opts.signal?.aborted) throw abortError();
    let job: Job;
    try {
      job = await getJob(id);
    } catch (e) {
      // A dropped connection or a retryable answer (for example while Alice restarts) must not
      // end the wait: the job goes on without us. Anything else, or the deadline, rejects.
      const transient = isApiError(e) ? e.retryable : e instanceof TypeError;
      if (opts.signal?.aborted) throw abortError();
      if (!transient || Date.now() > deadline) throw e;
      await sleep(interval, opts.signal);
      continue;
    }
    if (opts.signal?.aborted) throw abortError();
    if (isTerminal(job.status)) return job;
    if (Date.now() > deadline) throw new JobTimeoutError(job);
    await sleep(interval, opts.signal);
  }
}
