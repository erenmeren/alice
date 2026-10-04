import { getDeployment } from './endpoints';
import { isTransient } from './jobs';
import type { Deployment, DeploymentDetail } from './types';

// A deployment in one of these statuses will not change on its own any more. needs_attention is not
// one of them: Alice keeps trying to reach the server (see deploymentView).
export const FINAL_STATUSES: ReadonlySet<string> = new Set(['succeeded', 'unchanged', 'failed', 'rolled_back', 'rollback_failed']);

// What a screen shows for a deployment:
//   final      a result: succeeded, unchanged, failed, rolled_back or rollback_failed
//   held       the license is expired and the job waits for an Administrator (job status blocked_license)
//   recovering the connection was lost; Alice checks the server and finishes or undoes the change
//              (state recovering, or status needs_attention when Alice cannot reach the server)
//   stopped    the job ended (failed, cancelled or given up) while the record is still not final
//   unknown    the status is a value this version does not know ('' or newer)
//   working    queued or running
export type DeploymentView = 'final' | 'held' | 'recovering' | 'stopped' | 'unknown' | 'working';

const KNOWN_ACTIVE: ReadonlySet<string> = new Set(['pending', 'running', 'needs_attention']);
const ENDED_JOBS: ReadonlySet<string> = new Set(['failed', 'cancelled', 'dead']);

export function deploymentView(d: Pick<Deployment, 'status' | 'state' | 'job_status'>): DeploymentView {
  if (FINAL_STATUSES.has(d.status)) return 'final';
  if (d.job_status === 'blocked_license') return 'held';
  if (d.state === 'recovering' || d.status === 'needs_attention') return 'recovering';
  if (ENDED_JOBS.has(d.job_status)) return 'stopped';
  if (!KNOWN_ACTIVE.has(d.status)) return 'unknown';
  return 'working';
}

// isSettled: polling can stop (the view is anything but working).
export const isSettled = (d: Pick<Deployment, 'status' | 'state' | 'job_status'>): boolean => deploymentView(d) !== 'working';

function abortError(): Error {
  const err = new Error('cancelled');
  err.name = 'AbortError';
  return err;
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

export interface WatchResult {
  // deployment is the last state read (null when none was read before the wait ended).
  deployment: DeploymentDetail | null;
  // timedOut: the deadline passed while the deployment was still working, or the connection to
  // Alice stayed down until then; the deployment itself goes on in the background.
  timedOut: boolean;
  // connectionLost: the last answer was a dropped connection or a retryable error.
  connectionLost: boolean;
}

// watchDeployment polls GET /deployments/{id} until the deployment is settled (see deploymentView)
// or the deadline passes. Every state read is passed to onUpdate, so a screen shows the steps as
// they arrive. A dropped connection or a retryable answer is waited out until the deadline (the
// deployment goes on without the browser); any other error rejects. A cancelled signal rejects with
// an AbortError (see isAbort in jobs.ts). It never loops forever: the deadline ends it.
export async function watchDeployment(
  id: string,
  opts: { signal?: AbortSignal; intervalMs?: number; timeoutMs?: number; onUpdate?: (d: DeploymentDetail) => void } = {},
): Promise<WatchResult> {
  const interval = opts.intervalMs ?? 1000;
  const deadline = Date.now() + (opts.timeoutMs ?? 120_000);
  let last: DeploymentDetail | null = null;
  let connectionLost: boolean;
  for (;;) {
    if (opts.signal?.aborted) throw abortError();
    try {
      const d = await getDeployment(id);
      if (opts.signal?.aborted) throw abortError();
      last = d;
      opts.onUpdate?.(d);
      if (isSettled(d)) return { deployment: d, timedOut: false, connectionLost: false };
      connectionLost = false;
    } catch (e) {
      if (opts.signal?.aborted) throw abortError();
      if (!isTransient(e)) throw e;
      connectionLost = true;
    }
    if (Date.now() > deadline) return { deployment: last, timedOut: true, connectionLost };
    await sleep(interval, opts.signal);
  }
}
