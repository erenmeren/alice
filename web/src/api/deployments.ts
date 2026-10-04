import { ApiError } from './client';
import { deploymentStatusKey } from './enums';
import { getDeployment } from './endpoints';
import { isTransient } from './jobs';
import type { Deployment, DeploymentDetail } from './types';

// A deployment in one of these statuses will not change on its own any more. needs_attention is not
// one of them: Alice keeps trying to reach the server (see deploymentView).
export const FINAL_STATUSES: ReadonlySet<string> = new Set(['succeeded', 'unchanged', 'failed', 'rolled_back', 'rollback_failed']);

// What a screen shows for a deployment:
//   final      a result: succeeded, unchanged, failed, rolled_back or rollback_failed
//   recovering the connection was lost; Alice checks the server and finishes or undoes the change
//              (state recovering, or status needs_attention when Alice cannot reach the server). It
//              wins over a held job: the API reports the status of the deployment's ORIGINAL job, which
//              can be blocked_license while a recovery job of its own follows a deployment that was sent.
//   held       nothing was sent yet (state queued or precheck) and the job waits for an Administrator
//              because the license expired (job status blocked_license)
//   finishing  the job succeeded but the record is not final yet (the result is being recorded)
//   stopped    the job ended (failed, cancelled or given up) while the record is still not final
//   unknown    the status is a value this version does not know ('' or newer)
//   working    queued or running
export type DeploymentView = 'final' | 'held' | 'recovering' | 'finishing' | 'stopped' | 'unknown' | 'working';

const KNOWN_ACTIVE: ReadonlySet<string> = new Set(['pending', 'running', 'needs_attention']);
const ENDED_JOBS: ReadonlySet<string> = new Set(['failed', 'cancelled', 'dead']);
// NOT_SENT are the states in which nothing has been sent to the server yet.
const NOT_SENT: ReadonlySet<string> = new Set(['queued', 'precheck']);

// CANCELLED_REASON is the error reason of a deployment an Administrator cancelled (discarded its
// waiting job) before anything was sent (ALC-DEP-0022). Its status is failed; screens call it
// cancelled, never a failure of the server.
export const CANCELLED_REASON = 'deployment.cancelled';

export const isCancelled = (d: Pick<Deployment, 'status' | 'error'>): boolean => d.status === 'failed' && d.error?.reason === CANCELLED_REASON;

// PENDING_CHANGE_RESTORED (ALC-DEP-0024): the deployment put back the files from before an unfinished
// EARLIER change on the server and did not write its own certificate. Its status is rolled_back, but
// "restored to its previous certificate" would read as the certificate that was live when Deploy was
// chosen, so screens give it its own headline.
export const PENDING_CHANGE_RESTORED = 'deployment.pending_change_restored';

// SERVER_OPERATION_PENDING (ALC-DEP-0023): an unfinished earlier change blocks the files; this
// deployment's certificate was not written, but an unfinished restore attempt may have put back one
// of the two files, so "nothing was changed" would be false.
export const SERVER_OPERATION_PENDING = 'deployment.server_operation_pending';

// deploymentStatusText is the text key of a deployment's status: a failed deployment that an
// Administrator cancelled before anything was sent reads "Cancelled", never as a failure.
export function deploymentStatusText(d: Pick<Deployment, 'status' | 'error'>): string {
  return isCancelled(d) ? 'deployments.cancelled' : deploymentStatusKey(d.status);
}

// wasSent: the deployment may have reached the server (it left the queued and pre-check states).
export const wasSent = (d: Pick<Deployment, 'state'>): boolean => d.state !== '' && !NOT_SENT.has(d.state);

export function deploymentView(d: Pick<Deployment, 'status' | 'state' | 'job_status'>): DeploymentView {
  if (FINAL_STATUSES.has(d.status)) return 'final';
  if (d.state === 'recovering' || d.status === 'needs_attention') return 'recovering';
  if (d.job_status === 'blocked_license' && NOT_SENT.has(d.state)) return 'held';
  if (d.job_status === 'succeeded' && KNOWN_ACTIVE.has(d.status)) return 'finishing';
  if (ENDED_JOBS.has(d.job_status)) return 'stopped';
  if (!KNOWN_ACTIVE.has(d.status)) return 'unknown';
  return 'working';
}

// isSettled: polling can stop (the view is anything but working).
export const isSettled = (d: Pick<Deployment, 'status' | 'state' | 'job_status'>): boolean => {
  const v = deploymentView(d);
  return v !== 'working' && v !== 'finishing';
};

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
  // error: reading this deployment failed for good (for example a 404); the others are still followed.
  error?: unknown;
}

// The request budget of one batch: one tick per second, and at most PER_TICK deployment reads in a
// tick, however many deployments the batch has (at most 20). That is at most 120 requests a minute
// for the whole batch, well inside the session's 300 a minute (internal/api/server.go), so the other
// screens keep working. A batch of N is read round-robin: every deployment is refreshed about every
// ceil(N / PER_TICK) seconds (1 s for N of 1 or 2, 3 s for 5, 10 s for 20).
export const POLL_TICK_MS = 1_000;
export const POLL_PER_TICK = 2;
// A 429 or 503 may carry Retry-After; the wait is capped so a silly value cannot stall the screen.
const MAX_RETRY_AFTER_MS = 60_000;

export interface BatchOptions {
  signal?: AbortSignal;
  intervalMs?: number;
  perTick?: number;
  timeoutMs?: number;
  onUpdate?: (id: string, d: DeploymentDetail) => void;
  // onDone is called once per deployment: when it settles, or when the deadline passes.
  onDone?: (id: string, result: WatchResult) => void;
}

// watchDeployments follows a batch of deployments with ONE loop (see the budget above) until every
// one is settled (deploymentView is not working) or the deadline passes. Every read goes to
// onUpdate, so a screen shows the steps as they arrive. A dropped connection or a retryable answer
// is waited out until the deadline; for a 429 or 503 the next request waits at least Retry-After.
// Any other error ends that one deployment (WatchResult.error) and not the batch. A cancelled signal rejects with an AbortError (see isAbort in jobs.ts).
export async function watchDeployments(ids: string[], opts: BatchOptions = {}): Promise<Record<string, WatchResult>> {
  const interval = opts.intervalMs ?? POLL_TICK_MS;
  const perTick = Math.max(1, opts.perTick ?? POLL_PER_TICK);
  const deadline = Date.now() + (opts.timeoutMs ?? 120_000);
  const last: Record<string, DeploymentDetail | null> = {};
  const results: Record<string, WatchResult> = {};
  let lost = false;
  for (const id of ids) last[id] = null;
  let cursor = 0;
  let waitUntil = 0;
  const finish = (id: string, r: WatchResult) => {
    results[id] = r;
    opts.onDone?.(id, r);
  };
  for (;;) {
    if (opts.signal?.aborted) throw abortError();
    const open = ids.filter((id) => !(id in results));
    if (open.length === 0) return results;
    // Round-robin: the next perTick open deployments after the cursor.
    const batch: string[] = [];
    for (let i = 0; i < open.length && batch.length < perTick; i++) batch.push(open[(cursor + i) % open.length]);
    cursor = (cursor + batch.length) % Math.max(1, open.length);
    for (const id of batch) {
      if (Date.now() < waitUntil) break;
      try {
        const d = await getDeployment(id);
        if (opts.signal?.aborted) throw abortError();
        last[id] = d;
        lost = false;
        opts.onUpdate?.(id, d);
        if (isSettled(d)) finish(id, { deployment: d, timedOut: false, connectionLost: false });
      } catch (e) {
        if (opts.signal?.aborted) throw abortError();
        if (!isTransient(e)) {
          // This deployment cannot be read: it is marked with its error, the rest of the batch goes on.
          finish(id, { deployment: last[id], timedOut: false, connectionLost: false, error: e });
          continue;
        }
        lost = true;
        const wait = e instanceof ApiError && e.retryAfter !== null ? Math.min(e.retryAfter * 1000, MAX_RETRY_AFTER_MS) : 0;
        waitUntil = Math.max(waitUntil, Date.now() + wait);
        break; // one failed read ends the tick: do not hammer a server that is struggling
      }
    }
    if (ids.every((id) => id in results)) return results;
    if (Date.now() > deadline) {
      for (const id of ids) if (!(id in results)) finish(id, { deployment: last[id], timedOut: true, connectionLost: lost });
      return results;
    }
    await sleep(Math.max(interval, waitUntil - Date.now()), opts.signal);
  }
}

// watchDeployment follows one deployment (a batch of one).
export async function watchDeployment(
  id: string,
  opts: { signal?: AbortSignal; intervalMs?: number; timeoutMs?: number; onUpdate?: (d: DeploymentDetail) => void } = {},
): Promise<WatchResult> {
  const res = await watchDeployments([id], { signal: opts.signal, intervalMs: opts.intervalMs, timeoutMs: opts.timeoutMs, onUpdate: (_id, d) => opts.onUpdate?.(d) });
  return res[id];
}
