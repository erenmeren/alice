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

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// waitForJob polls GET /jobs/{id} until the job has finished. Long operations answer 202 with a
// job ID (spec §9.1); the screens wait here and then refresh what the job changed.
export async function waitForJob(id: string, opts: { intervalMs?: number; timeoutMs?: number } = {}): Promise<Job> {
  const interval = opts.intervalMs ?? 1000;
  const deadline = Date.now() + (opts.timeoutMs ?? 120_000);
  for (;;) {
    const job = await getJob(id);
    if (isTerminal(job.status)) return job;
    if (Date.now() > deadline) throw new JobTimeoutError(job);
    await sleep(interval);
  }
}
