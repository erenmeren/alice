import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { http, HttpResponse } from 'msw';
import { deploymentDetailFixture, jobFixture, statusWith, targetFixture } from '../test/fixtures';
import { server } from '../test/server';
import { watchDeployments } from './deployments';
import { getDeployment, getLicenseStatus, getTarget, listAudit, listJobs } from './endpoints';
import { waitForJob } from './jobs';

// AUD-01 follow-up: a request the SPA sends by itself (a poll) must never be state-changing: the
// server slides a session's idle timeout on any non-GET request, so an automatic POST would keep
// an unattended tab signed in.

const SRC = join(process.cwd(), 'src');

function sources(dir = SRC): string[] {
  const out: string[] = [];
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) out.push(...sources(p));
    else if (/\.tsx?$/.test(e.name) && !/\.test\.tsx?$/.test(e.name) && !p.includes(`${join('src', 'test')}`)) out.push(p);
  }
  return out;
}

describe('polling', () => {
  it('happens only in the places reviewed here', () => {
    const pollers = sources()
      .filter((f) => /\brefetchInterval\b|\bwaitForJob\(|\bwatchDeployments\(/.test(readFileSync(f, 'utf8')))
      .map((f) => relative(SRC, f).split('\\').join('/'))
      .sort();
    // A new file here needs its query function added to the test below.
    expect(pollers).toEqual([
      'api/deployments.ts',
      'api/jobs.ts',
      'auth/SessionActivity.tsx',
      'components/AddServerModal.tsx',
      'components/DeployDialog.tsx',
      'components/RemoveKeyDialog.tsx',
      'pages/DeploymentDetailPage.tsx',
      'pages/TargetDetailPage.tsx',
    ]);
  });

  it('reads with GET only: the license status, a server, a deployment, a job and a batch of deployments', async () => {
    const methods: string[] = [];
    const seen = (request: Request) => {
      methods.push(`${request.method} ${new URL(request.url).pathname}`);
    };
    server.use(
      http.all('/api/v1/*', ({ request }) => {
        seen(request);
      }),
      http.get('/api/v1/license/status', () => HttpResponse.json(statusWith())),
      http.get('/api/v1/targets/:id', () => HttpResponse.json(targetFixture)),
      http.get('/api/v1/deployments/:id', ({ params }) => HttpResponse.json(deploymentDetailFixture({ id: String(params.id) }))),
      http.get('/api/v1/jobs/:id', () => HttpResponse.json(jobFixture({ status: 'succeeded' }))),
    );
    await getLicenseStatus();
    await getLicenseStatus({ keepalive: true });
    await getTarget(targetFixture.id);
    await getDeployment('d1');
    await waitForJob('j1', { intervalMs: 1 });
    await watchDeployments(['d1', 'd2'], { intervalMs: 1 });
    expect(methods.length).toBeGreaterThanOrEqual(6);
    expect(methods.filter((m) => !m.startsWith('GET '))).toEqual([]);
  });
});

describe('query strings (malformed-query refusals, AUD-13)', () => {
  it('escapes separators and reserved characters in every value', async () => {
    const queries: string[] = [];
    server.use(
      http.get('/api/v1/audit', ({ request }) => {
        queries.push(new URL(request.url).search);
        return HttpResponse.json({ items: [], next_cursor: null });
      }),
      http.get('/api/v1/jobs', ({ request }) => {
        queries.push(new URL(request.url).search);
        return HttpResponse.json({ items: [], next_cursor: null });
      }),
    );
    await listAudit({ action: 'auth.;x=1&y', cursor: 'a;b c+d#e' });
    await listJobs({ status: 'blocked_license', cursor: 'p;2&z=%' });
    for (const q of queries) {
      expect(q, q).not.toMatch(/;/);
      expect(q.slice(1).split('&').every((pair) => /^[a-z_]+=[A-Za-z0-9._~%+-]*$/.test(pair)), q).toBe(true);
    }
    expect(queries[0]).toContain('action=auth.%3Bx%3D1%26y');
  });
});
