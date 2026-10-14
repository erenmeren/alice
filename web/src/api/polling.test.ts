import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { http, HttpResponse } from 'msw';
import { deploymentDetailFixture, jobFixture, statusWith, targetFixture } from '../test/fixtures';
import { server } from '../test/server';
import { watchDeployments } from './deployments';
import { getDeployment, getLicenseStatus, getTarget, listAudit, listJobs } from './endpoints';
import { waitForJob } from './jobs';
import { getKVImport } from './keyvault';
import { getACMECertificate, listACMEOrders } from './acme';
import { listAllDiscoveryScopes, listDiscoveryScans } from './discovery';

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
      'components/AccessCheckPanel.tsx',
      'components/AddServerModal.tsx',
      // the dashboard summary (getDashboardSummary, a GET), shared with pages/DashboardPage.tsx
      'components/BackupBanner.tsx',
      'components/BindingPanel.tsx',
      'components/DeployDialog.tsx',
      'components/DeployKeyDialog.tsx',
      'components/ImportHistory.tsx',
      'components/ImportToKeyVaultDialog.tsx',
      'components/KVDeployDialog.tsx',
      'components/NotificationsBanner.tsx',
      'components/RemoveKeyDialog.tsx',
      // the scans while one is queued or running (listDiscoveryScans: a GET)
      'components/discovery/ScansTab.tsx',
      // an issued certificate and its orders while an order runs (getACMECertificate, listACMEOrders: GETs)
      'pages/AcmeCertificatePage.tsx',
      'pages/DashboardPage.tsx',
      'pages/DeploymentDetailPage.tsx',
      // the scan scopes while a scan is queued or running (listAllDiscoveryScopes: GETs)
      'pages/DiscoveryPage.tsx',
      'pages/KeyVaultDetailPage.tsx',
      'pages/RotationRunPage.tsx',
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
      http.get('/api/v1/targets/:id/kv/imports/:import', () => HttpResponse.json({})),
      http.get('/api/v1/acme/certificates/:id', () => HttpResponse.json({})),
      http.get('/api/v1/acme/certificates/:id/orders', () => HttpResponse.json({ items: [] })),
      http.get('/api/v1/discovery/scopes', () => HttpResponse.json({ items: [], next_cursor: null })),
      http.get('/api/v1/discovery/scans', () => HttpResponse.json({ items: [], next_cursor: null })),
    );
    await getLicenseStatus();
    await getLicenseStatus({ keepalive: true });
    await getTarget(targetFixture.id);
    await getDeployment('d1');
    await waitForJob('j1', { intervalMs: 1 });
    await getKVImport('v1', 'i1');
    await watchDeployments(['d1', 'd2'], { intervalMs: 1 });
    await getACMECertificate('a1');
    await listACMEOrders('a1', 20);
    await listAllDiscoveryScopes();
    await listDiscoveryScans();
    expect(methods.length).toBeGreaterThanOrEqual(10);
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
