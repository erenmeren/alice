import { http, HttpResponse } from 'msw';
import type { DiscoveredCertificate, DiscoveryScan, DiscoveryScope, DiscoverySettings } from '../api/discovery';
import type { SessionInfo } from '../api/types';
import { discoveredCertificateFixture, discoveredEndpointFixture, discoveryScanFixture, discoveryScopeFixture, discoverySettingsFixture, sessionFor, sessionHandlers } from './fixtures';
import { server } from './server';

export interface DiscoveryWorld {
  session?: SessionInfo;
  scopes?: DiscoveryScope[] | (() => DiscoveryScope[]);
  settings?: DiscoverySettings;
  certificates?: DiscoveredCertificate[];
  scans?: DiscoveryScan[] | (() => DiscoveryScan[]);
  locked?: boolean;
}

export interface Seen {
  method: string;
  path: string;
  search: URLSearchParams;
  body: unknown;
  ifMatch: string | null;
}

// discoveryWorld installs the discovery API for a page test and records every request to it.
export function discoveryWorld(w: DiscoveryWorld = {}): Seen[] {
  const seen: Seen[] = [];
  const scopes = () => (typeof w.scopes === 'function' ? w.scopes() : (w.scopes ?? [discoveryScopeFixture()]));
  const scans = () => (typeof w.scans === 'function' ? w.scans() : (w.scans ?? [discoveryScanFixture()]));
  server.use(
    ...sessionHandlers(w.session ?? sessionFor('admin')),
    http.get('/api/v1/license/status', () =>
      HttpResponse.json(w.locked ? { expired: true, phase: 'locked', banners: [] } : { expired: false, banners: [] }),
    ),
    http.get('/api/v1/discovery/scopes', () => HttpResponse.json({ items: scopes(), next_cursor: null })),
    http.get('/api/v1/discovery/settings', () => HttpResponse.json(w.settings ?? discoverySettingsFixture())),
    http.get('/api/v1/discovery/certificates', () => HttpResponse.json({ items: w.certificates ?? [discoveredCertificateFixture()], next_cursor: null })),
    http.get('/api/v1/discovery/certificates/export', () => new HttpResponse('a,b\n', { headers: { 'Content-Type': 'text/csv' } })),
    http.get('/api/v1/discovery/certificates/:fp', ({ params }) => {
      const c = (w.certificates ?? [discoveredCertificateFixture()]).find((x) => x.fingerprint_sha256 === params.fp) ?? discoveredCertificateFixture();
      return HttpResponse.json({ ...c, endpoints: c.endpoints ?? [discoveredEndpointFixture()], more_endpoints: c.more_endpoints ?? false });
    }),
    http.get('/api/v1/discovery/scans', () => HttpResponse.json({ items: scans(), next_cursor: null })),
    http.post('/api/v1/discovery/scopes/:id/scans', ({ params }) => HttpResponse.json(discoveryScanFixture({ scope_id: String(params.id), state: 'queued', started_at: null, finished_at: null }), { status: 202 })),
    http.post('/api/v1/discovery/scans/:id/cancel', ({ params }) => HttpResponse.json(discoveryScanFixture({ id: String(params.id), state: 'running', cancel_requested: true, finished_at: null }))),
  );
  track(seen);
  return seen;
}

export const requests = (seen: Seen[], method: string, path: string | RegExp) => seen.filter((s) => s.method === method && (typeof path === 'string' ? s.path === path : path.test(s.path)));

const recorded = new WeakSet<Request>();

// track records every discovery request into seen, once each. A test that overrides a discovery route calls it again
// after its server.use, so the recorder sits above the override.
export function track(seen: Seen[]): void {
  server.use(
    http.all('/api/v1/discovery/*', async ({ request }) => {
      if (recorded.has(request)) return;
      recorded.add(request);
      const u = new URL(request.url);
      const text = request.method === 'GET' || request.method === 'DELETE' ? '' : await request.clone().text();
      seen.push({ method: request.method, path: u.pathname, search: u.searchParams, body: text ? JSON.parse(text) : undefined, ifMatch: request.headers.get('If-Match') });
    }),
  );
}
