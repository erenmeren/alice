import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { http, HttpResponse } from 'msw';
import en from '../locales/en.json';
import tr from '../locales/tr.json';
import commonEn from '../../../locales/common/en.json';
import { errorResponse } from '../test/fixtures';
import { server } from '../test/server';
import { ApiError } from './client';
import * as d from './discovery';
import * as keys from './queryKeys';

const spec = readFileSync(resolve(process.cwd(), '../api/openapi.yaml'), 'utf8');

function schemaBlock(schema: string): string {
  const start = spec.indexOf(`\n    ${schema}:\n`);
  if (start < 0) throw new Error(`schema ${schema} not found`);
  const rest = spec.slice(start + 1);
  const end = rest.slice(1).search(/\n {4}\S/);
  return end < 0 ? rest : rest.slice(0, end + 1);
}

function enumOf(schema: string, prop: string): string[] {
  const line = schemaBlock(schema)
    .split('\n')
    .find((l) => l.trimStart().startsWith(`${prop}:`));
  const m = /enum: \[([^\]]*)\]/.exec(line ?? '');
  if (!m) throw new Error(`${schema}.${prop} has no enum`);
  return m[1].split(',').map((v) => v.trim().replace(/^"|"$/g, '')).filter((v) => v !== '');
}

function lookup(bundle: unknown, key: string): unknown {
  return key.split('.').reduce<unknown>((o, k) => (o && typeof o === 'object' ? (o as Record<string, unknown>)[k] : undefined), bundle);
}

describe('the discovery enums and limits', () => {
  it('match api/openapi.yaml', () => {
    expect([...d.SCAN_STATES]).toEqual(enumOf('DiscoveryScan', 'state'));
    expect([...d.SCAN_TRIGGERS]).toEqual(enumOf('DiscoveryScan', 'trigger'));
    expect([...d.DISCOVERED_STATUSES]).toEqual(enumOf('DiscoveredCertificate', 'status'));
    expect([...d.ENDPOINT_STATES]).toEqual(enumOf('DiscoveredEndpoint', 'state'));
    expect([...d.ENDPOINT_ERRORS]).toEqual(enumOf('DiscoveredEndpoint', 'last_error_code'));
    expect(schemaBlock('DiscoveredEndpoint')).toContain('last_error_code: { type: string, enum: ["", refused');
    expect(spec).toContain(`{ name: status, in: query, schema: { type: string, enum: [${d.STATUS_FILTERS.join(', ')}] } }`);
  });

  it('match the bounds of a scope and of the settings', () => {
    const create = schemaBlock('DiscoveryScopeCreate');
    expect(create).toContain(`name: { type: string, maxLength: ${d.MAX_SCOPE_NAME}`);
    expect(create).toContain(`maxItems: ${d.MAX_ENTRIES}`);
    expect(create).toContain(`ports: { type: array, maxItems: ${d.MAX_PORTS}`);
    expect(create).toContain(`sni_names: { type: array, maxItems: ${d.MAX_SNI_NAMES}`);
    expect(create).toContain(`exclusions: { type: array, maxItems: ${d.MAX_EXCLUSIONS}`);
    expect(create).toContain(`schedule_hours: { type: integer, minimum: 0, maximum: ${d.MAX_SCHEDULE_HOURS}`);
    expect(create).toContain(`rate_per_sec: { type: integer, minimum: 0, maximum: ${d.MAX_RATE}, description: "New connections per second; 0: ${d.DEFAULT_RATE}"`);
    expect(create).toContain(`concurrency: { type: integer, minimum: 0, maximum: ${d.MAX_CONCURRENCY}, description: "Workers of a scan; 0: ${d.DEFAULT_CONCURRENCY}"`);
    expect(schemaBlock('DiscoverySettingsInput')).toContain(`retention_days: { type: integer, minimum: ${d.MIN_RETENTION_DAYS}, maximum: ${d.MAX_RETENTION_DAYS}, examples: [${d.DEFAULT_RETENTION_DAYS}]`);
    // The size limits and the two-scan cap are in the error texts the person reads.
    expect(commonEn.errors.discovery.scope_too_large.cause).toContain(d.MAX_ADDRESSES.toLocaleString('en-US'));
    expect(commonEn.errors.discovery.scope_too_large.cause).toContain(d.MAX_ENDPOINTS.toLocaleString('en-US'));
    expect(commonEn.errors.discovery.too_many_scans.cause).toContain('two scans');
    expect(d.MAX_ACTIVE_SCANS).toBe(2);
  });

  it.each([
    ['en', en],
    ['tr', tr],
  ])('have a %s label for every value', (_lang, bundle) => {
    const all = [
      ...d.SCAN_STATES.map(d.scanStateKey),
      ...d.SCAN_TRIGGERS.map(d.scanTriggerKey),
      ...d.DISCOVERED_STATUSES.map(d.statusKey),
      ...d.ENDPOINT_STATES.map(d.endpointStateKey),
      ...d.ENDPOINT_ERRORS.map(d.endpointErrorKey),
    ];
    expect(all.filter((k) => typeof lookup(bundle, k) !== 'string')).toEqual([]);
  });

  it('gives a value from a newer server the neutral label', () => {
    expect(d.scanStateKey('paused')).toBe('enum.unknown');
    expect(d.endpointErrorKey('')).toBe('enum.unknown');
    expect(d.statusKey('unmanaged')).toBe('discovery.enum.status.unmanaged');
  });
});

describe('the discovery helpers', () => {
  it('writes an endpoint as address:port, an IPv6 address in brackets', () => {
    expect(d.endpointAddress({ address: '10.0.0.5', port: 443 })).toBe('10.0.0.5:443');
    expect(d.endpointAddress({ address: '2001:db8::1', port: 8443 })).toBe('[2001:db8::1]:8443');
  });

  it('splits a text box into entries by line and comma', () => {
    expect(d.lines(' 10.0.0.0/24 \n\n intranet.example, 10.0.1.5 \r\n')).toEqual(['10.0.0.0/24', 'intranet.example', '10.0.1.5']);
    expect(d.lines('   ')).toEqual([]);
  });

  it('reads ports and names the first problem', () => {
    expect(d.parsePorts('443, 8443 443\n636')).toEqual({ ports: [443, 8443, 636], problem: '' });
    expect(d.parsePorts('')).toEqual({ ports: [], problem: 'discovery.scope.portsRequired' });
    expect(d.parsePorts('443, https')).toEqual({ ports: [], problem: 'discovery.scope.portInvalid' });
    expect(d.parsePorts('0')).toEqual({ ports: [], problem: 'discovery.scope.portInvalid' });
    expect(d.parsePorts('65536')).toEqual({ ports: [], problem: 'discovery.scope.portInvalid' });
    expect(d.parsePorts(Array.from({ length: 17 }, (_, i) => 1000 + i).join(','))).toEqual({ ports: [], problem: 'discovery.scope.portsTooMany' });
    for (const k of ['portsRequired', 'portInvalid', 'portsTooMany']) {
      expect(typeof lookup(en, `discovery.scope.${k}`)).toBe('string');
      expect(typeof lookup(tr, `discovery.scope.${k}`)).toBe('string');
    }
  });

  it('finds the element a refusal names, never a value', () => {
    const e = (reason: string, params: Record<string, string>) =>
      new ApiError(422, { code: 'ALC-DSC-0003', reason, message_key: `errors.${reason}`, message: '', params, details: [], request_id: 'r', retryable: false });
    expect(d.elementProblem(e('discovery.entry_invalid', { field: 'entries', index: '2' }))).toEqual({ field: 'entries', index: 2, reason: 'discovery.entry_invalid' });
    expect(d.elementProblem(e('discovery.name_unresolved', { field: 'entries', index: '0' }))).toEqual({ field: 'entries', index: 0, reason: 'discovery.name_unresolved' });
    expect(d.elementProblem(e('discovery.scope_too_large', { field: 'entries' }))).toEqual({ field: 'entries', index: null, reason: 'discovery.scope_too_large' });
    expect(d.elementProblem(e('discovery.entry_invalid', { field: 'ports', index: 'x' }))?.index).toBeNull();
    expect(d.elementProblem(e('discovery.entry_invalid', {}))).toEqual({ field: '', index: null, reason: 'discovery.entry_invalid' });
    expect(d.elementProblem(e('discovery.name_taken', {}))).toBeNull();
    expect(d.elementProblem(new Error('x'))).toBeNull();
    expect(d.isActiveScan('queued') && d.isActiveScan('running') && !d.isActiveScan('done')).toBe(true);
  });

  it('follows cursors to the end and stops at a repeated cursor', async () => {
    const pages: Record<string, d.Page<number>> = { '': { items: [1, 2], next_cursor: 'a' }, a: { items: [3], next_cursor: 'b' }, b: { items: [4], next_cursor: 'a' } };
    const seen: (string | null)[] = [];
    const all = await d.allPages((c) => {
      seen.push(c);
      return Promise.resolve(pages[c ?? '']);
    });
    expect(all).toEqual({ items: [1, 2, 3, 4], next_cursor: null });
    expect(seen).toEqual([null, 'a', 'b']);
    expect(d.nextCursor({ items: [], next_cursor: 'z' })).toBe('z');
  });
});

describe('the discovery client', () => {
  function capture() {
    const seen: { method: string; path: string; ifMatch: string | null; body: unknown }[] = [];
    server.use(
      http.all('/api/v1/discovery/*', async ({ request }) => {
        const u = new URL(request.url);
        const text = request.method === 'GET' || request.method === 'DELETE' ? '' : await request.text();
        seen.push({ method: request.method, path: u.pathname + u.search, ifMatch: request.headers.get('If-Match'), body: text ? JSON.parse(text) : undefined });
        if (u.pathname.endsWith('/export')) return new HttpResponse('a,b\n', { headers: { 'Content-Type': 'text/csv' } });
        if (request.method === 'DELETE') return new HttpResponse(null, { status: 204 });
        return HttpResponse.json({ items: [], next_cursor: null });
      }),
    );
    return seen;
  }

  it('reads and writes scopes at their addresses', async () => {
    const seen = capture();
    await d.listDiscoveryScopes({ cursor: 'c 1', limit: 10 });
    await d.listAllDiscoveryScopes();
    await d.getDiscoveryScope('s/1');
    await d.createDiscoveryScope({ name: 'Lab', entries: ['10.0.0.0/24'], ports: [443] });
    await d.updateDiscoveryScope('s1', { enabled: false }, 4);
    await d.updateDiscoveryScope('s1', { name: 'x' });
    await d.deleteDiscoveryScope('s1', 5);
    await d.previewDiscoveryScope({ entries: ['10.0.0.1'], ports: [443] });
    expect(seen.map((s) => `${s.method} ${s.path} ${s.ifMatch ?? ''}`.trim())).toEqual([
      'GET /api/v1/discovery/scopes?cursor=c+1&limit=10',
      'GET /api/v1/discovery/scopes?limit=200',
      'GET /api/v1/discovery/scopes/s%2F1',
      'POST /api/v1/discovery/scopes',
      'PATCH /api/v1/discovery/scopes/s1 "4"',
      'PATCH /api/v1/discovery/scopes/s1',
      'DELETE /api/v1/discovery/scopes/s1 "5"',
      'POST /api/v1/discovery/scopes/preview',
    ]);
    expect(seen[3].body).toEqual({ name: 'Lab', entries: ['10.0.0.0/24'], ports: [443] });
    expect(seen[4].body).toEqual({ enabled: false });
  });

  it('starts, lists and cancels scans by a scope id only', async () => {
    const seen = capture();
    await d.startDiscoveryScan('s1');
    await d.listDiscoveryScans({ scope_id: 's1', state: 'running', cursor: 'x', limit: 50 });
    await d.listDiscoveryScans();
    await d.getDiscoveryScan('n1');
    await d.cancelDiscoveryScan('n1');
    expect(seen.map((s) => `${s.method} ${s.path}`)).toEqual([
      'POST /api/v1/discovery/scopes/s1/scans',
      'GET /api/v1/discovery/scans?scope_id=s1&state=running&cursor=x&limit=50',
      'GET /api/v1/discovery/scans',
      'GET /api/v1/discovery/scans/n1',
      'POST /api/v1/discovery/scans/n1/cancel',
    ]);
    expect(seen[0].body).toBeUndefined();
  });

  it('sends the certificate filters to the list and the same ones to the export', async () => {
    const seen = capture();
    const filters: d.CertificateQuery = { status: 'unmanaged', expiring_within_days: 30, self_signed: true, current: true, q: ' web ', scope_id: 's1' };
    await d.listDiscoveredCertificates({ ...filters, cursor: 'k', limit: 50 });
    await d.listDiscoveredCertificates({ status: 'all', expired: true, current: false });
    const blob = await d.exportDiscoveredCertificates(filters);
    await d.getDiscoveredCertificate('ab'.repeat(32));
    await d.listDiscoveredEndpoints({ scope_id: 's1', fingerprint: 'cd', cursor: 'e', limit: 20 });
    await d.getDiscoverySettings();
    await d.putDiscoverySettings({ allowed_networks: ['10.0.0.0/16'], global_exclusions: [], retention_days: 90 });
    await d.getDiscoverySummary();
    expect(seen.map((s) => `${s.method} ${s.path}`)).toEqual([
      'GET /api/v1/discovery/certificates?status=unmanaged&expiring_within_days=30&self_signed=true&current=true&q=web&scope_id=s1&cursor=k&limit=50',
      'GET /api/v1/discovery/certificates?expired=true',
      'GET /api/v1/discovery/certificates/export?status=unmanaged&expiring_within_days=30&self_signed=true&current=true&q=web&scope_id=s1',
      `GET /api/v1/discovery/certificates/${'ab'.repeat(32)}`,
      'GET /api/v1/discovery/endpoints?scope_id=s1&fingerprint=cd&cursor=e&limit=20',
      'GET /api/v1/discovery/settings',
      'PUT /api/v1/discovery/settings',
      'GET /api/v1/discovery/summary',
    ]);
    expect(blob).toBeInstanceOf(Blob);
    expect(d.discoveredCertificatesExportPath()).toBe('/api/v1/discovery/certificates/export');
  });

  it('turns a refusal into an ApiError with the ALC-DSC code', async () => {
    server.use(http.post('/api/v1/discovery/scopes/:id/scans', () => errorResponse(409, 'ALC-DSC-0007', 'discovery.too_many_scans', { retryable: true })));
    const err = await d.startDiscoveryScan('s1').catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).code).toBe('ALC-DSC-0007');
    expect((err as ApiError).messageKey).toBe('errors.discovery.too_many_scans');
  });
});

describe('the discovery query keys', () => {
  it('sit under one prefix, and no id addresses a list', () => {
    for (const k of [keys.DISCOVERY_SUMMARY_KEY, keys.DISCOVERY_SETTINGS_KEY, keys.DISCOVERY_SCOPE_LIST_KEY, keys.discoveryScanListKey({}), keys.discoveredCertificateListKey({}), keys.discoveredCertificateKey('ab')])
      expect(k[0]).toBe(keys.DISCOVERY_KEY[0]);
    expect(keys.discoveredCertificateKey('list')).not.toEqual(keys.discoveredCertificateListKey({}));
    expect(keys.DISCOVERY_SCOPE_LIST_KEY.slice(0, 2)).toEqual([...keys.DISCOVERY_SCOPES_KEY]);
    expect(keys.discoveryScanListKey({}).slice(0, 2)).toEqual([...keys.DISCOVERY_SCANS_KEY]);
    expect(keys.discoveredCertificateKey('ab').slice(0, 2)).toEqual([...keys.DISCOVERY_CERTIFICATES_KEY]);
  });
});
