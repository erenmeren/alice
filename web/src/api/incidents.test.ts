import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { http, HttpResponse } from 'msw';
import en from '../locales/en.json';
import tr from '../locales/tr.json';
import { goConsts } from '../test/goSources';
import { server } from '../test/server';
import * as inc from './incidents';
import { INCIDENT_LOCATION_STATUSES, INCIDENT_REVOCATIONS, INCIDENT_STATES } from './incidents';
import { REVOCATION_REASONS, SOURCE_CAPABILITIES } from './types';

const spec = readFileSync(resolve(process.cwd(), '../api/openapi.yaml'), 'utf8');

function schemaBlock(schema: string): string {
  const start = spec.indexOf(`\n    ${schema}:\n`);
  if (start < 0) throw new Error(`schema ${schema} not found`);
  const rest = spec.slice(start + 1);
  const end = rest.slice(1).search(/\n {4}\S/);
  return end < 0 ? rest : rest.slice(0, end + 1);
}

function enumIn(block: string, prop: string): string[] {
  const line = block.split('\n').find((l) => l.trimStart().startsWith(`${prop}:`));
  const m = /enum: \[([^\]]*)\]/.exec(line ?? '');
  if (!m) throw new Error(`${prop} has no enum`);
  return m[1].split(',').map((v) => v.trim().replace(/^"|"$/g, '')).filter((v) => v !== '');
}

function lookup(bundle: unknown, key: string): unknown {
  return key.split('.').reduce<unknown>((o, k) => (o && typeof o === 'object' ? (o as Record<string, unknown>)[k] : undefined), bundle);
}

describe('the incident and revocation enums', () => {
  it('match api/openapi.yaml', () => {
    expect([...INCIDENT_STATES]).toEqual(enumIn(schemaBlock('Incident'), 'state'));
    expect([...INCIDENT_REVOCATIONS]).toEqual(enumIn(schemaBlock('Incident'), 'revocation'));
    expect([...INCIDENT_LOCATION_STATUSES]).toEqual(enumIn(schemaBlock('IncidentLocation'), 'status'));
    expect([...REVOCATION_REASONS]).toEqual(enumIn(schemaBlock('RevocationReason').replace('RevocationReason:', 'x:'), 'enum'));
    expect([...SOURCE_CAPABILITIES]).toEqual(enumIn(schemaBlock('SourceCapability').replace('SourceCapability:', 'x:'), 'enum'));
  });

  it('match the Go sources', () => {
    expect([...SOURCE_CAPABILITIES].sort()).toEqual(goConsts('internal/inventory/source_capabilities.go', /^SourceCap/).sort());
    expect([...INCIDENT_STATES].sort()).toEqual(goConsts('internal/inventory/incidents.go', /^Incident(AwaitingReplacement|Ordering|Deploying|Revoking|NeedsAttention|Completed|Closed)$/).sort());
    expect([...INCIDENT_LOCATION_STATUSES].sort()).toEqual(goConsts('internal/inventory/incidents.go', /^IncidentLocation[A-Z]/).sort());
  });

  it('have a label in both languages', () => {
    for (const bundle of [en, tr]) {
      for (const s of INCIDENT_STATES) expect(typeof lookup(bundle, `incidents.states.${s}`), s).toBe('string');
      for (const r of INCIDENT_REVOCATIONS) expect(typeof lookup(bundle, `incidents.revocation.${r}`), r).toBe('string');
      for (const l of INCIDENT_LOCATION_STATUSES) expect(typeof lookup(bundle, `incidents.locationStatus.${l}`), l).toBe('string');
      for (const r of REVOCATION_REASONS) expect(typeof lookup(bundle, `acme.issued.revoke.reasons.${r}`), r).toBe('string');
      for (const c of SOURCE_CAPABILITIES) {
        for (const part of ['names', 'yes', 'no']) expect(typeof lookup(bundle, `certificates.capabilities.${part}.${c}`), c).toBe('string');
      }
    }
  });
});

describe('the incident client', () => {
  it('calls every incident route of the specification with its method, path and body', async () => {
    const seen: { method: string; path: string; body: unknown }[] = [];
    server.use(
      http.all('/api/v1/*', async ({ request }) => {
        const url = new URL(request.url);
        const text = request.method === 'GET' ? '' : await request.text();
        seen.push({ method: request.method, path: url.pathname + url.search, body: text ? JSON.parse(text) : undefined });
        return HttpResponse.json({ items: [] });
      }),
    );
    const calls: [() => Promise<unknown>, string, string, unknown?][] = [
      [() => inc.getCertificateImpact('c1'), 'GET', '/api/v1/certificate-impact/c1'],
      [() => inc.getCertificateCapabilities(), 'GET', '/api/v1/certificates/capabilities'],
      [() => inc.startIncident('c1', 'after_verified'), 'POST', '/api/v1/certificates/c1/incidents', { revoke_mode: 'after_verified' }],
      [() => inc.listIncidents(), 'GET', '/api/v1/incidents'],
      [() => inc.listIncidents({ open: true, certificate_id: 'c1' }), 'GET', '/api/v1/incidents?open=true&certificate_id=c1'],
      [() => inc.listIncidents({ state: 'closed', cursor: 'c2', limit: 50 }), 'GET', '/api/v1/incidents?state=closed&cursor=c2&limit=50'],
      [() => inc.getIncident('i1'), 'GET', '/api/v1/incidents/i1'],
      [() => inc.retryIncident('i1'), 'POST', '/api/v1/incidents/i1/retry'],
      [() => inc.revokeIncidentNow('i1'), 'POST', '/api/v1/incidents/i1/revoke-now'],
      [() => inc.chooseIncidentReplacement('i1', 'c2'), 'POST', '/api/v1/incidents/i1/replacement', { certificate_id: 'c2' }],
      [() => inc.closeIncident('i1'), 'POST', '/api/v1/incidents/i1/close'],
    ];
    for (const [call] of calls) await call();
    expect(seen).toEqual(calls.map(([, method, path, body]) => ({ method, path, body })));
    const specPaths = [...spec.matchAll(/^ {2}(\/api\/v1\/(?:incidents|certificate-impact)[^:]*|\/api\/v1\/certificates\/(?:capabilities|\{id\}\/incidents)):$/gm)].map((m) =>
      m[1].replace(/\{[a-z_]+\}/g, 'X'),
    );
    const called = new Set(seen.map((s) => s.path.split('?')[0].replace(/\/(c1|i1)(?=\/|$)/g, '/X')));
    expect(specPaths.length).toBe(9);
    for (const p of specPaths) expect(called, p).toContain(p);
  });

  it('polls only while Alice works on an incident', () => {
    expect(inc.incidentBusy({ state: 'deploying', finished_at: null })).toBe(true);
    expect(inc.incidentBusy({ state: 'ordering', finished_at: null })).toBe(true);
    expect(inc.incidentBusy({ state: 'needs_attention', finished_at: null })).toBe(false);
    expect(inc.incidentBusy({ state: 'awaiting_replacement', finished_at: null })).toBe(false);
    expect(inc.incidentBusy({ state: 'completed', finished_at: '2026-10-20T00:00:00Z' })).toBe(false);
    expect(inc.incidentOpen({ finished_at: null })).toBe(true);
  });
});
