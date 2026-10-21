import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { http, HttpResponse } from 'msw';
import en from '../locales/en.json';
import tr from '../locales/tr.json';
import { driftedObservationFixture, observationFixture } from '../test/fixtures';
import { goConsts } from '../test/goSources';
import { server } from '../test/server';
import { DRIFT_MODE_SETTINGS, DRIFT_MODES, driftSummary, healthKey, LOCATION_HEALTHS, modeKey, observedInstead, repairDrift, setDriftMode } from './drift';

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

describe('the drift enums (R52)', () => {
  it('match api/openapi.yaml', () => {
    expect([...LOCATION_HEALTHS]).toEqual(enumIn(schemaBlock('LocationObservation'), 'health'));
    expect([...DRIFT_MODES]).toEqual(enumIn(schemaBlock('LocationObservation'), 'mode'));
    expect([...DRIFT_MODE_SETTINGS]).toEqual(enumIn(schemaBlock('DriftModeInput'), 'mode'));
  });

  it('match the Go sources', () => {
    expect([...LOCATION_HEALTHS].sort()).toEqual(goConsts('internal/inventory/drift.go', /^Health[A-Z]/).sort());
    expect([...DRIFT_MODE_SETTINGS].sort()).toEqual(goConsts('internal/inventory/drift.go', /^DriftMode[A-Z]/).sort());
  });

  it('have a label in both languages', () => {
    for (const bundle of [en, tr]) {
      for (const h of LOCATION_HEALTHS) expect(typeof lookup(bundle, healthKey(h)), h).toBe('string');
      for (const m of DRIFT_MODE_SETTINGS) expect(typeof lookup(bundle, modeKey(m)), m).toBe('string');
      for (const b of ['flapping', 'repair_failing']) expect(typeof lookup(bundle, `drift.backoff.${b}`), b).toBe('string');
    }
    expect(healthKey('nonsense')).toBe('enum.unknown');
  });
});

describe('the drift client', () => {
  it('calls the two routes of the specification', async () => {
    const seen: { method: string; path: string; body: unknown }[] = [];
    server.use(
      http.all('/api/v1/locations/*', async ({ request }) => {
        const text = await request.text();
        seen.push({ method: request.method, path: new URL(request.url).pathname, body: text ? JSON.parse(text) : undefined });
        return HttpResponse.json({ deployments: [] });
      }),
    );
    await setDriftMode('l1', 'approve');
    await repairDrift('l1');
    expect(seen).toEqual([
      { method: 'PUT', path: '/api/v1/locations/l1/drift-mode', body: { mode: 'approve' } },
      { method: 'POST', path: '/api/v1/locations/l1/actions/repair', body: undefined },
    ]);
    expect(spec).toContain('  /api/v1/locations/{id}/drift-mode:');
    expect(spec).toContain('  /api/v1/locations/{id}/actions/repair:');
  });
});

describe('the summary of the observed places', () => {
  it('counts in sync, unreachable, drifted and the rest, and finds the soonest end of what a drifted place serves', () => {
    const s = driftSummary([
      observationFixture(),
      observationFixture(),
      observationFixture({ health: 'unreachable' }),
      driftedObservationFixture(),
      driftedObservationFixture({ tls: null, file: { certificate_id: null, fingerprint: 'ab'.repeat(32), not_after: '2026-10-20T20:00:00Z', observed_at: '2026-10-20T12:00:00Z', changed_outside_at: null } }),
      observationFixture({ health: 'stale' }),
      observationFixture({ health: 'unmanaged' }),
      null,
    ]);
    expect(s).toEqual({ total: 6, inSync: 2, unreachable: 1, drifted: 2, other: 1, driftedExpires: '2026-10-20T20:00:00Z' });
  });

  it('names the website before the file as what a drifted place serves instead', () => {
    const o = driftedObservationFixture();
    expect(observedInstead(o)).toBe(o.tls);
    expect(observedInstead(observationFixture())).toBeNull();
  });
});
