import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import en from '../locales/en.json';
import tr from '../locales/tr.json';
import { CERTIFICATE_SOURCES, CSR_STATUSES, DEPLOYMENT_STATUSES, KEY_ALGORITHMS, UPLOAD_WARNING_KEYS } from './enums';

// The enums are read from api/openapi.yaml, so a value the API gains without a label fails here.
const spec = readFileSync(resolve(process.cwd(), '../api/openapi.yaml'), 'utf8');

// schemaProp returns the text of one property (its flow-style line plus its block description).
function schemaProp(schema: string, prop: string): string {
  const start = spec.indexOf(`\n    ${schema}:\n`);
  if (start < 0) throw new Error(`schema ${schema} not found`);
  const rest = spec.slice(start + 1);
  const end = rest.slice(1).search(/\n {4}\S/);
  const block = end < 0 ? rest : rest.slice(0, end + 1);
  const at = block.indexOf(`\n        ${prop}:`);
  if (at < 0) throw new Error(`${schema}.${prop} not found`);
  const tail = block.slice(at + 1);
  const next = tail.slice(1).search(/\n {8}\S/);
  return next < 0 ? tail : tail.slice(0, next + 1);
}

function enumOf(schema: string, prop: string): string[] {
  const m = /enum: \[([^\]]*)\]/.exec(schemaProp(schema, prop));
  if (!m) throw new Error(`${schema}.${prop} has no enum`);
  return m[1].split(',').map((v) => v.trim().replace(/^"|"$/g, ''));
}

function knownValues(schema: string, prop: string): string[] {
  const text = schemaProp(schema, prop).replace(/\s+/g, ' ');
  const m = /Known values: ([^;"]*?)(?:;|"|\}|$)/.exec(text);
  if (!m) throw new Error(`${schema}.${prop} has no known values`);
  return m[1].split(',').map((v) => v.trim().replace(/\.$/, ''));
}

function lookup(bundle: unknown, key: string): unknown {
  return key.split('.').reduce<unknown>((o, k) => (o && typeof o === 'object' ? (o as Record<string, unknown>)[k] : undefined), bundle);
}

const bundles = { en, tr } as const;

describe('enum labels cover every value of api/openapi.yaml', () => {
  it('reads sane values from the specification', () => {
    expect(enumOf('CSR', 'status')).toEqual(['pending', 'completed', 'cancelled']);
    expect(knownValues('Certificate', 'source')).toContain('uploaded');
  });

  const cases: { name: string; values: () => string[]; labelKey: (v: string) => string; known: readonly string[] }[] = [
    { name: 'certificate source', values: () => knownValues('Certificate', 'source'), labelKey: (v) => `enum.certificateSource.${v}`, known: CERTIFICATE_SOURCES },
    { name: 'key algorithm', values: () => knownValues('Certificate', 'key_algorithm'), labelKey: (v) => `enum.keyAlgorithm.${v}`, known: KEY_ALGORITHMS },
    { name: 'signing request status', values: () => enumOf('CSR', 'status'), labelKey: (v) => `enum.csrStatus.${v}`, known: CSR_STATUSES },
    { name: 'deployment status', values: () => enumOf('Deployment', 'status'), labelKey: (v) => `enum.deploymentStatus.${v}`, known: DEPLOYMENT_STATUSES },
    { name: 'upload warning', values: () => knownValues('CertificateStored', 'warnings'), labelKey: (v) => UPLOAD_WARNING_KEYS[v] ?? `missing.${v}`, known: Object.keys(UPLOAD_WARNING_KEYS) },
  ];

  describe.each(cases)('$name', ({ values, labelKey, known }) => {
    it.each(['en', 'tr'] as const)('has a %s label for every API value', (lang) => {
      for (const v of values()) {
        expect(typeof lookup(bundles[lang], labelKey(v)), `${lang}: ${labelKey(v)}`).toBe('string');
      }
    });
    it('lists every API value in the code table', () => {
      for (const v of values()) expect(known, v).toContain(v);
    });
  });

  it('has a label for every value in the code tables, in both languages', () => {
    for (const lang of ['en', 'tr'] as const) {
      for (const v of CERTIFICATE_SOURCES) expect(typeof lookup(bundles[lang], `enum.certificateSource.${v}`)).toBe('string');
      for (const v of KEY_ALGORITHMS) expect(typeof lookup(bundles[lang], `enum.keyAlgorithm.${v}`)).toBe('string');
      for (const key of Object.values(UPLOAD_WARNING_KEYS)) expect(typeof lookup(bundles[lang], key)).toBe('string');
    }
  });
});
