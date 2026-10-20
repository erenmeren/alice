import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { http, HttpResponse } from 'msw';
import en from '../locales/en.json';
import tr from '../locales/tr.json';
import { server } from '../test/server';
import * as acme from './acme';
import {
  ACME_ACCOUNT_STATES,
  ACME_BINDING_STATES,
  ACME_CERTIFICATE_STATES,
  ACME_CHALLENGES,
  ACME_KEY_TYPES,
  ACME_ORDER_STATES,
  ACME_PRESETS,
  ACME_RENEW_AT_SOURCES,
  ACME_REPLACES_OUTCOMES,
  HOOK_POLL_MAX,
  HOOK_POLL_MIN,
  HOOK_SECRET_MAX,
  HOOK_SECRET_MIN,
  HOOK_TOTAL_MAX,
  HOOK_WAIT_MAX,
  PRESET_DIRECTORIES,
  accountStateKey,
  bindingStateKey,
  certificateStateKey,
  challengeKey,
  directoryHost,
  keyTypeKey,
  orderStateKey,
  presetKey,
  suffixProblem,
} from './acme';
import * as keys from './queryKeys';

const spec = readFileSync(resolve(process.cwd(), '../api/openapi.yaml'), 'utf8');

// schemaBlock is the text of one schema of components.schemas.
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

describe('the ACME enums', () => {
  it('match api/openapi.yaml', () => {
    expect([...ACME_PRESETS]).toEqual(enumOf('ACMEProviderCreate', 'preset'));
    expect([...ACME_ACCOUNT_STATES]).toEqual(enumOf('ACMEAccount', 'state'));
    expect([...ACME_CERTIFICATE_STATES]).toEqual(enumOf('ACMECertificate', 'state'));
    expect([...ACME_CHALLENGES]).toEqual(enumOf('ACMECertificate', 'challenge'));
    expect([...ACME_KEY_TYPES]).toEqual(enumOf('ACMECertificateCreate', 'key_type'));
    expect([...ACME_ORDER_STATES]).toEqual(enumOf('ACMEOrder', 'state'));
    expect([...ACME_BINDING_STATES]).toEqual(enumOf('ACMEBinding', 'state'));
    expect([...ACME_RENEW_AT_SOURCES]).toEqual(enumOf('ACMECertificate', 'renew_at_source'));
    expect([...ACME_REPLACES_OUTCOMES]).toEqual(enumOf('ACMEOrder', 'replaces_outcome'));
  });

  it('match the bounds of a DNS hook in api/openapi.yaml', () => {
    const hook = schemaBlock('ACMEHookCreate');
    expect(hook).toContain(`propagation_wait_seconds: { type: integer, minimum: 0, maximum: ${HOOK_WAIT_MAX}`);
    expect(hook).toContain(`poll_timeout_seconds: { type: integer, minimum: ${HOOK_POLL_MIN}, maximum: ${HOOK_POLL_MAX}`);
    expect(hook).toContain(`minLength: ${HOOK_SECRET_MIN}, maxLength: ${HOOK_SECRET_MAX}`);
    expect(spec).toContain(`are at most ${HOOK_TOTAL_MAX}`);
  });

  it.each([
    ['en', en],
    ['tr', tr],
  ] as const)('have a label for every value in %s, and a neutral one for an unknown value', (_lang, bundle) => {
    const groups: [readonly string[], (v: string) => string][] = [
      [ACME_PRESETS, presetKey],
      [ACME_ACCOUNT_STATES, accountStateKey],
      [ACME_CERTIFICATE_STATES, certificateStateKey],
      [ACME_CHALLENGES, challengeKey],
      [ACME_KEY_TYPES, keyTypeKey],
      [ACME_ORDER_STATES, orderStateKey],
      [ACME_BINDING_STATES, bindingStateKey],
    ];
    for (const [values, keyOf] of groups) {
      for (const v of values) expect(typeof lookup(bundle, keyOf(v)), v).toBe('string');
      expect(keyOf('brand_new')).toBe('enum.unknown');
    }
  });

  it('pre-fill the documented directory addresses of the public CAs, all https', () => {
    expect(PRESET_DIRECTORIES).toEqual({
      letsencrypt: 'https://acme-v02.api.letsencrypt.org/directory',
      letsencrypt_staging: 'https://acme-staging-v02.api.letsencrypt.org/directory',
      zerossl: 'https://acme.zerossl.com/v2/DV90',
    });
  });
});

describe('suffixProblem', () => {
  it.each([
    ['example.com', ''],
    ['.example.com', ''],
    [' Corp.Example.COM ', ''],
    ['xn--bcher-kva.example', ''],
    ['a-b.c-d.example', ''],
    ['', 'acme.suffix.empty'],
    ['.', 'acme.suffix.empty'],
    ['com', 'acme.suffix.twoLabels'],
    ['.com', 'acme.suffix.twoLabels'],
    ['-bad.example.com', 'acme.suffix.invalid'],
    ['bad-.example.com', 'acme.suffix.invalid'],
    ['exa mple.com', 'acme.suffix.invalid'],
    ['*.example.com', 'acme.suffix.invalid'],
    ['example..com', 'acme.suffix.invalid'],
    [`${'a'.repeat(64)}.com`, 'acme.suffix.invalid'],
    [`${'a.'.repeat(127)}com`, 'acme.suffix.tooLong'],
  ])('%j -> %j', (value, problem) => {
    expect(suffixProblem(value)).toBe(problem);
  });

  it('finds an entry that is already in the list, whatever its letter case', () => {
    expect(suffixProblem('Example.com', ['example.com'])).toBe('acme.suffix.duplicate');
    expect(suffixProblem('.example.com', ['example.com'])).toBe('');
  });
});

it('shows the host of an address, or the address itself when it is not one', () => {
  expect(directoryHost('https://acme-v02.api.letsencrypt.org/directory')).toBe('acme-v02.api.letsencrypt.org');
  expect(directoryHost('https://ca.example.com:8443/acme')).toBe('ca.example.com:8443');
  expect(directoryHost('not a url')).toBe('not a url');
});

describe('the ACME client', () => {
  // Every request the client makes: method, path with query and body, recorded by one catch-all handler.
  function record() {
    const seen: { method: string; path: string; body: unknown }[] = [];
    server.use(
      http.all('/api/v1/acme/*', async ({ request }) => {
        const url = new URL(request.url);
        const text = request.method === 'GET' || request.method === 'DELETE' ? '' : await request.text();
        seen.push({ method: request.method, path: url.pathname + url.search, body: text ? JSON.parse(text) : undefined });
        return request.method === 'DELETE' ? new HttpResponse(null, { status: 204 }) : HttpResponse.json({ items: [], next_cursor: null });
      }),
    );
    return seen;
  }

  it('calls every ACME route of the specification with its method, path and body', async () => {
    const seen = record();
    const id = 'p1';
    const calls: [() => Promise<unknown>, string, string, unknown?][] = [
      [() => acme.listACMEProviders(), 'GET', '/api/v1/acme/providers'],
      [() => acme.getACMEProvider(id), 'GET', '/api/v1/acme/providers/p1'],
      [() => acme.createACMEProvider({ name: 'n', directory_url: 'https://d' }), 'POST', '/api/v1/acme/providers', { name: 'n', directory_url: 'https://d' }],
      [() => acme.updateACMEProvider(id, { remove_eab: true }), 'PATCH', '/api/v1/acme/providers/p1', { remove_eab: true }],
      [() => acme.deleteACMEProvider(id), 'DELETE', '/api/v1/acme/providers/p1'],
      [() => acme.previewACMEProvider(id), 'POST', '/api/v1/acme/providers/p1/preview'],
      [() => acme.registerACMEAccount(id, { tos_accepted: true, accepted_terms_url: 'https://t' }), 'POST', '/api/v1/acme/providers/p1/account', { tos_accepted: true, accepted_terms_url: 'https://t' }],
      [() => acme.rolloverACMEAccount('a1'), 'POST', '/api/v1/acme/accounts/a1/rollover'],
      [() => acme.recoverACMERollover('a1'), 'POST', '/api/v1/acme/accounts/a1/rollover/recover'],
      [() => acme.deactivateACMEAccount('a1'), 'POST', '/api/v1/acme/accounts/a1/deactivate'],
      [() => acme.listACMEHooks(), 'GET', '/api/v1/acme/hooks'],
      [() => acme.getACMEHook('h1'), 'GET', '/api/v1/acme/hooks/h1'],
      [() => acme.createACMEHook({ name: 'h', url: 'https://h', secret: 's' }), 'POST', '/api/v1/acme/hooks', { name: 'h', url: 'https://h', secret: 's' }],
      [() => acme.updateACMEHook('h1', { name: 'x' }), 'PATCH', '/api/v1/acme/hooks/h1', { name: 'x' }],
      [() => acme.deleteACMEHook('h1'), 'DELETE', '/api/v1/acme/hooks/h1'],
      [() => acme.listACMECertificates(), 'GET', '/api/v1/acme/certificates'],
      [() => acme.listACMECertificates({ state: 'active', provider_id: 'p1', q: '', limit: 200 }), 'GET', '/api/v1/acme/certificates?state=active&provider_id=p1&limit=200'],
      [() => acme.getACMECertificate('c1'), 'GET', '/api/v1/acme/certificates/c1'],
      [() => acme.createACMECertificate({ provider_id: 'p1', names: ['a.example'], challenge: 'dns01', hook_id: 'h1' }), 'POST', '/api/v1/acme/certificates', { provider_id: 'p1', names: ['a.example'], challenge: 'dns01', hook_id: 'h1' }],
      [() => acme.updateACMECertificate('c1', { auto_renew: false }), 'PATCH', '/api/v1/acme/certificates/c1', { auto_renew: false }],
      [() => acme.deleteACMECertificate('c1'), 'DELETE', '/api/v1/acme/certificates/c1'],
      [() => acme.orderACMECertificate('c1'), 'POST', '/api/v1/acme/certificates/c1/order'],
      [() => acme.testACMECertificate('c1'), 'POST', '/api/v1/acme/certificates/c1/test'],
      [() => acme.listACMEOrders('c1'), 'GET', '/api/v1/acme/certificates/c1/orders'],
      [() => acme.listACMEOrders('c1', 5), 'GET', '/api/v1/acme/certificates/c1/orders?limit=5'],
      [() => acme.rearmACMECertificate('c1'), 'POST', '/api/v1/acme/certificates/c1/rearm'],
      [() => acme.releaseACMEHold('c1'), 'POST', '/api/v1/acme/certificates/c1/release-hold'],
      [() => acme.listACMEBindings('c1'), 'GET', '/api/v1/acme/certificates/c1/bindings'],
      [() => acme.putACMEBinding('c1', 'l1', true), 'PUT', '/api/v1/acme/certificates/c1/bindings/l1', { auto_deploy: true }],
      [() => acme.deleteACMEBinding('c1', 'l1'), 'DELETE', '/api/v1/acme/certificates/c1/bindings/l1'],
      [() => acme.deployACMECertificate('c1'), 'POST', '/api/v1/acme/certificates/c1/deploy', {}],
      [() => acme.deployACMECertificate('c1', { location_ids: ['l1'], confirm_incomplete_chain: true }), 'POST', '/api/v1/acme/certificates/c1/deploy', { location_ids: ['l1'], confirm_incomplete_chain: true }],
      [() => acme.revokeACMECertificate('c1', 'superseded'), 'POST', '/api/v1/acme/certificates/c1/revoke', { reason: 'superseded' }],
      [() => acme.revokeACMECertificate('c1', 'keyCompromise', 'l1'), 'POST', '/api/v1/acme/certificates/c1/revoke', { reason: 'keyCompromise', certificate_id: 'l1' }],
    ];
    for (const [call] of calls) await call();
    expect(seen).toEqual(calls.map(([, method, path, body]) => ({ method, path, body })));
    // Every path of the specification under /acme is called.
    const specPaths = [...spec.matchAll(/^ {2}(\/api\/v1\/acme\/[^:]+):$/gm)].map((m) => m[1].replace(/\{[a-z_]+\}/g, 'X'));
    const called = new Set(seen.map((s) => s.path.split('?')[0].replace(/\/(p1|a1|h1|c1|l1)(?=\/|$)/g, '/X')));
    expect(specPaths.length).toBeGreaterThan(15);
    for (const p of specPaths) expect(called, p).toContain(p);
  });

  it('escapes the ids it puts into a path', async () => {
    const seen = record();
    await acme.getACMEProvider('a/b');
    expect(seen[0].path).toBe('/api/v1/acme/providers/a%2Fb');
  });
});

describe('the ACME query keys', () => {
  it('put every ACME entry under one prefix, and the lists apart from any id', () => {
    for (const k of [keys.ACME_PROVIDERS_KEY, keys.ACME_PROVIDER_LIST_KEY, keys.acmeProviderKey('p'), keys.ACME_HOOKS_KEY, keys.ACME_HOOK_LIST_KEY, keys.acmeCertificateKey('c'), keys.acmeOrdersKey('c'), keys.acmeBindingsKey('c'), keys.acmeCertificateListKey({})])
      expect(k.slice(0, 1)).toEqual([...keys.ACME_KEY]);
    expect(keys.acmeProviderKey('p').slice(0, 2)).toEqual([...keys.ACME_PROVIDERS_KEY]);
    expect(keys.ACME_PROVIDER_LIST_KEY.slice(0, 2)).toEqual([...keys.ACME_PROVIDERS_KEY]);
    expect(keys.acmeOrdersKey('c').slice(0, 3)).toEqual([...keys.acmeCertificateKey('c')]);
    expect(keys.acmeCertificateListKey({ provider_id: 'p' })).not.toEqual(keys.acmeCertificateListKey({ provider_id: 'q' }));
    // The preview sits under the provider but no providers invalidation refreshes it (it contacts the CA).
    expect(keys.acmePreviewKey('p').slice(0, 3)).toEqual([...keys.acmeProviderKey('p')]);
    expect(keys.notACMEPreview({ queryKey: keys.acmePreviewKey('p') })).toBe(false);
    expect(keys.notACMEPreview({ queryKey: keys.acmeProviderKey('p') })).toBe(true);
    expect(keys.notACMEPreview({ queryKey: keys.ACME_PROVIDER_LIST_KEY })).toBe(true);
  });
});
