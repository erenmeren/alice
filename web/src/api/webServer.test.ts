import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { can } from './capabilities';
import { WEB_SERVER_TYPES, isServerType, isWebServer, webServerState } from './webServer';
import { nginxTargetFixture, nginxTargetWith, webServerFacts, windowsTargetFixture } from '../test/fixtures';

describe('isWebServer / isServerType', () => {
  it('knows the web-server types', () => {
    expect(isWebServer('nginx')).toBe(true);
    expect(isWebServer('linux')).toBe(false);
    expect(isWebServer('azure_key_vault')).toBe(false);
    expect(isWebServer('')).toBe(false);
  });
  it('a server is Linux or a web server', () => {
    expect(isServerType('linux')).toBe(true);
    expect(isServerType('nginx')).toBe(true);
    expect(isServerType('azure_key_vault')).toBe(false);
  });
});

describe('webServerState', () => {
  it('has no block for a healthy server', () => {
    expect(webServerState(nginxTargetFixture)).toEqual({ block: null, stale: false, configInvalid: false, iisMissing: false });
  });
  it('blocks on status, profile, not found, config, last error and a failed scan, in that order', () => {
    expect(webServerState(nginxTargetWith({ status: 'unreachable' })).block).toBe('status');
    expect(webServerState(nginxTargetWith({ status: 'checking' }))).toMatchObject({ block: 'status', stale: false });
    const w = (code: string) => ({ warnings: [{ code, params: {} }] });
    expect(webServerState(nginxTargetWith({}, w('web_server_profile_missing'))).block).toBe('profile_missing');
    expect(webServerState(nginxTargetWith({}, w('web_server_helper_too_old'))).block).toBe('helper_too_old');
    expect(webServerState(nginxTargetWith({}, { warnings: [{ code: 'web_server_helper_too_old', params: {} }, { code: 'web_server_profile_missing', params: {} }] })).block).toBe('profile_missing');
    expect(webServerState(nginxTargetWith({}, { warnings: [{ code: 'web_server_helper_too_old', params: {} }, { code: 'web_server_not_found', params: {} }] })).block).toBe('helper_too_old');
    expect(webServerState(nginxTargetWith({}, w('web_server_not_found'))).block).toBe('server_not_found');
    expect(webServerState(nginxTargetWith({}, { web_server: webServerFacts({ found: false, version: '' }) })).block).toBe('server_not_found');
    const bad = webServerState(nginxTargetWith({}, { web_server: webServerFacts({ config_valid: false }) }));
    expect(bad).toMatchObject({ block: 'config_invalid', configInvalid: true, stale: true });
    expect(webServerState(nginxTargetWith({ last_error: { code: 'X', reason: 'y' } })).block).toBe('last_error');
    expect(webServerState(nginxTargetFixture, true).block).toBe('discovery_failed');
  });
  // A Windows server without IIS is not a stale scan (final review I2).
  it('takes IIS missing on a Windows server as a fact, not a block', () => {
    const facts = { ...windowsTargetFixture.facts, web_server: webServerFacts({ software: 'iis', found: false, version: '' }), warnings: [{ code: 'web_server_not_found', params: {} }] };
    expect(webServerState({ ...windowsTargetFixture, facts })).toEqual({ block: null, stale: false, configInvalid: false, iisMissing: true });
    expect(webServerState({ ...windowsTargetFixture, facts, status: 'unreachable' })).toMatchObject({ block: 'status', iisMissing: true });
    expect(webServerState(windowsTargetFixture).iisMissing).toBe(false);
  });
});

describe('can', () => {
  it('reads the target capabilities', () => {
    expect(can({ capabilities: ['deploy_certificate'] }, 'deploy_certificate')).toBe(true);
    expect(can({ capabilities: [] }, 'deploy_certificate')).toBe(false);
  });
});

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((n) => {
    const p = join(dir, n);
    if (statSync(p).isDirectory()) return sources(p);
    return /\.tsx?$/.test(n) && !/\.test\.tsx?$/.test(n) ? [p] : [];
  });
}

describe('web-server type literals', () => {
  it('has at least the types the guard is meant to cover', () => {
    expect(WEB_SERVER_TYPES).toContain('nginx');
  });

  it('no component decides availability by a web-server type literal', () => {
    const root = resolve(process.cwd(), 'src');
    const allowed = ['api/webServer.ts'];
    const literal = (type: string) => new RegExp(`(['"\`])${type}\\1`);
    const hits = sources(root)
      .filter((f) => WEB_SERVER_TYPES.some((type) => literal(type).test(readFileSync(f, 'utf8'))))
      .map((f) => relative(root, f))
      .filter((f) => !f.startsWith('test/') && !allowed.includes(f));
    expect(hits).toEqual([]);
  });
});
