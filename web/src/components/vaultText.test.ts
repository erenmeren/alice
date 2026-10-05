import { accessFixture, accessRow, vaultWith } from '../test/fixtures';
import { authKey, isRecentNewVersion, keyTypeParam, shortVersion, vaultNameOf, vaultStatusKey, versionBlock } from './vaultText';

describe('vaultNameOf', () => {
  it('reads the name out of what a person types', () => {
    expect(vaultNameOf('contoso-prod')).toBe('contoso-prod');
    expect(vaultNameOf(' https://contoso-prod.vault.azure.net/ ')).toBe('contoso-prod');
    expect(vaultNameOf('Contoso-Prod.vault.azure.net')).toBe('Contoso-Prod');
  });
  it('gives nothing for text that is not a vault name', () => {
    for (const s of ['', 'ab', 'contoso.evil.test', 'a b', 'x'.repeat(25), '$(id)']) expect(vaultNameOf(s)).toBe('');
  });
});

describe('vaultStatusKey', () => {
  it('keeps the plain statuses', () => {
    expect(vaultStatusKey(vaultWith({ status: 'ok' }))).toBe('enum.targetStatus.ok');
    expect(vaultStatusKey(vaultWith({ status: 'unreachable' }))).toBe('vaults.status.unreachable');
    expect(vaultStatusKey(vaultWith({ status: 'auth_failed', last_error: { code: 'x', reason: 'azure.auth_failed' } }))).toBe('vaults.status.auth_failed');
  });
  it('says what a degraded vault lacks only when it is the certificate listing', () => {
    const forbidden = { access: accessFixture({ checks: [accessRow('list_certificates', 'forbidden', 'Key Vault Reader')] }) };
    expect(vaultStatusKey(vaultWith({ status: 'degraded', last_error: { code: 'x', reason: 'azure.forbidden' } }, forbidden))).toBe('vaults.status.noCertPermission');
    expect(vaultStatusKey(vaultWith({ status: 'degraded', last_error: { code: 'x', reason: 'azure.firewall' } }, forbidden))).toBe('vaults.status.degraded');
    expect(vaultStatusKey(vaultWith({ status: 'degraded', last_error: null }, { access: null }))).toBe('vaults.status.degraded');
  });
  it('names expired credentials', () => {
    expect(vaultStatusKey(vaultWith({ status: 'auth_failed', last_error: { code: 'x', reason: 'azure.credentials_expired' } }))).toBe('vaults.status.credentialsExpired');
  });
});

describe('helpers', () => {
  it('shortens a version to its first eight digits', () => {
    expect(shortVersion('0123456789abcdef0123456789abcdef')).toBe('01234567');
  });
  it('calls a version new when it was made after Alice first saw the certificate, within a week', () => {
    const now = Date.parse('2026-10-05T00:00:00Z');
    expect(isRecentNewVersion('2026-10-04T00:00:00Z', '2026-09-01T00:00:00Z', now)).toBe(true);
    expect(isRecentNewVersion('2026-09-01T00:00:00Z', '2026-09-01T00:00:00Z', now)).toBe(false);
    expect(isRecentNewVersion('2026-09-20T00:00:00Z', '2026-09-01T00:00:00Z', now)).toBe(false);
    expect(isRecentNewVersion(null, '2026-09-01T00:00:00Z', now)).toBe(false);
  });
});

describe('keyTypeParam, versionBlock and authKey', () => {
  it('maps the key types Azure writes to the websites filter', () => {
    expect([keyTypeParam('RSA'), keyTypeParam('rsa'), keyTypeParam('RSA-HSM'), keyTypeParam('EC'), keyTypeParam('ecdsa'), keyTypeParam('oct'), keyTypeParam('')]).toEqual(['rsa', 'rsa', 'rsa', 'ecdsa', 'ecdsa', '', '']);
  });
  it('says why a version cannot be deployed, in the order the API checks', () => {
    const now = Date.parse('2026-10-05T00:00:00Z');
    const ok = { certificate_id: 'c', enabled: true, expires: '2030-01-01T00:00:00Z', not_before: '2026-01-01T00:00:00Z', exportable: true as boolean | null };
    expect(versionBlock(ok, now)).toBeNull();
    expect(versionBlock({ ...ok, exportable: null }, now)).toBeNull();
    expect(versionBlock({ ...ok, certificate_id: null, enabled: false }, now)).toBe('noDetails');
    expect(versionBlock({ ...ok, enabled: false }, now)).toBe('disabled');
    expect(versionBlock({ ...ok, expires: '2026-10-05T00:00:00Z' }, now)).toBe('expired');
    expect(versionBlock({ ...ok, not_before: '2026-10-06T00:00:00Z' }, now)).toBe('notYetValid');
    expect(versionBlock({ ...ok, exportable: false }, now)).toBe('notExportable');
  });
  it('shows an unknown sign-in method as Unknown, not as a certificate', () => {
    expect(authKey('client_secret')).toBe('vaults.auth.client_secret');
    expect(authKey('')).toBe('enum.unknown');
  });
});
