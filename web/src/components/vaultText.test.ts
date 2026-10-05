import { accessFixture, accessRow, vaultWith } from '../test/fixtures';
import { isRecentNewVersion, shortVersion, vaultNameOf, vaultStatusKey } from './vaultText';

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
