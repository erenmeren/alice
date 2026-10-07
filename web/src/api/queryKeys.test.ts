import { kvListKey, targetKey, VAULTS_KEY } from './queryKeys';

describe('query keys', () => {
  it('carry the vault id, so two vaults never share a list', () => {
    for (const kind of ['certificates', 'keys', 'secrets'] as const) expect(kvListKey('vault-a', kind)).not.toEqual(kvListKey('vault-b', kind));
  });
  it('never let the list of vaults be read as the key of one target', () => {
    expect(VAULTS_KEY).not.toEqual(targetKey('vaults'));
    expect(VAULTS_KEY).not.toEqual(targetKey('list'));
    expect(VAULTS_KEY.length).toBeGreaterThan(2);
  });
});

describe('SSH key query keys', () => {
  it('put the key detail under the list prefix and the key files under the target', async () => {
    const { sshKey, keyFiles, SSH_KEYS_KEY } = await import('./queryKeys');
    expect(sshKey('k1')).toEqual([...SSH_KEYS_KEY, 'k1']);
    expect(keyFiles('t1').slice(0, 2)).toEqual(targetKey('t1'));
  });
});

describe('Phase 7 query keys', () => {
  it('put the expiring list under the dashboard prefix, so one invalidation refreshes both', async () => {
    const { DASHBOARD_KEY, EXPIRING_KEY, viewsKey } = await import('./queryKeys');
    expect(EXPIRING_KEY.slice(0, DASHBOARD_KEY.length)).toEqual([...DASHBOARD_KEY]);
    expect(viewsKey('certificates')).not.toEqual(viewsKey('ssh_keys'));
  });
});
