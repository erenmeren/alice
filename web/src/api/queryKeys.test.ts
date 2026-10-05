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
