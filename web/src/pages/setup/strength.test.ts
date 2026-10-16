import { readRepoFile } from '../../test/goSources';
import { passphraseStrength, type Strength } from './strength';

type Vector = { passphrase: string; strength: Strength; note: string };

describe('passphraseStrength', () => {
  it('rejects fewer than 16 characters, counting letters not bytes', () => {
    expect(passphraseStrength('short')).toBe('tooShort');
    expect(passphraseStrength('ığdırığdırığdır')).toBe('tooShort'); // 15 letters
    expect(passphraseStrength('ığdırığdırığdırı')).toBe('fair'); // 16 letters
  });
  it('rates longer and more varied passphrases higher', () => {
    expect(passphraseStrength('abcdefghijklmnopqrst')).toBe('fair');
    expect(passphraseStrength('correct horse battery staple')).toBe('strong');
    expect(passphraseStrength('Tr0ub4dor&3-Tr0ub4dor')).toBe('strong');
  });
  it('rates the shared vectors exactly like the server', () => {
    // internal/setup/testdata/strength.json also drives the Go test of setup.PassphraseStrength, which refuses "fair".
    const vectors = JSON.parse(readRepoFile('internal/setup/testdata/strength.json')) as Vector[];
    expect(vectors.length).toBeGreaterThanOrEqual(30);
    for (const v of vectors) expect([v.note, passphraseStrength(v.passphrase)]).toEqual([v.note, v.strength]);
  });
});
