import { passphraseStrength } from './strength';

describe('passphraseStrength', () => {
  it('rejects fewer than 16 characters, counting letters not bytes', () => {
    expect(passphraseStrength('short')).toBe('tooShort');
    expect(passphraseStrength('ığdırığdırığdır')).toBe('tooShort'); // 15 letters
    expect(passphraseStrength('ığdırığdırığdırı')).toBe('fair'); // 16 letters
  });
  it('rates longer and more varied passphrases higher', () => {
    expect(passphraseStrength('abcdefghijklmnopqrst')).toBe('good');
    expect(passphraseStrength('correct horse battery staple')).toBe('strong');
    expect(passphraseStrength('Tr0ub4dor&3-Tr0ub4dor')).toBe('strong');
  });
});
