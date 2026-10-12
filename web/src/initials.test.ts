import { describe, expect, it } from 'vitest';
import { initials } from './initials';

describe('initials', () => {
  it('takes the first letter of the first two words, upper-cased', () => {
    expect(initials('Eren Altan', 'en')).toBe('EA');
    expect(initials('ada lovelace byron', 'en')).toBe('AL');
    expect(initials('  admin  ', 'en')).toBe('A');
    expect(initials('', 'en')).toBe('');
  });

  it("upper-cases in the reader's language and keeps a whole character", () => {
    expect(initials('ilker ışık', 'tr')).toBe('İI');
    expect(initials('𝒜da Lovelace', 'en')).toBe('𝒜L');
  });
});
