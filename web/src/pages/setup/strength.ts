export type Strength = 'tooShort' | 'fair' | 'good' | 'strong';

export const MIN_PASSPHRASE_LENGTH = 16;

// passphraseStrength is a simple, local estimate for the strength meter. The server
// enforces the real minimum (16 characters); this only guides the user.
export function passphraseStrength(p: string): Strength {
  const length = [...p].length;
  if (length < MIN_PASSPHRASE_LENGTH) return 'tooShort';
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9\s]/].filter((re) => re.test(p)).length;
  const words = p.trim().split(/\s+/).length;
  const score = Number(length >= 20) + Number(length >= 28) + Number(classes >= 3 || words >= 4);
  if (score >= 2) return 'strong';
  return score === 1 ? 'good' : 'fair';
}
