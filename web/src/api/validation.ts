// Client-side checks that mirror the server's rules for a location's verification settings, so a
// wrong value is explained before the request (the server still decides).

export type SNIProblem = 'ip' | 'wildcard' | 'invalid';

const IPV4 = /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;
const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;

// validateSNI mirrors internal/inventory validSNI (and helperproto.ValidSNI): after trimming, 1 to
// 253 characters of dot-separated labels of letters, digits and hyphens (1 to 63 characters, no
// leading or trailing hyphen), no wildcard, no IP address literal. The server folds letters to lower
// case, so upper case is accepted. "" is valid (it clears the value).
export function validateSNI(value: string): SNIProblem | null {
  const s = value.trim();
  if (s === '') return null;
  if (s.startsWith('*')) return 'wildcard';
  if (IPV4.test(s) || s.includes(':')) return 'ip';
  if (s.length > 253) return 'invalid';
  return s.split('.').every((l) => LABEL.test(l)) ? null : 'invalid';
}

// parsePort reads the port field: '' means "not set" (0 on the wire), a number from 0 to 65535 is
// kept; anything else is null (invalid). 0 is accepted because the API treats it as "clear".
export function parsePort(value: string): number | null {
  const s = value.trim();
  if (s === '') return 0;
  if (!/^\d{1,5}$/.test(s)) return null;
  const n = Number(s);
  return n <= 65535 ? n : null;
}
