import { formatDateTime } from './datetime';

describe('formatDateTime', () => {
  it('returns an empty string for null', () => {
    expect(formatDateTime(null, 'en')).toBe('');
  });
  it('returns the input when it is not a date', () => {
    expect(formatDateTime('not a date', 'en')).toBe('not a date');
  });
  it('formats in the requested language', () => {
    expect(formatDateTime('2026-09-30T08:00:00Z', 'en')).toMatch(/2026/);
    expect(formatDateTime('2026-09-30T08:00:00Z', 'tr')).toMatch(/Eyl/);
  });
});
