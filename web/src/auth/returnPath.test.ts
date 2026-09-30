import { safeReturnPath } from './returnPath';

describe('safeReturnPath', () => {
  it('accepts same-origin relative paths, strings and locations', () => {
    expect(safeReturnPath('/users')).toBe('/users');
    expect(safeReturnPath('/audit?result=failure#x')).toBe('/audit?result=failure#x');
    expect(safeReturnPath({ pathname: '/tokens', search: '?a=1', hash: '' })).toBe('/tokens?a=1');
  });

  it.each([
    '//evil.example',
    '///evil.example',
    '/\\evil.example',
    'https://evil.example/x',
    'javascript:alert(1)',
    '/redirect?to=https://evil.example',
    'users',
    '',
    '/a\nb',
  ])('falls back to / for %j', (bad) => {
    expect(safeReturnPath(bad)).toBe('/');
  });

  it('falls back to / for anything that is not a path', () => {
    expect(safeReturnPath(null)).toBe('/');
    expect(safeReturnPath(undefined)).toBe('/');
    expect(safeReturnPath(42)).toBe('/');
    expect(safeReturnPath({ pathname: '//evil.example' })).toBe('/');
  });
});
