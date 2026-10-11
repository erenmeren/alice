import { goTo, safeTarget } from './navigation';

describe('navigation', () => {
  it('accepts https, and http only on an http page', () => {
    expect(safeTarget('https://idp.example.com/a?b=1')).toBe('https://idp.example.com/a?b=1');
    expect(window.location.protocol).toBe('http:'); // jsdom's test page
    expect(safeTarget('http://127.0.0.1:9444/a')).toBe('http://127.0.0.1:9444/a');
  });
  it('refuses javascript:, data:, relative and malformed values', () => {
    for (const bad of ['javascript:alert(1)', 'data:text/html,x', '/login', 'not a url', '']) expect(safeTarget(bad)).toBeNull();
  });
  it('goTo ignores an address it refuses', () => {
    expect(() => goTo('javascript:alert(1)')).not.toThrow();
  });
});
