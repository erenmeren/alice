import { readFileSync } from 'node:fs';

const source = readFileSync('public/theme-init.js', 'utf8');
const run = () => new Function(source)();
const root = document.documentElement;

function media(dark: boolean) {
  window.matchMedia = ((q: string) => ({ matches: dark && q.includes('dark'), media: q, addEventListener() {}, removeEventListener() {} })) as unknown as typeof window.matchMedia;
}

describe('theme-init.js (runs before the app, CSP script-src self)', () => {
  const original = window.matchMedia;
  afterEach(() => {
    window.matchMedia = original;
    root.removeAttribute('data-mantine-color-scheme');
    root.removeAttribute('data-density');
  });
  it('follows the system when nothing is stored', () => {
    media(true);
    run();
    expect(root.getAttribute('data-mantine-color-scheme')).toBe('dark');
  });
  it('follows the system for the stored "auto"', () => {
    media(false);
    localStorage.setItem('alice.colorScheme', 'auto');
    run();
    expect(root.getAttribute('data-mantine-color-scheme')).toBe('light');
  });
  it('applies a stored explicit scheme and compact density', () => {
    media(false);
    localStorage.setItem('alice.colorScheme', 'dark');
    localStorage.setItem('alice.density', 'compact');
    run();
    expect(root.getAttribute('data-mantine-color-scheme')).toBe('dark');
    expect(root.getAttribute('data-density')).toBe('compact');
  });
  it('never throws when storage is blocked', () => {
    const get = vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => { throw new DOMException('blocked'); });
    expect(run).not.toThrow();
    get.mockRestore();
  });
  it('is loaded from index.html as a same-origin script, not inline', () => {
    expect(readFileSync('index.html', 'utf8')).toMatch(/<script src="\/theme-init\.js"><\/script>/);
    expect(source).not.toMatch(/innerHTML|document\.write|eval\(/);
  });
});
