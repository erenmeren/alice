import { readCspNonce, shareCspNonce } from './csp';

describe('CSP nonce', () => {
  afterEach(() => {
    document.head.innerHTML = '';
    globalThis.__webpack_nonce__ = undefined;
  });

  it('is shared with libraries that inject their own style tags (get-nonce)', () => {
    document.head.innerHTML = '<meta name="csp-nonce" content="abc123==">';
    shareCspNonce(readCspNonce());
    expect(globalThis.__webpack_nonce__).toBe('abc123==');
  });

  it('is not shared when the page has none', () => {
    shareCspNonce(readCspNonce());
    expect(globalThis.__webpack_nonce__).toBeUndefined();
  });
});
