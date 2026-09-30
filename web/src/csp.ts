// The server replaces __CSP_NONCE__ in index.html with a per-request nonce.
// Mantine adds it to the <style> tag it injects, so CSP needs no 'unsafe-inline'.
export function readCspNonce(): string {
  return document.querySelector('meta[name="csp-nonce"]')?.getAttribute('content') ?? '';
}

declare global {
  var __webpack_nonce__: string | undefined;
}

// shareCspNonce hands the nonce to libraries that inject their own <style> tags through
// get-nonce (react-style-singleton, used by Mantine's Modal to lock page scrolling). get-nonce
// reads the global __webpack_nonce__; without it the browser blocks those styles under the CSP.
export function shareCspNonce(nonce: string): void {
  if (nonce) globalThis.__webpack_nonce__ = nonce;
}
