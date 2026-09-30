// The server replaces __CSP_NONCE__ in index.html with a per-request nonce.
// Mantine adds it to the <style> tag it injects, so CSP needs no 'unsafe-inline'.
export function readCspNonce(): string {
  return document.querySelector('meta[name="csp-nonce"]')?.getAttribute('content') ?? '';
}
