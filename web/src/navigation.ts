// safeTarget returns the address when it may be navigated to: https, or http only when this page is http itself (development
// and the e2e stack). Anything else (javascript:, data:, a malformed value) is refused.
export function safeTarget(url: string): string | null {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return null;
  }
  if (u.protocol === 'https:' || (u.protocol === 'http:' && window.location.protocol === 'http:')) return u.href;
  return null;
}

// goTo leaves the single-page app for another site (the identity provider's sign-in page). It is the one place that does
// so, it ignores an address safeTarget refuses, and tests replace it.
export function goTo(url: string): void {
  const target = safeTarget(url);
  if (target) window.location.assign(target);
}

// openDownload lets the browser fetch a file of Alice's own API (a backup): the answer is an attachment, so the page
// stays, and a large file streams to disk instead of into memory. The path is a relative /api/v1 path; tests replace
// this function.
export function openDownload(path: string): void {
  if (!path.startsWith('/api/v1/')) return;
  window.location.assign(path);
}
