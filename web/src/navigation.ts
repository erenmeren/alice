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
