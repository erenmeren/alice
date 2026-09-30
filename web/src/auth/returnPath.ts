// safeReturnPath turns the location saved by a redirect into a path that is safe to
// navigate to after sign-in: same-origin and relative only (no open redirect).
export function safeReturnPath(from: unknown): string {
  const path = toPath(from);
  if (path === null) return '/';
  // eslint-disable-next-line no-control-regex -- control characters are never valid in a return path
  const unsafe = /[\\\u0000-\u001f\u007f]/.test(path) || path.includes('://');
  if (!path.startsWith('/') || path.startsWith('//') || unsafe) return '/';
  return path;
}

function toPath(from: unknown): string | null {
  if (typeof from === 'string') return from;
  if (typeof from === 'object' && from !== null && 'pathname' in from && typeof from.pathname === 'string') {
    const { search, hash } = from as { search?: unknown; hash?: unknown };
    return from.pathname + (typeof search === 'string' ? search : '') + (typeof hash === 'string' ? hash : '');
  }
  return null;
}
