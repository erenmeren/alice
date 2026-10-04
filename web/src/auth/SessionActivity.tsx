import { useEffect } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { hasActivity, installActivityListeners } from '../api/activity';
import { getLicenseStatus } from '../api/endpoints';
import { LICENSE_STATUS_KEY } from '../api/queryKeys';
import { useAuth } from './AuthProvider';

// STATUS_POLL_MS is how often the license status is read while someone is signed in.
export const STATUS_POLL_MS = 60_000;

// SessionActivity carries a person's activity to the server (AUD-01, Decisions 1 and 2). While
// someone is signed in it listens for input (api/activity.ts) and polls the license status every
// minute on every signed-in screen, the setup wizard's signed-in steps included. A screen that
// sends no request of its own (a form being filled in, a page being read and scrolled) still marks
// the session as used within a minute of the input, through this poll; no separate heartbeat
// request exists. The poll pauses while the tab is hidden (nobody can give input there) and
// refetches when it is shown again. Because the poll pauses, input given just before the tab is
// hidden or closed is sent at once: one marked license status request (kept alive past the page's
// end) when the tab becomes hidden or the page is left, only if a mark is waiting. Signed out,
// nothing of it is mounted: no listeners, no poll, and no query of the previous user left in the
// cache.
export function SessionActivity() {
  const { session } = useAuth();
  return session ? <SignedInActivity /> : null;
}

function SignedInActivity() {
  const client = useQueryClient();
  useEffect(() => installActivityListeners(window), []);
  useEffect(() => {
    const flush = (e: Event) => {
      if (e.type === 'visibilitychange' && document.visibilityState !== 'hidden') return;
      if (!hasActivity()) return; // a visibilitychange and a pagehide in a row send it once
      getLicenseStatus({ keepalive: true }).then(
        (status) => client.setQueryData(LICENSE_STATUS_KEY, status),
        () => undefined, // the next poll or request carries the mark again (apiFetch returns it)
      );
    };
    document.addEventListener('visibilitychange', flush);
    window.addEventListener('pagehide', flush);
    return () => {
      document.removeEventListener('visibilitychange', flush);
      window.removeEventListener('pagehide', flush);
    };
  }, [client]);
  useQuery({ queryKey: LICENSE_STATUS_KEY, queryFn: () => getLicenseStatus(), refetchInterval: STATUS_POLL_MS });
  return null;
}
