import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { listLocations } from '../api/endpoints';
import { locationsKey } from '../api/queryKeys';
import type { CertificateLocation } from '../api/types';

// useLocations is the websites of an Nginx server. The server page and the websites panel share
// the query (same key), so the list is read once.
export function useLocations(targetId: string, missing = false, enabled = true) {
  return useQuery({
    queryKey: [...locationsKey(targetId), { missing }],
    queryFn: () => listLocations(targetId, missing),
    placeholderData: keepPreviousData,
    enabled,
  });
}

// websitesAsOf is the time Alice last read a website from the server: the latest last_seen_at of
// the listed locations. It is null when no website was ever read. (The target's last_discovery_at
// also moves when only the SSH-key half of a scan worked, so it is not used for this.)
export function websitesAsOf(items: CertificateLocation[]): string | null {
  let best: string | null = null;
  for (const l of items) if (best === null || Date.parse(l.last_seen_at) > Date.parse(best)) best = l.last_seen_at;
  return best;
}
