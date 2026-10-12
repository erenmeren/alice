import { useCallback, useState } from 'react';

// Per-device presentation preferences (design: "Your preference stays on this device"). The color mode is stored by
// Mantine's localStorageColorSchemeManager under COLOR_SCHEME_KEY; public/theme-init.js reads both keys before the app
// runs. A blocked store only loses persistence.
export const COLOR_SCHEME_KEY = 'alice.colorScheme';
export const DENSITY_KEY = 'alice.density';

export type Density = 'comfortable' | 'compact';

export function readDensity(): Density {
  try {
    return localStorage.getItem(DENSITY_KEY) === 'compact' ? 'compact' : 'comfortable';
  } catch {
    return 'comfortable';
  }
}

export function applyDensity(d: Density): void {
  document.documentElement.dataset.density = d;
}

export function saveDensity(d: Density): void {
  applyDensity(d);
  try {
    localStorage.setItem(DENSITY_KEY, d);
  } catch {
    // A private window or a policy: the choice holds until the page is reloaded.
  }
}

export function useDensity(): [Density, (d: Density) => void] {
  const [density, setDensity] = useState<Density>(readDensity);
  const set = useCallback((d: Density) => {
    saveDensity(d);
    setDensity(d);
  }, []);
  return [density, set];
}
