import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useSearchParams } from 'react-router';

// useUrlFilters keeps a list page's filters in the address (R42 rows 15-17): a link, a saved view and the export
// reproduce the list exactly. Only the allowed keys are read; an empty value removes the key; replace keeps the
// browser history to one entry per page visit while a person types. Pass a module-level array so the keys are stable.
export function useUrlFilters<K extends string>(keys: readonly K[]): [Record<K, string>, (next: Partial<Record<K, string>>) => void, () => void] {
  const [params, setParams] = useSearchParams();
  const values = useMemo(() => {
    const out = {} as Record<K, string>;
    for (const k of keys) out[k] = params.get(k) ?? '';
    return out;
  }, [params, keys]);
  const set = useCallback(
    (next: Partial<Record<K, string>>) =>
      setParams(
        (prev) => {
          const p = new URLSearchParams(prev);
          for (const [k, v] of Object.entries(next) as [K, string | undefined][]) {
            if (v) p.set(k, v);
            else p.delete(k);
          }
          return p;
        },
        { replace: true },
      ),
    [setParams],
  );
  const clear = useCallback(() => setParams(new URLSearchParams(), { replace: true }), [setParams]);
  return [values, set, clear];
}

// useDebouncedParam is a text box whose value reaches the address after the person stops typing (delay ms). urlValue is
// the parameter now in the address: when it changes from outside (a link, a saved view, Clear filters) and nothing is
// waiting to be written, the box follows it. reset(next) cancels a pending write and shows next at once; call it just
// before changing the address from outside so a stale write cannot overwrite the new value.
export function useDebouncedParam(urlValue: string, write: (value: string) => void, delay = 300): [string, (value: string) => void, (next: string) => void] {
  const [draft, setDraft] = useState(urlValue);
  const [seen, setSeen] = useState(urlValue);
  const [pending, setPending] = useState(false);
  const timer = useRef<number | undefined>(undefined);
  const writeRef = useRef(write);
  useEffect(() => {
    writeRef.current = write;
  });
  useEffect(() => () => window.clearTimeout(timer.current), []);
  if (seen !== urlValue) {
    setSeen(urlValue);
    if (!pending) setDraft(urlValue);
  }
  const change = useCallback(
    (value: string) => {
      setDraft(value);
      setPending(true);
      window.clearTimeout(timer.current);
      timer.current = window.setTimeout(() => {
        setPending(false);
        writeRef.current(value.trim());
      }, delay);
    },
    [delay],
  );
  const reset = useCallback((next: string) => {
    window.clearTimeout(timer.current);
    setPending(false);
    setDraft(next);
  }, []);
  return [draft, change, reset];
}
