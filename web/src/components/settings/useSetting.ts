import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { isApiError } from '../../api/client';
import { settingsKey } from '../../api/queryKeys';
import { useStepUp } from '../StepUpProvider';

type Name = Parameters<typeof settingsKey>[0];

// Every /settings request needs a fresh verification (R42 row 29): the first read of a form goes through step-up, so
// the code prompt appears once on arrival, and so does every change.
export function useSetting<T>(name: Name, read: () => Promise<T>) {
  const { run } = useStepUp();
  return useQuery({ queryKey: settingsKey(name), queryFn: () => run(read) });
}

// useChange sends a change with the version the form was loaded with (If-Match). The answer replaces the cached setting,
// so the form is drawn again from it (keyed by version); a 412 (somebody else changed it) reads the setting again.
export function useChange<T extends { version: number }, V>(name: Name, version: number, send: (version: number, value: V) => Promise<T>) {
  const { run } = useStepUp();
  const client = useQueryClient();
  return useMutation({
    mutationFn: (value: V) => run(() => send(version, value)),
    onSuccess: (data) => client.setQueryData(settingsKey(name), data),
    onError: (e) => {
      if (isApiError(e, 'system.precondition_failed')) void client.invalidateQueries({ queryKey: settingsKey(name) });
    },
  });
}
