import { Button, Group, Modal, Stack, Text, TextInput } from '@mantine/core';
import { createContext, useCallback, useContext, useMemo, useRef, useState, type FormEvent, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { isApiError } from '../api/client';
import { stepUp } from '../api/endpoints';
import { useAuth } from '../auth/AuthProvider';
import { ErrorAlert } from './ErrorAlert';

interface StepUpApi {
  // run calls fn; when the server answers auth.stepup_required it asks for a fresh
  // authenticator code, re-confirms the session and calls fn once more.
  run: <T>(fn: () => Promise<T>) => Promise<T>;
}

const StepUpContext = createContext<StepUpApi | null>(null);

export function useStepUp(): StepUpApi {
  const ctx = useContext(StepUpContext);
  if (!ctx) throw new Error('useStepUp must be used inside <StepUpProvider>');
  return ctx;
}

interface Pending {
  promise: Promise<void>;
  resolve: () => void;
  reject: (e: unknown) => void;
  original: unknown;
}

export function StepUpProvider({ children }: { children: ReactNode }) {
  const { t } = useTranslation();
  const { setSession } = useAuth();
  const [opened, setOpened] = useState(false);
  const [code, setCode] = useState('');
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const pending = useRef<Pending | null>(null);

  const askForCode = useCallback(
    (original: unknown) => {
      // Concurrent calls share one dialog and one promise, so none is orphaned.
      if (pending.current) return pending.current.promise;
      let resolve!: () => void;
      let reject!: (e: unknown) => void;
      const promise = new Promise<void>((res, rej) => {
        resolve = res;
        reject = rej;
      });
      pending.current = { promise, resolve, reject, original };
      setCode('');
      setError(null);
      setOpened(true);
      return promise;
    },
    [],
  );

  const run = useCallback(
    async <T,>(fn: () => Promise<T>): Promise<T> => {
      try {
        return await fn();
      } catch (e) {
        if (!isApiError(e, 'auth.stepup_required')) throw e;
        await askForCode(e);
        return fn();
      }
    },
    [askForCode],
  );

  const cancel = () => {
    setOpened(false);
    pending.current?.reject(pending.current.original);
    pending.current = null;
  };

  const submit = async (ev: FormEvent) => {
    ev.preventDefault();
    setBusy(true);
    setError(null);
    try {
      setSession(await stepUp(code.trim()));
      setOpened(false);
      pending.current?.resolve();
      pending.current = null;
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  const api = useMemo(() => ({ run }), [run]);
  return (
    <StepUpContext.Provider value={api}>
      {children}
      {/* zIndex above page modals (default 200): step-up often opens on top of an open form dialog. */}
      <Modal opened={opened} onClose={cancel} title={t('ui.stepUp.title')} centered zIndex={1000} transitionProps={{ duration: 0 }}>
        <form onSubmit={submit}>
          <Stack>
            <Text size="sm">{t('ui.stepUp.help')}</Text>
            <ErrorAlert error={error} />
            <TextInput
              label={t('ui.codeLabel')}
              value={code}
              onChange={(e) => setCode(e.currentTarget.value)}
              inputMode="numeric"
              autoComplete="one-time-code"
              maxLength={6}
              data-autofocus
            />
            <Group justify="flex-end">
              <Button variant="default" onClick={cancel}>
                {t('ui.cancel')}
              </Button>
              <Button type="submit" loading={busy}>
                {t('ui.stepUp.confirm')}
              </Button>
            </Group>
          </Stack>
        </form>
      </Modal>
    </StepUpContext.Provider>
  );
}
