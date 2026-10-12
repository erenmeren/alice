import { Button, Stack, Text, TextInput } from '@mantine/core';
import { useMutation, useQuery } from '@tanstack/react-query';
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type FormEvent, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { isApiError, onUnauthorized } from '../api/client';
import { stepUp } from '../api/endpoints';
import { PUBLIC_PROVIDERS_KEY } from '../api/queryKeys';
import { listPublicProviders, startSSOStepUp } from '../api/sso';
import { goTo } from '../navigation';
import { useAuth } from '../auth/AuthProvider';
import { Icon } from '../design/Icon';
import { ErrorAlert } from './ErrorAlert';
import { AppModal } from './AppModal';
import { DialogActions } from './ui';

interface StepUpApi {
  // run calls fn; when the server answers auth.stepup_required it asks for a fresh
  // authenticator code, re-confirms the session and calls fn once more.
  run: <T>(fn: () => Promise<T>) => Promise<T>;
  // confirm makes sure the session's step-up is fresh before something the browser fetches itself (a download that is
  // not a fetch() and so cannot be repeated after a refusal): it asks for a code unless the step-up still has a minute.
  // A cancelled prompt rejects with StepUpCancelled.
  confirm: () => Promise<void>;
}

// StepUpCancelled is the rejection of confirm() when the person closes the code prompt.
export class StepUpCancelled extends Error {
  constructor() {
    super('step-up cancelled');
    this.name = 'StepUpCancelled';
  }
}

// A step-up that ends within this margin is renewed before a download, so it cannot expire on the way.
const FRESH_MARGIN_MS = 60_000;

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

// StepUpProvider asks for a fresh authenticator code when the server wants one. The dialog closes
// with the session (AUD-25 d): when the session ends (expired or revoked elsewhere), the dialog
// closes and the waiting call gives up with its original error. The typed code is cleared whenever
// the dialog closes, and with the provider when it unmounts.
export function StepUpProvider({ children }: { children: ReactNode }) {
  const { t } = useTranslation();
  const { session, setSession } = useAuth();
  const sso = session?.user.auth_source === 'oidc';
  const [opened, setOpened] = useState(false);
  const [code, setCode] = useState('');
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const pending = useRef<Pending | null>(null);
  const ssoStart = useMutation({
    mutationFn: () => startSSOStepUp(window.location.pathname + window.location.search),
    onSuccess: (r) => goTo(r.authorize_url),
  });

  const resetSsoStart = ssoStart.reset;
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
      resetSsoStart();
      setOpened(true);
      return promise;
    },
    [resetSsoStart],
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

  const stepupUntil = session?.stepup_until ?? null;
  const confirm = useCallback(async () => {
    if (stepupUntil && Date.parse(stepupUntil) - Date.now() > FRESH_MARGIN_MS) return;
    await askForCode(new StepUpCancelled());
  }, [stepupUntil, askForCode]);

  // giveUp closes the dialog, clears what was typed and rejects the waiting call with its error.
  const giveUp = useCallback(() => {
    setOpened(false);
    setCode('');
    setError(null);
    pending.current?.reject(pending.current.original);
    pending.current = null;
  }, []);
  const cancel = giveUp;

  // The session ended (a request answered 401 auth.unauthenticated: it expired or was revoked): a
  // confirmation for it can no longer succeed.
  useEffect(() => onUnauthorized(giveUp), [giveUp]);

  // Unmounted with a dialog open (the whole application went away): nobody can answer it.
  useEffect(() => () => {
    pending.current?.reject(pending.current.original);
    pending.current = null;
  }, []);

  const submit = async (ev: FormEvent) => {
    ev.preventDefault();
    setBusy(true);
    setError(null);
    try {
      setSession(await stepUp(code.trim()));
      setOpened(false);
      setCode('');
      pending.current?.resolve();
      pending.current = null;
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  // An SSO user has no authenticator code: the identity provider confirms. The browser leaves for it and the callback
  // brings the person back to this page (the action is repeated by the person, as after any step-up).
  const providers = useQuery({ queryKey: PUBLIC_PROVIDERS_KEY, queryFn: listPublicProviders, enabled: opened && sso });
  const providerName = providers.data?.items.find((p) => p.id === session?.user.sso_provider_id)?.name ?? t('stepUp.ssoFallbackName');

  const api = useMemo(() => ({ run, confirm }), [run, confirm]);
  return (
    <StepUpContext.Provider value={api}>
      {children}
      {/* zIndex above page modals (default 200): step-up often opens on top of an open form dialog. */}
      <AppModal opened={opened} onClose={cancel} title={sso ? t('stepUp.ssoTitle') : t('ui.stepUp.title')} centered zIndex={1000} transitionProps={{ duration: 0 }}>
        {/* The design's stepUp(): the reason first, the code field, then the footer bar with Cancel and Confirm. */}
        {sso ? (
          <>
            <Stack>
              <Text size="sm">{t('ui.stepUp.subtitle')}</Text>
              <ErrorAlert error={ssoStart.error} />
            </Stack>
            <DialogActions>
              <Button variant="default" onClick={cancel}>
                {t('ui.cancel')}
              </Button>
              <Button loading={ssoStart.isPending} onClick={() => ssoStart.mutate()} leftSection={<Icon name="ArrowUpRight" size={15} />} data-autofocus>
                {t('stepUp.ssoAction', { name: providerName })}
              </Button>
            </DialogActions>
          </>
        ) : (
          <form onSubmit={submit}>
            <Stack>
              <Text size="sm">{t('ui.stepUp.subtitle')}</Text>
              <Text size="sm" c="dimmed">
                {t('ui.stepUp.help')}
              </Text>
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
            </Stack>
            <DialogActions>
              <Button variant="default" onClick={cancel}>
                {t('ui.cancel')}
              </Button>
              <Button type="submit" loading={busy} leftSection={<Icon name="ShieldCheck" size={15} />}>
                {t('ui.stepUp.confirm')}
              </Button>
            </DialogActions>
          </form>
        )}
      </AppModal>
    </StepUpContext.Provider>
  );
}
