import { Alert, Button, Container, Divider, Group, PasswordInput, Stack, TextInput, Title } from '@mantine/core';
import { useMutation, useQuery } from '@tanstack/react-query';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { Navigate, useLocation, useNavigate, useSearchParams } from 'react-router';
import { isApiError } from '../api/client';
import { enrollMfa, login, verifyMfa } from '../api/endpoints';
import { listPublicProviders, ssoErrorReason, startSSO } from '../api/sso';
import { PUBLIC_PROVIDERS_KEY } from '../api/queryKeys';
import { goTo } from '../navigation';
import { SSOErrorAlert } from '../components/SSOErrorAlert';
import type { MfaEnrollment, SessionInfo, SessionWithCodes } from '../api/types';
import { useAuth } from '../auth/AuthProvider';
import { PageLoader } from '../auth/guards';
import { safeReturnPath } from '../auth/returnPath';
import { ErrorAlert } from '../components/ErrorAlert';
import { RecoveryCodes } from '../components/RecoveryCodes';
import { TotpEnrollment } from '../components/TotpEnrollment';
import { LanguageSwitcher } from '../LanguageSwitcher';

type Phase = 'password' | 'mfa' | 'enroll' | 'codes';

function PasswordForm({ onDone, onError }: { onDone: (p: Phase, e?: MfaEnrollment) => void; onError: (e: unknown) => void }) {
  const { t } = useTranslation();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async (ev: FormEvent) => {
    ev.preventDefault();
    setBusy(true);
    onError(null);
    const secret = password;
    setPassword(''); // the password is not kept in the page once it is sent
    try {
      const res = await login(username.trim(), secret);
      if (res.status === 'mfa_required') onDone('mfa');
      else onDone('enroll', await enrollMfa());
    } catch (e) {
      onError(e);
      setBusy(false);
    }
  };

  return (
    <form onSubmit={submit}>
      <Stack>
        <TextInput
          label={t('login.username')}
          value={username}
          onChange={(e) => setUsername(e.currentTarget.value)}
          autoComplete="username"
        />
        <PasswordInput
          label={t('login.password')}
          value={password}
          onChange={(e) => setPassword(e.currentTarget.value)}
          autoComplete="current-password"
        />
        <Button type="submit" loading={busy}>
          {t('login.signIn')}
        </Button>
      </Stack>
    </form>
  );
}

// SSOButtons lists the identity providers anybody may sign in with. A click asks the server for the provider's address and
// leaves the page for it (the callback brings the person back, signed in or with ?sso_error=). The list failing only hides it.
function SSOButtons({ returnTo, onError }: { returnTo: string; onError: (e: unknown) => void }) {
  const { t } = useTranslation();
  const providers = useQuery({ queryKey: PUBLIC_PROVIDERS_KEY, queryFn: listPublicProviders });
  const start = useMutation({
    mutationFn: (id: string) => startSSO(id, returnTo),
    onMutate: () => onError(null),
    onSuccess: (r) => goTo(r.authorize_url),
    onError,
  });
  const items = providers.data?.items ?? [];
  if (items.length === 0) return null;
  return (
    <Stack gap="xs">
      <Divider label={t('login.or')} labelPosition="center" styles={{ label: { color: 'var(--mantine-color-gray-7)' } }} />
      {items.map((p) => (
        <Button key={p.id} variant="default" loading={start.isPending && start.variables === p.id} onClick={() => start.mutate(p.id)}>
          {t('login.ssoWith', { name: p.name })}
        </Button>
      ))}
    </Stack>
  );
}

function MfaForm({ onSession, onError }: { onSession: (s: SessionInfo) => void; onError: (e: unknown) => void }) {
  const { t } = useTranslation();
  const [recovery, setRecovery] = useState(false);
  const [value, setValue] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async (ev: FormEvent) => {
    ev.preventDefault();
    setBusy(true);
    onError(null);
    const input = recovery ? { recovery_code: value.trim() } : { code: value.trim() };
    setValue('');
    try {
      onSession(await verifyMfa(input));
    } catch (e) {
      onError(e);
      setBusy(false);
    }
  };

  return (
    <form onSubmit={submit}>
      <Stack>
        <Title order={2}>{t('login.mfaTitle')}</Title>
        {recovery ? (
          <TextInput
            key="recovery"
            label={t('login.recoveryCode')}
            value={value}
            onChange={(e) => setValue(e.currentTarget.value)}
            autoComplete="off"
            spellCheck={false}
          />
        ) : (
          <TextInput
            key="code"
            label={t('ui.codeLabel')}
            value={value}
            onChange={(e) => setValue(e.currentTarget.value)}
            inputMode="numeric"
            autoComplete="one-time-code"
            maxLength={6}
          />
        )}
        <Group justify="space-between">
          <Button
            variant="subtle"
            onClick={() => {
              setRecovery(!recovery);
              setValue('');
            }}
          >
            {recovery ? t('login.useApp') : t('login.useRecovery')}
          </Button>
          <Button type="submit" loading={busy}>
            {t('ui.verify')}
          </Button>
        </Group>
      </Stack>
    </form>
  );
}

export function LoginPage() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const location = useLocation();
  const [params] = useSearchParams();
  const { loading, session, setupStatus, setSession } = useAuth();
  const [phase, setPhase] = useState<Phase>('password');
  const [enrollment, setEnrollment] = useState<MfaEnrollment | null>(null);
  const [withCodes, setWithCodes] = useState<SessionWithCodes | null>(null);
  const [error, setError] = useState<unknown>(null);

  // RequireAuth saved where the user wanted to go; safeReturnPath keeps that same-origin and never /login.
  const ssoReason = ssoErrorReason(params.get('sso_error'));
  const returnTo = safeReturnPath((location.state as { from?: unknown } | null)?.from);

  if (loading) return <PageLoader />;
  if (phase === 'password' && setupStatus && !setupStatus.admin_exists) return <Navigate to="/setup" replace />;
  if (phase === 'password' && session) return <Navigate to={returnTo} replace />;

  const finish = (s: SessionInfo) => {
    setSession(s);
    navigate(returnTo, { replace: true });
  };

  // A pending sign-in lasts a few minutes; when it expires the user starts again.
  const onMfaError = (e: unknown) => {
    setError(e);
    if (isApiError(e, 'auth.unauthenticated')) setPhase('password');
  };

  const verifyEnrollment = async (code: string) => {
    let res: SessionWithCodes;
    try {
      res = await verifyMfa({ code });
    } catch (e) {
      // The pending sign-in expired while the user set up the app: start again, like the MFA step.
      if (isApiError(e, 'auth.unauthenticated')) {
        setError(e);
        setPhase('password');
        return;
      }
      throw e;
    }
    if (res.recovery_codes && res.recovery_codes.length > 0) {
      setWithCodes(res);
      setPhase('codes');
    } else {
      finish(res);
    }
  };

  return (
    <Container size="xs" my="xl">
      <Stack>
        <Group justify="flex-end">
          <LanguageSwitcher />
        </Group>
        <Title order={1}>{t('login.title')}</Title>
        {phase === 'password' && params.get('ended') === '1' && !error && (
          <Alert color="yellow">{t('login.sessionEnded')}</Alert>
        )}
        {phase === 'password' && ssoReason && <SSOErrorAlert reason={ssoReason} />}
        {phase !== 'enroll' && <ErrorAlert error={error} />}
        {phase === 'password' && (
          <PasswordForm
            onError={setError}
            onDone={(next, e) => {
              setEnrollment(e ?? null);
              setPhase(next);
            }}
          />
        )}
        {phase === 'password' && <SSOButtons returnTo={returnTo} onError={setError} />}
        {phase === 'mfa' && <MfaForm onSession={finish} onError={onMfaError} />}
        {phase === 'enroll' && enrollment && <TotpEnrollment enrollment={enrollment} onVerify={verifyEnrollment} />}
        {phase === 'codes' && withCodes && <RecoveryCodes codes={withCodes.recovery_codes ?? []} onContinue={() => finish(withCodes)} />}
      </Stack>
    </Container>
  );
}
