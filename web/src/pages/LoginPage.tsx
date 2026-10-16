import { Alert, Button, NativeSelect, PasswordInput, Stack, TextInput, Title } from '@mantine/core';
import { useMutation, useQuery } from '@tanstack/react-query';
import { useEffect, useRef, useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { Navigate, useLocation, useNavigate, useSearchParams } from 'react-router';
import { isApiError } from '../api/client';
import { enrollMfa, getSession, login, verifyMfa } from '../api/endpoints';
import { directoryLogin, directorySignInReason, listPublicDirectories, type PublicDirectory } from '../api/ldap';
import { listPublicProviders, ssoErrorReason, startSSO } from '../api/sso';
import { PUBLIC_DIRECTORIES_KEY, PUBLIC_PROVIDERS_KEY } from '../api/queryKeys';
import { goTo } from '../navigation';
import { SSOErrorAlert } from '../components/SSOErrorAlert';
import type { MfaEnrollment, SessionInfo, SessionWithCodes } from '../api/types';
import { useAuth } from '../auth/AuthProvider';
import { PageLoader } from '../auth/guards';
import { adminExists } from '../auth/setupStatus';
import { safeReturnPath } from '../auth/returnPath';
import { ErrorAlert } from '../components/ErrorAlert';
import { RecoveryCodes } from '../components/RecoveryCodes';
import { TotpEnrollment } from '../components/TotpEnrollment';
import { AuthLayout } from '../components/auth/AuthLayout';
import classes from '../components/auth/auth.module.css';
import { Icon } from '../design/Icon';

type Phase = 'password' | 'mfa' | 'enroll' | 'codes';

// LOCAL is the "Sign in to" value of Alice's own accounts; every other value is a directory's ID.
const LOCAL = 'local';

// PasswordForm is the user name and password form, for a local account or, when chosen under "Sign in to", a directory.
// Both answers lead into the same phases (the code, the enrolment); a directory that asks for no code signs in at once
// (onSession). A refused directory sign-in is shown as one generic text (onReason), never the server's variation.
function PasswordForm({
  directories,
  onDone,
  onSession,
  onError,
  onReason,
}: {
  directories: PublicDirectory[];
  onDone: (p: Phase, e?: MfaEnrollment) => void;
  onSession: (s: SessionInfo) => void;
  onError: (e: unknown) => void;
  onReason: (r: string | null) => void;
}) {
  const { t } = useTranslation();
  const [target, setTarget] = useState(LOCAL);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  // A directory that is no longer offered falls back to Local.
  const directory = directories.find((d) => d.id === target) ?? null;

  const submit = async (ev: FormEvent) => {
    ev.preventDefault();
    setBusy(true);
    onError(null);
    onReason(null);
    const secret = password;
    setPassword(''); // the password is not kept in the page once it is sent
    try {
      const res = directory ? await directoryLogin(directory.id, username.trim(), secret) : await login(username.trim(), secret);
      if (res.status === 'signed_in') onSession(await getSession());
      else if (res.status === 'mfa_required') onDone('mfa');
      else onDone('enroll', await enrollMfa());
    } catch (e) {
      const reason = directory && isApiError(e) ? directorySignInReason(e.status) : null;
      if (reason) onReason(reason);
      else onError(e);
      setBusy(false);
    }
  };

  return (
    <form onSubmit={submit}>
      <Stack>
        {directories.length > 0 && (
          <NativeSelect
            label={t('login.signInTo')}
            value={directory ? directory.id : LOCAL}
            onChange={(e) => setTarget(e.currentTarget.value)}
            data={[{ value: LOCAL, label: t('login.local') }, ...directories.map((d) => ({ value: d.id, label: d.name }))]}
          />
        )}
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
        <Button type="submit" loading={busy} fullWidth className={classes.authButton} rightSection={<Icon name="ArrowRight" size={15} />}>
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
    <>
      <div className={classes.divider}>{t('login.or')}</div>
      <Stack gap="xs">
        {items.map((p) => (
          <Button
            key={p.id}
            variant="default"
            fullWidth
            className={classes.authButton}
            leftSection={<Icon name="Building2" size={15} />}
            loading={start.isPending && start.variables === p.id}
            onClick={() => start.mutate(p.id)}
          >
            {t('login.ssoWith', { name: p.name })}
          </Button>
        ))}
      </Stack>
    </>
  );
}

function MfaForm({ onSession, onError }: { onSession: (s: SessionInfo) => void; onError: (e: unknown) => void }) {
  const { t } = useTranslation();
  const [recovery, setRecovery] = useState(false);
  const [value, setValue] = useState('');
  const [busy, setBusy] = useState(false);
  // The code field takes the focus when the step opens and when the kind of code changes.
  const field = useRef<HTMLInputElement>(null);
  useEffect(() => field.current?.focus(), [recovery]);

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
            ref={field}
            label={t('login.recoveryCode')}
            value={value}
            onChange={(e) => setValue(e.currentTarget.value)}
            autoComplete="off"
            spellCheck={false}
          />
        ) : (
          <TextInput
            key="code"
            ref={field}
            label={t('ui.codeLabel')}
            value={value}
            onChange={(e) => setValue(e.currentTarget.value)}
            inputMode="numeric"
            autoComplete="one-time-code"
            maxLength={6}
          />
        )}
        <Button type="submit" loading={busy} fullWidth className={classes.authButton}>
          {t('ui.verify')}
        </Button>
        <Button
          variant="subtle"
          fullWidth
          onClick={() => {
            setRecovery(!recovery);
            setValue('');
          }}
        >
          {recovery ? t('login.useApp') : t('login.useRecovery')}
        </Button>
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
  const [dirReason, setDirReason] = useState<string | null>(null);
  // The switched-on directories offered under "Sign in to". The list failing only hides the choice (Local stays).
  const directories = useQuery({ queryKey: PUBLIC_DIRECTORIES_KEY, queryFn: listPublicDirectories, enabled: phase === 'password' });

  // The enrollment and recovery-code phases replace the form the person was in: focus moves to the new phase's title
  // (the code phase focuses its own field).
  const phaseArea = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (phase !== 'enroll' && phase !== 'codes') return;
    const title = phaseArea.current?.querySelector<HTMLElement>('h2');
    title?.setAttribute('tabindex', '-1');
    title?.focus();
  }, [phase]);

  // RequireAuth saved where the user wanted to go; safeReturnPath keeps that same-origin and never /login.
  const ssoReason = ssoErrorReason(params.get('sso_error'));
  const returnTo = safeReturnPath((location.state as { from?: unknown } | null)?.from);

  if (loading) return <PageLoader />;
  if (phase === 'password' && setupStatus && !adminExists(setupStatus)) return <Navigate to="/setup" replace />;
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
    <AuthLayout wide={phase === 'enroll' || phase === 'codes'}>
      <span className={classes.iconTile}>
        <Icon name="Fingerprint" size={16} />
      </span>
      {/* One h1 in every phase: the code, enrollment and recovery-code steps add their own h2 below it. */}
      <Title order={1} size={29} className={classes.heading}>
        {t('login.title')}
      </Title>
      {phase === 'password' ? <p className={classes.subtitle}>{t('login.subtitle')}</p> : <div className={classes.subtitle} />}
      <Stack ref={phaseArea}>
        {phase === 'password' && params.get('ended') === '1' && !error && (
          <Alert color="yellow">{t('login.sessionEnded')}</Alert>
        )}
        {phase === 'password' && ssoReason && <SSOErrorAlert reason={ssoReason} />}
        {phase === 'password' && dirReason && <SSOErrorAlert reason={dirReason} testId="directory-error" />}
        {phase !== 'enroll' && <ErrorAlert error={error} />}
        {phase === 'password' && (
          <PasswordForm
            directories={directories.data?.items ?? []}
            onSession={finish}
            onReason={setDirReason}
            onError={setError}
            onDone={(next, e) => {
              setEnrollment(e ?? null);
              setPhase(next);
            }}
          />
        )}
        {phase === 'mfa' && <MfaForm onSession={finish} onError={onMfaError} />}
        {phase === 'enroll' && enrollment && <TotpEnrollment enrollment={enrollment} onVerify={verifyEnrollment} />}
        {phase === 'codes' && withCodes && <RecoveryCodes codes={withCodes.recovery_codes ?? []} onContinue={() => finish(withCodes)} />}
      </Stack>
      {/* Under the password form only: Alice does not enforce MFA for single sign-on (the identity provider does), so the
          note never sits under the SSO buttons (owner ruling on review M-3). */}
      {phase === 'password' && (
        <p className={classes.note}>
          <Icon name="LockKeyhole" size={14} />
          {t('login.mfaNote')}
        </p>
      )}
      {phase === 'password' && <SSOButtons returnTo={returnTo} onError={setError} />}
    </AuthLayout>
  );
}
