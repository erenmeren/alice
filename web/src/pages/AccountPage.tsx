import { Alert, Button, Paper, PasswordInput, Stack, Text, Title } from '@mantine/core';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { changePassword, regenerateRecoveryCodes } from '../api/endpoints';
import { useAuth } from '../auth/AuthProvider';
import { ErrorAlert } from '../components/ErrorAlert';
import { RecoveryCodes } from '../components/RecoveryCodes';
import { useStepUp } from '../components/StepUpProvider';

function ChangePassword() {
  const { t } = useTranslation();
  const { setSession } = useAuth();
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [repeat, setRepeat] = useState('');
  const [mismatch, setMismatch] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [done, setDone] = useState(false);
  const [busy, setBusy] = useState(false);

  const submit = async (ev: FormEvent) => {
    ev.preventDefault();
    setError(null);
    setDone(false);
    setMismatch(next !== repeat);
    if (next !== repeat) return;
    setBusy(true);
    try {
      setSession(await changePassword(current, next));
      setCurrent('');
      setNext('');
      setRepeat('');
      setDone(true);
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Paper withBorder p="md">
      <form onSubmit={submit}>
        <Stack>
          <Title order={2}>{t('account.password.title')}</Title>
          {done && <Alert color="green">{t('account.password.changed')}</Alert>}
          {mismatch && (
            <Alert color="red" role="alert">
              {t('account.password.mismatch')}
            </Alert>
          )}
          <ErrorAlert error={error} />
          <PasswordInput
            label={t('account.password.current')}
            value={current}
            onChange={(e) => setCurrent(e.currentTarget.value)}
            autoComplete="current-password"
          />
          <PasswordInput
            label={t('account.password.new')}
            description={t('account.password.newHelp')}
            value={next}
            onChange={(e) => setNext(e.currentTarget.value)}
            autoComplete="new-password"
          />
          <PasswordInput
            label={t('account.password.repeat')}
            value={repeat}
            onChange={(e) => setRepeat(e.currentTarget.value)}
            autoComplete="new-password"
          />
          <Button type="submit" loading={busy}>
            {t('account.password.submit')}
          </Button>
        </Stack>
      </form>
    </Paper>
  );
}

function NewRecoveryCodes() {
  const { t } = useTranslation();
  const { run } = useStepUp();
  const [codes, setCodes] = useState<string[] | null>(null);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const create = async () => {
    setBusy(true);
    setError(null);
    setSaved(false);
    try {
      setCodes((await run(() => regenerateRecoveryCodes())).recovery_codes);
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Paper withBorder p="md">
      <Stack>
        <Title order={2}>{t('account.recovery.title')}</Title>
        <Text>{t('account.recovery.help')}</Text>
        <ErrorAlert error={error} />
        {saved && <Alert color="green">{t('account.recovery.active')}</Alert>}
        {codes ? (
          <RecoveryCodes
            codes={codes}
            onContinue={() => {
              setCodes(null);
              setSaved(true);
            }}
          />
        ) : (
          <Button variant="default" onClick={() => void create()} loading={busy}>
            {t('account.recovery.create')}
          </Button>
        )}
      </Stack>
    </Paper>
  );
}

export function AccountPage() {
  const { t } = useTranslation();
  const { session } = useAuth();
  if (!session) return null;
  return (
    <Stack maw={640}>
      <Title order={1}>{t('account.title')}</Title>
      <Text data-testid="account-summary">
        {t('account.summary', {
          username: session.user.username,
          role: t(`enum.role.${session.user.role}`, { ns: 'common' }),
        })}
      </Text>
      <Text size="sm" c="gray.7">
        {t('account.languageHelp')}
      </Text>
      <ChangePassword />
      <NewRecoveryCodes />
    </Stack>
  );
}
