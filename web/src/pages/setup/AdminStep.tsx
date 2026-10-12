import { Alert, Button, PasswordInput, Stack, TextInput } from '@mantine/core';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { startAdminEnrollment } from '../../api/endpoints';
import type { MfaEnrollment } from '../../api/types';
import { isGone } from './gone';
import { ErrorAlert } from '../../components/ErrorAlert';
import { Icon } from '../../design/Icon';
import { StepActions, StepHeading } from './SetupShell';

export function AdminStep({ onEnrolled, onGone }: { onEnrolled: (e: MfaEnrollment) => void; onGone: () => void }) {
  const { t } = useTranslation();
  const [username, setUsername] = useState('admin');
  const [displayName, setDisplayName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [repeat, setRepeat] = useState('');
  const [mismatch, setMismatch] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (ev: FormEvent) => {
    ev.preventDefault();
    setError(null);
    setMismatch(password !== repeat);
    if (password !== repeat) return;
    setBusy(true);
    try {
      onEnrolled(
        await startAdminEnrollment({ username: username.trim(), display_name: displayName.trim(), email: email.trim(), password }),
      );
    } catch (e) {
      if (isGone(e)) return onGone();
      setError(e);
      setBusy(false);
    }
  };

  return (
    <form onSubmit={submit}>
      <Stack>
        <StepHeading title={t('setup.admin.title')} intro={t('setup.admin.help')} />
        <ErrorAlert error={error} />
        {mismatch && (
          <Alert color="red" role="alert">
            {t('setup.admin.passwordMismatch')}
          </Alert>
        )}
        <TextInput
          label={t('setup.admin.username')}
          description={t('ui.usernameHelp')}
          value={username}
          onChange={(e) => setUsername(e.currentTarget.value)}
          autoComplete="username"
        />
        <TextInput
          label={t('setup.admin.fullName')}
          value={displayName}
          onChange={(e) => setDisplayName(e.currentTarget.value)}
          autoComplete="name"
        />
        <TextInput
          label={t('setup.admin.email')}
          type="email"
          value={email}
          onChange={(e) => setEmail(e.currentTarget.value)}
          autoComplete="email"
        />
        <PasswordInput
          label={t('setup.admin.password')}
          description={t('setup.admin.passwordHelp')}
          value={password}
          onChange={(e) => setPassword(e.currentTarget.value)}
          autoComplete="new-password"
        />
        <PasswordInput
          label={t('setup.admin.repeatPassword')}
          value={repeat}
          onChange={(e) => setRepeat(e.currentTarget.value)}
          autoComplete="new-password"
        />
        <StepActions>
          <Button type="submit" loading={busy} rightSection={<Icon name="ArrowRight" size={15} />}>
            {t('ui.continue')}
          </Button>
        </StepActions>
      </Stack>
    </form>
  );
}
