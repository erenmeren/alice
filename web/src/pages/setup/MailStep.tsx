import { Alert, Button, Group, Stack, Text, Title } from '@mantine/core';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { skipMail } from '../../api/endpoints';
import { useAuth } from '../../auth/AuthProvider';
import { ErrorAlert } from '../../components/ErrorAlert';
import { MailSettings, type MailDraft } from '../../components/settings/MailSettings';
import { useStepUp } from '../../components/StepUpProvider';
import { isGone } from './gone';

// MailStep is the wizard's optional mail server step (R43 row 16, Phase 7 carry 21). It is the Settings mail form
// itself, with its test e-mail. Continue needs saved mail settings (the server then counts mail as chosen); Skip
// records the choice, and the dashboard's "Finish setting up" list keeps the mail server on it.
export function MailStep({ onDone, onGone, draft, onDraft }: { onDone: () => void; onGone: () => void; draft?: MailDraft | null; onDraft?: (d: MailDraft) => void }) {
  const { t } = useTranslation();
  const { run } = useStepUp();
  const { refreshSetupStatus } = useAuth();
  const [notSaved, setNotSaved] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState<'skip' | 'continue' | null>(null);

  const go = async () => {
    setBusy('continue');
    setError(null);
    try {
      const status = await refreshSetupStatus();
      if (status?.mail_chosen) return onDone();
      setNotSaved(true);
    } catch (e) {
      setError(e);
    }
    setBusy(null);
  };

  const skip = async () => {
    setBusy('skip');
    setError(null);
    try {
      await run(skipMail); // settings.manage: a fresh code if the step-up expired
      await refreshSetupStatus();
      onDone();
    } catch (e) {
      if (isGone(e)) return onGone();
      setError(e);
      setBusy(null);
    }
  };

  return (
    <Stack>
      <Title order={2}>{t('setup.mail.title')}</Title>
      <Text>{t('setup.mail.help')}</Text>
      <MailSettings draft={draft} onDraft={onDraft} />
      {notSaved && (
        <Alert color="yellow" role="alert">
          {t('setup.mail.notSaved')}
        </Alert>
      )}
      <ErrorAlert error={error} />
      <Group>
        <Button variant="default" data-testid="setup-skip" loading={busy === 'skip'} onClick={() => void skip()}>
          {t('setup.skip')}
        </Button>
        <Button loading={busy === 'continue'} onClick={() => void go()}>
          {t('ui.continue')}
        </Button>
      </Group>
    </Stack>
  );
}
