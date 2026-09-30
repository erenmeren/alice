import { Button, Stack, Text, Title } from '@mantine/core';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router';
import { completeSetup } from '../../api/endpoints';
import { useAuth } from '../../auth/AuthProvider';
import { ErrorAlert } from '../../components/ErrorAlert';
import { useStepUp } from '../../components/StepUpProvider';
import { isGone } from './gone';

export function DoneStep({ onGone }: { onGone: () => void }) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { refreshSetupStatus } = useAuth();
  const { run } = useStepUp();
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const finish = async () => {
    setBusy(true);
    setError(null);
    try {
      await run(completeSetup); // finishing needs a fresh step-up (settings.manage)
      await refreshSetupStatus();
      navigate('/', { replace: true });
    } catch (e) {
      if (isGone(e)) return onGone();
      setError(e);
      setBusy(false);
    }
  };

  return (
    <Stack>
      <Title order={2}>{t('setup.done.title')}</Title>
      <Text>{t('setup.done.help')}</Text>
      <ErrorAlert error={error} />
      <Button onClick={() => void finish()} loading={busy}>
        {t('setup.done.button')}
      </Button>
    </Stack>
  );
}
