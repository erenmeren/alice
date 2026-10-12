import { Button, Stack } from '@mantine/core';
import { useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router';
import { completeSetup } from '../../api/endpoints';
import { useAuth } from '../../auth/AuthProvider';
import { ErrorAlert } from '../../components/ErrorAlert';
import { useStepUp } from '../../components/StepUpProvider';
import { Icon } from '../../design/Icon';
import { isGone } from './gone';
import { StepActions, StepHeading } from './SetupShell';

export function DoneStep({ onGone, back }: { onGone: () => void; back?: ReactNode }) {
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
      <StepHeading title={t('setup.done.title')} intro={t('setup.done.help')} />
      <ErrorAlert error={error} />
      <StepActions back={back}>
        <Button onClick={() => void finish()} loading={busy} rightSection={<Icon name="ArrowRight" size={15} />}>
          {t('setup.done.button')}
        </Button>
      </StepActions>
    </Stack>
  );
}
