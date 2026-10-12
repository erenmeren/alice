import { Alert, Button, Stack } from '@mantine/core';
import { useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { AddServerModal } from '../../components/AddServerModal';
import { PlatformKeyPanel } from '../../components/PlatformKeyPanel';
import { Icon } from '../../design/Icon';
import { StepActions, StepHeading } from './SetupShell';

// PlatformStep is wizard step 7 (spec §18.5): Alice's own public key with the commands that
// prepare a server, and an optional first server. It may be skipped; the Servers page offers the
// same later, so the step stores nothing of its own. A server added here keeps the Administrator
// in the wizard: the dialog closes and the wizard goes on with Continue.
export function PlatformStep({ onDone, back }: { onDone: () => void; back?: ReactNode }) {
  const { t } = useTranslation();
  const [adding, setAdding] = useState(false);
  const [added, setAdded] = useState<'ok' | 'failed' | null>(null);
  return (
    <Stack>
      <StepHeading title={t('setup.platform.title')} intro={t('setup.platform.help')} />
      <PlatformKeyPanel titleOrder={3} />
      {added === 'ok' && (
        <Alert color="green" role="status">
          {t('targets.added')}
        </Alert>
      )}
      {added === 'failed' && (
        <Alert color="yellow" role="status">
          {t('setup.platform.addedFailed')}
        </Alert>
      )}
      <StepActions back={back}>
        <Button variant="default" leftSection={<Icon name="Plus" size={15} />} onClick={() => setAdding(true)}>
          {t('setup.platform.addNow')}
        </Button>
        <Button onClick={onDone} rightSection={<Icon name="ArrowRight" size={15} />}>
          {t('setup.platform.continue')}
        </Button>
      </StepActions>
      {adding && (
        <AddServerModal
          onClose={() => setAdding(false)}
          onAdded={() => {
            setAdding(false);
            setAdded('ok');
          }}
          onFailedClose={() => {
            setAdding(false);
            setAdded('failed');
          }}
        />
      )}
    </Stack>
  );
}
