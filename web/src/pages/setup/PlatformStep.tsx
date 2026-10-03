import { Alert, Button, Group, Stack, Text, Title } from '@mantine/core';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { AddServerModal } from '../../components/AddServerModal';
import { PlatformKeyPanel } from '../../components/PlatformKeyPanel';

// PlatformStep is wizard step 7 (spec §18.5): Alice's own public key with the commands that
// prepare a server, and an optional first server. It may be skipped; the Servers page offers the
// same later, so the step stores nothing of its own. A server added here keeps the Administrator
// in the wizard: the dialog closes and the wizard goes on with Continue.
export function PlatformStep({ onDone }: { onDone: () => void }) {
  const { t } = useTranslation();
  const [adding, setAdding] = useState(false);
  const [added, setAdded] = useState<'ok' | 'failed' | null>(null);
  return (
    <Stack>
      <Title order={2}>{t('setup.platform.title')}</Title>
      <Text>{t('setup.platform.help')}</Text>
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
      <Group>
        <Button variant="default" onClick={() => setAdding(true)}>
          {t('setup.platform.addNow')}
        </Button>
        <Button onClick={onDone}>{t('setup.platform.continue')}</Button>
      </Group>
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
