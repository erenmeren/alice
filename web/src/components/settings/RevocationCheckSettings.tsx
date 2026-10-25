import { Stack, Switch, Text, Title } from '@mantine/core';
import { useTranslation } from 'react-i18next';
import { getRevocationChecks, saveRevocationChecks, type RevocationCheckSettings as Settings } from '../../api/settings';
import { ErrorAlert } from '../ErrorAlert';
import { LoadingIndicator } from '../LoadingIndicator';
import { SavedNote } from './SavedNote';
import { useChange, useSetting } from './useSetting';

// RevocationCheckSettings is the switch of the revocation check (R64, D5) in Settings, General: whether Alice asks the
// authority that issued each certificate whether it was revoked. A change is sent with the version read (If-Match).
export function RevocationCheckSettings() {
  const q = useSetting('revocation', getRevocationChecks);
  if (q.isPending) return <LoadingIndicator />;
  if (q.isError) return <ErrorAlert error={q.error} />;
  return <RevocationPanel settings={q.data} />;
}

function RevocationPanel({ settings }: { settings: Settings }) {
  const { t } = useTranslation();
  const save = useChange('revocation', settings.version, saveRevocationChecks);
  return (
    <Stack gap="sm" maw={560} mt="lg" data-testid="revocation-check-settings">
      <Title order={3}>{t('settings.revocationCheck.title')}</Title>
      <Text size="sm">{t('settings.revocationCheck.help')}</Text>
      <Switch
        label={t('settings.revocationCheck.enabled')}
        checked={settings.enabled}
        disabled={save.isPending}
        onChange={(e) => save.mutate(e.currentTarget.checked)}
      />
      <SavedNote show={save.isSuccess} />
      <ErrorAlert error={save.error} />
    </Stack>
  );
}
