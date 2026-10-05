import { Button, Group, Stack, Switch, Text } from '@mantine/core';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { setAutoDeploy, type Binding } from '../api/keyvault';
import { formatDateTime } from '../datetime';
import { AppModal } from './AppModal';
import { ErrorAlert } from './ErrorAlert';
import { useStepUp } from './StepUpProvider';

// AutoDeploySwitch is "Automatic deployment" of a connection. An Administrator switches it (a fresh
// step-up is asked for when the server wants one); switching it on first shows what it means.
// Switching it off is immediate. Everybody else sees the state and who can change it.
export function AutoDeploySwitch({ binding, admin, exportable, onChanged }: { binding: Binding; admin: boolean; exportable: boolean | null; onChanged: () => void }) {
  const { t, i18n } = useTranslation();
  const { run } = useStepUp();
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const set = async (enabled: boolean) => {
    setBusy(true);
    setError(null);
    try {
      await run(() => setAutoDeploy(binding.id, binding.version, enabled));
      setConfirming(false);
      onChanged();
    } catch (e) {
      setError(e);
      // The connection may have moved on: the screen reads it again.
      onChanged();
    }
    setBusy(false);
  };

  return (
    <Stack gap={4} data-testid="auto-deploy">
      <Group gap="sm" align="center">
        <Text size="sm" fw={600} id={`auto-${binding.id}`}>
          {t('bindings.autoDeploy')}
        </Text>
        {admin ? (
          <Switch
            aria-labelledby={`auto-${binding.id}`}
            checked={binding.auto_deploy}
            disabled={busy || (!binding.auto_deploy && exportable === false)}
            label={t(binding.auto_deploy ? 'bindings.autoDeployState.on' : 'bindings.autoDeployState.off')}
            onChange={(e) => (e.currentTarget.checked ? setConfirming(true) : void set(false))}
          />
        ) : (
          <Text size="sm" data-testid="auto-deploy-state">
            {t(binding.auto_deploy ? 'bindings.autoDeployState.on' : 'bindings.autoDeployState.off')}
          </Text>
        )}
      </Group>
      <Text size="sm">{t('bindings.autoDeployHelp')}</Text>
      {binding.auto_deploy && binding.auto_since && <Text size="xs">{t('bindings.autoDeploySince', { time: formatDateTime(binding.auto_since, i18n.language) })}</Text>}
      {!admin && <Text size="xs">{t('bindings.adminOnly')}</Text>}
      {!confirming && <ErrorAlert error={error} />}
      {confirming && (
        <AppModal opened onClose={() => !busy && setConfirming(false)} title={t('bindings.autoDeployConfirmTitle')}>
          <Stack gap="sm">
            <Text size="sm">{t('bindings.autoDeployHelp')}</Text>
            <Text size="sm">{t('bindings.autoDeployOnlyNew')}</Text>
            <ErrorAlert error={error} />
            <Group justify="flex-end">
              <Button variant="default" disabled={busy} onClick={() => setConfirming(false)}>
                {t('ui.cancel')}
              </Button>
              <Button loading={busy} onClick={() => void set(true)}>
                {t('bindings.autoDeployConfirm')}
              </Button>
            </Group>
          </Stack>
        </AppModal>
      )}
    </Stack>
  );
}
