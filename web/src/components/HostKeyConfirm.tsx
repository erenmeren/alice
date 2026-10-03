import { Button, Code, Group, Stack, Text } from '@mantine/core';
import { useTranslation } from 'react-i18next';
import type { HostKey } from '../api/types';
import { WRAP } from './wrap';

// HostKeyConfirm asks a person to compare the presented fingerprint with the one the server
// shows (TOFU with human confirmation, SEC-080). Nothing is trusted until onYes.
export function HostKeyConfirm({
  host,
  hostKey,
  onYes,
  onNo,
  busy = false,
}: {
  host: string;
  hostKey: HostKey;
  onYes: () => void;
  onNo?: () => void;
  busy?: boolean;
}) {
  const { t } = useTranslation();
  return (
    <Stack gap="xs">
      <Text size="sm">{t('hostKeys.confirmHelp', { host })}</Text>
      <Text size="sm" fw={600}>
        {t('hostKeys.fingerprintLabel')}
      </Text>
      <Code block data-testid="host-key-fingerprint" style={WRAP}>
        {hostKey.fingerprint}
      </Code>
      <Text size="sm" fw={600}>
        {t('hostKeys.commandLabel')}
      </Text>
      <Code block data-testid="host-key-command" style={WRAP}>
        {hostKey.verify_command}
      </Code>
      {onNo && (
        <Text size="xs" c="gray.7">
          {t('hostKeys.pendingNote')}
        </Text>
      )}
      <Group justify="flex-end">
        {onNo && (
          <Button variant="default" onClick={onNo}>
            {t('hostKeys.no')}
          </Button>
        )}
        <Button onClick={onYes} loading={busy}>
          {t('hostKeys.yes')}
        </Button>
      </Group>
    </Stack>
  );
}
