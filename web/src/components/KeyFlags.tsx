import { Group } from '@mantine/core';
import { useTranslation } from 'react-i18next';
import type { KeyLocation } from '../api/types';
import { StatusBadge } from './ui';

// KeyFlags shows "Alice's key" and the findings of the scan (spec §13.3 item 5) as text badges.
export function KeyFlags({ location }: { location: Pick<KeyLocation, 'flags' | 'is_alice_connection_key'> }) {
  const { t, i18n } = useTranslation();
  const flags = location.flags.filter((f) => i18n.exists(`sshKeys.flags.${f}`));
  if (!location.is_alice_connection_key && flags.length === 0) return null;
  return (
    <Group gap={4}>
      {location.is_alice_connection_key && (
        <StatusBadge tone="brand" icon="KeyRound" size="sm">
          {t('sshKeys.aliceKey')}
        </StatusBadge>
      )}
      {flags.map((f) => (
        <StatusBadge key={f} tone={f === 'weak' || f === 'root_without_from' ? 'warning' : 'neutral'} size="sm">
          {t(`sshKeys.flags.${f}`)}
        </StatusBadge>
      ))}
    </Group>
  );
}
