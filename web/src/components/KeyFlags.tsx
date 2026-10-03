import { Badge, Group } from '@mantine/core';
import { useTranslation } from 'react-i18next';
import type { KeyLocation } from '../api/types';

// KeyFlags shows "Alice's key" and the findings of the scan (spec §13.3 item 5) as text badges.
export function KeyFlags({ location }: { location: Pick<KeyLocation, 'flags' | 'is_alice_connection_key'> }) {
  const { t, i18n } = useTranslation();
  const flags = location.flags.filter((f) => i18n.exists(`sshKeys.flags.${f}`));
  if (!location.is_alice_connection_key && flags.length === 0) return null;
  return (
    <Group gap={4}>
      {location.is_alice_connection_key && (
        <Badge variant="light" color="indigo" tt="none">
          {t('sshKeys.aliceKey')}
        </Badge>
      )}
      {flags.map((f) => (
        <Badge key={f} variant="light" color={f === 'weak' || f === 'root_without_from' ? 'orange' : 'gray'} tt="none">
          {t(`sshKeys.flags.${f}`)}
        </Badge>
      ))}
    </Group>
  );
}
