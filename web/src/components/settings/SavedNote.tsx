import { Text } from '@mantine/core';
import { useTranslation } from 'react-i18next';

// SavedNote confirms a save in a status region, so a screen reader announces it.
export function SavedNote({ show }: { show: boolean }) {
  const { t } = useTranslation();
  return (
    <Text role="status" size="sm" c="var(--alice-success)" mih="1.2em">
      {show ? t('settings.saved') : ''}
    </Text>
  );
}
