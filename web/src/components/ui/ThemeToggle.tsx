import { ActionIcon, useComputedColorScheme, useMantineColorScheme } from '@mantine/core';
import { useTranslation } from 'react-i18next';
import { Icon } from '../../design/Icon';

// ThemeToggle is the top bar's light/dark switch; it stores an explicit choice (Your account offers "System" again).
export function ThemeToggle() {
  const { t } = useTranslation();
  const { setColorScheme } = useMantineColorScheme();
  const computed = useComputedColorScheme('light');
  return (
    <ActionIcon variant="subtle" color="gray" size="lg" aria-label={t('appearance.toggle')} title={t('appearance.toggle')} onClick={() => setColorScheme(computed === 'dark' ? 'light' : 'dark')}>
      <Icon name={computed === 'dark' ? 'Sun' : 'Moon'} />
    </ActionIcon>
  );
}
