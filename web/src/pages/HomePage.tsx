import { Stack, Text, Title } from '@mantine/core';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { getVersion } from '../api/endpoints';
import { useAuth } from '../auth/AuthProvider';

export function HomePage() {
  const { t } = useTranslation();
  const { session } = useAuth();
  const version = useQuery({ queryKey: ['version'], queryFn: getVersion });

  let status = t('home.serverChecking');
  if (version.isSuccess) status = t('home.serverVersion', { version: version.data.version });
  if (version.isError) status = t('home.serverUnreachable');

  return (
    <Stack gap="sm">
      <Title order={1}>{t('home.title', { name: session?.user.display_name ?? '' })}</Title>
      <Text>{t('home.subtitle')}</Text>
      <Text size="sm" c="gray.7" data-testid="server-status" aria-live="polite">
        {status}
      </Text>
    </Stack>
  );
}
