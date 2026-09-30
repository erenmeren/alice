import { AppShell, Container, Group, Stack, Text, Title } from '@mantine/core';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { fetchVersion } from './api';
import { LanguageSwitcher } from './LanguageSwitcher';

export function App() {
  const { t } = useTranslation();
  const version = useQuery({ queryKey: ['version'], queryFn: fetchVersion });

  let status = t('home.serverChecking');
  if (version.isSuccess) status = t('home.serverVersion', { version: version.data.version });
  if (version.isError) status = t('home.serverUnreachable');

  return (
    <AppShell header={{ height: 60 }} padding="md">
      <AppShell.Header>
        <Group h="100%" px="md" justify="space-between">
          <Text fw={700} size="xl">
            {t('app.name', { ns: 'common' })}
          </Text>
          <LanguageSwitcher />
        </Group>
      </AppShell.Header>
      <AppShell.Main>
        <Container size="sm">
          <Stack gap="sm" mt="xl">
            <Title order={1}>{t('home.title')}</Title>
            <Text>{t('home.subtitle')}</Text>
            <Text size="sm" c="gray.7" data-testid="server-status" aria-live="polite">
              {status}
            </Text>
          </Stack>
        </Container>
      </AppShell.Main>
    </AppShell>
  );
}
