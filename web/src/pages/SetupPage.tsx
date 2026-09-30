import { Container, Title } from '@mantine/core';
import { useTranslation } from 'react-i18next';

// Setup wizard entry point. Task 20 replaces this file with the full wizard.
export function SetupPage() {
  const { t } = useTranslation();
  return (
    <Container size="sm" mt="xl">
      <Title order={1}>{t('setup.title')}</Title>
    </Container>
  );
}
