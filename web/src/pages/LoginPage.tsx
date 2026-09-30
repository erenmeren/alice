import { Alert, Container, Stack, Title } from '@mantine/core';
import { useTranslation } from 'react-i18next';
import { useSearchParams } from 'react-router';

// Sign-in entry point. Task 21 replaces this file with the full password + MFA flow.
export function LoginPage() {
  const { t } = useTranslation();
  const [params] = useSearchParams();
  return (
    <Container size="xs" mt="xl">
      <Stack>
        <Title order={1}>{t('login.title')}</Title>
        {params.get('ended') === '1' && <Alert color="yellow">{t('login.sessionEnded')}</Alert>}
      </Stack>
    </Container>
  );
}
