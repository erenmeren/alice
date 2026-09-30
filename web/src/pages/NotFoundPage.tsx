import { Anchor, Container, Stack, Text, Title } from '@mantine/core';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';

export function NotFoundPage() {
  const { t } = useTranslation();
  return (
    <Container size="sm" mt="xl">
      <Stack>
        <Title order={1}>{t('ui.notFoundTitle')}</Title>
        <Text>{t('ui.notFoundText')}</Text>
        <Anchor component={Link} to="/">
          {t('ui.backHome')}
        </Anchor>
      </Stack>
    </Container>
  );
}
