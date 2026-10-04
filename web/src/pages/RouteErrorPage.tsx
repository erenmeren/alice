import { Anchor, Button, Container, Group, Stack, Text, Title } from '@mantine/core';
import { useTranslation } from 'react-i18next';

// RouteErrorPage is the error element of the top-level route (AUD-25 d): an error thrown while a
// screen renders shows this page instead of a blank one. It never shows the error itself (its text
// or stack may name internals); React Router reports the error on the browser console, in
// development and in production, so it is not swallowed. The page sits outside the AuthProvider
// (the error may come from it), so both ways back load the application again from the start: a
// reload of the same address, or the home page.
export function RouteErrorPage() {
  const { t } = useTranslation();
  return (
    <Container size="sm" mt="xl">
      <Stack>
        <Title order={1}>{t('routeError.title')}</Title>
        <Text>{t('routeError.text')}</Text>
        <Group>
          <Button onClick={() => window.location.reload()}>{t('routeError.reload')}</Button>
          <Anchor href="/">{t('ui.backHome')}</Anchor>
        </Group>
      </Stack>
    </Container>
  );
}
