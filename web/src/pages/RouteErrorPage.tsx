import { Anchor, Button } from '@mantine/core';
import { useEffect, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { AuthLayout, AuthMessage } from '../components/auth/AuthLayout';
import { Icon } from '../design/Icon';

// RouteErrorPage is the error element of the top-level route (AUD-25 d): an error thrown while a
// screen renders shows this page instead of a blank one. It never shows the error itself (its text
// or stack may name internals); React Router reports the error on the browser console, in
// development and in production, so it is not swallowed. The page sits outside the AuthProvider
// (the error may come from it), so both ways back load the application again from the start: a
// reload of the same address, or the home page.
export function RouteErrorPage() {
  const { t } = useTranslation();
  // Focus moves to the heading, so a screen reader announces the page that replaced the screen.
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => heading.current?.focus(), []);
  return (
    <AuthLayout brand={false}>
      <AuthMessage
        icon="CircleAlert"
        title={t('routeError.title')}
        text={t('routeError.text')}
        headingRef={heading}
        actions={
          <>
            <Button onClick={() => window.location.reload()} leftSection={<Icon name="RefreshCw" size={15} />}>
              {t('routeError.reload')}
            </Button>
            <Anchor href="/">{t('ui.backHome')}</Anchor>
          </>
        }
      />
    </AuthLayout>
  );
}
