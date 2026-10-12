import { Button } from '@mantine/core';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router';
import { AuthLayout, AuthMessage } from '../components/auth/AuthLayout';
import { Icon } from '../design/Icon';

// NotFoundPage is the design's notFound() for an address no route knows. It sits outside the signed-in layout, so it
// uses the sign-in layout's form side (with the theme and language toggles) and links home.
export function NotFoundPage() {
  const { t } = useTranslation();
  return (
    <AuthLayout brand={false}>
      <AuthMessage
        icon="Search"
        title={t('ui.notFoundTitle')}
        text={t('ui.notFoundText')}
        actions={
          <Button component={Link} to="/" leftSection={<Icon name="ArrowLeft" size={15} />}>
            {t('ui.backHome')}
          </Button>
        }
      />
    </AuthLayout>
  );
}
