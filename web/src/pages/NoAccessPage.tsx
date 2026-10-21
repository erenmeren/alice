import { Button } from '@mantine/core';
import { useTranslation } from 'react-i18next';
import { useAuth } from '../auth/AuthProvider';
import { AuthMessage } from '../components/auth/AuthLayout';
import { Icon } from '../design/Icon';

// NoAccessPage is the one page of a signed-in person who holds no role anywhere: no global role and no role on any
// service or environment (design §9). Every address of the app shows it; signing out still works. It reads nothing from
// the server: there is nothing the person may read.
export function NoAccessPage() {
  const { t } = useTranslation();
  const { signOut } = useAuth();
  return (
    <div data-testid="no-access">
      <AuthMessage
        icon="ShieldAlert"
        title={t('access.none.title')}
        text={t('access.none.text')}
        actions={
          <Button variant="default" leftSection={<Icon name="LogOut" size={15} />} onClick={() => void signOut()}>
            {t('nav.signOut')}
          </Button>
        }
      />
    </div>
  );
}
