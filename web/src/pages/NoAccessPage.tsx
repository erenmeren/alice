import { useTranslation } from 'react-i18next';
import { AuthMessage } from '../components/auth/AuthLayout';

// NoAccessPage is the one page of a signed-in person who holds no role anywhere: no global role and no role on any
// service or environment (design §9). Every address of the app shows it; signing out still works (the shell's own Sign
// out, so the page has one). It reads nothing from the server: there is nothing the person may read.
export function NoAccessPage() {
  const { t } = useTranslation();
  return (
    <div data-testid="no-access">
      <AuthMessage icon="ShieldAlert" title={t('access.none.title')} text={t('access.none.text')} />
    </div>
  );
}
