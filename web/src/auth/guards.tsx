import { Center, Loader, Text } from '@mantine/core';
import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { Navigate, useLocation } from 'react-router';
import type { Role } from '../api/types';
import { useAuth } from './AuthProvider';
import { adminExists } from './setupStatus';

export function PageLoader() {
  const { t } = useTranslation();
  return (
    <Center mih={200}>
      <Loader aria-label={t('ui.loading')} />
    </Center>
  );
}

// RequireAuth sends visitors to the setup wizard (fresh install) or the sign-in page.
export function RequireAuth({ children }: { children: ReactNode }) {
  const { session, setupStatus, loading, sessionEnded } = useAuth();
  const location = useLocation();
  if (loading) return <PageLoader />;
  if (setupStatus && !adminExists(setupStatus)) return <Navigate to="/setup" replace />;
  if (!session) {
    // The sign-in page returns the user to `from` (through safeReturnPath) after sign-in.
    return <Navigate to={sessionEnded ? '/login?ended=1' : '/login'} replace state={{ from: location }} />;
  }
  return <>{children}</>;
}

// RequireRole hides a page from roles that may not use it. The server enforces the same rule.
export function RequireRole({ roles, children }: { roles: Role[]; children: ReactNode }) {
  const { t } = useTranslation();
  const { session } = useAuth();
  if (!session || !roles.includes(session.user.role)) {
    return (
      <Text role="alert" mt="xl">
        {t('ui.noAccess')}
      </Text>
    );
  }
  return <>{children}</>;
}
