import { Button, Center, Loader } from '@mantine/core';
import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, Navigate, useLocation } from 'react-router';
import { AuthMessage } from '../components/auth/AuthLayout';
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

// RequireRole hides a page from roles that may not use it. The server enforces the same rule. The no-access view is the
// design's deniedPage(): the page's <h1> says so, with the way home.
export function RequireRole({ roles, children }: { roles: Role[]; children: ReactNode }) {
  const { t } = useTranslation();
  const { session } = useAuth();
  if (!session || !roles.includes(session.user.role)) {
    // role="alert" as before: the refusal is announced when the page is reached through the navigation.
    return (
      <div role="alert">
        <AuthMessage
          icon="ShieldAlert"
          title={t('ui.noAccess')}
          actions={
            <Button component={Link} to="/" variant="default">
              {t('ui.backHome')}
            </Button>
          }
        />
      </div>
    );
  }
  return <>{children}</>;
}
