import { Button, Center, Loader } from '@mantine/core';
import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, Navigate, useLocation } from 'react-router';
import { AuthMessage } from '../components/auth/AuthLayout';
import type { Permission } from '../api/types';
import { useAuth } from './AuthProvider';
import { can, canPlatform } from './permissions';
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

// RequirePermission hides a page from people without the permission it needs: a platform page (people, settings, audit,
// license) needs a global grant (platform), any other the permission on some service. The server enforces the same rule.
// The no-access view is the design's deniedPage(): the page's <h1> says so, with the way home.
export function RequirePermission({ perm, platform = false, children }: { perm: Permission; platform?: boolean; children: ReactNode }) {
  const { t } = useTranslation();
  const { session } = useAuth();
  if (!session || !(platform ? canPlatform(session, perm) : can(session, perm))) {
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
