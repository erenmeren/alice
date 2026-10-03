import { Outlet, type RouteObject } from 'react-router';
import { AuthProvider } from './auth/AuthProvider';
import { RequireAuth, RequireRole } from './auth/guards';
import { StepUpProvider } from './components/StepUpProvider';
import { AppLayout } from './layout/AppLayout';
import { AccountPage } from './pages/AccountPage';
import { AuditPage } from './pages/AuditPage';
import { HomePage } from './pages/HomePage';
import { LicensePage } from './pages/LicensePage';
import { LoginPage } from './pages/LoginPage';
import { NotFoundPage } from './pages/NotFoundPage';
import { TargetDetailPage } from './pages/TargetDetailPage';
import { TargetsPage } from './pages/TargetsPage';
import { SetupPage } from './pages/SetupPage';
import { SSHKeyDetailPage } from './pages/SSHKeyDetailPage';
import { SSHKeysPage } from './pages/SSHKeysPage';
import { TokensPage } from './pages/TokensPage';
import { UsersPage } from './pages/UsersPage';

function Root() {
  return (
    <AuthProvider>
      <StepUpProvider>
        <Outlet />
      </StepUpProvider>
    </AuthProvider>
  );
}

// routes is shared by the browser router (main.tsx) and the memory router in tests.
export function routes(): RouteObject[] {
  return [
    {
      element: <Root />,
      children: [
        { path: '/setup', element: <SetupPage /> },
        { path: '/login', element: <LoginPage /> },
        {
          path: '/',
          element: (
            <RequireAuth>
              <AppLayout />
            </RequireAuth>
          ),
          children: [
            { index: true, element: <HomePage /> },
            { path: 'account', element: <AccountPage /> },
            { path: 'servers', element: <TargetsPage /> },
            { path: 'servers/:id', element: <TargetDetailPage /> },
            { path: 'ssh-keys', element: <SSHKeysPage /> },
            { path: 'ssh-keys/:id', element: <SSHKeyDetailPage /> },
            {
              path: 'users',
              element: (
                <RequireRole roles={['admin']}>
                  <UsersPage />
                </RequireRole>
              ),
            },
            { path: 'tokens', element: <TokensPage /> },
            {
              path: 'audit',
              element: (
                <RequireRole roles={['admin', 'auditor']}>
                  <AuditPage />
                </RequireRole>
              ),
            },
            {
              path: 'license',
              element: (
                <RequireRole roles={['admin', 'auditor']}>
                  <LicensePage />
                </RequireRole>
              ),
            },
          ],
        },
        { path: '*', element: <NotFoundPage /> },
      ],
    },
  ];
}
