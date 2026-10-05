import { Outlet, type RouteObject } from 'react-router';
import { AuthProvider } from './auth/AuthProvider';
import { RequireAuth, RequireRole } from './auth/guards';
import { SessionActivity } from './auth/SessionActivity';
import { StepUpProvider } from './components/StepUpProvider';
import { AppLayout } from './layout/AppLayout';
import { AccountPage } from './pages/AccountPage';
import { AuditPage } from './pages/AuditPage';
import { CertificateDetailPage } from './pages/CertificateDetailPage';
import { CertificatesPage } from './pages/CertificatesPage';
import { DeploymentDetailPage } from './pages/DeploymentDetailPage';
import { DeploymentsPage } from './pages/DeploymentsPage';
import { HomePage } from './pages/HomePage';
import { KeyVaultDetailPage } from './pages/KeyVaultDetailPage';
import { KeyVaultsPage } from './pages/KeyVaultsPage';
import { KVCertificatePage } from './pages/KVCertificatePage';
import { LicensePage } from './pages/LicensePage';
import { LoginPage } from './pages/LoginPage';
import { NotFoundPage } from './pages/NotFoundPage';
import { RouteErrorPage } from './pages/RouteErrorPage';
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
      <SessionActivity />
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
      // An error thrown while any screen renders shows a translated error page, not a blank one.
      errorElement: <RouteErrorPage />,
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
            { path: 'key-vaults', element: <KeyVaultsPage /> },
            { path: 'key-vaults/:id', element: <KeyVaultDetailPage /> },
            { path: 'key-vaults/:vaultId/certificates/:id', element: <KVCertificatePage /> },
            { path: 'certificates', element: <CertificatesPage /> },
            { path: 'certificates/:id', element: <CertificateDetailPage /> },
            { path: 'deployments', element: <DeploymentsPage /> },
            { path: 'deployments/:id', element: <DeploymentDetailPage /> },
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
