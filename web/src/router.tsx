import { Outlet, type RouteObject } from 'react-router';
import { AuthProvider } from './auth/AuthProvider';
import { RequireAuth, RequirePermission } from './auth/guards';
import { SessionActivity } from './auth/SessionActivity';
import { StepUpProvider } from './components/StepUpProvider';
import { AppLayout } from './layout/AppLayout';
import { AccountPage } from './pages/AccountPage';
import { AcmeCertificatePage } from './pages/AcmeCertificatePage';
import { AcmeCertificatesPage } from './pages/AcmeCertificatesPage';
import { AuditPage } from './pages/AuditPage';
import { CertificateDetailPage } from './pages/CertificateDetailPage';
import { CertificatesPage } from './pages/CertificatesPage';
import { DashboardPage } from './pages/DashboardPage';
import { DeploymentDetailPage } from './pages/DeploymentDetailPage';
import { DeploymentsPage } from './pages/DeploymentsPage';
import { DiscoveryPage } from './pages/DiscoveryPage';
import { IncidentPage } from './pages/IncidentPage';
import { IncidentsPage } from './pages/IncidentsPage';
import { KeyVaultDetailPage } from './pages/KeyVaultDetailPage';
import { KeyVaultsPage } from './pages/KeyVaultsPage';
import { KVCertificatePage } from './pages/KVCertificatePage';
import { LicensePage } from './pages/LicensePage';
import { LoginPage } from './pages/LoginPage';
import { NotFoundPage } from './pages/NotFoundPage';
import { RotationRunPage } from './pages/RotationRunPage';
import { RouteErrorPage } from './pages/RouteErrorPage';
import { TargetDetailPage } from './pages/TargetDetailPage';
import { TargetsPage } from './pages/TargetsPage';
import { ServicePage } from './pages/ServicePage';
import { ServicesPage } from './pages/ServicesPage';
import { SettingsPage } from './pages/SettingsPage';
import { SetupPage } from './pages/SetupPage';
import { RotationsPage } from './pages/RotationsPage';
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
            { index: true, element: <DashboardPage /> },
            { path: 'account', element: <AccountPage /> },
            { path: 'servers', element: <TargetsPage /> },
            { path: 'servers/:id', element: <TargetDetailPage /> },
            { path: 'key-vaults', element: <KeyVaultsPage /> },
            { path: 'key-vaults/:id', element: <KeyVaultDetailPage /> },
            { path: 'key-vaults/:vaultId/certificates/:id', element: <KVCertificatePage /> },
            { path: 'certificates', element: <CertificatesPage /> },
            { path: 'certificates/:id', element: <CertificateDetailPage /> },
            // Issued certificates (ACME): every role reads them (acme.view); the pages hide what a role cannot do.
            { path: 'acme', element: <AcmeCertificatesPage /> },
            { path: 'acme/:id', element: <AcmeCertificatePage /> },
            { path: 'incidents', element: <IncidentsPage /> },
            { path: 'incidents/:id', element: <IncidentPage /> },
            // Network discovery: every role reads it (discovery.view); the page hides what a role cannot do.
            { path: 'discovery', element: <DiscoveryPage /> },
            { path: 'deployments', element: <DeploymentsPage /> },
            { path: 'deployments/:id', element: <DeploymentDetailPage /> },
            { path: 'ssh-keys', element: <SSHKeysPage /> },
            { path: 'ssh-keys/:id', element: <SSHKeyDetailPage /> },
            { path: 'rotations', element: <RotationsPage /> },
            { path: 'rotation/runs/:id', element: <RotationRunPage /> },
            // Services (R49): every role reads them; the pages hide what a role cannot change.
            { path: 'services', element: <ServicesPage /> },
            { path: 'services/:id', element: <ServicePage /> },
            {
              path: 'users',
              element: (
                <RequirePermission perm="users.read" platform>
                  <UsersPage />
                </RequirePermission>
              ),
            },
            {
              path: 'settings',
              element: (
                <RequirePermission perm="settings.manage" platform>
                  <SettingsPage />
                </RequirePermission>
              ),
            },
            { path: 'tokens', element: <TokensPage /> },
            {
              path: 'audit',
              element: (
                <RequirePermission perm="audit.read" platform>
                  <AuditPage />
                </RequirePermission>
              ),
            },
            {
              path: 'license',
              element: (
                <RequirePermission perm="license.read" platform>
                  <LicensePage />
                </RequirePermission>
              ),
            },
          ],
        },
        { path: '*', element: <NotFoundPage /> },
      ],
    },
  ];
}
