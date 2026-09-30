import { Outlet, type RouteObject } from 'react-router';
import { AuthProvider } from './auth/AuthProvider';
import { RequireAuth } from './auth/guards';
import { StepUpProvider } from './components/StepUpProvider';
import { AppLayout } from './layout/AppLayout';
import { AccountPage } from './pages/AccountPage';
import { HomePage } from './pages/HomePage';
import { LoginPage } from './pages/LoginPage';
import { NotFoundPage } from './pages/NotFoundPage';
import { SetupPage } from './pages/SetupPage';

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
          ],
        },
        { path: '*', element: <NotFoundPage /> },
      ],
    },
  ];
}
