import { render } from '@testing-library/react';
import { MantineProvider } from '@mantine/core';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { I18nextProvider } from 'react-i18next';
import { createMemoryRouter, RouterProvider, type InitialEntry } from 'react-router';
import { StrictMode, type ReactElement } from 'react';
import { createI18n } from '../i18n';
import { AuthProvider } from '../auth/AuthProvider';
import { routes } from '../router';

function newClient() {
  return new QueryClient({ defaultOptions: { queries: { retry: false } } });
}

function providers(ui: ReactElement, i18n: Awaited<ReturnType<typeof createI18n>>, client: QueryClient) {
  return (
    <I18nextProvider i18n={i18n}>
      <QueryClientProvider client={client}>
        <MantineProvider>{ui}</MantineProvider>
      </QueryClientProvider>
    </I18nextProvider>
  );
}

// renderApp renders a single component with the app providers (no router).
export async function renderApp(ui: ReactElement, languages: readonly string[] = ['en-US']) {
  const i18n = await createI18n(languages);
  const client = newClient();
  return { ...render(providers(ui, i18n, client)), i18n, client };
}

// renderRoute renders the whole application at path, using the real route table.
export async function renderRoute(path: InitialEntry, opts: { languages?: readonly string[]; strict?: boolean } = {}) {
  const i18n = await createI18n(opts.languages ?? ['en-US']);
  const router = createMemoryRouter(routes(), { initialEntries: [path] });
  const client = newClient();
  const ui = providers(<RouterProvider router={router} />, i18n, client);
  return { ...render(opts.strict ? <StrictMode>{ui}</StrictMode> : ui), i18n, router, client };
}

// renderWithAuth renders one component inside a router and the AuthProvider (the session comes from
// the sessionHandlers of the test), for dialogs that read the signed-in role.
export async function renderWithAuth(ui: ReactElement, languages: readonly string[] = ['en-US']) {
  const i18n = await createI18n(languages);
  const client = newClient();
  const router = createMemoryRouter([{ path: '*', element: <AuthProvider>{ui}</AuthProvider> }], { initialEntries: ['/'] });
  return { ...render(providers(<RouterProvider router={router} />, i18n, client)), i18n, router, client };
}
