import { render } from '@testing-library/react';
import { MantineProvider } from '@mantine/core';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { I18nextProvider } from 'react-i18next';
import { createMemoryRouter, RouterProvider } from 'react-router';
import type { ReactElement } from 'react';
import { createI18n } from '../i18n';
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
export async function renderRoute(path: string, opts: { languages?: readonly string[] } = {}) {
  const i18n = await createI18n(opts.languages ?? ['en-US']);
  const router = createMemoryRouter(routes(), { initialEntries: [path] });
  const client = newClient();
  return { ...render(providers(<RouterProvider router={router} />, i18n, client)), i18n, router, client };
}
