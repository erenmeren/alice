import { render } from '@testing-library/react';
import { MantineProvider, localStorageColorSchemeManager } from '@mantine/core';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { I18nextProvider } from 'react-i18next';
import { createMemoryRouter, RouterProvider, type InitialEntry } from 'react-router';
import { StrictMode, type ReactElement } from 'react';
import { createI18n } from '../i18n';
import { appTheme, cssVariablesResolver } from '../theme';
import { AuthProvider } from '../auth/AuthProvider';
import { routes } from '../router';
import { StepUpProvider } from '../components/StepUpProvider';
import { COLOR_SCHEME_KEY } from '../preferences';

function newClient() {
  return new QueryClient({ defaultOptions: { queries: { retry: false } } });
}

// RenderOptions picks the color scheme a test renders in; without it Mantine follows the (light) test system.
export interface RenderOptions {
  colorScheme?: 'light' | 'dark';
}

// The app's color-scheme manager (ThemeProvider): the mode is stored under alice.colorScheme, "auto" by default.
const schemeManager = localStorageColorSchemeManager({ key: COLOR_SCHEME_KEY });

// providers renders ui inside the app's own theme (appTheme, cssVariablesResolver, color-scheme manager and default),
// as ThemeProvider does in the app.
function providers(ui: ReactElement, i18n: Awaited<ReturnType<typeof createI18n>>, client: QueryClient, opts: RenderOptions = {}) {
  return (
    <I18nextProvider i18n={i18n}>
      <QueryClientProvider client={client}>
        <MantineProvider theme={appTheme(i18n.t('ui.scrollRegion'))} cssVariablesResolver={cssVariablesResolver}
          colorSchemeManager={schemeManager}
          defaultColorScheme="auto"
          forceColorScheme={opts.colorScheme}
        >
          {ui}
        </MantineProvider>
      </QueryClientProvider>
    </I18nextProvider>
  );
}

// renderApp renders a single component with the app providers (no router).
export async function renderApp(ui: ReactElement, languages: readonly string[] = ['en-US'], opts: RenderOptions = {}) {
  const i18n = await createI18n(languages);
  const client = newClient();
  return { ...render(providers(ui, i18n, client, opts)), i18n, client };
}

// renderRoute renders the whole application at path, using the real route table.
export async function renderRoute(path: InitialEntry, opts: { languages?: readonly string[]; strict?: boolean } & RenderOptions = {}) {
  const i18n = await createI18n(opts.languages ?? ['en-US']);
  const router = createMemoryRouter(routes(), { initialEntries: [path] });
  const client = newClient();
  const ui = providers(<RouterProvider router={router} />, i18n, client, opts);
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

// renderWithStepUp is renderWithAuth with the step-up dialog available, for dialogs whose requests need a
// fresh verification code from an Administrator (a vault's credentials, automatic deployment, an import).
export function renderWithStepUp(ui: ReactElement, languages: readonly string[] = ['en-US']) {
  return renderWithAuth(<StepUpProvider>{ui}</StepUpProvider>, languages);
}
