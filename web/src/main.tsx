import '@mantine/core/styles.css';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { MantineProvider } from '@mantine/core';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { I18nextProvider } from 'react-i18next';
import { createBrowserRouter, RouterProvider } from 'react-router';
import { queryDefaults } from './api/retry';
import { createI18n } from './i18n';
import { readCspNonce, shareCspNonce } from './csp';
import { routes } from './router';
import { theme } from './theme';

shareCspNonce(readCspNonce());

const queryClient = new QueryClient({ defaultOptions: queryDefaults });
const router = createBrowserRouter(routes());

createI18n(navigator.languages).then((i18n) => {
  createRoot(document.getElementById('root')!).render(
    <StrictMode>
      <I18nextProvider i18n={i18n}>
        <QueryClientProvider client={queryClient}>
          <MantineProvider theme={theme} getStyleNonce={readCspNonce} defaultColorScheme="light">
            <RouterProvider router={router} />
          </MantineProvider>
        </QueryClientProvider>
      </I18nextProvider>
    </StrictMode>,
  );
});
