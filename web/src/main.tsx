import '@mantine/core/styles.css';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { MantineProvider } from '@mantine/core';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { I18nextProvider } from 'react-i18next';
import { App } from './App';
import { createI18n } from './i18n';
import { readCspNonce } from './csp';
import { theme } from './theme';

const queryClient = new QueryClient();

createI18n(navigator.languages).then((i18n) => {
  createRoot(document.getElementById('root')!).render(
    <StrictMode>
      <I18nextProvider i18n={i18n}>
        <QueryClientProvider client={queryClient}>
          <MantineProvider theme={theme} getStyleNonce={readCspNonce} defaultColorScheme="light">
            <App />
          </MantineProvider>
        </QueryClientProvider>
      </I18nextProvider>
    </StrictMode>,
  );
});
