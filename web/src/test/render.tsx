import { render } from '@testing-library/react';
import { MantineProvider } from '@mantine/core';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { I18nextProvider } from 'react-i18next';
import type { ReactElement } from 'react';
import { createI18n } from '../i18n';

export async function renderApp(ui: ReactElement, languages: readonly string[] = ['en-US']) {
  const i18n = await createI18n(languages);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const result = render(
    <I18nextProvider i18n={i18n}>
      <QueryClientProvider client={client}>
        <MantineProvider>{ui}</MantineProvider>
      </QueryClientProvider>
    </I18nextProvider>,
  );
  return { ...result, i18n };
}
