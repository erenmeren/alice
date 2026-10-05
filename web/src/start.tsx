import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { i18n as I18n } from 'i18next';
import { I18nextProvider } from 'react-i18next';
import { createBrowserRouter, RouterProvider } from 'react-router';
import { queryDefaults } from './api/retry';
import { createEnglishI18n, createI18n } from './i18n';
import { routes } from './router';
import { ThemeProvider } from './ThemeProvider';

export interface StartOptions {
  languages?: readonly string[];
  createI18n?: (languages: readonly string[]) => Promise<I18n>;
  createFallback?: () => Promise<I18n>;
}

// startApp renders the application into container once its texts are ready, and returns the
// function that unmounts it (tests). The texts never keep the page blank (AUD-25 d): a language
// that cannot be loaded leaves English (createI18n), any other failure retries with the bundled
// English texts alone, and if even that fails a plain English message with a reload button is
// shown.
export async function startApp(container: HTMLElement, opts: StartOptions = {}): Promise<() => void> {
  const make = opts.createI18n ?? createI18n;
  const fallback = opts.createFallback ?? (() => createEnglishI18n());
  const root = createRoot(container);
  let i18n: I18n;
  try {
    i18n = await make(opts.languages ?? navigator.languages);
  } catch {
    try {
      i18n = await fallback();
    } catch {
      root.render(<TextsFailed />);
      return () => root.unmount();
    }
  }
  const queryClient = new QueryClient({ defaultOptions: queryDefaults });
  const router = createBrowserRouter(routes());
  root.render(
    <StrictMode>
      <I18nextProvider i18n={i18n}>
        <QueryClientProvider client={queryClient}>
          <ThemeProvider>
            <RouterProvider router={router} />
          </ThemeProvider>
        </QueryClientProvider>
      </I18nextProvider>
    </StrictMode>,
  );
  return () => root.unmount();
}

// TextsFailed is shown when no texts could be created at all; it uses no catalog, so it is English.
function TextsFailed() {
  return (
    <main lang="en" style={{ fontFamily: 'sans-serif', padding: '2rem' }}>
      <p>Alice could not load its texts. Reload the page.</p>
      <button type="button" onClick={() => window.location.reload()}>
        Reload
      </button>
    </main>
  );
}
