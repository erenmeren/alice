import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MantineProvider } from '@mantine/core';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { I18nextProvider } from 'react-i18next';
import { createMemoryRouter, RouterProvider, type RouteObject } from 'react-router';
import { createI18n } from '../i18n';
import { routes } from '../router';
import { sessionFor, sessionHandlers } from '../test/fixtures';
import { expectNoRawKeys } from '../test/i18nAssert';
import { server } from '../test/server';

const SECRET_TEXT = 'boom: internal detail /srv/alice/secret.go:42';

function Boom(): never {
  throw new Error(SECRET_TEXT);
}

// renderWithBrokenRoute renders the real route table with one extra route whose element throws
// while it renders, below the signed-in layout (as a page bug would).
async function renderWithBrokenRoute(path: string, languages: readonly string[] = ['en-US']) {
  const table = routes();
  const signedIn = table[0].children!.find((r) => r.path === '/') as RouteObject;
  signedIn.children!.push({ path: 'boom', element: <Boom /> });
  table[0].children!.push({ path: '/boom-public', element: <Boom /> });
  const i18n = await createI18n(languages);
  const router = createMemoryRouter(table, { initialEntries: [path] });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <I18nextProvider i18n={i18n}>
      <QueryClientProvider client={client}>
        <MantineProvider>
          <RouterProvider router={router} />
        </MantineProvider>
      </QueryClientProvider>
    </I18nextProvider>,
  );
  return { router };
}

describe('RouteErrorPage', () => {
  let consoleError: { mock: { calls: unknown[][] }; mockRestore: () => void };
  // React's development build rethrows a render error as an uncaught window error before the
  // boundary takes it; jsdom would print it.
  const quiet = (e: ErrorEvent) => e.preventDefault();
  beforeEach(() => {
    // React Router reports the error on the console; keep the test output clean.
    consoleError = vi.spyOn(console, 'error').mockImplementation(() => {});
    window.addEventListener('error', quiet);
  });
  afterEach(() => {
    consoleError.mockRestore();
    window.removeEventListener('error', quiet);
  });

  it('is the error element of the top-level route', () => {
    expect(routes()[0].errorElement).toBeTruthy();
  });

  it('shows a translated error page with a way back instead of a blank screen, and never the error text', async () => {
    server.use(...sessionHandlers(sessionFor('admin')));
    await renderWithBrokenRoute('/boom');
    expect(await screen.findByRole('heading', { level: 1, name: 'Something went wrong' })).toBeInTheDocument();
    expect(screen.getByText(/This page could not be shown/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Reload' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Go to the home page' })).toHaveAttribute('href', '/');
    expect(document.body.textContent).not.toContain('boom');
    expect(document.body.textContent).not.toContain('secret.go');
    expect(document.body.textContent).not.toMatch(/\bat \w+ \(/); // no stack frames
    expectNoRawKeys();
  });

  it('is shown in Turkish on a public route too', async () => {
    await renderWithBrokenRoute('/boom-public', ['tr-TR']);
    expect(await screen.findByRole('heading', { level: 1, name: 'Bir sorun oluştu' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Yeniden yükle' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Ana sayfaya dön' })).toBeInTheDocument();
    expect(document.body.textContent).not.toContain('secret.go');
    expectNoRawKeys();
  });

  it('reloads the page from its button', async () => {
    const reload = vi.fn();
    const original = window.location;
    Object.defineProperty(window, 'location', { configurable: true, value: { ...original, reload } });
    try {
      await renderWithBrokenRoute('/boom-public');
      await userEvent.click(await screen.findByRole('button', { name: 'Reload' }));
      expect(reload).toHaveBeenCalledTimes(1);
    } finally {
      Object.defineProperty(window, 'location', { configurable: true, value: original });
    }
  });

  it('does not swallow the error in development: it is reported on the console', async () => {
    await renderWithBrokenRoute('/boom-public');
    await screen.findByRole('heading', { name: 'Something went wrong' });
    const reported = consoleError.mock.calls.some((args: unknown[]) => args.some((a: unknown) => a instanceof Error && a.message === SECRET_TEXT));
    expect(reported).toBe(true);
  });
});
