import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { App } from './App';
import { renderApp } from './test/render';

function mockVersion(ok = true) {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () =>
      ok
        ? new Response(JSON.stringify({ version: '1.2.3', commit: 'abc', build_time: 't' }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          })
        : new Response('{}', { status: 503 }),
    ),
  );
}

describe('App', () => {
  beforeEach(() => {
    localStorage.clear();
    document.documentElement.lang = 'en';
  });
  afterEach(() => vi.unstubAllGlobals());

  it('renders the English home page with the server version', async () => {
    mockVersion();
    await renderApp(<App />);
    expect(screen.getByRole('heading', { name: 'Welcome to Alice' })).toBeInTheDocument();
    await waitFor(() => expect(screen.getByTestId('server-status')).toHaveTextContent('Server version: 1.2.3'));
  });

  it('starts in Turkish for a Turkish browser', async () => {
    mockVersion();
    await renderApp(<App />, ['tr-TR']);
    expect(screen.getByRole('heading', { name: "Alice'e hoş geldiniz" })).toBeInTheDocument();
    expect(document.documentElement.lang).toBe('tr');
  });

  it('switches language, updates <html lang> and remembers the choice', async () => {
    mockVersion();
    await renderApp(<App />);
    await userEvent.click(screen.getByText('Türkçe'));
    expect(await screen.findByRole('heading', { name: "Alice'e hoş geldiniz" })).toBeInTheDocument();
    expect(document.documentElement.lang).toBe('tr');
    expect(localStorage.getItem('alice.lang')).toBe('tr');
  });

  it('explains when the server is unreachable', async () => {
    mockVersion(false);
    await renderApp(<App />);
    await waitFor(() => expect(screen.getByTestId('server-status')).toHaveTextContent('cannot be reached'));
  });
});
