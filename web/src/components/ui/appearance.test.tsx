import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { renderApp } from '../../test/render';
import { server } from '../../test/server';
import { AppearanceControl, LanguageToggle, ThemeToggle } from '.';

// failLoad makes the next language switch fail as a failed download of the texts would.
const lang = vi.hoisted(() => ({ failLoad: false }));
vi.mock('../../i18n', async (importOriginal) => {
  const real = await importOriginal<typeof import('../../i18n')>();
  return {
    ...real,
    setLanguage: (...args: Parameters<typeof real.setLanguage>) => (lang.failLoad ? Promise.reject(new Error('load failed')) : real.setLanguage(...args)),
  };
});
afterEach(() => {
  lang.failLoad = false;
});

const root = document.documentElement;

describe('AppearanceControl', () => {
  it('offers light, dark and system as radios and remembers the choice on this device', async () => {
    await renderApp(<AppearanceControl signedIn={false} />);
    const dark = screen.getByRole('radio', { name: /Dark/ });
    await userEvent.click(dark);
    expect(dark).toBeChecked();
    expect(root).toHaveAttribute('data-mantine-color-scheme', 'dark');
    expect(localStorage.getItem('alice.colorScheme')).toBe('dark');
    await userEvent.click(screen.getByRole('radio', { name: /System/ }));
    expect(localStorage.getItem('alice.colorScheme')).toBe('auto');
  });
  it('switches compact tables and saves the language to the account only when signed in', async () => {
    const saved = vi.fn();
    server.use(http.put('/api/v1/auth/locale', () => { saved(); return new HttpResponse(null, { status: 204 }); }));
    await renderApp(<AppearanceControl signedIn />);
    await userEvent.click(screen.getByRole('switch', { name: 'Compact tables' }));
    expect(root).toHaveAttribute('data-density', 'compact');
    await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Language' }), 'tr');
    await waitFor(() => expect(root).toHaveAttribute('lang', 'tr'));
    expect(saved).toHaveBeenCalledOnce();
  });
});

describe('ThemeToggle and LanguageToggle', () => {
  it('flips the computed scheme', async () => {
    await renderApp(<ThemeToggle />);
    await userEvent.click(screen.getByRole('button', { name: 'Switch color mode' }));
    expect(root).toHaveAttribute('data-mantine-color-scheme', 'dark');
  });
  it('is named by the other language in its own name and switches to it (two languages)', async () => {
    await renderApp(<LanguageToggle signedIn={false} />);
    const toggle = screen.getByRole('button', { name: 'Türkçe' });
    expect(toggle).toHaveTextContent('tr');
    await userEvent.click(toggle);
    await waitFor(() => expect(root).toHaveAttribute('lang', 'tr'));
    expect(screen.getByRole('button', { name: 'English' })).toBeVisible();
  });
});

describe('appearance edge cases', () => {
  it('keeps the language on the device only when signed out', async () => {
    const saved = vi.fn();
    server.use(http.put('/api/v1/auth/locale', () => { saved(); return new HttpResponse(null, { status: 204 }); }));
    await renderApp(<AppearanceControl signedIn={false} />);
    expect(screen.queryByText('Saved to your account, so it follows you to other browsers.')).not.toBeInTheDocument();
    await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Language' }), 'tr');
    await waitFor(() => expect(root).toHaveAttribute('lang', 'tr'));
    expect(saved).not.toHaveBeenCalled();
  });

  it('switches compact tables back to comfortable', async () => {
    await renderApp(<AppearanceControl signedIn={false} />);
    const sw = screen.getByRole('switch', { name: 'Compact tables' });
    await userEvent.click(sw);
    await userEvent.click(sw);
    expect(root).toHaveAttribute('data-density', 'comfortable');
    expect(localStorage.getItem('alice.density')).toBe('comfortable');
  });

  it('keeps the new language when saving it to the account fails', async () => {
    server.use(http.put('/api/v1/auth/locale', () => HttpResponse.json({}, { status: 500 })));
    const { unmount } = await renderApp(<AppearanceControl signedIn />);
    await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Language' }), 'tr');
    await waitFor(() => expect(root).toHaveAttribute('lang', 'tr'));
    unmount();
    await renderApp(<LanguageToggle signedIn />, ['tr-TR']);
    await userEvent.click(screen.getByRole('button', { name: 'English' }));
    await waitFor(() => expect(root).toHaveAttribute('lang', 'en'));
  });

  it('the language toggle saves to the account when signed in', async () => {
    const saved = vi.fn();
    server.use(http.put('/api/v1/auth/locale', async ({ request }) => { saved(await request.json()); return new HttpResponse(null, { status: 204 }); }));
    await renderApp(<LanguageToggle signedIn />);
    await userEvent.click(screen.getByRole('button', { name: 'Türkçe' }));
    await waitFor(() => expect(saved).toHaveBeenCalledWith({ locale: 'tr' }));
  });

  it('the theme toggle goes back to light from dark', async () => {
    localStorage.setItem('alice.colorScheme', 'dark');
    await renderApp(<ThemeToggle />);
    expect(root).toHaveAttribute('data-mantine-color-scheme', 'dark');
    await userEvent.click(screen.getByRole('button', { name: 'Switch color mode' }));
    expect(root).toHaveAttribute('data-mantine-color-scheme', 'light');
    expect(localStorage.getItem('alice.colorScheme')).toBe('light');
  });
});

describe('a language whose texts cannot be loaded', () => {
  it('stays in the current language and saves nothing to the account', async () => {
    const saved = vi.fn();
    server.use(http.put('/api/v1/auth/locale', () => { saved(); return new HttpResponse(null, { status: 204 }); }));
    lang.failLoad = true;
    const { unmount } = await renderApp(<AppearanceControl signedIn />);
    await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Language' }), 'tr');
    unmount();
    await renderApp(<LanguageToggle signedIn />);
    await userEvent.click(screen.getByRole('button', { name: 'Türkçe' }));
    expect(screen.getByRole('button', { name: 'Türkçe' })).toBeVisible();
    expect(root).toHaveAttribute('lang', 'en');
    expect(saved).not.toHaveBeenCalled();
  });
});
