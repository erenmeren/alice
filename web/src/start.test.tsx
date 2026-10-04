import { screen, waitFor } from '@testing-library/react';
import { act } from 'react';
import { createI18n } from './i18n';
import { startApp } from './start';

describe('startApp', () => {
  let container: HTMLDivElement;
  let unmount: (() => void) | undefined;
  beforeEach(() => {
    container = document.createElement('div');
    document.body.appendChild(container);
    window.history.replaceState(null, '', '/');
  });
  afterEach(() => {
    act(() => unmount?.());
    container.remove();
  });

  it('renders the application in the browser language', async () => {
    unmount = await act(() => startApp(container, { languages: ['en-US'] }));
    expect(await screen.findByRole('heading', { name: 'Sign in to Alice' })).toBeInTheDocument();
  });

  it('renders in English when the texts of the chosen language cannot be loaded', async () => {
    localStorage.setItem('alice.lang', 'tr');
    const failingTurkish = (langs: readonly string[]) => createI18n(langs, { load: () => Promise.reject(new Error('chunk')) });
    unmount = await act(() => startApp(container, { languages: ['tr-TR'], createI18n: failingTurkish }));
    expect(await screen.findByRole('heading', { name: 'Sign in to Alice' })).toBeInTheDocument();
    await waitFor(() => expect(window.location.pathname).toBe('/login'));
  });

  it('renders in English when creating the texts fails altogether', async () => {
    unmount = await act(() => startApp(container, { languages: ['tr-TR'], createI18n: () => Promise.reject(new Error('broken')) }));
    expect(await screen.findByRole('heading', { name: 'Sign in to Alice' })).toBeInTheDocument();
  });

  it('shows a plain English message with a reload button when no texts can be created', async () => {
    const broken = () => Promise.reject(new Error('broken'));
    unmount = await act(() => startApp(container, { createI18n: broken, createFallback: broken }));
    expect(screen.getByText('Alice could not load its texts. Reload the page.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Reload' })).toBeInTheDocument();
  });
});
