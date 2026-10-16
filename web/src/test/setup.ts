import '@testing-library/jest-dom/vitest';
import { cleanup, configure } from '@testing-library/react';
import { setCsrfToken } from '../api/client';
import { server } from './server';

// jsdom lacks these browser APIs that Mantine uses.
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: (query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => false,
  }),
});
class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}
window.ResizeObserver = ResizeObserverStub as unknown as typeof ResizeObserver;
window.HTMLElement.prototype.scrollIntoView = () => {};

// findBy*/waitFor wait up to 1 s by default; under the full parallel suite a busy machine needs more
// (shell attention bell, network discovery dialogs). Failing waits only take longer to fail.
configure({ asyncUtilTimeout: 5000 });

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
beforeEach(() => {
  localStorage.clear(); // also the per-device preferences alice.colorScheme and alice.density
  document.documentElement.removeAttribute('data-density');
  document.documentElement.lang = 'en';
  setCsrfToken(null);
});
afterEach(() => {
  cleanup();
  server.resetHandlers();
});
afterAll(() => server.close());
