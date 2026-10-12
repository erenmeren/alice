import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import * as activity from '../api/activity';
import { installedStatus, sessionFor, sessionHandlers, statusWith } from '../test/fixtures';
import { renderRoute } from '../test/render';
import { server } from '../test/server';

const keydown = { isTrusted: true, type: 'keydown' } as unknown as Event;

describe('session activity (AUD-01)', () => {
  afterEach(() => vi.restoreAllMocks());

  it('listens for input only while someone is signed in, and stops on sign-out', async () => {
    const install = vi.spyOn(activity, 'installActivityListeners');
    const add = vi.spyOn(window, 'addEventListener');
    const remove = vi.spyOn(window, 'removeEventListener');
    const ours = (calls: unknown[][]) => calls.filter(([, fn]) => fn === activity.noteInput).length;
    server.use(...sessionHandlers(sessionFor('admin')), http.post('/api/v1/auth/logout', () => new HttpResponse(null, { status: 204 })));
    const { router } = await renderRoute('/');
    await screen.findByRole('heading', { level: 1, name: 'Overview' });
    expect(install).toHaveBeenCalledTimes(1);
    expect(ours(add.mock.calls)).toBe(5);
    expect(ours(remove.mock.calls)).toBe(0);
    await userEvent.click(screen.getByRole('button', { name: 'Sign out' }));
    await waitFor(() => expect(router.state.location.pathname).toBe('/login'));
    expect(ours(remove.mock.calls)).toBe(5);
    expect(install).toHaveBeenCalledTimes(1);
  });

  it('installs nothing for a signed-out visitor', async () => {
    const install = vi.spyOn(activity, 'installActivityListeners');
    const { router } = await renderRoute('/');
    await waitFor(() => expect(router.state.location.pathname).toBe('/login'));
    expect(install).not.toHaveBeenCalled();
  });

  it('removes the listeners when the application unmounts', async () => {
    const remove = vi.spyOn(window, 'removeEventListener');
    server.use(...sessionHandlers(sessionFor('operator')));
    const { unmount } = await renderRoute('/');
    await screen.findByRole('heading', { level: 1, name: 'Overview' });
    unmount();
    expect(remove.mock.calls.filter(([, fn]) => fn === activity.noteInput)).toHaveLength(5);
  });

  it('gives the page load mark to the session probe, not to the public setup status', async () => {
    activity.resetActivity(true); // a fresh page load
    const marks: Record<string, string | null> = {};
    server.use(
      http.get('/api/v1/setup/status', ({ request }) => {
        marks.status = request.headers.get('X-Alice-Activity');
        return HttpResponse.json(installedStatus);
      }),
      http.get('/api/v1/auth/session', ({ request }) => {
        marks.session = request.headers.get('X-Alice-Activity');
        return HttpResponse.json(sessionFor('admin'));
      }),
    );
    await renderRoute('/');
    await screen.findByRole('heading', { level: 1, name: 'Overview' });
    expect(marks).toEqual({ status: null, session: '1' });
  });

  it('polls the license status on the signed-in steps of the setup wizard too, carrying input', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      const marks: (string | null)[] = [];
      server.use(
        ...sessionHandlers(sessionFor('admin'), { ...installedStatus, completed: false, recovery_passphrase_set: false }),
        http.get('/api/v1/license/status', ({ request }) => {
          marks.push(request.headers.get('X-Alice-Activity'));
          return HttpResponse.json(statusWith());
        }),
      );
      await renderRoute('/setup');
      await screen.findByRole('heading', { name: 'Choose a recovery passphrase' });
      await vi.waitFor(() => expect(marks.length).toBeGreaterThan(0));
      activity.resetActivity(false);
      const before = marks.length;
      await vi.advanceTimersByTimeAsync(60_000);
      await vi.waitFor(() => expect(marks.length).toBe(before + 1));
      expect(marks[before]).toBeNull(); // nobody typed: the poll is unmarked
      activity.noteInput(keydown); // typing a passphrase sends no request of its own
      await vi.advanceTimersByTimeAsync(60_000);
      await vi.waitFor(() => expect(marks.length).toBe(before + 2));
      expect(marks[before + 1]).toBe('1');
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('session activity: hidden tabs and StrictMode (AUD-01 follow-ups)', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
    setVisibility('visible');
  });

  function setVisibility(state: DocumentVisibilityState) {
    Object.defineProperty(document, 'visibilityState', { configurable: true, get: () => state });
  }

  function countStatus(): { marks: (string | null)[]; keepalive: boolean[] } {
    const out = { marks: [] as (string | null)[], keepalive: [] as boolean[] };
    server.use(
      http.get('/api/v1/license/status', ({ request }) => {
        out.marks.push(request.headers.get('X-Alice-Activity'));
        out.keepalive.push(request.keepalive);
        return HttpResponse.json(statusWith());
      }),
    );
    return out;
  }

  it('sends a pending mark with one license status request when the tab is hidden or closed', async () => {
    server.use(...sessionHandlers(sessionFor('admin')));
    const seen = countStatus();
    await renderRoute('/');
    await screen.findByRole('heading', { level: 1, name: 'Overview' });
    await waitFor(() => expect(seen.marks.length).toBeGreaterThan(0));
    const before = seen.marks.length;

    activity.noteInput(keydown); // typed, then switched tabs before any request went out
    setVisibility('hidden');
    document.dispatchEvent(new Event('visibilitychange'));
    window.dispatchEvent(new Event('pagehide'));
    await waitFor(() => expect(seen.marks.length).toBe(before + 1));
    expect(seen.marks[before]).toBe('1');
    expect(seen.keepalive[before]).toBe(true); // it may outlive a closing page

    // Nothing pending: hiding the tab again sends nothing.
    document.dispatchEvent(new Event('visibilitychange'));
    window.dispatchEvent(new Event('pagehide'));
    await new Promise((r) => setTimeout(r, 50));
    expect(seen.marks.length).toBe(before + 1);
  });

  it('sends nothing when the tab is shown again', async () => {
    server.use(...sessionHandlers(sessionFor('operator')));
    await renderRoute('/');
    await screen.findByRole('heading', { level: 1, name: 'Overview' });
    const seen = countStatus();
    activity.noteInput(keydown);
    setVisibility('visible');
    document.dispatchEvent(new Event('visibilitychange'));
    await new Promise((r) => setTimeout(r, 50));
    expect(seen.marks).toEqual([]);
  });

  it('installs the listeners and the poll once under StrictMode', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const add = vi.spyOn(window, 'addEventListener');
    const remove = vi.spyOn(window, 'removeEventListener');
    const net = (type: string) =>
      add.mock.calls.filter(([t, fn]) => t === type && fn === activity.noteInput).length -
      remove.mock.calls.filter(([t, fn]) => t === type && fn === activity.noteInput).length;
    server.use(...sessionHandlers(sessionFor('admin')));
    const seen = countStatus();
    await renderRoute('/', { strict: true });
    await screen.findByRole('heading', { level: 1, name: 'Overview' });
    for (const type of ['pointerdown', 'click', 'keydown', 'wheel', 'touchstart']) expect(net(type), type).toBe(1);
    await vi.waitFor(() => expect(seen.marks.length).toBe(1));
    await vi.advanceTimersByTimeAsync(60_000);
    await vi.waitFor(() => expect(seen.marks.length).toBe(2));
    await vi.advanceTimersByTimeAsync(60_000);
    await vi.waitFor(() => expect(seen.marks.length).toBe(3));
    // The hidden-tab flush is not doubled either: one request for one pending mark.
    activity.noteInput(keydown);
    setVisibility('hidden');
    document.dispatchEvent(new Event('visibilitychange'));
    await vi.waitFor(() => expect(seen.marks.length).toBe(4));
    await vi.advanceTimersByTimeAsync(10);
    expect(seen.marks.length).toBe(4);
    expect(seen.marks[3]).toBe('1');
  });
});
