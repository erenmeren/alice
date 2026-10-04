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
    await screen.findByRole('heading', { name: 'Welcome, Ayşe Yılmaz' });
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
    await screen.findByRole('heading', { name: /^Welcome/ });
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
    await screen.findByRole('heading', { name: 'Welcome, Ayşe Yılmaz' });
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
