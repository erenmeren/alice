import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { scopedSession, sessionHandlers } from '../test/fixtures';
import { expectNoRawKeys } from '../test/i18nAssert';
import { renderRoute } from '../test/render';
import { server } from '../test/server';

const linkNames = () =>
  within(screen.getByRole('navigation', { name: /navigation|gezinme/i }))
    .queryAllByRole('link')
    .map((a) => a.textContent ?? '');

describe('NoAccessPage', () => {
  it.each(['/', '/certificates', '/users', '/services', '/account'])('is the only page of a person with no role anywhere (%s)', async (path) => {
    server.use(...sessionHandlers(scopedSession([])));
    await renderRoute(path);
    expect(await screen.findByRole('heading', { level: 1, name: 'You do not have access to anything yet.' })).toBeInTheDocument();
    expect(screen.getByText('Ask an Administrator.')).toBeInTheDocument();
    expect(linkNames()).toEqual([]);
    expect(screen.getByTestId('current-user')).toHaveTextContent('Deniz Kaya');
    expect(screen.getByText('No role on all services')).toBeInTheDocument();
  });

  it('still signs out', async () => {
    let loggedOut = false;
    server.use(
      ...sessionHandlers(scopedSession([])),
      http.post('/api/v1/auth/logout', () => {
        loggedOut = true;
        return new HttpResponse(null, { status: 204 });
      }),
    );
    const { router } = await renderRoute('/certificates');
    const page = await screen.findByTestId('no-access');
    await userEvent.click(within(page).getByRole('button', { name: 'Sign out' }));
    await waitFor(() => expect(router.state.location.pathname).toBe('/login'));
    expect(loggedOut).toBe(true);
  });

  it('is Turkish in Turkish', async () => {
    server.use(...sessionHandlers(scopedSession([], 'tr')));
    await renderRoute('/', { languages: ['tr'] });
    expect(await screen.findByRole('heading', { level: 1, name: 'Henüz hiçbir şeye erişiminiz yok.' })).toBeInTheDocument();
    expect(screen.getByText('Bir yöneticiye başvurun.')).toBeInTheDocument();
    expect(screen.getByText('Tüm hizmetlerde rol yok')).toBeInTheDocument();
    expectNoRawKeys(document.body);
  });
});
