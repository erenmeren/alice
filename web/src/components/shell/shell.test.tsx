import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { adminSession, errorResponse, operatorSession, sessionHandlers, vaultFixture } from '../../test/fixtures';
import { renderRoute } from '../../test/render';
import { server } from '../../test/server';

describe('command palette', () => {
  it('opens with Ctrl+K and lists only the pages the role may open', async () => {
    server.use(...sessionHandlers(operatorSession));
    await renderRoute('/');
    await screen.findByRole('navigation', { name: 'Main navigation' });
    await userEvent.keyboard('{Control>}k{/Control}');
    const dialog = await screen.findByRole('dialog', { name: 'Go to a page' });
    await userEvent.type(await screen.findByRole('textbox', { name: 'Find a page…' }), 'audit');
    expect(dialog).toHaveTextContent('No page matches.');
  });
  it('opens the first match with Enter', async () => {
    server.use(...sessionHandlers(adminSession), http.get('/api/v1/audit', () => HttpResponse.json({ items: [], next_cursor: null })));
    const { router } = await renderRoute('/');
    await userEvent.click(await screen.findByRole('button', { name: 'Search pages' }));
    await userEvent.type(await screen.findByRole('textbox', { name: 'Find a page…' }), 'audit{Enter}');
    await waitFor(() => expect(router.state.location.pathname).toBe('/audit'));
    // The modal leaves after its closing transition.
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Go to a page' })).not.toBeInTheDocument());
  });
  it('opens a page by its link, and Escape closes the palette and forgets the query', async () => {
    server.use(...sessionHandlers(adminSession));
    const { router } = await renderRoute('/');
    const trigger = await screen.findByRole('button', { name: 'Search pages' });
    await userEvent.click(trigger);
    await userEvent.type(await screen.findByRole('textbox', { name: 'Find a page…' }), 'lic');
    await userEvent.keyboard('{Escape}');
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Go to a page' })).not.toBeInTheDocument());
    await userEvent.click(trigger);
    expect(await screen.findByRole('textbox', { name: 'Find a page…' })).toHaveValue('');
    const dialog = screen.getByRole('dialog', { name: 'Go to a page' });
    expect(dialog).toHaveTextContent('Only pages you can open');
    await userEvent.click(within(dialog).getByRole('link', { name: 'License' }));
    await waitFor(() => expect(router.state.location.pathname).toBe('/license'));
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Go to a page' })).not.toBeInTheDocument());
  });
  it('does nothing on Enter when no page matches', async () => {
    server.use(...sessionHandlers(adminSession));
    const { router } = await renderRoute('/');
    await userEvent.click(await screen.findByRole('button', { name: 'Search pages' }));
    await userEvent.type(await screen.findByRole('textbox', { name: 'Find a page…' }), 'zzz{Enter}');
    expect(screen.getByRole('dialog', { name: 'Go to a page' })).toHaveTextContent('No page matches.');
    expect(router.state.location.pathname).toBe('/');
  });
});

describe('attention bell', () => {
  it('reads /alerts only while open and shows each condition with its place', async () => {
    let reads = 0;
    server.use(
      ...sessionHandlers(adminSession),
      http.get('/api/v1/alerts', () => {
        reads++;
        return HttpResponse.json({ items: [{ kind: 'host_key_changed', object_id: 't1', name: 'seed-web-3', since: '2026-10-12T08:00:00Z', error_code: '' }] });
      }),
    );
    await renderRoute('/license');
    await screen.findByRole('navigation', { name: 'Main navigation' });
    expect(reads).toBe(0);
    await userEvent.click(screen.getByRole('button', { name: 'View attention items' }));
    const name = await screen.findByText('seed-web-3', { exact: true });
    await waitFor(() => expect(name).toBeVisible()); // after the popover's opening transition
    expect(screen.getByRole('link', { name: /Server identity changed/ })).toHaveAttribute('href', '/servers/t1');
    expect(reads).toBe(1);
  });

  it('links a Key Vault sign-in failure to the vault, closes when a row is chosen and offers the overview', async () => {
    server.use(
      ...sessionHandlers(adminSession),
      http.get('/api/v1/alerts', () =>
        HttpResponse.json({
          items: [
            { kind: 'auth_failed', object_id: vaultFixture.id, name: vaultFixture.name, since: '2026-10-12T08:00:00Z', error_code: '' },
            { kind: 'something_new', object_id: 'x', name: 'x', since: '2026-10-12T08:00:00Z', error_code: '' },
          ],
        }),
      ),
      http.get('/api/v1/targets', () => HttpResponse.json({ items: [vaultFixture], next_cursor: null })),
    );
    const { router } = await renderRoute('/license');
    const bell = await screen.findByRole('button', { name: 'View attention items' });
    await userEvent.click(bell);
    const row = await screen.findByRole('link', { name: /Sign-in refused/ });
    await waitFor(() => expect(row).toHaveAttribute('href', `/key-vaults/${vaultFixture.id}`));
    expect(screen.getAllByRole('listitem')).toHaveLength(1); // the unknown kind is not shown
    await userEvent.click(row);
    await waitFor(() => expect(router.state.location.pathname).toBe(`/key-vaults/${vaultFixture.id}`));
    await waitFor(() => expect(screen.queryByRole('link', { name: 'Open the overview' })).not.toBeInTheDocument());
    await userEvent.click(bell);
    await userEvent.click(await screen.findByRole('link', { name: 'Open the overview' }));
    await waitFor(() => expect(router.state.location.pathname).toBe('/'));
  });

  it('starts at its title while loading and gives focus back to the bell when Escape closes it', async () => {
    let release: () => void = () => undefined;
    const answered = new Promise<void>((r) => {
      release = r;
    });
    server.use(
      ...sessionHandlers(adminSession),
      http.get('/api/v1/alerts', async () => {
        await answered;
        return HttpResponse.json({ items: [] });
      }),
    );
    await renderRoute('/license');
    const bell = await screen.findByRole('button', { name: 'View attention items' });
    bell.focus();
    await userEvent.keyboard('{Enter}');
    // The rows are still loading: focus starts at the popover's title, not at the footer link after the rows.
    await waitFor(() => expect(screen.getByText('Needs attention')).toHaveFocus());
    release();
    expect(await screen.findByText('Nothing needs your attention.')).toBeInTheDocument();
    await userEvent.keyboard('{Escape}');
    await waitFor(() => expect(screen.queryByText('Nothing needs your attention.')).not.toBeInTheDocument());
    await waitFor(() => expect(bell).toHaveFocus());
  });

  it('says when nothing needs attention, and shows a failed read', async () => {
    server.use(...sessionHandlers(adminSession), http.get('/api/v1/alerts', () => HttpResponse.json({ items: [] })));
    await renderRoute('/license');
    const bell = await screen.findByRole('button', { name: 'View attention items' });
    await userEvent.click(bell);
    expect(await screen.findByText('Nothing needs your attention.')).toBeInTheDocument();
    await userEvent.click(bell);
    await waitFor(() => expect(screen.queryByText('Nothing needs your attention.')).not.toBeInTheDocument());
    server.use(http.get('/api/v1/alerts', () => errorResponse(500, 'ALC-SYS-0003', 'internal.unexpected')));
    await userEvent.click(bell);
    expect(await screen.findByText(/ALC-SYS-0003/)).toBeInTheDocument();
  });
});
