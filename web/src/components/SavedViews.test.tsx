import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse, type RequestHandler } from 'msw';
import { errorResponse, operatorSession, sessionHandlers, targetFixture } from '../test/fixtures';
import { renderRoute } from '../test/render';
import { server } from '../test/server';

const view = { id: 'v1', page: 'certificates', name: 'Web 1 soon', query: { expiry: '30', target_id: targetFixture.id }, created_at: '2026-10-07T09:00:00Z' };

function base(extra: RequestHandler[] = []) {
  server.use(
    ...sessionHandlers(operatorSession),
    http.get('/api/v1/targets', () => HttpResponse.json({ items: [targetFixture], next_cursor: null })),
    http.get('/api/v1/certificates/csr', () => HttpResponse.json({ items: [] })),
    http.get('/api/v1/certificates', () => HttpResponse.json({ items: [], next_cursor: null })),
    ...extra,
  );
}

describe('SavedViews', () => {
  it('saves the current filters and applies a saved view', async () => {
    let posted: unknown;
    base([
      http.get('/api/v1/views', () => HttpResponse.json({ items: [view] })),
      http.post('/api/v1/views', async ({ request }) => {
        posted = await request.json();
        return HttpResponse.json({ id: 'v2', page: 'certificates', name: 'Expired', query: { expiry: 'expired' }, created_at: '2026-10-07T09:00:00Z' }, { status: 201 });
      }),
    ]);
    const { router } = await renderRoute('/certificates?expiry=expired');
    await userEvent.click(await screen.findByRole('button', { name: 'Save view' }));
    await userEvent.type(within(await screen.findByRole('dialog')).getByLabelText('Name of the view'), 'Expired');
    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Save view' }));
    await waitFor(() => expect(posted).toEqual({ page: 'certificates', name: 'Expired', query: { expiry: 'expired' } }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    await userEvent.click(screen.getByRole('button', { name: 'Saved views' }));
    await userEvent.click(await screen.findByRole('menuitem', { name: 'Web 1 soon' }));
    await waitFor(() => expect(new URLSearchParams(router.state.location.search).get('target_id')).toBe(targetFixture.id));
    expect(new URLSearchParams(router.state.location.search).get('expiry')).toBe('30');
  });

  it('holds only menu items in the open menu (axe aria-required-children) and draws the delete item in red 9 (axe color-contrast)', async () => {
    base([http.get('/api/v1/views', () => HttpResponse.json({ items: [view] }))]);
    await renderRoute('/certificates');
    await userEvent.click(await screen.findByRole('button', { name: 'Saved views' }));
    const menu = await screen.findByRole('menu');
    expect([...menu.children].map((el) => el.getAttribute('role'))).toEqual(['menuitem', 'menuitem']);
    // red 6 text is 3.3:1 on white; red 9 is above 4.5:1 (WCAG AA).
    expect(within(menu).getByRole('menuitem', { name: 'Delete view Web 1 soon', hidden: true }).getAttribute('style')).toContain('color: var(--mantine-color-red-9)');
  });

  it('clears every other filter key when a view is applied', async () => {
    base([http.get('/api/v1/views', () => HttpResponse.json({ items: [view] }))]);
    const { router } = await renderRoute('/certificates?source=csr&q=zzz');
    await userEvent.click(await screen.findByRole('button', { name: 'Saved views' }));
    await userEvent.click(await screen.findByRole('menuitem', { name: 'Web 1 soon' }));
    await waitFor(() => expect(new URLSearchParams(router.state.location.search).get('expiry')).toBe('30'));
    const p = new URLSearchParams(router.state.location.search);
    expect(p.get('source')).toBeNull();
    expect(p.get('q')).toBeNull();
  });

  it('deletes a view with its own menu item', async () => {
    let deleted = '';
    base([
      http.get('/api/v1/views', () => HttpResponse.json({ items: [view] })),
      http.delete('/api/v1/views/:id', ({ params }) => {
        deleted = String(params.id);
        return new HttpResponse(null, { status: 204 });
      }),
    ]);
    await renderRoute('/certificates');
    await userEvent.click(await screen.findByRole('button', { name: 'Saved views' }));
    await userEvent.click(await screen.findByRole('menuitem', { name: 'Delete view Web 1 soon' }));
    await waitFor(() => expect(deleted).toBe('v1'));
  });

  it.each([
    ['ALC-RPT-0003', 'views.name_taken', undefined, 'A saved view with this name already exists.'],
    ['ALC-RPT-0002', 'views.limit_reached', { max: '50' }, 'You have reached the limit of saved views.'],
  ])('shows the text of %s when saving is refused', async (code, reason, params, title) => {
    base([
      http.get('/api/v1/views', () => HttpResponse.json({ items: [] })),
      http.post('/api/v1/views', () => errorResponse(409, code, reason, { params })),
    ]);
    await renderRoute('/certificates');
    await userEvent.click(await screen.findByRole('button', { name: 'Save view' }));
    await userEvent.type(within(await screen.findByRole('dialog')).getByLabelText('Name of the view'), 'Again');
    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Save view' }));
    expect(await within(screen.getByRole('dialog')).findByText(title)).toBeInTheDocument();
  });

  it('shows a failed delete even when the list failed as well', async () => {
    let reads = 0;
    base([
      http.get('/api/v1/views', () => (++reads === 1 ? HttpResponse.json({ items: [view] }) : errorResponse(500, 'ALC-SYS-0003', 'internal.unexpected'))),
      http.delete('/api/v1/views/:id', () => errorResponse(404, 'ALC-SYS-0001', 'system.not_found')),
    ]);
    const { client } = await renderRoute('/certificates');
    await userEvent.click(await screen.findByRole('button', { name: 'Saved views' }));
    await userEvent.click(await screen.findByRole('menuitem', { name: 'Delete view Web 1 soon' }));
    await waitFor(() => expect(screen.getAllByRole('alert').length).toBeGreaterThan(0));
    await client.invalidateQueries({ queryKey: ['views', 'certificates'] });
    await waitFor(() => expect(screen.getAllByRole('alert')).toHaveLength(2));
  });

  it('counts characters, not UTF-16 units: 60 emoji are allowed, 61 are refused on the field', async () => {
    let posted: { name?: string } | undefined;
    base([
      http.get('/api/v1/views', () => HttpResponse.json({ items: [] })),
      http.post('/api/v1/views', async ({ request }) => {
        posted = (await request.json()) as { name?: string };
        return HttpResponse.json({ id: 'v9', page: 'certificates', name: posted.name, query: {}, created_at: '2026-10-07T09:00:00Z' }, { status: 201 });
      }),
    ]);
    await renderRoute('/certificates');
    await userEvent.click(await screen.findByRole('button', { name: 'Save view' }));
    const dialog = await screen.findByRole('dialog');
    const field = within(dialog).getByLabelText('Name of the view');
    await userEvent.click(field);
    await userEvent.paste('😀'.repeat(61));
    expect(within(dialog).getByText('A name can have at most 60 characters.')).toBeInTheDocument();
    expect(within(dialog).getByRole('button', { name: 'Save view' })).toBeDisabled();
    await userEvent.clear(field);
    await userEvent.paste('😀'.repeat(60));
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save view' }));
    await waitFor(() => expect([...(posted?.name ?? '')]).toHaveLength(60));
  });
});
