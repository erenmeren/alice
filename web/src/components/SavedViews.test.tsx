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

  it('shows the server error when saving is refused', async () => {
    base([
      http.get('/api/v1/views', () => HttpResponse.json({ items: [] })),
      // A stand-in pair of the existing catalogue: the ALC-RPT-* pairs arrive with Task 14 (errorPairs.test.ts checks the Go table).
      http.post('/api/v1/views', () => errorResponse(409, 'ALC-USR-0001', 'user.username_taken')),
    ]);
    await renderRoute('/certificates');
    await userEvent.click(await screen.findByRole('button', { name: 'Save view' }));
    await userEvent.type(within(await screen.findByRole('dialog')).getByLabelText('Name of the view'), 'Again');
    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Save view' }));
    expect(await within(screen.getByRole('dialog')).findByRole('alert')).toBeInTheDocument();
  });
});
