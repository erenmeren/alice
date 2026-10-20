import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { adminSession, environmentFixture, PRODUCTION_ID, sessionHandlers } from '../../test/fixtures';
import { renderRoute } from '../../test/render';
import { server } from '../../test/server';

const steppedUp = { ...adminSession, stepup_until: '2099-01-01T00:00:00Z' };

function environments() {
  const seen: { method: string; path: string; body: unknown; ifMatch: string | null }[] = [];
  const record = async (request: Request) =>
    seen.push({ method: request.method, path: new URL(request.url).pathname, body: request.method === 'DELETE' ? null : await request.json(), ifMatch: request.headers.get('If-Match') });
  server.use(
    ...sessionHandlers(steppedUp),
    http.get('/api/v1/environments', () =>
      HttpResponse.json({ items: [environmentFixture(), environmentFixture({ id: 'e2', key: 'lab', name: 'Lab', sort: 50, services: 0, version: 3 })] }),
    ),
    http.post('/api/v1/environments', async ({ request }) => {
      await record(request);
      return HttpResponse.json(environmentFixture({ id: 'e3', key: 'qa', name: 'QA', sort: 60 }), { status: 201 });
    }),
    http.patch('/api/v1/environments/:id', async ({ request }) => {
      await record(request);
      return HttpResponse.json(environmentFixture());
    }),
    http.delete('/api/v1/environments/:id', async ({ request }) => {
      await record(request);
      return new HttpResponse(null, { status: 204 });
    }),
  );
  return seen;
}

describe('EnvironmentsSettings', () => {
  it('lists the environments, a seeded one in the reader’s language, and deletes only an unused one', async () => {
    const seen = environments();
    await renderRoute('/settings?tab=environments');
    const table = await screen.findByTestId('environments-table');
    const rows = within(table).getAllByRole('row').slice(1);
    expect(within(rows[0]).getByText('Production')).toBeInTheDocument();
    expect(within(rows[0]).getByRole('button', { name: 'Delete' })).toBeDisabled();
    await userEvent.click(within(rows[1]).getByRole('button', { name: 'Delete' }));
    await waitFor(() => expect(seen).toEqual([{ method: 'DELETE', path: '/api/v1/environments/e2', body: null, ifMatch: '"3"' }]));
  });

  it('adds an environment after the last one, and refuses a key it cannot store', async () => {
    const seen = environments();
    await renderRoute('/settings?tab=environments');
    await screen.findByTestId('environments-table');
    const key = screen.getByRole('textbox', { name: /^Key/ });
    await userEvent.type(key, 'QA');
    expect(screen.getByText('Use lowercase letters, digits and dashes, starting with a letter.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Add environment' })).toBeDisabled();
    await userEvent.clear(key);
    await userEvent.type(key, 'qa');
    await userEvent.type(screen.getByRole('textbox', { name: 'Name' }), 'QA');
    await userEvent.click(screen.getByRole('button', { name: 'Add environment' }));
    await waitFor(() => expect(seen).toEqual([{ method: 'POST', path: '/api/v1/environments', body: { key: 'qa', name: 'QA', sort: 60 }, ifMatch: null }]));
  });

  it('renames and reorders an environment with its version', async () => {
    const seen = environments();
    await renderRoute('/settings?tab=environments');
    const table = await screen.findByTestId('environments-table');
    await userEvent.click(within(table).getAllByRole('button', { name: 'Rename' })[0]);
    const dialog = await screen.findByRole('dialog', { name: 'Rename production' });
    const name = within(dialog).getByRole('textbox', { name: /Name/ });
    expect(name).toHaveValue('Production');
    await userEvent.clear(name);
    await userEvent.type(name, 'Live');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(seen).toEqual([{ method: 'PATCH', path: `/api/v1/environments/${PRODUCTION_ID}`, body: { name: 'Live', sort: 10 }, ifMatch: '"1"' }]));
  });
});
