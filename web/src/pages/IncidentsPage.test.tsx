import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import type { Incident } from '../api/incidents';
import { incidentFixture, sessionFor, sessionHandlers } from '../test/fixtures';
import { expectNoRawKeys } from '../test/i18nAssert';
import { renderRoute } from '../test/render';
import { server } from '../test/server';

const SECOND = '0192f100-0000-7000-8000-0000000000b2';

// list answers each request from pages (by cursor: '' is the first page) and records the query strings.
function list(pages: Record<string, { items: Incident[]; next_cursor: string | null }>, role: 'admin' | 'auditor' = 'auditor', lang = 'en') {
  const queries: URLSearchParams[] = [];
  server.use(
    ...sessionHandlers(sessionFor(role, lang)),
    http.get('/api/v1/incidents', ({ request }) => {
      const q = new URL(request.url).searchParams;
      queries.push(q);
      return HttpResponse.json(pages[q.get('cursor') ?? ''] ?? { items: [], next_cursor: null });
    }),
  );
  return queries;
}

describe('IncidentsPage (D2, HB-06)', () => {
  it('lists incidents newest first with their state and places', async () => {
    list({
      '': {
        items: [
          incidentFixture({ counts: { verified: 1, failed: 1 } }),
          incidentFixture({ id: SECOND, certificate_name: 'api.example.test', state: 'closed', counts: { verified: 2, skipped: 1 }, finished_at: '2026-10-21T09:00:00Z' }),
        ],
        next_cursor: null,
      },
    });
    await renderRoute('/incidents');
    expect(await screen.findByRole('heading', { name: 'Key compromise incidents' })).toBeInTheDocument();
    const table = await screen.findByRole('table', { name: 'Incidents' });
    const rows = within(table).getAllByRole('row').slice(1);
    expect(rows).toHaveLength(2);
    expect(rows[0]).toHaveTextContent('Needs attention');
    expect(rows[0]).toHaveTextContent('1 of 2 replaced');
    expect(rows[0]).toHaveTextContent('Ada');
    expect(rows[1]).toHaveTextContent('Closed');
    expect(rows[1]).toHaveTextContent('2 of 2 replaced');
    const link = within(rows[0]).getByRole('link', { name: incidentFixture().certificate_name });
    expect(link).toHaveAttribute('href', `/incidents/${incidentFixture().id}`);
    expect(within(rows[1]).getByRole('link', { name: 'api.example.test' })).toHaveAttribute('href', `/incidents/${SECOND}`);
    expectNoRawKeys();
  });

  it('sends the filter', async () => {
    const queries = list({ '': { items: [incidentFixture()], next_cursor: null } });
    await renderRoute('/incidents');
    await screen.findByRole('table', { name: 'Incidents' });
    expect(queries[0].get('open')).toBeNull();
    expect(queries[0].get('state')).toBeNull();
    expect(queries[0].get('limit')).toBe('50');
    await userEvent.click(screen.getByRole('radio', { name: 'Open' }));
    await waitFor(() => expect(queries.at(-1)?.get('open')).toBe('true'));
    expect(queries.at(-1)?.get('state')).toBeNull();
    await userEvent.click(screen.getByRole('radio', { name: 'Needs attention' }));
    await waitFor(() => expect(queries.at(-1)?.get('state')).toBe('needs_attention'));
    expect(queries.at(-1)?.get('open')).toBeNull();
  });

  it('pages through incidents with Load more', async () => {
    const queries = list({
      '': { items: [incidentFixture()], next_cursor: 'c1' },
      c1: { items: [incidentFixture({ id: SECOND, certificate_name: 'api.example.test' })], next_cursor: null },
    });
    await renderRoute('/incidents');
    await screen.findByRole('link', { name: incidentFixture().certificate_name });
    await userEvent.click(screen.getByRole('button', { name: 'Show more incidents' }));
    expect(await screen.findByRole('link', { name: 'api.example.test' })).toBeInTheDocument();
    expect(queries.at(-1)?.get('cursor')).toBe('c1');
    expect(within(screen.getByRole('table', { name: 'Incidents' })).getAllByRole('row')).toHaveLength(3);
    expect(screen.queryByRole('button', { name: 'Show more incidents' })).not.toBeInTheDocument();
  });

  it('shows the empty states', async () => {
    list({});
    await renderRoute('/incidents');
    expect(await screen.findByText('No incidents.')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('radio', { name: 'Completed' }));
    expect(await screen.findByText('No incidents match this filter.')).toBeInTheDocument();
  });

  it('opens an incident whose back link returns to the list', async () => {
    list({ '': { items: [incidentFixture()], next_cursor: null } }, 'admin');
    server.use(http.get(`/api/v1/incidents/${incidentFixture().id}`, () => HttpResponse.json(incidentFixture())));
    await renderRoute('/incidents');
    await userEvent.click(await screen.findByRole('link', { name: incidentFixture().certificate_name }));
    expect(await screen.findByRole('heading', { name: 'Key compromise incident' })).toBeInTheDocument();
    const back = screen.getAllByRole('link', { name: 'Incidents' }).filter((l) => l.getAttribute('aria-current') !== 'page');
    expect(back).toHaveLength(1);
    expect(back[0]).toHaveAttribute('href', '/incidents');
    expect(screen.queryByRole('link', { name: 'Certificate' })).not.toBeInTheDocument();
  });

  it('renders in Turkish', async () => {
    list({ '': { items: [incidentFixture()], next_cursor: null } }, 'auditor', 'tr');
    await renderRoute('/incidents', { languages: ['tr-TR'] });
    expect(await screen.findByRole('heading', { name: 'Anahtar ele geçirme olayları' })).toBeInTheDocument();
    expect(await screen.findByText('2 yerin 1 tanesi değiştirildi')).toBeInTheDocument();
    expectNoRawKeys();
  });
});
