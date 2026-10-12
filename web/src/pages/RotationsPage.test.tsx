import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { adminSession, auditorSession, errorResponse, operatorSession, policyFixture, POLICY_ID, runFixture, sessionFor, sessionHandlers } from '../test/fixtures';
import { expectNoRawKeys } from '../test/i18nAssert';
import { renderRoute } from '../test/render';
import { server } from '../test/server';

const KEY_ID = '0192b000-0000-7000-8000-0000000000k1';

describe('RotationsPage', () => {
  it('lists every live policy and the runs that are not final, for every role', async () => {
    server.use(
      ...sessionHandlers(auditorSession),
      http.get('/api/v1/rotation/policies', () => HttpResponse.json({ items: [policyFixture({ id: POLICY_ID, name: 'deploy-production', enabled: true, open_rotation_id: 'r1' })] })),
      http.get('/api/v1/rotation/runs', () => HttpResponse.json({ items: [runFixture({ id: 'r1', status: 'overlap' }), runFixture({ id: 'r0', status: 'completed' })], next_cursor: null })),
    );
    await renderRoute('/rotations');
    expect(await screen.findByRole('heading', { level: 1, name: 'Key rotations' })).toBeVisible();
    expect(screen.getByRole('link', { name: 'Key rotations' })).toHaveAttribute('aria-current', 'page');
    const active = screen.getByRole('region', { name: 'Active rotations' });
    expect(within(active).getAllByRole('link', { name: 'Inspect run and locations' })).toHaveLength(1);
    expect(within(active).getByRole('link', { name: 'Inspect run and locations' })).toHaveAttribute('href', '/rotation/runs/r1');
    expect(screen.getByRole('table', { name: 'Rotation policies' })).toHaveTextContent('deploy-production');
    expect(screen.queryByRole('button', { name: /Create|Run now|Finish|Stop/ })).not.toBeInTheDocument();
  });

  it('says so when there is no policy and no running rotation', async () => {
    server.use(...sessionHandlers(operatorSession), http.get('/api/v1/rotation/policies', () => HttpResponse.json({ items: [] })), http.get('/api/v1/rotation/runs', () => HttpResponse.json({ items: [], next_cursor: null })));
    await renderRoute('/rotations');
    expect(await screen.findByText('No rotation is running.')).toBeVisible();
    expect(screen.getByText(/No rotation policy yet/)).toBeVisible();
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
  });

  it('shares the SSH key tabs: Inventory and Rotation policies, plain links, the current one marked', async () => {
    server.use(...sessionHandlers(adminSession));
    await renderRoute('/rotations');
    await screen.findByRole('heading', { level: 1, name: 'Key rotations' });
    const tabs = screen.getByRole('group', { name: 'SSH key sections' });
    expect(within(tabs).getByRole('link', { name: 'Inventory' })).toHaveAttribute('href', '/ssh-keys');
    expect(within(tabs).getByRole('link', { name: 'Inventory' })).not.toHaveAttribute('aria-current');
    expect(within(tabs).getByRole('link', { name: 'Rotation policies' })).toHaveAttribute('aria-current', 'page');
    expect(screen.queryByRole('tablist')).not.toBeInTheDocument();
    // Page-wide link names stay unique: the navigation's Key rotations and the tab are told apart.
    expect(screen.getAllByRole('link', { name: 'Key rotations' })).toHaveLength(1);
    expect(screen.getAllByRole('link', { name: 'Rotation policies' })).toHaveLength(1);
  });

  it('shows each active run with its key, status, time, progress and link; a paused run shows no countdown', async () => {
    server.use(
      ...sessionHandlers(adminSession),
      http.get('/api/v1/rotation/policies', () => HttpResponse.json({ items: [policyFixture({ id: POLICY_ID, name: 'deploy-production', enabled: true })] })),
      http.get('/api/v1/rotation/runs', () =>
        HttpResponse.json({
          items: [
            runFixture({ id: 'r1', status: 'overlap', overlap_until: '2026-10-13T08:05:00Z' }),
            runFixture({ id: 'r2', policy_id: 'gone', status: 'overlap', paused_license: true }),
            runFixture({ id: 'r3', status: 'dry_run_notified' }),
            runFixture({ id: 'r4', status: 'rolling_back' }),
            runFixture({ id: 'r5', status: 'aborted' }),
          ],
          next_cursor: null,
        }),
      ),
    );
    await renderRoute('/rotations');
    const active = await screen.findByRole('region', { name: 'Active rotations' });
    const items = await within(active).findAllByTestId('active-rotation');
    expect(items).toHaveLength(4);
    expect(within(items[0]).getByRole('heading', { level: 3, name: 'deploy-production' })).toBeInTheDocument();
    expect(within(items[0]).getByText('Both keys valid')).toBeInTheDocument();
    expect(within(items[0]).getByText(/^Both keys work until/)).toBeInTheDocument();
    expect(within(items[0]).getByRole('list', { name: 'Rotation progress' })).toBeInTheDocument();
    // A run whose policy is gone is named by its old key's fingerprint; a license pause shows no end time.
    expect(within(items[1]).getByText('SHA256:oldOldOldOldOldOldOldOldOldOldOldOldOld0').tagName).toBe('CODE');
    expect(within(items[1]).getByText('Paused')).toBeInTheDocument();
    expect(within(items[1]).getByText('The overlap is on hold: it resumes after you choose Continue, with the time that was left.')).toBeInTheDocument();
    expect(within(items[1]).queryByText(/^Both keys work until/)).not.toBeInTheDocument();
    expect(within(items[2]).getByText(/^Planned for/)).toBeInTheDocument();
    // Undoing is not progress: the badge and no path.
    expect(within(items[3]).getByText('Undoing')).toBeInTheDocument();
    expect(within(items[3]).queryByRole('list', { name: 'Rotation progress' })).not.toBeInTheDocument();
    expect(within(active).getByText('4 shown')).toBeInTheDocument();
    expectNoRawKeys();
  });

  it('loads further pages of runs with Show more, and does not claim nothing runs while pages remain', async () => {
    const cursors: (string | null)[] = [];
    server.use(
      ...sessionHandlers(operatorSession),
      http.get('/api/v1/rotation/runs', ({ request }) => {
        const cursor = new URL(request.url).searchParams.get('cursor');
        cursors.push(cursor);
        return cursor
          ? HttpResponse.json({ items: [runFixture({ id: 'r9', status: 'adding_new' })], next_cursor: null })
          : HttpResponse.json({ items: [runFixture({ id: 'r0', status: 'completed' })], next_cursor: 'c2' });
      }),
    );
    await renderRoute('/rotations');
    expect(await screen.findByText('No running rotation among the runs shown so far.')).toBeInTheDocument();
    expect(screen.queryByText('No rotation is running.')).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Show more' }));
    expect(await screen.findByRole('link', { name: 'Inspect run and locations' })).toHaveAttribute('href', '/rotation/runs/r9');
    expect(cursors).toEqual([null, 'c2']);
    expect(screen.queryByRole('button', { name: 'Show more' })).not.toBeInTheDocument();
  });

  it('shows each policy with its key link, interval, overlap, next run, state and run links', async () => {
    server.use(
      ...sessionHandlers(adminSession),
      http.get('/api/v1/rotation/policies', () =>
        HttpResponse.json({
          items: [
            policyFixture({ id: 'p1', name: 'deploy-production', enabled: true, next_run_at: '2026-11-01T08:00:00Z', last_run_id: 'r0', last_run_status: 'completed' }),
            policyFixture({ id: 'p2', name: 'ci-<b>deploy</b>', ssh_key_id: 'k2', enabled: true, interval_days: 1, overlap_minutes: 30, open_rotation_id: 'r1' }),
            policyFixture({ id: 'p3', name: 'quarterly', ssh_key_id: 'k3', enabled: false }),
          ],
        }),
      ),
    );
    await renderRoute('/rotations');
    const table = await screen.findByRole('table', { name: 'Rotation policies' });
    const rows = within(table).getAllByRole('row');
    expect(within(rows[0]).getAllByRole('columnheader').map((h) => h.textContent)).toEqual(['Policy / key', 'Interval', 'Overlap', 'Next run', 'Status', 'Runs']);
    expect(within(rows[1]).getByRole('link', { name: 'deploy-production' })).toHaveAttribute('href', `/ssh-keys/${KEY_ID}`);
    expect(rows[1]).toHaveTextContent('Every 90 days');
    expect(rows[1]).toHaveTextContent('7 days');
    expect(within(rows[1]).getByText('On')).toBeInTheDocument();
    expect(rows[1]).toHaveTextContent('Last run: Completed');
    expect(within(rows[1]).getByRole('link', { name: 'Open the last run' })).toHaveAttribute('href', '/rotation/runs/r0');
    expect(within(rows[1]).queryByRole('link', { name: 'Open the current run' })).not.toBeInTheDocument();
    expect(within(rows[2]).getByRole('link', { name: 'ci-<b>deploy</b>' })).toHaveAttribute('href', '/ssh-keys/k2');
    expect(document.querySelector('b')).toBeNull();
    expect(rows[2]).toHaveTextContent('Every day');
    expect(rows[2]).toHaveTextContent('30 minutes');
    expect(rows[2]).toHaveTextContent('In progress');
    expect(within(rows[2]).getByRole('link', { name: 'Open the current run' })).toHaveAttribute('href', '/rotation/runs/r1');
    expect(within(rows[3]).getByText('Off')).toBeInTheDocument();
    expect(rows[3]).toHaveTextContent('Not planned');
  });

  it('shows the error of a list it cannot read and keeps the other', async () => {
    server.use(
      ...sessionHandlers(adminSession),
      http.get('/api/v1/rotation/policies', () => errorResponse(500, 'ALC-SYS-0003', 'internal.unexpected')),
    );
    await renderRoute('/rotations');
    expect(await screen.findByRole('alert')).toBeInTheDocument();
    expect(await screen.findByText('No rotation is running.')).toBeInTheDocument();
  });

  it('shows the error of the run list too', async () => {
    server.use(...sessionHandlers(adminSession), http.get('/api/v1/rotation/runs', () => errorResponse(500, 'ALC-SYS-0003', 'internal.unexpected')));
    await renderRoute('/rotations');
    await waitFor(() => expect(screen.getAllByRole('alert')).toHaveLength(1));
    expect(screen.queryByText('No rotation is running.')).not.toBeInTheDocument();
  });

  it('renders in Turkish with no missing key', async () => {
    server.use(
      ...sessionHandlers(sessionFor('auditor', 'tr')),
      http.get('/api/v1/rotation/policies', () => HttpResponse.json({ items: [policyFixture({ enabled: true, open_rotation_id: 'r1' })] })),
      http.get('/api/v1/rotation/runs', () => HttpResponse.json({ items: [runFixture({ id: 'r1', status: 'overlap' })], next_cursor: null })),
    );
    await renderRoute('/rotations', { languages: ['tr-TR'] });
    expect(await screen.findByRole('heading', { level: 1, name: 'Anahtar rotasyonları' })).toBeVisible();
    expect(await screen.findByRole('table', { name: 'Rotasyon ilkeleri' })).toBeInTheDocument();
    expect(screen.getByText('Anahtar değişimini kontrollü bir geçişle yönetin.')).toBeInTheDocument();
    expectNoRawKeys();
  });
});
