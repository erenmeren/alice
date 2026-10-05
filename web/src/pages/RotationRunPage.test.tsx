import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import type { Run } from '../api/rotation';
import { errorResponse, runFixture, runLocationFixture, RUN_ID, sessionFor, sessionHandlers } from '../test/fixtures';
import { expectNoRawKeys } from '../test/i18nAssert';
import { renderRoute } from '../test/render';
import { server } from '../test/server';

const BASE = `/api/v1/rotation/runs/${RUN_ID}`;

function serve(run: Run, role: 'admin' | 'operator' | 'auditor' = 'admin', lang = 'en') {
  const counts = { reads: 0 };
  server.use(
    ...sessionHandlers(sessionFor(role, lang)),
    http.get(BASE, () => (counts.reads++, HttpResponse.json(run))),
  );
  return counts;
}
const open = (lang = 'en-US') => renderRoute(`/rotation/runs/${RUN_ID}`, { languages: [lang] });

describe('RotationRunPage', () => {
  it.each([
    ['dry_run_notified', 'Planned'],
    ['adding_new', 'Adding the new key'],
    ['verifying_new', 'Waiting for a decision'],
    ['overlap', 'Both keys valid'],
    ['removing_old', 'Removing the old key'],
    ['completed', 'Completed'],
    ['rolling_back', 'Undoing'],
    ['aborted', 'Undone'],
    ['needs_attention', 'Needs attention'],
    ['cancelled', 'Cancelled'],
  ])('labels the status %s as %s', async (status, label) => {
    serve(runFixture({ status }));
    await open();
    expect(await screen.findByRole('heading', { name: 'Key rotation', level: 1 })).toBeInTheDocument();
    expect(screen.getAllByText(label).length).toBeGreaterThan(0);
    expectNoRawKeys();
  });

  it('labels a status this version does not know generically', async () => {
    serve(runFixture({ status: 'from_the_future' }));
    await open();
    expect((await screen.findAllByText('Unknown')).length).toBeGreaterThan(0);
  });

  it('shows both fingerprints as non-translated code, the overlap end and the trigger', async () => {
    serve(runFixture());
    await open();
    const old = await screen.findByText('SHA256:oldOldOldOldOldOldOldOldOldOldOldOldOld0');
    expect(old.tagName).toBe('CODE');
    expect(old).toHaveAttribute('translate', 'no');
    expect(screen.getByText('SHA256:newNewNewNewNewNewNewNewNewNewNewNewNew0')).toBeInTheDocument();
    expect(screen.getByText(/^Both keys work until/)).toBeInTheDocument();
    expect(screen.getByText('Started by an administrator')).toBeInTheDocument();
  });

  it.each([
    [[], []],
    [['continue'], ['Continue']],
    [['finish_now', 'abort'], ['Finish now', 'Stop and undo']],
    [['keep_old', 'abort'], ['Keep the old key on these servers', 'Stop and undo']],
    [['continue', 'finish_now', 'keep_old', 'abort'], ['Continue', 'Finish now', 'Keep the old key on these servers', 'Stop and undo']],
  ] as const)('offers exactly the buttons of actions_allowed %j', async (allowed, names) => {
    serve(runFixture({ actions_allowed: [...allowed] }));
    await open();
    await screen.findByRole('heading', { name: 'Key rotation', level: 1 });
    const all = ['Continue', 'Finish now', 'Keep the old key on these servers', 'Stop and undo'];
    for (const n of all) expect(screen.queryByRole('button', { name: n }) !== null).toBe((names as readonly string[]).includes(n));
  });

  it('shows the paused banner and explains why Continue is not there yet', async () => {
    serve(runFixture({ status: 'overlap', paused_license: true, actions_allowed: ['abort'] }));
    await open();
    expect(await screen.findByText(/Paused: the license expired or could not be checked/)).toBeInTheDocument();
    expect(screen.getByText('Alice is still preparing the email about the license renewal.')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Open the license page' })).toHaveAttribute('href', '/license');
    expect(screen.getByText(/You can still stop and undo the rotation/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Continue' })).not.toBeInTheDocument();
  });

  it('shows Continue without the explanation once the API offers it, and sends it', async () => {
    serve(runFixture({ paused_license: true, actions_allowed: ['continue', 'abort'] }));
    let posted = 0;
    server.use(http.post(`${BASE}/actions/continue`, () => (posted++, new HttpResponse(null, { status: 204 }))));
    await open();
    await userEvent.click(await screen.findByRole('button', { name: 'Continue' }));
    await waitFor(() => expect(posted).toBe(1));
    expect(screen.queryByText('Alice is still preparing the email about the license renewal.')).not.toBeInTheDocument();
  });

  it('asks for the step-up code on a decision when the server wants one', async () => {
    serve(runFixture({ actions_allowed: ['continue'], paused_license: true }));
    let posted = 0;
    server.use(
      http.post(`${BASE}/actions/continue`, () => (++posted === 1 ? errorResponse(403, 'ALC-AUTH-0003', 'auth.stepup_required') : new HttpResponse(null, { status: 204 }))),
      http.post('/api/v1/auth/stepup', () => HttpResponse.json(sessionFor('admin'))),
    );
    const user = userEvent.setup();
    await open();
    await user.click(await screen.findByRole('button', { name: 'Continue' }));
    await user.type(await screen.findByLabelText('6-digit code'), '123456');
    await user.click(screen.getByRole('button', { name: 'Confirm' }));
    await waitFor(() => expect(posted).toBe(2));
  });

  it('finishes now after the confirmation text', async () => {
    serve(runFixture({ actions_allowed: ['finish_now'] }));
    let posted = 0;
    server.use(http.post(`${BASE}/actions/finish-now`, () => (posted++, new HttpResponse(null, { status: 204 }))));
    await open();
    await userEvent.click(await screen.findByRole('button', { name: 'Finish now' }));
    const dialog = await screen.findByRole('dialog', { name: 'Finish now' });
    expect(within(dialog).getByText('Alice checks the new key once more on each server, then removes the old key.')).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Finish now' }));
    await waitFor(() => expect(posted).toBe(1));
  });

  it('stops and undoes without a step-up prompt when the server does not ask for one', async () => {
    serve(runFixture({ actions_allowed: ['abort'] }));
    let posted = 0;
    server.use(http.post(`${BASE}/actions/abort`, () => (posted++, new HttpResponse(null, { status: 204 }))));
    await open();
    await userEvent.click(await screen.findByRole('button', { name: 'Stop and undo' }));
    const dialog = await screen.findByRole('dialog', { name: 'Stop and undo' });
    expect(within(dialog).getByText('Stop the rotation and remove the new key where Alice added it? The old key stays.')).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Stop and undo' }));
    await waitFor(() => expect(posted).toBe(1));
    expect(screen.queryByLabelText('6-digit code')).not.toBeInTheDocument();
  });

  it('keeps the old key on the checked untestable places only', async () => {
    const a = runLocationFixture({ id: 'u1', state: 'unverifiable', verify_note: 'root_login_disabled', os_user: 'root' });
    const b = runLocationFixture({ id: 'u2', n: 2, state: 'unverifiable', target_name: 'db-01', os_user: 'ops' });
    serve(runFixture({ status: 'verifying_new', awaiting_decision: true, decision_due_at: '2026-10-20T08:00:00Z', actions_allowed: ['keep_old', 'abort'], locations: [a, b, runLocationFixture({ id: 'v1', n: 3 })] }));
    let body: unknown;
    server.use(http.post(`${BASE}/actions/keep-old`, async ({ request }) => ((body = await request.json()), new HttpResponse(null, { status: 204 }))));
    const user = userEvent.setup();
    await open();
    expect(await screen.findByText(/^Decide before/)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Keep the old key on these servers' }));
    const dialog = await screen.findByRole('dialog', { name: 'Keep the old key on these servers' });
    expect(within(dialog).getAllByRole('checkbox')).toHaveLength(2);
    expect(within(dialog).getByRole('button', { name: 'Keep the old key on these servers' })).toBeDisabled();
    await user.click(within(dialog).getByRole('checkbox', { name: /db-01, ops/ }));
    await user.click(within(dialog).getByRole('button', { name: 'Keep the old key on these servers' }));
    await waitFor(() => expect(body).toEqual({ location_ids: ['u2'] }));
  });

  it('shows the places with state, skip reason, note, error title, code and backup in code', async () => {
    serve(
      runFixture({
        status: 'needs_attention',
        kept_count: 2,
        result: { code: 'ALC-ROT-0009', reason: 'rotation.remove_incomplete' },
        locations: [
          runLocationFixture({ id: 'a', state: 'skipped', skip_reason: 'host_key_changed' }),
          runLocationFixture({ id: 'b', n: 2, state: 'remove_failed', error: { code: 'ALC-ROT-0015', reason: 'rotation.new_key_failed' }, backup: '/var/backups/<b>x</b>' }),
          runLocationFixture({ id: 'c', n: 3, state: 'kept_old', target_name: '<i>evil</i>' }),
          runLocationFixture({ id: 'd', n: 4, state: 'undo_failed', error: { code: 'ALC-ROT-0018', reason: 'rotation.old_key_gone' } }),
        ],
      }),
    );
    await open();
    const rows = await screen.findAllByTestId('run-location');
    expect(within(rows[0]).getByText("The server's identity changed.")).toBeInTheDocument();
    expect(within(rows[0]).getByText('Skipped')).toBeInTheDocument();
    expect(within(rows[1]).getByText('Old key not removed')).toBeInTheDocument();
    expect(within(rows[1]).getByText(/ALC-ROT-0015/)).toBeInTheDocument();
    expect(within(rows[1]).getByText('/var/backups/<b>x</b>').tagName).toBe('CODE');
    expect(within(rows[2]).getByText('<i>evil</i>')).toHaveAttribute('translate', 'no');
    expect(document.querySelector('i')).toBeNull();
    expect(within(rows[3]).getByText('Check this')).toBeInTheDocument();
    expect(screen.getByText('Places where the old key stays: 2')).toBeInTheDocument();
    expect(screen.getByRole('alert')).toBeInTheDocument();
    expectNoRawKeys();
  });

  it('shows a late result step and an undone run with an old key that was gone as warnings, not successes', async () => {
    serve(
      runFixture({
        status: 'needs_attention',
        result: { code: 'ALC-ROT-0022', reason: 'rotation.late_result' },
        steps: [
          { n: 1, location_id: null, name: 'adding_new', status: 'ok', at: '2026-10-06T08:00:00Z', params: {} },
          { n: 2, location_id: 'rl1', name: 'late_result', status: 'ok', at: '2026-10-06T09:00:00Z', params: { result: 'removed' } },
          { n: 3, location_id: 'rl1', name: 'add_answered', status: 'ok', at: '2026-10-06T09:01:00Z', params: {} },
          { n: 4, location_id: 'rl1', name: 'verified', status: 'failed', at: '2026-10-06T09:02:00Z', params: {} },
          { n: 5, location_id: null, name: 'something_new', status: 'ok', at: '2026-10-06T09:03:00Z', params: {} },
        ],
      }),
    );
    await open();
    const steps = await screen.findByTestId('run-steps');
    expect(within(steps).getByText('A late answer arrived after Alice had given up')).toBeInTheDocument();
    expect(within(steps).getByText('Check this')).toBeInTheDocument();
    expect(within(steps).getByText('The server answered the addition')).toBeInTheDocument();
    expect(within(steps).getByText('New key works')).toBeInTheDocument();
    expect(within(steps).getByText('Failed')).toBeInTheDocument();
    expect(within(steps).getByText('Other step')).toBeInTheDocument();
    expectNoRawKeys(steps);
    const alert = screen.getByText("A server's answer arrived after Alice had given up on it.").closest('[role]');
    expect(alert).toHaveAttribute('role', 'status');
  });

  it('puts the table in its own scroll area so the page never scrolls sideways', async () => {
    serve(runFixture());
    await open();
    const table = await screen.findByRole('table', { name: 'Places' });
    expect(table.closest('[class*="ScrollArea"]')).not.toBeNull();
  });

  it('shows the error when the run cannot be read', async () => {
    server.use(...sessionHandlers(sessionFor('admin')), http.get(BASE, () => errorResponse(404, 'ALC-SYS-0001', 'system.not_found')));
    await open();
    expect(await screen.findByRole('alert')).toBeInTheDocument();
  });

  it('polls a moving run again after three seconds', async () => {
    const counts = serve(runFixture({ status: 'adding_new' }));
    await open();
    await screen.findByRole('heading', { name: 'Key rotation', level: 1 });
    expect(counts.reads).toBe(1);
    await waitFor(() => expect(counts.reads).toBeGreaterThanOrEqual(2), { timeout: 5000 });
  }, 10000);

  it('does not poll a final run', async () => {
    const counts = serve(runFixture({ status: 'completed' }));
    await open();
    await screen.findByRole('heading', { name: 'Key rotation', level: 1 });
    await new Promise((r) => setTimeout(r, 3500));
    expect(counts.reads).toBe(1);
  }, 10000);

  it('renders every part in Turkish with no missing key', async () => {
    serve(
      runFixture({
        status: 'verifying_new',
        paused_license: true,
        awaiting_decision: true,
        decision_due_at: '2026-10-20T08:00:00Z',
        kept_count: 1,
        actions_allowed: ['continue', 'finish_now', 'keep_old', 'abort'],
        result: { code: 'ALC-ROT-0010', reason: 'rotation.decision_timeout' },
        locations: [runLocationFixture({ state: 'unverifiable', verify_note: 'from_option', backup: '/b' }), runLocationFixture({ id: 's', n: 2, state: 'skipped', skip_reason: 'duplicate_lines' })],
        steps: [{ n: 1, location_id: null, name: 'paused', status: 'ok', at: '2026-10-06T08:00:00Z', params: {} }],
      }),
      'admin',
      'tr',
    );
    await open('tr-TR');
    expect(await screen.findByRole('heading', { name: 'Anahtar yenileme', level: 1 })).toBeInTheDocument();
    expect(screen.getByText('Karar bekleniyor', { selector: '.mantine-Badge-label' })).toBeInTheDocument();
    expectNoRawKeys();
    for (const name of ['Bu sunucularda eski anahtarı tut', 'Şimdi bitir', 'Durdur ve geri al']) {
      await userEvent.click(screen.getByRole('button', { name }));
      await screen.findByRole('dialog');
      expectNoRawKeys();
      await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'İptal' }));
      await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    }
  });

  it('shows the notice error of the service when it says why Continue is not offered', async () => {
    serve({ ...runFixture({ paused_license: true, actions_allowed: ['abort'] }), notice_error: { code: 'ALC-NTF-0001', reason: 'notify.queue_failed' } });
    await open();
    expect(await screen.findByText('Alice could not queue the email about the license renewal.')).toBeInTheDocument();
    expect(screen.queryByText('Alice is still preparing the email about the license renewal.')).not.toBeInTheDocument();
  });

  it('renders a run without places or steps (a list item shape) without failing', async () => {
    const bare: Run = runFixture();
    delete bare.locations;
    delete bare.steps;
    serve(bare);
    await open();
    expect(await screen.findByRole('heading', { name: 'Key rotation', level: 1 })).toBeInTheDocument();
  });
});
