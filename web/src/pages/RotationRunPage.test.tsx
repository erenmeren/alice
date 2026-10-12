import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import type { Run } from '../api/rotation';
import { errorResponse, policyFixture, runFixture, runLocationFixture, RUN_ID, sessionFor, sessionHandlers } from '../test/fixtures';
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

  it('shows the licence pause with its own text and the stop-and-undo line, and no email text the server did not send', async () => {
    serve(runFixture({ status: 'overlap', paused_license: true, actions_allowed: ['abort'], decision_due_at: '2026-10-20T08:00:00Z', awaiting_decision: true }));
    await open();
    expect(await screen.findByText(/Paused: the license expired or could not be checked/)).toBeInTheDocument();
    expect(screen.getByText(/Alice adds no new key and removes no old key for this rotation/)).toBeInTheDocument();
    expect(screen.getByText(/You can still stop and undo the rotation: Alice then removes the new key where it added it/)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Open the license page' })).toHaveAttribute('href', '/license');
    expect(screen.queryByText('Alice is still preparing the email about the license renewal.')).not.toBeInTheDocument();
    expect(screen.queryByText(/^Decide before/)).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Continue' })).not.toBeInTheDocument();
  });

  it('does not offer the stop-and-undo line when the API does not offer Stop and undo (a pause while removing)', async () => {
    serve(runFixture({ status: 'removing_old', paused_license: true, actions_allowed: [] }));
    await open();
    expect(await screen.findByText(/Paused: the license expired or could not be checked/)).toBeInTheDocument();
    expect(screen.queryByText(/You can still stop and undo/)).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Stop and undo' })).not.toBeInTheDocument();
  });

  it('explains the pending renewal email only when the server says so (notice_state)', async () => {
    serve({ ...runFixture({ paused_license: true, actions_allowed: ['abort'] }), notice_state: { code: 'ALC-ROT-0021', reason: 'rotation.notice_pending' } });
    await open();
    expect(await screen.findByText('Alice is still preparing the email about the license renewal.')).toBeInTheDocument();
  });

  it('shows the queue failure of notice_error', async () => {
    serve({ ...runFixture({ paused_license: true, actions_allowed: ['abort'] }), notice_error: { code: 'ALC-NTF-0001', reason: 'notify.queue_failed' } });
    await open();
    expect(await screen.findByText('Alice could not queue the email about the license renewal.')).toBeInTheDocument();
  });

  it('labels every place count the way the server defines it, unknown buckets generically', async () => {
    serve(runFixture({ location_counts: { total: 9, verified: 1, removed: 1, skipped: 1, kept: 1, failed: 1, undone: 1, cancelled: 1, in_flight: 1, brand_new: 3 } }));
    await open();
    const list = await screen.findByTestId('run-counts');
    for (const text of [
      'Total: 9',
      'New key works, old key still there: 1',
      'Old key removed: 1',
      'Old key kept: 1',
      'Not started (never sent, or refused when about to send): 1',
      'New key removed again: 1',
      'In progress: 1',
      'Other: 3',
    ])
      expect(within(list).getByText(text)).toBeInTheDocument();
    expectNoRawKeys(list);
  });

  it('shows how often an add was sent again and the planner reason of a place refused at send time', async () => {
    serve(
      runFixture({
        locations: [
          runLocationFixture({ id: 'a', add_resend_count: 2, add_resent_at: '2026-10-06T09:00:00Z' }),
          runLocationFixture({ id: 'b', n: 2, state: 'cancelled', error: { code: 'ALC-ROT-0024', reason: 'rotation.skipped_at_send' }, skip_reason: 'connection_account_file' }),
        ],
      }),
    );
    await open();
    const rows = await screen.findAllByTestId('run-location');
    expect(within(rows[0]).getByText(/Sent again 2 times after a lost answer, last at/)).toBeInTheDocument();
    expect(within(rows[1]).getByText(/account Alice connects with/)).toBeInTheDocument();
    expect(within(rows[0]).queryByText(/Sent 0 times/)).not.toBeInTheDocument();
  });

  it('shows the licence-locked notice state through its catalogue text', async () => {
    serve({ ...runFixture({ paused_license: true, actions_allowed: ['abort'] }), notice_state: { code: 'ALC-ROT-0011', reason: 'rotation.paused_license' } });
    await open();
    expect(await screen.findByText(/Paused: the license expired or could not be checked/)).toBeInTheDocument();
    // one message for one fact: the banner, not the catalogue text on top of it
    expect(screen.queryByText('The rotation is paused because the license has expired or could not be checked.')).not.toBeInTheDocument();
  });

  it('offers the stop-and-undo line only when the page shows the button (role-gated)', async () => {
    serve(runFixture({ paused_license: true, actions_allowed: ['abort'] }), 'operator');
    await open();
    await screen.findByText(/Paused: the license expired/);
    expect(screen.queryByText(/You can still stop and undo/)).not.toBeInTheDocument();
  });

  it('shows no end time or countdown for an overlap that is paused for the license', async () => {
    serve(runFixture({ status: 'overlap', paused_license: true, overlap_until: '2026-10-13T08:05:00Z', actions_allowed: ['abort'] }));
    await open();
    expect(await screen.findByText('The overlap is on hold: it resumes after you choose Continue, with the time that was left.')).toBeInTheDocument();
    expect(screen.queryByText(/^Both keys work until/)).not.toBeInTheDocument();
  });

  it('shows the end of the overlap again once it is not paused', async () => {
    serve(runFixture({ status: 'overlap', paused_license: false, overlap_until: '2026-10-13T08:05:00Z' }));
    await open();
    expect(await screen.findByText(/^Both keys work until/)).toBeInTheDocument();
    expect(screen.queryByText(/The overlap is on hold/)).not.toBeInTheDocument();
  });

  it('shows the paused overlap in Turkish with no missing key', async () => {
    serve(runFixture({ status: 'overlap', paused_license: true, overlap_until: '2026-10-13T08:05:00Z', actions_allowed: ['abort'] }), 'admin', 'tr');
    await open('tr-TR');
    expect(await screen.findByText('Geçiş süresi beklemede: Devam et\'i seçtiğinizde, kalan süreyle birlikte yeniden başlar.')).toBeInTheDocument();
    expectNoRawKeys();
  });

  it('labels the listing_incomplete step', async () => {
    serve(runFixture({ steps: [{ n: 1, location_id: 'rl1', name: 'listing_incomplete', status: 'failed', at: '2026-10-06T09:00:00Z', params: {} }] }));
    await open();
    expect(await within(await screen.findByTestId('run-steps')).findByText('Alice could not read the key file completely')).toBeInTheDocument();
  });

  it('labels the retry_returned step', async () => {
    serve(runFixture({ steps: [{ n: 1, location_id: 'rl1', name: 'retry_returned', status: 'skipped', at: '2026-10-06T09:00:00Z', params: {} }] }));
    await open();
    const steps = await screen.findByTestId('run-steps');
    expect(within(steps).queryByText('Other step')).not.toBeInTheDocument();
    expectNoRawKeys(steps);
  });

  it('keeps polling a first read that answered 503 with Retry-After, and shows a busy Try again', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      let reads = 0;
      server.use(
        ...sessionHandlers(sessionFor('admin')),
        http.get(BASE, () => (++reads === 1 ? HttpResponse.json({ error: { code: 'ALC-NTF-0001', reason: 'notify.queue_failed', message_key: 'errors.notify.queue_failed', message: 'x', request_id: 'r', retryable: true, params: {}, details: [] } }, { status: 503, headers: { 'Retry-After': '5' } }) : HttpResponse.json(runFixture()))),
      );
      await open();
      await screen.findByRole('alert');
      await vi.advanceTimersByTimeAsync(5100);
      expect(await screen.findByRole('heading', { name: 'Key rotation', level: 1 })).toBeInTheDocument();
      expect(reads).toBe(2);
    } finally {
      vi.useRealTimers();
    }
  });

  it.each(['operator', 'auditor'] as const)('shows %s the run without any decision button', async (role) => {
    serve(runFixture({ actions_allowed: ['continue', 'finish_now', 'keep_old', 'abort'] }), role);
    await open();
    await screen.findByRole('heading', { name: 'Key rotation', level: 1 });
    for (const n of ['Continue', 'Finish now', 'Keep the old key on these servers', 'Stop and undo']) expect(screen.queryByRole('button', { name: n })).not.toBeInTheDocument();
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
    expect(within(dialog).getByText("Alice ends the overlap now and emails the administrators. In each place it tests the new key once more and removes the old key only where the new key works; places where the old key is kept are not touched.")).toBeInTheDocument();
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

  it('shows the step-up prompt for Stop and undo when the server asks for a code', async () => {
    serve(runFixture({ actions_allowed: ['abort'] }));
    let posted = 0;
    server.use(
      http.post(`${BASE}/actions/abort`, () => (++posted === 1 ? errorResponse(403, 'ALC-AUTH-0003', 'auth.stepup_required') : new HttpResponse(null, { status: 204 }))),
      http.post('/api/v1/auth/stepup', () => HttpResponse.json(sessionFor('admin'))),
    );
    const user = userEvent.setup();
    await open();
    await user.click(await screen.findByRole('button', { name: 'Stop and undo' }));
    await user.click(within(await screen.findByRole('dialog', { name: 'Stop and undo' })).getByRole('button', { name: 'Stop and undo' }));
    await user.type(await screen.findByLabelText('6-digit code'), '123456');
    await user.click(screen.getByRole('button', { name: 'Confirm' }));
    await waitFor(() => expect(posted).toBe(2));
  });

  it('forgets the ticked places when the Keep old dialog is closed', async () => {
    const a = runLocationFixture({ id: 'u1', state: 'unverifiable' });
    serve(runFixture({ status: 'verifying_new', awaiting_decision: true, actions_allowed: ['keep_old'], locations: [a, runLocationFixture({ id: 'v1', n: 2 })] }));
    const user = userEvent.setup();
    await open();
    await user.click(await screen.findByRole('button', { name: 'Keep the old key on these servers' }));
    let dialog = await screen.findByRole('dialog');
    await user.click(within(dialog).getByRole('checkbox'));
    await user.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    await user.click(screen.getByRole('button', { name: 'Keep the old key on these servers' }));
    dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByRole('checkbox')).not.toBeChecked();
  });

  it('says what Keep old really does', async () => {
    serve(runFixture({ status: 'verifying_new', awaiting_decision: true, actions_allowed: ['keep_old'], locations: [runLocationFixture({ id: 'u1', state: 'unverifiable' })] }));
    await open();
    await userEvent.click(await screen.findByRole('button', { name: 'Keep the old key on these servers' }));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText(/nor from other places in the same file/)).toBeInTheDocument();
    expect(within(dialog).getByText(/At least one place where the new key works must remain/)).toBeInTheDocument();
    expect(within(dialog).getByText(/Alice undoes the whole rotation/)).toBeInTheDocument();
  });

  it('shows a decision that the server refuses (409) and reads the run again', async () => {
    const counts = serve(runFixture({ actions_allowed: ['finish_now'] }));
    server.use(http.post(`${BASE}/actions/finish-now`, () => errorResponse(409, 'ALC-ROT-0005', 'rotation.not_waiting')));
    await open();
    await userEvent.click(await screen.findByRole('button', { name: 'Finish now' }));
    await userEvent.click(within(await screen.findByRole('dialog', { name: 'Finish now' })).getByRole('button', { name: 'Finish now' }));
    expect(await screen.findByRole('alert')).toBeInTheDocument();
    await waitFor(() => expect(counts.reads).toBeGreaterThanOrEqual(2));
  });

  it('goes back to the old key until the rotation is completed', async () => {
    serve(runFixture({ status: 'overlap' }));
    const v = await open();
    expect(await screen.findByRole('link', { name: 'Back to the SSH key' })).toHaveAttribute('href', '/ssh-keys/0192b000-0000-7000-8000-0000000000k1');
    v.unmount();
    serve(runFixture({ status: 'completed' }));
    await open();
    expect(await screen.findByRole('link', { name: 'Back to the SSH key' })).toHaveAttribute('href', '/ssh-keys/0192b000-0000-7000-8000-0000000000k2');
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
          { n: 6, location_id: 'rl1', name: 'undo_not_sent', status: 'skipped', at: '2026-10-06T09:04:00Z', params: {} },
          { n: 7, location_id: null, name: 'notice_failed', status: 'failed', at: '2026-10-06T09:05:00Z', params: {} },
        ],
      }),
    );
    await open();
    const steps = await screen.findByTestId('run-steps');
    expect(within(steps).getByText('A late answer arrived after Alice had given up')).toBeInTheDocument();
    expect(within(steps).getAllByText('Check this')).toHaveLength(2);
    expect(within(steps).getByText('The removal of the new key was not sent: too many attempts')).toBeInTheDocument();
    expect(within(steps).getByText('The email about the license renewal could not be queued')).toBeInTheDocument();
    expect(within(steps).getByText('The server answered the addition')).toBeInTheDocument();
    expect(within(steps).getByText('New key works')).toBeInTheDocument();
    expect(within(steps).getAllByText('Failed').length).toBeGreaterThan(0);
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

  describe('polling', () => {
    beforeEach(() => vi.useFakeTimers({ shouldAdvanceTime: true }));
    afterEach(() => vi.useRealTimers());

    it('reads a moving run again after three seconds', async () => {
      const counts = serve(runFixture({ status: 'adding_new' }));
      await open();
      await screen.findByRole('heading', { name: 'Key rotation', level: 1 });
      expect(counts.reads).toBe(1);
      await vi.advanceTimersByTimeAsync(3100);
      await waitFor(() => expect(counts.reads).toBe(2));
    });

    it('does not read a final run again', async () => {
      const counts = serve(runFixture({ status: 'completed' }));
      await open();
      await screen.findByRole('heading', { name: 'Key rotation', level: 1 });
      await vi.advanceTimersByTimeAsync(10000);
      expect(counts.reads).toBe(1);
    });

    it('stops reading a run that cannot be read and shows why', async () => {
      let reads = 0;
      server.use(...sessionHandlers(sessionFor('admin')), http.get(BASE, () => (reads++, errorResponse(404, 'ALC-SYS-0001', 'system.not_found'))));
      await open();
      expect(await screen.findByRole('alert')).toBeInTheDocument();
      await vi.advanceTimersByTimeAsync(20000);
      expect(reads).toBe(1);
    });

    it('keeps the page and shows a failed refresh', async () => {
      let reads = 0;
      server.use(
        ...sessionHandlers(sessionFor('admin')),
        http.get(BASE, () => (++reads === 1 ? HttpResponse.json(runFixture({ status: 'adding_new' })) : errorResponse(502, 'ALC-AKV-0001', 'azure.auth_failed'))),
      );
      await open();
      await screen.findByRole('heading', { name: 'Key rotation', level: 1 });
      await vi.advanceTimersByTimeAsync(3100);
      expect(await screen.findByRole('alert')).toBeInTheDocument();
      expect(screen.getByRole('heading', { name: 'Key rotation', level: 1 })).toBeInTheDocument();
    });
  });

  it('announces the status politely', async () => {
    serve(runFixture({ status: 'adding_new' }));
    await open();
    const live = (await screen.findAllByText('Adding the new key')).map((e) => e.closest('[aria-live]')).find(Boolean);
    expect(live).toHaveAttribute('aria-live', 'polite');
  });

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

describe('RotationRunPage in the design', () => {
  it('has the run title as the only h1 with the status badge in its polite live region, and the key, type and places as its description', async () => {
    serve(runFixture({ status: 'overlap', location_counts: { total: 6, verified: 6 } }));
    server.use(http.get('/api/v1/rotation/policies', () => HttpResponse.json({ items: [policyFixture({ name: 'deploy-production' })] })));
    await open();
    const h1 = await screen.findByRole('heading', { level: 1 });
    expect(h1).toHaveTextContent('Key rotation');
    expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
    const header = h1.closest('header')!;
    const live = within(header as HTMLElement).getByRole('status');
    expect(live).toHaveAttribute('aria-live', 'polite');
    expect(live.querySelector('.mantine-Badge-root')).toHaveTextContent('Both keys valid');
    expect(await within(header as HTMLElement).findByText('deploy-production · ed25519 · 6 locations')).toBeInTheDocument();
    expect(document.querySelectorAll('[role="status"][aria-live="polite"] .mantine-Badge-root')).toHaveLength(1);
  });

  it('draws the progress path for a moving run and none for a stopped one', async () => {
    serve(runFixture({ status: 'overlap' }));
    const v = await open();
    expect(await screen.findByRole('list', { name: 'Rotation progress' })).toBeInTheDocument();
    v.unmount();
    serve(runFixture({ status: 'aborted' }));
    await open();
    await screen.findByRole('heading', { level: 1, name: 'Key rotation' });
    expect(screen.queryByRole('list', { name: 'Rotation progress' })).not.toBeInTheDocument();
  });

  it('shows the key transition: old and new fingerprints in code and the run facts', async () => {
    serve(runFixture({ status: 'overlap', trigger: 'scheduled' }));
    server.use(http.get('/api/v1/rotation/policies', () => HttpResponse.json({ items: [policyFixture({ name: 'deploy-production' })] })));
    await open();
    const panel = await screen.findByRole('region', { name: 'Key transition' });
    expect(within(panel).getByText('SHA256:oldOldOldOldOldOldOldOldOldOldOldOldOld0').tagName).toBe('CODE');
    expect(within(panel).getByText('SHA256:newNewNewNewNewNewNewNewNewNewNewNewNew0').tagName).toBe('CODE');
    expect(await within(panel).findByText('deploy-production')).toBeInTheDocument();
    expect(within(panel).getByText('Every 90 days')).toBeInTheDocument();
    expect(within(panel).getByText('Scheduled run')).toBeInTheDocument();
    // notified_at is when Alice announced the run (and queued the email), not a delivery mark.
    expect(within(panel).getByText('Announced')).toBeInTheDocument();
    expect(within(panel).queryByText(/sent/i)).not.toBeInTheDocument();
  });

  it.each([
    ['notice_error', { notice_error: { code: 'ALC-NTF-0001', reason: 'notify.queue_failed' } }],
    ['notice_state', { notice_state: { code: 'ALC-ROT-0021', reason: 'rotation.notice_pending' } }],
  ])('states no announcement fact next to a %s: the email did not go out', async (_, extra) => {
    serve({ ...runFixture({ status: 'overlap' }), ...extra });
    await open();
    const panel = await screen.findByRole('region', { name: 'Key transition' });
    expect(within(panel).queryByText('Announced')).not.toBeInTheDocument();
    expect(screen.queryByText(/Notice sent/)).not.toBeInTheDocument();
  });

  it('names the location results and keeps the places table and its rows', async () => {
    serve(runFixture());
    await open();
    const results = await screen.findByRole('region', { name: 'Location results' });
    expect(within(results).getByText('Old keys are not removed from unverified locations.')).toBeInTheDocument();
    expect(within(results).getByRole('table', { name: 'Places' })).toHaveAttribute('data-testid', 'run-locations');
    expect(within(results).getByTestId('run-counts')).toBeInTheDocument();
    const row = within(results).getByTestId('run-location');
    expect(within(row).getByRole('cell', { name: 'deploy' })).toBeInTheDocument();
  });

  it.each([
    ['admin', ['finish_now', 'abort'], true],
    ['admin', [], false],
    ['operator', ['finish_now', 'abort'], false],
    ['auditor', ['continue'], false],
  ] as const)('shows the decisions panel to %s with actions %j: %s', async (role, allowed, shown) => {
    serve(runFixture({ actions_allowed: [...allowed] }), role);
    await open();
    await screen.findByRole('heading', { level: 1, name: 'Key rotation' });
    const panel = screen.queryByRole('region', { name: 'Available decisions' });
    expect(panel !== null).toBe(shown);
    if (panel) {
      expect(within(panel).getByText('Review the affected locations before confirming. Each decision asks for a fresh verification code.')).toBeInTheDocument();
      expect(within(panel).getByRole('button', { name: 'Finish now' })).toBeInTheDocument();
      expect(within(panel).getByRole('button', { name: 'Stop and undo' })).toBeInTheDocument();
    }
  });

  it('keeps the license pause as one alert with its link in the notice color', async () => {
    serve(runFixture({ status: 'overlap', paused_license: true, actions_allowed: ['abort'] }));
    await open();
    const alert = (await screen.findByText(/Paused: the license expired/)).closest('[role="alert"]') as HTMLElement;
    expect(alert).not.toBeNull();
    expect(within(alert).getByText('Paused by the license')).toBeInTheDocument();
    const link = within(alert).getByRole('link', { name: 'Open the license page' });
    expect(link).toHaveAttribute('data-underline', 'always');
    expect(screen.getAllByRole('alert')).toHaveLength(1);
  });

  it('colors the place and step states by meaning, with text', async () => {
    serve(
      runFixture({
        status: 'needs_attention',
        locations: [
          runLocationFixture({ id: 'a', state: 'removed' }),
          runLocationFixture({ id: 'b', n: 2, state: 'add_failed' }),
          runLocationFixture({ id: 'c', n: 3, state: 'kept_old' }),
          runLocationFixture({ id: 'd', n: 4, state: 'planned' }),
        ],
        steps: [{ n: 1, location_id: null, name: 'paused', status: 'failed', at: '2026-10-06T09:00:00Z', params: {} }],
      }),
    );
    await open();
    const rows = await screen.findAllByTestId('run-location');
    const tone = (row: HTMLElement) => row.querySelector('.mantine-Badge-root')?.getAttribute('data-tone');
    expect(rows.map(tone)).toEqual(['success', 'danger', 'warning', 'neutral']);
    expect(within(screen.getByTestId('run-steps')).getByText('Failed').closest('.mantine-Badge-root')).toHaveAttribute('data-tone', 'danger');
  });
});
