import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { errorResponse, POLICY_ID, policyFixture, runFixture, RUN_ID, sessionFor, sessionHandlers } from '../test/fixtures';
import { expectNoRawKeys } from '../test/i18nAssert';
import { renderWithStepUp } from '../test/render';
import { server } from '../test/server';
import { RotationPolicyPanel } from './RotationPolicyPanel';
import ui from './ui/ui.module.css';

type Role = 'admin' | 'operator' | 'auditor';

function world(policy = policyFixture(), role: Role = 'admin', lang = 'en') {
  server.use(
    ...sessionHandlers(sessionFor(role, lang)),
    http.get(`/api/v1/rotation/policies/${POLICY_ID}`, () => HttpResponse.json(policy, { headers: { ETag: `"${policy.version}"` } })),
    http.get('/api/v1/rotation/runs', () => HttpResponse.json({ items: [runFixture({ status: 'completed' })], next_cursor: null })),
  );
}
const panel = (policyId: string | null = POLICY_ID, isAdmin = true, lang = 'en') =>
  renderWithStepUp(<RotationPolicyPanel keyId="k1" policyId={policyId} isAdmin={isAdmin} />, [lang === 'en' ? 'en-US' : 'tr-TR']);

describe('RotationPolicyPanel', () => {
  it('offers to create a policy to an Administrator and only says so to others', async () => {
    world();
    const v = await panel(null, true);
    expect(await screen.findByText('No rotation policy. Alice changes this key only when you ask.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Create rotation policy' })).toBeInTheDocument();
    v.unmount();
    await panel(null, false);
    expect(await screen.findByText(/No rotation policy/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Create rotation policy' })).not.toBeInTheDocument();
  });

  it('shows a policy that is off with its help, the plural forms and the overlap in days or minutes', async () => {
    world(policyFixture({ overlap_days: 0, overlap_minutes: 1, interval_days: 1 }));
    await panel();
    expect(await screen.findByText('Every day')).toBeInTheDocument();
    // The sentences are a styled list without bullets: the explicit role keeps it a list in WebKit (as C5's attentionList).
    expect(screen.getByText('Every day').closest('ul')).toHaveAttribute('role', 'list');
    expect(screen.getByText('Overlap: 1 minute')).toBeInTheDocument();
    expect(screen.getByText('The policy is off. Alice plans no run until you switch it on.')).toBeInTheDocument();
    expect(screen.getByRole('switch', { name: 'Rotate automatically' })).not.toBeChecked();
    expectNoRawKeys();
  });

  it('shows 7 days, the notice time, the next run of a policy that is on and Quarterly as text', async () => {
    world(policyFixture({ enabled: true, next_run_at: '2026-12-01T08:00:00Z', name: '<b>Q</b>' }));
    await panel();
    expect(await screen.findByText('Overlap: 7 days')).toBeInTheDocument();
    expect(screen.getByText('<b>Q</b>')).toHaveAttribute('translate', 'no');
    expect(screen.getByText(/^Next run:/)).toBeInTheDocument();
    expect(screen.queryByText(/Alice plans no run/)).not.toBeInTheDocument();
  });

  it('asks for the step-up code before switching on and sends If-Match with the version', async () => {
    world(policyFixture({ version: 1 }));
    const seen: (string | null)[] = [];
    server.use(
      http.post(`/api/v1/rotation/policies/${POLICY_ID}/actions/enable`, ({ request }) => {
        seen.push(request.headers.get('If-Match'));
        return seen.length === 1 ? errorResponse(403, 'ALC-AUTH-0003', 'auth.stepup_required') : HttpResponse.json(policyFixture({ enabled: true, version: 2 }));
      }),
      http.post('/api/v1/auth/stepup', () => HttpResponse.json(sessionFor('admin'))),
    );
    const user = userEvent.setup();
    await panel();
    await user.click(await screen.findByRole('switch', { name: 'Rotate automatically' }));
    await user.type(await screen.findByLabelText('6-digit code'), '123456');
    await user.click(screen.getByRole('button', { name: 'Confirm' }));
    await waitFor(() => expect(seen).toEqual(['"1"', '"1"']));
  });

  it('switches off without a code', async () => {
    world(policyFixture({ enabled: true, version: 4 }));
    let ifMatch: string | null = null;
    server.use(
      http.post(`/api/v1/rotation/policies/${POLICY_ID}/actions/disable`, ({ request }) => {
        ifMatch = request.headers.get('If-Match');
        return HttpResponse.json(policyFixture({ enabled: false, version: 5 }));
      }),
    );
    await panel();
    await userEvent.click(await screen.findByRole('switch', { name: 'Rotate automatically' }));
    await waitFor(() => expect(ifMatch).toBe('"4"'));
    expect(screen.queryByLabelText('6-digit code')).not.toBeInTheDocument();
  });

  it.each(['operator', 'auditor'] as const)('shows %s a read-only panel', async (role) => {
    world(policyFixture(), role);
    await panel(POLICY_ID, false);
    const sw = await screen.findByRole('switch', { name: 'Rotate automatically' });
    expect(sw).toBeDisabled();
    for (const n of ['Preview next run', 'Run now', 'Edit', 'Delete policy']) expect(screen.queryByRole('button', { name: n })).not.toBeInTheDocument();
  });

  it('shows the last run outcome and reason, so a policy that skips silently is visible', async () => {
    world(
      policyFixture({
        enabled: true,
        last_run_id: RUN_ID,
        last_run_status: 'cancelled',
        last_run_result: { code: 'ALC-ROT-0017', reason: 'rotation.notice_undelivered' },
      }),
    );
    await panel();
    expect(await screen.findByText('Last run: Cancelled')).toBeInTheDocument();
    expect(screen.getByText('The planned rotation was cancelled because its notice email was not delivered in time.')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Open the last run' })).toHaveAttribute('href', `/rotation/runs/${RUN_ID}`);
  });

  it('links to an open run and lists the earlier runs', async () => {
    world(policyFixture({ open_rotation_id: RUN_ID }));
    await panel();
    expect(await screen.findByRole('link', { name: 'Open the current run' })).toHaveAttribute('href', `/rotation/runs/${RUN_ID}`);
    const table = await screen.findByRole('table', { name: 'Earlier runs' });
    expect(within(table).getByText('Completed')).toBeInTheDocument();
  });

  it('keeps Run now enabled for a previewed (planned) run, which Run now starts', async () => {
    world(policyFixture({ enabled: true, open_rotation_id: RUN_ID }));
    server.use(http.get('/api/v1/rotation/runs', () => HttpResponse.json({ items: [runFixture({ status: 'dry_run_notified' })], next_cursor: null })));
    await panel();
    await screen.findByRole('table', { name: 'Earlier runs' });
    expect(screen.getByRole('button', { name: 'Run now' })).toBeEnabled();
  });

  it('disables Run now while a run is in progress', async () => {
    world(policyFixture({ enabled: true, open_rotation_id: RUN_ID }));
    server.use(http.get('/api/v1/rotation/runs', () => HttpResponse.json({ items: [runFixture({ status: 'overlap' })], next_cursor: null })));
    await panel();
    await screen.findByRole('table', { name: 'Earlier runs' });
    expect(screen.getByRole('button', { name: 'Run now' })).toBeDisabled();
  });

  it('explains under the last run that a planned run that did not happen shows its reason', async () => {
    world(policyFixture({ last_run_id: RUN_ID, last_run_status: 'cancelled', last_run_result: { code: 'ALC-ROT-0017', reason: 'rotation.notice_undelivered' } }));
    await panel();
    expect(await screen.findByText('A planned run that did not happen shows its reason here.')).toBeInTheDocument();
  });

  it('reads the runs again after switching off, because a planned run is cancelled', async () => {
    world(policyFixture({ enabled: true }));
    let reads = 0;
    server.use(
      http.get('/api/v1/rotation/runs', () => (reads++, HttpResponse.json({ items: [], next_cursor: null }))),
      http.post(`/api/v1/rotation/policies/${POLICY_ID}/actions/disable`, () => HttpResponse.json(policyFixture({ enabled: false, version: 2 }))),
    );
    await panel();
    await userEvent.click(await screen.findByRole('switch', { name: 'Rotate automatically' }));
    await waitFor(() => expect(reads).toBeGreaterThanOrEqual(2));
  });

  it('shows a busy delete button while the policy is being deleted', async () => {
    world(policyFixture());
    server.use(http.delete(`/api/v1/rotation/policies/${POLICY_ID}`, async () => (await new Promise((r) => setTimeout(r, 200)), new HttpResponse(null, { status: 204 }))));
    const user = userEvent.setup();
    await panel();
    await user.click(await screen.findByRole('button', { name: 'Delete policy' }));
    const dialog = await screen.findByRole('dialog', { name: 'Delete policy' });
    await user.click(within(dialog).getByRole('button', { name: 'Delete policy' }));
    expect(within(dialog).getByRole('button', { name: 'Delete policy' })).toBeDisabled();
  });

  it.each(['cancelled', 'completed', 'aborted', 'needs_attention'])('keeps Run now enabled when the open run is already %s', async (status) => {
    world(policyFixture({ enabled: true, open_rotation_id: RUN_ID }));
    server.use(http.get('/api/v1/rotation/runs', () => HttpResponse.json({ items: [runFixture({ status })], next_cursor: null })));
    await panel();
    await screen.findByRole('table', { name: 'Earlier runs' });
    expect(screen.getByRole('button', { name: 'Run now' })).toBeEnabled();
  });

  it('deletes a policy with If-Match after a confirmation', async () => {
    world(policyFixture({ version: 3 }));
    let ifMatch: string | null = null;
    server.use(
      http.delete(`/api/v1/rotation/policies/${POLICY_ID}`, ({ request }) => {
        ifMatch = request.headers.get('If-Match');
        return new HttpResponse(null, { status: 204 });
      }),
    );
    const user = userEvent.setup();
    await panel();
    await user.click(await screen.findByRole('button', { name: 'Delete policy' }));
    const dialog = await screen.findByRole('dialog', { name: 'Delete policy' });
    expect(within(dialog).getByText('Delete this rotation policy? The key stays as it is. A planned run that has not started is cancelled.')).toBeInTheDocument();
    await user.click(within(dialog).getByRole('button', { name: 'Delete policy' }));
    await waitFor(() => expect(ifMatch).toBe('"3"'));
  });

  it('renders in Turkish with no missing key', async () => {
    world(policyFixture({ enabled: true, next_run_at: '2026-12-01T08:00:00Z', last_run_id: RUN_ID, last_run_status: 'cancelled', last_run_result: { code: 'ALC-ROT-0017', reason: 'rotation.notice_undelivered' } }), 'admin', 'tr');
    await panel(POLICY_ID, true, 'tr');
    expect(await screen.findByText('Her 90 günde bir')).toBeInTheDocument();
    expect(screen.getByText('Geçiş süresi: 7 gün')).toBeInTheDocument();
    expectNoRawKeys();
  });

  it('is the design panel: a titled section, the state as a badge in the history and a named link column', async () => {
    world(policyFixture());
    await panel();
    const section = await screen.findByTestId('rotation-panel');
    expect(section.tagName).toBe('SECTION');
    expect(within(section).getByRole('heading', { name: 'Automatic rotation', level: 2 })).toBeInTheDocument();
    const history = await within(section).findByRole('table', { name: 'Earlier runs' });
    expect(within(history).getAllByRole('columnheader').map((h) => h.textContent)).toEqual(['Planned for', 'State', 'Details']);
    const badge = within(history).getAllByRole('row')[1].querySelector('.mantine-Badge-root')!;
    expect(badge).toHaveAttribute('data-tone', 'success');
    expect(within(history).getByRole('link', { name: 'Open' })).toHaveAttribute('href', `/rotation/runs/${RUN_ID}`);
  });

  it('confirms the deletion in a dialog with the design footer', async () => {
    world(policyFixture());
    await panel();
    await userEvent.click(await screen.findByRole('button', { name: 'Delete policy' }));
    const dialog = await screen.findByRole('dialog', { name: 'Delete policy' });
    expect(within(dialog).getByRole('button', { name: 'Delete policy' }).parentElement).toHaveClass(ui.dialogActions);
  });

  it('keeps the policy when the deletion is refused and says why; Cancel leaves it alone', async () => {
    world(policyFixture());
    server.use(http.delete(`/api/v1/rotation/policies/${POLICY_ID}`, () => errorResponse(412, 'ALC-SYS-0008', 'system.precondition_failed')));
    await panel();
    await userEvent.click(await screen.findByRole('button', { name: 'Delete policy' }));
    let dialog = await screen.findByRole('dialog', { name: 'Delete policy' });
    await userEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Delete policy' })).not.toBeInTheDocument());
    await userEvent.click(screen.getByRole('button', { name: 'Delete policy' }));
    dialog = await screen.findByRole('dialog', { name: 'Delete policy' });
    await userEvent.click(within(dialog).getByRole('button', { name: 'Delete policy' }));
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Delete policy' })).not.toBeInTheDocument());
    expect(await within(screen.getByTestId('rotation-panel')).findByRole('alert')).toBeInTheDocument();
  });

  it('opens and closes the edit and preview dialogs from the panel', async () => {
    world(policyFixture());
    server.use(http.post(`/api/v1/rotation/policies/${POLICY_ID}/actions/preview`, () => new Promise(() => {})));
    await panel();
    await userEvent.click(await screen.findByRole('button', { name: 'Edit' }));
    const edit = await screen.findByRole('dialog', { name: 'Edit the rotation policy' });
    await userEvent.click(within(edit).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Edit the rotation policy' })).not.toBeInTheDocument());
    await userEvent.click(screen.getByRole('button', { name: 'Preview next run' }));
    const preview = await screen.findByRole('dialog', { name: 'Preview of the next run' });
    await userEvent.click(within(preview).getAllByRole('button', { name: 'Close' }).at(-1)!);
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Preview of the next run' })).not.toBeInTheDocument());
  });
});
