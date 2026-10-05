import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { errorResponse, POLICY_ID, policyFixture, previewActionFixture, previewFixture, RUN_ID, sessionFor, sessionHandlers } from '../test/fixtures';
import { expectNoRawKeys } from '../test/i18nAssert';
import { renderWithStepUp } from '../test/render';
import { server } from '../test/server';
import { RotationPreviewDialog } from './RotationPreviewDialog';

const PREVIEW = `/api/v1/rotation/policies/${POLICY_ID}/actions/preview`;
const RUN = `/api/v1/rotation/policies/${POLICY_ID}/actions/run`;

beforeEach(() => server.use(...sessionHandlers(sessionFor('admin'))));
const open = (onStarted = vi.fn(), lang = 'en-US') => renderWithStepUp(<RotationPreviewDialog policy={policyFixture()} onClose={() => {}} onStarted={onStarted} />, [lang]);

describe('RotationPreviewDialog', () => {
  it('plans when it opens and shows one change and one skip with the lines as code', async () => {
    let calls = 0;
    server.use(http.post(PREVIEW, () => (calls++, HttpResponse.json(previewFixture()))));
    await open();
    expect(await screen.findByText('Places that will change: 1')).toBeInTheDocument();
    expect(screen.getByText('Places that will be skipped: 1')).toBeInTheDocument();
    expect(screen.getByText('Alice is emailing this preview to the administrators.')).toBeInTheDocument();
    const table = screen.getByRole('table', { name: 'Preview of the next run' });
    const rows = within(table).getAllByRole('row').slice(1);
    expect(within(rows[0]).getByText('ssh-ed25519 AAAANEWNEWNEW deploy-key').tagName).toBe('CODE');
    expect(within(rows[0]).getByText('ssh-ed25519 AAAAOLDOLDOLD deploy-key').tagName).toBe('CODE');
    expect(within(rows[0]).getByText('/home/deploy/.ssh/authorized_keys')).toHaveAttribute('translate', 'no');
    expect(within(rows[1]).getByText('Alice cannot connect to the server right now.')).toBeInTheDocument();
    expect(within(rows[1]).getByText('Skipped')).toBeInTheDocument();
    expect(within(rows[0]).queryByText('Alice cannot test a login here')).not.toBeInTheDocument();
    expect(calls).toBe(1);
    expectNoRawKeys();
  });

  it('asks only once under React StrictMode', async () => {
    const { StrictMode } = await import('react');
    let calls = 0;
    server.use(http.post(PREVIEW, () => (calls++, HttpResponse.json(previewFixture()))));
    await renderWithStepUp(
      <StrictMode>
        <RotationPreviewDialog policy={policyFixture()} onClose={() => {}} onStarted={() => {}} />
      </StrictMode>,
    );
    await screen.findByText('Places that will change: 1');
    expect(calls).toBe(1);
  });

  it('says so when the preview was already emailed', async () => {
    server.use(http.post(PREVIEW, () => HttpResponse.json(previewFixture({ emailed: false }))));
    await open();
    expect(await screen.findByText('A preview of this key was already emailed in the last 10 minutes, so this one was not emailed.')).toBeInTheDocument();
  });

  it('renders skip reasons it has no special knowledge of through the catalogue, and an unknown one generically', async () => {
    server.use(
      http.post(PREVIEW, () =>
        HttpResponse.json(
          previewFixture({
            actions: [
              previewActionFixture({ skip_reason: 'shared_file_skipped', add_line: '', remove_line: '' }),
              previewActionFixture({ n: 2, skip_reason: 'root_forced_commands_only', add_line: '', remove_line: '' }),
              previewActionFixture({ n: 3, skip_reason: 'a_reason_from_a_newer_server', add_line: '', remove_line: '' }),
              previewActionFixture({ n: 4, verify_note: 'root_login_disabled', verify: false }),
            ],
          }),
        ),
      ),
    );
    await open();
    expect(await screen.findByText('Several users of this server read this file, so Alice does not change the key in it.')).toBeInTheDocument();
    expect(screen.getByText('root may sign in here only with a fixed command, and this line has none.')).toBeInTheDocument();
    expect(screen.getByText('Something went wrong.')).toBeInTheDocument();
    expect(screen.getByText('root may not sign in over SSH here')).toBeInTheDocument();
    expect(screen.getByText('Alice cannot test a login here')).toBeInTheDocument();
    expectNoRawKeys();
  });

  it('starts the run with the digest of this preview after a confirmation', async () => {
    server.use(http.post(PREVIEW, () => HttpResponse.json(previewFixture({ plan_digest: 'cd'.repeat(32) }))));
    let body: unknown;
    server.use(http.post(RUN, async ({ request }) => ((body = await request.json()), HttpResponse.json({ rotation_id: RUN_ID, status_url: '' }, { status: 202 }))));
    const onStarted = vi.fn();
    const user = userEvent.setup();
    await open(onStarted);
    await user.click(await screen.findByRole('button', { name: 'Run now' }));
    const confirm = await screen.findByRole('dialog', { name: 'Start this rotation now?' });
    await user.click(within(confirm).getByRole('button', { name: 'Start rotation' }));
    await waitFor(() => expect(onStarted).toHaveBeenCalledWith(RUN_ID));
    expect(body).toEqual({ plan_digest: 'cd'.repeat(32) });
  });

  it('asks for the step-up code and retries the same digest', async () => {
    server.use(http.post(PREVIEW, () => HttpResponse.json(previewFixture())), http.post('/api/v1/auth/stepup', () => HttpResponse.json(sessionFor('admin'))));
    const bodies: unknown[] = [];
    server.use(
      http.post(RUN, async ({ request }) => {
        bodies.push(await request.json());
        return bodies.length === 1 ? errorResponse(403, 'ALC-AUTH-0003', 'auth.stepup_required') : HttpResponse.json({ rotation_id: RUN_ID, status_url: '' }, { status: 202 });
      }),
    );
    const onStarted = vi.fn();
    const user = userEvent.setup();
    await open(onStarted);
    await user.click(await screen.findByRole('button', { name: 'Run now' }));
    await user.click(within(await screen.findByRole('dialog', { name: 'Start this rotation now?' })).getByRole('button', { name: 'Start rotation' }));
    await user.type(await screen.findByLabelText('6-digit code'), '123456');
    await user.click(screen.getByRole('button', { name: 'Confirm' }));
    await waitFor(() => expect(onStarted).toHaveBeenCalled());
    expect(bodies).toHaveLength(2);
  });

  it('on a digest mismatch (409) shows the new preview, says so, and never retries by itself', async () => {
    let previews = 0;
    server.use(http.post(PREVIEW, () => (previews++, HttpResponse.json(previewFixture({ plan_digest: (previews === 1 ? 'aa' : 'bb').repeat(32), change_count: previews === 1 ? 1 : 2 })))));
    let runs = 0;
    server.use(http.post(RUN, () => (runs++, errorResponse(409, 'ALC-ROT-0003', 'rotation.plan_changed'))));
    const onStarted = vi.fn();
    const user = userEvent.setup();
    await open(onStarted);
    await user.click(await screen.findByRole('button', { name: 'Run now' }));
    await user.click(within(await screen.findByRole('dialog', { name: 'Start this rotation now?' })).getByRole('button', { name: 'Start rotation' }));
    expect(await screen.findByText(/The plan changed since you looked at it/)).toBeInTheDocument();
    expect(await screen.findByText('Places that will change: 2')).toBeInTheDocument();
    expect(previews).toBe(2);
    expect(runs).toBe(1);
    expect(onStarted).not.toHaveBeenCalled();
  });

  it('cannot run when no place would change', async () => {
    server.use(http.post(PREVIEW, () => HttpResponse.json(previewFixture({ change_count: 0, actions: [] }))));
    await open();
    expect(await screen.findByText('No place would change, so there is nothing to rotate.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Run now' })).toBeDisabled();
  });

  it('shows the error when the plan cannot be made', async () => {
    server.use(http.post(PREVIEW, () => errorResponse(409, 'ALC-KEY-0006', 'sshkey.not_managed')));
    await open();
    expect(await screen.findByText('Alice holds no private key for this key.')).toBeInTheDocument();
  });

  it('renders in Turkish with no missing key', async () => {
    server.use(...sessionHandlers(sessionFor('admin', 'tr')), http.post(PREVIEW, () => HttpResponse.json(previewFixture())));
    await open(vi.fn(), 'tr-TR');
    expect(await screen.findByText('Değişecek yer sayısı: 1')).toBeInTheDocument();
    expect(screen.getByText('Alice şu anda sunucuya bağlanamıyor.')).toBeInTheDocument();
    expectNoRawKeys();
  });
});
