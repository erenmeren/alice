import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { errorResponse, sessionFor, sessionHandlers } from '../test/fixtures';
import { expectNoRawKeys } from '../test/i18nAssert';
import { renderWithStepUp } from '../test/render';
import { server } from '../test/server';
import { DownloadKeyDialog } from './DownloadKeyDialog';

const PASS = 'Canary-passphrase-4711';
const REASON = 'quarterly access review';
const OCTET = { headers: { 'Content-Type': 'application/octet-stream' } };
const PATH = '/api/v1/ssh-keys/k1/actions/download-private-key';

let created: Blob[];
let revoked: string[];
let downloads: string[];

beforeEach(() => {
  server.use(...sessionHandlers(sessionFor('admin')));
  created = [];
  revoked = [];
  downloads = [];
  Object.assign(URL, {
    createObjectURL: vi.fn((b: Blob) => {
      created.push(b);
      return 'blob:canary';
    }),
    revokeObjectURL: vi.fn((u: string) => revoked.push(u)),
  });
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
    downloads.push(this.download);
  });
});
afterEach(() => vi.restoreAllMocks());

function serveFile(onBody?: (b: unknown) => void) {
  server.use(
    http.post(PATH, async ({ request }) => {
      onBody?.(await request.json());
      return new HttpResponse('file-bytes', { headers: { 'Content-Type': 'application/octet-stream' } });
    }),
  );
}

const open = (props: Partial<Parameters<typeof DownloadKeyDialog>[0]> = {}, langs?: string[]) =>
  renderWithStepUp(<DownloadKeyDialog keyId="k1" label="Deploy Key" opened onClose={() => {}} {...props} />, langs);

async function fill(user: ReturnType<typeof userEvent.setup>, reason = REASON, pass = PASS, repeat = pass) {
  await user.type(await screen.findByLabelText(/^Reason/), reason);
  await user.type(screen.getByLabelText(/^Passphrase/), pass);
  await user.type(screen.getByLabelText(/^Repeat the passphrase/), repeat);
}

describe('DownloadKeyDialog', () => {
  it('warns, protects with a passphrase by default and keeps password managers out', async () => {
    await open();
    expect(await screen.findByText(/Anyone with this file can sign in/)).toBeInTheDocument();
    expect(screen.getByRole('checkbox', { name: 'Protect the file with a passphrase (recommended)' })).toBeChecked();
    for (const re of [/^Passphrase/, /^Repeat the passphrase/]) {
      const f = screen.getByLabelText(re);
      expect(f).toHaveAttribute('type', 'password');
      expect(f).toHaveAttribute('autocomplete', 'new-password');
      expect(f).toHaveAttribute('data-1p-ignore');
      expect(f).toHaveAttribute('data-lpignore', 'true');
    }
    expectNoRawKeys();
  });

  it('refuses a reason of 9 characters before any request', async () => {
    let calls = 0;
    server.use(http.post(PATH, () => (calls++, new HttpResponse('x'))));
    const user = userEvent.setup();
    await open();
    await fill(user, '123456789');
    await user.click(screen.getByRole('button', { name: 'Download' }));
    expect(await screen.findByText('Enter at least 10 characters.')).toBeInTheDocument();
    expect(calls).toBe(0);
  });

  it('refuses a passphrase that is too short or does not match, and sends nothing', async () => {
    let calls = 0;
    server.use(http.post(PATH, () => (calls++, new HttpResponse('x'))));
    const user = userEvent.setup();
    await open();
    await fill(user, REASON, PASS, PASS + 'x');
    await user.click(screen.getByRole('button', { name: 'Download' }));
    expect(await screen.findByText('The passphrases do not match.')).toBeInTheDocument();
    await user.clear(screen.getByLabelText(/^Passphrase/));
    await user.clear(screen.getByLabelText(/^Repeat the passphrase/));
    await user.type(screen.getByLabelText(/^Passphrase/), 'short');
    await user.type(screen.getByLabelText(/^Repeat the passphrase/), 'short');
    await user.click(screen.getByRole('button', { name: 'Download' }));
    expect(await screen.findByText('Enter at least 12 characters.')).toBeInTheDocument();
    expect(calls).toBe(0);
  });

  it('downloads once through one object URL, revokes it, clears the form and keeps the secrets out of storage and the console', async () => {
    const logs: string[] = [];
    (['log', 'info', 'warn', 'error', 'debug'] as const).forEach((m) => vi.spyOn(console, m).mockImplementation((...a: unknown[]) => void logs.push(a.map(String).join(' '))));
    const setItem = vi.spyOn(Storage.prototype, 'setItem');
    let body: unknown;
    serveFile((b) => (body = b));
    const user = userEvent.setup();
    const view = await open();
    const invalidate = vi.spyOn(view.client, 'invalidateQueries');
    await fill(user);
    await user.click(screen.getByRole('button', { name: 'Download' }));
    expect(await screen.findByText('The file was downloaded. Keep it safe and delete it when it is no longer needed.')).toBeInTheDocument();
    expect(body).toEqual({ reason: REASON, passphrase: PASS });
    expect(URL.createObjectURL).toHaveBeenCalledTimes(1);
    expect(created[0]).toBeInstanceOf(Blob);
    expect(downloads).toEqual(['alice-deploy-key.key']);
    await waitFor(() => expect(revoked).toEqual(['blob:canary']));
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['ssh-keys', 'k1'] });
    expect(screen.queryByLabelText(/^Passphrase/)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/^Reason/)).not.toBeInTheDocument();
    expect(document.body.innerHTML).not.toContain(PASS);
    expect(document.body.innerHTML).not.toContain(REASON);
    expect(setItem).not.toHaveBeenCalled();
    expect(JSON.stringify({ ...localStorage, ...sessionStorage })).not.toContain(PASS);
    expect(logs.join('\n')).not.toContain(PASS);
    expect(JSON.stringify(view.client.getQueryCache().getAll().map((q) => [q.queryKey, q.state.data]))).not.toContain(PASS);
  });

  it('sends no passphrase when protection is switched off', async () => {
    let body: unknown;
    serveFile((b) => (body = b));
    const user = userEvent.setup();
    await open();
    await user.click(await screen.findByRole('checkbox', { name: 'Protect the file with a passphrase (recommended)' }));
    expect(screen.queryByLabelText(/^Passphrase/)).not.toBeInTheDocument();
    await user.type(screen.getByLabelText(/^Reason/), REASON);
    await user.click(screen.getByRole('button', { name: 'Download' }));
    await screen.findByText(/The file was downloaded/);
    expect(body).toEqual({ reason: REASON });
  });

  it('asks for the step-up code and sends the same download again', async () => {
    let calls = 0;
    const bodies: unknown[] = [];
    server.use(
      http.post(PATH, async ({ request }) => {
        calls++;
        bodies.push(await request.json());
        return calls === 1 ? errorResponse(403, 'ALC-AUTH-0003', 'auth.stepup_required') : new HttpResponse('file-bytes', OCTET);
      }),
      http.post('/api/v1/auth/stepup', () => HttpResponse.json(sessionFor('admin'))),
    );
    const user = userEvent.setup();
    await open();
    await fill(user);
    await user.click(screen.getByRole('button', { name: 'Download' }));
    await user.type(await screen.findByLabelText('6-digit code'), '123456');
    // the typed passphrase is no longer in the form while the code is asked for
    expect(screen.getByLabelText(/^Passphrase/)).toHaveValue('');
    await user.click(screen.getByRole('button', { name: 'Confirm' }));
    expect(await screen.findByText(/The file was downloaded/)).toBeInTheDocument();
    expect(calls).toBe(2);
    expect(bodies[1]).toEqual({ reason: REASON, passphrase: PASS });
    expect(created).toHaveLength(1);
  });

  it('shows the error and clears the passphrases but keeps the reason after a refusal', async () => {
    server.use(http.post(PATH, () => errorResponse(409, 'ALC-KEY-0006', 'sshkey.not_managed')));
    const user = userEvent.setup();
    await open();
    await fill(user);
    await user.click(screen.getByRole('button', { name: 'Download' }));
    expect(await screen.findByRole('alert')).toBeInTheDocument();
    expect(screen.getByLabelText(/^Passphrase/)).toHaveValue('');
    expect(screen.getByLabelText(/^Repeat the passphrase/)).toHaveValue('');
    expect(screen.getByLabelText(/^Reason/)).toHaveValue(REASON);
    expect(document.body.innerHTML).not.toContain(PASS);
    expect(created).toHaveLength(0);
  });

  it('wipes everything when it is cancelled, even if the parent keeps it open', async () => {
    const onClose = vi.fn();
    const user = userEvent.setup();
    await open({ onClose });
    await fill(user);
    await user.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(onClose).toHaveBeenCalled();
    expect(screen.getByLabelText(/^Passphrase/)).toHaveValue('');
    expect(screen.getByLabelText(/^Reason/)).toHaveValue('');
    expect(document.body.innerHTML).not.toContain(PASS);
  });

  it('renders in Turkish with no missing key', async () => {
    server.use(...sessionHandlers(sessionFor('admin', 'tr')));
    await open({}, ['tr-TR']);
    expect(await screen.findByRole('dialog', { name: 'Özel anahtarı indir' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'İndir' })).toBeInTheDocument();
    expectNoRawKeys();
  });
});
