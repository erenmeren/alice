import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { errorResponse, jobFixture, platformKeyFixture, sessionFor, sessionHandlers, tlsHostKeyFixture, windowsWinRMTargetFixture } from '../test/fixtures';
import { expectNoRawKeys } from '../test/i18nAssert';
import { renderWithStepUp } from '../test/render';
import { server } from '../test/server';
import { AddServerModal, WinRMSetupScript } from './AddServerModal';
import commonEn from '@locales/common/en.json';

// R71 Ruling 22: the WinRM transport of a Windows server in the Add server dialog.
const WN26 = 'Under WinRM, anyone with this account\'s password can run any command on the server as an administrator. With OpenSSH, Alice\'s key can run only alice-helper.exe.';
const SET_AT = '2026-10-31T10:00:00Z';
// The password is built at run time (never a literal a secret scanner flags).
const secret = (n: number) => Array.from({ length: n }, (_, i) => String.fromCharCode(0x61 + ((i * 7) % 26))).join('');

async function openWindows(lang = 'en') {
  server.use(...sessionHandlers(sessionFor('admin', lang)), http.post('/api/v1/auth/stepup', () => HttpResponse.json(sessionFor('admin', lang))));
  const onAdded = vi.fn();
  const view = await renderWithStepUp(<AddServerModal onClose={vi.fn()} onAdded={onAdded} />, lang === 'tr' ? ['tr-TR'] : ['en-US']);
  const dialog = await screen.findByRole('dialog');
  return { dialog, onAdded, view };
}

describe('AddServerModal WinRM transport', () => {
  it('offers the transport for a Windows server only, OpenSSH by default', async () => {
    const { dialog } = await openWindows();
    expect(within(dialog).queryByLabelText(/^Connection/)).not.toBeInTheDocument();
    await userEvent.selectOptions(within(dialog).getByLabelText('Server type'), 'windows');
    const transport = within(dialog).getByLabelText(/^Connection/);
    expect(transport).toHaveValue('ssh');
    expect(within(transport).getAllByRole('option').map((o) => o.textContent)).toEqual(['OpenSSH (recommended)', 'WinRM over HTTPS']);
    expect(within(dialog).getByLabelText(/^SSH port/)).toHaveValue('22');
    expect(within(dialog).queryByText(WN26)).not.toBeInTheDocument();
    expect(await within(dialog).findByTestId('add-server-script')).toHaveTextContent('# windows setup script');
  });

  it('keeps a typed port when the type changes between Linux servers', async () => {
    const { dialog } = await openWindows();
    const port = within(dialog).getByLabelText(/^SSH port/);
    await userEvent.clear(port);
    await userEvent.type(port, '2222');
    await userEvent.selectOptions(within(dialog).getByLabelText('Server type'), 'nginx');
    expect(within(dialog).getByLabelText(/^SSH port/)).toHaveValue('2222');
  });

  it('sets port 5986 under WinRM, shows the WN-26 warning and the account forms, and goes back to 22', async () => {
    const { dialog } = await openWindows();
    await userEvent.selectOptions(within(dialog).getByLabelText('Server type'), 'windows');
    await userEvent.selectOptions(within(dialog).getByLabelText(/^Connection/), 'winrm');
    expect(within(dialog).getByLabelText(/^WinRM HTTPS port/)).toHaveValue('5986');
    expect(within(dialog).getByText(WN26)).toBeInTheDocument();
    expect(within(dialog).getByLabelText(/^Windows account/)).toHaveAccessibleDescription(expect.stringContaining('alice, .\\alice, SERVER\\alice or DOMAIN\\alice'));
    // The SSH script does not prepare WinRM: the WinRM one comes after the server is added.
    expect(within(dialog).queryByTestId('add-server-script')).not.toBeInTheDocument();
    await userEvent.selectOptions(within(dialog).getByLabelText(/^Connection/), 'ssh');
    expect(within(dialog).getByLabelText(/^SSH port/)).toHaveValue('22');
    expect(within(dialog).queryByText(WN26)).not.toBeInTheDocument();
  });

  it('refuses a UPN under WinRM and accepts .\\alice', async () => {
    let posted = 0;
    server.use(
      http.post('/api/v1/targets', () => {
        posted++;
        return HttpResponse.json({ target: windowsWinRMTargetFixture, job_id: 'job-1', status_url: '/api/v1/jobs/job-1' }, { status: 201 });
      }),
      http.get('/api/v1/targets/:id/winrm-setup', () => HttpResponse.json({ script: '# winrm setup script' })),
    );
    const { dialog } = await openWindows();
    await userEvent.selectOptions(within(dialog).getByLabelText('Server type'), 'windows');
    await userEvent.selectOptions(within(dialog).getByLabelText(/^Connection/), 'winrm');
    await userEvent.type(within(dialog).getByLabelText(/^Name/), 'iis-02');
    await userEvent.type(within(dialog).getByLabelText(/^Address/), 'iis-02.example.com');
    const account = within(dialog).getByLabelText(/^Windows account/);
    await userEvent.clear(account);
    await userEvent.type(account, 'alice@corp.example');
    expect(account).toHaveAccessibleDescription(expect.stringContaining('e-mail-style name'));
    await userEvent.click(within(dialog).getByRole('button', { name: 'Connect' }));
    expect(posted).toBe(0);
    await userEvent.clear(account);
    await userEvent.type(account, '.\\alice');
    expect(account).not.toHaveAccessibleDescription(expect.stringContaining('e-mail-style name'));
    await userEvent.click(within(dialog).getByRole('button', { name: 'Connect' }));
    await waitFor(() => expect(posted).toBe(1));
  });

  it('after creation shows the WinRM script, then the password with step-up, then the TLS identity', async () => {
    const bodies: Record<string, unknown> = {};
    const observed = tlsHostKeyFixture({ id: 'hk-tls', status: 'observed', confirmed_at: null, confirmed_by_name: '' });
    let stepUpAsked = false;
    server.use(
      http.post('/api/v1/targets', async ({ request }) => {
        bodies.create = await request.json();
        return HttpResponse.json({ target: windowsWinRMTargetFixture, job_id: 'job-1', status_url: '/api/v1/jobs/job-1' }, { status: 201 });
      }),
      http.get('/api/v1/targets/:id/winrm-setup', () => HttpResponse.json({ script: '# winrm setup script\n$AliceUser = \'.\\alice\'' })),
      http.put('/api/v1/targets/:id/winrm-password', async ({ request }) => {
        if (!stepUpAsked) {
          stepUpAsked = true;
          return errorResponse(403, 'ALC-AUTH-0003', 'auth.stepup_required');
        }
        bodies.password = { body: await request.json(), ifMatch: request.headers.get('If-Match') };
        return HttpResponse.json({ ...windowsWinRMTargetFixture, winrm_password_set_at: SET_AT, version: windowsWinRMTargetFixture.version + 1 });
      }),
      http.post('/api/v1/targets/:id/actions/test', () => HttpResponse.json({ job_id: 'job-2', status_url: '/api/v1/jobs/job-2' }, { status: 202 })),
      http.get('/api/v1/jobs/:id', ({ params }) =>
        HttpResponse.json(
          params.id === 'job-2'
            ? jobFixture({ id: 'job-2', status: 'failed', error: { code: 'ALC-TGT-0002', reason: 'target.host_key_unconfirmed', params: { fingerprint: observed.fingerprint } } })
            : params.id === 'job-1'
              ? jobFixture({ id: 'job-1', status: 'failed', error: { code: 'ALC-WIN-0025', reason: 'windows.winrm_password_missing' } })
              : jobFixture({ id: 'job-3', status: 'succeeded' }),
        ),
      ),
      http.get('/api/v1/targets/:id/host-keys', () => HttpResponse.json({ items: [observed] })),
      http.post('/api/v1/targets/:id/host-keys/:keyId/actions/confirm', async ({ request }) => {
        bodies.confirm = await request.json();
        return HttpResponse.json({ job_id: 'job-3', status_url: '/api/v1/jobs/job-3' }, { status: 202 });
      }),
    );
    const { dialog, onAdded } = await openWindows();
    await userEvent.selectOptions(within(dialog).getByLabelText('Server type'), 'windows');
    await userEvent.selectOptions(within(dialog).getByLabelText(/^Connection/), 'winrm');
    await userEvent.type(within(dialog).getByLabelText(/^Name/), 'iis-02');
    await userEvent.type(within(dialog).getByLabelText(/^Address/), 'iis-02.example.com');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Connect' }));

    // 1. The script of this server, from the endpoint.
    expect(await within(dialog).findByTestId('winrm-setup-script')).toHaveTextContent('# winrm setup script');
    expect(within(dialog).getByText('WinRM setup script')).toBeInTheDocument();
    expect(bodies.create).toEqual({ name: 'iis-02', type: 'windows', host: 'iis-02.example.com', port: 5986, username: 'alice', transport: 'winrm' });

    // 2. The password, with the step-up.
    const pw = secret(16);
    await userEvent.type(within(dialog).getByLabelText(/^WinRM password/), pw);
    await userEvent.click(within(dialog).getByRole('button', { name: 'Set password' }));
    await userEvent.type(await screen.findByLabelText('6-digit code'), '123456');
    await userEvent.click(screen.getByRole('button', { name: 'Confirm' }));
    await waitFor(() => expect(bodies.password).toEqual({ body: { password: pw }, ifMatch: `"${windowsWinRMTargetFixture.version}"` }));

    // 3. The connection test finds the listener's identity, which the Administrator confirms.
    const confirm = await screen.findByRole('dialog', { name: 'Is this your server?' });
    expect(within(confirm).getByText('TLS certificate key (SPKI SHA-256)')).toBeInTheDocument();
    expect(within(confirm).getByTestId('host-key-fingerprint')).toHaveTextContent(observed.fingerprint);
    expect(document.body.innerHTML).not.toContain(pw);
    await userEvent.click(within(confirm).getByRole('button', { name: 'Yes, this is my server' }));
    await waitFor(() => expect(onAdded).toHaveBeenCalled());
    expect(bodies.confirm).toEqual({ fingerprint: observed.fingerprint });
  });

  it('is worded in Turkish', async () => {
    const { dialog, view } = await openWindows('tr');
    await userEvent.selectOptions(within(dialog).getByLabelText('Sunucu türü'), 'windows');
    await userEvent.selectOptions(within(dialog).getByLabelText(/^Bağlantı/), 'winrm');
    expect(within(dialog).getAllByRole('option', { name: /WinRM|OpenSSH/ }).map((o) => o.textContent)).toEqual(['OpenSSH (önerilen)', 'HTTPS üzerinden WinRM']);
    expectNoRawKeys(view.container);
  });
});

// R72 Ruling 3 (B1): Alice's address, when typed, reaches the served scripts as ?from=; the API decides what is valid.
describe('Alice\'s address in the setup scripts', () => {
  const ADDRESS = /^Alice's address/;

  // platformKey answers the platform key with the address in the Windows script and records every from it was asked.
  function platformKey() {
    const froms: (string | null)[] = [];
    server.use(
      http.get('/api/v1/ssh-keys/platform-key', ({ request }) => {
        const from = new URL(request.url).searchParams.get('from');
        froms.push(from);
        if (from === 'not-an-ip') return errorResponse(422, 'ALC-SYS-0006', 'validation.failed', { details: [{ field: 'from', code: 'validation.pattern' }] });
        const windows = { sudoers: '', script: `# windows setup script\n$AliceAddress = '${from ?? ''}'\n$AliceUser = 'alice'\n` };
        return HttpResponse.json({ ...platformKeyFixture, profiles: { ...platformKeyFixture.profiles, windows } });
      }),
    );
    return froms;
  }

  it('sends the typed address to the platform key and shows the script it answers', async () => {
    const froms = platformKey();
    const { dialog } = await openWindows();
    await userEvent.selectOptions(within(dialog).getByLabelText('Server type'), 'windows');
    expect(await within(dialog).findByTestId('add-server-script')).toHaveTextContent("$AliceAddress = ''");
    expect(froms).toEqual([null]);
    await userEvent.type(within(dialog).getByLabelText(ADDRESS), '10.0.0.5');
    await waitFor(() => expect(within(dialog).getByTestId('add-server-script')).toHaveTextContent("$AliceAddress = '10.0.0.5'"));
    expect(froms.at(-1)).toBe('10.0.0.5');
    expect(within(dialog).getByLabelText(ADDRESS)).toHaveAccessibleDescription(expect.stringContaining('to that address only'));
    expect(within(dialog).getByText(/With Alice's address above, the key line and the firewall rule accept that address only/)).toBeInTheDocument();
  });

  it('shows the API\'s field error for a bad address and no script', async () => {
    platformKey();
    const { dialog } = await openWindows();
    await userEvent.selectOptions(within(dialog).getByLabelText('Server type'), 'windows');
    await within(dialog).findByTestId('add-server-script');
    await userEvent.type(within(dialog).getByLabelText(ADDRESS), 'not-an-ip');
    await waitFor(() => expect(within(dialog).getByLabelText(ADDRESS)).toHaveAccessibleDescription(expect.stringContaining(commonEn.validation.pattern)));
    expect(within(dialog).queryByTestId('add-server-script')).not.toBeInTheDocument();
  });

  it('hides the script while the typed address is not yet asked, so no older script can be copied', async () => {
    platformKey();
    const { dialog } = await openWindows();
    await userEvent.selectOptions(within(dialog).getByLabelText('Server type'), 'windows');
    await within(dialog).findByTestId('add-server-script');
    await userEvent.type(within(dialog).getByLabelText(ADDRESS), '10.0.0.6');
    expect(within(dialog).queryByTestId('add-server-script')).not.toBeInTheDocument();
    await waitFor(() => expect(within(dialog).getByTestId('add-server-script')).toHaveTextContent("$AliceAddress = '10.0.0.6'"));
  });

  it('says on a Linux server that the address limits the key line only', async () => {
    platformKey();
    const { dialog } = await openWindows();
    await userEvent.selectOptions(within(dialog).getByLabelText('Server type'), 'nginx');
    await within(dialog).findByTestId('add-server-script');
    const help = within(dialog).getByLabelText(ADDRESS);
    expect(help).toHaveAccessibleDescription(expect.stringContaining("Alice's key line accepts that address only"));
    expect(help).not.toHaveAccessibleDescription(expect.stringContaining('firewall'));
  });

  it('asks the WinRM setup script with the typed address, and without one when the field is empty', async () => {
    const froms: (string | null)[] = [];
    server.use(
      ...sessionHandlers(sessionFor('admin')),
      http.get('/api/v1/targets/:id/winrm-setup', ({ request }) => {
        const from = new URL(request.url).searchParams.get('from');
        froms.push(from);
        return HttpResponse.json({ script: `# winrm setup script\n$AliceAddress = '${from ?? ''}'` });
      }),
    );
    await renderWithStepUp(<WinRMSetupScript targetId={windowsWinRMTargetFixture.id} />);
    expect(await screen.findByTestId('winrm-setup-script')).toHaveTextContent("$AliceAddress = ''");
    expect(froms).toEqual([null]);
    expect(screen.getByText(/to Alice's address when you entered one above/)).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText(ADDRESS), 'fd00::5');
    await waitFor(() => expect(screen.getByTestId('winrm-setup-script')).toHaveTextContent("$AliceAddress = 'fd00::5'"));
    expect(froms.at(-1)).toBe('fd00::5');
    await userEvent.clear(screen.getByLabelText(ADDRESS));
    await waitFor(() => expect(screen.getByTestId('winrm-setup-script')).toHaveTextContent("$AliceAddress = ''"));
    expect(froms.filter((f) => f === null).length).toBeGreaterThanOrEqual(1);
  });
});

// A9, A10 (R72): what a close without a password means, and what a refused sign-in after the password needs.
describe('AddServerModal WinRM hints', () => {
  function created(testError: { code: string; reason: string }) {
    server.use(
      http.post('/api/v1/targets', () => HttpResponse.json({ target: windowsWinRMTargetFixture, job_id: 'job-1', status_url: '/api/v1/jobs/job-1' }, { status: 201 })),
      http.get('/api/v1/targets/:id/winrm-setup', () => HttpResponse.json({ script: '# winrm setup script' })),
      http.put('/api/v1/targets/:id/winrm-password', () => HttpResponse.json({ ...windowsWinRMTargetFixture, winrm_password_set_at: SET_AT, version: windowsWinRMTargetFixture.version + 1 })),
      http.post('/api/v1/targets/:id/actions/test', () => HttpResponse.json({ job_id: 'job-2', status_url: '/api/v1/jobs/job-2' }, { status: 202 })),
      http.get('/api/v1/jobs/:id', () => HttpResponse.json(jobFixture({ id: 'job-2', status: 'failed', error: testError }))),
    );
  }

  async function toWinRMPhase() {
    const { dialog } = await openWindows();
    await userEvent.selectOptions(within(dialog).getByLabelText('Server type'), 'windows');
    await userEvent.selectOptions(within(dialog).getByLabelText(/^Connection/), 'winrm');
    await userEvent.type(within(dialog).getByLabelText(/^Name/), 'iis-02');
    await userEvent.type(within(dialog).getByLabelText(/^Address/), 'iis-02.example.com');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Connect' }));
    await within(dialog).findByTestId('winrm-setup-script');
    return dialog;
  }

  it('the winrm phase says what a close without the password means', async () => {
    created({ code: 'ALC-WIN-0024', reason: 'windows.winrm_auth_refused' });
    const dialog = await toWinRMPhase();
    expect(within(dialog).getByText('If you close now, Alice keeps the server without a password and cannot reach it. You can set the password later on the server\'s page.')).toBeInTheDocument();
  });

  it('a refused sign-in after the password shows the hint', async () => {
    created({ code: 'ALC-WIN-0024', reason: 'windows.winrm_auth_refused' });
    const dialog = await toWinRMPhase();
    await userEvent.type(within(dialog).getByLabelText(/^WinRM password/), secret(16));
    await userEvent.click(within(dialog).getByRole('button', { name: 'Set password' }));
    expect(
      await within(dialog).findByText('The password is saved. If the server refused the sign-in, compare the password with the one set on the server, then use Test connection on the server\'s page.'),
    ).toBeInTheDocument();
    expect(within(dialog).queryByText(/If you close now/)).not.toBeInTheDocument();
  });
});
