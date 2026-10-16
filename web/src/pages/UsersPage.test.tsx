import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import type { SessionInfo, User } from '../api/types';
import { adminSession, DIRECTORY_ID, directoryFixture, errorResponse, providerFixture, sessionFor } from '../test/fixtures';
import { renderRoute } from '../test/render';
import { server } from '../test/server';

const operator: User = {
  id: '0192a000-0000-7000-8000-00000000000a',
  username: 'operator1',
  display_name: 'Oğuz Işık',
  email: '',
  role: 'operator',
  locale: 'tr',
  disabled: false,
  mfa_enrolled: false,
  last_login_at: null,
  created_at: '2026-09-30T08:00:00Z',
  auth_source: 'local',
  sso_provider_id: null,
  ldap_directory_id: null,
};

function signedInAs(session: SessionInfo) {
  server.use(
    http.get('/api/v1/auth/session', () => HttpResponse.json(session)),
    http.get('/api/v1/setup/status', () =>
      HttpResponse.json({ admin_exists: true, recovery_passphrase_set: true, completed: true, default_locale: 'en' }),
    ),
    http.get('/api/v1/version', () => HttpResponse.json({ version: '1.2.3', commit: 'abc', build_time: 't' })),
  );
}

function withUsers(items: User[]) {
  server.use(http.get('/api/v1/users', () => HttpResponse.json({ items })));
}

describe('UsersPage', () => {
  beforeEach(() => localStorage.clear());

  it('lists users with localized roles in English', async () => {
    signedInAs(adminSession);
    withUsers([adminSession.user, operator]);
    await renderRoute('/users');
    expect(await screen.findByRole('heading', { name: 'People & access' })).toBeInTheDocument();
    const row = (await screen.findByText('operator1')).closest('tr')!;
    expect(within(row).getByText('Operator')).toBeInTheDocument();
    expect(within(row).getByText('Authenticator app not set up yet')).toBeInTheDocument();
    expect(within(row).getByText('Oğuz Işık')).toBeInTheDocument();
  });

  it('has the design header, the three role cards and the people table in its scroll region', async () => {
    signedInAs(adminSession);
    withUsers([adminSession.user, { ...operator, email: 'oguz@example.com', disabled: true, last_login_at: '2026-10-01T09:30:00Z' }]);
    await renderRoute('/users');
    const h1 = await screen.findByRole('heading', { level: 1, name: 'People & access' });
    expect(h1.closest('header')).toHaveTextContent('Clear responsibilities. Deliberate permissions.');
    expect(within(h1.closest('header')!).getByRole('button', { name: 'Add user' })).toBeInTheDocument();
    const roles = screen.getByRole('group', { name: 'Roles' });
    const cards = within(roles).getAllByRole('heading', { level: 2 });
    expect(cards.map((c) => c.textContent)).toEqual(['Administrator', 'Operator', 'Auditor']);
    expect(roles).toHaveTextContent('Manage the installation, identities and policies.');
    expect(roles).toHaveTextContent('Discover inventory and operate certificates and SSH keys.');
    expect(roles).toHaveTextContent('Read inventory, inspect evidence and export records.');

    const table = await screen.findByRole('table', { name: 'People' });
    expect(screen.getByRole('group', { name: 'Table, scrolls sideways' })).toContainElement(table);
    expect(within(table).getAllByRole('columnheader').map((h) => h.textContent)).toEqual([
      'Person',
      'Role',
      'Sign-in method',
      'Status',
      'Last sign-in',
      'Actions',
    ]);
    const row = within(table).getByText('operator1').closest('tr')!;
    // Person: initials, name, user name and e-mail; then the role, the sign-in method with the authenticator state, the status.
    expect(within(row).getByText('OI')).toHaveAttribute('aria-hidden', 'true');
    expect(within(row).getByText('Oğuz Işık')).toBeInTheDocument();
    expect(within(row).getByText('oguz@example.com')).toBeInTheDocument();
    expect(within(row).getByText('Operator')).toBeInTheDocument();
    expect(within(row).getByText('Local account').closest('.mantine-Badge-root')).toHaveAttribute('data-tone', 'warning');
    expect(within(row).getByText('Disabled').closest('.mantine-Badge-root')).toHaveAttribute('data-tone', 'neutral');
    expect(within(row).getByRole('button', { name: 'Manage operator1' })).toBeInTheDocument();
    const admin = within(table).getByText('admin').closest('tr')!;
    expect(within(admin).getByText('Authenticator app set up')).toBeInTheDocument();
    expect(within(admin).getByText('Local account').closest('.mantine-Badge-root')).toHaveAttribute('data-tone', 'success');
    expect(within(admin).getByText('Active').closest('.mantine-Badge-root')).toHaveAttribute('data-tone', 'success');
    expect(within(admin).getByText('Never')).toBeInTheDocument();
  });

  it('is fully translated in Turkish', async () => {
    signedInAs(sessionFor('admin', 'tr')); // the signed-in user's locale wins over the browser language
    withUsers([operator]);
    await renderRoute('/users', { languages: ['tr-TR'] });
    expect(await screen.findByRole('heading', { name: 'Kişiler ve erişim' })).toBeInTheDocument();
    const row = (await screen.findByText('operator1')).closest('tr')!;
    expect(within(row).getByText('Operatör')).toBeInTheDocument();
    expect(within(row).getByText('Doğrulama uygulaması henüz kurulmadı')).toBeInTheDocument();
    expect(screen.getByRole('group', { name: 'Roller' })).toHaveTextContent('Envanteri okur, kanıtları inceler ve kayıtları dışa aktarır.');
    expect(screen.getByRole('button', { name: 'Kullanıcı ekle' })).toBeInTheDocument();
  });

  it('creates a user with the chosen role and initial password', async () => {
    signedInAs(adminSession);
    withUsers([adminSession.user]);
    let body: unknown = null;
    server.use(
      http.post('/api/v1/users', async ({ request }) => {
        body = await request.json();
        return HttpResponse.json({ ...operator, username: 'auditor1', role: 'auditor' }, { status: 201 });
      }),
    );
    await renderRoute('/users');
    await userEvent.click(await screen.findByRole('button', { name: 'Add user' }));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByLabelText(/^Username/)).toHaveAccessibleDescription(
      '2 to 64 characters: English letters (A–Z), digits, dot, underscore or hyphen. Start with a letter or digit.',
    );
    await userEvent.type(within(dialog).getByLabelText(/^Username/), 'auditor1');
    await userEvent.type(within(dialog).getByLabelText(/^Full name/), 'Ayşe Denetçi');
    await userEvent.selectOptions(within(dialog).getByLabelText(/^Role/), 'auditor');
    await userEvent.type(within(dialog).getByLabelText(/^Initial password/), 'auditor-password-2026');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Create user' }));
    await waitFor(() =>
      expect(body).toEqual({
        username: 'auditor1',
        display_name: 'Ayşe Denetçi',
        email: '',
        role: 'auditor',
        password: 'auditor-password-2026',
      }),
    );
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  });

  it('shows the server error when the last administrator would be demoted', async () => {
    signedInAs(adminSession);
    withUsers([adminSession.user]);
    server.use(
      http.patch('/api/v1/users/:id', () =>
        HttpResponse.json(
          {
            error: {
              code: 'ALC-USR-0002',
              reason: 'user.last_admin',
              message_key: 'errors.user.last_admin',
              message: 'At least one administrator must remain.',
              request_id: 'req-last-admin',
              retryable: false,
            },
          },
          { status: 409 },
        ),
      ),
    );
    await renderRoute('/users');
    await userEvent.click(await screen.findByRole('button', { name: 'Manage admin' }));
    await userEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Edit' }));
    const dialog = await screen.findByRole('dialog');
    await userEvent.selectOptions(within(dialog).getByLabelText(/^Role/), 'operator');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save changes' }));
    const alert = await within(dialog).findByRole('alert');
    expect(alert).toHaveTextContent('req-last-admin');
    expect(screen.getByRole('dialog')).toBeInTheDocument();
  });

  it('resets two-factor sign-in and signs a user out everywhere', async () => {
    signedInAs(adminSession);
    withUsers([adminSession.user, operator]);
    const calls: string[] = [];
    server.use(
      http.post('/api/v1/users/:id/actions/:action', ({ params }) => {
        calls.push(`${String(params.id)} ${String(params.action)}`);
        return new HttpResponse(null, { status: 204 });
      }),
    );
    await renderRoute('/users');
    await userEvent.click(await screen.findByRole('button', { name: 'Manage operator1' }));
    await userEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Reset two-factor sign-in' }));
    let dialog = await screen.findByRole('dialog');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Reset two-factor sign-in' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());

    await userEvent.click(screen.getByRole('button', { name: 'Manage operator1' }));
    await userEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Sign out everywhere' }));
    dialog = await screen.findByRole('dialog');
    // AUD-12: signing someone out everywhere also revokes their API tokens.
    expect(dialog).toHaveTextContent('The person is signed out on every device and all their API tokens stop working.');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Sign out everywhere' }));
    await waitFor(() => expect(calls).toEqual([`${operator.id} reset-mfa`, `${operator.id} revoke-sessions`]));
  });

  it('disables a user', async () => {
    signedInAs(adminSession);
    withUsers([operator]);
    let body: unknown = null;
    server.use(
      http.patch('/api/v1/users/:id', async ({ request }) => {
        body = await request.json();
        return HttpResponse.json({ ...operator, disabled: true });
      }),
    );
    await renderRoute('/users');
    await userEvent.click(await screen.findByRole('button', { name: 'Manage operator1' }));
    await userEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Disable' }));
    const dialog = await screen.findByRole('dialog');
    expect(dialog).toHaveTextContent('API tokens');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Disable user' }));
    await waitFor(() => expect(body).toEqual({ disabled: true }));
  });

  it('says that setting a new password revokes the API tokens (AUD-12)', async () => {
    signedInAs(adminSession);
    withUsers([operator]);
    await renderRoute('/users');
    await userEvent.click(await screen.findByRole('button', { name: 'Manage operator1' }));
    await userEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Set a new password' }));
    expect(await screen.findByRole('dialog')).toHaveTextContent(
      'The person is signed out everywhere, their API tokens stop working, and they must use this password at the next sign-in. Give it to them in a safe way.',
    );
  });

  it('says it in Turkish with the established term for API tokens', async () => {
    signedInAs(sessionFor('admin', 'tr'));
    withUsers([operator]);
    await renderRoute('/users', { languages: ['tr-TR'] });
    await userEvent.click(await screen.findByRole('button', { name: 'Yönet: operator1' }));
    await userEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Yeni parola belirle' }));
    expect(await screen.findByRole('dialog')).toHaveTextContent(
      'Kişinin tüm oturumları kapatılır, API anahtarları çalışmaz olur ve bir sonraki girişte bu parolayı kullanması gerekir.',
    );
  });
});

describe('UsersPage access and step-up', () => {
  beforeEach(() => localStorage.clear());

  it('hides the page from non-administrators', async () => {
    signedInAs(sessionFor('operator'));
    await renderRoute('/users');
    expect(await screen.findByRole('alert')).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'People & access' })).not.toBeInTheDocument();
  });

  it('asks for an authenticator code and retries when step-up is required', async () => {
    signedInAs(adminSession);
    withUsers([operator]);
    let attempts = 0;
    server.use(
      http.patch('/api/v1/users/:id', () => {
        attempts += 1;
        if (attempts === 1) {
          return HttpResponse.json(
            {
              error: {
                code: 'ALC-AUTH-0003',
                reason: 'auth.stepup_required',
                message_key: 'errors.auth.stepup_required',
                message: 'Step-up required',
                request_id: 'req-step',
                retryable: false,
              },
            },
            { status: 403 },
          );
        }
        return HttpResponse.json({ ...operator, disabled: true });
      }),
      http.post('/api/v1/auth/stepup', () => HttpResponse.json(adminSession)),
    );
    await renderRoute('/users');
    await userEvent.click(await screen.findByRole('button', { name: 'Manage operator1' }));
    await userEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Disable' }));
    await userEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Disable user' }));
    const codeBox = await screen.findByLabelText(/code/i);
    await userEvent.type(codeBox, '123456');
    await userEvent.keyboard('{Enter}');
    await waitFor(() => expect(attempts).toBe(2));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  });

  it('marks SSO users and offers no password, MFA or role change for them', async () => {
    signedInAs(adminSession);
    const sso: User = { ...operator, id: 'u-sso', username: 'ayse@corp.example', display_name: 'Ayşe SSO', auth_source: 'oidc', sso_provider_id: 'p1', mfa_enrolled: false };
    withUsers([operator, sso]);
    server.use(http.get('/api/v1/sso/providers', () => HttpResponse.json({ items: [providerFixture()] })));
    await renderRoute('/users');
    const row = (await screen.findByText('ayse@corp.example')).closest('tr')!;
    expect(within(row).getByText('Single sign-on')).toBeInTheDocument();
    expect(await within(row).findByText('Corp IdP')).toBeInTheDocument();
    expect(within(row).getByText('At the identity provider')).toBeInTheDocument();
    expect(within(row).queryByText('Authenticator app not set up yet')).not.toBeInTheDocument();
    expect(within(row).queryByText('Local account')).not.toBeInTheDocument();
    const local = screen.getByText('operator1').closest('tr')!;
    expect(within(local).queryByText('Single sign-on')).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: 'Manage ayse@corp.example' }));
    const manage = await screen.findByRole('dialog');
    expect(within(manage).queryByRole('button', { name: 'Set a new password' })).not.toBeInTheDocument();
    expect(within(manage).queryByRole('button', { name: 'Reset two-factor sign-in' })).not.toBeInTheDocument();
    expect(within(manage).getByRole('button', { name: 'Sign out everywhere' })).toBeInTheDocument();
    expect(within(manage).getByRole('button', { name: 'Disable' })).toBeInTheDocument();
    await userEvent.click(within(manage).getByRole('button', { name: 'Edit' }));
    const edit = await screen.findByRole('dialog');
    expect(within(edit).queryByLabelText('Role')).not.toBeInTheDocument();
  });

  it('marks directory users with the directory, offers Reset two-factor sign-in but no password or role change', async () => {
    signedInAs(adminSession);
    const dir: User = { ...operator, id: 'u-dir', username: 'deniz', display_name: 'Deniz Kaya', auth_source: 'ldap', ldap_directory_id: DIRECTORY_ID, mfa_enrolled: true };
    withUsers([operator, dir]);
    let body: Record<string, unknown> | undefined;
    server.use(
      http.get('/api/v1/ldap/directories', () => HttpResponse.json({ items: [directoryFixture()] })),
      http.patch('/api/v1/users/u-dir', async ({ request }) => {
        body = (await request.json()) as Record<string, unknown>;
        return HttpResponse.json(dir);
      }),
    );
    await renderRoute('/users');
    const row = (await screen.findByText('deniz')).closest('tr')!;
    expect(within(row).getByText('Directory')).toBeInTheDocument();
    expect(await within(row).findByText('Corp AD')).toBeInTheDocument();
    expect(within(row).getByText('Authenticator app set up')).toBeInTheDocument();
    expect(within(row).queryByText('Local account')).not.toBeInTheDocument();
    expect(within(row).queryByText('Single sign-on')).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Manage deniz' }));
    const manage = await screen.findByRole('dialog');
    expect(within(manage).queryByRole('button', { name: 'Set a new password' })).not.toBeInTheDocument();
    expect(within(manage).getByRole('button', { name: 'Reset two-factor sign-in' })).toBeInTheDocument();
    await userEvent.click(within(manage).getByRole('button', { name: 'Edit' }));
    const edit = await screen.findByRole('dialog');
    expect(within(edit).queryByLabelText('Role')).not.toBeInTheDocument();
    await userEvent.click(within(edit).getByRole('button', { name: 'Save changes' }));
    await waitFor(() => expect(body).toBeDefined());
    expect(body).not.toHaveProperty('role');
  });

  it('leaves the directory name out when the directories cannot be read without a fresh verification', async () => {
    signedInAs(adminSession);
    withUsers([{ ...operator, id: 'u-dir', username: 'deniz', auth_source: 'ldap', ldap_directory_id: DIRECTORY_ID }]);
    let reads = 0;
    server.use(
      http.get('/api/v1/ldap/directories', () => {
        reads++;
        return errorResponse(403, 'ALC-AUTH-0003', 'auth.stepup_required');
      }),
    );
    await renderRoute('/users');
    const row = (await screen.findByText('deniz')).closest('tr')!;
    expect(within(row).getByText('Directory')).toBeInTheDocument();
    await waitFor(() => expect(reads).toBe(1));
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument(); // no step-up prompt for a name
  });

  it('sends no role when an SSO user is edited, and shows ALC-USR-0003 when the server refuses', async () => {
    signedInAs(adminSession);
    const sso: User = { ...operator, id: 'u-sso', username: 'ayse@corp.example', auth_source: 'oidc', sso_provider_id: 'p1' };
    withUsers([sso]);
    let body: Record<string, unknown> | undefined;
    server.use(
      http.get('/api/v1/sso/providers', () => HttpResponse.json({ items: [] })),
      http.patch('/api/v1/users/u-sso', async ({ request }) => {
        body = (await request.json()) as Record<string, unknown>;
        return errorResponse(409, 'ALC-USR-0003', 'user.sso_user');
      }),
    );
    await renderRoute('/users');
    await userEvent.click(await screen.findByRole('button', { name: 'Manage ayse@corp.example' }));
    await userEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Edit' }));
    await userEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Save changes' }));
    expect(await screen.findByText('This change is not possible for a single sign-on or directory user.')).toBeInTheDocument();
    expect(body).not.toHaveProperty('role');
  });

  it('shows why the list cannot be read', async () => {
    signedInAs(adminSession);
    server.use(http.get('/api/v1/users', () => errorResponse(500, 'ALC-SYS-0003', 'internal.unexpected')));
    await renderRoute('/users');
    expect(await screen.findByRole('alert')).toHaveTextContent('ALC-SYS-0003');
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
  });

  it('enables a disabled user, edits a name and e-mail, and sets a new password', async () => {
    signedInAs(adminSession);
    const disabled: User = { ...operator, disabled: true };
    withUsers([disabled]);
    const patches: unknown[] = [];
    let password: unknown = null;
    server.use(
      http.patch('/api/v1/users/:id', async ({ request }) => {
        patches.push(await request.json());
        return HttpResponse.json(disabled);
      }),
      http.post('/api/v1/users/:id/actions/reset-password', async ({ request }) => {
        password = await request.json();
        return new HttpResponse(null, { status: 204 });
      }),
    );
    await renderRoute('/users');
    await userEvent.click(await screen.findByRole('button', { name: 'Manage operator1' }));
    await userEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Enable' }));
    await userEvent.click(within(await screen.findByRole('dialog', { name: 'Enable operator1?' })).getByRole('button', { name: 'Enable user' }));
    await waitFor(() => expect(patches).toEqual([{ disabled: false }]));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());

    await userEvent.click(screen.getByRole('button', { name: 'Manage operator1' }));
    await userEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Edit' }));
    const edit = await screen.findByRole('dialog', { name: 'Edit operator1' });
    await userEvent.clear(within(edit).getByLabelText(/^Full name/));
    await userEvent.type(within(edit).getByLabelText(/^Full name/), 'Oğuz Yeni');
    await userEvent.type(within(edit).getByLabelText(/^Email/), 'oguz@example.com');
    await userEvent.click(within(edit).getByRole('button', { name: 'Save changes' }));
    await waitFor(() => expect(patches[1]).toEqual({ display_name: 'Oğuz Yeni', email: 'oguz@example.com', role: 'operator' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());

    await userEvent.click(screen.getByRole('button', { name: 'Manage operator1' }));
    await userEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Set a new password' }));
    const reset = await screen.findByRole('dialog', { name: 'Set a new password for operator1' });
    await userEvent.type(within(reset).getByLabelText(/^New password/), 'a brand new password');
    await userEvent.click(within(reset).getByRole('button', { name: 'Set password' }));
    await waitFor(() => expect(password).not.toBeNull());
    expect(JSON.stringify(password)).toContain('a brand new password');
  });
});
