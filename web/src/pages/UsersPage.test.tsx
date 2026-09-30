import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import type { SessionInfo, User } from '../api/types';
import { adminSession, sessionFor } from '../test/fixtures';
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
    expect(await screen.findByRole('heading', { name: 'Users' })).toBeInTheDocument();
    const row = (await screen.findByText('operator1')).closest('tr')!;
    expect(within(row).getByText('Operator')).toBeInTheDocument();
    expect(within(row).getByText('Not set up yet')).toBeInTheDocument();
    expect(within(row).getByText('Oğuz Işık')).toBeInTheDocument();
  });

  it('is fully translated in Turkish', async () => {
    signedInAs(sessionFor('admin', 'tr')); // the signed-in user's locale wins over the browser language
    withUsers([operator]);
    await renderRoute('/users', { languages: ['tr-TR'] });
    expect(await screen.findByRole('heading', { name: 'Kullanıcılar' })).toBeInTheDocument();
    expect(await screen.findByText('Operatör')).toBeInTheDocument();
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
    await userEvent.click(within(dialog).getByRole('button', { name: 'Disable user' }));
    await waitFor(() => expect(body).toEqual({ disabled: true }));
  });
});

describe('UsersPage access and step-up', () => {
  beforeEach(() => localStorage.clear());

  it('hides the page from non-administrators', async () => {
    signedInAs(sessionFor('operator'));
    await renderRoute('/users');
    expect(await screen.findByRole('alert')).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Users' })).not.toBeInTheDocument();
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
});
