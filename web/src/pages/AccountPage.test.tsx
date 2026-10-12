import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { errorResponse, sessionFor, sessionHandlers, ssoSessionFor } from '../test/fixtures';
import { renderRoute } from '../test/render';
import { server } from '../test/server';

async function fillPasswords(current: string, next: string, repeat: string) {
  await userEvent.type(await screen.findByLabelText('Current password'), current);
  await userEvent.type(screen.getByLabelText('New password'), next);
  await userEvent.type(screen.getByLabelText('Repeat new password'), repeat);
  await userEvent.click(screen.getByRole('button', { name: 'Change password' }));
}

describe('account page', () => {
  it('shows who is signed in', async () => {
    server.use(...sessionHandlers(sessionFor('auditor')));
    await renderRoute('/account');
    expect(await screen.findByRole('heading', { name: 'Your account' })).toBeInTheDocument();
    expect(screen.getByTestId('account-summary')).toHaveTextContent('Signed in as auditor (Auditor)');
  });

  it('has the design header, the profile panel and the appearance panel', async () => {
    server.use(...sessionHandlers(sessionFor('admin')));
    await renderRoute('/account');
    const h1 = await screen.findByRole('heading', { level: 1, name: 'Your account' });
    expect(h1.closest('header')).toHaveTextContent('Personal security, language and workspace preferences.');

    const profile = screen.getByRole('heading', { level: 2, name: 'Sign-in and recovery' }).closest('section')!;
    expect(within(profile).getByText('AY')).toHaveAttribute('aria-hidden', 'true');
    expect(within(profile).getByText('Ayşe Yılmaz')).toBeInTheDocument();
    expect(within(profile).getByText('Administrator')).toBeInTheDocument();
    expect(within(profile).getByText('admin@example.com')).toBeInTheDocument();
    expect(within(profile).getByTestId('account-summary')).toHaveTextContent('Signed in as admin (Administrator)');
    const facts = profile.querySelector('dl')!;
    expect(facts).toHaveTextContent('Local account + authenticator app');
    expect(within(facts).getByText('Enabled').closest('.mantine-Badge-root')).toHaveAttribute('data-tone', 'success');
    expect(within(profile).getByRole('button', { name: 'Create new recovery codes' })).toBeInTheDocument();
    expect(within(profile).getByRole('button', { name: 'Change password' })).toBeInTheDocument();
    expect(within(profile).getByLabelText('Current password')).toBeInTheDocument();

    const appearance = screen.getByRole('heading', { level: 2, name: 'A workspace that feels right' }).closest('section')!;
    expect(appearance).toHaveTextContent('Choose a color mode and information density. Your preference stays on this device.');
    const mode = within(appearance).getByRole('group', { name: 'Color mode' });
    expect(within(mode).getAllByRole('radio').map((r) => r.closest('label')!.textContent)).toEqual(['Light', 'Dark', 'System']);
    await userEvent.click(within(mode).getByRole('radio', { name: 'Dark' }));
    expect(localStorage.getItem('alice.colorScheme')).toBe('dark');
    await userEvent.click(within(appearance).getByRole('switch', { name: 'Compact tables' }));
    expect(localStorage.getItem('alice.density')).toBe('compact');
    expect(within(appearance).getByRole('combobox', { name: 'Language' })).toHaveValue('en');
    // The old pointer to the top bar's switch is gone: the language is chosen here.
    expect(screen.queryByText(/Use the language switcher at the top of the page/)).not.toBeInTheDocument();
  });

  it('saves the language chosen on the page to the account', async () => {
    let saved: unknown = null;
    server.use(
      ...sessionHandlers(sessionFor('operator')),
      http.put('/api/v1/auth/locale', async ({ request }) => {
        saved = await request.json();
        return new HttpResponse(null, { status: 204 });
      }),
    );
    await renderRoute('/account');
    await userEvent.selectOptions(await screen.findByRole('combobox', { name: 'Language' }), 'tr');
    expect(await screen.findByRole('heading', { level: 1, name: 'Hesabınız' })).toBeInTheDocument();
    await waitFor(() => expect(saved).toEqual({ locale: 'tr' }));
  });

  it('shows a single sign-on account without a password form or recovery codes', async () => {
    server.use(...sessionHandlers(ssoSessionFor('operator')));
    await renderRoute('/account');
    expect(await screen.findByRole('heading', { level: 1, name: 'Your account' })).toBeInTheDocument();
    expect(screen.getByTestId('account-summary')).toHaveTextContent('Signed in as ayse@corp.example (Operator)');
    expect(screen.getByText('Single sign-on')).toBeInTheDocument();
    expect(screen.getByText('At the identity provider').closest('.mantine-Badge-root')).toHaveAttribute('data-tone', 'neutral');
    expect(screen.getByText('Your password and second factor are managed by your identity provider, so they are not changed here.')).toBeInTheDocument();
    expect(screen.queryByLabelText('Current password')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Change password' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Create new recovery codes' })).not.toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 2, name: 'A workspace that feels right' })).toBeInTheDocument();
  });

  it('changes the password and keeps the user signed in with the new session', async () => {
    let body: unknown = null;
    let csrfAfter: string | null = null;
    const renewed = { ...sessionFor('operator'), csrf_token: 'csrf-renewed' };
    server.use(
      ...sessionHandlers(sessionFor('operator')),
      http.post('/api/v1/auth/password', async ({ request }) => {
        body = await request.json();
        return HttpResponse.json(renewed);
      }),
      http.post('/api/v1/auth/recovery-codes', ({ request }) => {
        csrfAfter = request.headers.get('X-CSRF-Token');
        return HttpResponse.json({ recovery_codes: ['AAAA-BBBB-CCCC-DDDD'] });
      }),
    );
    await renderRoute('/account');
    await fillPasswords('old password here', 'a much longer new one', 'a much longer new one');
    expect(await screen.findByText('Your password was changed. Your other sessions were signed out.')).toBeInTheDocument();
    expect(body).toEqual({ current_password: 'old password here', new_password: 'a much longer new one' });
    expect(screen.getByLabelText('Current password')).toHaveValue('');
    expect(screen.getByLabelText('New password')).toHaveValue('');
    expect(screen.getByLabelText('Repeat new password')).toHaveValue('');
    await userEvent.click(screen.getByRole('button', { name: 'Create new recovery codes' }));
    await waitFor(() => expect(csrfAfter).toBe('csrf-renewed'));
  });

  it('catches different new passwords locally', async () => {
    let called = false;
    server.use(
      ...sessionHandlers(sessionFor('operator')),
      http.post('/api/v1/auth/password', () => {
        called = true;
        return HttpResponse.json(sessionFor('operator'));
      }),
    );
    await renderRoute('/account');
    await fillPasswords('old password here', 'a much longer new one', 'a much longer new two');
    expect(await screen.findByRole('alert')).toHaveTextContent('The two new passwords are different.');
    expect(called).toBe(false);
  });

  it('explains a wrong current password', async () => {
    server.use(
      ...sessionHandlers(sessionFor('operator')),
      http.post('/api/v1/auth/password', () => errorResponse(422, 'ALC-AUTH-0011', 'auth.current_password_invalid')),
    );
    const { i18n } = await renderRoute('/account');
    await fillPasswords('wrong', 'a much longer new one', 'a much longer new one');
    expect(await screen.findByRole('alert')).toHaveTextContent(i18n.t('errors.auth.current_password_invalid.title'));
  });

  it('creates new recovery codes after confirming with a code', async () => {
    let calls = 0;
    server.use(
      ...sessionHandlers(sessionFor('admin')),
      http.post('/api/v1/auth/recovery-codes', () => {
        calls += 1;
        return calls === 1
          ? errorResponse(403, 'ALC-AUTH-0003', 'auth.stepup_required')
          : HttpResponse.json({ recovery_codes: ['AAAA-BBBB-CCCC-DDDD', 'EEEE-FFFF-GGGG-HHHH'] });
      }),
      http.post('/api/v1/auth/stepup', () => HttpResponse.json(sessionFor('admin'))),
    );
    await renderRoute('/account');
    await userEvent.click(await screen.findByRole('button', { name: 'Create new recovery codes' }));
    await screen.findByRole('dialog', { name: "Confirm it's you" });
    await userEvent.type(screen.getByLabelText('6-digit code'), '123456');
    await userEvent.click(screen.getByRole('button', { name: 'Confirm' }));
    expect(await screen.findByTestId('recovery-codes')).toHaveTextContent('EEEE-FFFF-GGGG-HHHH');
    await userEvent.click(screen.getByLabelText('I saved these codes in a safe place'));
    await userEvent.click(screen.getByRole('button', { name: 'Continue' }));
    expect(await screen.findByText('Your new recovery codes are active.')).toBeInTheDocument();
  });

  it('shows an authenticator that is not set up, and why new recovery codes could not be made', async () => {
    const session = sessionFor('operator');
    server.use(
      ...sessionHandlers({ ...session, user: { ...session.user, mfa_enrolled: false, email: '' } }),
      http.post('/api/v1/auth/recovery-codes', () => errorResponse(500, 'ALC-SYS-0003', 'internal.unexpected')),
    );
    await renderRoute('/account');
    expect((await screen.findByText('Not set up')).closest('.mantine-Badge-root')).toHaveAttribute('data-tone', 'warning');
    await userEvent.click(screen.getByRole('button', { name: 'Create new recovery codes' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('ALC-SYS-0003');
    expect(screen.queryByTestId('recovery-codes')).not.toBeInTheDocument();
  });
});
