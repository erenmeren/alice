import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { errorResponse, sessionFor, sessionHandlers } from '../test/fixtures';
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
    expect(await screen.findByRole('heading', { name: 'My account' })).toBeInTheDocument();
    expect(screen.getByTestId('account-summary')).toHaveTextContent('Signed in as auditor (Auditor)');
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
});
