import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import type { ApiToken, SessionInfo } from '../api/types';
import { errorResponse, operatorSession, sessionFor, ssoSessionFor } from '../test/fixtures';
import { renderRoute } from '../test/render';
import { server } from '../test/server';

const token: ApiToken = {
  id: '0192a000-0000-7000-8000-0000000000t1',
  user_id: operatorSession.user.id,
  name: 'backup script',
  prefix: 'alice_Ab12Cd',
  scope: 'read',
  expires_at: '2026-12-29T08:00:00Z',
  last_used_at: null,
  created_at: '2026-09-30T08:00:00Z',
};

function signedInAs(session: SessionInfo, items: ApiToken[]) {
  server.use(
    http.get('/api/v1/auth/session', () => HttpResponse.json(session)),
    http.get('/api/v1/setup/status', () =>
      HttpResponse.json({ admin_exists: true, recovery_passphrase_set: true, completed: true, default_locale: 'en' }),
    ),
    http.get('/api/v1/version', () => HttpResponse.json({ version: '1.2.3', commit: 'abc', build_time: 't' })),
    http.get('/api/v1/tokens', () => HttpResponse.json({ items })),
  );
}

describe('TokensPage', () => {
  beforeEach(() => localStorage.clear());

  it('lists own tokens in English', async () => {
    signedInAs(operatorSession, [token]);
    await renderRoute('/tokens');
    expect(await screen.findByRole('heading', { name: 'API tokens' })).toBeInTheDocument();
    const row = (await screen.findByText('backup script')).closest('tr')!;
    expect(within(row).getByText('alice_Ab12Cd')).toBeInTheDocument();
    expect(within(row).getByText('Read only')).toBeInTheDocument();
    expect(within(row).getByText('Never')).toBeInTheDocument();
  });

  it('has the design header, the boundary notice and the token table in its scroll region', async () => {
    signedInAs(operatorSession, [token]);
    await renderRoute('/tokens');
    const h1 = await screen.findByRole('heading', { level: 1, name: 'API tokens' });
    const header = h1.closest('header')!;
    expect(header).toHaveTextContent('Personal access for automation, bounded by your role.');
    expect(within(header).getByRole('button', { name: 'Create token' })).toBeInTheDocument();
    const bound = screen.getByText('A token never has more access than its owner').closest('[role="note"]')!;
    expect(bound).not.toBeNull();
    expect(bound).toHaveTextContent('Sensitive actions that need the browser, such as downloading a private key, are not possible with a token.');
    const table = await screen.findByRole('table', { name: 'Your API tokens' });
    expect(screen.getByRole('group', { name: 'Table, scrolls sideways' })).toContainElement(table);
    expect(within(table).getAllByRole('columnheader').map((h) => h.textContent)).toEqual(['Name', 'Starts with', 'Access', 'Expires', 'Last used', 'Actions']);
    const row = within(table).getByText('backup script').closest('tr')!;
    expect(within(row).getByText('Read only').closest('.mantine-Badge-root')).not.toBeNull();
    expect(within(row).getByRole('button', { name: 'Revoke token backup script' })).toHaveTextContent('Revoke');
  });

  it('says there are no tokens with the empty state and what tokens are for', async () => {
    signedInAs(operatorSession, []);
    await renderRoute('/tokens');
    expect(await screen.findByText('You have no API tokens.')).toBeInTheDocument();
    expect(screen.getByText(/API tokens let scripts and other tools use Alice on your behalf/)).toBeInTheDocument();
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
  });

  it('creates a token and shows the secret once', async () => {
    signedInAs(operatorSession, []);
    let body: unknown = null;
    server.use(
      http.post('/api/v1/tokens', async ({ request }) => {
        body = await request.json();
        return HttpResponse.json({ token: 'alice_SECRET-VALUE', item: { ...token, scope: 'operate' } }, { status: 201 });
      }),
    );
    await renderRoute('/tokens');
    await userEvent.click(await screen.findByRole('button', { name: 'Create token' }));
    const dialog = await screen.findByRole('dialog');
    await userEvent.type(within(dialog).getByLabelText(/^Name/), 'deploy bot');
    await userEvent.selectOptions(within(dialog).getByLabelText(/^Access/), 'operate');
    const days = within(dialog).getByLabelText(/^Valid for \(days\)/);
    await userEvent.clear(days);
    await userEvent.type(days, '30');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Create' }));
    expect(await screen.findByTestId('new-token')).toHaveTextContent('alice_SECRET-VALUE');
    expect(screen.getByText('Copy this token now. It will not be shown again.')).toBeInTheDocument();
    // The secret is shown once on the page: never in the address, never stored in the browser.
    expect(window.location.href).not.toContain('SECRET');
    expect(JSON.stringify({ ...localStorage })).not.toContain('SECRET');
    expect(screen.getByRole('button', { name: 'Copy' })).toBeInTheDocument();
    expect(body).toEqual({ name: 'deploy bot', scope: 'operate', expires_in_days: 30 });
    await userEvent.click(screen.getByRole('button', { name: 'Done' }));
    expect(screen.queryByTestId('new-token')).not.toBeInTheDocument();
  });

  it('offers only read access to auditors, in Turkish', async () => {
    signedInAs(sessionFor('auditor', 'tr'), []); // the signed-in user's locale wins over the browser language
    await renderRoute('/tokens', { languages: ['tr-TR'] });
    expect(await screen.findByRole('heading', { name: 'API anahtarları' })).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Anahtar oluştur' }));
    const dialog = await screen.findByRole('dialog');
    const access = within(dialog).getByLabelText(/^Erişim/);
    expect(within(access).getAllByRole('option').map((o) => o.textContent)).toEqual(['Salt okunur']);
  });

  it('revokes a token after confirmation', async () => {
    signedInAs(operatorSession, [token]);
    let deleted = '';
    server.use(
      http.delete('/api/v1/tokens/:id', ({ params }) => {
        deleted = String(params.id);
        return new HttpResponse(null, { status: 204 });
      }),
    );
    await renderRoute('/tokens');
    await userEvent.click(await screen.findByRole('button', { name: 'Revoke token backup script' }));
    const dialog = await screen.findByRole('dialog');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Revoke token' }));
    await waitFor(() => expect(deleted).toBe(token.id));
  });

  it('offers no token creation to a single sign-on user, who can still revoke a token (I-2)', async () => {
    signedInAs(ssoSessionFor('admin'), [token]);
    let posted = false;
    server.use(
      http.post('/api/v1/tokens', () => {
        posted = true;
        return HttpResponse.json({}, { status: 500 });
      }),
    );
    await renderRoute('/tokens');
    expect(await screen.findByRole('heading', { name: 'API tokens' })).toBeInTheDocument();
    expect(
      await screen.findByText('You sign in through single sign-on, so you cannot create API tokens. Ask an Administrator if a script needs one.'),
    ).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Create token' })).not.toBeInTheDocument();
    expect(screen.getByTestId('tokens-sso-note')).toHaveAttribute('role', 'note');
    expect(await screen.findByRole('button', { name: 'Revoke token backup script' })).toBeInTheDocument();
    expect(posted).toBe(false);
  });

  it('tells a single sign-on user in Turkish that tokens are not available', async () => {
    signedInAs(ssoSessionFor('operator', 'tr'), []);
    await renderRoute('/tokens', { languages: ['tr-TR'] });
    expect(await screen.findByRole('heading', { name: 'API anahtarları' })).toBeInTheDocument();
    expect(
      await screen.findByText(
        'Çoklu oturum açma (SSO) ile oturum açtığınız için API anahtarı oluşturamazsınız. Bir betik için anahtar gerekiyorsa bir Yöneticiye başvurun.',
      ),
    ).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Anahtar oluştur' })).not.toBeInTheDocument();
  });

  it('names the revoke button of each token in Turkish', async () => {
    signedInAs(sessionFor('operator', 'tr'), [token]);
    await renderRoute('/tokens', { languages: ['tr-TR'] });
    expect(await screen.findByRole('button', { name: 'İptal et: backup script' })).toBeInTheDocument();
  });

  it('shows why the list cannot be read', async () => {
    signedInAs(operatorSession, []);
    server.use(http.get('/api/v1/tokens', () => errorResponse(500, 'ALC-SYS-0003', 'internal.unexpected')));
    await renderRoute('/tokens');
    expect(await screen.findByRole('alert')).toHaveTextContent('ALC-SYS-0003');
  });

  it('marks an operate token and its last use, and copies a new token to the clipboard', async () => {
    signedInAs(operatorSession, [{ ...token, scope: 'operate', last_used_at: '2026-10-01T09:30:00Z' }]);
    server.use(http.post('/api/v1/tokens', () => HttpResponse.json({ token: 'alice_COPY-ME', item: token }, { status: 201 })));
    await renderRoute('/tokens');
    const row = (await screen.findByText('backup script')).closest('tr')!;
    expect(within(row).getByText('Read and operate').closest('.mantine-Badge-root')).toHaveAttribute('data-tone', 'info');
    expect(within(row).queryByText('Never')).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Create token' }));
    const dialog = await screen.findByRole('dialog');
    await userEvent.type(within(dialog).getByLabelText(/^Name/), 'ci');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Create' }));
    await screen.findByTestId('new-token');
    const user = userEvent.setup(); // provides the clipboard Mantine's CopyButton writes to
    await user.click(screen.getByRole('button', { name: 'Copy' }));
    expect(await navigator.clipboard.readText()).toBe('alice_COPY-ME');
    expect(await screen.findByRole('button', { name: 'Copied' })).toBeInTheDocument();
  });

  it('keeps the dialogs open with the server error, and closes them on Cancel or close', async () => {
    signedInAs(operatorSession, [token]);
    server.use(
      http.post('/api/v1/tokens', () => errorResponse(422, 'ALC-TOK-0001', 'token.scope_not_allowed')),
      http.delete('/api/v1/tokens/:id', () => errorResponse(500, 'ALC-SYS-0003', 'internal.unexpected')),
    );
    await renderRoute('/tokens');
    await userEvent.click(await screen.findByRole('button', { name: 'Create token' }));
    let dialog = await screen.findByRole('dialog');
    await userEvent.type(within(dialog).getByLabelText(/^Name/), 'ci');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Create' }));
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('ALC-TOK-0001');
    expect(screen.queryByTestId('new-token')).not.toBeInTheDocument();
    await userEvent.keyboard('{Escape}');
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());

    await userEvent.click(screen.getByRole('button', { name: 'Revoke token backup script' }));
    dialog = await screen.findByRole('dialog');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Revoke token' }));
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('ALC-SYS-0003');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  });
});
