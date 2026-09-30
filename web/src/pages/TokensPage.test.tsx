import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import type { ApiToken, SessionInfo } from '../api/types';
import { operatorSession, sessionFor } from '../test/fixtures';
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

  it('names the revoke button of each token in Turkish', async () => {
    signedInAs(sessionFor('operator', 'tr'), [token]);
    await renderRoute('/tokens', { languages: ['tr-TR'] });
    expect(await screen.findByRole('button', { name: 'İptal et: backup script' })).toBeInTheDocument();
  });
});
