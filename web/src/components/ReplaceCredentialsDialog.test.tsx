import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { accessFixture, CLIENT_ID, errorResponse, sessionFor, sessionHandlers, TENANT_ID, VAULT_ID, vaultFixture, vaultWith } from '../test/fixtures';
import { expectNoRawKeys } from '../test/i18nAssert';
import { renderWithStepUp } from '../test/render';
import { server } from '../test/server';
import { ReplaceCredentialsDialog } from './ReplaceCredentialsDialog';

const SECRET = 'fake-new-secret';

function asAdmin(lang = 'en') {
  server.use(...sessionHandlers(sessionFor('admin', lang)));
}

describe('ReplaceCredentialsDialog', () => {
  it('has the fields of adding a vault without the name and the address, and keeps the IDs', async () => {
    asAdmin();
    await renderWithStepUp(<ReplaceCredentialsDialog vault={vaultWith({}, { auth: 'client_secret' })} onClose={vi.fn()} onReplaced={vi.fn()} />);
    expect(screen.queryByLabelText(/^Name/)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/^Vault address/)).not.toBeInTheDocument();
    expect(screen.getByRole('radio', { name: 'Client secret' })).toBeChecked();
    expect(screen.getByLabelText(/^Directory \(tenant\) ID/)).toHaveValue(TENANT_ID);
    expect(screen.getByLabelText(/^Application \(client\) ID/)).toHaveValue(CLIENT_ID);
    expect(screen.getByLabelText(/^Secret value/)).toHaveValue('');
  });

  it('sends PUT vault-credentials with the vault version as If-Match and clears the secret', async () => {
    asAdmin();
    const user = userEvent.setup();
    let body: unknown = null;
    let ifMatch: string | null = null;
    server.use(
      http.put(`/api/v1/targets/${VAULT_ID}/vault-credentials`, async ({ request }) => {
        body = await request.json();
        ifMatch = request.headers.get('If-Match');
        return HttpResponse.json({ target: vaultFixture, access: accessFixture(), job_id: 'j1' });
      }),
    );
    const onReplaced = vi.fn();
    await renderWithStepUp(<ReplaceCredentialsDialog vault={vaultWith({}, { auth: 'client_secret' })} onClose={vi.fn()} onReplaced={onReplaced} />);
    await user.type(screen.getByLabelText(/^Secret value/), SECRET);
    await user.type(screen.getByLabelText(/^The secret expires on/), '2027-01-31');
    await user.click(screen.getByRole('button', { name: 'Replace credentials' }));
    await waitFor(() => expect(onReplaced).toHaveBeenCalled());
    expect(ifMatch).toBe('"4"');
    expect(body).toEqual({ auth: 'client_secret', tenant_id: TENANT_ID, client_id: CLIENT_ID, client_secret: SECRET, secret_expires_on: '2027-01-31T23:59:59Z' });
    expect(document.body.innerHTML).not.toContain(SECRET);
  });

  it('asks for step-up, keeps the dialog on a refusal and clears the secret', async () => {
    asAdmin();
    const user = userEvent.setup();
    let calls = 0;
    server.use(
      http.put(`/api/v1/targets/${VAULT_ID}/vault-credentials`, () => {
        calls++;
        return calls === 1 ? errorResponse(403, 'ALC-AUTH-0003', 'auth.stepup_required') : errorResponse(502, 'ALC-AKV-0001', 'azure.auth_failed', { params: { aadsts: 'AADSTS7000215' } });
      }),
      http.post('/api/v1/auth/stepup', () => HttpResponse.json(sessionFor('admin'))),
    );
    const onReplaced = vi.fn();
    await renderWithStepUp(<ReplaceCredentialsDialog vault={vaultWith({}, { auth: 'client_secret' })} onClose={vi.fn()} onReplaced={onReplaced} />);
    await user.type(screen.getByLabelText(/^Secret value/), SECRET);
    await user.click(screen.getByRole('button', { name: 'Replace credentials' }));
    await user.type(await screen.findByLabelText('6-digit code'), '123456');
    await user.click(screen.getByRole('button', { name: 'Confirm' }));
    expect(await screen.findByText('Azure sign-in refused')).toBeInTheDocument();
    expect(onReplaced).not.toHaveBeenCalled();
    expect(calls).toBe(2);
    expect(screen.getByLabelText(/^Secret value/)).toHaveValue('');
    expect(document.body.innerHTML).not.toContain(SECRET);
  });

  it('is complete in Turkish', async () => {
    asAdmin('tr');
    await renderWithStepUp(<ReplaceCredentialsDialog vault={vaultFixture} onClose={vi.fn()} onReplaced={vi.fn()} />, ['tr-TR']);
    expect(await screen.findByText('Oturum açma kimlik bilgilerini değiştirin')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Kimlik bilgilerini değiştir' })).toBeInTheDocument();
    expectNoRawKeys();
  });
});
