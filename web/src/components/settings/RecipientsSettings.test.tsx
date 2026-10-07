import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { adminSession, errorResponse, sessionHandlers } from '../../test/fixtures';
import { renderRoute } from '../../test/render';
import { server } from '../../test/server';

const steppedUp = { ...adminSession, stepup_until: '2099-01-01T00:00:00Z' };
const recipients = (over: Record<string, unknown> = {}) => ({ administrators: true, addresses: [{ email: 'ops@example.com', locale: 'tr' }], version: 3, ...over });

describe('RecipientsSettings', () => {
  it('edits the list and saves it with the version it was loaded with', async () => {
    let sent: { body: unknown; ifMatch: string | null } | undefined;
    server.use(
      ...sessionHandlers(steppedUp),
      http.get('/api/v1/settings/notifications', () => HttpResponse.json(recipients())),
      http.put('/api/v1/settings/notifications', async ({ request }) => {
        sent = { body: await request.json(), ifMatch: request.headers.get('If-Match') };
        return HttpResponse.json(recipients({ version: 4 }));
      }),
    );
    await renderRoute('/settings?tab=recipients');
    expect(await screen.findByRole('checkbox', { name: 'Send alerts to every administrator with an e-mail address' })).toBeChecked();
    expect(screen.getByLabelText('E-mail address 1')).toHaveValue('ops@example.com');
    expect(screen.getByLabelText('Language of address 1')).toHaveValue('tr');
    await userEvent.click(screen.getByRole('button', { name: 'Add address' }));
    await userEvent.type(screen.getByLabelText('E-mail address 2'), 'sec@example.com');
    await userEvent.click(screen.getByRole('checkbox', { name: /Send alerts to every administrator/ }));
    await userEvent.click(screen.getByRole('button', { name: 'Save recipients' }));
    await waitFor(() => expect(sent).toBeDefined());
    expect(sent).toEqual({
      ifMatch: '"3"',
      body: { administrators: false, addresses: [{ email: 'ops@example.com', locale: 'tr' }, { email: 'sec@example.com', locale: 'en' }] },
    });
    expect(await screen.findByText('Saved.')).toBeInTheDocument();
  });

  it('removes an address and stops adding at 20', async () => {
    server.use(
      ...sessionHandlers(steppedUp),
      http.get('/api/v1/settings/notifications', () =>
        HttpResponse.json(recipients({ addresses: Array.from({ length: 20 }, (_, i) => ({ email: `a${i}@example.com`, locale: 'en' })) })),
      ),
    );
    await renderRoute('/settings?tab=recipients');
    expect(await screen.findByRole('button', { name: 'Add address' })).toBeDisabled();
    await userEvent.click(screen.getByRole('button', { name: 'Remove address 1' }));
    expect(screen.getByRole('button', { name: 'Add address' })).toBeEnabled();
    expect(screen.getByLabelText('E-mail address 1')).toHaveValue('a1@example.com');
  });

  it('shows a refusal (no recipient at all) with its text', async () => {
    server.use(
      ...sessionHandlers(steppedUp),
      http.get('/api/v1/settings/notifications', () => HttpResponse.json(recipients({ addresses: [] }))),
      http.put('/api/v1/settings/notifications', () => errorResponse(422, 'ALC-SYS-0006', 'validation.failed', { details: [{ field: 'addresses', code: 'validation.required' }] })),
    );
    await renderRoute('/settings?tab=recipients');
    await userEvent.click(await screen.findByRole('button', { name: 'Save recipients' }));
    const alert = await screen.findByRole('alert');
    expect(within(alert).getByText(/This field is required/)).toBeInTheDocument();
  });
});
