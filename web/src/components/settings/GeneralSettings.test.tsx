import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { adminSession, sessionHandlers } from '../../test/fixtures';
import { renderRoute } from '../../test/render';
import { server } from '../../test/server';

const steppedUp = { ...adminSession, stepup_until: '2099-01-01T00:00:00Z' };

describe('GeneralSettings', () => {
  it("prefills Alice's address from the page when none is set, and saves", async () => {
    let sent: { body: unknown; ifMatch: string | null } | undefined;
    server.use(
      ...sessionHandlers(steppedUp),
      http.get('/api/v1/settings/general', () => HttpResponse.json({ public_url: '', retired_key_retention_days: 30, version: 0 })),
      http.put('/api/v1/settings/general', async ({ request }) => {
        sent = { body: await request.json(), ifMatch: request.headers.get("If-Match") };
        return HttpResponse.json({ public_url: window.location.origin, retired_key_retention_days: 90, version: 1 });
      }),
    );
    await renderRoute('/settings?tab=general');
    const url = await screen.findByLabelText("Alice's address");
    expect(url).toHaveValue(window.location.origin);
    expect(screen.getByText(/The address people use to open Alice/)).toBeInTheDocument();
    const days = screen.getByLabelText('Keep the private key of a retired SSH key for this many days');
    expect(days).toHaveValue('30');
    await userEvent.clear(days);
    await userEvent.type(days, '90');
    await userEvent.click(screen.getByRole('button', { name: 'Save general settings' }));
    await waitFor(() => expect(sent).toEqual({ ifMatch: '"0"', body: { public_url: window.location.origin, retired_key_retention_days: 90 } }));
    expect(await screen.findByText('Saved.')).toBeInTheDocument();
  });

  it('keeps an address that is set', async () => {
    server.use(
      ...sessionHandlers(steppedUp),
      http.get('/api/v1/settings/general', () => HttpResponse.json({ public_url: 'https://alice.example.com', retired_key_retention_days: 7, version: 2 })),
    );
    await renderRoute('/settings?tab=general');
    expect(await screen.findByLabelText("Alice's address")).toHaveValue('https://alice.example.com');
  });
});
