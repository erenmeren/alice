import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { adminSession, sessionFor, sessionHandlers } from '../../test/fixtures';
import { expectNoRawKeys } from '../../test/i18nAssert';
import { renderRoute } from '../../test/render';
import { server } from '../../test/server';

const steppedUp = { ...adminSession, stepup_until: '2099-01-01T00:00:00Z' };

// The revocation check switch (R64, D5, HB-17) in Settings, General.
describe('RevocationCheckSettings', () => {
  it('shows the switch on and saves it off with the version read', async () => {
    let sent: { body: unknown; ifMatch: string | null } | undefined;
    server.use(
      ...sessionHandlers(steppedUp),
      http.get('/api/v1/settings/general', () => HttpResponse.json({ public_url: 'https://alice.example.com', retired_key_retention_days: 30, version: 1 })),
      http.get('/api/v1/settings/revocation-checks', () => HttpResponse.json({ enabled: true, version: 0 })),
      http.put('/api/v1/settings/revocation-checks', async ({ request }) => {
        sent = { body: await request.json(), ifMatch: request.headers.get('If-Match') };
        return HttpResponse.json({ enabled: false, version: 1 });
      }),
    );
    await renderRoute('/settings?tab=general');
    expect(await screen.findByRole('heading', { name: 'Revocation checks' })).toBeInTheDocument();
    expect(screen.getByText(/ports 80 and 443/)).toBeInTheDocument();
    const toggle = screen.getByRole('switch', { name: 'Check certificates for revocation' });
    expect(toggle).toBeChecked();
    await userEvent.click(toggle);
    await waitFor(() => expect(sent).toEqual({ ifMatch: '"0"', body: { enabled: false } }));
    await waitFor(() => expect(screen.getByRole('switch', { name: 'Check certificates for revocation' })).not.toBeChecked());
    expectNoRawKeys();
  });

  it('renders in Turkish', async () => {
    server.use(
      ...sessionHandlers({ ...sessionFor('admin', 'tr'), stepup_until: '2099-01-01T00:00:00Z' }),
      http.get('/api/v1/settings/general', () => HttpResponse.json({ public_url: 'https://alice.example.com', retired_key_retention_days: 30, version: 1 })),
      http.get('/api/v1/settings/revocation-checks', () => HttpResponse.json({ enabled: false, version: 3 })),
    );
    await renderRoute('/settings?tab=general', { languages: ['tr-TR'] });
    expect(await screen.findByRole('heading', { name: 'İptal denetimleri' })).toBeInTheDocument();
    expect(screen.getByRole('switch', { name: 'Sertifikaların iptalini denetle' })).not.toBeChecked();
    expectNoRawKeys();
  });
});
