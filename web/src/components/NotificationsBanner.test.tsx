import { screen } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import { adminSession, operatorSession, sessionHandlers } from '../test/fixtures';
import { renderRoute } from '../test/render';
import { server } from '../test/server';

describe('NotificationsBanner', () => {
  it('tells Administrators that e-mails could not be sent (owner step 4)', async () => {
    server.use(
      ...sessionHandlers(adminSession),
      http.get('/api/v1/notifications/status', () =>
        HttpResponse.json({ failing: true, consecutive_failures: 3, last_failure_at: '2026-10-07T09:00:00Z', last_failure_code: 'smtp.connect', last_success_at: null, pending: 2, failed_24h: 0 }),
      ),
    );
    await renderRoute('/account');
    const banner = await screen.findByTestId('notifications-banner');
    expect(banner).toHaveAttribute('role', 'alert');
    expect(banner).toHaveTextContent('E-mails could not be sent');
    expect(banner).toHaveTextContent('smtp.connect');
    expect(banner).toHaveTextContent('The last 3 attempts');
    expect(screen.getByRole('link', { name: 'Open the mail settings' })).toHaveAttribute('href', '/settings?tab=mail');
  });

  it('is not shown when delivery works', async () => {
    server.use(...sessionHandlers(adminSession), http.get('/api/v1/notifications/status', () => HttpResponse.json({ failing: false })));
    await renderRoute('/account');
    await screen.findByRole('heading', { level: 1 });
    expect(screen.queryByTestId('notifications-banner')).not.toBeInTheDocument();
  });

  it('is not shown to other roles', async () => {
    server.use(...sessionHandlers(operatorSession), http.get('/api/v1/notifications/status', () => HttpResponse.json({ failing: false })));
    await renderRoute('/account');
    await screen.findByRole('heading', { level: 1 });
    expect(screen.queryByTestId('notifications-banner')).not.toBeInTheDocument();
  });
});
