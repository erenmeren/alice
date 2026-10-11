import { screen, within } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import { adminSession, auditorSession, backupStateFixture, emptyDashboardSummary, sessionFor, sessionHandlers } from '../test/fixtures';
import { expectNoRawKeys } from '../test/i18nAssert';
import { renderRoute } from '../test/render';
import { server } from '../test/server';

const withAlarm = (alarm: boolean) =>
  http.get('/api/v1/dashboard/summary', () => HttpResponse.json({ ...emptyDashboardSummary, backup: backupStateFixture({ alarm }) }));

describe('BackupBanner', () => {
  it('tells Administrators on every page that no backup succeeded for 48 hours', async () => {
    server.use(...sessionHandlers(adminSession), withAlarm(true));
    await renderRoute('/account');
    const banner = await screen.findByTestId('backup-alarm-banner');
    expect(banner).toHaveAttribute('role', 'alert');
    expect(within(banner).getByRole('link', { name: 'No successful backup for 48 hours' })).toHaveAttribute('href', '/settings?tab=backups');
    expectNoRawKeys();
  });

  it('is in Turkish for a Turkish Administrator', async () => {
    server.use(...sessionHandlers(sessionFor('admin', 'tr')), withAlarm(true));
    await renderRoute('/account', { languages: ['tr-TR'] });
    expect(await screen.findByTestId('backup-alarm-banner')).toHaveTextContent('48 saattir başarılı yedek yok');
  });

  it('is not shown without the alarm', async () => {
    server.use(...sessionHandlers(adminSession), withAlarm(false));
    await renderRoute('/account');
    await screen.findByRole('heading', { level: 1 });
    expect(screen.queryByTestId('backup-alarm-banner')).not.toBeInTheDocument();
  });

  it('is not shown to an Auditor, even with the alarm on', async () => {
    let asked = 0;
    server.use(
      ...sessionHandlers(auditorSession),
      http.get('/api/v1/dashboard/summary', () => {
        asked += 1;
        return HttpResponse.json({ ...emptyDashboardSummary, backup: backupStateFixture({ alarm: true }) });
      }),
    );
    await renderRoute('/account');
    await screen.findByRole('heading', { level: 1 });
    expect(screen.queryByTestId('backup-alarm-banner')).not.toBeInTheDocument();
    expect(asked).toBe(0);
  });
});
