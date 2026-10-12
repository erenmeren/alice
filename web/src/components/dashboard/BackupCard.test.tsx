import { screen, within } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import { formatDateTime } from '../../datetime';
import { adminSession, auditorSession, backupStateFixture, emptyDashboardSummary, operatorSession, sessionFor, sessionHandlers } from '../../test/fixtures';
import { expectNoRawKeys } from '../../test/i18nAssert';
import { renderRoute } from '../../test/render';
import { server } from '../../test/server';

const withBackup = (backup: unknown) => http.get('/api/v1/dashboard/summary', () => HttpResponse.json({ ...emptyDashboardSummary, backup }));

describe('BackupCard', () => {
  it('shows an Administrator the last successful backup, its age and a link to the Backups tab', async () => {
    server.use(...sessionHandlers(adminSession), withBackup(backupStateFixture({ age_hours: 6 })));
    await renderRoute('/?view=assurance');
    const card = await screen.findByTestId('backup-card');
    expect(within(card).getByRole('heading', { name: 'Recovery readiness' })).toBeInTheDocument();
    expect(within(card).getByText('Latest backup available')).toBeVisible();
    expect(within(card).getByText('Not established by a backup checksum')).toBeVisible();
    expect(within(card).getByText(`Last successful backup: ${formatDateTime('2026-10-10T02:30:00Z', 'en')}`)).toBeInTheDocument();
    expect(within(card).getByText('6 hours ago')).toBeInTheDocument();
    expect(within(card).getByRole('link', { name: 'Open the backups' })).toHaveAttribute('href', '/settings?tab=backups');
    expectNoRawKeys();
  });

  it('shows an Auditor the same, without the link to the settings', async () => {
    server.use(...sessionHandlers(auditorSession), withBackup(backupStateFixture({ age_hours: 1 })));
    await renderRoute('/?view=assurance');
    const card = await screen.findByTestId('backup-card');
    expect(within(card).getByText('1 hour ago')).toBeInTheDocument();
    expect(within(card).queryByRole('link')).not.toBeInTheDocument();
  });

  it('draws nothing for an Operator, whose summary has no backup part', async () => {
    server.use(...sessionHandlers(operatorSession), http.get('/api/v1/dashboard/summary', () => HttpResponse.json(emptyDashboardSummary)));
    await renderRoute('/');
    await screen.findByText('Nothing expires within 30 days.');
    expect(screen.queryByTestId('backup-card')).not.toBeInTheDocument();
  });

  it('says when no backup was made, when backups are not configured, when the last one failed and when the alarm is on', async () => {
    server.use(
      ...sessionHandlers(adminSession),
      withBackup(backupStateFixture({ last_success_at: null, last_success_name: '', age_hours: null, failing: true, alarm: true, configured: true })),
    );
    await renderRoute('/?view=assurance');
    const card = await screen.findByTestId('backup-card');
    expect(within(card).getByText('No backup has been made yet.')).toBeInTheDocument();
    expect(within(card).getByText('The last backup failed. Alice e-mailed the administrators.')).toBeInTheDocument();
    expect(within(card).getByText('No successful backup for 48 hours')).toBeInTheDocument();
    expect(within(card).queryByText('Latest backup available')).not.toBeInTheDocument();
  });

  it('says backups start after the recovery passphrase', async () => {
    server.use(...sessionHandlers(sessionFor('admin', 'tr')), withBackup(backupStateFixture({ configured: false, last_success_at: null, age_hours: null })));
    await renderRoute('/?view=assurance', { languages: ['tr-TR'] });
    const card = await screen.findByTestId('backup-card');
    expect(within(card).getByText('Yedekleme, kurtarma parolası belirlendikten sonra başlar.')).toBeInTheDocument();
    expectNoRawKeys();
  });
});
