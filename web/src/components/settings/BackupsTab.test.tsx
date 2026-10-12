import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { formatDateTime } from '../../datetime';
import {
  adminSession,
  BACKUP_NAME,
  backupFixture,
  backupListFixture,
  backupScheduleFixture,
  backupStateFixture,
  errorResponse,
  sessionFor,
  sessionHandlers,
} from '../../test/fixtures';
import { expectNoRawKeys } from '../../test/i18nAssert';
import { renderRoute } from '../../test/render';
import { server } from '../../test/server';
import ui from '../ui/ui.module.css';
import classes from './settings.module.css';
import { formatSize, scheduleProblems, zoneOptions } from './BackupsTab';

const saved: { blob: Blob; name: string }[] = [];
vi.mock('../saveBlob', () => ({ saveBlob: (blob: Blob, name: string) => saved.push({ blob, name }) }));

const steppedUp = { ...adminSession, stepup_until: '2099-01-01T00:00:00Z' };
const steppedUpTr = { ...sessionFor('admin', 'tr'), stepup_until: '2099-01-01T00:00:00Z' };
const MANUAL = 'alice-backup-7F3K92QD-20261010T101500Z-manual.alicebak';

describe('BackupsTab', () => {
  it('lists the backups with the name as data, the kind, the size and the time in the browser zone', async () => {
    server.use(
      ...sessionHandlers(steppedUp),
      http.get('/api/v1/backups', () =>
        HttpResponse.json(
          backupListFixture({
            items: [backupFixture(), backupFixture({ name: 'before-firewall-change.alicebak', kind: 'pre-upgrade-1.0.1', size: 1_500 })],
          }),
        ),
      ),
    );
    await renderRoute('/settings?tab=backups');
    const table = await screen.findByTestId('backups-table');
    const name = within(table).getByText(BACKUP_NAME);
    expect(name.tagName).toBe('CODE');
    expect(name).toHaveAttribute('translate', 'no');
    const row = name.closest('tr') as HTMLElement;
    expect(within(row).getByText('Daily')).toBeInTheDocument();
    expect(within(row).getByText('52.4 MB')).toBeInTheDocument();
    expect(within(row).getByText(formatDateTime('2026-10-10T02:30:00Z', 'en'))).toBeInTheDocument();
    expect(within(row).getByText('Checked')).toBeInTheDocument();
    expect(within(table).getByText('Before the update to 1.0.1')).toBeInTheDocument();
    expect(within(table).getByText('1.5 kB')).toBeInTheDocument();

    expect(screen.getByText(`Last successful backup: ${formatDateTime('2026-10-10T02:30:00Z', 'en')}`)).toBeInTheDocument();
    expect(screen.getByText('Backups are stored on this server only. Copy them to another machine regularly.')).toBeInTheDocument();
    expect(screen.getByText(/Restoring is done on the server with/)).toBeInTheDocument();
    expect(screen.getByText('Free disk space for backups: 41.2 GB')).toBeInTheDocument();
    expectNoRawKeys();
  });

  it('draws the state and the schedule as the design\'s cards, the files in a resource table and the actions in rows', async () => {
    server.use(...sessionHandlers(steppedUp));
    await renderRoute('/settings?tab=backups');
    const table = await screen.findByTestId('backups-table');
    expect(table.closest(`.${ui.tablePanel}`)).not.toBeNull();
    expect(table).toHaveAttribute('aria-label', 'Backup files on this server');
    const headers = within(table).getAllByRole('columnheader').map((h) => h.textContent);
    expect(headers).toEqual(['File', 'Kind', 'Size', 'Made at', 'Check', 'Actions']);
    const check = within(table).getByText('Checked').closest('.mantine-Badge-root') as HTMLElement;
    expect(check).toHaveAttribute('data-tone', 'success');
    const last = screen.getByText('Last backup').closest(`.${classes.microCard}`) as HTMLElement;
    expect(last).toHaveTextContent(`Last successful backup: ${formatDateTime('2026-10-10T02:30:00Z', 'en')}`);
    expect(last).toHaveTextContent('Free disk space for backups: 41.2 GB');
    const schedule = (await screen.findByText('Schedule')).closest(`.${classes.microCard}`) as HTMLElement;
    expect(within(schedule).getByText('02:30 Europe/Istanbul')).toHaveAttribute('translate', 'no');
    expect(schedule).toHaveTextContent(`Next backup: ${formatDateTime('2026-10-10T23:30:00Z', 'en')}`);
    expect(screen.getByTestId('backup-now').closest(`.${classes.formActions}`)).not.toBeNull();
    expect((await screen.findByRole('button', { name: 'Save backup schedule' })).closest(`.${classes.formActions}`)).not.toBeNull();
    expect(screen.getByRole('heading', { level: 3, name: 'Daily backup' })).toBeInTheDocument();
    // The off-host advice is a note, not an alert: a download that works leaves no alert on the page.
    expect(screen.getByText('Backups are stored on this server only. Copy them to another machine regularly.').closest('[role="note"]')).not.toBeNull();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('shows an unreadable file with the reason and offers no download for it', async () => {
    server.use(
      ...sessionHandlers(steppedUp),
      http.get('/api/v1/backups', () =>
        HttpResponse.json(
          backupListFixture({
            items: [
              backupFixture({ name: 'locked.alicebak', check: 'unreadable', code: 'permission_denied', kind: 'manual' }),
              backupFixture({ name: 'broken.alicebak', check: 'unreadable', code: 'io', kind: 'manual' }),
              backupFixture({ name: 'odd.alicebak', check: 'unreadable', code: '', kind: 'manual' }),
              backupFixture({ name: 'bad.alicebak', check: 'checksum mismatch', kind: 'manual' }),
              backupFixture({ name: 'nosum.alicebak', check: 'missing checksum', kind: 'manual' }),
              backupFixture({ name: 'text.alicebak', check: 'unreadable header', kind: 'manual' }),
              backupFixture({ name: 'future.alicebak', check: 'something new', kind: 'something-new' }),
            ],
          }),
        ),
      ),
    );
    await renderRoute('/settings?tab=backups');
    const table = await screen.findByTestId('backups-table');
    expect(within(table).getByText('Alice cannot read this file: permission denied')).toBeInTheDocument();
    expect(within(table).getByText('Alice cannot read this file: read error')).toBeInTheDocument();
    expect(within(table).getByText('Alice cannot read this file')).toBeInTheDocument();
    expect(within(table).getByText('Damaged: the checksum does not match')).toBeInTheDocument();
    expect(within(table).getByText('Checksum file missing')).toBeInTheDocument();
    expect(within(table).getByText('Not a readable backup file')).toBeInTheDocument();
    expect(within(table).getByText('Unknown state')).toBeInTheDocument();
    // An unknown kind is data, shown as it is.
    expect(within(table).getByText('something-new').tagName).toBe('CODE');
    expect(screen.queryByTestId('backup-download-locked.alicebak')).not.toBeInTheDocument();
    expect(screen.queryByTestId('backup-download-broken.alicebak')).not.toBeInTheDocument();
    expect(screen.getByTestId('backup-download-bad.alicebak')).toBeInTheDocument();
    expectNoRawKeys();
  });

  it('says when no backup exists yet, when backups are not configured and when the alarm is on', async () => {
    server.use(
      ...sessionHandlers(steppedUp),
      http.get('/api/v1/backups', () =>
        HttpResponse.json(
          backupListFixture({
            items: [],
            state: backupStateFixture({ last_success_at: null, last_success_name: '', age_hours: null, configured: false, failing: true, alarm: true }),
          }),
        ),
      ),
    );
    await renderRoute('/settings?tab=backups');
    expect(await screen.findByText('No backup has been made yet.')).toBeInTheDocument();
    expect(screen.getByText('There are no backup files yet.')).toBeInTheDocument();
    expect(screen.getByText('Backups start after the recovery passphrase is set.')).toBeInTheDocument();
    expect(screen.getByText('The last backup failed. Alice e-mailed the administrators.')).toBeInTheDocument();
    expect(screen.getAllByText('No successful backup for 48 hours').length).toBeGreaterThan(0);
    expect(screen.getByText('No backup has been made yet.').closest(`.${classes.microCard}`)).not.toBeNull();
    expect(screen.getByText('There are no backup files yet.').closest(`.${ui.tablePanel}`)).not.toBeNull();
    expect(screen.getByText('The last backup failed. Alice e-mailed the administrators.').closest('[role="note"]')).not.toBeNull();
  });

  it('backs up now and reads the list again', async () => {
    let lists = 0;
    let made = false;
    server.use(
      ...sessionHandlers(steppedUp),
      http.get('/api/v1/backups', () => {
        lists += 1;
        return HttpResponse.json(backupListFixture({ items: made ? [backupFixture({ name: MANUAL, kind: 'manual' }), backupFixture()] : [backupFixture()] }));
      }),
      http.post('/api/v1/backups', () => {
        made = true;
        return HttpResponse.json(backupFixture({ name: MANUAL, kind: 'manual' }), { status: 201 });
      }),
    );
    await renderRoute('/settings?tab=backups');
    await screen.findByTestId('backups-table');
    expect(lists).toBe(1);
    await userEvent.click(screen.getByTestId('backup-now'));
    expect(await screen.findByText(MANUAL, { selector: '[role="status"] code' })).toBeInTheDocument();
    await waitFor(() => expect(lists).toBe(2));
    expect(await within(screen.getByTestId('backups-table')).findByText(MANUAL)).toBeInTheDocument();
    expect(within(screen.getByTestId('backups-table')).getByText('Manual')).toBeInTheDocument();
  });

  it('explains a refused backup', async () => {
    server.use(
      ...sessionHandlers(steppedUp),
      http.post('/api/v1/backups', () => errorResponse(409, 'ALC-BAK-0001', 'backup.running')),
    );
    const { i18n } = await renderRoute('/settings?tab=backups');
    await screen.findByTestId('backups-table');
    await userEvent.click(screen.getByTestId('backup-now'));
    const alert = await screen.findByRole('alert');
    // The catalogue title once the code is in the catalogue, the server's text before.
    expect(alert).toHaveTextContent(i18n.exists('errors.backup.running.title') ? i18n.t('errors.backup.running.title') : 'server text for backup.running');
  });

  it('asks for a code before a download, then fetches the file as a Blob and saves it', async () => {
    saved.length = 0;
    let fetched = 0;
    server.use(
      ...sessionHandlers(adminSession),
      http.get('/api/v1/backups/:name/download', () => {
        fetched++;
        return new HttpResponse('x', { headers: { 'Content-Type': 'application/octet-stream' } });
      }),
      http.post('/api/v1/auth/stepup', () => HttpResponse.json(steppedUp)),
    );
    await renderRoute('/settings?tab=backups');
    await userEvent.click(await screen.findByTestId(`backup-download-${BACKUP_NAME}`));
    expect(await screen.findByRole('dialog', { name: "Confirm it's you" })).toBeInTheDocument();
    expect(fetched).toBe(0);
    await userEvent.type(screen.getByLabelText('6-digit code'), '123456');
    await userEvent.click(screen.getByRole('button', { name: 'Confirm' }));
    await waitFor(() => expect(saved).toHaveLength(1));
    expect(saved[0]?.name).toBe(BACKUP_NAME);

    // The step-up is fresh now: a second download needs no code.
    await userEvent.click(screen.getByTestId(`backup-download-${BACKUP_NAME}`));
    await waitFor(() => expect(saved).toHaveLength(2));
    expect(screen.queryByRole('dialog', { name: "Confirm it's you" })).not.toBeInTheDocument();
  });

  it('asks for a code when the server wants a new step-up although the browser thought it fresh (clock skew)', async () => {
    saved.length = 0;
    let calls = 0;
    server.use(
      ...sessionHandlers(steppedUp),
      http.get('/api/v1/backups/:name/download', () =>
        ++calls === 1 ? errorResponse(403, 'ALC-AUTH-0003', 'auth.stepup_required') : new HttpResponse('x', { headers: { 'Content-Type': 'application/octet-stream' } }),
      ),
      http.post('/api/v1/auth/stepup', () => HttpResponse.json(steppedUp)),
    );
    await renderRoute('/settings?tab=backups');
    await userEvent.click(await screen.findByTestId(`backup-download-${BACKUP_NAME}`));
    expect(await screen.findByRole('dialog', { name: "Confirm it's you" })).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText('6-digit code'), '123456');
    await userEvent.click(screen.getByRole('button', { name: 'Confirm' }));
    await waitFor(() => expect(saved).toHaveLength(1));
    expect(saved[0]?.name).toBe(BACKUP_NAME);
    expect(calls).toBe(2);
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it.each([
    [429, 'ALC-RATE-0001', 'rate.limited'],
    [404, 'ALC-BAK-0003', 'backup.not_found'],
  ])('shows an alert and stays on the page when the download is refused with %i', async (status, code, reason) => {
    saved.length = 0;
    server.use(
      ...sessionHandlers(steppedUp),
      http.get('/api/v1/backups/:name/download', () => errorResponse(status, code, reason)),
    );
    await renderRoute('/settings?tab=backups');
    await userEvent.click(await screen.findByTestId(`backup-download-${BACKUP_NAME}`));
    expect(await screen.findByRole('alert')).toBeInTheDocument();
    expect(saved).toHaveLength(0);
    expect(screen.getByTestId('backups-table')).toBeInTheDocument();
  });

  it('downloads nothing when the code prompt is cancelled', async () => {
    saved.length = 0;
    server.use(...sessionHandlers(adminSession));
    await renderRoute('/settings?tab=backups');
    await userEvent.click(await screen.findByTestId(`backup-download-${BACKUP_NAME}`));
    const dialog = await screen.findByRole('dialog', { name: "Confirm it's you" });
    await userEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByRole('dialog', { name: "Confirm it's you" })).not.toBeInTheDocument());
    expect(saved).toHaveLength(0);
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('validates the schedule before sending it, then saves it with If-Match', async () => {
    let sent: { body: unknown; ifMatch: string | null } | undefined;
    server.use(
      ...sessionHandlers(steppedUp),
      http.put('/api/v1/settings/backups', async ({ request }) => {
        sent = { body: await request.json(), ifMatch: request.headers.get('If-Match') };
        return HttpResponse.json(backupScheduleFixture({ time: '03:15', retention: 30, version: 4 }));
      }),
    );
    await renderRoute('/settings?tab=backups');
    const time = await screen.findByLabelText('Daily backup time');
    expect(time).toHaveValue('02:30');
    expect(screen.getByRole('combobox', { name: 'Time zone' })).toHaveValue('Europe/Istanbul');
    const retention = screen.getByLabelText('Automatic backups to keep');
    expect(retention).toHaveValue('14');

    await userEvent.clear(time);
    await userEvent.type(time, '25:00');
    await userEvent.clear(retention);
    await userEvent.type(retention, '6');
    await userEvent.click(screen.getByRole('button', { name: 'Save backup schedule' }));
    expect(await screen.findByText('Enter a time as HH:MM, for example 02:30.')).toBeInTheDocument();
    expect(screen.getByText('Enter a whole number from 7 to 60.')).toBeInTheDocument();
    expect(sent).toBeUndefined();

    await userEvent.clear(retention);
    await userEvent.type(retention, '61');
    await userEvent.click(screen.getByRole('button', { name: 'Save backup schedule' }));
    expect(screen.getByText('Enter a whole number from 7 to 60.')).toBeInTheDocument();
    expect(sent).toBeUndefined();

    await userEvent.clear(time);
    await userEvent.type(time, '03:15');
    await userEvent.clear(retention);
    await userEvent.type(retention, '30');
    await userEvent.click(screen.getByRole('button', { name: 'Save backup schedule' }));
    await waitFor(() => expect(sent).toEqual({ ifMatch: '"3"', body: { time: '03:15', zone: 'Europe/Istanbul', retention: 30 } }));
    expect(await screen.findByText('Saved.')).toBeInTheDocument();
    expect(screen.queryByText('Enter a time as HH:MM, for example 02:30.')).not.toBeInTheDocument();
  });

  it('chooses another time zone from the list', async () => {
    let sent: unknown;
    server.use(
      ...sessionHandlers(steppedUp),
      http.put('/api/v1/settings/backups', async ({ request }) => {
        sent = await request.json();
        return HttpResponse.json(backupScheduleFixture({ zone: 'Europe/Berlin', version: 4 }));
      }),
    );
    await renderRoute('/settings?tab=backups');
    await userEvent.selectOptions(await screen.findByRole('combobox', { name: 'Time zone' }), 'Europe/Berlin');
    await userEvent.click(screen.getByRole('button', { name: 'Save backup schedule' }));
    await waitFor(() => expect(sent).toEqual({ time: '02:30', zone: 'Europe/Berlin', retention: 14 }));
  });

  it('is shown in Turkish without a raw key', async () => {
    server.use(...sessionHandlers(steppedUpTr));
    await renderRoute('/settings?tab=backups', { languages: ['tr-TR'] });
    expect(await screen.findByTestId('backups-table')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Şimdi yedekle' })).toBeInTheDocument();
    expect(screen.getByText('Yedekler için boş disk alanı: 41,2 GB')).toBeInTheDocument();
    expectNoRawKeys();
  });
});

describe('backup schedule rules', () => {
  const zones = zoneOptions('Europe/Istanbul');
  it('accepts a valid schedule', () => {
    expect(scheduleProblems({ time: '00:00', zone: 'Europe/Istanbul', retention: 7 }, zones)).toEqual({});
    expect(scheduleProblems({ time: '23:59', zone: 'UTC', retention: 60 }, zones)).toEqual({});
  });
  it('refuses a bad time, a zone outside the list and a retention outside 7 to 60', () => {
    expect(Object.keys(scheduleProblems({ time: '24:00', zone: 'Mars/Olympus', retention: 6.5 }, zones)).sort()).toEqual(['retention', 'time', 'zone']);
    expect(Object.keys(scheduleProblems({ time: '2:30', zone: '', retention: 61 }, zones)).sort()).toEqual(['retention', 'time', 'zone']);
  });
  it('lists the browser zones, UTC and a stored zone the browser does not know, once each', () => {
    const z = zoneOptions('Etc/Unknown');
    expect(z).toContain('UTC');
    expect(z).toContain('Etc/Unknown');
    expect(z).toContain('Europe/Istanbul');
    expect(new Set(z).size).toBe(z.length);
  });
  it('formats sizes in decimal units in the UI language', () => {
    expect(formatSize(999, 'en')).toBe('999 byte');
    expect(formatSize(1_500, 'en')).toBe('1.5 kB');
    expect(formatSize(52_400_000, 'tr')).toBe('52,4 MB');
    expect(formatSize(2_000_000_000_000, 'en')).toBe('2 TB');
  });
});
