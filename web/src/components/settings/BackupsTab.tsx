import { Button, Code, NativeSelect, NumberInput, Stack, Table, Text, TextInput, Title } from '@mantine/core';
import { useMutation, useQuery, useQueryClient, type UseQueryResult } from '@tanstack/react-query';
import { useId, useMemo, useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { createBackup, downloadBackup, getBackupSchedule, listBackups, saveBackupSchedule } from '../../api/endpoints';
import { BACKUPS_KEY, DASHBOARD_KEY } from '../../api/queryKeys';
import type { Backup, BackupSchedule, BackupState } from '../../api/types';
import { formatDateTime } from '../../datetime';
import { CodeText } from '../CodeText';
import { saveBlob } from '../saveBlob';
import { ErrorAlert } from '../ErrorAlert';
import { fieldErrorsOf } from '../fieldErrors';
import { LoadingIndicator } from '../LoadingIndicator';
import { StepUpCancelled, useStepUp } from '../StepUpProvider';
import { EmptyState, Notice, ResourceTable, StatusBadge } from '../ui';
import ui from '../ui/ui.module.css';
import { Icon } from '../../design/Icon';
import { SavedNote } from './SavedNote';
import classes from './settings.module.css';
import { useChange, useSetting } from './useSetting';

const UNITS = ['kilobyte', 'megabyte', 'gigabyte', 'terabyte'] as const;

// formatSize shows a byte count in decimal units (1 kB = 1000 bytes) in the UI language.
export function formatSize(bytes: number, lang: string): string {
  let value = bytes;
  let unit: string = 'byte';
  for (const u of UNITS) {
    if (value < 1000) break;
    value /= 1000;
    unit = u;
  }
  return new Intl.NumberFormat(lang, { style: 'unit', unit, unitDisplay: 'short', maximumFractionDigits: 1 }).format(value);
}

// zoneOptions is every time zone the browser knows, UTC, and the stored zone when the browser does not know it (so a
// saved setting is always shown as it is).
export function zoneOptions(current: string): string[] {
  const zones = new Set(Intl.supportedValuesOf('timeZone'));
  zones.add('UTC');
  if (current) zones.add(current);
  return [...zones].sort();
}

export interface ScheduleInput {
  time: string;
  zone: string;
  retention: number;
}

// scheduleProblems checks the schedule as the server does: a 24-hour HH:MM, a zone from the list, 7 to 60 backups.
export function scheduleProblems(s: ScheduleInput, zones: readonly string[]): Partial<Record<keyof ScheduleInput, true>> {
  const p: Partial<Record<keyof ScheduleInput, true>> = {};
  if (!/^([01]\d|2[0-3]):[0-5]\d$/.test(s.time)) p.time = true;
  if (!zones.includes(s.zone)) p.zone = true;
  if (!Number.isInteger(s.retention) || s.retention < 7 || s.retention > 60) p.retention = true;
  return p;
}

const CHECK_KEYS: Record<string, string> = {
  ok: 'backups.checks.ok',
  'missing checksum': 'backups.checks.missingChecksum',
  'checksum mismatch': 'backups.checks.checksumMismatch',
  'unreadable header': 'backups.checks.unreadableHeader',
};

function checkLabel(b: Backup): string {
  if (b.check === 'unreadable') {
    if (b.code === 'permission_denied') return 'backups.checks.unreadablePermission';
    if (b.code === 'io') return 'backups.checks.unreadableIo';
    return 'backups.checks.unreadable';
  }
  return CHECK_KEYS[b.check] ?? 'backups.checks.unknown';
}

// KindLabel names the kind of a backup; an unknown kind is data and shown as it is.
function KindLabel({ kind }: { kind: string }) {
  const { t } = useTranslation();
  if (kind === 'auto') return <>{t('backups.kinds.auto')}</>;
  if (kind === 'manual') return <>{t('backups.kinds.manual')}</>;
  if (kind === 'pre-restore') return <>{t('backups.kinds.preRestore')}</>;
  if (kind.startsWith('pre-upgrade-')) return <>{t('backups.kinds.preUpgrade', { version: kind.slice('pre-upgrade-'.length) })}</>;
  return <Code translate="no">{kind}</Code>;
}

// BackupsTab is Settings → Backups (C12, C13): the state, Back up now, the list with downloads, and the daily schedule.
// Restoring is done on the server (alicectl restore), so the page only says so. Every request needs a fresh step-up
// (backup.manage, settings.manage); a download is fetched as a Blob after confirm() (and through run, so a step-up the
// server still wants asks for a code) and saved, never kept in a cache.
export function BackupsTab() {
  const { t, i18n } = useTranslation();
  const { run, confirm } = useStepUp();
  const client = useQueryClient();
  const list = useQuery({ queryKey: BACKUPS_KEY, queryFn: () => run(listBackups) });
  const schedule = useSetting('backups', getBackupSchedule);
  const [downloadError, setDownloadError] = useState<unknown>(null);
  const [downloading, setDownloading] = useState(false);
  const rowId = useId();
  const backUp = useMutation({
    mutationFn: () => run(createBackup),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: BACKUPS_KEY });
      void client.invalidateQueries({ queryKey: DASHBOARD_KEY });
    },
  });

  const download = async (name: string) => {
    if (downloading) return;
    setDownloadError(null);
    setDownloading(true);
    try {
      await confirm();
      // run as well: the server decides whether the step-up is fresh, and a browser whose clock is behind the server's
      // can think it is when it is not; a refusal then asks for the code instead of failing.
      saveBlob(await run(() => downloadBackup(name)), name);
    } catch (e) {
      if (!(e instanceof StepUpCancelled)) setDownloadError(e);
    } finally {
      setDownloading(false);
    }
  };

  return (
    <Stack gap="md">
      {list.isPending && <LoadingIndicator />}
      <ErrorAlert error={list.error} />
      {list.data && <StateNotices state={list.data.state} />}
      <div className={classes.grid2}>
        {list.data && <StateCard state={list.data.state} />}
        <ScheduleCard schedule={schedule.data} />
      </div>
      <Notice tone="info" title={t('backups.offHost')}>
        {t('backups.restoreHint')}
      </Notice>
      <ErrorAlert error={downloadError} />
      {list.data && list.data.items.length === 0 && (
        <div className={ui.tablePanel}>
          <EmptyState icon="DatabaseBackup" title={t('backups.empty')} />
        </div>
      )}
      {list.data && list.data.items.length > 0 && (
        <ResourceTable label={t('backups.tableLabel')} testId="backups-table" minWidth={720}>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>{t('backups.columns.name')}</Table.Th>
              <Table.Th>{t('backups.columns.kind')}</Table.Th>
              <Table.Th>{t('backups.columns.size')}</Table.Th>
              <Table.Th>{t('backups.columns.created')}</Table.Th>
              <Table.Th>{t('backups.columns.check')}</Table.Th>
              <Table.Th>{t('backups.columns.actions')}</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {list.data.items.map((b, i) => (
              <Table.Tr key={b.name}>
                <Table.Td>
                  <Code id={`${rowId}-${i}`} translate="no" style={{ overflowWrap: 'anywhere' }}>
                    {b.name}
                  </Code>
                </Table.Td>
                <Table.Td>
                  <KindLabel kind={b.kind} />
                </Table.Td>
                <Table.Td>{formatSize(b.size, i18n.language)}</Table.Td>
                <Table.Td>{formatDateTime(b.created_at, i18n.language)}</Table.Td>
                <Table.Td>
                  <StatusBadge tone={b.check === 'ok' ? 'success' : 'danger'} icon={b.check === 'ok' ? 'CircleCheck' : 'CircleAlert'}>
                    {t(checkLabel(b))}
                  </StatusBadge>
                </Table.Td>
                <Table.Td>
                  {b.check !== 'unreadable' && (
                    <Button
                      size="xs"
                      variant="default"
                      leftSection={<Icon name="Download" size={14} />}
                      disabled={downloading}
                      data-testid={`backup-download-${b.name}`}
                      // The file name is data: it describes the button instead of being part of its translated name.
                      aria-describedby={`${rowId}-${i}`}
                      onClick={() => void download(b.name)}
                    >
                      {t('backups.download')}
                    </Button>
                  )}
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </ResourceTable>
      )}
      <div className={classes.formActions}>
        <Button data-testid="backup-now" leftSection={<Icon name="DatabaseBackup" size={15} />} loading={backUp.isPending} onClick={() => backUp.mutate()}>
          {t('backups.backUpNow')}
        </Button>
      </div>
      {backUp.isSuccess && (
        <Text role="status" size="sm" c="var(--alice-success)">
          <CodeText i18nKey="backups.created" param="name" value={backUp.data.name} />
        </Text>
      )}
      <ErrorAlert error={backUp.error} />
      <ScheduleSettings query={schedule} />
    </Stack>
  );
}

// StateNotices are the backup alarms: no success for 48 hours (an alert), not configured yet, the last backup failed.
function StateNotices({ state }: { state: BackupState }) {
  const { t } = useTranslation();
  return (
    <>
      {state.alarm && (
        <Notice tone="danger" role="alert" title={t('backups.alarm')}>
          {t('backups.alarmHelp')}
        </Notice>
      )}
      {!state.configured && <Notice tone="warning" title={t('backups.notConfigured')} />}
      {state.failing && <Notice tone="danger" title={t('backups.failing')} />}
    </>
  );
}

// StateCard is the design's micro-card for the last backup and the free space.
function StateCard({ state }: { state: BackupState }) {
  const { t, i18n } = useTranslation();
  return (
    <div className={classes.microCard}>
      <p className={classes.eyebrow}>{t('settings.page.lastBackup')}</p>
      <div className={classes.microLines}>
        <p>{state.last_success_at ? t('backups.lastSuccess', { time: formatDateTime(state.last_success_at, i18n.language) }) : t('backups.never')}</p>
        <p>{t('backups.freeSpace', { size: formatSize(state.free_bytes, i18n.language) })}</p>
      </div>
    </div>
  );
}

// ScheduleCard is the design's micro-card for the daily schedule: the time and zone (data) and the next run.
function ScheduleCard({ schedule }: { schedule: BackupSchedule | undefined }) {
  const { t, i18n } = useTranslation();
  if (!schedule) return null;
  return (
    <div className={classes.microCard}>
      <p className={classes.eyebrow}>{t('settings.page.schedule')}</p>
      <p className={classes.microValue} translate="no">
        {schedule.time} {schedule.zone}
      </p>
      {schedule.next_at && (
        <div className={classes.microLines}>
          <p>{t('backups.schedule.next', { time: formatDateTime(schedule.next_at, i18n.language) })}</p>
        </div>
      )}
    </div>
  );
}

function ScheduleSettings({ query: q }: { query: UseQueryResult<BackupSchedule> }) {
  const { t } = useTranslation();
  return (
    <section className={classes.subSection}>
      <Title order={3} className={classes.subTitle}>
        {t('backups.schedule.title')}
      </Title>
      {q.isPending && <LoadingIndicator />}
      <ErrorAlert error={q.error} />
      {q.data && <SchedulePanel schedule={q.data} />}
    </section>
  );
}

function SchedulePanel({ schedule }: { schedule: BackupSchedule }) {
  const { t, i18n } = useTranslation();
  const client = useQueryClient();
  const save = useChange('backups', schedule.version, saveBackupSchedule);
  return (
    <Stack gap="sm">
      <ScheduleForm
        key={schedule.version}
        schedule={schedule}
        busy={save.isPending}
        fieldErrors={fieldErrorsOf(save.error, t, i18n)}
        onSave={(body) => save.mutate(body, { onSuccess: () => void client.invalidateQueries({ queryKey: BACKUPS_KEY }) })}
      />
      <SavedNote show={save.isSuccess} />
      <ErrorAlert error={save.error} />
    </Stack>
  );
}

function ScheduleForm({
  schedule,
  busy,
  fieldErrors,
  onSave,
}: {
  schedule: BackupSchedule;
  busy: boolean;
  fieldErrors: Record<string, string>;
  onSave: (b: ScheduleInput) => void;
}) {
  const { t } = useTranslation();
  const [time, setTime] = useState(schedule.time);
  const [zone, setZone] = useState(schedule.zone);
  const [retention, setRetention] = useState<number | string>(schedule.retention);
  const [problems, setProblems] = useState<ReturnType<typeof scheduleProblems>>({});
  const zones = useMemo(() => zoneOptions(schedule.zone), [schedule.zone]);

  const submit = (ev: FormEvent) => {
    ev.preventDefault();
    const input = { time: time.trim(), zone, retention: Number(retention) };
    const found = scheduleProblems(input, zones);
    setProblems(found);
    if (Object.keys(found).length === 0) onSave(input);
  };

  return (
    <form onSubmit={submit} noValidate>
      <Stack gap="sm">
        <TextInput
          label={t('backups.schedule.time')}
          description={t('backups.schedule.timeHelp')}
          value={time}
          onChange={(e) => setTime(e.currentTarget.value)}
          error={problems.time ? t('backups.schedule.timeInvalid') : fieldErrors.time}
          inputMode="numeric"
          maxLength={5}
          autoComplete="off"
        />
        <NativeSelect
          label={t('backups.schedule.zone')}
          data={zones}
          value={zone}
          onChange={(e) => setZone(e.currentTarget.value)}
          error={problems.zone ? t('backups.schedule.zoneInvalid') : fieldErrors.zone}
        />
        <NumberInput
          label={t('backups.schedule.retention')}
          description={t('backups.schedule.retentionHelp')}
          value={retention}
          onChange={setRetention}
          min={7}
          max={60}
          allowDecimal={false}
          clampBehavior="none"
          error={problems.retention ? t('backups.schedule.retentionInvalid') : fieldErrors.retention}
        />
      </Stack>
      <div className={classes.formActions}>
        <Button type="submit" loading={busy} leftSection={<Icon name="Check" size={15} />}>
          {t('backups.schedule.save')}
        </Button>
      </div>
    </form>
  );
}
