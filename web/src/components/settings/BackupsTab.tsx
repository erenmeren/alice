import { Alert, Badge, Button, Code, Group, NativeSelect, NumberInput, Stack, Table, Text, TextInput, Title } from '@mantine/core';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useId, useMemo, useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { backupDownloadPath, createBackup, getBackupSchedule, listBackups, saveBackupSchedule } from '../../api/endpoints';
import { BACKUPS_KEY, DASHBOARD_KEY } from '../../api/queryKeys';
import type { Backup, BackupSchedule, BackupState } from '../../api/types';
import { formatDateTime } from '../../datetime';
import { openDownload } from '../../navigation';
import { CodeText } from '../CodeText';
import { ErrorAlert } from '../ErrorAlert';
import { fieldErrorsOf } from '../fieldErrors';
import { LoadingIndicator } from '../LoadingIndicator';
import { StepUpCancelled, useStepUp } from '../StepUpProvider';
import { SavedNote } from './SavedNote';
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
// (backup.manage, settings.manage); a download is opened by the browser after confirm(), never fetched into the page.
export function BackupsTab() {
  const { t, i18n } = useTranslation();
  const { run, confirm } = useStepUp();
  const client = useQueryClient();
  const list = useQuery({ queryKey: BACKUPS_KEY, queryFn: () => run(listBackups) });
  const [downloadError, setDownloadError] = useState<unknown>(null);
  const rowId = useId();
  const backUp = useMutation({
    mutationFn: () => run(createBackup),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: BACKUPS_KEY });
      void client.invalidateQueries({ queryKey: DASHBOARD_KEY });
    },
  });

  const download = async (name: string) => {
    setDownloadError(null);
    try {
      await confirm();
      openDownload(backupDownloadPath(name));
    } catch (e) {
      if (!(e instanceof StepUpCancelled)) setDownloadError(e);
    }
  };

  return (
    <Stack gap="lg">
      {list.isPending && <LoadingIndicator />}
      <ErrorAlert error={list.error} />
      {list.data && <StateLines state={list.data.state} />}
      <Text size="sm">{t('backups.offHost')}</Text>
      <Text size="sm">{t('backups.restoreHint')}</Text>
      <Group>
        <Button data-testid="backup-now" loading={backUp.isPending} onClick={() => backUp.mutate()}>
          {t('backups.backUpNow')}
        </Button>
      </Group>
      {backUp.isSuccess && (
        <Text role="status" size="sm" c="teal.9">
          <CodeText i18nKey="backups.created" param="name" value={backUp.data.name} />
        </Text>
      )}
      <ErrorAlert error={backUp.error} />
      <ErrorAlert error={downloadError} />
      {list.data && list.data.items.length === 0 && <Text c="gray.7">{t('backups.empty')}</Text>}
      {list.data && list.data.items.length > 0 && (
        <Table.ScrollContainer minWidth={720}>
          <Table striped data-testid="backups-table" aria-label={t('backups.tableLabel')}>
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
                    <Badge variant="light" color={b.check === 'ok' ? 'green' : 'red'} tt="none">
                      {t(checkLabel(b))}
                    </Badge>
                  </Table.Td>
                  <Table.Td>
                    {b.check !== 'unreadable' && (
                      <Button
                        size="xs"
                        variant="default"
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
          </Table>
        </Table.ScrollContainer>
      )}
      <ScheduleSettings />
    </Stack>
  );
}

function StateLines({ state }: { state: BackupState }) {
  const { t, i18n } = useTranslation();
  return (
    <Stack gap="xs">
      {state.alarm && (
        <Alert color="red" role="alert" title={t('backups.alarm')}>
          {t('backups.alarmHelp')}
        </Alert>
      )}
      {!state.configured && <Alert color="yellow" role="note">{t('backups.notConfigured')}</Alert>}
      {state.failing && <Text size="sm" c="red.9">{t('backups.failing')}</Text>}
      <Text size="sm">{state.last_success_at ? t('backups.lastSuccess', { time: formatDateTime(state.last_success_at, i18n.language) }) : t('backups.never')}</Text>
      <Text size="sm">{t('backups.freeSpace', { size: formatSize(state.free_bytes, i18n.language) })}</Text>
    </Stack>
  );
}

function ScheduleSettings() {
  const q = useSetting('backups', getBackupSchedule);
  if (q.isPending) return <LoadingIndicator />;
  if (q.isError) return <ErrorAlert error={q.error} />;
  return <SchedulePanel schedule={q.data} />;
}

function SchedulePanel({ schedule }: { schedule: BackupSchedule }) {
  const { t, i18n } = useTranslation();
  const client = useQueryClient();
  const save = useChange('backups', schedule.version, saveBackupSchedule);
  return (
    <Stack gap="sm">
      <Title order={2} size="h4">
        {t('backups.schedule.title')}
      </Title>
      {schedule.next_at && <Text size="sm">{t('backups.schedule.next', { time: formatDateTime(schedule.next_at, i18n.language) })}</Text>}
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
      <Stack gap="sm" maw={560}>
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
        <Group>
          <Button type="submit" loading={busy}>
            {t('backups.schedule.save')}
          </Button>
        </Group>
      </Stack>
    </form>
  );
}
